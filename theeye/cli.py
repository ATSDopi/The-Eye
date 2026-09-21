from __future__ import annotations

import argparse
import asyncio
import csv
import json
import re
import sys
import time
from pathlib import Path

from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from .models import Status, ScanReport, SiteResult
from .sitesdb import load_sites, filter_sites, all_tags
from .engine import Scanner
from .enrich import Enricher, avatar_pivots
from .variants import generate
from .report import write_html
from . import db

console = Console()
ERR = Console(stderr=True)

BANNER = r"""[red]
   ████████╗██╗  ██╗███████╗    ███████╗██╗   ██╗███████╗
   ╚══██╔══╝██║  ██║██╔════╝    ██╔════╝╚██╗ ██╔╝██╔════╝
      ██║   ███████║█████╗      █████╗   ╚████╔╝ █████╗
      ██║   ██╔══██║██╔══╝      ██╔══╝    ╚██╔╝  ██╔══╝
      ██║   ██║  ██║███████╗    ███████╗   ██║   ███████╗
      ╚═╝   ╚═╝  ╚═╝╚══════╝    ╚══════╝   ╚═╝   ╚══════╝[/red]
              [dim].--.        .--.
             .+(    )===(    )+.      free osint toolkit
              ''-. /.-=-. \.-''           v0.1[/dim]
"""


def show_banner():
    console.print(BANNER)

CONF_STYLE = {"high": "green", "medium": "yellow", "low": "red"}
STATUS_STYLE = {Status.FOUND: "green", Status.NOT_FOUND: "dim",
                Status.UNKNOWN: "yellow", Status.ILLEGAL: "magenta"}


# ---------------------------------------------------------------- args

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="theeye",
        description="The Eye — free OSINT username scanner (6000+ sites)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", help="scan a username across all sites")
    s.add_argument("username")
    s.add_argument("--top", type=int, help="only check the N most popular sites")
    s.add_argument("--tags", help="comma-separated categories (coding,gaming,dating...)")
    s.add_argument("--country", help="only sites tagged with this country code (fr,us...)")
    s.add_argument("--nsfw", action="store_true", help="include NSFW sites")
    s.add_argument("--include-disabled", action="store_true")
    s.add_argument("--site", action="append", help="only these site names (repeatable)")
    s.add_argument("--exclude-site", action="append")
    s.add_argument("--variants", choices=["sep", "common", "full"],
                   help="also try username variants")
    s.add_argument("--variants-top", type=int, default=500,
                   help="variants are only checked on the top N ranked sites (default 500)")
    s.add_argument("--no-verify", action="store_true",
                   help="skip the false-positive verification pass")
    s.add_argument("--deep", action="store_true",
                   help="second-order scan: pivot usernames found on profiles are rescanned on the top 100")
    s.add_argument("--no-enrich", action="store_true", help="skip profile enrichment")
    s.add_argument("--enrich-limit", type=int, default=60)
    s.add_argument("--concurrency", type=int, default=100)
    s.add_argument("--timeout", type=float, default=12.0)
    s.add_argument("--retries", type=int, default=1)
    s.add_argument("--proxy", help="http:// or socks5:// proxy")
    s.add_argument("--case", default="default", help="case name for history grouping")
    s.add_argument("--json", metavar="FILE")
    s.add_argument("--csv", metavar="FILE")
    s.add_argument("--html", metavar="FILE", nargs="?", const="AUTO",
                   help="write HTML report (default: reports/<user>-<ts>.html)")
    s.add_argument("--no-save", action="store_true", help="don't store scan in history db")
    s.add_argument("--show-all", action="store_true",
                   help="also print not-found/unknown in the table")

    t = sub.add_parser("sites", help="inspect the site database")
    t.add_argument("--tags", action="store_true", help="list tag categories")
    t.add_argument("--search", help="find sites by name")
    t.add_argument("--fp", action="store_true",
                   help="list sites flagged FP-prone by selfcheck")
    t.add_argument("--stats", action="store_true")

    h = sub.add_parser("history", help="list past scans")
    h.add_argument("--case")
    h.add_argument("--limit", type=int, default=30)

    r = sub.add_parser("report", help="export a stored scan")
    r.add_argument("scan_id", type=int)
    r.add_argument("--format", choices=["html", "json", "csv"], default="html")
    r.add_argument("-o", "--output")

    e = sub.add_parser("email", help="email intelligence (gravatar, breaches...)")
    e.add_argument("address")
    e.add_argument("--case", default="default")
    e.add_argument("--proxy")
    e.add_argument("--timeout", type=float, default=15.0)
    e.add_argument("--json", metavar="FILE")
    e.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    e.add_argument("--smtp", action="store_true",
                   help="opt-in SMTP RCPT mailbox probe (port 25, often blocked)")
    e.add_argument("--breach-only", action="store_true",
                   help="only run breach/leak sources (skip identity modules)")
    e.add_argument("--no-save", action="store_true")

    d = sub.add_parser("domain", help="domain intelligence (dns, rdap, subdomains...)")
    d.add_argument("domain")
    d.add_argument("--case", default="default")
    d.add_argument("--proxy")
    d.add_argument("--timeout", type=float, default=15.0)
    d.add_argument("--json", metavar="FILE")
    d.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    d.add_argument("--no-save", action="store_true")

    b = sub.add_parser("breach", help="consolidated breach report (all leak sources merged)")
    b.add_argument("address")
    b.add_argument("--case", default="default")
    b.add_argument("--proxy")
    b.add_argument("--timeout", type=float, default=15.0)
    b.add_argument("--json", metavar="FILE")
    b.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    b.add_argument("--no-save", action="store_true")

    sc = sub.add_parser("selfcheck",
                        help="ghost-probe the whole site DB once to flag FP-prone sites")
    sc.add_argument("--unknown", action="store_true",
                    help="only re-probe sites whose cached verdict is unknown")
    sc.add_argument("--concurrency", type=int, default=150)
    sc.add_argument("--timeout", type=float, default=10.0)
    sc.add_argument("--retries", type=int, default=1)
    sc.add_argument("--top", type=int, help="only selfcheck the top N sites")
    sc.add_argument("--proxy")

    i = sub.add_parser("ip", help="ip intelligence (ports, CVEs, ASN, geo...)")
    i.add_argument("ip")
    i.add_argument("--case", default="default")
    i.add_argument("--proxy")
    i.add_argument("--timeout", type=float, default=15.0)
    i.add_argument("--json", metavar="FILE")
    i.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    i.add_argument("--no-save", action="store_true")

    ph = sub.add_parser("phone", help="phone intelligence (offline parse + leaks)")
    ph.add_argument("number")
    ph.add_argument("--case", default="default")
    ph.add_argument("--proxy")
    ph.add_argument("--timeout", type=float, default=15.0)
    ph.add_argument("--json", metavar="FILE")
    ph.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    ph.add_argument("--no-save", action="store_true")

    a = sub.add_parser("address", help="postal address intel (OSM + BAN france)")
    a.add_argument("address")
    a.add_argument("--case", default="default")
    a.add_argument("--proxy")
    a.add_argument("--timeout", type=float, default=15.0)
    a.add_argument("--json", metavar="FILE")
    a.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    a.add_argument("--no-save", action="store_true")

    c = sub.add_parser("crypto", help="crypto address intel (btc/eth/ltc/doge/sol/xmr)")
    c.add_argument("address")
    c.add_argument("--case", default="default")
    c.add_argument("--proxy")
    c.add_argument("--timeout", type=float, default=15.0)
    c.add_argument("--json", metavar="FILE")
    c.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    c.add_argument("--no-save", action="store_true")

    do = sub.add_parser("dossier",
                        help="TOTAL RESEARCH — cross every field you have on a target")
    do.add_argument("target", nargs="?",
                    help="any single value (auto-detected) — or use flags below")
    do.add_argument("--first"); do.add_argument("--last")
    do.add_argument("--name", help="full name (alternative to --first/--last)")
    do.add_argument("--username"); do.add_argument("--email")
    do.add_argument("--phone"); do.add_argument("--domain")
    do.add_argument("--ip"); do.add_argument("--address")
    do.add_argument("--crypto", help="crypto address (btc/eth/ltc/doge/sol/xmr)")
    do.add_argument("--case", default="default")
    do.add_argument("--proxy")
    do.add_argument("--timeout", type=float, default=15.0)
    do.add_argument("--top", type=int, default=150,
                    help="sites per username candidate (default 150)")
    do.add_argument("--deep", action="store_true",
                    help="also rescan pivot usernames found on profiles")
    do.add_argument("--html", metavar="FILE", nargs="?", const="AUTO")
    do.add_argument("--no-save", action="store_true")

    sub.add_parser("update", help="refresh the site database from upstream")
    return p


# ---------------------------------------------------------------- scan

async def run_scan(args) -> int:
    sites = load_sites()
    sites = filter_sites(
        sites,
        include_disabled=args.include_disabled,
        include_nsfw=args.nsfw,
        tags=args.tags.split(",") if args.tags else None,
        country=args.country,
        top=args.top,
        only=args.site,
        exclude=args.exclude_site,
    )
    if not sites:
        ERR.print("[red]No sites match the filters.[/red]")
        return 1

    queries = [args.username]
    variant_sites: set[int] = set()
    if args.variants:
        variants = generate(args.username, args.variants)
        queries += variants
        ranked = sorted((s for s in sites if s.rank), key=lambda s: s.rank)
        variant_sites = {id(s) for s in ranked[:args.variants_top]}
        if not variant_sites:          # no ranks -> take first N
            variant_sites = {id(s) for s in sites[:args.variants_top]}

    n_checks = len(sites) + (len(queries) - 1) * (len(variant_sites) or len(sites))
    console.print(Panel(
        f"[bold]{args.username}[/bold] — {len(sites)} sites"
        + (f" + {len(queries)-1} variants ×{len(variant_sites)}" if len(queries) > 1 else "")
        + f" · ~{n_checks} checks · case [cyan]{args.case}[/cyan]",
        title="The Eye", border_style="red"))

    scanner = Scanner(args.concurrency, args.timeout, args.proxy, args.retries)
    report = ScanReport(username=args.username, case=args.case)
    state = {"done": 0, "found": 0, "t0": time.monotonic()}

    def progress_line() -> Text:
        el = time.monotonic() - state["t0"]
        rate = state["done"] / el if el else 0
        return Text.from_markup(
            f"checked {state['done']}/{n_checks}  "
            f"found [green]{state['found']}[/green]  "
            f"{rate:.0f}/s", style="bold")

    def on_result(r: SiteResult):
        state["done"] += 1
        if r.status == Status.FOUND:
            state["found"] += 1

    try:
        with Live(progress_line(), console=console, refresh_per_second=8) as live:
            tasks = []
            for q in queries:
                for site in sites:
                    if q != args.username and variant_sites and id(site) not in variant_sites:
                        continue
                    tasks.append(scanner.check(site, args.username, q))

            for fut in asyncio.as_completed(tasks):
                res = await fut
                report.results.append(res)
                on_result(res)
                live.update(progress_line())
    finally:
        pass

    # false-positive verification: re-probe each hit with a ghost username
    fp_count = 0
    if not args.no_verify:
        n_found = sum(1 for r in report.results if r.status == Status.FOUND)
        if n_found:
            console.print(f"[dim]verifying {n_found} hits against ghost usernames...[/dim]")
            from .verify import verify_found, load_health
            counts = await verify_found(scanner, sites, report.results,
                                        health=load_health())
            fp_count = counts["fp"]

    # enrichment on the same client before closing — skip known FPs
    if not args.no_enrich:
        found = [r for r in report.results
                 if r.status == Status.FOUND and r.verified != "fp"]
        if found:
            console.print(f"[dim]enriching {min(len(found), args.enrich_limit)} profiles...[/dim]")
            enr = Enricher()
            await enr.enrich_all(scanner.client, found, args.enrich_limit)
            shared = await avatar_pivots(scanner.client, found)
            if shared:
                lines = []
                for sites_sharing in shared.values():
                    lines.append("[bold]" + ", ".join(sites_sharing) +
                                 "[/bold] use the same avatar image")
                    for r in found:
                        if r.site in sites_sharing:
                            r.enriched["avatar_shared_with"] = [
                                s for s in sites_sharing if s != r.site]
                console.print(Panel("\n".join(lines),
                                    title="Avatar reuse — strong identity link",
                                    title_align="left", border_style="green",
                                    expand=False))

    # --deep: pivot usernames discovered on profiles -> rescan on top 100
    if getattr(args, "deep", False):
        seen = {r.query.lower() for r in report.results if r.query}
        handles = sorted(_pivot_handles(report.results, args.username) - seen)
        if handles:
            handles = handles[:4]
            deep_sites = sorted((s for s in sites if s.rank),
                                key=lambda s: s.rank)[:100]
            if not deep_sites:
                deep_sites = sites[:100]
            console.print(f"[dim]deep scan: pivot usernames {', '.join(handles)} "
                          f"× {len(deep_sites)} sites...[/dim]")
            tasks = [scanner.check(s, h, h) for h in handles for s in deep_sites]
            new = []
            for fut in asyncio.as_completed(tasks):
                new.append(await fut)
            report.results += new
            from .verify import verify_found, load_health
            counts = await verify_found(scanner, sites, new,
                                        health=load_health())
            fp_count += counts["fp"]
            if not args.no_enrich:
                found = [r for r in new
                         if r.status == Status.FOUND and r.verified != "fp"]
                if found:
                    await Enricher().enrich_all(
                        scanner.client, found, args.enrich_limit)
    await scanner.close()
    report.finished = time.time()

    print_results(report, show_all=args.show_all)
    s = report.summary()
    confirmed = sum(1 for r in report.results
                    if r.status == Status.FOUND and r.verified == "confirmed")
    console.print(
        f"\n[bold]done in {s['duration_s']}s[/bold] — "
        f"[green]{s['found']} found[/green] ({confirmed} confirmed, "
        f"[red]{fp_count} likely false positive{'s' if fp_count != 1 else ''}[/red]) · "
        f"{s['not_found']} not found · [yellow]{s['unknown']} unknown[/yellow]"
        + (f" · [magenta]{s['illegal']} illegal[/magenta]" if s["illegal"] else ""))

    if not args.no_save:
        sid = db.save_scan(report, args.case)
        console.print(f"[dim]saved to history (scan #{sid})[/dim]")

    if args.json:
        Path(args.json).write_text(json.dumps(
            {**s, "results": [r.to_dict() for r in report.results]},
            ensure_ascii=False, indent=1), encoding="utf-8")
        console.print(f"[dim]json -> {args.json}[/dim]")
    if args.csv:
        write_csv(report, args.csv)
        console.print(f"[dim]csv -> {args.csv}[/dim]")
    if args.html:
        path = args.html
        if path == "AUTO":
            out = Path("reports"); out.mkdir(exist_ok=True)
            path = str(out / f"{args.username}-{int(time.time())}.html")
        write_html(report, path)
        console.print(f"[dim]html -> {path}[/dim]")
    return 0


def write_csv(report: ScanReport, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["site", "status", "url", "http_code", "confidence",
                    "query", "response_ms", "tags", "nsfw"])
        for r in report.results:
            w.writerow([r.site, r.status.value, r.url, r.http_code,
                        r.confidence, r.query, r.response_ms,
                        "|".join(r.tags), r.nsfw])


_PIVOT_HOSTS = {"twitter.com", "x.com", "instagram.com", "github.com",
                "tiktok.com", "reddit.com", "t.me", "telegram.me", "bsky.app",
                "youtube.com", "linkedin.com", "mastodon.social",
                "codepen.io", "dev.to", "medium.com", "substack.com"}


def _pivot_handles(results: list[SiteResult], base: str) -> set[str]:
    """Usernames hidden inside outbound links found on enriched profiles."""
    from urllib.parse import urlparse
    out = set()
    for r in results:
        for l in (r.enriched or {}).get("links", []):
            try:
                host = re.sub(r"^www\.", "", urlparse(l).netloc.lower())
                seg = [p for p in urlparse(l).path.split("/") if p]
                if host in _PIVOT_HOSTS and seg:
                    h = seg[-1] if host == "linkedin.com" else seg[0]
                    h = h.lstrip("@").lower()
                    if (h != base.lower()
                            and re.match(r"^[a-z0-9_.-]{2,30}$", h)):
                        out.add(h)
            except Exception:
                continue
    return out


def _ver_badge(r: SiteResult) -> str:
    return {"confirmed": "[green]✓ verified[/]",
            "fp": "[red]✗ likely fp[/]"}.get(r.verified, "[dim]?[/dim]")


def _link(url: str, width: int = 58) -> str:
    """OSC8 hyperlink: short display text, ctrl+click opens the full URL."""
    if not url:
        return ""
    disp = re.sub(r"^https?://", "", url).rstrip("/")
    if len(disp) > width:
        disp = disp[:width - 1] + "…"
    return f"[cyan][link={url}]{disp}[/link][/cyan]"


def _fill_table(t: Table, rows: list[SiteResult]):
    for r in rows:
        enr = r.enriched or {}
        bits = [enr.get("og_title") or enr.get("ld_name") or "",
                enr.get("description") or "", enr.get("followers") or ""]
        site_name = r.site.replace("{username}", r.query or "")
        name = (f"[green]{site_name}[/green]" if r.verified != "fp"
                else f"[dim]{site_name}[/dim]")
        t.add_row(name, _link(r.url or ""), _ver_badge(r),
                  f"[{CONF_STYLE[r.confidence]}]{r.confidence}[/]",
                  r.query, ",".join(r.tags[:3]),
                  " · ".join(b for b in bits if b)[:140])


def print_results(report: ScanReport, show_all: bool = False):
    found = [r for r in report.results if r.status == Status.FOUND]
    # dedupe: same site + same final profile = one row (variants can collide)
    uniq, seen_k = [], set()
    for r in found:
        k = (r.site, r.url or r.query)
        if k not in seen_k:
            seen_k.add(k)
            uniq.append(r)
    found = uniq
    found.sort(key=lambda r: (r.verified == "fp", r.rank or 10**9,
                              r.site.lower()))
    real = [r for r in found if r.verified != "fp"]
    fps = [r for r in found if r.verified == "fp"]

    t = Table(title=f"Found — {report.username}", title_justify="left",
              border_style="red", header_style="bold")
    t.add_column("Site", style="bold", no_wrap=True, max_width=22)
    t.add_column("URL", no_wrap=True, max_width=48)
    t.add_column("Ver", no_wrap=True)
    t.add_column("Conf", no_wrap=True)
    t.add_column("Query", style="dim", no_wrap=True, max_width=14)
    t.add_column("Extracted", style="dim", max_width=30, overflow="fold")
    _fill_table(t, real)
    console.print(t)

    if fps:
        ft = Table(title="Likely false positives — these sites return "
                         "'found' even for usernames that don't exist",
                   title_justify="left", border_style="grey23",
                   header_style="bold dim")
        ft.add_column("Site", no_wrap=True, max_width=22)
        ft.add_column("URL", no_wrap=True, max_width=48)
        ft.add_column("Ver", no_wrap=True)
        ft.add_column("Query", style="dim", no_wrap=True, max_width=16)
        for r in fps:
            ft.add_row(f"[dim]{r.site.replace('{username}', r.query or '')}[/dim]",
                       _link(r.url or "", 46), _ver_badge(r), r.query)
        console.print(ft)

    # cross-account pivots harvested during enrichment
    pivots, emails = {}, set()
    for r in real:
        enr = r.enriched or {}
        for l in enr.get("links", []):
            pivots.setdefault(l, []).append(r.site)
        emails.update(enr.get("emails", []))
    if pivots or emails:
        lines = [f"[link={l}]{l}[/link]  [dim](via {', '.join(v)})[/dim]"
                 for l, v in sorted(pivots.items())]
        lines += [f"[bold]email:[/bold] {e}" for e in sorted(emails)]
        console.print(Panel("\n".join(lines),
                            title="Pivots — links & contacts found on profiles",
                            title_align="left", border_style="cyan",
                            expand=False))

    if show_all:
        t2 = Table(title="Not found / unknown", border_style="grey23",
                   header_style="bold dim")
        t2.add_column("Site"); t2.add_column("Status"); t2.add_column("Detail", style="dim")
        for r in sorted(report.results, key=lambda r: r.site.lower()):
            if r.status == Status.FOUND:
                continue
            t2.add_row(r.site, f"[{STATUS_STYLE[r.status]}]{r.status.value}[/]",
                       r.reason[:70])
        console.print(t2)


def _detail_lines(r: SiteResult) -> list[str]:
    """Human-readable detail lines for an email-intel module result."""
    d = r.enriched or {}
    lines = []
    if r.site == "gravatar":
        for k, lab in (("display_name", "name"), ("username", "user"),
                       ("location", "loc"), ("bio", "bio")):
            if d.get(k):
                lines.append(f"{lab}: {d[k]}")
        for a in d.get("accounts", []):
            lines.append(f"  + {a.get('service')}: {a.get('username')} — {a.get('url')}")
    elif r.site == "leakcheck":
        for s in d.get("sources", []):
            lines.append(f"  - {s.get('name')} ({s.get('date') or 'n/a'})")
        if d.get("fields"):
            lines.append("  fields: " + ", ".join(d["fields"]))
    elif r.site == "proxynova":
        lines += [f"  {l}" for l in d.get("lines", [])]
    elif r.site == "intelx":
        for rec in d.get("records", [])[:15]:
            lines.append("  - " + str(rec.get("name") or "?")[:70]
                         + f" · {rec.get('bucket') or '?'}"
                         + (f" · {rec.get('date')}" if rec.get("date") else ""))
        if d.get("buckets"):
            lines.append("  buckets: " + ", ".join(d["buckets"]))
    elif r.site == "gh_commits":
        for a in d.get("authors", []):
            lines.append(f"  author: {a}")
        for repo in d.get("repos", [])[:8]:
            lines.append(f"  repo: {repo}")
    elif r.site == "hudsonrock":
        for s in d.get("stealers", []):
            lines.append(f"  - {s.get('date') or '?'} · {s.get('os') or '?'} · "
                         f"{s.get('computer') or '?'} · {s.get('malware_path') or ''}")
    else:
        for k, v in d.items():
            if isinstance(v, (str, int, bool, float)):
                lines.append(f"{k}: {v}")
            elif isinstance(v, list):
                lines.append(f"{k}:")
                for it in v[:15]:
                    if isinstance(it, dict):
                        lines.append("  - " + " · ".join(
                            str(x) for x in it.values() if x))
                    else:
                        lines.append(f"  - {it}")
                if len(v) > 15:
                    lines.append(f"  … +{len(v) - 15} more")
    return lines


async def run_email(args) -> ScanReport:
    from .email_intel import run_email_scan, MODULES, BREACH_MODULES

    if not re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", args.address):
        ERR.print("[red]Invalid email address.[/red]")
        return 1

    console.print(Panel(f"[bold]{args.address}[/bold] — {len(MODULES)} modules · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — email", border_style="red"))
    only = list(BREACH_MODULES) if getattr(args, "breach_only", False) else None
    if getattr(args, "smtp", False):
        only = (only or [n for n, _ in MODULES]) + ["smtp"]
    report = ScanReport(username=args.address, case=args.case)
    with console.status("[bold]querying sources...[/bold]"):
        report.results = await run_email_scan(args.address, args.timeout,
                                              args.proxy, only=only)
    report.finished = time.time()
    _render_module_results(report, "Email intel")
    _export_module_report(report, args, "email")
    return report


async def run_domain(args) -> ScanReport:
    from .domain_intel import run_domain_scan, MODULES, DOMAIN_RE

    domain = args.domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not DOMAIN_RE.match(domain):
        ERR.print("[red]Invalid domain name.[/red]")
        return 1

    console.print(Panel(f"[bold]{domain}[/bold] — {len(MODULES)} modules · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — domain", border_style="red"))
    report = ScanReport(username=domain, case=args.case)
    with console.status("[bold]querying sources...[/bold]"):
        report.results = await run_domain_scan(domain, args.timeout, args.proxy)
    report.finished = time.time()
    _render_module_results(report, "Domain intel")
    _export_module_report(report, args, "domain")
    return report


async def run_breach(args) -> ScanReport:
    from .email_intel import run_email_scan, BREACH_MODULES
    from .breach import aggregate
    from .report import render_breach_html, LEVEL_COLOR

    if not re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", args.address):
        ERR.print("[red]Invalid email address.[/red]")
        return 1

    console.print(Panel(f"[bold]{args.address}[/bold] — consolidated breach report · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — breach", border_style="red"))
    report = ScanReport(username=args.address, case=args.case)
    with console.status("[bold]querying breach sources...[/bold]"):
        report.results = await run_email_scan(args.address, args.timeout,
                                              args.proxy, only=BREACH_MODULES)
    report.finished = time.time()
    agg = aggregate(report.results)

    col = LEVEL_COLOR[agg["level"]]
    console.print(Panel(f"[bold {col}]{agg['level'].upper()}[/bold {col}] exposure — "
                        f"{len(agg['breaches'])} breach(es) · "
                        f"{len(agg['stealers'])} stealer infection(s) · "
                        f"{len(agg['cred_lines'])} credential line(s)",
                        border_style=col))

    if agg["breaches"]:
        t = Table(title="Breach timeline", title_justify="left",
                  border_style="red", header_style="bold")
        t.add_column("Breach", style="bold", no_wrap=True)
        t.add_column("Date", no_wrap=True)
        t.add_column("Seen via", style="dim")
        for b_ in agg["breaches"]:
            t.add_row(b_["name"], b_["date"] or "?", ", ".join(b_["via"]))
        console.print(t)
    if agg["fields"]:
        console.print("[dim]leaked field types:[/dim] " + ", ".join(agg["fields"]))
    if agg["stealers"]:
        t = Table(title="Infostealer infections", title_justify="left",
                  border_style="red", header_style="bold")
        t.add_column("Date"); t.add_column("OS"); t.add_column("Computer")
        t.add_column("Malware path", style="dim", max_width=50, overflow="fold")
        for s_ in agg["stealers"]:
            t.add_row(str(s_.get("date") or "?")[:10], str(s_.get("os") or "?"),
                      str(s_.get("computer") or "?"),
                      str(s_.get("malware_path") or ""))
        console.print(t)
    if agg["cred_lines"]:
        console.print(Panel("\n".join(agg["cred_lines"]),
                            title="Credential lines (masked)",
                            title_align="left", border_style="grey42",
                            expand=False))
    src = " · ".join(f"{k}: [{STATUS_STYLE.get(Status(v), 'dim')}]{v}[/]"
                     for k, v in agg["per_source"].items())
    console.print(f"[dim]sources: {src}[/dim]")

    if not args.no_save:
        sid = db.save_scan(report, args.case)
        console.print(f"[dim]saved to history (scan #{sid})[/dim]")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {**agg, "results": [r.to_dict() for r in report.results]},
            ensure_ascii=False, indent=1), encoding="utf-8")
        console.print(f"[dim]json -> {args.json}[/dim]")
    if args.html:
        path = args.html
        if path == "AUTO":
            out = Path("reports"); out.mkdir(exist_ok=True)
            path = str(out / f"breach-{args.address}-{int(time.time())}.html")
        Path(path).write_text(
            render_breach_html(args.address, agg, report.started), encoding="utf-8")
        console.print(f"[dim]html -> {path}[/dim]")
    return report


async def run_ip(args) -> ScanReport:
    import ipaddress
    from .ip_intel import run_ip_scan, MODULES
    ip = args.ip.strip()
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        ERR.print("[red]Invalid IP address.[/red]")
        return 1
    console.print(Panel(f"[bold]{ip}[/bold] — {len(MODULES)} modules · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — ip", border_style="red"))
    report = ScanReport(username=ip, case=args.case)
    with console.status("[bold]querying sources...[/bold]"):
        report.results = await run_ip_scan(ip, args.timeout, args.proxy)
    report.finished = time.time()
    _render_module_results(report, "IP intel")
    _export_module_report(report, args, "ip")
    return report


async def run_phone(args) -> ScanReport:
    from .phone_intel import run_phone_scan
    console.print(Panel(f"[bold]{args.number}[/bold] — parse + leak sources · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — phone", border_style="red"))
    report = ScanReport(username=args.number, case=args.case)
    with console.status("[bold]querying sources...[/bold]"):
        report.results = await run_phone_scan(args.number, args.timeout,
                                              args.proxy)
    report.finished = time.time()
    _render_module_results(report, "Phone intel")
    _export_module_report(report, args, "phone")
    return report


async def run_address(args) -> ScanReport:
    from .address_intel import run_address_scan, MODULES
    console.print(Panel(f"[bold]{args.address}[/bold] — {len(MODULES)} modules · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — address", border_style="red"))
    report = ScanReport(username=args.address, case=args.case)
    with console.status("[bold]querying sources...[/bold]"):
        report.results = await run_address_scan(args.address, args.timeout,
                                                args.proxy)
    report.finished = time.time()
    _render_module_results(report, "Address intel")
    _export_module_report(report, args, "address")
    return report


def _username_candidates(first: str, last: str, email: str | None,
                         username: str | None) -> list[str]:
    """Generate likely usernames from a person's name + email local part."""
    import unicodedata

    def norm(s: str) -> str:
        s = unicodedata.normalize("NFKD", s.lower())
        return re.sub(r"[^a-z]", "", s.encode("ascii", "ignore").decode())

    cands = []
    if username:
        cands.append(username)
    if email:
        local = email.split("@")[0]
        cands.append(local)
        cands.append(re.sub(r"\d+$", "", local))   # john.doe42 -> john.doe
        cands += [p for p in re.split(r"[._-]", local) if len(p) >= 3]
    f, l = norm(first), norm(last)
    if f and l:
        cands += [f + l, f"{f}.{l}", f"{f}{l[0]}", f"{f[0]}{l}",
                  f"{f}_{l}", f"{l}{f}", f"{l}.{f}", f"{f[0]}.{l}"]
    elif f:
        cands.append(f)
    elif l:
        cands.append(l)
    seen, out = set(), []
    for c in cands:
        c = c.lower().strip(".-_")
        if c and c not in seen and len(c) >= 3:
            seen.add(c)
            out.append(c)
    return out[:8]


def _email_candidates(first: str, last: str,
                      domains: list[str]) -> list[str]:
    """j.dupont@, jdupont@, jd@… — candidates to test against breach DBs.
    A leak hit on a generated address proves the mailbox exists."""
    import unicodedata

    def norm(s: str) -> str:
        s = unicodedata.normalize("NFKD", s.lower())
        return re.sub(r"[^a-z]", "", s.encode("ascii", "ignore").decode())

    f, l = norm(first), norm(last)
    if not f or not l:
        return []
    locals_ = [f"{f}.{l}", f + l, f"{f[0]}{l}", f"{f}{l[0]}",
               f"{f}_{l}", f"{l}{f}", f"{l}.{f}", f]
    out, seen = [], set()
    for loc in locals_:
        for d in domains:
            e = f"{loc}@{d}"
            if e not in seen:
                seen.add(e)
                out.append(e)
    return out


async def run_crypto(args) -> ScanReport:
    from .crypto_intel import run_crypto_scan
    console.print(Panel(f"[bold]{args.address}[/bold] — public explorers · "
                        f"case [cyan]{args.case}[/cyan]",
                        title="The Eye — crypto", border_style="red"))
    report = ScanReport(username=args.address, case=args.case)
    with console.status("[bold]querying explorers...[/bold]"):
        report.results = await run_crypto_scan(args.address, args.timeout,
                                               args.proxy)
    report.finished = time.time()
    _render_module_results(report, "Crypto intel")
    _export_module_report(report, args, "crypto")
    return report


async def run_dossier(args) -> int:
    """TOTAL RESEARCH — every field you give gets cross-correlated."""
    import ipaddress
    from .domain_intel import DOMAIN_RE
    from .email_intel import run_email_scan, BREACH_MODULES
    from .phone_intel import run_phone_scan, e164
    from .address_intel import run_address_scan
    from .crypto_intel import detect_chain
    from .breach import aggregate

    fields = {"username": args.username, "email": args.email,
              "phone": args.phone, "domain": args.domain, "ip": args.ip,
              "address": args.address, "crypto": args.crypto}
    first, last = args.first or "", args.last or ""
    if args.name and not (first or last):
        parts = args.name.strip().split()
        first, last = (parts[0], " ".join(parts[1:])) if len(parts) > 1 \
            else (parts[0], "")

    # positional target auto-detection
    t = (args.target or "").strip()
    if t:
        if re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", t):
            fields["email"] = fields["email"] or t
        else:
            try:
                ipaddress.ip_address(t)
                fields["ip"] = fields["ip"] or t
            except ValueError:
                if re.match(r"^\+?[0-9 ()-]{6,}$", t):
                    fields["phone"] = fields["phone"] or t
                elif detect_chain(t):
                    fields["crypto"] = fields["crypto"] or t
                elif DOMAIN_RE.match(t.split("/")[0]):
                    fields["domain"] = fields["domain"] or t.split("/")[0]
                elif (re.match(r"^[A-Za-zÀ-ÿ' \-]{3,60}$", t) and " " in t
                        and not re.search(r"\d", t)):
                    if not (first or last):
                        parts = t.split()
                        first, last = parts[0], " ".join(parts[1:])
                elif re.search(r"[ ,]", t):
                    fields["address"] = fields["address"] or t
                else:
                    fields["username"] = fields["username"] or t

    if not any(fields.values()) and not (first or last):
        ERR.print("[red]nothing to investigate — pass a target or flags "
                  "(--email --username --phone --domain --ip --address "
                  "--first/--last)[/red]")
        return 1

    def ns_for(cmd: str, *a):
        ns = build_parser().parse_args([cmd, *a])
        ns.case, ns.no_save = args.case, args.no_save
        for k in ("proxy", "timeout"):
            if hasattr(ns, k):
                setattr(ns, k, getattr(args, k))
        if hasattr(ns, "html"):
            ns.html = "AUTO" if args.html else None
        if hasattr(ns, "json"):
            ns.json = None
        return ns

    identity = {"usernames": set(), "emails": set(), "names": set(),
                "accounts_registered": set(), "phones": set(),
                "addresses": set(), "domains": set(), "crypto": set(),
                "profiles": set()}
    avatar_pool = []          # results with avatars — cross-suite hash match

    # ---------- username matrix (given + generated from name/email) ----------
    cands = _username_candidates(first, last, fields["email"],
                                 fields["username"])
    if cands:
        console.print(f"[bold]username matrix:[/bold] {', '.join(cands)} "
                      f"× top {args.top} sites")
        ns = ns_for("scan", cands[0])
        ns.top = args.top
        sites = filter_sites(load_sites(), top=args.top)
        scanner = Scanner(ns.concurrency, ns.timeout, ns.proxy, ns.retries)
        report = ScanReport(username=cands[0], case=args.case)
        n_checks = len(cands) * len(sites)
        state = {"done": 0, "found": 0, "t0": time.monotonic()}

        def line():
            el = time.monotonic() - state["t0"]
            return Text.from_markup(
                f"checked {state['done']}/{n_checks}  "
                f"found [green]{state['found']}[/green]", style="bold")

        with Live(line(), console=console, refresh_per_second=8) as live:
            for fut in asyncio.as_completed(
                    [scanner.check(s, u, u) for u in cands for s in sites]):
                res = await fut
                report.results.append(res)
                state["done"] += 1
                state["found"] += res.status == Status.FOUND
                live.update(line())
        from .verify import verify_found, load_health
        await verify_found(scanner, sites, report.results,
                           health=load_health())
        found = [r for r in report.results
                 if r.status == Status.FOUND and r.verified != "fp"]
        if found:
            console.print(f"[dim]enriching {min(len(found), 40)} profiles...[/dim]")
            await Enricher().enrich_all(scanner.client, found, 40)
            shared = await avatar_pivots(scanner.client, found)
            for sites_sharing in shared.values():
                for r in found:
                    if r.site in sites_sharing:
                        r.enriched["avatar_shared_with"] = [
                            s for s in sites_sharing if s != r.site]
        # --deep: pivot handles found on profiles -> rescan top 100
        if args.deep:
            seen = {r.query.lower() for r in report.results if r.query}
            handles = sorted(_pivot_handles(report.results, cands[0]) - seen)
            if handles:
                handles = handles[:4]
                deep_sites = sorted((s for s in sites if s.rank),
                                    key=lambda s: s.rank)[:100] or sites[:100]
                console.print(f"[dim]deep scan: {', '.join(handles)} "
                              f"× {len(deep_sites)} sites[/dim]")
                new = []
                for fut in asyncio.as_completed(
                        [scanner.check(s, h, h)
                         for h in handles for s in deep_sites]):
                    res = await fut
                    new.append(res)
                    report.results.append(res)
                await verify_found(scanner, sites, new,
                                   health=load_health())
                new_found = [r for r in new
                             if r.status == Status.FOUND and r.verified != "fp"]
                if new_found:
                    await Enricher().enrich_all(scanner.client, new_found, 20)
                    avatar_pool += new_found
        avatar_pool += found
        await scanner.close()
        report.finished = time.time()
        print_results(report)
        for r in found:
            identity["usernames"].add(r.query)
            identity["profiles"].add(f"{r.site}: {r.url}")
            enr = r.enriched or {}
            for k in ("og_title", "ld_name"):
                if enr.get(k):
                    identity["names"].add(str(enr[k])[:80])
            identity["emails"].update(enr.get("emails", []))
        if not args.no_save:
            db.save_scan(report, args.case)

    # ---------- email ----------
    if fields["email"]:
        console.print("[bold]email suite[/bold]")
        rep = await run_email(ns_for("email", fields["email"]))
        await run_breach(ns_for("breach", fields["email"]))
        identity["emails"].add(fields["email"])
        if isinstance(rep, ScanReport):
            for r in rep.results:
                if r.status != Status.FOUND:
                    continue
                if r.site in ("twitter", "spotify", "protonmail", "github"):
                    identity["accounts_registered"].add(
                        f"{r.site}: {r.reason}")
                d = r.enriched or {}
                if r.site == "github" and d.get("login"):
                    identity["usernames"].add(d["login"])
                if r.site == "gh_commits":
                    identity["names"].update(d.get("authors", []))
                    identity["profiles"].update(
                        f"github repo: {x}" for x in d.get("repos", []))
                if r.site == "gravatar":
                    d = r.enriched or {}
                    if d.get("username"):
                        identity["usernames"].add(d["username"])
                    if d.get("display_name") or d.get("name"):
                        identity["names"].add(
                            d.get("display_name") or d.get("name"))
                    if d.get("avatar"):
                        avatar_pool.append(r)
        if DOMAIN_RE.match(fields["email"].split("@")[1]):
            dom = fields["email"].split("@")[1]
            identity["domains"].add(dom)
            if dom not in ("gmail.com", "yahoo.com", "outlook.com",
                           "hotmail.com", "proton.me", "icloud.com",
                           "aol.com", "mail.com"):
                await run_domain(ns_for("domain", dom))
                fields["domain"] = fields["domain"] or dom

    # ---------- email permutation -> breach-existence proof ----------
    if first and last:
        domains = ([fields["domain"]] if fields["domain"] else []) + \
                  ["gmail.com", "outlook.com", "proton.me"]
        ecands = _email_candidates(first, last, domains)
        console.print(f"[bold]email permutation:[/bold] {len(ecands)} candidates "
                      f"× breach sources")
        from .email_intel import run_email_scan as _rescan
        import httpx as _hx
        results = await asyncio.gather(*(
            _rescan(e, args.timeout, args.proxy,
                    only=["leakcheck", "xposedornot", "proxynova"])
            for e in ecands))
        for e, rep in zip(ecands, results):
            hits = [r for r in rep if r.status == Status.FOUND]
            if hits:
                srcs = ", ".join(r.site for r in hits)
                identity["emails"].add(f"{e}  ← in breach data ({srcs})")
                console.print(f"  [green]✓[/green] {e} — found in breach "
                              f"data via {srcs}")

    # ---------- phone ----------
    if fields["phone"]:
        console.print("[bold]phone suite[/bold]")
        rep = await run_phone(ns_for("phone", fields["phone"]))
        identity["phones"].add(fields["phone"])
        if isinstance(rep, ScanReport):
            for r in rep.results:
                if r.status == Status.FOUND and r.site in ("leakcheck",
                                                           "proxynova",
                                                           "intelx"):
                    identity["accounts_registered"].add(
                        f"leak({r.site}): {r.reason}")

    # ---------- domain / ip / address / crypto ----------
    if fields["domain"]:
        console.print("[bold]domain suite[/bold]")
        await run_domain(ns_for("domain", fields["domain"]))
        identity["domains"].add(fields["domain"])
    if fields["ip"]:
        console.print("[bold]ip suite[/bold]")
        await run_ip(ns_for("ip", fields["ip"]))
    if fields["crypto"]:
        console.print("[bold]crypto suite[/bold]")
        rep = await run_crypto(ns_for("crypto", fields["crypto"]))
        identity["crypto"].add(fields["crypto"])
        if isinstance(rep, ScanReport):
            for r in rep.results:
                if r.status == Status.FOUND and r.site != "detect":
                    identity["crypto"].add(
                        f"{r.site}: {r.reason}")
    if fields["address"]:
        console.print("[bold]address suite[/bold]")
        rep = await run_address(ns_for("address", fields["address"]))
        identity["addresses"].add(fields["address"])
        if isinstance(rep, ScanReport):
            for r in rep.results:
                if r.status == Status.FOUND:
                    for k in ("display", "label", "coords", "city"):
                        v = (r.enriched or {}).get(k)
                        if v:
                            identity["addresses"].add(str(v)[:90])

    # ---------- cross-suite avatar correlation ----------
    if avatar_pool:
        import httpx
        async with httpx.AsyncClient(timeout=12, proxy=args.proxy,
                                     follow_redirects=True) as client:
            shared = await avatar_pivots(client, avatar_pool)
        for sites_sharing in shared.values():
            note = "SAME AVATAR IMAGE on: " + ", ".join(sites_sharing)
            identity["names"].add(note)
            console.print(Panel(f"[bold green]{note}[/bold green]",
                                title="avatar reuse — strong identity link",
                                title_align="left", border_style="green",
                                expand=False))

    # ---------- identity graph ----------
    t = Table(title="Identity graph — everything correlated",
              title_justify="left", border_style="cyan", header_style="bold")
    t.add_column("Entity", style="bold", no_wrap=True)
    t.add_column("Value(s)", overflow="fold", max_width=90)
    for k in ("usernames", "names", "emails", "phones", "addresses",
              "domains", "crypto", "accounts_registered", "profiles"):
        vals = sorted(identity[k])
        if vals:
            t.add_row(k, "\n".join(vals[:12]) +
                      (f"\n… +{len(vals)-12}" if len(vals) > 12 else ""))
    console.print(t)

    if not args.no_save or args.html:
        out = Path("reports"); out.mkdir(exist_ok=True)
    if not args.no_save:
        jpath = out / f"dossier-{int(time.time())}.json"
        jpath.write_text(json.dumps(
            {"supplied": {k: v for k, v in fields.items() if v},
             "name": f"{first} {last}".strip() or None,
             "identity": {k: sorted(v) for k, v in identity.items()}},
            ensure_ascii=False, indent=1), encoding="utf-8")
        console.print(f"[dim]dossier json -> {jpath}[/dim]")
    if args.html:
        from .report import render_dossier_html
        path = str(out / f"dossier-{int(time.time())}.html") \
            if args.html == "AUTO" else args.html
        Path(path).write_text(render_dossier_html(fields, first, last,
                                                 identity), encoding="utf-8")
        console.print(f"[dim]dossier html -> {path}[/dim]")
    return 0


def _render_module_results(report: ScanReport, title: str):
    t = Table(title=title, title_justify="left",
              border_style="red", header_style="bold")
    t.add_column("Module", style="bold", no_wrap=True)
    t.add_column("Status", no_wrap=True)
    t.add_column("Result", overflow="fold", max_width=85)
    for r in report.results:
        t.add_row(r.site,
                  f"[{STATUS_STYLE[r.status]}]{r.status.value}[/]",
                  r.reason)
    console.print(t)

    for r in report.results:
        if r.status != Status.FOUND:
            continue
        lines = _detail_lines(r)
        if lines:
            console.print(Panel("\n".join(lines), title=r.site,
                                title_align="left", border_style="grey42",
                                expand=False))

    s = report.summary()
    console.print(f"\n[bold]done[/bold] — [green]{s['found']} hit(s)[/green] · "
                  f"{s['not_found']} clean · [yellow]{s['unknown']} unknown[/yellow]")


def _export_module_report(report: ScanReport, args, kind: str):
    if not args.no_save:
        sid = db.save_scan(report, args.case)
        console.print(f"[dim]saved to history (scan #{sid})[/dim]")
    if args.json:
        Path(args.json).write_text(json.dumps(
            {**report.summary(),
             "results": [r.to_dict() for r in report.results]},
            ensure_ascii=False, indent=1), encoding="utf-8")
        console.print(f"[dim]json -> {args.json}[/dim]")
    if args.html:
        path = args.html
        if path == "AUTO":
            out = Path("reports"); out.mkdir(exist_ok=True)
            path = str(out / f"{kind}-{report.username}-{int(time.time())}.html")
        write_html(report, path)
        console.print(f"[dim]html -> {path}[/dim]")


# ---------------------------------------------------------------- misc cmds

def cmd_sites(args) -> int:
    sites = load_sites()
    if args.fp:
        from .verify import load_health
        bad = sorted(n for n, v in load_health().items()
                     if v.get("v") == "fp")
        console.print(f"[red]{len(bad)} FP-prone sites[/red] "
                      f"(return 'found' for non-existent usernames):")
        if bad:
            console.print("  " + " · ".join(bad))
    if args.stats or (not args.tags and not args.search and not args.fp):
        en = [s for s in sites if not s.disabled]
        console.print(f"[bold]{len(sites)}[/bold] sites — {len(en)} enabled, "
                      f"{len(sites)-len(en)} disabled, "
                      f"{sum(1 for s in sites if s.nsfw)} nsfw")
        from .verify import load_health
        health = load_health()
        if health:
            from collections import Counter
            c = Counter(v.get("v") for v in health.values())
            console.print(f"[dim]health cache:[/dim] "
                          f"[green]{c.get('ok', 0)} reliable[/green] · "
                          f"[red]{c.get('fp', 0)} fp-prone[/red] · "
                          f"[yellow]{c.get('unknown', 0)} unknown[/yellow]")
    if args.tags:
        t = Table(title="Tags", header_style="bold")
        t.add_column("tag"); t.add_column("sites", justify="right")
        for tag, n in all_tags(sites).items():
            t.add_row(tag, str(n))
        console.print(t)
    if args.search:
        q = args.search.lower()
        t = Table(header_style="bold")
        t.add_column("site"); t.add_column("url", style="cyan"); t.add_column("status")
        for s in sites:
            if q in s.name.lower() or q in s.url.lower():
                t.add_row(s.name, s.url,
                          "[red]disabled[/]" if s.disabled else "[green]on[/]")
        console.print(t)
    return 0


def cmd_history(args) -> int:
    scans = db.list_scans(args.limit)
    t = Table(title="Scan history", border_style="red", header_style="bold")
    t.add_column("#", justify="right"); t.add_column("username")
    t.add_column("case"); t.add_column("date"); t.add_column("found", justify="right")
    t.add_column("checked", justify="right")
    for s in scans:
        if args.case and s["case"] != args.case:
            continue
        t.add_row(str(s["id"]), s["username"], s["case"],
                  time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started"])),
                  str(s["summary"].get("found", 0)), str(s["summary"].get("total", 0)))
    console.print(t)
    return 0


def cmd_report(args) -> int:
    data = db.load_scan(args.scan_id)
    if not data:
        ERR.print(f"[red]scan #{args.scan_id} not found[/red]")
        return 1
    if args.format == "json":
        out = args.output or f"scan-{args.scan_id}.json"
        Path(out).write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    elif args.format == "csv":
        out = args.output or f"scan-{args.scan_id}.csv"
        with open(out, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["site", "status", "url", "http_code", "confidence", "query"])
            for r in data["results"]:
                w.writerow([r["site"], r["status"], r["url"], r["http_code"],
                            r["confidence"], r["query"]])
    else:
        rep = ScanReport(username=data["username"], started=data["started"],
                         finished=data["finished"], case=data["case"])
        for r in data["results"]:
            rep.results.append(SiteResult(
                site=r["site"], status=Status(r["status"]), url=r["url"],
                http_code=r["http_code"], confidence=r["confidence"],
                reason=r["reason"], query=r["query"], rank=r["rank"],
                enriched=r["enriched"], verified=r.get("verified", "")))
        out = args.output or f"scan-{args.scan_id}.html"
        # stored breach scans get their dedicated timeline page back
        from .email_intel import BREACH_MODULES
        if sum(1 for r in rep.results if r.site in BREACH_MODULES) >= 3:
            from .breach import aggregate
            from .report import render_breach_html
            Path(out).write_text(
                render_breach_html(rep.username, aggregate(rep.results),
                                   rep.started), encoding="utf-8")
        else:
            write_html(rep, out)
    console.print(f"[green]{out}[/green]")
    return 0


def cmd_update() -> int:
    import subprocess
    script = Path(__file__).parent.parent / "scripts" / "update_sites.py"
    rc = subprocess.call([sys.executable, str(script)])
    # also refresh the disposable-email blocklist used by `email validate`
    try:
        import httpx
        out = Path(__file__).parent / "data" / "disposable.txt"
        out.parent.mkdir(exist_ok=True)
        r = httpx.get("https://raw.githubusercontent.com/disposable-email-domains/"
                      "disposable-email-domains/master/"
                      "disposable_email_blocklist.conf", timeout=20,
                      follow_redirects=True)
        if r.status_code == 200 and len(r.text) > 1000:
            out.write_text(r.text, encoding="utf-8")
            console.print(f"[dim]disposable blocklist -> {len(r.text.splitlines())} domains[/dim]")
    except Exception as e:
        console.print(f"[yellow]disposable blocklist refresh failed: {e}[/yellow]")
    return rc


async def run_selfcheck(args) -> int:
    """Ghost-probe every enabled site once; cache verdicts to data/site_health.json."""
    from .verify import probe_sites, load_health, save_health
    sites = [s for s in load_sites() if not s.disabled]
    sites = filter_sites(sites, top=args.top)
    if args.unknown:
        prev = load_health()
        sites = [s for s in sites
                 if (prev.get(s.name) or {}).get("v") == "unknown"]
    show_banner()
    console.print(Panel(f"ghost-probing [bold]{len(sites)}[/bold] sites — "
                        f"this doubles as a site-health audit",
                        title="The Eye — selfcheck", border_style="red"))
    scanner = Scanner(args.concurrency, args.timeout, args.proxy, args.retries)
    state = {"done": 0, "ok": 0, "fp": 0, "unk": 0, "t0": time.monotonic()}

    def on_done(_name, verdict):
        state["done"] += 1
        state[{"ok": "ok", "fp": "fp"}.get(verdict, "unk")] += 1

    def line() -> Text:
        el = time.monotonic() - state["t0"]
        return Text.from_markup(
            f"probed {state['done']}/{len(sites)}  "
            f"[green]{state['ok']} ok[/green]  "
            f"[red]{state['fp']} fp-prone[/red]  "
            f"[yellow]{state['unk']} unknown[/yellow]  "
            f"{state['done']/el:.0f}/s" if el else "", style="bold")

    with Live(line(), console=console, refresh_per_second=8) as live:
        health = await probe_sites(scanner, sites, on_done)
        live.update(line())
    await scanner.close()

    merged = load_health()          # keep verdicts for sites not re-probed
    merged.update(health)
    save_health(merged)
    console.print(f"[green]done[/green] — health cache -> {len(merged)} sites "
                  f"({state['ok']} reliable, {state['fp']} fp-prone, "
                  f"{state['unk']} unknown). Future scans verify instantly.")
    return 0


# ---------------------------------------------------------------- main

def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    known = {"scan", "email", "domain", "breach", "ip", "phone", "address",
             "crypto", "dossier", "selfcheck", "sites", "history", "report",
             "update", "-h", "--help"}
    if argv and argv[0] not in known and not argv[0].startswith("-"):
        # auto-route bare values to the right suite
        t = argv[0]
        routed = "scan"
        try:
            import ipaddress
            ipaddress.ip_address(t)
            routed = "ip"
        except ValueError:
            if re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", t):
                routed = "email"
            else:
                from .crypto_intel import detect_chain
                from .domain_intel import DOMAIN_RE
                if detect_chain(t):
                    routed = "crypto"
                elif DOMAIN_RE.match(t.split("/")[0]) and "." in t:
                    routed = "domain"
                elif re.match(r"^[A-Za-zÀ-ÿ' \-]{3,60}$", t) and " " in t \
                        and not re.search(r"\d", t):
                    routed = "dossier"   # bare full name -> total research
        argv.insert(0, routed)
    elif not argv:
        argv = ["--help"]

    args = build_parser().parse_args(argv)
    if args.cmd in ("scan", "email", "domain", "breach", "ip", "phone",
                    "address", "crypto", "dossier"):
        show_banner()
    if args.cmd == "scan":
        try:
            return asyncio.run(run_scan(args))
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "email":
        try:
            asyncio.run(run_email(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "domain":
        try:
            asyncio.run(run_domain(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "breach":
        try:
            asyncio.run(run_breach(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "selfcheck":
        try:
            return asyncio.run(run_selfcheck(args))
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "ip":
        try:
            asyncio.run(run_ip(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "phone":
        try:
            asyncio.run(run_phone(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "address":
        try:
            asyncio.run(run_address(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "crypto":
        try:
            asyncio.run(run_crypto(args)); return 0
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "dossier":
        try:
            return asyncio.run(run_dossier(args))
        except KeyboardInterrupt:
            ERR.print("\n[yellow]interrupted[/yellow]")
            return 130
    if args.cmd == "sites":
        return cmd_sites(args)
    if args.cmd == "history":
        return cmd_history(args)
    if args.cmd == "report":
        return cmd_report(args)
    if args.cmd == "update":
        return cmd_update()
    return 0
