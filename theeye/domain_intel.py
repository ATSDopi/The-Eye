"""Free domain intelligence — no API keys required.

Modules:
  dns         A/AAAA/MX/NS/TXT/CNAME records via Google DoH
  rdap        registrar, creation/expiry dates, domain status (rdap.org)
  subdomains  certificate-transparency subdomains (crt.sh)
  urlscan     recent urlscan.io scans + screenshots
  wayback     first/last Wayback Machine captures (archive.org CDX)
  mailsec     SPF / DMARC / DKIM-sel presence from TXT records
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime

import httpx

from .engine import USER_AGENTS
from .models import SiteResult, Status

UA = {"User-Agent": USER_AGENTS[0]}
DOH = "https://dns.google/resolve"
RRTYPE = {"A": 1, "NS": 2, "CNAME": 5, "MX": 15, "TXT": 16, "AAAA": 28}


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


async def _doh(client: httpx.AsyncClient, name: str, rtype: str) -> list[str]:
    try:
        resp = await client.get(DOH, params={"name": name, "type": rtype},
                                timeout=10)
        if resp.status_code != 200:
            return []
        return [a.get("data", "").rstrip(".")
                for a in resp.json().get("Answer", [])
                if a.get("type") == RRTYPE[rtype]]
    except Exception:
        return []


async def check_dns(client: httpx.AsyncClient, domain: str) -> SiteResult:
    recs: dict[str, list[str]] = {}
    results = await asyncio.gather(
        *(_doh(client, domain, t) for t in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")))
    for t, vals in zip(("A", "AAAA", "MX", "NS", "TXT", "CNAME"), results):
        if vals:
            recs[t] = vals[:8]
    if not recs:
        # distinguish NXDOMAIN (status 3) from no-records
        try:
            resp = await client.get(DOH, params={"name": domain, "type": "A"},
                                    timeout=10)
            if resp.json().get("Status") == 3:
                return _r("dns", Status.NOT_FOUND, "NXDOMAIN — domain does not exist")
        except Exception:
            pass
        return _r("dns", Status.UNKNOWN, "no DNS records resolved")
    reason = ", ".join(f"{t}×{len(v)}" for t, v in recs.items())
    return _r("dns", Status.FOUND, reason, recs)


async def check_rdap(client: httpx.AsyncClient, domain: str) -> SiteResult:
    try:
        resp = await client.get(f"https://rdap.org/domain/{domain}",
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("rdap", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 404:
        return _r("rdap", Status.NOT_FOUND, "not registered (no RDAP record)")
    if resp.status_code != 200:
        return _r("rdap", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    data: dict = {"handle": js.get("handle"),
                  "status": ", ".join(js.get("status", [])[:4])}
    for ev in js.get("events", []):
        act = ev.get("eventAction", "")
        date = (ev.get("eventDate") or "")[:10]
        if act == "registration":
            data["registered"] = date
        elif act in ("expiration", "registry expiration"):
            data["expires"] = date
        elif act == "last changed":
            data["updated"] = date
    for ent in js.get("entities", []):
        if "registrar" in ent.get("roles", []):
            for item in ent.get("vcardArray", [None, []])[1]:
                if item[0] == "fn":
                    data["registrar"] = item[3]
    if js.get("secureDNS", {}).get("delegationSigned"):
        data["dnssec"] = "signed"
    who = data.get("registrar") or data.get("handle") or ""
    return _r("rdap", Status.FOUND,
              f"registrar: {who}" +
              (f" — created {data['registered']}" if data.get("registered") else ""),
              {k: v for k, v in data.items() if v})


async def _subdomains_crtsh(client: httpx.AsyncClient, domain: str) -> set[str]:
    resp = await client.get("https://crt.sh/",
                            params={"q": f"%.{domain}", "output": "json"},
                            headers=UA, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"crt.sh HTTP {resp.status_code}")
    subs = set()
    for e in resp.json():
        for n in str(e.get("name_value", "")).splitlines():
            n = n.strip().lstrip("*.").lower()
            if n.endswith("." + domain) and "@" not in n:
                subs.add(n)
    return subs


async def _subdomains_hackertarget(client: httpx.AsyncClient,
                                   domain: str) -> dict[str, str]:
    resp = await client.get("https://api.hackertarget.com/hostsearch/",
                            params={"q": domain}, timeout=20)
    if resp.status_code != 200 or "error" in resp.text.lower()[:60]:
        raise RuntimeError(f"hackertarget HTTP {resp.status_code}")
    return {line.split(",")[0].strip().lower(): line.split(",")[1].strip()
            for line in resp.text.splitlines()
            if "," in line and line.split(",")[0].strip().lower()
               .endswith("." + domain)}


async def check_subdomains(client: httpx.AsyncClient, domain: str) -> SiteResult:
    try:
        subs = await _subdomains_crtsh(client, domain)
        ordered = sorted(subs)
        if not ordered:
            return _r("subdomains", Status.NOT_FOUND,
                      "no subdomains in certificate transparency logs")
        return _r("subdomains", Status.FOUND,
                  f"{len(ordered)} unique subdomain(s) via crt.sh",
                  {"subdomains": ordered}, f"https://crt.sh/?q=%25.{domain}")
    except Exception as e:
        crt_err = e
    try:                                    # fallback: hackertarget hostsearch
        hosts = await _subdomains_hackertarget(client, domain)
    except Exception:
        return _r("subdomains", Status.UNKNOWN,
                  f"crt.sh: {crt_err}; fallback also failed")
    if not hosts:
        return _r("subdomains", Status.NOT_FOUND, "no known subdomains")
    ordered = sorted(hosts)
    return _r("subdomains", Status.FOUND,
              f"{len(ordered)} subdomain(s) via hackertarget",
              {"subdomains": ordered, "ips": hosts})


async def check_urlscan(client: httpx.AsyncClient, domain: str) -> SiteResult:
    try:
        resp = await client.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 25}, timeout=15)
    except Exception as e:
        return _r("urlscan", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("urlscan", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    results = js.get("results", [])
    if not results:
        return _r("urlscan", Status.NOT_FOUND, "no urlscan.io submissions")
    data = {
        "total_scans": js.get("total"),
        "recent": [{"url": r.get("page", {}).get("url"),
                    "date": (r.get("task", {}).get("time") or "")[:10],
                    "verdict": (r.get("verdicts", {}).get("overall") or {})
                               .get("verdict"),
                    "report": r.get("task", {}).get("reportURL")}
                   for r in results[:15]],
    }
    bad = sum(1 for r in data["recent"] if r["verdict"] == "malicious")
    reason = f"{data['total_scans']} scan(s) on urlscan.io"
    if bad:
        reason += f" — [bold red]{bad} flagged malicious[/bold red]"
    return _r("urlscan", Status.FOUND, reason, data,
              f"https://urlscan.io/search/#domain%3A{domain}")


async def check_wayback(client: httpx.AsyncClient, domain: str) -> SiteResult:
    try:
        first, last, count = await asyncio.gather(
            client.get("https://web.archive.org/cdx/search/cdx",
                       params={"url": domain, "output": "json", "fl": "timestamp",
                               "limit": 1}, timeout=20),
            client.get("https://web.archive.org/cdx/search/cdx",
                       params={"url": domain, "output": "json", "fl": "timestamp",
                               "limit": -1}, timeout=20),
            client.get("https://archive.org/wayback/available",
                       params={"url": domain}, timeout=15),
        )
    except Exception as e:
        return _r("wayback", Status.UNKNOWN, type(e).__name__)
    data: dict = {}
    try:
        rows = first.json()
        if len(rows) > 1:
            data["first_capture"] = rows[1][0][:8]
    except Exception:
        pass
    try:
        rows = last.json()
        if len(rows) > 1:
            data["last_capture"] = rows[-1][0][:8]
    except Exception:
        pass
    try:
        snap = count.json().get("archived_snapshots", {}).get("closest", {})
        if snap.get("available"):
            data["snapshot_url"] = snap.get("url")
    except Exception:
        pass
    if not data:
        return _r("wayback", Status.NOT_FOUND, "never archived by the Wayback Machine")
    for k in ("first_capture", "last_capture"):
        if data.get(k):
            data[k] = f"{data[k][:4]}-{data[k][4:6]}-{data[k][6:8]}"
    if data.get("first_capture"):
        reason = (f"archived {data['first_capture']} → "
                  f"{data.get('last_capture', '?')}")
    else:
        reason = "archived snapshots available (CDX index unreachable)"
    return _r("wayback", Status.FOUND, reason, data, data.get("snapshot_url"))


async def check_mailsec(client: httpx.AsyncClient, domain: str) -> SiteResult:
    txt, dmarc = await asyncio.gather(
        _doh(client, domain, "TXT"),
        _doh(client, f"_dmarc.{domain}", "TXT"))
    spf = [t for t in txt if t.startswith('"v=spf1') or t.startswith("v=spf1")]
    dmarc_rec = [t for t in dmarc if "v=DMARC1" in t]
    if not spf and not dmarc_rec:
        return _r("mailsec", Status.NOT_FOUND,
                  "no SPF and no DMARC — domain can't receive mail or is unprotected")
    data = {"spf": [s.strip('"') for s in spf],
            "dmarc": [d.strip('"') for d in dmarc_rec],
            "other_txt": [t.strip('"')[:120] for t in txt
                          if "v=spf1" not in t][:6]}
    missing = [x for x, recs in (("SPF", spf), ("DMARC", dmarc_rec)) if not recs]
    return _r("mailsec", Status.FOUND,
              ("SPF + DMARC configured" if not missing
               else f"missing: {', '.join(missing)}"), data)


async def check_ransomware(client: httpx.AsyncClient, domain: str) -> SiteResult:
    """Is this org a known ransomware-leak-site victim? (ransomware.live)"""
    try:
        resp = await client.get("https://data.ransomware.live/victims.json",
                                headers=UA, timeout=45)
    except Exception as e:
        return _r("ransomware", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("ransomware", Status.UNKNOWN, f"HTTP {resp.status_code}")
    try:
        victims = resp.json()
    except Exception:
        return _r("ransomware", Status.UNKNOWN, "bad response")
    hits = []
    for v in victims:
        hay = " ".join(str(v.get(k, "") or "")
                       for k in ("website", "domain", "post_title",
                                 "victim")).lower()
        if domain in hay:
            hits.append({
                "victim": v.get("post_title") or v.get("victim") or "?",
                "group": v.get("group_name"),
                "date": (v.get("attackdate") or v.get("discovered") or "")[:10],
                "claim": v.get("claim_url") or v.get("post_url"),
            })
    if not hits:
        return _r("ransomware", Status.NOT_FOUND,
                  "no ransomware leak-site victim matches this domain")
    groups = sorted({h["group"] for h in hits if h["group"]})
    return _r("ransomware", Status.FOUND,
              f"[bold red]{len(hits)} leak-site victim post(s)[/bold red] "
              f"by: {', '.join(groups[:5])}",
              {"victims": hits[:15]},
              "https://www.ransomware.live/")


SEC_HEADERS = ["content-security-policy", "strict-transport-security",
               "x-frame-options", "x-content-type-options",
               "referrer-policy", "permissions-policy"]


async def check_headers(client: httpx.AsyncClient, domain: str) -> SiteResult:
    """Security headers + server/powered-by fingerprint."""
    try:
        resp = await client.get(f"https://{domain}/", headers=UA, timeout=15)
    except Exception as e:
        return _r("headers", Status.UNKNOWN, type(e).__name__)
    h = {k.lower(): v for k, v in resp.headers.items()}
    present = {k: h[k][:120] for k in SEC_HEADERS if k in h}
    missing = [k for k in SEC_HEADERS if k not in h]
    data = {"server": h.get("server"), "powered_by": h.get("x-powered-by"),
            "present": present, "missing": missing,
            "generator": None}
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)',
                  resp.text[:60000], re.I)
    if m:
        data["generator"] = m.group(1)
    fp = ", ".join(x for x in (data["server"], data["powered_by"],
                               data["generator"]) if x) or "?"
    grade = "good" if len(present) >= 4 else \
            ("partial" if present else "none")
    return _r("headers", Status.FOUND,
              f"{len(present)}/{len(SEC_HEADERS)} sec headers ({grade}) · {fp}",
              data)


def _tls_probe(domain: str) -> dict:
    import socket, ssl
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as s:
            cert = s.getpeercert()
    issuer = dict(x[0] for x in cert.get("issuer", []))
    exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
    return {"issuer": issuer.get("organizationName") or
            issuer.get("commonName") or "?",
            "expires": exp.strftime("%Y-%m-%d"),
            "days_left": (exp - datetime.utcnow()).days,
            "san_count": len(cert.get("subjectAltName", []))}


async def check_tls(client: httpx.AsyncClient, domain: str) -> SiteResult:
    try:
        d = await asyncio.to_thread(_tls_probe, domain)
    except Exception as e:
        return _r("tls", Status.UNKNOWN, type(e).__name__)
    warn = " [red]EXPIRED[/red]" if d["days_left"] < 0 else \
           (" [yellow]expires soon[/yellow]" if d["days_left"] < 21 else "")
    return _r("tls", Status.FOUND,
              f"{d['issuer']} · expires {d['expires']} ({d['days_left']}d){warn} · "
              f"{d['san_count']} SANs", d)


async def check_sectxt(client: httpx.AsyncClient, domain: str) -> SiteResult:
    for path in ("/.well-known/security.txt", "/security.txt"):
        try:
            resp = await client.get(f"https://{domain}{path}",
                                    headers=UA, timeout=10)
        except Exception as e:
            return _r("security.txt", Status.UNKNOWN, type(e).__name__)
        if resp.status_code == 200 and "contact" in resp.text.lower():
            contacts = [l.split(":", 1)[1].strip() for l in
                        resp.text.splitlines() if l.lower().startswith("contact:")]
            return _r("security.txt", Status.FOUND,
                      f"published — contact: {', '.join(contacts[:3]) or '?'}",
                      {"contacts": contacts, "path": path},
                      f"https://{domain}{path}")
    return _r("security.txt", Status.NOT_FOUND, "no security.txt")


async def check_intelx(client: httpx.AsyncClient, domain: str) -> SiteResult:
    """IntelX search on the domain — leak dumps & pastes mentioning it."""
    from .intelx import intelx_search
    from .config import intelx_key
    if not intelx_key():
        return _r("intelx", Status.UNKNOWN,
                  "skipped — set INTELX_KEY in .env (free at intelx.io)")
    res = await intelx_search(client, domain, maxresults=15)
    if res["error"]:
        return _r("intelx", Status.UNKNOWN, res["error"])
    recs = res["records"]
    if not recs:
        return _r("intelx", Status.NOT_FOUND, "no intelx records")
    buckets = sorted({r["bucket"] for r in recs if r.get("bucket")})
    return _r("intelx", Status.FOUND,
              f"{len(recs)} record(s) in leaks/pastes/darknet",
              {"records": recs[:15], "buckets": buckets})


MODULES = [
    ("dns", check_dns),
    ("rdap", check_rdap),
    ("subdomains", check_subdomains),
    ("headers", check_headers),
    ("tls", check_tls),
    ("security.txt", check_sectxt),
    ("urlscan", check_urlscan),
    ("wayback", check_wayback),
    ("mailsec", check_mailsec),
    ("ransomware", check_ransomware),
    ("intelx", check_intelx),
]

DOMAIN_RE = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
                       r"[a-zA-Z]{2,63}$")


async def run_domain_scan(domain: str, timeout: float = 15.0,
                          proxy: str | None = None) -> list[SiteResult]:
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        return await asyncio.gather(*(fn(client, domain) for _, fn in MODULES))
