"""Structured investigation report creator ("doxx").

Collects everything already known about a subject — interactively or via
flags — then writes a clean standalone HTML/JSON report. Field sections are
grouped into presets so you only fill what's relevant. Optionally runs the
full dossier investigation first and embeds the correlated identity graph.
"""
from __future__ import annotations

import html
import json
import re
import time
from datetime import datetime
from pathlib import Path

# (section key, label, [(field key, prompt, multi-value?)])
SECTIONS: list[tuple[str, str, list[tuple[str, str, bool]]]] = [
    ("case", "Case", [
        ("title", "Report title / codename", False),
        ("investigator", "Investigator handle", False),
        ("classification", "Classification (e.g. internal / confidential)", False),
    ]),
    ("identity", "Identity", [
        ("first", "First name", False),
        ("middle", "Middle name(s)", False),
        ("last", "Last name", False),
        ("aliases", "Aliases / nicknames (comma-separated)", True),
        ("dob", "Date of birth", False),
        ("nationality", "Nationality", False),
        ("occupation", "Occupation / employer", False),
    ]),
    ("digital", "Digital footprint", [
        ("usernames", "Usernames (comma-separated)", True),
        ("emails", "Email addresses (comma-separated)", True),
        ("phones", "Phone numbers (comma-separated)", True),
        ("profiles", "Known profile URLs (comma-separated)", True),
    ]),
    ("network", "Infrastructure", [
        ("domains", "Domains (comma-separated)", True),
        ("ips", "IP addresses (comma-separated)", True),
        ("crypto", "Crypto wallets (comma-separated)", True),
    ]),
    ("location", "Location", [
        ("addresses", "Postal addresses (one per line, empty ends)", "lines"),
        ("city", "City", False),
        ("country", "Country", False),
    ]),
    ("context", "Context", [
        ("associates", "Known associates (comma-separated)", True),
        ("vehicles", "Vehicles / plates (comma-separated)", True),
        ("notes", "Notes — free text, one per line, empty ends", "lines"),
    ]),
]

PRESETS: dict[str, list[str]] = {
    "full":     [s for s, _, _ in SECTIONS],
    "identity": ["case", "identity", "digital", "location"],
    "digital":  ["case", "digital", "network", "context"],
    "network":  ["case", "network"],
    "minimal":  ["case", "identity"],
}


def sections_for(preset: str) -> list[tuple[str, str, list]]:
    keys = PRESETS.get(preset, PRESETS["full"])
    return [s for s in SECTIONS if s[0] in keys]


def collect_interactive(console, preset: str) -> dict:
    """Prompt every field of the preset; blank = skipped."""
    from rich.prompt import Prompt

    data: dict[str, list[str]] = {}
    console.print("[bold]Leave a field empty to skip it.[/bold] "
                  "Comma-separate multiple values.")
    for _key, label, fields in sections_for(preset):
        console.print(f"\n[bold cyan]{label}[/bold cyan]")
        for fkey, prompt, multi in fields:
            if multi == "lines":
                vals = []
                while True:
                    v = Prompt.ask(f"  {prompt}", default="")
                    if not v:
                        break
                    vals.append(v)
                if vals:
                    data[fkey] = vals
                continue
            v = Prompt.ask(f"  {prompt}", default="").strip()
            if not v:
                continue
            if multi is True:
                data[fkey] = [x.strip() for x in v.split(",") if x.strip()]
            else:
                data[fkey] = [v]
    return data


def collect_from_args(args) -> dict:
    """Non-interactive: every --field becomes report data."""
    data: dict[str, list[str]] = {}
    for _sk, _sl, fields in SECTIONS:
        for fkey, _p, multi in fields:
            raw = getattr(args, fkey, None)
            if not raw:
                continue
            vals = ([x.strip() for x in raw.split(",") if x.strip()]
                    if multi is True else [raw])
            if vals:
                data[fkey] = vals
    return data


def split_values(v) -> list[str]:
    """'a, b ,c' -> ['a','b','c'] ; None -> [] ; str -> [str]."""
    if not v:
        return []
    if isinstance(v, list):
        return [x for x in v if x]
    return [x.strip() for x in str(v).split(",") if x.strip()]


# ------------------------------------------------------------------ dossier
# bridge: doxx fields -> dossier CLI flags

def dossier_args(data: dict) -> dict:
    """Map collected doxx data onto run_dossier fields (first value wins)."""
    first = (data.get("first") or [""])[0]
    last = " ".join(filter(None, [(data.get("middle") or [""])[0],
                                  (data.get("last") or [""])[0]]))
    return {
        "first": first, "last": last,
        "username": (data.get("usernames") or [None])[0],
        "extra_usernames": (data.get("usernames") or [None, ])[1:] or [],
        "email": (data.get("emails") or [None])[0],
        "extra_emails": (data.get("emails") or [None, ])[1:] or [],
        "phone": (data.get("phones") or [None])[0],
        "domain": (data.get("domains") or [None])[0],
        "ip": (data.get("ips") or [None])[0],
        "address": (data.get("addresses") or [None])[0],
        "crypto": (data.get("crypto") or [None])[0],
    }


# ------------------------------------------------------------------ render

_LABELS = {f: p.rstrip(" —").split("(")[0].strip()
           for _s, _l, fields in SECTIONS for f, p, _m in fields}
_SECTION_LABELS = {k: l for k, l, _f in SECTIONS}


def render_doxx_html(data: dict, preset: str,
                     identity: dict | None = None) -> str:
    from .report import CSS  # reuse the house style

    title = (data.get("title") or ["Unnamed subject"])[0]
    meta = [datetime.now().strftime("%Y-%m-%d %H:%M"),
            f"preset: {preset}"]
    if data.get("investigator"):
        meta.append(f"by {data['investigator'][0]}")
    if data.get("classification"):
        meta.append(f"classification: {data['classification'][0]}")

    # subject headline = name or first username
    name = " ".join(x for x in [(data.get("first") or [""])[0],
                                (data.get("middle") or [""])[0],
                                (data.get("last") or [""])[0]] if x).strip()
    subject = name or (data.get("usernames") or
                       data.get("emails") or ["—"])[0]

    parts = []
    for skey, slabel, fields in sections_for(preset):
        if skey == "case":
            continue
        rows = ""
        for fkey, _p, _m in fields:
            vals = data.get(fkey)
            if not vals:
                continue
            lis = "".join(f"<li>{html.escape(str(v))}</li>" for v in vals)
            rows += (f"<tr><td style='width:190px'><b>"
                     f"{html.escape(_LABELS.get(fkey, fkey))}</b></td>"
                     f"<td><ul style='margin:0;padding-left:18px'>{lis}</ul>"
                     f"</td></tr>")
        if rows:
            parts.append(f"<h2>{html.escape(slabel)}</h2>"
                         f"<table><tbody>{rows}</tbody></table>")

    ent_html = ""
    if identity:
        rows = ""
        for k in ("usernames", "names", "emails", "phones", "addresses",
                  "domains", "crypto", "accounts_registered", "profiles"):
            vals = sorted(identity.get(k) or [])
            if not vals:
                continue
            lis = "".join(f"<li>{html.escape(str(v))}</li>" for v in vals)
            rows += (f"<tr><td style='width:190px'><b>{html.escape(k)}</b></td>"
                     f"<td><ul style='margin:0;padding-left:18px'>"
                     f"{lis}</ul></td></tr>")
        if rows:
            ent_html = ("<h2>Investigation — correlated identity graph</h2>"
                        f"<table><thead><tr><th>Entity</th><th>Value(s)</th>"
                        f"</tr></thead><tbody>{rows}</tbody></table>")

    n_fields = sum(len(v) for v in data.values())
    n_ent = sum(len(v) for v in (identity or {}).values())
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>The Eye — {html.escape(title)}</title><style>{CSS}
h2{{margin:28px 0 10px;font-size:15px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut)}}
.subject{{font-size:26px;font-weight:700;margin:6px 0 2px}}
</style></head><body>
<header><h1>The Eye — <em>investigation report</em></h1>
<span class="mut">{' · '.join(html.escape(m) for m in meta)}</span>
<div class="subject">{html.escape(subject)}</div>
<div class="stats">
<div class="stat"><b>{n_fields}</b><span class="mut">known facts</span></div>
<div class="stat"><b>{n_ent}</b><span class="mut">correlated entities</span></div>
</div></header><main>
{''.join(parts) or '<p class="mut">No data supplied.</p>'}
{ent_html}
</main><footer>generated by The Eye · correlation != confirmation —
verify everything before acting · for lawful investigations only
</footer></body></html>"""


def save_doxx(data: dict, preset: str, identity: dict | None,
              html_path: str | None) -> tuple[str, str]:
    """Write reports/doxx-<slug>-<ts>.html + .json; returns both paths."""
    out = Path("reports")
    out.mkdir(exist_ok=True)
    slug = re.sub(r"[^a-z0-9]+", "-",
                  ((data.get("title") or ["subject"])[0]).lower()).strip("-")
    ts = int(time.time())
    jpath = out / f"doxx-{slug}-{ts}.json"
    jpath.write_text(json.dumps(
        {"preset": preset, "generated": datetime.now().isoformat(),
         "fields": data, "identity": {k: sorted(v) for k, v in
                                      (identity or {}).items()}},
        ensure_ascii=False, indent=1), encoding="utf-8")
    hpath = html_path or str(out / f"doxx-{slug}-{ts}.html")
    Path(hpath).write_text(render_doxx_html(data, preset, identity),
                          encoding="utf-8")
    return str(jpath), hpath
