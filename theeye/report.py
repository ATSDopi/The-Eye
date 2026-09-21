"""Self-contained HTML report (dark theme, no external deps)."""

from __future__ import annotations

import html
import json
from datetime import datetime

from .models import ScanReport, Status

CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#e6edf3;--mut:#8b949e;
--acc:#f78166;--ok:#3fb950;--warn:#d29922;--bad:#f85149}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:14px/1.5 -apple-system,"Segoe UI",Roboto,sans-serif}
header{padding:24px 32px;border-bottom:1px solid var(--border);display:flex;
flex-wrap:wrap;gap:16px;align-items:baseline}
h1{font-size:22px;margin:0}h1 em{color:var(--acc);font-style:normal}
.mut{color:var(--mut)}.stats{display:flex;gap:12px;flex-wrap:wrap;margin-left:auto}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:8px;
padding:8px 14px;text-align:center}.stat b{display:block;font-size:18px}
.controls{padding:12px 32px;display:flex;gap:10px;flex-wrap:wrap}
input[type=search]{background:var(--panel);border:1px solid var(--border);
border-radius:6px;color:var(--fg);padding:7px 12px;min-width:260px}
select{background:var(--panel);border:1px solid var(--border);color:var(--fg);
border-radius:6px;padding:7px}
main{padding:0 32px 40px}
table{width:100%;border-collapse:collapse;background:var(--panel);
border:1px solid var(--border);border-radius:10px;overflow:hidden}
th{position:sticky;top:0;background:#1c2129;text-align:left;padding:10px 12px;
font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);
cursor:pointer;user-select:none}
td{padding:9px 12px;border-top:1px solid var(--border);vertical-align:top}
tr:hover td{background:#1c212966}
a{color:#58a6ff;text-decoration:none}a:hover{text-decoration:underline}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:11px;
font-weight:600}
.b-high{background:#3fb95022;color:var(--ok);border:1px solid #3fb95055}
.b-medium{background:#d2992222;color:var(--warn);border:1px solid #d2992255}
.b-low{background:#f8514922;color:var(--bad);border:1px solid #f8514955}
.b-ver{background:#3fb95022;color:var(--ok);border:1px solid #3fb95055}
.b-fp{background:#f8514922;color:var(--bad);border:1px solid #f8514955}
tr.fp td{opacity:.55}
.tag{display:inline-block;background:#21262d;border:1px solid var(--border);
border-radius:8px;padding:0 6px;font-size:11px;color:var(--mut);margin:1px}
.enr{color:var(--mut);font-size:12px;max-width:420px}
.enr img{width:34px;height:34px;border-radius:6px;object-fit:cover;
vertical-align:middle;margin-right:8px}
footer{padding:20px 32px;color:var(--mut);font-size:12px;border-top:1px solid var(--border)}
"""

JS = """
const q=document.getElementById('q'),cf=document.getElementById('conf'),vf=document.getElementById('ver');
function f(){const s=q.value.toLowerCase(),c=cf.value,v=vf.value;
document.querySelectorAll('#t tbody tr').forEach(r=>{
r.style.display=(r.textContent.toLowerCase().includes(s)&&(!c||r.dataset.conf===c)
&&(!v||r.dataset.ver===v))?'':'none'})}
q.oninput=f;cf.onchange=f;vf.onchange=f;
document.querySelectorAll('th').forEach((th,i)=>th.onclick=()=>{
const tb=document.querySelector('#t tbody');const asc=th.dataset.a!=='1';
th.dataset.a=asc?'1':'0';
[...tb.rows].sort((a,b)=>a.cells[i].textContent.localeCompare(b.cells[i].textContent)
*(asc?1:-1)).forEach(r=>tb.appendChild(r))});
"""


def _badge(conf: str) -> str:
    return f'<span class="badge b-{conf}">{conf}</span>'


def _vbadge(ver: str) -> str:
    if ver == "confirmed":
        return '<span class="badge b-ver">verified</span>'
    if ver == "fp":
        return '<span class="badge b-fp">likely fp</span>'
    return '<span class="badge" style="color:var(--mut)">?</span>'


def _enr(enr: dict) -> str:
    if not enr:
        return ""
    parts = []
    img = enr.get("avatar") or enr.get("ld_image")
    if img:
        parts.append(f'<img src="{html.escape(str(img))}" loading="lazy" onerror="this.remove()">')
    bits = []
    for k, label in (("og_title", ""), ("ld_name", ""), ("ld_alternateName", "aka "),
                     ("description", ""), ("followers", ""), ("ld_location", "")):
        if enr.get(k):
            v = html.escape(str(enr[k]))
            bits.append(f"<b>{v}</b>" if k in ("og_title", "ld_name") else f"{label}{v}")
    return '<div class="enr">' + "".join(parts) + "<br>".join(bits[:3]) + "</div>"


def render_html(report: ScanReport) -> str:
    s = report.summary()
    found = [r for r in report.results if r.status == Status.FOUND]
    found.sort(key=lambda r: (r.verified == "fp", r.rank or 10**9,
                              -(r.response_ms or 0)))
    n_fp = sum(1 for r in found if r.verified == "fp")

    rows = []
    for r in found:
        tags = " ".join(f'<span class="tag">{html.escape(t)}</span>' for t in r.tags[:4])
        fpcls = ' class="fp"' if r.verified == "fp" else ""
        rows.append(
            f'<tr data-conf="{r.confidence}" data-ver="{r.verified or "unverified"}"{fpcls}>'
            f"<td><b>{html.escape(r.site)}</b></td>"
            f"<td>{_vbadge(r.verified)}</td>"
            f'<td><a href="{html.escape(r.url or "")}" target="_blank">{html.escape(r.url or "")}</a></td>'
            f"<td>{_badge(r.confidence)}</td>"
            f"<td>{html.escape(str(r.query))}</td>"
            f"<td>{r.http_code or ''}</td>"
            f"<td>{r.response_ms or ''}</td>"
            f"<td>{tags}</td>"
            f"<td>{_enr(r.enriched)}</td></tr>"
        )

    stats = "".join(
        f'<div class="stat"><b>{v}</b><span class="mut">{k}</span></div>'
        for k, v in (("found", s["found"]), ("likely fp", n_fp),
                     ("not found", s["not_found"]),
                     ("unknown", s["unknown"]), ("checked", s["total"]),
                     ("seconds", s["duration_s"]))
    )
    raw = html.escape(json.dumps(report.summary()))
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>The Eye — {html.escape(report.username)}</title><style>{CSS}</style></head><body>
<header><h1>The Eye — <em>{html.escape(report.username)}</em></h1>
<span class="mut">{datetime.fromtimestamp(report.started):%Y-%m-%d %H:%M} · case "{html.escape(report.case)}"</span>
<div class="stats">{stats}</div></header>
<div class="controls"><input id="q" type="search" placeholder="Filter results...">
<select id="conf"><option value="">all confidence</option><option>high</option>
<option>medium</option><option>low</option></select>
<select id="ver"><option value="">all results</option><option value="confirmed">
verified</option><option value="fp">likely fp</option>
<option value="unverified">unverified</option></select></div>
<main><table id="t"><thead><tr><th>Site</th><th>Verified</th><th>Profile URL</th><th>Confidence</th>
<th>Query</th><th>HTTP</th><th>ms</th><th>Tags</th><th>Extracted</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></main>
<footer>generated by The Eye · {s['total']} sites checked · summary: {raw}</footer>
<script>{JS}</script></body></html>"""


def write_html(report: ScanReport, path: str) -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(render_html(report))
    return path


LEVEL_COLOR = {"clean": "#3fb950", "low": "#d29922", "moderate": "#db6d28",
               "high": "#f85149", "critical": "#ff2d2d"}


def render_breach_html(email: str, agg: dict, started: float) -> str:
    level = agg["level"]
    col = LEVEL_COLOR[level]
    breach_rows = "".join(
        f"<tr><td><b>{html.escape(b['name'])}</b></td>"
        f"<td>{html.escape(b['date'] or 'unknown')}</td>"
        f"<td>{html.escape(', '.join(b['via']))}</td></tr>"
        for b in agg["breaches"])
    steal_rows = "".join(
        f"<tr><td>{html.escape(str(s.get('date') or '?'))[:10]}</td>"
        f"<td>{html.escape(str(s.get('os') or '?'))}</td>"
        f"<td>{html.escape(str(s.get('computer') or '?'))}</td>"
        f"<td class='mut'>{html.escape(str(s.get('malware_path') or ''))}</td></tr>"
        for s in agg["stealers"])
    cred_rows = "".join(
        f"<tr><td class='mut'>{html.escape(l)}</td></tr>"
        for l in agg["cred_lines"])
    src_rows = "".join(
        f"<tr><td>{html.escape(k)}</td><td>{html.escape(v)}</td></tr>"
        for k, v in agg["per_source"].items())
    fields = " ".join(f'<span class="tag">{html.escape(f)}</span>'
                      for f in agg["fields"])
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>The Eye — breach report {html.escape(email)}</title><style>{CSS}
.sev{{font-size:28px;font-weight:800;color:{col};text-transform:uppercase}}
h2{{margin:28px 0 10px;font-size:15px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut)}}
</style></head><body>
<header><h1>Breach report — <em>{html.escape(email)}</em></h1>
<span class="mut">{datetime.fromtimestamp(started):%Y-%m-%d %H:%M}</span>
<div class="stats">
<div class="stat"><b class="sev">{level}</b><span class="mut">exposure</span></div>
<div class="stat"><b>{len(agg['breaches'])}</b><span class="mut">breaches</span></div>
<div class="stat"><b>{len(agg['stealers'])}</b><span class="mut">stealer infections</span></div>
<div class="stat"><b>{len(agg['cred_lines'])}</b><span class="mut">credential lines</span></div>
</div></header><main>
<h2>Breach timeline</h2>
<table><thead><tr><th>Breach</th><th>Date</th><th>Source(s)</th></tr></thead>
<tbody>{breach_rows or '<tr><td colspan=3 class="mut">no breaches found</td></tr>'}</tbody></table>
<h2>Leaked field types</h2><p>{fields or '<span class=mut>unknown</span>'}</p>
<h2>Infostealer infections</h2>
<table><thead><tr><th>Date</th><th>OS</th><th>Computer</th><th>Malware path</th></tr></thead>
<tbody>{steal_rows or '<tr><td colspan=4 class="mut">none detected</td></tr>'}</tbody></table>
<h2>Credential lines (masked)</h2>
<table><tbody>{cred_rows or '<tr><td class="mut">none</td></tr>'}</tbody></table>
<h2>Source coverage</h2>
<table><thead><tr><th>Source</th><th>Result</th></tr></thead>
<tbody>{src_rows}</tbody></table>
</main><footer>generated by The Eye · credentials are masked ·
verify findings before acting on them</footer></body></html>"""


def render_dossier_html(fields: dict, first: str, last: str,
                        identity: dict) -> str:
    """Standalone identity-graph page for `theeye dossier --html`."""
    supplied = {k: v for k, v in fields.items() if v}
    if first or last:
        supplied["name"] = f"{first} {last}".strip()
    sup_rows = "".join(
        f"<tr><td><b>{html.escape(k)}</b></td>"
        f"<td>{html.escape(str(v))}</td></tr>"
        for k, v in supplied.items())
    ent_rows = ""
    for k, vals in sorted(identity.items()):
        vals = sorted(vals)
        if not vals:
            continue
        lis = "".join(f"<li>{html.escape(str(v))}</li>" for v in vals)
        ent_rows += (f"<tr><td><b>{html.escape(k)}</b></td>"
                     f"<td><ul style='margin:0;padding-left:18px'>{lis}</ul>"
                     f"</td></tr>")
    n = sum(len(v) for v in identity.values())
    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>The Eye — dossier</title><style>{CSS}
h2{{margin:28px 0 10px;font-size:15px;text-transform:uppercase;
letter-spacing:.05em;color:var(--mut)}}
</style></head><body>
<header><h1>The Eye — <em>dossier</em></h1>
<span class="mut">{datetime.now():%Y-%m-%d %H:%M}</span>
<div class="stats">
<div class="stat"><b>{len(supplied)}</b><span class="mut">fields supplied</span></div>
<div class="stat"><b>{n}</b><span class="mut">entities correlated</span></div>
</div></header><main>
<h2>Supplied fields</h2>
<table><tbody>{sup_rows or '<tr><td class="mut">none</td></tr>'}</tbody></table>
<h2>Identity graph — everything correlated</h2>
<table><thead><tr><th>Entity</th><th>Value(s)</th></tr></thead>
<tbody>{ent_rows or '<tr><td colspan=2 class="mut">nothing correlated</td></tr>'}</tbody></table>
</main><footer>generated by The Eye · correlation != confirmation —
verify before acting</footer></body></html>"""
