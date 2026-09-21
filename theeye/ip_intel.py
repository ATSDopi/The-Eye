"""Free IP intelligence — no API keys required.

Modules:
  internetdb  Shodan InternetDB: open ports, CPEs, CVEs, hostnames, tags
  rdap        network range, owner org, country (rdap.org)
  geo         geolocation + ASN + vpn/tor/datacenter/abuse flags (ipapi.is)
  ptr         reverse DNS records (Google DoH)
"""

from __future__ import annotations

import asyncio
import ipaddress
import re

import httpx

from .engine import USER_AGENTS
from .models import SiteResult, Status

UA = {"User-Agent": USER_AGENTS[0]}


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


def _ptr_name(ip: str) -> str:
    a = ipaddress.ip_address(ip)
    if a.version == 4:
        return ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    return ".".join(reversed(a.exploded.replace(":", ""))) + ".ip6.arpa"


async def check_internetdb(client: httpx.AsyncClient, ip: str) -> SiteResult:
    try:
        resp = await client.get(f"https://internetdb.shodan.io/{ip}",
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("internetdb", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 404:
        return _r("internetdb", Status.NOT_FOUND,
                  "no scan data (never seen / nothing exposed)")
    if resp.status_code != 200:
        return _r("internetdb", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    data = {k: js.get(k) for k in ("ports", "vulns", "cpes", "hostnames", "tags")
            if js.get(k)}
    ports = ",".join(str(p) for p in js.get("ports", [])[:12]) or "none"
    vulns = js.get("vulns", [])
    reason = f"ports: {ports}"
    if vulns:
        reason += f" — [bold red]{len(vulns)} CVE(s)[/bold red]"
    return _r("internetdb", Status.FOUND, reason, data,
              f"https://internetdb.shodan.io/{ip}")


async def check_ip_rdap(client: httpx.AsyncClient, ip: str) -> SiteResult:
    try:
        resp = await client.get(f"https://rdap.org/ip/{ip}",
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("rdap", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 404:
        return _r("rdap", Status.NOT_FOUND, "no RDAP record (bogon/reserved)")
    if resp.status_code != 200:
        return _r("rdap", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    data: dict = {"range": f"{js.get('startAddress','?')} - {js.get('endAddress','?')}",
                  "name": js.get("name"), "country": js.get("country"),
                  "type": js.get("type")}
    for ent in js.get("entities", []):
        if "registrant" in ent.get("roles", []) or "abuse" in ent.get("roles", []):
            try:
                fn = next(i[3] for i in ent["vcardArray"][1] if i[0] == "fn")
                data.setdefault("owner", fn)
            except Exception:
                pass
        # nested entities often carry the actual org
        for sub in ent.get("entities", []):
            try:
                fn = next(i[3] for i in sub["vcardArray"][1] if i[0] == "fn")
                data.setdefault("owner", fn)
            except Exception:
                pass
    who = data.get("owner") or data.get("name") or "?"
    return _r("rdap", Status.FOUND,
              f"{who} — {data['range']} ({data.get('country') or '?'})",
              {k: v for k, v in data.items() if v})


async def check_geo(client: httpx.AsyncClient, ip: str) -> SiteResult:
    try:
        resp = await client.get("https://api.ipapi.is/",
                                params={"q": ip}, timeout=15)
    except Exception as e:
        return _r("geo", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("geo", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if js.get("is_bogon"):
        return _r("geo", Status.NOT_FOUND, "bogon / reserved address")
    # free tier returns flat fields; richer responses nest asn/location
    asn = js.get("asn") or {}
    if isinstance(asn, dict):
        asn_s = f"AS{asn.get('asn')}" if asn.get("asn") else None
        org = asn.get("org")
    else:
        asn_s, org = asn, None
    loc = js.get("location") or {}
    flags = [k.replace("is_", "") for k in ("is_vpn", "is_tor", "is_datacenter",
             "is_proxy", "is_abuser", "is_crawler", "is_mobile") if js.get(k)]
    comp = js.get("company")
    data = {
        "asn": asn_s,
        "org": org or (comp.get("name") if isinstance(comp, dict) else comp),
        "city": loc.get("city") or js.get("city"),
        "region": loc.get("region") or js.get("region"),
        "country": loc.get("country") or js.get("country"),
        "coords": (f"{js['lat']},{js['lon']}"
                   if js.get("lat") is not None else None),
        "timezone": js.get("timezone"),
        "flags": flags,
    }
    data = {k: v for k, v in data.items() if v}
    geo = ", ".join(x for x in (data.get("city"), data.get("country")) if x)
    reason = f"{data.get('asn') or ''} {data.get('org') or ''} — {geo}"
    if flags:
        reason += f" — [yellow]{', '.join(flags)}[/yellow]"
    return _r("geo", Status.FOUND, reason.strip(" —"), data)


async def check_ptr(client: httpx.AsyncClient, ip: str) -> SiteResult:
    try:
        resp = await client.get("https://dns.google/resolve",
                                params={"name": _ptr_name(ip), "type": "PTR"},
                                timeout=10)
        ans = resp.json().get("Answer", [])
        ptrs = [a["data"].rstrip(".") for a in ans if a.get("type") == 12]
    except Exception as e:
        return _r("ptr", Status.UNKNOWN, type(e).__name__)
    if not ptrs:
        return _r("ptr", Status.NOT_FOUND, "no reverse DNS")
    return _r("ptr", Status.FOUND,
              f"{len(ptrs)} PTR record(s)", {"hostnames": ptrs})


async def check_tor(client: httpx.AsyncClient, ip: str) -> SiteResult:
    """Is this IP a current Tor exit node? (official bulk exit list)"""
    try:
        v = ipaddress.ip_address(ip).version
        url = ("https://check.torproject.org/torbulkexitlist" if v == 4
               else "https://check.torproject.org/torbulkexitlist-ipv6")
        resp = await client.get(url, headers=UA, timeout=20)
    except Exception as e:
        return _r("tor", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("tor", Status.UNKNOWN, f"HTTP {resp.status_code}")
    exits = set(resp.text.split())
    if ip in exits:
        return _r("tor", Status.FOUND,
                  "[bold red]active Tor exit node[/bold red]",
                  {"exit_node": True})
    return _r("tor", Status.NOT_FOUND, "not a current Tor exit")


async def check_threatfox(client: httpx.AsyncClient, ip: str) -> SiteResult:
    """abuse.ch ThreatFox — is this IP a known malware IOC?"""
    try:
        resp = await client.post("https://threatfox-api.abuse.ch/api/v1/",
                                 json={"query": "search_ioc",
                                       "search_term": ip},
                                 headers=UA, timeout=15)
    except Exception as e:
        return _r("threatfox", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("threatfox", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if js.get("query_status") == "no_result":
        return _r("threatfox", Status.NOT_FOUND, "no malware IOC")
    data = js.get("data") or []
    if not data:
        return _r("threatfox", Status.UNKNOWN, str(js.get("query_status")))
    malware = sorted({d.get("malware_printable") or "?"
                      for d in data})
    types = sorted({d.get("ioc_type") for d in data if d.get("ioc_type")})
    return _r("threatfox", Status.FOUND,
              f"[bold red]{len(data)} IOC(s)[/bold red] — "
              f"{', '.join(malware[:5])} ({', '.join(types[:4])})",
              {"iocs": [{"malware": d.get("malware_printable"),
                         "type": d.get("ioc_type"),
                         "confidence": d.get("confidence_level"),
                         "first_seen": d.get("first_seen")}
                        for d in data[:15]]})


MODULES = [
    ("internetdb", check_internetdb),
    ("rdap", check_ip_rdap),
    ("geo", check_geo),
    ("ptr", check_ptr),
    ("tor", check_tor),
    ("threatfox", check_threatfox),
]


async def run_ip_scan(ip: str, timeout: float = 15.0,
                      proxy: str | None = None) -> list[SiteResult]:
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        return await asyncio.gather(*(fn(client, ip) for _, fn in MODULES))
