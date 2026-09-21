"""Phone intelligence.

Local parsing via libphonenumber (offline) + leak/dump sources that accept
phone numbers: leakcheck, proxynova COMB, intelx (if INTELX_KEY set).
"""

from __future__ import annotations

import asyncio
import re

import httpx
import phonenumbers
from phonenumbers import carrier, geocoder, timezone

from .engine import USER_AGENTS
from .models import SiteResult, Status
from .email_intel import _mask

UA = {"User-Agent": USER_AGENTS[0]}

TYPE_NAMES = {
    phonenumbers.PhoneNumberType.MOBILE: "mobile",
    phonenumbers.PhoneNumberType.FIXED_LINE: "fixed line",
    phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed/mobile",
    phonenumbers.PhoneNumberType.VOIP: "voip",
    phonenumbers.PhoneNumberType.TOLL_FREE: "toll-free",
    phonenumbers.PhoneNumberType.PREMIUM_RATE: "premium rate",
    phonenumbers.PhoneNumberType.SHARED_COST: "shared cost",
    phonenumbers.PhoneNumberType.PERSONAL_NUMBER: "personal",
    phonenumbers.PhoneNumberType.PAGER: "pager",
    phonenumbers.PhoneNumberType.UAN: "UAN",
    phonenumbers.PhoneNumberType.VOICEMAIL: "voicemail",
    phonenumbers.PhoneNumberType.UNKNOWN: "unknown",
}


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


def e164(number: str) -> str | None:
    try:
        n = phonenumbers.parse(number, None)
        if phonenumbers.is_possible_number(n):
            return phonenumbers.format_number(
                n, phonenumbers.PhoneNumberFormat.E164)
    except phonenumbers.NumberParseException:
        pass
    return None


def check_parse(number: str) -> SiteResult:
    r = _r("phonenum", Status.UNKNOWN, "")
    try:
        n = phonenumbers.parse(number, None)
    except phonenumbers.NumberParseException as e:
        r.status = Status.ILLEGAL
        r.reason = f"cannot parse: {e}"
        return r
    r.enriched = {
        "e164": phonenumbers.format_number(n, phonenumbers.PhoneNumberFormat.E164),
        "international": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
        "national": phonenumbers.format_number(
            n, phonenumbers.PhoneNumberFormat.NATIONAL),
        "country_code": f"+{n.country_code}",
        "region": geocoder.description_for_number(n, "en"),
        "carrier": carrier.name_for_number(n, "en"),
        "line_type": TYPE_NAMES.get(phonenumbers.number_type(n), "unknown"),
        "timezones": list(timezone.time_zones_for_number(n)),
        "possible": phonenumbers.is_possible_number(n),
        "valid": phonenumbers.is_valid_number(n),
    }
    if r.enriched["valid"]:
        r.status = Status.FOUND
        r.reason = (f"valid {r.enriched['line_type']} — "
                    f"{r.enriched['region'] or '?'} · {r.enriched['carrier'] or '?'}")
    elif r.enriched["possible"]:
        r.reason = "possible but not confirmed valid"
    else:
        r.status = Status.NOT_FOUND
        r.reason = "not a valid number"
    return r


async def check_leakcheck(client: httpx.AsyncClient, num: str) -> SiteResult:
    try:
        resp = await client.get("https://leakcheck.io/api/public",
                                params={"check": num}, timeout=15)
    except Exception as e:
        return _r("leakcheck", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("leakcheck", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if not js.get("success") or not js.get("found"):
        return _r("leakcheck", Status.NOT_FOUND, "not in known breaches")
    sources = js.get("sources", [])
    data = {"count": js.get("found"), "fields": js.get("fields", []),
            "sources": [{"name": s.get("name"), "date": s.get("date")}
                        for s in sources]}
    names = ", ".join(s["name"] for s in data["sources"][:5])
    return _r("leakcheck", Status.FOUND,
              f"{data['count']} breach(es): {names}", data)


async def check_proxynova(client: httpx.AsyncClient, num: str) -> SiteResult:
    digits = re.sub(r"\D", "", num)
    for q in (num, digits):
        if not q:
            continue
        try:
            resp = await client.get("https://api.proxynova.com/comb",
                                    params={"query": q, "start": 0, "limit": 25},
                                    timeout=20)
        except Exception as e:
            return _r("proxynova", Status.UNKNOWN, type(e).__name__)
        if resp.status_code != 200:
            continue
        try:
            lines = resp.json().get("lines", [])
        except Exception:
            continue
        hits = [l for l in lines if digits and digits in re.sub(r"\D", "", l)]
        if hits:
            masked = []
            for l in hits[:10]:
                _, _, secret = l.partition(":")
                masked.append(f"{l.split(':')[0]}:{_mask(secret)}")
            return _r("proxynova", Status.FOUND,
                      f"{len(hits)} COMB line(s) mention this number (masked)",
                      {"lines": masked})
    return _r("proxynova", Status.NOT_FOUND, "no COMB entries")


async def check_intelx(client: httpx.AsyncClient, num: str) -> SiteResult:
    from .intelx import intelx_search
    from .config import intelx_key
    if not intelx_key():
        return _r("intelx", Status.UNKNOWN,
                  "skipped — set INTELX_KEY in .env")
    res = await intelx_search(client, num, maxresults=15)
    if res["error"]:
        return _r("intelx", Status.UNKNOWN, res["error"])
    recs = res["records"]
    if not recs:
        return _r("intelx", Status.NOT_FOUND, "no intelx records")
    buckets = sorted({r["bucket"] for r in recs if r.get("bucket")})
    return _r("intelx", Status.FOUND,
              f"{len(recs)} record(s) in leaks/pastes/darknet",
              {"records": recs[:15], "buckets": buckets})


ASYNC_MODULES = [
    ("leakcheck", check_leakcheck),
    ("proxynova", check_proxynova),
    ("intelx", check_intelx),
]


async def run_phone_scan(number: str, timeout: float = 15.0,
                         proxy: str | None = None) -> list[SiteResult]:
    parsed = check_parse(number)
    if parsed.status == Status.ILLEGAL:
        return [parsed]
    num = parsed.enriched.get("e164") or number
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        remote = await asyncio.gather(*(fn(client, num)
                                      for _, fn in ASYNC_MODULES))
    return [parsed, *remote]
