"""Postal address intelligence — free geocoders only.

Modules:
  nominatim   OpenStreetMap geocoding: normalized address, coords, place type
  ban         api-adresse.data.gouv.fr — official French address DB (BAN)
  revgeo      reverse geocode -> what is actually at those coordinates
"""

from __future__ import annotations

import asyncio
import re

import httpx

from .engine import USER_AGENTS
from .models import SiteResult, Status

UA = {"User-Agent": f"TheEye-OSINT/0.1 ({USER_AGENTS[0]})"}  # OSM needs a real UA


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


async def check_nominatim(client: httpx.AsyncClient, addr: str) -> SiteResult:
    try:
        resp = await client.get("https://nominatim.openstreetmap.org/search",
                                params={"q": addr, "format": "jsonv2",
                                        "addressdetails": 1, "limit": 3},
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("nominatim", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("nominatim", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if not js:
        return _r("nominatim", Status.NOT_FOUND, "address not found in OSM")
    best = js[0]
    a = best.get("address") or {}
    data = {"display": best.get("display_name"),
            "type": f"{best.get('category')}/{best.get('type')}",
            "coords": f"{best.get('lat')},{best.get('lon')}",
            "road": a.get("road"), "city": a.get("city") or a.get("town")
            or a.get("village"), "postcode": a.get("postcode"),
            "country": a.get("country"), "country_code": a.get("country_code"),
            "alternatives": [x.get("display_name") for x in js[1:]]}
    data = {k: v for k, v in data.items() if v}
    return _r("nominatim", Status.FOUND,
              f"{data.get('city') or ''} {data.get('country') or ''} — {data.get('coords')}",
              data, f"https://www.openstreetmap.org/#map=18/{best.get('lat')}/{best.get('lon')}")


async def check_ban(client: httpx.AsyncClient, addr: str) -> SiteResult:
    try:
        resp = await client.get("https://api-adresse.data.gouv.fr/search/",
                                params={"q": addr, "limit": 3}, timeout=15)
    except Exception as e:
        return _r("ban", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("ban", Status.UNKNOWN, f"HTTP {resp.status_code}")
    feats = resp.json().get("features", [])
    if not feats:
        return _r("ban", Status.NOT_FOUND, "not a French address (BAN)")
    f = feats[0]
    p = f.get("properties") or {}
    c = f.get("geometry", {}).get("coordinates") or []
    data = {"label": p.get("label"), "score": p.get("score"),
            "city": p.get("city"), "postcode": p.get("postcode"),
            "citycode": p.get("citycode"), "context": p.get("context"),
            "coords": f"{c[1]},{c[0]}" if len(c) == 2 else None,
            "type": p.get("type")}
    data = {k: v for k, v in data.items() if v}
    return _r("ban", Status.FOUND,
              f"BAN match (score {data.get('score')}) — {data.get('label')}",
              data)


async def check_revgeo(client: httpx.AsyncClient, addr: str) -> SiteResult:
    """Reverse-geocode the best match — what is actually at those coordinates."""
    nom = await check_nominatim(client, addr)
    if nom.status != Status.FOUND or not nom.enriched.get("coords"):
        return _r("revgeo", Status.UNKNOWN, "no coordinates to reverse")
    lat, lon = nom.enriched["coords"].split(",")
    try:
        resp = await client.get("https://nominatim.openstreetmap.org/reverse",
                                params={"lat": lat, "lon": lon, "format": "jsonv2",
                                        "zoom": 18, "addressdetails": 1},
                                headers=UA, timeout=15)
    except Exception as e:
        return _r("revgeo", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("revgeo", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if "error" in js:
        return _r("revgeo", Status.NOT_FOUND, "nothing at these coordinates")
    a = js.get("address") or {}
    data = {"what": f"{js.get('category')}/{js.get('type')}",
            "name": js.get("name"),
            "display": js.get("display_name"),
            "amenity": a.get("amenity"), "building": a.get("building"),
            "shop": a.get("shop"), "office": a.get("office")}
    data = {k: v for k, v in data.items() if v}
    what = data.get("name") or data.get("amenity") or data.get("building") \
        or data.get("what") or "?"
    return _r("revgeo", Status.FOUND, f"at coords: {what}", data)


MODULES = [
    ("nominatim", check_nominatim),
    ("ban", check_ban),
    ("revgeo", check_revgeo),
]


async def run_address_scan(address: str, timeout: float = 15.0,
                           proxy: str | None = None) -> list[SiteResult]:
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        return await asyncio.gather(*(fn(client, address)
                                      for _, fn in MODULES))
