"""Intelligence X integration (free-tier API key via .env INTELX_KEY).

Searches leaks, pastes and darknet buckets. Flow: POST /intelligent/search ->
poll /intelligent/search/result until records arrive.
"""

from __future__ import annotations

import asyncio

import httpx

from .config import intelx_key
from .engine import USER_AGENTS

BASE = "https://free.intelx.io"


async def intelx_search(client: httpx.AsyncClient, term: str,
                        maxresults: int = 30, wait_s: float = 30.0) -> dict:
    """Returns {"records": [...], "error": str|None}. Raises no exceptions."""
    key = intelx_key()
    if not key:
        return {"records": [], "error": "no INTELX_KEY in .env"}
    h = {"x-key": key, "User-Agent": USER_AGENTS[0]}
    try:
        r = await client.post(f"{BASE}/intelligent/search", headers=h, json={
            "term": term, "maxresults": maxresults, "media": 0, "sort": 2,
            "terminate": [], "target": 0}, timeout=20)
        if r.status_code == 401:
            return {"records": [], "error": "invalid INTELX_KEY (401)"}
        if r.status_code != 200:
            return {"records": [], "error": f"search HTTP {r.status_code}"}
        sid = r.json().get("id")
        if not sid:
            return {"records": [], "error": "no search id"}
    except Exception as e:
        return {"records": [], "error": type(e).__name__}

    waited = 0.0
    while waited < wait_s:
        await asyncio.sleep(3)
        waited += 3
        try:
            r = await client.get(f"{BASE}/intelligent/search/result",
                                 headers=h, params={
                                     "id": sid, "limit": maxresults,
                                     "statistics": 1, "previewlines": 4},
                                 timeout=20)
            js = r.json()
            recs = js.get("records") or js.get("selectors") or []
            if recs:
                return {"records": [_clean(x) for x in recs], "error": None}
            if js.get("status") == 2:          # finished, nothing found
                return {"records": [], "error": None}
        except Exception as e:
            return {"records": [], "error": type(e).__name__}
    return {"records": [], "error": "search timed out"}


def _clean(x: dict) -> dict:
    return {
        "name": x.get("name"),
        "bucket": x.get("bucket"),
        "media": x.get("mediah"),
        "type": x.get("typeh"),
        "date": (x.get("date") or "")[:10],
        "access": x.get("accesslevelh"),
        "size": x.get("size"),
        "score": x.get("xscore"),
        "systemid": x.get("systemid"),
        "storageid": x.get("storageid"),
    }
