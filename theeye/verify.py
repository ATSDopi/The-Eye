"""False-positive verification.

Every "found" result is re-tested on the same site with a username that is
guaranteed not to exist (the site's `known_unclaimed` from the DB, else a
random suffix). If the ghost username also comes back "found", the site
cannot tell existing from non-existing accounts -> the hit is a probable
false positive ("fp"). If the ghost is correctly "not found", the hit is
"confirmed". Probe inconclusive -> left "unverified".
"""

from __future__ import annotations

import asyncio
import json
import secrets
import string
import time
from pathlib import Path

from .models import Site, SiteResult, Status

HEALTH_PATH = Path(__file__).parent / "data" / "site_health.json"


def load_health() -> dict:
    """{site_name: {"v": "ok"|"fp"|"unknown", "ts": epoch}} cached site probes."""
    try:
        return json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_health(health: dict):
    HEALTH_PATH.parent.mkdir(exist_ok=True)
    HEALTH_PATH.write_text(json.dumps(health), encoding="utf-8")


def _ghost_username(site: Site, base: str) -> str:
    if site.known_unclaimed:
        return site.known_unclaimed
    suffix = "".join(secrets.choice(string.ascii_lowercase + string.digits)
                     for _ in range(8))
    # keep the same shape as the queried username so site regexes still pass
    return f"{base}{suffix}"


async def verify_found(scanner, sites: list[Site], results: list[SiteResult],
                       health: dict | None = None, on_done=None) -> dict:
    by_name = {s.name: s for s in sites}
    health = health or {}
    counts = {"confirmed": 0, "fp": 0, "unverified": 0}
    probes = []
    targets = []
    for r in results:
        if r.status != Status.FOUND:
            continue
        site = by_name.get(r.site)
        if not site:
            continue
        cached = (health.get(site.name) or {}).get("v")
        if cached == "fp":
            r.verified = "fp"
            r.confidence = "low"
            r.reason += " | site known FP-prone (selfcheck)"
            counts["fp"] += 1
            continue
        if cached == "ok":
            r.verified = "confirmed"
            if r.confidence == "low":
                r.confidence = "medium"
            counts["confirmed"] += 1
            continue
        ghost = _ghost_username(site, r.query or "")
        probes.append(scanner.check(site, ghost, ghost))
        targets.append(r)

    for r, ghost_res in zip(targets, await asyncio.gather(*probes)):
        if ghost_res.status == Status.FOUND:
            r.verified = "fp"
            r.confidence = "low"
            r.reason += " | site returns found for non-existent users"
        elif ghost_res.status == Status.NOT_FOUND:
            r.verified = "confirmed"
            if r.confidence == "low":
                r.confidence = "medium"
        else:
            r.verified = "unverified"
        counts[r.verified] += 1
        if on_done:
            on_done(r)

    # persist what we just learned — organic health-cache growth
    learned = {r.site for r in targets}
    dirty = False
    for name in learned:
        verdicts = {r.verified for r in targets if r.site == name}
        v = "fp" if "fp" in verdicts else \
            ("ok" if "confirmed" in verdicts else "unknown")
        if (health.get(name) or {}).get("v") != v:
            health[name] = {"v": v, "ts": int(time.time())}
            dirty = True
    if dirty:
        save_health(health)
    return counts


async def probe_sites(scanner, sites: list[Site], on_done=None) -> dict:
    """Self-check: ghost-probe every site once. Returns {name: verdict}."""
    out = {}
    tasks = [(s, asyncio.ensure_future(
        scanner.check(s, _ghost_username(s, "theeyeselfcheck"), 
                      _ghost_username(s, "theeyeselfcheck"))))
        for s in sites]
    for site, fut in tasks:
        res = await fut
        verdict = {"found": "fp", "not_found": "ok"}.get(
            res.status.value, "unknown")
        out[site.name] = {"v": verdict, "ts": int(time.time())}
        if on_done:
            on_done(site.name, verdict)
    return out
