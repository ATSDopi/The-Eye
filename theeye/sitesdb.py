from __future__ import annotations

import json
from pathlib import Path

from .models import Site

DATA_FILE = Path(__file__).parent / "data" / "sites.json"


def db_meta() -> dict:
    """Version/count/generated-date of the bundled DB."""
    try:
        data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return {k: data.get(k) for k in ("count", "enabled", "generated", "sources")}


def db_age_days() -> int | None:
    try:
        gen = db_meta().get("generated")
        if not gen:
            return None
        from datetime import datetime, timezone
        d = datetime.strptime(gen, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - d).days
    except Exception:
        return None


def load_sites() -> list[Site]:
    data = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    return [Site.from_dict(s) for s in data["sites"]]


def filter_sites(
    sites: list[Site],
    *,
    include_disabled: bool = False,
    include_nsfw: bool = False,
    tags: list[str] | None = None,
    country: str | None = None,
    top: int | None = None,
    only: list[str] | None = None,
    exclude: list[str] | None = None,
) -> list[Site]:
    out = []
    only_l = {o.lower() for o in only} if only else None
    excl_l = {e.lower() for e in exclude} if exclude else set()
    tags_l = {t.lower() for t in tags} if tags else None

    for s in sites:
        if s.disabled and not include_disabled:
            continue
        if s.nsfw and not include_nsfw:
            continue
        if only_l and s.name.lower() not in only_l:
            continue
        if s.name.lower() in excl_l:
            continue
        if tags_l and not tags_l & {t.lower() for t in s.tags}:
            continue
        if country and country.lower() not in {t.lower() for t in s.tags}:
            continue
        out.append(s)

    if top:
        ranked = sorted((s for s in out if s.rank), key=lambda s: s.rank)
        unranked = [s for s in out if not s.rank]
        out = (ranked + unranked)[:top]
    return out


def all_tags(sites: list[Site]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for s in sites:
        for t in s.tags:
            counts[t] = counts.get(t, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))
