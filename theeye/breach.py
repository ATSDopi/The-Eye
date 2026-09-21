"""Consolidated breach report — merges every leak source into one timeline.

Aggregation rules:
  - leakcheck gives breach names + dates + leaked field types
  - xposedornot gives breach names (wider coverage, no dates)
  - proxynova gives raw credential lines (masked before display)
  - hudsonrock gives infostealer infections (date, OS, computer)
Names are normalized so the same breach reported by two sources merges
(e.g. "LinkedIn.com" / "LinkedIn" / "linkedin.com 2016").
"""

from __future__ import annotations

import re

from .models import SiteResult, Status


def norm_breach(name: str) -> str:
    """Canonical key so the same dump merges across spellings/sources:
    'Houzz.com.rar/Houzz.com_3.txt [Part 132 of 1025]' == 'Houzz.com'."""
    n = name.lower()
    n = re.sub(r"\[part \d+ of \d+\]", "", n)
    n = n.split("/")[0].strip()              # 'archive.rar/member.txt' -> archive
    n = re.sub(r"\.(txt|csv|tsv|sql|json|log|db|dump|rar|zip|7z|tar|gz|"
               r"xlsx?|xml|eml|pst|lst)$", "", n.strip())
    n = re.sub(r"\.(com|net|org|io|xyz|us|info|biz|ru|de|fr|co|uk|gg|tv|me)"
               r"(?=\.|_|\s|$)", "", n)       # embedded tld: 'houzz.com_rar'
    n = re.sub(r"[^a-z0-9]", "", n)
    n = re.sub(r"(scraping|scraped|scrape|data|breach|leak|part)+$", "", n)
    n = re.sub(r"(\d{8}|\d{6}|\d{4}|\d+)$", "", n)   # trailing dates/counters
    n = re.sub(r"(com|net|org|io|xyz|us|info|biz)$", "", n)
    return n


def display_name(names: set[str]) -> str:
    # prefer human-readable names over dump filenames
    clean = [n for n in names if "/" not in n and "[part" not in n.lower()]
    pool = clean or list(names)
    return sorted(pool, key=lambda n: (-len(n), n))[0][:80]


def aggregate(results: list[SiteResult]) -> dict:
    """Merge module results into {breaches, stealers, creds, fields, sources}."""
    breaches: dict[str, dict] = {}
    stealers: list[dict] = []
    cred_lines: list[str] = []
    fields: set[str] = set()
    per_source: dict[str, str] = {}

    for r in results:
        d = r.enriched or {}
        per_source[r.site] = r.status.value
        if r.site in ("leakcheck", "xposedornot"):
            for s in d.get("sources", []):
                name = s["name"] if isinstance(s, dict) else s
                key = norm_breach(name)
                b = breaches.setdefault(key, {"names": set(), "dates": set(),
                                              "via": set()})
                b["names"].add(name)
                b["via"].add(r.site)
                if isinstance(s, dict) and s.get("date"):
                    b["dates"].add(str(s["date"]))
            for f in d.get("fields", []):
                fields.add(str(f))
            for f, n in (d.get("password_strength") or {}).items():
                if n:
                    fields.add(f"passwords:{f.lower()}")
        elif r.site == "proxynova":
            cred_lines += d.get("lines", [])
        elif r.site == "hudsonrock":
            stealers += d.get("stealers", [])
        elif r.site == "intelx":
            for rec in d.get("records", []):
                name = rec.get("name") or rec.get("bucket") or "?"
                key = norm_breach(name)
                b = breaches.setdefault(key, {"names": set(), "dates": set(),
                                              "via": set()})
                b["names"].add(name)
                b["via"].add("intelx")
                if rec.get("date"):
                    b["dates"].add(str(rec["date"]))
        elif r.site == "darkweb":
            for m in d.get("mentions", []):
                breaches.setdefault("__darkweb__", {"names": set(),
                                                    "dates": set(),
                                                    "via": set()})
                breaches["__darkweb__"]["names"].add(
                    f".onion: {(m.get('title') or '?')[:60]}")
                breaches["__darkweb__"]["via"].add("ahmia")

    timeline = []
    for key, b in breaches.items():
        dates = sorted(b["dates"])
        timeline.append({
            "name": display_name(b["names"]),
            "date": dates[0] if dates else None,
            "dates": dates,
            "via": sorted(b["via"]),
        })
    timeline.sort(key=lambda x: (x["date"] is None, x["date"] or ""))

    has_password_field = any("pass" in f.lower() or "password" in f.lower()
                             for f in fields)
    score = (len(timeline) + len(stealers) * 3 + len(cred_lines)
             + (2 if has_password_field else 0))
    level = ("clean" if score == 0 else "low" if score <= 3 else
             "moderate" if score <= 7 else "high" if score <= 14 else "critical")
    return {"breaches": timeline, "stealers": stealers, "cred_lines": cred_lines,
            "fields": sorted(fields), "per_source": per_source,
            "score": score, "level": level}
