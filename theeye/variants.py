"""Username variant generation.

Modes:
  sep    — permute word separators (_, -, ., none). "johndoe" is left as-is;
           "john.doe" -> john_doe, john-doe, johndoe, john.doe
  common — sep + common account suffixes/prefixes people actually use
  full   — common + digit patterns (1, 01, 123, birth years-ish)
"""

from __future__ import annotations

import re

SEPARATORS = ["", "_", "-", "."]
COMMON_AFFIXES = ["1", "01", "123", "_", "official", "real", "tv", "yt"]
YEAR_SUFFIXES = ["69", "99", "00", "07", "21", "22", "23", "24"]


def _split(username: str) -> list[str]:
    parts = re.split(r"[_\-.]+", username)
    return [p for p in parts if p]


def generate(username: str, mode: str = "sep") -> list[str]:
    out: list[str] = []
    seen = {username}

    def add(v: str):
        if v and v not in seen:
            seen.add(v)
            out.append(v)

    parts = _split(username)
    if len(parts) > 1:
        for sep in SEPARATORS:
            add(sep.join(parts))
        # reversed word order, same separators
        for sep in SEPARATORS:
            add(sep.join(reversed(parts)))

    if mode in ("common", "full"):
        for aff in COMMON_AFFIXES:
            if not username.endswith(aff):
                add(username + aff)
            add(aff + username if aff.isalpha() else username + aff)

    if mode == "full":
        for y in YEAR_SUFFIXES:
            add(username + y)
        # leetspeak-lite for the most common substitutions
        leet = str.maketrans({"a": "4", "e": "3", "i": "1", "o": "0", "s": "5", "t": "7"})
        add(username.translate(leet))

    return out
