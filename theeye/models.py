from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from enum import Enum


class Status(str, Enum):
    FOUND = "found"
    NOT_FOUND = "not_found"
    UNKNOWN = "unknown"      # protected / ambiguous / network error
    ILLEGAL = "illegal"      # username rejected by site regex
    SKIPPED = "skipped"      # disabled site


@dataclass
class Site:
    name: str
    url: str
    url_probe: str | None = None
    url_main: str | None = None
    check_type: str = "status_code"          # status_code | message | response_url
    presence_strs: list[str] = field(default_factory=list)
    absence_strs: list[str] = field(default_factory=list)
    error_url: str | None = None
    regex_check: str | None = None
    head_only: bool = False
    ignore_403: bool = False
    method: str = "GET"
    headers: dict = field(default_factory=dict)
    payload: dict | None = None
    engine: str | None = None
    tags: list[str] = field(default_factory=list)
    nsfw: bool = False
    rank: int | None = None
    disabled: bool = False
    protection: list[str] = field(default_factory=list)
    source: list[str] = field(default_factory=list)
    known_claimed: str | None = None
    known_unclaimed: str | None = None
    e_code: int | None = None
    m_code: int | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Site":
        known = {f for f in cls.__dataclass_fields__}
        return cls(**{k: v for k, v in d.items() if k in known})

    def check_url(self, username: str) -> str:
        tpl = self.url_probe or self.url
        return tpl.replace("{username}", username)

    def profile_url(self, username: str) -> str:
        return self.url.replace("{username}", username)


@dataclass
class SiteResult:
    site: str
    status: Status
    url: str | None = None
    http_code: int | None = None
    response_ms: int | None = None
    confidence: str = "low"                 # high | medium | low
    reason: str = ""
    protection: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    nsfw: bool = False
    rank: int | None = None
    enriched: dict = field(default_factory=dict)
    query: str = ""                          # username variant actually queried
    verified: str = ""                       # "" | "confirmed" | "fp" (false positive)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class ScanReport:
    username: str
    started: float = field(default_factory=time.time)
    finished: float = 0.0
    case: str = "default"
    results: list[SiteResult] = field(default_factory=list)

    def summary(self) -> dict:
        c = {s.value: 0 for s in Status}
        for r in self.results:
            c[r.status.value] += 1
        return {
            "username": self.username,
            "case": self.case,
            "total": len(self.results),
            **c,
            "duration_s": round(self.finished - self.started, 1) if self.finished else None,
        }

    def found(self) -> list[SiteResult]:
        return [r for r in self.results if r.status == Status.FOUND]
