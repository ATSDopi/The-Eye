"""Local SQLite storage: scan history + per-case grouping (the free/local
equivalent of usersearch's case management)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .models import ScanReport

DB_PATH = Path(__file__).parent.parent / "theeye.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT, case_name TEXT, started REAL, finished REAL, summary TEXT);
CREATE TABLE IF NOT EXISTS results(
  scan_id INTEGER, site TEXT, status TEXT, url TEXT, http_code INT,
  confidence TEXT, reason TEXT, query TEXT, rank INT, enriched TEXT,
  verified TEXT);
CREATE INDEX IF NOT EXISTS idx_results_scan ON results(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(username);
"""


def _conn() -> sqlite3.Connection:
    c = sqlite3.connect(DB_PATH)
    c.executescript(_SCHEMA)
    cols = {r[1] for r in c.execute("PRAGMA table_info(results)")}
    if "verified" not in cols:          # migrate pre-verification DBs
        c.execute("ALTER TABLE results ADD COLUMN verified TEXT")
    return c


def save_scan(report: ScanReport, case: str = "default") -> int:
    with _conn() as c:
        cur = c.execute(
            "INSERT INTO scans(username,case_name,started,finished,summary) VALUES(?,?,?,?,?)",
            (report.username, case, report.started, report.finished,
             json.dumps(report.summary())))
        sid = cur.lastrowid
        c.executemany(
            "INSERT INTO results(scan_id,site,status,url,http_code,confidence,reason,query,rank,enriched,verified)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            [(sid, r.site, r.status.value, r.url, r.http_code, r.confidence,
              r.reason, r.query, r.rank, json.dumps(r.enriched), r.verified)
             for r in report.results])
    return sid


def list_scans(limit: int = 50) -> list[dict]:
    with _conn() as c:
        rows = c.execute(
            "SELECT id,username,case_name,started,summary FROM scans ORDER BY id DESC LIMIT ?",
            (limit,)).fetchall()
    return [{"id": r[0], "username": r[1], "case": r[2], "started": r[3],
             "summary": json.loads(r[4])} for r in rows]


def load_scan(scan_id: int) -> dict | None:
    with _conn() as c:
        s = c.execute("SELECT id,username,case_name,started,finished,summary FROM scans WHERE id=?",
                      (scan_id,)).fetchone()
        if not s:
            return None
        rs = c.execute("SELECT site,status,url,http_code,confidence,reason,query,rank,enriched,verified"
                       " FROM results WHERE scan_id=?", (scan_id,)).fetchall()
    return {"id": s[0], "username": s[1], "case": s[2], "started": s[3],
            "finished": s[4], "summary": json.loads(s[5]),
            "results": [{"site": r[0], "status": r[1], "url": r[2], "http_code": r[3],
                         "confidence": r[4], "reason": r[5], "query": r[6],
                         "rank": r[7], "enriched": json.loads(r[8] or "{}"),
                         "verified": r[9] or ""} for r in rs]}
