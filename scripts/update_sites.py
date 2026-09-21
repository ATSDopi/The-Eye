"""Download and merge public username-site databases into theeye/data/sites.json.

Sources (all free/open):
  - Maigret  : https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json
  - WhatsMyName: https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json
  - Sherlock : https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json

Output schema (per site), normalized:

  name            str   display name
  url             str   profile URL template, contains "{username}"
  url_probe       str?  alternate check URL template (defaults to url)
  url_main        str?  site homepage
  check_type      str   status_code | message | response_url
  presence_strs   [str] strings that PROVE the account exists
  absence_strs    [str] strings that PROVE the account does not exist
  error_url       str?  redirect target meaning "not found"
  regex_check     str?  username must match or the site is skipped
  head_only       bool  use HEAD instead of GET
  ignore_403      bool  treat HTTP 403 as "unknown" instead of hit
  method          str   HTTP method (GET/POST...)
  headers         dict  extra request headers
  tags            [str] categories (fr/en style tags, country codes, nsfw...)
  nsfw            bool
  rank            int?  popularity rank (lower = more popular)
  disabled        bool  known-broken / needs special engine
  protection      [str] captcha, cloudflare, ... -> unreliable result
  source          [str] which upstream DBs contributed this entry
  known_claimed   str?  a username known to exist (self-check)
  known_unclaimed str?  a username known to NOT exist (self-check)
"""

import json
import re
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "theeye" / "data" / "sites.json"
TMP = ROOT / ".tmp"
TMP.mkdir(exist_ok=True)

SOURCES = {
    "maigret": "https://raw.githubusercontent.com/soxoj/maigret/main/maigret/resources/data.json",
    "wmn": "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json",
    "sherlock": "https://raw.githubusercontent.com/sherlock-project/sherlock/master/sherlock_project/resources/data.json",
    "nexfil": "https://raw.githubusercontent.com/thewhiteh4t/nexfil/master/src/nexfil/url_store.json",
    "social_analyzer": "https://raw.githubusercontent.com/qeeqbox/social-analyzer/main/data/sites.json",
    # email->registration checks (blackbird) — saved to email_sites.json
    "blackbird_email": "https://raw.githubusercontent.com/p1ngul1n0/blackbird/main/data/email-data.json",
}

NSFW_TAGS = {
    "porn", "erotic", "webcam", "nsfw", "adult", "dating_adult", "xx NSFW xx",
    "escort", "fetish", "hentai", "sex",
}


def fetch(url: str, dest: Path) -> dict:
    """Download a dataset; on network failure fall back to the cached copy."""
    print(f"  GET {url}")
    req = urllib.request.Request(url, headers={"User-Agent": "theeye-db-updater"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        dest.write_bytes(data)
        return json.loads(data.decode("utf-8"))
    except Exception as e:
        if dest.exists():
            print(f"    failed ({type(e).__name__}) — using cached copy")
            return json.loads(dest.read_text(encoding="utf-8"))
        raise RuntimeError(f"source {url} failed and no cache: {e}") from e


def host_of(url: str) -> str:
    m = re.search(r"https?://([^/]+)", url or "")
    return re.sub(r"^www\d*\.", "", m.group(1).lower()) if m else ""


def path_of(url: str) -> str:
    m = re.search(r"https?://[^/]+(/.*)", url or "")
    return m.group(1) if m else "/"


def dedup_key(name: str, url: str) -> str:
    """Sites are the same if host + url path shape match, else by name."""
    host = host_of(url)
    path = path_of(url)
    path = re.sub(r"\{username\}|\{account\}|\{\}", "@", path)
    path = re.sub(r"[@/]+$", "", path)
    if host:
        return f"{host}{path}"
    return name.lower().strip()


def is_nsfw(tags) -> bool:
    return any(t.lower() in NSFW_TAGS for t in tags or [])


def _materialize(template: str | None, url_main: str, subpath: str) -> str | None:
    if not template:
        return None
    return (template.replace("{urlMain}", url_main or "")
                    .replace("{urlSubpath}", subpath or ""))


def norm_maigret(raw: dict) -> list[dict]:
    engines = raw.get("engines", {})
    out = []
    for name, s in raw["sites"].items():
        # Entries without a direct "url" inherit a template from their
        # engine (e.g. DiscourseJson -> {urlMain}/u/{username}.json).
        if not s.get("url") and s.get("engine") in engines:
            base = dict(engines[s["engine"]].get("site") or {})
            base.update(s)          # site fields override engine defaults
            s = base
            s["url"] = _materialize(s.get("url"), s.get("urlMain", ""), s.get("urlSubpath", ""))
            s["urlProbe"] = _materialize(s.get("urlProbe"), s.get("urlMain", ""), s.get("urlSubpath", ""))
        url = s.get("url")
        if not url or "{username}" not in url:
            continue
        tags = [t.lower() for t in s.get("tags", []) or []]
        # activation flows (login/cookies) can't be done with plain HTTP
        disabled = bool(s.get("disabled")) or bool(s.get("activation"))
        out.append({
            "name": name,
            "url": url,
            "url_probe": s.get("urlProbe"),
            "url_main": s.get("urlMain"),
            "check_type": s.get("checkType", "status_code"),
            "presence_strs": s.get("presenseStrs") or s.get("presense_strs") or [],
            "absence_strs": list(s.get("absenceStrs") or []) + list((s.get("errors") or {}).values()),
            "error_url": s.get("errorUrl"),
            "regex_check": s.get("regexCheck"),
            "head_only": bool(s.get("requestHeadOnly")),
            "ignore_403": bool(s.get("ignore403")),
            "method": s.get("requestMethod", "GET").upper(),
            "headers": s.get("headers") or {},
            "payload": s.get("requestPayload") or None,
            "engine": s.get("engine"),
            "tags": tags,
            "nsfw": is_nsfw(tags),
            "rank": s.get("alexaRank"),
            "disabled": disabled,
            "protection": [p.lower() for p in s.get("protection", []) or []],
            "source": ["maigret"],
            "known_claimed": s.get("usernameClaimed"),
            "known_unclaimed": s.get("usernameUnclaimed"),
        })
    return out


def norm_wmn(raw: dict) -> list[dict]:
    out = []
    for s in raw["sites"]:
        if s.get("invalid"):
            continue
        url = (s.get("uri_check") or "").replace("{account}", "{username}")
        if not url or "{username}" not in url:
            continue
        cat = (s.get("cat") or "").lower()
        tags = [cat] if cat else []
        absence = [s["m_string"]] if s.get("m_string") else []
        presence = [s["e_string"]] if s.get("e_string") else []
        # wmn encodes "exists" via e_code/e_string, "missing" via m_code/m_string
        check_type = "message" if (absence or presence) else "status_code"
        out.append({
            "name": s.get("name") or host_of(url),
            "url": url,
            "url_probe": (s.get("uri_pretty") or "").replace("{account}", "{username}") or None,
            "url_main": s.get("uri_home"),
            "check_type": check_type,
            "presence_strs": presence,
            "absence_strs": absence,
            "error_url": None,
            "e_code": s.get("e_code"),
            "m_code": s.get("m_code"),
            "regex_check": s.get("account_check"),
            "head_only": False,
            "ignore_403": False,
            "method": "GET",
            "headers": {},
            "tags": tags,
            "nsfw": is_nsfw(tags),
            "rank": None,
            "disabled": False,
            "protection": [p.lower() for p in s.get("protection", []) or []],
            "source": ["wmn"],
            "known_claimed": (s.get("known") or [None])[0],
            "known_unclaimed": None,
        })
    return out


def norm_sherlock(raw: dict) -> list[dict]:
    out = []
    for name, s in raw.items():
        if name.startswith("$"):
            continue
        url = (s.get("url") or "").replace("{}", "{username}")
        if not url or "{username}" not in url:
            continue
        tags = [t.lower() for t in s.get("tags", []) or []]
        out.append({
            "name": name,
            "url": url,
            "url_probe": (s.get("urlProbe") or "").replace("{}", "{username}") or None,
            "url_main": s.get("urlMain"),
            "check_type": s.get("errorType", "status_code"),
            "presence_strs": [],
            "absence_strs": s.get("errorMsg") or [],
            "error_url": s.get("errorUrl"),
            "regex_check": s.get("regexCheck"),
            "head_only": s.get("request_method") == "HEAD" or bool(s.get("requestHeadOnly")),
            "ignore_403": False,
            "method": (s.get("request_method") or "GET").upper(),
            "headers": s.get("headers") or {},
            "tags": tags,
            "nsfw": is_nsfw(tags) or bool(s.get("isNSFW")),
            "rank": s.get("alexaRank"),
            "disabled": bool(s.get("disabled")),
            "protection": [],
            "source": ["sherlock"],
            "known_claimed": s.get("username_claimed"),
            "known_unclaimed": s.get("username_unclaimed"),
        })
    return out


def norm_nexfil(raw: list) -> list[dict]:
    out = []
    for e in raw:
        url = (e.get("url") or "").replace("{}", "{username}")
        if "{username}" not in url:
            continue
        test = e.get("test")
        absence = [e["data"]] if test == "string" and isinstance(
            e.get("data"), str) else []
        out.append({
            "name": host_of(url).rsplit(".", 1)[0] or url,
            "url": url,
            "url_probe": None, "url_main": None,
            "check_type": "message" if absence else "status_code",
            "presence_strs": [], "absence_strs": absence,
            "error_url": None, "regex_check": None,
            "head_only": False, "ignore_403": False, "method": "GET",
            "headers": {}, "tags": [], "nsfw": False, "rank": None,
            # "headless"/"xpath" checks need a browser engine — skip them
            "disabled": test in ("headless", "xpath") or
                        isinstance(e.get("data"), dict),
            "protection": [],
            "source": ["nexfil"],
            "known_claimed": None, "known_unclaimed": None,
        })
    return out


def norm_social_analyzer(raw: dict) -> list[dict]:
    out = []
    for e in raw.get("websites_entries", []):
        url = e.get("url") or ""
        if "{username}" not in url:
            continue
        presence, absence = [], []
        for d in e.get("detections") or []:
            s = d.get("string")
            if not s or d.get("type") == "shared":
                continue                     # shared engines not materializable
            (presence if d.get("return") == "true" else absence).append(s)
        cat = (e.get("type") or "").split(">")[-1].strip().lower()
        tags = [t for t in (cat, (e.get("country") or "").lower()) if t]
        out.append({
            "name": host_of(url).rsplit(".", 1)[0].title() or url,
            "url": url,
            "url_probe": None, "url_main": None,
            "check_type": "message" if (presence or absence) else "status_code",
            "presence_strs": presence, "absence_strs": absence,
            "error_url": None, "regex_check": None,
            "head_only": False, "ignore_403": False, "method": "GET",
            "headers": {}, "tags": tags,
            "nsfw": str(e.get("nsfw")).lower() == "true" or is_nsfw(tags),
            "rank": e.get("global_rank") or None,
            "disabled": False, "protection": [],
            "source": ["social_analyzer"],
            "known_claimed": None, "known_unclaimed": None,
        })
    return out


def norm_blackbird_email(raw: dict) -> list[dict]:
    """email->site registration checks -> separate data/email_sites.json."""
    out = []
    for s in raw.get("sites", []):
        uri = (s.get("uri_check") or "").replace("{account}", "{email}")
        data = (s.get("data") or "").replace("{account}", "{email}")
        # the email may live in the URI (GET) or the POST body
        if "{email}" not in uri and "{email}" not in data:
            continue
        # can't generically solve multi-step flows (CSRF pre-fetch etc.)
        if "{csrftoken_value}" in json.dumps(s.get("headers") or {}):
            continue
        out.append({
            "name": s.get("name") or host_of(uri),
            "uri_check": uri,
            "method": (s.get("method") or "GET").upper(),
            "headers": s.get("headers") or {},
            "data": data or None,
            "e_code": s.get("e_code"), "e_string": s.get("e_string"),
            "m_code": s.get("m_code"), "m_string": s.get("m_string"),
            "cat": s.get("cat"),
            "input_operation": s.get("input_operation"),
        })
    return out


def merge(lists: list[list[dict]]) -> list[dict]:
    by_key: dict[str, dict] = {}
    by_name: dict[str, str] = {}  # lowercase name -> dedup key
    for entries in lists:
        for e in entries:
            key = dedup_key(e["name"], e["url"])
            name_key = e["name"].lower().strip()
            existing_key = by_name.get(name_key)
            if existing_key and existing_key in by_key:
                key = existing_key
            if key in by_key:
                cur = by_key[key]
                cur["source"] = sorted(set(cur["source"]) | set(e["source"]))
                # fill missing fields from the new entry, prefer existing
                for f in ("presence_strs", "absence_strs", "tags", "protection"):
                    cur[f] = sorted(set(cur.get(f) or []) | set(e.get(f) or []))
                for f in ("url_probe", "url_main", "error_url", "regex_check",
                          "rank", "known_claimed", "known_unclaimed", "e_code", "m_code"):
                    if not cur.get(f) and e.get(f):
                        cur[f] = e[f]
                cur["nsfw"] = cur["nsfw"] or e["nsfw"]
                cur["disabled"] = cur["disabled"] and e["disabled"] if "engine" not in e else cur["disabled"]
            else:
                by_key[key] = e
                by_name[name_key] = key
    sites = sorted(by_key.values(), key=lambda s: (s.get("rank") or 10**9, s["name"].lower()))
    return sites


def main() -> None:
    raws = {}
    for label, url in SOURCES.items():
        raws[label] = fetch(url, TMP / f"{label}.json")

    # email->registration dataset lives in its own file
    esites = norm_blackbird_email(raws["blackbird_email"])
    (OUT.parent / "email_sites.json").write_text(json.dumps(
        esites, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"  email registration sites: {len(esites)}")

    merged = merge([
        norm_maigret(raws["maigret"]),
        norm_wmn(raws["wmn"]),
        norm_sherlock(raws["sherlock"]),
        norm_nexfil(raws["nexfil"]),
        norm_social_analyzer(raws["social_analyzer"]),
    ])

    enabled = [s for s in merged if not s["disabled"]]
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp_out = OUT.with_suffix(".json.tmp")
    tmp_out.write_text(json.dumps({
        "version": 1,
        "count": len(merged),
        "enabled": len(enabled),
        "sources": sorted(SOURCES),
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "sites": merged,
    }, ensure_ascii=False, indent=1), encoding="utf-8")
    tmp_out.replace(OUT)  # atomic-ish: never leave a half-written DB

    multi = sum(1 for s in merged if len(s["source"]) > 1)
    print(f"\nDone: {len(merged)} sites ({len(enabled)} enabled, {multi} merged from >1 source)")
    print(f"-> {OUT}")


if __name__ == "__main__":
    sys.exit(main())
