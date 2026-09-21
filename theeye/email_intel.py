"""Free email intelligence — no API keys required (intelx optional via .env).

Modules:
  validate    syntax, MX records (Google DNS), disposable-domain detection
              (full ~3600-domain blocklist fetched by `theeye update`)
  gravatar    public Gravatar profile (name, bio, linked accounts, avatar)
  protonmail  PGP keyserver lookup -> account exists + key creation date
  github      users who made this email public on their profile
  gh_commits  public commits authored with this email (leaks real name + repos)
  twitter     X/Twitter registration check (email_available endpoint)
  spotify     Spotify registration check (signup validation endpoint)
  leakcheck   breach sources containing the email (leakcheck.io public API)
  xposedornot breach names + password-strength/industry analytics
  proxynova   leaked credential lines from the COMB dataset (masked)
  hudsonrock  infostealer-infection check (cavalier free API)
  intelx      leaks/pastes/darknet records (needs INTELX_KEY in .env)
  darkweb     Ahmia .onion search — only via --proxy socks5:// (Tor)
  smtp        RCPT-TO mailbox probe with catch-all detection (opt-in --smtp)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from datetime import datetime, timezone

import httpx
from pathlib import Path

from .engine import USER_AGENTS
from .models import SiteResult, Status
import random

PROTON_DOMAINS = {"proton.me", "protonmail.com", "protonmail.ch", "pm.me", "protonmail.fr"}

# Fallback compact list — the full blocklist (~3600 domains) is downloaded
# to data/disposable.txt by `theeye update`.
DISPOSABLE_DOMAINS = {
    "mailinator.com", "tempmail.com", "temp-mail.org", "guerrillamail.com",
    "guerrillamail.net", "guerrillamail.org", "yopmail.com", "10minutemail.com",
    "10minutemail.net", "throwawaymail.com", "maildrop.cc", "sharklasers.com",
    "dispostable.com", "getnada.com", "tempail.com", "fakeinbox.com",
    "mailnesia.com", "trashmail.com", "trashmail.net", "mohmal.com",
    "emailondeck.com", "mintemail.com", "mytemp.email", "tmpmail.org",
    "spamgourmet.com", "harakirimail.com", "33mail.com", "anonaddy.com",
    "simplelogin.com", "duck.com", "relay.firefox.com", "privaterelay.appleid.com",
}

UA = {"User-Agent": USER_AGENTS[0]}

_DISPOSABLE_PATH = Path(__file__).parent / "data" / "disposable.txt"


def _disposable_domains() -> set:
    if _DISPOSABLE_PATH.exists():
        try:
            return {l.strip().lower() for l in
                    _DISPOSABLE_PATH.read_text(encoding="utf-8").splitlines()
                    if l.strip() and not l.startswith("#")}
        except Exception:
            pass
    return DISPOSABLE_DOMAINS


def _r(module: str, status: Status, reason: str, data: dict | None = None,
       url: str | None = None) -> SiteResult:
    return SiteResult(site=module, status=status, reason=reason,
                      enriched=data or {}, url=url, query=module)


def _mask(value: str) -> str:
    """Keep only a hint of a leaked secret."""
    if len(value) <= 2:
        return "*" * len(value)
    return value[:2] + "***"


async def check_validate(client: httpx.AsyncClient, email: str) -> SiteResult:
    if not re.match(r"^[^@\s]+@[^@\s]+\.[a-zA-Z]{2,}$", email):
        return _r("validate", Status.ILLEGAL, "invalid email syntax")
    domain = email.split("@")[1].lower()
    data: dict = {"domain": domain,
                  "disposable": domain in _disposable_domains()}
    try:
        resp = await client.get("https://dns.google/resolve",
                                params={"name": domain, "type": "MX"}, timeout=10)
        js = resp.json()
        mx = [a["data"] for a in js.get("Answer", []) if a.get("type") == 15]
        data["mx"] = mx
        status = Status.FOUND if mx else Status.NOT_FOUND
        reason = (f"{'disposable, ' if data['disposable'] else ''}"
                  f"{'MX: ' + ', '.join(mx[:3]) if mx else 'no MX records'}")
        return _r("validate", status, reason, data)
    except Exception as e:
        return _r("validate", Status.UNKNOWN, type(e).__name__, data)


async def check_gravatar(client: httpx.AsyncClient, email: str) -> SiteResult:
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://en.gravatar.com/{h}.json"
    try:
        resp = await client.get(url, headers=UA, timeout=12)
    except Exception as e:
        return _r("gravatar", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 404:
        return _r("gravatar", Status.NOT_FOUND, "no Gravatar profile")
    if resp.status_code != 200:
        return _r("gravatar", Status.UNKNOWN, f"HTTP {resp.status_code}")
    e = (resp.json().get("entry") or [{}])[0]
    data = {
        "username": e.get("preferredUsername"),
        "display_name": e.get("displayName"),
        "name": (e.get("name") or {}).get("formatted"),
        "location": e.get("currentLocation"),
        "bio": (e.get("aboutMe") or "")[:300],
        "avatar": (e.get("photos") or [{}])[0].get("value"),
        "profile_url": e.get("profileUrl"),
        "accounts": [{"service": a.get("shortname"), "username": a.get("username"),
                      "url": a.get("url")} for a in e.get("accounts", [])],
    }
    data = {k: v for k, v in data.items() if v}
    who = data.get("display_name") or data.get("username") or ""
    n = len(data.get("accounts", []))
    return _r("gravatar", Status.FOUND,
              f"profile: {who}" + (f" (+{n} linked accounts)" if n else ""),
              data, data.get("profile_url"))


async def check_protonmail(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get("https://api.protonmail.ch/pks/lookup",
                                params={"op": "index", "search": email}, timeout=12)
    except Exception as e:
        return _r("protonmail", Status.UNKNOWN, type(e).__name__)
    if "pub:" not in resp.text:
        return _r("protonmail", Status.NOT_FOUND,
                  "no PGP key (not a Proton address, or key not published)")
    data = {}
    for line in resp.text.splitlines():
        if line.startswith("pub:"):
            parts = line.split(":")
            if len(parts) > 4 and parts[4].isdigit():
                data["key_created"] = datetime.fromtimestamp(
                    int(parts[4]), tz=timezone.utc).strftime("%Y-%m-%d")
            data["keyid"] = parts[1][:16] if len(parts) > 1 else None
        if line.startswith("uid:"):
            data["uid"] = line[4:].split("<")[0].strip()
    reason = "ProtonMail account" + (f" — key created {data['key_created']}"
                                     if data.get("key_created") else "")
    return _r("protonmail", Status.FOUND, reason, data)


async def check_github(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get(
            "https://api.github.com/search/users",
            params={"q": f"{email} in:email"},
            headers={**UA, "Accept": "application/vnd.github+json"}, timeout=12)
    except Exception as e:
        return _r("github", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 403:
        return _r("github", Status.UNKNOWN, "rate-limited (unauthenticated API)")
    if resp.status_code != 200:
        return _r("github", Status.UNKNOWN, f"HTTP {resp.status_code}")
    items = resp.json().get("items", [])
    if not items:
        return _r("github", Status.NOT_FOUND, "no account with public email")
    u = items[0]
    data = {"login": u.get("login"), "url": u.get("html_url"),
            "avatar": u.get("avatar_url")}
    return _r("github", Status.FOUND, f"user: {u.get('login')}", data,
              u.get("html_url"))


async def check_gh_commits(client: httpx.AsyncClient, email: str) -> SiteResult:
    """Commits authored with this email — leaks real names + repos."""
    try:
        resp = await client.get(
            "https://api.github.com/search/commits",
            params={"q": f"author-email:{email}", "per_page": 5},
            headers={**UA, "Accept": "application/vnd.github+json"},
            timeout=12)
    except Exception as e:
        return _r("gh_commits", Status.UNKNOWN, type(e).__name__)
    if resp.status_code == 403:
        return _r("gh_commits", Status.UNKNOWN,
                  "rate-limited (unauthenticated API)")
    if resp.status_code != 200:
        return _r("gh_commits", Status.UNKNOWN, f"HTTP {resp.status_code}")
    items = resp.json().get("items", [])
    if not items:
        return _r("gh_commits", Status.NOT_FOUND,
                  "no public commits authored with this email")
    authors = sorted({c["commit"]["author"]["name"]
                      for c in items if c.get("commit", {}).get("author")})
    repos = sorted({c["repository"]["full_name"] for c in items
                    if c.get("repository")})
    data = {"authors": authors, "repos": repos,
            "sample": [c.get("html_url") for c in items[:5]]}
    return _r("gh_commits", Status.FOUND,
              f"{resp.json().get('total_count', len(items))} public commit(s) — "
              f"author name(s): {', '.join(authors[:3])}", data,
              data["sample"][0] if data["sample"] else None)


async def check_leakcheck(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get("https://leakcheck.io/api/public",
                                params={"check": email}, timeout=15)
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


async def check_xposedornot(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp, ana = await asyncio.gather(
            client.get(f"https://api.xposedornot.com/v1/check-email/{email}",
                       timeout=15),
            client.get("https://api.xposedornot.com/v1/breach-analytics",
                       params={"email": email}, timeout=15))
    except Exception as e:
        return _r("xposedornot", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("xposedornot", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    if js.get("status") != "success":
        return _r("xposedornot", Status.UNKNOWN, js.get("status", "error"))
    breaches = js.get("breaches") or [[]]
    names = sorted({b for group in breaches for b in group})
    if not names:
        return _r("xposedornot", Status.NOT_FOUND, "not in known breaches")
    data: dict = {"sources": names}
    try:
        m = (ana.json().get("BreachMetrics") or {})
        strength = (m.get("passwords_strength") or [{}])[0]
        industry = (m.get("industry") or [[]])[0]
        data["password_strength"] = {k: v for k, v in strength.items() if v}
        data["industries"] = [i[0] for i in industry if i[1]][:8]
    except Exception:
        pass
    weak = (data.get("password_strength") or {}).get("PlainText", 0) + \
           (data.get("password_strength") or {}).get("EasyToCrack", 0)
    return _r("xposedornot", Status.FOUND,
              f"{len(names)} breach source(s)" +
              (f" — {weak} weak/plaintext password(s)" if weak else ""), data)


async def check_proxynova(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get("https://api.proxynova.com/comb",
                                params={"query": email, "start": 0, "limit": 25},
                                timeout=20)
    except Exception as e:
        return _r("proxynova", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("proxynova", Status.UNKNOWN, f"HTTP {resp.status_code}")
    try:
        lines = resp.json().get("lines", [])
    except Exception:
        return _r("proxynova", Status.UNKNOWN, "bad response")
    hits = [l for l in lines if l.lower().startswith(email.lower() + ":")]
    if not hits:
        return _r("proxynova", Status.NOT_FOUND, "no COMB entries")
    masked = []
    for l in hits[:10]:
        _, _, secret = l.partition(":")
        masked.append(f"{email}:{_mask(secret)}")
    return _r("proxynova", Status.FOUND,
              f"{len(hits)} credential line(s) in COMB (masked)",
              {"lines": masked})


async def check_hudsonrock(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get(
            "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email",
            params={"email": email}, timeout=15)
    except Exception as e:
        return _r("hudsonrock", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("hudsonrock", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    stealers = js.get("stealers", [])
    if not stealers:
        return _r("hudsonrock", Status.NOT_FOUND, "no infostealer infection found")
    data = {
        "stealers": [{"date": s.get("date_compromised"),
                      "os": s.get("operating_system"),
                      "computer": s.get("computer_name"),
                      "malware_path": s.get("malware_path"),
                      "antiviruses": s.get("antiviruses")} for s in stealers],
        "corporate_services": js.get("total_corporate_services", 0),
        "user_services": js.get("total_user_services", 0),
    }
    return _r("hudsonrock", Status.FOUND,
              f"{len(stealers)} infostealer infection(s), "
              f"{data['user_services']} user services exposed", data)


async def check_twitter(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get(
            "https://api.twitter.com/i/users/email_available.json",
            params={"email": email}, headers=UA, timeout=12)
    except Exception as e:
        return _r("twitter", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("twitter", Status.UNKNOWN, f"HTTP {resp.status_code}")
    try:
        js = resp.json()
    except Exception:
        return _r("twitter", Status.UNKNOWN, "bad response")
    if js.get("taken"):
        return _r("twitter", Status.FOUND,
                  "email registered on X/Twitter",
                  {"registered": True, "msg": js.get("msg")})
    if js.get("valid") is False and not js.get("taken"):
        return _r("twitter", Status.NOT_FOUND, "no account for this email")
    return _r("twitter", Status.UNKNOWN, f"ambiguous: {js}")


async def check_spotify(client: httpx.AsyncClient, email: str) -> SiteResult:
    try:
        resp = await client.get(
            "https://spclient.wg.spotify.com/signup/public/v1/account",
            params={"validate": 1, "email": email}, headers=UA, timeout=12)
    except Exception as e:
        return _r("spotify", Status.UNKNOWN, type(e).__name__)
    if resp.status_code != 200:
        return _r("spotify", Status.UNKNOWN, f"HTTP {resp.status_code}")
    js = resp.json()
    err = (js.get("errors") or {}).get("email", "")
    if "already registered" in err.lower():
        return _r("spotify", Status.FOUND, "email registered on Spotify",
                  {"registered": True,
                   "country": js.get("country")})
    if js.get("status") == 20:
        return _r("spotify", Status.NOT_FOUND, "no account for this email")
    return _r("spotify", Status.UNKNOWN, f"status {js.get('status')}")


_EMAIL_SITES_PATH = Path(__file__).parent / "data" / "email_sites.json"


def _email_sites() -> list[dict]:
    try:
        return json.loads(_EMAIL_SITES_PATH.read_text(encoding="utf-8"))
    except Exception:
        return []


async def check_registration(client: httpx.AsyncClient, email: str) -> SiteResult:
    """Generic email->account registration checks (blackbird dataset)."""
    sites = _email_sites()
    if not sites:
        return _r("registration", Status.UNKNOWN, "no email_sites.json — run `update`")
    found, checked = [], 0

    async def one(e: dict):
        nonlocal checked
        op = e.get("input_operation")
        if op == "hash-sha256":
            val = hashlib.sha256(email.encode()).hexdigest()
        elif op == "hash-md5":
            val = hashlib.md5(email.encode()).hexdigest()
        else:
            val = email
        url = e["uri_check"].replace("{email}", val)
        try:
            if (e.get("method") or "GET") == "POST":
                resp = await client.post(url, headers={**UA, **(e.get("headers") or {})}, timeout=12)
            else:
                resp = await client.get(url, headers={**UA, **(e.get("headers") or {})}, timeout=12)
        except Exception:
            return
        checked += 1
        body = resp.text
        if e.get("m_string") and e["m_string"] in body:
            return
        if e.get("m_code") is not None and resp.status_code == e["m_code"]:
            return
        hit = True
        if e.get("e_code") is not None and resp.status_code != e["e_code"]:
            hit = False
        if e.get("e_string") and e["e_string"] not in body:
            hit = False
        if not e.get("e_code") and not e.get("e_string"):
            hit = False                       # no detection rule at all
        if hit:
            found.append(e["name"])

    await asyncio.gather(*(one(e) for e in sites))
    if not found:
        return _r("registration", Status.NOT_FOUND,
                  f"not registered on {checked} checked service(s)",
                  {"checked": checked})
    return _r("registration", Status.FOUND,
              f"registered on: {', '.join(sorted(found))}",
              {"services": sorted(found), "checked": checked})


async def check_intelx(client: httpx.AsyncClient, email: str) -> SiteResult:
    from .intelx import intelx_search
    from .config import intelx_key
    if not intelx_key():
        return _r("intelx", Status.UNKNOWN,
                  "skipped — set INTELX_KEY in .env (free at intelx.io)")
    res = await intelx_search(client, email)
    if res["error"]:
        return _r("intelx", Status.UNKNOWN, res["error"])
    recs = res["records"]
    if not recs:
        return _r("intelx", Status.NOT_FOUND, "no intelx records")
    buckets = sorted({r["bucket"] for r in recs if r.get("bucket")})
    return _r("intelx", Status.FOUND,
              f"{len(recs)} record(s) in leaks/pastes/darknet",
              {"records": recs[:15], "buckets": buckets})


def _smtp_probe(email: str, mx: str, timeout: float) -> dict:
    """RCPT TO probe + catch-all detection. Runs in a thread (smtplib is sync)."""
    import smtplib
    with smtplib.SMTP(mx, 25, timeout=timeout) as s:
        s.ehlo("theeye.local")
        s.mail("probe@theeye.local")
        code, _ = s.rcpt(email)
        ghost = f"theeye-{random.randrange(10**9):09d}@{email.split('@')[1]}"
        gcode, _ = s.rcpt(ghost)
        return {"rcpt_code": code, "ghost_code": gcode, "mx": mx}


async def check_smtp(client: httpx.AsyncClient, email: str) -> SiteResult:
    """Mailbox existence via SMTP RCPT — opt-in (--smtp), often blocked on port 25."""
    domain = email.split("@")[1].lower()
    try:
        resp = await client.get("https://dns.google/resolve",
                                params={"name": domain, "type": "MX"},
                                timeout=10)
        mx = [a["data"].rstrip(".") for a in resp.json().get("Answer", [])
              if a.get("type") == 15]
    except Exception as e:
        return _r("smtp", Status.UNKNOWN, f"MX lookup failed: {type(e).__name__}")
    if not mx:
        return _r("smtp", Status.NOT_FOUND, "no MX host to probe")
    try:
        r = await asyncio.to_thread(_smtp_probe, email, mx[0], 12.0)
    except Exception as e:
        return _r("smtp", Status.UNKNOWN,
                  f"port 25 blocked/refused ({type(e).__name__})")
    code, gcode = r["rcpt_code"], r["ghost_code"]
    if code == 250 and gcode == 250:
        return _r("smtp", Status.UNKNOWN,
                  f"catch-all domain ({mx[0]} accepts anything) — unverifiable", r)
    if code == 250:
        return _r("smtp", Status.FOUND,
                  f"mailbox accepted by {mx[0]} (RCPT 250, ghost rejected)", r)
    if code in (550, 551, 553):
        return _r("smtp", Status.NOT_FOUND,
                  f"mailbox rejected by {mx[0]} (RCPT {code})", r)
    return _r("smtp", Status.UNKNOWN, f"inconclusive RCPT {code} via {mx[0]}", r)


AHMIA_ONION = ("http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd"
               ".onion/search/")


async def check_darkweb(client: httpx.AsyncClient, email: str,
                        tor: bool = False) -> SiteResult:
    """Ahmia search over the .onion endpoint — only reachable via Tor."""
    if not tor:
        return _r("darkweb", Status.UNKNOWN,
                  "skipped — needs a Tor proxy (--proxy socks5://127.0.0.1:9050)")
    try:
        resp = await client.get(AHMIA_ONION,
                                params={"q": f'"{email}"'}, timeout=45)
    except Exception as e:
        return _r("darkweb", Status.UNKNOWN,
                  f"Tor/onion unreachable: {type(e).__name__}")
    if resp.status_code != 200:
        return _r("darkweb", Status.UNKNOWN, f"HTTP {resp.status_code}")
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(resp.text, "html.parser")
    hits = []
    for li in soup.select("li.result"):
        a = li.find("a")
        cite = li.find("cite")
        hits.append({"title": a.get_text(strip=True) if a else "?",
                     "onion": cite.get_text(strip=True) if cite else
                     (a["href"] if a else "")})
    if not hits:
        return _r("darkweb", Status.NOT_FOUND,
                  "no .onion pages indexed by Ahmia mention this email")
    return _r("darkweb", Status.FOUND,
              f"{len(hits)} .onion page(s) mention this email",
              {"mentions": hits[:15]})


MODULES = [
    ("validate", check_validate),
    ("gravatar", check_gravatar),
    ("protonmail", check_protonmail),
    ("github", check_github),
    ("gh_commits", check_gh_commits),
    ("registration", check_registration),
    ("twitter", check_twitter),
    ("spotify", check_spotify),
    ("leakcheck", check_leakcheck),
    ("xposedornot", check_xposedornot),
    ("proxynova", check_proxynova),
    ("hudsonrock", check_hudsonrock),
    ("intelx", check_intelx),
    ("darkweb", check_darkweb),
    ("smtp", check_smtp),          # opt-in only (skipped unless in `only`)
]

OPT_IN = {"smtp"}

BREACH_MODULES = ["leakcheck", "xposedornot", "proxynova", "hudsonrock",
                  "intelx", "darkweb"]


async def run_email_scan(email: str, timeout: float = 15.0,
                         proxy: str | None = None,
                         only: list[str] | None = None) -> list[SiteResult]:
    mods = [(n, fn) for n, fn in MODULES
            if (only and n in only) or (not only and n not in OPT_IN)]
    tor = bool(proxy and "socks" in proxy)
    async with httpx.AsyncClient(timeout=timeout, proxy=proxy,
                                 follow_redirects=True) as client:
        return await asyncio.gather(*(
            check_darkweb(client, email, tor) if n == "darkweb"
            else fn(client, email) for n, fn in mods))
