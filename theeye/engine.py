from __future__ import annotations

import asyncio
import random
import re
import time

import httpx

from .models import Site, SiteResult, Status, ScanReport

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]

BLOCK_CODES = {401, 403, 406, 429, 503}
NOT_FOUND_CODES = {404, 410}


def _judge(site: Site, status: int, body: str, final_url: str, username: str) -> tuple[Status, str, str]:
    """Return (status, confidence, reason)."""
    body_l = body.lower()

    for needle in site.absence_strs:
        n = needle.replace("{username}", username)
        if n and n.lower() in body_l:
            return Status.NOT_FOUND, "high", f"absence string: {n[:60]!r}"

    for needle in site.presence_strs:
        n = needle.replace("{username}", username)
        if n and n.lower() in body_l:
            return Status.FOUND, "high", f"presence string: {n[:60]!r}"

    if site.check_type == "response_url" or site.error_url:
        err = (site.error_url or "").replace("{username}", username)
        if err and final_url.startswith(err):
            return Status.NOT_FOUND, "medium", "redirected to error url"
        if err and not final_url.startswith(err):
            return Status.FOUND, "medium", "no error redirect"

    if site.m_code is not None and status == site.m_code:
        return Status.NOT_FOUND, "high", f"missing code {status}"
    if site.e_code is not None and status == site.e_code:
        return Status.FOUND, "high", f"exists code {status}"

    if status in NOT_FOUND_CODES:
        return Status.NOT_FOUND, "medium", f"HTTP {status}"
    if site.ignore_403 and status == 403:
        return Status.UNKNOWN, "low", "403 ignored by site config"
    if status in BLOCK_CODES:
        return Status.UNKNOWN, "low", f"HTTP {status} (blocked/protected)"
    if 200 <= status < 300:
        conf = "medium" if site.check_type == "status_code" else "low"
        return Status.FOUND, conf, f"HTTP {status}"
    if 300 <= status < 400:
        return Status.UNKNOWN, "low", f"HTTP {status} redirect"
    return Status.UNKNOWN, "low", f"HTTP {status}"


class Scanner:
    def __init__(
        self,
        concurrency: int = 100,
        timeout: float = 12.0,
        proxy: str | None = None,
        retries: int = 1,
    ):
        self.sem = asyncio.Semaphore(concurrency)
        self._host_sems: dict[str, asyncio.Semaphore] = {}
        self.timeout = timeout
        self.retries = retries
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=8.0),
            follow_redirects=True,
            proxy=proxy,
            limits=httpx.Limits(max_connections=concurrency * 2,
                                max_keepalive_connections=concurrency),
            http2=False,
        )

    async def close(self):
        await self.client.aclose()

    def _host_sem(self, url: str) -> asyncio.Semaphore:
        """Per-host concurrency cap (6) — global semaphore alone hammers one
        domain with 100 parallel requests and collects 429s."""
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        sem = self._host_sems.get(host)
        if sem is None:
            sem = self._host_sems[host] = asyncio.Semaphore(6)
        return sem

    async def check(self, site: Site, username: str, query: str | None = None) -> SiteResult:
        q = query or username
        base = dict(site=site.name, url=None,
                    protection=site.protection, tags=site.tags,
                    nsfw=site.nsfw, rank=site.rank, query=q)

        if site.regex_check and not re.match(site.regex_check, q):
            return SiteResult(**base, status=Status.ILLEGAL,
                              reason="username rejected by site regex")

        url = site.check_url(q)
        base["url"] = site.profile_url(q)
        method = "HEAD" if site.head_only else (site.method or "GET")
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
            **{k: v.replace("{username}", q) for k, v in (site.headers or {}).items()},
        }
        payload = None
        if site.payload:
            payload = {k: str(v).replace("{username}", q) for k, v in site.payload.items()}

        t0 = time.monotonic()
        try:
            async with self.sem, self._host_sem(url):
                resp = await self._request(method, url, headers, payload)
        except Exception as e:  # network error, dns, ssl, timeout...
            return SiteResult(**base, status=Status.UNKNOWN,
                              response_ms=int((time.monotonic() - t0) * 1000),
                              reason=type(e).__name__)

        ms = int((time.monotonic() - t0) * 1000)
        try:
            body = "" if method == "HEAD" else resp.text
        except Exception:
            body = ""

        status, conf, reason = _judge(site, resp.status_code, body, str(resp.url), q)
        if site.protection and status == Status.FOUND:
            conf = "low"
            reason += " | protected site"

        return SiteResult(**base, status=status, http_code=resp.status_code,
                          response_ms=ms, confidence=conf, reason=reason)

    async def _request(self, method: str, url: str, headers: dict, payload):
        last = None
        for attempt in range(self.retries + 1):
            try:
                if method == "HEAD":
                    resp = await self.client.head(url, headers=headers)
                elif method == "POST":
                    resp = await self.client.post(url, headers=headers, data=payload)
                else:
                    resp = await self.client.get(url, headers=headers)
                # transient blocks deserve a retry, not an instant "unknown"
                if resp.status_code in (429, 503) and attempt < self.retries:
                    ra = resp.headers.get("retry-after")
                    try:
                        wait = min(float(ra), 5.0) if ra else 0.8 * (attempt + 1)
                    except ValueError:
                        wait = 0.8 * (attempt + 1)
                    await asyncio.sleep(wait)
                    continue
                return resp
            except (httpx.ConnectError, httpx.ConnectTimeout, httpx.ReadTimeout,
                    httpx.WriteTimeout, httpx.PoolTimeout, httpx.RemoteProtocolError) as e:
                last = e
                if attempt < self.retries:
                    await asyncio.sleep(0.3 * (attempt + 1))
        raise last

    async def scan(self, username: str, sites: list[Site],
                   on_result=None, queries: list[str] | None = None) -> ScanReport:
        report = ScanReport(username=username)
        tasks = []
        qs = queries or [username]
        for q in qs:
            for site in sites:
                tasks.append(self.check(site, username, q))

        for fut in asyncio.as_completed(tasks):
            res = await fut
            report.results.append(res)
            if on_result:
                on_result(res)
        report.finished = time.time()
        return report
