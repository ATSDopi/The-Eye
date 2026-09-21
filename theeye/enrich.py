"""Enrich found profiles by scraping public metadata from the profile page.

Extracts: title, meta/OG description, OG image (avatar), JSON-LD Person fields,
canonical url, and site-specific JSON blobs when cheap to grab.
"""

from __future__ import annotations

import asyncio
import json
import re

import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse

from .engine import USER_AGENTS
from .models import SiteResult
import random

# outbound links worth following — cross-account pivots
PIVOT_DOMAINS = {
    "twitter.com", "x.com", "github.com", "gitlab.com", "instagram.com",
    "linkedin.com", "youtube.com", "facebook.com", "t.me", "telegram.me",
    "keybase.io", "bsky.app", "tiktok.com", "reddit.com", "medium.com",
    "substack.com", "twitch.tv", "discord.gg", "discord.com", "paypal.me",
    "patreon.com", "cash.app", "venmo.com", "linktr.ee", "ko-fi.com",
    "buymeacoffee.com", "mastodon.social", "stackoverflow.com",
    "codepen.io", "dev.to", "hashnode.com", "behance.net", "dribbble.com",
}


# path segments that are navigation, not profiles
NON_PROFILE = {"docs", "collections", "enterprise", "site-policy", "features",
               "pricing", "explore", "topics", "marketplace", "about", "blog",
               "support", "legal", "settings", "articles", "help", "login",
               "signup", "search", "organizations", "customer-stories", "home"}


def _pivots(soup: BeautifulSoup, own_host: str = "") -> tuple[list[str], list[str]]:
    """External profile links + mailto emails found on the page."""
    links, emails = set(), set()
    for a in soup.find_all("a", href=True):
        h = a["href"].strip()
        if h.startswith("mailto:"):
            e = h[7:].split("?")[0].strip()
            if "@" in e and "." in e:
                emails.add(e.lower())
        elif h.startswith("http"):
            try:
                host = re.sub(r"^www\.", "", urlparse(h).netloc.lower())
                seg = [p for p in urlparse(h).path.split("/") if p]
                is_pivot = host in PIVOT_DOMAINS or any(
                    host.endswith("." + d) for d in PIVOT_DOMAINS)
                # profile-ish only: a handle in the path, not site navigation
                if (is_pivot and seg and seg[0].lower() not in NON_PROFILE
                        and host != own_host):
                    links.add(h.split("?")[0].split("#")[0].rstrip("/"))
            except Exception:
                continue
    return sorted(links)[:12], sorted(emails)[:5]


def _meta(soup: BeautifulSoup, *names: str) -> str | None:
    for n in names:
        tag = soup.find("meta", attrs={"property": n}) or soup.find("meta", attrs={"name": n})
        if tag and tag.get("content"):
            return tag["content"].strip()
    return None


def _jsonld(soup: BeautifulSoup) -> dict:
    out = {}
    for tag in soup.find_all("script", attrs={"type": "application/ld+json"}):
        try:
            data = json.loads(tag.string or tag.get_text() or "")
        except Exception:
            continue
        nodes = data if isinstance(data, list) else [data]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            t = node.get("@type", "")
            t = t[0] if isinstance(t, list) else t
            if t in ("Person", "ProfilePage", "Organization"):
                for k in ("name", "alternateName", "description", "jobTitle",
                          "nationality", "homeLocation"):
                    if node.get(k) and k not in out:
                        v = node[k]
                        out[k] = v.get("name") if isinstance(v, dict) else v
                img = node.get("image")
                if isinstance(img, dict):
                    img = img.get("url")
                if img and "image" not in out:
                    out["image"] = img
                loc = node.get("address") or node.get("location")
                if isinstance(loc, dict) and loc.get("addressLocality"):
                    out.setdefault("location", loc["addressLocality"])
    return out


def parse_profile(html: str, url: str) -> dict:
    soup = BeautifulSoup(html, "html.parser")
    data: dict = {}

    title = soup.find("title")
    if title and title.get_text(strip=True):
        data["title"] = title.get_text(strip=True)[:200]

    for key, names in {
        "description": ("og:description", "description", "twitter:description"),
        "og_title": ("og:title", "twitter:title"),
        "avatar": ("og:image", "twitter:image"),
        "site_name": ("og:site_name",),
        "canonical": (),
    }.items():
        v = _meta(soup, *names)
        if v:
            data[key] = v[:500] if key == "description" else v

    link = soup.find("link", rel="canonical")
    if link and link.get("href"):
        data["canonical"] = link["href"]

    data.update({f"ld_{k}": v for k, v in _jsonld(soup).items()})

    # follower/member counts often embedded like "12,345 followers"
    text = soup.get_text(" ", strip=True)[:20000]
    m = re.search(r"([\d,.]+[KkMm]?)\s+(followers|abonnés|members|subscribers)", text, re.I)
    if m:
        data["followers"] = f"{m.group(1)} {m.group(2)}"

    own_host = ""
    try:
        own_host = re.sub(r"^www\.", "", urlparse(url).netloc.lower())
    except Exception:
        pass
    links, emails = _pivots(soup, own_host)
    if links:
        data["links"] = links
    if emails:
        data["emails"] = emails

    return {k: v for k, v in data.items() if v}


class Enricher:
    def __init__(self, concurrency: int = 20, timeout: float = 10.0):
        self.sem = asyncio.Semaphore(concurrency)
        self.timeout = timeout

    async def enrich_all(self, client: httpx.AsyncClient, results: list[SiteResult],
                         limit: int = 60, on_done=None) -> int:
        todo = [r for r in results if r.url][:limit]
        count = 0

        async def one(r: SiteResult):
            nonlocal count
            async with self.sem:
                try:
                    resp = await client.get(
                        r.url,
                        headers={"User-Agent": random.choice(USER_AGENTS)},
                        timeout=self.timeout,
                        follow_redirects=True,
                    )
                    if 200 <= resp.status_code < 300:
                        r.enriched = parse_profile(resp.text, resp.url and str(resp.url) or r.url)
                        count += 1
                except Exception:
                    pass
            if on_done:
                on_done(r)

        await asyncio.gather(*(one(r) for r in todo))
        return count


async def avatar_pivots(client: httpx.AsyncClient, results,
                        limit: int = 40) -> dict[str, list[str]]:
    """Hash profile avatars — the same image on several sites is a strong
    identity link (same person reusing their picture)."""
    import hashlib
    urls: dict[str, list[SiteResult]] = {}
    for r in results:
        if getattr(r, "verified", "") == "fp":
            continue
        u = (r.enriched or {}).get("avatar") or (r.enriched or {}).get("ld_image")
        if u:
            urls.setdefault(u, []).append(r)

    hashes: dict[str, set[str]] = {}
    for u, rs in list(urls.items())[:limit]:
        try:
            resp = await client.get(u, timeout=10,
                                    headers={"User-Agent": random.choice(USER_AGENTS)})
            if resp.status_code == 200 and len(resp.content) > 100:
                h = hashlib.sha256(resp.content).hexdigest()
                for r in rs:
                    hashes.setdefault(h, set()).add(r.site)
        except Exception:
            continue
    return {h: sorted(s) for h, s in hashes.items() if len(s) > 1}
