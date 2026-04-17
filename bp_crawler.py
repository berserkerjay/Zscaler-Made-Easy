#!/usr/bin/env python3
"""
Zscaler Best-Practices Discovery Crawler
==========================================
Starts at https://help.zscaler.com/ and BFS-crawls every sub-site
it links to (ZIA, ZPA, ZCC, ZDX, ZIdentity, Deception, Deployments,
and anything else the portal adds in the future). Collects every URL
whose path contains "best-practices" or "leading-practices",
deduplicates against the curated catalog in zscaler_best_practices.py,
and returns any new discoveries.

Secure-by-design
----------------
- Allowlist: only help.zscaler.com. Any off-domain link is dropped
  before fetch, regardless of how many hops deep we are.
- Extension blocklist: .pdf, .zip, images, media, archives, and
  script/style assets are never fetched.
- Reuses the hardened HTTP path from zscaler_update_check._safe_get
  (timeouts, proxy / TLS-inspection env vars, strict host check).
- Uses stdlib html.parser only — no BeautifulSoup, no JS execution,
  no external JS fetched, so a malicious page cannot run code against
  this process.
- Polite throttle (CRAWL_POLITE_DELAY) between requests so we don't
  hammer the help portal.
- Hard caps on pages (MAX_PAGES), depth (MAX_DEPTH), and links per
  page (MAX_LINKS_PER_PAGE) so a runaway crawl is impossible.
- Cached to disk at the OS-native cache path (default TTL 24h).
"""
from __future__ import annotations

import json
import os
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse, urljoin


# Seeds — start at the root plus every known sub-site landing page.
# The root alone is sometimes a JS-rendered SPA with no static <a>
# links (stdlib html.parser can't execute JS), which would starve
# the BFS queue. Pairing the root with the curated sub-site landing
# pages guarantees we always have extractable HTML to traverse, and
# BFS still picks up any NEW sub-site the root links to.
SEED_PAGES = [
    "https://help.zscaler.com/",
    "https://help.zscaler.com/zia",
    "https://help.zscaler.com/zpa",
    "https://help.zscaler.com/zscaler-client-connector",
    "https://help.zscaler.com/zdx",
    "https://help.zscaler.com/zidentity",
    "https://help.zscaler.com/deception",
    "https://help.zscaler.com/zscaler-deployments-operations",
]

# Host allowlist — ANY fetch outside this set is refused.
ALLOWED_HOST = "help.zscaler.com"

# URL-path patterns we keep as matches. These are substrings (case-insensitive).
ARTICLE_PATTERNS = [
    "best-practice",     # /best-practices-..., /best-practice-...
    "leading-practice",  # /leading-practices-...
]

# File extensions we never fetch — attachments, media, archives.
SKIP_EXTENSIONS = (
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".mp4", ".webm", ".mp3", ".wav",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".css", ".js", ".json", ".xml",
)

# Caps so a buggy page can never turn this into a crawl-the-internet.
MAX_PAGES = 250             # total pages we'll fetch per crawl
MAX_LINKS_PER_PAGE = 400    # links inspected on any one page
MAX_DEPTH = 4               # hops from the root seed
CRAWL_POLITE_DELAY = 0.25   # seconds between requests
CACHE_TTL_SECONDS = 86400   # 24h

# Service guesser: infer ZIA/ZPA/ZCC/Deception from the URL path.
_SERVICE_BY_PATH_PREFIX = [
    ("/zia/",                         "ZIA"),
    ("/zpa/",                         "ZPA"),
    ("/zscaler-client-connector/",    "ZCC"),
    ("/zscaler-deployments-operations/", "Deployment"),
    ("/deception/",                   "Deception"),
    ("/zdx/",                         "ZDX"),
    ("/zidentity/",                   "ZIdentity"),
]


def _cache_path() -> str:
    """Same OS conventions as the update-checker cache."""
    try:
        import sys
        if sys.platform == "win32":
            base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
            d = os.path.join(base, "ZscalerAssessment")
        elif sys.platform == "darwin":
            d = os.path.expanduser("~/Library/Caches/ZscalerAssessment")
        else:
            d = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")),
                             "zscaler_assessment")
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(d, "bp_crawl_cache.json")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]) -> None:
    try:
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def _service_from_url(url: str) -> str:
    p = (urlparse(url).path or "").lower()
    for prefix, label in _SERVICE_BY_PATH_PREFIX:
        if p.startswith(prefix):
            return label
    return "Other"


def _is_allowed(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and (p.hostname or "").lower() == ALLOWED_HOST
    except Exception:
        return False


def _matches_article_pattern(url: str) -> bool:
    p = (urlparse(url).path or "").lower()
    return any(pat in p for pat in ARTICLE_PATTERNS)


def _has_skip_extension(url: str) -> bool:
    p = (urlparse(url).path or "").lower()
    return p.endswith(SKIP_EXTENSIONS)


def _titleize_from_slug(url: str) -> str:
    """Fallback title when the link text is empty — pulled from the URL slug."""
    slug = (urlparse(url).path or "").rstrip("/").rsplit("/", 1)[-1]
    words = slug.replace("-", " ").replace("_", " ").split()
    return " ".join(w.capitalize() if not w.isupper() else w for w in words)


class _LinkExtractor(HTMLParser):
    """Collects (href, link_text) pairs. Ignores scripts/styles, treats
    any href value as-is (it's validated later by _is_allowed)."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: List[Tuple[str, str]] = []
        self._inside_a = False
        self._href: Optional[str] = None
        self._text_buf: List[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a":
            href = dict(attrs).get("href", "")
            if href:
                self._inside_a = True
                self._href = href
                self._text_buf = []

    def handle_endtag(self, tag):
        if tag in ("script", "style", "noscript"):
            if self._skip_depth > 0:
                self._skip_depth -= 1
            return
        if tag == "a" and self._inside_a:
            text = " ".join("".join(self._text_buf).split()).strip()
            self.out.append((self._href or "", text))
            self._inside_a = False
            self._href = None
            self._text_buf = []

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._inside_a:
            self._text_buf.append(data)


def _extract_links(html: str, base_url: str) -> List[Tuple[str, str]]:
    """Return (absolute_url, link_text) pairs. Resolves relative hrefs
    against base_url so '/zia/xyz' becomes 'https://help.zscaler.com/zia/xyz'."""
    try:
        p = _LinkExtractor()
        p.feed(html[:2_000_000])   # hard cap in case a page is pathologically large
    except Exception:
        return []
    out = []
    for href, text in p.out[:MAX_LINKS_PER_PAGE]:
        try:
            abs_url = urljoin(base_url, href)
            # Drop fragment so /foo#bar and /foo are the same entry
            abs_url = abs_url.split("#", 1)[0]
            if abs_url:
                out.append((abs_url, text))
        except Exception:
            continue
    return out


def crawl(skip_tls_verify: bool = False, force: bool = False) -> Dict[str, Any]:
    """
    Discover Zscaler best-practice articles beyond the curated list.

    Args:
      skip_tls_verify: pass-through to the HTTP client for corporate
        TLS-MITM environments (same as update-checker).
      force: ignore the cache TTL and re-crawl.

    Returns:
      {
        "started_at": ISO ts,
        "elapsed_seconds": float,
        "pages_fetched": N,
        "pages_failed": N,
        "total_matched": N,
        "discovered": [
          {"url", "title", "service", "source_page"}, ...
        ],
        "curated_count": N,
        "new_since_curated": N,
        "cache_age_seconds": float or None,
        "from_cache": bool,
        "errors": [{"url","error"}, ...],
      }
    """
    started = time.time()

    # Cache check
    cache = _load_cache()
    cache_ts = cache.get("timestamp") or 0
    cache_age = time.time() - cache_ts if cache_ts else None
    if not force and cache_ts and (time.time() - cache_ts) < CACHE_TTL_SECONDS:
        cache["from_cache"] = True
        cache["cache_age_seconds"] = round(time.time() - cache_ts, 1)
        return cache

    # Reuse the update-checker's HTTP path so proxy / TLS-bypass /
    # timeout rules stay consistent with everything else in the app.
    try:
        from zscaler_update_check import _safe_get
    except Exception as e:
        return {"error": f"_safe_get unavailable: {e}", "discovered": []}

    # Load curated list to dedupe against
    try:
        from zscaler_best_practices import BEST_PRACTICES
        curated_urls = {entry["url"] for entry in BEST_PRACTICES}
    except Exception:
        curated_urls = set()

    seen_urls: Set[str] = set()        # everything we've fetched or queued
    matched: Dict[str, Dict[str, Any]] = {}  # url -> entry
    link_titles: Dict[str, str] = {}   # preserve anchor text seen in-link for later
    errors: List[Dict[str, Any]] = []
    # Diagnostics: capture how many links we found on each fetched page,
    # so if a crawl returns 0 matches we can see whether the pages were
    # empty (SPA/JS-only) or full of non-matching links.
    per_page_links: List[Dict[str, Any]] = []

    # BFS queue of (url, depth). Start at root seeds; every help.zscaler.com
    # link discovered during a fetch gets enqueued up to MAX_DEPTH hops.
    to_fetch: List[Tuple[str, int]] = [(u, 0) for u in SEED_PAGES]
    for u, _ in to_fetch:
        seen_urls.add(u)
    pages_fetched = 0
    pages_failed = 0

    while to_fetch and pages_fetched < MAX_PAGES:
        url, depth = to_fetch.pop(0)
        if not _is_allowed(url) or _has_skip_extension(url):
            continue

        # Polite throttle — don't hammer the help portal
        if pages_fetched > 0 and CRAWL_POLITE_DELAY > 0:
            time.sleep(CRAWL_POLITE_DELAY)

        body, code, err = _safe_get(url, verify_tls=False if skip_tls_verify else None)
        if err or code != 200 or not body:
            pages_failed += 1
            errors.append({"url": url, "error": err or f"HTTP {code}"})
            continue
        pages_fetched += 1

        try:
            html = body.decode("utf-8", errors="ignore")
        except Exception:
            continue

        all_links = _extract_links(html, url)
        allowed_links = 0
        bp_links_this_page = 0
        for abs_url, text in all_links:
            if not _is_allowed(abs_url) or _has_skip_extension(abs_url):
                continue
            allowed_links += 1

            # Track anchor text for any BP article we see — used as title
            if _matches_article_pattern(abs_url):
                bp_links_this_page += 1
                if abs_url not in matched:
                    title = (text or _titleize_from_slug(abs_url)).strip()
                    title = re.sub(r"\s*[›»→]\s*$", "", title)
                    matched[abs_url] = {
                        "url": abs_url,
                        "title": title or _titleize_from_slug(abs_url),
                        "service": _service_from_url(abs_url),
                        "source_page": url,
                    }

            # Enqueue for deeper crawl if within depth budget
            if depth + 1 <= MAX_DEPTH and abs_url not in seen_urls:
                seen_urls.add(abs_url)
                to_fetch.append((abs_url, depth + 1))

        # Keep a small per-page breadcrumb for diagnostics
        if len(per_page_links) < 25:
            per_page_links.append({
                "url": url,
                "depth": depth,
                "bytes": len(body),
                "total_links": len(all_links),
                "allowed_links": allowed_links,
                "bp_links": bp_links_this_page,
            })

    discovered = sorted(matched.values(), key=lambda e: (e["service"], e["title"].lower()))
    new_since_curated = [e for e in discovered if e["url"] not in curated_urls]

    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.time() - started, 2),
        "pages_fetched": pages_fetched,
        "pages_failed": pages_failed,
        "pages_seen": len(seen_urls),
        "max_depth": MAX_DEPTH,
        "total_matched": len(discovered),
        "discovered": discovered,
        "curated_count": len(curated_urls),
        "new_since_curated": len(new_since_curated),
        "new_entries": new_since_curated,
        "errors": errors[:20],
        "per_page_sample": per_page_links,
        "from_cache": False,
        "cache_age_seconds": None,
        "timestamp": time.time(),
        "cache_file": _cache_path(),
    }
    _save_cache(result)
    return result


def reset_cache() -> bool:
    try:
        p = _cache_path()
        if os.path.exists(p):
            os.remove(p)
        return True
    except Exception:
        return False


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--skip-tls", action="store_true")
    args = ap.parse_args()
    if args.reset:
        print("cache cleared:", reset_cache())
    out = crawl(skip_tls_verify=args.skip_tls, force=args.force)
    # Print a concise summary rather than the full blob
    print(f"pages: {out.get('pages_fetched')} fetched, {out.get('pages_failed')} failed, "
          f"{out.get('pages_seen', 0)} seen (depth<={out.get('max_depth','?')}), "
          f"{out.get('elapsed_seconds')}s elapsed")
    print(f"total matched: {out.get('total_matched')}  "
          f"(curated: {out.get('curated_count')}, new: {out.get('new_since_curated')})")
    for e in (out.get('new_entries') or [])[:20]:
        print(f"  NEW  [{e['service']}] {e['title']}")
        print(f"       {e['url']}")
