#!/usr/bin/env python3
"""
Zscaler Best-Practices Discovery Crawler
==========================================
Iterates the source registry in bp_sources.py (help.zscaler.com,
Zscaler blogs, developer portal, community, Microsoft Learn, AWS docs,
etc.) and BFS-crawls each crawlable source. Collects every URL whose
path matches that source's article-patterns (best-practices /
leading-practices / how-to / guide), tags each discovery with the
source's credibility tier, deduplicates against the curated catalog
in zscaler_best_practices.py, and returns any new discoveries.

Secure-by-design
----------------
- Host allowlist: each crawled URL must match the host of a registered
  source AND must be in zscaler_update_check.ALLOWED_HOSTS. Off-domain
  links are dropped before fetch regardless of depth.
- Per-source BFS: the crawler never jumps sources mid-walk. A link
  from help.zscaler.com to www.zscaler.com is ignored; each source is
  seeded independently so credibility attribution stays honest.
- Extension blocklist: .pdf, .zip, images, media, archives, and
  script/style assets are never fetched.
- Reuses the hardened HTTP path from zscaler_update_check._safe_get
  (timeouts, proxy / TLS-inspection env vars, strict host check).
- Uses stdlib html.parser only — no BeautifulSoup, no JS execution,
  no external JS fetched, so a malicious page cannot run code against
  this process.
- Polite throttle (CRAWL_POLITE_DELAY) between requests so we don't
  hammer any single source.
- Hard caps on pages (MAX_PAGES_PER_SOURCE), depth (MAX_DEPTH), and
  links per page (MAX_LINKS_PER_PAGE) so a runaway crawl is impossible.
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


# File extensions we never fetch — attachments, media, archives.
SKIP_EXTENSIONS = (
    ".pdf", ".zip", ".tar", ".gz", ".7z", ".rar",
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".mp4", ".webm", ".mp3", ".wav",
    ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".css", ".js", ".json", ".xml",
)

# Caps so a buggy page can never turn this into a crawl-the-internet.
MAX_PAGES_PER_SOURCE = 120  # pages we'll fetch from any single source
MAX_PAGES_TOTAL = 500       # overall ceiling across every source
MAX_LINKS_PER_PAGE = 400    # links inspected on any one page
MAX_DEPTH = 4               # hops from a source's seed
CRAWL_POLITE_DELAY = 0.25   # seconds between requests to the same source
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


def _host_of(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def _is_allowed_for_source(url: str, source_host: str) -> bool:
    """A URL is crawlable within a source only if (a) scheme is http/s
    and (b) its host matches the source's declared host exactly. This
    keeps a help.zscaler.com crawl from wandering onto www.zscaler.com
    (and vice versa) — each source is walked in isolation so the
    credibility attribution stays honest."""
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and (p.hostname or "").lower() == source_host
    except Exception:
        return False


def _matches_article_patterns(url: str, patterns) -> bool:
    if not patterns:
        return False
    p = (urlparse(url).path or "").lower()
    return any(pat in p for pat in patterns)


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


def _crawl_source(source: Dict[str, Any], safe_get, skip_tls_verify: bool,
                  global_page_budget: int) -> Dict[str, Any]:
    """BFS-walk a single source. Returns a per-source sub-report.
    `global_page_budget` caps pages_fetched from THIS source to keep
    the overall crawl bounded even when many sources are registered."""
    source_host = source.get("host", "")
    seeds = source.get("seeds") or []
    patterns = [p.lower() for p in (source.get("article_patterns") or [])]
    per_source_cap = min(MAX_PAGES_PER_SOURCE, max(1, global_page_budget))

    seen: Set[str] = set()
    matched: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, Any]] = []
    per_page: List[Dict[str, Any]] = []

    to_fetch: List[Tuple[str, int]] = []
    for u in seeds:
        if u not in seen:
            to_fetch.append((u, 0))
            seen.add(u)

    pages_fetched = 0
    pages_failed = 0

    while to_fetch and pages_fetched < per_source_cap:
        url, depth = to_fetch.pop(0)
        if not _is_allowed_for_source(url, source_host) or _has_skip_extension(url):
            continue

        if pages_fetched > 0 and CRAWL_POLITE_DELAY > 0:
            time.sleep(CRAWL_POLITE_DELAY)

        body, code, err = safe_get(url, verify_tls=False if skip_tls_verify else None)
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
            if not _is_allowed_for_source(abs_url, source_host) or _has_skip_extension(abs_url):
                continue
            allowed_links += 1

            if _matches_article_patterns(abs_url, patterns):
                bp_links_this_page += 1
                if abs_url not in matched:
                    title = (text or _titleize_from_slug(abs_url)).strip()
                    title = re.sub(r"\s*[›»→]\s*$", "", title)
                    matched[abs_url] = {
                        "url": abs_url,
                        "title": title or _titleize_from_slug(abs_url),
                        "service": _service_from_url(abs_url),
                        "source_page": url,
                        "source_id": source["id"],
                        "source_name": source.get("name", source["id"]),
                        "credibility": int(source.get("credibility", 0)),
                        "tier": source.get("tier", "unverified"),
                    }

            if depth + 1 <= MAX_DEPTH and abs_url not in seen:
                seen.add(abs_url)
                to_fetch.append((abs_url, depth + 1))

        if len(per_page) < 10:
            per_page.append({
                "url": url,
                "depth": depth,
                "bytes": len(body),
                "total_links": len(all_links),
                "allowed_links": allowed_links,
                "bp_links": bp_links_this_page,
            })

    return {
        "source_id": source["id"],
        "source_name": source.get("name", source["id"]),
        "host": source_host,
        "tier": source.get("tier", "unverified"),
        "credibility": int(source.get("credibility", 0)),
        "pages_fetched": pages_fetched,
        "pages_failed": pages_failed,
        "pages_seen": len(seen),
        "matched": list(matched.values()),
        "errors": errors[:10],
        "per_page_sample": per_page,
    }


def crawl(skip_tls_verify: bool = False, force: bool = False,
          source_ids: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Discover Zscaler best-practice articles beyond the curated list.

    Args:
      skip_tls_verify: pass-through to the HTTP client for corporate
        TLS-MITM environments (same as update-checker).
      force: ignore the cache TTL and re-crawl.
      source_ids: optional filter — only crawl these source ids. When
        omitted, every crawlable source in bp_sources is visited.

    Returns:
      {
        "started_at": ISO ts,
        "elapsed_seconds": float,
        "pages_fetched": N,            # total across all sources
        "pages_failed": N,
        "total_matched": N,
        "discovered": [
          {"url","title","service","source_page",
           "source_id","source_name","credibility","tier"}, ...
        ],
        "new_entries": [...],          # subset not in curated catalog
        "per_source": [ {...}, ... ],  # per-source rollup
        "errors": [{"url","error"}, ...],
        "from_cache": bool,
      }
    """
    started = time.time()

    cache = _load_cache()
    cache_ts = cache.get("timestamp") or 0
    if not force and cache_ts and (time.time() - cache_ts) < CACHE_TTL_SECONDS:
        cache["from_cache"] = True
        cache["cache_age_seconds"] = round(time.time() - cache_ts, 1)
        return cache

    try:
        from zscaler_update_check import _safe_get
    except Exception as e:
        return {"error": f"_safe_get unavailable: {e}", "discovered": []}

    try:
        from bp_sources import crawlable_sources
    except Exception as e:
        return {"error": f"bp_sources unavailable: {e}", "discovered": []}

    try:
        from zscaler_best_practices import BEST_PRACTICES
        curated_urls = {entry["url"] for entry in BEST_PRACTICES}
    except Exception:
        curated_urls = set()

    sources = crawlable_sources()
    if source_ids:
        want = set(source_ids)
        sources = [s for s in sources if s["id"] in want]

    all_matched: Dict[str, Dict[str, Any]] = {}
    per_source_reports: List[Dict[str, Any]] = []
    total_pages_fetched = 0
    total_pages_failed = 0
    total_pages_seen = 0
    all_errors: List[Dict[str, Any]] = []
    per_page_sample: List[Dict[str, Any]] = []

    for src in sources:
        remaining = MAX_PAGES_TOTAL - total_pages_fetched
        if remaining <= 0:
            break
        report = _crawl_source(src, _safe_get, skip_tls_verify, remaining)
        per_source_reports.append({k: v for k, v in report.items() if k != "matched"})
        total_pages_fetched += report["pages_fetched"]
        total_pages_failed += report["pages_failed"]
        total_pages_seen += report["pages_seen"]
        all_errors.extend(report.get("errors") or [])
        per_page_sample.extend(report.get("per_page_sample") or [])
        # Dedup discoveries by URL across sources; highest-credibility
        # source wins if the same URL appears twice (unlikely given
        # per-source host isolation, but defensive).
        for e in report.get("matched") or []:
            prev = all_matched.get(e["url"])
            if not prev or e.get("credibility", 0) > prev.get("credibility", 0):
                all_matched[e["url"]] = e

    discovered = sorted(
        all_matched.values(),
        key=lambda e: (-int(e.get("credibility", 0)), e.get("service", ""), e["title"].lower()),
    )
    new_since_curated = [e for e in discovered if e["url"] not in curated_urls]

    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.time() - started, 2),
        "pages_fetched": total_pages_fetched,
        "pages_failed": total_pages_failed,
        "pages_seen": total_pages_seen,
        "max_depth": MAX_DEPTH,
        "sources_crawled": len(per_source_reports),
        "per_source": per_source_reports,
        "total_matched": len(discovered),
        "discovered": discovered,
        "curated_count": len(curated_urls),
        "new_since_curated": len(new_since_curated),
        "new_entries": new_since_curated,
        "errors": all_errors[:30],
        "per_page_sample": per_page_sample[:25],
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
    ap.add_argument("--source", action="append",
                    help="only crawl this source id (repeatable)")
    args = ap.parse_args()
    if args.reset:
        print("cache cleared:", reset_cache())
    out = crawl(skip_tls_verify=args.skip_tls, force=args.force,
                source_ids=args.source)
    print(f"pages: {out.get('pages_fetched')} fetched, {out.get('pages_failed')} failed, "
          f"{out.get('pages_seen', 0)} seen across {out.get('sources_crawled', 0)} source(s), "
          f"{out.get('elapsed_seconds')}s elapsed")
    print(f"total matched: {out.get('total_matched')}  "
          f"(curated: {out.get('curated_count')}, new: {out.get('new_since_curated')})")
    for r in out.get('per_source') or []:
        print(f"  {r['source_id']:<20} [{r['tier']:<13}] {r['pages_fetched']:>3} pages, "
              f"{r['pages_failed']:>2} failed")
    for e in (out.get('new_entries') or [])[:20]:
        print(f"  NEW  [{e['service']}] ({e.get('tier','?')}) {e['title']}")
        print(f"       {e['url']}")
