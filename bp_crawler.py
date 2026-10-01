#!/usr/bin/env python3
"""
Zscaler Best-Practices Discovery Crawler
==========================================
Iterates the source registry in bp_sources.py (help.zscaler.com,
Zscaler blogs, developer portal, community, Microsoft Learn, AWS docs,
etc.) and finds every article whose URL matches that source's
article-patterns (best-practices / leading-practices / how-to / guide),
tags each discovery with the source's credibility tier, deduplicates
against the curated catalog in zscaler_best_practices.py, and returns
the new ones.

How discovery works (in order)
------------------------------
1. Sitemaps first. Sources that declare ``sitemaps`` are read from their
   XML sitemap (and sitemap index). That lists every published article
   in one or two requests, does not depend on how the site's navigation
   is rendered, and is what the site itself publishes for crawlers.
2. Page walk as the fallback. Sources without a sitemap, or whose
   sitemap could not be read, are BFS-walked from their seed pages the
   way they always were. (help.zscaler.com's pages render in the
   browser: a plain fetch gets an empty shell with no links, so for it
   the walk finds nothing and the sitemap is what discovers articles.)
3. Titles. Sitemaps carry no titles, so the page of every new article is
   fetched (bounded) and its <title>/<h1> used (for help.zscaler.com,
   the article's title from the help center's fetch-data answer); the
   URL slug is the last resort.

A crawl that reached nothing is never cached: the previous good result
is kept and the failure is recorded separately, so the next "Update
library" click tries again instead of replaying a 24-hour-old error.

Secure-by-design
----------------
- Host allowlist: each crawled URL must match the host of a registered
  source AND must be in zscaler_update_check.ALLOWED_HOSTS. Off-domain
  links are dropped before fetch regardless of depth.
- Per-source walk: the crawler never jumps sources mid-walk, so the
  credibility attribution stays honest.
- Extension blocklist: .pdf, .zip, images, media, archives, and
  script/style assets are never fetched (sitemap XML is fetched only
  from the URLs the registry declares).
- Reuses the hardened HTTP path from zscaler_update_check._safe_get
  (timeouts, proxy / TLS-inspection env vars, strict host check).
- stdlib html.parser and regex only: no JS execution, no external code.
- Polite throttle (CRAWL_POLITE_DELAY) between requests to one source.
- Hard caps on sitemaps, pages, depth, links per page and title fetches
  so a runaway crawl is impossible.
- Cached to disk at the OS-native cache path (default TTL 24h).
"""
from __future__ import annotations

import html as htmllib
import json
import os
import re
import time
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
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
MAX_SITEMAPS_PER_SOURCE = 40   # sitemap files (index children included) per source
MAX_SITEMAP_BYTES = 8_000_000  # a sitemap larger than this is truncated, not rejected
MAX_TITLE_FETCHES = 60      # new-article pages fetched for their <title> per crawl
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

Progress = Optional[Callable[[Dict[str, Any]], None]]


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
            data = json.load(f)
            return data if isinstance(data, dict) else {}
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


_TITLE_SUFFIX = re.compile(r"\s*[|\-–—:]\s*(Zscaler(\s+Help)?|Zscaler Blog|Zscaler Community|Microsoft Learn|AWS Prescriptive Guidance|Okta|Splunk Lantern|CrowdStrike)\s*$", re.I)


def _clean_title(text: str) -> str:
    t = " ".join(htmllib.unescape(text or "").split()).strip()
    t = re.sub(r"\s*[›»→]\s*$", "", t)
    t = _TITLE_SUFFIX.sub("", t).strip()
    return t


class _LinkExtractor(HTMLParser):
    """Collects (href, link_text) pairs plus the page <title> and first
    <h1>. Ignores scripts/styles, treats any href value as-is (it's
    validated later by _is_allowed)."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out: List[Tuple[str, str]] = []
        self.title = ""
        self.h1 = ""
        self._inside_a = False
        self._href: Optional[str] = None
        self._text_buf: List[str] = []
        self._skip_depth = 0
        self._in_title = False
        self._in_h1 = False
        self._h1_buf: List[str] = []

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style", "noscript"):
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "title" and not self.title:
            self._in_title = True
        elif tag == "h1" and not self.h1:
            self._in_h1 = True
            self._h1_buf = []
        elif tag == "a":
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
        if tag == "title":
            self._in_title = False
        elif tag == "h1" and self._in_h1:
            self._in_h1 = False
            self.h1 = " ".join("".join(self._h1_buf).split()).strip()
        elif tag == "a" and self._inside_a:
            text = " ".join("".join(self._text_buf).split()).strip()
            self.out.append((self._href or "", text))
            self._inside_a = False
            self._href = None
            self._text_buf = []

    def handle_data(self, data):
        if self._skip_depth:
            return
        if self._in_title:
            self.title += data
        if self._in_h1:
            self._h1_buf.append(data)
        if self._inside_a:
            self._text_buf.append(data)


def _parse_page(html: str) -> _LinkExtractor:
    p = _LinkExtractor()
    try:
        p.feed(html[:2_000_000])   # hard cap in case a page is pathologically large
    except Exception:
        pass
    return p


def _extract_links(html: str, base_url: str) -> List[Tuple[str, str]]:
    """Return (absolute_url, link_text) pairs. Resolves relative hrefs
    against base_url so '/zia/xyz' becomes 'https://help.zscaler.com/zia/xyz'."""
    p = _parse_page(html)
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


def page_title(html: str) -> str:
    """The page's <title> (site suffix stripped), else its first <h1>."""
    p = _parse_page(html)
    return _clean_title(p.title) or _clean_title(p.h1)


# ── Sitemaps ──────────────────────────────────────────────────────────

_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
_SITEMAP_CHILD_RE = re.compile(r"<sitemap>.*?<loc>\s*([^<\s]+)\s*</loc>.*?</sitemap>", re.I | re.S)


def parse_sitemap(xml_text: str) -> Tuple[List[str], List[str]]:
    """Return (child_sitemaps, page_urls) from a sitemap or sitemap index."""
    text = xml_text[:MAX_SITEMAP_BYTES]
    children = [htmllib.unescape(u) for u in _SITEMAP_CHILD_RE.findall(text)]
    child_set = set(children)
    pages = [htmllib.unescape(u) for u in _LOC_RE.findall(text) if htmllib.unescape(u) not in child_set]
    return children, pages


def _entry(url: str, title: str, source: Dict[str, Any], found_in: str, via: str) -> Dict[str, Any]:
    return {
        "url": url,
        "title": _clean_title(title) or _titleize_from_slug(url),
        "service": _service_from_url(url),
        "source_page": found_in,
        "source_id": source["id"],
        "source_name": source.get("name", source["id"]),
        "credibility": int(source.get("credibility", 0)),
        "tier": source.get("tier", "unverified"),
        "via": via,
    }


def _crawl_sitemaps(source: Dict[str, Any], safe_get, skip_tls_verify: bool,
                    progress: Progress) -> Dict[str, Any]:
    """Read the source's sitemaps (following a sitemap index) and collect
    every article URL that matches the source's patterns."""
    source_host = source.get("host", "")
    patterns = [p.lower() for p in (source.get("article_patterns") or [])]
    child_filter = [c.lower() for c in (source.get("sitemap_child_filter") or [])]
    queue: List[str] = list(source.get("sitemaps") or [])
    seen: Set[str] = set(queue)
    matched: Dict[str, Dict[str, Any]] = {}
    errors: List[Dict[str, Any]] = []
    fetched = failed = urls_seen = 0
    while queue and fetched + failed < MAX_SITEMAPS_PER_SOURCE:
        url = queue.pop(0)
        if not _is_allowed_for_source(url, source_host):
            continue
        if fetched + failed > 0 and CRAWL_POLITE_DELAY > 0:
            time.sleep(CRAWL_POLITE_DELAY)
        body, code, err = safe_get(url, verify_tls=False if skip_tls_verify else None)
        if err or code != 200 or not body:
            failed += 1
            errors.append({"url": url, "error": err or f"HTTP {code}"})
            continue
        fetched += 1
        try:
            text = body.decode("utf-8", errors="ignore")
        except Exception:
            continue
        children, pages = parse_sitemap(text)
        for child in children:
            if child in seen or not _is_allowed_for_source(child, source_host):
                continue
            if child_filter and not any(f in child.lower() for f in child_filter):
                continue
            seen.add(child)
            queue.append(child)
        for page in pages:
            urls_seen += 1
            page = page.split("#", 1)[0]
            if not _is_allowed_for_source(page, source_host) or _has_skip_extension(page):
                continue
            if _matches_article_patterns(page, patterns) and page not in matched:
                matched[page] = _entry(page, "", source, url, "sitemap")
        if progress:
            progress({"phase": "sitemap", "source": source.get("name", source["id"]), "pages": fetched,
                      "found": len(matched), "detail": f"{urls_seen} URLs listed"})
    return {"sitemaps_fetched": fetched, "sitemaps_failed": failed, "urls_listed": urls_seen,
            "matched": matched, "errors": errors}


# ── Page walk ─────────────────────────────────────────────────────────

def _crawl_source(source: Dict[str, Any], safe_get, skip_tls_verify: bool,
                  global_page_budget: int, progress: Progress = None) -> Dict[str, Any]:
    """Discover one source: sitemaps first, then a BFS page walk when the
    source has no sitemap or none could be read. Returns a per-source
    sub-report. `global_page_budget` caps pages fetched from THIS source
    to keep the overall crawl bounded."""
    source_host = source.get("host", "")
    seeds = source.get("seeds") or []
    patterns = [p.lower() for p in (source.get("article_patterns") or [])]
    per_source_cap = min(MAX_PAGES_PER_SOURCE, max(1, global_page_budget))

    sm = _crawl_sitemaps(source, safe_get, skip_tls_verify, progress) if source.get("sitemaps") else \
        {"sitemaps_fetched": 0, "sitemaps_failed": 0, "urls_listed": 0, "matched": {}, "errors": []}
    matched: Dict[str, Dict[str, Any]] = dict(sm["matched"])
    errors: List[Dict[str, Any]] = list(sm["errors"])
    per_page: List[Dict[str, Any]] = []
    pages_fetched = pages_failed = 0
    seen: Set[str] = set()
    method = "sitemap" if sm["sitemaps_fetched"] else "pages"

    if method == "pages":
        to_fetch: List[Tuple[str, int]] = []
        for u in seeds:
            if u not in seen:
                to_fetch.append((u, 0))
                seen.add(u)
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
                # Every seed failed: stop early instead of burning the budget.
                if pages_fetched == 0 and pages_failed >= len(seeds):
                    break
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
                        matched[abs_url] = _entry(abs_url, text, source, url, "page")
                    elif text and matched[abs_url].get("via") == "sitemap" and not matched[abs_url].get("titled"):
                        matched[abs_url]["title"] = _clean_title(text) or matched[abs_url]["title"]
                        matched[abs_url]["titled"] = True
                if depth + 1 <= MAX_DEPTH and abs_url not in seen:
                    seen.add(abs_url)
                    to_fetch.append((abs_url, depth + 1))
            if len(per_page) < 10:
                per_page.append({"url": url, "depth": depth, "bytes": len(body), "total_links": len(all_links),
                                 "allowed_links": allowed_links, "bp_links": bp_links_this_page})
            if progress:
                progress({"phase": "pages", "source": source.get("name", source["id"]), "pages": pages_fetched,
                          "found": len(matched), "detail": f"depth {depth}"})

    reached = bool(sm["sitemaps_fetched"] or pages_fetched)
    return {
        "source_id": source["id"],
        "source_name": source.get("name", source["id"]),
        "host": source_host,
        "tier": source.get("tier", "unverified"),
        "credibility": int(source.get("credibility", 0)),
        "method": method,
        "reached": reached,
        "sitemaps_fetched": sm["sitemaps_fetched"],
        "sitemaps_failed": sm["sitemaps_failed"],
        "urls_listed": sm["urls_listed"],
        "pages_fetched": pages_fetched,
        "pages_failed": pages_failed,
        "pages_seen": len(seen),
        "matched_count": len(matched),
        "matched": list(matched.values()),
        "errors": errors[:10],
        "per_page_sample": per_page,
    }


def _resolve_titles(entries: List[Dict[str, Any]], safe_get, skip_tls_verify: bool,
                    progress: Progress) -> int:
    """Fetch the page of each sitemap-discovered entry (bounded) and use
    its real title. Returns the number of requests made.

    help.zscaler.com pages are an empty browser shell with no title; the
    article (title included) comes from the help center's fetch-data
    answer, so that is read instead. An article that answers 404/403
    keeps its slug title. Only an unusable answer falls back to the page."""
    import zscaler_update_check as zu
    verify = False if skip_tls_verify else None
    fetched = 0

    def get(url: str):
        nonlocal fetched
        if fetched and CRAWL_POLITE_DELAY > 0:
            time.sleep(CRAWL_POLITE_DELAY)
        fetched += 1
        return safe_get(url, verify_tls=verify)

    todo = [e for e in entries if e.get("via") == "sitemap" and not e.get("titled")]
    for e in todo[:MAX_TITLE_FETCHES]:
        t, read = "", False
        api = zu.help_api_url(e["url"])
        if api:
            body, code, err = get(api)
            art = zu.help_article(body) if not err and code == 200 and body else None
            if art:
                read = True
                if art[1].get("article_status") == 200:
                    t = art[1].get("title") or ""
        if not read:
            body, code, err = get(e["url"])
            if not err and code == 200 and body:
                try:
                    t = page_title(body.decode("utf-8", errors="ignore"))
                except Exception:
                    t = ""
        if t:
            e["title"] = _clean_title(t) or e["title"]
            e["titled"] = True
        if progress:
            progress({"phase": "titles", "source": e.get("source_name", ""), "pages": fetched,
                      "found": len(todo), "detail": e["title"][:60]})
    return fetched


# ── Entry point ───────────────────────────────────────────────────────

def crawl(skip_tls_verify: bool = False, force: bool = False,
          source_ids: Optional[List[str]] = None, progress: Progress = None) -> Dict[str, Any]:
    """
    Discover Zscaler best-practice articles beyond the curated list.

    Args:
      skip_tls_verify: pass-through to the HTTP client for corporate
        TLS-MITM environments (same as update-checker).
      force: ignore the cache TTL and re-crawl.
      source_ids: optional filter — only crawl these source ids. When
        omitted, every crawlable source in bp_sources is visited.
      progress: optional callback receiving {"phase","source","pages",
        "found","detail","sources_done","sources_total"} as work proceeds.

    Returns:
      {
        "started_at": ISO ts, "elapsed_seconds": float,
        "pages_fetched": N, "pages_failed": N, "sitemaps_fetched": N,
        "sources_reached": N, "sources_crawled": N,
        "total_matched": N,
        "discovered": [{"url","title","service","source_page","source_id","source_name","credibility","tier","via"}, ...],
        "new_entries": [...],          # subset not in curated catalog
        "per_source": [ {...}, ... ],  # per-source rollup
        "errors": [{"url","error"}, ...],
        "error": str | None,           # set when no source could be reached
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
        return {"error": f"_safe_get unavailable: {e}", "discovered": [], "new_entries": []}

    try:
        from bp_sources import crawlable_sources
    except Exception as e:
        return {"error": f"bp_sources unavailable: {e}", "discovered": [], "new_entries": []}

    try:
        from zscaler_best_practices import BEST_PRACTICES, _load_discovered
        curated_urls = {entry["url"] for entry in BEST_PRACTICES}
        known_titles = {e.get("url"): e.get("title") for e in _load_discovered() if e.get("url")}
        known_urls = curated_urls | set(known_titles)
    except Exception:
        curated_urls = set()
        known_titles = {}
        known_urls = set()

    sources = crawlable_sources()
    if source_ids:
        want = set(source_ids)
        sources = [s for s in sources if s["id"] in want]

    all_matched: Dict[str, Dict[str, Any]] = {}
    per_source_reports: List[Dict[str, Any]] = []
    totals = {"pages_fetched": 0, "pages_failed": 0, "pages_seen": 0, "sitemaps_fetched": 0, "sitemaps_failed": 0}
    all_errors: List[Dict[str, Any]] = []
    per_page_sample: List[Dict[str, Any]] = []

    def _prog(d: Dict[str, Any]) -> None:
        if progress:
            d = dict(d)
            d["sources_done"] = len(per_source_reports)
            d["sources_total"] = len(sources)
            d["total_found"] = len(all_matched) + d.get("found", 0)
            try:
                progress(d)
            except Exception:
                pass

    for src in sources:
        remaining = MAX_PAGES_TOTAL - totals["pages_fetched"]
        if remaining <= 0:
            break
        _prog({"phase": "start", "source": src.get("name", src["id"]), "pages": 0, "found": 0, "detail": ""})
        report = _crawl_source(src, _safe_get, skip_tls_verify, remaining, _prog)
        per_source_reports.append({k: v for k, v in report.items() if k != "matched"})
        for k in totals:
            totals[k] += report.get(k, 0)
        all_errors.extend(report.get("errors") or [])
        per_page_sample.extend(report.get("per_page_sample") or [])
        # Dedup discoveries by URL across sources; highest-credibility
        # source wins if the same URL appears twice.
        for e in report.get("matched") or []:
            prev = all_matched.get(e["url"])
            if not prev or e.get("credibility", 0) > prev.get("credibility", 0):
                all_matched[e["url"]] = e

    # Real titles: articles already in the library keep the title stored
    # there; the ones we have not seen before are fetched for theirs.
    for e in all_matched.values():
        if known_titles.get(e["url"]):
            e["title"] = known_titles[e["url"]]
            e["titled"] = True
    fresh = [e for e in all_matched.values() if e["url"] not in known_urls]
    totals["pages_fetched"] += _resolve_titles(fresh, _safe_get, skip_tls_verify, _prog)
    for e in all_matched.values():
        e.pop("titled", None)

    discovered = sorted(
        all_matched.values(),
        key=lambda e: (-int(e.get("credibility", 0)), e.get("service", ""), e["title"].lower()),
    )
    new_since_curated = [e for e in discovered if e["url"] not in curated_urls]
    reached = [r for r in per_source_reports if r.get("reached")]

    result = {
        "started_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.time() - started, 2),
        "pages_fetched": totals["pages_fetched"],
        "pages_failed": totals["pages_failed"],
        "pages_seen": totals["pages_seen"],
        "sitemaps_fetched": totals["sitemaps_fetched"],
        "sitemaps_failed": totals["sitemaps_failed"],
        "max_depth": MAX_DEPTH,
        "sources_crawled": len(per_source_reports),
        "sources_reached": len(reached),
        "per_source": per_source_reports,
        "total_matched": len(discovered),
        "discovered": discovered,
        "curated_count": len(curated_urls),
        "new_since_curated": len(new_since_curated),
        "new_entries": new_since_curated,
        "new_since_last_crawl": len(fresh),
        "errors": all_errors[:30],
        "error": None,
        "per_page_sample": per_page_sample[:25],
        "from_cache": False,
        "cache_age_seconds": None,
        "timestamp": time.time(),
        "cache_file": _cache_path(),
    }
    if sources and not reached:
        # Nothing could be read: keep the last good result, record the
        # failure next to it so the library can show what went wrong.
        first = (all_errors[0].get("error") if all_errors else "") or "no page could be fetched"
        result["error"] = f"No source could be reached ({len(sources)} tried). {first}"
        previous = _load_cache()
        previous["last_attempt"] = {"timestamp": result["timestamp"], "error": result["error"],
                                    "errors": all_errors[:10], "sources_tried": len(sources)}
        _save_cache(previous)
        return result
    result["last_attempt"] = {"timestamp": result["timestamp"], "error": None,
                              "sources_reached": len(reached), "sources_tried": len(sources),
                              "new_since_curated": len(new_since_curated), "new_since_last_crawl": len(fresh)}
    _save_cache(result)
    return result


def last_summary() -> Dict[str, Any]:
    """What the library page shows about the most recent crawl, without
    crawling: when it last succeeded, how many sources answered, what
    the last attempt's error was (if any)."""
    cache = _load_cache()
    attempt = cache.get("last_attempt") or {}
    return {
        "last_success_at": cache.get("timestamp"),
        "last_success_sources": cache.get("sources_reached"),
        "last_success_total_matched": cache.get("total_matched"),
        "last_success_new": cache.get("new_since_curated"),
        "last_attempt_at": attempt.get("timestamp"),
        "last_attempt_error": attempt.get("error"),
        "last_attempt_errors": attempt.get("errors") or [],
        "per_source": [{k: r.get(k) for k in ("source_id", "source_name", "tier", "method", "reached",
                                               "sitemaps_fetched", "pages_fetched", "pages_failed", "matched_count")}
                       for r in (cache.get("per_source") or [])],
    }


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
    out = crawl(skip_tls_verify=args.skip_tls, force=args.force, source_ids=args.source,
                progress=lambda d: print(f"  … {d.get('phase'):<8} {d.get('source', ''):<32} {d.get('pages', 0):>4} fetched, {d.get('found', 0):>4} found  {d.get('detail', '')}"))
    if out.get("error"):
        print("ERROR:", out["error"])
    print(f"pages: {out.get('pages_fetched')} fetched, {out.get('pages_failed')} failed, "
          f"{out.get('sitemaps_fetched', 0)} sitemaps, {out.get('sources_reached', 0)}/{out.get('sources_crawled', 0)} source(s) reached, "
          f"{out.get('elapsed_seconds')}s elapsed")
    print(f"total matched: {out.get('total_matched')}  "
          f"(curated: {out.get('curated_count')}, new: {out.get('new_since_curated')})")
    for r in out.get('per_source') or []:
        print(f"  {r['source_id']:<22} [{r['tier']:<13}] {r.get('method', '?'):<8} {r.get('sitemaps_fetched', 0):>2} sitemaps, "
              f"{r['pages_fetched']:>3} pages, {r['pages_failed']:>2} failed, {r.get('matched_count', 0):>3} matched")
    for e in (out.get('new_entries') or [])[:20]:
        print(f"  NEW  [{e['service']}] ({e.get('tier', '?')}) {e['title']}")
        print(f"       {e['url']}")
