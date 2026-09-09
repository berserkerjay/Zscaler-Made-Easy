"""Best Practices library updates: sitemap-first discovery, page-walk
fallback, titles, never caching a failed crawl, and the update endpoints."""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

import bp_crawler as bc
import bp_sources
import zscaler_best_practices as zbp
import zscaler_update_check as zuc

HELP = {
    "id": "help_zscaler", "name": "Zscaler Help Portal", "host": "help.zscaler.com", "tier": "official",
    "credibility": 100, "crawlable": True,
    "seeds": ["https://help.zscaler.com/zia"],
    "sitemaps": ["https://help.zscaler.com/sitemap.xml"],
    "article_patterns": ["best-practice", "leading-practice"],
}
BLOG = {
    "id": "zscaler_blogs", "name": "Zscaler Blogs", "host": "www.zscaler.com", "tier": "official",
    "credibility": 100, "crawlable": True,
    "seeds": ["https://www.zscaler.com/blogs"],
    "sitemaps": ["https://www.zscaler.com/sitemap.xml"], "sitemap_child_filter": ["blog"],
    "article_patterns": ["best-practice"],
}

SITEMAP_INDEX = """<?xml version="1.0"?><sitemapindex><sitemap><loc>https://help.zscaler.com/sitemap.xml?page=1</loc></sitemap>
<sitemap><loc>https://help.zscaler.com/sitemap.xml?page=2</loc></sitemap></sitemapindex>"""
SITEMAP_1 = """<urlset><url><loc>https://help.zscaler.com/zia/best-practices-testing-and-rolling-out-ssltls-inspection</loc></url>
<url><loc>https://help.zscaler.com/zia/best-practices-brand-new-guide</loc></url>
<url><loc>https://help.zscaler.com/zia/about-dlp</loc></url>
<url><loc>https://help.zscaler.com/zia/best-practices-slides.pdf</loc></url>
<url><loc>https://www.example.com/zia/best-practices-elsewhere</loc></url></urlset>"""
SITEMAP_2 = """<urlset><url><loc>https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new</loc></url></urlset>"""
BLOG_INDEX = """<sitemapindex><sitemap><loc>https://www.zscaler.com/sitemap-blogs.xml</loc></sitemap>
<sitemap><loc>https://www.zscaler.com/sitemap-products.xml</loc></sitemap></sitemapindex>"""
BLOG_SITEMAP = """<urlset><url><loc>https://www.zscaler.com/blogs/product-insights/best-practices-for-ssl-everywhere</loc></url></urlset>"""
PAGE_NEW = "<html><head><title>Best Practices: Brand New Guide | Zscaler</title></head><body><h1>x</h1></body></html>"
PAGE_ZPA = "<html><head><title></title></head><body><h1>ZPA Leading Practices Guide (new)</h1></body></html>"
HUB = """<html><body><a href="/zia/best-practices-from-hub">Hub linked guide ›</a><a href="/zia/other">Other</a>
<a href="https://www.zscaler.com/blogs/x-best-practice">off host</a><a href="/zia/deep">Deep</a></body></html>"""
DEEP = '<html><body><a href="/zia/best-practices-deep-guide">Deep guide</a></body></html>'


class Fake:
    """Stand-in for zscaler_update_check._safe_get: url -> body or error."""
    def __init__(self, pages, fail=None):
        self.pages = pages
        self.fail = fail or {}
        self.calls = []

    def __call__(self, url, verify_tls=None):
        self.calls.append(url)
        if url in self.fail:
            return None, 0, self.fail[url]
        if url in self.pages:
            return self.pages[url].encode(), 200, ""
        return None, 404, ""


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    monkeypatch.setattr(bc, "CRAWL_POLITE_DELAY", 0)
    monkeypatch.setattr(bp_sources, "crawlable_sources", lambda: [HELP, BLOG])
    return tmp_path


def _wire(monkeypatch, fake):
    monkeypatch.setattr(zuc, "_safe_get", fake)


def test_sitemaps_are_read_first_and_titles_fetched(env, monkeypatch):
    fake = Fake({
        "https://help.zscaler.com/sitemap.xml": SITEMAP_INDEX,
        "https://help.zscaler.com/sitemap.xml?page=1": SITEMAP_1,
        "https://help.zscaler.com/sitemap.xml?page=2": SITEMAP_2,
        "https://help.zscaler.com/zia/best-practices-brand-new-guide": PAGE_NEW,
        "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new": PAGE_ZPA,
        "https://www.zscaler.com/sitemap.xml": BLOG_INDEX,
        "https://www.zscaler.com/sitemap-blogs.xml": BLOG_SITEMAP,
        "https://www.zscaler.com/blogs/product-insights/best-practices-for-ssl-everywhere": "<html><title>SSL everywhere - Zscaler Blog</title></html>",
    })
    _wire(monkeypatch, fake)
    progress = []
    out = bc.crawl(force=True, progress=progress.append)
    assert out["error"] is None and out["sources_reached"] == 2 and out["sitemaps_fetched"] == 5
    urls = {e["url"]: e for e in out["discovered"]}
    # Matched by pattern, on the source host, no attachments, no other hosts.
    assert "https://help.zscaler.com/zia/best-practices-brand-new-guide" in urls
    assert "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new" in urls
    assert "https://help.zscaler.com/zia/best-practices-testing-and-rolling-out-ssltls-inspection" in urls
    assert not any(u.endswith(".pdf") or "example.com" in u or "/about-dlp" in u for u in urls)
    # The products sitemap child was filtered out; the blog child was read.
    assert "https://www.zscaler.com/sitemap-products.xml" not in fake.calls
    assert "https://www.zscaler.com/blogs/product-insights/best-practices-for-ssl-everywhere" in urls
    # Titles: <title> with the site suffix stripped, <h1> fallback, slug as last resort.
    assert urls["https://help.zscaler.com/zia/best-practices-brand-new-guide"]["title"] == "Best Practices: Brand New Guide"
    assert urls["https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new"]["title"] == "ZPA Leading Practices Guide (new)"
    assert urls["https://www.zscaler.com/blogs/product-insights/best-practices-for-ssl-everywhere"]["title"] == "SSL everywhere"
    # The curated article is not fetched for a title (already known) and is not "new".
    assert "https://help.zscaler.com/zia/best-practices-testing-and-rolling-out-ssltls-inspection" not in fake.calls
    new = {e["url"] for e in out["new_entries"]}
    assert "https://help.zscaler.com/zia/best-practices-testing-and-rolling-out-ssltls-inspection" not in new
    assert len(new) == 3 and out["new_since_curated"] == 3
    per = {r["source_id"]: r for r in out["per_source"]}
    assert per["help_zscaler"]["method"] == "sitemap" and per["help_zscaler"]["reached"] and per["help_zscaler"]["matched_count"] == 3
    assert per["help_zscaler"]["pages_fetched"] == 0  # no page walk when the sitemap worked
    assert any(p["phase"] == "sitemap" for p in progress) and any(p["phase"] == "titles" for p in progress)
    assert all("sources_total" in p for p in progress)
    # Cached for the background refresh.
    again = bc.crawl(force=False)
    assert again["from_cache"] is True and again["total_matched"] == out["total_matched"]
    s = bc.last_summary()
    assert s["last_success_sources"] == 2 and s["last_attempt_error"] is None and len(s["per_source"]) == 2


def test_page_walk_when_no_sitemap_can_be_read(env, monkeypatch):
    fake = Fake({
        "https://help.zscaler.com/zia": HUB,
        "https://help.zscaler.com/zia/deep": DEEP,
        "https://help.zscaler.com/zia/other": "<html></html>",
    }, fail={"https://help.zscaler.com/sitemap.xml": "HTTP 404", "https://www.zscaler.com/sitemap.xml": "connection error: refused",
             "https://www.zscaler.com/blogs": "connection error: refused"})
    _wire(monkeypatch, fake)
    out = bc.crawl(force=True)
    per = {r["source_id"]: r for r in out["per_source"]}
    assert per["help_zscaler"]["method"] == "pages" and per["help_zscaler"]["reached"] and per["help_zscaler"]["sitemaps_failed"] == 1
    urls = {e["url"]: e for e in out["discovered"]}
    assert urls["https://help.zscaler.com/zia/best-practices-from-hub"]["title"] == "Hub linked guide"
    assert "https://help.zscaler.com/zia/best-practices-deep-guide" in urls
    assert "https://www.zscaler.com/blogs/x-best-practice" not in urls   # off-host link dropped
    assert not per["zscaler_blogs"]["reached"] and out["sources_reached"] == 1 and out["error"] is None
    # Titles for page-walk finds come from the link text; no extra fetch of them.
    assert fake.calls.count("https://help.zscaler.com/zia/best-practices-from-hub") == 1  # crawled as a page, not re-fetched for its title twice


def test_failed_crawl_is_not_cached_and_is_reported(env, monkeypatch):
    good = Fake({"https://help.zscaler.com/sitemap.xml": SITEMAP_2,
                 "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new": PAGE_ZPA})
    monkeypatch.setattr(bp_sources, "crawlable_sources", lambda: [HELP])
    _wire(monkeypatch, good)
    first = bc.crawl(force=True)
    assert first["error"] is None and first["total_matched"] == 1
    bad = Fake({}, fail={"https://help.zscaler.com/sitemap.xml": "Proxy rejected the request: 403 Forbidden",
                         "https://help.zscaler.com/zia": "Proxy rejected the request: 403 Forbidden"})
    _wire(monkeypatch, bad)
    out = bc.crawl(force=True)
    assert out["error"].startswith("No source could be reached (1 tried)") and "403" in out["error"]
    assert out["sources_reached"] == 0 and out["total_matched"] == 0
    # The last good result is still what the cache returns...
    cached = bc.crawl(force=False)
    assert cached["from_cache"] and cached["total_matched"] == 1 and cached["error"] is None
    # ...and the failure is visible next to it.
    s = bc.last_summary()
    assert s["last_attempt_error"] == out["error"] and s["last_success_total_matched"] == 1
    assert s["last_attempt_at"] > s["last_success_at"]
    # A later success clears the recorded failure.
    _wire(monkeypatch, good)
    bc.crawl(force=True)
    assert bc.last_summary()["last_attempt_error"] is None


def test_discoveries_persist_and_are_not_refetched(env, monkeypatch):
    monkeypatch.setattr(bp_sources, "crawlable_sources", lambda: [HELP])
    fake = Fake({"https://help.zscaler.com/sitemap.xml": SITEMAP_2,
                 "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new": PAGE_ZPA})
    _wire(monkeypatch, fake)
    out = bc.crawl(force=True)
    assert zbp.save_discovered(out["new_entries"]) == 1
    entries = zbp.list_all()
    mine = [e for e in entries if e["url"].endswith("zpa-leading-practices-guide-new")]
    assert mine and mine[0]["discovered"] and mine[0]["title"] == "ZPA Leading Practices Guide (new)" and mine[0]["tier"] == "official"
    assert zbp.save_discovered(out["new_entries"]) == 0   # idempotent
    # Next crawl: the article is known, so its page is not fetched again for a title.
    fake.calls.clear()
    out2 = bc.crawl(force=True)
    assert out2["new_since_last_crawl"] == 0 and out2["new_since_curated"] == 1
    assert "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new" not in fake.calls
    # ...and keeps the title stored in the library instead of the URL slug.
    assert out2["new_entries"][0]["title"] == "ZPA Leading Practices Guide (new)"
    assert zbp.reset_discovered() and not any(e.get("discovered") for e in zbp.list_all())


def test_parse_helpers():
    children, pages = bc.parse_sitemap(SITEMAP_INDEX)
    assert children == ["https://help.zscaler.com/sitemap.xml?page=1", "https://help.zscaler.com/sitemap.xml?page=2"] and pages == []
    children, pages = bc.parse_sitemap(SITEMAP_1)
    assert children == [] and len(pages) == 5
    assert bc.page_title("<html><head><title>  Best Practices for DNS Control &amp; Rules | Zscaler  </title></head></html>") == "Best Practices for DNS Control & Rules"
    assert bc.page_title("<html><body><h1>Only a heading</h1></body></html>") == "Only a heading"
    assert bc.page_title("<html><body>nothing</body></html>") == ""


def test_update_endpoints(env, monkeypatch):
    import dlp_api_server as srv
    monkeypatch.setattr(bp_sources, "crawlable_sources", lambda: [HELP])
    fake = Fake({"https://help.zscaler.com/sitemap.xml": SITEMAP_2,
                 "https://help.zscaler.com/zscaler-deployments-operations/zpa-leading-practices-guide-new": PAGE_ZPA})
    _wire(monkeypatch, fake)
    c = TestClient(srv.app)
    r = c.post("/api/best-practices/crawl", json={"force": True})
    assert r.status_code == 200
    d = r.json()
    assert d["added_to_library"] == 1 and d["error"] is None and d["sources_reached"] == 1 and d["per_source"][0]["method"] == "sitemap"
    assert [e["title"] for e in d["added_entries"]] == ["ZPA Leading Practices Guide (new)"]
    # Second run: nothing new is added, and the result says so without listing old finds.
    d1 = c.post("/api/best-practices/crawl", json={"force": True}).json()
    assert d1["added_to_library"] == 0 and d1["added_entries"] == [] and d1["new_since_curated"] == 1
    st = c.get("/api/best-practices/crawl/status").json()
    assert st["running"] is False and st["phase"] in ("sitemap", "titles", "start")
    lib = c.get("/api/best-practices").json()
    assert lib["discovered_count"] == 1 and lib["last_crawl"]["last_success_sources"] == 1 and lib["crawl_running"] is False
    assert lib["last_refresh_status"] == "ok"
    assert any(e.get("discovered") for e in lib["entries"])
    # A failed update is reported, not hidden, and the library keeps its entries.
    _wire(monkeypatch, Fake({}, fail={"https://help.zscaler.com/sitemap.xml": "TLS error (corporate TLS inspection?)", "https://help.zscaler.com/zia": "TLS error"}))
    d2 = c.post("/api/best-practices/crawl", json={"force": True}).json()
    assert d2["error"] and d2["added_to_library"] == 0 and d2["errors"][0]["error"].startswith("TLS error")
    lib2 = c.get("/api/best-practices").json()
    assert lib2["last_refresh_status"] == "error" and lib2["last_crawl"]["last_attempt_error"] == d2["error"] and lib2["discovered_count"] == 1
    html = c.get("/").text
    assert "Update library now" in html and "Force refresh" not in html and "/api/best-practices/crawl/status" in html
    zbp.reset_discovered()
