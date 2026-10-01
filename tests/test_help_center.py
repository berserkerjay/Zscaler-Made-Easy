"""help.zscaler.com renders in the browser: every URL answers the same
empty shell and the article comes from /zapi/fetch-data. The update check,
Beacon and the best-practice crawler read that answer instead of the
shell. Every answer here is a fake; nothing leaves this machine."""
from __future__ import annotations

import json
from urllib.parse import parse_qs, urlparse

import pytest

import beacon
import bp_crawler as bc
import zscaler_update_check as zu
from test_beacon import fake_upstream, upstream_report

SHELL = (b'<!doctype html><html lang="en"><head><meta charset="utf-8" /><script type="module" src="/assets/js/index.js"></script>'
         b'</head><body><noscript>If you\'re seeing this message, that means JavaScript has been disabled on your browser, '
         b'please enable JS to make this app work.</noscript><div id="app"></div></body></html>')
BODY = "<p>" + "Real guidance from the help center. " * 30 + "</p>"
HTML_SOURCES = [s for s in zu.SOURCES if s["type"] == "html_hash"]


def article(title="About DLP Engines", content=BODY, status=200):
    if status == 200:
        return json.dumps({"data": {"info": {"status": 200, "url": "/x"}, "body": {"title": title, "content": content}}}).encode()
    if status == 404:
        return json.dumps({"data": {"info": {"status": 404, "url": "/x", "metatags": {"title": "Page not found | Zscaler"}},
                                    "body": {"title": "Page Not Found", "message": "The article you're trying to view is not available. Visit <a href='https://help.zscaler.com'>help.zscaler.com</a>."}}}).encode()
    return json.dumps({"data": {"info": {"status": 403, "url": "/oneapi"},
                                "body": {"title": "Help Article in Maintenance",
                                         "message": "This help article is currently undergoing maintenance and cannot be accessed at this time. It will be back."}}}).encode()


def alias(url):
    """The url_alias of a fetch-data URL, or None for any other URL."""
    u = urlparse(url)
    return parse_qs(u.query).get("url_alias", [None])[0] if u.path == "/zapi/fetch-data" else None


def site(articles):
    """A _safe_get stand-in for the help center: fetch-data answers from
    {path: bytes}, every page the shell. Records each URL asked for."""
    calls = []

    def get(url, verify_tls=None):
        calls.append(url)
        a = alias(url)
        if a is not None:
            return (articles[a], 200, "") if a in articles else (article(status=404), 200, "")
        return SHELL, 200, ""
    get.calls = calls
    return get


# ── help_api_url / help_article ───────────────────────────────────────

def test_help_api_url_is_only_for_the_help_center():
    u = zu.help_api_url("https://help.zscaler.com/zia/about-dlp-engines/")
    assert u.startswith("https://help.zscaler.com/zapi/fetch-data?url_alias=/zia/about-dlp-engines&view_type=full&")
    assert u.endswith("&language=en&_format=json") and alias(u) == "/zia/about-dlp-engines"
    assert alias(zu.help_api_url("https://HELP.zscaler.com/oneapi")) == "/oneapi"
    assert zu.help_api_url("https://www.zscaler.com/blogs/x") is None and zu.help_api_url("https://pypi.org/pypi/x/json") is None
    assert urlparse(zu.help_api_url("https://help.zscaler.com/zia/a b?x=1")).hostname == "help.zscaler.com"
    assert "a%20b" in zu.help_api_url("https://help.zscaler.com/zia/a b") and "x=1" not in zu.help_api_url("https://help.zscaler.com/zia/a?x=1")


def test_help_article_reads_200_404_403_and_refuses_junk():
    content, q = zu.help_article(article())
    assert q["ok"] and q["title"] == "About DLP Engines" and q["basis"] == "article" and q["article_status"] == 200
    assert content.startswith(b"About DLP Engines\n") and b"Real guidance" in content
    # The same article read twice hashes the same; a changed body does not.
    assert zu._hash(zu.help_article(article())[0]) == zu._hash(content)
    assert zu._hash(zu.help_article(article(content=BODY + "<p>New.</p>"))[0]) != zu._hash(content)
    # Too short to be an article.
    assert not zu.help_article(article(content="<p>stub</p>"))[1]["ok"]
    content, q = zu.help_article(article(status=404))
    assert content == b"" and not q["ok"] and q["article_status"] == 404
    assert "no longer exists" in q["reason"] and "Page Not Found" in q["reason"] and q["reason"].startswith("HTTP 404")
    content, q = zu.help_article(article(status=403))
    assert content == b"" and not q["ok"] and q["article_status"] == 403
    assert q["reason"] == ('HTTP 403: the help center says "Help Article in Maintenance" (This help article is currently '
                           'undergoing maintenance and cannot be accessed at this time.)')
    for junk in (None, b"", SHELL, b"[]", b'{"data": []}', b'{"data": {"info": {}}}', b'{"data": {"info": {"status": "x"}}}',
                 b'{"data": {"info": {"status": 200}, "body": "nope"}}', "not bytes either"):
        assert zu.help_article(junk) is None, junk


def test_a_documentation_index_is_read_as_its_list_of_guides():
    """/zscaler-deployments-operations has no content of its own: its
    article answer lists categories and the guides under them, and that
    list is what is checked and hashed (a guide added is a change)."""
    def index(*extra):
        arts = [{"nid": str(i), "title": f"ZIA Guide {i}: Deployment & Operations", "url": f"/zscaler-deployments-operations/guide-{i}"}
                for i in range(12)] + list(extra)
        return json.dumps({"data": {"info": {"status": 200, "url": "/zscaler-deployments-operations"},
                                    "body": {"title": "Zscaler Deployments & Operations", "product_id": "5701",
                                             "categories": [{"tid": "1", "title": "ZIA Deployments & Operations", "articles": arts}, "junk"]}}}).encode()
    content, q = zu.help_article(index())
    assert q["ok"] and q["title"] == "Zscaler Deployments & Operations" and q["article_status"] == 200
    assert b"ZIA Deployments &amp; Operations" in content and b"/zscaler-deployments-operations/guide-11" in content
    added, _ = zu.help_article(index({"nid": "99", "title": "A brand new guide", "url": "/zscaler-deployments-operations/new"}))
    assert zu._hash(added) != zu._hash(content)
    # An article with content of its own ignores any categories it carries.
    own = json.loads(article())
    own["data"]["body"]["categories"] = [{"title": "Other", "articles": []}]
    assert zu.help_article(json.dumps(own).encode())[0] == zu.help_article(article())[0]


# ── read_page ─────────────────────────────────────────────────────────

def test_read_page_uses_the_article_and_falls_back_to_the_page():
    url = "https://help.zscaler.com/zia/about-dlp-engines"
    get = site({"/zia/about-dlp-engines": article()})
    content, q, code, err = zu.read_page(url, get)
    assert (code, err, q["ok"], q["basis"]) == (200, "", True, "article") and b"Real guidance" in content
    assert len(get.calls) == 1, "the shell is not fetched when the article answered"
    # An unusable fetch-data answer: the page itself is read (and here, is the shell).
    get = lambda u, verify_tls=None: (b"<html>oops</html>", 200, "") if alias(u) else (SHELL, 200, "")
    content, q, code, err = zu.read_page(url, get)
    assert q["basis"] == "page" and not q["ok"] and "no readable content" in q["reason"]
    # fetch-data answering an HTTP error and the page 404: no verdict, the status is passed on.
    get = lambda u, verify_tls=None: (None, 500, "") if alias(u) else (b"gone", 404, "")
    assert zu.read_page(url, get) == (b"gone", None, 404, "")
    # Another host never asks the help center.
    asked = []
    content, q, code, err = zu.read_page("https://www.zscaler.com/x", lambda u: asked.append(u) or (b"<html><title>T</title>" + b"word " * 200 + b"</html>", 200, ""))
    assert asked == ["https://www.zscaler.com/x"] and q["ok"] and q["basis"] == "page"


# ── The Zscaler SDK & docs updates tab ────────────────────────────────

SRC = {"key": "dlp_engines_bp", "name": "DLP Engines Best Practices", "type": "html_hash", "url": "https://help.zscaler.com/zia/about-dlp-engines"}


def test_check_html_hashes_the_article(monkeypatch):
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines": article()}))
    r = zu._check_html(SRC, {})
    assert r["status"] == "new" and r["page"]["ok"] and r["page"]["title"] == "About DLP Engines" and r["basis"] == "article"
    assert r["link"] == SRC["url"] and "link_note" not in r
    same = zu._check_html(SRC, {"hash": r["current"], "basis": "article", "url": SRC["url"]})
    assert same["status"] == "unchanged" and same["action_hint"] is None
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines": article(content=BODY + "<p>New.</p>")}))
    changed = zu._check_html(SRC, {"hash": r["current"], "basis": "article", "url": SRC["url"]})
    assert changed["status"] == "changed" and changed["previous"] == r["current"]


def test_check_html_says_moved_or_maintenance(monkeypatch):
    monkeypatch.setattr(zu, "_safe_get", site({}))
    r = zu._check_html(SRC, {})
    assert r["status"] == "dead_link" and r["link"] == "https://help.zscaler.com/zia" and r["link_fallback"]
    assert "no longer exists" in r["link_note"] and "section index" in r["link_note"]
    one = {"key": "oneapi_reference", "name": "OneAPI Reference", "type": "html_hash", "url": "https://help.zscaler.com/oneapi"}
    monkeypatch.setattr(zu, "_safe_get", site({"/oneapi": article(status=403)}))
    r = zu._check_html(one, {})
    # /oneapi is its own section: the link stays on the page, and the note says why it is not readable.
    assert r["status"] == "unreadable" and r["link"] == one["url"] and not r["link_fallback"]
    assert "Maintenance" in r["link_note"] and "section index" not in r["link_note"]
    # fetch-data unusable and the page itself 404s: an error that still links to the section.
    monkeypatch.setattr(zu, "_safe_get", lambda u, verify_tls=None: (b"junk", 200, "") if alias(u) else (b"", 404, ""))
    r = zu._check_html(SRC, {})
    assert r["status"] == "error" and r["link"] == "https://help.zscaler.com/zia" and "no longer exists" in r["link_note"]


def test_the_first_article_read_is_a_new_baseline_not_a_change(monkeypatch, tmp_path):
    cache = tmp_path / "update_cache.json"
    # What the cache held before: a hash of the old full HTML page.
    cache.write_text(json.dumps({"dlp_engines_bp": {"hash": "0123456789abcdef", "last_checked": "2026-09-01T00:00:00+00:00"}}))
    monkeypatch.setattr(zu, "_cache_path", lambda: str(cache))
    monkeypatch.setattr(zu, "SOURCES", [SRC])
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines": article()}))
    r = zu.check_for_updates()["results"][0]
    assert r["status"] == "new" and r["previous"] is None and "new baseline, not a change" in r["action_hint"]
    entry = json.loads(cache.read_text())["dlp_engines_bp"]
    assert entry["hash"] == r["current"] and entry["basis"] == "article" and entry["url"] == SRC["url"]
    again = zu.check_for_updates()["results"][0]
    assert again["status"] == "unchanged" and again["action_hint"] is None
    # A watched page that moves to another address starts over too.
    monkeypatch.setattr(zu, "SOURCES", [{**SRC, "url": "https://help.zscaler.com/zia/about-dlp-engines-v2"}])
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines-v2": article()}))
    moved = zu.check_for_updates()["results"][0]
    assert moved["status"] == "new" and "new baseline" in moved["action_hint"]


# ── Beacon ────────────────────────────────────────────────────────────

@pytest.fixture
def beacon_state(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_BEACON_STATE", str(tmp_path / "beacon_state.json"))


def api_fetch(gone=(), changed_key=None, maintenance=()):
    """Beacon's fetch (url -> (text, err)) for the help center: the
    fetch-data answer per watched source, the shell for every page."""
    by_path = {urlparse(s["url"]).path: s for s in HTML_SOURCES}

    def fetch(url):
        a = alias(url)
        if a is None:
            return SHELL.decode(), ""
        s = by_path.get(a)
        if not s or s["key"] in gone:
            return article(status=404).decode(), ""
        if s["key"] in maintenance:
            return article(status=403).decode(), ""
        return article(title=s["name"], content=BODY + ("<p>A new section.</p>" if s["key"] == changed_key else "")).decode(), ""
    return fetch


def shell_fetch(url):
    return (None, "HTTP 404") if alias(url) else (SHELL.decode(), "")


def test_beacon_reads_each_page_through_the_article():
    pages = beacon.watch_pages(api_fetch(gone={"genai_bp"}, maintenance={"oneapi_reference"}))
    by = {p["key"]: p for p in pages}
    assert len(pages) == len(HTML_SOURCES)
    assert all(by[k]["ok"] and by[k]["hash"] and by[k]["basis"] == "article" and by[k]["article_status"] == 200
               for k in by if k not in ("genai_bp", "oneapi_reference"))
    assert by["dlp_engines_bp"]["title"] == "DLP Engines Best Practices"
    gone, locked = by["genai_bp"], by["oneapi_reference"]
    assert gone["hash"] and not gone["ok"] and gone["article_status"] == 404 and "no longer exists" in gone["reason"]
    assert locked["hash"] and not locked["ok"] and locked["article_status"] == 403 and "Maintenance" in locked["reason"]
    # Read the old way (the shell only), every page has no readable content.
    old = beacon.watch_pages(shell_fetch)
    assert all(p["basis"] == "page" and not p["ok"] and "no readable content" in p["reason"] for p in old)


def test_beacon_diff_rebaselines_once_then_reports_changes_and_gone_pages(beacon_state):
    up = fake_upstream(upstream_report())
    beacon.run(online=True, fetch=shell_fetch, upstream=up)
    s = beacon.run(online=True, fetch=api_fetch(), upstream=up)
    assert not [c for c in s["diff"]["changes"] if c["kind"] in ("doc_changed", "doc_gone")], \
        "the switch from the shell to the article is not a change on every page"
    s = beacon.run(online=True, fetch=api_fetch(), upstream=up)
    assert not [c for c in s["diff"]["changes"] if c["kind"] in ("doc_changed", "doc_gone")]
    s = beacon.run(online=True, fetch=api_fetch(changed_key="dlp_eval_all", gone={"genai_bp"}), upstream=up)
    kinds = {(c["kind"], c.get("key")) for c in s["diff"]["changes"]}
    assert ("doc_changed", "dlp_eval_all") in kinds
    # A page that was readable and now answers 404 is gone, not "changed" (its empty body also hashes differently).
    gone = [c for c in s["diff"]["changes"] if c.get("key") == "genai_bp"]
    assert [c["kind"] for c in gone] == ["doc_gone"] and "no longer exists" in gone[0]["text"]
    assert all(c.get("key") in ("dlp_eval_all", "genai_bp") for c in s["diff"]["changes"] if c["kind"].startswith("doc_"))


def test_the_beacon_tab_names_a_moved_page():
    js = open("static/beacon.js", encoding="utf-8").read()
    assert "'moved or gone'" in js and "'not readable'" in js and "article_status" in js


# ── Best-practice crawler titles ──────────────────────────────────────

def test_crawler_titles_come_from_the_article(monkeypatch):
    monkeypatch.setattr(bc, "CRAWL_POLITE_DELAY", 0)
    new = "https://help.zscaler.com/zia/best-practices-brand-new-guide"
    moved = "https://help.zscaler.com/zia/best-practices-moved-away"
    other = "https://www.zscaler.com/blogs/best-practices-x"
    entries = [{"url": u, "title": bc._titleize_from_slug(u), "via": "sitemap"} for u in (new, moved, other)]
    get = site({"/zia/best-practices-brand-new-guide": article(title="Best Practices: Brand New Guide")})
    base = get

    def fake(url, verify_tls=None):
        if url == other:
            base.calls.append(url)
            return b"<html><head><title>Blog post title | Zscaler</title></head></html>", 200, ""
        return base(url, verify_tls)
    n = bc._resolve_titles(entries, fake, False, None)
    by = {e["url"]: e for e in entries}
    assert by[new]["title"] == "Best Practices: Brand New Guide" and by[new]["titled"]
    assert by[moved]["title"] == bc._titleize_from_slug(moved) and not by[moved].get("titled"), "a 404 article keeps its slug title"
    assert by[other]["title"] == "Blog post title" and by[other]["titled"]
    # Help-center pages are read through fetch-data only; their shell is never fetched.
    assert new not in get.calls and moved not in get.calls and n == len(get.calls) == 3


# ── Review fixes (PR #40) ─────────────────────────────────────────────

def test_a_network_error_on_the_article_is_not_retried_on_the_page():
    """A timeout (status 0) on fetch-data is reported as is; the page, on
    the same host, is not fetched too (that only doubled the wait)."""
    calls = []

    def down(url, verify_tls=None):
        calls.append(url)
        return None, 0, "read timeout to help.zscaler.com (8s)"
    assert zu.read_page(SRC["url"], down) == (None, None, 0, "read timeout to help.zscaler.com (8s)")
    assert len(calls) == 1 and alias(calls[0]) == "/zia/about-dlp-engines"
    # Beacon: a fetcher's network error stops there; an HTTP error still falls back to the page.
    asked = []
    e = beacon._page_entry(SRC, lambda u: asked.append(u) or (None, "connection error: getaddrinfo failed"))
    assert len(asked) == 1 and e["hash"] is None and "getaddrinfo" in e["reason"]
    asked.clear()
    e = beacon._page_entry(SRC, lambda u: asked.append(u) or ((None, "HTTP 502") if alias(u) else (SHELL.decode(), "")))
    assert len(asked) == 2 and e["basis"] == "page" and not e["ok"]


def _snap(i, *entries):
    return {"id": str(i), "online": True, "api": {"pages": list(entries)}}


def _entry(answer):
    return beacon._page_entry(SRC, lambda u: (answer.decode(), "") if alias(u) else (SHELL.decode(), ""))


def _doc_changes(cur, history):
    return [(c["kind"], c.get("key")) for c in beacon.diff(cur, history)["changes"] if c["kind"].startswith("doc_")]


def test_a_page_back_from_maintenance_unchanged_is_not_a_change():
    ok, locked = _entry(article()), _entry(article(status=403))
    assert _doc_changes(_snap(2, locked), [_snap(1, ok)]) == [("doc_gone", "dlp_engines_bp")]
    assert _doc_changes(_snap(3, _entry(article())), [_snap(1, ok), _snap(2, locked)]) == [],         "readable again with the same text: compared with the last readable read, not the maintenance notice"
    assert _doc_changes(_snap(3, _entry(article(content=BODY + "<p>New.</p>"))), [_snap(1, ok), _snap(2, locked)]) ==         [("doc_changed", "dlp_engines_bp")]
    # Still in maintenance: said once, not on every run.
    assert _doc_changes(_snap(3, _entry(article(status=403))), [_snap(1, ok), _snap(2, locked)]) == []


def test_one_failed_read_does_not_hide_the_next_change():
    ok = _entry(article())
    shell = beacon._page_entry(SRC, lambda u: (None, "HTTP 500") if alias(u) else (SHELL.decode(), ""))
    unread = beacon._page_entry(SRC, lambda u: (None, "read timeout"))
    assert shell["basis"] == "page" and unread["hash"] is None
    new = _entry(article(content=BODY + "<p>New.</p>"))
    for between in (shell, unread):
        assert _doc_changes(_snap(2, between), [_snap(1, ok)]) == []
        assert _doc_changes(_snap(3, new), [_snap(1, ok), _snap(2, between)]) == [("doc_changed", "dlp_engines_bp")]


# ── Review fixes, round 2 (PR #40) ────────────────────────────────────

def _down(answer):
    calls = []

    def get(url, verify_tls=None):
        calls.append(url)
        return answer
    get.calls = calls
    return get


@pytest.mark.parametrize("answer", [(None, 0, "Connection timeout to help.zscaler.com."), (b"Too Many Requests", 429, "")])
def test_crawler_titles_do_not_fetch_the_page_after_a_network_error_or_429(monkeypatch, answer):
    """The crawler reads titles through read_page: a timeout or a 429 on
    fetch-data costs one request per article, not two."""
    monkeypatch.setattr(bc, "CRAWL_POLITE_DELAY", 0)
    entries = [{"url": f"https://help.zscaler.com/zia/a{i}", "title": f"a{i}", "via": "sitemap"} for i in range(bc.MAX_TITLE_FETCHES + 10)]
    get = _down(answer)
    n = bc._resolve_titles(entries, get, False, None)
    assert n == len(get.calls) == bc.MAX_TITLE_FETCHES and all(alias(u) for u in get.calls)
    assert all(not e.get("titled") and e["title"].startswith("a") for e in entries)
    get = _down(answer)
    assert zu.read_page(SRC["url"], get)[1] is None and len(get.calls) == 1


def test_updates_tab_keeps_the_link_of_an_article_in_maintenance(monkeypatch):
    """A 403 maintenance article is not readable, not gone: its own link is
    kept and it is not sent to the section index."""
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines": article(status=403)}))
    r = zu._check_html(SRC, {"hash": "abc", "basis": "article", "url": SRC["url"]})
    assert r["status"] == "unreadable" and r["link"] == SRC["url"] and not r["link_fallback"]
    assert "Maintenance" in r["link_note"] and "section index" not in r["link_note"]
    html = open("static/index.html", encoding="utf-8").read()
    assert "unreadable: ['#f59e0b','NOT READABLE']" in html


@pytest.mark.parametrize("title", ["Viewing Removed Devices", "About Error Codes", "Configuring the Access Denied Page", "Page Not Found Settings"])
def test_a_real_article_is_not_dead_because_of_its_title(monkeypatch, title):
    content = "<p>" + "Real guidance about devices. " * 40 + "</p>"
    _, q = zu.help_article(article(title=title, content=content))
    assert q["ok"] and q["title"] == title
    monkeypatch.setattr(zu, "_safe_get", site({"/zia/about-dlp-engines": article(title=title, content=content)}))
    r = zu._check_html(SRC, {})
    assert r["status"] == "new" and r["link"] == SRC["url"]


def test_a_malformed_index_answer_does_not_raise(monkeypatch):
    for bad in (5, True, "x", {"a": 1}):
        body = json.dumps({"data": {"info": {"status": 200}, "body": {"title": "Idx", "content": "", "categories": [{"title": "A", "articles": bad}]}}}).encode()
        _, q = zu.help_article(body)
        assert not q["ok"]
    monkeypatch.setattr(bc, "CRAWL_POLITE_DELAY", 0)
    entries = [{"url": f"https://help.zscaler.com/zia/b{i}", "title": f"b{i}", "via": "sitemap"} for i in range(2)]
    bad = json.dumps({"data": {"info": {"status": 200}, "body": {"title": "Idx", "content": "", "categories": [{"title": "A", "articles": 5}]}}}).encode()
    assert bc._resolve_titles(entries, lambda u, verify_tls=None: (bad, 200, ""), False, None) == 2


def test_help_api_url_keeps_an_already_encoded_path():
    assert "url_alias=/zia/caf%C3%A9-guide&" in zu.help_api_url("https://help.zscaler.com/zia/caf%C3%A9-guide")
    assert "url_alias=/zia/caf%C3%A9-guide&" in zu.help_api_url("https://help.zscaler.com/zia/café-guide")


def test_the_word_report_fallback_cites_the_live_guides_page():
    import report_docx
    text = report_docx._resolve_best_practice("zzz-no-such-label", "zzz", "ZZZ.0")
    assert "https://help.zscaler.com/zscaler-deployments-operations " in text
