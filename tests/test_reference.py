"""The reference pages (the framework HTMLs an engineer keeps next to the
tool) are served from the app under their own routes, listed for the
sidebar, and explained in the catalogue like every other page."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_every_reference_page_is_served_listed_and_explained():
    c = TestClient(srv.app)
    listed = c.get("/api/reference").json()["pages"]
    assert [p["slug"] for p in listed] == [p["slug"] for p in srv.REFERENCE_PAGES] and len(listed) == 4
    explain = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    for p in listed:
        assert p["available"] and p["bytes"] > 1000, p
        r = c.get(p["href"])
        assert r.status_code == 200 and r.headers["content-type"].startswith("text/html"), p["href"]
        assert f"<title>{p['name']}</title>" in r.text, f"{p['href']} serves the page whose title matches its name"
        assert "Content-Security-Policy" in r.headers and "script-src 'self' 'unsafe-inline'" in r.headers["Content-Security-Policy"], "their inline scripts may run"
        assert re.search(r"href: '%s'" % re.escape(p["href"]), explain), f"{p['href']} is in the explain catalogue"
        assert p["blurb"].endswith(".")
    # Only the listed slugs are served; nothing else under static/reference is reachable by path.
    assert c.get("/reference/../index").status_code in (404, 400)
    assert c.get("/reference/nope").status_code == 404


def test_the_reference_pages_load_nothing_from_the_network():
    for p in srv.REFERENCE_PAGES:
        html = open(os.path.join(ROOT, "static", "reference", f"{p['slug']}.html"), encoding="utf-8").read()
        assert not re.search(r'<(?:script|link|img|iframe)[^>]+(?:src|href)="https?://', html), f"{p['slug']} references an external resource"


def test_every_reference_page_has_a_toolbar_button_that_opens_it():
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "function openReferenceTab(slug)" in index and "window.open(`/reference/${encodeURIComponent(slug)}`, '_blank')" in index
    for p in srv.REFERENCE_PAGES:
        assert f"""onclick="openReferenceTab('{p['slug']}')\"""" in index, p["slug"]


def test_every_tab_can_return_to_the_assessment_page():
    """A reference page is served with the shared theme script, which adds a
    fixed "Back to the assessment" button when the page has no link home;
    report pages' own home links focus the opener tab and close."""
    c = TestClient(srv.app)
    for p in srv.REFERENCE_PAGES:
        html = c.get(f"/reference/{p['slug']}").text
        assert '<script src="/static/report_theme.js"></script>' in html, p["slug"]
    theme = open(os.path.join(ROOT, "static", "report_theme.js"), encoding="utf-8").read()
    assert "backHomeBtn" in theme and "← Back to the assessment" in theme and "window.opener" in theme and "location.href = '/'" in theme
    assert "document.querySelector('link[href=\"/app.css\"]')" in theme, "the theme toggle stays off self-contained pages"
    for name in os.listdir(os.path.join(ROOT, "static")):
        if name.startswith("report_") and name.endswith(".html") or name == "help.html":
            html = open(os.path.join(ROOT, "static", name), encoding="utf-8").read()
            assert 'href="/"' in html and "report_theme.js" in html, f"{name} has a way back"


def test_the_data_security_architect_site_is_an_external_reference_link():
    """The uploaded "Data Security Architect.app" was a Chrome app-mode
    launcher for a Google Sites page under the zscaler.com workspace, not
    content: the sidebar carries it as an external link that opens in a
    new tab with noopener, says it needs the zscaler.com sign-in, and is
    explained like every other Reference item."""
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    html = c.get("/").text
    url = "https://sites.google.com/zscaler.com/datasecurityarchitecture/data-security-architect"
    assert f"const DATA_SECURITY_ARCHITECT_URL = '{url}'" in html
    assert "window.open(DATA_SECURITY_ARCHITECT_URL, '_blank', 'noopener')" in html
    assert 'onclick="openDataSecurityArchitectTab()"' in html and "needs a zscaler.com Google sign-in" in html
    xp = c.get("/static/explain.js").text
    assert "X.dsarchitect = {" in xp and f"href: '{url}'" in xp and "group: 'Reference', name: 'Data Security Architect'" in xp
    # The flow pages are the gap analysis and the traffic flows; each links to the reference architecture it is measured against.
    for page in ("/report/dataflow", "/report/path", "/report/sslflow", "/report/bypass"):
        t = c.get(page).text
        assert f'href="{url}" target="_blank" rel="noopener"' in t and "Reference architecture" in t, page
