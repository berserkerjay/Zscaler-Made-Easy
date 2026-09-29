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
    assert [p["slug"] for p in listed] == [p["slug"] for p in srv.REFERENCE_PAGES] and len(listed) == 5
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


def test_the_data_security_architect_page_carries_its_diagrams_and_tables_offline():
    """The Architect app's diagrams (WebP under static/reference/dsa) and
    the tables from its screenshots live in an in-app reference page; the
    flow pages link to its inline-web module as the architecture they are
    measured against; the live source site is linked from the page, never
    loaded."""
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    page = c.get("/reference/data-security-architect").text
    assert "<title>Data Security Architect</title>" in page
    figs = re.findall(r'<img src="(/static/reference/dsa/[a-z0-9-]+\.webp)"', page)
    assert len(figs) == 33 and len(set(figs)) == 33, "every diagram once"
    for f in figs:
        assert os.path.exists(os.path.join(ROOT, f.lstrip("/"))), f
        assert c.get(f).status_code == 200, f
    for sec in ("chain", "dictionaries", "engines", "inline", "endpoint", "email", "saas", "edmidm", "aisec", "workflow", "setup", "walkbacks"):
        assert f'<section id="{sec}"' in page, sec
    for needle in ("POSIX-ERE syntax", "Match Any Patterns and Any Phrases", "no Exclude at root", "exempt_dlpidentifier",
                   "Silently pre-empts DLP", "X-Zscaler-Block: 1", "Scan Initialized", "Escalate is allowed", "Reopen", "Saved ≠ active.",
                   "Workflow Automation shows no incidents", "Inline web rule never fires"):
        assert needle in page, needle
    assert 'id="lb"' in page and "showModal()" in page and 'class="zoom"' in page, "each diagram opens full size"
    assert 'href="https://sites.google.com/zscaler.com/datasecurityarchitecture/data-security-architect" target="_blank" rel="noopener"' in page
    assert "Data Security Architect" in [p["name"] for p in srv.REFERENCE_PAGES]
    html = c.get("/").text
    assert "openReferenceTab('data-security-architect')" in html and "DATA_SECURITY_ARCHITECT_URL" not in html
    xp = c.get("/static/explain.js").text
    assert "X.dsarchitect = {" in xp and "href: '/reference/data-security-architect'" in xp
    for flow in ("/report/dataflow", "/report/path", "/report/sslflow", "/report/bypass"):
        t = c.get(flow).text
        assert 'href="/reference/data-security-architect#inline"' in t and "Reference architecture" in t, flow
