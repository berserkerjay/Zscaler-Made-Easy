"""The plain-English layer: every function on the toolbar has an entry in
the explain catalogue, every report page loads the explainer box, and
the /help page lists every function, the glossary and the trouble list."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


# Toolbar opener -> catalogue key. A new toolbar button must be added here
# AND to explain.js, so nothing ships unexplained.
TOOLBAR = {
    "openQuickStartTab()": "quickstart", "openHelpTab()": "help", "openDataFlowTab()": "dataflow",
    "openToolTab('efficacy')": "efficacy", "openDetectionHealthTab()": "health", "openDlpPacksModal()": "packs",
    "openToolTab('terraform')": "terraform", "_gdGoMigration()": "migration", "openEvalAllTab()": "evalall",
    "openToolTab('bestpractices')": "bestpractices", "openAdvancedTab()": "advanced", "openToolTab('updates')": "updates",
    "openLogAnalyzerTab()": "logs", "openDigestTab()": "digest",
}


def _catalogue_keys():
    js = _read("explain.js")
    return set(re.findall(r"^\s{2}X\.(\w+) = \{", js, re.M))


def test_every_toolbar_button_is_explained():
    html = _read("index.html")
    start = html.index('<div class="hero-toolbar"')
    end = html.index("<!-- DLP Efficacy modal -->", start)
    toolbar = html[start:end]
    clicks = re.findall(r'onclick="([^"]+)"', toolbar)
    assert clicks, "toolbar has buttons"
    unknown = [c for c in clicks if c not in TOOLBAR]
    assert not unknown, f"toolbar buttons without an explanation: {unknown}"
    keys = _catalogue_keys()
    missing = [k for k in TOOLBAR.values() if k not in keys]
    assert not missing, f"explain.js lacks: {missing}"
    assert 'aria-label="Troubleshoot"' in toolbar and "Log Analyzer" in toolbar
    assert "What does everything do?" in toolbar


def test_catalogue_entries_are_complete_sentences_for_a_first_week_engineer():
    js = _read("explain.js")
    for key in _catalogue_keys():
        block = js[js.index(f"  X.{key} = {{"):]
        block = block[: block.index("\n  };")]
        for field in ("group", "name", "what", "why", "when", "get", "next"):
            m = re.search(rf"(?:^|[\s,])\s*{field}: '((?:[^'\\]|\\.)*)'", block, re.M)
            assert m, f"{key} lacks {field}"
            if field not in ("group", "name"):
                assert len(m.group(1)) >= 40, f"{key}.{field} is too short to help anyone"
    groups = set(re.findall(r"group: '([^']+)'", js))
    assert groups == {"Start", "Find the gaps", "Close the gaps", "Reference", "Troubleshoot"}


def test_every_report_route_has_an_explainer_and_loads_the_script():
    js = _read("explain.js")
    routes = sorted(r.path for r in srv.app.routes if getattr(r, "path", "").startswith("/report/"))
    for path in routes:
        assert f"'{path}'" in js, f"explain.js does not map {path}"
    for name in sorted(n for n in os.listdir(STATIC) if n.startswith("report_") and n.endswith(".html")) + ["quickstart.html", "help.html"]:
        html = _read(name)
        assert '<script src="/static/explain.js"></script>' in html, name
        assert '<script src="/static/report_theme.js"></script>' in html, name
        assert html.index("report_theme.js") < html.index("explain.js"), name
    assert "hero.insertAdjacentElement('afterend', box)" in js and "zassess_explain_hidden" in js


def test_help_page_and_guide_share_one_catalogue():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    page = c.get("/help")
    assert page.status_code == 200
    for needle in ("DLP_FIRST_DAY", "DLP_EXPLAIN_CARD", "DLP_GLOSSARY", "DLP_TROUBLE", 'id="glossary"', 'id="trouble"', "<main"):
        assert needle in page.text, needle
    guide = _read("guide.js")
    assert "const GD_GLOSSARY = window.DLP_GLOSSARY" in guide and "window.DLP_TROUBLE" in guide
    assert 'href="/help"' in guide and "<dt>Log Analyzer</dt>" in guide
    home = c.get("/").text
    assert home.index("/static/explain.js") < home.index("/static/guide.js")
    js = _read("explain.js")
    for term in ("Client Connector (ZCC)", "PAC file", "Captive portal", "Z-Tunnel 1.0 / 2.0"):
        assert term in js
