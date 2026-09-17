"""The dashboard layout: a left sidebar built from the toolbar's own
buttons, and the results drawn as the maturity ring, completion ring,
score radar, pillar cards, key insights, action tiles, list-row findings
and a sticky progress footer. It is an add-on (static/dashboard.js +
dashboard.css) injected last, so it wraps the inline script's entry
points and never becomes a second source of truth."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(name):
    return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()


def test_the_add_on_is_injected_last_and_only_wraps_the_page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    html = c.get("/").text
    scripts = re.findall(r'<script src="/static/([a-z_]+\.js)\?v=', html)
    assert scripts[-1] == "dashboard.js", scripts
    assert '<link rel="stylesheet" href="/static/dashboard.css?v=' in html
    js = _read("dashboard.js")
    # Guarded to the assessment page; report tabs never get a sidebar.
    assert "location.pathname.replace(/\\/+$/, '') || '/') !== '/'" in js
    # Wraps, never replaces: the original functions are called first.
    for fn in ("showResults", "renderChecks", "resetForm"):
        assert f"window.{fn} = function" in js and f"orig" in js, fn
    assert "origShow.apply(this, arguments)" in js and "origRender.apply(this, arguments)" in js


def test_the_sidebar_moves_the_toolbar_buttons_instead_of_copying_them():
    js = _read("dashboard.js")
    assert "tools.appendChild(g)" in js and "toolbar.hidden = true" in js, "the buttons move; no duplicate onclick targets"
    assert "'.tool-group'" in js and "'aria-label', 'Navigation'" in js and 'aria-label="Workflow"' in js
    for step in ("configure", "scope", "run", "review"):
        assert f'data-db="{step}"' in js, step
    assert "_stepGo(k)" in js and "Current implementation" in js
    assert "'themeToggleBtn', 'bgIntensityControl'" in js, "the theme toggle docks in the sidebar foot"
    assert "aria-controls=\"dbSidebar\"" in js.replace("'", '"') or "setAttribute('aria-controls', 'dbSidebar')" in js
    assert "aria-expanded" in js


def test_the_dashboard_keeps_every_id_the_inline_script_updates():
    js = _read("dashboard.js")
    for i in ("scoreNum", "scoreLabel", "scoreMeta"):
        assert f'id="{i}"' in js, i
    for i in ("dbRingArc", "dbCompArc", "dbRadar", "dbPillars", "dbInsights", "dbActions", "dbBand", "dbFooter"):
        assert i in js, i
    # The maturity band matches the assessment's own thresholds.
    assert "['Ad Hoc', 'Initial', 'Developing', 'Managed', 'Optimized']" in js
    assert "score >= 90 ? 4 : score >= 75 ? 3 : score >= 50 ? 2 : score >= 25 ? 1 : 0" in js
    assert 'role="img"' in js and "aria-labelledby" in js, "the rings and radar are described for assistive tech"
    assert "openRemediationReview" in js and "openDataFlowTab" in js and "downloadDocx" in js and "openDlpPacksModal" in js and "openPathAnalyzerTab" in js


def test_the_stylesheet_reads_the_tokens_and_respects_reduced_motion_and_light_theme():
    css = _read("dashboard.css")
    assert ":root" not in css, "tokens live in index.html's first <style>"
    assert "prefers-color-scheme" not in css and "prefers-reduced-motion" in css
    assert "body.theme-light #dbSidebar" in css and "body.theme-light #dbFooter" in css
    assert "var(--btn, #2563eb)" in css
    assert "@media (max-width: 1000px)" in css and "#dbMenuBtn" in css
    for cls in (".db-ring", ".db-band", ".db-radar", ".db-pillar", ".db-insights", ".db-action", "#dbFooter", ".check-item::before"):
        assert cls in css, cls
