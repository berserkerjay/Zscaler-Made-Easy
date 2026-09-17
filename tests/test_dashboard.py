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


def test_the_mirrored_results_tab_is_styled_like_the_page():
    """The results open in their own tab (report_view.html mirrors the
    results HTML). The dashboard markup travels with that HTML, so its
    styles must key off classes inside the results, not the page body,
    and the tab must load the stylesheet; otherwise the rings are blank
    circles and nothing lines up."""
    css = _read("dashboard.css")
    js = _read("dashboard.js")
    view = _read("report_view.html")
    assert '<link rel="stylesheet" href="/static/dashboard.css">' in view
    assert "heroCard.classList.add('db-dash')" in js and "checksList.classList.add('db-rows')" in js
    assert ".score-hero.db-dash {" in css and ".db-dash .score-num {" in css and ".db-rows .check-item {" in css and ".db-rows .check-item::before {" in css
    assert "body.db-layout, body.tool-tab { --db-w" in css, "the tab gets the colour tokens the rings use"
    for bad in ("body.db-layout .score-hero", "body.db-layout .score-num", "body.db-layout .check-item", "body.db-layout .section-header"):
        assert bad not in css, f"{bad} would style the page only, never the mirrored tab"


def test_run_from_the_sidebar_signs_in_first_and_lands_on_this_page():
    """Clicking Run assessment in the sidebar: missing details open the
    Connect step on the first blank field and queue the run; a tenant not
    yet authenticated is authenticated, then assessed; a successful
    Authenticate starts a queued run. The run happens on this page (no
    pop-out tab), so the dashboard is where you land."""
    js = _read("dashboard.js")
    assert "function runFromSidebar()" in js and "if (k === 'run') { runFromSidebar(); return; }" in js
    assert "function missingFields()" in js and "['org', 'assessor'].concat(legacy ? ['zuser', 'zpass', 'zkey'] : ['vd', 'cid', 'csec'])" in js
    assert "remembered && (id === 'csec' || id === 'zpass' || id === 'zkey')" in js, "a profile's remembered secret counts"
    assert "function signedIn()" in js and "GD.conn" in js
    assert "pendingRun = true" in js and "goConnect(missing[0])" in js and "await authenticateTenant()" in js
    assert "window._gdTest = async function" in js and "if (pendingRun && signedIn()) startRun()" in js
    assert "runAssessment();" in js and "openToolTab('results'" not in js, "the sidebar run stays on this page"
    assert "Sign in first" in js and "starts by itself right after" in js
    css = _read("dashboard.css")
    assert ".db-note" in css and ".db-note.warn" in css


def test_the_channels_page_is_wired_a_real_new_nav_item_not_decoration():
    """Channel Selection: a new sidebar nav item that shows 11 real
    channels (icon, risk, category, description), lets the operator mark
    each Zscaler-owned or covered by an alternative, tallies owned /
    alternatives / coverage gaps, persists the choice in this browser,
    and hides the rest of the main content (including the guide panel)
    while it is open."""
    js = _read("dashboard.js")
    css = _read("dashboard.css")
    assert 'data-db="channels"' in js and "showChannels()" in js and "hideChannels()" in js
    for name in ("Inline Web DLP", "Endpoint DLP", "Email DLP", "SaaS Security (CASB)", "GenAI Security", "Shadow IT Discovery",
                 "Endpoint Data Scan", "SSL/TLS Inspection", "Cloud App Control", "Device Control", "Workflow Automation"):
        assert f"name: '{name}'" in js, name
    assert "CHANNELS_KEY = 'zassess_channels_v1'" in js and "localStorage.setItem(CHANNELS_KEY" in js
    assert "'stepBar', 'gdPanel', 'configPark', 'configCard', 'progressCard', 'results'" in js, "the guide panel is hidden with the rest of main, or it bleeds through"
    assert "dbChOwned" in js and "dbChAlt" in js and "dbChGaps" in js and "dbChFootTxt" in js and "dbChContinue" in js
    for cls in (".db-ch-row", ".db-ch-choice", ".db-pill", ".db-ch-foot", ".db-chip.risk-fail", ".db-chip.risk-ok"):
        assert cls in css, cls
