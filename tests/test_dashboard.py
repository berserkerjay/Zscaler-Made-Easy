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


def test_the_score_distribution_radar_never_clips_and_has_an_exploded_view():
    """The radar's viewBox is computed from the actual label set (never a
    fixed box), so a long or crowded set of section names can't overflow
    one side and get silently clipped by the SVG. An expand button on the
    tile opens a full-size modal with untruncated labels, per-point
    percentages and a legend table; Escape or the backdrop closes it and
    returns focus to the button."""
    js = _read("dashboard.js")
    css = _read("dashboard.css")
    assert "function radarSvg(sections" in js
    assert "viewBox=\"0 0 ${(halfX * 2)" in js, "the box is sized from the labels, not a fixed constant"
    for legacy in ('viewBox="0 0 220 190"', "cx = 110", "cy = 95"):
        assert legacy not in js, f"{legacy} would be the old fixed, clipping viewBox"
    assert "function openRadarModal()" in js and "function closeRadarModal()" in js
    assert "id=\"dbRadarExpand\"" in js and "radarSvg(lastSections, { R: 220" in js
    assert "dlg.classList.contains('open')" in js and "e.key === 'Escape'" in js
    assert "e.target === dlg" in js, "clicking the backdrop closes it too"
    assert "btn.focus()" in js, "focus returns to the expand button on close"
    assert "dbRadarTbl" in js and "db-radar-legend" in js
    assert ".db-modal {" in css and ".db-modal.open {" in css and ".db-expand {" in css
    assert "#dbRadarBig svg .area {" in css and "#dbRadarBig svg .pt {" in css, "the exploded view must use the same theme colours as the tile, not SVG defaults"


def test_tenant_configuration_is_hidden_until_its_own_sidebar_link_is_used():
    """The "Start here" guide and the tenant details form it carries (with
    the scope checklist nested inside) are a sign-in surface, not part of
    the dashboard: they must not be on screen the moment the page loads.
    They appear only when the operator goes to Connect to the tenant or
    Scope — from this sidebar, the legacy step strip above it, or a route
    the app itself takes there (a missing field, a failed sign-in, a
    reset) — and hide again once the operator moves on."""
    js = _read("dashboard.js")
    assert "function showTenantConfig()" in js and "function hideTenantConfig()" in js
    assert "hideTenantConfig();" in js, "hidden the moment the add-on runs, before any click"
    assert "CONFIG_VIEW_KEYS = new Set(['configure', 'scope'])" in js
    assert "(CONFIG_VIEW_KEYS.has(k) ? showTenantConfig : hideTenantConfig)();" in js, "setCurrent is the one place every route (sidebar, step strip, goConnect, reset) passes through"
    assert "const origGoConfig = window._gdGoConfig;" in js and "showTenantConfig(); return origGoConfig.apply(this, arguments);" in js, "the legacy step strip's Configure/Scope buttons call _gdGoConfig directly, bypassing the sidebar handler"


def test_connect_to_the_tenant_sits_directly_below_dashboard_in_the_sidebar():
    js = _read("dashboard.js")
    keys = ("dashboard", "configure", "channels", "scope", "run", "review")
    nav = [k for k in re.findall(r'data-db="([a-z]+)"', js) if k in keys][:len(keys)]
    assert nav == ["dashboard", "configure", "channels", "scope", "run", "review"], nav


def test_the_dashboard_never_sits_blank_before_a_run():
    """Before a fresh run in this tab, the space where results render
    must show either the tenant's last recorded assessment (score,
    maturity, when it ran) or a plain prompt to connect — never nothing.
    It hides again once real results, Channels, or Connect/Scope are on
    screen, so it never stacks with them."""
    js = _read("dashboard.js")
    css = _read("dashboard.css")
    assert "function renderLastRunOrEmpty()" in js and "id = 'dbLastRun'" in js
    assert "GD.profileDetail" in js and "det.last_assessed" in js
    assert "No assessment yet" in js and "Last assessment" in js
    assert "'progressCard', 'results', 'dbLastRun']" in js, "hidden with the rest of main while Channels is open"
    assert "(CONFIG_VIEW_KEYS.has(k) ? showTenantConfig : hideTenantConfig)();\n    renderLastRunOrEmpty();" in js, "updates the moment the nav selection changes"
    assert ".db-lastrun-stat {" in css and ".db-lastrun-btn {" in css


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
