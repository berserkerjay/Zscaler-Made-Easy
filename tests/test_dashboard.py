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
    for step in ("dashboard", "configure", "scope"):
        assert f'data-db="{step}"' in js, step
    assert 'data-db="run"' not in js, "Run assessment is a button on the Scope assessment page, not a nav item"
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


def test_automation_readiness_sections_do_not_get_their_own_pillar_tiles():
    """Automation Readiness (SDK/OneAPI, Terraform, Ansible, ZPA, ZCC, IaC
    Hygiene) still runs and still counts toward the overall score — only
    the Score by Section grid stops giving each of its six sub-sections
    its own tile; every other section keeps one."""
    js = _read("dashboard.js")
    assert "filter(([name]) => !/^Automation — /.test(name))" in js
    assert "function pillars(sections)" in js


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


def test_run_from_the_sidebar_asks_to_sign_in_first_and_lands_on_this_page():
    """Clicking Run assessment on the Scope assessment page: a missing
    organisation or assessor stays on that page (Report details); missing
    sign-in details, or a tenant not yet authenticated, open the Connect
    step and say to sign in, then click Run again. Nothing is queued:
    Authenticate never starts an assessment. The run happens on this page
    (no pop-out tab), so the dashboard is where you land."""
    js = _read("dashboard.js")
    assert "function runFromSidebar()" in js and "sec.querySelector('#dbScopeRun').addEventListener('click', () => { runFromSidebar(); });" in js
    assert "if (k === 'run')" not in js
    assert "const report = missing.filter(id => id === 'org' || id === 'assessor');" in js and "under Report details in Connect to the tenant, then click Run assessment" in js
    assert "goConnect(report[0]);" in js, "a missing organisation or assessor opens Connect on that field"
    assert "hideScopeView(); setCurrent('dashboard');" in js, "the Scope assessment page steps aside when the run starts"
    assert "function missingFields()" in js and "['org', 'assessor'].concat(legacy ? ['zuser', 'zpass', 'zkey'] : ['vd', 'cid', 'csec'])" in js
    assert "remembered && (id === 'csec' || id === 'zpass' || id === 'zkey')" in js, "a profile's remembered secret counts"
    assert "function signedIn()" in js and "GD.conn" in js
    # Signed out, a Run click says to sign in and goes to the form; signing
    # in never starts the run (every read counts against ZIA's rate limit).
    assert "goConnect(missing[0])" in js and "then click Run assessment again" in js
    assert "pendingRun" not in js and "window._gdTest =" not in js and "await authenticateTenant()" not in js
    assert "starts by itself" not in js and "the assessment starts right after" not in js
    assert "runAssessment();" in js and "openToolTab('results'" not in js, "the sidebar run stays on this page"
    assert "Sign in first" in js
    # Enter in a field never starts an assessment: only a Run button does.
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "activeEl.tagName === 'INPUT') runAssessment()" not in html and "No Enter-to-run" in html
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
    """The "Start here" guide and the tenant details form it carries are
    a sign-in surface, not part of the dashboard: they must not be on
    screen the moment the page loads. They appear only when the operator
    goes to Connect to the tenant — from this sidebar, the legacy step
    strip above it, or a route the app itself takes there (a missing
    field, a failed sign-in, a reset) — and hide again once the operator
    moves on. Scope has its own combined page and no longer opens this."""
    js = _read("dashboard.js")
    assert "function showTenantConfig()" in js and "function hideTenantConfig()" in js
    assert "hideTenantConfig();" in js, "hidden the moment the add-on runs, before any click"
    assert "CONFIG_VIEW_KEYS = new Set(['configure'])" in js
    assert "(CONFIG_VIEW_KEYS.has(k) ? showTenantConfig : hideTenantConfig)();" in js, "setCurrent is the one place every route (sidebar, step strip, goConnect, reset) passes through"
    assert "const origGoConfig = window._gdGoConfig;" in js and "showTenantConfig(); return origGoConfig.apply(this, arguments);" in js, "the legacy step strip's Configure/Scope buttons call _gdGoConfig directly, bypassing the sidebar handler"


def test_the_workflow_sidebar_follows_the_steps_connect_scope_then_dashboard():
    # "Move connect to the tenant above the dashboard": the Workflow group
    # reads in the order the work is done, like the step strip.
    js = _read("dashboard.js")
    keys = ("dashboard", "configure", "scope", "review")
    nav = [k for k in re.findall(r'class="db-item" data-db="([a-z]+)"', js) if k in keys]
    assert nav == ["configure", "scope", "dashboard"], nav
    assert 'data-db="dashboard" aria-current="page"' in js, "the Dashboard is still the page that opens first"
    assert 'data-db="channels"' not in js, "Channels is folded into Scope, not its own nav item"
    assert 'data-db="review"' not in js, "Findings & report is the Dashboard, not its own nav item"
    assert "if (k === 'review') k = 'dashboard';" in js, "the step strip's review step lands on the Dashboard"


def test_the_score_tiles_are_always_on_screen_even_before_a_run():
    """The score tiles (ring, completion, radar, pillars, insights,
    actions) live outside #results, moved there rather than copied, so
    they are on screen the moment the page loads — not only after a run
    in this tab. A slim note above them names the tenant profile's last
    recorded assessment (score, maturity, when it ran) when the server
    has one on file, and fills the ring from it; otherwise a plain
    prompt into Connect to the tenant. Real results, once shown, hide the
    note and overwrite the tiles as before."""
    js = _read("dashboard.js")
    css = _read("dashboard.css")
    tt = _read("tool_tabs.js")
    assert "function renderLastRunOrEmpty()" in js and "id = 'dbLastRun'" in js
    assert "GD.profileDetail" in js and "det.last_assessed" in js
    assert "No assessment recorded yet" in js and "Showing the last recorded assessment" in js
    assert "heroCard.id = 'dbHero';" in js and "lastRun.insertAdjacentElement('afterend', heroCard);" in js, "moved out of #results, not copied"
    assert "'progressCard', 'results', 'dbLastRun']" in js, "hidden with the rest of main while Scope is open"
    assert "(CONFIG_VIEW_KEYS.has(k) ? showTenantConfig : hideTenantConfig)();\n    renderLastRunOrEmpty();" in js, "updates the moment the nav selection changes"
    assert ".db-lastrun-note {" in css and ".db-lastrun-btn {" in css
    assert "panels: ['dbHero', 'progressCard', 'results']" in tt, "the mirrored 'Open in new tab' results view must still carry the hero"


def test_scope_combines_channels_assessment_scope_and_compliance_frameworks():
    """Scope assessment is one combined page, reached from a single sidebar
    link: Channels (11 real channels — icon, risk, category, description —
    the operator marks each Zscaler-owned or covered by an alternative,
    with a running tally), then Assessment Scope, then Compliance
    Frameworks, then Report details (organisation, assessor) — the same
    live fields the assessment itself reads, moved into the page rather
    than copied, so the tenant configuration keeps sign-in details only.
    It hides the rest of the main content (including the guide panel)
    while it is open, and its Run assessment button is the run."""
    js = _read("dashboard.js")
    css = _read("dashboard.css")
    assert 'data-db="scope"' in js and "function showScopeView()" in js and "function hideScopeView()" in js
    assert "window.__dbShowScope = showScopeView" in js, "the legacy step strip's Scope button (_stepGo) calls this directly"
    for name in ("Inline Web DLP", "Endpoint DLP", "Email DLP", "SaaS Security (CASB)", "GenAI Security", "Shadow IT Discovery",
                 "Endpoint Data Scan", "SSL/TLS Inspection", "Cloud App Control", "Device Control", "Workflow Automation"):
        assert f"name: '{name}'" in js, name
    assert "CHANNELS_KEY = 'zassess_channels_v1'" in js and "localStorage.setItem(CHANNELS_KEY" in js
    assert "'stepBar', 'gdPanel', 'configPark', 'configCard', 'dbHero', 'progressCard', 'results'" in js, "the guide panel and the score tiles are hidden with the rest of main, or they bleed through"
    assert "dbChFootTxt" in js and "dbScopeRun" in js and "dbScopeContinue" not in js
    assert "Scope assessment</h1>" in js and 'data-db="scope"><span class="db-ico" aria-hidden="true">🎯</span>Scope assessment</button>' in js
    assert "$('scopeField'); if (sf) sec.querySelector('#dbScopeAssessBody').appendChild(sf)" in js
    assert "$('complianceFwField'); if (fw) sec.querySelector('#dbScopeFwBody').appendChild(fw)" in js
    assert "dbScopeReportBody" not in js, "Report details are part of the tenant configuration, not Scope assessment"
    html = _read("index.html")
    assert "What the app needs to read the tenant, and the report details" in html
    for cls in (".db-ch-row", ".db-ch-choice", ".db-pill", ".db-scope-section", ".db-scope-tally", ".db-scope-foot", ".db-chip.risk-fail", ".db-chip.risk-ok"):
        assert cls in css, cls


def test_report_details_are_part_of_the_tenant_configuration():
    # "Make the report details section part of the tenant config": the
    # organisation and assessor fields sit in their own Report details block
    # inside the tenant configuration card, above Authenticate.
    js = _read("dashboard.js")
    assert "(function reportDetailsInTenantConfig()" in js
    assert "box.id = 'dbConnectReport'" in js and "<h3>Report details</h3>" in js
    assert "[org, who].forEach(el => { const f = el.closest('.field'); if (f) box.querySelector('#dbConnectReportBody').appendChild(f); });" in js
    assert "actions.insertAdjacentElement('beforebegin', box)" in js, "above Authenticate"
    assert ".db-connect-report" in _read("dashboard.css")
