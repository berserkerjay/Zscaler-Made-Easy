"""Page layout requests: Quick Start Assessment in its own tab from the top
toolbar, tenant details folded into the Connect step, the Evaluate All
Rules flow and simulator in the migration wizard."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_quick_start_is_a_top_button_that_opens_its_own_tab():
    c = _page()
    html = c.get("/").text
    assert "Quick start assessment" in html and "openQuickStartTab()" in html
    assert '<h2>Quick Start</h2>' not in html, "the Quick Start card must be gone from the page body"
    assert html.index('aria-label="Start"') < html.index('aria-label="Find the gaps"'), "Start comes first in the toolbar"
    qs = c.get("/quickstart")
    assert qs.status_code == 200 and "Quick Start</span> Assessment" in qs.text and "OneAPI credentials" in qs.text
    assert TestClient(srv.app).get("/quickstart").status_code == 200   # no token needed for the page itself


def test_tenant_details_live_inside_the_connect_step():
    c = _page()
    html = c.get("/").text
    assert 'id="configPark"' in html and 'id="configCard"' in html
    guide = c.get("/static/guide.js").text
    assert "gdTenantSlot" in guide and "gdTenantDetails" in guide and "Show tenant details" in guide
    assert "slot.appendChild(card)" in guide and "GD._lastHtml" in guide
    assert ".gd-tenant" in c.get("/static/guide.css").text


def test_authenticate_ends_with_an_inline_success_or_an_in_app_failure_dialog():
    """Both Authenticate buttons (the guide's and the form's) end in
    _gdTest. Success stays inline (announced, focus on the connected card,
    the next step obvious); a failure opens the app's own accessible
    dialog with cause, fix and technical detail — never the browser's
    alert() or prompt(), which an embedded browser may not support. The
    four failure kinds are told apart: this app's own token missing, the
    browser unable to show a dialog, the server unreachable, the tenant
    refusing (credentials or permission)."""
    c = _page()
    guide = c.get("/static/guide.js").text
    assert "function _gdAuthVerdict(conn)" in guide and "_gdAuthVerdict(GD.conn)" in guide and "window.dlpDialog.notice(" in guide
    assert "window.alert(" not in guide.split("function _gdAuthVerdict")[1].split("function _gdAuthPopup")[0]
    assert "fat-fingered" not in guide and "SUCCESS —" not in guide
    for kind in ("token", "dialog", "server"):
        assert f"{kind}: {{ kind:" in guide
    assert "if (GD.testing) return;" in guide and "formBtn.disabled = true" in guide   # no double submit
    assert "data.token_required" in guide and "'permission' : 'tenant'" in guide
    assert "function _gdIdent()" in guide and "c.vd !== _gdIdent()" in guide   # the classic sign-in's status is not blanked
    assert guide.count("_gdTest(") == 2, "only the guide's button (and the form's, via index.html) call _gdTest"
    html = c.get("/").text
    assert "await _gdTest(); return;" in html   # the form's Authenticate funnels into the same function
    # The token unlock: the in-app dialog first, the browser prompt only as a guarded fallback.
    assert "window.__dlpUnlockDialog" in html and "r.dlpTokenRequired = true" in html and "askFailed = String(e && e.message || e); return null;" in html
    assert "r.dlpDialogUnavailable = askFailed" in html and "r.dlpDialogUnavailable\n        ? _gdConnFailure('dialog'" in guide   # a browser that cannot ask is named as such
    ua = c.get("/static/ui_auth.js")
    assert ua.status_code == 200 and "window.dlpDialog = { unlock, notice }" in ua.text and "showModal()" in ua.text
    assert 'type="password"' in ua.text and "aria-labelledby" in ua.text and "addEventListener('cancel'" in ua.text
    theme = c.get("/static/report_theme.js").text
    assert "window.__dlpUnlockDialog" in theme and "askFailed = String(e && e.message || e); return null;" in theme and "r.dlpDialogUnavailable = askFailed" in theme
    for page in ("/report/digest", "/report/view", "/help"):
        assert '/static/ui_auth.js' in c.get(page).text, page
    # The copy about secrets says what the code does (tenant_profiles.upsert).
    assert "Never stored by this tool" not in html and "Kept only in this form for this browser session" in html
    assert "optional <code>keyring</code> package is installed, otherwise" in guide
    c = _page()
    html = c.get("/").text
    assert 'id="evalAllFlow"' in html and '/static/eval_all.js' in html and "evalAllLoadRules(migrateRules)" in html
    js = c.get("/static/eval_all.js").text
    assert "Tie on the action" in js and "lowest order number" in js and "about-first-match-wins-and-evaluate-all-rules-for-dlp" in js


def test_evaluate_all_rules_has_its_own_tab_with_the_tie_breaker():
    c = _page()
    page = c.get("/report/evalall")
    assert page.status_code == 200 and "tie-breaker" in page.text and "Rule order breaks the tie" in page.text and "lowest order number" in page.text
    assert 'id="evalAllFlow"' in page.text and "/static/eval_all.js" in page.text and 'role="img"' in page.text
    assert "SaaS Security API DLP" in page.text and "first match" in page.text
    js = c.get("/static/eval_all.js").text
    assert "EA_EVAL_ALL = { web: true, endpoint: true, email: true, saas: false }" in js and "No tie-breaker on this channel" in js
    # The reference tab is the decision only: the simulator stays in the migration wizard.
    assert "const EA_SIMULATOR = location.pathname !== '/report/evalall'" in js and "if (EA_SIMULATOR) _eaRun()" in js
    assert "simulator" not in page.text.lower().replace("the simulator that runs", "")
    assert TestClient(srv.app).get("/report/evalall").status_code == 200
    html = c.get("/").text
    assert "openEvalAllTab()" in html and "How Evaluate All Rules decides" in html


def test_step_strip_buttons_take_you_to_each_step():
    c = _page()
    html = c.get("/").text
    for step in ("configure", "scope", "run", "review"):
        assert f'<button type="button" class="step-item" data-step="{step}"' in html and f"_stepGo('{step}')" in html, step
    assert "function _stepGo(step)" in html and 'id="scopeField"' in html and "Click a step to go there" in html
    assert '<span class="step-item"' not in html, "the strip is made of real buttons, not labels"
