"""Page layout requests: no Quick start page (it overlapped the sidebar
workflow and was removed), tenant details folded into the Connect step,
the Evaluate All Rules decision flow in the migration wizard (its transaction simulator was removed)."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_quick_start_is_gone_it_overlapped_the_sidebar_workflow():
    c = _page()
    html = c.get("/").text
    assert "Quick start" not in html and "openQuickStartTab" not in html and "/quickstart" not in html
    assert html.index('aria-label="Start"') < html.index('aria-label="Find the gaps"'), "Start comes first in the toolbar"
    assert c.get("/quickstart").status_code == 404
    for name in ("explain.js", "help.html"):
        assert "quickstart" not in c.get(f"/static/{name}").text.lower(), name
    assert "seven things" in c.get("/help").text


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
    assert ua.status_code == 200 and "window.dlpDialog = { unlock, notice, phrase, ask }" in ua.text and "showModal()" in ua.text
    assert 'type="password"' in ua.text and "aria-labelledby" in ua.text and "addEventListener('cancel'" in ua.text
    theme = c.get("/static/report_theme.js").text
    assert "window.__dlpUnlockDialog" in theme and "askFailed = String(e && e.message || e); return null;" in theme and "r.dlpDialogUnavailable = askFailed" in theme
    for page in ("/report/digest", "/report/view", "/help"):
        assert '/static/ui_auth.js' in c.get(page).text, page
    # The copy about secrets says what the code does (tenant_profiles.upsert).
    assert "Never stored by this tool" not in html and "Kept only in this form for this browser session" in html
    assert "through the <code>keyring</code> package the installer pins with the app" in guide and "optional <code>keyring</code>" not in guide
    c = _page()
    html = c.get("/").text
    assert 'id="evalAllFlow"' in html and '/static/eval_all.js' in html and "evalAllLoadRules" not in html, "the wizard no longer hands rules to a simulator"
    js = c.get("/static/eval_all.js").text
    assert "Tie on the action" in js and "lowest order number" in js and "configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled" in js


def test_evaluate_all_rules_has_its_own_tab_with_the_tie_breaker():
    c = _page()
    page = c.get("/report/evalall")
    assert page.status_code == 200 and "tie-breaker" in page.text and "Rule order breaks the tie" in page.text and "lowest order number" in page.text
    assert 'id="evalAllFlow"' in page.text and "/static/eval_all.js" in page.text and 'role="img"' in page.text
    assert "SaaS Security API DLP" in page.text and "first match" in page.text
    js = c.get("/static/eval_all.js").text
    assert "No tie-breaker on this channel" in js and "SaaS Security API DLP rules are the exception" in js
    # The Simulate a transaction section is gone from both places the flow renders: no rule table, no presets, no result box.
    for gone in ("Simulate a transaction", "eaMatch", "eaResult", "_eaRun", "EA_SIMULATOR", "EA_PRESETS", "evalAllLoadRules", "evalAllSimulate", "ea-table"):
        assert gone not in js, gone
    assert "simulat" not in page.text.lower() and "simulat" not in c.get("/static/explain.js").text.lower()
    assert TestClient(srv.app).get("/report/evalall").status_code == 200
    html = c.get("/").text
    assert "openEvalAllTab()" in html and "How Evaluate All Rules decides" in html


def test_step_strip_buttons_take_you_to_each_step():
    c = _page()
    html = c.get("/").text
    for step in ("configure", "scope", "review"):
        assert f'<button type="button" class="step-item" data-step="{step}"' in html and f"_stepGo('{step}')" in html, step
    assert 'data-step="run"' not in html, "Run assessment lives on the Scope assessment page, not as its own step"
    assert "① Connect" in html and "② Scope assessment" in html and "③ Dashboard: findings + export" in html
    assert "function _stepGo(step)" in html and 'id="scopeField"' in html and "Click a step to go there" in html
    assert '<span class="step-item"' not in html, "the strip is made of real buttons, not labels"


def test_terraform_hand_off_says_when_to_use_each_and_defaults_to_static():
    js = _page().get("/static/deploy_studio.js").text
    assert "2 · Which hand-off" in js and 'class="tf-choose"' in js
    for choice in ("<b>Deploy policy packs</b>", "<b>Gap mode</b>", "<b>Static</b>", "<b>Neither yet</b>"):
        assert choice in js
    assert js.count("<b>Use when</b>") == 2 and js.count("<b>Not when</b>") == 2
    # Gap mode reads the tenant, so it is never picked just because credentials are there.
    assert "return TF.mode === 'gap' && _tfCanGap() ? 'gap' : 'static';" in js
