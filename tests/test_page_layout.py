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
    assert "Quick Start Assessment" in html and "openQuickStartTab()" in html
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


def test_evaluate_all_rules_flow_and_simulator_are_in_the_wizard():
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
