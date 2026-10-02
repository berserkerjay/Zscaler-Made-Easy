"""Findings and remediation clarity (UI/UX stage 3): every class of
result has its own tile, filter and pill; a refused read never reads as
"not configured"; the remediable subset is counted against all open
findings; ticks are not consent; Apply is for the plan that was previewed."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c.get("/").text


def test_each_result_class_has_its_own_tile_filter_and_pill():
    html = _page()
    assert 'id="notPermStat" hidden' in html and 'id="errorStat" hidden' in html
    assert "document.getElementById('infoCount').textContent = sum.informational;" in html
    for f in ("NOTPERM", "NOTSCOPE", "ERROR"):
        assert f'data-filter="{f}"' in html, f
    assert ".status-NOTPERM {" in html and ".status-NOTSCOPE {" in html and ".status-ERROR {" in html
    assert "const classOf = c => c.out_of_scope ? 'NOTSCOPE' : notPermitted.has(c.id) ? 'NOTPERM' : c.status === 'ERROR' ? 'ERROR'" in html
    assert "b.textContent = `${b.dataset.label} (${n})`" in html   # the filters carry their counts
    assert "sit outside it. A 🔧 button means a one-click recipe exists" in html


def test_review_and_remediate_counts_the_remediable_subset_and_ticks_are_not_consent():
    html = _page()
    assert "of ${openCount} open finding" in html and "remediable finding(s)" not in html
    intro = html.split('id="reviewIntro"')[1].split("</p>")[0]
    assert "Ticking a finding only puts it in the walkthrough" in intro and "only when write mode is on" in intro
    assert "'Action required' : 'Needs review'" in html and "${escapeHtml(it.status)}</span>" not in html
    # The existing safeguards stay: preview before Apply, a confirm on a destructive recipe, dry_run false only on Apply.
    assert "document.getElementById('wizardApplyBtn').style.display = 'none';" in html
    assert "if (recipe.destructive && !confirm(" in html and "body.dry_run = false;" in html
    # New: editing a field after the preview hides Apply until the new values are previewed.
    assert "The values changed since the preview. Click Preview again" in html and "fields.dataset.guarded" in html


def test_dashboard_tile_and_guide_say_what_is_remediable():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    dash = c.get("/static/dashboard.js").text
    assert "with a one-click recipe" in dash and "_findRecipeForCheck(c.id)" in dash
    guide = c.get("/static/guide.js").text
    assert "Detailed findings lists every check, grouped by section" in guide and "Critical findings first" not in guide
