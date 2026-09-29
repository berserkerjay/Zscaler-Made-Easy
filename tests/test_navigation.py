"""One navigation model (UI/UX stage 2): every "Run assessment" runs on
the page, the no-results path is inline, the last result survives a
reload of its tab, labels do not collide, and report intros fold."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_every_run_assessment_button_runs_on_the_page():
    c = _page()
    guide = c.get("/static/guide.js").text
    dash = c.get("/static/dashboard.js").text
    html = c.get("/").text
    # The guide's steps 2 and 7 and the step strip funnel into the sidebar's runner (sign-in first, then run here).
    assert "window.__dbRunFromSidebar()" in guide and "openToolTab('results', 'run')" not in guide
    assert "window.__dbRunFromSidebar = runFromSidebar" in dash and "runAssessment();" in dash
    assert "alert('An assessment is already running.')" not in guide
    assert 'run the assessment on this page from there"' in html, "the step strip's Scope assessment step says the run happens on this page"
    # The mirrored tab stays as the explicit opt-in on the results.
    assert "openToolTab('results', 'view')" in html and "Open in new tab" in html


def test_findings_without_results_is_an_inline_note_not_an_alert():
    c = _page()
    html = c.get("/").text
    body = html.split("function _stepGo(step)")[1].split("function setStep(")[0]
    assert "alert(" not in body and "window.__dbNote" in body and "No results in this tab yet" in body
    assert "_stepGo('run')" not in body.split("if (step === 'review')")[1], "nothing starts by itself"
    assert "window.__dbNote = note" in c.get("/static/dashboard.js").text


def test_the_last_result_survives_a_reload_of_its_tab():
    c = _page()
    html = c.get("/").text
    assert "const RESULTS_KEY = 'zassess_last_results'" in html and "sessionStorage.setItem(RESULTS_KEY" in html
    assert "function restoreResults()" in html and "data.__restored = true" in html and "'Restored from this tab · '" in html
    assert "if (!restored) rememberResults(data);" in html and "if (!restored) window.scrollTo" in html
    assert "forgetResults();" in html.split("function resetForm()")[1].split("}")[0]
    assert "localStorage.setItem(RESULTS_KEY" not in html, "this tab only, never shared across tabs"


def test_labels_say_what_they_open_and_no_icon_is_used_twice():
    c = _page()
    html = c.get("/").text
    assert "Rule migration wizard" in html and "How Evaluate All Rules decides" in html
    assert "Zscaler SDK &amp; docs updates" in html and ">Zscaler Updates<" not in html
    assert "New assessment (clears results)" in html and "Run Another Assessment" not in html
    dash = c.get("/static/dashboard.js").text
    assert "'Start a new assessment', 'clears these results, then run again'" in dash
    assert "setCurrent('review');" in dash.split("function renderDashboard(data)")[1].split("window.__dbRunStarted")[0]
    guide = c.get("/static/guide.js").text
    assert "Choose a scope in Tenant Configuration" not in guide and "Journey card (Deploy policy packs)" in guide
    toolbar = html.split('<div class="hero-toolbar"')[1].split("</div>\n  </div>")[0]
    icons = []
    for line in toolbar.splitlines():
        if '<span aria-hidden="true">' in line and "</span> " in line:
            icons.append(line.split('<span aria-hidden="true">')[1].split("</span>")[0])
    assert len(icons) >= 18 and len(icons) == len(set(icons)), sorted(i for i in icons if icons.count(i) > 1)


def test_report_intros_fold_to_the_first_sentence_and_the_digest_link_is_not_dead():
    c = _page()
    theme = c.get("/static/report_theme.js").text
    assert "function fold()" in theme and "rpHeroMore" in theme and "aria-expanded" in theme and "btn.type = 'button'" in theme
    digest = c.get("/report/digest").text
    assert 'id="dgHealth"' in digest and 'href="/report/health" target="_blank"' not in digest
    assert "o.openDetectionHealthTab()" in digest and "window.__dlpGoHome" in digest
