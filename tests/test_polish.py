"""Visual polish and accessibility (UI/UX stage 6): bars are the primary
section view and the radar the optional expanded one; nothing floats over
the content; keyboard focus is visible; links that act are buttons; modals
give focus back; contrast tokens; landmarks and headings; 960px layout."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _c():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_bars_first_radar_expanded_and_no_null_percent():
    js = _c().get("/static/dashboard.js").text
    assert 'class="db-secbars" aria-label="Score by section"' in js and "Score by section<button" in js
    assert "btn.disabled = measuredNames(sections).length < 3" in js   # a radar needs a shape to read
    assert "filter(k => sections[k] && sections[k].pct !== null && sections[k].pct !== undefined)" in js   # unmeasured sections are not plotted
    assert "'Not measured'}</td></tr>" in js and "${d.pct}%</td></tr>" not in js
    # The expanded view and its literals stay.
    assert "function openRadarModal()" in js and "radarSvg(lastSections, { R: 220" in js and "dbRadarTbl" in js
    css = _c().get("/static/dashboard.css").text
    assert ".db-secbars li {" in css and "h3.db-tile-t {" in css


def test_nothing_floats_over_the_content_and_the_narrow_menu_is_reachable():
    js = _c().get("/static/dashboard.js").text
    css = _c().get("/static/dashboard.css").text
    assert "brand.appendChild(fab)" in js and "#dbSidebar #gdHelpFab { position: static !important;" in css
    assert "body.db-layout #gdHelpFab { left:" not in css and "body.db-has-footer #gdHelpFab" not in css
    assert "#dbSidebar { transform: translateX(-100%); visibility: hidden;" in css and "body.db-open #dbBackdrop { display: block; }" in css
    assert "backdrop.id = 'dbBackdrop'" in js and "e.key === 'Escape' && document.body.classList.contains('db-open')" in js
    assert "menu.innerHTML = '<span aria-hidden=\"true\">☰</span> Menu'" in js
    assert "@media (max-width: 1250px) { .db-grid { grid-template-columns: 1fr 1fr; }" in css
    html = _c().get("/").text
    assert "@media (max-width: 1000px) { .stats { grid-template-columns: repeat(2, 1fr); } }" in html


def test_keyboard_focus_is_visible_and_actions_are_buttons_that_give_focus_back():
    c = _c()
    html = c.get("/").text
    field = html.split(".field input:focus, .field select:focus {")[1].split("}")[0]
    assert "outline: none" not in field
    assert ".field input:focus-visible, .field select:focus-visible { outline: 3px solid var(--accent-hover); outline-offset: 2px; }" in html
    assert '<button type="button" class="link-btn" onclick="toggleFrameworks(true)"' in html and '<a onclick="toggleFrameworks' not in html
    wiz = html.split("function closeWizard()")[1].split("\n}\n")[0]
    assert "_lastFocus.focus()" in wiz
    ds = c.get("/static/deploy_studio.js").text
    assert "DZ._opener = document.activeElement" in ds and "const o = DZ._opener; DZ._opener = null;" in ds
    guide = c.get("/static/guide.js").text
    assert "GD._migrateOpener = document.activeElement" in guide and "const o = GD._migrateOpener; GD._migrateOpener = null;" in guide


def test_contrast_tokens_landmarks_and_headings():
    c = _c()
    html = c.get("/").text
    assert "--info: #94a3b8;" in html and "--info: #64748b" not in html
    assert "linear-gradient(135deg,#f59e0b,#ef4444)" not in html and "linear-gradient(135deg, #f59e0b, #ef4444)" not in html
    assert "linear-gradient(135deg,#b45309,#b91c1c)" in html and "linear-gradient(135deg, #b45309, #b91c1c)" in html
    assert ".field input::placeholder { color: var(--dim); opacity: 0.8; }" in html
    assert "body.theme-light #zccDiagModal > div" in html
    assert 'role="document"' not in html and '<div id="results" role="region" aria-label="Assessment results">' in html
    assert '<span aria-hidden="true">🔧</span> Review &amp; Remediate' in html and '<span aria-hidden="true">📄</span> Export All (CSV)' in html
    js = c.get("/static/dashboard.js").text
    assert js.count('<h3 class="db-tile-t"') + js.count('<h3 class="db-tile-t db-tile-t-row"') == 5
    assert "heroCard.setAttribute('role', 'region')" in js
    css = c.get("/static/dashboard.css").text
    assert ".db-chip.risk-warn-strong { background: rgba(245,158,11,0.2); color: var(--warn); }" in css
    theme = c.get("/static/report_theme.js").text
    assert "background:var(--card-solid, rgba(15,23,42,0.85))" in theme
