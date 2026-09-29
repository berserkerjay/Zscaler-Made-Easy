"""One symbol set (HIG stage 3): static/icons.js draws every icon as an
inline SVG on a 24-point grid in currentColor, bundled (offline), loaded
first on the assessment page and on every report page; the emoji stay in
the markup as the readable fallback and are swapped at run time."""
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _c():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_the_symbol_set_is_served_bundled_and_loaded_first():
    c = _c()
    js = c.get("/static/icons.js")
    assert js.status_code == 200 and "window.dlpIcon = " in js.text and "window.dlpIconize = " in js.text
    assert 'viewBox="0 0 24 24" fill="none" stroke="currentColor"' in js.text and "http" not in js.text.split("(function")[1][:400]
    # Every emoji the pages use as an icon has a symbol, and every symbol named has a path.
    body = js.text
    emoji_map = body.split("const EMOJI = {")[1].split("};")[0] + body.split("Object.assign(EMOJI, {")[1].split("});")[0]
    names = set(re.findall(r"'([a-z0-9-]+)'", emoji_map))
    paths = set(re.findall(r"^\s+'([a-z0-9-]+)': 'M", body, re.M))
    assert names and names <= paths, sorted(names - paths)
    html = c.get("/").text
    srcs = re.findall(r'<script src="/static/([a-z_]+\.js)\?v=\d+"></script>', html)
    assert srcs[0] == "icons.js", srcs
    for page in ("/report/digest", "/report/advanced", "/report/compliance", "/help", "/report/logs"):
        assert '<script src="/static/icons.js"></script>' in c.get(page).text, page


def test_dashboard_draws_section_and_row_icons_from_the_set():
    c = _c()
    js = c.get("/static/dashboard.js").text
    assert "[/ssl|tls/i, 'lock', '🔒']" in js and "window.dlpIcon(sym)" in js
    assert "row.dataset.ico = '';" in js and 'class="db-row-ico" aria-hidden="true"' in js and "row.dataset.decorated" in js
    css = c.get("/static/dashboard.css").text
    assert '.db-rows .check-item[data-ico=""]::before { display: none; }' in css and ".db-row-ico {" in css
