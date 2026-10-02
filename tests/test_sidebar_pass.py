"""The sidebar walk-through (every page opened one at a time, both themes)
found four defects; these pins keep them fixed."""
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_report_tabs_get_a_sentence_never_object_object():
    """The data-flow, bypass and SSL-flow generators throw the server's
    {cause, fix} detail as text, so the tab's error box reads as a
    sentence instead of "[object Object]"."""
    html = _page().get("/").text
    assert "function _reportErrorText(data, status)" in html
    assert html.count("throw new Error(_reportErrorText(data, resp.status))") == 3
    assert "throw new Error((data && data.detail) || `Error ${resp.status}`)" not in html


def test_native_dialog_is_centred_despite_the_global_margin_reset():
    """`* { margin: 0 }` in app.css cancels the UA's `dialog { margin: auto }`,
    which anchored every notice at the top-left corner."""
    ua = _page().get("/static/ui_auth.js").text
    assert "dialog.dlp-dlg { margin: auto;" in ua


def test_scope_select_all_is_a_checkbox_not_a_text_field():
    css = _page().get("/static/reports.css").text
    assert '.df-ctl input:not([type="checkbox"]):not([type="radio"]), .df-ctl select {' in css
    assert '.df-ctl input[type="checkbox"], .df-ctl input[type="radio"] { width: 18px; height: 18px; min-height: 0;' in css


def test_reference_back_link_has_its_own_colour_and_sits_bottom_left():
    """The framework reference pages define none of the app's tokens, so
    the injected link needs a literal fallback, and their brand sits
    top-left where the link used to cover it."""
    theme = _page().get("/static/report_theme.js").text
    assert "background:var(--accent, #0a84ff)" in theme and "bottom:0.9rem;left:0.9rem" in theme
    assert "top:0.6rem;left:0.6rem" not in theme
