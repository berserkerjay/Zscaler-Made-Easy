"""App-wide safety banner: while write mode is on, or the UI token gate is
off, every page of the app says so at the top (static/safety_banner.js).
Write mode gets a "Back to read-only" button that uses the existing
/api/write-mode switch; the gate warning says which setting turns it
back on. Deploy Studio and Advanced settings show those states as
warnings (amber), never as a green "ok"."""
import os
import re
import shutil
import subprocess

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TAG = '<script src="/static/safety_banner.js"></script>'


def _read(name):
    return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()


def _client():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_the_banner_script_says_both_warnings_in_plain_words():
    js = _read("safety_banner.js")
    assert "Write mode is on: this app can change your Zscaler tenant." in js
    assert "The UI token gate is off: anyone who can reach this address can use the app." in js
    assert "'Back to read-only'" in js
    # The gate warning says how to turn it back on, with the real setting name
    # (security.ui_auth_enabled reads ZSCALER_UI_AUTH; 0/false/no/off turn it off).
    assert "ZSCALER_UI_AUTH=0" in js and "ZSCALER_UI_AUTH=1" in js and "restart" in js
    assert 'os.environ.get("ZSCALER_UI_AUTH", "1")' in open(os.path.join(ROOT, "security.py"), encoding="utf-8").read()


def test_the_banner_reads_the_existing_status_endpoints_and_turns_write_mode_off_through_the_api():
    js = _read("safety_banner.js")
    assert "getJson('/api/auth/status')" in js and "getJson('/api/write-mode')" in js
    assert "a.required === false" in js and "w && w.enabled" in js
    # A locked page does not ask for write mode (which would pop the unlock dialog every poll).
    assert "if (auth && (!auth.required || auth.unlocked))" in js
    off = js.split("async function backToReadOnly()")[1].split("\n  }\n")[0]
    assert "fetch('/api/write-mode', { method: 'POST'" in off and "JSON.stringify({ enable: false, confirm: '' })" in off
    assert "if (!r.ok) throw new Error(" in off and "state.write = data;" in off and "render();" in off
    assert "Could not switch back to read-only: " in off


def test_the_banner_refreshes_on_load_on_change_in_other_tabs_and_every_minute():
    js = _read("safety_banner.js")
    assert "const POLL_MS = 60000;" in js and "setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);" in js
    assert "document.addEventListener('DOMContentLoaded', refresh)" in js
    assert "window.addEventListener('dlp:write-mode'" in js
    assert "window.addEventListener('storage', e => { if (e.key === PING_KEY) refresh(); });" in js
    assert "document.addEventListener('visibilitychange'" in js


def test_the_banner_never_renders_server_text_as_html():
    js = _read("safety_banner.js")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML" not in js
    assert "n.textContent = String(text)" in js
    assert "msg.textContent = 'Could not switch back to read-only: ' + String(" in js


def test_the_banner_pushes_the_page_down_fits_both_themes_and_phones():
    js = _read("safety_banner.js")
    # In the flow at the top of <body>, never fixed over the content.
    assert "document.body.insertBefore(el, document.body.firstChild);" in js
    css = js.split("const CSS = `")[1].split("`;")[0]
    assert "position: fixed" not in css and "position: absolute" not in css and "position: sticky" not in css
    # The app's own tokens (redefined by body.theme-light), including the warning colour.
    assert "var(--warn" in css and "var(--text" in css and "var(--card-solid" in css
    assert not re.search(r":\s*#[0-9a-fA-F]{3,6}\s*;", css), "colours come from the theme tokens (hex only as fallbacks)"
    # Beside the assessment page's fixed sidebar, and clear of its Menu button on small screens.
    assert "body.db-layout #dlpSafetyBanner { margin-left: var(--db-w, 264px); }" in css
    assert "@media (max-width: 1000px)" in css and "@media (max-width: 480px)" in css
    assert "flex-wrap: wrap" in css and "overflow-wrap: anywhere" in css
    assert "role', 'region'" in js and "setAttribute('role', 'alert')" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_the_banner_script_parses():
    r = subprocess.run(["node", "--check", os.path.join(ROOT, "static", "safety_banner.js")], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_every_page_of_the_app_loads_the_banner():
    pages = [n for n in os.listdir(os.path.join(ROOT, "static")) if n.endswith(".html")]
    assert "index.html" in pages and "report_advanced.html" in pages and "report_flow.html" in pages
    for name in pages:
        assert _read(name).count(TAG) == 1, name
    c = _client()
    for path in ("/", "/help", "/report/advanced", "/report/flow", "/report/deploy-flow", "/report/view", "/report/digest",
                 "/report/logs", "/report/compliance", "/report/vendor", "/report/health", "/report/evalall"):
        r = c.get(path)
        assert r.status_code == 200 and TAG in r.text, path
    assert c.get("/static/safety_banner.js").status_code == 200


def test_the_report_pages_load_the_banner_after_the_shared_auth_scripts():
    for name in os.listdir(os.path.join(ROOT, "static")):
        if not name.endswith(".html"):
            continue
        html = _read(name)
        if '<script src="/static/report_theme.js"></script>' in html:
            assert html.index('<script src="/static/report_theme.js"></script>') < html.index(TAG), name


def test_deploy_studio_shows_write_mode_as_a_warning_and_tells_the_banner():
    js = _read("deploy_studio.js")
    banner = js.split("function _dzWriteBanner()")[1].split("function _dzGatesHtml")[0]
    assert '<div class="dz-write on"><span class="dz-status warnings">Write mode</span>' in banner
    assert 'dz-status ready">Write mode' not in js
    gates = js.split("function _dzGatesHtml")[1].split("function _dzUntickedChannels")[0]
    assert "if (w.enabled) gates.push({ ok: false, warn: true, text: 'Write mode is on for this server" in gates
    css = _read("deploy_studio.css")
    assert ".dz-write.on { border-left: 3px solid var(--warn); }" in css and ".dz-write.on { border-left: 3px solid var(--pass); }" not in css
    # A switch made in the Studio reaches the banner at once; one made from the banner reaches the Studio.
    setter = js.split("async function _dzSetWriteMode(enable)")[1].split("function _dzWriteBanner()")[0]
    assert "window.dispatchEvent(new CustomEvent('dlp:write-mode', { detail: { from: 'studio', status: data } }))" in setter
    assert "window.addEventListener('dlp:write-mode', e => {" in js and "e.detail.from !== 'banner'" in js


def test_advanced_settings_shows_the_token_gate_off_as_a_warning():
    js = _read("advanced.js")
    row = [l for l in js.splitlines() if "['UI token gate'" in l][0]
    assert '<span class="chip warn">Off</span>' in row and '<span class="chip">Off</span>' not in row
    assert "anyone who can reach this address can use the app" in row and "ZSCALER_UI_AUTH=1" in row


def test_the_status_the_banner_reads_matches_the_server(monkeypatch):
    """The two facts the banner relies on: /api/auth/status says required:false
    when ZSCALER_UI_AUTH=0, and POST /api/write-mode {enable:false} turns
    write mode off whatever turned it on."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    c = TestClient(srv.app)
    assert c.get("/api/auth/status").json()["required"] is False
    monkeypatch.setenv("ENABLE_WRITE_ACTIONS", security.WRITE_CONFIRM_PHRASE)
    monkeypatch.setattr(security, "_write_override", None)
    assert c.get("/api/write-mode").json()["enabled"] is True
    out = c.post("/api/write-mode", json={"enable": False, "confirm": ""})
    assert out.status_code == 200 and out.json()["enabled"] is False
    assert c.get("/api/write-mode").json()["enabled"] is False
