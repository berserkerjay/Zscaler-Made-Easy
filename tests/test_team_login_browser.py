"""The Team server page and the sign-in screens in a real browser (node +
headless Chrome over CDP, the harness of tests/test_findings_reflow.py;
skipped without either), on a team server served at http://localhost on an
ephemeral port, with made-up accounts in a temporary store. Nothing is sent
to a tenant or an identity provider; no network beyond loopback.

Run 1 (SAML and passkeys set on the page): the login screen is used by
keyboard only; the Team server page's Sign-in section shows the SAML and
passkey controls to an administrator, a passkey is added with Chrome's
virtual authenticator, SAML is saved from metadata and turned on, and the
login screen then offers "Sign in with SAML" and asks for the passkey after
the password; a viewer sees no administrator controls. Run 2 (SAML set by
the server's settings, passkeys not set up): the SAML form is shown but
locked, "require a passkey" cannot be ticked, and no passkey button shows.
Both runs: labels, help marks, 320px reflow, light and dark themes with AA
contrast, and no script error.

TEAM_SHOTS=<folder> saves screenshots of each state there (off by default)."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest

from test_c6_tooltips import SKIP_REASONS
from test_findings_reflow import CDP_PRELUDE, _chrome
from test_sample_tenant_browser import EVENTS
from test_team_saml import IDP, IDP_CERT, IDP_SSO
from test_team_signin_settings import metadata

ADMIN, ADMIN_PW = "root", "correct horse battery staple"
VIEWER, VIEWER_PW = "vera", "a viewer's own long password"

COMMON = CDP_PRELUDE + "process.env.UI_DEADLINE_MS = process.env.UI_DEADLINE_MS || '300000';\n" + EVENTS + r"""
const [cfgJson, shots] = args;
const cfg = JSON.parse(cfgJson);
const out = { errors: [] };
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 300); } };
const shot = async name => { if (!shots) return; const r = await send('Page.captureScreenshot', { format: 'png' }); fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(r.result.data, 'base64')); };
const frames = () => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
const width = w => send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
const key = async (k, code, vk, text) => { await send('Input.dispatchKeyEvent', Object.assign({ type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk }, text ? { text } : {})); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk }); };
const pressTab = () => key('Tab', 'Tab', 9);
const active = () => ev(`(() => { const a = document.activeElement; return a ? (a.id || a.getAttribute('data-hh-mark') || a.tagName) : null; })()`);
// Tab from the top of the page until `id` has focus; the ids passed on the way.
const tabTo = async (id, max = 60) => { const seenIds = []; for (let i = 0; i < max; i++) { await pressTab(); const a = await active(); seenIds.push(a); if (a === id) return seenIds; } throw new Error('Tab never reached #' + id + ': ' + seenIds.join(' ')); };
const type = text => send('Input.insertText', { text });
const visible = id => ev(`(() => { const e = document.getElementById(${JSON.stringify(id)}); return !!e && !!e.getClientRects().length && !e.closest('[hidden]'); })()`);
// Every visible form control has a name a screen reader reads (a <label>, aria-label or aria-labelledby).
const unlabelled = () => ev(`[...document.querySelectorAll('input:not([type=hidden]), select, textarea')].filter(e => e.getClientRects().length && !e.closest('[hidden]'))
  .filter(e => !(e.labels && e.labels.length) && !e.getAttribute('aria-label') && !e.getAttribute('aria-labelledby')).map(e => e.id || e.name || e.type)`);
// The help audit of tests/test_c6_tooltips.py: each visible control has a catalogue entry and a "?" mark, or a reason it needs none.
const helpAudit = () => ev(`(() => { const H = window.HoverHelp; if (!H) return null; H.scan();
  return H.controls(document).filter(e => H.isVisible(e)).map(el => { const item = H.entryFor(el), mark = H.markOf(el);
    return { c: H.describe(el), key: item ? item.sel : null, mark: !!(mark && mark.getAttribute('data-hh-mark') === 'help'), skip: item ? H.skipReason(el, item) : 'no entry' }; }); })()`);
const reflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
const wide = () => ev(`(() => { const W = document.documentElement.clientWidth; return [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > W + 1 && getComputedStyle(e).position !== 'fixed' && !(e.parentElement && e.parentElement.getBoundingClientRect().right > W + 1); }).map(e => e.tagName + '#' + e.id + '.' + String(e.className).slice(0, 40) + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 10); })()`);
// AA contrast of the page's words against what is behind them (translucent layers blended in order).
const contrast = () => ev(`(() => {
  // rgb()/rgba(), or color(srgb r g b / a) with 0..1 channels (what a color-mix() fill computes to).
  const rgba = s => { s = String(s); let m = s.match(/color\\(srgb ([^)]+)\\)/); if (m) { const v = m[1].split(/[ \\/]+/).filter(Boolean).map(Number); return { r: v[0] * 255, g: v[1] * 255, b: v[2] * 255, a: v.length > 3 ? v[3] : 1 }; }
    m = s.match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const v = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const behind = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let c = { r: 255, g: 255, b: 255, a: 1 }; const root = rgba(getComputedStyle(document.documentElement).backgroundColor); if (root && root.a > 0) c = over(root, c); for (const n of chain.reverse()) { const b = rgba(getComputedStyle(n).backgroundColor); if (b && b.a > 0) c = over(b, c); } return c; };
  return [...document.querySelectorAll('main label, main button, main p, main h2, main h3, main summary, main legend, main td, main th, main .k, main .v, main a, header h1, header p')]
    .filter(e => e.getClientRects().length && !e.closest('[hidden]') && (e.textContent || '').trim() && !e.disabled)
    .map(e => { const bg = behind(e); return { e: (e.id || e.tagName) + ' ' + e.textContent.trim().slice(0, 30), r: Math.round(ratio(over(rgba(getComputedStyle(e).color), bg), bg) * 100) / 100 }; })
    .filter(x => x.r < 4.5);
})()`);
const theme = async (t, url) => { await ev(`(localStorage.setItem('zassess_theme', ${JSON.stringify(t)}), 1)`); await go(url); await settle(url + ' ' + t); return ev(`document.body.classList.contains('theme-light') ? 'light' : 'dark'`); };
// Light and dark, 320px: the reflow and the words below AA on the page as it is now.
const looks = async (name, url, prep) => {
  const res = {};
  for (const t of ['light', 'dark']) {
    res[t] = { theme: await theme(t, url) };
    if (prep) await prep();
    await frames();
    res[t].lowContrast = await contrast();
    await shot(name + '-' + t);
    await width(320); await frames();
    res[t].reflow = await reflow();
    res[t].wide = res[t].reflow > 0 ? await wide() : [];
    await shot(name + '-' + t + '-320');
    await width(1280); await frames();
  }
  return res;
};
const call = (method, url, body) => ev(`fetch(${JSON.stringify(url)}, { method: ${JSON.stringify(method)}, credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: ${body ? JSON.stringify(JSON.stringify(body)) : 'undefined'} }).then(async r => ({ status: r.status, body: await r.json().catch(() => null) }))`);
// Sign in by keyboard only: Tab to the user name, type, Tab to the password, type, Enter.
const keyboardSignIn = async (user, pw) => {
  await go('/login'); await until(() => ev(`!!window.HoverHelp && document.getElementById('lgUser') !== null`), 'the login form');
  await until(() => ev(`document.getElementById('lgMsg').textContent === '' || true`), 'status');
  const path1 = await tabTo('lgUser'); await type(user);
  const path2 = await tabTo('lgPass', 10); await type(pw);
  await key('Enter', 'Enter', 13, '\r');
  return path1.concat(path2);
};
"""

RUN1 = COMMON + r"""
await send('WebAuthn.enable');
await send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

// 1. The login screen, signed out: labels, help, the passkey button (passkeys on), no SAML button (SAML off).
await go('/login'); await until(() => ev(`!!window.HoverHelp`), 'hover help'); await settle('/login');
await safe('loginBefore', async () => ({ passkey: await visible('lgPasskeyBtn'), saml: await visible('lgSamlBtn'), sso: await visible('lgSso'),
  unlabelled: await unlabelled(), help: await helpAudit() }));
await safe('loginLooks', () => looks('login', '/login'));

// 2. The administrator signs in by keyboard; the Team server page.
await safe('adminKeys', () => keyboardSignIn(cfg.admin, cfg.adminPw));
await until(() => ev(`location.pathname === '/'`), 'the app after sign-in', 30000);
await go('/report/team');
await until(() => ev(`!document.getElementById('tmAdmin').hidden && document.querySelectorAll('#tmSamlState .tm-tile').length > 0`), 'the administrator view', 30000);
await settle('/report/team');
await safe('teamAdmin', async () => ({
  signIn: await visible('tmSignInH'), pk: await visible('tmPk'),
  controls: await ev(`['tmSamlMeta', 'tmSamlFile', 'tmSamlIdp', 'tmSamlSso', 'tmSamlCert', 'tmSamlSp', 'tmSamlAcs', 'tmSamlGroups', 'tmSamlSave', 'tmSamlTest', 'tmSamlOn', 'tmReqPk', 'tmPkName', 'tmPkCur', 'tmPkAdd']
    .map(id => { const e = document.getElementById(id); return [id, !!e, !!e && e.disabled]; })`),
  env: await visible('tmSamlEnv'), unlabelled: await unlabelled(), help: await helpAudit(),
  keys: await (async () => { await ev(`(document.activeElement && document.activeElement.blur(), window.scrollTo(0, 0), 1)`); return tabTo('tmPkAdd', 200).then(a => tabTo('tmSamlOn', 200).then(b => tabTo('tmReqPk', 40).then(c => a.concat(b, c)))); })(),
}));
await safe('teamLooks', () => looks('team-admin', '/report/team', () => until(() => ev(`!document.getElementById('tmAdmin').hidden && document.querySelectorAll('#tmSamlState .tm-tile').length > 0`), 'admin view', 30000)));

// 3. Add a passkey (the virtual authenticator answers), save SAML from metadata and turn it on.
await ev(`(document.querySelector('#tmSamlManual').open = true, 1)`);
await ev(`(() => { const s = (id, v) => { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); }; s('tmPkName', 'Test laptop'); s('tmPkCur', ${JSON.stringify(cfg.adminPw)}); document.getElementById('tmPkAdd').click(); return 1; })()`);
await safe('passkeyAdded', () => until(() => ev(`/Test laptop/.test(document.getElementById('tmPkList').textContent) && document.getElementById('tmPkList').textContent`), 'the new passkey', 30000));
await ev(`(() => { const m = document.getElementById('tmSamlMeta'); m.value = ${JSON.stringify(cfg.metadata)}; document.getElementById('tmSamlSave').click(); return 1; })()`);
await until(() => ev(`/saved/.test(document.getElementById('tmStatus').textContent) || document.getElementById('tmStatus').classList.contains('bad')`), 'SAML saved', 30000);
await safe('samlSaved', () => ev(`({ status: document.getElementById('tmStatus').textContent, idp: [...document.querySelectorAll('#tmSamlState .tm-tile')].map(t => t.textContent) })`));
await ev(`(document.getElementById('tmSamlOn').click(), 1)`);
await until(() => ev(`/SAML sign-in is on/.test(document.getElementById('tmStatus').textContent) || document.getElementById('tmStatus').classList.contains('bad')`), 'SAML on', 30000);
await safe('samlOn', () => ev(`({ status: document.getElementById('tmStatus').textContent, button: document.getElementById('tmSamlOn').textContent })`));

// 4. Signed out: the login screen now offers SAML; the password is followed by the passkey step.
await ev(`(document.getElementById('tmSignOut').click(), 1)`);
await until(() => ev(`location.pathname === '/login'`), 'the login page', 30000);
await until(() => ev(`!!window.HoverHelp`), 'hover help'); await settle('/login after');
await safe('loginAfter', async () => ({ saml: await visible('lgSamlBtn'), samlHref: await ev(`document.getElementById('lgSamlBtn').getAttribute('href')`), passkey: await visible('lgPasskeyBtn'), help: await helpAudit() }));
await safe('step2Keys', () => keyboardSignIn(cfg.admin, cfg.adminPw));
await until(() => ev(`!document.getElementById('lgStep2').hidden`), 'the passkey step', 30000);
await safe('step2', async () => ({ focused: await active(), text: await ev(`document.getElementById('lgStep2Text').textContent`), form: await visible('lgForm'),
  session: (await call('GET', '/api/auth/status')).body.unlocked, help: await helpAudit() }));
await shot('login-passkey-step');
await width(320); await frames(); await safe('step2Reflow', reflow); await width(1280);
await key('Enter', 'Enter', 13, '\r');   // the focused "Use my passkey" button, by keyboard
await safe('step2Done', () => until(() => ev(`location.pathname === '/' && 'signed in'`), 'signed in with the passkey', 30000));

// 5. A viewer: no administrator controls on the Team server page.
out.errorsBeforeViewer = seen.errors.slice();
await go('/login');
await ev(`fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }).then(r => r.status)`);
await keyboardSignIn(cfg.viewer, cfg.viewerPw);
await until(() => ev(`location.pathname === '/'`), 'the app for the viewer', 30000);
await go('/report/team'); await until(() => ev(`/vera/.test(document.getElementById('tmMe').textContent)`), 'the viewer view', 30000); await settle('viewer');
await safe('viewer', async () => ({ admin: await visible('tmAdmin'), signIn: await visible('tmSignInH'), saml: await visible('tmSamlSave'), reqPk: await visible('tmReqPk'),
  pk: await visible('tmPk'), unlabelled: await unlabelled(), help: await helpAudit(),
  api: (await call('POST', '/api/team/sign-in', { require_passkey: true })).status }));
await shot('team-viewer');
out.errors = seen.errors.filter(e => !/favicon/.test(e));
fs.writeFileSync(path.join(dir, 'out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'out.json') }));
p.kill();
process.exit(0);
"""

RUN2 = COMMON + r"""
await go('/login'); await until(() => ev(`!!window.HoverHelp`), 'hover help'); await settle('/login');
await safe('login', async () => ({ saml: await visible('lgSamlBtn'), passkey: await visible('lgPasskeyBtn'), unlabelled: await unlabelled(), help: await helpAudit() }));
await keyboardSignIn(cfg.admin, cfg.adminPw);
await until(() => ev(`location.pathname === '/'`), 'the app after sign-in', 30000);
await go('/report/team');
await until(() => ev(`!document.getElementById('tmAdmin').hidden && document.querySelectorAll('#tmSamlState .tm-tile').length > 0`), 'the administrator view', 30000);
await settle('/report/team');
await safe('team', async () => ({
  env: await visible('tmSamlEnv'), pk: await visible('tmPk'),
  disabled: await ev(`[...document.querySelectorAll('#tmSamlForm input, #tmSamlForm textarea, #tmSamlForm button')].map(e => [e.id, e.disabled])`),
  reqPk: await ev(`({ disabled: document.getElementById('tmReqPk').disabled, note: document.getElementById('tmReqPkNote').textContent })`),
  state: await ev(`[...document.querySelectorAll('#tmSamlState .tm-tile')].map(t => t.textContent)`),
  unlabelled: await unlabelled(), help: await helpAudit(),
  api: (await call('POST', '/api/team/sign-in', { saml: { enabled: false } })).status,
}));
await safe('looks', () => looks('team-env', '/report/team', () => until(() => ev(`!document.getElementById('tmAdmin').hidden && document.querySelectorAll('#tmSamlState .tm-tile').length > 0`), 'admin view', 30000)));
out.errors = seen.errors.filter(e => !/favicon/.test(e));
fs.writeFileSync(path.join(dir, 'out.json'), JSON.stringify(out));
console.log(JSON.stringify({ file: path.join(dir, 'out.json') }));
p.kill();
process.exit(0);
"""


def _serve(tmp: Path, env: dict, driver: str, timeout: int = 360) -> dict:
    """The real app as a team server on http://localhost:<free port>
    (passkeys need a host name, not an IP), the driver run against it in
    headless Chrome; the app and the browser are always stopped."""
    chrome, node = _chrome(), shutil.which("node")
    if not chrome or not node:
        pytest.skip("needs node and Chrome/Chromium")
    import uvicorn

    import dlp_api_server as srv
    import sso
    import sso_saml
    import team_passkeys
    import team_server as team
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    base = f"http://localhost:{port}"
    mp = pytest.MonkeyPatch()
    for key, name in (("DLP_CHECK_PROFILES", "profiles.json"), ("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_UI_TOKEN_DIR", ""),
                      ("DLP_CHECK_ZIA_RATE_STATE", "rate.json"), ("DLP_CHECK_TEAM_STORE", "team.json")):
        mp.setenv(key, str(tmp / name) if name else str(tmp))
    (tmp / "profiles.json").write_text("{}")
    for k in [k for k in os.environ if k.startswith("ZSCALER_SAML_") or k in ("ZSCALER_UI_AUTH", "ZSCALER_TEAM_PASSKEY_ORIGIN")]:
        mp.delenv(k, raising=False)
    mp.setenv("ZSCALER_TEAM_MODE", "1")
    mp.setenv("ENABLE_WRITE_ACTIONS", "")
    for k, v in env.items():
        mp.setenv(k, v.replace("{base}", base))
    mp.setattr(srv, "_latest_remote_commit", lambda branch="main": None)
    mp.setattr(team, "SCRYPT_LOG_N", 10)
    import app_update
    mp.setattr(app_update, "update", lambda *a, **k: {"ok": False, "updated": False, "message": "disabled in tests"})
    mp.setattr(app_update, "schedule_restart", lambda *a, **k: {"ok": False, "message": "disabled in tests"})
    for reset in (team._FAILURES.clear, team._IP_ATTEMPTS.clear, sso._SESSIONS.clear, sso_saml.reset, team_passkeys.reset):
        reset()
    team._CACHE.update(key=None, data=None)
    team.create_user(username=ADMIN, role="admin", password=ADMIN_PW)
    team.create_user(username=VIEWER, role="viewer", password=VIEWER_PW)
    server = uvicorn.Server(uvicorn.Config(srv.app, lifespan="off", log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not server.started and time.monotonic() < deadline:
            time.sleep(0.02)   # bounded wait for the socket, not a fixed delay
        assert server.started, "the app did not start"
        cfg = {"admin": ADMIN, "adminPw": ADMIN_PW, "viewer": VIEWER, "viewerPw": VIEWER_PW, "metadata": metadata()}
        (tmp / "drive.mjs").write_text(driver, encoding="utf-8")
        r = subprocess.run([node, str(tmp / "drive.mjs"), chrome, base, str(tmp / "profile"), json.dumps(cfg), os.environ.get("TEAM_SHOTS", "")],
                           capture_output=True, text=True, timeout=timeout)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        sock.close()
        for reset in (sso._SESSIONS.clear, sso_saml.reset, team_passkeys.reset):
            reset()
        team._CACHE.update(key=None, data=None)
        mp.undo()
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(Path(json.loads(r.stdout.strip().splitlines()[-1])["file"]).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def page_set(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("team-page")
    return _serve(tmp, {"ZSCALER_TEAM_PASSKEY_ORIGIN": "{base}"}, RUN1)


@pytest.fixture(scope="module")
def env_set(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("team-env")
    cert = tmp / "idp.pem"
    cert.write_bytes(IDP_CERT)
    return _serve(tmp, {"ZSCALER_SAML_ENABLED": "1", "ZSCALER_SAML_IDP_ENTITY_ID": IDP, "ZSCALER_SAML_IDP_SSO_URL": IDP_SSO,
                        "ZSCALER_SAML_IDP_CERT_FILE": str(cert), "ZSCALER_SAML_SP_ENTITY_ID": "{base}/api/auth/saml/metadata",
                        "ZSCALER_SAML_ACS_URL": "{base}/api/auth/saml/acs"}, RUN2)


def _no_err(*vals):
    bad = [v for v in vals if isinstance(v, str) and v.startswith("ERR ")]
    assert not bad, bad


def _help_gaps(audit):
    assert isinstance(audit, list) and audit, audit
    missing = [a["c"] for a in audit if not a["key"]]
    unmarked = [f"{a['c']}: {a['skip']}" for a in audit if a["key"] and not a["mark"] and a["skip"] not in SKIP_REASONS]
    return missing + unmarked


def test_the_login_screen_is_labelled_helped_and_offers_a_passkey_but_no_saml_until_it_is_on(page_set):
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · SC 4.1.2 · ASVS V2.1.1: every field has a label and every control a help entry with its mark; with passkeys set up the passkey button shows; SAML is not offered while it is off."""
    b = page_set["loginBefore"]
    _no_err(b)
    assert b["passkey"] is True and b["saml"] is False and b["sso"] is False
    assert b["unlabelled"] == [] and _help_gaps(b["help"]) == []


def test_the_login_screen_works_by_keyboard_alone(page_set):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3 · SC 2.4.7: Tab reaches the user name and then the password, and Enter signs in (the app opens)."""
    keys = page_set["adminKeys"]
    _no_err(keys)
    assert "lgUser" in keys and "lgPass" in keys and keys.index("lgUser") < keys.index("lgPass")


@pytest.mark.parametrize("which", ["loginLooks", "teamLooks"])
def test_both_themes_keep_aa_contrast_and_reflow_at_320px(page_set, which):
    """WCAG 2.2 SC 1.4.3 · SC 1.4.10 · SC 1.4.11: the login screen and the Team server page (administrator view) in light and dark: every visible word keeps AA contrast and nothing scrolls sideways at 320px."""
    looks = page_set[which]
    _no_err(looks)
    assert looks["light"]["theme"] == "light" and looks["dark"]["theme"] == "dark"
    for t in ("light", "dark"):
        assert looks[t]["lowContrast"] == [], (t, looks[t]["lowContrast"][:10])
        assert looks[t]["reflow"] <= 0, (t, looks[t]["reflow"], looks[t]["wide"])


def test_the_administrator_sees_the_sign_in_section_with_saml_and_passkey_controls_open(page_set):
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · ASVS V1.14.1 · ASVS V2.1.1: the Sign-in section shows the SAML form (metadata, file, manual values, this server's values, groups, Save, Test, Turn on) and the passkey controls, all enabled; every field is labelled and every control has help."""
    a = page_set["teamAdmin"]
    _no_err(a)
    assert a["signIn"] is True and a["pk"] is True and a["env"] is False
    assert all(present and not disabled for _id, present, disabled in a["controls"]), a["controls"]
    assert a["unlabelled"] == [] and _help_gaps(a["help"]) == []


def test_the_sign_in_controls_are_reached_by_keyboard(page_set):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3: Tab reaches Add a passkey, Turn SAML sign-in on and Require a passkey."""
    keys = page_set["teamAdmin"]["keys"]
    _no_err(keys)
    assert {"tmPkAdd", "tmSamlOn", "tmReqPk"} <= set(keys), keys[-20:]


def test_a_passkey_is_added_and_saml_is_saved_and_turned_on_from_the_page(page_set):
    """ASVS V2.1.1 · ASVS V2.8.1 · CWE-308: a passkey added from the page (a virtual authenticator) is listed; SAML saved from the identity provider's metadata shows its entity ID and turns on."""
    _no_err(page_set["passkeyAdded"], page_set["samlSaved"], page_set["samlOn"])
    assert "Test laptop" in page_set["passkeyAdded"]
    assert "saved" in page_set["samlSaved"]["status"] and any(IDP in t for t in page_set["samlSaved"]["idp"])
    assert "on" in page_set["samlOn"]["status"] and page_set["samlOn"]["button"] == "Turn SAML sign-in off"


def test_with_saml_on_the_login_screen_offers_it_and_a_password_is_followed_by_the_passkey(page_set):
    """ASVS V2.1.1 · ASVS V2.8.1 · CWE-308 · WCAG 2.2 SC 2.4.3: once SAML is on, the login screen offers Sign in with SAML; the password of an account with a passkey gives no session yet, focus moves to Use my passkey, and Enter on it signs in."""
    after, step2 = page_set["loginAfter"], page_set["step2"]
    _no_err(after, step2, page_set["step2Done"])
    assert after["saml"] is True and after["samlHref"] == "/api/auth/saml/login" and _help_gaps(after["help"]) == []
    assert step2["focused"] == "lgPkGo" and step2["form"] is False and step2["session"] is not True
    assert "passkey" in step2["text"] and _help_gaps(step2["help"]) == []
    assert page_set["step2Reflow"] <= 0 and page_set["step2Done"] == "signed in"


def test_a_viewer_gets_no_sign_in_settings(page_set):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: a viewer's Team server page has no Accounts or Sign-in section, and the sign-in settings route refuses them."""
    v = page_set["viewer"]
    _no_err(v)
    assert v["admin"] is False and v["signIn"] is False and v["saml"] is False and v["reqPk"] is False
    assert v["api"] == 403 and v["unlabelled"] == [] and _help_gaps(v["help"]) == []


def test_saml_set_by_the_servers_settings_is_shown_but_locked_and_passkeys_cannot_be_required(env_set):
    """ASVS V14.1.1 · ASVS V1.14.1 · CWE-284 · WCAG 2.2 SC 3.3.2: SAML from the server's settings is offered on the login screen; on the Team server page its form is locked (only Test stays) with a note saying why; with passkeys not set up, Require a passkey is disabled and says why, and no passkey control shows."""
    login, t = env_set["login"], env_set["team"]
    _no_err(login, t)
    assert login["saml"] is True and login["passkey"] is False and _help_gaps(login["help"]) == []
    assert t["env"] is True and t["pk"] is False
    assert all(dis for i, dis in t["disabled"] if i != "tmSamlTest") and dict(t["disabled"]).get("tmSamlTest") is False, t["disabled"]
    assert t["reqPk"]["disabled"] is True and "not set up" in t["reqPk"]["note"]
    assert t["api"] == 400 and t["unlabelled"] == [] and _help_gaps(t["help"]) == []
    looks = env_set["looks"]
    _no_err(looks)
    for th in ("light", "dark"):
        assert looks[th]["lowContrast"] == [] and looks[th]["reflow"] <= 0, (th, looks[th])


def test_no_script_errors_on_the_way(page_set, env_set):
    """WCAG 2.2 SC 4.1.2 · ASVS V14.1.1: no script error and no failed request on either run, other than the expected refusals."""
    allowed = ("/api/team/sign-in",)   # the viewer's 403 and the environment's 400 are asserted above
    for run in (page_set, env_set):
        errs = [e for e in run["errors"] if not any(a in e for a in allowed)]
        assert not errs, errs
