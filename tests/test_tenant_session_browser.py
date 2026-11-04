"""The owner's bug in a real browser: sign in on the expert page, then
choose Simple mode. Before the fix Simple mode had no credentials and the
assessment failed; now it says "Connected to <tenant>" and runs. Then Sign
out of tenant on the expert page, and Simple mode is no longer connected.

The app runs in-process on a loopback port (tests/test_findings_reflow.py
run_in_browser), the sign-in and the assessment client are fakes; skips
without node or Chrome."""
from __future__ import annotations

import json

import pytest

import dlp_api_server as srv
from dlp_assessment_full_auto import R
from test_findings_reflow import CDP_PRELUDE, run_in_browser

SECRET = "CANARYbrowser+/=Q7x9Zk2"
ACME = {"auth_method": "oneapi", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclient0001", "client_secret": SECRET}

DRIVER = CDP_PRELUDE + r"""
process.on('exit', () => { try { p.kill(); } catch (e) { /* gone */ } });
const deadline = setTimeout(() => { try { p.kill(); } catch (e) { /* gone */ } process.exit(3); }, 150000);
const [credsJson] = args;
const errors = [];
const _onmsg = ws.onmessage;
ws.onmessage = e => { _onmsg(e); const m = JSON.parse(e.data); if (m.id) return;
  if (m.method === 'Runtime.exceptionThrown') errors.push('exception: ' + String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200));
  if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') errors.push('console: ' + m.params.args.map(a => a.value || a.description || '').join(' ').slice(0, 200));
  if (m.method === 'Network.responseReceived' && m.params.response.status >= 400 && m.params.response.url.startsWith(base)) errors.push(m.params.response.status + ' ' + m.params.response.url.slice(base.length));
};
await send('Network.enable');
const go = async url => { await send('Page.navigate', { url: base + url }); await until(() => ev(`document.readyState === 'complete'`), url + ' load'); };
const out = {};
// 1. The expert page: Authenticate (the same POST the button sends).
await go('/');
await ev(`(localStorage.setItem('zsimple_mode', 'expert'), true)`);
out.check = await ev(`fetch('/api/tenant/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(${credsJson}) }).then(r => r.status)`);
await go('/');
out.expert = await until(() => ev(`(() => { const s = document.getElementById('authStatus'), b = document.getElementById('authSignOutBtn');
  return s && /Signed in to acme/.test(s.textContent) ? { status: s.textContent, signOutShown: !b.hidden } : null; })()`), 'the expert page connected state');
// The guide redraws every 2.5 s and after its profiles load: run exactly
// what its timer runs, then read the status again (it must still be there).
out.expertKept = await ev(`(async () => { for (let i = 0; i < 3; i++) { if (typeof _gdRender === 'function') _gdRender(); if (typeof _gdAuthStatus === 'function') _gdAuthStatus(); }
  if (typeof _gdProfilesLoad === 'function') await _gdProfilesLoad(); if (typeof _gdRender === 'function') _gdRender();
  return { guide: typeof _gdRender === 'function', status: document.getElementById('authStatus').textContent }; })()`);
// 2. Simple mode: connected, and the check runs without asking for anything.
await go('/simple#check');
out.simpleConn = await until(() => ev(`(() => { const t = (document.getElementById('smConn') || {}).textContent || ''; return /Connected to/.test(t) ? t : null; })()`), 'Connected to');
const next = () => ev(`(() => { const b = document.getElementById('smNext'); if (!b || b.disabled) return false; b.click(); return true; })()`);
await until(() => ev(`!!document.getElementById('smNext') && !/First, connect/.test(document.getElementById('smStepBody').textContent)`), 'the connected step');
await until(next, 'Next (connected)');
await until(() => ev(`!!document.querySelector('input[name="smCh"]')`), 'the channel step');
await until(next, 'Next (channels)');
await until(() => ev(`!!document.getElementById('smRun')`), 'the run step');
await until(next, 'Check now');
out.result = await until(() => ev(`(() => { const d = document.getElementById('smDone'); const e = document.getElementById('smErr'); if (e && e.textContent.trim()) return { error: e.textContent }; return d ? { done: true, body: document.getElementById('smStepBody').textContent.slice(0, 200) } : null; })()`), 'the result', 30000);
out.storage = await ev(`JSON.stringify(Object.assign({}, localStorage)) + JSON.stringify(Object.assign({}, sessionStorage)) + document.cookie`);
// 3. Sign out of tenant on the expert page: Simple mode is no longer connected.
await go('/');
await until(() => ev(`(() => { const b = document.getElementById('authSignOutBtn'); return b && !b.hidden; })()`), 'the sign-out button');
await ev(`signOutTenant().then(() => true)`);
out.signedOut = await until(() => ev(`(() => { const s = document.getElementById('authStatus'); return /Signed out of the tenant/.test(s.textContent) && document.getElementById('authSignOutBtn').hidden ? s.textContent : null; })()`), 'signed out');
await go('/simple#check');
out.after = await until(() => ev(`(() => { const b = document.getElementById('smStepBody'); return b && /First, connect/.test(b.textContent) ? document.getElementById('smConn').textContent : null; })()`), 'not connected');
out.errors = errors;
console.log(JSON.stringify(out));
clearTimeout(deadline); ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def journey(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    seen = {"assessed": []}

    class Raw:
        def auth(self):
            return True

        def get(self, endpoint, *a, **k):
            return [], 200

        def close(self):
            pass

    def raw(creds):
        seen["assessed"].append(dict(srv._validate_creds(creds)))
        return Raw()

    mp.setattr(srv, "_build_sdk_client", lambda creds: (srv._validate_creds(creds), object())[1])
    mp.setattr(srv, "_raw_client", raw)
    mp.setattr(srv, "_readiness_token_access", lambda client, method: {})
    mp.setattr(srv, "_close_quietly", lambda client: None)
    mp.setattr(srv, "_get_checks", lambda scope, scopes: [("DLP.1", "DLP", "Check 1", lambda c: R(R.FAIL, "not set"))])
    mp.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    tmp = tmp_path_factory.mktemp("signed-in")
    mp.setattr(srv, "_APP_DIR", str(tmp))
    try:
        out = run_in_browser(tmp, DRIVER, json.dumps(ACME), timeout=170)
    finally:
        mp.undo()
    out["assessed"] = seen["assessed"]
    return out


def test_simple_mode_after_authenticate_proceeds_without_the_sign_in_details(journey):
    """ASVS V3.2.1 · CWE-287 · WSTG-SESS-01 · WCAG 2.2 SC 3.3.7: after Authenticate, Simple mode says Connected and its check runs to the result, signed in with the remembered tenant."""
    assert journey["check"] == 200
    assert "acme (zscalerten)" in journey["simpleConn"], journey["simpleConn"]
    assert journey["result"].get("done"), journey["result"]
    assert [c["vanity_domain"] for c in journey["assessed"]] == ["acme"]
    assert journey["errors"] == [], journey["errors"]


def test_the_expert_page_shows_the_signed_in_tenant_and_signs_out(journey):
    """ASVS V3.3.1 · CWE-613 · WSTG-SESS-06 · WCAG 2.2 SC 4.1.3: the expert page says it is signed in, offers Sign out of tenant, and after it Simple mode is not connected."""
    assert journey["expert"]["signOutShown"] is True
    assert "Signed out of the tenant" in journey["signedOut"]
    assert "Not connected yet" in journey["after"]


def test_the_expert_pages_signed_in_state_stays_while_the_guide_redraws(journey):
    """ASVS V3.3.1 · CWE-665 · WSTG-SESS-06 · WCAG 2.2 SC 4.1.3: the guide's redraws (every 2.5 s, and after its profiles load) leave "Signed in to <tenant>" in place."""
    assert journey["expertKept"]["guide"] is True
    assert "Signed in to acme" in journey["expertKept"]["status"], journey["expertKept"]


def test_the_browser_keeps_no_secret(journey):
    """ASVS V8.2.2 · CWE-922 · WSTG-CLNT-12: no browser storage or script-readable cookie holds the secret."""
    assert SECRET not in journey["storage"]


# ── Simple mode: adopting the guide's tenant profile, and a sign-in that ended ──

ENDED_DRIVER = CDP_PRELUDE + r"""
process.on('exit', () => { try { p.kill(); } catch (e) { /* gone */ } });
const deadline = setTimeout(() => { try { p.kill(); } catch (e) { /* gone */ } process.exit(3); }, 150000);
const [credsJson, clockFile] = args;
const go = async url => { await send('Page.navigate', { url: base + url }); await until(() => ev(`document.readyState === 'complete'`), url + ' load'); };
// A fresh load of Simple mode (navigating to the same URL with its #hash would not reload it).
const simple = async () => { await go('/'); await go('/simple#check'); };
const conn = re => until(() => ev(`(() => { const t = (document.getElementById('smConn') || {}).textContent || ''; return ${re}.test(t) ? t : null; })()`), String(re));
const next = () => ev(`(() => { const b = document.getElementById('smNext'); if (!b || b.disabled) return false; b.click(); return true; })()`);
const out = {};
// 1. Nothing signed in: Simple mode adopts the tenant profile the guide picked (zassess_profile).
await go('/');
const prof = await ev(`fetch('/api/tenant-profiles', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Bolt profile', cloud: 'zscalerten', vanity_domain: 'bolt', client_id: 'boltclient0001' }) }).then(r => r.json())`);
await ev(`(localStorage.setItem('zassess_profile', ${JSON.stringify(prof.id)}), localStorage.removeItem('zsimple_conn'), true)`);
await simple();
out.adopted = await conn('/Connected to Bolt profile/');
// 2. Authenticate (the expert page's POST); with no profile of its own, Simple mode uses that sign-in.
await ev(`(localStorage.removeItem('zassess_profile'), localStorage.removeItem('zsimple_conn'), true)`);
out.check = await ev(`fetch('/api/tenant/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(${credsJson}) }).then(r => r.status)`);
await simple();
out.signed = await conn('/Connected to acme/');
// 3. The sign-in ends (the server's clock moves past 30 idle minutes); the check then says so in words.
fs.writeFileSync(clockFile, 'later');
await until(() => ev(`!!document.getElementById('smNext') && !/First, connect/.test(document.getElementById('smStepBody').textContent)`), 'the connected step');
await until(next, 'Next (connected)');
await until(() => ev(`!!document.querySelector('input[name="smCh"]')`), 'the channel step');
await until(next, 'Next (channels)');
await until(() => ev(`!!document.getElementById('smRun')`), 'the run step');
await until(next, 'Check now');
out.failed = await until(() => ev(`(() => { const e = document.getElementById('smErr'); return e && e.textContent.trim() ? e.textContent : null; })()`), 'the error', 30000);
// 4. Loaded again: Simple mode says the sign-in ended, not just "Not connected".
await simple();
out.onLoad = await conn('/sign-in ended/');
console.log(JSON.stringify(out));
clearTimeout(deadline); ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def ended(tmp_path_factory):
    import os
    import time

    import tenant_session
    mp = pytest.MonkeyPatch()
    tmp = tmp_path_factory.mktemp("signed-in-ended")
    later = tmp / "later"
    # The server's clock, moved 31 minutes on once the driver writes `later`.
    mp.setattr(tenant_session, "_clock", lambda: time.monotonic() + (31 * 60 if os.path.exists(later) else 0))
    mp.setattr(srv, "_build_sdk_client", lambda creds: (srv._validate_creds(creds), object())[1])
    mp.setattr(srv, "_readiness_token_access", lambda client, method: {})
    mp.setattr(srv, "_close_quietly", lambda client: None)
    mp.setattr(srv, "_get_checks", lambda scope, scopes: [("DLP.1", "DLP", "Check 1", lambda c: R(R.FAIL, "not set"))])
    mp.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    mp.setattr(srv, "_APP_DIR", str(tmp))
    try:
        return run_in_browser(tmp, ENDED_DRIVER, json.dumps(ACME), str(later), timeout=170)
    finally:
        mp.undo()
        tenant_session.clear_all()


def test_simple_mode_adopts_the_guides_tenant_profile(ended):
    """ASVS V3.2.1 · CWE-287 · WSTG-SESS-01 · WCAG 2.2 SC 3.3.7: with no sign-in kept, Simple mode connects with the tenant profile the guide picked."""
    assert "Connected to Bolt profile" in ended["adopted"], ended["adopted"]
    assert ended["check"] == 200 and "Connected to acme" in ended["signed"]


def test_simple_mode_says_in_words_when_the_sign_in_ended(ended):
    """ASVS V3.3.2 · CWE-613 · WSTG-SESS-07 · WCAG 2.2 SC 3.3.1: a check run after the sign-in ended, and the next load, say the sign-in ended and to connect again."""
    assert "sign-in ended" in ended["failed"] and "connect again" in ended["failed"], ended["failed"]
    assert "sign-in ended" in ended["onLoad"], ended["onLoad"]
