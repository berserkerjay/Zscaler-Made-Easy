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


def test_the_browser_keeps_no_secret(journey):
    """ASVS V8.2.2 · CWE-922 · WSTG-CLNT-12: no browser storage or script-readable cookie holds the secret."""
    assert SECRET not in journey["storage"]
