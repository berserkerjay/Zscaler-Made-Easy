"""Functionality in a real browser on the sample tenant (Larkspur Freight):
the way a first-time user meets the app, driven over CDP in headless Chrome.

* The Connect page's "Try with a sample tenant", then Run assessment from the
  Scope page, with no sign-in details (the sample needs none). The bug (Wave 6
  UI check): the Scope page's Run assessment (static/dashboard.js) still asked
  for a vanity domain, client ID and secret and sent the user back to Connect,
  so the sample tenant could not be assessed from the sidebar at all.
* Every Simple mode wizard runs end to end on the sample (table over the
  seven tasks): each reaches its last screen with no error and no console
  error.
* Every ?build=<type> hand-off opens Bulk changes with that builder picked.
* Nothing is written while write mode is off: the sample's change counter
  stays at zero after all of it.

The app runs in-process on a loopback port (tests/test_findings_reflow.py
run_in_browser); skips without node or Chrome.
"""
from __future__ import annotations

import json

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

# CDP events (console errors, exceptions, HTTP errors) on top of the shared
# prelude, and the helpers every driver here uses.
EVENTS = r"""
// The driver ends itself (and its Chrome) before the test's own timeout, so a hung page never leaves a browser behind.
process.on('exit', () => { try { p.kill(); } catch (e) { /* gone */ } });   // a driver that throws never leaves its Chrome running
const deadline = setTimeout(() => { try { p.kill(); } catch (e) { /* gone */ } console.error('driver deadline reached'); process.exit(3); }, Number(process.env.UI_DEADLINE_MS || 840000));
const seen = { errors: [] };
// UI_TRACE=<file> writes the driver's progress there (debugging a hung run); off by default.
const trace = (...a) => { if (process.env.UI_TRACE) fs.appendFileSync(process.env.UI_TRACE, a.map(String).join(' ') + '\n'); };
const _onmsg = ws.onmessage;
ws.onmessage = e => { _onmsg(e); const m = JSON.parse(e.data); if (m.id) return;
  if (m.method === 'Runtime.exceptionThrown') seen.errors.push('exception: ' + String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200));
  if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') seen.errors.push('console: ' + m.params.args.map(a => a.value || a.description || '').join(' ').slice(0, 200));
  // A script dialog (alert, confirm) would block every evaluation: record it and accept it, as a user clicking OK.
  if (m.method === 'Page.javascriptDialogOpening') { seen.dialogs = (seen.dialogs || []).concat(m.params.message.slice(0, 160)); ws.send(JSON.stringify({ id: 900000 + seen.dialogs.length, method: 'Page.handleJavaScriptDialog', params: { accept: true } })); }
  if (m.method === 'Network.responseReceived' && m.params.response.status >= 400 && m.params.response.url.startsWith(base)) seen.errors.push(m.params.response.status + ' ' + m.params.response.url.slice(base.length));
};
await send('Network.enable');
await send('Page.setDownloadBehavior', { behavior: 'deny' });
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
const go = async url => { await send('Page.navigate', { url: base + url }); await until(() => ev(`document.readyState === 'complete'`), url + ' load'); };
const settle = async (what, ms = 8000) => { let last = '', same = 0; await until(async () => { const now = await ev(`new Promise(r => requestAnimationFrame(() => r(document.documentElement.scrollHeight + ':' + document.body.innerText.length)))`); same = now === last ? same + 1 : 0; last = now; return same >= 4; }, what + ' settle', ms).catch(() => null); };
const clickText = (sel, text) => ev(`(() => { const b = [...document.querySelectorAll(${JSON.stringify(sel)})].find(e => e.offsetParent && e.textContent.replace(/\\s+/g, ' ').trim() === ${JSON.stringify(text)}); if (!b) return false; b.click(); return true; })()`);
"""

# Open the sample tenant through the Connect page, fill the report details,
# tick every scope the sample serves and run the assessment from the Scope
# page, as a user does. Leaves `run` = { started, org, checks }.
SAMPLE_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]
SETUP = r"""
trace('setup: start');
await go('/');
await ev(`(localStorage.setItem('zsimple_mode', 'expert'), true)`);
trace('setup: home loaded');
await until(() => clickText('button', 'Connect to the tenant'), 'the Connect item');
await until(() => clickText('button', 'Try with a sample tenant'), 'Try with a sample tenant');
await until(() => ev(`fetch('/api/offline/status').then(r => r.json()).then(s => s.mode === 'sample')`), 'the sample tenant');
trace('setup: sample open');
await ev(`(() => { for (const [id, v] of [['org', 'Larkspur Freight'], ['assessor', 'Synthetic Assessor'], ['custid', '72000000000000001']]) { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); } return true; })()`);
await until(() => clickText('button', 'Scope assessment'), 'the Scope item');
await settle('the Scope page', 4000);
// Tick every scope the sample serves, until the page itself reports them all (the page may redraw while it opens).
await until(() => ev(`(() => { const want = ${JSON.stringify(SCOPES)}; document.querySelectorAll('.scope-cb').forEach(cb => { if (cb.checked !== want.includes(cb.value)) cb.click(); });
  const got = typeof getSelectedScopes === 'function' ? getSelectedScopes() : []; return want.every(s => got.includes(s)); })()`), 'every sample scope ticked');
// Every channel on Zscaler (the Channels card's Select all), so no check is hidden as out of scope.
await ev(`(() => { const a = document.getElementById('dbChSelectAll'); if (a && !a.checked) a.click(); return true; })()`);
// Save config keeps the scope through a reload of the assessment page (the pages visited later reload it).
await ev(`(typeof saveConfig === 'function' && saveConfig(), true)`);
await until(() => ev(`(() => { const b = document.getElementById('dbScopeRun'); if (!b || !b.offsetParent) return false; b.click(); return true; })()`), 'Run assessment on the Scope page');
const run = { note: await ev(`((document.getElementById('dbRunNote') || {}).textContent || '')`) };
trace('setup: run clicked', run.note);
run.started = await until(() => ev(`!!sessionStorage.getItem('zassess_last_results')`), 'the assessment result', 150000).catch(() => false);
run.org = await ev(`(() => { try { return JSON.parse(sessionStorage.getItem('zassess_last_results')).metadata.org; } catch (e) { return ''; } })()`);
run.checks = await ev(`(() => { try { return JSON.parse(sessionStorage.getItem('zassess_last_results')).checks.length; } catch (e) { return 0; } })()`);
"""


def sample_setup():
    return SETUP.replace("${JSON.stringify(SCOPES)}", json.dumps(SAMPLE_SCOPES))


# ── The sample tenant, Simple mode and the hand-offs ─────────────────────

TILES = ["connect", "check", "fix", "protect", "path", "changes", "report"]
FILL = {"smSite": "chat.openai.com", "smOrg": "Larkspur Freight", "smWho": "Synthetic Assessor"}
PICK = {"smHow": "sample"}

DRIVER = CDP_PRELUDE + EVENTS + "%SETUP%" + r"""
const [tilesJson, fillJson, pickJson, buildsJson] = args;
const out = { run, setupErrors: seen.errors.splice(0), wizards: {}, builds: {} };
// Simple mode: every wizard, end to end.
for (const id of JSON.parse(tilesJson)) {
  const rec = out.wizards[id] = { steps: [] };
  await go('/simple#' + id);
  for (let n = 0; n < 12; n++) {
    await until(() => ev(`(() => { const b = document.getElementById('smStepBody'); return !!b && !/^(Working|One moment)/i.test(b.textContent.trim()); })()`), id + ' step', 20000).catch(() => null);
    const st = await ev(`({ step: (document.getElementById('smStepText') || {}).textContent || '', err: ((document.getElementById('smErr') || {}).innerText || '').trim(), done: !!document.getElementById('smDone'), body: ((document.getElementById('smStepBody') || {}).innerText || '').slice(0, 200) })`);
    rec.steps.push(st.step);
    trace(id, st.step, st.err ? 'ERR ' + st.err : '', st.done ? 'DONE' : '');
    if (st.err) { rec.error = st.err; break; }
    if (st.done) { rec.done = true; rec.final = st.body; break; }
    await ev(`(() => { const FILL = ${fillJson}, PICK = ${pickJson};
      const groups = new Set([...document.querySelectorAll('#smStepBody input[type=radio]')].map(r => r.name));
      for (const g of groups) if (!document.querySelector('input[name="' + g + '"]:checked')) { const w = PICK[g] && document.querySelector('input[name="' + g + '"][value="' + PICK[g] + '"]'); (w || document.querySelector('input[name="' + g + '"]')).click(); }
      for (const [k, v] of Object.entries(FILL)) { const e = document.getElementById(k); if (e && !e.value) { e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); } }
      return true; })()`);
    const before = st.step;
    if (!(await ev(`(() => { const n = document.getElementById('smNext'); if (!n || n.disabled) return false; n.click(); return true; })()`))) { rec.error = 'no Next button'; break; }
    const moved = await until(() => ev(`((document.getElementById('smStepText') || {}).textContent || '') !== ${JSON.stringify(before)} || !!((document.getElementById('smErr') || {}).innerText || '').trim()`), id + ' next', 150000).catch(() => false);
    if (!moved) { rec.error = 'stuck after ' + before; break; }
  }
  rec.errors = seen.errors.splice(0);
}
// Bulk changes: each ?build=<type> picks that builder.
for (const t of JSON.parse(buildsJson)) {
  await go('/report/operations?build=' + t);
  out.builds[t] = await until(() => ev(`(() => { const r = document.querySelector('input[name="opKind"]:checked'); return r && r.value !== 'rule_state' ? r.value : null; })()`), t + ' picked', 8000).catch(() => null);
}
out.buildErrors = seen.errors.splice(0);
out.offline = await ev(`fetch('/api/offline/status').then(r => r.json())`);
out.writes = await ev(`fetch('/api/write-mode').then(r => r.ok ? r.json() : { status: r.status }).catch(e => ({ error: String(e) }))`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def _builder_types():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    return sorted(p["type"] for p in TestClient(srv.app).get("/api/operations/plugins").json()["plugins"])


@pytest.fixture(scope="module")
def journey(tmp_path_factory):
    driver = DRIVER.replace("%SETUP%", sample_setup())
    return run_in_browser(tmp_path_factory.mktemp("sample-journey"), driver, json.dumps(TILES), json.dumps(FILL), json.dumps(PICK),
                          json.dumps(_builder_types()), timeout=900)


def test_the_sample_tenant_runs_the_assessment_from_the_scope_page(journey):
    """WCAG 2.2 SC 3.3.1, 3.3.3 · CWE-754: with the sample open, Run assessment on the Scope page runs it (it asked for a client ID and secret the sample does not need)."""
    run = journey["run"]
    assert "Sign in first" not in run["note"], run
    assert run["started"] and run["org"] == "Larkspur Freight" and run["checks"] > 100, run
    assert journey["setupErrors"] == [], journey["setupErrors"]


@pytest.mark.parametrize("tile", TILES)
def test_every_simple_mode_wizard_runs_end_to_end_on_the_sample(journey, tile):
    """WCAG 2.2 SC 3.3.1, 3.3.2 · table over the seven Simple mode tasks: each reaches its last screen on the sample, with no error and no console error."""
    rec = journey["wizards"][tile]
    assert rec.get("done") and not rec.get("error"), rec
    assert rec["errors"] == [], rec["errors"]


@pytest.mark.parametrize("build", _builder_types())
def test_every_build_hand_off_picks_its_builder(journey, build):
    """WCAG 2.2 SC 3.2.4 · table over every registered builder: /report/operations?build=<type> opens Bulk changes with that builder picked."""
    assert journey["builds"][build] == build, journey["builds"]


def test_nothing_reached_the_tenant_while_write_mode_was_off(journey):
    """ASVS V4.1.5 · CWE-284 · WCAG 2.2 SC 3.3.4: after the whole journey in read-only mode, the sample tenant has no change and write mode is still off."""
    assert journey["offline"]["mode"] == "sample" and journey["offline"]["changes"] == 0, journey["offline"]
    assert journey["writes"].get("enabled") is False, journey["writes"]
    assert journey["buildErrors"] == [], journey["buildErrors"]
