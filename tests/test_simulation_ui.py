"""Rehearse, then simulate, in a real browser (node + headless Chrome over CDP,
the harness of tests/test_findings_reflow.py; skipped without either).

Bulk changes: the page's API is replaced by a fake injected before the page
loads (a rehearsal preview on the sample tenant), so the test pins what the
page sends and draws: "Apply to a simulation" waits for the typed phrase,
posts the rehearsal's plan hash to /api/offline/simulate/operation (never the
real apply), labels the result a simulation, the safety banner then says a
simulation is in use, and "Leave the simulation" posts the discard route.
Tenant-controlled words (the base label) stay text.

POV planner: the real app on the sample tenant. A rehearsed build is applied
to a simulation from the Build tab, the result and the banner say so, the
real Apply is never offered, and Leave the simulation (on the result, then
on the Connect page) goes back to the sample. No network, no real tenant."""
from __future__ import annotations

import json
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_findings_reflow import CDP_PRELUDE, run_in_browser  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PHRASE = "APPLY 2 CHANGES"
XSS = '<img src=x onerror="window.__xss=1">'

FAKE_API = r"""
(() => {
  if (location.pathname !== '/report/operations') return;
  const XSS = %(xss)s, PHRASE = %(phrase)s;
  const store = (k, v) => { try { const a = JSON.parse(sessionStorage.getItem(k) || '[]'); a.push(v); sessionStorage.setItem(k, JSON.stringify(a)); } catch (e) {} };
  const rules = [1, 2].map(i => ({ policy: 'url_filtering', policy_label: 'URL filtering', rule_type: '', id: i, name: 'Rule ' + i, order: i, state: 'ENABLED', locked: '' }));
  const plan = { status: 'ready', plan_hash: 'a'.repeat(64), confirm_phrase: PHRASE, title: 'Disable 2 rules', tenant_label: 'Sample tenant', writes: 2, needs_activation: true,
    counts: { change: 2, noop: 0, excluded: 0, total: 2 }, blockers: [], warnings: [], notes: [], impact: [],
    rehearsal: { kind: 'sample', note: 'Rehearsal — nothing was written.', apply: 'Rehearsal only: this is the sample tenant.', simulate: 'Apply to a simulation: the rehearsed plan is applied to an in-memory copy.' },
    items: rules.map(r => ({ key: 'r' + r.id, object: { name: r.name, policy_label: r.policy_label }, field: 'state', before: 'ENABLED', after: 'DISABLED', status: 'change', reason: '' })) };
  const jobs = { j_read: { status: 'done', result: { status: 'done', tenant_label: 'Sample', policies: [{ policy: 'url_filtering', label: 'URL filtering', ordered: true, rules }] } },
                 j_prev: { status: 'done', result: plan } };
  const sim = { source: 'sim-0123456789abcdef', tenant_label: 'Simulation of ' + XSS, base_label: XSS, base_kind: 'sample',
    note: 'Simulation: applied to an in-memory copy only. Nothing was written to a tenant.', applied: [{ what: 'rule_state', status: 'applied', at: '2026-11-01T10:00:00+00:00' }] };
  window.__calls = [];
  const real = window.fetch.bind(window);
  const json = (body, status) => Promise.resolve(new Response(JSON.stringify(body), { status: status || 200, headers: { 'Content-Type': 'application/json' } }));
  window.fetch = (url, opts) => {
    const u = String(url), body = opts && opts.body ? JSON.parse(opts.body) : null;
    if (u.startsWith('/api/')) { window.__calls.push({ url: u, body }); store('__calls', { url: u, body }); }
    if (u === '/api/operations/plugins') return json({ plugins: [] });
    if (u === '/api/write-mode') return json({ enabled: false });
    if (u === '/api/tenant-profiles') return json({ profiles: [] });
    if (u === '/api/operations') return json({ operations: [] });
    if (u === '/api/offline/status') return json(sessionStorage.getItem('__sim') ? { mode: 'simulation', source: sim.source, tenant_label: sim.tenant_label, simulation: sim } : { mode: 'sample', source: 'sample', company: 'Larkspur Freight', tenant_label: 'Sample tenant' });
    if (u === '/api/operations/objects/start') return json({ job_id: 'j_read' });
    if (u === '/api/operations/preview/start') return json({ job_id: 'j_prev', operation: body.operation });
    if (u === '/api/operations/apply/start') return json({ detail: 'the real apply must not be called' }, 500);
    if (u === '/api/offline/simulate/operation') {
      sessionStorage.setItem('__sim', '1');
      return json({ status: 'applied', type: 'rule_state', product: 'zia', title: 'Disable 2 rules', counts_run: { applied: 2 }, verification: { checked: 2, confirmed: 2 },
        activation: null, items: [], writes_enabled: false, simulation: sim });
    }
    if (u === '/api/offline/simulation/discard') { sessionStorage.removeItem('__sim'); return json({ mode: 'sample', source: 'sample', message: 'The simulation was dropped: back to Sample tenant.' }); }
    const m = /^\/api\/dlp-packs\/jobs\/(j_[a-z]+)\?/.exec(u);
    if (m) return json(Object.assign({ logs: [], next: 0 }, jobs[m[1]]));
    return real(url, opts);
  };
})();
""" % {"xss": json.dumps(XSS), "phrase": json.dumps(PHRASE)}

OPS_DRIVER = CDP_PRELUDE + r"""
const [fakeApi] = args;
const out = { errors: [] };
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.method === 'Runtime.exceptionThrown') out.errors.push(String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200)); });
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 160); } };
await send('Page.addScriptToEvaluateOnNewDocument', { source: fakeApi });
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/operations' });
await until(() => ev(`document.readyState === 'complete' && !!document.getElementById('opRead')`), 'the page');
await ev(`document.getElementById('opRead').click(), 1`);
await until(() => ev(`document.querySelectorAll('input[data-k]').length === 2`), 'the rules');
await ev(`document.getElementById('opAll').click(), 1`);
await ev(`document.getElementById('opPreview').click(), 1`);
await safe('box', () => until(() => ev(`!!document.getElementById('opSimulate')`), 'the simulation box', 8000).then(() => true));
await safe('beforePhrase', () => ev(`({ sim: document.getElementById('opSimulate').disabled, go: document.getElementById('opGo').disabled, why: document.getElementById('opSimWhy').textContent,
  how: document.getElementById('opSimBox').textContent })`));
await ev(`(() => { const p = document.getElementById('opPhrase'); p.value = ' apply 2 changes '; p.dispatchEvent(new Event('input')); return 1; })()`);
await safe('afterPhrase', () => ev(`({ sim: document.getElementById('opSimulate').disabled, go: document.getElementById('opGo').disabled })`));
await ev(`document.getElementById('opSimulate').click(), 1`);
await safe('card', () => until(() => ev(`!!document.getElementById('opSimCard')`), 'the simulation card', 8000).then(() => true));
await safe('result', () => ev(`({ title: (document.querySelector('#opResultCard .t') || {}).textContent || '', card: document.getElementById('opSimCard').textContent,
  img: !!document.querySelector('#opResult img'), xss: window.__xss === undefined ? null : window.__xss,
  path: (document.getElementById('opSimPath') || {}).getAttribute ? document.getElementById('opSimPath').getAttribute('href') : '',
  calls: window.__calls.filter(c => /simulate|apply/.test(c.url)).map(c => ({ url: c.url, plan_hash: c.body && c.body.plan_hash, confirm: c.body && c.body.confirm, confirm_text: c.body && c.body.confirm_text, type: c.body && c.body.operation && c.body.operation.type })) })`));
await safe('banner', () => until(() => ev(`(() => { const r = document.querySelector('#dlpSafetyBanner .sb-offline'); return r && !r.hidden && /Simulation/.test(r.textContent) ? { text: r.textContent, leave: r.querySelector('.sb-leave').textContent } : null; })()`), 'the banner', 8000));
await ev(`document.getElementById('opSimLeave').click(), 1`);
await safe('left', () => until(() => ev(`(() => { const t = document.getElementById('opSimCard').textContent; return /dropped/.test(t) ? { text: t, leave: !!document.getElementById('opSimLeave'), discard: window.__calls.filter(c => c.url === '/api/offline/simulation/discard').length } : null; })()`), 'the leave', 8000));
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(200);
await safe('over320', () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`));
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""

POV_DRIVER = CDP_PRELUDE + r"""
const out = { errors: [] };
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.method === 'Runtime.exceptionThrown') out.errors.push(String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200)); });
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 300); } };
const post = (u, b) => ev(`fetch(${JSON.stringify(u)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: ${JSON.stringify(JSON.stringify(b))} }).then(r => r.json())`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/pov' });
await until(() => ev(`document.readyState === 'complete'`), 'the planner');
await post('/api/offline/sample', { reset: true });
await ev(`(localStorage.removeItem('pov_profile_v1'), localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['dlp', 'zia_extras', 'zpa', 'zcc', 'aiguard'] })), 1)`);
await send('Page.navigate', { url: base + '/report/pov?profile=none#build' });
await until(() => ev(`!!document.querySelector('#pvBuild form.pv-form') || document.querySelectorAll('#pvBuild input.pb-on').length > 0`), 'the rehearsal intake', 30000);
if (await ev(`!!document.querySelector('#pvBuild form.pv-form')`)) {
  await ev(`(() => { const f = document.querySelector('#pvBuild form.pv-form'); const c = f.querySelector('input[maxlength="120"]'); c.value = 'Larkspur Freight'; c.dispatchEvent(new Event('input', { bubbles: true }));
    const d = f.querySelector('input[placeholder="corp.example.com"]'); d.value = 'corp.larkspur-freight.example'; f.requestSubmit(); return 1; })()`);
}
await until(() => ev(`document.querySelectorAll('#pvBuild input.pb-on').length > 0`), 'the rehearsal parts', 30000);
// Only the ZPA connector group: a part the offline tenant reads back (the test of the route covers the rest).
// Each tick redraws the tab, so the boxes are looked up again after every click.
for (let i = 0; i < 20; i++) {
  const left = await ev(`(() => { const b = [...document.querySelectorAll('#pvBuild input.pb-on')].find(x => !x.disabled && x.checked !== (x.dataset.step === 'zpa_connector_group')); if (!b) return false; b.click(); return true; })()`);
  if (!left) break;
}
out.parts = await ev(`[...document.querySelectorAll('#pvBuild input.pb-on')].map(b => b.dataset.step + ':' + (b.checked ? 'on' : 'off') + (b.disabled ? ':disabled' : ''))`);
await ev(`(document.getElementById('pbPreview').click(), 1)`);
await until(() => ev(`!!document.querySelector('#pbPreviewOut .pb-summary') || !!document.querySelector('#pbPreviewOut .bp-card.risk')`), 'the rehearsal', 60000);
await safe('rehearsal', () => ev(`({ go: !!document.getElementById('pbGo'), sim: !!document.getElementById('pbSimulate'), error: (document.querySelector('#pbPreviewOut .bp-card.risk') || {}).textContent || '',
  disabled: (document.getElementById('pbSimulate') || {}).disabled, phrase: !!document.getElementById('pbSimPhrase') })`));
await ev(`(() => { const p = document.getElementById('pbSimPhrase'); if (p) { const l = document.querySelector('label[for="pbSimPhrase"]').textContent.replace('Type ', '').replace(' to confirm', ''); p.value = l; p.dispatchEvent(new Event('input', { bubbles: true })); } return 1; })()`);
await safe('armed', () => ev(`!document.getElementById('pbSimulate').disabled`));
await ev(`(document.getElementById('pbSimulate').click(), 1)`);
await safe('result', () => until(() => ev(`(() => { const c = document.querySelector('#pbResultOut .pb-simulation'); if (!c) return null;
  return { card: c.textContent, title: (document.querySelector('#pbResultOut .bp-card:not(.pb-simulation) .t') || {}).textContent || '', leave: !!document.getElementById('pbSimLeave'), go: !!document.getElementById('pbGo') }; })()`), 'the simulation result', 60000));
await safe('status', () => ev(`fetch('/api/offline/status').then(r => r.json()).then(d => d.mode)`));
await safe('banner', () => until(() => ev(`(() => { const r = document.querySelector('#dlpSafetyBanner .sb-offline'); return r && !r.hidden && /Simulation/.test(r.textContent) ? r.querySelector('.sb-leave').textContent : null; })()`), 'the banner', 10000));
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(200);
await safe('over320', () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`));
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await ev(`(document.getElementById('pbSimLeave').click(), 1)`);
await safe('left', () => until(() => ev(`fetch('/api/offline/status').then(r => r.json()).then(d => d.mode === 'sample' && !document.querySelector('#pbResultOut .pb-simulation') ? d.mode : null)`), 'the leave', 20000));
// Simulate again, then leave from the Connect page instead.
await ev(`(document.getElementById('pbPreview').click(), 1)`);
await until(() => ev(`!!document.getElementById('pbSimPhrase')`), 'the second rehearsal', 60000);
await ev(`(() => { const p = document.getElementById('pbSimPhrase'); p.value = document.querySelector('label[for="pbSimPhrase"]').textContent.replace('Type ', '').replace(' to confirm', ''); p.dispatchEvent(new Event('input', { bubbles: true })); document.getElementById('pbSimulate').click(); return 1; })()`);
await until(() => ev(`!!document.querySelector('#pbResultOut .pb-simulation')`), 'the second simulation', 60000);
await send('Page.navigate', { url: base + '/' });
await until(() => ev(`document.readyState === 'complete' && !!document.querySelector('[data-db="configure"]')`), 'the home page');
await ev(`document.querySelector('[data-db="configure"]').click(), 1`);
await safe('connect', () => until(() => ev(`(() => { const b = document.querySelector('#gdOffline .zo-row button.gd-btn.primary'); return b && b.offsetParent && /simulation/.test(b.textContent) ? { button: b.textContent, words: document.getElementById('gdOffline').textContent } : null; })()`), 'the Connect step', 20000));
await ev(`(document.querySelector('#gdOffline .zo-row button.gd-btn.primary').click(), 1)`);
await safe('connectLeft', () => until(() => ev(`fetch('/api/offline/status').then(r => r.json()).then(d => d.mode === 'sample' ? d.mode : null)`), 'the Connect leave', 20000));
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def test_bulk_changes_offers_apply_to_a_simulation_after_a_rehearsal_and_leaves_it(tmp_path):
    """WCAG 2.2 SC 3.3.4 · SC 4.1.3 · ASVS V4.1.1 · ASVS V5.3.3 · CWE-79 · CWE-441: after a rehearsal preview, Apply to a simulation needs the typed phrase, posts the rehearsal's hash to the simulate route (never the real apply), the result and the safety banner say simulation, tenant words stay text, and Leave the simulation posts the discard route."""
    # Act
    out = run_in_browser(tmp_path, OPS_DRIVER, FAKE_API)
    # Assert
    assert out["errors"] == [], out["errors"]
    assert out["box"] is True, out["box"]
    assert out["beforePhrase"]["sim"] is True and PHRASE in out["beforePhrase"]["why"], out["beforePhrase"]
    assert out["beforePhrase"]["go"] is True and "in-memory copy" in out["beforePhrase"]["how"]
    assert out["afterPhrase"] == {"sim": False, "go": True}, out["afterPhrase"]
    r = out["result"]
    assert r["calls"] == [{"url": "/api/offline/simulate/operation", "plan_hash": "a" * 64, "confirm": True, "confirm_text": " apply 2 changes ", "type": "rule_state"}], r["calls"]
    assert r["title"].startswith("Applied to the simulation"), r["title"]
    assert "Simulation: nothing here is real" in r["card"] and "in-memory copy only" in r["card"] and XSS in r["card"]
    assert r["img"] is False and r["xss"] is None and r["path"] == "/report/path"
    assert out["banner"]["leave"] == "Leave the simulation", out["banner"]
    assert out["left"]["discard"] == 1 and out["left"]["leave"] is False and "dropped" in out["left"]["text"], out["left"]
    assert out["over320"] <= 0


def test_the_pov_build_tab_applies_a_rehearsal_to_a_simulation_and_leaves_it(tmp_path, monkeypatch):
    """WCAG 2.2 SC 3.3.4 · SC 4.1.3 · ASVS V4.1.1 · CWE-441 · CWE-841: on the sample tenant the Build tab offers Apply to a simulation (never the real Apply) once the phrase is typed; the simulated build's result and the safety banner say simulation, this browser uses the copy, and Leave the simulation (on the result and on the Connect page) goes back to the sample; no sideways scroll at 320px."""
    # Arrange
    import offline_tenant as ot
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    # Act
    out = run_in_browser(tmp_path, POV_DRIVER, timeout=300)
    # Assert
    assert out["errors"] == [], out["errors"]
    reh = out["rehearsal"]
    assert "zpa_connector_group:on" in out["parts"], out["parts"]
    assert reh["go"] is False and reh["sim"] is True and reh["disabled"] is True and not reh["error"], reh
    assert out["armed"] is True
    r = out["result"]
    assert isinstance(r, dict), r
    assert r["title"] == "Build applied to the simulation" and "Simulation: nothing here is real" in r["card"] and r["leave"] and r["go"] is False, r
    assert out["status"] == "simulation" and out["banner"] == "Leave the simulation", (out["status"], out["banner"])
    assert out["over320"] <= 0
    assert out["left"] == "sample", out["left"]
    assert out["connect"]["button"] == "Leave the simulation" and "Using a simulation of" in out["connect"]["words"], out["connect"]
    assert out["connectLeft"] == "sample", out["connectLeft"]


# ── The help and the release marks for the new controls ─────────────────

def _catalog():
    text = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    return json.loads(re.search(r"window\.HELP_CATALOG\s*=\s*(\{.*\})\s*;\s*$", text, re.S).group(1))


@pytest.mark.parametrize("page,sel", [("/report/operations", s) for s in ("#opSimulate", "#opSimLeave", "#opSimPath", "#zbSearch", "#zbChanged", "#zbSelSave", "#zbSelLoad")]
                         + [("/report/pov", s) for s in ("#pbSimulate", "#pbSimPhrase", "#pbSimLeave", "#pbSimPath")])
def test_every_new_simulation_and_review_control_has_help(page, sel):
    """WCAG 2.2 SC 3.3.2 · ASVS V1.14.1: each control this change adds has a help entry on its page (what it does, what it expects, its effect); none of them changes a tenant."""
    e = _catalog()["pages"][page].get(sel)
    assert e and e["what"].strip() and e["input"].strip(), sel
    assert e["effect"] != "write", (sel, e["effect"])


def test_the_banner_and_connect_page_leave_words_cover_a_simulation():
    """WCAG 2.2 SC 3.3.2: the shared Leave controls (safety banner, Connect page) say what they do in a simulation."""
    cat = _catalog()["pages"]
    assert "simulation" in cat["*"]["#dlpSafetyBanner .sb-leave"]["what"]
    assert "simulation" in cat["/"]["#gdOffline .zo-row button.gd-btn.primary"]["what"]
