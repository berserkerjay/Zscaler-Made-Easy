"""The POV planner's Build tab in a real browser (node + headless Chrome over
CDP, the harness of tests/test_findings_reflow.py; skipped without either).

Live tenant: the app's client factory hands out the stateful SDK wire fake
(tests/sdk_wire_fake.py), so the page previews the combined dry run (a
section per product, every object, one plan hash), applies it with one
typed phrase, lists the build and offers Undo. Sample tenant: the same tab
rehearses with an intake typed on the page and offers no Apply. Every width
down to 320px keeps the page from scrolling sideways, and everything is
reached with the keyboard. Screenshots go to POV_BUILD_SHOTS when it is set.
No network, no real tenant."""
from __future__ import annotations

import json
import os
import pathlib
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_findings_reflow import CDP_PRELUDE, run_in_browser  # noqa: E402

DRIVER = CDP_PRELUDE + r"""
const [outDir] = args;
const out = { errors: [] };
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.method === 'Runtime.exceptionThrown') out.errors.push(String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200)); });
async function shot(name, sel) {
  if (!outDir) return;
  const r = await ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); if (!e) return null; e.scrollIntoView({block:'start'}); const b = e.getBoundingClientRect(); return {x:Math.max(0,b.left), y:b.top + scrollY, w:Math.max(1,b.width), h:Math.max(1,Math.min(b.height, 2400))}; })()`);
  if (!r) return;
  await sleep(250);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 } });
  fs.writeFileSync(path.join(outDir, name + '.png'), Buffer.from(s.result.data, 'base64'));
}
const post = (u, b) => ev(`fetch(${JSON.stringify(u)}, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: ${JSON.stringify(JSON.stringify(b))} }).then(r => r.json())`);
const over = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/pov' });
await until(() => ev(`document.readyState === 'complete'`), 'the planner');
// A tenant profile with a POV (the live tenant is the wire fake behind the client factory).
const prof = await post('/api/tenant-profiles', { name: 'Acme', vanity_domain: 'acme', client_id: 'abc123456789', client_secret: 'browser-test-secret-1', remember_secret: true, customer_id: '7200000000000001' });
const pid = (prof.profile || prof).id;
await post('/api/pov/create', { profile_id: pid, intake: { customer: 'Acme Health', domain: 'corp.example.com', prefix: 'AH', vertical: 'healthcare',
  products: ['url_filtering', 'threat', 'ssl', 'cloud_apps', 'firewall', 'zpa'] } });
await ev(`(localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['dlp', 'zia_extras', 'zpa', 'zcc', 'aiguard'] })), 1)`);
await send('Page.navigate', { url: base + '/report/pov?profile=' + encodeURIComponent(pid) + '#build' });
await until(() => ev(`document.querySelectorAll('#pvBuild input.pb-on').length > 0`), 'the parts', 30000);
out.parts = await ev(`[...document.querySelectorAll('#pvBuild input.pb-on')].map(b => b.dataset.step + ':' + (b.checked ? 'on' : 'off'))`);
// Keyboard: Tab reaches the dry-run button.
await ev(`(document.querySelector('#tab-build').focus(), 1)`);
let reached = false;
for (let i = 0; i < 200 && !reached; i++) {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  reached = await ev(`document.activeElement && document.activeElement.id === 'pbPreview'`);
}
out.keyboard_preview = reached;
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
await until(() => ev(`!!document.querySelector('#pbPreviewOut .pb-summary') || !!document.querySelector('#pbPreviewOut .bp-card.risk')`), 'the dry run', 60000)
  .catch(async e => { throw new Error(e.message + ': ' + String(await ev(`(document.getElementById('pbPreviewOut') || document.body).innerText.slice(0, 1500) + ' | active=' + (document.activeElement || {}).id + ' | ' + document.getElementById('pvStatus').textContent`))); });
out.preview = await ev(`({ sections: [...document.querySelectorAll('#pbPreviewOut section.pb-section h3')].map(h => h.textContent),
  parts: document.querySelectorAll('#pbPreviewOut details.pb-prev-part').length, rows: document.querySelectorAll('#pbPreviewOut .pb-table tbody tr').length,
  hash: (document.querySelector('#pbPreviewOut .pb-hash') || {}).textContent || '', error: (document.querySelector('#pbPreviewOut .bp-card.risk') || {}).textContent || '',
  phrase: ((document.querySelector('label[for="pbPhrase"]') || {}).textContent || '').replace('Type ', '').replace(' to confirm', '') })`);
await ev(`(document.querySelectorAll('#pbPreviewOut details.pb-prev-part').forEach((d, i) => { d.open = i < 3; }), 1)`);
await shot('desk_pov_build_dry_run', '#pbPreviewOut');
await shot('desk_pov_build_apply_panel', '#pbApplyOut');
for (const w of [320, 768]) {
  await send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(200);
  out['over_' + w] = await over();
  if (w === 320) { await shot('phone_pov_build_parts', '#pvBuild .pb-parts'); await shot('phone_pov_build_dry_run', '#pbPreviewOut .pb-summary'); }
}
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
// One typed confirmation applies the whole build.
await ev(`(() => { const set = (id, v) => { const e = document.getElementById(id); e.value = v; e.dispatchEvent(new Event('input', { bubbles: true })); };
  set('pbAssessor', 'Jane Doe'); set('pbPhrase', ${JSON.stringify('')} || document.querySelector('label[for="pbPhrase"]').textContent.replace('Type ', '').replace(' to confirm', ''));
  const a = document.getElementById('pbAgree'); a.checked = true; a.dispatchEvent(new Event('change', { bubbles: true })); return 1; })()`);
out.go_enabled = await ev(`!document.getElementById('pbGo').disabled`);
await ev(`(document.getElementById('pbGo').click(), 1)`);
await until(() => ev(`!!document.querySelector('#pbResultOut .bp-card')`), 'the result', 90000);
out.result = await ev(`({ title: document.querySelector('#pbResultOut .bp-card .t').textContent, steps: [...document.querySelectorAll('#pbResultOut .pb-steps > li')].map(l => l.textContent.slice(0, 80)),
  undo: !!document.querySelector('#pbResultOut button.pb-undo-build'), listed: document.querySelectorAll('#pvBuild button.pb-undo-build').length })`);
await shot('desk_pov_build_result', '#pbResultOut');
// The sample tenant: a rehearsal with an intake typed on the page, no Apply.
await post('/api/offline/sample', { reset: true });
await send('Page.navigate', { url: base + '/report/pov#build' });
await until(() => ev(`!!document.querySelector('#pvBuild')`), 'the planner on the sample');
await ev(`(localStorage.removeItem('pov_profile_v1'), 1)`);
await send('Page.navigate', { url: base + '/report/pov?profile=none#build' });
await until(() => ev(`!!document.querySelector('#pvBuild form.pv-form') || document.querySelectorAll('#pvBuild input.pb-on').length > 0`), 'the rehearsal intake', 30000);
out.rehearsal_intake = await ev(`!!document.querySelector('#pvBuild .pb-rehearsal')`);
if (await ev(`!!document.querySelector('#pvBuild form.pv-form')`)) {
  await ev(`(() => { const f = document.querySelector('#pvBuild form.pv-form'); const c = f.querySelector('input[maxlength="120"]'); c.value = 'Larkspur Freight'; c.dispatchEvent(new Event('input', { bubbles: true }));
    const d = f.querySelector('input[placeholder="corp.example.com"]'); d.value = 'corp.larkspur-freight.example'; f.requestSubmit(); return 1; })()`);
}
await until(() => ev(`document.querySelectorAll('#pvBuild input.pb-on').length > 0`), 'the rehearsal parts', 30000);
await ev(`(document.getElementById('pbPreview').click(), 1)`);
await until(() => ev(`!!document.querySelector('#pbPreviewOut .pb-summary') || !!document.querySelector('#pbPreviewOut .bp-card.risk')`), 'the rehearsal', 60000);
out.rehearsal = await ev(`({ note: ((document.querySelector('#pbPreviewOut .pb-rehearsal .t') || {}).textContent || ''), apply: !!document.getElementById('pbGo'),
  sections: [...document.querySelectorAll('#pbPreviewOut section.pb-section h3')].map(h => h.textContent), error: (document.querySelector('#pbPreviewOut .bp-card.risk') || {}).textContent || '' })`);
await shot('desk_pov_build_rehearsal_sample', '#pbPreviewOut');
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(200);
out.over_rehearsal_320 = await over();
await shot('phone_pov_build_rehearsal_sample', '#pbPreviewOut .pb-summary');
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture
def wired(monkeypatch):
    """The live tenant is the SDK wire fake; write mode on for this process."""
    import admin_ops as ao
    import dlp_api_server as srv
    import ops_zpa
    import pack_channels as pc
    import security
    import sdk_wire_fake as wf
    import zpa_reader
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    ao.load_plugins()
    extra = {}
    for f in (wf.zia_catalogues, wf.zpa_builder_lists, wf.aiguard_lists):
        extra.update(f())
    st = wf.WireStore(extra)
    real = srv._build_sdk_client
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: real(creds) if str(creds.get("client_id", "")).startswith("offline-") else wf.WireClient(st))
    monkeypatch.setattr(security, "_write_override", True)
    return st


def test_the_build_tab_previews_applies_and_rehearses_in_a_browser(tmp_path, wired):
    """WCAG 2.2 SC 1.4.10 · SC 2.1.1 · SC 3.3.4 · ASVS V11.1.1 · CWE-841: one dry run (a section per product, every object, one hash), one typed phrase applies every part and offers Undo; on the sample it is a rehearsal with no Apply; no sideways scroll at 320px; the dry run is reached by keyboard."""
    # Arrange
    shots = os.environ.get("POV_BUILD_SHOTS", "")
    if shots:
        pathlib.Path(shots).mkdir(parents=True, exist_ok=True)
    # Act
    out = run_in_browser(tmp_path, DRIVER, shots, timeout=300)
    # Assert
    assert out["errors"] == [], out["errors"]
    assert "zia_baseline:on" in out["parts"] and "zpa_policies:on" in out["parts"], out["parts"]
    assert out["keyboard_preview"] is True
    p = out["preview"]
    assert not p["error"], p["error"]
    assert p["sections"] == ["Internet Access (ZIA)", "Private Access (ZPA)"] and p["parts"] == 4 and p["rows"] > 20 and len(p["hash"]) == 64
    assert out["over_320"] <= 0 and out["over_768"] <= 0 and out["over_rehearsal_320"] <= 0
    assert out["go_enabled"] is True
    assert out["result"]["title"] == "Build applied" and len(out["result"]["steps"]) == 4 and out["result"]["undo"], out["result"]
    r = out["rehearsal"]
    assert out["rehearsal_intake"] is True and not r["error"], r
    assert r["note"] == "Rehearsal — nothing was written." and r["apply"] is False and r["sections"]
    assert wired.violations == []
