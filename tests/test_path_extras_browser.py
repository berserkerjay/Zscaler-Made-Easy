"""WCAG 2.2 SC 1.3.1 · SC 2.1.1 · SC 1.4.10: the Path analyzer's device pick, two-identity compare and Test from here in a real browser.

Headless Chrome over CDP (tests/test_findings_reflow.py's harness) drives
the real page on the made-up sample tenant (Larkspur Freight, served from
memory): look a user's devices up and pick one, analyze with it (the
device block says which app profile applied and why, and what is
unknown), compare two devices (the step where they diverge is marked),
and Test from here against a loopback TLS test server whose made-up
certificate names a Zscaler issuer. Every control is a native button or
field, reachable from the keyboard; nothing scrolls sideways at 320px.
A screenshot of each piece is saved (to PE_SHOTS_DIR when set). Skips
without node or Chrome.
"""
from __future__ import annotations

import json
import os

import pytest

import path_probe as pp
from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_path_probe import Server, _cert

DRIVER = CDP_PRELUDE + r"""
const [shotDir, probePort] = args;
const out = { shots: [] };
const shot = async (name, sel) => {
  // The sticky page bar would cover the top of the piece: it is laid out in place while the picture is taken.
  await ev(`(() => { const st = document.createElement('style'); st.id = 'peShot'; st.textContent = '.rp-bar, .rp-hero, .safety-banner, [class*="banner"] { position: static !important; }'; document.head.appendChild(st);
    document.querySelector(${JSON.stringify(sel)}).scrollIntoView({ block: 'start', behavior: 'instant' }); return 1; })()`);
  await sleep(250);
  const r = await ev(`(() => { const b = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return { x: b.left + scrollX, y: b.top + scrollY, w: b.width, h: b.height }; })()`);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false, clip: { x: Math.max(0, r.x - 8), y: Math.max(0, r.y - 8), width: Math.ceil(r.w + 16), height: Math.min(1780, Math.ceil(r.h + 16)), scale: 1 } });
  fs.writeFileSync(path.join(shotDir, name + '.png'), Buffer.from(s.result.data, 'base64'));
  await ev(`(() => { const st = document.getElementById('peShot'); if (st) st.remove(); return 1; })()`);
  out.shots.push(name);
};
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 1800, deviceScaleFactor: 1, mobile: false });
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
await send('Page.navigate', { url: base + '/report/path' });
await until(() => ev(`document.readyState === 'complete'`), 'load');
out.sample = await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
await ev(`localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['dlp', 'zia_extras', 'zcc', 'zpa'] }));
  localStorage.setItem('zassess_channels_v1', JSON.stringify({ web_dlp: 'zscaler', ssl_inspection: 'zscaler', cloud_app_control: 'zscaler' })); 1`);
await send('Page.reload');
await until(() => ev(`document.readyState === 'complete' && !!window.PathExtras`), 'reload');

// 1. Device pick: find Jordan's device and use it.
await ev(`document.getElementById('paDevice').open = true; document.getElementById('paDevice').dispatchEvent(new Event('toggle')); document.getElementById('paDevQ').value = 'jordan'; 1`);
await ev(`document.getElementById('paDevFind').focus(); 1`);
out.findState = await ev(`({ disabled: document.getElementById('paDevFind').disabled, focus: document.activeElement && document.activeElement.id, hint: document.getElementById('paDevScope').textContent })`);
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
await until(() => ev(`!!document.querySelector('#paDevRes button[data-dev-pick]')`), 'the devices found: ' + JSON.stringify(out.findState));
out.found = await ev(`[...document.querySelectorAll('#paDevRes button[data-dev-pick]')].map(b => b.textContent)`);
out.focusAfterFind = await ev(`document.activeElement && document.activeElement.hasAttribute('data-dev-pick')`);
await ev(`document.querySelector('#paDevRes button[data-dev-pick]').click(); 1`);
await until(() => ev(`!document.getElementById('paDevChosen').hidden && !!document.getElementById('paDevClear')`), 'the chosen device');
out.chosen = await ev(`({ card: document.getElementById('paDevChosen').textContent.replace(/\\s+/g, ' '), platDisabled: document.getElementById('paPlat').disabled,
  platFrom: document.getElementById('paPlatFrom').textContent, focus: document.activeElement && document.activeElement.id })`);
await shot('1-device-pick', '#paDevice');

// 2. Analyze with the device: the device block under the verdict.
await ev(`document.getElementById('paDest').value = 'dropbox.com'; document.getElementById('paNet').value = 'on'; document.getElementById('paRun').click(); 1`);
await until(() => ev(`!!document.getElementById('paDeviceOut')`), 'the device block', 60000);
out.device = await ev(`(() => { const s = document.getElementById('paDeviceOut');
  return { underVerdict: !!(s.previousElementSibling && s.previousElementSibling.classList.contains('pa-verdict')), text: s.textContent.replace(/\\s+/g, ' '),
    unknown: s.querySelectorAll('.pa-unknown').length, rows: s.querySelectorAll('tbody tr').length, headline: document.getElementById('paHeadline').textContent }; })()`);
await shot('2-device-result', '#paDeviceOut');

// 3. Compare: A is Jordan's device, B is Avery's.
await ev(`document.getElementById('paCompare').open = true; document.getElementById('paCompare').dispatchEvent(new Event('toggle')); document.getElementById('paCmpDevQ').value = 'avery'; document.getElementById('paCmpDevFind').click(); 1`);
await until(() => ev(`!!document.querySelector('#paCmpDevRes button[data-dev-pick]')`), 'B devices');
await ev(`document.querySelector('#paCmpDevRes button[data-dev-pick]').click(); 1`);
await until(() => ev(`!!document.getElementById('paCmpDevClear')`), 'B chosen');
await ev(`document.getElementById('paCmpRun').click(); 1`);
await until(() => ev(`!!document.querySelector('#paCmpOut .pa-cmp-table')`), 'the comparison', 60000);
out.compare = await ev(`(() => { const f = document.querySelector('#paCmpOut tr.pa-cmp-first');
  return { headline: document.getElementById('paCmpH').textContent, first: f ? f.querySelector('th').textContent.replace(/\\s+/g, ' ') : null,
    firsts: document.querySelectorAll('#paCmpOut tr.pa-cmp-first').length, rows: document.querySelectorAll('#paCmpOut tbody tr').length,
    csv: !!document.getElementById('paCmpCsv'), json: !!document.getElementById('paCmpJson') }; })()`);
out.csv = await ev(`(async () => { const r = await fetch('/api/path-analyzer/compare/' + 'x' + '/export'); return r.status; })()`);
await shot('3-compare', '#paCompare');

// 4. Test from here, against the loopback test server.
await ev(`document.getElementById('paDevClear').click(); document.getElementById('paDest').value = 'https://127.0.0.1:${probePort}/'; document.getElementById('paRun').click(); 1`);
await until(() => ev(`!!document.getElementById('paProbeRun') && /127\\.0\\.0\\.1/.test(document.getElementById('paProbeH').parentElement.textContent)`), 'the probe section', 60000);
await ev(`document.getElementById('paProbeRun').click(); 1`);
await until(() => ev(`!!document.querySelector('#paProbeOut .pa-probe-list')`), 'the probe result', 30000);
out.probe = await ev(`(() => { const o = document.getElementById('paProbeOut'); return { text: o.textContent.replace(/\\s+/g, ' '),
  chips: [...o.querySelectorAll('.pa-probe-cmp .df-chip')].map(c => c.textContent), stored: Object.keys(localStorage).filter(k => /probe|test-from/i.test(k)) }; })()`);
await shot('4-test-from-here', '#paProbeSec');

// 5. Phone width: nothing scrolls sideways with every panel open and a result shown.
await ev(`document.getElementById('paDevice').open = true; document.getElementById('paCompare').open = true; 1`);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(400);
out.narrow = await ev(`(() => { const W = document.documentElement.clientWidth;
  const wide = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > W + 1 && getComputedStyle(e).position !== 'fixed' && !(e.parentElement && e.parentElement.getBoundingClientRect().right > W + 1); }).map(e => e.tagName + '#' + e.id + '.' + e.className + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 8);
  return { overflow: document.documentElement.scrollWidth - W, wide }; })()`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("path-extras")
    shots = os.environ.get("PE_SHOTS_DIR") or str(tmp / "shots")
    os.makedirs(shots, exist_ok=True)
    mp = pytest.MonkeyPatch()
    server = Server("tls", _cert(tmp, "Zscaler Intermediate Root CA (zscalerthree.net) (test)", "Zscaler Inc.", "probe"))
    mp.setattr(pp, "ALLOW_LOOPBACK", True)
    mp.setattr(pp, "ALLOWED_PORTS", tuple(pp.ALLOWED_PORTS) + (server.port,))
    pp.reset_rate_limit()
    try:
        out = run_in_browser(tmp, DRIVER, shots, str(server.port), timeout=300)
    finally:
        mp.undo()
        server.close()
        pp.reset_rate_limit()
    out["dir"] = shots
    return out


def test_a_users_device_is_found_and_picked_from_the_keyboard(page):
    """WCAG 2.2 SC 2.1.1 · SC 4.1.3 · ASVS V4.1.3: Enter on Find devices lists only that user's device, focus moves to it, and picking it fixes the platform."""
    assert page["sample"] == 200 and len(page["found"]) == 1 and "LKF-CT-0003" in page["found"][0] and page["focusAfterFind"]
    c = page["chosen"]
    assert "Windows - Contractors" in c["card"] and c["platDisabled"] and c["platFrom"] == "Platform from the picked device: Windows" and c["focus"] == "paDevClear"


def test_the_result_says_which_profile_applied_and_what_is_unknown(page):
    """WCAG 2.2 SC 1.3.1 · ASVS V1.4.4: the device block sits under the verdict, names the applied profile and why, and marks what the API does not give."""
    d = page["device"]
    assert d["underVerdict"] and "App profile appliedWindows - Contractors" in d["text"] and "reports app profile" in d["text"]
    assert d["unknown"] >= 3 and d["rows"] == 13 and "Contractor - direct at the depot" in d["text"]
    assert "Never reaches Zscaler" in d["headline"]


def test_two_devices_are_compared_with_the_divergence_marked(page):
    """WCAG 2.2 SC 1.3.1 · SC 1.4.1: the first differing step is marked in words (not colour only), once; CSV and JSON are offered."""
    c = page["compare"]
    assert c["firsts"] == 1 and "Client Connector app profile" in c["first"] and "Paths diverge here" in c["first"]
    assert "diverge at Client Connector app profile" in c["headline"] and c["rows"] >= 5 and c["csv"] and c["json"]
    assert page["csv"] == 404   # an unknown comparison is not served


def test_test_from_here_shows_the_observation_beside_the_prediction(page):
    """WCAG 2.2 SC 1.3.1 · ASVS V12.6.1 · CWE-918: the result names where it was observed, the Zscaler issuer, and agrees or differs in words; nothing is stored in the browser."""
    p = page["probe"]
    assert "from the computer running this app" in p["text"] and "Zscaler Intermediate Root CA" in p["text"]
    assert p["chips"] and all(c in ("Agrees", "Differs", "Cannot tell") for c in p["chips"]) and p["stored"] == []


def test_nothing_scrolls_sideways_at_320px(page):
    """WCAG 2.2 SC 1.4.10: with both panels open and a result shown, the page fits 320px."""
    assert page["narrow"]["overflow"] == 0, page["narrow"]["wide"]


def test_a_screenshot_of_each_piece_is_saved(page):
    """WCAG 2.2 SC 1.4.10 (evidence): the device pick, the device result, the comparison and Test from here are each captured."""
    assert page["shots"] == ["1-device-pick", "2-device-result", "3-compare", "4-test-from-here"]
    assert all(os.path.getsize(os.path.join(page["dir"], n + ".png")) > 2000 for n in page["shots"])
