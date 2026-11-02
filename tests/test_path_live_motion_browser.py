"""The live path and the list flow in a real browser (headless Chrome over
CDP, as tests/test_findings_reflow.py drives it): the real app serves the
real pages; only the two job endpoints the pages poll answer with fixtures
(through the CDP Fetch domain), so no tenant is read and nothing waits on a
network. The result is the Path analyzer's own output for UDP/443 over the
fake tenant (blocked by the Cloud Firewall rule "Block QUIC").

Checked: the SVG renders and animates (its frame counter advances), stops
while the tab is hidden, draws its final picture and requests no frame
under prefers-reduced-motion (Play motion still starts it), keeps a text
alternative, opens a module's card from the keyboard, sits right under the
verdict, never scrolls the page sideways at 320 or 390 px, and the Test a
list flow counts climb from the job poll's tally. Skips without node or
Chrome.
"""
from __future__ import annotations

import json

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

DRIVER = CDP_PRELUDE + r"""
const F = JSON.parse(args[0]);
const handlers = [];
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } else if (m.method) handlers.forEach(h => h(m)); };
let bulkPolls = 0;
handlers.push(async m => {
  if (m.method !== 'Fetch.requestPaused') return;
  const u = m.params.request.url;
  let body = null;
  if (u.includes('/api/path-analyzer/start')) body = { job_id: 'pathjob', status: 'running' };
  else if (u.includes('/api/bulk-test/start')) body = { job_id: 'bulkjob', status: 'running', rows: F.bulk.flow.total };
  else if (u.includes('/jobs/pathjob')) body = { status: 'done', result: F.path, logs: ['Tracing the path hop by hop…'], next: 1, elapsed_seconds: 1 };
  else if (u.includes('/jobs/bulkjob')) { bulkPolls++; body = bulkPolls === 1 ? { status: 'running', logs: ['Tracing'], next: 1, progress: F.half } : { status: 'done', logs: [], next: 1, result: F.bulk, progress: F.bulk.flow }; }
  if (!body) { await send('Fetch.continueRequest', { requestId: m.params.requestId }); return; }
  await send('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
});
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/path-analyzer/start*' }, { urlPattern: '*/api/dlp-packs/jobs/*' }, { urlPattern: '*/api/bulk-test/start*' }] });
await send('Page.addScriptToEvaluateOnNewDocument', { source: `try { localStorage.setItem('zassess_path_last', ${JSON.stringify(JSON.stringify({ at: '2026-01-01T00:00:00Z', result: F.path }))}); } catch (e) {}` });
const frames = sel => ev(`+((document.querySelector(${JSON.stringify(sel)}) || {}).getAttribute ? (document.querySelector(${JSON.stringify(sel)}).getAttribute('data-tp-frames') || document.querySelector(${JSON.stringify(sel)}).getAttribute('data-lf-frames') || 0) : -1)`);
const overflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
async function go(url, width, reduce) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: reduce ? 'reduce' : 'no-preference' }] });
  await send('Page.navigate', { url: base + url });
  await until(() => ev(`document.readyState === 'complete'`), 'load ' + url);
}
const out = {};

// 1. Before any result: the reference path idles, animated, with its words.
await go('/report/path', 1280, false);
await until(() => ev(`!!document.querySelector('#paFlowRef svg .fa-box')`), 'the reference path');
const r0 = await frames('#paFlowRef'); await sleep(700); const r1 = await frames('#paFlowRef');
out.reference = await ev(`(() => { const svg = document.querySelector('#paFlowRef svg'), ol = document.getElementById(svg.getAttribute('aria-describedby'));
  return { boxes: document.querySelectorAll('#paFlowRef .fa-box').length, steps: ol ? ol.querySelectorAll('li').length : 0, role: svg.getAttribute('role'),
           btn: document.querySelector('#paFlowRef .tp-play').textContent }; })()`);
Object.assign(out.reference, { f0: r0, f1: r1 });

// 2. A hidden tab requests no frame; shown again, it moves on.
await ev(`Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }); document.dispatchEvent(new Event('visibilitychange')); 1`);
await sleep(150); const h0 = await frames('#paFlowRef'); await sleep(600); const h1 = await frames('#paFlowRef');
await ev(`Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }); document.dispatchEvent(new Event('visibilitychange')); 1`);
await sleep(500); const h2 = await frames('#paFlowRef');
out.hidden = { h0, h1, h2 };

// 3. Analyze: the live path sits under the verdict, animates and stops at the firewall.
await ev(`document.getElementById('paDest').value = 'chat.openai.com'; document.getElementById('paProto').value = 'udp'; document.getElementById('paPort').value = '443'; document.getElementById('paRun').click(); 1`);
await until(() => ev(`!!document.querySelector('#paFlowHost svg .fa-box')`), 'the live path', 20000);
const a0 = await frames('#paFlowHost'); await sleep(700); const a1 = await frames('#paFlowHost');
await until(() => ev(`[...document.querySelectorAll('#paFlowHost .tp-tag')].some(t => t.getAttribute('display') === 'inline')`), 'the stop marker', 20000);
out.result = await ev(`(() => { const sec = document.getElementById('paFlowSec');
  return { underVerdict: !!(sec.previousElementSibling && sec.previousElementSibling.classList.contains('pa-verdict')),
           tag: [...document.querySelectorAll('#paFlowHost .tp-tag')].filter(t => t.getAttribute('display') === 'inline').map(t => t.textContent),
           chips: document.querySelector('#paFlowHost .tp-head').textContent.replace(/\s+/g, ' '),
           steps: document.querySelectorAll('#paFlowHost .tp-steps li').length, boxes: document.querySelectorAll('#paFlowHost .fa-box').length,
           buttons: document.querySelectorAll('#paFlowHost .fa-box[role="button"][tabindex="0"]').length }; })()`);
Object.assign(out.result, { f0: a0, f1: a1 });

// 4. The keyboard: Enter on the Cloud Firewall step opens its module card.
await ev(`[...document.querySelectorAll('#paFlowHost .fa-box[role="button"]')].find(b => /Cloud Firewall/.test(b.getAttribute('aria-label'))).focus(); 1`);
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
await sleep(900);
out.card = await ev(`(() => { const c = document.querySelector('.pm-hop[data-module="firewall"]'), r = c.getBoundingClientRect();
  return { sel: c.classList.contains('sel'), focused: document.activeElement === c, inView: r.bottom > 0 && r.top < innerHeight }; })()`);

// 5. The second picture: hop by hop to Web DLP.
await ev(`document.querySelector('[data-flow-view="hops"]').click(); 1`);
out.hops = await ev(`({ hopView: !document.getElementById('paHopView').hidden, pathHidden: document.getElementById('paFlowHost').hidden, svg: !!document.querySelector('#paHopHost svg') })`);
await ev(`document.querySelector('[data-flow-view="path"]').click(); 1`);

// 6. Phone widths: the picture lays itself out again and the page never scrolls sideways.
out.narrow = {};
for (const width of [320, 390]) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await sleep(400);
  out.narrow[width] = await ev(`(() => { const svg = document.querySelector('#paFlowHost svg'), vb = svg.viewBox.baseVal;
    return { overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth, svgRight: Math.round(svg.getBoundingClientRect().right), W: document.documentElement.clientWidth, vbw: vb.width }; })()`);
}

// 7. Reduced motion: the final picture, no frame, Play motion starts it.
await go('/report/path', 390, true);
await until(() => ev(`!!document.querySelector('#paFlowRef svg .fa-box')`), 'the reference path (reduced)');
await sleep(600);
out.reduced = await ev(`({ frames: document.getElementById('paFlowRef').getAttribute('data-tp-frames'), btn: document.querySelector('#paFlowRef .tp-play').textContent,
  note: document.querySelector('#paFlowRef .tp-note').textContent, steps: document.querySelectorAll('#paFlowRef .tp-steps li').length })`);
await ev(`document.querySelector('#paFlowRef .tp-play').click(); 1`);
await sleep(600);
out.reduced.after = await frames('#paFlowRef');
out.reduced.overflow = await overflow();

// 8. Test a list: the counts climb from the job poll's tally.
await go('/report/path', 1280, false);
await ev(`document.getElementById('tab-list').click(); 1`);
await until(() => ev(`!document.getElementById('panel-list').hidden`), 'the list tab');
await ev(`document.getElementById('plText').value = 'a.example\\nb.example'; document.getElementById('plRun').click(); 1`);
await until(() => ev(`!document.getElementById('plFlow').hidden && !!document.querySelector('#plFlowHost svg')`), 'the list flow', 20000);
await until(() => ev(`/2 blocked/.test(document.querySelector('#plFlowHost .lf-tot').textContent)`), 'the first tally', 20000);
out.list = { half: await ev(`document.querySelector('#plFlowHost .lf-tot').textContent`) };
await until(() => ev(`!!document.getElementById('plSummary')`), 'the list result', 20000);
await sleep(1200);
Object.assign(out.list, await ev(`({ tot: document.querySelector('#plFlowHost .lf-tot').textContent, frames: +(document.getElementById('plFlowHost').getAttribute('data-lf-frames') || 0),
  alt: document.querySelectorAll('#plFlowHost .lf-alt li').length, role: document.querySelector('#plFlowHost svg').getAttribute('role') })`));

// 9. The Flow animator's replay: step back and forward, at a phone width.
await go('/report/motion#path', 390, false);
await until(() => ev(`!!document.querySelector('#tpHost svg .fa-box')`), 'the replay');
await ev(`document.querySelector('#tpHost .tp-back').click(); document.querySelector('#tpHost .tp-back').click(); 1`);
const back = await ev(`document.querySelector('#tpHost .tp-note').textContent`);
await ev(`document.querySelector('#tpHost .tp-next').click(); 1`);
out.replay = { back, next: await ev(`document.querySelector('#tpHost .tp-note').textContent`), src: await ev(`document.getElementById('tpSrc').textContent`),
  overflow: await overflow(), speed: await ev(`document.querySelectorAll('#tpHost .tp-speed-sel option').length`) };

console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def _fixtures():
    from test_path_zia_modules import run
    res = json.loads(json.dumps(run("chat.openai.com", "udp", 443), default=str))
    res.pop("snapshot_for_cache", None)
    flow = {"done": 12, "total": 12, "phase": "done", "results": {"blocked": 4, "allowed": 6, "bypassed": 1, "unverified": 1},
            "at": {"url": {"blocked": 3, "allowed": 4}, "firewall": {"blocked": 1, "allowed": 1}, "client_connector": {"bypassed": 1},
                   "zpa": {"allowed": 1}, "none": {"unverified": 1}}}
    half = {"done": 6, "total": 12, "phase": "trace", "results": {"blocked": 2, "allowed": 4}, "at": {"url": {"blocked": 2, "allowed": 3}, "zpa": {"allowed": 1}}}
    bulk = {"status": "done", "rows": 12, "run_id": "bulkjob", "counts": {"blocked": 4, "allowed": 6, "bypassed": 1, "unverified": 1},
            "preview": [], "lists": [], "top_rules": [], "top_categories": [], "assumptions": [], "flow": flow}
    return {"path": res, "bulk": bulk, "half": half}


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("live-motion"), DRIVER, json.dumps(_fixtures()), timeout=240)


def test_the_reference_path_renders_and_animates_before_any_result(page):
    """WCAG 2.2 SC 2.2.2 · SC 1.1.1: the idle reference path is an SVG whose frame counter advances, with its 16 steps in words."""
    r = page["reference"]
    assert r["boxes"] == 16 and r["steps"] == 16 and r["role"] == "group"
    assert r["f1"] > r["f0"] >= 0 and r["btn"] == "Pause motion"


def test_a_hidden_tab_stops_the_motion_and_showing_it_resumes(page):
    """WCAG 2.2 SC 2.2.2: no frame while the tab is hidden; frames again once it is shown."""
    h = page["hidden"]
    assert h["h1"] - h["h0"] <= 1 and h["h2"] > h["h1"]


def test_the_result_animates_under_the_verdict_and_stops_at_the_firewall(page):
    """WCAG 2.2 SC 2.2.2 · SC 1.3.1: after Analyze the path sits right under the verdict, animates, and ends with a block marker at the Cloud Firewall."""
    r = page["result"]
    assert r["underVerdict"] and r["f1"] > r["f0"]
    assert r["tag"] == ["■ blocked"] and r["boxes"] == r["steps"] == r["buttons"] == 16
    assert "UDP/443" in r["chips"] and "chat.openai.com" in r["chips"]


def test_enter_on_a_step_opens_and_focuses_its_module_card(page):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3: Enter on a step scrolls to its card, highlights it and moves focus there."""
    assert page["card"] == {"sel": True, "focused": True, "inView": True}


def test_the_hop_by_hop_chain_stays_as_the_second_picture(page):
    """WCAG 2.2 SC 1.3.1: the DLP hop-by-hop picture is still there, one press away."""
    assert page["hops"] == {"hopView": True, "pathHidden": True, "svg": True}


@pytest.mark.parametrize("width", [320, 390])
def test_the_live_path_never_scrolls_the_page_sideways_on_a_phone(page, width):
    """WCAG 2.2 SC 1.4.10: at 320 and 390 px the path lays itself out in the width it has; nothing passes the right edge."""
    n = page["narrow"][str(width)]
    assert n["overflow"] == 0 and n["svgRight"] <= n["W"] and n["vbw"] <= n["W"], n


def test_reduced_motion_requests_no_frame_and_play_starts_it(page):
    """WCAG 2.2 SC 2.3.3 · SC 2.2.2: with reduced motion the picture is still, says so in words and offers Play motion, which works."""
    r = page["reduced"]
    assert r["frames"] is None and r["btn"] == "Play motion" and r["steps"] == 16
    assert r["note"].startswith("Motion is off because your system asks for reduced motion")
    assert r["after"] > 0 and r["overflow"] == 0


def test_the_list_flow_counts_climb_from_the_job_poll(page):
    """WCAG 2.2 SC 2.2.2 · SC 1.1.1: while the list job runs the tally on each poll moves the counts; the end matches the result, in words too."""
    r = page["list"]
    assert r["half"] == "2 blocked · 4 allowed · 0 bypassed · 1 ZPA"
    assert r["tot"] == "4 blocked · 6 allowed · 1 bypassed · 1 ZPA" and r["frames"] > 0 and r["role"] == "img" and r["alt"] == 10


def test_the_flow_animator_replays_the_result_step_by_step(page):
    """WCAG 2.2 SC 2.2.2 · SC 2.1.1 · SC 1.4.10: the replay steps back and forward with a speed choice, from the kept result, without sideways scroll."""
    r = page["replay"]
    assert r["back"].startswith("Step ") and r["next"].startswith("Step ") and r["back"] != r["next"]
    assert "From the Path analyzer" in r["src"] and r["speed"] == 3 and r["overflow"] == 0
