"""The traffic motion on the Data Flow Map, SSL flow and SSL coverage pages,
in a real headless Chrome over CDP (node + Chrome; skips when either is
missing), against reports the app's own code builds from fake tenant reads:
the picture renders, its packets move, reduced motion starts it still with
a working Play button, it stops while the tab is hidden, it has a text
alternative with the page's own numbers, a stream is keyboard operable, the
page never scrolls sideways at 320 or 390 px, and a hostile tenant string
stays text. Table-driven over the three pages."""
from __future__ import annotations

import json

import pytest

import flow_motion_fixtures as fx
from test_findings_reflow import CDP_PRELUDE, run_in_browser

PAGES = {
    "dataflow": {"route": "/report/dataflow", "svg": "#dfMotionStage svg.fa-river", "button": "#dfMotionPlay", "alt": "#dfMotionAlt"},
    "sslflow": {"route": "/report/sslflow", "svg": "#sfWalkStage svg.fa-walk", "button": "#sfMotionPlay", "alt": "#sfWalkAlt"},
    "sslcoverage": {"route": "/report/sslcoverage", "svg": "#scRiverTraffic svg.fa-river", "button": "#scRiverPlay", "alt": "#scRiverAlt"},
}

DRIVER = CDP_PRELUDE + r"""
const [pagesJson] = args;
const pages = JSON.parse(pagesJson);
const out = {};
const errors = [];
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.text + ' ' + JSON.stringify((m.params.exceptionDetails.exception || {}).description || '').slice(0, 200)); });
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
const dots = sel => ev(`[...document.querySelectorAll('${sel} .fa-dot.pk')].map(d => (d.getAttribute('cx') || '') + ',' + (d.getAttribute('cy') || '')).join(';')`);
async function open(p, width, reduce) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: reduce ? 'reduce' : 'no-preference' }] });
  await send('Page.navigate', { url: base + p.route + '?id=' + encodeURIComponent(p.id) });
  await until(() => ev(`document.readyState === 'complete' && !!document.querySelector('${p.svg}') && document.querySelectorAll('${p.svg} .fa-dot.pk').length > 0`), p.route + ' picture');
}
for (const [name, p] of Object.entries(pages)) {
  const r = out[name] = {};
  // Normal motion: packets are drawn and move; the button offers Pause.
  await open(p, 1280, false);
  r.packets = await ev(`document.querySelectorAll('${p.svg} .fa-dot.pk').length`);
  await until(() => ev(`[...document.querySelectorAll('${p.svg} .fa-dot.pk')].every(d => d.hasAttribute('cx'))`), 'first frame', 5000).catch(() => null);
  const a = await dots(p.svg);
  r.moves = !!(await until(async () => (await dots(p.svg)) !== a, 'packets moving', 5000).catch(() => false));
  r.button = await ev(`(() => { const b = document.querySelector('${p.button}'); return { text: b.textContent, pressed: b.getAttribute('aria-pressed'), tag: b.tagName, type: b.type }; })()`);
  // Pause stops it; Play starts it again.
  await ev(`document.querySelector('${p.button}').click(), 1`);
  await frames(2);
  const paused = await dots(p.svg); await frames(12);
  r.pauseStops = (await dots(p.svg)) === paused;
  r.pausedButton = await ev(`document.querySelector('${p.button}').textContent`);
  await ev(`document.querySelector('${p.button}').click(), 1`);
  r.playResumes = !!(await until(async () => (await dots(p.svg)) !== paused, 'resumed', 5000).catch(() => false));
  // A hidden tab stops the clock; showing it again restarts it.
  await ev(`(Object.defineProperty(document, 'hidden', { configurable: true, get: () => true }), document.dispatchEvent(new Event('visibilitychange')), 1)`);
  await frames(3);
  const hidden = await dots(p.svg); await frames(12);
  r.hiddenStops = (await dots(p.svg)) === hidden;
  await ev(`(Object.defineProperty(document, 'hidden', { configurable: true, get: () => false }), document.dispatchEvent(new Event('visibilitychange')), 1)`);
  r.visibleResumes = !!(await until(async () => (await dots(p.svg)) !== hidden, 'visible again', 5000).catch(() => false));
  // Text alternative: the picture points at a list of words.
  r.alt = await ev(`(() => { const s = document.querySelector('${p.svg}'), id = s.getAttribute('aria-describedby'), el = id && document.getElementById(id);
    return { describedBy: id, items: el ? el.querySelectorAll('li').length : 0, text: el ? el.textContent : '', label: s.getAttribute('aria-label') || '', role: s.getAttribute('role') }; })()`);
  // Keyboard: a stream (or the walk) takes focus; Enter on a stream lists what it carries.
  r.focusable = await ev(`(() => { const t = document.querySelector('${p.svg} .fa-band') || document.querySelector('${p.svg}'); t.focus(); return document.activeElement === t; })()`);
  if (name !== 'sslflow') {
    await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
    await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
    await frames(2);
    r.pick = await ev(`(() => { const box = document.querySelector('#dfMotionPick, #scRiverPick'); const a = box && box.querySelector('a[href^="#dfRow-"]');
      return { text: box ? box.textContent : '', live: box ? box.getAttribute('aria-live') : '', link: a ? a.getAttribute('href') : null,
               rowExists: a ? !!document.querySelector(a.getAttribute('href')) : null, focusInPick: !!(box && box.contains(document.activeElement)) }; })()`);
    if (r.pick.link) {
      await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
      await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
      await frames(2);
      r.rowFocused = await ev(`(() => { const e = document.activeElement; return !!(e && e.classList.contains('df-row') && e.classList.contains('sel')); })()`);
    }
  }
  // Reduced motion: drawn still, the button offers Play, and Play starts it.
  await open(p, 1280, true);
  await frames(6);
  r.reducedStill = await ev(`[...document.querySelectorAll('${p.svg} .fa-dot.pk')].every(d => !d.hasAttribute('cx'))`);
  r.cssStill = await ev(`[...document.querySelectorAll('.sf-edge.flow, .df-edge')].every(e => getComputedStyle(e).animationName === 'none')`);
  r.reducedButton = await ev(`(() => { const b = document.querySelector('${p.button}'); return { text: b.textContent, pressed: b.getAttribute('aria-pressed') }; })()`);
  await ev(`document.querySelector('${p.button}').click(), 1`);
  r.reducedPlay = !!(await until(() => ev(`[...document.querySelectorAll('${p.svg} .fa-dot.pk')].some(d => d.hasAttribute('cx'))`), 'played', 5000).catch(() => false));
  // Reflow: no sideways page scroll on a phone.
  r.overflow = {};
  for (const w of [320, 390]) {
    await open(p, w, false);
    r.overflow[w] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  }
}
// Hostile tenant strings stay text.
const hostile = JSON.parse(args[1]);
out.xss = {};
for (const [name, p] of Object.entries(hostile)) {
  await open(p, 1280, false);
  if (name === 'sslflow') { await ev(`(() => { const n = document.querySelector('.sf-node[data-key="file_share"]'); n.dispatchEvent(new MouseEvent('click', { bubbles: true })); return 1; })()`); await frames(3); }
  out.xss[name] = await ev(`({ fired: window.__xss === 1, imgs: document.querySelectorAll('img[src="x"]').length })`);
}
out.errors = errors;
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def motion(tmp_path_factory):
    import dlp_api_server as srv
    kinds = {"dataflow": fx.dataflow_report, "sslflow": fx.sslflow_report, "sslcoverage": fx.sslcoverage_report}
    pages, hostile, made = {}, {}, []
    for name, build in kinds.items():
        rid = srv._remember_report(name, build(), "Fixture tenant")
        hid = srv._remember_report(name, build(hostile=True), "Fixture tenant")
        made += [rid, hid]
        pages[name] = dict(PAGES[name], id=rid)
        hostile[name] = dict(PAGES[name], id=hid)
    try:
        return run_in_browser(tmp_path_factory.mktemp("flow-motion"), DRIVER, json.dumps(pages), json.dumps(hostile), timeout=240)
    finally:
        for rid in made:
            srv._REPORTS.pop(rid, None)


NAMES = list(PAGES)


@pytest.mark.parametrize("page", NAMES)
def test_the_picture_renders_and_animates(motion, page):
    """WCAG 2.2 SC 2.2.2: the picture is drawn from the page's result with packets that move, and the button offers Pause."""
    r = motion[page]
    assert r["packets"] > 0 and r["moves"], r
    assert r["button"] == {"text": "Pause motion", "pressed": "true", "tag": "BUTTON", "type": "button"}


@pytest.mark.parametrize("page", NAMES)
def test_pause_stops_and_play_resumes(motion, page):
    """WCAG 2.2 SC 2.2.2 (Pause, Stop, Hide): Pause freezes every packet, Play moves them again."""
    r = motion[page]
    assert r["pauseStops"] and r["pausedButton"] == "Play motion" and r["playResumes"], r


@pytest.mark.parametrize("page", NAMES)
def test_a_hidden_tab_stops_the_motion(motion, page):
    """WCAG 2.2 SC 2.2.2 · CWE-400: nothing animates while the tab is hidden, and it resumes when shown."""
    r = motion[page]
    assert r["hiddenStops"] and r["visibleResumes"], r


@pytest.mark.parametrize("page", NAMES)
def test_reduced_motion_starts_still_with_a_play_button(motion, page):
    """WCAG 2.2 SC 2.3.3 (Animation from Interactions): with reduced motion nothing moves until Play is pressed."""
    r = motion[page]
    assert r["reducedStill"], r
    assert r["reducedButton"] == {"text": "Play motion", "pressed": "false"}
    assert r["reducedPlay"], "Play starts the motion on request"


@pytest.mark.parametrize("page", NAMES)
def test_reduced_motion_also_stills_the_dashed_edges(motion, page):
    """WCAG 2.2 SC 2.3.3: the CSS dash animation on the SSL flow and path diagrams stops under reduced motion (it ran on the SSL flow before)."""
    assert motion[page]["cssStill"] is True


@pytest.mark.parametrize("page", NAMES)
def test_the_picture_has_a_text_alternative_with_the_page_numbers(motion, page):
    """WCAG 2.2 SC 1.1.1 (Non-text Content): the picture is labelled and described by a list of words with the page's numbers."""
    r = motion[page]
    alt = r["alt"]
    assert alt["describedBy"] and alt["items"] >= 3 and alt["label"], alt
    if page == "dataflow":
        s = fx.dataflow_report()["summary"]
        assert f"Never reach Zscaler: {s['bypassed']}" in alt["text"] and f"A DLP rule can block: {s['enforced']}." in alt["text"]
    elif page == "sslflow":
        assert "decides" in alt["text"] and "Then: " in alt["text"]
    else:
        assert "inspected" in alt["text"] and "Causes found: " in alt["text"]


@pytest.mark.parametrize("page", NAMES)
def test_a_stream_is_keyboard_operable(motion, page):
    """WCAG 2.2 SC 2.1.1 (Keyboard) · SC 4.1.3: a stream takes focus, and Enter announces what it carries in a live region."""
    r = motion[page]
    assert r["focusable"], r
    if page == "sslflow":
        return
    assert r["pick"]["live"] == "polite" and r["pick"]["text"], r["pick"]
    if page == "dataflow":
        assert r["pick"]["link"] and r["pick"]["rowExists"] and r["pick"]["focusInPick"], r["pick"]
        assert r["rowFocused"], "a path's link takes the keyboard to its row in the table"


@pytest.mark.parametrize("width", ["320", "390"])
@pytest.mark.parametrize("page", NAMES)
def test_no_sideways_scroll_on_a_phone(motion, page, width):
    """WCAG 2.2 SC 1.4.10 (Reflow): with the motion drawn, the page is no wider than a 320 or 390 px window."""
    assert motion[page]["overflow"][width] == 0, motion[page]["overflow"]


@pytest.mark.parametrize("page", NAMES)
def test_a_hostile_tenant_name_stays_text(motion, page):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: a rule name carrying markup is drawn as text in the picture and never runs."""
    x = motion["xss"][page]
    assert x["fired"] is False and x["imgs"] == 0, x


def test_no_script_error_while_animating(motion):
    """CWE-755: the three pages animate, pause, hide and replay without a script error."""
    assert motion["errors"] == [], motion["errors"]
