"""What the glass effect costs to draw, measured in a real browser (headless
Chrome over CDP, the harness of tests/test_findings_reflow.py; skipped
without node or Chrome). Headless Chrome draws without a graphics card, as a
slow office computer does, so the compositor's own trace (Display::
DrawAndSwap: how many frames it drew and how long drawing them took) shows
what the backdrop blur costs.

Guarded: with nothing moving on the page, the backdrop's drift draws about
one frame a second (it drew four or more a second per layer, each one
re-blurring every glass layer); while the page scrolls, the cards and hero
in the page flow drop their blur (only the soft backdrop is behind them, so
they look the same) and floating bars keep theirs, and the blur comes back
when scrolling stops; drawing a scrolled second with the glass on costs at
most a bounded multiple of drawing it with the glass off (it was about
sixteen times on the Team server page); under prefers-reduced-motion
nothing is drawn while nothing moves. The numbers measured are kept in the
result for the record (GLASS_PERF=1 prints them).

Run it alone and once under `taskset -c 0,1` (two CPUs, as the CI runners)."""
from __future__ import annotations

import json
import os

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS

PAGE = "/report/team"
IDLE_MS = 3000
SCROLL_MS = 3000

DRIVER = CDP_PRELUDE + "process.env.UI_DEADLINE_MS = process.env.UI_DEADLINE_MS || '240000';\n" + EVENTS + r"""
const [page, idleMs, scrollMs] = args;
const out = { errors: [] };
const safe = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'ERR ' + String(e.message).slice(0, 300); } };
// Frames the compositor drew and the time it spent drawing them, while fn runs.
const traced = async fn => {
  const events = []; let done = null;
  const prev = ws.onmessage;
  ws.onmessage = e => { prev(e); const m = JSON.parse(e.data); if (m.method === 'Tracing.dataCollected') events.push(...m.params.value); if (m.method === 'Tracing.tracingComplete') done(); };
  await send('Tracing.start', { categories: 'viz', transferMode: 'ReportEvents' });
  const r = await fn();
  const fin = new Promise(res => { done = res; });
  await send('Tracing.end'); await fin;
  ws.onmessage = prev;
  const draws = events.filter(e => e.name === 'Display::DrawAndSwap');
  return Object.assign(r || {}, { frames: draws.length, drawMs: Math.round(draws.reduce((a, e) => a + (e.dur || 0), 0) / 1000) });
};
const idle = () => ev(`new Promise(r => setTimeout(() => r({}), ${Number(idleMs)}))`);
// Scroll the page up and down, 40px a frame, and say what was blurred mid-scroll.
const scroll = () => ev(`new Promise(r => { let n = 0; const t0 = performance.now(); let dir = 1, mid = null;
  const blurred = () => [...document.querySelectorAll('*')].filter(e => { const f = getComputedStyle(e).backdropFilter; return f && f !== 'none'; }).map(e => e.id || e.className.split(' ')[0] || e.tagName);
  const step = now => { n++; window.scrollBy(0, 40 * dir); if (window.scrollY + innerHeight >= document.documentElement.scrollHeight - 2) dir = -1; if (window.scrollY <= 0) dir = 1;
    if (!mid && now - t0 > 500) mid = { cls: document.documentElement.classList.contains('glass-scrolling'), blurred: blurred() };
    if (now - t0 < ${Number(scrollMs)}) requestAnimationFrame(step); else r({ fps: Math.round(n * 1000 / (now - t0)), mid }); };
  requestAnimationFrame(step); })`);
// Make the page tall enough to scroll: more glass cards like its own.
const fill = `(() => { const m = document.querySelector('main'); for (let i = 0; i < 12; i++) { const d = document.createElement('section'); d.className = 'rp-card'; d.style.margin = '12px 0';
  const h = document.createElement('h2'); h.textContent = 'Card ' + i; const p = document.createElement('p'); p.textContent = 'Words on a glass card. '.repeat(20); d.append(h, p); m.appendChild(d); }
  return document.documentElement.scrollHeight > innerHeight * 2; })()`;
const blurredNow = () => ev(`[...document.querySelectorAll('*')].filter(e => { const f = getComputedStyle(e).backdropFilter; return f && f !== 'none'; }).map(e => e.id || e.className.split(' ')[0] || e.tagName)`);
const open = async off => {
  await go(page); await settle(page);
  await ev(`(localStorage.setItem('zassess_glass', ${off ? "'off'" : "'on'"}), 1)`);
  await go(page); await settle(page);
  await ev(fill);
  await ev(`new Promise(r => setTimeout(() => r(1), 400))`);   // the glass-fit marks of the new cards
};
for (const off of [false, true]) {
  const k = off ? 'off' : 'on';
  await open(off);
  await safe(k + 'Rest', blurredNow);
  await safe(k + 'Idle', () => traced(idle));
  await safe(k + 'Scroll', () => traced(scroll));
  await safe(k + 'After', () => ev(`new Promise(r => setTimeout(() => r({ cls: document.documentElement.classList.contains('glass-scrolling') }), 600))`).then(async x => Object.assign(x, { blurred: await blurredNow() })));
}
await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: 'reduce' }] });
await open(false);
await safe('reducedIdle', () => traced(idle));
out.errors = seen.errors.filter(e => !/favicon/.test(e));
console.log(JSON.stringify(out));
p.kill();
process.exit(0);
"""


@pytest.fixture(scope="module")
def perf(tmp_path_factory):
    out = run_in_browser(tmp_path_factory.mktemp("glass-perf"), DRIVER, PAGE, str(IDLE_MS), str(SCROLL_MS), timeout=300)
    if os.environ.get("GLASS_PERF"):
        print("GLASS_PERF", json.dumps({k: v for k, v in out.items() if k != "errors"}))
    bad = {k: v for k, v in out.items() if isinstance(v, str) and v.startswith("ERR ")}
    assert not bad, bad
    return out


def test_with_nothing_moving_the_backdrop_draws_about_one_frame_a_second(perf):
    """WCAG 2.2 SC 2.3.3 · CWE-400 · CWE-1050: an idle glass page draws at most about one frame a second (the drift's steps on both layers fall together); it drew fifteen a second, each re-blurring every glass layer."""
    frames = perf["onIdle"]["frames"]
    assert frames <= IDLE_MS / 1000 * 2 + 2, perf["onIdle"]


def test_under_reduced_motion_nothing_is_drawn_while_nothing_moves(perf):
    """WCAG 2.2 SC 2.3.3 · CWE-1050: with prefers-reduced-motion the drift stands still, so an idle page draws (almost) nothing."""
    assert perf["reducedIdle"]["frames"] <= 3, perf["reducedIdle"]


def test_while_scrolling_only_the_floating_glass_stays_blurred_and_the_blur_comes_back(perf):
    """WCAG 2.2 SC 1.4.3 · CWE-1050: at rest the cards and the hero are blurred glass; mid-scroll html.glass-scrolling is set and only floating chrome (the page bar, the theme button) keeps its blur; 600 ms after the scroll the blur is back on the same surfaces."""
    rest, mid, after = perf["onRest"], perf["onScroll"]["mid"], perf["onAfter"]
    assert "rp-card" in rest and "hero" in rest, rest
    assert mid["cls"] is True and "rp-card" not in mid["blurred"] and "hero" not in mid["blurred"] and "sb-row" not in mid["blurred"], mid
    assert mid["blurred"] and set(mid["blurred"]) < set(rest), (mid, rest)
    assert after["cls"] is False and sorted(after["blurred"]) == sorted(rest), (after, rest)


def test_a_scrolled_second_with_the_glass_costs_a_bounded_multiple_of_one_without(perf):
    """CWE-400 · CWE-1050: drawing the scrolled page with the glass on takes at most ten times the drawing time with it off (it was about sixteen times on this page before the in-flow blur was dropped while scrolling), and the page keeps drawing frames while it scrolls."""
    on, off = perf["onScroll"], perf["offScroll"]
    assert on["frames"] >= SCROLL_MS / 1000 * 10, on
    assert on["drawMs"] <= 10 * max(off["drawMs"], 100), (on, off)


def test_the_glass_off_page_blurs_nothing_and_no_script_errors(perf):
    """WCAG 2.2 SC 4.1.2 · CWE-1050: with the glass switched off nothing is blurred at rest or while scrolling; no script error on the way."""
    assert perf["offRest"] == [] and perf["offScroll"]["mid"]["blurred"] == []
    assert not perf["errors"], perf["errors"]
