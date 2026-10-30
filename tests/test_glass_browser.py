"""The glass effect in a real browser (headless Chrome over CDP, the harness
of tests/test_findings_reflow.py), on the sample tenant.

One Chrome opens the sample tenant and runs the assessment (so the dashboard
and its cards are full), then visits every page styled by the app's own
stylesheet, in the dark and the light theme, and measures:
  - the glass layer is applied (the material on its surfaces, the blur on
    the chrome, the backdrop of colour fields behind);
  - text on every glass surface keeps WCAG 2.2 AA contrast against the worst
    case behind it (pure white and pure black behind floating chrome; the
    brightest and darkest point of the backdrop's colour fields behind
    surfaces in the flow and behind the sidebar where it sits beside the
    page; with and without the sheen and the pointer lens);
  - no fixed element sits inside a blurred one (backdrop-filter makes its
    element the containing block of fixed descendants), the number of blurred
    layers stays small and no table is blurred;
  - no horizontal scroll at 320 and 390 px with the glass on.
Then: prefers-reduced-transparency, prefers-contrast: more, forced colours
and print (Emulation.setEmulatedMedia) turn every surface solid and remove
the blur; the "Glass effect" switch in Advanced settings turns it off and the
choice survives a reload and reaches other pages; the pointer lens follows
the pointer and is off under prefers-reduced-motion; the focus ring stays
visible on a glass button; the backdrop drifts, stands still under
prefers-reduced-motion, pauses while the tab is hidden, and is gone when the
glass is off, under reduced transparency and forced colours; it never makes
the page scroll sideways at 320 px. Skips without node or Chrome. No real
tenant."""
from __future__ import annotations

import json
import os

import pytest

import dlp_api_server as srv
from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS, sample_setup

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


def _glass_routes():
    """Every page styled by app.css (the reference documents and /permissions carry their own look)."""
    routes = sorted({r.path for r in srv.app.routes if getattr(r, "methods", None) and "GET" in r.methods and "{" not in r.path
                     and (r.path.startswith("/report/") or r.path in ("/", "/simple", "/help"))})
    assert len(routes) >= 34, routes
    return routes


ROUTES = _glass_routes()
THEMES = ("dark", "light")
MAX_BLURRED = 16   # blurred layers on one page at once: chrome only, never per card or per row

# What the page shows of the glass, and the worst-case contrast of the text on it.
AUDIT = r"""(() => {
  const vis = e => { const r = e.getBoundingClientRect(); const s = getComputedStyle(e); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none' && !e.closest('[aria-hidden="true"],[inert],details:not([open]) > :not(summary)'); };
  const desc = e => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + '.' + String(e.className.baseVal ?? e.className).trim().split(/\s+/).slice(0, 2).join('.') + ' "' + (e.getAttribute('aria-label') || e.textContent || '').trim().replace(/\s+/g, ' ').slice(0, 30) + '"';
  const rgba = s => { s = String(s || '').trim(); let m = s.match(/rgba?\(([^)]+)\)/); if (m) { const v = m[1].split(/[ ,\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; }
    m = s.match(/color\(srgb\s+([^)]+)\)/); if (m) { const v = m[1].split(/[ \/]+/).filter(Boolean).map(Number); return { r: v[0] * 255, g: v[1] * 255, b: v[2] * 255, a: v.length > 3 ? v[3] : 1 }; }
    if (s === 'transparent') return { r: 0, g: 0, b: 0, a: 0 }; return null; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const mix = (x, y, p) => ({ r: x.r * p + y.r * (1 - p), g: x.g * p + y.g * (1 - p), b: x.b * p + y.b * (1 - p), a: x.a * p + y.a * (1 - p) });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const hex = c => '#' + [c.r, c.g, c.b].map(v => Math.round(v).toString(16).padStart(2, '0')).join('');
  const WHITE = { r: 255, g: 255, b: 255, a: 1 }, BLACK = { r: 0, g: 0, b: 0, a: 1 };
  const out = { on: !document.documentElement.classList.contains('glass-off') };
  const surf = e => parseInt(getComputedStyle(e).getPropertyValue('--glass-surface'), 10) || 0;
  const all = [...document.querySelectorAll('body *')];
  const surfaces = all.filter(e => surf(e) > 0 && vis(e));
  const blurred = all.filter(e => /blur\(/.test(getComputedStyle(e).backdropFilter || '') && vis(e));
  out.surfaces = surfaces.length;
  out.blurred = blurred.map(desc);
  out.opaque = surfaces.filter(e => { const c = rgba(getComputedStyle(e).backgroundColor); return c && c.a >= 0.999; }).length;
  out.wash = getComputedStyle(document.body, '::before').backgroundImage;
  out.wash2 = getComputedStyle(document.body, '::after').backgroundImage;
  out.cardsBlurred = blurred.filter(e => e.matches('.rp-card, .container .card, .xp-details')).length;
  // A fixed element inside a blurred one is positioned against it, not the window.
  // (A fixed element that is not drawn is left out: the sidebar's drop marker shows only while an item is dragged, and the
  // sidebar drops its blur for that; checked on its own below.)
  out.fixedInBlur = all.filter(e => getComputedStyle(e).position === 'fixed' && getComputedStyle(e).display !== 'none' && blurred.some(b => b !== e && b.contains(e))).map(desc).slice(0, 6);
  const sb = document.getElementById('dbSidebar');
  if (sb) { const was = getComputedStyle(sb).backdropFilter; sb.classList.add('sb-dragging'); out.sidebarDrag = { resting: was, dragging: getComputedStyle(sb).backdropFilter }; sb.classList.remove('sb-dragging'); }
  out.tallBlur = blurred.filter(e => e.getBoundingClientRect().height > innerHeight + 1).map(desc).slice(0, 6);
  out.tables = [...document.querySelectorAll('table')].filter(vis).filter(t => { const s = getComputedStyle(t); const c = rgba(s.backgroundColor); return /blur\(/.test(s.backdropFilter || '') || (surfaces.some(g => g.contains(t)) && c && c.a > 0 && c.a < 0.95); }).map(desc).slice(0, 6);
  // The backdrop: the page colour, each colour field's peak, and each pair half and half.
  const bs = getComputedStyle(document.body), bg = rgba(bs.backgroundColor);
  const peaks = [1, 2, 3, 4, 5].map(i => rgba(bs.getPropertyValue('--glass-amb-' + i))).filter(c => c && c.a > 0);
  const washOn = (out.wash && out.wash !== 'none') || (out.wash2 && out.wash2 !== 'none');
  out.fields = peaks.length;
  // A fixed surface beside the page (the sidebar on a wide screen): no other content shares its columns, so only the
  // backdrop is ever behind it (the page scrolls up and down, never under it).
  const besideCache = new Map();
  const beside = n => { if (!besideCache.has(n)) { const r = n.getBoundingClientRect();
    besideCache.set(n, !all.some(o => { if (o === n || n.contains(o) || o.contains(n)) return false; const q = o.getBoundingClientRect();
      // (an element above the top of the document, a skip link waiting for focus, can never scroll behind it)
      return q.width > 0 && q.height > 0 && q.bottom + scrollY > 0 && q.left < r.right - 1 && q.right > r.left + 1 && getComputedStyle(o).visibility !== 'hidden'; })); }
    return besideCache.get(n); };
  const ambient = [bg].concat(washOn ? peaks.map(p => over(p, bg)).concat(peaks.flatMap((a, i) => peaks.slice(i + 1).map(b => over(mix(a, b, 0.5), bg)))) : []);
  out.ambient = ambient.length;
  // Text on glass: the layers from the text up to what is behind the glass.
  out.contrast = []; out.measured = 0; out.lowest = 99;
  const texts = all.filter(e => [...e.childNodes].some(n => n.nodeType === 3 && n.nodeValue.trim()) && vis(e) && !e.closest('svg, option, [disabled], [aria-disabled="true"], .sr-only'));
  for (const e of texts.slice(0, 2500)) {
    let o = 1; for (let n = e; n && n.nodeType === 1; n = n.parentElement) o *= parseFloat(getComputedStyle(n).opacity || '1');
    if (o < 0.5) continue;   // a dimmed, inactive control (SC 1.4.3 exempts it)
    const layers = []; let bases = null, glass = false, image = false;
    for (let n = e; n; n = n.parentElement) {
      const s = getComputedStyle(n);
      if (n === document.body) { bases = ambient; break; }
      const g = surf(n);
      if (s.backgroundImage !== 'none' && !g && !/^url\(/.test(s.backgroundImage)) { image = true; break; }
      const c = rgba(s.backgroundColor) || { r: 0, g: 0, b: 0, a: 0 };
      const extras = [];
      if (g) { glass = true; const sh = rgba(s.getPropertyValue('--glass-sheen')); if (sh && sh.a > 0 && /linear-gradient/.test(s.backgroundImage)) extras.push(sh);
               const lens = rgba(s.getPropertyValue('--glass-lens-on')); if (lens && lens.a > 0 && /radial-gradient/.test(s.backgroundImage)) extras.push(lens); }
      layers.push({ c, extras });
      if (c.a >= 0.999 && !g) { bases = [{ r: 0, g: 0, b: 0, a: 0 }]; break; }
      if (g && g < 3 && s.position === 'fixed' && beside(n)) { bases = ambient; break; }
      if (g >= 3 || s.position === 'fixed' || s.position === 'sticky' || n.tagName === 'DIALOG') { bases = [WHITE, BLACK]; break; }
    }
    if (!glass || image || !bases) continue;
    const s = getComputedStyle(e); const fg0 = rgba(s.color); if (!fg0 || fg0.a === 0) continue;
    const size = parseFloat(s.fontSize), bold = parseInt(s.fontWeight, 10) >= 700, need = (size >= 24 || (bold && size >= 18.66)) ? 3 : 4.5;
    let low = 99, at = '';
    for (const base of bases) for (const withExtras of [false, true]) {
      let c = base.a ? base : WHITE;
      for (const l of [...layers].reverse()) { c = over(l.c, c); if (withExtras) for (const x of l.extras) c = over(x, c); }
      const fg = over(fg0, c), r = ratio(fg, c);
      if (r < low) { low = r; at = hex(fg) + ' on ' + hex(c); }
    }
    out.measured++; out.lowest = Math.min(out.lowest, low);
    if (low + 0.02 < need) out.contrast.push(desc(e) + ' ' + low.toFixed(2) + ':1 (' + at + ')');
  }
  out.contrast = [...new Set(out.contrast)].slice(0, 12);
  out.lowest = Math.round(out.lowest * 100) / 100;
  return out;
})()"""

SOLID = r"""(() => {
  const vis = e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.height > 0 && getComputedStyle(e).display !== 'none'; };
  const all = [...document.querySelectorAll('body *')].filter(vis);
  const surfaces = all.filter(e => (parseInt(getComputedStyle(e).getPropertyValue('--glass-surface'), 10) || 0) > 0);
  const alpha = s => { const m = String(s).match(/rgba?\(([^)]+)\)|color\(srgb\s+([^)]+)\)/); if (!m) return 1; const v = (m[1] || m[2]).split(/[ ,\/]+/).filter(Boolean); return v.length > 3 ? Number(v[3]) : 1; };
  return { surfaces: surfaces.length,
    blurred: all.filter(e => /blur\(/.test(getComputedStyle(e).backdropFilter || '')).length,
    clear: surfaces.filter(e => alpha(getComputedStyle(e).backgroundColor) < 0.999).map(e => e.tagName + '.' + String(e.className).split(' ')[0]).slice(0, 6),
    sheen: surfaces.filter(e => getComputedStyle(e).backgroundImage !== 'none').length,
    wash: getComputedStyle(document.body, '::before').backgroundImage, wash2: getComputedStyle(document.body, '::after').backgroundImage };
})()"""

# The backdrop: its layers, its colour fields and the state of its drift.
BACKDROP = r"""(() => {
  const b = document.body, s1 = getComputedStyle(b, '::before'), s2 = getComputedStyle(b, '::after');
  const anims = document.getAnimations().filter(a => a.effect && /^::(before|after)$/.test(a.effect.pseudoElement || ''));
  const n = s => (String(s.backgroundImage).match(/radial-gradient/g) || []).length;
  return { fields: n(s1) + n(s2), before: s1.backgroundImage !== 'none', after: s2.backgroundImage !== 'none',
    running: anims.filter(a => a.playState === 'running').length, paused: anims.filter(a => a.playState === 'paused').length,
    still: document.documentElement.classList.contains('glass-still'),
    overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth };
})()"""

DRIVER = CDP_PRELUDE + "process.env.UI_DEADLINE_MS = process.env.UI_DEADLINE_MS || '840000';\n" + EVENTS + "%SETUP%" + r"""
const [routesJson, themesJson, auditJs, solidJs, backdropJs] = args;
// A page load may take a while on a busy machine: 60 s, not the shared 20 s.
const load = async url => { await send('Page.navigate', { url: base + url }); await until(() => ev(`document.readyState === 'complete'`), url + ' load', 60000); };
const routes = JSON.parse(routesJson);
const out = { run, pages: {}, solid: {}, reflow: {}, errors: [] };
const media = async (features, type = '') => send('Emulation.setEmulatedMedia', { media: type, features });
const frames = () => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
// 1. Every page, both themes, glass on: applied, contrast, structure.
for (const theme of JSON.parse(themesJson)) {
  await ev(`(localStorage.setItem('zassess_theme', ${JSON.stringify(theme)}), localStorage.removeItem('zassess_glass'), true)`);
  await media([{ name: 'prefers-color-scheme', value: theme }, { name: 'prefers-reduced-motion', value: 'reduce' }]);
  for (const route of routes) {
    await load(route); await settle(route, 4000); await frames();
    out.pages[theme + ' ' + route] = await ev(auditJs);
    trace('audit', theme, route);
  }
}
// 2. No horizontal scroll at 320 and 390 px with the glass on.
await media([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
for (const route of routes) {
  await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
  await load(route); await settle(route, 3000); await frames();
  const rec = out.reflow[route] = { 320: await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`) };
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 800, deviceScaleFactor: 1, mobile: false });
  await frames();
  rec[390] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
}
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
// 3. The system's preferences and print turn every surface solid and remove the blur.
const PREFS = { transparency: [[{ name: 'prefers-reduced-transparency', value: 'reduce' }], ''],
                contrast: [[{ name: 'prefers-contrast', value: 'more' }], ''],
                forced: [[{ name: 'forced-colors', value: 'active' }], ''],
                print: [[], 'print'] };
for (const [name, [features, type]] of Object.entries(PREFS)) {
  for (const route of (name === 'transparency' ? routes : ['/', '/report/path', '/report/advanced'])) {
    await media(features.concat([{ name: 'prefers-reduced-motion', value: 'reduce' }]), type);
    await load(route); await settle(route, 3000); await frames();
    out.solid[name + ' ' + route] = await ev(solidJs);
  }
}
await media([]);
// The baseline the preferences are measured against: the same pages with nothing asked.
for (const route of ['/', '/report/path', '/report/advanced']) { await load(route); await settle(route, 3000); out.solid['none ' + route] = await ev(solidJs); }
// 4. The switch in Advanced settings: off, survives a reload and reaches other pages; back on.
const sw = out.switch = {};
await load('/report/advanced'); await settle('advanced', 4000);
sw.initially = await ev(`({ checked: document.getElementById('advGlass').checked, on: !document.documentElement.classList.contains('glass-off'), note: document.getElementById('advGlassNote').textContent })`);
await ev(`(document.getElementById('advGlass').focus(), true)`);
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: ' ', code: 'Space', windowsVirtualKeyCode: 32 });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: ' ', code: 'Space', windowsVirtualKeyCode: 32 });
await frames();
sw.afterSpace = await ev(`({ checked: document.getElementById('advGlass').checked, off: document.documentElement.classList.contains('glass-off'), stored: localStorage.getItem('zassess_glass'), note: document.getElementById('advGlassNote').textContent, solid: ${solidJs} })`);
await load('/report/advanced'); await settle('advanced again', 4000);
sw.afterReload = await ev(`({ checked: document.getElementById('advGlass').checked, off: document.documentElement.classList.contains('glass-off'), solid: ${solidJs} })`);
await load('/report/path'); await settle('path', 3000);
sw.otherPage = await ev(`({ off: document.documentElement.classList.contains('glass-off'), solid: ${solidJs} })`);
await load('/'); await settle('home', 4000);
sw.home = await ev(`({ off: document.documentElement.classList.contains('glass-off'), headScript: !!document.querySelector('head script[src*="/static/glass.js"]') })`);
await load('/report/advanced'); await settle('advanced back on', 4000);
await ev(`(document.getElementById('advGlass').click(), true)`);
await load('/report/advanced'); await settle('advanced on again', 4000);
sw.backOn = await ev(`({ checked: document.getElementById('advGlass').checked, off: document.documentElement.classList.contains('glass-off'), stored: localStorage.getItem('zassess_glass') })`);
// 5. The lens follows the pointer, and is off under prefers-reduced-motion.
const lens = out.lens = {};
for (const motion of ['no-preference', 'reduce']) {
  await media([{ name: 'prefers-reduced-motion', value: motion }]);
  await load('/report/advanced'); await settle('lens', 3000);
  // A point in the card's own padding, half way down the window (clear of the sticky bar and of nested panels).
  const at = await ev(`(() => { const c = document.querySelector('.rp-card'); c.scrollIntoView({ block: 'start', behavior: 'instant' }); window.scrollBy({ top: 200, behavior: 'instant' });
    const r = c.getBoundingClientRect(), x = Math.round(r.left + 6);
    for (let y = Math.round(innerHeight / 2); y < innerHeight; y += 10) if (document.elementFromPoint(x, y) === c) return { x, y };
    return { x, y: Math.round(innerHeight / 2) }; })()`);
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: at.x, y: at.y });
  await send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: at.x + 7, y: at.y + 5 });
  await frames(); await frames();
  lens[motion] = await ev(`(() => { const c = document.querySelector('.rp-card'), s = getComputedStyle(c); return { x: c.style.getPropertyValue('--glass-x'), y: c.style.getPropertyValue('--glass-y'), lens: s.getPropertyValue('--glass-lens').trim(), hovered: c.matches(':hover') }; })()`);
}
// 6. The focus ring stays visible on a glass button.
await media([{ name: 'prefers-reduced-motion', value: 'reduce' }]);
await load('/report/path'); await settle('path focus', 3000);
out.focus = [];
for (let i = 0; i < 6; i++) {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await frames();
  const f = await ev(`(() => { const e = document.activeElement; if (!e || e === document.body) return null; const s = getComputedStyle(e);
    return { d: e.tagName + '.' + String(e.className).split(' ')[0], glass: (parseInt(s.getPropertyValue('--glass-surface'), 10) || 0) > 0, outline: s.outlineStyle, width: parseFloat(s.outlineWidth) }; })()`);
  if (f) out.focus.push(f);
}
// 7. The backdrop: drifting with nothing asked, still under reduced motion, paused while the tab is hidden, gone when
//    the glass is off or the system asks for less transparency or forced colours; never wider than the window.
const back = out.backdrop = {};
for (const route of ['/', '/report/path']) {
  await media([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);
  await load(route); await settle(route, 3000); await frames();
  back['moving ' + route] = await ev(backdropJs);
  await ev(`(Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' }), document.dispatchEvent(new Event('visibilitychange')), true)`);
  await frames();
  back['hidden ' + route] = await ev(backdropJs);
  await ev(`(delete document.visibilityState, document.dispatchEvent(new Event('visibilitychange')), true)`);
  await frames();
  back['shown ' + route] = await ev(backdropJs);
  for (const [name, features] of [['reduced-motion', [{ name: 'prefers-reduced-motion', value: 'reduce' }]], ['transparency', [{ name: 'prefers-reduced-transparency', value: 'reduce' }]], ['forced', [{ name: 'forced-colors', value: 'active' }]]]) {
    await media(features); await frames();
    back[name + ' ' + route] = await ev(backdropJs);
  }
  await media([{ name: 'prefers-reduced-motion', value: 'no-preference' }]);
  await ev(`(localStorage.setItem('zassess_glass', 'off'), true)`);
  await load(route); await settle(route, 3000);
  back['off ' + route] = await ev(backdropJs);
  await ev(`(localStorage.removeItem('zassess_glass'), true)`);
  await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 720, deviceScaleFactor: 1, mobile: false });
  await load(route); await settle(route, 3000);
  const at320 = [];
  for (let i = 0; i < 4; i++) { at320.push(await ev(backdropJs)); await sleep(400); }
  back['320 ' + route] = at320;
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
}
await media([]);
out.errors = seen.errors.splice(0);
// The record is larger than a pipe's buffer: exit only once it is all written.
ws.close(); p.kill();
process.stdout.write(JSON.stringify(out) + '\n', () => process.exit(0));
"""


@pytest.fixture(scope="module")
def glass(tmp_path_factory):
    driver = DRIVER.replace("%SETUP%", sample_setup())
    return run_in_browser(tmp_path_factory.mktemp("glass"), driver, json.dumps(ROUTES), json.dumps(THEMES), AUDIT, SOLID, BACKDROP, timeout=900)


def _page(glass, theme, route):
    return glass["pages"][f"{theme} {route}"]


@pytest.mark.parametrize("route", ROUTES)
def test_the_glass_layer_is_applied_on_every_page(glass, route):
    """WCAG 2.2 SC 1.4.3 (the material is measured where it is drawn) · ASVS V14.4: table over every page and theme: the glass is on by default, its surfaces carry the material, the chrome is blurred and the soft background is drawn."""
    assert glass["run"]["started"], glass["run"]
    for theme in THEMES:
        rec = _page(glass, theme, route)
        assert rec["on"] and rec["surfaces"] >= 2 and len(rec["blurred"]) >= 1, (theme, route, rec["surfaces"], rec["blurred"])
        assert "radial-gradient" in rec["wash"] and "radial-gradient" in rec["wash2"] and rec["fields"] == 5, (theme, route, rec["wash"], rec["wash2"])
        assert rec["surfaces"] > rec["opaque"], (theme, route, "some glass is translucent")


@pytest.mark.parametrize("theme", THEMES)
@pytest.mark.parametrize("route", ROUTES)
def test_text_on_glass_meets_aa_against_the_worst_backdrop(glass, route, theme):
    """WCAG 2.2 SC 1.4.3: table over every page and theme: every text on a glass surface is 4.5:1 (3:1 when large) against the worst case behind the glass (white and black behind floating chrome, the page wash's extremes behind surfaces in the flow), with and without the sheen and the lens."""
    rec = _page(glass, theme, route)
    assert rec["measured"] >= 1, (theme, route)
    assert rec["contrast"] == [], rec["contrast"]


@pytest.mark.parametrize("route", ROUTES)
def test_blur_stays_on_a_few_chrome_layers(glass, route):
    """Performance (smooth scrolling) · WCAG 2.2 SC 1.4.10: few blurred layers per page, none taller than the window, no table blurred or see-through, and no fixed element trapped inside a blurred one (a backdrop-filter becomes its containing block)."""
    for theme in THEMES:
        rec = _page(glass, theme, route)
        assert len(rec["blurred"]) <= MAX_BLURRED, (theme, route, rec["blurred"])
        assert rec["tallBlur"] == [] and rec["tables"] == [] and rec["fixedInBlur"] == [], (theme, route, rec)


@pytest.mark.parametrize("route", ROUTES)
def test_no_horizontal_scroll_at_320_and_390_px(glass, route):
    """WCAG 2.2 SC 1.4.10 (Reflow): table over every page: with the glass on, the page never scrolls sideways at 320 or 390 CSS px."""
    assert glass["reflow"][route] == {"320": 0, "390": 0}, glass["reflow"][route]


@pytest.mark.parametrize("route", ROUTES)
def test_reduced_transparency_removes_the_blur(glass, route):
    """WCAG 2.2 SC 1.4.3, 1.4.8 · CSS Media Queries 5 prefers-reduced-transparency (emulated): table over every page: no blur, no sheen, no background wash, every glass surface opaque."""
    rec = glass["solid"]["transparency " + route]
    assert rec["surfaces"] >= 2 and rec["blurred"] == 0 and rec["clear"] == [] and rec["sheen"] == 0 and rec["wash"] == rec["wash2"] == "none", rec


@pytest.mark.parametrize("pref", ["contrast", "forced", "print"])
@pytest.mark.parametrize("route", ["/", "/report/path", "/report/advanced"])
def test_more_contrast_forced_colours_and_print_are_solid(glass, pref, route):
    """WCAG 2.2 SC 1.4.3, 1.4.11 · prefers-contrast: more, forced-colors: active and print (emulated): no blur and no see-through glass, against a baseline that has both."""
    base, rec = glass["solid"]["none " + route], glass["solid"][pref + " " + route]
    assert base["blurred"] >= 1 and base["clear"], base
    assert rec["blurred"] == 0 and rec["clear"] == [], (pref, route, rec)


def test_the_advanced_settings_switch_turns_it_off_and_the_choice_persists(glass):
    """WCAG 2.2 SC 2.1.1, 4.1.2, 3.2.4 · ASVS V14.4: the "Glass effect" switch is on by default, Space turns it off at once (solid, no blur), the choice survives a reload, reaches every page (the head script runs before paint) and turns back on."""
    sw = glass["switch"]
    assert sw["initially"]["checked"] and sw["initially"]["on"] and sw["initially"]["note"].startswith("On")
    a = sw["afterSpace"]
    assert not a["checked"] and a["off"] and a["stored"] == "off" and a["note"].startswith("Off"), a
    assert a["solid"]["blurred"] == 0 and a["solid"]["surfaces"] == 0 and a["solid"]["wash"] == a["solid"]["wash2"] == "none", a["solid"]
    assert sw["afterReload"]["off"] and not sw["afterReload"]["checked"] and sw["afterReload"]["solid"]["blurred"] == 0
    assert sw["otherPage"]["off"] and sw["otherPage"]["solid"]["blurred"] == 0
    assert sw["home"] == {"off": True, "headScript": True}
    assert sw["backOn"] == {"checked": True, "off": False, "stored": "on"}


def test_the_lens_follows_the_pointer_and_stops_under_reduced_motion(glass):
    """WCAG 2.2 SC 2.3.3, 2.2.2: the pointer-follow highlight moves with the pointer (CSS variables set per frame), and under prefers-reduced-motion it is never set."""
    on, off = glass["lens"]["no-preference"], glass["lens"]["reduce"]
    assert on["hovered"] and on["x"].endswith("px") and on["y"].endswith("px"), on
    assert on["lens"] not in ("", "transparent", "rgba(0, 0, 0, 0)"), on
    assert off["hovered"] and off["x"] == "" and off["y"] == "", off
    assert off["lens"] in ("transparent", "rgba(0, 0, 0, 0)"), off


def test_the_focus_ring_stays_visible_on_glass_buttons(glass):
    """WCAG 2.2 SC 2.4.7, 2.4.11, 1.4.11: keyboard focus on a glass button draws the solid 3px outline (the rim and drop shadow are not taken for a ring)."""
    stops = [f for f in glass["focus"] if f["glass"]]
    assert stops, glass["focus"]
    assert all(f["outline"] == "solid" and f["width"] >= 2 for f in stops), stops


def test_the_glass_run_left_no_script_errors(glass):
    """WCAG 2.2 SC 4.1.2 · CWE-754: switching the glass, the preferences and the lens raise no script or console error."""
    assert glass["errors"] == [], glass["errors"]


def test_short_cards_are_real_glass_and_tall_ones_are_not_blurred(glass):
    """Performance (no render surface taller than the window) · WCAG 2.2 SC 1.4.3: table over every page: some pages show blurred cards (a card that fits the window is real glass), and no blurred layer anywhere is taller than the window."""
    blurred = {route: _page(glass, "dark", route)["cardsBlurred"] for route in ROUTES}
    assert sum(1 for n in blurred.values() if n) >= 5, blurred
    assert all(_page(glass, theme, route)["tallBlur"] == [] for theme in THEMES for route in ROUTES)


@pytest.mark.parametrize("route", ["/", "/report/path"])
def test_the_backdrop_is_drawn_and_drifts_when_the_glass_is_on(glass, route):
    """WCAG 2.2 SC 1.4.3 (the colour behind the glass is the one measured above) · ASVS V14.4: with nothing asked, both backdrop layers are drawn with their five colour fields, and both drift (two running animations)."""
    rec = glass["backdrop"]["moving " + route]
    assert rec["before"] and rec["after"] and rec["fields"] == 5, rec
    assert rec["running"] == 2 and not rec["still"], rec


@pytest.mark.parametrize("route", ["/", "/report/path"])
def test_the_drift_pauses_while_the_tab_is_hidden_and_resumes(glass, route):
    """WCAG 2.2 SC 2.2.2 · performance: hiding the tab (visibilitychange) pauses both layers' drift (html.glass-still); showing it again resumes them."""
    hidden, shown = glass["backdrop"]["hidden " + route], glass["backdrop"]["shown " + route]
    assert hidden["still"] and hidden["paused"] == 2 and hidden["running"] == 0, hidden
    assert not shown["still"] and shown["running"] == 2, shown


@pytest.mark.parametrize("route", ["/", "/report/path"])
def test_the_backdrop_stands_still_under_reduced_motion(glass, route):
    """WCAG 2.2 SC 2.3.3, 2.2.2 · prefers-reduced-motion (emulated): the colour fields stay, the drift stops (no animation at all)."""
    rec = glass["backdrop"]["reduced-motion " + route]
    assert rec["fields"] == 5 and rec["running"] == 0 and rec["paused"] == 0, rec


@pytest.mark.parametrize("pref", ["transparency", "forced", "off"])
@pytest.mark.parametrize("route", ["/", "/report/path"])
def test_the_backdrop_is_gone_when_off_or_solid(glass, pref, route):
    """WCAG 2.2 SC 1.4.3, 1.4.11 · prefers-reduced-transparency, forced-colors (emulated) and the viewer's switch: no colour field and no animation is left."""
    rec = glass["backdrop"][pref + " " + route]
    assert not rec["before"] and not rec["after"] and rec["fields"] == 0 and rec["running"] == 0, (pref, rec)


@pytest.mark.parametrize("route", ["/", "/report/path"])
def test_the_drifting_backdrop_never_scrolls_sideways_at_320_px(glass, route):
    """WCAG 2.2 SC 1.4.10 (Reflow): at 320 CSS px, sampled while the backdrop drifts, the page never scrolls sideways (the layers are fixed and larger than the window, never part of the page's width)."""
    recs = glass["backdrop"]["320 " + route]
    assert all(r["overflow"] == 0 and r["running"] == 2 for r in recs), recs


def test_the_sidebar_drops_its_blur_while_an_item_is_dragged(glass):
    """WCAG 2.2 SC 2.1.1, 2.5.7 (dragging movements) · CSS Filter Effects 2 (a backdrop-filter is the containing block of fixed descendants): the sidebar is glass at rest and drops its blur while an item is dragged, so the fixed drop marker (shown only then) is placed against the window; sidebar_order.js sets the class before it shows the marker."""
    for theme in THEMES:
        drag = _page(glass, theme, "/")["sidebarDrag"]
        assert "blur(" in drag["resting"] and drag["dragging"] == "none", (theme, drag)
    js = open(os.path.join(STATIC, "sidebar_order.js"), encoding="utf-8").read()
    move = js[js.index("function onMove(e)"):]
    assert move.index("root.classList.add('sb-dragging')") < move.index("showLine(")
