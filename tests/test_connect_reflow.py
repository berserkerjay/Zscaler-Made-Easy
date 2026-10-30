"""WCAG 2.2 SC 1.4.10 (Reflow): the Connect step on the assessment page (/)
never scrolls sideways on a phone.

The bug (found with Playwright at 375x812): with Connect to the tenant open,
the page was 622px wide. Two things set the width of the whole step list,
because a grid column of `1fr` is never narrower than its content:
- the ZPA customer ID helper quotes an unbroken admin URL in <code>;
- the tenant profile picker (min-width 260px) is as wide as its longest
  option, "— no profile (type the details below) —".
Once those were fixed, at 320px the profile details grid (240px columns) and
the setting names in <code> in its notes still ran past the edge.
The fix: the step grid's column is `minmax(0, 1fr)`, code in the helper and
the profiles bar may break, the profile details columns are at most 100%
wide, and on a phone the picker takes the line.

The browser test drives the real page in headless Chrome over CDP with the
prelude of tests/test_findings_reflow.py, and skips without node or Chrome.
"""
import json
import os
import re

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    return open(os.path.join(ROOT, *parts), encoding="utf-8").read()


# ── The cause, in the stylesheets ───────────────────────────────────

@pytest.mark.parametrize("sheet,selector,declaration", [
    (("static", "guide.css"), r"\.gd-step\s*\{", r"grid-template-columns\s*:\s*2\.2rem\s+minmax\(0,\s*1fr\)"),
    (("static", "guide.css"), r"\.gd-step\s*\{\s*grid-template-columns", r"grid-template-columns\s*:\s*minmax\(0,\s*1fr\)"),
    (("static", "index.html"), r"\.field \.helper code\s*\{", r"overflow-wrap\s*:\s*anywhere\b"),
    (("static", "guide.css"), r"\.gd-prof-grid\s*\{", r"minmax\(min\(240px,\s*100%\),\s*1fr\)"),
    (("static", "guide.css"), r"\.gd-profiles code\s*\{", r"overflow-wrap\s*:\s*anywhere\b"),
    # Wave 6: the update branch list (it names the checkout's branch) shrinks to the line at 320px.
    (("static", "guide.css"), r"\.gd-upd-branch select\s*\{", r"max-width\s*:\s*100%"),
    (("static", "guide.css"), r"\.gd-upd-branch\s*\{", r"flex-wrap\s*:\s*wrap\b"),
])
def test_connect_step_rules_let_the_content_shrink(sheet, selector, declaration):
    """WCAG 2.2 SC 1.4.10: the step grid column can shrink below its content and the helper's sample URL breaks."""
    css = _read(*sheet)
    blocks = [m.group(0) for m in re.finditer(selector + r"[^}]*\}", css)]
    assert any(re.search(declaration, b) for b in blocks), (sheet, selector, blocks)


def test_no_step_grid_column_is_a_bare_1fr():
    """WCAG 2.2 SC 1.4.10: no .gd-step rule goes back to a bare `1fr` column (which grows to its widest child)."""
    css = _read("static", "guide.css")
    for m in re.finditer(r"\.gd-step\s*\{[^}]*\}", css):
        cols = re.search(r"grid-template-columns\s*:\s*([^;}]+)", m.group(0))
        if cols:
            bare = re.sub(r"minmax\([^)]*\)", "", cols.group(1))
            assert not re.search(r"(^|\s)1fr\b", bare), cols.group(1)


# ── Behaviour in a real browser ─────────────────────────────────────

DRIVER = CDP_PRELUDE + r"""
const [widthsJson] = args;
const out = {};
for (const width of JSON.parse(widthsJson)) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 812, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + '/' });
  await until(() => ev(`document.readyState === 'complete' && !!document.querySelector('[data-db="configure"]')`), 'the page');
  await ev(`document.querySelector('[data-db="configure"]').click(), 1`);
  // The Connect step is drawn: the tenant profiles bar and the sample tenant block are on screen.
  await until(() => ev(`(() => { const s = document.getElementById('gdProfSelect'), o = document.querySelector('#gdOffline .gd-btn'); return !!(s && s.offsetParent && o && o.offsetParent); })()`), 'the Connect step');
  await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
  out[width] = await ev(`(() => {
    const W = document.documentElement.clientWidth;
    const wide = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); if (!(r.width > 0 && r.right > W + 1) || getComputedStyle(e).position === 'fixed') return false;
      for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) { const s = getComputedStyle(a).overflowX; if (s === 'auto' || s === 'scroll' || s === 'hidden' || s === 'clip') return false; }
      return true; }).map(e => e.tagName + '#' + e.id + '.' + String(e.className.baseVal ?? e.className).slice(0, 40) + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 8);
    return { W, overflow: document.documentElement.scrollWidth - W, wide };
  })()`);
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""

WIDTHS = [320, 375, 390, 1280]   # 320: WCAG reflow boundary; 375 and 390: phones; 1280: desktop


@pytest.fixture(scope="module")
def connect_layout(tmp_path_factory):
    out = run_in_browser(tmp_path_factory.mktemp("connect-reflow"), DRIVER, json.dumps(WIDTHS))
    return {int(k): v for k, v in out.items()}


@pytest.mark.parametrize("width", WIDTHS)
def test_connect_step_never_scrolls_sideways(connect_layout, width):
    """WCAG 2.2 SC 1.4.10: with Connect to the tenant open, / is no wider than the window at 320, 375, 390 and 1280px."""
    m = connect_layout[width]
    assert m["overflow"] == 0, (width, m)
    assert m["wide"] == [], (width, m["wide"])
