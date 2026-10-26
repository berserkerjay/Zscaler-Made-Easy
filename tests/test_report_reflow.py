"""WCAG 2.2 SC 1.4.10 (Reflow): every report page, and Simple mode, fits a
320px-wide window without scrolling sideways, and still fits at 1280px.

The bugs (QA check T2, found with Playwright at 320px, and at 390px with a
classic scrollbar): a long button label (.rp-btn was white-space: nowrap)
on /report/evalall and /report/posture, a labelled control that could not
wrap (.df-ctl) on /report/posture, an unbroken setting name in <code> in the
hero of /report/digest and in the "What is this page" box on every page
(explain.js .xp-dl), and the file picker on /report/vendor. The shared fix is
in static/reports.css and static/explain.js.

The route list is read from the app, so a new /report/* page is measured
too. The browser test drives headless Chrome over CDP (node + Chrome) with
the CDP prelude of tests/test_findings_reflow.py, and skips when either is
missing.
"""
import json
import os
import re

import pytest

from test_findings_reflow import CDP_PRELUDE, _rules, run_in_browser

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _page_routes():
    import dlp_api_server as srv
    paths = sorted({r.path for r in srv.app.routes
                    if getattr(r, "methods", None) and "GET" in r.methods
                    and (r.path.startswith("/report/") or r.path == "/simple") and "{" not in r.path})
    assert len(paths) >= 30, paths   # the route list was really read
    return paths


ROUTES = _page_routes()
WIDTHS = [320, 1280]


def _reports_css():
    return open(os.path.join(ROOT, "static", "reports.css"), encoding="utf-8").read()


# ── The cause, in the shared stylesheet ─────────────────────────────

@pytest.mark.parametrize("selector,declaration", [
    (".rp-btn", r"white-space\s*:\s*normal\b"),               # a long button label wraps inside the button
    (".rp-btn", r"max-width\s*:\s*100%"),                     # ... and the button is never wider than its line
    (".df-ctl", r"flex-wrap\s*:\s*wrap\b"),                   # a label and its control may stack
    (".rp-page code", r"overflow-wrap\s*:\s*anywhere\b"),     # an unbroken setting name or URL breaks
    ('.rp-page input[type="file"]', r"max-width\s*:\s*100%"), # the file picker shrinks to the line
])
def test_the_shared_report_stylesheet_reflows(selector, declaration):
    """WCAG 2.2 SC 1.4.10: reports.css lets the parts that widened a 320px page wrap or break."""
    # Arrange
    css = _reports_css()
    # Act
    bodies = _rules(css, selector)
    # Assert
    assert any(re.search(declaration, b) for b in bodies), (selector, bodies)


def test_no_report_rule_puts_nowrap_back_on_buttons():
    """WCAG 2.2 SC 1.4.10: no later .rp-btn rule turns wrapping off again (negative case)."""
    css = re.sub(r"/\*.*?\*/", "", _reports_css(), flags=re.S)
    last = [m.group(1) for m in re.finditer(r"(?:^|\})\s*\.rp-btn\s*\{([^{}]*)\}", css)]
    assert last and "nowrap" not in last[-1], last


def test_the_what_is_this_page_box_breaks_long_words():
    """WCAG 2.2 SC 1.4.10: the explain box on every page breaks a long token in its answers."""
    js = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    assert re.search(r"\.xp-dl dd\{[^}]*overflow-wrap:anywhere", js)


@pytest.mark.parametrize("route", ROUTES)
def test_every_report_page_loads_the_shared_stylesheet(route):
    """WCAG 2.2 SC 1.4.10: each report page gets the reflow rules from reports.css (table-driven over the routes)."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    html = TestClient(srv.app).get(route).text
    assert "/static/reports.css" in html, route


# ── Behaviour in a real browser ─────────────────────────────────────

DRIVER = CDP_PRELUDE + r"""
const [routesJson, widthsJson] = args;
const out = {};
for (const width of JSON.parse(widthsJson)) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  for (const route of JSON.parse(routesJson)) {
    await send('Page.navigate', { url: base + route });
    await until(() => ev(`document.readyState === 'complete'`), route + ' load');
    // Settled: the page's own first fetches have drawn (the size is the same three frames running).
    let last = '', same = 0;
    await until(async () => { const now = await ev(`new Promise(r => requestAnimationFrame(() => r(document.documentElement.scrollWidth + 'x' + document.documentElement.scrollHeight)))`); same = now === last ? same + 1 : 0; last = now; return same >= 3; }, route + ' settle', 8000).catch(() => null);
    out[width + ' ' + route] = await ev(`(() => {
      const W = document.documentElement.clientWidth;
      const wide = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); if (!(r.width > 0 && r.right > W + 1) || getComputedStyle(e).position === 'fixed') return false;
        for (let a = e.parentElement; a && a !== document.body; a = a.parentElement) { const s = getComputedStyle(a).overflowX; if (s === 'auto' || s === 'scroll' || s === 'hidden' || s === 'clip') return false; if (a.getBoundingClientRect().right > W + 1) return false; }
        return true; }).map(e => e.tagName + '#' + e.id + '.' + String(e.className.baseVal ?? e.className).slice(0, 40) + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 6);
      return { W, overflow: document.documentElement.scrollWidth - W, wide };
    })()`);
  }
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def report_layout(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("report-reflow"), DRIVER, json.dumps(ROUTES), json.dumps(WIDTHS), timeout=300)


@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("route", ROUTES)
def test_no_report_page_scrolls_sideways(report_layout, route, width):
    """WCAG 2.2 SC 1.4.10: the page is no wider than the window at 320px (boundary) and 1280px."""
    m = report_layout[f"{width} {route}"]
    assert m["overflow"] == 0, (route, width, m)
