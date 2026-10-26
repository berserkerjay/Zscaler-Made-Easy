"""WCAG 2.2 SC 1.4.10 (Reflow): the results on the assessment page (and their
mirror in /report/view, which shares /app.css) never make the page scroll
sideways on a phone.

The bugs (QA check T2, found with Playwright on a restored assessment):
- each finding row is a flex row of a fixed icon, a status pill that never
  shrinks (white-space: nowrap, min-width) and the text. At 390px the pill
  and icon took the whole row, the text column was squeezed to 0px and its
  definition list was pushed 116-170px past the right edge;
- the best-practice gaps quote a finding's detail, and a long unbroken URL
  or API path in it pushed the page up to 1387px wide;
- at 320px (the WCAG reflow width) the score ring's text sat past the edge.
The fix lets those flex rows wrap, gives the finding text a real flex basis
and lets long unbroken tokens break.

The source tests read the served stylesheet; the browser tests drive the
real page in headless Chrome over CDP (node + Chrome, as
tests/test_sidebar_order.py does) with a synthetic assessment restored from
sessionStorage, and skip when either is missing.
"""
import json
import os
import re
import shutil
import subprocess
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _chrome():
    from test_sidebar_order import _chrome as find
    return find()


def _css_of(text):
    """The CSS of a stylesheet, or of an HTML file's <style> blocks, without comments."""
    if text.lstrip().lower().startswith(("<!doctype", "<html")):
        text = "\n".join(re.findall(r"<style[^>]*>(.*?)</style>", text, re.S))
    return re.sub(r"/\*.*?\*/", "", text, flags=re.S)


def _rules(css, selector):
    """Every declaration block whose selector list contains `selector` exactly."""
    out = []
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", _css_of(css)):
        if selector in [s.strip() for s in sel.split(",")]:
            out.append(body)
    return out


@pytest.fixture(scope="module")
def app_css():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    return TestClient(srv.app).get("/app.css").text


def _sheet(name):
    return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()


# ── The cause, in the stylesheets ───────────────────────────────────

@pytest.mark.parametrize("sheet,selector,declaration", [
    ("/app.css", ".check-item", r"flex-wrap\s*:\s*wrap\b"),                    # the finding row may wrap
    ("/app.css", ".check-body", r"overflow-wrap\s*:\s*anywhere\b"),             # a long token in a finding breaks
    ("/app.css", "#benchmarkBody li", r"overflow-wrap\s*:\s*anywhere\b"),       # ... and where the gaps quote it
    ("dashboard.css", ".db-ring", r"flex-wrap\s*:\s*wrap\b"),                   # the score text may go under the ring
])
def test_flex_rows_and_long_tokens_reflow(app_css, sheet, selector, declaration):
    """WCAG 2.2 SC 1.4.10: each results row that held a fixed-width part may wrap, and long tokens break."""
    # Arrange
    css = app_css if sheet == "/app.css" else _sheet(sheet)
    # Act
    rules = _rules(css, selector)
    # Assert
    assert any(re.search(declaration, body) for body in rules), (sheet, selector, rules)


def test_finding_text_asks_for_a_readable_width(app_css):
    """WCAG 2.2 SC 1.4.10: the finding text has a real flex basis (boundary: 160-320px), not 0."""
    m = re.search(r"flex\s*:\s*1\s+1\s+([0-9.]+)(rem|px)", " ".join(_rules(app_css, ".check-body")))
    assert m, ".check-body has flex: 1 1 <basis>"
    basis_px = float(m.group(1)) * (16 if m.group(2) == "rem" else 1)
    assert 160 <= basis_px <= 320, basis_px   # readable alone, and still beside the pill on a desktop row


@pytest.mark.parametrize("sheet", ["index.html", "dashboard.css", "reports.css", "simple.css"])
@pytest.mark.parametrize("selector", [".check-item", ".db-ring"])
def test_no_stylesheet_turns_the_wrap_back_off(sheet, selector):
    """WCAG 2.2 SC 1.4.10: no other rule forbids those rows from wrapping (negative case)."""
    css = _css_of(_sheet(sheet))
    assert len(css) > 500, sheet   # the stylesheet was really read
    for sel, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        if selector in sel:
            assert not re.search(r"flex-wrap\s*:\s*nowrap|flex-flow\s*:[^;]*nowrap", body), (sheet, sel)


# ── Behaviour in a real browser ─────────────────────────────────────

# A real help URL (98 characters, as a check detail quotes it) and a longer
# unbroken API path (boundary): neither may widen the page.
URL = "https://help.zscaler.com/zscaler-deployments-operations/zia-ssl-inspection-leading-practices-guide"
LONG = "/zia/" + "x" * 260


def _report():
    """A small deterministic assessment: every pill text (the longest is
    "Could not be checked"), long labels and an unbroken token in the detail."""
    plain = {"found": "Synthetic finding text that is long enough to wrap over several lines on a phone screen.",
             "means": "What it means for the business, written out in a full sentence.",
             "do": "What to do next, written out in a full sentence with a place in the console.",
             "outcome": "What the business gets once it is fixed."}
    statuses = ["ERROR", "FAIL", "REVIEW", "PASS", "INFO"]
    checks = [{"id": f"9.{i + 1}", "section": "9 - Synthetic reflow section", "status": st,
               "label": f"Synthetic {st.lower()} check with a fairly long label for a narrow screen",
               "detail": f"Reference: {URL} Read failed: {LONG}", "plain": dict(plain)} for i, st in enumerate(statuses)]
    return {"metadata": {"tool": "Zscaler Made Easy", "org": "Synthetic Org", "assessor": "Synthetic Assessor",
                         "timestamp": "2026-01-01T00:00:00+00:00", "total_checks": len(checks), "scope": "dlp"},
            "score": 40, "maturity": "Developing",
            "sections": {"9 - Synthetic reflow section": {"total": 5, "pass": 1, "fail": 1, "warn": 1, "info": 2, "scored": 3, "pct": 33}},
            "checks": checks, "critical": [c for c in checks if c["status"] == "FAIL"],
            "review": [c for c in checks if c["status"] == "REVIEW"]}


# Shared by the reflow tests: start headless Chrome (debugging port chosen by
# Chrome itself, loopback only), connect over CDP, and define send/ev/until.
CDP_PRELUDE = r"""
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
const [chrome, base, dir, ...args] = process.argv.slice(2);
const p = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
async function until(fn, what, ms = 20000) { const end = Date.now() + ms; for (;;) { const v = await fn().catch(() => null); if (v) return v; if (Date.now() > end) throw new Error('timed out waiting for ' + what); await sleep(50); } }
const port = await until(async () => fs.readFileSync(path.join(dir, 'DevToolsActivePort'), 'utf8').split('\n')[0].trim() || null, 'DevToolsActivePort');
const tab = await until(async () => (await (await fetch(`http://127.0.0.1:${port}/json`)).json()).find(t => t.type === 'page'), 'a page target');
if (!/^ws:\/\/127\.0\.0\.1:/.test(tab.webSocketDebuggerUrl)) throw new Error('debugger must be loopback');
const ws = new WebSocket(tab.webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id = 0; const pend = {}; ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } };
const send = (method, params = {}) => new Promise(r => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async x => { const r = await send('Runtime.evaluate', { expression: x, returnByValue: true, awaitPromise: true }); if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 400)); return r.result.result.value; };
await send('Page.enable'); await send('Runtime.enable');
"""

DRIVER = CDP_PRELUDE + r"""
const [widthsJson, reportJson] = args;
await send('Page.addScriptToEvaluateOnNewDocument', { source: `try { sessionStorage.setItem('zassess_last_results', ${JSON.stringify(reportJson)}); } catch (e) {}` });
const out = {};
for (const width of JSON.parse(widthsJson)) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + '/' });
  await until(() => ev(`document.readyState === 'complete' && document.querySelectorAll('#checksList .check-item').length === 5`), 'the restored findings');
  await ev(`document.querySelectorAll('#checksList details').forEach(d => d.open = true), 1`);
  await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
  out[width] = await ev(`(() => {
    const W = document.documentElement.clientWidth;
    const rows = [...document.querySelectorAll('#checksList .check-item')].map(row => {
      const body = row.querySelector('.check-body').getBoundingClientRect(), pill = row.querySelector('.check-status').getBoundingClientRect();
      return { body: Math.round(body.width), bodyLeft: Math.round(body.left), pillRight: Math.round(pill.right), pillTop: Math.round(pill.top), bodyTop: Math.round(body.top) };
    });
    const past = [...document.querySelectorAll('#checksList *')].filter(e => e.getBoundingClientRect().right > W + 1).map(e => e.tagName + '.' + e.className).slice(0, 5);
    const wide = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > W + 1 && getComputedStyle(e).position !== 'fixed' && !(e.parentElement && e.parentElement.getBoundingClientRect().right > W + 1); }).map(e => e.tagName + '#' + e.id + '.' + e.className + ' R' + Math.round(e.getBoundingClientRect().right)).slice(0, 8);
    return { W, overflow: document.documentElement.scrollWidth - W, rows, past, wide };
  })()`);
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""

WIDTHS = [320, 390, 1280]   # 320: WCAG reflow boundary; 390: a phone; 1280: desktop must keep one row


def run_in_browser(tmp_dir, driver, *args, timeout=180):
    """Serve the real app on an ephemeral loopback port, run a node CDP
    driver against it in headless Chrome, and return the driver's JSON.
    Skips without node or Chrome. Isolated: temporary profiles, audit, rate
    and token files; no remote Git lookup (the health check's only outbound
    call), and the suite's offline guard stays in force."""
    chrome, node = _chrome(), shutil.which("node")
    if not chrome or not node:
        pytest.skip("needs node and Chrome/Chromium")
    import uvicorn
    import dlp_api_server as srv
    mp = pytest.MonkeyPatch()
    for key, name in (("DLP_CHECK_PROFILES", "profiles.json"), ("DLP_CHECK_AUDIT", "audit.log"),
                      ("DLP_CHECK_UI_TOKEN_DIR", ""), ("DLP_CHECK_ZIA_RATE_STATE", "rate.json")):
        mp.setenv(key, str(tmp_dir / name) if name else str(tmp_dir))
    (tmp_dir / "profiles.json").write_text("{}")
    mp.setenv("ZSCALER_UI_AUTH", "0")
    mp.setenv("ENABLE_WRITE_ACTIONS", "")
    mp.setattr(srv, "_latest_remote_commit", lambda branch="main": None)
    server = uvicorn.Server(uvicorn.Config(srv.app, host="127.0.0.1", port=0, lifespan="off", log_level="warning", access_log=False))
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 20
        while not (server.started and server.servers) and time.monotonic() < deadline:
            time.sleep(0.02)   # bounded wait for the socket, not a fixed delay
        assert server.started, "the app did not start"
        port = server.servers[0].sockets[0].getsockname()[1]
        (tmp_dir / "drive.mjs").write_text(driver, encoding="utf-8")
        r = subprocess.run([node, str(tmp_dir / "drive.mjs"), chrome, f"http://127.0.0.1:{port}", str(tmp_dir / "profile"), *args],
                           capture_output=True, text=True, timeout=timeout)
    finally:
        server.should_exit = True
        thread.join(timeout=10)
        mp.undo()
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.fixture(scope="module")
def browser_layout(tmp_path_factory):
    out = run_in_browser(tmp_path_factory.mktemp("reflow"), DRIVER, json.dumps(WIDTHS), json.dumps(_report()))
    return {int(k): v for k, v in out.items()}


@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_never_scrolls_sideways_with_findings_shown(browser_layout, width):
    """WCAG 2.2 SC 1.4.10: with findings and their details open, nothing passes the right edge."""
    m = browser_layout[width]
    assert m["overflow"] == 0, (m["W"], m["wide"])
    assert m["past"] == [], m["past"]


@pytest.mark.parametrize("width", WIDTHS)
def test_every_finding_keeps_a_readable_text_column(browser_layout, width):
    """WCAG 2.2 SC 1.4.10: the text of every finding is at least 150px wide (it was 0px at 390px)."""
    assert all(row["body"] >= 150 for row in browser_layout[width]["rows"]), browser_layout[width]


def test_desktop_keeps_the_pill_and_the_text_on_one_line(browser_layout):
    """WCAG 2.2 SC 1.4.10: the wrap only happens when it is needed; at 1280px the text sits beside the pill."""
    assert all(row["bodyLeft"] >= row["pillRight"] for row in browser_layout[1280]["rows"]), browser_layout[1280]


def test_a_phone_puts_the_text_under_the_pill(browser_layout):
    """WCAG 2.2 SC 1.4.10: at 390px the text drops below the pill instead of being squeezed beside it."""
    assert all(row["bodyTop"] > row["pillTop"] for row in browser_layout[390]["rows"]), browser_layout[390]
