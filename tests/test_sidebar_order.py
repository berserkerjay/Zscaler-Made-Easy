"""The sidebar can be rearranged: drag an item or a section heading, or
Alt+arrows on a focused item; the order is kept per browser by stable ids
and merged with whatever the page has now (static/sidebar_order.js).

The behaviour tests drive the real static/sidebar_order.js and
static/dashboard.css in headless Chrome over CDP (node + chrome), with
real mouse and key events; they skip when either is missing. The wiring
tests read the sources."""
import glob
import http.server
import json
import os
import re
import shutil
import subprocess
import threading

import pytest

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
KEY = "dlpcheck_sidebar_order_v1"


def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def _chrome():
    c = os.environ.get("CHROME_BIN")
    if c and os.path.exists(c):
        return c
    hits = glob.glob(os.path.expanduser("~/AppData/Local/ms-playwright/chromium-*/chrome-win64/chrome.exe")) + \
        glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux/chrome"))
    for p in (r"C:\Program Files\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
              r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
              "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"):
        if os.path.exists(p):
            hits.append(p)
    return hits[0] if hits else (shutil.which("chromium") or shutil.which("google-chrome") or shutil.which("chrome"))


# ── Wiring ──────────────────────────────────────────────────────────

def test_the_reorder_add_on_loads_before_dashboard_js_which_starts_it():
    names = [n for n, k in srv.GUI_ADDONS if k == "script"]
    assert names.index("sidebar_order.js") == names.index("dashboard.js") - 1
    dash = _read("static", "dashboard.js")
    assert "window.SidebarOrder.init({ root: aside, container: tools, menuHost: $('dbFoot') })" in dash
    # The Workflow section shares the sections container with the tool groups, so sections can swap.
    assert '<div id="dbTools" class="db-sections" role="navigation" aria-label="Workflow and tools">' in dash and 'data-sb-id="workflow"' in dash


def test_sections_carry_stable_ids_not_positions():
    html = _read("static", "index.html")
    for i in ("start", "find-gaps", "close-gaps", "reference", "troubleshoot"):
        assert f'data-sb-id="{i}"' in html, i


def test_stored_order_is_never_inserted_as_html():
    js = _read("static", "sidebar_order.js")
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML" not in js
    assert "/^[A-Za-z0-9_:.~-]{1,160}$/" in js, "ids from storage are validated before use"
    # Every storage access is guarded.
    for call in ("store.getItem(KEY)", "store.setItem(KEY", "store.removeItem(KEY)"):
        line = next(l for l in js.splitlines() if call in l)
        assert "try {" in line, line


def test_the_help_text_and_changelog_mention_it():
    assert "Reset sidebar order" in _read("static", "explain.js")
    cl = _read("CHANGELOG.md")
    top = cl[cl.index("## 2026-10-02"):]
    top = top[:top.index("\n## ", 5)] if "\n## " in top[5:] else top
    assert "Alt+Shift+" in top and "Reset sidebar order" in top


# ── Behaviour in a real browser ─────────────────────────────────────

HARNESS = r"""<!doctype html><html><head><meta charset="utf-8">
<style>:root{--sp-1:4px;--sp-2:8px;--sp-3:12px;--sp-4:16px;--r-sm:6px;--r-md:8px;--ctl-md:34px;--fs-caption:11px;--fs-subhead:14px;--fs-footnote:12px;--fs-headline:15px;
--text:#eee;--dim:#999;--card:#222;--card-solid:#222;--well:#333;--border:#444;--accent:#0a84ff} body{margin:0;background:#111;color:#eee;font:14px sans-serif}</style>
<link rel="stylesheet" href="dashboard.css"></head>
<body class="db-layout">
<div id="liveRegion" role="status" aria-live="polite"></div>
<aside id="dbSidebar" aria-label="Navigation">
  <div id="dbTools" class="db-sections">
    <div class="db-nav" role="group" aria-label="Workflow" data-sb-id="workflow">
      <div class="db-nav-l">Workflow</div>
      <button type="button" class="db-item" data-db="configure"><span class="db-ico" aria-hidden="true">X</span>Connect to the tenant</button>
      <button type="button" class="db-item" data-db="scope"><span class="db-ico" aria-hidden="true">X</span>Scope assessment</button>
      <div id="dbRunNote" class="db-note">Sign in first</div>
      <button type="button" class="db-item" data-db="dashboard" aria-current="page"><span class="db-ico" aria-hidden="true">X</span>Dashboard</button>
    </div>
    <div class="tool-group" role="group" aria-label="Start" data-sb-id="start"><div class="tool-group-l">Start</div>
      <button class="btn btn-ghost" onclick="hit('help')"><span aria-hidden="true">?</span> Help</button></div>
    <div class="tool-group" role="group" aria-label="Find the gaps" data-sb-id="find-gaps"><div class="tool-group-l">Find the gaps</div>
      <button class="btn btn-ghost" onclick="hit('flow')"><span aria-hidden="true">F</span> Traffic flow</button>
      <button class="btn btn-ghost" onclick="hit('path')"><span aria-hidden="true">P</span> Path analyzer</button>
      __EXTRA__
      <button class="btn btn-ghost" onclick="openToolTab('efficacy')"><span aria-hidden="true">E</span> DLP efficacy</button></div>
    <div class="tool-group" role="group" aria-label="Reference" data-sb-id="reference"><div class="tool-group-l">Reference</div>
      <button class="btn btn-ghost" onclick="hit('adv')"><span aria-hidden="true">A</span> Advanced settings</button>
      <button class="btn btn-ghost" onclick="hit('upd')"><span aria-hidden="true">U</span> Zscaler updates</button></div>
    __EXTRA_SEC__
  </div>
  <div class="db-foot" id="dbFoot"><span id="dbBuild">build</span></div>
</aside>
<script>
window.__hits = []; window.__said = []; window.__errors = [];
window.addEventListener('error', e => __errors.push(String(e.message)));
function hit(k) { __hits.push(k); }
function openToolTab(k) { __hits.push('tab:' + k); }
function announce(t) { __said.push(t); }
document.querySelectorAll('.db-item').forEach(b => b.addEventListener('click', () => {
  __hits.push('db:' + b.dataset.db);
  document.querySelectorAll('.db-item').forEach(x => x === b ? x.setAttribute('aria-current', 'page') : x.removeAttribute('aria-current'));
}));
</script>
<script src="sidebar_order.js"></script>
<script>
window.ctl = SidebarOrder.init({ root: document.getElementById('dbSidebar'), container: document.getElementById('dbTools'), menuHost: document.getElementById('dbFoot') });
window.order = () => ctl.current();
window.flat = () => ctl.current().map(s => s.id + ':' + s.items.join(','));
window.ctr = sel => { const r = document.querySelector(sel).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2, top: r.top, bottom: r.bottom, left: r.left }; };
window.sid = id => `[data-sb-id="${id}"]`;
</script></body></html>"""

DRIVER = r"""
import { spawn } from 'node:child_process';
const [chrome, base, dir] = process.argv.slice(2);
const port = 9400 + Math.floor(Math.random() * 500);
const p = spawn(chrome, ['--headless=new', `--remote-debugging-port=${port}`, '--no-first-run', '--no-default-browser-check', `--user-data-dir=${dir}`, '--window-size=1280,900', 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let tabs; for (let i = 0; i < 200; i++) { try { tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (tabs.find(t => t.type === 'page')) break; } catch {} await sleep(200); }
const ws = new WebSocket(tabs.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id = 0; const pend = {}; ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } };
const send = (method, params = {}) => new Promise(r => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async x => { const r = await send('Runtime.evaluate', { expression: x, returnByValue: true, awaitPromise: true }); if (r.result.exceptionDetails) throw new Error(x + ' => ' + JSON.stringify(r.result.exceptionDetails)); return r.result.result.value; };
const out = {};
await send('Page.enable'); await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
async function open(page, storage) {
  await send('Page.navigate', { url: base + page });
  await sleep(500);
  if (storage !== undefined) {
    await ev(storage === null ? `localStorage.clear(), 1` : `localStorage.setItem(${JSON.stringify("__KEY__")}, ${JSON.stringify(storage)}), 1`);
    await send('Page.reload'); await sleep(500);
  }
  for (let i = 0; i < 50 && !(await ev('!!window.ctl')); i++) await sleep(100);
}
const mouse = (type, x, y, buttons) => send('Input.dispatchMouseEvent', { type, x, y, button: 'left', buttons, clickCount: 1 });
async function drag(fromSel, toX, toY) {
  const a = await ev(`ctr(${JSON.stringify(fromSel)})`);
  await mouse('mouseMoved', a.x, a.y, 0);
  await mouse('mousePressed', a.x, a.y, 1);
  for (let i = 1; i <= 6; i++) { await mouse('mouseMoved', a.x + (toX - a.x) * i / 6, a.y + (toY - a.y) * i / 6, 1); await sleep(15); }
  out.lineShownDuringDrag = out.lineShownDuringDrag || await ev(`!document.querySelector('.sb-drop-line').hidden && getComputedStyle(document.querySelector('.sb-drop-line')).display !== 'none'`);
  await mouse('mouseReleased', toX, toY, 0);
  await sleep(50);
}
async function click(sel) { const a = await ev(`ctr(${JSON.stringify(sel)})`); await mouse('mouseMoved', a.x, a.y, 0); await mouse('mousePressed', a.x, a.y, 1); await mouse('mouseReleased', a.x, a.y, 0); await sleep(30); }
async function key(k, mods) {
  const code = k; const vk = k === 'ArrowUp' ? 38 : 40;
  await send('Input.dispatchKeyEvent', { type: 'rawKeyDown', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods });
  await sleep(80);
}
const ALT = 1, SHIFT = 8;

// 1. Default order, ids and the grip/drag mode at desktop width.
await open('h.html', null);
out.default = await ev('flat()');
out.dragOnWide = await ev(`document.getElementById('dbSidebar').classList.contains('sb-drag-on')`);
out.keyshortcuts = await ev(`document.querySelector(sid('wf-scope')).getAttribute('aria-keyshortcuts')`);

// 2. Drag an item within its section: Path analyzer above Traffic flow; the drag is not a click.
let t = await ev(`ctr(sid('fn-hit-flow'))`);
await drag(`[data-sb-id="fn-hit-path"]`, t.x, t.top + 3);
out.afterWithin = await ev('flat()');
out.hitsAfterDrag = await ev('__hits.slice()');
out.saidWithin = await ev('__said[__said.length - 1]');
out.focusAfterDrag = await ev('document.activeElement.dataset.sbId');

// 3. Drag an item into another section: DLP efficacy to the bottom of Reference.
t = await ev(`ctr(sid('fn-hit-upd'))`);
await drag(`[data-sb-id="fn-openToolTab-efficacy"]`, t.x, t.bottom - 2);
out.afterCross = await ev('flat()');

// 4. Drag a whole section by its heading: Reference above Workflow.
t = await ev(`ctr(sid('workflow'))`);
await drag(`[data-sb-id="reference"] .tool-group-l`, t.x, t.top + 2);
out.afterSection = await ev('flat()');
out.saidSection = await ev('__said[__said.length - 1]');

// 5. Clicks still activate, after the reorder.
await ev('__hits.length = 0, 1');
await click(`[data-sb-id="fn-hit-path"]`);
await click(`[data-sb-id="fn-openToolTab-efficacy"]`);
await click(`[data-sb-id="wf-scope"]`);
out.clicksAfter = await ev('__hits.slice()');
out.currentAfter = await ev(`document.querySelector('.db-item[aria-current="page"]').dataset.db`);
// The note stays under Scope assessment wherever that goes.
out.noteFollows = await ev(`document.querySelector(sid('wf-scope')).nextElementSibling.id`);

// 6. Keyboard: Alt+Down on Scope assessment, Alt+Up back, crossing sections, Alt+Shift for the section.
await ev(`document.querySelector(sid('wf-scope')).focus(), 1`);
await key('ArrowDown', ALT);
out.kbDown = await ev('flat()');
out.kbFocus = await ev('document.activeElement.dataset.sbId');
out.kbSaid = await ev('__said[__said.length - 1]');
out.kbNoteFollows = await ev(`document.querySelector(sid('wf-scope')).nextElementSibling.id`);
await key('ArrowDown', ALT);   // last in Workflow -> first in the next section
out.kbCross = await ev('flat()');
await key('ArrowUp', ALT);     // back into Workflow, at its end
out.kbBack = await ev('flat()');
await key('ArrowUp', ALT | SHIFT);   // Workflow section up one
out.kbSection = await ev('flat()');
out.kbSectionFocus = await ev('document.activeElement.dataset.sbId');
out.kbSectionSaid = await ev('__said[__said.length - 1]');
await ev(`document.querySelector(sid('wf-configure')).focus(), 1`);
const before = await ev('flat()');
// Workflow is first and Connect its first item: Alt+Up has nowhere to go.
await key('ArrowUp', ALT);
out.kbEdgeUnchanged = JSON.stringify(before) === JSON.stringify(await ev('flat()'));
out.kbEdgeSaid = await ev('__said[__said.length - 1]');

// 7. Persistence: the saved value is ids, and a reload restores the order.
out.saved = await ev(`JSON.parse(localStorage.getItem('__KEY__'))`);
const beforeReload = await ev('flat()');
await open('h.html');
out.reloadSame = JSON.stringify(beforeReload) === JSON.stringify(await ev('flat()'));

// 8. Reset from the sidebar foot menu.
await click('#sbOrderMenu > summary');
out.menuOpen = await ev(`document.getElementById('sbOrderMenu').open`);
await click('#sbOrderReset');
out.afterReset = await ev('flat()');
out.storageAfterReset = await ev(`localStorage.getItem('__KEY__')`);
out.resetSaid = await ev('__said[__said.length - 1]');
out.resetFocus = await ev(`document.activeElement.tagName`);

// 9. Merge: unknown ids dropped, new items and sections in their default place.
const saved = { v: 1, sections: [
  { id: 'reference', items: ['fn-hit-upd', 'gone-item', 'fn-hit-adv'] },
  { id: 'gone-section', items: ['fn-hit-help'] },
  { id: 'find-gaps', items: ['fn-hit-path', 'fn-hit-flow', 'fn-openToolTab-efficacy'] },
  { id: 'workflow', items: ['wf-dashboard', 'wf-configure', 'wf-scope'] },
  { id: 'start', items: ['fn-hit-help'] },
] };
await open('h2.html', JSON.stringify(saved));
out.merged = await ev('flat()');

// 10. Corrupt or hostile storage falls back to the default, with no errors and nothing inserted.
out.corrupt = [];
for (const bad of ['{bad', 'null', '[1,2]', '{"v":2,"sections":[]}', '{"v":1,"sections":"x"}', '{"v":1,"sections":[{"id":"<img src=x onerror=hit(1)>","items":[]}]}',
                   '{"v":1,"sections":[{"id":"workflow","items":[1,{"a":1},"<b>x</b>"]}]}', 'x'.repeat(70000)]) {
  await open('h.html', bad);
  out.corrupt.push({ order: await ev('flat()'), errors: await ev('__errors.slice()'), imgs: await ev(`document.querySelectorAll('#dbSidebar img, #dbSidebar b').length`) });
}

// 11. localStorage that throws: the page still works and keeps its default order.
await open('h.html', null);
await ev(`Object.defineProperty(window, 'localStorage', { get() { throw new Error('blocked'); } }), 1`);
out.throwingInit = await ev(`(() => { const c = SidebarOrder.init({ root: document.getElementById('dbSidebar'), container: document.getElementById('dbTools') }); c.save(); c.reset(); return c.current().length; })()`);

// 12. Narrow width: dragging is off, Alt+arrows still move.
await open('h.html', null);
await send('Emulation.setDeviceMetricsOverride', { width: 800, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(150);
out.dragOnNarrow = await ev(`document.getElementById('dbSidebar').classList.contains('sb-drag-on')`);
await ev(`document.getElementById('dbSidebar').style.cssText = 'transform:none;visibility:visible', 1`);
t = await ev(`ctr(sid('fn-hit-flow'))`);
await drag(`[data-sb-id="fn-hit-path"]`, t.x, t.top + 3);
out.narrowAfterDrag = await ev('flat()');
await ev(`document.querySelector(sid('fn-hit-path')).focus(), 1`);
await key('ArrowUp', ALT);
out.narrowAfterKey = await ev('flat()');
out.errors = await ev('__errors.slice()');

console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def browser_run(tmp_path_factory):
    chrome, node = _chrome(), shutil.which("node")
    if not chrome or not node:
        pytest.skip("needs node and Chrome/Chromium")
    d = tmp_path_factory.mktemp("sidebar")
    for f in ("sidebar_order.js", "dashboard.css"):
        shutil.copy(os.path.join(ROOT, "static", f), d / f)
    (d / "h.html").write_text(HARNESS.replace("__EXTRA__", "").replace("__EXTRA_SEC__", ""), encoding="utf-8")
    # The app grew an item (Live feed, between Path analyzer and DLP efficacy) and a section (Troubleshoot).
    (d / "h2.html").write_text(HARNESS.replace("__EXTRA__", '<button class="btn btn-ghost" onclick="hit(\'live\')">Live feed</button>').replace(
        "__EXTRA_SEC__", '<div class="tool-group" role="group" aria-label="Troubleshoot" data-sb-id="troubleshoot"><div class="tool-group-l">Troubleshoot</div>'
        '<button class="btn btn-ghost" onclick="hit(\'logs\')">Logs</button></div>'), encoding="utf-8")
    (d / "drive.mjs").write_text(DRIVER.replace("__KEY__", KEY), encoding="utf-8")

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *a, **k):
            super().__init__(*a, directory=str(d), **k)

        def log_message(self, *a):
            pass

    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        r = subprocess.run([node, str(d / "drive.mjs"), chrome, f"http://127.0.0.1:{httpd.server_port}/", str(d / "profile")],
                           capture_output=True, text=True, timeout=180)
    finally:
        httpd.shutdown()
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


DEFAULT = ["workflow:wf-configure,wf-scope,wf-dashboard", "start:fn-hit-help",
           "find-gaps:fn-hit-flow,fn-hit-path,fn-openToolTab-efficacy", "reference:fn-hit-adv,fn-hit-upd"]


def test_items_get_stable_ids_and_drag_is_on_at_desktop_width(browser_run):
    assert browser_run["default"] == DEFAULT
    assert browser_run["dragOnWide"] is True
    assert "Alt+ArrowUp" in browser_run["keyshortcuts"] and "Alt+Shift+ArrowDown" in browser_run["keyshortcuts"]


def test_dragging_reorders_items_within_and_across_sections_and_whole_sections(browser_run):
    r = browser_run
    assert r["lineShownDuringDrag"] is True, "an insertion line shows where the drop lands"
    assert r["afterWithin"][2] == "find-gaps:fn-hit-path,fn-hit-flow,fn-openToolTab-efficacy"
    assert r["hitsAfterDrag"] == [], "a drag is not a click"
    assert r["saidWithin"] == "Moved Path analyzer to position 1 of 3 in Find the gaps."
    assert r["focusAfterDrag"] == "fn-hit-path"
    assert r["afterCross"][2:] == ["find-gaps:fn-hit-path,fn-hit-flow", "reference:fn-hit-adv,fn-hit-upd,fn-openToolTab-efficacy"]
    assert r["afterSection"] == ["reference:fn-hit-adv,fn-hit-upd,fn-openToolTab-efficacy", "workflow:wf-configure,wf-scope,wf-dashboard",
                                 "start:fn-hit-help", "find-gaps:fn-hit-path,fn-hit-flow"]
    assert r["saidSection"] == "Moved section Reference to position 1 of 4."


def test_clicks_still_activate_after_a_reorder(browser_run):
    assert browser_run["clicksAfter"] == ["path", "tab:efficacy", "db:scope"]
    assert browser_run["currentAfter"] == "scope", "aria-current follows the item, not its position"
    assert browser_run["noteFollows"] == "dbRunNote"


def test_alt_arrows_move_the_focused_item_and_alt_shift_its_section(browser_run):
    r = browser_run
    assert r["kbDown"][1] == "workflow:wf-configure,wf-dashboard,wf-scope"
    assert r["kbFocus"] == "wf-scope"
    assert r["kbSaid"] == "Moved Scope assessment to position 3 of 3 in Workflow."
    assert r["kbNoteFollows"] == "dbRunNote"
    assert r["kbCross"][1:3] == ["workflow:wf-configure,wf-dashboard", "start:wf-scope,fn-hit-help"]
    assert r["kbBack"][1:3] == ["workflow:wf-configure,wf-dashboard,wf-scope", "start:fn-hit-help"]
    assert r["kbSection"][:2] == ["workflow:wf-configure,wf-dashboard,wf-scope", "reference:fn-hit-adv,fn-hit-upd,fn-openToolTab-efficacy"]
    assert r["kbSectionFocus"] == "wf-scope"
    assert r["kbSectionSaid"] == "Moved section Workflow to position 1 of 4."
    assert r["kbEdgeUnchanged"] is True
    assert r["kbEdgeSaid"] == "Connect to the tenant is already at the top of the sidebar."


def test_the_order_is_saved_by_id_and_restored_on_reload(browser_run):
    s = browser_run["saved"]
    assert s["v"] == 1 and [x["id"] for x in s["sections"]] == ["workflow", "reference", "start", "find-gaps"]
    assert s["sections"][0]["items"] == ["wf-configure", "wf-dashboard", "wf-scope"]
    assert browser_run["reloadSame"] is True


def test_reset_puts_the_default_back_and_forgets_the_saved_order(browser_run):
    assert browser_run["menuOpen"] is True
    assert browser_run["afterReset"] == DEFAULT
    assert browser_run["storageAfterReset"] is None
    assert browser_run["resetSaid"] == "Sidebar order reset to the default."
    assert browser_run["resetFocus"] == "SUMMARY"


def test_merge_drops_unknown_ids_and_places_new_items_and_sections_by_default(browser_run):
    assert browser_run["merged"] == [
        "reference:fn-hit-upd,fn-hit-adv",
        "troubleshoot:fn-hit-logs",                                                 # new section, after its default predecessor
        "find-gaps:fn-hit-path,fn-hit-live,fn-hit-flow,fn-openToolTab-efficacy",   # new item, after its default predecessor
        "workflow:wf-dashboard,wf-configure,wf-scope",
        "start:fn-hit-help",                                                        # the unknown section's ids are dropped with it
    ]


def test_corrupt_or_hostile_storage_falls_back_to_the_default(browser_run):
    for i, c in enumerate(browser_run["corrupt"]):
        assert c["errors"] == [] and c["imgs"] == 0, (i, c)
        assert c["order"] == DEFAULT, (i, c)
    assert browser_run["throwingInit"] == 4


def test_narrow_widths_turn_dragging_off_but_keep_the_keyboard(browser_run):
    r = browser_run
    assert r["dragOnNarrow"] is False
    assert r["narrowAfterDrag"] == DEFAULT
    assert r["narrowAfterKey"][2] == "find-gaps:fn-hit-path,fn-hit-flow,fn-openToolTab-efficacy"
    assert r["errors"] == []


# ── Pure merge/parse under node ─────────────────────────────────────

@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_parse_and_merge_without_a_browser(tmp_path):
    code = _read("static", "sidebar_order.js")
    f = tmp_path / "m.js"
    f.write_text("const window = {};\n" + code + r"""
const S = window.SidebarOrder;
const def = [{ id: 'a', items: ['1', '2'] }, { id: 'b', items: ['3'] }];
console.log(JSON.stringify({
  none: S.merge(def, null),
  bad: [S.parse('{'), S.parse('null'), S.parse(''), S.parse(42), S.parse('{"v":1,"sections":{}}')],
  dup: S.merge(def, S.parse('{"v":1,"sections":[{"id":"b","items":["2","2","1"]},{"id":"b","items":["3"]},{"id":"a","items":[]}]}')),
}));
""", encoding="utf-8")
    out = json.loads(subprocess.run(["node", str(f)], capture_output=True, text=True, check=True).stdout)
    assert out["none"] == [{"id": "a", "items": ["1", "2"]}, {"id": "b", "items": ["3"]}]
    assert out["bad"] == [None, None, None, None, None]
    # Duplicates keep their first place; the second "b" is ignored, so 3 goes back to its default place (first in b).
    assert out["dup"] == [{"id": "b", "items": ["3", "2", "1"]}, {"id": "a", "items": []}]
