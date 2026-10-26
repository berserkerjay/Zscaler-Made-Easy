"""The rule filter in "Export from tenant as a pack" must keep keyboard focus
while the operator types (and so must Remove rules' filter, same pattern).
Drives the real static/deploy_studio.js in headless Chromium over CDP (node +
chrome). Skips when either is missing. Copy into tests/."""
import glob, http.server, json, os, shutil, subprocess, threading

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPRO = os.path.join(os.path.dirname(os.path.abspath(__file__)))


def _chrome():
    c = os.environ.get("CHROME_BIN")
    if c and os.path.exists(c):
        return c
    hits = glob.glob(os.path.expanduser("~/AppData/Local/ms-playwright/chromium-*/chrome-win64/chrome.exe")) + \
        glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium-*/chrome-linux/chrome"))
    return hits[0] if hits else shutil.which("chromium") or shutil.which("google-chrome")


HARNESS = r"""<!doctype html><html><head><meta charset="utf-8"></head><body>
<div id="dzTitle"></div><div id="dzSteps"></div><div id="dzSub"></div><div id="dzBody"></div><div id="dzFoot"></div>
<script>function escapeHtml(s){return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));} function announce(){}</script>
<script src="deploy_studio.js"></script>
<script>
window.setup = function(n){
  const chans=['web','endpoint','saas','email']; const rules=[];
  for(let i=0;i<n;i++) rules.push({channel:chans[i%4], id:1000+i, name:`Rule ${i}`, state:'ENABLED', engines:[`Engine ${i}`], action:'BLOCK', parent_id:null});
  DZ.exportPack={inventory:{tenant_label:'acme',errors:{}}, rules, selected:new Set(rules.map(r=>`${r.channel}:${r.id}`)), filter:'', name:'', result:null, running:false};
  _dzExportRender(); return 1;
};
window.setupRemoval = function(n){
  const chans=['web','endpoint','saas','email']; const rules=[];
  for(let i=0;i<n;i++) rules.push({channel:chans[i%4], id:1000+i, name:`Rule ${i}`, state:'ENABLED', engines:[`Engine ${i}`], action:'BLOCK', parent_id:null, tagged:false});
  DZ.removal={id:RM_PICK, mode:'pick', pack:{id:RM_PICK, name:'the selected rules'}, inventory:{tenant_label:'acme', rules, orphans:{}, errors:{}}, selected:new Set(), filter:'', plan:null, step:0, result:null};
  _dzRemovalRender(); return 1;
};
</script></body></html>"""

DRIVER = r"""
import { spawn } from 'node:child_process';
import { readFile } from 'node:fs/promises';
const [chrome, url, dir, which] = process.argv.slice(2);
const p = spawn(chrome, ['--headless=new', '--remote-debugging-port=0', '--remote-debugging-address=127.0.0.1', '--no-first-run', `--user-data-dir=${dir}`, 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
// Chrome picks a free port itself (port 0) and writes it to DevToolsActivePort in its own profile:
// never a guessed port that another browser on this machine may already own.
let port; for (let i = 0; i < 200 && !port; i++) { try { port = (await readFile(`${dir}/DevToolsActivePort`, 'utf8')).split('\n')[0].trim(); } catch {} if (!port) await sleep(100); }
if (!port) throw new Error('Chrome did not open its debugging port');
let tabs; for (let i=0;i<200;i++){ try { tabs = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (tabs.find(t=>t.type==='page')) break; } catch {} await sleep(200); }
const ws = new WebSocket(tabs.find(t=>t.type==='page').webSocketDebuggerUrl);
await new Promise(r => ws.onopen = r);
let id=0; const pend={}; ws.onmessage = e => { const m=JSON.parse(e.data); if(m.id&&pend[m.id]) {pend[m.id](m); delete pend[m.id];} };
const send=(method,params={})=>new Promise(r=>{const i=++id; pend[i]=r; ws.send(JSON.stringify({id:i,method,params}));});
const ev=async x=>(await send('Runtime.evaluate',{expression:x,returnByValue:true,awaitPromise:true})).result.result.value;
await send('Page.enable'); await send('Page.navigate',{url});
// Ready when the harness has defined its setup functions, however long loading takes on a busy machine.
for (let i=0;i<200 && !(await ev(`typeof setup === 'function' && typeof setupRemoval === 'function'`));i++) await sleep(50);
await ev(which === 'removal' ? `setupRemoval(900)` : `setup(900)`);
await ev(`document.querySelector('input[aria-label="Filter rules"]').focus(), 1`);
for (const ch of 'Rule 12') { await send('Input.insertText',{text:ch}); }
const out = await ev(`({filter: ${which === 'removal' ? 'DZ.removal' : 'DZ.exportPack'}.filter, active: document.activeElement.getAttribute('aria-label')||document.activeElement.tagName, rows: document.querySelectorAll('.dz-pick').length})`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.mark.parametrize("which", ["export", "removal"])
def test_export_rule_filter_keeps_focus_while_typing(tmp_path, which):
    chrome, node = _chrome(), shutil.which("node")
    if not chrome or not node:
        pytest.skip("needs node and a Chromium build")
    shutil.copy(os.path.join(ROOT, "static", "deploy_studio.js"), tmp_path / "deploy_studio.js")
    (tmp_path / "harness.html").write_text(HARNESS, encoding="utf-8")
    (tmp_path / "drive.mjs").write_text(DRIVER, encoding="utf-8")
    handler = lambda *a, **k: http.server.SimpleHTTPRequestHandler(*a, directory=str(tmp_path), **k)  # noqa: E731
    httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{httpd.server_address[1]}/harness.html"
        out = subprocess.run([node, str(tmp_path / "drive.mjs"), chrome, url, str(tmp_path / "profile"), which],
                             capture_output=True, text=True, timeout=120)
    finally:
        httpd.shutdown()
    res = json.loads(out.stdout.strip().splitlines()[-1])
    # Typing "Rule 12" filters to Rule 12 and Rule 120-129 (11 rows), focus stays in the box.
    assert res["filter"] == "Rule 12", res
    assert res["active"] == "Filter rules", res
    assert res["rows"] == 11, res
