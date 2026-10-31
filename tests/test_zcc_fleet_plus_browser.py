"""The Client Connector fleet page's new sections in a real browser (node +
headless Chrome over CDP, the harness of tests/test_findings_reflow.py;
skipped without either): on the made-up sample tenant the read shows the
version x service matrix, profile health, the last-seen histogram, site
grouping, the history with its trend chart and compare, and the PDF button;
an import of portal CSV files with a hostile host name stays text; nothing
scrolls sideways at 320px; every new control takes keyboard focus. No real
tenant is contacted: the sample is served from memory.

Set FLEET_SHOTS=<folder> to also save screenshots of the page there."""
from __future__ import annotations

import base64
import json
import os

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_sample_tenant_browser import EVENTS

HOSTILE = '<img src=x onerror="window.__xss=1">'
DEVICE_CSV = ('"User","Device type","Hostname","UDID","Zscaler Client Connector Version","Policy Name","Registration State"\n'
              + "".join(f'"u{i}@acme.example","Windows","LON-LT-{i:03d}","UD-{i}","4.7.2.5","Corp","Registered"\n' for i in range(1, 6))
              + f'"evil@acme.example","Windows","{HOSTILE.replace(chr(34), chr(34) * 2)}","UD-9","4.6.0.1","Corp","Registered"\n')
SERVICE_CSV = ('"User","Device type","UDID","ZIA Health","ZPA Health","ZDX Health","Last Seen Connected to ZIA"\n'
               + "".join(f'"u{i}@acme.example","Windows","UD-{i}","Active","Active","Active","2026-10-30 10:00:00 GMT"\n' for i in range(1, 6))
               + '"evil@acme.example","Windows","UD-9","Inactive","Active","Active","2026-10-30 09:00:00 GMT"\n')
NEW_CONTROLS = ["zfExpPdf", "zfImpDev", "zfImpSvc", "zfImpLabel", "zfImpGo", "zfSiteMode", "zfSiteApply", "zfHistSave", "zfHistForget",
                "zfHistA", "zfHistB", "zfHistCompare"]

DRIVER = CDP_PRELUDE + EVENTS + r"""
const [shots, devCsv, svcCsv, controlsJson] = args;
const out = {};
const frame = () => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`);
const shot = async name => {
  if (!shots) return;
  const m = await ev(`({ w: document.documentElement.clientWidth, h: Math.min(document.documentElement.scrollHeight, 12000) })`);
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: 0, width: m.w, height: m.h, scale: 1 } });
  fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(r.result.data, 'base64'));
};
// A screenshot of the page from one heading's section down to another's.
const shotPart = async (name, fromId, toId) => {
  if (!shots) return;
  const m = await ev(`(() => { const a = document.getElementById('${fromId}').closest('section').getBoundingClientRect(), b = document.getElementById('${toId}').closest('section').getBoundingClientRect();
    return { y: a.top + scrollY, h: b.bottom - a.top, w: document.documentElement.clientWidth }; })()`);
  const r = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: 0, y: m.y, width: m.w, height: Math.min(m.h, 6000), scale: 1 } });
  fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(r.result.data, 'base64'));
};
const overflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
await go('/report/fleet');
out.sample = await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
await ev(`(localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['zcc'] })), localStorage.removeItem('zf_site_rule_v1'), localStorage.setItem('zassess_theme', 'dark'), true)`);
await go('/report/fleet');
await until(() => ev(`!!document.getElementById('zfRun') && !!window.HoverHelp`), 'the fleet page');
const read = async () => {
  await ev(`(document.getElementById('zfRun').click(), true)`);
  await until(() => ev(`!!document.getElementById('zfHistBody') && !/Loading/.test(document.getElementById('zfHistBody').textContent)`), 'the fleet read', 60000);
  await settle('the fleet');
};
await read();
const sec = id => `document.getElementById('${id}').closest('section')`;
out.live = await ev(`({
  sections: ['zfVerH', 'zfProfHealthH', 'zfSeenH', 'zfSiteH', 'zfHistH'].filter(id => !document.getElementById(id)),
  verRows: ${sec('zfVerH')}.querySelectorAll('tbody tr').length,
  verText: ${sec('zfVerH')}.innerText,
  profText: ${sec('zfProfHealthH')}.innerText,
  seenRows: ${sec('zfSeenH')}.querySelectorAll('tbody tr').length, seenText: ${sec('zfSeenH')}.innerText,
  quarantine: [...document.querySelectorAll('.zf-tile .k')].some(k => k.textContent === 'Quarantined'),
  pdf: !document.getElementById('zfExpPdf').disabled,
  banner: document.querySelector('.zf-banner').className })`);
await shot('fleet_live_1280');
// Sites: group by the part before the first hyphen.
await ev(`(() => { const m = document.getElementById('zfSiteMode'); m.value = 'delimiter'; m.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
out.siteForm = await ev(`({ len: document.getElementById('zfSiteLenW').hidden, delim: document.getElementById('zfSiteDelimW').hidden, list: document.getElementById('zfSiteListW').hidden })`);
await ev(`(document.getElementById('zfSiteApply').click(), true)`);
await until(() => ev(`/LKF/.test(document.getElementById('zfSiteTable').innerText)`), 'the sites');
out.siteKept = await ev(`localStorage.getItem('zf_site_rule_v1')`);
// History: save, read again, save again: a trend chart and a compare.
await ev(`(document.getElementById('zfHistSave').click(), true)`);
await until(() => ev(`/Saved/.test(document.getElementById('zfHistStatus').textContent)`), 'the first save');
await sleep(1100);   // the next read gets a later read time (to the second)
await read();
await ev(`(document.getElementById('zfHistSave').click(), true)`);
await until(() => ev(`!!document.querySelector('#zfHistBody svg.zf-chart')`), 'the trend chart');
out.chart = await ev(`(() => { const s = document.querySelector('#zfHistBody svg.zf-chart'); return { role: s.getAttribute('role'), label: s.getAttribute('aria-label'), lines: s.querySelectorAll('polyline').length, rows: document.querySelectorAll('#zfHistBody tbody tr').length }; })()`);
await ev(`(document.getElementById('zfHistCompare').click(), true)`);
await until(() => ev(`!!document.querySelector('#zfHistCmp table')`), 'the compare');
out.compare = await ev(`document.getElementById('zfHistCmp').innerText.slice(0, 2000)`);
out.siteAfterRead = await ev(`/LKF/.test(document.getElementById('zfSiteTable').innerText)`);
// Keyboard: every new control takes focus.
out.focus = await ev(`${controlsJson}.filter(id => { const e = document.getElementById(id); if (!e) return true; e.focus(); return document.activeElement !== e; })`);
await shot('fleet_history_1280');
await shotPart('part_versions_profiles', 'zfVerH', 'zfProfHealthH');
await shotPart('part_lastseen_sites_history', 'zfSeenH', 'zfHistH');
// 320px: nothing scrolls sideways with every section open.
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await frame();
out.narrowLive = await overflow();
await shot('fleet_live_320');
await shotPart('part_320_versions', 'zfVerH', 'zfSeenH');
// Forget asks first (the harness accepts the dialog) and removes both snapshots.
await ev(`(document.getElementById('zfHistForget').click(), true)`);
await until(() => ev(`/Removed/.test(document.getElementById('zfHistStatus').textContent)`), 'forget');
out.forget = { dialogs: (seen.dialogs || []).slice(), status: await ev(`document.getElementById('zfHistStatus').textContent`) };
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
// Import: a hostile host name in the CSV stays text.
await ev(`(() => {
  const put = (id, name, text) => { const dt = new DataTransfer(); dt.items.add(new File([text], name, { type: 'text/csv' })); document.getElementById(id).files = dt.files; };
  put('zfImpDev', 'device_export_2026_10_30-10-00-00.csv', ${JSON.stringify(devCsv)});
  put('zfImpSvc', 'service_status_export_2026_10_30-10-00-05.csv', ${JSON.stringify(svcCsv)});
  document.getElementById('zfImpLabel').value = 'Acme import';
  document.getElementById('zfImpGo').click(); return true; })()`);
await until(() => ev(`/What was imported/.test(document.getElementById('zfOut').innerText)`), 'the import', 30000);
await until(() => ev(`!/Loading/.test((document.getElementById('zfHistBody') || {}).textContent || '')`), 'the import history');
await settle('the import');
out.imported = await ev(`({ xss: window.__xss || null, imgs: document.querySelectorAll('#zfOut img').length, text: document.getElementById('zfOut').innerText.includes('<img src=x'),
  status: document.getElementById('zfImpStatus').textContent, meta: document.getElementById('rpMeta').textContent,
  verRows: ${sec('zfVerH')}.querySelectorAll('tbody tr').length })`);
await shot('fleet_import_1280');
await shotPart('part_import_versions', 'zfVerH', 'zfSeenH');
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 800, deviceScaleFactor: 1, mobile: false });
await frame();
out.narrowImport = await overflow();
out.errors = seen.errors.splice(0);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def fleet_page(tmp_path_factory):
    shots = os.environ.get("FLEET_SHOTS", "")
    if shots:
        os.makedirs(shots, exist_ok=True)
    tmp = tmp_path_factory.mktemp("fleet_plus")
    mp = pytest.MonkeyPatch()
    mp.setenv("DLP_CHECK_FLEET_HISTORY", str(tmp / "fleet_history.json"))
    try:
        return run_in_browser(tmp, DRIVER, shots, DEVICE_CSV, SERVICE_CSV, json.dumps(NEW_CONTROLS), timeout=300)
    finally:
        mp.undo()


def test_the_sample_read_shows_every_new_section(fleet_page):
    """WCAG 2.2 SC 1.3.1 · SC 4.1.2 · ASVS V11.1.4: on the sample tenant the read shows the version matrix (three versions and the fleet row), profile health, the five last-seen buckets, sites, history, a Quarantined tile and the PDF button."""
    live = fleet_page["live"]
    assert fleet_page["sample"] == 200 and live["sections"] == [] and "full" in live["banner"]
    assert live["verRows"] == 4 and "4.5.0.334" in live["verText"] and "Whole fleet" in live["verText"]
    assert "Windows - Contractors" in live["profText"] and live["seenRows"] == 5 and "Never seen\t0" in live["seenText"] and live["quarantine"] and live["pdf"]


def test_site_grouping_shows_only_its_own_fields_and_is_kept(fleet_page):
    """WCAG 2.2 SC 3.3.2 · ASVS V5.1.3: the delimiter form shows its own fields only; the sites appear and the choice is kept in the browser and reused by the next read."""
    assert fleet_page["siteForm"] == {"len": True, "delim": False, "list": True}
    assert json.loads(fleet_page["siteKept"]) == {"mode": "delimiter", "delimiter": "-", "segments": 1}
    assert fleet_page["siteAfterRead"]


def test_history_draws_a_named_trend_chart_and_compares(fleet_page):
    """WCAG 2.2 SC 1.1.1 · SC 1.4.1 · ASVS V8.3.4: two saved reads draw a chart named in words (role img), with a table beside it; compare lists the change; forget asks first."""
    c = fleet_page["chart"]
    assert c["role"] == "img" and "ZIA from" in c["label"] and c["lines"] >= 2 and c["rows"] == 2
    assert "Registered" in fleet_page["compare"] and "Windows versions" in fleet_page["compare"]
    f = fleet_page["forget"]
    assert any("Remove all 2 saved fleet snapshots" in d for d in f["dialogs"]) and "Removed 2" in f["status"]


def test_every_new_control_takes_keyboard_focus(fleet_page):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3: every new control is reachable from the keyboard."""
    assert fleet_page["focus"] == []


def test_a_hostile_host_name_from_an_import_stays_text(fleet_page):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: an imported host name carrying markup is shown as text: no element, no script run."""
    imp = fleet_page["imported"]
    assert imp["xss"] is None and imp["imgs"] == 0 and imp["text"], imp
    assert "Imported 6 device records" in imp["status"] and "Acme import" in imp["meta"] and imp["verRows"] == 3


def test_no_sideways_scroll_at_320px(fleet_page):
    """WCAG 2.2 SC 1.4.10: at 320px, with every new section shown (read and import), the page never scrolls sideways."""
    assert fleet_page["narrowLive"] <= 0 and fleet_page["narrowImport"] <= 0


def test_no_script_or_http_error(fleet_page):
    """WCAG 2.2 SC 4.1.2 · CWE-754: the whole walk raised no script error, console error or HTTP error."""
    assert fleet_page["errors"] == []
