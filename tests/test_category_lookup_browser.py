"""The Category lookup tab in a real browser (headless Chrome over CDP, as
tests/test_findings_reflow.py drives it): the real app serves the real
page; only the lookup's two endpoints answer with a fixture (category_lookup
run over the fake tenant of tests/test_category_lookup.py), through the CDP
Fetch domain, so no tenant is read.

Checked: a #categories= link (Find anything) opens the tab and fills the
box without reading; Look up draws each category with its rules in
evaluation order; a markup payload from the tenant is shown as text; the
tabs are keyboard operable; nothing scrolls the page sideways at 320 or
390 px; Trace its path moves the host to the first tab. With CL_SHOT_DIR set
it also saves screenshots there. Skips without node or Chrome.
"""
from __future__ import annotations

import json
import os

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

DRIVER = CDP_PRELUDE + r"""
const F = JSON.parse(args[0]);
const shots = args[1] || '';
const handlers = [];
let started = 0;
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m); delete pend[m.id]; } else if (m.method) handlers.forEach(h => h(m)); };
handlers.push(async m => {
  if (m.method !== 'Fetch.requestPaused') return;
  const u = m.params.request.url;
  let body = null;
  if (u.includes('/api/category-lookup/start')) { started++; body = { job_id: 'catjob', status: 'running', entries: F.entries.length }; }
  else if (u.includes('/jobs/catjob')) body = { status: 'done', result: F, logs: ['Reading the URL filtering rules…', "Asking ZIA's URL lookup about 2 destination(s)…"], next: 2 };
  if (!body) { await send('Fetch.continueRequest', { requestId: m.params.requestId }); return; }
  await send('Fetch.fulfillRequest', { requestId: m.params.requestId, responseCode: 200, responseHeaders: [{ name: 'Content-Type', value: 'application/json' }], body: Buffer.from(JSON.stringify(body)).toString('base64') });
});
await send('Fetch.enable', { patterns: [{ urlPattern: '*/api/category-lookup/start*' }, { urlPattern: '*/api/dlp-packs/jobs/*' }] });
const overflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
async function shot(name, sel) {
  if (!shots) return;
  const r = await ev(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.scrollIntoView({block:'start'}); const b = e.getBoundingClientRect(); return {x: b.left, y: b.top + scrollY, w: b.width, h: Math.min(b.height, 2400)}; })()`);
  await sleep(300);
  const s = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip: { x: r.x, y: r.y, width: r.w, height: r.h, scale: 1 } });
  fs.writeFileSync(path.join(shots, name + '.png'), Buffer.from(s.result.data, 'base64'));
}
async function go(url, width) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + url });
  await until(() => ev(`document.readyState === 'complete'`), 'load ' + url);
}
const out = {};

// 1. A Find anything link: the tab opens, the box is filled, nothing is read.
await go('/report/path#categories=' + encodeURIComponent('casino.example'), 1280);
await until(() => ev(`document.getElementById('tab-cat').getAttribute('aria-selected') === 'true'`), 'the Category lookup tab');
await sleep(400);
out.link = await ev(`({ value: document.getElementById('clText').value, panel: !document.getElementById('panel-cat').hidden,
  others: document.getElementById('panel-one').hidden && document.getElementById('panel-list').hidden, focused: document.activeElement.id })`);
out.link.started = started;

// 2. Look up: the answer.
await ev(`document.getElementById('clText').value = 'casino.example\\nportal.partner.example\\ncategory:Partner portals', document.getElementById('clRun').click(), 1`);
await until(() => ev(`!!document.getElementById('clSummary')`), 'the answer');
out.answer = await ev(`(() => {
  const sec = [...document.querySelectorAll('#clBody .cl-entry')];
  return { entries: sec.length, heads: sec.map(s => s.querySelector('h2').textContent.trim()),
    firstRules: [...sec[0].querySelectorAll('table tbody tr')].slice(0, 5).map(tr => [...tr.children].map(td => td.textContent.trim())),
    imgs: document.querySelectorAll('#clBody img').length, canary: document.getElementById('clBody').textContent.includes('<img src=x onerror=alert(1)>'),
    focused: document.activeElement.id, read: document.querySelectorAll('#clBody .df-table').length };
})()`);
out.answer.started = started;
await shot('category_lookup_desktop', '#panel-cat');

// 3. The tabs from the keyboard.
await ev(`document.getElementById('tab-cat').focus(), 1`);
await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 });
await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'ArrowRight', code: 'ArrowRight', windowsVirtualKeyCode: 39 });
out.keys = await ev(`({ focused: document.activeElement.id, selected: document.querySelector('[role=tab][aria-selected=true]').id })`);
await ev(`document.getElementById('tab-cat').click(), 1`);

// 4. Trace its path moves the host to the first tab.
await ev(`document.querySelector('[data-cltrace]').click(), 1`);
out.trace = await ev(`({ dest: document.getElementById('paDest').value, selected: document.querySelector('[role=tab][aria-selected=true]').id })`);

// 5. Phones: nothing scrolls sideways.
out.narrow = {};
for (const w of [320, 390]) {
  await go('/report/path#categories', w);
  await until(() => ev(`document.getElementById('tab-cat').getAttribute('aria-selected') === 'true'`), 'the tab at ' + w);
  await ev(`document.getElementById('clText').value = 'casino.example', document.getElementById('clRun').click(), 1`);
  await until(() => ev(`!!document.getElementById('clSummary')`), 'the answer at ' + w);
  out.narrow[w] = { overflow: await overflow() };
  if (w === 390) await shot('category_lookup_phone', '#panel-cat');
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""

XSS = "<img src=x onerror=alert(1)>"


def _fixture():
    import category_lookup as cl
    import data_flow as df
    from test_category_lookup import Client, ROUTES
    routes = json.loads(json.dumps(ROUTES))
    routes["/zia/firewallFilteringRules"].append({"id": 99, "name": XSS, "order": 3, "state": "ENABLED", "action": "ALLOW", "destIpCategories": ["GAMBLING"]})
    res = cl.run(Client(routes), cl.parse("casino.example\nportal.partner.example\ncategory:Partner portals"), df.full_path_scope())
    res.pop("snapshot_for_cache", None)
    return dict(json.loads(json.dumps(res, default=str)), status="done", report_id="catlookup-test", tenant_label="acme (zscalertwo)")


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    shots = os.environ.get("CL_SHOT_DIR", "")
    return run_in_browser(tmp_path_factory.mktemp("catlookup"), DRIVER, json.dumps(_fixture()), shots, timeout=240)


def test_a_find_anything_link_opens_the_tab_and_fills_the_box_without_reading(page):
    """ASVS V4.1.3 · CWE-352 · WCAG 2.2 SC 3.2.2: /report/path#categories=<host> selects the tab and fills the box; nothing is sent until Look up."""
    assert page["link"] == {"value": "casino.example", "panel": True, "others": True, "focused": "clText", "started": 0}


def test_look_up_draws_each_entry_with_its_rules_in_evaluation_order(page):
    """WCAG 2.2 SC 1.3.1 · SC 2.4.3: one section per entry, each category's rules in a table (policy, position, rule, order, rank, action, field); focus moves to the summary."""
    a = page["answer"]
    assert a["started"] == 1 and a["entries"] == 3 and a["focused"] == "clSummary"
    assert a["heads"][0].startswith("Destination: casino.example") and a["heads"][2] == "Category: category:Partner portals"
    assert a["firstRules"][0][:6] == ["URL filtering", "1", "Admin caution gambling", "5", "0", "caution"]


def test_a_markup_payload_from_the_tenant_is_shown_as_text(page):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: a rule named like an HTML tag is text on the page, never an element."""
    assert page["answer"]["imgs"] == 0 and page["answer"]["canary"]


def test_the_tabs_work_from_the_keyboard(page):
    """WCAG 2.2 SC 2.1.1 · SC 4.1.2: Arrow Right from the last tab wraps to the first, moving focus and selection."""
    assert page["keys"] == {"focused": "tab-one", "selected": "tab-one"}


def test_trace_its_path_hands_the_host_to_the_analyzer(page):
    """WCAG 2.2 SC 3.2.4: Trace its path fills the destination and shows the first tab."""
    assert page["trace"] == {"dest": "casino.example", "selected": "tab-one"}


@pytest.mark.parametrize("width", ["320", "390"])
def test_the_answer_never_scrolls_the_page_sideways_on_a_phone(page, width):
    """WCAG 2.2 SC 1.4.10: at 320 and 390 px the answer fits; tables scroll inside their own region."""
    assert page["narrow"][width]["overflow"] == 0
