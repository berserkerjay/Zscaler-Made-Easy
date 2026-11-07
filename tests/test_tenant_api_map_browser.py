"""The Tenant API map page in a real browser (headless Chrome over CDP, as tests/test_findings_reflow.py drives it): the real
app serves the real page and, with the sample tenant chosen, runs the real map offline.

Checked: nothing is sent before the endpoint list is confirmed; the list shows exactly the endpoints the plan holds; Cancel
returns focus to the button; the whole flow works from the keyboard (Enter on the buttons); the result draws the feature
and endpoint tables with the verdict words, a "no permission" row, the saved-map list and the export links; a markup payload
is shown as text; help marks sit beside the controls; nothing scrolls the page sideways at 320 and 390 px (wide tables scroll
inside their own region); the verdict chips and dim text keep 4.5:1 in both themes. Skips without node or Chrome."""
from __future__ import annotations

import json

import pytest

from test_findings_reflow import CDP_PRELUDE, run_in_browser

DRIVER = CDP_PRELUDE + r"""
const sleepMs = ms => new Promise(r => setTimeout(r, ms));
const key = async (k, code, vk, text) => {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, text });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk });
};
const overflow = () => ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
async function go(url, width) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + url });
  await until(() => ev(`document.readyState === 'complete'`), 'load ' + url);
}
const out = {};
await go('/', 1280);
// The sample tenant: the page's run is answered offline by the real server.
await until(() => ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status === 200)`), 'the sample tenant');
await go('/report/api-map', 1280);
await until(() => ev(`document.querySelectorAll('#amProducts input[data-product]').length >= 8`), 'the product boxes');
out.intro = await ev(`({ h1: document.querySelector('.rp-hero h1').textContent, separate: /its own tool/.test(document.querySelector('.rp-hero p').textContent) &&
  /separate from the Scope page/.test(document.querySelector('.rp-hero p').textContent), products: document.querySelectorAll('#amProducts input').length,
  confirmHidden: document.getElementById('amConfirmBox').hidden, features: !!document.getElementById('amFeatures') })`);

// 1. Run -> the list, nothing sent.
await ev(`document.getElementById('amRun').focus(), 1`);
await key('Enter', 'Enter', 13, '\r');
await until(() => ev(`!document.getElementById('amConfirmBox').hidden && !!document.getElementById('amConfirm')`), 'the confirmation');
out.list = await ev(`(() => {
  const rows = document.querySelectorAll('#amConfirmBox details[open] tbody tr').length;
  const btn = document.getElementById('amConfirm').textContent;
  return { rows, btn, focusedId: document.activeElement.id, started: performance.getEntriesByType('resource').filter(r => r.name.includes('/tenant-api-map/start')).length,
    planned: performance.getEntriesByType('resource').filter(r => r.name.includes('/tenant-api-map/plan')).length, get: /GET/.test(document.getElementById('amConfirmBox').textContent),
    noScope: /does not use the Scope page/.test(document.getElementById('amConfirmBox').textContent), features: !!document.getElementById('amFeatures') };
})()`);

// 2. Cancel -> focus back on the button, still nothing sent.
await ev(`document.getElementById('amCancel').focus(), 1`);
await key('Enter', 'Enter', 13, '\r');
out.cancel = await ev(`({ hidden: document.getElementById('amConfirmBox').hidden, focused: document.activeElement.id,
  started: performance.getEntriesByType('resource').filter(r => r.name.includes('/tenant-api-map/start')).length })`);

// 3. Features only, run, confirm from the keyboard.
await ev(`document.getElementById('amFeaturesOnly').click(), document.getElementById('amRun').click(), 1`);
await until(() => ev(`!!document.getElementById('amConfirm')`), 'the short list');
out.short = await ev(`document.querySelectorAll('#amConfirmBox details[open] tbody tr').length`);
await ev(`document.getElementById('amCancel').click(), document.getElementById('amFeaturesOnly').click(), document.getElementById('amRun').click(), 1`);
await until(() => ev(`!!document.getElementById('amConfirm')`), 'the full list');
await ev(`document.getElementById('amConfirm').focus(), 1`);
await key('Enter', 'Enter', 13, '\r');
await until(() => ev(`!!document.getElementById('amFeatures')`), 'the result', 60000);
out.result = await ev(`(() => {
  const rows = [...document.querySelectorAll('#amFeatures tbody tr')].map(tr => [...tr.children].map(c => c.textContent.trim()));
  const eps = document.querySelectorAll('#amEps tbody tr').length;
  const chips = [...new Set([...document.querySelectorAll('#amBody .df-chip')].map(c => c.textContent))];
  return { features: rows.length, webDlp: rows.find(r => r[0] === 'Web DLP'), zwa: rows.find(r => r[0].startsWith('Workflow Automation')), eps, chips,
    tiles: [...document.querySelectorAll('.am-stat')].map(t => t.textContent), meta: document.getElementById('rpMeta').textContent,
    exportHrefs: ['amExpJson', 'amExpFeat', 'amExpEps'].map(id => { const a = document.getElementById(id); return [a.hidden, a.getAttribute('href')]; }),
    saved: !!document.getElementById('amSaved'), startCalls: performance.getEntriesByType('resource').filter(r => r.name.includes('/tenant-api-map/start')).length };
})()`);

// 4. Filter to the endpoint that refused this API client.
await ev(`document.querySelector('#amBody .am-filter button[data-v="no permission"]').click(), 1`);
out.filter = await ev(`({ rows: [...document.querySelectorAll('#amEps tbody tr')].map(tr => tr.children[0].textContent.trim()), pressed: document.querySelector('.am-filter button[aria-pressed="true"]').dataset.v,
  focused: document.activeElement.dataset.v })`);

// 5. The export link downloads a JSON map with no values.
out.export = await ev(`fetch(document.getElementById('amExpJson').getAttribute('href')).then(async r => { const t = await r.text(); return { status: r.status, type: r.headers.get('content-type'), disp: r.headers.get('content-disposition'), valuesKept: t.includes('"values_kept": false'), bytes: t.length }; })`);
out.csv = await ev(`fetch(document.getElementById('amExpEps').getAttribute('href')).then(async r => ({ status: r.status, head: (await r.text()).split(String.fromCharCode(10))[0] }))`);

// 6. Help marks beside the controls.
out.help = await ev(`(() => { window.HoverHelp && window.HoverHelp.scan && window.HoverHelp.scan();
  const marks = [...document.querySelectorAll('.hh-mark')]; const names = marks.map(m => m.getAttribute('aria-label') || m.textContent);
  return { n: marks.length, run: !!document.getElementById('amRun').parentElement.querySelector('.hh-mark') || marks.some(m => m.__hhFor && m.__hhFor.id === 'amRun'), names: names.slice(0, 12) }; })()`);

// 7. Phones and both themes.
out.narrow = {};
for (const w of [320, 390]) {
  await go('/report/api-map', w);
  await until(() => ev(`document.querySelectorAll('#amProducts input').length >= 8`), 'boxes at ' + w);
  await ev(`document.getElementById('amFeaturesOnly').click(), document.getElementById('amRun').click(), 1`);
  await until(() => ev(`!!document.getElementById('amConfirm')`), 'list at ' + w);
  const listOverflow = await overflow();
  await ev(`document.getElementById('amConfirm').click(), 1`);
  await until(() => ev(`!!document.getElementById('amFeatures')`), 'result at ' + w, 60000);
  out.narrow[w] = { list: listOverflow, result: await overflow(), scrollRegions: await ev(`[...document.querySelectorAll('.am-scroll')].every(e => e.scrollWidth >= e.clientWidth)`) };
}
const LUM = String.raw`const lin = c => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
  const parse = s => { const m = s.match(/[\d.]+/g).map(Number); if (/^color\(/.test(s)) return m.slice(0, 3).map(v => v * 255); return m.slice(0, 3); };
  const L = c => 0.2126 * lin(c[0]) + 0.7152 * lin(c[1]) + 0.0722 * lin(c[2]);
  const bgOf = e => { for (let n = e; n; n = n.parentElement) { const b = getComputedStyle(n).backgroundColor; const a = (b.match(/[\d.]+/g) || []).map(Number); if (!/rgba\(.*,\s*0\)$/.test(b) && b !== 'transparent' && (a[3] === undefined || a[3] > 0.9)) return parse(b); } const pr = document.createElement('i'); pr.style.background = 'var(--card-solid)'; document.body.appendChild(pr); const c = parse(getComputedStyle(pr).backgroundColor); pr.remove(); return c; };
  const ratio = e => { const f = parse(getComputedStyle(e).color), b = bgOf(e); const l1 = L(f), l2 = L(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); };`;
out.themes = {};
for (const theme of ['dark', 'light']) {
  await ev(`(localStorage.setItem('zassess_theme', '${theme}'), true)`);
  await go('/report/api-map', 1280);
  await until(() => ev(`document.querySelectorAll('#amProducts input').length >= 8`), 'boxes ' + theme);
  await ev(`document.getElementById('amFeaturesOnly').click(), document.getElementById('amRun').click(), 1`);
  await until(() => ev(`!!document.getElementById('amConfirm')`), 'list ' + theme);
  await ev(`document.getElementById('amConfirm').click(), 1`);
  await until(() => ev(`!!document.getElementById('amFeatures')`), 'result ' + theme, 60000);
  out.themes[theme] = await ev(`(() => { ${LUM}
    const sel = '#amBody .df-chip, #amBody .am-dim, #amBody .am-stat .k, #amBody .df-table th[scope=col], #amBody .df-table td';
    const worst = [...document.querySelectorAll(sel)].filter(e => e.textContent.trim() && e.offsetParent).map(e => [ratio(e), e.className, e.textContent.trim().slice(0, 20)]).sort((a, b) => a[0] - b[0])[0];
    return { light: document.body.classList.contains('theme-light'), worst }; })()`);
}
await ev(`(localStorage.setItem('zassess_theme', 'dark'), true)`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    return run_in_browser(tmp_path_factory.mktemp("apimap"), DRIVER, timeout=420)


def test_the_page_says_it_is_its_own_tool_and_its_own_action(page):
    """WCAG 2.2 SC 3.3.2 · ASVS V1.14: the page states that it is separate from the licence check and from the Scope page, and offers the products."""
    assert page["intro"]["h1"].startswith("Tenant API map") and page["intro"]["separate"] and page["intro"]["products"] >= 8
    assert page["intro"]["confirmHidden"] is True and page["intro"]["features"] is False


def test_the_list_is_shown_with_every_endpoint_and_nothing_is_sent_before_confirming(page):
    """ASVS V4.2.2 · WCAG 2.2 SC 3.3.4: Enter on the button shows the exact endpoint list, GET and the no-Scope-page statement, focus moves to it, and no start request was made."""
    li = page["list"]
    assert li["rows"] > 300 and li["btn"] == f"Read these {li['rows']} endpoints" and li["focusedId"] == "amConfirmH"
    assert li["started"] == 0 and li["planned"] >= 2 and li["get"] and li["noScope"] and li["features"] is False


def test_cancel_reads_nothing_and_returns_focus_to_the_button(page):
    """WCAG 2.2 SC 2.4.3 · SC 3.2.2: Cancel closes the list, focus returns to Map this tenant's APIs, still no start request."""
    assert page["cancel"] == {"hidden": True, "focused": "amRun", "started": 0}


def test_features_only_is_a_short_list(page):
    """ASVS V5.1.3: ticking features only shows the short list of deciding endpoints (about 45)."""
    assert 20 <= page["short"] <= 60


def test_the_result_has_the_feature_table_the_endpoint_table_and_the_verdict_words(page):
    """WCAG 2.2 SC 1.3.1 · SC 1.4.1: features and endpoints are tables; each result is a word, not only a colour; one start request was made."""
    r = page["result"]
    assert r["features"] >= 27 and r["webDlp"][1] == "Present" and r["webDlp"][2] == "/zia/api/v1/webDlpRules" and r["zwa"][1] == "Not checked"
    assert r["eps"] > 300 and {"Present", "Not licensed or not enabled", "No permission"} <= set(r["chips"]) and r["startCalls"] == 1
    assert r["saved"] is True and "Sample tenant" in r["meta"]
    assert all(h[0] is False and "/api/tenant-api-map/export/apimap-" in h[1] for h in r["exportHrefs"])


def test_the_filter_shows_the_refused_endpoint_and_keeps_focus(page):
    """WCAG 2.2 SC 2.4.3 · SC 4.1.2: the No permission button is pressed, lists the one endpoint the sample client may not read, and keeps focus."""
    f = page["filter"]
    assert f["rows"] == ["/zia/api/v1/users/auditors"] and f["pressed"] == "no permission" and f["focused"] == "no permission"


def test_the_exports_download_with_no_value(page):
    """CWE-200 · ASVS V8.3.4: the JSON export is an attachment of statuses, counts and field names; the CSV starts with its header row."""
    e, c = page["export"], page["csv"]
    assert e["status"] == 200 and "application/json" in e["type"] and "attachment" in e["disp"] and e["valuesKept"] is True and e["bytes"] > 1000
    assert c["status"] == 200 and c["head"].startswith("product,endpoint,http status,verdict")


def test_help_marks_sit_beside_the_controls(page):
    """WCAG 2.2 SC 3.3.5: the page's controls get their help marks from the catalogue."""
    assert page["help"]["n"] >= 5 and page["help"]["run"]


@pytest.mark.parametrize("w", ["320", "390"])
def test_nothing_scrolls_sideways_on_a_phone(page, w):
    """WCAG 2.2 SC 1.4.10: at 320 and 390 px neither the list nor the result widens the page; wide tables scroll inside their own region."""
    n = page["narrow"][w]
    assert n["list"] <= 0 and n["result"] <= 0 and n["scrollRegions"] is True


@pytest.mark.parametrize("theme", ["dark", "light"])
def test_text_keeps_aa_contrast_in_both_themes(page, theme):
    """WCAG 2.2 SC 1.4.3: chips, dim text, headers and cells keep at least 4.5:1 in the dark and the light theme."""
    t = page["themes"][theme]
    assert t["light"] is (theme == "light")
    assert t["worst"][0] >= 4.5, t["worst"]
