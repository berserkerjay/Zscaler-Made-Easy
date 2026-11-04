"""The Data Flow Map for first-time readers: a simple view by default (one
path as numbered steps in reading order, a decision word and a shape per
step, a legend beside it, one step's details at a time, a walk-through with
Back and Next) and "Show all details" with today's full map; the moving
picture weights each path by the bytes users really uploaded (ZIA Insights,
Shadow IT) and, without those numbers, starts still as an opt-in extra.

Three halves: the traffic shares (data_flow.traffic_shares / read_traffic /
attach_traffic and the route helper) in Python; the models
(FA.dataFlowTrafficModel, DataFlowSimple.stepsOf) under node; the page in a
real headless Chrome over CDP on the made-up sample tenant (skipped without
node or Chrome). No real tenant is contacted.
"""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess

import pytest

import data_flow as df
import flow_motion_fixtures as fx

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
NOW_MS = 1_793_404_800_000

APPS = [  # Shadow IT rows (made up): name, category, bytes up, bytes down
    {"application": "Box", "application_category": "File Share", "data_uploaded": 6_000, "data_downloaded": 1_000, "data_consumed": 7_000},
    {"application": "Gmail", "application_category": "Webmail", "data_uploaded": 3_000, "data_downloaded": 500, "data_consumed": 3_500},
    {"application": "Slack", "application_category": "Enterprise Collaboration", "data_uploaded": 1_000, "data_downloaded": 0, "data_consumed": 1_000},
    {"application": "Salesforce", "application_category": "Sales and Marketing", "data_uploaded": -5, "data_downloaded": "x", "data_consumed": None},
    {"application": "", "application_category": "File Share", "data_uploaded": 99_999},
    "not a row",
]


def _report_with_traffic(apps=APPS):
    rep = fx.dataflow_report()
    df.attach_traffic(rep, {"status": "ok", "apps": copy.deepcopy(apps), "window": {"key": "7d", "label": "Last 7 days"}})
    return rep


# ── Python: traffic shares ──────────────────────────────────────────────
def test_apps_go_to_their_traffic_class_once_and_bad_amounts_count_zero():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: each Shadow IT application lands in one traffic class (by category, else all other web traffic); bad rows and amounts count as nothing."""
    tr = _report_with_traffic()["traffic"]
    c = tr["classes"]
    assert tr["available"] is True and tr["unit"] == "bytes uploaded"
    assert c["file_share"]["upload"] == 6_000 and c["file_share"]["apps"] == ["Box"]
    assert c["webmail"]["upload"] == 3_000 and c["collab"]["upload"] == 1_000
    assert c["general"]["apps"] == ["Salesforce"] and c["general"]["upload"] == 0
    assert tr["total_upload"] == 10_000 == sum(x["upload"] for x in c.values())
    assert tr["apps_read"] == 5 and "network" in tr["basis"]


def test_a_catalogue_name_wins_over_the_category():
    """ASVS V5.1.3 · CWE-20: an application the tenant's catalogue puts in a class is counted there, whatever its Shadow IT category says."""
    traces = [{"destination": {"kind": "class", "class": "ai_ml", "label": "AI", "applications": [], "app_classes": ["AI_ML"]}},
              {"destination": {"kind": "class", "class": "general", "label": "Other", "applications": [], "app_classes": []}}]
    tr = df.traffic_shares(traces, [{"application": "Chat GPT", "application_category": "System and Development", "data_uploaded": 7}],
                           {"AI_ML": ["CHATGPT"]})
    assert tr["classes"]["ai_ml"]["upload"] == 7 and tr["classes"]["general"]["upload"] == 0


@pytest.mark.parametrize("read, word", [
    (None, "not in scope"),
    ({"status": "error", "apps": [], "error": "HTTP 403"}, "HTTP 403"),
    ({"status": "ok", "apps": [], "window": None}, "no cloud application traffic"),
])
def test_without_numbers_the_map_says_why_and_never_invents_bytes(read, word):
    """ASVS V7.4.1 · CWE-1287 · WSTG-INFO-05: no Insights numbers means no traffic shares, with the reason in words."""
    rep = fx.dataflow_report()
    tr = df.attach_traffic(rep, read)
    assert tr["available"] is False and word in tr["reason"] and "classes" not in tr


def test_read_traffic_asks_insights_once_over_the_sample_tenant():
    """ASVS V12.6.1 · CWE-918 · WSTG-INFO-08: one Shadow IT query on the offline sample tenant; a missing Insights client is an error, not a crash."""
    import offline_tenant as ot
    zins = ot.OfflineSdkClient(ot.sample_store(), {}).zins
    r = df.read_traffic(zins, now_ms=NOW_MS)
    assert r["status"] in ("ok", "partial") and len(r["apps"]) >= 5 and r["window"]["key"] == "7d"
    assert df.read_traffic(None, now_ms=NOW_MS)["status"] == "error"


class _Req:
    scopes: list = []


@pytest.fixture()
def route(monkeypatch):
    import dlp_api_server as srv
    calls = []
    monkeypatch.setattr(srv, "_tenant_creds", lambda req: {"client_secret": "s3cr3t-value", "auth_method": "oneapi"})
    monkeypatch.setattr(srv, "_offline_client", lambda creds, kind: None)
    monkeypatch.setattr(srv.tenant_auth, "normalize", lambda c: {"auth_method": "oneapi"})
    return srv, calls


def test_the_route_reads_no_traffic_unless_insights_is_ticked(route, monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: with ZIA Insights not ticked on the Scope page no Insights client is built and the map says so."""
    srv, calls = route
    monkeypatch.setattr(srv, "_scope_selection", lambda req: (["dlp", "zcc"], {}, "page"))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: calls.append(1))
    rep = fx.dataflow_report()
    srv._dataflow_traffic(_Req(), rep)
    assert calls == [] and rep["traffic"] == {"available": False, "reason": df.TRAFFIC_NOT_IN_SCOPE}


def test_the_route_weights_paths_when_insights_answers(route, monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: with ZIA Insights ticked the route asks Shadow IT once and stores the shares."""
    srv, _ = route
    monkeypatch.setattr(srv, "_scope_selection", lambda req: (["dlp", "zcc", "insights"], {}, "page"))

    class Shadow:
        def __init__(self):
            self.n = 0

        def get_apps(self, **kw):
            self.n += 1
            return (copy.deepcopy(APPS[:3]), None, None)   # the SDK's (entries, response, error)

    class Sdk:
        zins = type("Z", (), {})()
    Sdk.zins.shadow_it = Shadow()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: Sdk)
    rep = fx.dataflow_report()
    srv._dataflow_traffic(_Req(), rep)
    assert Sdk.zins.shadow_it.n == 1
    assert rep["traffic"]["available"] is True and rep["traffic"]["total_upload"] == 10_000, rep["traffic"]


def test_a_failed_insights_sign_in_never_shows_the_secret(route, monkeypatch):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: an Insights sign-in error keeps the map and masks every secret in the reason."""
    srv, _ = route
    from fastapi import HTTPException
    monkeypatch.setattr(srv, "_scope_selection", lambda req: (["dlp", "insights"], {}, "page"))

    def boom(creds):
        raise HTTPException(status_code=401, detail="bad secret s3cr3t-value")
    monkeypatch.setattr(srv, "_build_sdk_client", boom)
    rep = fx.dataflow_report()
    srv._dataflow_traffic(_Req(), rep)
    assert rep["traffic"]["available"] is False and "s3cr3t-value" not in json.dumps(rep["traffic"]) and "not read" in rep["traffic"]["reason"]


# ── node: the models ────────────────────────────────────────────────────
def _node(expr, **data):
    script = ("global.window = globalThis; const FA = require(%s); require(%s); const S = globalThis.DataFlowSimple;\n"
              "const D = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
              "const out = (function () { %s })();\nprocess.stdout.write(JSON.stringify(out));\n"
              ) % (json.dumps(os.path.join(ROOT, "static", "flow_anim.js")), json.dumps(os.path.join(ROOT, "static", "data_flow_simple.js")), expr)
    r = subprocess.run([NODE, "-e", script], input=json.dumps(data, default=str), capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


@needs_node
def test_the_traffic_model_weights_each_path_by_its_uploads_on_one_network():
    """WCAG 2.2 SC 1.1.1 · CWE-1287: streams are as wide as the bytes uploaded on the chosen network; the shares add up to 100% and the words name the network caveat."""
    rep = _report_with_traffic()
    m = _node("const m = FA.dataFlowTrafficModel(D.rep, 'off'); return { total: m.total, network: m.network, ends: m.ends, alt: m.alt,"
              " routeSum: m.routes.reduce((a, r) => a + r.weight, 0), src: m.nodes.filter(n => n.key === 'src')[0].value };", rep=rep)
    assert m["total"] == 10_000 == m["routeSum"] == m["src"] and m["network"] == "off"
    assert abs(sum(e["share"] for e in m["ends"]) - 1) < 1e-9
    vis = {t["destination"]["class"]: df.visibility(t) for t in rep["traces"] if t["network"] == "off"}
    blind = [e for e in m["ends"] if e["key"] == "enc"]
    assert vis["webmail"] == "blind" and blind and blind[0]["bytes"] == 3_000
    assert any("cannot say which network" in a for a in m["alt"]) and any("30%" in a for a in m["alt"])


@needs_node
def test_without_traffic_numbers_there_is_no_traffic_model():
    """CWE-1287: a report without Insights numbers gives no weighted picture (the page keeps the still view)."""
    rep = fx.dataflow_report()
    df.attach_traffic(rep, None)
    assert _node("return FA.dataFlowTrafficModel(D.rep, 'off');", rep=rep) is None


@needs_node
def test_the_steps_read_from_the_device_to_the_destination_in_order():
    """WCAG 2.2 SC 1.3.2 (Meaningful Sequence): the simple view's steps run device → Client Connector → forwarding → … → Web DLP → destination, each with a decision and a sentence."""
    rep = fx.dataflow_report()
    out = _node("return D.rep.traces.map(t => S.stepsOf(t, D.rep).map(s => [s.key, s.dec, s.cap]));", rep=rep)
    order = ["device", "zcc", "forwarding", "pac", "policy", "ssl", "ftc", "dlp", "dest"]
    for steps in out:
        keys = [s[0] for s in steps]
        assert keys[0] == "device" and keys[-1] == "dest" and keys == sorted(keys, key=order.index)
        assert all(s[1] in ("start", "allowed", "inspected", "notinspected", "blocked", "bypassed", "unsure", "skipped") and s[2].endswith(".") for s in steps)
    blind = [steps for t, steps in zip(rep["traces"], out) if df.visibility(t) == "blind"][0]
    assert ("ssl", "notinspected") in [(s[0], s[1]) for s in blind] and blind[-1][1] == "notinspected"
    bypassed = [steps for t, steps in zip(rep["traces"], out) if df.visibility(t) == "bypassed"][0]
    assert "bypassed" in [s[1] for s in bypassed] and bypassed[-1][1] == "bypassed"


# ── Browser: the page ───────────────────────────────────────────────────
from test_findings_reflow import CDP_PRELUDE, run_in_browser  # noqa: E402

DRIVER = CDP_PRELUDE + r"""
const [ids] = args;
const { sample, plain } = JSON.parse(ids);
const out = {};
const errors = [];
ws.addEventListener('message', e => { const m = JSON.parse(e.data); if (m.method === 'Runtime.exceptionThrown') errors.push(m.params.exceptionDetails.text + ' ' + ((m.params.exceptionDetails.exception || {}).description || '').slice(0, 200)); });
const frames = n => ev(`new Promise(r => { let k = ${n}; const f = () => (--k <= 0 ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
const key = async (k, code, vk, mods) => { await send('Input.dispatchKeyEvent', Object.assign({ type: 'keyDown', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods || 0 }, k === 'Enter' ? { text: '\r' } : {})); await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code, windowsVirtualKeyCode: vk, modifiers: mods || 0 }); };
async function open(id, width, opts) {
  const o = opts || {};
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: o.reduce ? 'reduce' : 'no-preference' }] });
  await send('Page.navigate', { url: base + '/report/dataflow?id=' + encodeURIComponent(id) });
  await until(() => ev(`document.readyState === 'complete' && document.querySelectorAll('#dfsSteps .dfs-btn').length > 0 && !!window.HoverHelp`), 'simple view');
  await frames(3);
}
const CONTRAST = `(sel) => {
  const rgba = s => { const m = String(s).match(/rgba?\\(([^)]+)\\)/); if (!m) return null; const v = m[1].split(/[ ,\\/]+/).filter(Boolean).map(Number); return { r: v[0], g: v[1], b: v[2], a: v.length > 3 ? v[3] : 1 }; };
  const over = (f, b) => ({ r: f.r * f.a + b.r * (1 - f.a), g: f.g * f.a + b.g * (1 - f.a), b: f.b * f.a + b.b * (1 - f.a), a: 1 });
  const lum = c => { const f = x => { x /= 255; return x <= 0.03928 ? x / 12.92 : ((x + 0.055) / 1.055) ** 2.4; }; return 0.2126 * f(c.r) + 0.7152 * f(c.g) + 0.0722 * f(c.b); };
  const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
  const behind = e => { const chain = []; for (let n = e; n; n = n.parentElement) chain.push(n); let c = { r: 255, g: 255, b: 255, a: 1 }; const root = rgba(getComputedStyle(document.documentElement).backgroundColor); if (root && root.a > 0) c = over(root, c); for (const n of chain.reverse()) { const b = rgba(getComputedStyle(n).backgroundColor); if (b && b.a > 0) c = over(b, c); } return c; };
  return [...document.querySelectorAll(sel)].filter(e => e.getClientRects().length).map(e => { const bg = behind(e); return { r: Math.round(ratio(over(rgba(getComputedStyle(e).color), bg), bg) * 100) / 100, what: e.className.baseVal != null ? 'svg.' + e.className.baseVal : e.tagName + '.' + e.className }; });
}`;
// 1. The simple view on the sample tenant, desktop.
await open(sample, 1280);
out.view = await ev(`({ simpleShown: !document.getElementById('dfSimpleWrap').hidden, allHidden: document.getElementById('dfAll').hidden,
  pressed: [document.getElementById('dfViewSimple').getAttribute('aria-pressed'), document.getElementById('dfViewAll').getAttribute('aria-pressed')],
  steps: [...document.querySelectorAll('#dfsSteps > li')].map(li => ({ key: li.dataset.step, num: li.querySelector('.dfs-num').textContent, word: li.querySelector('.dfs-dec').textContent,
    shape: !!li.querySelector('svg.dfs-shape path, svg.dfs-shape circle'), cap: li.querySelector('.dfs-cap').textContent })),
  legend: [...document.querySelectorAll('#dfsLegend li')].map(li => ({ dec: li.dataset.dec, word: li.querySelector('strong').textContent, shape: !!li.querySelector('svg.dfs-shape') })),
  beside: (() => { const l = document.getElementById('dfsLegend').getBoundingClientRect(), s = document.getElementById('dfsSteps').getBoundingClientRect(); return l.left >= s.right && l.top < s.bottom; })(),
  detailShown: document.getElementById('dfsDetail').textContent.length > 20, howTo: document.querySelector('.dfs-howto p').textContent,
  scrollY: window.scrollY })`);
// The uploads picture moves (real numbers), with Pause.
await until(() => ev(`[...document.querySelectorAll('#dfsFlowStage .fa-dot.pk')].some(d => d.hasAttribute('cx'))`), 'packets', 5000).catch(() => null);
const pk = () => ev(`[...document.querySelectorAll('#dfsFlowStage .fa-dot.pk')].map(d => d.getAttribute('cx')).join(',')`);
const a0 = await pk();
out.flow = { moves: !!(await until(async () => (await pk()) !== a0, 'moving', 5000).catch(() => false)),
  button: await ev(`document.getElementById('dfsFlowPlay').textContent`), alt: await ev(`document.getElementById('dfsFlowAlt').textContent`),
  described: await ev(`document.querySelector('#dfsFlowStage svg').getAttribute('aria-describedby')`) };
// Keyboard: Tab from the path picker reaches every step, and focus shows that step's details.
await ev(`(document.getElementById('dfsPath').focus(), 1)`);
const reached = new Set(); const shown = [];
for (let k = 0; k < 80 && reached.size < out.view.steps.length; k++) {
  await key('Tab', 'Tab', 9);
  const f = await ev(`(() => { const a = document.activeElement; return a && a.classList.contains('dfs-btn') ? { i: a.dataset.i, title: a.querySelector('.dfs-title').textContent, head: document.getElementById('dfsDetailH').textContent, ring: getComputedStyle(a).outlineStyle } : null; })()`);
  if (f) { reached.add(f.i); shown.push(f); }
}
out.keyboard = { reached: reached.size, shown };
// Walk-through: Next and Back move one step; Esc ends it and gives focus back.
await ev(`(document.getElementById('dfsWalk').click(), 1)`); await frames(2);
out.walk = { open: await ev(`!document.getElementById('dfsWalkBar').hidden && getComputedStyle(document.getElementById('dfsWalkBar')).display !== 'none'`),
  pos0: await ev(`document.getElementById('dfsWalkPos').textContent`), focusNext: await ev(`document.activeElement.id`) };
await key('Enter', 'Enter', 13); await frames(2);
out.walk.pos1 = await ev(`document.getElementById('dfsWalkPos').textContent`);
out.walk.head1 = await ev(`document.getElementById('dfsDetailH').textContent`);
await ev(`(document.getElementById('dfsBack').click(), 1)`); await frames(2);
out.walk.pos2 = await ev(`document.getElementById('dfsWalkPos').textContent`);
out.walk.backDisabled = await ev(`document.getElementById('dfsBack').disabled`);
await ev(`(document.getElementById('dfsNext').focus(), 1)`);
await key('Escape', 'Escape', 27); await frames(2);
out.walk.closed = await ev(`document.getElementById('dfsWalkBar').hidden`);
out.walk.focusBack = await ev(`document.activeElement.id`);
// Help marks on the new controls.
out.help = await ev(`HoverHelp.audit().filter(r => /dfs|dfView|df-about/.test(r.control + ' ' + (r.key || ''))).map(r => ({ control: r.control, key: r.key, mark: r.mark, skip: r.skip }))`);
// AA contrast of the new words and 3:1 of the shapes, both themes, glass on and off.
out.contrast = {};
for (const theme of ['dark', 'light']) for (const glass of ['on', 'off']) {
  await ev(`(localStorage.setItem('zassess_theme', '${theme}'), localStorage.setItem('zassess_glass', '${glass}'), 1)`);
  await open(sample, 1280);
  out.contrast[theme + '-' + glass] = { text: await ev(`(${CONTRAST})('#dfSimple .dfs-lead, #dfSimple .dfs-title, #dfSimple .dfs-btn .dfs-cap, #dfSimple .dfs-dec, #dfSimple .dfs-leg-t, #dfSimple .dfs-note, #dfsDetail p, #dfsDetail dd, #dfsDetail dt, .dfs-result, .dfs-views .rp-btn, #dfsWalk')`),
    shapes: await ev(`(${CONTRAST})('#dfSimple svg.dfs-shape')`), glassOff: await ev(`document.documentElement.classList.contains('glass-off')`) };
}
// Show all details: today's full map, every path in the table, its motion opt-in.
await ev(`(document.getElementById('dfViewAll').click(), 1)`); await frames(3);
out.all = await ev(`({ shown: !document.getElementById('dfAll').hidden, simpleHidden: document.getElementById('dfSimpleWrap').hidden,
  rows: document.querySelectorAll('#dfOverview .df-row').length, ref: document.querySelectorAll('#dfEnforcement .df-step').length,
  hops: document.querySelectorAll('#dfTraceBody .df-hop').length, play: document.getElementById('dfMotionPlay').textContent,
  still: [...document.querySelectorAll('#dfMotionStage .fa-dot.pk')].every(d => !d.hasAttribute('cx')), hash: location.hash })`);
await ev(`(document.getElementById('dfMotionPlay').click(), 1)`);
out.all.playStarts = !!(await until(() => ev(`[...document.querySelectorAll('#dfMotionStage .fa-dot.pk')].some(d => d.hasAttribute('cx'))`), 'played', 5000).catch(() => false));
// A step's "Show this step in all details" opens the full map at it.
await ev(`(document.getElementById('dfViewSimple').click(), 1)`); await frames(2);
out.all.backToSimple = await ev(`!document.getElementById('dfSimpleWrap').hidden && document.getElementById('dfMotionPlay').textContent === 'Play motion'`);
await ev(`(document.querySelector('#dfsSteps li[data-step="ssl"] .dfs-btn').click(), document.getElementById('dfsMore').click(), 1)`); await frames(2);
out.all.more = await ev(`({ shown: !document.getElementById('dfAll').hidden, focus: document.activeElement.dataset.hop || document.activeElement.id })`);
// Reduced motion: the uploads picture starts still with Play.
await open(sample, 1280, { reduce: true }); await frames(4);
out.reduced = { still: await ev(`[...document.querySelectorAll('#dfsFlowStage .fa-dot.pk')].every(d => !d.hasAttribute('cx'))`), button: await ev(`document.getElementById('dfsFlowPlay').textContent`) };
// No traffic numbers: no moving picture, the reason in words.
await open(plain, 1280);
out.plain = await ev(`({ note: (document.getElementById('dfsNoTraffic') || {}).textContent || '', stage: !!document.getElementById('dfsFlowStage') })`);
// Reflow: no sideways scroll at 320 and 390 px, in both views.
out.overflow = {};
for (const w of [320, 390]) {
  await open(sample, w);
  out.overflow[w + '-simple'] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  out.overflow[w + '-legendFirst'] = await ev(`document.getElementById('dfsLegend').getBoundingClientRect().top < document.getElementById('dfsSteps').getBoundingClientRect().top`);
  await ev(`(document.getElementById('dfViewAll').click(), 1)`); await frames(3);
  out.overflow[w + '-all'] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
}
out.errors = errors;
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def page(tmp_path_factory):
    import dlp_api_server as srv
    import offline_tenant as ot
    st = ot.sample_store()
    rep = df.generate_data_flow_report(ot.OfflineRawClient(st, {}), platform="windows", scope=df.full_path_scope())
    df.attach_traffic(rep, df.read_traffic(ot.OfflineSdkClient(st, {}).zins, now_ms=NOW_MS))
    plain = fx.dataflow_report()
    df.attach_traffic(plain, None)
    ids = {"sample": srv._remember_report("dataflow", rep, "Larkspur Freight (sample)"), "plain": srv._remember_report("dataflow", plain, "Fixture")}
    try:
        out = run_in_browser(tmp_path_factory.mktemp("df-clarity"), DRIVER, json.dumps(ids), timeout=300)
    finally:
        for rid in ids.values():
            srv._REPORTS.pop(rid, None)
    out["_report"] = rep
    return out


def test_the_simple_view_is_the_default_and_shows_the_numbered_path(page):
    """WCAG 2.2 SC 1.3.2 (Meaningful Sequence) · SC 3.3.5 (Help): the page opens on the numbered steps, device first and destination last, each with a plain sentence."""
    v = page["view"]
    assert v["simpleShown"] and v["allHidden"] and v["pressed"] == ["true", "false"]
    steps = v["steps"]
    assert [s["num"] for s in steps] == [str(i + 1) for i in range(len(steps))] and len(steps) >= 6
    assert steps[0]["key"] == "device" and steps[-1]["key"] == "dest"
    assert all(s["cap"].endswith(".") and len(s["cap"].split()) <= 16 for s in steps)
    assert v["detailShown"] and v["howTo"].count(".") == 3 and v["scrollY"] == 0


def test_every_decision_has_a_word_and_a_shape_and_the_legend_sits_beside_it(page):
    """WCAG 2.2 SC 1.4.1 (Use of Color): each step and legend entry carries a shape and a word, never colour alone; the legend is beside the steps."""
    v = page["view"]
    assert all(s["shape"] and s["word"] for s in v["steps"])
    assert [x["dec"] for x in v["legend"]] == ["start", "allowed", "inspected", "notinspected", "blocked", "bypassed", "unsure", "skipped"]
    assert all(x["shape"] and x["word"] for x in v["legend"])
    assert {s["word"] for s in v["steps"]} <= {x["word"] for x in v["legend"]}
    assert v["beside"] is True


def test_the_keyboard_reaches_every_step_and_focus_shows_its_details(page):
    """WCAG 2.2 SC 2.1.1 (Keyboard) · SC 2.4.7 (Focus Visible) · SC 1.4.13: Tab reaches every step; focusing one shows its details, with a visible focus ring."""
    k = page["keyboard"]
    assert k["reached"] == len(page["view"]["steps"]), k
    assert all(f["head"].endswith(f["title"]) and f["ring"] != "none" for f in k["shown"]), k["shown"]


def test_the_walk_through_moves_with_next_and_back_and_esc_ends_it(page):
    """WCAG 2.2 SC 2.1.1 · SC 2.4.3 (Focus Order): the walk-through starts at step 1, Next and Back move one step, Esc ends it and returns focus."""
    w, n = page["walk"], len(page["view"]["steps"])
    assert w["open"] and w["pos0"] == f"Step 1 of {n}" and w["focusNext"] == "dfsNext"
    assert w["pos1"] == f"Step 2 of {n}" and w["head1"].startswith("Step 2:")
    assert w["pos2"] == f"Step 1 of {n}" and w["backDisabled"] is True
    assert w["closed"] is True and w["focusBack"] == "dfsWalk"


def test_the_uploads_picture_moves_only_with_real_numbers(page):
    """WCAG 2.2 SC 2.2.2 · SC 1.1.1: with Insights numbers the uploads picture moves, has Pause and a text alternative; without them nothing moves and the page says why."""
    f = page["flow"]
    assert f["moves"] and f["button"] == "Pause motion" and f["described"] == "dfsFlowAlt" and "%" in f["alt"]
    assert page["reduced"] == {"still": True, "button": "Play motion"}
    assert page["plain"]["stage"] is False and "not read" in page["plain"]["note"]


def test_show_all_details_keeps_every_fact_and_its_motion_is_opt_in(page):
    """WCAG 2.2 SC 2.2.2 · SC 2.3.3: Show all details has every traced path, the reference order and the hops; its path-count picture starts still and plays on request."""
    a, rep = page["all"], page["_report"]
    assert a["shown"] and a["simpleHidden"] and a["rows"] == len(rep["traces"]) and a["ref"] >= 15 and a["hops"] >= 5
    assert a["play"] == "Play motion" and a["still"] and a["playStarts"] and a["hash"] == "#details"
    assert a["backToSimple"] and a["more"]["shown"] and a["more"]["focus"] == "ssl"


def test_help_marks_on_the_new_controls(page):
    """WCAG 2.2 SC 3.3.5 (Help): every new control has a help entry and a "?" mark, or a recorded reason it needs none."""
    rows = page["help"]
    assert rows and all(r["key"] for r in rows), [r for r in rows if not r["key"]]
    assert all(r["mark"] or r["skip"] for r in rows), [r for r in rows if not (r["mark"] or r["skip"])]
    keys = {r["key"] for r in rows if r["mark"]}
    assert {"#dfViewSimple", "#dfViewAll", "#dfsPath", "#dfsWalk", "#dfsDetail a.dfs-term"} <= keys, keys


@pytest.mark.parametrize("combo", ["dark-on", "dark-off", "light-on", "light-off"])
def test_aa_contrast_in_both_themes_with_glass_on_and_off(page, combo):
    """WCAG 2.2 SC 1.4.3 (Contrast) · SC 1.4.11 (Non-text Contrast): the new words reach 4.5:1 and the shapes 3:1, in both themes, with Liquid Glass on and off."""
    c = page["contrast"][combo]
    assert c["glassOff"] is combo.endswith("off")
    low = [x for x in c["text"] if x["r"] < 4.5]
    assert c["text"] and not low, low
    lows = [x for x in c["shapes"] if x["r"] < 3]
    assert c["shapes"] and not lows, lows


@pytest.mark.parametrize("width", ["320", "390"])
def test_no_sideways_scroll_on_a_phone(page, width):
    """WCAG 2.2 SC 1.4.10 (Reflow): neither view scrolls sideways at 320 or 390 px, and the legend comes before the steps there."""
    o = page["overflow"]
    assert o[f"{width}-simple"] == 0 and o[f"{width}-all"] == 0 and o[f"{width}-legendFirst"] is True, o


def test_no_script_errors(page):
    """CWE-755: the simple view, the walk-through, both views and both pictures run without a script error."""
    assert page["errors"] == [], page["errors"]
