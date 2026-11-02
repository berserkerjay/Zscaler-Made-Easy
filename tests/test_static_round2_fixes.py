"""Round-2 fixes in the browser code (SEC2-3, FE2-3..FE2-8).

- The guide's connection record never keeps the classic API's admin login
  (user rule 3): its "same tenant" key is a one-way hash, its fallback name
  is "classic API (<cloud>)", and an old record holding the login is dropped.
- The sidebar's tenant line follows the chosen sign-in: a classic-API
  sign-in never shows the vanity domain left in the hidden OneAPI field.
- The Terraform hand-off allows gap mode for a complete classic sign-in.
- Best practices opened in its own tab stops its 30 s re-fetch when the tab closes.
- FP/TP detection ratio with the pop-up blocked reads nothing and says so.
- /report/deploy-flow follows the light theme.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGIN = "jane.admin@acme-corp.com"
needs_node = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _fn(src, start, end):
    i = src.index(start)
    return src[i:src.index(end, i)]


def _node(tmp_path, script, name="h.js"):
    f = tmp_path / name
    f.write_text(script, encoding="utf-8")
    out = subprocess.run(["node", str(f)], capture_output=True, text=True, encoding="utf-8")
    assert out.returncode == 0, out.stderr
    return json.loads(out.stdout)


# --- SEC2-3 / FE2-4: the guide's connection record ------------------------------------

GUIDE_HARNESS = r"""
const vm = require('vm');
const VALUES = __VALUES__;
const RESPONSES = __RESPONSES__;
const STORED = __STORED__;
const store = Object.assign({}, STORED);
const els = {};
const el = id => (id in VALUES) ? (els[id] || (els[id] = {id, value: VALUES[id]})) : null;
const announced = [], dialogs = [];
let n = 0;
const ctx = {
  document: {getElementById: el, querySelector: () => null, querySelectorAll: () => [], body: {appendChild(){}}, addEventListener(){}},
  localStorage: {getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); }, removeItem: k => { delete store[k]; }},
  announce: m => announced.push(m),
  currentAuthMethod: () => VALUES.authMethod,
  migrateCredBody: () => ({auth_method: VALUES.authMethod, cloud: VALUES.cloud, vanity_domain: VALUES.authMethod === 'legacy' ? '' : VALUES.vd,
                           client_id: '', client_secret: '', username: VALUES.authMethod === 'legacy' ? VALUES.zuser : '',
                           password: 'pw', api_key: 'key', customer_id: '', profile_id: ''}),
  fetch: async () => { const r = RESPONSES[n++]; return {ok: r.status < 300, status: r.status, json: async () => r.body}; },
  console, setTimeout, clearTimeout, setInterval, clearInterval, JSON, Math, Date, String, Object, Array,
};
ctx.window = ctx; ctx.window.addEventListener = () => {};
ctx.window.dlpDialog = {notice: d => dialogs.push(d)};
vm.createContext(ctx);
vm.runInContext(__CODE__, ctx);
vm.runInContext('_gdRender = function () {};', ctx);
(async () => {
  const steps = [];
  vm.runInContext('_gdLoad()', ctx);
  steps.push({loaded: vm.runInContext('GD.conn', ctx), store: Object.assign({}, store)});
  for (let i = 0; i < RESPONSES.length; i++) {
    await vm.runInContext('_gdTest()', ctx);
    steps.push({conn: vm.runInContext('GD.conn', ctx), store: Object.assign({}, store),
                html: vm.runInContext('_gdConnHtml()', ctx), ident: vm.runInContext('_gdIdent()', ctx)});
  }
  process.stdout.write(JSON.stringify({steps, announced, dialogs}));
})();
"""


def _guide(tmp_path, values, responses, stored=None):
    script = (GUIDE_HARNESS.replace("__VALUES__", json.dumps(values))
              .replace("__RESPONSES__", json.dumps(responses))
              .replace("__STORED__", json.dumps(stored or {}))
              .replace("__CODE__", json.dumps(_read("static/guide.js"))))
    return _node(tmp_path, script, "guide.js")


@needs_node
def test_a_classic_sign_in_never_keeps_or_shows_the_admin_login(tmp_path):
    values = {"authMethod": "legacy", "zuser": LOGIN, "cloud": "zscalertwo", "vd": "old-tenant.zscalertwo.net"}
    out = _guide(tmp_path, values, [
        {"status": 429, "body": {"detail": "Rate limit exceeded. Slow down."}},      # the app's own rate limiter
        {"status": 200, "body": {"tenant_label": "classic API (zscalertwo)", "problems": []}},
    ])
    everything = json.dumps(out)
    assert LOGIN not in everything and "old-tenant" not in everything, everything
    fail, ok = out["steps"][1], out["steps"][2]
    assert out["dialogs"][0]["title"] == "Could not connect to classic API (zscalertwo)"
    assert LOGIN not in fail["store"]["zassess_guide_conn"] and LOGIN not in ok["store"]["zassess_guide_conn"]
    # "Same tenant" still matches the form, so step 1 and the status do not go blank.
    assert ok["conn"]["ok"] and ok["conn"]["vd"] == ok["ident"] and ok["html"], ok
    assert "classic API (zscalertwo)" in ok["html"]


@needs_node
def test_another_classic_login_is_not_the_same_tenant(tmp_path):
    out = _guide(tmp_path, {"authMethod": "legacy", "zuser": "a@acme.com", "cloud": "zscalertwo", "vd": ""},
                 [{"status": 200, "body": {"tenant_label": "classic API (zscalertwo)"}}])
    key = out["steps"][1]["conn"]["vd"]
    out2 = _guide(tmp_path, {"authMethod": "legacy", "zuser": "b@acme.com", "cloud": "zscalertwo", "vd": ""},
                  [], stored={"zassess_guide_conn": out["steps"][1]["store"]["zassess_guide_conn"]})
    assert out2["steps"][0]["loaded"]["vd"] == key   # a v2 record is kept across restarts
    assert key.startswith("classic:") and "@" not in key


@needs_node
def test_an_old_record_holding_the_login_is_dropped_on_load(tmp_path):
    old = json.dumps({"ok": True, "vd": LOGIN, "label": "ZIA zscalerthree (classic API)"})
    out = _guide(tmp_path, {"authMethod": "legacy", "zuser": LOGIN, "cloud": "zscalerthree", "vd": ""},
                 [], stored={"zassess_guide_conn": old, "zassess_guide_mode": "guided"})
    assert out["steps"][0]["loaded"] is None
    assert "zassess_guide_conn" not in out["steps"][0]["store"]


@needs_node
def test_a_oneapi_failure_still_names_the_vanity_domain(tmp_path):
    out = _guide(tmp_path, {"authMethod": "oneapi", "zuser": "", "cloud": "zscalertwo", "vd": "acme.zscalertwo.net"},
                 [{"status": 422, "body": {"detail": [{"msg": "bad"}]}}])
    assert out["dialogs"][0]["title"] == "Could not connect to acme.zscalertwo.net"
    assert out["steps"][1]["conn"]["vd"] == "acme.zscalertwo.net"


# --- FE2-5: the sidebar's tenant line, and its signed-in check ------------------------

def _dashboard(tmp_path, values, conn=None):
    js = _read("static/dashboard.js")
    # refreshCurrent writes through the file's own change-only helper.
    code = (_fn(js, "  const setText = ", "  const setHtml = ")
            + _fn(js, "  function signedIn()", "  function note(")
            + _fn(js, "  function refreshCurrent()", "  refreshCurrent(); setInterval"))
    guide = _read("static/guide.js")
    gcode = _fn(guide, "function _gdHash(", "function _gdAuthStatus(") + "const _gdVal = id => ((document.getElementById(id) || {}).value || '').trim();"
    script = r"""
const vm = require('vm');
const VALUES = __VALUES__;
const els = {};
const el = id => els[id] || (els[id] = {id, value: VALUES[id] || '', textContent: '', title: '', attrs: {}, setAttribute(k, v){ this.attrs[k] = String(v); }, getAttribute(k){ return k in this.attrs ? this.attrs[k] : null; }});
const ctx = {document: {getElementById: el}, currentAuthMethod: () => VALUES.authMethod, renderLastRunOrEmpty(){}, console};
ctx.window = ctx; ctx.GD = {profile: '', conn: __CONN__};
vm.createContext(ctx);
vm.runInContext(__G__ + 'const $ = id => document.getElementById(id);' + __CODE__ + ';this.__r = refreshCurrent; this.__s = signedIn; this.__ident = _gdIdent;', ctx);
ctx.__r();
process.stdout.write(JSON.stringify({tenant: el('dbCurTenant').textContent, signedIn: ctx.__s(), ident: ctx.__ident()}));
""".replace("__VALUES__", json.dumps(values)).replace("__CONN__", json.dumps(conn)).replace(
        "__G__", json.dumps(gcode)).replace("__CODE__", json.dumps(code))
    return _node(tmp_path, script, "dash.js")


@needs_node
def test_the_sidebar_never_shows_a_stale_vanity_domain_for_a_classic_sign_in(tmp_path):
    out = _dashboard(tmp_path, {"authMethod": "legacy", "vd": "old-tenant.zscalertwo.net", "cloud": "zscalerthree", "zuser": LOGIN})
    assert out["tenant"] == "classic API · zscalerthree"
    assert "old-tenant" not in json.dumps(out) and LOGIN not in json.dumps(out)
    out = _dashboard(tmp_path, {"authMethod": "oneapi", "vd": "acme.zscalertwo.net", "cloud": "zscalertwo"})
    assert out["tenant"] == "acme.zscalertwo.net · zscalertwo"


@needs_node
def test_the_sidebar_signed_in_check_uses_the_guides_key(tmp_path):
    values = {"authMethod": "legacy", "cloud": "zscalerthree", "zuser": LOGIN}
    key = _dashboard(tmp_path, values)["ident"]
    assert _dashboard(tmp_path, values, {"ok": True, "vd": key})["signedIn"] is True
    assert _dashboard(tmp_path, values, {"ok": True, "vd": "classic:other"})["signedIn"] is False


# --- FE2-3: Terraform gap mode for a classic sign-in ---------------------------------

def _can_gap(tmp_path, creds, profile=False):
    code = _fn(_read("static/deploy_studio.js"), "function _tfCanGap()", "// Static unless the operator picks gap")
    script = r"""
const vm = require('vm');
const ctx = {_dzCreds: () => (__CREDS__), GD: {profile: __PROF__ ? 'p1' : '', profileHasSecret: __PROF__}, String};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(__CODE__ + ';this.__f = _tfCanGap;', ctx);
process.stdout.write(JSON.stringify(ctx.__f()));
""".replace("__CREDS__", json.dumps(creds)).replace("__PROF__", json.dumps(profile)).replace("__CODE__", json.dumps(code))
    return _node(tmp_path, script, "tf.js")


@needs_node
def test_gap_mode_is_offered_for_a_complete_classic_sign_in(tmp_path):
    legacy = {"auth_method": "legacy", "cloud": "zscalertwo", "vanity_domain": "", "client_id": "", "client_secret": "",
              "username": LOGIN, "password": "pw", "api_key": "abcdefghijkl"}
    assert _can_gap(tmp_path, legacy) is True
    assert _can_gap(tmp_path, dict(legacy, password="", api_key="")) is False
    assert _can_gap(tmp_path, dict(legacy, password="", api_key=""), profile=True) is True
    assert _can_gap(tmp_path, dict(legacy, username="")) is False
    oneapi = {"auth_method": "oneapi", "vanity_domain": "acme", "client_id": "cid", "client_secret": "sec", "username": ""}
    assert _can_gap(tmp_path, oneapi) is True
    assert _can_gap(tmp_path, dict(oneapi, client_secret="")) is False
    assert _can_gap(tmp_path, dict(oneapi, client_secret=""), profile=True) is True


# --- FE2-6: Best practices in its own tab stops its re-fetch ---------------------------

def _tool_tab(tmp_path, ready):
    script = r"""
const vm = require('vm');
const live = new Set();
const si = (f, ms) => { const h = setInterval(f, ms); live.add(h); return h; };
const ci = h => { if (h) { live.delete(h); clearInterval(h); } };
const panel = {innerHTML: '', querySelectorAll: () => []};
const modal = {style: {}, firstElementChild: panel};
const win = {closed: false, close() { this.closed = true; }};
if (__READY__) {
  win.__ttApply = () => {};
  win.document = {title: '', getElementById: id => ({rpBody: {}, rpTitle: {innerHTML: ''}})[id] || null, querySelector: () => null,
                  body: {classList: {toggle(){}}}};
}
const ctx = {
  document: {getElementById: id => id === 'bestPracticesModal' ? modal : null, querySelector: () => null,
             body: {style: {}, classList: {contains: () => false}}},
  getComputedStyle: () => ({display: 'block'}), MutationObserver: class { observe(){} disconnect(){} },
  setInterval: si, clearInterval: ci, setTimeout, clearTimeout, console, encodeURIComponent,
};
ctx.window = ctx; ctx.window.open = () => win;
vm.createContext(ctx);
vm.runInContext(`let _bestPracticesPoll = null;
async function openBestPracticesModal() { modal.style.display = 'block';
  if (_bestPracticesPoll) clearInterval(_bestPracticesPoll);
  _bestPracticesPoll = setInterval(() => {}, 30000); }`, Object.assign(ctx, {modal}));
vm.runInContext(__CODE__, ctx);
(async () => {
  await vm.runInContext("openToolTab('bestpractices')", ctx);
  const before = vm.runInContext('_bestPracticesPoll', ctx) !== null;
  await new Promise(r => setTimeout(r, 400));   // the tab has loaded (or not)
  win.closed = true;                              // the operator closes it
  await new Promise(r => setTimeout(r, 1600));
  const after = vm.runInContext('_bestPracticesPoll', ctx);
  const n = live.size;
  for (const h of live) clearInterval(h);
  process.stdout.write(JSON.stringify({before, after, live: n}));
})();
""".replace("__READY__", json.dumps(ready)).replace("__CODE__", json.dumps(_read("static/tool_tabs.js")))
    return _node(tmp_path, script, "tt.js")


@needs_node
@pytest.mark.parametrize("ready", [True, False])
def test_closing_the_best_practices_tab_stops_its_poll(tmp_path, ready):
    out = _tool_tab(tmp_path, ready)
    assert out["before"] is True
    assert out["after"] is None and out["live"] == 0, out


# --- FE2-7: FP/TP detection ratio with the pop-up blocked -----------------------------

@needs_node
@pytest.mark.parametrize("creds_ok", [True, False])
def test_detection_health_reads_nothing_when_the_tab_is_blocked(tmp_path, creds_ok):
    html = _read("static/index.html")
    code = _fn(html, "async function openDetectionHealthTab()", "function openReferenceTab(")
    script = r"""
const vm = require('vm');
const sent = [], alerts = [];
const ctx = {
  open: () => null, alert: m => alerts.push(m),
  migrateValidateCreds: () => (__OK__ ? {auth_method: 'oneapi'} : null), scopePageSelection: () => ({}),
  fetch: async (u) => { sent.push(u); return {ok: true, json: async () => ({report_id: 'r1'})}; },
  console, encodeURIComponent, JSON,
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(__CODE__ + ';this.__f = openDetectionHealthTab;', ctx);
ctx.__f().then(() => process.stdout.write(JSON.stringify({sent, alerts, error: null})),
               e => process.stdout.write(JSON.stringify({sent, alerts, error: String(e)})));
""".replace("__OK__", json.dumps(creds_ok)).replace("__CODE__", json.dumps(code))
    out = _node(tmp_path, script, "dh.js")
    assert out["sent"] == [] and out["error"] is None, out
    assert len(out["alerts"]) == (1 if creds_ok else 0)


# --- FE2-8: the deployment flow page follows the theme --------------------------------

def test_the_deploy_flow_page_follows_the_light_theme():
    page = _read("static/deploy_flow.html")
    assert '<script src="/static/report_theme.js"></script>' in page


def test_the_deploy_flow_page_is_revalidated():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    r = TestClient(srv.app).get("/report/deploy-flow")
    assert r.status_code == 200
    assert "no-cache" in r.headers.get("cache-control", "")
