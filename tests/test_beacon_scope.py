"""Beacon's tenant API watch reads only what is in scope (beacon_scope.py):
the scopes ticked on the Scope page and the channels marked Zscaler pick
the endpoints; everything else is never GET. Every tenant is a fake that
records its calls; nothing leaves this machine."""
from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient

import beacon
import beacon_scope as bs

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALL = bs.watch_endpoints()
WEB_EMAIL = {"web_dlp": {"choice": "zscaler"}, "email_dlp": {"choice": "zscaler"},
             "endpoint_dlp": {"choice": "alternative", "note": "Vendor X"}, "saas_casb": {"choice": "gap"}}


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_BEACON_STATE", str(tmp_path / "beacon_state.json"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    yield


class Recorder:
    """A tenant that answers every GET and records it; any write fails the test."""
    def __init__(self, customer_id="7"):
        self.legacy, self.customer_id = False, customer_id
        self.calls = []
        self.closed = False

    def get(self, ep, p=None):
        self.calls.append(ep)
        return [{"id": 1}], 200

    def post(self, *a, **k):
        raise AssertionError("the tenant watch must never write")

    put = delete = patch = post

    def close(self):
        self.closed = True


def _watch(scopes, channels, client=None, label="acme (production)"):
    sel = bs.select(scopes, channels)
    client = client or Recorder()
    snap = beacon.run(online=False, upstream=lambda **k: {}, tenant_client=client, tenant_label=label,
                      tenant_scope=sel, probe=lambda c, endpoints: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None))
    return sel, client, snap


# ── The map ───────────────────────────────────────────────────────────

def test_every_watched_endpoint_is_mapped_or_listed_as_unmapped():
    m = bs.scope_map()
    mapped = set().union(*m["scopes"].values(), *m["channels"].values())
    assert mapped | set(m["unmapped"]) == set(ALL) and not mapped & set(m["unmapped"])
    assert m["unmapped"] == [], "every watched endpoint is read by some check"
    assert "/zia/fileTypeRules" in m["scopes"]["zia_extras"], "SEC.5 (ZIA platform) reads it through _items()"
    assert set(m["scopes"]) >= {"dlp", "zia_extras", "zpa", "zcc", "automation", "zdx", "zidentity", "rbac"}
    # The channel rule endpoints belong to their channel, nothing else brings them in.
    assert "/zia/emailDlpRules" in m["channels"]["email_dlp"] and "/zia/casbDlpRules/all" in m["channels"]["saas_casb"]
    assert "/zia/endPointDlpRules" in m["channels"]["endpoint_dlp"]


def test_each_scope_reads_only_its_own_platform():
    for scope, prefix in (("zdx", "/zdx/"), ("zidentity", "/zid/"), ("zpa", "/zpa/")):
        sel = bs.select([scope], {})
        assert sel["endpoints"] and all(ep.startswith(prefix) for ep in sel["endpoints"]), scope
    zcc = bs.select(["zcc"], {})["endpoints"]
    assert zcc and all(ep.startswith("/zcc/") for ep in zcc)
    zia = bs.select(["zia_extras"], {})["endpoints"]
    assert "/zia/firewallFilteringRules" in zia and "/zia/webDlpRules" not in zia and not [e for e in zia if not e.startswith("/zia/")]


def test_channel_rule_endpoints_need_their_channel_on_zscaler():
    rules = ("/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules/all")
    none = bs.select(["dlp"], {})
    assert not set(rules) & set(none["endpoints"]) and set(rules) <= set(none["not_in_scope"])
    sel = bs.select(["dlp"], WEB_EMAIL)
    assert "/zia/emailDlpRules" in sel["endpoints"]
    assert "/zia/endPointDlpRules" not in sel["endpoints"], "alternative is out of scope"
    assert "/zia/casbDlpRules/all" not in sel["endpoints"], "a gap is out of scope for the watch"
    # SSL inspection is Inline Web DLP's prerequisite (channel_scope.PREREQUISITES): read with it.
    assert sel["channels"] == ["web_dlp", "email_dlp", "ssl_inspection"]
    assert sel["summary"] == f"{len(sel['endpoints'])} endpoints for DLP (Web, Email, SSL)"
    assert "/zia/sslInspectionRules" in sel["endpoints"]
    # A channel alone, without its scope ticked, reads nothing.
    assert bs.select([], WEB_EMAIL)["endpoints"] == {}


def test_a_channel_widens_only_its_own_checks():
    base = set(bs.select(["dlp"], {})["endpoints"])
    assert "/zia/dlpDictionaries" in base, "the general DLP section reads shared objects without a channel"
    assert "/zia/webDlpRules" not in base, "Inline Web DLP's rules are its own: never read with the channel unticked"
    web = set(bs.select(["dlp"], {"web_dlp": "zscaler"})["endpoints"])
    assert {"/zia/webDlpRules", "/zia/webDlpGlobalOptions"} <= web - base
    platform = set(bs.select(["zia_extras"], {})["endpoints"])
    cac = set(bs.select(["zia_extras"], {"cloud_app_control": "zscaler"})["endpoints"])
    # /zia/advancedSettings is read under ZIA platform alone too (domain fronting THR.9, Microsoft 365 one-click UF.7).
    assert "/zia/advancedSettings" in platform
    assert {"/zia/cloudApplicationRules", "/zia/tenancyRestrictionProfile"} <= cac - platform,         "ZIA platform's Cloud Apps checks are in scope only with Cloud App Control on Zscaler"
    assert set(bs.select(["zia_extras"], {"cloud_app_control": "alternative"})["endpoints"]) == platform,         "alternative and gap are both out of scope, as the assessment does"


def test_a_ticked_non_dlp_scope_reads_only_its_channels_on_zscaler():
    # As the assessment: a channel that is undeclared, a gap or an
    # alternative takes its checks out, whichever scope they sit in.
    for ch in ({}, {"genai_security": "gap"}, {"genai_security": "alternative"}):
        assert bs.select(["genai"], ch)["endpoints"] == {}, ch
    genai = bs.select(["genai"], {"genai_security": "zscaler"})
    # SSL inspection comes with GenAI Security as its prerequisite.
    assert genai["endpoints"] and genai["summary"] == f"{len(genai['endpoints'])} endpoints for GenAI & prompts, channels on Zscaler: GenAI, SSL"
    assert "/zia/urlCategories" in genai["endpoints"] and "/zia/cloudApplicationRules" not in genai["endpoints"]
    both = bs.select(["genai"], {"genai_security": "zscaler", "cloud_app_control": "zscaler"})
    assert "/zia/cloudApplicationRules" in both["endpoints"]


def test_server_watches_the_genai_scope_alone(server):
    tenant, built = server
    c = _client()
    for ch in ({}, {"genai_security": {"choice": "gap"}}):
        d = c.post("/api/beacon/scope", json={"scopes": ["genai"], "channels": ch}).json()
        assert d["ok"] is False and d["endpoints"] == 0 and "Nothing is in scope" in d["detail"], d
        r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["genai"], "channels": ch})
        assert r.status_code == 400 and not tenant.calls, r.text
    on = {"genai_security": "zscaler"}
    d = c.post("/api/beacon/scope", json={"scopes": ["genai"], "channels": on}).json()
    assert d["ok"] is True and d["summary"].endswith("endpoints for GenAI & prompts, channels on Zscaler: GenAI, SSL"), d
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["genai"], "channels": on})
    assert r.status_code == 200, r.text
    _wait_idle(c)
    assert tenant.calls and set(tenant.calls) == set(bs.select(["genai"], on)["endpoints"])


class _RecordAll:
    """A tenant for running checks: answers every read with an empty list."""
    legacy, customer_id, requests_made = False, "7", 0

    def __init__(self):
        self.paths = set()

    def get(self, ep, p=None):
        self.paths.add(ep)
        return [], 200

    def __getattr__(self, name):
        return lambda *a, **k: ([], 200)


def test_the_map_gives_each_check_every_endpoint_it_really_reads():
    """Run every registered check against a recording tenant: each watched
    endpoint it GETs must be in its row of the map, so its scope reads it."""
    universe = set(ALL)
    rows = {(r["scope"], r["id"]): set(r["endpoints"]) for r in bs.check_map()}
    missing = {}
    for scope, regs in bs.SCOPE_REGISTRIES.items():
        for module, attr, prefix in regs:
            for chk in bs._registry(module, attr):
                cid, section, fn = str(chk[0]), str(chk[1]), chk[-1]
                if prefix and not section.startswith(prefix):
                    continue
                t = _RecordAll()
                try:
                    fn(t)
                except Exception:  # noqa: BLE001 — what it read before failing still counts
                    pass
                gap = (t.paths & universe) - rows.get((scope, cid), set())
                if gap:
                    missing[f"{scope} {cid}"] = sorted(gap)
    assert not missing, missing
    # The helpers the testers named: _items() (SEC.5, UF.1) and _rules() (GenAI).
    zia = bs.select(["zia_extras"], {})["endpoints"]
    assert {"/zia/fileTypeRules", "/zia/urlFilteringRules", "/zia/urlCategories", "/zia/nssFeeds"} <= set(zia)
    assert {"/zpa/application", "/zpa/appConnectorGroup"} <= set(bs.select(["zpa"], {})["endpoints"])
    assert {"/zia/webDlpRules", "/zia/urlFilteringRules"} <= set(bs.select(["automation"], {"web_dlp": "zscaler"})["endpoints"])


def test_summary_names_scopes_and_zscaler_channels():
    sel = bs.select(["dlp", "zcc"], WEB_EMAIL)
    assert sel["summary"].endswith("endpoints for DLP (Web, Email, SSL), ZCC")
    assert bs.select(["zdx"], {})["summary"] == "6 endpoints for ZDX"
    assert bs.select(["nonsense"], {})["scopes"] == []


# ── The watch GETs only what is in scope ──────────────────────────────

def test_out_of_scope_endpoints_are_never_read():
    sel, t, snap = _watch(["dlp", "zcc"], WEB_EMAIL)
    assert t.calls and set(t.calls) == set(sel["endpoints"])
    never = set(ALL) - set(sel["endpoints"])
    assert never and not never & set(t.calls)
    for ep in ("/zia/endPointDlpRules", "/zia/casbDlpRules/all", "/zia/fileTypeRules", "/zdx/alerts/ongoing", "/zpa/idp"):
        assert ep not in t.calls, ep
    ts = snap["tenant"]["scope"]
    assert ts["endpoints"] == len(sel["endpoints"]) == snap["tenant"]["requests"] and ts["summary"] == sel["summary"]
    assert ts["unmapped"] == [] and set(ts["not_in_scope"]) | set(ts["read"]) | set(ts["unmapped"]) == set(ALL)


def test_only_zdx_reads_six_endpoints():
    sel, t, _ = _watch(["zdx"], {})
    assert sorted(t.calls) == sorted(sel["endpoints"]) and len(t.calls) == 6


def test_nothing_in_scope_is_refused_and_never_falls_back_to_everything():
    with pytest.raises(ValueError, match="Nothing is in scope"):
        beacon.run(online=False, upstream=lambda **k: {}, tenant_client=Recorder(), save=False)
    with pytest.raises(ValueError, match="Nothing is in scope"):
        beacon.run(online=False, upstream=lambda **k: {}, tenant_client=Recorder(), tenant_scope=bs.select([], {}), save=False)
    with pytest.raises(ValueError):
        beacon.probe_tenant(Recorder(), sleep=lambda s: None)


def test_a_changed_scope_compares_only_the_shared_endpoints_and_says_so():
    _watch(["zdx"], {})
    t2 = Recorder()
    sel, _, snap = _watch(["zdx", "zidentity"], {}, client=t2)
    tenant_changes = [c for c in snap["diff"]["changes"] if c["watcher"] == "tenant"]
    scope = [c for c in tenant_changes if c["kind"] == "scope_changed"]
    assert len(scope) == 1 and "scope changed" in scope[0]["text"] and "6 endpoints read both times" in scope[0]["text"]
    assert "3 newly in scope" in scope[0]["text"]
    assert not [c for c in tenant_changes if c["kind"] == "endpoint_status"]
    # The same scope again: nothing to say about it.
    _, _, again = _watch(["zdx", "zidentity"], {})
    assert not [c for c in again["diff"]["changes"] if c["kind"] == "scope_changed"]


# ── The server ────────────────────────────────────────────────────────

def _client():
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _wait_idle(c, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        d = c.get("/api/beacon").json()
        if not d["running"]:
            return d
        time.sleep(0.05)
    pytest.fail("the Beacon run did not finish")


@pytest.fixture
def server(monkeypatch):
    import dlp_api_server as srv
    real = beacon.run
    tenant = Recorder()
    built = []

    def run(online=True, tenant_client=None, tenant_label="", trigger="manual", tenant_scope=None, **kw):
        return real(online=False, upstream=lambda **k: {}, tenant_client=tenant_client, tenant_label=tenant_label, trigger=trigger,
                    tenant_scope=tenant_scope, probe=lambda c, endpoints: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None))
    monkeypatch.setattr(beacon, "run", run)
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(req) or tenant)
    return tenant, built


def test_the_run_reads_only_the_scope_the_page_sent(server):
    tenant, _ = server
    c = _client()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zdx"], "channels": {}})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["endpoints"] == 6 and body["scope"]["summary"] == "6 endpoints for ZDX" and body["scope"]["source"] == "the Scope page"
    d = _wait_idle(c)
    assert sorted(tenant.calls) == sorted(bs.select(["zdx"], {})["endpoints"]) and tenant.closed
    assert d["latest"]["tenant"]["scope"]["summary"] == "6 endpoints for ZDX"


def test_nothing_in_scope_is_a_400_before_signing_in(server):
    tenant, built = server
    c = _client()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True})
    assert r.status_code == 400 and r.json()["detail"] == "Nothing is in scope — choose what to assess on the Scope page."
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["compliance"], "channels": {"web_dlp": "alternative"}})
    assert r.status_code == 400 and r.json()["detail"].startswith("Nothing is in scope")
    assert built == [] and tenant.calls == [], "no sign-in, no read"
    assert c.get("/api/beacon").json()["running"] is False
    # Without the tenant watch, the scope is not needed.
    assert c.post("/api/beacon/run", json={"online": False}).status_code == 200
    _wait_idle(c)


def test_the_profile_scope_is_used_when_the_page_sent_none(server):
    import tenant_profiles
    tenant, _ = server
    tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "cid-abcdef123456",
                            "scopes": ["dlp"], "channels": {"email_dlp": {"choice": "zscaler"}}}, profile_id="acme")
    c = _client()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "profile_id": "acme"})
    assert r.status_code == 200, r.text
    sc = r.json()["scope"]
    assert sc["scopes"] == ["dlp"] and sc["channels"] == ["email_dlp"] and "Acme" in sc["source"]
    _wait_idle(c)
    assert "/zia/emailDlpRules" in tenant.calls and "/zia/endPointDlpRules" not in tenant.calls and "/zcc/machineTunnel" not in tenant.calls
    # The page's selection wins over the profile's.
    tenant.calls.clear()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "profile_id": "acme", "scopes": ["zidentity"]})
    assert r.json()["scope"]["scopes"] == ["zidentity"]
    _wait_idle(c)
    assert sorted(tenant.calls) == ["/zid/groups", "/zid/resourceServers", "/zid/users"]
    # ... and is never mixed with it: the profile's channels do not widen a page selection.
    tenant.calls.clear()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "profile_id": "acme", "scopes": ["dlp"]})
    sc = r.json()["scope"]
    assert sc["channels"] == [] and sc["source"] == "the Scope page"
    _wait_idle(c)
    assert "/zia/emailDlpRules" not in tenant.calls


def test_the_scope_preview_says_what_will_be_read_without_touching_a_tenant(server):
    tenant, built = server
    c = _client()
    d = c.post("/api/beacon/scope", json={"scopes": ["dlp", "zcc"], "channels": WEB_EMAIL}).json()
    assert d["ok"] is True and d["summary"].endswith("endpoints for DLP (Web, Email, SSL), ZCC") and d["endpoints"] == len(d["read"])
    assert "/zia/fileTypeRules" in d["not_in_scope"] and d["unmapped"] == []
    d = c.post("/api/beacon/scope", json={}).json()
    assert d["ok"] is False and d["detail"] == "Nothing is in scope — choose what to assess on the Scope page."
    assert built == [] and tenant.calls == []


def test_beacon_js_sends_the_scope_page_selection():
    js = open(os.path.join(ROOT, "static", "beacon.js"), encoding="utf-8").read()
    assert "'zassess_scopes_live_v1'" in js and "'zassess_channels_v1'" in js
    assert "'zscaler_made_easy_config'" not in js, "the last Save config copy can be stale; never read it"
    assert "getSelectedScopes" in js and "__dbChannelScope" in js, "the open assessment tab's live selection first"
    assert "scopes: sc.scopes, channels: sc.channels" in js, "the run body carries the selection"
    assert "'/api/beacon/scope'" in js and "id=\"bcScope\"" in open(os.path.join(ROOT, "static", "report_beacon.html"), encoding="utf-8").read()


def test_the_page_says_it_reads_only_what_is_in_scope():
    html = open(os.path.join(ROOT, "static", "report_beacon.html"), encoding="utf-8").read()
    assert "in scope on the Scope page" in html and "reads every endpoint the app" not in html.lower()
    ex = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    entry = ex[ex.index("X.beacon = {"):ex.index("X.logs = {")]
    assert "in scope on the Scope page" in entry and "every endpoint the app uses" not in entry


# ── A watch that read nothing ─────────────────────────────────────────

def _boom(c, endpoints):
    raise ConnectionError("tenant unreachable")


def _watch_with(probe, scopes=("zdx",), client=None):
    sel = bs.select(list(scopes), {})
    return beacon.run(online=False, upstream=lambda **k: {}, tenant_client=client or Recorder(), tenant_label="acme",
                      tenant_scope=sel, probe=probe)


def _ok(answer=None):
    class T(Recorder):
        def get(self, ep, p=None):
            self.calls.append(ep)
            return answer(ep) if answer else ([{"id": 1}], 200)
    return lambda c, endpoints: beacon.probe_tenant(T(), endpoints=endpoints, sleep=lambda s: None)


def test_a_failed_watch_is_not_a_scope_change_and_is_not_the_next_baseline():
    _watch_with(_ok())
    failed = _watch_with(_boom)
    kinds = [c["kind"] for c in failed["diff"]["changes"]]
    assert kinds == ["watch_failed"], failed["diff"]["changes"]
    assert "read nothing (ConnectionError: tenant unreachable)" in failed["diff"]["changes"][0]["text"]
    assert failed["diff"]["summary"][0] == "1 change since the last run: 1 tenant watch that read nothing."
    # The next good watch compares with the first one, endpoint by endpoint.
    gone = sorted(bs.select(["zdx"], {})["endpoints"])[0]
    third = _watch_with(_ok(lambda ep: ({"error": "nope"}, 403) if ep == gone else ([{"id": 1}], 200)))
    ch = third["diff"]["changes"]
    assert not [c for c in ch if c["kind"] == "scope_changed"], ch
    assert [c["endpoint"] for c in ch if c["kind"] == "endpoint_status"] == [gone]


def test_an_unanswered_endpoint_is_not_a_scope_change():
    _watch_with(_ok())
    snap = _watch_with(lambda c, endpoints: {"endpoints": [], "counts": {}, "requests": 0, "stopped": None, "method": "GET"})
    assert not [c for c in snap["diff"]["changes"] if c["kind"] == "scope_changed"]


def test_a_failed_watch_ends_the_run_in_error(server, monkeypatch):
    c = _client()
    monkeypatch.setattr(beacon, "probe_tenant", lambda *a, **k: _boom(None, None))
    assert c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zdx"]}).status_code == 200
    d = _wait_idle(c)
    assert d["timer"]["last_status"] == "error" and "tenant unreachable" in d["timer"]["last_error"]


# ── Pacing: every HTTP GET, not every endpoint ───────────────────────

def test_fan_out_gets_are_paced_and_counted():
    import dlp_assessment_full_auto as full

    class Resp:
        status_code = 200

        def json(self):
            return []
    cl = full.Client("cid", "sec", "acme", "production", "7")
    cl.token, cl.exp = "t", time.time() + 3600
    sent = []
    cl.sess.get = lambda url, **k: sent.append((time.time(), url)) or Resp()
    eps = {ep: ["x"] for ep in ("/zia/cloudApplicationRules", "/zia/webDlpRules")}
    assert "/zia/cloudApplicationRules" in full._FAN_OUT
    before_gap = cl._limiter.min_gap
    t = beacon.probe_tenant(cl, endpoints=eps, gap=0.05)
    assert len(sent) > len(eps) and t["requests"] == len(sent) == cl.requests_made
    gaps = [b[0] - a[0] for a, b in zip(sent, sent[1:])]
    assert min(gaps) >= 0.045, "each fan-out GET waits the watch's gap, not the client's"
    assert cl._limiter.min_gap == before_gap, "the client's own pacing is put back"


def test_without_a_pacer_the_wait_grows_with_the_gets_an_endpoint_took():
    class Fan(Recorder):
        requests_made = 0

        def get(self, ep, p=None):
            self.calls.append(ep)
            self.requests_made += 3 if ep == "/a" else 1
            return [], 200
    waits = []
    t = beacon.probe_tenant(Fan(), endpoints={"/a": [], "/b": [], "/c": []}, sleep=waits.append, gap=1.0)
    assert waits == [3.0, 1.0] and t["requests"] == 5


# ── Nothing readable with this sign-in ────────────────────────────────

LEGACY = {"auth_method": "legacy", "cloud": "production", "username": "admin@acme.com", "password": "pw-123456789", "api_key": "a" * 12}
ONEAPI = {"auth_method": "oneapi", "cloud": "production", "vanity_domain": "acme", "client_id": "cid-abcdef123456", "client_secret": "s" * 20}


def test_a_sign_in_that_can_read_nothing_in_scope_is_refused_before_signing_in(server):
    tenant, built = server
    c = _client()
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zcc"], **LEGACY})
    assert r.status_code == 400 and "classic ZIA API sign-in reaches ZIA only" in r.json()["detail"], r.text
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zpa"], **ONEAPI})
    assert r.status_code == 400 and "no ZPA customer id" in r.json()["detail"], r.text
    assert built == [] and tenant.calls == [], "no sign-in, no read"
    # Something readable: the run goes ahead.
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zpa", "zdx"], **ONEAPI})
    assert r.status_code == 200, r.text
    _wait_idle(c)


# ── The page ──────────────────────────────────────────────────────────

_NODE_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const store = JSON.parse(process.argv[3]);
const els = {}, posts = [], listeners = {};
let writes = 0;
function el(id) {
  if (!els[id]) {
    const o = { value: '', checked: false, disabled: false, textContent: '', addEventListener() {} };
    let html = '';
    Object.defineProperty(o, 'innerHTML', { get: () => html, set: v => { html = v; if (id === 'bcScope') writes++; } });
    els[id] = o;
  }
  return els[id];
}
global.document = { getElementById: el, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
global.window = { opener: null, addEventListener: (k, f) => { listeners[k] = f; } };
global.localStorage = { getItem: k => (k in store ? store[k] : null), setItem() {} };
global.fetch = async (url, opt) => {
  if (opt && opt.method === 'POST') posts.push({ url, body: JSON.parse(opt.body) });
  const body = url === '/api/tenant-profiles' ? { profiles: [] } : url === '/api/beacon/scope' ? { ok: true, summary: '6 endpoints for ZDX', source: 'the Scope page' } : {};
  return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) };
};
eval(src);
const tick = () => new Promise(r => setTimeout(r, 20));
(async () => {
  await tick();
  for (let i = 0; i < 3; i++) { listeners.focus && listeners.focus(); await tick(); }
  console.log(JSON.stringify({ posts: posts.filter(p => p.url === '/api/beacon/scope'), writes }));
})();
"""


def _page(store, tmp_path):
    import json
    import shutil
    import subprocess
    if shutil.which("node") is None:
        pytest.skip("node not available")
    h = tmp_path / "h.js"
    h.write_text(_NODE_HARNESS, encoding="utf-8")
    r = subprocess.run(["node", str(h), os.path.join(ROOT, "static", "beacon.js"), json.dumps(store)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


CHANNELS = '{"web_dlp":{"choice":"zscaler","note":"Contact: Jane Doe jane.doe@customer.example"},"email_dlp":{"choice":"gap","note":"x"}}'


def test_the_page_sends_live_scopes_and_channel_choices_only(tmp_path):
    d = _page({"zassess_scopes_live_v1": '{"scopes":["dlp"]}', "zassess_channels_v1": CHANNELS,
               "zscaler_made_easy_config": '{"scopes":["zpa","zdx"]}'}, tmp_path)
    body = d["posts"][0]["body"]
    assert body["scopes"] == ["dlp"], "the live ticks, not the last Save config copy"
    assert body["channels"] == {"web_dlp": "zscaler"}, "only the choice; the free-text note never leaves the browser"
    assert len(d["posts"]) == 1 and d["writes"] == 1, "a window focus with nothing changed neither re-asks nor rewrites the live region"


def test_without_the_live_ticks_the_page_sends_no_selection(tmp_path):
    d = _page({"zassess_channels_v1": CHANNELS, "zscaler_made_easy_config": '{"scopes":["zpa","zdx"]}'}, tmp_path)
    assert d["posts"][0]["body"]["scopes"] == [] and d["posts"][0]["body"]["channels"] == {}, "the profile's selection is used whole"


def test_the_scope_page_publishes_its_ticks_on_every_change():
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "localStorage.setItem('zassess_scopes_live_v1'" in html
    assert "contains('scope-cb')) publishScopes()" in html and "loadConfig();\npublishScopes();" in html
    fn = html[html.index("function setSelectedScopes"):html.index("function publishScopes")]
    assert "publishScopes()" in fn


# ── Round 2: the map covers every endpoint a check reads ───────────────

def test_every_endpoint_an_in_scope_check_reads_is_read_or_listed_as_not_read():
    universe = set(ALL)
    assert not [ep for ep in universe if ep.endswith("/")], "a base or prefix is not an endpoint"
    for scopes in (["zia_extras", "zpa"], ["dlp"], ["zcc", "rbac"], list(bs.SCOPE_REGISTRIES)):
        sel = bs.select(scopes, WEB_EMAIL)
        known = set(sel["endpoints"]) | set(sel["not_in_scope"]) | set(sel["unmapped"])
        missing = [(r["id"], ep) for r in bs.check_map() if r["scope"] in scopes for ep in r["endpoints"] if ep not in known]
        assert not missing, (scopes, missing)
    platform = bs.select(["zia_extras", "zpa"], {})["endpoints"]
    for ep in ("/zia/firewallIpsRules", "/zia/networkServices", "/zia/bandwidthControlRules", "/zpa/serverGroup", "/zpa/connector", "/zpa/serviceEdge"):
        assert ep in platform, ep
    assert "/zia/casbTenant/lite" in bs.select(["dlp"], WEB_EMAIL)["endpoints"]


def test_the_map_is_built_once_and_quickly_even_when_asked_at_the_same_time(monkeypatch):
    import threading
    monkeypatch.setattr(bs, "_MAP", None)
    monkeypatch.setattr(bs, "_DIRECT", {})
    builds = []
    real = bs._build_map
    monkeypatch.setattr(bs, "_build_map", lambda: builds.append(1) or real())
    start = time.time()
    out = []
    ts = [threading.Thread(target=lambda: out.append(bs.check_map())) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert builds == [1] and len(out) == 4 and all(o is out[0] for o in out)
    assert time.time() - start < 20, "each function is parsed once, not once per check"


# ── Round 2: the same selection is the same scope ─────────────────────

def test_channels_in_another_order_are_the_same_scope():
    a, _, _ = _watch(["dlp"], {"web_dlp": "zscaler", "email_dlp": "zscaler"})
    b, _, snap = _watch(["dlp"], {"email_dlp": "zscaler", "web_dlp": "zscaler"})
    assert a["summary"] == b["summary"] and a["channels"] == b["channels"] == ["web_dlp", "email_dlp", "ssl_inspection"]
    assert not snap["diff"]["changes"], snap["diff"]["changes"]
    assert snap["diff"]["summary"][0].startswith("Nothing changed")


def test_a_channel_that_brings_nothing_in_is_not_named_and_is_not_a_scope_change():
    a = bs.select(["zcc"], {"web_dlp": "zscaler", "email_dlp": "zscaler"})
    assert a["summary"] == bs.select(["zcc"], {})["summary"] == "23 endpoints for ZCC"
    _watch(["zcc"], {})
    _, _, snap = _watch(["zcc"], {"web_dlp": "zscaler"})
    assert not [c for c in snap["diff"]["changes"] if c["kind"] == "scope_changed"]


# ── Round 2: a partial or unreachable watch ───────────────────────────

def _clock_after(n_reads, budget=900):
    """A clock that is past the budget once `n_reads` endpoints were read."""
    state = {"calls": 0}

    def clock():
        state["calls"] += 1
        return 0.0 if state["calls"] <= n_reads + 1 else budget + 1
    return clock


def test_a_watch_that_ran_out_of_budget_is_partial_not_nothing_changed():
    first = _watch_with(_ok(), scopes=("zcc",))
    n = len(first["tenant"]["endpoints"])
    part = _watch_with(lambda c, endpoints: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None, clock=_clock_after(2)), scopes=("zcc",))
    assert part["tenant"]["counts"].get("not probed") == n - 2, part["tenant"]["counts"]
    kinds = [c["kind"] for c in part["diff"]["changes"]]
    assert "watch_partial" in kinds and not part["diff"]["summary"][0].startswith("Nothing changed"), part["diff"]["summary"]
    assert f"{n - 2} of {n} endpoints in scope were not read" in " ".join(part["diff"]["summary"])
    assert beacon.watch_problem(part["tenant"])[0] == "partial"
    # The next complete watch compares with the complete one, not the partial one.
    third = _watch_with(_ok(), scopes=("zcc",))
    assert third["diff"]["against"]["tenant"] == first["id"]


class _Down(Recorder):
    """A tenant that cannot be reached: what Client.get answers on a ConnectionError."""
    def get(self, ep, p=None):
        self.calls.append(ep)
        return {"error": "connection error: refused", "status": 0}, 0


_REAL_PROBE = beacon.probe_tenant


def _unreachable(c, endpoints):
    return _REAL_PROBE(_Down(), endpoints=endpoints, sleep=lambda s: None)


def test_a_watch_where_no_get_got_an_answer_read_nothing_and_is_not_the_baseline():
    first = _watch_with(_ok(), scopes=("zcc",))
    down = _watch_with(_unreachable, scopes=("zcc",))
    assert [c["kind"] for c in down["diff"]["changes"]] == ["watch_failed"], down["diff"]["changes"]
    assert "could not be reached" in down["diff"]["changes"][0]["text"]
    assert beacon.watch_problem(down["tenant"])[0] == "error"
    back = _watch_with(_ok(), scopes=("zcc",))
    assert back["diff"]["against"]["tenant"] == first["id"] and not back["diff"]["changes"], back["diff"]


def _partial(endpoints):
    rows = [{"endpoint": ep, "status": "OK" if i < 2 else "not probed", "http": 200 if i < 2 else None, "items": 1}
            for i, ep in enumerate(endpoints)]
    return {"endpoints": rows, "counts": {}, "requests": 2, "stopped": "the 900-second budget ran out", "method": "GET", "seconds": 1.0}


def test_an_unreachable_or_partial_watch_is_said_in_the_run_status(server, monkeypatch):
    c = _client()
    monkeypatch.setattr(beacon, "probe_tenant", lambda cl, endpoints=None, **k: _unreachable(cl, endpoints))
    assert c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zdx"]}).status_code == 200
    d = _wait_idle(c)
    assert d["timer"]["last_status"] == "error" and "could not be reached" in d["timer"]["last_error"], d["timer"]
    monkeypatch.setattr(beacon, "probe_tenant", lambda cl, endpoints=None, **k: _partial(endpoints))
    assert c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zdx"]}).status_code == 200
    d = _wait_idle(c)
    assert d["timer"]["last_status"] == "partial" and "4 of 6 endpoints in scope were not read" in d["timer"]["last_error"], d["timer"]


def test_the_get_count_includes_gets_that_timed_out():
    import requests
    import dlp_assessment_full_auto as full
    cl = full.Client("cid", "sec", "acme", "production", "7")
    cl.token, cl.exp = "t", time.time() + 3600
    cl._limiter.min_gap = 0
    sent = []

    def boom(url, **k):
        sent.append(url)
        raise requests.exceptions.Timeout("read timed out")
    cl.sess.get = boom
    eps = {ep: ["x"] for ep in ("/zia/webDlpRules", "/zia/dlpDictionaries")}
    t = beacon.probe_tenant(cl, endpoints=eps, gap=0, sleep=lambda s: None)
    assert t["counts"] == {"timeout": 2} and t["requests"] == len(sent) == 4, (t, sent)


# ── Round 2: the preview judges the sign-in the run will use ──────────

_ENV_KEYS = ("ZSCALER_AUTH_METHOD", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY", "ZSCALER_CLIENT_ID",
             "ZSCALER_CLIENT_SECRET", "ZSCALER_VANITY_DOMAIN", "ZSCALER_CUSTOMER_ID", "ZSCALER_CLOUD")


def test_the_preview_and_the_run_agree_on_the_sign_in(server, monkeypatch):
    import tenant_profiles
    for k in _ENV_KEYS:
        monkeypatch.delenv(k, raising=False)
    tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "cid-abcdef123456"}, profile_id="acme")
    c = _client()

    def both(body):
        p = c.post("/api/beacon/scope", json=body).json()
        r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, **body})
        if r.status_code == 200:
            _wait_idle(c)
        return p["ok"], r.status_code == 200, p
    # A ZPA customer id typed on the assessment tab; the profile has none.
    ok, ran, p = both({"scopes": ["zpa"], "channels": {}, "profile_id": "acme", "customer_id": "72000001"})
    assert ok and ran, p
    # The classic ZIA sign-in typed on the assessment tab, only ZDX in scope.
    ok, ran, p = both({"scopes": ["zdx"], "channels": {}, **LEGACY})
    assert not ok and not ran and "reaches ZIA only" in p["detail"], p
    # The classic ZIA sign-in saved on this computer (environment).
    monkeypatch.setenv("ZSCALER_AUTH_METHOD", "legacy")
    monkeypatch.setenv("ZSCALER_USERNAME", LEGACY["username"])
    monkeypatch.setenv("ZSCALER_PASSWORD", LEGACY["password"])
    monkeypatch.setenv("ZSCALER_API_KEY", LEGACY["api_key"])
    ok, ran, p = both({"scopes": ["zcc"], "channels": {}, "profile_id": ""})
    assert not ok and not ran and "reaches ZIA only" in p["detail"], p


def test_every_scope_unticked_on_the_page_is_nothing_in_scope_not_the_profile(server):
    import tenant_profiles
    tenant, built = server
    tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "cid-abcdef123456",
                            "scopes": ["dlp", "zia_extras", "zpa", "zcc", "zdx"]}, profile_id="acme")
    c = _client()
    body = {"scopes": [], "channels": {}, "profile_id": "acme", "from_page": True}
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, **body})
    assert r.status_code == 400 and r.json()["detail"].startswith("Nothing is in scope"), r.text
    assert c.post("/api/beacon/scope", json=body).json()["ok"] is False
    assert built == [] and tenant.calls == []
    # Without the page's ticks the profile's selection is still used.
    assert c.post("/api/beacon/scope", json={"profile_id": "acme"}).json()["ok"] is True


def test_the_page_says_when_every_scope_is_unticked(tmp_path):
    d = _page({"zassess_scopes_live_v1": '{"scopes":[]}'}, tmp_path)
    body = d["posts"][0]["body"]
    assert body["scopes"] == [] and body["from_page"] is True
    d = _page({}, tmp_path)
    assert d["posts"][0]["body"]["from_page"] is False


# ── Round 2: the page ─────────────────────────────────────────────────

_RENDER_HARNESS = r"""
const fs = require('fs');
const src = fs.readFileSync(process.argv[2], 'utf8');
const cfg = JSON.parse(process.argv[3]);
const store = cfg.store || {};
const els = {}, posts = [], listeners = {}, writes = {};
function el(id) {
  if (!els[id]) {
    const o = { value: '', checked: false, disabled: false, textContent: '', addEventListener() {}, querySelector: () => el(id + ' tbody') };
    let html = '';
    Object.defineProperty(o, 'innerHTML', { get: () => html, set: v => { html = v; writes[id] = (writes[id] || 0) + 1; } });
    els[id] = o;
  }
  return els[id];
}
const realST = setTimeout;
global.setTimeout = (f, ms) => realST(f, Math.min(ms || 0, 5));
global.document = { getElementById: el, querySelector: () => null, querySelectorAll: () => [], addEventListener() {} };
global.window = { opener: null, addEventListener: (k, f) => { listeners[k] = f; } };
global.localStorage = { getItem: k => (k in store ? store[k] : null), setItem() {} };
global.fetch = async (url, opt) => {
  if (opt && opt.method === 'POST') posts.push({ url, body: JSON.parse(opt.body) });
  let body = {};
  if (url === '/api/tenant-profiles') body = { profiles: [] };
  else if (url === '/api/beacon/scope') { await new Promise(r => realST(r, cfg.scopeDelay || 0)); body = { ok: true, summary: '6 endpoints for ZDX', source: 'the Scope page' }; }
  else if (url === '/api/beacon') body = cfg.beacon || { latest: null, history: [] };
  return { ok: true, status: 200, json: async () => body };
};
eval(src);
(async () => {
  await new Promise(r => realST(r, 30));
  for (let i = 0; i < (cfg.focus || 0); i++) { if (listeners.focus) listeners.focus(); await new Promise(r => realST(r, 5)); }
  await new Promise(r => realST(r, cfg.wait || 150));
  console.log(JSON.stringify({ posts: posts.filter(p => p.url === '/api/beacon/scope'), writes,
    tenant: el('bcTenantBody').innerHTML, changes: el('bcChanges').innerHTML }));
  process.exit(0);
})();
"""


def _render(cfg, tmp_path):
    import json
    import shutil
    import subprocess
    if shutil.which("node") is None:
        pytest.skip("node not available")
    h = tmp_path / "r.js"
    h.write_text(_RENDER_HARNESS, encoding="utf-8")
    r = subprocess.run(["node", str(h), os.path.join(ROOT, "static", "beacon.js"), json.dumps(cfg)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


def _snap(tenant, changes=()):
    return {"latest": {"at": "2026-10-01T00:00:00+00:00", "online": False, "trigger": "manual", "seconds": 1, "drift": [], "tenant": tenant},
            "diff": {"changes": list(changes), "summary": ["x"], "against": {}}, "history": [], "timer": {}}


_SCOPE = {"summary": "2 endpoints for DLP", "source": "the Scope page", "not_in_scope": ["/zia/a"], "unmapped": ["/zia/b"], "read": ["/zia/c"]}


def test_polling_does_not_rebuild_an_unchanged_tenant_body(tmp_path):
    t = {"label": "acme", "counts": {"OK": 1}, "requests": 1, "seconds": 1.0, "endpoints": [{"endpoint": "/zia/c", "status": "OK", "http": 200}], "scope": _SCOPE}
    d = _render({"beacon": dict(_snap(t), running=True), "wait": 200}, tmp_path)
    assert d["writes"].get("bcTenantBody") == 1, d["writes"]
    assert (d["writes"].get("bcChanges") or 0) > 3, "the page did poll"
    # The disclosure sits beside the scope paragraph, never inside a <p>.
    assert "</p><details" in d["tenant"], d["tenant"]


def test_a_failed_watch_reads_as_failed_and_its_change_has_a_label(tmp_path):
    t = {"label": "acme", "endpoints": [], "counts": {}, "requests": 0, "stopped": "ConnectionError: boom", "failed": True, "scope": _SCOPE}
    d = _render({"beacon": _snap(t, [{"watcher": "tenant", "kind": "watch_failed", "text": "The tenant API watch of acme read nothing"}])}, tmp_path)
    assert "failed: read nothing" in d["tenant"] and " in  s" not in d["tenant"] and "Read only what is in scope" not in d["tenant"]
    assert 'chip warn">read nothing<' in d["changes"] and "watch_failed" not in d["changes"], d["changes"]


def test_a_preview_in_flight_is_not_asked_again_on_focus(tmp_path):
    d = _render({"store": {"zassess_scopes_live_v1": '{"scopes":["zdx"]}'}, "scopeDelay": 80, "focus": 4, "wait": 150}, tmp_path)
    assert len(d["posts"]) == 1, d["posts"]


# ── Release round 1: the watch reads no more than the assessment would ──

import channel_scope  # noqa: E402

_DECLARATIONS = (
    {}, {"genai_security": "gap"}, {"endpoint_dlp": "zscaler"}, {"email_dlp": "zscaler"},
    {"web_dlp": "gap", "ssl_inspection": "gap", "cloud_app_control": "gap"}, WEB_EMAIL,
    {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler", "genai_security": "zscaler"},
)


def _run_endpoints(scopes, channels):
    """The endpoints of the checks the assessment runs for this selection
    (channel_scope.partition, every channel not on Zscaler out)."""
    decl = bs.declaration(channels)
    rows = [r for r in bs.check_map() if r["scope"] in scopes]
    run, _, _ = channel_scope.partition([(r["id"], r["section"], "", r) for r in rows], decl)
    return set().union(*[set(chk[3]["endpoints"]) for chk in run]) if run else set()


@pytest.mark.parametrize("channels", _DECLARATIONS)
@pytest.mark.parametrize("scope", sorted(bs.SCOPE_REGISTRIES))
def test_the_watch_never_reads_what_the_assessment_leaves_out(scope, channels):
    sel = bs.select([scope], channels)
    on = set(bs.zscaler_channels(channels))
    for ep in sel["endpoints"]:
        chans = channel_scope.endpoint_channels(ep)
        assert not chans or set(chans) & on, f"{scope} {channels}: {ep} belongs to {chans}, none on Zscaler"
    assert set(sel["endpoints"]) <= _run_endpoints({scope}, channels), (scope, channels)


def test_genai_with_its_channel_a_gap_reads_nothing_as_the_assessment_runs_nothing():
    for ch in ({"genai_security": "gap"}, {"genai_security": "alternative"}):
        assert channel_scope.partition([(r["id"], r["section"], "") for r in bs.check_map() if r["scope"] == "genai"], ch)[0] == []
        assert bs.select(["genai"], ch)["endpoints"] == {}, ch


def test_the_probe_never_gets_an_unticked_channels_rules_even_from_a_stale_selection():
    sel, t, _ = _watch(["dlp"], {"email_dlp": "zscaler"})
    for ep in ("/zia/webDlpRules", "/zia/sslInspectionRules", "/zia/cloudApplicationRules", "/zia/tenancyRestrictionProfile"):
        assert ep not in sel["endpoints"] and ep in sel["not_in_scope"] and ep not in t.calls, ep
    assert "/zia/emailDlpRules" in t.calls
    # A selection that lists an unticked channel's endpoint anyway (drift, a
    # hand-built scope) is still refused at the client: the tenant is not read.
    forged = dict(sel, endpoints=dict(sel["endpoints"], **{"/zia/webDlpRules": ["x.py"]}))
    t2 = Recorder()
    beacon.run(online=False, upstream=lambda **k: {}, tenant_client=t2, tenant_scope=forged, save=False,
               probe=lambda c, endpoints: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None))
    assert t2.calls and "/zia/webDlpRules" not in t2.calls


def test_the_beacon_button_says_the_watch_reads_only_what_is_in_scope():
    import re
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "every endpoint the app uses" not in html
    tip = re.search(r'title="Watches the Zscaler Python SDK[^"]*"', html).group(0)
    assert "in scope on the Scope page" in tip and "GET only" in tip and "one request a second" in tip
