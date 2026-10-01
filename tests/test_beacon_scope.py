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
ALL = beacon.tenant_endpoints()
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
    assert m["unmapped"] == ["/zia/fileTypeRules"], "only data_flow.py reads it; no check does"
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
    assert sel["channels"] == ["web_dlp", "email_dlp"]
    assert sel["summary"] == f"{len(sel['endpoints'])} endpoints for DLP (Web, Email)"
    # A channel alone, without its scope ticked, reads nothing.
    assert bs.select([], WEB_EMAIL)["endpoints"] == {}


def test_a_channel_widens_only_its_own_checks():
    base = set(bs.select(["dlp"], {})["endpoints"])
    assert "/zia/dlpDictionaries" in base and "/zia/webDlpRules" in base, "the general DLP section reads them without a channel"
    assert set(bs.select(["dlp"], {"genai_security": "zscaler"})["endpoints"]) - base == {"/zia/urlCategories"}
    platform = set(bs.select(["zia_extras"], {})["endpoints"])
    cac = set(bs.select(["zia_extras"], {"cloud_app_control": "zscaler"})["endpoints"])
    assert "/zia/advancedSettings" in cac - platform and "/zia/advancedSettings" not in base
    assert bs.select(["genai"], {})["endpoints"] == {}, "every GenAI check belongs to the GenAI Security channel"
    assert "/zia/urlCategories" in bs.select(["genai"], {"genai_security": "zscaler"})["endpoints"]


def test_summary_names_scopes_and_zscaler_channels():
    sel = bs.select(["dlp", "zcc"], WEB_EMAIL)
    assert sel["summary"].endswith("endpoints for DLP (Web, Email), ZCC")
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
    assert ts["unmapped"] == ["/zia/fileTypeRules"] and set(ts["not_in_scope"]) | set(ts["read"]) | set(ts["unmapped"]) == set(ALL)


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
    assert d["ok"] is True and d["summary"].endswith("endpoints for DLP (Web, Email), ZCC") and d["endpoints"] == len(d["read"])
    assert "/zia/fileTypeRules" in d["unmapped"]
    d = c.post("/api/beacon/scope", json={}).json()
    assert d["ok"] is False and d["detail"] == "Nothing is in scope — choose what to assess on the Scope page."
    assert built == [] and tenant.calls == []


def test_beacon_js_sends_the_scope_page_selection():
    js = open(os.path.join(ROOT, "static", "beacon.js"), encoding="utf-8").read()
    assert "'zscaler_assessment_config'" in js and "'zassess_channels_v1'" in js and "zassess_channels_v1_extra" in js
    assert "getSelectedScopes" in js and "__dbChannelScope" in js, "the open assessment tab's live selection first"
    assert "scopes: sc.scopes, channels: sc.channels" in js, "the run body carries the selection"
    assert "'/api/beacon/scope'" in js and "id=\"bcScope\"" in open(os.path.join(ROOT, "static", "report_beacon.html"), encoding="utf-8").read()


def test_the_page_says_it_reads_only_what_is_in_scope():
    html = open(os.path.join(ROOT, "static", "report_beacon.html"), encoding="utf-8").read()
    assert "in scope on the Scope page" in html and "reads every endpoint the app" not in html.lower()
    ex = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    entry = ex[ex.index("X.beacon = {"):ex.index("X.logs = {")]
    assert "in scope on the Scope page" in entry and "every endpoint the app uses" not in entry
