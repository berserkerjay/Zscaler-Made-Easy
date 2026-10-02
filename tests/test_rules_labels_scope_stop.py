"""User rules on the server's tenant reads, labels and Terraform workspaces.

- Rule 3: a classic-API tenant is never named by its admin login or by a
  vanity domain left in the form, in a label, a kept Beacon snapshot, a
  Path analyzer / Data Flow / Bypass / SSL flow report or an export.
  Beacon history written before keeps no login either, and still finds
  its baseline.
- Rule 1: the Data Flow Map, the FP/TP Detection Ratio and the live feed
  read only what is in scope on the Scope page, and refuse before signing
  in when nothing they read is.
- Rule 4: Stop ends the Beacon tenant watch, and the plan read of a
  Terraform gap hand-off, a deployment and a removal: nothing more is
  read after Stop.
- Rule 2: a Terraform workspace written without an assessor's name (an
  upload, a rebuild, the committed terraform/<pack>/) never tags what it
  pushes with "DLP-Check": the required `assessor` variable names it.

Fakes only: no real tenant is contacted.
"""
from __future__ import annotations

import glob
import json
import os
import threading
import time

import pytest
from fastapi.testclient import TestClient

import beacon
import beacon_scope as bs
import data_flow as df
import dlp_api_server as srv
import tenant_auth

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGIN = "secret.admin@acme.com"
STALE = "stalevanity"
LEG = {"auth_method": "legacy", "cloud": "zscalerten", "username": LOGIN, "password": "Passw0rd-long-enough",
       "api_key": "abcdefABCDEF", "vanity_domain": STALE}
CLASSIC = "classic API (zscalerten)"
WEB_SCOPE = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler"}, "from_page": True}


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_BEACON_STATE", str(tmp_path / "beacon_state.json"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    srv._live_rules_cache.clear()
    yield


def _no_secret(text: str) -> None:
    assert LOGIN not in text, "the classic API's admin login is named"
    assert STALE not in text, "a stale vanity domain names a classic-API tenant"


# ── Rule 3: labels ─────────────────────────────────────────────────────

def test_a_label_never_names_the_classic_login():
    assert tenant_auth.label(LEG) == CLASSIC == tenant_auth.record_label(LEG)
    assert LOGIN not in tenant_auth.identity(LEG)
    old = f"The tenant API watch of {LOGIN} (zscalerten, classic API) read nothing."
    assert tenant_auth.scrub_classic_login(old) == f"The tenant API watch of {CLASSIC} read nothing."
    assert tenant_auth.scrub_classic_login("acme (zscalerten)") == "acme (zscalerten)"


class Recorder:
    """A Beacon tenant that answers every GET and records it. `hold` blocks
    the first GET until it is set (a test presses Stop meanwhile)."""

    def __init__(self, legacy=False, hold=None):
        self.legacy, self.customer_id = legacy, "7"
        self.calls = []
        self.hold = hold
        self.entered = threading.Event()
        self.closed = False

    def get(self, ep, p=None):
        self.calls.append(ep)
        if self.hold is not None and len(self.calls) == 1:
            self.entered.set()
            self.hold.wait(10)
        return [{"id": 1}], 200

    def post(self, *a, **k):
        raise AssertionError("the tenant watch must never write")

    put = delete = patch = post

    def close(self):
        self.closed = True


def _beacon_server(monkeypatch, tenant):
    real = beacon.run

    def run(online=True, tenant_client=None, tenant_label="", trigger="manual", tenant_scope=None, stop=None, **kw):
        return real(online=False, upstream=lambda **k: {}, tenant_client=tenant_client, tenant_label=tenant_label, trigger=trigger,
                    tenant_scope=tenant_scope, stop=stop,
                    probe=lambda c, endpoints, **k: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None, **k))
    monkeypatch.setattr(beacon, "run", run)
    monkeypatch.setattr(srv, "_build_client", lambda req: tenant)
    return TestClient(srv.app)


def _wait_idle(c, timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        d = c.get("/api/beacon").json()
        if not d["running"]:
            return d
        time.sleep(0.05)
    pytest.fail("the Beacon run did not finish")


def test_the_beacon_watch_never_keeps_the_classic_login(monkeypatch, tmp_path):
    tenant = Recorder(legacy=True)
    c = _beacon_server(monkeypatch, tenant)
    r = c.post("/api/beacon/run", json=dict(LEG, online=False, tenant_watch=True, scopes=["dlp"], channels={"web_dlp": "zscaler"}))
    assert r.status_code == 200, r.text
    assert r.json()["tenant"] == CLASSIC
    d = _wait_idle(c)
    assert tenant.calls, "the watch read the tenant"
    assert d["latest"]["tenant"]["label"] == CLASSIC and d["history"][0]["tenant"] == CLASSIC
    _no_secret(json.dumps(d))
    _no_secret((tmp_path / "beacon_state.json").read_text(encoding="utf-8"))


def test_beacon_history_written_with_the_login_is_scrubbed_and_stays_the_baseline(tmp_path):
    path = str(tmp_path / "beacon_state.json")
    sel = bs.select(["dlp"], {"web_dlp": "zscaler"})
    first = beacon.run(online=False, upstream=lambda **k: {}, tenant_client=Recorder(legacy=True), tenant_label=CLASSIC,
                       tenant_scope=sel, path=path, save=False,
                       probe=lambda c, endpoints, **k: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None))
    # As an older version kept it: the label named the admin login, and one endpoint answered 403.
    old_label = f"{LOGIN} (zscalerten, classic API)"
    first["tenant"]["label"] = old_label
    next(e for e in first["tenant"]["endpoints"] if e["status"] == "OK").update(status="403", http=403, items=None)
    first["diff"] = {"summary": [f"The tenant API watch of {old_label} ran."], "changes": []}
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "snapshots": [first]}, f)
    hist = beacon.load_history(path)
    assert hist[0]["tenant"]["label"] == CLASSIC
    _no_secret(json.dumps(hist))
    _no_secret(open(path, encoding="utf-8").read())   # rewritten on disk too
    second = beacon.run(online=False, upstream=lambda **k: {}, tenant_client=Recorder(legacy=True), tenant_label=CLASSIC,
                        tenant_scope=sel, path=path,
                        probe=lambda c, endpoints, **k: beacon.probe_tenant(c, endpoints=endpoints, sleep=lambda s: None))
    kinds = [ch.get("kind") for ch in second["diff"]["changes"]]
    assert "endpoint_status" in kinds, ("the watch kept before is still this tenant's baseline", second["diff"])


def test_the_path_analyzer_report_never_names_the_classic_login(monkeypatch):
    from test_path_scope_stop import Tenant
    monkeypatch.setattr(srv, "_build_client", lambda req: Tenant())
    t = TestClient(srv.app)
    r = t.post("/api/path-analyzer", json=dict(LEG, destination="chat.openai.com", **WEB_SCOPE))
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["tenant_label"] == CLASSIC and srv._REPORTS[res["report_id"]]["tenant_label"] == CLASSIC
    _no_secret(r.text)
    _no_secret(t.get(f"/api/report/data-flow/export/{res['report_id']}?format=json").text)


@pytest.mark.parametrize("ep", ["/api/report/data-flow", "/api/report/bypass", "/api/report/ssl-flow"])
def test_reports_name_a_classic_tenant_by_neither_login_nor_stale_vanity(monkeypatch, ep):
    from test_path_scope_stop import Tenant
    monkeypatch.setattr(srv, "_build_client", lambda req: Tenant())
    t = TestClient(srv.app)
    r = t.post(ep, json=dict(LEG, **WEB_SCOPE))
    assert r.status_code == 200, r.text[:300]
    assert r.json()["tenant_label"] == CLASSIC
    rid = r.json()["report_id"]
    assert srv._REPORTS[rid]["tenant_label"] == CLASSIC
    _no_secret(json.dumps(srv._REPORTS[rid], default=str))


def test_the_sign_in_check_and_the_live_feed_never_name_the_classic_login(monkeypatch):
    from test_detection_health import _client
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _client([]))
    monkeypatch.setattr(srv, "_close_quietly", lambda client: None)
    t = TestClient(srv.app)
    r = t.post("/api/tenant/check", json=LEG)
    assert r.status_code == 200 and r.json()["tenant_label"] == CLASSIC, r.text
    _no_secret(r.text)
    r = t.post("/api/live-feed", json=dict(LEG, scopes=["dlp"], channels={"web_dlp": "zscaler", "workflow_automation": "zscaler"}))
    assert r.status_code == 200 and r.json()["tenant_label"] == CLASSIC, r.text
    _no_secret(r.text)
    assert all(LOGIN not in k and STALE not in k for k in srv._live_rules_cache), "the rule cache key names no classic tenant"


# ── Rule 1: only what is in scope is read ───────────────────────────

def test_the_data_flow_map_reads_only_what_is_in_scope(monkeypatch):
    from test_path_scope_stop import Tenant
    built = []
    tenant = Tenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or tenant)
    t = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    # Nothing in scope: refused before signing in, nothing read.
    for body in (creds, dict(creds, scopes=[], channels={}, from_page=True), dict(creds, scopes=["zpa"], from_page=True)):
        r = t.post("/api/report/data-flow", json=body)
        assert r.status_code == 400 and r.json()["detail"] == df.MAP_NOTHING_IN_SCOPE, r.text
    assert not built and not tenant.requests
    r = t.post("/api/report/data-flow", json=dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler"}, from_page=True))
    assert r.status_code == 200, r.text
    gets = set(tenant.gets())
    for ep in ("/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/trustedNetworks", "/zia/pacFiles", "/zia/sslInspectionRules",
               "/zia/cloudApplicationRules", "/zia/endPointDlpRules", "/zia/casbDlpRules/all", "/zia/emailDlpRules"):
        assert ep not in gets, f"{ep} is not in scope and was read"
    assert "/zia/webDlpRules" in gets
    rep = r.json()
    assert rep["path_scope"] == df.path_scope(["dlp"], {"web_dlp": "zscaler"})["key"] and rep["scope"]["source"] == "the Scope page"
    hops = {h["key"]: h["status"] for h in rep["traces"][0]["hops"]}
    assert hops.get("zcc") == "out_of_scope" and hops.get("ssl") == "out_of_scope", hops
    # A destination typed on the tab is traced from the kept read with the same scope.
    tr = t.post(f"/api/report/data-flow/{rep['report_id']}/trace", json={"destination": "webmail", "network": "off", "platform": "windows"}).json()
    assert {h["key"]: h["status"] for h in tr["hops"]}.get("zcc") == "out_of_scope"


def test_the_index_page_sends_the_scope_page_selection_and_only_the_chosen_sign_in():
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert "...scopePageSelection(), platform" in html and "...scopePageSelection(), days" in html
    assert "vanity_domain: only('vd', false)" in html and "username: only('zuser', true)" in html
    live = open(os.path.join(ROOT, "static", "report_live.html"), encoding="utf-8").read()
    assert "scopeSelection(), { since, stats }" in live


def _dh(monkeypatch):
    import detection_health
    calls, built = [], []

    def generate(client, **kw):
        calls.append(kw)
        return {"findings": [], "rules": [], "summary": {}, "errors": [], "read": {"incidents": kw.get("read_incidents", True), "rules": True}}
    monkeypatch.setattr(detection_health, "generate", generate)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or object())
    return TestClient(srv.app), calls, built


def test_the_fp_tp_ratio_reads_only_the_channels_and_incidents_in_scope(monkeypatch):
    t, calls, built = _dh(monkeypatch)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    for body, why in ((creds, "nothing in scope"), (dict(creds, scopes=["dlp"], from_page=True), "no DLP channel on Zscaler"),
                      (dict(creds, scopes=["zcc"], channels={"web_dlp": "zscaler"}), "DLP not ticked")):
        r = t.post("/api/detection-health", json=body)
        assert r.status_code == 400 and r.json()["detail"] == srv.DH_NOTHING_IN_SCOPE, (why, r.text)
    r = t.post("/api/detection-health", json=dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "workflow_automation": "alternative"}))
    assert r.status_code == 400 and r.json()["detail"] == srv.DH_WA_ALTERNATIVE
    assert not built and not calls, "refused before signing in"
    r = t.post("/api/detection-health", json=dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "endpoint_dlp": "alternative"}))
    assert r.status_code == 200, r.text
    assert calls[-1]["channels"] == ["web"] and calls[-1]["read_incidents"] is False, calls[-1]
    r = t.post("/api/detection-health", json=dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "email_dlp": "zscaler",
                                                                                     "workflow_automation": "zscaler"}))
    assert r.status_code == 200 and sorted(calls[-1]["channels"]) == ["email", "web"] and calls[-1]["read_incidents"] is True


def test_the_fp_tp_ratio_uses_the_profile_scope_when_the_page_sent_none(monkeypatch):
    import tenant_profiles
    t, calls, built = _dh(monkeypatch)
    monkeypatch.setattr(tenant_profiles, "get", lambda pid, **kw: {"id": pid, "name": "Acme", "scopes": ["dlp"],
                                                                    "channels": {"endpoint_dlp": "zscaler"}} if pid == "p1" else None)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "profile_id": "p1"}
    r = t.post("/api/detection-health", json=creds)
    assert r.status_code == 200, r.text
    assert calls[-1]["channels"] == ["endpoint"]
    # The page's selection (nothing) is never widened by the profile.
    r = t.post("/api/detection-health", json=dict(creds, scopes=[], channels={}, from_page=True))
    assert r.status_code == 400


def test_the_live_feed_reads_only_what_is_in_scope(monkeypatch):
    import detection_health
    import pack_removal
    from test_detection_health import _client
    inv, polls, built = [], [], []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or _client([]))
    monkeypatch.setattr(pack_removal, "inventory", lambda client, channels=None: inv.append(channels) or {"rules": []})
    real_poll = detection_health.poll_incidents
    monkeypatch.setattr(detection_health, "poll_incidents", lambda *a, **k: polls.append(1) or real_poll(*a, **k))
    t = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    for body in (creds, dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler"}),
                 dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "workflow_automation": "alternative"}),
                 dict(creds, scopes=["zcc"], channels={"workflow_automation": "zscaler"})):
        r = t.post("/api/live-feed", json=body)
        assert r.status_code == 400 and r.json()["detail"] == srv.LIVE_NOTHING_IN_SCOPE, r.text
    assert not built and not polls and not inv, "refused before signing in"
    r = t.post("/api/live-feed", json=dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "workflow_automation": "zscaler",
                                                                             "endpoint_dlp": "alternative"}))
    assert r.status_code == 200, r.text
    assert inv == [["web"]], inv
    # No DLP channel on Zscaler: the incidents are read, no rule inventory is.
    srv._live_rules_cache.clear()
    r = t.post("/api/live-feed", json=dict(creds, scopes=["dlp"], channels={"workflow_automation": "zscaler"}))
    assert r.status_code == 200 and inv == [["web"]]


# ── Rule 4: Stop ─────────────────────────────────────────────────────

def test_stop_ends_the_beacon_tenant_watch(monkeypatch):
    hold = threading.Event()
    tenant = Recorder(hold=hold)
    c = _beacon_server(monkeypatch, tenant)
    sel = bs.select(["zdx"], {})
    assert len(sel["endpoints"]) > 2
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "scopes": ["zdx"], "channels": {},
                                        "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"})
    assert r.status_code == 200, r.text
    assert tenant.entered.wait(10)
    s = c.post("/api/beacon/stop")
    assert s.status_code == 200 and s.json()["stopping"] is True
    hold.set()
    d = _wait_idle(c)
    assert len(tenant.calls) == 1, f"{len(tenant.calls) - 1} reads after Stop"
    t = d["latest"]["tenant"]
    assert t["stopped"] == beacon.STOPPED_BY_OPERATOR
    assert sum(1 for e in t["endpoints"] if e["status"] == "not probed") == len(sel["endpoints"]) - 1
    assert d["timer"]["last_status"] == "partial"
    # Nothing running: Stop says so and changes nothing.
    assert c.post("/api/beacon/stop").json() == {"stopping": False, "running": False}
    page = open(os.path.join(ROOT, "static", "report_beacon.html"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "beacon.js"), encoding="utf-8").read()
    assert 'id="bcStop"' in page and "/api/beacon/stop" in js


def test_a_stop_hook_ends_the_probe_between_endpoints():
    tenant = Recorder()
    eps = bs.select(["zdx"], {})["endpoints"]
    out = beacon.probe_tenant(tenant, endpoints=eps, sleep=lambda s: None, stop=lambda: len(tenant.calls) >= 2)
    assert len(tenant.calls) == 2 and out["stopped"] == beacon.STOPPED_BY_OPERATOR
    assert [e["status"] for e in out["endpoints"]].count("not probed") == len(eps) - 2


class _Counting:
    """A fake SDK client that counts every service call; the first call
    blocks until `gate` is set (Stop is pressed meanwhile)."""

    def __init__(self, inner, gate, entered):
        self._inner, self.calls, self._gate, self._entered = inner, [], gate, entered
        outer = self

        class _Z:
            def __getattr__(zs, svc_name):
                svc = getattr(inner.zia, svc_name)

                class _S:
                    def __getattr__(ss, m):
                        f = getattr(svc, m)
                        if not callable(f):
                            return f

                        def wrapped(*a, **k):
                            outer.calls.append(f"{svc_name}.{m}")
                            if len(outer.calls) == 1:
                                outer._entered.set()
                                outer._gate.wait(10)
                            return f(*a, **k)
                        return wrapped
                return _S()
        self.zia = _Z()

    def __getattr__(self, n):
        return getattr(self._inner, n)


def _wait_job(t, job):
    end = time.time() + 30
    while time.time() < end:
        s = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if s["status"] != "running":
            return s
        time.sleep(0.05)
    pytest.fail("job did not finish")


ONEAPI = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


@pytest.mark.parametrize("kind", ["terraform", "deploy", "removal"])
def test_stop_during_the_plan_read_reads_nothing_more(monkeypatch, kind):
    from test_channel_targets_undo import _with_delete
    from test_pack_channels import TENANTS, add_control_services, make_client
    gate, entered = threading.Event(), threading.Event()
    gate.set()
    client = _Counting(_with_delete(add_control_services(make_client(casb_tenants=TENANTS))), gate, entered)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: client)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    t = TestClient(srv.app)
    body = dict(ONEAPI, pack_ids=["healthcare_phi_baseline"], assessor="Jane Doe")
    if kind == "removal":
        ph = t.post("/api/dlp-packs/preflight", json=body).json()["plan_hash"]
        done = _wait_job(t, t.post("/api/dlp-packs/apply/start", json=dict(body, plan_hash=ph, confirm=True)).json()["job_id"])
        assert done["status"] == "done", done
        ph = t.post("/api/dlp-packs/removal/preflight", json=dict(ONEAPI, pack_ids=["healthcare_phi_baseline"])).json()["plan_hash"]
    elif kind == "deploy":
        ph = t.post("/api/dlp-packs/preflight", json=body).json()["plan_hash"]
    client.calls.clear()
    gate.clear()
    entered.clear()
    if kind == "terraform":
        r = t.post("/api/dlp-packs/terraform/start", json=dict(body, mode="gap"))
    elif kind == "deploy":
        r = t.post("/api/dlp-packs/apply/start", json=dict(body, plan_hash=ph, confirm=True))
    else:
        r = t.post("/api/dlp-packs/removal/apply/start", json=dict(ONEAPI, pack_ids=["healthcare_phi_baseline"], plan_hash=ph, confirm=True))
    assert r.status_code == 200, r.text[:300]
    job = r.json()["job_id"]
    assert entered.wait(10)
    t.post(f"/api/dlp-packs/jobs/{job}/cancel")
    n = len(client.calls)
    gate.set()
    s = _wait_job(t, job)
    after = client.calls[n:]
    assert after == [], f"{len(after)} tenant calls after Stop: {after[:8]}"
    res = s.get("result") or {}
    assert s["status"] in ("cancelled", "done") and (res.get("status") == "stopped" or s["status"] == "cancelled"), (s["status"], res.get("status"))


# ── Rule 2: Terraform workspaces never tag what they push "DLP-Check" ─────

def test_a_workspace_without_an_assessor_requires_one_and_never_says_dlp_check():
    import pack_terraform as pt
    from dlp_importer import discover_packs
    p = next(x for x in discover_packs() if x["id"] == "cjis_policy_pack")
    files = pt.generate({"id": p["id"], "dir": p["dir"]})
    tf = "".join(v for k, v in files.items() if k.endswith(".tf"))
    assert "[DLP-Check pack" not in tf and "[DLP-Check baseline" not in tf
    assert "[${var.assessor} pack cjis_policy_pack" in tf and 'variable "assessor"' in files["variables.tf"]
    assert "default" not in files["variables.tf"].split('variable "assessor"')[1].split("\n}\n")[0], "no default: apply needs a name"
    named = pt.generate({"id": p["id"], "dir": p["dir"]}, assessor="Jane Doe")
    assert 'variable "assessor"' not in named["variables.tf"], "a named workspace asks for nothing more"
    assert "[Jane Doe pack cjis_policy_pack" in named["dictionaries.tf"]


def test_the_committed_workspaces_never_tag_objects_dlp_check():
    folders = [d for d in glob.glob(os.path.join(ROOT, "terraform", "*")) if os.path.isdir(d)]
    assert folders
    for d in folders:
        for f in glob.glob(os.path.join(d, "*.tf")):
            text = open(f, encoding="utf-8").read()
            assert "[DLP-Check pack" not in text and "[DLP-Check baseline" not in text, f
        assert 'variable "assessor"' in open(os.path.join(d, "variables.tf"), encoding="utf-8").read(), d


def test_the_committed_workspaces_say_to_name_the_assessor_before_apply():
    # TD1-2: the READMEs of the committed workspaces tell the reader to
    # apply them, so their Use section names the required assessor.
    folders = [d for d in glob.glob(os.path.join(ROOT, "terraform", "*")) if os.path.isdir(d)]
    assert folders
    for d in folders:
        readme = open(os.path.join(d, "README.md"), encoding="utf-8").read()
        use = readme.split("## Use", 1)[1].split("\n## ", 1)[0]
        assert "assessor" in use and "-var" in use, d
    docs = open(os.path.join(ROOT, "POLICY_PACKS.md"), encoding="utf-8").read()
    section = docs.split("**Committed workspaces.**", 1)[1].split("**Gap mode", 1)[0]
    assert "assessor" in section and "--assessor" in section


def test_the_terraform_cli_names_the_assessor_or_leaves_it_to_apply(tmp_path):
    import pack_terraform as pt
    pt.main(["cjis_policy_pack", "--out", str(tmp_path / "a"), "--assessor", "Jane Doe"])
    rules = (tmp_path / "a" / "cjis_policy_pack" / "rules.tf").read_text(encoding="utf-8")
    assert "[Jane Doe pack cjis_policy_pack" in rules and "DLP-Check pack" not in rules
    pt.main(["cjis_policy_pack", "--out", str(tmp_path / "b")])
    rules = (tmp_path / "b" / "cjis_policy_pack" / "rules.tf").read_text(encoding="utf-8")
    assert "[${var.assessor} pack cjis_policy_pack" in rules and "DLP-Check pack" not in rules
    with pytest.raises(SystemExit):
        pt.main(["cjis_policy_pack", "--out", str(tmp_path / "c"), "--assessor", "DLP-Check"])


def test_a_snapshot_is_kept_when_a_poll_holds_the_history_file_open(monkeypatch, tmp_path):
    # Windows refuses the move while GET /api/beacon reads the file: the save retries
    # instead of losing the run's snapshot (the Beacon tab then showed no result).
    import os as _os
    real, calls = _os.replace, []

    def flaky(src, dst):
        calls.append(dst)
        if len(calls) == 1:
            raise PermissionError(13, "The process cannot access the file because it is being used by another process")
        return real(src, dst)
    monkeypatch.setattr(beacon.os, "replace", flaky)
    monkeypatch.setattr(beacon.time, "sleep", lambda s: None)
    p = str(tmp_path / "beacon_state.json")
    beacon.save_history([{"at": "x"}], p)
    assert len(calls) == 2 and beacon.load_history(p)[-1]["at"] == "x"
