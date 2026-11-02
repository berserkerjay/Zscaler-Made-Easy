"""Cloud & Branch Connector (ztw_overview, /report/ztw, ZTW.1 to ZTW.8):
the connector read is read-only and only what the Scope page ticks, every
SDK service, method and path it uses exists in the installed SDK, secrets
and people never reach a result, each check says the right thing, the
assessment runs the checks only with Cloud & Branch Connector ticked, the
snapshot captures and masks the answers, and the page's link reuses the
read in the Path analyzer's workload trace.

Offline only: the sample tenant (offline_tenant) and in-memory fakes; no
network, no real tenant.
"""
from __future__ import annotations

import inspect
import io
import json
import os
import re
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

import offline_tenant as ot
import sample_tenant
import workload_path
import ztw_overview as zo

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
NOW = 1793000000.0     # 2026-10-26, after every sample time
# What must never leave the read: the sample's API key value, a VPN pre-shared
# key, admin e-mail addresses and names, and location IP addresses.
SECRETS = ("sample-placeholder-not-a-key", "sample-not-a-real-key", "it-admin@larkspur-freight.example", "cloud-ops@larkspur-freight.example",
           "Cloud Ops", "198.51.100.40", "203.0.113.20", "tacoma@larkspur-freight.example")
WRITE = re.compile(r"^(add|update|delete|regenerate|activate|change|generate|create)", re.I)


class Recorder:
    """client.ztw.<service>.<method> recorded; a write method fails the test."""

    def __init__(self, inner):
        self._inner, self.calls = inner, []

    @property
    def ztw(self):
        rec, ztw = self, self._inner.ztw

        class Svc:
            def __init__(self, name):
                self._name, self._svc = name, getattr(ztw, name)

            def __getattr__(self, attr):
                fn = getattr(self._svc, attr)
                if WRITE.match(attr):
                    raise AssertionError(f"write method called: {self._name}.{attr}")

                def call(*a, **k):
                    rec.calls.append(f"{self._name}.{attr}")
                    return fn(*a, **k)
                return call

        class Z:
            def __getattr__(self, name):
                return Svc(name)
        return Z()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def sample_sdk():
    return Recorder(ot.OfflineSdkClient(ot.sample_store(reset=True), CREDS))


def data(**over):
    """A healthy connector set-up as the checks take it; `over` replaces lists."""
    d = {"ec_groups": [{"id": 1, "name": "G1", "ecVMs": [{"name": "a", "buildVersion": "24.3", "operationalStatus": "ACTIVE"},
                                                          {"name": "b", "buildVersion": "24.3", "operationalStatus": "ACTIVE"}]}],
         "forwarding_rules": [{"id": 1, "name": "To ZIA", "order": 1, "state": "ENABLED", "forwardMethod": "ZIA"}],
         "forwarding_gateways": [{"id": 1, "name": "GW", "failClosed": True}],
         "activation": [{"orgEditStatus": "EDITS_CLEARED"}],
         "locations": [{"id": 1, "name": "L", "ofwEnabled": True, "ipsControl": True}],
         "location_templates": [{"id": 1, "name": "T", "template": {"ofwEnabled": True, "ipsControl": True}}],
         "admin_users": [{"role": "Super", "disabled": False}, {"role": "Audit", "disabled": False}],
         "admin_roles": [{"name": "Super", "policyAccess": "READ_WRITE"}, {"name": "Audit", "isAuditor": True}],
         "api_keys": [{"id": "k1", "enabled": True, "lastModifiedTime": NOW - 10 * 86400}]}
    d.update(over)
    return d


# ── the SDK ─────────────────────────────────────────────────────────────
def test_every_service_method_and_path_exists_in_the_installed_sdk():
    """ASVS V14.2.1 · CWE-1104 · WSTG-INFO-02: each ztw service, read method and path the page uses is in zscaler-sdk-python 1.11.3, and every method is a read."""
    from zscaler.ztw.ztw_service import ZTWService
    import zscaler.ztw as ztw_pkg
    for key, _label, svc, method, *one in zo.LISTS:
        prop = getattr(ZTWService, svc, None)
        assert isinstance(prop, property), svc
        cls = inspect.signature(prop.fget).return_annotation
        cls = getattr(__import__(prop.fget.__module__, fromlist=["x"]), cls) if isinstance(cls, str) else cls
        assert callable(getattr(cls, method, None)), (svc, method)
        assert re.match(r"^(list_|get_)", method) and not WRITE.match(method)
        src = inspect.getsource(getattr(cls, method))
        tail = zo.PATHS[key][len(zo.BASE):]
        assert tail in src, (key, tail)
        assert '"get".upper()' in src or "'get'.upper()" in src or 'http_method = "GET"' in src, (svc, method)
    assert os.path.isdir(os.path.dirname(ztw_pkg.__file__))
    # the provisioning URL service exists but is never called
    assert "provisioning_url" not in {svc for _k, _l, svc, *_r in zo.LISTS}


# ── the read ────────────────────────────────────────────────────────────
def test_the_sample_read_is_complete_read_only_and_keeps_no_secret_or_person():
    """ASVS V8.3.4 · CWE-200 · CWE-312 · WSTG-INFO-05: reading the sample tenant reads all 14 collections with list/get calls only and keeps no key value, pre-shared key, admin identity or location address."""
    sdk = sample_sdk()
    snap = zo.read(sdk, pace=0)
    assert all(v["read"] for v in snap["collections"].values()) and len(snap["collections"]) == 14
    assert sdk.calls and all(re.match(r"^\w+\.(list_|get_)", c) for c in sdk.calls)
    blob = json.dumps(snap)
    for s in SECRETS:
        assert s not in blob, s
    assert snap["api_keys"][0]["keyValue"] == zo.MASK
    assert snap["admin_users"] == [zo._admin_row(a) for a in sample_tenant.ZTW_ADMIN_USERS]
    assert snap["locations"][1]["vpnCredentialCount"] == 1 and snap["locations"][0]["ipAddressCount"] == 1


def test_switch_names_that_look_like_secrets_keep_their_value():
    """ASVS V8.3.4 · CWE-682: an admin's isPasswordLoginAllowed false is not turned into "(set)" by the secret masking, so password sign-in is counted right."""
    snap = zo.sanitize({"admin_users": [{"isPasswordLoginAllowed": False}, {"isPasswordLoginAllowed": True}]})
    assert [a["isPasswordLoginAllowed"] for a in snap["admin_users"]] == [False, True]


def test_a_provisioning_url_is_masked_in_a_read_and_in_a_snapshot():
    """ASVS V8.3.4 · CWE-522 · WSTG-INFO-05: a provisioning URL or a mobile app token list under any key spelling is masked by the page and by every snapshot."""
    body = {"provUrl": "https://connector.example/prov/abc", "provUrlData": {"x": 1}, "provisioningUrl": "https://x.example/p",
            "execMobileAppTokens": [{"token": "t-1"}], "name": "kept"}
    for out in (ot.scrub(body), zo._mask(body)):
        assert out["name"] == "kept"
        assert "https://" not in json.dumps(out) and "t-1" not in json.dumps(out)


def test_stop_before_the_read_reads_nothing():
    """ASVS V11.1.4 · CWE-400: Stop before the first call ends the read with nothing read."""
    sdk = sample_sdk()
    stop = threading.Event()
    stop.set()
    with pytest.raises(zo.Stopped):
        zo.read(sdk, cancel=stop, pace=0)
    assert sdk.calls == []


# ── the checks ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("fn", [f for _i, f, _k in zo.CHECKS])
def test_every_check_is_not_applicable_without_connectors(fn):
    """ASVS V1.14.6 · CWE-754: not licensed (groups unreadable) or not deployed (no group) is INFO, never a pass or a failure."""
    assert fn({"ec_groups": None})[0] == "INFO"
    assert fn({"ec_groups": []})[0] == "INFO"


def test_a_healthy_setup_passes_every_check():
    """ASVS V1.14.6 · CWE-697: the recommended configuration passes all eight checks."""
    res = zo.assess(data(), NOW)
    assert [f["status"] for f in res] == ["PASS"] * 8
    assert all(f["title"] and f["why"] and f["fix"] for f in res)


@pytest.mark.parametrize("over, cid, status, needle", [
    ({"ec_groups": [{"name": "G1", "ecVMs": [{"name": "a", "operationalStatus": "ACTIVE"}]}]}, "ZTW.1", "REVIEW", "G1"),
    ({"ec_groups": [{"name": "G1", "ecVMs": [{"name": "a", "operationalStatus": "ACTIVE"}, {"name": "b", "operationalStatus": "INACTIVE"}]}]}, "ZTW.2", "FAIL", "b (G1: INACTIVE)"),
    ({"ec_groups": [{"name": "G1", "ecVMs": [{"name": "a", "buildVersion": "1", "operationalStatus": "ACTIVE"}, {"name": "b", "buildVersion": "2", "operationalStatus": "ACTIVE"}]}]}, "ZTW.2", "REVIEW", "2 software versions"),
    ({"forwarding_rules": [{"name": "All out", "state": "ENABLED", "forwardMethod": "DIRECT"}]}, "ZTW.3", "FAIL", "All out"),
    ({"forwarding_rules": [{"name": "S3", "state": "ENABLED", "forwardMethod": "DIRECT", "destAddresses": ["52.218.128.0/17"]}]}, "ZTW.3", "REVIEW", "S3"),
    ({"forwarding_rules": [{"name": "Off", "state": "DISABLED", "forwardMethod": "DIRECT"}]}, "ZTW.3", "PASS", "None of the 0"),
    ({"forwarding_gateways": [{"name": "GW", "failClosed": False}]}, "ZTW.4", "REVIEW", "GW"),
    ({"activation": [{"orgEditStatus": "EDITS_PRESENT"}]}, "ZTW.5", "REVIEW", "waiting to be activated"),
    ({"activation": [{"orgEditStatus": "SOMETHING_NEW"}]}, "ZTW.5", "INFO", "not one this tool knows"),
    ({"locations": [{"name": "L", "ofwEnabled": True, "ipsControl": False}]}, "ZTW.6", "REVIEW", "location L (IPS off)"),
    ({"location_templates": [{"name": "T", "template": {"ofwEnabled": False, "ipsControl": True}}]}, "ZTW.6", "REVIEW", "template T (firewall off)"),
    ({"admin_users": [{"role": "Super", "disabled": False}]}, "ZTW.7", "REVIEW", "only 1 enabled admin"),
    ({"admin_roles": [{"name": "Super", "policyAccess": "READ_WRITE"}]}, "ZTW.7", "REVIEW", "no read-only or auditor role"),
    ({"api_keys": [{"id": "k1", "enabled": True, "lastModifiedTime": (NOW - 400 * 86400) * 1000}]}, "ZTW.8", "REVIEW", "k1 (400 days)"),
    ({"api_keys": [{"id": "k1", "enabled": False, "lastModifiedTime": 1}]}, "ZTW.8", "PASS", "No enabled"),
])
def test_each_check_names_the_gap(over, cid, status, needle):
    """ASVS V1.14.6 · CWE-697: each gap gives the right result and names the object, so the finding can be acted on."""
    f = next(x for x in zo.assess(data(**over), NOW) if x["id"] == cid)
    assert f["status"] == status and needle in f["detail"], f


def test_the_sample_tenant_has_a_gap_for_every_check():
    """ASVS V1.14.6 · CWE-1059: the sample tenant shows a finding for each of the eight checks, so every page part has something to show offline."""
    rep = zo.analyse(zo.read(sample_sdk(), pace=0), NOW)
    assert {f["id"]: f["status"] for f in rep["findings"]} == {f"ZTW.{n}": "REVIEW" for n in range(1, 9)}
    assert rep["counts"]["direct_rules"] == 1 and rep["counts"]["single_instance_groups"] == 1
    direct = next(r for r in rep["rules"] if r["forward_method"] == "DIRECT")
    assert direct["first_destination"] == "52.218.128.1" and direct["workload_groups"] == ["Backup agents"]


# ── the assessment ──────────────────────────────────────────────────────
def test_the_checks_run_only_with_cloud_and_branch_connector_ticked():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: the ZTW checks are selected only by the ztw Scope page key, never by another key or the legacy full scope."""
    import dlp_api_server as srv
    ids = lambda checks: {c[0] for c in checks if c[0].startswith("ZTW.")}
    assert ids(srv._get_checks(scopes=["ztw"])) == {f"ZTW.{n}" for n in range(1, 10)}   # ZTW.9: coverage checks (IP groups)
    for other in (["zia_extras", "zpa", "zcc", "rbac", "dlp"], None):
        assert ids(srv._get_checks("full", other)) == set()
    assert ids(srv._get_checks(scopes=["ztw"])) == {c["id"] for c in TestClient(srv.app).get("/api/checks?scope=ztw").json()}


def test_the_analysis_client_refuses_a_ztw_read_when_it_is_not_ticked():
    """ASVS V4.1.3 · CWE-284: the Scope page guard sends no ZTW request unless Cloud & Branch Connector is ticked."""
    import dlp_analysis

    class Raw:
        sent = []

        def get(self, ep, *a, **k):
            self.sent.append(ep)
            return [], 200
    raw = Raw()
    sc = dlp_analysis.ScopedClient(raw, {}, ["zia_extras"])
    body, code = sc.get(zo.PATHS["ec_groups"])
    assert code == 0 and raw.sent == []
    dlp_analysis.ScopedClient(raw, {}, ["ztw"]).get(zo.PATHS["ec_groups"])
    assert raw.sent == [zo.PATHS["ec_groups"]]


def test_the_assessment_checks_read_the_rest_paths_and_say_not_licensed_on_404():
    """ASVS V1.14.6 · CWE-754: through the assessment client the checks give the sample's findings, and a 404 on the groups is not applicable."""
    import zscaler_full_checks as fc
    raw = ot.OfflineRawClient(ot.sample_store(reset=True), CREDS)
    checks = [c for c in fc.PLATFORM_REG if c[0].startswith("ZTW.")]
    assert [c[1] for c in checks] == [zo.SECTION] * 9
    assert {c[3](raw).status for c in checks} == {"REVIEW"}

    class Missing:
        def get(self, ep, *a, **k):
            return {"message": "not found"}, 404
    r = checks[0][3](Missing())
    assert r.status == "INFO" and "not licensed" in r.detail


# ── the snapshot ────────────────────────────────────────────────────────
def test_a_snapshot_captures_the_connector_answers_only_when_ticked():
    """ASVS V4.1.3 · CWE-284 · CWE-312: the snapshot plan holds the 15 ZTW paths (14 for the page, the IP groups for ZTW.9) with ztw ticked and none without; captured answers carry no key value."""
    assert not [p for p in ot.capture_plan(["zia_extras", "zpa", "zcc", "rbac"]) if p.startswith("/ztw/")]
    plan = [p for p in ot.capture_plan(["ztw"]) if p.startswith("/ztw/")]
    assert sorted(plan) == sorted(list(zo.PATHS.values()) + ["/ztw/api/v1/ipGroups"])   # + the IP groups ZTW.9 reads (coverage checks)
    raw = ot.OfflineRawClient(ot.sample_store(reset=True), CREDS)
    out = ot.capture(raw, ["ztw"], {}, lambda m: None)
    assert len([p for p in out["responses"] if p.startswith("/ztw/")]) == len(plan) == 15
    doc = ot.build_snapshot(out["responses"], {"scopes": ["ztw"]})
    blob = json.dumps(doc)
    assert "sample-placeholder-not-a-key" not in blob and "sample-not-a-real-key" not in blob
    assert doc["meta"]["scopes"] == ["ztw"]


# ── the API ─────────────────────────────────────────────────────────────
class SyncJob:
    def __init__(self, kind, result):
        self.id, self.kind, self.status, self.result = "sync", kind, "done", result


@pytest.fixture
def api(tmp_path, monkeypatch):
    """An isolated app whose SDK client is the sample tenant and whose jobs run in the request."""
    import dlp_api_server as srv
    import pack_jobs
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(workload_path, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(srv, "_REPORTS", {})
    jobs = {}

    def start(kind, fn, **k):
        jobs["last"] = SyncJob(kind, fn(lambda line: None, threading.Event()))
        return jobs["last"]
    monkeypatch.setattr(pack_jobs, "start", start)
    state = {"sdk": sample_sdk(), "built": []}
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: state["built"].append("sdk") or state["sdk"])
    monkeypatch.setattr(srv, "_build_client", lambda req: state["built"].append("raw") or ot.OfflineRawClient(ot.sample_store(), CREDS))
    state["t"] = TestClient(srv.app)
    state["result"] = lambda: jobs["last"].result
    return state


@pytest.mark.parametrize("body", [{"scopes": [], "from_page": True}, {"scopes": ["zia_extras", "zpa", "zcc", "rbac"], "from_page": True}])
def test_refused_before_sign_in_when_not_ticked(api, body):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: without Cloud & Branch Connector ticked the read is a 400 and nothing is signed in to or read."""
    r = api["t"].post("/api/ztw/start", json=dict(CREDS, **body))
    assert r.status_code == 400 and "Cloud & Branch Connector" in r.json()["detail"] and "Nothing was read" in r.json()["detail"]
    assert api["built"] == [] and api["sdk"].calls == []


def test_the_classic_sign_in_is_refused_before_sign_in(api):
    """ASVS V4.1.3 · CWE-284: the classic ZIA API cannot read ZTW, so it is refused with the reason before any sign-in."""
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "k" * 12}
    r = api["t"].post("/api/ztw/start", json=dict(legacy, scopes=["ztw"], from_page=True))
    assert r.status_code == 400 and "OneAPI" in r.json()["detail"] and api["built"] == []
    assert "pw-pw-pw-pw" not in r.text


def _texts_of_workbook(blob: bytes) -> str:
    z = zipfile.ZipFile(io.BytesIO(blob))
    return "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())


def test_the_job_reads_assesses_and_exports_without_secrets(api):
    """ASVS V8.3.4 · CWE-200 · CWE-359 · WSTG-INFO-05: the job reads the sample read-only, keeps the report and the workload read, and neither the result nor the Excel or JSON export holds a key value, a person or an address."""
    r = api["t"].post("/api/ztw/start", json=dict(CREDS, scopes=["ztw"], from_page=True))
    assert r.status_code == 200 and r.json()["kind"] == "ztw", r.text
    res = api["result"]()
    assert res["status"] == "done" and res["report_id"].startswith("ztw-") and res["path_report_id"].startswith("pathztw-")
    assert res["counts"]["review"] == 8 and len(res["summary"]) >= 4
    t = api["t"]
    assert t.get(f"/api/ztw/report/{res['report_id']}").json()["findings"] == res["findings"]
    x = t.get(f"/api/ztw/report/{res['report_id']}/export?format=xlsx")
    j = t.get(f"/api/ztw/report/{res['report_id']}/export?format=json")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert j.status_code == 200 and json.loads(j.content)["counts"] == res["counts"]
    for blob in (json.dumps(res), _texts_of_workbook(x.content), j.text):
        for s in SECRETS + ("secret-secret-secret",):
            assert s not in blob, s
    assert t.get("/api/ztw/report/ztw-nope").status_code == 404
    assert t.get(f"/api/ztw/report/{res['report_id']}/export?format=csv").status_code == 400
    assert t.get(f"/api/browser-security/report/{res['report_id']}").status_code == 404


def test_the_page_link_reuses_the_read_in_the_workload_trace(api, monkeypatch):
    """ASVS V4.2.1 · CWE-639 · WSTG-BUSL-01: the Path analyzer's workload trace reuses the page's read for the same tenant (no second connector read) and follows the DIRECT rule the page names."""
    api["t"].post("/api/ztw/start", json=dict(CREDS, scopes=["ztw"], from_page=True))
    rid = api["result"]()["path_report_id"]
    monkeypatch.setattr(workload_path, "read", lambda *a, **k: (_ for _ in ()).throw(AssertionError("read again")))
    r = api["t"].post("/api/path-analyzer/start", json=dict(CREDS, from_page=True, scopes=["ztw"], destination="52.218.128.1", source="workload",
                                                           ztw_report_id=rid, workload={"ip": "10.20.0.5", "tags": "Role=backup", "connector_group": "Larkspur AWS us-west-2"}))
    assert r.status_code == 200, r.text
    res = api["result"]()
    assert res["ztw_report_id"] == rid
    assert "Backups direct to S3" in json.dumps(res) and res["verdict"]["outcome"] == "bypassed", res["verdict"]


def test_another_tenant_does_not_reuse_the_read(api):
    """ASVS V4.2.1 · CWE-639: a kept connector read is not served to another tenant's trace."""
    import dlp_api_server as srv
    api["t"].post("/api/ztw/start", json=dict(CREDS, scopes=["ztw"], from_page=True))
    rid = api["result"]()["path_report_id"]
    assert srv._path_kept(rid, "pathztw", dict(CREDS)) is not None
    assert srv._path_kept(rid, "pathztw", dict(CREDS, vanity_domain="other")) is None


# ── the page ────────────────────────────────────────────────────────────
def test_the_page_is_served_registered_and_escapes_tenant_text():
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-01 · WCAG 2.2 SC 4.1.2: the page is served, registered in help and the toolbar, every control has a help entry, and tenant text goes through the escaper."""
    import dlp_api_server as srv
    r = TestClient(srv.app).get("/report/ztw")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js", "help_catalog.js", "hover_help.js"):
        assert f"/static/{s}" in html
    assert "innerHTML = `" in html and "${E(" in html   # escaping proven in the browser test below
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    for sel in ("#ztTenant", "#ztRun", "#ztStop", "#expXlsx", "#expJson", "#ztBody .zt-filter button[data-st]", "#ztBody a.zt-trace"):
        assert json.dumps(sel)[1:-1] in cat, sel
    idx = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert 'onclick="openCloudConnectorTab()"' in idx and "window.open('/report/ztw'" in idx
    js = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    assert "'/report/ztw': 'ztw'" in js and "X.ztw = {" in js
    wn = open(os.path.join(ROOT, "static", "whats_new.js"), encoding="utf-8").read()
    assert '"id": "cloud-connector", "release": "2026-10-31"' in wn


def test_the_path_analyzer_takes_the_workload_from_the_link_but_only_a_kept_read_id():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the Path analyzer fills the connector group, workload group and IP from the link, and only an id shaped like a kept connector read is reused (the server still checks the tenant)."""
    html = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    assert "[['ec', 'paWlEc'], ['wlg', 'paWlGroup'], ['wlip', 'paWlIp']]" in html and ".slice(0, 200)" in html
    assert "/^pathztw-[A-Za-z0-9_-]{6,40}$/.test(q.get('ztw') || '')" in html
    # the form is filled, never started
    tail = html[html.index("[['ec', 'paWlEc']"):]
    assert "run()" not in tail.split("syncSource(); syncPortHint();")[0]


# ── the page in a browser (skipped without node and Chrome) ──────────────
HOSTILE = '<img src=x onerror="window.__pwned=1">'
DRIVER_TAIL = r"""
const [widthsJson, reportJson] = args;
const fake = `(() => {
  const rep = ${reportJson};
  const real = window.fetch.bind(window);
  window.fetch = (u, o) => {
    const url = String(u);
    const ok = b => Promise.resolve(new Response(JSON.stringify(b), { status: 200, headers: { 'Content-Type': 'application/json' } }));
    if (url.startsWith('/api/ztw/start')) return ok({ job_id: 'j1', status: 'running', kind: 'ztw' });
    if (url.startsWith('/api/dlp-packs/jobs/j1')) return ok({ status: 'done', next: 1, logs: ['Read 2 connector groups.'], result: rep });
    if (url.startsWith('/api/tenant-profiles')) return ok({ profiles: [] });
    return real(u, o);
  };
  try { localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['ztw'] })); } catch (e) {}
})();`;
await send('Page.addScriptToEvaluateOnNewDocument', { source: fake });
const out = {};
for (const width of JSON.parse(widthsJson)) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: false });
  await send('Page.navigate', { url: base + '/report/ztw' });
  await until(() => ev(`document.readyState === 'complete' && !!document.getElementById('ztRun')`), 'the page');
  await ev(`document.getElementById('ztRun').click(), 1`);
  await until(() => ev(`!document.getElementById('expXlsx').hidden`), 'the result', 30000);
  await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
  out[width] = await ev(`(() => {
    const W = document.documentElement.clientWidth;
    const links = [...document.querySelectorAll('#ztBody a.zt-trace')].map(a => a.getAttribute('href'));
    const filters = [...document.querySelectorAll('#ztBody .zt-filter button')].map(b => b.tabIndex);
    return { W, overflow: document.documentElement.scrollWidth - W, pwned: !!window.__pwned, imgs: document.querySelectorAll('#ztBody img').length,
             literal: document.getElementById('ztBody').textContent.includes('<img src=x'), links, filters,
             findings: document.querySelectorAll('#ztBody .pa-impacts > li').length,
             apiKeyShown: document.getElementById('ztBody').textContent.includes('sample-placeholder-not-a-key') };
  })()`);
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


@pytest.fixture(scope="module")
def ztw_browser(tmp_path_factory):
    from test_findings_reflow import CDP_PRELUDE, run_in_browser
    snap = zo.read(Recorder(ot.OfflineSdkClient(ot.sample_store(reset=True), CREDS)), pace=0)
    for key in ("ec_groups", "forwarding_rules", "forwarding_gateways", "locations"):
        snap[key][0]["name"] = HOSTILE + " " + snap[key][0]["name"]
    rep = zo.analyse(snap, NOW)
    rep.update(summary=zo.summary_lines(rep), report_id="ztw-test", path_report_id="pathztw-abcdefgh", tenant_label=HOSTILE, status="done")
    out = run_in_browser(tmp_path_factory.mktemp("ztw"), CDP_PRELUDE + DRIVER_TAIL, json.dumps([320, 1280]), json.dumps(rep))
    return {int(k): v for k, v in out.items()}


@pytest.mark.parametrize("width", [320, 1280])
def test_the_page_renders_tenant_text_inert_and_never_scrolls_sideways(ztw_browser, width):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01 · WCAG 2.2 SC 1.4.10: hostile names in the connector configuration show as text, never markup, and at 320px nothing scrolls sideways."""
    m = ztw_browser[width]
    assert m["pwned"] is False and m["imgs"] == 0 and m["literal"] is True, m
    assert m["overflow"] <= 0, m
    assert m["findings"] == 8 and m["apiKeyShown"] is False


def test_the_page_links_into_the_workload_trace_and_its_filters_are_keyboard_reachable(ztw_browser):
    """ASVS V5.1.3 · CWE-601 · WCAG 2.2 SC 2.1.1: every trace link stays on this app's Path analyzer with the kept read, and the filters are keyboard reachable."""
    m = ztw_browser[1280]
    assert m["links"] and all(h.startswith("/report/path?src=workload") and "ztw=pathztw-abcdefgh" in h for h in m["links"]), m["links"]
    assert m["filters"] and all(t >= 0 for t in m["filters"])
