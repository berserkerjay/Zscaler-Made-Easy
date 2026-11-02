"""The sample tenant and offline snapshots (offline_tenant.py, sample_tenant.py).

The sample tenant and a snapshot are served by clients with no network code,
handed out by the app's own client factories for offline credentials; the
browser's choice is a cookie; snapshots are scoped, credential-free,
owner-only files kept beside the tenant profiles; an opened snapshot file is
untrusted input. Every test uses fakes: no network, no real tenant."""
import ast
import json
import os
import socket
import stat
import threading
import types

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import offline_tenant as ot
import sample_tenant

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY_SECRET = "CANARYofflineSecret+/=9Qx"
CANARY_FIELD = "CANARYzccExitPass0042"
LIVE = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclientid0001", "client_secret": CANARY_SECRET,
        "customer_id": "7210000000000"}
ALL_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]
CHANNELS = {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                   "ssl_inspection", "cloud_app_control")}
SCOPE = {"scopes": ALL_SCOPES, "channels": CHANNELS, "from_page": True}


class SyncJob:
    def __init__(self, kind, result=None, error=""):
        self.id, self.kind, self.result, self.error = "sync-job", kind, result, error
        self.status = "failed" if error else "done"


JOBS = []


def _sync_start(kind, fn, **_k):
    """pack_jobs.start, run inside the request: no thread, sleep or poll."""
    try:
        job = SyncJob(kind, fn(lambda line: None, threading.Event()))
    except Exception as e:  # noqa: BLE001
        job = SyncJob(kind, None, f"{type(e).__name__}: {e}")
    JOBS.append(job)
    return job


@pytest.fixture
def app(tmp_path, monkeypatch):
    """An isolated app: state files in tmp_path, no environment tenant, no
    network (any socket use fails the test), jobs run in the request."""
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)

    def no_network(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    import pack_jobs
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    monkeypatch.setattr(srv, "_REPORTS", {})
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    return TestClient(srv.app, base_url="http://127.0.0.1")


def _sample(client):
    r = client.post("/api/offline/sample", json={})
    assert r.status_code == 200
    return r


def _live_store():
    """A 'live tenant' for the save tests: the sample's answers plus a
    Client Connector profile whose exit password is a canary."""
    resp = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()}
    prof = resp["/zcc/papi/public/v1/application-profiles"]["body"]["policies"]
    prof[0]["policyExtension"] = {"exitPass": CANARY_FIELD, "logoutPassword": CANARY_FIELD}
    prof[0]["uninstallPassword"] = CANARY_FIELD
    return ot.OfflineStore("snap-" + "0" * 16, "snapshot", resp, {"tenant_label": "acme (zscalerten)"})


# ── no network code; the factories hand out the offline clients ──────────

NETWORK_PACKAGES = {"socket", "requests", "httpx", "aiohttp", "urllib3", "ssl", "asyncio"}
NETWORK_MODULES = {"urllib.request", "http.client"}


@pytest.mark.parametrize("module", ["offline_tenant.py", "sample_tenant.py"])
def test_the_offline_modules_import_no_network_library(module):
    """ASVS V1.14.1 · CWE-653 · SSDF PW.5.1: the sample and snapshot clients have no network code at all (no socket or HTTP import)."""
    # Arrange
    tree = ast.parse(open(os.path.join(ROOT, module), encoding="utf-8").read())
    # Act
    names = {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    names |= {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    # Assert
    assert not {m for m in names if m.split(".")[0] in NETWORK_PACKAGES or m in NETWORK_MODULES}, names


@pytest.mark.parametrize("kind, factory", [("raw", "_raw_client"), ("sdk", "_build_sdk_client")])
def test_the_client_factories_hand_out_the_offline_client_before_any_network_client(app, monkeypatch, kind, factory):
    """ASVS V1.4.1 · CWE-653 · CWE-441: offline credentials get the offline client; no live client class is ever built for them."""
    # Arrange
    def refuse(*a, **k):
        raise AssertionError("a network client was built for offline credentials")
    monkeypatch.setattr(srv, "Client", refuse)
    import zscaler
    monkeypatch.setattr(zscaler, "ZscalerClient", refuse)
    creds = ot.creds_for(ot.sample_store())
    # Act
    client = getattr(srv, factory)(creds)
    # Assert
    assert getattr(client, "offline", False) is True
    assert isinstance(client, ot.OfflineRawClient if kind == "raw" else ot.OfflineSdkClient)


def test_the_readers_work_unchanged_on_the_sample_with_no_socket(app):
    """ASVS V1.14.1 · CWE-653: the DLP export reader, the ZPA reader and the raw reads answer from the sample with every socket blocked."""
    # Arrange
    import pack_export
    import zpa_reader
    st = ot.sample_store(reset=True)
    sdk, raw = ot.client_for(ot.creds_for(st), "sdk"), ot.client_for(ot.creds_for(st), "raw")
    # Act
    dlp = pack_export.read_tenant(sdk)
    zpa = zpa_reader.read(sdk, pace=0)
    cac, code = raw.get("/zia/cloudApplicationRules")
    # Assert
    assert len(dlp["dictionaries"]) == len(sample_tenant.DICTIONARIES) and set(dlp["rules"]) == {"web", "endpoint", "saas", "email"}
    assert not dlp["errors"] and all(v["read"] for v in zpa["collections"].values())
    assert code == 200 and {r["type"] for r in cac} == set(sample_tenant.CAC_RULES)


# ── writes: in memory on the sample, refused on a snapshot ───────────────

@pytest.mark.parametrize("method", ["post", "put", "delete"])
def test_a_snapshot_refuses_every_write_in_words(method):
    """ASVS V4.1.1 · CWE-284 · WSTG-ATHZ-02: an offline snapshot is read-only; a write is refused with a clear message and changes nothing."""
    # Arrange
    st = ot.OfflineStore("file-" + "1" * 16, "snapshot", {"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "R"}]}}, {})
    raw = ot.OfflineRawClient(st, ot.creds_for(st))
    # Act
    body, code = getattr(raw, method)("/zia/webDlpRules/1" if method != "post" else "/zia/webDlpRules", {"name": "x"})
    # Assert
    assert code == 403 and body["message"] == ot.READ_ONLY and "nothing is sent to a tenant" in body["message"]
    assert st.responses["/zia/api/v1/webDlpRules"]["body"] == [{"id": 1, "name": "R"}]


def test_a_snapshot_refuses_an_sdk_write_with_the_error_the_sdk_returns():
    """ASVS V4.1.1 · CWE-284: an SDK add on a snapshot answers (None, response, error) naming the refusal; nothing changes."""
    # Arrange
    st = ot.OfflineStore("file-" + "2" * 16, "snapshot", {"/zia/api/v1/webDlpRules": {"status": 200, "body": []}}, {})
    sdk = ot.OfflineSdkClient(st, ot.creds_for(st))
    # Act
    res, _resp, err = sdk.zia.dlp_web_rules.add_rule(name="x", action="ALLOW", state="DISABLED", order=1)
    # Assert
    assert res is None and isinstance(err, ot.OfflineRefused) and err.status == 403 and "read-only" in str(err)
    assert st.responses["/zia/api/v1/webDlpRules"]["body"] == []


def test_sample_writes_change_only_the_in_memory_copy():
    """ASVS V1.4.1 · CWE-653: a deploy on the sample adds to its memory only; the shipped data and a reset sample are untouched."""
    # Arrange
    st = ot.sample_store(reset=True)
    sdk = ot.OfflineSdkClient(st, ot.creds_for(st))
    before = len(sample_tenant.WEB_DLP_RULES)
    # Act
    rule, _r, err = sdk.zia.dlp_web_rules.add_rule(name="Pack rule", action="ALLOW", state="DISABLED", order=9)
    # Assert
    assert err is None and rule.name == "Pack rule" and st.writes == 1
    assert len(st.responses["/zia/api/v1/webDlpRules"]["body"]) == before + 1
    assert st.responses["/zia/api/v1/webDlpRules"]["body"][-1]["name"] == "Pack rule"   # stored as the API spells it
    assert len(sample_tenant.WEB_DLP_RULES) == before
    assert len(ot.sample_store(reset=True).responses["/zia/api/v1/webDlpRules"]["body"]) == before


def test_zpa_new_object_ids_are_unique_across_collections():
    """ASVS V1.4.1 · CWE-706: ZPA ids are one space across object types, as a real tenant allocates, so a new connector group and a new segment group never share an id; a POV build's later parts (an app segment on the group a step earlier created) resolve the distinct ids by name."""
    # Arrange
    st = ot.sample_store(reset=True)
    base = "/zpa/mgmtconfig/v1/admin/customers/1"
    # Act
    s1, b1 = st.answer_write("POST", base + "/appConnectorGroup", {"name": "LKF-group"})
    s2, b2 = st.answer_write("POST", base + "/segmentGroup", {"name": "LKF-seg-group"})
    # Assert
    assert s1 == 200 and s2 == 200
    assert b1["id"] != b2["id"] and int(b2["id"]) > int(b1["id"])   # one space, ascending: no collision between collections
    assert int(b1["id"]) > 90000 and isinstance(b1["id"], str)      # a ZPA id is a string, past every existing id


def test_a_sample_change_it_does_not_model_is_refused_in_words():
    """ASVS V4.1.1 · CWE-754: a write the sample cannot represent is refused (400) and says nothing reached a tenant."""
    # Arrange
    raw = ot.OfflineRawClient(ot.sample_store(reset=True), {})
    # Act
    body, code = raw.post("/zpa/policySet/123/rule", {"name": "x"})
    # Assert
    assert code == 400 and "nothing was sent to a tenant" in body["message"]


# ── the browser's choice (cookie) and the credentials it stands for ──────

def test_opening_the_sample_sets_a_strict_httponly_cookie_and_leave_clears_it(app):
    """ASVS V3.4.2 · ASVS V3.4.3 · CWE-1004 · WSTG-SESS-02: the offline choice is an HttpOnly, SameSite=Strict cookie; Leave removes it."""
    # Act
    r = _sample(app)
    left = app.post("/api/offline/leave", json={})
    # Assert
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{ot.COOKIE}=sample") and "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("Strict", "strict")
    assert r.json()["mode"] == "sample" and r.json()["company"] == sample_tenant.COMPANY
    assert left.json() == {"mode": "live"} and app.get("/api/offline/status").json() == {"mode": "live"}


def test_with_the_sample_open_typed_credentials_are_never_used(app, monkeypatch):
    """ASVS V1.4.1 · CWE-441 · WSTG-BUSL-01: while the sample is open, a typed live secret never reaches a client factory or a reply."""
    # Arrange
    seen = []
    real = srv._build_sdk_client
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (seen.append(dict(creds)), real(creds))[1])
    _sample(app)
    # Act
    r = app.post("/api/tenant/check", json=LIVE)
    # Assert
    assert r.status_code == 200 and r.json()["tenant_label"] == sample_tenant.LABEL
    assert seen and all(ot.is_offline_creds(c) for c in seen)
    assert CANARY_SECRET not in json.dumps(seen) and CANARY_SECRET not in r.text


def test_an_offline_tenant_that_is_gone_fails_closed_never_live(app, monkeypatch):
    """ASVS V1.4.1 · CWE-636 · CWE-441: a cookie naming a snapshot no longer open is a 409, and no live client is built."""
    # Arrange
    def refuse(*a, **k):
        raise AssertionError("fell back to the live tenant")
    monkeypatch.setattr(srv, "Client", refuse)
    app.cookies.set(ot.COOKIE, "file-" + "a" * 16)
    # Act
    r = app.post("/api/tenant/check", json=LIVE)
    # Assert
    assert r.status_code == 409 and "no longer open" in r.json()["detail"]
    assert app.get("/api/offline/status").json()["mode"] == "gone"


@pytest.mark.parametrize("value", ["../etc", "snap-123", "SAMPLE", "sample x", "snap-" + "g" * 16, "file-" + "0" * 17, ""])
def test_a_hostile_cookie_value_is_ignored(app, value):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: only the exact offline ids are honoured; anything else is the live tenant."""
    # Arrange
    app.cookies.set(ot.COOKIE, value)
    # Act
    st = app.get("/api/offline/status").json()
    # Assert
    assert st == {"mode": "live"}


def test_the_record_label_names_the_sample_never_a_real_tenant():
    """ASVS V7.1.1 · CWE-451: deployment records and messages name the sample as the sample."""
    # Act
    import tenant_auth
    label = tenant_auth.record_label(ot.creds_for(ot.sample_store()))
    # Assert
    assert label == sample_tenant.LABEL


def test_an_assessment_of_the_sample_is_never_kept_in_a_real_profile(app):
    """ASVS V1.4.1 · CWE-472: a run on the sample, sent with a real profile id, adds nothing to that profile's history."""
    # Arrange
    import tenant_profiles
    p = tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "acmeclientid0001"})
    _sample(app)
    # Act
    with app.stream("POST", "/api/assess", json=dict(SCOPE, scopes=["dlp"], scope="", profile_id=p["id"])) as r:
        body = "".join(r.iter_text())
    # Assert
    assert r.status_code == 200 and "event: complete" in body and sample_tenant.COMPANY in body
    assert tenant_profiles.get(p["id"])["history"] == []


# ── every page works on the sample ──────────────────────────────────────

@pytest.mark.parametrize("path, body", [
    ("/api/path-analyzer/start", {"destination": "chat.openai.com"}),
    ("/api/dlp-packs/export/start", {"pack_name": "lkf"}),
    ("/api/shadow-rules/start", {}),
    ("/api/zpa/analysis/start", {}),
    ("/api/exports/policies/start", {"format": "xlsx"}),
])
def test_tenant_reading_jobs_finish_on_the_sample(app, path, body):
    """ASVS V1.14.1 · CWE-653: Path analyzer, exports, shadowed rules and ZPA analysis complete on the sample with no network."""
    # Arrange
    _sample(app)
    # Act
    r = app.post(path, json=dict(SCOPE, **body))
    # Assert
    assert r.status_code == 200, r.text
    assert r.json().get("job_id") == "sync-job"
    assert JOBS[-1].error == "" and isinstance(JOBS[-1].result, dict), JOBS[-1].error


def test_a_deploy_preview_works_on_the_sample(app):
    """ASVS V1.14.1 · CWE-653: Deploy policy packs' preflight (a preview, writes nothing) reads the sample."""
    # Arrange
    _sample(app)
    # Act
    r = app.post("/api/dlp-packs/preflight", json=dict(SCOPE, pack_ids=["cjis_policy_pack"]))
    # Assert
    assert r.status_code == 200 and r.json()["packs"][0]["id"] == "cjis_policy_pack"
    assert ot.sample_store().writes == 0


# ── saving a snapshot: scoped, owner-only, no credentials ────────────────

@pytest.fixture
def live(monkeypatch):
    """The live tenant, faked: an offline raw client over _live_store,
    built by _raw_client for the typed (real-looking) credentials."""
    st = _live_store()
    real = srv._raw_client

    def factory(creds):
        if ot.is_offline_creds(creds):
            return real(creds)
        assert creds["client_secret"] == CANARY_SECRET
        return ot.OfflineRawClient(st, creds)
    monkeypatch.setattr(srv, "_raw_client", factory)
    return st


def test_a_saved_snapshot_is_owner_only_and_carries_no_secret(app, live, tmp_path):
    """ASVS V8.3.4 · ASVS V6.1.1 · CWE-312 · CWE-732: the snapshot file is 0600 in a 0700 folder; neither the client secret nor a secret field's value is in it."""
    # Arrange
    import tenant_profiles
    p = tenant_profiles.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": LIVE["client_id"]})
    # Act
    r = app.post("/api/tenant-profiles/snapshots/save/start", json=dict(LIVE, **SCOPE, profile_id=p["id"]))
    # Assert
    assert r.status_code == 200, r.text
    snaps = tenant_profiles.list_snapshots(p["id"])
    assert len(snaps) == 1 and snaps[0]["tenant_label"] == "acme (zscalerten)"
    path = tenant_profiles.snapshot_path(snaps[0]["id"])
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(os.path.dirname(path)).st_mode) == 0o700
    every_file = "".join(open(os.path.join(d, f), encoding="utf-8", errors="replace").read()
                         for d, _, fs in os.walk(tmp_path) for f in fs)
    assert CANARY_SECRET not in every_file and CANARY_FIELD not in every_file
    doc = json.load(open(path, encoding="utf-8"))
    assert '"exitPass":"(set)"' in json.dumps(doc, separators=(",", ":"))
    assert "client_secret" not in json.dumps(doc) and set(doc) == {"format", "version", "meta", "responses"}
    assert [s["id"] for s in app.get("/api/tenant-profiles").json()["profiles"][0]["snapshots"]] == [snaps[0]["id"]]


def test_a_snapshot_keeps_only_what_is_in_scope(app, live):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: with only ZPA ticked, the snapshot holds ZPA answers and nothing else."""
    # Arrange
    import tenant_profiles
    # Act
    r = app.post("/api/tenant-profiles/snapshots/save/start", json=dict(LIVE, scopes=["zpa"], channels={}, from_page=True))
    # Assert
    assert r.status_code == 200
    sid = tenant_profiles.list_snapshots("")[0]["id"]
    doc = json.loads(tenant_profiles.read_snapshot(sid, ot.MAX_SNAPSHOT_BYTES))
    assert doc["responses"] and all(k.startswith("/zpa/") for k in doc["responses"])
    assert doc["meta"]["scopes"] == ["zpa"]


def test_saving_a_snapshot_is_refused_while_the_sample_is_open(app, live):
    """ASVS V1.4.1 · CWE-441: a snapshot is a read of your own tenant; while the sample is open the save is refused before sign-in."""
    # Arrange
    _sample(app)
    # Act
    r = app.post("/api/tenant-profiles/snapshots/save/start", json=dict(LIVE, **SCOPE))
    # Assert
    assert r.status_code == 409 and "Leave" in r.json()["detail"]


def test_a_saved_snapshot_opens_offline_and_compares_with_the_live_tenant(app, live):
    """ASVS V1.14.1 · CWE-653: an opened snapshot serves every reader read-only, and comparing names what changed live since."""
    # Arrange
    import tenant_profiles
    app.post("/api/tenant-profiles/snapshots/save/start", json=dict(LIVE, **SCOPE))
    sid = tenant_profiles.list_snapshots("")[0]["id"]
    live.responses["/zia/api/v1/webDlpRules"]["body"].append({"id": 999, "name": "Added later", "state": "ENABLED"})
    live.responses["/zia/api/v1/webDlpRules"]["body"][0]["state"] = "DISABLED"
    # Act
    opened = app.post(f"/api/tenant-profiles/snapshots/{sid}/open", json={})
    check = app.post("/api/tenant/check", json={})
    app.post("/api/offline/leave", json={})
    cmp_ = app.post("/api/tenant-profiles/snapshots/compare/start", json=dict(LIVE, **SCOPE, snapshot_id=sid))
    # Assert
    assert opened.status_code == 200 and opened.json()["mode"] == "snapshot" and opened.json()["source"] == sid
    assert check.json()["tenant_label"].startswith("Snapshot of acme (zscalerten)")
    assert cmp_.status_code == 200 and JOBS[-1].error == ""
    diff = JOBS[-1].result
    web = next(x for x in diff["lists"] if x["what"] == "Inline Web DLP rules")
    assert web["added"] == ["Added later"] and web["changed"] == [sample_tenant.WEB_DLP_RULES[0]["name"]] and web["removed"] == []
    assert diff["live_label"] == "acme (zscalerten)" and CANARY_SECRET not in json.dumps(diff)


def test_compare_names_added_removed_and_changed_and_ignores_change_times():
    """ASVS V7.1.1 · CWE-1023: the comparison is per object (id, else name); a new modified time alone is no change."""
    # Arrange
    old = {"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "A", "state": "ENABLED", "lastModifiedTime": 1},
                                                                {"id": 2, "name": "B"}]}}
    new = {"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "A", "state": "ENABLED", "lastModifiedTime": 9},
                                                                {"id": 3, "name": "C"}]},
           "/zpa/mgmtconfig/v1/admin/customers/{customerId}/application": {"status": 200, "body": {"list": []}}}
    # Act
    d = ot.compare(old, new)
    # Assert
    row = d["lists"][0]
    assert row["what"] == "Inline Web DLP rules" and row["added"] == ["C"] and row["removed"] == ["B"] and row["changed"] == []
    assert d["only_live"] == ["ZPA application segments"] and not d["same"]


# ── an opened snapshot file is untrusted ─────────────────────────────────

def _doc(**over):
    d = ot.build_snapshot({"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "R"}]}}, {"tenant_label": "acme (zscalerten)"})
    d.update(over)
    return d


def _nested(depth):
    v = "x"
    for _ in range(depth):
        v = [v]
    return v


REFUSED = {
    "not-utf8": b"\xff\xfe\x00",
    "not-json": b"{not json",
    "another-format": json.dumps(_doc(format="other")).encode(),
    "another-version": json.dumps(_doc(version=2)).encode(),
    "unknown-field": json.dumps(_doc(extra=1)).encode(),
    "no-answers": json.dumps(_doc(responses={})).encode(),
    "dot-dot-path": json.dumps(_doc(responses={"/zia/api/v1/../../etc": {"status": 200, "body": []}})).encode(),
    "file-path": json.dumps(_doc(responses={"/etc/passwd": {"status": 200, "body": []}})).encode(),
    "windows-path": json.dumps(_doc(responses={"C:\\Windows\\x": {"status": 200, "body": []}})).encode(),
    "url-path": json.dumps(_doc(responses={"https://evil.example/zia/x": {"status": 200, "body": []}})).encode(),
    "error-status": json.dumps(_doc(responses={"/zia/api/v1/x": {"status": 500, "body": []}})).encode(),
    "status-not-int": json.dumps(_doc(responses={"/zia/api/v1/x": {"status": "200", "body": []}})).encode(),
    "extra-entry-key": json.dumps(_doc(responses={"/zia/api/v1/x": {"status": 200, "body": [], "file": "/etc/passwd"}})).encode(),
    "too-deep": json.dumps(_doc(responses={"/zia/api/v1/x": {"status": 200, "body": _nested(ot.MAX_DEPTH)}})).encode(),
}


@pytest.mark.parametrize("case", sorted(REFUSED))
def test_an_untrusted_snapshot_file_is_refused_in_words(case):
    """ASVS V5.1.1 · ASVS V12.1.1 · CWE-20 · CWE-22 · CWE-674 · WSTG-INPV-13: wrong format, depth, schema or any non-API path is refused, not opened."""
    # Act / Assert
    with pytest.raises(ot.SnapshotInvalid) as e:
        ot.parse_snapshot(REFUSED[case])
    assert e.value.status == 400 and len(str(e.value)) > 20


def test_a_snapshot_file_too_large_is_refused_unread(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · CWE-770: a file over the size cap is refused before it is decoded or parsed."""
    # Arrange
    monkeypatch.setattr(ot, "MAX_SNAPSHOT_BYTES", 100)
    monkeypatch.setattr(json, "loads", lambda *a, **k: pytest.fail("parsed a file over the cap"))
    # Act / Assert
    with pytest.raises(ot.SnapshotInvalid, match="larger than"):
        ot.parse_snapshot(b"{" + b" " * 200 + b"}")


def test_a_snapshot_with_too_many_values_is_refused(monkeypatch):
    """ASVS V12.1.1 · CWE-770: a file with more JSON values than the cap is refused."""
    # Arrange
    monkeypatch.setattr(ot, "MAX_NODES", 50)
    raw = json.dumps(_doc(responses={"/zia/api/v1/x": {"status": 200, "body": list(range(100))}})).encode()
    # Act / Assert
    with pytest.raises(ot.SnapshotInvalid, match="too many values"):
        ot.parse_snapshot(raw)


def test_nesting_at_the_cap_is_accepted():
    """ASVS V5.1.4 · CWE-674: the depth cap is a boundary, not an off-by-one (MAX_DEPTH levels open)."""
    # Arrange: the document's own envelope adds four levels
    raw = json.dumps(_doc(responses={"/zia/api/v1/x": {"status": 200, "body": _nested(ot.MAX_DEPTH - 4)}})).encode()
    # Act
    answers, _meta = ot.parse_snapshot(raw)
    # Assert
    assert "/zia/api/v1/x" in answers


def test_an_opened_file_names_nothing_the_app_uses_and_its_secrets_are_scrubbed(app):
    """ASVS V5.1.3 · ASVS V8.3.4 · CWE-22 · CWE-312: the id is the app's own, meta text is cleaned, and a secret-named value is dropped."""
    # Arrange
    doc = _doc()
    doc["meta"].update({"id": "../../etc/passwd", "profile_id": "acme", "tenant_label": "acme\x00\n<b>x</b>"})
    doc["responses"]["/zcc/papi/public/v1/getDevices"] = {"status": 200, "body": [{"udid": "u1", "uninstallPassword": "CANARYleak"}]}
    # Act
    r = app.post("/api/tenant-profiles/snapshots/open-file", json={"name": "../x.json", "content": json.dumps(doc)})
    # Assert
    assert r.status_code == 200
    st = r.json()
    assert ot.SOURCE_RE.match(st["source"]) and st["source"].startswith("file-")
    assert "\x00" not in st["tenant_label"] and "\n" not in st["tenant_label"]
    devices = app.get("/api/offline/status")  # the cookie now names the opened file
    assert devices.json()["mode"] == "snapshot"
    store = ot.store(st["source"])
    assert "CANARYleak" not in json.dumps(store.responses)


@pytest.mark.parametrize("sid", ["../tenant_profiles", "snap-zz", "snap-" + "0" * 16, "sample", "file-" + "0" * 16])
def test_only_a_listed_snapshot_id_opens_downloads_or_deletes(app, sid):
    """ASVS V4.2.1 · ASVS V12.3.1 · CWE-22 · CWE-639 · WSTG-ATHZ-01: a snapshot is reached by an id the app listed, never by a path."""
    # Act
    opened = app.post(f"/api/tenant-profiles/snapshots/{sid}/open", json={})
    got = app.get(f"/api/tenant-profiles/snapshots/{sid}/download")
    deleted = app.post(f"/api/tenant-profiles/snapshots/{sid}/delete", json={})
    # Assert
    assert {opened.status_code, got.status_code, deleted.status_code} == {404}


def test_deleting_a_profile_deletes_its_snapshots(app, live):
    """ASVS V8.3.2 · CWE-459: snapshots belong to their profile; forgetting the profile removes their files."""
    # Arrange
    import tenant_profiles
    p = tenant_profiles.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": LIVE["client_id"]})
    app.post("/api/tenant-profiles/snapshots/save/start", json=dict(LIVE, **SCOPE, profile_id=p["id"]))
    path = tenant_profiles.snapshot_path(tenant_profiles.list_snapshots(p["id"])[0]["id"])
    # Act
    app.delete(f"/api/tenant-profiles/{p['id']}")
    # Assert
    assert not os.path.exists(path) and tenant_profiles.list_snapshots() == []


@pytest.mark.parametrize("ep", ["/zia/urlLookup", "/zia/auditlogEntryReport"])
def test_a_snapshot_cannot_answer_a_live_lookup_and_says_so(ep):
    """ASVS V4.1.1 · CWE-754: a read the API asks for with a POST has no offline answer; it is refused in words, nothing is sent."""
    # Arrange
    st = ot.OfflineStore("file-" + "3" * 16, "snapshot", {"/zia/api/v1/webDlpRules": {"status": 200, "body": []}}, {})
    # Act
    body, code = ot.OfflineRawClient(st, {}).post(ep, ["example.com"])
    # Assert
    assert code == 404 and "needs the live tenant" in body["message"] and "Nothing was sent" in body["message"]


def test_the_sample_answers_a_url_lookup_from_its_own_table():
    """ASVS V1.14.1 · CWE-653: the sample's URL lookup (used by the Path analyzer) is answered in memory."""
    # Act
    body, code = ot.OfflineRawClient(ot.sample_store(), {}).post("/zia/urlLookup", ["https://chat.openai.com/x", "unknown.example"])
    # Assert
    assert code == 200 and body[0]["urlClassifications"] == ["AI_ML_APPS"] and body[1]["urlClassifications"] == ["OTHER_MISCELLANEOUS"]


# ── Wave 6 UI check: Find anything's tags and to-dos work on the sample ──

@pytest.mark.parametrize("query", ["", "?profile_id=", "?vanity_domain=&cloud=production"])
def test_find_anything_notes_on_the_sample_are_kept_under_the_sample(app, tmp_path, monkeypatch, query):
    """WCAG 2.2 SC 3.3.1 · CWE-754: with the sample open, Find anything's notes load (they were refused with 400 "pick a tenant first")."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "notes.json"))
    _sample(app)
    # Act
    r = app.get("/api/workspace/notes" + query)
    # Assert
    assert r.status_code == 200, r.text
    assert r.json()["tenant"] == sample_tenant.LABEL and r.json()["notes"] == []


def test_a_to_do_on_the_sample_is_saved_under_the_sample_never_a_profile(app, tmp_path, monkeypatch):
    """WCAG 2.2 SC 3.3.1 · CWE-472: a to-do written on a sample object is kept under the sample's label, even when a profile id is sent."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "notes.json"))
    import tenant_profiles
    p = tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "acmeclientid0001"})
    _sample(app)
    # Act
    r = app.post("/api/workspace/notes", json={"profile_id": p["id"], "kind": "dlp_rule", "ref": "101", "label": "Rule",
                                               "action": "add_todo", "text": "Review this rule"})
    # Assert
    assert r.status_code == 200, r.text
    assert r.json()["tenant"] == sample_tenant.LABEL


def test_without_the_sample_notes_still_need_a_tenant(app, tmp_path, monkeypatch):
    """WCAG 2.2 SC 3.3.1 · CWE-754: negative case: with no tenant at all the notes are refused in words, as before."""
    # Arrange
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "notes.json"))
    # Act
    r = app.get("/api/workspace/notes")
    # Assert
    assert r.status_code == 400 and "pick a tenant first" in r.text
