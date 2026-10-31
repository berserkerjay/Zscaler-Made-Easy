"""Rehearsal on sample or offline data: every builder (each Build new type,
the classic Bulk changes types, the POV build, policy packs) makes its full
plan and dry run on the sample tenant and on an opened snapshot, with no
network and no tenant client built, labelled "Rehearsal — nothing was
written"; an apply there is refused with a clear message and nothing is
written. A snapshot saved from a tenant carries what the builders read.

No network: every socket call is refused and recorded; the SDK's client
and the classic-API helper raise if anything builds them."""
from __future__ import annotations

import copy
import os
import socket
import sys
import threading

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dlp_api_server as srv  # noqa: E402
import offline_tenant as ot  # noqa: E402
import sample_tenant  # noqa: E402

SCOPE = {"scopes": ["dlp", "zia_extras", "zpa", "zcc", "zdx", "genai", "automation", "aiguard"],
         "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "ssl_inspection", "cloud_app_control")},
         "from_page": True}
FAILED_READ = ("could not be read", "has no data", "Not in this snapshot", "HTTP 404", "no answer")

# Every Build new type and classic Bulk changes type, with a spec that names the sample's own objects.
BUILDERS = {
    "zia_baseline": {"type": "zia_baseline", "tier": "balanced", "prefix": "LKF", "areas": ["firewall", "url", "ssl", "sandbox", "dns", "ftc", "cac"]},
    "ssl_certificate_move": {"type": "ssl_certificate_move", "certificate": 52, "rules": [705]},
    "zpa_connector_group": {"type": "zpa_connector_group", "prefix": "LKF"},
    "zpa_app_segments": {"type": "zpa_app_segments", "prefix": "LKF", "connector_group_id": "2401",
                         "preset": {"vertical": "general", "domain": "corp.larkspur-freight.example"}},
    "zpa_prefix_delete": {"type": "zpa_prefix_delete", "prefix": "LKF", "everything": True},
    "zcc_profile_build": {"type": "zcc_profile_build", "platform": "windows", "forwarding": {"template": "best_practice", "name": "LKF POV forwarding"},
                          "app": {"template": "best_practice", "name": "LKF POV Windows"}},
    "zcc_profile_delete": {"type": "zcc_profile_delete", "targets": [{"kind": "app", "id": "1204", "name": "iOS - Drivers", "platform": "ios"}]},
    "zdx_probes": {"type": "zdx_probes", "template": "best_practice", "interval_minutes": 5, "protocol": "ADAPTIVE",
                   "predefined": [{"provider": "MICROSOFT_LOGIN", "web": True, "cloudpath": True}],
                   "custom": [{"name": "Larkspur intranet", "url": "https://intranet.larkspur-freight.example/", "cloudpath": True}]},
    "zdx_probe_state": {"type": "zdx_probe_state", "targets": [{"app": 3002, "to": "off"}]},
    "zdx_probe_delete": {"type": "zdx_probe_delete", "targets": [{"app": 3002, "name": "Freight billing"}]},
    "aiguard_routing": {"type": "aiguard_routing", "prefix": "LKF", "apps": ["chatgpt", "claude"], "cert": {"mode": "existing", "id": 11}},
    "aiguard_detection_policy": {"type": "aiguard_detection_policy", "prefix": "LKF", "profile": "GENERAL", "apps": ["chatgpt"]},
    "rule_state": {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 602}]},
    "reorder": {"type": "reorder", "policy": "url_filtering", "order": [603, 602, 601]},
    "url_categories": {"type": "url_categories", "action": "add", "target": "CUSTOM_01", "urls": ["new.larkspur-freight.example"]},
    "zpa_domains": {"type": "zpa_domains", "action": "copy", "source": "2201", "target": "2202", "domains": ["billing.larkspur-freight.example"]},
}
# The POV build: every part at once, the ZPA parts depending on each other.
POV_PARTS = {"zia_baseline": BUILDERS["zia_baseline"], "ssl_certificates": BUILDERS["ssl_certificate_move"],
             "zpa_connector_group": BUILDERS["zpa_connector_group"],
             "zpa_app_segments": {"type": "zpa_app_segments", "prefix": "LKF", "preset": {"vertical": "general", "domain": "corp.larkspur-freight.example"}},
             "zpa_policies": {"type": "zpa_policies", "prefix": "LKF", "access": True, "timeout": True, "inspection": True},
             "zcc_profiles": BUILDERS["zcc_profile_build"], "zdx_probes": BUILDERS["zdx_probes"],
             "aiguard_routing": BUILDERS["aiguard_routing"], "aiguard_policy": BUILDERS["aiguard_detection_policy"]}


class _Job:
    def __init__(self, kind, result=None, error=""):
        self.id, self.kind, self.result, self.error = "sync-job", kind, result, error
        self.status = "failed" if error else "done"


@pytest.fixture
def offline(tmp_path, monkeypatch):
    """An isolated app with the real client factories; no network; any
    attempt to build a tenant client fails the test."""
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    import pack_jobs
    import security
    import tenant_auth
    import zpa_reader
    import zscaler
    jobs, attempts, built = [], [], []

    def sync_start(kind, fn, **_k):
        try:
            job = _Job(kind, fn(lambda line: None, threading.Event()))
        except Exception as e:  # noqa: BLE001
            job = _Job(kind, None, f"{type(e).__name__}: {e}")
        jobs.append(job)
        return job

    def guard(*a, **_k):
        attempts.append(repr(a[:2])[:120])
        raise OSError("socket guard: no network in this test")

    def no_client(*a, **_k):
        built.append("tenant client")
        raise AssertionError("a tenant client was built")
    monkeypatch.setattr(pack_jobs, "start", sync_start)
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo"), (socket, "create_connection")):
        monkeypatch.setattr(owner, name, guard)
    monkeypatch.setattr(zscaler, "ZscalerClient", no_client)
    monkeypatch.setattr(tenant_auth, "build_legacy_sdk_client", no_client)
    monkeypatch.setattr(security, "_write_override", True)   # write mode on: only the rehearsal rule refuses an apply
    monkeypatch.setattr(srv, "_REPORTS", {})
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    c = TestClient(srv.app, base_url="http://127.0.0.1")
    return {"c": c, "jobs": jobs, "attempts": attempts, "built": built}


def _use_sample(c):
    r = c.post("/api/offline/sample", json={"reset": True})
    assert r.status_code == 200, r.text
    return ot.sample_store()


def _use_snapshot(c):
    """A snapshot saved the way the app saves one (offline_tenant.capture over
    a tenant read, scrubbed and checked as untrusted when it is opened)."""
    live = ot.sample_store(reset=True)
    got = ot.capture(ot.OfflineRawClient(live, ot.creds_for(live)), SCOPE["scopes"], SCOPE["channels"], lambda m: None)
    doc = ot.build_snapshot(got["responses"], {"tenant_label": "acme (zscalerten)", "scopes": SCOPE["scopes"]})
    r = c.post("/api/tenant-profiles/snapshots/open-file", json={"content": ot.dumps(doc)})
    assert r.status_code == 200 and r.json()["mode"] == "snapshot", r.text
    return ot.store(r.json()["source"])


SOURCES = {"sample": _use_sample, "snapshot": _use_snapshot}


def _assert_rehearsal(out, kind):
    assert out.get("rehearsal", {}).get("kind") == kind and out["rehearsal"]["note"] == "Rehearsal — nothing was written.", out.get("rehearsal")
    text = " ".join(str(x) for x in (out.get("blockers") or []) + (out.get("warnings") or []))
    assert not any(w in text for w in FAILED_READ), text[:400]


@pytest.mark.parametrize("source", list(SOURCES))
@pytest.mark.parametrize("op", list(BUILDERS))
def test_every_builder_plans_offline_as_a_rehearsal(offline, source, op):
    """ASVS V1.14.1 · V12.6.1 · CWE-653 · CWE-441 · WSTG-INPV-19: each Build new and Bulk changes type plans on the sample and on a snapshot, labelled a rehearsal, with every catalogue it reads present, no socket and no tenant client."""
    # Arrange
    c = offline["c"]
    st = SOURCES[source](c)
    # Act
    r = c.post("/api/operations/preview", json=dict(SCOPE, operation=copy.deepcopy(BUILDERS[op])))
    # Assert
    assert r.status_code == 200, r.text[:400]
    out = r.json()
    _assert_rehearsal(out, source)
    assert out["items"] or (op == "zpa_prefix_delete" and out["status"] == "nothing_to_do"), out.get("blockers")   # nothing named LKF-… yet
    assert out["status"] in ("ready", "nothing_to_do", "blocked"), out["status"]
    if op not in ("zcc_profile_delete", "zdx_probe_delete"):   # deleting an object in use is refused on any tenant
        assert out["status"] != "blocked", out["blockers"]
    assert st.writes == 0 and offline["attempts"] == [] and offline["built"] == []


@pytest.mark.parametrize("source", list(SOURCES))
def test_the_pov_build_rehearses_every_part_offline(offline, source):
    """ASVS V1.14.1 · CWE-653 · CWE-841: the combined POV plan, every part and the ZPA parts that need each other, is one dry run on the sample and on a snapshot, needing no saved POV, labelled a rehearsal."""
    # Arrange
    c = offline["c"]
    st = SOURCES[source](c)
    # Act
    r = c.post("/api/pov/build/preview", json=dict(SCOPE, parts=copy.deepcopy(POV_PARTS)))
    # Assert
    assert r.status_code == 200, r.text[:400]
    out = r.json()
    _assert_rehearsal(out, source)
    assert out["status"] == "ready" and not out["blockers"], out["blockers"]
    assert out["order"] == list(POV_PARTS) and all(p["items"] for p in out["parts"])
    assert len(out["plan_hash"]) == 64 and out["confirm_phrase"].startswith("APPLY ")
    assert st.writes == 0 and offline["attempts"] == [] and offline["built"] == []


@pytest.mark.parametrize("source", list(SOURCES))
def test_a_policy_pack_preview_and_removal_preview_rehearse_offline(offline, source):
    """ASVS V1.14.1 · CWE-653: Deploy policy packs' preflight and the removal preview work offline, labelled a rehearsal."""
    # Arrange
    c = offline["c"]
    st = SOURCES[source](c)
    # Act
    pre = c.post("/api/dlp-packs/preflight", json=dict(SCOPE, pack_ids=["cjis_policy_pack"], assessor="Jane Doe"))
    rem = c.post("/api/dlp-packs/removal/preflight", json=dict(SCOPE, pack_ids=["cjis_policy_pack"]))
    # Assert
    assert pre.status_code == 200 and rem.status_code == 200, (pre.text[:300], rem.text[:300])
    assert pre.json()["rehearsal"]["kind"] == source and rem.json()["rehearsal"]["kind"] == source
    assert pre.json()["plan_hash"] and pre.json()["packs"][0]["id"] == "cjis_policy_pack"
    assert st.writes == 0 and offline["attempts"] == [] and offline["built"] == []


def _apply_bulk(c):
    op = copy.deepcopy(BUILDERS["rule_state"])
    prev = c.post("/api/operations/preview", json=dict(SCOPE, operation=op)).json()
    return c.post("/api/operations/apply", json=dict(SCOPE, operation=op, plan_hash=prev["plan_hash"], confirm=True, assessor="Jane Doe"))


def _apply_bulk_job(c):
    op = copy.deepcopy(BUILDERS["zia_baseline"])
    prev = c.post("/api/operations/preview", json=dict(SCOPE, operation=op)).json()
    return c.post("/api/operations/apply/start", json=dict(SCOPE, operation=op, plan_hash=prev["plan_hash"], confirm=True,
                                                          confirm_text=prev["confirm_phrase"], assessor="Jane Doe"))


def _apply_pov(c):
    prev = c.post("/api/pov/build/preview", json=dict(SCOPE, parts=copy.deepcopy(POV_PARTS))).json()
    return c.post("/api/pov/build/apply/start", json=dict(SCOPE, parts=copy.deepcopy(POV_PARTS), plan_hash=prev["plan_hash"], confirm=True,
                                                         confirm_text=prev["confirm_phrase"], assessor="Jane Doe"))


def _deploy_pack(c):
    pre = c.post("/api/dlp-packs/preflight", json=dict(SCOPE, pack_ids=["cjis_policy_pack"], assessor="Jane Doe")).json()
    return c.post("/api/dlp-packs/apply/start", json=dict(SCOPE, pack_ids=["cjis_policy_pack"], plan_hash=pre["plan_hash"], confirm=True,
                                                         assessor="Jane Doe"))


def _remove_pack(c):
    pre = c.post("/api/dlp-packs/removal/preflight", json=dict(SCOPE, pack_ids=["cjis_policy_pack"])).json()
    return c.post("/api/dlp-packs/removal/apply", json=dict(SCOPE, pack_ids=["cjis_policy_pack"], plan_hash=pre.get("plan_hash") or "a" * 64,
                                                           confirm=True, assessor="Jane Doe", confirm_phrase=pre.get("confirm_phrase") or "DELETE 1 OBJECTS"))


APPLIES = {"bulk-change": _apply_bulk, "build-new-job": _apply_bulk_job, "pov-build": _apply_pov, "pack-deploy": _deploy_pack,
           "pack-removal": _remove_pack}


@pytest.mark.parametrize("source", list(SOURCES))
@pytest.mark.parametrize("write", list(APPLIES))
def test_an_apply_offline_is_refused_with_a_clear_message_and_writes_nothing(offline, source, write):
    """ASVS V4.1.1 · V1.4.1 · CWE-284 · CWE-441 · WSTG-ATHZ-02: with write mode on, a writer, the assessor and the confirmation, an apply on the sample or a snapshot is refused (409, "Rehearsal only … nothing was written") and the offline tenant is unchanged."""
    # Arrange
    c = offline["c"]
    st = SOURCES[source](c)
    before = copy.deepcopy(st.responses)
    # Act
    r = APPLIES[write](c)
    # Assert
    assert r.status_code == 409, (r.status_code, r.text[:300])
    detail = r.json()["detail"]
    assert detail.startswith("Rehearsal only:") and "nothing was written" in detail
    assert ("read-only" in detail) is (source == "snapshot")
    assert st.writes == 0 and st.responses == before
    assert offline["attempts"] == [] and offline["built"] == []
    assert not any(j.kind in ("deploy", "removal", "ops_apply", "pov_build_apply") for j in offline["jobs"])


def test_the_sample_carries_every_catalogue_the_builders_read():
    """ASVS V1.14.1 · CWE-440: the sample answers each builder catalogue (URL categories, network and cloud apps, certificates, ZPA enrollment and OWASP lists, ZDX configuration, AI Guard lists) and a read for one cloud-app class still answers no data, as before."""
    # Arrange
    st = ot.sample_store(reset=True)
    # Act
    paths = set(st.responses)
    by_class = st.answer_get("/zia/api/v1/cloudApplications/policy", {"app_class": "WEBMAIL", "page_size": 1000})
    whole = st.answer_get("/zia/api/v1/cloudApplications/policy", {"page": 1, "page_size": 1000})
    # Assert
    for p in sample_tenant.builder_catalogues():
        assert ot.normalize_path(p) in paths, p
    assert by_class[0] == 404 and whole[0] == 200 and whole[1]


def test_a_snapshot_saves_what_the_builders_read_only_for_what_is_in_scope():
    """ASVS V1.14.1 · V4.1.3 · CWE-285: a snapshot captures the builder catalogues of each ticked product, and none of an unticked one (AI Guard, ZDX)."""
    # Arrange
    live = ot.sample_store(reset=True)
    client = ot.OfflineRawClient(live, ot.creds_for(live))
    # Act
    full = ot.capture(client, SCOPE["scopes"], SCOPE["channels"], lambda m: None)["responses"]
    zia_only = ot.capture(client, ["zia_extras"], {}, lambda m: None)["responses"]
    # Assert
    for p in ("/zia/api/v1/urlCategories/lite", "/zia/api/v1/intermediateCaCertificate/readyToUse", "/aiguard/v1/llm-providers",
              "/zdx/v1/config/applications/supported", "/zpa/mgmtconfig/v1/admin/customers/{customerId}/inspectionControls/predefined/versions"):
        assert p in full, p
    assert "/zia/api/v1/networkApplications" in zia_only
    assert not any(p.startswith(("/aiguard/", "/zdx/", "/zpa/")) for p in zia_only)
    assert isinstance(full["/zpa/mgmtconfig/v1/admin/customers/{customerId}/inspectionControls/predefined/versions"]["body"], list)
