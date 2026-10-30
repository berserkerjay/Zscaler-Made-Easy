"""POV build (pov_build.py, /api/pov/build/*): one combined plan across the
Build new plugins, one dry run with one plan hash, one apply with one typed
confirmation in a safe order, stop at the first failure, and an Undo of
everything applied so far, latest first.

The tenant is the stateful SDK wire fake (tests/sdk_wire_fake.py): the
installed zscaler-sdk-python 1.11.3 services and models sit between the
app and the fake, so every request is the SDK's. No network, no clock, no
real tenant; every store in the test's own folder (tests/conftest.py)."""
from __future__ import annotations

import copy
import json
import os
import sys
import threading

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import deployments  # noqa: E402
import pack_channels as pc  # noqa: E402
import pov  # noqa: E402
import pov_build as pb  # noqa: E402
import sdk_wire_fake as wf  # noqa: E402
from sdk_wire_fake import ZCC, ZIA, ZPA1  # noqa: E402

ALL = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc", "zdx", "genai", "automation", "aiguard"],
                   {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
INTAKE = {"customer": "Acme Health", "domain": "corp.example.com", "prefix": "AH", "vertical": "healthcare",
          "products": ["url_filtering", "threat", "ssl", "dlp", "cloud_apps", "firewall", "dns", "zpa", "zdx"]}
ZDX_OFF = ("zdx_probes",)   # the wire fake has no ZDX configuration API (tests/test_ops_zdx.py has its own fake)


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    import ops_zpa
    import zpa_reader
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    import zscaler.zia.url_categories as sdk_urls
    monkeypatch.setattr(sdk_urls.time, "sleep", lambda s: None)
    ao.load_plugins()


def tenant():
    extra = {}
    for f in (wf.zia_catalogues, wf.zpa_builder_lists, wf.aiguard_lists):
        extra.update(f())
    st = wf.WireStore(extra)
    return st, wf.WireClient(st)


def parts_for(*keys, intake=INTAKE):
    d = pb.defaults(intake)
    raw = {}
    for k in keys or [k for k in pb.ORDER if k not in ZDX_OFF]:
        spec = copy.deepcopy(d[k]["spec"])
        if k == "ssl_certificates":
            spec = {"type": "ssl_certificate_move", "certificate": 52, "rules": [705]}   # the sample's Inspect rule
        if k == "aiguard_routing":
            spec["cert"] = {"mode": "existing", "id": 11}
        raw[k] = spec
    return raw


def recorder():
    def record(result, undo_of):
        rec = ao.record(result, by="Jane Doe", undo_of=undo_of)
        return rec["id"] if rec else None
    return record


def apply(cl, parts, combined, **kw):
    return pb.execute(cl, parts, plan_hash=combined["plan_hash"], scope=ALL, writes_enabled=True, confirm_text=combined["confirm_phrase"],
                      assessor="Jane Doe", record=recorder(), settle_seconds=0, **kw)


def undo(cl, result):
    up, ids = pb.undo_parts(pb.build_record(result, by="Jane Doe", build_id="b-000000000001"), deployments.get_operation)
    cu = pb.plan(cl, up, scope=ALL, undo_of=ids)
    return cu, pb.execute(cl, up, plan_hash=cu["plan_hash"], scope=ALL, writes_enabled=True, confirm_text=cu["confirm_phrase"],
                          assessor="Jane Doe", record=recorder(), undo_of=ids, settle_seconds=0)


# ── The combined plan and its hash ──────────────────────────────────────

def test_the_combined_plan_holds_every_part_in_the_safe_order_under_one_hash():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06: the parts are planned in dependency order whatever order the request gives, each with every object, and one sha256 covers them all."""
    # Arrange
    st, cl = tenant()
    raw = parts_for()
    shuffled = dict(reversed(list(raw.items())))
    # Act
    c = pb.plan(cl, pb.clean_parts(shuffled), scope=ALL, tenant_label="acme")
    again = pb.plan(cl, pb.clean_parts(raw), scope=ALL, tenant_label="acme")
    # Assert
    assert c["order"] == [k for k in pb.ORDER if k in raw]
    assert c["order"].index("zpa_connector_group") < c["order"].index("zpa_app_segments") < c["order"].index("zpa_policies")
    assert c["plan_hash"] == again["plan_hash"] and len(c["plan_hash"]) == 64
    assert c["status"] == "ready" and c["changes"] == sum(p["counts"]["change"] for p in c["parts"]) > 0
    assert c["confirm_phrase"] == f"APPLY {c['changes']} POV CHANGES"
    assert [s["section"] for s in c["sections"]] == ["Internet Access (ZIA)", "Private Access (ZPA)", "Client Connector", "AI Guard"]
    for p in c["parts"]:
        assert p["items"] and all({"object", "field", "before", "after", "status"} <= set(u) for u in p["items"])
    assert st.write_log() == []


def test_the_hash_moves_when_a_part_or_the_tenant_changes():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-06: a different option in any part, or a tenant that changed, gives another plan hash."""
    # Arrange
    st, cl = tenant()
    raw = parts_for("zia_baseline", "zpa_connector_group")
    base = pb.plan(cl, pb.clean_parts(raw), scope=ALL)["plan_hash"]
    other = copy.deepcopy(raw)
    other["zpa_connector_group"]["max_usage"] = 9
    # Act
    by_spec = pb.plan(cl, pb.clean_parts(other), scope=ALL)["plan_hash"]
    st.responses[f"{ZPA1}/appConnectorGroup"]["body"]["list"].append({"id": "2499", "name": "AH-connector-group", "enabled": True})
    by_tenant = pb.plan(cl, pb.clean_parts(raw), scope=ALL)["plan_hash"]
    # Assert
    assert len({base, by_spec, by_tenant}) == 3


def test_a_part_that_needs_an_earlier_part_is_planned_against_it_not_blocked():
    """ASVS V11.1.1 · CWE-841: on their own, segments without a connector group and policies without segments are blocked; in one build they show what the earlier part creates."""
    # Arrange
    st, cl = tenant()
    raw = parts_for("zpa_connector_group", "zpa_app_segments", "zpa_policies")
    # Act
    alone_segments = ao.plan(cl, raw["zpa_app_segments"], scope=ALL)
    alone_policies = ao.plan(cl, raw["zpa_policies"], scope=ALL)
    c = pb.plan(cl, pb.clean_parts(raw), scope=ALL)
    # Assert
    assert alone_segments["status"] == "blocked" and alone_policies["status"] == "blocked"
    assert c["status"] == "ready" and not c["blockers"]
    seg = next(p for p in c["parts"] if p["key"] == "zpa_app_segments")
    assert any("built by an earlier step" in str(u.get("value")) for u in seg["items"])
    pol = next(p for p in c["parts"] if p["key"] == "zpa_policies")
    assert any(ao.PENDING_PREFIX in json.dumps(g) for g in (pol.get("core") or {}).get("groups") or [])


# ── Apply: one confirmation, dependencies first, read back, Undo latest first ──

def test_one_apply_builds_every_part_in_order_and_undo_reverses_it_exactly():
    """ASVS V11.1.1 · V11.1.6 · CWE-841 · WSTG-BUSL-06: one typed confirmation applies every part (the connector group before the segments, the segments before the policies), each read back; Undo applies the inverses latest first and the tenant is as before."""
    # Arrange
    st, cl = tenant()
    before = wf.semantic(st.state())
    parts = pb.clean_parts(parts_for())
    c = pb.plan(cl, parts, scope=ALL, tenant_label="acme")
    # Act
    r = apply(cl, parts, c)
    # Assert
    assert r["status"] == "applied", [(s["key"], s["status"], s["message"]) for s in r["steps"]]
    assert all(s["status"] == "applied" and s["operation_id"] for s in r["steps"]), r["steps"]
    assert all(s["verification"].get("checked") == s["verification"].get("confirmed") for s in r["steps"])
    posts = [p for m, p in st.write_log() if m == "POST"]
    first = lambda frag: next(i for i, p in enumerate(posts) if frag in p)  # noqa: E731
    assert first("/appConnectorGroup") < first("/segmentGroup") < first("/application") < first("/policySet/")
    assert first(f"{ZIA}/") < first("/zpa/") < first("/zcc/")
    assert len(r["applied_operations"]) == len(r["steps"])
    # Undo: one plan over the recorded inverses, latest first, back to the tenant as it was.
    cu, ru = undo(cl, r)
    assert cu["order"] == list(reversed(c["order"])) and cu["confirm_phrase"].startswith("UNDO ")
    assert ru["status"] == "applied", [(s["key"], s["status"], s["message"]) for s in ru["steps"]]
    assert wf.semantic(st.state()) == before
    assert all(deployments.get_operation(op)["undone_by"] for op in r["applied_operations"])
    assert st.violations == []


def test_new_objects_arrive_disabled_or_monitor_only_by_default():
    """ASVS V1.4.4 · CWE-1188: the build's defaults create ZIA rules disabled, ZPA segments disabled and the AI Guard policy in Monitor."""
    # Arrange
    st, cl = tenant()
    parts = pb.clean_parts(parts_for("zia_baseline", "zpa_connector_group", "zpa_app_segments", "aiguard_policy"))
    c = pb.plan(cl, parts, scope=ALL)
    # Act
    r = apply(cl, parts, c)
    # Assert
    assert r["status"] == "applied"
    made = [x for x in st.rows(f"{ZIA}/urlFilteringRules") if str(x.get("name", "")).startswith("AH")]
    assert made and all(x.get("state") == "DISABLED" for x in made)
    segs = [x for x in st.rows(f"{ZPA1}/application") if str(x.get("name", "")).startswith("AH-")]
    assert segs and all(x.get("enabled") is False for x in segs)
    assert all(p["spec"].get("mode") in (None, "monitor") for p in c["parts"] if p["key"] == "aiguard_policy")


def test_the_run_stops_at_the_first_failure_and_undo_reverses_only_what_was_applied(monkeypatch):
    """ASVS V11.1.1 · CWE-754 · CWE-841 · WSTG-BUSL-06: a part ZCC refuses stops the run there; the parts after it are not attempted, the report names the failure, and Undo reverses the earlier parts latest first."""
    # Arrange
    st, cl = tenant()
    before = wf.semantic(st.state())
    raw = parts_for("zia_baseline", "zpa_connector_group", "zcc_profiles", "aiguard_policy")
    parts = pb.clean_parts(raw)
    c = pb.plan(cl, parts, scope=ALL)
    real = st.answer_write

    def refuse_zcc(method, url, body=None):
        if "/zcc/" in str(url) and method != "GET":
            return 403, {"code": "FORBIDDEN", "message": "Client Connector refused the change (test)"}
        return real(method, url, body)
    monkeypatch.setattr(st, "answer_write", refuse_zcc)
    # Act
    r = apply(cl, parts, c)
    # Assert
    status = {s["key"]: s["status"] for s in r["steps"]}
    assert r["status"] == "stopped" and r["stopped_at"] == "Client Connector profiles"
    assert status["zia_baseline"] == "applied" and status["zpa_connector_group"] == "applied"
    assert status["zcc_profiles"] in ("failed", "partial") and status["aiguard_policy"] == "not_attempted"
    zcc = next(s for s in r["steps"] if s["key"] == "zcc_profiles")
    assert "Nothing after it was written" in zcc["message"] and zcc["problems"]
    assert not any("/aiguard/" in p for _m, p in st.write_log())
    monkeypatch.setattr(st, "answer_write", real)
    cu, ru = undo(cl, r)
    assert cu["order"] == [s["key"] for s in reversed(r["steps"]) if s["operation_id"]]
    assert cu["order"][-2:] == ["zpa_connector_group", "zia_baseline"]
    assert ru["status"] == "applied"
    assert wf.semantic(st.state()) == before


def test_a_tenant_that_moved_since_the_preview_writes_nothing():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-06: the whole plan is re-read first; a changed tenant answers plan_changed and nothing is written."""
    # Arrange
    st, cl = tenant()
    parts = pb.clean_parts(parts_for("zia_baseline", "zpa_connector_group"))
    c = pb.plan(cl, parts, scope=ALL)
    st.responses[f"{ZPA1}/appConnectorGroup"]["body"]["list"].append({"id": "2499", "name": "AH-connector-group", "enabled": False})
    # Act
    r = apply(cl, parts, c)
    # Assert
    assert r["status"] == "plan_changed" and r["steps"] == [] and "Nothing was written" in r["message"]
    assert st.write_log() == []


def test_a_part_that_changed_while_the_build_ran_stops_the_run_there():
    """ASVS V11.1.6 · CWE-367 · CWE-841: each part is planned again right before it is written; one that no longer matches the preview stops the run with nothing of it written."""
    # Arrange
    st, cl = tenant()
    parts = pb.clean_parts(parts_for("zia_baseline", "zpa_connector_group", "zpa_app_segments"))
    c = pb.plan(cl, parts, scope=ALL)
    rec = recorder()

    def record_then_move(result, undo_of):
        if result.get("type") == "zpa_connector_group":   # someone adds a clashing segment meanwhile
            st.responses[f"{ZPA1}/application"]["body"]["list"].append({"id": "2290", "name": "other", "enabled": True,
                                                                         "domainNames": ["ehr.corp.example.com"], "tcpPortRanges": ["443", "443"]})
        return rec(result, undo_of)
    # Act
    r = pb.execute(cl, parts, plan_hash=c["plan_hash"], scope=ALL, writes_enabled=True, confirm_text=c["confirm_phrase"], assessor="Jane Doe",
                   record=record_then_move, settle_seconds=0)
    # Assert
    status = {s["key"]: s["status"] for s in r["steps"]}
    assert status == {"zia_baseline": "applied", "zpa_connector_group": "applied", "zpa_app_segments": "plan_changed"}
    assert r["status"] == "stopped" and r["undo_available"] is True
    assert not any(p.endswith("/application") for m, p in st.write_log() if m == "POST")


@pytest.mark.parametrize("change", ["phrase", "write_mode", "assessor"])
def test_the_gates_hold_inside_the_engine(change):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: a wrong typed phrase, write mode off or no assessor writes nothing."""
    # Arrange
    st, cl = tenant()
    parts = pb.clean_parts(parts_for("zia_baseline"))
    c = pb.plan(cl, parts, scope=ALL)
    kw = dict(plan_hash=c["plan_hash"], scope=ALL, writes_enabled=True, confirm_text=c["confirm_phrase"], assessor="Jane Doe", settle_seconds=0)
    # Act / Assert
    if change == "phrase":
        r = pb.execute(cl, parts, **dict(kw, confirm_text="APPLY 1 POV CHANGE"))
        assert r["status"] == "refused" and c["confirm_phrase"] in r["message"]
    elif change == "write_mode":
        with pytest.raises(PermissionError):
            pb.execute(cl, parts, **dict(kw, writes_enabled=None))
    else:
        with pytest.raises(pb.BuildError):
            pb.execute(cl, parts, **dict(kw, assessor=" "))
    assert st.write_log() == []


@pytest.mark.parametrize("raw,word", [
    ({}, "at least one"), ({"nope": {"type": "zia_baseline"}}, "Unknown part"),
    ({"zia_baseline": {"type": "zpa_policies"}}, "operation type"), ({"zia_baseline": "x"}, "must be an object"),
    ({"zpa_policies": {"type": "zpa_policies", "action": "undo"}}, "Undo"),
    ({"zpa_app_segments": {"type": "zpa_app_segments", "csv": "x" * (pb.MAX_SPEC_BYTES + 10)}}, "larger than"),
])
def test_a_request_is_checked_before_anything_is_read(raw, word):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unknown parts, a wrong type, an Undo form or an oversized part are refused with the reason."""
    with pytest.raises(pb.BuildError) as e:
        pb.clean_parts(raw)
    assert word in str(e.value)


# ── Defaults from the intake preset (data-driven) ─────────────────────────

def test_the_intake_preset_drives_the_defaults_and_a_new_preset_merges_as_data(monkeypatch):
    """ASVS V1.4.4 · CWE-1188: healthcare asks for the Healthcare tier with HIPAA; a preset added to the data (with its own build row) is offered and honoured without code."""
    # Arrange
    d = pb.defaults(INTAKE)
    monkeypatch.setitem(pov.VERTICALS, "qa_preset", {"label": "QA preset", "description": "A preset added as data.", "products": ["url_filtering", "zpa"],
                                                     "criteria": ["It works."], "build": {"tier": "strict", "overlays": ["CJIS"], "aiguard": "CJIS"}})
    # Act
    q = pb.defaults(dict(INTAKE, vertical="qa_preset", products=["url_filtering", "zpa"]))
    cat = pov.catalog()
    # Assert
    assert d["zia_baseline"]["spec"]["tier"] == "healthcare" and "HIPAA" in d["zia_baseline"]["spec"]["overlays"]
    assert d["zia_baseline"]["spec"]["enable_rules"] is False and d["zpa_app_segments"]["spec"]["enable"] is False
    assert d["aiguard_policy"]["spec"]["mode"] == "monitor"
    assert q["zia_baseline"]["spec"]["tier"] == "strict" and q["zia_baseline"]["spec"]["overlays"] == ["CJIS"]
    assert q["aiguard_policy"]["spec"]["profile"] == "CJIS" and q["zdx_probes"]["on"] is False
    assert "qa_preset" in [v["key"] for v in cat["verticals"]]
    assert pov.clean_intake({"customer": "Q", "vertical": "qa_preset"})["products"] == ["url_filtering", "zpa"]


# ── The routes: the live tenant (a fake behind the factory), the POV record, Undo ──

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "pov-build-secret-never-kept", "customer_id": "7200000000000001"}
SCOPE = {"scopes": ["dlp", "zia_extras", "zpa", "zcc", "zdx", "genai", "aiguard"],
         "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}, "from_page": True}


class _Job:
    def __init__(self, kind, result=None, error=""):
        self.id, self.kind, self.result, self.error = "sync-job", kind, result, error
        self.status = "failed" if error else "done"


@pytest.fixture
def live(tmp_path, monkeypatch):
    """An isolated app whose tenant client is the wire fake; jobs run in the request."""
    import dlp_api_server as srv
    import pack_jobs
    import security
    import tenant_profiles
    for var, name in (("DLP_CHECK_PROFILES", "profiles/tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_FINGERPRINT_KEY", "fp.key")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    jobs = []

    def sync_start(kind, fn, **_k):
        try:
            job = _Job(kind, fn(lambda line: None, threading.Event()))
        except Exception as e:  # noqa: BLE001
            job = _Job(kind, None, f"{type(e).__name__}: {e}")
        jobs.append(job)
        return job
    monkeypatch.setattr(pack_jobs, "start", sync_start)
    st, cl = tenant()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds.get("vanity_domain")) or cl)
    monkeypatch.setattr(security, "_write_override", True)
    pid = tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": CREDS["client_id"],
                                  "customer_id": CREDS["customer_id"]}, client_secret=CREDS["client_secret"], remember_secret=True)["id"]
    c = TestClient(srv.app)
    r = c.post("/api/pov/create", json=dict(CREDS, profile_id=pid, intake=INTAKE))
    assert r.status_code == 200, r.text
    return {"c": c, "st": st, "jobs": jobs, "pid": pid, "built": built}


def _body(live, **extra):
    return dict(CREDS, **SCOPE, profile_id=live["pid"], assessor="Jane Doe", **extra)


def test_the_route_previews_applies_records_on_the_pov_and_undoes(live):
    """ASVS V11.1.1 · V7.2.1 · CWE-841 · WSTG-BUSL-06: preview → one typed confirmation → every part applied and recorded (Bulk changes and the POV list it) → Undo restores the tenant."""
    # Arrange
    c, st = live["c"], live["st"]
    before = wf.semantic(st.state())
    raw = parts_for("zia_baseline", "zpa_connector_group", "zpa_app_segments", "zpa_policies")
    # Act
    prev = c.post("/api/pov/build/preview", json=_body(live, parts=raw))
    assert prev.status_code == 200, prev.text
    p = prev.json()
    job = c.post("/api/pov/build/apply/start", json=_body(live, parts=raw, plan_hash=p["plan_hash"], confirm=True, confirm_text=p["confirm_phrase"]))
    # Assert
    assert job.status_code == 200, job.text
    res = live["jobs"][-1].result
    assert res["status"] == "applied" and res["build_id"], res
    assert "rehearsal" not in p and p["parts_request"].keys() == raw.keys()
    stored = pov.require(live["pid"])[1]
    assert stored["builds"][-1]["id"] == res["build_id"] and all(s["operation_id"] for s in stored["builds"][-1]["steps"])
    assert {o["id"] for o in deployments.list_operations()} >= set(res["applied_operations"])
    assert CREDS["client_secret"] not in json.dumps(stored)
    up = c.post("/api/pov/build/undo/preview/start", json=_body(live, build_id=res["build_id"]))
    assert up.status_code == 200, up.text
    u = live["jobs"][-1].result
    assert u["undo"] is True and u["order"] == ["zpa_policies", "zpa_app_segments", "zpa_connector_group", "zia_baseline"]
    ua = c.post("/api/pov/build/undo/apply/start", json=_body(live, build_id=res["build_id"], plan_hash=u["plan_hash"], confirm=True,
                                                              confirm_text=u["confirm_phrase"]))
    assert ua.status_code == 200 and live["jobs"][-1].result["status"] == "applied", live["jobs"][-1].result
    assert wf.semantic(st.state()) == before
    again = c.post("/api/pov/build/undo/preview/start", json=_body(live, build_id=res["build_id"]))
    assert again.status_code == 409 and "already undone" in again.text


def test_a_part_out_of_scope_is_refused_before_sign_in(live):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a part whose product is not ticked on the Scope page is a 400 naming it, before any client is built."""
    # Arrange
    c = live["c"]
    body = _body(live, parts=parts_for("zcc_profiles"))
    body["scopes"] = ["dlp", "zia_extras"]
    # Act
    r = c.post("/api/pov/build/preview", json=body)
    # Assert
    assert r.status_code == 400 and r.json()["detail"].startswith("Client Connector profiles:")
    assert live["built"] == []


def test_the_live_build_needs_the_profiles_pov(live):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a live build belongs to the profile's POV: a profile without one is refused before sign-in."""
    # Arrange
    import tenant_profiles
    c = live["c"]
    other = tenant_profiles.upsert({"name": "Acme 2", "cloud": "production", "vanity_domain": "acme", "client_id": "abc999999999",
                                    "customer_id": CREDS["customer_id"]}, client_secret="x" * 12, remember_secret=True)["id"]
    # Act
    r = c.post("/api/pov/build/preview", json=dict(_body(live, parts=parts_for("zia_baseline")), profile_id=other))
    # Assert
    assert r.status_code == 404 and "no POV" in r.text
    assert live["built"] == []


@pytest.mark.parametrize("drop", ["confirm", "plan_hash", "assessor", "write_mode"])
def test_the_route_refuses_an_apply_without_each_gate(live, monkeypatch, drop):
    """ASVS V4.1.3 · V4.1.5 · CWE-284 · WSTG-ATHZ-02: without confirm, the plan hash, the assessor or write mode the build is refused before sign-in and nothing is written."""
    # Arrange
    import security
    c = live["c"]
    body = _body(live, parts=parts_for("zia_baseline"), plan_hash="a" * 64, confirm=True, confirm_text="APPLY 1 POV CHANGE")
    if drop == "write_mode":
        monkeypatch.setattr(security, "_write_override", False)
    elif drop == "assessor":
        body["assessor"] = ""
    else:
        body[drop] = False if drop == "confirm" else ""
    # Act
    r = c.post("/api/pov/build/apply/start", json=body)
    # Assert
    assert r.status_code in (400, 403), r.text
    assert live["built"] == [] and live["st"].write_log() == []
