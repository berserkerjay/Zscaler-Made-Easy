"""The same Client Connector device removal across several saved tenants:
one plan per tenant, each with its own hash, typed phrase, record and result,
a failure in one tenant leaving the others, and every cap per tenant.
Fakes only (tests/admin_fakes.py): no network, no real tenant."""
from __future__ import annotations

import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import dlp_api_server as srv  # noqa: E402
import ops_zcc_admin as zc  # noqa: E402
import security  # noqa: E402
from conftest import read_store_text  # noqa: E402
import team_routes  # noqa: E402
from admin_fakes import ZccClient  # noqa: E402

SPEC = {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]}
BASE = {"scopes": ["zcc"], "channels": {}, "from_page": True, "assessor": "Jane Doe"}


@pytest.fixture()
def tenants(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(security, "_write_override", True)
    monkeypatch.setattr(zc, "_LEDGER", {})   # an empty hourly call budget: calls counted by earlier tests in the same hour do not leak in
    fakes = {}
    for pid in ("acme", "beta", "gamma"):
        c = ZccClient()
        c.tenant.seed()
        fakes[pid] = c
    broken = set()

    def creds(req):
        return {"cloud": "", "vanity_domain": req.profile_id, "client_id": "abc123456789", "client_secret": "secret-secret-secret",
                "auth_method": "oneapi", "customer_id": ""}

    def build(c):
        if c["vanity_domain"] in broken:
            raise RuntimeError("sign-in refused for this tenant")
        return fakes[c["vanity_domain"]]

    monkeypatch.setattr(srv, "_tenant_creds", creds)
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(srv, "_offline_creds", lambda: None)
    fakes["broken"] = broken
    return fakes, TestClient(srv.app), tmp_path


def preview(api, ids, op=SPEC):
    r = api.post("/api/operations/zcc/multi-remove/preview", json=dict(BASE, profile_ids=ids, operation=op))
    assert r.status_code == 200, r.text
    return {t["profile_id"]: t for t in r.json()["tenants"]}


def test_one_plan_per_tenant_each_with_its_own_hash_and_phrase(tenants):
    """ASVS V4.1.3 · CWE-841 · WSTG-BUSL-01: each tenant is planned and shown on its own with its own plan_hash and typed phrase; nothing is written."""
    fakes, api, _ = tenants
    rows = preview(api, ["acme", "beta"])
    assert set(rows) == {"acme", "beta"}
    for pid, row in rows.items():
        assert row["plan"]["confirm_phrase"] == "REMOVE 1 DEVICE" and row["plan"]["plan_hash"] and row["status"] == "ready"
        assert fakes[pid].tenant.writes == []
    # a different device state in one tenant gives that tenant a different hash
    fakes["beta"].tenant.devices[0]["registrationState"] = "Removal Pending"
    again = preview(api, ["acme", "beta"])
    assert again["acme"]["plan"]["plan_hash"] == rows["acme"]["plan"]["plan_hash"]
    assert again["beta"]["plan"]["plan_hash"] != rows["beta"]["plan"]["plan_hash"]


def test_a_failing_tenant_does_not_touch_the_others_in_preview_or_apply(tenants):
    """ASVS V4.1.3 · CWE-754 · WSTG-BUSL-01: a tenant that cannot sign in, has a wrong hash or a wrong phrase fails alone; the others apply, are recorded and audited."""
    fakes, api, tmp = tenants
    rows = preview(api, ["acme", "beta", "gamma"])
    fakes["broken"].add("gamma")
    rows2 = preview(api, ["acme", "beta", "gamma"])
    assert rows2["gamma"]["status"] == "failed" and "sign-in refused" in rows2["gamma"]["message"] and rows2["acme"]["status"] == "ready"
    fakes["broken"].clear()
    body = dict(BASE, profile_ids=["acme", "beta", "gamma"], operation=SPEC, confirm=True, tenants=[
        {"profile_id": "acme", "plan_hash": rows["acme"]["plan"]["plan_hash"], "confirm_text": "remove 1 device"},
        {"profile_id": "beta", "plan_hash": "0" * 64, "confirm_text": "remove 1 device"},
        {"profile_id": "gamma", "plan_hash": rows["gamma"]["plan"]["plan_hash"], "confirm_text": "nope"}])
    r = api.post("/api/operations/zcc/multi-remove/apply", json=body)
    assert r.status_code == 200, r.text
    out = {t["profile_id"]: t for t in r.json()["tenants"]}
    assert out["acme"]["status"] == "applied" and out["acme"].get("operation_id")
    assert out["beta"]["status"] in ("plan_changed", "refused", "blocked") and out["gamma"]["status"] == "refused"
    assert [w[0] for w in fakes["acme"].tenant.writes] == ["remove"]
    assert fakes["beta"].tenant.writes == [] and fakes["gamma"].tenant.writes == []
    audit = read_store_text(tmp / "audit.log")
    assert "VMW-1:AAA" in audit
    ops = api.get("/api/operations").json()["operations"]
    assert len(ops) == 1


def test_apply_needs_confirm_and_a_hash_for_each_tenant(tenants):
    """ASVS V4.1.3 · CWE-352 · CWE-285: no confirm, or a tenant without its own plan_hash, is refused before any sign-in; write mode off is refused."""
    fakes, api, _ = tenants
    base = dict(BASE, profile_ids=["acme"], operation=SPEC)
    assert api.post("/api/operations/zcc/multi-remove/apply", json=dict(base, tenants=[{"profile_id": "acme", "plan_hash": "x"}])).status_code == 400
    assert api.post("/api/operations/zcc/multi-remove/apply", json=dict(base, confirm=True, tenants=[{"profile_id": "acme"}])).status_code == 400
    security._write_override = False
    r = api.post("/api/operations/zcc/multi-remove/apply", json=dict(base, confirm=True, tenants=[{"profile_id": "acme", "plan_hash": "x", "confirm_text": "y"}]))
    out = r.json()["tenants"][0] if r.status_code == 200 else {"status": r.status_code}
    assert out["status"] in ("refused", "failed", 403) and fakes["acme"].tenant.writes == []


def test_caps_stay_per_tenant(tenants):
    """ASVS V4.1.3 · CWE-770 · WSTG-BUSL-05: at most MAX_TENANTS tenants; the per-call cap applies to each tenant's plan; the hourly budget is counted per tenant."""
    fakes, api, _ = tenants
    r = api.post("/api/operations/zcc/multi-remove/preview", json=dict(BASE, profile_ids=[f"t{i}" for i in range(zc.MAX_TENANTS + 1)], operation=SPEC))
    assert r.status_code == 400
    r = api.post("/api/operations/zcc/multi-remove/preview", json=dict(BASE, profile_ids=["acme", "acme"], operation=SPEC))
    assert r.status_code == 400
    r = api.post("/api/operations/zcc/multi-remove/preview", json=dict(BASE, profile_ids=["acme"], operation={"type": "rule_state"}))
    assert r.status_code == 400
    big = dict(SPEC, devices=[{"udid": f"U{i}", "user": "jdoe@acme.com"} for i in range(zc.MAX_DEVICES + 1)])
    rows = preview(api, ["acme", "beta"], big)
    assert all(t["status"] == "refused" and "Pick 1 to 25" in t["message"] for t in rows.values()) or all(t["status"] == "refused" for t in rows.values())
    zc.note_calls(fakes["acme"], 90)
    assert zc.budget(fakes["acme"])["remaining"] == 10 and zc.budget(fakes["beta"])["remaining"] == zc.ZCC_CALLS_PER_HOUR


def test_multi_routes_have_team_rules_and_pass_the_batch_cap(tenants):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: the routes carry a team_routes rule (plan and apply); the list removal keeps BATCH_MAX per tenant."""
    assert team_routes.ROUTE_RULES["POST /api/operations/zcc/multi-remove/preview"] == team_routes.PLAN
    assert team_routes.ROUTE_RULES["POST /api/operations/zcc/multi-remove/apply"] == team_routes.APPLY
    fakes, api, _ = tenants
    op = {"type": zc.T_BULK, "mode": "remove", "batch_size": zc.BATCH_MAX + 1, "devices": SPEC["devices"]}
    rows = preview(api, ["acme"], op)
    assert rows["acme"]["status"] == "refused" and "batch size" in rows["acme"]["message"]
    assert json.dumps(rows).count("secret-secret") == 0


# ── offline planning against a saved snapshot, then a live re-plan ───────

def _snapshot(state_of_first="Registered"):
    import copy
    import offline_tenant as ot
    import sample_tenant
    responses = {ot.normalize_path(p): {"status": 200, "body": copy.deepcopy(b)} for p, b in sample_tenant.responses().items()}
    key = ot.normalize_path(f"{sample_tenant.ZCC}/getDevices")
    responses[key]["body"][0]["registrationState"] = state_of_first
    return ot.OfflineStore("snap-test0001", "snapshot", responses, {"tenant_label": "Saved copy", "saved_at": "2026-11-01"}, writable=False)


OFFLINE_SPEC = {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "LKF-WIN-0001", "user": "avery.quinn@larkspur-freight.example"}]}


def test_offline_plan_reads_the_snapshot_only_and_its_hash_follows_the_devices():
    """ASVS V4.1.3 · CWE-841 · WSTG-BUSL-01: a removal planned on a snapshot contacts no tenant, is marked offline and not appliable, and its hash differs when the devices differ."""
    import offline_tenant as ot
    a = ot.plan_remove(_snapshot(), OFFLINE_SPEC)
    assert a["offline"]["applies"] is False and a["counts"]["change"] == 1 and a["confirm_phrase"] == "REMOVE 1 DEVICE"
    assert "no tenant was contacted" in a["notes"][0]
    assert ot.plan_remove(_snapshot(), OFFLINE_SPEC)["plan_hash"] == a["plan_hash"]
    b = ot.plan_remove(_snapshot("Removal Pending"), OFFLINE_SPEC)
    assert b["plan_hash"] != a["plan_hash"] and b["counts"]["change"] == 0
    with pytest.raises(ot.OfflineError):
        ot.plan_remove(_snapshot(), {"type": "rule_state"})


def test_the_offline_hash_cannot_be_applied_and_the_live_replan_names_what_changed():
    """ASVS V4.1.3 · CWE-345 · WSTG-BUSL-01: the offline plan_hash never matches a live apply; replan_live shows the devices that differ and hands back the live hash."""
    import admin_ops as ao
    import offline_tenant as ot
    off = ot.plan_remove(_snapshot(), OFFLINE_SPEC)
    live = ZccClient()
    live.tenant.seed()
    spec = {"type": zc.T_REMOVE, "mode": "remove", "devices": [{"udid": "VMW-1:AAA", "user": "jdoe@acme.com"}]}
    ao.load_plugins()
    lp = ao.plan(live, spec, scope=ao.scope_for(["zcc"], {}), tenant_label="acme")
    r = ot.replan_live(off, lp)
    assert r["same"] is False and r["changed"] and r["apply_hash"] == lp["plan_hash"] and r["offline_hash"] != lp["plan_hash"]
    res = ao.execute(live, spec, plan_hash=off["plan_hash"], scope=ao.scope_for(["zcc"], {}), writes_enabled=True, assessor="Jane Doe", confirm_text="REMOVE 1 DEVICE")
    assert res["status"] != "applied" and live.tenant.writes == []
    same = ot.replan_live(ot.plan_remove(_snapshot(), OFFLINE_SPEC), ot.plan_remove(_snapshot(), OFFLINE_SPEC) | {"plan_hash": off["live_hash"]})
    assert same["same"] is True and not same["changed"]


def test_the_sample_tenant_takes_remove_and_force_remove_in_memory_only():
    """ASVS V4.1.3 · CWE-841: removeDevices marks a sample device Removal Pending and forceRemoveDevices drops it, in memory; a snapshot refuses both."""
    import offline_tenant as ot
    st = ot.sample_store(reset=True)
    code, body = st.answer_write("POST", "/zcc/papi/public/v1/removeDevices", {"udids": ["LKF-WIN-0001"]})
    assert code == 200 and body["devicesRemoved"] == 1
    states = {d["udid"]: d["registrationState"] for d in st.answer_get("/zcc/papi/public/v1/getDevices")[1]}
    assert states["LKF-WIN-0001"] == "Removal Pending"
    code, body = st.answer_write("POST", "/zcc/papi/public/v1/forceRemoveDevices", {"udids": ["LKF-WIN-0001"]})
    assert code == 200 and "LKF-WIN-0001" not in {d["udid"] for d in st.answer_get("/zcc/papi/public/v1/getDevices")[1]}
    assert _snapshot().answer_write("POST", "/zcc/papi/public/v1/removeDevices", {"udids": ["LKF-WIN-0001"]})[0] == 403
    ot.sample_store(reset=True)


def test_not_ticked_zcc_is_refused_before_any_sign_in(tenants, monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZCC ticked on the Scope page the preview and the apply are refused 400 before any tenant is signed in to."""
    fakes, api, _ = tenants
    signed = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: signed.append(c) or fakes["acme"])
    body = dict(BASE, scopes=["zpa"], profile_ids=["acme"], operation=SPEC)
    assert api.post("/api/operations/zcc/multi-remove/preview", json=body).status_code == 400
    r = api.post("/api/operations/zcc/multi-remove/apply", json=dict(body, confirm=True, tenants=[{"profile_id": "acme", "plan_hash": "x"}]))
    assert r.status_code == 400 and signed == [] and fakes["acme"].tenant.reads == []
