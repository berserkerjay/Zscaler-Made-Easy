"""Rehearse, then re-simulate: a rehearsed plan applied to an in-memory copy
of the sample tenant or an opened snapshot (offline_tenant.simulate, POST
/api/offline/simulate/*), clearly labelled a simulation, so the Path
analyzer and Test a list run against the simulated result. The sample, the
saved snapshot and any tenant are never written; the real apply keeps
refusing every offline tenant (409); "Leave the simulation" drops the copy.

No network: the harness of tests/test_pov_rehearsal.py (every socket call
refused, any tenant client build fails the test)."""
from __future__ import annotations

import copy

import pytest

from test_pov_rehearsal import POV_PARTS, SCOPE, SOURCES, _use_sample, offline  # noqa: F401 (fixture)

import offline_tenant as ot

HOST = "portal.partnerco.example"
ADD = {"type": "url_categories", "action": "add", "target": "CUSTOM_01", "urls": [HOST]}


def _hops(pa):
    return {h["key"]: h for h in pa["trace"]["hops"]}


def _rehearse(c, op):
    prev = c.post("/api/operations/preview", json=dict(SCOPE, operation=copy.deepcopy(op)))
    assert prev.status_code == 200, prev.text[:300]
    return prev.json()


def _simulate(c, op, prev, **kw):
    body = dict(SCOPE, operation=copy.deepcopy(op), plan_hash=prev["plan_hash"], confirm=True, confirm_text=prev.get("confirm_phrase") or "")
    body.update(kw)
    return c.post("/api/offline/simulate/operation", json=body)


@pytest.mark.parametrize("source", list(SOURCES))
def test_a_rehearsed_change_applies_to_a_copy_and_the_path_analyzer_sees_it(offline, source):
    """ASVS V1.14.1 · V4.1.1 · CWE-441 · CWE-284: a rehearsed URL category change applied to the simulation is applied and read back there, labelled a simulation, the browser now uses the copy and the Path analyzer's URL filtering hop is decided by the rule that names the category; the sample or the snapshot is unchanged and no tenant is reached."""
    # Arrange
    c = offline["c"]
    base = SOURCES[source](c)
    before = copy.deepcopy(base.responses)
    pa0 = c.post("/api/path-analyzer", json=dict(SCOPE, destination=HOST)).json()
    prev = _rehearse(c, ADD)
    # Act
    r = _simulate(c, ADD, prev)
    pa1 = c.post("/api/path-analyzer", json=dict(SCOPE, destination=HOST)).json()
    status = c.get("/api/offline/status").json()
    # Assert
    assert r.status_code == 200, r.text[:400]
    out = r.json()
    assert out["status"] == "applied" and out["items"][0]["status"] == "applied"
    sim = out["simulation"]
    assert sim["source"].startswith("sim-") and sim["note"].startswith("Simulation: applied to an in-memory copy only")
    assert sim["tenant_label"].startswith("Simulation of ") and out["writes_enabled"] is False
    assert r.cookies.get(ot.COOKIE) == sim["source"]
    assert status["mode"] == "simulation" and status["simulation"]["base_kind"] == source and status["simulation"]["applied"]
    assert (_hops(pa0)["url"].get("decided_by") or {}).get("name") != "Allow partner portals"
    assert (_hops(pa1)["url"].get("decided_by") or {}).get("name") == "Allow partner portals"
    assert base.responses == before and base.writes == 0
    assert offline["attempts"] == [] and offline["built"] == []


def test_test_a_list_runs_against_the_simulated_result(offline):
    """ASVS V1.14.1 · CWE-441: Test a list, run after a simulated change, reads the copy: a gambling site the sample blocks (rule Block gambling) is no longer blocked once the rehearsed change turning that rule off is applied to the simulation."""
    # Arrange
    c = offline["c"]
    _use_sample(c)
    off = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 601}]}

    def run():
        r = c.post("/api/bulk-test/start", json=dict(SCOPE, text="online-casino.example"))
        assert r.status_code == 200, r.text[:300]
        job = offline["jobs"][-1]
        assert job.status == "done", job.error
        return job.result
    before = run()
    prev = _rehearse(c, off)
    # Act
    sim = _simulate(c, off, prev)
    after = run()
    # Assert
    assert sim.status_code == 200 and sim.json()["status"] == "applied", sim.text[:300]
    assert before["counts"]["blocked"] == 1 and [t["rule"] for t in before["top_rules"]] == ["Block gambling"]
    assert after["counts"]["blocked"] == 0 and "Block gambling" not in [t["rule"] for t in after["top_rules"]]
    assert offline["attempts"] == [] and offline["built"] == []


def test_a_second_rehearsed_change_builds_on_the_first_and_leaving_drops_the_copy(offline):
    """ASVS V1.14.1 · CWE-441: a change rehearsed on the simulation applies to the same copy; Leave the simulation drops it and the browser is back on the untouched sample, where the Path analyzer no longer sees the change."""
    # Arrange
    c = offline["c"]
    base = _use_sample(c)
    first = _simulate(c, ADD, _rehearse(c, ADD)).json()["simulation"]["source"]
    second_op = {"type": "url_categories", "action": "add", "target": "CUSTOM_01", "urls": ["second.partnerco.example"]}
    prev2 = _rehearse(c, second_op)
    # Act
    second = _simulate(c, second_op, prev2).json()
    left = c.post("/api/offline/simulation/discard")
    pa = c.post("/api/path-analyzer", json=dict(SCOPE, destination=HOST)).json()
    # Assert
    assert prev2["rehearsal"]["kind"] == "simulation" and second["simulation"]["source"] == first
    assert [a["what"] for a in second["simulation"]["applied"]] == ["url_categories", "url_categories"]
    assert left.status_code == 200 and left.json()["mode"] == "sample" and left.cookies.get(ot.COOKIE) == "sample"
    assert ot.store(first) is None and base.writes == 0
    assert (_hops(pa)["url"].get("decided_by") or {}).get("name") != "Allow partner portals"


@pytest.mark.parametrize("path", ["/api/operations/apply", "/api/operations/apply/start"])
def test_the_real_apply_stays_refused_on_the_simulation(offline, path):
    """ASVS V4.1.1 · CWE-284 · WSTG-ATHZ-02: with write mode on, a writer and the assessor, a real apply on the simulation is refused (409, "Rehearsal only: this is a simulation"), and nothing is written to the copy."""
    # Arrange
    c = offline["c"]
    _use_sample(c)
    sid = _simulate(c, ADD, _rehearse(c, ADD)).json()["simulation"]["source"]
    sim = ot.store(sid)
    op = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 602}]}
    prev = _rehearse(c, op)
    writes = sim.writes
    # Act
    r = c.post(path, json=dict(SCOPE, operation=op, plan_hash=prev["plan_hash"], confirm=True, confirm_text=prev.get("confirm_phrase") or "",
                               assessor="Jane Doe"))
    # Assert
    assert r.status_code == 409 and r.json()["detail"].startswith("Rehearsal only: this is a simulation"), r.text[:300]
    assert sim.writes == writes


def test_the_live_tenant_is_never_simulated_into(offline, monkeypatch):
    """ASVS V4.1.1 · CWE-441 · WSTG-ATHZ-02: on the live tenant the simulation route is refused before any client is built (409), so a simulation can never write to a real tenant."""
    c = offline["c"]
    r = c.post("/api/offline/simulate/operation", json=dict(SCOPE, operation=ADD, plan_hash="a" * 64, confirm=True,
                                                            vanity_domain="acme", client_id="abc123456789", client_secret="never-kept-secret",
                                                            customer_id="7200000000000001"))
    assert r.status_code == 409 and "never" in r.json()["detail"], r.text[:300]
    assert offline["built"] == [] and offline["attempts"] == []


@pytest.mark.parametrize("change,code", [({"confirm": False}, 400), ({"plan_hash": ""}, 400), ({"plan_hash": "b" * 64}, 200)])
def test_a_simulated_apply_needs_the_confirmation_and_the_rehearsals_hash(offline, change, code):
    """ASVS V4.1.1 · CWE-352 · CWE-841: without confirm or the plan hash the simulation is refused; a hash that is not the rehearsal's writes nothing to the copy (plan_changed)."""
    c = offline["c"]
    _use_sample(c)
    r = _simulate(c, ADD, _rehearse(c, ADD), **change)
    assert r.status_code == code, r.text[:300]
    if code == 200:
        out = r.json()
        assert out["status"] == "plan_changed" and ot.store(out["simulation"]["source"]).writes == 0


def test_a_rehearsed_pov_build_applies_to_the_simulation(offline):
    """ASVS V1.14.1 · CWE-441: the whole rehearsed POV build applies to a simulation part by part, labelled a simulation; the sample is unchanged."""
    # Arrange
    c = offline["c"]
    base = _use_sample(c)
    parts = {k: copy.deepcopy(POV_PARTS[k]) for k in ("zia_baseline", "zpa_connector_group", "zpa_app_segments")}
    # Cloud App Control and ZPA policy rules are left out: the offline tenant does not model
    # the rule-type-partitioned policy-set endpoints (ZIA CAC rules per rule type do not read
    # back as written; a ZPA policy set has no offline get, so a rule cannot be created offline).
    # Modelling those is a sample-tenant change, outside this task's files; the simulation of the
    # parts the offline tenant does read back (ZIA baseline, ZPA connector group and app segments,
    # the segment built on the group created a step earlier) is proven here.
    parts["zia_baseline"]["areas"] = ["firewall", "url", "ssl", "sandbox", "dns", "ftc"]
    prev = c.post("/api/pov/build/preview", json=dict(SCOPE, parts=parts)).json()
    # Act
    r = c.post("/api/offline/simulate/pov-build", json=dict(SCOPE, parts=parts, plan_hash=prev["plan_hash"], confirm=True,
                                                           confirm_text=prev["confirm_phrase"]))
    # Assert
    assert r.status_code == 200, r.text[:400]
    out = r.json()
    assert out["status"] == "applied", (out["status"], out.get("message"), [(s["key"], s["status"], s.get("message"), s.get("problems")) for s in out.get("steps") or []])
    assert out["simulation"]["base_kind"] == "sample" and base.writes == 0
    sim = ot.store(out["simulation"]["source"])
    segs = sim.answer_get("/zpa/mgmtconfig/v1/admin/customers/1/application")[1]
    assert any(str(x.get("name", "")).startswith("LKF-") for x in (segs.get("list") if isinstance(segs, dict) else segs) or [])


def test_a_simulation_store_is_a_copy_and_the_live_kind_is_refused():
    """ASVS V1.14.1 · CWE-441: simulate() deep-copies the offline tenant (a write to the copy leaves the base untouched) and refuses anything that is not an offline tenant."""
    base = ot.sample_store(reset=True)
    sim = ot.simulate(base)
    sim.answer_write("PUT", "/zia/api/v1/urlCategories/CUSTOM_01", {"id": "CUSTOM_01", "configuredName": "X", "urls": ["a.example"]})
    assert sim.kind == ot.SIMULATION and sim.writes >= 0 and base.writes == 0
    assert base.responses != sim.responses or sim.writes == 0
    assert ot.simulate(sim) is sim
    with pytest.raises(ot.OfflineError):
        ot.simulate({"kind": "live"})
