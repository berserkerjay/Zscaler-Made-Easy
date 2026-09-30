"""Every tenant write and every run's ending is in the audit log.

- A background job (deploy, removal, Terraform hand-off) ends with one
  `job_finished` entry, whether it succeeded, failed or was cancelled:
  job id, kind, actor, tenant, plan_hash, final status, counts,
  activation, cancelled, duration. The HTTP entry of the /start call only
  says "200"; this is the evidence of what the job did.
- Every create / update / delete in pack_ops leaves one `object_write`
  entry: job id, tenant, action, object type, id, name, result
  (ok / failed / skipped), HTTP status and a short error. No request body.
- A synchronous run leaves the same object entries and one `run_finished`.
- A failure to write the audit log never fails the run.
"""
from __future__ import annotations

import json
import logging
import threading
import time

import pytest

import audit
import pack_channels as pc
import pack_deploy as pd
import pack_jobs
import pack_ops as ops
import pack_removal as pr
from dlp_importer import discover_packs
from test_zia_contract import strict_tenant

TENANT = "acme (zscalerten)"
EDIT_LOCK = {"status": 409, "code": "EDIT_LOCK_NOT_AVAILABLE",
             "message": "EDIT_LOCK_NOT_AVAILABLE: Another admin session holds the edit lock for this tenant"}


@pytest.fixture(autouse=True)
def _audit_log(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))


def _entries(event=None):
    rows = audit.tail(100000)
    return [r for r in rows if event is None or r.get("event") == event]


def _pack(pid="zbp_enterprise_baseline"):
    return next({"id": p["id"], "dir": p["dir"]} for p in discover_packs() if p["id"] == pid)


def _activates(monkeypatch):
    """The fake tenant has no activation endpoint; make it activate."""
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, seconds, log=None: "ACTIVE")


def _tenant():
    client = strict_tenant()
    client._zia_rate_label = TENANT   # as _build_sdk_client stamps it (zia_rate.attach_client)
    return client


def _run_job(kind, fn, **kw):
    job = pack_jobs.start(kind, fn, **kw)
    deadline = time.time() + 90
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    assert job.status != pack_jobs.RUNNING, "the job did not finish in time"
    return job


def _one_finished(job):
    rows = [r for r in _entries("job_finished") if r["job_id"] == job.id]
    assert len(rows) == 1, rows
    return rows[0]


def _expected_counts(summary):
    s = summary
    return {"created": s.get("created", 0), "updated": s.get("restored", 0) + s.get("modified", 0), "deleted": s.get("deleted", 0),
            "skipped": s.get("skipped", 0), "failed": s.get("failed", 0) + s.get("still_present", 0),
            "unchanged": s.get("reused", 0) + s.get("gone", 0)}


def _written(results):
    """(object_type, name) of every object the run created or overwrote."""
    return sorted((r["kind"], r["name"]) for r in results if r["status"] in ("created", "restored", "modified"))


def _check_one_ok_entry_per_object(writes, results):
    """One `ok` entry per object written. A write ZIA refused first and the
    run sent again (a SaaS rule placed at another order) is two requests,
    so two entries: the refusal is kept, for the same object."""
    ok = sorted((w["object_type"], w["name"]) for w in writes if w["result"] == "ok")
    assert ok == _written(results), "one ok entry per object written"
    assert all((w["object_type"], w["name"]) in ok for w in writes), "every other entry is an earlier try of an object written"


def test_a_successful_deploy_job_leaves_job_finished_and_one_object_write_per_object(monkeypatch):
    _activates(monkeypatch)
    client = _tenant()
    pack = _pack()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    box = {}

    def work(log, cancel):
        box["res"] = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=log, cancel=cancel)
        return box["res"]
    job = _run_job("deploy", work, label="zbp_enterprise_baseline", actor="alice@example.com")
    res = box["res"]
    assert job.status == "done" and res["status"] == "applied" and res["summary"]["created"] > 10

    fin = _one_finished(job)
    assert fin["kind"] == "deploy" and fin["status"] == "done" and fin["result_status"] == "applied"
    assert fin["actor"] == "alice@example.com" and fin["tenant"] == TENANT and fin["plan_hash"] == rep["plan_hash"]
    assert fin["counts"] == _expected_counts(res["summary"]) and fin["counts"]["failed"] == 0
    assert fin["cancelled"] is False and fin["error"] is None and fin["duration_seconds"] >= 0
    assert fin["activation"] == {"attempted": True, "activated": True, "status": "ACTIVE", "error": None}

    writes = [r for r in _entries("object_write") if r.get("job_id") == job.id]
    _check_one_ok_entry_per_object(writes, res["results"])
    by_name = {(w["object_type"], w["name"]): w for w in writes if w["result"] == "ok"}
    for r in res["results"]:
        if r["status"] == "created":
            w = by_name[(r["kind"], r["name"])]
            assert w["action"] == "create" and w["result"] == "ok" and str(w["id"]) == str(r["id"])
            assert w["tenant"] == TENANT and w["actor"] == "alice@example.com" and w["error"] is None
    assert not _entries("run_finished"), "a job's summary is its job_finished entry, not a second one"


def test_a_failed_job_leaves_job_finished_with_what_it_wrote_before_it_failed(monkeypatch):
    # A refusal: the job runs to its end, the deploy itself failed.
    client = _tenant()
    pack = _pack("cjis_policy_pack")
    client.zia.dlp_dictionary.add_dict = lambda *a, **kw: (None, None, EDIT_LOCK)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    box = {}

    def locked(log, cancel):
        box["res"] = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=log, cancel=cancel)
        return box["res"]
    job = _run_job("deploy", locked)
    res = box["res"]
    fin = _one_finished(job)
    assert fin["status"] == "done" and fin["result_status"] == "failed" and "edit lock" in fin["stopped"]
    assert fin["counts"] == _expected_counts(res["summary"]) and fin["counts"]["failed"] == 1 and fin["counts"]["created"] == 0
    assert fin["activation"] == {"attempted": False}
    writes = [r for r in _entries("object_write") if r.get("job_id") == job.id]
    failed = [w for w in writes if w["result"] == "failed"]
    assert len(failed) == 1 and failed[0]["http_status"] == 409 and "EDIT_LOCK" in failed[0]["error"] and failed[0]["action"] == "create"
    assert writes[1:] and all(w["result"] == "skipped" and w["error"].startswith("not attempted") for w in writes[1:]), \
        "writes the stopped run never sent are recorded as skipped"

    # An exception: the job fails; its entry still has the writes made before it.
    client = _tenant()
    pack = _pack()
    rep = pd.preflight(client, [pack], writes_enabled=True)

    def crash(zia):
        raise RuntimeError("activation service crashed")
    monkeypatch.setattr(pc, "activate", crash)
    job = _run_job("deploy", lambda log, cancel: pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False,
                                                          log=log, cancel=cancel))
    assert job.status == "failed"
    fin = _one_finished(job)
    writes = [r for r in _entries("object_write") if r.get("job_id") == job.id]
    assert fin["status"] == "failed" and fin["error"].startswith("RuntimeError: activation service crashed")
    assert fin["counts"]["created"] == sum(1 for w in writes if w["action"] == "create" and w["result"] == "ok") > 10
    assert fin["counts"]["failed"] == 0 and fin["tenant"] == TENANT and fin["plan_hash"] == rep["plan_hash"]


def test_a_cancelled_job_leaves_job_finished_marked_cancelled():
    client = _tenant()
    pack = _pack()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    real_add = client.zia.dlp_dictionary.add_dict
    box = {}

    def work(log, cancel):
        def add_dict(name, match_type, dict_type, **kw):
            out = real_add(name, match_type, dict_type, **kw)
            cancel.set()      # the operator clicks Stop right after the first write
            return out
        client.zia.dlp_dictionary.add_dict = add_dict
        box["res"] = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=log, cancel=cancel)
        return box["res"]
    job = _run_job("deploy", work)
    res = box["res"]
    assert job.status == "cancelled"
    fin = _one_finished(job)
    assert fin["status"] == "cancelled" and fin["cancelled"] is True and fin["stopped"] == ops.CANCELLED_REASON
    assert fin["counts"] == _expected_counts(res["summary"]) and fin["counts"]["created"] == 1 and fin["counts"]["skipped"] >= 10
    assert fin["activation"]["attempted"] is True, "what was written is still activated"
    writes = [r for r in _entries("object_write") if r.get("job_id") == job.id]
    assert [w["result"] for w in writes].count("ok") == 1 and writes[0]["result"] == "ok"
    assert all(w["result"] == "skipped" and w["http_status"] is None for w in writes[1:])


def test_a_synchronous_deploy_and_removal_leave_the_same_entries_and_run_finished(monkeypatch):
    _activates(monkeypatch)
    client = _tenant()
    pack = _pack()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    fin = _entries("run_finished")
    assert len(fin) == 1 and fin[0]["run"] == "deploy" and fin[0]["result_status"] == "applied" and fin[0]["tenant"] == TENANT
    assert fin[0]["counts"] == _expected_counts(res["summary"]) and fin[0]["plan_hash"] == rep["plan_hash"] and fin[0]["cancelled"] is False
    writes = _entries("object_write")
    _check_one_ok_entry_per_object(writes, res["results"])
    assert all("job_id" not in w or w["job_id"] is None for w in writes) and all(w["run"] == "deploy" for w in writes)

    plan = pr.plan_removal(client, [pack])
    out = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    assert out["status"] == "removed"
    fin = _entries("run_finished")
    assert len(fin) == 2 and fin[1]["run"] == "removal" and fin[1]["counts"] == _expected_counts(out["summary"])
    assert fin[1]["counts"]["deleted"] == plan["remove_count"] and fin[1]["activation"]["activated"] is True
    deletes = [w for w in _entries("object_write") if w["action"] == "delete"]
    assert len(deletes) == plan["remove_count"] and all(w["result"] == "ok" and w["id"] is not None for w in deletes)


def test_job_start_endpoints_carry_the_actor_and_no_secret(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    import dlp_api_server as srv
    import security
    from fastapi.testclient import TestClient
    client = _tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(security, "current_actor", lambda request: "alice@example.com", raising=False)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    plan = c.post("/api/dlp-packs/preflight", json=dict(creds, pack_ids=["zbp_enterprise_baseline"])).json()
    r = c.post("/api/dlp-packs/apply/start", json=dict(creds, pack_ids=["zbp_enterprise_baseline"], plan_hash=plan["plan_hash"], confirm=True, verify=False))
    assert r.status_code == 200, r.text
    job = pack_jobs.get(r.json()["job_id"])
    deadline = time.time() + 90
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    fin = _one_finished(job)
    assert fin["actor"] == "alice@example.com" and fin["status"] == "done" and fin["counts"]["created"] > 10
    assert all(w["actor"] == "alice@example.com" for w in _entries("object_write") if w.get("job_id") == job.id)
    text = open(audit.path(), encoding="utf-8").read()
    assert "secret-secret-secret" not in text, "no secret reaches the audit log"
    assert all(set(w) <= {"at", "event", "job_id", "tenant", "action", "object_type", "channel", "id", "name", "result", "http_status",
                          "error", "run", "actor"} for w in _entries("object_write")), "no request body in an object entry"
    # The Terraform hand-off writes nothing to the tenant and still leaves its entry.
    t = c.post("/api/dlp-packs/terraform/start", json={"pack_ids": ["zbp_enterprise_baseline"], "mode": "static"})
    tjob = pack_jobs.get(t.json()["job_id"])
    while tjob.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    tfin = _one_finished(tjob)
    assert tfin["kind"] == "terraform" and tfin["status"] == "done" and tfin["actor"] == "alice@example.com"
    assert set(tfin["counts"].values()) == {0}


def test_an_audit_log_that_cannot_be_written_never_fails_the_run(monkeypatch, tmp_path, caplog):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path))   # a directory: every append fails
    client = _tenant()
    pack = _pack()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    with caplog.at_level(logging.ERROR):
        res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
        job = _run_job("terraform", lambda log, cancel: {"status": "ready"})
    assert res["status"] == "applied" and job.status == "done"
    assert any("AUDIT WRITE FAILED" in r.getMessage() for r in caplog.records), "said loudly"

    def boom(*a, **kw):
        raise ValueError("disk on fire")
    monkeypatch.setattr(audit, "record", boom)
    client = _tenant()
    res = pd.apply(client, [pack], plan_hash=pd.preflight(client, [pack], writes_enabled=True)["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied"
