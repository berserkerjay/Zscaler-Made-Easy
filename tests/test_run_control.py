"""A deploy or removal never looks hung, and never grinds on against a
tenant that refuses everything.

- Run control (pack_ops.run_scope): the first refusal no later write can
  get past — the portal's edit lock, the exhausted hourly request limit,
  refused credentials — stops the run at once; every later write comes
  back "not attempted" without touching the tenant, the reason is in
  words, and the result says `stopped`. The operator's Stop does the same.
- A create refused as a duplicate the plan did not see reuses the existing
  object instead of failing everything behind it; a pack dictionary named
  like a predefined dictionary's display name is a conflict in the plan.
- Background jobs (pack_jobs, the /start and /jobs endpoints): the browser
  follows the log while the tenant is written to and gets the result at
  the end; the SDK client is built with bounded waits.
"""
from __future__ import annotations

import json
import os
import shutil
import threading
import time

import pytest

import pack_deploy as pd
import pack_jobs
import pack_ops as ops
import pack_removal as pr
from dlp_importer import discover_packs
from test_pack_channels import TENANTS, add_control_services, make_client
from test_pack_deploy import Obj
from test_zia_contract import strict_tenant

EDIT_LOCK = {"status": 409, "code": "EDIT_LOCK_NOT_AVAILABLE",
             "message": "EDIT_LOCK_NOT_AVAILABLE: Another admin session holds the edit lock for this tenant"}
RETRY_TOO_LONG = "RetryTooLong: Retry wait time 3421 seconds exceeds configured maxRetrySeconds 30."


def _pack(pid):
    return next({"id": p["id"], "dir": p["dir"]} for p in discover_packs() if p["id"] == pid)


# ---------------------------------------------------------------------------
# Run control
# ---------------------------------------------------------------------------

def test_fatal_refusals_are_explained_in_words_and_object_refusals_are_not():
    assert "edit lock" in ops.fatal_reason(EDIT_LOCK["message"]) and "Sign out of the portal" in ops.fatal_reason("409 edit lock held")
    limit = ops.fatal_reason(RETRY_TOO_LONG)
    assert "request limit for this hour" in limit and "57 minutes" in limit and "already written is kept" in limit
    assert "credentials" in ops.fatal_reason("401 Unauthorized - token refresh attempts exhausted or OAuth not available.")
    assert "DLP policy write permission" in ops.fatal_reason("403 Forbidden")
    for per_object in ("Duplicate DLP dictionary names are not allowed. [X].", "Request body is invalid.", "Channel is mandatory",
                       "Name exceeds the max length 31 characters", "rate limit exceeded, try again", None, ""):
        assert ops.fatal_reason(per_object) is None, per_object


def test_the_first_fatal_refusal_stops_every_later_write_inside_a_run():
    calls = []

    def fn(**kw):
        calls.append(kw)
        return None, None, EDIT_LOCK

    logs = []
    with ops.run_scope():
        first = ops.call(fn, op="create", kind="dictionary", name="a", log=logs.append, kw={"n": 1})
        second = ops.call(fn, op="create", kind="dictionary", name="b", log=logs.append, kw={"n": 2})
        assert not first.ok and first.code == "EDIT_LOCK_NOT_AVAILABLE" and first.http_status == 409
        assert second.code == ops.STOPPED and second.error.startswith("not attempted: Someone is signed in to the ZIA Admin Portal")
        assert "edit lock" in ops.stop_reason()
    assert len(calls) == 1, "the second write was never sent"
    assert any(l.startswith("STOPPED — nothing more is written.") for l in logs) and sum(l.startswith("STOPPED") for l in logs) == 1
    assert ops.stop_reason() is None, "the stop does not outlive the run"
    # Outside a run (direct calls, older callers) nothing is held back.
    assert ops.call(fn, op="create", kind="dictionary", name="c").code == "EDIT_LOCK_NOT_AVAILABLE" and len(calls) == 2


def test_the_hourly_limit_stops_the_run_with_the_wait_in_minutes():
    def fn(**kw):
        raise RuntimeError(RETRY_TOO_LONG)

    with ops.run_scope():
        out = ops.call(fn, op="create", kind="engine", name="e")
        assert not out.ok and "57 minutes" in ops.stop_reason()
        assert ops.call(fn, op="create", kind="engine", name="f").code == ops.STOPPED


def test_cancel_stops_the_next_write_without_sending_it():
    calls = []
    cancel = threading.Event()

    def fn(**kw):
        calls.append(1)
        return Obj(id=1), None, None

    logs = []
    with ops.run_scope(cancel):
        assert ops.call(fn, op="create", kind="dictionary", name="a", log=logs.append).ok
        cancel.set()
        out = ops.call(fn, op="create", kind="dictionary", name="b", log=logs.append)
        assert out.code == ops.STOPPED and out.error == "not attempted: " + ops.CANCELLED_REASON
        assert ops.stop_reason() == ops.CANCELLED_REASON, "the result's `stopped` says the operator stopped it"
        ops.call(fn, op="create", kind="dictionary", name="c", log=logs.append)
    assert calls == [1] and logs == ["STOPPED — nothing more is written. " + ops.CANCELLED_REASON], "said once"


def test_a_stopped_deploy_reports_itself_as_stopped_not_as_a_success():
    client = strict_tenant()
    cancel = threading.Event()
    real_add = client.zia.dlp_dictionary.add_dict

    def add_dict(name, match_type, dict_type, **kw):
        out = real_add(name, match_type, dict_type, **kw)
        cancel.set()      # the operator clicks Stop right after the first write
        return out
    client.zia.dlp_dictionary.add_dict = add_dict
    pack = _pack("zbp_enterprise_baseline")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, cancel=cancel)
    assert res["stopped"] == ops.CANCELLED_REASON and res["summary"]["created"] == 1 and res["summary"].get("failed", 0) == 0
    assert res["summary"]["skipped"] >= 10 and all(r["reason"].startswith("not attempted: You clicked Stop") for r in res["results"] if r["status"] == "skipped")
    assert res["activation"] is not None, "what was written is still activated"


def test_a_stopped_write_is_recorded_as_skipped_not_failed():
    rec = ops.Recorder(run="deploy")
    entry = rec.record("engine", "E", "failed", op="create", outcome=ops.Outcome(False, error="not attempted: you stopped the run", code=ops.STOPPED),
                       error="not attempted: you stopped the run")
    assert entry["status"] == "skipped" and entry["reason"] == "not attempted: you stopped the run" and "error" not in entry
    assert rec.events[-1]["status"] == "skipped"


def test_a_deploy_against_a_locked_tenant_stops_at_the_first_write_and_says_why():
    client = strict_tenant()
    z = client.zia
    attempts = []

    def add_dict(name, match_type, dict_type, **kw):
        attempts.append(name)
        return None, None, EDIT_LOCK
    z.dlp_dictionary.add_dict = add_dict
    pack = _pack("cjis_policy_pack")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    logs = []
    started = time.monotonic()
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=logs.append)
    assert time.monotonic() - started < 10, "no waiting on a tenant that refuses everything"
    assert len(attempts) == 1, "one write was enough to know"
    assert z.dlp_engine.added == [] and z.dlp_web_rules.added == [] and z.endpoint_dlp_rules.added == []
    assert res["status"] == "failed" and "edit lock" in res["stopped"] and "Sign out of the portal" in res["stopped"]
    assert res["summary"]["failed"] == 1 and res["summary"]["skipped"] >= 60, res["summary"]
    skipped = [r for r in res["results"] if r["status"] == "skipped"]
    assert all(r["reason"].startswith("not attempted: Someone is signed in") or r["reason"].startswith("dependency failed") for r in skipped)
    assert sum(1 for r in skipped if r["reason"].startswith("not attempted")) >= 50
    assert any(l.startswith("STOPPED — nothing more is written. Someone is signed in") for l in logs)
    assert not res["activation"], "nothing was written, so nothing is activated"


def test_a_removal_against_a_locked_tenant_stops_and_reports_what_was_never_tried():
    client = strict_tenant()
    z = client.zia
    pack = _pack("zbp_enterprise_baseline")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)["summary"].get("failed", 0) == 0
    deletes = []
    for svc in (z.dlp_web_rules, z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules):
        def refuse(*a, _svc=svc, **kw):
            deletes.append(_svc)
            return None, None, EDIT_LOCK
        svc.delete_rule = refuse
    plan = pr.plan_removal(client, [pack])
    logs = []
    out = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, log=logs.append)
    assert len(deletes) == 1 and "edit lock" in out["stopped"]
    assert out["summary"].get("deleted", 0) == 0 and out["summary"]["failed"] == 1
    assert out["summary"]["skipped"] == plan["remove_count"] - 1, out["summary"]
    assert all(r["reason"].startswith("not attempted") for r in out["results"] if r["status"] == "skipped")
    assert z.dlp_engine.items and z.dlp_dictionary.items, "engines and dictionaries were never touched"
    assert out["status"] == "failed" and not out["verification"]["clean"]


# ---------------------------------------------------------------------------
# Duplicates the plan did not see, and names ZIA already shows
# ---------------------------------------------------------------------------

def test_a_duplicate_refusal_reuses_the_existing_object_so_its_dependents_are_built(monkeypatch):
    client = add_control_services(make_client(casb_tenants=TENANTS))
    pack = _pack("zbp_source_code_baseline")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    target = next(i["name"] for i in rep["items"] if i["kind"] == "dictionary" and i["status"] == "create")
    real_create = ops.create
    refused = []

    def create(zia, kind, payload, **kw):
        if kind == "dictionary" and payload["name"] == target and not refused:
            # Made in the portal between the plan and the write, under another case; ZIA refuses the duplicate.
            refused.append(payload["name"])
            zia.dlp_dictionary.items.append(Obj(id=4242, name=target.upper(), custom=True, custom_phrase_match_type=payload["custom_phrase_match_type"],
                                                dictionary_type="PATTERNS_AND_PHRASES", patterns=[], phrases=[]))
            return ops.Outcome(False, error=f"Duplicate DLP dictionary names are not allowed. [{target}].", code="INVALID_INPUT_ARGUMENT", http_status=400)
        return real_create(zia, kind, payload, **kw)
    monkeypatch.setattr(ops, "create", create)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    row = next(r for r in res["results"] if r["kind"] == "dictionary" and r["name"] == target)
    assert row["status"] == "reused" and row["id"] == 4242 and "already exists" in row["reason"]
    assert res["summary"].get("failed", 0) == 0 and not [r for r in res["results"] if str(r.get("reason", "")).startswith("dependency failed")]
    engines_using = [e for e in client.zia.dlp_engine.added if "4242" in str(e["engine_expression"])]
    assert engines_using, "the engine that references the dictionary was built on the existing id"


def test_a_pack_dictionary_named_like_a_predefined_display_name_is_a_conflict_in_the_plan(tmp_path):
    src = _pack("fed_policy_pack")
    shutil.copytree(src["dir"], tmp_path / "fed", ignore=shutil.ignore_patterns("*.pyc", "__pycache__"))
    dicts_path = tmp_path / "fed" / "configs" / "dlp_dictionaries.json"
    dicts = json.loads(dicts_path.read_text(encoding="utf-8"))
    clone = next(d for d in dicts if d["name"] == "Z-Private keys")
    clone["name"] = "Private Key"                     # the name the real tenant refused (CRED_LEAKAGE is shown as "Private Key")
    engines_path = tmp_path / "fed" / "configs" / "dlp_engines.json"
    engines_path.write_text(engines_path.read_text(encoding="utf-8").replace("D:Z-Private keys", "D:Private Key"), encoding="utf-8")
    dicts_path.write_text(json.dumps(dicts), encoding="utf-8")
    client = strict_tenant()
    rep = pd.preflight(client, [{"id": "fed", "dir": str(tmp_path / "fed")}], writes_enabled=True)
    item = next(i for i in rep["items"] if i["kind"] == "dictionary" and i["name"] == "Private Key")
    assert item["status"] == "conflict" and "predefined dictionaries under this name" in item["reason"] and "Rename" in item["reason"]
    res = pd.apply(client, [{"id": "fed", "dir": str(tmp_path / "fed")}], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert "Private Key" not in [d["name"] for d in client.zia.dlp_dictionary.added], "never sent: ZIA would refuse it"
    assert next(r for r in res["results"] if r["name"] == "Private Key")["status"] == "skipped"


def test_the_shipped_fed_pack_no_longer_uses_the_taken_name():
    names = [d["name"] for d in json.load(open(os.path.join(_pack("fed_policy_pack")["dir"], "configs", "dlp_dictionaries.json"), encoding="utf-8"))]
    assert "Private Key" not in names and "Z-Private keys" in names


def test_names_are_matched_the_way_zia_compares_them():
    client = add_control_services(make_client(casb_tenants=TENANTS))
    pack = _pack("zbp_enterprise_baseline")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    first = next(i for i in rep["items"] if i["kind"] == "dictionary" and i["status"] == "create")
    client.zia.dlp_dictionary.items.append(Obj(id=777, name="  " + first["name"].swapcase() + " ", custom=True))
    again = pd.preflight(client, [pack], writes_enabled=True)
    item = next(i for i in again["items"] if i["kind"] == "dictionary" and i["name"] == first["name"])
    assert item["status"] in ("reuse", "reuse_differs") and item["tenant"]["id"] == 777


# ---------------------------------------------------------------------------
# Background jobs
# ---------------------------------------------------------------------------

def test_a_job_streams_its_log_and_keeps_its_result():
    gate = threading.Event()

    def work(log, cancel):
        log("Phase 1: dictionaries")
        log("[dictionary] A: created")
        gate.wait(5)
        log("Read-back: all 1 object(s) present.")
        return {"status": "applied", "summary": {"created": 1}}
    job = pack_jobs.start("deploy", work, label="test")
    deadline = time.time() + 5
    while len(job.logs) < 2 and time.time() < deadline:
        time.sleep(0.02)
    snap = pack_jobs.snapshot(job)
    assert snap["status"] == "running" and snap["logs"] == ["Phase 1: dictionaries", "[dictionary] A: created"] and snap["next"] == 2 and "result" not in snap
    gate.set()
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    tail = pack_jobs.snapshot(job, since=2)
    assert tail["status"] == "done" and tail["logs"] == ["Read-back: all 1 object(s) present."] and tail["result"]["status"] == "applied" and tail["error"] is None
    assert pack_jobs.get(job.id) is job and pack_jobs.cancel(job.id) is False, "a finished job cannot be cancelled"


def test_a_cancelled_job_ends_as_cancelled_and_an_exception_as_failed():
    def work(log, cancel):
        cancel.wait(5)
        return {"status": "partial", "stopped": "you stopped the run"}
    job = pack_jobs.start("deploy", work)
    assert pack_jobs.cancel(job.id) is True and job.logs[-1].startswith("Stop requested")
    deadline = time.time() + 5
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    assert job.status == "cancelled" and pack_jobs.snapshot(job)["cancel_requested"]

    def boom(log, cancel):
        raise RuntimeError("the tenant vanished")
    job2 = pack_jobs.start("removal", boom)
    while job2.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.02)
    assert job2.status == "failed" and "the tenant vanished" in job2.error and job2.logs[-1].startswith("The run stopped with an error")
    assert pack_jobs.get("nope") is None and pack_jobs.cancel("nope") is False
    # Old finished jobs are forgotten; running ones never are.
    job2.finished -= pack_jobs.KEEP_SECONDS + 1
    assert pack_jobs.prune() >= 1 and pack_jobs.get(job2.id) is None


def _wait_job(c, job_id, timeout=90):
    since, logs = 0, []
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = c.get(f"/api/dlp-packs/jobs/{job_id}?since={since}")
        assert r.status_code == 200, r.text
        snap = r.json()
        logs += snap["logs"]
        since = snap["next"]
        if snap["status"] != "running":
            snap["logs"] = logs
            return snap
        time.sleep(0.05)
    raise AssertionError("the job did not finish in time")


def test_deploy_and_removal_run_as_jobs_the_browser_can_follow(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    import deployments
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    client = strict_tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    plan = c.post("/api/dlp-packs/preflight", json=dict(creds, pack_ids=["zbp_enterprise_baseline"])).json()
    assert c.post("/api/dlp-packs/apply/start", json=dict(creds, pack_ids=["zbp_enterprise_baseline"], plan_hash=plan["plan_hash"])).status_code == 400, "confirm is required"
    r = c.post("/api/dlp-packs/apply/start", json=dict(creds, pack_ids=["zbp_enterprise_baseline"], plan_hash=plan["plan_hash"], confirm=True, verify=False))
    assert r.status_code == 200 and r.json()["status"] == "running" and r.json()["kind"] == "deploy", r.text
    snap = _wait_job(c, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "applied" and snap["result"]["summary"]["created"] > 0, snap.get("error")
    assert "Phase 1: dictionaries" in snap["logs"] and any(l.startswith("Read-back:") for l in snap["logs"]) and snap["elapsed_seconds"] >= 0
    assert snap["result"]["deployment_id"] and snap["result"]["stopped"] is None
    assert deployments.list_all()[0]["packs"] == ["zbp_enterprise_baseline"]
    assert c.post(f"/api/dlp-packs/jobs/{r.json()['job_id']}/cancel").json()["cancelled"] is False, "finished jobs cannot be cancelled"
    assert c.get("/api/dlp-packs/jobs/nope").status_code == 404
    # The removal of that deployment, the same way.
    rm = c.post("/api/dlp-packs/removal/apply/start", json=dict(creds, deployment_id=snap["result"]["deployment_id"], confirm=True))
    assert rm.status_code == 200 and rm.json()["kind"] == "removal", rm.text
    done = _wait_job(c, rm.json()["job_id"])
    assert done["status"] == "done" and done["result"]["status"] == "removed" and done["result"]["verification"]["clean"], done.get("error")
    assert done["result"]["deployment"]["remaining"] == 0 and done["result"]["stopped"] is None
    assert client.zia.dlp_web_rules.items == [] and client.zia.dlp_engine.items == []
    # A stale plan is a result, not an exception, so the page can show it.
    stale = c.post("/api/dlp-packs/removal/apply/start", json=dict(creds, pack_ids=["zbp_enterprise_baseline"], plan_hash="stale", confirm=True))
    assert _wait_job(c, stale.json()["job_id"])["result"]["status"] in ("stale", "nothing")


def test_the_sdk_client_is_built_with_bounded_waits(monkeypatch):
    zscaler = pytest.importorskip("zscaler")
    import dlp_api_server as srv
    seen = {}

    class Client:
        def __init__(self, config):
            seen.update(config)

        def authenticate(self):
            return True
    monkeypatch.setattr(zscaler, "ZscalerClient", Client)
    srv._build_sdk_client({"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"})
    assert seen["requestTimeout"] == srv.SDK_REQUEST_TIMEOUT == 90
    assert seen["rateLimit"] == {"maxRetries": 2, "maxRetrySeconds": 30}, "a Retry-After of an hour is not slept through"
    assert "cloud" not in seen, "a commercial cloud sends no OneAPI cloud"


# ---------------------------------------------------------------------------
# The page
# ---------------------------------------------------------------------------

def test_the_deploy_studio_follows_jobs_and_forgets_channel_choices_between_visits():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    for needle in ("/api/dlp-packs/apply/start", "/api/dlp-packs/removal/apply/start", "/api/dlp-packs/jobs/", "_dzCancelJob", "dzJobLog", "dzJobElapsed",
                   "_dzUntickedChannels", "X.stopped", "data.stopped"):
        assert needle in js, needle
    assert "fetch('/api/dlp-packs/apply'" not in js and "fetch('/api/dlp-packs/removal/apply'" not in js, "the page no longer waits on one long request"
    assert "localStorage.setItem(DZ_LS_CHANNELS" not in js and "localStorage.removeItem(DZ_LS_CHANNELS)" in js, "no channel choice survives a page reload"
    css = open(os.path.join(root, "static", "deploy_studio.css"), encoding="utf-8").read()
    assert ".dz-log-live" in css and ".dz-gates li.warn" in css
