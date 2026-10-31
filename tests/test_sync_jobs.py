"""Scheduled sync, done safely (sync_jobs.py, /api/sync-jobs/*, the change
queue's admin_operation requests): a run only reads and files one plan per
target for four-eyes approval; nothing is applied until a named writer
applies the approved request through the gates; a plan whose target
changed since is refused as stale; a newer run supersedes an older plan;
the schedule, the history and the notification.

No real tenant: the source and the targets are made-up sample tenants
(fake_rule_tenant.FakeStore) served to the real SDK services."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import change_queue
import dlp_api_server as srv
import security
import sync_jobs
import tenant_profiles

ao.load_plugins()
import ops_rule_csv as orc  # noqa: E402
from fake_rule_tenant import client as fake_client  # noqa: E402
from test_team_queue import _person, _sso_on, _wait  # noqa: E402

FW_PATH = "/zia/api/v1/firewallFilteringRules"
SECRETS = {"src": "SrcSecret-9f8e7d", "tgt": "TgtSecret-1a2b3c", "tgt2": "Tgt2Secret-4d5e6f"}


def _target_drift(resp):
    rules = resp[FW_PATH]
    rules[1]["description"] = "drifted in the target"


def _source_extra(resp):
    resp[FW_PATH].insert(2, {"id": 806, "order": 3, "rank": 7, "name": "SYNC-new rule", "state": "ENABLED", "action": "BLOCK_DROP",
                             "nwServices": [{"id": 41, "name": "QUIC"}]})


@pytest.fixture
def env(monkeypatch, tmp_path):
    for k, v in {"DLPCHECK_CHANGE_QUEUE_FILE": "change_requests.json", "DLPCHECK_SYNC_JOBS_FILE": "sync_jobs.json", "DLP_CHECK_AUDIT": "audit.log",
                 "DLP_CHECK_DEPLOYMENTS": "deployments.json", "DLP_CHECK_PROFILES": "tenant_profiles.json"}.items():
        monkeypatch.setenv(k, str(tmp_path / v))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.delenv("DLP_CHECK_FOUR_EYES", raising=False)
    monkeypatch.delenv("DLP_CHECK_NOTIFY", raising=False)
    monkeypatch.setattr(security, "_write_override", None)
    stores = {}
    built = []
    stores["src"] = fake_client(_source_extra, "src")
    stores["tgt"] = fake_client(_target_drift, "tgt")
    stores["tgt2"] = fake_client(None, "tgt2")
    for pid, scopes in (("src", ["zia_extras", "dlp"]), ("tgt", ["zia_extras", "dlp"]), ("tgt2", ["dlp"])):
        tenant_profiles.upsert({"name": pid.upper(), "cloud": "production", "vanity_domain": pid, "client_id": f"cid-{pid}-123456",
                                "auth_method": "oneapi", "scopes": scopes}, client_secret=SECRETS[pid], remember_secret=True, profile_id=pid)

    def build(creds):
        built.append(creds["vanity_domain"])
        return stores[creds["vanity_domain"]][1]
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    return {"stores": stores, "built": built, "deps": sync_jobs.Deps(build_client=build, tenant_key=srv._cq_tenant)}


def _job(**kw):
    base = {"name": "Firewall baseline", "source": {"kind": "profile", "id": "src"}, "targets": ["tgt"], "groups": ["zia_firewall"],
            "interval_hours": 0}
    base.update(kw)
    return base


def _writes(env, pid):
    return [w for w in env["stores"][pid][0].writes_seen]


# ── a run reads and plans; it never writes ─────────────────────────────
def test_a_run_files_a_plan_per_target_and_writes_to_no_tenant(env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: a sync run reads the source and the target and files a pending plan with its plan hash; no write is sent to any tenant."""
    job = sync_jobs.create_job(_job(), by="alice@example.com")
    run = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    assert run["status"] == "planned" and len(run["filed"]) == 1, run
    assert _writes(env, "src") == [] and _writes(env, "tgt") == []
    rec = change_queue.get(run["filed"][0])
    assert rec["status"] == "pending" and rec["kind"] == "admin_operation" and rec["requested_by"] == "alice@example.com"
    assert len(rec["plan_hash"]) == 64 and rec["payload"]["operation"]["type"] == "zia_rules_csv"
    got = {(i["status"], i["name"]) for i in rec["items"]}
    assert ("add", "SYNC-new rule") in got and ("update", "Allow office traffic") in got
    assert rec["summary"]["add"] == 1 and rec["summary"]["update"] == 1 and rec["summary"]["delete"] == 0
    hist = sync_jobs.get_job(job["id"])["history"]
    assert hist[0]["id"] == run["id"] and hist[0]["targets"][0]["request"] == rec["id"]


def test_a_target_without_the_policy_in_scope_is_not_read(env):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a target whose saved Scope page selection lacks the policy is reported and never signed in to or read."""
    job = sync_jobs.create_job(_job(targets=["tgt", "tgt2"]), by="alice@example.com")
    run = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    by = {t["profile"]: t for t in run["targets"]}
    assert by["tgt2"]["status"] == "not_in_scope" and "tgt2" not in env["built"]
    assert env["stores"]["tgt2"][0].gets == []
    assert by["tgt"]["status"] == "planned"


def test_deletes_are_planned_only_when_the_job_asks_and_only_within_the_selection(env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: without include_deletes nothing is deleted; with it and a prefix, only target rules with that prefix that the source lacks, and the plan needs DELETE <n> RULES."""
    env["stores"]["tgt"][0].responses[FW_PATH]["body"].insert(1, {"id": 807, "order": 2, "rank": 7, "name": "SYNC-old", "state": "ENABLED",
                                                                    "action": "ALLOW"})
    j1 = sync_jobs.create_job(_job(prefix="SYNC-"), by="alice@example.com")
    r1 = sync_jobs.run_job(j1["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    rec1 = change_queue.get(r1["filed"][0])
    assert rec1["summary"]["delete"] == 0 and rec1["payload"]["confirm_phrase"] == ""
    j2 = sync_jobs.create_job(_job(name="With deletes", prefix="SYNC-", include_deletes=True), by="alice@example.com")
    r2 = sync_jobs.run_job(j2["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    rec2 = change_queue.get(r2["filed"][0])
    assert [i["name"] for i in rec2["items"] if i["status"] == "delete"] == ["SYNC-old"]
    assert rec2["payload"]["confirm_phrase"] == "DELETE 1 RULES"
    assert _writes(env, "tgt") == []


def test_a_newer_run_supersedes_the_older_plan_and_an_unchanged_one_is_not_filed_twice(env):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: running again with the same target gives 'unchanged'; a target that changed gives a new plan and the older open request turns stale."""
    job = sync_jobs.create_job(_job(), by="alice@example.com")
    first = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    again = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    assert again["targets"][0]["status"] == "unchanged" and again["filed"] == []
    env["stores"]["tgt"][0].responses[FW_PATH]["body"][0]["description"] = "another drift"
    third = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    assert third["filed"] and third["targets"][0]["superseded"] == first["filed"]
    old = change_queue.get(first["filed"][0])
    assert old["status"] == "stale" and old["history"][-1]["action"] == "superseded"
    assert len(sync_jobs.get_job(job["id"])["history"]) == 3


# ── approval, apply through the gates, stale ───────────────────────────
def _team(monkeypatch):
    _sso_on(monkeypatch)
    return _person("alice@example.com", ["dlp-admins"]), _person("bob@example.com", ["dlp-admins"]), _person("reader@example.com", ["dlp-readers"])


SCOPE_BODY = {"scopes": ["zia_extras", "dlp"], "channels": {}, "from_page": True}


def _filed_via_api(alice, **kw):
    r = alice.post("/api/sync-jobs", json={**_job(**kw), **SCOPE_BODY})
    assert r.status_code == 200, r.text
    jid = r.json()["id"]
    r = alice.post(f"/api/sync-jobs/{jid}/run", json={})
    assert r.status_code == 200, r.text
    job = _wait(r.json()["job_id"])
    assert job.status == "done", (job.error, job.logs)
    run = job.result["run"]
    assert run["filed"], run
    return jid, run["filed"][0]


def test_nothing_applies_until_another_writer_approves_and_applies_through_the_gates(monkeypatch, env):
    """ASVS V4.1.1 · CWE-862 · WSTG-ATHZ-02: a sync plan cannot be applied while pending, its requester cannot approve it, and the approved plan applies only with write mode, the assessor and both typed confirmations; then it is read back and recorded with an Undo."""
    alice, bob, reader = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice)
    body = {"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob Reviewer"}
    assert bob.post(f"/api/change-queue/{rid}/apply", json=body).status_code == 409          # pending
    assert alice.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 403        # four-eyes
    assert reader.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 403       # not a writer
    assert bob.post(f"/api/change-queue/{rid}/approve", json={"comment": "ok"}).status_code == 200
    r = bob.post(f"/api/change-queue/{rid}/apply", json=body)
    assert r.status_code == 403 and "ENABLE_WRITE_ACTIONS" in r.json()["detail"]
    monkeypatch.setattr(security, "_write_override", True)
    assert bob.post(f"/api/change-queue/{rid}/apply", json={**body, "confirm": "yes"}).status_code == 400
    assert bob.post(f"/api/change-queue/{rid}/apply", json={**body, "assessor": ""}).status_code == 400
    assert _writes(env, "tgt") == []
    r = bob.post(f"/api/change-queue/{rid}/apply", json=body)
    assert r.status_code == 200, r.text
    job = _wait(r.json()["job_id"])
    assert job.status == "done", (job.error, job.logs)
    rec = change_queue.get(rid)
    assert rec["status"] == "applied" and rec["applied_by"] == "bob@example.com" and rec["decided_by"] == "bob@example.com"
    assert rec["result"]["operation_id"], "recorded on Bulk changes with an Undo"
    names = {x["name"]: x for x in env["stores"]["tgt"][0].responses[FW_PATH]["body"]}
    assert names["SYNC-new rule"]["state"] == "DISABLED", "a new rule arrives disabled"
    assert names["Allow office traffic"].get("description", "") == ""
    import deployments
    op = deployments.get_operation(rec["result"]["operation_id"])
    assert op["inverse"]["action"] == "undo" and op["by"] == "Bob Reviewer"


def test_a_plan_whose_target_changed_since_is_refused_as_stale(monkeypatch, env):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: the apply plans the target again; a different plan hash marks the request stale and nothing is written."""
    alice, bob, _reader = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice)
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200
    env["stores"]["tgt"][0].responses[FW_PATH]["body"][1]["description"] = "changed after the plan"
    monkeypatch.setattr(security, "_write_override", True)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob"})
    job = _wait(r.json()["job_id"])
    assert change_queue.get(rid)["status"] == "stale"
    assert [w for w in _writes(env, "tgt") if w[0] != "GET"] == []
    assert job.result["change_request"]["status"] == "stale"


def test_a_plan_with_deletes_needs_its_own_typed_phrase_before_sign_in(monkeypatch, env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: applying an approved sync plan that deletes needs DELETE <n> RULES typed too; without it nothing is signed in to."""
    env["stores"]["tgt"][0].responses[FW_PATH]["body"].insert(1, {"id": 807, "order": 2, "rank": 7, "name": "SYNC-old", "state": "ENABLED", "action": "ALLOW"})
    alice, bob, _reader = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice, prefix="SYNC-", include_deletes=True)
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200
    monkeypatch.setattr(security, "_write_override", True)
    env["built"].clear()
    body = {"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob"}
    r = bob.post(f"/api/change-queue/{rid}/apply", json=body)
    assert r.status_code == 400 and "DELETE 1 RULES" in r.json()["detail"] and env["built"] == []
    r = bob.post(f"/api/change-queue/{rid}/apply", json={**body, "confirm_text": "DELETE 1 RULES"})
    job = _wait(r.json()["job_id"])
    assert change_queue.get(rid)["status"] == "applied", job.logs
    assert "SYNC-old" not in {x["name"] for x in env["stores"]["tgt"][0].responses[FW_PATH]["body"]}


# ── jobs: who may, scope, schedule, notification, history ──────────────
def test_only_writers_manage_jobs_and_every_group_must_be_in_scope(monkeypatch, env):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a reader cannot create or run a job; a group whose policy is not ticked on the Scope page is a 400; a bad source or target is refused."""
    alice, _bob, reader = _team(monkeypatch)
    assert reader.post("/api/sync-jobs", json={**_job(), **SCOPE_BODY}).status_code == 403
    r = alice.post("/api/sync-jobs", json={**_job(), "scopes": ["dlp"], "from_page": True})
    assert r.status_code == 400 and "Cloud Firewall rules were not read" in r.json()["detail"], r.text
    for bad, needle in ((_job(targets=["src"]), "cannot also be a target"), (_job(targets=["nobody"]), "does not exist"),
                        (_job(groups=["everything"]), "Pick what to keep"), (_job(interval_hours=3), "How often"),
                        (_job(source={"kind": "template", "id": "t1"}), "Templates are not available"),
                        (_job(name="x\x07y"), "name")):
        r = alice.post("/api/sync-jobs", json={**bad, **SCOPE_BODY})
        assert r.status_code == 400 and needle in r.json()["detail"], (bad, r.text)
    jid = alice.post("/api/sync-jobs", json={**_job(), **SCOPE_BODY}).json()["id"]
    assert reader.post(f"/api/sync-jobs/{jid}/run", json={}).status_code == 403
    assert reader.delete(f"/api/sync-jobs/{jid}").status_code == 403
    listing = reader.get("/api/sync-jobs").json()
    assert [j["id"] for j in listing["jobs"]] == [jid]
    text = json.dumps(listing)
    assert not any(s in text for s in SECRETS.values())


def test_the_timer_runs_due_jobs_in_the_owners_name_and_only_plans(monkeypatch, env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: the scheduler starts a due job, which files its plan in the owner's name (so another writer approves it) and writes nothing; a job not due is left alone."""
    monkeypatch.setattr(srv, "_cq_tenant", srv._cq_tenant)
    due = sync_jobs.create_job(_job(interval_hours=4), by="alice@example.com")
    later = sync_jobs.create_job(_job(name="Later", interval_hours=24), by="carol@example.com")
    data = json.load(open(sync_jobs.store_path()))
    data["jobs"][due["id"]]["next_run_at"] = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    json.dump(data, open(sync_jobs.store_path(), "w"))
    ran = srv._sync_tick()
    assert len(ran) == 1
    job = sync_jobs.get_job(due["id"])
    run = job["history"][0]
    assert run["trigger"] == "schedule" and run["by"] == "alice@example.com"
    assert change_queue.get(run["filed"][0])["requested_by"] == "alice@example.com"
    assert datetime.fromisoformat(job["next_run_at"]) > datetime.now(timezone.utc) + timedelta(hours=3)
    assert sync_jobs.get_job(later["id"])["history"] == []
    assert _writes(env, "tgt") == [] and _writes(env, "src") == []


def test_a_paused_job_is_not_due_and_a_manual_only_job_never_is(env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: a job with no schedule or a paused one is never started by the timer."""
    manual = sync_jobs.create_job(_job(), by="alice@example.com")
    paused = sync_jobs.create_job(_job(name="P", interval_hours=1), by="alice@example.com")
    sync_jobs.set_enabled(paused["id"], False, by="alice@example.com")
    future = datetime.now(timezone.utc) + timedelta(days=30)
    assert [j["id"] for j in sync_jobs.due_jobs(future)] == []
    sync_jobs.set_enabled(paused["id"], True, by="alice@example.com")
    assert [j["id"] for j in sync_jobs.due_jobs(future)] == [paused["id"]]
    assert manual["next_run_at"] is None


def test_the_notification_names_the_plans_and_carries_no_secret(env):
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: a run that filed plans sends one message (names, counts, request ids) through the configured channel, without any secret."""
    sent = []
    deps = sync_jobs.Deps(build_client=env["deps"].build_client, tenant_key=srv._cq_tenant, notify=lambda s, b: sent.append((s, b)) or [{"sent": True}])
    job = sync_jobs.create_job(_job(), by="alice@example.com")
    run = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=deps)
    assert len(sent) == 1 and run["filed"][0] in sent[0][1] and "waiting for approval" in sent[0][0]
    assert not any(s in sent[0][0] + sent[0][1] for s in SECRETS.values())
    assert run["notified"] == [{"sent": True}]


def test_notify_via_digest_respects_never_and_unconfigured(monkeypatch):
    """ASVS V7.1.1 · CWE-200 · WSTG-CONF-05: the sync notification uses the digest's settings: DLP_CHECK_NOTIFY=never sends nothing, and nothing configured sends nothing."""
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "never")
    assert sync_jobs.notify_via_digest("s", "b")[0]["sent"] is False
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "always")
    for k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK"):
        monkeypatch.delenv(k, raising=False)
    assert sync_jobs.notify_via_digest("s", "b") == [{"channel": "none", "sent": False, "why": "no e-mail or webhook configured"}]


def test_a_sign_in_error_never_keeps_the_secret_in_the_history(env):
    """ASVS V7.1.1 · CWE-532 · WSTG-INFO-05: an error that echoes the target's secret is kept in the run history without it."""
    def boom(creds):
        if creds["vanity_domain"] == "tgt":
            raise RuntimeError(f"401 for client_secret={creds['client_secret']}")
        return env["stores"]["src"][1]
    deps = sync_jobs.Deps(build_client=boom, tenant_key=srv._cq_tenant)
    job = sync_jobs.create_job(_job(), by="alice@example.com")
    run = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=deps)
    assert run["targets"][0]["status"] == "error"
    stored = json.dumps(sync_jobs.get_job(job["id"]))
    assert SECRETS["tgt"] not in stored and "[secret]" in stored


def test_a_snapshot_can_be_the_source_and_is_read_offline(env, monkeypatch):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a saved snapshot is a valid source; the run reads it offline and still only files a plan."""
    import offline_tenant as ot
    st, cl = env["stores"]["src"]
    monkeypatch.setattr(tenant_profiles, "list_snapshots", lambda profile_id=None: [{"id": "snap-00112233aabbccdd", "tenant_label": "Source snap",
                                                                                       "saved_at": "2026-10-30T10:00:00+00:00", "scopes": ["zia_extras"]}])
    st.meta["scopes"] = ["zia_extras"]
    monkeypatch.setattr(ot, "open_saved", lambda sid: st)
    job = sync_jobs.create_job(_job(source={"kind": "snapshot", "id": "snap-00112233aabbccdd"}), by="alice@example.com")
    run = sync_jobs.run_job(job["id"], trigger="manual", by="alice@example.com", deps=env["deps"])
    assert run["status"] == "planned" and "src" not in env["built"] and _writes(env, "tgt") == []


def test_the_boundary_takes_any_source_snapshot(env):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: target_plan works from a snapshot of rows (the restore and clone side can hand one over), read-only."""
    _st, tgt = env["stores"]["tgt"]
    snap = {"policies": {"firewall": {"rows": [{"name": "Allow office traffic", "rank": 7, "state": "ENABLED", "action": "ALLOW", "description": "x"}]}}}
    prep = sync_jobs.target_plan(snap, "firewall", tgt, ao.scope_for(["zia_extras"], {}), {"include_deletes": False}, lambda m: None)
    assert prep["counts"]["change"] == 1 and _writes(env, "tgt") == []
    with pytest.raises(ao.OperationError, match="empty source"):
        sync_jobs.target_plan({"policies": {"firewall": {"rows": []}}}, "firewall", tgt, ao.scope_for(["zia_extras"], {}), {"include_deletes": True},
                              lambda m: None)
