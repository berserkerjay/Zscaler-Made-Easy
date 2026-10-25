"""Self-healing (self_heal.py).

Layer 1, the app heals itself: every check repairs a simulated fault (a
damaged store moved aside and restored from its last-good copy, a stale
lock whose owner process is gone released, a stuck or orphaned job ended
as failed, permissions set back to owner-only, an overlong rate hold
lifted, a failing cached sign-in dropped, low disk pruning only the app's
own old digests, an update without a restart reported) and never deletes
user data.

Layer 2, the tenant heals back to what was approved: a drift becomes a
heal proposal with the exact change; a recorded approved change is not
flagged; an accepted drift is not proposed again; a heal goes through the
write gate and the proposal apply path; automatic application is refused;
nothing in scope is refused before any read; nothing is written to the
tenant without the explicit heal call; no secret in any output.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

import audit
import continuous_eval
import deployments
import dlp_api_server as srv
import pack_deploy as pd
import pack_jobs
import proposal_apply as pa
import proposals as pr
import self_heal as sh
import tenant_auth
import tenant_profiles
import zia_rate
from test_baselines import baseline_pack, tenant_dict, tenant_engine, tenant_rule  # noqa: F401 - the policy pack fixture
from test_pack_deploy import PREDEF_SSN, FakeClient

SECRET = "Sup3r-S3cret-never-shown-42"
CREDS = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-123", "client_secret": SECRET}
DLP_SCOPE = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True}
RULE_KEY = "policy:web:ZBP-Alpha-Monitor"


@pytest.fixture
def env(tmp_path, monkeypatch):
    """Every store in a temporary folder; the app checks run on it."""
    d = tmp_path / "data"
    d.mkdir()
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(d / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(d / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(d / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_SELF_HEAL_STATE", str(d / "self_heal.json"))
    monkeypatch.setenv("DLP_CHECK_DIGESTS", str(d / "digests"))
    monkeypatch.setenv("DLP_CHECK_GUIDANCE_STATE", str(d / "guidance_state.json"))
    monkeypatch.delenv("DLPCHECK_CHANGE_QUEUE_FILE", raising=False)
    monkeypatch.delenv(sh.AUTO_APPLY_ENV, raising=False)
    monkeypatch.setattr(sh, "ROOT", str(tmp_path / "app"))
    (tmp_path / "app").mkdir()
    return d


def _labels():
    return list(tenant_auth.record_labels(CREDS))


def _client(rule=None, engine=None, rules=None):
    return FakeClient(dicts=[PREDEF_SSN, tenant_dict()], engines=[engine or tenant_engine()],
                      rules=rules if rules is not None else [rule or tenant_rule()])


def _look(client, pack, now):
    rep = pd.preflight(client, [pack], writes_enabled=False, apply_tweaks=False, channel_targets={pack["id"]: ["web"]},
                       read_scope={"channels": ["web"], "casb": False})
    return sh.raise_from_report(rep, tenant_key="acme", labels=_labels(), channels=["web"], now=now)


def _heals(status=("open", "approved")):
    return [p for p in pr.list_queue("acme", include_closed=True) if p.get("kind") == "heal_drift" and p.get("status") in status]


def _no_writes(client):
    z = client.zia
    assert z.dlp_web_rules.added == [] and z.dlp_web_rules.updated == []
    assert z.dlp_dictionary.added == [] and z.dlp_dictionary.updated == [] and z.dlp_engine.added == []
    assert getattr(z.dlp_engine, "updated", []) == []


def _dead_pid():
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    return p.pid


# ════════════════════════════ Layer 1 ══════════════════════════════════
def test_damaged_store_is_moved_aside_and_restored_from_the_last_good_copy(env):
    pr.merge("acme", [{"id": "p-1", "kind": "retire_rule", "target": "a", "title": "first"}])
    pr.merge("acme", [{"id": "p-2", "kind": "retire_rule", "target": "b", "title": "second"}], resolve_missing=False)
    store = pr.store_path()
    assert os.path.exists(store + sh.LAST_GOOD), "every atomic write keeps the previous good version"
    good = open(store + sh.LAST_GOOD, encoding="utf-8").read()
    with open(store, "w", encoding="utf-8") as f:
        f.write('{"version": 1, "tenants": {"acme": {"propo')   # a write cut short
    r = sh.check_stores()
    assert r["status"] == sh.HEALED and "restored the last good copy" in r["actions"][0]
    kept = [n for n in os.listdir(env) if n.startswith("proposals.json.corrupt-")]
    assert len(kept) == 1, "the damaged file is moved aside, never deleted"
    assert open(env / kept[0], encoding="utf-8").read().startswith('{"version": 1, "tenants": {"acme": {"propo')
    assert open(store, encoding="utf-8").read() == good
    assert [p["id"] for p in pr.list_queue("acme")] == ["p-1"], "the queue is back as last saved good"
    if os.name != "nt":
        assert oct(os.stat(store).st_mode & 0o777) == oct(0o600) and oct(os.stat(env / kept[0]).st_mode & 0o777) == oct(0o600)
    assert sh.check_stores()["status"] == sh.OK


def test_damaged_store_without_a_copy_starts_empty_says_so_and_keeps_the_damaged_file(env):
    p = deployments.store_path()
    with open(p, "w", encoding="utf-8") as f:
        f.write("")   # an empty file: a write that never finished
    r = sh.check_stores()
    assert r["status"] == sh.NEEDS_YOU and "starts empty" in r["actions"][0] and ".corrupt-" in r["next"]
    assert not os.path.exists(p) and deployments.list_all() == []
    again = sh.check_stores()
    assert again["status"] == sh.NEEDS_YOU and "Earlier" in again["actions"][0], "the loss is not forgotten on the next run"
    assert any(n.startswith("deployments.json.corrupt-") for n in os.listdir(env))
    # Shape counts too: valid JSON the module would silently replace is damaged.
    with open(pr.store_path(), "w", encoding="utf-8") as f:
        json.dump(["not", "a", "queue"], f)
    assert any("not in the shape" in a for a in sh.check_stores()["actions"])


def test_a_write_over_a_damaged_store_keeps_the_damaged_file_and_the_last_good_copy(env):
    path = tenant_profiles.store_path()
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "profiles": {"acme": {"id": "acme", "name": "Acme"}}}, f)
    sh.keep_last_good(path)
    good = open(path + sh.LAST_GOOD, encoding="utf-8").read()
    with open(path, "w", encoding="utf-8") as f:
        f.write("garbage{")
    tenant_profiles._write({"version": 1, "profiles": {}})   # the app writes on top of a damaged file
    assert any(n.startswith("tenant_profiles.json.corrupt-") for n in os.listdir(env)), "the damaged file is kept"
    assert open(path + sh.LAST_GOOD, encoding="utf-8").read() == good, "the last good copy is not replaced by damage"


def test_digest_that_cannot_be_read_is_moved_aside_and_the_others_kept(env):
    dd = continuous_eval.digest_dir()
    with open(os.path.join(dd, "digest-20260101-000000.json"), "w") as f:
        json.dump({"id": "20260101-000000"}, f)
    with open(os.path.join(dd, "digest-20260102-000000.json"), "w") as f:
        f.write("{")
    r = sh.check_stores()
    assert r["status"] == sh.HEALED and "digest-20260102-000000.json" in r["actions"][0]
    names = os.listdir(dd)
    assert "digest-20260101-000000.json" in names and any(n.startswith("digest-20260102-000000.json.corrupt-") for n in names)


def test_stale_run_lock_whose_owner_is_gone_is_released(env):
    import fcntl
    path = os.path.join(continuous_eval.digest_dir(), continuous_eval.LOCK_NAME)
    # The lock is held (an fd a crashed run left to a child process), and its owner process is gone.
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    os.write(fd, f"{_dead_pid()} {int(time.time())}\n".encode())
    try:
        with pytest.raises(continuous_eval.LoopRunInProgress):
            with continuous_eval.run_lock():
                pass
        r = sh.check_locks()
        assert r["status"] == sh.HEALED and "owner (process" in r["actions"][0]
        with continuous_eval.run_lock():   # a fresh lock is taken
            assert str(os.getpid()) in open(path).read(), "the run names its owner"
        assert open(path).read() == "", "released cleanly"
    finally:
        os.close(fd)


def test_a_lock_held_by_a_live_process_is_left_alone(env):
    with continuous_eval.run_lock():
        r = sh.check_locks()
        assert r["status"] == sh.OK and "in progress" in r["summary"]
        with pytest.raises(continuous_eval.LoopRunInProgress):
            with continuous_eval.run_lock():
                pass


def test_server_pid_and_rate_state_lock_left_behind_are_removed(env, tmp_path):
    (tmp_path / "app" / "server.pid").write_text(str(_dead_pid()))
    lock = zia_rate.state_path() + ".lock"
    open(lock, "w").close()
    old = time.time() - 600
    os.utime(lock, (old, old))
    r = sh.check_locks()
    assert r["status"] == sh.HEALED and len(r["actions"]) == 2
    assert not os.path.exists(tmp_path / "app" / "server.pid") and not os.path.exists(lock)
    (tmp_path / "app" / "server.pid").write_text(str(os.getpid()))
    assert sh.check_locks()["status"] == sh.OK and os.path.exists(tmp_path / "app" / "server.pid"), "a live server's pid file stays"


def test_stuck_job_is_ended_as_failed_and_a_late_ending_does_not_flip_it(env):
    gate = threading.Event()

    def fn(log, cancel):
        log("Reading…")
        gate.wait(10)
        return {"status": "done"}
    job = pack_jobs.start("export", fn, label="slow export")
    time.sleep(0.05)
    assert sh.check_jobs()["status"] == sh.OK, "a fresh job is not stuck"
    job.started -= 4 * 3600
    job.last_log_at -= 3 * 3600
    r = sh.check_jobs()
    assert r["status"] == sh.HEALED and "slow export" in r["actions"][0]
    snap = pack_jobs.snapshot(job)
    assert snap["status"] == pack_jobs.FAILED and "stuck" in snap["error"] and job.cancel.is_set()
    gate.set()
    job.thread.join(5)
    assert pack_jobs.snapshot(job)["status"] == pack_jobs.FAILED, "the late ending is logged, the failed status stays"
    assert any("after it had been marked stuck" in line for line in job.logs)
    events = [e.get("event") for e in audit.tail(50)]
    assert events.count("job_finished") >= 1 and "job_finished_late" in events


def test_orphaned_job_whose_thread_died_is_failed(env):
    job = pack_jobs.Job(id="orphan123456", kind="deploy", label="deploy that lost its worker")
    dead = threading.Thread(target=lambda: None)
    dead.start()
    dead.join()
    job.thread = dead
    with pack_jobs._registry_lock:
        pack_jobs._jobs[job.id] = job
    try:
        r = sh.check_jobs()
        assert r["status"] == sh.HEALED and "worker had stopped" in r["actions"][0]
        assert job.status == pack_jobs.FAILED and "worker stopped" in job.error
    finally:
        pack_jobs._jobs.pop(job.id, None)


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_permissions_on_secrets_and_stores_are_set_back_to_owner_only(env, tmp_path):
    pr.merge("acme", [{"id": "p-1", "kind": "retire_rule", "target": "a", "title": "t"}])
    os.chmod(pr.store_path(), 0o644)
    cfg = tmp_path / "app" / "tenant_config.json"
    cfg.write_text("{}")
    os.chmod(cfg, 0o666)
    dd = continuous_eval.digest_dir()
    os.chmod(dd, 0o755)
    r = sh.check_permissions()
    assert r["status"] == sh.HEALED
    assert os.stat(pr.store_path()).st_mode & 0o777 == 0o600 and os.stat(cfg).st_mode & 0o777 == 0o600
    assert os.stat(dd).st_mode & 0o777 == 0o700
    assert json.load(open(pr.store_path()))["tenants"]["acme"], "content untouched"
    assert sh.check_permissions()["status"] == sh.OK


def test_a_rate_hold_that_outlived_its_window_is_lifted_and_a_real_one_kept(env):
    zia_rate.hold(10 * 3600, key="tenant-a")       # ten hours: no ZIA limit window is that long
    zia_rate.hold(30, key="tenant-b")              # a real 30-second pause
    r = sh.check_rate_holds()
    assert r["status"] == sh.HEALED and len(r["actions"]) == 1
    assert zia_rate.paused_for("tenant-a") == 0 and zia_rate.paused_for("tenant-b") > 0
    assert sh.check_rate_holds()["status"] == sh.OK


def test_a_cached_sign_in_that_keeps_failing_is_dropped(env, monkeypatch):
    from zscaler.oneapi_oauth_client import OAuth

    class Fake:
        cleared = False

        def clear_access_token(self):
            Fake.cleared = True
    monkeypatch.setattr(OAuth, "_instance", Fake())
    monkeypatch.setattr(OAuth, "_last_config", {"x": 1})
    sh._AUTH_FAILURES.clear()
    sh.note_auth_failure()
    assert sh.check_sign_in()["status"] == sh.OK
    sh.note_auth_failure()
    sh.note_auth_failure()
    r = sh.check_sign_in()
    assert r["status"] == sh.HEALED and Fake.cleared and OAuth._instance is None and OAuth._last_config is None
    assert SECRET not in json.dumps(r)
    assert sh.check_sign_in()["status"] == sh.OK


def test_low_disk_prunes_only_the_apps_own_old_digests(env, monkeypatch):
    dd = continuous_eval.digest_dir()
    old = time.time() - 30 * 86400
    for i in range(15):
        for ext in (".json", ".md"):
            p = os.path.join(dd, f"digest-202601{i + 1:02d}-000000{ext}")
            open(p, "w").write("{}")
            os.utime(p, (old, old))
    keep = [os.path.join(dd, "digest-20260101-000000.json.corrupt-20260102-000000"), os.path.join(dd, "notes.txt"), str(env / "my_export.xlsx")]
    for p in keep:
        open(p, "w").write("user data")
        os.utime(p, (old, old))

    class Usage:
        def __init__(self, free):
            self.free = free
    frees = iter([10 * 1024 * 1024, 10 * 1024 * 1024])
    monkeypatch.setattr(sh.shutil, "disk_usage", lambda p: Usage(next(frees)))
    r = sh.check_disk()
    assert r["status"] == sh.NEEDS_YOU and "Removed 10 old digest file(s)" in r["actions"][0]
    left = sorted(n for n in os.listdir(dd) if n.endswith(".json"))
    assert len(left) == 10 and left[-1] == "digest-20260115-000000.json", "the newest ten are kept"
    assert all(os.path.exists(p) for p in keep), "nothing but the app's own digests is removed"


def test_an_update_without_a_restart_is_reported_with_the_one_click_fix(env, monkeypatch):
    heads = iter(["abc1234", "def5678"])
    monkeypatch.setattr(sh, "_git_head", lambda d: next(heads))
    sh.mark_started()
    r = sh.check_version()
    assert r["status"] == sh.NEEDS_YOU and "def5678" in r["summary"] and r["fix"] == {"label": "Restart the app", "method": "POST", "url": "/api/app/restart"}
    monkeypatch.setattr(sh, "_git_head", lambda d: "abc1234")
    sh.mark_started()
    assert sh.check_version()["status"] == sh.OK


def test_run_endpoint_runs_every_check_keeps_the_result_and_audits_it(env):
    c = TestClient(srv.app)
    out = c.post("/api/self-heal/run").json()
    assert [k["id"] for k in out["checks"]] == ["jobs", "stores", "permissions", "locks", "rate_holds", "sign_in", "disk", "version"]
    assert all(k["status"] in (sh.OK, sh.HEALED, sh.NEEDS_YOU) and k["summary"] for k in out["checks"])
    got = c.get("/api/self-heal").json()
    assert got["last_run"]["at"] == out["at"] and got["settings"]["auto_apply"]["enabled"] is False
    runs = [e for e in audit.tail(50) if e.get("event") == "self_heal_run"]
    assert runs and runs[-1]["trigger"] == "manual"


def test_the_run_endpoint_needs_the_ui_token(env, monkeypatch):
    import security
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "test-token-abc123")
    c = TestClient(srv.app)
    assert c.post("/api/self-heal/run").status_code == 401
    assert c.post("/api/self-heal/run", headers={"X-DLP-Check-Token": "test-token-abc123"}).status_code == 200


def test_interval_setting(monkeypatch):
    monkeypatch.delenv(sh.MINUTES_ENV, raising=False)
    assert sh.interval_minutes() == 10
    for raw, want in (("0", 0), ("-3", 0), ("abc", 0), ("0.1", 1), ("99999", 1440), ("5", 5)):
        monkeypatch.setenv(sh.MINUTES_ENV, raw)
        assert sh.interval_minutes() == want, raw


# ════════════════════════════ Layer 2 ══════════════════════════════════
def test_first_look_records_what_is_there_and_reports_no_drift(env, baseline_pack):
    client = _client()
    res = _look(client, baseline_pack, time.time())
    assert res["drifts"] == [] and _heals() == []
    st = json.load(open(sh.state_path()))["tenants"]["acme"]["approved"]
    assert st[RULE_KEY]["state"] == "ENABLED" and st[RULE_KEY]["action"] == "ALLOW"
    _no_writes(client)


def test_a_rule_turned_off_becomes_a_heal_proposal_with_the_exact_change(env, baseline_pack):
    now = time.time()
    _look(_client(), baseline_pack, now - 100)
    client = _client(rule=tenant_rule(state="DISABLED"))
    res = _look(client, baseline_pack, now)
    assert [d["kind"] for d in res["drifts"]] == ["disabled"]
    [p] = _heals()
    assert p["kind"] == "heal_drift" and p["gate"] == "approve_double" and p["one_click"] and p["status"] == "open"
    assert p["change"] == {"apply": "rule", "rule_id": "7100", "channel": "web", "field": "state", "from": "DISABLED", "to": "ENABLED"}
    assert p["title"] == "Turn rule ZBP-Alpha-Monitor (Web DLP) back on"
    ev = p["evidence"]
    assert ev["approved_value"] == "ENABLED" and ev["current_value"] == "DISABLED" and "turned off" in ev["what_changed"]
    assert ev["who"] is None and "Automation readiness" in ev["how"]
    _no_writes(client)   # raising the proposal writes nothing to the tenant
    # It goes through the proposal apply path: the gate holds, then preview, update, read-back, rollback recorded.
    with pytest.raises(ValueError, match="not approved"):
        pa.apply(client, "acme", p["id"], writes_enabled=True)
    with pytest.raises(ValueError, match="I UNDERSTAND"):
        pr.decide("acme", p["id"], "approve")
    pr.decide("acme", p["id"], "approve", confirm="I UNDERSTAND")
    with pytest.raises(PermissionError):
        pa.apply(client, "acme", p["id"], writes_enabled=False)
    out = pa.apply(client, "acme", p["id"], writes_enabled=True, by="jane")
    assert out["ok"] and out["results"][0]["verified"] and client.zia.dlp_web_rules.items[0].state == "ENABLED"
    assert pr.get("acme", p["id"])["applied"]["before"] == {"7100": "DISABLED"}
    # Healed: the next look finds nothing; a second drift reopens it.
    assert _look(client, baseline_pack, now + 100)["drifts"] == []
    client.zia.dlp_web_rules.items[0].state = "DISABLED"
    _look(client, baseline_pack, now + 200)
    assert [x["id"] for x in _heals()] == [p["id"]] and "drifted again" in (pr.get("acme", p["id"]).get("note") or "")


def test_a_weakened_action_is_drift_and_a_stricter_one_is_progress(env, baseline_pack):
    now = time.time()
    _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now - 200)
    res = _look(_client(rule=tenant_rule(action="ALLOW")), baseline_pack, now - 100)
    [d] = res["drifts"]
    assert d["kind"] == "weakened" and d["approved"] == "BLOCK" and d["current"] == "ALLOW"
    [p] = _heals()
    assert p["change"]["field"] == "action" and p["change"]["from"] == "ALLOW" and p["change"]["to"] == "BLOCK"
    assert "blocks" in p["evidence"]["what_changed"] and "only watches" in p["evidence"]["what_changed"]
    # Put back by hand in the portal: the proposal resolves itself.
    _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now - 50)
    assert _heals() == [] and pr.get("acme", p["id"])["status"] == "resolved"
    # Hardening is progress, never drift: the approved value moves forward.
    env2 = _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now)
    assert env2["drifts"] == []


def test_monitor_to_block_is_never_flagged(env, baseline_pack):
    now = time.time()
    _look(_client(rule=tenant_rule(action="ALLOW", state="DISABLED")), baseline_pack, now - 100)
    assert _look(_client(rule=tenant_rule(action="BLOCK", state="ENABLED")), baseline_pack, now)["drifts"] == []
    st = json.load(open(sh.state_path()))["tenants"]["acme"]["approved"][RULE_KEY]
    assert st["action"] == "BLOCK" and st["state"] == "ENABLED"


def test_a_change_this_app_recorded_is_not_flagged(env, baseline_pack):
    now = time.time()
    _look(_client(), baseline_pack, now - 100)
    # The app's own write (pack_ops' object_write audit entry) after the approved look.
    audit.record("object_write", tenant=_labels()[0], action="update", object_type="policy", channel="web", id=7100,
                 name="ZBP-Alpha-Monitor", result="ok")
    res = _look(_client(rule=tenant_rule(state="DISABLED")), baseline_pack, now + 5)
    assert res["drifts"] == [] and _heals() == []
    st = json.load(open(sh.state_path()))["tenants"]["acme"]["approved"][RULE_KEY]
    assert st["state"] == "DISABLED" and "this app's own update" in st["source"]


def test_a_bulk_change_explains_only_the_field_it_changed(env, baseline_pack):
    now = time.time()
    _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now - 100)
    deployments.add_operation({"id": "op-1", "at": sh._iso(now - 50), "tenant_label": _labels()[0], "type": "rule_state", "title": "Disable 1 rule",
                               "items": [{"status": "applied", "field": "state", "before": "ENABLED", "after": "DISABLED",
                                          "object": {"type": "rule", "policy": "web_dlp", "id": 7100, "name": "ZBP-Alpha-Monitor"}}]})
    res = _look(_client(rule=tenant_rule(state="DISABLED", action="ALLOW")), baseline_pack, now)
    assert [(d["field"], d["kind"]) for d in res["drifts"]] == [("action", "weakened")], "the disable was approved; the weaker action was not"


def test_an_accepted_drift_is_not_proposed_again(env, baseline_pack):
    now = time.time()
    _look(_client(), baseline_pack, now - 100)
    _look(_client(rule=tenant_rule(state="DISABLED")), baseline_pack, now - 50)
    [p] = _heals()
    sh.accept("acme", p["id"], by="jane", note="agreed with the customer")
    rec = pr.get("acme", p["id"])
    assert rec["status"] == "dismissed" and rec["note"].startswith("accepted - stop proposing")
    assert _look(_client(rule=tenant_rule(state="DISABLED")), baseline_pack, now)["drifts"] == [] and _heals() == []
    v = sh.tenant_view("acme")
    assert v["accepted"][0]["key"] == RULE_KEY and v["accepted"][0]["value"] == "DISABLED" and v["accepted"][0]["by"] == "jane"
    assert any(e.get("event") == "self_heal_accept" and e.get("by") == "jane" for e in audit.tail(50))


def test_an_object_a_deployment_created_and_someone_deleted_is_proposed_back(env, baseline_pack):
    deployments.add({"id": "dep-1", "at": sh._iso(time.time() - 3600), "tenant_label": _labels()[0], "packs": ["alpha_baseline"],
                     "created": [{"kind": "policy", "name": "ZBP-Alpha-Monitor", "id": 7100, "channel": "web"}], "undone_at": None})
    res = _look(_client(rules=[]), baseline_pack, time.time())
    [d] = res["drifts"]
    assert d["kind"] == "deleted"
    [p] = _heals()
    assert not p["one_click"] and p["change"]["apply"] == "manual" and p["change"]["kind"] == "redeploy_pack"
    assert "Deploy policy packs" in p["expected_effect"]
    with pytest.raises(ValueError, match="ZIA portal"):
        pa.preview(_client(rules=[]), "acme", p["id"])


def test_an_edited_engine_is_flagged_with_the_steps(env, baseline_pack):
    now = time.time()
    _look(_client(), baseline_pack, now - 100)
    res = _look(_client(engine=tenant_engine(expr="(D4100.S > 5)")), baseline_pack, now)
    assert [(d["object_kind"], d["kind"]) for d in res["drifts"]] == [("engine", "edited")]
    [p] = _heals()
    assert p["change"]["apply"] == "manual" and "Accept" in p["expected_effect"]
    assert p["evidence"]["approved_value"] == "the content you approved" and p["evidence"]["current_value"] == "different content"
    sh.accept("acme", p["id"], by="jane")
    assert _look(_client(engine=tenant_engine(expr="(D4100.S > 5)")), baseline_pack, now + 50)["drifts"] == []


def test_a_fix_applied_through_a_proposal_and_undone_is_proposed_again(env, baseline_pack):
    p = {"id": pr.proposal_id("acme", "promote_rule", "rule:web:ZBP-Alpha-Monitor"), "tenant": "acme", "kind": "promote_rule",
         "label": "Promote rule", "target": "rule:web:ZBP-Alpha-Monitor", "title": "Promote ZBP-Alpha-Monitor from monitor to confirm",
         "change": {"apply": "rule", "rule_id": 7100, "channel": "web", "field": "action", "from": "ALLOW", "to": "CONFIRM"},
         "evidence": {}, "expected_effect": "asks", "rollback": {"field": "action", "to": "ALLOW"}, "gate": "approve_double",
         "applies_via": "phase 3", "channel": "web", "rule": "ZBP-Alpha-Monitor"}
    pr.merge("acme", [p])
    pr.decide("acme", p["id"], "approve", confirm="I UNDERSTAND")
    client = _client()
    assert pa.apply(client, "acme", p["id"], writes_enabled=True)["ok"]
    client.zia.dlp_web_rules.items[0].action = "ALLOW"   # someone undid it in the portal
    res = _look(client, baseline_pack, time.time() + 5)
    [d] = res["drifts"]
    assert d["kind"] == "undone" and d["approved"] == "CONFIRM" and d["current"] == "ALLOW"
    [h] = _heals()
    assert h["change"]["to"] == "CONFIRM" and "A fix you applied" in h["evidence"]["what_changed"]


# ── the endpoints ───────────────────────────────────────────────────────
def _drifted_endpoint_setup(monkeypatch, baseline_pack, rule_kw=None):
    now = time.time()
    _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now - 100)
    client = _client(rule=tenant_rule(**(rule_kw or {"action": "ALLOW"})))
    _look(client, baseline_pack, now)
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or client)
    return client, built


def test_heal_goes_through_the_write_gate_and_the_typed_confirmation(env, baseline_pack, monkeypatch):
    client, built = _drifted_endpoint_setup(monkeypatch, baseline_pack)
    [p] = _heals()
    c = TestClient(srv.app)
    body = {**CREDS, **DLP_SCOPE, "ids": [p["id"]], "confirm": "I UNDERSTAND"}
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    r = c.post("/api/self-heal/tenant/heal", json=body)
    assert r.status_code == 403 and "ENABLE_WRITE_ACTIONS" in r.json()["detail"]
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    r = c.post("/api/self-heal/tenant/heal", json={**body, "confirm": "yes"})
    assert r.status_code == 400 and "I UNDERSTAND" in r.json()["detail"]
    assert built == [] and client.zia.dlp_web_rules.updated == [], "refused before signing in or writing"
    r = c.post("/api/self-heal/tenant/heal", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["healed"] == 1 and out["results"][0]["results"][0]["verified"]
    assert client.zia.dlp_web_rules.items[0].action == "BLOCK"
    rec = pr.get("acme", p["id"])
    assert rec["status"] == "applied" and rec["applied"]["before"] == {"7100": "ALLOW"}, "the undo is recorded"
    assert any(e.get("event") == "self_heal_heal" for e in audit.tail(50))
    assert SECRET not in r.text


def test_heal_refuses_when_the_setting_moved_again(env, baseline_pack, monkeypatch):
    client, _ = _drifted_endpoint_setup(monkeypatch, baseline_pack)
    [p] = _heals()
    client.zia.dlp_web_rules.items[0].action = "CONFIRM"   # moved again since the scan
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    r = TestClient(srv.app).post("/api/self-heal/tenant/heal", json={**CREDS, **DLP_SCOPE, "ids": [p["id"]], "confirm": "I UNDERSTAND"})
    assert r.status_code == 200
    res = r.json()["results"][0]
    assert not res["ok"] and "not ALLOW" in res["why"] and client.zia.dlp_web_rules.updated == []


def test_out_of_scope_is_refused_before_any_sign_in(env, monkeypatch):
    def boom(creds):
        raise AssertionError("signed in although nothing is in scope")
    monkeypatch.setattr(srv, "_build_sdk_client", boom)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    c = TestClient(srv.app)
    for scope in ({"scopes": [], "channels": {}, "from_page": True}, {"scopes": ["dlp"], "channels": {"web_dlp": "alternative"}, "from_page": True}):
        for url, extra in (("/api/self-heal/tenant/scan", {}), ("/api/self-heal/tenant/heal", {"ids": ["p-1"], "confirm": "I UNDERSTAND"}),
                           ("/api/self-heal/tenant/accept", {"id": "p-1"}), ("/api/self-heal/tenant/view", {})):
            r = c.post(url, json={**CREDS, **scope, **extra})
            assert r.status_code == 400 and "not in scope" in r.json()["detail"] and "Nothing was read" in r.json()["detail"], (url, r.text)
    # Who changed it needs Automation readiness in scope too.
    r = c.post("/api/self-heal/tenant/scan", json={**CREDS, **DLP_SCOPE, "include_who": True})
    assert r.status_code == 400 and "Automation readiness" in r.json()["detail"]


def test_scan_job_reads_only_and_raises_the_proposals(env, baseline_pack, monkeypatch):
    now = time.time()
    _look(_client(rule=tenant_rule(action="BLOCK")), baseline_pack, now - 100)
    client = _client(rule=tenant_rule(action="ALLOW"))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(srv, "_self_heal_packs", lambda req, ch, label: ([baseline_pack], {baseline_pack["id"]: ["web"]}))
    c = TestClient(srv.app)
    r = c.post("/api/self-heal/tenant/scan", json={**CREDS, **DLP_SCOPE})
    assert r.status_code == 200, r.text
    job = pack_jobs.get(r.json()["job_id"])
    job.thread.join(10)
    snap = c.get(f"/api/dlp-packs/jobs/{job.id}").json()
    assert snap["status"] == "done", snap
    res = snap["result"]
    assert res["ok"] and [d["kind"] for d in res["drifts"]] == ["weakened"] and res["view"]["open"] == 1
    _no_writes(client)
    view = c.post("/api/self-heal/tenant/view", json={**CREDS, **DLP_SCOPE}).json()
    assert view["open"] == 1 and view["items"][0]["kind"] == "heal_drift"
    for text in (json.dumps(snap), json.dumps(view), c.get("/api/self-heal").text, open(audit.path(), encoding="utf-8").read()):
        assert SECRET not in text


def test_accept_endpoint_is_audited_and_stops_proposing(env, baseline_pack, monkeypatch):
    _drifted_endpoint_setup(monkeypatch, baseline_pack)
    [p] = _heals()
    c = TestClient(srv.app)
    out = c.post("/api/self-heal/tenant/accept", json={**CREDS, **DLP_SCOPE, "id": p["id"], "note": "agreed"}).json()
    assert out["open"] == 0 and out["accepted"][0]["note"] == "agreed"
    assert any(e.get("event") == "self_heal_accept" for e in audit.tail(50))
    assert c.post("/api/self-heal/tenant/accept", json={**CREDS, **DLP_SCOPE, "id": p["id"]}).status_code == 400


def test_automatic_application_is_refused_whatever_the_setting_says(env, monkeypatch):
    monkeypatch.setenv(sh.AUTO_APPLY_ENV, "1")
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("no tenant call")))
    s = sh.auto_apply_setting()
    assert s["requested"] is True and s["enabled"] is False and "not enabled in this version" in s["why"]
    assert sh.auto_apply("acme")["status"] == "refused"
    r = TestClient(srv.app).post("/api/self-heal/tenant/auto-apply", json={})
    assert r.status_code == 403 and "not enabled in this version" in r.json()["detail"]


def test_the_page_route_and_the_continuous_evaluation_hook(env):
    html = TestClient(srv.app).get("/report/self-heal").text
    assert "<title>Self-healing — Zscaler Made Easy</title>" in html
    assert "This app" in html and "Your tenant" in html and "/report/queue" in html
    src = open(os.path.join(os.path.dirname(sh.__file__), "continuous_eval.py"), encoding="utf-8").read()
    assert "self_heal.raise_from_report(" in src
