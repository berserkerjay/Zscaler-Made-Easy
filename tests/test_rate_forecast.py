"""Each pack says how it measures against ZIA's rate limits, and every deploy
or removal preview checks, from what the app executed for that tenant,
whether the run will succeed, succeed with pauses, or likely fail."""
from __future__ import annotations

import json
import threading

import pytest

import pack_deploy as pd
import pack_removal as pr
import zia_rate
from dlp_importer import discover_packs
from test_pack_regression import PACKS, the_tenant

A = zia_rate.key_for("zscaler.net", "tenant-a", "client-a")
B = zia_rate.key_for("zscaler.net", "tenant-b", "client-b")


@pytest.fixture
def clock(monkeypatch):
    """A fixed wall clock and ZIA's documented limits (conftest turns pacing off)."""
    t = [1_800_000_000.0]
    monkeypatch.setattr(zia_rate, "_now", lambda: t[0])
    for bucket in zia_rate.DEFAULTS:
        monkeypatch.delenv(f"DLP_CHECK_ZIA_LIMIT_{bucket.upper()}", raising=False)
    zia_rate.reset()
    return t


def _restart():
    """What a restart leaves: nothing in memory, the state file on disk."""
    with zia_rate._lock:
        for t in zia_rate._tenants.values():
            for q in t.sent.values():
                q.clear()
            t.hold[0] = 0.0
            t.refused.clear()
            t.server.clear()
        zia_rate._loaded[0] = False


def _client(key):
    c = the_tenant()
    c._zia_rate_key = key
    return c


def test_every_pack_card_has_a_rate_note():
    for p in discover_packs():
        note = p["rate"]
        assert note["deploy"]["activate"] == 1 and note["remove"]["activate"] == 1
        assert note["deploy"]["endpoint_rules"] == p["channels"].get("endpoint", 0)
        assert note["remove"]["delete"] == p["dictionaries"] + p["engines"] + p["app_groups"] + sum(p["channels"].values())
        assert "Full deploy" in note["text"] and "Removal" in note["text"] and note["deploy_seconds"] > 0


def test_a_quiet_hour_goes_straight_through_at_the_documented_limits(clock):
    f = zia_rate.forecast({"write": 90, "endpoint_rules": 14, "activate": 1}, key=A)
    assert f["severity"] == "ok" and f["title"] == "Will succeed", f["verdict"]
    assert f["seconds"] == pytest.approx(149), "90 writes at 1/s, then 14 Endpoint rules (the 11th waits for the minute), in that order"


def test_recent_requests_make_the_forecast_pause_and_say_why(clock):
    zia_rate._t(A).sent["endpoint_rules"].extend(clock[0] - 600 + i for i in range(38))
    f = zia_rate.forecast({"endpoint_rules": 9, "activate": 1}, key=A)
    assert f["severity"] == "warn" and "38 of 40/hr already used" in f["verdict"]
    assert f["seconds"] > 45 * 60, "the 3rd rule waits until the oldest of the 38 leaves the hour"


def test_more_than_the_hourly_limit_is_flagged_even_from_a_fresh_start(clock):
    f = zia_rate.forecast({"activate": 45}, key=A)
    assert f["severity"] == "warn" and "over the 40/hr limit" in f["verdict"]


def test_a_block_in_the_last_hour_is_likely_to_fail_with_when_to_run(clock):
    zia_rate._t(A).sent["write"].extend(clock[0] - 200 + i * 1.7 for i in range(110))
    zia_rate.note_refusal("write", "Resource Access Blocked", key=A, status=403)
    clock[0] += 600
    f = zia_rate.forecast({"write": 10, "activate": 1}, key=A)
    assert f["severity"] == "fail" and "after 110 writes from DLP-Check in 5 minutes" in f["verdict"]
    assert f["run_after"] == pytest.approx(clock[0] - 600 + 3600) and "UTC" in f["verdict"]


def test_a_429_with_a_reset_is_a_pause_not_a_failure_nor_a_ceiling(clock):
    zia_rate._t(A).sent["write"].extend(clock[0] - 5 + i for i in range(3))
    zia_rate.note_refusal("write", "Too Many Requests", key=A, reset=30, status=429)
    f = zia_rate.forecast({"write": 5}, key=A)
    assert f["severity"] == "warn" and "still resetting" in f["verdict"]
    clock[0] += 60
    assert zia_rate.forecast({"write": 5}, key=A)["severity"] == "ok", "the reset has run out"
    assert zia_rate.forecast({"write": 300}, key=A)["tolerated"] is None, "a 429 says nothing about what ZIA tolerates"


def test_a_read_429_never_makes_a_deploy_fail(clock):
    zia_rate.observe("GET", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 429, {}, "Too Many Requests", key=A)
    assert zia_rate.forecast({"write": 50, "activate": 1}, key=A)["severity"] == "ok"


def test_what_zia_tolerated_is_remembered_and_compared_write_for_write(clock):
    zia_rate._t(A).sent["write"].extend(clock[0] - 200 + i * 1.7 for i in range(110))
    zia_rate._t(A).sent["read"].extend(clock[0] - 200 + i for i in range(150))
    zia_rate.note_refusal("write", "Resource Access Blocked", key=A, status=403)
    r = zia_rate._t(A).refused[-1]
    assert r["kind"] == "blocked" and r["writes_5m"] == 110 and r["reads_5m"] == 150
    clock[0] += 2 * 3600
    big = zia_rate.forecast({"write": 158, "activate": 1}, key=A)
    assert big["severity"] == "fail" and "after 110 writes in 5 minutes" in big["verdict"]
    assert zia_rate.forecast({"write": 20, "activate": 1}, key=A)["severity"] == "ok"
    near = zia_rate.forecast({"write": 95, "activate": 1}, key=A)
    assert near["severity"] == "warn" and "close to what ZIA tolerates" in near["verdict"]


def test_one_tenants_block_does_not_touch_another_tenant(clock):
    zia_rate._t(A).sent["write"].extend(clock[0] - 200 + i for i in range(110))
    zia_rate.note_refusal("write", "Resource Access Blocked", key=A, status=403)
    assert zia_rate.forecast({"write": 158, "activate": 1}, key=A)["severity"] == "fail"
    b = zia_rate.forecast({"write": 158, "activate": 1}, key=B)
    assert b["severity"] == "ok" and b["sent_last_hour"] == {}, "tenant B's record is its own"
    with zia_rate._lock:
        assert zia_rate._t(B).hold[0] == 0.0


def test_zias_own_count_adds_to_the_apps_record_instead_of_replacing_it(clock):
    t = zia_rate._t(A)
    t.sent["endpoint_rules"].extend(clock[0] - 3000 + i * 60 for i in range(30))    # 30 in the hour, 1 in the last minute
    zia_rate.note_headers("endpoint_rules", {"x-ratelimit-limit": "10", "x-ratelimit-remaining": "2", "x-ratelimit-reset": "40"}, key=A)
    f = zia_rate.forecast({"endpoint_rules": 12}, key=A)
    row = f["buckets"][0]
    assert row["zia_reports_used"] == 8 and row["used_last_hour"] == 30
    assert f["severity"] == "warn", "30 + 8 of 40 in the hour: the 3rd of 12 waits for the hour, which a replaced history would miss"


def test_requests_survive_a_restart_and_two_processes_merge(clock, tmp_path, monkeypatch):
    state = tmp_path / "rate.json"
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(state))
    zia_rate._loaded[0] = False
    for _ in range(3):
        zia_rate.wait("POST", channel="endpoint", kind="policy", key=A)
    data = json.loads(state.read_text())
    assert data["version"] == 2 and len(data["tenants"][A]["sent"]["endpoint_rules"]) == 3
    # Another process wrote a refusal for tenant B meanwhile: this process's next save keeps it.
    data["tenants"][B] = {"sent": {"write": [clock[0] - 5]}, "hold_until": 0, "refused": [
        {"at": clock[0] - 5, "bucket": "write", "message": "Resource Access Blocked", "kind": "blocked", "reset": None, "writes_5m": 40}],
        "server": {}}
    state.write_text(json.dumps(data))
    zia_rate.wait("POST", channel="endpoint", kind="policy", key=A)
    data = json.loads(state.read_text())
    assert len(data["tenants"][A]["sent"]["endpoint_rules"]) == 4 and data["tenants"][B]["refused"], "merged, not overwritten"
    _restart()
    assert zia_rate.forecast({"endpoint_rules": 1}, key=A)["recent"]["endpoint_rules"] == 4
    assert zia_rate.forecast({"write": 1}, key=B)["severity"] == "fail"
    assert not list(tmp_path.glob(".zia_rate-*")), "no temp file left behind"


def test_the_container_state_of_the_refused_run(clock, tmp_path, monkeypatch):
    """The container's own record after tonight's run, written before refusals
    were kept: 110 writes in about 3 minutes, then a one-hour hold."""
    start = clock[0] - 300
    state = tmp_path / "zia_rate.json"
    state.write_text(json.dumps({"sent": {"write": [start + i * 1.72 for i in range(110)]}, "hold_until": start + 3600}))
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(state))
    _restart()
    f = zia_rate.forecast({"write": 40, "activate": 1}, key=A)
    assert f["severity"] == "fail" and "110 writes" in f["verdict"], "the unrecorded tenant's record applies to every tenant"
    # Written back, the inferred refusal is kept, and after the hold it still sets the ceiling.
    zia_rate.hold(0, key="")
    clock[0] += 2 * 3600
    _restart()
    assert zia_rate.forecast({"write": 158, "activate": 1}, key=A)["severity"] == "fail"
    assert zia_rate.forecast({"write": 20, "activate": 1}, key=A)["severity"] == "ok"
    # A legacy file read only after its hold ended still gives the refusal.
    state.write_text(json.dumps({"sent": {"write": [start + i * 1.72 for i in range(110)]}, "hold_until": start + 3600}))
    _restart()
    assert zia_rate.forecast({"write": 158}, key=A)["tolerated"]["writes_5m"] == 110


def test_every_zia_answer_on_a_tenants_session_is_observed(clock):
    zia_rate.observe("GET", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 200, key=A)
    zia_rate.observe("GET", "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/1/segment", 200, key=A)   # not ZIA
    zia_rate.observe("GET", "https://zsapi.zscaler.net/api/v1/webDlpRules", 200,
                     {"x-ratelimit-limit": "1000", "x-ratelimit-remaining": "900", "x-ratelimit-reset": "1200"}, key=A)
    assert zia_rate.forecast({"write": 1}, key=A)["sent_last_hour"] == {"read": 2}
    assert zia_rate._t(A).server["read"]["remaining"] == 900
    zia_rate.observe("PUT", "https://api.zsapi.net/zia/api/v1/endpointDlpRules/5", 403, None, '{"message":"Forbidden: role"}', key=A)
    assert not zia_rate._t(A).refused, "a permission 403 is not a rate refusal"
    zia_rate.observe("POST", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 403, None, '{"message":"Resource Access Blocked"}', key=A)
    assert zia_rate._t(A).refused[-1]["kind"] == "blocked"


def test_the_session_hook_reports_to_its_own_tenant():
    import requests
    s = zia_rate.attach(requests.Session(), A)
    zia_rate.attach(s, A)

    class Req:
        method, url = "POST", "https://api.zsapi.net/zia/api/v1/status/activate"

    class Resp:
        status_code, text, request = 429, "Too Many Requests", Req()
        headers = {"x-ratelimit-limit": "10", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "30"}
    zia_rate.reset()
    for h in s.hooks["response"]:
        h(Resp(), stream=False)
    assert len(s.hooks["response"]) >= 1
    with zia_rate._lock:
        t = zia_rate._t(A)
        assert t.refused[-1]["bucket"] == "activate" and t.refused[-1]["reset"] == 30 and t.server["activate"]["remaining"] == 0
        assert not zia_rate._t(B).refused


def test_a_paced_write_does_not_hold_up_other_threads(clock, monkeypatch):
    """wait() sleeps without the lock: while one thread waits out a limit,
    another thread's forecast and observation go through."""
    zia_rate._t(A).sent["endpoint_rules"].extend(clock[0] - 10 + i for i in range(10))
    asleep, release = threading.Event(), threading.Event()

    def sleep(s):
        asleep.set()
        release.wait(5)
        clock[0] += s
    monkeypatch.setattr(zia_rate, "_sleep", sleep)
    th = threading.Thread(target=lambda: zia_rate.wait("POST", channel="endpoint", kind="policy", key=A))
    th.start()
    assert asleep.wait(5)
    done = threading.Event()
    threading.Thread(target=lambda: (zia_rate.forecast({"write": 1}, key=A),
                                     zia_rate.observe("GET", "https://api.zsapi.net/zia/api/v1/x", 200, key=B), done.set())).start()
    assert done.wait(2), "the forecast and a read were blocked by a sleeping write"
    release.set()
    th.join(5)


def test_the_preflight_check_says_will_succeed_or_likely_to_fail(clock):
    pack = next(p for p in PACKS if p["id"] == "zbp_enterprise_baseline")
    rep = pd.preflight(_client(A), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    f = rep["rate_forecast"]
    assert next(r for r in f["buckets"] if r["bucket"] == "endpoint_rules")["requests"] == pack["channels"]["endpoint"]
    assert f["title"] == "Will succeed" and "This run sends" in f["detail"]
    assert not any(w.startswith("ZIA rate limits") for w in rep["warnings"])
    zia_rate._t(A).sent["write"].extend(clock[0] - 200 + i for i in range(60))
    zia_rate.note_refusal("write", "Resource Access Blocked", key=A, status=403)
    clock[0] += 600
    rep2 = pd.preflight(_client(A), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    assert rep2["rate_forecast"]["severity"] == "fail" and rep2["warnings"][0].startswith("ZIA rate limits: Likely to fail")
    assert rep2["plan_hash"] == rep["plan_hash"], "the forecast is not part of the plan"
    rep3 = pd.preflight(_client(B), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    assert rep3["rate_forecast"]["severity"] == "ok", "another tenant's preflight is not affected"


def test_removal_preview_forecasts_its_deletes(clock, tmp_path):
    from test_pack_removal import _deletable, _pack_dir, _tenant
    client = _deletable(_tenant(with_survivors=False))
    client._zia_rate_key = A
    plan = pr.plan_removal(client, [_pack_dir(tmp_path)])
    f = plan["rate_forecast"]
    assert {r["bucket"]: r["requests"] for r in f["buckets"]} == {"delete": plan["remove_count"], "activate": 1}
    assert f["severity"] == "ok" and f["detail"]


def test_refused_runs_in_the_deployment_log_are_part_of_the_history(clock, tmp_path, monkeypatch):
    from datetime import datetime, timezone
    log = tmp_path / "deployments.json"
    at = datetime.fromtimestamp(clock[0] - 86400, timezone.utc).isoformat(timespec="seconds")
    log.write_text(json.dumps({"version": 1, "deployments": [
        {"id": "d1", "at": at, "tenant_label": "a", "created": [{"kind": "dictionary", "name": "X", "status": "failed", "error": "Resource Access Blocked"}]},
        {"id": "d2", "at": at, "tenant_label": "b", "created": [{"kind": "dictionary", "name": "Y", "status": "failed", "error": "Resource Access Blocked"}]}]}))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(log))
    f = zia_rate.forecast({"write": 5}, key=A, tenant_label="a")
    assert len(f["refused_runs"]) == 1 and "1 run(s) in the deployment log" in zia_rate.history_text(f)
