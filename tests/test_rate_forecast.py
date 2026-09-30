"""Each pack says how it measures against ZIA's rate limits, and a deploy or
removal preview says, from the requests sent in the last hour, whether the
run goes straight through or pauses for a limit."""
from __future__ import annotations

import json

import pytest

import pack_deploy as pd
import pack_removal as pr
import zia_rate
from dlp_importer import discover_packs
from test_pack_regression import PACKS, the_tenant


@pytest.fixture
def clock(monkeypatch):
    t = [1_800_000_000.0]
    monkeypatch.setattr(zia_rate, "_now", lambda: t[0])
    zia_rate.reset()
    return t


def test_every_pack_card_has_a_rate_note():
    for p in discover_packs():
        note = p["rate"]
        assert note["deploy"]["activate"] == 1 and note["remove"]["activate"] == 1
        assert note["deploy"]["endpoint_rules"] == p["channels"].get("endpoint", 0)
        assert note["remove"]["delete"] == p["dictionaries"] + p["engines"] + p["app_groups"] + sum(p["channels"].values())
        assert "Full deploy" in note["text"] and "Removal" in note["text"] and note["deploy_seconds"] > 0


def test_a_fresh_hour_goes_straight_through(clock):
    f = zia_rate.forecast({"write": 30, "endpoint_rules": 14, "activate": 1})
    assert f["severity"] == "ok" and f["title"] == "Will succeed" and "goes straight through" in f["verdict"]
    ep = next(r for r in f["buckets"] if r["bucket"] == "endpoint_rules")
    assert 60 <= ep["seconds"] < 120, "the 11th Endpoint rule waits for the minute"


def test_recent_requests_make_the_forecast_pause_and_say_why(clock):
    for i in range(38):
        zia_rate._sent["endpoint_rules"].append(clock[0] - 600 + i)
    f = zia_rate.forecast({"endpoint_rules": 9, "activate": 1})
    assert f["severity"] == "warn" and "38 of 40/hr already used" in f["verdict"]
    assert f["seconds"] > 45 * 60, "the 3rd rule waits until the oldest of the 38 leaves the hour"


def test_more_than_the_hourly_limit_is_flagged_even_from_a_fresh_start(clock):
    f = zia_rate.forecast({"activate": 45})
    assert f["severity"] == "warn" and "over the 40/hr limit" in f["verdict"]


def test_an_active_hold_is_the_verdict(clock):
    zia_rate.hold(600)
    assert "still resetting" in zia_rate.forecast({"write": 1})["verdict"]


def test_requests_survive_a_restart(clock, tmp_path, monkeypatch):
    state = tmp_path / "rate.json"
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(state))
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_ENDPOINT_RULES", "10/m,40/h")
    for _ in range(3):
        zia_rate.wait("POST", channel="endpoint", kind="policy")
    assert len(json.loads(state.read_text())["sent"]["endpoint_rules"]) == 3
    # A restart: the in-memory count is gone, the file brings it back.
    for q in zia_rate._sent.values():
        q.clear()
    zia_rate._loaded[0] = False
    f = zia_rate.forecast({"endpoint_rules": 1})
    assert f["recent"]["endpoint_rules"] == 3
    # Older than an hour: dropped on load.
    state.write_text(json.dumps({"sent": {"endpoint_rules": [clock[0] - 4000]}, "hold_until": 0}))
    for q in zia_rate._sent.values():
        q.clear()
    zia_rate._loaded[0] = False
    assert zia_rate.forecast({"endpoint_rules": 1})["recent"]["endpoint_rules"] == 0


def test_the_preflight_check_says_will_succeed_or_likely_to_fail(clock):
    pack = next(p for p in PACKS if p["id"] == "zbp_enterprise_baseline")
    rep = pd.preflight(the_tenant(), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    f = rep["rate_forecast"]
    ep = next(r for r in f["buckets"] if r["bucket"] == "endpoint_rules")
    assert ep["requests"] == pack["channels"]["endpoint"]
    assert f["title"] == "Will succeed" and "This run sends" in f["detail"]
    assert not any(w.startswith("ZIA rate limits") for w in rep["warnings"])
    # ZIA refused this client ten minutes ago: the check says it is likely to fail, first among the warnings.
    zia_rate.note_refusal("write", "Resource Access Blocked")
    clock[0] += 600
    rep2 = pd.preflight(the_tenant(), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    assert rep2["rate_forecast"]["severity"] == "fail" and rep2["warnings"][0].startswith("ZIA rate limits: Likely to fail")
    assert rep2["plan_hash"] == rep["plan_hash"], "the forecast is not part of the plan"


def test_the_container_state_of_the_refused_run_reads_as_likely_to_fail(clock, tmp_path, monkeypatch):
    """The container's own record after tonight's run: 110 writes in about
    3 minutes, then a one-hour hold. ZIA blocked the client far below its
    documented 400 an hour; that record predates refusal details, so the
    refusal is read from the hold."""
    start = clock[0] - 300
    writes = [start + i * 1.72 for i in range(110)]
    state = tmp_path / "zia_rate.json"
    state.write_text(json.dumps({"sent": {"write": writes}, "hold_until": start + 3600}))
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(state))
    for q in zia_rate._sent.values():
        q.clear()
    zia_rate._loaded[0] = False
    f = zia_rate.forecast({"write": 40, "activate": 1})
    assert f["severity"] == "fail" and f["verdict"].startswith("Likely to fail") and "110 requests" in f["verdict"]
    # Two hours later the hour has passed, but ZIA's tolerance is remembered: a
    # run as busy as that one is still called out, a small one is not.
    clock[0] += 7200
    big = zia_rate.forecast({"write": 158, "activate": 1})
    assert big["severity"] == "fail" and "blocked this API client after 110 requests in 5 minutes" in big["verdict"]
    small = zia_rate.forecast({"write": 20, "activate": 1})
    assert small["severity"] == "ok"


def test_every_zia_request_the_app_sends_is_observed(clock):
    zia_rate.observe("GET", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 200)
    zia_rate.observe("GET", "https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/1/segment", 200)   # not ZIA
    zia_rate.observe("GET", "https://zsapi.zscaler.net/api/v1/webDlpRules", 200, {"x-ratelimit-limit": "1000", "x-ratelimit-remaining": "900", "x-ratelimit-reset": "1200"})
    assert zia_rate.forecast({"write": 1})["sent_last_hour"] == {"read": 2}
    assert zia_rate._server["read"]["remaining"] == 900
    zia_rate.observe("POST", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 403, None, '{"code":"FORBIDDEN","message":"Resource Access Blocked"}')
    r = zia_rate._refused[-1]
    assert r[1] == "write" and "Resource Access Blocked" in r[2] and r[5] == 2
    zia_rate.observe("POST", "https://api.zsapi.net/zia/api/v1/dlpDictionaries", 403, None, '{"message":"Forbidden: role"}')
    assert len(zia_rate._refused) == 1, "a permission 403 is not a rate refusal"


def test_the_tap_sees_requests_sent_through_requests(clock, monkeypatch):
    from requests.adapters import HTTPAdapter
    import requests

    class Resp:
        status_code, headers, text = 429, {"x-ratelimit-limit": "10", "x-ratelimit-remaining": "0", "x-ratelimit-reset": "30"}, "Too Many Requests"
    monkeypatch.setattr(HTTPAdapter, "send", lambda self, request, *a, **k: Resp())
    monkeypatch.setattr(zia_rate, "_tapped", [False])
    zia_rate.install_tap()
    requests.Request("POST", "https://api.zsapi.net/zia/api/v1/status/activate").prepare()
    HTTPAdapter().send(requests.Request("POST", "https://api.zsapi.net/zia/api/v1/status/activate").prepare())
    assert zia_rate._refused[-1][1] == "activate" and zia_rate._server["activate"]["remaining"] == 0


def test_refused_runs_in_the_deployment_log_are_part_of_the_history(clock, tmp_path, monkeypatch):
    from datetime import datetime, timezone
    log = tmp_path / "deployments.json"
    at = datetime.fromtimestamp(clock[0] - 86400, timezone.utc).isoformat(timespec="seconds")
    log.write_text(json.dumps({"version": 1, "deployments": [{"id": "d1", "at": at, "created": [
        {"kind": "dictionary", "name": "X", "status": "failed", "error": "Resource Access Blocked"}]}]}))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(log))
    f = zia_rate.forecast({"write": 5})
    assert len(f["refused_runs"]) == 1 and "1 run(s) in the deployment log" in zia_rate.history_text(f)


def test_removal_preview_forecasts_its_deletes(clock, tmp_path):
    from test_pack_removal import _deletable, _pack_dir, _tenant
    plan = pr.plan_removal(_deletable(_tenant(with_survivors=False)), [_pack_dir(tmp_path)])
    f = plan["rate_forecast"]
    assert {r["bucket"]: r["requests"] for r in f["buckets"]} == {"delete": plan["remove_count"], "activate": 1}
    assert f["severity"] == "ok" and f["detail"]
