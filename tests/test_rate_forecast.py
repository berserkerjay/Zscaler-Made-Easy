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
    assert f["severity"] == "ok" and f["verdict"].startswith("Goes straight through")
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


def test_preflight_shows_the_rate_forecast_as_an_impact(clock):
    pack = next(p for p in PACKS if p["id"] == "zbp_enterprise_baseline")
    rep = pd.preflight(the_tenant(), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    f = rep["rate_forecast"]
    ep = next(r for r in f["buckets"] if r["bucket"] == "endpoint_rules")
    assert ep["requests"] == pack["channels"]["endpoint"]
    card = next(i for i in rep["impacts"] if i["type"] == "rate_limits")
    assert card["severity"] == "ok" and "Endpoint DLP rules" in card["detail"]
    # The same preview after 38 Endpoint rule writes in the last hour warns.
    for i in range(38):
        zia_rate._sent["endpoint_rules"].append(clock[0] - 300 + i)
    rep2 = pd.preflight(the_tenant(), [pack], writes_enabled=True, channel_targets={pack["id"]: ["endpoint"]})
    card2 = next(i for i in rep2["impacts"] if i["type"] == "rate_limits")
    assert card2["severity"] == "warning" and "38 of 40/hr" in card2["detail"]
    assert rep2["plan_hash"] == rep["plan_hash"], "the forecast is not part of the plan"


def test_removal_preview_forecasts_its_deletes(clock, tmp_path):
    from test_pack_removal import _deletable, _pack_dir, _tenant
    plan = pr.plan_removal(_deletable(_tenant(with_survivors=False)), [_pack_dir(tmp_path)])
    f = plan["rate_forecast"]
    assert {r["bucket"]: r["requests"] for r in f["buckets"]} == {"delete": plan["remove_count"], "activate": 1}
    assert f["severity"] == "ok"
