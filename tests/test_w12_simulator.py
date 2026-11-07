"""Wave 12 simulator rows: port-only check, stated default assumptions, per-area paste lists.

Offline: every read is a fake tenant; nothing touches the network and
nothing is written.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import path_analyzer as pa
import path_port_check as pc
from test_qa_func_path import DEFAULT_FW, FULL, Tenant, fw_rule

TELNET = {"id": 7, "name": "Telnet", "destTcpPorts": [{"start": 23, "end": 23}]}


def _zia(rules, services=None):
    t = Tenant({"/zia/firewallFilteringRules": rules, "/zia/networkServices": services or [TELNET]})
    out = pa.analyze(t, "example.com", "off", "windows", scope=FULL)
    assert t.writes == []
    return out["snapshot_for_cache"]["snapshot"]["zia"]


def test_a_port_blocked_by_a_rule_for_everyone_is_said_so_and_other_ports_are_not():
    """ASVS V1.1.2 · CWE-1059 · WSTG-CONF-01: a port only an unrestricted firewall rule blocks is blocked for everyone; another port is not."""
    zia = _zia([fw_rule(1, 1, "BLOCK_DROP", nwServices=[{"id": 7}]), DEFAULT_FW])
    blocked, other = pc.check(zia, "tcp", 23), pc.check(zia, "tcp", 25)
    assert blocked["answer"] == "blocked_for_everyone" and blocked["rule"]["name"] == "FW 1" and blocked["read_only"] is True
    assert other["answer"] == "allowed_for_everyone"
    assert pc.check(zia, "udp", 23)["answer"] == "allowed_for_everyone"


def test_a_rule_limited_to_some_destinations_makes_the_answer_depend_never_blocked_for_everyone():
    """ASVS V1.1.2 · CWE-693: a block limited to a destination group cannot be reported as blocked for everyone."""
    zia = _zia([fw_rule(1, 1, "BLOCK_DROP", nwServices=[{"id": 7}], destIpGroups=[{"id": 9, "name": "Partners"}]), DEFAULT_FW])
    r = pc.check(zia, "tcp", 23)
    assert r["answer"] == "depends" and any("FW 1" in d for d in r["depends_on"])


def test_an_unread_firewall_claims_nothing_and_a_bad_port_is_refused_in_words():
    """ASVS V5.1.3 · CWE-20: no firewall read gives no claim; a missing or out-of-range port is a plain sentence."""
    assert pc.check({"modules": {"firewall": {"state": "out_of_scope", "why": "Not in scope"}}}, "tcp", 23)["answer"] == "not_read"
    for bad in (None, "", 0, 70000, "x", True):
        with pytest.raises(ValueError):
            pc.check({}, "tcp", bad)
    with pytest.raises(ValueError):
        pc.check({}, "icmp", 23)


def test_the_port_check_route_answers_from_a_kept_read_and_refuses_unknown_reports():
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: the route reads only a kept data-flow report, makes no tenant call and 400s a bad port."""
    zia = _zia([fw_rule(1, 1, "BLOCK_DROP", nwServices=[{"id": 7}]), DEFAULT_FW])
    srv._REPORTS["dataflow-w12port"] = {"snapshot": {"zia": zia}, "tenant_label": "t"}
    c = TestClient(srv.app)
    try:
        ok = c.post("/api/report/data-flow/dataflow-w12port/port-check", json={"protocol": "tcp", "port": 23})
        assert ok.status_code == 200 and ok.json()["answer"] == "blocked_for_everyone"
        assert c.post("/api/report/data-flow/dataflow-w12port/port-check", json={"protocol": "tcp", "port": 0}).status_code == 400
        assert c.post("/api/report/data-flow/nope/port-check", json={"port": 23}).status_code == 404
    finally:
        srv._REPORTS.pop("dataflow-w12port", None)


def test_the_default_assumptions_are_stated_with_every_result_and_follow_the_traffic():
    """ASVS V1.1.2 · CWE-1059: every result lists what it assumed (any user, managed device, live read, unevaluated conditions, assumed port)."""
    res = pa.analyze(Tenant(), "example.com", "off", "windows", scope=FULL)
    text = " ".join(res["assumptions"])
    for phrase in ("Any user, group, department and location", "managed device", "time-of-day, device posture and user risk score are not evaluated",
                   "shown as unknown, never guessed"):
        assert phrase in text
    udp = pa.analyze(Tenant(), "example.com", "off", "windows", scope=FULL, protocol="udp", port=5000)
    assert "UDP/5000" in " ".join(udp["assumptions"]) and "Browser traffic over HTTPS" not in " ".join(udp["assumptions"])
    assert any("HTTPS (TCP/443) is assumed" in a for a in res["assumptions"])
