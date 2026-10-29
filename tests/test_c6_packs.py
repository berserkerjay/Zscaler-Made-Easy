"""Deep QA of the policy-pack execution path: pack_channels (channel table
and payloads), pack_ops (the shared write path: call(), retries, rate
limits, every kind's create / update / delete), pack_jobs (background jobs,
progress, cancel, stop-before-start) and pack_library (the on-disk pack
library, whose uploads are untrusted input).

Every Zscaler API detail below is checked against the installed
zscaler-sdk-python 1.11.3 (signatures through autospec, payload keys
against the SDK's models); the few that the SDK does not name are marked
"assumed". No test contacts a tenant: the SDK services are autospecced
fakes, and every store lives in the test's own folder.
"""
from __future__ import annotations

import importlib
import json
import math
import os
import re
import stat
import threading
from types import SimpleNamespace
from unittest import mock

import pytest

import audit
import pack_channels as pc
import pack_jobs
import pack_library as pl
import pack_ops as ops

SDK_ROOT = os.path.dirname(importlib.import_module("zscaler").__file__)


@pytest.fixture(autouse=True)
def _audit_log(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))


def _entries(event):
    return [r for r in audit.tail(100000) if r.get("event") == event]


# ---------------------------------------------------------------------------
# SDK fakes: every service an autospec of the real 1.11.3 class, so a call
# with arguments the SDK method does not take fails exactly as it would.
# ---------------------------------------------------------------------------

def _sdk_service(package: str, module: str, method: str):
    mod = importlib.import_module(f"zscaler.{package}.{module}")
    for name in dir(mod):
        cls = getattr(mod, name)
        if isinstance(cls, type) and cls.__module__ == mod.__name__ and hasattr(cls, method):
            return mock.create_autospec(cls, instance=True)
    raise AssertionError(f"zscaler.{package}.{module} has no class with {method}")


ZIA_SERVICES = {
    "dlp_dictionary": "add_dict", "dlp_engine": "add_dlp_engine", "proxies": "add_proxy",
    "cloud_firewall": "add_ip_destination_group", "forwarding_control": "add_rule", "cloud_firewall_rules": "add_rule",
    "sandbox_rules": "add_rule", "cloud_firewall_dns": "add_rule", "url_categories": "add_url_category",
    "url_filtering": "add_rule", "atp_policy": "update_atp_settings", "dlp_web_rules": "add_rule",
    "endpoint_dlp_rules": "add_rule", "casb_dlp_rules": "add_rule", "outbound_email_dlp_rules": "add_rule",
    "cloudappcontrol": "add_rule", "file_type_control_rule": "add_rule", "ssl_inspection_rules": "add_rule",
}
ZPA_SERVICES = {"application_segment": "add_segment", **{svc: c for svc, c, _u, _d in ops.ZPA_KINDS.values()}}


def sdk_zia():
    return SimpleNamespace(**{k: _sdk_service("zia", k, m) for k, m in ZIA_SERVICES.items()})


def sdk_zpa():
    return SimpleNamespace(**{k: _sdk_service("zpa", k, m) for k, m in ZPA_SERVICES.items()})


def sdk_aiguard():
    return SimpleNamespace(policies=_sdk_service("aiguard", "policies", "add_policy"),
                           policy_match_rules=_sdk_service("aiguard", "policy_match_rules", "add_rule"))


NAMED = {"name": "QA object", "description": "made by a test"}
ZPA_RULE = dict(NAMED, action="ALLOW")

CREATE_CASES = [
    ("zia", "dictionary", None, dict(NAMED, custom_phrase_match_type="MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY")),
    ("zia", "engine", None, dict(NAMED, engine_expression="((D63.S > 1))")),
    ("zia", "zia_proxy", None, NAMED), ("zia", "ip_destination_group", None, NAMED), ("zia", "forwarding_rule", None, NAMED),
    ("zia", "policy", "firewall", NAMED), ("zia", "policy", "sandbox", NAMED), ("zia", "policy", "dns", NAMED),
    ("zia", "url_category", None, {"super_category": "USER_DEFINED", "configured_name": "QA", "urls": ["qa.example"]}),
    *[("zia", "policy", ch, dict(NAMED, type="AI_ML")) for ch in pc.CHANNELS],
    ("zpa", "zpa_segment", None, NAMED),
    *[("zpa", k, None, ZPA_RULE) for k in ops.ZPA_KINDS],
    ("aiguard", "aiguard_policy", None, NAMED), ("aiguard", "aiguard_rule", None, NAMED),
]
UPDATE_CASES = [
    ("zia", "dictionary", None, NAMED), ("zia", "engine", None, NAMED), ("zia", "ip_destination_group", None, NAMED),
    ("zia", "forwarding_rule", None, NAMED), ("zia", "url_app_settings", None, {"enable_cipa_compliance": False}),
    ("zia", "atp_settings", None, {"risk_tolerance": 50}), ("zia", "url_category", None, {"configured_name": "QA"}),
    ("zia", "policy", "firewall", NAMED), ("zia", "policy", "sandbox", NAMED), ("zia", "policy", "dns", NAMED),
    *[("zia", "policy", ch, dict(NAMED, type="AI_ML")) for ch in pc.CHANNELS],
    ("zpa", "zpa_segment", None, NAMED),
    *[("zpa", k, None, ZPA_RULE) for k in ops.ZPA_KINDS],
    ("aiguard", "aiguard_policy", None, NAMED), ("aiguard", "aiguard_rule", None, NAMED),
]
DELETE_CASES = [
    ("zia", {"kind": "dictionary"}), ("zia", {"kind": "engine"}), ("zia", {"kind": "url_category"}), ("zia", {"kind": "zia_proxy"}),
    ("zia", {"kind": "ip_destination_group"}), ("zia", {"kind": "forwarding_rule"}),
    ("zia", {"kind": "policy", "channel": "firewall"}), ("zia", {"kind": "policy", "channel": "sandbox"}),
    ("zia", {"kind": "policy", "channel": "dns"}),
    *[("zia", {"kind": "policy", "channel": ch, "type": "AI_ML" if ch == pc.CLOUD_APP else "OFLCASB_DLP_FILE"}) for ch in pc.CHANNELS],
    ("zpa", {"kind": "zpa_segment", "force_delete": True}), *[("zpa", {"kind": k}) for k in ops.ZPA_KINDS],
    ("aiguard", {"kind": "aiguard_policy"}), ("aiguard", {"kind": "aiguard_rule"}),
]
ROOTS = {"zia": sdk_zia, "zpa": sdk_zpa, "aiguard": sdk_aiguard}


@pytest.mark.parametrize("root,kind,channel,payload", CREATE_CASES, ids=lambda v: str(v) if isinstance(v, str) else None)
def test_every_create_binds_to_the_sdk_1_11_3_method_signature(root, kind, channel, payload):
    """ASVS V5.1.1 · CWE-628 · WSTG-INPV-01: every kind's create calls an SDK 1.11.3 method that exists, with arguments it accepts."""
    client = ROOTS[root]()
    out = ops.create(client, kind, dict(payload), channel=channel)
    assert out.ok, out.error


@pytest.mark.parametrize("root,kind,channel,payload", UPDATE_CASES, ids=lambda v: str(v) if isinstance(v, str) else None)
def test_every_update_binds_to_the_sdk_1_11_3_method_signature(root, kind, channel, payload):
    """ASVS V5.1.1 · CWE-628 · WSTG-INPV-01: every kind's update calls an SDK 1.11.3 method that exists, with arguments it accepts."""
    client = ROOTS[root]()
    out = ops.update(client, kind, 42, dict(payload), channel=channel, action="ADD_TO_LIST" if kind == "url_category" else None)
    assert out.ok, out.error


@pytest.mark.parametrize("root,item", DELETE_CASES, ids=lambda v: v if isinstance(v, str) else f"{v['kind']}-{v.get('channel')}")
def test_every_delete_binds_to_the_sdk_1_11_3_method_signature(root, item):
    """ASVS V5.1.1 · CWE-628 · WSTG-INPV-01: every kind's delete calls an SDK 1.11.3 method that exists, with arguments it accepts."""
    client = ROOTS[root]()
    out = ops.delete(client, dict(item, id=42, name="QA object"))
    assert out.ok, out.error


def test_a_saas_delete_passes_the_rule_type_the_sdk_takes():
    """ASVS V5.1.1 · CWE-628 · WSTG-INPV-01: a SaaS rule delete sends rule_type, which casb_dlp_rules.delete_rule needs (else the rule survives)."""
    zia = sdk_zia()
    ops.delete(zia, {"kind": "policy", "channel": pc.SAAS, "id": 7, "name": "R", "type": "OFLCASB_DLP_GENAI"})
    zia.casb_dlp_rules.delete_rule.assert_called_once_with(7, rule_type="OFLCASB_DLP_GENAI")


def test_a_zpa_policy_rule_is_deleted_by_its_policy_type():
    """ASVS V5.1.1 · CWE-628 · WSTG-INPV-01: ZPA policies.delete_rule(policy_type, rule_id) gets the policy type of each rule kind."""
    zpa = sdk_zpa()
    for kind, policy in ops.ZPA_RULE_POLICY.items():
        ops.delete(zpa, {"kind": kind, "id": 9, "name": "R"})
        zpa.policies.delete_rule.assert_called_with(policy, 9)


def _model_fields(module: str) -> set:
    src = open(os.path.join(SDK_ROOT, "zia", "models", module + ".py"), encoding="utf-8").read()
    return set(re.findall(r"self\.([a-z_0-9]+)\s*=", src))


CHANNEL_MODELS = {pc.WEB: "dlp_web_rules", pc.ENDPOINT: "endpoint_dlp_rules", pc.SAAS: "casb_dlp_rules",
                  pc.EMAIL: "outbound_email_dlp_rules", pc.CLOUD_APP: "cloudappcontrol", pc.FILE_TYPE: "filetyperules",
                  pc.URL: "url_filtering_rules", pc.SSL: "ssl_inspection_rules"}
EVERY_OPTION = {
    "name": "R", "description": "d", "severity": "RULE_SEVERITY_HIGH", "file_types": ["FTCATEGORY_PDF_DOCUMENT"], "engines": ["E"],
    "user_risk_score_levels": ["LOW"], "network_type": "TRUSTED", "min_size": 1, "eun_enabled": True, "saas_type": "OFLCASB_DLP_FILE",
    "components": ["COMPONENT_FILE"], "content_location": "CONTENT_LOCATION_SHARED", "recipient": "EXTERNAL", "domains": ["a.example"],
    "content_locations": ["BODY"], "custom_header": "X-QA", "type": "AI_ML", "actions": ["ALLOW_AI_ML_UPLOAD"], "applications": ["CHATGPT"],
    "user_agent_types": ["OTHER"], "time_quota": 1, "size_quota": 1, "url_categories": ["ANY"], "device_trust_levels": ["LOW_TRUST"],
    "max_size": 2, "active_content": True, "unscannable": True, "request_methods": ["GET"], "end_user_notification_url": "https://n.example",
    "block_override": True, "road_warrior_for_kerberos": True, "protocols": ["ANY_RULE"], "filtering_action": "ALLOW", "operation": "UPLOAD",
}
EVERY_RESOLVED = {"labels": [1], "notification_template": 2, "app_group_ids": [3], "uc_template_id": 4,
                  "tenants": [{"id": 5, "name": "t"}], "cloud_applications": ["CHATGPT"]}


@pytest.mark.parametrize("channel", sorted(CHANNEL_MODELS))
def test_every_payload_field_is_a_field_of_the_sdk_model_for_that_rule(channel):
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: every key build_payload sends for a channel is a field of that rule's SDK 1.11.3 model."""
    p = dict(EVERY_OPTION, channel=channel, action={"type": "DO_NOT_DECRYPT"} if channel == pc.SSL else "CONFIRM")
    body = pc.build_payload(channel, p, [9], EVERY_RESOLVED)
    assert set(body) - _model_fields(CHANNEL_MODELS[channel]) == set()


def test_a_saas_rule_payload_carries_no_notification_template():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: the SaaS Security API rule (CasbdDlpRules) has no notification template, so none is sent."""
    body = pc.build_payload(pc.SAAS, {"name": "R", "saas_type": "OFLCASB_DLP_FILE"}, [1], {"notification_template": 77})
    assert "notification_template" not in body


@pytest.mark.parametrize("channel", [pc.ENDPOINT, pc.EMAIL])
def test_the_notification_template_still_reaches_endpoint_and_email_rules(channel):
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: Endpoint and Email DLP rules keep their notification template ({id})."""
    body = pc.build_payload(channel, {"name": "R"}, [1], {"notification_template": 77})
    assert body["notification_template"] == {"id": 77}


# ---------------------------------------------------------------------------
# Channel table: rule types and actions as ZIA names them
# ---------------------------------------------------------------------------

def test_the_saas_rule_types_are_exactly_those_the_sdk_documents():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: SAAS_RULE_TYPES equals casb_dlp_rules' supported rule types (ANY and NONE are list filters)."""
    src = open(os.path.join(SDK_ROOT, "zia", "casb_dlp_rules.py"), encoding="utf-8").read()
    documented = set(re.findall(r"`(OFLCASB_DLP_[A-Z]+)`", src))
    assert set(pc.SAAS_RULE_TYPES) == documented


# The monitor (non-enforcing) actions per channel. SaaS: the SDK's own example
# action is OFLCASB_DLP_REPORT_INCIDENT; the rest follow the ZIA API and are
# assumed (the SDK documents action as a free string).
MONITOR_ORACLE = {pc.WEB: {"ALLOW"}, pc.ENDPOINT: {"ALLOW"}, pc.SAAS: {"OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW"},
                  pc.EMAIL: {"ALLOW"}, pc.FILE_TYPE: {"ALLOW"}, pc.URL: {"ALLOW"}, pc.SSL: {"DO_NOT_DECRYPT"}}
ENFORCING_ORACLE = [(pc.WEB, "BLOCK"), (pc.WEB, "CONFIRM"), (pc.WEB, "ICAP_RESPONSE"), (pc.ENDPOINT, "BLOCK"), (pc.ENDPOINT, "CONFIRM"),
                    (pc.SAAS, "OFLCASB_DLP_QUARANTINE"), (pc.EMAIL, "BLOCK"), (pc.EMAIL, "CUSTOMHEADERINSERTION"),
                    (pc.FILE_TYPE, "BLOCK"), (pc.FILE_TYPE, "CAUTION"), (pc.URL, "BLOCK"), (pc.URL, "CAUTION"), (pc.URL, "ISOLATE"),
                    (pc.SSL, "DECRYPT"), (pc.SSL, "BLOCK"), (pc.CLOUD_APP, "BLOCK_AI_ML_UPLOAD"), (pc.CLOUD_APP, "UPLOAD=ISOLATE")]


@pytest.mark.parametrize("channel", sorted(MONITOR_ORACLE))
def test_each_channel_names_exactly_its_monitor_actions(channel):
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: the channel table's monitor actions match ZIA's monitor-only action per rule type."""
    assert pc.CHANNELS[channel]["monitor_actions"] == MONITOR_ORACLE[channel]
    assert all(not pc.is_enforcing(channel, a) for a in MONITOR_ORACLE[channel])


@pytest.mark.parametrize("channel,action", ENFORCING_ORACLE)
def test_each_enforcing_action_is_enforcing(channel, action):
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: every ZIA action that blocks, warns, decrypts or isolates is reported as enforcing."""
    assert pc.is_enforcing(channel, action)


@pytest.mark.parametrize("channel,action", [(pc.ENDPOINT, "block"), (pc.EMAIL, "QUARANTINE"), (pc.WEB, "Block"),
                                            (pc.URL, "REDIRECT"), (pc.FILE_TYPE, "ALLOW_WITH_WARNING")])
def test_an_action_the_table_does_not_name_is_enforcing(channel, action):
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: deny by default: an unknown or lower-case action counts as enforcing, never as monitoring."""
    assert pc.is_enforcing(channel, action)


@pytest.mark.parametrize("channel,action", [(pc.ENDPOINT, "block"), (pc.EMAIL, "QUARANTINE"), (pc.SAAS, "oflcasb_dlp_block"),
                                            (pc.WEB, "Block"), (pc.WEB, "REDIRECT")])
def test_a_rule_with_an_unknown_action_is_created_monitor_only(channel, action):
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: a pack rule whose action is unknown or lower case is created with the monitor action, disabled."""
    p = {"name": "R", "channel": channel, "action": action, "saas_type": "OFLCASB_DLP_FILE"}
    body = pc.build_payload(channel, p, [1], {})
    assert (body["action"], body["state"]) == (pc.default_action(channel), "DISABLED")


def test_ship_monitor_keeps_an_unknown_action_as_the_target_and_ships_monitor():
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: a lower-case 'block' is kept as target_action and the rule ships ALLOW."""
    (q,) = pc.ship_monitor([{"name": "R", "channel": "endpoint", "action": "block"}])
    assert (q["action"], q["target_action"]) == ("ALLOW", "block")


def test_an_empty_action_is_not_enforcing():
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-02: no action at all is the monitor default, not enforcement (boundary)."""
    assert not any(pc.is_enforcing(ch, a) for ch in pc.CHANNELS for a in ("", None, "   "))


def test_endpoint_transfer_methods_include_the_ones_the_sdk_names():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the Endpoint DLP transfer methods include the SDK's examples (the other two are assumed)."""
    assert {"NETWORK_DRIVE_TRANSFER", "PRINTING"} <= set(pc.ENDPOINT_TRANSFER_METHODS)
    assert pc.validate({"name": "R", "channel": "endpoint", "data_transfer_method": "ANY"})


# ---------------------------------------------------------------------------
# Raw request paths: an id is a number or nothing is sent
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [(7, "7"), ("12", "12"), (" 12 ", "12"), (0, "0"), (-1, None), (True, None), (None, None),
                                            ("", None), ("1/../../status", None), ("7?x=1", None), ("1e3", None), ("٣", None),
                                            ("9" * 21, None), (1.5, None)])
def test_path_id_accepts_only_a_whole_number(value, expected):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: only a non-negative whole number is put into a raw request path (oracle table)."""
    assert pc.path_id(value) == expected


def test_a_sub_rule_create_with_a_path_in_its_parent_id_sends_nothing(monkeypatch):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: an Endpoint sub-rule create whose parent id is a path is refused before any request."""
    sent = []
    monkeypatch.setattr(pc, "raw_request", lambda *a, **k: sent.append(a) or ({"id": 1}, None))
    out = ops.create(object(), "policy", {"name": "S"}, channel=pc.ENDPOINT, parent_id="1/../../status/activate")
    assert (out.ok, sent) == (False, [])


def test_a_sub_rule_update_with_a_path_in_its_id_sends_nothing(monkeypatch):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: an Endpoint sub-rule update whose id is a path is refused before any request."""
    sent = []
    monkeypatch.setattr(pc, "raw_request", lambda *a, **k: sent.append(a) or ({"id": 1}, None))
    out = ops.update(object(), "policy", "2/../9", {"name": "S"}, channel=pc.ENDPOINT, parent_id=1)
    assert (out.ok, sent) == (False, [])


def test_an_app_group_update_with_a_path_in_its_id_sends_nothing(monkeypatch):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: an application group update whose id is a path is refused before any request."""
    sent = []
    monkeypatch.setattr(pc, "raw_request", lambda *a, **k: sent.append(a) or ({"id": 1}, None))
    out = ops.update(object(), "app_group", "1?x", {"name": "G"})
    assert (out.ok, sent) == (False, [])


@pytest.mark.parametrize("item", [{"kind": "app_group", "id": "1/../../status"}, {"kind": "root_certificate", "id": "x"},
                                  {"kind": "policy", "channel": "endpoint", "parent_id": "1/..", "id": 3},
                                  {"kind": "policy", "channel": "endpoint", "parent_id": 1, "id": "3/x"}])
def test_a_raw_path_delete_with_an_id_that_is_not_a_number_sends_nothing(monkeypatch, item):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: a delete sent as a raw path refuses an id that is not a number; no DELETE goes out."""
    sent = []
    monkeypatch.setattr(pc, "raw_request", lambda *a, **k: sent.append(a) or (None, None))
    out = ops.delete(object(), dict(item, name="N"))
    assert (out.ok, sent) == (False, [])
    assert "nothing was sent" in out.error


def test_a_raw_path_delete_with_a_numeric_id_is_sent_to_that_path(monkeypatch):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: a valid sub-rule delete reaches /endPointDlpRules/{parent}/subRule/{id} (positive case)."""
    sent = []
    monkeypatch.setattr(pc, "raw_request", lambda zia, method, path, *a: sent.append((method, path)) or (None, None))
    out = ops.delete(object(), {"kind": "policy", "channel": "endpoint", "parent_id": "11", "id": 22, "name": "S"})
    assert out.ok and sent == [("DELETE", "/endPointDlpRules/11/subRule/22")]


def test_a_delete_with_an_unknown_channel_is_refused_in_words():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a rule delete naming an unknown channel fails in words, not with a KeyError."""
    out = ops.delete(sdk_zia(), {"kind": "policy", "channel": "fax", "id": 4, "name": "R"})
    assert not out.ok and "unknown channel" in out.error


def test_a_delete_with_no_id_sends_nothing():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a delete item without an id fails in words (boundary), never a KeyError."""
    zia = sdk_zia()
    out = ops.delete(zia, {"kind": "dictionary", "name": "D"})
    assert not out.ok and zia.dlp_dictionary.delete_dict.call_count == 0


def test_a_failed_delete_is_still_audited():
    """ASVS V7.1.3 · CWE-778 · WSTG-ERRH-01: a delete refused before sending still leaves one object_write audit entry."""
    ops.delete(object(), {"kind": "app_group", "id": "../x", "name": "G"})
    assert [e["result"] for e in _entries("object_write")] == ["failed"]


# ---------------------------------------------------------------------------
# call(): retries, backoff, rate limits
# ---------------------------------------------------------------------------

class _Resp:
    def __init__(self, headers):
        self.headers = headers


def _refusal(status, message, headers=None):
    return (None, _Resp(headers or {}), {"status": status, "message": message})


def _scripted(*answers):
    """An SDK method that answers each call with the next item (an exception is raised)."""
    calls = []

    def fn(*a, **k):
        calls.append((a, k))
        ans = answers[min(len(calls), len(answers)) - 1]
        if isinstance(ans, BaseException):
            raise ans
        return ans
    fn.calls = calls
    return fn


@pytest.fixture
def sleeps(monkeypatch):
    seen = []
    monkeypatch.setattr(ops, "_sleep", seen.append)
    return seen


def test_a_transient_refusal_backs_off_linearly(sleeps):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a 503 on an update is retried with growing waits (1 s, 2 s), up to MAX_ATTEMPTS tries."""
    fn = _scripted(_refusal(503, "Service Unavailable"))
    out = ops.call(fn, op="update", kind="engine", name="E")
    assert (len(fn.calls), sleeps, out.attempts) == (ops.MAX_ATTEMPTS, [1.0, 2.0], ops.MAX_ATTEMPTS)


def test_a_refusal_that_is_not_transient_is_sent_once(sleeps):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a 400 is reported once, never retried."""
    fn = _scripted(_refusal(400, "Request body is invalid."))
    out = ops.call(fn, op="update", kind="engine", name="E")
    assert (len(fn.calls), sleeps, out.ok) == (1, [], False)


@pytest.mark.parametrize("message", ["Rule 15030 not found", "Dictionary id 4290 is in use", "engine 50412 refused", "v1.503 schema"])
def test_a_number_containing_a_status_code_is_not_transient(message):
    """ASVS V11.1.4 · CWE-697 · WSTG-BUSL-05: an id such as 15030 in ZIA's message is not mistaken for a 503 and retried."""
    assert not ops.is_transient(message)


@pytest.mark.parametrize("message", ["HTTP 503", "status_code=429", "504 Gateway Time-out", "(502)", "Read timed out", "try again later"])
def test_a_real_transient_answer_is_still_transient(message):
    """ASVS V11.1.4 · CWE-697 · WSTG-BUSL-05: the statuses and words of a transient refusal are still recognised (oracle table)."""
    assert ops.is_transient(message)


def test_a_create_that_timed_out_is_not_resent_without_a_read_by_name(sleeps):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: a create (POST) answered by a timeout is not sent twice when nothing can show it is absent."""
    fn = _scripted(TimeoutError("Read timed out"), {"id": 5})
    out = ops.call(fn, op="create", kind="zia_proxy", name="P")
    assert (len(fn.calls), out.ok) == (1, False) and "not sent again" in out.error


def test_a_default_write_that_timed_out_is_not_resent(sleeps):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: call()'s default op 'write' is a POST, so a timeout there is not resent blindly either."""
    fn = _scripted(TimeoutError("Read timed out"), {"id": 5})
    out = ops.call(fn, kind="x", name="P")
    assert (len(fn.calls), out.ok) == (1, False)


def test_a_create_that_timed_out_is_resent_only_after_a_read_shows_it_absent(sleeps):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: a read by name that finds nothing lets the create go out again once."""
    fn = _scripted(TimeoutError("Read timed out"), {"id": 5})
    out = ops.call(fn, op="create", kind="engine", name="E", exists=lambda: None)
    assert (len(fn.calls), out.ok, out.id) == (2, True, 5)


def test_a_create_found_by_name_after_a_timeout_is_its_answer(sleeps):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: a create that was applied despite the timeout is found by name and not sent again."""
    fn = _scripted(TimeoutError("Read timed out"))
    out = ops.call(fn, op="create", kind="engine", name="E", exists=lambda: 88)
    assert (len(fn.calls), out.ok, out.id) == (1, True, 88)


def test_a_create_refused_with_a_429_is_retried_because_it_was_never_processed(sleeps):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: a 429 create was not processed, so it is retried without a read by name."""
    fn = _scripted(_refusal(429, "Too Many Requests"), {"id": 3})
    out = ops.call(fn, op="create", kind="engine", name="E")
    assert (len(fn.calls), out.ok) == (2, True)


def test_outside_a_run_a_429_waits_for_zias_reset_timer(sleeps):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a 429 with Retry-After: 20 is not tried again before 20 s (the 1 s backoff is not enough)."""
    fn = _scripted(_refusal(429, "Too Many Requests", {"Retry-After": "20"}), {"id": 3})
    out = ops.call(fn, op="update", kind="engine", name="E")
    assert out.ok and sleeps == [20.0]


def test_outside_a_run_a_429_with_a_long_reset_is_reported_not_retried(sleeps):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a 429 asking for 10 minutes is reported at once instead of retried early or held."""
    fn = _scripted(_refusal(429, "Too Many Requests", {"Retry-After": "600"}), {"id": 3})
    out = ops.call(fn, op="update", kind="engine", name="E")
    assert (len(fn.calls), out.ok, sleeps) == (1, False, [])


@pytest.mark.parametrize("value,expected", [("30", 30.0), ("0", None), ("-5", None), ("inf", None), ("nan", None), ("1e12", None),
                                            ("3600", 3600.0), ("3601", None), ("Wed, 21 Oct 2026 07:28:00 GMT", None), ("12, 40", 12.0)])
def test_zias_reset_timer_is_trusted_only_when_finite_and_bounded(value, expected):
    """ASVS V11.1.4 · CWE-835 · WSTG-BUSL-05: Retry-After of inf, NaN, 1e12 or an HTTP date never becomes an unbounded hold (oracle table)."""
    assert ops._reset_seconds(_refusal(429, "x", {"Retry-After": value})) == expected


def test_headers_that_are_not_a_mapping_keep_the_refusal():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: an answer whose headers are not a mapping still yields ZIA's refusal, not a TypeError."""
    out = ops.normalize((None, _Resp([1, 2, 3]), {"status": 429, "message": "Too Many Requests"}))
    assert (out.ok, out.http_status, out.reset_seconds) == (False, 429, None)


def test_an_exception_quoting_a_bearer_token_is_redacted():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: an SDK exception that echoes the Authorization header never carries the token on."""
    token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJxYSJ9.c2lnbmF0dXJlLXFh"
    fn = _scripted(RuntimeError(f"401 for request with Authorization: Bearer {token}"))
    out = ops.call(fn, op="update", kind="engine", name="E")
    assert token not in out.error and "redacted" in out.error


def test_an_error_answer_quoting_a_token_is_redacted():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: an error body that repeats a session id is redacted before it reaches a log."""
    out = ops.normalize((None, None, {"status": 500, "message": "JSESSIONID=ABCDEF1234567890 rejected"}))
    assert "ABCDEF1234567890" not in out.error


def test_a_huge_error_message_is_bounded():
    """ASVS V7.1.1 · CWE-400 · WSTG-ERRH-01: a megabyte error answer is cut to 300 characters before it is kept."""
    out = ops.normalize((None, None, "x" * 1_000_000))
    assert len(out.error) <= 300


@pytest.mark.parametrize("ret,ok,oid", [((None, None, None), True, None), (({"id": 4}, None, None), True, 4), ((None, "boom"), False, None),
                                        (({"id": 6},), True, 6), ((), True, None), (None, False, None), ({"id": 8}, True, 8),
                                        (SimpleNamespace(id=9), True, 9)])
def test_normalize_reads_every_sdk_return_shape(ret, ok, oid):
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: (data, response, error), (data, error), a bare object, a dict and None become one Outcome."""
    out = ops.normalize(ret)
    assert (out.ok, out.id) == (ok, oid)


def _zia_403():
    zia = sdk_zia()
    zia.dlp_engine.update_dlp_engine.return_value = _refusal(403, "Forbidden")
    return zia


def test_inside_a_run_a_zia_403_is_waited_out_and_retried(sleeps):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: a ZIA 403 inside a run is retried FORBIDDEN_ATTEMPTS times after waits, then stops the run."""
    zia = _zia_403()
    with ops.run_scope():
        out = ops.update(zia, "engine", 5, {"name": "E"})
        stopped = ops.stop_reason()
    assert zia.dlp_engine.update_dlp_engine.call_count == 1 + ops.FORBIDDEN_ATTEMPTS
    assert not out.ok and stopped


def test_a_zpa_403_inside_a_run_is_not_retried_as_if_it_were_zia(sleeps):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: the 403 wait-and-retry is ZIA's only; a ZPA write refused with 403 is sent once."""
    zpa = sdk_zpa()
    zpa.segment_groups.update_group.return_value = _refusal(403, "Forbidden")
    with ops.run_scope():
        ops.update(zpa, "zpa_segment_group", 5, {"name": "G"})
    assert zpa.segment_groups.update_group.call_count == 1


def test_an_aiguard_403_inside_a_run_is_not_retried_as_if_it_were_zia(sleeps):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: AI Guard has no activation, so its 403 gets no ZIA wait-and-retry."""
    aig = sdk_aiguard()
    aig.policies.update_policy.return_value = _refusal(403, "Forbidden")
    with ops.run_scope():
        ops.update(aig, "aiguard_policy", 5, {"name": "P"})
    assert aig.policies.update_policy.call_count == 1


def test_outside_a_run_a_zia_403_is_sent_once(sleeps):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: one change from a page (outside a run) is not retried on a 403."""
    zia = _zia_403()
    ops.update(zia, "engine", 5, {"name": "E"})
    assert zia.dlp_engine.update_dlp_engine.call_count == 1


def test_a_cancelled_run_sends_nothing():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: after Stop, a write comes back not attempted and the SDK is never called."""
    zia, stop = sdk_zia(), threading.Event()
    stop.set()
    with ops.run_scope(stop):
        out = ops.create(zia, "engine", {"name": "E"})
    assert (out.code, zia.dlp_engine.add_dlp_engine.call_count) == (ops.STOPPED, 0)


def test_an_unknown_kind_is_refused_in_words():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: create / update / delete of an unknown kind fail in words, sending nothing."""
    outs = [ops.create(object(), "fax", {}), ops.update(object(), "fax", 1, {}), ops.delete(object(), {"kind": "fax", "id": 1})]
    assert all(not o.ok and "unknown object kind" in o.error for o in outs)


# ---------------------------------------------------------------------------
# pack_jobs: cancel, caps, logs, start tokens
# ---------------------------------------------------------------------------

@pytest.fixture
def jobs(monkeypatch):
    """A clean job registry for the test."""
    monkeypatch.setattr(pack_jobs, "_jobs", {})
    monkeypatch.setattr(pack_jobs, "_pending_stops", {})
    monkeypatch.setattr(pack_jobs, "_token_jobs", {})
    return pack_jobs


def _finish(job):
    job.thread.join(timeout=2)
    assert not job.thread.is_alive()
    return job


def test_a_poller_keeps_receiving_lines_after_the_log_is_cut(jobs, monkeypatch):
    """ASVS V7.1.4 · CWE-400 · WSTG-BUSL-05: once the log is cut at the top, a poller following `next` still gets every new line."""
    monkeypatch.setattr(jobs, "MAX_LOG_LINES", 5)
    job = jobs.Job(id="j1", kind="deploy")
    for i in range(5):
        job.log(f"line {i}")
    cursor = jobs.snapshot(job)["next"]
    job.log("line 5")
    snap = jobs.snapshot(job, cursor)
    assert (snap["logs"], snap["next"]) == (["line 5"], 6)


def test_a_poller_far_behind_gets_what_is_left(jobs, monkeypatch):
    """ASVS V7.1.4 · CWE-400 · WSTG-BUSL-05: a poller whose cursor was cut away gets the kept lines, not an error (boundary)."""
    monkeypatch.setattr(jobs, "MAX_LOG_LINES", 3)
    job = jobs.Job(id="j1", kind="deploy")
    for i in range(10):
        job.log(f"line {i}")
    assert jobs.snapshot(job, 1)["logs"] == ["line 7", "line 8", "line 9"]


def test_a_negative_cursor_returns_the_whole_log(jobs):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: since=-5 is read as the start of the log (boundary)."""
    job = jobs.Job(id="j1", kind="deploy")
    job.log("a")
    assert jobs.snapshot(job, -5)["logs"] == ["a"]


def test_one_job_log_line_is_capped(jobs):
    """ASVS V7.1.4 · CWE-400 · WSTG-BUSL-05: a single log line of a megabyte is cut to MAX_LOG_LINE_CHARS."""
    job = jobs.Job(id="j1", kind="deploy")
    job.log("x" * 1_000_000)
    assert len(job.logs[0]) <= jobs.MAX_LOG_LINE_CHARS + 10


@pytest.mark.parametrize("line,secret", [("client_secret=s3cr3t-Value done", "s3cr3t-Value"), ('{"password": "hunter2 x"}', "hunter2"),
                                         ("provisioningKey=3|abc.def", "3|abc.def"), ("api_key: K-123,", "K-123"),
                                         ("Authorization: Bearer abcdefghijkl12345", "abcdefghijkl12345")])
def test_a_secret_in_a_job_log_line_is_masked(jobs, line, secret):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: a client secret, password, API key, provisioning key or token in a job log is masked."""
    job = jobs.Job(id="j1", kind="deploy")
    job.log(line)
    assert secret not in job.logs[0]


@pytest.mark.parametrize("line", ["ZIP member is password-protected; export it again", "[zpa_provisioning_key] Key 1: created",
                                  "Stop requested: the write in flight finishes"])
def test_an_ordinary_job_log_line_is_kept_as_written(jobs, line):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: masking leaves lines that only mention a secret's name untouched (negative case)."""
    job = jobs.Job(id="j1", kind="deploy")
    job.log(line)
    assert job.logs == [line]


def test_an_abandon_racing_the_runs_own_ending_writes_one_job_finished(jobs, monkeypatch):
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: when self-heal abandons a job while it writes its own ending, only one ending wins."""
    real = jobs._audit_finished

    def racing(job, final):
        jobs.abandon(job, "stuck")   # self-heal lands while the run is writing its own ending
        real(job, final)
    monkeypatch.setattr(jobs, "_audit_finished", racing)
    job = _finish(jobs.start("deploy", lambda log, cancel: {"status": "ok"}))
    assert (job.status, [e["status"] for e in _entries("job_finished")]) == (jobs.DONE, [jobs.DONE])


def test_an_abandoned_job_stays_failed_when_its_thread_ends_later(jobs):
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: a job marked stuck keeps status failed and its late ending is audited apart."""
    gate = threading.Event()
    job = jobs.start("deploy", lambda log, cancel: gate.wait(2) and {"status": "ok"})
    assert jobs.abandon(job, "stuck: no log line for an hour")
    gate.set()
    _finish(job)
    assert (job.status, len(_entries("job_finished")), len(_entries("job_finished_late"))) == (jobs.FAILED, 1, 1)


def test_prune_never_drops_a_job_that_has_not_published_its_ending(jobs):
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: a job whose finish time is set but whose status is still running is kept."""
    job = jobs.Job(id="j1", kind="deploy", finished=1.0)
    jobs._jobs[job.id] = job
    jobs.prune(now=1e12)
    assert jobs.get("j1") is job


def test_the_finished_job_store_is_capped(jobs, monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: at most MAX_FINISHED_JOBS finished jobs are kept, the oldest dropped first."""
    monkeypatch.setattr(jobs, "MAX_FINISHED_JOBS", 3)
    for i in range(6):
        jobs._jobs[f"f{i}"] = jobs.Job(id=f"f{i}", kind="deploy", status=jobs.DONE, finished=100.0 + i)
    jobs._jobs["r"] = jobs.Job(id="r", kind="deploy")
    dropped = jobs.prune(now=101.0)
    assert (dropped, sorted(jobs._jobs)) == (3, ["f3", "f4", "f5", "r"])


def test_a_job_finished_more_than_an_hour_ago_is_dropped(jobs):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: a finished job older than KEEP_SECONDS goes; a running one never does."""
    jobs._jobs["old"] = jobs.Job(id="old", kind="deploy", status=jobs.DONE, finished=1.0)
    jobs._jobs["run"] = jobs.Job(id="run", kind="deploy")
    jobs.prune(now=jobs.KEEP_SECONDS + 2.0)
    assert sorted(jobs._jobs) == ["run"]


@pytest.mark.parametrize("token", ["short", "x" * 65, "has space12", "abc$defgh", "", None, "../../etc1"])
def test_a_malformed_start_token_is_refused(jobs, token):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a start token that is not 8-64 letters, digits, '-' or '_' is refused (oracle table)."""
    with pytest.raises(ValueError):
        jobs.stop_before_start(token)


def test_a_malformed_start_token_on_start_names_no_job(jobs):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: start() ignores a malformed token rather than registering it."""
    job = _finish(jobs.start("deploy", lambda log, cancel: {}, start_token="bad token!"))
    assert job.status == jobs.DONE and jobs._token_jobs == {}


def test_a_stop_before_the_start_makes_the_job_begin_stopped(jobs):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: a Stop sent with the start token before the job exists makes it start cancelled."""
    seen = {}
    assert jobs.stop_before_start("tok_12345678")["pending"] is True
    job = _finish(jobs.start("deploy", lambda log, cancel: seen.setdefault("cancel", cancel.is_set()) and {"stopped": "x"},
                             start_token="tok_12345678"))
    assert seen["cancel"] and job.status == jobs.CANCELLED and job.logs[0] == jobs.STOPPED_BEFORE_START


def test_a_stop_after_the_start_cancels_the_running_job(jobs):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: a Stop sent with the token of a job that already runs cancels that job."""
    gate = threading.Event()
    job = jobs.start("deploy", lambda log, cancel: gate.wait(2) and {"stopped": "y"} if cancel.wait(2) else {}, start_token="tok_abcdefgh")
    res = jobs.stop_before_start("tok_abcdefgh")
    gate.set()
    _finish(job)
    assert (res["job_id"], res["cancelled"], job.status) == (job.id, True, jobs.CANCELLED)


def test_pending_stops_are_capped(jobs, monkeypatch):
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: at most MAX_PENDING_STOPS early stops are kept; the oldest is dropped."""
    monkeypatch.setattr(jobs, "MAX_PENDING_STOPS", 2)
    ticks = iter([1.0, 2.0, 3.0])
    monkeypatch.setattr(jobs.time, "time", lambda: next(ticks))
    for t in ("tok_aaaaaaaa", "tok_bbbbbbbb", "tok_cccccccc"):
        jobs.stop_before_start(t)
    assert sorted(jobs._pending_stops) == ["tok_bbbbbbbb", "tok_cccccccc"]


def test_cancel_of_a_finished_or_unknown_job_is_false(jobs):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: Stop on a job that ended, or does not exist, changes nothing."""
    job = _finish(jobs.start("deploy", lambda log, cancel: {}))
    assert (jobs.cancel(job.id), jobs.cancel("nope"), job.cancel.is_set()) == (False, False, False)


def test_a_job_error_is_redacted_and_bounded(jobs):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: an exception in a job becomes a short failed status with tokens masked."""
    def boom(log, cancel):
        raise RuntimeError("Bearer abcdefghijklmnop1234 " + "y" * 5000)
    job = _finish(jobs.start("deploy", boom))
    assert job.status == jobs.FAILED and "abcdefghijklmnop1234" not in job.error and len(job.error) < 400


def test_an_artifact_is_served_beside_the_result_never_inside(jobs):
    """ASVS V8.3.1 · CWE-200 · WSTG-INFO-05: a job's file is offered for download, its bytes never in the polled JSON."""
    job = _finish(jobs.start("export", lambda log, cancel: {"artifact": ("w.zip", "application/zip", b"PK\x03\x04")}))
    snap = jobs.snapshot(job)
    assert "artifact" not in snap["result"] and snap["download"].endswith(f"/{job.id}/download") and snap["bytes"] == 4


@pytest.mark.parametrize("kind,words", [("path", "nothing more is read"), ("insights", "Insights query"), ("zpa", "ZPA analysis"),
                                        ("export", "no pack is produced"), ("policy_export", "no file is produced"),
                                        ("ops_objects", "nothing is written"), ("inventory", "no workbook"), ("deploy", "activation and the read-back")])
def test_each_job_kind_says_in_words_what_stop_does(jobs, kind, words):
    """ASVS V7.4.1 · CWE-841 · WSTG-BUSL-07: Stop on each kind of job logs what it stops and what still runs."""
    job = jobs.Job(id="k", kind=kind)
    jobs._jobs["k"] = job
    assert jobs.cancel("k") and words in job.logs[-1]


def test_note_and_progress_outside_a_job_report_false(jobs):
    """ASVS V7.1.3 · CWE-778 · WSTG-ERRH-01: note() and progress() on a thread with no job say so, so the caller audits itself."""
    assert (jobs.note(tenant="t"), jobs.progress({"done": 1})) == (False, False)


def test_progress_inside_a_job_reaches_the_snapshot(jobs):
    """ASVS V7.1.3 · CWE-778 · WSTG-BUSL-05: progress reported by the run inside a job appears in the polled snapshot."""
    job = _finish(jobs.start("deploy", lambda log, cancel: jobs.progress({"done": 3, "total": 9}) and {}))
    assert jobs.snapshot(job)["progress"] == {"done": 3, "total": 9}


# ---------------------------------------------------------------------------
# pack_library: uploads are untrusted
# ---------------------------------------------------------------------------

def _upload(obj, name="pack.json"):
    return pl.assemble_pack([{"name": name, "content": obj if isinstance(obj, str) else json.dumps(obj)}])


GOOD = {"name": "QA Pack", "dictionaries": [{"name": "QA Dict", "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "QA-[0-9]{6}"}]}],
        "engines": [{"name": "QA Engine", "expression": "((D:QA Dict > 1))"}],
        "policies": [{"name": "QA Rule", "channel": "web", "engines": ["QA Engine"], "action": "BLOCK"}]}


def _with(part, idx, **fields):
    obj = json.loads(json.dumps(GOOD))
    obj[part][idx].update(fields)
    return obj


@pytest.mark.parametrize("obj", [
    _with("dictionaries", 0, name=["QA Dict"]), _with("dictionaries", 0, name={"a": 1}), _with("dictionaries", 0, patterns=5),
    _with("dictionaries", 0, patterns=[{"pattern": 7}]), _with("dictionaries", 0, phrases=[None]), _with("engines", 0, expression=["x"]),
    _with("engines", 0, name=3.5), _with("policies", 0, engines="QA Engine"), _with("policies", 0, engines=[["QA Engine"]]),
    _with("policies", 0, action=5), _with("policies", 0, channel=["web"]), _with("policies", 0, sub_rules=[{"name": ["S"]}]),
    _with("policies", 0, actions_by_verb=["UPLOAD"]), _with("policies", 0, state=True), {**GOOD, "name": ["QA"]},
    {**GOOD, "description": {"x": 1}}, {**GOOD, "engines": ["just a string"]}, {**GOOD, "policies": [1]},
])
def test_an_entry_of_the_wrong_type_is_refused_in_words(obj):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a pack whose fields have the wrong JSON type is refused with a reason, never a TypeError (fuzz-found)."""
    with pytest.raises(ValueError):
        pl.validate_pack(_upload(obj))


def test_a_well_formed_pack_is_still_accepted():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: the shape check accepts a normal pack and its numeric version (regression)."""
    pack = _upload({**GOOD, "version": 2})
    assert pl.validate_pack(pack)["ok"] and pack["meta"]["version"] == "2"


def test_json_nested_too_deep_is_refused():
    """ASVS V5.1.4 · CWE-674 · WSTG-INPV-01: a pack nested past MAX_JSON_DEPTH is refused before anything walks it."""
    deep = {**GOOD, "references": json.loads("[" * 200 + "]" * 200)}
    with pytest.raises(ValueError, match="nested"):
        _upload(deep)


def test_json_at_the_depth_limit_is_accepted():
    """ASVS V5.1.4 · CWE-674 · WSTG-INPV-01: nesting up to the limit is read (boundary)."""
    inner = json.loads("[" * (pl.MAX_JSON_DEPTH - 1) + "]" * (pl.MAX_JSON_DEPTH - 1))
    assert _upload({**GOOD, "references": inner})["meta"]["name"] == "QA Pack"


@pytest.mark.parametrize("text", ['{"name": NaN, "dictionaries": []}', '[{"name": "D", "proximity": Infinity}]',
                                  '[{"name": "D", "proximity": 1e999}]'])
def test_nan_and_infinity_are_refused(text):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: NaN, Infinity and an overflowing number are refused, never kept in the pack."""
    with pytest.raises(ValueError, match="not valid JSON"):
        _upload(text, name="dlp_dictionaries.json")


def test_non_text_file_content_is_refused_without_allocating():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: file content that is a number is refused, never passed to bytes() (a 10 GB allocation)."""
    with pytest.raises(ValueError, match="must be text"):
        pl.assemble_pack([{"name": "pack.json", "content": 10 ** 10}])


def test_invalid_base64_is_refused_in_words():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a ZIP sent as malformed base64 is refused as such, not silently decoded."""
    with pytest.raises(ValueError, match="not valid base64"):
        pl.assemble_pack([{"name": "pack.zip", "content": "UEsDB*@@@", "encoding": "base64"}])


def test_an_upload_over_the_size_cap_is_refused(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: an upload larger than MAX_UPLOAD_BYTES is refused."""
    monkeypatch.setattr(pl, "MAX_UPLOAD_BYTES", 100)
    with pytest.raises(ValueError, match="larger than"):
        _upload({**GOOD, "description": "x" * 200})


@pytest.mark.parametrize("value", ["[1]", '"ten"', "{ a = 1 }"])
def test_a_terraform_proximity_that_is_not_a_number_is_refused_in_words(value):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a Terraform dictionary whose proximity is a list, text or block is refused, not a TypeError."""
    tf = f'resource "zia_dlp_dictionaries" "d" {{\n  name = "D"\n  proximity = {value}\n}}\n'
    with pytest.raises(ValueError, match="whole number"):
        pl.assemble_pack([{"name": "main.tf", "content": tf}])


def test_a_terraform_template_id_that_is_not_a_number_is_refused_in_words():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: dict_template_id = [..] is refused in words, not a TypeError."""
    tf = 'resource "zia_dlp_dictionaries" "d" {\n  name = "D"\n  dict_template_id = [3]\n}\n'
    with pytest.raises(ValueError, match="whole number"):
        pl.assemble_pack([{"name": "main.tf", "content": tf}])


def test_a_malformed_native_export_is_refused_in_words():
    """ASVS V5.1.4 · CWE-755 · WSTG-ERRH-01: a Zscaler API export with a field of the wrong type is refused, not a server error (fuzz-found)."""
    native = [{"id": 5, "name": "N1", "dictionaryType": "PATTERNS_AND_PHRASES",
               "customPhraseMatchType": "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "phrases": 1}]
    with pytest.raises(ValueError):
        pl.validate_pack(_upload(native, name="dlp_dictionaries.json"))


def test_a_traversal_name_in_a_zip_never_becomes_a_path(tmp_path):
    """ASVS V12.3.1 · CWE-22 · WSTG-INPV-11: a ZIP member named ../../x.json is read as data; nothing is written outside the library."""
    import base64
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("../../evil/pack.json", json.dumps(GOOD))
    pack = pl.assemble_pack([{"name": "p.zip", "content": base64.b64encode(buf.getvalue()).decode(), "encoding": "base64"}])
    saved = pl.save_pack(pack, root=str(tmp_path))
    assert os.path.dirname(saved["dir"]) == os.path.join(str(tmp_path), "user_packs") and not (tmp_path.parent / "evil").exists()


@pytest.mark.parametrize("pack_id,slug", [("../../etc", "etc"), ("A/B\\C", "a_b_c"), ("名前", None), ("..", None)])
def test_a_pack_id_becomes_a_safe_folder_name(pack_id, slug):
    """ASVS V12.3.1 · CWE-22 · WSTG-INPV-11: a pack id with separators or dots becomes a slug with neither (oracle table)."""
    got = pl.pack_slug(pack_id)
    assert (got == slug) if slug is not None else re.fullmatch(r"pack_[0-9a-f]{10}", got)


def test_the_reserved_library_folder_name_cannot_be_a_pack_id(tmp_path):
    """ASVS V12.3.1 · CWE-22 · WSTG-INPV-11: a pack may not take the id 'user_packs' (it would be the library itself)."""
    with pytest.raises(FileExistsError):
        pl.save_pack(_upload(GOOD), pack_id="user_packs", root=str(tmp_path))


def test_a_saved_pack_is_owner_only(tmp_path):
    """ASVS V12.3.4 · CWE-276 · WSTG-CONF-09: an uploaded pack is written 0700 (folders) and 0600 (files)."""
    saved = pl.save_pack(_upload(GOOD), root=str(tmp_path))
    modes = {os.path.relpath(os.path.join(d, n), saved["dir"]): stat.S_IMODE(os.stat(os.path.join(d, n)).st_mode)
             for d, dirs, files in os.walk(saved["dir"]) for n in dirs + files}
    assert stat.S_IMODE(os.stat(saved["dir"]).st_mode) == 0o700 and all(m in (0o700, 0o600) for m in modes.values()), modes


def test_a_second_pack_with_the_same_id_is_refused(tmp_path):
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: a pack id that is taken is refused; the first pack is untouched."""
    pl.save_pack(_upload(GOOD), root=str(tmp_path))
    with pytest.raises(FileExistsError):
        pl.save_pack(_upload(GOOD), root=str(tmp_path))


def test_delete_refuses_a_path_outside_the_library(tmp_path):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: delete_pack('../..') and a built-in pack id are refused; nothing is removed."""
    (tmp_path / "keep").mkdir()
    for pid in ("../..", "..", "", "keep"):
        with pytest.raises(FileNotFoundError):
            pl.delete_pack(pid, root=str(tmp_path))
    assert (tmp_path / "keep").is_dir()


def test_delete_refuses_a_symlink_that_leaves_the_library(tmp_path):
    """ASVS V12.3.1 · CWE-59 · WSTG-ATHZ-01: a link inside the library that points outside it is not followed by delete."""
    outside = tmp_path / "outside"
    outside.mkdir()
    lib = tmp_path / "user_packs"
    lib.mkdir()
    (lib / "evil").symlink_to(outside, target_is_directory=True)
    with pytest.raises(FileNotFoundError):
        pl.delete_pack("evil", root=str(tmp_path))
    assert outside.is_dir()


def test_a_saved_pack_round_trips_through_its_bundle(tmp_path):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: save → pack_bundle → upload gives the same dictionaries, engines and rules (regression)."""
    saved = pl.save_pack(_upload(GOOD), root=str(tmp_path))
    again = _upload(pl.pack_bundle(saved["dir"]))
    assert all(again[k] == _upload(GOOD)[k] for k in ("dictionaries", "engines", "policies"))


def test_the_library_lists_an_uploaded_pack(tmp_path):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: after save, library() lists the pack with its counts and source (functionality)."""
    pl.save_pack(_upload(GOOD), root=str(tmp_path))
    rows = [p for p in pl.library(str(tmp_path))["packs"] if p["id"] == "qa_pack"]
    assert rows and rows[0]["source"] == "uploaded"


def test_an_older_bundle_with_endpoint_application_groups_still_loads():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a bundle that names app groups 'endpoint_application_groups' (the earlier key) still loads."""
    obj = {**GOOD, "endpoint_application_groups": [{"name": "G", "resources": ["1"]}]}
    assert _upload(obj)["app_groups"] == [{"name": "G", "resources": ["1"]}]


# ---------------------------------------------------------------------------
# ReDoS in the Terraform reader (CPU time, as the repository's other ReDoS tests)
# ---------------------------------------------------------------------------

def _cpu(fn, *a):
    import time
    start = time.process_time()
    try:
        fn(*a)
    except ValueError:
        pass
    return time.process_time() - start


def test_an_unterminated_terraform_string_of_escapes_is_read_in_linear_time():
    """ASVS V11.1.4 · CWE-1333 · WSTG-BUSL-09: an unterminated "$${$${... (a 100-byte upload) cannot pin the CPU (was exponential)."""
    assert _cpu(pl.parse_hcl, 'x = "' + "$${" * 24 + "\n") < 1.0


def test_a_long_run_of_spaces_in_a_terraform_description_is_read_in_linear_time():
    """ASVS V11.1.4 · CWE-1333 · WSTG-BUSL-09: stripping the provenance tag from a description of 60 000 spaces is not quadratic."""
    assert _cpu(pl._strip_provenance, " " * 60000 + "x") < 1.0


@pytest.mark.parametrize("text,expected", [
    ("Detects PHI. [Jo pack zbp_x v1] Terraform-managed.", "Detects PHI."),
    ("Detects PHI. [DLP-Check baseline b v1] Terraform-managed", "Detects PHI."),
    ("No tag here", "No tag here"), ("", ""), (None, ""),
    ("x" * 1000 + " [Jo pack p v1] Terraform-managed.", "x" * 1000),
])
def test_the_provenance_tag_is_still_stripped(text, expected):
    """ASVS V11.1.4 · CWE-1333 · WSTG-BUSL-09: the linear provenance strip gives the same descriptions (oracle table, regression)."""
    assert pl._strip_provenance(text) == expected


def test_terraform_string_escapes_are_still_read():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: $${, %%{, \\" and \\u escapes in a Terraform string still read as before (regression)."""
    assert pl.parse_hcl('a = "$${x} %%{y} \\"q\\" \\u00e9"') == {"a": '${x} %{y} "q" é'}


@pytest.mark.parametrize("text,words", [("/* never closed", "not closed"), ("a = <<EOT\nbody", "heredoc"), ("a = §", "unexpected character"),
                                        ("resource \"a\" \"b\" {", "not closed"), ("= 1", "expected an attribute"),
                                        ("block \"x\" 5", "expected '{'"), ("a =", "end of file"),
                                        ("a = " + "[" * 70 + "]" * 70, "nested")])
def test_malformed_terraform_is_a_plain_error(text, words):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: unclosed comments, heredocs, blocks, stray characters and deep nesting are an HCLError in words."""
    with pytest.raises(pl.HCLError, match=words):
        pl.parse_hcl(text)


# ---------------------------------------------------------------------------
# More functionality: raw requests, tables, activation, run locks
# ---------------------------------------------------------------------------

class _Executor:
    def __init__(self, body=None, create_err=None, exec_err=None, raises=None):
        self.body, self.create_err, self.exec_err, self.raises, self.requests = body, create_err, exec_err, raises, []

    def create_request(self, method, url, body, headers, params=None):
        if self.raises:
            raise self.raises
        self.requests.append((method, url, body))
        return ("req", self.create_err)

    def execute(self, req):
        return (SimpleNamespace(get_body=lambda: self.body), self.exec_err)


def _raw_zia(ex):
    svc = SimpleNamespace(_request_executor=ex)
    return SimpleNamespace(endpoint_dlp_rules=svc, proxies=svc)


def test_a_raw_request_goes_to_the_zia_base_path_and_reads_json():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: raw_request sends METHOD /zia/api/v1<path> and parses a JSON text body."""
    ex = _Executor(body='{"id": 3}')
    assert pc.raw_request(_raw_zia(ex), "post", "/endPointApplicationGroups", {"name": "G"}) == ({"id": 3}, None)
    assert ex.requests == [("POST", "/zia/api/v1/endPointApplicationGroups", {"name": "G"})]


@pytest.mark.parametrize("ex", [_Executor(create_err="Bearer abcdefghijklmnop1234"), _Executor(exec_err="Bearer abcdefghijklmnop1234"),
                                _Executor(raises=RuntimeError("Bearer abcdefghijklmnop1234"))])
def test_a_raw_request_error_is_redacted(ex):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: an executor error that echoes the bearer token is masked before it is returned."""
    data, err = pc.raw_request(_raw_zia(ex), "GET", "/status")
    assert data is None and "abcdefghijklmnop1234" not in err


def test_a_raw_get_error_is_redacted():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: raw_get masks a token an error repeats, like raw_request."""
    _data, err = pc.raw_get(_raw_zia(_Executor(exec_err="JSESSIONID=ABCDEFGH12345678")), "/x")
    assert "ABCDEFGH12345678" not in err


def test_a_raw_get_answer_that_is_not_json_is_an_error():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: raw_get refuses a text answer that is not JSON, in words."""
    assert pc.raw_get(_raw_zia(_Executor(body="<html>")), "/x") == (None, "the answer was not JSON")


def test_a_raw_request_without_an_executor_says_so():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: an SDK without a request executor gives a plain error, not an AttributeError."""
    assert "no request executor" in pc.raw_request(SimpleNamespace(), "GET", "/status")[1]
    assert "no request executor" in pc.raw_get(SimpleNamespace(), "/x")[1]


@pytest.mark.parametrize("body", ['[{"name": "G", "id": 1, "resources": [2, 1]}]', '{"list": [{"name": "G", "groupId": 1, "resources": [2, 1]}]}'])
def test_application_groups_are_read_from_either_list_shape(body):
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: endpoint application groups are read from a bare list or a {list: [...]} answer."""
    groups, err = pc.list_app_groups(_raw_zia(_Executor(body=body)))
    assert err is None and groups == {"G": {"id": 1, "description": "", "resources": ["1", "2"]}}


def test_sub_rules_are_flattened_after_their_parent():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: an Endpoint rule's sub_rules become rules naming their parent, ordered among siblings."""
    flat = pc.expand_sub_rules([{"name": "P", "channel": "endpoint", "rank": 3, "sub_rules": [{"name": "S1"}, {"name": "S2", "order": 9}]}])
    assert [(p["name"], p.get("parent_rule"), p.get("order"), p.get("rank")) for p in flat] == [
        ("P", None, None, 3), ("S1", "P", 1, 3), ("S2", "P", 9, 3)]


@pytest.mark.parametrize("name,channel,suffix,expected", [
    ("Short", pc.SAAS, "", "Short"), ("A" * 31, pc.SAAS, "", "A" * 31), ("A" * 40, pc.SAAS, "", "A" * 31),
    ("Payment Card Data Monitor Rule", pc.SAAS, " - SaaS", "Payment Card Data - SaaS"), ("A" * 200, pc.WEB, "", "A" * 200)])
def test_a_rule_name_fits_the_channel_limit(name, channel, suffix, expected):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: SaaS rule names are cut to 31 characters at a word boundary; other channels are left whole."""
    assert pc.fit_rule_name(name, channel, suffix) == expected


@pytest.mark.parametrize("p,key", [({"channel": "saas", "saas_type": "OFLCASB_DLP_FILE"}, "saas_type"), ({"channel": "email"}, "tenants"),
                                   ({"channel": "endpoint"}, "data_transfer_method"), ({"channel": "url", "url_categories": ["ANY"]}, "url_categories"),
                                   ({"channel": "web", "labels": ["b", "a"]}, "labels")])
def test_the_policy_signature_names_the_fields_that_make_two_rules_differ(p, key):
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: same-named rules on different channels or settings get different signatures."""
    assert key in pc.policy_signature_extra(dict(p, name="R"))


def _lister(rules, err=None):
    svc = mock.Mock()
    svc.list_rules.return_value = (rules, None, err)
    svc.list_all_rules.return_value = (rules, None, err)
    return svc


def test_the_saas_rule_type_is_looked_up_by_id():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: saas_rule_type finds a rule's type by id; None when it is absent or the list fails."""
    zia = SimpleNamespace(casb_dlp_rules=_lister([{"id": 4, "type": "OFLCASB_DLP_CRM"}]))
    assert (pc.saas_rule_type(zia, "4"), pc.saas_rule_type(zia, 5)) == ("OFLCASB_DLP_CRM", None)
    assert pc.saas_rule_type(SimpleNamespace(casb_dlp_rules=_lister([], "boom")), 4) is None


def test_rule_names_include_endpoint_sub_rules():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: the post-deploy name read includes Endpoint sub-rules."""
    zia = SimpleNamespace(endpoint_dlp_rules=_lister([{"id": 1, "name": "P ", "subRules": [{"id": 2, "name": "S"}]}]))
    assert pc.list_rule_names(zia, pc.ENDPOINT) == ({"P", "S"}, None)


def test_rule_counts_and_name_reads_report_errors_in_words():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a failed list is an error string, never an exception."""
    zia = SimpleNamespace(dlp_web_rules=_lister([], "HTTP 500"), cloudappcontrol=_lister([], "HTTP 500"))
    assert pc.count_rules(zia, pc.WEB) == (None, "HTTP 500")
    assert pc.list_rule_names(zia, pc.CLOUD_APP, ["AI_ML"]) == (None, "HTTP 500")
    assert pc.count_rules(SimpleNamespace(), pc.WEB)[1].endswith("zscaler-sdk-python")


@pytest.mark.parametrize("status,message,words", [
    (403, "Resource Access Blocked", "not a rate limit"), (403, "rule rank is higher than the admin rank", "admin rank"),
    (403, "Forbidden", "role does not allow"), (429, "", "rate limit"), (401, "", "sign-in was rejected"),
    (400, "", "rejected the request body"), (404, "", "not in the tenant"), (409, "", "edit lock"), (503, "", "retries"), (418, "", "HTTP 418")])
def test_each_http_status_is_explained_in_words(status, message, words):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: every HTTP status ZIA answers with is named in words (403 vs 429 apart)."""
    assert words in ops.http_label(status, message)


def test_a_known_refusal_has_a_plain_explanation_and_an_unknown_none():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: explain() turns a known ZIA refusal into an action, and says nothing for an unknown one."""
    assert "31 characters" in ops.explain("Name exceeds the max length 31 characters")
    assert (ops.explain("something new"), ops.explain(None), ops.http_label(None)) == (None, None, None)


def test_a_zdx_permission_refusal_names_zdx():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a 403 on a ZDX write is explained as a ZDX role problem, not a DLP one."""
    assert "ZDX" in ops.fatal_reason("403 Forbidden", "zdx") and "DLP policy" in ops.fatal_reason("403 Forbidden")


def test_find_by_name_ignores_case_and_spaces():
    """ASVS V5.1.1 · CWE-20 · WSTG-INPV-01: a duplicate refusal reuses the object listed under the same name (case, spaces ignored)."""
    zia = SimpleNamespace(dlp_engine=_lister([{"id": "12", "name": "  QA   Engine "}]))
    zia.dlp_engine.list_dlp_engines.return_value = ([{"id": "12", "name": "  QA   Engine "}], None, None)
    assert (ops.find_by_name(zia, "engine", "qa engine"), ops.find_by_name(zia, "engine", "other")) == (12, None)


def test_the_read_by_name_raises_when_the_list_cannot_be_read():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-07: name_check raises (no proof of absence) when the tenant list fails, so nothing is resent."""
    zia = SimpleNamespace(dlp_engine=mock.Mock())
    zia.dlp_engine.list_dlp_engines.return_value = (None, None, "HTTP 500")
    with pytest.raises(RuntimeError):
        ops.name_check(zia, "engine", "E")()
    assert ops.name_check(zia, "zia_proxy", "P") is None and ops.name_check(zia, "policy", "R", "fax") is None


def test_a_second_write_run_on_the_same_tenant_is_refused():
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: while one write run holds a tenant, a second gets False and writes nothing."""
    client = object()
    with ops.tenant_run(client) as first:
        with ops.tenant_run(client) as second:
            assert (first, second) == (True, False)
    with ops.tenant_run(client) as again:
        assert again
    assert ops.busy_result()["busy"] is True


def test_the_activation_after_a_rate_refusal_waits_and_tries_again(monkeypatch, sleeps):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: an activation refused for ZIA's rate is retried after the limit's window, then succeeds."""
    answers = iter([{"activated": False, "error": "429 Too Many Requests"}, {"activated": True, "status": "ACTIVE", "error": None}])
    monkeypatch.setattr(pc, "activate", lambda zia: next(answers))
    act = ops.activate_once(object())
    assert act["activated"] is True


def test_activate_and_settle_waits_for_active(monkeypatch):
    """ASVS V11.1.4 · CWE-841 · WSTG-BUSL-05: after activating, the run waits for ZIA to report ACTIVE before reading back."""
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "PENDING", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, seconds, log: "ACTIVE")
    assert ops.activate_and_settle(object(), 5)["settled_status"] == "ACTIVE"


def test_a_run_summary_without_a_result_counts_the_writes_sent():
    """ASVS V7.1.3 · CWE-778 · WSTG-ERRH-01: a run that raised still reports the writes it sent, from the audit tally."""
    tally = {("engine", None, "E", ""): ("create", "ok"), ("dictionary", None, "D", "1"): ("delete", "failed")}
    assert ops.run_summary(None, tally)["counts"] == {"created": 1, "updated": 0, "deleted": 0, "skipped": 0, "failed": 1, "unchanged": 0}


def test_a_stopped_write_is_recorded_as_skipped_not_failed():
    """ASVS V7.1.3 · CWE-778 · WSTG-ERRH-01: a write never sent because the run stopped is 'skipped' with the reason, not a failure."""
    rec = ops.Recorder()
    entry = rec.record("engine", "E", "failed", op="create", outcome=ops.Outcome(False, error="not attempted: x", code=ops.STOPPED))
    assert (entry["status"], entry["reason"], "error" not in entry) == ("skipped", "not attempted: x", True)
