"""Distinct local-simulation, API-read and scenario evidence contracts.

Each parametrized case has a behavior ID; no real tenant or outbound traffic.
"""
import json
import pytest
import corpus_engines as ce
import dlp_efficacy as eff
import scenario_flow as sf


class Reader:
    def __init__(self, data=None, code=200, error=None):
        self.data, self.code, self.error, self.calls = data, code, error, []

    def get(self, endpoint):
        self.calls.append(endpoint)
        if self.error:
            raise self.error
        return self.data, self.code


@pytest.mark.parametrize("field,value", [
    ("channel", "other"), ("channel", "zpa"), ("network", "home"), ("network", "split-vpn"),
    ("platform", "unknown"), ("platform", "win32"), ("destination", "x" * 2049),
    ("destination", "example.com\nadmin"), ("operation", "x" * 81), ("operation", "\tUPLOAD"),
    ("file_type", "x" * 121), ("file_type", ["ZIP"]), ("scenario_id", "x" * 101),
    ("scenario_id", "\x00bad"), ("corpus", "x" * (256 * 1024 + 1)), ("corpus", {"file": "x"}),
], ids=["channel-unknown", "channel-private-not-web", "network-unmapped", "network-no-guessed-enum", "platform-unknown", "platform-no-guessed-enum", "destination-cap", "destination-control-char", "operation-cap", "operation-control-char", "file-type-cap", "file-type-shape", "scenario-id-cap", "scenario-id-control", "corpus-cap", "corpus-type"])
def test_input_rejects_ambiguous_context(field, value):
    with pytest.raises(ValueError):
        sf.normalize_input({field: value})


@pytest.mark.parametrize("code,reason", [(401, "Authentication failed"), (403, "Permission denied"), (404, "Route unavailable"), (429, "Rate limited"), (500, "Read failed"), (503, "Read failed")], ids=["auth", "permission", "route", "rate", "server", "unavailable"])
def test_read_failure_is_not_empty_configuration(code, reason):
    r = eff.read_collection(Reader({"error": "private response"}, code), "/zia/dlpEngines")
    assert r["status"] == "unverified" and r["reason"] == reason and not r["items"]
    assert "private response" not in str(r)


@pytest.mark.parametrize("data", [[], [{"id": 1}], {"list": []}, {"items": [{"id": 2}]}, {"data": []}, {"results": [{"id": 3}]}], ids=["bare-empty", "bare-items", "list-empty", "items-wrapper", "data-empty", "results-wrapper"])
def test_read_success_preserves_collection_shape(data):
    r = eff.read_collection(Reader(data), "/zia/dlpEngines")
    assert r["status"] == "verified" and r["items"] == eff._ls(data)


@pytest.mark.parametrize("data", [None, "denied", {"error": "oops"}, {"items": {}}, [None], [{"id": 1}, "bad"], {"items": [False]}], ids=["null", "text", "error-wrapper", "wrong-wrapper", "null-row", "mixed-row", "bool-row"])
def test_malformed_success_is_unknown(data):
    assert eff.read_collection(Reader(data), "/zia/dlpEngines")["status"] == "unverified"


@pytest.mark.parametrize("metadata", [{"totalCount": 2}, {"total_count": 3}, {"total": "bad"}, {"hasMore": True}, {"has_more": True}, {"nextPageToken": "token"}, {"next_page": 2}], ids=["total-count", "sdk-total", "malformed-total", "has-more", "sdk-has-more", "token", "next-page"])
def test_partial_reads_do_not_establish_complete_inventory(metadata):
    c = Reader({"items": [{"id": 1}], **metadata})
    r = eff.read_collection(c, "/zia/dlpEngines")
    assert r["status"] == "unverified" and "Incomplete" in r["reason"]
    assert c.calls == ["/zia/dlpEngines"]


def test_read_exception_does_not_leak_credential_text():
    r = eff.read_collection(Reader(error=RuntimeError("password=private-secret")), "/zia/dlpEngines")
    assert r["status"] == "unverified" and "private-secret" not in str(r)


def test_204_is_distinct_successfully_empty():
    r = eff.read_collection(Reader(None, 204), "/zia/dlpEngines")
    assert r["status"] == "verified" and r["items"] == []


TRUTH = [(0, 0), (0, 1), (0, None), (1, 0), (1, 1), (1, None), (None, 0), (None, 1), (None, None)]
@pytest.mark.parametrize("a,b", TRUTH, ids=["false-false", "false-true", "false-unknown", "true-false", "true-true", "true-unknown", "unknown-false", "unknown-true", "unknown-unknown"])
@pytest.mark.parametrize("op", ["AND", "OR"], ids=["required-all", "any-alternative"])
def test_boolean_unknown_preserves_short_circuit_certainty(a, b, op):
    expected = (False if a == 0 or b == 0 else None if a is None or b is None else True) if op == "AND" else (True if a == 1 or b == 1 else None if a is None or b is None else False)
    assert ce.evaluate_expression(f"D1.S > 0 {op} D2.S > 0", {1: a, 2: b})[0] is expected


@pytest.mark.parametrize("op,expect", [(">", [False, False, True]), (">=", [False, True, True]), ("<", [True, False, False]), ("<=", [True, True, False]), ("=", [False, True, False]), ("!=", [True, False, True])], ids=["strict-more", "at-least", "strict-less", "at-most", "equal", "not-equal"])
@pytest.mark.parametrize("count", [4, 5, 6], ids=["below-threshold", "threshold", "above-threshold"])
def test_threshold_explanations_respect_exact_operator(op, expect, count):
    r = ce.engine_results([{"id": 10, "name": "Engine", "engineExpression": f"D8.S {op} 5"}], [], {8: count}, {8: "Detector"})[0]
    assert r["fires"] is expect[count - 4]
    assert r["dictionary_refs"] == [{"id": 8, "name": "Detector", "count": count}]


@pytest.mark.parametrize("value,result", [(0, True), (1, False), (None, None)], ids=["excluded-absent", "excluded-present", "excluded-unknown"])
def test_negation_is_not_explained_as_nothing_to_match(value, result):
    e = ce.engine_results([{"id": 1, "engineExpression": "NOT (D2.S > 0)"}], [], {2: value}, {2: "Excluded"})[0]
    assert e["fires"] is result and "nothing to match" not in e["explanation"]
    assert e["expression_evaluated"] == "NOT (D2.S > 0)"


@pytest.mark.parametrize("state", ["ENABLED", "DISABLED", "UNKNOWN", ""], ids=["enabled", "disabled", "unknown", "missing"])
@pytest.mark.parametrize("action", ["BLOCK", "ALLOW", "QUARANTINE"], ids=["block", "allow", "quarantine"])
def test_rule_references_are_not_enforcement_claims(state, action):
    r = ce.rule_reference({"id": 17, "name": "Policy", "state": state, "action": action, "dlpEngines": [{"id": 21}], "password": "never-export"})
    assert r["applicability"] == ("disabled" if state == "DISABLED" else "conditional")
    assert r["engine_ids"] == ["21"] and r["action"] == action
    assert "never-export" not in str(r)


def evidence(channel="web", status="verified"):
    return {"mode": "simulated", "channel": channel, "engines": [], "rules": [], "read_evidence": {k: {"status": status, "source": "fixture", "reason": "fixture state"} for k in ("dictionaries", "engines", "rules")}}


@pytest.mark.parametrize("channel", list(sf.CHANNELS), ids=["web", "endpoint", "email", "saas"])
@pytest.mark.parametrize("read_status", ["verified", "unverified", "out_of_scope"], ids=["read-ok", "read-failed", "excluded"])
def test_channel_graph_always_accounts_for_required_controls(channel, read_status):
    c = sf.normalize_input({"channel": channel, "corpus": "synthetic"})
    import dlp_analysis
    scope = {"scopes": ["dlp"] if read_status != "out_of_scope" else [], "read": ["url", "ssl", "ftc", "cac"], "channel_enabled": read_status != "out_of_scope"}
    scope["required_controls"] = dlp_analysis.requirements(scope["scopes"], {}, tested_channel=channel)
    r = sf.build_result(c, tenant_key="tenant", scope=scope, corpus=evidence(channel, read_status))
    nodes = {s["key"]: s for s in r["stages"]}
    assert all(k in nodes for k, _ in sf.CONTROLS)
    assert all(nodes[k]["status"] == ("unverified" if channel == "web" else "not_applicable") for k, _ in sf.CONTROLS)
    assert nodes["dictionaries"]["status"] == {"verified": "simulated", "unverified": "unverified", "out_of_scope": "out_of_scope"}[read_status]
    assert nodes["workflow"]["status"] == ("out_of_scope" if read_status == "out_of_scope" else "unverified")
    assert r["scenario"]["channel"] == channel


@pytest.mark.parametrize("key", ["zcc", "pac", "cac", "url", "ssl", "ftc"], ids=["client-bypass", "pac-bypass", "app-block", "url-block", "ssl-block", "file-block"])
def test_local_simulation_never_unblocks_a_stopped_path(key):
    c = sf.normalize_input({"corpus": "synthetic"})
    path = {"trace": {"hops": [{"key": key, "label": key, "status": "bypass" if key in ("zcc", "pac") else "blocked"}]}}
    r = sf.build_result(c, tenant_key="tenant", scope={"scopes": ["dlp"], "channel_enabled": True}, corpus=evidence(), path=path)
    nodes = {s["key"]: s for s in r["stages"]}
    assert nodes["dictionaries"]["status"] == nodes["engines"]["status"] == nodes["rules"]["status"] == nodes["action"]["status"] == "not_reached"
    assert nodes["dictionaries"]["evidence_status"] == "simulated"
    assert any("counterfactual" in text for text in r["limitations"])


def test_scope_identity_includes_channel_ownership_and_order_is_irrelevant():
    assert sf.scope_key(["dlp", "zcc"], {"web_dlp": "zscaler"}) == sf.scope_key(["zcc", "dlp"], {"web_dlp": "zscaler"})
    assert sf.scope_key(["dlp"], {"web_dlp": "zscaler"}) != sf.scope_key(["dlp"], {"web_dlp": "alternative"})


def test_each_result_has_fresh_configuration_identity_and_never_content():
    c = sf.normalize_input({"corpus": "private-test-content", "scenario_id": "caller"})
    a = sf.build_result(c, tenant_key="a", scope={})
    b = sf.build_result(c, tenant_key="b", scope={})
    assert a["scenario"]["configuration_id"] != b["scenario"]["configuration_id"]
    assert a["scenario"]["tenant_key"] != b["scenario"]["tenant_key"]
    assert "private-test-content" not in json.dumps(a)


def test_http_permission_failure_reaches_corpus_result():
    r = eff.corpus_test(Reader({}, 403), "synthetic")
    assert len(r["errors"]) == 3
    assert all(v["status"] == "unverified" for v in r["read_evidence"].values())


@pytest.mark.parametrize("channel", list(sf.CHANNELS), ids=["web-rule-source", "endpoint-rule-source", "email-rule-source", "saas-rule-source"])
def test_supplied_channel_rules_do_not_trigger_hidden_web_read(channel):
    c = Reader([])
    r = eff.corpus_test(c, "synthetic", read_rules=False, channel=channel,
                        channel_rules=[], rules_evidence={"source": sf.CHANNELS[channel][1], "status": "verified", "items": []})
    assert c.calls == ["/zia/dlpDictionaries", "/zia/dlpEngines"]
    assert r["channel"] == channel and r["read_evidence"]["rules"]["source"] == sf.CHANNELS[channel][1]


@pytest.fixture
def scenario_api(monkeypatch):
    import dlp_api_server as api
    import tenant_fingerprint
    from fastapi.testclient import TestClient
    reader = Reader([])
    monkeypatch.setattr(api, "_build_client", lambda req: reader)
    monkeypatch.setattr(api, "_tenant_creds", lambda req: {"vanity_domain": "fixture"})
    monkeypatch.setattr(tenant_fingerprint, "proposal_key", lambda creds, label: "fixture-opaque-tenant")
    return TestClient(api.app), reader


@pytest.mark.parametrize("channel", list(sf.CHANNELS), ids=["api-web", "api-endpoint", "api-email", "api-saas"])
@pytest.mark.parametrize("mode", ["configuration", "simulated"], ids=["no-content", "local-content"])
def test_api_composes_only_selected_channel_and_shared_definitions(scenario_api, channel, mode):
    api, reader = scenario_api
    scope_channel, endpoint, _ = sf.CHANNELS[channel]
    r = api.post("/api/flow/scenario", json={"channel": channel, "scopes": ["dlp"], "channels": {scope_channel: "zscaler"}, "from_page": True, "corpus": "synthetic" if mode == "simulated" else ""})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["scenario"]["channel"] == channel and body["scenario"]["mode"] == mode
    assert set(reader.calls) == {endpoint, "/zia/dlpDictionaries", "/zia/dlpEngines", "/zia/urlFilteringRules", "/zia/sslInspectionRules", "/zia/fileTypeRules", "/zia/cloudApplicationRules"}
    assert body["scenario"]["tenant_key"] == "fixture-opaque-tenant"
    assert body["scenario"]["id"] == body["scenario"]["scenario_id"]


@pytest.mark.parametrize("channel", list(sf.CHANNELS), ids=["excluded-web", "excluded-endpoint", "excluded-email", "excluded-saas"])
def test_api_excluded_selected_channel_does_not_read_its_rules(scenario_api, channel):
    api, reader = scenario_api
    scope_channel = sf.CHANNELS[channel][0]
    r = api.post("/api/flow/scenario", json={"channel": channel, "scopes": ["dlp"], "channels": {scope_channel: "alternative"}, "from_page": True, "corpus": "synthetic"})
    assert r.status_code == 200
    assert set(reader.calls) == {"/zia/dlpDictionaries", "/zia/dlpEngines", "/zia/urlFilteringRules", "/zia/sslInspectionRules", "/zia/fileTypeRules", "/zia/cloudApplicationRules"}
    assert sf.CHANNELS[channel][1] not in reader.calls
    assert next(x for x in r.json()["stages"] if x["key"] == "rules")["status"] == "out_of_scope"


def test_empty_scope_returns_visible_gaps_without_credentials(monkeypatch):
    import dlp_api_server as api
    from fastapi.testclient import TestClient
    def forbidden(*args):
        raise AssertionError("No credentials or client allowed for an empty scope")
    monkeypatch.setattr(api, "_build_client", forbidden)
    monkeypatch.setattr(api, "_tenant_creds", forbidden)
    r = TestClient(api.app).post("/api/flow/scenario", json={"corpus": "synthetic", "from_page": True})
    assert r.status_code == 200
    assert all(x["status"] == "out_of_scope" for x in r.json()["stages"] if x["key"] in ("url", "ssl", "ftc", "rules", "workflow"))


def test_api_invalid_channel_is_rejected_before_reading(scenario_api):
    api, reader = scenario_api
    r = api.post("/api/flow/scenario", json={"channel": "unknown", "scopes": ["dlp"], "from_page": True})
    assert r.status_code == 400 and not reader.calls


def test_api_permission_denial_remains_explicit_unknown(scenario_api):
    api, reader = scenario_api
    reader.code = 403
    r = api.post("/api/flow/scenario", json={"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True, "corpus": "synthetic"})
    assert r.status_code == 200
    assert len(r.json()["errors"]) == 3
    assert next(x for x in r.json()["stages"] if x["key"] == "engines")["status"] == "unverified"


@pytest.mark.parametrize("names,actions,result", [
    (["a"], {"a": ""}, "unknown"), (["a"], {"a": "NEW_UNKNOWN_ENUM"}, "unknown"),
    (["a", "missing"], {"a": "ALLOW"}, "unknown"), (["a", "missing"], {"a": "BLOCK"}, "unknown"),
    (["a", "b"], {"a": "ALLOW", "b": "BLOCK"}, "enforced"),
    (["a", "b"], {"a": "ALLOW", "b": "REPORT"}, "monitor"),
], ids=["empty-action", "new-action-enum", "partial-monitor", "partial-enforce", "known-config-enforce", "known-config-monitor"])
def test_live_configuration_inference_remains_unknown_for_missing_evidence(names, actions, result):
    import detection_health
    assert detection_health.incident_action({"rules": names}, actions) == result


def test_failed_live_poll_retains_cursor(monkeypatch):
    import detection_health as dh
    from datetime import datetime, timedelta, timezone
    now = datetime.now(timezone.utc)
    since = now - timedelta(seconds=30)
    monkeypatch.setattr(dh, "fetch_incidents_window", lambda *args: ([], [{"error": "permission denied"}]))
    out = dh.poll_incidents(None, since=since, now=now)
    assert out["next_since"] == since.isoformat() and out["errors"]


def test_duplicate_rule_name_conflicts_do_not_choose_last_action(monkeypatch):
    import detection_health as dh
    import pack_removal
    monkeypatch.setattr(pack_removal, "inventory", lambda *args, **kw: {"rules": [{"name": "Same", "action": "BLOCK"}, {"name": "Same", "action": "ALLOW"}, {"name": "Same", "action": "BLOCK"}]})
    assert dh.rule_actions(None)["Same"] == ""


@pytest.mark.parametrize("field,value", [("phrases", "bad"), ("patterns", {}), ("phrases", [None]), ("patterns", ["bad"]), ("patterns", [{"pattern": 42}]), ("patterns", [{"pattern": "[invalid"}])], ids=["phrase-wrong-shape", "pattern-missing", "phrase-null", "pattern-string", "pattern-number", "invalid-regex"])
def test_malformed_dictionary_definition_is_unknown_not_zero(field, value):
    class Client:
        def get(self, endpoint):
            if endpoint == "/zia/dlpDictionaries":
                return [{"id": 1, "name": "Malformed", "custom": True, field: value}], 200
            return [], 200
    r = eff.corpus_test(Client(), "synthetic")
    assert r["results"][0]["total_hits"] is None and r["results"][0]["simulated"] is False


@pytest.mark.parametrize("value,expected", [(False, False), ("false", False), ("0", False), (True, True), ("true", True), (1, True)], ids=["bool-false", "text-false", "text-zero", "bool-true", "text-true", "numeric-one"])
def test_false_receiver_flags_are_preserved(value, expected):
    r = ce.rule_reference({"zscalerIncidentReceiver": value, "withoutContentInspection": value})
    assert r["incident_receiver"] is expected and r["without_content_inspection"] is expected


def test_cancelled_read_never_calls_client():
    c = Reader([])
    c.stop_check = lambda: True
    with pytest.raises(eff.CorpusReadStopped):
        eff.read_collection(c, "/zia/dlpEngines")
    assert c.calls == []


def test_corpus_stop_between_collections_prevents_later_requests():
    c = Reader([])
    c.stop_check = lambda: len(c.calls) > 0
    with pytest.raises(eff.CorpusReadStopped):
        eff.corpus_test(c, "synthetic")
    assert c.calls == ["/zia/dlpDictionaries"]


@pytest.mark.parametrize("pattern,content,expected", [(r"secret", "SECRET secret", 2), (r"[0-9]{3}", "123 456", 2), (r"(ab)+", "ab abab", 2), (r"nothing", "synthetic", 0), (r"(?=a)", "aaa", 3)], ids=["case-insensitive", "repeat-matches", "capture-group-count", "no-match", "zero-width"])
def test_isolated_regex_preserves_valid_counting(pattern, content, expected):
    import time
    assert eff._safe_regex_count(pattern, content, time.monotonic() + 3) == expected


def test_catastrophic_regex_is_killed_and_unknown():
    import time
    start = time.monotonic()
    assert eff._safe_regex_count("(a+)+$", "a" * 28 + "!", start + 2) is None
    assert time.monotonic() - start < 2


def test_exhausted_regex_budget_starts_no_subprocess(monkeypatch):
    import time
    monkeypatch.setattr(eff.subprocess, "run", lambda *a, **kw: pytest.fail("Expired budget starts no process"))
    assert eff._safe_regex_count("a", "a", time.monotonic() - 1) is None


def test_invalid_isolated_regex_is_unknown():
    import time
    assert eff._safe_regex_count("[", "synthetic", time.monotonic() + 2) is None


def test_regex_content_is_not_a_command_argument_or_file(monkeypatch):
    import time
    seen = {}
    def run(args, **kwargs):
        seen.update(args=args, **kwargs)
        return type("Result", (), {"returncode": 0, "stdout": "1"})()
    monkeypatch.setattr(eff.subprocess, "run", run)
    assert eff._safe_regex_count("unique-pattern", "private-corpus", time.monotonic() + 2) == 1
    assert "private-corpus" not in str(seen["args"]) and "unique-pattern" not in str(seen["args"])
    assert json.loads(seen["input"]) == ["unique-pattern", "private-corpus"]
    assert seen["timeout"] <= 0.75
