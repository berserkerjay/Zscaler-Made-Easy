"""Configuration evidence contracts. Every case is a distinct control/branch failure mode."""
import copy
import json
import subprocess
from pathlib import Path

import pytest
import data_flow as df
import path_analyzer as pa
import ssl_flow as sf


DEST = {"label": "example.com", "host": "example.com", "kind": "host", "categories": ["TEST"], "applications": ["APP"], "app_classes": ["FILE_SHARE"]}
SCOPE = df.path_scope(["dlp"], {"ssl_inspection": "zscaler", "web_dlp": "zscaler"})


def snapshot():
    zcc = {"app_profiles": [{"id": 1, "name": "App", "platform": "windows", "active": True, "priority": 1,
            "bypass": {"domains": [], "apps": [], "ips": []}, "strict_enforcement": True, "ssl_cert": True,
            "endpoint_dlp": True, "forwarding_profile": 2}],
           "forwarding_profiles": [{"id": 2, "name": "Forward", "actions": {"off": {"mode_kind": "tunnel", "mode_label": "Z-Tunnel 2.0"}}}],
           "pac_files": [], "errors": []}
    zia = {k: [] for k in ("ssl", "url", "cac", "ftc", "dlp", "endpoint", "saas", "email")}
    zia["ssl"] = [sf.normalize_ssl_rule({"id": 10, "name": "Decrypt", "action": "DECRYPT"})]
    return zcc, zia


def run(zcc=None, zia=None, context=None, scope=None):
    a, b = snapshot()
    return df.trace(copy.deepcopy(DEST), "off", "windows", zcc or a, zia or b, scope=scope, context=context)


def by(t, key):
    return next(h for h in t["hops"] if h["key"] == key)


@pytest.mark.parametrize("stop", ["zcc", "forwarding", "pac", "url", "ssl", "ftc", "cac"])
def test_stopped_branch_retains_complete_control_architecture(stop):
    zcc, zia = snapshot()
    context = {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}
    if stop == "zcc": zcc["app_profiles"][0]["bypass"]["domains"] = ["example.com"]
    if stop == "forwarding": zcc["forwarding_profiles"][0]["actions"]["off"]["mode_kind"] = "none"
    if stop == "pac":
        zcc["app_profiles"][0]["pac_url"] = "https://pac.example/corp.pac"
        zcc["pac_files"] = [{"id": 3, "name": "Corp PAC", "url": "https://pac.example/corp.pac", "has_content": True, "direct_hosts": ["example.com"]}]
    if stop == "url": zia["url"] = [df._norm_generic({"id": 20, "name": "URL stop", "action": "BLOCK"})]
    if stop == "ssl": zia["ssl"] = [sf.normalize_ssl_rule({"id": 21, "name": "TLS stop", "action": "BLOCK"})]
    if stop == "ftc": zia["ftc"] = [df._norm_generic({"id": 22, "name": "ZIP stop", "action": "BLOCK", "operation": "UPLOAD", "fileTypes": ["FTCATEGORY_ZIP"]})]
    if stop == "cac": zia["cac"] = [df._norm_generic({"id": 23, "name": "App stop", "applications": ["APP"], "actions": ["BLOCK_FILE_SHARE_UPLOAD"]})]
    t = run(zcc, zia, context)
    assert {"url", "ssl", "ftc", "dlp", "incident"} <= {h["key"] for h in t["hops"]}
    assert by(t, "dlp")["status"] == "not_reached"
    assert by(t, "incident")["stopped_by"]["key"] == stop
    assert by(t, "incident")["stopped_by"]["object_name"]
    assert not t["content_inspected"] and not t["content_inspection_possible"]
    if stop not in ("ssl", "ftc"): assert not t["decrypted"]
    assert t["outcome"] == ("bypassed" if stop in ("zcc", "forwarding", "pac") else "blocked")


FTC_CASES = [
    ("missing-both", {}, {}, "conditional"),
    ("missing-file", {"operation": "UPLOAD"}, {}, "conditional"),
    ("missing-operation", {"file_type": "FTCATEGORY_ZIP"}, {}, "conditional"),
    ("upload-zip-block", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {}, "blocked"),
    ("different-file", {"operation": "UPLOAD", "file_type": "FTCATEGORY_PDF"}, {}, "none"),
    ("different-operation", {"operation": "DOWNLOAD", "file_type": "FTCATEGORY_ZIP"}, {}, "none"),
    ("download-rule", {"operation": "DOWNLOAD", "file_type": "FTCATEGORY_ZIP"}, {"operation": "DOWNLOAD"}, "blocked"),
    ("any-operation", {"operation": "DOWNLOAD", "file_type": "FTCATEGORY_ZIP"}, {"operation": "ANY"}, "blocked"),
    ("any-file", {"operation": "UPLOAD", "file_type": "FTCATEGORY_PDF"}, {"fileTypes": ["ANY"]}, "blocked"),
    ("all-file-types", {"operation": "UPLOAD", "file_type": "FTCATEGORY_PDF"}, {"fileTypes": []}, "blocked"),
    ("allow", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"action": "ALLOW"}, "pass"),
    ("caution", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"action": "CAUTION"}, "warn"),
    ("disabled", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"state": "DISABLED"}, "none"),
    ("different-destination", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"urlCategories": ["OTHER"]}, "none"),
    ("group-scoped", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"groups": [{"id": 1}]}, "conditional"),
    ("user-scoped", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"users": [{"id": 1}]}, "conditional"),
    ("location-scoped", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"locations": [{"id": 1}]}, "conditional"),
    ("device-scoped", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"devices": [{"id": 1}]}, "conditional"),
    ("time-scoped", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"timeWindows": [{"id": 1}]}, "conditional"),
    ("multi-class-payload", {"operation": "UPLOAD", "file_types": ["FTCATEGORY_PDF", "FTCATEGORY_ZIP"]}, {}, "blocked"),
    ("normalized-operation", {"operation": "upload", "file_type": "ftcategory_zip"}, {}, "blocked"),
    ("no-action", {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, {"action": ""}, "warn"),
]
@pytest.mark.parametrize("name,context,patch,expected", FTC_CASES, ids=[x[0] for x in FTC_CASES])
def test_ftc_requires_supported_applicability(name, context, patch, expected):
    zcc, zia = snapshot()
    rule = dict(id=30, name="FTC candidate", action="BLOCK", operation="UPLOAD", fileTypes=["FTCATEGORY_ZIP"])
    rule.update(patch)
    zia["ftc"] = [df._norm_generic(rule)]
    h = by(run(zcc, zia, context), "ftc")
    assert h["status"] == expected
    if expected == "conditional": assert not h["decided_by"] and h["candidate_rules"][0]["id"] == 30


@pytest.mark.parametrize("state", ["encrypted", "ssl-unread", "ssl-excluded", "ftc-unread", "ftc-excluded", "ordered-rules", "scoped-predecessor"])
def test_ftc_prerequisites_and_precedence(state):
    zcc, zia = snapshot(); scope = None
    zia["ftc"] = [df._norm_generic({"id": 31, "name": "Later block", "order": 9, "action": "BLOCK"}), df._norm_generic({"id": 32, "name": "Earlier allow", "order": 1, "action": "ALLOW"})]
    expected = "pass"
    if state == "encrypted": zia["ssl"][0] = sf.normalize_ssl_rule({"id": 10, "action": "DO_NOT_DECRYPT"}); expected = "blind"
    if state == "ssl-unread": zia["ssl"] = []; zia["unread"] = {"ssl": "403"}; expected = "unknown"
    if state == "ftc-unread": zia["unread"] = {"ftc": "429"}; expected = "unknown"
    if state.endswith("excluded"):
        key = state.split('-')[0]; scope = {"not_in_scope": {key: "Not in scope"}}; expected = "out_of_scope" if key == "ftc" else "unknown"
    if state == "scoped-predecessor": zia["ftc"][1]["scoped"] = True; expected = "conditional"
    h = by(run(zcc, zia, {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"}, scope), "ftc")
    assert h["status"] == expected
    if state == "ordered-rules": assert h["decided_by"]["id"] == 32


class Fake:
    def __init__(self, overrides=None):
        self.calls = []; self.routes = {"/zia/sslInspectionRules": [{"id": 1, "name": "Decrypt", "action": "DECRYPT"}], "/zia/webDlpRules": [], "/zia/urlFilteringRules": [], "/zia/fileTypeRules": []}
        self.routes.update(overrides or {})
    def get(self, endpoint, *args, **kwargs):
        self.calls.append(endpoint); value = self.routes.get(endpoint, [])
        if isinstance(value, Exception): raise value
        return value if isinstance(value, tuple) else (value, 200)


SOURCES = [("ssl", "/zia/sslInspectionRules"), ("dlp", "/zia/webDlpRules"), ("url", "/zia/urlFilteringRules"), ("ftc", "/zia/fileTypeRules")]
FAILURES = [("unauthenticated", ({}, 401)), ("permission-denied", ({}, 403)), ("unsupported-route", ({}, 404)), ("rate-limited", ({}, 429)), ("upstream-error", ({}, 500)), ("transport", TimeoutError("timeout")), ("malformed-object", ({"unexpected": []}, 200)), ("malformed-row", (["invalid"], 200))]
@pytest.mark.parametrize("key,endpoint", SOURCES, ids=[x[0] for x in SOURCES])
@pytest.mark.parametrize("failure,response", FAILURES, ids=[x[0] for x in FAILURES])
def test_ssl_report_failed_reads_remain_unknown(key, endpoint, failure, response):
    report = sf.generate_ssl_flow_report(Fake({endpoint: response}), scope=SCOPE)
    assert key in report["read_errors"]
    for row in report["classes"]:
        assert {c["key"] for c in row["controls"]} == {"url", "ssl", "ftc"}
        if key in ("ssl", "dlp"): assert row["dlp_status"] == "unknown"
        if key == "ssl": assert row["decision"] == "unknown" and not row["gaps"]
        if key in ("url", "ftc"): assert next(c for c in row["controls"] if c["key"] == key)["status"] == "unknown"
    assert not any(g["type"] == "ungoverned" for g in report["gaps"]) if key in ("ssl", "dlp") else True


@pytest.mark.parametrize("key,endpoint", SOURCES, ids=[x[0] for x in SOURCES])
@pytest.mark.parametrize("response", [([], 200), (None, 204)], ids=["read-empty", "no-content"])
def test_successful_empty_is_distinct_from_failed(key, endpoint, response):
    report = sf.generate_ssl_flow_report(Fake({endpoint: response}), scope=SCOPE)
    assert key not in report["read_errors"]
    if key == "ssl": assert all(r["decision"] == "no_rule" for r in report["classes"])


@pytest.mark.parametrize("channel", ["endpoint", "saas", "email"])
@pytest.mark.parametrize("condition", ["empty", "allow", "block", "disabled", "unread", "excluded"])
def test_nonweb_channels_are_inventory_not_tested_coverage(channel, condition):
    zcc, zia = snapshot(); scope = None
    if condition not in ("empty", "unread", "excluded"):
        zia[channel] = [{"id": 4, "name": "Separate rule", "state": "DISABLED" if condition == "disabled" else "ENABLED", "action": "BLOCK" if condition == "block" else "ALLOW", "engines": ["Engine"]}]
    if condition == "unread": zia["unread"] = {channel: "403"}
    if condition == "excluded": scope = {"not_in_scope": {channel: "Excluded"}}
    c = run(zcc, zia, scope=scope)["channels"][channel]
    assert c["status"] == ("unknown" if condition == "unread" else "out_of_scope" if condition == "excluded" else "inventory")
    assert c["tested"] is False and c["coverage"] == "unverified" and c["forwarding_status"] == "unverified"
    if condition == "block": assert c["rule_objects"][0]["id"] == 4 and c["enabled_count"] == 1


@pytest.mark.parametrize("condition", ["content-monitor", "content-block", "metadata-only", "no-engine", "scoped-only", "scoped-plus-general"])
def test_dlp_configuration_never_claims_observed_payload_scan(condition):
    zcc, zia = snapshot()
    rule = {"id": 50, "name": "DLP candidate", "action": "BLOCK" if condition == "content-block" else "ALLOW", "dlpEngines": [{"id": 5, "name": "Engine"}]}
    if condition == "metadata-only": rule["withoutContentInspection"] = True
    if condition == "no-engine": rule["dlpEngines"] = []
    if condition.startswith("scoped"): rule["groups"] = [{"id": 1}]
    zia["dlp"] = [sf.normalize_dlp_rule(rule)]
    if condition == "scoped-plus-general": zia["dlp"].append(sf.normalize_dlp_rule(dict(id=51, name="General", action="ALLOW", dlpEngines=[{"name": "General engine"}])))
    t = run(zcc, zia)
    assert not t["content_inspected"] and t["evidence_mode"] == "configuration"
    assert t["content_inspection_possible"] == (condition in ("content-monitor", "content-block", "scoped-plus-general"))
    if condition == "scoped-only": assert by(t, "dlp")["status"] == "conditional"
    if condition in ("metadata-only", "no-engine"): assert by(t, "dlp")["status"] == "metadata_only"


@pytest.mark.parametrize("receiver,icap", [(False, False), (True, False), (False, True), (True, True)], ids=["no-forwarding", "receiver-setting", "icap-only", "both-settings"])
def test_forwarding_configuration_never_confirms_workflow_delivery(receiver, icap):
    zcc, zia = snapshot()
    zia["dlp"] = [sf.normalize_dlp_rule({"id": 60, "name": "Rule", "action": "ALLOW", "dlpEngines": ["Engine"], "zscalerIncidentReceiver": receiver, "icapServer": {"id": 8, "name": "ICAP"} if icap else None})]
    h = by(run(zcc, zia), "incident")
    assert h["delivery_status"] == "unverified" and h["observed"] is False and h["status"] != "pass"
    assert bool(h["forwarders"]) == receiver and bool(h["icap_forwarders"]) == icap
    assert "does not establish" in h["detail"]


@pytest.mark.parametrize("excluded", ["ssl", "url", "ftc", "dlp"])
def test_scope_exclusion_retains_required_nodes_without_extra_reads(excluded):
    scope = copy.deepcopy(SCOPE)
    if excluded == "ssl":
        with pytest.raises(ValueError): sf.generate_ssl_flow_report(Fake(), scope={"read": [], "not_in_scope": {"ssl": "Excluded"}})
        return
    scope["read"] = [k for k in scope["read"] if k != excluded]
    scope["not_in_scope"][excluded] = "Excluded"
    c = Fake(); report = sf.generate_ssl_flow_report(c, scope=scope)
    endpoint = dict(SOURCES)[excluded]
    assert endpoint not in c.calls
    if excluded != "dlp": assert all(next(h for h in row["controls"] if h["key"] == excluded)["status"] == "out_of_scope" for row in report["classes"])
    else: assert all(row["dlp_status"] == "not_in_scope" for row in report["classes"])


VISIBILITY = [
    ("url-blocked", {"outcome": "blocked", "decrypted": True, "reaches_zscaler": True}, "Blocked"),
    ("ssl-blocked", {"outcome": "blocked", "decrypted": False, "reaches_zscaler": True}, "Blocked"),
    ("ftc-blocked", {"outcome": "blocked", "decrypted": True, "reaches_zscaler": True, "hops": [{"key": "ftc", "status": "blocked"}]}, "Blocked"),
    ("bypassed", {"outcome": "bypassed", "decrypted": False, "reaches_zscaler": False}, "Bypassed"),
    ("routing-unknown", {"conditional": True}, "Unable to verify"),
    ("ssl-unknown", {"hops": [{"key": "ssl", "status": "unknown"}]}, "Unable to verify"),
    ("ssl-excluded", {"hops": [{"key": "ssl", "status": "out_of_scope"}]}, "Unable to verify"),
    ("encryption-visible", {"reaches_zscaler": True, "decrypted": False}, "Encrypted"),
    ("configured-monitor", {"outcome": "monitor", "reaches_zscaler": True, "decrypted": True}, "Decryption configured · monitor"),
    ("no-content-rule", {"outcome": "metadata_only", "reaches_zscaler": True, "decrypted": True}, "Decryption configured"),
]
@pytest.mark.parametrize("name,trace,label", VISIBILITY, ids=[x[0] for x in VISIBILITY])
def test_visibility_text_never_confuses_stopped_with_inspected(name, trace, label):
    js = "const fs=require('fs'),vm=require('vm'),c={window:{}};vm.createContext(c);vm.runInContext(fs.readFileSync('static/data_flow.js','utf8'),c);console.log(JSON.stringify(vm.runInContext('_dfVisibility('+process.argv[1]+')',c)));"
    p = subprocess.run(["node", "-e", js, json.dumps(trace)], capture_output=True, text=True, check=True)
    result = json.loads(p.stdout)
    assert result[0] == label
    assert "Decrypted and inspected" not in result[2]


@pytest.mark.parametrize("key,endpoint", SOURCES, ids=[x[0] for x in SOURCES])
def test_partial_rule_inventories_are_retryable_unknown_not_complete(key, endpoint):
    report = sf.generate_ssl_flow_report(Fake({endpoint: ({"rules": [{"id": 1}], "totalCount": 2}, 200)}), scope=SCOPE)
    assert key in report["read_errors"]
    assert any(d["error_type"] == "incomplete response" for d in report["diagnostics"])


@pytest.mark.parametrize("format", ["csv", "markdown"])
def test_ssl_exports_retain_the_three_required_controls_and_unknowns(format):
    report = sf.generate_ssl_flow_report(Fake({"/zia/sslInspectionRules": ({}, 403)}), scope=SCOPE)
    out = sf.to_csv(report) if format == "csv" else sf.to_markdown(report)
    for label in ("URL Filtering", "SSL Inspection", "File Type Control"):
        assert label in out
    assert "unknown" in out


@pytest.mark.parametrize("channel", ["endpoint", "saas", "email"])
def test_other_channels_cannot_be_silently_recast_as_inline_web(channel):
    with pytest.raises(ValueError, match="inline web"):
        run(context={"channel": channel})
    client = Fake()
    with pytest.raises(ValueError, match="inline web"):
        pa.analyze(client, "example.com", scope=SCOPE, context={"channel": channel})
    assert client.calls == []


def test_ssl_block_retains_file_type_control_and_its_stop_source():
    report = sf.generate_ssl_flow_report(Fake({"/zia/sslInspectionRules": [{"id": 9, "name": "TLS block", "action": "BLOCK"}]}), scope=SCOPE)
    for row in report["classes"]:
        ftc = next(h for h in row["controls"] if h["key"] == "ftc")
        assert ftc["status"] == "not_reached"
        assert ftc["stopped_by"]["object_id"] == 9 and ftc["stopped_by"]["object_name"] == "TLS block"


@pytest.mark.parametrize("extension", ["pdf", "xlsx", "txt", "zip", "application/pdf"])
def test_extension_or_mime_hint_is_not_a_verified_zia_file_category(extension):
    zcc, zia = snapshot()
    zia["ftc"] = [df._norm_generic({"id": 70, "name": "PDF restriction", "action": "BLOCK", "operation": "UPLOAD", "fileTypes": ["FTCATEGORY_PDF"]})]
    h = by(run(zcc, zia, {"channel": "web", "operation": "UPLOAD", "file_type": extension}), "ftc")
    assert h["status"] == "conditional" and "file type" in h["missing_context"]
    assert h["candidate_rules"][0]["id"] == 70


def test_unknown_ssl_action_stays_unknown_in_trace_and_verdict():
    zcc, zia = snapshot()
    zia["ssl"] = [sf.normalize_ssl_rule({"id": 90, "name": "Future rule", "action": "FUTURE_ENUM"})]
    zia["cac"] = [df._norm_generic({"id": 91, "name": "App upload", "applications": ["APP"], "actions": ["BLOCK_FILE_SHARE_UPLOAD"]})]
    t = run(zcc, zia, {"operation": "UPLOAD", "file_type": "FTCATEGORY_ZIP"})
    for key in ("ssl", "ftc", "dlp", "cac"):
        assert by(t, key)["status"] == "unknown"
    assert by(t, "url")["status"] == "conditional"
    assert t["outcome"] == "unknown" and not t["content_inspection_possible"]
    v = pa.derive_verdict(t, pa.parse_destination("example.com"), {"security_alerts": []})
    assert "not recognized" in v["headline"] and "encrypted" not in v["headline"]


URL_SCOPE_CASES = [
    ("scoped-allow-before-block", "ALLOW", "BLOCK", 1, 2, "ENABLED", ["TEST"], "conditional"),
    ("scoped-block-before-allow", "BLOCK", "ALLOW", 1, 2, "ENABLED", ["TEST"], "conditional"),
    ("scoped-rule-after-global", "ALLOW", "BLOCK", 2, 1, "ENABLED", ["TEST"], "blocked"),
    ("disabled-scoped-rule", "ALLOW", "BLOCK", 1, 2, "DISABLED", ["TEST"], "blocked"),
    ("nonmatching-scoped-rule", "ALLOW", "BLOCK", 1, 2, "ENABLED", ["OTHER"], "blocked"),
]
@pytest.mark.parametrize("name,scoped_action,general_action,first,last,state,cats,expected", URL_SCOPE_CASES, ids=[r[0] for r in URL_SCOPE_CASES])
def test_url_identity_conditions_obey_precedence(name, scoped_action, general_action, first, last, state, cats, expected):
    zcc, zia = snapshot()
    zia["url"] = [df._norm_generic({"id": 93, "name": "Global", "action": general_action, "order": last}),
                  df._norm_generic({"id": 92, "name": "Scoped", "action": scoped_action, "order": first, "state": state, "urlCategories": cats, "groups": [{"id": 1}]})]
    t = run(zcc, zia)
    assert by(t, "url")["status"] == expected
    if expected == "conditional":
        assert t["policy_conditional"] and not by(t, "url")["decided_by"]
        assert by(t, "dlp")["status"] != "not_reached"


METHOD_CASES = [
    ("download-not-http-method", {"operation": "DOWNLOAD"}, ["POST"], "conditional"),
    ("known-get-does-not-match-post", {"request_method": "GET"}, ["POST"], "pass"),
    ("known-post-matches", {"request_method": "POST"}, ["POST"], "blocked"),
    ("any-method-needs-no-guess", {}, ["ANY"], "blocked"),
]
@pytest.mark.parametrize("name,context,methods,status", METHOD_CASES, ids=[r[0] for r in METHOD_CASES])
def test_url_request_method_is_never_inferred_from_operation(name, context, methods, status):
    zcc, zia = snapshot()
    zia["url"] = [df._norm_generic({"id": 94, "name": "Method rule", "action": "BLOCK", "requestMethods": methods})]
    assert by(run(zcc, zia, context), "url")["status"] == status


@pytest.mark.parametrize("action,order,expected", [("DO_NOT_DECRYPT", 1, "conditional"), ("BLOCK", 1, "conditional"), ("DO_NOT_DECRYPT", 3, "pass")], ids=["earlier-scoped-exemption", "earlier-scoped-block", "later-scoped-exemption"])
def test_scoped_ssl_precedence_keeps_dependent_inspection_conditional(action, order, expected):
    zcc, zia = snapshot()
    zia["ssl"] = [sf.normalize_ssl_rule({"id": 95, "name": "Global decrypt", "order": 2, "action": "DECRYPT"}),
                  sf.normalize_ssl_rule({"id": 96, "name": "Scoped SSL", "order": order, "action": action, "groups": [{"id": 1}]})]
    t = run(zcc, zia)
    assert by(t, "ssl")["status"] == expected
    if expected == "conditional":
        assert not t["decrypted"] and t["policy_conditional"]
        assert by(t, "ftc")["status"] == "conditional" and by(t, "dlp")["status"] == "conditional"
        assert t["outcome"] == "conditional" and not t["content_inspection_possible"]
    else:
        assert t["decrypted"] and not t["policy_conditional"]


def test_supporting_rule_evidence_exports_only_allowlisted_fields():
    report = sf.generate_ssl_flow_report(Fake({"/zia/urlFilteringRules": [{"id": 100, "name": "Policy", "action": "ALLOW", "unexpectedToken": "PRIVATE_MARKER"}]}), scope=SCOPE)
    assert report["supporting_rules"]["url"][0]["name"] == "Policy"
    assert "PRIVATE_MARKER" not in json.dumps(report)
