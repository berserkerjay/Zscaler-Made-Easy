"""Required DLP analysis dependencies, exercised through production boundaries.

All clients below are deterministic recording fakes. Required analysis never
implies a tenant write, a generated incident, a deployment target, or a newly
started monitor. Cases cover distinct entry points and evidence failure modes.
"""
from __future__ import annotations

import copy
import json
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import channel_scope
import continuous_eval
import data_flow
import dlp_api_server as api
import scenario_flow

REQUIRED = ("ssl", "url", "ftc", "cac", "workflow")
INLINE = REQUIRED[:-1]
ENDPOINTS = {
    "ssl": "/zia/sslInspectionRules",
    "url": "/zia/urlFilteringRules",
    "ftc": "/zia/fileTypeRules",
    "cac": "/zia/cloudApplicationRules",
}
OWNERSHIP = {"ssl": "ssl_inspection", "cac": "cloud_app_control", "workflow": "workflow_automation"}
CREDS = {"vanity_domain": "required-control-fixture", "client_id": "fixture-client-id", "client_secret": "fixture-not-a-real-secret"}
CHANNELS = ("web", "endpoint", "email", "saas")
ROUTES = [
    pytest.param("/api/flow/scenario", {"corpus": "SYNTHETIC-CONTROL-MARKER"}, id="unified-local-test"),
    pytest.param("/api/dlp/efficacy", {}, id="legacy-efficacy"),
    pytest.param("/api/dlp/efficacy/test", {"corpus": "SYNTHETIC-CONTROL-MARKER"}, id="legacy-corpus-test"),
    pytest.param("/api/dlp/efficacy/export", {"format": "json"}, id="efficacy-json-export"),
    pytest.param("/api/path-analyzer", {"destination": "example.test"}, id="legacy-path"),
    pytest.param("/api/report/data-flow", {"destinations": ["example.test"]}, id="data-flow-map"),
    pytest.param("/api/report/ssl-flow", {}, id="ssl-report"),
    pytest.param("/api/report/bypass", {}, id="bypass-report"),
    pytest.param("/api/report/bypass/export", {"format": "json"}, id="bypass-json-export"),
    pytest.param("/api/detection-health", {"days": 1}, id="detection-health"),
    pytest.param("/api/live-feed", {}, id="explicit-live-poll"),
]


def body(tested_channel="web", **patch):
    result = dict(CREDS, scopes=["dlp"], channels={scenario_flow.CHANNELS[tested_channel][0]: "zscaler"}, from_page=True)
    result.update(patch)
    return result


def controls(result):
    rows = result.get("required_controls")
    assert isinstance(rows, list), "Every DLP analysis response must expose its required control evidence"
    indexed = {row["key"]: row for row in rows}
    assert len(indexed) == len(rows), "Required control evidence must not contain duplicate control keys"
    assert set(REQUIRED) <= indexed.keys(), indexed
    return indexed


class RecordingClient:
    """Permit reads and the documented URL lookup; fail every policy write."""
    def __init__(self):
        self.calls = []
        self.lookups = []
        self.failures = {}
        self.requests_made = 0
        self.routes = {
            "/zia/sslInspectionRules": [{"id": 12, "name": "Fixture TLS decrypt", "state": "ENABLED", "action": {"type": "DECRYPT"}, "order": 1}],
            "/zia/urlFilteringRules": [{"id": 13, "name": "Fixture URL allow", "state": "ENABLED", "action": "ALLOW", "order": 1}],
            "/zia/fileTypeRules": [{"id": 14, "name": "Fixture file allow", "state": "ENABLED", "action": "ALLOW", "order": 1}],
            "/zia/cloudApplicationRules": [{"id": 15, "name": "Fixture app policy", "state": "ENABLED", "action": "ALLOW", "order": 1}],
        }
        self._zs = SimpleNamespace(zia=SimpleNamespace(cloud_applications=SimpleNamespace(
            list_cloud_app_policy=lambda **kwargs: ([], None, None))))

    def auth(self):
        return True

    def close(self):
        pass

    def get(self, endpoint, *args, **kwargs):
        self.calls.append(endpoint)
        self.requests_made += 1
        if endpoint in self.failures:
            value, code = self.failures[endpoint]
            if isinstance(value, Exception):
                raise value
            return copy.deepcopy(value), code
        return copy.deepcopy(self.routes.get(endpoint, [])), 200

    def post(self, endpoint, value=None, *args, **kwargs):
        assert endpoint == "/zia/urlLookup", "DLP analysis attempted a tenant mutation: " + endpoint
        self.lookups.append(copy.deepcopy(value))
        return [{"url": value[0], "urlClassifications": []}], 200

    def put(self, *args, **kwargs):
        raise AssertionError("DLP analysis must not mutate tenant policy")

    patch = put
    delete = put


@pytest.fixture
def harness(monkeypatch, tmp_path):
    import tenant_fingerprint
    import proposals
    from test_detection_health import _client

    raw = RecordingClient()
    sdk = _client([])
    monkeypatch.setattr(api, "_tenant_creds", lambda req: dict(CREDS))
    monkeypatch.setattr(api, "_build_client", lambda req: raw)
    monkeypatch.setattr(api, "_raw_client", lambda creds: raw)
    monkeypatch.setattr(api, "_build_sdk_client", lambda creds: sdk)
    monkeypatch.setattr(tenant_fingerprint, "proposal_key", lambda *args: "required-controls-fixture")
    monkeypatch.setattr(continuous_eval, "_proposal_key_migrated", lambda *args: "required-controls-fixture")
    monkeypatch.setattr(proposals, "refresh_from_report", lambda *args: {})
    monkeypatch.setattr(proposals, "merge", lambda *args, **kwargs: {})
    monkeypatch.setattr(api, "_journey_packs", lambda *args: [])
    monkeypatch.setattr(api, "_live_rules_cache", {})
    monkeypatch.setattr(api, "_live_connector_cache", {})
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    return SimpleNamespace(http=TestClient(api.app), raw=raw, sdk=sdk)


@pytest.mark.parametrize("channel", CHANNELS)
def test_dlp_path_scope_keeps_inline_dependencies_for_each_selected_channel(channel):
    raw = {scenario_flow.CHANNELS[channel][0]: "zscaler"}
    before = copy.deepcopy(raw)
    selection = data_flow.path_scope(["dlp"], raw)
    assert set(INLINE) <= set(selection["read"])
    assert not (set(INLINE) & set(selection["not_in_scope"]))
    assert raw == before, "Derived analysis requirements must not rewrite the saved declaration"
    assert "zcc" not in selection["read"] and "pac" not in selection["read"]


@pytest.mark.parametrize("key", ("ssl", "cac"))
def test_alternative_inline_dependency_is_unmet_and_not_silently_read(key):
    selection = data_flow.path_scope(["dlp"], {"web_dlp": "zscaler", OWNERSHIP[key]: {"choice": "alternative", "note": "Other vendor"}})
    assert key not in selection["read"]
    assert key not in selection["not_in_scope"], "An unmet required dependency is not out of scope"
    assert key in json.dumps(selection).lower() and "alternative" in json.dumps(selection).lower()


@pytest.mark.parametrize("channel", CHANNELS)
@pytest.mark.parametrize("corpus", ("", "SYNTHETIC-CONTROL-MARKER"), ids=("configuration", "local-simulation"))
def test_scenario_keeps_all_required_stages_with_honest_channel_applicability(harness, channel, corpus):
    response = harness.http.post("/api/flow/scenario", json=body(channel, channel=channel, corpus=corpus))
    assert response.status_code == 200, response.text
    result = response.json()
    stages = {row["key"]: row for row in result["stages"]}
    assert set(REQUIRED) <= stages.keys()
    for key in REQUIRED:
        assert stages[key]["status"] != "out_of_scope", (key, stages[key])
    if channel != "web":
        assert all(stages[key]["status"] == "not_applicable" for key in INLINE)
    else:
        assert set(ENDPOINTS.values()) <= set(harness.raw.calls), "A destination-free test still assesses required configuration"
    assert stages["workflow"]["status"] in ("unknown", "unverified", "unmet")
    assert harness.sdk.zwa.dlp_incidents.calls == [], "Local testing must not turn into incident polling"
    assert not harness.raw.lookups, "A destination-free test must not invent a URL"
    assert result["scenario"]["mode"] == ("simulated" if corpus else "configuration")


@pytest.mark.parametrize("path,extra", ROUTES)
def test_every_dlp_analysis_entrypoint_exposes_five_required_controls(harness, path, extra):
    response = harness.http.post(path, json=body(**extra))
    assert response.status_code == 200, response.text
    rows = controls(response.json())
    assert all(row["status"] != "out_of_scope" for row in rows.values())
    for key in INLINE:
        assert ENDPOINTS[key] in harness.raw.calls, (path, key, harness.raw.calls)
    if path not in ("/api/live-feed", "/api/detection-health"):
        assert not harness.sdk.zwa.dlp_incidents.calls, "Configuration analysis must not poll live events as a side effect"


@pytest.mark.parametrize("path,extra", ROUTES)
def test_alternative_required_controls_stay_visible_and_are_never_queried(harness, path, extra):
    declaration = {"web_dlp": "zscaler", **{cid: {"choice": "alternative", "note": "Other vendor"} for cid in OWNERSHIP.values()}}
    response = harness.http.post(path, json=body(channels=declaration, **extra))
    assert response.status_code == 200, response.text
    rows = controls(response.json())
    for key in OWNERSHIP:
        assert rows[key]["status"] in ("unknown", "unverified", "unmet"), (key, rows[key])
        assert "alternative" in json.dumps(rows[key]).lower() or "other vendor" in json.dumps(rows[key]).lower()
    assert ENDPOINTS["ssl"] not in harness.raw.calls and ENDPOINTS["cac"] not in harness.raw.calls
    assert not harness.sdk.zwa.dlp_incidents.calls
    if path == "/api/live-feed":
        assert response.json()["incidents"] == []


@pytest.mark.parametrize("key", INLINE)
@pytest.mark.parametrize("code,reason", [(401, "auth"), (403, "permission"), (404, "unavailable"), (429, "rate"), (503, "fail")], ids=("authentication", "permission", "unsupported-route", "rate-limit", "service-unavailable"))
def test_failed_required_control_read_remains_unknown_not_missing_configuration(harness, key, code, reason):
    harness.raw.failures[ENDPOINTS[key]] = ({"error": "private-provider-response"}, code)
    response = harness.http.post("/api/flow/scenario", json=body(corpus="SYNTHETIC-CONTROL-MARKER"))
    assert response.status_code == 200, response.text
    row = controls(response.json())[key]
    assert row["status"] in ("unknown", "unverified")
    text = json.dumps(row).lower()
    assert reason in text or str(code) in text
    assert "private-provider-response" not in text
    assert "out_of_scope" not in text
    assert harness.raw.calls.count(ENDPOINTS[key]) == 1, "A denied read must not be retried through another route"


@pytest.mark.parametrize("path,extra", ROUTES)
@pytest.mark.parametrize("code", (401, 403), ids=("authentication-refused", "permission-refused"))
def test_analysis_does_not_turn_client_authorization_failures_into_success(harness, monkeypatch, path, extra, code):
    def denied(*args, **kwargs):
        raise HTTPException(status_code=code, detail="Fixture authorization refusal")
    monkeypatch.setattr(api, "_build_client", denied)
    monkeypatch.setattr(api, "_build_sdk_client", denied)
    response = harness.http.post(path, json=body(**extra))
    assert response.status_code == code, response.text
    assert response.json()["detail"] == "Fixture authorization refusal"
    assert not harness.raw.calls and not harness.sdk.zwa.dlp_incidents.calls


@pytest.mark.parametrize("channel", CHANNELS)
def test_analysis_requirements_never_expand_scheduled_monitor_incident_scope(channel):
    declaration = {scenario_flow.CHANNELS[channel][0]: "zscaler", "workflow_automation": "gap"}
    scope = continuous_eval.profile_scope({"scopes": ["dlp"], "channels": declaration})
    assert scope["pack_channels"] == [channel]
    assert scope["read_incidents"] is False
    assert declaration["workflow_automation"] == "gap"


@pytest.mark.parametrize("channel", CHANNELS)
def test_analysis_requirements_never_expand_deployment_channel_targets(channel):
    declaration = {scenario_flow.CHANNELS[channel][0]: "zscaler", "ssl_inspection": "gap", "cloud_app_control": "gap", "workflow_automation": "gap"}
    assert channel_scope.pack_targets(declaration) == [channel]
    assert declaration["ssl_inspection"] == declaration["cloud_app_control"] == declaration["workflow_automation"] == "gap"


@pytest.mark.parametrize("path,extra", ROUTES)
def test_dlp_requirements_do_not_authorize_reads_without_selected_dlp_scope(harness, path, extra):
    response = harness.http.post(path, json=body(scopes=[], **extra))
    assert response.status_code == (200 if path == "/api/flow/scenario" else 400), response.text
    assert not harness.raw.calls and not harness.sdk.zwa.dlp_incidents.calls


def _assessment(harness, **patch):
    from test_assess_stream import _events
    response = harness.http.post("/api/assess", json=body(**patch))
    assert response.status_code == 200, response.text
    events = _events(response)
    assert not [row for kind, row in events if kind == "error"], events[-3:]
    return next(row for kind, row in events if kind == "complete"), [row for kind, row in events if kind == "check"]


def test_inline_only_assessment_never_reports_required_ssl_as_out_of_scope(harness):
    report, streamed = _assessment(harness)
    evidence = controls(report)
    expected_ids = {"DLP.CTRL." + key.upper() for key in REQUIRED}
    indexed = {row["id"]: row for row in report["checks"]}
    assert expected_ids <= indexed.keys()
    assert expected_ids <= {row["id"] for row in streamed}
    assert "4.1" in indexed, "The user's Inline-Web-only reproduction must include SSL assessment"
    assert all(not indexed[key].get("out_of_scope") for key in expected_ids)
    assert all(row["status"] != "out_of_scope" for row in evidence.values())
    assert set(ENDPOINTS.values()) <= set(harness.raw.calls)
    assert "12.4" in indexed and "12.5" in indexed and "12.7" in indexed
    assert not harness.sdk.zwa.dlp_incidents.calls
    assert report["metadata"]["total_checks"] == len(report["checks"]) == report["summary"]["total"]
    assert not any(path.startswith(("/zcc/", "/zpa/", "/zdx/")) for path in harness.raw.calls)


def test_alternative_ssl_assessment_retains_visible_unmet_rows_without_ssl_read(harness):
    declaration = {"web_dlp": "zscaler", "ssl_inspection": {"choice": "alternative", "note": "Other proxy"}}
    report, streamed = _assessment(harness, channels=declaration)
    rows = {row["id"]: row for row in report["checks"]}
    assert "4.1" in rows and "DLP.CTRL.SSL" in rows
    assert rows["4.1"]["status"] == "INFO" and not rows["4.1"].get("out_of_scope")
    assert "4.1" in {row["id"] for row in streamed}
    assert controls(report)["ssl"]["status"] in ("unknown", "unverified", "unmet")
    assert ENDPOINTS["ssl"] not in harness.raw.calls
    assert all(row.get("status") != "PASS" for row in (rows["4.1"], rows["DLP.CTRL.SSL"]))
    assert report["metadata"]["total_checks"] == len(rows) == report["summary"]["total"]


@pytest.mark.parametrize("channel", ("endpoint", "email", "saas"))
def test_non_web_assessment_retains_required_dependency_inventory(harness, channel):
    report, _ = _assessment(harness, channels={scenario_flow.CHANNELS[channel][0]: "zscaler"})
    rows = controls(report)
    assert all(rows[key]["status"] != "out_of_scope" for key in REQUIRED)
    assert set(ENDPOINTS.values()) <= set(harness.raw.calls)
    assert "/zia/webDlpRules" not in harness.raw.calls
    assert not harness.sdk.zwa.dlp_incidents.calls


CACHED = [
    pytest.param("/api/report/data-flow", {"destinations": ["example.test"]}, "/api/report/data-flow/", "/api/report/data-flow/export/", id="data-flow"),
    pytest.param("/api/report/ssl-flow", {}, "/api/report/ssl-flow/", "/api/report/ssl-flow/export/", id="ssl-flow"),
    pytest.param("/api/report/bypass", {}, "/api/report/bypass/", "/api/report/bypass/export/", id="bypass"),
    pytest.param("/api/detection-health", {"days": 1}, "/api/detection-health/", "/api/detection-health/export/", id="detection-health"),
]


@pytest.mark.parametrize("generate,extra,read,export", CACHED)
def test_cached_report_and_json_download_preserve_required_evidence(harness, generate, extra, read, export):
    declaration = {"web_dlp": "zscaler", "ssl_inspection": "alternative", "workflow_automation": "alternative"}
    response = harness.http.post(generate, json=body(channels=declaration, **extra))
    assert response.status_code == 200, response.text
    original = response.json()
    expected = controls(original)
    calls = list(harness.raw.calls)
    for url in (read + original["report_id"], export + original["report_id"] + "?format=json"):
        result = harness.http.get(url)
        assert result.status_code == 200, result.text
        assert controls(result.json()) == expected
    assert harness.raw.calls == calls, "Reading or exporting a saved report must not reread the tenant"


@pytest.mark.parametrize("generate,extra,read,export", CACHED)
def test_markdown_report_names_every_required_control_and_alternative_gap(harness, generate, extra, read, export):
    declaration = {"web_dlp": "zscaler", "ssl_inspection": "alternative", "workflow_automation": "alternative"}
    response = harness.http.post(generate, json=body(channels=declaration, **extra))
    assert response.status_code == 200, response.text
    original = response.json()
    evidence = controls(original)
    result = harness.http.get(export + original["report_id"] + "?format=markdown")
    assert result.status_code == 200, result.text
    for row in evidence.values():
        assert row["label"].lower() in result.text.lower()
    assert "alternative" in result.text.lower() and "unverified" in result.text.lower()


@pytest.mark.parametrize("fmt", ("csv", "markdown", "json"))
def test_legacy_efficacy_export_carries_required_controls(harness, fmt):
    response = harness.http.post("/api/dlp/efficacy/export", json=body(format=fmt))
    assert response.status_code == 200, response.text
    if fmt == "json":
        controls(response.json())
    else:
        for label in ("URL filtering", "SSL", "File Type Control", "Cloud App Control", "Workflow Automation"):
            assert label.lower() in response.text.lower()
