"""PR55 integration contracts against fake tenants and executable UI helpers.

The read-only prerequisite graph must not change declared ownership or pack
write targets. Hiding assessment rows must not hide path-control evidence.
No network, saved credentials, tenant configuration or remote writes are used.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess

import pytest
from fastapi.testclient import TestClient

import beacon_scope
import channel_scope as cs
import data_flow as df
import dlp_api_server as srv
import path_analyzer as pa
import permissions
from dlp_assessment_full_auto import R
from test_assess_stream import _events
from test_flow_control_contract import DEST, snapshot


ROOT = Path(__file__).resolve().parents[1]
CREDS = {"vanity_domain": "fixture", "client_id": "fixture-client-id", "client_secret": "fixture-secret-value"}
DEPENDENCIES = [
    ("web_dlp", "ssl_inspection", "/zia/sslInspectionRules"),
    ("genai_security", "ssl_inspection", "/zia/sslInspectionRules"),
    ("device_control", "endpoint_dlp", "/zia/endPointDlpRules"),
]


class RecordingTenant:
    def __init__(self, routes=None):
        self.routes = routes or {}
        self.reads = []
        self.requests_made = 0

    def auth(self):
        return True

    def get(self, endpoint, *args, **kwargs):
        self.reads.append(endpoint)
        self.requests_made += 1
        value = self.routes.get(endpoint, [])
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, tuple) else (copy.deepcopy(value), 200)

    def post(self, endpoint, body=None):
        assert endpoint == "/zia/urlLookup", "Only the read-only classification lookup is allowed"
        self.reads.append(endpoint)
        return [{"url": body[0], "urlClassifications": []}], 200


def assessment(monkeypatch, channels, scopes, checks=None):
    client = RecordingTenant()
    monkeypatch.setattr(srv, "Client", lambda *args, **kwargs: client)
    monkeypatch.setattr(srv, "_journey_scope", lambda *args: ([], {}))
    monkeypatch.setattr(srv, "CHECK_TIMEOUT", 5)
    if checks is not None:
        monkeypatch.setattr(srv, "_get_checks", lambda *args: checks)
    with TestClient(srv.app).stream("POST", "/api/assess", json=dict(CREDS, channels=channels, scopes=scopes)) as response:
        assert response.status_code == 200, response.read()
        events = _events(response)
    return next(data for kind, data in events if kind == "complete"), events, client


@pytest.mark.parametrize("parent,prerequisite,endpoint", DEPENDENCIES, ids=[x[0] for x in DEPENDENCIES])
def test_derived_prerequisites_are_readable_without_mutating_the_declaration(parent, prerequisite, endpoint):
    channels = {parent: {"choice": "zscaler"}, prerequisite: {"choice": "gap", "note": "Keep this operator note"}}
    saved = copy.deepcopy(channels)
    effective = cs.effective(channels)
    assert effective[prerequisite]["choice"] == "zscaler"
    assert effective[prerequisite]["declared"] == "gap"
    assert effective[prerequisite]["required_by"] == [parent]
    tenant = RecordingTenant()
    assert cs.ScopedClient(tenant, channels).get(endpoint)[1] == 200
    assert tenant.reads == [endpoint]
    assert channels == saved
    assert cs.normalize(channels)[prerequisite]["choice"] == "gap"


@pytest.mark.parametrize("parent", ["web_dlp", "genai_security"])
def test_ssl_vendor_exclusion_wins_over_an_implied_dependency(parent):
    channels = {parent: "zscaler", "ssl_inspection": {"choice": "alternative", "note": "Existing third-party TLS service"}}
    assert cs.effective(channels)["ssl_inspection"]["choice"] == "alternative"
    tenant = RecordingTenant()
    guarded = cs.ScopedClient(tenant, channels)
    for endpoint in ("/zia/sslInspectionRules", "/zia/sslInspectionRules/42", "raw:/zia/sslInspectionRules?pagesize=100"):
        assert guarded.get(endpoint)[1] == 0
    assert tenant.reads == []
    checks = srv._get_checks("", ["dlp", "genai"])
    run, skipped, _ = cs.partition(checks, channels)
    assert not ({"4.1", "5.5", "AI.5", "AI.6"} & {c[0] for c in run})
    assert {"4.1", "AI.5", "AI.6"} <= {c["id"] for c in skipped}


def test_device_control_conflict_fails_closed_without_selecting_endpoint_product():
    channels = {"device_control": "zscaler", "endpoint_dlp": {"choice": "alternative", "note": "Third-party endpoint DLP"}}
    assert cs.effective(channels)["endpoint_dlp"]["choice"] == "alternative"
    assert "endpoint_dlp" not in cs.in_scope(channels)
    tenant = RecordingTenant()
    # A contradictory prerequisite declaration must not authorize the shared read.
    assert cs.ScopedClient(tenant, channels).get("/zia/endPointDlpRules")[1] == 0
    assert tenant.reads == []
    run, _, _ = cs.partition(srv._get_checks("", ["dlp"]), channels)
    ids = {c[0] for c in run}
    assert not {"8.1", "5.1", "B.1", "B.5", "B.6"} & ids
    selected = beacon_scope.select(["dlp"], channels)
    assert "/zia/endPointDlpRules" not in selected["endpoints"]
    assert cs.pack_targets(channels) == []


@pytest.mark.parametrize("channels,targets", [
    ({"device_control": "zscaler"}, []),
    ({"device_control": "zscaler", "endpoint_dlp": "gap"}, []),
    ({"device_control": "zscaler", "endpoint_dlp": "zscaler"}, ["endpoint"]),
    ({"web_dlp": "zscaler", "device_control": "zscaler"}, ["web"]),
    ({"genai_security": "zscaler", "email_dlp": "zscaler"}, ["email"]),
], ids=["device-only", "endpoint-gap", "explicit-endpoint", "web-and-device", "genai-and-email"])
def test_read_prerequisites_never_expand_policy_pack_targets(channels, targets):
    assert cs.pack_targets(channels) == targets


@pytest.mark.parametrize("parent,prerequisite,endpoint", DEPENDENCIES, ids=[x[0] for x in DEPENDENCIES])
def test_channel_dependency_cannot_enable_a_deselected_path_service(parent, prerequisite, endpoint):
    scope = df.path_scope(["zdx"], {parent: "zscaler"})
    tenant = RecordingTenant()
    data = df.read_zia(tenant, scope=scope)
    assert scope["read"] == [] and not scope["lookup"]
    assert tenant.reads == []
    assert {"url", "ssl", "ftc", "endpoint"} <= data["not_in_scope"].keys()
    assert data["unread"] == {}, "Deliberately unassessed is not an API failure"
    with pytest.raises(ValueError, match="in scope"):
        pa.analyze(tenant, "example.com", scope=scope)
    assert tenant.reads == []


@pytest.mark.parametrize("channels,expected,excluded", [
    ({"web_dlp": "zscaler"}, {"/zia/sslInspectionRules", "/zia/webDlpRules"}, {"/zia/endPointDlpRules"}),
    ({"genai_security": "zscaler"}, {"/zia/sslInspectionRules"}, {"/zia/webDlpRules", "/zia/endPointDlpRules"}),
    ({"device_control": "zscaler"}, {"/zia/endPointDlpRules"}, {"/zia/sslInspectionRules", "/zia/webDlpRules"}),
    ({"web_dlp": "zscaler", "ssl_inspection": "alternative"}, {"/zia/webDlpRules"}, {"/zia/sslInspectionRules", "/zia/endPointDlpRules"}),
], ids=["web-ssl", "genai-ssl", "device-endpoint", "web-with-other-tls"])
def test_path_reads_only_the_resolved_channel_set(channels, expected, excluded):
    tenant = RecordingTenant()
    scope = df.path_scope(["dlp"], channels)
    data = df.read_zia(tenant, scope=scope)
    assert expected <= set(tenant.reads)
    assert not excluded & set(tenant.reads)
    assert {"/zia/urlFilteringRules", "/zia/fileTypeRules"} <= set(tenant.reads)
    assert not {"/zia/emailDlpRules", "/zia/casbDlpRules/all", "/zia/cloudApplicationRules"} & set(tenant.reads)
    assert data["unread"] == {}


@pytest.mark.parametrize("parent", ["web_dlp", "genai_security"])
def test_watch_and_assessment_agree_that_other_vendor_ssl_is_unread(parent):
    selected = beacon_scope.select(["dlp", "genai"], {parent: "zscaler", "ssl_inspection": "alternative"})
    assert "/zia/sslInspectionRules" not in selected["endpoints"]
    assert "/zia/sslInspectionRules" in selected["not_in_scope"]
    assert "ssl_inspection" not in selected["channels"]


def test_changing_ssl_ownership_invalidates_a_wider_cached_path():
    before = df.path_scope(["dlp"], {"web_dlp": "zscaler"})
    after = df.path_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "alternative"})
    first = pa.analyze(RecordingTenant(), "example.com", scope=before)
    cached = first["snapshot_for_cache"]
    assert pa.reusable(cached, before)
    assert not pa.reusable(cached, after)
    next_tenant = RecordingTenant()
    result = pa.analyze(next_tenant, "example.com", scope=after, snapshot=cached)
    assert result["fresh_read"]
    assert "/zia/sslInspectionRules" not in next_tenant.reads
    ssl = next(h for h in result["trace"]["hops"] if h["key"] == "ssl")
    assert ssl["status"] == "out_of_scope"
    assert not result["trace"]["content_inspected"]


def test_explicit_and_implied_ssl_with_the_same_read_set_can_reuse_cache():
    implied = df.path_scope(["dlp"], {"web_dlp": "zscaler"})
    explicit = df.path_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler"})
    cached = pa.analyze(RecordingTenant(), "example.com", scope=implied)["snapshot_for_cache"]
    tenant = RecordingTenant()
    result = pa.analyze(tenant, "example.com", scope=explicit, snapshot=cached)
    assert not result["fresh_read"]
    assert tenant.reads == ["/zia/urlLookup"]


@pytest.mark.parametrize("channels,scopes,required,forbidden", [
    ({"genai_security": "zscaler"}, ["genai"], {"AI.5", "AI.6"}, {"4.1", "B.1", "A.1"}),
    ({"device_control": "zscaler"}, ["dlp"], {"8.1", "5.1", "B.1"}, {"4.1", "A.1"}),
    ({"web_dlp": "zscaler", "ssl_inspection": "alternative"}, ["dlp"], {"A.1"}, {"4.1", "5.5", "A.2"}),
], ids=["genai-only-registry", "device-prerequisite", "excluded-ssl"])
def test_real_assessment_registry_respects_dependencies_and_selected_scopes(monkeypatch, channels, scopes, required, forbidden):
    report, events, tenant = assessment(monkeypatch, channels, scopes)
    visible = {c["id"] for c in report["checks"]}
    assert required <= visible and not forbidden & visible
    streamed = [row for event, row in events if event == "check"]
    assert {c["id"] for c in streamed} == visible
    assert not any(c.get("out_of_scope") for c in streamed + report["checks"])
    progress = [row for event, row in events if event == "progress"]
    assert progress[0]["completed"] == 0
    assert all(row["total"] == len(visible) for row in progress)
    assert progress[-1]["completed"] == len(visible) and progress[-1]["pct"] == 100
    assert report["summary"]["hidden"] == report["hidden_checks"] == report["channel_coverage"]["hidden"]
    if channels.get("ssl_inspection") == "alternative":
        assert "/zia/sslInspectionRules" not in tenant.reads


def test_hiding_assessment_rows_does_not_hide_in_scope_permission_failures(monkeypatch):
    calls = []

    def hidden(client):
        calls.append("hidden")
        return R(R.FAIL, "Must never execute")

    checks = [
        ("A.1", "Ch.A — Inline Web", "Web", lambda client: R(R.PASS, "Configured")),
        ("4.1", "4 — SSL Policy", "TLS", lambda client: R(R.INFO, "HTTP 403 Forbidden: API role lacks permission")),
        ("B.5", "Ch.B — Endpoint", "Endpoint", hidden),
    ]
    report, events, _ = assessment(monkeypatch, {"web_dlp": "zscaler"}, ["dlp"], checks)
    assert calls == []
    assert report["summary"]["not_permitted"] == 1
    assert report["summary"]["state"] == "partial"
    assert report["summary"]["score"] == 100
    assert report["summary"]["total"] == 2
    assert report["hidden_checks"] == 1
    assert "4 — SSL Policy" in report["sections"] and "Ch.B — Endpoint" not in report["sections"]
    assert {c["id"] for event, c in events if event == "check"} == {"A.1", "4.1"}


@pytest.mark.parametrize("mode", ["other-vendor", "api-denied", "service-excluded", "url-blocked"])
def test_always_visible_path_controls_keep_honest_prerequisite_status(mode):
    zcc, zia = snapshot()
    scope = df.path_scope(["dlp", "zcc"], {"web_dlp": "zscaler"})
    if mode == "other-vendor":
        scope = df.path_scope(["dlp", "zcc"], {"web_dlp": "zscaler", "ssl_inspection": "alternative"})
        zia["ssl"] = []
    elif mode == "api-denied":
        zia["ssl"] = []
        zia["unread"] = {"ssl": "HTTP 403 Forbidden"}
    elif mode == "service-excluded":
        scope = df.path_scope(["zcc"], {"web_dlp": "zscaler"})
        zia["ssl"] = []
    elif mode == "url-blocked":
        zia["url"] = [df._norm_generic({"id": 81, "name": "URL block", "action": "BLOCK"})]
    result = df.trace(copy.deepcopy(DEST), "off", "windows", zcc, zia, scope=scope)
    hops = {h["key"]: h for h in result["hops"]}
    assert {"url", "ssl", "ftc"} <= hops.keys()
    assert not result["content_inspected"]
    if mode == "other-vendor":
        assert hops["ssl"]["status"] == "out_of_scope" and hops["ftc"]["status"] == "unknown"
    elif mode == "api-denied":
        assert hops["ssl"]["status"] == "unknown" and hops["ftc"]["status"] == "unknown"
    elif mode == "service-excluded":
        assert all(hops[key]["status"] == "out_of_scope" for key in ("url", "ssl", "ftc"))
    else:
        assert hops["url"]["status"] == "blocked"
        assert hops["ssl"]["status"] == hops["ftc"]["status"] == "not_reached"
        assert hops["ftc"]["stopped_by"]["object_id"] == 81


def test_executable_legacy_report_filter_is_idempotent_and_preserves_path_evidence():
    report = {"checks": [
        {"id": "A.1", "section": "Web", "status": "PASS"},
        {"id": "B.1", "section": "Endpoint", "status": "FAIL", "out_of_scope": True},
        {"id": "4.1", "section": "TLS", "status": "ERROR", "detail": "Timed out"},
    ], "metadata": {"total_checks": 3}, "score": 50,
        "trace": {"hops": [{"key": "ssl", "status": "out_of_scope"}, {"key": "url", "status": "not_reached"}, {"key": "ftc", "status": "unknown"}]}}
    script = r"""
const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync(process.argv[1], 'utf8');
const helpers = html.slice(html.indexOf('const NOT_PERMITTED_RE ='), html.indexOf('function coverageSentence(s, meta)'));
const ctx = {}; vm.createContext(ctx); vm.runInContext(helpers, ctx);
ctx.report = JSON.parse(process.argv[2]);
vm.runInContext('scopeVisible(report); scopeVisible(report)', ctx);
console.log(JSON.stringify(ctx.report));
"""
    completed = subprocess.run(["node", "-e", script, str(ROOT / "static/index.html"), json.dumps(report)],
                               capture_output=True, text=True, check=True, timeout=15)
    result = json.loads(completed.stdout)
    assert [c["id"] for c in result["checks"]] == ["A.1", "4.1"]
    assert result["hidden_checks"] == 1
    assert result["trace"] == report["trace"]
    assert set(result["sections"]) == {"Web", "TLS"}
    expected = permissions.assessment_summary(report["checks"])
    for key in ("score", "total", "scored", "state", "errors", "hidden"):
        assert result["summary"][key] == expected[key], key


@pytest.mark.parametrize("parent,prerequisite,endpoint", DEPENDENCIES, ids=[x[0] for x in DEPENDENCIES])
def test_blocked_prerequisite_is_reported_without_claiming_it_was_assessed(parent, prerequisite, endpoint):
    channels = {parent: "zscaler", prerequisite: {"choice": "alternative", "note": "Other vendor"}}
    coverage = cs.coverage(channels)
    assert prerequisite not in {row["id"] for row in coverage["zscaler"]}
    assert prerequisite in {row["id"] for row in coverage["alternative"]}
    dependency = next(row for row in coverage["prerequisites"] if row["id"] == prerequisite)
    assert dependency["blocked"] and dependency["declared"] == "alternative"
    assert dependency["required_by"] == [parent]
    assert "not read" in dependency["note"] and "included because" not in dependency["note"]
    assert dependency["note"] in coverage["note"]


def legacy_rows():
    return [
        {"id": "visible-pass", "sec": "Web", "label": "Visible configured rule", "status": "PASS", "detail": "Configured"},
        {"id": "visible-fail", "sec": "Web", "label": "Visible missing rule", "status": "FAIL", "detail": "Needs action"},
        {"id": "hidden-fail", "sec": "Excluded endpoint", "label": "SCOPE_FILTERED_LABEL", "status": "FAIL", "detail": "SCOPE_FILTERED_DETAIL", "out_of_scope": True},
        {"id": "hidden-review", "sec": "Excluded endpoint", "label": "SCOPE_FILTERED_REVIEW", "status": "REVIEW", "detail": "Out of scope", "out_of_scope": True},
    ]


@pytest.mark.parametrize("rendering", ["text", "rich"])
def test_cli_report_hides_legacy_rows_and_preserves_the_hidden_count(rendering, capsys):
    import io
    import dlp_assessment_full_auto as full
    from rich.console import Console

    rows = legacy_rows()
    cfg = {"org_name": "Fixture", "hidden_checks": 3}
    if rendering == "rich":
        stream = io.StringIO()
        console = Console(file=stream, width=160, force_terminal=False)
        full.report(rows, cfg, con=console)
        text = stream.getvalue()
        assert "CRITICAL (1)" in text
    else:
        full.report(rows, cfg)
        text = capsys.readouterr().out
    assert "Visible configured rule" in text and "Visible missing rule" in text
    assert "SCOPE_FILTERED" not in text and "Excluded endpoint" not in text
    assert "5 checks are outside the selected scope" in text
    assert "Assessed 2 of 2 checks" in text and "50%" in text
    assert rows[-1]["out_of_scope"], "Filtering must not rewrite the caller's legacy report"


def test_cli_json_cannot_resurrect_hidden_rows_as_unflagged_findings(tmp_path):
    import dlp_assessment_full_auto as full

    path = tmp_path / "assessment.json"
    full.save(legacy_rows(), {"org_name": "Fixture", "hidden_checks": 3}, path)
    report = json.loads(path.read_text())
    assert {row["id"] for row in report["checks"]} == {"visible-pass", "visible-fail"}
    assert [row["id"] for row in report["critical"]] == ["visible-fail"]
    assert report["review"] == []
    assert report["metadata"]["checks"] == report["coverage"]["total"] == 2
    assert report["score"] == 50 and set(report["sections"]) == {"Web"}
    assert report["hidden_checks"] == report["coverage"]["hidden"] == 5
    assert "SCOPE_FILTERED" not in path.read_text()


def test_profile_history_counts_only_visible_critical_findings():
    import tenant_profiles

    rows = legacy_rows()
    report = {"checks": rows, "critical": [r for r in rows if r["status"] == "FAIL"],
              "metadata": {"assessor": "Fixture assessor"}, "score": 50, "maturity": "Developing"}
    history = tenant_profiles.snapshot(report)
    assert history["checks"] == 2 and history["critical"] == 1
    assert history["score"] == 50 and history["assessor"] == "Fixture assessor"
    assert len(report["checks"]) == 4 and len(report["critical"]) == 2


def test_device_prerequisite_does_not_start_new_ongoing_drift_reads(tmp_path, monkeypatch):
    import continuous_eval
    from test_continuous_eval import _env, _profile

    _env(tmp_path, monkeypatch)
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _profile(scopes=["dlp"], channels={"device_control": "zscaler"}, baseline_packs=["healthcare_phi_baseline"])
    built = []
    digest = continuous_eval.run_once(build_client=lambda creds: built.append(creds) or RecordingTenant(), notify=False)
    assert built == [], "An assessment prerequisite is not authorization for new ongoing channel reads"
    tenant = digest["tenants"][0]
    assert tenant["scope"]["pack_channels"] == []
    assert tenant["errors"] == [] and tenant["drift"]["packs"] == []
    assert "drift not measured" in tenant["drift"]["note"]
    assert digest["summary"]["tenants"] == 0


@pytest.mark.parametrize("independent,check_id,section", [
    ("web_dlp", "A.9", "Ch.A — Inline Web"),
    ("email_dlp", "D.9", "Ch.D — Email DLP"),
], ids=["independent-web", "independent-email"])
def test_blocked_device_dependency_does_not_revoke_other_owners_of_shared_settings(independent, check_id, section):
    channels = {independent: "zscaler", "device_control": "zscaler", "endpoint_dlp": "alternative"}
    tenant = RecordingTenant()
    guarded = cs.ScopedClient(tenant, channels)
    assert guarded.get("/zia/webDlpGlobalOptions")[1] == 200
    assert guarded.get("/zia/endPointDlpRules")[1] == 0
    assert tenant.reads == ["/zia/webDlpGlobalOptions"]
    checks = [(check_id, section, "Independent channel settings", lambda client: None),
              ("8.1", "8 — Advanced DLP", "Conflicting device rules", lambda client: None)]
    run, skipped, _ = cs.partition(checks, channels)
    assert [row[0] for row in run] == [check_id]
    assert [row["id"] for row in skipped] == ["8.1"]
    watch = beacon_scope.select(["dlp"], channels)
    assert "/zia/webDlpGlobalOptions" in watch["endpoints"]
    assert "/zia/endPointDlpRules" not in watch["endpoints"]
