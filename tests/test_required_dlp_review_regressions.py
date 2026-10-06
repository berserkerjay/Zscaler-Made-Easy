"""Independent review regressions for mandatory DLP evidence composition.

Recording clients prove request boundaries; they deliberately provide no cache
of their own, so failed-read de-duplication cannot accidentally rely on a fake.
"""
from collections import Counter

import pytest

import data_flow
import path_analyzer
from test_required_dlp_controls import ENDPOINTS, body, controls, harness  # noqa: F401


@pytest.mark.parametrize("before,after", [("zscaler", "alternative"), ("alternative", "zscaler"), ("gap", "alternative")])
def test_changed_workflow_declaration_invalidates_cached_required_evidence(harness, before, after):
    prior = body(channels={"web_dlp": "zscaler", "workflow_automation": before}, destination="first.example.test")
    current = body(channels={"web_dlp": "zscaler", "workflow_automation": after}, destination="second.example.test")
    first = harness.http.post("/api/path-analyzer", json=prior)
    assert first.status_code == 200, first.text
    prior_scope = data_flow.path_scope(prior["scopes"], prior["channels"])
    next_scope = data_flow.path_scope(current["scopes"], current["channels"])
    assert prior_scope["key"] != next_scope["key"]
    assert not path_analyzer.reusable({"path_scope": prior_scope["key"]}, next_scope)
    second = harness.http.post("/api/path-analyzer", json=dict(current, report_id=first.json()["report_id"]))
    assert second.status_code == 200, second.text
    result = second.json()
    assert result["fresh_read"] is True
    workflow = controls(result)["workflow"]
    assert workflow["declared"] == after
    assert workflow["read_permitted"] is (after != "alternative")
    if after == "alternative":
        assert "alternative" in workflow["detail"].lower()


def test_unchanged_path_scope_reuses_identical_required_evidence_without_reads(harness):
    first = harness.http.post("/api/path-analyzer", json=body(destination="first.example.test"))
    assert first.status_code == 200, first.text
    first_result = first.json()
    call_counts = Counter(harness.raw.calls)
    second = harness.http.post("/api/path-analyzer", json=body(destination="second.example.test", report_id=first_result["report_id"]))
    assert second.status_code == 200, second.text
    result = second.json()
    assert result["fresh_read"] is False
    assert controls(result) == controls(first_result)
    assert Counter(harness.raw.calls) == call_counts


@pytest.mark.parametrize("route,extra", [
    ("/api/flow/scenario", {"destination": "example.test", "corpus": "SYNTHETIC REVIEW MARKER"}),
    ("/api/path-analyzer", {"destination": "example.test"}),
    ("/api/report/data-flow", {"destinations": ["example.test"]}),
    ("/api/report/ssl-flow", {}),
    ("/api/report/bypass", {}),
])
def test_composed_routes_do_not_repeat_denied_required_collection_reads(harness, route, extra):
    harness.raw.failures[ENDPOINTS["ssl"]] = ({"error": "permission denied fixture"}, 403)
    response = harness.http.post(route, json=body(**extra))
    assert response.status_code == 200, response.text
    evidence = controls(response.json())
    assert evidence["ssl"]["status"] == "unverified"
    assert evidence["ssl"]["evidence_status"] == "unverified"
    assert "403" in evidence["ssl"]["detail"]
    for endpoint in ENDPOINTS.values():
        assert harness.raw.calls.count(endpoint) == 1, (route, endpoint, harness.raw.calls)
    assert not any(p.startswith("raw:") for p in harness.raw.calls)


def test_path_created_dataflow_report_and_download_retain_required_evidence(harness):
    result = harness.http.post("/api/path-analyzer", json=body(destination="example.test"))
    assert result.status_code == 200, result.text
    original = result.json()
    calls = list(harness.raw.calls)
    for url in ("/api/report/data-flow/" + original["report_id"],
                "/api/report/data-flow/export/" + original["report_id"] + "?format=json"):
        cached = harness.http.get(url)
        assert cached.status_code == 200, cached.text
        assert controls(cached.json()) == controls(original)
    markdown = harness.http.get("/api/report/data-flow/export/" + original["report_id"] + "?format=markdown")
    assert markdown.status_code == 200, markdown.text
    for row in controls(original).values():
        assert row["label"] in markdown.text
    assert harness.raw.calls == calls


def test_composed_scenario_does_not_repeat_exceptional_required_read(harness):
    harness.raw.failures[ENDPOINTS["ssl"]] = (OSError("private-provider-error"), 0)
    response = harness.http.post("/api/flow/scenario", json=body(destination="example.test"))
    assert response.status_code == 200, response.text
    row = controls(response.json())["ssl"]
    assert row["status"] == "unverified"
    assert "private-provider-error" not in row["detail"]
    assert harness.raw.calls.count(ENDPOINTS["ssl"]) == 1


def test_request_memo_checks_stop_even_for_cached_evidence():
    import threading
    import dlp_analysis
    import dlp_efficacy
    from test_required_dlp_controls import RecordingClient
    raw = RecordingClient()
    memo = dlp_analysis.read_once(raw)
    memo.get(ENDPOINTS["ssl"])
    cancel = threading.Event()
    memo.stop_check = cancel.is_set
    cancel.set()
    with pytest.raises(dlp_efficacy.CorpusReadStopped):
        memo.get(ENDPOINTS["ssl"])
    assert raw.calls == [ENDPOINTS["ssl"]]


def test_request_memo_does_not_share_mutable_inventory_or_cross_client_data():
    import dlp_analysis
    from test_required_dlp_controls import RecordingClient
    raw = RecordingClient()
    memo = dlp_analysis.read_once(raw)
    first, _ = memo.get(ENDPOINTS["ssl"])
    first[0]["name"] = "accidental consumer mutation"
    second, _ = memo.get(ENDPOINTS["ssl"])
    assert second[0]["name"] == "Fixture TLS decrypt"
    other = RecordingClient()
    other.routes[ENDPOINTS["ssl"]][0]["name"] = "Another tenant rule"
    third, _ = dlp_analysis.read_once(other).get(ENDPOINTS["ssl"])
    assert third[0]["name"] == "Another tenant rule"
    assert raw.calls == other.calls == [ENDPOINTS["ssl"]]
