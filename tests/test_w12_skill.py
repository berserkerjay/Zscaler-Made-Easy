"""Wave 12 (assistant skill rows): capacity review, incident postmortem, graded answers.

Offline: sample tenant and tmp stores; no sign-in, no network."""
from __future__ import annotations

import asyncio
import json

import pytest

import offline_tenant


def call(tool, /, **args):
    import dlp_mcp_server
    res = asyncio.run(dlp_mcp_server.mcp.call_tool(tool, args))
    return json.loads(res.content[0].text)


@pytest.fixture
def local(tmp_path, monkeypatch):
    for var, name in (("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"), ("DLP_CHECK_CAPACITY", "cap.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in ("ZSCALER_MCP_PROFILE", "ZSCALER_MCP_SCOPES", "ZSCALER_MCP_CHANNELS", "ZSCALER_CLIENT_SECRET", "ZSCALER_CLIENT_ID",
              "ZSCALER_VANITY_DOMAIN", "ZSCALER_AUTH_METHOD"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "ztw,zpa,automation")
    offline_tenant.sample_store(reset=True)
    return tmp_path


def test_headroom_status_bands_and_unknowns():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01: headroom is (licensed-used)/licensed; over, low, watch, ok bands; no read or no licensed count is stated, never guessed."""
    import capacity_review as cr
    # Act
    rep = cr.review({"locations": 95, "tunnels": 15, "zpa_segments": 120, "app_connectors": 10, "users": True},
                    {"locations": 100, "tunnels": 20, "zpa_segments": 100, "app_connectors": 100, "users": 5})
    # Assert
    by = {r["metric"]: r for r in rep["rows"]}
    assert (by["locations"]["status"], by["locations"]["headroom_pct"]) == ("low", 5.0)
    assert (by["tunnels"]["status"], by["tunnels"]["headroom_pct"]) == ("ok", 25.0)
    assert by["zpa_segments"]["status"] == "over" and by["app_connectors"]["status"] == "ok"
    assert by["users"]["status"] == "not_read" and rep["flagged"] == ["Locations", "ZPA application segments"]
    assert cr.review({"locations": 3}, {})["rows"][1]["status"] == "no_licensed_count"


def test_entitlements_file_ignores_bad_values_and_exports_are_csv_safe(tmp_path):
    """CWE-1236 · ASVS V5.2.2 · WSTG-INPV-01: bad licensed counts are dropped; a formula-looking value in the export is neutralised; markdown names are escaped."""
    import capacity_review as cr
    f = tmp_path / "e.json"
    f.write_text(json.dumps({"locations": 50, "users": -1, "tunnels": "x", "evil": 9}))
    # Act
    ent = cr.load_entitlements(str(f))
    rep = cr.review({"locations": 1}, ent)
    rep["rows"][0]["label"] = "=HYPERLINK(\"http://x\")"
    # Assert
    assert ent == {"locations": 50}
    assert "'=HYPERLINK" in cr.to_csv(rep) and "[x](" not in cr.to_markdown(rep, "[x](javascript:1)")


def test_capacity_review_tool_counts_the_sample_and_changes_nothing(local):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: the tool reports sample locations and ZPA counts with headroom against the local licensed file; the tenant copy is untouched."""
    (local / "cap.json").write_text(json.dumps({"locations": 10, "zpa_segments": 1000, "app_connectors": 1000}))
    # Act
    out = call("capacity_review", source="sample")
    # Assert
    rows = {r["metric"]: r for r in out["data"]["rows"]}
    assert rows["locations"]["used"] is not None and rows["locations"]["headroom_pct"] is not None
    assert rows["zpa_segments"]["used"] >= 1 and rows["users"]["status"] == "not_read"
    assert offline_tenant.sample_store().writes == 0


def test_capacity_review_is_refused_when_neither_product_is_in_scope(local, monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: with Cloud & Branch Connector and ZPA unticked nothing is read."""
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "automation")
    # Act
    out = call("capacity_review", source="sample")
    # Assert
    assert out["code"] == "not_in_scope"


def test_postmortem_builds_markdown_and_csv_from_the_window(local):
    """ASVS V7.2.1 · CWE-117 · CWE-1236 · WSTG-INPV-01: records in the window are in the timeline, records outside it are not; an injected name is inert in Markdown and neutralised in CSV."""
    import audit
    import postmortem as pm
    import audit_timeline as at
    audit.record("object_write", actor="jane.admin@example.com", action="update", kind="url_filtering_rule", name="=cmd|' /C calc'!A1 [x](javascript:1)",
                 tenant="acme (production)")
    win = at.window(7)
    # Act
    rep = pm.generate(window_=win, deployments=[], audit_entries=audit.tail(1000), title="Outage <b>1</b>")
    md, csv_text = pm.to_markdown(rep), pm.to_csv(rep)
    # Assert
    assert rep["summary"]["events"] >= 1 and rep["people"] == 1
    assert "\\[x\\]" in md and "<b>" not in md and "### Root cause:" in md
    assert "'=cmd" in csv_text
    old = pm.generate(window_=at.window(None, "2020-01-01", "2020-01-02"), deployments=[], audit_entries=audit.tail(1000))
    assert old["summary"]["events"] == 0


def test_postmortem_tool_is_scoped_and_bounded(local, monkeypatch):
    """ASVS V4.1.3 · V5.1.3 · CWE-1284: the tool returns Markdown for a chosen window, refuses a window over 31 days and refuses without Automation in scope."""
    import audit
    audit.record("object_write", actor="a@example.com", action="update", kind="rule", name="Block X", tenant="t")
    # Act
    ok = call("postmortem", title="Week")
    long = call("postmortem", start="2020-01-01")
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "ztw")
    refused = call("postmortem")
    # Assert
    assert ok["data"]["markdown"].startswith("# Week") and ok["data"]["summary"]["events"] >= 1
    assert long["code"] == "bad_input" and refused["code"] == "not_in_scope"


def test_every_answer_is_graded_with_source_tier_and_confidence(local):
    """ASVS V8.3.4 · CWE-1059: each tool answer carries a grade (source tier, confidence, basis, as-of); sample answers are illustrative, local-record answers say so."""
    # Act
    sample = call("ztw_summary", source="sample")
    tl = call("timeline")
    # Assert
    assert sample["grade"]["source_tier"] == "configuration" and sample["grade"]["confidence"] == "illustrative" and sample["grade"]["basis"]
    assert tl["grade"]["source_tier"] == "local_records" and tl["grade"]["confidence"] == "high"


def test_postmortem_route_exports_md_csv_and_rejects_bad_windows():
    """ASVS V4.1.3 · V5.1.3 · CWE-1284 · WSTG-INPV-01: the authenticated route returns the report as Markdown or CSV downloads with no-store, and refuses a bad window or format with a 400."""
    from fastapi.testclient import TestClient
    import dlp_api_server as api
    t = TestClient(api.app)
    # Act
    md = t.post("/api/postmortem", json={"days": 3, "format": "md", "title": "T"})
    csv_r = t.post("/api/postmortem", json={"days": 3, "format": "csv"})
    bad = t.post("/api/postmortem", json={"days": 999})
    fmt = t.post("/api/postmortem", json={"format": "exe"})
    # Assert
    assert md.status_code == 200 and md.text.startswith("# T") and "attachment" in md.headers["content-disposition"]
    assert csv_r.status_code == 200 and csv_r.text.startswith("time,")
    assert bad.status_code == 400 and fmt.status_code == 400
