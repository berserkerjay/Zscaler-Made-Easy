"""The audit log is JSON Lines (one structured record per line) and exports as JSONL or CSV: spreadsheet-safe cells,
no secret, an authenticated no-store download. Local only."""
from __future__ import annotations

import csv
import io
import json

import pytest
from fastapi.testclient import TestClient

import audit
import dlp_api_server as srv


@pytest.fixture
def log(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_STORE_ENCRYPTION", "0")
    return tmp_path / "audit.log"


def test_the_log_is_one_compact_json_object_per_line(log):
    """ASVS V7.1.3 · CWE-778 · WSTG-CONF-05: every audit record is one JSON object on its own line with the time, event and actor, and a secret in a field is redacted."""
    audit.record("demo", actor="alice", api_key="sk-LIVE-SECRET-1234", note="x")
    audit.record("demo2", actor="bob")
    lines = log.read_text().splitlines()
    assert len(lines) == 2
    recs = [json.loads(ln) for ln in lines]
    assert recs[0]["event"] == "demo" and recs[0]["actor"] == "alice" and "at" in recs[0]
    assert "sk-LIVE-SECRET-1234" not in log.read_text()


def test_csv_export_is_spreadsheet_safe_and_keeps_the_extra_fields_as_json():
    """ASVS V5.2.2 · CWE-1236: a formula-looking value is neutralised in the CSV, the fixed columns are present and the other fields ride in detail."""
    rows = [{"at": "2026-11-07T10:00:00+0000", "event": "api", "actor": "=HYPERLINK(\"http://x\")", "method": "POST", "path": "/api/x", "status": 200, "extra": 1}]
    out = list(csv.reader(io.StringIO(audit.export(rows, "csv"))))
    assert out[0] == list(audit.EXPORT_COLUMNS) and out[1][0] == "2026-11-07T10:00:00+0000"
    assert out[1][2].startswith("'") and json.loads(out[1][-1]) == {"extra": 1}
    assert audit.export(rows, "jsonl").count("\n") == 1 and json.loads(audit.export(rows, "jsonl")) == rows[0]
    with pytest.raises(ValueError):
        audit.export(rows, "xml")


def test_the_export_route_downloads_the_log_without_caching(log):
    """ASVS V4.1.1 · V8.3.4 · CWE-524 · WSTG-ATHZ-02: the export is an authenticated no-store attachment in either format, a bad format is a 400."""
    audit.record("demo", actor="alice", path="/p")
    c = TestClient(srv.app)
    j = c.get("/api/audit/export", params={"format": "jsonl"})
    assert j.status_code == 200 and j.headers["cache-control"] == "no-store" and "attachment" in j.headers["content-disposition"]
    assert any(json.loads(ln)["event"] == "demo" for ln in j.text.splitlines())
    k = c.get("/api/audit/export", params={"format": "csv"})
    assert k.status_code == 200 and k.text.splitlines()[0].startswith("at,event,actor")
    assert c.get("/api/audit/export", params={"format": "xml"}).status_code == 400
