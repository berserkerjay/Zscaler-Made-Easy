"""The Client Connector fleet Excel export (zcc_fleet.export_xlsx and
GET /api/zcc/fleet/{job}/export?format=xlsx): devices, versions, operating
systems and stale devices, the counts-only form that names nobody, the UI
token gate, and that it only exists for a run started with ZCC in scope.
Fixtures come from test_zcc_fleet."""
from __future__ import annotations

import zcc_fleet as zf
from test_xlsx_writer import read_workbook
from test_zcc_fleet import CREDS, NAMES, ZCC_SCOPE, SDK, _api, _follow, full_run

XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def _all_text(wb):
    return "\n".join(str(c) for rows in wb.values() for r in rows for c in r if c is not None)


def test_the_workbook_has_devices_versions_os_and_stale_devices():
    r = full_run()
    stem, data = zf.export_xlsx(r, False)
    wb = read_workbook(data)
    assert stem == "zcc_fleet"
    assert list(wb) == ["Summary", "Versions", "Operating systems", "Stale devices", "Devices", "Alerts", "Plan"]
    k = r["kpis"]
    versions = {(row[0], row[1]): row[2] for row in wb["Versions"][1:]}
    assert versions == {(p, v): str(n) for p, vs in k["versions"].items() for v, n in vs.items()}
    assert sum(int(row[2]) for row in wb["Operating systems"][1:] if len(row) > 2) == k["registered"]
    ghosts = r["alerts"]["ghost"]["rows"]
    stale = wb["Stale devices"]
    hosts = {row[1] for row in stale[1:] if len(row) > 1}
    assert stale[0][:2] == ["User", "Host name"] and hosts == {d["hostname"] for d in ghosts}
    assert "DAVE-LT" in hosts and "CAROL-LT" not in hosts, "31 days + 1 min, not 31 days"
    assert any("Ghost devices" in (row[0] or "") for row in stale)
    assert len(wb["Devices"]) == len(r["devices"]) + 1 and wb["Devices"][0][0] == "User"
    assert len(wb["Plan"]) == len(r["plan"]) + 1
    assert {row[0] for row in wb["Alerts"][1:]} == {r["alerts"][a]["label"] for a in r["alert_order"]}
    summary = {(row[0], row[1]): row[2] for row in wb["Summary"][1:]}
    assert summary[("Devices", "Registered")] == str(k["registered"])


def test_counts_only_names_no_user_or_device():
    r = full_run()
    stem, data = zf.export_xlsx(r, True)
    wb = read_workbook(data)
    assert stem == "zcc_fleet_counts"
    text = _all_text(wb)
    assert not [n for n in NAMES if n in text], [n for n in NAMES if n in text]
    assert wb["Stale devices"][0] == ["Platform", "Stale devices"]
    assert "left out" in wb["Devices"][1][0]


def test_configuration_only_says_unknown_not_zero():
    r = full_run(sdk=SDK(list_error="HTTP 403 Forbidden"))
    wb = read_workbook(zf.export_xlsx(r, False)[1])
    assert "unknown, not zero" in wb["Versions"][1][0] and "unknown, not zero" in wb["Operating systems"][1][0]
    assert "Not evaluated" in _all_text({"s": wb["Stale devices"]})


def test_formula_text_is_neutralised():
    r = full_run()
    evil = dict(r, plan=[dict(r["plan"][0], title="=HYPERLINK(1)")])
    wb = read_workbook(zf.export_xlsx(evil, False)[1])
    assert "'=HYPERLINK(1)" in [c for row in wb["Plan"] for c in row]


def test_the_endpoint_serves_the_workbook_behind_the_ui_token(monkeypatch):
    import dlp_api_server as srv
    t, built, _raw = _api(monkeypatch)
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, **ZCC_SCOPE))
    jid = _follow(t, r.json()["job_id"])["job_id"]
    x = t.get(f"/api/zcc/fleet/{jid}/export?format=xlsx")
    assert x.status_code == 200 and x.headers["content-type"] == XLSX and ".xlsx" in x.headers["content-disposition"]
    assert x.content[:2] == b"PK" and "ALICE-LT" in _all_text(read_workbook(x.content))
    c = t.get(f"/api/zcc/fleet/{jid}/export?format=xlsx&counts_only=true")
    assert c.status_code == 200 and "_counts_" in c.headers["content-disposition"]
    assert not [n for n in NAMES if n in _all_text(read_workbook(c.content))]
    assert t.get("/api/zcc/fleet/nope/export?format=xlsx").status_code == 404
    monkeypatch.setattr(srv._security, "ui_auth_enabled", lambda: True)
    assert t.get(f"/api/zcc/fleet/{jid}/export?format=xlsx").status_code == 401
    ok = t.get(f"/api/zcc/fleet/{jid}/export?format=xlsx", headers={"X-DLP-Check-Token": srv._security.ui_token()})
    assert ok.status_code == 200


def test_no_workbook_without_zcc_in_scope(monkeypatch):
    t, built, _raw = _api(monkeypatch)
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, scopes=["dlp"], channels={}, from_page=True))
    assert r.status_code == 400 and not built   # no run, so nothing to export


def test_the_page_has_the_excel_button():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = open(os.path.join(root, "static", "report_fleet.html"), encoding="utf-8").read()
    js = open(os.path.join(root, "static", "zcc_fleet.js"), encoding="utf-8").read()
    assert 'id="zfExpXlsx" disabled aria-disabled="true"' in html and "Everything (Excel)" in html
    assert "exportCsv('all', 'xlsx')" in js and "&format=${fmt}" in js
