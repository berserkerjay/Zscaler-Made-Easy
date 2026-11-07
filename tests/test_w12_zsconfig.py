"""ASVS V4.1.3 · CWE-200 · WSTG-ATHZ-02: SCIM visibility, audit-log full-text search and the approval gate of scheduled sync.

Fakes only: SDK-shaped objects for ZPA, a tmp audit log, the sample tenants of
test_sync_jobs for the scheduler. No network, no real tenant, no clock sleeps."""
from __future__ import annotations

import ast
import inspect
import json
import os
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops
import audit
import change_queue
import dlp_api_server as srv
import scim_view
import security
import sync_jobs
import zpa_reader
from test_sync_jobs import FW_PATH, SCOPE_BODY, _filed_via_api, _job, _named, _team, _wait, _writes, env  # noqa: F401,E402

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "216196257331281920"}


@pytest.fixture(autouse=True)
def _no_pacing(monkeypatch):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)


# ── SCIM visibility ─────────────────────────────────────────────────────
class _Svc:
    def __init__(self, rows, calls):
        self.rows, self.calls = rows, calls

    def _page(self, name, *a, query_params=None):
        self.calls.append(name)
        return (self.rows if (query_params or {}).get("page", "1") == "1" else []), None, None


def _zpa(calls):
    idps = [{"id": "11", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True},
            {"id": "12", "name": "Entra", "enabled": True, "scimEnabled": False}]
    groups = [{"id": "g1", "name": "Finance", "idpId": "11", "modifiedTime": "1700000100", "members": ["secret-person@example.com"]},
              {"id": "g2", "name": "Eng", "idpId": "11", "modifiedTime": "1700000900"}]
    idp = SimpleNamespace(list_idps=lambda query_params=None: _Svc(idps, calls)._page("list_idps", query_params=query_params))
    saml = SimpleNamespace(list_saml_attributes=lambda query_params=None: _Svc([], calls)._page("list_saml", query_params=query_params))
    scim = SimpleNamespace(list_scim_groups=lambda i, query_params=None: _Svc(groups if i == "11" else [], calls)._page("list_scim_groups", query_params=query_params))
    return SimpleNamespace(idp=idp, saml_attributes=saml, scim_groups=scim)


def test_scim_view_lists_idps_groups_and_sync_status_and_only_reads():
    """ASVS V4.1.3 · CWE-200 · WSTG-ATHZ-02: the SCIM view reads IdPs and groups only, shows sync status, and never lists group members."""
    calls = []
    out = scim_view.overview(SimpleNamespace(zpa=_zpa(calls)))
    assert set(calls) == {"list_idps", "list_saml", "list_scim_groups"}
    okta, entra = out["idps"]
    assert okta["status"] == "synced" and okta["groups"] == ["Eng", "Finance"] and okta["group_count"] == 2 and okta["last_change"] == "1700000900"
    assert entra["status"] == "scim_off" and entra["groups"] == []
    assert out["scim_idps"] == 1
    assert "secret-person" not in json.dumps(out)


def test_scim_route_needs_zpa_in_scope_and_reads_nothing_otherwise(monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the SCIM route is 400 before sign-in without ZPA ticked; with it, it returns the view."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: built.append(1) or SimpleNamespace(zpa=_zpa([])))
    c = TestClient(srv.app)
    no = c.post("/api/scim/overview", json=dict(CREDS, from_page=True, scopes=["dlp"]))
    assert no.status_code == 400 and built == []
    ok = c.post("/api/scim/overview", json=dict(CREDS, from_page=True, scopes=["zpa"]))
    assert ok.status_code == 200, ok.text
    assert ok.json()["idps"][0]["name"] == "Okta" and built == [1]


# ── audit-log full-text search ──────────────────────────────────────────
@pytest.fixture
def log(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    audit.record("sync_job.created", actor="alice@example.com", note="Firewall baseline")
    audit.record("operation.applied", actor="bob@example.com", note="firewall rule ADDED", profile="p1")
    audit.record("login", actor="carol@example.com", client_secret="Hunter2-do-not-log")
    return tmp_path


def test_audit_search_requires_every_word_ignores_case_and_returns_newest_first(log):
    """ASVS V7.1.1 · CWE-532 · WSTG-ATHZ-02: every word must match anywhere in the entry, case-insensitively, newest first; secrets are not in the log."""
    r = audit.search("FIREWALL bob")
    assert [e["event"] for e in r["entries"]] == ["operation.applied"]
    assert [e["event"] for e in audit.search("firewall")["entries"]] == ["operation.applied", "sync_job.created"]
    assert audit.search("firewall nomatchword")["entries"] == []
    assert audit.search("", event="login")["entries"][0]["actor"] == "carol@example.com"
    assert audit.search("hunter2")["entries"] == []


def test_audit_search_is_bounded_and_empty_query_matches_nothing(log):
    """ASVS V13.1.1 · CWE-770 · WSTG-BUSL-05: the result count, the words and an empty query are bounded."""
    assert audit.search("")["entries"] == []
    assert len(audit.search("example", limit=1)["entries"]) == 1 and audit.search("example", limit=1)["truncated"] is True
    assert audit.search("example", limit=10**9)["matched"] == 3
    many = " ".join(f"w{i}" for i in range(50))
    assert audit.search(many)["entries"] == []   # only the first words count; none match


def test_audit_search_route_filters_to_what_the_person_may_see_and_answers_nothing_for_empty(log, monkeypatch):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: the route applies the team filter before counting and an empty search matches nothing."""
    c = TestClient(srv.app)
    assert c.get("/api/audit/search").json()["entries"] == []
    assert len(c.get("/api/audit/search", params={"q": "example"}).json()["entries"]) == 3
    monkeypatch.setattr(srv._team, "filter_audit_entries", lambda es: [e for e in es if e.get("profile") == "p1"])
    got = c.get("/api/audit/search", params={"q": "example"}).json()
    assert [e["event"] for e in got["entries"]] == ["operation.applied"]


# ── scheduled sync: read, compare, queue; approval-gated apply ─────────
WRITE_NAMES = ("execute", "begin_apply", "finish_apply", "decide")


def test_the_sync_module_has_no_path_to_a_write():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: sync_jobs (the scheduler's only engine) never references admin_ops.execute or the queue's apply/approve calls."""
    tree = ast.parse(inspect.getsource(sync_jobs))
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not (called & set(WRITE_NAMES)), called & set(WRITE_NAMES)


def test_the_timer_is_off_by_default_and_a_setting_turns_it_on(monkeypatch):
    """ASVS V1.4.1 · CWE-1188: the scheduled sync timer is opt-in."""
    monkeypatch.delenv("DLP_CHECK_SYNC_TIMER", raising=False)
    assert srv._sync_timer_on() is False
    monkeypatch.setenv("DLP_CHECK_SYNC_TIMER", "1")
    assert srv._sync_timer_on() is True


def test_a_scheduled_tick_never_calls_a_write_and_queues_the_plan(monkeypatch, env):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: the tick calls no admin_ops.execute, sends no tenant write, and the plan waits in the Awaiting approval queue."""
    def boom(*a, **k):
        raise AssertionError("the scheduler must never write")
    monkeypatch.setattr(admin_ops, "execute", boom)
    monkeypatch.setattr(change_queue, "begin_apply", boom)
    job = sync_jobs.create_job(_job(interval_hours=4), by="alice@example.com")
    sync_jobs.run_job(job["id"], trigger="schedule", by="", deps=env["deps"])
    assert _writes(env, "tgt") == []
    waiting = sync_jobs.awaiting_approval()
    assert len(waiting) == 1 and waiting[0]["status"] == "pending" and waiting[0]["payload"]["source"] == "sync"
    c = TestClient(srv.app)
    got = c.get("/api/sync-jobs/awaiting-approval").json()
    assert got["count"] == 1 and got["items"][0]["id"] == waiting[0]["id"] and got["items"][0]["plan_hash"] == waiting[0]["plan_hash"]


def test_applying_without_approval_is_refused_and_nothing_is_written(monkeypatch, env):
    """ASVS V4.1.1 · CWE-862 · WSTG-ATHZ-02: a queued sync plan cannot be applied while pending; admin_ops is never reached."""
    called = []
    monkeypatch.setattr(admin_ops, "execute", lambda *a, **k: called.append(1))
    alice, bob, _r = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice)
    monkeypatch.setattr(security, "_write_override", True)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob"})
    assert r.status_code == 409 and called == [] and _writes(env, "tgt") == []
    assert [x["id"] for x in sync_jobs.awaiting_approval()] == [rid]


def test_applying_after_the_drift_changed_marks_it_stale_and_refuses(monkeypatch, env):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: if the target drifted after the plan was queued, the approved plan is marked stale and admin_ops writes nothing."""
    alice, bob, _r = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice)
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200
    _named(env["stores"]["tgt"][0].responses[FW_PATH]["body"], "Allow office traffic")["description"] = "drift after queueing"
    monkeypatch.setattr(security, "_write_override", True)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob"})
    _wait(r.json()["job_id"])
    assert change_queue.get(rid)["status"] == "stale"
    assert [w for w in _writes(env, "tgt") if w[0] != "GET"] == []
    assert sync_jobs.awaiting_approval() == []   # a stale plan no longer waits


def test_an_approved_plan_with_a_matching_hash_goes_through_admin_ops(monkeypatch, env):
    """ASVS V4.1.1 · CWE-285 · WSTG-BUSL-06: an approved plan is applied by admin_ops.execute with the queued plan hash and the named assessor (mocked)."""
    seen = {}

    def fake_execute(client, operation, *, plan_hash, **kw):
        seen.update(plan_hash=plan_hash, assessor=kw.get("assessor"), writes=kw.get("writes_enabled"), type=operation.get("type"))
        return {"status": "applied", "items": [], "verification": {"confirmed": 1}}
    monkeypatch.setattr(admin_ops, "execute", fake_execute)
    alice, bob, _r = _team(monkeypatch)
    _jid, rid = _filed_via_api(alice)
    queued_hash = change_queue.get(rid)["plan_hash"]
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200
    monkeypatch.setattr(security, "_write_override", True)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={"profile_id": "tgt", **SCOPE_BODY, "confirm": "I UNDERSTAND", "assessor": "Bob Reviewer"})
    assert r.status_code == 200, r.text
    _wait(r.json()["job_id"])
    assert seen["plan_hash"] == queued_hash and seen["assessor"] and seen["writes"] is True and seen["type"] == "zia_rules_csv"
    assert change_queue.get(rid)["status"] == "applied"
