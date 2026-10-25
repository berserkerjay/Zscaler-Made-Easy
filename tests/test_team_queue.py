"""The team change queue (change_queue.py + /api/change-queue/*): change
requests filed from a preflight, a removal preview or a recipe preview,
four-eyes approval by a different writer, apply through the app's existing
apply path with the plan re-checked (a changed tenant marks the request
stale and writes nothing), withdraw and reject, the audit trail with
actors, a store that two writers can share, and the page conventions.

No real tenant: the deploy tests run the real planner and apply path
(pack_deploy) against the fake ZIA from test_pack_deploy; the removal and
recipe tests fake the tenant calls underneath the existing paths."""
from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
import threading
import time

import pytest
from fastapi.testclient import TestClient

import change_queue
import dlp_api_server as srv
import pack_deploy
import pack_jobs
import pack_removal
import remediation
import security
import sso
from test_pack_deploy import FakeClient, PREDEF_SSN, Obj, _dict, _engine, _policy, write_pack

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
CREDS = {"cloud": "production", "vanity_domain": "acme", "client_id": "cid-12345", "client_secret": "S3cr3t-never-stored",
         "auth_method": "oneapi", "assessor": "Alex Assessor"}
WRITERS = "dlp-admins"


# ── fixtures ────────────────────────────────────────────────────────────
@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLPCHECK_CHANGE_QUEUE_FILE", str(tmp_path / "change_requests.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.delenv("DLP_CHECK_FOUR_EYES", raising=False)
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setattr(security, "_write_override", None)
    srv._CQ_PLANS.clear()
    yield
    srv._CQ_PLANS.clear()


def _sso_on(monkeypatch, writers=WRITERS):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "https://idp.example.test/oauth2/default")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_ID", "client-123")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("ZSCALER_SSO_REDIRECT_URL", "http://testserver/api/auth/sso/callback")
    if writers:
        monkeypatch.setenv("ZSCALER_SSO_WRITERS", writers)
    else:
        monkeypatch.delenv("ZSCALER_SSO_WRITERS", raising=False)


def _person(email, groups=()):
    """A TestClient signed in (a real server-side SSO session) as `email`."""
    sid = sso.create_session({"sub": email, "email": email, "groups": list(groups)})
    c = TestClient(srv.app)
    c.cookies.set(security.SSO_SESSION_COOKIE, sid)
    return c


def _team(monkeypatch):
    _sso_on(monkeypatch)
    return (_person("alice@example.com", ["dlp-admins"]), _person("bob@example.com", ["dlp-admins"]),
            _person("reader@example.com", ["dlp-readers"]))


@pytest.fixture
def tenant(monkeypatch, tmp_path):
    """A fake ZIA tenant and one pack that creates a dictionary, an engine
    and a rule in it; the server builds its SDK client from the fake."""
    client = FakeClient(dicts=[PREDEF_SSN])
    pack = write_pack(tmp_path, "teamq_pack", dicts=[_dict("TQ Dict")], engines=[_engine("TQ Engine", "(D:TQ Dict)")],
                      policies=[_policy("TQ-Monitor", ["TQ Engine"])], meta={"name": "Team queue pack", "confidence_tweaks": []})
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [pack for i in ids if i == "teamq_pack"] or (_ for _ in ()).throw(
        srv.HTTPException(status_code=404, detail="Unknown pack")))
    return client


def _preflight(c):
    r = c.post("/api/dlp-packs/preflight", json={"pack_ids": ["teamq_pack"], **CREDS})
    assert r.status_code == 200, r.text
    return r.json()


def _file_deploy(c, rep, **extra):
    return c.post("/api/change-queue/deploy", json={"pack_ids": ["teamq_pack"], "plan_hash": rep["plan_hash"], **CREDS, **extra})


def _wait(job_id, timeout=30):
    end = time.time() + timeout
    while time.time() < end:
        j = pack_jobs.get(job_id)
        if j is not None and j.status != "running":
            return j
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def _audit_lines():
    p = os.environ["DLP_CHECK_AUDIT"]
    if not os.path.exists(p):
        return []
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()]


def _steps():
    return [(e["action"], e["actor"]) for e in _audit_lines() if e.get("event") == "change_request"]


# ── filing ──────────────────────────────────────────────────────────────
def test_filing_a_preflight_keeps_the_servers_plan_and_names_the_requester_from_the_session(monkeypatch, tenant):
    alice, bob, reader = _team(monkeypatch)
    rep = _preflight(reader)
    calls = []
    real = pack_deploy.preflight
    monkeypatch.setattr(pack_deploy, "preflight", lambda *a, **k: calls.append(1) or real(*a, **k))
    # A non-writer may file; a name the page sends is ignored.
    r = _file_deploy(reader, rep, title="Roll out the TQ pack", note="please review", by="mallory@example.com", requested_by="mallory")
    assert r.status_code == 200, r.text
    rec = r.json()["request"]
    assert calls == [], "the preflight this server just ran is filed without reading the tenant again"
    assert rec["requested_by"] == "reader@example.com" and rec["status"] == "pending" and rec["kind"] == "pack_deploy"
    assert rec["plan_hash"] == rep["plan_hash"] and rec["tenant"] == "acme" and rec["tenant_label"] == "acme (production)"
    names = {(i["kind"], i["name"], i["status"]) for i in rec["items"]}
    assert ("dictionary", "TQ Dict", "create") in names and ("engine", "TQ Engine", "create") in names and ("policy", "TQ-Monitor", "create") in names
    assert rec["summary"].get("create") == 3 and rec["comments"][0]["text"] == "please review"
    assert rec["payload"]["pack_ids"] == ["teamq_pack"]
    # The same plan cannot be queued twice while it is open.
    again = _file_deploy(alice, rep)
    assert again.status_code == 409 and rec["id"] in again.json()["detail"]
    # No secret is stored; the store is owner-only.
    path = os.environ["DLPCHECK_CHANGE_QUEUE_FILE"]
    raw = open(path, encoding="utf-8").read()
    assert CREDS["client_secret"] not in raw and CREDS["client_id"] not in raw
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(path).st_mode) == 0o600


def test_filing_without_a_cached_preflight_re_reads_and_refuses_a_hash_that_does_not_match(monkeypatch, tenant):
    alice, _bob, _reader = _team(monkeypatch)
    rep = _preflight(alice)
    srv._CQ_PLANS.clear()                     # e.g. the server restarted between preflight and filing
    assert _file_deploy(alice, rep).status_code == 200            # re-planned: same hash
    srv._CQ_PLANS.clear()
    bad = _file_deploy(alice, {"plan_hash": "0" * 64})
    assert bad.status_code == 409 and "run the preflight again" in bad.json()["detail"]
    assert alice.post("/api/change-queue/deploy", json={"pack_ids": ["teamq_pack"], **CREDS}).status_code == 400   # no plan_hash


# ── four-eyes ───────────────────────────────────────────────────────────
def test_four_eyes_refuses_the_requester_and_lets_another_writer_approve(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    rid = _file_deploy(alice, _preflight(alice)).json()["request"]["id"]
    own = alice.post(f"/api/change-queue/{rid}/approve", json={"comment": "looks fine", "by": "bob@example.com"})
    assert own.status_code == 403 and "four-eyes" in own.json()["detail"] and "alice@example.com" in own.json()["detail"]
    assert change_queue.get(rid)["status"] == "pending"
    ok = bob.post(f"/api/change-queue/{rid}/approve", json={"comment": "checked with the customer"})
    assert ok.status_code == 200, ok.text
    rec = ok.json()["request"]
    assert rec["status"] == "approved" and rec["decided_by"] == "bob@example.com"
    assert rec["comments"][-1] == {**rec["comments"][-1], "by": "bob@example.com", "text": "checked with the customer"}
    again = bob.post(f"/api/change-queue/{rid}/approve", json={})
    assert again.status_code == 409   # only a pending request is decided


def test_four_eyes_off_lets_a_single_person_approve_their_own(monkeypatch, tenant):
    alice, _bob, _reader = _team(monkeypatch)
    monkeypatch.setenv("DLP_CHECK_FOUR_EYES", "0")
    rid = _file_deploy(alice, _preflight(alice)).json()["request"]["id"]
    r = alice.post(f"/api/change-queue/{rid}/approve", json={})
    assert r.status_code == 200 and r.json()["request"]["decided_by"] == "alice@example.com"
    assert alice.get("/api/change-queue").json()["settings"]["four_eyes"] is False


def test_without_sso_four_eyes_says_it_needs_sso_and_the_setting_turns_it_off(monkeypatch, tenant):
    c = TestClient(srv.app)          # conftest: UI token gate off, SSO off: everyone is "local, no UI token"
    lst = c.get("/api/change-queue").json()
    assert lst["settings"]["four_eyes"] is True and lst["settings"]["sso"] is False and "needs SSO" in lst["settings"]["note"]
    assert lst["viewer"]["actor"] == security.LOCAL_NO_TOKEN_ACTOR
    rid = _file_deploy(c, _preflight(c)).json()["request"]["id"]
    r = c.post(f"/api/change-queue/{rid}/approve", json={})
    assert r.status_code == 403 and "DLP_CHECK_FOUR_EYES=0" in r.json()["detail"] and "SSO" in r.json()["detail"]
    monkeypatch.setenv("DLP_CHECK_FOUR_EYES", "0")
    assert c.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200


def test_a_non_writer_may_file_and_comment_but_not_approve_reject_or_apply(monkeypatch, tenant):
    alice, _bob, reader = _team(monkeypatch)
    rid = _file_deploy(alice, _preflight(alice)).json()["request"]["id"]
    for act in ("approve", "reject"):
        r = reader.post(f"/api/change-queue/{rid}/{act}", json={"comment": "no"})
        assert r.status_code == 403 and "ZSCALER_SSO_WRITERS" in r.json()["detail"], act
    r = reader.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "I UNDERSTAND"})
    assert r.status_code == 403 and "ZSCALER_SSO_WRITERS" in r.json()["detail"]
    assert reader.post(f"/api/change-queue/{rid}/comment", json={"comment": "what about endpoint?"}).status_code == 200
    v = reader.get("/api/change-queue").json()["viewer"]
    assert v == {"actor": "reader@example.com", "may_write": False, "sso": True}
    assert change_queue.get(rid)["status"] == "pending"


def test_state_changing_calls_keep_the_origin_check(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    rid = _file_deploy(alice, _preflight(alice)).json()["request"]["id"]
    evil = {"Origin": "http://evil.example"}
    for path in (f"/api/change-queue/{rid}/approve", f"/api/change-queue/{rid}/reject", f"/api/change-queue/{rid}/withdraw",
                 f"/api/change-queue/{rid}/comment", f"/api/change-queue/{rid}/apply", "/api/change-queue/deploy",
                 "/api/change-queue/removal", "/api/change-queue/recipe"):
        r = bob.post(path, json={"comment": "x"}, headers=evil)
        assert r.status_code == 403 and "Origin not allowed" in r.json()["detail"], path
    assert change_queue.get(rid)["status"] == "pending"


# ── withdraw and reject ─────────────────────────────────────────────────
def test_withdraw_is_the_requesters_and_reject_needs_a_comment(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    rep = _preflight(alice)
    rid = _file_deploy(alice, rep).json()["request"]["id"]
    r = bob.post(f"/api/change-queue/{rid}/withdraw", json={})
    assert r.status_code == 403 and "only the requester" in r.json()["detail"]
    w = alice.post(f"/api/change-queue/{rid}/withdraw", json={"comment": "wrong channel"})
    assert w.status_code == 200 and w.json()["request"]["status"] == "withdrawn"
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 409
    # Withdrawn frees the plan to be filed again; a writer rejects it with a reason.
    rid2 = _file_deploy(alice, rep).json()["request"]["id"]
    assert bob.post(f"/api/change-queue/{rid2}/reject", json={"comment": ""}).status_code == 400
    rj = bob.post(f"/api/change-queue/{rid2}/reject", json={"comment": "deploy Web first"})
    assert rj.status_code == 200 and rj.json()["request"]["status"] == "rejected" and rj.json()["request"]["decided_by"] == "bob@example.com"
    assert alice.post(f"/api/change-queue/{rid2}/withdraw", json={}).status_code == 409


# ── apply ───────────────────────────────────────────────────────────────
def _approved(monkeypatch, tenant_client=None):
    alice, bob, reader = _team(monkeypatch)
    rid = _file_deploy(alice, _preflight(alice)).json()["request"]["id"]
    assert bob.post(f"/api/change-queue/{rid}/approve", json={}).status_code == 200
    return alice, bob, reader, rid


def test_apply_needs_write_mode_the_typed_confirmation_and_the_same_tenant(monkeypatch, tenant):
    alice, bob, _reader, rid = _approved(monkeypatch)
    body = {**CREDS, "confirm": "I UNDERSTAND"}
    r = bob.post(f"/api/change-queue/{rid}/apply", json=body)
    assert r.status_code == 403 and "ENABLE_WRITE_ACTIONS" in r.json()["detail"]
    monkeypatch.setattr(security, "_write_override", True)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "yes"})
    assert r.status_code == 400 and "I UNDERSTAND" in r.json()["detail"]
    r = bob.post(f"/api/change-queue/{rid}/apply", json={**body, "vanity_domain": "other"})
    assert r.status_code == 409 and "Switch tenant" in r.json()["detail"]
    assert tenant.zia.dlp_dictionary.items == [PREDEF_SSN] or all(getattr(d, "name", "") != "TQ Dict" for d in tenant.zia.dlp_dictionary.items)
    assert change_queue.get(rid)["status"] == "approved"


def test_apply_runs_the_existing_deploy_path_and_records_the_result(monkeypatch, tenant):
    alice, bob, _reader, rid = _approved(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    seen = []
    real_run, real_apply = srv._run_apply, pack_deploy.apply
    monkeypatch.setattr(srv, "_run_apply", lambda *a, **k: seen.append(("_run_apply", a[2].plan_hash, a[2].pack_ids)) or real_run(*a, **k))
    monkeypatch.setattr(pack_deploy, "apply", lambda *a, **k: seen.append(("pack_deploy.apply", k["plan_hash"])) or real_apply(*a, **{**k, "settle_seconds": 0}))
    r = alice.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "i understand"})   # the requester may apply once approved
    assert r.status_code == 200, r.text
    job = _wait(r.json()["job_id"])
    assert job.status == "done", (job.error, job.logs)
    plan_hash = change_queue.get(rid)["plan_hash"]
    assert ("_run_apply", plan_hash, ["teamq_pack"]) in seen and ("pack_deploy.apply", plan_hash) in seen
    rec = change_queue.get(rid)
    assert rec["status"] == "applied" and rec["applied_by"] == "alice@example.com" and rec["result"]["status"] == "applied"
    assert rec["result"].get("deployment_id"), "the deployment is recorded for undo, as from Deploy policy packs"
    assert "applying" not in rec
    names = {getattr(d, "name", None) for d in tenant.zia.dlp_dictionary.items}
    assert "TQ Dict" in names
    assert job.result["change_request"]["status"] == "applied"
    # Applied is final.
    assert alice.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "I UNDERSTAND"}).status_code == 409


def test_a_tenant_that_changed_since_the_request_marks_it_stale_and_writes_nothing(monkeypatch, tenant):
    alice, bob, _reader, rid = _approved(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    # Someone creates the pack's dictionary by hand meanwhile: the plan changes.
    tenant.zia.dlp_dictionary.items.append(Obj(id=777, name="TQ Dict", custom=True, phrases=[], patterns=[],
                                               custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", description=""))
    before_engines = list(tenant.zia.dlp_engine.items)
    r = bob.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "I UNDERSTAND"})
    assert r.status_code == 200, r.text
    job = _wait(r.json()["job_id"])
    rec = change_queue.get(rid)
    assert rec["status"] == "stale" and rec["result"]["status"] == "plan_changed"
    assert any("stale: the tenant changed since it was requested; request again" in line for line in job.logs)
    assert tenant.zia.dlp_engine.items == before_engines and not tenant.zia.dlp_web_rules.items, "nothing written"
    assert ("stale", "bob@example.com") in _steps()


def test_every_step_is_audited_with_its_actor(monkeypatch, tenant):
    alice, bob, _reader, rid = _approved(monkeypatch)
    alice.post(f"/api/change-queue/{rid}/comment", json={"comment": "ready when you are"})
    steps = _steps()
    assert ("filed", "alice@example.com") in steps and ("approved", "bob@example.com") in steps and ("commented", "alice@example.com") in steps
    refused = [e for e in _audit_lines() if e.get("path") == f"/api/change-queue/{rid}/approve"]
    assert refused and all(e["actor"] == "bob@example.com" for e in refused), "the HTTP call is in the log too (AuditMiddleware)"
    entry = next(e for e in _audit_lines() if e.get("event") == "change_request" and e.get("action") == "approved")
    assert entry["request"] == rid and entry["requested_by"] == "alice@example.com" and entry["four_eyes"] is True
    assert CREDS["client_secret"] not in open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()


# ── removal and recipe kinds ────────────────────────────────────────────
def test_a_removal_plan_is_filed_from_its_preview_and_applied_through_the_removal_path(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    plan = {"status": "ready", "items": [{"kind": "policy", "channel": "web", "id": 5, "name": "Old rule", "status": "remove"},
                                         {"kind": "engine", "channel": None, "id": 9, "name": "Shared engine", "status": "keep", "keep": "still used"}],
            "plan_hash": "abcd1234abcd1234", "warnings": [], "blockers": []}
    monkeypatch.setattr(pack_removal, "plan_removal_selected", lambda client, sel, **k: dict(plan))
    removed = []
    monkeypatch.setattr(pack_removal, "remove_selected", lambda client, sel, **k: removed.append((sel, k["plan_hash"])) or
                        {"status": "removed", "summary": {"deleted": 1}, "results": [], "complete": True})
    rules = [{"channel": "web", "id": 5}]
    prev = alice.post("/api/dlp-packs/removal/preflight", json={"pack_ids": [], "rules": rules, **CREDS})
    assert prev.status_code == 200
    r = alice.post("/api/change-queue/removal", json={"rules": rules, "plan_hash": plan["plan_hash"], **CREDS})
    assert r.status_code == 200, r.text
    rec = r.json()["request"]
    assert rec["kind"] == "pack_removal" and rec["summary"] == {"remove": 1, "keep": 1}
    assert bob.post(f"/api/change-queue/{rec['id']}/approve", json={}).status_code == 200
    ap = bob.post(f"/api/change-queue/{rec['id']}/apply", json={**CREDS, "confirm": "I UNDERSTAND"})
    assert ap.status_code == 200, ap.text
    _wait(ap.json()["job_id"])
    assert removed == [([{"kind": "policy", "channel": "web", "id": "5"}], plan["plan_hash"])]
    assert change_queue.get(rec["id"])["status"] == "applied"


def test_a_stale_removal_plan_is_marked_stale(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    monkeypatch.setattr(pack_removal, "plan_removal_selected", lambda client, sel, **k: {
        "status": "ready", "items": [{"kind": "policy", "channel": "web", "id": 5, "name": "Old rule", "status": "remove"}],
        "plan_hash": "feedfeedfeedfeed", "warnings": [], "blockers": []})
    monkeypatch.setattr(pack_removal, "remove_selected", lambda client, sel, **k: {"status": "stale", "blockers": ["changed"], "results": []})
    rules = [{"channel": "web", "id": 5}]
    alice.post("/api/dlp-packs/removal/preflight", json={"pack_ids": [], "rules": rules, **CREDS})
    rid = alice.post("/api/change-queue/removal", json={"rules": rules, "plan_hash": "feedfeedfeedfeed", **CREDS}).json()["request"]["id"]
    bob.post(f"/api/change-queue/{rid}/approve", json={})
    _wait(bob.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "I UNDERSTAND"}).json()["job_id"])
    assert change_queue.get(rid)["status"] == "stale"


class _FakeRaw:
    def __init__(self):
        self.sent = []

    def post(self, endpoint, body):
        self.sent.append(("POST", endpoint, body))
        return {"id": 42}, 200


RECIPE = {"check_id": "FW-01", "criteria": {"name": "Default_deny", "description": "Deny by default", "action": "BLOCK_DROP",
                                            "state": "ENABLED", "order": "1", "rank": "7"}}


def test_a_fix_recipe_is_filed_from_its_preview_and_applied_through_remediation_execute(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    raw = _FakeRaw()
    monkeypatch.setattr(srv, "_build_client", lambda req: raw)
    calls = []
    real = remediation.execute
    monkeypatch.setattr(remediation, "execute", lambda *a, **k: calls.append((a[1:], k)) or real(*a, **k))
    r = alice.post("/api/change-queue/recipe", json={**RECIPE, **CREDS})
    assert r.status_code == 200, r.text
    rec = r.json()["request"]
    assert rec["kind"] == "fix_recipe" and rec["items"][0]["endpoint"] == "/zia/firewallFilteringRules" and rec["items"][0]["body"]["order"] == 1
    assert raw.sent == [], "filing sends nothing"
    assert alice.post("/api/change-queue/recipe", json={"check_id": "FW-01", "criteria": {}, **CREDS}).status_code == 400
    bob.post(f"/api/change-queue/{rec['id']}/approve", json={})
    _wait(bob.post(f"/api/change-queue/{rec['id']}/apply", json={**CREDS, "confirm": "I UNDERSTAND"}).json()["job_id"])
    assert calls == [(("FW-01", RECIPE["criteria"]), {"dry_run": False})]
    assert raw.sent and raw.sent[0][1] == "/zia/firewallFilteringRules"
    done = change_queue.get(rec["id"])
    assert done["status"] == "applied" and done["result"]["http_status"] == 200


def test_a_recipe_that_changed_since_it_was_requested_is_stale_and_sends_nothing(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    monkeypatch.setattr(security, "_write_override", True)
    raw = _FakeRaw()
    monkeypatch.setattr(srv, "_build_client", lambda req: raw)
    rid = alice.post("/api/change-queue/recipe", json={**RECIPE, **CREDS}).json()["request"]["id"]
    bob.post(f"/api/change-queue/{rid}/approve", json={})
    recipe = remediation.get_recipe("FW-01")
    monkeypatch.setitem(recipe, "endpoint", "/zia/firewallFilteringRules/v2")
    _wait(bob.post(f"/api/change-queue/{rid}/apply", json={**CREDS, "confirm": "I UNDERSTAND"}).json()["job_id"])
    assert change_queue.get(rid)["status"] == "stale" and raw.sent == []


# ── the store ───────────────────────────────────────────────────────────
def _file_many(n, who):
    for i in range(n):
        change_queue.file_request(kind="fix_recipe", tenant="acme", tenant_label="acme (production)", title=f"{who} {i}", summary={"calls": 1},
                                  items=[], plan_hash=f"{who}-{i}", requested_by=who, payload={})


def test_two_writers_never_lose_each_others_requests(tmp_path):
    # Two threads in this process ...
    ts = [threading.Thread(target=_file_many, args=(25, f"t{k}")) for k in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    # ... and two server processes on the same store at once.
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import change_queue\n"
            "for i in range(20):\n"
            "    change_queue.file_request(kind='fix_recipe', tenant='acme', tenant_label='acme', title=str(i), summary={}, items=[],\n"
            "                              plan_hash=sys.argv[2] + str(i), requested_by=sys.argv[2], payload={})\n")
    env = dict(os.environ)
    procs = [subprocess.Popen([sys.executable, "-c", code, ROOT, f"p{k}-"], env=env) for k in range(2)]
    assert all(p.wait(timeout=60) == 0 for p in procs)
    data = json.load(open(os.environ["DLPCHECK_CHANGE_QUEUE_FILE"], encoding="utf-8"))
    assert len(data["requests"]) == 2 * 25 + 2 * 20
    # Concurrent decisions on one request: exactly one wins.
    rec = change_queue.file_request(kind="fix_recipe", tenant="acme", tenant_label="acme", title="race", summary={}, items=[],
                                    plan_hash="race", requested_by="alice@example.com", payload={})
    wins, errors = [], []

    def decide(who, what):
        try:
            change_queue.decide(rec["id"], what, by=who, comment="x")
            wins.append(who)
        except change_queue.QueueError as e:
            errors.append(str(e))
    ts = [threading.Thread(target=decide, args=(f"w{k}@example.com", "approve" if k % 2 else "reject")) for k in range(6)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert len(wins) == 1 and len(errors) == 5
    assert not [n for n in os.listdir(os.path.dirname(os.environ["DLPCHECK_CHANGE_QUEUE_FILE"])) if n.endswith(".tmp")]


def test_exports_say_the_same_thing_as_rows(monkeypatch, tenant):
    alice, bob, _reader = _team(monkeypatch)
    rid = _file_deploy(alice, _preflight(alice), note="first").json()["request"]["id"]
    j = alice.get("/api/change-queue/export?format=json")
    assert j.status_code == 200 and "attachment" in j.headers["content-disposition"]
    body = j.json()
    assert body["items"][0]["id"] == rid and body["rows"][0]["id"] == rid and set(body["rows"][0]) == set(change_queue.ROW_COLUMNS)
    md = alice.get("/api/change-queue/export?format=markdown")
    assert md.status_code == 200 and md.headers["content-type"].startswith("text/markdown")
    assert f"Id: {rid}" in md.text and "Requested by alice@example.com" in md.text and "TQ Dict" in md.text and "first" in md.text
    assert alice.get("/api/change-queue?tenant=other").json()["items"] == []


# ── page conventions ────────────────────────────────────────────────────
def _read(name):
    return open(os.path.join(STATIC, name), encoding="utf-8").read()


def test_the_change_queue_page_follows_the_report_page_conventions():
    c = TestClient(srv.app)
    r = c.get("/report/queue")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html
    assert '<a class="rp-btn" href="/">← Back to the assessment</a>' in html and '<main class="rp-card"' in html
    scripts = re.findall(r'<script src="/static/([^"]+)"></script>', html)
    assert scripts == ["icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js"]
    assert 'role="tablist"' in html and html.count('role="tab"') == 3 and 'role="tabpanel"' in html
    assert 'role="status"' in html and 'aria-live' in html and '<th scope="col">' in html and "prefers-reduced-motion" in html
    for needle in ("Pending", "Approved", "History", 'data-act="approve"', 'data-act="reject"', 'data-act="apply"', 'data-act="withdraw"',
                   "/api/change-queue/export?format=json", "/api/change-queue/export?format=markdown", "window.queueRows", "dlg.phrase({ title: 'Apply this approved request?'"):
        assert needle in html, needle
    style = html[html.index("<style>"):html.index("</style>")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style) and "gradient" not in style and "box-shadow" not in style
    js = _read("explain.js")
    assert "X.queue = {" in js and js.index("X.queue = {") < js.index("X.advanced = {") and "group: 'Close the gaps', name: 'Change queue'" in js
    assert "'/report/queue': 'queue'" in js and "'remediate', 'queue'," in js
    index = _read("index.html")
    btn = index.index('onclick="openQueueTab()"')
    assert btn < index.index('onclick="openAdvancedTab()"') and "Change queue" in index[btn:index.index('onclick="openAdvancedTab()"')]
    assert "function openQueueTab()" in index and "window.open('/report/queue'" in index
    # The two "Request approval" buttons, beside the existing apply actions.
    dz = _read("deploy_studio.js")
    review = dz.split("function _dzRenderReview()")[1].split("function _dzRequestedHtml")[0]
    assert review.index('id="dzRequestApproval"') < review.rindex("Review &amp; approve") and ">Request approval</button>" in review
    assert "'/api/change-queue/deploy'" in dz and "'/api/change-queue/removal'" in dz
    wiz = index[index.index("function _ensureWizardModal()"):]
    assert wiz.index('id="wizardApplyBtn"') < wiz.index('id="wizardRequestBtn"') and "fetch('/api/change-queue/recipe'" in index
    assert "_wizardPlanReady(true)" in index and "wizardApplyBtn').style.display = 'inline-flex'" not in index


def test_the_module_is_packaged_and_the_store_is_git_ignored():
    pyproject = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert '"change_queue"' in pyproject
    gi = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
    assert "change_requests.json" in gi
