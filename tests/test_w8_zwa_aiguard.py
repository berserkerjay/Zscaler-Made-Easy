"""Wave 8, zwa-aiguard: Workflow Automation incidents in depth (zwa_incidents.py,
ops_zwa.py), AI Guard depth (ai_guard.py inventory and Test a prompt), the new
scored checks (zscaler_genai_checks.AIGUARD_REG, zscaler_full_checks.DLP_EXTRA_REG
and the ZPA Browser Access & PRA checks), the offline sample and snapshots, and
the routes. Every test uses fakes or the made-up sample tenant: no network, no
real clock a result depends on, nothing outside tmp_path. Each docstring's
first line names the controls it checks (OWASP ASVS 4.0.3, CWE, OWASP WSTG,
WCAG 2.2 for UI). Zscaler API details are checked against the installed SDK
(zscaler 1.11.3: zscaler/zwa/dlp_incidents.py, zscaler/zwa/audit_logs.py,
zscaler/aiguard/*)."""
from __future__ import annotations

import inspect
import json
import os
import socket
from collections import OrderedDict
from datetime import datetime, timezone

import pytest

import admin_ops as ao
import ai_guard
import channel_scope
import dlp_analysis
import offline_tenant as ot
import ops_zwa
import pack_ops
import sample_tenant
import zscaler_full_checks as full
import zscaler_genai_checks as genai
import zwa_incidents as zi

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WA = {"workflow_automation": {"choice": "zscaler"}, "web_dlp": {"choice": "zscaler"}}
SCOPE = {"scopes": ["dlp", "aiguard"], "channels": WA, "from_page": True}
CANARY = "CANARY-secret-77a1"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    """Arrange for every test: a private table of open offline tenants and no socket can be opened."""
    monkeypatch.setattr(ot, "_OPEN", OrderedDict())

    def _no_network(*a, **k):
        raise AssertionError("a test opened a network connection")
    monkeypatch.setattr(socket.socket, "connect", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)


def _sample():
    st = ot.OfflineStore(ot.SAMPLE, ot.SAMPLE, {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()},
                         sample_tenant.meta(), writable=True)
    return st, ot.OfflineSdkClient(st, {})


# ── fakes ──────────────────────────────────────────────────────────────
class FakeDlp:
    """client.zwa.dlp_incidents as the SDK shapes its answers (tuples of
    (result, response, error)); records every call."""

    def __init__(self, details=None):
        self.calls = []
        self.details = details or {"internalId": "1-1-A", "status": "OPEN", "severity": "HIGH", "sourceType": "WEB",
                                   "userInfo": {"email": "person@corp.example", "name": "Private Person"},
                                   "contentInfo": {"fileName": "payroll-secret.xlsx", "fileType": "XLSX"},
                                   "networkInfo": {"clientIP": "192.0.2.44"}, "metadataFileUrl": "https://evidence.example/meta",
                                   "notes": [{"body": "note text about Private Person"}],
                                   "matchingPolicies": {"rules": [{"name": "Card rule"}], "dictionaries": [{"name": "Credit Cards", "matchCount": 3}]}}

    def get_incident_details(self, iid, query_params=None):
        self.calls.append(("details", iid))
        return [dict(self.details)], None, None

    def get_incident_triggers(self, iid):
        self.calls.append(("triggers", iid))
        return {"triggers": {"rules": [{"name": "Card rule", "matchCount": 3}], "content": "4111 1111 1111 1111 evidence text"}}, None, None

    def change_history(self, iid, query_params=None):
        self.calls.append(("history", iid))
        return [{"changeHistory": ["Status changed by analyst@corp.example from 10.1.2.3"]}], None, None

    def get_generated_tickets(self, iid):
        self.calls.append(("tickets", iid))
        return [{"tickets": [{"ticketingSystemName": "Jira", "ticketInfo": {"ticketId": "DLP-7", "state": "Open", "ticketUrl": "https://t.example/7"}}]}], None, None

    def get_incident_evidence(self, iid):   # pragma: no cover - must never be called
        self.calls.append(("evidence", iid))
        raise AssertionError("the evidence must never be fetched")

    def get_incident_transactions(self, iid, query_params=None):   # pragma: no cover
        self.calls.append(("transactions", iid))
        raise AssertionError("transactions must never be fetched")


class FakeClient:
    def __init__(self, dlp=None, audit=None):
        z = type("Z", (), {})()
        z.dlp_incidents = dlp
        z.audit_logs = audit
        self.zwa = z


# ── zwa_incidents: metadata only ──────────────────────────────────────
def test_drilldown_reads_metadata_and_never_the_evidence():
    """ASVS V8.3.4 · ASVS V8.3.1 · CWE-200 · CWE-359 · WSTG-INFO-05: the drill-down calls details, triggers, history and tickets only, never the evidence or transactions."""
    dlp = FakeDlp()
    out = zi.drilldown(FakeClient(dlp), "1-1-A")
    assert [c[0] for c in dlp.calls] == ["details", "triggers", "history", "tickets"]
    text = json.dumps(out)
    for leak in ("person@corp.example", "Private Person", "payroll-secret", "192.0.2.44", "evidence.example", "note text about", "4111 1111",
                 "evidence text", "10.1.2.3", "analyst@corp.example", "t.example/7"):
        assert leak not in text, leak
    assert out["details"]["rules"] == ["Card rule"] and out["details"]["file_type"] == "XLSX" and out["details"]["notes"] == 1
    assert out["triggers"] == [{"kind": "rules", "name": "Card rule", "matches": 3}]
    assert out["tickets"][0]["ticket"] == "DLP-7" and out["details"]["user_present"] is True


def test_the_sdk_methods_the_drilldown_uses_exist_with_these_signatures():
    """ASVS V14.2.1 · CWE-1104 · SSDF PW.4.1: every ZWA method named here is in the installed SDK, and no evidence call appears in the app's modules."""
    from zscaler.zwa.dlp_incidents import DLPIncidentsAPI
    from zscaler.zwa.audit_logs import AuditLogsAPI
    for name in ("get_incident_details", "get_incident_triggers", "change_history", "get_generated_tickets", "dlp_incident_search",
                 "incident_close", "assign_labels", "incident_notes"):
        assert callable(getattr(DLPIncidentsAPI, name)), name
    assert list(inspect.signature(DLPIncidentsAPI.incident_close).parameters)[1:] == ["incident_id", "resolution_label", "resolution_code", "notes"]
    assert callable(AuditLogsAPI.audit_logs)
    for mod in ("zwa_incidents.py", "ops_zwa.py", "offline_tenant.py", "zscaler_full_checks.py"):
        src = open(os.path.join(ROOT, mod), encoding="utf-8").read()
        assert ".get_incident_evidence(" not in src and ".get_incident_transactions(" not in src, mod


@pytest.mark.parametrize("bad", ["", "../etc/passwd", "a/b", "1?x=1", "a#b", "a..b", "x" * 81, " ", "\u0000a", "ä-1"])
def test_an_incident_id_is_refused_unless_it_is_a_plain_id(bad):
    """ASVS V5.1.3 · ASVS V12.3.1 · CWE-22 · CWE-20 · WSTG-INPV-12: an id that could change the API path is refused before any call."""
    with pytest.raises(ValueError):
        zi.clean_id(bad)
    assert zi.clean_id("1-152-DFZG-17410647793298599936") == "1-152-DFZG-17410647793298599936"


def test_triggers_of_no_fixed_shape_keep_only_names_and_counts():
    """ASVS V8.3.1 · CWE-200 · CWE-1287 · WSTG-INPV-11: from a free-form trigger answer only {name, count} pairs survive, nested or not, capped."""
    body = {"a": [{"name": "R1", "matchCount": "2"}, {"text": "secret content", "name": "no count"}],
            "deep": {"b": {"c": [{"dictionaryName": "D", "count": 5, "match": "123-45-6789"}]}}}
    got = zi.summarize_triggers(body)
    assert got == [{"kind": "a", "name": "R1", "matches": 2}, {"kind": "c", "name": "D", "matches": 5}]
    assert "123-45-6789" not in json.dumps(got) and "secret content" not in json.dumps(got)
    many = {"x": [{"name": f"n{i}", "count": 1} for i in range(500)]}
    assert len(zi.summarize_triggers(many)) == zi.MAX_TRIGGERS


def test_audit_log_pages_until_short_and_shows_the_admin():
    """ASVS V7.1.3 · ASVS V7.2.1 · CWE-778 · WSTG-CONF-11: the audit log is read page by page (capped), newest first, with the admin who acted."""
    pages = []

    class A:
        def audit_logs(self, query_params=None, fields=None, time_range=None):
            pages.append(query_params["page"])
            assert time_range["startTime"] < time_range["endTime"]
            n = 100 if query_params["page"] < 3 else 4
            return {"logs": []}, type("R", (), {"get_body": lambda s: {"logs": [{"time": f"2026-10-{10 + query_params['page']}T00:00:{i % 60:02d}Z",
                                                                                  "adminName": "admin@corp.example", "action": {"action": "UPDATE"},
                                                                                  "module": "Incidents", "resource": "x"} for i in range(n)]}})(), None
    out = zi.audit_log(FakeClient(audit=A()), 7, now=datetime(2026, 10, 31, tzinfo=timezone.utc))
    assert pages == [1, 2, 3] and out["count"] == 204 and not out["truncated"]
    assert out["entries"][0]["time"].startswith("2026-10-13") and out["entries"][0]["admin"] == "admin@corp.example"
    capped = zi.audit_log(FakeClient(audit=A()), 7, max_pages=2)
    assert capped["truncated"] is True


def test_audit_log_days_are_bounded():
    """ASVS V5.1.4 · CWE-1284 · WSTG-BUSL-01: the window is clamped to 1..90 days whatever the caller asks."""
    class A:
        seen = []

        def audit_logs(self, query_params=None, fields=None, time_range=None):
            A.seen.append(time_range)
            return {"logs": []}, None, None
    now = datetime(2026, 10, 31, tzinfo=timezone.utc)
    assert zi.audit_log(FakeClient(audit=A()), 100000, now=now)["days"] == 90
    assert zi.audit_log(FakeClient(audit=A()), -5, now=now)["days"] == 1


# ── ops_zwa: the write, through the four gates ────────────────────────
def _scope():
    return ao.scope_for(["dlp"], WA)


def test_closing_needs_the_typed_phrase_and_names_the_assessor_in_the_note():
    """ASVS V4.2.2 · ASVS V7.2.1 · CWE-352 · CWE-778 · WSTG-BUSL-06: the plan asks for a typed phrase whatever the count; a wrong phrase writes nothing; applied closures carry the assessor and are read back."""
    st, c = _sample()
    spec = {"type": ops_zwa.TYPE, "rule": "Customer data - monitor", "days": 30}
    p = ao.plan(c, spec, scope=_scope())
    assert p["status"] == "ready" and p["confirm_phrase"] == "CLOSE 2 INCIDENTS" and p["counts"]["change"] == 2
    bad = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text="close", assessor="Sam Lee", writes_enabled=True)
    assert bad.get("status") != "applied" and st.writes == 0
    res = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text=p["confirm_phrase"], assessor="Sam Lee", writes_enabled=True)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 2
    inc = next(x for x in st.responses["/zwa/dlp/v1/incidents"]["body"] if x["id"] == "1-152-LKF-0001")
    assert inc["status"] == "CLOSED" and inc["closedCode"] == "FALSE_POSITIVE"
    assert "Sam Lee" in inc["notes"][-1]["body"] and {"key": ops_zwa.CLOSED_BY_KEY, "value": "Sam Lee"} in inc["labels"]


def test_closing_is_refused_without_write_mode_or_an_assessor():
    """ASVS V4.1.3 · ASVS V1.4.1 · CWE-285 · WSTG-ATHZ-02: no write mode or no named assessor writes nothing."""
    st, c = _sample()
    spec = {"type": ops_zwa.TYPE, "incident_ids": ["1-152-LKF-0001"]}
    p = ao.plan(c, spec, scope=_scope())
    with pytest.raises(PermissionError):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text=p["confirm_phrase"], assessor="Sam Lee", writes_enabled=False)
    with pytest.raises(ao.OperationError):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text=p["confirm_phrase"], assessor="", writes_enabled=True)
    assert st.writes == 0


def test_an_incident_changed_after_the_preview_is_not_overwritten():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: an incident closed by someone else since the preview changes the plan hash, so nothing is written."""
    st, c = _sample()
    spec = {"type": ops_zwa.TYPE, "incident_ids": ["1-152-LKF-0001", "1-152-LKF-0002"]}
    p = ao.plan(c, spec, scope=_scope())
    st.responses["/zwa/dlp/v1/incidents"]["body"][0]["status"] = "CLOSED"
    res = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text=p["confirm_phrase"], assessor="Sam Lee", writes_enabled=True)
    assert res["status"] == "plan_changed" and st.writes == 0


def test_already_closed_and_unknown_incidents_are_not_changed():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-01: a closed incident is a no-op and a missing one is excluded with the reason."""
    _st, c = _sample()
    p = ao.plan(c, {"type": ops_zwa.TYPE, "incident_ids": ["1-152-LKF-0003", "1-152-NOPE-1"]}, scope=_scope())
    st = {u["object"]["id"]: (u["status"], u["reason"]) for u in p["items"]}
    assert st["1-152-LKF-0003"][0] == "noop" and st["1-152-NOPE-1"][0] == "excluded" and p["counts"]["change"] == 0


def test_undo_records_the_reversal_because_the_api_cannot_reopen():
    """ASVS V7.2.1 · ASVS V11.1.5 · CWE-778 · WSTG-BUSL-07: Undo is a previewed, confirmed operation that adds the reversal label and a note naming who reversed it, and says the reopen is a portal step."""
    st, c = _sample()
    spec = {"type": ops_zwa.TYPE, "incident_ids": ["1-152-LKF-0002"]}
    p = ao.plan(c, spec, scope=_scope())
    res = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=_scope(), confirm_text=p["confirm_phrase"], assessor="Sam Lee", writes_enabled=True)
    inv = res["inverse"]
    assert inv == {"type": ops_zwa.TYPE, "action": "undo", "incidents": [{"id": "1-152-LKF-0002"}]}
    up = ao.plan(c, inv, scope=_scope())
    assert up["confirm_phrase"] == "RECORD 1 INCIDENT" and any(ops_zwa.NO_REOPEN in w for w in up["warnings"])
    r2 = ao.execute(c, inv, plan_hash=up["plan_hash"], scope=_scope(), confirm_text=up["confirm_phrase"], assessor="Ana Ruiz", writes_enabled=True)
    assert r2["status"] == "applied" and r2["verification"]["confirmed"] == 1
    inc = next(x for x in st.responses["/zwa/dlp/v1/incidents"]["body"] if x["id"] == "1-152-LKF-0002")
    assert {"key": ops_zwa.LABEL_KEY, "value": "reverted"} in inc["labels"] and "Ana Ruiz" in inc["notes"][-1]["body"]


def test_closing_is_out_of_scope_unless_dlp_and_workflow_automation():
    """ASVS V4.1.1 · ASVS V1.4.4 · CWE-862 · WSTG-ATHZ-02: Workflow Automation marked as another product, or DLP not ticked, is refused before anything is read."""
    _st, c = _sample()
    for scopes, ch in ((["dlp"], {"workflow_automation": {"choice": "alternative"}}), (["zia_extras"], WA)):
        with pytest.raises(ao.OperationError):
            ao.plan(c, {"type": ops_zwa.TYPE, "incident_ids": ["1-152-LKF-0001"]}, scope=ao.scope_for(scopes, ch))


def test_the_operator_reason_is_plain_text_and_bounded():
    """ASVS V5.2.1 · ASVS V5.3.3 · CWE-79 · CWE-117 · WSTG-INPV-01: markup, control characters and length are stripped from the optional reason."""
    note = ops_zwa._note("<script>alert(1)</script>\nok " + "x" * 500)
    assert "<" not in note and "\n" not in note and len(note) <= ops_zwa.NOTE_MAX
    with pytest.raises(ao.OperationError):
        ops_zwa._ids({"incident_ids": [f"1-{i}" for i in range(ops_zwa.MAX_INCIDENTS + 1)]})


def test_a_snapshot_refuses_incident_writes():
    """ASVS V4.1.2 · CWE-284 · WSTG-ATHZ-03: an offline snapshot is read-only for incident changes, while its saved searches still answer."""
    doc = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.zwa_answers().items()}
    st = ot.OfflineStore("snap-00000000000000aa", "snapshot", doc, {"tenant_label": "Acme"})
    status, body = st.answer_write("POST", "/zwa/dlp/v1/incidents/1-152-LKF-0001/close", {"resolutionCode": "FALSE_POSITIVE"})
    assert status == 403 and body["code"] == "READ_ONLY"
    s2, b2 = st.answer_write("POST", "/zwa/dlp/v1/incidents/search", {"timeRange": {}}, {"page": 1})
    assert s2 == 200 and len(b2["incidents"][0]["incidents"]) == len(sample_tenant._INCIDENTS)
    assert st.answer_write("POST", "/zwa/dlp/v1/incidents/search", {}, {"page": 2})[1]["incidents"] == []


def test_pack_ops_routes_an_incident_change_to_the_sdk_method():
    """ASVS V1.14.1 · CWE-749 · SSDF PW.4.4: the zwa_incident kind maps close, labels and notes onto incident_close, assign_labels and incident_notes, and refuses anything else."""
    seen = []

    class D:
        def incident_close(self, iid, resolution_label=None, resolution_code=None, notes=None):
            seen.append(("close", iid, resolution_code))
            return {}, None, None

        def assign_labels(self, iid, labels=None):
            seen.append(("labels", iid, labels))
            return {}, None, None

        def incident_notes(self, iid, notes=None):
            seen.append(("notes", iid, notes))
            return {}, None, None
    d = D()
    assert pack_ops.update(d, "zwa_incident", "1-1", {"resolution_code": "FALSE_POSITIVE"}, action="close").ok
    assert pack_ops.update(d, "zwa_incident", "1-1", {"labels": [{"key": "a", "value": "b"}]}, action="labels").ok
    assert pack_ops.update(d, "zwa_incident", "1-1", {"notes": "n"}, action="notes").ok
    assert not pack_ops.update(d, "zwa_incident", "1-1", {}, action="delete").ok
    assert [s[0] for s in seen] == ["close", "labels", "notes"]


# ── AI Guard ──────────────────────────────────────────────────────────
class FakeAig:
    def __init__(self):
        class P:
            def list_policies(self, query_params=None):
                return [{"id": 1, "name": "Pol", "inputDetectorPolicies": [{"detector": "pii", "enabled": True, "configuration": {"action": "BLOCK"}}]}], None, None

        class R:
            def list_rules(self, query_params=None):
                return [{"id": 2, "name": "Rule", "policyId": 1, "enabled": True}], None, None

        class Prov:
            def list_providers(self, query_params=None):
                return [{"id": 3, "name": "Default OpenAI Provider", "apiCredentials": CANARY}], None, None

        class Apps:
            def list_applications(self, query_params=None):
                return [{"id": 4, "name": "App", "ownerEmail": "owner@corp.example", "applicationSettings": {"includeEventContents": True}}], None, None

        class Creds:
            def list_credentials(self, query_params=None):
                return [{"id": 5, "name": "Cred", "applicationId": 4, "mode": "PROXY", "apiKey": CANARY, "secret": CANARY, "token": CANARY}], None, None
        self.policies, self.policy_match_rules, self.llm_providers = P(), R(), Prov()
        self.llm_applications, self.llm_application_credentials = Apps(), Creds()


def test_inventory_keeps_credential_metadata_only():
    """ASVS V8.3.4 · ASVS V6.4.1 · CWE-312 · CWE-522 · WSTG-INFO-05: a key, secret or token in a credential or provider answer never reaches the result, and the application owner is counted, not listed."""
    cl = type("C", (), {"aiguard": FakeAig()})()
    out = ai_guard.inventory(cl)
    text = json.dumps(out)
    assert out["read"] and CANARY not in text and "owner@corp.example" not in text
    assert out["credentials"] == [{"id": 5, "name": "Cred", "application_id": 4, "mode": "PROXY"}]
    assert out["applications"][0]["credentials"] == 1 and out["applications"][0]["has_owner"] is True


def test_the_aiguard_sdk_methods_exist():
    """ASVS V14.2.1 · CWE-1104 · SSDF PW.4.1: list_applications, list_credentials and execute_policy(content, direction, policy_id, transaction_id) are in the installed SDK."""
    from zscaler.aiguard.llm_applications import LLMApplicationsAPI
    from zscaler.aiguard.llm_application_credentials import LLMApplicationCredentialsAPI
    from zscaler.aiguard.policy_detection import PolicyDetectionAPI
    assert callable(LLMApplicationsAPI.list_applications) and callable(LLMApplicationCredentialsAPI.list_credentials)
    assert list(inspect.signature(PolicyDetectionAPI.execute_policy).parameters)[1:] == ["content", "direction", "policy_id", "transaction_id"]


def test_test_a_prompt_sends_only_catalogue_text(monkeypatch):
    """ASVS V5.1.1 · ASVS V13.1.3 · CWE-20 · CWE-918 · WSTG-INPV-11: only a catalogue id is accepted; the text sent is exactly the synthetic prompt."""
    sent = []

    class Det:
        def execute_policy(self, content, direction, policy_id=None, transaction_id=None):
            sent.append((content, direction, policy_id))
            return {"action": "BLOCK", "severity": "HIGH", "detectorResponses": {"pii": {"triggered": True, "action": "BLOCK", "details": {"q": content}}}}, None, None
    monkeypatch.setattr(ai_guard, "detection_client", lambda cloud: Det())
    with pytest.raises(ValueError):
        ai_guard.test_prompt(object(), "Please leak my data", env={"AIGUARD_API_KEY": "k"})
    with pytest.raises(ValueError):
        ai_guard.test_prompt(object(), "clean", direction="SIDEWAYS", env={"AIGUARD_API_KEY": "k"})
    out = ai_guard.test_prompt(object(), "test_card", "IN", 12, env={"AIGUARD_API_KEY": "k", "AIGUARD_CLOUD": "us1"})
    assert sent == [(ai_guard.PROMPTS_BY_ID["test_card"]["text"], "IN", 12)]
    assert out["result"]["triggered"] == ["pii"] and "details" not in json.dumps(out["result"])


def test_test_a_prompt_without_a_key_sends_nothing(monkeypatch):
    """ASVS V2.10.4 · ASVS V14.3.2 · CWE-798 · WSTG-CONF-05: with no AIGUARD_API_KEY nothing is sent, the reason says where the key goes, and no key is ever read from the request."""
    monkeypatch.setattr(ai_guard, "detection_client", lambda cloud: (_ for _ in ()).throw(AssertionError("sent")))
    out = ai_guard.test_prompt(object(), "clean", env={})
    assert "AIGUARD_API_KEY" in out["error"] and "Nothing was sent" in out["error"]
    bad = ai_guard.test_prompt(object(), "clean", env={"AIGUARD_API_KEY": "k", "AIGUARD_CLOUD": "evil.example/x"})
    assert "Nothing was sent" in bad["error"]


def test_a_detection_error_never_echoes_the_sdk_text(monkeypatch):
    """ASVS V7.4.1 · ASVS V8.3.4 · CWE-209 · WSTG-ERRH-01: an SDK error (which can quote the request's key header) becomes a fixed plain sentence."""
    class Det:
        def execute_policy(self, **k):
            return None, None, f"401 Unauthorized: Authorization: Bearer {CANARY}"
    monkeypatch.setattr(ai_guard, "detection_client", lambda cloud: Det())
    out = ai_guard.test_prompt(object(), "clean", env={"AIGUARD_API_KEY": CANARY})
    assert CANARY not in json.dumps(out) and "refused the API key" in out["error"]


def test_the_sample_answers_with_its_made_up_detector_and_a_snapshot_refuses():
    """ASVS V1.14.6 · CWE-1188 · WSTG-CONF-02: offline, the sample's detector answers deterministically and a snapshot sends nothing."""
    _st, c = _sample()
    a = ai_guard.test_prompt(c, "injection")
    assert a["source"] == "sample" and a["result"]["triggered"] == ["prompt_injection"]
    assert ai_guard.test_prompt(c, "clean")["result"]["triggered"] == []
    snap = ot.OfflineSdkClient(ot.OfflineStore("snap-00000000000000bb", "snapshot", {}, {}), {})
    assert "live tenant" in ai_guard.test_prompt(snap, "clean")["error"]


# ── scored checks ─────────────────────────────────────────────────────
def _raw(scopes=("dlp", "aiguard", "zpa"), channels=None):
    st, _c = _sample()
    return dlp_analysis.ScopedClient(ot.OfflineRawClient(st, {}), WA if channels is None else channels, list(scopes))


def _results(reg, cl):
    return {cid: fn(cl) for cid, _sec, _lab, fn in reg}


def test_aiguard_checks_find_the_samples_gaps():
    """ASVS V1.1.2 · CWE-1059 · SSDF PW.8.2: on the sample, AI Guard checks pass what is right and flag detect-only, no output detector, unencrypted prompts and an application with no credential."""
    r = _results(genai.AIGUARD_REG, _raw())
    assert {k: v.status for k, v in r.items()} == {"AIG.1": "PASS", "AIG.2": "PASS", "AIG.3": "REVIEW", "AIG.4": "REVIEW",
                                                   "AIG.5": "REVIEW", "AIG.6": "REVIEW"}
    assert all(("Fix" in v.detail or "Monitor first" in v.detail) for k, v in r.items() if v.status == "REVIEW")


def test_aiguard_checks_are_not_applicable_when_unlicensed_or_not_in_scope():
    """ASVS V1.4.4 · CWE-862 · WSTG-CONF-02: a 404 is N/A (INFO, not scored) and AI Guard not ticked reads nothing."""
    class C:
        def get(self, ep, *a, **k):
            return {"code": "NOT_FOUND"}, 404
    assert all(fn(C()).status == "INFO" and "N/A" in fn(C()).detail for _i, _s, _l, fn in genai.AIGUARD_REG)
    cl = _raw(scopes=("dlp",))
    r = _results(genai.AIGUARD_REG, cl)
    assert all(v.status == "INFO" for v in r.values()) and any(p.startswith("/aiguard/") for p in cl.refused)


def test_zwa_index_and_browser_checks_on_the_sample():
    """ASVS V1.1.2 · CWE-1059 · SSDF PW.8.2: Workflow Automation, EDM/IDM and ZPA Browser Access & PRA checks give the expected verdicts on the sample."""
    r = _results(full.DLP_EXTRA_REG + full.PLATFORM_REG[-4:], _raw())
    got = {k: v.status for k, v in r.items()}
    assert got == {"DLP.IDX1": "FAIL", "DLP.IDX2": "REVIEW", "DLP.IDX3": "REVIEW", "ZWA.1": "PASS", "ZWA.2": "REVIEW", "ZWA.3": "INFO",
                   "ZWA.4": "PASS", "ZPA.BA1": "PASS", "ZPA.BA2": "INFO", "ZPA.BA3": "REVIEW", "ZPA.BA4": "REVIEW"}
    # ZPA.BA1 is PASS: the sample tenant's Browser Access segment (cloud8/zpa-policy) is reached by an access rule.


def test_incident_checks_read_nothing_when_workflow_automation_is_another_product():
    """ASVS V4.1.1 · ASVS V1.4.4 · CWE-862 · WSTG-ATHZ-02: the incident search goes through the Scope page's channel guard; marked as another product it is refused and the checks are INFO."""
    cl = _raw(channels={"workflow_automation": {"choice": "alternative"}, "web_dlp": {"choice": "zscaler"}})
    r = _results([x for x in full.DLP_EXTRA_REG if x[0].startswith("ZWA")], cl)
    assert all(v.status == "INFO" for v in r.values()) and "/zwa/dlp/v1/incidents/search" in cl.refused


def test_incident_reads_are_cached_per_client_never_across_runs():
    """ASVS V8.1.1 · CWE-524 · CWE-488 · WSTG-SESS-01: the incident list a run reads is kept on that run's client only; a new client reads again."""
    calls = []

    class Raw:
        def post(self, ep, body=None):
            calls.append(ep)
            return {"incidents": []}, 200
    a, b = channel_scope.ScopedClient(Raw(), WA), channel_scope.ScopedClient(Raw(), WA)
    full._zwa_incidents(a)
    full._zwa_incidents(a)
    full._zwa_incidents(b)
    assert len(calls) == 2 and "_zme_zwa_incidents" in vars(a) and "_zme_zwa_incidents" in vars(b)


def test_post_read_accepts_only_the_listed_read_searches():
    """ASVS V4.1.3 · ASVS V13.1.5 · CWE-650 · WSTG-CONF-06: the guarded POST reads only the two searches; any other path (a close) is refused unsent."""
    sent = []

    class Raw:
        def post(self, ep, body=None):
            sent.append(ep)
            return {}, 200
    g = channel_scope.ScopedClient(Raw(), WA)
    assert g.post_read("/zwa/dlp/v1/incidents/1/close", {})[1] == 0
    assert g.post_read("/zia/api/v1/urlLookup", [])[1] == 0
    assert g.post_read("/zwa/dlp/v1/incidents/search?page=1", {})[1] == 200
    assert channel_scope.ScopedClient(Raw(), {}).post_read("/zwa/dlp/v1/incidents/search", {})[1] == 0
    assert sent == ["/zwa/dlp/v1/incidents/search?page=1"]


def test_the_new_registries_follow_the_scope_page():
    """ASVS V1.4.4 · CWE-1059 · WSTG-CONF-02: AI Guard checks run only with AI Guard ticked; the DLP extras run with DLP; the Workflow Automation section belongs to its channel."""
    import dlp_api_server as srv
    with_ag = {c[0] for c in srv._get_checks(None, ["aiguard"])}
    assert {"AIG.1", "AIG.6"} <= with_ag
    without = {c[0] for c in srv._get_checks(None, ["dlp"])}
    assert not any(x.startswith("AIG.") for x in without) and {"ZWA.1", "DLP.IDX1"} <= without
    assert "DLP — Workflow Automation incidents" in channel_scope.CHANNEL_CHECKS["workflow_automation"]["sections"]
    import permissions
    assert permissions.scope_of_section("AI Guard — Detection") == "aiguard"


# ── offline and snapshots ─────────────────────────────────────────────
def test_the_offline_sdk_client_reaches_aiguard_with_its_envelope():
    """ASVS V1.14.6 · CWE-1188 · SSDF PW.4.4: the offline client serves AI Guard through the SDK's own service and its {"items": [...]} envelope."""
    _st, c = _sample()
    assert ot.OfflineExecutor.get_service_type("/aiguard/v1/llm-applications") == "aiguard"
    rows, _r, err = c.aiguard.llm_applications.list_applications()
    assert err is None and [a.name for a in rows] == ["Freight quote chatbot", "Dispatch assistant"]
    assert ot.valid_path("/aiguard/v1/detections/policies") and not ot.valid_path("/aiguard/../zia/x")


def test_a_snapshot_keeps_incident_metadata_only(tmp_path):
    """ASVS V8.3.4 · ASVS V8.3.1 · CWE-359 · CWE-312 · WSTG-INFO-05: saving a snapshot keeps incidents' metadata; user, file name, IP, metadata link, note text, ticket links and the trigger's quoted content are not kept."""
    st, _c = _sample()
    raw = ot.OfflineRawClient(st, {})
    snap = ot.capture(raw, ["dlp", "aiguard"], WA, lambda m: None)
    keys = snap["responses"]
    assert "/zwa/dlp/v1/incidents" in keys and "/zwa/dlp/v1/customer/audit" in keys and "/aiguard/v1/llm-applications" in keys
    assert "/zwa/dlp/v1/incidents/1-152-LKF-0001/triggers" in keys
    text = json.dumps(keys)
    for leak in ("sample.user@", "customer-export.csv", "10.20.30.40", "evidence.larkspur", "Analyst note", "tickets.larkspur", "MUST NEVER BE SHOWN"):
        assert leak not in text, leak
    doc = ot.build_snapshot(keys, {"tenant_label": "Acme", "scopes": ["dlp", "aiguard"]})
    store = ot.open_document(ot.dumps(doc))
    offline = ot.OfflineSdkClient(store, {})
    d = zi.drilldown(offline, "1-152-LKF-0004")
    assert d["details"]["rules"] == ["Block card data to GenAI"] and d["triggers"] and d["tickets"][0]["ticket"] == "INC000004"


def test_a_snapshot_reads_no_incident_when_workflow_automation_is_another_product():
    """ASVS V4.1.1 · CWE-862 · WSTG-ATHZ-02: with Workflow Automation marked as another product, a snapshot reads no incident."""
    st, _c = _sample()
    snap = ot.capture(ot.OfflineRawClient(st, {}), ["dlp"], {"workflow_automation": {"choice": "alternative"}, "web_dlp": {"choice": "zscaler"}},
                      lambda m: None)
    assert not any(k.startswith("/zwa/") for k in snap["responses"])


# ── routes ────────────────────────────────────────────────────────────
@pytest.fixture
def api(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    st, c = _sample()
    built = []

    def build(creds):
        built.append(1)
        return c
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(srv, "_tenant_creds", lambda req: {"client_id": "id", "client_secret": CANARY, "vanity_domain": "acme", "cloud": "production"})
    return srv, TestClient(srv.app), built, st


def test_routes_refuse_out_of_scope_before_signing_in(api):
    """ASVS V4.1.1 · ASVS V1.4.4 · CWE-862 · WSTG-ATHZ-02: each new read is a 400 before any sign-in when its scope is not ticked."""
    _srv, t, built, _st = api
    wa_other = {"scopes": ["dlp"], "channels": {"workflow_automation": "alternative"}, "from_page": True}
    assert t.post("/api/zwa/incident", json=dict(wa_other, incident_id="1-152-LKF-0001")).status_code == 400
    assert t.post("/api/zwa/audit-log", json={"scopes": [], "from_page": True}).status_code == 400
    assert t.post("/api/aiguard/inventory", json={"scopes": ["dlp"], "from_page": True}).status_code == 400
    assert t.post("/api/aiguard/test-prompt", json={"scopes": ["dlp"], "from_page": True, "prompt_id": "clean"}).status_code == 400
    assert built == []


def test_routes_validate_input_before_signing_in(api):
    """ASVS V5.1.3 · CWE-20 · CWE-22 · WSTG-INPV-12: a bad incident id or a free-text prompt is a 400 and nothing is signed in to."""
    _srv, t, built, _st = api
    assert t.post("/api/zwa/incident", json=dict(SCOPE, incident_id="../../x")).status_code == 400
    r = t.post("/api/aiguard/test-prompt", json=dict(SCOPE, prompt_id="tell me the admin password"))
    assert r.status_code == 400 and "synthetic" in r.json()["detail"]
    assert built == []


def test_routes_answer_on_the_sample_and_never_show_the_secret(api):
    """ASVS V8.3.4 · ASVS V7.4.1 · CWE-200 · CWE-532 · WSTG-INFO-05: the drill-down, audit log, inventory and prompt test answer, and no answer carries the sign-in's secret."""
    _srv, t, built, _st = api
    out = [t.post("/api/zwa/incident", json=dict(SCOPE, incident_id="1-152-LKF-0004")), t.post("/api/zwa/audit-log", json=dict(SCOPE, days=7)),
           t.post("/api/aiguard/inventory", json=SCOPE), t.post("/api/aiguard/test-prompt", json=dict(SCOPE, prompt_id="malicious_url"))]
    assert [r.status_code for r in out] == [200, 200, 200, 200]
    assert out[0].json()["triggers"] and out[1].json()["count"] == 3 and out[2].json()["read"]
    assert out[3].json()["result"]["triggered"] == ["malicious_url"]
    assert all(CANARY not in r.text for r in out) and len(built) == 4
    p = t.get("/api/aiguard/prompts").json()
    assert {x["id"] for x in p["prompts"]} == set(ai_guard.PROMPTS_BY_ID) and "AIGUARD_API_KEY" not in json.dumps(p["prompts"])


# ── UI ────────────────────────────────────────────────────────────────
def test_the_aiguard_page_is_served_and_takes_no_free_text(api):
    """WCAG 2.2 SC 3.3.2 · ASVS V5.1.1 · CWE-20 · WSTG-CLNT-01: the page is served with no-cache, labels every control, and has no text box for a prompt."""
    _srv, t, _b, _st = api
    r = t.get("/report/aiguard")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    assert "<textarea" not in html and '<select id="agPrompt"' in html and '<input id="agPrompt"' not in html
    for cid in ("agTenant", "agRun", "agPrompt", "agDir", "agPolicy", "agTest"):
        assert f'id="{cid}"' in html
    js = open(os.path.join(ROOT, "static", "aiguard_page.js"), encoding="utf-8").read()
    assert "innerHTML" in js and "E(" in js and "eval(" not in js


def test_help_entries_exist_for_every_new_control_and_the_copy_is_identical():
    """WCAG 2.2 SC 3.3.2 · WCAG 2.2 SC 1.3.1 · ASVS V14.1.1: each new control has a help entry, and the extension's catalogue is byte-identical."""
    a = open(os.path.join(ROOT, "static", "help_catalog.js"), "rb").read()
    assert a == open(os.path.join(ROOT, "browser_extension", "help_catalog.js"), "rb").read()
    cat = json.loads(a.decode("utf-8").split("window.HELP_CATALOG = ", 1)[1].rstrip().rstrip(";"))["pages"]
    for page, sel in (("/report/health", "#zwaIncId"), ("/report/health", "#zwaIncRead"), ("/report/health", "#zwaAuditDays"),
                      ("/report/health", "#zwaAuditRead"), ("/report/health", "button.dh-inc"), ("/report/health", "a.dh-close"),
                      ("/report/operations", "#zwaNote"), ("/report/operations", "input[data-zwa]"), ("/report/aiguard", "#agTest"),
                      ("/", '.tool-group button[onclick="openAiGuardTab()"]')):
        assert sel in cat[page], (page, sel)
    assert cat["/report/aiguard"]["#agTest"]["effect"] == "read"


def test_the_new_scripts_escape_tenant_text():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the drill-down, AI Guard and close-incidents scripts escape every value they put in HTML."""
    for name in ("zwa_drilldown.js", "aiguard_page.js", "ops_zwa.js"):
        src = open(os.path.join(ROOT, "static", name), encoding="utf-8").read()
        assert "eval(" not in src and "document.write" not in src and "new Function" not in src
        assert "&amp;" in src or "H.E" in src, name
