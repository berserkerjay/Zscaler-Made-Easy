"""Activate pending ZIA changes (ops_zia_activation) on the Bulk changes
engine: the plan reads ZIA's activation status, PENDING needs ACTIVATE
typed, ACTIVE is refused, the apply is audited with the actor, and there is
no Undo.

Runs against the fake ZIA tenant of tests/test_admin_ops.py with ZIA's
activation status faked (GET /status, POST /status/activate): no network,
no clock, state in tmp_path."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zia_activation as za  # noqa: E402
import pack_channels as pc  # noqa: E402
import pack_ops as ops  # noqa: E402
from test_admin_ops import FULL_SCOPE, Tenant  # noqa: E402

ASSESSOR = "Jane Doe"
SPEC = {"type": za.TYPE}
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Zia:
    """ZIA's activation status: activate() makes it ACTIVE; nothing is sent while frozen (a preview)."""

    def __init__(self, t, status="PENDING", read_error=None, activate_error=None, after=None):
        self.t, self.status, self.read_error, self.activate_error = t, status, read_error, activate_error
        self.after = after            # the status ZIA reports once activated (default ACTIVE)
        self.reads, self.sent = 0, []

    def read(self, zia):
        self.reads += 1
        return (None, self.read_error) if self.read_error else (self.status, None)

    def activate(self, zia):
        if self.t.frozen:
            raise AssertionError("an activation was sent during a preview")
        self.sent.append("POST /status/activate")
        if self.activate_error:
            return {"activated": False, "status": self.status, "error": self.activate_error}
        self.status = self.after or "ACTIVE"
        return {"activated": True, "status": self.status, "error": None}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    ao.load_plugins()
    return tmp_path


def tenant(monkeypatch, **kw):
    t = Tenant()
    z = Zia(t, **kw)
    monkeypatch.setattr(pc, "activation_status", z.read)
    monkeypatch.setattr(pc, "activate", z.activate)
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: z.read(zia)[0])
    return t, z


def preview(t, spec=SPEC, scope=FULL_SCOPE):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec=SPEC, *, phrase=None, prepared=None, writes=True, assessor=ASSESSOR):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=writes, assessor=assessor, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


def test_registered_on_the_engine_under_day_to_day_admin_with_the_zia_admin_form():
    """ASVS V1.14.1 · CWE-1059: ZIA activation is one ZIA plugin type of the one engine, its form in the ZIA admin script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[za.TYPE]["product"] == "zia" and cat[za.TYPE]["group"] == "Day-to-day admin" and cat[za.TYPE]["script"] == "ops_zia_admin.js"
    with open(os.path.join(ROOT, "static", "ops_zia_admin.js"), encoding="utf-8") as f:
        assert "type: 'zia_activation'" in f.read()


def test_pending_status_is_listed_and_needs_activate_typed(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-841 · WSTG-BUSL-01: with ZIA reporting PENDING the plan lists the pending status, asks ACTIVATE every time and says there is no Undo; nothing is sent."""
    t, z = tenant(monkeypatch, status="PENDING")
    p = preview(t)
    assert p["status"] == "ready" and p["counts"]["change"] == 1
    item = p["items"][0]
    assert (item["field"], item["before"], item["after"]) == ("status", "PENDING", "ACTIVE")
    assert p["impact"][0]["status"] == "PENDING" and "pending" in p["impact"][0]["detail"].lower()
    assert p["confirm_phrase"] == "ACTIVATE"
    assert p["undo_note"] == za.NO_UNDO and za.NO_UNDO in p["warnings"] and "cannot be undone" in za.NO_UNDO.lower()
    # The plan activates as its own step: the engine adds no second activation and no "activates once" note.
    assert p["needs_activation"] is False and not any("activates once" in n for n in p["notes"])
    assert z.sent == [] and t.writes == []


def test_active_status_is_refused_and_nothing_is_sent(monkeypatch):
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-01: with ZIA reporting ACTIVE there is nothing to activate: the plan is blocked and an apply sends nothing."""
    t, z = tenant(monkeypatch, status="ACTIVE")
    p = preview(t)
    assert p["status"] == "blocked" and p["groups"] == [] and p["confirm_phrase"] == ""
    assert "nothing is pending" in " ".join(p["blockers"]).lower()
    _p, r = apply(t, prepared=p, phrase="ACTIVATE")
    assert r["status"] == "blocked" and z.sent == []


def test_an_activation_already_in_progress_is_refused(monkeypatch):
    """ASVS V11.1.1 · CWE-362: ZIA activating already: the plan is blocked; nothing is sent."""
    t, z = tenant(monkeypatch, status="INPROGRESS")
    p = preview(t)
    assert p["status"] == "blocked" and "in progress" in " ".join(p["blockers"]).lower() and z.sent == []


@pytest.mark.parametrize("kw", [{"read_error": "HTTP 500 server error"}, {"status": "SOMETHING_NEW"}, {"status": None}])
def test_a_status_that_cannot_be_read_or_is_not_known_is_unknown_never_pending(monkeypatch, kw):
    """ASVS V7.4.1 · CWE-754 · CWE-697: an unreadable or unfamiliar activation status is unknown, so nothing is planned (never treated as pending)."""
    t, z = tenant(monkeypatch, **kw)
    with pytest.raises(ao.OperationError, match="unknown"):
        preview(t)
    assert z.sent == []


def test_apply_activates_once_reads_back_active_and_audits_the_actor(monkeypatch, isolated):
    """ASVS V7.1.3 · V7.2.1 · CWE-778 · WSTG-BUSL-01: ACTIVATE typed: one POST /status/activate, read back ACTIVE, recorded with no Undo, and the audit entry names the actor."""
    t, z = tenant(monkeypatch, status="PENDING")
    with ops.audit_scope(actor="alice"):
        p, r = apply(t)
    assert r["status"] == "applied" and z.sent == ["POST /status/activate"]
    assert r["verification"] == {"checked": 1, "confirmed": 1, "mismatched": [], "unread": []}
    assert r["activation"]["activated"] is True and r["inverse"] is None
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    assert rec and rec["inverse"] is None and rec["type"] == za.TYPE
    import audit
    entries = audit.tail(50)
    ops_entry = [e for e in entries if e.get("event") == "admin_operation"]
    assert ops_entry and ops_entry[-1]["actor"] == "alice" and ops_entry[-1]["type"] == za.TYPE and ops_entry[-1]["by"] == ASSESSOR
    finished = [e for e in entries if e.get("event") == "run_finished"]
    assert finished and finished[-1]["actor"] == "alice" and finished[-1]["activation"]["activated"] is True


@pytest.mark.parametrize("phrase", ["", "APPLY 1 CHANGES", "ACTIVATE.", "ACTIVAT"])
def test_without_the_typed_phrase_nothing_is_activated(monkeypatch, phrase):
    """ASVS V4.1.3 · CWE-841 · WSTG-ATHZ-02: a missing or wrong typed phrase is refused on the server; no activation is sent."""
    t, z = tenant(monkeypatch)
    _p, r = apply(t, phrase=phrase)
    assert r["status"] == "refused" and "ACTIVATE" in r["message"] and z.sent == []


def test_without_write_mode_or_the_assessor_nothing_is_read_or_activated(monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: write mode off or no named assessor: refused before anything is read; no activation is sent."""
    t, z = tenant(monkeypatch)
    p = preview(t)
    reads = z.reads
    with pytest.raises(PermissionError):
        apply(t, prepared=p, writes=False)
    with pytest.raises(ao.OperationError, match="assessor"):
        apply(t, prepared=p, assessor=" ")
    assert z.sent == [] and z.reads == reads


def test_out_of_scope_is_refused_before_anything_is_read(monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: with no ZIA area ticked on the Scope page the plan and the status read are refused; nothing is read."""
    t, z = tenant(monkeypatch)
    only_zpa = ao.scope_for(["zpa"], {})
    with pytest.raises(ao.OperationError):
        ao.plan(t, SPEC, scope=only_zpa)
    with pytest.raises(ao.OperationError):
        ao.read_objects(t, za.FAMILY, only_zpa)
    assert z.reads == 0 and z.sent == []


def test_activated_meanwhile_changes_the_plan_hash_and_nothing_is_sent(monkeypatch):
    """ASVS V11.1.1 · CWE-367 · WSTG-BUSL-01: someone activates in the portal after the preview: the re-plan differs, nothing is sent."""
    t, z = tenant(monkeypatch)
    p = preview(t)
    z.status = "ACTIVE"
    _p, r = apply(t, prepared=p)
    assert r["status"] == "plan_changed" and z.sent == []


def test_the_handler_rereads_the_status_right_before_the_activation(monkeypatch):
    """ASVS V11.1.1 · CWE-367: the status is read again right before the POST; activated in between, the unit is a conflict and nothing is sent."""
    t, z = tenant(monkeypatch)
    p = ao.plan(t, SPEC, scope=FULL_SCOPE)
    run = ao._Run(t, p, lambda m: None, ASSESSOR)
    z.status = "ACTIVE"
    za.h_activate(run, p["groups"][0], run.group_units(p["groups"][0]))
    assert p["items"][0]["status"] == "conflict" and z.sent == []


def test_a_refused_activation_is_reported_failed_in_words(monkeypatch):
    """ASVS V7.4.1 · CWE-755: ZIA refuses the activation: the unit is failed with ZIA's words; nothing claims it is active."""
    t, z = tenant(monkeypatch, activate_error="HTTP 409 EDIT_LOCK_NOT_AVAILABLE")
    _p, r = apply(t)
    assert r["status"] == "failed" and r["items"][0]["status"] == "failed" and "EDIT_LOCK" in r["items"][0]["error"]
    assert ao.record(r, by=ASSESSOR, actor="alice") is None     # nothing applied: nothing recorded as done


def test_still_pending_after_the_activation_is_a_read_back_mismatch(monkeypatch):
    """ASVS V7.4.1 · CWE-754: ZIA still reports PENDING after accepting the activation: the read-back says so; the run is not called applied."""
    t, z = tenant(monkeypatch, after="PENDING")
    _p, r = apply(t)
    assert r["verification"]["mismatched"] and r["status"] == "partial"


def test_no_undo_is_offered(monkeypatch):
    """ASVS V7.1.3 · CWE-1059: an activation has no inverse; the hint and the preview say so."""
    assert za.inverse({"items": [{"status": "applied", "group": "activate"}], "groups": [{"key": "activate", "handler": "zia_activate"}]}) is None
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert "no undo" in cat[za.TYPE]["hint"].lower()


def test_the_activation_is_classed_as_creating_nothing_enforcing():
    """ASVS V4.1.3 · CWE-1188: the type is listed in the secure-defaults table with its reason."""
    import test_sbd_writes
    assert len(test_sbd_writes.DEFAULT_OFF[za.TYPE]) >= 20
