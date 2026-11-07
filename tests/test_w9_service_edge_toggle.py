"""Toggling one Private Service Edge (ops_zpa_admin kind "service_edge") on
the Bulk changes engine: the payload sent, the gates, the read-back and Undo.

Runs against the stateful ZPA fake in tests/admin_fakes.py: no network, no
clock (ZPA pacing set to 0), state files in tmp_path."""
from __future__ import annotations

import json
import os
import sys

import pytest
from conftest import read_store_text

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zpa  # noqa: E402
import ops_zpa_admin as za  # noqa: E402
import zpa_reader  # noqa: E402
from admin_fakes import ZpaClient  # noqa: E402

ZPA = ao.scope_for(["zpa"], {})
NO_ZPA = ao.scope_for(["zcc"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    monkeypatch.setattr(za, "_CERTS", {})
    ao.load_plugins()
    return tmp_path


def _spec(se_id, enabled):
    return {"type": za.T_UPDATE, "targets": [{"kind": "service_edge", "id": se_id, "set": {"enabled": enabled}}]}


def _apply(c, spec, phrase=None):
    p = ao.plan(c, spec, scope=ZPA, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") if phrase is None else phrase)
    return p, r


def test_turning_off_one_private_service_edge_sends_only_that_edge_and_undo_turns_it_back_on(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle: PUT /serviceEdge/{id} carries the edge as read with enabled false, nothing else is written; read back; Undo restores it."""
    c = ZpaClient()
    s = c.tenant.seed()
    se = s["se"]["id"]
    p, r = _apply(c, _spec(se, False))
    assert p["status"] == "ready" and any("moves its users' traffic" in w for w in p["warnings"])
    assert [u["object"]["type"] for u in p["items"] if u["status"] == "change"] == ["zpa_service_edge"]
    assert r["status"] == "applied" and r["verification"]["confirmed"] == r["verification"]["checked"] == 1
    assert c.tenant.writes == [("update", "service_edge", se, {"name": "pse-fra-1", "description": "", "enabled": False})]
    assert c.tenant.rows["service_edge"][se]["enabled"] is False
    assert c.tenant.rows["service_edge_group"][s["sg"]["id"]]["enabled"] is True     # the group is untouched
    ao.record(r, by=ASSESSOR, actor="alice")
    inv = r["inverse"]
    assert inv and ao.is_undo_only(inv)
    _p2, r2 = _apply(c, inv)
    assert r2["status"] == "applied" and c.tenant.rows["service_edge"][se]["enabled"] is True
    audit = [json.loads(x) for x in read_store_text(isolated / "audit.log").splitlines() if x.strip()]
    writes = [e for e in audit if e.get("event") == "object_write" and e.get("action") == "update"]
    assert writes and all(str(e.get("id")) == se for e in writes)
    assert any(e.get("event") == "admin_operation" and e.get("actor") == "alice" for e in audit)


def test_an_edge_already_off_is_a_noop_and_writes_nothing():
    """ASVS V11.1.1 · CWE-841: asking for the state the edge already has changes nothing."""
    c = ZpaClient()
    s = c.tenant.seed()
    c.tenant.rows["service_edge"][s["se"]["id"]]["enabled"] = False
    p, r = _apply(c, _spec(s["se"]["id"], False))
    assert p["status"] == "nothing_to_do" and c.tenant.writes == []


def test_an_edge_turned_on_in_zpa_after_the_preview_is_not_overwritten():
    """ASVS V11.1.4 · CWE-367: the edge changed since the preview gives plan_changed; nothing is sent."""
    c = ZpaClient()
    s = c.tenant.seed()
    spec = _spec(s["se"]["id"], False)
    p = ao.plan(c, spec, scope=ZPA)
    c.tenant.rows["service_edge"][s["se"]["id"]]["enabled"] = False
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR)
    assert r["status"] == "plan_changed" and c.tenant.writes == []


def test_the_gates_hold_for_an_edge_toggle():
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: no write mode, no assessor or ZPA not in scope writes and reads nothing."""
    c = ZpaClient()
    s = c.tenant.seed()
    spec = _spec(s["se"]["id"], False)
    p = ao.plan(c, spec, scope=ZPA)
    with pytest.raises(PermissionError):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=False, assessor=ASSESSOR)
    with pytest.raises(ao.OperationError):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor="")
    c.tenant.reads.clear()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZPA)
    assert c.tenant.reads == [] and c.tenant.writes == []


def test_a_refused_edge_write_is_reported_failed_and_nothing_else_is_sent():
    """ASVS V7.4.1 · CWE-755: ZPA refusing the PUT marks the edge failed with the reason; no Undo is offered for it."""
    c = ZpaClient()
    s = c.tenant.seed()
    c.tenant.fail[("update", "service_edge")] = "HTTP 400: invalid.request"
    _p, r = _apply(c, _spec(s["se"]["id"], False))
    assert r["status"] in ("failed", "nothing_applied") and [u["status"] for u in r["items"] if u["object"]["type"] == "zpa_service_edge"][0] == "failed"
    assert r["inverse"] is None and c.tenant.rows["service_edge"][s["se"]["id"]]["enabled"] is True
