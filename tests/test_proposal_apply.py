"""Continuous evaluation, phase 3: an approved proposal is applied through
the deploy path (write gate, re-read, update, read-back) and can be
rolled back; drift since the proposal was raised refuses the change."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import proposal_apply as pa
import proposals as pr
import security
from test_pack_deploy import FakeClient, Obj
from test_proposals import REPORT, _store


def _queue(tenant="acme"):
    pr.refresh_from_report(REPORT, tenant)
    return {p["kind"] + ":" + p["target"]: p for p in pr.list_queue(tenant)}


def _client(action="ALLOW"):
    return FakeClient(rules=[Obj(id=7003, name="Old-Monitor", order=1, rank=7, action=action, state="ENABLED",
                                 dlp_engines=[{"id": 5100}], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_HIGH",
                                 last_modified_time=123, zscaler_incident_receiver=False)])


def test_preview_apply_read_back_and_rollback(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    q = _queue()
    promo = q["promote_rule:rule:web:Old-Monitor"]
    pr.decide("acme", promo["id"], "approve", by="jane", confirm="I UNDERSTAND")
    client = _client()
    pv = pa.preview(client, "acme", promo["id"])
    assert pv["ok"] and pv["changes"] == 1 and pv["field"] == "action"
    step = pv["steps"][0]
    assert step["current"] == "ALLOW" and step["to"] == "CONFIRM" and step["rule_id"] == 7003

    out = pa.apply(client, "acme", promo["id"], writes_enabled=True, by="jane")
    assert out["ok"] and out["status"] == "applied" and out["changed"] == 1
    assert out["results"][0]["verified"] and out["results"][0]["read_back"] == "CONFIRM"
    sent = client.zia.dlp_web_rules.updated[-1]
    assert sent["id"] == 7003 and sent["action"] == "CONFIRM" and "last_modified_time" not in sent and sent["name"] == "Old-Monitor"
    rec = pr.get("acme", promo["id"])
    assert rec["status"] == "applied" and rec["applied"]["before"] == {"7003": "ALLOW"} and rec["history"][-1]["decision"] == "applied"

    # Roll back puts the recorded value back and verifies it.
    back = pa.preview(client, "acme", promo["id"], direction="rollback")
    assert back["ok"] and back["steps"][0]["to"] == "ALLOW" and back["steps"][0]["current"] == "CONFIRM"
    out = pa.rollback(client, "acme", promo["id"], writes_enabled=True, by="jane")
    assert out["ok"] and out["status"] == "rolled_back" and client.zia.dlp_web_rules.items[0].action == "ALLOW"
    assert pr.get("acme", promo["id"])["status"] == "rolled_back"


def test_drift_since_the_proposal_refuses_and_gates_hold(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    q = _queue()
    promo = q["promote_rule:rule:web:Old-Monitor"]
    # Not approved yet: nothing is applied.
    with pytest.raises(ValueError, match="not approved"):
        pa.apply(_client(), "acme", promo["id"], writes_enabled=True)
    pr.decide("acme", promo["id"], "approve", confirm="I UNDERSTAND")
    # Write mode off: refused before anything is read.
    with pytest.raises(PermissionError):
        pa.apply(_client(), "acme", promo["id"], writes_enabled=False)
    # The tenant moved since the evidence was gathered (someone set BLOCK): refused, recorded, still approved.
    client = _client(action="BLOCK")
    pv = pa.preview(client, "acme", promo["id"])
    assert not pv["ok"] and "not ALLOW as when the proposal was raised" in pv["steps"][0]["why"]
    with pytest.raises(ValueError, match="refused"):
        pa.apply(client, "acme", promo["id"], writes_enabled=True)
    assert client.zia.dlp_web_rules.updated == [] and pr.get("acme", promo["id"])["status"] == "approved"
    # A rule that disappeared is reported, not guessed.
    gone = FakeClient(rules=[])
    assert "no longer exists" in pa.preview(gone, "acme", promo["id"])["steps"][0]["why"]
    # Manual proposals (dictionary tuning) are not applied from here.
    tune = q["tune_dictionary:dictionary:SSN - High"]
    with pytest.raises(ValueError, match="ZIA portal"):
        pa.preview(_client(), "acme", tune["id"])


def test_forwarding_proposal_touches_every_silent_rule_by_name(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    q = _queue()
    fwd = q["enable_incident_forwarding:delivery:web:silent"]
    pr.decide("acme", fwd["id"], "approve")
    client = _client()
    pv = pa.preview(client, "acme", fwd["id"])
    assert pv["ok"] and pv["steps"][0]["name"] == "Old-Monitor" and pv["steps"][0]["current"] is False and pv["steps"][0]["to"] is True
    out = pa.apply(client, "acme", fwd["id"], writes_enabled=True)
    assert out["ok"] and client.zia.dlp_web_rules.items[0].zscaler_incident_receiver is True


def test_http_routes_gate_writes_and_confirmation(tmp_path, monkeypatch):
    _store(tmp_path, monkeypatch)
    q = _queue()
    promo = q["promote_rule:rule:web:Old-Monitor"]
    pr.decide("acme", promo["id"], "approve", confirm="I UNDERSTAND")
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _client())
    creds = {"cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    r = c.post(f"/api/proposals/acme/{promo['id']}/preview", json=creds)
    assert r.status_code == 200 and r.json()["ok"] and r.json()["steps"][0]["to"] == "CONFIRM"
    assert c.post(f"/api/proposals/acme/{promo['id']}/apply", json=creds).status_code == 400          # confirm missing
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    assert c.post(f"/api/proposals/acme/{promo['id']}/apply", json={**creds, "confirm": True}).status_code == 403
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    r = c.post(f"/api/proposals/acme/{promo['id']}/apply", json={**creds, "confirm": True, "by": "jane"})
    assert r.status_code == 200 and r.json()["status"] == "applied" and r.json()["results"][0]["verified"]
    assert c.post(f"/api/proposals/acme/{promo['id']}/apply", json={}).status_code == 400, "no credentials: explained, not attempted"


# --- the proposal's tenant and the classic API (F2-1, F2-2, FE2-2) -----------------

def _routes(tmp_path, monkeypatch, tenant):
    _store(tmp_path, monkeypatch)
    promo = _queue(tenant)["promote_rule:rule:web:Old-Monitor"]
    pr.decide(tenant, promo["id"], "approve", confirm="I UNDERSTAND")
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    return c, promo


def test_a_proposal_is_never_previewed_applied_or_rolled_back_on_another_tenant(tmp_path, monkeypatch):
    c, promo = _routes(tmp_path, monkeypatch, "acme")
    built = []
    globex = _client()

    def build(creds):
        built.append(creds.get("vanity_domain"))
        return globex
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    other = {"cloud": "production", "vanity_domain": "globex", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    for step, body in (("preview", other), ("apply", {**other, "confirm": True}), ("rollback", {**other, "confirm": True})):
        r = c.post(f"/api/proposals/acme/{promo['id']}/{step}", json=body)
        assert r.status_code == 409, (step, r.text)
        assert "globex" not in r.json()["detail"] or "another tenant" in r.json()["detail"]
    assert built == [], "the other tenant is never signed in to"
    assert globex.zia.dlp_web_rules.updated == [] and pr.get("acme", promo["id"])["status"] == "approved"
    # The proposal's own tenant (any case in the URL) still works.
    r = c.post(f"/api/proposals/ACME/{promo['id']}/preview", json={**other, "vanity_domain": "acme"})
    assert r.status_code == 200 and built == ["acme"]


def test_a_classic_api_tenant_can_preview_apply_and_roll_back_its_proposals(tmp_path, monkeypatch):
    import tenant_fingerprint
    legacy = {"auth_method": "legacy", "cloud": "zscalertwo", "username": "admin@corp.example",
              "password": "pw-pw-pw-pw", "api_key": "a" * 12, "vanity_domain": "", "client_id": "", "client_secret": ""}
    key = tenant_fingerprint.proposal_key(legacy)
    assert key.startswith("classic-")
    c, promo = _routes(tmp_path, monkeypatch, key)
    client = _client()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    r = c.post(f"/api/proposals/{key}/{promo['id']}/preview", json=legacy)
    assert r.status_code == 200 and r.json()["steps"][0]["to"] == "CONFIRM", r.text
    r = c.post(f"/api/proposals/{key}/{promo['id']}/apply", json={**legacy, "confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    r = c.post(f"/api/proposals/{key}/{promo['id']}/rollback", json={**legacy, "confirm": True})
    assert r.status_code == 200 and r.json()["status"] == "rolled_back", r.text
    # Another classic login is another tenant.
    other = dict(legacy, username="admin@other.example")
    assert c.post(f"/api/proposals/{key}/{promo['id']}/preview", json=other).status_code == 409
    assert c.post(f"/api/proposals/{key}/{promo['id']}/preview", json=dict(legacy, password="")).status_code == 400
