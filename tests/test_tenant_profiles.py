"""
Tenant profiles: one saved record per customer tenant with credentials
(secret only when explicitly remembered, never returned), engagement
context (industry, baseline packs) and a history of assessments and
journey positions. The API fills blank credentials from a profile.
"""
from __future__ import annotations

import json
import os

import pytest

import tenant_profiles as tp


@pytest.fixture(autouse=True)
def store(tmp_path, monkeypatch):
    p = tmp_path / "profiles.json"
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(p))
    return p


def test_upsert_masks_secret_and_remembers_only_when_asked(store):
    row = tp.upsert({"name": "Acme Health", "org_name": "Acme Health System", "cloud": "production",
                     "vanity_domain": "acme", "client_id": "abc123", "industry": "Healthcare",
                     "baseline_packs": ["healthcare_phi_baseline"]}, client_secret="s3cret", remember_secret=False)
    assert row["id"] == "acme-health" and row["has_secret"] is False
    assert "client_secret" not in row and "client_secret" not in json.dumps(tp.list_profiles())
    row = tp.upsert({"name": "Acme Health"}, client_secret="s3cret", remember_secret=True, profile_id="acme-health")
    assert row["has_secret"] is True
    assert tp.get("acme-health", with_secret=True)["client_secret"] == "s3cret"
    assert "client_secret" not in tp.get("acme-health")
    # Blank secret keeps the remembered one; remember_secret=False forgets it.
    assert tp.upsert({"notes": "x"}, client_secret="", remember_secret=True, profile_id="acme-health")["has_secret"] is True
    assert tp.upsert({"notes": "y"}, client_secret="", remember_secret=False, profile_id="acme-health")["has_secret"] is False
    # Store is owner-only where the OS supports it.
    if os.name == "posix":
        assert oct(os.stat(store).st_mode & 0o777) == "0o600"


def test_history_is_appended_and_capped():
    tp.upsert({"name": "Beta"}, profile_id="beta")
    for i in range(tp.HISTORY_LIMIT + 5):
        tp.add_history("beta", {"score": i})
    p = tp.get("beta")
    assert len(p["history"]) == tp.HISTORY_LIMIT
    assert p["history"][-1]["score"] == tp.HISTORY_LIMIT + 4 and p["last_assessed"]["score"] == tp.HISTORY_LIMIT + 4
    assert all("at" in h for h in p["history"])
    assert tp.add_history("nope", {"score": 1}) is None
    assert tp.delete("beta") is True and tp.get("beta") is None and tp.delete("beta") is False


def test_snapshot_keeps_score_and_journey_only():
    report = {"score": 72, "maturity": "Managed", "checks": [1, 2, 3], "critical": [1], "metadata": {"assessor": "Jane"},
              "journey": {"status": "in_progress", "stage": 3, "score": 80,
                          "baselines": [{"id": "phi", "name": "PHI", "stage": 3, "stage_name": "Visibility", "score": 80,
                                         "state": "in_progress", "next_steps": ["a", "b", "c", "d"], "objects": [{"big": 1}]}]}}
    snap = tp.snapshot(report)
    assert snap["score"] == 72 and snap["critical"] == 1 and snap["journey"]["stage"] == 3
    assert snap["journey"]["baselines"][0]["next_steps"] == ["a", "b", "c"]
    assert "objects" not in snap["journey"]["baselines"][0]
    assert "journey" not in tp.snapshot({"score": 1, "journey": {"status": "error", "error": "boom"}})


def test_api_roundtrip_and_credential_fill():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv

    c = TestClient(srv.app)
    r = c.post("/api/tenant-profiles", json={"name": "Acme Health", "org_name": "Acme Health System", "assessor": "Jane",
                                             "cloud": "production", "vanity_domain": "acme", "client_id": "clientid1",
                                             "client_secret": "topsecret", "remember_secret": True,
                                             "industry": "Healthcare", "baseline_packs": ["healthcare_phi_baseline"],
                                             "scopes": ["dlp"], "notes": "Kickoff in May"})
    assert r.status_code == 200, r.text
    row = r.json()
    assert row["id"] == "acme-health" and row["has_secret"] is True and "topsecret" not in r.text
    lst = c.get("/api/tenant-profiles").json()
    assert [p["id"] for p in lst["profiles"]] == ["acme-health"] and "topsecret" not in json.dumps(lst)
    assert c.get("/api/tenant-profiles/acme-health").json()["baseline_packs"] == ["healthcare_phi_baseline"]
    # Blank credentials in a request are filled from the profile, remembered secret included.
    creds = srv._tenant_creds(srv.TenantCredsRequest(profile_id="acme-health"))
    assert creds["client_id"] == "clientid1" and creds["client_secret"] == "topsecret" and creds["vanity_domain"] == "acme"
    # Typed values win over the profile.
    creds = srv._tenant_creds(srv.TenantCredsRequest(profile_id="acme-health", client_id="other", client_secret="x"))
    assert creds["client_id"] == "other" and creds["client_secret"] == "x"
    assert c.post("/api/tenant-profiles", json={"vanity_domain": "bad domain!"}).status_code == 400
    assert c.delete("/api/tenant-profiles/acme-health").status_code == 200
    assert c.get("/api/tenant-profiles/acme-health").status_code == 404


def test_write_mode_switch_requires_phrase_and_localhost(monkeypatch):
    from fastapi.testclient import TestClient
    import security
    import dlp_api_server as srv

    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setenv("ZSCALER_BIND_HOST", "127.0.0.1")
    monkeypatch.setattr(security, "_write_override", None)
    c = TestClient(srv.app)
    st = c.get("/api/write-mode").json()
    assert st["enabled"] is False and st["source"] == "default" and st["can_toggle"] is True
    assert c.post("/api/write-mode", json={"enable": True, "confirm": "yes"}).status_code == 403
    assert security.writes_enabled() is False
    on = c.post("/api/write-mode", json={"enable": True, "confirm": "YES_I_UNDERSTAND"})
    assert on.status_code == 200 and on.json()["enabled"] is True and on.json()["source"] == "session"
    assert security.writes_enabled() is True
    off = c.post("/api/write-mode", json={"enable": False}).json()
    assert off["enabled"] is False and security.writes_enabled() is False
    # Bound to the network: the browser switch is refused, the env var still works.
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    monkeypatch.setattr(security, "_write_override", None)
    r = c.post("/api/write-mode", json={"enable": True, "confirm": "YES_I_UNDERSTAND"})
    assert r.status_code == 403 and "bound to 0.0.0.0" in r.json()["detail"]
    assert c.get("/api/write-mode").json()["can_toggle"] is False
    monkeypatch.setenv("ENABLE_WRITE_ACTIONS", "YES_I_UNDERSTAND")
    assert security.writes_enabled() is True and c.get("/api/write-mode").json()["source"] == "environment"
