"""Data migration: the files the last release before Wave 5 saved still load
and keep working with the current code, or are refused safely; never a
crash.

`tests/fixtures/pre_wave5_stores.json` was written by the release itself
(tools/pre_wave5_fixtures.py, run on commit 9b28a1c): tenant profiles with a
remembered secret, a classic sign-in and assessment history (with and
without per-check states), proposals, the change queue, workspace notes,
posture settings, a deployment, a bulk change and a self-heal run. Each
test copies the stores into its own data folder.
"""
from __future__ import annotations

import json
import os
import urllib.parse
from datetime import datetime, timezone
from typing import Any, Dict

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import proposals

HERE = os.path.dirname(os.path.abspath(__file__))
TENANT = "acme (zscalertwo)"
TQ = urllib.parse.quote(TENANT)

with open(os.path.join(HERE, "fixtures", "pre_wave5_stores.json"), "r", encoding="utf-8") as _f:
    BUNDLE: Dict[str, Any] = json.load(_f)["stores"]

# The moment tools/pre_wave5_fixtures.py saved the bundle (every created_at in
# it). The stores are read as of then: a snooze it saved for a week is still
# a snooze, whatever today's date (the real clock made this test expire).
SAVED_AT = datetime(2026, 10, 29, 0, 57, 23, tzinfo=timezone.utc)

ENV_FOR = {
    "tenant_profiles.json": "DLP_CHECK_PROFILES", "proposals.json": "DLPCHECK_PROPOSALS_FILE",
    "change_requests.json": "DLPCHECK_CHANGE_QUEUE_FILE", "workspace_notes.json": "DLP_CHECK_WORKSPACE_NOTES",
    "posture_settings.json": "DLP_CHECK_POSTURE_SETTINGS", "deployments.json": "DLP_CHECK_DEPLOYMENTS",
    "self_heal_state.json": "DLP_CHECK_SELF_HEAL_STATE",
}


@pytest.fixture
def old_data(tmp_path, monkeypatch):
    """The pre-Wave-5 stores in this test's own folder; secrets in the owner-only file, as they were saved."""
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    monkeypatch.setattr(proposals, "_utcnow", lambda: SAVED_AT)
    for name, env in ENV_FOR.items():
        path = tmp_path / name
        path.write_text(json.dumps(BUNDLE[name]), encoding="utf-8")
        monkeypatch.setenv(env, str(path))
    return tmp_path


@pytest.fixture
def c(old_data):
    return TestClient(srv.app)


def test_the_bundle_holds_every_store_the_release_saved():
    """SSDF PW.8.2 · CWE-440: the fixture bundle carries each store, made by the pre-Wave-5 release (never hand-written)."""
    assert set(BUNDLE) == set(ENV_FOR)
    assert BUNDLE["tenant_profiles.json"]["version"] == 1 and "snapshots" not in BUNDLE["tenant_profiles.json"]


# Every store answers its read route (table-driven: a store added to the
# bundle without a route here fails the test above).
READS = {
    "tenant_profiles.json": "/api/tenant-profiles",
    "proposals.json": f"/api/proposals?tenant={TQ}&include_closed=true",
    "change_requests.json": "/api/change-queue",
    "workspace_notes.json": f"/api/workspace/notes?tenant={TQ}",
    "posture_settings.json": "/api/posture/settings",
    "deployments.json": "/api/deployments",
    "self_heal_state.json": "/api/self-heal",
}


@pytest.mark.parametrize("store", sorted(ENV_FOR))
def test_each_old_store_loads_through_its_route(c, store):
    """SSDF PW.8.2 · CWE-440: each store saved by the pre-Wave-5 release answers its read route with 200."""
    r = c.get(READS[store])
    assert r.status_code == 200, r.text


def test_old_profiles_list_with_their_history_and_no_snapshots(c):
    """SSDF PW.8.2 · CWE-440: old profiles list as before, with their assessment history, and the new snapshot fields empty."""
    body = c.get("/api/tenant-profiles").json()
    by = {p["id"]: p for p in body["profiles"]}
    assert set(by) == {"acme-corp", "classic-tenant", "bare"}
    assert by["acme-corp"]["has_secret"] is True and by["classic-tenant"]["has_secret"] is True and by["bare"]["has_secret"] is False
    assert all(p["snapshots"] == [] for p in body["profiles"]) and body["unfiled_snapshots"] == []
    acme = c.get("/api/tenant-profiles/acme-corp").json()
    assert [h["score"] for h in acme["history"]] == [71, 64, 50]
    assert "fixture-secret-not-real" not in json.dumps(body) and "fixture-password-not-real" not in json.dumps(body)
    assert "fixture-secret-not-real" not in json.dumps(acme), "a remembered secret is never returned"


@pytest.mark.parametrize("profile_id,expect", [
    ("acme-corp", {"auth_method": "oneapi", "cloud": "zscalertwo", "vanity_domain": "acme", "client_id": "cid-acme",
                   "client_secret": "fixture-secret-not-real"}),
    ("classic-tenant", {"auth_method": "legacy", "cloud": "zscloud", "username": "admin@example.com",
                        "password": "fixture-password-not-real", "api_key": "fixturekey00"}),
])
def test_an_old_profiles_remembered_sign_in_still_resolves(old_data, profile_id, expect):
    """SSDF PW.8.2 · CWE-440: a remembered sign-in saved before Wave 5 still resolves to the same credentials (cloud from the profile)."""
    creds = srv._tenant_creds(srv.TenantCredsRequest(profile_id=profile_id))
    assert {k: creds[k] for k in expect} == expect


def test_old_history_feeds_the_posture_summary(c):
    """SSDF PW.8.2 · CWE-440: history entries with and without per-check states still drive the score-drop summary."""
    r = c.post("/api/posture/summary", json={"profile_id": "acme-corp"})
    assert r.status_code == 200, r.text
    assert {"alert", "coverage", "settings"} <= set(r.json())
    assert r.json()["settings"]["score_drop_points"] == 7


def test_old_queues_and_notes_keep_their_content(c):
    """SSDF PW.8.2 · CWE-440: proposals, change requests, notes and records saved before Wave 5 read back with their content."""
    props = c.get(f"/api/proposals?tenant={TQ}&include_closed=true").json()
    assert len(props["items"]) == 2 and props["summary"]["snoozed"] == 1
    queue = c.get("/api/change-queue").json()
    assert sorted(i["status"] for i in queue["items"]) == ["pending", "rejected"]
    pending = next(i for i in queue["items"] if i["status"] == "pending")
    assert [cm["text"] for cm in c.get(f"/api/change-queue/{pending['id']}").json()["request"]["comments"]] == ["please", "looks fine"]
    note = c.get(f"/api/workspace/notes?tenant={TQ}").json()["notes"][0]
    assert note["tags"] == ["urgent"] and [x["text"] for x in note["comments"]] == ["Customer asked about endpoints"]
    assert [t["text"] for t in note["todos"]] == ["Call back"]
    assert [d["id"] for d in c.get("/api/deployments").json()["deployments"]] == ["dep-fixture1"]
    assert c.get("/api/operations/op-fixture1").status_code == 200
    assert c.get("/api/self-heal").json()["last_run"]["trigger"] == "manual"


def test_changing_old_data_keeps_what_was_there(c):
    """SSDF PW.8.2 · CWE-440: updating an old profile, adding a note comment and deleting another profile keep the old history, secret and comments."""
    r = c.post("/api/tenant-profiles", json={"id": "acme-corp", "name": "Acme Corp", "vanity_domain": "acme", "cloud": "zscalertwo",
                                             "client_id": "cid-acme", "assessor": "Dana Two", "remember_secret": True})
    assert r.status_code == 200, r.text
    acme = c.get("/api/tenant-profiles/acme-corp").json()
    assert acme["assessor"] == "Dana Two" and len(acme["history"]) == 3 and acme["has_secret"] is True
    r = c.post("/api/workspace/notes", json={"tenant": TENANT, "kind": "check", "ref": "DLP.2", "action": "add_comment", "text": "second"})
    assert r.status_code == 200, r.text
    note = c.get(f"/api/workspace/notes?tenant={TQ}").json()["notes"][0]
    assert [x["text"] for x in note["comments"]] == ["Customer asked about endpoints", "second"]
    assert c.delete("/api/tenant-profiles/bare").status_code == 200
    assert {p["id"] for p in c.get("/api/tenant-profiles").json()["profiles"]} == {"acme-corp", "classic-tenant"}


def test_a_snapshot_can_be_saved_beside_old_profiles(old_data):
    """SSDF PW.8.2 · CWE-440: the Wave 5 snapshot list is added to an old profile store without touching its profiles."""
    import tenant_profiles
    ref = tenant_profiles.save_snapshot("{}", {"saved_at": "2026-01-01T00:00:00+00:00", "tenant_label": TENANT}, "acme-corp")
    assert ref["profile_id"] == "acme-corp"
    assert [s["id"] for s in tenant_profiles.list_snapshots("acme-corp")] == [ref["id"]]
    assert len(tenant_profiles.get("acme-corp")["history"]) == 3


@pytest.mark.parametrize("snapshots", [["snap-0123456789abcdef"], "text", 7, True])
def test_a_snapshots_entry_of_the_wrong_type_is_ignored_not_a_crash(c, old_data, snapshots):
    """ASVS V5.1.4 · A04:2021 · CWE-20: a profile store whose snapshots entry is not an object still lists and deletes profiles (no 500)."""
    path = old_data / "tenant_profiles.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    data["snapshots"] = snapshots
    path.write_text(json.dumps(data), encoding="utf-8")
    r = c.get("/api/tenant-profiles")
    assert r.status_code == 200, r.text
    assert {p["id"] for p in r.json()["profiles"]} == {"acme-corp", "classic-tenant", "bare"} and r.json()["unfiled_snapshots"] == []
    assert c.delete("/api/tenant-profiles/bare").status_code == 200
    assert {p["id"] for p in c.get("/api/tenant-profiles").json()["profiles"]} == {"acme-corp", "classic-tenant"}
