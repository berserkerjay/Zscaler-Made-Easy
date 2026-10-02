"""
Classic-API tenants on one cloud are told apart by a keyed, one-way
fingerprint (tenant_fingerprint): HMAC-SHA256 of the cloud and the admin
login under an install-local key. Two such tenants cannot undo or remove
each other's deployments, records written before the fingerprint still
work, the fingerprint never reaches an API response or the UI, and the
rate-limit history stays apart per tenant. No tenant is ever called.
"""
from __future__ import annotations

import glob
import hashlib
import json
import os
import re
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import deployments
import pack_deploy as pd
import pack_removal as pr
import tenant_auth
import tenant_fingerprint as tf
import zia_rate

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
A = {"auth_method": "legacy", "username": "admin@acme.com", "password": "pw", "api_key": "k" * 12,
     "vanity_domain": "acme-stale", "cloud": "zscalerten"}
B = dict(A, username="admin@other.com", vanity_domain="")
CREATED = {"results": [{"kind": "dictionary", "name": "d", "id": 1, "status": "created"}]}


@pytest.fixture
def server(monkeypatch, tmp_path):
    import dlp_api_server as srv
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())       # never a real tenant
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [{"id": "alpha"}])
    monkeypatch.setattr(pd, "apply", lambda client, packs, **kw: dict(CREATED, status="applied", summary={"created": 1}))
    monkeypatch.setattr(pd, "undo", lambda client, rec, **kw: {"status": "undone", "complete": True, "results": []})
    monkeypatch.setattr(pr, "plan_removal_deployment", lambda client, rec: {"items": [], "plan_hash": "h"})
    return srv, TestClient(srv.app)


def _deploy(c, creds):
    # A pack push names its assessor (it is refused without one).
    r = c.post("/api/dlp-packs/alpha/import", json=dict(creds, plan_hash="h", assessor="Jane Doe"))
    assert r.status_code == 200, r.text
    return deployments._read()["deployments"][-1], r


# --- the fingerprint ------------------------------------------------------------

def test_the_fingerprint_is_keyed_short_and_names_nobody(monkeypatch, tmp_path):
    fa, fb = tf.fingerprint(A), tf.fingerprint(B)
    assert re.fullmatch(r"[0-9a-f]{16}", fa) and fa != fb
    assert tf.fingerprint(dict(A, username=" ADMIN@Acme.com ")) == fa          # the login is normalized
    assert tf.fingerprint(dict(A, vanity_domain="whatever")) == fa              # a stale vanity domain plays no part
    assert tf.fingerprint(dict(A, cloud="zscalertwo")) != fa                    # one login on two clouds: two tenants
    assert tf.fingerprint({"auth_method": "oneapi", "vanity_domain": "acme", "client_id": "c", "cloud": "zscalerten"}) == ""
    # Not guessable from a known login without the key: no plain hash of the inputs matches it...
    for raw in ("classic|zscalerten|admin@acme.com", "zscalerten|admin@acme.com", "admin@acme.com", "zscalerten|acme-stale|admin@acme.com"):
        assert hashlib.sha256(raw.encode()).hexdigest()[:16] != fa
    assert tf.legacy_unkeyed_key(A) != fa
    # ...and another install's key gives another fingerprint for the same login.
    monkeypatch.setenv("DLP_CHECK_FINGERPRINT_KEY", str(tmp_path / "other.key"))
    assert tf.fingerprint(A) not in ("", fa)


def test_the_key_is_created_once_owner_only_next_to_the_deployment_records(monkeypatch, tmp_path):
    monkeypatch.delenv("DLP_CHECK_FINGERPRINT_KEY", raising=False)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "data" / "deployments.json"))
    tf._reset_cache()
    first = tf.fingerprint(A)
    path = tmp_path / "data" / tf.KEY_FILE
    assert path.exists() and tf.key_path() == str(path)
    text = path.read_text()
    assert re.fullmatch(r"[0-9a-f]{64}", text.strip()) and "acme" not in text
    if os.name == "posix":
        assert (path.stat().st_mode & 0o077) == 0
    tf._reset_cache()
    assert tf.fingerprint(A) == first and path.read_text() == text          # kept across restarts
    assert tf.KEY_FILE in open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read().split()
    assert tf.KEY_FILE in open(os.path.join(ROOT, ".dockerignore"), encoding="utf-8").read().split()


def test_without_a_usable_key_classic_tenants_fall_back_to_the_label(monkeypatch, tmp_path):
    monkeypatch.setattr(tf, "install_key", lambda: None)
    assert tf.fingerprint(A) == "" and tf.record_ids(A) == {}
    assert tf.tenant_key(A) == tf.tenant_key(B) and "acme" not in tf.tenant_key(A)
    assert tf.same_tenant({"tenant_label": "classic API (zscalerten)"}, B)


# --- undo and removal -------------------------------------------------------------

def test_two_classic_api_tenants_on_one_cloud_cannot_undo_or_remove_each_others_deployment(server):
    srv, c = server
    rec, _ = _deploy(c, A)
    assert rec["tenant_label"] == "classic API (zscalerten)" and rec["tenant_fp"] == tf.fingerprint(A)
    assert "tenant_key" not in rec and "acme" not in json.dumps(rec) and "admin@" not in json.dumps(rec)
    r = c.post(f"/api/deployments/{rec['id']}/undo", json=dict(B, confirm=True))
    assert r.status_code == 409 and "another classic API (zscalerten) tenant" in r.json()["detail"]
    r = c.post("/api/dlp-packs/removal/preflight", json=dict(B, deployment_id=rec["id"]))
    assert r.status_code == 409
    with pytest.raises(srv.HTTPException) as ex:
        srv._deployment_for_removal(srv.PackRemovalRequest(deployment_id=rec["id"]), tenant_auth.normalize(B))
    assert ex.value.status_code == 409
    # The same login with another stale vanity domain is the same tenant.
    mine = dict(A, vanity_domain="")
    assert c.post("/api/dlp-packs/removal/preflight", json=dict(mine, deployment_id=rec["id"])).status_code == 200
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(mine, confirm=True)).status_code == 200


def test_a_oneapi_tenant_cannot_undo_a_classic_api_deployment(server):
    _, c = server
    rec, _ = _deploy(c, A)
    oneapi = {"auth_method": "oneapi", "vanity_domain": "acme", "client_id": "cid", "client_secret": "s", "cloud": "zscalerten"}
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(oneapi, confirm=True)).status_code == 409


@pytest.mark.parametrize("label", ["classic API (zscalerten)", "acme-stale (zscalerten)"])
def test_a_record_written_before_the_fingerprint_still_undoes(server, label):
    srv, c = server
    old = deployments.add(deployments.from_apply(CREATED, tenant_label=label, packs=["alpha"], options={}))
    assert "tenant_fp" not in old and "tenant_key" not in old
    assert srv._deployment_for_removal(srv.PackRemovalRequest(deployment_id=old["id"]), tenant_auth.normalize(A))["id"] == old["id"]
    assert c.post(f"/api/deployments/{old['id']}/undo", json=dict(A, confirm=True)).status_code == 200


def test_a_record_with_the_earlier_unkeyed_key_still_undoes_for_its_own_tenant_only(server):
    _, c = server
    rec = deployments.from_apply(CREATED, tenant_label="classic API (zscalerten)", packs=["alpha"], options={})
    rec["tenant_key"] = tf.legacy_unkeyed_key(A)          # what the previous build wrote
    deployments.add(rec)
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(B, confirm=True)).status_code == 409
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(A, confirm=True)).status_code == 200


def test_oneapi_records_keep_the_vanity_domain_label_and_their_key(server):
    _, c = server
    one = {"auth_method": "oneapi", "vanity_domain": "acme", "client_id": "cid", "client_secret": "s", "cloud": "zscalerten"}
    rec, _ = _deploy(c, one)
    assert rec["tenant_label"] == "acme (zscalerten)" and rec.get("tenant_key") and "tenant_fp" not in rec
    other = dict(one, vanity_domain="other")
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(other, confirm=True)).status_code == 409
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(one, confirm=True)).status_code == 200


# --- never shown -------------------------------------------------------------------

def test_the_fingerprint_never_appears_in_an_api_response_or_the_ui(server, monkeypatch):
    srv, c = server
    fp = tf.fingerprint(A)
    rec, r = _deploy(c, A)
    bodies = [r.text,
              c.get("/api/deployments").text,
              c.get("/api/deployments", params={"tenant_label": "classic API (zscalerten)"}).text,
              c.post("/api/dlp-packs/removal/preflight", json=dict(A, deployment_id=rec["id"])).text,
              c.post("/api/rate-check", json=dict(A, counts={"write": 2})).text,
              c.post(f"/api/deployments/{rec['id']}/undo", json=dict(A, confirm=True)).text,
              c.post(f"/api/deployments/{rec['id']}/undo", json=dict(B, confirm=True)).text]
    for body in bodies:
        assert fp not in body and "tenant_fp" not in body and "tenant_key" not in body
        assert "admin@acme.com" not in body and "acme-stale" not in body
    assert "tenant_fp" not in deployments.summary(rec)
    for path in glob.glob(os.path.join(ROOT, "static", "*")):
        if os.path.isfile(path):
            text = open(path, encoding="utf-8", errors="replace").read()
            assert "tenant_fp" not in text and "tenant_fingerprint" not in text, path


# --- rate-limit history --------------------------------------------------------------

def test_the_rate_limit_history_stays_apart_per_classic_api_tenant(server):
    srv, c = server
    rec, _ = _deploy(c, A)
    data = deployments._read()
    data["deployments"][-1]["at"] = datetime.now(timezone.utc).isoformat()
    data["deployments"][-1]["failed"] = [{"kind": "engine", "name": "e", "error": "HTTP 429 Rate Limit (1/SECOND) exceeded"}]
    deployments._write(data)
    ka, kb = srv._tenant_key(tenant_auth.normalize(A)), srv._tenant_key(tenant_auth.normalize(B))
    assert ka == tf.fingerprint(A) and kb == tf.fingerprint(B) and ka != kb
    fa = c.post("/api/rate-check", json=dict(A, counts={"write": 3})).json()
    fb = c.post("/api/rate-check", json=dict(B, counts={"write": 3})).json()
    assert fa["refused_runs"] and not fb["refused_runs"]
    assert fa["success"]["track_record"]["runs"] == 1 and fb["success"]["track_record"]["runs"] == 0
    # ZIA's refusals in the rate state are kept per fingerprint too, and the
    # state file holds no plain hash of the login.
    zia_rate.note_refusal("write", "HTTP 429 Rate Limit (1/SECOND) exceeded", key=ka, status=429)
    assert c.post("/api/rate-check", json=dict(A, counts={"write": 3})).json()["refused_last_hour"] == 1
    assert c.post("/api/rate-check", json=dict(B, counts={"write": 3})).json()["refused_last_hour"] == 0
    state = open(zia_rate.state_path(), encoding="utf-8").read()
    assert ka in state and tf.legacy_unkeyed_key(A) not in state and "admin@acme.com" not in state


def test_the_assessment_client_counts_a_classic_tenant_under_its_fingerprint():
    from dlp_assessment_full_auto import Client
    cl = Client("", "", "acme-stale", "zscalerten", auth_method="legacy", username="admin@acme.com", password="pw", api_key="k" * 12)
    assert cl.rate_key == tf.fingerprint(A)
    one = Client("cid", "s", "acme", "zscalerten")
    assert one.rate_key == zia_rate.key_for("zscalerten", "acme", "cid")
