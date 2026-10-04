"""Continuous evaluation and classic-API profiles, release round 2:

- B2-3: moving a classic-API tenant's pre-release proposal queue never
  takes another tenant's queue: not from a vanity domain in the request's
  form, not from a key a OneAPI profile claims, and only once;
- UR2-4: a classic-API profile saved before the release, named and keyed
  by its admin login, is renamed and re-keyed, so neither reaches the
  digest; a new save never names it by the login or the discarded vanity
  domain (user rule 3).
"""
from __future__ import annotations

import glob
import json
import os
import re

from fastapi.testclient import TestClient

import continuous_eval as ce
import detection_health
import dlp_api_server as srv
import proposals
import security
import tenant_profiles as tp
from test_continuous_eval import _env
from test_continuous_eval_unread_and_classic import _fake_inventory, _legacy_profile

import pytest

@pytest.fixture(autouse=True)
def _remember_secrets_in_the_profile_file(monkeypatch):
    # No credential store in the tests: remembering a secret in the profile
    # file is the explicit opt-in (DLP_CHECK_SECRET_STORE=file).
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")


def _loop_env(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _fake_inventory(monkeypatch, [])
    monkeypatch.setattr(tp, "add_history", lambda pid, entry: None)


def _dismissed(tenant, target):
    proposals.merge(tenant, [{"id": proposals.proposal_id(tenant, "retire_rule", target), "kind": "retire_rule", "target": target,
                              "title": "Disable PCI block"}])
    proposals.decide(tenant, proposals.list_queue(tenant)[0]["id"], "dismiss", by="Jay")


def _statuses(tenant, target):
    return [p["status"] for p in proposals.list_queue(tenant, include_closed=True) if p["target"] == target]


def _oneapi_acme():
    tp.upsert({"name": "Acme OneAPI", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": [],
               "scopes": ["dlp"], "channels": {"endpoint_dlp": "zscaler", "workflow_automation": "zscaler"}},
              client_secret="secret-secret-secret", remember_secret=True)


# ── B2-3 ───────────────────────────────────────────────────────────────

def test_a_classic_sign_in_never_takes_the_queue_named_by_the_forms_vanity_domain(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    monkeypatch.setattr(detection_health, "generate", lambda client, **kw: {"findings": [], "rules": [], "summary": {}, "errors": [],
                                                                            "read": {"incidents": True, "rules": True}})
    tgt = "rule:web:PCI block"
    _dismissed("acme", tgt)
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    body = {"auth_method": "legacy", "cloud": "zscalertwo", "username": "admin@tenant-b.org", "password": "pw-pw-pw-pw", "api_key": "abcdefghijkl",
            "vanity_domain": "acme", "scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "workflow_automation": "zscaler"}}
    r = c.post("/api/detection-health", json=body)
    assert r.status_code == 200, r.text
    assert _statuses("acme", tgt) == ["dismissed"]
    assert not proposals.list_queue(r.json()["tenant_key"], include_closed=True)
    # Naming a saved classic profile of another tenant does not help either.
    pid = _legacy_profile(name="Other", vanity_domain="acme", username="admin@other.org")
    r = c.post("/api/detection-health", json=dict(body, profile_id=pid))
    assert r.status_code == 200, r.text
    assert _statuses("acme", tgt) == ["dismissed"]


def test_the_loop_never_moves_a_oneapi_profiles_queue_to_a_classic_profile_with_that_stale_vanity_domain(tmp_path, monkeypatch):
    _loop_env(tmp_path, monkeypatch)
    _oneapi_acme()
    tgt = "rule:endpoint:PCI block"
    _dismissed("acme", tgt)
    _legacy_profile(name="Other", vanity_domain="acme", username="admin@other.org")
    for _ in range(2):
        ce.run_once(build_client=lambda creds: object(), notify=False)
        assert _statuses("acme", tgt) == ["dismissed"], "acme's dismissal is gone from acme's queue"


def test_a_classic_profiles_own_queue_is_moved_once_and_never_again(tmp_path, monkeypatch):
    _loop_env(tmp_path, monkeypatch)
    pid = _legacy_profile()                         # stale vanity domain "acmecorp", no OneAPI profile claims it
    tgt = "rule:endpoint:PCI block"
    _dismissed("acmecorp", tgt)
    ce.run_once(build_client=lambda creds: object(), notify=False)
    key = ce.proposal_key(tp.creds_from(tp.get(pid, with_secret=True)), pid)
    assert _statuses(key, tgt) == ["dismissed"] and not _statuses("acmecorp", tgt)
    assert tp.get(pid)["proposal_queue_migrated"] is True
    # A queue that appears under that domain later (a OneAPI tenant signed in
    # without a profile) is someone else's: it stays where it is.
    _dismissed("acmecorp", "rule:endpoint:Other")
    ce.run_once(build_client=lambda creds: object(), notify=False)
    assert _statuses("acmecorp", "rule:endpoint:Other") == ["dismissed"]


# ── UR2-4 ──────────────────────────────────────────────────────────────

LOGIN = "api-admin@acme.com"


def _pre_release_classic_profile(**extra):
    """A nameless classic profile as main/dev saved it: name = admin login,
    id = slug of it."""
    p = {"id": "api-admin-acme-com", "name": LOGIN, "auth_method": "legacy", "cloud": "zscalerten", "username": LOGIN,
         "password": "Pa55word!", "api_key": "aBcDeFgHiJkL", "scopes": ["dlp"],
         "channels": {"endpoint_dlp": "zscaler", "workflow_automation": "zscaler"}, "baseline_packs": [], "history": []}
    p.update(extra)
    with open(os.environ["DLP_CHECK_PROFILES"], "w", encoding="utf-8") as f:
        json.dump({"version": 1, "profiles": {p["id"]: p}}, f)


def test_a_classic_profile_named_by_its_admin_login_never_names_the_digest(tmp_path, monkeypatch):
    _loop_env(tmp_path, monkeypatch)
    _pre_release_classic_profile()
    tgt = "rule:endpoint:PCI block"
    _dismissed("api-admin-acme-com", tgt)           # the loop queued it under the profile id before the release
    d = ce.run_once(build_client=lambda creds: object(), notify=False)
    t = d["tenants"][0]
    assert t["errors"] == [] and t["name"] == "classic API (zscalerten)" and t["profile_id"] == "classic-api-zscalerten", t
    texts = [json.dumps(d, default=str), ce.to_markdown(d)]
    for f in glob.glob(os.path.join(os.environ["DLP_CHECK_DIGESTS"], "*")):
        texts.append(os.path.basename(f))
        with open(f, encoding="utf-8") as fh:
            texts.append(fh.read())
    with open(os.environ["DLP_CHECK_PROFILES"], encoding="utf-8") as f:
        texts.append(json.dumps(json.load(f)["profiles"]["classic-api-zscalerten"]["name"]))
    with open(os.environ["DLPCHECK_PROPOSALS_FILE"], encoding="utf-8") as f:
        texts.append(f.read())
    for text in texts:
        assert LOGIN not in text and "api-admin-acme-com" not in text
    # The secrets came along and the decision carried over.
    full = tp.get("classic-api-zscalerten", with_secret=True)
    assert full["password"] == "Pa55word!" and full["api_key"] == "aBcDeFgHiJkL"
    key = ce.proposal_key(tp.creds_from(full), "classic-api-zscalerten")
    assert _statuses(key, tgt) == ["dismissed"]


def test_a_classic_profile_named_by_its_stale_vanity_domain_is_renamed(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    _pre_release_classic_profile(id="acmecorp", name="AcmeCorp", vanity_domain="acmecorp")
    rows = tp.list_profiles()
    assert [(r["id"], r["name"]) for r in rows] == [("classic-api-zscalerten", "classic API (zscalerten)")]
    # A profile the operator named stays as it is.
    _pre_release_classic_profile(id="customer-x", name="Customer X")
    assert [(r["id"], r["name"]) for r in tp.list_profiles()] == [("customer-x", "Customer X")]


def test_saving_a_classic_profile_named_by_the_login_or_the_discarded_vanity_domain_is_renamed(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    base = {"auth_method": "legacy", "username": LOGIN, "cloud": "zscalertwo", "password": "pw-pw-pw-pw", "api_key": "abcdefghijkl",
            "remember_secret": True, "scopes": ["dlp"]}
    for extra in ({"name": "acmecorp", "vanity_domain": "acmecorp"}, {"name": LOGIN}, {"org_name": LOGIN}, {}):
        r = c.post("/api/tenant-profiles", json=dict(base, **extra))
        assert r.status_code == 200, r.text
        got = r.json()
        assert got["name"] == "classic API (zscalertwo)" and "acme" not in got["id"] and "acme" not in json.dumps(got.get("org_name")), got


def test_the_guide_never_names_a_classic_profile_by_the_hidden_vanity_domain():
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "guide.js"), encoding="utf-8") as f:
        js = f.read()
    body = js[js.index("function _gdProfileFormValues()"):js.index("async function _gdProfileSave(")]
    name = re.search(r"^\s*name:(.*)$", body, re.M).group(1)
    assert "_gdLegacy() ? '' : _gdVal('vd')" in name, name
    assert "vanity_domain: _gdLegacy() ? '' : _gdVal('vd')" in body
