"""Continuous evaluation, release round 1:

- incidents that were never read are never counted as "no incident": no
  rule is called dead, no "Disable <rule>" proposal is raised and no
  history entry records 0 incidents (BUGS1-1);
- a classic-API profile is never named or keyed by a vanity domain left in
  the form: not in the digest, the digest files, the proposal store or the
  saved profile (UR3-continuous-eval-digest-vanity, user rule 3).
"""
from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

import continuous_eval as ce
import detection_health
import dlp_api_server as srv
import proposals
import security
import tenant_profiles as tp
from test_continuous_eval import _env


@pytest.fixture(autouse=True)
def _remember_secrets_in_the_profile_file(monkeypatch):
    # No credential store in the tests: remembering a secret in the profile
    # file is the explicit opt-in (DLP_CHECK_SECRET_STORE=file).
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")


RULES = [{"id": 1, "name": "PCI block", "channel": "endpoint", "state": "ENABLED", "action": "BLOCK", "engines": ["PCI"]},
         {"id": 2, "name": "PII monitor", "channel": "endpoint", "state": "ENABLED", "action": "ALLOW", "engines": ["PII"]}]


def _fake_inventory(monkeypatch, fetched):
    monkeypatch.setattr("pack_removal.inventory", lambda client, channels=None: {"status": "ok", "rules": [dict(r) for r in RULES], "dictionaries": {}})
    monkeypatch.setattr(detection_health, "fetch_incidents", lambda client, days, log: fetched.append(1) or ([], []))


# ── BUGS1-1: unread incidents are not "no incident" ─────────────────────

def test_a_report_without_incidents_read_calls_no_rule_dead_and_raises_no_disable(monkeypatch):
    fetched = []
    _fake_inventory(monkeypatch, fetched)
    rep = detection_health.generate(object(), channels=["endpoint"], read_incidents=False)
    assert fetched == [] and rep["read"]["incidents"] is False and rep["errors"] == []
    assert rep["summary"]["dead_rules"] == 0 and not any(f["kind"] == "dead_rule" for f in rep["findings"]), rep["findings"]
    assert all(r["status"] == "not_measured" for r in rep["rules"]), [r["status"] for r in rep["rules"]]
    assert not [p for p in proposals.build_proposals(rep, "acme") if p["kind"] == "retire_rule"]


def test_a_failed_incident_read_calls_no_rule_dead(monkeypatch):
    monkeypatch.setattr("pack_removal.inventory", lambda client, channels=None: {"status": "ok", "rules": [dict(r) for r in RULES], "dictionaries": {}})
    monkeypatch.setattr(detection_health, "fetch_incidents", lambda client, days, log: ([], ["Workflow Automation incident search: HTTP 403"]))
    rep = detection_health.generate(object(), channels=["endpoint"])
    assert rep["read"]["incidents"] is False and rep["summary"]["dead_rules"] == 0
    assert not [p for p in proposals.build_proposals(rep, "acme") if p["kind"] == "retire_rule"]


def test_incidents_read_and_none_found_still_finds_dead_rules(monkeypatch):
    fetched = []
    _fake_inventory(monkeypatch, fetched)
    rep = detection_health.generate(object(), channels=["endpoint"], read_incidents=True)
    assert fetched == [1] and rep["read"]["incidents"] is True and rep["summary"]["dead_rules"] == 2


@pytest.mark.parametrize("wa", ["gap", None])
def test_the_loop_with_workflow_automation_not_on_zscaler_proposes_no_disable_and_records_no_zero(tmp_path, monkeypatch, wa):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    fetched = []
    _fake_inventory(monkeypatch, fetched)
    history = []
    monkeypatch.setattr(tp, "add_history", lambda pid, entry: history.append(entry))
    chans = {"endpoint_dlp": "zscaler"}
    if wa:
        chans["workflow_automation"] = wa
    tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": [],
               "scopes": ["dlp"], "channels": chans}, client_secret="secret-secret-secret", remember_secret=True)
    d = ce.run_once(build_client=lambda creds: object(), notify=False)
    t = d["tenants"][0]
    assert fetched == [] and t["errors"] == [], t
    assert not [p for p in proposals.list_queue("acme", include_closed=True) if p["kind"] == "retire_rule"]
    assert t["detection_health"]["incidents"] is None and t["detection_health"]["dead_rules"] is None, t["detection_health"]
    assert history == [], "a run that read no incidents is not a measurement and is not recorded"
    assert "incidents not read" in ce.to_markdown(d)


def test_an_unread_run_does_not_resolve_proposals_raised_when_incidents_were_read(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _fake_inventory(monkeypatch, [])
    monkeypatch.setattr(tp, "add_history", lambda pid, entry: None)
    old = proposals.merge("acme", [{"id": proposals.proposal_id("acme", "promote_rule", "rule:endpoint:PII monitor"), "kind": "promote_rule",
                                    "target": "rule:endpoint:PII monitor", "title": "Promote PII monitor"}])
    assert old["new"] == 1
    tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": [],
               "scopes": ["dlp"], "channels": {"endpoint_dlp": "zscaler", "workflow_automation": "gap"}},
              client_secret="secret-secret-secret", remember_secret=True)
    ce.run_once(build_client=lambda creds: object(), notify=False)
    assert [p["status"] for p in proposals.list_queue("acme", include_closed=True)] == ["open"]


# ── UR3: a classic-API profile is never named by a vanity domain ────────

def _legacy_profile(**extra):
    fields = {"name": "Acme", "cloud": "zscalertwo", "vanity_domain": "acmecorp", "auth_method": "legacy", "username": "api-admin@acme.com",
              "baseline_packs": [], "scopes": ["dlp"], "channels": {"endpoint_dlp": "zscaler", "workflow_automation": "zscaler"}}
    fields.update(extra)
    return tp.upsert(fields, password="pw-pw-pw-pw", api_key="abcdefghijkl", remember_secret=True)["id"]


def _all_text(path):
    out = []
    for root, _dirs, files in os.walk(path):
        for f in files:
            with open(os.path.join(root, f), encoding="utf-8", errors="replace") as fh:
                out.append(fh.read())
    return "\n".join(out)


def test_the_digest_and_proposal_store_never_name_a_classic_tenant_by_its_stale_vanity_domain(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _fake_inventory(monkeypatch, [])
    monkeypatch.setattr(tp, "add_history", lambda pid, entry: None)
    _legacy_profile()
    d = ce.run_once(build_client=lambda creds: object(), notify=False)
    t = d["tenants"][0]
    assert t["errors"] == [] and t["tenant"] == "classic API (zscalertwo)", t
    with open(os.environ["DLPCHECK_PROPOSALS_FILE"], encoding="utf-8") as f:
        store = f.read()
    assert json.loads(store)["tenants"], "the run raised proposals"
    for text in (json.dumps(d, default=str), _all_text(os.environ["DLP_CHECK_DIGESTS"]), store, ce.to_markdown(d)):
        assert "acmecorp" not in text and "api-admin" not in text


def test_a_failing_classic_profile_is_not_named_by_its_vanity_domain_either(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _legacy_profile()
    monkeypatch.setattr(ce, "_evaluate_tenant", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    d = ce.run_once(build_client=lambda creds: object(), notify=False)
    assert d["tenants"][0]["tenant"] == "classic API (zscalertwo)" and "acmecorp" not in json.dumps(d, default=str)


def test_proposals_queued_under_the_stale_vanity_domain_move_to_the_classic_key(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    _fake_inventory(monkeypatch, [])
    monkeypatch.setattr(tp, "add_history", lambda pid, entry: None)
    pid = _legacy_profile()
    target = "rule:endpoint:PCI block"
    proposals.merge("acmecorp", [{"id": proposals.proposal_id("acmecorp", "retire_rule", target), "kind": "retire_rule", "target": target,
                                  "title": "Disable PCI block"}])
    first = proposals.list_queue("acmecorp")[0]["id"]
    proposals.decide("acmecorp", first, "dismiss", by="Jay")
    ce.run_once(build_client=lambda creds: object(), notify=False)
    with open(os.environ["DLPCHECK_PROPOSALS_FILE"], encoding="utf-8") as f:
        data = json.load(f)
    assert "acmecorp" not in data["tenants"]
    key = ce.proposal_key(tp.creds_from(tp.get(pid, with_secret=True)), pid)
    items = proposals.list_queue(key, include_closed=True)
    # The dismissal carried over: the same rule is not raised again as a new open proposal.
    assert [p["status"] for p in items if p["target"] == target] == ["dismissed"], items


def test_saving_a_classic_profile_drops_the_vanity_domain_left_in_the_form(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.post("/api/tenant-profiles", json={"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "workflow_automation": "zscaler"}, "vanity_domain": "acmecorp", "auth_method": "legacy", "username": "api-admin@acme.com",
                                             "cloud": "zscalertwo", "password": "pw-pw-pw-pw", "api_key": "abcdefghijkl", "remember_secret": True})
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["vanity_domain"] == "" and "acmecorp" not in got["name"] and "api-admin" not in got["name"], got
    # A OneAPI profile keeps its vanity domain.
    r = c.post("/api/tenant-profiles", json={"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"})
    assert r.status_code == 200 and r.json()["vanity_domain"] == "acme" and r.json()["name"] == "acme"


def test_the_detection_health_report_keys_a_classic_tenant_without_its_vanity_domain(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())
    from test_ssl_flow import FakeCl
    monkeypatch.setattr(srv, "_build_client", lambda req: FakeCl({}))
    monkeypatch.setattr(detection_health, "generate", lambda client, **kw: {"findings": [], "rules": [], "summary": {}, "errors": [], "read": {"incidents": True, "rules": True}})
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.post("/api/detection-health", json={"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "workflow_automation": "zscaler"}, "vanity_domain": "acmecorp", "auth_method": "legacy", "username": "api-admin@acme.com",
                                              "password": "pw-pw-pw-pw", "api_key": "abcdefghijkl", "cloud": "zscalertwo"})
    assert r.status_code == 200, r.text
    assert r.json()["tenant_key"].startswith("classic-") and "acmecorp" not in r.text and "api-admin" not in r.text
    # OneAPI keeps the vanity domain as its queue key.
    r = c.post("/api/detection-health", json={"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "workflow_automation": "zscaler"}, "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"})
    assert r.status_code == 200 and r.json()["tenant_key"] == "acme"
