"""Channel targets per pack (which DLP channels receive the pack's
engines) and undoing a deployment."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

import deployments
import pack_channels as pc
import pack_deploy as pd
from test_pack_channels import TENANTS, make_client, multi_pack  # noqa: F401
from test_pack_deploy import Obj, _dict, _engine, _policy, items_by, write_pack  # noqa: F401

ALL = ["web", "endpoint", "saas", "email"]


def _pack(tmp_path, pack_id="alpha", prefix="ZBP-", policies=None, engines=None):
    return write_pack(
        tmp_path, pack_id,
        dicts=[_dict("Alpha Dict")],
        engines=[_engine("Alpha Engine", "(D:Alpha Dict)")] if engines is None else engines,
        policies=[_policy("Z-Alpha-Monitor", ["Alpha Engine"])] if policies is None else policies,
        meta={"name": "Alpha Pack", "confidence_tweaks": [], "baseline": {"prefix": prefix, "version": "1"}},
    )


def _with_delete(client):
    """Give the fake services delete methods that behave like the API."""
    def deleter(svc, attr="items"):
        def delete(rid, *a, **kw):
            before = len(getattr(svc, attr))
            setattr(svc, attr, [i for i in getattr(svc, attr) if getattr(i, "id", None) != rid])
            return (None, None, None) if len(getattr(svc, attr)) < before else (None, None, {"message": "not found"})
        return delete
    z = client.zia
    z.dlp_web_rules.delete_rule = deleter(z.dlp_web_rules)
    z.endpoint_dlp_rules.delete_rule = deleter(z.endpoint_dlp_rules)
    z.casb_dlp_rules.delete_rule = deleter(z.casb_dlp_rules)
    z.outbound_email_dlp_rules.delete_rule = deleter(z.outbound_email_dlp_rules)
    z.dlp_engine.delete_dlp_engine = deleter(z.dlp_engine)
    z.dlp_dictionary.delete_dict = deleter(z.dlp_dictionary)
    for name in ("cloudappcontrol", "file_type_control_rule", "url_filtering", "ssl_inspection_rules"):
        svc = getattr(z, name, None)
        if svc is not None:
            d = deleter(svc)
            svc.delete_rule = (lambda d: (lambda rule_type, rid: d(rid)))(d) if name == "cloudappcontrol" else d
    return client


# ── Channel targets ───────────────────────────────────────────────────

def test_extension_names_follow_the_prefix_style():
    assert pc.extension_name("endpoint", "ZBP-", "x") == "ZBP-Endpoint DLP Monitor"
    assert pc.extension_name("saas", "R_PHI_", "x") == "R_PHI_SAAS_DLP_MONITOR"
    assert pc.extension_name("email", "", "Healthcare PHI Baseline") == "Healthcare PHI Baseline Email DLP Monitor"
    assert pc.normalize_targets(["Web", "endpoint", "ssl", "nope", "web"]) == ["web", "endpoint"]
    assert pc.normalize_targets(None) is None and pc.normalize_targets([]) == []


def test_targets_extend_missing_channels_and_skip_deselected_ones(tmp_path):
    pack = _pack(tmp_path)
    client = make_client(casb_tenants=TENANTS)
    rep = pd.preflight(client, [pack], writes_enabled=True, channel_targets={"alpha": ALL})
    assert rep["status"] in ("ready", "warnings"), rep["blockers"]
    pol = items_by(rep, "policy")
    assert set(pol) == {"Z-Alpha-Monitor", "ZBP-Endpoint DLP Monitor", "ZBP-SaaS DLP Monitor", "ZBP-Email DLP Monitor"}
    for n in ("ZBP-Endpoint DLP Monitor", "ZBP-SaaS DLP Monitor", "ZBP-Email DLP Monitor"):
        assert pol[n]["status"] == pd.CREATE and pol[n]["extension"] and pol[n]["detail"]["engines"] == ["Alpha Engine"]
    assert pol["ZBP-Endpoint DLP Monitor"]["detail"]["channel"] == "endpoint" and pol["ZBP-Endpoint DLP Monitor"]["detail"]["action"] == "ALLOW"
    assert pol["ZBP-SaaS DLP Monitor"]["detail"]["saas_type"] == "OFLCASB_DLP_FILE" and pol["ZBP-SaaS DLP Monitor"]["detail"]["tenants"] == ["Acme Box", "Acme Google Workspace"]
    assert pol["ZBP-Email DLP Monitor"]["detail"]["tenants"] == ["Acme M365 Mail"]
    assert not pol["Z-Alpha-Monitor"]["extension"]
    note = rep["packs"][0]["channels"]
    assert note["targets"] == ALL and [e["channel"] for e in note["extended"]] == ["endpoint", "saas", "email"] and note["skipped_rules"] == []
    assert rep["summary"]["channels"] == {"web": {"create": 1}, "endpoint": {"create": 1}, "saas": {"create": 1}, "email": {"create": 1}}

    # Endpoint only: the packed web rule is skipped, the endpoint extension is the only rule.
    rep2 = pd.preflight(client, [pack], writes_enabled=True, channel_targets={"alpha": ["endpoint"]})
    pol2 = items_by(rep2, "policy")
    assert set(pol2) == {"ZBP-Endpoint DLP Monitor"}
    assert rep2["packs"][0]["channels"]["skipped_rules"] == ["Z-Alpha-Monitor"] and rep2["packs"][0]["channels"]["skipped_channels"] == ["web"]
    assert rep2["plan_hash"] != rep["plan_hash"] and rep2["options"]["channel_targets"] == {"alpha": ["endpoint"]}
    # No choice at all: the pack as packed.
    rep3 = pd.preflight(client, [pack], writes_enabled=True)
    assert set(items_by(rep3, "policy")) == {"Z-Alpha-Monitor"} and rep3["options"]["channel_targets"] == {}


def test_apply_creates_extension_rules_with_the_pack_engines(tmp_path):
    pack = _pack(tmp_path)
    client = make_client(casb_tenants=TENANTS)
    targets = {"alpha": ["web", "endpoint", "email"]}
    rep = pd.preflight(client, [pack], writes_enabled=True, channel_targets=targets)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, channel_targets=targets, verify=False)
    assert res["status"] == "applied" and res["summary"]["created"] == 5, res["results"]
    ep = client.zia.endpoint_dlp_rules.added[0]
    assert ep["name"] == "ZBP-Endpoint DLP Monitor" and ep["state"] == "DISABLED" and ep["action"] == "ALLOW"
    assert ep["data_transfer_method"] == "ANY" and ep["dlp_engines"] == [{"id": client.zia.dlp_engine.items[0].id}]
    em = client.zia.outbound_email_dlp_rules.added[0]
    assert em["name"] == "ZBP-Email DLP Monitor" and em["email_tenants"] == [{"id": 503}]
    assert client.zia.casb_dlp_rules.added == []
    # The plan hash binds the channel choice: applying an approved plan with a different choice is refused.
    fresh = make_client(casb_tenants=TENANTS)
    approved = pd.preflight(fresh, [pack], writes_enabled=True, channel_targets=targets)
    res2 = pd.apply(fresh, [pack], plan_hash=approved["plan_hash"], writes_enabled=True, channel_targets={"alpha": ["web"]}, verify=False)
    assert res2["status"] == "plan_changed" and fresh.zia.dlp_web_rules.added == []


def test_pack_without_engines_cannot_extend(tmp_path):
    pack = write_pack(tmp_path, "ctl", dicts=[], engines=[],
                      policies=[{"name": "SSL-Decrypt", "channel": "ssl", "state": "DISABLED", "action": {"type": "DECRYPT"}}],
                      meta={"name": "Control Only", "confidence_tweaks": []})
    from test_pack_channels import add_control_services
    client = add_control_services(make_client())
    rep = pd.preflight(client, [pack], writes_enabled=True, channel_targets={"ctl": ["endpoint"]})
    assert set(items_by(rep, "policy")) == {"SSL-Decrypt"}   # containment rules are never part of the choice
    assert any("no engines" in w for w in rep["warnings"])


def test_terraform_honours_channel_targets(tmp_path):
    import pack_terraform as tf
    pack = _pack(tmp_path)
    src = tf.load_pack(pack, ["endpoint", "email"])
    assert [p["name"] for p in src["policies"]] == ["ZBP-Endpoint DLP Monitor", "ZBP-Email DLP Monitor"]
    files = tf.generate(pack, channel_targets=["web", "endpoint"])
    rules = files["rules.tf"]
    assert 'resource "zia_endpoint_dlp_rules"' in rules and "ZBP-Endpoint DLP Monitor" in rules and "Z-Alpha-Monitor" in rules
    assert "zia_outbound_email_dlp" not in rules


# ── Undo ──────────────────────────────────────────────────────────────

@pytest.fixture
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    return tmp_path


def _deploy(tmp_path, client, targets=None):
    pack = _pack(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True, channel_targets=targets)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, channel_targets=targets, verify=False)
    assert res["status"] == "applied", res["results"]
    rec = deployments.from_apply(res, tenant_label="acme (production)", packs=["alpha"], options={}, channel_targets=targets or {})
    return pack, rec


def test_undo_deletes_created_objects_in_dependency_order(store, tmp_path):
    client = _with_delete(make_client(casb_tenants=TENANTS))
    pack, rec = _deploy(tmp_path, client, {"alpha": ["web", "endpoint", "email"]})
    deployments.add(rec)
    assert rec["status"] == "applied" and [c["kind"] for c in rec["created"]].count("policy") == 3
    z = client.zia
    assert len(z.dlp_dictionary.items) == 2 and len(z.dlp_engine.items) == 1 and len(z.dlp_web_rules.items) == 1
    out = pd.undo(client, rec, writes_enabled=True)
    assert out["status"] == "undone" and out["complete"] and out["activation_required"]
    order = [(r["kind"], r["status"]) for r in out["results"]]
    assert [k for k, _ in order] == ["policy", "policy", "policy", "engine", "dictionary"] and all(s == "deleted" for _, s in order)
    assert z.dlp_web_rules.items == [] and z.endpoint_dlp_rules.items == [] and z.outbound_email_dlp_rules.items == [] and z.dlp_engine.items == []
    assert [d.name for d in z.dlp_dictionary.items] == ["Social Security Numbers (US)"]   # the predefined one was never ours
    upd = deployments.mark_undo(rec["id"], out["results"], complete=True)
    assert upd["undone_at"] and all(c.get("undone") for c in upd["created"])
    s = deployments.list_all("acme (production)")[0]
    assert s["remaining"] == 0 and s["created"] == 5 and s["created_by_kind"] == {"dictionary": 1, "engine": 1, "policy": 3}
    # A second undo has nothing left to do.
    again = pd.undo(client, deployments.get(rec["id"]), writes_enabled=True)
    assert again["status"] == "nothing" and again["results"] == []


def test_undo_leaves_renamed_or_shared_objects_alone(store, tmp_path):
    client = _with_delete(make_client())
    pack, rec = _deploy(tmp_path, client)
    z = client.zia
    # The customer renamed the rule and another rule now uses the engine.
    z.dlp_web_rules.items[0].name = "Customer renamed this"
    z.dlp_engine.delete_dlp_engine = lambda rid: (None, None, {"message": "engine is referenced by a rule"})
    out = pd.undo(client, rec, writes_enabled=True)
    by = {r["kind"]: r for r in out["results"]}
    assert by["policy"]["status"] == "skipped" and "now carries the name" in by["policy"]["reason"]
    assert by["engine"]["status"] == "failed" and "referenced" in by["engine"]["error"]
    assert by["dictionary"]["status"] == "deleted"
    assert out["status"] == "partial" and not out["complete"]
    assert len(z.dlp_web_rules.items) == 1
    # Read-only mode never deletes.
    assert pd.undo(client, rec, writes_enabled=False)["status"] == "blocked"
    # Already gone in the tenant: reported, not an error.
    z.dlp_web_rules.items = []
    z.dlp_web_rules.items.clear()
    out2 = pd.undo(client, rec, writes_enabled=True)
    assert {r["kind"]: r["status"] for r in out2["results"]}["policy"] == "gone"


def test_from_apply_ignores_reused_and_records_nothing_when_nothing_created():
    res = {"status": "applied", "results": [{"kind": "dictionary", "name": "D", "status": "reused", "id": 1},
                                            {"kind": "policy", "name": "P", "status": "created", "id": 7, "channel": "web"},
                                            {"kind": "tweak", "name": "T", "status": "modified", "id": 3}]}
    rec = deployments.from_apply(res, tenant_label="t", packs=["a"], options={})
    assert [c["name"] for c in rec["created"]] == ["P"] and [o["name"] for o in rec["other"]] == ["D", "T"]
    assert deployments.from_apply({"status": "applied", "results": [{"kind": "dictionary", "name": "D", "status": "reused", "id": 1}]},
                                  tenant_label="t", packs=[], options={}) is None


def test_undo_endpoints(store, tmp_path, monkeypatch):
    import dlp_api_server as srv
    client = _with_delete(make_client())
    pack, rec = _deploy(tmp_path, client)
    deployments.add(rec)
    c = TestClient(srv.app)
    lst = c.get("/api/deployments").json()
    assert lst["deployments"][0]["id"] == rec["id"] and lst["deployments"][0]["remaining"] == 3
    assert c.get("/api/deployments?tenant_label=other").json()["deployments"] == []
    body = {"cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s3cret-s3cret", "confirm": True}
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=dict(body, confirm=False)).status_code == 400
    assert c.post("/api/deployments/nope/undo", json=body).status_code == 404
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    assert c.post(f"/api/deployments/{rec['id']}/undo", json=body).status_code == 403
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    r = c.post(f"/api/deployments/{rec['id']}/undo", json=dict(body, vanity_domain="other"))
    assert r.status_code == 409 and "Switch tenant" in r.json()["detail"]
    r = c.post(f"/api/deployments/{rec['id']}/undo", json=body)
    assert r.status_code == 200 and r.json()["status"] == "undone" and r.json()["deployment"]["remaining"] == 0
    assert client.zia.dlp_web_rules.items == [] and client.zia.dlp_engine.items == []
