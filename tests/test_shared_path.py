"""The shared execution path (pack_ops) is the only way a policy pack's
objects get into or out of a tenant, whatever the pack.

These tests lock that in:
  - a guard that fails the build if any module other than the shared path
    (and the channel abstraction it calls) names an SDK write method;
  - every shipped pack deploys through it on the strict tenant, deploys
    AGAIN without creating or failing anything (idempotent), and is torn
    down completely by the same executor the removal wizard and the undo
    use (no orphan);
  - transient refusals are retried and reported the same way for every
    kind; a refusal that time cannot clear is reported once, in plain
    words;
  - validation runs before any write and blocks with the reason;
  - every write leaves one structured event with the same keys;
  - the single-pack import endpoint and the verify endpoint go through
    the same path.
"""
from __future__ import annotations

import glob
import os
import re

import pytest

import deployments
import pack_deploy as pd
import pack_ops as ops
import pack_removal as pr
from dlp_importer import discover_packs
from test_channel_targets_undo import _with_delete
from test_pack_channels import TENANTS, _dict, _engine, _policy, add_control_services, make_client, write_pack
from test_zia_contract import strict_tenant

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

WRITE_CALL = re.compile(r"\.(add_dict|add_dlp_engine|add_rule|add_sub_rule|update_dict|update_dlp_engine|update_rule|update_sub_rule|"
                        r"delete_dict|delete_dlp_engine|delete_rule|raw_request|"
                        # Bulk changes (admin_ops): URL categories, ZPA application segments, cloud app sanction.
                        r"add_url_category|update_url_category|add_urls_to_category|delete_urls_from_category|delete_category|"
                        r"add_segment|update_segment|delete_segment|bulk_update|"
                        # The ZPA builder (ops_zpa): its kinds in pack_ops.ZPA_KINDS.
                        r"add_connector_group|update_connector_group|delete_connector_group|add_provisioning_key|update_provisioning_key|"
                        r"delete_provisioning_key|add_group|update_group|delete_group|add_segment_pra|update_segment_pra|delete_segment_pra|"
                        r"add_profile|update_profile|delete_profile|add_console|update_console|delete_console|add_access_rule|"
                        r"update_access_rule|add_timeout_rule|update_timeout_rule|add_app_protection_rule|update_app_protection_rule|"
                        r"add_isolation_rule|update_isolation_rule)\(|\bclient\.(post|put|patch|delete)\(")
# The only files allowed to name an SDK write method, and why.
ALLOWED = {
    "pack_ops.py": "the shared execution path itself",
    "pack_channels.py": "the per-channel SDK adapter pack_ops calls (payload shapes, raw requests)",
    "fed_policy_pack/dlp_stand_alone_import.py": "the original Fed importer, kept as the reference; the app never runs it",
    # Known exceptions, not packs: they write directly (still behind write
    # mode), and the Secure by Design page says so rather than claiming
    # pack_ops is the only writer. Do not add to this list lightly.
    "remediation.py": "assessment fix recipes (POST/PUT/DELETE through the REST client)",
    "rule_migrator.py": "Evaluate All Rules reorder and rule migration (PUT/POST/DELETE through the REST client)",
}


def _py_files():
    for path in glob.glob(os.path.join(ROOT, "**", "*.py"), recursive=True):
        rel = os.path.relpath(path, ROOT).replace(os.sep, "/")
        if rel.startswith(("tests/", "node_modules/", ".venv/", "venv/", "user_packs/")) or "/node_modules/" in rel:
            continue
        yield rel, path


def test_no_module_writes_to_the_tenant_outside_the_shared_path():
    """A future pack, tool or endpoint that calls the SDK directly is
    caught here, with the file and line, before it can diverge."""
    offenders = []
    for rel, path in _py_files():
        if rel in ALLOWED:
            continue
        with open(path, encoding="utf-8") as f:
            for n, line in enumerate(f, 1):
                s = line.strip()
                if s.startswith(("#", "def ", "async def ")):
                    continue
                if WRITE_CALL.search(line):
                    offenders.append(f"{rel}:{n}: {s[:100]}")
    assert not offenders, ("These lines write to the tenant outside pack_ops. Route them through pack_ops.create/update/delete "
                           "(see docs/SHARED_EXECUTION_PATH.md):\n" + "\n".join(offenders))


def test_the_fed_reference_script_is_not_imported_by_the_app():
    for rel, path in _py_files():
        if rel.startswith("fed_policy_pack/"):
            continue
        src = open(path, encoding="utf-8").read()
        assert "dlp_stand_alone_import" not in src, f"{rel} imports the reference script; the app deploys every pack through pack_ops"


def test_every_kind_is_validated_before_any_write():
    assert any("'/'" in p for p in ops.validate("dictionary", {"name": "A / B", "phrases": [{"phrase": "alpha beta"}]}))
    assert any("expression" in p for p in ops.validate("engine", {"name": "E", "expression": ""}))
    assert any("resources" in p for p in ops.validate("app_group", {"name": "G", "resources": []}))
    assert any("31" in p for p in ops.validate("policy", {"name": "SRC-JavaScript Code to AI [SaaS]", "channel": "saas", "saas_type": "OFLCASB_DLP_FILE", "engines": ["e"]}))
    assert any("transfer method" in p for p in ops.validate("policy", {"name": "E", "channel": "endpoint", "engines": ["e"], "data_transfer_method": "ANY"}))
    assert ops.validate("dictionary", {"name": "Fine", "phrases": [{"phrase": "alpha beta"}]}) == []
    assert ops.validate("policy", {"name": "R", "channel": "web", "engines": ["e"]}) == []
    assert ops.validate("nonsense", {"name": "x"}) == ["unknown object kind 'nonsense'"]


def test_a_bad_name_is_stopped_in_the_plan_and_nothing_is_written(tmp_path):
    pack = write_pack(tmp_path / "bad", "bad", dicts=[_dict("Bad + Name")], engines=[_engine("E", "(D:Bad + Name)")],
                      policies=[_policy("Web-Monitor", ["E"])], meta={"name": "Bad", "confidence_tweaks": []})
    client = make_client(casb_tenants=TENANTS)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    d = next(i for i in rep["items"] if i["kind"] == "dictionary")
    assert d["status"] == pd.BLOCKED_DEPENDENCY and "'+'" in d["reason"] and "ZIA allows" in d["reason"]
    # Everything else depends on that dictionary, so the plan has nothing it can create and says so.
    e = next(i for i in rep["items"] if i["kind"] == "engine")
    assert e["status"] == pd.BLOCKED_DEPENDENCY and "Bad + Name" in e["reason"]
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "blocked" and res["blockers"], res
    assert client.zia.dlp_dictionary.added == [] and client.zia.dlp_engine.added == [] and client.zia.dlp_web_rules.added == []


def test_transient_refusals_are_retried_and_hard_refusals_reported_in_plain_words(tmp_path):
    pack = write_pack(tmp_path / "t", "t", dicts=[_dict("T Dict"), _dict("T Dict Two", pattern=r"\bY\d{3}\b")], engines=[_engine("T Engine", "(D:T Dict)")],
                      policies=[_policy("T-Web-Monitor", ["T Engine"])], meta={"name": "T", "confidence_tweaks": []})
    client = make_client(casb_tenants=TENANTS)
    z = client.zia
    real_add = z.dlp_dictionary.add_dict
    calls = {"n": 0}

    def flaky(name, match_type, dict_type, **kw):
        calls["n"] += 1
        if name == "T Dict" and calls["n"] == 1:
            return None, None, {"status": 429, "message": "Rate limit exceeded, try again later"}
        if name == "T Dict Two":
            return None, None, {"status": 400, "code": "INVALID_INPUT_ARGUMENT", "message": "Confidence score value is not supported in custom dictionary"}
        return real_add(name, match_type, dict_type, **kw)
    z.dlp_dictionary.add_dict = flaky
    logs = []
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False, log=logs.append)
    by = {r["name"]: r for r in res["results"]}
    assert by["T Dict"]["status"] == "created" and by["T Dict"]["attempts"] == 2
    assert any("Rate limit" in l and "trying again" in l for l in logs)
    two = by["T Dict Two"]
    assert two["status"] == "failed" and two.get("attempts", 1) == 1 and two["http_status"] == 400 and two["code"] == "INVALID_INPUT_ARGUMENT"
    assert "does not allow a confidence score" in two["explanation"]
    assert any("What this means:" in l and "T Dict Two" in l for l in logs)
    assert by["T Engine"]["status"] == "created" and by["T-Web-Monitor"]["status"] == "created"


def test_every_write_leaves_one_structured_event_in_every_run(tmp_path, monkeypatch):
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: "ACTIVE")
    monkeypatch.setattr(pr, "RETRY_BASE_SECONDS", 0.0)
    pack = write_pack(tmp_path / "ev", "ev", dicts=[_dict("EV Dict")], engines=[_engine("EV Engine", "(D:EV Dict)")],
                      policies=[_policy("EV-Web-Monitor", ["EV Engine"])], meta={"name": "EV", "confidence_tweaks": []})
    client = _with_delete(add_control_services(make_client(casb_tenants=TENANTS)))
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["events"] and all(set(ops.EVENT_KEYS) <= set(e) for e in res["events"])
    assert [e["status"] for e in res["events"]] == [r["status"] for r in res["results"]]
    assert {e["op"] for e in res["events"] if e["status"] == "created"} == {"create"}
    rec = deployments.from_apply(res, tenant_label="t", packs=["ev"], options={})
    out = pr.remove_deployment(client, rec, plan_hash="", writes_enabled=True)
    assert out["status"] == "removed" and out["events"] and all(set(ops.EVENT_KEYS) <= set(e) for e in out["events"])
    assert {e["op"] for e in out["events"]} == {"delete"} and {e["run"] for e in out["events"]} == {"remove"}


@pytest.mark.parametrize("pack_id", [p["id"] for p in discover_packs()])
def test_every_shipped_pack_deploys_twice_without_creating_or_failing_anything(pack_id):
    """Idempotency, on the tenant that refuses what ZIA refuses: the
    second run reuses everything by name, creates nothing, fails nothing,
    and no channel ends up with two rules of one name."""
    client = strict_tenant()
    pack = next(p for p in discover_packs() if p["id"] == pack_id)
    pack = {"id": pack["id"], "dir": pack["dir"]}
    rep = pd.preflight(client, [pack], writes_enabled=True)
    first = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert first["summary"].get("failed", 0) == 0 and first["summary"]["created"] > 0
    z = client.zia
    before = {svc: len(svc.items) for svc in (z.dlp_dictionary, z.dlp_engine, z.dlp_web_rules, z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules)}
    again = pd.preflight(client, [pack], writes_enabled=True)
    assert not [i for i in again["items"] if i["status"] == pd.CREATE], [i["name"] for i in again["items"] if i["status"] == pd.CREATE]
    assert all(i["status"] in (pd.REUSE, pd.NOOP) for i in again["items"] if i["kind"] != "tweak"), [(i["name"], i["status"]) for i in again["items"] if i["status"] not in (pd.REUSE, pd.NOOP)][:5]
    # A second deploy has nothing to do and says so, in words, instead of writing anything.
    second = pd.apply(client, [pack], plan_hash=again["plan_hash"], writes_enabled=True, verify=False)
    assert second["status"] == "blocked" and any("already exists in the tenant" in b for b in second["blockers"]), second
    assert {svc: len(svc.items) for svc in before} == before, "the second run created something"
    for svc in (z.dlp_dictionary, z.dlp_engine, z.dlp_web_rules, z.endpoint_dlp_rules, z.casb_dlp_rules, z.outbound_email_dlp_rules):
        names = [str(getattr(i, "name", "")) for i in svc.items]
        assert len(names) == len(set(names)), f"duplicate names after the second deploy: {[n for n in names if names.count(n) > 1]}"


def test_every_shipped_pack_is_torn_down_completely_by_the_undo_of_its_deployment(monkeypatch):
    """Deploy every pack (one record each), then undo each record through
    the shared executor: nothing of any pack remains, and the customer's
    own objects are untouched."""
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: "ACTIVE")
    monkeypatch.setattr(pr, "RETRY_BASE_SECONDS", 0.0)
    client = strict_tenant()
    z = client.zia
    seed = {"dicts": [i.id for i in z.dlp_dictionary.items], "saas": [i.id for i in z.casb_dlp_rules.items]}
    records = []
    for p in discover_packs():
        pack = {"id": p["id"], "dir": p["dir"]}
        rep = pd.preflight(client, [pack], writes_enabled=True)
        res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
        assert res["summary"].get("failed", 0) == 0, (p["id"], res["summary"])
        records.append(deployments.from_apply(res, tenant_label="t", packs=[p["id"]], options={}))
    for rec in reversed(records):
        out = pd.undo(client, rec, writes_enabled=True)
        assert out["status"] == "undone" and out["complete"], (rec["packs"], out["summary"], [r for r in out["results"] if r["status"] != "deleted"][:3])
    assert not z.dlp_engine.items and not z.dlp_web_rules.items and not z.endpoint_dlp_rules.items and not z.outbound_email_dlp_rules.items
    assert [i.id for i in z.dlp_dictionary.items] == seed["dicts"] and [i.id for i in z.casb_dlp_rules.items] == seed["saas"]


def test_single_pack_import_and_verify_endpoints_use_the_shared_path(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    client = add_control_services(make_client(casb_tenants=TENANTS))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "assessor": "Jane Doe"}
    r = c.post("/api/dlp-packs/zbp_source_code_baseline/import", json=creds)
    assert r.status_code == 200 and r.json()["status"] == "plan" and r.json()["plan_hash"] and "Nothing was written" in r.json()["message"]
    assert client.zia.dlp_dictionary.added == []
    plan_hash = r.json()["plan_hash"]
    assert c.post("/api/dlp-packs/zbp_source_code_baseline/import", json=dict(creds, plan_hash=plan_hash, confirm=True)).status_code == 403
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    assert c.post("/api/dlp-packs/zbp_source_code_baseline/import", json=dict(creds, plan_hash=plan_hash)).status_code == 400   # no confirm
    assert client.zia.dlp_dictionary.added == []
    r = c.post("/api/dlp-packs/zbp_source_code_baseline/import", json=dict(creds, plan_hash=plan_hash, verify=False, confirm=True))
    body = r.json()
    assert r.status_code == 200 and body["status"] == "applied" and body["summary"]["created"] > 0 and body["events"], body.get("summary")
    assert deployments.list_all() and deployments.list_all()[0]["packs"] == ["zbp_source_code_baseline"]
    v = c.post("/api/dlp-packs/zbp_source_code_baseline/verify", json=creds).json()
    assert v["all_good"] and v["dictionaries"]["ok"] == v["dictionaries"]["total"] > 0 and v["rules"]["web"]["ok"] == 14 and "Everything this pack defines" in v["message"]
    # The private-key clone has no template on this tenant: said as "cannot be created here", not counted as missing.
    assert [b["name"] for b in v["blocked"]] == ["SRC-Private Key"] and "cannot be created on this tenant" in v["message"]
    v2 = c.post("/api/dlp-packs/cjis_policy_pack/verify", json=creds).json()
    assert not v2["all_good"] and v2["dictionaries"]["missing"] and "not in the tenant" in v2["message"]
