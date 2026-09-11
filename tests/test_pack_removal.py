"""
Methodical removal of a deployed pack: discovery by provenance tag and by
name, dependency-safe keep decisions, reverse-order deletion, and the
plan_hash / stale guard.
"""
from __future__ import annotations

import pytest

import pack_removal as pr
from test_pack_deploy import FakeClient, Obj, _dict, _engine, _policy, write_pack

TAG = "[DLP-Check baseline removeme v1] Deployed by DLP-Check; measured on every journey check, never overwritten."
META = {"name": "Remove Me", "baseline": {"pack": "removeme", "version": "1", "prefix": "RM-"}, "confidence_tweaks": []}


def _pack_dir(tmp_path):
    d = write_pack(tmp_path, "removeme",
                   dicts=[_dict("RM-Dict")],
                   engines=[_engine("RM-Engine", "(D:RM-Dict > 0)")],
                   policies=[_policy("RM-Web-Monitor", ["RM-Engine"])],
                   meta=META)
    return {"id": "removeme", "dir": d["dir"]}


def _deletable(client):
    z = client.zia
    z.dlp_dictionary.delete_dict = lambda oid: (_pop(z.dlp_dictionary, oid), None, None)
    z.dlp_engine.delete_dlp_engine = lambda oid: (_pop(z.dlp_engine, oid), None, None)
    z.dlp_web_rules.delete_rule = lambda oid: (_pop(z.dlp_web_rules, oid), None, None)
    return client


def _pop(svc, oid):
    svc.items = [it for it in svc.items if str(it.id) != str(oid)]
    return None


def _tenant(with_survivors: bool):
    """A tenant carrying the removeme pack's objects, all tool-tagged."""
    dicts = [Obj(id=9001, name="RM-Dict", custom=True, description="United States SSNs " + TAG)]
    engines = [Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description=TAG)]
    rules = [Obj(id=7001, name="RM-Web-Monitor", order=1, rank=7, action="ALLOW", state="DISABLED",
                 dlp_engines=[{"id": 5001}], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_INFO", description=TAG)]
    if with_survivors:
        # A rule and an engine NOT part of the pack that still use the pack's objects.
        rules.append(Obj(id=7002, name="Someone Else's Rule", order=2, rank=7, action="BLOCK", state="ENABLED",
                         dlp_engines=[{"id": 5001}], protocols=["HTTPS_RULE"], description="hand-made"))
        engines.append(Obj(id=5002, name="Someone Else's Engine", engine_expression="D9001.S > 2", description="hand-made"))
    return FakeClient(dicts=dicts, engines=engines, rules=rules)


def test_plan_finds_tagged_objects_and_orders_them(tmp_path):
    pack = _pack_dir(tmp_path)
    rep = pr.plan_removal(_tenant(with_survivors=False), [pack])
    assert rep["status"] == "ready" and rep["remove_count"] == 3
    kinds = [(i["kind"], i["name"], i["status"]) for i in rep["items"]]
    # Reverse dependency order: rule, then engine, then dictionary.
    assert kinds == [("policy", "RM-Web-Monitor", "remove"),
                     ("engine", "RM-Engine", "remove"),
                     ("dictionary", "RM-Dict", "remove")]
    assert all(i["match"] == "tag" for i in rep["items"])


def test_plan_keeps_objects_still_used_outside_the_pack(tmp_path):
    pack = _pack_dir(tmp_path)
    rep = pr.plan_removal(_tenant(with_survivors=True), [pack])
    by = {i["name"]: i for i in rep["items"]}
    assert by["RM-Web-Monitor"]["status"] == "remove"          # the pack's own rule goes
    assert by["RM-Engine"]["status"] == "keep" and "outside this pack" in by["RM-Engine"]["keep"]
    assert by["RM-Dict"]["status"] == "keep" and "outside this pack" in by["RM-Dict"]["keep"]
    assert rep["remove_count"] == 1 and rep["keep_count"] == 2


def test_predefined_dictionaries_are_never_removed(tmp_path):
    pack = _pack_dir(tmp_path)
    client = _tenant(with_survivors=False)
    client.zia.dlp_dictionary.items.append(Obj(id=1, name="RM-Dict-Predef", custom=False, description=TAG))
    rep = pr.plan_removal(client, [pack])
    assert not any(i["name"] == "RM-Dict-Predef" for i in rep["items"])


def test_remove_deletes_in_order_and_reports(tmp_path):
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["summary"].get("deleted") == 3
    assert [it.id for it in client.zia.dlp_web_rules.items] == []
    assert [it.id for it in client.zia.dlp_engine.items] == []
    assert [it.id for it in client.zia.dlp_dictionary.items] == []


def test_remove_activates_between_tiers_and_at_the_end(tmp_path, monkeypatch):
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    calls = []
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (calls.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    # Rules, then engine, then dictionary all deleted; activation ran between
    # tiers (so the engine/dictionary are no longer referenced) and at the end.
    assert res["summary"].get("deleted") == 3
    assert len(calls) >= 2 and res["activation"]["activated"] and res["activation_required"] is False
    assert not client.zia.dlp_engine.items and not client.zia.dlp_dictionary.items


SAAS_POL = {"name": "RM-Web-Monitor [SaaS]", "channel": "saas", "engines": ["RM-Engine"], "action": "OFLCASB_DLP_REPORT_INCIDENT",
            "state": "DISABLED", "saas_type": "OFLCASB_DLP_FILE", "tenants": "any", "severity": "RULE_SEVERITY_INFO", "channel_mirror": True}


def test_remove_clears_saas_rules_using_their_rule_type(tmp_path, monkeypatch):
    """A SaaS Security API rule can only be deleted with its ruleType; the
    plan carries the type it read and the delete passes it on."""
    from test_pack_channels import make_client
    d = write_pack(tmp_path, "removeme", dicts=[_dict("RM-Dict")], engines=[_engine("RM-Engine", "(D:RM-Dict > 0)")],
                   policies=[_policy("RM-Web-Monitor", ["RM-Engine"]), SAAS_POL], meta=META)
    pack = {"id": "removeme", "dir": d["dir"]}
    client = make_client(saas_rules=[Obj(id=8501, name="RM-Web-Monitor [SaaS]", type="OFLCASB_DLP_FILE", state="DISABLED",
                                         action="OFLCASB_DLP_REPORT_INCIDENT", dlp_engines=[{"id": 5001}], description=TAG)])
    base = _tenant(with_survivors=False)
    client.zia.dlp_dictionary.items = base.zia.dlp_dictionary.items
    client.zia.dlp_engine.items = base.zia.dlp_engine.items
    client.zia.dlp_web_rules.items = base.zia.dlp_web_rules.items
    _deletable(client)
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    plan = pr.plan_removal(client, [pack])
    saas = next(i for i in plan["items"] if i.get("channel") == "saas")
    assert saas["name"] == "RM-Web-Monitor [SaaS]" and saas["type"] == "OFLCASB_DLP_FILE" and saas["status"] == "remove"
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["complete"] and res["summary"] == {"deleted": 4}
    assert client.zia.casb_dlp_rules.deleted == [(8501, "OFLCASB_DLP_FILE")] and client.zia.casb_dlp_rules.items == []
    # Verified by a fresh read: the same discovery the preview ran finds nothing left.
    v = res["verification"]
    assert v["read"] and v["clean"] and v["remaining"] == [] and v["plan"]["status"] == "nothing"


def test_remove_several_packs_in_one_pass(tmp_path, monkeypatch):
    """Removing every deployed pack at once: one plan, one pass, one verification."""
    a = write_pack(tmp_path, "packa", dicts=[_dict("A-Dict")], engines=[_engine("A-Engine", "(D:A-Dict > 0)")],
                   policies=[_policy("A-Monitor", ["A-Engine"])], meta={"name": "A", "confidence_tweaks": []})
    b = write_pack(tmp_path, "packb", dicts=[_dict("B-Dict")], engines=[_engine("B-Engine", "(D:B-Dict > 0)")],
                   policies=[_policy("B-Monitor", ["B-Engine"])], meta={"name": "B", "confidence_tweaks": []})
    packs = [{"id": "packa", "dir": a["dir"]}, {"id": "packb", "dir": b["dir"]}]
    client = _deletable(FakeClient(
        dicts=[Obj(id=1, name="A-Dict", custom=True, description="[DLP-Check pack packa] x"), Obj(id=2, name="B-Dict", custom=True, description="[DLP-Check pack packb] x")],
        engines=[Obj(id=11, name="A-Engine", engine_expression="D1.S > 0", description="[DLP-Check pack packa] x"),
                 Obj(id=12, name="B-Engine", engine_expression="D2.S > 0", description="[DLP-Check pack packb] x")],
        rules=[Obj(id=21, name="A-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 11}], description="[DLP-Check pack packa] x"),
               Obj(id=22, name="B-Monitor", order=2, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 12}], description="[DLP-Check pack packb] x")]))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    plan = pr.plan_removal(client, packs)
    assert plan["packs"] == ["packa", "packb"] and plan["remove_count"] == 6
    res = pr.remove(client, packs, plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["summary"] == {"deleted": 6} and res["verification"]["clean"]
    assert not client.zia.dlp_web_rules.items and not client.zia.dlp_engine.items and not client.zia.dlp_dictionary.items


def test_remove_reports_objects_the_tenant_still_lists(tmp_path, monkeypatch):
    """A delete that returns no error but leaves the object in place is
    reported as still present, and the removal is not called complete."""
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    client.zia.dlp_web_rules.delete_rule = lambda oid: (None, None, None)   # "succeeds", removes nothing
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    rule = next(r for r in res["results"] if r["kind"] == "policy")
    assert rule["status"] == "still_present" and "still lists" in rule["error"]
    assert res["complete"] is False and res["status"] == "partial" and res["summary"]["still_present"] == 1
    v = res["verification"]
    assert v["read"] and not v["clean"] and [i["name"] for i in v["remaining"]] == ["RM-Web-Monitor"]
    assert v["plan"]["plan_hash"]   # a plan for exactly the leftovers, ready to run again


def test_remove_everything_covers_retired_packs_and_old_names(tmp_path, monkeypatch):
    """"Remove all" must not stop at the packs in the library: objects
    tagged by a pack that is no longer shipped, and objects earlier pack
    versions created under names no current pack defines, are found too,
    with the same keep-if-used-elsewhere rule."""
    pack = _pack_dir(tmp_path)
    client = _deletable(FakeClient(
        dicts=[Obj(id=9001, name="RM-Dict", custom=True, description=TAG),
               Obj(id=9101, name="CUI-Banner-Structural", custom=True, description="[DLP-Check baseline cui_marking_baseline v1.0] Deployed by DLP-Check"),
               Obj(id=9102, name="CUI Category Phrase", custom=True, description="CUI Category phrases"),          # Fed 1.1, untagged
               Obj(id=9103, name="Hand-made Dict", custom=True, description="mine")],
        engines=[Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description=TAG),
                 Obj(id=5101, name="CUI-Detect-All", engine_expression="D9101.S > 0", description="[DLP-Check baseline cui_marking_baseline v1.0] Deployed by DLP-Check"),
                 Obj(id=5102, name="CUI Engine (Low Confidence)", engine_expression="D9102.S > 2", description=""),
                 Obj(id=5103, name="PCI - High", engine_expression="D1.S > 9", description=""),
                 Obj(id=5104, name="Customer Engine", engine_expression="D9103.S > 0 OR D9102.S > 0", description="")],
        rules=[Obj(id=7001, name="RM-Web-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5001}], description=TAG),
               Obj(id=7101, name="CUI-Monitor-All", order=2, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5101}], description="[DLP-Check baseline cui_marking_baseline v1.0] Deployed by DLP-Check"),
               Obj(id=7102, name="Z-Controlled Unclassified Information-Monitor", order=3, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5102}], description=""),
               Obj(id=7103, name="Customer Rule", order=4, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5104}], description="")]))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    # A single pack sees only its own objects.
    single = pr.plan_removal(client, [pack])
    assert {i["name"] for i in single["items"]} == {"RM-Web-Monitor", "RM-Engine", "RM-Dict"}
    # Everything: the retired CUI pack's tagged objects and Fed 1.1's untagged ones are in scope;
    # the customer's own objects are not, and a dictionary a customer engine still uses is kept.
    plan = pr.plan_removal(client, [pack], everything=True)
    by = {i["name"]: i for i in plan["items"]}
    assert plan["everything"] and "Customer Rule" not in by and "Customer Engine" not in by and "Hand-made Dict" not in by
    assert by["CUI-Monitor-All"]["match"] == "tag" and by["CUI-Detect-All"]["status"] == "remove" and by["CUI-Banner-Structural"]["status"] == "remove"
    assert by["Z-Controlled Unclassified Information-Monitor"]["match"] == "name" and by["CUI Engine (Low Confidence)"]["status"] == "remove"
    assert by["PCI - High"]["status"] == "remove"
    assert by["CUI Category Phrase"]["status"] == "keep" and "outside" in by["CUI Category Phrase"]["keep"]
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, everything=True)
    assert res["status"] == "removed" and res["verification"]["clean"]
    assert {r.name for r in client.zia.dlp_web_rules.items} == {"Customer Rule"}
    assert {e.name for e in client.zia.dlp_engine.items} == {"Customer Engine"}
    assert {d.name for d in client.zia.dlp_dictionary.items} == {"CUI Category Phrase", "Hand-made Dict"}


def test_pick_rules_removes_them_with_the_engines_and_dictionaries_only_they_use(tmp_path, monkeypatch):
    """Pick mode: the operator selects rules from the inventory; the plan
    removes those rules plus the engines and dictionaries only they used,
    keeping anything an unselected rule or a surviving engine still uses."""
    from test_pack_channels import make_client
    client = make_client(saas_rules=[Obj(id=8501, name="Old [SaaS]", type="OFLCASB_DLP_FILE", state="DISABLED",
                                         action="OFLCASB_DLP_REPORT_INCIDENT", dlp_engines=[{"id": 5001}], description="")])
    client.zia.dlp_dictionary.items = [Obj(id=9001, name="Old-Dict", custom=True, description=""),
                                       Obj(id=9002, name="Shared-Dict", custom=True, description=""),
                                       Obj(id=1, name="SSN", custom=False, description="")]
    client.zia.dlp_engine.items = [Obj(id=5001, name="Old-Engine", engine_expression="D9001.S > 0 OR D9002.S > 0", description=""),
                                   Obj(id=5002, name="Shared-Engine", engine_expression="D9002.S > 0", description=""),
                                   Obj(id=5003, name="Keep-Engine", engine_expression="D1.S > 0", description="")]
    client.zia.dlp_web_rules.items = [
        Obj(id=7001, name="Old-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5001}, {"id": 5002}], description="[DLP-Check pack oldpack v1] x"),
        Obj(id=7002, name="Keep-Monitor", order=2, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5002}, {"id": 5003}], description="mine")]
    _deletable(client)
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    inv = pr.inventory(client)
    by = {(r["channel"], r["name"]): r for r in inv["rules"]}
    assert inv["status"] == "ready" and set(by) == {("web", "Old-Monitor"), ("web", "Keep-Monitor"), ("saas", "Old [SaaS]")}
    assert by[("web", "Old-Monitor")]["tagged"] and by[("web", "Old-Monitor")]["pack"] == "oldpack" and by[("web", "Old-Monitor")]["engines"] == ["Old-Engine", "Shared-Engine"]
    assert not by[("web", "Keep-Monitor")]["tagged"]
    sel = [{"channel": "web", "id": 7001}, {"channel": "saas", "id": 8501}]
    plan = pr.plan_removal_selected(client, sel)
    st = {i["name"]: i for i in plan["items"]}
    assert st["Old-Monitor"]["status"] == "remove" and st["Old [SaaS]"]["status"] == "remove" and "Keep-Monitor" not in st
    assert st["Old-Engine"]["status"] == "remove" and st["Shared-Engine"]["status"] == "keep" and "Keep-Engine" not in st
    assert st["Old-Dict"]["status"] == "remove" and st["Shared-Dict"]["status"] == "keep" and "SSN" not in st
    assert st["Old-Monitor"]["depends_on"] == ["engine:Old-Engine", "engine:Shared-Engine"] and st["Old-Engine"]["depends_on"] == ["dictionary:Old-Dict", "dictionary:Shared-Dict"]
    res = pr.remove_selected(client, sel, plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["verification"]["clean"] and res["summary"] == {"deleted": 4}
    assert {r.name for r in client.zia.dlp_web_rules.items} == {"Keep-Monitor"} and client.zia.casb_dlp_rules.items == []
    assert {e.name for e in client.zia.dlp_engine.items} == {"Shared-Engine", "Keep-Engine"}
    assert {d.name for d in client.zia.dlp_dictionary.items} == {"Shared-Dict", "SSN"}
    # A stale hash (tenant changed) is refused, as for a pack.
    assert pr.remove_selected(client, sel, plan_hash="stale", writes_enabled=True)["status"] in ("stale", "nothing")


def test_remove_is_refused_read_only_and_when_stale(tmp_path):
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    assert pr.remove(client, [pack], plan_hash="x", writes_enabled=False)["status"] == "blocked"
    assert pr.remove(client, [pack], plan_hash="stale-hash", writes_enabled=True)["status"] == "stale"


def test_name_only_match_is_flagged(tmp_path):
    pack = _pack_dir(tmp_path)
    # Same names, but no DLP-Check tag anywhere.
    client = FakeClient(
        dicts=[Obj(id=9001, name="RM-Dict", custom=True, description="hand-made")],
        engines=[Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description="")],
        rules=[Obj(id=7001, name="RM-Web-Monitor", order=1, action="ALLOW", dlp_engines=[{"id": 5001}], description="")])
    rep = pr.plan_removal(client, [pack])
    assert rep["remove_count"] == 3 and all(i["match"] == "name" for i in rep["items"])
    assert any("matched by name only" in w for w in rep["warnings"])
