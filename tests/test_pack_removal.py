"""
Methodical removal of a deployed pack: discovery by provenance tag and by
name, dependency-safe keep decisions, reverse-order deletion, and the
plan_hash / stale guard.
"""
from __future__ import annotations

import pytest

import pack_removal as pr
from test_pack_deploy import FakeClient, Obj, _dict, _engine, _policy, write_pack

TAG = "[DLP-Check baseline removeme v1] Measured on every journey check, never overwritten."
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


def test_remove_activates_once_when_everything_is_deleted(tmp_path, monkeypatch):
    """"Don't activate until the entire deployment is complete or completely
    deleted": rules, engine and dictionary are deleted, then one activation."""
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    calls = []
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (calls.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["summary"].get("deleted") == 3
    assert len(calls) == 1 and res["activation"]["activated"] and res["activation_required"] is False
    assert not client.zia.dlp_engine.items and not client.zia.dlp_dictionary.items and res["run_again"] is False


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
    by = {r["kind"]: r for r in res["results"]}
    assert by["policy"]["status"] == "still_present" and "still lists" in by["policy"]["error"]
    # The rule is still there, so the check right before the engine tier keeps the engine, and the dictionary follows.
    assert by["engine"]["status"] == "skipped" and "checked again just before removal: still used by rule 'RM-Web-Monitor' (Web DLP)" in by["engine"]["reason"]
    assert by["dictionary"]["status"] == "skipped" and "still used by engine 'RM-Engine'" in by["dictionary"]["reason"]
    assert res["complete"] is False and res["status"] in ("partial", "failed") and res["summary"]["still_present"] == 1
    assert len(client.zia.dlp_engine.items) == 1 and len(client.zia.dlp_dictionary.items) == 1, "nothing the rule needs was deleted"
    v = res["verification"]
    assert v["read"] and not v["clean"] and [i["name"] for i in v["remaining"]] == ["RM-Web-Monitor", "RM-Engine", "RM-Dict"], "nothing went, so everything is left over"
    assert v["plan"]["plan_hash"]   # a plan for exactly the leftovers, ready to run again


def test_remove_everything_covers_retired_packs_and_old_names(tmp_path, monkeypatch):
    """"Remove all" must not stop at the packs in the library: objects
    tagged by a pack that is no longer shipped, and objects earlier pack
    versions created under names no current pack defines, are found too,
    with the same keep-if-used-elsewhere rule."""
    pack = _pack_dir(tmp_path)
    client = _deletable(FakeClient(
        dicts=[Obj(id=9001, name="RM-Dict", custom=True, description=TAG),
               Obj(id=9101, name="CUI-Banner-Structural", custom=True, description="[DLP-Check baseline cui_marking_baseline v1.0]"),
               Obj(id=9102, name="CUI Category Phrase", custom=True, description="CUI Category phrases"),          # Fed 1.1, untagged
               Obj(id=9103, name="Hand-made Dict", custom=True, description="mine")],
        engines=[Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description=TAG),
                 Obj(id=5101, name="CUI-Detect-All", engine_expression="D9101.S > 0", description="[DLP-Check baseline cui_marking_baseline v1.0]"),
                 Obj(id=5102, name="CUI Engine (Low Confidence)", engine_expression="D9102.S > 2", description=""),
                 Obj(id=5103, name="PCI - High", engine_expression="D1.S > 9", description=""),
                 Obj(id=5104, name="Customer Engine", engine_expression="D9103.S > 0 OR D9102.S > 0", description="")],
        rules=[Obj(id=7001, name="RM-Web-Monitor", order=1, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5001}], description=TAG),
               Obj(id=7101, name="CUI-Monitor-All", order=2, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5101}], description="[DLP-Check baseline cui_marking_baseline v1.0]"),
               Obj(id=7102, name="Z-Controlled Unclassified Information-Monitor", order=3, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5102}], description=""),
               Obj(id=7103, name="Customer Rule", order=4, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5104}], description="")]))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    # A single pack sees only its own objects.
    single = pr.plan_removal(client, [pack])
    # One pack: its own objects, plus Zscaler Made Easy's historical names (name-only matches, flagged); never another pack's tagged objects.
    single_names = {i["name"] for i in single["items"]}
    assert {"RM-Web-Monitor", "RM-Engine", "RM-Dict"} <= single_names and "CUI-Monitor-All" not in single_names and "Customer Rule" not in single_names
    assert all(i["match"] == "name" for i in single["items"] if i["name"] not in {"RM-Web-Monitor", "RM-Engine", "RM-Dict"})
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
    # Same names, but no Zscaler Made Easy tag anywhere.
    client = FakeClient(
        dicts=[Obj(id=9001, name="RM-Dict", custom=True, description="hand-made")],
        engines=[Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description="")],
        rules=[Obj(id=7001, name="RM-Web-Monitor", order=1, action="ALLOW", dlp_engines=[{"id": 5001}], description="")])
    rep = pr.plan_removal(client, [pack])
    assert rep["remove_count"] == 3 and all(i["match"] == "name" for i in rep["items"])
    assert any("matched by name only" in w for w in rep["warnings"])


def test_deployment_undo_goes_through_the_guided_removal(tmp_path, monkeypatch):
    """The undo of a recorded deployment is planned, executed and verified
    exactly like a pack removal: objects the tenant still lists under the
    name we gave them are removed in tiers; a renamed id is kept and said;
    an object already gone is reported; the read-back proves the rest."""
    client = _deletable(_tenant(with_survivors=True))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    record = {"id": "dep-1", "at": "2026-09-11T00:00:00+00:00", "tenant_label": "acme (production)", "packs": ["removeme"],
              "created": [{"kind": "policy", "channel": "web", "id": 7001, "name": "RM-Web-Monitor"},
                          {"kind": "engine", "channel": None, "id": 5001, "name": "RM-Engine"},
                          {"kind": "dictionary", "channel": None, "id": 9001, "name": "RM-Dict"},
                          {"kind": "dictionary", "channel": None, "id": 9999, "name": "Gone-Dict"}]}
    plan = pr.plan_removal_deployment(client, record)
    st = {i["name"]: i for i in plan["items"]}
    assert plan["status"] == "ready" and plan["deployment"]["id"] == "dep-1" and plan["plan_hash"]
    assert st["RM-Web-Monitor"]["status"] == "remove" and st["RM-Web-Monitor"]["match"] == "deployment"
    # The engine and the dictionary are still used by someone else's rule and engine: kept, not deleted.
    assert st["RM-Engine"]["status"] == "keep" and "outside this deployment" in st["RM-Engine"]["keep"]
    assert st["RM-Dict"]["status"] == "keep" and st["Gone-Dict"]["status"] == "not-found"
    res = pr.remove_deployment(client, record, plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["summary"] == {"deleted": 1} and res["verification"]["read"]
    assert {r.name for r in client.zia.dlp_web_rules.items} == {"Someone Else's Rule"}
    assert {e.name for e in client.zia.dlp_engine.items} == {"RM-Engine", "Someone Else's Engine"}
    # A stale hash is refused, and read-only mode blocks it, as for every removal.
    assert pr.remove_deployment(client, record, plan_hash="stale", writes_enabled=True)["status"] in ("stale", "nothing")
    assert pr.remove_deployment(client, record, plan_hash=plan["plan_hash"], writes_enabled=False)["status"] == "blocked"
    # Without survivors everything the deployment created goes, in tiers.
    client2 = _deletable(_tenant(with_survivors=False))
    plan2 = pr.plan_removal_deployment(client2, record)
    assert {i["name"]: i["status"] for i in plan2["items"]} == {"RM-Web-Monitor": "remove", "RM-Engine": "remove", "RM-Dict": "remove", "Gone-Dict": "not-found"}
    res2 = pr.remove_deployment(client2, record, plan_hash=plan2["plan_hash"], writes_enabled=True)
    assert res2["summary"] == {"deleted": 3} and res2["verification"]["clean"]


def test_plan_says_what_it_read_and_never_calls_a_partial_read_nothing(tmp_path):
    """A tenant listing that omits the custom flag must not hide our own
    tagged dictionary; a preview that could not list a whole kind says so
    instead of "nothing to remove"; every plan carries a read summary."""
    pack = _pack_dir(tmp_path)
    # 1. The custom flag is absent from the listing: the tag still identifies our dictionary.
    client = _tenant(with_survivors=False)
    client.zia.dlp_dictionary.items = [Obj(id=9001, name="RM-Dict", description="United States SSNs " + TAG)]
    rep = pr.plan_removal(client, [pack])
    assert rep["status"] == "ready" and any(i["kind"] == "dictionary" and i["name"] == "RM-Dict" for i in rep["items"])
    assert rep["read"]["dictionaries"] == 1 and rep["read"]["tagged_dictionaries"] == 1 and rep["read"]["engines"] == 1 and rep["read"]["rules"]["web"] == 1
    # 2. Dictionaries could not be listed but engines and rules could: warned, still ready.
    client = _tenant(with_survivors=False)
    client.zia.dlp_dictionary.fail = True
    rep = pr.plan_removal(client, [pack])
    assert rep["status"] == "ready" and any("Could not list the tenant's dictionaries" in w for w in rep["warnings"])
    assert rep["read"]["unreadable"]["dictionaries"]
    # 3. Nothing matched AND part of the tenant could not be read: blocked with the reason, not "nothing".
    client = FakeClient(dicts=[], engines=[], rules=[])
    client.zia.dlp_dictionary.fail = True
    rep = pr.plan_removal(client, [pack])
    assert rep["status"] == "blocked" and "could not be fully read" in rep["blockers"][0] and "dictionaries" in rep["blockers"][0]


def test_an_engine_still_in_use_is_left_for_a_second_run_after_the_one_activation(tmp_path, monkeypatch):
    """ZIA the way it behaves: an engine is "in use" until the activation
    that removes its rules has run. With one activation at the end, the
    first run deletes the rules, reports the engine as still in use (not
    retried: a retry cannot succeed before the activation, and refused
    requests get the client blocked), activates once and says to run the
    removal again; the second run removes the engine and the dictionary.
    A rate-limited SaaS delete is still retried inside the same pass."""
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
    z = client.zia
    state = {"activated": 0, "saas_tries": 0, "engine_tries": 0}
    real_engine_delete = z.dlp_engine.delete_dlp_engine
    def engine_delete(oid):
        state["engine_tries"] += 1
        if state["activated"] < 1:
            return None, None, {"code": "RESOURCE_IN_USE", "message": "DLP engine is in use by a DLP rule"}
        return real_engine_delete(oid)
    z.dlp_engine.delete_dlp_engine = engine_delete
    real_saas_delete = z.casb_dlp_rules.delete_rule
    def saas_delete(oid, rule_type=None):
        state["saas_tries"] += 1
        if state["saas_tries"] == 1:
            return None, None, {"status": 429, "message": "Rate limit exceeded, try again later"}
        return real_saas_delete(oid, rule_type=rule_type)
    z.casb_dlp_rules.delete_rule = saas_delete
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (state.__setitem__("activated", state["activated"] + 1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: "ACTIVE")
    monkeypatch.setattr(pr, "RETRY_BASE_SECONDS", 0.0)
    logs = []
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, log=logs.append)
    by = {r["name"]: r for r in res["results"]}
    assert by["RM-Web-Monitor"]["status"] == "deleted" and by["RM-Web-Monitor [SaaS]"]["status"] == "deleted"
    assert by["RM-Web-Monitor [SaaS]"]["attempts"] == 2 and state["saas_tries"] == 2, "the rate limit is retried inside the pass"
    assert by["RM-Engine"]["status"] == "failed" and state["engine_tries"] == 1, "an in-use refusal is not retried before the activation"
    assert by["RM-Engine"]["reason"] == pr.RUN_AGAIN and res["run_again"] is True and not res["complete"]
    assert state["activated"] == 1 and len(res["activations"]) == 1, "one activation, at the end"
    assert any("run the removal again" in l for l in logs)
    # The second run, after that activation, finishes the job.
    plan2 = pr.plan_removal(client, [pack])
    res2 = pr.remove(client, [pack], plan_hash=plan2["plan_hash"], writes_enabled=True)
    assert res2["complete"] and not z.dlp_engine.items and not z.dlp_dictionary.items and state["activated"] == 2
    # What each refusal means for a retry.
    assert not pr._retryable("not found") and not pr._retryable("DLP engine is in use by a DLP rule") and pr._retryable("Rate limit exceeded")
    assert pr._in_use("DLP engine is in use by a DLP rule") and not pr._in_use("Rate limit exceeded")


def test_pick_mode_lists_and_removes_orphan_engines_and_dictionaries(tmp_path, monkeypatch):
    """An engine no rule uses, or a dictionary no engine uses (a leftover
    from an older build, or something made outside the app), cannot be
    reached through a rule: the inventory lists such orphans on their own
    and a picked orphan is planned and removed, with its dependencies."""
    from test_pack_channels import make_client
    client = make_client()
    z = client.zia
    z.dlp_dictionary.items = [Obj(id=1, name="Social Security Numbers (US)", custom=False),
                              Obj(id=9101, name="PII Phrases", custom=True, description="hand made"),
                              Obj(id=9102, name="Unused Dict", custom=True, description="hand made")]
    z.dlp_engine.items = [Obj(id=5101, name="PII (US) - High Volume", engine_expression="((D9101.S > 5))", description="made in the portal"),
                          Obj(id=5102, name="Used Engine", engine_expression="((D1.S > 0))", description="")]
    z.dlp_web_rules.items = [Obj(id=7101, name="Uses Engine", order=1, rank=7, action="ALLOW", state="DISABLED", dlp_engines=[{"id": 5102}], protocols=["HTTPS_RULE"], description="")]
    _deletable(client)
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: "ACTIVE")
    inv = pr.inventory(client)
    assert [o["name"] for o in inv["orphans"]["engines"]] == ["PII (US) - High Volume"] and inv["orphans"]["engines"][0]["dictionaries"] == ["PII Phrases"] and not inv["orphans"]["engines"][0]["tagged"]
    assert [o["name"] for o in inv["orphans"]["dictionaries"]] == ["Unused Dict"]
    sel = [{"kind": "engine", "id": 5101}, {"kind": "dictionary", "id": 9102}]
    plan = pr.plan_removal_selected(client, sel)
    names = {(i["kind"], i["name"]): i for i in plan["items"]}
    assert plan["status"] == "ready" and names[("engine", "PII (US) - High Volume")]["status"] == "remove" and names[("engine", "PII (US) - High Volume")]["match"] == "selected"
    assert names[("dictionary", "PII Phrases")]["status"] == "remove" and names[("dictionary", "PII Phrases")]["match"] == "dependency"
    assert names[("dictionary", "Unused Dict")]["status"] == "remove" and names[("dictionary", "Unused Dict")]["match"] == "selected"
    assert ("engine", "Used Engine") not in names and plan["remove_count"] == 3
    res = pr.remove_selected(client, sel, plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["summary"] == {"deleted": 3}
    assert [e.name for e in z.dlp_engine.items] == ["Used Engine"] and sorted(d.name for d in z.dlp_dictionary.items) == ["Social Security Numbers (US)"]
    # A picked id that is gone is reported, not silently dropped.
    assert any("no longer in the tenant" in w for w in pr.plan_removal_selected(client, [{"kind": "engine", "id": 424242}])["warnings"])


def test_the_usage_check_runs_again_right_before_engines_and_dictionaries_go(tmp_path, monkeypatch):
    """The plan said the engine and the dictionary go with the rule. While
    the rules tier ran, someone made a new rule that uses the engine: the
    check right before the engine tier sees it, keeps the engine and names
    the rule; the dictionary tier then keeps the dictionary the surviving
    engine uses. Nothing anyone else depends on is ever deleted."""
    client = _deletable(_tenant(with_survivors=False))
    z = client.zia
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    sel = [{"channel": "web", "id": 7001}]
    plan = pr.plan_removal_selected(client, sel)
    assert {i["name"]: i["status"] for i in plan["items"]} == {"RM-Web-Monitor": "remove", "RM-Engine": "remove", "RM-Dict": "remove"}
    real_delete = z.dlp_web_rules.delete_rule

    def delete_and_someone_adds_a_rule(oid):
        out = real_delete(oid)
        z.dlp_web_rules.items.append(Obj(id=7009, name="Made during the run", order=1, rank=7, action="BLOCK", state="ENABLED",
                                         dlp_engines=[{"id": 5001}], protocols=["HTTPS_RULE"], description="hand-made"))
        return out
    z.dlp_web_rules.delete_rule = delete_and_someone_adds_a_rule
    logs = []
    res = pr.remove_selected(client, sel, plan_hash=plan["plan_hash"], writes_enabled=True, log=logs.append)
    by = {r["kind"]: r for r in res["results"]}
    assert by["policy"]["status"] == "deleted"
    assert by["engine"]["status"] == "skipped" and by["engine"]["reason"] == "checked again just before removal: still used by rule 'Made during the run' (Web DLP); left alone"
    assert by["dictionary"]["status"] == "skipped" and by["dictionary"]["reason"] == "checked again just before removal: still used by engine 'RM-Engine'; left alone"
    assert {e.name for e in z.dlp_engine.items} == {"RM-Engine"} and {d.name for d in z.dlp_dictionary.items} == {"RM-Dict"}
    assert any(l.startswith("Checking again which rules still use the engines") for l in logs)
    assert any(l.startswith("Checking again which engines still use the dictionaries") for l in logs)
    assert res["status"] in ("partial", "failed") and not res["complete"]
    # A re-check that cannot read the tenant does not block: the plan and ZIA's own refusal remain the safeguard.
    client2 = _deletable(_tenant(with_survivors=False))
    plan2 = pr.plan_removal_selected(client2, sel)
    real_list, calls = client2.zia.dlp_engine.list_dlp_engines, {"n": 0}

    def flaky():   # the preview (call 1) and the executor's own plan (call 2) read fine; the re-check before the dictionaries (call 3) cannot
        calls["n"] += 1
        return (None, "boom") if calls["n"] == 3 else real_list()
    client2.zia.dlp_engine.list_dlp_engines = flaky
    logs2 = []
    res2 = pr.remove_selected(client2, sel, plan_hash=plan2["plan_hash"], writes_enabled=True, log=logs2.append)
    assert any("Could not check the dictionaries against the tenant again" in l for l in logs2)
    assert {r["kind"]: r["status"] for r in res2["results"]}["dictionary"] == "deleted"


def test_the_page_removes_only_through_the_rule_picker_and_shows_no_inline_diagram():
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()
    assert "Remove from tenant" not in js and "Remove all…" not in js and "_dzRemove(RM_ALL)" not in js
    assert "Remove rules…" in js and "_dzRemovePick()" in js and "The one way to remove" in js
    assert "Permanently remove ${rules.length} rule(s)" in js, "the final confirmation names the rules"
    assert "checked again right before each" in js and "What was checked" in js
    for fn in ("_dzRemovalPreview", "_dzRenderDeploy", "_dzRenderReview"):
        m = re.search(r"function %s\(\) \{(.*?)\n\}\n" % fn, js, re.S)
        assert m, fn
        assert "_dzFlowHtml(" not in m.group(1) and "_dzViewToggle()" not in m.group(1), f"{fn} still draws the inline diagram"
    assert "function _dzFlowHtml(items, results, opts)" in js, "the standalone flow page keeps its renderer"


def test_removal_deletes_rules_engines_dictionaries_then_activates_once(tmp_path, monkeypatch):
    """The order a removal runs in: rules, engines and dictionaries deleted,
    then ONE activation and a wait for ACTIVE. Nothing is activated between
    tiers or on a retry."""
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    z = client.zia
    seq = []

    def wrap(kind, fn):
        return lambda oid, *a, **k: (seq.append(f"delete:{kind}") or fn(oid, *a, **k))
    z.dlp_web_rules.delete_rule = wrap("policy", z.dlp_web_rules.delete_rule)
    z.dlp_engine.delete_dlp_engine = wrap("engine", z.dlp_engine.delete_dlp_engine)
    z.dlp_dictionary.delete_dict = wrap("dictionary", z.dlp_dictionary.delete_dict)
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (seq.append("activate") or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: (seq.append("wait-active") or "ACTIVE"))
    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True)
    assert res["status"] == "removed" and res["complete"]
    assert seq == ["delete:policy", "delete:engine", "delete:dictionary", "activate", "wait-active"]
    assert [a["after"] for a in res["activations"]] == ["dictionaries"] and all(a["activated"] for a in res["activations"])
    assert res["activation"]["after"] == "dictionaries" and res["activation_required"] is False and res["verification"]["activation_status"] == "ACTIVE"
    # Only the rules tier attempted, its delete refused: the one activation follows it.
    client4 = _deletable(_tenant(with_survivors=True))   # the engine and dictionary are kept: something else uses them
    z4 = client4.zia
    seq4 = []
    z4.dlp_web_rules.delete_rule = lambda oid: (seq4.append("delete:policy") or (None, None, {"code": "INVALID_INPUT_ARGUMENT", "message": "Bad request: invalid rule"}))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (seq4.append("activate") or {"activated": True, "status": "ACTIVE", "error": None}))
    plan4 = pr.plan_removal(client4, [pack])
    res4 = pr.remove(client4, [pack], plan_hash=plan4["plan_hash"], writes_enabled=True)
    assert seq4 == ["delete:policy", "activate"] and [a["after"] for a in res4["activations"]] == ["rules"] and res4["status"] == "failed"
    assert res4["activation"]["after"] == "rules" and res4["activation_required"] is False, "the activation that ran is the one reported"
    # A run stopped before its first delete reaches ZIA sends no activation at all.
    client5 = _deletable(_tenant(with_survivors=False))
    seq5 = []
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (seq5.append("activate") or {"activated": True, "status": "ACTIVE", "error": None}))
    plan5 = pr.plan_removal(client5, [pack])
    cancel = __import__("threading").Event(); cancel.set()
    res5 = pr.remove(client5, [pack], plan_hash=plan5["plan_hash"], writes_enabled=True, cancel=cancel)
    assert seq5 == [] and res5["activations"] == [] and res5["activation"] is None and res5["stopped"] and all(r["status"] == "skipped" for r in res5["results"])
    # Every rule delete refused for good: the engine and the dictionary are kept because the
    # surviving rule still uses them, and the one activation still runs at the end.
    client2 = _deletable(_tenant(with_survivors=False))
    z2 = client2.zia
    seq2 = []
    z2.dlp_web_rules.delete_rule = lambda oid: (seq2.append("delete:policy") or (None, None, {"code": "INVALID_INPUT_ARGUMENT", "message": "Bad request: invalid rule"}))
    z2.dlp_engine.delete_dlp_engine = lambda oid: (seq2.append("delete:engine") or (_pop(z2.dlp_engine, oid), None, None))
    monkeypatch.setattr(pr.pc, "activate", lambda zia: (seq2.append("activate") or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pr, "_settle", lambda zia, s, log: (seq2.append("wait-active") or "ACTIVE"))
    plan2 = pr.plan_removal(client2, [pack])
    logs = []
    res2 = pr.remove(client2, [pack], plan_hash=plan2["plan_hash"], writes_enabled=True, log=logs.append)
    assert seq2 == ["delete:policy", "activate", "wait-active"], seq2
    by = {r["kind"]: r for r in res2["results"]}
    assert by["policy"]["status"] == "failed" and by["engine"]["status"] == "skipped" and by["dictionary"]["status"] == "skipped"
    assert res2["status"] == "failed" and not res2["complete"] and res2["activation"]["after"] == "rules" and res2["activation_required"] is False
    assert any(l.startswith("Every tier done; activating once") for l in logs)


def test_the_wizards_rule_deletion_activates_after_the_rules_go(monkeypatch):
    """Step 4 of the Inline DLP Rule migration wizard deletes web rules
    through the assessment's raw client; it now activates once the rules
    were attempted (rules → activate, whatever ZIA answered, then a wait for
    ACTIVE), reports whether the activation ran and what ZIA reported, sends
    nothing when write mode is off and activates nothing when no delete was
    attempted."""
    import rule_migrator as rm
    import security

    class Client:
        def __init__(self):
            self.calls = []

        def get(self, ep):
            if ep == "/zia/status":
                self.calls.append(("GET", ep)); return ({"status": "ACTIVE"}, 200)
            return ([{"id": 1, "name": "A", "action": "BLOCK", "state": "ENABLED"}, {"id": 2, "name": "B"}], 200)

        def delete(self, ep, body=None):
            self.calls.append(("DELETE", ep)); return (None, 204)

        def post(self, ep, body=None):
            self.calls.append(("POST", ep)); return ({"status": "ACTIVE"}, 200)

    c = Client()
    assert rm.delete_all_rules(c, dry_run=True)["status"] == "dry_run" and c.calls == []
    monkeypatch.setattr(security, "_write_override", True)
    out = rm.delete_all_rules(c, dry_run=False)
    assert out["status"] == "completed" and out["deleted_count"] == 2
    assert c.calls == [("DELETE", "/zia/webDlpRules/1"), ("DELETE", "/zia/webDlpRules/2"), ("POST", "/zia/status/activate"), ("GET", "/zia/status")]
    assert out["activation"] == {"requested": True, "http_status": 200, "status": "ACTIVE"}, "the wizard waits for ACTIVE like a pack removal"
    c2 = Client()
    c2.delete = lambda ep, body=None: (c2.calls.append(("DELETE", ep)) or (None, 400))
    out2 = rm.delete_all_rules(c2, dry_run=False)
    # Every delete refused: the rules were still attempted, so the activation still runs (the same rule as a pack removal).
    assert out2["status"] == "partial" and out2["deleted_count"] == 0 and out2["activation"] == {"requested": True, "http_status": 200, "status": "ACTIVE"} and c2.calls[-2] == ("POST", "/zia/status/activate")
    # The wait is bounded and reports what ZIA last said.
    monkeypatch.setattr(rm, "ACTIVATION_WAIT_SECONDS", 0.0)
    c6 = Client()
    c6.get = lambda ep: ({"status": "PENDING"}, 200) if ep == "/zia/status" else ([{"id": 1, "name": "A"}], 200)
    assert rm.delete_all_rules(c6, dry_run=False)["activation"]["status"] == "PENDING"
    c5 = Client()
    c5.get = lambda ep: ([], 200)
    assert rm.delete_all_rules(c5, dry_run=False)["activation"] is None and c5.calls == [], "nothing attempted, nothing activated"
    c3 = Client()
    c3.post = lambda ep, body=None: (c3.calls.append(("POST", ep)) or ({"error": "no"}, 500))
    assert rm.delete_all_rules(c3, dry_run=False)["activation"] == {"requested": False, "http_status": 500}
    monkeypatch.setattr(security, "_write_override", False)
    c4 = Client()
    assert rm.delete_all_rules(c4, dry_run=False)["status"] == "blocked" and c4.calls == []


def test_the_wizards_activation_poll_bypasses_the_clients_response_cache(monkeypatch):
    """The assessment client caches every GET by path; the poll for ACTIVE
    sets the /status entry aside before each read so a PENDING answer
    cached earlier never masks the activation settling."""
    import collections
    import threading
    import rule_migrator as rm

    class CachingClient:
        def __init__(self):
            self._c = collections.OrderedDict({"/zia/api/v1/status|{}": ({"status": "PENDING"}, 200), "/zia/api/v1/webDlpRules|{}": ([], 200)})
            self._lock = threading.Lock()
            self.reads = 0

        def get(self, ep, p=None):
            k = "/zia/api/v1/status|{}"
            if k in self._c:
                return self._c[k]
            self.reads += 1
            res = ({"status": "ACTIVE"}, 200)
            self._c[k] = res
            return res

    c = CachingClient()
    assert rm._wait_active_raw(c, 0.0) == "ACTIVE" and c.reads == 1, "the stale PENDING entry was set aside and ZIA was asked again"
    assert "/zia/api/v1/webDlpRules|{}" in c._c, "other cached paths are left alone"


def test_the_removal_sheet_owns_its_title_and_footer_on_every_step():
    """"On the Remove rules option it says deploy at the top and still
    shows preflight at the bottom": a removal renames the sheet, labels the
    step strip as removal steps and writes each step's buttons into the
    sheet's footer, so the deploy footer with Run preflight never shows
    under a removal; leaving it restores the deploy chrome."""
    import os
    import re
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    js = open(os.path.join(root, "static", "deploy_studio.js"), encoding="utf-8").read()

    def body(fn):
        m = re.search(r"function %s\(\) \{(.*?)\n\}\n" % fn, js, re.S)
        assert m, fn
        return m.group(1)
    render = body("_dzRemovalRender")
    assert "document.getElementById('dzTitle').textContent = pick ? 'Remove rules'" in render and "'Undo a deployment'" in render and "`Remove ${(R.pack && R.pack.name) || 'the pack'}`" in render
    assert "steps.setAttribute('aria-label', 'Removal steps')" in render
    for fn, needle in (("_dzRemovalSelect", "Preview removal of"), ("_dzRemovalPreview", "Continue to approve"), ("_dzRemovalApprove", "Remove now"),
                       ("_dzRemovalBusy", "dzJobStop"), ("_dzRemovalDone", "Back to packs")):
        b = body(fn)
        foot = b.split("document.getElementById('dzFoot').innerHTML")
        assert len(foot) == 2, f"{fn} writes the sheet footer once"
        assert needle in foot[1], f"{fn}: {needle} sits in the footer"
        assert '<div class="dz-actions">' not in foot[0] and "<div class=\"dz-actions\">" not in foot[0], f"{fn} leaves no button row in the body"
        assert '<div class="dz-summary">' in foot[1], f"{fn}: the footer carries a one-line summary"
    deploy = body("_dzRender")
    assert "document.getElementById('dzTitle').textContent = 'Deploy policy packs'" in deploy and "steps.setAttribute('aria-label', 'Deployment steps')" in deploy
    assert "Run preflight" not in body("_dzRemovalSelect") and "Run preflight" in body("_dzRenderSelect")


def test_a_403_is_never_a_delete_that_a_later_pass_clears():
    """"Resource Access Blocked" is a 403 about the client, answered by
    ops.call's five activations; the removal's later passes are for
    deletes ZIA refuses because the object is still in use. The letters
    'lock' inside 'blocked' must not make it look like an edit lock."""
    assert not pr._retryable("Resource Access Blocked") and not pr._retryable("HTTP 403: Resource Access Blocked", 403)
    assert not pr._retryable("Forbidden") and not pr._retryable("anything", 403)
    assert pr._retryable("EDIT_LOCK_NOT_AVAILABLE: Another admin session holds the edit lock")
    assert not pr._retryable("DLP engine is in use by a DLP rule"), "in use clears only with the end-of-run activation; run the removal again"
    assert pr._retryable("Rate limit exceeded", 429) and not pr._retryable("not attempted: You clicked Stop")


def test_the_wizards_delete_all_rules_answers_a_403_with_activate_wait_and_retry(monkeypatch):
    """The migration wizard's Delete all rules step goes through the raw
    client, not the shared path; it follows the same 403 rule: activate,
    wait 15 seconds, try again, up to five times, and a 403 still there
    after that stops the rest."""
    import security
    import rule_migrator as rm
    sleeps = []
    monkeypatch.setattr(rm, "_sleep", lambda s: sleeps.append(s))
    monkeypatch.setattr(rm, "ACTIVATION_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(security, "_write_override", True)

    class Client:
        def __init__(self, refusals):
            self.calls = []
            self.refusals = dict(refusals)   # rule id -> how many 403s before the delete goes through

        def get(self, ep):
            if ep == "/zia/status":
                self.calls.append(("GET", ep)); return ({"status": "ACTIVE"}, 200)
            return ([{"id": 1, "name": "A"}, {"id": 2, "name": "B"}], 200)

        def delete(self, ep, body=None):
            self.calls.append(("DELETE", ep))
            rid = int(ep.rsplit("/", 1)[1])
            if self.refusals.get(rid, 0) > 0:
                self.refusals[rid] -= 1
                return ({"status": 403, "message": "Resource Access Blocked"}, 403)
            return (None, 204)

        def post(self, ep, body=None):
            self.calls.append(("POST", ep)); return ({"status": "ACTIVE"}, 200)

    c = Client({1: 2})
    out = rm.delete_all_rules(c, dry_run=False)
    assert out["status"] == "completed" and out["deleted_count"] == 2 and out["stopped"] is None
    assert sleeps == [30.0, 60.0] and len(out["activations_after_403"]) == 2 and all(a["requested"] for a in out["activations_after_403"])
    assert c.calls[:5] == [("DELETE", "/zia/webDlpRules/1"), ("POST", "/zia/status/activate"), ("DELETE", "/zia/webDlpRules/1"),
                           ("POST", "/zia/status/activate"), ("DELETE", "/zia/webDlpRules/1")]
    assert c.calls[5:] == [("DELETE", "/zia/webDlpRules/2"), ("POST", "/zia/status/activate"), ("GET", "/zia/status")], "then the step's own activation"
    # Never clears: six tries and five activations on the first rule, then the rest is not attempted.
    sleeps.clear()
    c = Client({1: 99, 2: 99})
    out = rm.delete_all_rules(c, dry_run=False)
    assert out["status"] == "partial" and out["deleted_count"] == 0 and out["failed_count"] == 2
    assert sleeps == [30.0, 60.0, 90.0, 120.0, 120.0] and sum(1 for k in c.calls if k == ("DELETE", "/zia/webDlpRules/1")) == 6 and ("DELETE", "/zia/webDlpRules/2") not in c.calls
    assert out["stopped"] and "kept refusing it after 5 waits" in out["stopped"]
    assert out["failed"][0]["http_status"] == 403 and out["failed"][1]["reason"].startswith("not attempted: ZIA refused a write with a 403")
    assert out["activation"]["requested"], "the rules were attempted, so the step's activation still runs"
