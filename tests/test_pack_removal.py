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
