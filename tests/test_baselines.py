"""
Immutable baselines: a pack whose pack.json declares `baseline` is the
authoritative definition of the objects it names. Preflight classifies
each one as in sync / drifted / missing, apply RESTORES drifted objects
(the one case where the planner overwrites), every write carries a
provenance tag, and ordinary packs keep their never-overwrite behaviour.
"""
from __future__ import annotations

import json

import pytest

import pack_channels as pc
import pack_deploy as pd
from test_pack_channels import FakeChannelRules, make_client  # noqa: F401
from test_pack_deploy import (  # noqa: F401
    PREDEF_SSN, FakeClient, Obj, _dict, _engine, _policy, write_pack, items_by,
)

BASELINE_META = {"name": "Alpha Baseline", "version": "2.1", "confidence_tweaks": [],
                 "baseline": {"immutable": True, "prefix": "ZBP-", "version": "2.1"}}


@pytest.fixture
def baseline_pack(tmp_path):
    return write_pack(
        tmp_path, "alpha_baseline",
        dicts=[_dict("ZBP-Alpha Dict", pattern=r"\bZ\d{4}\b")],
        engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")],
        policies=[_policy("ZBP-Alpha-Monitor", ["ZBP-Alpha Engine"])],
        meta=BASELINE_META,
    )


@pytest.fixture
def plain_pack(tmp_path):
    return write_pack(
        tmp_path, "alpha_plain",
        dicts=[_dict("ZBP-Alpha Dict", pattern=r"\bZ\d{4}\b")],
        engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")],
        policies=[_policy("ZBP-Alpha-Monitor", ["ZBP-Alpha Engine"])],
        meta={"name": "Alpha Plain", "confidence_tweaks": []},
    )


def tenant_dict(pattern=r"\bZ\d{4}\b", description="", **kw):
    return Obj(id=4100, name="ZBP-Alpha Dict", custom=True, proximity=0, description=description,
               custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
               confidence_threshold="CONFIDENCE_LEVEL_HIGH",
               patterns=[Obj(action="PATTERN_COUNT_TYPE_ALL", pattern=pattern)], phrases=[], **kw)


def tenant_engine(expr="(D4100.S > 0)", description=""):
    return Obj(id=5100, name="ZBP-Alpha Engine", engine_expression=expr, description=description)


def tenant_rule(action="ALLOW", state="ENABLED", engines=(5100,), order=3, description="", severity="RULE_SEVERITY_HIGH"):
    return Obj(id=7100, name="ZBP-Alpha-Monitor", order=order, rank=7, action=action, state=state,
               dlp_engines=[{"id": e} for e in engines], protocols=["HTTPS_RULE"], severity=severity, description=description)


def in_sync_client():
    return FakeClient(dicts=[PREDEF_SSN, tenant_dict()], engines=[tenant_engine()], rules=[tenant_rule()])


# ---------------------------------------------------------------------------
# Preflight: drift classification
# ---------------------------------------------------------------------------

def test_missing_baseline_objects_are_created_with_provenance(baseline_pack):
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True)
    assert rep["status"] == "ready"
    assert all(i["status"] == pd.CREATE for i in rep["items"])
    assert all(i["baseline"] == "alpha_baseline" for i in rep["items"])
    assert rep["baselines"][0]["state"] == "missing"
    assert rep["baselines"][0]["missing"] == 3

    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    z = client.zia
    assert pd.BASELINE_MARK in z.dlp_dictionary.added[0]["description"]
    assert "v2.1" in z.dlp_dictionary.added[0]["description"]
    assert pd.BASELINE_MARK in z.dlp_engine.added[0]["description"]
    assert pd.BASELINE_MARK in z.dlp_web_rules.added[0]["description"]


def test_in_sync_baseline_has_nothing_to_deploy(baseline_pack):
    rep = pd.preflight(in_sync_client(), [baseline_pack], writes_enabled=True)
    assert {i["name"]: i["status"] for i in rep["items"]} == {
        "ZBP-Alpha Dict": pd.REUSE, "ZBP-Alpha Engine": pd.REUSE, "ZBP-Alpha-Monitor": pd.REUSE}
    assert rep["status"] == "blocked"
    assert any("every baseline object is already in sync" in b for b in rep["blockers"])
    assert rep["baselines"][0]["state"] == "in_sync"
    assert rep["baselines"][0]["in_sync"] == 3
    status = pd.baseline_status(rep)
    assert status["status"] == "in_sync"
    assert status["blockers"] == []  # the "nothing to deploy" blocker is not a drift problem


def test_drifted_baseline_objects_are_restored(baseline_pack):
    client = FakeClient(
        dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")],       # content drifted
        engines=[tenant_engine()],                                       # in sync (same ID-resolved expression)
        rules=[tenant_rule(action="BLOCK", order=3)],                    # action drifted
    )
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True)
    d, e, p = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.RESTORE and d["ZBP-Alpha Dict"]["drift"] == ["patterns"]
    assert d["ZBP-Alpha Dict"]["adopt"] is True                          # no provenance tag on the tenant copy
    assert e["ZBP-Alpha Engine"]["status"] == pd.REUSE                   # a restore keeps its ID, so the engine stays valid
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.RESTORE and p["ZBP-Alpha-Monitor"]["drift"] == ["action"]
    assert rep["will_restore"] == 2
    assert rep["status"] == "warnings"
    assert any(i["type"] == "baseline_restore" for i in rep["impacts"])
    assert any("drifted from baseline" in w for w in rep["warnings"])
    assert rep["baselines"][0]["state"] == "drifted"
    assert {o["name"] for o in rep["baselines"][0]["objects"]} == {"ZBP-Alpha Dict", "ZBP-Alpha-Monitor"}

    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    assert res["summary"] == {"restored": 2, "reused": 1}
    assert res["activation_required"] is True
    z = client.zia
    upd = z.dlp_dictionary.updated[-1]
    assert upd["id"] == 4100 and upd["patterns"] == [("PATTERN_COUNT_TYPE_ALL", r"\bZ\d{4}\b")]
    assert pd.BASELINE_MARK in upd["description"]
    rule = z.dlp_web_rules.updated[-1]
    assert rule["id"] == 7100 and rule["action"] == "ALLOW"
    assert rule["order"] == 3                                            # position kept, content restored
    assert pd.BASELINE_MARK in rule["description"]
    # A second preflight now sees everything in sync.
    again = pd.preflight(client, [baseline_pack], writes_enabled=True)
    assert again["baselines"][0]["state"] == "in_sync"


def test_missing_dictionary_forces_engine_rewrite(baseline_pack):
    # Dictionary gone, engine still points at the old ID: the engine must be restored too.
    client = FakeClient(dicts=[PREDEF_SSN], engines=[tenant_engine(expr="(D4100.S > 0)")], rules=[tenant_rule()])
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True)
    d, e, p = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.CREATE
    assert e["ZBP-Alpha Engine"]["status"] == pd.RESTORE and e["ZBP-Alpha Engine"]["drift"] == ["dictionaries"]
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.REUSE                  # engine keeps its ID, rule still valid
    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["summary"] == {"created": 1, "restored": 1, "reused": 1}
    new_dict_id = client.zia.dlp_dictionary.items[-1].id
    assert client.zia.dlp_engine.updated[-1]["engine_expression"] == f"(D{new_dict_id}.S > 0)"


def test_plain_pack_keeps_never_overwrite_behaviour(plain_pack):
    client = FakeClient(dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")], engines=[tenant_engine()],
                        rules=[tenant_rule(action="BLOCK")])
    rep = pd.preflight(client, [plain_pack], writes_enabled=True)
    d, p = items_by(rep, "dictionary"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.REUSE_DIFFERS
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.REUSE_DIFFERS
    assert rep["baselines"] == []
    assert not any(i["type"].startswith("baseline") for i in rep["impacts"])


def test_baseline_cannot_manage_a_predefined_dictionary(tmp_path):
    pack = write_pack(tmp_path, "clash", dicts=[_dict("Social Security Numbers (US)")], meta=BASELINE_META)
    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    assert items_by(rep, "dictionary")["Social Security Numbers (US)"]["status"] == pd.CONFLICT


def test_baseline_description_is_idempotent():
    item = {"baseline": {"pack": "p", "version": "1.0"}}
    once = pd.baseline_description(item, "Detects things.")
    twice = pd.baseline_description(item, once)
    assert once == twice
    assert once.startswith("Detects things. [DLP-Check baseline p v1.0]")


# ---------------------------------------------------------------------------
# Dynamic cloud-application scope (AI_ML)
# ---------------------------------------------------------------------------

class FakeCloudApps:
    def __init__(self, apps=None, fail=False):
        self.apps = list(apps or [])
        self.fail = fail
        self.calls = []

    def list_cloud_app_policy(self, query_params=None):
        self.calls.append(query_params)
        if self.fail:
            return None, None, {"message": "boom"}
        cls = (query_params or {}).get("app_class")
        return [Obj(app=a, app_class=cls) for a in self.apps], None, None


def ai_pack(tmp_path):
    rule = dict(_policy("ZBP-Block Code to AI", ["ZBP-Alpha Engine"], action="BLOCK"), cloud_app_classes=["AI_ML"])
    return write_pack(tmp_path, "ai", dicts=[_dict("ZBP-Alpha Dict")], engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")],
                      policies=[rule], meta=BASELINE_META)


def test_cloud_app_class_resolves_to_current_catalogue(tmp_path):
    client = FakeClient(dicts=[PREDEF_SSN])
    client.zia.cloud_applications = FakeCloudApps(["CHATGPT", "GEMINI", "CLAUDE"])
    pack = ai_pack(tmp_path)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    pol = items_by(rep, "policy")["ZBP-Block Code to AI"]
    assert pol["status"] == pd.CREATE
    assert "resource:Cloud applications: AI_ML (3)" in pol["depends_on"]
    assert any(r["requirement"].startswith("Cloud applications: AI_ML") and r["status"] == "ok" for r in rep["dependencies"])
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    assert client.zia.dlp_web_rules.added[0]["cloud_applications"] == ["CHATGPT", "CLAUDE", "GEMINI"]
    assert client.zia.cloud_applications.calls[0]["app_class"] == "AI_ML"


def test_cloud_app_class_with_no_apps_blocks_only_that_rule(tmp_path):
    client = FakeClient(dicts=[PREDEF_SSN])
    client.zia.cloud_applications = FakeCloudApps([])
    rep = pd.preflight(client, [ai_pack(tmp_path)], writes_enabled=True)
    pol = items_by(rep, "policy")["ZBP-Block Code to AI"]
    assert pol["status"] == pd.BLOCKED_DEPENDENCY
    assert "AI_ML" in pol["reason"]
    assert items_by(rep, "engine")["ZBP-Alpha Engine"]["status"] == pd.CREATE


# ---------------------------------------------------------------------------
# Terraform template converter
# ---------------------------------------------------------------------------

def test_pack_from_terraform_converts_references():
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    from pack_from_terraform import convert
    tf = {
        "data": {"zia_dlp_dictionaries": {"tpl_ssn": {"name": "SSN"}}},
        "resource": {
            "zia_dlp_dictionaries": {
                "d_custom": {"name": "ZBP-Custom", "description": "Custom words Terraform managed ZBP pack; prefix ZBP-; original dictionary: Custom.",
                             "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                             "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "secret"}]},
                "d_clone": {"name": "ZBP-SSN High", "dict_template_id": "${data.zia_dlp_dictionaries.tpl_ssn.id}",
                            "confidence_level_for_predefined_dict": "CONFIDENCE_LEVEL_HIGH"},
            },
            "zia_dlp_engines": {"e1": {"name": "ZBP-E1", "engine_expression": "((D${zia_dlp_dictionaries.d_custom.id}.S > 0) OR (D${zia_dlp_dictionaries.d_clone.id}.S > 2))"}},
            "zia_dlp_web_rules": {"r1": {"name": "ZBP-R1", "action": "ALLOW", "state": "DISABLED", "protocols": ["ANY_RULE"],
                                         "severity": "RULE_SEVERITY_INFO", "dlp_engines": [{"id": ["${zia_dlp_engines.e1.id}"]}]}},
        },
    }
    pack = convert(tf, enable_rules=True)
    assert pack["dictionaries"][0]["description"] == "Custom words"
    assert pack["dictionaries"][1]["predefined_clone"] is True and pack["dictionaries"][1]["dict_template_name"] == "SSN"
    assert pack["engines"][0]["expression"] == "((D:ZBP-Custom > 0) OR (D:ZBP-SSN High > 2))"
    assert pack["policies"][0]["engines"] == ["ZBP-E1"] and pack["policies"][0]["state"] == "ENABLED"


def test_shipped_baselines_are_discoverable_and_plan():
    from dlp_importer import discover_packs
    packs = {p["id"]: p for p in discover_packs()}
    for pid in ("zbp_enterprise_baseline", "zbp_source_code_baseline", "healthcare_phi_baseline"):
        assert pid in packs and pd.baseline_meta(packs[pid], pid), pid
    # Healthcare PHI: engines reference the tenant's predefined medical dictionaries by name.
    phi = packs["healthcare_phi_baseline"]
    client = FakeClient(dicts=[Obj(id=1, name="MEDICAL", custom=False), Obj(id=2, name="ML_MEDICAL_DOC_LEAKAGE", custom=False)])
    rep = pd.preflight(client, [{"id": phi["id"], "dir": phi["dir"]}], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"]
    res = pd.apply(client, [{"id": phi["id"], "dir": phi["dir"]}], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["summary"] == {"created": 8}
    rule = client.zia.dlp_web_rules.added[0]
    assert rule["ocr_enabled"] is True and rule["min_size"] == 10
    assert client.zia.dlp_engine.added[0]["engine_expression"].startswith("((((D1.S > 0) OR (D2.S > 0)")
    ent = packs["zbp_enterprise_baseline"]
    templates = sorted({d["dict_template_name"] for d in json.load(open(f"{ent['dir']}/configs/dlp_dictionaries.json")) if d.get("predefined_clone")})
    # Predefined dictionaries the engines reference directly (API names, as a tenant exports them).
    predefined = templates + ["DISEASES_LEAKAGE", "DRUGS_LEAKAGE", "FINANCIAL", "MEDICAL",
                              "ML_CORPORATE_FINANCE_LEAKAGE", "ML_MEDICAL_DOC_LEAKAGE", "ML_TAX_LEAKAGE"]
    client = FakeClient(dicts=[Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(predefined)])
    rep = pd.preflight(client, [{"id": ent["id"], "dir": ent["dir"]}], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"]
    assert rep["baselines"][0]["missing"] == 46
