"""
Baselines and the data-governance journey: a pack whose pack.json declares
`baseline` is the reference a tenant is measured against. Deploying it is
greenfield (nothing exists: create it all) or brownfield (keep what exists
exactly as the customer has it, create the rest). Nothing is overwritten
unless converge mode (`restore_drift=True`) is asked for explicitly. The
journey check reports each object's position and the stage reached.
"""
from __future__ import annotations

import json

import pytest

import pack_channels as pc
import pack_deploy as pd
from test_pack_channels import FakeChannelRules, add_control_services, make_client, tenant as casb_tenant  # noqa: F401
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
    assert rep["baselines"][0]["state"] == "not_started"
    assert rep["baselines"][0]["missing"] == 3
    assert rep["tenant_mode"]["mode"] == "greenfield"
    assert any(i["type"] == "greenfield" for i in rep["impacts"])

    acts = []
    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.setattr(pd.pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    monkeypatch.undo()
    assert res["status"] == "applied"
    # A deploy that wrote objects activates them so they are live for users.
    assert acts == [1] and res["activation"]["activated"] and res["activation_required"] is False
    # ...and reads the tenant back: every object it created is found by a fresh preflight.
    rc = res["read_check"]
    assert rc["read"] and rc["clean"] and rc["expected"] == 3 and rc["present"] == 3 and rc["missing"] == []
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
    assert any("every policy pack object already exists" in b for b in rep["blockers"])
    assert rep["tenant_mode"]["mode"] == "brownfield"
    row = rep["baselines"][0]
    assert row["state"] == "in_progress"                                  # deployed and monitoring, not yet enforcing
    assert row["in_sync"] == 3
    j = pd.journey(rep)
    assert j["status"] == "in_progress"
    assert j["blockers"] == []                                            # "nothing to deploy" is not a journey problem


def test_customized_baseline_objects_are_kept_by_default(baseline_pack):
    """Brownfield: the customer tuned a dictionary and hardened a rule.
    Both are progress; the plan keeps them and says so."""
    client = FakeClient(
        dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")],       # content differs
        engines=[tenant_engine()],                                       # matches
        rules=[tenant_rule(action="BLOCK", order=3)],                    # hardened to BLOCK
    )
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True)
    d, e, p = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.REUSE_DIFFERS and d["ZBP-Alpha Dict"]["drift"] == ["patterns"]
    assert d["ZBP-Alpha Dict"]["position"] == "customized"
    assert e["ZBP-Alpha Engine"]["status"] == pd.REUSE
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.REUSE_DIFFERS and p["ZBP-Alpha-Monitor"]["drift"] == ["action"]
    assert p["ZBP-Alpha-Monitor"]["position"] == "enforcing"
    assert "Kept exactly as the customer has it" in p["ZBP-Alpha-Monitor"]["reason"]
    assert rep["will_restore"] == 0
    assert not any(i["type"] == "baseline_restore" for i in rep["impacts"])
    assert any(i["type"] == "brownfield" and "customized" in i["detail"] for i in rep["impacts"])
    assert rep["status"] == "blocked"                                     # nothing to write
    assert any("customized in the tenant" in w for w in rep["warnings"])
    assert client.zia.dlp_dictionary.updated == [] and client.zia.dlp_web_rules.updated == []


def test_converge_mode_restores_when_asked_explicitly(baseline_pack):
    client = FakeClient(
        dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")],
        engines=[tenant_engine()],
        rules=[tenant_rule(action="BLOCK", order=3)],
    )
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True, restore_drift=True)
    d, e, p = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.RESTORE and d["ZBP-Alpha Dict"]["drift"] == ["patterns"]
    assert e["ZBP-Alpha Engine"]["status"] == pd.REUSE
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.RESTORE and p["ZBP-Alpha-Monitor"]["drift"] == ["action"]
    assert rep["will_restore"] == 2
    assert rep["status"] == "warnings"
    assert any(i["type"] == "baseline_restore" for i in rep["impacts"])
    assert rep["options"]["restore_drift"] is True

    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True, restore_drift=True)
    assert res["status"] == "applied"
    assert res["summary"] == {"restored": 2, "reused": 1}
    z = client.zia
    upd = z.dlp_dictionary.updated[-1]
    assert upd["id"] == 4100 and upd["patterns"] == [("PATTERN_COUNT_TYPE_ALL", r"\bZ\d{4}\b")]
    assert pd.BASELINE_MARK in upd["description"]
    rule = z.dlp_web_rules.updated[-1]
    assert rule["id"] == 7100 and rule["action"] == "ALLOW" and rule["order"] == 3
    # Without the option the same plan hash is rejected (options are part of it).
    again = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert again["status"] in ("plan_changed", "blocked")


def test_missing_dictionary_leaves_existing_engine_alone_unless_converging(baseline_pack):
    # Dictionary gone, engine still points at the old ID.
    client = FakeClient(dicts=[PREDEF_SSN], engines=[tenant_engine(expr="(D4100.S > 0)")], rules=[tenant_rule()])
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True)
    d, e, p = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert d["ZBP-Alpha Dict"]["status"] == pd.CREATE
    assert e["ZBP-Alpha Engine"]["status"] == pd.REUSE_DIFFERS and e["ZBP-Alpha Engine"]["drift"] == ["dictionaries"]
    assert p["ZBP-Alpha-Monitor"]["status"] == pd.REUSE
    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["summary"] == {"created": 1, "reused": 2}
    assert getattr(client.zia.dlp_engine, "updated", []) == []
    # Converge mode rewrites the engine against the new dictionary.
    client = FakeClient(dicts=[PREDEF_SSN], engines=[tenant_engine(expr="(D4100.S > 0)")], rules=[tenant_rule()])
    rep = pd.preflight(client, [baseline_pack], writes_enabled=True, restore_drift=True)
    assert items_by(rep, "engine")["ZBP-Alpha Engine"]["status"] == pd.RESTORE
    res = pd.apply(client, [baseline_pack], plan_hash=rep["plan_hash"], writes_enabled=True, restore_drift=True)
    assert res["summary"] == {"created": 1, "restored": 1, "reused": 1}
    new_dict_id = client.zia.dlp_dictionary.items[-1].id
    assert client.zia.dlp_engine.updated[-1]["engine_expression"] == f"(D{new_dict_id}.S > 0)"


# ---------------------------------------------------------------------------
# The journey: positions, stages, next steps
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _keep_containment(monkeypatch):
    """The baseline / journey tests validate full pack contents and the
    data-governance journey, which spans containment channels. They run
    with the pack carve-out disabled; the carve-out default is covered in
    test_pack_channels."""
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")


def journey_pack(tmp_path):
    """One DLP rule, one SSL rule, one Cloud App Control rule — enough to
    exercise every stage."""
    from test_pack_channels import add_control_services
    policies = [
        dict(_policy("ZBP-PHI-Monitor", ["ZBP-Alpha Engine"], action="ALLOW"), state="DISABLED"),
        {"name": "ZBP-SSL-Decrypt", "channel": "ssl", "state": "DISABLED", "cloud_app_classes": ["AI_ML"],
         "action": {"type": "DECRYPT", "ssl_interception_cert": {"id": 1}}},
        {"name": "ZBP-CAC-AI", "channel": "cloud_app", "type": "AI_ML", "state": "DISABLED",
         "actions_by_verb": {"UPLOAD": "BLOCK", "*": "ALLOW"}},
    ]
    pack = write_pack(tmp_path, "journey", dicts=[_dict("ZBP-Alpha Dict", pattern=r"\bZ\d{4}\b")],
                      engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")], policies=policies, meta=BASELINE_META)
    return pack, add_control_services


def _journey(client, pack):
    rep = pd.preflight(client, [pack], writes_enabled=True)
    return pd.journey(rep)["baselines"][0], rep


def test_journey_greenfield_is_stage_zero(tmp_path):
    pack, add = journey_pack(tmp_path)
    row, rep = _journey(add(FakeClient(dicts=[PREDEF_SSN])), pack)
    assert row["state"] == "not_started" and row["stage"] == 0 and row["stage_name"] == "Not started"
    assert row["missing"] == 5 and row["score"] == 0
    assert [s["done"] for s in row["stages"]] == [False, False, False, False, False]
    assert row["next_steps"][0].startswith("Deploy dictionary 'ZBP-Alpha Dict'")
    assert rep["tenant_mode"]["mode"] == "greenfield"


def test_journey_advances_as_rules_are_enabled_and_hardened(tmp_path):
    pack, add = journey_pack(tmp_path)
    ssl_off = Obj(id=9801, name="ZBP-SSL-Decrypt", order=1, rank=7, state="DISABLED", action={"type": "DECRYPT"}, applications=["CHATGPT_AI", "GEMINI"], description="")
    cac_off = Obj(id=9501, name="ZBP-CAC-AI", type="AI_ML", order=1, rank=7, state="DISABLED",
                  actions=["BLOCK_AI_ML_UPLOAD", "ALLOW_AI_ML_WEB_USE"], applications=["CHATGPT_AI", "GEMINI"], description="")

    def client(rule_state="DISABLED", rule_action="ALLOW", ssl_state="DISABLED", cac_state="DISABLED"):
        ssl = Obj(**{**ssl_off.__dict__, "state": ssl_state})
        cac = Obj(**{**cac_off.__dict__, "state": cac_state})
        c = FakeClient(dicts=[PREDEF_SSN, tenant_dict()], engines=[tenant_engine()],
                       rules=[Obj(id=7100, name="ZBP-PHI-Monitor", order=1, rank=7, action=rule_action, state=rule_state,
                                  dlp_engines=[{"id": 5100}], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_HIGH", description="")])
        c = add(c, cac_rules=[cac])
        c.zia.ssl_inspection_rules.items.append(ssl)
        return c

    # Everything deployed, nothing enabled: stage 2.
    row, _ = _journey(client(), pack)
    assert row["stage"] == 2 and row["stage_name"] == "Policies deployed"
    assert row["deployed"] == 5 and row["state"] == "in_progress"
    assert any("Enable rule 'ZBP-SSL-Decrypt'" in n for n in row["next_steps"])
    assert any("Enable rule 'ZBP-PHI-Monitor'" in n for n in row["next_steps"])
    # SSL and DLP rule enabled (monitor): stage 3, containment is next.
    row, _ = _journey(client(rule_state="ENABLED", ssl_state="ENABLED"), pack)
    assert row["stage"] == 3 and row["stage_name"] == "Visibility"
    assert row["monitoring"] == 1 and row["enforcing"] == 1
    assert row["next_steps"] == ["Enable rule 'ZBP-CAC-AI' in Policy > Cloud App Control after reviewing its scope."]
    # Containment on: stage 4; enforcement next.
    row, _ = _journey(client(rule_state="ENABLED", ssl_state="ENABLED", cac_state="ENABLED"), pack)
    assert row["stage"] == 4 and row["next_steps"][0].startswith("Switch rule 'ZBP-PHI-Monitor'")
    # DLP rule hardened to BLOCK: governed. The hardened action is a customization, kept.
    row, rep = _journey(client(rule_state="ENABLED", rule_action="BLOCK", ssl_state="ENABLED", cac_state="ENABLED"), pack)
    assert row["stage"] == 5 and row["state"] == "governed" and row["score"] == 100
    assert items_by(rep, "policy")["ZBP-PHI-Monitor"]["status"] == pd.REUSE_DIFFERS
    assert items_by(rep, "policy")["ZBP-PHI-Monitor"]["position"] == "enforcing"
    assert pd.journey(rep)["status"] == "governed"
    # Enabling the rule while the pack ships it disabled is never reported as drift to revert.
    assert rep["will_restore"] == 0


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
    assert "resource:Cloud applications: AI_ML (3): CHATGPT, CLAUDE, GEMINI" in pol["depends_on"]
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
    assert "fed_policy_pack" in packs and "cui_marking_baseline" not in packs   # CUI markings live in the Fed pack now
    # Healthcare PHI: engines reference the tenant's predefined medical dictionaries by name.
    phi = packs["healthcare_phi_baseline"]
    client = add_control_services(make_client(casb_tenants=[casb_tenant("Acme M365 Mail", "OFFICE_365", 503),
                                                            casb_tenant("Acme OneDrive", "ONEDRIVE", 504)]))
    client.zia.dlp_dictionary.items = [Obj(id=1, name="MEDICAL", custom=False), Obj(id=2, name="ML_MEDICAL_DOC_LEAKAGE", custom=False)]
    rep = pd.preflight(client, [{"id": phi["id"], "dir": phi["dir"]}], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"] + rep.get("warnings", [])
    res = pd.apply(client, [{"id": phi["id"], "dir": phi["dir"]}], plan_hash=rep["plan_hash"], writes_enabled=True)
    # Detection only, mirrored to every channel: 5 dicts + 2 engines + one
    # rule per channel (web, endpoint, saas, email).
    assert res["summary"] == {"created": 11}   # 5 dicts + 2 engines + 1 rule x 4 channels (web is the cue; every channel carries the same count)
    assert any(r["name"].endswith("[Email]") for r in client.zia.outbound_email_dlp_rules.added)
    rule = client.zia.dlp_web_rules.added[0]
    assert rule["ocr_enabled"] is True and rule["min_size"] == 10
    assert client.zia.dlp_engine.added[0]["engine_expression"].startswith("((((D1.S > 0) OR (D2.S > 0)")
    ent = packs["zbp_enterprise_baseline"]
    templates = sorted({d["dict_template_name"] for d in json.load(open(f"{ent['dir']}/configs/dlp_dictionaries.json")) if d.get("predefined_clone")})
    # Predefined dictionaries the engines reference directly (API names, as a tenant exports them).
    predefined = templates + ["DISEASES_LEAKAGE", "DRUGS_LEAKAGE", "FINANCIAL", "MEDICAL",
                              "ML_CORPORATE_FINANCE_LEAKAGE", "ML_MEDICAL_DOC_LEAKAGE", "ML_TAX_LEAKAGE"]
    client = add_control_services(make_client(casb_tenants=[casb_tenant("Acme M365 Mail", "OFFICE_365", 503),
                                                            casb_tenant("Acme OneDrive", "ONEDRIVE", 504)]))
    client.zia.dlp_dictionary.items = [Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(predefined)]
    rep = pd.preflight(client, [{"id": ent["id"], "dir": ent["dir"]}], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"] + rep.get("warnings", [])
    assert rep["baselines"][0]["missing"] == 64   # 31 dicts + 9 engines + 6 rules x 4 channels


def test_shipped_packs_ship_disabled_at_info():
    """Shipping convention: every rule in every shipped pack is DISABLED at
    INFO severity (Zscaler's Fed pack delivery convention). Actions keep
    their authored meaning; enabling is a deliberate, per-rule step."""
    from dlp_importer import discover_packs
    import pack_channels as pc
    for p in discover_packs():
        for pol in json.load(open(f"{p['dir']}/configs/dlp_policies.json", encoding="utf-8")):
            assert pol.get("state") == "DISABLED", f"{p['id']}: {pol['name']} ships {pol.get('state')}"
            # Containment rules (Cloud App Control, File Type Control, URL Filtering,
            # SSL Inspection) carry no DLP severity field in the API.
            if pc.has_engines(pc.channel_of(pol)):
                assert pol.get("severity") == "RULE_SEVERITY_INFO", f"{p['id']}: {pol['name']} ships {pol.get('severity')}"


def _fed():
    from dlp_importer import discover_packs
    return next(p for p in discover_packs() if p["id"] == "fed_policy_pack")


def test_fed_pack_carries_the_cui_marking_design():
    """The CUI Marking design lives inside the Fed pack: 31 marking
    dictionaries in seven tiers, four CUI engines (full surface, contextual,
    block-grade, caution-grade, every one with the AND NOT decontrol
    exclusion) and three CUI web rules next to the V1.1 monitor rules. The
    V1.1 CUI engines and the orphan AEA Medium engine are gone."""
    fed = _fed()
    dicts = json.load(open(f"{fed['dir']}/configs/dlp_dictionaries.json", encoding="utf-8"))
    cui = [d for d in dicts if d["name"].startswith(("CUI-", "Legacy-"))]
    assert len(cui) == 31 and len(dicts) == 72 and all(len(d["description"].encode()) <= 255 for d in dicts)
    assert not any(d["name"].startswith(("CUI Registry", "CUI Portion", "Declassify Date", "CUI Contextual", "CUI Category")) for d in dicts)
    engines = {e["name"]: e for e in json.load(open(f"{fed['dir']}/configs/dlp_engines.json", encoding="utf-8"))}
    cui_e = {n: e for n, e in engines.items() if n.startswith("CUI-")}
    assert set(cui_e) == {"CUI-Detect-All", "CUI-Detect-Contextual", "CUI-Detect-Block-Grade", "CUI-Detect-Caution-Grade"}
    assert not any(n.startswith("CUI Engine") for n in engines) and "AEA Medium Confidence" not in engines
    assert all("AND NOT" in e["expression"] and "(D:CUI-Decontrol-Context > 0)" in e["expression"] for e in cui_e.values())
    assert all(p["phrase"].startswith('"') for d in cui for p in d["phrases"] if " " in p["phrase"].strip('"'))  # exact, not fuzzy
    assert "D:CUI-Basic-Bare" not in cui_e["CUI-Detect-Block-Grade"]["expression"]      # never wired to block
    assert "(D:CUI-Basic-Bare > 2)" in cui_e["CUI-Detect-Caution-Grade"]["expression"]  # min 3 unique
    assert "(D:CUI-Declassify-Date > 0)" in cui_e["CUI-Detect-Caution-Grade"]["expression"]
    # The contextual engine (V1.1 low-confidence signal) needs three marking-guide phrases plus a category name.
    assert cui_e["CUI-Detect-Contextual"]["expression"].startswith("(((D:CUI-Contextual-Phrases > 2) AND (D:CUI-Category-Phrases > 0)))")
    assert "CUI-Category-Phrases" not in cui_e["CUI-Detect-Block-Grade"]["expression"] + cui_e["CUI-Detect-Caution-Grade"]["expression"]
    rules = {r["name"]: r for r in json.load(open(f"{fed['dir']}/configs/dlp_policies.json", encoding="utf-8")) if not r.get("channel_mirror")}
    assert rules["CUI-Monitor-All"]["engines"] == ["CUI-Detect-All", "CUI-Detect-Contextual"]
    assert rules["CUI-Block-Marked-Documents"]["engines"] == ["CUI-Detect-Block-Grade"]
    assert "Z-Controlled Unclassified Information-Monitor" not in rules and len(rules) == 12
    # Every dictionary an engine names is shipped by the pack or is a tenant predefined one.
    shipped = {d["name"] for d in dicts}
    import re
    for e in engines.values():
        for ref in re.findall(r"D:([^>]+?)\s*>", e["expression"]):
            assert ref.strip() in shipped or ref.strip().isupper(), f"{e['name']} references {ref!r}"


def test_fed_pack_cui_rules_deploy_and_measure():
    from test_pack_channels import add_control_services
    fed = _fed()
    client = add_control_services(make_client(casb_tenants=[casb_tenant("Acme M365 Mail", "OFFICE_365", 503),
                                                            casb_tenant("Acme OneDrive", "ONEDRIVE", 504)]))
    predefined = ["DISEASES_LEAKAGE", "DRUGS_LEAKAGE", "FINANCIAL", "MEDICAL", "ML_CORPORATE_FINANCE_LEAKAGE", "ML_MEDICAL_DOC_LEAKAGE", "ML_TAX_LEAKAGE",
                  "SSN", "USITIN_LEAKAGE", "USDL_LEAKAGE", "ABA_LEAKAGE", "CREDIT_CARD"]
    client.zia.dlp_dictionary.items = [Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(predefined)]
    rep = pd.preflight(client, [{"id": fed["id"], "dir": fed["dir"]}], writes_enabled=True)
    # "warnings": the V1.1 confidence tweaks raise predefined dictionaries to high confidence.
    assert rep["status"] in ("ready", "warnings"), rep["blockers"] + rep["warnings"]
    res = pd.apply(client, [{"id": fed["id"], "dir": fed["dir"]}], plan_hash=rep["plan_hash"], writes_enabled=True)
    # 72 dicts + 17 engines + 12 rules per channel across web, endpoint, saas, email
    # (plus the V1.1 confidence tweaks modifying two predefined dictionaries).
    assert res["summary"]["created"] == 72 + 17 + 48   # 12 rules x 4 channels
    full = next(e for e in client.zia.dlp_engine.added if e["name"] == "CUI-Detect-All")["engine_expression"]
    assert "D:" not in full and full.count(".S") == 28 and "AND NOT (D" in full
    prox = next(d for d in client.zia.dlp_dictionary.added if d["name"] == "CUI-Prox-LEGAL")
    assert prox["proximity"] == 300 and prox["match"] == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
    rules = {r["name"]: r for r in client.zia.dlp_web_rules.added}
    assert rules["CUI-Block-Marked-Documents"]["action"] == "BLOCK" and rules["CUI-Caution-Weak-Markings"]["action"] == "CONFIRM"
    assert all(r["state"] == "DISABLED" for r in rules.values()) and rules["CUI-Monitor-All"]["ocr_enabled"]
    # Re-running preflight finds everything present: nothing left to create.
    again = pd.preflight(client, [{"id": fed["id"], "dir": fed["dir"]}], writes_enabled=True)
    assert not any(i["status"] == pd.CREATE for i in again["items"])


def test_dictionary_limits_block_only_the_offending_dictionary(tmp_path):
    from dlp_importer import dictionary_limit_problems
    bad = dict(_dict("Too-Many"), patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": f"\\bX{i}\\b"} for i in range(9)])
    look = dict(_dict("Lookaround", pattern=r"(?<=CUI//)[A-Z]+"))
    far = dict(_dict("Far"), proximity=20000)
    assert dictionary_limit_problems(bad) and dictionary_limit_problems(look) and dictionary_limit_problems(far)
    assert dictionary_limit_problems(_dict("Fine", pattern=r"\bCUI//(SP-)?[A-Z]{2,10}\b")) == []
    pack = write_pack(tmp_path, "limits", dicts=[bad, look, far, _dict("Fine")],
                      engines=[_engine("E", "(D:Fine)")], policies=[_policy("R", ["E"])], meta=BASELINE_META)
    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    d = items_by(rep, "dictionary")
    assert d["Fine"]["status"] == pd.CREATE
    assert d["Too-Many"]["status"] == pd.BLOCKED_DEPENDENCY and "at most 8" in d["Too-Many"]["reason"]
    assert d["Lookaround"]["status"] == pd.BLOCKED_DEPENDENCY and "lookaround" in d["Lookaround"]["reason"]
    assert d["Far"]["status"] == pd.BLOCKED_DEPENDENCY and "0-10000" in d["Far"]["reason"]
    assert items_by(rep, "policy")["R"]["status"] == pd.CREATE


def test_phrase_match_type_and_engine_count_limits(tmp_path):
    from dlp_importer import dictionary_limit_problems, engine_limit_problems
    assert any("3-128 bytes" in x for x in dictionary_limit_problems({"phrases": [{"phrase": "ab"}]}))
    assert any("unknown match type" in x for x in dictionary_limit_problems({"custom_phrase_match_type": "MATCH_NOPE", "patterns": [{"pattern": "x"}]}))
    assert any("needs at least one pattern and one phrase" in x for x in dictionary_limit_problems(
        {"custom_phrase_match_type": "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE", "patterns": [{"pattern": "x"}], "phrases": []}))
    assert dictionary_limit_problems({"custom_phrase_match_type": "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE",
                                      "patterns": [{"pattern": r"\bCUI\b"}], "phrases": [{"phrase": "SP-EXPT"}], "proximity": 400}) == []
    assert engine_limit_problems("(D:A > 1000)") and engine_limit_problems("(D:A > 999)") == []
    pack = write_pack(tmp_path, "counts", dicts=[_dict("A")], engines=[_engine("Big", "(D:A > 1500)"), _engine("Ok", "(D:A > 2)")],
                      policies=[_policy("R", ["Ok"])], meta=BASELINE_META)
    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    e = items_by(rep, "engine")
    assert e["Big"]["status"] == pd.BLOCKED_DEPENDENCY and "under 1000" in e["Big"]["reason"]
    assert e["Ok"]["status"] == pd.CREATE and items_by(rep, "policy")["R"]["status"] == pd.CREATE


def test_cui_proximity_dictionaries_anchor_pattern_to_phrase():
    from dlp_importer import build_dict_kwargs
    cui = _fed()
    dicts = {d["name"]: d for d in json.load(open(f"{cui['dir']}/configs/dlp_dictionaries.json", encoding="utf-8"))}
    for name in [n for n in dicts if n.startswith("CUI-Prox-")] + ["CUI-Designation-Indicator"]:
        d = dicts[name]
        assert d["custom_phrase_match_type"] == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
        assert d["patterns"] == [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": r"\bCUI\b"}] and d["phrases"]
        assert d["proximity"] > 0 and d["proximity_enabled_for_custom_dictionary"] is True
        kw, err = build_dict_kwargs(d, {})
        assert err is None and kw["proximity"] == d["proximity"] and kw["proximity_enabled_for_custom_dictionary"] is True
    assert dicts["CUI-Prox-EXPT"]["phrases"] == [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "SP-EXPT"}]
