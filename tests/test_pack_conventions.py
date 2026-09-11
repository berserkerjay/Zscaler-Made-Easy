"""Every rule in every pack ships DISABLED and monitor-only; the designed
action survives as target_action so the journey can name the hardening
step. Applies to the shipped packs on disk and, at load time, to any
uploaded pack."""
from __future__ import annotations

import glob
import json
import os

import pack_channels as pc
import pack_deploy as pd
import pack_terraform

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MONITOR = {"ALLOW", "OFLCASB_DLP_REPORT_INCIDENT"}


def test_every_shipped_pack_rule_is_disabled_and_monitor_only():
    files = sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_policies.json")))
    assert len(files) >= 6
    targets = 0
    for f in files:
        for r in json.load(open(f, encoding="utf-8")):
            assert str(r.get("state", "ENABLED")).upper() == "DISABLED", (f, r["name"])
            ch = pc.channel_of(r)
            if pc.has_engines(ch):
                assert r.get("action") in MONITOR, (f, r["name"], r.get("action"))
                if r.get("target_action"):
                    assert pc.is_enforcing(ch, r["target_action"]), (f, r["name"])
                    targets += 1
    assert targets == 0, "shipped packs carry no block target: every rule simply monitors (uploaded packs keep target_action via ship_monitor)"


def test_ship_monitor_normalises_uploaded_rules_and_keeps_the_design():
    rules = [
        {"name": "Up-Block", "channel": "web", "action": "BLOCK", "state": "ENABLED", "engines": ["E"]},
        {"name": "Up-Confirm", "channel": "endpoint", "action": "CONFIRM", "state": "DISABLED", "engines": ["E"]},
        {"name": "Up-SaaS", "channel": "saas", "action": "OFLCASB_DLP_REMOVE_SHARING", "saas_type": "OFLCASB_DLP_FILE", "engines": ["E"]},
        {"name": "Up-Monitor", "channel": "email", "action": "ALLOW", "state": "DISABLED", "engines": ["E"]},
        {"name": "Up-URL", "channel": "url", "action": "BLOCK", "state": "ENABLED", "url_categories": ["OTHER_MISCELLANEOUS"]},
    ]
    out = pc.ship_monitor(rules)
    by = {r["name"]: r for r in out}
    assert by["Up-Block"]["action"] == "ALLOW" and by["Up-Block"]["target_action"] == "BLOCK"
    assert by["Up-Block"]["state"] == "ENABLED", "the state is forced where the rule is created, not here"
    assert by["Up-Confirm"]["action"] == "ALLOW" and by["Up-Confirm"]["target_action"] == "CONFIRM"
    assert by["Up-SaaS"]["action"] == "OFLCASB_DLP_REPORT_INCIDENT" and by["Up-SaaS"]["target_action"] == "OFLCASB_DLP_REMOVE_SHARING"
    assert by["Up-Monitor"]["action"] == "ALLOW" and "target_action" not in by["Up-Monitor"]
    assert by["Up-URL"]["action"] == "BLOCK", "containment rules have no monitor form and are left as designed"
    body = pc.build_payload("web", by["Up-Block"], [1], {})
    assert body["state"] == "DISABLED" and body["action"] == "ALLOW" and "target_action" not in body, "the API never sees the target"
    body = pc.build_payload("endpoint", {"name": "E", "channel": "endpoint", "action": "BLOCK", "state": "ENABLED", "engines": ["E"]}, [1], {})
    assert body["state"] == "DISABLED" and body["action"] == "ALLOW"
    assert rules[0]["action"] == "BLOCK" and rules[0]["state"] == "ENABLED", "the originals are untouched"
    assert pc.target_action(by["Up-Block"]) == "BLOCK" and pc.target_action(by["Up-Monitor"]) == "ALLOW"


def test_loaders_apply_the_convention_and_the_journey_names_the_target():
    pack = {"id": "healthcare_phi_baseline", "dir": os.path.join(ROOT, "healthcare_phi_baseline")}
    src = pd.load_sources([pack])[0]
    crit = next(p for p in src["policies"] if p["name"] == "HC-HIPAA Critical-Monitor")
    assert crit["action"] == "ALLOW" and "target_action" not in crit and crit["state"] == "DISABLED"
    step = pd._next_step({"kind": "policy", "name": crit["name"], "definition": crit, "channel": "web"}, "monitoring", "enforcing")
    assert "from monitor to an enforcing action (BLOCK)" in step
    files = pack_terraform.generate(pack)
    main = "\n".join(files.values())
    assert 'action                       = "ALLOW"' in main or 'action = "ALLOW"' in main.replace("  ", " ")
    assert "designed action once incidents are tuned" not in main, "no shipped rule carries a block target"
    assert '"BLOCK"' not in main.split("zia_dlp_web_rules")[1].split("zia_endpoint_dlp_rules")[0] if "zia_endpoint_dlp_rules" in main else True


def test_validator_warns_about_enforcing_uploads():
    import pack_library as pl
    pack = {"meta": {"name": "Up"}, "dictionaries": [{"name": "D1", "phrases": [{"phrase": "alpha beta gamma"}]}],
            "engines": [{"name": "E1", "expression": "D:D1"}],
            "policies": [{"name": "R1", "channel": "web", "action": "BLOCK", "state": "DISABLED", "engines": ["E1"]}], "app_groups": []}
    v = pl.validate_pack(pack)
    assert v["ok"] and any("carry an enforcing action" in w and "R1 (BLOCK)" in w for w in v["warnings"])


def test_one_rule_per_engine_and_equal_counts_on_every_channel():
    """The pack convention: every Web DLP rule carries exactly one engine,
    every engine has a rule, and Endpoint, SaaS and Email each mirror the
    Web rules one for one."""
    for f in sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_policies.json"))):
        pack = os.path.basename(os.path.dirname(os.path.dirname(f)))
        rules = json.load(open(f, encoding="utf-8"))
        engines = sorted(e["name"] for e in json.load(open(os.path.join(os.path.dirname(f), "dlp_engines.json"), encoding="utf-8")))
        web = [r for r in rules if pc.channel_of(r) == pc.WEB]
        assert all(len(r.get("engines") or []) == 1 for r in web), (pack, [r["name"] for r in web if len(r.get("engines") or []) != 1])
        assert sorted(r["engines"][0] for r in web) == engines, (pack, "every engine has exactly one Web rule")
        counts = {ch: sum(1 for r in rules if pc.channel_of(r) == ch) for ch in (pc.WEB, pc.ENDPOINT, pc.SAAS, pc.EMAIL)}
        assert len(set(counts.values())) == 1, (pack, counts)
        names = [r["name"] for r in rules]
        assert len(names) == len(set(names)), (pack, "rule names are unique")


def test_healthcare_deploys_on_a_tenant_without_the_medical_bundle():
    """A tenant that exposes only the SSN dictionary (no medical bundle, no
    driver's-licence or NDC dictionaries) still gets every healthcare
    engine (pruned, with the missing terms named) and every rule on every
    channel. Names with parentheses used to be reported truncated, which
    blocked the engines and skipped all 32 rules."""
    import sys
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from test_pack_channels import TENANTS, make_client
    client = make_client(casb_tenants=TENANTS)
    pack = {"id": "healthcare_phi_baseline", "dir": os.path.join(ROOT, "healthcare_phi_baseline")}
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["status"] != "blocked", rep["blockers"]
    engines = [i for i in rep["items"] if i["kind"] == "engine"]
    assert engines and all(i["status"] == pd.CREATE for i in engines), [(i["name"], i["status"], i.get("reason")) for i in engines if i["status"] != pd.CREATE]
    pruned = {i["name"]: i["pruned"] for i in engines}
    assert "Names (US)" in pruned["HIPAA Identity Trifecta"] and "Driver's License (United States)" in pruned["HIPAA Identity Trifecta"]
    # The Fed-derived PII clones of TIN and driver's licence have no template on this tenant:
    # they are blocked, and the engines that use them are created without those terms.
    assert "HC-Tax Identification Number (US) - High" in pruned["HIPAA US PII"] and "HC-Drivers License (United States) - Prox 500" in pruned["HIPAA US PHI - High Confidence"]
    rules = [i for i in rep["items"] if i["kind"] == "policy"]
    assert len(rules) == 48 and all(i["status"] == pd.CREATE for i in rules), [(i["name"], i["status"]) for i in rules if i["status"] != pd.CREATE]
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    # 7 custom + 12 PII (4 clones without a template here) + 9 financial (4 clones without a template) dictionaries, 12 engines, 12 rules x 4 channels
    assert res["summary"]["created"] == (7 + 12 - 4 + 9 - 4) + 12 + 48


def test_no_shipped_dictionary_sets_proximity_on_a_type_zia_rejects():
    """ZIA accepts a proximity window only on MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE
    (a real tenant answered 400 "Proximity can be enabled only for 'Match any
    Patterns and any Phrases'..." for four healthcare dictionaries on the
    Match All type, which blocked every engine and rule behind them)."""
    from dlp_importer import DICT_PROXIMITY_MATCH_TYPE, dictionary_limit_problems
    bad = []
    files = sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_dictionaries.json")))
    assert len(files) >= 6
    for f in files:
        for d in json.load(open(f, encoding="utf-8")):
            if d.get("predefined_clone"):
                continue    # a clone's proximity rides the template (proximity_length_enabled); the Fed pack deployed them on Match Any
            if (d.get("proximity") or 0) > 0 and d.get("custom_phrase_match_type") != DICT_PROXIMITY_MATCH_TYPE:
                bad.append((f, d["name"], d.get("custom_phrase_match_type")))
            assert not dictionary_limit_problems(d), (f, d["name"], dictionary_limit_problems(d))
    assert bad == []
    assert any("needs match type" in p for p in dictionary_limit_problems(
        {"custom_phrase_match_type": "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "proximity": 50,
         "patterns": [{"pattern": r"\bMRN\d{6}\b"}], "phrases": [{"phrase": "medical record"}]}))


def test_every_shipped_name_uses_characters_zia_accepts_and_engine_descriptions_fit(tmp_path):
    """A real tenant refused "HIPAA Narrative / Low Volume" (INVALID_NAME: only
    alphanumeric, underscore, hyphen, dot, parentheses and space) and every
    engine whose description passed 255 characters. Engine names are checked
    in the pack and by preflight; descriptions are clamped on deploy, which
    is exercised here against the fake tenant that refuses both like the
    real one. Dictionary names keep clear of the same slash / plus / ampersand."""
    from dlp_importer import name_problems
    for f in sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_engines.json"))):
        for e in json.load(open(f, encoding="utf-8")):
            assert name_problems(e["name"]) == [], (f, e["name"])
    for f in sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_dictionaries.json"))):
        for d in json.load(open(f, encoding="utf-8")):
            assert not any(c in d["name"] for c in "/+&"), (f, d["name"])
    assert name_problems("HIPAA Narrative / Low Volume") and name_problems("A + B") and not name_problems("HIPAA Critical (Strong Signature and Clinical Document)")
    import sys
    sys.path.insert(0, os.path.join(ROOT, "tests"))
    from test_pack_channels import TENANTS, make_client
    client = make_client(casb_tenants=TENANTS)
    pack = {"id": "healthcare_phi_baseline", "dir": os.path.join(ROOT, "healthcare_phi_baseline")}
    rep = pd.preflight(client, [pack], writes_enabled=True)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    # 7 custom + 12 PII (4 clones without a template here) + 9 financial (4 clones without a template) dictionaries, 12 engines, 12 rules x 4 channels
    assert res["summary"]["created"] == (7 + 12 - 4 + 9 - 4) + 12 + 48, res["summary"]
    assert len(client.zia.dlp_engine.added) == 12
    for e in client.zia.dlp_engine.added:
        assert len(e["description"].encode("utf-8")) <= 255 and "[DLP-Check baseline healthcare_phi_baseline" in e["description"], e["name"]
    # A bad engine name is stopped in the plan, with the reason, before any write.
    from test_pack_channels import _dict, _engine, _policy, write_pack
    bad_pack = write_pack(tmp_path / "badname", "badname", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha / Beta", "(D:Alpha Dict)")],
                          policies=[_policy("Web-Monitor", ["Alpha / Beta"])], meta={"name": "Bad", "confidence_tweaks": []})
    bad = pd.preflight(make_client(casb_tenants=TENANTS), [bad_pack], writes_enabled=True)
    eng = next(i for i in bad["items"] if i["kind"] == "engine")
    assert eng["status"] == pd.BLOCKED_DEPENDENCY and "ZIA allows" in eng["reason"] and "'/'" in eng["reason"]
