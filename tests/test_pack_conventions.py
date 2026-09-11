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
    assert targets >= 10, "the designed block/confirm actions are kept as targets"


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
    crit = next(p for p in src["policies"] if p["name"] == "HC-HIPAA Critical-Block")
    assert crit["action"] == "ALLOW" and crit["target_action"] == "BLOCK" and crit["state"] == "DISABLED"
    step = pd._next_step({"kind": "policy", "name": crit["name"], "definition": crit, "channel": "web"}, "monitoring", "enforcing")
    assert "from monitor to an enforcing action (BLOCK)" in step
    files = pack_terraform.generate(pack)
    main = "\n".join(files.values())
    assert 'action                       = "ALLOW"' in main or 'action = "ALLOW"' in main.replace("  ", " ")
    assert "designed action once incidents are tuned is BLOCK" in main
    assert '"BLOCK"' not in main.split("zia_dlp_web_rules")[1].split("zia_endpoint_dlp_rules")[0] if "zia_endpoint_dlp_rules" in main else True


def test_validator_warns_about_enforcing_uploads():
    import pack_library as pl
    pack = {"meta": {"name": "Up"}, "dictionaries": [{"name": "D1", "phrases": [{"phrase": "alpha beta gamma"}]}],
            "engines": [{"name": "E1", "expression": "D:D1"}],
            "policies": [{"name": "R1", "channel": "web", "action": "BLOCK", "state": "DISABLED", "engines": ["E1"]}], "app_groups": []}
    v = pl.validate_pack(pack)
    assert v["ok"] and any("carry an enforcing action" in w and "R1 (BLOCK)" in w for w in v["warnings"])
