"""Policy packs: a literal "ANY" in a rule's device trust or user risk level
list. ["ANY"] alone means every level and goes out as the explicit list (the
API's and the zscaler/zia provider's form) in deploy and Terraform alike;
ANY next to other levels, or an unknown level, is refused with the reason."""
from __future__ import annotations

import json
import re

import pytest

import pack_channels as pc
import pack_deploy as pd
import pack_terraform as pt
from test_baselines import BASELINE_META  # noqa: F401
from test_pack_deploy import _dict, _engine, write_pack  # noqa: F401

TRUST = list(pc.ENDPOINT_TRUST_LEVELS)
RISK = list(pc.ENDPOINT_RISK_LEVELS)


def ep(name="EP-USB", **kw):
    return dict({"name": name, "channel": "endpoint", "action": "BLOCK", "state": "DISABLED", "severity": "RULE_SEVERITY_INFO",
                 "engines": ["Alpha Engine"], "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER"}, **kw)


def test_a_literal_any_is_expanded_to_every_level():
    """ASVS V5.1.3 · CWE-20: ["ANY"] (any case) becomes every device trust and user risk level, in the parent rule and its sub-rules."""
    p = ep(device_trust_levels=["ANY"], user_risk_score_levels=["any"],
           sub_rules=[{"name": "S1", "device_trust_levels": ["Any"], "user_risk_score_levels": ["low", "HIGH"]}])
    n = pc.normalize_levels(p)
    assert n["device_trust_levels"] == TRUST and n["user_risk_score_levels"] == RISK
    assert n["sub_rules"][0]["device_trust_levels"] == TRUST and n["sub_rules"][0]["user_risk_score_levels"] == ["LOW", "HIGH"]
    assert p["device_trust_levels"] == ["ANY"]        # a copy: the pack as read is not changed
    assert pc.validate(p) is None
    plain = ep(device_trust_levels=["LOW_TRUST"])
    assert pc.normalize_levels(plain) is plain and pc.normalize_levels(ep()) == ep()


@pytest.mark.parametrize("field, value, words", [
    ("device_trust_levels", ["ANY", "LOW_TRUST"], "mixes ANY with other levels"),
    ("user_risk_score_levels", ["HIGH", "any"], "mixes ANY with other levels"),
    ("device_trust_levels", ["SUPER_TRUST"], "unknown level 'SUPER_TRUST'"),
    ("user_risk_score_levels", ["SEVERE"], "unknown level 'SEVERE'"),
    ("device_trust_levels", "ANY", "must be a list"),
    ("user_risk_score_levels", [1, 2], "must be a list"),
])
def test_ambiguous_or_unknown_levels_are_refused_with_the_reason(field, value, words):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ANY next to other levels, an unknown level or a non-list is refused by validation, naming the field."""
    err = pc.validate(ep(**{field: value}))
    assert err and words in err and field in err
    sub = ep(sub_rules=[{"name": "S1", field: value}])
    assert "sub-rule 'S1'" in pc.validate(sub)


def test_the_pack_reader_expands_any_and_refuses_a_mix(tmp_path):
    """ASVS V5.1.3 · CWE-20: the app's one pack-file reader expands ["ANY"] for deploy, removal, Terraform and the library, and refuses a mix."""
    pack = write_pack(tmp_path, "anyp", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
                      policies=[ep(device_trust_levels=["ANY"], user_risk_score_levels=["ANY"])], meta={"name": "Any pack", "confidence_tweaks": []})
    rows = pd.load_pack_file(f"{pack['dir']}/configs", "dlp_policies.json", "anyp")
    assert rows[0]["device_trust_levels"] == TRUST and rows[0]["user_risk_score_levels"] == RISK
    json.dump([ep(device_trust_levels=["ANY", "HIGH_TRUST"])], open(f"{pack['dir']}/configs/dlp_policies.json", "w"))
    with pytest.raises(pd.PackFileError, match="mixes ANY with other levels"):
        pd.load_pack_file(f"{pack['dir']}/configs", "dlp_policies.json", "anyp")


def test_the_deploy_payload_carries_the_explicit_lists():
    """ASVS V5.1.3 · CWE-20: the add_rule payload of a rule written with ["ANY"] names every level, never ANY."""
    body = pc.build_payload(pc.ENDPOINT, ep(device_trust_levels=["ANY"], user_risk_score_levels=["ANY"]), [11], {})
    flat = json.dumps(body)
    assert '"ANY"' not in flat
    assert body["device_trust_levels"] == TRUST and body["user_risk_score_levels"] == RISK
    # The same rule with the explicit lists has the same signature, so a re-deploy finds it unchanged.
    assert pc.policy_signature_extra(ep(device_trust_levels=["ANY"])) == pc.policy_signature_extra(ep(device_trust_levels=TRUST))


def test_terraform_writes_the_explicit_lists(tmp_path):
    """ASVS V5.1.3 · CWE-20: the generated workspace gives the provider the explicit levels (it takes no ANY)."""
    pack = write_pack(tmp_path, "anytf", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
                      policies=[ep(device_trust_levels=["ANY"], user_risk_score_levels=["ANY"])],
                      meta=dict(BASELINE_META, name="Any TF"))
    rules = re.sub(r"[ \t]+=[ \t]+", " = ", pt.generate(pack)["rules.tf"])
    assert 'device_trust_levels = ["UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST"]' in rules
    assert 'user_risk_score_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]' in rules
    assert '"ANY"' not in rules.split("zia_endpoint_dlp_rules", 1)[1].split("}\n\n", 1)[0]
