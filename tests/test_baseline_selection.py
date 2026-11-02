"""ZIA baseline rule review: a selection saved as a file and loaded again
(ops_zia_baseline.selection_doc / load_selection, POST
/api/zia-baseline/selection). The loaded file is untrusted: format, size,
every key and the build's own normalize() decide; nothing reads or writes a
tenant. No network."""
from __future__ import annotations

import copy
import json

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import dlp_api_server as srv
import ops_zia_baseline as zb

SPEC = {"type": "zia_baseline", "tier": "strict", "prefix": "QA", "areas": ["firewall", "url", "ucaas"], "overlays": ["CJIS"],
        "rules": {"fw.p2p": {"on": False}, "url.legal": {"action": "ALLOW"}}, "atp": {"tor_blocked": False},
        "ucaas": {"enableUcaasZoom": True}, "mode": "tier", "compliance_profile": "FEDRAMP_MOD", "enable_rules": False}


@pytest.fixture
def client():
    return TestClient(srv.app, base_url="http://127.0.0.1")


def test_a_saved_selection_loads_back_to_the_same_review():
    """ASVS V5.1.3 · CWE-20: a selection saved from the review loads back to the same choices, and the review built from it is the review it was saved from."""
    # Arrange
    doc = zb.selection_doc(SPEC)
    # Act
    back = zb.load_selection(json.loads(json.dumps(doc)))
    # Assert
    assert doc["format"] == zb.SELECTION_FORMAT and doc["format_version"] == zb.SELECTION_VERSION and "framework" not in doc
    sel = back["selection"]
    assert sel["tier"] == "strict" and sel["rules"] == {"fw.p2p": {"on": False, "action": "TIER"}, "url.legal": {"on": True, "action": "ALLOW"}}
    assert sel["ucaas"] == {"enableUcaasZoom": True} and sel["compliance_profile"] == "FEDRAMP_MOD" and "NIST_800_53" in sel["overlays"]
    a, b = zb.review(SPEC), zb.review(dict(sel, type=zb.TYPE))
    assert [(r["key"], r["on"], r["action"]) for r in a["rules"]] == [(r["key"], r["on"], r["action"]) for r in b["rules"]]
    assert back["ignored"] == []


@pytest.mark.parametrize("change,word", [
    (lambda d: d.update(format="zia-policy-framework"), "Not a ZIA baseline selection"),
    (lambda d: d.update(format_version=99), "newer version"),
    (lambda d: d.update(format_version="1"), "format_version"),
    (lambda d: d.update(framework={"x": 1}), "Unknown field"),
    (lambda d: d.update(tier="nope"), "Unknown tier"),
    (lambda d: d.update(prefix="<script>"), "prefix"),
    (lambda d: d.update(rules={"<img src=x>": {"on": False}}), "Not a baseline rule key"),
    (lambda d: d.update(rules={"fw.p2p": {"action": "DELETE"}}), "TIER, ALLOW, BLOCK or ISOLATE"),
    (lambda d: d.update(atp={"rm_rf": True}), "Advanced Threat Protection"),
    (lambda d: d.update(ucaas={"enableUcaasZoom": "yes"}), "UCaaS"),
    (lambda d: d.update(enable_rules="true"), "enable_rules"),
    (lambda d: d.update(compliance_profile="NOPE"), "Unknown compliance profile"),
    (lambda d: d.update(overlays=["x" * 300000]), "larger than"),
])
def test_an_untrusted_selection_is_refused_with_the_reason(change, word):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · WSTG-INPV-01: a wrong format or version, an unknown field, rule key, action, switch, profile or an oversized file is refused, naming why."""
    doc = zb.selection_doc(SPEC)
    change(doc)
    with pytest.raises(ao.OperationError, match=word):
        zb.load_selection(doc)


def test_a_rule_this_version_does_not_know_is_left_out_and_listed():
    """ASVS V5.1.3 · CWE-20: a well-formed rule key that is not in this version's catalog is left out and named, never used."""
    doc = zb.selection_doc(SPEC)
    doc["rules"]["fw.future_rule"] = {"on": False}
    back = zb.load_selection(doc)
    assert back["ignored"] == ["fw.future_rule"] and "fw.future_rule" not in back["selection"]["rules"]


def test_the_route_saves_and_checks_a_selection(client):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the route saves a spec as a selection and checks an uploaded one; a bad file is a 400 with the reason; both or neither is a 400."""
    # Act
    saved = client.post("/api/zia-baseline/selection", json={"spec": SPEC})
    loaded = client.post("/api/zia-baseline/selection", json={"selection": saved.json()["selection"]})
    bad = client.post("/api/zia-baseline/selection", json={"selection": dict(saved.json()["selection"], tier="nope")})
    both = client.post("/api/zia-baseline/selection", json={"spec": SPEC, "selection": {}})
    # Assert
    assert saved.status_code == 200 and saved.json()["selection"]["format"] == zb.SELECTION_FORMAT
    assert loaded.status_code == 200 and loaded.json()["selection"]["tier"] == "strict"
    assert bad.status_code == 400 and "Unknown tier" in bad.json()["detail"]
    assert both.status_code == 400


def test_a_selection_is_not_saved_from_a_framework_or_an_undo():
    """ASVS V5.1.3 · CWE-20: a selection holds a tier's choices only; a loaded framework file or an Undo form is refused."""
    with pytest.raises(ao.OperationError, match="tier"):
        zb.selection_doc({"action": "revert", "steps": [{"op": "restore_atp", "values": {}}]})
