"""Edition-aware rule sets (editions.py): the Cloud Firewall, Cloud Sandbox
and ZDX editions read from the tenant's ZIA licence list, and what the ZIA
security baseline and the ZDX probe setup offer or leave out for each.

The tenant is the made-up sample tenant (offline_tenant, sample_tenant.py),
whose licence list is swapped per test; no network, no real tenant."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import editions  # noqa: E402
import offline_tenant as ot  # noqa: E402
import ops_zia_baseline as zb  # noqa: E402

SUBS = ot.normalize_path("/zia/api/v1/subscriptions")
ZIA_ZDX = ao.scope_for(["dlp", "zia_extras", "zdx"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
ZDX_ONLY = ao.scope_for(["zdx"], {})
BASELINE = {"type": "zia_baseline", "tier": "strict", "prefix": "LKF", "areas": ["firewall", "sandbox"]}
ZDX_SETUP = {"type": "zdx_probes", "template": "", "interval_minutes": 5, "protocol": "ADAPTIVE",
             "predefined": [{"provider": "MICROSOFT_LOGIN", "web": True, "cloudpath": True}, {"provider": "ZOOM", "web": True, "cloudpath": True}],
             "custom": [{"name": "Larkspur intranet", "url": "https://intranet.larkspur-freight.example/", "cloudpath": True}]}


@pytest.fixture(autouse=True)
def _plugins(monkeypatch):
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    ao.load_plugins()


def sample(*skus, missing=False):
    st = ot.sample_store(reset=True)
    if missing:
        st.responses.pop(SUBS, None)
    elif skus:
        st.responses[SUBS] = {"status": 200, "body": [{"id": s, "subscribed": True, "status": "ACTIVE"} for s in skus]}
    return st, ot.OfflineSdkClient(st, ot.creds_for(st))


def by_key(out):
    return {u["key"]: u for u in out["items"]}


@pytest.mark.parametrize("skus,want", [
    (["ZFW_NG_WITH_LOG", "ZSEC_WEB_ABA_ADV", "ZDX_ADVANCED"], ("advanced", "advanced", "advanced")),
    (["Z_FIREWALL_BASIC", "ZSEC_WEB_ABA", "Z_ZDX_STD"], ("standard", "standard", "standard")),
    (["ZIA_ATP", "Z_ZDX_M365"], ("standard", "standard", "m365")),
    (["ZDX_LITE"], ("unknown", "unknown", "lite")),
    (["ZIA_BUS"], ("unknown", "unknown", "unknown")),
    (["Z_FIREWALL_BASIC", "ZFW_NG_WITH_LOG", "ZDX_ADV_PLUS", "Z_ZDX_STD"], ("advanced", "unknown", "advanced")),
])
def test_editions_are_detected_from_the_licence_ids(skus, want):
    """ASVS V1.14.1 · CWE-1188: each subscription id maps to its edition, the higher edition wins, and a list that names none leaves it unknown."""
    ed = editions.detect(skus)
    assert (ed["firewall"], ed["sandbox"], ed["zdx"]) == want and ed["read"] is True
    assert editions.detect(None) == {"firewall": "unknown", "sandbox": "unknown", "zdx": "unknown", "read": False}


def test_the_licence_list_is_read_only_when_a_zia_scope_is_ticked():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: with only ZDX ticked the ZIA licence list is not read (the Scope rule) and every edition is unknown, saying why; with ZIA ticked it is read."""
    # Arrange
    st, cl = sample()
    seen = []
    real = st.answer_get
    st.answer_get = lambda url, params=None: seen.append(ot.normalize_path(url)) or real(url, params)
    # Act
    off = editions.read(cl, ZDX_ONLY)
    on = editions.read(cl, ZIA_ZDX)
    # Assert
    assert off["zdx"] == "unknown" and "no ZIA scope" in off["why"] and seen.count(SUBS) == 1
    assert on["firewall"] == "standard" and on["zdx"] == "standard"


def test_a_standard_firewall_and_sandbox_leave_out_the_advanced_rules():
    """ASVS V1.14.1 · CWE-1188: with only the standard Cloud Firewall and Sandbox, the application-based firewall rules, the default deny and the quarantine sandbox rules are left out with the reason, the executables rule loses AI Instant Verdict, and the preview says so."""
    # Arrange
    st, cl = sample("ZIA_TENANT", "Z_FIREWALL_BASIC", "ZSEC_WEB_ABA")
    # Act
    out = ao.plan(cl, dict(BASELINE), scope=ZIA_ZDX)
    # Assert
    k = by_key(out)
    for key in editions.FIREWALL_ADVANCED_ONLY + editions.SANDBOX_ADVANCED_ONLY:
        u = k[f"zb:{key.split('.')[0].replace('fw', 'firewall').replace('sb', 'sandbox')}:{key}:rule"]
        assert u["status"] == "excluded" and "Advanced" in u["reason"], (key, u)
    for key in ("fw.geo_out", "fw.geo_in", "fw.quic", "sb.executables"):
        area = "firewall" if key.startswith("fw") else "sandbox"
        assert k[f"zb:{area}:{key}:rule"]["status"] == "change", key
    exe = next(g for g in out["groups"] if g["key"] == "zb:sandbox:sb.executables")
    assert exe["target"]["payload"]["ml_action_enabled"] is False
    assert out["editions"]["firewall"] == "standard" and out["editions"]["sandbox"] == "standard"
    assert any("Only the standard Cloud Firewall is licensed" in n for n in out["notes"])
    assert any("AI Instant Verdict" in w for w in out["warnings"])


def test_the_advanced_editions_or_an_unknown_one_offer_every_rule():
    """ASVS V1.14.1 · CWE-1188: Cloud Firewall and Sandbox Advanced keep every rule; an unreadable licence list (unknown edition) keeps every rule too and says the edition is not known."""
    for kw in ({"skus": ("ZFW_NG_WITH_LOG", "ZSEC_WEB_ABA_ADV")}, {"missing": True}):
        # Arrange
        st, cl = sample(*kw.get("skus", ()), missing=kw.get("missing", False))
        # Act
        out = ao.plan(cl, dict(BASELINE), scope=ZIA_ZDX)
        # Assert
        assert not [u for u in out["items"] if u["status"] == "excluded"], kw
        exe = next(g for g in out["groups"] if g["key"] == "zb:sandbox:sb.executables")
        assert exe["target"]["payload"]["ml_action_enabled"] is True
        if kw.get("missing"):
            assert any("edition not known" in n for n in out["notes"])


def test_a_required_rule_the_edition_leaves_out_warns_that_its_control_is_not_met():
    """ASVS V1.14.1 · CWE-1188: FedRAMP Moderate requires the default deny (SC-7(5)); a standard-only firewall leaves it out and the preview says the control is not met."""
    st, cl = sample("Z_FIREWALL_BASIC")
    out = ao.plan(cl, dict(BASELINE, compliance_profile="FEDRAMP_MOD"), scope=ZIA_ZDX)
    assert by_key(out)["zb:firewall:fw.default_deny:rule"]["status"] == "excluded"
    assert any("FW-Default-Deny" in w and "control is not met" in w for w in out["warnings"])


def test_the_baseline_form_marks_the_rules_the_edition_leaves_out():
    """ASVS V1.14.1 · CWE-1188: the form's read lists the edition, its plain note and, per rule, why the edition leaves it out."""
    st, cl = sample("Z_FIREWALL_BASIC", "ZSEC_WEB_ABA")
    res = zb._read_catalog(cl, ZIA_ZDX, lambda m: None, None)
    ed = res["editions"]
    assert ed["firewall"] == "standard" and set(ed["limits"]) >= set(editions.FIREWALL_ADVANCED_ONLY) | set(editions.SANDBOX_ADVANCED_ONLY)
    assert "fw.geo_out" not in ed["limits"] and ed["notes"]


@pytest.mark.parametrize("skus,left_out", [
    (("ZDX_ADVANCED",), set()),
    (("Z_ZDX_STD",), {"Zoom"}),
    (("Z_ZDX_M365",), {"Zoom", "Larkspur intranet"}),
    (("ZDX_LITE",), {"Microsoft 365 sign-in", "Zoom", "Larkspur intranet"}),
])
def test_the_zdx_setup_offers_only_what_the_zdx_edition_allows(skus, left_out):
    """ASVS V1.14.1 · CWE-1188: ZDX Standard leaves out call-quality apps, M365 everything but Microsoft 365, Lite every app; Advanced keeps all; each left-out app says why and the notes name the edition."""
    # Arrange
    st, cl = sample(*skus)
    spec = dict(ZDX_SETUP, predefined=[dict(p, prefix="larkspur") for p in ZDX_SETUP["predefined"]])
    # Act
    out = ao.plan(cl, spec, scope=ZIA_ZDX)
    # Assert
    apps = {(u["object"] or {}).get("name"): u for u in out["items"] if u["kind"] == "zdx_app"}
    assert set(apps) == {"Microsoft 365 sign-in", "Zoom", "Larkspur intranet"}
    gone = {n for n, u in apps.items() if u["status"] == "excluded" and "licensed edition" in (u.get("reason") or "")}
    assert gone == left_out, (gone, {n: u.get("reason") for n, u in apps.items()})
    assert any(editions.label("zdx", editions.detect(skus)["zdx"]) in n for n in out["notes"])


def test_the_zdx_form_says_what_the_edition_leaves_out():
    """ASVS V1.14.1 · CWE-1188: the ZDX form's read names the edition, its note and the providers and custom apps it leaves out."""
    import ops_zdx as oz
    st, cl = sample("Z_ZDX_M365")
    res = oz.read_objects(cl, ZIA_ZDX, lambda m: None, None)
    ed = res["zdx"]["edition"]
    assert ed["zdx"] == "m365" and ed["label"] == "ZDX M365" and ed["custom_limit"] and "ZOOM" in ed["limits"]
    assert "MICROSOFT_LOGIN" not in ed["limits"] and ed["notes"]
