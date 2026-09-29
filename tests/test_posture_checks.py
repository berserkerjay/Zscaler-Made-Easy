"""
Assessment checks that read real tenant state rather than placeholders:
the DLP rule evaluation mode (Evaluate All Rules on/off) and Browser
Isolation (profiles exist AND policy routes traffic to them).
"""
from __future__ import annotations

import dlp_assessment_full_auto as chk


class FakeCl:
    """Minimal stand-in for sdk_client.Client: .get(endpoint) -> (data, status)."""
    def __init__(self, routes, cac=None):
        self.routes = routes
        self.calls = []
        if cac is not None:
            self._zs = type("Z", (), {})()
            self._zs.zia = type("ZIA", (), {})()
            self._zs.zia.cloudappcontrol = _FakeCac(cac)

    def get(self, endpoint, params=None):
        self.calls.append(endpoint)
        ep = endpoint.replace("raw:", "")
        if ep in self.routes:
            return self.routes[ep], 200
        return {"error": "not found"}, 404


class _FakeCac:
    def __init__(self, by_type):
        self.by_type = by_type

    def list_rules(self, rule_type, query_params=None):
        return list(self.by_type.get(rule_type, [])), None, None


RULES = [
    {"id": 1, "name": "Monitor PII", "order": 1, "action": "ALLOW", "state": "ENABLED", "dlpEngines": [{"id": 1}]},
    {"id": 2, "name": "Block SSN", "order": 2, "action": "BLOCK", "state": "ENABLED", "dlpEngines": [{"id": 2}]},
]


def test_evaluate_all_rules_on_is_a_pass():
    cl = FakeCl({"/zia/advancedSettings": {"inlineDlpRuleEvaluation": "EVALUATE_ALL_RULES"}, "/zia/webDlpRules": RULES})
    r = chk.c_5_20(cl)
    assert r.status == chk.R.PASS and "Evaluate All Rules is ON" in r.detail and r.data["evaluate_all"] is True
    assert "2/2 web DLP rules enabled" in r.detail


def test_by_rule_order_is_flagged_with_order_safety():
    cl = FakeCl({"/zia/advancedSettings": {"inlineDlpRuleEvaluation": "BY_RULE_ORDER"}, "/zia/webDlpRules": RULES})
    r = chk.c_5_20(cl)
    assert r.status == chk.R.WARN and "Evaluate All Rules is OFF" in r.detail and r.data["evaluate_all"] is False
    assert "first matching rule fires" in r.detail
    # A monitor rule above a block rule is exactly the unsafe order the wizard reorders.
    assert "NOT yet safe" in r.detail or "already safe" in r.detail


def test_unknown_mode_is_info_not_a_failure():
    cl = FakeCl({"/zia/webDlpRules": RULES})
    r = chk.c_5_20(cl)
    assert r.status == chk.R.INFO and "does not expose" in r.detail and r.data["evaluate_all"] is None
    assert chk.c_a9(cl).status == chk.R.INFO   # A.9 is the same check under the Inline Web channel


PROFILES = [{"id": 1, "name": "Restricted", "defaultProfile": True}]


def test_isolation_profiles_without_rules_is_a_warning():
    cl = FakeCl({"/zia/isolationProfile": PROFILES, "/zia/urlFilteringRules": [
        {"name": "Block gambling", "action": "BLOCK", "state": "ENABLED", "urlCategories": ["GAMBLING"]}]}, cac={})
    r = chk.c_3_7(cl)
    assert r.status == chk.R.WARN and "nothing is actually isolated" in r.detail
    assert r.data == {"profiles": 1, "url_rules": 0, "cac_rules": 0}


def test_isolation_in_policy_counts_url_and_cac_rules_across_types():
    cl = FakeCl({"/zia/isolationProfile": PROFILES, "/zia/urlFilteringRules": [
        {"name": "Isolate unknown", "action": "ISOLATE", "state": "ENABLED", "urlCategories": ["OTHER_MISCELLANEOUS"]},
        {"name": "Old isolate", "action": "ISOLATE", "state": "DISABLED", "urlCategories": ["GAMBLING"]}]},
        cac={"AI_ML": [{"name": "Isolate AI", "state": "ENABLED", "actions": ["ISOLATE_AI_ML_WEB_USE"]}],
             "FILE_SHARE": [{"name": "Allow FS", "state": "ENABLED", "actions": ["ALLOW_FILE_SHARE_VIEW"]}]})
    r = chk.c_3_7(cl)
    assert r.status == chk.R.PASS and r.data == {"profiles": 1, "url_rules": 1, "cac_rules": 1}
    assert "Isolate unknown" in r.detail and "Isolate AI (CAC AI_ML)" in r.detail
    cov = chk.c_a17(cl)
    assert cov.status == chk.R.PASS and cov.data["cac_classes"] == ["AI_ML"] and "FILE_SHARE" in cov.detail  # listed as missing
    assert chk.c_e13(cl).status == chk.R.PASS
    assert chk.c_mc5(cl).status == chk.R.PASS


def test_isolation_not_licensed_is_info():
    cl = FakeCl({}, cac={})
    r = chk.c_3_7(cl)
    assert r.status == chk.R.INFO and "not licensed" in r.detail
    assert chk.c_a17(cl).status == chk.R.INFO


def test_new_check_is_registered():
    ids = [c[0] for c in chk.REG]
    assert "A.17" in ids and len(ids) == len(set(ids))
