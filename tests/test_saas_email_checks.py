"""SaaS Security (Ch.C) and Email DLP (Ch.D) are scored channel sections."""
from __future__ import annotations

import dlp_assessment_full_auto as a
import saas_email_checks as se


class FakeCl:
    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, ep, p=None):
        self.calls.append((ep, dict(p or {})))
        key = (ep, (p or {}).get("appType"))
        if key in self.routes:
            return self.routes[key]
        return self.routes.get(ep, ([], 200))


SP = {"tenant_id": 11, "tenant_name": "SMOES", "saas_application": "SHAREPOINT"}
EXO = {"tenant_id": 22, "tenant_name": "Corp mail", "saas_application": "MSEXCHANGE"}


def _saas_rule(**kw):
    r = {"name": "ZBP-US PII [SaaS]", "type": "OFLCASB_DLP_FILE", "state": "DISABLED", "action": "OFLCASB_DLP_REPORT_INCIDENT",
         "dlp_engines": [{"id": 5}], "cloud_app_tenants": [{"id": 11}], "collaboration_scope": ["ANY"]}
    r.update(kw)
    return r


def _email_rule(**kw):
    r = {"name": "ZBP-US PII [Email]", "state": "DISABLED", "action": "ALLOW", "dlp_engines": [{"id": 5}]}
    r.update(kw)
    return r


def run(cl):
    return {cid: fn(cl) for cid, _, _, fn in se.CHECKS}


def test_both_channels_are_scored_sections_in_the_assessment():
    secs = [r[1] for r in a.REG]
    assert secs.count(se.SAAS) == 8 and secs.count(se.EMAIL) == 8
    assert secs.index(se.SAAS) > secs.index("Ch.B — Endpoint") and secs.index(se.EMAIL) < secs.index("Ch.E — GenAI")
    import channel_scope
    assert se.SAAS in channel_scope.CHANNEL_CHECKS["saas_casb"]["sections"]
    assert se.EMAIL in channel_scope.CHANNEL_CHECKS["email_dlp"]["sections"]
    import plain_english as pe
    assert pe.outcome_for("C.1", se.SAAS) != pe.FALLBACK_OUTCOME and pe.outcome_for("D.1", se.EMAIL) != pe.FALLBACK_OUTCOME


def test_a_tenant_with_sharepoint_and_monitor_only_pack_rules():
    cl = FakeCl({
        ("/zia/casbTenant/lite", None): ([SP], 200),
        ("/zia/casbTenant/lite", "EMAIL"): ([], 200),
        "/zia/casbDlpRules/all": ([_saas_rule()], 200),
        "/zia/emailDlpRules": ([_email_rule()], 200),
    })
    res = run(cl)
    st = {k: v.status for k, v in res.items()}
    assert st["C.1"] == "PASS" and "SMOES (SHAREPOINT)" in res["C.1"].detail
    assert st["C.2"] == "PASS" and st["C.3"] == "PASS" and st["C.4"] == "PASS" and st["C.5"] == "PASS" and st["C.8"] == "PASS"
    assert st["C.6"] == "FAIL" and "disabled" in res["C.6"].detail
    assert st["C.7"] == "REVIEW"
    assert st["D.1"] == "FAIL" and "Exchange, Gmail or secure email gateway" in res["D.1"].detail and "requires one" in res["D.1"].detail
    assert st["D.2"] == "PASS" and st["D.3"] == "PASS" and st["D.4"] == "FAIL" and st["D.5"] == "REVIEW"
    assert st["D.6"] == "REVIEW" and "name no email tenant" in res["D.6"].detail
    assert all(ep in ("/zia/casbTenant/lite", "/zia/casbDlpRules/all", "/zia/emailDlpRules") for ep, _ in cl.calls), "read-only GETs only"
    assert ("/zia/casbTenant/lite", {"activeOnly": "true", "appType": "EMAIL"}) in cl.calls


def test_an_exchange_tenant_is_recognised_and_scoped_rules_pass():
    cl = FakeCl({
        ("/zia/casbTenant/lite", None): ([SP, EXO], 200),
        ("/zia/casbTenant/lite", "EMAIL"): ([EXO], 200),
        "/zia/casbDlpRules/all": ([_saas_rule(state="ENABLED", action="OFLCASB_DLP_QUARANTINE")], 200),
        "/zia/emailDlpRules": ([_email_rule(state="ENABLED", action="BLOCK", email_tenants=[{"id": 22}], external_auditor_email="soc@corp.example")], 200),
    })
    st = {k: v.status for k, v in run(cl).items()}
    assert st["D.1"] == "PASS" and st["D.4"] == "PASS" and st["D.5"] == "PASS" and st["D.6"] == "PASS" and st["D.7"] == "PASS"
    assert st["C.6"] == "PASS" and st["C.7"] == "PASS"


def test_nothing_onboarded_and_not_licensed_are_said_plainly():
    cl = FakeCl({("/zia/casbTenant/lite", None): ([], 200), ("/zia/casbTenant/lite", "EMAIL"): ([], 200),
                 "/zia/casbDlpRules/all": ({"error": "nf"}, 404), "/zia/emailDlpRules": ([], 200)})
    res = run(cl)
    assert res["C.1"].status == "FAIL" and res["C.2"].status == "INFO" and "not licensed" in res["C.2"].detail
    assert res["D.2"].status == "FAIL" and res["D.3"].status == "INFO"
    denied = FakeCl({"/zia/emailDlpRules": ({"error": "denied"}, 403)})
    assert se.c_d2(denied).status == "ERROR" and "role" in se.c_d2(denied).detail


def test_a_rule_without_engines_and_an_uncovered_app_fail():
    box = {"tenant_id": 33, "tenant_name": "Box", "saas_application": "BOX"}
    cl = FakeCl({("/zia/casbTenant/lite", None): ([SP, box], 200),
                 "/zia/casbDlpRules/all": ([_saas_rule(dlp_engines=[])], 200)})
    assert se.c_c5(cl).status == "FAIL" and se.c_c3(cl).status == "FAIL" and "Box (BOX)" in se.c_c3(cl).detail
