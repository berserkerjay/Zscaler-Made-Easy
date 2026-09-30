"""Checks brought in line with current Zscaler guidance and with the field
names the APIs actually return (zscaler-sdk-python 1.11.0): SSL Inspection
actions are objects, Client Connector settings live in policyExtension and
the per-platform policies, Windows 11 also reports version 10.0, and the
reference texts name current dates and pages."""
from __future__ import annotations

import json

import dlp_assessment_full_auto as chk
import zscaler_genai_checks as genai


class FakeCl:
    customer_id = ""

    def __init__(self, routes):
        self.routes = routes

    def get(self, endpoint, params=None):
        ep = endpoint.replace("raw:", "")
        if ep in self.routes:
            return self.routes[ep], 200
        return {"error": "not found"}, 404


# ── SSL Inspection: the action is {"type": ...} ─────────────────────────
SSL_RULES = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True,
     "action": {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": True}}},
    {"id": 2, "name": "Decrypt everything else", "order": 2, "state": "ENABLED",
     "action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "BLOCK", "minServerTLSVersion": "SERVER_TLS_1_2"}}},
    {"id": 3, "name": "Old pilot", "order": 3, "state": "DISABLED", "action": {"type": "DECRYPT"}},
]


def test_ssl_checks_read_the_action_object():
    cl = FakeCl({"/zia/sslInspectionRules": SSL_RULES})
    r = chk.c_4_1(cl)
    assert r.status == chk.R.PASS and "1 enabled Decrypt rule(s), 1 Do Not Decrypt" in r.detail
    assert chk.c_4_13(cl).status == chk.R.PASS
    assert chk.c_7_3(cl).status == chk.R.PASS
    assert chk.c_e2(cl).status == chk.R.PASS
    dni = chk.c_4_5(cl)
    assert dni.status == chk.R.WARN and "Zscaler Recommended Exemptions" in dni.detail
    assert genai.ai_5(cl).status == chk.R.PASS
    assert genai.ai_6(cl).status == chk.R.PASS


def test_a_broad_do_not_decrypt_rule_above_decrypt_is_caught():
    rules = [{"name": "Exempt all", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}},
             {"name": "Decrypt", "order": 2, "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    r = chk.c_4_3(FakeCl({"/zia/sslInspectionRules": rules}))
    assert r.status == chk.R.FAIL and "shadows" in r.detail
    # A category-scoped exemption does not shadow the decrypt rule.
    rules[0]["urlCategories"] = ["FINANCE"]
    assert chk.c_4_3(FakeCl({"/zia/sslInspectionRules": rules})).status == chk.R.PASS


def test_only_disabled_decrypt_rules_is_no_inspection():
    rules = [{"name": "Decrypt", "state": "DISABLED", "action": {"type": "DECRYPT"}}]
    cl = FakeCl({"/zia/sslInspectionRules": rules})
    assert chk.c_4_1(cl).status == chk.R.FAIL
    assert genai.ai_5(cl).status == chk.R.FAIL


def test_ssl_string_actions_from_old_exports_still_read():
    cl = FakeCl({"/zia/sslInspectionRules": [{"name": "x", "state": "ENABLED", "action": "INSPECT"}]})
    assert chk.c_4_1(cl).status == chk.R.PASS


def test_genai_exemption_of_an_ai_domain_is_a_failure():
    rules = [{"name": "Exempt ChatGPT", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["chatgpt.com"]}]
    assert genai.ai_6(FakeCl({"/zia/sslInspectionRules": rules})).status == chk.R.FAIL


# ── Client Connector: settings in policyExtension / platform policies ───
def _profile(**ext):
    return {"id": 1, "name": "Corp", "active": 1, "disablePassword": "x", "uninstallPassword": "x",
            "windowsPolicy": {"installCerts": ext.pop("installCerts", 1)},
            "policyExtension": json.dumps(ext)}


def test_install_endpoint_dlp_is_read_from_policy_extension():
    on = FakeCl({"/zcc/appProfiles": {"list": [_profile(enableZdpService=1)]}})
    r = chk.c_3_2(on)
    assert r.status == chk.R.PASS and "1/1" in r.detail
    assert chk.c_5_1(on).status == chk.R.PASS and chk.c_b1(on).status == chk.R.PASS
    off = FakeCl({"/zcc/appProfiles": {"list": [_profile(enableZdpService=0)]}})
    assert chk.c_3_2(off).status == chk.R.FAIL
    # Not reported at all is a question for the portal, not a failure.
    unknown = FakeCl({"/zcc/appProfiles": {"list": [{"id": 1, "name": "Corp"}]}})
    assert chk.c_3_2(unknown).status == chk.R.WARN


def test_ssl_certificate_install_is_read_from_the_platform_policy():
    assert chk.c_3_3(FakeCl({"/zcc/appProfiles": [_profile(installCerts=1)]})).status == chk.R.PASS
    assert chk.c_3_3(FakeCl({"/zcc/appProfiles": [_profile(installCerts=0)]})).status == chk.R.WARN


def test_dns_exclusion_priority_is_an_app_profile_setting():
    routes = {"/zcc/forwardingProfiles": [{"id": 5, "name": "fp"}]}
    routes["/zcc/appProfiles"] = [_profile(prioritizeDnsExclusions=1)]
    assert chk.c_1_7(FakeCl(routes)).status == chk.R.WARN
    routes["/zcc/appProfiles"] = [_profile(prioritizeDnsExclusions=0)]
    assert chk.c_1_7(FakeCl(routes)).status == chk.R.PASS


def test_z_tunnel_2_is_read_from_the_forwarding_actions():
    fp = {"id": 5, "name": "Corp", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ZSCALER_TUNNEL_2"}]}
    r = chk.c_1_6(FakeCl({"/zcc/forwardingProfiles": [fp]}))
    assert r.status == chk.R.PASS and "1 of 1" in r.detail
    pac = {"id": 6, "name": "PAC", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ENFORCE_PROXY"}]}
    r = chk.c_1_6(FakeCl({"/zcc/forwardingProfiles": [pac]}))
    assert r.status == chk.R.WARN and "Z-Tunnel 2.0" in r.detail


# ── Windows 10: Windows 11 also reports 10.0 ───────────────────────────
def test_windows_11_is_not_counted_as_windows_10():
    devs = [{"osType": "Windows", "osVersion": "10.0.22631"},                 # Windows 11 23H2
            {"osType": "Windows", "osVersion": "Microsoft Windows 11 Enterprise;64 bit"},
            {"osType": "Windows", "osVersion": "10.0.19045"},                 # Windows 10 22H2
            {"osType": "Windows", "osVersion": "Microsoft Windows 10 Pro;64 bit"},
            {"osType": "macOS", "osVersion": "10.15.7"}]
    r = chk.c_6_7(FakeCl({"/zcc/devices": devs}))
    assert r.status == chk.R.WARN and r.detail.startswith("2 Windows 10 device(s)")
    assert "14 October 2025" in r.detail and "Oct 2026" not in r.detail
    assert chk.c_6_7(FakeCl({"/zcc/devices": devs[:2]})).status == chk.R.PASS


# ── SSL decrypt sub-actions (4.14) ──────────────────────────────────────
def test_decrypt_rule_hardening_follows_the_leading_practices_guide():
    good = {"name": "Inspect all", "state": "ENABLED", "action": {"type": "DECRYPT", "decryptSubActions": {
        "serverCertificates": "BLOCK", "ocspCheck": True, "blockUndecrypt": True,
        "minClientTLSVersion": "CLIENT_TLS_1_2", "minServerTLSVersion": "SERVER_TLS_1_2"}}}
    r = chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [good]}))
    assert r.status == chk.R.PASS and r.data == {"rules": 1, "weak": 0}
    weak = {"name": "Legacy decrypt", "state": "ENABLED", "action": {"type": "DECRYPT", "decryptSubActions": {
        "serverCertificates": "PASS_THRU", "ocspCheck": False, "blockUndecrypt": False,
        "minClientTLSVersion": "CLIENT_TLS_1_0", "minServerTLSVersion": "SERVER_TLS_1_2"}}}
    r = chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [good, weak]}))
    assert r.status == chk.R.WARN and r.data == {"rules": 2, "weak": 1}
    for part in ("Legacy decrypt", "PASS_THRU", "OCSP revocation check off", "undecryptable traffic allowed", "CLIENT_TLS_1_0"):
        assert part in r.detail
    assert "SERVER_TLS_1_2" not in r.detail
    # Sub-actions the API did not return are not held against the rule; no decrypt rule is INFO.
    assert chk.c_4_14(FakeCl({"/zia/sslInspectionRules": [{"name": "x", "state": "ENABLED", "action": {"type": "DECRYPT"}}]})).status == chk.R.PASS
    assert chk.c_4_14(FakeCl({"/zia/sslInspectionRules": SSL_RULES[:1]})).status == chk.R.INFO


def test_new_ssl_check_is_registered_once():
    ids = [c[0] for c in chk.REG]
    assert ids.count("4.14") == 1 and len(ids) == len(set(ids))
    assert ids.index("4.14") == ids.index("4.13") + 1


# ── ECH is handled in DNS Control (4.12) ────────────────────────────────
def test_ech_is_suppressed_by_blocking_https_and_svcb_records():
    both = [{"name": "Block ECH", "state": "ENABLED", "action": "BLOCK_WITH_RESPONSE", "dnsRuleRequestTypes": ["HTTPS", "SVCB"]}]
    r = chk.c_4_12(FakeCl({"/zia/firewallDnsRules": both}))
    assert r.status == chk.R.PASS and "Block ECH" in r.detail
    one = [{"name": "Block HTTPS RR", "state": "ENABLED", "action": "BLOCK", "dnsRuleRequestTypes": ["HTTPS"]}]
    assert chk.c_4_12(FakeCl({"/zia/firewallDnsRules": one})).status == chk.R.WARN
    allow = [{"name": "Allow", "state": "ENABLED", "action": "ALLOW", "dnsRuleRequestTypes": ["HTTPS", "SVCB"]}]
    r = chk.c_4_12(FakeCl({"/zia/firewallDnsRules": allow}))
    assert r.status == chk.R.WARN and "best-practices-dns-control-rules" in r.detail
    # An SSL rule whose name merely contains "ech" (e.g. "Technology") no longer passes.
    assert chk.c_4_12(FakeCl({"/zia/sslInspectionRules": [{"name": "Technology", "action": {"type": "DECRYPT"}}]})).status == chk.R.INFO


# ── OCR is a DLP Advanced Settings switch (5.19) ───────────────────────
def test_ocr_is_read_from_dlp_advanced_settings():
    on = FakeCl({"/zia/webDlpGlobalOptions": {"enableInlineDlpOcr": True, "enableCasbOcr": False, "enableEmailDlpOcr": True}})
    r = chk.c_5_19(on)
    assert r.status == chk.R.PASS and "SaaS Security API" in r.detail and r.data["inline_ocr"] is True
    assert chk.c_8_12(on).status == chk.R.PASS and chk.c_b10(on).status == chk.R.PASS
    off = FakeCl({"/zia/webDlpGlobalOptions": {"enableInlineDlpOcr": False}, "/zia/webDlpRules": [{"name": "r", "state": "ENABLED", "ocrEnabled": True}]})
    r = chk.c_5_19(off)
    assert r.status == chk.R.WARN and "image files" in r.detail and "configuring-dlp-advanced-settings" in r.detail


def test_ocr_without_the_global_setting_is_not_a_per_rule_finding():
    rules = [{"name": "r", "state": "ENABLED"}]
    r = chk.c_5_19(FakeCl({"/zia/webDlpRules": rules}))
    assert r.status == chk.R.INFO and "not per rule" in r.detail
    # An older tenant that still reports the per-rule flag passes as before.
    assert chk.c_5_19(FakeCl({"/zia/webDlpRules": [{"name": "r", "state": "ENABLED", "ocrEnabled": True}]})).status == chk.R.PASS


# ── Evaluate All Rules read from DLP Advanced Settings (5.20) ──────────
DLP_RULES = [{"id": 1, "name": "Monitor PII", "order": 1, "action": "ALLOW", "state": "ENABLED", "dlpEngines": [{"id": 1}]},
             {"id": 2, "name": "Block SSN", "order": 2, "action": "BLOCK", "state": "ENABLED", "dlpEngines": [{"id": 2}]}]


def test_evaluate_all_rules_is_found_in_web_dlp_global_options():
    r = chk.c_5_20(FakeCl({"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": True}, "/zia/webDlpRules": DLP_RULES}))
    assert r.status == chk.R.PASS and "/zia/webDlpGlobalOptions" in r.data["found_via"] and "most restrictive" in r.detail
    r = chk.c_5_20(FakeCl({"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}, "/zia/webDlpRules": DLP_RULES}))
    assert r.status == chk.R.WARN and r.data["evaluate_all"] is False and "deleted" in r.detail


# ── EDM and IDM from dictionaryType (5.12, 5.14, 5.15) ─────────────────
def test_edm_and_idm_are_recognised_by_dictionary_type():
    dicts = [{"id": 1, "name": "Customer records", "custom": True, "dictionaryType": "EXACT_DATA_MATCH"},
             {"id": 2, "name": "Board papers", "custom": True, "dictionaryType": "INDEXED_DATA_MATCH",
              "idmProfileMatchAccuracyDetails": [{"matchAccuracy": "HEAVY"}]},
             {"id": 3, "name": "Cards", "custom": True, "dictionaryType": "PATTERNS_AND_PHRASES", "patterns": [{"pattern": "x"}]}]
    cl = FakeCl({"/zia/dlpDictionaries": dicts})
    assert chk.c_5_14(cl).status == chk.R.PASS and chk.c_5_15(cl).status == chk.R.PASS
    m = chk.c_5_12(cl)
    assert m.status == chk.R.PASS and "EDM" in m.detail and "IDM" in m.detail
    none = FakeCl({"/zia/dlpDictionaries": dicts[2:]})
    assert "about-exact-data-match" in chk.c_5_14(none).detail and "about-indexed-document-match" in chk.c_5_15(none).detail


# ── Endpoint channels come from Endpoint DLP rules (8.1–8.4) ───────────
def test_endpoint_channels_are_read_from_endpoint_dlp_rules():
    ep = [{"name": "Block USB PII", "state": "ENABLED", "type": "REMOVABLE_MEDIA", "action": "BLOCK"},
          {"name": "Printing", "state": "ENABLED", "dataTransferMethod": "PRINTING", "action": "CONFIRM"},
          {"name": "Shares", "state": "DISABLED", "dataTransferMethod": "NETWORK_DRIVE_TRANSFER"}]
    cl = FakeCl({"/zia/endPointDlpRules": ep, "/zia/webDlpRules": [{"name": "web", "state": "ENABLED", "cloudApplications": []}]})
    assert chk.c_8_1(cl).status == chk.R.PASS and chk.c_b7(cl).status == chk.R.PASS
    assert chk.c_8_2(cl).status == chk.R.PASS
    assert chk.c_8_3(cl).status == chk.R.WARN            # the share rule is disabled
    r = chk.c_8_4(cl)                                    # a web rule's cloudApplications key is not a personal-cloud rule
    assert r.status == chk.R.WARN and "Endpoint DLP" in r.detail
    r = chk.c_8_1(FakeCl({}))
    assert r.status == chk.R.INFO and "not readable" in r.detail


# ── NSS DLP rule field (12.9) ──────────────────────────────────────────
def test_nss_feed_should_name_the_triggered_dlp_rule():
    fmt = "%s{time} %s{dlpeng} %s{dlpdict} %s{dlpmd5} %s{trig_dlprulename}"
    assert chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "feedOutputFormat": fmt}]})).status == chk.R.PASS
    old = fmt.replace("trig_dlprulename", "dlprulename")
    r = chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "feedOutputFormat": old}]}))
    assert r.status == chk.R.WARN and "only for Allow rules" in r.detail
    r = chk.c_12_9(FakeCl({"/zia/nssFeeds": [{"name": "SIEM", "formatString": "%s{time} %s{dlpeng}"}]}))
    assert r.status == chk.R.WARN and "dlpdict" in r.detail and "trig_dlprulename" in r.detail


# ── Client Connector versions and strict enforcement ────────────────────
def test_client_connector_version_is_read_from_agent_version():
    devs = [{"osType": "Windows", "agentVersion": "3.9.0.150"}, {"osType": "Windows", "agentVersion": "4.8.0.1"},
            {"osType": "Linux", "agentVersion": "3.7.2.18"}]
    r = chk.c_6_1(FakeCl({"/zcc/devices": devs}))
    assert r.status == chk.R.FAIL and r.detail.startswith("1 device(s)") and "supported-versions" in r.detail
    assert chk.c_6_1(FakeCl({"/zcc/devices": devs[1:]})).status == chk.R.PASS


def test_strict_enforcement_is_read_from_the_flattened_profile():
    on = {"id": 1, "name": "Corp", "policyExtension": json.dumps({"strictEnforcement": 1})}
    assert chk.c_1_8(FakeCl({"/zcc/appProfiles": [on]})).status == chk.R.PASS
    off = {"id": 2, "name": "BYOD", "strictEnforcement": 0}
    r = chk.c_1_8(FakeCl({"/zcc/appProfiles": [on, off]}))
    assert r.status == chk.R.FAIL and "BYOD" in r.detail
    assert chk.c_1_8(FakeCl({"/zcc/appProfiles": [{"id": 3, "name": "x"}]})).status == chk.R.WARN


# ── Retention, timeout and naming texts match Zscaler's pages ───────────
def test_log_retention_texts_say_six_months_not_thirty_days():
    empty = FakeCl({"/zia/nssFeeds": []})
    for r in (chk.c_12_11(empty), chk.c_e15(empty), genai.ai_16(empty)):
        assert "30 days" not in r.detail and "30-day" not in r.detail and "six" in r.detail
    import zscaler_full_checks as full
    zpa = FakeCl({})
    assert "14 days" in full.zpa_14(zpa).detail and "30 days" not in full.zpa_14(zpa).detail
    t = full.zpa_7(zpa).detail
    assert "15min" not in t and "7 days" in t
    assert "Generative AI and ML Applications" in genai.ai_1(FakeCl({"/zia/urlCategories": []})).detail
