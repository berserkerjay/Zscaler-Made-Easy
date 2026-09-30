"""The paths the app reads are the ones the Zscaler APIs serve: a probe of a
live tenant (OneAPI, zscaler-sdk-python 1.11.0) found checks reading paths
that answer 404, 400 or 405, and some of them turned the refusal into a
finding. These pin the corrected paths, the endpoints the API only lists in
parts (Cloud App Control per rule type, ZCC admin users per userType), the
ZIdentity base path, and the checks that now say "not available by API"
instead of reporting a gap that was really a wrong path."""
from __future__ import annotations

import os
import re
import time

import pytest

import dlp_assessment_full_auto as fa

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class _Resp:
    def __init__(self, status, body=None):
        self.status_code, self._body, self.text, self.headers = status, body, "" if body is not None else "not found", {}

    def json(self):
        return self._body


class _Session:
    """Answers GETs from a {path: (status, body)} table; anything else is 404."""
    def __init__(self, table):
        self.table, self.headers, self.cookies, self.calls = table, {}, {}, []

    def get(self, url, params=None, timeout=None):
        path = url.split("api.zsapi.net", 1)[-1]
        self.calls.append((path, dict(params or {})))
        key = (path, tuple(sorted((params or {}).items())))
        hit = self.table.get(key, self.table.get(path))
        return _Resp(*hit) if hit else _Resp(404)


def _client(monkeypatch, table):
    sess = _Session(table)
    monkeypatch.setattr(fa.requests, "Session", lambda: sess)
    c = fa.Client("cid", "sec", "acme", "production")
    c.token, c.exp = "t", time.time() + 3600
    c._limiter = fa._RateLimiter(0)
    return c, sess


# ---------------------------------------------------------------------------
# The resolver
# ---------------------------------------------------------------------------

def test_zidentity_lives_at_ziam_admin_api_v1():
    assert fa._resolve_ep("/zid/users") == "/ziam/admin/api/v1/users"
    assert fa._resolve_ep("/zid/groups") == "/ziam/admin/api/v1/groups"
    assert fa._resolve_ep("/zid/resourceServers") == "/ziam/admin/api/v1/resource-servers"
    assert "userEntitlement" not in fa._ZID_MAP, "entitlements are per user; there is no list of all of them"


def test_zcc_device_cleanup_uses_the_real_path():
    assert fa._resolve_candidates("/zcc/deviceCleanup") == ["/zcc/papi/public/v1/getDeviceCleanupInfo"]


def test_zidentity_pages_are_read_from_records():
    assert fa._ls({"records": [{"id": 1}], "results_total": 1}) == [{"id": 1}]


# ---------------------------------------------------------------------------
# Endpoints listed in parts
# ---------------------------------------------------------------------------

def test_cloud_app_control_rules_are_read_for_every_rule_type(monkeypatch):
    c, sess = _client(monkeypatch, {
        "/zia/api/v1/webApplicationRules/AI_ML": (200, [{"id": 1, "name": "block genai"}]),
        "/zia/api/v1/webApplicationRules/WEBMAIL": (200, [{"id": 2, "name": "webmail"}]),
        "/zia/api/v1/webApplicationRules/FILE_SHARE": (200, []),
    })
    rules, code = c.get("/zia/cloudApplicationRules")
    assert code == 200
    assert sorted((r["id"], r["type"]) for r in rules) == [(1, "AI_ML"), (2, "WEBMAIL")], "each rule carries the type it was listed under"
    asked = {p for p, _ in sess.calls}
    assert asked == {f"/zia/api/v1/webApplicationRules/{t}" for t in fa._CAC_TYPES}, "one call per rule type, never the non-existent flat list"
    n = len(sess.calls)
    assert c.get("/zia/cloudApplicationRules") == (rules, 200) and len(sess.calls) == n, "the combined answer is cached"


def test_a_fan_out_where_no_part_answers_reports_the_first_status(monkeypatch):
    c, _ = _client(monkeypatch, {})
    data, code = c.get("/zia/cloudApplicationRules")
    assert code == 404 and isinstance(data, dict)


def test_zcc_admin_users_are_read_per_user_type(monkeypatch):
    c, sess = _client(monkeypatch, {
        ("/zcc/papi/public/v1/getAdminUsers", (("userType", 1),)): (200, [{"id": "a", "userName": "zia-admin"}]),
        ("/zcc/papi/public/v1/getAdminUsers", (("userType", 3),)): (200, [{"id": "b", "userName": "zid-admin"}]),
        ("/zcc/papi/public/v1/getAdminUsers", (("userType", 2),)): (200, []),
        ("/zcc/papi/public/v1/getAdminUsers", (("userType", 4),)): (200, []),
    })
    users, code = c.get("/zcc/adminUsers")
    assert code == 200 and [(u["id"], u["userType"]) for u in users] == [("a", 1), ("b", 3)]
    assert all(p.get("userType") in (1, 2, 3, 4) for _, p in sess.calls), "the API refuses getAdminUsers without userType"


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

class _Fixed:
    """A client stub for single checks: {short path: (data, status)}."""
    def __init__(self, table):
        self.table, self.asked = table, []

    def get(self, ep, p=None):
        self.asked.append(ep)
        return self.table.get(ep, ({"error": "not found"}, 404))


def test_malware_settings_are_read_from_the_blocked_flags():
    import zscaler_full_checks as fc
    on = fc.sec_3(_Fixed({"/zia/cyberThreatProtection/malwareSettings": ({"trojanBlocked": True, "spywareBlocked": False}, 200)}))
    off = fc.sec_3(_Fixed({"/zia/cyberThreatProtection/malwareSettings": ({"trojanBlocked": False, "spywareBlocked": False}, 200)}))
    assert on.status == "PASS" and off.status != "PASS"


def test_the_security_blacklist_is_a_field_of_security_advanced():
    import zscaler_full_checks as fc
    cl = _Fixed({"/zia/security/advanced": ({"blacklistUrls": ["bad.example"]}, 200)})
    r = fc.sec_1(cl)
    assert r.status == "PASS" and "1 URL" in r.detail
    assert "/zia/security/advanced/blacklistUrls" not in cl.asked, "that path only takes POST/PUT"


def test_zidentity_entitlements_are_not_reported_as_group_based_when_unreadable():
    import zscaler_rbac_checks as rb
    import zscaler_zidentity_checks as zid
    r1 = rb.rbac_zid_group_based(_Fixed({}))
    r2 = zid.zid_user_entitlements(_Fixed({}))
    assert r1.status == "INFO" and r2.status == "INFO", "an unreadable list used to pass as 'group-only binding is in force'"


def test_checks_without_a_public_api_say_so_instead_of_reporting_a_gap():
    for fn in (fa.c_5_2, fa.c_12_4, fa.c_b15):
        r = fn(_Fixed({}))
        assert r.status == "INFO", fn.__name__
    r = fa.c_1_13(_Fixed({}))
    assert r.status == "INFO" and "Client Connector portal" in r.detail


def test_no_check_reads_a_path_the_live_api_does_not_serve():
    """Paths a live tenant answered 404/400/405 to, and the real ones."""
    wrong = {
        "/zia/firewallRules": "/zia/firewallFilteringRules", "/zia/dnsRules": "/zia/firewallDnsRules",
        "/zia/ipsRules": "/zia/firewallIpsRules", "/zia/staticIPs": "/zia/staticIP", "/zia/admins": "/zia/adminUsers",
        "/zia/atpSettings": "/zia/cyberThreatProtection/advancedThreatSettings",
        "/zia/malwareProtection": "/zia/cyberThreatProtection/malwareSettings",
        "/zia/cloudApplicationSslPolicy": "/zia/cloudApplications/sslPolicy", "/zia/fileTypeControlRules": "/zia/fileTypeRules",
        "/zia/endpointDlpRules": "/zia/endPointDlpRules", "/zia/isolationProfile": "/zia/browserIsolation/profiles",
        "/zia/incidentReceivers": "/zia/incidentReceiverServers", "/zia/notificationTemplates": "/zia/dlpNotificationTemplates",
        "/zia/nssFeed": "/zia/nssFeeds", "/zia/adminAndRoleManagement": "/zia/adminRoles",
        "/zia/authenticationSettings": "/zia/authSettings", "/zia/security/advanced/blacklistUrls": "/zia/security/advanced",
        "/zia/workflows": None, "/zia/workflowAutomation": None, "/zia/emailSecurityRules": None,
        "/zia/devicePostureProfiles": None, "/zid/userEntitlement": None,
    }
    offenders = []
    for name in sorted(os.listdir(ROOT)):
        if not name.endswith(".py") or name == "discover_endpoints.py":
            continue
        text = open(os.path.join(ROOT, name), encoding="utf-8").read()
        for path in wrong:
            if re.search(r'"' + re.escape(path) + r'"', text):
                offenders.append(f"{name}: {path}")
    assert not offenders, offenders
    # A bare casbDlpRules GET needs a rule type; /all lists every rule.
    for name in ("dlp_assessment_full_auto.py", "data_flow.py"):
        assert 'get("/zia/casbDlpRules")' not in open(os.path.join(ROOT, name), encoding="utf-8").read()


def test_the_sdk_route_map_has_no_aliases_to_the_wrong_list():
    text = open(os.path.join(ROOT, "sdk_client.py"), encoding="utf-8").read()
    assert '"/zia/endpointDlpResources"' not in text, "it returned the ICAP server list"
    assert '"/zia/devicePostureProfiles"' not in text, "it returned device groups"
    assert '"STREAMING_MEDIA")' not in text, "Cloud App Control rules of one type only"
    keys = re.findall(r'^\s+"(/z[a-z]+/[^"]+)":', text, re.M)
    assert len(keys) == len(set(keys)), "a duplicate key silently wins"


# ---------------------------------------------------------------------------
# ZPA and ZDX (verified on a tenant once its API client had both roles)
# ---------------------------------------------------------------------------

def test_zpa_paths_use_the_base_and_policy_type_the_api_serves():
    base = "/zpa/mgmtconfig/{}/admin/customers/42/"
    assert fa._resolve_ep("/zpa/application", "42") == base.format("v1") + "application"
    for short, real in (("/zpa/idp", "idp"), ("/zpa/trustedNetwork", "network"), ("/zpa/postureProfile", "posture"),
                        ("/zpa/samlAttribute", "samlAttribute"), ("/zpa/lssConfig", "lssConfig")):
        assert fa._resolve_ep(short, "42") == base.format("v2") + real, short
    assert fa._resolve_ep("/zpa/policySet/rules/ACCESS_POLICY", "42") == base.format("v1") + "policySet/rules/policyType/ACCESS_POLICY"
    assert fa._resolve_ep("/zpa/policySet/rules/TIMEOUT_POLICY", "42") == base.format("v1") + "policySet/rules/policyType/TIMEOUT_POLICY"
    assert fa._resolve_ep("/zpa/applicationSegments", "42") == base.format("v1") + "application"


def test_zdx_paths_use_the_names_the_api_serves():
    assert fa._resolve_ep("/zdx/administration/apps") == "/zdx/v1/apps"
    assert fa._resolve_ep("/zdx/troubleshooting/devices") == "/zdx/v1/devices"
    assert fa._resolve_ep("/zdx/alerts/ongoing") == "/zdx/v1/alerts/ongoing"


def test_zpa_policy_checks_read_the_access_policy_type():
    import zscaler_full_checks as fc
    import zscaler_rbac_checks as rb
    rules = [{"id": 1, "name": "allow finance", "conditions": [{"operands": [{"objectType": "SCIM_GROUP"}]}]}]
    cl = _Fixed({"/zpa/policySet/rules/ACCESS_POLICY": ({"list": rules}, 200)})
    assert fc.zpa_6(cl).status == "PASS"
    assert "/zpa/policySet/rules/GLOBAL_POLICY" not in cl.asked and "/zpa/policySet/rules" not in cl.asked, "no GLOBAL_POLICY type exists"
    cl = _Fixed({"/zpa/policySet/rules/ACCESS_POLICY": ({"list": rules}, 200)})
    rb.rbac_zpa_policies_group_bound(cl)
    assert cl.asked == ["/zpa/policySet/rules/ACCESS_POLICY"]


def test_zdx_checks_without_an_api_say_so_without_a_call():
    import zscaler_zdx_checks as zc
    for fn in (zc.zdx_alert_rules, zc.zdx_reports_available):
        cl = _Fixed({})
        r = fn(cl)
        assert r.status == "INFO" and "ZDX Admin Portal" in r.detail and not cl.asked, fn.__name__
