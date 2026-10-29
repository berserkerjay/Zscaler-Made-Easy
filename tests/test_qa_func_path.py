"""Functional correctness of traffic analysis (QA wave 6, slug func-path):
the Path analyzer (path_analyzer, zia_path_modules, zpa_path,
workload_path, pac_eval, path_whatif), Test a list (bulk_test), the Data
Flow Map (data_flow), SSL flow and SSL coverage, and ZPA diagnostics.

Oracle tables from Zscaler's documented semantics (zscaler-sdk-python
1.11.3 models and docstrings, the help text the app itself cites, and the
PAC specification); property tests over random tenants with a fixed seed;
edge cases; the wording of definite and conditional answers; and the
arithmetic of every count. Fake tenants only: nothing is read from or
written to a real tenant. Assumed semantics are marked "assumed" in the
docstrings and in docs/qa/findings/func-path.json."""
from __future__ import annotations

import copy
import json
import math
import random

import pytest

import bulk_test as bt
import data_flow as df
import pac_eval
import path_analyzer as pa
import path_whatif as pw
import ssl_coverage as sc
import ssl_flow as sf
import zia_path_modules as zpm
import zpa_analysis as za
import zpa_path as zp
from test_path_zpa_workloads import stage as zpa_stage, zpa_data
from test_zpa_analysis import APP, _cond, _op, _rule, _seg

SEED = 20261029
FULL = pa.full_path_scope()

# ── A small fake tenant ─────────────────────────────────────────────────
APP_PROFILES = [{"id": 1, "name": "Win", "os": "windows", "active": True, "ruleOrder": 1, "forwardingProfileId": 5,
                 "strictEnforcement": True, "installEndpointDlp": True, "sslCertInstall": True}]
TUNNEL = [{"id": 5, "name": "Fwd", "forwardingProfileActions": [
    {"networkType": n, "tunnelType": "ZSCALER_TUNNEL_2"} for n in ("ON_TRUSTED_NETWORK", "OFF_TRUSTED_NETWORK", "VPN_TRUSTED_NETWORK")]}]
PAC_FWD = [{"id": 5, "name": "Fwd", "forwardingProfileActions": [
    {"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "ENFORCE_PROXY", "customPac": "https://pac.example/p.pac"}]}]
DECRYPT_ALL = {"id": 3, "name": "Decrypt all", "order": 9, "state": "ENABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["ANY"]}
DLP_BLOCK = {"id": 50, "name": "DLP block", "order": 1, "state": "ENABLED", "action": "BLOCK", "dlpEngines": [{"name": "PCI"}]}
DEFAULT_FW = {"id": 999, "name": "Default Firewall Filtering Rule", "order": -1, "defaultRule": True, "state": "ENABLED", "action": "ALLOW"}
BASE = {
    "/zcc/webPolicies": APP_PROFILES, "/zcc/forwardingProfiles": TUNNEL, "/zcc/trustedNetworks": [], "/zia/pacFiles": [],
    "/zia/sslInspectionRules": [DECRYPT_ALL], "/zia/urlFilteringRules": [], "/zia/cloudApplicationRules": [], "/zia/fileTypeRules": [],
    "/zia/webDlpRules": [DLP_BLOCK], "/zia/endPointDlpRules": [], "/zia/casbDlpRules/all": [], "/zia/emailDlpRules": [], "/zia/urlCategories": [],
    "/zia/cyberThreatProtection/advancedThreatSettings": {}, "/zia/cyberThreatProtection/securityExceptions": {"bypassUrls": []},
    "/zia/cyberThreatProtection/maliciousUrls": {"maliciousUrls": []}, "/zia/security": {"whitelistUrls": []},
    "/zia/security/advanced": {"blacklistUrls": []}, "/zia/firewallFilteringRules": [DEFAULT_FW],
    "/zia/networkServices": [], "/zia/networkServiceGroups": [], "/zia/networkApplicationGroups": [],
    "/zia/ipDestinationGroups": [], "/zia/ipSourceGroups": [], "/zia/firewallDnsRules": [], "/zia/sandboxRules": [],
}
LOOKUP = {"casino.example": ["GAMBLING"], "mail.example": ["WEB_MAIL"], "files.example": ["FILE_HOST"], "chat.example": ["AI_ML_APPS"],
          "news.example": ["NEWS_AND_MEDIA"], "203.0.113.5": ["OTHER_MISCELLANEOUS"]}


class Tenant:
    """GET answers the routes; POST answers only ZIA's read-only URL lookup."""

    def __init__(self, routes=None, lookup=None):
        self.routes = dict(copy.deepcopy(BASE), **copy.deepcopy(routes or {}))
        self.lookup = LOOKUP if lookup is None else lookup
        self.writes = []

    def get(self, ep, p=None):
        return (copy.deepcopy(self.routes[ep]), 200) if ep in self.routes else ([], 200)

    def post(self, ep, body=None):
        if ep != "/zia/urlLookup":
            self.writes.append(ep)
            raise AssertionError("only the read-only URL lookup may be posted")
        return [{"url": h, "urlClassifications": self.lookup.get(h, [])} for h in body], 200


def run(dest, routes=None, scope=FULL, **kw):
    return pa.analyze(Tenant(routes), dest, kw.pop("network", "off"), kw.pop("platform", "windows"), scope=scope, **kw)


def hop(res, key):
    return next(h for h in res["trace"]["hops"] if h["key"] == key)


def mod(res, key):
    return next(m for m in res["zia_modules"]["modules"] if m["key"] == key)


def url_rule(i, order, action, cats, **kw):
    return dict({"id": i, "name": f"URL {i}", "order": order, "state": "ENABLED", "action": action, "urlCategories": cats}, **kw)


def fw_rule(i, order, action, **kw):
    return dict({"id": i, "name": f"FW {i}", "order": order, "state": "ENABLED", "action": action}, **kw)


# ═══ 1. Oracle tables ═══════════════════════════════════════════════════

# ── Destinations as typed ───────────────────────────────────────────────
@pytest.mark.parametrize("typed,host,is_ip,port,kind", [
    ("EXAMPLE.COM.", "example.com", False, None, "host"),                       # upper case, trailing dot
    ("https://u:pw@Example.com:8443/a/b?q=1#frag", "example.com", False, 8443, "url"),   # user info, port, path, query, fragment
    ("http://10.0.0.1/x", "10.0.0.1", True, None, "ip"),                         # IP literal in a URL
    ("2001:db8::1", "2001:db8::1", True, None, "ip"),                            # bare IPv6
    ("[2001:db8::1]:443", "2001:db8::1", True, 443, "ip"),
    ("https://[2001:DB8::1]:65535/", "2001:db8::1", True, 65535, "ip"),         # highest port
    ("münchen.de", "xn--mnchen-3ya.de", False, None, "host"),                   # IDN to punycode
    ("https://BÜCHER.example/x", "xn--bcher-kva.example", False, None, "url"),
    ("xn--mnchen-3ya.de", "xn--mnchen-3ya.de", False, None, "host"),
])
def test_a_destination_is_placed_by_the_host_the_tenant_sees(typed, host, is_ip, port, kind):
    """ASVS V5.1.3 · CWE-20: upper case, trailing dots, user info, ports, IPv6 and IDN hosts are placed by the host ZIA sees."""
    d = pa.parse_destination(typed)
    assert (d["host"], d["is_ip"], d["port"], d["kind"]) == (host, is_ip, port, kind)


@pytest.mark.parametrize("typed", ["http://example.com:0/", "example.com:65536", "exa mple.com", "", "localhost"])
def test_a_destination_that_is_not_one_is_refused_in_words(typed):
    """ASVS V5.1.3 · CWE-20: port 0, port 65536, spaces and single-label names are refused with a sentence."""
    with pytest.raises(ValueError):
        pa.parse_destination(typed)


def test_the_password_in_a_typed_url_is_never_repeated_back():
    """ASVS V8.3.1 · CWE-200: a user name and password typed in a URL are not echoed in the result or its messages."""
    res = run("https://alice:hunter2-secret@example.com/upload")
    assert "hunter2-secret" not in json.dumps(res, default=str) and res["destination"]["input"] == "https://example.com/upload"
    with pytest.raises(ValueError) as e:
        pa.parse_destination("https://alice:hunter2-secret@exa mple.com/")
    assert "hunter2-secret" not in str(e.value)


@pytest.mark.parametrize("typed,private", [("10.0.0.1", True), ("::ffff:10.0.0.1", True), ("fd00::1", True), ("203.0.113.5", False),
                                           ("2001:db8::5", False), ("172.32.0.1", False), ("172.31.255.255", True)])
def test_private_addresses_follow_rfc1918_loopback_and_link_local(typed, private):
    """ASVS V5.1.3 · CWE-697: RFC 1918 boundaries, IPv6 ULA and IPv4-mapped IPv6 are private; documentation ranges are not."""
    assert pa.parse_destination(typed)["private"] is private


# ── ZIA URL lists (custom categories, ATP lists) ─────────────────────────
@pytest.mark.parametrize("entry,host,path,visible,state", [
    ("example.com", "example.com", "/", True, "match"),
    ("example.com", "sub.example.com", "/", True, "no_match"),       # a bare entry is that host only
    (".example.com", "example.com", "/", True, "match"),             # a leading dot: the domain ...
    (".example.com", "a.b.example.com", "/", True, "match"),         # ... and every subdomain
    ("*.example.com", "a.example.com", "/", True, "match"),
    (".example.com", "badexample.com", "/", True, "no_match"),
    ("EXAMPLE.com.", "example.com", "/", True, "match"),             # upper case, trailing dot
    ("example.com/private", "example.com", "/private/x", True, "match"),
    ("example.com/private", "example.com", "/public", True, "no_match"),
    ("example.com/private", "example.com", "/private", None, "unknown"),   # path, decryption not established
    ("203.0.113.0/24", "203.0.113.255", "/", True, "match"),        # CIDR boundary, last address
    ("203.0.113.0/24", "203.0.114.0", "/", True, "no_match"),       # first address past it
    ("203.0.113.1-203.0.113.9", "203.0.113.9", "/", True, "match"),
    ("2001:db8::/32", "2001:db8:ffff::1", "/", True, "match"),
])
def test_zia_url_list_semantics(entry, host, path, visible, state):
    """ASVS V4.1.3 · CWE-697: 'example.com' is that host, '.example.com' the domain and its subdomains, a path needs the path (app help text)."""
    assert zpm.url_hit([entry], {"host": host, "path": path}, visible)[0] == state


@pytest.mark.parametrize("entry,dest,blocked", [
    ("partner.example", "partner.example", True),
    ("partner.example", "evil.partner.example", False),
    (".partner.example", "evil.partner.example", True),
    ("partner.example/secret", "https://partner.example/secret/a", True),
    ("partner.example/secret", "partner.example", False),
])
def test_a_custom_url_category_places_a_destination_by_zia_semantics(entry, dest, blocked):
    """ASVS V4.1.3 · CWE-697: a bare custom-category entry does not cover subdomains, so a URL rule on it does not block them."""
    routes = {"/zia/urlCategories": [{"id": "CUSTOM_01", "configuredName": "Partner", "customCategory": True, "urls": [entry], "dbCategorizedUrls": []}],
              "/zia/urlFilteringRules": [url_rule(20, 1, "BLOCK", ["CUSTOM_01"])]}
    assert (run(dest, routes)["verdict"]["outcome"] == "blocked") is blocked


# ── Rule order, first match, default rule, disabled rules (Cloud Firewall) ─
@pytest.mark.parametrize("rules,verdict,rule", [
    ([fw_rule(1, 2, "BLOCK_DROP"), fw_rule(2, 1, "ALLOW")], "allow", "FW 2"),                                   # order, not list position
    ([fw_rule(1, 1, "BLOCK_DROP", state="DISABLED"), fw_rule(2, 2, "ALLOW")], "allow", "FW 2"),                 # disabled skipped
    ([dict(DEFAULT_FW, action="BLOCK_DROP"), fw_rule(2, 5, "ALLOW", destAddresses=["198.51.100.0/24"])], "block", DEFAULT_FW["name"]),
    ([dict(DEFAULT_FW, action="BLOCK_DROP"), fw_rule(2, 5, "ALLOW")], "allow", "FW 2"),                         # default rule last
])
def test_the_firewall_decides_by_first_match_in_order_with_the_default_rule_last(rules, verdict, rule):
    """ASVS V4.1.3 · CWE-863: rules in order, the first match decides, disabled rules never do, the default rule is last."""
    m = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": rules}, protocol="tcp", port=22), "firewall")
    assert (m["verdict"], m["certainty"], m["rule"]["name"]) == (verdict, "definite", rule)


SERVICES = [{"id": 1, "name": "HTTPS", "tag": "HTTPS", "destTcpPorts": [{"start": 443}]},
            {"id": 2, "name": "UDP_ANY", "tag": "UDP_ANY"}, {"id": 3, "name": "ICMP_ANY", "tag": "ICMP_ANY"},
            {"id": 4, "name": "TCP_ANY", "tag": "TCP_ANY"}, {"id": 5, "name": "High", "destTcpPorts": [{"start": 60000, "end": 65535}]},
            {"id": 6, "name": "ANY", "tag": "ANY"}]


@pytest.mark.parametrize("crit,proto,port,state", [
    ({"nwServices": [{"id": 1}]}, "tcp", 443, "match"),
    ({"nwServices": [{"id": 1}]}, "udp", 443, "no_match"),        # QUIC is not TCP/443
    ({"nwServices": [{"id": 2}]}, "tcp", 22, "no_match"),         # UDP_ANY never carries TCP
    ({"nwServices": [{"id": 3}]}, "tcp", 22, "no_match"),         # ICMP_ANY never carries TCP
    ({"nwServices": [{"id": 3}]}, "udp", 53, "no_match"),
    ({"nwServices": [{"id": 2}]}, "udp", 443, "match"),
    ({"nwServices": [{"id": 4}]}, "tcp", 1, "match"),
    ({"nwServices": [{"id": 5}]}, "tcp", 65535, "match"),         # range end inclusive
    ({"nwServices": [{"id": 5}]}, "tcp", 59999, "no_match"),
    ({"nwServices": [{"id": 6, "name": "ANY"}]}, "udp", 9999, "match"),   # "any" service
    ({"destAddresses": ["198.51.100.0/24"]}, "tcp", 22, "no_match"),
    ({"destAddresses": ["203.0.113.0/24"]}, "tcp", 22, "match"),
    ({"destIpv6Groups": [{"id": 6, "name": "v6 net"}]}, "tcp", 22, "no_match"),   # an IPv4 address is never in an IPv6 group
    ({"destIpCategories": ["GAMBLING"]}, "tcp", 22, "no_match"),
    ({"destCountries": ["COUNTRY_FR"]}, "tcp", 22, "unknown"),     # this tool does not geolocate
    ({"users": [{"id": 1, "name": "bob"}]}, "tcp", 22, "unknown"),
    ({"groups": [{"id": 1, "name": "Finance"}]}, "tcp", 22, "unknown"),
    ({"departments": [{"id": 1, "name": "Sales"}]}, "tcp", 22, "unknown"),
    ({"locations": [{"id": 1, "name": "HQ"}]}, "tcp", 22, "unknown"),
    ({"timeWindows": [{"id": 1, "name": "Night"}]}, "tcp", 22, "unknown"),
    ({"deviceTrustLevels": ["LOW_TRUST"]}, "tcp", 22, "unknown"),
    ({"srcIps": ["10.0.0.0/8"]}, "tcp", 22, "unknown"),           # source not given
    ({"srcIpv6Groups": [{"id": 7, "name": "v6 src"}]}, "tcp", 22, "unknown"),
])
def test_every_firewall_criterion_kind_is_match_no_match_or_unknown(crit, proto, port, state):
    """ASVS V4.1.3 · CWE-697: each firewall criterion kind is evaluated, or unknown when this tool cannot know it; never guessed."""
    rules = [fw_rule(1, 1, "BLOCK_DROP", **crit), DEFAULT_FW]
    m = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": rules, "/zia/networkServices": SERVICES,
                                "/zia/ipDestinationGroups": [{"id": 6, "name": "v6 net", "addresses": []}]}, protocol=proto, port=port), "firewall")
    states = {"match": m["rule"]["name"] == "FW 1" and m["certainty"] == "definite",
              "no_match": m["rule"]["name"] == DEFAULT_FW["name"] and m["certainty"] == "definite",
              "unknown": m["certainty"] == "conditional"}
    assert states[state], (m["verdict"], m["certainty"], m["rule"], m["could_override"])


def test_a_source_address_given_decides_the_source_criterion():
    """ASVS V4.1.3 · CWE-697: with the device's address given, a source IP condition matches or does not, at its boundary."""
    rules = [fw_rule(1, 1, "BLOCK_DROP", srcIps=["10.0.0.0/24"]), DEFAULT_FW]
    inside = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": rules}, protocol="tcp", port=22, context={"source_ip": "10.0.0.255"}), "firewall")
    outside = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": rules}, protocol="tcp", port=22, context={"source_ip": "10.0.1.0"}), "firewall")
    assert (inside["verdict"], inside["certainty"]) == ("block", "definite") and (outside["verdict"], outside["certainty"]) == ("allow", "definite")


def test_a_firewall_rule_on_ipv6_groups_does_not_block_ipv4_and_is_unknown_for_ipv6():
    """ASVS V4.1.3 · CWE-863: a rule naming only IPv6 destination groups is never a catch-all."""
    rules = [fw_rule(1, 1, "BLOCK_DROP", destIpv6Groups=[{"id": 6, "name": "v6 net"}]), DEFAULT_FW]
    v4 = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": rules}, protocol="tcp", port=22), "firewall")
    v6 = mod(run("2001:db8::5", {"/zia/firewallFilteringRules": rules}, protocol="tcp", port=22), "firewall")
    assert (v4["verdict"], v4["certainty"]) == ("allow", "definite")
    assert (v6["verdict"], v6["certainty"]) == ("allow", "conditional") and v6["could_override"][0]["name"] == "FW 1"


# ── URL filtering in the trace ─────────────────────────────────────────
@pytest.mark.parametrize("dest,rules,outcome,by", [
    ("casino.example", [url_rule(1, 2, "BLOCK", ["GAMBLING"]), url_rule(2, 1, "ALLOW", ["GAMBLING"])], "enforce", None),   # first in order
    ("casino.example", [url_rule(1, 1, "BLOCK", ["GAMBLING"], state="DISABLED")], "enforce", None),
    ("casino.example", [url_rule(1, 1, "BLOCK", ["ANY"])], "blocked", "URL 1"),
    ("casino.example", [url_rule(1, 1, "BLOCK", ["NEWS_AND_MEDIA"])], "enforce", None),
    ("casino.example", [url_rule(1, 1, "BLOCK", ["GAMBLING"], protocols=["HTTP_RULE"])], "enforce", None),      # HTTP-only rule, HTTPS traffic
    ("http://casino.example/", [url_rule(1, 1, "BLOCK", ["GAMBLING"], protocols=["HTTP_RULE"])], "blocked", "URL 1"),
    ("casino.example", [url_rule(1, 1, "BLOCK", ["GAMBLING"], protocols=["HTTPS_RULE"])], "blocked", "URL 1"),
    ("casino.example", [url_rule(1, 1, "BLOCK", ["GAMBLING"], protocols=["ANY_RULE"])], "blocked", "URL 1"),
])
def test_url_filtering_first_match_disabled_any_and_protocols(dest, rules, outcome, by):
    """ASVS V4.1.3 · CWE-863: URL filtering takes the first enabled rule in order whose categories and protocols match."""
    v = run(dest, {"/zia/urlFilteringRules": rules})["verdict"]
    assert (v["outcome"], v["blocked_by"]) == (outcome, by)


@pytest.mark.parametrize("extra,depends", [
    ({"timeWindows": [{"id": 1, "name": "Night"}]}, "time window Night"),
    ({"deviceTrustLevels": ["LOW_TRUST"]}, "device trust level LOW_TRUST"),
    ({"userRiskScoreLevels": ["HIGH"]}, "user risk score level HIGH"),
    ({"groups": [{"id": 7, "name": "Finance"}]}, "group Finance"),
    ({"locations": [{"id": 8, "name": "HQ"}]}, "location HQ"),
    ({"enforceTimeValidity": True, "validityStartTime": 1700000000, "validityEndTime": 1800000000}, "validity period from 2023-11-14 22:13"),
])
def test_a_rule_that_applies_only_sometimes_is_conditional_and_says_on_what(extra, depends):
    """ASVS V4.1.3 · CWE-863: a block limited to a time, device, risk score, group, location or validity period is conditional, named."""
    v = run("casino.example", {"/zia/urlFilteringRules": [url_rule(1, 1, "BLOCK", ["GAMBLING"], **extra)]})["verdict"]
    assert v["outcome"] != "blocked" and v["certainty"] == "conditional"
    assert any("URL filtering" in r and "'URL 1' (BLOCK)" in r and depends in r for r in v["certainty_reasons"]), v["certainty_reasons"]


def test_a_scoped_rule_with_the_same_action_as_the_deciding_one_changes_nothing():
    """ASVS V4.1.3 · CWE-670: a scoped rule ahead of the deciding rule makes it conditional only when it acts differently."""
    same = run("casino.example", {"/zia/urlFilteringRules": [url_rule(1, 1, "BLOCK", ["GAMBLING"], groups=[{"id": 7, "name": "Finance"}]),
                                                            url_rule(2, 2, "BLOCK", ["GAMBLING"])]})["verdict"]
    other = run("casino.example", {"/zia/urlFilteringRules": [url_rule(1, 1, "ALLOW", ["GAMBLING"], groups=[{"id": 7, "name": "Finance"}]),
                                                             url_rule(2, 2, "BLOCK", ["GAMBLING"])]})["verdict"]
    assert (same["outcome"], same["blocked_by"], same["certainty"]) == ("blocked", "URL 2", "definite")
    assert other["outcome"] != "blocked" and other["certainty"] == "conditional"


# ── SSL inspection ──────────────────────────────────────────────────────
@pytest.mark.parametrize("ssl,dest,outcome,certainty", [
    ([], "news.example", "blind", "definite"),                                                            # no rule: encrypted
    ([DECRYPT_ALL], "news.example", "enforce", "definite"),
    ([{"id": 1, "name": "Exempt mail", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["WEB_MAIL"]}, DECRYPT_ALL],
     "mail.example", "blind", "definite"),
    ([{"id": 1, "name": "Exempt mail", "order": 1, "state": "DISABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["WEB_MAIL"]}, DECRYPT_ALL],
     "mail.example", "enforce", "definite"),
    ([{"id": 1, "name": "Block TLS", "order": 1, "state": "ENABLED", "action": {"type": "BLOCK"}, "urlCategories": ["GAMBLING"]}, DECRYPT_ALL],
     "casino.example", "blocked", "definite"),
    ([dict(DECRYPT_ALL, id=2, name="Decrypt Finance", order=1, groups=[{"id": 7, "name": "Finance"}]), DECRYPT_ALL],
     "news.example", "enforce", "definite"),                                                              # same action, scoped: no effect
    ([{"id": 2, "name": "Exempt Finance", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["ANY"],
       "groups": [{"id": 7, "name": "Finance"}]}, DECRYPT_ALL], "news.example", "conditional", "conditional"),
    ([], "http://news.example/", "enforce", "definite"),                                                  # plain HTTP: nothing to decrypt
    ([{"id": 1, "name": "No decrypt", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["ANY"]}],
     "http://news.example/", "enforce", "definite"),
])
def test_ssl_inspection_decides_what_dlp_can_see(ssl, dest, outcome, certainty):
    """ASVS V4.1.3 · CWE-863: first matching SSL rule; a scoped exemption is conditional; plain HTTP is visible without decryption."""
    v = run(dest, {"/zia/sslInspectionRules": ssl})["verdict"]
    assert (v["outcome"], v["certainty"]) == (outcome, certainty), v["headline"]


def test_plain_http_is_never_called_encrypted_or_decrypted():
    """ASVS V4.1.3 · CWE-684: TCP/80 is not reported as 'encrypted, DLP blind'; its SSL hop is not applicable."""
    res = run("http://news.example/form", {"/zia/sslInspectionRules": []})
    assert hop(res, "ssl")["status"] == "na" and res["trace"]["decrypted"] is True
    assert "unencrypted (plain HTTP)" in res["verdict"]["headline"] and "encrypted:" not in res["verdict"]["headline"]
    assert run("news.example", protocol="tcp", port=80)["verdict"]["outcome"] == "enforce"


# ── Web DLP: exclusions and what-if ─────────────────────────────────────
EXCLUDING = [dict(DLP_BLOCK, name="Block except Execs", excludedGroups=[{"id": 9, "name": "Execs"}])]


@pytest.mark.parametrize("identity,outcome", [(None, "conditional"), ({"groups": ["Execs"]}, "none"), ({"groups": ["Sales"]}, "enforce"),
                                              ({"user": "bob"}, "conditional")])
def test_a_dlp_rule_with_excluded_groups_does_not_apply_to_them(identity, outcome):
    """ASVS V4.1.3 · CWE-863: Web DLP's excluded users, groups and departments are a negated scope (SDK dlp_web_rules)."""
    v = run("news.example", {"/zia/webDlpRules": EXCLUDING}, identity=identity)["verdict"]
    assert v["outcome"] == outcome


@pytest.mark.parametrize("scope_fields,ident,applies", [
    ({"groups": [{"id": 1, "name": "Finance"}], "departments": [{"id": 2, "name": "Sales"}]}, {"groups": ["Finance"]}, True),   # any of who
    ({"groups": [{"id": 1, "name": "Finance"}], "locations": [{"id": 3, "name": "HQ"}]}, {"groups": ["Finance"]}, None),       # where not given
    ({"groups": [{"id": 1, "name": "Finance"}], "locations": [{"id": 3, "name": "HQ"}]}, {"groups": ["Finance"], "location": "HQ"}, True),
    ({"groups": [{"id": 1, "name": "Finance"}]}, {"groups": ["Sales"]}, False),
    ({"users": [{"id": 1, "name": "Bob (bob@x.example)"}]}, {"user": "bob@x.example"}, True),
    ({"groups": [{"id": 1, "name": "Finance"}], "timeWindows": [{"id": 4, "name": "Night"}]}, {"groups": ["Finance"]}, None),
    ({"groups": [{"id": 1, "name": "Finance"}], "userRiskScoreLevels": ["HIGH"]}, {"groups": ["Finance"]}, None),
    ({"excludedGroups": [{"id": 9, "name": "Execs"}]}, {"groups": ["Execs"]}, False),
    ({"excludedGroups": [{"id": 9, "name": "Execs"}]}, {"groups": ["Sales"]}, True),
    ({"excludedUsers": [{"id": 9, "name": "bob"}]}, {"groups": ["Sales"]}, None),
])
def test_what_if_scope_semantics(scope_fields, ident, applies):
    """ASVS V4.1.3 · CWE-863: who (users, groups, departments) is any-of, where any-of, kinds AND-ed; exclusions negate (assumed per help text)."""
    rule = {"scope": sf._scope(scope_fields), "scope_items": pw.scope_items(scope_fields)}
    assert pw.rule_criteria(rule, pw.normalize_identity(ident))[0] is applies


# ── PAC helpers against the PAC specification ───────────────────────────
def _pac(cond, url="https://www.example.com/", host=None, **kw):
    src = "function FindProxyForURL(url, host) { if (" + cond + ") return \"DIRECT\"; return \"PROXY gateway.zscaler.net:80\"; }"
    return pac_eval.evaluate(src, url, host, **kw)


@pytest.mark.parametrize("cond,url,host,kind", [
    ('dnsDomainIs(host, ".example.com")', "https://www.example.com/", "www.example.com", "direct"),
    ('dnsDomainIs(host, ".example.com")', "https://www/", "www", "zscaler"),
    ('shExpMatch(host, "*.example.com")', "https://a.b.example.com/", "a.b.example.com", "direct"),
    ('shExpMatch(host, "a?.com")', "https://ab.com/", "ab.com", "direct"),
    ('shExpMatch(host, "a.com")', "https://abcom/", "abcom", "zscaler"),                  # "." is literal
    ('shExpMatch(host, "*.EXAMPLE.com")', "https://a.example.com/", "a.example.com", "zscaler"),   # case-sensitive
    ('isInNet(host, "10.0.0.0", "255.255.255.0")', "https://10.0.0.255/", "10.0.0.255", "direct"),
    ('isInNet(host, "10.0.0.0", "255.255.255.0")', "https://10.0.1.0/", "10.0.1.0", "zscaler"),
    ('localHostOrDomainIs(host, "www.example.com")', "https://www.example.com/", "www.example.com", "direct"),
    ('localHostOrDomainIs(host, "www.example.com")', "https://www/", "www", "direct"),
    ('localHostOrDomainIs(host, "www.example.com")', "https://home.example.com/", "home.example.com", "zscaler"),
    ('isPlainHostName(host)', "https://intranet/", "intranet", "direct"),
    ('isPlainHostName(host)', "https://intranet.corp/", "intranet.corp", "zscaler"),
    ('dnsDomainLevels(host) > 1', "https://a.b.example/", "a.b.example", "direct"),
    ('dnsDomainLevels(host) > 1', "https://b.example/", "b.example", "zscaler"),
    ('weekdayRange("MON", "FRI")', "https://a.com/", "a.com", "mixed"),                 # time: both answers, never guessed
    ('timeRange(9, 17)', "https://a.com/", "a.com", "mixed"),
    ('dateRange("JAN", "MAR")', "https://a.com/", "a.com", "mixed"),
    ('isInNet(myIpAddress(), "10.0.0.0", "255.0.0.0")', "https://a.com/", "a.com", "mixed"),
    ('isResolvable(host)', "https://a.com/", "a.com", "mixed"),                          # no DNS lookup is made
])
def test_pac_helpers_follow_the_pac_specification(cond, url, host, kind):
    """ASVS V5.2.4 · CWE-697: each PAC helper is interpreted as the PAC spec defines it; time, DNS and the device address stay unknown."""
    assert _pac(cond, url, host)["kind"] == kind


def test_an_https_url_reaches_the_pac_file_without_its_path():
    """ASVS V5.2.4 · CWE-697: browsers strip https:// URLs to scheme, host and port before FindProxyForURL (assumed browser behaviour)."""
    pac = [{"id": 1, "name": "p.pac", "pacUrl": "https://pac.example/p.pac", "pacContent":
            'function FindProxyForURL(url, host) { if (shExpMatch(url, "*secret*")) return "DIRECT"; '
            'if (shExpMatch(url, "http:*")) return "DIRECT"; return "PROXY ${GATEWAY}:80"; }'}]
    routes = {"/zcc/forwardingProfiles": PAC_FWD, "/zia/pacFiles": pac}
    assert hop(run("https://news.example/secret/x", routes), "pac")["status"] == "pass"
    assert hop(run("http://news.example/a", routes), "pac")["status"] == "bypass"
    assert pa.pac_url(pa.parse_destination("https://[2001:db8::1]:8443/x?y"), zpm.traffic_context(pa.parse_destination("https://[2001:db8::1]:8443/x"))) \
        == "https://[2001:db8::1]:8443/"


# ── ZPA: segments, bypass, client forwarding, access ────────────────────
@pytest.mark.parametrize("segments,dest,port,segment", [
    ([_seg("a", "Wild", ["*.corp.example"], [(443, 443)], "g1", ["sg1"]), _seg("b", "Deeper", ["*.eu.corp.example"], [(443, 443)], "g1", ["sg1"])],
     "git.eu.corp.example", None, "Deeper"),                                                     # longest wildcard suffix
    ([_seg("a", "Wild", ["*.corp.example"], [(1, 65535)], "g1", ["sg1"]), _seg("b", "Narrow ports", ["*.corp.example"], [(443, 443)], "g1", ["sg1"])],
     "git.corp.example", None, "Narrow ports"),                                                  # tie: narrowest port range (assumed)
    ([_seg("a", "Wild", ["*.corp.example"], [(443, 443)], "g1", ["sg1"])], "corp.example", None, None),   # wildcard does not cover the apex
    ([_seg("a", "Off", ["git.corp.example"], [(443, 443)], "g1", ["sg1"], enabled=False)], "git.corp.example", None, None),
    ([_seg("a", "Top port", ["git.corp.example"], [(65535, 65535)], "g1", ["sg1"])], "git.corp.example", "65535", "Top port"),
    ([_seg("a", "V6", ["2001:db8::/48"], [(443, 443)], "g1", ["sg1"])], "2001:db8::7", "443", "V6"),
    ([_seg("a", "V6", ["2001:db8::/48"], [(443, 443)], "g1", ["sg1"])], "2001:db9::7", "443", None),
    ([_seg("a", "IDN", ["xn--mnchen-3ya.example"], [(443, 443)], "g1", ["sg1"])], "münchen.example", None, "IDN"),
])
def test_zpa_picks_the_most_specific_enabled_segment(segments, dest, port, segment):
    """ASVS V4.1.3 · CWE-863: exact FQDN, then the longest wildcard, then the longest prefix; disabled segments and port misses never match."""
    st = zpa_stage(dest, port=port, segments=segments, access=[_rule("r1", 1, "Allow", "ALLOW", _cond(_op("APP_GROUP", "id", "g1")))])
    assert (st["segment"] or {}).get("name") == segment


@pytest.mark.parametrize("bypass,network,forwarding,carries", [
    ("ALWAYS", "off", None, False), ("ON_NET", "on", None, False), ("ON_NET", "off", None, True), ("NEVER", "on", None, True),
    ("NEVER", "off", "BYPASS", False), ("NEVER", "off", "INTERCEPT", True), ("NEVER", "off", "INTERCEPT_ACCESSIBLE", True),
])
def test_zpa_bypass_modes_and_client_forwarding(bypass, network, forwarding, carries):
    """ASVS V4.1.3 · CWE-863: bypass Always / On-Net / Never per network, then the client forwarding action (SDK values)."""
    segs = [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"], bypassType=bypass)]
    fwd = [_rule("f1", 1, "Fwd", forwarding, _cond(APP("s1")))] if forwarding else None
    st = zpa_stage("git.corp.example", network=network, segments=segs, forwarding=fwd,
                   access=[_rule("r1", 1, "Allow", "ALLOW", _cond(APP("s1")))])
    assert st["carries"] is carries


@pytest.mark.parametrize("access,outcome", [
    ([], "zpa_denied"),                                                                          # default deny
    ([_rule("r1", 1, "Allow", "ALLOW", _cond(APP("s1")), disabled=True)], "zpa_denied"),         # a disabled rule never decides
    ([_rule("r1", 2, "Allow", "ALLOW", _cond(APP("s1"))), _rule("r0", 1, "Deny", "DENY", _cond(APP("s1")))], "zpa_denied"),   # rule order
    ([_rule("r1", 1, "Allow on posture", "ALLOW", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true")))], "zpa_conditional"),
    ([_rule("r1", 1, "Allow not posture", "ALLOW", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true"), negated=True))], "zpa_conditional"),
    ([_rule("r1", 1, "Allow SCIM", "ALLOW", _cond(APP("s1")), _cond(_op("SCIM_GROUP", "idp1", "42")))], "zpa_conditional"),   # identity not given
])
def test_zpa_access_policy_first_match_default_deny_posture_both_ways(access, outcome):
    """ASVS V4.1.3 · CWE-863: first enabled access rule in order, deny by default, posture answered passing and failing."""
    segs = [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"])]
    assert zpa_stage("git.corp.example", segments=segs, access=access)["outcome"] == outcome


def test_zpa_posture_pass_and_fail_give_opposite_answers_for_a_posture_rule():
    """ASVS V4.1.3 · CWE-863: a posture rule allows when posture passes and falls to default deny when it fails."""
    segs = [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"])]
    st = zpa_stage("git.corp.example", segments=segs, access=[_rule("r1", 1, "Allow on posture", "ALLOW", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true")))])
    assert (st["scenarios"]["pass"]["access"], st["scenarios"]["fail"]["access"]) == ("allow", "deny")


@pytest.mark.parametrize("network,segment_kw,access,named", [
    ("off", {}, [_rule("r1", 1, "Allow SCIM", "ALLOW", _cond(APP("s1")), _cond(_op("SCIM_GROUP", "idp1", "42")))], "rule “Allow SCIM” (ALLOW), which needs SCIM groups"),
    ("vpn", {"bypassType": "ON_NET"}, None, "whether the VPN counts as a trusted network"),
])
def test_a_conditional_zpa_answer_names_what_it_depends_on(network, segment_kw, access, named):
    """ASVS V1.4.4 · CWE-684: 'depends on' names the rule and the fact it needs, or the VPN question, never just 'facts not given'."""
    segs = [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"], **segment_kw)]
    st = zpa_stage("git.corp.example", network=network, segments=segs, **({"access": access} if access is not None else {}))
    assert st["outcome"] == "zpa_conditional" and named in st["headline"] and "facts not given" not in st["headline"]


# ── ZPA diagnostics (one user, one destination) ────────────────────────
SCIM42 = _cond(_op("SCIM_GROUP", "idp1", "42"))


@pytest.mark.parametrize("access,user,outcome,unless", [
    ([], None, "denied", False),                                                                       # default deny
    ([_rule("r0", 1, "Deny SCIM", "DENY", _cond(APP("s1")), SCIM42)], None, "denied", False),           # every answer is deny
    ([_rule("r0", 1, "Allow SCIM", "ALLOW", _cond(APP("s1")), SCIM42)], None, "conditional", False),
    ([_rule("r0", 1, "Allow SCIM", "ALLOW", _cond(APP("s1")), SCIM42), _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], None, "allowed", False),
    ([_rule("r0", 1, "Deny SCIM", "DENY", _cond(APP("s1")), SCIM42), _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], None, "allowed", True),
    ([_rule("r0", 1, "Deny SCIM", "DENY", _cond(APP("s1")), SCIM42), _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], {"scim_groups": ["42"]}, "denied", False),
    ([_rule("r0", 1, "Deny SCIM", "DENY", _cond(APP("s1")), SCIM42), _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], {"scim_groups": ["7"]}, "allowed", False),
    ([_rule("r0", 1, "Deny off", "DENY", _cond(APP("s1")), disabled=True), _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], None, "allowed", False),
    ([_rule("r0", 1, "Deny not EDR", "DENY", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true"), negated=True)),
      _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], {"posture_pass": ["udid-1"]}, "allowed", False),
    ([_rule("r0", 1, "Deny not EDR", "DENY", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true"), negated=True)),
      _rule("r1", 2, "Allow all", "ALLOW", _cond(APP("s1")))], {"posture_pass": []}, "denied", False),
])
def test_zpa_diagnostics_depends_on_the_user_only_when_the_answer_would_differ(access, user, outcome, unless):
    """ASVS V4.1.3 · CWE-684: an earlier rule that needs a fact not given makes the answer conditional only when it would allow where the rest deny (or the reverse)."""
    snap, _ = zp.read(__import__("test_zpa_analysis").FakeTenant(zpa_data(segments=[_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"])],
                                                                             access=access)), pace=0)
    v = za.diagnose(snap, user, "git.corp.example")["verdict"]
    assert v["outcome"] == outcome and ("unless" in v["headline"]) is unless, v["headline"]


# ── Cloud and Branch Connector forwarding (workloads) ───────────────────
@pytest.mark.parametrize("rules,ip,dest,go", [
    ([("Range", "DIRECT", {"srcIps": ["10.8.0.1-10.8.0.9"]})], "10.8.0.9", "example.com", "direct"),        # range end inclusive
    ([("Range", "DIRECT", {"srcIps": ["10.8.0.1-10.8.0.9"]})], "10.8.0.10", "example.com", "zia"),
    ([("Net", "DROP", {"destAddresses": ["198.51.100.0/31"]})], "10.0.0.1", "198.51.100.1", "drop"),         # CIDR boundary
    ([("Net", "DROP", {"destAddresses": ["198.51.100.0/31"]})], "10.0.0.1", "198.51.100.2", "zia"),
    ([("V6", "DROP", {"destAddresses": ["2001:db8::/64"]})], "10.0.0.1", "2001:db8::ffff", "drop"),
    ([("Name", "DIRECT", {"destAddresses": [".example.com"]})], "10.0.0.1", "EXAMPLE.com.", "direct"),
    ([("Same", "ZIA", {"destCountries": ["COUNTRY_CA"]})], "10.0.0.1", "example.com", "zia"),              # unknown, but same end either way
    ([("Off", "DROP", {"state": "DISABLED"})], "10.0.0.1", "example.com", "zia"),                            # disabled never decides
])
def test_connector_forwarding_first_match_boundaries_and_defaults(rules, ip, dest, go):
    """ASVS V4.1.3 · CWE-863: connector forwarding rules decide in order; ranges and CIDR boundaries are exact; no match goes to ZIA."""
    import workload_path as wp
    from test_path_zpa_workloads import fwd, wl, ztw_data, ztw_snap
    data = ztw_data([fwd(i + 1, i + 1, n, m, **kw) for i, (n, m, kw) in enumerate(rules)] + [fwd(99, -1, "Default", "ZIA")])
    d = zp.destination(dest, "443")
    assert wp.evaluate(ztw_snap(data), wl(ip=ip), d)["go"] == go


# ═══ 2. Properties (deterministic seed) ═════════════════════════════════
CATS = ["GAMBLING", "WEB_MAIL", "FILE_HOST", "AI_ML_APPS", "NEWS_AND_MEDIA", "CUSTOM_01", "ANY"]
HOSTS = ["casino.example", "mail.example", "files.example", "chat.example", "news.example", "partner.example", "x.partner.example",
         "plain.example", "203.0.113.9", "198.51.100.1", "2001:db8::5"]
SCOPES = [{}, {"groups": [{"id": 7, "name": "Finance"}]}, {"timeWindows": [{"id": 1, "name": "Night"}]}, {"deviceTrustLevels": ["LOW_TRUST"]},
          {"userRiskScoreLevels": ["HIGH"]}, {"departments": [{"id": 3, "name": "Sales"}]}]
TRAFFIC = [(None, None), ("tcp", 443), ("tcp", 80), ("udp", 443), ("tcp", 22), ("udp", 53), ("tcp", 65535), ("tcp", 8443), ("tcp", 1)]
PAC_FILE = [{"id": 1, "name": "p.pac", "pacUrl": "https://pac.example/p.pac", "pacContent":
             'function FindProxyForURL(url, host) { if (shExpMatch(url, "http:*")) return "DIRECT"; '
             'if (dnsDomainIs(host, ".partner.example")) return "DIRECT"; return "PROXY ${GATEWAY}:80"; }'}]


def random_tenant(rng, scoped=True):
    """A random tenant over URL filtering, SSL, Web DLP, Cloud Firewall, a
    custom category and (sometimes) a PAC file."""
    pick = (lambda: rng.choice(SCOPES)) if scoped else (lambda: {})
    r = {"/zia/urlCategories": [{"id": "CUSTOM_01", "configuredName": "Partner", "customCategory": True,
                                 "urls": [rng.choice(["partner.example", ".partner.example", "Partner.Example.", "*.partner.example"])],
                                 "dbCategorizedUrls": []}]}
    r["/zia/urlFilteringRules"] = [dict(url_rule(100 + i, i + 1, rng.choice(["ALLOW", "BLOCK", "CAUTION", "ISOLATE"]), rng.sample(CATS, rng.randint(1, 2)),
                                                 state=rng.choice(["ENABLED", "ENABLED", "DISABLED"]),
                                                 protocols=rng.choice([[], ["ANY_RULE"], ["HTTPS_RULE"], ["HTTP_RULE"]])), **pick())
                                   for i in range(rng.randint(0, 6))]
    r["/zia/sslInspectionRules"] = [dict({"id": 200 + i, "name": f"SSL {i}", "order": i + 1, "state": rng.choice(["ENABLED", "ENABLED", "DISABLED"]),
                                          "action": {"type": rng.choice(["DECRYPT", "DO_NOT_DECRYPT", "BLOCK"])},
                                          "urlCategories": rng.choice([["ANY"], rng.sample(CATS[:-1], 1)])}, **pick())
                                    for i in range(rng.randint(0, 4))]
    r["/zia/webDlpRules"] = [dict({"id": 300 + i, "name": f"DLP {i}", "order": i + 1, "state": rng.choice(["ENABLED", "DISABLED"]),
                                   "action": rng.choice(["BLOCK", "ALLOW"]), "dlpEngines": [{"name": "PCI"}],
                                   "urlCategories": rng.choice([[], rng.sample(CATS[:-1], 1)])},
                                  **(rng.choice([{}, {"excludedGroups": [{"id": 9, "name": "Execs"}]}, {"groups": [{"id": 7, "name": "Finance"}]}]) if scoped else {}))
                             for i in range(rng.randint(0, 3))]
    r["/zia/networkServices"] = SERVICES
    r["/zia/ipDestinationGroups"] = [{"id": 5, "name": "Docs net", "type": "DSTN_IP", "addresses": ["203.0.113.0/24"]}]
    crits = [{"nwServices": [{"id": rng.choice([1, 2, 3, 4, 5])}]}, {"destIpGroups": [{"id": 5, "name": "Docs net"}]},
             {"destAddresses": ["198.51.100.0/24"]}, {"destIpv6Groups": [{"id": 6, "name": "v6"}]}, {}]
    r["/zia/firewallFilteringRules"] = [dict(fw_rule(400 + i, i + 1, rng.choice(["ALLOW", "BLOCK_DROP"]), state=rng.choice(["ENABLED", "ENABLED", "DISABLED"])),
                                             **rng.choice(crits), **pick()) for i in range(rng.randint(0, 5))] + \
        [dict(DEFAULT_FW, action=rng.choice(["ALLOW", "BLOCK_DROP"]))]
    if rng.random() < 0.3:
        r["/zcc/forwardingProfiles"] = PAC_FWD
        r["/zia/pacFiles"] = PAC_FILE
    return r


def projection(res):
    """Everything a verdict says, without lists whose order is cosmetic."""
    v = res["verdict"]
    return (v["outcome"], v.get("certainty"), v["headline"], v["stops_at"], v["blocked_by"], tuple(v.get("certainty_reasons") or ()),
            tuple((h["key"], h["status"], (h.get("decided_by") or {}).get("name")) for h in res["trace"]["hops"]),
            tuple((m["key"], m["verdict"], m["certainty"], (m.get("rule") or {}).get("name")) for m in res["zia_modules"]["modules"]))


def _cases(n, seed, scoped=True):
    rng = random.Random(seed)
    return [(random_tenant(rng, scoped), rng.choice(HOSTS), rng.choice(TRAFFIC), rng) for _ in range(n)]


@pytest.mark.parametrize("section", ["/zia/urlFilteringRules", "/zia/sslInspectionRules", "/zia/webDlpRules", "/zia/firewallFilteringRules"])
def test_property_an_unrelated_disabled_rule_never_changes_a_verdict(section):
    """ASVS V4.1.3 · CWE-670: inserting a disabled rule anywhere, in any section, never changes the answer."""
    for routes, host, (proto, port), rng in _cases(12, SEED):
        before = projection(run(host, routes, protocol=proto, port=port))
        r2 = copy.deepcopy(routes)
        pos = rng.randint(0, len(r2[section]))
        for x in r2[section]:
            if isinstance(x.get("order"), int) and x["order"] > pos:
                x["order"] += 1
        action = {"/zia/sslInspectionRules": {"type": "DECRYPT"}, "/zia/firewallFilteringRules": "BLOCK_DROP"}.get(section, "BLOCK")
        r2[section].insert(pos, {"id": 9000, "name": "Disabled", "order": pos + 1, "state": "DISABLED", "action": action, "urlCategories": ["ANY"]})
        assert projection(run(host, r2, protocol=proto, port=port)) == before, (host, proto, port, section)


@pytest.mark.parametrize("key,section,make", [
    ("url", "/zia/urlFilteringRules", lambda i, rng: url_rule(i, i, rng.choice(["ALLOW", "BLOCK", "CAUTION"]), rng.sample(CATS, 2))),
    ("ssl", "/zia/sslInspectionRules", lambda i, rng: {"id": i, "name": f"SSL {i}", "order": i, "state": "ENABLED",
                                                        "action": {"type": rng.choice(["DECRYPT", "DO_NOT_DECRYPT", "BLOCK"])}, "urlCategories": rng.sample(CATS, 2)}),
    ("firewall", "/zia/firewallFilteringRules", lambda i, rng: fw_rule(i, i, rng.choice(["ALLOW", "BLOCK_DROP"]),
                                                                       **rng.choice([{}, {"nwServices": [{"id": rng.choice([1, 2, 4, 5])}]},
                                                                                     {"destAddresses": ["198.51.100.0/24"]}]))),
])
def test_property_reordering_rules_below_the_deciding_rule_never_changes_it(key, section, make):
    """ASVS V4.1.3 · CWE-670: first match wins, so shuffling every rule after the deciding one changes nothing."""
    rng = random.Random(SEED + len(key))
    checked = 0
    for _ in range(14):
        rules = [make(i, rng) for i in range(1, 9)] + ([DEFAULT_FW] if key == "firewall" else [])
        host = rng.choice(HOSTS)
        proto, port = (("tcp", 22) if key == "firewall" else (None, None))
        routes = {section: rules, "/zia/networkServices": SERVICES}
        res = run(host, routes, protocol=proto, port=port)
        dec = (hop(res, key).get("decided_by") or {})
        deciding = next((r for r in rules if str(r["id"]) == str(dec.get("id"))), None)
        if deciding is None or hop(res, key)["status"] in ("conditional", "unknown") or deciding["order"] < 0:
            continue
        below = [r for r in rules if isinstance(r["order"], int) and r["order"] > deciding["order"]]
        orders = [r["order"] for r in below]
        rng.shuffle(orders)
        for r, o in zip(below, orders):
            r["order"] = o
        assert projection(run(host, routes, protocol=proto, port=port))[:5] == projection(res)[:5], (key, host)
        checked += 1
    assert checked >= 4


def test_property_test_a_list_gives_exactly_the_single_destination_answer_for_every_row():
    """ASVS V1.4.4 · CWE-682: every row of Test a list, over random protocols and ports, equals analyzing that destination alone."""
    rng = random.Random(SEED)
    protos = ["", "TCP", "UDP", "ANY", "http", "https"]
    ports = ["", "1", "22", "53", "80", "443", "8080", "8443", "65535", "3389"]
    extra = ["a.casino.example", "deep.x.partner.example", "203.0.113.200", "198.51.100.77", "2001:db8::9", "münchen.example", "UPPER.News.Example."]
    checked = 0
    for _ in range(4):
        routes = random_tenant(rng)
        rows = [(rng.choice(HOSTS + extra), rng.choice(ports), rng.choice(protos)) for _ in range(12)]
        rn = bt.run(Tenant(routes), bt.parse("destination,port,protocol\n" + "\n".join(f"{h},{po},{pr}" for h, po, pr in rows)),
                    scope=FULL, sleep=lambda s: None)
        for i, (h, po, pr) in enumerate(rows):
            row = rn.row(i)
            p = {"TCP": "tcp", "UDP": "udp", "ANY": "tcp", "http": "tcp", "https": "tcp"}.get(pr)
            port = int(po) if po else {"http": 80, "https": 443}.get(pr)
            alone = bt.summarize_analysis(pa.analyze(Tenant(routes), row["target"], scope=FULL, protocol=p, port=port))
            assert (row["result"], row["rule"], row["area"], row["inspection"], row["action"], row["stops_at"], row["blockable_by"]) == \
                (alone["result"], alone["rule"], alone["area"], alone["inspection"], alone["action"], alone["stops_at"], "; ".join(sorted(set(alone["blockable_by"])))), (h, po, pr)
            checked += 1
    assert checked == 4 * 12


def test_property_a_what_if_identity_that_no_rule_is_scoped_to_equals_no_what_if():
    """ASVS V4.1.3 · CWE-670: with no rule scoped to anyone, giving an identity changes nothing."""
    for routes, host, (proto, port), _rng in _cases(12, SEED + 1, scoped=False):
        plain = projection(run(host, routes, protocol=proto, port=port))
        ident = projection(run(host, routes, protocol=proto, port=port, identity={"user": "bob", "groups": ["Finance"], "location": "HQ"}))
        assert ident == plain, (host, proto, port)


def test_property_an_identity_on_a_dimension_no_rule_uses_equals_no_what_if():
    """ASVS V4.1.3 · CWE-670: rules scoped only to groups are untouched by an identity that gives only a location."""
    for routes, host, (proto, port), _rng in _cases(12, SEED + 2):
        for sec in ("/zia/urlFilteringRules", "/zia/sslInspectionRules", "/zia/webDlpRules", "/zia/firewallFilteringRules"):
            for r in routes[sec]:
                for k in ("timeWindows", "deviceTrustLevels", "userRiskScoreLevels", "departments", "excludedGroups"):
                    r.pop(k, None)
        plain = run(host, routes, protocol=proto, port=port)
        ident = run(host, routes, protocol=proto, port=port, identity={"location": "Nowhere"})
        assert projection(ident)[:5] == projection(plain)[:5], (host, proto, port)


@pytest.mark.parametrize("key", [k for k in df.PATH_SECTIONS])
def test_property_a_part_out_of_scope_always_says_not_in_scope_never_no_rule(key):
    """ASVS V1.4.4 · CWE-1287: a section the Scope page leaves out is drawn 'not in scope', never 'no rule' or 'could not read'."""
    scope = copy.deepcopy(FULL)
    scope["read"] = [k for k in scope["read"] if k != key]
    scope["not_in_scope"][key] = f"Not in scope: test {key}."
    routes = {"/zcc/forwardingProfiles": PAC_FWD, "/zia/pacFiles": PAC_FILE}
    res = run("news.example", routes, scope=scope)
    if key in ("endpoint", "saas", "email"):
        assert res["trace"]["channels"][key]["status"] == "out_of_scope"
        return
    if key == "zcc":
        assert hop(res, "zcc")["status"] == "out_of_scope"
        return
    h = hop(res, key)
    assert h["status"] == "out_of_scope" and "Not in scope" in h["detail"] and "No " not in h["detail"][:3]
    if key in {m["key"] for m in res["zia_modules"]["modules"]}:
        assert mod(res, key)["status"] == "out_of_scope"
    if key in ("dlp", "ssl"):
        assert res["verdict"]["outcome"] == "out_of_scope" and "no DLP rule" not in res["verdict"]["headline"]


# ═══ 3. Edges through the whole analyzer ════════════════════════════════
@pytest.mark.parametrize("dest,proto,port,label,web", [
    ("2001:db8::5", None, None, "TCP/443 (HTTPS (web))", True),
    ("münchen.example", None, None, "TCP/443 (HTTPS (web))", True),
    ("https://news.example:65535/", None, None, "TCP/65535", False),
    ("news.example", "udp", 443, "UDP/443 (QUIC (HTTP/3 over UDP))", False),
    ("news.example", "tcp", 1, "TCP/1", False),
    ("http://news.example:8080/", None, None, "TCP/8080 (HTTP on 8080)", True),
])
def test_edges_trace_without_inventing_categories(dest, proto, port, label, web):
    """ASVS V5.1.3 · CWE-20: IPv6, IDN, the highest port, QUIC and port 1 are traced, and an address is never its own category."""
    res = run(dest, protocol=proto, port=port)
    assert res["zia_modules"]["traffic"]["label"] == label and res["zia_modules"]["traffic"]["web"] is web
    assert all(":" not in c and not c.startswith("XN--") for c in res["verdict"]["categories"])


def test_icmp_is_refused_by_the_analyzer_and_marked_not_traced_in_a_list():
    """ASVS V5.1.3 · CWE-20: ICMP is out of the analyzer's model: refused in words alone, 'not traced' in a list, never 'allowed'."""
    with pytest.raises(ValueError, match="TCP or UDP"):
        run("news.example", protocol="icmp")
    rn = bt.run(Tenant(), bt.parse("destination,protocol\nnews.example,icmp"), scope=FULL, sleep=lambda s: None)
    assert rn.row(0)["result"] == "unverified" and rn.row(0)["inspection"] == "not traced"


def test_a_list_shares_a_trace_only_between_rows_the_pac_file_answers_alike():
    """ASVS V1.4.4 · CWE-682: rows on port 80 get the PAC answer for their own http:// URL, not one shared from an https:// probe."""
    pac = [{"id": 1, "name": "p.pac", "pacUrl": "https://pac.example/p.pac",
            "pacContent": 'function FindProxyForURL(url, host) { if (url.substring(0, 5) == "http:" && host.charAt(0) == "a") return "DIRECT"; '
                          'return "PROXY ${GATEWAY}:80"; }'}]
    routes = {"/zcc/forwardingProfiles": PAC_FWD, "/zia/pacFiles": pac}
    rn = bt.run(Tenant(routes), bt.parse("destination,port\nb.example,80\na.example,80\na.example,443"), scope=FULL, sleep=lambda s: None)
    assert [rn.row(i)["result"] for i in range(3)] == ["allowed", "bypassed", "allowed"]


def test_a_list_never_shares_an_ipv4_answer_with_an_ipv6_row():
    """ASVS V1.4.4 · CWE-682: an IPv4 and an IPv6 row are traced apart: an IPv6 group can only ever hold the IPv6 one."""
    routes = {"/zia/firewallFilteringRules": [fw_rule(1, 1, "ALLOW", destIpv6Groups=[{"id": 6, "name": "v6 net"}]), dict(DEFAULT_FW, action="BLOCK_DROP")]}
    rn = bt.run(Tenant(routes), bt.parse("destination,port\n198.51.100.77,22\n2001:db8::9,22"), scope=FULL, sleep=lambda s: None)
    assert [rn.row(i)["result"] for i in range(2)] == ["blocked", "unverified"]


def test_a_list_relates_rows_to_list_entries_written_with_a_trailing_dot():
    """ASVS V1.4.4 · CWE-682: a custom category entry 'partner.example.' still separates partner.example from other rows."""
    routes = {"/zia/urlCategories": [{"id": "CUSTOM_01", "configuredName": "Partner", "customCategory": True, "urls": ["Partner.Example."], "dbCategorizedUrls": []}],
              "/zia/urlFilteringRules": [url_rule(20, 1, "BLOCK", ["CUSTOM_01"])]}
    rn = bt.run(Tenant(routes), bt.parse("other.example\npartner.example"), scope=FULL, sleep=lambda s: None)
    assert [rn.row(i)["result"] for i in range(2)] == ["allowed", "blocked"]


def test_a_list_row_with_protocol_http_is_tcp_80():
    """ASVS V5.1.3 · CWE-20: a protocol cell 'http' means TCP/80 as http:// does, not HTTPS."""
    p = bt.parse("destination,protocol\nnews.example,http\nnews.example,https\nnews.example:8080,http")
    assert [p.entries[i].get("port") for i in range(3)] == [80, 443, 8080]


# ═══ 4. Verdict wording ═════════════════════════════════════════════════
GENERIC = "the decision depends on conditions that are not established"


def test_property_definite_means_nothing_on_the_path_is_conditional_and_every_conditional_names_why():
    """ASVS V1.4.4 · CWE-684: 'definite' has no conditional step; every 'conditional' names the rule or the condition it depends on."""
    rng = random.Random(SEED + 3)
    for _ in range(50):
        routes = random_tenant(rng)
        host, (proto, port) = rng.choice(HOSTS), rng.choice(TRAFFIC)
        ident = rng.choice([None, {"groups": ["Finance"]}, {"groups": ["Execs"]}, {"department": "Sales"}])
        res = run(host, routes, protocol=proto, port=port, identity=ident)
        v = res["verdict"]
        conditional_hops = [h["key"] for h in res["trace"]["hops"] if h["status"] == "conditional" and h["key"] != "incident"]
        if v["certainty"] == "definite":
            assert not conditional_hops and not v["policy_conditional"], (host, proto, port, ident, conditional_hops)
        else:
            assert v["certainty_reasons"], (host, proto, port)
            assert not any(GENERIC in r for r in v["certainty_reasons"]), v["certainty_reasons"]


def test_a_module_after_a_definite_block_does_not_make_the_answer_conditional():
    """ASVS V1.4.4 · CWE-684: once the Cloud Firewall blocks for certain, a later conditional SSL rule is not reached and not a reason."""
    routes = {"/zia/firewallFilteringRules": [dict(DEFAULT_FW, action="BLOCK_DROP")],
              "/zia/sslInspectionRules": [{"id": 2, "name": "Exempt Finance", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"},
                                           "urlCategories": ["ANY"], "groups": [{"id": 7, "name": "Finance"}]}, DECRYPT_ALL]}
    v = run("news.example", routes)["verdict"]
    assert (v["outcome"], v["certainty"], v["certainty_reasons"]) == ("blocked", "definite", [])


def test_non_web_traffic_is_not_policy_conditional_on_web_rules_it_never_meets():
    """ASVS V1.4.4 · CWE-684: a scoped URL rule does not make SSH traffic 'policy conditional'."""
    res = run("news.example", {"/zia/urlFilteringRules": [url_rule(1, 1, "BLOCK", ["ANY"], groups=[{"id": 7, "name": "Finance"}])]}, protocol="tcp", port=22)
    assert res["verdict"]["certainty"] == "definite" and res["verdict"]["policy_conditional"] is False


# ═══ 5. Counts: Data Flow Map, SSL flow, SSL coverage, Test a list ══════
def _flow_tenant(rng):
    r = copy.deepcopy(BASE)
    r.update(random_tenant(rng))
    if rng.random() < 0.5:
        r["/zcc/webPolicies"] = [dict(APP_PROFILES[0], hostnameBypassForIpv4=["*.box.com"])]
    return r


def test_data_flow_map_counts_add_up_and_match_the_page_lists():
    """ASVS V1.4.4 · CWE-682: every traced path is in exactly one visibility class; the tiles sum to the paths traced."""
    rng = random.Random(SEED)
    for _ in range(6):
        rep = df.generate_data_flow_report(Tenant(_flow_tenant(rng)))
        s = rep["summary"]
        parts = s["bypassed"] + s["blind"] + s["enforced"] + s["monitored"] + s["blocked"] + s["unverified"] + s["decrypted_other"]
        assert parts == s["traces"] == len(rep["traces"])
        lost = [t for t in rep["traces"] if df.visibility(t) in ("bypassed", "blind")]
        assert len(lost) == s["bypassed"] + s["blind"]
        assert all(df.visibility(t) in df.VISIBILITY for t in rep["traces"])


def test_ssl_flow_counts_add_up():
    """ASVS V1.4.4 · CWE-682: SSL flow classes sum to the classes; gaps by severity sum to the gaps."""
    rng = random.Random(SEED)
    for _ in range(10):
        routes = random_tenant(rng)
        rep = sf.analyse(routes["/zia/sslInspectionRules"], routes["/zia/webDlpRules"], {}, {})
        s = rep["summary"]
        assert s["inspected"] + s["not_inspected"] + s["blocked"] + s["unknown"] == s["classes"] == len(rep["classes"])
        assert s["high"] + s["medium"] + s["low"] + sum(1 for g in rep["gaps"] if g["severity"] == "info") == s["gaps"]


@pytest.mark.parametrize("rows,ssl,total", [
    ([{"name": "HTTPS", "total": 30}, {"name": "SSL", "total": 70}, {"name": "HTTP", "total": 100}], 30.0, 65.0),
    ([{"name": "HTTPS", "total": 0}, {"name": "SSL", "total": 0}], None, None),
    ([{"name": "HTTPS", "total": "1e400"}, {"name": "SSL", "total": 5}, {"name": "HTTP", "total": float("nan")}], 0.0, 0.0),
    ([{"name": "HTTPS", "total": -5}, {"name": "SSL", "total": 5}, {"name": "TUNNEL", "total": 50}], 0.0, 0.0),
])
def test_ssl_coverage_percentages_stay_between_0_and_100(rows, ssl, total):
    """ASVS V1.4.4 · CWE-682: every share is in 0-100 or not measurable; a non-finite or negative volume is not counted."""
    p = sc.protocol_split(rows)
    assert (p["ssl_pct"], p["total_pct"]) == (ssl, total)
    for k in ("ssl_pct", "http_pct", "total_pct", "total_pct_if_other_not_inspected"):
        assert p[k] is None or (math.isfinite(p[k]) and 0 <= p[k] <= 100)
    json.dumps(p, allow_nan=False)


def test_ssl_coverage_class_counts_add_up():
    """ASVS V1.4.4 · CWE-682: covered plus not-inspected classes equal the classes known; causes by risk sum to the causes."""
    rng = random.Random(SEED)
    for _ in range(10):
        rep = sc.analyse(random_tenant(rng)["/zia/sslInspectionRules"])
        s = rep["summary"]
        assert s["classes_covered"] + s["classes_not_inspected"] == s["classes_total"]
        assert sum(s["by_risk"].values()) == s["causes"] and (s["class_coverage_pct"] is None or 0 <= s["class_coverage_pct"] <= 100)


def test_test_a_list_counts_add_up_to_the_rows():
    """ASVS V1.4.4 · CWE-682: results plus 'not tested' equal the rows; allowed-but-blockable is a part of allowed."""
    rng = random.Random(SEED)
    rows = "\n".join(rng.choice(HOSTS) for _ in range(40))
    rn = bt.run(Tenant(random_tenant(rng)), bt.parse(rows), scope=FULL, sleep=lambda s: None)
    c = rn.summary["counts"]
    assert sum(c[k] for k in bt.RESULTS) + c["not_tested"] == rn.summary["rows"] == 40
    assert c["allowed_but_blockable"] <= c["allowed"]
