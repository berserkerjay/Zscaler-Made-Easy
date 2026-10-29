"""Deep QA of the Path analyzer, Test a list, PAC evaluation, what-if and
the Data Flow Map (cloud wave 6, slug path): path_analyzer,
zia_path_modules, workload_path, data_flow, bulk_test, pac_eval and
path_whatif.

Goes beyond tests/test_qa_func_path.py and tests/test_sbd_untrusted_input.py:
regression tests for the defects this wave fixed (each failed before its
fix), oracle tables for Cloud & Branch Connector forwarding (every forward
method, workload groups by tag), Cloud Firewall network service and
network application groups, every DNS Control action, Sandbox and File
Type Control per file type and protocol, the Data Flow Map's counts for
every network and platform, and the performance and memory bounds.

Zscaler semantics are checked against the installed zscaler-sdk-python
1.11.3 (models and docstrings); where the SDK documents no more, the test
says "assumed". Fake tenants only: nothing is read from or written to a
real tenant. No sleeps, no real clock (pace=0, injected sleep), no network."""
from __future__ import annotations

import copy
import ipaddress
import threading
import time
import tracemalloc

import pytest

import bulk_test as bt
import data_flow as df
import pac_eval
import path_analyzer as pa
import path_whatif as pw
import workload_path as wp
import zia_path_modules as zpm
import zpa_path as zp
from test_path_zpa_workloads import ConnectorTenant, fwd, wl, ztw_data, ztw_snap
from test_qa_func_path import DEFAULT_FW, FULL, Tenant, fw_rule, hop, mod, run, url_rule

FTC_ZIP = "FTCATEGORY_ZIP"
FTC_EXE = "FTCATEGORY_WINDOWS_EXECUTABLES"


def fw(dest, rules, **kw):
    """The Cloud Firewall module for one destination and these rules."""
    routes = dict({"/zia/firewallFilteringRules": rules + [DEFAULT_FW]}, **kw.pop("routes", {}))
    return mod(run(dest, routes, **kw), "firewall")


def dns(dest, rules, **kw):
    routes = dict({"/zia/firewallDnsRules": rules}, **kw.pop("routes", {}))
    return mod(run(dest, routes, **kw), "dns")


def dns_rule(i, order, action, **kw):
    return dict({"id": i, "name": f"DNS {i}", "order": order, "state": "ENABLED", "action": action}, **kw)


def connector(rules, **extra):
    data = ztw_data(rules + [fwd(99, -1, "Default", "ZIA")])
    data.update(extra)
    return ztw_snap(data)


# ═══ 1. Regressions: each failed before its fix ═════════════════════════

# ── C6-PATH-01: an IP range of the other address family ────────────────
def test_an_ipv6_destination_against_an_ipv4_firewall_range_is_no_match_not_a_crash():
    """ASVS V5.1.3 · CWE-704 · CWE-755 · WSTG-INPV-01: an IPv6 destination meets an IPv4 a-b range in a firewall rule: no match, never a TypeError."""
    # Arrange
    rules = [fw_rule(1, 1, "BLOCK_DROP", destAddresses=["10.0.0.1-10.0.0.9"])]
    # Act
    m = fw("2001:db8::5", rules, protocol="tcp", port=22)
    # Assert
    assert (m["verdict"], m["certainty"], m["rule"]["name"]) == ("allow", "definite", DEFAULT_FW["name"])


def test_an_ipv6_source_against_an_ipv4_source_range_is_no_match_not_a_crash():
    """ASVS V5.1.3 · CWE-704 · CWE-755: an IPv6 source address given for an IPv4 source range does not match and does not crash."""
    rules = [fw_rule(1, 1, "BLOCK_DROP", srcIps=["10.0.0.1-10.0.0.9"])]
    m = fw("203.0.113.5", rules, protocol="tcp", port=22, context={"source_ip": "2001:db8::7"})
    assert (m["verdict"], m["certainty"]) == ("allow", "definite")


@pytest.mark.parametrize("entry,host,state", [
    ("10.0.0.1-10.0.0.9", "2001:db8::1", "no_match"),        # other family: never in it
    ("10.0.0.1-2001:db8::9", "10.0.0.5", "no_match"),        # a range whose ends differ in family is no range
    ("2001:db8::1-2001:db8::9", "2001:db8::9", "match"),     # last address inclusive
    ("2001:db8::1-2001:db8::9", "2001:db8::a", "no_match"),
    ("10.0.0.1-10.0.0.9", "10.0.0.1", "match"),              # first address inclusive
])
def test_a_url_list_ip_range_compares_only_addresses_of_its_own_family(entry, host, state):
    """ASVS V5.1.3 · CWE-704 · CWE-1287: an a-b range in a URL list matches only addresses of its own family, ends inclusive."""
    assert zpm.url_hit([entry], {"host": host}, True)[0] == state


@pytest.mark.parametrize("entries,ip,hit", [
    (["10.0.0.1-2001:db8::1"], "10.0.0.5", False),
    (["10.0.0.1-10.0.0.9"], "2001:db8::5", False),
    (["10.0.0.1-10.0.0.9", "2001:db8::/64"], "2001:db8::5", True),
])
def test_a_connector_range_of_mixed_families_is_never_a_crash(entries, ip, hit):
    """ASVS V5.1.3 · CWE-704 · CWE-755: a connector source or destination range whose families differ answers no match, never a TypeError."""
    assert wp._ip_in(ip, entries) is hit


def test_a_list_row_for_an_ipv6_address_meets_an_ipv4_range_and_is_tested():
    """ASVS V5.1.3 · CWE-755 · WSTG-ERRH-01: Test a list with an IPv6 row and a firewall rule on an IPv4 range answers the row, never fails the run."""
    # Arrange
    tenant = Tenant({"/zia/firewallFilteringRules": [fw_rule(1, 1, "BLOCK_DROP", destAddresses=["10.0.0.1-10.0.0.9"]), DEFAULT_FW]})
    parsed = bt.parse("destination,port,protocol\n2001:db8::5,22,tcp\n10.0.0.5,22,tcp\n")
    # Act
    rn = bt.run(tenant, parsed, scope=FULL, lookup=False, sleep=lambda s: None)
    # Assert
    assert [rn.row(i)["result"] for i in range(2)] == ["allowed", "blocked"]


# ── C6-PATH-02: network applications on a port no service names ────────
def test_a_network_application_on_an_unnamed_port_is_unknown_not_no_match():
    """ASVS V4.1.3 · CWE-697 · WSTG-BUSL-01: ZIA identifies SSH on TCP/2222 from the traffic, so a Block-SSH rule is unknown there, never a definite allow."""
    m = fw("203.0.113.5", [fw_rule(1, 1, "BLOCK_DROP", nwApplications=["SSH"])], protocol="tcp", port=2222)
    assert (m["verdict"], m["certainty"]) == ("allow", "conditional")
    assert m["could_override"][0]["criteria"][0]["state"] == "unknown"


def test_a_network_application_on_another_named_service_port_is_no_match():
    """ASVS V4.1.3 · CWE-697: on TCP/443 (HTTPS) a rule for SSH does not match (boundary: the port names the service)."""
    m = fw("203.0.113.5", [fw_rule(1, 1, "BLOCK_DROP", nwApplications=["SSH"])], protocol="tcp", port=443)
    assert (m["verdict"], m["certainty"], m["rule"]["name"]) == ("allow", "definite", DEFAULT_FW["name"])


# ── C6-PATH-03: the DNS rule protocols as the SDK writes them ──────────
@pytest.mark.parametrize("protocols,certainty,decides", [
    (["UDP"], "definite", "DNS 1"),            # the SDK docstring's spelling (cloud_firewall_dns.py)
    (["UDP_RULE"], "definite", "DNS 1"),
    (["ANY_RULE"], "definite", "DNS 1"),
    (["TCP_RULE"], "conditional", "DNS 2"),    # a lookup over TCP or DoH is not known: unknown
    (["DOHTTPS_RULE"], "conditional", "DNS 2"),
    (["DOHTTPS"], "conditional", "DNS 2"),
])
def test_a_dns_rule_protocol_is_read_in_both_the_sdk_and_api_spelling(protocols, certainty, decides):
    """ASVS V4.1.3 · CWE-697 · CWE-1287: a DNS rule for UDP (or UDP_RULE) matches the assumed UDP lookup; TCP and DoH only are unknown."""
    rules = [dns_rule(1, 1, "BLOCK", protocols=protocols), dns_rule(2, -1, "ALLOW", defaultRule=True)]
    m = dns("casino.example", rules)
    assert (m["certainty"], m["rule"]["name"]) == (certainty, decides)


# ── C6-PATH-04: DNS rules on IP destination groups ─────────────────────
def test_a_dns_rule_on_a_destination_group_uses_the_groups_the_firewall_read():
    """ASVS V4.1.3 · CWE-697: a DNS rule naming an FQDN destination group is decided from that group's members, read with the Cloud Firewall."""
    # Arrange
    groups = [{"id": 70, "name": "Blocked names", "type": "DSTN_FQDN", "addresses": [".casino.example"]}]
    rules = [dns_rule(1, 1, "BLOCK", destIpGroups=[{"id": 70, "name": "Blocked names"}]), dns_rule(2, -1, "ALLOW", defaultRule=True)]
    # Act
    hit = dns("www.casino.example", rules, routes={"/zia/ipDestinationGroups": groups})
    miss = dns("news.example", rules, routes={"/zia/ipDestinationGroups": groups})
    # Assert
    assert (hit["verdict"], hit["certainty"], hit["rule"]["name"]) == ("block", "definite", "DNS 1")
    assert (miss["verdict"], miss["certainty"], miss["rule"]["name"]) == ("allow", "definite", "DNS 2")


def test_a_dns_rule_on_a_destination_group_that_was_not_read_stays_unknown():
    """ASVS V4.1.3 · CWE-754: when the IP destination groups could not be read, a DNS rule on one depends on its members, never guessed."""
    class NoGroups(Tenant):
        def get(self, ep, p=None):
            return ({"error": "rate limited"}, 429) if ep == "/zia/ipDestinationGroups" else super().get(ep, p)
    rules = [dns_rule(1, 1, "BLOCK", destIpGroups=[{"id": 70, "name": "Blocked names"}]), dns_rule(2, -1, "ALLOW", defaultRule=True)]
    res = pa.analyze(NoGroups({"/zia/firewallDnsRules": rules}), "www.casino.example", scope=FULL)
    assert mod(res, "dns")["certainty"] == "conditional"


# ── C6-PATH-05: a bare file extension is not a ZIA file category ───────
@pytest.mark.parametrize("given,verdict,content_dependent", [
    (["pdf"], "inspect", True),                     # an extension decides nothing: the rule holds the file if it is one of its types
    (["FTCATEGORY_PDF_DOCUMENT"], "none", False),   # a ZIA file category of another type: a definite no match
    ([FTC_EXE], "inspect", False),                  # its own type: a definite match
])
def test_a_sandbox_file_type_is_compared_only_with_zia_file_categories(given, verdict, content_dependent):
    """ASVS V5.1.3 · CWE-697 · CWE-1287: a Sandbox rule's file types are matched with ZIA file categories; a bare extension is never a definite no match."""
    # Arrange
    rules = [{"id": 1, "name": "Hold exe", "order": 1, "state": "ENABLED", "baRuleAction": "BLOCK", "fileTypes": [FTC_EXE]}]
    # Act
    m = mod(run("files.example", {"/zia/sandboxRules": rules}, context={"file_types": given}), "sandbox")
    # Assert
    assert (m["verdict"], m["certainty"], bool(m.get("content_dependent"))) == (verdict, "definite", content_dependent)


# ── C6-PATH-06: a network service that also needs a source port ────────
def test_a_network_service_with_a_source_port_is_unknown_when_the_destination_port_matches():
    """ASVS V4.1.3 · CWE-697: a service limited to a source port depends on that port, which the trace does not know: unknown, never a definite match."""
    # Arrange
    services = [{"id": 1, "name": "Agent", "destTcpPorts": [{"start": 9000}], "srcTcpPorts": [{"start": 1024, "end": 2048}]}]
    rules = [fw_rule(1, 1, "BLOCK_DROP", nwServices=[{"id": 1, "name": "Agent"}])]
    # Act
    m = fw("203.0.113.5", rules, protocol="tcp", port=9000, routes={"/zia/networkServices": services})
    # Assert
    assert (m["verdict"], m["certainty"]) == ("allow", "conditional")
    assert "source port" in m["could_override"][0]["criteria"][0]["detail"]


# ── C6-PATH-07: File Type Control for uploads and downloads ────────────
@pytest.mark.parametrize("rule_op,op,status", [
    ("UPLOAD_DOWNLOAD", "UPLOAD", "blocked"),    # both directions include an upload (pack_channels validates this value)
    ("UPLOAD_DOWNLOAD", "DOWNLOAD", "blocked"),
    ("UPLOAD", "UPLOAD", "blocked"),
    ("DOWNLOAD", "UPLOAD", "none"),              # another direction never applies
    ("", "UPLOAD", "blocked"),
])
def test_a_file_type_rule_for_both_directions_applies_to_an_upload_and_a_download(rule_op, op, status):
    """ASVS V4.1.3 · CWE-863: a File Type Control rule for UPLOAD_DOWNLOAD applies to an upload and to a download; one for the other direction does not."""
    # Arrange
    ftc = {"id": 60, "name": "Block zip", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK", "operation": rule_op,
           "fileTypes": [FTC_ZIP], "urlCategories": ["ANY"]}
    # Act
    res = run("files.example", {"/zia/fileTypeRules": [ftc]}, context={"operation": op, "file_types": [FTC_ZIP]})
    # Assert
    assert hop(res, "ftc")["status"] == status


# ── C6-PATH-08: destination workload groups are not evaluated ──────────
def test_a_forwarding_rule_on_destination_workload_groups_is_conditional_not_a_match():
    """ASVS V4.1.3 · CWE-697 · CWE-754: a connector rule restricted to destination workload groups (SDK destWorkloadGroups) depends on them: conditional."""
    snap = connector([fwd(1, 1, "East-west direct", "DIRECT", destWorkloadGroups=[{"id": 12, "name": "Dev"}])])
    ev = wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"))
    assert (ev["go"], ev["possible"]) == ("conditional", ["direct", "zia"])
    assert {"name": "Destination workload group (not evaluated)", "state": "unknown"} in ev["walked"][0]["criteria"]


# ── C6-PATH-09: sourceIpGroupExclusion ─────────────────────────────────
@pytest.mark.parametrize("ip,go", [
    ("10.9.1.1", "zia"),      # inside the excluded group: the rule does not apply
    ("10.8.0.9", "zia"),      # inside its range, last address
    ("10.7.0.1", "direct"),   # outside every excluded group: the rule applies
    ("", "conditional"),      # no source address given: depends on it
])
def test_a_forwarding_rule_that_excludes_source_groups_applies_only_outside_them(ip, go):
    """ASVS V4.1.3 · CWE-863 · CWE-697: with sourceIpGroupExclusion the rule is for sources outside its IP source groups (assumed from the SDK field)."""
    snap = connector([fwd(1, 1, "Others direct", "DIRECT", srcIpGroups=[{"id": 21, "name": "Builders"}], sourceIpGroupExclusion=True)])
    assert wp.evaluate(snap, wl(ip=ip), zp.destination("example.com"))["go"] == go


def test_an_exclusion_on_a_source_group_that_was_not_read_is_unknown():
    """ASVS V4.1.3 · CWE-754: excluded groups whose members are not known make the rule depend on them, never a match."""
    snap = connector([fwd(1, 1, "Others direct", "DIRECT", srcIpGroups=[{"id": 404, "name": "Gone"}], sourceIpGroupExclusion=True)])
    ev = wp.evaluate(snap, wl(ip="10.7.0.1"), zp.destination("example.com"))
    assert ev["go"] == "conditional"


def test_an_exclusion_with_source_ips_checks_both():
    """ASVS V4.1.3 · CWE-863: source IPs still have to match when the rule's source groups are an exclusion."""
    snap = connector([fwd(1, 1, "Others direct", "DIRECT", srcIps=["10.7.0.0/24"], srcIpGroups=[{"id": 21, "name": "Builders"}],
                          sourceIpGroupExclusion=True)])
    assert [wp.evaluate(snap, wl(ip=ip), zp.destination("example.com"))["go"] for ip in ("10.7.0.1", "10.6.0.1")] == ["direct", "zia"]


# ── C6-PATH-10: a forward method this tool does not know ───────────────
@pytest.mark.parametrize("method", ["INVALID", "GEO_STEER", ""])
def test_an_unknown_forward_method_is_unknown_never_assumed_to_be_zia(method):
    """ASVS V1.4.4 · CWE-636 · CWE-754: a rule whose forward method is INVALID or unrecognised decides "unknown", never "forwarded to ZIA" (fail closed)."""
    # Arrange
    rule = fwd(1, 1, "Odd", "ZIA")
    rule["forwardMethod"] = method
    snap = connector([rule]) if method else connector([{k: v for k, v in rule.items() if k != "forwardMethod"}])
    # Act
    ev = wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"))
    # Assert
    if not method:   # no forward method at all: the SDK default ZIA (normalize_rule) still applies
        assert ev["go"] == "zia"
        return
    fm = next(m for m in ev["modules"] if m["key"] == "connector_forwarding")
    assert (ev["go"], fm["verdict"], ev["hops"][-1]["status"]) == ("unknown", "unknown", "unknown")
    assert ev["impacts"] and ev["impacts"][0]["status"] == "unknown" and "does not recognise" in ev["headline"]


# ── C6-PATH-11: ZPA segment references by ZPA id ───────────────────────
def test_a_zpa_rule_naming_a_segment_by_its_zpa_id_matches_after_a_rename():
    """ASVS V4.1.3 · CWE-697: a connector ZPA rule matches the segment by its ZPA id (externalId) when the name it holds is stale."""
    snap = connector([fwd(1, 1, "To ZPA", "ZPA", zpaAppSegments=[{"id": 900, "name": "Old name", "externalId": "s1"}])])
    seg = {"id": "s1", "name": "Git", "segment_group_id": "g1", "segment_group_name": "Corp"}
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("git.corp.example"), seg, True)["go"] == "zpa"


def test_a_zpa_rule_on_a_nameless_segment_group_ref_never_matches_a_segment_without_a_group():
    """ASVS V4.1.3 · CWE-697 · CWE-1287: an empty name or id never matches an empty one: a ZPA rule is not taken for every segment."""
    snap = connector([fwd(1, 1, "To ZPA", "ZPA", zpaApplicationSegmentGroups=[{"name": ""}], zpaAppSegments=[{"name": "Other"}])])
    seg = {"id": "s9", "name": "Wiki", "segment_group_id": None, "segment_group_name": None}
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("wiki.corp.example"), seg, True)["go"] == "zia"


def test_a_zpa_rule_naming_a_segment_group_by_its_zpa_id_matches():
    """ASVS V4.1.3 · CWE-697: a segment group is matched by its ZPA id (zpaId, ztw/models/forwarding_rules.py)."""
    snap = connector([fwd(1, 1, "To ZPA", "ZPA", zpaApplicationSegmentGroups=[{"id": 5, "name": "Renamed", "zpaId": "g1"}])])
    seg = {"id": "s1", "name": "Git", "segment_group_id": "g1", "segment_group_name": "Corp"}
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("git.corp.example"), seg, True)["go"] == "zpa"


# ── C6-PATH-12: PAC string methods follow ECMAScript ───────────────────
def _pac(expr):
    r = pac_eval.evaluate('function FindProxyForURL(url, host) { return "" + (%s); }' % expr, "https://a.example/", "a.example")
    return r["result"] if r["status"] == "ok" else r["error"]


@pytest.mark.parametrize("expr,want", [
    ('"abc".lastIndexOf("c", -5)', "-1"),       # fromIndex is honoured
    ('"abca".lastIndexOf("a", 2)', "0"),
    ('"abcabc".lastIndexOf("bc", 4)', "4"),
    ('"abcabc".lastIndexOf("bc", 3)', "1"),
    ('"abc".lastIndexOf("a", 0/0)', "0"),        # NaN searches the whole string
    ('"abc".lastIndexOf("")', "3"),
    ('"abc".indexOf("a", 1/0)', "-1"),           # Infinity, never an OverflowError refusal
    ('"abc".indexOf("c", -1/0)', "2"),
    ('"abc".indexOf("", 9)', "3"),
    ('"abc".charAt(1/0)', ""),
    ('"abc".charAt(1.9)', "b"),
    ('"abcdef".substr(2, 1/0)', "cdef"),
    ('"abcdef".substr(-1/0, 2)', "ab"),
    ('"abcdef".substr(1/0)', ""),
    ('"abcdef".substr(1.7, 2.9)', "bc"),
    ('"abc".substring(1/0, -1/0)', "abc"),
    ('"abcdef".substr(-3)', "def"),
    ('"abc".substring(-1, 2)', "ab"),
])
def test_pac_string_methods_answer_as_ecmascript_does(expr, want):
    """ASVS V5.1.3 · CWE-682 · CWE-1287: the PAC string methods give JavaScript's answer for every position, including NaN and Infinity."""
    assert _pac(expr) == want


# ── C6-PATH-13: a 250,000-row list keeps one answer per distinct answer ─
def test_rows_that_get_the_same_answer_share_one_kept_answer():
    """ASVS V1.11.3 · CWE-400 · CWE-770: rows with the same answer keep one evaluation between them, so memory grows with answers, not rows."""
    # Arrange
    parsed = bt.parse("destination\n10.1.0.0/22\n" + "\n".join(f"h{i}.example" for i in range(200)))
    # Act
    rn = bt.run(Tenant(), parsed, scope=FULL, lookup=False, sleep=lambda s: None)
    # Assert
    assert len(parsed) == 1224 and len(rn.evals) <= 4
    assert all(rn.row(i)["result"] == "allowed" for i in (0, 1023, 1223))


def test_a_kept_answer_never_carries_another_rows_headline():
    """ASVS V8.3.1 · CWE-200 · CWE-668: a shared answer keeps no headline naming the first row's destination."""
    rn = bt.run(Tenant(), bt.parse("a.example\nb.example\n"), scope=FULL, lookup=False, sleep=lambda s: None)
    assert all("headline" not in e for e in rn.evals)


def test_an_answer_an_evaluator_returns_with_unhashable_values_is_kept_on_its_own():
    """ASVS V1.11.3 · CWE-755: an evaluator's answer that cannot be compared is still kept, once per row key."""
    evals, same = [], {}
    a = bt._keep_eval(evals, same, bt._result(notes=[{"x": 1}]))
    b = bt._keep_eval(evals, same, bt._result(notes=[{"x": 1}]))
    c = bt._keep_eval(evals, same, bt._result(result="blocked"))
    d = bt._keep_eval(evals, same, bt._result(result="blocked"))
    assert (a, b, c, d) == (0, 1, 2, 2)


def test_a_large_list_keeps_well_under_a_kilobyte_per_row():
    """ASVS V1.11.3 · CWE-400 · CWE-770: Test a list keeps under 400 bytes per row (a 250,000-row list under 100 MB), measured on 4,096 rows."""
    # Arrange
    parsed = bt.parse("destination\n10.2.0.0/20\n")
    tenant = Tenant()
    tracemalloc.start()
    try:
        before = tracemalloc.get_traced_memory()[0]
        # Act
        rn = bt.run(tenant, parsed, scope=FULL, lookup=False, sleep=lambda s: None)
        kept = tracemalloc.get_traced_memory()[0] - before
    finally:
        tracemalloc.stop()
    # Assert
    assert len(rn.p) == 4096 and kept / len(rn.p) < 400, kept / len(rn.p)


# ═══ 2. Cloud & Branch Connector forwarding: every forward method ═══════
@pytest.mark.parametrize("method,go,verdict,status", [
    ("ZIA", "zia", "forwarded", "pass"),
    ("ECSELF", "zia", "forwarded", "pass"),
    ("ZPA", "zpa", "forwarded", "pass"),
    ("ECZPA", "zpa", "forwarded", "pass"),
    ("DIRECT", "direct", "bypassed", "bypass"),
    ("LOCAL_SWITCH", "local", "bypassed", "bypass"),
    ("PROXYCHAIN", "proxy", "bypassed", "bypass"),
    ("DROP", "drop", "dropped", "blocked"),
])
def test_every_connector_forward_method_ends_where_the_sdk_says(method, go, verdict, status):
    """ASVS V1.4.4 · CWE-284 · CWE-697: each forward method the SDK documents (ztw forwarding_rules add_rule) ends the traffic where it says."""
    # Arrange
    snap = connector([fwd(1, 1, "Rule", method, proxyGateway={"id": 1, "name": "GW"} if method == "PROXYCHAIN" else None)])
    # Act
    ev = wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"), None, False)
    fm = next(m for m in ev["modules"] if m["key"] == "connector_forwarding")
    # Assert
    assert (ev["go"], fm["verdict"], ev["hops"][-1]["status"], ev["method"]) == (go, verdict, status, method)
    assert ev["rule"] == {"name": "Rule", "order": 1}


def test_a_proxy_chain_rule_names_its_gateway_and_wan_selection():
    """ASVS V1.4.4 · CWE-284: the deciding rule's proxy gateway and WAN selection are named in its notes."""
    snap = connector([fwd(1, 1, "Chain", "PROXYCHAIN", proxyGateway={"id": 1, "name": "Partner GW"}, wanSelection="BALANCED_RULE")])
    ev = wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"))
    notes = next(m for m in ev["modules"] if m["key"] == "connector_forwarding")["notes"]
    assert "through gateway “Partner GW”" in notes[0] and "WAN selection: BALANCED_RULE." in notes


@pytest.mark.parametrize("wan", ["NONE", "INVALID", ""])
def test_a_wan_selection_of_none_is_not_named(wan):
    """ASVS V1.4.4 · CWE-200: a WAN selection of none or invalid adds no note."""
    snap = connector([fwd(1, 1, "Direct", "DIRECT", wanSelection=wan)])
    notes = next(m for m in wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"))["modules"] if m["key"] == "connector_forwarding")["notes"]
    assert not any("WAN" in n for n in notes)


def test_a_zpa_rule_is_unknown_when_zpa_was_not_read_and_no_match_when_no_segment_matches():
    """ASVS V1.4.4 · CWE-754: a ZPA forwarding rule on segments depends on ZPA when it was not read, and does not match a destination in no segment."""
    snap = connector([fwd(1, 1, "To ZPA", "ZPA", zpaAppSegments=[{"name": "Git"}])])
    d = zp.destination("example.com")
    unread = wp.evaluate(snap, wl(ip="10.0.0.1"), d, None, False)
    no_seg = wp.evaluate(snap, wl(ip="10.0.0.1"), d, None, True)
    assert (unread["go"], unread["possible"]) == ("conditional", ["zia", "zpa"]) and no_seg["go"] == "zia"


def test_the_zpa_edge_segment_matches_every_segment():
    """ASVS V1.4.4 · CWE-697: a rule naming "ZPA Edge App Segment" forwards every ZPA application (assumed: the predefined catch-all)."""
    snap = connector([fwd(1, 1, "Edge", "ZPA", zpaAppSegments=[{"name": "ZPA Edge App Segment"}])])
    seg = {"id": "s7", "name": "Anything", "segment_group_id": "g9", "segment_group_name": "Other"}
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("x.corp.example"), seg, True)["go"] == "zpa"


@pytest.mark.parametrize("rule_kw,w,go", [
    ({"ecGroups": [{"id": 31, "name": "Branch-EU"}]}, dict(connector_group="branch-eu"), "drop"),   # case-insensitive by name
    ({"ecGroups": [{"id": 31, "name": "Branch-EU"}]}, dict(connector_group="31"), "drop"),          # by id
    ({"ecGroups": [{"id": 31, "name": "Branch-EU"}]}, dict(connector_group="AWS-US"), "zia"),
    ({"ecGroups": [{"id": 31, "name": "Branch-EU"}]}, dict(), "conditional"),                       # none given: depends on it
    ({"srcIps": ["10.0.0.0/30"]}, dict(ip="10.0.0.3"), "drop"),
    ({"srcIps": ["10.0.0.0/30"]}, dict(ip="10.0.0.4"), "zia"),
    ({"srcIps": ["10.0.0.0/30"]}, dict(), "conditional"),
    ({"srcIpGroups": [{"id": 404, "name": "Gone"}]}, dict(ip="10.0.0.1"), "conditional"),         # group not read
    ({"destAddresses": ["*.bad.example"]}, dict(), "drop"),
    ({"destAddresses": ["bad.example"]}, dict(), "zia"),                                          # exact name only
    ({"destIpGroups": [{"id": 404, "name": "Gone"}]}, dict(), "conditional"),
    ({"destAddresses": ["100.64.0.0/10"]}, dict(), "zia"),     # a hostname reaches the ZPA pool only through ZPA
])
def test_connector_rule_criteria_oracle(rule_kw, w, go):
    """ASVS V4.1.3 · CWE-863 · CWE-697: connector group, source IP and group, and destination criteria decide, or are unknown when not given."""
    snap = connector([fwd(1, 1, "Rule", "DROP", **rule_kw)])
    assert wp.evaluate(snap, wl(**w), zp.destination("www.bad.example"))["go"] == go


class Overridden(ConnectorTenant):
    """A connector tenant where some services are replaced."""

    def __init__(self, data, **services):
        super().__init__(data)
        base = self.ztw
        self.ztw = type("Z", (), {"__getattr__": lambda me, name: services[name] if name in services else getattr(base, name)})()


def test_unreadable_forwarding_rules_leave_every_end_possible():
    """ASVS V1.4.4 · CWE-754: forwarding rules that could not be read give "unknown" with every end possible and the reason, never ZIA."""
    t = Overridden(ztw_data(), forwarding_rules=type("S", (), {"list_rules": lambda self, *a, **k: (None, None, "HTTP 403")})())
    ev = wp.evaluate(wp.read(t, pace=0), wl(ip="10.0.0.1"), zp.destination("example.com"))
    assert ev["go"] == "unknown" and set(ev["possible"]) == {"zia", "zpa", "direct", "local", "proxy", "drop"} and "HTTP 403" in ev["headline"]


@pytest.mark.parametrize("order,expect", [
    ([(5, "A"), (-1, "B"), (-2, "C"), (None, "D"), (1, "E")], ["E", "A", "C", "B", "D"]),
    ([("x", "A"), (0, "B")], ["B", "A"]),
])
def test_connector_rules_order_numbered_then_predefined_then_unordered(order, expect):
    """ASVS V4.1.3 · CWE-696: numbered rules first, then predefined negative ones (-2 before -1), then rules without an order (assumed)."""
    rules = [wp.normalize_rule({"name": n, "order": o}, i) for i, (o, n) in enumerate(order)]
    assert [r["name"] for r in wp.order_rules(rules)] == expect


# ── Workload groups by tag ─────────────────────────────────────────────
def _group(op, *containers):
    return {"id": 50, "name": "G", "expressionJson": {"operator": op, "expressionContainers": [
        {"tagType": t, "operator": "AND", "tagContainer": {"operator": cop, "tags": [{"key": k, "value": v} for k, v in tags]}}
        for t, cop, tags in containers]}}


@pytest.mark.parametrize("group,tags,state", [
    (_group("AND", ("ATTR", "AND", [("Env", "prod"), ("Tier", "web")])), "Env=prod, Tier=web", "match"),
    (_group("AND", ("ATTR", "AND", [("Env", "prod"), ("Tier", "web")])), "Env=prod", "nomatch"),
    (_group("AND", ("ATTR", "OR", [("Env", "prod"), ("Env", "stage")])), "env=STAGE", "match"),       # case-insensitive
    (_group("OR", ("VPC", "AND", [("Vpc-id", "vpc-1")]), ("ATTR", "AND", [("Env", "prod")])), "Env=prod", "match"),
    (_group("AND", ("VPC", "AND", [("Vpc-id", "vpc-1")]), ("ATTR", "AND", [("Env", "prod")])), "Env=prod", "nomatch"),
    (_group("AND", ("VM", "AND", [("Name", "")])), "VM:Name=anything", "match"),                     # no value: any value
    (_group("AND", ("VM", "AND", [("Name", "web")])), "ENI:Name=web", "nomatch"),                    # typed tag of another type
    (_group("AND", ("VM", "AND", [("Name", "web")])), "Name=web", "match"),                          # untyped tag matches any type
    (_group("AND", ("SUBNET", "AND", [])), "Env=prod", "nomatch"),                                   # an empty container never matches
    ({"id": 50, "name": "G"}, "Env=prod", "unknown"),                                                 # no expression to read
    ({"id": 50, "name": "G", "expressionJson": {"expressionContainers": ["junk", None]}}, "Env=prod", "unknown"),
])
def test_workload_group_membership_by_tag_oracle(group, tags, state):
    """ASVS V4.1.3 · CWE-863 · CWE-697: membership follows the group's expression: AND/OR within and across containers, tag types, any value."""
    assert wp.member(group, wp.parse_tags(tags), None)["state"] == state


def test_a_group_picked_by_name_or_id_is_a_member_and_no_tags_with_a_pick_is_no_match():
    """ASVS V4.1.3 · CWE-863: the group the operator picks counts as a member; another group without tags given is then not one."""
    g = _group("AND", ("ATTR", "AND", [("Env", "prod")]))
    assert wp.member(g, [], "g")["state"] == "match" and wp.member(g, [], "50")["state"] == "match"
    assert wp.member(g, [], "Other")["state"] == "nomatch"


def test_a_picked_group_that_was_not_read_is_still_a_member_and_unreadable_groups_are_said():
    """ASVS V4.1.3 · CWE-754: a group picked by name that the read did not return is kept as a member; unreadable groups are named."""
    snap = connector([fwd(1, 1, "Dev direct", "DIRECT", srcWorkloadGroups=[{"name": "Ghost"}])], workload_groups=None)
    snap["workload_groups"] = None
    ev = wp.evaluate(snap, wl(workload_group="Ghost"), zp.destination("example.com"))
    notes = next(m for m in ev["modules"] if m["key"] == "workload_groups")["notes"]
    assert ev["go"] == "direct" and any("could not be read" in n for n in notes)


def test_a_rule_on_workload_groups_with_no_tags_given_depends_on_them():
    """ASVS V4.1.3 · CWE-754: with no workload tags given, a rule on a workload group depends on membership (unknown)."""
    snap = connector([fwd(1, 1, "Dev direct", "DIRECT", srcWorkloadGroups=[{"id": 12, "name": "Dev"}])])
    assert wp.evaluate(snap, wl(), zp.destination("example.com"))["go"] == "conditional"


@pytest.mark.parametrize("value,expect", [
    ([{"type": "vpc", "key": "Vpc-id", "value": "vpc-1"}, {"type": "WEIRD", "key": "a", "value": "b"}, {"key": ""}],
     [{"type": "VPC", "key": "Vpc-id", "value": "vpc-1"}, {"type": None, "key": "a", "value": "b"}]),
    ("SUBNET: Name=web=1", [{"type": "SUBNET", "key": "Name", "value": "web=1"}]),
    ("Other: x=y", [{"type": None, "key": "Other: x", "value": "y"}]),
    (None, []),
    ("  ,;\n ", []),
])
def test_workload_tags_parse_from_text_or_a_list(value, expect):
    """ASVS V5.1.3 · CWE-20: tags as typed or as a list are parsed into {type, key, value}; an unknown type is no type."""
    assert wp.parse_tags(value) == expect


@pytest.mark.parametrize("value", [[{"key": f"k{i}"} for i in range(51)], "k=v," * 6000, [{"key": "k" * 201}]])
def test_too_many_or_too_long_workload_tags_are_refused_in_words(value):
    """ASVS V5.1.4 · CWE-400 · CWE-20: more than 50 tags, or a tag over 200 characters, is refused with a plain sentence."""
    with pytest.raises(ValueError, match="workload tag"):
        wp.parse_tags(value)


def test_exactly_fifty_tags_of_two_hundred_characters_are_accepted():
    """ASVS V5.1.4 · CWE-20: the boundary itself (50 tags, 200 characters each) is accepted."""
    assert len(wp.parse_tags([{"key": "k" * 200, "value": "v" * 200}] * 50)) == 50


@pytest.mark.parametrize("w,ip", [({"ip": "2001:DB8::1"}, "2001:db8::1"), ({"ip": " "}, None), ("not a dict", None)])
def test_a_workload_source_ip_is_normalised(w, ip):
    """ASVS V5.1.3 · CWE-20: an IPv6 source is normalised, an empty one is none, a body that is not an object is empty."""
    assert wp.workload_input(w)["ip"] == ip


def test_a_connector_group_found_names_its_location_and_one_not_found_says_so():
    """ASVS V1.4.4 · CWE-200: the connector group's ZIA location is named; one not in the read is marked not found."""
    snap = ztw_snap()
    assert wp.find_ec_group(snap, "branch-eu") == {"id": "31", "name": "Branch-EU", "location": "Frankfurt branch", "found": True}
    assert wp.find_ec_group(snap, "Nowhere")["found"] is False and wp.find_ec_group(snap, None) is None


# ── The connector read ─────────────────────────────────────────────────
def test_the_connector_read_needs_a_ztw_client():
    """ASVS V1.4.4 · CWE-284: a sign-in without the connector API is refused in words (the classic ZIA API reaches ZIA only)."""
    import zpa_reader
    with pytest.raises(zpa_reader.ReadError, match="no Cloud & Branch Connector API"):
        wp.read(object(), pace=0)


def test_a_missing_or_failing_list_is_recorded_and_the_read_goes_on():
    """ASVS V7.4.1 · CWE-755 · CWE-209: a list the SDK lacks or that fails is recorded as not read; the other lists are still read."""
    def boom(*a, **k):
        raise RuntimeError("socket closed")
    t = Overridden(ztw_data(), workload_groups=type("S", (), {"list_groups": None})(), ec_groups=type("S", (), {"list_ec_groups": staticmethod(boom)})())
    snap = wp.read(t, pace=0)
    cols = snap["collections"]
    assert cols["workload_groups"]["error"] == "not available in this SDK version" and snap["workload_groups"] is None
    assert cols["ec_groups"]["read"] is False and "socket closed" in cols["ec_groups"]["error"]
    assert cols["forwarding_rules"]["read"] is True


def test_a_list_longer_than_max_pages_is_marked_incomplete(monkeypatch):
    """ASVS V1.11.3 · CWE-400 · CWE-770: paging stops at MAX_PAGES and the list is marked incomplete, never read without end."""
    monkeypatch.setattr(wp, "MAX_PAGES", 2)
    data = ztw_data()
    data["workload_groups"] = [[{"id": i, "name": f"G{i}"}] for i in range(5)]
    snap = wp.read(ConnectorTenant(data), pace=0)
    assert snap["collections"]["workload_groups"]["complete"] is False and len(snap["workload_groups"]) == 2


def test_the_connector_read_waits_its_pace_on_the_stop_event_and_stop_ends_it():
    """ASVS V1.11.3 · CWE-400: between calls the read waits its pace on the Stop event (no sleep), and a Stop during the wait ends it."""
    class Ev:
        def __init__(self):
            self.waited = []

        def is_set(self):
            return False

        def wait(self, s):
            self.waited.append(s)
            return len(self.waited) >= 2    # Stop arrives during the second wait
    ev = Ev()
    with pytest.raises(wp.Stopped):
        wp.read(ConnectorTenant(ztw_data()), cancel=ev, pace=60)
    assert len(ev.waited) == 2 and all(0 < s <= 60 for s in ev.waited)


# ═══ 3. Cloud Firewall: network service groups and network app groups ═══
SVC = [{"id": 1, "name": "HTTPS", "tag": "HTTPS", "destTcpPorts": [{"start": 443}]},
       {"id": 2, "name": "DNS", "tag": "DNS", "destTcpPorts": [{"start": 53}], "destUdpPorts": [{"start": 53}]},
       {"id": 3, "name": "Web alt", "destTcpPorts": [{"start": 8000, "end": 8100}]}]
SVC_GROUPS = [{"id": 20, "name": "Web", "services": [{"id": 1, "name": "HTTPS"}, {"id": 3, "name": "Web alt"}]},
              {"id": 21, "name": "Empty", "services": []},
              {"id": 22, "name": "By name only", "services": [{"name": "SSH"}, "TELNET"]}]
APP_GROUPS = [{"id": 30, "name": "Remote", "networkApplications": ["SSH", "RDP"]}, {"id": 31, "name": "Nothing", "networkApplications": []},
              {"id": 32, "name": "Exotic", "networkApplications": ["SKYPE"]}]
FW_ROUTES = {"/zia/networkServices": SVC, "/zia/networkServiceGroups": SVC_GROUPS, "/zia/networkApplicationGroups": APP_GROUPS}


@pytest.mark.parametrize("crit,proto,port,state", [
    ({"nwServiceGroups": [{"id": 20, "name": "Web"}]}, "tcp", 443, "match"),
    ({"nwServiceGroups": [{"id": 20, "name": "Web"}]}, "tcp", 8100, "match"),       # range end inclusive
    ({"nwServiceGroups": [{"id": 20, "name": "Web"}]}, "tcp", 8101, "no_match"),
    ({"nwServiceGroups": [{"id": 20, "name": "Web"}]}, "udp", 443, "no_match"),     # TCP services never carry UDP
    ({"nwServiceGroups": [{"id": 21, "name": "Empty"}]}, "tcp", 443, "unknown"),    # members not known
    ({"nwServiceGroups": [{"id": 404, "name": "Gone"}]}, "tcp", 443, "unknown"),
    ({"nwServiceGroups": [{"id": 22, "name": "By name only"}]}, "tcp", 22, "match"),  # predefined service known by name (WELL_KNOWN)
    ({"nwServiceGroups": [{"id": 22, "name": "By name only"}]}, "tcp", 23, "match"),
    ({"nwServiceGroups": [{"id": 22, "name": "By name only"}]}, "tcp", 80, "no_match"),
    ({"nwServices": [{"id": 2}]}, "udp", 53, "match"),
    ({"nwServices": [{"name": "Custom unknown"}]}, "tcp", 9999, "unknown"),          # neither ports nor a known name
    ({"nwServices": [{"name": "ANY"}]}, "tcp", 1, "match"),
    ({"nwApplicationGroups": [{"id": 30, "name": "Remote"}]}, "tcp", 3389, "match"),
    ({"nwApplicationGroups": [{"id": 30, "name": "Remote"}]}, "tcp", 443, "no_match"),
    ({"nwApplicationGroups": [{"id": 30, "name": "Remote"}]}, "tcp", 4444, "unknown"),  # no named service on 4444
    ({"nwApplicationGroups": [{"id": 31, "name": "Nothing"}]}, "tcp", 22, "unknown"),
    ({"nwApplicationGroups": [{"id": 404, "name": "Gone"}]}, "tcp", 22, "unknown"),
    ({"nwApplicationGroups": [{"id": 32, "name": "Exotic"}]}, "tcp", 443, "unknown"),  # an application this tool does not know
    ({"nwApplications": ["DNS"]}, "udp", 53, "match"),
    ({"nwApplications": ["QUIC"]}, "udp", 443, "match"),
    ({"nwApplications": ["ANY"]}, "tcp", 22, "match"),                                # ANY is no condition
])
def test_firewall_service_groups_and_application_groups_oracle(crit, proto, port, state):
    """ASVS V4.1.3 · CWE-697 · CWE-863: network service groups resolve to their services' ports, application groups to their applications; unknown members stay unknown."""
    m = fw("203.0.113.5", [fw_rule(1, 1, "BLOCK_DROP", **crit)], protocol=proto, port=port, routes=FW_ROUTES)
    got = "match" if m["rule"]["name"] == "FW 1" and m["certainty"] == "definite" else \
        "no_match" if m["rule"]["name"] == DEFAULT_FW["name"] and m["certainty"] == "definite" else \
        "unknown" if m["certainty"] == "conditional" else m["certainty"]
    assert got == state, (m["rule"], m["certainty"], m["could_override"])


@pytest.mark.parametrize("action,verdict", [("ALLOW", "allow"), ("EVAL_NWAPP", "allow"), ("BLOCK_DROP", "block"), ("BLOCK_RESET", "block"),
                                            ("BLOCK_ICMP", "block"), ("DROP", "block"), ("RESET", "block"), ("FUTURE", "future"), ("", "unknown")])
def test_every_firewall_action_is_named_by_its_verdict(action, verdict):
    """ASVS V4.1.3 · CWE-697: each firewall action gives its verdict; an unknown action is named as it is, never taken for an allow."""
    m = fw("203.0.113.5", [fw_rule(1, 1, action)], protocol="tcp", port=22)
    assert (m["verdict"], m["rule"]["name"]) == (verdict, "FW 1")


def test_a_firewall_access_control_action_is_read_when_action_is_absent():
    """ASVS V4.1.3 · CWE-697: a rule giving accessControl instead of action (cloud_firewall_dns_rules model) is still read."""
    r = {k: v for k, v in fw_rule(1, 1, "").items() if k != "action"}
    r["accessControl"] = "BLOCK_DROP"
    assert fw("203.0.113.5", [r], protocol="tcp", port=22)["verdict"] == "block"


def test_without_the_default_rule_and_no_match_the_firewall_is_unknown():
    """ASVS V1.4.4 · CWE-754: no rule matches and no default rule was read: the firewall's action is unknown, never assumed."""
    m = mod(run("203.0.113.5", {"/zia/firewallFilteringRules": [fw_rule(1, 1, "BLOCK_DROP", destAddresses=["198.51.100.0/24"])]},
                protocol="tcp", port=22), "firewall")
    assert (m["verdict"], m["certainty"]) == ("unknown", "unknown")


def test_unreadable_firewall_groups_are_named_and_rules_on_them_unknown():
    """ASVS V7.4.1 · CWE-754: the firewall lists that could not be read are named, and a rule on one of them is unknown."""
    class Fails(Tenant):
        def get(self, ep, p=None):
            if ep in ("/zia/networkServiceGroups", "/zia/ipSourceGroups"):
                raise RuntimeError("timeout")
            return super().get(ep, p)
    res = pa.analyze(Fails({"/zia/firewallFilteringRules": [fw_rule(1, 1, "BLOCK_DROP", nwServiceGroups=[{"id": 20, "name": "Web"}]), DEFAULT_FW]}),
                     "203.0.113.5", scope=FULL, protocol="tcp", port=443)
    m = mod(res, "firewall")
    assert m["certainty"] == "conditional" and any("Network service groups" in n and "IP source groups" in n for n in m["notes"])


# ═══ 4. DNS Control: every action, redirect and the DoH category ════════
@pytest.mark.parametrize("action,verdict,status", [
    ("ALLOW", "allow", "pass"), ("BLOCK", "block", "blocked"), ("BLOCK_WITH_RESPONSE", "block", "blocked"),
    ("REDIR_REQ", "redirect", "warn"), ("REDIR_RES", "redirect", "warn"), ("REDIR_ZPA", "redirect", "warn"),
    ("REDIR_REQ_DOH", "redirect", "warn"), ("REDIR_REQ_KEEP_SENDER", "redirect", "warn"), ("REDIR_REQ_TCP", "redirect", "warn"),
    ("REDIR_REQ_UDP", "redirect", "warn"),
])
def test_every_dns_control_action_the_sdk_lists_gives_its_verdict(action, verdict, status):
    """ASVS V4.1.3 · CWE-697: each DNS Control action of the SDK (cloud_firewall_dns.py: ALLOW, BLOCK, REDIR_*, BLOCK_WITH_RESPONSE) gives its verdict and hop."""
    # Arrange
    rules = [dns_rule(1, 1, action, destIpCategories=["GAMBLING"]), dns_rule(2, -1, "ALLOW", defaultRule=True)]
    # Act
    res = run("casino.example", {"/zia/firewallDnsRules": rules})
    m = mod(res, "dns")
    # Assert
    assert (m["verdict"], m["certainty"], m["rule"]["name"], hop(res, "dns")["status"]) == (verdict, "definite", "DNS 1", status)
    assert any("answers the lookup differently" in n for n in m["notes"]) is (verdict == "redirect")


def test_a_dns_block_ends_the_path_and_names_the_rule():
    """ASVS V4.1.3 · CWE-697: a definite DNS block ends the path before the web modules, with the rule in the summary."""
    res = run("casino.example", {"/zia/firewallDnsRules": [dns_rule(1, 1, "BLOCK", destIpCategories=["GAMBLING"])]})
    assert res["verdict"]["outcome"] == "blocked" and "answers the lookup with a block" in res["verdict"]["summary"]
    assert hop(res, "url")["status"] == "not_reached"


@pytest.mark.parametrize("rule_kw,state", [
    ({"destIpCategories": ["DNS_OVER_HTTPS"]}, "match"),                  # the DoH category: a DoH provider is in it
    ({"destIpCategories": ["GAMBLING"]}, "no_match"),
    ({"protocols": ["DOHTTPS_RULE"]}, "unknown"),                         # a lookup over DoH is not known
    ({"dnsRuleRequestTypes": ["A", "MX"]}, "match"),                      # an address lookup is assumed
    ({"dnsRuleRequestTypes": ["MX", "TXT"]}, "no_match"),
    ({"resCategories": ["GAMBLING"]}, "unknown"),                         # the resolved address's category
    ({"applications": ["DNS_TUNNEL"]}, "unknown"),
    ({"applicationGroups": [{"id": 1, "name": "Tunnels"}]}, "unknown"),
    ({"destAddresses": ["dns.example"]}, "match"),
    ({"destAddresses": [".other.example"]}, "no_match"),
    ({"destAddresses": ["8.8.8.0/24"]}, "unknown"),                       # a hostname's address is never resolved
    ({"destCountries": ["COUNTRY_US"]}, "unknown"),
    ({"timeWindows": [{"id": 1, "name": "Night"}]}, "unknown"),
])
def test_dns_control_criteria_oracle_with_the_doh_category(rule_kw, state):
    """ASVS V4.1.3 · CWE-697 · CWE-863: each DNS rule criterion is a match, no match or unknown; the DNS-over-HTTPS category matches a DoH provider."""
    # Arrange
    rules = [dns_rule(1, 1, "BLOCK", **rule_kw), dns_rule(2, -1, "ALLOW", defaultRule=True)]
    # Act
    m = mod(pa.analyze(Tenant({"/zia/firewallDnsRules": rules}, lookup={"dns.example": ["DNS_OVER_HTTPS"]}), "dns.example", scope=FULL), "dns")
    # Assert
    got = "match" if m["rule"]["name"] == "DNS 1" and m["certainty"] == "definite" else \
        "no_match" if m["rule"]["name"] == "DNS 2" and m["certainty"] == "definite" else "unknown"
    assert got == state, (m["rule"], m["certainty"], m["could_override"])


def test_dns_control_on_an_ip_address_is_not_applicable_and_on_a_resolver_unknown():
    """ASVS V4.1.3 · CWE-754: an IP destination makes no lookup (not applicable); DNS to a resolver IP carries unknown queries."""
    rules = [dns_rule(1, 1, "BLOCK")]
    web = mod(run("203.0.113.5", {"/zia/firewallDnsRules": rules}), "dns")
    resolver = mod(run("203.0.113.5", {"/zia/firewallDnsRules": rules}, protocol="udp", port=53), "dns")
    assert (web["verdict"], web["status"]) == ("not_applicable", "not_applicable")
    assert (resolver["verdict"], resolver["certainty"]) == ("unknown", "unknown")


def test_no_dns_rule_matching_resolves_normally():
    """ASVS V4.1.3 · CWE-697: with no DNS rule matching, the lookup resolves (allow, definite)."""
    m = dns("news.example", [dns_rule(1, 1, "BLOCK", destIpCategories=["GAMBLING"])])
    assert (m["verdict"], m["certainty"], m["rule"]) == ("allow", "definite", None) and "resolves normally" in m["detail"]


# ═══ 5. Sandbox and File Type Control per file type and protocol ════════
SANDBOX = {"id": 1, "name": "Hold exe", "order": 1, "state": "ENABLED", "baRuleAction": "BLOCK", "firstTimeEnable": True,
           "firstTimeOperation": "QUARANTINE", "fileTypes": [FTC_EXE]}


@pytest.mark.parametrize("dest,protocols,files,verdict,certainty", [
    ("https://files.example/", ["HTTPS_RULE"], [FTC_EXE], "inspect", "definite"),
    ("https://files.example/", ["HTTPS_RULE"], [FTC_ZIP], "none", "definite"),          # another file type
    ("https://files.example/", ["HTTPS_RULE"], [], "inspect", "definite"),              # unknown file: held when it is one (content-dependent)
    ("https://files.example/", ["HTTP_RULE"], [FTC_EXE], "none", "definite"),           # rule for plain HTTP only
    ("http://files.example/", ["HTTP_RULE"], [FTC_EXE], "inspect", "definite"),
    ("http://files.example/", ["HTTPS_RULE"], [FTC_EXE], "none", "definite"),
    ("http://files.example/", ["FTP_RULE", "FOHTTP_RULE"], [FTC_EXE], "none", "definite"),
    ("https://files.example/", ["ANY_RULE"], [FTC_EXE], "inspect", "definite"),
    ("https://files.example/", [], [FTC_EXE], "inspect", "definite"),
])
def test_sandbox_per_file_type_and_protocol(dest, protocols, files, verdict, certainty):
    """ASVS V4.1.3 · CWE-697 · CWE-863: a Sandbox rule holds a file only for its file types and protocols (sandbox_rules.py fields)."""
    rule = dict(SANDBOX, protocols=protocols)
    m = mod(run(dest, {"/zia/sandboxRules": [rule]}, context={"file_types": files}), "sandbox")
    assert (m["verdict"], m["certainty"]) == (verdict, certainty), m


def test_a_sandbox_rule_names_its_first_time_action_and_is_content_dependent_without_a_file():
    """ASVS V4.1.3 · CWE-200: the deciding Sandbox rule names its action and first-time action; without a file it holds files of its types when one is carried."""
    m = mod(run("files.example", {"/zia/sandboxRules": [SANDBOX]}), "sandbox")
    assert m["rule"]["action"] == "BLOCK, first time: QUARANTINE" and m.get("content_dependent") is True


def test_a_sandbox_rule_on_traffic_left_encrypted_sees_no_file():
    """ASVS V4.1.3 · CWE-697: a Sandbox rule on traffic SSL inspection leaves encrypted sees no file (blind)."""
    m = mod(run("files.example", {"/zia/sandboxRules": [SANDBOX], "/zia/sslInspectionRules": []}, context={"file_types": [FTC_EXE]}), "sandbox")
    assert (m["verdict"], m["certainty"]) == ("blind", "definite")


@pytest.mark.parametrize("extra", [{"baPolicyCategories": ["RANSOMWARE"]}, {"byThreatScore": 70}])
def test_a_sandbox_rule_on_a_threat_class_or_score_is_decided_on_the_file(extra):
    """ASVS V4.1.3 · CWE-754: a Sandbox rule on a threat category or score is decided on the file itself: unknown criterion, content-dependent."""
    m = mod(run("files.example", {"/zia/sandboxRules": [dict(SANDBOX, **extra)]}, context={"file_types": [FTC_EXE]}), "sandbox")
    assert m["verdict"] == "inspect" and any(c["state"] == "unknown" for c in m["criteria"])


FTC = {"id": 60, "name": "Block zip", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK", "operation": "UPLOAD",
       "fileTypes": [FTC_ZIP], "urlCategories": ["ANY"]}


@pytest.mark.parametrize("dest,protocols,files,action,status", [
    ("https://files.example/", ["HTTPS_RULE"], [FTC_ZIP], "BLOCK", "blocked"),
    ("https://files.example/", ["HTTPS_RULE"], [FTC_EXE], "BLOCK", "none"),          # another file type
    ("https://files.example/", ["HTTPS_RULE"], [], "BLOCK", "conditional"),          # file type not given
    ("https://files.example/", ["HTTPS_RULE"], ["zip"], "BLOCK", "conditional"),     # an extension is not a file category
    ("https://files.example/", ["HTTP_RULE"], [FTC_ZIP], "BLOCK", "none"),           # rule for plain HTTP only
    ("http://files.example/", ["HTTP_RULE"], [FTC_ZIP], "BLOCK", "blocked"),
    ("http://files.example/", ["HTTPS_RULE"], [FTC_ZIP], "BLOCK", "none"),
    ("https://files.example/", ["FTP_RULE"], [FTC_ZIP], "BLOCK", "none"),
    ("https://files.example/", ["HTTPS_RULE"], [FTC_ZIP], "CAUTION", "warn"),
    ("https://files.example/", ["HTTPS_RULE"], [FTC_ZIP], "ALLOW", "pass"),
])
def test_file_type_control_per_file_type_and_protocol(dest, protocols, files, action, status):
    """ASVS V4.1.3 · CWE-697 · CWE-863: File Type Control applies a rule only to its file types and protocols (file_type_control_rule.py fields)."""
    rule = dict(FTC, protocols=protocols, filteringAction=action)
    res = run(dest, {"/zia/fileTypeRules": [rule]}, context={"operation": "UPLOAD", "file_types": files})
    assert hop(res, "ftc")["status"] == status


def test_file_type_control_on_encrypted_traffic_is_blind():
    """ASVS V4.1.3 · CWE-697: File Type Control cannot see a file in traffic left encrypted."""
    res = run("files.example", {"/zia/fileTypeRules": [FTC], "/zia/sslInspectionRules": []}, context={"operation": "UPLOAD", "file_types": [FTC_ZIP]})
    assert hop(res, "ftc")["status"] == "blind"


# ═══ 6. Data Flow Map counts for every network and platform ═════════════
class FlowTenant(Tenant):
    """App profiles for Windows (tunnel on the office network, none off it,
    PAC on VPN), macOS (bypasses mail) and Linux (no forwarding profile)."""

    def __init__(self):
        super().__init__({
            "/zcc/webPolicies": [
                {"id": 1, "name": "Win", "os": "windows", "active": True, "ruleOrder": 1, "forwardingProfileId": 5, "strictEnforcement": True,
                 "installEndpointDlp": True, "sslCertInstall": True},
                {"id": 2, "name": "Mac", "os": "macos", "active": True, "ruleOrder": 1, "forwardingProfileId": 5, "strictEnforcement": True,
                 "sslCertInstall": True, "bypassDomains": ["mail.example"]},
                {"id": 3, "name": "Linux", "os": "linux", "active": True, "ruleOrder": 1, "strictEnforcement": True}],
            "/zcc/forwardingProfiles": [{"id": 5, "name": "Fwd", "forwardingProfileActions": [
                {"networkType": "ON_TRUSTED_NETWORK", "tunnelType": "ZSCALER_TUNNEL_2"},
                {"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "NONE"},
                {"networkType": "VPN_TRUSTED_NETWORK", "tunnelType": "ENFORCE_PROXY", "customPac": "https://pac.example/p.pac"}]},
                {"id": 6, "name": "Other", "forwardingProfileActions": []}],
            "/zia/pacFiles": [{"id": 1, "name": "p.pac", "pacUrl": "https://pac.example/p.pac",
                               "pacContent": 'function FindProxyForURL(u, h) { if (dnsDomainIs(h, "news.example")) return "DIRECT"; return "PROXY ${GATEWAY}:80"; }'}],
        })


def test_data_flow_map_counts_for_every_network_and_platform():
    """ASVS V1.4.4 · CWE-682 · CWE-1339: for every platform and network each path is in exactly one class, the counts add up and match a recount."""
    for platform in df.PLATFORMS:
        # Act
        rep = df.generate_data_flow_report(FlowTenant(), ["mail.example", "news.example", "files.example"], platform=platform, scope=FULL)
        s = rep["summary"]
        classes = [df.visibility(t) for t in rep["traces"]]
        # Assert
        assert s["traces"] == len(rep["traces"]) == 3 * len(df.NETWORKS)
        assert sum(s[k] for k in ("bypassed", "blind", "enforced", "monitored", "blocked", "unverified", "decrypted_other")) == s["traces"]
        assert (s["bypassed"], s["blind"], s["enforced"], s["monitored"], s["blocked"], s["unverified"], s["decrypted_other"]) == tuple(
            classes.count(c) for c in ("bypassed", "blind", "enforce", "monitor", "blocked", "unverified", "decrypted"))
        assert s["high"] == sum(1 for t in rep["traces"] for w in t["weak_points"] if w["severity"] == "high")


@pytest.mark.parametrize("platform,network,dest,cls", [
    ("windows", "on", "files.example", "enforce"),        # tunnel, decrypted, a blocking DLP rule
    ("windows", "off", "files.example", "bypassed"),      # forwarding none off network
    ("windows", "vpn", "news.example", "bypassed"),       # PAC returns DIRECT
    ("windows", "vpn", "files.example", "enforce"),       # PAC proxies it to Zscaler
    ("macos", "on", "mail.example", "bypassed"),          # app profile bypass
    ("macos", "on", "files.example", "enforce"),
    ("linux", "on", "files.example", "unverified"),       # no forwarding profile linked
    ("ios", "on", "files.example", "unverified"),         # no app profile for the platform
])
def test_data_flow_map_class_oracle_by_network_and_platform(platform, network, dest, cls):
    """ASVS V1.4.4 · CWE-697: the Data Flow Map's class for a destination follows the platform's app profile and the network's forwarding action."""
    rep = df.generate_data_flow_report(FlowTenant(), [dest], platform=platform, scope=FULL)
    t = next(t for t in rep["traces"] if t["network"] == network)
    assert df.visibility(t) == cls, [(h["key"], h["status"]) for h in t["hops"]]


def test_a_destination_the_tracer_cannot_trace_is_a_diagnostic_and_none_traced_is_an_error(monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: one destination that breaks the tracer is reported in the diagnostics; when none traces, the error says why."""
    real = df.trace

    def flaky(rd, *a, **k):
        if rd.get("label") == "bad.example":
            raise KeyError("boom")
        return real(rd, *a, **k)
    monkeypatch.setattr(df, "trace", flaky)
    rep = df.generate_data_flow_report(FlowTenant(), ["bad.example", "files.example"], scope=FULL)
    assert rep["summary"]["traces"] == 3 and sum(1 for d in rep["diagnostics"] if str(d.get("section")).startswith("trace bad.example")) == 3
    with pytest.raises(RuntimeError, match="no path could be traced: KeyError"):
        df.generate_data_flow_report(FlowTenant(), ["bad.example"], scope=FULL)


def test_a_stored_map_traces_a_typed_destination_with_a_bad_network_as_off():
    """ASVS V5.1.3 · CWE-20: a stored report traces a typed destination; an unknown network or platform falls back to off / windows."""
    rep = df.generate_data_flow_report(FlowTenant(), ["files.example"], scope=FULL)
    t = df.trace_from_report(rep, "files.example", "moon", "plan9")
    assert (t["network"], t["platform"]) == ("off", "windows")


def test_the_data_flow_markdown_escapes_tenant_strings():
    """ASVS V5.3.3 · CWE-74 · CWE-1236: a destination or profile name with Markdown or HTML is written as inert text."""
    rep = df.generate_data_flow_report(FlowTenant(), ["files.example"], scope=FULL)
    rep["traces"][0]["destination"]["label"] = "<img src=x onerror=alert(1)> [x](javascript:alert(1))"
    md = df.to_markdown(rep, "Acme <b>")
    assert "<img" not in md and " [x](javascript:" not in md and "\\[x\\](javascript:" in md and "<b>" not in md


# ═══ 7. Performance ═════════════════════════════════════════════════════
def big_tenant(n=5000):
    per = n // 7
    return {
        "/zia/urlFilteringRules": [url_rule(i, i + 1, "ALLOW", [f"CAT_{i}"]) for i in range(per)],
        "/zia/sslInspectionRules": [{"id": 10000 + i, "name": f"S{i}", "order": i + 1, "state": "ENABLED", "action": {"type": "DECRYPT"},
                                     "urlCategories": [f"CAT_{i}"]} for i in range(per)],
        "/zia/webDlpRules": [{"id": 20000 + i, "name": f"D{i}", "order": i + 1, "state": "ENABLED", "action": "BLOCK", "dlpEngines": [{"name": "PCI"}],
                              "urlCategories": [f"CAT_{i}"]} for i in range(per)],
        "/zia/firewallFilteringRules": [fw_rule(30000 + i, i + 1, "ALLOW", nwServiceGroups=[{"id": 20, "name": "Web"}],
                                                destAddresses=[f"10.{i // 250}.{i % 250}.0/24"]) for i in range(per)] + [DEFAULT_FW],
        "/zia/firewallDnsRules": [dns_rule(40000 + i, i + 1, "BLOCK", destIpCategories=[f"CAT_{i}"]) for i in range(per)],
        "/zia/sandboxRules": [{"id": 50000 + i, "name": f"B{i}", "order": i + 1, "state": "ENABLED", "baRuleAction": "BLOCK",
                               "urlCategories": [f"CAT_{i}"]} for i in range(per)],
        "/zia/fileTypeRules": [{"id": 60000 + i, "name": f"F{i}", "order": i + 1, "state": "ENABLED", "filteringAction": "BLOCK",
                                "urlCategories": [f"CAT_{i}"], "fileTypes": [FTC_ZIP]} for i in range(n - 6 * per)],
        **FW_ROUTES,
    }


def test_one_analysis_of_a_tenant_with_5000_rules_takes_under_two_seconds():
    """ASVS V1.11.3 · CWE-400 · CWE-1176: one analysis against a 5,000-rule tenant (every section) finishes in under 2 s, read included."""
    tenant = Tenant(big_tenant())
    t0 = time.perf_counter()
    res = pa.analyze(tenant, "news.example", scope=FULL)
    first = time.perf_counter() - t0
    t0 = time.perf_counter()
    pa.analyze(tenant, "203.0.113.5", scope=FULL, protocol="tcp", port=443, snapshot=res["snapshot_for_cache"])
    again = time.perf_counter() - t0
    assert first < 2.0 and again < 2.0, (first, again)


def test_the_list_parser_caps_rows_at_exactly_max_rows(monkeypatch):
    """ASVS V5.1.4 · CWE-400 · CWE-770: a list expanding to exactly MAX_ROWS is read; one row more is refused in words (cap shrunk for speed)."""
    monkeypatch.setattr(bt, "MAX_ROWS", 260)
    assert len(bt.parse("10.0.0.0/24\na.example\nb.example\nc.example\nd.example\n")) == 260
    with pytest.raises(bt.ListError, match="more than 260 rows"):
        bt.parse("10.0.0.0/24\na.example\nb.example\nc.example\nd.example\ne.example\n")
    with pytest.raises(bt.ListError, match="more than 260 rows"):
        bt.parse("a.example\n10.0.0.0/24\n10.0.1.0/30\n")


# ═══ 8. The HAR batch and the URL lookup (path_analyzer) ════════════════
class Lookup:
    """POST /urlLookup answers from a table; counts the requests."""

    def __init__(self, answer=None, status=200, raises=None, echo=True):
        self.answer, self.status, self.raises, self.echo, self.posts = answer or {}, status, raises, echo, []

    def post(self, ep, body):
        self.posts.append(list(body))
        if self.raises:
            raise self.raises
        if self.status != 200:
            return {"error": "slow down"}, self.status
        return [dict({"urlClassifications": self.answer.get(h, [])}, **({"url": h} if self.echo else {})) for h in body], 200


def test_lookup_many_asks_a_hundred_hosts_per_request_and_matches_by_the_echoed_url():
    """ASVS V1.11.3 · CWE-400: the URL lookup is asked a hundred hosts per request (url_categories.lookup's chunk) and answers are matched by url."""
    hosts = [f"h{i}.example" for i in range(250)]
    c = Lookup({"h7.example": ["NEWS"], "h249.example": ["GAMBLING"]})
    out = pa.lookup_many(c, hosts)
    assert [len(p) for p in c.posts] == [100, 100, 50]
    assert out["h7.example"]["categories"] == ["NEWS"] and out["h249.example"]["categories"] == ["GAMBLING"]


def test_lookup_many_matches_by_position_only_when_no_url_is_echoed():
    """ASVS V5.1.3 · CWE-20: without an echoed url the answer is taken by position; a missing answer is said, never invented."""
    class Short(Lookup):
        def post(self, ep, body):
            return [{"urlClassifications": ["A"]}], 200
    out = pa.lookup_many(Short(), ["a.example", "b.example"])
    assert out["a.example"]["categories"] == ["A"] and out["b.example"]["error"] == "the URL lookup returned no answer for this host"


@pytest.mark.parametrize("client,err", [
    (object(), "this client cannot run a URL lookup"),
    (Lookup(raises=RuntimeError("reset by peer")), "URL lookup failed: reset by peer"),
    (Lookup(status=429), "URL lookup answered HTTP 429: slow down"),
])
def test_a_lookup_that_cannot_answer_gives_each_host_the_reason(client, err):
    """ASVS V7.4.1 · CWE-754 · CWE-209: a lookup that fails gives every host of its chunk the reason, never an invented category."""
    assert pa.lookup_many(client, ["a.example"])["a.example"] == {"categories": [], "security_alerts": [], "application": None, "error": err}
    assert pa.lookup_categories(client, "a.example")["error"] == err


def test_lookup_many_stops_before_the_next_chunk():
    """ASVS V1.11.3 · CWE-400: Stop ends the lookup between requests: nothing more is asked."""
    stop = threading.Event()

    class Stopping(Lookup):
        def post(self, ep, body):
            stop.set()
            return super().post(ep, body)
    c = Stopping()
    with pytest.raises(df.ReadStopped):
        pa.lookup_many(c, [f"h{i}.example" for i in range(150)], cancel=stop)
    assert len(c.posts) == 1


def test_the_lookup_keeps_the_application_and_security_alerts():
    """ASVS V1.4.4 · CWE-697: ZIA's lookup application and security alerts are kept upper-case and sorted."""
    class App:
        def post(self, ep, body):
            return [{"url": body[0], "urlClassifications": ["web_mail"], "urlClassificationsWithSecurityAlert": ["phishing"], "application": "gmail"}], 200
    assert pa.lookup_categories(App(), "a.example") == {"categories": ["WEB_MAIL"], "security_alerts": ["PHISHING"], "application": "GMAIL", "error": None}
    assert pa.lookup_many(App(), ["a.example"])["a.example"]["application"] == "GMAIL"


def test_a_batch_analyzes_every_host_against_one_read():
    """ASVS V1.11.3 · CWE-400: a HAR batch reads the tenant once and traces each host against that read; rows carry the HAR counts."""
    class Counting(Tenant):
        gets = 0

        def get(self, ep, p=None):
            Counting.gets += 1
            return super().get(ep, p)
    t = Counting({"/zia/urlFilteringRules": [url_rule(1, 1, "BLOCK", ["GAMBLING"])]})
    out = pa.analyze_batch(t, ["casino.example", "news.example", "mail.example"], scope=FULL,
                           stats={"casino.example": {"requests": 3, "uploads": 1, "bytes_sent": 99, "methods": ["POST"]}})
    first_read = Counting.gets
    assert [r["outcome"] for r in out["rows"]] == ["blocked", "inspected", "inspected"]
    assert out["rows"][0]["deciding_rule"] == "URL 1" and out["rows"][0]["requests"] == 3 and out["rows"][1]["requests"] == 0
    assert out["snapshot_for_cache"] is not None and out["stopped"] is None and first_read == Counting.gets


def test_a_batch_refuses_more_than_its_cap_and_nothing_in_scope():
    """ASVS V5.1.4 · CWE-770 · CWE-400: more than BATCH_MAX hosts, or nothing in scope, is refused before anything is read."""
    with pytest.raises(ValueError, match=f"At most {pa.BATCH_MAX}"):
        pa.analyze_batch(Tenant(), ["a.example"] * (pa.BATCH_MAX + 1), scope=FULL)
    with pytest.raises(ValueError, match="Nothing the Path analyzer reads is in scope"):
        pa.analyze_batch(Tenant(), ["a.example"], scope={"read": []})


def test_a_batch_records_a_host_that_cannot_be_traced_and_goes_on():
    """ASVS V7.4.1 · CWE-755: a host the analyzer refuses is recorded with its reason; the others are still analyzed."""
    out = pa.analyze_batch(Tenant(), ["not a host!", "news.example"], scope=FULL)
    assert list(out["errors"]) == ["not a host!"] and [r["host"] for r in out["rows"]] == ["news.example"]


@pytest.mark.parametrize("analyzed", [0, 1])
def test_a_batch_stopped_keeps_what_was_analyzed_and_lists_the_rest(analyzed):
    """ASVS V1.11.3 · CWE-400: Stop keeps the hosts already analyzed, lists the rest as not analyzed, and keeps no partial read."""
    stop = threading.Event()
    if analyzed == 0:
        stop.set()

    def log(line):
        if line.startswith(f"Tracing {analyzed} of"):
            stop.set()
    hosts = ["a.example", "b.example", "c.example"]
    res = pa.analyze_batch(Tenant(), hosts, scope=dict(FULL, lookup=False), cancel=stop, log=log)
    assert len(res["rows"]) == analyzed and res["not_analyzed"] == hosts[analyzed:] and res["snapshot_for_cache"] is None
    assert "Nothing was written" in res["stopped"]


@pytest.mark.parametrize("outcome,hops,deciding", [
    ("bypassed", [{"key": "zcc", "status": "bypass", "decided_by": {"name": "Win"}}], "Win"),
    ("blind", [{"key": "ssl", "status": "blind", "decided_by": {"name": "No decrypt"}}], "No decrypt"),
    ("monitor", [{"key": "dlp", "status": "monitor", "decided_by": {"name": "Watch"}, "rules": [{"name": "Watch"}, {"x": 1}]}], "Watch"),
    ("unknown", [{"key": "dlp", "status": "out_of_scope", "rules": [{"name": "Hidden"}]}], ""),
])
def test_a_batch_row_names_the_deciding_object_for_each_outcome(outcome, hops, deciding):
    """ASVS V1.4.4 · CWE-697: a batch row names what decides it (the bypassing profile, the SSL rule, the DLP rule) and no DLP rule out of scope."""
    row = pa.batch_row("a.example", {"verdict": {"outcome": outcome}, "trace": {"hops": hops}})
    assert row["deciding_rule"] == deciding and row["outcome"] == pa.BATCH_OUTCOMES[outcome]
    assert row["dlp_rules"] == (["Watch"] if outcome == "monitor" else [])
    assert row["stops_at"] == ("" if outcome == "bypassed" else "reaches the destination")


# ═══ 9. Destinations, scope and the verdict (path_analyzer) ═════════════
@pytest.mark.parametrize("typed,why", [
    ("https://example.com:99999/", "not a URL"),     # port out of range (urlsplit refuses it)
    ("https://example.com:0/", "port must be a whole number"),
    ("https://:443/", "not a URL"),
    ("ex ample.com", "not a URL"),
    ("xn--.com", "not a URL"),
    ("a" * 64 + ".example", "not a URL"),             # a label over 63 characters
])
def test_a_destination_that_cannot_be_one_is_refused_in_words(typed, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an invalid port, an empty host, a space or an over-long label is refused with a plain sentence."""
    with pytest.raises(ValueError, match=why):
        pa.parse_destination(typed)


@pytest.mark.parametrize("typed,host,private", [
    ("::ffff:10.0.0.1", "::ffff:10.0.0.1", True),      # an IPv4-mapped address is its IPv4 address
    ("fe80::1", "fe80::1", True),
    ("100.64.0.1", "100.64.0.1", False),                # shared address space is not RFC 1918
    ("ｅxample.com", "example.com", False),             # full-width letters fold to ASCII (UTS 46)
])
def test_unicode_ipv6_and_mapped_addresses_are_placed(typed, host, private):
    """ASVS V5.1.3 · CWE-20 · CWE-176: IPv4-mapped IPv6, link-local, shared space and full-width IDN names are placed as the tenant sees them."""
    d = pa.parse_destination(typed)
    assert (d["host"], d["private"]) == (host, private)


def test_a_channel_other_than_web_is_refused_before_anything_is_read():
    """ASVS V1.4.4 · CWE-841: the analyzer models inline web traffic only; another channel is refused before any read."""
    t = Tenant()
    with pytest.raises(ValueError, match="models inline web traffic"):
        pa.analyze(t, "a.example", scope=FULL, context={"channel": "endpoint"})


@pytest.mark.parametrize("snap,key", [(None, None), ({"path_scope": 7}, None), ({"path_scope": "a,b"}, "a,b")])
def test_a_kept_read_says_which_scope_it_was_made_for(snap, key):
    """ASVS V4.1.3 · CWE-284: a kept read names its scope only as a string; anything else names none."""
    assert pa.snapshot_scope_key(snap) == key


def test_a_kept_read_for_another_platform_is_not_reused():
    """ASVS V4.1.3 · CWE-284 · CWE-367: a kept Client Connector read for another platform is read again, never reused."""
    res = run("news.example")
    snap = res["snapshot_for_cache"]
    snap["client_connector"]["profile_platform"] = "macos"
    assert pa.reusable(snap, FULL, "macos") and not pa.reusable(snap, FULL, "windows")


@pytest.mark.parametrize("outcome,hops,head", [
    ("unknown", [{"key": "ssl", "status": "unknown", "why": "SSL action not recognized", "detail": "odd", "label": "SSL"}], "SSL rule action is not recognized"),
    ("unknown", [{"key": "dlp", "status": "unknown", "detail": "x", "label": "Inline Web DLP"}], "the Inline Web DLP rules could not be read"),
    ("out_of_scope", [{"key": "dlp", "status": "out_of_scope", "detail": "nis", "label": "Inline Web DLP"}], "not in scope"),
    ("metadata_only", [{"key": "dlp", "status": "metadata_only", "detail": "meta", "label": "Inline Web DLP"}], "no eligible content-inspecting"),
    ("conditional", [], "conditional on missing identity"),
    ("monitor", [{"key": "dlp", "status": "monitor", "detail": "m", "label": "DLP", "rules": [{"name": "W"}], "decided_by": {"name": "W"}}], "configured to monitor"),
    ("none", [], "no DLP rule covers this traffic"),
])
def test_every_verdict_outcome_has_its_own_headline(outcome, hops, head):
    """ASVS V7.4.1 · CWE-209 · CWE-1287: every outcome gets its own plain headline (unknown, out of scope, metadata only, conditional, monitor, none)."""
    t = {"hops": hops, "outcome": outcome, "reaches_zscaler": True, "decrypted": True, "destination": {}, "channels": {}}
    v = pa.derive_verdict(t, {"host": "a.example"}, {"security_alerts": []})
    assert head in v["headline"] and v["outcome"] == outcome


def test_a_security_alert_and_a_channel_weak_point_are_impacts():
    """ASVS V7.4.1 · CWE-200: a lookup security alert is the first impact; a channel's weak point is listed too."""
    t = {"hops": [], "outcome": "none", "reaches_zscaler": True, "decrypted": True, "destination": {},
         "channels": {"email": {"label": "Email", "status": "none", "detail": "d", "weak_point": {"severity": "low", "fix": "f"}}}}
    v = pa.derive_verdict(t, {"host": "a.example"}, {"security_alerts": ["PHISHING"]})
    assert [i["hop"] for i in v["impacts"]] == ["lookup", "email"] and v["impacts"][0]["severity"] == "high"


@pytest.mark.parametrize("ep_status,action,severity", [
    ("out_of_scope", "Endpoint DLP is not in scope", "info"),
    ("unknown", "Read the Endpoint DLP rules again", "medium"),
    ("off", "Enable Endpoint DLP for this device", "high"),
    ("none", "Enable Endpoint DLP for this device", "high"),
    ("inventory", "Verify Endpoint DLP applicability on this device", "info"),
])
def test_endpoint_dlp_is_weighed_first_when_the_path_gives_no_visibility(ep_status, action, severity):
    """ASVS V1.4.4 · CWE-693: for a bypassed path the first mitigation is Endpoint DLP, worded by its state."""
    t = {"hops": [], "channels": {"endpoint": {"status": ep_status, "detail": "d"}}}
    m = pa.recommend_mitigations(t, {"outcome": "bypassed", "reaches_zscaler": False, "categories": [], "applications": []})
    assert (m[0]["channel"], m[0]["action"], m[0]["severity"]) == ("endpoint", action, severity)


def test_mail_and_saas_mitigations_follow_the_destination_shape():
    """ASVS V1.4.4 · CWE-693: Email DLP is recommended only for webmail, the SaaS API only for a recognised application."""
    t = {"hops": [], "channels": {"email": {"status": "none"}, "saas": {"status": "none"}}}
    m = pa.recommend_mitigations(t, {"outcome": "monitor", "reaches_zscaler": True, "categories": ["WEB_MAIL"], "applications": ["GMAIL"]})
    assert [x["channel"] for x in m] == ["web", "email", "saas"] and m[0]["action"] == "Promote the monitoring rule to block"
    assert pa.recommend_mitigations(t, {"outcome": "enforce", "reaches_zscaler": True, "categories": ["NEWS"], "applications": []}) == []


def test_a_kept_snapshot_with_dlp_rules_missing_their_flags_still_traces():
    """Regression · ASVS V5.1.3 · CWE-1287: a kept read from before DLP rules carried enforcing / without_content_inspection still traces."""
    res = run("news.example")
    snap = copy.deepcopy(res["snapshot_for_cache"])
    for r in snap["snapshot"]["zia"]["dlp"]:
        r.pop("enforcing", None)
        r.pop("without_content_inspection", None)
    again = pa.analyze(Tenant(), "news.example", scope=FULL, snapshot=snap)
    assert again["verdict"]["outcome"] == res["verdict"]["outcome"] and again["fresh_read"] is False


# ═══ 10. The ZIA module read (zia_path_modules.read) ════════════════════
class ModuleTenant(Tenant):
    def __init__(self, answers):
        super().__init__()
        self.answers = answers

    def get(self, ep, p=None):
        a = self.answers.get(ep)
        if isinstance(a, Exception):
            raise a
        return a if a is not None else super().get(ep, p)


@pytest.mark.parametrize("answer,state,why", [
    (([], 204), "read", None),                                                     # 204 is an empty list
    (({"error": "busy"}, 503), "unread", "HTTP 503 (busy)"),
    (("not a list", 200), "unread", "not a complete list"),
    (({"list": [{"id": 1}]}, 200), "read", None),                                    # a wrapped list
    (([{"id": 1}, "junk"], 200), "unread", "not a complete list"),
    (RuntimeError("socket closed"), "unread", "RuntimeError: socket closed"),
])
def test_a_module_read_that_fails_is_recorded_never_an_empty_list(answer, state, why):
    """ASVS V7.4.1 · CWE-754 · CWE-209: a failed module read is recorded as unread with its reason, never taken as an empty rule list."""
    out = zpm.read(ModuleTenant({"/zia/firewallDnsRules": answer}), FULL)
    assert out["dns"]["state"] == state and (why is None or why in out["dns"]["why"])


def test_a_settings_object_that_is_not_one_makes_atp_partial():
    """ASVS V7.4.1 · CWE-754: an ATP list answering with a value that is not a settings object is a partial read, named."""
    out = zpm.read(ModuleTenant({"/zia/security": ("text", 200)}), FULL)
    assert out["atp"]["state"] == "partial" and "not a settings object" in out["atp"]["why"]


def test_a_module_read_is_stopped_between_requests():
    """ASVS V1.11.3 · CWE-400: Stop ends the module read between requests; nothing more is sent."""
    stop = threading.Event()

    class Stopper(Tenant):
        n = 0

        def get(self, ep, p=None):
            Stopper.n += 1
            stop.set()
            return super().get(ep, p)
    with pytest.raises(df.ReadStopped):
        zpm.read(Stopper(), FULL, cancel=stop)
    assert Stopper.n == 1


def test_an_atp_list_that_could_not_be_read_makes_atp_conditional():
    """ASVS V7.4.1 · CWE-754: an unread ATP list is an unknown check that could block: ATP is conditional, never a definite allow."""
    res = pa.analyze(ModuleTenant({"/zia/cyberThreatProtection/maliciousUrls": RuntimeError("timeout")}), "news.example", scope=FULL)
    m = mod(res, "atp")
    assert (m["verdict"], m["certainty"]) == ("allow", "conditional")


def test_atp_settings_that_could_not_be_read_make_the_module_unknown():
    """ASVS V7.4.1 · CWE-754: unreadable ATP settings (its primary read) make the whole module unknown, never "no threat"."""
    res = pa.analyze(ModuleTenant({"/zia/cyberThreatProtection/advancedThreatSettings": ({}, 403)}), "news.example", scope=FULL)
    m = mod(res, "atp")
    assert (m["verdict"], m["certainty"], m["status"]) == ("unknown", "unknown", "unread") and "HTTP 403" in m["detail"]


def test_atp_settings_of_the_wrong_shape_make_the_toggles_unknown():
    """ASVS V5.1.3 · CWE-1287 · CWE-754: ATP settings that are not an object make the category toggles an unknown check: conditional, named."""
    res = pa.analyze(ModuleTenant({"/zia/cyberThreatProtection/advancedThreatSettings": ([], 200)}), "news.example", scope=FULL)
    m = mod(res, "atp")
    assert (m["verdict"], m["certainty"]) == ("allow", "conditional") and any("could not be read" in n for n in m["notes"])


@pytest.mark.parametrize("settings,cats,verdict", [
    ({"malwareSitesBlocked": True}, ["MALWARE_SITE"], "block"),
    ({"malwareSitesBlocked": False}, ["MALWARE_SITE"], "allow"),
    ({"cmdCtlServerBlocked": True}, ["BOTNET"], "block"),
    ({"blockedCountries": ["COUNTRY_KP"], "riskTolerance": 30}, ["NEWS"], "allow"),
])
def test_atp_toggles_block_their_categories(settings, cats, verdict):
    """ASVS V4.1.3 · CWE-697: an ATP category toggle blocks the lookup categories it covers (assumed mapping); blocked countries stay unknown."""
    res = pa.analyze(Tenant({"/zia/cyberThreatProtection/advancedThreatSettings": settings}, lookup={"x.example": cats}), "x.example", scope=FULL)
    m = mod(res, "atp")
    assert m["verdict"] == verdict
    if "blockedCountries" in settings:
        assert m["certainty"] == "conditional" and any("risk tolerance" in n for n in m["notes"])


@pytest.mark.parametrize("start,end,words", [
    (0, 86400, "from 1970-01-01 00:00 to 1970-01-02 00:00 (UTC)"),
    ("x", 10 ** 20, "from an unknown time to an unknown time (UTC)"),
])
def test_a_validity_period_is_named_in_utc_and_a_bad_time_is_unknown(start, end, words):
    """ASVS V5.1.3 · CWE-20 · CWE-190: a URL rule's validity period is named in UTC; a time that is not a time is "an unknown time", never a crash."""
    assert zpm.validity({"enforceTimeValidity": True, "validityStartTime": start, "validityEndTime": end}) == words
    assert zpm.validity({"validityStartTime": start}) is None


@pytest.mark.parametrize("protocol,port", [("icmp", None), ("tcp", 0), ("tcp", 65536), ("tcp", True), ("tcp", "22a"), ("tcp", 2.5)])
def test_a_protocol_or_port_that_is_not_one_is_refused_in_words(protocol, port):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: only TCP and UDP, and a whole port 1-65535, are taken; anything else is refused in words."""
    with pytest.raises(ValueError, match="protocol must be TCP or UDP|port must be a whole number"):
        zpm.traffic_context(pa.parse_destination("a.example"), protocol, port)


@pytest.mark.parametrize("protocol,port,label,web", [("udp", "443", "UDP/443 (QUIC (HTTP/3 over UDP))", False), ("tcp", 8443.0, "TCP/8443 (HTTPS on 8443)", True),
                                                     ("udp", None, "UDP/443 (QUIC (HTTP/3 over UDP))", False)])
def test_a_port_given_as_text_or_a_whole_float_is_taken(protocol, port, label, web):
    """ASVS V5.1.3 · CWE-20: a port as digits or as a whole number in a float is taken; a protocol without a port assumes 443."""
    t = zpm.traffic_context(pa.parse_destination("a.example"), protocol, port)
    assert (t["label"], t["web"]) == (label, web)


def test_a_host_name_that_cannot_be_encoded_is_refused():
    """ASVS V5.1.3 · CWE-20 · CWE-176: an internationalised name that IDNA refuses is refused in words."""
    with pytest.raises(ValueError, match="not a valid internationalised host name"):
        zpm.ascii_host("a‍‍.example" + "ß" * 70)


# ═══ 11. What-if identities (path_whatif) ═══════════════════════════════
@pytest.mark.parametrize("raw,label", [
    ({"user": {"id": 7, "name": "Ada", "email": "ada@example.com"}}, "user Ada"),
    ({"group": "Finance, Sales,  "}, "group Finance, Sales"),
    ({"groups": [{"id": "x" * 41, "name": "Ops"}, None, 5]}, "group Ops"),
    ({"department": " ", "location": {"id": 3}}, "location "),
    ({"user": None}, ""),
    ("not a dict", ""),
])
def test_a_what_if_identity_is_normalised_and_bounded(raw, label):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: an identity as sent is normalised (names trimmed, an id over 40 characters dropped); nothing given is none."""
    assert pw.describe(pw.normalize_identity(raw)) == label


@pytest.mark.parametrize("item,val,user,same", [
    ({"name": "Ada Lovelace (ada@example.com)"}, {"name": "x", "email": "ada@example.com"}, True, True),
    ({"name": "ada@example.com"}, {"name": "ada@example.com"}, True, True),
    ({"id": 5, "name": "A"}, {"id": "5", "name": "B"}, False, True),
    ({"name": ""}, {"name": ""}, False, False),           # empty names never match
])
def test_a_what_if_user_is_matched_by_id_name_or_login(item, val, user, same):
    """ASVS V4.1.3 · CWE-863 · CWE-697: a rule's user matches by id, by name or by the login ZIA shows in parentheses; empty names never match."""
    assert pw._same(item, val, user) is same


def test_a_what_if_search_reaches_only_its_endpoint_and_caps_the_answer():
    """ASVS V5.1.3 · CWE-400 · CWE-918: an identity search is one GET to its fixed endpoint, answers capped at SEARCH_LIMIT."""
    class Users:
        def __init__(self):
            self.calls = []

        def get(self, ep, params=None):
            self.calls.append((ep, dict(params)))
            return {"list": [{"id": i, "name": f"U{i}", "department": {"id": 1, "name": "D"}, "groups": [{"id": 2, "name": "G"}, "junk"]}
                             for i in range(30)] + ["junk"]}, 200
    c = Users()
    out = pw.search_identities(c, "user", "  ad  ")
    assert c.calls == [("/zia/users", {"name": "ad", "page": 1, "pageSize": pw.SEARCH_LIMIT})]
    assert out["capped"] and len(out["results"]) == pw.SEARCH_LIMIT and out["results"][0]["groups"] == [{"id": 2, "name": "G"}]


@pytest.mark.parametrize("client,err", [
    (type("E", (), {"get": lambda self, *a: (_ for _ in ()).throw(RuntimeError("secret-token-xyz"))})(), "the lookup failed (RuntimeError)"),
    (type("H", (), {"get": lambda self, *a: ({}, 403)})(), "ZIA answered HTTP 403"),
])
def test_a_what_if_search_that_fails_says_why_without_the_exception_text(client, err):
    """ASVS V7.4.1 · CWE-209 · CWE-532: a failed search says why in words and never repeats the exception's text."""
    out = pw.search_identities(client, "group", "fin")
    assert out["error"] == err and "secret" not in str(out)


def test_a_what_if_search_refuses_an_unknown_kind_or_a_bad_query():
    """ASVS V5.1.3 · CWE-20: a search kind outside the list, or a query outside 2-64 printable characters, is refused in words."""
    with pytest.raises(ValueError, match="Search for one of"):
        pw.search_identities(Tenant(), "admin", "ab")
    with pytest.raises(ValueError, match="Type 2 to 64"):
        pw.search_identities(Tenant(), "user", "a\x00b")


def test_a_rule_scoped_only_by_its_counted_scope_is_undecided():
    """ASVS V4.1.3 · CWE-754: a rule read before its scope was itemised depends on the identity (unknown), never applies to everyone."""
    state, crit = pw.rule_criteria({"scope": ["2 groups"], "scoped": True}, pw.normalize_identity({"group": "Finance"}))
    assert state is None and crit[0]["state"] == "unknown"


def test_depends_on_ranks_blocking_changes_first_and_skips_same_action():
    """ASVS V4.1.3 · CWE-697: the conditions the action depends on are ranked blocking first; a scoped rule with the same action is not listed."""
    zia = {"url": [dict(df._norm_generic(url_rule(1, 1, "CAUTION", ["NEWS"], groups=[{"id": 1, "name": "G1"}]))),
                   dict(df._norm_generic(url_rule(2, 2, "BLOCK", ["NEWS"], groups=[{"id": 2, "name": "G2"}]))),
                   dict(df._norm_generic(url_rule(3, 3, "ALLOW", ["NEWS"], groups=[{"id": 3, "name": "G3"}]))),
                   dict(df._norm_generic(url_rule(4, 4, "ALLOW", ["NEWS"])))]}
    deps = pw.depends_on(zia, {"categories": ["NEWS"], "applications": [], "app_classes": []})
    assert [d["rule"]["name"] for d in deps] == ["URL 2", "URL 1"] and deps[0]["otherwise"] == "ALLOW"


# ═══ 12. Test a list: parsing, lookups, recommendations ═════════════════
@pytest.mark.parametrize("line,why", [
    ("10.0.0.0/33", "not a valid CIDR block"),
    ("10.0.0.5-300", "last octet is over 255"),
    ("10.0.0.5-10.0.0.1", "ends before it starts"),
    ("10.0.0.5-banana", "end is not an IP address"),
    ("10.0.0.0/15", "at most 65,536"),
])
def test_a_list_line_that_is_a_bad_block_or_range_is_skipped_with_its_reason(line, why):
    """ASVS V5.1.3 · CWE-20 · CWE-400: a malformed or too-large block or range is skipped with the reason; the rest of the list is read."""
    p = bt.parse(f"{line}\nok.example\n")
    assert len(p) == 1 and why in p.skipped[0]["why"]


def test_a_list_with_a_header_reads_every_column_and_notes_what_it_ignores():
    """ASVS V5.1.3 · CWE-20: the header's aliases name the columns; a bad port, protocol, source, category or expectation is noted, not fatal."""
    p = bt.parse("Dest;Port;Proto;Src IP;Category;Expected;User\n"
                 "a.example;99999;smtp;nope;bad cat!;maybe;ada\n"
                 "b.example;80;http;10.0.0.1;gambling;block;\n")
    a, b = p.entries
    assert set(p.columns) >= {"destination", "port", "protocol", "source_ip", "category", "expected", "user"}
    assert "port" not in a and "protocol" not in a and "source_ip" not in a and len(a["notes"]) == 4 and a["user"] == "ada"
    assert a["category"] == ("BAD",)   # "bad cat!" splits into words; BAD is a valid category id, CAT! is not
    assert (b["port"], b["protocol"], b["source_ip"], b["category"], b["expected"]) == (80, "TCP", "10.0.0.1", ("GAMBLING",), "BLOCK")


def test_a_list_that_is_not_text_or_names_nothing_is_refused_in_words():
    """ASVS V5.1.3 · CWE-20: a list that is not text, or has no destination, is refused with a plain sentence."""
    with pytest.raises(bt.ListError, match="Send the list as text"):
        bt.parse(b"a.example")
    with pytest.raises(bt.ListError, match="names no destination"):
        bt.parse("destination,port\n,80\n# comment\n")


class LookupClient(Tenant):
    """POST /urlLookup with a scripted list of (status, body) answers."""

    def __init__(self, script):
        super().__init__()
        self.script, self.posts = list(script), []

    def post(self, ep, body=None):
        self.posts.append(list(body))
        st, data = self.script.pop(0) if self.script else (200, None)
        if isinstance(st, Exception):
            raise st
        if data is None:
            data = [{"url": h, "urlClassifications": ["NEWS"]} for h in body]
        return data, st


@pytest.mark.parametrize("script,kind,looked_up", [
    ([(429, {"error": "hourly quota exceeded"})], "quota", 0),
    ([(429, {}), (429, {}), (429, {}), (429, {})], "quota", 0),
    ([(403, {})], "denied", 0),
    ([(200, None), (403, {}), (403, {}), (403, {}), (403, {})], "quota", 100),
    ([(500, {}), (200, None), (200, None)], None, 150),
])
def test_the_list_lookup_waits_retries_and_stops_on_quota_with_injected_sleep(script, kind, looked_up):
    """ASVS V1.11.3 · CWE-400 · CWE-770: 429s, quota and refusals are waited out on an injected clock and end with "rerun later", never invented categories."""
    waits = []
    out, state = bt.lookup_all(LookupClient(script), [f"h{i}.example" for i in range(150)], sleep=waits.append)
    assert state["stopped_kind"] == kind and state["looked_up"] == looked_up and len(out) == 150
    assert all(v["error"] for v in out.values() if not v["categories"])


def test_a_bad_entry_in_a_lookup_chunk_is_found_by_halving():
    """ASVS V5.1.3 · CWE-20: a 400 for a chunk is split until the one entry ZIA refuses is found; every other entry is looked up."""
    class Picky(LookupClient):
        def post(self, ep, body=None):
            self.posts.append(list(body))
            if "bad.example" in body:
                return {"error": "invalid url"}, 400
            return [{"url": h, "urlClassifications": ["NEWS"]} for h in body], 200
    out, state = bt.lookup_all(Picky([]), ["a.example", "bad.example", "c.example", "d.example"], sleep=lambda s: None)
    assert out["bad.example"]["error"].startswith("the URL lookup answered HTTP 400") and state["looked_up"] == 3


def test_the_list_lookup_cap_marks_the_rest_rerun_later():
    """ASVS V1.11.3 · CWE-770: the run's request cap ends the lookups; the rest are labelled "rerun later"."""
    out, state = bt.lookup_all(LookupClient([]), [f"h{i}.example" for i in range(250)], max_requests=2, sleep=lambda s: None)
    assert state["stopped_kind"] == "cap" and state["not_looked_up"] == 50 and out["h249.example"]["error"] == bt.CAP_LABEL


@pytest.mark.parametrize("row,area", [
    ({"expected": "BLOCK", "result": "allowed", "category": "PHISHING"}, "ATP"),
    ({"expected": "BLOCK", "result": "allowed", "category": "NEWLY_REG_DOMAINS"}, "URL"),
    ({"expected": "BLOCK", "result": "allowed", "application": "DROPBOX"}, "Cloud App"),
    ({"expected": "BLOCK", "result": "allowed", "is_ip": True}, "Firewall"),
    ({"expected": "BLOCK", "result": "allowed", "protocol": "UDP"}, "DNS"),
    ({"expected": "BLOCK", "result": "allowed", "area": "Firewall", "blockable_by": "R1"}, "Firewall"),
    ({"expected": "BLOCK", "result": "bypassed", "private": True}, "Client Connector"),
    ({"expected": "ALLOW", "result": "blocked", "area": "DNS"}, "DNS"),
    ({"expected": "ALLOW", "result": "blocked", "area": "Cloud App"}, "Cloud App"),
    ({"expected": "ALLOW", "result": "blocked", "security_alert": "PHISHING"}, "ATP"),
    ({"expected": "ALLOW", "result": "caution", "area": "URL"}, "URL"),
])
def test_the_recommended_area_follows_the_deciding_module(row, area):
    """ASVS V1.4.4 · CWE-697: a row that misses its expectation is sent to the module that decided it (ATP, URL, Cloud App, Firewall, DNS, Client Connector)."""
    meets, got, text = bt.recommend(row)
    assert (meets, got) == ("no", area) and text


def test_fix_selected_takes_only_rows_of_this_run_and_areas_with_a_custom_category():
    """ASVS V4.1.3 · CWE-20 · CWE-841: Fix selected takes row numbers of this run only and refuses areas not changed through a URL category; it writes nothing."""
    rn = bt.run(Tenant(), bt.parse("a.example,block\n10.0.0.1,block\n"), scope=FULL, lookup=False, sleep=lambda s: None)
    with pytest.raises(bt.ListError, match="not a row of this run"):
        bt.fix_handoff(rn, rows=[3])
    with pytest.raises(bt.ListError, match="not a row of this run"):
        bt.fix_handoff(rn, rows=[True])
    with pytest.raises(bt.ListError, match="is not changed through a custom URL category"):
        bt.fix_handoff(rn, area="firewall")
    with pytest.raises(bt.ListError, match="Unknown area"):
        bt.fix_handoff(rn, area="moon")
    rec = bt.fix_handoff(rn, rows=[1, 1], now=1000.0)
    assert rec["urls"] == ["a.example"] and bt.get_fix(rec["id"], now=1000.0 + bt.FIX_KEEP_SECONDS + 1) is None
    assert bt.get_fix("../" + rec["id"]) is None


def test_the_list_exports_neutralise_formulas():
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-13: a destination label starting with = is written as text in the CSV, never a formula."""
    rn = bt.run(Tenant(), bt.parse("destination,label\na.example,=HYPERLINK(\"http://x\")\n"), scope=FULL, lookup=False, sleep=lambda s: None)
    body = "".join(bt.csv_lines(rn))
    assert ",=HYPERLINK" not in body and "'=HYPERLINK" in body
    data, cut = bt.workbook(rn)
    assert data[:2] == b"PK" and cut is False


def test_icmp_and_any_rows_are_noted():
    """ASVS V1.4.4 · CWE-754: an ICMP row is not traced (said in words); a row for protocol any is traced as TCP and noted."""
    rn = bt.run(Tenant(), bt.parse("destination,protocol\na.example,icmp\nb.example,any\n"), scope=FULL, lookup=False, sleep=lambda s: None)
    a, b = rn.row(0), rn.row(1)
    assert a["result"] == "unverified" and bt.ICMP_NOTE in a["notes"] and bt.ANY_NOTE in b["notes"]


# ── C6-PATH-14: an app profile scoped to groups or users ───────────────
def _profiles(*profiles):
    base = {"active": True, "forwardingProfileId": 5, "strictEnforcement": True, "installEndpointDlp": True, "sslCertInstall": True, "os": "windows"}
    return {"/zcc/webPolicies": [dict(base, **p) for p in profiles]}


def test_a_platform_whose_only_app_profile_is_for_one_group_is_unverified_for_any_user():
    """ASVS V4.1.3 · CWE-863 · CWE-754: the only app profile of a platform applies to one group; for any user how the device reaches ZIA is not verified."""
    res = run("files.example", _profiles({"id": 1, "name": "Drivers", "ruleOrder": 1, "groups": [{"id": 32, "name": "Drivers"}]}))
    zcc = hop(res, "zcc")
    assert zcc["status"] == "conditional" and "applies to group Drivers" in zcc["detail"] and "no windows app profile" in zcc["detail"]
    assert res["verdict"]["outcome"] == "unknown" and res["verdict"]["headline"].startswith("Unable to verify how the device reaches")


def test_a_scoped_profile_ahead_that_bypasses_the_destination_makes_it_depend_on_the_user():
    """ASVS V4.1.3 · CWE-863: a group's profile ahead of the everyone profile that bypasses this destination makes the path depend on the user."""
    res = run("files.example", _profiles({"id": 1, "name": "Contractors", "ruleOrder": 1, "users": [{"id": 9, "name": "ada"}],
                                          "hostnameBypassForIpv4": ["files.example"]},
                                         {"id": 2, "name": "Corp", "ruleOrder": 2}))
    zcc = hop(res, "zcc")
    assert zcc["status"] == "conditional" and "everyone else gets 'Corp'" in zcc["detail"]
    assert [c["name"] for c in zcc["candidate_rules"]] == ["Contractors", "Corp"] and df.visibility(res["trace"]) == "unverified"


def test_a_scoped_profile_ahead_that_treats_the_destination_alike_changes_nothing():
    """ASVS V4.1.3 · CWE-697: a scoped profile that forwards this destination as the everyone profile does leaves the answer definite."""
    res = run("files.example", _profiles({"id": 1, "name": "Contractors", "ruleOrder": 1, "groups": [{"id": 32, "name": "Drivers"}],
                                          "hostnameBypassForIpv4": ["other.example"]},
                                         {"id": 2, "name": "Corp", "ruleOrder": 2}))
    assert (hop(res, "zcc")["status"], hop(res, "zcc")["decided_by"]["name"]) == ("pass", "Corp") and res["verdict"]["outcome"] == "enforce"


def test_a_scoped_profile_after_the_everyone_profile_never_decides():
    """ASVS V4.1.3 · CWE-697: a scoped profile ordered after the everyone profile is shadowed; the everyone profile decides."""
    res = run("files.example", _profiles({"id": 2, "name": "Corp", "ruleOrder": 1},
                                         {"id": 1, "name": "Contractors", "ruleOrder": 2, "groups": [{"id": 32, "name": "Drivers"}],
                                          "hostnameBypassForIpv4": ["files.example"]}))
    assert (hop(res, "zcc")["status"], hop(res, "zcc")["decided_by"]["name"]) == ("pass", "Corp")


def test_a_kept_read_from_before_profiles_carried_users_still_traces():
    """Regression · ASVS V5.1.3 · CWE-1287: a kept Client Connector read whose app profiles have no users key traces as before."""
    res = run("files.example")
    snap = copy.deepcopy(res["snapshot_for_cache"])
    for p in snap["client_connector"]["app_profiles"]:
        p.pop("users", None)
    again = pa.analyze(Tenant(), "files.example", scope=FULL, snapshot=snap)
    assert again["verdict"]["outcome"] == res["verdict"]["outcome"] == "enforce"


# ═══ 13. Client Connector reads and forwarding actions (data_flow) ══════
@pytest.mark.parametrize("profile,want", [
    ({"forwardingProfileActions": [{"networkType": "ON_TRUSTED_NETWORK", "actionType": "1", "enablePacketTunnel": True}]},
     {"on": "Z-Tunnel 2.0"}),                                                     # Z-Tunnel 1.0 code with packet tunnel on is 2.0
    ({"forwardingProfileActions": [{"networkType": "2", "actionType": "4"}, {"networkType": "0", "actionType": "0"}]},
     {"vpn": "Z-Tunnel 2.0", "off": "None (direct)"}),                             # numeric codes
    ({"enableUnifiedTunnel": True, "unifiedTunnel": [{"networkType": "OFF_TRUSTED_NETWORK", "actionTypeZIA": "ENFORCE_PROXY"}],
      "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"}]}, {"off": "Enforce proxy (PAC)"}),
    ({"enableUnifiedTunnel": False, "unifiedTunnel": [{"networkType": "OFF_TRUSTED_NETWORK", "actionTypeZIA": "ENFORCE_PROXY"}],
      "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"}]}, {"off": "None (direct)"}),
    ({"forwardingProfileZpaActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "NONE"}]}, {}),   # the ZPA list never decides ZIA
    ({"forwardingProfileActions": [{"networkType": "ON_TRUSTED_NETWORK", "proxyAction": "Tunnel with local proxy"}]},
     {"on": "Tunnel with local proxy"}),                                          # a mode read from an unnamed field
    ({"forwardingProfileActions": [{"networkType": "ON_TRUSTED_NETWORK", "dnsTimeout": 5}]}, {}),             # no mode at all: skipped
    ({"tunnelMode": "Z-Tunnel 1.0"}, {"any": "Z-Tunnel 1.0"}),                     # one mode for every network
    ({"tunnelMode": "warp drive"}, {}),
])
def test_forwarding_profile_actions_oracle(profile, want):
    """ASVS V5.1.3 · CWE-20 · CWE-697: each forwarding profile shape gives the mode per network (codes, unified tunnel, ZPA list ignored)."""
    got = {k: v["mode_label"] for k, v in df.forwarding_actions(profile).items()}
    assert got == want


@pytest.mark.parametrize("raw,mode", [("", ("not set", "unknown")), (None, ("not set", "unknown")), ("xyz", ("unknown (xyz)", "unknown")),
                                      ("3", ("Tunnel with local proxy", "tunnel")), ("ZSCALER_TUNNEL_1", ("Z-Tunnel 1.0", "tunnel"))])
def test_a_forwarding_mode_is_named_or_unknown(raw, mode):
    """ASVS V5.1.3 · CWE-20: a forwarding mode the tool does not know is "unknown (value)", never taken for a tunnel."""
    assert df.classify_mode(raw) == mode


@pytest.mark.parametrize("raw,net", [("2", "vpn"), ("TRUSTED", "on"), ("untrusted wifi", "off"), (None, "any"), ("??", "any")])
def test_a_network_type_is_named_or_any(raw, net):
    """ASVS V5.1.3 · CWE-20: a network type is on, off, vpn or (unknown) any."""
    assert df.classify_network(raw) == net


class ZccTenant(Tenant):
    def __init__(self, routes, fail=()):
        super().__init__(routes)
        self.fail = set(fail)

    def get(self, ep, p=None):
        if ep in self.fail:
            raise RuntimeError(f"{ep} timed out")
        return super().get(ep, p)


def test_the_client_connector_read_records_every_failure_and_keeps_raw_only_when_asked():
    """ASVS V7.4.1 · CWE-755 · CWE-209: a failed Client Connector list is recorded, never raised; raw profiles are kept only when asked."""
    routes = {"/zcc/webPolicies": [{"id": 1, "name": "Win", "deviceType": "DEVICE_TYPE_WINDOWS", "active": 1, "ruleOrder": 1,
                                    "vpnGateways": ["vpn.example"], "bypassProcesses": ["a.exe"], "bypassApps": [{"name": "Zoom"}],
                                    "ipExclusions": [{"ip": "10.0.0.0/8"}], "groups": [{"id": 1, "name": "All"}]}],
              "/zcc/forwardingProfiles": [{"id": 5, "name": "Fwd"}], "/zcc/trustedNetworks": [{"id": 1, "networkName": "HQ", "dnsServers": "10.0.0.1"}, 7]}
    out = df.read_client_connector(ZccTenant(routes), keep_raw=True)
    p = out["app_profiles"][0]
    assert p["platform"] == "windows" and p["bypass"]["vpn_gateways"] == ["vpn.example"] and p["bypass"]["processes"] == ["a.exe"]
    assert p["bypass"]["apps"] == ["Zoom"] and p["bypass"]["ips"] == ["10.0.0.0/8"] and "raw" in p and "raw" in out["forwarding_profiles"][0]
    assert out["trusted_networks"] == [{"id": 1, "name": "HQ", "conditions": {"dnsServers": "10.0.0.1"}}]
    failing = df.read_client_connector(ZccTenant(routes, fail={"/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/trustedNetworks", "/zia/pacFiles"}))
    assert failing["read_status"] == {"app_profiles": "unverified", "forwarding_profiles": "unverified"}
    assert len(failing["errors"]) >= 4 and all("timed out" in e for e in failing["errors"])


def test_a_forwarding_profile_list_that_answers_an_error_is_unverified():
    """ASVS V7.4.1 · CWE-754: a forwarding profile list answering an HTTP error is unverified with the status, never an empty list."""
    class Err(Tenant):
        def get(self, ep, p=None):
            return ({"error": "denied"}, 403) if ep in ("/zcc/forwardingProfiles", "/zia/pacFiles") else super().get(ep, p)
    out = df.read_client_connector(Err())
    assert out["read_status"]["forwarding_profiles"] == "unverified" and "/zcc/forwardingProfiles: HTTP 403 (denied)" in out["errors"]
    assert out["read_status"]["pac_files"] == "unverified"


def test_the_client_connector_read_is_stopped_between_requests():
    """ASVS V1.11.3 · CWE-400: Stop ends the Client Connector read before the next request."""
    stop = threading.Event()

    class Stopper(Tenant):
        calls = []

        def get(self, ep, p=None):
            Stopper.calls.append(ep)
            stop.set()
            return super().get(ep, p)
    with pytest.raises(df.ReadStopped):
        df.read_client_connector(Stopper(), cancel=stop)
    assert len({c.split("?")[0] for c in Stopper.calls}) == 1


@pytest.mark.parametrize("cancel,stopped", [(None, False), (lambda: True, True), (lambda: 1 / 0, False), (threading.Event(), False)])
def test_stop_requested_takes_an_event_or_a_callable_and_a_broken_hook_never_stops(cancel, stopped):
    """ASVS V1.11.3 · CWE-755: Stop is an Event or a callable; a hook that raises never stops a read by itself."""
    assert df.stop_requested(cancel) is stopped


def test_stop_on_binds_and_restores_the_clients_stop_hook():
    """ASVS V1.11.3 · CWE-664: while a read runs the client's stop hook is the operator's Stop; it is put back afterwards, even for a client without one."""
    class C:
        stop_check = "before"
    c, stop = C(), threading.Event()
    with df.stop_on(c, stop):
        stop.set()
        assert c.stop_check() is True
    assert c.stop_check == "before"

    class Frozen:
        __slots__ = ()
    with df.stop_on(Frozen(), stop):
        pass


@pytest.mark.parametrize("pack_channel,rule,state", [
    ("ssl", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["ANY"]}, "enforcing"),
    ("ssl", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["ANY"]}, "monitoring"),
    ("cloud_app", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "actions": ["BLOCK_FILE_SHARE_UPLOAD"], "applications": ["DROPBOX"]}, "enforcing"),
    ("cloud_app", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "actions": ["ALLOW_FILE_SHARE_UPLOAD"], "applications": ["DROPBOX"]}, "monitoring"),
    ("url", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "action": "CAUTION", "urlCategories": ["NEWS"]}, "enforcing"),
    ("url", {"id": 1, "name": "P", "order": 1, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["NEWS"]}, "monitoring"),
    ("url", {"id": 1, "name": "P", "order": 1, "state": "DISABLED", "action": "BLOCK", "urlCategories": ["NEWS"]}, "disabled"),
    ("file_type", {"id": 1, "name": "Q", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK"}, "missing"),
])
def test_the_policy_pack_overlay_names_each_rules_state(pack_channel, rule, state):
    """ASVS V1.4.4 · CWE-697: each policy pack rule is enforcing, monitoring, disabled or missing, by its channel's own action."""
    section = {"ssl": "/zia/sslInspectionRules", "cloud_app": "/zia/cloudApplicationRules", "url": "/zia/urlFilteringRules",
               "file_type": "/zia/fileTypeRules"}[pack_channel]
    pack = [{"id": "p", "name": "Pack", "policies": [{"name": "P", "channel": pack_channel}]}]
    res = run("news.example", {section: [rule]}, packs=pack)
    assert res["trace"]["packs"][0]["rules"][0]["state"] == state


# ═══ 14. Test a list with ZPA in scope (bulk_test.PathEvaluator) ════════
def _zpa_in():
    from test_path_zpa_workloads import zpa_snap
    snap, prof = zpa_snap()
    return {"snapshot": snap, "profiles": prof}


def test_a_list_row_zpa_carries_is_answered_by_zpa_and_others_by_zia():
    """ASVS V4.1.3 · CWE-863: a row in a ZPA segment is answered by ZPA's access policy; a row in none goes on to ZIA."""
    parsed = bt.parse("destination\ngit.corp.example\nwiki.corp.example\nnews.example\n")
    rn = bt.run(Tenant(), parsed, scope=FULL, lookup=False, sleep=lambda s: None, zpa=_zpa_in())
    rows = [rn.row(i) for i in range(3)]
    assert [r["area"] for r in rows] == ["ZPA", "ZPA", "URL"] and rows[0]["segment"] == "Git" and rows[1]["segment"] == "Corp wildcard"
    assert rn.summary["zpa"]["state"] == "kept"


def test_a_list_with_zpa_that_cannot_be_read_says_so_once():
    """ASVS V7.4.1 · CWE-754: ZPA in scope but not readable is said once in the assumptions; rows go on to ZIA."""
    rn = bt.run(Tenant(), bt.parse("git.corp.example\n"), scope=FULL, lookup=False, sleep=lambda s: None,
                zpa={"problem": "ZPA is not reachable with this sign-in."})
    assert rn.row(0)["area"] != "ZPA" and "ZPA is not reachable with this sign-in." in rn.summary["assumptions"]


def test_a_list_reads_zpa_once_with_its_client_and_masks_a_read_error():
    """ASVS V7.4.1 · CWE-209 · CWE-532: a ZPA read error is masked before it is shown; the rows go on to ZIA."""
    import zpa_path

    class Broken:
        pass

    def boom(*a, **k):
        raise zpa_path.ReadError("token=abc123 refused")
    orig = zpa_path.read
    zpa_path.read = boom
    try:
        rn = bt.run(Tenant(), bt.parse("git.corp.example\n"), scope=FULL, lookup=False, sleep=lambda s: None,
                    zpa={"client": Broken(), "mask": lambda s: s.replace("abc123", "***")})
    finally:
        zpa_path.read = orig
    note = rn.summary["zpa"]["note"]
    assert "abc123" not in note and "***" in note and rn.row(0)["result"] == "allowed"


def test_a_list_with_only_zpa_in_scope_traces_no_zia():
    """ASVS V4.1.3 · CWE-284: with no ZIA part in scope a row ZPA does not carry is "not in scope", never traced through ZIA."""
    zpa_only = df.path_scope(["zpa"], {})
    rn = bt.run(Tenant(), bt.parse("news.example\n"), scope=zpa_only, lookup=False, sleep=lambda s: None, zpa=_zpa_in())
    assert rn.row(0)["result"] == "unverified" and bt.ZIA_NOT_IN_SCOPE in rn.row(0)["notes"]


def test_rows_sharing_a_source_condition_fingerprint_share_a_trace():
    """ASVS V1.11.3 · CWE-400 · CWE-697: rows whose source addresses relate alike to the firewall's source conditions share one trace."""
    tenant = Tenant({"/zia/firewallFilteringRules": [fw_rule(1, 1, "BLOCK_DROP", srcIps=["10.0.0.0/24"]), DEFAULT_FW]})
    parsed = bt.parse("destination,port,protocol,source ip\n203.0.113.5,22,tcp,10.0.0.1\n203.0.113.5,22,tcp,10.0.0.2\n203.0.113.5,22,tcp,10.0.1.1\n")
    rn = bt.run(tenant, parsed, scope=FULL, lookup=False, sleep=lambda s: None)
    assert [rn.row(i)["result"] for i in range(3)] == ["blocked", "blocked", "allowed"] and rn.summary["traced"] == 2


# ═══ 15. PAC refusals: every construct outside the subset is refused in words
@pytest.mark.parametrize("src,construct", [
    ('function FindProxyForURL(url, host) { return "x', "an unterminated string"),
    ('function FindProxyForURL(url, host) { var if = 1; return "DIRECT"; }', "the keyword 'if' used as a name"),
    ('function f() { return 1; } function f() { return 2; } function FindProxyForURL(u, h) { return "DIRECT"; }', "defined twice"),
    ('function FindProxyForURL(url, host) { return "DIRECT";', "a block that is never closed"),
    ('function FindProxyForURL(url, host) { if (x = 1) return "DIRECT"; }', "an assignment inside an expression"),
    ('function FindProxyForURL(url, host) { function g() {} return "DIRECT"; }', "a function defined inside another"),
    ('function FindProxyForURL(url, host) { return 1 == 1 == 1; }', "a chained comparison"),
    ('function FindProxyForURL(url, host) { return 1 < 2 < 3; }', "a chained comparison"),
    ('function FindProxyForURL(url, host) { return (host)("x"); }', "a call of a computed value"),
    ('function FindProxyForURL(url, host) { return url.foo(); }', "the property 'foo'"),
    ('function FindProxyForURL(url, host) { return url.foo; }', "the property 'foo'"),
    ('function FindProxyForURL(url, host) { return (1).length; }', "'.length' of a value that is not a string"),
    ('return "DIRECT"; function FindProxyForURL(url, host) { return "DIRECT"; }', "a return outside a function"),
    ('var x = 1;', "no function FindProxyForURL(url, host)"),
    ('function FindProxyForURL(url, host) { return 1 & 2; }', "could not evaluate safely"),
    ('function FindProxyForURL(url, host) { return ,; }', "unexpected ','"),
])
def test_a_pac_construct_outside_the_subset_is_refused_in_words(src, construct):
    """ASVS V5.2.4 · CWE-94 · CWE-95 · WSTG-INPV-11: a PAC construct outside the evaluated subset is refused "could not evaluate safely: ...", never run."""
    r = pac_eval.evaluate(src, "https://a.example/", "a.example")
    assert r["status"] == "error" and r["error"].startswith(pac_eval.PREFIX) and construct in r["error"]


@pytest.mark.parametrize("src,want", [
    ('function FindProxyForURL(url, host) { return true ? "DIRECT" : "PROXY x:1"; }', "DIRECT"),
    ('function FindProxyForURL(url, host) { return false ? "DIRECT" : "PROXY ${GATEWAY}:80"; }', "PROXY ${GATEWAY}:80"),
    ('var p = "PROXY "; function FindProxyForURL(url, host) { p += "${GATEWAY}:80"; return p; }', "PROXY ${GATEWAY}:80"),
    ('function FindProxyForURL(url, host) { alert("x"); var n = 3 % 2; if (n) return "DIRECT"; return "PROXY a:1"; }', "DIRECT"),
    ('function FindProxyForURL(url, host) { var s = "" + undefined; return s == "undefined" ? "DIRECT" : "PROXY a:1"; }', "DIRECT"),
    ('function FindProxyForURL(url, host) { return "" + (1 === 1.0) + (null === undefined); }', "truefalse"),
])
def test_pac_values_and_operators_answer_as_javascript_does(src, want):
    """ASVS V5.1.3 · CWE-682: ternaries, += on a global, %, alert (ignored), undefined and strict equality answer as JavaScript does."""
    r = pac_eval.evaluate(src, "https://a.example/", "a.example")
    assert r["status"] == "ok" and r["result"] == want


def test_a_pac_with_a_resolver_injected_uses_it_and_a_failing_resolver_is_not_resolvable():
    """ASVS V5.1.3 · CWE-918 · CWE-755: DNS is never looked up; an injected resolver answers, and one that raises means "not resolvable"."""
    src = 'function FindProxyForURL(url, host) { if (isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT"; return "PROXY ${GATEWAY}:80"; }'
    assert pac_eval.evaluate(src, "https://a.example/", resolve=lambda h: "10.1.2.3")["result"] == "DIRECT"
    assert pac_eval.evaluate(src, "https://a.example/", resolve=lambda h: 1 / 0)["result"] == "PROXY ${GATEWAY}:80"
    assert pac_eval.evaluate(src, "https://a.example/")["status"] == "depends"


@pytest.mark.parametrize("answer,kind,proxy,fallback", [
    ("PROXY [2001:db8::1]:8080; DIRECT", "other_proxy", "2001:db8::1:8080", True),
    ("PROXY gateway.zscalertwo.net:80", "zscaler", "gateway.zscalertwo.net:80", False),
    ("PROXY evilzscaler.net:80", "other_proxy", "evilzscaler.net:80", False),
    ("PROXY zscaler.net.evil.example:80", "other_proxy", "zscaler.net.evil.example:80", False),
    ("PROXY 127.0.0.1:9000", "zscaler", "127.0.0.1:9000", False),
    ("SOCKS5", "invalid", None, False),
    ("", "invalid", None, False),
])
def test_a_pac_answer_is_classified_by_its_first_entry(answer, kind, proxy, fallback):
    """ASVS V5.1.3 · CWE-697 · CWE-346: the first entry decides; a host only ending in a Zscaler name is another proxy; a later DIRECT is fail-open."""
    c = pac_eval.classify(answer)
    assert (c["kind"], c["proxy"], c["fallback_direct"]) == (kind, proxy, fallback)


# ═══ 16. Destinations that are not one (path_analyzer.parse_destination) ═
@pytest.mark.parametrize("typed", ["a::b::c", "‍‍.example"])
def test_an_ipv6_looking_or_unencodable_name_is_refused_in_words(typed):
    """ASVS V5.1.3 · CWE-20 · CWE-176: text with colons that is no IPv6 address, or a name IDNA cannot encode, is refused in words."""
    with pytest.raises(ValueError, match="not a URL, hostname or IP address"):
        pa.parse_destination(typed)


def test_a_conditional_route_is_said_before_any_policy_answer():
    """ASVS V1.4.4 · CWE-754: when how the device reaches ZIA is not verified, the headline says so before any policy result."""
    t = {"hops": [], "outcome": "unknown", "reaches_zscaler": True, "decrypted": False, "destination": {}, "channels": {}, "conditional": True}
    v = pa.derive_verdict(t, {"host": "a.example"}, {"security_alerts": []})
    assert v["headline"] == "Unable to verify how the device reaches a.example."


# ── C6-PATH-15: hostile shapes in tenant lists (fuzz, fixed seed) ──────
_JUNK = [None, "", 0, -1, 1.5, float("nan"), True, "x", "10.0.0.1-2001:db8::1", "::", "*", [], [None], [1, "a"], {}, {"id": None},
         {"name": 5}, [{"start": "a", "end": None}], [{"start": 10, "end": 5}], [{"id": {"x": 1}}], "ANY", ["ANY"], "2001:db8::/129",
         "300.1.1.1", ["*.example"], [".", "*.", "-"], "\U0001f642", ["\U0001f642"] * 3]


@pytest.mark.parametrize("field,value,go", [("srcIps", True, "drop"), ("destAddresses", 1.5, "drop"), ("srcIpGroups", True, "drop"),
                                            ("ecGroups", 7, "drop"), ("zpaAppSegments", {"name": "x"}, "drop"),
                                            ("srcWorkloadGroups", "Dev", "conditional"),   # one string is one item, never its letters
                                            ("srcIps", "10.0.0.1", "drop"), ("srcIps", "10.9.9.9", "zia")])
def test_a_connector_rule_list_field_of_the_wrong_type_is_no_list_not_a_crash(field, value, go):
    """ASVS V5.1.3 · CWE-20 · CWE-1287 · CWE-755: a forwarding rule list field that is a number, true or an object is no list; one string is one item."""
    snap = connector([fwd(1, 1, "Odd", "DROP", **{field: value})])
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("example.com"))["go"] == go


def test_connector_group_and_tag_lists_of_the_wrong_type_are_no_list():
    """ASVS V5.1.3 · CWE-20 · CWE-1287: workload groups, tag containers and IP group members of the wrong type are read as empty."""
    data = ztw_data([fwd(1, 1, "Src", "DROP", srcIpGroups=[{"id": 21, "name": "B"}])])
    data["workload_groups"] = [[{"id": 1, "name": "G", "expressionJson": {"expressionContainers": 5}},
                                {"id": 2, "name": "H", "expressionJson": {"expressionContainers": [{"tagContainer": {"tags": True}}]}}]]
    data["ip_source_groups"] = [[{"id": 21, "name": "B", "ipAddresses": 10}]]
    snap = ztw_snap(data)
    ev = wp.evaluate(snap, wl(ip="10.0.0.1", tags="Env=prod"), zp.destination("example.com"))
    assert ev["go"] == "conditional" and [g["state"] for g in ev["groups"]] == ["unknown", "nomatch"]


def _junk_rule(rng, fields):
    r = {"id": rng.randint(1, 9), "name": "R", "order": rng.randint(-2, 5), "state": "ENABLED",
         "action": rng.choice(["ALLOW", "BLOCK_DROP", "BLOCK", "REDIR_ZPA"])}
    for f in rng.sample(fields, rng.randint(1, 8)):
        r[f] = copy.deepcopy(rng.choice(_JUNK))
    return r


def test_fuzz_hostile_module_rules_never_crash_the_analyzer():
    """ASVS V5.1.3 · CWE-20 · CWE-1287 · CWE-755 · WSTG-INPV-01: 90 random tenants with wrong types in every firewall, DNS, Sandbox and ATP field never raise."""
    import random
    rng = random.Random(20261029)
    fields = ["destAddresses", "srcIps", "destIpGroups", "srcIpGroups", "nwServices", "nwServiceGroups", "nwApplications", "nwApplicationGroups",
              "destIpCategories", "destCountries", "order", "action", "state", "name", "id", "defaultRule", "predefined", "users", "timeWindows",
              "destIpv6Groups", "srcIpv6Groups", "protocols", "dnsRuleRequestTypes", "resCategories", "applications", "applicationGroups",
              "fileTypes", "urlCategories", "baRuleAction", "firstTimeEnable", "firstTimeOperation", "baPolicyCategories", "byThreatScore",
              "enforceTimeValidity", "validityStartTime", "validityEndTime", "accessControl", "excludedUsers"]
    for _ in range(90):
        routes = {"/zia/firewallFilteringRules": [_junk_rule(rng, fields) for _ in range(3)] + [DEFAULT_FW],
                  "/zia/firewallDnsRules": [_junk_rule(rng, fields) for _ in range(2)], "/zia/sandboxRules": [_junk_rule(rng, fields)],
                  "/zia/networkServices": [_junk_rule(rng, fields + ["destTcpPorts", "srcUdpPorts", "tag"])],
                  "/zia/networkServiceGroups": [dict(_junk_rule(rng, fields), services=rng.choice(_JUNK))],
                  "/zia/networkApplicationGroups": [dict(_junk_rule(rng, fields), networkApplications=rng.choice(_JUNK))],
                  "/zia/ipDestinationGroups": [dict(_junk_rule(rng, fields), addresses=rng.choice(_JUNK), ipCategories=rng.choice(_JUNK))],
                  "/zia/ipSourceGroups": [dict(_junk_rule(rng, fields), ipAddresses=rng.choice(_JUNK))],
                  "/zia/cyberThreatProtection/advancedThreatSettings": {"malwareSitesBlocked": rng.choice(_JUNK), "blockedCountries": rng.choice(_JUNK),
                                                                         "riskTolerance": rng.choice(_JUNK)},
                  "/zia/cyberThreatProtection/maliciousUrls": {"maliciousUrls": ["a.example", rng.choice(["10.0.0.1-10.0.0.9", "::1", "x/y"])]}}
        dest = rng.choice(["203.0.113.5", "2001:db8::5", "casino.example", "https://x.example/a", "10.0.0.5"])
        proto, port = rng.choice([(None, None), ("tcp", 22), ("udp", 53), ("udp", 443), ("tcp", 2222), ("tcp", 80)])
        res = pa.analyze(Tenant(routes), dest, scope=FULL, protocol=proto, port=port,
                         context={"source_ip": rng.choice(["10.0.0.1", "2001:db8::9", None]), "file_types": rng.choice([None, ["pdf"], [5]])})
        assert res["zia_modules"]["certainty"] in ("definite", "conditional")


def test_fuzz_hostile_connector_rules_never_crash_the_workload_evaluation():
    """ASVS V5.1.3 · CWE-20 · CWE-1287 · CWE-755: 300 random connector reads with wrong types in every forwarding rule field never raise."""
    import random
    rng = random.Random(20261030)
    fields = ["srcIps", "destAddresses", "srcIpGroups", "destIpGroups", "srcWorkloadGroups", "ecGroups", "zpaAppSegments", "zpaApplicationSegmentGroups",
              "proxyGateway", "zpaGateway", "wanSelection", "order", "state", "forwardMethod", "sourceIpGroupExclusion", "destCountries", "name"]
    for _ in range(300):
        rules = []
        for _ in range(3):
            r = fwd(rng.randint(1, 9), rng.randint(-2, 4), "R", rng.choice(["ZIA", "ZPA", "DIRECT", "DROP", "INVALID"]))
            for f in rng.sample(fields, rng.randint(1, 6)):
                r[f] = copy.deepcopy(rng.choice(_JUNK))
            rules.append(r)
        data = ztw_data(rules)
        data["workload_groups"] = [[{"id": 1, "name": "G", "expressionJson": rng.choice(_JUNK + [{"expressionContainers": [
            {"tagType": rng.choice(_JUNK), "tagContainer": rng.choice(_JUNK + [{"tags": rng.choice(_JUNK)}])}]}])}]]
        data["ip_source_groups"] = [[{"id": 21, "name": "B", "ipAddresses": rng.choice(_JUNK)}]]
        w = wp.workload_input({"ip": rng.choice(["10.0.0.1", "2001:db8::1", ""]), "tags": rng.choice(["Env=prod", "", "VPC:a=b"]),
                               "workload_group": rng.choice(["", "G"]), "connector_group": rng.choice(["", "x"])})
        d = zp.destination(rng.choice(["example.com", "10.0.0.5", "2001:db8::5", "100.64.0.1"]), "443")
        seg = rng.choice([None, {"id": "s1", "name": "Git", "segment_group_id": None, "segment_group_name": None}])
        ev = wp.evaluate(ztw_snap(data), w, d, seg, rng.random() < 0.5)
        assert ev["go"] in ("zia", "zpa", "direct", "local", "proxy", "drop", "conditional", "unknown")


# ── C6-PATH-16: app profile order and proxy data from the API ──────────
@pytest.mark.parametrize("orders,decides", [
    (["10", "9"], "P9"),          # numbers sent as text sort as numbers, not as text ("10" < "9")
    (["1", 2], "P1"),             # text and a number together: no TypeError
    ([[], 3], "P3"),              # an order that is not a number sorts last
    ([{"x": 1}, True], "P{'x': 1}"),
])
def test_app_profiles_are_ordered_by_their_rule_order_as_numbers(orders, decides):
    """ASVS V5.1.3 · CWE-1287 · CWE-697: app profiles sort by ruleOrder as a number; an order of the wrong type sorts last and never crashes."""
    profiles = [{"id": i + 1, "name": f"P{o}", "ruleOrder": o} for i, o in enumerate(orders)]
    res = run("files.example", _profiles(*profiles))
    assert hop(res, "zcc")["decided_by"]["name"] == decides


@pytest.mark.parametrize("proxy", ["x", 5, ["a"]])
def test_system_proxy_data_that_is_not_an_object_is_ignored(proxy):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: a forwarding action's systemProxyData that is not an object is ignored, never an AttributeError."""
    acts = df.forwarding_actions({"forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "actionType": "ENFORCE_PROXY",
                                                                "systemProxyData": proxy, "customPac": "https://pac.example/p.pac"}]})
    assert acts["off"]["mode_label"] == "Enforce proxy (PAC)" and acts["off"]["pac_url"] == "https://pac.example/p.pac"


# ── C6-PATH-17: a URL lookup answer of the wrong shape ─────────────────
class OddLookup:
    def __init__(self, cats, alerts=None, app=None):
        self.cats, self.alerts, self.app = cats, alerts, app

    def post(self, ep, body):
        return [{"url": h, "urlClassifications": self.cats, "urlClassificationsWithSecurityAlert": self.alerts, "application": self.app}
                for h in body], 200


@pytest.mark.parametrize("cats,alerts,app,want", [
    (5, None, None, ([], [], None)),                                  # a number is no list: never a TypeError
    ("NEWS", "PHISHING", "gmail", (["NEWS"], ["PHISHING"], "GMAIL")),  # one string is one category, never its letters
    ([{"x": 1}, "news", None], [], {"id": 1}, (["NEWS"], [], None)),  # an object inside the list is skipped
])
def test_a_url_lookup_answer_of_the_wrong_shape_is_read_defensively(cats, alerts, app, want):
    """ASVS V5.1.3 · CWE-20 · CWE-1287 · CWE-755: every URL lookup parser (single, batch, list) reads categories of the wrong type as none, never crashes."""
    c = OddLookup(cats, alerts, app)
    single = pa.lookup_categories(c, "a.example")
    batch = pa.lookup_many(c, ["a.example"])["a.example"]
    listed = bt.lookup_all(c, ["a.example"], sleep=lambda s: None)[0]["a.example"]
    for got in (single, batch):
        assert (got["categories"], got["security_alerts"], got["application"]) == want
    assert (listed["categories"], listed["security_alerts"]) == want[:2]


# ── C6-PATH-18: 5,000 firewall rules on service and destination groups ─
def test_5000_firewall_rules_on_shared_groups_analyze_in_under_two_seconds():
    """ASVS V1.11.3 · CWE-400 · CWE-1176 · CWE-407: 5,000 firewall rules on 500 service groups (2,000 services) and 500 destination groups take under 2 s."""
    # Arrange
    svcs = [{"id": i, "name": f"S{i}", "destTcpPorts": [{"start": 1000 + i}]} for i in range(2000)]
    groups = [{"id": 10000 + g, "name": f"G{g}", "services": [{"id": (g * 10 + k) % 2000} for k in range(10)]} for g in range(500)]
    dgroups = [{"id": 20000 + g, "name": f"D{g}", "addresses": [f"10.{g % 250}.{k}.0/24" for k in range(20)]} for g in range(500)]
    rules = [fw_rule(i, i + 1, "ALLOW", nwServiceGroups=[{"id": 10000 + i % 500}], destIpGroups=[{"id": 20000 + i % 500}],
                     users=[{"id": 1, "name": "u"}]) for i in range(5000)] + [DEFAULT_FW]
    tenant = Tenant({"/zia/firewallFilteringRules": rules, "/zia/networkServices": svcs, "/zia/networkServiceGroups": groups,
                     "/zia/ipDestinationGroups": dgroups})
    # Act
    t0 = time.perf_counter()
    res = pa.analyze(tenant, "10.1.2.3", scope=FULL, protocol="tcp", port=1005)
    took = time.perf_counter() - t0
    # Assert
    assert took < 2.0, took
    assert mod(res, "firewall")["considered"] == 5001


def test_an_address_entry_longer_than_any_address_is_none_and_not_cached():
    """ASVS V1.11.3 · CWE-400 · CWE-770: a tenant string longer than any address is no address entry and is not kept in the parse cache."""
    before = zpm._parse_cached.cache_info().currsize
    assert zpm._is_ip_entry("1" * 5000) is False and zpm._parse_cached.cache_info().currsize == before
    assert zpm._is_ip_entry("2001:db8::1-2001:db8::ffff") is True


def test_the_pack_library_is_read_with_every_file_closed(tmp_path, monkeypatch):
    """ASVS V1.11.3 · CWE-775 · CWE-404: reading the policy packs closes every file it opens (no ResourceWarning); a pack that is not JSON has no rules."""
    import gc
    import warnings
    import dlp_importer
    good, bad = tmp_path / "good", tmp_path / "bad"
    for d, text in ((good, '[{"name": "R1", "channel": "web"}]'), (bad, "not json")):
        (d / "configs").mkdir(parents=True)
        (d / "configs" / "dlp_policies.json").write_text(text, encoding="utf-8")
    monkeypatch.setattr(dlp_importer, "discover_packs", lambda: [{"id": "good", "dir": str(good)}, {"id": "bad", "dir": str(bad)}])
    with warnings.catch_warnings(record=True) as seen:
        warnings.simplefilter("always", ResourceWarning)
        packs = df.load_packs()
        gc.collect()
    assert [p["policies"] for p in packs] == [[{"name": "R1", "channel": "web"}], []]
    assert not [w for w in seen if issubclass(w.category, ResourceWarning)]


def test_5000_connector_rules_on_shared_groups_evaluate_in_under_two_seconds():
    """ASVS V1.11.3 · CWE-400 · CWE-407: 5,000 connector forwarding rules on 500 source and destination groups and 300 workload groups take under 2 s."""
    # Arrange
    rules = [fwd(i, i + 1, f"R{i}", "DIRECT", srcIpGroups=[{"id": 1000 + i % 500}], destIpGroups=[{"id": 2000 + i % 500}],
                 srcWorkloadGroups=[{"id": 1, "name": "G"}]) for i in range(5000)]
    data = ztw_data(rules)
    data["ip_source_groups"] = [[{"id": 1000 + g, "name": f"S{g}", "ipAddresses": [f"10.{g % 250}.{k}.0/24" for k in range(20)]} for g in range(500)]]
    data["ip_destination_groups"] = [[{"id": 2000 + g, "name": f"D{g}", "addresses": [f"172.16.{k}.0/24" for k in range(20)]} for g in range(500)]]
    data["workload_groups"] = [[{"id": i, "name": f"G{i}", "expressionJson": {"expressionContainers": [
        {"tagType": "ATTR", "tagContainer": {"operator": "AND", "tags": [{"key": "Env", "value": "prod"}]}}]}} for i in range(300)]]
    snap = ztw_snap(data)
    # Act
    t0 = time.perf_counter()
    ev = wp.evaluate(snap, wl(ip="192.168.1.1", tags="Env=dev"), zp.destination("198.51.100.5", "443"))
    took = time.perf_counter() - t0
    # Assert
    assert took < 2.0 and ev["go"] == "zia" and len(ev["walked"]) == 60, took
