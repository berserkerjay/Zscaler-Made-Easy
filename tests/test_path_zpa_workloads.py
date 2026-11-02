"""Path analyzer, ZPA first and workload traffic (zpa_path, workload_path,
through the one start endpoint POST /api/path-analyzer/start; the page's
own controls in static/report_path.html, rendered by static/path_modules.js).

Fake tenants only: the ZPA side answers with the SDK's own models through
tests/test_zpa_analysis.FakeTenant; the Cloud & Branch Connector side is a
recording fake of client.ztw.<service>.list_*(); ZIA is the Path analyzer's
own fake (tests/test_path_analyzer). Jobs run in the request (pack_jobs.start
replaced), so nothing sleeps or polls, and every state file lives in tmp_path.
"""
from __future__ import annotations

import copy
import os
import re
import threading

import pytest
from fastapi.testclient import TestClient

import workload_path as wp
import zpa_path as zp
from test_path_analyzer import _lookup_client
from test_zpa_analysis import APP, FakeTenant, _cond, _op, _rule, _seg

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "canary-secret-7f3a91"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET, "customer_id": "216196257331281920"}
CHANNELS = {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}
MODULE_KEYS = {"key", "module", "verdict", "rule", "overlaps", "could_override", "criteria", "notes", "detail"}


# ── fake tenants ────────────────────────────────────────────────────────
def zpa_data(access=None, forwarding=None, segments=None):
    """A small ZPA tenant: Git (exact), a corp wildcard, an apex-only
    wildcard, a CIDR pair, one EDR posture profile and two connectors."""
    segs = segments if segments is not None else [
        _seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"]),
        _seg("s2", "Corp wildcard", ["*.corp.example"], [(1, 65535)], "g1", ["sg1"]),
        _seg("s3", "Apex only", ["*.apex.example"], [(443, 443)], "g1", ["sg1"]),
        _seg("s4", "Wide net", ["10.0.0.0/8"], [(443, 443)], "g1", ["sg1"]),
        _seg("s5", "Narrow net", ["10.1.0.0/16"], [(443, 443)], "g1", ["sg1"]),
        _seg("s6", "Apex exact", ["sub.example"], [(443, 443)], "g1", ["sg1"]),
    ]
    return {"segments": segs, "segment_groups": [{"id": "g1", "name": "Corp", "enabled": True}],
            "server_groups": [{"id": "sg1", "name": "SG", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": [{"id": "cg1", "name": "CG"}]}],
            "connector_groups": [{"id": "cg1", "name": "CG", "enabled": True}],
            "connectors": [{"id": f"c{i}", "name": f"C{i}", "appConnectorGroupId": "cg1", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"} for i in (1, 2)],
            "service_edge_groups": [], "service_edges": [], "idps": [], "saml_attributes": [], "trusted_networks": [], "machine_groups": [],
            "posture_profiles": [{"id": "p1", "name": "CrowdStrike ZTA", "postureUdid": "udid-1", "postureType": "CROWDSTRIKE_ZTA_SCORE"}],
            "policies": {"access": access if access is not None else [_rule("r1", 1, "Allow corp", "ALLOW", _cond(_op("APP_GROUP", "id", "g1")))],
                         "client_forwarding": forwarding or [], "timeout": [], "inspection": [], "isolation": []},
            "scim_groups": {}}


def zpa_snap(**kw):
    return zp.read(FakeTenant(zpa_data(**kw)), pace=0)


def stage(dest, network="off", port=None, **kw):
    snap, prof = zpa_snap(**kw)
    return zp.stage(snap, zp.destination(dest, port), network=network, platform="windows", profiles=prof)


class Resp:
    def __init__(self, raw, nxt=None):
        self._raw, self._nxt = raw, nxt

    def get_results(self):
        return copy.deepcopy(self._raw)

    def has_next(self):
        return self._nxt is not None

    def next(self):
        return [dict(x) for x in self._nxt._raw], self._nxt, None


class ZtwService:
    def __init__(self, t, name):
        self._t, self._name = t, name

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        if not attr.startswith("list_"):
            def write(*a, **k):
                self._t.writes.append(f"ztw.{self._name}.{attr}")
                raise AssertionError("write attempted")
            return write

        def lister(*a, **k):
            self._t.calls.append(f"ztw.{self._name}.{attr}")
            if self._t.on_call:
                self._t.on_call()
            pages = self._t.data.get(self._name) or [[]]
            resp = None
            for raw in reversed(pages):
                resp = Resp(raw, resp)
            return [dict(x) for x in pages[0]], resp, None
        return lister


class Ztw:
    def __init__(self, t):
        self._t = t

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return ZtwService(self._t, name)


class ConnectorTenant:
    """client.ztw.<service>.list_*() with pages of raw JSON."""

    def __init__(self, data, on_call=None):
        self.data, self.calls, self.writes, self.on_call = data, [], [], on_call
        self.ztw = Ztw(self)


def fwd(i, order, name, method, **kw):
    d = {"id": i, "name": name, "order": order, "state": "ENABLED", "type": "EC_RDR", "forwardMethod": method}
    d.update(kw)
    return d


WG_PROD = {"id": 11, "name": "Prod web", "expressionJson": {"operator": "AND", "expressionContainers": [
    {"tagType": "VPC", "operator": "AND", "tagContainer": {"operator": "AND", "tags": [{"key": "Vpc-id", "value": "vpc-1"}]}},
    {"tagType": "ATTR", "operator": "AND", "tagContainer": {"operator": "OR", "tags": [{"key": "Env", "value": "prod"}, {"key": "Env", "value": "stage"}]}}]}}
WG_DEV = {"id": 12, "name": "Dev", "expressionJson": {"operator": "AND", "expressionContainers": [
    {"tagType": "ATTR", "operator": "AND", "tagContainer": {"operator": "AND", "tags": [{"key": "Env", "value": "dev"}]}}]}}


def ztw_data(rules=None):
    return {"forwarding_rules": [rules if rules is not None else [
        fwd(1, 1, "Drop bad", "DROP", destAddresses=["bad.example", "*.bad.example"]),
        fwd(2, 2, "Prod to ZPA", "ZPA", srcWorkloadGroups=[{"id": 11, "name": "Prod web"}], zpaAppSegments=[{"name": "Git", "externalId": "s1"}]),
        fwd(3, 3, "Dev direct", "DIRECT", srcWorkloadGroups=[{"id": 12, "name": "Dev"}]),
        fwd(4, 4, "Builders local", "LOCAL_SWITCH", srcIpGroups=[{"id": 21, "name": "Builders"}]),
        fwd(5, 5, "Partner proxy", "PROXYCHAIN", ecGroups=[{"id": 31, "name": "Branch-EU"}], proxyGateway={"id": 1, "name": "Partner GW"}),
        fwd(6, 6, "Off rule", "DROP", state="DISABLED"),
        fwd(98, -1, "Default", "ZIA"),
        fwd(97, -2, "ZPA pool for stray traffic", "DROP", destAddresses=["100.64.0.0/10"]),
    ]],
        "workload_groups": [[WG_PROD, WG_DEV]],
        "ec_groups": [[{"id": 31, "name": "Branch-EU", "location": {"id": 7, "name": "Frankfurt branch"}}, {"id": 32, "name": "AWS-US"}]],
        "ip_source_groups": [[{"id": 21, "name": "Builders", "ipAddresses": ["10.9.0.0/16", "10.8.0.1-10.8.0.9"]}]],
        "ip_destination_groups": [[]]}


def ztw_snap(data=None):
    return wp.read(ConnectorTenant(data or ztw_data()), pace=0)


def wl(**kw):
    base = {"ip": "", "tags": "", "workload_group": "", "connector_group": ""}
    base.update(kw)
    return wp.workload_input(base)


# ── ZPA: application segment ────────────────────────────────────────────
@pytest.mark.parametrize("dest,port,segment", [
    ("git.corp.example", None, "Git"),          # exact FQDN beats the wildcard
    ("wiki.corp.example", None, "Corp wildcard"),
    ("10.1.2.3", "443", "Narrow net"),          # longest CIDR wins
    ("10.200.0.1", "443", "Wide net"),
])
def test_the_most_specific_segment_whose_ports_contain_the_port_matches(dest, port, segment):
    """ASVS V1.4.4 · CWE-284 · WSTG-ATHZ-02: the application segment is chosen by exact FQDN, then longest wildcard, then longest CIDR."""
    # Act
    st = stage(dest, port=port)
    # Assert
    assert st["segment"]["name"] == segment
    assert st["modules"][0]["module"] == "ZPA application segment" and st["modules"][0]["verdict"] == "matched"


def test_a_less_specific_match_is_listed_as_an_overlap_and_a_port_miss_as_a_hint():
    """ASVS V1.4.4 · CWE-284: overlapping segments are compressed into one hop; a port miss is said with its fix."""
    # Act
    st = stage("git.corp.example", port="22")
    # Assert: Git serves 443 only, so the wildcard carries port 22, and Git's port miss is a hint.
    seg = st["modules"][0]
    assert st["segment"]["name"] == "Corp wildcard"
    assert any("“Git” lists git.corp.example but serves TCP 443, not 22" in n for n in seg["notes"])
    assert stage("git.corp.example")["modules"][0]["overlaps"][0] == {"name": "Corp wildcard", "order": None, "differs": False,
                                                                     "detail": "*.corp.example, TCP 1-65535: less specific"}


@pytest.mark.parametrize("dest,hint", [
    ("apex.example", "lists *.apex.example, which covers subdomains only: add apex.example itself"),
    ("a.sub.example", "lists sub.example, which does not cover its subdomains such as a.sub.example"),
])
def test_an_apex_or_subdomain_miss_is_explained(dest, hint):
    """ASVS V1.4.4 · CWE-284: a wildcard does not cover its apex and an apex does not cover subdomains; both are said, never guessed."""
    # Act
    st = stage(dest)
    # Assert
    assert st["outcome"] == "not_zpa" and st["carries"] is False
    assert any(hint in h for h in st["hints"])
    assert st["impacts"] and st["impacts"][0]["severity"] == "low"


# ── ZPA: bypass, client forwarding, access ──────────────────────────────
@pytest.mark.parametrize("bypass,network,carries,verdict", [
    ("NEVER", "on", True, "intercepted"),
    ("ALWAYS", "off", False, "bypassed"),
    ("ON_NET", "on", False, "bypassed"),
    ("ON_NET", "off", True, "intercepted"),
    ("ON_NET", "vpn", None, "conditional"),
])
def test_the_segment_bypass_setting_is_applied_per_network(bypass, network, carries, verdict):
    """ASVS V1.4.4 · CWE-284: Never, On-Net and Always bypass are applied for the network the device is on."""
    # Arrange
    segs = [_seg("s1", "Git", ["git.corp.example"], [(443, 443)], "g1", ["sg1"], bypassType=bypass)]
    # Act
    st = stage("git.corp.example", network=network, segments=segs)
    # Assert
    assert st["carries"] is carries
    assert next(m for m in st["modules"] if m["module"] == "ZPA segment bypass")["verdict"] == verdict


@pytest.mark.parametrize("action,allowed,carries,outcome", [
    ("INTERCEPT", True, True, "zpa_allowed"),
    ("BYPASS", True, False, "outside"),
    ("INTERCEPT_ACCESSIBLE", True, True, "zpa_allowed"),
    ("INTERCEPT_ACCESSIBLE", False, False, "outside"),    # not accessible: goes outside ZPA
    ("INTERCEPT", False, True, "zpa_denied"),
])
def test_the_client_forwarding_policy_decides_whether_zpa_carries_it(action, allowed, carries, outcome):
    """ASVS V1.4.4 · CWE-284: Intercept, Intercept accessible and Bypass are applied with the access policy's answer."""
    # Arrange
    access = [_rule("r1", 1, "Allow corp", "ALLOW", _cond(APP("s1")))] if allowed else []
    forwarding = [_rule("f1", 1, "Forward corp", action, _cond(APP("s1")))]
    # Act
    st = stage("git.corp.example", access=access, forwarding=forwarding)
    # Assert
    assert (st["carries"], st["outcome"]) == (carries, outcome)
    fm = next(m for m in st["modules"] if m["module"] == "ZPA client forwarding policy")
    assert fm["rule"] == {"name": "Forward corp", "order": 1}


def test_posture_is_evaluated_as_pass_and_as_fail():
    """ASVS V4.1.3 · CWE-863: a rule that needs device posture is answered both ways, and the condition is worded by device_posture."""
    # Arrange
    access = [_rule("r1", 1, "Allow Git with EDR", "ALLOW", _cond(APP("s1")), _cond(_op("POSTURE", "udid-1", "true")))]
    # Act
    st = stage("git.corp.example", access=access)
    # Assert
    assert st["posture_matters"] and st["outcome"] == "zpa_conditional" and st["carries"] is True
    assert st["scenarios"]["pass"]["access"] == "allow" and st["scenarios"]["fail"]["access"] == "deny"
    acc = next(m for m in st["modules"] if m["module"] == "ZPA access policy")
    assert acc["verdict"] == "conditional"
    assert {"name": "Device posture: passes “CrowdStrike ZTA” (EDR or antivirus)", "state": "match"} in acc["criteria"]
    assert any(n.startswith("Allow “Git” when the device passes the EDR or antivirus check") for n in acc["notes"])
    assert "when posture passes ZPA allows it; when it fails ZPA denies it" in st["headline"]


def test_and_or_and_negation_are_evaluated():
    """ASVS V4.1.3 · CWE-863: a rule's AND, a condition's OR and a negated condition are applied as ZPA documents them."""
    # Arrange: deny Windows (negated: NOT windows) first; then allow (Windows OR Linux).
    access = [_rule("r0", 1, "Deny non-Windows", "DENY", _cond(APP("s1")), _cond(_op("PLATFORM", "windows", "true"), negated=True)),
              _rule("r1", 2, "Allow desktops", "ALLOW", _cond(APP("s1")), _cond(_op("PLATFORM", "windows", "true"), _op("PLATFORM", "linux", "true")))]
    # Act
    snap, prof = zpa_snap(access=access)
    win = zp.stage(snap, zp.destination("git.corp.example"), platform="windows", profiles=prof)
    ios = zp.stage(snap, zp.destination("git.corp.example"), platform="ios", profiles=prof)
    # Assert
    assert win["outcome"] == "zpa_allowed" and win["scenarios"]["pass"]["rule"] == "Allow desktops"
    assert ios["outcome"] == "zpa_denied" and ios["scenarios"]["pass"]["rule"] == "Deny non-Windows"


def test_an_operand_this_tool_cannot_evaluate_is_flagged_and_makes_the_answer_conditional():
    """ASVS V1.4.4 · CWE-754: an unknown operand (risk score) is named and never guessed as met or not met."""
    # Arrange
    access = [_rule("r0", 1, "Deny risky", "DENY", _cond(APP("s1")), _cond(_op("RISK_FACTOR_TYPE", "ZIA", "HIGH"))),
              _rule("r1", 2, "Allow corp", "ALLOW", _cond(APP("s1")))]
    # Act
    st = stage("git.corp.example", access=access)
    # Assert
    assert st["flagged"] == [{"rule": "Deny risky", "order": 1, "types": ["RISK_FACTOR_TYPE"]}]
    assert st["outcome"] == "zpa_conditional" and st["carries"] is True
    acc = next(m for m in st["modules"] if m["module"] == "ZPA access policy")
    assert acc["overlaps"] == [] and acc["could_override"][0]["name"] == "Deny risky"
    assert (acc["could_override"][0]["order"], acc["could_override"][0]["action"]) == (1, "DENY")
    assert acc["could_override"][0]["detail"].startswith("Could decide instead: it depends on")
    assert any(i["label"] == "ZPA rule not fully evaluated" for i in st["impacts"])


def test_every_hop_has_the_shared_module_shape():
    """ASVS V5.1.3 · CWE-20: each ZPA and connector step is the one hop shape static/path_modules.js renders, in its one vocabulary."""
    import zia_path_modules as zpm
    # Arrange
    st = stage("git.corp.example")
    ev = wp.evaluate(ztw_snap(), wl(ip="10.9.1.1"), zp.destination("example.com"))
    # Assert
    for m in st["modules"] + ev["modules"]:
        assert set(m) == MODULE_KEYS
        assert m["rule"] is None or set(m["rule"]) == {"name", "order"}
        assert all(set(c) == {"name", "state"} and c["state"] in zpm.CRITERION_STATES for c in m["criteria"])
        assert m["verdict"] in zpm.VERDICTS


def test_an_unreadable_segment_list_is_unknown_never_not_zpa():
    """ASVS V7.4.1 · CWE-754 · CWE-636: a failed ZPA read says unknown; it never claims ZPA does not carry the traffic."""
    # Arrange
    snap, prof = zp.read(FakeTenant(zpa_data(), fail={"application_segment": "HTTP 403"}), pace=0)
    # Act
    st = zp.stage(snap, zp.destination("git.corp.example"), profiles=prof)
    # Assert
    assert st["carries"] is None and st["status"] == "unknown" and st["modules"][0]["verdict"] == "unknown"


# ── workloads ───────────────────────────────────────────────────────────
def test_tags_are_parsed_with_and_without_a_type_and_bounded():
    """ASVS V5.1.4 · CWE-20 · CWE-400: typed workload tags are parsed; too many or too long are refused in words."""
    # Act
    tags = wp.parse_tags("VPC: Vpc-id=vpc-1, Env=prod; vm:Name=web\nnokey")
    # Assert
    assert tags == [{"type": "VPC", "key": "Vpc-id", "value": "vpc-1"}, {"type": None, "key": "Env", "value": "prod"},
                    {"type": "VM", "key": "Name", "value": "web"}, {"type": None, "key": "nokey", "value": ""}]
    with pytest.raises(ValueError, match="at most 50"):
        wp.parse_tags(",".join(f"k{i}=v" for i in range(51)))
    with pytest.raises(ValueError, match="longer than 200"):
        wp.parse_tags("k=" + "v" * 201)
    with pytest.raises(ValueError, match="not an IP address"):
        wp.workload_input({"ip": "10.0.0.300"})


@pytest.mark.parametrize("tags,prod,dev", [
    ("VPC:Vpc-id=vpc-1, Env=prod", "match", "nomatch"),
    ("VPC:Vpc-id=vpc-1, Env=stage", "match", "nomatch"),       # OR inside the container
    ("Env=prod", "nomatch", "nomatch"),                        # AND across containers
    ("VM:Vpc-id=vpc-1, Env=prod", "nomatch", "nomatch"),       # a typed tag must match the container's type
    ("", "unknown", "unknown"),
])
def test_workload_group_membership_follows_the_tag_expression(tags, prod, dev):
    """ASVS V4.1.3 · CWE-863: membership is worked out from the group's tag expression (AND / OR, tag type)."""
    # Act
    groups = {g["name"]: g["state"] for g in wp.membership(ztw_snap(), wl(tags=tags))}
    # Assert
    assert (groups["Prod web"], groups["Dev"]) == (prod, dev)


@pytest.mark.parametrize("w,dest,go,rule", [
    (dict(ip="10.0.0.5"), "x.bad.example", "drop", "Drop bad"),
    (dict(tags="VPC:Vpc-id=vpc-1, Env=prod"), "git.corp.example", "zpa", "Prod to ZPA"),
    (dict(tags="Env=dev"), "example.com", "direct", "Dev direct"),
    (dict(ip="10.8.0.5", tags="Env=qa"), "example.com", "local", "Builders local"),
    (dict(ip="10.7.0.1", tags="Env=qa", connector_group="Branch-EU"), "example.com", "proxy", "Partner proxy"),
    (dict(ip="10.7.0.1", tags="Env=qa", connector_group="AWS-US"), "100.64.1.2", "drop", "ZPA pool for stray traffic"),
    (dict(ip="10.7.0.1", tags="Env=qa", connector_group="AWS-US"), "example.com", "zia", "Default"),
])
def test_the_connector_forwarding_rules_decide_in_order(w, dest, go, rule):
    """ASVS V1.4.4 · CWE-284: ZIA, ZPA, Direct, Local switch, Proxy chaining and Drop rules are evaluated in order, predefined rules last."""
    # Arrange
    zsnap, _ = zpa_snap()
    d = zp.destination(dest, "443" if dest[0].isdigit() else None)
    seg = {"id": "s1", "name": "Git", "segment_group_id": "g1", "segment_group_name": "Corp"} if dest == "git.corp.example" else None
    # Act
    ev = wp.evaluate(ztw_snap(), wl(**w), d, seg, True)
    # Assert
    assert (ev["go"], ev["rule"]["name"]) == (go, rule), ev["walked"]
    assert all(r["name"] != "Off rule" or r["status"] == "disabled" for r in ev["walked"])


def test_a_criterion_this_tool_cannot_evaluate_makes_the_rule_conditional():
    """ASVS V1.4.4 · CWE-754: a forwarding rule on a country or category depends on it; the possible ends are all named."""
    # Arrange
    data = ztw_data([fwd(1, 1, "Countries direct", "DIRECT", destCountries=["COUNTRY_CA"]), fwd(9, -1, "Default", "ZIA")])
    # Act
    ev = wp.evaluate(ztw_snap(data), wl(ip="10.0.0.1"), zp.destination("example.com"))
    # Assert
    assert ev["go"] == "conditional" and ev["possible"] == ["direct", "zia"]
    fm = next(m for m in ev["modules"] if m["module"] == "Connector forwarding")
    could = fm["could_override"][0]
    assert (could["name"], could["order"], could["action"]) == ("Countries direct", 1, "DIRECT")
    assert could["criteria"] == [{"name": "Destination country (not evaluated)", "state": "unknown"}]


def test_a_hostname_is_never_resolved_against_ip_destinations():
    """ASVS V1.4.4 · CWE-754 · CWE-350: a hostname against IP-address destinations depends on its address; it is never resolved or guessed."""
    # Arrange
    data = ztw_data([fwd(1, 1, "Net direct", "DIRECT", destAddresses=["198.51.100.0/24"]), fwd(9, -1, "Default", "ZIA")])
    # Act
    by_name = wp.evaluate(ztw_snap(data), wl(ip="10.0.0.1"), zp.destination("example.com"))
    by_ip = wp.evaluate(ztw_snap(data), wl(ip="10.0.0.1"), zp.destination("198.51.100.9", "443"))
    # Assert
    assert by_name["go"] == "conditional" and by_name["possible"] == ["direct", "zia"]
    assert by_ip["go"] == "direct"


def test_the_connector_reader_pages_reads_only_lists_and_stops():
    """ASVS V1.14.5 · CWE-284 · CWE-400: only list methods are called, every page is read, and Stop ends the read with nothing more read."""
    # Arrange
    data = ztw_data()
    data["workload_groups"] = [[WG_PROD], [WG_DEV]]
    t = ConnectorTenant(data)
    # Act
    snap = wp.read(t, pace=0)
    # Assert
    assert [g["name"] for g in snap["workload_groups"]] == ["Prod web", "Dev"] and not t.writes
    assert t.calls == ["ztw.forwarding_rules.list_rules", "ztw.workload_groups.list_groups", "ztw.ec_groups.list_ec_groups",
                       "ztw.ip_source_groups.list_ip_source_groups", "ztw.ip_destination_groups.list_ip_destination_groups"]
    stop = threading.Event()
    t2 = ConnectorTenant(ztw_data(), on_call=stop.set)
    with pytest.raises(wp.Stopped):
        wp.read(t2, cancel=stop, pace=0)
    assert len(t2.calls) == 1


def test_the_sdk_paths_the_reader_relies_on_exist():
    """SSDF PW.4.1 · CWE-1104: every ZTW list method the reader calls exists in the installed SDK at the documented path."""
    import inspect
    from zscaler.ztw.ztw_service import ZTWService
    for _, _, svc, _method in wp.LISTS:
        assert isinstance(getattr(ZTWService, svc), property), svc
    import zscaler.ztw.forwarding_rules as fr
    s = inspect.getsource(fr)
    assert "/ecRules/ecRdr" in s and "LOCAL_SWITCH" in s and "PROXYCHAIN" in s and "ECZPA" in s
    import zscaler.ztw.workload_groups as wg
    assert "/workloadGroups" in inspect.getsource(wg)
    from zscaler.ztw.forwarding_rules import ForwardingControlRulesAPI
    from zscaler.ztw.workload_groups import WorkloadGroupsAPI
    from zscaler.ztw.ec_groups import ECGroupsAPI
    from zscaler.ztw.ip_source_groups import IPSourceGroupsAPI
    from zscaler.ztw.ip_destination_groups import IPDestinationGroupsAPI
    for cls, m in ((ForwardingControlRulesAPI, "list_rules"), (WorkloadGroupsAPI, "list_groups"), (ECGroupsAPI, "list_ec_groups"),
                   (IPSourceGroupsAPI, "list_ip_source_groups"), (IPDestinationGroupsAPI, "list_ip_destination_groups")):
        assert callable(getattr(cls, m))


# ── the API ─────────────────────────────────────────────────────────────
class Sdk:
    """What _build_sdk_client returns: client.zpa (FakeTenant) and client.ztw."""

    def __init__(self, zdata=None, wdata=None):
        self.zpa_t = FakeTenant(zdata or zpa_data())
        self.ztw_t = ConnectorTenant(wdata or ztw_data())
        self.zpa, self.ztw = self.zpa_t.zpa, self.ztw_t.ztw


class SyncJob:
    def __init__(self, kind, result):
        self.id, self.kind, self.status, self.result = "sync", kind, "done", result


@pytest.fixture
def api(tmp_path, monkeypatch):
    """Arrange: an isolated app whose client factories are the fakes and whose jobs run in the request."""
    import dlp_api_server as srv
    import pack_jobs
    import workload_path
    import zpa_reader
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments")):
        monkeypatch.setenv(var, str(tmp_path / name))
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(workload_path, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(srv, "_REPORTS", {})
    jobs = {}

    def start(kind, fn, **k):
        job = SyncJob(kind, fn(lambda line: None, threading.Event()))
        jobs["last"] = job
        return job
    monkeypatch.setattr(pack_jobs, "start", start)
    raw = _lookup_client()
    raw.paths = []
    inner = raw.get
    raw.get = lambda ep, p=None: raw.paths.append(ep) or inner(ep, p)
    state = {"raw": raw, "sdk": Sdk(), "built": []}
    monkeypatch.setattr(srv, "_build_client", lambda req: state["built"].append("raw") or state["raw"])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: state["built"].append("sdk") or state["sdk"])
    state["post"] = lambda **body: TestClient(srv.app).post("/api/path-analyzer/start", json=dict(CREDS, from_page=True, **body))
    state["result"] = lambda: jobs["last"].result
    return state


def test_zpa_carries_it_so_zia_is_not_traced(api):
    """ASVS V1.4.4 · CWE-284 · OWASP A04:2021: when ZPA carries the destination, ZIA is not read or traced, and the answer says ZIA does not apply."""
    # Act
    r = api["post"](destination="git.corp.example", scopes=["zpa", "dlp", "zcc"], channels=CHANNELS)
    # Assert
    assert r.status_code == 200, r.text
    res = api["result"]()
    assert res["verdict"]["outcome"] == "zpa_allowed" and "ZIA does not apply" in res["verdict"]["headline"]
    assert res["zia_applies"] is False and api["raw"].reads == 0 and not api["raw"].lookups
    assert [m["module"] for m in res["modules"]][:4] == ["ZPA application segment", "ZPA segment bypass", "ZPA client forwarding policy", "ZPA access policy"]
    assert res["zpa_report_id"].startswith("pathzpa-") and res["tenant_label"] == "acme (production)"


def test_zpa_does_not_carry_it_so_zia_is_traced_after_it(api):
    """ASVS V1.4.4 · CWE-284: a destination no segment matches is traced through ZIA with the ZPA step in front."""
    # Act
    api["post"](destination="https://casino.example/x", scopes=["zpa", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    res = api["result"]()
    # Assert
    assert res["zia_applies"] is True and res["verdict"]["blocked_by"] == "Block gambling"
    assert res["trace"]["hops"][0]["key"] == "zpa_segment" and res["modules"][0]["verdict"] == "not_matched"
    assert res["verdict"]["summary"].startswith("ZPA does not carry it")


def test_a_kept_zpa_read_is_reused_for_the_same_tenant_only(api):
    """ASVS V4.2.1 · CWE-639: the next destination reuses the ZPA read for the same tenant; another tenant reads its own."""
    # Arrange
    api["post"](destination="git.corp.example", scopes=["zpa"])
    rid = api["result"]()["zpa_report_id"]
    first = len(api["sdk"].zpa_t.calls)
    # Act
    api["post"](destination="wiki.corp.example", scopes=["zpa"], zpa_report_id=rid)
    same = len(api["sdk"].zpa_t.calls)
    reused = api["result"]()
    api["post"](destination="wiki.corp.example", scopes=["zpa"], zpa_report_id=rid, vanity_domain="other")
    # Assert
    assert first > 0 and same == first and reused["zpa_report_id"] == rid
    assert len(api["sdk"].zpa_t.calls) == 2 * first and api["result"]()["zpa_report_id"] != rid


def test_workload_traffic_to_zia_skips_client_connector(api):
    """ASVS V1.4.4 · CWE-272: workload traffic the connector sends to ZIA is traced without reading or assessing Client Connector."""
    # Act
    r = api["post"](destination="https://casino.example/x", source="workload", workload={"ip": "10.7.0.1", "tags": "Env=qa", "connector_group": "AWS-US"},
                    scopes=["ztw", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    # Assert
    assert r.status_code == 200, r.text
    res = api["result"]()
    assert res["source"] == "workload" and res["verdict"]["blocked_by"] == "Block gambling"
    zcc = [h for h in res["trace"]["hops"] if h["key"] in ("zcc", "forwarding", "pac")]
    assert zcc and all(h["status"] == "na" for h in zcc)
    assert api["raw"].paths and not [p for p in api["raw"].paths if p.startswith("/zcc/")]
    assert not any(x["hop"] in ("zcc", "forwarding", "pac") for x in res["verdict"]["not_in_scope"])
    assert res["modules"][0]["module"] == "Workload groups" and res["modules"][1]["module"] == "Connector forwarding"


def test_workload_traffic_sent_direct_never_reaches_zscaler(api):
    """ASVS V1.4.4 · CWE-284: a Direct forwarding rule is the answer, and nothing in ZIA is read or claimed."""
    # Act
    api["post"](destination="example.com", source="workload", workload={"tags": "Env=dev"}, scopes=["ztw", "dlp"], channels=CHANNELS)
    res = api["result"]()
    # Assert
    v = res["verdict"]
    assert v["outcome"] == "bypassed" and not v["reaches_zscaler"] and v["blocked_by"] == "Dev direct" and v["stops_at"] == "Connector forwarding"
    assert api["raw"].reads == 0 and not api["raw"].lookups   # signed in (ZIA is in scope) but nothing in ZIA is read
    assert v["mitigations"][0]["action"] == "Forward this workload traffic to ZIA"


def test_workload_traffic_to_zpa_is_evaluated_by_zpa(api):
    """ASVS V1.4.4 · CWE-284: a ZPA forwarding rule hands the workload to ZPA's segment and access policy."""
    # Act
    api["post"](destination="git.corp.example", source="workload", workload={"tags": "VPC:Vpc-id=vpc-1, Env=prod"}, scopes=["ztw", "zpa"])
    res = api["result"]()
    # Assert
    assert res["verdict"]["outcome"] == "zpa_allowed"
    assert [m["module"] for m in res["modules"]][:3] == ["Workload groups", "Connector forwarding", "ZPA application segment"]
    assert "Not used" in next(m for m in res["modules"] if m["module"] == "ZPA segment bypass")["notes"][0]


@pytest.mark.parametrize("body,detail", [
    (dict(destination="example.com", scopes=[]), "scope"),
    (dict(destination="example.com", scopes=["zdx"]), "scope"),
    (dict(destination="example.com", source="workload", scopes=["dlp", "zpa"], channels=CHANNELS), "Cloud & Branch Connector"),
    (dict(destination="example.com", source="workload", workload={"ip": "300.1.1.1"}, scopes=["ztw"]), "not an IP address"),
    (dict(destination="example.com", source="workload", workload={"tags": ",".join(f"k{i}=v" for i in range(60))}, scopes=["ztw"]), "at most 50"),
    (dict(destination="example.com", source="satellite", scopes=["zpa"]), "user device or a workload"),
    (dict(destination="not a host", scopes=["zpa"]), "URL"),
    (dict(destination="example.com", port="70000", scopes=["zpa"]), "port"),
])
def test_bad_or_out_of_scope_requests_are_refused_before_sign_in(api, body, detail):
    """ASVS V4.1.3 · ASVS V5.1.3 · CWE-20 · CWE-272 · WSTG-INPV-01: nothing in scope or a bad input is a 400 before any client is built."""
    # Act
    r = api["post"](**body)
    # Assert
    assert r.status_code == 400 and detail in r.json()["detail"], r.text
    assert api["built"] == []


def test_the_classic_sign_in_cannot_read_workloads_and_says_zpa_was_not_read(api):
    """ASVS V4.1.3 · CWE-287: the classic ZIA API sign-in is refused for workloads; for ZPA it is said, never assumed."""
    # Arrange
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-canary-1", "api_key": "a" * 12}
    import dlp_api_server as srv
    t = TestClient(srv.app)
    # Act
    w = t.post("/api/path-analyzer/start", json=dict(legacy, cloud="zscaler", from_page=True, destination="example.com", source="workload", scopes=["ztw"]))
    z = t.post("/api/path-analyzer/start", json=dict(legacy, cloud="zscaler", from_page=True, destination="example.com", scopes=["zpa"]))
    # Assert
    assert w.status_code == 400 and "OneAPI" in w.json()["detail"]
    assert z.status_code == 400 and "classic ZIA API" in z.json()["detail"] and api["built"] == []


def test_no_secret_reaches_the_result_or_the_log(api):
    """ASVS V7.1.1 · ASVS V8.3.4 · CWE-532 · CWE-200: the client secret never appears in the result, its log or an error a fake echoes."""
    # Arrange: the ZPA fake fails one list with a message that echoes the secret.
    api["sdk"] = Sdk()
    api["sdk"].zpa_t.fail["posture_profiles"] = f"denied for secret={SECRET}"
    # Act
    api["post"](destination="git.corp.example", scopes=["zpa"])
    # Assert
    assert SECRET not in repr(api["result"]())


# ── one start endpoint ──────────────────────────────────────────────────
@pytest.mark.parametrize("method", ["post", "get"])
def test_the_second_start_endpoint_is_gone(api, method):
    """ASVS V1.14.5 · ASVS V14.5.1 · CWE-1059: the Path analyzer has one start endpoint; the old /full/start answers 404 or 405 and reads nothing."""
    import dlp_api_server as srv
    # Act
    r = getattr(TestClient(srv.app), method)("/api/path-analyzer/full/start", **({"json": dict(CREDS, destination="example.com", scopes=["zpa"])} if method == "post" else {}))
    # Assert
    assert r.status_code in (404, 405) and api["built"] == []
    assert not [x for x in srv.app.routes if getattr(x, "path", "") == "/api/path-analyzer/full/start"]


def test_one_start_body_reaches_the_workload_the_zia_modules_and_the_what_if(api):
    """ASVS V1.4.4 · ASVS V5.1.3 · CWE-20: one body with protocol, port (as text), identity and source=workload drives every part of one analysis."""
    # Act
    r = api["post"](destination="https://casino.example/x", protocol="tcp", port="8443", identity={"group": "Interns"},
                    source="workload", workload={"ip": "10.7.0.1", "tags": "Env=qa", "connector_group": "AWS-US"},
                    scopes=["ztw", "zpa", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    # Assert
    assert r.status_code == 200, r.text
    res = api["result"]()
    assert res["source"] == "workload" and [m["module"] for m in res["modules"]][:2] == ["Workload groups", "Connector forwarding"]
    assert res["ztw_report_id"].startswith("pathztw-") and res["zpa_report_id"].startswith("pathzpa-")   # ZPA read for the segment criteria
    assert res["zia_modules"]["traffic"]["label"].startswith("TCP/8443")
    assert res["whatif"]["identity_label"] == "group Interns"
    assert api["built"] == ["raw", "sdk"]


def test_one_start_body_reaches_zpa_the_pac_file_the_zia_modules_and_the_what_if(api):
    """ASVS V1.4.4 · ASVS V5.1.3 · CWE-20: a device body with protocol, port and identity gives ZPA, then the evaluated PAC file, then the ZIA modules and the what-if."""
    # Act: macOS off network forwards by PAC in the Data Flow fake; no ZPA segment matches casino.example.
    r = api["post"](destination="https://casino.example/x", network="off", platform="macos", protocol="tcp", port=443,
                    identity={"user": "jane@acme.example"}, scopes=["zpa", "dlp", "zcc", "zia_extras"], channels=CHANNELS)
    # Assert
    assert r.status_code == 200, r.text
    res = api["result"]()
    keys = [m["key"] for m in res["modules"]]
    assert keys[0] == "zpa_segment" and keys[-1] == "pac" and res["modules"][-1]["verdict"] == "forwarded"
    assert res["zia_modules"]["modules"] and res["zia_modules"]["traffic"]["label"].startswith("TCP/443")
    assert res["whatif"]["identity_label"].startswith("user jane@acme.example")
    import zia_path_modules as zpm
    assert all(set(m) >= set(MODULE_KEYS) and m["verdict"] in zpm.VERDICTS for m in res["modules"])


@pytest.mark.parametrize("port,status", [("443", 200), (8443, 200), (" 22 ", 200), ("", 200), ("0", 400), ("65536", 400), ("eighty", 400), (True, 400)])
def test_the_port_is_a_number_or_a_numeric_string_from_1_to_65535(api, port, status):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: one port definition: a number or numeric text, 1 to 65535; anything else is a 400 in words before sign-in."""
    # Act
    r = api["post"](destination="example.com", port=port, scopes=["zpa"])
    # Assert
    assert r.status_code == status, r.text
    if status == 400:
        assert "port" in r.json()["detail"] and api["built"] == []


@pytest.mark.parametrize("protocol,status", [("tcp", 200), ("UDP", 200), ("", 200), ("icmp", 400)])
def test_the_protocol_is_tcp_udp_or_empty(api, protocol, status):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: one protocol definition: TCP, UDP or empty (the URL's scheme decides)."""
    # Act
    r = api["post"](destination="example.com", protocol=protocol, scopes=["zpa"])
    # Assert
    assert r.status_code == status, r.text


def test_a_profile_only_request_uses_the_profiles_cloud(api, monkeypatch):
    """ASVS V4.2.1 · CWE-639 · CWE-1188: a body with only a profile id signs in to the profile's saved cloud, never the model's "production" default."""
    import dlp_api_server as srv
    import tenant_profiles
    # Arrange
    pid = tenant_profiles.upsert({"name": "Acme two", "cloud": "zscalertwo", "vanity_domain": "acme", "client_id": CREDS["client_id"],
                                  "customer_id": CREDS["customer_id"]})["id"]
    # Act
    r = TestClient(srv.app).post("/api/path-analyzer/start", json={"profile_id": pid, "destination": "git.corp.example", "scopes": ["zpa"], "from_page": True})
    # Assert
    assert r.status_code == 200, r.text
    assert api["result"]()["tenant_label"] == "acme (zscalertwo)"


def _cloud_default_models():
    import dlp_api_server as srv
    from pydantic import BaseModel
    # The model families whose unnamed cloud resolves to production (their
    # field default is blank so it never replaces a profile's cloud).
    families = (srv.AssessRequest, srv.MigrateRequest, srv.RemediationPlanRequest, srv.RemediationExecuteRequest)
    return sorted((c for c in vars(srv).values() if isinstance(c, type) and issubclass(c, BaseModel) and "profile_id" in c.model_fields
                   and "cloud" in c.model_fields and issubclass(c, families)), key=lambda c: c.__name__)


@pytest.mark.parametrize("model", _cloud_default_models(), ids=lambda c: c.__name__)
def test_every_request_model_with_a_production_default_takes_the_profiles_cloud(api, model):
    """ASVS V4.2.1 · CWE-639 · CWE-1188: the shared credential resolver (_tenant_creds) fills an unsent cloud from the profile, for every request model."""
    import dlp_api_server as srv
    import tenant_profiles
    # Arrange
    pid = tenant_profiles.upsert({"name": "Acme two", "cloud": "zscalertwo", "vanity_domain": "acme", "client_id": CREDS["client_id"]})["id"]
    # Act
    creds = srv._tenant_creds(model.model_validate({"profile_id": pid}))
    # Assert
    assert creds["cloud"] == "zscalertwo" and srv._tenant_creds(model.model_validate({}))["cloud"] == "production"


def test_a_typed_cloud_still_wins_over_the_profiles(api):
    """ASVS V4.2.1 · CWE-639: a cloud the body sends is used as sent."""
    import dlp_api_server as srv
    # Act
    TestClient(srv.app).post("/api/path-analyzer/start", json=dict(CREDS, cloud="zscalerthree", destination="git.corp.example", scopes=["zpa"], from_page=True))
    # Assert
    assert api["result"]()["tenant_label"] == "acme (zscalerthree)"


# ── the page ────────────────────────────────────────────────────────────
def _page():
    return open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()


def test_the_page_has_one_start_call_and_no_wrappers():
    """ASVS V14.4.3 · ASVS V1.14.5 · CWE-1059: Analyze is the page's own start call with the traffic fields; no page function is reassigned and fetch is never shadowed."""
    # Arrange
    html = _page()
    script = html[html.rindex("<script>"):]
    js = {n: open(os.path.join(ROOT, "static", n), encoding="utf-8").read() for n in ("path_modules.js", "path_whatif.js", "path_list.js")}
    # Assert
    assert not os.path.exists(os.path.join(ROOT, "static", "path_zpa.js")) and "path_zpa.js" not in html
    assert script.count("fetch('/api/path-analyzer/start'") == 1 and "full/start" not in html + "".join(js.values())
    assert "credBody(), scopeSelection(), traffic()," in script
    assert not re.search(r"^\s*(credBody|render|fetch|run)\s*=", script, re.M), "a page function is reassigned"
    assert "const fetch" not in script
    for name, text in js.items():
        assert "window.fetch =" not in text and "realFetch" not in text, name
        assert "MutationObserver" not in text, name


def test_the_page_controls_sit_in_its_bar_with_its_classes():
    """WCAG 2.2 SC 1.3.1 · WCAG 2.2 SC 4.1.2 · WCAG 2.2 SC 2.1.1: Traffic from, protocol, port, the workload fields and the what-if are labelled controls in the page's own markup."""
    # Arrange
    html = _page()
    bar = html[html.index('<nav class="rp-bar" aria-label="Page actions">'):html.index("</nav>")]
    panel = html[html.index('id="panel-one"'):html.index('id="panel-list"')]
    # Assert
    for needle in ('id="paSource" aria-label="Where the traffic comes from"', 'id="paProto" aria-label="Protocol of the traffic"',
                   'id="paPort" inputmode="numeric"', 'aria-label="Destination port'):
        assert needle in bar and '<label class="df-ctl' in bar, needle
    wl = html[html.index('id="paWorkload"'):html.index('<main class="rp-card">')]
    assert 'class="rp-bar pa-workload"' in html and 'role="group"' in wl and wl.count('<label class="df-ctl">') == 4
    assert 'aria-label="The workload\'s source IP address"' in wl
    assert '<details class="pa-framework pa-whatif" id="paWhatIf">' in panel and panel.count('class="rp-btn" data-wi-find=') == 4
    assert 'id="paWiLive" role="status" aria-live="polite"' in panel
    assert panel.index('id="paWhatIf"') < panel.index('id="paFramework"') < panel.index('id="paBody"')
    css = open(os.path.join(ROOT, "static", "reports.css"), encoding="utf-8").read()
    assert ".rp-bar .df-ctl[hidden]" in css and ".rp-bar.pa-workload { position: static; }" in css


def test_the_steps_before_zia_are_drawn_by_the_shared_renderer():
    """WCAG 2.2 SC 1.3.1 · ASVS V14.4.1: ZPA, connector and PAC hops go through PathModules (one hop renderer, one verdict vocabulary)."""
    # Arrange
    import zia_path_modules as zpm
    html, js = _page(), open(os.path.join(ROOT, "static", "path_modules.js"), encoding="utf-8").read()
    # Assert
    assert "${PathModules.section(res)}" in html and "PathWhatIf.section(res.whatif)" in html
    assert "function beforeSection(res)" in js and "res.modules" in js and "root.PathModules = { render, hop, section, portHint" in js
    table = js[js.index("const VERDICT = {"):js.index("const STATE = {")]
    assert set(re.findall(r"(\w+): \['", table)) == set(zpm.VERDICTS)
    data_flow = open(os.path.join(ROOT, "static", "data_flow.js"), encoding="utf-8").read()
    assert "zpa_allowed: ['Carried by ZPA'" in data_flow and "zpa_allowed: ['Carried by ZPA and allowed" in data_flow


def test_the_scope_page_offers_cloud_and_branch_connector_off_by_default():
    """ASVS V1.4.4 · CWE-272: the new scope key is listed with its read-only API role and is off unless ticked."""
    import data_flow
    import scope_permissions as sp
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert '<input type="checkbox" class="scope-cb" value="ztw" style="width:auto;cursor:pointer;">' in html
    assert "ztw" in data_flow.SCOPE_KEYS and data_flow.SCOPE_LABELS["ztw"] == "Cloud & Branch Connector"
    p = sp.get_scope_permissions("ztw")
    assert p and not p.get("permissions_write")
