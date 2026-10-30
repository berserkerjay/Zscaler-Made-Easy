"""Client Connector bypasses on the Path analyzer (zcc_bypass, data_flow.trace).

Oracle tables for every list the Client Connector step checks, in order:
the VPN gateway bypass, the IP-based application bypass (custom and
predefined IP-based applications and app services, by address, port and
protocol), Z-Tunnel 1.0's web ports, Enforce proxy's web-only traffic and
Z-Tunnel 2.0's own exclusions and inclusions. Each answer names the list
and the entry that decided, and anything the definitions cannot settle
stays unknown. A fake tenant (tests/test_qa_func_path.Tenant) answers every
read; nothing touches the network."""
from __future__ import annotations

import copy
import ipaddress

import pytest

import bulk_test as bt
import data_flow as df
import path_analyzer as pa
import zcc_bypass as zb
from test_qa_func_path import FULL, Tenant, hop, run

T1 = [{"id": 5, "name": "Fwd", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "ZSCALER_TUNNEL_1"}]}]
TWLP = [{"id": 5, "name": "Fwd", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "TUNNEL_WITH_LOCAL_PROXY"}]}]
PAC_MODE = [{"id": 5, "name": "Fwd", "forwardingProfileActions": [{"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "ENFORCE_PROXY"}]}]
CUSTOM = {"customAppContracts": [{"id": 77, "appName": "Teams media", "active": True,
                                  "appDataBlob": [{"proto": "UDP", "port": "3478-3481", "ipaddr": "52.112.0.0/14", "fqdn": ""}]},
                                 {"id": 78, "appName": "Bank portal", "active": True,
                                  "appDataBlob": [{"proto": "TCP", "port": "443", "ipaddr": "", "fqdn": "*.bank.example"}]}]}
PREDEFINED = {"appServiceContracts": [{"id": 3, "appSvcId": 903, "appName": "Zoom Meetings",
                                       "appDataBlob": [{"proto": "*", "port": "", "ipaddr": "170.114.0.0/16", "fqdn": ""}]}]}


def profiles(*ps, fwd=None, **routes):
    base = {"active": True, "forwardingProfileId": 5, "strictEnforcement": True, "installEndpointDlp": True, "sslCertInstall": True, "os": "windows"}
    out = {"/zcc/webPolicies": [dict(base, **p) for p in ps]}
    if fwd is not None:
        out["/zcc/forwardingProfiles"] = fwd
    out.update(routes)
    return out


def corp(**kw):
    return dict({"id": 1, "name": "Corp", "ruleOrder": 1}, **kw)


def zmod(res):
    return next(m for m in res["modules"] if m["key"] == "zcc")


def crit(res, name):
    return next(c for c in zmod(res)["criteria"] if c["name"] == name)


# ═══ VPN gateway bypass ════════════════════════════════════════════════
@pytest.mark.parametrize("gateways,dest,status,entry", [
    ("vpn.acme.example,198.51.100.9", "vpn.acme.example", "bypass", "vpn.acme.example"),       # the policyExtension's comma string
    (["vpn.acme.example"], "VPN.ACME.EXAMPLE", "bypass", "vpn.acme.example"),                    # a list; the host is case-insensitive
    ("*.vpn.acme.example", "eu.vpn.acme.example", "bypass", "*.vpn.acme.example"),               # a wildcard
    ("198.51.100.9", "198.51.100.9", "bypass", "198.51.100.9"),                                  # an address
    ("198.51.100.0/24:443", "198.51.100.20", "bypass", "198.51.100.0/24:443"),                   # a port on the entry is ignored
    ("vpn.acme.example", "files.example", "pass", None),                                         # another host
    ("vpn.acme.example", "203.0.113.5", "pass", None),                                           # an address is not a host-name gateway
    ("", "vpn.acme.example", "pass", None),                                                      # none configured
])
def test_vpn_gateway_bypass_oracle(gateways, dest, status, entry):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: a destination that is one of the app profile's VPN gateways leaves the device directly, and the step names the gateway."""
    res = run(dest, profiles(corp(policyExtension={"vpnGateways": gateways})))
    z = hop(res, "zcc")
    assert z["status"] == status, z["detail"]
    assert crit(res, "VPN gateway bypass")["state"] == ("match" if entry else "no_match")
    if entry:
        assert z["bypass"] == {"list": "VPN gateway bypass", "entry": entry}
        assert zmod(res)["verdict"] == "bypassed" and zmod(res)["rule"]["name"] == f"VPN gateway bypass: {entry}"
        assert res["verdict"]["outcome"] == "bypassed" and not res["verdict"]["reaches_zscaler"]


def test_vpn_gateways_are_read_from_every_spelling_of_the_profile():
    """ASVS V5.1.3 · CWE-1287: vpnGateways at the top level, in a policyExtension object or JSON string, are all read; an object or number is none."""
    import json
    assert zb.profile_lists({"vpnGateways": ["a.example"], "policyExtension": json.dumps({"vpnGateways": "b.example;c.example"})})["vpn_gateways"] \
        == ["a.example", "b.example", "c.example"]
    assert zb.profile_lists({"vpnGateways": 7})["vpn_gateways"] == [] and zb.profile_lists({"policyExtension": "{not json"})["vpn_gateways"] == []
    assert zb.split_entries("[FF00::/8], 10.0.0.0/8\n") == ["FF00::/8", "10.0.0.0/8"]


# ═══ IP-based application bypass ═══════════════════════════════════════
@pytest.mark.parametrize("ids,dest,proto,port,state,app", [
    ({"bypassCustomAppIds": ["77"]}, "52.112.1.1", "udp", 3478, "match", "Teams media"),       # address, port range and protocol match
    ({"bypassCustomAppIds": ["77"]}, "52.112.1.1", "udp", 3482, "no_match", None),            # the port is outside the range
    ({"bypassCustomAppIds": ["77"]}, "52.112.1.1", "tcp", 3478, "no_match", None),            # another protocol
    ({"bypassCustomAppIds": ["77"]}, "52.120.0.1", "udp", 3478, "no_match", None),            # another address
    ({"bypassCustomAppIds": ["78"]}, "www.bank.example", "tcp", 443, "match", "Bank portal"),  # a host name entry (fqdn)
    ({"bypassAppIds": ["3"]}, "170.114.5.5", "tcp", 443, "match", "Zoom Meetings"),            # predefined, any port and protocol
    ({"bypassAppIds": ["903"]}, "170.114.5.5", "udp", 8801, "match", "Zoom Meetings"),         # by its appSvcId
    ({"appServiceIds": ["3"]}, "170.114.5.5", "tcp", 443, "match", "Zoom Meetings"),           # an app service id finds the predefined app
    ({"bypassCustomAppIds": ["99"]}, "52.112.1.1", "udp", 3478, "no_match", None),            # an id the tenant does not define
])
def test_ip_based_application_bypass_oracle(ids, dest, proto, port, state, app):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: an IP-based application the app profile bypasses decides by address (or host name), port and protocol, and is named."""
    res = run(dest, profiles(corp(**ids), **{"/zcc/customIpBasedApps": CUSTOM, "/zcc/predefinedIpBasedApps": PREDEFINED}),
              protocol=proto, port=port)
    c = crit(res, "IP-based application bypass")
    assert c["state"] == state, c
    z = hop(res, "zcc")
    if app:
        assert z["status"] == "bypass" and z["bypass"]["list"] == "IP-based application bypass" and app in z["bypass"]["entry"]
        assert app in z["detail"] and res["verdict"]["outcome"] == "bypassed"
    else:
        assert z["status"] == "pass"


def test_a_host_name_against_address_only_apps_is_assumed_to_resolve_outside_them_and_says_so():
    """ASVS V1.4.4 · CWE-754: a host name is never resolved; an IP-based app with addresses only does not decide it, and the step says so."""
    res = run("teams.example", profiles(corp(bypassCustomAppIds=["77"]), **{"/zcc/customIpBasedApps": CUSTOM}), protocol="udp", port=3478)
    assert hop(res, "zcc")["status"] == "pass"
    assert any("not resolved" in n and "Teams media" in n for n in zmod(res)["notes"])


class Refuses(Tenant):
    def get(self, ep, p=None):
        if ep in ("/zcc/customIpBasedApps", "/zcc/predefinedIpBasedApps", "/zcc/webAppService"):
            return {"error": "denied"}, 403
        return super().get(ep, p)


def test_definitions_that_cannot_be_read_leave_an_address_unknown_never_not_bypassed():
    """ASVS V7.4.1 · CWE-754 · CWE-703: when the IP-based application definitions cannot be read, an address the profile may bypass is unknown, not "reaches Zscaler"."""
    res = pa.analyze(Refuses(profiles(corp(bypassCustomAppIds=["77"]))), "52.112.1.1", "off", "windows", scope=FULL, protocol="udp", port=3478)
    z = hop(res, "zcc")
    assert z["status"] == "unknown" and z["decided_by"] is None
    assert crit(res, "IP-based application bypass")["state"] == "unknown"
    assert res["verdict"]["outcome"] == "unknown" and res["verdict"]["headline"].startswith("Unable to verify how the device reaches")
    assert any("/zcc/customIpBasedApps: HTTP 403" in e for e in res["snapshot_for_cache"]["client_connector"]["errors"])


def test_the_definitions_are_read_only_when_a_profile_names_one():
    """ASVS V1.4.1 · CWE-272: the IP-based application definitions are read only when an app profile names one (nothing extra is read otherwise)."""
    class Counting(Tenant):
        seen: list = []

        def get(self, ep, p=None):
            self.seen.append(ep)
            return super().get(ep, p)
    t = Counting(profiles(corp()))
    t.seen = []
    df.read_client_connector(t)
    assert not any("IpBasedApps" in e or "webAppService" in e for e in t.seen)
    t2 = Counting(profiles(corp(bypassAppIds=["3"])))
    t2.seen = []
    out = df.read_client_connector(t2)
    assert "/zcc/predefinedIpBasedApps" in t2.seen and out["read_status"]["ip_apps"] == "read"


# ═══ Z-Tunnel 1.0, Tunnel with local proxy and Enforce proxy ═══════════
@pytest.mark.parametrize("fwd,proto,port,status", [
    (T1, "tcp", 443, "pass"), (T1, "tcp", 80, "pass"),
    (T1, "tcp", 22, "bypass"),                  # SSH: not a web port
    (T1, "tcp", 8080, "bypass"),                # a web port other than 80 and 443
    (T1, "udp", 443, "bypass"),                 # QUIC
    (TWLP, "tcp", 443, "pass"), (TWLP, "tcp", 3389, "bypass"),
    (PAC_MODE, "tcp", 443, "warn"),             # web traffic: the PAC file decides (see PAC file)
    (PAC_MODE, "tcp", 22, "bypass"), (PAC_MODE, "udp", 443, "bypass"),
])
def test_z_tunnel_1_and_enforce_proxy_carry_web_traffic_only(fwd, proto, port, status):
    """ASVS V1.4.4 · CWE-693 · CWE-697: Z-Tunnel 1.0 carries TCP 80 and 443 only and Enforce proxy web traffic only; anything else goes direct and the forwarding mode is named as what decided."""
    res = run("example.org", profiles(corp(), fwd=fwd), protocol=proto, port=port)
    f = hop(res, "forwarding")
    assert f["status"] == status, f["detail"]
    if status == "bypass":
        assert f["bypass"]["list"] == "Forwarding mode" and zmod(res)["verdict"] == "bypassed"
        assert crit(res, "Forwarding mode")["state"] == "match" and res["verdict"]["outcome"] == "bypassed"
        assert all(m["verdict"] == "not_reached" for m in res["zia_modules"]["modules"])


def test_z_tunnel_1_with_the_proxy_port_option_leaves_another_web_port_unknown():
    """ASVS V1.4.4 · CWE-754: with the app profile's proxy port option for Z-Tunnel 1.0 on, a web port other than 80 or 443 is unknown, not "direct"."""
    res = run("example.org", profiles(corp(policyExtension={"useProxyPortForT1": "1"}), fwd=T1), protocol="tcp", port=8080)
    assert hop(res, "forwarding")["status"] == "unknown" and res["verdict"]["outcome"] == "unknown"
    ssh = run("example.org", profiles(corp(policyExtension={"useProxyPortForT1": "1"}), fwd=T1), protocol="tcp", port=22)
    assert hop(ssh, "forwarding")["status"] == "bypass"


def test_z_tunnel_2_carries_every_port_and_protocol():
    """ASVS V1.4.4 · CWE-697: Z-Tunnel 2.0 carries SSH and QUIC too, unless its own lists leave the address out."""
    for proto, port in (("tcp", 22), ("udp", 443), ("tcp", 8080)):
        res = run("example.org", profiles(corp()), protocol=proto, port=port)
        assert hop(res, "forwarding")["status"] == "pass" and res["trace"]["reaches_zscaler"]
        assert crit(res, "Forwarding mode")["state"] == "no_match"


# ═══ Z-Tunnel 2.0's own lists ══════════════════════════════════════════
@pytest.mark.parametrize("prof,dest,status,decider", [
    ({"packetTunnelExcludeList": "52.0.0.0/8"}, "52.1.2.3", "bypass", "Z-Tunnel 2.0 destination exclusions"),
    ({"packetTunnelIncludeList": "198.51.100.0/24"}, "203.0.113.5", "bypass", "Z-Tunnel 2.0 destination inclusions"),
    ({"packetTunnelIncludeList": "198.51.100.0/24"}, "198.51.100.7", "pass", None),
    ({"packetTunnelIncludeList": "198.51.100.0/24"}, "example.org", "unknown", None),        # a host name limited inclusions would need resolved
    ({"packetTunnelIncludeList": "0.0.0.0/0"}, "example.org", "pass", None),
    ({"packetTunnelExcludeList": "10.0.0.0/8"}, "example.org", "pass", None),                # private exclusions: a public host is outside them
])
def test_z_tunnel_2_lists_oracle(prof, dest, status, decider):
    """ASVS V1.4.4 · CWE-697 · CWE-754: Z-Tunnel 2.0's exclusions and limited inclusions decide an address; a host name they would need resolved is unknown."""
    res = run(dest, profiles(corp(**prof)))
    f = hop(res, "forwarding")
    assert f["status"] == status, f["detail"]
    if decider:
        assert f["bypass"]["list"] == decider and zmod(res)["rule"]["name"].startswith(decider)
    if status == "unknown":
        assert crit(res, "Z-Tunnel 2.0 destination inclusions")["state"] == "unknown" and res["verdict"]["outcome"] == "unknown"


def test_z_tunnel_2_domain_lists_only_note_where_dns_is_resolved():
    """ASVS V1.4.4 · CWE-697: Z-Tunnel 2.0's domain exclusions decide where the DNS lookup goes, not whether the traffic is tunnelled; the step says so."""
    res = run("files.example", profiles(corp(policyExtension={"packetTunnelDnsExcludeList": "files.example"})))
    assert hop(res, "forwarding")["status"] == "pass"
    assert any("DNS lookup is resolved outside the tunnel" in n for n in zmod(res)["notes"])


# ═══ The step as one module, the order and the who-depends check ══════
def test_the_client_connector_step_lists_every_check_in_order():
    """ASVS V1.4.4 · CWE-1059: the Client Connector step shows each list it checked, in order, and no rule when nothing bypassed."""
    res = run("example.org", profiles(corp()))
    m = zmod(res)
    assert [c["name"] for c in m["criteria"]] == ["VPN gateway bypass", "Destination bypass (host names)", "Destination bypass (addresses)",
                                                  "IP-based application bypass", "Application bypass (by name)", "Forwarding mode",
                                                  "Z-Tunnel 2.0 destination exclusions", "Z-Tunnel 2.0 destination inclusions"]
    assert m["verdict"] == "forwarded" and m["rule"] is None and res["modules"][0]["key"] == "zcc"


def test_the_first_list_that_bypasses_is_the_one_named():
    """ASVS V1.4.4 · CWE-697: a VPN gateway that is also in the host name bypass is decided by the VPN gateway bypass (checked first)."""
    res = run("vpn.acme.example", profiles(corp(policyExtension={"vpnGateways": "vpn.acme.example"}, hostnameBypassForIpv4=["*.acme.example"])))
    assert hop(res, "zcc")["bypass"]["list"] == "VPN gateway bypass"
    assert [c["state"] for c in zmod(res)["criteria"][:2]] == ["match", "match"]


def test_a_scoped_profile_ahead_with_a_vpn_gateway_bypass_makes_the_path_depend_on_the_user():
    """ASVS V4.1.3 · CWE-863: a group's profile ahead of the everyone profile that bypasses a VPN gateway makes the answer depend on who the user is."""
    res = run("vpn.acme.example", profiles(dict(corp(name="Contractors", groups=[{"id": 32, "name": "Drivers"}]),
                                                policyExtension={"vpnGateways": "vpn.acme.example"}),
                                           {"id": 2, "name": "Corp", "ruleOrder": 2}))
    assert hop(res, "zcc")["status"] == "conditional" and res["verdict"]["outcome"] == "unknown" and zmod(res)["verdict"] == "conditional"


def test_out_of_scope_client_connector_is_not_assessed():
    """ASVS V4.1.3 · CWE-863: with ZCC not in scope the Client Connector step says not in scope and checks nothing."""
    scope = pa.path_scope(["dlp", "zia_extras"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    res = run("vpn.acme.example", profiles(corp(policyExtension={"vpnGateways": "vpn.acme.example"})), scope=scope)
    assert zmod(res)["verdict"] == "out_of_scope" and zmod(res)["criteria"] == []


def test_a_kept_read_from_before_the_bypass_lists_is_read_again():
    """ASVS V1.4.4 · CWE-1287: a tenant read kept from before the bypass lists were read (profile schema 4) is not reused."""
    res = run("example.org", profiles(corp()))
    snap = copy.deepcopy(res["snapshot_for_cache"])
    assert pa.reusable(snap, FULL, "windows")
    snap["client_connector"]["profile_schema"] = 4
    assert not pa.reusable(snap, FULL, "windows")


def test_test_a_list_answers_a_vpn_gateway_row_apart_from_another_row():
    """ASVS V1.4.4 · CWE-697: Test a list relates rows to the VPN gateways and IP-based apps, so a bypassed row never shares a tunnelled row's answer."""
    routes = profiles(corp(policyExtension={"vpnGateways": "198.51.100.9"}, bypassCustomAppIds=["77"]), **{"/zcc/customIpBasedApps": CUSTOM})
    rn = bt.run(Tenant(routes), bt.parse("198.51.100.8\n198.51.100.9\n52.112.1.1,3478,udp\n"), scope=FULL, lookup=False, sleep=lambda s: None)
    assert [rn.row(i)["result"] for i in range(3)] == ["allowed", "bypassed", "bypassed"]


def test_ip_app_entries_parse_defensively():
    """ASVS V5.1.3 · CWE-20 · CWE-1287: definition blobs as objects, JSON strings or bare addresses parse; junk and wrong types are none, never a crash."""
    apps = zb.normalize_apps({"customAppContracts": [{"id": 1, "appName": "A", "appDataBlob": ['{"ipaddr": "192.0.2.0/24", "port": "443"}', "198.51.100.1",
                                                                                                 7, None, [{"ipaddr": "203.0.113.0/24"}]]},
                                                     "junk", {"id": 2}]}, "custom")
    assert [e["ips"] for e in apps["1"]["entries"]] == [["192.0.2.0/24"], ["198.51.100.1"], ["203.0.113.0/24"]]
    assert apps["2"]["entries"] == []
    ip = ipaddress.ip_address("192.0.2.5")
    assert zb.app_hit(apps["1"], ip, "", "tcp", 443)[0] == "match"
    assert zb.app_hit({"entries": [{"ips": ["192.0.2.0/24"], "fqdns": [], "ports": ["abc"], "proto": ""}]}, ip, "", "tcp", 443)[0] == "unknown"
    assert zb.app_hit({"entries": [{"ips": ["192.0.2.0/24"], "fqdns": [], "ports": [], "proto": "icmp"}]}, ip, "", "tcp", 443)[0] == "unknown"


def test_the_sample_tenant_contractors_bypass_names_their_custom_app():
    """ASVS V1.4.4 · CWE-697: on the sample tenant the contractors' custom IP-based app (Depot handheld sync) is read and decides for its addresses."""
    import offline_tenant
    st = offline_tenant.sample_store()
    zcc = df.read_client_connector(offline_tenant.OfflineRawClient(st, offline_tenant.creds_for(st)))
    assert zcc["ip_apps"]["apps"]["custom"]["5001"]["name"] == "Depot handheld sync"
    contractors = next(p for p in zcc["app_profiles"] if p["name"] == "Windows - Contractors")
    c, hit, _n = zb.ip_app_check(contractors["lists"], zcc["ip_apps"], "", ipaddress.ip_address("198.51.100.20"), "tcp", 443)
    assert c["state"] == "match" and hit["name"] == "Depot handheld sync"
