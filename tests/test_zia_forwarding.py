"""ZIA forwarding and traffic path: the FWD.* assessment checks
(zscaler_full_checks, analysis in zia_forwarding) and the Path analyzer's
Forwarding control step (zia_path_modules). Proxy chaining with and
without a fallback, connector DIRECT rules, ZPA and dedicated IP gateways,
data centre exclusions, GRE VIP diversity, IPv6, NAT control, Virtual
Service Edges and DNS gateway failover; not licensed is not applicable;
read-only, in scope only, untrusted input bounded, no secret shown.
Fake tenants and the made-up sample tenant only: no network."""
from __future__ import annotations

import copy
import json
import os
import re
import threading

import pytest

import dlp_assessment_full_auto as engine
import offline_tenant as ot
import path_analyzer as pa
import sample_tenant
import scope_permissions
import zia_forwarding as zf
import zia_path_modules as zpm
import zscaler_full_checks as zfc
from dlp_assessment_full_auto import R
from test_path_zia_modules import Tenant
from zia_module_fixtures import MODULE_ROUTES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FWD_PATHS = ("/zia/forwardingRules", "/zia/proxyGateways", "/zia/zpaGateways", "/zia/datacenters", "/zia/dcExclusions", "/zia/greTunnels",
             "/zia/vips", "/zia/ipv6config", "/zia/ipv6config/nat64prefix", "/zia/dedicatedIPGateways/lite", "/zia/dnatRules",
             "/zia/virtualZenClusters", "/zia/virtualZenNodes", "/zia/dnsGateways")
CHECK = {cid: fn for cid, _sec, _label, fn in zfc.PLATFORM_REG}


class Cl:
    """The assessment client: GET only, (data, status) per short endpoint;
    an endpoint not given answers 404 (not licensed). Records every read."""

    def __init__(self, routes=None):
        self.routes = dict(routes or {})
        self.reads = []

    def get(self, ep, params=None):
        self.reads.append(ep)
        v = self.routes.get(ep)
        if v is None:
            return {"error": "not found"}, 404
        return v if isinstance(v, tuple) else (v, 200)


def run(cid, **routes):
    """One FWD check, permission-guarded as the registry runs it."""
    cl = Cl({k.replace("__", "/"): v for k, v in routes.items()})
    return CHECK[cid](cl), cl


def rule(name, method, rtype="FORWARDING", **kw):
    return dict({"id": abs(hash(name)) % 10 ** 6, "name": name, "type": rtype, "state": "ENABLED", "forwardMethod": method, "order": 1}, **kw)


# ── The checks, one by one ───────────────────────────────────────────
def test_fwd1_connector_direct_rules_are_named_and_zia_direct_is_not_a_bypass():
    """ASVS V1.14.6 · CWE-693 · WSTG-CONF-01: a connector DIRECT rule with no destination fails, a named one is reviewed; ZIA's own DIRECT and disabled rules are not bypasses."""
    broad = rule("All direct", "DIRECT", "EC_RDR")
    narrow = rule("Updates direct", "DIRECT", "EC_RDR", destAddresses=["updates.example"])
    zia = rule("Default", "DIRECT", defaultRule=True, order=-1)
    off = dict(broad, name="Off", state="DISABLED")
    r, _ = run("FWD.1", **{"/zia/forwardingRules": [broad, narrow, zia]})
    assert r.status == R.FAIL and "All direct" in r.detail and "Why it matters" in r.detail and "Best Practice" in r.detail
    r, _ = run("FWD.1", **{"/zia/forwardingRules": [narrow, zia, off]})
    assert r.status == R.WARN and "Updates direct" in r.detail and "Off" not in r.detail
    r, _ = run("FWD.1", **{"/zia/forwardingRules": [zia, rule("Chain", "PROXYCHAIN")]})
    assert r.status == R.PASS
    assert run("FWD.1", **{"/zia/forwardingRules": []})[0].status == R.INFO


@pytest.mark.parametrize("cid", [f"FWD.{n}" for n in range(1, 11)])
def test_not_licensed_is_not_applicable_and_never_scored(cid):
    """ASVS V1.14.6 · CWE-754: every list answering 404 (not licensed) gives INFO "not applicable", which the score leaves out."""
    r, cl = run(cid)
    assert r.status == R.INFO and ("Not applicable" in r.detail or "not licensed" in r.detail), r.detail
    assert cl.reads and all(ep in FWD_PATHS or ep == "/zia/locations" for ep in cl.reads), cl.reads
    secs, pct = engine.compute([{"id": cid, "sec": "ZIA — Forwarding", "status": r.status}])
    assert pct is None and secs["ZIA — Forwarding"]["scored"] == 0


def test_fwd2_proxy_chaining_needs_a_gateway_and_a_fallback():
    """ASVS V1.14.6 · CWE-1188 · CWE-636: no gateway or a gateway with no secondary that does not fail closed fails; fail closed is reviewed; a secondary passes."""
    chain = rule("Chain partner", "PROXYCHAIN", proxyGateway={"id": 9, "name": "GW"})
    gw = {"id": 9, "name": "GW", "primaryProxy": {"id": 1, "name": "P1"}, "failClosed": False}
    assert run("FWD.2", **{"/zia/forwardingRules": [rule("No gw", "PROXYCHAIN")], "/zia/proxyGateways": [gw]})[0].status == R.FAIL
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [rule("Gone", "PROXYCHAIN", proxyGateway={"id": 77})], "/zia/proxyGateways": [gw]})
    assert r.status == R.FAIL and "Gone" in r.detail
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [chain], "/zia/proxyGateways": [gw]})
    assert r.status == R.FAIL and "does not fail closed" in r.detail
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [chain], "/zia/proxyGateways": [dict(gw, failClosed=True)]})
    assert r.status == R.WARN and "fails closed" in r.detail
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [chain], "/zia/proxyGateways": [dict(gw, secondaryProxy={"id": 2, "name": "P2"})]})
    assert r.status == R.PASS
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [chain], "/zia/proxyGateways": ({"error": "boom"}, 500)})
    assert r.status == R.INFO and "not known" in r.detail
    assert run("FWD.2", **{"/zia/forwardingRules": [rule("D", "DIRECT")]})[0].status == R.INFO


def test_fwd3_zpa_gateways_need_a_server_group_segments_and_a_rule():
    """ASVS V1.14.6 · CWE-1188: a ZPA gateway with no server group or segment, or a ZPA rule with no gateway, fails; an unused gateway is reviewed."""
    gw = {"id": 5, "name": "Anchor", "zpaServerGroup": {"externalId": "1", "name": "SG"}, "zpaAppSegments": [{"externalId": "2", "name": "App"}]}
    use = rule("Anchor app", "ZPA", zpaGateway={"id": 5, "name": "Anchor"})
    assert run("FWD.3", **{"/zia/zpaGateways": [gw], "/zia/forwardingRules": [use]})[0].status == R.PASS
    r, _ = run("FWD.3", **{"/zia/zpaGateways": [dict(gw, zpaServerGroup=None)], "/zia/forwardingRules": [use]})
    assert r.status == R.FAIL and "no server group" in r.detail
    r, _ = run("FWD.3", **{"/zia/zpaGateways": [gw], "/zia/forwardingRules": [use, rule("Bare", "ZPA")]})
    assert r.status == R.FAIL and "Bare" in r.detail
    r, _ = run("FWD.3", **{"/zia/zpaGateways": [gw], "/zia/forwardingRules": []})
    assert r.status == R.WARN and "not used" in r.detail
    assert run("FWD.3", **{"/zia/zpaGateways": [], "/zia/forwardingRules": []})[0].status == R.INFO


def test_fwd4_data_centre_exclusions_in_force(monkeypatch):
    """ASVS V1.14.6 · CWE-1188: only exclusions in force count (not expired, started, not ended); open-ended or longer than 30 days are named."""
    now = 1_800_000_000
    monkeypatch.setattr(zf.time, "time", lambda: now)
    rows = [{"dcid": 1, "dcName": {"name": "OLD"}, "expired": True, "startTime": now - 9e5},
            {"dcid": 2, "dcName": {"name": "LATER"}, "startTime": now + 3600},
            {"dcid": 3, "dcName": {"name": "ENDED"}, "startTime": now - 9e5, "endTime": now - 60}]
    assert run("FWD.4", **{"/zia/dcExclusions": rows})[0].status == R.PASS
    short = {"dcid": 4, "dcName": {"name": "SHORT"}, "startTime": now - 3600, "endTime": now + 2 * 86400}
    r, _ = run("FWD.4", **{"/zia/dcExclusions": rows + [short]})
    assert r.status == R.WARN and "SHORT" in r.detail and "each with an end date" in r.detail
    forever = {"dcid": 5, "dcName": {"name": "FOREVER"}, "startTime": (now - 3600) * 1000}   # milliseconds are accepted
    r, _ = run("FWD.4", **{"/zia/dcExclusions": [forever]})
    assert r.status == R.WARN and "FOREVER (no end date)" in r.detail
    assert [x["name"] for x in zf.active_exclusions(rows + [short, forever], now)] == ["SHORT", "FOREVER"]


def test_fwd5_gre_tunnels_need_a_secondary_vip_in_another_data_centre():
    """ASVS V1.14.6 · CWE-1188: a missing secondary, one VIP for both, or two VIPs in one data centre fail; the public VIP list places VIPs the tunnel does not."""
    vips = [{"dataCenter": "SEA1", "greIps": ["203.0.113.1"]}, {"dataCenter": "SJC4", "greIps": ["203.0.113.2", "203.0.113.3"]}]
    good = {"id": 1, "comment": "HQ", "sourceIp": "198.51.100.1", "primaryDestVip": {"virtualIp": "203.0.113.1"}, "secondaryDestVip": {"virtualIp": "203.0.113.2"}}
    assert run("FWD.5", **{"/zia/greTunnels": [good], "/zia/vips": vips})[0].status == R.PASS
    same = dict(good, comment="Depot", primaryDestVip={"virtualIp": "203.0.113.2"}, secondaryDestVip={"virtualIp": "203.0.113.3"})
    r, _ = run("FWD.5", **{"/zia/greTunnels": [good, same], "/zia/vips": vips})
    assert r.status == R.FAIL and "Depot (198.51.100.1) (SJC4)" in r.detail
    lone = dict(good, comment="Lone", secondaryDestVip=None)
    assert "no secondary VIP: Lone" in run("FWD.5", **{"/zia/greTunnels": [lone]})[0].detail
    named = dict(good, primaryDestVip={"virtualIp": "192.0.2.1", "datacenter": "AMS1"}, secondaryDestVip={"virtualIp": "192.0.2.2", "datacenter": "FRA4"})
    assert run("FWD.5", **{"/zia/greTunnels": [named]})[0].status == R.PASS      # placed by the tunnel itself, no VIP list needed
    unplaced = dict(good, primaryDestVip={"virtualIp": "192.0.2.9"}, secondaryDestVip={"virtualIp": "192.0.2.8"})
    assert run("FWD.5", **{"/zia/greTunnels": [unplaced], "/zia/vips": vips})[0].status == R.WARN
    assert run("FWD.5", **{"/zia/greTunnels": []})[0].status == R.INFO


def test_fwd6_ipv6_off_with_locations_and_on_without_nat64():
    """ASVS V1.14.6 · CWE-693: IPv6 off while locations carry it fails, off with locations is reviewed, on without a NAT64 prefix is reviewed, on with one passes."""
    locs = [{"id": 1, "name": "HQ", "ipv6Enabled": True}, {"id": 2, "name": "Depot"}]
    r, _ = run("FWD.6", **{"/zia/ipv6config": {"ipV6Enabled": False}, "/zia/locations": locs})
    assert r.status == R.FAIL and "HQ" in r.detail
    assert run("FWD.6", **{"/zia/ipv6config": {"ipV6Enabled": False}, "/zia/locations": locs[1:]})[0].status == R.WARN
    assert run("FWD.6", **{"/zia/ipv6config": {"ipV6Enabled": False}, "/zia/locations": []})[0].status == R.INFO
    assert run("FWD.6", **{"/zia/ipv6config": {"ipV6Enabled": True}, "/zia/ipv6config/nat64prefix": []})[0].status == R.WARN
    r, _ = run("FWD.6", **{"/zia/ipv6config": {"ipV6Enabled": True}, "/zia/ipv6config/nat64prefix": [{"id": 1, "prefixMask": "64:ff9b::/96"}]})
    assert r.status == R.PASS and "1 NAT64" in r.detail


def test_fwd7_to_fwd10_failover_and_scope():
    """ASVS V1.14.6 · CWE-1188 · CWE-636: dedicated IP, NAT control, Virtual Service Edge and DNS gateway findings, each with the passing shape beside it."""
    ok_gw = {"id": 1, "name": "Egress", "primaryDataCenter": {"name": "SEA1"}, "secondaryDataCenter": {"name": "SJC4"}}
    assert run("FWD.7", **{"/zia/dedicatedIPGateways/lite": [ok_gw]})[0].status == R.PASS
    r, _ = run("FWD.7", **{"/zia/dedicatedIPGateways/lite": [dict(ok_gw, secondaryDataCenter={"name": "sea1"}), dict(ok_gw, name="Solo", secondaryDataCenter=None)]})
    assert r.status == R.WARN and "Solo" in r.detail and "same data centre" in r.detail
    scoped = {"id": 1, "name": "Relay", "state": "ENABLED", "destAddresses": ["relay.example"], "redirectIp": "198.51.100.4", "redirectPort": 8443}
    assert run("FWD.8", **{"/zia/dnatRules": [scoped]})[0].status == R.PASS
    r, _ = run("FWD.8", **{"/zia/dnatRules": [dict(scoped, name="All", destAddresses=[])]})
    assert r.status == R.WARN and "All (to 198.51.100.4:8443)" in r.detail
    assert run("FWD.8", **{"/zia/dnatRules": [dict(scoped, redirectIp=None)]})[0].status == R.FAIL
    assert run("FWD.8", **{"/zia/dnatRules": [{"id": 9, "name": "Default", "defaultRule": True}]})[0].status == R.INFO
    two = [{"id": 11, "name": "n1", "status": "ENABLED", "inProduction": True}, {"id": 12, "name": "n2", "status": "ENABLED", "inProduction": True}]
    cluster = {"id": 10, "name": "VSE", "status": "ENABLED", "virtualZenNodes": [{"id": 11}, {"id": 12}]}
    assert run("FWD.9", **{"/zia/virtualZenClusters": [cluster], "/zia/virtualZenNodes": two})[0].status == R.PASS
    down = [two[0], dict(two[1], status="DISABLED")]
    r, _ = run("FWD.9", **{"/zia/virtualZenClusters": [cluster], "/zia/virtualZenNodes": down})
    assert r.status == R.FAIL and "VSE (1 working node)" in r.detail
    r, _ = run("FWD.9", **{"/zia/virtualZenClusters": [cluster], "/zia/virtualZenNodes": two + [{"id": 13, "name": "stray", "status": "ENABLED"}]})
    assert r.status == R.WARN and "stray" in r.detail
    dns = {"id": 1, "name": "Resolver", "primaryIpOrFqdn": "198.51.100.53", "failureBehavior": "FAIL_RET_ERR"}
    assert run("FWD.10", **{"/zia/dnsGateways": [dns]})[0].status == R.FAIL
    assert run("FWD.10", **{"/zia/dnsGateways": [dict(dns, failureBehavior="FAIL_ALLOW_IGNORE_DNAT")]})[0].status == R.WARN
    assert run("FWD.10", **{"/zia/dnsGateways": [dict(dns, secondaryIpOrFqdn="198.51.100.54")]})[0].status == R.PASS


def test_a_refused_read_is_not_permitted_never_judged():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a 403 on any read the check makes turns its verdict into "not permitted" (INFO), never pass or fail."""
    r, _ = run("FWD.2", **{"/zia/forwardingRules": [rule("Chain", "PROXYCHAIN", proxyGateway={"id": 9})], "/zia/proxyGateways": ({"error": "denied"}, 403)})
    assert r.status == R.INFO and ("Not permitted" in r.detail or "Access denied" in r.detail)
    r, _ = run("FWD.5", **{"/zia/greTunnels": ({"error": "denied"}, 401)})
    assert r.status == R.INFO and "not readable (HTTP 401" in r.detail


def test_the_checks_are_registered_under_zia_platform_with_plain_titles():
    """ASVS V1.14.6 · CWE-1059: ten FWD checks in "ZIA — Forwarding" (in scope with ZIA platform), each with a plain title and one of the existing statuses."""
    fwd = [c for c in zfc.PLATFORM_REG if c[0].startswith("FWD.")]
    assert [c[0] for c in fwd] == [f"FWD.{n}" for n in range(1, 11)]
    assert all(c[1] == "ZIA — Forwarding" and c[1].startswith("ZIA") and 10 <= len(c[2]) <= 60 for c in fwd)
    assert len({c[2] for c in fwd}) == 10


# ── Read-only, bounded, no secret ────────────────────────────────────
class GetOnly(Cl):
    def __getattr__(self, name):          # post, put, delete, request...: any other call is a write attempt
        raise AssertionError(f"the check called {name}")


def test_the_checks_only_read_and_only_their_own_endpoints():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: every FWD check only GETs, and only the forwarding endpoints (plus the locations list for IPv6)."""
    routes = {ep: [] for ep in FWD_PATHS}
    routes["/zia/ipv6config"] = {"ipV6Enabled": False}
    for cid in CHECK:
        if cid.startswith("FWD."):
            cl = GetOnly(routes)
            CHECK[cid](cl)
            assert set(cl.reads) <= set(FWD_PATHS) | {"/zia/locations"}, (cid, cl.reads)
    assert set(FWD_PATHS) <= set(scope_permissions.SCOPE_PERMISSIONS["zia_extras"]["endpoints_used"])


JUNK = [None, "x", 7, [], ["nested"], {"name": None}, {"name": "<script>alert(1)</script>" + "A" * 5000, "state": "ENABLED", "forwardMethod": "DIRECT",
                                                       "type": "EC_RDR", "secondaryProxy": 3, "virtualZenNodes": "notalist"}]


@pytest.mark.parametrize("cid", [f"FWD.{n}" for n in range(1, 11)])
def test_hostile_tenant_answers_never_crash_and_names_are_capped(cid):
    """ASVS V5.1.4 · CWE-20 · CWE-400 · WSTG-INPV-01: lists of junk, wrong types and very long names give a result; a name is cut to 120 characters and at most five are listed."""
    many = [dict(JUNK[-1], name=f"rule-{i}") for i in range(40)]
    routes = {ep: JUNK + many for ep in FWD_PATHS}
    routes["/zia/ipv6config"] = ["junk"]
    r = CHECK[cid](Cl(routes))
    assert r.status in (R.PASS, R.FAIL, R.WARN, R.INFO)
    assert "A" * 121 not in r.detail and len(r.detail) < 2500
    groups = max(1, r.detail.count(": "))
    assert len(re.findall(r"rule-\d+", r.detail)) <= 5 * groups and ("more" in r.detail or "rule-" not in r.detail)


def test_no_credential_reaches_a_finding():
    """ASVS V8.3.4 · CWE-200 · CWE-532: certificate, key and password fields on gateways and proxies never appear in a check's words or the path step."""
    canary = "SECRET-CANARY-7f3e"
    gw = {"id": 9, "name": "GW", "failClosed": False, "primaryProxy": {"id": 1, "name": "P1", "cert": canary, "password": canary}, "apiKey": canary}
    chain = rule("Chain", "PROXYCHAIN", proxyGateway={"id": 9, "name": "GW"}, destAddresses=["chat.openai.com"], description=canary)
    dns = {"id": 3, "name": "DNS", "primaryIpOrFqdn": "198.51.100.53", "psk": canary}
    for cid in ("FWD.1", "FWD.2", "FWD.10"):
        r, _ = run(cid, **{"/zia/forwardingRules": [chain], "/zia/proxyGateways": [gw], "/zia/dnsGateways": [dns]})
        assert canary not in r.detail
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [chain], "/zia/proxyGateways": [gw], "/zia/dnsGateways": [dns]})
    m = fwd_module(res)
    shown = json.dumps({k: v for k, v in res.items() if k != "snapshot_for_cache"}, default=str)
    assert canary not in shown and m["rule"]["name"] == "Chain"


# ── The sample tenant and snapshots ──────────────────────────────────
def sample_client():
    return ot.OfflineRawClient(ot.sample_store(reset=True), {})


def test_the_sample_tenant_answers_every_forwarding_read_and_shows_its_gaps():
    """ASVS V1.14.6 · CWE-1059: Larkspur Freight answers each new read offline, with the gaps the checks should find."""
    cl = sample_client()
    for ep in FWD_PATHS:
        _data, code = cl.get(ep)
        assert code == 200, ep
    got = {cid: CHECK[cid](cl).status for cid in CHECK if cid.startswith("FWD.")}
    assert got == {"FWD.1": R.WARN, "FWD.2": R.FAIL, "FWD.3": R.PASS, "FWD.4": R.WARN, "FWD.5": R.FAIL, "FWD.6": R.WARN,
                   "FWD.7": R.PASS, "FWD.8": R.PASS, "FWD.9": R.FAIL, "FWD.10": R.FAIL}, got
    resp = sample_tenant.responses()
    assert all(f"/zia/api/v1/{ep[5:]}" in resp for ep in FWD_PATHS)


def test_a_snapshot_saves_the_forwarding_reads_only_with_zia_platform_and_reopens_them():
    """ASVS V4.1.3 · CWE-285 · CWE-502: the snapshot reads the forwarding lists only when ZIA platform is ticked, and an opened snapshot answers the checks the same."""
    plan = ot.capture_plan(["zia_extras"])
    assert set(FWD_PATHS) <= set(plan)
    assert not set(FWD_PATHS) & set(ot.capture_plan(["dlp", "zpa", "zcc"]))
    out = ot.capture(sample_client(), ["zia_extras"], {}, lambda m: None)
    assert not out["stopped"]
    doc = {"format": ot.FORMAT, "version": ot.VERSION, "meta": {"tenant_label": "Fwd"}, "responses": out["responses"]}
    store = ot.open_document(json.dumps(doc))
    snap = ot.OfflineRawClient(store, {})
    live = sample_client()
    for cid in CHECK:
        if cid.startswith("FWD."):
            a, b = CHECK[cid](snap), CHECK[cid](live)
            assert (a.status, a.detail) == (b.status, b.detail), cid


# ── The Path analyzer's Forwarding control step ──────────────────────
CHAIN_GW = {"id": 9, "name": "Partner GW", "primaryProxy": {"id": 1, "name": "P1"}, "failClosed": False}


def path_run(dest, fwd_routes, protocol=None, port=None, tenant_cls=Tenant, **kw):
    routes = dict(MODULE_ROUTES, **fwd_routes)
    return pa.analyze(tenant_cls(routes), dest, "off", "windows", scope=pa.full_path_scope(), protocol=protocol, port=port, **kw)


def fwd_module(res):
    return next(m for m in res["zia_modules"]["modules"] if m["key"] == "fwdctl")


def fwd_hop(res):
    return next(h for h in res["trace"]["hops"] if h["key"] == "fwdctl")


def test_proxy_chaining_without_a_fallback_is_a_weak_point_with_its_fix():
    """ASVS V1.14.6 · CWE-636 · WSTG-BUSL-01: the deciding chain rule is named with its gateway; no secondary proxy makes the hop a weak point with the fix."""
    chain = rule("Chain AI", "PROXYCHAIN", proxyGateway={"id": 9, "name": "Partner GW"}, destAddresses=["chat.openai.com"])
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [chain, rule("Default", "DIRECT", defaultRule=True, order=-1)], "/zia/proxyGateways": [CHAIN_GW]})
    m, h = fwd_module(res), fwd_hop(res)
    assert m["verdict"] == "forwarded" and m["certainty"] == "definite" and m["rule"]["name"] == "Chain AI"
    assert m["rule"]["action"] == "PROXYCHAIN via Partner GW" and any(c["name"] == "Destination" and c["state"] == "match" for c in m["criteria"])
    assert h["status"] == "warn" and h["weak_point"]["title"] == "Proxy chaining without a fallback proxy" and "secondary proxy" in h["weak_point"]["fix"]
    assert any(i["hop"] == "fwdctl" and i["fix"] for i in res["verdict"]["impacts"])
    ok = path_run("chat.openai.com", {"/zia/forwardingRules": [chain], "/zia/proxyGateways": [dict(CHAIN_GW, secondaryProxy={"id": 2, "name": "P2"})]})
    assert fwd_hop(ok)["status"] == "pass" and not any(i["hop"] == "fwdctl" for i in ok["verdict"]["impacts"])
    other = path_run("news.example", {"/zia/forwardingRules": [chain], "/zia/proxyGateways": [CHAIN_GW]})
    assert fwd_module(other)["rule"] is None and fwd_module(other)["verdict"] == "forwarded" and "direct" in fwd_module(other)["detail"]


def test_a_drop_rule_blocks_the_path_and_the_verdict_names_it():
    """ASVS V4.1.3 · CWE-670: a matching DROP forwarding rule is a definite block; the path stops there and the headline names the rule."""
    drop = rule("Drop gambling", "DROP", resCategories=["GAMBLING"])
    res = path_run("casino.example", {"/zia/forwardingRules": [drop]})
    assert res["zia_modules"]["stops_at"] not in (None, "fwdctl") and fwd_module(res)["verdict"] == "not_reached", "an earlier module blocks gambling first"
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [rule("Drop all", "DROP")]})
    assert fwd_module(res)["verdict"] == "block" and res["zia_modules"]["stops_at"] == "fwdctl"
    assert res["verdict"]["outcome"] == "blocked" and "Forwarding control" in res["verdict"]["headline"] and "Drop all" in res["verdict"]["headline"]


def test_an_earlier_scoped_rule_with_another_method_makes_the_step_conditional():
    """ASVS V1.14.6 · CWE-670: an earlier rule for a group (not evaluated for any user) that would drop makes the step conditional, naming it."""
    scoped = rule("Drop contractors", "DROP", groups=[{"id": 1, "name": "Contractors"}])
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [scoped, dict(rule("Default", "DIRECT", defaultRule=True), order=-1)]})
    m = fwd_module(res)
    assert m["certainty"] == "conditional" and m["could_override"][0]["name"] == "Drop contractors"
    assert any("Forwarding control" in x for x in res["verdict"]["certainty_reasons"])


def test_not_licensed_is_not_applicable_and_a_refused_read_is_unknown():
    """ASVS V7.4.1 · CWE-754 · CWE-755: a 404 makes the step not applicable and adds no uncertainty; a 403 is "could not be read", never an empty rule list."""
    res = path_run("chat.openai.com", {})
    m = fwd_module(res)
    assert m["status"] == "not_applicable" and "not available on this tenant" in m["detail"]
    assert not any("Forwarding control" in x for x in res["verdict"]["certainty_reasons"])
    assert fwd_hop(res)["status"] == "na"

    class Refusing(Tenant):
        def get(self, ep, p=None):
            if ep == "/zia/forwardingRules":
                self.paths.append(ep)
                return {"error": "forbidden"}, 403
            return super().get(ep, p)

    res = path_run("chat.openai.com", {}, tenant_cls=Refusing)
    m = fwd_module(res)
    assert m["status"] == "unread" and m["verdict"] == "unknown" and "HTTP 403" in m["detail"]
    assert any(x.startswith("Forwarding control: not established") for x in res["verdict"]["certainty_reasons"])


def test_connector_rules_do_not_decide_a_device_path():
    """ASVS V4.1.3 · CWE-670: Cloud or Branch Connector forwarding rules (EC types) belong to the workload path; a device's path ignores them."""
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [rule("Connector drop", "DROP", "EC_RDR")]})
    m = fwd_module(res)
    assert m["rule"] is None and m["verdict"] == "forwarded" and m["considered"] == 0


def test_nat_control_ipv6_exclusions_and_dns_gateway_notes():
    """ASVS V1.14.6 · CWE-670 · CWE-1188: a NAT control rewrite, IPv6 off for an IPv6 destination, an exclusion in force and a DNS gateway with no failover are said on the path."""
    dnat = {"id": 1, "name": "Relay", "state": "ENABLED", "destAddresses": ["chat.openai.com"], "redirectIp": "198.51.100.4", "redirectPort": 8443}
    routes = {"/zia/forwardingRules": [], "/zia/dnatRules": [dnat], "/zia/ipv6config": {"ipV6Enabled": False},
              "/zia/dcExclusions": [{"dcid": 2, "dcName": {"name": "SJC4"}, "startTime": 1}]}
    m = fwd_module(path_run("chat.openai.com", routes))
    assert any("rewrites the destination to 198.51.100.4:8443" in n for n in m["notes"]) and m["dnat"]["to"] == "198.51.100.4:8443"
    assert any("Data centre exclusion in force: SJC4" in n for n in m["notes"])
    v6 = path_run("2001:db8::7", routes)
    assert any("IPv6 is off in ZIA" in n for n in fwd_module(v6)["notes"]) and fwd_hop(v6)["status"] == "warn"
    assert not any("IPv6" in n for n in m["notes"])
    redirect = {"id": 811, "order": 1, "name": "To resolver", "state": "ENABLED", "action": "REDIR_REQ", "destAddresses": ["chat.openai.com"],
                "dnsGateway": {"id": 3, "name": "Depot DNS"}}
    dns_routes = dict(routes, **{"/zia/firewallDnsRules": [redirect], "/zia/dnsGateways": [{"id": 3, "name": "Depot DNS", "failureBehavior": "FAIL_RET_ERR"}]})
    d = next(x for x in path_run("chat.openai.com", dns_routes)["zia_modules"]["modules"] if x["key"] == "dns")
    assert d["verdict"] == "redirect" and any("answers with an error when its resolver is down" in n for n in d["notes"])


def test_nothing_is_read_for_the_step_without_zia_platform_and_stop_ends_the_read():
    """ASVS V4.1.3 · CWE-285 · CWE-400 · WSTG-ATHZ-02: without ZIA platform no forwarding endpoint is asked; Stop during the forwarding reads ends the analysis."""
    scope = pa.path_scope(["dlp", "zcc"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    t = Tenant(dict(MODULE_ROUTES, **{"/zia/forwardingRules": [rule("Drop all", "DROP")]}))
    res = pa.analyze(t, "chat.openai.com", "off", "windows", scope=scope)
    assert not set(t.paths) & set(FWD_PATHS)
    assert fwd_module(res)["status"] == "out_of_scope"
    stop = threading.Event()

    class Stopping(Tenant):
        def get(self, ep, p=None):
            if ep in FWD_PATHS:
                stop.set()
            return super().get(ep, p)

    s = Stopping(dict(MODULE_ROUTES))
    with pytest.raises(pa.Stopped):
        pa.analyze(s, "chat.openai.com", "off", "windows", scope=pa.full_path_scope(), cancel=stop)
    assert sum(1 for ep in s.paths if ep in FWD_PATHS) == 1, "nothing more is asked once Stop is set"


def test_the_step_keeps_the_shared_hop_shape_and_its_place():
    """ASVS V1.1.2 · CWE-20: the step is the last ZIA module, in the shared shape, and its hop sits before the incident hop."""
    res = path_run("chat.openai.com", {"/zia/forwardingRules": [rule("Default", "DIRECT", defaultRule=True, order=-1)]})
    keys = [m["key"] for m in res["zia_modules"]["modules"]]
    assert keys[-1] == "fwdctl" and zpm.SECTIONS["fwdctl"][1] == ("zia_extras",)
    m = fwd_module(res)
    assert {"module", "verdict", "rule", "overlaps", "criteria", "notes", "certainty"} <= set(m) and m["module"] == "Forwarding control"
    assert m["verdict"] in zpm.VERDICTS
    hops = [h["key"] for h in res["trace"]["hops"]]
    assert hops.index("fwdctl") == hops.index("incident") - 1


# ── The page ─────────────────────────────────────────────────────────
def test_the_ui_names_the_new_step_and_marks_the_features():
    """WCAG 2.2 SC 3.3.2 · SC 1.3.1: the animated path, the framework text, the Scope page help and the What's new list name Forwarding control and the checks."""
    fa = open(os.path.join(ROOT, "static", "flow_anim.js"), encoding="utf-8").read()
    assert "fwdctl: 'Forwarding control'" in fa and "['fwdctl', 'Forwarding control'" in fa
    assert "then Forwarding control" in open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    help_ = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    assert re.search(r'scope-cb\[value=\\"zia_extras\\"\]": \{\s*"what": "[^"]*forwarding', help_)
    wn = open(os.path.join(ROOT, "static", "whats_new.js"), encoding="utf-8").read()
    man = json.loads(re.search(r"window\.WHATS_NEW\s*=\s*(\{.*?\n\});", wn, re.S).group(1))
    ids = {f["id"]: f for f in man["features"]}
    # While 2026-10-31 is one of the newest two releases both are marked; once rotated out (keep: 2) they stay in CHANGELOG.md.
    if "2026-10-31" in man["releases"]:
        assert ids["zia-forwarding-checks"]["release"] == ids["path-forwarding-step"]["release"] == "2026-10-31"
    else:
        assert "## 2026-10-31" in open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
        assert "zia-forwarding-checks" not in ids and "path-forwarding-step" not in ids


class _PagedVips:
    """GRE tunnels plus a /vips list served page by page like ZIA (the SDK's default page is 100)."""

    def __init__(self, vips, tunnels, fail_page=None):
        self.vips, self.tunnels, self.fail_page, self.calls = vips, tunnels, fail_page, []

    def get(self, ep, p=None):
        p = p or {}
        if ep == "/zia/greTunnels":
            return self.tunnels, 200
        if ep == "/zia/vips":
            page, size = int(p.get("page", 1)), int(p.get("pageSize", 100))
            self.calls.append((page, size))
            if page == self.fail_page:
                return {"message": "busy"}, 429
            return self.vips[(page - 1) * size: page * size], 200
        return None, 404


def _many_vips(n):
    return [{"dataCenter": f"DC{i}", "greIps": [f"198.51.{i // 250}.{i % 250 + 1}"]} for i in range(n)]


def _tunnel_on(vips, a, b):
    return [{"sourceIp": "192.0.2.10",
             "primaryDestVip": {"virtualIp": vips[a]["greIps"][0]},
             "secondaryDestVip": {"virtualIp": vips[b]["greIps"][0]}}]


def test_gre_diversity_reads_every_vip_page_not_just_the_first_100():
    """ASVS V1.14.6 · CWE-1284 · WSTG-BUSL-01: a GRE tunnel whose VIPs sit past the first page of /vips is still placed in its data centres."""
    # Arrange: 2,500 public VIPs; the tunnel's two VIPs are numbers 1,200 and 2,400
    vips = _many_vips(2500)
    cl = _PagedVips(vips, _tunnel_on(vips, 1200, 2400))
    # Act
    r = zfc.fwd_5(cl)
    # Assert
    assert r.status == r.PASS, r.detail
    assert cl.calls == [(1, 1000), (2, 1000), (3, 1000)]


def test_gre_diversity_says_the_vip_list_may_be_incomplete_when_a_page_fails():
    """ASVS V1.14.6 · CWE-1284 · WSTG-BUSL-01: when a later VIP page cannot be read, an unplaced tunnel is a warning that says the list was partial, never a pass."""
    # Arrange
    vips = _many_vips(2500)
    cl = _PagedVips(vips, _tunnel_on(vips, 1200, 2400), fail_page=2)
    # Act
    r = zfc.fwd_5(cl)
    # Assert
    assert r.status == r.WARN
    assert "Only the first 1000 public VIPs could be read" in r.detail
