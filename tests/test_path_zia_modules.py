"""Path analyzer, every ZIA module in order: Advanced Threat Protection,
Cloud Firewall, DNS Control, Cloud App Control and URL filtering, Sandbox,
File Type Control and Web DLP, with SSL inspection as the modifier; a
protocol and port for traffic that is not web; the deciding rule, the
overlaps and each criterion as match, no match or unknown; definite or
conditional. Fake tenants only."""
from __future__ import annotations

import copy
import os
import re
import threading

import pytest

import data_flow as df
import path_analyzer as pa
import scope_permissions
import zia_path_modules as zpm
from test_data_flow import ROUTES
from test_path_analyzer import LookupCl
from test_ssl_flow import CATALOGUE
from zia_module_fixtures import ATP_SETTINGS, FIREWALL_RULES, MODULE_ROUTES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = pa.full_path_scope()
STATES = {"match", "no_match", "unknown"}


class Tenant(LookupCl):
    """The Data Flow fake, ZIA's URL lookup and the module endpoints; it
    records every GET so a test can say what was (not) read."""
    LOOKUP = dict(LookupCl.LOOKUP, **{
        "bad.example": {"urlClassifications": ["OTHER_MISCELLANEOUS"]},
        "trusted.example": {"urlClassifications": ["MALICIOUS_CONTENT"], "urlClassificationsWithSecurityAlert": ["MALICIOUS_CONTENT"]},
        "files.example": {"urlClassifications": ["WEB_MAIL"]},
        "x.blocked-domain.example": {"urlClassifications": ["OTHER_MISCELLANEOUS"]},
        "ssh.example.com": {"urlClassifications": ["OTHER_MISCELLANEOUS"]},
    })

    def __init__(self, routes=None, fail=()):
        super().__init__(dict(ROUTES, **(MODULE_ROUTES if routes is None else routes)), CATALOGUE)
        self.paths = []
        self.fail = dict(fail) if isinstance(fail, dict) else {ep: 403 for ep in fail}

    def get(self, ep, p=None):
        self.paths.append(ep)
        if ep in self.fail:
            return {"error": "forbidden"}, self.fail[ep]
        return super().get(ep, p)


def run(dest, protocol=None, port=None, network="off", platform="windows", scope=FULL, tenant=None, **kw):
    return pa.analyze(tenant or Tenant(), dest, network, platform, scope=scope, protocol=protocol, port=port, **kw)


def mod(res, key):
    return next(m for m in res["zia_modules"]["modules"] if m["key"] == key)


def hop(res, key):
    return next(h for h in res["trace"]["hops"] if h["key"] == key)


# ── Traffic: protocol and port ──────────────────────────────────────
@pytest.mark.parametrize("typed,protocol,port,label,web", [
    ("chat.openai.com", None, None, "TCP/443 (HTTPS (web))", True),
    ("http://intranet.example", None, None, "TCP/80 (HTTP (web))", True),
    ("https://x.example:8443/a", None, None, "TCP/8443 (HTTPS on 8443)", True),
    ("chat.openai.com", "udp", 443, "UDP/443 (QUIC (HTTP/3 over UDP))", False),
    ("ssh.example.com", "tcp", "22", "TCP/22 (SSH)", False),
    ("203.0.113.10", "udp", 51999, "UDP/51999", False),
])
def test_the_protocol_and_port_name_the_traffic_from_a_well_known_table(typed, protocol, port, label, web):
    """ASVS V5.1.3 · CWE-20: protocol and port become one named transaction (UDP/443 is QUIC), web or not."""
    t = zpm.traffic_context(pa.parse_destination(typed), protocol, port)
    assert t["label"] == label and t["web"] is web


def test_with_no_protocol_or_port_https_is_assumed_and_said():
    """ASVS V5.1.3 · CWE-20: a missing port is an assumption the result states, not a silent default."""
    t = zpm.traffic_context(pa.parse_destination("dropbox.com"))
    assert t["assumed"] and t["port"] == 443 and t["protocol"] == "tcp" and any("assumed" in n for n in t["notes"])
    assert "No protocol or port was given" in " ".join(run("dropbox.com")["assumptions"])


@pytest.mark.parametrize("protocol,port", [("icmp", None), ("tcp", 0), ("udp", 65536), ("tcp", "eighty"), ("tcp", -1), ("tcp", True), ("tcp", 1.5)])
def test_a_protocol_or_port_that_is_not_valid_is_refused_in_words(protocol, port):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an invalid protocol or port is refused with a plain sentence."""
    with pytest.raises(ValueError, match="protocol must be TCP or UDP|port must be a whole number"):
        zpm.traffic_context(pa.parse_destination("x.example"), protocol, port)


# ── Cloud Firewall ──────────────────────────────────────────────────
def test_quic_is_decided_by_the_cloud_firewall_and_the_web_modules_never_see_it():
    """ASVS V1.1.2 · CWE-693: UDP/443 meets the firewall's QUIC rule; web modules say not applicable, not 'no rule'."""
    r = run("chat.openai.com", "udp", 443)
    fw, v = mod(r, "firewall"), r["verdict"]
    assert fw["verdict"] == "block" and fw["certainty"] == "definite" and fw["rule"]["name"] == "Block QUIC" and fw["rule"]["order"] == 1
    assert fw["criteria"] == [{"name": "Network service", "state": "match", "detail": "UDP/443 (QUIC (HTTP/3 over UDP)) is in QUIC."}]
    assert v["outcome"] == "blocked" and v["blocked_by"] == "Block QUIC" and v["stops_at"] == "Cloud Firewall" and v["certainty"] == "definite"
    assert all(mod(r, k)["verdict"] == "not_applicable" for k in ("atp", "cac", "url", "sandbox", "ftc", "dlp"))
    assert hop(r, "firewall")["status"] == "blocked" and all(hop(r, k)["status"] == "not_reached" for k in ("dns", "url", "ssl", "dlp"))


def test_the_deciding_rule_its_overlaps_and_the_default_rule_are_named():
    """ASVS V1.1.2 · CWE-670: first match decides; later matches are overlaps; the default rule is counted, a disabled rule ignored."""
    fw = mod(run("chat.openai.com"), "firewall")
    assert fw["verdict"] == "allow" and fw["rule"]["name"] == "Allow web" and fw["rule"]["order"] == 3
    assert [o["name"] for o in fw["overlaps"]] == ["Allow all web (later)"] and fw["overlaps_catch_all"] == 1
    assert fw["considered"] == len([r for r in FIREWALL_RULES if r["state"] == "ENABLED"])
    assert any("handed to the web proxy" in n for n in fw["notes"])


def test_a_time_window_is_unknown_and_makes_the_firewall_result_conditional():
    """ASVS V1.1.2 · CWE-670: an earlier rule with an unevaluated time window and another outcome is shown, never guessed."""
    r = run("203.0.113.10", "tcp", 3389)
    fw = mod(r, "firewall")
    assert fw["verdict"] == "block" and fw["certainty"] == "conditional" and fw["rule"]["default"]
    could = fw["could_override"][0]
    assert could["name"] == "Office hours RDP" and {"name": "Time window", "state": "unknown"}.items() <= next(c for c in could["criteria"] if c["name"] == "Time window").items()
    v = r["verdict"]
    assert v["certainty"] == "conditional" and any("Cloud Firewall" in x for x in v["certainty_reasons"])
    assert v["headline"].startswith("TCP/3389 (Remote Desktop (RDP)) to 203.0.113.10 is blocked by Cloud Firewall rule 'Default Firewall Filtering Rule' (the default rule), unless")
    assert hop(r, "firewall")["status"] == "conditional" and v["outcome"] != "blocked"


@pytest.mark.parametrize("dest,blocked_by,state", [
    ("198.51.100.7", "Block SSH to bad nets", "match"),        # in the IP destination group
    ("203.0.113.5", "Default Firewall Filtering Rule", "no_match"),
])
def test_ip_destination_groups_and_network_service_groups_are_resolved(dest, blocked_by, state):
    """ASVS V1.1.2 · CWE-670: a rule's IP group and service group are expanded from the tenant's own objects."""
    fw = mod(run(dest, "tcp", 22), "firewall")
    assert fw["rule"]["name"] == blocked_by and fw["certainty"] == "definite"
    ssh_rule = fw if blocked_by == "Block SSH to bad nets" else None
    if ssh_rule:
        assert {c["name"]: c["state"] for c in fw["criteria"]} == {"Destination": "match", "Network service": "match"}


def _allow_ssh_to_bad_nets():
    routes = copy.deepcopy(MODULE_ROUTES)
    next(r for r in routes["/zia/firewallFilteringRules"] if r["id"] == 2)["action"] = "ALLOW"
    return routes


def test_a_hostname_against_ip_entries_is_unknown_because_names_are_not_resolved():
    """ASVS V1.1.2 · CWE-670: the tool never resolves DNS, so a hostname against IP ranges is unknown."""
    same = mod(run("ssh.example.com", "tcp", 22), "firewall")
    assert same["certainty"] == "definite" and not same["could_override"], "an unknown rule with the same outcome changes nothing"
    r = run("ssh.example.com", "tcp", 22, tenant=Tenant(_allow_ssh_to_bad_nets()))
    fw = mod(r, "firewall")
    assert fw["certainty"] == "conditional" and fw["could_override"][0]["name"] == "Block SSH to bad nets"
    dest = next(c for c in fw["could_override"][0]["criteria"] if c["name"] == "Destination")
    assert dest["state"] == "unknown" and "does not do" in dest["detail"]


def test_non_web_traffic_on_a_web_only_forwarding_mode_never_reaches_zia():
    """ASVS V1.1.2 · CWE-693: PAC forwarding carries only web traffic; UDP/443 leaves the device directly."""
    r = run("chat.openai.com", "udp", 443, platform="macos")
    v = r["verdict"]
    assert v["outcome"] == "bypassed" and not v["reaches_zscaler"] and v["stops_at"] == "Forwarding profile"
    assert all(m["verdict"] == "not_reached" for m in r["zia_modules"]["modules"])
    assert any(w["title"] == "Non-web traffic not forwarded" for w in r["trace"]["weak_points"])


# ── DNS Control ─────────────────────────────────────────────────────
def test_dns_control_blocks_the_lookup_before_url_filtering_runs():
    """ASVS V1.1.2 · CWE-670: DNS Control comes before URL filtering; later modules are not reached."""
    r = run("https://casino.example/play")
    dns = mod(r, "dns")
    assert dns["verdict"] == "block" and dns["rule"]["name"] == "Block gambling lookups"
    assert dns["criteria"][0]["name"] == "Requested domain" and dns["criteria"][0]["state"] == "match"
    assert r["verdict"]["outcome"] == "blocked" and r["verdict"]["blocked_by"] == "Block gambling lookups" and r["verdict"]["stops_at"] == "DNS Control"
    assert mod(r, "url")["verdict"] == "not_reached" and hop(r, "url")["status"] == "not_reached"
    keys = [h["key"] for h in r["trace"]["hops"]]
    assert keys.index("atp") < keys.index("firewall") < keys.index("dns") < keys.index("cac") < keys.index("url") < keys.index("ssl") < keys.index("sandbox") < keys.index("ftc") < keys.index("dlp")


def test_an_ip_destination_needs_no_lookup_so_dns_control_is_not_applicable():
    """ASVS V1.1.2 · CWE-670: no name, no lookup: DNS Control is not applicable, not 'allowed'."""
    assert mod(run("203.0.113.10"), "dns")["verdict"] == "not_applicable"


# ── Advanced Threat Protection ──────────────────────────────────────
def test_the_atp_denylist_blocks_first_and_the_allowlist_wins_over_a_category_toggle():
    """ASVS V1.1.2 · CWE-670: denylist blocks; a security exception exempts a host its category would block."""
    bad = run("bad.example")
    assert mod(bad, "atp")["verdict"] == "block" and mod(bad, "atp")["rule"]["name"] == "Malicious URLs (ATP denylist)"
    assert bad["verdict"]["stops_at"] == "Advanced Threat Protection" and mod(bad, "firewall")["verdict"] == "not_reached"
    trusted = mod(run("trusted.example"), "atp")
    assert trusted["verdict"] == "allow" and trusted["rule"]["name"] == "Security exceptions (ATP allowlist)"
    assert [o["name"] for o in trusted["overlaps"]] == ["Malicious content sites: blocked"]
    assert mod(run("x.blocked-domain.example"), "atp")["rule"]["name"] == "Security policy denylist"


def test_a_category_toggle_blocks_what_zia_flags():
    """ASVS V1.1.2 · CWE-693: ZIA's security alert for the host meets the ATP toggle that blocks it."""
    r = run("evil.example")
    atp = mod(r, "atp")
    assert atp["verdict"] == "block" and atp["rule"]["name"] == "Malicious content sites: blocked" and r["verdict"]["outcome"] == "blocked"


def test_a_list_entry_with_a_path_needs_decryption_to_match():
    """ASVS V1.1.2 · CWE-670: a path is invisible on encrypted traffic, so a path entry cannot match it."""
    st, _ = zpm.url_hit(["files.example/payload"], pa.parse_destination("https://files.example/payload/x"), False)
    assert st == "no_match"
    assert zpm.url_hit(["files.example/payload"], pa.parse_destination("https://files.example/payload/x"), True)[0] == "match"
    assert zpm.url_hit(["files.example/payload"], pa.parse_destination("https://files.example/payload/x"), None)[0] == "unknown"
    assert zpm.url_hit([".example.com"], pa.parse_destination("a.b.example.com"), False)[0] == "match"
    assert zpm.url_hit(["example.com"], pa.parse_destination("a.example.com"), False)[0] == "no_match"
    assert zpm.url_hit(["198.51.100.0/24"], pa.parse_destination("198.51.100.9"), False)[0] == "match"


def test_blocked_countries_are_unknown_because_the_tool_does_not_geolocate():
    """ASVS V1.1.2 · CWE-670: a country condition is unknown and makes the result conditional."""
    routes = copy.deepcopy(MODULE_ROUTES)
    routes["/zia/cyberThreatProtection/advancedThreatSettings"] = dict(ATP_SETTINGS, blockedCountries=["COUNTRY_KP"])
    r = run("chat.openai.com", tenant=Tenant(routes))
    atp = mod(r, "atp")
    assert atp["certainty"] == "conditional" and atp["could_override"][0]["name"] == "Blocked countries (1)"
    assert r["verdict"]["certainty"] == "conditional"


# ── Sandbox and the SSL modifier ────────────────────────────────────
def test_ssl_inspection_decides_what_the_sandbox_and_later_modules_can_see():
    """ASVS V1.1.2 · CWE-693: decrypted traffic is inspected by Sandbox; traffic left encrypted leaves it blind."""
    dec = run("chat.openai.com")
    assert dec["zia_modules"]["modifier"]["verdict"] == "decrypt" and dec["zia_modules"]["modifier"]["rule"]["name"] == "Decrypt all"
    sb = mod(dec, "sandbox")
    assert sb["verdict"] == "inspect" and sb["certainty"] == "definite" and sb["rule"]["name"] == "Quarantine unknown executables"
    assert {c["name"]: c["state"] for c in sb["criteria"]}["File type"] == "unknown"
    enc = run("mail.example.com")
    assert enc["zia_modules"]["modifier"]["verdict"] == "no_decrypt" and mod(enc, "sandbox")["verdict"] == "blind"


def test_the_existing_web_modules_keep_their_decision_and_show_their_criteria():
    """ASVS V1.1.2 · CWE-670: URL filtering decides as before; its deciding rule's criteria are listed."""
    r = run("https://files.example/doc", tenant=Tenant())
    url = mod(r, "url")
    assert url["status"] == "evaluated" and url["verdict"] in ("allow", "none", "caution", "conditional")
    g = run("evil.example", tenant=Tenant(routes={k: v for k, v in MODULE_ROUTES.items() if "cyberThreat" not in k and "security" not in k}))
    # With ATP unread the URL lookup still feeds URL filtering, and the unread module is unknown, not "allowed".
    assert mod(g, "atp")["verdict"] == "unknown" and mod(g, "atp")["status"] == "unread" and g["verdict"]["certainty"] == "conditional"


# ── The shared shape ────────────────────────────────────────────────
@pytest.mark.parametrize("dest,protocol,port", [("chat.openai.com", None, None), ("chat.openai.com", "udp", 443), ("casino.example", None, None),
                                                ("mail.example.com", None, None), ("203.0.113.10", "tcp", 3389), ("updates.vendor.com", None, None)])
def test_every_module_has_the_shared_shape_and_only_three_criterion_states(dest, protocol, port):
    """ASVS V1.1.2 · CWE-20: each hop is {module, verdict, rule, overlaps, criteria, notes}; criteria are match, no match or unknown."""
    r = run(dest, protocol, port)
    hops = [r["zia_modules"]["modifier"]] + r["zia_modules"]["modules"]
    assert [m["key"] for m in r["zia_modules"]["modules"]] == ["atp", "firewall", "dns", "cac", "url", "sandbox", "ftc", "dlp"]
    for m in hops:
        assert {"module", "verdict", "rule", "overlaps", "criteria", "notes"} <= set(m)
        assert m["rule"] is None or {"name", "order"} <= set(m["rule"])
        assert all(c["state"] in STATES and c["name"] for c in m["criteria"])
        assert all(c["state"] in STATES for o in m["could_override"] for c in o.get("criteria") or [])
        assert m["certainty"] in ("definite", "conditional", "unknown")
    assert r["verdict"]["certainty"] in ("definite", "conditional")


# ── Scope, reads, Stop and the kept read ────────────────────────────
def test_the_module_sections_are_in_the_scope_table_gated_by_zia_platform():
    """ASVS V4.1.3 · CWE-285: each new section has a Scope page key; ZIA platform puts it in scope; the API table lists every endpoint."""
    for key in zpm.SECTIONS:
        assert df.PATH_SECTIONS[key] == zpm.SECTIONS[key] and df.PATH_SECTIONS[key][1] == ("zia_extras",)
    used = scope_permissions.SCOPE_PERMISSIONS["zia_extras"]["endpoints_used"]
    assert all(ep in used for ep in zpm.ENDPOINTS if ep != "/zia/security"), [ep for ep in zpm.ENDPOINTS if ep not in used]
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert re.search(r'title="[^"]*Cloud Firewall[^"]*DNS Control and Sandbox[^"]*">\s*<input type="checkbox" class="scope-cb" value="zia_extras"', html)


@pytest.mark.parametrize("endpoint", zpm.ENDPOINTS)
def test_nothing_out_of_scope_is_read(endpoint):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: without ZIA platform ticked no module endpoint is requested; each says not in scope."""
    scope = df.path_scope(["dlp", "zcc"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    c = Tenant()
    r = run("chat.openai.com", scope=scope, tenant=c)
    assert endpoint not in c.paths
    for key in zpm.SECTIONS:
        m = mod(r, key)
        assert m["status"] == "out_of_scope" and "ZIA platform is not ticked" in m["detail"]
    assert r["verdict"]["certainty"] == "conditional" and any("not in scope" in x for x in r["verdict"]["certainty_reasons"])


def test_a_failed_read_is_unknown_never_an_empty_rule_list():
    """ASVS V7.4.1 · CWE-755: a refused rule list is 'could not be read'; a missing group list leaves its criteria unknown."""
    r = run("chat.openai.com", "udp", 443, tenant=Tenant(fail=["/zia/firewallFilteringRules"]))
    fw = mod(r, "firewall")
    assert fw["status"] == "unread" and fw["verdict"] == "unknown" and "HTTP 403" in fw["detail"] and r["verdict"]["outcome"] == "unknown"
    t = Tenant(_allow_ssh_to_bad_nets(), fail=["/zia/ipDestinationGroups"])
    g = mod(run("198.51.100.7", "tcp", 22, tenant=t), "firewall")
    assert g["certainty"] == "conditional" and any("IP destination groups" in n for n in g["notes"])
    assert "members of Bad nets are not known" in next(c for c in g["could_override"][0]["criteria"] if c["name"] == "Destination")["detail"]


def test_secrets_and_error_bodies_do_not_leak_into_the_module_result():
    """ASVS V7.1.1 · CWE-209: a failing read's body is cut short and no credential appears in the result."""
    c = Tenant(fail={"/zia/sandboxRules": 500})
    c.routes = dict(c.routes)
    r = run("chat.openai.com", tenant=c)
    text = repr(r["zia_modules"])
    assert "secret" not in text.lower() and len(mod(r, "sandbox")["detail"]) < 400


def test_stop_during_the_module_reads_ends_the_run_and_sends_nothing_more():
    """ASVS V11.1.4 · CWE-400: Stop is honoured between module reads; a partial read is never a result."""
    ev = threading.Event()

    class StopAtFirewall(Tenant):
        def get(self, ep, p=None):
            if ep == "/zia/firewallFilteringRules":
                ev.set()
            return super().get(ep, p)

    c = StopAtFirewall()
    with pytest.raises(pa.Stopped):
        run("chat.openai.com", tenant=c, cancel=ev)
    assert "/zia/networkServices" not in c.paths and "/zia/sandboxRules" not in c.paths


def test_the_kept_read_carries_the_modules_and_a_read_without_them_is_not_reused():
    """ASVS V4.1.3 · CWE-664: the next destination reuses the module read; a Data Flow Map read (no modules) is read again."""
    c = Tenant()
    first = run("casino.example", tenant=c)
    snap = first["snapshot_for_cache"]
    n = len(c.paths)
    second = run("chat.openai.com", "udp", 443, tenant=c, snapshot=snap)
    assert len(c.paths) == n and mod(second, "firewall")["rule"]["name"] == "Block QUIC"
    stale = copy.deepcopy(snap)
    del stale["snapshot"]["zia"]["modules"]
    assert not pa.reusable(stale, FULL, "windows") and pa.reusable(snap, FULL, "windows")


# ── The endpoint ────────────────────────────────────────────────────
SCOPE_ALL = {"scopes": ["dlp", "zia_extras", "zcc"],
             "channels": {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                          "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}}


def test_the_endpoint_takes_protocol_and_port_and_refuses_bad_ones_before_signing_in(monkeypatch):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: bad protocol or port is a 400 before any sign-in; a good one traces QUIC."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    built = []
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or Tenant())
    t = TestClient(srv.app)
    creds = dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}, **SCOPE_ALL)
    for bad in ({"protocol": "icmp"}, {"protocol": "tcp", "port": 70000}, {"protocol": "udp", "port": 0}):
        r = t.post("/api/path-analyzer", json=dict(creds, destination="chat.openai.com", **bad))
        assert r.status_code == 400 and ("TCP or UDP" in r.text or "whole number" in r.text)
    assert not built
    r = t.post("/api/path-analyzer", json=dict(creds, destination="chat.openai.com", protocol="udp", port=443))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["zia_modules"]["traffic"]["label"].startswith("UDP/443") and body["verdict"]["blocked_by"] == "Block QUIC"
    assert "secret-secret-secret" not in r.text


# ── The page ────────────────────────────────────────────────────────
def test_the_page_loads_the_shared_module_renderer_with_its_documented_shape():
    """WCAG 2.2 SC 1.3.1 · ASVS V14.4.1: the renderer is one shared file, documents its data shape and uses the page's chip and table classes."""
    page = open(os.path.join(ROOT, "static", "report_path.html"), encoding="utf-8").read()
    js = open(os.path.join(ROOT, "static", "path_modules.js"), encoding="utf-8").read()
    assert page.index('src="/static/har_parse.js"') < page.index('src="/static/path_modules.js"') < page.index("PathModules.zia.mountControls")
    head = js[:2500]
    for word in ("module:", "verdict:", "rule:", "overlaps:", "criteria:", "notes:", "'match' | 'no_match' | 'unknown'"):
        assert word in head, word
    assert "df-chip" in js and "df-table" in js and '<th scope="col">' in js and "aria-label=\"Destination port" in js
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", open(os.path.join(ROOT, "static", "reports.css"), encoding="utf-8").read().split("/* Path modules")[1])
