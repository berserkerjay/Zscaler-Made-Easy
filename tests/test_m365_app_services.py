"""App services and app service groups matched with Microsoft's published
Microsoft 365 endpoint list (app_services.py, m365_endpoints.py): an
oracle of match, no match and unknown (host names with Microsoft's
wildcards, IDN and case, IPv4, IPv6 and IPv4-mapped addresses, ports), the
list checked as untrusted (malformed, oversized, stale), the optional
fetch (off by default, one host, no redirect, capped) and the Path
analyzer, its what-if, DNS Control, workload forwarding, Test a list,
Shadowed rules, the sample tenant and the Advanced settings API.

No test reaches Microsoft or a tenant: the list is a small fixture
(tests/fixtures/m365_endpoints_small.json, in Microsoft's format), the
network is a recorder that answers from a table, and the tenants are
fakes or the made-up sample tenant."""
from __future__ import annotations

import copy
import datetime as dt
import ipaddress
import json
import os
import re
from pathlib import Path

import pytest
import requests
import requests.adapters
from requests.models import Response

import app_services as aps
import m365_endpoints as m365
import path_analyzer as pa
import shadow_rules as sr
import zia_path_modules as zpm

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "m365_endpoints_small.json"
VERSION = "2026100100"
ONE_CLICK = {"id": 50, "name": "Office 365 One Click Rule", "order": 0, "state": "ENABLED", "action": "ALLOW", "predefined": True,
             "appServiceGroups": [{"id": 361, "name": "OFFICE365"}]}
T443 = {"protocol": "tcp", "port": 443}


@pytest.fixture(autouse=True)
def _own_folder(tmp_path, monkeypatch):
    """Every test keeps its list in its own folder; the network is refused
    unless a test installs its recorder."""
    monkeypatch.setenv("DLP_CHECK_M365_DIR", str(tmp_path / "m365"))
    monkeypatch.delenv("DLP_CHECK_M365_MAX_AGE_DAYS", raising=False)

    def refuse(self, request, **kw):
        raise AssertionError(f"no network in tests: {request.url}")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", refuse)
    m365._CACHE.update(key=None, list=None)
    yield
    m365._CACHE.update(key=None, list=None)


def fixture_bytes() -> bytes:
    return FIXTURE.read_bytes()


def keep(now=None, version=VERSION):
    """Import the fixture as the kept list; the list it gives."""
    m365.import_file(fixture_bytes(), version, now=now)
    return m365.load()


def crit(dest, traffic=T443, lst=None, rule=None, **kw):
    """The criterion for `dest` (a host name, an IDN or an address) as the Path analyzer gives it."""
    d = pa.parse_destination(dest)
    ip = None
    try:
        ip = ipaddress.ip_address(d["host"])
    except ValueError:
        pass
    return aps.criterion(rule or ONE_CLICK, d["host"], ip, traffic, lst if lst is not None else m365.load(), **kw)


# ── The oracle ───────────────────────────────────────────────────────
@pytest.mark.parametrize("dest,traffic,state,why", [
    # exact host names, case and a trailing dot
    ("outlook.office365.com", T443, "match", "'Exchange Online' (endpoint set 1"),
    ("OUTLOOK.Office365.COM.", T443, "match", "'Exchange Online'"),
    ("outlook.office.com", {"protocol": "tcp", "port": 80}, "match", "TCP 80, 443"),
    # *.domain: one or more labels below it, never the domain itself or a look-alike
    ("x.officeapps.live.com", T443, "match", "*.officeapps.live.com"),
    ("a.b.officeapps.live.com", T443, "match", "*.officeapps.live.com"),
    ("officeapps.live.com", T443, "unknown", "not one of the host names"),
    ("evilofficeapps.live.com", T443, "unknown", "not one of the host names"),
    ("officeapps.live.com.evil.example", T443, "unknown", "not one of the host names"),
    # a * inside a label and Microsoft's <tenant> placeholder: one label part
    ("foocdn.onenote.net", T443, "match", "*cdn.onenote.net"),
    ("cdn.onenote.net", T443, "unknown", "not one of the host names"),
    ("a.bcdn.onenote.net", T443, "unknown", "not one of the host names"),
    ("autodiscover.contoso.onmicrosoft.com", T443, "match", "autodiscover.*.onmicrosoft.com"),
    ("autodiscover.a.b.onmicrosoft.com", T443, "unknown", "not one of the host names"),
    ("contoso.sharepoint.com", T443, "match", "<tenant>.sharepoint.com"),
    ("contoso-my.sharepoint.com", T443, "match", "<tenant>-my.sharepoint.com"),
    ("a.b.sharepoint.com", T443, "unknown", "not one of the host names"),
    ("sharepoint.com", T443, "unknown", "not one of the host names"),
    # an internationalised name is compared in punycode
    ("bücher.sharepoint.com", T443, "match", "xn--bcher-kva.sharepoint.com is in"),
    # a host name the list does not name: its address is not resolved
    ("example.com", T443, "unknown", "its IP address is not resolved here"),
    # IPv4, IPv6 and IPv4-mapped addresses
    ("40.97.1.2", T443, "match", "40.96.0.0/13"),
    ("203.0.113.9", T443, "no_match", "none of the 8 IPv4 ranges"),
    ("2603:1006::5", T443, "match", "2603:1006::/40"),
    ("[2603:1006::5]", T443, "match", "2603:1006::/40"),
    ("2001:db8::1", T443, "no_match", "none of the 3 IPv6 ranges"),
    ("::ffff:40.97.1.2", T443, "match", "40.96.0.0/13"),
    # ports: Microsoft publishes the set for some ports only
    ("40.97.1.2", {"protocol": "tcp", "port": 22}, "unknown", "not TCP/22"),
    ("x.mail.protection.outlook.com", T443, "unknown", "publishes for TCP 25, not TCP/443"),
    ("x.mail.protection.outlook.com", {"protocol": "tcp", "port": 25}, "match", "endpoint set 10"),
    ("13.107.64.5", {"protocol": "udp", "port": 3478}, "match", "UDP 3478-3481"),
    ("13.107.64.5", T443, "unknown", "not TCP/443"),
])
def test_the_oracle_of_match_no_match_and_unknown(dest, traffic, state, why):
    """ASVS V1.4.4 · CWE-697 · CWE-176: each destination against the OFFICE365 group is match, no match or unknown as Microsoft's published list says, and the reason names the set, entry, version and date."""
    lst = keep()
    c = crit(dest, traffic, lst)
    assert c["name"] == "App service groups" and c["state"] == state, c
    assert why in c["detail"], c["detail"]
    if state != "unknown" or "not TCP" in why:
        assert f"list version {VERSION}, imported {dt.datetime.now(dt.timezone.utc):%Y-%m-%d}" in c["detail"], c["detail"]


def test_the_match_reads_as_one_plain_sentence():
    """ASVS V7.4.1 · WCAG 2.2 SC 3.3.1: the result says why it matched: the host, Microsoft's service area, the set and ports, the list's version and date, and the group."""
    keep()
    c = crit("outlook.office365.com")
    day = f"{dt.datetime.now(dt.timezone.utc):%Y-%m-%d}"
    assert c["detail"] == (f"outlook.office365.com is in Microsoft 365 'Exchange Online' (endpoint set 1: TCP 80, 443; UDP 443; "
                           f"list version {VERSION}, imported {day}), which OFFICE365 holds.")


@pytest.mark.parametrize("rule,dest,state,why", [
    ({"appServices": [{"id": 1, "name": "EXCHANGEONLINE"}]}, "13.107.136.5", "no_match", "'Exchange Online'"),   # a SharePoint address
    ({"appServices": [{"id": 1, "name": "EXCHANGEONLINE"}]}, "40.97.1.2", "match", "which EXCHANGEONLINE holds"),
    ({"appServices": [{"id": 2, "name": "FILE_SHAREPT_ONEDRIVE"}]}, "contoso.sharepoint.com", "match", "SharePoint"),
    ({"app_service_groups": [{"id": 3, "name": "OFFICE365"}]}, "40.97.1.2", "match", "OFFICE365"),       # SDK snake_case
    # Another provider's group: unknown until that provider's list is kept (vendor_endpoints, tests/test_vendor_app_services.py).
    ({"appServiceGroups": [{"id": 4, "name": "ZOOM"}]}, "40.97.1.2", "unknown", "no Zoom list is kept"),
    ({"appServiceGroups": [{"id": 4, "name": "WEBEX_TEAMS"}]}, "40.97.1.2", "unknown", "no Webex list is kept"),
    ({"appServiceGroups": [{"id": 4, "name": "ZSCALER_SERVICES"}]}, "40.97.1.2", "unknown", "no published list is used"),
    ({"appServiceGroups": [{"id": 3, "name": "OFFICE365"}, {"id": 4, "name": "ZOOM"}]}, "203.0.113.9", "unknown", "no Zoom list is kept"),
    ({"appServiceGroups": [{"id": 3, "name": "OFFICE365"}, {"id": 4, "name": "ZOOM"}]}, "40.97.1.2", "match", "OFFICE365"),
    ({"appServiceGroups": ["ANY"]}, "40.97.1.2", None, None),
])
def test_which_app_services_are_microsoft_365_and_how_several_combine(rule, dest, state, why):
    """ASVS V1.4.4 · CWE-697: an app service the list covers is evaluated for its own service areas; one it does not (Zoom, Webex Teams) stays unknown; several are alternatives."""
    keep()
    c = crit(dest, rule=rule)
    if state is None:
        assert c is None
        return
    assert c["state"] == state and why in c["detail"], c


def test_without_a_list_the_criterion_stays_unknown_and_says_how_to_settle_it():
    """ASVS V1.4.4 · CWE-754: with no list kept the app service group is unknown, never a match or a miss, and the words point to Advanced settings."""
    c = crit("outlook.office365.com", lst=None)
    assert m365.load() is None and c["state"] == "unknown"
    assert "Advanced settings" in c["detail"] and "OFFICE365" in c["detail"]


# ── The list as untrusted input ──────────────────────────────────────
def _with(**changes):
    doc = json.loads(fixture_bytes())
    doc[0].update(changes)
    return json.dumps(doc)


@pytest.mark.parametrize("text,why", [
    ("{\"not\": \"a list\"}", "not Microsoft's endpoint list"),
    ("not json at all", "not valid JSON"),
    ("[]", "empty"),
    ("[1, 2]", "is not an object"),
    ("[{\"serviceArea\": \"Exchange\", \"urls\": [\"a.example\"]}]", "no whole-number id"),
    ("[{\"id\": true, \"serviceArea\": \"Exchange\", \"urls\": [\"a.example\"]}]", "no whole-number id"),
    ("[{\"id\": 1, \"urls\": [\"a.example\"]}]", "no service area"),
    ("[{\"id\": 1, \"serviceArea\": \"Exchange\", \"urls\": [\"a.example\"]}, {\"id\": 1, \"serviceArea\": \"Common\", \"urls\": [\"b.example\"]}]", "appears twice"),
    (_with(urls=["exa mple.com"]), "not a host name pattern"),
    (_with(urls=["<script>.example.com"]), "placeholder other than <tenant>"),
    (_with(urls=["*"]), "not a host name pattern"),
    (_with(urls=["*.example.*"]), "not a host name pattern"),
    (_with(urls="outlook.office.com"), "must be lists"),
    (_with(urls=[42]), "not text"),
    (_with(ips=["999.1.1.1/8"]), "not an IP address or range"),
    (_with(ips=["40.96.0.0/13; rm -rf /"]), "not an IP address or range"),
    (_with(tcpPorts="80,70000"), "not a port from 1 to 65535"),
    (_with(tcpPorts="80,https"), "not a list of port numbers"),
    (_with(tcpPorts="443-80"), "not a port from 1 to 65535"),
    (_with(required="yes"), "'required' must be true or false"),
    ("[{\"id\": 1, \"serviceArea\": \"Exchange\", \"urls\": [\"a.example\"], \"x\": NaN}]", "not valid JSON"),
    ("[" * 5000 + "]" * 5000, "nested too deeply|not valid JSON|not an object"),
    ("[{\"id\": 1, \"serviceArea\": \"Exchange\"}]", "names no host name and no address"),
])
def test_a_malformed_list_is_refused_whole_in_plain_words(text, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a list that is not Microsoft's endpoint list is refused whole with a plain reason, never partly kept."""
    with pytest.raises(m365.ListError, match=why):
        m365.parse(text)


def test_a_malformed_import_keeps_the_list_kept_before():
    """ASVS V5.1.3 · CWE-20: a refused import changes nothing: the list kept before still decides."""
    keep()
    with pytest.raises(m365.ListError):
        m365.import_file(_with(ips=["not-an-address"]), "2026110100")
    assert m365.load().version == VERSION and crit("40.97.1.2")["state"] == "match"


def test_an_oversized_list_is_refused_without_being_read():
    """ASVS V12.1.1 · CWE-400 · CWE-770 · WSTG-BUSL-07: a list over the 2 MB cap is refused before it is parsed, and the import keeps nothing."""
    big = b"[" + b" " * (m365.MAX_BYTES + 1) + b"]"
    with pytest.raises(m365.ListError, match="larger than 2 MB"):
        m365.import_file(big)
    assert m365.load() is None
    many = json.dumps([{"id": i, "serviceArea": "Common", "urls": [f"h{i}.example"]} for i in range(m365.MAX_SETS + 1)])
    with pytest.raises(m365.ListError, match="more than 2000 endpoint sets"):
        m365.parse(many)


def test_a_damaged_kept_file_is_not_used():
    """ASVS V5.1.3 · CWE-345: the kept file is checked again when it is read; one edited by hand into something else is not used (unknown, not a crash)."""
    keep()
    doc = json.loads(Path(m365.list_path()).read_text())
    doc["sets"][0]["ips"] = ["0.0.0.0/0x"]
    Path(m365.list_path()).write_text(json.dumps(doc))
    assert m365.load() is None and crit("40.97.1.2", lst=None)["state"] == "unknown"


def test_the_kept_list_is_owner_only_and_names_its_version_source_and_date():
    """ASVS V8.3.4 · CWE-732: the list is kept owner-only (0600) with its version, where it came from and when."""
    when = dt.datetime(2026, 10, 30, 9, 0, tzinfo=dt.timezone.utc)
    keep(now=when)
    st = m365.status(now=when + dt.timedelta(days=1))
    assert (st["version"], st["source"], st["fetched_at"], st["stale"], st["enabled"]) == (VERSION, "imported", "2026-10-30T09:00:00Z", False, False)
    assert st["counts"] == {"sets": 6, "urls": 10, "ipv4": 8, "ipv6": 3}
    if os.name != "nt":
        assert os.stat(m365.list_path()).st_mode & 0o077 == 0


def test_a_stale_list_settles_nothing():
    """ASVS V1.4.4 · CWE-672: a list not confirmed for more than 30 days makes every app service criterion unknown, a match as well as a miss, and says how old it is."""
    lst = keep(now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=31))
    assert lst.stale() and m365.status()["stale"] is True
    for dest in ("outlook.office365.com", "203.0.113.9"):
        c = crit(dest, lst=lst)
        assert c["state"] == "unknown" and "was last confirmed 31 days ago, more than 30 days" in c["detail"], c


def test_the_age_limit_is_a_bounded_setting(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: DLP_CHECK_M365_MAX_AGE_DAYS sets the age limit, clamped to 1-365 days; junk falls back to 30."""
    lst = keep(now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=40))
    monkeypatch.setenv("DLP_CHECK_M365_MAX_AGE_DAYS", "60")
    assert not lst.stale() and crit("40.97.1.2", lst=lst)["state"] == "match"
    for raw, days in (("0", 1), ("9999", 365), ("soon", 30)):
        monkeypatch.setenv("DLP_CHECK_M365_MAX_AGE_DAYS", raw)
        assert m365.max_age_days() == days


# ── The optional fetch ───────────────────────────────────────────────
class Net:
    """The network as a table: host -> callable(request) -> (status, headers, body); every request recorded."""

    def __init__(self, monkeypatch):
        self.sent, self.routes = [], {}
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", lambda adapter, request, **kw: self.send(adapter, request, **kw))
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(k, raising=False)

    def send(self, adapter, request, stream=False, timeout=None, verify=True, **kw):
        self.sent.append({"url": request.url, "method": request.method, "timeout": timeout, "verify": verify, "body": request.body})
        from urllib3.util import parse_url
        route = self.routes.get(parse_url(request.url).path)
        if route is None:
            raise requests.exceptions.ConnectionError("no route")
        status, headers, body = route(request)
        r = Response()
        r.status_code, r._content, r.url, r.request = status, body, request.url, request
        r.headers.update(headers)
        return r


def _microsoft(net, version=VERSION, body=None):
    net.routes["/version/worldwide"] = lambda req: (200, {"Content-Type": "application/json"}, json.dumps({"instance": "Worldwide", "latest": version}).encode())
    net.routes["/endpoints/worldwide"] = lambda req: (200, {"Content-Type": "application/json"}, fixture_bytes() if body is None else body)


def test_fetching_is_off_by_default_and_then_sends_nothing(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: out of the box fetching is off: Fetch now is refused, nothing is due in the background and no request leaves the machine."""
    net = Net(monkeypatch)
    _microsoft(net)
    assert m365.settings()["enabled"] is False and m365.status()["enabled"] is False
    with pytest.raises(m365.FetchDisabled, match="off"):
        m365.fetch()
    assert m365.refresh_due() is False and m365.refresh_in_background() is False
    assert net.sent == [] and m365.load() is None


def test_turned_on_it_fetches_the_version_then_the_list_from_the_one_host(monkeypatch):
    """ASVS V12.6.1 · V9.2.1 · CWE-918 · CWE-295: GETs to endpoints.office.com only, https, a timeout, TLS verified, a random request id and nothing about the tenant; the list is kept with Microsoft's version."""
    net = Net(monkeypatch)
    _microsoft(net)
    m365.set_enabled(True)
    st = m365.fetch()
    assert (st["version"], st["source"], st["present"], st["last_error"]) == (VERSION, "fetched", True, None)
    assert [s["url"].split("?")[0] for s in net.sent] == ["https://endpoints.office.com/version/worldwide", "https://endpoints.office.com/endpoints/worldwide"]
    for s in net.sent:
        assert s["method"] == "GET" and s["body"] is None and s["verify"] is True and s["timeout"] == m365.FETCH_TIMEOUT
        assert re.fullmatch(r"https://endpoints\.office\.com/[a-z]+/worldwide\?clientrequestid=[0-9a-f-]{36}", s["url"]), s["url"]
    assert net.sent[0]["url"] != net.sent[1]["url"].replace("endpoints/", "version/")   # a fresh id per request
    assert "fetched" in crit("outlook.office365.com")["detail"]


def test_the_same_version_is_not_downloaded_again(monkeypatch):
    """ASVS V12.6.1 · CWE-400: when Microsoft's version has not changed only the small version answer is read, and the list is marked confirmed."""
    net = Net(monkeypatch)
    _microsoft(net)
    m365.set_enabled(True)
    m365.fetch(now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=29))
    net.sent.clear()
    st = m365.fetch()
    assert [s["url"].split("?")[0].rsplit("/", 2)[1] for s in net.sent] == ["version"]
    assert st["fetched_at"] != st["checked_at"] and st["age_days"] < 1


@pytest.mark.parametrize("route,why", [
    (lambda req: (302, {"Location": "https://evil.example/list.json"}, b""), "redirect"),
    (lambda req: (500, {}, b"oops"), "HTTP 500"),
    (lambda req: (200, {"Content-Length": str(m365.MAX_BYTES + 1)}, b"[]"), "larger than"),
    (lambda req: (200, {}, b"[" + b" " * (m365.MAX_BYTES + 10) + b"]"), "larger than"),
    (lambda req: (200, {}, b"<html>captive portal</html>"), "not valid JSON"),
    (lambda req: (200, {}, b'[{"id": 1, "serviceArea": "Exchange", "ips": ["1.2.3.4/99"]}]'), "not an IP address"),
])
def test_a_bad_answer_is_refused_recorded_and_the_kept_list_stays(monkeypatch, route, why):
    """ASVS V12.6.1 · V5.1.3 · CWE-918 · CWE-20 · CWE-400: a redirect, an error, an oversized or malformed answer is refused (fail safe), the reason recorded, and the list kept before still used."""
    keep()
    net = Net(monkeypatch)
    _microsoft(net, version="2026110100")
    net.routes["/endpoints/worldwide"] = route
    m365.set_enabled(True)
    with pytest.raises(m365.ListError, match=why):
        m365.fetch()
    st = m365.status()
    assert st["version"] == VERSION and why.split()[0].lower() in st["last_error"].lower()
    assert all(s["url"].startswith("https://endpoints.office.com/") for s in net.sent)


@pytest.mark.parametrize("url", ["http://endpoints.office.com/version/worldwide", "https://evil.example/version/worldwide",
                                 "https://user:pw@endpoints.office.com/x", "https://endpoints.office.com:8443/x", "file:///etc/passwd"])
def test_the_fetcher_refuses_any_other_address(monkeypatch, url):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: the fetcher talks to https://endpoints.office.com only: any other scheme, host, port or a URL with credentials is refused before a request."""
    net = Net(monkeypatch)
    with pytest.raises(m365.ListError, match="Only https://endpoints.office.com"):
        m365._get(url, 1024)
    assert net.sent == []


def test_a_background_check_runs_only_when_due_and_not_again_soon_after_a_failure(monkeypatch):
    """ASVS V12.6.1 · CWE-400: with fetching on, a check is due when the list was not confirmed in 24 hours, and a failed try is not retried within the hour."""
    m365.set_enabled(True)
    assert m365.refresh_due() is True
    net = Net(monkeypatch)    # no routes: the try fails
    with pytest.raises(m365.ListError):
        m365.fetch()
    assert m365.refresh_due() is False and m365.settings()["last_error"]
    assert len(net.sent) == 1


# ── Path analyzer, what-if, DNS Control, workloads ───────────────────
def _tenant(dns_rules=None):
    from test_path_zia_modules import Tenant
    from zia_module_fixtures import MODULE_ROUTES
    routes = copy.deepcopy(MODULE_ROUTES)
    routes["/zia/firewallFilteringRules"] = [copy.deepcopy(ONE_CLICK)] + routes["/zia/firewallFilteringRules"]
    if dns_rules is not None:
        routes["/zia/firewallDnsRules"] = dns_rules
    return Tenant(routes)


def _fw(res):
    return next(m for m in res["zia_modules"]["modules"] if m["key"] == "firewall")


def _one_click(m):
    return next(c for c in m["criteria"] if c["name"] == "App service groups") if m["rule"] and m["rule"]["name"] == ONE_CLICK["name"] else \
        next(c for o in m["could_override"] if o["name"] == ONE_CLICK["name"] for c in o["criteria"] if c["name"] == "App service groups")


def test_the_one_click_rule_decides_a_microsoft_365_host_in_the_path_analyzer():
    """ASVS V1.4.4 · CWE-697: outlook.office365.com is allowed by the Office 365 One Click rule, definitely, with the reason and the list named in the result."""
    keep()
    res = pa.analyze(_tenant(), "outlook.office365.com", "off", "windows", scope=pa.full_path_scope())
    fw = _fw(res)
    assert fw["rule"]["name"] == "Office 365 One Click Rule" and fw["verdict"] == "allow" and fw["certainty"] == "definite"
    c = next(c for c in fw["criteria"] if c["name"] == "App service groups")
    assert c["state"] == "match" and "'Exchange Online'" in c["detail"] and f"list version {VERSION}" in c["detail"]
    assert any("Microsoft's published endpoint list" in n for n in fw["notes"])
    assert res["app_service_list"]["present"] and res["app_service_list"]["version"] == VERSION


def test_an_address_outside_microsoft_365_is_not_decided_by_the_one_click_rule():
    """ASVS V1.4.4 · CWE-697: an address in none of the published ranges does not match the One Click rule: the next rule decides, and that is definite, not conditional."""
    keep()
    fw = _fw(pa.analyze(_tenant(), "203.0.113.9", "off", "windows", scope=pa.full_path_scope()))
    assert fw["rule"]["name"] == "Allow web" and fw["certainty"] == "definite" and not fw["could_override"]


def test_without_the_list_the_one_click_rule_is_unknown_as_before():
    """ASVS V1.4.4 · CWE-754: with no list kept the One Click rule is never a match for every destination: it does not decide, and where its allow would differ it is an earlier rule that might decide (unknown)."""
    fw = _fw(pa.analyze(_tenant(), "outlook.office365.com", "off", "windows", scope=pa.full_path_scope()))
    assert fw["rule"]["name"] == "Allow web"
    quic = _fw(pa.analyze(_tenant(), "40.97.1.2", "off", "windows", scope=pa.full_path_scope(), protocol="udp", port=443))
    assert quic["rule"]["name"] == "Block QUIC" and quic["certainty"] == "conditional"
    c = _one_click(quic)
    assert c["state"] == "unknown" and "Advanced settings" in c["detail"]


def test_a_port_microsoft_does_not_publish_keeps_the_one_click_rule_conditional():
    """ASVS V1.4.4 · CWE-697: TCP/22 to an Exchange address: Microsoft publishes the set for 80 and 443 only, so the One Click rule might decide and the block is conditional."""
    keep()
    fw = _fw(pa.analyze(_tenant(), "40.97.1.2", "off", "windows", scope=pa.full_path_scope(), protocol="tcp", port=22))
    assert fw["certainty"] == "conditional"
    assert _one_click(fw)["state"] == "unknown" and "not TCP/22" in _one_click(fw)["detail"]


def test_the_what_if_for_a_user_keeps_the_match():
    """ASVS V1.4.4 · CWE-697: with an identity given (what-if) the One Click rule still matches by the list."""
    keep()
    res = pa.analyze(_tenant(), "contoso.sharepoint.com", "off", "windows", scope=pa.full_path_scope(), identity={"group": "Finance"})
    fw = _fw(res)
    assert res["whatif"]["identity"] and fw["rule"]["name"] == ONE_CLICK["name"]


def test_a_dns_rule_on_office365_matches_the_name_looked_up():
    """ASVS V1.4.4 · CWE-697: a DNS Control rule on the OFFICE365 group matches the looked-up name (a lookup has no web port)."""
    keep()
    dns = [{"id": 1, "name": "Resolve M365", "order": 1, "state": "ENABLED", "action": "ALLOW", "appServiceGroups": [{"id": 361, "name": "OFFICE365"}]},
           {"id": 2, "name": "Block the rest", "order": 2, "state": "ENABLED", "action": "BLOCK"}]
    res = pa.analyze(_tenant(dns), "outlook.office365.com", "off", "windows", scope=pa.full_path_scope())
    d = next(m for m in res["zia_modules"]["modules"] if m["key"] == "dns")
    assert d["rule"]["name"] == "Resolve M365" and d["certainty"] == "definite"


def test_a_workload_forwarding_rule_on_office365_is_evaluated():
    """ASVS V1.4.4 · CWE-697: a Cloud & Branch Connector forwarding rule on the OFFICE365 group decides for a Microsoft 365 address and is passed over for another."""
    import workload_path as wp
    import zpa_path as zp
    from test_path_zpa_workloads import fwd, wl, ztw_data, ztw_snap
    lst = keep()
    data = ztw_data([fwd(1, 1, "M365 direct", "DIRECT", appServiceGroups=[{"id": 361, "name": "OFFICE365"}]), fwd(9, -1, "Default", "ZIA")])
    snap = dict(ztw_snap(data), _app_service_list=lst)
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("40.97.1.2", "443"))["go"] == "direct"
    assert wp.evaluate(snap, wl(ip="10.0.0.1"), zp.destination("203.0.113.9", "443"))["go"] == "zia"
    nolist = wp.evaluate(dict(snap, _app_service_list=None), wl(ip="10.0.0.1"), zp.destination("40.97.1.2", "443"))
    assert nolist["go"] == "conditional"


# ── Test a list ──────────────────────────────────────────────────────
def test_test_a_list_decides_microsoft_365_rows_with_the_one_click_rule():
    """ASVS V1.4.4 · CWE-697: in Test a list Teams media and QUIC to Microsoft 365 are allowed by the One Click rule and the same ports elsewhere blocked, each definite; rows that share a trace never mix a Microsoft 365 address with another."""
    import bulk_test as bt
    from test_bulk_test import Sleeps, Tenant as BulkTenant
    from zia_module_fixtures import MODULE_ROUTES

    class T(BulkTenant):
        def __init__(self):
            super().__init__()
            self.routes = dict(self.routes, **copy.deepcopy(MODULE_ROUTES))
            self.routes["/zia/firewallFilteringRules"] = [copy.deepcopy(ONE_CLICK)] + self.routes["/zia/firewallFilteringRules"]
    text = ("destination,port,protocol\n13.107.64.5,3478,udp\n203.0.113.9,3478,udp\n40.97.1.2,443,udp\n203.0.113.9,443,udp\n"
            "outlook.office365.com,443,udp\n")
    before = {(r["target"], r["port"]): (r["result"], r["rule"]) for r in bt.run(T(), bt.parse(text), scope=pa.full_path_scope(), sleep=Sleeps()).rows()}
    assert {v[0] for v in before.values()} == {"unverified"}
    keep()
    rows = {(r["target"], r["port"]): (r["result"], r["rule"]) for r in bt.run(T(), bt.parse(text), scope=pa.full_path_scope(), sleep=Sleeps()).rows()}
    assert rows == {("13.107.64.5", 3478): ("allowed", ONE_CLICK["name"]), ("203.0.113.9", 3478): ("blocked", "Default Firewall Filtering Rule"),
                    ("40.97.1.2", 443): ("allowed", ONE_CLICK["name"]), ("203.0.113.9", 443): ("blocked", "Block QUIC"),
                    ("outlook.office365.com", 443): ("allowed", ONE_CLICK["name"])}


def test_an_app_service_unknown_is_about_the_destination_not_the_context():
    """ASVS V1.4.4 · CWE-697: Test a list does not count a rule unknown only on its app service group as 'blocks in some contexts': it is the destination that is not known."""
    import bulk_test as bt
    assert bt._context_only({"criteria": [{"name": "Groups", "state": "unknown"}]})
    assert not bt._context_only({"criteria": [{"name": "App service groups", "state": "unknown"}]})


# ── Shadowed rules ───────────────────────────────────────────────────
SERVICES = [{"id": 12, "name": "HTTPS", "destTcpPorts": [{"start": 443, "end": 443}]},
            {"id": 25, "name": "SMTP", "destTcpPorts": [{"start": 25}]},
            {"id": 30, "name": "Web", "destTcpPorts": [{"start": 80}, {"start": 443}]}]
GROUPS = [{"id": 40, "name": "Web group", "services": [{"id": 12, "name": "HTTPS"}]}]


def _later(**kw):
    r = {"id": 60, "name": "Block Outlook", "order": 5, "state": "ENABLED", "action": "BLOCK_DROP",
         "destAddresses": ["outlook.office365.com", "40.96.0.0/16", "2603:1006::/48"], "nwServices": [{"id": 12, "name": "HTTPS"}]}
    r.update(kw)
    return r


def _shadow(later, lst="kept", services=SERVICES, groups=GROUPS):
    lst = m365.load() if lst == "kept" else lst
    one = dict(ONE_CLICK, order=1)
    res = sr.analyse({"firewall": [one, later]}, app_list=lst, network_services=services, network_service_groups=groups)
    return [f for f in res["findings"] if f["rule"] == later["name"] and f["kind"] == "shadowed"], res


def test_a_later_rule_on_microsoft_365_destinations_is_shadowed_by_the_one_click_rule():
    """ASVS V1.4.4 · CWE-561 · CWE-697: a later firewall rule whose host names and ranges are all published Microsoft 365 endpoints, on a port Microsoft publishes, never matches below the One Click rule; the finding names the list."""
    keep()
    found, res = _shadow(_later())
    assert len(found) == 1 and found[0]["shadowed_by"]["name"] == ONE_CLICK["name"]
    assert f"list version {VERSION}" in found[0]["reason"] and found[0]["via"]
    assert "Microsoft's published endpoint list" in res["notes"]["firewall"]
    assert _shadow(_later(nwServices=[], nwServiceGroups=[{"id": 40, "name": "Web group"}]))[0]


@pytest.mark.parametrize("later,why", [
    (_later(), "no list"),
    (_later(destAddresses=["outlook.office365.com", "203.0.113.0/24"]), "an address outside the ranges"),
    (_later(destAddresses=["outlook.office365.com", "example.com"]), "a host name not in the list"),
    (_later(destAddresses=["*.officeapps.live.com"]), "a wildcard whose apex is not in the list"),
    (_later(destAddresses=["2603:1006::/39"]), "an IPv6 block wider than the published one"),
    (_later(destAddresses=["40.96.0.0-41.0.0.0"]), "a range past the published block"),
    (_later(nwServices=[]), "no port limit (any port)"),
    (_later(nwServices=[{"id": 25, "name": "SMTP"}]), "a port Microsoft does not publish for the set"),
    (_later(nwServices=[{"id": 99, "name": "Unread"}]), "a network service that was not read"),
    (_later(destIpGroups=[{"id": 1, "name": "Group"}]), "an IP group whose members are not compared"),
    (_later(appServiceGroups=[{"id": 4, "name": "ZOOM"}]), "another app service group"),
])
def test_shadowing_is_never_claimed_without_proof(later, why):
    """ASVS V1.4.4 · CWE-697 · CWE-754: no shadowed finding unless every destination and port of the later rule is proven to be a published Microsoft 365 endpoint by a current list."""
    if why != "no list":
        keep()
    found, _ = _shadow(later, lst=None if why == "no list" else "kept")
    assert found == [], why


def test_a_stale_list_proves_no_shadowing():
    """ASVS V1.4.4 · CWE-672: a list not confirmed for 30 days does not prove that a later rule is hidden."""
    keep(now=dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=45))
    assert _shadow(_later())[0] == []


def test_without_network_services_read_nothing_is_claimed():
    """ASVS V1.4.4 · CWE-754: when the network services were not read, the later rule's ports are not known, so it is not reported."""
    keep()
    assert _shadow(_later(), services=None, groups=None)[0] == []


def test_the_shadow_reader_reads_network_services_only_when_they_can_matter():
    """ASVS V1.14.1 · CWE-200 · CWE-863: the network services are read (GET, firewall in scope) only when a firewall rule names an app service and a list is kept."""
    class C:
        def __init__(self, rules):
            self.rules, self.paths = rules, []

        def get(self, ep, p=None):
            self.paths.append(ep)
            if ep.endswith("firewallFilteringRules"):
                return self.rules, 200
            if ep.endswith("networkServices"):
                return SERVICES, 200
            if ep.endswith("networkServiceGroups"):
                return GROUPS, 200
            return {}, 404
    scope = {"read": ["firewall"], "scopes": ["zia_extras"], "not_in_scope": {}}
    plain = C([dict(_later(), order=1)])
    sr.read_policies(plain, scope)
    assert not any("networkService" in p for p in plain.paths)
    keep()
    c = C([dict(ONE_CLICK, order=1), _later()])
    got = sr.read_policies(c, scope)
    assert [p for p in c.paths if "networkService" in p] == ["/zia/networkServices", "/zia/networkServiceGroups"]
    assert got["network_services"] == SERVICES and got["network_service_groups"] == GROUPS


# ── The sample tenant ────────────────────────────────────────────────
def _sample():
    import offline_tenant as ot
    st = ot.sample_store(reset=True)
    return ot.client_for(ot.creds_for(st), "raw")


def test_the_sample_tenant_shows_the_one_click_rule_with_its_excerpt():
    """ASVS V1.4.4 · CWE-697: the made-up sample tenant has the predefined Office 365 One Click rule; with no list kept its short excerpt matches Exchange Online and says it is not the real list."""
    import sample_tenant
    assert any(r["name"] == "Office 365 One Click Rule" and r["appServiceGroups"][0]["name"] == "OFFICE365" for r in sample_tenant.FIREWALL_RULES)
    res = pa.analyze(_sample(), "outlook.office365.com", "off", "windows", scope=pa.full_path_scope())
    fw = _fw(res)
    c = next(c for c in fw["criteria"] if c["name"] == "App service groups")
    assert fw["rule"]["name"] == "Office 365 One Click Rule" and c["state"] == "match"
    assert "sample tenant's short excerpt of Microsoft's list, not the real list" in c["detail"]
    assert res["app_service_list"]["source"] == "sample"


def test_the_excerpt_is_never_used_for_a_real_tenant_and_a_kept_list_wins():
    """ASVS V1.4.4 · CWE-345: the sample's excerpt is for the sample only: a live (fake) tenant without a list stays unknown, and a kept list replaces the excerpt on the sample."""
    assert aps.current(_tenant()) is None
    assert aps.current(_sample()).meta["source"] == "sample"
    keep()
    assert aps.current(_sample()).meta["source"] == "imported"


# ── Advanced settings API and page ───────────────────────────────────
def _api():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_the_api_reads_switches_imports_and_removes_and_audits_each_change():
    """ASVS V4.1.3 · V7.2.1 · CWE-778: the setting starts off; switching, importing and removing are audited; a refused import is a 400 in words and Fetch now while off is a 409."""
    c = _api()
    st = c.get("/api/m365-endpoints").json()
    assert st["enabled"] is False and st["present"] is False and st["host"] == "endpoints.office.com"
    assert c.post("/api/m365-endpoints/refresh").status_code == 409
    bad = c.post("/api/m365-endpoints/import", json={"content": "{}", "version": ""})
    assert bad.status_code == 400 and "not Microsoft's endpoint list" in bad.json()["detail"]
    assert c.post("/api/m365-endpoints/import", json={"content": fixture_bytes().decode(), "version": "12"}).status_code == 400
    ok = c.post("/api/m365-endpoints/import", json={"content": fixture_bytes().decode(), "version": VERSION})
    assert ok.status_code == 200 and ok.json()["version"] == VERSION and ok.json()["source"] == "imported"
    assert c.put("/api/m365-endpoints/settings", json={"enabled": True}).json()["enabled"] is True
    assert c.delete("/api/m365-endpoints").json()["present"] is False
    log = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    for event in ("m365_endpoints_import", "m365_endpoints_settings", "m365_endpoints_remove"):
        assert event in log


def test_an_oversized_import_is_refused_by_the_api():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: an import body past the list's cap is refused (422 or 413) and nothing is kept."""
    c = _api()
    r = c.post("/api/m365-endpoints/import", json={"content": "[" + " " * (m365.MAX_BYTES + 2048) + "]", "version": ""})
    assert r.status_code in (413, 422) and m365.load() is None


def test_the_advanced_page_has_the_section_off_by_default_with_help():
    """WCAG 2.2 SC 3.3.2 · SC 4.1.2 · ASVS V14.1.1: the Advanced settings section names the destination, starts unticked, labels each control and has help for each."""
    html = (ROOT / "static" / "report_advanced.html").read_text(encoding="utf-8")
    for needle in ('<section id="m365" aria-labelledby="advM365H">', 'href="#m365"', '<input type="checkbox" id="advM365On" role="switch" aria-describedby="advM365Box">',
                   '<label class="adv-field" for="advM365File">', '<label class="adv-field" for="advM365Ver">', "endpoints.office.com"):
        assert needle in html, needle
    assert 'id="advM365On" role="switch" checked' not in html
    from test_c6_tooltips import CAT
    page = CAT["pages"]["/report/advanced"]
    for sel in ("#advM365On", "#advM365Fetch", "#advM365Remove", "#advM365File", "#advM365Ver", "#advM365Import"):
        assert sel in page and page[sel]["effect"] == "local", sel
    js = (ROOT / "static" / "advanced.js").read_text(encoding="utf-8")
    assert "/api/m365-endpoints" in js and "innerHTML = rows.map" in js and "E(st.last_error)" in js


def test_the_destination_is_declared_with_the_other_outbound_destinations():
    """ASVS V14.1.1 · V12.6.1 · CWE-1059: endpoints.office.com is the fetcher's only host and is listed in SECURITY.md with the app's other outbound calls, as off by default."""
    assert m365.ALLOWED_HOSTS == frozenset({"endpoints.office.com"})
    text = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    line = next(l for l in text.splitlines() if l.startswith("| Outbound calls"))
    assert "endpoints.office.com" in line and "off by default" in line
