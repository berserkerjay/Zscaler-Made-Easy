"""App service groups out of the box (endpoint_snapshots, vendor_endpoints,
m365_endpoints, app_services).

A bundled, dated excerpt of Microsoft's published Microsoft 365 list,
copied from Microsoft's version 2026043000, makes Microsoft 365 groups
match offline with nothing fetched; an excerpt shows a match, never a no
match, and expires; a kept list (fetched or imported) wins. No other
provider ships an excerpt (none could be checked against its source), so
their groups match only after a fetch or an import. GoTo's
JSON list is fetchable (off by default, its own switch, Fetch now only)
and parsed strictly; Webex, RingCentral and Talkdesk stay import-only.
Zscaler's own groups stay unknown, with the exact reason. Freshness labels,
the API's status contract and the declared outbound hosts. No test reaches
a provider or a tenant: the network is refused unless a test installs its
recorder, and the clock is passed in."""
from __future__ import annotations

import datetime as dt
import ipaddress
import json
import os
from pathlib import Path

import pytest
import requests
import requests.adapters
from requests.models import Response

import app_services as aps
import endpoint_snapshots as es
import m365_endpoints as m365
import vendor_endpoints as ve

ROOT = Path(__file__).resolve().parents[1]
T443 = {"protocol": "tcp", "port": 443}
DAY0 = es.checked()
SOON = DAY0 + dt.timedelta(days=10)
LATE = DAY0 + dt.timedelta(days=es.BUNDLED_MAX_AGE_DAYS + 20)
GOTO_JSON = json.dumps({"updated": "2026-11-01", "version": "1.2.3", "regions": [
    {"name": "us-east", "time": "12:30", "ipv4": ["67.217.64.0/19", "216.115.208.0/20"], "ipv6": ["2a05:a00::/32"]},
    {"name": "eu", "ranges": [{"cidr": "185.36.20.0/22", "note": "media"}]}]})


@pytest.fixture(autouse=True)
def _own_folder(tmp_path, monkeypatch):
    """Each test keeps its lists in its own folder; the network is refused unless a test installs its recorder."""
    monkeypatch.setenv("DLP_CHECK_M365_DIR", str(tmp_path / "lists"))
    monkeypatch.delenv("DLP_CHECK_M365_MAX_AGE_DAYS", raising=False)

    def refuse(self, request, **kw):
        raise AssertionError(f"no network in tests: {request.url}")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", refuse)
    ve._CACHE.clear()
    ve._CURRENT["lists"] = None
    m365._CACHE.update(key=None, list=None)
    yield
    ve._CACHE.clear()
    ve._CURRENT["lists"] = None
    m365._CACHE.update(key=None, list=None)


def crit(dest, names, now=SOON, vendors=None, lst="current", traffic=T443):
    ip = None
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        pass
    rule = {"appServiceGroups": [{"name": n} for n in names]}
    if lst == "current":
        lst = aps.current(now=now)
    return aps.criterion(rule, "" if ip is not None else dest, ip, traffic, lst, now=now, vendors=vendors)


# A made-up excerpt in VENDOR's shape, installed only by the tests that
# check the mechanism; nothing like it ships (es.VENDOR is empty).
TEST_EXCERPT = {"source": "https://example.com/test-excerpt", "source_name": "a made-up test excerpt",
                "ips": ["170.114.0.0/16"], "hosts": ["*.zoom.us"]}


def _install_excerpt(monkeypatch, pid="zoom", snap=None):
    monkeypatch.setitem(es.VENDOR, pid, dict(snap or TEST_EXCERPT))
    es._CACHE.pop("v:" + pid, None)
    monkeypatch.setattr(es, "_CACHE", dict(es._CACHE))


class Net:
    """A recorder in place of the network: every request is kept, the answer comes from the table."""

    def __init__(self, monkeypatch, status=200, headers=None, body=GOTO_JSON.encode()):
        self.sent = []
        self.answer = (status, headers or {}, body)
        monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", self.send)
        for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE"):
            monkeypatch.delenv(k, raising=False)

    def send(self, request, stream=False, timeout=None, verify=True, **kw):
        self.sent.append({"url": request.url, "method": request.method, "timeout": timeout, "verify": verify})
        r = Response()
        r.status_code, r._content, r.url, r.request = self.answer[0], self.answer[2], request.url, request
        r.headers.update(self.answer[1])
        return r


# ── The bundled excerpts themselves ───────────────────────────────────
def test_no_unchecked_provider_excerpt_ships():
    """ASVS V14.2.1 · CWE-1059 · CWE-345: only data checked against its official source ships: no Zoom, Webex, RingCentral, GoTo or Talkdesk excerpt."""
    assert es.VENDOR == {}
    for pid in ve.PROVIDERS:
        assert es.vendor_list(pid) is None and ve.bundled(pid) is None
    assert set(es.summary(SOON)["providers"]) == {"m365"}


def test_a_provider_excerpt_if_one_is_added_passes_the_strict_parser_and_is_dated(monkeypatch):
    """ASVS V5.1.3 · V14.2.1 · CWE-20: an excerpt added to VENDOR is checked like a fetched list, names its source and carries its date."""
    _install_excerpt(monkeypatch)
    lst = es.vendor_list("zoom")
    assert lst is not None and lst.bundled and lst.partial and lst.counts == {"ipv4": 1, "ipv6": 0, "hosts": 1}
    assert lst.meta["source_url"].startswith("https://") and lst.meta["fetched_at"].startswith(es.SNAPSHOT_DATE)
    assert lst.meta["checked_at"].startswith(es.CHECKED_DATE) and es.SNAPSHOT_DATE in lst.describe()


def test_the_microsoft_365_excerpt_is_microsofts_published_version_2026043000():
    """ASVS V5.1.3 · V14.2.1 · CWE-20 · CWE-345: the excerpt is Microsoft's own JSON shape, checked by the same parser as a fetched list, and dated and versioned by its source."""
    lst = es.m365_list()
    assert lst.bundled and lst.partial and not lst.stale(SOON)
    assert {s["area"] for s in lst.sets} == {"Exchange", "Skype", "SharePoint", "Common"}
    assert (es.SNAPSHOT_VERSION, es.SNAPSHOT_DATE) == ("2026043000", "2026-04-30") and lst.version == es.SNAPSHOT_VERSION
    assert es.SNAPSHOT_DATE in lst.describe() and es.SNAPSHOT_VERSION in lst.describe() and es.CHECKED_DATE in lst.describe()
    assert lst.meta["fetched_at"].startswith(es.SNAPSHOT_DATE) and lst.meta["checked_at"].startswith(es.CHECKED_DATE)


def test_the_microsoft_365_excerpt_carries_the_verified_corrections():
    """ASVS V5.1.3 · CWE-345 · CWE-697: Teams media is only Microsoft's three ranges, SharePoint is *.sharepoint.com, and Teams and SharePoint carry UDP 443."""
    sets = {x["id"]: x for x in es.M365_SETS}
    assert sets[11]["ips"] == ["52.112.0.0/14", "52.122.0.0/15", "2603:1063::/38"]
    assert sets[31]["urls"] == ["*.sharepoint.com"]
    assert sets[12]["udpPorts"] == sets[31]["udpPorts"] == sets[1]["udpPorts"] == "443"
    assert not any("<" in u for x in es.M365_SETS for u in x.get("urls", []))


def test_an_address_microsoft_does_not_publish_for_teams_media_does_not_match():
    """ASVS V1.4.4 · CWE-697 · CWE-345: 13.107.64.0/18 is not in Microsoft's Teams media set, so a destination there is not a Teams match."""
    c = crit("13.107.64.9", ["MICROSOFTTEAMS"], traffic={"protocol": "udp", "port": 3478})
    assert c["state"] == "unknown", c
    assert crit("52.112.9.9", ["MICROSOFTTEAMS"], traffic={"protocol": "udp", "port": 3478})["state"] == "match"


@pytest.mark.parametrize("dest", ["acme.sharepoint.com", "acme-my.sharepoint.com", "teams.microsoft.com"])
def test_quic_to_teams_and_sharepoint_matches(dest):
    """ASVS V1.4.4 · CWE-697: Microsoft publishes UDP 443 for Teams and SharePoint, so QUIC to them matches instead of staying unknown."""
    c = crit(dest, ["OFFICE365"], traffic={"protocol": "udp", "port": 443})
    assert c["state"] == "match", c


def test_a_tampered_excerpt_fails_loudly(monkeypatch):
    """ASVS V5.1.3 · CWE-20 · CWE-345: an excerpt entry that is not a public range, or not a range at all, is refused by the parser, never used."""
    _install_excerpt(monkeypatch, "talkdesk", dict(TEST_EXCERPT, ips=["10.0.0.0/8"]))
    with pytest.raises(ve.ListError, match="public"):
        es.vendor_list("talkdesk")
    monkeypatch.setattr(es, "M365_SETS", [dict(es.M365_SETS[0], ips=["999.1.2.3/24"])])
    es._CACHE.pop("m365", None)
    with pytest.raises(m365.ListError, match="not an IP address"):
        es.m365_list()


# ── Matching from the excerpts, offline ───────────────────────────────
@pytest.mark.parametrize("names,dest", [
    (["OFFICE365"], "outlook.office365.com"), (["OFFICE365"], "outlook.cloud.microsoft"), (["OFFICE365"], "52.112.4.4"),
    (["OFFICE365"], "acme.sharepoint.com"), (["EXCHANGEONLINE"], "40.96.1.1"), (["OFFICE365"], "login.microsoftonline-p.com"),
])
def test_microsoft_365_groups_match_from_the_excerpt_with_nothing_fetched(names, dest):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: out of the box a destination in Microsoft's published list matches its group, saying which excerpt and when it was checked."""
    c = crit(dest, names)
    assert c["state"] == "match", c
    assert "bundled excerpt" in c["detail"] and es.SNAPSHOT_VERSION in c["detail"] and "(checked 10 days ago)" in c["detail"]


@pytest.mark.parametrize("names", [["ZOOM"], ["WEBEX"], ["RINGCENTRAL"], ["GOTO"], ["LOGMEIN"], ["TALKDESK"]])
def test_other_providers_groups_stay_unknown_until_their_list_is_fetched_or_imported(names):
    """ASVS V1.4.4 · CWE-1059 · CWE-754: with no excerpt shipped, a provider's group with no kept list is unknown and says to import or fetch its list."""
    c = crit("170.114.5.5", names)
    assert c["state"] == "unknown" and "list is kept for" in c["detail"] and "Advanced settings" in c["detail"], c


@pytest.mark.parametrize("names,dest", [(["OFFICE365"], "8.8.8.8"), (["OFFICE365"], "example.org"), (["MICROSOFTTEAMS"], "13.107.64.9")])
def test_an_excerpt_never_says_no_match(names, dest):
    """ASVS V1.4.4 · CWE-697 · CWE-754: a destination not in an excerpt stays unknown (an excerpt is not the whole list), with what to do."""
    c = crit(dest, names)
    assert c["state"] == "unknown", c
    assert "cannot rule it out" in c["detail"] and "Advanced settings" in c["detail"]


def test_a_vendor_excerpt_never_says_no_match(monkeypatch):
    """ASVS V1.4.4 · CWE-697 · CWE-754: the same holds for an excerpt added to VENDOR: in it is a match, outside it is unknown."""
    _install_excerpt(monkeypatch)
    assert crit("170.114.5.5", ["ZOOM"])["state"] == "match"
    c = crit("8.8.8.8", ["ZOOM"])
    assert c["state"] == "unknown" and "cannot rule it out" in c["detail"], c


def test_an_expired_excerpt_settles_nothing():
    """ASVS V1.4.4 · CWE-672: an excerpt not checked for longer than its limit leaves the group unknown, naming its age limit."""
    c = crit("outlook.office365.com", ["OFFICE365"], now=LATE)
    assert c["state"] == "unknown" and str(es.BUNDLED_MAX_AGE_DAYS) in c["detail"], c


def test_zscalers_own_groups_stay_unknown_with_the_exact_reason():
    """ASVS V1.4.4 · CWE-1059: a Zscaler-managed group whose members the API never gives stays unknown, and says the SDK has no call for it."""
    c = crit("170.114.5.5", ["ZSCALER_SERVICES"])
    assert c["state"] == "unknown" and "no call that lists app service groups or their members" in c["detail"]
    mixed = crit("8.8.8.8", ["ZOOM", "ZSCALER_SERVICES"])
    assert mixed["state"] == "unknown" and "members of ZSCALER_SERVICES are not known" in mixed["detail"]
    ve.import_file("zoom", "170.114.0.0/16\n", now=SOON)
    assert crit("170.114.5.5", ["ZOOM", "ZSCALER_SERVICES"])["state"] == "match"   # any one group is enough


def test_the_sdk_still_has_no_app_service_group_call():
    """ASVS V14.2.1 · CWE-1059: the reason shown is still true of the installed SDK: ZIA's firewall service lists no app services or their groups."""
    from zscaler.zia import cloud_firewall
    names = [n.lower() for n in dir(cloud_firewall.FirewallResourcesAPI)]
    assert not [n for n in names if "app_service" in n or "appservice" in n]
    assert "list_network_app_groups" in names                  # a different object: application signatures


def test_a_kept_whole_list_wins_over_the_excerpt():
    """ASVS V1.4.4 · CWE-697: a current imported list is the whole list, so a destination outside it is a no match even when the excerpt would match."""
    m365.import_file(json.dumps(es.M365_SETS[:1]), "2026110100", now=SOON)
    c = crit("52.112.4.4", ["OFFICE365"])
    assert c["state"] == "no_match", c


def test_an_address_only_kept_list_lets_the_excerpts_host_names_match(monkeypatch):
    """ASVS V1.4.4 · CWE-697: a kept list that names no host names leaves the excerpt's host names to settle a host name (a match only)."""
    _install_excerpt(monkeypatch)
    ve.import_file("zoom", "170.114.0.0/16\n", now=SOON)
    c = crit("us05web.zoom.us", ["ZOOM"])
    assert c["state"] == "match" and "bundled excerpt" in c["detail"]


def test_a_stale_kept_list_gives_way_only_to_a_newer_excerpt(monkeypatch):
    """ASVS V1.4.4 · CWE-672: a stale kept list older than the excerpt gives way to it; one newer than the excerpt still settles nothing."""
    _install_excerpt(monkeypatch)
    ve.import_file("zoom", "3.7.35.0/25\n", now=DAY0 - dt.timedelta(days=60))
    assert crit("170.114.5.5", ["ZOOM"], now=DAY0 + dt.timedelta(days=1))["state"] == "match"
    ve.import_file("zoom", "3.7.35.0/25\n", now=DAY0 + dt.timedelta(days=5))
    c = crit("170.114.5.5", ["ZOOM"], now=DAY0 + dt.timedelta(days=60))
    assert c["state"] == "unknown" and "settles nothing" in c["detail"]


def test_the_microsoft_365_list_in_use_is_kept_then_sample_then_excerpt():
    """ASVS V1.4.4 · CWE-697: with none kept the Microsoft 365 excerpt is used; a kept list replaces it."""
    assert aps.current(now=SOON).bundled
    sets = json.dumps(es.M365_SETS[:1])
    m365.import_file(sets, "2026110100", now=SOON)
    assert aps.current(now=SOON).meta["source"] == "imported"


# ── Freshness labels ─────────────────────────────────────────────────
def test_freshness_labels_name_the_state_and_age():
    """ASVS V1.4.4 · CWE-754 · WCAG 2.2 SC 3.3.2: one label per state, with the date and the age in plain words."""
    z = es.m365_list()
    assert z.freshness(SOON) == {"state": "bundled", "label": z.freshness(SOON)["label"]}
    assert "as published 2026-04-30, last checked against it 2026-11-04 (10 days ago)" in z.freshness(SOON)["label"]
    assert "never a no match" in z.freshness(SOON)["label"]
    assert z.freshness(LATE)["state"] == "bundled_old" and "too old" in z.freshness(LATE)["label"]
    ve.import_file("webex", "webex.com\n", now=SOON)
    w = ve.load("webex")
    assert w.freshness(SOON + dt.timedelta(days=1)) == {"state": "fresh", "label": "Current: last confirmed 1 day ago."}
    assert w.freshness(SOON + dt.timedelta(days=45))["state"] == "stale"
    assert es.freshness("Zoom", present=False, stale=None, age=None, source=None, max_age=0)["state"] == "none"


def test_status_says_which_list_is_in_use_and_why_zscalers_groups_stay_unknown():
    """ASVS V1.4.4 · V14.1.1 · CWE-1059: every provider row says kept or bundled, the excerpt's date and source, and the freshness label."""
    ve.import_file("webex", "webex.com\n", now=SOON)
    st = ve.status(SOON)
    rows = {p["id"]: p for p in st["providers"]}
    assert rows["webex"]["in_use"] == "kept" and rows["zoom"]["in_use"] is None and "bundled" not in rows["zoom"]
    assert rows["zoom"]["freshness"]["state"] == "none" and rows["webex"]["freshness"]["state"] == "fresh"
    assert "never returns their members" in st["zscaler_groups"] and st["bundled_max_age_days"] == es.BUNDLED_MAX_AGE_DAYS
    ms = m365.status(SOON)
    assert ms["present"] is False and ms["in_use"] == "bundled" and ms["freshness"]["state"] == "bundled"
    assert (ms["bundled"]["date"], ms["bundled"]["checked"], ms["bundled"]["version"]) == ("2026-04-30", "2026-11-04", "2026043000")
    assert ms["bundled"]["source_url"].startswith("https://")


# ── GoTo's JSON list: strict parsing ──────────────────────────────────
def test_gotos_json_list_yields_only_its_address_ranges():
    """ASVS V5.1.3 · CWE-20: every address range in the JSON is taken, wherever it sits; versions, dates and times are not ranges."""
    got = ve.parse(GOTO_JSON)
    assert got == {"ips": ["67.217.64.0/19", "216.115.208.0/20", "2a05:a00::/32", "185.36.20.0/22"], "hosts": []}


@pytest.mark.parametrize("text,why", [
    ('{"ipv4": ["67.217.64.0/19",', "not valid JSON"),
    ('{"ipv4": ["10.0.0.0/8"]}', "public"),
    ('{"ipv4": ["0.0.0.0/0"]}', "wider than"),
    ('{"ipv4": ["999.1.2.3/24"]}', "not an IP address"),
    ('{"name": "GoTo", "version": "1.2.3"}', "names no address range"),
    ('{"v": NaN, "ipv4": ["67.217.64.0/19"]}', "not valid JSON"),
    ("[" * 40 + '"67.217.64.0/19"' + "]" * 40, "nested more than"),
])
def test_a_malformed_json_list_is_refused_whole(text, why):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-674 · WSTG-INPV-01: bad JSON, a private, over-broad or malformed range, nothing to match or too deep refuses the whole list."""
    with pytest.raises(ve.ListError, match=why):
        ve.parse(text)


def test_an_oversized_or_overlong_json_list_is_refused():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: a list past the byte cap, or one with too many values, is not read."""
    with pytest.raises(ve.ListError, match="larger than"):
        ve.parse(b"[" + b'"67.217.64.0/19",' * (ve.MAX_BYTES // 16) + b'"x"]')
    with pytest.raises(ve.ListError, match="more than"):
        ve.parse(json.dumps([0] * (ve.MAX_JSON_VALUES + 1)))


def test_gotos_json_file_can_be_imported_by_hand():
    """ASVS V5.1.3 · CWE-20: the same JSON, saved on another machine, imports as GoTo's list and matches its group."""
    ve.import_file("goto", GOTO_JSON, now=SOON)
    assert ve.load("goto").counts == {"ipv4": 3, "ipv6": 1, "hosts": 0}
    assert crit("185.36.21.1", ["GOTO"])["state"] == "match"


# ── No outbound call unless switched on ──────────────────────────────
def test_nothing_is_fetched_by_matching_status_or_while_switched_off(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: excerpts, status and matching send nothing; Fetch now while GoTo's switch is off sends nothing."""
    net = Net(monkeypatch)
    crit("170.114.5.5", ["ZOOM", "WEBEX", "GOTO", "RINGCENTRAL", "TALKDESK", "OFFICE365"])
    ve.status()
    m365.status()
    assert ve.settings()["enabled"] == {pid: False for pid in ve.PROVIDERS}
    with pytest.raises(ve.FetchDisabled, match="off"):
        ve.fetch("goto")
    for pid in ("webex", "ringcentral", "talkdesk"):
        with pytest.raises(ve.FetchDisabled, match="no file to fetch"):
            ve.set_enabled(pid, True)
    assert net.sent == []


def test_turned_on_goto_is_fetched_from_its_one_host_and_kept_with_its_date(monkeypatch):
    """ASVS V12.6.1 · V9.2.1 · CWE-918 · CWE-295: one GET to GoTo's published address, https, a timeout, TLS verified; kept as fetched, with its date."""
    net = Net(monkeypatch)
    ve.set_enabled("goto", True)
    st = ve.fetch("goto", now=SOON)
    row = next(p for p in st["providers"] if p["id"] == "goto")
    assert row["present"] and row["source"] == "fetched" and row["fetched_at"].startswith("2026-11-14") and row["in_use"] == "kept"
    assert [s["url"] for s in net.sent] == [ve.PROVIDERS["goto"]["fetch"]]
    assert net.sent[0]["method"] == "GET" and net.sent[0]["verify"] is True and net.sent[0]["timeout"] == ve.FETCH_TIMEOUT


@pytest.mark.parametrize("status,headers,body,why", [
    (301, {"Location": "https://evil.example/"}, b"", "redirect"),
    (200, {"Content-Length": str(ve.MAX_BYTES + 1)}, b"{}", "larger than"),
    (200, {}, b'{"ipv4": ["192.168.0.0/16"]}', "public"),
])
def test_a_bad_goto_answer_is_refused_and_nothing_is_kept(monkeypatch, status, headers, body, why):
    """ASVS V12.6.1 · V5.1.3 · CWE-918 · CWE-20 · CWE-400: a redirect, an oversized or tampered answer is refused and recorded; nothing is kept, so GoTo's group stays unknown."""
    Net(monkeypatch, status, headers, body)
    ve.set_enabled("goto", True)
    with pytest.raises(ve.ListError, match=why):
        ve.fetch("goto", now=SOON)
    assert ve.load("goto") is None and ve.settings()["last_error"]["goto"]
    assert crit("67.217.70.1", ["GOTO"])["state"] == "unknown"


def test_every_fetch_host_is_declared_in_security_md_and_the_secure_by_design_line():
    """ASVS V14.1.1 · V12.6.1 · CWE-1059: each host the app may fetch a provider's list from is declared where the outbound calls are listed."""
    import secure_by_design
    sec = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    line = secure_by_design._vendor_hosts()
    for host in sorted(ve.FETCH_HOSTS | m365.ALLOWED_HOSTS):
        assert f"https://{host}" in sec and host in line
    assert ve.FETCH_HOSTS == {"assets.zoom.us", "goto-ipblocks.live.gtc.goto.com"}


# ── Routes (existing; the contract grows additively) ─────────────────
def _api():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _clock(monkeypatch, when):
    """The routes take no clock, so the modules' own is replaced (no real clock in tests)."""
    monkeypatch.setattr(ve, "_now", lambda: when)
    monkeypatch.setattr(m365, "_now", lambda: when)


def test_the_status_routes_carry_the_excerpt_and_goto_has_its_own_switch(monkeypatch):
    """ASVS V4.1.3 · V12.6.1 · CWE-918 · CWE-1059: GET says kept, bundled or none and why Zscaler's groups stay unknown; GoTo's switch turns on alone; Fetch now while off is a 409 that sends nothing; an unknown provider is a 400."""
    net = Net(monkeypatch)
    _clock(monkeypatch, SOON)
    c = _api()
    st = c.get("/api/vendor-endpoints")
    assert st.status_code == 200
    body = st.json()
    assert body["zscaler_groups"] and all(p["in_use"] is None and p["freshness"]["state"] == "none" for p in body["providers"])
    assert c.post("/api/vendor-endpoints/refresh", json={"provider": "goto"}).status_code == 409
    assert c.post("/api/vendor-endpoints/refresh", json={"provider": "nope"}).status_code == 400
    on = c.put("/api/vendor-endpoints/settings", json={"provider": "goto", "enabled": True}).json()
    assert {p["id"]: p["enabled"] for p in on["providers"]} == {"zoom": False, "webex": False, "ringcentral": False, "goto": True, "talkdesk": False}
    ms = c.get("/api/m365-endpoints").json()
    assert ms["in_use"] == "bundled" and ms["bundled"]["date"] == es.SNAPSHOT_DATE and ms["freshness"]["state"] == "bundled"
    assert net.sent == []


def test_the_status_route_says_when_the_excerpt_is_too_old(monkeypatch):
    """ASVS V1.4.4 · CWE-672: with the clock past the excerpt's limit the route says it is too old to use (the clock is injected, so this holds on any day)."""
    _clock(monkeypatch, LATE)
    ms = _api().get("/api/m365-endpoints").json()
    assert ms["in_use"] == "bundled" and ms["bundled"]["stale"] is True and ms["freshness"]["state"] == "bundled_old"


# ── The page ──────────────────────────────────────────────────────────
def test_advanced_settings_has_gotos_switch_and_the_notes_with_help_and_new_marks():
    """ASVS V1.14.6 · CWE-1059 · WCAG 2.2 SC 3.3.2 · SC 4.1.2: the GoTo switch and button exist with help entries, the excerpt and Zscaler-group notes say what they mean, and the release marks point at them."""
    html = (ROOT / "static" / "report_advanced.html").read_text(encoding="utf-8")
    for el in ('id="advVendGotoOn"', 'id="advVendGotoFetch"', 'id="advVendBundled"', 'id="advVendZs"'):
        assert el in html
    assert 'role="switch"' in html.split('id="advVendGotoOn"')[1][:60]
    cat = (ROOT / "static" / "help_catalog.js").read_text(encoding="utf-8")
    assert '"#advVendGotoOn"' in cat and '"#advVendGotoFetch"' in cat
    assert cat == (ROOT / "browser_extension" / "help_catalog.js").read_text(encoding="utf-8")
    wn = (ROOT / "static" / "whats_new.js").read_text(encoding="utf-8")
    assert '"app-service-group-excerpts"' in wn and '"#advVendGotoOn"' in wn
