"""App service groups out of the box (endpoint_snapshots, vendor_endpoints,
m365_endpoints, app_services).

Bundled, dated excerpts of the six providers' published lists make their
groups match offline with nothing fetched; an excerpt shows a match, never
a no match, and expires; a kept list (fetched or imported) wins. GoTo's
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
DAY0 = es.captured()
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


def crit(dest, names, now=SOON, vendors=None, lst="current"):
    ip = None
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        pass
    rule = {"appServiceGroups": [{"name": n} for n in names]}
    if lst == "current":
        lst = aps.current(now=now)
    return aps.criterion(rule, "" if ip is not None else dest, ip, T443, lst, now=now, vendors=vendors)


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
@pytest.mark.parametrize("pid", sorted(es.VENDOR))
def test_every_provider_excerpt_passes_the_strict_parser_and_is_dated_and_sourced(pid):
    """ASVS V5.1.3 · V14.2.1 · CWE-20: each bundled excerpt is checked like a fetched list (public, not over-broad), names an https source and carries its date."""
    lst = es.vendor_list(pid)
    assert lst is not None and lst.bundled and lst.partial
    assert lst.counts["ipv4"] + lst.counts["ipv6"] + lst.counts["hosts"] > 0
    assert lst.meta["source_url"].startswith("https://") and lst.meta["fetched_at"].startswith(es.SNAPSHOT_DATE)
    assert es.SNAPSHOT_DATE in lst.describe()


def test_the_microsoft_365_excerpt_passes_microsofts_parser_and_covers_every_service_area():
    """ASVS V5.1.3 · CWE-20: the Microsoft 365 excerpt is Microsoft's own JSON shape, checked by the same parser as a fetched list."""
    lst = es.m365_list()
    assert lst.bundled and lst.partial and not lst.stale(SOON)
    assert {s["area"] for s in lst.sets} == {"Exchange", "Skype", "SharePoint", "Common"}
    assert es.SNAPSHOT_DATE in lst.describe()


def test_a_tampered_excerpt_fails_loudly(monkeypatch):
    """ASVS V5.1.3 · CWE-20 · CWE-345: an excerpt entry that is not a public range is refused by the parser, never used."""
    monkeypatch.setitem(es.VENDOR, "talkdesk", dict(es.VENDOR["talkdesk"], ips=["10.0.0.0/8"]))
    es._CACHE.pop("v:talkdesk", None)
    with pytest.raises(ve.ListError, match="public"):
        es.vendor_list("talkdesk")
    es._CACHE.pop("v:talkdesk", None)


# ── Matching from the excerpts, offline ───────────────────────────────
@pytest.mark.parametrize("names,dest", [
    (["ZOOM"], "170.114.5.5"), (["ZOOM"], "us05web.zoom.us"), (["WEBEX"], "62.109.200.1"), (["WEBEX"], "acme.webex.com"),
    (["RINGCENTRAL"], "199.68.212.10"), (["RINGCENTRAL"], "media.ringcentral.com"), (["LOGMEIN"], "67.217.70.1"),
    (["GOTO"], "global.gotoconference.com"), (["TALKDESK"], "acme.talkdesk.com"), (["OFFICE365"], "outlook.office365.com"),
    (["OFFICE365"], "52.112.4.4"),
])
def test_each_providers_group_matches_from_its_excerpt_with_nothing_fetched(names, dest):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: out of the box a destination in a provider's published list matches its group, saying which excerpt and how old."""
    c = crit(dest, names)
    assert c["state"] == "match", c
    assert "bundled excerpt" in c["detail"] and es.SNAPSHOT_DATE in c["detail"] and "(10 days old)" in c["detail"]


@pytest.mark.parametrize("names,dest", [(["ZOOM"], "8.8.8.8"), (["WEBEX", "ZOOM"], "203.0.113.9"), (["OFFICE365"], "8.8.8.8"),
                                        (["OFFICE365"], "example.org"), (["TALKDESK"], "example.org")])
def test_an_excerpt_never_says_no_match(names, dest):
    """ASVS V1.4.4 · CWE-697 · CWE-754: a destination not in an excerpt stays unknown (an excerpt is not the whole list), with what to do."""
    c = crit(dest, names)
    assert c["state"] == "unknown", c
    assert "cannot rule it out" in c["detail"] and "Advanced settings" in c["detail"]


def test_an_expired_excerpt_settles_nothing():
    """ASVS V1.4.4 · CWE-672: an excerpt older than its limit leaves the group unknown, naming its age limit."""
    for names, dest in ((["ZOOM"], "170.114.5.5"), (["OFFICE365"], "outlook.office365.com")):
        c = crit(dest, names, now=LATE)
        assert c["state"] == "unknown" and str(es.BUNDLED_MAX_AGE_DAYS) in c["detail"], c


def test_zscalers_own_groups_stay_unknown_with_the_exact_reason():
    """ASVS V1.4.4 · CWE-1059: a Zscaler-managed group whose members the API never gives stays unknown, and says the SDK has no call for it."""
    c = crit("170.114.5.5", ["ZSCALER_SERVICES"])
    assert c["state"] == "unknown" and "no call that lists app service groups or their members" in c["detail"]
    mixed = crit("8.8.8.8", ["ZOOM", "ZSCALER_SERVICES"])
    assert mixed["state"] == "unknown" and "members of ZSCALER_SERVICES are not known" in mixed["detail"]
    assert crit("170.114.5.5", ["ZOOM", "ZSCALER_SERVICES"])["state"] == "match"   # any one group is enough


def test_the_sdk_still_has_no_app_service_group_call():
    """ASVS V14.2.1 · CWE-1059: the reason shown is still true of the installed SDK: ZIA's firewall service lists no app services or their groups."""
    from zscaler.zia import cloud_firewall
    names = [n.lower() for n in dir(cloud_firewall.FirewallResourcesAPI)]
    assert not [n for n in names if "app_service" in n or "appservice" in n]
    assert "list_network_app_groups" in names                  # a different object: application signatures


def test_a_kept_whole_list_wins_over_the_excerpt():
    """ASVS V1.4.4 · CWE-697: a current imported list is the whole list, so a destination outside it is a no match even when the excerpt would match."""
    ve.import_file("zoom", "3.7.35.0/25\n", now=SOON)
    c = crit("170.114.5.5", ["ZOOM"])
    assert c["state"] == "no_match", c
    assert crit("3.7.35.9", ["ZOOM"])["detail"].count("imported") == 1


def test_an_address_only_kept_list_lets_the_excerpts_host_names_match():
    """ASVS V1.4.4 · CWE-697: Zoom's fetched list names no host names, so the excerpt's still settle a host name (a match only)."""
    ve.import_file("zoom", "170.114.0.0/16\n", now=SOON)
    c = crit("us05web.zoom.us", ["ZOOM"])
    assert c["state"] == "match" and "bundled excerpt" in c["detail"]


def test_a_stale_kept_list_gives_way_only_to_a_newer_excerpt():
    """ASVS V1.4.4 · CWE-672: a stale kept list older than the excerpt gives way to it; one newer than the excerpt still settles nothing."""
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
    z = es.vendor_list("zoom")
    assert z.freshness(SOON) == {"state": "bundled", "label": z.freshness(SOON)["label"]}
    assert "from 2026-11-04, 10 days old" in z.freshness(SOON)["label"] and "never a no match" in z.freshness(SOON)["label"]
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
    assert rows["webex"]["in_use"] == "kept" and rows["zoom"]["in_use"] == "bundled"
    assert rows["zoom"]["bundled"]["date"] == es.SNAPSHOT_DATE and rows["zoom"]["bundled"]["source_url"].startswith("https://")
    assert rows["zoom"]["freshness"]["state"] == "bundled" and rows["webex"]["freshness"]["state"] == "fresh"
    assert "no call that lists app services or app service groups" in st["zscaler_groups"] and st["bundled_max_age_days"] == es.BUNDLED_MAX_AGE_DAYS
    ms = m365.status(SOON)
    assert ms["present"] is False and ms["in_use"] == "bundled" and ms["bundled"]["date"] == es.SNAPSHOT_DATE


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
def test_a_bad_goto_answer_is_refused_and_the_excerpt_still_matches(monkeypatch, status, headers, body, why):
    """ASVS V12.6.1 · V5.1.3 · CWE-918 · CWE-20 · CWE-400: a redirect, an oversized or tampered answer is refused and recorded; nothing is kept and the excerpt still works."""
    Net(monkeypatch, status, headers, body)
    ve.set_enabled("goto", True)
    with pytest.raises(ve.ListError, match=why):
        ve.fetch("goto", now=SOON)
    assert ve.load("goto") is None and ve.settings()["last_error"]["goto"]
    assert crit("67.217.70.1", ["GOTO"])["state"] == "match"


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


def test_the_status_routes_carry_the_excerpts_and_goto_has_its_own_switch(monkeypatch):
    """ASVS V4.1.3 · V12.6.1 · CWE-918 · CWE-1059: GET says kept or bundled and why Zscaler's groups stay unknown; GoTo's switch turns on alone; Fetch now while off is a 409 that sends nothing; an unknown provider is a 400."""
    net = Net(monkeypatch)
    c = _api()
    st = c.get("/api/vendor-endpoints")
    assert st.status_code == 200
    body = st.json()
    assert body["zscaler_groups"] and all(p["in_use"] == "bundled" and p["freshness"]["state"] == "bundled" for p in body["providers"])
    assert c.post("/api/vendor-endpoints/refresh", json={"provider": "goto"}).status_code == 409
    assert c.post("/api/vendor-endpoints/refresh", json={"provider": "nope"}).status_code == 400
    on = c.put("/api/vendor-endpoints/settings", json={"provider": "goto", "enabled": True}).json()
    assert {p["id"]: p["enabled"] for p in on["providers"]} == {"zoom": False, "webex": False, "ringcentral": False, "goto": True, "talkdesk": False}
    ms = c.get("/api/m365-endpoints").json()
    assert ms["in_use"] == "bundled" and ms["bundled"]["date"] == es.SNAPSHOT_DATE
    assert net.sent == []


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
