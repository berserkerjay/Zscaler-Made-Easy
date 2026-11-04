"""App service groups beyond Microsoft 365 (vendor_endpoints, app_services):
Zoom, Webex, RingCentral, GoTo and Talkdesk groups matched with the
provider's own published list, kept with its date, imported by hand or
(Zoom only) fetched when an operator turns it on and clicks Fetch now.

An oracle of match, no match and unknown; the list checked as untrusted
(malformed, oversized, private or over-broad ranges refused whole); the
optional fetch (off by default, one host, no redirect, capped); Zscaler's
own groups staying unknown; Test a list tracing two destinations apart;
and the Advanced settings API. No test reaches a provider or a tenant:
the network is a recorder that answers from a table."""
from __future__ import annotations

import datetime as dt
import ipaddress
import os

import pytest
from conftest import read_store_text
import requests
import requests.adapters
from requests.models import Response

import app_services as aps
import endpoint_snapshots
import m365_endpoints as m365
import vendor_endpoints as ve

# Zoom's own published ranges include 170.114.0.0/16 (public unicast); the
# fixture is a short excerpt in the plain-text format.
ZOOM_TXT = "# Zoom IP ranges (excerpt)\n170.114.0.0/16\n3.7.35.0/25\n2620:123:2000::/40\n"
WEBEX_TXT = "*.webex.com\nwebex.com\n62.109.192.0/18  # Webex media\n"
ONE_CLICK = {"id": 90, "name": "UCaaS One Click Rule", "order": 2, "state": "ENABLED", "predefined": True, "action": "ALLOW",
             "appServiceGroups": [{"id": 2, "name": "ZOOM"}, {"id": 3, "name": "WEBEX"}]}
T443 = {"protocol": "tcp", "port": 443}
BUNDLED = (endpoint_snapshots.vendor_list, endpoint_snapshots.m365_list)   # the real excerpts, for the page test


@pytest.fixture(autouse=True)
def _own_folder(tmp_path, monkeypatch):
    """Each test keeps its lists in its own folder; the network is refused unless a test installs its recorder."""
    monkeypatch.setenv("DLP_CHECK_M365_DIR", str(tmp_path / "lists"))
    monkeypatch.delenv("DLP_CHECK_M365_MAX_AGE_DAYS", raising=False)

    def refuse(self, request, **kw):
        raise AssertionError(f"no network in tests: {request.url}")
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", refuse)
    # These tests pin the kept-list logic, so the bundled excerpts are left
    # out here; tests/test_app_service_snapshots.py tests them on their own.
    monkeypatch.setattr(endpoint_snapshots, "vendor_list", lambda pid: None)
    monkeypatch.setattr(endpoint_snapshots, "m365_list", lambda: None)
    ve._CACHE.clear()
    ve._CURRENT["lists"] = None
    m365._CACHE.update(key=None, list=None)
    yield
    ve._CACHE.clear()
    ve._CURRENT["lists"] = None


def crit(dest, rule=ONE_CLICK, now=None):
    ip = None
    try:
        ip = ipaddress.ip_address(dest)
    except ValueError:
        pass
    return aps.criterion(rule, "" if ip is not None else dest, ip, T443, m365.load(), now=now)


# ── Which provider a name belongs to ─────────────────────────────────
@pytest.mark.parametrize("name,pid", [("ZOOM", "zoom"), ("Zoom Phone", "zoom"), ("WEBEX", "webex"), ("RINGCENTRAL", "ringcentral"),
                                      ("LOGMEIN", "goto"), ("GoTo Connect", "goto"), ("TALKDESK", "talkdesk"),
                                      ("OFFICE365", None), ("ZSCALER_SERVICES", None), ("", None)])
def test_group_names_map_to_providers(name, pid):
    """ASVS V1.4.4 · CWE-697: the UCaaS one-click group names (assumed) map to their provider; Microsoft 365 and Zscaler's own groups do not."""
    assert ve.provider_for(name) == pid


# ── The oracle ───────────────────────────────────────────────────────
@pytest.mark.parametrize("lists,dest,state,why", [
    ({}, "170.114.5.5", "unknown", "no Zoom list is kept"),
    ({"zoom": ZOOM_TXT}, "170.114.5.5", "match", "Zoom's list, imported"),
    ({"zoom": ZOOM_TXT}, "2620:123:2000::9", "match", "Zoom's list"),
    ({"zoom": ZOOM_TXT}, "8.8.8.8", "unknown", "no Webex list"),                         # Webex not known: not settled
    ({"zoom": ZOOM_TXT, "webex": WEBEX_TXT}, "8.8.8.8", "no_match", "none of the published lists"),
    ({"zoom": ZOOM_TXT, "webex": WEBEX_TXT}, "meet.webex.com", "match", "*.webex.com"),
    ({"zoom": ZOOM_TXT, "webex": WEBEX_TXT}, "zoom.us", "unknown", "not resolved"),       # a host name against Zoom's ranges
    ({"zoom": ZOOM_TXT, "webex": WEBEX_TXT}, "62.109.200.1", "match", "Webex's list"),
])
def test_ucaas_groups_oracle(lists, dest, state, why):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: a provider's kept list makes its group match or no match; anything a list cannot settle stays unknown, with the reason."""
    for pid, txt in lists.items():
        ve.import_file(pid, txt)
    c = crit(dest)
    assert c["state"] == state, c
    assert why in c["detail"]


def test_a_stale_list_settles_nothing():
    """ASVS V1.4.4 · CWE-672: a list not confirmed for longer than the age limit leaves the group unknown."""
    old = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=m365.max_age_days() + 2)
    ve.import_file("zoom", ZOOM_TXT, now=old)
    c = crit("170.114.5.5", rule={"appServiceGroups": [{"name": "ZOOM"}]})
    assert c["state"] == "unknown" and "settles nothing" in c["detail"]


def test_zscaler_own_groups_stay_unknown():
    """ASVS V1.4.4 · CWE-1059: a Zscaler-managed group whose members neither the tenant nor the SDK give stays unknown, never a guess."""
    ve.import_file("zoom", ZOOM_TXT)
    c = crit("170.114.5.5", rule={"appServiceGroups": [{"name": "ZSCALER_SERVICES"}]})
    assert c["state"] == "unknown"
    mixed = crit("8.8.8.8", rule={"appServiceGroups": [{"name": "ZOOM"}, {"name": "ZSCALER_SERVICES"}]})
    assert mixed["state"] == "unknown" and "members of ZSCALER_SERVICES are not known" in mixed["detail"]


def test_microsoft_365_and_zoom_together():
    """ASVS V1.4.4 · CWE-697: a rule naming OFFICE365 and ZOOM is unknown for a Zoom address until Zoom's list is kept, then a match."""
    rule = {"appServiceGroups": [{"name": "OFFICE365"}, {"name": "ZOOM"}]}
    assert crit("170.114.5.5", rule=rule)["state"] == "unknown"
    ve.import_file("zoom", ZOOM_TXT)
    assert crit("170.114.5.5", rule=rule)["state"] == "match"


# ── The list as untrusted input ──────────────────────────────────────
@pytest.mark.parametrize("text,why", [
    ("", "names no address range"),
    ("# only comments\n", "names no address range"),
    ("0.0.0.0/0\n", "wider than"),
    ("10.0.0.0/8\n", "not a public"),
    ("192.168.1.1\n", "not a public"),
    ("<script>alert(1)</script>\n", "is not an address range or a host name"),
    ("zoom.us\nbad host\x07\n", "control characters"),
    ("a" * 300 + ".com\n", "longer than 253"),
    ("170.114.0.0/16\n" * 2 + "x" * (ve.MAX_BYTES + 1), "larger than"),
    (b"\xff\xfe\x00", "not text"),
])
def test_a_bad_list_is_refused_whole_and_the_kept_one_stays(text, why):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-400 · CWE-1287: an empty, over-broad, private, malformed or oversized list is refused whole with the reason; the list kept before stays."""
    ve.import_file("zoom", ZOOM_TXT)
    with pytest.raises(ve.ListError) as e:
        ve.import_file("zoom", text)
    assert why in str(e.value)
    assert ve.load("zoom").counts["ipv4"] == 2


def test_an_unknown_provider_is_refused():
    """ASVS V5.1.3 · CWE-22 · CWE-20: only the known providers have files; a path-like name is refused."""
    for pid in ("../../etc/passwd", "office365", 7):
        with pytest.raises(ve.ListError):
            ve.import_file(pid, ZOOM_TXT)


def test_a_damaged_kept_file_is_not_used():
    """ASVS V5.1.3 · CWE-345: a kept file edited by hand into something that no longer passes is not used."""
    ve.import_file("zoom", ZOOM_TXT)
    with open(ve.list_path("zoom"), "w", encoding="utf-8") as f:
        f.write('{"format": 1, "provider": "zoom", "source": "imported", "fetched_at": "2026-10-31T00:00:00Z", "ips": ["0.0.0.0/0"]}')
    ve._CACHE.clear()
    assert ve.load("zoom") is None


# ── The optional fetch ───────────────────────────────────────────────
class Net:
    def __init__(self, monkeypatch, status=200, headers=None, body=ZOOM_TXT.encode()):
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


def test_fetching_is_off_by_default_and_import_only_providers_cannot_fetch(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: every provider starts off; Fetch now while off sends nothing; Webex, RingCentral and Talkdesk publish no machine-readable file, so fetching them cannot be turned on."""
    net = Net(monkeypatch)
    st = ve.status()
    assert all(p["enabled"] is False for p in st["providers"])
    assert [p["id"] for p in st["providers"] if p["fetchable"]] == ["zoom", "goto"]
    for pid in ("zoom", "goto"):
        with pytest.raises(ve.FetchDisabled, match="off"):
            ve.fetch(pid)
    for pid in ("webex", "ringcentral", "talkdesk"):
        with pytest.raises(ve.FetchDisabled, match="import its list by hand"):
            ve.set_enabled(pid, True)
        with pytest.raises(ve.FetchDisabled):
            ve.fetch(pid)
    assert net.sent == []


def test_turned_on_zoom_is_fetched_from_its_one_host_and_kept_with_its_date(monkeypatch):
    """ASVS V12.6.1 · V9.2.1 · CWE-918 · CWE-295: one GET to Zoom's published address, https, a timeout, TLS verified; the list is kept as fetched."""
    net = Net(monkeypatch)
    ve.set_enabled("zoom", True)
    st = ve.fetch("zoom")
    zoom = next(p for p in st["providers"] if p["id"] == "zoom")
    assert zoom["present"] and zoom["source"] == "fetched" and zoom["counts"] == {"ipv4": 2, "ipv6": 1, "hosts": 0}
    assert [s["url"] for s in net.sent] == [ve.PROVIDERS["zoom"]["fetch"]]
    assert net.sent[0]["method"] == "GET" and net.sent[0]["verify"] is True and net.sent[0]["timeout"] == ve.FETCH_TIMEOUT
    assert "fetched" in crit("170.114.5.5", rule={"appServiceGroups": [{"name": "ZOOM"}]})["detail"]


@pytest.mark.parametrize("status,headers,body,why", [
    (302, {"Location": "https://evil.example/x"}, b"", "redirect"),
    (500, {}, b"oops", "HTTP 500"),
    (200, {"Content-Length": str(ve.MAX_BYTES + 1)}, b"170.114.0.0/16", "larger than"),
    (200, {}, b"<html>captive portal</html>", "not an address range"),
])
def test_a_bad_answer_is_refused_recorded_and_the_kept_list_stays(monkeypatch, status, headers, body, why):
    """ASVS V12.6.1 · V5.1.3 · CWE-918 · CWE-20 · CWE-400: a redirect, an error, an oversized or malformed answer is refused, the reason recorded, and the list kept before still used."""
    ve.import_file("zoom", ZOOM_TXT)
    Net(monkeypatch, status, headers, body)
    ve.set_enabled("zoom", True)
    with pytest.raises(ve.ListError, match=why):
        ve.fetch("zoom")
    zoom = next(p for p in ve.status()["providers"] if p["id"] == "zoom")
    assert zoom["present"] and zoom["source"] == "imported" and zoom["last_error"]


@pytest.mark.parametrize("url", ["http://assets.zoom.us/docs/ipranges/Zoom.txt", "https://evil.example/Zoom.txt",
                                 "https://u:p@assets.zoom.us/x", "https://assets.zoom.us:8443/x", "file:///etc/passwd"])
def test_the_fetcher_refuses_any_other_address(monkeypatch, url):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: only https to the allowlisted host; any other scheme, host, port or credentials is refused before a request."""
    net = Net(monkeypatch)
    with pytest.raises(ve.ListError, match="Only the provider's published address"):
        ve._get(url, 1024)
    assert net.sent == []


def test_the_fetch_host_is_declared_with_the_other_outbound_destinations():
    """ASVS V14.1.1 · V12.6.1 · CWE-1059: every host fetched is listed in SECURITY.md's outbound calls."""
    sec = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "SECURITY.md"), encoding="utf-8").read()
    assert ve.FETCH_HOSTS == {"assets.zoom.us", "goto-ipblocks.live.gtc.goto.com"}
    assert "https://assets.zoom.us" in sec and "https://goto-ipblocks.live.gtc.goto.com" in sec


# ── Test a list: two destinations, two answers ───────────────────────
def test_test_a_list_decides_zoom_rows_with_the_one_click_rule_and_never_mixes_them():
    """ASVS V1.4.4 · CWE-697: in Test a list a Zoom address is allowed by the UCaaS One Click rule once Zoom's list is kept, the same port elsewhere is not, and rows in and outside the list never share one answer."""
    import copy
    import bulk_test as bt
    import path_analyzer as pa
    from test_bulk_test import Sleeps, Tenant as BulkTenant
    from zia_module_fixtures import MODULE_ROUTES

    zoom_rule = dict(ONE_CLICK, name="Zoom One Click Rule", order=0, appServiceGroups=[{"id": 2, "name": "ZOOM"}])

    class T(BulkTenant):
        def __init__(self):
            super().__init__()
            self.routes = dict(self.routes, **copy.deepcopy(MODULE_ROUTES))
            self.routes["/zia/firewallFilteringRules"] = [copy.deepcopy(zoom_rule)] + self.routes["/zia/firewallFilteringRules"]
            self.routes["/zia/advancedUrlFilterAndCloudAppSettings"] = {"enableUcaasZoom": True}
    text = "destination,port,protocol\n170.114.5.5,8801,udp\n8.8.8.8,8801,udp\n170.114.9.9,8801,udp\n"
    before = {r["target"]: r["result"] for r in bt.run(T(), bt.parse(text), scope=pa.full_path_scope(), sleep=Sleeps()).rows()}
    assert before["170.114.5.5"] == before["8.8.8.8"]              # unknown membership: no difference can be told
    ve.import_file("zoom", ZOOM_TXT)
    rows = {r["target"]: (r["result"], r["rule"]) for r in bt.run(T(), bt.parse(text), scope=pa.full_path_scope(), sleep=Sleeps()).rows()}
    assert rows["170.114.5.5"] == ("allowed", "Zoom One Click Rule") and rows["170.114.9.9"] == rows["170.114.5.5"]
    assert rows["8.8.8.8"][1] != "Zoom One Click Rule"


# ── Advanced settings API ────────────────────────────────────────────
def _api():
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def test_the_api_imports_switches_and_removes_and_audits_each_change():
    """ASVS V4.1.3 · V7.2.1 · CWE-778: every provider starts off; import, switch and remove are audited; a refused import is a 400 naming the line; Fetch now while off is a 409."""
    c = _api()
    st = c.get("/api/vendor-endpoints").json()
    assert {p["id"] for p in st["providers"]} == set(ve.PROVIDERS) and not any(p["enabled"] for p in st["providers"])
    assert c.post("/api/vendor-endpoints/refresh", json={"provider": "zoom"}).status_code == 409
    bad = c.post("/api/vendor-endpoints/import", json={"provider": "webex", "content": "webex.com\n10.0.0.0/8\n"})
    assert bad.status_code == 400 and "Line 2" in bad.json()["detail"]
    assert c.put("/api/vendor-endpoints/settings", json={"provider": "webex", "enabled": True}).status_code == 400
    ok = c.post("/api/vendor-endpoints/import", json={"provider": "webex", "content": WEBEX_TXT})
    assert ok.status_code == 200 and next(p for p in ok.json()["providers"] if p["id"] == "webex")["present"]
    assert next(p for p in c.put("/api/vendor-endpoints/settings", json={"provider": "zoom", "enabled": True}).json()["providers"]
                if p["id"] == "zoom")["enabled"] is True
    assert not next(p for p in c.delete("/api/vendor-endpoints/webex").json()["providers"] if p["id"] == "webex")["present"]
    assert c.delete("/api/vendor-endpoints/nope").status_code == 400
    log = read_store_text(os.environ["DLP_CHECK_AUDIT"])
    for event in ("vendor_endpoints_import", "vendor_endpoints_settings", "vendor_endpoints_remove"):
        assert event in log


def test_an_oversized_import_is_refused_by_the_api():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: an import body past the cap is refused (422 or 413) and nothing is kept."""
    c = _api()
    r = c.post("/api/vendor-endpoints/import", json={"provider": "zoom", "content": "1" * (ve.MAX_BYTES + 2048)})
    assert r.status_code in (413, 422) and ve.load("zoom") is None


# ── The Advanced settings card, in a real browser ─────────────────────
def _vend_driver() -> str:
    from test_findings_reflow import CDP_PRELUDE
    return CDP_PRELUDE + r"""
const [listFile] = args;
const out = {};
const seen = [];
await send('Runtime.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 1000, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: base + '/report/advanced#vendors' });
await until(() => ev(`document.readyState === 'complete'`), 'load', 60000);
await until(() => ev(`!!document.querySelector('#advVendBox strong')`), 'the provider lists', 60000);
await ev(`(() => { window.dlpDialog = { ask: async () => true };
  const f = window.fetch; window.__vend = []; window.fetch = (u, o) => { if (String(u).includes('/api/vendor-endpoints')) window.__vend.push([(o && o.method) || 'GET', String(u), (o && o.body) || '']); return f(u, o); }; return 1; })()`);
out.start = await ev(`({ on: document.getElementById('advVendZoomOn').checked, fetchDisabled: document.getElementById('advVendFetch').disabled,
  removeDisabled: document.getElementById('advVendRemove').disabled, box: document.getElementById('advVendBox').textContent,
  switchRole: document.getElementById('advVendZoomOn').getAttribute('role'), gotoOn: document.getElementById('advVendGotoOn').checked,
  gotoFetchDisabled: document.getElementById('advVendGotoFetch').disabled, gotoRole: document.getElementById('advVendGotoOn').getAttribute('role') })`);
// Import Webex's list from a text file.
await ev(`(() => { const s = document.getElementById('advVendProv'); s.value = 'webex'; s.dispatchEvent(new Event('change')); return 1; })()`);
const root = (await send('DOM.getDocument', { depth: 0 })).result.root.nodeId;
const node = await send('DOM.querySelector', { nodeId: root, selector: '#advVendFile' });
await send('DOM.setFileInputFiles', { nodeId: node.result.nodeId, files: [listFile] });
await ev(`(document.getElementById('advVendImport').click(), 1)`);
await until(() => ev(`document.getElementById('advVendBox').textContent.includes('Imported.')`), 'the import', 30000);
out.imported = await ev(`({ box: document.getElementById('advVendBox').textContent, removeDisabled: document.getElementById('advVendRemove').disabled })`);
// Turn fetching Zoom's list on: nothing is fetched by that alone.
await ev(`(() => { const c = document.getElementById('advVendZoomOn'); c.click(); return 1; })()`);
await until(() => ev(`!document.getElementById('advVendFetch').disabled`), 'Fetch now enabled', 30000);
out.on = await ev(`({ box: document.getElementById('advVendBox').textContent, calls: window.__vend.map(c => c[0] + ' ' + c[1].replace(location.origin, '') + ' ' + c[2]) })`);
// Remove Webex's list again.
await ev(`(document.getElementById('advVendRemove').click(), 1)`);
await until(() => ev(`document.getElementById('advVendBox').textContent.includes('Removed.')`), 'the removal', 30000);
out.removed = await ev(`({ box: document.getElementById('advVendBox').textContent, removeDisabled: document.getElementById('advVendRemove').disabled,
  calls: window.__vend.map(c => c[0] + ' ' + c[1].replace(location.origin, '')) })`);
out.names = await ev(`['advVendZoomOn', 'advVendFetch', 'advVendGotoOn', 'advVendGotoFetch', 'advVendProv', 'advVendFile', 'advVendImport', 'advVendRemove'].map(id => { const e = document.getElementById(id); e.disabled = false; e.focus();
  return { id, focused: document.activeElement === e, name: ((e.labels && e.labels.length ? e.labels[0].textContent : '') || e.textContent || '').trim() }; })`);
await send('Emulation.setDeviceMetricsOverride', { width: 320, height: 900, deviceScaleFactor: 1, mobile: false });
await sleep(300);
out.overflow = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def test_the_advanced_settings_card_imports_switches_and_removes_with_zoom_fetching_off_by_default(tmp_path, monkeypatch):
    """ASVS V1.14.6 · V12.6.1 · CWE-918 · WCAG 2.2 SC 4.1.2 · SC 1.4.10: the card exists in Advanced settings, as SECURITY.md says; fetching Zoom's and GoTo's lists is off by default and turning it on fetches nothing; with none kept no excerpt is shown (none ships for these providers); a provider's list is imported from a text file and removed; every control is named and reachable; nothing scrolls sideways at 320px."""
    from test_findings_reflow import run_in_browser
    monkeypatch.setattr(endpoint_snapshots, "vendor_list", BUNDLED[0])    # the page shows the excerpts as shipped
    monkeypatch.setattr(endpoint_snapshots, "m365_list", BUNDLED[1])
    lst = tmp_path / "webex.txt"
    lst.write_text(WEBEX_TXT, encoding="utf-8")
    (tmp_path / "b").mkdir()
    out = run_in_browser(tmp_path / "b", _vend_driver(), str(lst), timeout=240)
    s = out["start"]
    assert s["on"] is False and s["fetchDisabled"] is True and s["removeDisabled"] is True and s["switchRole"] == "switch"
    assert "Zoom: no list kept" in s["box"] and "Fetching from assets.zoom.us: off" in s["box"] and "Webex: no list kept" in s["box"]
    assert s["gotoOn"] is False and s["gotoFetchDisabled"] is True and s["gotoRole"] == "switch"
    assert "Fetching from goto-ipblocks.live.gtc.goto.com: off" in s["box"] and "Using the excerpt that comes with the app" not in s["box"]
    assert "GoTo: no list kept, so its app service group" in s["box"] and "never returns their members" in s["box"]
    assert "Webex's list, imported" in out["imported"]["box"] and "host names" in out["imported"]["box"] and out["imported"]["removeDisabled"] is False
    assert "Fetching from assets.zoom.us: on" in out["on"]["box"] and "Nothing is fetched until you click" in out["on"]["box"]
    assert [c.split(" ")[0] + " " + c.split(" ")[1] for c in out["on"]["calls"]] == ["POST /api/vendor-endpoints/import", "PUT /api/vendor-endpoints/settings"]
    assert '"provider":"zoom"' in out["on"]["calls"][1] and '"enabled":true' in out["on"]["calls"][1]
    assert not any("/refresh" in c for c in out["removed"]["calls"]), "turning fetching on never fetches by itself"
    assert out["removed"]["calls"][-1] == "DELETE /api/vendor-endpoints/webex" and "Webex: no list kept" in out["removed"]["box"]
    for c in out["names"]:
        assert c["name"] and c["focused"], c
    assert out["overflow"] <= 0
