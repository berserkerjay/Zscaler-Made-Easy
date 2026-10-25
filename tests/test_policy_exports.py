"""Policy exports (policy_exports, POST /api/exports/policies/start): one
workbook (or PDF review copy) per policy, every rule in order with names
instead of ids, the shadowed-rule findings per rule, read-only and only
what is in scope, Stop honoured, tenant text never a formula."""
from __future__ import annotations

import io
import os
import threading
import time
import zipfile

import pytest

import data_flow
import policy_exports as pe
from test_pdf_writer import parse_pdf, strings
from test_xlsx_writer import read_workbook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
ALL = {k: v for k, v in data_flow.full_path_scope_request().items() if k != "from_page"}
NONE = {"scopes": [], "channels": {}}
DLP_ONLY = {"scopes": ["dlp"], "channels": {"ssl_inspection": "alternative", "cloud_app_control": "alternative"}}
ZIA_ONLY = {"scopes": ["zia_extras"], "channels": {}}   # URL filtering, File Type Control and Cloud Firewall


class ReadOnlyClient:
    """A raw assessment client that answers GETs from `routes` and fails
    the test on anything else."""

    def __init__(self, routes):
        self.routes = routes
        self.calls = []

    def get(self, endpoint, params=None):
        self.calls.append(("GET", endpoint))
        if endpoint in self.routes:
            v = self.routes[endpoint]
            return (v[0], v[1]) if isinstance(v, tuple) else (v, 200)
        return {"error": "not found"}, 404

    def __getattr__(self, name):
        if name in ("post", "put", "patch", "delete", "zia", "_zs"):
            raise AssertionError(f"the export tried a write or SDK call: {name}")
        raise AttributeError(name)


def _r(i, name, order, action, **kw):
    return dict({"id": i, "name": name, "order": order, "state": "ENABLED", "action": action}, **kw)


INJECTION = '=HYPERLINK("http://evil.example/x","click")'
ROUTES = {
    "/zia/urlFilteringRules": [
        _r(2, "Block gambling", 2, "BLOCK", urlCategories=["GAMBLING", "CUSTOM_01"], groups=[{"id": 5, "name": "Finance"}],
           users=[{"id": 9, "name": "jane.doe@acme.com"}], lastModifiedTime=1700000000,
           lastModifiedBy={"id": 3, "name": "admin.person@acme.com"}, description=INJECTION, protocols=["HTTPS_RULE"]),
        _r(1, "Allow all", 1, "ALLOW"),
        _r(4, "Default URL Filter Rule", 99, "ALLOW", defaultRule=True),
        _r(3, "Old rule", 3, "BLOCK", state="DISABLED", locations=[{"id": 77, "name": "HQ"}], someNewField="kept"),
    ],
    "/zia/cloudApplicationRules": [
        _r(30, "Allow streaming", 1, None, type="STREAMING_MEDIA", applications=["YOUTUBE"], actions=["ALLOW_STREAMING_VIEW_LISTEN"]),
    ],
    "/zia/sslInspectionRules": [
        _r(40, "Do not inspect finance", 1, {"type": "DO_NOT_DECRYPT", "doNotDecryptSubActions": {"bypassOtherPolicies": True}},
           urlCategories=["CUSTOM_01"], destIpGroups=[{"id": 7, "name": "Bank IPs"}]),
    ],
    "/zia/firewallFilteringRules": [
        _r(20, "Allow DNS", 1, "ALLOW", nwServices=[{"id": 5, "name": "DNS"}]),
        _r(21, "Block DNS", 2, "BLOCK_DROP", nwServices=[{"id": 5, "name": "DNS"}], destAddresses=["evil.example.com"]),
    ],
    "/zia/fileTypeRules": [
        {"id": 50, "name": "Block executables", "order": 1, "state": "DISABLED", "filteringAction": "BLOCK",
         "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"], "operation": "DOWNLOAD"},
    ],
    "/zia/urlCategories/lite": [{"id": "CUSTOM_01", "configuredName": "Finance apps", "customCategory": True},
                                {"id": "GAMBLING", "configuredName": "Gambling"}],
    "/zia/networkServiceGroups": [{"id": 1, "name": "Web services", "services": [{"id": 5, "name": "DNS"}]}],
    "/zia/networkServices": [{"id": 5, "name": "DNS", "type": "PREDEFINED", "destUdpPorts": [{"start": 53}]}],
    "/zia/networkApplicationGroups": ({"error": "forbidden"}, 403),
    "/zia/ipDestinationGroups": [{"id": 7, "name": "Bank IPs", "type": "DSTN_IP", "addresses": ["203.0.113.0/24"]}],
}


def _files(artifact):
    name, media, data = artifact
    if media == pe.ZIP:
        z = zipfile.ZipFile(io.BytesIO(data))
        return {n: z.read(n) for n in z.namelist()}
    return {name: data}


def _book(files, prefix):
    name = next(n for n in files if n.startswith(prefix))
    return read_workbook(files[name])


def _table(sheet):
    head = sheet[0]
    return [dict(zip(head, row + [None] * (len(head) - len(row)))) for row in sheet[1:]]


def _run(policies=None, fmt="xlsx", scope=ALL, routes=ROUTES, **kw):
    c = ReadOnlyClient(routes)
    sc = pe.scope_for(**scope)
    picked, _ = pe.pick(sc, policies)
    out = pe.run(c, sc, picked, fmt, tenant_label="acme (production)", **kw)
    return c, out


# ── Workbooks ──────────────────────────────────────────────────────────
def test_every_policy_gets_its_own_workbook_with_every_rule_in_order_and_names_not_ids():
    c, out = _run()
    assert out["status"] == "ready" and out["artifact"][1] == pe.ZIP
    files = _files(out["artifact"])
    assert sorted(n.split("_policy_")[0] for n in files) == ["cloud_app_control", "cloud_firewall", "file_type_control",
                                                               "ssl_inspection", "url_filtering"]
    url = _book(files, "url_filtering")
    assert list(url) == ["Summary", "Rules"]
    head = url["Rules"][0]
    for col in ("Order", "Rule", "State", "Action", "Users", "Groups", "Locations", "URL categories", "Protocols", "Description",
                "Last modified", "Usage and notes", "Other settings"):
        assert col in head, col
    assert "Hits" not in head
    rules = _table(url["Rules"])
    # Evaluation order, the Default rule last whatever its order says.
    assert [r["Rule"] for r in rules] == ["Allow all", "Block gambling", "Old rule", "Default URL Filter Rule"]
    block = rules[1]
    assert block["Action"] == "Block" and block["State"] == "Enabled"
    assert block["Groups"] == "Finance" and block["URL categories"] == "Gambling\nFinance apps"   # the custom category by its name
    assert block["Users"] == "1 person" and block["Protocols"] == "Https rule"
    assert block["Last modified"] == "2023-11-14 22:13 UTC"
    # Shadowed-rule findings land on the rule they are about.
    assert block["Usage and notes"].startswith("Below a catch-all (") and "'Allow all'" in block["Usage and notes"]
    assert rules[2]["Usage and notes"].startswith("Disabled (info)") and rules[2]["Locations"] == "HQ"
    assert rules[2]["Other settings"] == "Some new field: kept"
    assert rules[3]["Usage and notes"].startswith("Default rule: always evaluated last.")
    summary = dict((r[0], r[1]) for r in url["Summary"][1:])
    assert summary["Rules"] == "4" and summary["Enabled"] == "3" and summary["Hit counts"] == pe.HITS_MISSING
    assert "Below a catch-all: 1" in summary["Shadowed-rule findings"] and "Disabled: 1" in summary["Shadowed-rule findings"]
    # People are counted, not named; the admin who changed a rule is not exported.
    allxml = b"".join(files.values())
    assert b"jane.doe@acme.com" not in allxml and b"admin.person" not in allxml and SECRET.encode() not in allxml
    # Read-only, and only these endpoints.
    assert all(m == "GET" for m, _ in c.calls)


def test_each_policy_has_the_columns_an_admin_needs():
    _, out = _run()
    files = _files(out["artifact"])
    ssl = _table(_book(files, "ssl_inspection")["Rules"])[0]
    assert ssl["Action"] == "Do not decrypt" and ssl["Action details"] == "Do not decrypt sub actions: Bypass other policies: Yes"
    assert ssl["Destination IP groups"] == "Bank IPs" and ssl["URL categories"] == "Finance apps"
    cac = _table(_book(files, "cloud_app_control")["Rules"])[0]
    assert cac["Application type"] == "Streaming media" and cac["Applications"] == "Youtube"
    assert cac["Action"] == "Allow streaming view listen"
    ftc = _table(_book(files, "file_type_control")["Rules"])[0]
    assert ftc["Action"] == "Block" and ftc["Operation"] == "Download" and ftc["State"] == "Disabled"
    assert ftc["Usage and notes"] == "Disabled: it never matches."
    fw = _book(files, "cloud_firewall")
    assert list(fw) == ["Summary", "Rules", "Network service groups", "Network services", "IP destination groups"]
    rules = _table(fw["Rules"])
    assert rules[1]["Network services"] == "DNS" and rules[1]["Destination addresses"] == "evil.example.com"
    assert rules[1]["Action"] == "Block drop" and rules[1]["Usage and notes"].startswith("Shadowed (")
    assert _table(fw["Network services"])[0]["Ports"] == "UDP 53"
    assert _table(fw["Network service groups"])[0]["Services"] == "DNS"
    assert _table(fw["IP destination groups"])[0]["Addresses"] == "203.0.113.0/24"
    summary = dict((r[0], r[1]) for r in fw["Summary"][1:])
    assert summary["Could not be read: Network application groups"] == "Permission denied"


def test_tenant_text_is_never_a_formula():
    _, out = _run(["url_filtering"])
    assert out["artifact"][1] == pe.XLSX     # one policy: the workbook itself
    rules = _table(read_workbook(out["artifact"][2])["Rules"])   # read_workbook also fails on any formula cell
    assert rules[1]["Description"] == "'" + INJECTION


def test_the_hits_hook_adds_a_hits_column():
    c = ReadOnlyClient(ROUTES)
    sc = pe.scope_for(**ALL)
    out = pe.run(c, sc, ["url_filtering"], "xlsx", hits={"url_filtering": {"2": 42, "Allow all": 7}})
    book = read_workbook(out["artifact"][2])
    rules = _table(book["Rules"])
    assert [r["Hits"] for r in rules] == ["7", "42", None, None]
    assert dict((r[0], r[1]) for r in book["Summary"][1:])["Hit counts"] == "Included (Hits column)."


def test_the_pdf_review_copy_lists_every_rule_with_its_notes():
    _, out = _run(["url_filtering"], fmt="pdf")
    name, media, data = out["artifact"]
    assert media == pe.PDF and name.endswith(".pdf")
    pdf = parse_pdf(data)
    text = " ".join(s for p in pdf["pages"] for s in strings(p["stream"]))
    for needle in ("URL filtering policy", "Allow all", "Block gambling", "Default URL Filter Rule", "Below a catch-all", "Finance apps"):
        assert needle in text, needle
    assert "jane.doe" not in text


# ── Scope, Stop and failures ───────────────────────────────────────────
def test_scope_decides_which_policies_are_read():
    nothing = pe.scope_for(**NONE)
    assert nothing["read"] == [] and nothing["summary"] == pe.NOTHING_IN_SCOPE
    dlp = pe.scope_for(**DLP_ONLY)
    assert dlp["read"] == ["url_filtering", "file_type_control"]
    assert "ZIA platform" in dlp["not_in_scope"]["firewall"]
    # Declared on another vendor: a required DLP control that is not read (and says why).
    assert "declared Alternative" in dlp["read_blocked"]["ssl_inspection"] and "cloud_app_control" in dlp["read_blocked"]
    picked, why = pe.pick(dlp, ["url_filtering", "firewall", "ssl_inspection"])
    assert picked == ["url_filtering"] and set(why) == {"firewall", "ssl_inspection"}
    zia = pe.scope_for(**ZIA_ONLY)
    assert zia["read"] == ["url_filtering", "firewall", "file_type_control"]
    assert "not marked Zscaler" in zia["not_in_scope"]["ssl_inspection"]
    with pytest.raises(ValueError, match="Unknown policy"):
        pe.pick(dlp, ["zpa_access"])
    c, out = _run(["url_filtering"], scope=DLP_ONLY)
    assert [e for _, e in c.calls] == ["/zia/urlFilteringRules", "/zia/urlCategories/lite"]


def test_stop_ends_the_read_before_the_next_request():
    stop = threading.Event()

    def log(line):
        if line.startswith("Reading the SSL inspection rules"):
            stop.set()
    c = ReadOnlyClient(ROUTES)
    with pytest.raises(pe.Stopped, match="You clicked Stop"):
        pe.run(c, pe.scope_for(**ALL), list(pe.POLICIES), "xlsx", log=log, cancel=stop)
    assert [e for _, e in c.calls] == ["/zia/urlFilteringRules", "/zia/cloudApplicationRules"]


def test_a_failed_read_is_named_not_an_empty_policy():
    routes = dict(ROUTES, **{"/zia/sslInspectionRules": ({"error": "forbidden"}, 403)})
    _, out = _run(["url_filtering", "ssl_inspection"], routes=routes)
    assert "HTTP 403" in out["read_errors"]["ssl_inspection"] and list(_files(out["artifact"])) == [out["artifact"][0]]
    _, none = _run(["ssl_inspection"], routes=routes)
    assert none["status"] == "error" and "SSL inspection" in none["error"] and "artifact" not in none


# ── API ────────────────────────────────────────────────────────────────
def _wait(t, job):
    deadline = time.time() + 20
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("the job never ended")


def _api(monkeypatch, client):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    signed = []

    def sign_in(req):
        signed.append(1)
        return client
    monkeypatch.setattr(srv, "_build_client", sign_in)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda *a, **k: (_ for _ in ()).throw(AssertionError("no SDK client")))
    return TestClient(srv.app), signed


def test_the_api_runs_one_read_only_job_and_serves_the_file(monkeypatch):
    c = ReadOnlyClient(ROUTES)
    t, signed = _api(monkeypatch, c)
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True, policies=["url_filtering", "firewall"], format="xlsx"))
    assert r.status_code == 200 and r.json()["kind"] == "policy_export", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    assert snap["result"]["counts"]["firewall"]["findings"] == 1 and snap["result"]["tenant_label"] == "acme (production)"
    d = t.get(snap["download"])
    assert d.status_code == 200 and d.headers["content-type"] == pe.ZIP
    names = zipfile.ZipFile(io.BytesIO(d.content)).namelist()
    assert len(names) == 2 and all(n.endswith(".xlsx") for n in names)
    assert SECRET not in str(snap) and all(m == "GET" for m, _ in c.calls)
    # PDF, one policy: the PDF itself.
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True, policies=["ssl_inspection"], format="pdf", page="letter"))
    snap = _wait(t, r.json()["job_id"])
    d = t.get(snap["download"])
    assert d.headers["content-type"] == pe.PDF and d.content.startswith(b"%PDF")


def test_the_api_refuses_before_signing_in(monkeypatch):
    t, signed = _api(monkeypatch, ReadOnlyClient(ROUTES))
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **NONE, from_page=True))
    assert r.status_code == 400 and r.json()["detail"] == pe.NOTHING_IN_SCOPE
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **DLP_ONLY, from_page=True, policies=["firewall"]))
    assert r.status_code == 400 and "None of the policies picked is in scope" in r.json()["detail"]
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True, format="docx"))
    assert r.status_code == 400 and "xlsx or pdf" in r.json()["detail"]
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True, policies=["zpa"]))
    assert r.status_code == 400 and "Unknown policy" in r.json()["detail"]
    assert signed == []


def test_stop_ends_the_job_with_no_file(monkeypatch):
    import pack_jobs
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    c = ReadOnlyClient(ROUTES)
    token = "tokpolicyexport0123456"

    def sign_in(req):
        pack_jobs.stop_before_start(token)
        return c
    monkeypatch.setattr(srv, "_build_client", sign_in)
    t = TestClient(srv.app)
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True), headers={"X-Start-Token": token})
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "cancelled" and snap["result"]["status"] == "stopped" and "download" not in snap, snap
    assert c.calls == []


def test_a_stop_pressed_while_reading_says_so_in_the_log():
    import pack_jobs
    c = ReadOnlyClient(ROUTES)
    gate = threading.Event()

    def slow_get(endpoint, params=None):
        gate.wait(5)
        return ReadOnlyClient.get(c, endpoint, params)
    c.get = slow_get
    import dlp_api_server as srv
    sc = pe.scope_for(**ALL)
    job = pack_jobs.start("policy_export", lambda log, cancel: srv._run_policy_exports(c, sc, list(pe.POLICIES), "xlsx", "A4", "acme", log, cancel))
    time.sleep(0.1)
    assert pack_jobs.cancel(job.id)
    gate.set()
    deadline = time.time() + 10
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.05)
    assert job.status == pack_jobs.CANCELLED and job.artifact is None
    assert any("Stop requested" in line for line in job.logs) and len(c.calls) == 1


# ── The page ───────────────────────────────────────────────────────────
def test_the_exports_page_is_served_wired_and_explained():
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    r = TestClient(srv.app).get("/report/exports")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">',
                   '<a class="rp-btn" href="/">← Back to the assessment</a>', '<main class="rp-card">',
                   "/api/exports/policies/start", "/api/exports/urls/start", "/api/exports/url-categories/analyze/start",
                   "/api/dlp-packs/inventory/start", "/api/dlp-packs/export/start", "`/api/report/${fmt}`", "assessment('xlsx')", "assessment('docx')",
                   "/api/exports/plans", 'role="log"', "Stop", "/api/exports/locations/start", "/api/exports/client-connector/start",
                   "/api/exports/columns", 'name="exLayout"', 'id="exSep"', 'id="exColsList"', "exportOptions()"):
        assert needle in html, needle
    order = [html.index(f'src="/static/{s}"') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    index = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    assert index.index('onclick="openExportsTab()"') < index.index('onclick="openAdvancedTab()"')
    explain = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    assert "X.exports = {" in explain and "'/report/exports': 'exports'" in explain


# ── Export options ─────────────────────────────────────────────────────
def _sheets(out, prefix):
    return _book(_files(out["artifact"]), prefix)


def test_default_options_give_exactly_the_workbook_of_before():
    _, plain = _run(["url_filtering", "firewall", "file_type_control"])
    _, dflt = _run(["url_filtering", "firewall", "file_type_control"], opts=pe.options())
    for prefix in ("url_filtering", "cloud_firewall", "file_type_control"):
        a, b = _sheets(plain, prefix), _sheets(dflt, prefix)
        assert list(a) == list(b) and all(a[k] == b[k] for k in a if k != "Summary"), prefix
        assert "Export options" not in dict((r[0], r[1]) for r in b["Summary"][1:])
    assert pe.options() == pe.DEFAULT_OPTIONS and pe.is_default(pe.options())


def test_columns_one_row_per_value_and_the_separator_shape_the_rules_sheet():
    opts = pe.options({"url_filtering": ["Action", "URL categories", "Usage and notes"]}, "rows", "semicolon")
    _, out = _run(["url_filtering"], opts=opts)
    book = read_workbook(out["artifact"][2])
    assert book["Rules"][0] == ["Order", "Rule", "Action", "URL categories", "Usage and notes"]   # identity columns always stay
    rules = _table(book["Rules"])
    gamb = [r for r in rules if r["Rule"] == "Block gambling"]
    assert [r["URL categories"] for r in gamb] == ["Gambling", "Finance apps"], "one row per value, the rest repeated"
    assert all(r["Action"] == "Block" and r["Usage and notes"] == gamb[0]["Usage and notes"] for r in gamb)
    assert "Layout: one row per value" in dict((r[0], r[1]) for r in book["Summary"][1:])["Export options"]
    _, flat = _run(["url_filtering"], opts=pe.options({}, "flat", "comma"))
    rules = _table(read_workbook(flat["artifact"][2])["Rules"])
    assert rules[1]["URL categories"] == "Gambling, Finance apps" and "Users" in rules[1]
    # Notes are lines, never split into rows, joined with the separator.
    cols, rows = pe.shape(["Order", "Rule", "A", "Usage and notes"], [[1, "R", ["x", "y"], ["n1", "n2"]]], pe.options({}, "rows", "comma"))
    assert rows == [[1, "R", "x", "n1, n2"], [1, "R", "y", "n1, n2"]]


def test_one_row_per_value_is_capped_per_record():
    many = [[1, "R", [f"a{i}" for i in range(40)], [f"b{i}" for i in range(40)]]]
    cols, rows = pe.shape(["Order", "Rule", "A", "B"], many, pe.options({}, "rows", "newline"))
    assert len(rows) == 40 and rows[0][3] == [f"b{i}" for i in range(40)], "the second column stays joined past the cap"


def test_bad_options_are_named():
    with pytest.raises(ValueError, match="layout"):
        pe.options(layout="pivot")
    with pytest.raises(ValueError, match="separator"):
        pe.options(separator="tab")
    with pytest.raises(ValueError, match="Unknown column for url_filtering"):
        pe.options({"url_filtering": ["Nope"]})
    with pytest.raises(ValueError, match="Unknown sheet"):
        pe.options({"zpa": ["Name"]})
    cat = pe.column_catalogue()
    assert set(cat) >= set(pe.POLICIES) | {"locations", "location_groups", "app_profiles", "forwarding_profiles", "pac_files"}


def test_file_type_control_lists_its_file_types_and_the_rules_that_use_them():
    _, out = _run(["file_type_control"])
    ft = _table(read_workbook(out["artifact"][2])["File types"])
    assert ft == [{"Name": "Windows executables", "Kind": "File type category", "API name": "FTCATEGORY_WINDOWS_EXECUTABLES",
                   "File Type Control rules": "Block executables", "Rules": "1"}]


# ── Locations ──────────────────────────────────────────────────────────
import config_exports as ce  # noqa: E402

PSK = "psk-never-exported-42"
LOC_ROUTES = dict(ROUTES, **{
    "/zia/locations": [
        {"id": 77, "name": "HQ", "country": "UNITED_STATES", "tz": "UNITED_STATES_AMERICA_LOS_ANGELES", "authRequired": True,
         "sslScanEnabled": True, "ofwEnabled": True, "xffForwardEnabled": False, "upBandwidth": 10000, "dnBandwidth": 50000,
         "surrogateIP": True, "idleTimeInMinutes": 480, "ipAddresses": ["198.51.100.7", "198.51.100.8"], "childCount": 1,
         "vpnCredentials": [{"id": 3, "type": "UFQDN", "fqdn": "hq@acme.example", "preSharedKey": PSK}],
         "staticLocationGroups": [{"id": 5, "name": "Branches"}], "profile": "CORPORATE"},
        {"id": 78, "name": "Lab", "childCount": 0, "ofwEnabled": False},
    ],
    "/zia/locations/77/sublocations": [{"id": 771, "name": "HQ guest wifi", "parentId": 77, "authRequired": False,
                                        "ipAddresses": ["10.1.0.0/16"], "profile": "GUESTWIFI"}],
    "/zia/locations/groups": [{"id": 5, "name": "Branches", "groupType": "STATIC_GROUP", "locations": [{"id": 77, "name": "HQ"}]},
                              {"id": 6, "name": "Corporate", "groupType": "DYNAMIC_GROUP",
                               "dynamicLocationGroupCriteria": {"profiles": ["CORPORATE"]}}],
    "/zia/firewallFilteringRules": [_r(20, "Allow DNS", 1, "ALLOW", locationGroups=[{"id": 5, "name": "Branches"}])],
    "/zia/sslInspectionRules": [_r(40, "Inspect HQ", 1, {"type": "DECRYPT"}, locations=[{"id": 77, "name": "HQ"}])],
    "/zia/webDlpRules": [_r(60, "Web PCI", 1, "BLOCK", locations=[{"id": 771, "name": "HQ guest wifi"}])],
})


def _loc_run(scope=ALL, routes=LOC_ROUTES, **kw):
    c = ReadOnlyClient(routes)
    sc = ce.locations_scope(**scope)
    return c, sc, ce.locations_export(c, sc, tenant_label="acme (production)", **kw)


def test_the_locations_export_has_settings_sub_locations_groups_and_policy_usage():
    c, sc, out = _loc_run()
    assert out["status"] == "ready" and out["counts"] == {"locations": 2, "sublocations": 1, "groups": 2,
                                                          "usage": ["URL filtering", "Cloud Firewall", "SSL inspection", "File Type Control", "Web DLP"]}
    book = read_workbook(out["artifact"][2])
    assert list(book) == ["Summary", "Locations", "Location groups", "Policy usage"]
    locs = {r["Name"]: r for r in _table(book["Locations"])}
    hq = locs["HQ"]
    assert hq["Type"] == "Location" and hq["Authentication required"] == "Yes" and hq["Firewall enabled"] == "Yes"
    assert hq["XFF forwarding"] == "No" and hq["Surrogate IP"] == "Yes" and hq["Upload bandwidth"] == "10000"
    assert hq["IP addresses"] == "2" and hq["VPN credentials"] == "1" and hq["Profile"] == "Corporate"
    assert hq["URL filtering rules"] == "Old rule" and hq["SSL inspection rules"] == "Inspect HQ"
    assert hq["Through location groups"] == "Cloud Firewall: Allow DNS (via Branches)" and hq["Rules using it"] == "3"
    sub = locs["HQ guest wifi"]
    assert sub["Type"] == "Sub-location" and sub["Parent location"] == "HQ" and sub["Web DLP rules"] == "Web PCI"
    assert locs["Lab"]["Rules using it"] == "0"
    groups = {r["Name"]: r for r in _table(book["Location groups"])}
    assert groups["Branches"]["Locations"] == "HQ" and groups["Branches"]["Cloud Firewall rules"] == "Allow DNS"
    assert groups["Corporate"]["Dynamic criteria"] == "Profiles: CORPORATE"
    usage = _table(book["Policy usage"])
    assert {"Object": "HQ", "Object type": "Location", "Policy": "Cloud Firewall", "Rule": "Allow DNS",
            "How": "Through location group Branches"} in usage
    blob = out["artifact"][2]
    assert PSK.encode() not in blob and b"198.51.100.7" not in blob and b"hq@acme.example" not in blob
    assert all(m == "GET" for m, _ in c.calls)
    assert "/zia/locations/78/sublocations" not in [e for _, e in c.calls], "only locations that have sub-locations are asked"


def test_the_locations_export_reads_only_what_is_in_scope_and_honours_options():
    assert ce.locations_scope(**DLP_ONLY)["in_scope"] is False
    c, sc, out = _loc_run(scope=ZIA_ONLY, opts=pe.options({"locations": ["Firewall enabled"]}, "flat", "comma"))
    assert sc["usage"] == ["url_filtering", "firewall", "file_type_control"] and "web_dlp" in sc["not_in_scope"]
    assert not any(e in ("/zia/webDlpRules", "/zia/sslInspectionRules") for _, e in c.calls)
    book = read_workbook(out["artifact"][2])
    assert book["Locations"][0] == ["Name", "Firewall enabled"]
    assert any(r[0] == "Not in scope: Web DLP" for r in book["Summary"])


def test_the_locations_export_stops_and_names_a_failed_read():
    stop = threading.Event()

    def log(line):
        if line.startswith("Reading the location groups"):
            stop.set()
    c = ReadOnlyClient(LOC_ROUTES)
    with pytest.raises(pe.Stopped):
        ce.locations_export(c, ce.locations_scope(**ALL), log=log, cancel=stop)
    assert [e for _, e in c.calls] == ["/zia/locations", "/zia/locations/77/sublocations"]
    _, _, out = _loc_run(routes=dict(LOC_ROUTES, **{"/zia/locations": ({"error": "forbidden"}, 403)}))
    assert out["status"] == "error" and "permission denied" in out["error"] and "artifact" not in out


# ── Client Connector ───────────────────────────────────────────────────
ZCC_PASSWORD = "Uninstall-Pa55-never"
ZCC_ROUTES = {
    "/zcc/webPolicies": [{"id": 11, "name": "Windows default", "deviceType": 3, "active": "1", "ruleOrder": 1, "forwardingProfileId": 7,
                          "pacUrl": "https://pac.example/app.pac", "uninstallPassword": ZCC_PASSWORD, "logLevel": "INFO",
                          "groups": [{"id": 1, "name": "Sales"}], "users": [{"id": 2, "name": "jane.doe@acme.com"}]},
                         {"id": 12, "name": "Mac default", "deviceType": 4, "active": "1", "ruleOrder": 1, "forwardingProfileId": 8}],
    "/zcc/forwardingProfiles": [{"id": 7, "name": "Remote", "forwardingProfileActions": [
                                    {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "1", "enablePacketTunnel": True},
                                    {"networkType": "TRUSTED_NETWORK", "actionType": "0"}],
                                 "trustedNetworks": [{"id": 1, "name": "Office"}]},
                                {"id": 8, "name": "PAC only", "forwardingProfileActions": [
                                    {"networkType": "OFF_TRUSTED_NETWORK", "actionType": "2", "systemProxyData": {"pacURL": "https://pac.example/fwd.pac"}}]}],
    "/zcc/trustedNetworks": [{"id": 1, "networkName": "Office", "dnsServers": "10.0.0.1"}],
    "/zia/pacFiles": [{"id": 1, "name": "Apps", "pacUrl": "https://pac.example/app.pac",
                       "pacContent": 'function FindProxyForURL(url, host) { if (dnsDomainIs(host, ".bank.example")) { return "DIRECT"; } return "PROXY ${GATEWAY}:80"; }'},
                      {"id": 2, "name": "Forwarding", "pacUrl": "https://pac.example/fwd.pac/"}],
}


def test_the_client_connector_export_links_profiles_forwarding_and_pac_files():
    c = ReadOnlyClient(ZCC_ROUTES)
    sc = ce.zcc_scope(**ALL)
    out = ce.client_connector_export(c, sc, tenant_label="acme")
    assert out["status"] == "ready" and out["counts"] == {"app_profiles": 2, "forwarding_profiles": 2, "pac_files": 2}, out
    book = read_workbook(out["artifact"][2])
    assert list(book) == ["Summary", "App profiles", "Forwarding profiles", "PAC files", "Profile usage"]
    apps = {r["Name"]: r for r in _table(book["App profiles"])}
    win = apps["Windows default"]
    assert win["Platform"] == "Windows" and win["Forwarding profile"] == "Remote" and win["PAC URL"] == "https://pac.example/app.pac"
    assert "Log level: INFO" in win["Settings"] and "Users: 1 person" in win["Settings"] and win["Groups"] == "Sales"
    fwd = {r["Name"]: r for r in _table(book["Forwarding profiles"])}
    assert fwd["Remote"]["Used by app profiles"] == "Windows default (Windows)" and fwd["Remote"]["Off trusted network"] == "Z-Tunnel 2.0"
    assert fwd["Remote"]["Trusted networks"] == "Office" and fwd["PAC only"]["PAC URLs"] == "https://pac.example/fwd.pac"
    pacs = {r["Name"]: r for r in _table(book["PAC files"])}
    assert pacs["Apps"]["Used by app profiles"] == "Windows default (Windows)" and pacs["Apps"]["Hosts sent DIRECT"] == ".bank.example"
    assert pacs["Forwarding"]["Used by forwarding profiles"] == "PAC only", "a trailing slash does not hide the match"
    blob = out["artifact"][2]
    assert ZCC_PASSWORD.encode() not in blob and b"jane.doe" not in blob
    assert all(m == "GET" for m, _ in c.calls)
    assert ce.zcc_scope(**DLP_ONLY)["in_scope"] is False


# ── The configuration exports' API ─────────────────────────────────────
def test_the_config_export_api_runs_read_only_jobs_and_refuses_before_signing_in(monkeypatch):
    c = ReadOnlyClient(dict(LOC_ROUTES, **ZCC_ROUTES))
    t, signed = _api(monkeypatch, c)
    cols = t.get("/api/exports/columns").json()
    assert "Firewall enabled" in cols["columns"]["locations"] and cols["defaults"] == pe.DEFAULT_OPTIONS
    r = t.post("/api/exports/locations/start", json=dict(CREDS, **ALL, from_page=True, layout="rows", separator="comma"))
    assert r.status_code == 200 and r.json()["kind"] == "locations_export", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["result"]["status"] == "ready", snap
    d = t.get(snap["download"])
    assert d.status_code == 200 and d.headers["content-type"] == pe.XLSX and SECRET not in str(snap)
    r = t.post("/api/exports/client-connector/start", json=dict(CREDS, **ALL, from_page=True))
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done" and snap["filename"].startswith("client_connector_profiles_"), snap
    assert all(m == "GET" for m, _ in c.calls)
    n = len(signed)
    for url, body, needle in (("/api/exports/locations/start", dict(CREDS, **DLP_ONLY, from_page=True), "ZIA platform"),
                              ("/api/exports/client-connector/start", dict(CREDS, **DLP_ONLY, from_page=True), "ZCC"),
                              ("/api/exports/locations/start", dict(CREDS, **ALL, from_page=True, layout="pivot"), "layout"),
                              ("/api/exports/policies/start", dict(CREDS, **ALL, from_page=True, columns={"url_filtering": ["Nope"]}), "Unknown column"),
                              ("/api/exports/policies/start", dict(CREDS, **ALL, from_page=True, separator="tab"), "separator")):
        r = t.post(url, json=body)
        assert r.status_code == 400 and needle in r.json()["detail"], (url, r.text)
    assert len(signed) == n, "refused before signing in"


def test_the_policy_export_api_passes_the_options(monkeypatch):
    t, _ = _api(monkeypatch, ReadOnlyClient(ROUTES))
    r = t.post("/api/exports/policies/start", json=dict(CREDS, **ALL, from_page=True, policies=["url_filtering"],
                                                         columns={"url_filtering": ["Action"]}, layout="flat", separator="semicolon"))
    snap = _wait(t, r.json()["job_id"])
    assert read_workbook(t.get(snap["download"]).content)["Rules"][0] == ["Order", "Rule", "Action"]
