"""Category lookup (category_lookup.py, the Path analyzer's third tab): a
URL, host, IP address or category in; its ZIA categories (ZIA's URL lookup
and the tenant's own lists) and every rule that names each category across
URL filtering, Cloud App Control, SSL inspection, Cloud Firewall, DNS
Control, File Type Control, Web DLP and Sandbox out, in evaluation order.
Fakes only: no tenant, no network, no clock."""
from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import threading

import pytest
from fastapi.testclient import TestClient

import category_lookup as cl
import data_flow as df
import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = df.full_path_scope()
WEB = df.path_scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "alternative", "cloud_app_control": "alternative"})   # URL, FTC, Web DLP
PLATFORM = df.path_scope(["zia_extras"], {})                    # ZIA platform: no Web DLP, no SSL or CAC (not marked Zscaler)

URL = [
    {"id": 1, "name": "Block gambling", "order": 2, "rank": 7, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["GAMBLING", "CUSTOM_01"]},
    {"id": 2, "name": "Admin caution gambling", "order": 5, "rank": 0, "state": "ENABLED", "action": "CAUTION", "urlCategories": ["GAMBLING"]},
    {"id": 3, "name": "Old gambling rule", "order": 1, "state": "DISABLED", "action": "ALLOW", "urlCategories": ["GAMBLING"]},
    {"id": 4, "name": "Default URL Filtering Rule", "order": -1, "defaultRule": True, "action": "ALLOW", "urlCategories": ["GAMBLING"]},
    {"id": 5, "name": "Allow all", "order": 9, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["ANY"]},
    {"id": 6, "name": "Both sets", "order": 10, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["FILE_HOST"], "urlCategories2": ["GAMBLING"]},
]
SSL = [{"id": 10, "name": "No decrypt partners", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["CUSTOM_01"]}]
CAC = [{"id": 20, "name": "Box uploads", "order": 1, "state": "ENABLED", "type": "FILE_SHARE", "actions": ["BLOCK_FILE_SHARE_UPLOAD"], "applications": ["BOX"]}]
FW = [{"id": 30, "name": "Block gambling IPs", "order": 1, "state": "ENABLED", "action": "BLOCK_DROP", "destIpCategories": ["GAMBLING"]},
      {"id": 31, "name": "Partner nets", "order": 2, "state": "ENABLED", "action": "ALLOW", "destIpGroups": [{"id": 70, "name": "Partner group"}]}]
DNS = [{"id": 40, "name": "Gambling answers", "order": 1, "state": "ENABLED", "action": "BLOCK", "resCategories": ["GAMBLING"]}]
FTC = [{"id": 50, "name": "No exe from gambling", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK", "urlCategories": ["GAMBLING"],
        "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"]}]
DLP = [{"id": 60, "name": "PCI to partners", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["CUSTOM_01"]}]
SANDBOX = [{"id": 80, "name": "Hold gambling files", "order": 1, "state": "ENABLED", "baRuleAction": "BLOCK", "urlCategories": ["GAMBLING"]}]
GROUPS = [{"id": 70, "name": "Partner group", "ipCategories": ["CUSTOM_01"]}]
CATEGORIES = [{"id": "GAMBLING", "configuredName": "Gambling"},
              {"id": "FILE_HOST", "configuredName": "File Host"},
              {"id": "CUSTOM_01", "configuredName": "Partner portals", "customCategory": True, "urls": [".partner.example", "203.0.113.9"]},
              {"id": "PROFESSIONAL_SERVICES", "configuredName": "Professional Services", "urls": ["consult.example"]}]
ROUTES = {"/zia/urlFilteringRules": URL, "/zia/sslInspectionRules": SSL, "/zia/cloudApplicationRules": CAC, "/zia/firewallFilteringRules": FW,
          "/zia/firewallDnsRules": DNS, "/zia/fileTypeRules": FTC, "/zia/webDlpRules": DLP, "/zia/sandboxRules": SANDBOX,
          "/zia/ipDestinationGroups": GROUPS, "/zia/urlCategories": CATEGORIES, "/zia/advancedSettings": {"enableAdminRankAccess": True}}
LOOKUP = {"casino.example": {"urlClassifications": ["GAMBLING"], "urlClassificationsWithSecurityAlert": []},
          "box.com": {"urlClassifications": ["FILE_HOST"], "application": "BOX"},
          "portal.partner.example": {"urlClassifications": ["PROFESSIONAL_SERVICES"]},
          "bad.example": {"urlClassifications": ["MALWARE_SITE"], "urlClassificationsWithSecurityAlert": ["MALWARE_SITE"]}}


class Client:
    """A fake assessment client: GET answers from ROUTES (a status per path
    in `fail`), POST /zia/urlLookup answers every URL; it records every call."""

    def __init__(self, routes=None, fail=None, lookup_status=200):
        self.routes = copy.deepcopy(ROUTES if routes is None else routes)
        self.fail = dict(fail or {})
        self.lookup_status = lookup_status
        self.gets, self.posts = [], []

    def get(self, ep, params=None):
        self.gets.append(ep)
        if ep in self.fail:
            return {"error": "denied"}, self.fail[ep]
        return copy.deepcopy(self.routes.get(ep, [])), 200

    def post(self, ep, body=None):
        self.posts.append((ep, list(body or [])))
        assert ep == "/zia/urlLookup"
        if self.lookup_status != 200:
            return {"error": "forbidden"}, self.lookup_status
        return [dict(LOOKUP.get(u, {"urlClassifications": []}), url=u) for u in body], 200


def run(text, scope=FULL, client=None, **kw):
    c = client or Client()
    return cl.run(c, cl.parse(text), scope, **kw), c


def entry(res, i=0):
    return res["entries"][i]


def cat(e, cid):
    return next(c for c in e["categories"] if c["id"] == cid)


# ── The entries ──────────────────────────────────────────────────────
def test_entries_are_destinations_or_categories_one_per_line():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a URL, a host, an IP address and a category are told apart; duplicates are looked up once."""
    p = cl.parse("https://Casino.example/play?x=1\nbox.com, box.com\n203.0.113.9\nGAMBLING\ncategory:Partner portals\n\n")
    kinds = [(e["kind"], e["host"] or e["query"]) for e in p["entries"]]
    assert kinds == [("host", "casino.example"), ("host", "box.com"), ("host", "203.0.113.9"), ("category", "GAMBLING"),
                     ("category", "Partner portals")]
    assert p["entries"][0]["path"] == "/play" and p["skipped"] == []


@pytest.mark.parametrize("text,why", [
    ("", "Nothing to look up"),
    ("   \n  ", "Nothing to look up"),
    (123, "Type a URL"),
    ("x" * (cl.MAX_TEXT + 1), "longer than"),
    ("<script>", "Nothing to look up"),
])
def test_nothing_to_look_up_or_too_much_is_refused_in_words(text, why):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · CWE-400 · WSTG-INPV-01: empty, wrong-type, oversized or malformed input is refused with a plain sentence."""
    with pytest.raises(cl.EntryError) as e:
        cl.parse(text)
    assert why in str(e.value)


def test_entries_beyond_the_cap_and_bad_lines_are_skipped_with_the_reason():
    """ASVS V5.1.4 · CWE-770 · CWE-20: at most MAX_ENTRIES entries per run; a line with control characters or an over-long one is skipped and said."""
    lines = [f"h{i}.example" for i in range(cl.MAX_ENTRIES + 3)] + ["a\x07b.example", "y" * (cl.MAX_ENTRY + 1) + ".example"]
    p = cl.parse("\n".join(lines))
    assert len(p["entries"]) == cl.MAX_ENTRIES
    assert sum(f"first {cl.MAX_ENTRIES} entries" in s["why"] for s in p["skipped"]) == 5   # 3 hosts and the two bad lines after the cap
    p = cl.parse("ok.example\na\x07b.example\n" + "y" * (cl.MAX_ENTRY + 1))
    assert [s["why"] for s in p["skipped"]] == ["It holds control characters.", f"Longer than {cl.MAX_ENTRY} characters."]


def test_the_cap_is_one_hundred_entries_looked_up_in_one_paced_request():
    """ASVS V5.1.4 · V11.1.4 · CWE-770 · WSTG-BUSL-05: 100 entries are looked up in one run (one POST /urlLookup of 100 hosts); the 101st is skipped and said."""
    assert cl.MAX_ENTRIES == 100
    hosts = [f"host{i:03d}.example" for i in range(100)]
    text = "\n".join("https://" + h + "/" + "p" * 400 for h in hosts)      # 100 long URLs still fit in MAX_TEXT
    assert len(text) <= cl.MAX_TEXT
    p = cl.parse(text)
    assert len(p["entries"]) == 100 and p["skipped"] == []
    res, c = run(text)
    looked = [u for ep, body in c.posts for u in body]
    assert len(c.posts) == 1 and sorted(looked) == sorted(hosts)
    assert len(res["entries"]) == 100
    p = cl.parse("\n".join(hosts + ["host100.example"]))
    assert len(p["entries"]) == 100
    assert [s["text"] for s in p["skipped"]] == ["host100.example"]
    assert "first 100 entries" in p["skipped"][0]["why"]


# ── The answer ───────────────────────────────────────────────────────
def test_a_host_gets_its_categories_and_every_rule_that_names_them_in_evaluation_order():
    """ASVS V1.1.2 · CWE-670 · WSTG-BUSL-01: the rules are listed per policy in ZIA's order: admin rank first when ranking is on, the default rule last, disabled rules unnumbered."""
    res, c = run("casino.example")
    g = cat(entry(res), "GAMBLING")
    assert g["name"] == "Gambling" and not g["custom"] and g["source"] == "from ZIA's URL lookup"
    rows = [(r["section"], r["name"], r["position"], r["rank"], r["action"], r["enabled"], r["default"]) for r in g["rules"]]
    assert rows == [
        ("url", "Admin caution gambling", 1, 0, "CAUTION", True, False),    # rank 0 before rank 7, though its order is later
        ("url", "Old gambling rule", None, None, "ALLOW", False, False),   # disabled: listed, not evaluated
        ("url", "Block gambling", 2, 7, "BLOCK", True, False),
        ("url", "Both sets", 4, None, "BLOCK", True, False),            # after "Allow all" (order 9), which names every category
        ("url", "Default URL Filtering Rule", 5, None, "ALLOW", True, True),
        ("firewall", "Block gambling IPs", 1, None, "BLOCK_DROP", True, False),
        ("dns", "Gambling answers", 1, None, "BLOCK", True, False),
        ("ftc", "No exe from gambling", 1, None, "BLOCK", True, False),
        ("sandbox", "Hold gambling files", 1, None, "BLOCK", True, False),
    ]
    via = {r["name"]: r["via"] for r in g["rules"]}
    assert via["Both sets"].startswith("second URL category set") and via["Gambling answers"] == "resolved IP categories"
    assert res["ranked"] is True and c.posts == [("/zia/urlLookup", ["casino.example"])]


def test_without_admin_ranking_the_rules_are_in_rule_order():
    """ASVS V1.1.2 · CWE-670: admin ranking off: plain rule order, the default rule last."""
    routes = dict(ROUTES, **{"/zia/advancedSettings": {"enableAdminRankAccess": False}})
    res, _ = run("GAMBLING", client=Client(routes))
    names = [r["name"] for r in cat(entry(res), "GAMBLING")["rules"] if r["section"] == "url"]
    assert names == ["Old gambling rule", "Block gambling", "Admin caution gambling", "Both sets", "Default URL Filtering Rule"]
    assert res["ranked"] is False


def test_custom_categories_that_list_a_host_are_found_with_their_rules_through_ip_groups_too():
    """ASVS V1.1.2 · CWE-670: a host a custom category lists (".partner.example" covers subdomains) gets that category, its SSL, DLP and URL rules, and a firewall rule naming it through an IP destination group."""
    res, _ = run("portal.partner.example")
    e = entry(res)
    assert e["custom_containing"] == [{"id": "CUSTOM_01", "name": "Partner portals"}]
    c1 = cat(e, "CUSTOM_01")
    assert c1["custom"] and c1["source"] == "listed in the tenant's category"
    assert {(r["section"], r["name"]) for r in c1["rules"]} == {("url", "Block gambling"), ("ssl", "No decrypt partners"),
                                                               ("firewall", "Partner nets"), ("dlp", "PCI to partners")}
    assert next(r for r in c1["rules"] if r["section"] == "firewall")["via"] == "IP destination group 'Partner group'"
    assert cat(e, "PROFESSIONAL_SERVICES")["source"] == "from ZIA's URL lookup"


def test_a_predefined_category_the_tenant_added_the_host_to_is_found_too():
    """ASVS V1.1.2 · CWE-670: a URL the tenant added to a predefined category places it there as well."""
    e = entry(run("consult.example")[0])
    assert cat(e, "PROFESSIONAL_SERVICES")["source"] == "listed in the tenant's category" and e["custom_containing"] == []


def test_the_cloud_application_gets_the_cloud_app_control_rules_that_name_it():
    """ASVS V1.1.2 · CWE-670: Cloud App Control names applications, not categories: listed for the application the lookup names."""
    e = entry(run("box.com")[0])
    assert e["application"] == "BOX" and [r["name"] for r in e["application_rules"]] == ["Box uploads"]
    assert e["application_rules"][0]["action"] == "BLOCK_FILE_SHARE_UPLOAD"


def test_a_category_by_name_or_id_and_one_not_in_the_tenant():
    """ASVS V5.1.3 · CWE-20: a category by its name (any case) or id; an unknown one is said, never invented."""
    res, _ = run("category:partner PORTALS\nfile_host\nNO_SUCH_THING\ncategory:Nothing here")
    assert [c["id"] for c in entry(res, 0)["categories"]] == ["CUSTOM_01"]
    assert [c["id"] for c in entry(res, 1)["categories"]] == ["FILE_HOST"]
    assert "not in the tenant's category list" in entry(res, 2)["categories"][0]["source"] and entry(res, 2)["categories"][0]["rules"] == []
    assert entry(res, 3)["categories"] == [] and "No category with that id or name" in entry(res, 3)["note"]


def test_rules_for_every_category_are_counted_not_listed():
    """ASVS V1.1.2 · CWE-670: a rule with ANY (or no) category applies to every category: counted per policy."""
    res, _ = run("GAMBLING")
    sec = {s["key"]: s for s in res["sections"]}
    assert sec["url"]["any_count"] == 1 and "Allow all" not in json.dumps(res["entries"])


def test_a_security_alert_and_a_failed_lookup_are_said():
    """ASVS V7.4.1 · CWE-755: ZIA's security alert is shown; a lookup ZIA refused is a reason, never an empty category list."""
    e = entry(run("bad.example")[0])
    assert e["security_alerts"] == ["MALWARE_SITE"]
    e = entry(run("casino.example", client=Client(lookup_status=403))[0])
    assert e["lookup_error"].startswith("not looked up") and e["categories"] == []


# ── Scope: only what is ticked is read ───────────────────────────────
def test_only_the_policies_in_scope_are_read():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: DLP with Inline Web DLP on Zscaler reads URL filtering, File Type Control and Web DLP only; the rest says not in scope."""
    res, c = run("casino.example", scope=WEB)
    assert set(c.gets) == {"/zia/urlFilteringRules", "/zia/fileTypeRules", "/zia/webDlpRules", "/zia/urlCategories"}
    sec = {s["key"]: s for s in res["sections"]}
    assert {k for k, s in sec.items() if s["state"] == "read"} == {"url", "ftc", "dlp"}
    assert sec["firewall"]["state"] == "out_of_scope" and "ZIA platform" in sec["firewall"]["why"]
    assert sec["ssl"]["state"] == "out_of_scope" and "Alternative" in sec["ssl"]["why"]
    assert res["scope_summary"] == ("Reads only what is in scope on the Scope page: the URL filtering, File Type Control and Web DLP rules, "
                                    "the URL categories and ZIA's URL lookup.")


def test_zia_platform_reads_the_firewall_dns_and_sandbox_and_the_ranking_setting():
    """ASVS V4.1.3 · CWE-285: ZIA platform alone reads its policies and IP groups, never Web DLP."""
    _, c = run("casino.example", scope=PLATFORM)
    assert "/zia/webDlpRules" not in c.gets and "/zia/sslInspectionRules" not in c.gets
    assert {"/zia/firewallFilteringRules", "/zia/firewallDnsRules", "/zia/sandboxRules", "/zia/ipDestinationGroups", "/zia/advancedSettings"} <= set(c.gets)


def test_nothing_in_scope_reads_nothing():
    """ASVS V4.1.3 · V1.4.4 · CWE-285: no policy the lookup reads in scope: lookup_scope reads nothing."""
    assert cl.lookup_scope(df.path_scope([], {}))["read"] == []
    assert cl.lookup_scope(df.path_scope(["zcc"], {}))["read"] == []


def test_a_policy_that_could_not_be_read_is_said_not_left_empty():
    """ASVS V7.4.1 · CWE-755 · CWE-252: a 403 on one policy is "could not be read"; the categories list failing is a note."""
    res, _ = run("casino.example", client=Client(fail={"/zia/firewallFilteringRules": 403, "/zia/urlCategories": 500}))
    sec = {s["key"]: s for s in res["sections"]}
    assert sec["firewall"]["state"] == "unread" and "HTTP 403" in sec["firewall"]["why"]
    assert any("URL categories could not be read" in n for n in res["notes"])
    assert cat(entry(res), "GAMBLING")["name"] == "Gambling" and not cat(entry(res), "GAMBLING")["known"]   # from the id


def test_stop_ends_the_read_and_nothing_more_is_sent():
    """ASVS V11.1.2 · CWE-400: Stop before the read: nothing is read or looked up, and no partial answer is given."""
    ev = threading.Event()
    ev.set()
    c = Client()
    with pytest.raises(cl.Stopped):
        cl.run(c, cl.parse("casino.example"), FULL, cancel=ev)
    assert c.gets == [] and c.posts == []


def test_a_kept_read_for_the_same_scope_is_reused_and_one_for_another_scope_is_not():
    """ASVS V4.1.3 · CWE-524: the second lookup reuses the read made for the same scope; a read for another scope reads again."""
    res, c = run("casino.example")
    snap = cl.read(Client(), FULL)
    c2 = Client()
    cl.run(c2, cl.parse("box.com"), FULL, snapshot=snap)
    assert c2.gets == [] and len(c2.posts) == 1
    c3 = Client()
    cl.run(c3, cl.parse("box.com"), WEB, snapshot=snap)
    assert c3.gets


# ── The route ────────────────────────────────────────────────────────
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s3cret-value-xyz", "customer_id": "7210000000000"}
SEL = {"scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"},
       "from_page": True}


class SyncJob:
    def __init__(self, kind, result, error=""):
        self.id, self.kind, self.result, self.error, self.status = "sync", kind, result, error, "done"


@pytest.fixture
def api(monkeypatch):
    built = []

    def factory(req):
        built.append(1)
        return Client()
    monkeypatch.setattr(srv, "_build_client", factory)
    import pack_jobs
    jobs = []

    def start(kind, fn, **kw):
        jobs.append(fn(lambda line: None, threading.Event()))
        return SyncJob(kind, jobs[-1])
    monkeypatch.setattr(pack_jobs, "start", start)
    monkeypatch.setattr(srv, "_REPORTS", {})
    return TestClient(srv.app), built, jobs


@pytest.mark.parametrize("body,why", [
    ({"text": ""}, "Nothing to look up"),
    ({"text": "x" * (cl.MAX_TEXT + 1)}, "longer than"),
])
def test_the_route_refuses_bad_input_before_signing_in(api, body, why):
    """ASVS V5.1.3 · V1.4.4 · CWE-20 · WSTG-INPV-01: bad input is a 400 before any client is built."""
    c, built, _ = api
    r = c.post("/api/category-lookup/start", json=dict(CREDS, **SEL, **body))
    assert r.status_code == 400 and why in r.text and built == []


def test_the_route_refuses_when_nothing_it_reads_is_in_scope(api):
    """ASVS V4.1.3 · V1.4.4 · CWE-285 · WSTG-ATHZ-02: nothing in scope is a 400 before sign-in, with the reason."""
    c, built, _ = api
    r = c.post("/api/category-lookup/start", json=dict(CREDS, text="box.com", scopes=["zcc"], channels={}, from_page=True))
    assert r.status_code == 400 and "Nothing the category lookup reads is in scope" in r.text and built == []


def test_the_route_answers_as_a_job_without_secrets_and_keeps_the_read(api):
    """ASVS V4.1.3 · V7.1.1 · CWE-200 · CWE-532: the job answers with the categories and rules, no secret, and a report id the next lookup reuses."""
    c, built, jobs = api
    r = c.post("/api/category-lookup/start", json=dict(CREDS, **SEL, text="casino.example\ncategory:Partner portals"))
    assert r.status_code == 200 and r.json()["entries"] == 2
    res = jobs[0]
    assert res["status"] == "done" and res["report_id"].startswith("catlookup-")
    assert "s3cret" not in json.dumps(res) and cat(res["entries"][0], "GAMBLING")["rules"]
    r = c.post("/api/category-lookup/start", json=dict(CREDS, **SEL, text="box.com", report_id=res["report_id"]))
    assert r.status_code == 200 and jobs[1]["report_id"] == res["report_id"]


# ── The page ─────────────────────────────────────────────────────────
def _read(*parts):
    return open(os.path.join(ROOT, *parts), encoding="utf-8").read()


def test_the_lookup_is_a_tab_of_the_path_analyzer_with_labelled_controls_and_help():
    """WCAG 2.2 SC 4.1.2 · SC 1.3.1 · SC 3.3.2: a third ARIA tab with a labelled text area, its help marks and the What's new mark."""
    html = _read("static", "report_path.html")
    assert 'id="tab-cat" aria-controls="panel-cat"' in html and 'role="tabpanel" id="panel-cat" aria-labelledby="tab-cat"' in html
    assert 'id="clText"' in html and 'aria-describedby="clHow"' in html and '<script src="/static/category_lookup.js"></script>' in html
    assert html.index("/static/path_list.js") < html.index("/static/category_lookup.js")
    cat_ = _read("static", "help_catalog.js")
    for sel in ("#tab-cat", "#clText", "#clRun", "#clFresh"):
        assert f'"{sel}": {{' in cat_
    assert _read("static", "help_catalog.js") == _read("browser_extension", "help_catalog.js")
    assert '"at": "#tab-cat"' in _read("static", "whats_new.js")


def test_test_a_list_rows_and_find_anything_open_the_lookup():
    """WCAG 2.2 SC 2.4.4 · SC 3.2.4: each Test a list row with one destination has a Categories button; Find anything offers the lookup for a host."""
    js = _read("static", "path_list.js")
    assert "catLink(r.target)" in js and "window.CategoryLookup.open(b.dataset.catq, true)" in js
    fa = _read("static", "find_anything.js")
    assert "'/report/path#categories=' + encodeURIComponent(it.target)" in fa
    ex = _read("static", "explain.js")
    assert "X.catlookup = {" in ex and "'catlookup'" in ex[ex.index("DLP_EXPLAIN_ORDER"):]


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("q,want", [("dropbox.com", "dropbox.com"), ("https://x.example/a?b=1", "https://x.example/a?b=1"), ("10.0.0.1", "10.0.0.1"),
                                    ("export to terraform", ""), ("engine", ""), ("a.b c", ""), ("x" * 600 + ".com", "")])
def test_find_anything_recognises_a_destination(q, want):
    """WCAG 2.2 SC 3.3.2 · CWE-20: a URL, host or IP address (and nothing else) gets the Category lookup result."""
    script = f"const c = require({json.dumps(os.path.join(ROOT, 'static', 'find_anything.js'))}); process.stdout.write(JSON.stringify(c.lookupTarget({json.dumps(q)})));"
    out = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    assert json.loads(out.stdout) == want


XSS = "<img src=x onerror=alert(1)>"


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_the_page_escapes_every_tenant_value_it_shows():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: a markup payload in every field the tenant or the input controls is shown as text, never as HTML."""
    rule = {"section": "url", "section_label": XSS, "id": XSS, "name": XSS, "order": XSS, "rank": XSS, "position": XSS, "action": XSS,
            "enabled": False, "default": True, "via": XSS}
    res = {"entries": [{"input": XSS, "kind": "host", "host": XSS, "categories": [{"id": XSS, "name": XSS, "custom": True, "source": XSS, "rules": [rule]}],
                        "application": XSS, "application_rules": [rule], "security_alerts": [XSS], "lookup_error": XSS,
                        "custom_containing": [{"id": XSS, "name": XSS}], "note": XSS}],
           "skipped": [{"text": XSS, "why": XSS}], "sections": [{"key": "url", "label": XSS, "state": "unread", "why": XSS, "rules": 1, "any_count": 0}],
           "notes": [XSS], "ranked": True, "scope_summary": XSS}
    script = (f"const c = require({json.dumps(os.path.join(ROOT, 'static', 'category_lookup.js'))});"
              f"process.stdout.write(c.pageHtml({json.dumps(res)}, [{json.dumps(XSS)}]));")
    out = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, timeout=20)
    assert out.returncode == 0, out.stderr
    assert "<img" not in out.stdout and out.stdout.count("&lt;img src=x onerror=alert(1)&gt;") >= 20


def test_a_link_fills_the_lookup_but_never_reads_on_its_own():
    """ASVS V4.1.3 · CWE-352: a #categories= link (Find anything) fills the box; reading the tenant needs the Look up click."""
    js = _read("static", "category_lookup.js")
    assert "open(q, false);   // filled in, never run on its own" in js and "addEventListener('hashchange', fromHash)" in js
