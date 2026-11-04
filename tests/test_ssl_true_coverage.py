"""True inspection coverage (ssl_true_coverage.py over ssl_coverage.py and
traffic_logs.py): the four parts always add up to 100% in each unit, bytes
and transactions are split apart, unknown is never counted as inspected,
each share left encrypted is tied to its cause (from NSS web logs by rule
order; from Insights by application bytes, capped), traffic that never
reaches ZIA is in no percentage, the policy estimate is always labelled an
estimate, missing data is said and never guessed, the web logs reference is
checked before any sign-in, and the page builds the section safely. No
tenant is contacted: the test fakes and the made-up sample tenant only."""
from __future__ import annotations

import copy
import io
import json
import math
import os
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import insights
import ssl_coverage as sc
import ssl_true_coverage as tc
import traffic_logs as tl
from test_ssl_coverage import CREDS, IN_SCOPE, NO_INSIGHTS, SSL, FakeCl, _cc, _poll, sdk, tenant_routes

ROOT = os.path.join(os.path.dirname(__file__), "..")
LOOKUP = {"FILE_HOST": {"configured_name": "File Host"}}
LOG_SSL = {"inspected": 700, "not_inspected": 220, "plain_http": 60, "not_logged": 20,
           "bytes": {"inspected": 7_000_000_000, "not_inspected": 2_500_000_000, "plain_http": 300_000_000, "not_logged": 200_000_000},
           "not_inspected_by": [{"category": "File Host", "app": "Dropbox", "count": 90, "bytes": 1_200_000_000},
                                {"category": "Finance", "app": "", "count": 60, "bytes": 300_000_000},
                                {"category": "Social Networking", "app": "Facebook", "count": 30, "bytes": 400_000_000},
                                {"category": "Online Chat", "app": "Zoom", "count": 20, "bytes": 300_000_000},
                                {"category": "News and Media", "app": "", "count": 10, "bytes": 100_000_000}]}


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_SSL_COVERAGE_STATE", str(tmp_path / "ssl_coverage_history.json"))


def _volume():
    return sc.read_volume(sdk().zins, "7d", log=lambda m: None)


def _logs(ssl=None):
    return {"ssl": copy.deepcopy(ssl or LOG_SSL), "period": {"first": "2026-11-01T00:00:00Z", "last": "2026-11-02T00:00:00Z"}, "records": 1000}


def _sum(sp):
    return round(sum(x["pct"] for x in sp["slices"]), 1)


# ── Arithmetic ──────────────────────────────────────────────────────────
@pytest.mark.parametrize("amounts", [
    {"http": 1, "https_inspected": 1, "https_not_inspected": 1, "unknown": 0},          # thirds
    {"http": 1, "https_inspected": 1, "https_not_inspected": 1, "unknown": 1e-9},
    {"http": 3, "https_inspected": 3, "https_not_inspected": 3, "unknown": 3},
    {"http": 0, "https_inspected": 9e18, "https_not_inspected": 1, "unknown": 0},       # one tiny slice next to a huge one
    {"http": 7, "https_inspected": 0, "https_not_inspected": 0, "unknown": 0},
    {"http": 2, "https_inspected": 655, "https_not_inspected": 276, "unknown": 37},
])
def test_the_four_parts_always_add_up_to_exactly_100(amounts):
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: rounded shares add up to 100.0 exactly; the true figure is HTTP plus decrypted HTTPS."""
    # Act
    sp = tc.unit_split(amounts)
    # Assert
    t = sp["_tenths"]
    assert sum(t.values()) == 1000 and _sum(sp) == 100.0 and sp["sum_pct"] == 100.0
    assert all(0 <= x["pct"] <= 100 for x in sp["slices"])
    assert sp["inspected_pct"] == (t["http"] + t["https_inspected"]) / 10
    assert sp["inspected_pct_high"] == (t["http"] + t["https_inspected"] + t["unknown"]) / 10


@pytest.mark.parametrize("amounts", [
    {}, {"http": 0, "https_inspected": 0}, {"http": -5, "https_inspected": float("nan")}, {"http": True, "unknown": float("inf")},
    {"http": "lots"},
])
def test_nothing_to_divide_is_no_share_never_0_or_100(amounts):
    """ASVS V5.1.4 · CWE-369 · WSTG-INPV-01: zero, negative, non-finite, boolean or text amounts give no split at all."""
    # Act / Assert
    assert tc.unit_split(amounts) is None


def test_unknown_is_never_counted_as_inspected():
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: Insights' unclassified protocols are unknown: the figure is a floor, the range shows the rest."""
    # Arrange
    rep = sc.analyse(SSL, cc=_cc(), volume=_volume(), lookup=LOOKUP)
    # Act
    tx = rep["true_coverage"]["units"]["TRANSACTIONS"]
    sl = {x["key"]: x for x in tx["slices"]}
    # Assert: 1050 transactions, 50 of them TUNNEL / QUIC_NEW (unknown)
    assert sl["unknown"]["amount"] == 50 and sl["unknown"]["pct"] == 4.8
    assert tx["inspected_pct"] == 76.2 and tx["inspected_pct_high"] == 81.0
    assert tx["inspected_pct"] < round(100 * 800 / 1000, 1)   # the old share left unknown out of the denominator
    assert rep["summary"]["inspected_pct_transactions"] == 76.2
    assert "between 76.2% and 81%" in tc._headline("measured", "TRANSACTIONS", tx, "last 7 days", 0)


def test_bytes_and_transactions_are_split_apart():
    """ASVS V1.4.4 · CWE-682: each unit is its own 100%; a slice's share differs by unit and the bytes figure leads."""
    # Arrange / Act
    t = sc.analyse(SSL, cc=_cc(), volume=_volume(), lookup=LOOKUP)["true_coverage"]
    by, tx = t["units"]["BYTES"], t["units"]["TRANSACTIONS"]
    # Assert
    assert _sum(by) == 100.0 and _sum(tx) == 100.0
    assert by["inspected_pct"] == 90.0 and by["not_inspected_pct"] == 10.0 and by["unknown_pct"] == 0.0
    assert tx["not_inspected_pct"] == 19.0 and tx["inspected_pct"] != by["inspected_pct"]
    assert t["primary_unit"] == "BYTES" and "of web bytes" in t["headline"] and t["window"] == "last 7 days"


# ── Cause attribution ───────────────────────────────────────────────────
def test_web_log_lines_left_encrypted_are_tied_to_the_rule_in_order():
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: each line's category or app maps to the first rule naming it; shares add up to the slice."""
    # Arrange / Act
    t = sc.analyse(SSL, cc=_cc(), lookup=LOOKUP, logs=_logs())["true_coverage"]
    rows = {r["rule"] or r["kind"]: r for r in t["causes"]}
    # Assert: the source and window
    assert t["source"] == "logs" and t["mode"] == "measured" and not t["estimate"] and "2026-11-01" in t["window"]
    # Category display names match rule ids; applications by name; the scoped catch-all only "probably".
    assert rows["DNI file hosts"]["TRANSACTIONS"] == 90 and rows["DNI file hosts"]["examples"] == ["File Host / Dropbox"]
    assert rows["Privacy DNI"]["TRANSACTIONS"] == 60 and rows["DNI social, skip all"]["BYTES"] == 400_000_000
    assert rows["DNI chat apps"]["how"].startswith("its cloud application")
    assert rows["Exec bypass"]["TRANSACTIONS"] == 10 and "groups" in rows["Exec bypass"]["how"]
    assert rows["rest"]["TRANSACTIONS"] == 10 and rows["rest"]["BYTES"] == 200_000_000   # 220 left encrypted, 210 in the top list
    for unit in tc.UNITS:
        shares = [r["pct_of"][unit] for r in t["causes"]]
        assert round(sum(shares), 1) == t["units"][unit]["not_inspected_pct"]
    assert rows["DNI file hosts"]["fix"] == {"href": "/report/operations?build=rule_edit", "label": "Edit the SSL inspection rule (Bulk changes)"}
    assert rows["Privacy DNI"]["fix"] is None   # expected privacy exemption: kept, no fix offered


@pytest.mark.parametrize("cat,app,expect,how", [
    ("Web Mail", "", None, "no enabled SSL rule"),
    ("", "ChatGPT", "DNI chat apps", "cloud application"),
    ("Social Networking", "", "DNI social, skip all", "URL category"),
    ("Sports", "Zoom", "DNI chat apps", "cloud application"),
])
def test_a_line_no_named_rule_explains_falls_to_catch_all_pinned_or_unexplained(cat, app, expect, how):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: without a catch-all a line no rule names is 'not explained', never guessed onto a rule."""
    # Arrange: the rules without the scoped and default catch-alls
    rules = [r for r in SSL if r["id"] not in (2, 9)]
    causes = tc._rule_causes(sc.ssl_rule_causes(rules, LOOKUP))
    # Act
    c, why = tc.match_log_row(cat, app, causes)
    # Assert
    assert (c and (c.get("source") or {}).get("name")) == expect and how in why


def test_a_pinned_application_falls_to_zscalers_pinned_exemptions():
    """ASVS V1.4.4 · CWE-697: a pinned app no rule names is put on Zscaler's certificate-pinned exemptions."""
    # Arrange
    causes = tc._rule_causes(sc.ssl_rule_causes([SSL[0]]))
    # Act
    c, why = tc.match_log_row("Online Chat", "Webex", causes)
    # Assert
    assert c["kind"] == "pinned_exemptions" and "certificate-pinned" in why and tc.fix_of(c) is None


def test_insights_splits_bytes_by_exempted_apps_once_and_never_past_the_slice():
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: app bytes count once, are scaled to fit the slice, and the rest is 'not split' with the likely rules."""
    # Arrange: Zoom is named by two rules; the second must not count it again; the bytes are far more than the slice
    rules = copy.deepcopy(SSL) + [{"id": 10, "name": "Zoom again", "order": 6, "state": "ENABLED", "cloud_applications": ["ZOOM"],
                                   "action": {"type": "DO_NOT_DECRYPT"}}]
    vol = _volume()
    vol["apps"] = [{"application": "Zoom", "data_consumed": 9e12}, {"application": "ChatGPT", "data_consumed": 3e12}]
    # Act
    t = sc.analyse(rules, cc=_cc(), volume=vol, lookup=LOOKUP)["true_coverage"]
    # Assert
    named = [r for r in t["causes"] if r["kind"] != "not_split"]
    assert [r["rule"] for r in named] == ["DNI chat apps"] and t["source"] == "insights"
    slice_b = t["units"]["BYTES"]["slices"][2]["amount"]
    assert math.isclose(sum(r["BYTES"] for r in named) + t["unattributed"]["BYTES"], slice_b)
    assert named[0]["BYTES"] <= slice_b and any("scaled down" in n for n in t["notes"])
    assert round(named[0]["pct_of"]["BYTES"] + t["unattributed"]["pct_of"]["BYTES"], 1) == t["units"]["BYTES"]["not_inspected_pct"]
    assert named[0]["pct_of"]["TRANSACTIONS"] is None and t["unattributed"]["pct_of"]["TRANSACTIONS"] == 19.0
    assert "estimate" in named[0]["basis"] and "Zscaler Recommended Exemptions" in [x["rule"] for x in t["unattributed"]["likely"]]


def test_traffic_that_never_reaches_zia_is_listed_apart_and_in_no_percentage():
    """ASVS V1.4.4 · CWE-682: Client Connector, forwarding and PAC bypasses and ZPA are outside, with fixes; they change no share."""
    # Arrange
    with_cc = sc.analyse(SSL, cc=_cc(), volume=_volume(), lookup=LOOKUP, zpa_in_scope=True)["true_coverage"]
    without = sc.analyse(SSL, volume=_volume(), lookup=LOOKUP)["true_coverage"]
    # Act
    kinds = [o["kind"] for o in with_cc["outside"]]
    # Assert
    assert {"forwarding_none", "zcc_domains", "pac_direct", "zcc_apps", "zpa_routed"} <= set(kinds) and without["outside"] == []
    assert with_cc["units"] == without["units"]
    fixes = {o["kind"]: (o["fix"] or {}).get("href") for o in with_cc["outside"]}
    assert fixes["pac_direct"] == "/report/operations?build=zia_pac" and fixes["zpa_routed"] == "/report/zpa"
    assert "send traffic around ZIA" in with_cc["headline"]
    assert all(re.fullmatch(r"/report/operations\?build=[a-z_]+", f"/report/operations?build={b}") for b, _ in tc.FIX_LINKS.values())


# ── Estimate versus measured ────────────────────────────────────────────
def test_without_traffic_numbers_it_is_an_estimate_and_says_what_is_needed():
    """ASVS V1.4.4 · CWE-1287 · WSTG-BUSL-01: the policy estimate is labelled, never shown as measured, and names the licence and permission."""
    # Arrange / Act
    rep = sc.analyse(SSL, cc=_cc(), lookup=LOOKUP, no_volume_reason="ZIA Insights is not in scope.")
    t = rep["true_coverage"]
    # Assert
    assert t["mode"] == "estimate" and t["estimate"] is True and t["source"] == "policy" and list(t["units"]) == ["MIX"]
    assert t["headline"].startswith("Estimate, not measured") and "not measured" in t["source_label"]
    assert "ZIA Insights" in t["needs"] and "OneAPI" in t["needs"] and "NSS" in t["needs"] and t["why_estimate"] == "ZIA Insights is not in scope."
    assert _sum(t["units"]["MIX"]) == 100.0 and t["assumed_mix"]["http_pct"] == tc.ASSUMED_HTTP_PCT
    assert round(sum(r["pct_of"]["MIX"] for r in t["causes"]), 1) == t["units"]["MIX"]["not_inspected_pct"]
    assert all(r["basis"] == "estimate from a typical traffic mix" for r in t["causes"])
    # Never presented as measured anywhere else either.
    assert "inspected_pct_bytes" not in rep["summary"] and "true_source" not in rep["summary"] and not rep["headline"].startswith("About")
    assert math.isclose(sum(tc.ASSUMED_MIX.values()), 100.0)


def test_measured_figures_are_labelled_measured_with_their_source():
    """ASVS V1.4.4 · CWE-1287: Insights and logs are labelled measured, with the source; logs win and the Insights figure is a note."""
    # Act
    ins = sc.analyse(SSL, cc=_cc(), volume=_volume(), lookup=LOOKUP)["true_coverage"]
    both = sc.analyse(SSL, cc=_cc(), volume=_volume(), lookup=LOOKUP, logs=_logs())["true_coverage"]
    # Assert
    assert ins["headline"].startswith("True inspection coverage (last 7 days)") and ins["needs"] is None
    assert ins["source_label"].startswith("Measured: ZIA Insights") and sc.PROTOCOL_NOTE in ins["notes"]
    assert both["source"] == "logs" and both["source_label"].startswith("Measured: ZIA NSS web logs")
    assert any(n.startswith("ZIA Insights for the chosen window gives") for n in both["notes"])


# ── Missing data ────────────────────────────────────────────────────────
def test_logs_without_an_inspection_status_are_not_used_and_it_says_so():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: logs with no decrypted field fall back to Insights, with the reason."""
    # Arrange
    empty = {"inspected": 0, "not_inspected": 0, "plain_http": 0, "not_logged": 0, "bytes": {}, "not_inspected_by": []}
    # Act
    t = sc.analyse(SSL, volume=_volume(), logs=_logs(empty))["true_coverage"]
    # Assert
    assert t["source"] == "insights" and any("no ZIA web traffic with an inspection status" in n for n in t["notes"])


def test_logs_without_sizes_have_no_bytes_split_and_say_so():
    """ASVS V5.1.4 · CWE-20: no request or response sizes means no bytes figure, never zero bytes made up."""
    # Arrange
    no_bytes = dict(copy.deepcopy(LOG_SSL), bytes={})
    for r in no_bytes["not_inspected_by"]:
        r["bytes"] = 0
    # Act
    t = sc.analyse(SSL, logs=_logs(no_bytes))["true_coverage"]
    # Assert
    assert t["units"]["BYTES"] is None and t["primary_unit"] == "TRANSACTIONS" and any("no split by bytes" in n for n in t["notes"])
    assert all(r["pct_of"]["BYTES"] is None for r in t["causes"])


def test_an_insights_unit_that_failed_is_said_and_the_other_leads():
    """ASVS V7.4.1 · CWE-755: a failed protocol query in one unit is a note; the other unit gives the figure."""
    # Arrange
    vol = _volume()
    vol["protocols"]["BYTES"] = None
    # Act
    t = sc.analyse(SSL, volume=vol)["true_coverage"]
    # Assert
    assert t["units"]["BYTES"] is None and t["primary_unit"] == "TRANSACTIONS"
    assert any("in bytes could not be read" in n for n in t["notes"])


def test_no_rules_and_no_traffic_gives_no_figure():
    """ASVS V7.4.1 · CWE-755: nothing to measure or estimate from is said plainly, not shown as 0%."""
    # Act
    t = tc.build([], [], None, None)
    # Assert
    assert t["mode"] == "none" and t["units"] == {} and "cannot be given" in t["headline"] and t["needs"]


# ── Web logs (traffic_logs.py) ──────────────────────────────────────────
def test_nss_web_lines_give_bytes_per_part_and_what_was_left_encrypted():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: each NSS web line counts once with its sizes; not-inspected lines keep category and app."""
    # Arrange
    ev = lambda **k: json.dumps({"sourcetype": "zscalernss-web", "event": dict({"datetime": "2026-11-01 10:00:00", "login": "a@x.example",  # noqa: E731
                                                                                 "action": "Allowed"}, **k)})
    lines = "\n".join([ev(proto="HTTPS", url="mail.example.com/x", urlcat="Web Mail", appname="Gmail", ssldecrypted="No", reqsize="100", respsize="900"),
                       ev(proto="HTTPS", url="docs.example.com/", urlcat="File Host", ssldecrypted="Yes", reqsize="10", respsize="-5"),
                       ev(proto="HTTP", url="news.example.com/", urlcat="News", reqsize="10", respsize="90"),
                       ev(proto="HTTPS", url="x.example.com/", urlcat="News", reqsize="nan")])
    # Act
    s = tl.analyze([{"name": "web.json", "content": lines}])["zia"]["zia_web"]["ssl"]
    # Assert
    assert (s["inspected"], s["not_inspected"], s["plain_http"], s["not_logged"]) == (1, 1, 1, 1)
    assert s["bytes"] == {"inspected": 10, "not_inspected": 1000, "plain_http": 100, "not_logged": 0}
    assert s["not_inspected_by"] == [{"category": "Web Mail", "app": "Gmail", "count": 1, "bytes": 1000}]


# ── The route ───────────────────────────────────────────────────────────
@pytest.mark.parametrize("rid,why", [
    ("../etc/passwd", "not a traffic log report id"),
    ("tlogs-" + "a" * 60, "not a traffic log report id"),
    ("tlogs-nothere123", "no longer in memory"),
    ("sslcoverage-abcdefgh", "not a traffic log report id"),
])
def test_a_bad_web_logs_reference_is_refused_before_sign_in(monkeypatch, rid, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a malformed, unknown or wrong-kind report id is a 400 before any client is built."""
    # Arrange
    def no_sign_in(*a, **k):
        raise AssertionError("signed in although refused")
    monkeypatch.setattr(srv, "_build_client", no_sign_in)
    monkeypatch.setattr(srv, "_build_sdk_client", no_sign_in)
    # Act
    r = TestClient(srv.app).post("/api/ssl-coverage/start", json=dict(CREDS, logs_report_id=rid, **IN_SCOPE))
    # Assert
    assert r.status_code == 400 and why in r.text and "Nothing was read" in r.text, r.text


def test_logs_without_zia_web_lines_are_refused_before_sign_in(monkeypatch):
    """ASVS V5.1.3 · CWE-20: a traffic log report of ZPA lines only cannot give web coverage: 400, nothing read."""
    # Arrange
    monkeypatch.setattr(srv, "_build_client", lambda req: (_ for _ in ()).throw(AssertionError("signed in")))
    rid = srv._remember_report("tlogs", {"kind": "traffic-logs", "zia": None, "zpa": {}})
    # Act
    r = TestClient(srv.app).post("/api/ssl-coverage/start", json=dict(CREDS, logs_report_id=rid, **NO_INSIGHTS))
    # Assert
    assert r.status_code == 400 and "no ZIA web traffic" in r.text


def test_the_job_uses_the_uploaded_logs_for_the_figure(monkeypatch):
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: a valid logs reference gives a measured, log-based figure in the job's result and export."""
    # Arrange
    cl = FakeCl(tenant_routes())
    monkeypatch.setattr(srv, "_build_client", lambda req: cl)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: sdk())
    rid = srv._remember_report("tlogs", {"kind": "traffic-logs", "period": {"first": "2026-11-01T00:00:00Z", "last": "2026-11-02T00:00:00Z"},
                                         "zia": {"zia_web": {"records": 1000, "ssl": copy.deepcopy(LOG_SSL)}}})
    c = TestClient(srv.app)
    # Act
    snap = _poll(c, c.post("/api/ssl-coverage/start", json=dict(CREDS, logs_report_id=rid, **IN_SCOPE)).json()["job_id"])
    # Assert
    res = snap["result"]
    t = res["true_coverage"]
    assert snap["status"] == "done" and t["source"] == "logs" and t["units"]["TRANSACTIONS"]["inspected_pct"] == 76.0
    assert res["summary"]["inspected_pct_transactions"] == 76.0 and res["summary"]["true_source"] == "logs"
    assert any("Using the uploaded ZIA web logs (1,000 records)" in line for line in snap["all_logs"])
    x = c.get(f"/api/ssl-coverage/export/{res['report_id']}?format=xlsx")
    z = zipfile.ZipFile(io.BytesIO(x.content))
    assert x.status_code == 200 and 'name="True coverage"' in z.read("xl/workbook.xml").decode()
    assert "DNI file hosts" in "".join(z.read(n).decode() for n in z.namelist() if n.startswith("xl/"))


def test_the_sample_tenant_gives_a_measured_figure_with_realistic_proportions():
    """ASVS V1.4.4 · CWE-682: offline, the made-up tenant's Insights answer per unit gives a measured split that adds up in both units."""
    # Arrange
    import data_flow
    import offline_tenant as ot
    creds = ot.creds_for(ot.sample_store())
    raw, sdk_cl = ot.client_for(creds, "raw"), ot.client_for(creds, "sdk")
    scope = data_flow.path_scope(["dlp", "zcc", "insights", "zpa"], {"ssl_inspection": "zscaler"})
    # Act
    t = sc.run(raw, scope, zins=sdk_cl.zins, volume_plan={"ask": True, "window": "7d"})["true_coverage"]
    # Assert
    by, tx = t["units"]["BYTES"], t["units"]["TRANSACTIONS"]
    assert t["source"] == "insights" and _sum(by) == 100.0 and _sum(tx) == 100.0 and by != tx
    assert 60 <= by["inspected_pct"] <= 80 and 10 <= by["not_inspected_pct"] <= 35 and 0 < by["unknown_pct"] < 10
    assert {"zpa_routed", "pac_direct"} <= {o["kind"] for o in t["outside"]}


# ── The page ────────────────────────────────────────────────────────────
def _page():
    with open(os.path.join(ROOT, "static", "report_ssl_coverage.html"), encoding="utf-8") as f:
        return f.read()


def test_the_page_builds_the_section_with_dom_calls_and_checks_fix_links():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01 · WCAG 2.2 SC 1.4.1: tenant text goes in with textContent; fix links are the app's own pages; parts have words, not colour only."""
    # Arrange
    html = _page()
    fn = html[html.index("function drawTrue()"):html.index("// ── Traffic river")]
    # Assert
    assert "innerHTML" not in fn and "insertAdjacentHTML" not in fn
    assert fn.count(r"/^\/report\/[a-z-]+(\?build=[a-z_]{1,40})?$/.test(r.fix.href)") == 2
    assert 'id="scTrue"' in html and "aria-hidden', 'true'" in fn and "<caption" not in fn and "el('caption'" in fn
    assert "logs_report_id: logsId" in html and r"/^tlogs-[A-Za-z0-9_-]{6,40}$/" in html and 'id="scLogsDrop"' in html


def test_help_marks_and_glossary_cover_the_new_controls():
    """WCAG 2.2 SC 3.3.2 · SC 3.3.5: every new control has help in both catalogues; the glossary explains the new words."""
    # Arrange
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    ext = open(os.path.join(ROOT, "browser_extension", "help_catalog.js"), encoding="utf-8").read()
    g = open(os.path.join(ROOT, "static", "glossary.js"), encoding="utf-8").read()
    # Assert
    for key in ('"#scLogsDrop"', '"#scTrueH"', '"#scTrue a.sc-fix"', '"#scTrue button[data-unit=\\"BYTES\\"]"', '"#tlTrueCoverage"'):
        assert key in cat, key
    assert cat == ext
    assert "'true inspection coverage'" in g and "'plain http'" in g
