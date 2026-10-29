"""QA cloud 6 — the assessment engine (dlp_assessment_full_auto), the DLP
analysis footprint (dlp_analysis) and the efficacy analyzer (dlp_efficacy).

Every test runs against in-memory fakes: no tenant, no network, no clock.
"""
import io
import json
import os
import stat
import sys

import pytest

import dlp_analysis
import dlp_assessment_full_auto as A
import dlp_efficacy as E
import permissions
from dlp_assessment_full_auto import R


# ── fakes ────────────────────────────────────────────────────────────

class Fake:
    """A tenant read by path: `routes` answers 200, anything else `default` (code)."""
    customer_id = ""

    def __init__(self, routes=None, default=404, codes=None):
        self.routes = routes or {}
        self.default = default
        self.codes = codes or {}
        self.calls = []

    def get(self, ep, p=None, *a, **k):
        ep = str(ep).replace("raw:", "")
        self.calls.append(ep)
        if ep in self.codes:
            return {"error": "refused"}, self.codes[ep]
        if ep in self.routes:
            v = self.routes[ep]
            return (v(ep) if callable(v) else v), 200
        return {"error": "x"}, self.default


class AllCode(Fake):
    """Every read answers `code` with `payload` (200) or an error body."""
    def __init__(self, code, payload=None):
        super().__init__(default=code)
        self.code, self.payload = code, payload

    def get(self, ep, p=None, *a, **k):
        self.calls.append(str(ep))
        if self.code == 200:
            return self.payload, 200
        return {"error": "refused"}, self.code


OWN = [c for c in A.REG if c[3].__module__ == A.__name__]
OWN_IDS = [c[0] for c in OWN]


def _cls(r):
    return permissions.classify({"status": r.status, "detail": r.detail})


def _check(cid):
    return next(c[3] for c in A.REG if c[0] == cid)


# ── 1. permission denied is "not permitted", never a pass ─────────────

@pytest.mark.parametrize("cid", OWN_IDS)
def test_every_check_reports_a_refused_read_as_not_permitted(cid):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a check whose every read is refused (HTTP 403) is "not permitted", never PASS, FAIL or REVIEW."""
    cl = AllCode(403)
    r = _check(cid)(cl)
    if not cl.calls:          # a manual check that reads nothing: it is never a pass
        assert r.status != R.PASS
        return
    assert _cls(r) == "not_permitted", (cid, r.status, r.detail)


@pytest.mark.parametrize("cid", OWN_IDS)
def test_no_check_passes_on_an_unauthenticated_read(cid):
    """ASVS V7.4.1 · A07:2021 · CWE-287 · WSTG-ATHN-04: an HTTP 401 on every read never yields PASS."""
    assert _check(cid)(AllCode(401)).status != R.PASS


@pytest.mark.parametrize("cid", ["6.1", "6.3", "6.7", "10.1", "10.3", "10.4", "2.3", "5.6", "MC.12", "B.2", "B.3"])
def test_checks_that_used_to_pass_on_a_refused_read_now_do_not(cid):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the eleven checks that answered PASS on a 403 (regression) are not permitted."""
    r = _check(cid)(AllCode(403))
    assert r.status == R.INFO and "HTTP 403" in r.detail


def test_browser_isolation_403_is_not_permitted_not_unlicensed():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: 3.7 says a 403 is a refusal, a 404 is not licensed."""
    denied = A.c_3_7(Fake(codes={"/zia/browserIsolation/profiles": 403}))
    missing = A.c_3_7(Fake(default=404))
    assert _cls(denied) == "not_permitted" and "not licensed" not in denied.detail
    assert missing.status == R.INFO and "not licensed" in missing.detail


def test_casb_not_licensed_is_informational_not_review():
    """ASVS V7.4.1 · CWE-755: MC.3 on a 404 (not licensed) is informational, outside the score (docs/SCORING.md)."""
    r = A.c_mc3(Fake(default=404))
    assert r.status == R.INFO and _cls(r) == "informational"


def test_genai_categories_refused_cac_read_is_not_permitted():
    """ASVS V7.4.1 · CWE-755: E.1 with no GenAI URL rule and a refused Cloud App Control read is not permitted, not "nothing governs GenAI"."""
    cl = Fake({"/zia/urlCategories": [], "/zia/urlFilteringRules": []}, codes={"/zia/cloudApplicationRules": 403})
    assert _cls(A.c_e1(cl)) == "not_permitted"


# ── 2. messy tenant data never crashes a check ───────────────────────

MESSY = [{"name": 5, "state": None, "description": 7, "action": 3, "osType": None, "custom": 1, "phrases": 1,
          "patterns": "x", "urlCategories": None, "fileTypes": [None, 3], "dlpEngines": [None, {"id": None}]},
         None, 3, "x", [], {"name": None, "state": 1, "action": {"type": None}}]


@pytest.mark.parametrize("payload", [MESSY, None, {"list": MESSY}, {"error": "x"}, 7, "text", {"list": None}],
                         ids=["list", "none", "wrapped", "errorbody", "int", "str", "nulllist"])
def test_no_check_raises_on_messy_tenant_data(payload):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: nulls, numbers for strings and non-objects never raise in any check."""
    crashed = []
    for cid, _, _, fn in OWN:
        try:
            fn(AllCode(200, payload))
        except Exception as exc:  # noqa: BLE001
            crashed.append((cid, repr(exc)))
    assert crashed == []


def test_numeric_device_and_rule_names_are_joined_as_text():
    """ASVS V5.1.4 · CWE-704: a numeric profile name is listed, not a TypeError (1.10 tamper passwords)."""
    r = A.c_1_10(Fake({"/zcc/appProfiles": [{"name": 42, "active": 1}]}))
    assert r.status == R.FAIL and "42" in r.detail


def test_web_dlp_action_object_is_counted_not_unhashable():
    """ASVS V5.1.4 · CWE-704: 5.3 counts a web DLP action given as an object ({"type": ...})."""
    r = A.c_5_3(Fake({"/zia/webDlpRules": [{"state": "ENABLED", "action": {"type": "BLOCK"}}, {"state": "ENABLED", "action": "ALLOW"}]}))
    assert r.status == R.PASS and "1xBLOCK" in r.detail and "1xALLOW" in r.detail


def test_huge_device_list_is_assessed_quickly():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: 50 000 devices are assessed by 6.1, 6.3 and 6.7 without error."""
    devs = [{"id": i, "state": 1, "osType": "Windows", "osVersion": "10.0.22631", "agentVersion": "4.6.0.200"} for i in range(50_000)]
    cl = Fake({"/zcc/devices": devs})
    for fn in (A.c_6_1, A.c_6_3, A.c_6_7):
        assert fn(cl).status in (R.PASS, R.FAIL, R.WARN)


# ── 3. oracle tables per check (pass / fail / missing fields / denied) ──

SSL_INSPECT_ALL = {"name": "Inspect all", "order": 5, "state": "ENABLED", "action": {"type": "DECRYPT"}}
SSL_REC = {"name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}}
SSL_BROAD_DNI = {"name": "Skip all", "order": 2, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}

ORACLE = [
    # (check, routes, codes, expected status)
    ("4.1", {"/zia/sslInspectionRules": [SSL_REC, SSL_INSPECT_ALL]}, {}, R.PASS),
    ("4.1", {"/zia/sslInspectionRules": [SSL_REC]}, {}, R.FAIL),
    ("4.1", {"/zia/sslInspectionRules": [{"name": "x"}]}, {}, R.FAIL),
    ("4.3", {"/zia/sslInspectionRules": [SSL_BROAD_DNI, SSL_INSPECT_ALL]}, {}, R.FAIL),
    ("4.3", {"/zia/sslInspectionRules": [SSL_REC, SSL_INSPECT_ALL]}, {}, R.PASS),
    ("5.3", {"/zia/webDlpRules": [{"state": "ENABLED", "action": "BLOCK"}]}, {}, R.PASS),
    ("5.3", {"/zia/webDlpRules": [{"state": "DISABLED"}]}, {}, R.FAIL),
    ("5.3", {"/zia/webDlpRules": [{"name": "no state"}]}, {}, R.FAIL),
    ("6.3", {"/zcc/devices": [{"state": 1}]}, {}, R.PASS),
    ("6.3", {"/zcc/devices": [{"state": 5}, {"state": "orphaned"}]}, {}, R.WARN),
    ("6.3", {"/zcc/devices": [{"id": 1}]}, {}, R.PASS),
    ("6.1", {"/zcc/devices": []}, {}, R.INFO),
    ("8.5", {"/zia/webDlpRules": [{"state": "ENABLED"}]}, {}, R.PASS),
    ("8.5", {"/zia/webDlpRules": []}, {}, R.WARN),
    ("10.4", {"/zcc/devices": [{"osType": "macOS"}]}, {}, R.PASS),
    ("MC.12", {"/zia/webDlpRules": [], "/zia/sslInspectionRules": []}, {}, R.INFO),
    ("12.2", {"/zia/icapServers": [{"name": "a", "url": "icaps://x"}]}, {}, R.PASS),
    ("12.2", {"/zia/icapServers": [{"name": "a", "url": "icap://x"}]}, {}, R.FAIL),
    ("12.2", {"/zia/icapServers": [{"name": "a"}]}, {}, R.FAIL),
    ("12.8", {"/zia/nssFeeds": [{"name": "w", "feedStatus": "ENABLED"}]}, {}, R.PASS),
    ("12.8", {"/zia/nssFeeds": [{"name": "w", "feedStatus": "DISABLED"}]}, {}, R.WARN),
    ("12.9", {"/zia/nssFeeds": [{"name": "w", "nssLogType": "WEBLOG", "feedOutputFormat": "%s{dlpeng} %s{dlpdict} %s{dlpmd5} %s{trig_dlprulename}"}]}, {}, R.PASS),
    ("12.9", {"/zia/nssFeeds": [{"name": "w", "nssLogType": "WEBLOG", "feedOutputFormat": 5}]}, {}, R.WARN),
    ("2.3", {"/zia/pacFiles": []}, {}, R.PASS),
    ("2.3", {"/zia/pacFiles": [{"name": "p"}]}, {}, R.WARN),
    ("5.6", {"/zia/urlFilteringRules": []}, {}, R.PASS),
    ("12.13", {"/zia/adminRoles": [{"id": 1}, {"id": 2}]}, {}, R.PASS),
    ("12.13", {"/zia/adminRoles": [{"id": 1}]}, {}, R.WARN),
]


@pytest.mark.parametrize("cid,routes,codes,want", ORACLE, ids=[f"{o[0]}-{i}" for i, o in enumerate(ORACLE)])
def test_check_oracle_table(cid, routes, codes, want):
    """ASVS V1.14.1 · A04:2021 · CWE-693 · WSTG-BUSL-01: each check's status matches the documented Zscaler best practice for a passing, failing and incomplete tenant."""
    assert _check(cid)(Fake(routes, codes=codes)).status == want


@pytest.mark.parametrize("cid,ep", [("4.1", "/zia/sslInspectionRules"), ("5.3", "/zia/webDlpRules"), ("6.3", "/zcc/devices"),
                                    ("12.2", "/zia/icapServers"), ("12.8", "/zia/nssFeeds"), ("2.3", "/zia/pacFiles")])
def test_check_oracle_denied_row(cid, ep):
    """ASVS V7.4.1 · CWE-755: the denied row of each oracle table is not permitted."""
    assert _cls(_check(cid)(Fake(codes={ep: 403}))) == "not_permitted"


# ── 4. scoring ───────────────────────────────────────────────────────

def _row(st, sec="S"):
    return {"id": "x", "sec": sec, "label": "l", "status": st, "detail": ""}


@pytest.mark.parametrize("statuses,score", [
    (["PASS", "PASS", "FAIL", "REVIEW"], 50),
    (["PASS", "INFO", "ERROR"], 100),
    (["FAIL", "INFO"], 0),
    (["INFO", "ERROR"], None),
    ([], None),
    (["PASS", "FAIL", "FAIL"], 33),
    (["PASS", "PASS", "FAIL"], 67),
])
def test_score_arithmetic_oracle(statuses, score):
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: score = pass ÷ (pass + fail + review), INFO/ERROR outside it, None when nothing is scoreable."""
    secs, overall = A.compute([_row(s) for s in statuses])
    assert overall == score
    assert permissions.assessment_summary([_row(s) for s in statuses])["score"] == score


def test_not_run_and_out_of_scope_results_never_count_as_passes():
    """ASVS V1.14.1 · CWE-682: a result marked out of scope, a malformed row or an unknown status adds no pass."""
    rows = [_row("FAIL"), dict(_row("PASS"), out_of_scope=True), None, "x", {"sec": "S"}, _row("pass"), _row(5)]
    secs, overall = A.compute(rows)
    assert overall == 0 and secs["S"]["pass"] == 0 and secs["S"]["total"] == 4


def test_section_percentages_and_counts():
    """ASVS V1.14.1 · CWE-682: per-section counts and percentages are exact; an all-INFO section is not measured."""
    secs, overall = A.compute([_row("PASS", "A"), _row("FAIL", "A"), _row("INFO", "B")])
    assert secs["A"] == {"total": 2, "pass": 1, "fail": 1, "warn": 0, "info": 0, "scored": 2, "pct": 50}
    assert secs["B"]["pct"] is None and overall == 50 and A.maturity(overall) == "Developing"


@pytest.mark.parametrize("p,label", [(None, "Not assessed"), (0, "Ad Hoc"), (24, "Ad Hoc"), (25, "Initial"), (50, "Developing"),
                                     (75, "Managed"), (89, "Managed"), (90, "Optimized"), (100, "Optimized")])
def test_maturity_boundaries(p, label):
    """ASVS V1.14.1 · CWE-682: maturity bands at their exact boundaries."""
    assert A.maturity(p) == label


def test_saved_results_from_an_older_version_still_score():
    """ASVS V1.14.1 · CWE-1357 (regression): a results list using "section" instead of "sec" still scores."""
    rows = [{"id": "1", "section": "Old", "status": "PASS"}, {"id": "2", "section": "Old", "status": "FAIL"}]
    secs, overall = A.compute(rows)
    assert overall == 50 and "Old" in secs


def test_refused_run_is_partial_and_not_scored_as_pass():
    """ASVS V7.4.1 · CWE-755: a run where every read is refused has no score and is "partial", never 100."""
    cl = AllCode(403)
    rows = [{"id": c, "sec": s, "label": l, "status": (r := fn(cl)).status, "detail": r.detail} for c, s, l, fn in OWN]
    cov = A.coverage(rows)
    assert cov["configured"] == 0 and cov["state"] == "partial" and cov["not_permitted"] > 100


# ── 5. scope ─────────────────────────────────────────────────────────

def test_alternative_channel_checks_are_hidden_not_run():
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: a check of a channel declared Alternative is hidden, not run."""
    checks = [("5.3", "5 — Endpoint DLP", "Web DLP rules", A.c_5_3), ("8.1", "8 — Pilot Tests", "USB", A.c_8_1)]
    import channel_scope
    declared = {cid: {"choice": "zscaler"} for cid in channel_scope.CHANNELS}
    declared["endpoint_dlp"] = {"choice": "alternative"}
    run, hidden, _ = dlp_analysis.assessment_checks(checks, declared, ["zia_extras"])
    assert [c[0] for c in run] == ["5.3"] and [h["id"] for h in hidden] == ["8.1"]


@pytest.mark.parametrize("ep,scopes,refused", [
    ("/zid/users", ["dlp"], True), ("raw:/ziam/admin/api/v1/users", ["dlp"], True), ("/zid/users", ["dlp", "zidentity"], False),
    ("/zcc/devices", ["dlp"], True), ("/zcc/devices", ["dlp", "zcc"], False), ("/zpa/idp", ["dlp"], True), ("/zia/webDlpRules", ["dlp"], False),
])
def test_analysis_client_refuses_services_outside_the_scope(ep, scopes, refused):
    """ASVS V4.1.3 · A01:2021 · CWE-284 · WSTG-ATHZ-02: a ZCC, ZPA, ZDX or ZIdentity read (/zid and /ziam too) is refused unless that scope is selected."""
    import channel_scope
    inner = Fake(default=200, routes={ep.replace("raw:", ""): []})
    sc = dlp_analysis.ScopedClient(inner, {cid: {"choice": "zscaler"} for cid in channel_scope.CHANNELS}, scopes)
    sc.get(ep)
    assert (inner.calls == []) is refused


# ── 6. escaping on every output ──────────────────────────────────────

EVIL = "[link=https://evil.example]x[/link] [bold red]PASS[/] \x1b]0;pwn\x07 =cmd|' /C calc'!A0 <script>alert(1)</script> | # H"


def test_terminal_text_strips_escapes_and_rich_markup():
    """ASVS V5.3.1 · A03:2021 · CWE-150 · WSTG-INPV-11: tenant text in the CLI report has no control characters and no live Rich markup."""
    t = A._term(EVIL)
    assert "\x1b" not in t and "\x07" not in t
    if A.HAS_RICH:
        from rich.text import Text
        assert Text.from_markup(t).plain == A._term(EVIL, markup=False)


def test_cli_report_prints_a_malicious_detail_inertly():
    """ASVS V5.3.1 · A03:2021 · CWE-74 · WSTG-INPV-11: report() never emits a tenant hyperlink or escape sequence."""
    if not A.HAS_RICH:
        pytest.skip("rich not installed")
    from rich.console import Console
    buf = io.StringIO()
    con = Console(file=buf, force_terminal=True, width=300)
    A.report([{"id": "1.1", "sec": EVIL, "label": EVIL, "status": "FAIL", "detail": EVIL}], {"org_name": EVIL}, con)
    out = buf.getvalue()
    assert "evil.example" in out and "\x1b]8;" not in out and "\x1b]0;" not in out


def test_plain_cli_report_strips_control_characters(capsys, monkeypatch):
    """ASVS V5.3.1 · CWE-150: the plain (no Rich) report prints no escape sequence from the tenant."""
    A.report([{"id": "1.1", "sec": "S", "label": EVIL, "status": "FAIL", "detail": EVIL}], {"org_name": EVIL}, None)
    assert "\x1b" not in capsys.readouterr().out


def test_required_controls_markdown_escapes_tenant_detail():
    """ASVS V5.3.1 · A03:2021 · CWE-79 · WSTG-CLNT-01: the required-controls Markdown renders tenant text inert."""
    md = "\n".join(dlp_analysis.markdown({"required_controls": [{"label": "URL", "status": "configured", "detail": EVIL}]}))
    assert "<script>" not in md and "[link=https://evil.example]" not in md


def _analysis(name):
    cl = Fake({"/zia/dlpDictionaries": [{"id": 1, "name": name, "custom": True, "phrases": [{"phrase": "secret"}]}],
               "/zia/dlpEngines": [{"id": 9, "name": name, "engineExpression": "((D1.S > 0))"}],
               "/zia/webDlpRules": [{"id": 3, "dlpEngines": [{"id": 9}]}]})
    return E.analyze(cl)


def test_efficacy_csv_neutralises_formula_injection():
    """ASVS V5.3.10 · A03:2021 · CWE-1236 · WSTG-INPV-11: a dictionary name starting with "=" is not a live formula in the CSV."""
    body = E.export_csv(_analysis("=HYPERLINK(\"http://evil\")")).decode()
    assert ",=HYPERLINK" not in body and "\n=HYPERLINK" not in body


def test_efficacy_markdown_escapes_tenant_names():
    """ASVS V5.3.1 · A03:2021 · CWE-79 · WSTG-CLNT-01: tenant names in the efficacy Markdown cannot inject HTML or table cells."""
    md = E.export_markdown(_analysis("<script>alert(1)</script> | x")).decode()
    assert "<script>" not in md and "</script> | x |" not in md


def test_efficacy_docx_accepts_xml_illegal_characters():
    """ASVS V5.3.1 · CWE-116: a control character in a tenant name does not break the Word export."""
    pytest.importorskip("docx")
    assert E.export_docx(_analysis("bad\x00\x0bname"))[:2] == b"PK"


# ── 7. efficacy correctness ──────────────────────────────────────────

@pytest.mark.parametrize("expr,ids", [
    ("((D63.S > 1))", [63]), ("((D63.S > 1) AND (D38.S > 0))", [63, 38]), ("D(123) AND D(456)", [123, 456]),
    ("((D63.S > 1) OR (D63.S > 3))", [63]), ("", []), (None, []), (5, []), ("AND OR NOT", []),
])
def test_engine_expression_oracle_matches_the_sdk_format(expr, ids):
    """ASVS V5.1.4 · CWE-1287 · WSTG-INPV-01: dictionary ids are read from the SDK's ((D63.S > 1)) form and the older D(63) form."""
    assert E._parse_engine_expression(expr) == ids


def test_dictionary_used_by_a_real_engine_expression_is_not_an_orphan():
    """ASVS V1.14.1 · CWE-697: a dictionary referenced as ((D1.S > 0)) by an engine a rule uses is not "unused" (regression)."""
    a = _analysis("PII")
    d = a["dictionaries"][0]
    assert d["orphan_engine"] is False and d["orphan_rule"] is False and a["orphans"]["dictionaries_unused_by_engines"] == []


def test_refused_rule_read_is_unknown_not_unused():
    """ASVS V7.4.1 · A04:2021 · CWE-755: when the Web DLP rules are refused, no engine is called unused and the error is reported."""
    cl = Fake({"/zia/dlpDictionaries": [], "/zia/dlpEngines": [{"id": 9, "name": "E", "engineExpression": "((D1.S > 0))"}]},
              codes={"/zia/webDlpRules": 403})
    a = E.analyze(cl)
    assert a["engines"][0]["orphan_rule"] is None and a["orphans"]["engines_unused_by_rules"] is None
    assert a["read_errors"] == [{"source": "/zia/webDlpRules", "http_status": 403, "reason": "Permission denied"}]
    assert "not readable" in E.export_markdown(a).decode()


def test_refused_dictionary_read_is_reported_not_empty():
    """ASVS V7.4.1 · CWE-755: a refused dictionary read is in read_errors, so an empty list is never shown as a clean tenant."""
    a = E.analyze(Fake({"/zia/dlpEngines": [], "/zia/webDlpRules": []}, codes={"/zia/dlpDictionaries": 403}))
    assert [e["source"] for e in a["read_errors"]] == ["/zia/dlpDictionaries"]


def test_efficacy_survives_messy_dictionaries_and_engines():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: numeric names, non-list phrases, non-object items and numeric expressions never raise."""
    cl = Fake({"/zia/dlpDictionaries": [None, 4, {"id": 1, "name": 7, "custom": True, "phrases": 5, "patterns": [{"pattern": 9}, 3]},
                                        {"id": "2", "name": None, "custom": True, "phrases": [{"phrase": 12}]}],
               "/zia/dlpEngines": [{"id": 9, "name": 11, "engineExpression": 5}, {"id": 8, "name": "b", "engineExpression": "((D1.S > 0))"}, "x"],
               "/zia/webDlpRules": [{"dlpEngines": "9"}, None]})
    a = E.analyze(cl)
    assert a["counts"]["dictionaries_total"] == 2 and a["counts"]["engines_total"] == 2
    assert E.export_markdown(a) and E.export_csv(a)


def test_efficacy_rules_out_of_scope_are_not_read():
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: with Inline Web DLP out of scope the Web DLP rules are never read."""
    cl = Fake({"/zia/dlpDictionaries": [], "/zia/dlpEngines": []})
    a = E.analyze(cl, read_rules=False)
    assert "/zia/webDlpRules" not in cl.calls and a["rules_not_in_scope"] == E.RULES_NOT_IN_SCOPE and a["read_errors"] == []


def test_fetch_error_hides_exception_text():
    """ASVS V7.1.1 · A09:2021 · CWE-209 · WSTG-ERRH-02: a failed read records the exception type, never its message (it may hold credentials)."""
    class Boom(Fake):
        def get(self, ep, *a, **k):
            raise RuntimeError("client_secret=hunter2")
    errors = []
    assert E._fetch(Boom(), "/zia/dlpEngines", errors) is None
    assert "hunter2" not in json.dumps(errors) and errors[0]["reason"] == "Read failed: RuntimeError"


# ── 8. files, configuration and paths ────────────────────────────────

@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_saved_report_is_owner_only(tmp_path):
    """ASVS V8.3.4 · A01:2021 · CWE-732 · WSTG-CONF-09: the JSON report is written 0600 even over a world-readable file."""
    path = tmp_path / "r.json"
    path.write_text("old")
    path.chmod(0o644)
    A.save([_row("PASS")], {"org_name": "o"}, str(path))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600 and json.loads(path.read_text())["score"] == 100


@pytest.mark.parametrize("org,want", [("../../etc/x", "zscaler_etc_x_T"), ("Acme Corp", "zscaler_Acme_Corp_T"), ("", "zscaler_T"),
                                      ("C:\\Windows\\", "zscaler_C_Windows_T"), ("ÜberCorp", "zscaler_berCorp_T"), (None, "zscaler_T")])
def test_report_basename_cannot_traverse(org, want):
    """ASVS V12.3.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: the default report name from an organisation name never contains a path."""
    assert A.report_basename(org, "T") == want


def test_config_file_size_is_capped(tmp_path):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: a configuration file over 64 KB is refused in plain words."""
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"client_id": "a", "client_secret": "b", "vanity_domain": "c", "pad": "x" * A.CONFIG_MAX_BYTES}))
    with pytest.raises(A.ConfigError, match="larger than"):
        A.load_config_file(str(p))


def test_config_file_deep_nesting_is_refused(tmp_path):
    """ASVS V5.1.4 · CWE-674 · WSTG-INPV-01: a deeply nested configuration file is a ConfigError, not a RecursionError."""
    p = tmp_path / "c.json"
    p.write_text("[" * 50_000 + "]" * 50_000)
    with pytest.raises(A.ConfigError):
        A.load_config_file(str(p))


def test_config_error_never_echoes_the_secret(tmp_path):
    """ASVS V7.1.1 · CWE-532: a configuration missing a field names the field, never the client secret."""
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"client_id": "a", "client_secret": "s3cr3t-value"}))
    with pytest.raises(A.ConfigError) as exc:
        A.load_config_file(str(p))
    assert "vanity_domain" in str(exc.value) and "s3cr3t-value" not in str(exc.value)


def test_config_file_not_utf8_is_refused(tmp_path):
    """ASVS V5.1.4 · CWE-20: a configuration that is not UTF-8 text is a plain ConfigError."""
    p = tmp_path / "c.json"
    p.write_bytes(b"\xff\xfe\x00{")
    with pytest.raises(A.ConfigError, match="UTF-8"):
        A.load_config_file(str(p))


# ── 9. the HTTP client: secrets never in errors, odd token answers ────

class _Resp:
    def __init__(self, code=200, body=None, text=""):
        self.status_code, self._body, self.text, self.headers = code, body, text, {}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError(f"HTTP {self.status_code}")


class _Sess:
    def __init__(self, get_exc=None, post=None):
        self.headers, self.cookies, self.get_exc, self._post = {}, {}, get_exc, post

    def get(self, *a, **k):
        raise self.get_exc

    def post(self, *a, **k):
        return self._post


def _client(monkeypatch, sess, cid):
    A._reset_tenant_gates()
    monkeypatch.setattr(A, "_sleep", lambda s: None)
    cl = A.Client(cid, "s3cr3t-Value!", "acme", "zscaler")
    cl.sess = sess
    cl.token, cl.exp = "t", float("inf")
    return cl


@pytest.mark.parametrize("exc", [RuntimeError("bad client_secret=s3cr3t-Value!"),
                                 __import__("requests").exceptions.ConnectionError("refused s3cr3t-Value!")])
def test_read_error_masks_the_client_secret(monkeypatch, exc):
    """ASVS V7.1.1 · A09:2021 · CWE-532 · WSTG-ERRH-02: an exception that echoes the client secret is masked in the read's error."""
    monkeypatch.setattr(A, "_nap", lambda *a, **k: True)
    cl = _client(monkeypatch, _Sess(get_exc=exc), "c6-mask-" + type(exc).__name__)
    d, code = cl.get("/zia/webDlpRules")
    assert code == 0 and "s3cr3t-Value!" not in json.dumps(d)


@pytest.mark.parametrize("raw,want", [({"expires_in": 1200}, 1200.0), ({"expires_in": "1200"}, 1200.0), ({}, 3600.0),
                                      ({"expires_in": "soon"}, 3600.0), ({"expires_in": None}, 3600.0),
                                      ({"expires_in": float("nan")}, 3600.0), ({"expires_in": 10**12}, 3600.0), ({"expires_in": 0}, 3600.0)])
def test_token_lifetime_oracle(raw, want):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: the token lifetime is read from a number or numeric text, else the OneAPI default."""
    assert A._expires_in(raw) == want


def test_sign_in_accepts_a_textual_token_lifetime(monkeypatch):
    """ASVS V5.1.4 · CWE-704: a token answer whose expires_in is text ("3600") signs in instead of failing."""
    cl = _client(monkeypatch, _Sess(post=_Resp(200, {"access_token": "tok", "expires_in": "3600"})), "c6-auth")
    cl.token = None
    assert cl.auth() is True and cl.sess.headers["Authorization"] == "Bearer tok"


def test_failed_sign_in_never_returns_the_secret(monkeypatch):
    """ASVS V7.1.1 · A07:2021 · CWE-209 · WSTG-ERRH-02: a refused sign-in answers a reason without the client secret."""
    cl = _client(monkeypatch, _Sess(post=_Resp(401, {}, "")), "c6-auth-fail")
    ok, reason = cl.auth()
    assert ok is False and "s3cr3t-Value!" not in reason


# ── 10. efficacy scoring oracles (hand-checked against the documented weights) ──

_P = lambda *w: [{"phrase": x} for x in w]  # noqa: E731
DICT_ORACLE = [
    # (dictionary, engine refs, rule-reachable, score, tp, fp band)
    ({"id": 1, "custom": True, "phrases": _P("secret")}, {1}, {1}, 85, 70, "Medium"),          # single phrase −15/−5
    ({"id": 1, "custom": True, "phrases": _P("secret")}, set(), set(), 55, 70, "Medium"),      # + unused by engines −30
    ({"id": 1, "custom": True, "phrases": _P("secret")}, {1}, set(), 75, 70, "Medium"),        # + unused by rules −10
    ({"id": 1, "custom": True, "phrases": _P("secret")}, {1}, None, 85, 70, "Medium"),         # rules not read: unknown
    ({"id": 1, "custom": True}, {1}, {1}, 10, 5, "Critical"),                                  # empty −90/−70, clamp 5
    ({"id": 1, "custom": True, "patterns": [{"pattern": "("}]}, {1}, {1}, 75, 60, "High"),      # invalid regex −25/−15
    ({"id": 1, "custom": True, "patterns": [{"pattern": ".*"}]}, {1}, {1}, 60, 20, "Critical"), # broad −40/−55
    ({"id": 1, "custom": True, "patterns": [{"pattern": r"\bA\d+\b"}, {"pattern": "^x"}]}, {1}, {1}, 100, 83, "Medium"),  # anchored +8
    ({"id": 1, "custom": True, "phrases": _P("ab", "the", "secret")}, {1}, {1}, 85, 45, "Critical"),  # tiny −15/−20, common −10
    ({"id": 1, "custom": True, "phrases": _P("a1", "b2"), "exactDataMatchDetails": [1]}, {1}, {1}, 85, 70, "Medium"),  # tiny −15/−20, EDM +15
    ({"id": 1, "custom": True, "phrases": _P("secret", "other"), "idmProfile": {"id": 1}, "minMatchCount": 3}, {1}, {1}, 100, 95, "Low"),
    ({"id": 1, "custom": True, "phrases": _P("secret", "other"), "minMatchCount": 2}, {1}, {1}, 100, 78, "Medium"),
    ({"id": 1, "custom": True, "phrases": _P(*[f"word{i}" for i in range(20)])}, {1}, {1}, 90, 65, "High"),  # lax −10/−10
    ({"id": 1, "dictionaryType": "PREDEFINED", "name": "SSN"}, set(), set(), 100, 92, "Low"),
]


@pytest.mark.parametrize("d,refs,reach,score,tp,band", DICT_ORACLE)
def test_dictionary_score_oracle(d, refs, reach, score, tp, band):
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: dictionary health, TP estimate and FP band follow the documented weights and clamps."""
    r = E._score_dictionary(d, refs, reach)
    assert (r["score"], r["tp_estimate"], r["fp_risk"]) == (score, tp, band)


_DICTS = {1: {"id": 1, "custom": True, "phrases": _P("secret")}, 2: {"id": 2, "custom": True},
          3: {"id": 3, "custom": True, "patterns": [{"pattern": ".*"}]}, 4: {"id": 4, "dictionaryType": "PREDEFINED"}}
ENGINE_ORACLE = [
    ("", {7}, 40, 15), ("", set(), 15, 15),
    ("((D1.S > 0) AND (D4.S > 0))", {7}, 100, 92), ("((D1.S > 0) AND (D4.S > 0))", None, 100, 92),
    ("((D1.S > 0) OR (D4.S > 0))", {7}, 90, 65), ("((D9.S > 0))", {7}, 70, 60),
    ("((D2.S > 0))", {7}, 80, 57), ("((D3.S > 0))", set(), 75, 63),
]


@pytest.mark.parametrize("expr,refs,score,tp", ENGINE_ORACLE)
def test_engine_score_oracle(expr, refs, score, tp):
    """ASVS V1.14.1 · CWE-682 · WSTG-BUSL-01: engine health and TP estimate for empty, AND, OR-only, broken, empty and weak references."""
    r = E._score_engine({"id": 7, "engineExpression": expr}, refs, _DICTS)
    assert (r["score"], r["tp_estimate"]) == (score, tp)


def test_predefined_engine_is_not_scored_down():
    """ASVS V1.14.1 · CWE-682: a predefined engine scores 100 even when no rule uses it."""
    assert E._score_engine({"id": 7, "predefinedEngineName": "HIPAA"}, set(), _DICTS)["score"] == 100


@pytest.mark.parametrize("fmt,mime", [("csv", "text/csv"), ("json", "application/json"), ("md", "text/markdown"), ("markdown", "text/markdown")])
def test_export_dispatch(fmt, mime):
    """ASVS V1.14.1 · CWE-20: every export format answers its media type."""
    body, got, name = E.export(_analysis("PII"), fmt)
    assert got == mime and body and name.startswith("dlp_efficacy.")


def test_export_unknown_format_is_refused():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an unknown export format is a ValueError (the API answers 400), never a guess."""
    with pytest.raises(ValueError):
        E.export({}, "exe")


# ── 11. corpus test: caps and untrusted input ─────────────────────────

def _corpus_client(dicts):
    return Fake({"/zia/dlpDictionaries": dicts, "/zia/dlpEngines": [], "/zia/webDlpRules": []})


def test_corpus_phrase_hits_are_counted_locally():
    """ASVS V1.14.1 · CWE-682: a custom dictionary's phrase is counted in the sample, case-insensitively."""
    r = E.corpus_test(_corpus_client([{"id": 1, "name": "D", "custom": True, "phrases": _P("Secret")}]), "a secret, SECRET, sec", read_rules=False)
    assert r["results"][0]["total_hits"] == 2 and r["results"][0]["simulated"] is True


@pytest.mark.parametrize("corpus,err", [(None, "corpus must be a string"), (5, "corpus must be a string"), ("   ", "corpus is empty"), ("", "corpus is empty")])
def test_corpus_rejects_non_text_and_empty(corpus, err):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a sample that is not text, or is empty, is refused in plain words before any read."""
    cl = _corpus_client([])
    assert E.corpus_test(cl, corpus)["error"] == err and cl.calls == []


def test_corpus_is_capped_at_256_kb():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-07: a sample over 256 KB is cut to the cap (multi-byte text stays valid)."""
    r = E.corpus_test(_corpus_client([]), "é" * 300_000, read_rules=False)
    assert r["corpus_length"] == E._CORPUS_CAP_BYTES // 2


def test_corpus_marks_malformed_dictionaries_unsupported():
    """ASVS V5.1.4 · CWE-20: a dictionary with non-list phrases or a broad regex is reported as not simulated, never as zero hits."""
    r = E.corpus_test(_corpus_client([{"id": 1, "name": "D", "custom": True, "phrases": "secret"},
                                      {"id": 2, "name": "B", "custom": True, "patterns": [{"pattern": ".*"}]}]), "secret", read_rules=False)
    assert all(x["total_hits"] is None and x["simulated"] is False for x in r["results"])


def test_corpus_refused_dictionary_read_is_an_error_not_empty():
    """ASVS V7.4.1 · CWE-755: a refused dictionary read is listed in errors with its HTTP status."""
    cl = Fake({"/zia/dlpEngines": []}, codes={"/zia/dlpDictionaries": 403})
    r = E.corpus_test(cl, "text", read_rules=False)
    assert r["errors"][0]["section"] == "dictionaries" and r["errors"][0]["http_status"] == 403


@pytest.mark.parametrize("payload,status,reason", [
    ({"list": [{"id": 1}], "totalCount": 5}, "unverified", "Incomplete collection; complete pagination was not established"),
    ({"list": [{"id": 1}], "hasMore": True}, "unverified", "Incomplete collection; complete pagination was not established"),
    ({"list": [{"id": 1}], "totalCount": "many"}, "unverified", "Incomplete collection; complete pagination was not established"),
    ([{"id": 1}, 3], "unverified", "Malformed collection response"),
    ({"x": 1}, "unverified", "Malformed collection response"),
    ([{"id": 1}], "verified", "Read successfully"),
    ([], "verified", "Successful empty response"),
])
def test_read_collection_oracle(payload, status, reason):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a partial, malformed or complete collection is labelled exactly; partial is never complete."""
    ev = E.read_collection(Fake({"/zia/x": payload}), "/zia/x")
    assert (ev["status"], ev["reason"]) == (status, reason)


def _iso_client(name, actions, cats):
    return Fake({"/zia/browserIsolation/profiles": [{"name": "P"}],
                 "/zia/urlFilteringRules": [{"name": name, "state": "ENABLED", "action": "ISOLATE", "urlCategories": cats}],
                 "/zia/cloudApplicationRules": [{"name": name, "state": "ENABLED", "actions": actions, "type": "AI_ML"}]})


def test_isolation_checks_accept_numeric_names_and_string_lists():
    """ASVS V5.1.4 · CWE-704 · WSTG-INPV-01: 3.7, A.17 and E.13 read a numeric rule name and a single action or category given as text."""
    cl = _iso_client(7, "ISOLATE_UPLOAD", "AI_ML_APPS")
    assert A.c_3_7(cl).status == R.PASS and "7" in A.c_3_7(cl).detail
    assert "AI_ML_APPS" in A.c_a17(cl).detail and A.c_e13(cl).status == R.PASS


def test_duplicate_ssl_rule_names_are_listed_in_a_stable_order():
    """ASVS V1.14.1 · CWE-1023: 4.6 lists duplicate names sorted, so the same tenant always gives the same finding."""
    rules = [{"name": n} for n in ("b", "a", "b", "a", 3, 3)]
    assert A.c_4_6(Fake({"/zia/sslInspectionRules": rules})).detail == "Duplicates: 3, a, b"


# ── 12. seeded fuzz: random field types never raise (deterministic: the seed is injected) ──

_FUZZ_KEYS = ["name", "state", "action", "actions", "type", "id", "urlCategories", "cloudApplications", "dlpEngines", "fileTypes",
              "fileTypeCategories", "description", "osType", "osVersion", "agentVersion", "status", "strictEnforcement", "phrases",
              "patterns", "custom", "engineExpression", "order", "predefined", "feedStatus", "nssLogType", "feedOutputFormat", "url",
              "dataTransferMethod", "eunEnabled", "receiver", "tenancyProfileIds", "dnsRuleRequestTypes", "customCategory",
              "enableZdpService", "active", "vpnGateways", "packetTunnelExcludeList", "enableInlineDlpOcr", "urls"]
_FUZZ_VALS = [None, 0, 1, 7.5, True, "", "x", "ENABLED", "DECRYPT", [], [None], [1, "a"], {}, {"type": None},
              {"id": None, "name": 3}, "((D1.S > 0))", [{"id": 1, "name": None}], {"decryptSubActions": {"minClientTLSVersion": 5}}]


@pytest.mark.parametrize("seed", [11, 12, 13])
def test_seeded_fuzz_never_raises_in_any_check(seed):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: 40 random tenants per seed (every field a random type) never raise in any check."""
    import random
    rnd = random.Random(seed)
    crashed = []
    for _ in range(40):
        recs = [{k: rnd.choice(_FUZZ_VALS) for k in rnd.sample(_FUZZ_KEYS, rnd.randint(1, 20))} for _ in range(rnd.randint(1, 3))]
        cl = AllCode(200, recs)
        for cid, _, _, fn in OWN:
            try:
                fn(cl)
            except Exception as exc:  # noqa: BLE001
                crashed.append((cid, repr(exc), recs))
    assert crashed == []


@pytest.mark.parametrize("cid,ep,rec", [
    ("E.1", "/zia/urlFilteringRules", {"state": "ENABLED", "urlCategories": True}),
    ("5.13", "/zia/webDlpRules", {"state": "ENABLED", "fileTypes": 5}),
    ("A.4", "/zia/webDlpRules", {"state": "ENABLED", "fileTypes": 5}),
])
def test_scalar_where_a_list_is_expected_does_not_raise(cid, ep, rec):
    """ASVS V5.1.4 · CWE-704: a bool or number in a list field (urlCategories, fileTypes) is read as no entries (regression of fuzz finds)."""
    assert _check(cid)(Fake({ep: [rec], "/zia/urlCategories": []}, default=404)).status in (R.PASS, R.WARN, R.INFO)


@pytest.mark.parametrize("seed", [21, 22])
def test_seeded_fuzz_never_raises_in_efficacy(seed):
    """ASVS V5.1.4 · A04:2021 · CWE-20 · WSTG-INPV-01: random dictionaries, engines and rules never raise in analyze() or its exports."""
    import random
    rnd = random.Random(seed)
    for _ in range(25):
        recs = [{k: rnd.choice(_FUZZ_VALS) for k in rnd.sample(_FUZZ_KEYS, rnd.randint(1, 20))} for _ in range(rnd.randint(1, 4))]
        a = E.analyze(Fake({"/zia/dlpDictionaries": recs, "/zia/dlpEngines": recs, "/zia/webDlpRules": recs}))
        assert E.export_csv(a) and E.export_markdown(a) and E.export_json(a)
