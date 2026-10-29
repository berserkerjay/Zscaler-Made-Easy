"""
Cloud wave 6 QA: traffic reports (bypass_report, ssl_coverage, ssl_flow,
insights, log_analyzer, detection_health).

Every test is offline: fakes and fixtures only, no tenant, no network, no
real clock (each time is injected). The first line of every docstring maps
the test to the standards it checks.
"""
from __future__ import annotations

import base64
import gzip
import io
import os
import re
import stat
import tarfile
import zipfile
from datetime import datetime, timedelta, timezone

import pytest

import bypass_report as br
import detection_health as dh
import insights
import log_analyzer as la
import ssl_coverage as sc
import ssl_flow as sf

NOW = datetime(2026, 10, 1, 12, 0, 0, tzinfo=timezone.utc)
NOW_MS = int(NOW.timestamp() * 1000)
DAY_MS = insights.DAY_MS


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def _zip(entries) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in entries:
            z.writestr(name, data)
    return buf.getvalue()


# ═══ log_analyzer: uploads are untrusted ════════════════════════════════
@pytest.mark.parametrize("line, secret", [
    ("Authorization: Bearer 3f9a8b7c6d5e4f3a2b1c", "3f9a8b7c6d5e4f3a2b1c"),
    ('{"password":"hunter2","user":"a"}', "hunter2"),
    ("POST /oauth access_token=abcdef123456&x=1", "abcdef123456"),
    ("refresh_token: zzz111yyy", "zzz111yyy"),
    ("id_token=QWERTY12345", "QWERTY12345"),
    ("Set JSESSIONID=ABCDEF1234 for the portal", "ABCDEF1234"),
    ("enrol with provisioning_key=PK123abcXYZ", "PK123abcXYZ"),
    ("Cookie: sid=abc123; zs_auth=def456", "def456"),
    ("proxy-authorization: Basic dXNlcjpwYXNz", "dXNlcjpwYXNz"),
])
def test_redact_hides_credentials_in_every_common_log_shape(line, secret):
    """ASVS V7.1.1 · A09:2021 · CWE-532 · WSTG-ERRH-01: a credential in an uploaded log line never reaches the evidence shown back."""
    out = la.redact(line)

    assert secret not in out and "redacted" in out


def test_redact_leaves_ordinary_log_text_alone():
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: lines with no credential are shown as they are (redaction is not a blanket wipe)."""
    line = "2026-09-01 08:00:04 ERR ZSATunnel: tunnel to gateway.zscalerthree.net dropped, reconnecting"

    assert la.redact(line) == line


def test_redact_of_a_long_hostile_line_is_linear():
    """ASVS V12.1.1 · CWE-1333 · WSTG-INPV-11: a 4 KB line of key-like words costs a linear scan, never a quadratic one."""
    import time
    line = ("a_" * 2040)[: la.MAX_LINE_CHARS]
    t0 = time.perf_counter()

    for _ in range(50):
        la.redact(line)

    assert time.perf_counter() - t0 < 1.0


def test_a_zip_with_thousands_of_entries_notes_the_member_cap_once(monkeypatch):
    """ASVS V12.1.1 · A04:2021 · CWE-400 · WSTG-BUSL-09: an archive past the member cap stops reading and says so once, not once per entry."""
    monkeypatch.setattr(la, "MAX_MEMBERS", 3)
    data = _zip([(f"f{i}.log", "2026-09-01 08:00:01 INF x\n") for i in range(400)])

    members, notes = la.expand([{"name": "many.zip", "content": _b64(data), "encoding": "base64"}])

    assert len(members) == 3
    assert sum("stopped after 3 files" in n for n in notes) == 1


def test_notes_about_skipped_members_are_capped(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-09: thousands of oversized members give a bounded list of notes ending in a count of the rest."""
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 10)
    data = _zip([(f"big{i}.log", "X" * 50) for i in range(300)])

    _members, notes = la.expand([{"name": "big.zip", "content": _b64(data), "encoding": "base64"}])

    assert len(notes) <= la.MAX_NOTES + 1
    assert re.search(r"and \d+ more", notes[-1])


def test_a_gzip_bomb_is_refused_without_inflating_past_the_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · WSTG-BUSL-09: a .gz that inflates past the per-member cap is skipped; nothing past the cap is read."""
    monkeypatch.setattr(la, "MAX_MEMBER_BYTES", 1024)
    bomb = gzip.compress(b"A" * 200_000)

    members, notes = la.expand([{"name": "ZSATray.log.gz", "content": _b64(bomb), "encoding": "base64"}])

    assert members == [] and any("larger than" in n for n in notes)


def test_a_tar_bomb_stops_at_the_total_cap(monkeypatch):
    """ASVS V12.1.1 · CWE-409 · WSTG-BUSL-09: a compressed tar is read as one stream that ends at the total cap."""
    monkeypatch.setattr(la, "MAX_TOTAL_BYTES", 4096)
    monkeypatch.setattr(la, "_TAR_SLACK", 0)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        for i in range(4):
            data = b"2026-09-01 08:00:01 INF x\n" * 200
            info = tarfile.TarInfo(f"f{i}.log")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))

    members, notes = la.expand([{"name": "b.tgz", "content": _b64(buf.getvalue()), "encoding": "base64"}])

    assert sum(len(d) for _, d in members) <= 4096
    assert any("stopped after" in n or "expands past" in n for n in notes)


def test_a_zip_member_name_is_never_a_path():
    """ASVS V12.3.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: a traversal or absolute member name is reduced to its last part and nothing is written."""
    data = _zip([("../../../../tmp/evil.log", "x\n"), ("/abs/C:\\Windows\\win.log", "y\n")])

    members, _ = la.expand([{"name": "../up.zip", "content": _b64(data), "encoding": "base64"}])

    assert [n for n, _ in members] == ["evil.log", "win.log"]


def test_a_huge_single_line_is_read_only_up_to_the_line_cap():
    """ASVS V12.1.1 · CWE-400 · CWE-1333 · WSTG-INPV-11: one multi-megabyte line is cut at MAX_LINE_CHARS before any pattern runs."""
    import time
    text = "2026-09-01 08:00:01 ERR " + "fail" * 500_000 + "\n"
    t0 = time.perf_counter()

    r = la.analyze_logs([("a.log", text)])

    assert time.perf_counter() - t0 < 1.5
    assert all(len(e["line"]) <= la.EVIDENCE_WIDTH for f in r["findings"] for e in f["evidence"])


def test_invalid_base64_is_a_plain_error_without_the_content():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a broken upload is refused in plain words that do not echo the upload back."""
    with pytest.raises(ValueError) as e:
        la.analyze([{"name": "x.zip", "content": "@@SECRETPAYLOAD@@=", "encoding": "base64"}])

    assert "base64" in str(e.value) and "SECRETPAYLOAD" not in str(e.value)


def test_counts_of_log_findings_add_up():
    """ASVS V5.1.3 · CWE-682 · WSTG-BUSL-01: a finding's count equals the sum of its per-file counts, and levels count each line once."""
    a = "2026-09-01 08:00:01 ERR ZSATunnel: request timed out\n" * 6
    b = "2026-09-01 08:00:02 ERR ZSATunnel: request timed out\n" * 3

    r = la.analyze_logs([("a.log", a), ("b.log", b)])

    t = next(f for f in r["findings"] if f["key"] == "timeouts")
    assert t["count"] == 9 == sum(x["count"] for x in t["files"])
    assert r["levels"] == {"error": 9}
    assert sum(f["lines"] for f in r["files"]) == 9


# ═══ detection_health: the FP/TP ratio, its math and its proposals ═════
def _dh_inc(iid, rule, *, days_ago=1, status="CLOSED", resolution="", closed_code="", user="a@example.com", url="https://chatgpt.com/x"):
    return {"internalId": iid, "createdAt": (NOW - timedelta(days=days_ago)).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "status": status, "resolution": resolution, "closedCode": closed_code, "severity": "HIGH", "sourceType": "WEB_DLP",
            "matchingPolicies": {"rules": [{"name": rule}], "engines": [{"name": "E"}], "dictionaries": [{"name": "SSN", "matchCount": 2}]},
            "applicationInfo": {"name": "ChatGPT", "url": url}, "userInfo": {"email": user, "department": "Sales"}}


class _Search:
    """Workflow Automation's dlp_incident_search (zscaler/zwa/dlp_incidents.py): page / page_size, time_range."""

    def __init__(self, incidents):
        self.incidents, self.calls = incidents, []

    def dlp_incident_search(self, query_params=None, fields=None, time_range=None, **kw):
        self.calls.append(dict(query_params or {}))
        page, size = int(query_params["page"]), int(query_params["page_size"])
        return {"incidents": self.incidents[(page - 1) * size: page * size]}, None, None


def _dh_client(incidents, *, forward=True):
    from test_pack_channels import make_client
    from test_pack_deploy import Obj
    c = make_client()
    c.zwa = type("ZWA", (), {"dlp_incidents": _Search(incidents)})()
    c.zia.dlp_web_rules.items = [
        Obj(id=7001, name="Busy-Rule", order=1, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5001}], description="",
            zscaler_incident_receiver=forward),
        Obj(id=7002, name="Quiet-Rule", order=2, action="ALLOW", state="ENABLED", dlp_engines=[{"id": 5001}], description="",
            zscaler_incident_receiver=forward)]
    return c


@pytest.mark.parametrize("settings, key", [
    ({"fp_window_days": "abc"}, "fp_window_days"),
    ({"fp_rate_pct": 250}, "fp_rate_pct"),
    ({"dead_days": True}, "dead_days"),
    ({"recent_limit": -1}, "recent_limit"),
    ({"not_real": "x"}, "not_real"),
])
def test_bad_threshold_overrides_fall_back_to_the_default_with_a_note(settings, key):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · CWE-755 · WSTG-INPV-01: an override that is not a whole number in range (or a list) is left at its default and said, never a 500."""
    rep = dh.generate(_dh_client([]), days=30, settings=settings, now=NOW)

    assert rep["settings"][key] == (min(dh.DEFAULTS[key], 30) if key.endswith("days") else dh.DEFAULTS[key])
    assert any(key in n for n in rep["settings_notes"])


def test_a_request_never_supplies_a_regular_expression():
    """ASVS V5.1.5 · A03:2021 · CWE-1333 · CWE-625 · WSTG-INPV-11: telemetry_patterns from a request are plain text: an unbalanced or catastrophic pattern neither crashes nor backtracks."""
    s, _ = dh.clean_settings({"telemetry_patterns": ["(", "(a+)+$", "/v9/beacon"]})

    assert not dh.looks_like_telemetry("aaaa", patterns=s["telemetry_patterns"])
    assert dh.looks_like_telemetry("cdn.(a+)+$.example", patterns=s["telemetry_patterns"])
    assert dh.looks_like_telemetry("app.example", ["/v9/beacon/1"], patterns=s["telemetry_patterns"])
    ev = dh.evaluate([], [], {"telemetry_patterns": ["("]}, now=NOW)
    assert ev["summary"]["incidents"] == 0


def test_the_not_real_override_decides_the_verdicts():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: a run given its own not-real resolutions counts by them, as the report says it did."""
    incs = [_dh_inc(f"i{i}", "Busy-Rule", resolution="Duplicate") for i in range(4)]

    rep = dh.generate(_dh_client(incs), days=30, settings={"not_real": ["duplicate"]}, now=NOW)

    assert rep["settings"]["not_real"] == ["duplicate"]
    assert rep["summary"]["not_real"] == 4 and rep["summary"]["real"] == 0 and rep["summary"]["fp_tp_ratio"] == "1:0"


def test_no_window_is_longer_than_the_incidents_read():
    """ASVS V11.1.1 · A04:2021 · CWE-841 · WSTG-BUSL-01: from 7 days of incidents no rule is called dead for 30 days, nor a 'Disable' proposal raised on it."""
    import proposals
    incs = [_dh_inc("i1", "Busy-Rule", days_ago=1)]

    rep = dh.generate(_dh_client(incs), days=7, now=NOW)

    quiet = next(r for r in rep["rules"] if r["name"] == "Quiet-Rule")
    assert rep["settings"]["dead_days"] == 7 and rep["settings"]["fp_window_days"] == 7 and rep["settings"]["promote_window_days"] == 7
    assert quiet["status"] == "dead" and "7 days" in quiet["why"]
    p = next(x for x in proposals.build_proposals(rep, "acme") if x["kind"] == "retire_rule")
    assert "7 days" in p["title"] and "30 days" not in p["title"]


def test_a_read_cut_at_the_page_cap_calls_no_rule_dead(monkeypatch):
    """ASVS V11.1.1 · A04:2021 · CWE-841 · WSTG-BUSL-01: when the incident search stops at MAX_PAGES the report says so and no rule is called dead."""
    import proposals
    monkeypatch.setattr(dh, "PAGE_SIZE", 2)
    incs = [_dh_inc(f"i{i}", "Busy-Rule") for i in range(2 * dh.MAX_PAGES + 3)]

    rep = dh.generate(_dh_client(incs), days=30, now=NOW)

    assert rep["incident_count"] == 2 * dh.MAX_PAGES
    assert any("Only the first 100 incidents" in e for e in rep["errors"])
    assert rep["summary"]["dead_rules"] == 0 and not [f for f in rep["findings"] if f["kind"] == "dead_rule"]
    assert not [p for p in proposals.build_proposals(rep, "acme") if p["kind"] == "retire_rule"]


def test_pagination_stops_at_a_short_page_and_reads_each_page_once():
    """ASVS V11.1.1 · CWE-835 · WSTG-BUSL-01: 250 incidents are three pages (100, 100, 50), each asked once, nothing counted twice."""
    c = _dh_client([_dh_inc(f"i{i}", "Busy-Rule") for i in range(250)])

    out, errors = dh.fetch_incidents(c, 30, now=NOW)

    assert len(out) == 250 == len({i["id"] for i in out}) and errors == []
    assert [x["page"] for x in c.zwa.dlp_incidents.calls] == [1, 2, 3]


def test_a_rule_that_forwards_no_incident_is_not_called_dead():
    """ASVS V11.1.1 · A04:2021 · CWE-841 · WSTG-BUSL-01: a Web DLP rule without an Incident Receiver cannot have incidents, so no 'Disable' proposal is raised on it."""
    import proposals
    rep = dh.generate(_dh_client([], forward=False), days=30, now=NOW)

    st = {r["name"]: r["status"] for r in rep["rules"]}
    assert st["Quiet-Rule"] == "not_measured" and st["Busy-Rule"] == "not_measured"
    assert rep["summary"]["dead_rules"] == 0
    assert not [p for p in proposals.build_proposals(rep, "acme") if p["kind"] == "retire_rule"]
    assert any(f["kind"] == "no_incident_delivery" for f in rep["findings"])


def test_the_unknown_user_row_is_not_counted_as_a_user():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: summary users and destinations count distinct known ones; the '(unknown …)' rows gather the rest."""
    incs = [dh.normalize_incident(_dh_inc("a", "R", user="u1@example.com"), dh.DEFAULTS["not_real"]),
            dh.normalize_incident(_dh_inc("b", "R", user="", url=""), dh.DEFAULTS["not_real"])]
    incs[1]["application"] = ""

    s = dh.evaluate(incs, [], now=NOW)["summary"]

    assert s["users"] == 1 and s["destinations"] == 1


# Oracle: (status, resolution, closed code) → real? (Workflow Automation verdicts)
@pytest.mark.parametrize("status, resolution, code, expected", [
    ("CLOSED", "False Positive", "", False),
    ("CLOSED", "", "FALSE_POSITIVE", False),
    ("RESOLVED", "Business-Justified", "", False),
    ("CLOSED", "Confirmed", "", True),
    ("CLOSED", "", "TRUE_POSITIVE", True),
    ("OPEN", "", "", None),
    ("IN_PROGRESS", "", "", None),
    ("", None, None, None),
])
def test_verdicts_follow_the_oracle_table(status, resolution, code, expected):
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: closed-as-not-real, closed-as-real and open map to False, True and None."""
    assert dh.verdict(status, resolution, code, dh.DEFAULTS["not_real"]) is expected


def test_counts_and_percentages_add_up_over_a_generated_corpus():
    """ASVS V11.1.1 · CWE-682 · CWE-190 · WSTG-BUSL-01: incidents = open + closed, closed = real + not real, channels sum to incidents, every % is 0..100, nothing counted twice."""
    import random
    rnd = random.Random(1234)
    picks = [("CLOSED", "False Positive"), ("CLOSED", "Confirmed"), ("OPEN", ""), ("CLOSED", "Benign")]
    incs = []
    for i in range(300):
        st, res = rnd.choice(picks)
        incs.append(dh.normalize_incident(_dh_inc(f"i{i}", rnd.choice(["A", "B", "C"]), days_ago=rnd.randint(0, 29), status=st, resolution=res,
                                                  user=f"u{rnd.randint(0, 9)}@example.com"), dh.DEFAULTS["not_real"]))

    ev = dh.evaluate(incs, [], now=NOW)

    s = ev["summary"]
    assert s["incidents"] == 300 == s["open"] + s["closed"] and s["closed"] == s["real"] + s["not_real"]
    assert sum(s["channels"].values()) == 300 and sum(r["incidents"] for r in ev["rules"]) == 300
    assert sum(u["incidents"] for u in ev["users"]) == 300
    pcts = [s["fp_rate_pct"], s["fp_share_pct"]] + [r["fp_rate_pct"] for r in ev["rules"]] + [d["fp_rate_pct"] for d in ev["dictionaries"]]
    assert all(p is None or 0 <= p <= 100 for p in pcts)
    fp, tp = (int(x) for x in s["fp_tp_ratio"].split(":"))
    assert fp * s["real"] == tp * s["not_real"]


def test_the_ratio_is_in_lowest_terms_and_a_dash_when_nothing_is_closed():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: FP:TP is reduced (6:4 → 3:2, 0:4 → 0:1, 4:0 → 1:0) and '–' with no verdict."""
    assert [dh._ratio(*x) for x in ((6, 4), (0, 4), (4, 0), (0, 0), (7, 7))] == ["3:2", "0:1", "1:0", "–", "1:1"]


def test_proposal_apply_is_refused_without_the_write_gates(monkeypatch):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · CWE-285 · WSTG-ATHZ-02: applying a Detection Health proposal without write mode is refused before any tenant client is built."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1))
    monkeypatch.delenv("DLP_CHECK_WRITE_MODE", raising=False)

    r = TestClient(srv.app).post("/api/proposals/acme/p1/apply", json={"vanity_domain": "acme", "client_id": "x", "client_secret": "y", "confirm": True})

    assert r.status_code in (400, 401, 403) and built == []


# ═══ bypass_report: the inventory of what skips inspection ═════════════
class _Get:
    """sdk_client.Client stand-in: .get(endpoint) → (data, status)."""

    def __init__(self, answers, default=([], 200)):
        self.answers, self.default, self.asked = answers, default, []

    def get(self, endpoint):
        self.asked.append(endpoint)
        return self.answers.get(endpoint, self.default)


HOSTILE = "evil`](javascript:alert(1))\n# Forged heading <img src=x onerror=alert(1)>"


def test_category_expansion_detail_in_markdown_is_inert():
    """ASVS V5.3.3 · A03:2021 · CWE-1236 · CWE-79 · WSTG-CLNT-01: tenant category names, rule names, URLs and keywords cannot add a heading, link or tag to the Markdown export."""
    rules = [{"id": 1, "name": HOSTILE, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["CUSTOM_01"]}]
    cats = [{"id": "CUSTOM_01", "configuredName": HOSTILE, "customCategory": True, "urls": [HOSTILE], "keywords": [HOSTILE]}]
    c = _Get({"/zia/sslInspectionRules": (rules, 200), "/zia/urlCategories": (cats, 200), "/zia/advancedSettings": ({}, 200)})

    md = br.to_markdown(br.generate_bypass_report(c))

    detail = md.split("## URL Category Expansion Detail", 1)[1]
    prose = re.sub(r"(`+).+?\1", "", detail)   # text outside code spans is what a viewer renders as Markdown
    assert "<img" not in prose and "](javascript:" not in prose.replace("\\]", "")
    assert "\n# Forged" not in detail


def test_a_switch_in_advanced_settings_is_not_an_exemption():
    """ASVS V11.1.1 · CWE-682 · CWE-843 · WSTG-BUSL-01: enableEvaluatePolicyOnGlobalSSLBypass=false is a setting, not a bypassed URL, and is not counted."""
    adv = {"enableEvaluatePolicyOnGlobalSSLBypass": False, "authBypassUrls": ["login.example.com"], "kerberosBypassUrlCategories": []}
    c = _Get({"/zia/advancedSettings": (adv, 200)})

    rep = br.generate_bypass_report(c)

    assert [i["value"] for i in rep["sections"]["ssl_exemptions"]["items"]] == ["login.example.com"]
    assert rep["summary"]["ssl_exemptions"] == 1
    assert "False" not in [u["value"] for u in rep["aggregated"]["urls"]["items"]]


@pytest.mark.parametrize("endpoint, section", [
    ("/zia/sslInspectionRules", "ssl_bypass_rules"), ("/zia/urlFilteringRules", "url_filter_allow"),
    ("/zia/firewallFilteringRules", "firewall_allow"), ("/zia/webDlpRules", "dlp_allow"), ("/zia/advancedSettings", "ssl_exemptions")])
def test_an_unreadable_section_is_could_not_be_read_not_zero_bypasses(endpoint, section):
    """ASVS V7.4.1 · A04:2021 · CWE-754 · CWE-636 · WSTG-ERRH-01: a 403 on a rule list is a diagnostic and an unverified section, never a clean 'no bypass'."""
    c = _Get({endpoint: ({"message": "forbidden"}, 403)})

    rep = br.generate_bypass_report(c)

    assert rep["sections"][section]["status"] == "unverified"
    assert any(d["section"] == section and "403" in d["error"] for d in rep["diagnostics"])


def test_an_endpoint_the_tenant_does_not_have_is_empty_not_an_error():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: a 404 (the API is not on this tenant) is no rules of that kind, with its status kept (boundary of the case above)."""
    c = _Get({"/zia/firewallFilteringRules": ({"error": "not found"}, 404)})

    rep = br.generate_bypass_report(c)

    sec = rep["sections"]["firewall_allow"]
    assert sec["count"] == 0 and sec["http_status"] == 404 and "status" not in sec
    assert not [d for d in rep["diagnostics"] if d["section"] == "firewall_allow"]


def test_no_client_connector_endpoint_answering_is_a_diagnostic():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: when no ZCC endpoint answers 200 the ZCC section is unverified and says why."""
    c = _Get({ep: ({}, 401) for ep in ("/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/trustedNetworks", "/zcc/webAppService")})

    rep = br.generate_bypass_report(c)

    assert rep["sections"]["zcc"]["status"] == "unverified"
    assert any(d["section"] == "zcc" and "401" in d["error"] for d in rep["diagnostics"])


def test_bypass_totals_equal_the_sum_of_their_parts():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: total_bypass_items is the sum of the ten section counts, and each count matches its items."""
    ssl = [{"id": i, "name": f"S{i}", "action": {"type": "DO_NOT_DECRYPT"}, "urls": [f"s{i}.example"]} for i in range(3)] + \
          [{"id": 9, "name": "Decrypt", "action": {"type": "DECRYPT"}}]
    url = [{"id": 20, "name": "U", "action": "ALLOW", "urls": ["a.example", "b.example"]}, {"id": 21, "name": "B", "action": "BLOCK"}]
    zcc = [{"id": 1, "name": "P", "bypassApps": [{"name": "Zoom"}], "bypassDomains": ["x.example", "y.example"]}]
    c = _Get({"/zia/sslInspectionRules": (ssl, 200), "/zia/urlFilteringRules": (url, 200), "/zcc/webPolicies": (zcc, 200)})

    rep = br.generate_bypass_report(c)

    s = rep["summary"]
    parts = [k for k in s if k != "total_bypass_items"]
    assert len(parts) == 10 and s["total_bypass_items"] == sum(s[k] for k in parts)
    assert s["ssl_bypass_rules"] == 3 == len(rep["sections"]["ssl_bypass_rules"]["items"]) and s["url_filter_allow"] == 1
    assert s["zcc_apps"] == 1 and s["zcc_domains"] == 2
    allu = {u["value"]: u for u in rep["aggregated"]["all_urls_bypassed"]["items"]}
    assert set(allu) == {"s0.example", "s1.example", "s2.example", "a.example", "b.example", "x.example", "y.example"}
    assert all(u["count"] == 1 for u in allu.values())


def test_the_bypass_report_reads_nothing_out_of_scope():
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: with only ZCC in scope no ZIA endpoint is asked, and nothing in scope is refused."""
    c = _Get({})

    rep = br.generate_bypass_report(c, {"read": ["zcc"], "not_in_scope": {"ssl": "no"}})

    assert all(ep.startswith("/zcc/") for ep in c.asked)
    assert rep["sections"]["ssl_bypass_rules"]["not_in_scope"] == "no"
    with pytest.raises(ValueError):
        br.generate_bypass_report(c, {"read": []})


# ═══ ssl_flow: what is decrypted, and the counts ════════════════════════
@pytest.mark.parametrize("rid, order", [("abc", 1), (None, "first"), (True, ""), (3, float("inf"))])
def test_tenant_ids_and_orders_that_are_not_numbers_never_stop_the_report(rid, order):
    """ASVS V5.1.3 · CWE-20 · CWE-755 · WSTG-INPV-01: a rule id or order sent as text, a bool or an infinity is sorted last, never a crash."""
    ssl = [{"id": rid, "name": "Odd", "order": order, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["FILE_HOST"]},
           {"id": 7, "name": "Decrypt all", "order": 2, "action": {"type": "DECRYPT"}}]
    dlp = [{"id": rid, "name": "D", "order": order, "action": "BLOCK"}]

    rep = sf.analyse(ssl, dlp)

    assert [r["name"] for r in rep["ssl_rules"]][-1] in ("Odd", "Decrypt all")
    assert rep["summary"]["ssl_rules"] == 2


def test_gap_severities_add_up_to_the_gap_total():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: high + medium + low + info == gaps, and class decisions add up to the classes."""
    ssl = [{"id": 1, "name": "Privacy", "order": 1, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["FINANCE"]},
           {"id": 2, "name": "No AI", "order": 2, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["AI_ML_APPS"]},
           {"id": 3, "name": "Decrypt off", "order": 3, "state": "DISABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["AI_ML_APPS"]}]

    s = sf.analyse(ssl, [])["summary"]

    assert s["info"] >= 1 and s["high"] + s["medium"] + s["low"] + s["info"] == s["gaps"]
    assert s["inspected"] + s["not_inspected"] + s["blocked"] + s["unknown"] == s["classes"] == len(sf.TRAFFIC_CLASSES)


# ═══ ssl_coverage: the protocol mapping and the percentages ════════════
# Oracle: Z-Insights WEB_TRAFFIC.protocols name → bucket (assumed: the SDK does not document the names).
@pytest.mark.parametrize("name, bucket, known", [
    ("HTTPS", "ssl_inspected", True), ("https", "ssl_inspected", True), ("SSL", "ssl_not_inspected", True),
    ("Tunnel SSL", "ssl_not_inspected", True), ("tunnel-ssl", "ssl_not_inspected", True), ("HTTP", "http", True),
    ("HTTP Proxy", "http", True), ("TUNNEL", "other", True), ("FTP over HTTP", "other", True), ("NATIVE_FTP", "other", True),
    ("QUIC", "other", False), ("HTTP2", "other", False), ("ＨＴＴＰＳ", "other", False), ("", "other", False), (None, "other", False),
    ("HTTPS‮", "other", False),
])
def test_protocol_names_follow_the_oracle_and_unknown_ones_are_never_guessed(name, bucket, known):
    """ASVS V11.1.1 · CWE-1287 · WSTG-BUSL-01: each known protocol name lands in its bucket; an unknown one is 'other, not recognised', never SSL or HTTP."""
    assert sc.bucket_of(name) == (bucket, known)


def test_an_unrecognised_protocol_is_listed_and_kept_out_of_every_percentage():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: unrecognised volume is listed by name, totalled apart, and in no inspected share."""
    rows = [{"name": "HTTPS", "total": 60}, {"name": "SSL", "total": 20}, {"name": "HTTP", "total": 20}, {"name": "QUIC", "total": 900},
            {"name": "TUNNEL", "total": 100}]

    sp = sc.protocol_split(rows)

    assert sp["unrecognised"] == [{"name": "QUIC", "total": 900.0}] and sp["unrecognised_total"] == 900.0
    assert sp["other_total"] == 1000.0 and sp["ssl_pct"] == 75.0 and sp["total_pct"] == 80.0
    assert sp["total_pct_if_other_not_inspected"] == 7.3
    assert sum(sp["buckets"].values()) == sum(r["total"] for r in rows)


@pytest.mark.parametrize("bad", [True, False, "x", None, float("nan"), float("inf"), -5, [1]])
def test_a_total_that_is_not_a_volume_is_skipped(bad):
    """ASVS V5.1.3 · CWE-20 · CWE-1287 · WSTG-INPV-01: a boolean, text, NaN, infinity or negative total adds nothing to any bucket."""
    sp = sc.protocol_split([{"name": "HTTPS", "total": bad}, {"name": "SSL", "total": 10}])

    assert sp["buckets"]["ssl_inspected"] == 0 and sp["ssl_pct"] == 0.0 and len(sp["by_name"]) == 1


def test_inspected_shares_stay_between_0_and_100_over_a_generated_corpus():
    """ASVS V11.1.1 · CWE-682 · CWE-190 · WSTG-BUSL-01: 500 seeded protocol tables give every share in 0..100 or None, and buckets that sum to the rows."""
    import random
    rnd = random.Random(42)
    names = list(sc.PROTOCOL_BUCKETS) + ["QUIC", "WEIRD", ""]
    for _ in range(500):
        rows = [{"name": rnd.choice(names), "total": rnd.choice([0, 1, rnd.randint(0, 10 ** 12)])} for _ in range(rnd.randint(0, 8))]
        sp = sc.protocol_split(rows)
        for k in ("ssl_pct", "http_pct", "total_pct", "total_pct_if_other_not_inspected"):
            assert sp[k] is None or 0.0 <= sp[k] <= 100.0, (k, rows)
        assert sum(sp["buckets"].values()) == sum(float(r["total"]) for r in rows)


def test_nothing_to_divide_is_none_never_a_made_up_percentage():
    """ASVS V11.1.1 · CWE-369 · WSTG-BUSL-01: no SSL or HTTP traffic gives None shares, not 0% or 100%."""
    sp = sc.protocol_split([{"name": "TUNNEL", "total": 5}])

    assert sp["ssl_pct"] is None and sp["total_pct"] is None and sp["http_pct"] is None


def test_cause_counts_add_up_by_risk_and_kind():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: causes by risk and by kind each sum to the causes, and covered + blind classes to the known ones."""
    ssl = [{"id": 1, "name": "No AI", "order": 1, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["AI_ML_APPS"]},
           {"id": 2, "name": "Banks", "order": 2, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["FINANCE"]},
           {"id": 3, "name": "Default", "order": 9, "defaultRule": True, "action": {"type": "DO_NOT_DECRYPT"}}]
    cc = {"app_profiles": [{"name": "P", "bypass": {"domains": ["dropbox.com", "intranet.corp"], "vpn_gateways": ["vpn.example"]}}],
          "forwarding_profiles": [{"id": 1, "name": "F", "actions": {"off": {"mode_kind": "none"}}}], "pac_files": []}

    rep = sc.analyse(ssl, cc=cc)

    s = rep["summary"]
    assert sum(s["by_risk"].values()) == s["causes"] == sum(s["by_kind"].values()) == len(rep["causes"])
    assert s["classes_covered"] + s["classes_not_inspected"] == s["classes_total"]
    assert s["class_coverage_pct"] is None or 0 <= s["class_coverage_pct"] <= 100


def test_the_history_file_is_owner_only_and_names_no_login(tmp_path, monkeypatch):
    """ASVS V8.3.4 · A01:2021 · CWE-276 · CWE-732 · WSTG-CONF-09: the run history is written 0600, atomically, and keyed by a record label."""
    p = str(tmp_path / "h" / "ssl_coverage_history.json")
    rep = {"summary": {"causes": 2, "by_risk": {"high": 1}, "class_coverage_pct": 50.0}, "plan": {"steps": [1]}}

    hist = sc.record("acme.zscalerthree.net", rep, path=p)

    assert len(hist) == 1 and hist[0]["causes"] == 2
    if os.name == "posix":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    assert [f for f in os.listdir(os.path.dirname(p)) if f.endswith(".tmp")] == []
    assert sc.load_history("acme.zscalerthree.net", path=p) == hist


def test_a_damaged_history_file_is_no_history():
    """ASVS V5.1.3 · CWE-502 · CWE-20 · WSTG-INPV-01: a history file that is not the expected JSON reads as empty, never a crash."""
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "h.json")
        for body in ("{", "[]", '{"tenants": []}', '{"tenants": {"t": "x"}}', '{"tenants": {"t": [1, {"at": "x"}]}}'):
            with open(p, "w", encoding="utf-8") as f:
                f.write(body)

            out = sc.load_history("t", path=p)

            assert out in ([], [{"at": "x"}])


class _Zins:
    """client.zins stand-in: each query returns the SDK's (entries, response, error) tuple."""

    def __init__(self, protocols=None, fail=None):
        outer = self
        self.calls = []
        self.fail = fail or {}

        def answer(name, entries):
            outer.calls.append(name)
            if name in outer.fail:
                return None, None, RuntimeError(outer.fail[name])
            return entries, None, None

        class WT:
            def get_protocols(self, **kw):
                outer.calls.append(("protocols", kw))
                return answer("protocols", protocols or [{"name": "HTTPS", "total": 3}, {"name": "SSL", "total": 1}])

            def get_no_grouping(self, **kw):
                return answer("no_grouping", [{"name": "all", "total": 9, "trend": {"trend_start_time": NOW_MS - DAY_MS, "trend_values": [4, 5]}}])

        class SI:
            def get_apps(self, **kw):
                return answer("apps", [{"application": "Dropbox", "data_consumed": 10}])

        self.web_traffic, self.shadow_it = WT(), SI()


def test_the_volume_read_is_paced_between_queries_never_before_the_first():
    """ASVS V11.1.4 · A04:2021 · CWE-770 · WSTG-BUSL-05: four Insights queries are separated by three pauses of PACE_SECONDS, the first is asked at once."""
    waits = []

    out = sc.read_volume(_Zins(), "7d", log=lambda m: None, now_ms=NOW_MS, sleep=waits.append)

    assert out["queries"] == 4 and waits == [insights.PACE_SECONDS] * 3
    assert out["status"] == "ok" and out["protocols"]["BYTES"]["ssl_pct"] == 75.0
    assert out["window"]["end_ms"] == NOW_MS and out["daily"] == [{"day_ms": NOW_MS - DAY_MS, "total": 4.0}, {"day_ms": NOW_MS, "total": 5.0}]


def test_one_failing_volume_query_is_partial_and_scrubbed():
    """ASVS V7.4.1 · CWE-209 · CWE-532 · WSTG-ERRH-01: a failed query is said (scrubbed), the others are kept, and the read is partial."""
    z = _Zins(fail={"apps": "boom token=SECRETVALUE"})

    out = sc.read_volume(z, "30d", log=lambda m: None, now_ms=NOW_MS, pace=0, scrub=lambda s: s.replace("SECRETVALUE", "[x]"))

    assert out["status"] == "partial" and out["apps"] == [] and out["protocols"]["TRANSACTIONS"]
    assert "SECRETVALUE" not in str(out) and any("Shadow IT" in e for e in out["errors"])


# ═══ insights: windows, queries, errors, the rate limit ════════════════
@pytest.mark.parametrize("start, end, ok", [
    (NOW_MS - insights.MIN_WINDOW_MS, NOW_MS, True),
    (NOW_MS - insights.MIN_WINDOW_MS + 1, NOW_MS, False),
    (NOW_MS - insights.MAX_WINDOW_DAYS * DAY_MS, NOW_MS, True),
    (NOW_MS - insights.MAX_WINDOW_DAYS * DAY_MS - 1, NOW_MS, False),
    (NOW_MS - insights.MAX_LOOKBACK_DAYS * DAY_MS, NOW_MS - insights.MAX_LOOKBACK_DAYS * DAY_MS + DAY_MS, True),
    (NOW_MS - insights.MAX_LOOKBACK_DAYS * DAY_MS - 1, NOW_MS - 100 * DAY_MS, False),
    (NOW_MS - DAY_MS, NOW_MS + insights.FUTURE_SKEW_MS, True),
    (NOW_MS - DAY_MS, NOW_MS + insights.FUTURE_SKEW_MS + 1, False),
    (float("inf"), NOW_MS, False), (NOW_MS - DAY_MS, float("-inf"), False), (float("nan"), NOW_MS, False),
    ("1700000000000", NOW_MS, False), (True, NOW_MS, False), (NOW_MS - DAY_MS + 0.5, NOW_MS, False), (0, NOW_MS, False),
])
def test_time_windows_follow_their_boundaries(start, end, ok):
    """ASVS V5.1.4 · CWE-20 · CWE-1284 · WSTG-INPV-01: each window boundary is accepted or refused exactly, and a non-number is a WindowError, never a crash."""
    if ok:
        assert insights.validate_window(start, end, NOW_MS) == (int(start), int(end))
    else:
        with pytest.raises(insights.WindowError):
            insights.validate_window(start, end, NOW_MS)


def test_query_inputs_are_typed_values_never_query_text():
    """ASVS V5.3.4 · A03:2021 · CWE-943 · WSTG-INPV-05: a traffic unit carrying GraphQL is refused before anything is asked; asked values are ints and enums."""
    z = _Zins()
    with pytest.raises(insights.WindowError):
        insights.read(z, NOW_MS - DAY_MS, NOW_MS, traffic_unit='BYTES) { __schema { types { name } } } #', pace=0, now_ms=NOW_MS)
    assert z.calls == []


def test_a_rate_limited_section_says_to_wait_and_try_again():
    """ASVS V11.1.4 · CWE-770 · WSTG-BUSL-05: a 429 or a rate-limit message gets a plain hint; other errors do not."""
    assert "rate limit" in insights._hint({"error": "HTTP 429 Too Many Requests", "classification": None})
    assert "rate limit" in insights._hint({"error": "x", "classification": "TOO_MANY_REQUESTS"})
    assert insights._hint({"error": "HTTP 500 server error", "classification": None}) is None


def test_insights_read_uses_the_injected_clock():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: read() checks the window against the clock it is given, so a window valid then is read."""
    class Z:
        def __getattr__(self, name):
            return self

        def __call__(self, **kw):
            return [], None, None
    z = Z()

    out = insights.read(z, NOW_MS - DAY_MS, NOW_MS, pace=0, now_ms=NOW_MS)

    assert out["window"] == {"start_ms": NOW_MS - DAY_MS, "end_ms": NOW_MS, "days": 1.0} and out["queries"] == 9


# ═══ pass 2: facts, verdicts, the live cursor, every export ═══════════
def test_the_last_tunnel_state_is_the_last_one_in_a_long_log():
    """ASVS V11.1.1 · CWE-682 · WSTG-BUSL-01: after more than 400 state changes the reported state is the latest, not the 400th."""
    lines = [f"2026-09-01 08:00:{i % 60:02d} INF ZSATunnel: Tunnel state changed to TUNNEL_STATE_CONNECTING" for i in range(450)]
    lines.append("2026-09-01 08:59:59 INF ZSATunnel: Tunnel state changed to TUNNEL_STATE_ZERO_TRUST_ON")

    r = la.analyze_logs([("t.log", "\n".join(lines))])

    assert r["facts"]["last_tunnel_state"] == "TUNNEL_STATE_ZERO_TRUST_ON"


def test_a_pac_with_a_low_finding_is_not_said_to_pass_every_check():
    """ASVS V11.1.1 · CWE-684 · WSTG-BUSL-01: the one-line verdict never contradicts the findings listed below it."""
    pac = 'function FindProxyForURL(url, host) {\n  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";\n}\n'

    r = la.analyze([{"name": "proxy.pac", "content": pac}])

    assert any(f["severity"] == "low" for f in r["pac"][0]["findings"])
    assert "passes every check" not in r["verdict"]["headline"]


def test_a_clean_pac_still_passes_every_check():
    """ASVS V11.1.1 · CWE-684 · WSTG-BUSL-01: a PAC with only informational findings keeps the calm verdict (negative case of the above)."""
    pac = ('function FindProxyForURL(url, host) {\n  if (isPlainHostName(host) || isInNet(dnsResolve(host), "10.0.0.0", "255.0.0.0")) return "DIRECT";\n'
           '  return "PROXY ${GATEWAY}:80; PROXY ${SECONDARY_GATEWAY}:80";\n}\n')

    r = la.analyze([{"name": "proxy.pac", "content": pac}])

    assert r["verdict"]["level"] == "ok"


@pytest.mark.parametrize("since", [datetime(2026, 10, 1, 11, 59, 0), NOW + timedelta(days=3)])
def test_a_live_feed_cursor_without_a_zone_or_from_the_future_is_read_safely(since):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: a naive or future 'since' is a UTC time no later than now, never a 500 or an inverted window."""
    c = type("C", (), {})()
    seen = []

    class Api:
        def dlp_incident_search(self, query_params=None, fields=None, time_range=None, **kw):
            seen.append(time_range)
            return {"incidents": []}, None, None
    c.zwa = type("Z", (), {"dlp_incidents": Api()})()

    out = dh.poll_incidents(c, since, now=NOW)

    assert out["errors"] == [] and seen[0]["startTime"] <= seen[0]["endTime"]
    assert datetime.fromisoformat(out["next_since"]) <= NOW


def _bypass_hostile_report():
    rules = [{"id": 1, "name": "=HYPERLINK(\"http://x\")\x00\x07" + HOSTILE, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["C1"],
              "urls": ["+cmd|' /C calc'!A0"], "description": "@SUM(1)"}]
    cats = [{"id": "C1", "configuredName": "C1\x0b", "customCategory": True, "urls": ["-2+3"], "keywords": ["k\x1f"]}]
    zcc = [{"id": 1, "name": "P\x01", "bypassApps": [{"name": "=1+1", "path": "C:\\x", "os": "win"}], "trustedNetworks": [{"ssid": "Net"}]}]
    return br.generate_bypass_report(_Get({"/zia/sslInspectionRules": (rules, 200), "/zia/urlCategories": (cats, 200),
                                           "/zcc/webPolicies": (zcc, 200), "/zia/advancedSettings": ({}, 200)}))


def test_the_bypass_word_export_survives_control_characters_and_keeps_names_as_text(tmp_path):
    """ASVS V5.3.1 · A03:2021 · CWE-74 · CWE-116 · WSTG-INPV-01: control characters and formula-like names make a valid .docx with the names as plain text."""
    import docx
    out = br.to_docx(_bypass_hostile_report(), str(tmp_path / "b.docx"))

    text = "\n".join(p.text for p in docx.Document(out).paragraphs) + "\n".join(c.text for t in docx.Document(out).tables for r in t.rows for c in r.cells)
    assert "HYPERLINK" in text and "\x00" not in text and "\x07" not in text
    with zipfile.ZipFile(out) as z:
        assert not [n for n in z.namelist() if "macro" in n.lower() or n.endswith(".bin")]


def test_the_bypass_csv_never_starts_a_cell_with_a_formula():
    """ASVS V5.3.10 · A03:2021 · CWE-1236 · WSTG-INPV-01: every tenant value that starts like a formula is neutralised in the CSV."""
    import csv
    cells = [c for row in csv.reader(io.StringIO(br.to_csv(_bypass_hostile_report()))) for c in row]

    assert cells and not [c for c in cells if c[:1] in ("=", "+", "-", "@", "\t", "\r")]


def test_the_ssl_coverage_workbook_has_no_formula_and_inert_names():
    """ASVS V5.3.10 · A03:2021 · CWE-1236 · WSTG-INPV-01: a tenant name like '=cmd|…' lands in the workbook as text, never as a formula."""
    ssl = [{"id": 1, "name": "=cmd|' /C calc'!A0", "order": 1, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["AI_ML_APPS"]}]
    rep = sc.analyse(ssl)
    rep.update(tenant_label="=evil", volume={"available": True, "protocols": {"BYTES": sc.protocol_split([{"name": "=X", "total": 1}]), "TRANSACTIONS": None}},
               history=[{"at": "2026-10-01", "by_risk": {"high": 1}}])

    data = sc.to_xlsx(rep)

    with zipfile.ZipFile(io.BytesIO(data)) as z:
        xml = "".join(z.read(n).decode("utf-8") for n in z.namelist() if n.endswith(".xml"))
    assert "<f>" not in xml and "<f " not in xml and "calc" in xml


def test_the_insights_csv_leaves_users_out_and_neutralises_formulas():
    """ASVS V8.3.1 · V5.3.10 · A01:2021 · CWE-359 · CWE-1236 · WSTG-INPV-01: per-user rows never reach the CSV and a tenant name is never a formula."""
    import csv
    res = {"traffic_unit": "BYTES", "order": list(insights.SECTION_KEYS), "sections": {
        "web_location": {"title": "Web", "status": "ok", "rows": [{"name": "=HQ", "total": 5}]},
        "top_users": {"title": "Users", "status": "ok", "rows": [{"name": "jane.doe@example.com", "total": 9}]}}}

    cells = [c for row in csv.reader(io.StringIO(insights.to_csv(res))) for c in row]

    assert "jane.doe@example.com" not in " ".join(cells) and not [c for c in cells if c.startswith("=")]
    assert insights.exportable(res)["sections"]["top_users"]["status"] == "omitted"


def test_the_detection_health_markdown_is_inert():
    """ASVS V5.3.3 · A03:2021 · CWE-1236 · CWE-79 · WSTG-CLNT-01: rule, user and destination names cannot add a link, tag or table row to the export."""
    incs = [dh.normalize_incident(_dh_inc(f"i{i}", HOSTILE, user=HOSTILE, url="https://evil.example/|x"), dh.DEFAULTS["not_real"]) for i in range(3)]
    ev = dh.evaluate(incs, [], now=NOW)
    ev.update(days=30, incident_count=3, errors=[HOSTILE])

    md = dh.to_markdown(ev, HOSTILE)

    prose = re.sub(r"(`+).+?\1", "", md)
    assert "<img" not in prose and "\n# Forged" not in md
    for line in md.splitlines():
        if line.startswith("| ") and "evil" in line:
            assert line.count(" | ") == line.replace("\\|", "").count(" | ")


def test_the_ssl_flow_markdown_and_csv_are_inert():
    """ASVS V5.3.3 · V5.3.10 · CWE-1236 · CWE-79 · WSTG-CLNT-01: a hostile rule name stays text in the Markdown and is never a formula in the CSV."""
    import csv
    rep = sf.analyse([{"id": 1, "name": "=1+1 " + HOSTILE, "order": 1, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["AI_ML_APPS"]}], [])

    md, text = sf.to_markdown(rep), sf.to_csv(rep)

    assert "<img" not in re.sub(r"(`+).+?\1", "", md) and "\n# Forged" not in md
    assert not [c for row in csv.reader(io.StringIO(text)) for c in row if c.startswith("=")]


@pytest.mark.parametrize("field", ["locationGroups", "sourceIpGroups", "deviceGroups", "devices", "deviceTrustLevels", "platforms",
                                   "userAgentTypes", "timeWindows", "workloadGroups", "userRiskScoreLevels"])
def test_a_bypass_rule_scoped_by_any_sdk_condition_is_not_flagged_global(field):
    """ASVS V11.1.1 · CWE-682 · CWE-863 · WSTG-BUSL-01: a rule limited by an SDK scope field (as_dict camelCase) is scoped, not 'applies to everyone'."""
    rules = [{"id": 1, "name": "Scoped", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, field: [{"id": 9}]},
             {"id": 2, "name": "Everyone", "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}}]

    rep = br.generate_bypass_report(_Get({"/zia/sslInspectionRules": (rules, 200)}))

    assert [r["name"] for r in rep["risk_flags"]] == ["Everyone"]
    assert rep["sections"]["ssl_bypass_rules"]["items"][0]["scope"] != "global (unscoped)"


@pytest.mark.parametrize("name", ["ZSATray.log.gz", "bundle.tgz", "bundle.tar"])
def test_a_damaged_compressed_upload_is_a_note_never_a_crash(name):
    """ASVS V7.4.1 · V12.1.1 · CWE-755 · CWE-248 · WSTG-ERRH-01: a gzip with a good header and a broken body is noted as unreadable; analyze() raises only the plain 'nothing readable'."""
    good = gzip.compress(b"2026-09-01 08:00:01 INF x\n" * 1000)
    bad = good[:20] + bytes(200) + good[220:]

    members, notes = la.expand([{"name": name, "content": _b64(bad), "encoding": "base64"}])

    assert members == [] and notes and name in notes[0]
    with pytest.raises(ValueError, match="nothing readable"):
        la.analyze([{"name": name, "content": _b64(bad), "encoding": "base64"}])


def _patched_zip(fn) -> bytes:
    b = bytearray(_zip([("a.log", "2026-09-01 08:00:01 INF x\n" * 20)]))
    fn(b)
    return bytes(b)


def _future_version(b):
    b[b.index(b"PK\x01\x02") + 6] = 200        # central directory: "needs ZIP version 20.0 to extract"


def _lying_offset(b):
    eocd = b.index(b"PK\x05\x06")
    off = int.from_bytes(b[eocd + 16: eocd + 20], "little") + 500
    b[eocd + 16: eocd + 20] = off.to_bytes(4, "little")   # member offsets now point before the file starts


@pytest.mark.parametrize("damage", [_future_version, _lying_offset], ids=["future-zip-version", "negative-member-offset"])
def test_a_zip_python_cannot_open_is_a_note_never_a_crash(damage):
    """ASVS V7.4.1 · V12.1.1 · CWE-755 · CWE-248 · WSTG-ERRH-01: a ZIP claiming a future version or lying about offsets is noted as unreadable, never a 500 or a misleading error."""
    data = _patched_zip(damage)

    members, notes = la.expand([{"name": "bundle.zip", "content": _b64(data), "encoding": "base64"}])

    assert members == [] and notes and ("not a valid ZIP" in notes[0] or "could not be read" in notes[0])


def test_seeded_mutations_of_every_bundle_kind_never_crash_the_analyzer():
    """ASVS V12.1.1 · V7.4.1 · CWE-248 · CWE-20 · WSTG-INPV-01: 300 seeded byte mutations of ZIP, tar, gzip, log and PAC uploads end in a result or the plain 'nothing readable'."""
    import random
    rnd = random.Random(2026)
    base = b"2026-09-01 08:00:01 ERR ZSATunnel: tunnel down, auth failed token=abc\n" * 20
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as t:
        info = tarfile.TarInfo("a.log")
        info.size = len(base)
        t.addfile(info, io.BytesIO(base))
    seeds = [("x.zip", _zip([("a.log", base), ("in.zip", _zip([("i.log", base)]))])), ("x.tgz", buf.getvalue()), ("x.log.gz", gzip.compress(base)),
             ("x.log", base), ("p.pac", b"function FindProxyForURL(url, host) { if (shExpMatch(host,'*.a')) return 'DIRECT'; return 'PROXY ${GATEWAY}:80'; }")]

    for _ in range(300):
        name, data = rnd.choice(seeds)
        b = bytearray(data)
        for _ in range(rnd.randint(1, 30)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        try:
            la.analyze([{"name": name, "content": _b64(bytes(b)), "encoding": "base64"}])
        except ValueError as e:
            assert "nothing readable" in str(e)
