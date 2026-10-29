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
