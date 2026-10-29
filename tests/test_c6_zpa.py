"""Cloud-6 QA of the ZPA slice: zpa_reader, zpa_analysis, zpa_path,
zpa_overview and the ZPA builder (ops_zpa).

Regression, Secure by Design and functionality checks; each test's first
docstring line maps it to the standards it checks. Everything runs on
in-memory snapshots and the stateful fake tenant in tests/zpa_fake.py: no
network, no real clock (pacing is 0, times are injected), state files in
tmp_path."""
from __future__ import annotations

import inspect
import importlib
import json
import os
import re
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zpa  # noqa: E402
import pack_ops  # noqa: E402
import zpa_analysis as za  # noqa: E402
import zpa_overview as zo  # noqa: E402
import zpa_path as zp  # noqa: E402
import zpa_reader as zr  # noqa: E402
from zpa_fake import CANARY_KEY, Client, Tenant  # noqa: E402

ZPA = ao.scope_for(["zpa"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(zr, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    ao.load_plugins()
    return tmp_path


# ── helpers ─────────────────────────────────────────────────────────────

def _seg(sid, name, domains, tcp=((443, 443),), udp=(), enabled=True, group="", bypass="NEVER", server_groups=()):
    return {"id": sid, "name": name, "domains": list(domains), "tcp": [list(r) for r in tcp], "udp": [list(r) for r in udp],
            "enabled": enabled, "segment_group_id": group, "server_groups": [{"id": g, "name": g} for g in server_groups],
            "bypass_type": bypass, "bypass": bypass in ("ALWAYS", "ON_NET"), "match_style": "", "health_reporting": "ON_ACCESS",
            "double_encrypt": False}


def _op(t, lhs="id", rhs="", name=""):
    return {"type": t, "lhs": lhs, "rhs": rhs, "name": name, "idp_id": ""}


def _cond(*ops, operator="OR", negated=False):
    return {"operator": operator, "negated": negated, "operands": list(ops)}


def _rule(rid, name, action, *conds, order=None, disabled=False, operator="AND"):
    return {"id": rid, "name": name, "action": action, "order": order, "disabled": disabled, "default_rule": False,
            "operator": operator, "conditions": list(conds), "server_group_ids": [], "connector_group_ids": [], "microtenant_id": ""}


def _snap(segments=(), **policies):
    cols = {"segments": {"read": True, "complete": True, "label": "application segments"}}
    for k in policies:
        cols[f"policy:{k}"] = {"read": True, "complete": True}
    return {"segments": list(segments), "posture_profiles": [], "collections": cols, "policies": dict(policies), "scim_groups": {}}


class _Resp:
    """An SDK-like response: the page's raw JSON and body."""

    def __init__(self, items, body=None, total=None):
        self._items, self._body = items, body if body is not None else {"list": items}
        if total is not None:
            self._total_pages = total

    def get_results(self):
        return self._items

    def get_body(self):
        return self._body


def _pager(pages, total=None, with_body=True):
    calls = []

    def call(q):
        calls.append(dict(q))
        items = pages.get(int(q["page"]), [])
        body = {"list": items} if total is None else {"list": items, "totalPages": str(total)}
        resp = _Resp(items, body) if with_body else type("R", (), {"get_results": lambda s: items, "_total_pages": 1})()
        return items, resp, None
    return call, calls


def _apply(client, spec):
    p = ao.plan(client, spec, scope=ZPA, tenant_label="acme")
    r = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") or "")
    return p, r


def _build(c, prefix, domain):
    _apply(c, {"type": "zpa_connector_group", "prefix": prefix})
    _apply(c, {"type": "zpa_app_segments", "prefix": prefix, "wildcard": {"domain": domain, "tcp": "443"}})
    _apply(c, {"type": "zpa_policies", "prefix": prefix, "access": True})


# ── zpa_reader: pagination ──────────────────────────────────────────────

def test_reader_reads_past_short_pages_when_total_pages_says_more():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01: a server answering 100 per page with totalPages 3 is read to the last page, not cut at page 1."""
    pages = {1: [{"id": str(i)} for i in range(100)], 2: [{"id": str(i)} for i in range(100, 200)], 3: [{"id": "200"}]}
    call, calls = _pager(pages, total=3)
    items, complete = zr.list_all(call, zr._Gate(None, 0))
    assert len(items) == 201 and complete is True and len(calls) == 3


def test_reader_does_not_trust_the_sdk_default_of_one_page_when_the_body_states_no_total():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01: a full page whose body carries no totalPages is followed by the next page (no silent truncation)."""
    pages = {1: [{"id": str(i)} for i in range(zr.PAGE_SIZE)], 2: [{"id": "last"}]}
    call, calls = _pager(pages)

    def with_sdk_default(q):
        items, resp, err = call(q)
        resp._total_pages = 1   # what the SDK sets when the body omits totalPages
        return items, resp, err
    items, complete = zr.list_all(with_sdk_default, zr._Gate(None, 0))
    assert len(items) == zr.PAGE_SIZE + 1 and complete is True


def test_reader_stops_at_an_empty_page_and_at_the_stated_total():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: an empty page or the stated last page ends the read: no extra calls."""
    call, calls = _pager({1: []}, total=5)
    assert zr.list_all(call, zr._Gate(None, 0)) == ([], True) and len(calls) == 1
    call, calls = _pager({1: [{"id": "1"}], 2: [{"id": "2"}]}, total=2)
    assert len(zr.list_all(call, zr._Gate(None, 0))[0]) == 2 and len(calls) == 2


def test_reader_marks_a_list_past_the_page_limit_incomplete():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a list longer than the page cap is returned as incomplete, never as complete."""
    pages = {n: [{"id": f"{n}-{i}"} for i in range(zr.PAGE_SIZE)] for n in range(1, 4)}
    call, _ = _pager(pages, total=10)
    items, complete = zr.list_all(call, zr._Gate(None, 0), max_pages=2)
    assert len(items) == 2 * zr.PAGE_SIZE and complete is False


def test_reader_keeps_the_sdk_total_for_a_response_without_a_body():
    """ASVS V5.1.3 · CWE-1284 · WSTG-BUSL-01 (regression): a response with no get_body still uses the SDK's _total_pages."""
    call, calls = _pager({1: [{"id": str(i)} for i in range(zr.PAGE_SIZE)]}, with_body=False)
    items, complete = zr.list_all(call, zr._Gate(None, 0))
    assert len(items) == zr.PAGE_SIZE and complete is True and len(calls) == 1


def test_reader_honours_stop_before_the_next_page():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: Stop raises before any further call, so nothing partial is analyzed."""
    ev = threading.Event()
    ev.set()
    call, calls = _pager({1: [{"id": "1"}]})
    with pytest.raises(zr.Stopped):
        zr.list_all(call, zr._Gate(ev, 0))
    assert calls == []


# ── zpa_reader: untrusted tenant strings ────────────────────────────────

@pytest.mark.parametrize("legacy", [["²", "²"], ["9" * 5000, "9" * 5000], ["٣", "٣"], ["-1", "5"], ["70000", "70000"]])
def test_reader_skips_port_strings_that_are_not_ascii_ports(legacy):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-13: a tenant port like "²" or 5,000 digits is skipped, never a crash of the whole read."""
    assert zr.port_ranges({"tcpPortRanges": legacy}, "tcp")[0] == []


def test_reader_parses_both_port_forms_with_boundaries():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-13: legacy pairs and {from, to} ranges, reversed ends swapped, 0 and 65535 kept, duplicates once."""
    seg = {"tcpPortRanges": ["443", "443", "8000", "7000", "0", "65535"], "tcpPortRange": [{"from": "443", "to": "443"}, {"from": "22"}]}
    assert zr.port_ranges(seg, "tcp")[0] == [[0, 65535], [22, 22], [443, 443], [7000, 8000]]


@pytest.mark.parametrize("raw", ["nan", "inf", "-inf", "", None, "abc", "0", "-5"])
def test_reader_epoch_is_none_for_non_finite_or_absent_times(raw):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-13: "NaN" or "inf" from the tenant is no time at all, so a dead connector is still flagged stale."""
    assert zr.epoch_seconds(raw) is None


def test_reader_epoch_unit_by_magnitude():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-13: seconds, milliseconds, microseconds and nanoseconds give the same time."""
    assert {zr.epoch_seconds(v) for v in ("1700000000", "1700000000000", "1700000000000000", "1700000000000000000")} == {1700000000.0}


def test_a_connector_with_a_nan_last_seen_is_reported_stale():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a disconnected connector whose last-seen is "NaN" is reported as having no recorded time."""
    c = zr.normalize_connector({"id": "1", "name": "c1", "controlChannelStatus": "ZPN_STATUS_DISCONNECTED", "lastBrokerConnectTime": "NaN"})
    out = za._t_stale({"connectors": [c]}, None, now=1_800_000_000.0)
    assert [f["template"] for f in out] == ["ZPA-AC-01"] and "no recorded connection time" in out[0]["reason"]


@pytest.mark.parametrize("text", [
    'HTTP 400 {"provisioningKey": "3|CANARY-PROVISIONING-KEY-q9Zx7Lm2Vt8Rb4Nw|do-not-leak"}',
    "key 3|CANARY-PROVISIONING-KEY-q9Zx7Lm2Vt8Rb4Nw|do-not-leak already used",
    "provisioning_key=3|CANARY-PROVISIONING-KEY-q9Zx7Lm2Vt8Rb4Nw|do-not-leak",
    "Authorization: Bearer abc.def.ghi",
])
def test_reader_error_text_hides_provisioning_keys_and_credentials(text):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: an SDK error that echoes a provisioning key or a bearer token never carries it into a log or result."""
    out = zr._err_text(text)
    assert "CANARY" not in out and "abc.def.ghi" not in out and "[hidden]" in out


def test_reader_error_text_keeps_plain_errors_and_caps_length():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: an ordinary error stays readable and is cut at 200 characters."""
    assert zr._err_text("HTTP 404: resource.not.found") == "HTTP 404: resource.not.found"
    assert len(zr._err_text("x " * 500)) == 200 and zr._err_text(None) == "the API answered an error"


# ── Customer ID: required and validated before any ZPA call ─────────────

class _CountingZpa:
    def __init__(self):
        self.calls = 0

    def __getattr__(self, name):
        outer = self

        class Svc:
            def __getattr__(self, m):
                def fn(*a, **k):
                    outer.calls += 1
                    return [], None, None
                return fn
        return Svc()


class _SdkLike:
    def __init__(self, customer_id):
        self._config = {"client": {"customerId": customer_id} if customer_id is not None else {}}
        self.zpa = _CountingZpa()


@pytest.mark.parametrize("cid", [None, "", "  ", "72;DROP", "7" * 65, "../72", "72 01"])
def test_reader_refuses_a_missing_or_invalid_customer_id_before_any_call(cid):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: with no valid customer ID the read is refused in words and ZPA is never called (no /customers/None/)."""
    c = _SdkLike(cid)
    with pytest.raises(zr.ReadError, match="customer ID"):
        zr.read(c, pace=0)
    assert c.zpa.calls == 0


def test_reader_reads_with_a_valid_customer_id():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a valid customer ID (letters and digits, at most 64) reads normally."""
    c = _SdkLike("7" * 64)
    snap = zr.read(c, pace=0)
    assert c.zpa.calls > 0 and zr.readable(snap)


def test_reader_does_not_judge_clients_without_an_sdk_configuration():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01 (regression): offline snapshots and fakes, which have no SDK config, are not refused."""
    assert zr.customer_id_problem(Client()) is None and zr.customer_id_problem(object()) is None


@pytest.mark.parametrize("cid", [None, "", "72;DROP"])
def test_builder_refuses_a_missing_or_invalid_customer_id_before_any_call(cid):
    """ASVS V5.1.3 · CWE-841 · WSTG-BUSL-06: the ZPA builder refuses to plan without a valid customer ID; nothing is read or written."""
    c = _SdkLike(cid)
    with pytest.raises(ao.OperationError, match="customer ID"):
        ops_zpa.plan_connector_group(c, {"prefix": "pov1"}, ZPA, lambda m: None, None)
    assert c.zpa.calls == 0


# ── zpa_analysis: destination parsing ───────────────────────────────────

@pytest.mark.parametrize("dest", ["git.corp.example:²", "[::1]:²", "git.corp.example:٤٤٣"])
def test_destination_with_a_non_ascii_inline_port_is_refused_in_plain_words(dest):
    """ASVS V7.4.1 · CWE-209 · WSTG-INPV-01: a port written with non-ASCII digits gives a plain message, never Python's int() error."""
    with pytest.raises(ValueError) as e:
        za.parse_destination(dest)
    assert "invalid literal" not in str(e.value)


@pytest.mark.parametrize("port", ["²", "٤٤٣", "+443", "4 43", "1e3", "9" * 5000])
def test_destination_with_a_non_ascii_port_field_is_refused_in_plain_words(port):
    """ASVS V7.4.1 · CWE-209 · WSTG-INPV-01: the port field accepts ASCII digits only and answers a plain sentence."""
    with pytest.raises(ValueError, match="The port must be a number from 1 to 65535"):
        za.parse_destination("git.corp.example", port)


@pytest.mark.parametrize("dest,port,want", [
    ("git.corp.example", None, (443, True)), ("https://git.corp.example/x", None, (443, False)), ("ssh://h.example", None, (22, False)),
    ("git.corp.example:8443", None, (8443, False)), ("git.corp.example:8443", "22", (22, False)), ("h.example", "1", (1, False)),
    ("h.example", "65535", (65535, False)), ("[2001:db8::1]:8080", None, (8080, False)), ("user@h.example:22", None, (22, False)),
])
def test_destination_port_oracle(dest, port, want):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the port is the field, else the inline port, else the scheme's, else 443 (assumed)."""
    d = za.parse_destination(dest, port)
    assert (d["port"], d["port_assumed"]) == want


@pytest.mark.parametrize("port", ["0", "65536"])
def test_destination_port_boundaries_are_refused(port):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: 0 and 65536 are outside 1-65535."""
    with pytest.raises(ValueError, match="1 to 65535"):
        za.parse_destination("h.example", port)


def test_destination_idn_is_matched_in_its_punycode_form():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a unicode host (IDN) is turned into the punycode ZPA stores, and matches either spelling of the entry."""
    d = za.parse_destination("Bücher.example")
    assert d["host"] == "xn--bcher-kva.example"
    for entry in ("xn--bcher-kva.example", "bücher.example", "*.example"):
        m = za.match_segment(_snap([_seg("s1", "Books", [entry])]), d)["match"]
        assert m is not None and m["id"] == "s1"


def test_destination_with_an_unencodable_label_is_refused():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an IDN label longer than 63 characters is a plain refusal."""
    with pytest.raises(ValueError, match="is not a hostname"):
        za.parse_destination("ü" * 70 + ".example")


@pytest.mark.parametrize("dest", ["", " ", "a" * 301, "bad host.example", "<script>.example", "h.example\u0000"])
def test_destination_refuses_empty_long_and_invalid_hosts(dest):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: empty, over-long and non-hostname input is refused in words."""
    with pytest.raises(ValueError):
        za.parse_destination(dest)


# ── zpa_analysis: segment matching oracle ───────────────────────────────

SEGS = [
    _seg("exact", "Exact", ["git.corp.example"]),
    _seg("w3", "Wildcard corp", ["*.corp.example"]),
    _seg("w2", "Wildcard example", ["*.example"]),
    _seg("all", "Catch-all", ["*"]),
    _seg("net8", "Net /8", ["10.0.0.0/8"]),
    _seg("net24", "Net /24", ["10.1.2.0/24"]),
    _seg("v6", "IPv6 /48", ["2001:db8:1::/48"]),
    _seg("v6w", "IPv6 /32", ["2001:db8::/32"]),
    _seg("udp", "DNS", ["dns.corp.example"], tcp=(), udp=((53, 53),)),
    _seg("narrow", "Narrow ports", ["*.corp.example"], tcp=((8443, 8443),)),
    _seg("wide", "Wide ports", ["*.corp.example"], tcp=((8000, 9000),)),
]


@pytest.mark.parametrize("dest,port,proto,want", [
    ("git.corp.example", 443, "tcp", "exact"),          # exact beats every wildcard
    ("a.b.corp.example", 443, "tcp", "w3"),            # longest wildcard suffix
    ("x.example", 443, "tcp", "w2"),
    ("corp.example", 443, "tcp", "w2"),                # *.corp.example does not cover its apex
    ("other.test", 443, "tcp", "all"),                 # catch-all last
    ("10.1.2.3", 443, "tcp", "net24"),                  # longest prefix
    ("10.9.9.9", 443, "tcp", "net8"),
    ("2001:db8:1::5", 443, "tcp", "v6"),
    ("2001:db8:2::5", 443, "tcp", "v6w"),
    ("dns.corp.example", 53, "udp", "udp"),
    ("dns.corp.example", 443, "tcp", "w3"),           # the UDP segment does not serve TCP: the wildcard does
    ("app.corp.example", 8443, "tcp", "narrow"),       # equally specific: the narrowest port range
    ("app.corp.example", 8000, "tcp", "wide"),
    ("app.corp.example", 9001, "tcp", None),           # just past the range end: no segment
])
def test_segment_matching_oracle(dest, port, proto, want):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: exact FQDN, then the longest wildcard, then the longest prefix; port ranges inclusive; UDP and TCP apart."""
    sm = za.match_segment(_snap(SEGS), za.parse_destination(dest, port, proto))
    assert (sm["match"] or {}).get("id") == want


def test_segment_matching_skips_disabled_and_portless_segments_and_names_them():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: a disabled segment or one without the port never carries it; both are named as hints."""
    snap = _snap([_seg("off", "Off", ["git.corp.example"], enabled=False), _seg("p", "Port 22 only", ["git.corp.example"], tcp=((22, 22),))])
    d = za.parse_destination("git.corp.example", 443)
    sm = za.match_segment(snap, d)
    assert sm["match"] is None and [x["id"] for x in sm["disabled"]] == ["off"] and [x["id"] for x in sm["near_misses"]] == ["p"]
    hints = zp.segment_hints(snap, d, sm)
    assert any("Port 22 only" in h and "443" in h for h in hints) and any("disabled" in h for h in hints)


def test_segment_matching_reports_an_ambiguous_tie():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: two equally specific segments with equal port spans are reported as ambiguous."""
    sm = za.match_segment(_snap([_seg("a", "A", ["h.example"]), _seg("b", "B", ["h.example"])]), za.parse_destination("h.example"))
    assert sm["match"]["id"] == "a" and [x["id"] for x in sm["ambiguous"]] == ["b"]


# ── zpa_analysis: access policy and "why not matched" ──────────────────

HR = _seg("s1", "HR", ["hr.corp"], group="g1")


def _why(rules, user, seg=HR):
    d = za.diagnose(_snap([seg], access=rules), user, "hr.corp", 443)
    return {w["name"]: w for w in d["access"]["evaluated"]}, d


def test_why_text_of_a_negated_application_condition_reads_correctly():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: a rule for every application except HR says so, not "applies to not app segment HR"."""
    w, _ = _why([_rule("r1", "All but HR", "ALLOW", _cond(_op("APP", rhs="s1"), negated=True), order=1)], {})
    assert w["All but HR"]["status"] == "not_matched"
    assert w["All but HR"]["why"] == "It applies to every application except app segment HR, and this destination is app segment HR."


def test_why_text_of_an_or_rule_names_every_failed_condition():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: a rule whose conditions are joined by OR fails only when none is met, and says all of them."""
    r = _rule("r1", "Linux or France", "ALLOW", _cond(_op("PLATFORM", lhs="linux", rhs="true")),
              _cond(_op("COUNTRY_CODE", lhs="FR", rhs="true")), order=1, operator="OR")
    w, _ = _why([r], {"platform": "windows", "country": "US"})
    assert w["Linux or France"]["why"] == ("It matches when any of its conditions is met (platform linux; or country FR), and none is.")


def test_why_text_of_a_negated_user_condition_reads_correctly():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: a rule excluding a platform says it excludes it, and that this user has it."""
    w, _ = _why([_rule("r1", "Not Linux", "ALLOW", _cond(_op("PLATFORM", lhs="linux", rhs="true"), negated=True), order=1)], {"platform": "linux"})
    assert w["Not Linux"]["why"] == "It excludes platform linux, and this user has that."


def test_why_text_of_a_plain_requirement_and_of_an_application_mismatch():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01 (regression): a failed requirement and a rule for another segment keep their sentences."""
    other = _seg("s2", "Finance", ["fin.corp"])
    rules = [_rule("r1", "Finance only", "ALLOW", _cond(_op("APP", rhs="s2")), order=1),
             _rule("r2", "Mac only", "ALLOW", _cond(_op("PLATFORM", lhs="mac", rhs="true")), order=2)]
    d = za.diagnose(_snap([HR, other], access=rules), {"platform": "windows"}, "hr.corp", 443)
    w = {x["name"]: x for x in d["access"]["evaluated"]}
    assert w["Finance only"]["why"] == "It applies to app segment Finance, not to app segment HR."
    assert w["Mac only"]["why"] == "It requires platform mac, which this user does not meet."


def test_why_text_of_an_operand_the_tool_cannot_evaluate_does_not_blame_the_user():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: a risk-score condition is "cannot evaluate", not "you left as any" (the user cannot give it)."""
    rules = [_rule("r1", "Risky", "ALLOW", _cond(_op("RISK_FACTOR_TYPE", lhs="ZIA", rhs="HIGH")), order=1),
             _rule("r2", "Risky Mac", "ALLOW", _cond(_op("RISK_FACTOR_TYPE", lhs="ZIA", rhs="HIGH")), _cond(_op("PLATFORM", lhs="mac", rhs="true")), order=2)]
    w, _ = _why(rules, {})
    assert w["Risky"]["status"] == "conditional"
    assert w["Risky"]["why"] == "It matches only if the user meets its conditions on risk factor type, which this tool cannot evaluate."
    assert w["Risky Mac"]["why"] == ("It matches only if the user meets its conditions on platform, which you left as any and its conditions on "
                                     "risk factor type, which this tool cannot evaluate.")


def test_access_policy_first_match_in_rule_order_skips_disabled_rules():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: rules are evaluated by ruleOrder, a disabled rule is skipped, the first match decides."""
    rules = zr.order_rules([
        dict(_rule("r3", "Allow all", "ALLOW", order=3), index=0),
        dict(_rule("r1", "Deny HR (disabled)", "DENY", _cond(_op("APP", rhs="s1")), order=1, disabled=True), index=1),
        dict(_rule("r2", "Deny HR", "DENY", _cond(_op("APP", rhs="s1")), order=2), index=2),
    ])
    _, d = _why(rules, {})
    assert d["verdict"]["outcome"] == "denied" and d["verdict"]["rule"] == "Deny HR"
    assert [w["status"] for w in d["access"]["evaluated"]] == ["disabled", "matched"]


def test_access_policy_denies_by_default_when_no_rule_matches():
    """ASVS V4.1.3 · CWE-276 · WSTG-ATHZ-02: when no rule matches ZPA denies (default deny)."""
    _, d = _why([_rule("r1", "Mac only", "ALLOW", _cond(_op("PLATFORM", lhs="mac", rhs="true")), order=1)], {"platform": "windows"})
    assert d["access"]["decision"] == "default_deny" and d["verdict"]["outcome"] == "denied"


def test_diagnose_with_no_access_rules_at_all_is_default_deny():
    """ASVS V4.1.3 · CWE-276 · WSTG-ATHZ-02: an empty access policy denies every application."""
    _, d = _why([], {})
    assert d["access"]["decision"] == "default_deny" and "Denied by default" in d["verdict"]["headline"]


# ── zpa_path: the ZPA stage ─────────────────────────────────────────────

def _stage(segs, network="off", **pol):
    return zp.stage(_snap(segs, **pol), zp.destination("hr.corp", 443), network=network)


def test_path_on_net_segment_off_network_does_not_claim_a_trusted_network_bypass():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: off a trusted network an On-Net segment is not bypassed; the headline names the forwarding rule instead."""
    seg = _seg("s1", "HR", ["hr.corp"], bypass="ON_NET")
    st = _stage([seg], "off", access=[], client_forwarding=[_rule("f1", "Accessible", "INTERCEPT_ACCESSIBLE", order=1)])
    assert st["outcome"] == "outside" and "trusted network" not in st["headline"]
    assert "intercepts only accessible applications" in st["headline"]


def test_path_on_net_segment_on_network_is_bypassed():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: on a trusted network an On-Net segment goes outside ZPA, and the headline says why."""
    st = _stage([_seg("s1", "HR", ["hr.corp"], bypass="ON_NET")], "on", access=[_rule("a", "Allow", "ALLOW", order=1)])
    assert st["outcome"] == "outside" and "bypasses ZPA on a trusted network" in st["headline"]


@pytest.mark.parametrize("bypass,network,fwd,want", [
    ("ALWAYS", "off", None, {"outside"}),
    ("NEVER", "off", "BYPASS", {"outside"}),
    ("NEVER", "off", "INTERCEPT", {"zpa_allow"}),
    ("ON_NET", "vpn", None, {"outside", "zpa_allow"}),
    ("ON_NET", "off", None, {"zpa_allow"}),
])
def test_path_bypass_and_forwarding_oracle(bypass, network, fwd, want):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: bypass Always / On-Net and the forwarding actions give the documented end."""
    pol = {"access": [_rule("a", "Allow", "ALLOW", order=1)]}
    if fwd:
        pol["client_forwarding"] = [_rule("f", "F", fwd, order=1)]
    st = _stage([_seg("s1", "HR", ["hr.corp"], bypass=bypass)], network, **pol)
    assert set(st["ends"]) == want


def test_path_posture_rule_answers_both_ways():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: an allow rule requiring posture allows when posture passes and denies by default when it fails."""
    snap = _snap([_seg("s1", "HR", ["hr.corp"])], access=[_rule("a", "Compliant", "ALLOW", _cond(_op("POSTURE", lhs="udid-1", rhs="true")), order=1)])
    snap["posture_profiles"] = [{"id": "p1", "name": "Disk encrypted", "posture_udid": "udid-1"}]
    st = zp.stage(snap, zp.destination("hr.corp", 443))
    assert st["posture_matters"] is True and st["scenarios"]["pass"]["access"] == "allow" and st["scenarios"]["fail"]["access"] == "deny"
    assert st["outcome"] == "zpa_conditional" and st["headline"].startswith("Depends on device posture")


def test_path_flags_operands_it_cannot_evaluate():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: a rule with a risk-score operand is flagged by name and makes the answer conditional."""
    st = _stage([_seg("s1", "HR", ["hr.corp"])], access=[_rule("a", "Risky", "DENY", _cond(_op("RISK_FACTOR_TYPE", lhs="ZIA", rhs="HIGH")), order=1),
                                                    _rule("b", "Allow", "ALLOW", order=2)])
    assert st["flagged"] == [{"rule": "Risky", "order": 1, "types": ["RISK_FACTOR_TYPE"]}] and st["outcome"] == "zpa_conditional"


def test_path_known_operands_are_the_ones_the_analysis_evaluates():
    """ASVS V1.1.2 · CWE-1068 · WSTG-INFO-10: the Path analyzer and the diagnosis share one list of evaluable operand types."""
    assert zp.KNOWN_OPERANDS is za.EVALUATED_OPERANDS


# ── zpa_analysis: untrusted connector versions ──────────────────────────

def test_analysis_sorts_mixed_text_and_number_versions_without_crashing():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-13: connector versions "23.1" and "beta.1" in one group are listed, not a TypeError that ends the analysis."""
    snap = {"connector_groups": [{"id": "g1", "name": "G", "enabled": True, "embedded_connectors": []}],
            "connectors": [zr.normalize_connector({"id": str(i), "name": f"c{i}", "appConnectorGroupId": "g1", "currentVersion": v,
                                                   "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}) for i, v in enumerate(["23.1", "beta.1", "²"])],
            "server_groups": [], "collections": {k: {"read": True, "complete": True} for k in ("connector_groups", "connectors")}}
    out = za.analyze(snap)
    cg4 = [f for f in out["findings"] if f["template"] == "ZPA-CG-04"]
    assert cg4 and "runs 3 versions" in cg4[0]["reason"]
    assert zo.overview(snap, out)["tables"]["connector_groups"]["rows"][0]["versions"].startswith("23.1")


def test_version_key_orders_numerically():
    """ASVS V5.1.3 · CWE-1077 · WSTG-BUSL-01: 23.10 sorts after 23.9 (numbers by value, not text)."""
    assert sorted(["23.10.1", "23.9.4", "22.100"], key=za._vkey) == ["22.100", "23.9.4", "23.10.1"]


# ── zpa_overview: the workbook ──────────────────────────────────────────

def test_overview_workbook_builds_the_tables_once(monkeypatch):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: the workbook computes the seven tables once, not twice per sheet."""
    calls = []
    real = zo.tables
    monkeypatch.setattr(zo, "tables", lambda m: calls.append(1) or real(m))
    snap = _snap([HR], access=[_rule("a", "Allow", "ALLOW", order=1)])
    data = zo.workbook(snap, za.analyze(snap), tenant_label="acme", read_at=1_700_000_000)
    assert data[:2] == b"PK" and len(calls) == 1


# ── ops_zpa: pagination, prefixes, lifecycle, payloads ──────────────────

def test_builder_refuses_to_plan_from_an_incomplete_list(monkeypatch):
    """ASVS V11.1.4 · CWE-1284 · WSTG-BUSL-01: a list cut at the page limit is a read error, so no duplicate is planned from a partial tenant."""
    monkeypatch.setattr(zr, "PAGE_SIZE", 2)
    monkeypatch.setattr(zr, "MAX_PAGES", 1)
    c = Client()
    for i in range(3):
        c.tenant.add("connector_group", {"name": f"other-{i}"})
    with pytest.raises(ao.OperationError, match="could not be read completely"):
        ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1"}, scope=ZPA, tenant_label="acme")
    assert c.tenant.writes == []


def test_builder_pages_through_every_object_before_planning(monkeypatch):
    """ASVS V11.1.4 · CWE-1284 · WSTG-BUSL-01: with small pages the builder still finds its own object on the last page and updates nothing twice."""
    monkeypatch.setattr(zr, "PAGE_SIZE", 2)
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    for i in range(5):
        c.tenant.add("connector_group", {"name": f"z-{i}"})
    p = ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1"}, scope=ZPA, tenant_label="acme")
    assert p["counts"]["change"] == 0 and c.tenant.names("connector_group").count("pov1-connector-group") == 1


def test_prefix_delete_never_deletes_another_builds_longer_prefix():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: deleting everything named "pov-…" keeps the build "pov-2", whose names also start with "pov-"."""
    c = Client()
    _build(c, "pov", "a.example.com")
    _build(c, "pov-2", "b.example.com")
    p = ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov", "everything": True}, scope=ZPA, tenant_label="acme")
    targets = [g["target"]["name"] for g in p["groups"]]
    assert targets and all(not n.startswith("pov-2-") for n in targets)
    assert "pov-access" in targets and any("pov-2" in w for w in p["warnings"])


def test_prefix_delete_applied_leaves_the_other_build_intact():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: after the delete of "pov" every "pov-2" object is still in ZPA."""
    c = Client()
    _build(c, "pov", "a.example.com")
    _build(c, "pov-2", "b.example.com")
    before = {k: [n for n in c.tenant.names(k) if n.startswith("pov-2-")] for k in c.tenant.rows}
    _, r = _apply(c, {"type": "zpa_prefix_delete", "prefix": "pov", "everything": True})
    assert r["status"] == "applied"
    assert {k: [n for n in c.tenant.names(k) if n.startswith("pov-2-")] for k in c.tenant.rows} == before
    assert not [n for k in c.tenant.rows for n in c.tenant.names(k) if n.startswith("pov-") and not n.startswith("pov-2-")]


def test_policies_of_a_prefix_cover_only_its_own_segments():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the "pov" access rule names pov's segments, not those of the build "pov-2"."""
    c = Client()
    _build(c, "pov-2", "b.example.com")
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov"})
    _apply(c, {"type": "zpa_app_segments", "prefix": "pov", "wildcard": {"domain": "a.example.com", "tcp": "443"}})
    _apply(c, {"type": "zpa_policies", "prefix": "pov", "access": True})
    mine = {s["id"] for s in c.tenant.rows["segment"].values() if s["name"].startswith("pov-wildcard")}
    rule = c.tenant.by_name("rule:access", "pov-access")
    assert {o["rhs"] for cnd in rule["conditions"] for o in cnd["operands"]} == mine


def test_prefix_ownership_oracle():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a longer prefix is recognised only from the builder's fixed object names."""
    data = {"segment_group": [{"name": "pov-2-segment-group"}], "access_rule": [{"name": "pov-access"}],
            "segment": [{"name": "pov-team-access"}]}
    others = ops_zpa.other_prefixes("pov", data)
    assert others == {"pov-2"}
    assert ops_zpa.owned("pov", "pov-team-access", others) and not ops_zpa.owned("pov", "pov-2-wildcard-x", others)
    assert not ops_zpa.owned("pov", "povx-access", others) and not ops_zpa.owned("pov", "pov", others)


@pytest.mark.parametrize("spec", [
    {"type": "zpa_connector_group", "prefix": "pov1"},
    {"type": "zpa_app_segments", "prefix": "pov1", "preset": {"vertical": "general", "domain": "corp.example.com"}},
    {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": True, "inspection": True},
])
def test_builder_rerun_is_idempotent(spec):
    """ASVS V1.4.4 · CWE-841 · WSTG-BUSL-06: running the same build twice changes nothing the second time (found by name, updated in place)."""
    c = Client()
    if spec["type"] != "zpa_connector_group":
        _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    if spec["type"] == "zpa_policies":
        _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443"}})
    _, r1 = _apply(c, spec)
    assert r1["status"] == "applied"
    n = len(c.tenant.writes)
    p2 = ao.plan(c, spec, scope=ZPA, tenant_label="acme")
    assert p2["counts"]["change"] == 0 and len(c.tenant.writes) == n


def test_builder_updates_in_place_then_undo_puts_it_back():
    """ASVS V1.4.4 · CWE-841 · WSTG-BUSL-06: a re-run with a new value updates the object in place; its Undo restores the old value."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 5})
    _, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 9})
    assert c.tenant.writes[-1] == ("update", "provisioning_key", "pov1-provisioning-key")
    assert c.tenant.by_name("provisioning_key", "pov1-provisioning-key")["maxUsage"] == "9"
    inv = ops_zpa.inverse(r)
    _, u = _apply(c, inv)
    assert u["status"] == "applied" and c.tenant.by_name("provisioning_key", "pov1-provisioning-key")["maxUsage"] == "5"
    assert c.tenant.names("connector_group") == ["pov1-connector-group"]


def test_builder_engine_refuses_without_write_mode_or_the_previewed_plan():
    """ASVS V4.2.2 · CWE-841 · WSTG-BUSL-06: without write mode, or with a plan hash that is not the preview's, nothing is written."""
    c = Client()
    spec = {"type": "zpa_connector_group", "prefix": "pov1"}
    p = ao.plan(c, spec, scope=ZPA, tenant_label="acme")
    for kw in ({"writes_enabled": False, "assessor": ASSESSOR, "plan_hash": p["plan_hash"]},
               {"writes_enabled": None, "assessor": ASSESSOR, "plan_hash": p["plan_hash"]},
               {"writes_enabled": True, "assessor": ASSESSOR, "plan_hash": "0" * 64}):
        try:
            r = ao.execute(c, spec, scope=ZPA, tenant_label="acme", **kw)
        except (ao.OperationError, PermissionError):
            r = {"status": "refused"}
        assert r.get("status") != "applied"
    assert c.tenant.writes == []


def test_provisioning_key_never_reaches_logs_results_or_records(isolated):
    """ASVS V8.3.4 · CWE-532 · WSTG-INFO-05: the new key is in no log line, result, record or audit entry; it is revealed once only."""
    c = Client()
    lines = []
    p = ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1"}, scope=ZPA, tenant_label="acme")
    r = ao.execute(c, {"type": "zpa_connector_group", "prefix": "pov1"}, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True,
                   assessor=ASSESSOR, tenant_label="acme", log=lines.append)
    for row in c.tenant.rows["provisioning_key"].values():
        row["provisioningKey"] = CANARY_KEY
    ao.record(r, by=ASSESSOR)
    blob = json.dumps([p, r, lines], default=str) + "".join(open(f, encoding="utf-8").read() for f in
                                                           (isolated / "deployments.json", isolated / "audit.log") if os.path.exists(f))
    assert "CANARY" not in blob
    rows, err = ops_zpa.list_kind(c.zpa, "provisioning_key", zr._Gate(None, 0))
    assert err is None and "CANARY" not in json.dumps(rows)
    token = r["one_time_secrets"][0]["token"]
    assert ops_zpa.reveal(token) is not None and ops_zpa.reveal(token) is None


@pytest.mark.parametrize("token", ["", None, "short", "x" * 101, "../../etc/passwd" + "a" * 20, "a" * 30 + "\n"])
def test_reveal_refuses_malformed_tokens(token):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a malformed token reveals nothing."""
    ops_zpa.stash("k", "n", None, now=0.0)
    assert ops_zpa.reveal(token, now=1.0) is None


def test_reveal_refuses_another_person_and_an_expired_token():
    """ASVS V4.1.3 · CWE-639 · WSTG-ATHZ-04: only the person whose run made the key, within ten minutes, sees it."""
    t1 = ops_zpa.stash("k1", "n1", "alice", now=0.0)
    assert ops_zpa.reveal(t1, actor="bob", now=1.0) is None and ops_zpa.reveal(t1, actor="alice", now=1.0)["provisioning_key"] == "k1"
    t2 = ops_zpa.stash("k2", "n2", "alice", now=0.0)
    assert ops_zpa.reveal(t2, actor="alice", now=ops_zpa.SECRET_TTL) is None


# Payload keys must be ones the SDK knows: in the service module or its models.
_SDK = importlib.import_module("zscaler.zpa.zpa_service")


def _sdk_text(svc_attr):
    for name, obj in inspect.getmembers(_SDK.ZPAService):
        if name == svc_attr and isinstance(obj, property):
            cls = getattr(_SDK, re.search(r"return (\w+)\(", inspect.getsource(obj.fget)).group(1))
            mod = inspect.getmodule(cls)
            text = inspect.getsource(mod)
            for m in re.findall(r"from zscaler\.zpa\.models\.(\w+) import", text):
                text += inspect.getsource(importlib.import_module("zscaler.zpa.models." + m))
            return text
    raise AssertionError(svc_attr)


def _keys(d):
    out = []
    for k, v in d.items():
        out.append(k)
        for x in (v if isinstance(v, list) else [v]):
            if isinstance(x, dict):
                out += _keys(x)
    return out


_PAYLOADS = {
    "connector_group": ({"enabled": True}, {"location": "london"}),
    "provisioning_key": ({"max_usage": "5", "connector_group": "1"}, {"enrollment_cert_id": "2"}),
    "segment_group": ({}, {}), "server_group": ({"connector_groups": ["1"]}, {}),
    "segment": ({"enabled": False, "domains": ["a.example"], "segment_group": "1", "server_groups": ["2"], "tcp": ["443-443"], "udp": ["53-53"]},
                {"browser_access": {"domain": "a.example", "port": 443, "certificate_id": "9"}}),
    "pra_segment": ({"enabled": False, "domains": ["a.example"], "segment_group": "1", "server_groups": ["2"], "tcp": ["3389-3389"], "udp": []},
                    {"pra": {"port": 3389, "protocol": "RDP", "host": "a.example"}}),
    "inspection_profile": ({}, {"version": "OWASP_CRS/4.8.0"}),
    "pra_console": ({"enabled": False}, {"pra_application_id": "1", "portal_id": "2"}),
    "access_rule": ({"apps": ["1"]}, {}),
    "timeout_rule": ({"apps": ["1"], "reauth_timeout": "3600", "reauth_idle_timeout": "900"}, {}),
    "inspection_rule": ({"apps": ["1"], "profile": "5"}, {}), "isolation_rule": ({"apps": ["1"], "profile": "5"}, {}),
}


@pytest.mark.parametrize("kind", sorted(_PAYLOADS))
def test_create_payload_fields_are_known_to_the_sdk(kind):
    """ASVS V1.14.6 · CWE-1059 · SSDF PW.4.1: every field of a create payload is one zscaler-sdk-python 1.11.3 names for that service or model."""
    want, extra = _PAYLOADS[kind]
    op = ops_zpa.KINDS[kind]["op"]
    svc = pack_ops.ZPA_KINDS[op][0] if op in pack_ops.ZPA_KINDS else "application_segment"
    text = _sdk_text(svc)
    payload = ops_zpa.create_payload({"kind": kind, "name": "pov1-x", "prefix": "pov1"}, want, extra, ASSESSOR)
    missing = [k for k in _keys(payload) if k not in text and ops_zpa._camel(k) not in text]
    assert missing == []


@pytest.mark.parametrize("kind,action", [("access_rule", "allow"), ("timeout_rule", "RE_AUTH"), ("inspection_rule", "inspect"),
                                         ("isolation_rule", "isolate")])
def test_rule_actions_are_the_sdk_documented_values(kind, action):
    """ASVS V1.14.6 · CWE-1059 · SSDF PW.4.1: each rule's action is the value the SDK documents for its policy type."""
    want, _ = _PAYLOADS[kind]
    p = ops_zpa.create_payload({"kind": kind, "name": "pov1-x", "prefix": "pov1"}, want, {}, ASSESSOR)
    assert p["action"] == action and action in _sdk_text("policies")
    assert p["conditions"] == [("app", "id", "1")]


def test_update_payload_of_a_provisioning_key_keeps_its_group_and_drops_the_key():
    """ASVS V8.3.4 · CWE-200 · WSTG-INFO-05: the PUT body keeps the key's group (zcomponentId) and never carries its value."""
    fresh = {"id": "1", "name": "pov1-provisioning-key", "enabled": True, "maxUsage": "5", "enrollmentCertId": "7", "zcomponentId": "9",
             "provisioningKey": CANARY_KEY}
    body = ops_zpa.update_payload("provisioning_key", ops_zpa._scrub(fresh), {"max_usage": "6"})
    assert body == {"name": "pov1-provisioning-key", "enabled": True, "max_usage": "6", "enrollment_cert_id": "7", "zcomponent_id": "9"}
    assert "zcomponentId" in _sdk_text("provisioning")
