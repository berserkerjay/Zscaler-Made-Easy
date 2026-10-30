"""Wave 6 follow-up: the low and info findings the QA agents left open
(docs/qa/findings/*.json), each fixed at its root and pinned here by a test
that fails without the fix.

Nothing here reaches a tenant: sign-in factories and pack deploys are
replaced by fakes, the only tenant data is made up, the browser-harness test
talks to a loopback server, and node runs the app's own scripts only.
Deterministic: seeded randomness, no clock, no sleeps."""
from __future__ import annotations

import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import types
import zipfile

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))
STATIC = os.path.join(ROOT, "static")
NODE = shutil.which("node")
node = pytest.mark.skipif(not NODE, reason="needs node")


def _node(tmp_path, script, *args):
    f = tmp_path / "run.mjs"
    f.write_text(script, encoding="utf-8")
    r = subprocess.run([NODE, str(f), *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    return json.loads(r.stdout.strip().splitlines()[-1])


# ── C6-API-SERVER-12: a bare IPv6 address is a destination ──────────────

@pytest.mark.parametrize("typed,host", [("2001:db8::1", "2001:db8::1"), ("::1", "::1"), ("2001:DB8:0:0::1", "2001:db8::1"),
                                        ("[2001:db8::1]:443", "2001:db8::1"), ("https://[::1]:8443/x", "::1")])
def test_a_bare_or_bracketed_ipv6_address_is_placed_as_an_ip(typed, host):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a bare IPv6 literal is an address, not host:port (it was a 400 and failed a whole list run)."""
    import path_analyzer
    # Act
    d = path_analyzer.parse_destination(typed)
    # Assert
    assert (d["host"], d["is_ip"]) == (host, True)


def test_every_address_of_an_ipv6_range_in_a_list_can_be_analysed():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a v6 CIDR row expands to bare addresses, and each one parses (one bad row failed the job)."""
    import bulk_test
    import path_analyzer
    # Arrange
    parsed = bulk_test.parse("2001:db8::/126\n[2001:db8::9]:443\nexample.com")
    # Act
    hosts = [path_analyzer.parse_destination(t)["host"] for t in parsed.targets]
    # Assert
    assert hosts[:4] == ["2001:db8::", "2001:db8::1", "2001:db8::2", "2001:db8::3"] and "2001:db8::9" in hosts and "example.com" in hosts


@pytest.mark.parametrize("typed", ["2001:db8::zz", ":::", "2001:db8::1::2"])
def test_a_malformed_ipv6_address_is_refused_in_words(typed):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: negative: text that only looks like IPv6 is refused with a sentence, not placed."""
    import path_analyzer
    with pytest.raises(ValueError, match="not a URL, hostname or IP address"):
        path_analyzer.parse_destination(typed)


# ── C6-DEPLOY-16: a partial single-pack deploy can be undone ──────────

CREDS = {"cloud": "zscalertwo", "vanity_domain": "acme", "client_id": "acmeclient0001", "client_secret": "s" * 16}
CREATED = [{"kind": "dictionary", "name": "D", "id": 11, "status": "created"}, {"kind": "policy", "name": "R", "id": 12, "status": "failed"}]


@pytest.fixture
def import_route(monkeypatch):
    import pack_deploy
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: object())        # never a real tenant
    monkeypatch.setattr(srv, "_resolve_pack_ids", lambda ids: [{"id": "alpha"}])

    def answer(status, results):
        monkeypatch.setattr(pack_deploy, "apply", lambda client, packs, **kw: {"status": status, "results": results,
                                                                                "summary": {"created": sum(r["status"] == "created" for r in results)}})
        return TestClient(srv.app).post("/api/dlp-packs/alpha/import", json=dict(CREDS, plan_hash="h", assessor="Jane Doe", confirm=True))
    return answer


@pytest.mark.parametrize("status", ["applied", "partial"])
def test_a_single_pack_deploy_that_created_objects_is_recorded_for_undo(import_route, status):
    """ASVS V7.4.1 · CWE-755 · WSTG-BUSL-01: a partial deploy created objects too: they are recorded, so Undo can remove them."""
    import deployments
    # Act
    r = import_route(status, CREATED)
    # Assert
    assert r.status_code == 200, r.text[:200]
    recs = deployments._read()["deployments"]
    assert [(x["status"], [c["id"] for c in x["created"]]) for x in recs] == [(status, [11])]


@pytest.mark.parametrize("status,results", [("failed", [dict(CREATED[1])]), ("plan_changed", CREATED), ("blocked", CREATED)])
def test_a_single_pack_deploy_that_created_nothing_records_nothing(import_route, status, results):
    """ASVS V7.4.1 · CWE-755 · WSTG-BUSL-01: negative: nothing created, or a deploy that never ran, leaves no record to undo."""
    import deployments
    r = import_route(status, results)
    assert r.status_code == 200 and deployments._read().get("deployments", []) == []


# ── C6-DEPLOY-17: the rebuild filter is documented as what it is ─────────

def test_the_rebuild_name_filter_is_documented_and_matched_as_literal_text():
    """ASVS V1.1.2 · CWE-1116 · CWE-1333: the field's comment says literal text (no regex), and a regex-looking filter matches only literally."""
    import inspect
    import pack_from_tenant as pft
    # Arrange
    line = next(x for x in inspect.getsource(srv.PackFromTenantRequest).splitlines() if "name_filter" in x)
    # Act / Assert
    assert "literal" in line and "regex" not in line.replace("never a regex", "")
    assert not pft._filter_matches("a.c", "abc") and pft._filter_matches("a.c", "x a.c y") and pft._filter_matches("^SRC-", "src-ssn")


# ── C6-EXPORTS-09: the rate forecast is not quadratic ───────────────────

def _scan_simulate(rules, prior, start, n):
    """The forecast as it was (a scan of every request per step): the oracle."""
    sim, out, t = sorted(prior), [], start
    for _ in range(n):
        wait_s = 0.0
        for lim, w in rules:
            inside = [x for x in sim if t - x < w]
            if len(inside) >= lim:
                wait_s = max(wait_s, inside[-lim] + w - t)
        t += max(0.0, wait_s)
        sim.append(t)
        out.append(t)
    return out


def test_the_rate_forecast_gives_the_same_times_as_the_scan():
    """ASVS V11.1.4 · CWE-407 · SSDF PW.8.2: oracle: on 300 seeded random runs the bisecting forecast equals the scan, to the bit."""
    import zia_rate
    rng = random.Random(6)
    for _ in range(300):
        rules = [(rng.randint(1, 20), rng.choice([1.0, 10.0, 60.0, 3600.0, rng.random() * 100])) for _ in range(rng.randint(1, 3))]
        start = rng.random() * 1000
        prior = [start - rng.random() * 4000 for _ in range(rng.randint(0, 60))]
        n = rng.randint(0, 80)
        assert zia_rate._simulate(rules, prior, start, n) == _scan_simulate(rules, prior, start, n)


def test_the_rate_forecast_looks_at_log_n_requests_per_step(monkeypatch):
    """ASVS V11.1.4 · CWE-407 · WSTG-BUSL-05: 2,000 requests touch the request list O(n log n) times, not n squared (a 10k-rule pack took minutes)."""
    import zia_rate
    touched = [0]

    class Counted(list):
        def __iter__(self):
            for x in list.__iter__(self):
                touched[0] += 1
                yield x

        def __getitem__(self, i):
            touched[0] += 1
            return list.__getitem__(self, i)
    monkeypatch.setattr(zia_rate, "sorted", lambda xs: Counted(list(xs)), raising=False)
    # Act
    zia_rate._simulate([(10, 1.0), (400, 60.0)], [], 0.0, 2000)
    # Assert: the scan visits about n^2 / 2 = 2,000,000 per rule
    assert touched[0] < 2000 * 2 * 40, touched[0]


# ── C6-EXPORTS-10: a captured framework names every rule it cut ──────────

def test_a_framework_capture_names_each_rule_past_the_cap():
    """ASVS V8.3.1 · CWE-223 · WSTG-BUSL-01: past MAX_FRAMEWORK_RULES rules, each rule left out is named with the reason, not only counted."""
    import ops_zia_baseline as zb
    import test_ops_zia_baseline as zt
    # Arrange
    cap = zb.MAX_FRAMEWORK_RULES
    many = [{"id": 100 + i, "name": f"Block {i}", "order": i + 1, "state": "ENABLED", "action": "BLOCK", "url_categories": ["GAMBLING"]}
            for i in range(cap + 3)]
    # Act
    fw = zb.capture(zt.Tenant(url=many), ["url"], tenant_label="src")["framework"]
    # Assert
    cut = [x for x in fw["not_exported"] if "fit in a framework" in x["reason"]]
    assert [x["name"] for x in cut] == [f"Block {i}" for i in range(cap, cap + 3)] and len(fw["areas"]["url"]) == cap


# ── C6-MIGRATE-32 / -33: the Evaluate All routes refuse what they cannot do ──

@pytest.mark.parametrize("fmt,status", [("json", 200), ("csv", 200), ("xml", 400), ("CSV", 400), ("", 400)])
def test_a_migration_export_in_an_unknown_format_is_a_400(fmt, status):
    """ASVS V5.1.3 · CWE-754 · WSTG-INPV-01: only json and csv are exports; any other format was a 200 empty CSV file."""
    r = TestClient(srv.app).post(f"/api/migrate/export?format={fmt}", json={"rules": [{"id": 1, "name": "R", "action": "ALLOW"}]})
    assert r.status_code == status, r.text[:200]


@pytest.mark.parametrize("mode", ["delete", "UPDATE", ""])
@pytest.mark.parametrize("dry_run", [True, False])
def test_an_unknown_post_mode_is_refused_by_the_route_before_any_gate_or_sign_in(monkeypatch, mode, dry_run):
    """ASVS V4.1.5 · CWE-841 · WSTG-BUSL-01: a mode other than auto/create/update is a 400 before the write gates and before sign-in."""
    signed_in = []
    monkeypatch.setattr(srv, "_build_client", lambda req: signed_in.append(1))
    body = dict(CREDS, proposed_rules=[{"id": 1, "name": "R"}], dry_run=dry_run, mode=mode, scopes=["dlp"], channels={"web_dlp": "zscaler"})
    r = TestClient(srv.app).post("/api/migrate/post", json=body)
    assert r.status_code == 400 and "mode must be one of" in r.text and signed_in == []


def test_a_known_post_mode_still_meets_the_write_gate():
    """ASVS V4.1.5 · CWE-841: negative control: mode=update with dry_run=false is still stopped by write mode (403), not by the mode check."""
    body = dict(CREDS, proposed_rules=[{"id": 1, "name": "R"}], dry_run=False, mode="update", confirm=True, assessor="Jane Doe",
                plan_hash="h", scopes=["dlp"], channels={"web_dlp": "zscaler"})
    r = TestClient(srv.app).post("/api/migrate/post", json=body)
    assert r.status_code == 403, r.text[:200]


# ── C6-PATH-26 / C6-POSTURE-15: shared normalizers and non-list fields ────

ODD = [None, 0, 7, 1e308, True, {}, {"a": 1}, [None], [{}]]


def _normalizers():
    import data_flow
    import ssl_flow
    import zpa_reader as zr
    seg = {"id": "1", "name": "s"}
    return {
        "ssl_flow._names": lambda v: ssl_flow._names(v),
        "ssl_flow._sort_key": lambda v: ssl_flow._sort_key({"id": v, "order": v}),
        "data_flow._norm_generic actions": lambda v: data_flow._norm_generic({"id": 1, "actions": v}),
        "data_flow._norm_generic urlCategories": lambda v: data_flow._norm_generic({"id": 1, "urlCategories": v}),
        "zpa_reader.normalize_segment domainNames": lambda v: zr.normalize_segment(dict(seg, domainNames=v)),
        "zpa_reader.normalize_segment serverGroups": lambda v: zr.normalize_segment(dict(seg, serverGroups=v)),
        "zpa_reader.normalize_segment appsConfig": lambda v: zr.normalize_segment(dict(seg, commonAppsDto={"appsConfig": v})),
        "zpa_reader.normalize_segment appTypes": lambda v: zr.normalize_segment(dict(seg, commonAppsDto={"appsConfig": [{"appTypes": v}]})),
        "zpa_reader.normalize_server_group servers": lambda v: zr.normalize_server_group({"id": "2", "servers": v}),
        "zpa_reader.normalize_connector_group connectors": lambda v: zr.normalize_connector_group({"id": "3", "connectors": v, "serverGroups": v}),
        "zpa_reader.normalize_service_edge_group serviceEdges": lambda v: zr.normalize_service_edge_group({"id": "4", "serviceEdges": v}),
        "zpa_reader.normalize_rule conditions": lambda v: zr.normalize_rule({"id": "5", "conditions": v}, 0, "access"),
        "zpa_reader.normalize_rule operands": lambda v: zr.normalize_rule({"id": "5", "conditions": [{"operands": v}]}, 0, "access"),
        "zpa_reader.normalize_rule values": lambda v: zr.normalize_rule({"id": "5", "conditions": [{"operands": [{"objectType": "APP", "values": v,
                                                                                                                    "entryValues": v}]}]}, 0, "access"),
    }


NORMALIZERS = _normalizers()


@pytest.mark.parametrize("name", sorted(NORMALIZERS))
def test_a_list_field_of_the_wrong_type_never_stops_a_shared_normalizer(name):
    """ASVS V5.1.4 · CWE-843 · CWE-1287 · WSTG-INPV-01: table over the shared normalizers: a number, true or an object where a list belongs reads as no item."""
    for v in ODD:
        NORMALIZERS[name](v)   # Act / Assert: no TypeError for any odd value


def test_one_string_where_a_list_belongs_is_one_item_not_its_characters():
    """ASVS V5.1.4 · CWE-843 · WSTG-INPV-01: a bare "ALLOW" action or one domain sent as text is one item, never one per character."""
    import data_flow
    import zpa_reader as zr
    assert data_flow._norm_generic({"id": 1, "actions": "allow"})["actions"] == ["ALLOW"]
    assert zr.normalize_segment({"id": "1", "domainNames": "a.example"})["domains"] == ["a.example"]
    assert zr.normalize_connector_group({"id": "3", "serverGroups": "2301"})["server_group_ids"] == ["2301"]


# ── C6-SCOPE-OFFLINE-16: the ZCC company check names the company ──────────

@pytest.mark.parametrize("body,shown", [({"businessName": "Larkspur Freight", "orgId": 1}, "Company: Larkspur Freight"),
                                        ({"companyName": "Old field"}, "Company: Old field"), ({}, "Company: ?")])
def test_the_zcc_company_check_reads_business_name(body, shown):
    """ASVS V5.1.3 · CWE-1287: getCompanyInfo names the company businessName (SDK 1.11.3 zcc/models/company_info.py); it always said '?'."""
    import zscaler_full_checks as zfc
    cl = types.SimpleNamespace(get=lambda path, *a, **k: (body, 200))
    assert zfc.zcc_5(cl).detail == shown


# ── C6-SCOPE-OFFLINE-17: an unreadable channel declaration narrows to nothing ──

PROFILE = {"name": "Saved", "scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler"}}


@pytest.fixture
def saved_profile(monkeypatch):
    import tenant_profiles
    monkeypatch.setattr(tenant_profiles, "get", lambda pid: dict(PROFILE) if pid == "p1" else None)


@pytest.mark.parametrize("channels", [{"": "zscaler"}, {"   ": "zscaler"}, {"no_such_channel": None}])
def test_an_unreadable_channel_declaration_puts_no_channel_in_scope(saved_profile, channels):
    """ASVS V4.1.3 · CWE-636 · WSTG-ATHZ-02: a non-empty declaration none of whose entries can be read makes every channel a gap (fail closed), never 'nothing narrowed'."""
    req = types.SimpleNamespace(scopes=["dlp"], channels=channels, profile_id="", from_page=False)
    with pytest.raises(HTTPException) as e:
        srv._require_in_scope(req, "dlp", "Inline Web DLP", "web_dlp")
    assert e.value.status_code == 400


def test_an_unreadable_channel_declaration_never_falls_back_to_the_saved_profile(saved_profile):
    """ASVS V4.1.3 · CWE-636 · WSTG-ATHZ-02: the page sent a declaration, so the wider saved profile is not read instead (user rule 1)."""
    req = types.SimpleNamespace(scopes=[], channels={"": "zscaler"}, profile_id="p1", from_page=False)
    sc, _ch, source = srv._scope_selection(req)
    assert (sc, source) == ([], "the Scope page")
    with pytest.raises(HTTPException) as e:
        srv._beacon_scope([], {"": "zscaler"}, profile_id="p1")
    assert e.value.status_code == 400


def test_with_nothing_sent_the_saved_profile_is_still_used(saved_profile):
    """ASVS V4.1.3 · CWE-636: negative control: an empty declaration from a page that sent nothing reads the saved profile, as before."""
    req = types.SimpleNamespace(scopes=[], channels={}, profile_id="p1", from_page=False)
    sc, _ch, source = srv._scope_selection(req)
    assert sc == PROFILE["scopes"] and source == "the saved profile Saved"


# ── C6-TOOLTIPS-06: the browser harness never runs the updater ────────────

UPDATE_DRIVER = r"""
const base = process.argv[3];
const post = async p => { const r = await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  return { status: r.status, body: await r.json() }; };
console.log(JSON.stringify({ update: await post('/api/app/update'), restart: await post('/api/app/restart') }));
"""


def test_the_browser_harness_never_runs_the_updater_or_a_restart(monkeypatch, tmp_path):
    """ASVS V14.1.1 · CWE-1188 · SSDF PO.5.1: a page toured by the shared harness that clicks Update now or Restart never runs git on the checkout or relaunches."""
    import app_update
    from test_findings_reflow import run_in_browser
    # Arrange: what the real ones would reach, recorded instead of run
    reached = []
    monkeypatch.setattr(app_update, "update", lambda *a, **k: reached.append("update") or {"ok": False})
    monkeypatch.setattr(app_update, "schedule_restart", lambda *a, **k: reached.append("restart") or {"ok": False})
    monkeypatch.setattr(app_update, "in_container", lambda: False)
    monkeypatch.setattr(app_update, "in_standalone", lambda: False)
    monkeypatch.setattr(app_update, "current_branch", lambda app_dir: "main")
    # Act
    out = run_in_browser(tmp_path, UPDATE_DRIVER)
    # Assert
    assert reached == [] and out["update"]["body"].get("message") == "disabled in tests", out


# ── C6-TRAFFIC-REPORTS-27: a ZIP member whose offset lies is refused ──────

def _zip_with_lying_offset(shift):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("a.json", "{}")
    data = bytearray(buf.getvalue())
    eocd = data.rfind(b"PK\x05\x06")
    struct.pack_into("<I", data, eocd + 16, struct.unpack_from("<I", data, eocd + 16)[0] + shift)
    return zipfile.ZipFile(io.BytesIO(bytes(data)))


@pytest.mark.parametrize("shift", [1, 100, 10_000])
def test_a_zip_member_whose_header_offset_lies_is_refused_as_an_archive_error(shift):
    """ASVS V7.4.1 · ASVS V12.1.2 · CWE-755 · WSTG-INPV-01: a central directory placed past its real start (a negative member offset) is ArchiveRefused, never a ValueError callers miss."""
    import safe_files
    z = _zip_with_lying_offset(shift)
    with pytest.raises(safe_files.ArchiveRefused, match="damaged or not what it claims"):
        safe_files.zip_member(z, z.infolist()[0], 1000)


def test_an_intact_member_is_still_read():
    """ASVS V12.1.2 · CWE-755: negative control: a ZIP whose offsets are true is read whole."""
    import safe_files
    z = _zip_with_lying_offset(0)
    assert safe_files.zip_member(z, z.infolist()[0], 1000) == b"{}"


# ── C6-ADMIN-OPS-22: local stores' lock files stay out of commits ─────────

@pytest.mark.parametrize("module", ["proposals", "change_queue", "workspace_notes"])
def test_every_store_lock_file_is_git_ignored(module):
    """ASVS V14.1.1 · CWE-538 · SSDF PS.1.1: table over the stores that lock <store>.lock beside the app: each lock file is in .gitignore."""
    import importlib
    if not shutil.which("git") or not os.path.isdir(os.path.join(ROOT, ".git")) and not os.path.isfile(os.path.join(ROOT, ".git")):
        pytest.skip("needs a git checkout")
    name = importlib.import_module(module).STORE_FILE + ".lock"
    r = subprocess.run(["git", "check-ignore", "-q", "--no-index", name], cwd=ROOT, timeout=30)
    assert r.returncode == 0, f"{name} is not ignored"


# ── C6-API-SERVER-14: the outermost refusals carry the hardening headers ───

def _capped_app(limit=8):
    import security

    async def echo(scope, receive, send):   # reads the whole body, then answers its length
        body, more = b"", True
        while more:
            m = await receive()
            body, more = body + m.get("body", b""), m.get("more_body", False)
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", b"text/plain")]})
        await send({"type": "http.response.body", "body": str(len(body)).encode()})
    return security.BodySizeLimitMiddleware(echo, max_bytes=limit)


def _over_declared(c):
    return c.post("/api/x", content=b"x" * 9)


def _over_streamed(c):
    return c.post("/api/x", content=iter([b"x" * 5, b"x" * 5]))


def _bad_length(c):
    return c.post("/api/x", content=b"x", headers={"content-length": "abc"})


@pytest.mark.parametrize("send,status", [(_over_declared, 413), (_over_streamed, 413), (_bad_length, 400)],
                         ids=["declared", "streamed", "invalid-length"])
def test_the_body_cap_refusals_carry_the_hardening_headers(send, status):
    """ASVS V14.4.3 · ASVS V14.4.4 · ASVS V14.4.7 · CWE-693 · WSTG-CLNT-09: the body cap answers outside the headers layer, with CSP, nosniff, frame denial and no-store."""
    import security
    r = send(TestClient(_capped_app()))
    h = r.headers
    assert r.status_code == status
    assert (h.get("x-content-type-options"), h.get("x-frame-options"), h.get("content-security-policy"), h.get("cache-control")) == \
        ("nosniff", "DENY", security.CONTENT_SECURITY_POLICY, "no-store")


def test_a_body_within_the_cap_is_answered_by_the_app():
    """ASVS V12.1.1 · CWE-770: boundary: exactly the cap reaches the app."""
    r = TestClient(_capped_app()).post("/api/x", content=b"x" * 8)
    assert (r.status_code, r.text) == (200, "8")


# ── C6-UI-OPS-18: the HAR note counts every host left out ─────────────────

def _har(n_hosts):
    return json.dumps({"log": {"entries": [{"request": {"url": f"https://h{i}.example/p", "method": "GET", "bodySize": 0}} for i in range(n_hosts)]}})


@node
@pytest.mark.parametrize("hosts,heading,summary", [
    (1700, "1500 more host(s) not analyzed", "Show the first 1000 of the 1500 host(s) left out"),
    (205, "5 more host(s) not analyzed", "Show the 5 host(s) left out"),
])
def test_the_har_note_counts_every_host_left_out_not_only_the_listed(tmp_path, hosts, heading, summary):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: past the listing cap the note says how many hosts were left out in all, not the 1,000 listed."""
    (tmp_path / "a.har").write_text(_har(hosts))
    got = _node(tmp_path, "import fs from 'node:fs'; import { createRequire } from 'node:module'; const m = createRequire(import.meta.url)(process.argv[2]);"
                          "console.log(JSON.stringify(m.leftOut(m.parse(fs.readFileSync(process.argv[3], 'utf8')))));",
                os.path.join(STATIC, "har_parse.js"), str(tmp_path / "a.har"))
    assert (got["heading"], got["summary"], got["note"]) == (heading, summary, "")


@node
def test_the_har_note_names_requests_to_hosts_past_the_tracking_cap(tmp_path):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-05: requests to hosts past MAX_TRACKED are counted in the note, never silently dropped."""
    got = _node(tmp_path, "import { createRequire } from 'node:module'; const m = createRequire(import.meta.url)(process.argv[2]);"
                          "console.log(JSON.stringify(m.leftOut({ more: [], more_total: 0, untracked: 7, capped: true })));",
                os.path.join(STATIC, "har_parse.js"))
    assert got["heading"] == "7 request(s) to further hosts not analyzed" and "past the 20000" in got["note"] and got["summary"] == ""


def test_the_path_page_draws_the_note_from_the_counted_total():
    """ASVS V5.3.3 · CWE-79 · CWE-400: the Path analyzer's note uses HarParse.leftOut (escaped), not the length of the capped list."""
    page = open(os.path.join(STATIC, "report_path.html"), encoding="utf-8").read()
    body = page[page.index("function moreNote(p)"):page.index("function renderHarIntro()")]
    assert "HarParse.leftOut(p)" in body and "E(L.heading)" in body and "${p.more.length} more host" not in body


# ── C6-ZIA-BASELINE-AIGUARD-25: the form flags weaker choices as the review does ──

@node
def test_the_baseline_form_flags_weaker_choices_exactly_as_the_server_review(tmp_path):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-01: table over every rule and choice of the Strict tier: the form's 'weaker than the tier' equals ops_zia_baseline.review's."""
    import ops_zia_baseline as zb
    # Arrange: the server's verdict for each (rule, choice)
    cases = []
    for choice in ("ALLOW", "BLOCK", "ISOLATE"):
        for row in zb.review({"tier": "strict", "rules": {r["key"]: {"action": choice} for r in zb.CATALOG}})["rules"]:
            cases.append({"r": {"key": row["key"], "def": row["default_action"], "default_on": row["default_on"], "choices": row["choices"],
                                "locked": row["locked"], "action_locked": row["action_locked"]},
                          "choice": choice, "want": row["weakened"]})
    (tmp_path / "cases.json").write_text(json.dumps(cases))
    # Act: the form's own effective() on the same rows
    got = _node(tmp_path, "import fs from 'node:fs'; import vm from 'node:vm';"
                          "const regs = []; const ctx = { window: { OPS_PLUGINS: { register: p => regs.push(p) } } };"
                          "vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), ctx);"
                          "const eff = regs.find(p => p.type === 'zia_baseline').effective;"
                          "const cases = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));"
                          "console.log(JSON.stringify(cases.map(c => eff(c.r, { mode: 'tier', rules: { [c.r.key]: { action: c.choice } } }).weakened)));",
                os.path.join(STATIC, "ops_zia_baseline.js"), str(tmp_path / "cases.json"))
    # Assert
    diff = [(c["r"]["key"], c["choice"], c["want"], g) for c, g in zip(cases, got) if c["want"] != g]
    assert diff == [] and any(c["want"].endswith("→ Isolate") for c in cases)


# ── The findings records the score reads (tools/quality_score.py) ─────────

def _record(**finding):
    f = {"id": "C6-OPEN-B-01", "title": "Fixture", "severity": "low", "status": "fixed", **finding}
    return {"area": "a", "title": "t", "findings": [f]}


PATCH = "--- a/x.py\n+++ b/x.py\n@@ -1 +1 @@\n-\told = 1\r\n+\tnew = 2\n"


@pytest.mark.parametrize("rec", [
    _record(proposed_patch=PATCH),
    _record(files=["dlp_api_server.py", "static/find_anything.js"]),
    _record(commit="cb3d1b3, d1fc71f"),
    dict(_record(), coverage={"before": 80.0, "after": 90.5, "method": "coverage --branch", "per_file": {"a.py": [70, 90]}}),
], ids=["multi-line patch", "finding files", "two commits", "coverage context"])
def test_the_wave_6_record_fields_are_accepted(rec):
    """ASVS V5.1.3 · CWE-20 · SSDF PW.8.2: the fields the wave-6 records carry (a diff, files, several commits, coverage context) validate."""
    import quality_score as qs
    assert qs.validate_record(rec, "c6-open-b")["findings"][0]["id"] == "C6-OPEN-B-01"


@pytest.mark.parametrize("rec", [
    _record(proposed_patch=PATCH + "‮gnp.exe\n"),
    _record(proposed_patch="a\x1b[31m red\n"),
    _record(commit="cb3d1b3,d1fc71f; rm -rf /"),
    _record(files=["<img src=x>"]),
    dict(_record(), coverage={"before": 80, "after": 90, "how": "line‮"}),
    dict(_record(), coverage={"before": 80, "after": 101}),
    dict(_record(), coverage={"before": 80, "after": 90, "detail": "x" * 9000}),
    dict(_record(), coverage=[80, 90]),
], ids=["patch bidi override", "patch escape sequence", "commit list injection", "markup file", "context bidi",
        "coverage over 100", "context too large", "coverage not an object"])
def test_the_wave_6_record_fields_stay_untrusted_input(rec):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20 · CWE-451 · CWE-400: negative: those fields still refuse control and bidi characters, markup, bad commits and oversize context."""
    import quality_score as qs
    with pytest.raises(qs.InputError):
        qs.validate_record(rec, "c6-open-b")
