"""Client Connector fleet depth (zcc_fleet, zcc_fleet_import, zcc_fleet_history;
/api/zcc/fleet/*): the version x service matrix, health per app and
forwarding profile, the last-seen histogram, site grouping (no free regex),
the counts-only history with trend and compare, the import of the Client
Connector Portal's CSV exports as untrusted input, and the PDF and Excel
exports. Fakes and fixtures only: no tenant, no network, no clock."""
from __future__ import annotations

import base64
import gzip
import io
import json
import os
import stat
import threading
import time
import zipfile
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import zcc_fleet as zf
import zcc_fleet_history as zh
import zcc_fleet_import as zi

NOW = datetime(2026, 10, 30, 12, 0, 0, tzinfo=timezone.utc)
ZCC_SCOPE = {"scopes": ["zcc"], "channels": {}, "from_page": True}
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


def ago(**kw):
    return (NOW - timedelta(**kw)).strftime("%Y-%m-%d %H:%M:%S")


def dev(n, *, plat=3, ver="4.7.2.5", reg="Registered", seen=None, policy="Corp Windows", host=None, user=None):
    return {"user": user or f"user{n}@acme.example", "machineHostname": host or f"LON-LT-{n:03d}", "type": plat, "agentVersion": ver,
            "registrationState": reg, "last_seen_time": seen if seen is not None else ago(hours=1), "policyName": policy,
            "udid": f"UDID-{n}", "osVersion": "Windows 11"}


def svc_row(d, zia, zpa, zdx):
    return {"user": d["user"], "udid": d["udid"], "hostname": d["machineHostname"], "zia": zia, "zpa": zpa, "zdx": zdx}


def normalized(devices, rows):
    return zf.normalize_devices(devices, rows, NOW)


# A fleet with known numbers: 20 devices on 4.7.2.5 (ZIA 19 of 20 active), 10 on 4.6.0.1 (ZIA 6 of 10 active,
# 60% against a fleet of 25 of 34 = 73.5%: 13.5 points below), 4 on 4.5.0.10 (ZIA 0 of 4: too few known to flag),
# 2 macOS on 4.5.2.1 with no service row, one quarantined and one unregistered device (never counted).
def fleet():
    devices, rows = [], []
    n = 0
    for i in range(20):
        n += 1
        d = dev(n)
        devices.append(d)
        rows.append(svc_row(d, "Active" if i < 19 else "Inactive", "Active", "Active"))
    for i in range(10):
        n += 1
        d = dev(n, ver="4.6.0.1", policy="Contractors", host=f"NYC-LT-{n:03d}")
        devices.append(d)
        rows.append(svc_row(d, "Active" if i < 6 else "Inactive", "Active", "Active" if i < 9 else "Inactive"))
    for i in range(4):
        n += 1
        d = dev(n, ver="4.5.0.10", policy="Contractors", host=f"NYC-LT-{n:03d}")
        devices.append(d)
        rows.append(svc_row(d, "Inactive", "Active", "N/A"))
    for i in range(2):
        n += 1
        devices.append(dev(n, plat=4, ver="4.5.2.1", policy="Corp Mac", host=f"PAR-MB-{n:03d}"))
    n += 1
    devices.append(dev(n, reg="Quarantined", host=f"LON-LT-{n:03d}"))
    n += 1
    devices.append(dev(n, reg="Unregistered", host=f"LON-LT-{n:03d}"))
    return devices, rows


PROFILES = [{"name": "Corp Windows", "platform": "Windows", "forwarding_profile": "Corp forwarding", "score": 95.0},
            {"name": "Contractors", "platform": "Windows", "forwarding_profile": "Contractor forwarding", "score": 40.0},
            {"name": "Corp Mac", "platform": "macOS", "forwarding_profile": None, "score": 80.0}]


# ── the version x service matrix ─────────────────────────────────────────
def test_version_matrix_counts_registered_devices_per_version_and_service():
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: each version row counts its registered devices and each service's active share among the known ones."""
    devs = normalized(*fleet())
    vh = zf.version_health(devs, True)
    rows = {(r["platform"], r["version"]): r for r in vh["rows"]}
    assert set(rows) == {("Windows", "4.7.2.5"), ("Windows", "4.6.0.1"), ("Windows", "4.5.0.10"), ("macOS", "4.5.2.1")}
    w47 = rows[("Windows", "4.7.2.5")]
    assert w47["devices"] == 20 and w47["services"]["zia"] == dict(active=19, inactive=1, not_applicable=0, unknown=0, known=20, percent=95.0)
    assert w47["newest"] and not w47["unsupported"] and w47["share"] == round(100 * 20 / 34, 1)
    w45 = rows[("Windows", "4.5.0.10")]
    assert w45["services"]["zdx"]["not_applicable"] == 4 and w45["services"]["zdx"]["percent"] is None and w45["unsupported"]
    mac = rows[("macOS", "4.5.2.1")]
    assert mac["services"]["zia"]["unknown"] == 2 and mac["services"]["zia"]["percent"] is None and mac["share"] == 100.0
    assert vh["fleet"]["zia"]["known"] == 34 and vh["fleet"]["zia"]["active"] == 25   # quarantined and unregistered left out
    assert [r["version"] for r in vh["rows"] if r["platform"] == "Windows"] == ["4.7.2.5", "4.6.0.1", "4.5.0.10"]   # newest first


def test_a_version_far_below_the_fleet_is_flagged_only_with_enough_known_devices():
    """ASVS V11.1.4 · CWE-682: a cell 10 or more points below the fleet with at least 5 known devices is flagged; 4 known devices never are."""
    vh = zf.version_health(normalized(*fleet()), True)
    rows = {r["version"]: r for r in vh["rows"]}
    assert rows["4.6.0.1"]["below_fleet"] == ["zia"]          # 60.0 against 73.5 (25 of 34): 13.5 below
    assert rows["4.5.0.10"]["below_fleet"] == []              # 0% but only 4 known: not flagged
    assert rows["4.7.2.5"]["below_fleet"] == []
    # The boundary itself: exactly 10 points below flags, 9.9 does not.
    fleet_pct = {"zia": {"percent": 80.0}, "zpa": {"percent": None}, "zdx": {"percent": 50.0}}
    at = {"zia": {"percent": 70.0, "known": 5}, "zpa": {"percent": 10.0, "known": 9}, "zdx": {"percent": 40.1, "known": 50}}
    assert zf._below(at, fleet_pct) == ["zia"]


def test_without_service_status_the_matrix_counts_devices_and_shows_no_share():
    """ASVS V11.1.4 · CWE-754 · WSTG-ERRH-01: no service status means no share (unknown), never 0% or 100%."""
    devices, _ = fleet()
    vh = zf.version_health(normalized(devices, []), False)
    assert all(r["services"][s]["percent"] is None for r in vh["rows"] for s in zf.SERVICES)
    assert sum(r["devices"] for r in vh["rows"]) == 36 and not vh["service_read"]


# ── health per app and forwarding profile ────────────────────────────────
def test_profile_health_rolls_app_profiles_up_to_their_forwarding_profiles():
    """ASVS V11.1.4 · CWE-682: devices count under the app profile they report, and through the read app profile under its forwarding profile."""
    ph = zf.profile_health(normalized(*fleet()), True, PROFILES)
    apps = {(r["name"], r["platform"]): r for r in ph["app_profiles"]}
    assert apps[("Corp Windows", "Windows")]["devices"] == 20 and apps[("Corp Windows", "Windows")]["forwarding_profile"] == "Corp forwarding"
    con = apps[("Contractors", "Windows")]
    assert con["devices"] == 14 and con["services"]["zia"]["active"] == 6 and con["services"]["zia"]["known"] == 14 and con["score"] == 40.0
    assert con["below_fleet"] == ["zia"]
    fwd = {g["name"]: g for g in ph["forwarding_profiles"]}
    assert fwd["Corp forwarding"]["devices"] == 20 and fwd["Contractor forwarding"]["devices"] == 14
    assert fwd["Contractor forwarding"]["services"]["zia"]["percent"] == 42.9
    assert fwd["(no forwarding profile linked)"]["devices"] == 2 and not fwd["(no forwarding profile linked)"]["known"]


def test_a_device_on_an_app_profile_that_was_not_read_has_an_unknown_forwarding_profile():
    """ASVS V11.1.4 · CWE-754: an app profile the read did not find is never guessed onto a forwarding profile."""
    ph = zf.profile_health(normalized([dev(1, policy="Ghost profile"), dev(2, policy="")], []), False, PROFILES)
    names = {r["name"]: r for r in ph["app_profiles"]}
    assert not names["Ghost profile"]["matched"] and names["Ghost profile"]["forwarding_profile"] is None
    assert zf.NO_PROFILE in names
    assert [g["name"] for g in ph["forwarding_profiles"]] == ["(not known: app profile not read)"]


# ── last seen ────────────────────────────────────────────────────────────
@pytest.mark.parametrize("seen,bucket", [
    (dict(hours=24), "under_1d"), (dict(hours=24, seconds=1), "1_7d"), (dict(days=7), "1_7d"), (dict(days=7, seconds=1), "7_30d"),
    (dict(days=30), "7_30d"), (dict(days=30, seconds=1), "over_30d"), (dict(days=400), "over_30d"), (None, "never")])
def test_last_seen_buckets_are_exact_to_the_second(seen, bucket):
    """ASVS V11.1.4 · CWE-682 · WSTG-BUSL-01: table over each bucket edge: at most 24 hours, 7 days and 30 days, to the second; no time is never."""
    d = normalized([dev(1, seen=ago(**seen) if seen else "")], [])[0]
    assert zf.last_seen_bucket(d) == bucket


def test_the_histogram_counts_registered_devices_only_and_per_platform():
    """ASVS V11.1.4 · CWE-682: the histogram adds up to the registered devices; quarantined and unregistered ones are left out."""
    devices = [dev(1), dev(2, seen=ago(days=3)), dev(3, seen=ago(days=45)), dev(4, seen=""), dev(5, plat=4, seen=ago(days=10)),
               dev(6, reg="Quarantined", seen=ago(days=90)), dev(7, reg="Unregistered")]
    h = zf.last_seen_histogram(normalized(devices, []))
    assert {b["key"]: b["devices"] for b in h["buckets"]} == {"under_1d": 1, "1_7d": 1, "7_30d": 1, "over_30d": 1, "never": 1}
    assert h["registered"] == 5 and sum(b["percent"] for b in h["buckets"]) == pytest.approx(100.0)
    assert h["by_platform"]["macOS"]["7_30d"] == 1 and "a ghost is more than 31" in h["definition"]


# ── sites ────────────────────────────────────────────────────────────────
def test_sites_by_prefix_delimiter_and_list():
    """ASVS V11.1.4 · CWE-682: a prefix length, a delimiter and a pick list each name the expected sites."""
    devs = normalized(*fleet())
    pre = {g["site"]: g for g in zf.site_groups(devs, {"mode": "prefix", "length": 3}, True)["groups"]}
    assert set(pre) == {"LON", "NYC", "PAR"} and pre["LON"]["devices"] == 22 and pre["LON"]["registered"] == 20 and pre["LON"]["quarantined"] == 1
    assert pre["NYC"]["services"]["zia"]["percent"] == 42.9 and pre["NYC"]["below_fleet"] == ["zia"] and pre["NYC"]["versions"] == 2
    dl = {g["site"] for g in zf.site_groups(devs, {"mode": "delimiter", "delimiter": "-", "segments": 2}, True)["groups"]}
    assert dl == {"LON-LT", "NYC-LT", "PAR-MB"}
    li = {g["site"]: g["devices"] for g in zf.site_groups(devs, {"mode": "list", "prefixes": "lon, ny, NYC"}, True)["groups"]}
    assert li == {"LON": 22, "NYC": 14, zf.OTHER_SITE: 2}          # the longest matching prefix wins; case does not matter
    assert zf.site_of("SHORT", {"mode": "delimiter", "delimiter": "-", "segments": 1}) == zf.NO_SITE
    assert zf.site_of("ab", {"mode": "prefix", "length": 3}) == zf.NO_SITE
    assert zf.site_groups(devs, {"mode": "none"}, True)["groups"] == []


@pytest.mark.parametrize("rule", [
    {"mode": "regex", "pattern": "(a+)+$"}, {"mode": "prefix", "length": 0}, {"mode": "prefix", "length": 13}, {"mode": "prefix", "length": True},
    {"mode": "prefix", "length": "3; drop"}, {"mode": "delimiter", "delimiter": "*"}, {"mode": "delimiter", "delimiter": "-", "segments": 5},
    {"mode": "list", "prefixes": "(a+)+"}, {"mode": "list", "prefixes": ["ok", "<b>"]}, {"mode": "list", "prefixes": ""},
    {"mode": "list", "prefixes": [f"P{i}" for i in range(201)]}])
def test_a_site_rule_is_never_a_pattern_and_out_of_range_is_refused(rule):
    """ASVS V5.1.3 · CWE-1333 · CWE-20 · WSTG-INPV-01: table over hostile rules: no regular expression mode exists and every field is range-checked."""
    with pytest.raises(ValueError):
        zf.site_rule(rule)


def test_counts_only_merges_sites_too_small_to_hide_a_device():
    """ASVS V8.3.4 · CWE-359: a counts-only site table merges sites with fewer than 3 registered devices, so a site name cannot single one out."""
    devs = normalized(*fleet()) + normalized([dev(90, host="SOLO-1")], [])
    full = {g["site"] for g in zf.site_groups(devs, {"mode": "prefix", "length": 3}, True)["groups"]}
    assert "SOL" in full and "PAR" in full
    co = {g["site"]: g for g in zf.site_groups(devs, {"mode": "prefix", "length": 3}, True, counts_only=True)["groups"]}
    assert "SOL" not in co and "PAR" not in co and co[zf.SMALL_SITES]["devices"] == 3


# ── the run: everything wired into analyze, and the start route ──────────
def _sdk(devices, csv_text):
    from test_zcc_fleet import SDK
    return SDK(devices=devices, csv_text=csv_text)


def _csv(devices, rows, head='"User","Device type","UDID","Hostname","ZIA Status","ZPA Status","ZDX Status"\n'):
    out = head
    for r in rows:
        out += f'"{r["user"]}","Windows","{r["udid"]}","{r["hostname"]}","{r["zia"]}","{r["zpa"]}","{r["zdx"]}"\n'
    return out


def test_analyze_carries_every_new_view_and_a_quarantined_count(monkeypatch):
    """ASVS V11.1.4 · CWE-754: a full run returns the matrix, profile health, last seen, the site groups chosen at start and the quarantined count."""
    from test_zcc_fleet import Raw
    monkeypatch.setattr(zf, "PAGE_PAUSE_SECONDS", 0.0)
    devices, rows = fleet()
    r = zf.run(Raw(), _sdk(devices, _csv(devices, rows)), log=lambda s: None, cancel=threading.Event(), label="acme", now=NOW,
               site={"mode": "prefix", "length": 3})
    assert r["mode"] == "full" and r["kpis"]["quarantined"] == 1 and r["service_read"] and r["source"] == "live"
    assert r["version_health"]["rows"] and r["profile_health"]["app_profiles"] and r["last_seen"]["registered"] == 36
    assert {g["site"] for g in r["sites"]["groups"]} == {"LON", "NYC", "PAR"}


def test_without_devices_the_new_views_are_absent_not_zero(monkeypatch):
    """ASVS V11.1.4 · CWE-754 · WSTG-ERRH-01: configuration only has no matrix, histogram or sites (unknown), never empty tables that read as zero."""
    from test_zcc_fleet import SDK, Raw
    r = zf.run(Raw(), SDK(list_error="HTTP 403"), log=lambda s: None, cancel=threading.Event(), label="acme", now=NOW)
    assert r["mode"] == "configuration"
    assert r["version_health"] is None and r["profile_health"] is None and r["last_seen"] is None and r["sites"] is None


def _api(monkeypatch, sdk=None):
    from test_zcc_fleet import Raw
    built = []
    monkeypatch.setattr(zf, "PAGE_PAUSE_SECONDS", 0.0)
    monkeypatch.setattr(srv, "_build_client", lambda req: (built.append("client"), Raw())[1])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (built.append("sdk"), sdk)[1])
    return TestClient(srv.app), built


def _follow(t, job_id):
    for _ in range(400):
        snap = t.get(f"/api/dlp-packs/jobs/{job_id}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.02)
    raise AssertionError("job did not finish")


def test_a_bad_site_rule_is_refused_before_sign_in(monkeypatch):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a site rule outside the allowed forms is a 400 before any client is built."""
    t, built = _api(monkeypatch)
    r = t.post("/api/zcc/fleet/start", json=dict(CREDS, site={"mode": "regex", "pattern": ".*"}, **ZCC_SCOPE))
    assert r.status_code == 400 and "Grouping must be" in r.json()["detail"] and built == []


def _live_job(monkeypatch, site=None):
    devices, rows = fleet()
    t, built = _api(monkeypatch, _sdk(devices, _csv(devices, rows)))
    body = dict(CREDS, **ZCC_SCOPE)
    if site:
        body["site"] = site
    r = t.post("/api/zcc/fleet/start", json=body)
    assert r.status_code == 200, r.text
    snap = _follow(t, r.json()["job_id"])
    assert snap["status"] == "done", snap
    return t, r.json()["job_id"], snap["result"]


def test_regrouping_sites_needs_no_tenant_and_the_exports_use_it(monkeypatch):
    """ASVS V4.1.3 · CWE-20: regrouping a finished run reads nothing, refuses a bad rule, and the workbook's Sites sheet follows it."""
    t, job, _ = _live_job(monkeypatch)
    import dlp_api_server
    calls = []
    monkeypatch.setattr(dlp_api_server, "_build_client", lambda req: calls.append(1))
    r = t.post(f"/api/zcc/fleet/{job}/sites", json={"site": {"mode": "delimiter", "delimiter": "-", "segments": 1}})
    assert r.status_code == 200 and {g["site"] for g in r.json()["groups"]} == {"LON", "NYC", "PAR"} and calls == []
    assert t.post(f"/api/zcc/fleet/{job}/sites", json={"site": {"mode": "prefix", "length": 99}}).status_code == 400
    assert t.post("/api/zcc/fleet/nosuchjob/sites", json={"site": {"mode": "none"}}).status_code == 404
    x = t.get(f"/api/zcc/fleet/{job}/export?format=xlsx")
    assert x.status_code == 200
    sheets = _sheets(x.content)
    assert "Sites" in sheets and "LON" in sheets["Sites"] and "Grouped by the host name up to its first" in sheets["Sites"]


# ── exports: the workbook and the PDF ─────────────────────────────────────
def _sheets(data: bytes) -> dict:
    """{sheet name: all its text} of an xlsx."""
    import re
    z = zipfile.ZipFile(io.BytesIO(data))
    wb = z.read("xl/workbook.xml").decode()
    names = re.findall(r'<sheet name="([^"]+)"', wb)
    out = {}
    for i, n in enumerate(names, 1):
        out[n.replace("&amp;", "&")] = z.read(f"xl/worksheets/sheet{i}.xml").decode()
    return out


def test_the_workbook_has_the_new_sheets_and_counts_only_names_no_one(monkeypatch):
    """ASVS V8.3.4 · CWE-359 · CWE-1236: the workbook gains version, profile, forwarding, last-seen and site sheets; counts only leaves every user and host name out."""
    t, job, res = _live_job(monkeypatch, site={"mode": "prefix", "length": 6})
    full = _sheets(t.get(f"/api/zcc/fleet/{job}/export?format=xlsx").content)
    for name in ("Version health", "Profile health", "Forwarding health", "Last seen", "Sites"):
        assert name in full, name
    assert "4.6.0.1" in full["Version health"] and "below the fleet" in full["Version health"]
    assert "Contractor forwarding" in full["Forwarding health"]
    co = _sheets(t.get(f"/api/zcc/fleet/{job}/export?format=xlsx&counts_only=true").content)
    text = "".join(co.values())
    assert "user1@acme.example" not in text and "LON-LT-001" not in text
    assert zf.SMALL_SITES.replace("(", "").split()[0] in co["Sites"] or "LON-LT" in co["Sites"]


def test_the_pdf_report_is_counts_only_and_has_every_section(monkeypatch):
    """ASVS V8.3.4 · CWE-359 · WSTG-BUSL-01: the PDF has the tiles, alerts, matrix, profiles, last seen and plan, in A4 or Letter, and names no user or device."""
    t, job, res = _live_job(monkeypatch, site={"mode": "prefix", "length": 3})
    r = t.get(f"/api/zcc/fleet/{job}/export?format=pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf" and r.content.startswith(b"%PDF-1.4")
    assert 'filename="zcc_fleet_report_' in r.headers["content-disposition"]
    body = r.content.decode("latin-1")
    for heading in ("Client Connector fleet", "Service health by Client Connector version", "Health per app profile",
                    "When devices were last seen", "Sites", "Remediation plan", "Counts only"):
        assert heading in body, heading
    assert "user1@acme.example" not in body and "LON-LT-001" not in body and "UDID-1" not in body
    assert t.get(f"/api/zcc/fleet/{job}/export?format=pdf&page=letter").status_code == 200
    assert t.get(f"/api/zcc/fleet/{job}/export?format=pdf&page=a3").status_code == 400
    assert t.get(f"/api/zcc/fleet/{job}/export?format=docx").status_code == 400


# ── history: counts only, owner-only, untrusted when read back ────────────
def test_a_history_snapshot_holds_counts_only(monkeypatch):
    """ASVS V8.3.4 · ASVS V8.1.1 · CWE-359 · CWE-312: a kept snapshot has numbers and versions, never a user, host name, device ID, profile or site."""
    _, _, res = _live_job(monkeypatch, site={"mode": "prefix", "length": 3})
    e = zh.entry(res)
    text = json.dumps(e)
    for leak in ("acme.example", "LON", "NYC", "UDID", "Corp Windows", "Contractors", "forwarding"):
        assert leak not in text, leak
    assert e["devices"] == 38 and e["registered"] == 36 and e["quarantined"] == 1 and e["services"]["zia"]["active"] == 25
    assert e["versions"]["Windows"] == {"4.7.2.5": 20, "4.6.0.1": 10, "4.5.0.10": 4} and e["alerts"]["bypass_risk"] == 9
    with pytest.raises(ValueError):
        zh.entry({"kpis": None})


def test_history_is_owner_only_dedups_a_read_and_keeps_the_newest(tmp_path, monkeypatch):
    """ASVS V8.3.4 · ASVS V12.3.1 · CWE-732 · CWE-400: the history file is 0600, a read saved twice is kept once, and only the newest 60 stay."""
    p = str(tmp_path / "hist.json")
    base = {"at": "2026-10-01T00:00:00+00:00", "devices": 5, "source": "live"}
    zh.record("acme", base, path=p)
    zh.record("acme", dict(base, devices=6), path=p)        # the same read again: replaced, not added
    assert [e["devices"] for e in zh.load("acme", path=p)] == [6]
    if os.name != "nt":
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    for i in range(zh.HISTORY_KEEP + 5):
        zh.record("acme", dict(base, at=(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(days=i)).isoformat()), path=p)
    hist = zh.load("acme", path=p)
    assert len(hist) == zh.HISTORY_KEEP and hist[0]["at"].startswith("2026-01-07") and hist[-1]["at"].startswith("2026-10-01")
    assert zh.forget("acme", path=p) == zh.HISTORY_KEEP and zh.load("acme", path=p) == []


def test_a_tampered_history_file_is_read_as_untrusted(tmp_path):
    """ASVS V5.1.3 · CWE-20 · CWE-502 · WSTG-INPV-01: unknown fields, wrong types, markup and impossible values are dropped; a huge file is no history."""
    p = tmp_path / "hist.json"
    bad = {"tenants": {"acme": [
        {"at": "2026-10-01T00:00:00+00:00", "devices": 4, "source": "<script>x</script>", "evil": "<img src=x>",
         "services": {"zia": {"active": "9", "inactive": -1, "percent": 140}}, "alerts": {"ghost": 1e300, "blind_spot": True},
         "versions": {"Windows": {"<b>1</b>": 3, "4.7.1": 2}, "<svg>": {"4.7": 1}}},
        {"at": "yesterday", "devices": 1}, {"at": "2026-10-02T00:00:00+00:00", "devices": "lots"}, "not a dict"]}}
    p.write_text(json.dumps(bad))
    hist = zh.load("acme", path=str(p))
    assert len(hist) == 1
    e = hist[0]
    assert e["source"] == "live" and "evil" not in e and e["services"]["zia"] == {"active": None, "inactive": None, "percent": None}
    assert e["alerts"]["ghost"] is None and e["alerts"]["blind_spot"] is None and e["versions"] == {"Windows": {"4.7.1": 2}}
    p.write_text("x" * (zh.MAX_FILE_BYTES + 1))
    assert zh.load("acme", path=str(p)) == []
    p.write_text("[" * 100000)
    assert zh.load("acme", path=str(p)) == []


def test_trend_and_compare_say_what_changed():
    """ASVS V11.1.4 · CWE-682: the trend gives each read's change since the one before; compare lists versions that came and went."""
    a = zh.clean_entry({"at": "2026-10-01T00:00:00+00:00", "devices": 10, "registered": 9, "services": {"zia": {"active": 6, "inactive": 3, "percent": 66.7}},
                        "alerts": {"ghost": 2}, "versions": {"Windows": {"4.6.0.1": 9}}})
    b = zh.clean_entry({"at": "2026-10-08T00:00:00+00:00", "devices": 12, "registered": 12, "services": {"zia": {"active": 11, "inactive": 1, "percent": 91.7}},
                        "alerts": {"ghost": 0}, "versions": {"Windows": {"4.7.2.5": 12}}})
    tr = zh.trend([a, b])
    assert tr["rows"][0]["delta"]["devices"] is None and tr["rows"][1]["delta"]["devices"] == 2
    assert tr["rows"][1]["delta"]["zia"] == 25.0 and tr["rows"][1]["alert_delta"]["ghost"] == -2 and tr["rows"][1]["delta"]["zpa"] is None
    c = zh.compare([a, b], 0, 1)
    vers = {r["item"]: r for r in c["rows"] if r["group"] == "Windows versions"}
    assert vers["4.7.2.5"]["change"] == "new" and vers["4.6.0.1"]["change"] == "gone" and vers["4.6.0.1"]["delta"] == -9
    with pytest.raises(ValueError):
        zh.compare([a, b], 0, 2)


def test_the_history_routes_save_list_compare_and_forget(monkeypatch):
    """ASVS V4.1.3 · ASVS V8.3.4 · CWE-352 · CWE-20: saving keeps one snapshot per read, the list and compare read no tenant, forgetting needs confirm, a configuration-only run has nothing to keep."""
    t, job, res = _live_job(monkeypatch)
    s1 = t.post(f"/api/zcc/fleet/{job}/history")
    assert s1.status_code == 200 and len(s1.json()["history"]) == 1
    assert len(t.post(f"/api/zcc/fleet/{job}/history").json()["history"]) == 1     # the same read twice: kept once
    tenant = s1.json()["tenant"]
    g = t.get("/api/zcc/fleet/history", params={"tenant": tenant}).json()
    assert len(g["trend"]["rows"]) == 1 and g["keep"] == zh.HISTORY_KEEP
    assert t.get("/api/zcc/fleet/history/compare", params={"tenant": tenant, "a": 0, "b": 5}).status_code == 400
    assert t.post("/api/zcc/fleet/history/forget", json={"tenant": tenant}).status_code == 400
    assert t.post("/api/zcc/fleet/history/forget", json={"tenant": tenant, "confirm": True}).json()["removed"] == 1
    from test_zcc_fleet import SDK
    t2, _ = _api(monkeypatch, SDK(list_error="HTTP 403"))
    j2 = t2.post("/api/zcc/fleet/start", json=dict(CREDS, **ZCC_SCOPE)).json()["job_id"]
    _follow(t2, j2)
    assert t2.post(f"/api/zcc/fleet/{j2}/history").status_code == 409


# ── import of the portal's CSV exports: untrusted input ──────────────────
DEVICE_HEAD = ('"User","Device type","Hostname","UDID","Zscaler Client Connector Version","Policy Name","Registration State",'
               '"OS Version","Tunnel Version"\n')
SERVICE_HEAD = ('"User","Device type","UDID","Hostname","Zscaler Client Connector Version","Registration State","ZIA Enabled",'
                '"ZIA Health","ZPA Enabled","ZPA Health","ZDX Enabled","ZDX Health","Last Seen Connected to ZIA"\n')


def portal_files(n=6, hostile=False):
    dev_lines, svc_lines = [DEVICE_HEAD], [SERVICE_HEAD]
    for i in range(1, n + 1):
        host = f"LON-LT-{i:03d}" if not (hostile and i == 1) else '=HYPERLINK("http://x")<img src=x onerror=alert(1)>'
        dev_lines.append(f'"u{i}@acme.example","Windows","{host.replace(chr(34), chr(34) * 2)}","UD-{i}","4.7.2.5 (64-bit)","Corp Windows",'
                         f'"Registered","Windows 11","Z-Tunnel 2.0"\n')
        zia = "Inactive" if i == 2 else "Active"
        zdx_on = "false" if i == 3 else "true"
        svc_lines.append(f'"u{i}@acme.example","Windows","UD-{i}","{host.replace(chr(34), chr(34) * 2)}","4.7.2.5","Registered","true","{zia}",'
                         f'"true","Active","{zdx_on}","Inactive","{(NOW - timedelta(hours=i)).strftime("%Y-%m-%d %H:%M:%S")} GMT"\n')
    return "".join(dev_lines), "".join(svc_lines)


def upload(text, name="device_export_2026_10_30-12-00-00.csv", enc="text"):
    if enc == "text":
        return {"name": name, "content": text}
    raw = text.encode("utf-8") if isinstance(text, str) else text
    if enc == "gzip-base64":
        raw = gzip.compress(raw)
    return {"name": name, "content": base64.b64encode(raw).decode(), "encoding": enc}


def test_an_import_of_both_exports_gives_the_same_figures_as_a_read():
    """ASVS V11.1.4 · CWE-20 · WSTG-BUSL-01: the two exports join by UDID; ZIA Health beats ZIA Enabled, a service not enabled is not applicable, a bracketed build note is not a version part."""
    d, s = portal_files()
    r = zi.run_import(upload(d), upload(s, "service_status_export_2026_10_30-12-00-05.csv", "gzip-base64"), label="Acme Corp")
    assert r["source"] == "import" and r["mode"] == "full" and r["status"] == "done" and r["tenant_label"] == "Acme Corp"
    assert r["read_at"].startswith("2026-10-30T12:00:00") and "export time in the file name" in r["banner"]
    assert r["kpis"]["registered"] == 6 and r["kpis"]["services"]["zia"]["active"] == 5
    assert r["kpis"]["services"]["zdx"]["not_applicable"] == 1 and r["kpis"]["services"]["zdx"]["inactive"] == 5
    assert [x["version"] for x in r["version_health"]["rows"]] == ["4.7.2.5"]
    assert r["telemetry"]["service_columns"]["zia"] == "ZIA Health"
    assert r["alerts"]["bypass_risk"]["count"] == 1 and r["profiles"] == [] and r["unmatched_profiles"] == []
    assert r["last_seen"]["buckets"][0]["devices"] == 6       # last seen joined from the service export


def test_service_columns_prefer_health_and_fall_back_to_enabled():
    """ASVS V5.1.3 · CWE-20: with Health and Enabled both present Health is the state and Enabled says applicable; Enabled alone is read as the state."""
    c = zf.service_columns(["User", "UDID", "ZIA Enabled", "ZIA Health", "ZPA Enabled", "ZDX Last Seen", "ZDX Health"])
    assert (c["zia"], c["zia_enabled"], c["zpa"], c["zpa_enabled"], c["zdx"]) == ("ZIA Health", "ZIA Enabled", "ZPA Enabled", None, "ZDX Health")
    d = normalized([dev(1)], [{"udid": "UDID-1", "zia": "Active", "zia_enabled": "FALSE", "zpa": "Active", "zdx": "Active"}])[0]
    assert d["services"]["zia"] == "not_applicable" and d["service_raw"]["zia"] == "not enabled" and d["services"]["zpa"] == "active"


def test_an_import_of_the_service_export_alone_counts_its_devices():
    """ASVS V11.1.4 · CWE-20: the Service Status export alone is enough: it names the devices, their version, state and last-seen time."""
    _, s = portal_files(4)
    r = zi.run_import(None, upload(s, "status.csv"))
    assert r["kpis"]["devices"] == 4 and r["mode"] == "full" and "newest last-seen time" in r["banner"]
    assert r["read_at"].startswith((NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H"))


def test_a_device_export_without_registration_counts_every_device_and_says_so():
    """ASVS V11.1.4 · CWE-754: no registration column is said in plain words (every listed device is counted as registered), and no service file means activity unknown."""
    text = '"User","Hostname","UDID","Zscaler Client Connector Version"\n"a@x","H1","U1","4.7"\n"b@x","H2","U2","4.6"\n'
    r = zi.run_import(upload(text, "devices.csv"), None, now=NOW)
    assert r["kpis"]["registered"] == 2 and any("counted as registered" in n for n in r["import"]["notes"])
    assert r["mode"] == "devices" and r["kpis"]["services"]["zia"]["percent"] is None and "time of the import" in r["banner"]


def test_exports_more_than_12_hours_apart_are_flagged():
    """ASVS V11.1.4 · CWE-20: two exports whose file names are more than 12 hours apart are flagged as not one snapshot."""
    d, s = portal_files(2)
    r = zi.run_import(upload(d, "device_export_2026_10_29-08-00-00.csv"), upload(s, "service_status_export_2026_10_30-09-00-00.csv"))
    assert any("25 hours apart" in n for n in r["import"]["notes"])
    assert zi.file_time("../../etc/device_export_2026_13_45-99-00-00.csv") is None
    assert zi.file_time("C:\\x\\device_export_2026_10_29-08-00-00.csv") == datetime(2026, 10, 29, 8, tzinfo=timezone.utc)


def test_a_preamble_line_before_the_header_is_skipped_and_text_encodings_are_read():
    """ASVS V5.1.3 · CWE-20 · CWE-176: the header is found by its names after a title line; UTF-16 with a BOM and Windows-1252 files are read."""
    d, _ = portal_files(2)
    text = "Enrolled devices export\n" + d
    assert zi.run_import(upload(text, enc="base64"), None)["kpis"]["devices"] == 2
    u16 = {"name": "d.csv", "content": base64.b64encode(("\ufeff" + d).encode("utf-16")).decode(), "encoding": "base64"}
    assert zi.run_import(u16, None)["kpis"]["devices"] == 2
    cp = {"name": "d.csv", "content": base64.b64encode(d.replace("Corp Windows", "Café").encode("cp1252")).decode(), "encoding": "base64"}
    r = zi.run_import(cp, None)
    assert r["devices"][0]["profile"] == "Café"


@pytest.mark.parametrize("make,why", [
    (lambda: {"name": "d.csv", "content": "not base64 !!!", "encoding": "base64"}, "valid base64"),
    (lambda: {"name": "d.csv", "content": base64.b64encode(b"\x1f\x8b\x08 junk").decode(), "encoding": "gzip-base64"}, "damaged"),
    (lambda: upload('"User","Hostname"\n"a\x00b","H"\n'), "NUL"),
    (lambda: upload("just some text\nwith no header at all\n"), "no header row"),
    (lambda: upload('"User","Hostname","UDID"\n'), "no device rows"),
    (lambda: upload(",".join(f'"c{i}"' for i in range(400)) + "\n"), "more than 300 columns"),
    (lambda: upload('"User","Hostname","Zscaler Client Connector Version"\n"a","' + "x" * 200000 + '","4.7"\n'), "malformed"),
    (lambda: {"name": "d.csv", "content": "x", "encoding": "rot13"}, "encoding must be"),
    (lambda: {"name": "d.csv", "content": ""}, "empty"),
    (lambda: "a string", "not sent as a file"),
])
def test_hostile_or_broken_files_are_refused_with_a_reason(make, why):
    """ASVS V5.1.3 · ASVS V12.1.1 · CWE-20 · CWE-434 · WSTG-INPV-01: table over damaged, binary, headerless, oversized-cell and unclosed files: each is a plain refusal, never a crash."""
    f = make()
    with pytest.raises(zi.ImportRefused) as e:
        zi.run_import(f, None)
    assert why in str(e.value), str(e.value)


def test_size_row_and_column_caps_and_a_gzip_bomb(monkeypatch):
    """ASVS V12.1.1 · ASVS V5.1.3 · CWE-400 · CWE-409 · WSTG-BUSL-07: a file over the size cap, too many rows or columns, and a small gzip upload that would inflate past the cap are refused before parsing it all."""
    monkeypatch.setattr(zi, "MAX_FILE_BYTES", 4096)
    monkeypatch.setattr(zi, "MAX_ENCODED_CHARS", 4096 * 4 // 3 + 16)
    bomb = gzip.compress(b'"User","Hostname"\n' + b"a" * 10_000_000)
    assert len(bomb) < 20000
    with pytest.raises(zi.ImportRefused, match="larger than"):
        zi.run_import({"name": "d.csv", "content": base64.b64encode(bomb).decode(), "encoding": "gzip-base64"}, None)
    with pytest.raises(zi.ImportRefused, match="larger than"):
        zi.run_import(upload("x" * 5000), None)
    with pytest.raises(zi.ImportRefused, match="larger than"):
        zi.run_import({"name": "d.csv", "content": "A" * 6000, "encoding": "base64"}, None)
    monkeypatch.setattr(zi, "MAX_FILE_BYTES", 48 * 1024 * 1024)
    monkeypatch.setattr(zi, "MAX_ROWS", 3)
    d, _ = portal_files(4)
    with pytest.raises(zi.ImportRefused, match="more than 3 rows"):
        zi.run_import(upload(d), None)
    monkeypatch.setattr(zi, "MAX_COLUMNS", 5)
    with pytest.raises(zi.ImportRefused, match="more than 5 columns"):
        zi.run_import(upload(d), None)


def test_cells_are_cut_and_the_label_is_cleaned():
    """ASVS V5.1.3 · ASVS V5.2.1 · CWE-20 · CWE-79: a long cell is cut to 200 characters; the history name keeps letters, digits and a few marks, never markup or an e-mail address."""
    text = '"User","Hostname","Zscaler Client Connector Version"\n"a@x","' + "H" * 5000 + '","4.7"\n'
    r = zi.run_import(upload(text), None)
    assert len(r["devices"][0]["hostname"]) == zf.MAX_CELL_CHARS
    assert zi.clean_label('<script>alert(1)</script> Acme admin@acme.com') == "scriptalert(1)script Acme"
    assert zi.clean_label("") == zi.DEFAULT_LABEL and len(zi.clean_label("x" * 500)) == zi.MAX_LABEL


def test_the_import_route_signs_in_nowhere_and_its_exports_neutralise_formulas(monkeypatch):
    """ASVS V5.3.10 · ASVS V4.1.3 · CWE-1236 · CWE-20 · WSTG-INPV-11: the import builds no tenant client, keeps a fleet run the exports use, and a formula-looking host name stays text in CSV and Excel."""
    t, built = _api(monkeypatch)
    d, s = portal_files(4, hostile=True)
    r = t.post("/api/zcc/fleet/import", json={"devices": upload(d, enc="gzip-base64"), "service": upload(s, "s.csv", "base64"),
                                              "tenant_label": "Acme", "site": {"mode": "prefix", "length": 3}})
    assert r.status_code == 200, r.text
    snap = _follow(t, r.json()["job_id"])
    res = snap["result"]
    assert snap["status"] == "done" and res["source"] == "import" and built == []
    assert res["sites"]["rule"] == {"mode": "prefix", "length": 3}
    csv_text = t.get(f"/api/zcc/fleet/{r.json()['job_id']}/export?what=devices").text
    assert "'=HYPERLINK" in csv_text and '\n=HYPERLINK' not in csv_text and ',=HYPERLINK' not in csv_text
    sheets = _sheets(t.get(f"/api/zcc/fleet/{r.json()['job_id']}/export?format=xlsx").content)
    assert "<f>" not in sheets["Devices"] and "&lt;img" in sheets["Devices"] and "'=HYPERLINK" in sheets["Devices"]
    assert t.post("/api/zcc/fleet/import", json={}).status_code == 400
    assert t.post("/api/zcc/fleet/import", json={"devices": {"name": "d", "content": "zz", "encoding": "base64"}}).status_code == 400
    assert t.post("/api/zcc/fleet/import", json={"devices": upload(d), "site": {"mode": "regex"}}).status_code == 400


def test_the_sample_tenant_fleet_now_has_service_status(monkeypatch):
    """ASVS V11.1.4 · CWE-754: the sample tenant's offline SDK answers the service-status download, so its fleet shows ZIA, ZPA and ZDX (one bypass risk) without any network."""
    import offline_tenant as o
    o.sample_store(reset=True)
    creds = {"client_id": o.CLIENT_ID_PREFIX + o.SAMPLE, "client_secret": "x", "vanity_domain": "sample" + o.OFFLINE_DOMAIN}
    sdk = o.client_for(creds, "sdk")
    assert sdk.get_request_executor() is sdk._request_executor
    out = zf.read_devices(sdk, log=lambda s: None, cancel=threading.Event())
    assert out["status"] == "read" and len(out["service"]["rows"]) == 3
    r = zf.analyze({"read_status": {}}, out, now=datetime(2026, 10, 28, 12, tzinfo=timezone.utc))
    assert r["mode"] == "full" and r["alerts"]["bypass_risk"]["count"] == 1
