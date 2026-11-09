"""Wave 12 operations: DNS push to several resolvers, delivery routes, log index, service files, DigiCert and /32 ranges, workbook chart.

Fakes only: no network, no real credential store, no tenant.
"""
from __future__ import annotations

import io
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import dns_forward_zones as dfz
import dns_push as dp
import log_pipeline_cli
import report_delivery as rd
import url_tools as ut
import xlsx_writer as xw
import zscaler_ip_ranges as zr

ROOT = Path(__file__).resolve().parent.parent
SECRET = "Canary-Pw-4821"


class KR:
    def __init__(self):
        self.d = {}

    def get_keyring(self):
        return self

    def set_password(self, s, u, p):
        self.d[(s, u)] = p

    def get_password(self, s, u):
        return self.d.get((s, u))


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_REPORT_DELIVERY", str(tmp_path / "rd.json"))
    monkeypatch.setenv("DLP_CHECK_DNS_PUSH", str(tmp_path / "dp.json"))
    kr = KR()
    monkeypatch.setattr(rd, "_keyring", lambda: kr)
    sent = []

    def fake_send(t, name, data, secret, known_hosts):
        if t["host"] == "dns2.example.com":
            raise OSError("down")
        sent.append((t["host"], name, data))
    monkeypatch.setattr(rd, "_send", fake_send)
    return sent


def _targets():
    base = {"transport": "sftp", "user": "svc", "remote_dir": "/etc/unbound"}
    return {f"r{i}": dict(base, host=f"dns{i}.example.com") for i in (1, 2, 3)}


def _setup(allow=("dns1.example.com", "dns2.example.com", "dns3.example.com")):
    rd.save_settings({"enabled": True, "allowed_hosts": list(allow), "targets": _targets()})
    for t in ("r1", "r2", "r3"):
        rd.set_credential(t, SECRET)


def _build():
    return dfz.build([{"hostname": "lt-1", "platform": "Windows", "registration": "registered", "user": "a@x.example", "seconds_since_seen": 5}],
                     domain="corp.example.com", resolvers="10.0.0.12")


def test_dns_push_off_by_default(env):
    """ASVS V1.14.6 · CWE-1188 · WSTG-CONF-01: DNS push is off and refuses to send until enabled, staged and given targets."""
    _setup()
    dp.stage(_build(), "unbound")
    with pytest.raises(rd.DeliveryError, match="off"):
        dp.push()
    assert env == []


def test_dns_push_each_host_reported_and_one_failure_does_not_stop_others(env):
    """ASVS V1.14.2 · CWE-755 · WSTG-ERRH-01: the file goes to every resolver; a failure on one host is reported for it and the rest still receive it."""
    _setup()
    b = _build()
    dp.stage(b, "unbound")
    dp.save_settings({"enabled": True, "targets": ["r1", "r2", "r3"]})
    res = dp.push()
    assert [r["status"] for r in res] == ["sent", "failed", "sent"]
    assert [h for h, _n, _d in env] == ["dns1.example.com", "dns3.example.com"]
    assert env[0][2].decode() == b["files"]["unbound"] and env[0][1] == "zcc_client_zones.conf"
    assert SECRET not in json.dumps(res) and "OSError" in res[1]["error"]


def test_dns_push_refuses_non_allowlisted_resolver(env):
    """ASVS V12.6.1 · CWE-918 · WSTG-CLNT-07: a resolver outside the host allowlist is refused for that host only; allowed ones still get the file."""
    _setup(allow=("dns1.example.com",))
    dp.stage(_build(), "unbound")
    dp.save_settings({"enabled": True, "targets": ["r1", "r3"]})
    res = dp.push()
    assert [r["status"] for r in res] == ["sent", "failed"] and "allowed hosts" in res[1]["error"]
    assert [h for h, *_ in env] == ["dns1.example.com"]


def test_dns_push_cron_once_per_minute(env):
    """ASVS V1.14.6 · CWE-770 · WSTG-BUSL-05: the schedule re-sends the staged file only when its minute matches, once."""
    _setup()
    dp.stage(_build(), "unbound")
    dp.save_settings({"enabled": True, "targets": ["r1"], "cron": "15 3 * * *"})
    at = datetime(2026, 11, 9, 3, 15, 5, tzinfo=timezone.utc)
    assert dp.tick(at)[0]["status"] == "sent"
    assert dp.tick(at) is None
    assert dp.tick(datetime(2026, 11, 9, 4, 15, tzinfo=timezone.utc)) is None


def test_dns_domains_deduped_across_mappings():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: two mappings to the same domain (and the main domain again) write one record per device, not a duplicate."""
    assert dfz.dedupe_domains(["a.example", "A.example", "b.example"]) == ["a.example", "b.example"]
    out = dfz.build([{"hostname": "lt-1", "platform": "Windows", "registration": "registered", "user": "u@acme.example", "seconds_since_seen": 5}],
                    domain="corp.example.com", resolvers="10.0.0.12",
                    mappings="acme.example=emea.example.com\nacme.example=emea.example.com\nacme.example=Corp.Example.com")
    assert out["counts"]["records"] == 2 and out["counts"]["duplicates"] == 0


# ── routes ───────────────────────────────────────────────────────────
@pytest.fixture
def api(env, monkeypatch):
    import dlp_api_server as srv
    return TestClient(srv.app)


def test_routes_store_password_in_keyring_never_echo_or_log(api, env, caplog):
    """ASVS V2.10.4 · CWE-532 · WSTG-ATHN-06: a password sent to the credential route goes to the keyring only; no answer, setting file, audit line or log holds it."""
    r = api.post("/api/delivery/settings", json={"enabled": True, "allowed_hosts": ["dns1.example.com"],
                                                 "targets": {"r1": {"transport": "sftp", "host": "dns1.example.com", "user": "svc", "remote_dir": "/in"}}})
    assert r.status_code == 200, r.text
    caplog.set_level("DEBUG")
    r = api.put("/api/delivery/credential/r1", json={"password": SECRET})
    assert r.status_code == 200 and SECRET not in r.text
    assert rd._credential("r1") == SECRET
    assert SECRET not in open(rd.store_path()).read() and SECRET not in caplog.text
    g = api.get("/api/delivery")
    assert g.status_code == 200 and SECRET not in g.text
    assert api.put("/api/delivery/credential/nope", json={"password": "x"}).status_code == 404
    assert api.put("/api/delivery/credential/r1", json={"password": SECRET, "extra": 1}).status_code == 422


def test_routes_allowlist_enforced_on_send_and_test(api, env):
    """ASVS V12.6.1 · CWE-918 · WSTG-CLNT-07: sending or testing a target whose host is not allowlisted is a 400 and nothing connects."""
    api.post("/api/delivery/settings", json={"enabled": True, "allowed_hosts": ["ok.example.com"],
                                             "targets": {"r1": {"transport": "sftp", "host": "dns1.example.com", "user": "svc", "remote_dir": "/in"}}})
    api.put("/api/delivery/credential/r1", json={"password": SECRET})
    t = api.post("/api/delivery/test/r1")
    assert t.status_code == 400 and "allowed" in t.text
    assert api.post("/api/delivery/send", json={"target": "r1", "report": "20240101-000000-abcdefgh.json"}).status_code == 400
    assert api.post("/api/dns-push/run").status_code == 400


def test_routes_dns_push_settings_validate(api, env):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: DNS push settings accept only defined targets and a valid cron expression."""
    api.post("/api/delivery/settings", json={"enabled": True, "allowed_hosts": ["dns1.example.com"],
                                             "targets": {"r1": {"transport": "sftp", "host": "dns1.example.com", "user": "svc", "remote_dir": "/in"}}})
    assert api.post("/api/dns-push/settings", json={"targets": ["ghost"]}).status_code == 400
    assert api.post("/api/dns-push/settings", json={"cron": "bad"}).status_code == 400
    ok = api.post("/api/dns-push/settings", json={"enabled": True, "targets": ["r1"], "cron": "0 3 * * *"})
    assert ok.status_code == 200 and ok.json()["settings"]["targets"] == ["r1"]


def test_team_rules_cover_new_routes():
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: every delivery and DNS push route has an admin-level team rule."""
    import team_routes as tr
    for k in ("GET /api/delivery", "POST /api/delivery/settings", "PUT /api/delivery/credential/{target_id}",
              "POST /api/delivery/test/{target_id}", "POST /api/delivery/send", "POST /api/dns-push/settings", "POST /api/dns-push/run"):
        assert tr.ROUTE_RULES[k] is tr.ADMIN


# ── log pipeline ────────────────────────────────────────────────────
def test_reindex_rebuilds_catalogue_from_disk(tmp_path, monkeypatch, capsys):
    """ASVS V8.3.4 · CWE-668 · WSTG-INFO-05: reindex rebuilds index.json from the saved reports on disk, names unreadable files, and opens nothing else."""
    import traffic_logs as tl
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    line = json.dumps({"LoginName": "a@example.com", "Timestamp": "2026-11-01T00:00:00Z"})
    rep = {"kind": tl.KIND, "version": tl.VERSION, "input": {"records": 3}, "period": None}
    p = tl.saved_dir()
    os.makedirs(p)
    import safe_files, store_crypto
    safe_files.write_private_atomic(os.path.join(p, "20260101-000000-abcdefgh.json"),
                                    store_crypto.seal_text(json.dumps(dict(rep, saved={"title": "T", "at": "2026-01-01T00:00:00Z", "names": False}))))
    safe_files.write_private_atomic(os.path.join(p, "20260102-000000-abcdefgh.json"), "not json")
    assert log_pipeline_cli.main(["reindex"]) == 0
    assert json.loads(capsys.readouterr().out) == {"indexed": 1, "unreadable": 1}
    cat = json.load(open(os.path.join(p, "index.json")))
    assert cat["reports"][0]["name"] == "20260101-000000-abcdefgh.json" and cat["unreadable"] == ["20260102-000000-abcdefgh.json"]
    assert oct(os.stat(os.path.join(p, "index.json")).st_mode & 0o777) == "0o600"
    assert line  # fixture text only


# ── service files ───────────────────────────────────────────────────
def test_unit_file_runs_unprivileged_on_localhost():
    """ASVS V1.14.1 · CWE-250 · WSTG-CONF-02: the systemd unit runs as a non-root user, binds 127.0.0.1, is sandboxed and enables no writes."""
    u = (ROOT / "deploy/rhel/zscaler-made-easy.service").read_text()
    assert "User=zscaler-made-easy" in u and "User=root" not in u
    assert "Environment=ZSCALER_BIND_HOST=127.0.0.1" in u and "0.0.0.0" not in u
    for h in ("NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "UMask=0077", "CapabilityBoundingSet="):
        assert h in u
    assert "ENABLE_WRITE_ACTIONS" not in u and "ExecStart=@APP_DIR@/.venv/bin/zscaler-made-easy" in u


def test_install_scripts_are_operator_only_and_app_never_runs_them():
    """ASVS V1.14.1 · CWE-269 · WSTG-CONF-02: the installer needs root, the wheelhouse build is hash-verified, and no app module references either script."""
    inst = (ROOT / "deploy/rhel/install_service.sh").read_text()
    assert 'id -u' in inst and "useradd --system" in inst and "nologin" in inst
    wh = (ROOT / "deploy/rhel/build_wheelhouse.sh").read_text()
    assert "--require-hashes" in wh and "requirements.lock" in wh and "sha256sum" in wh
    for py in ROOT.glob("*.py"):
        t = py.read_text(errors="ignore")
        assert "install_service.sh" not in t and "build_wheelhouse.sh" not in t, py.name


# ── ranges ──────────────────────────────────────────────────────────
def test_digicert_hosts_with_source_and_single_host_form(tmp_path, monkeypatch):
    """ASVS V1.4.4 · CWE-682 · WSTG-CONF-01: the shipped DigiCert list is added only on request with its source and date; a /32 can be written as a bare address; overlaps still consolidate."""
    monkeypatch.setenv("DLP_CHECK_ZSCALER_RANGES_DIR", str(tmp_path / "r"))
    doc = json.dumps({"ipv4Prefixes": [], "prefixes": []})
    off = zr.build("zscaler", ["cenr"], extra="23.4.43.0/24\n23.4.43.128/25\n23.4.44.9/32")
    assert off["all"]["ipv4"] == ["23.4.43.0/24", "23.4.44.9/32"] and off["digicert"] is None
    on = zr.build("zscaler", ["cenr"], extra="23.4.44.9/32", digicert=True, single_hosts=True)
    assert on["all"]["ipv4"] == ["23.4.44.9"] and "ocsp.digicert.com" in {h["host"] for h in on["hosts"]}
    assert on["digicert"]["source"] and on["digicert"]["as_of"] and doc
    assert zr.host_form(["10.0.0.1/32", "10.0.0.0/24", "2001:db8::1/128"]) == ["10.0.0.1", "10.0.0.0/24", "2001:db8::1"]


# ── workbook chart ──────────────────────────────────────────────────
def test_category_analyzer_workbook_has_summary_sheet_and_native_chart():
    """ASVS V5.3.3 · CWE-1236 · WSTG-INPV-02: the analyzer workbook holds a Summary sheet and a native bar chart part pointing at the verdict counts, with no formula cell."""
    res = {"totals": {"redundant": 3, "different": 1}, "per_category": [], "rows": [], "lookup": {}, "notes": []}
    z = zipfile.ZipFile(io.BytesIO(ut.analyzer_workbook(res, tenant_label="acme")))
    names = z.namelist()
    assert "xl/charts/chart1.xml" in names and "xl/drawings/drawing1.xml" in names
    chart = z.read("xl/charts/chart1.xml").decode()
    assert "<c:barChart>" in chart and "'Summary'!$B$" in chart and "<c:f>" in chart and "URLs by verdict" in chart
    assert "drawingml.chart+xml" in z.read("[Content_Types].xml").decode()
    assert "<drawing " in z.read("xl/worksheets/sheet1.xml").decode()
    assert "<f>" not in z.read("xl/worksheets/sheet1.xml").decode()
    for n in names:
        if n.endswith((".xml", ".rels")):
            import xml.etree.ElementTree as ET
            ET.fromstring(z.read(n))


def test_chart_rows_must_exist():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a chart pointing outside the sheet is refused."""
    ws = xw.Workbook().add_sheet("S", columns=["a", "b"])
    with pytest.raises(ValueError):
        ws.add_bar_chart("t", label_col=0, value_col=1, first_row=2, last_row=9)


# ── row 10 evidence (existing behaviour) ────────────────────────────
def test_zcc_removal_modes_batch_cap_and_plan_gate_exist():
    """ASVS V4.1.3 · CWE-841 · WSTG-BUSL-01: Client Connector removal has soft and force modes, a capped batch size, and goes plan -> typed confirmation through admin_ops."""
    import ops_zcc_admin as zc
    assert zc.BATCH_MAX == 100 and zc.BULK_MAX == 2000 and zc.T_REMOVE != zc.T_BULK
    src = (ROOT / "ops_zcc_admin.py").read_text()
    assert 'mode not in ("remove", "force")' in src and "admin_ops" in src or "import admin_ops" in src
