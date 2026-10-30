"""Secure by Design, Wave 6: the sample tenant and snapshots never reach a
network or a tenant, and everything new written to disk is owner-only.

* Every tenant-reading route of the scope table (tests/test_scope_rule_routes.py
  ROUTES, so a new row is covered here too) runs on the sample tenant with
  every socket call refused and recorded: none may be attempted.
* With a snapshot open and all four write gates held (write mode, writer,
  assessor, typed confirmation), a bulk change and a pack deployment still
  change nothing: the snapshot answers read-only.
* The files the Wave 5 features write (snapshots, POVs and their templates,
  the profile store beside them) are 0600 in 0700 folders even with a umask
  of 0, and the offline-tenant cookie is Secure behind a TLS proxy.

Mappings: OWASP ASVS 4.0.3 L2, OWASP Top 10 2021, CWE, WSTG. Deterministic:
no network, no sleeps (pacing injected to zero), jobs run in the request,
every store in tmp_path.
"""
from __future__ import annotations

import copy
import os
import socket
import stat
import threading

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import offline_tenant as ot
import sample_tenant
import test_scope_rule_routes as scope_table

ALL = {"scopes": scope_table.ALL_SCOPES, "channels": dict(scope_table.ALL_CHANNELS), "from_page": True}
SAMPLE_ROWS = list({r.path: r for r in scope_table.ROUTES if r.setup is None}.values())
JOBS = []


def _sync_start(kind, fn, **_k):
    """pack_jobs.start, run inside the request: no thread, sleep or poll."""
    job = scope_table._sync_start(kind, fn)
    JOBS.append(job)
    return job


@pytest.fixture
def offline_app(tmp_path, monkeypatch):
    """Arrange: an isolated app (stores in tmp_path, no environment tenant),
    the real client factories (which hand out the offline clients), no
    pacing against the real clock, jobs in the request, and a socket guard
    that refuses and records every attempt to reach any address."""
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLPCHECK_PROPOSALS_FILE", "proposals.json"), ("DLPCHECK_CHANGE_QUEUE_FILE", "change_queue.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    import audit_timeline
    import insights
    import pack_jobs
    import zcc_fleet
    import zpa_reader
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(audit_timeline, "POLL_SECONDS", 0.0)
    monkeypatch.setattr(audit_timeline, "POLL_TIMEOUT", 0.0)
    monkeypatch.setattr(zcc_fleet, "_nap", lambda seconds, cancel: None)
    monkeypatch.setattr(srv, "_REPORTS", {})
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    attempts = []

    def guard(*args, **_k):
        attempts.append(repr(args[:2])[:120])
        raise OSError("socket guard: this test may not reach any network")
    for owner, name in ((socket.socket, "connect"), (socket.socket, "connect_ex"), (socket, "getaddrinfo"),
                        (socket, "gethostbyname"), (socket, "create_connection")):
        monkeypatch.setattr(owner, name, guard)
    yield TestClient(srv.app, base_url="http://127.0.0.1"), attempts
    # A Beacon run (/api/beacon/run) works on its own thread: it is stopped and
    # waited for while the guard is still in place, so it never outlives the test.
    import beacon
    srv._BEACON_STOP.set()
    if beacon.RUN_LOCK.acquire(timeout=30):
        beacon.RUN_LOCK.release()
    srv._BEACON_STOP.clear()
    assert attempts == [], attempts[:3]


# ── The sample tenant never reaches a network ──────────────────────────

@pytest.mark.parametrize("route", SAMPLE_ROWS, ids=lambda r: r.path)
def test_every_tenant_reading_route_on_the_sample_opens_no_socket(offline_app, route):
    """ASVS V1.14.1 · ASVS V12.6.1 · CWE-653 · CWE-441 · A10:2021 · WSTG-INPV-19: with the sample tenant open and everything in scope, a tenant-reading route attempts no DNS lookup and no connection."""
    # Arrange
    c, attempts = offline_app
    assert c.post("/api/offline/sample", json={"reset": True}).status_code == 200
    # Act
    r = c.post(route.path, json=dict(route.body, **ALL))
    # Assert
    assert attempts == [], (route.path, r.status_code, attempts[:3])
    assert r.status_code < 500, r.text[:300]


# ── A snapshot never triggers a write, even with every gate held ───────

def _open_snapshot(c):
    resp = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()}
    doc = ot.build_snapshot(resp, {"tenant_label": "acme (zscalerten)"})
    r = c.post("/api/tenant-profiles/snapshots/open-file", json={"content": ot.dumps(doc)})
    assert r.status_code == 200 and r.json()["mode"] == "snapshot"
    return ot.store(r.json()["source"])


RULE = sample_tenant.WEB_DLP_RULES[0]["id"]
FULL_GATES = dict(ALL, assessor="Jane Doe", confirm=True)


def _apply_bulk_change(c):
    op = {"type": "rule_state", "targets": [{"policy": "web_dlp", "id": RULE, "to": "DISABLED"}]}
    prev = c.post("/api/operations/preview", json=dict(ALL, operation=op))
    assert prev.status_code == 200, prev.text[:300]
    return c.post("/api/operations/apply", json=dict(FULL_GATES, operation=op, plan_hash=prev.json()["plan_hash"]))


def _deploy_a_pack(c):
    pre = c.post("/api/dlp-packs/preflight", json=dict(ALL, pack_ids=["cjis_policy_pack"], assessor="Jane Doe"))
    assert pre.status_code == 200, pre.text[:300]
    return c.post("/api/dlp-packs/apply", json=dict(FULL_GATES, pack_ids=["cjis_policy_pack"], plan_hash=pre.json()["plan_hash"]))


@pytest.mark.parametrize("write", [_apply_bulk_change, _deploy_a_pack], ids=["bulk-change", "pack-deploy"])
def test_a_snapshot_with_every_gate_held_still_changes_nothing(offline_app, monkeypatch, write):
    """ASVS V4.1.1 · ASVS V1.4.1 · CWE-284 · CWE-441 · WSTG-ATHZ-02: write mode on, a writer, the assessor and the confirmation all held: a write on an open snapshot is refused read-only, the snapshot is unchanged and nothing is sent."""
    # Arrange
    import security
    c, attempts = offline_app
    st = _open_snapshot(c)
    before = copy.deepcopy(st.responses)
    monkeypatch.setattr(security, "_write_override", True)
    # Act
    r = write(c)
    # Assert
    assert r.status_code < 500, r.text[:300]
    assert "read-only" in r.text, r.text[:300]
    assert st.writes == 0 and st.responses == before
    assert attempts == []


# ── Least privilege on disk ────────────────────────────────────────────

@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits")
def test_everything_the_new_features_write_is_owner_only_even_with_umask_zero(offline_app, tmp_path, monkeypatch):
    """ASVS V8.3.4 · ASVS V14.1.3 · CWE-732 · CWE-276 · CWE-379: a snapshot, a POV, its template and its proof are 0600 files in 0700 folders whatever the umask."""
    # Arrange
    import tenant_profiles
    c, _attempts = offline_app
    live = ot.OfflineStore("snap-" + "2" * 16, "snapshot",
                           {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()},
                           {"tenant_label": "acme (zscalerten)"})
    monkeypatch.setattr(srv, "_raw_client", lambda creds: ot.OfflineRawClient(live, creds))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ot.OfflineSdkClient(live, creds))
    creds = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclientid0001", "client_secret": "qa-secret-value"}
    old = os.umask(0)
    try:
        pid = tenant_profiles.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "acmeclientid0001"},
                                     client_secret="qa-secret-value", remember_secret=True)["id"]
        # Act
        answers = [c.post("/api/tenant-profiles/snapshots/save/start", json=dict(creds, **ALL, profile_id=pid)),
                   c.post("/api/pov/create", json=dict(creds, profile_id=pid, intake={"customer": "Acme", "vertical": "general"})),
                   c.post("/api/pov/templates", json=dict(creds, profile_id=pid, name="Template")),
                   c.post("/api/pov/prove/start", json=dict(creds, **ALL, profile_id=pid, test_id="url-block"))]
    finally:
        os.umask(old)
    # Assert
    assert [a.status_code for a in answers] == [200] * 4, [a.text[:200] for a in answers]
    assert tenant_profiles.list_snapshots(pid) and JOBS[-1].error == ""
    wide = []
    for root, dirs, files in os.walk(tmp_path):
        wide += [(os.path.join(root, d), oct(stat.S_IMODE(os.stat(os.path.join(root, d)).st_mode))) for d in dirs
                 if stat.S_IMODE(os.stat(os.path.join(root, d)).st_mode) != 0o700]
        wide += [(os.path.join(root, f), oct(stat.S_IMODE(os.stat(os.path.join(root, f)).st_mode))) for f in files
                 if stat.S_IMODE(os.stat(os.path.join(root, f)).st_mode) != 0o600]
    written = sum(len(f) for _r, _d, f in os.walk(tmp_path))
    assert written >= 4, "the snapshot, the profile store, the POV and the template were written"
    assert wide == [], wide


@pytest.mark.parametrize("headers,secure", [({}, False), ({"X-Forwarded-Proto": "https"}, True)])
def test_the_offline_tenant_cookie_is_secure_behind_a_tls_proxy(offline_app, headers, secure):
    """ASVS V3.4.1 · CWE-614 · WSTG-SESS-02: the sample/snapshot cookie follows the UI token cookie's rule: Secure whenever the page came over HTTPS, a TLS reverse proxy included."""
    # Arrange
    c, _attempts = offline_app
    # Act
    r = c.post("/api/offline/sample", json={}, headers=headers)
    # Assert
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(ot.COOKIE + "=") and "HttpOnly" in cookie and "SameSite=strict" in cookie
    assert ("Secure" in cookie) is secure, cookie


# ── The access token's claims are for display only ─────────────────────

# The functions of dlp_api_server that may use readiness (the decoded token
# and the latest answers): its own routes, sign-in (display) and the API
# access page. No write gate, scope check or sign-in decision is among them.
READINESS_USERS = {"_readiness_latest", "_readiness_token_access", "permissions_required", "readiness_catalog", "readiness_latest",
                   "readiness_start", "serve_permissions_page", "tenant_check"}


def test_no_authorization_decision_reads_the_unverified_token_claims():
    """ASVS V3.5.3 · ASVS V4.1.1 · CWE-345 · CWE-347 · A07:2021: the token is decoded without its signature, so its claims may only be shown: no other function of the server reads readiness or its answers, and no other module imports it."""
    import ast
    import glob
    import re
    # Arrange
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tree = ast.parse(open(os.path.join(root, "dlp_api_server.py"), encoding="utf-8").read())
    names = {"readiness", "_READINESS", "_readiness_latest", "_readiness_token_access"}
    # Act
    users = set()
    for fn in tree.body:
        if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            used = {x.id for x in ast.walk(fn) if isinstance(x, ast.Name)}
            used |= {a.name for x in ast.walk(fn) if isinstance(x, (ast.Import, ast.ImportFrom)) for a in x.names}
            if used & names:
                users.add(fn.name)
    importers = [os.path.basename(f) for f in glob.glob(os.path.join(root, "*.py"))
                 if os.path.basename(f) not in ("readiness.py", "dlp_api_server.py")
                 and re.search(r"^\s*(import readiness\b|from readiness import)", open(f, encoding="utf-8").read(), re.M)]
    # Assert
    assert users == READINESS_USERS, sorted(users ^ READINESS_USERS)
    assert importers == []
