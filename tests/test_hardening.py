"""Hardening: audit log of write calls, one write gate for every writer,
keyring-backed profile secrets, hash-pinned installs, container files."""
from __future__ import annotations

import json
import os
import sys
import types

from fastapi.testclient import TestClient

import audit
import dlp_api_server as srv
import security
import tenant_profiles as tp

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_audit_logs_write_calls_with_redacted_bodies(monkeypatch, tmp_path):
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    c = TestClient(srv.app)
    assert c.get("/api/health").status_code == 200                    # GETs are not logged
    r = c.post("/api/tenant/check", json={"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"})
    assert r.status_code in (200, 400, 401, 502, 503)
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert len(lines) == 1
    e = lines[0]
    assert e["event"] == "api" and e["method"] == "POST" and e["path"] == "/api/tenant/check" and e["status"] == r.status_code
    assert e["body"]["client_secret"] == "[redacted]" and e["body"]["vanity_domain"] == "acme"
    assert "secret-secret-secret" not in log.read_text()
    assert "write_mode" in e and "ms" in e
    if os.name != "nt":
        assert oct(os.stat(log).st_mode & 0o777) == "0o600"
    assert audit.tail(5)[-1]["path"] == "/api/tenant/check"


def test_audit_redaction_and_rotation(monkeypatch, tmp_path):
    assert audit.redact({"Authorization": "x", "token": "t", "nested": {"api_key": "k", "name": "n"}, "long": "a" * 300, "list": list(range(30))}) == {
        "Authorization": "[redacted]", "token": "[redacted]", "nested": {"api_key": "[redacted]", "name": "n"},
        "long": "a" * 200 + "…", "list": list(range(20)) + ["…"]}
    log = tmp_path / "a.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    monkeypatch.setenv("DLP_CHECK_AUDIT_MAX_MB", "0.0001")
    for i in range(30):
        audit.record("test", i=i, pad="x" * 50)
    assert (tmp_path / "a.log.1").exists()


def test_every_writer_honours_the_session_write_gate(monkeypatch):
    import remediation
    import rule_migrator
    src = open(os.path.join(ROOT, "remediation.py")).read() + open(os.path.join(ROOT, "rule_migrator.py")).read()
    assert 'os.environ.get("ENABLE_WRITE_ACTIONS") != "YES_I_UNDERSTAND"' not in src
    assert 'writes_enabled()' in src
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setattr(security, "_write_override", None)
    cid = next(iter(remediation.REMEDIATIONS))["check_id"]
    res = remediation.execute(None, cid, {}, dry_run=False)
    assert res["status"] in ("blocked", "invalid")


def test_profile_secret_goes_to_the_keyring_when_available(monkeypatch, tmp_path):
    store = {}
    fake = types.SimpleNamespace(
        set_password=lambda svc, user, pw: store.__setitem__((svc, user), pw),
        get_password=lambda svc, user: store.get((svc, user)),
        delete_password=lambda svc, user: store.pop((svc, user), None))
    monkeypatch.setitem(sys.modules, "keyring", fake)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    assert tp.secret_storage() == "keyring"
    row = tp.upsert({"name": "Acme", "vanity_domain": "acme", "client_id": "abc123456789"}, client_secret="s3cret", remember_secret=True)
    raw = json.loads((tmp_path / "profiles.json").read_text())
    stored = raw["profiles"][row["id"]]
    assert stored[tp.SECRET_FIELD] == tp.KEYRING_MARK and "s3cret" not in (tmp_path / "profiles.json").read_text()
    assert store[("dlp-check", row["id"])] == "s3cret"
    assert tp.get(row["id"], with_secret=True)[tp.SECRET_FIELD] == "s3cret"
    assert tp.get(row["id"])["has_secret"] is True
    tp.upsert({"name": "Acme"}, profile_id=row["id"], remember_secret=False)
    assert ("dlp-check", row["id"]) not in store and tp.SECRET_FIELD not in tp.get(row["id"], with_secret=True)


def test_profile_secret_falls_back_to_the_file_without_keyring(monkeypatch, tmp_path):
    monkeypatch.setitem(sys.modules, "keyring", None)
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    assert tp.secret_storage() == "file"
    row = tp.upsert({"name": "Beta", "vanity_domain": "beta", "client_id": "abc123456789"}, client_secret="plain", remember_secret=True)
    assert tp.get(row["id"], with_secret=True)[tp.SECRET_FIELD] == "plain"


def test_installs_are_hash_pinned_and_container_files_are_present():
    lock = open(os.path.join(ROOT, "requirements.lock")).read()
    assert lock.count("--hash=sha256:") > 100 and "fastapi==" in lock and "zscaler-sdk-python==" in lock
    assert "--require-hashes" in open(os.path.join(ROOT, "INSTALL_Zscaler_Assessment.bat")).read()
    assert "--require-hashes" in open(os.path.join(ROOT, "app_update.py")).read()
    df = open(os.path.join(ROOT, "Dockerfile")).read()
    assert "USER dlpcheck" in df and "--require-hashes" in df and "HEALTHCHECK" in df
    dc = open(os.path.join(ROOT, "docker-compose.yml")).read()
    assert '"127.0.0.1:8000:8000"' in dc and "read_only: true" in dc and "no-new-privileges:true" in dc
    wf = open(os.path.join(ROOT, ".github", "workflows", "tests.yml")).read()
    assert "pip-audit" in wf and "cyclonedx" in wf and "trivy" in wf
    assert "github.actor == github.repository_owner" in open(os.path.join(ROOT, ".github", "workflows", "apply-patch.yml")).read()
    assert os.path.exists(os.path.join(ROOT, ".github", "dependabot.yml"))
    for f in ("LICENSE", "CHANGELOG.md", "SECURITY.md"):
        assert os.path.exists(os.path.join(ROOT, f)), f
    assert not os.path.exists(os.path.join(ROOT, "dlp-assessment-automation.zip"))
