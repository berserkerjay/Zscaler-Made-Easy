"""Secure-by-default behaviours: loopback binds, gated writes to the app
folder, temp report files removed after sending, no secrets echoed."""
from __future__ import annotations

import os
import re

from fastapi.testclient import TestClient

import dlp_api_server as srv


def test_mcp_server_binds_loopback_by_default():
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dlp_mcp_server.py"), encoding="utf-8").read()
    assert 'host="0.0.0.0"' not in src
    assert '"ZSCALER_MCP_BIND_HOST", "127.0.0.1"' in src


def test_pack_upload_is_refused_unless_bound_to_localhost(monkeypatch, tmp_path):
    monkeypatch.setattr(srv, "get_bind_host", lambda: "0.0.0.0")
    monkeypatch.setattr(srv, "PACKS_ROOT", str(tmp_path))
    c = TestClient(srv.app)
    r = c.post("/api/dlp-packs/upload", json={"pack_name": "evil", "dictionaries": [], "engines": [], "policies": []})
    assert r.status_code == 403 and not os.path.exists(tmp_path / "evil")


def test_word_report_temp_file_is_removed_after_download(monkeypatch):
    removed = []
    real = srv._unlink_quietly

    def record(path):
        removed.append(path); real(path)

    monkeypatch.setattr(srv, "_unlink_quietly", record)
    c = TestClient(srv.app)
    checks = [{"id": "4.1", "section": "4 — SSL Policy", "label": "Decrypt", "status": "PASS", "detail": "ok"}]
    r = c.post("/api/report/docx", json={"checks": checks, "metadata": {"org": "Acme Bank/../x"}})
    assert r.status_code == 200, r.text[:200]
    assert re.search(r'filename="zscaler_Acme_Bank_x_\d{8}\.docx', r.headers["content-disposition"])
    assert len(r.content) > 1000
    # The FileResponse's background task unlinks the file once it has been sent.
    assert removed and not os.path.exists(removed[0])


def test_security_policy_is_documented():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sec = open(os.path.join(root, "SECURITY.md"), encoding="utf-8").read()
    assert "Reporting a vulnerability" in sec and "Known limitations" in sec
    readme = open(os.path.join(root, "README.md"), encoding="utf-8").read()
    assert "SECURITY.md" in readme and "read-only GET requests" not in readme


def test_same_origin_requests_pass_on_any_port_cross_origin_is_refused():
    """The CSRF check trusts the allowlist and the page the server itself
    served (Origin == scheme://Host), so a spare port or a machine name
    works; a page on another local port is still refused."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    c = TestClient(srv.app, base_url="http://127.0.0.1:8013")
    ok = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://127.0.0.1:8013", "Host": "127.0.0.1:8013"})
    assert ok.status_code != 403, ok.text
    bad = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://127.0.0.1:9999", "Host": "127.0.0.1:8013"})
    assert bad.status_code == 403 and "Origin not allowed" in bad.text
    named = c.post("/api/auth/unlock", json={"token": "nope"}, headers={"Origin": "http://laptop-42:8000", "Host": "laptop-42:8000"})
    assert named.status_code != 403
