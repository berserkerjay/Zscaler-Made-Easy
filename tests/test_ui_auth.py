"""UI token: the page and its assets load, everything else needs the token
(cookie, header or bearer); the launcher's ?token= URL becomes a cookie."""
from __future__ import annotations

import os
from conftest import read_store_text

from fastapi.testclient import TestClient

import dlp_api_server as srv
import security


def _on(monkeypatch):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "test-token-abc123")
    return TestClient(srv.app)


def test_api_needs_the_token_but_the_page_and_assets_do_not(monkeypatch):
    c = _on(monkeypatch)
    r = c.get("/api/health")
    assert r.status_code == 401 and r.json()["token_required"] and "ui_token.txt" in r.json()["detail"]
    assert "content-security-policy" in {k.lower() for k in r.headers}
    assert c.get("/").status_code == 200 and c.get("/app.css").status_code == 200
    assert c.get("/static/report_theme.js").status_code == 200 and c.get("/report/flow").status_code == 200
    assert c.get("/api/ping").json() == {"ok": True}
    assert c.get("/api/auth/status").json() == {"required": True, "unlocked": False, "token_file": "ui_token.txt", "sso": False}
    assert c.get("/api/health", headers={"X-DLP-Check-Token": "test-token-abc123"}).status_code == 200
    assert c.get("/api/health", headers={"Authorization": "Bearer test-token-abc123"}).status_code == 200
    assert c.get("/api/health", headers={"X-DLP-Check-Token": "wrong"}).status_code == 401


def test_launcher_url_sets_the_cookie_and_strips_the_token(monkeypatch):
    c = _on(monkeypatch)
    r = c.get("/?token=test-token-abc123", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    cookie = r.headers["set-cookie"]
    assert "dlpcheck_token=test-token-abc123" in cookie and "HttpOnly" in cookie and "SameSite=strict" in cookie.replace("SameSite=Strict", "SameSite=strict")
    assert c.get("/api/auth/status").json()["unlocked"] is True     # the client keeps the cookie
    assert c.get("/api/health").status_code == 200
    bad = TestClient(srv.app).get("/?token=nope", follow_redirects=False)
    assert bad.status_code == 401


def test_unlock_endpoint_exchanges_the_token_for_the_cookie(monkeypatch):
    c = _on(monkeypatch)
    assert c.post("/api/auth/unlock", json={"token": "nope"}).status_code == 401
    r = c.post("/api/auth/unlock", json={"token": "test-token-abc123"})
    assert r.status_code == 200 and "dlpcheck_token=" in r.headers["set-cookie"]
    assert c.get("/api/health").status_code == 200


def test_auth_can_be_switched_off_and_the_token_file_is_owner_only(monkeypatch, tmp_path):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    c = TestClient(srv.app)
    assert c.get("/api/health").status_code == 200
    assert c.get("/api/auth/status").json()["required"] is False
    assert security.write_ui_token_file(str(tmp_path)) is None
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.delenv("ZSCALER_UI_TOKEN", raising=False)
    path = security.write_ui_token_file(str(tmp_path))
    assert path and open(path).read() == security.ui_token() and len(security.ui_token()) >= 30
    if os.name != "nt":
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_pages_and_launcher_carry_the_unlock_flow():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    idx = open(os.path.join(root, "static", "index.html"), encoding="utf-8").read()
    theme = open(os.path.join(root, "static", "report_theme.js"), encoding="utf-8").read()
    vbs = open(os.path.join(root, "START_Zscaler_Made_Easy.vbs"), encoding="utf-8").read()
    assert "/api/auth/unlock" in idx and "token_required" in idx and "/api/auth/status" in idx
    assert "/api/auth/unlock" in theme and "token_required" in theme
    assert "ui_token.txt" in vbs and "/api/ping" in vbs and "?token=" in vbs
    assert "ui_token.txt" in open(os.path.join(root, ".gitignore")).read()


def test_rejected_tokens_are_written_to_the_audit_log(monkeypatch, tmp_path):
    """The token gate sits outside the audit middleware, so it records its own
    401s; the token that was offered is never written."""
    import json
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    c = _on(monkeypatch)
    assert c.get("/api/health", headers={"X-DLP-Check-Token": "guess-one"}).status_code == 401
    assert c.get("/api/health").status_code == 401
    assert c.get("/?token=guess-two", follow_redirects=False).status_code == 401
    assert c.get("/api/health", headers={"X-DLP-Check-Token": "test-token-abc123"}).status_code == 200
    text = read_store_text(log)
    events = [json.loads(ln) for ln in text.splitlines()]
    denied = [e for e in events if e["event"] == "auth_denied"]
    assert [(e["path"], e["reason"]) for e in denied] == [
        ("/api/health", "invalid UI token"), ("/api/health", "no UI token or sign-in"),
        ("/", "the UI token in the address was not valid")], denied
    assert all(e.get("client") for e in denied)
    assert "guess-one" not in text and "guess-two" not in text and "test-token-abc123" not in text


def test_without_sso_the_audit_actor_is_the_local_ui_token(monkeypatch, tmp_path):
    """SSO off: every audit line says the call came through the local UI
    token (or no token at all when the gate is off); a proposal's "by" is
    set the same way, whatever name the page sends."""
    import json
    import proposals as pr
    from test_proposals import REPORT
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    c = _on(monkeypatch)
    pr.refresh_from_report(REPORT, "acme")
    pid = next(p["id"] for p in pr.list_queue("acme") if p["kind"] == "retire_rule")
    r = c.post(f"/api/proposals/acme/{pid}/decide", json={"decision": "dismiss", "by": "Mallory"},
               headers={"X-DLP-Check-Token": "test-token-abc123"})
    assert r.status_code == 200 and r.json()["decided_by"] == "local UI token"
    events = [json.loads(ln) for ln in read_store_text(log).splitlines()]
    assert {e["actor"] for e in events if e["event"] in ("api", "proposal_decision")} == {"local UI token"}
    assert "Mallory" not in json.dumps([e for e in events if e["event"] == "proposal_decision"])
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    TestClient(srv.app).post("/api/tenant/check", json={})
    assert json.loads(read_store_text(log).splitlines()[-1])["actor"] == "local, no UI token"


def test_a_failed_audit_write_is_reported_loudly(monkeypatch, tmp_path, capsys):
    import audit
    import proposals as pr
    from test_proposals import REPORT
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "no-such-dir" / "audit.log"))
    assert audit.record("test_event", x=1) is None
    assert "AUDIT LOG WRITE FAILED" in capsys.readouterr().err
    # A crash inside the audit call of a decision is reported, not swallowed.
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    pr.refresh_from_report(REPORT, "acme")
    pid = next(p["id"] for p in pr.list_queue("acme") if p["kind"] == "retire_rule")
    def boom(*a, **k):
        raise RuntimeError("disk on fire")
    monkeypatch.setattr(audit, "record", boom)
    assert pr.decide("acme", pid, "dismiss", by="x")["status"] == "dismissed"
    err = capsys.readouterr().err
    assert "AUDIT LOG WRITE FAILED" in err and "disk on fire" in err
