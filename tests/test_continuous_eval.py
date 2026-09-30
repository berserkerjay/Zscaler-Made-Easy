"""Continuous evaluation, phase 5: one run evaluates guidance and every
tenant profile that remembers its secret, writes a digest, and notifies
only when there is something to say."""
from __future__ import annotations

import json
import os
import types

import pytest
from fastapi.testclient import TestClient

import continuous_eval as ce
import dlp_api_server as srv
import security
import tenant_profiles as tp
from test_pack_deploy import FakeClient, Obj
from test_proposals import REPORT


def _env(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_GUIDANCE_STATE", str(tmp_path / "guidance_state.json"))
    monkeypatch.setenv("DLP_CHECK_CHECKS_CONFIG", str(tmp_path / "checks_config.json"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DIGESTS", str(tmp_path / "digests"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX", str(tmp_path / "saas_apps.local.json"))
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX_REFRESH", "0")
    for k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_NOTIFY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})   # never this machine's real crawl cache


class _Casb:
    def __init__(self, tenants):
        self.tenants = tenants

    def list_casb_tenant_lite(self, query_params=None):
        return [Obj(**t) for t in self.tenants], None, None


def _client(tenants):
    c = FakeClient(rules=[Obj(id=7003, name="Old-Monitor", order=1, rank=7, action="ALLOW", state="ENABLED", dlp_engines=[{"id": 5100}], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_HIGH")])
    c.zia.saas_security_api = _Casb(tenants)
    return c


def _profile(remember=True):
    p = tp.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789", "baseline_packs": []},
                  client_secret="secret-secret-secret", remember_secret=remember)
    return p["id"]


def test_run_once_builds_a_digest_and_raises_tenant_proposals(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    pid = _profile()
    tenants = [{"tenant_id": 1, "tenant_name": "Acme OneDrive", "saas_application": "ONEDRIVE", "status": "ACTIVE", "saas_type": "OFLCASB_DLP_FILE"},
               {"tenant_id": 2, "tenant_name": "Acme Box", "saas_application": "BOX", "status": "AUTH_EXPIRED", "saas_type": "OFLCASB_DLP_FILE"}]
    monkeypatch.setattr("detection_health.generate", lambda client, days=30, settings=None, log=None: dict(REPORT, incident_count=36, summary={"closed": 30, "not_real": 12, "fp_rate_pct": 40, "noisy_rules": 1, "dead_rules": 1, "promotable_rules": 1, "noisy_dictionaries": 1}))
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    logs = []
    d = ce.run_once(build_client=lambda creds: _client(tenants), log=logs.append, notify=True)
    assert d["tenants"] and d["tenants"][0]["profile_id"] == pid and d["tenants"][0]["errors"] == [] , d["tenants"][0]
    t = d["tenants"][0]
    assert t["detection_health"]["incidents"] == 36 and t["proposals"]["new"] >= 4 and t["proposals"]["open"] >= 4
    assert t["tenants"]["not_active"][0]["name"] == "Acme Box" and "Email mirrors" in t["tenants"]["gaps"][0]
    assert t["drift"]["note"].startswith("no packs ticked")
    assert d["noteworthy"] and d["summary"]["proposals_new"] >= 4 and d["summary"]["tenants_not_active"] == 1
    import proposals
    kinds = {p["kind"] for p in proposals.list_queue("acme")}
    assert "reauthorise_tenant" in kinds and "promote_rule" in kinds
    # The digest is on disk, listed, readable, and rendered in plain English.
    assert os.path.isfile(d["path"]) and ce.list_digests()[0]["id"] == d["id"]
    md = ce.to_markdown(ce.get_digest(d["id"]))
    assert "Re-authorise SaaS tenant Acme Box" in md and "36 incidents" in md and "Something needs a look" in md
    # Nothing configured: the digest says so instead of failing.
    assert d["notified"][0]["channel"] == "none" and "no e-mail or webhook configured" in d["notified"][0]["why"]
    # The profile history carries the run.
    hist = tp.get(pid)["history"]
    assert any(h.get("continuous_evaluation") and h.get("detection_health") for h in hist)
    assert any("detection health 36 incidents" in line for line in logs)


def test_quiet_run_is_not_noteworthy_and_notifies_only_when_told(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    d = ce.run_once(build_client=None, notify=True)   # no profiles with a secret: only guidance
    assert d["tenants"] == [] and not d["noteworthy"] and d["notified"][0]["sent"] is False and "quiet" in d["notified"][0]["why"]
    # E-mail and webhook, sent through monkeypatched transports.
    sent = {}

    class _SMTP:
        def __init__(self, host, port, timeout=0): sent["host"] = (host, port)
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self, context=None): sent["tls"] = context
        def login(self, u, p): sent["login"] = u
        def send_message(self, msg): sent["subject"] = msg["Subject"]; sent["to"] = msg["To"]
    monkeypatch.setattr(ce.smtplib, "SMTP", _SMTP)
    posted = {}
    monkeypatch.setattr("requests.post", lambda url, json=None, timeout=0: (posted.update({"url": url, "text": json["text"]}) or types.SimpleNamespace(status_code=200, text="ok")))
    monkeypatch.setenv("DLP_CHECK_NOTIFY", "always")
    monkeypatch.setenv("DLP_CHECK_SMTP_HOST", "smtp.example.test"); monkeypatch.setenv("DLP_CHECK_DIGEST_TO", "soc@example.test"); monkeypatch.setenv("DLP_CHECK_SMTP_USER", "bot")
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "https://example.webhook.office.com/webhookb2/abc")
    d = ce.run_once(build_client=None, notify=True)
    chans = {n["channel"]: n for n in d["notified"]}
    assert chans["email"]["sent"] and sent["to"] == "soc@example.test" and sent["tls"] and sent["login"] == "bot" and "DLP-Check digest" in sent["subject"]
    # STARTTLS checks the mail server's certificate and name before the password is sent.
    import ssl
    assert sent["tls"].verify_mode == ssl.CERT_REQUIRED and sent["tls"].check_hostname
    # With TLS switched off the password is never sent in clear text.
    sent.clear()
    monkeypatch.setenv("DLP_CHECK_SMTP_TLS", "0")
    r = ce._send_email("s", "b", ce.notification_settings()["email"])
    assert not r["sent"] and "unencrypted" in r["why"] and "login" not in sent
    monkeypatch.delenv("DLP_CHECK_SMTP_USER")
    assert ce._send_email("s", "b", ce.notification_settings()["email"])["sent"] and "login" not in sent, "an open relay without sign-in still works"
    monkeypatch.delenv("DLP_CHECK_SMTP_TLS")
    assert chans["webhook"]["sent"] and posted["url"].startswith("https://") and "DLP-Check digest" in posted["text"]
    cfg = ce.notification_settings()
    assert cfg["email"]["configured"] and cfg["webhook"]["kind"] == "teams" and cfg["mode"] == "always"
    monkeypatch.setenv("DLP_CHECK_DIGEST_WEBHOOK", "http://insecure.example/hook")
    assert not ce.notification_settings()["webhook"]["configured"]


def test_endpoints_and_page(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.post("/api/digests/run", json={"notify": False})
    assert r.status_code == 200 and r.json()["digest"]["id"], r.text
    did = r.json()["digest"]["id"]
    lst = c.get("/api/digests").json()
    assert lst["digests"][0]["id"] == did and "notifications" in lst and "schedule" in lst and lst["sources"]["watched"] >= 10
    assert c.get(f"/api/digests/{did}").json()["id"] == did
    assert c.get(f"/api/digests/{did}?format=markdown").text.startswith("# DLP-Check digest")
    assert c.get("/api/digests/nope").status_code == 404
    assert c.get("/api/guidance/sources").json()["sources"][0]["id"]
    assert c.get("/api/saas-apps").json()["applications"]
    page = TestClient(srv.app).get("/report/digest")
    assert page.status_code == 200 and "Digest" in page.text and "/api/digests" in page.text and '<nav class="rp-bar" aria-label="Page actions">' in page.text
    assert "openDigestTab()" in c.get("/").text and "/report/digest" in c.get("/static/explain.js").text


def test_guidance_approval_lands_in_checks_config_over_http(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    import guidance, time
    art = {"url": "https://help.zscaler.com/zia/nss-dlp-fields", "title": "NSS feed: new DLP fields", "first_seen": time.time(), "source_name": "Zscaler Help Portal"}
    guidance.evaluate([art])
    import proposals
    p = proposals.list_queue(guidance.APP_TENANT)[0]
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.post(f"/api/proposals/app/{p['id']}/decide", json={"decision": "approve", "by": "jane"})
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    assert guidance.references_for("12.8")[0]["url"] == art["url"]
