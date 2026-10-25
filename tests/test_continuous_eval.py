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


@pytest.fixture(autouse=True)
def _remember_secrets_in_the_profile_file(monkeypatch):
    # No credential store in the tests: remembering a secret in the profile
    # file is the explicit opt-in (DLP_CHECK_SECRET_STORE=file).
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")


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


IN_SCOPE = {"scopes": ["dlp"], "channels": {"saas_casb": "zscaler", "email_dlp": "zscaler"}}


def _profile(remember=True, name="Acme", **fields):
    base = {"name": name, "cloud": "production", "vanity_domain": name.lower(), "client_id": "abc123456789", "baseline_packs": []}
    base.update(IN_SCOPE if not fields else fields)
    p = tp.upsert(base, client_secret="secret-secret-secret", remember_secret=remember)
    return p["id"]


def test_run_once_builds_a_digest_and_raises_tenant_proposals(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    # No credential store in the test environment: remembering a secret in
    # the profile file is an explicit opt-in (DLP_CHECK_SECRET_STORE=file).
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")

    pid = _profile()
    tenants = [{"tenant_id": 1, "tenant_name": "Acme OneDrive", "saas_application": "ONEDRIVE", "status": "ACTIVE", "saas_type": "OFLCASB_DLP_FILE"},
               {"tenant_id": 2, "tenant_name": "Acme Box", "saas_application": "BOX", "status": "AUTH_EXPIRED", "saas_type": "OFLCASB_DLP_FILE"}]
    monkeypatch.setattr("detection_health.generate", lambda client, days=30, settings=None, log=None, **kw: dict(REPORT, incident_count=36, summary={"closed": 30, "not_real": 12, "fp_rate_pct": 40, "noisy_rules": 1, "dead_rules": 1, "promotable_rules": 1, "noisy_dictionaries": 1}))
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
    assert chans["email"]["sent"] and sent["to"] == "soc@example.test" and sent["tls"] and sent["login"] == "bot" and "Zscaler Made Easy digest" in sent["subject"]
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
    assert chans["webhook"]["sent"] and posted["url"].startswith("https://") and "Zscaler Made Easy digest" in posted["text"]
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
    assert c.get(f"/api/digests/{did}?format=markdown").text.startswith("# Zscaler Made Easy digest")
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


# ── Off by default, and only what is in scope ────────────────────────
# Every tenant read counts against the ZIA API rate limit: nothing reads a
# tenant until the operator runs it, and then only what the profile's Scope
# page puts in scope.

def _state(monkeypatch):
    st = {"enabled": False, "interval_seconds": None, "interval_hours": None, "last_run_at": None, "next_run_at": None,
          "last_status": None, "profiles": {}}
    monkeypatch.setattr(srv, "_DH_REFRESH_STATE", st)
    started = []
    monkeypatch.setattr(srv.asyncio, "create_task", lambda coro: started.append(coro) or coro.close())
    return st, started


@pytest.mark.parametrize("value", [None, "", "0", "abc", "-6", "nan"])
def test_the_timer_is_off_unless_the_operator_opts_in(monkeypatch, value):
    import asyncio
    if value is None:
        monkeypatch.delenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", raising=False)
    else:
        monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", value)
    st, started = _state(monkeypatch)
    asyncio.run(srv._start_dh_refresh())
    assert started == [] and st["enabled"] is False and st["next_run_at"] is None and st["interval_hours"] == 0
    assert ce.notification_settings()["interval_hours"] == 0


def test_the_timer_starts_when_the_operator_sets_hours(monkeypatch):
    import asyncio
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "6")
    st, started = _state(monkeypatch)
    asyncio.run(srv._start_dh_refresh())
    assert len(started) == 1 and st["enabled"] is True and st["interval_seconds"] == 6 * 3600
    assert ce.notification_settings()["interval_hours"] == 6


def test_a_bad_value_is_logged(monkeypatch, capsys):
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "six")
    assert ce.interval_hours() == 0
    assert "DLP_CHECK_CONTINUOUS_EVAL_HOURS='six' is not a number" in capsys.readouterr().out


class _Recorder:
    """Records every tenant read the loop makes."""

    def __init__(self, monkeypatch):
        self.calls = []
        rec = self.calls
        monkeypatch.setattr("detection_health.generate", lambda client, days=30, settings=None, log=None, **kw: rec.append(("detection_health",)) or dict(REPORT, incident_count=1, summary={}))
        monkeypatch.setattr("saas_matrix.list_tenants", lambda client: rec.append(("list_tenants",)) or ([], None))

        def _preflight(client, packs, **kw):
            rec.append(("preflight", sorted(p["id"] for p in packs), kw.get("channel_targets")))
            return {"items": [], "summary": {}}
        monkeypatch.setattr("pack_deploy.preflight", _preflight)
        monkeypatch.setattr("pack_deploy.journey", lambda rep: {"baselines": []})
        monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])

    def build(self, creds):
        self.calls.append(("connect",))
        return object()

    def kinds(self):
        return [c[0] for c in self.calls]


def test_a_profile_with_no_scope_saved_is_not_read(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(scopes=[], channels={}, baseline_packs=["healthcare_phi_baseline"])
    d = ce.run_once(build_client=rec.build, notify=False)
    t = d["tenants"][0]
    assert rec.calls == [], "nothing in scope: no client is built and nothing is read"
    assert t["note"].startswith("nothing in scope") and t["errors"] == [] and t["detection_health"] is None and t["drift"] is None
    assert "Nothing in scope" in ce.to_markdown(d)


def test_only_the_saas_channel_in_scope_reads_only_the_saas_tenants(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(scopes=["zia_extras"], channels={"saas_casb": "zscaler", "web_dlp": "zscaler"}, baseline_packs=["healthcare_phi_baseline"])
    d = ce.run_once(build_client=rec.build, notify=False)
    assert rec.kinds() == ["connect", "list_tenants"], rec.calls
    t = d["tenants"][0]
    assert t["detection_health"] is None and t["drift"] is None and any("DLP is not in" in x for x in t["skipped"])


@pytest.mark.parametrize("choice", ["alternative", "gap", None])
def test_saas_not_on_zscaler_is_never_read(tmp_path, monkeypatch, choice):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    chans = {"web_dlp": "zscaler", "email_dlp": "alternative"}
    if choice:
        chans["saas_casb"] = choice
    _profile(scopes=["dlp"], channels=chans, baseline_packs=["healthcare_phi_baseline"])
    d = ce.run_once(build_client=rec.build, notify=False)
    assert "list_tenants" not in rec.kinds(), rec.calls
    assert rec.kinds() == ["connect", "detection_health", "preflight"], rec.calls
    # Only the ticked pack, only on the DLP channels the Scope page puts on Zscaler.
    assert rec.calls[-1] == ("preflight", ["healthcare_phi_baseline"], {"healthcare_phi_baseline": ["web"]})
    assert any("SaaS Security" in x for x in d["tenants"][0]["skipped"])


def test_pack_drift_never_defaults_to_every_pack_or_every_channel(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(name="NoPacks", scopes=["dlp"], channels={"web_dlp": "zscaler"}, baseline_packs=[])
    _profile(name="NoChannels", scopes=["dlp"], channels={"web_dlp": "gap", "endpoint_dlp": "alternative"}, baseline_packs=["healthcare_phi_baseline"])
    d = ce.run_once(build_client=rec.build, notify=False)
    assert "preflight" not in rec.kinds(), rec.calls
    by = {t["profile_id"]: t for t in d["tenants"]}
    assert by["nopacks"]["drift"]["note"].startswith("no packs ticked")
    assert "drift not measured" in by["nochannels"]["drift"]["note"]


def test_dlp_without_saas_or_dlp_scope_reads_nothing(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(scopes=["zpa", "zcc"], channels={"web_dlp": "zscaler", "saas_casb": "alternative"}, baseline_packs=["healthcare_phi_baseline"])
    d = ce.run_once(build_client=rec.build, notify=False)
    assert rec.calls == [] and d["tenants"][0]["note"].startswith("nothing in scope for the loop")


def test_manual_run_honours_scope_over_http(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=[], channels={})
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    r = c.post("/api/digests/run", json={"notify": False})
    assert r.status_code == 200 and rec.calls == [], (r.text, rec.calls)
    assert srv._DH_REFRESH_STATE["profiles"]["acme"]["status"] == "not in scope"


# ── Round 1 fixes: bounded timer, one run at a time, honest status ───

def _http():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


@pytest.mark.parametrize("value", ["1e306", "1e308", "inf", "-inf", "9000", "0.0001", "1e-9", "0.5"])
def test_an_unusable_number_of_hours_leaves_the_timer_off_and_the_digest_tab_loads(tmp_path, monkeypatch, capsys, value):
    import asyncio
    _env(tmp_path, monkeypatch)
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", value)
    st, started = _state(monkeypatch)
    asyncio.run(srv._start_dh_refresh())
    assert started == [] and st["enabled"] is False and st["interval_seconds"] is None and st["interval_hours"] == 0
    assert "the timer stays off" in capsys.readouterr().out
    c = _http()
    for path in ("/api/digests", "/api/detection-health/schedule"):
        r = c.get(path)
        assert r.status_code == 200, (path, r.text)


@pytest.mark.parametrize("value,hours", [("1", 1.0), ("6", 6.0), ("8784", 8784.0)])
def test_the_timer_accepts_one_hour_to_a_year(monkeypatch, value, hours):
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", value)
    assert ce.interval_hours() == hours


def test_a_bad_value_is_logged_once_at_startup_not_on_every_page_load(tmp_path, monkeypatch, capsys):
    import asyncio
    _env(tmp_path, monkeypatch)
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "six")
    st, _ = _state(monkeypatch)
    asyncio.run(srv._start_dh_refresh())
    assert capsys.readouterr().out.count("is not a number") == 1
    c = _http()
    for _ in range(3):
        r = c.get("/api/digests")
        assert r.status_code == 200 and r.json()["notifications"]["interval_hours"] == 0
    assert "DLP_CHECK_CONTINUOUS_EVAL_HOURS" not in capsys.readouterr().out
    # The page shows what the timer started with, not what the environment says now.
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "6")
    assert c.get("/api/digests").json()["notifications"]["interval_hours"] == 0


def test_a_non_ascii_value_never_stops_the_server_on_a_cp1252_log(monkeypatch):
    import asyncio
    import io
    import sys
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "6\u0447")
    buf = io.BytesIO()
    out = io.TextIOWrapper(buf, encoding="cp1252", errors="strict")
    monkeypatch.setattr(sys, "stdout", out)
    st, started = _state(monkeypatch)
    asyncio.run(srv._start_dh_refresh())
    out.flush()
    assert started == [] and st["enabled"] is False and b"\u0447" in buf.getvalue()


@pytest.mark.parametrize("scopes,read", [(5, False), (True, False), ({"dlp": 1}, False), ("dlp", True)])
def test_a_malformed_scopes_value_does_not_stop_the_run(tmp_path, monkeypatch, scopes, read):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(name="Good", scopes=["dlp"], channels={"web_dlp": "zscaler"})
    _profile(name="Odd", scopes=scopes, channels={"web_dlp": "zscaler"})
    d = ce.run_once(build_client=rec.build, notify=False)
    by = {t["profile_id"]: t for t in d["tenants"]}
    assert by["good"]["detection_health"] is not None
    assert (by["odd"]["detection_health"] is not None) is read, by["odd"]
    if not read:
        assert by["odd"]["note"].startswith("nothing in scope")


def test_a_second_run_while_one_is_in_progress_is_refused(tmp_path, monkeypatch):
    import asyncio
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"})
    c = _http()
    assert srv._LOOP_RUN_LOCK.acquire(blocking=False)
    try:
        r = c.post("/api/digests/run", json={"notify": False})
        assert r.status_code == 409 and "already in progress" in r.text, r.text
        assert rec.calls == []
        # The timer's pass is skipped too, without an error.
        st, _ = _state(monkeypatch)
        st.update({"enabled": True, "interval_seconds": 3600})

        async def _go():
            sleeps = []

            async def _sleep(s):
                sleeps.append(s)
                if len(sleeps) > 1:
                    st["enabled"] = False
            monkeypatch.setattr(srv.asyncio, "sleep", _sleep)
            await srv._dh_auto_refresh_loop()
        asyncio.run(_go())
        assert rec.calls == [] and st["last_status"] is None
    finally:
        srv._LOOP_RUN_LOCK.release()
    r = c.post("/api/digests/run", json={"notify": False})
    assert r.status_code == 200 and "detection_health" in rec.kinds()


def test_a_run_whose_tenant_reads_failed_is_not_reported_as_ok(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)

    def _limited(client, days=30, settings=None, log=None, **kw):
        raise RuntimeError("429 Too Many Requests: rate limit exceeded")
    monkeypatch.setattr("detection_health.generate", _limited)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"})
    st, _ = _state(monkeypatch)
    r = _http().post("/api/digests/run", json={"notify": False})
    assert r.status_code == 200
    assert st["last_status"] == "partial" and st["last_run_at"], st
    assert ce.main(["--once", "--no-notify"]) == 1


def test_a_clean_run_is_ok(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    monkeypatch.setattr(srv, "_build_sdk_client", rec.build)
    _profile(scopes=["dlp"], channels={"web_dlp": "zscaler"})
    st, _ = _state(monkeypatch)
    assert _http().post("/api/digests/run", json={"notify": False}).status_code == 200
    assert st["last_status"] == "ok"


def test_a_profile_not_read_is_not_counted_as_evaluated(tmp_path, monkeypatch):
    _env(tmp_path, monkeypatch)
    rec = _Recorder(monkeypatch)
    _profile(scopes=[], channels={})
    d = ce.run_once(build_client=rec.build, notify=False)
    assert rec.calls == [] and d["summary"]["tenants"] == 0 and d["summary"]["tenants_not_in_scope"] == 1
    page = open(os.path.join(ce.ROOT, "static", "report_digest.html"), encoding="utf-8").read()
    assert "s.tenants_not_in_scope" in page and "not in scope, not read" in page


def test_digest_tile_text_wraps_and_the_docs_say_off_by_default():
    page = open(os.path.join(ce.ROOT, "static", "report_digest.html"), encoding="utf-8").read()
    assert ".dg-tile .d { font-size: 0.8rem; color: var(--dim); overflow-wrap: anywhere; }" in page
    ov = open(os.path.join(ce.ROOT, "docs", "OVERVIEW.md"), encoding="utf-8").read()
    assert "loop runs while the server runs" not in ov and "The **Digest** loop is off by default" in ov
    gs = open(os.path.join(ce.ROOT, "GETTING_STARTED.md"), encoding="utf-8").read()
    step2 = gs.split("2. refreshes Zscaler's SaaS tenant capability matrix")[1].split("3. runs")[0]
    assert "when SaaS Security (CASB) is marked as run on Zscaler" in step2
