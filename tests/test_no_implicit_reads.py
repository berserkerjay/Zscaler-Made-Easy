"""The tenant is never read implicitly: not on server start, not on
sign-in, and an assessment reads only what the Scope page put in scope.
An unticked channel's configuration is never read, an empty or unknown
scope is refused before signing in, a run nobody listens to stops, and a
sign-in-only session is closed."""
from __future__ import annotations

import asyncio
import collections
import os
import tempfile
import threading
import time

import pytest
from fastapi.testclient import TestClient

import channel_scope as cs
import dlp_api_server as srv
import security
from dlp_assessment_full_auto import R

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
ALL_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac"]


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


class Recorder:
    """A client whose every GET is recorded and answered locally."""
    customer_id = ""
    vd = "acme"
    cloud = "zscaler"
    auth_method = "oneapi"

    def __init__(self, data):
        self.data = data
        self.eps = []

    def get(self, ep, *a, **k):
        self.eps.append(str(ep))
        return self.data, 200

    def __getattr__(self, name):
        return lambda *a, **k: ([], 200)


_ITEM = {"id": 1, "name": "x", "state": "ENABLED", "order": 1}
# List-, dict- and error-shaped answers: a check that reads a channel's
# configuration only after a dict answer (CA.5 after the advanced
# settings) is exercised too.
_SHAPES = ([], [_ITEM], {}, dict(_ITEM), {"list": [_ITEM]}, {"cascadeUrlFiltering": False, "enabled": False},
           {"cascadeUrlFiltering": True, "enabled": True})


def _reads(fn):
    eps = set()
    for data in _SHAPES:
        rec = Recorder(data)
        try:
            fn(rec)
        except Exception:  # noqa: BLE001 — a check that trips on the fake data still shows what it read
            pass
        eps |= set(rec.eps)
    return eps


# ── Server start reads nothing ───────────────────────────────────────────

def test_server_start_does_not_start_the_tenant_reading_loop(monkeypatch):
    monkeypatch.delenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", raising=False)
    started, built = [], []

    async def spy():
        started.append(1)

    monkeypatch.setattr(srv, "_dh_auto_refresh_loop", spy)
    monkeypatch.setattr(srv, "_DH_REFRESH_STATE", dict(srv._DH_REFRESH_STATE))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds))
    with TestClient(srv.app) as c:
        c.get("/")
        state = c.get("/api/detection-health/schedule").json()
    assert started == [] and built == [], "starting the server or loading the page must not read a tenant"
    assert state["enabled"] is False and "DLP_CHECK_CONTINUOUS_EVAL_HOURS" in state["setting"]


@pytest.mark.parametrize("value", ["", "0", "-3", "nonsense", "nan"])
def test_the_loop_stays_off_without_a_positive_opt_in(monkeypatch, value):
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", value)
    assert srv._continuous_eval_hours() == 0.0


def test_the_loop_runs_only_when_the_operator_opts_in(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "6")
    started = []

    async def spy():
        started.append(srv._DH_REFRESH_STATE["interval_seconds"])

    monkeypatch.setattr(srv, "_dh_auto_refresh_loop", spy)
    monkeypatch.setattr(srv, "_DH_REFRESH_STATE", dict(srv._DH_REFRESH_STATE))   # restored after the test
    with TestClient(srv.app):
        pass
    assert started == [6 * 3600] and srv._DH_REFRESH_STATE["enabled"] is True


# ── An unticked channel is never read ────────────────────────────────────

def test_every_check_that_reads_a_channel_configuration_is_mapped_to_it():
    """CHANNEL_READS cannot drift: a check that GETs a channel's endpoint
    must be listed under that endpoint."""
    missing = collections.defaultdict(list)
    for chk in srv._get_checks("", ALL_SCOPES):
        for ep in _reads(chk[3]):
            path = ep[4:] if ep.startswith("raw:") else ep
            for prefix in cs.ENDPOINT_CHANNELS:
                if (path == prefix or path.startswith(prefix + "/")) and chk[0] not in cs.CHANNEL_READS[prefix]:
                    missing[prefix].append(chk[0])
    assert not missing, dict(missing)


@pytest.mark.parametrize("ticked", [[], ["endpoint_dlp"], ["web_dlp"], ["genai_security"], ["email_dlp"]])
def test_checks_left_to_run_read_no_unticked_channel(ticked):
    channels = {c: ("zscaler" if c in ticked else "gap") for c in cs.CHANNELS}
    checks = srv._get_checks("", ALL_SCOPES)
    to_run, skipped, _ = cs.partition(checks, channels)
    on = set(ticked)
    bad = collections.defaultdict(list)
    for chk in to_run:
        for ep in _reads(chk[3]):
            chans = cs.endpoint_channels(ep)
            if chans and not on.intersection(chans):
                bad[ep.split("?")[0]].append(chk[0])
    assert not bad, f"ticked={ticked}: unticked channels read: {dict(bad)}"
    if not ticked:
        ids = {r["id"] for r in skipped}
        for cid in ("5.3", "8.4", "6.4", "5.18", "MC.12", "3.2"):
            assert cid in ids, cid


def test_the_checks_client_refuses_an_unticked_channel_without_reading():
    rec = Recorder([{"id": 1}])
    guard = cs.ScopedClient(rec, {"endpoint_dlp": "zscaler"})
    data, code = guard.get("/zia/webDlpRules")
    assert code == 0 and data["error"] == "not in scope" and rec.eps == []
    assert guard.get("/zia/endPointDlpRules") == ([{"id": 1}], 200)
    assert guard.get("/zia/dlpDictionaries")[1] == 200   # shared objects stay readable
    assert guard.get("/zia/casbTenant/lite")[1] == 0 and guard.get("/zia/sslInspectionRules?page=1")[1] == 0
    assert rec.eps == ["/zia/endPointDlpRules", "/zia/dlpDictionaries"] and guard.vd == "acme"
    # Nothing declared (an MCP / CLI caller): nothing is refused.
    assert cs.ScopedClient(rec, {}).get("/zia/webDlpRules")[1] == 200


def test_a_partial_or_malformed_declaration_leaves_the_rest_unticked():
    checks = srv._get_checks("dlp", ["dlp"])
    full = cs.partition(checks, {c: ("zscaler" if c == "web_dlp" else "gap") for c in cs.CHANNELS})
    for partial in ({"web_dlp": "zscaler"}, {"web_dlp": "zscaler", "endpoint_dlp": None}, {"web_dlp": "zscaler", "endpoint_dlp": 7}):
        run, skipped, _ = cs.partition(checks, partial)
        assert [c[0] for c in run] == [c[0] for c in full[0]], partial
        assert {"5.1", "MC.2", "8.1", "B.1", "B.2"} <= {r["id"] for r in skipped}
    cov = cs.coverage({"web_dlp": "zscaler"})
    assert [g["id"] for g in cov["gaps"]] == [c for c in cs.CHANNELS if c != "web_dlp"]
    assert cs.normalize({"endpoint_dlp": None})["endpoint_dlp"]["choice"] == "gap"
    # Nothing declared still narrows nothing.
    assert cs.partition(checks, {})[1] == []


# ── The journey reads only the channels in scope ─────────────────────────

def test_an_endpoint_only_journey_does_not_read_web_dlp_rules(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")
    from test_pack_channels import add_control_services, make_client
    packs, targets = srv._journey_scope(["zbp_enterprise_baseline"],
                                        {"endpoint_dlp": "zscaler", "web_dlp": "gap", "email_dlp": "gap", "saas_casb": "gap"})
    assert targets == {"zbp_enterprise_baseline": ["endpoint"]}
    client = add_control_services(make_client())
    web, ep = [], []
    real_web, real_ep = client.zia.dlp_web_rules.list_rules, client.zia.endpoint_dlp_rules.list_rules
    monkeypatch.setattr(client.zia.dlp_web_rules, "list_rules", lambda *a, **k: web.append(1) or real_web(*a, **k))
    monkeypatch.setattr(client.zia.endpoint_dlp_rules, "list_rules", lambda *a, **k: ep.append(1) or real_ep(*a, **k))
    srv._journey_for(client, packs, channel_targets=targets, progress=lambda *a: None)
    assert web == [], "Web DLP is unticked but the journey read its rules"
    assert ep, "the ticked channel is still read"
    # The explicit journey and the deploy path (no channel targets) still read web rules.
    srv._journey_for(client, packs, progress=lambda *a: None)
    assert web


# ── Nothing selected is refused before signing in ────────────────────────

def _stream(body):
    with _page().stream("POST", "/api/assess", json=body) as r:
        return r.status_code, r.read()


@pytest.mark.parametrize("extra", [{"scopes": ["bogus"]}, {"scopes": [""]}, {"scopes": ["DLP"]},
                                   {"scope": ""}, {"scope": "nonsense"}, {"scope": "  "}])
def test_an_unknown_or_blank_scope_is_refused_before_sign_in(monkeypatch, extra):
    built = []

    class Fake:
        def __init__(self, *a, **k):
            built.append(1)

        def auth(self):
            return True

    monkeypatch.setattr(srv, "Client", Fake)
    status, body = _stream(dict(CREDS, **extra))
    assert status == 400 and b"Nothing to assess" in body and built == [], extra


def test_a_scope_whose_checks_are_all_in_unticked_channels_is_refused(monkeypatch):
    built = []
    monkeypatch.setattr(srv, "Client", lambda *a, **k: built.append(1))
    channels = {c: "gap" for c in cs.CHANNELS}
    status, body = _stream(dict(CREDS, scopes=["genai"], channels=channels))
    assert status == 400 and b"GenAI Security" in body and b"Tick the channel" in body and built == []


# ── A run nobody listens to stops reading ────────────────────────────────

def test_closing_the_stream_cancels_the_queued_checks(monkeypatch):
    ran = []
    lock = threading.Lock()

    def slow(c):
        time.sleep(0.2)
        with lock:
            ran.append(1)
        return R(R.PASS, "ok")

    class Fake:
        requests_made = 0

        def __init__(self, *a, **k):
            pass

        def auth(self):
            return True

    monkeypatch.setattr(srv, "Client", Fake)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [(f"c{i}", "sec", f"Check {i}", slow) for i in range(40)])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    req = srv.AssessRequest(**CREDS, scopes=["dlp"])

    async def go():
        resp = await srv.assess_stream(req)
        it = resp.body_iterator
        n = 0
        async for chunk in it:
            if "event: check" in str(chunk):
                n += 1
                if n >= 2:
                    break
        await it.aclose()
        with lock:
            at_close = len(ran)
        await asyncio.sleep(1.5)
        return at_close

    at_close = asyncio.run(go())
    with lock:
        after = len(ran)
    assert after - at_close <= srv.ASSESS_WORKERS, f"{after - at_close} checks ran after the stream closed"
    assert after < 40


# ── A sign-in-only session is closed ─────────────────────────────────────

def test_authenticate_closes_the_session_it_opened(monkeypatch):
    events = []

    class Sdk:
        def close(self):
            events.append("close")

    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: events.append("login") or Sdk())
    r = _page().post("/api/tenant/check", json=CREDS)
    assert r.status_code == 200 and r.json()["ok"] is True
    assert events == ["login", "close"]


def test_the_journey_session_is_closed(monkeypatch, tmp_path):
    import tenant_profiles
    from test_assess_stream import FakeClient
    events = []

    class Sdk:
        def close(self):
            events.append("close")

    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "p.json"))
    pid = tenant_profiles.upsert({"name": "Acme", "vanity_domain": "acme", "client_id": "abc123456789",
                                  "baseline_packs": ["zbp_enterprise_baseline"], "scopes": ["dlp"]})["id"]
    monkeypatch.setattr(srv, "Client", FakeClient)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: events.append("login") or Sdk())
    monkeypatch.setattr(srv, "_journey_for", lambda sdk, packs, **kw: {"status": "in_progress", "baselines": [], "stages": [], "blockers": []})
    with _page().stream("POST", "/api/assess", json=dict(CREDS, scopes=["dlp"], profile_id=pid, channels={"web_dlp": "zscaler"})) as r:
        assert r.status_code == 200
        r.read()
    assert events == ["login", "close"]


# ── The page says what happens ───────────────────────────────────────────

def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_run_while_signed_out_focuses_authenticate_and_sign_in_clears_the_warning():
    js = _read("static/dashboard.js")
    block = js[js.index("if (!signedIn()) {"):]
    block = block[:block.index("startRun();")]
    assert "goConnect('authBtn')" in block, "focus goes to the Authenticate button, never to <body>"
    assert "window.__dbSignedIn = function" in js
    guide = _read("static/guide.js")
    ok = guide[guide.index("function _gdAuthVerdict"):]
    ok = ok[ok.index("if (conn.ok) {"):]
    assert "window.__dbSignedIn()" in ok[:ok.index("return;")]


def test_authenticate_help_does_not_promise_a_role_check():
    assert "missing role" not in _read("static/explain.js")


def test_the_word_report_counts_a_gap_channel_checks():
    from docx import Document
    from report_docx import generate_report
    from dlp_assessment_full_auto import compute, maturity
    rows = [{"id": "1", "sec": "Web", "section": "Web", "label": "a", "status": "PASS", "detail": ""},
            {"id": "2", "sec": "Email", "section": "Email", "label": "b", "status": "INFO", "detail": "Not in scope: ...", "out_of_scope": True, "gap": True},
            {"id": "3", "sec": "Email", "section": "Email", "label": "c", "status": "INFO", "detail": "Not in scope: ...", "out_of_scope": True, "gap": True}]
    cov = cs.coverage({"web_dlp": "zscaler", "email_dlp": "gap"}, [{"channel": "email_dlp"}, {"channel": "email_dlp"}])
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "r.docx")
        generate_report(rows, {"org_name": "Acme", "channel_coverage": cov}, path, compute, maturity)
        doc = Document(path)
        text = "\n".join(p.text for p in doc.paragraphs)
        table = next(t for t in doc.tables if t.rows[0].cells[0].text == "Channel" and t.rows[0].cells[2].text == "Checks not in scope")
        rows_by_name = {r.cells[0].text: [c.text for c in r.cells] for r in table.rows[1:]}
    assert rows_by_name["Email DLP"][1] == "Gap" and rows_by_name["Email DLP"][2] == "2"
    assert rows_by_name["Inline Web DLP"][2] == "—"
    assert "was left as a gap on the Scope page" in text
