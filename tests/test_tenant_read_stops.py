"""What an explicit run reads, and when it stops: every session the
assessment opens is ended, the journey makes no tenant read once the run
has ended or timed out, a legacy DLP scope still gets its journey, a
declaration nobody can read narrows everything, the Digest's loop reads
only each profile's saved scope, a read the tenant did not answer is
"Could not be checked", and the page shows a refused run's reason."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
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
LEGACY = {"vanity_domain": "acme", "auth_method": "legacy", "username": "admin@acme.com", "password": "pw-pw-pw-pw",
          "api_key": "abcdefghijkl"}


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


# ── Every session the assessment opens is ended ──────────────────────────

def _session_client(events):
    class Fake:
        requests_made = 7

        def __init__(self, *a, **k):
            events.append("login")

        def auth(self):
            return True

        def get(self, ep, *a, **k):
            return [], 200

        def close(self):
            events.append("close")
    return Fake


def test_the_checks_session_is_closed_when_the_run_ends(monkeypatch):
    events = []
    monkeypatch.setattr(srv, "Client", _session_client(events))
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    with _page().stream("POST", "/api/assess", json=dict(LEGACY, scopes=["dlp"], channels={"web_dlp": "zscaler"})) as r:
        assert r.status_code == 200
        body = r.read()
    assert b"event: complete" in body
    assert events == ["login", "close"]
    report = json.loads(body.decode("utf-8").split("event: complete\ndata: ", 1)[1].split("\n", 1)[0])
    assert report["metadata"]["api_requests"] == 7   # still counted, though the session is closed


def test_the_checks_session_is_closed_when_sign_in_fails(monkeypatch):
    events = []
    Fake = _session_client(events)
    Fake.auth = lambda self: (False, "refused")
    monkeypatch.setattr(srv, "Client", Fake)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    with _page().stream("POST", "/api/assess", json=dict(LEGACY, scopes=["dlp"])) as r:
        r.read()
    assert events == ["login", "close"]


class _Resp429:
    status_code = 429
    headers = {"Retry-After": "2"}
    text = ""

    def json(self):
        return []


def _limited_client(monkeypatch, sent):
    """The real Client, signed in, whose every GET is answered 429
    (Retry-After 2 s): a rate-limited tenant. Nothing leaves the process."""
    import dlp_assessment_full_auto as full
    lock = threading.Lock()

    def fake_get(url, params=None, timeout=None):
        with lock:
            sent.append((time.time(), url))
        return _Resp429()

    c = full.Client("abc123456789", "secret-secret-secret", "acme", "zscaler")
    c.token, c.exp = "t", time.time() + 3600
    c.sess.get = fake_get
    return c


def test_a_stopped_client_sends_nothing_more_not_even_a_retry(monkeypatch):
    sent = []
    c = _limited_client(monkeypatch, sent)
    res = []
    t = threading.Thread(target=lambda: res.append(c.get("/zia/webDlpRules")), daemon=True)
    t.start()
    while not sent:
        time.sleep(0.02)
    c.stop()
    t.join(5)
    assert not t.is_alive(), "the read kept waiting on Retry-After after the stop"
    assert len(sent) == 1 and res and res[0][1] == 0 and "stopped" in res[0][0]["error"]
    assert c.get("/zia/urlFilteringRules") == ({"error": "run stopped", "status": 0}, 0) and len(sent) == 1


def test_stop_ends_the_reads_of_checks_already_running(monkeypatch):
    # A check already running when the stream closes (Stop, the browser
    # gone) sends no further request: no 429 retry, no next endpoint.
    import dlp_assessment_full_auto as full
    sent = []
    made = []

    class C(full.Client):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.sess.get = _limited_client(monkeypatch, sent).sess.get
            made.append(self)

        def auth(self):
            self.token, self.exp = "t", time.time() + 3600
            return True

    def check(cl):   # reads several endpoints in turn, like AUTO-TF-01
        for ep in ("/zia/webDlpRules", "/zia/urlFilteringRules", "/zia/firewallFilteringRules", "/zia/sslInspectionRules"):
            cl.get(ep)
        return R(R.PASS, "ok")

    monkeypatch.setattr(srv, "Client", C)
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("AUTO-TF-01", "Automation", "ids", check)])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: ([], {}))
    req = srv.AssessRequest(**CREDS, scopes=["automation"])

    async def go():
        resp = await srv.assess_stream(req)

        async def consume():
            async for _ in resp.body_iterator:
                pass
        task = asyncio.ensure_future(consume())
        while not sent:
            await asyncio.sleep(0.02)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        t = time.time()
        await asyncio.sleep(3)   # longer than the tenant's Retry-After
        return t

    closed_at = asyncio.run(go())
    assert made and made[0].stopped.is_set()
    assert [u for ts, u in sent if ts > closed_at + 0.05] == [], "the running check kept reading after the stop"


def test_the_explicit_journey_endpoint_closes_its_session(monkeypatch):
    events = []

    class Sdk:
        def close(self):
            events.append("close")

    monkeypatch.setattr(srv, "_journey_packs", lambda ids: [{"id": "p1", "dir": "x"}])
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: events.append("login") or Sdk())
    monkeypatch.setattr(srv, "_journey_for", lambda *a, **k: events.append("read") or {"baselines": []})
    r = _page().post("/api/dlp-packs/journey", json=dict(CREDS, pack_ids=["p1"]))
    assert r.status_code == 200
    assert events == ["login", "read", "close"]


# ── The journey stops reading when the run ends ──────────────────────────

class _Reads:
    """An SDK client whose every listing is a timed tenant read; close()
    is recorded too."""

    def __init__(self, delay):
        self.delay = delay
        self.reads = []
        self.closed_at = None
        outer = self

        class Svc:
            def list_rules(self, *a, **k):
                time.sleep(outer.delay)
                outer.reads.append(time.time())
                return [], None, None

        class Zia:
            dlp_web_rules = Svc()

        self.zia = Zia()

    def close(self):
        self.closed_at = time.time()


def _journey_setup(monkeypatch, sdk, n_packs, reads_per_pack):
    import pack_deploy
    packs = [{"id": f"p{i}", "dir": "x"} for i in range(n_packs)]

    def preflight(client, pks, **kw):
        for _ in range(reads_per_pack):
            client.zia.dlp_web_rules.list_rules()
        return {}

    monkeypatch.setattr(pack_deploy, "load_sources", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("no files")))
    monkeypatch.setattr(pack_deploy, "preflight", preflight)
    monkeypatch.setattr(pack_deploy, "journey", lambda rep: {"baselines": [], "blockers": []})
    monkeypatch.setattr(srv, "Client", _session_client([]))
    monkeypatch.setattr(srv, "_get_checks", lambda scope, scopes: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, channels: (packs, {p["id"]: ["web"] for p in packs}))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: sdk)
    return srv.AssessRequest(**CREDS, scopes=["dlp"], channels={"web_dlp": "zscaler"})


def test_closing_the_stream_stops_the_journey_before_its_next_read(monkeypatch):
    sdk = _Reads(0.1)
    req = _journey_setup(monkeypatch, sdk, n_packs=5, reads_per_pack=5)

    async def go():
        resp = await srv.assess_stream(req)
        it = resp.body_iterator
        async for chunk in it:
            if '"journey": true' in str(chunk):
                break
        await asyncio.sleep(0.25)
        await it.aclose()
        closed = time.time()
        await asyncio.sleep(1.5)
        return closed

    closed = asyncio.run(go())
    after = [t for t in sdk.reads if t > closed]
    assert len(after) <= 1, f"{len(after)} journey reads after the stream closed"   # at most the read in flight
    assert len(sdk.reads) < 25
    assert sdk.closed_at is not None and all(t <= sdk.closed_at for t in sdk.reads), "the session was closed under a running read"


def test_a_timed_out_journey_reads_nothing_more(monkeypatch):
    sdk = _Reads(0.3)
    req = _journey_setup(monkeypatch, sdk, n_packs=3, reads_per_pack=4)
    monkeypatch.setattr(srv, "JOURNEY_TIMEOUT", 1)

    async def go():
        resp = await srv.assess_stream(req)
        ev = None
        async for chunk in resp.body_iterator:
            if "event: journey" in str(chunk):
                ev = time.time()
                payload = json.loads(str(chunk).split("data: ", 1)[1])
        await asyncio.sleep(1.5)
        return ev, payload

    ev, payload = asyncio.run(go())
    assert payload["journey"]["status"] == "error" and "did not finish" in payload["journey"]["error"]
    assert len([t for t in sdk.reads if t > ev]) <= 1, "the journey kept reading after it was reported as timed out"
    assert sdk.closed_at is not None and all(t <= sdk.closed_at for t in sdk.reads)


def test_the_stop_signal_refuses_any_further_sdk_call():
    stop = threading.Event()
    sdk = _Reads(0)
    wrapped = srv._StopAware(sdk, stop)
    wrapped.zia.dlp_web_rules.list_rules()
    stop.set()
    with pytest.raises(srv.JourneyStopped):
        wrapped.zia.dlp_web_rules.list_rules()
    assert len(sdk.reads) == 1


# ── A legacy scope with DLP still measures the journey ──────────────────

@pytest.mark.parametrize("scope,journey", [("dlp", True), ("full", True), ("all", True), ("zia", True), ("zpa", False)])
def test_a_legacy_scope_with_dlp_gets_the_journey(monkeypatch, tmp_path, scope, journey):
    import tenant_profiles
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "p.json"))
    pid = tenant_profiles.upsert({"name": "Acme", "vanity_domain": "acme", "client_id": "abc123456789",
                                  "baseline_packs": ["zbp_enterprise_baseline"]})["id"]
    called = []
    monkeypatch.setattr(srv, "Client", _session_client([]))
    monkeypatch.setattr(srv, "_get_checks", lambda s, ss: [("c1", "sec", "Check 1", lambda c: R(R.PASS, "ok"))])
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, ch: called.append(ids) or ([], {}))
    with _page().stream("POST", "/api/assess", json=dict(CREDS, scope=scope, profile_id=pid, channels={"web_dlp": "zscaler"})) as r:
        assert r.status_code == 200
        r.read()
    assert bool(called) is journey


# ── A declaration nobody can read is still a declaration ─────────────────

@pytest.mark.parametrize("channels", [{"x": None}, {"": "gap"}, {"   ": {"choice": "gap"}}, {"custom": 7}])
def test_an_unreadable_declaration_leaves_every_channel_unticked(channels):
    checks = srv._get_checks("dlp", ["dlp"])
    all_gap = cs.partition(checks, {c: "gap" for c in cs.CHANNELS})
    run, skipped, _ = cs.partition(checks, channels)
    assert [c[0] for c in run] == [c[0] for c in all_gap[0]], channels
    assert skipped
    rec_calls = []

    class Rec:
        def get(self, ep, *a, **k):
            rec_calls.append(ep)
            return [], 200

    guard = cs.ScopedClient(Rec(), channels)
    assert guard.get("/zia/webDlpRules")[1] == 0 and rec_calls == []
    assert cs.coverage(channels)["declared"] is True


# ── The opt-in timer has a floor ─────────────────────────────────────────
# A value below an hour never runs the timer more often: it is off.

@pytest.mark.parametrize("value,hours", [("0.00001", 0.0), ("1e-300", 0.0), ("0.5", 0.0), ("1", 1.0), ("6", 6.0), ("0", 0.0), ("", 0.0)])
def test_the_loop_interval_never_drops_below_an_hour(monkeypatch, value, hours):
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", value)
    assert srv._continuous_eval_hours() == hours


# ── The Digest's loop reads only each profile's saved scope ─────────────

class _Rec:
    """Records every SDK call by its path (zia.<service>.<method>)."""

    def __init__(self, target, calls, path="client"):
        object.__setattr__(self, "_t", target)
        object.__setattr__(self, "_calls", calls)
        object.__setattr__(self, "_path", path)

    def __getattr__(self, name):
        v = getattr(self._t, name)
        p = f"{self._path}.{name}"
        if callable(v) and not isinstance(v, type):
            def call(*a, **k):
                self._calls.append(p)
                return v(*a, **k)
            return call
        if isinstance(v, (str, int, float, bool, type(None), dict, list, tuple)):
            return v
        return _Rec(v, self._calls, p)


def _digest_profile(tmp_path, monkeypatch, **fields):
    import tenant_profiles as tp
    for k, v in {"DLP_CHECK_PROFILES": "p.json", "DLPCHECK_PROPOSALS_FILE": "proposals.json", "DLP_CHECK_AUDIT": "audit.log",
                 "DLP_CHECK_DIGESTS": "digests"}.items():
        monkeypatch.setenv(k, str(tmp_path / v))
    p = tp.upsert(dict({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": "abc123456789"}, **fields),
                  client_secret="secret-secret-secret", remember_secret=True)
    return tp.get(p["id"])


def test_the_digest_reads_only_the_ticked_channels(tmp_path, monkeypatch):
    import continuous_eval as ce
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")
    from test_pack_channels import add_control_services, make_client
    profile = _digest_profile(tmp_path, monkeypatch, baseline_packs=["zbp_enterprise_baseline"], scopes=["dlp"],
                              channels={"web_dlp": "zscaler", "endpoint_dlp": "gap", "saas_casb": "gap", "email_dlp": "gap"})
    dh = []
    monkeypatch.setattr("detection_health.generate", lambda client, days=30, **k: dh.append(1) or {"summary": {}})
    calls = []
    out = ce._evaluate_tenant(profile, lambda creds: _Rec(add_control_services(make_client()), calls), days=30, log=lambda s: None)
    read = set(calls)
    for bad in ("client.zia.endpoint_dlp_rules.list_rules", "client.zia.casb_dlp_rules.list_all_rules",
                "client.zia.outbound_email_dlp_rules.list_rules", "client.zia.saas_security_api.list_casb_tenant_lite"):
        assert bad not in read, f"{bad} was read though its channel is unticked"
    assert "client.zia.dlp_web_rules.list_rules" in read, "the ticked channel is still measured"
    assert dh == [1] and out["drift"]["packs"]
    assert any("SaaS tenants" in n for n in out["skipped"])


def _digest_client(calls):
    """The recording fake SDK client, with a Workflow Automation incident
    search and the Web DLP incident-receiver listers, so the real
    detection_health.generate can run on it (nothing is stubbed out)."""
    from types import SimpleNamespace
    from test_pack_channels import add_control_services, make_client
    c = add_control_services(make_client())
    c.zwa = SimpleNamespace(dlp_incidents=SimpleNamespace(dlp_incident_search=lambda **k: ([], None, None)))
    c.zia.dlp_resources = SimpleNamespace(list_dlp_incident_receiver=lambda: ([], None, None),
                                          list_dlp_icap_servers=lambda: ([], None, None))
    return _Rec(c, calls)


UNTICKED_READS = {
    "web_dlp": ("client.zia.dlp_web_rules.list_rules", "client.zia.dlp_resources.list_dlp_incident_receiver",
                "client.zia.dlp_resources.list_dlp_icap_servers"),
    "endpoint_dlp": ("client.zia.endpoint_dlp_rules.list_rules",),
    "saas_casb": ("client.zia.casb_dlp_rules.list_all_rules",),
    "email_dlp": ("client.zia.outbound_email_dlp_rules.list_rules",),
    "workflow_automation": ("client.zwa.dlp_incidents.dlp_incident_search",),
}


@pytest.mark.parametrize("ticked", [("web_dlp",), ("endpoint_dlp", "workflow_automation"), ("email_dlp",), ()])
def test_the_digests_detection_health_reads_only_the_ticked_channels(tmp_path, monkeypatch, ticked):
    # The FP/TP Detection Ratio step itself (detection_health.generate, not
    # stubbed): no unticked channel's rules, no SaaS tenant list unless
    # SaaS Security is ticked, no incidents unless Workflow Automation is.
    # With no DLP channel ticked nothing is read at all.
    import continuous_eval as ce
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")
    channels = {cid: ("zscaler" if cid in ticked else "gap") for cid in UNTICKED_READS}
    profile = _digest_profile(tmp_path, monkeypatch, baseline_packs=[], scopes=["dlp"], channels=channels)
    calls = []
    out = ce._evaluate_tenant(profile, lambda creds: _digest_client(calls), days=30, log=lambda s: None)
    read = set(calls)
    if not {"web_dlp", "endpoint_dlp", "saas_casb", "email_dlp"} & set(ticked):
        assert read == set() and out["detection_health"] is None and out["note"].startswith("nothing in scope"), (read, out)
        return
    assert out["detection_health"] is not None, out["errors"]
    for cid, eps in UNTICKED_READS.items():
        for ep in eps:
            if cid in ticked:
                assert ep in read, f"{ep} not read though {cid} is ticked"
            else:
                assert ep not in read, f"{ep} was read though {cid} is unticked"
    if "saas_casb" not in ticked:
        assert "client.zia.saas_security_api.list_casb_tenant_lite" not in read
        assert any("SaaS tenants" in n for n in out["skipped"])
    if "workflow_automation" not in ticked:
        assert any("Workflow Automation" in n for n in out["skipped"])
    # Shared objects stay readable.
    assert "client.zia.dlp_dictionary.list_dicts" in read


def test_detection_health_on_its_own_still_reads_every_channel():
    # The FP/TP Detection Ratio page (an explicit run without a scope) is unchanged.
    import detection_health
    calls = []
    detection_health.generate(_digest_client(calls), days=30)
    for eps in UNTICKED_READS.values():
        for ep in eps:
            assert ep in calls, ep


def test_the_digest_signs_in_to_nothing_outside_the_profiles_scope(tmp_path, monkeypatch):
    import continuous_eval as ce
    built = []
    for fields in ({"scopes": ["genai"], "channels": {"web_dlp": "zscaler"}}, {}):
        profile = _digest_profile(tmp_path, monkeypatch, baseline_packs=["zbp_enterprise_baseline"], **fields)
        out = ce._evaluate_tenant(profile, lambda creds: built.append(1), days=30, log=lambda s: None)
        assert out["drift"] is None and out["tenants"] is None and out["detection_health"] is None and (out["skipped"] or out["note"])
    assert built == []


# ── A read the tenant did not answer is "Could not be checked" ──────────

@pytest.mark.parametrize("code", [429, 503, 0])
def test_an_unanswered_read_is_could_not_be_checked(code):
    class Limited:
        def get(self, ep, *a, **k):
            return {"error": "rate limited", "status": code}, code

    checks = {c[0]: c for c in srv._get_checks("", ["dlp", "zia_extras"])}
    guard = cs.ScopedClient(Limited(), {})
    for cid in ("6.1", "6.3", "10.3", "2.3", "1.13", "UF.1"):
        guard.begin()
        r = checks[cid][3](guard)
        r = srv._unanswered_result(r, checks[cid][2], guard.unanswered())
        assert str(r.status) == "ERROR" and "Could not be checked" in r.detail, (cid, r.status, r.detail)
    # An answered read is judged as before.
    guard.begin()
    assert srv._unanswered_result(R(R.PASS, "ok"), "x", guard.unanswered()).status == R.PASS


class _Answer:
    headers = {"Retry-After": "0"}
    text = ""

    def __init__(self, code):
        self.status_code = code

    def json(self):
        return []


@pytest.mark.parametrize("code", [429, 503])
def test_a_partly_unanswered_fan_out_read_is_could_not_be_checked(code):
    # /zia/cloudApplicationRules is read one rule type at a time: one type
    # the tenant did not answer makes the whole read unanswered, never a
    # partial "no rules" list reported as HTTP 200.
    import dlp_assessment_full_auto as full
    import zscaler_full_checks as zf
    c = full.Client("abc123456789", "secret-secret-secret", "acme", "zscaler")
    c.token, c.exp, c._limiter.min_gap = "t", time.time() + 3600, 0
    c.sess.get = lambda url, params=None, timeout=None: _Answer(code if url.endswith("/webApplicationRules/AI_ML") else 200)
    sc = cs.ScopedClient(c, {"cloud_app_control": "zscaler"})
    sc.begin()
    r = srv._unanswered_result(zf.capp_1(sc), "Cloud app control", sc.unanswered())
    assert str(r.status) == "ERROR" and "Could not be checked" in r.detail, (r.status, r.detail)


def test_a_fan_out_part_the_tenant_refuses_is_still_left_out():
    # A rule type the tenant answers 404/403 for (not licensed) is skipped as before.
    import dlp_assessment_full_auto as full
    c = full.Client("abc123456789", "secret-secret-secret", "acme", "zscaler")
    c.token, c.exp, c._limiter.min_gap = "t", time.time() + 3600, 0
    c.sess.get = lambda url, params=None, timeout=None: _Answer(404 if url.endswith("/webApplicationRules/AI_ML") else 200)
    assert c.get("/zia/cloudApplicationRules") == ([], 200)


def test_a_rate_limited_run_reports_could_not_be_checked(monkeypatch):
    class Limited:
        requests_made = 0

        def __init__(self, *a, **k):
            pass

        def auth(self):
            return True

        def get(self, ep, *a, **k):
            return {"error": "rate limited", "status": 429}, 429

    monkeypatch.setattr(srv, "Client", Limited)
    checks = [c for c in srv._get_checks("", ["dlp", "zia_extras"]) if c[0] in ("6.1", "2.3")]
    monkeypatch.setattr(srv, "_get_checks", lambda s, ss: checks)
    monkeypatch.setattr(srv, "_journey_scope", lambda ids, ch: ([], {}))
    with _page().stream("POST", "/api/assess", json=dict(CREDS, scopes=["dlp"])) as r:
        body = r.read().decode("utf-8")
    report = json.loads(body.split("event: complete\ndata: ", 1)[1].split("\n", 1)[0])
    assert [c["status"] for c in report["checks"]] == ["ERROR", "ERROR"]
    assert report["score"] is None


# ── The page ─────────────────────────────────────────────────────────────

def _fn(src, start, end):
    i = src.index(start)
    return src[i:src.index(end, i)]


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_a_refused_run_shows_the_servers_reason_where_the_run_started(tmp_path):
    html = _read("static/index.html")
    code = (_fn(html, "async function runAssessment()", "function buildPartialReport()")
            + _fn(html, "// The server's reason for refusing a run", "function resetForm()"))
    detail = ("Nothing to assess: every check in the chosen scope belongs to a channel that is not ticked as Zscaler on the "
              "Scope page (GenAI Security). Tick the channel, then run the assessment.")
    harness = """
const vm = require('vm');
const els = {};
const el = id => els[id] || (els[id] = {id, value: 'x', textContent: '', disabled: false, style: {}, className: '',
  classList: {add(){}, remove(){}}});
const status = [], refused = [];
const ctx = {
  document: {getElementById: el}, window: {__dbRunStarted(){}, __dbRunRefused(r){ refused.push(r); }},
  profileHasSecret: () => false, popMissingCredsAlert(){}, getSelectedScopes: () => ['genai'],
  setStatus: (m, t) => status.push([m, t]), setStep(){}, migrateCredBody: () => ({}), alert(){}, confirm: () => true,
  AbortController, console, TextDecoder, setInterval, clearInterval,
  fetch: async () => ({ok: false, status: 400, json: async () => ({detail: DETAIL})}),
  buildPartialReport(){}, handleEvent(){},
};
vm.createContext(ctx);
vm.runInContext(CODE + '\\nthis.__run = runAssessment;', ctx);
ctx.__run().then(() => { process.stdout.write(JSON.stringify({status, refused, btn: els.runBtn.disabled})); });
""".replace("DETAIL", json.dumps(detail)).replace("CODE", json.dumps(code))
    f = tmp_path / "h.js"
    f.write_text(harness, encoding="utf-8")
    out = json.loads(subprocess.run(["node", str(f)], capture_output=True, text=True, check=True).stdout)
    assert out["refused"] == [detail]
    assert not any("Connection lost" in m or "partial" in m for m, _t in out["status"]), out["status"]
    assert out["status"][-1][0] == detail and out["btn"] is False


def test_a_refused_run_puts_the_tiles_back_and_returns_to_the_scope_page():
    js = _read("static/dashboard.js")
    block = _fn(js, "window.__dbRunRefused = function", "window.__dbProgress")
    for needle in ("showScopeView()", "setCurrent('scope')", "note(reason, 'warn')", "run.focus()", "b.cp", "b.sm"):
        assert needle in block, needle
    assert "beforeRun = {" in _fn(js, "window.__dbRunStarted = function", "window.__dbRunRefused")


def test_signing_in_answers_only_a_sign_in_first_warning():
    js = _read("static/dashboard.js")
    block = _fn(js, "window.__dbSignedIn = function", "};")
    assert "/^Sign in first/.test(" in block


def test_stop_aborts_the_running_assessment():
    html = _read("static/index.html")
    assert 'id="stopBtn"' in html and 'onclick="stopAssessment()"' in html
    run = _fn(html, "async function runAssessment()", "function buildPartialReport()")
    assert "signal: ctl ? ctl.signal : undefined" in run and "assessAbort = ctl" in run
    stop = _fn(html, "function stopAssessment()", "function resetForm()")
    assert "assessAbort.abort()" in stop
    assert "stopAssessment();" in _fn(html, "function resetForm()", "}\n")


def test_stop_during_the_journey_keeps_the_servers_complete_report(tmp_path):
    # Every check is in and the complete report is shown; the stream stays
    # open for the journey. Stop then ends only the journey measurement:
    # no browser-built PARTIAL report, no "queued checks were cancelled",
    # and the run's watchdog timer is cleared.
    html = _read("static/index.html")
    code = (_fn(html, "async function runAssessment()", "function buildPartialReport()")
            + _fn(html, "// The server's reason for refusing a run", "function resetForm()"))
    harness = """
const vm = require('vm');
const els = {};
const el = id => els[id] || (els[id] = {id, value: 'x', textContent: '', disabled: false, style: {}, className: '',
  classList: {add(){}, remove(){}}});
const status = [], calls = [], cards = [];
const timers = new Set();
const ctx = {
  document: {getElementById: el}, window: {__dbRunStarted(){}, __dbRunRefused(){}},
  profileHasSecret: () => false, popMissingCredsAlert(){}, getSelectedScopes: () => ['dlp'],
  setStatus: (m, t) => status.push([m, t]), setStep(){}, migrateCredBody: () => ({}), alert(){}, confirm: () => true,
  AbortController, console, TextDecoder,
  setInterval: (f, ms) => { const t = setInterval(f, ms); timers.add(t); return t; },
  clearInterval: t => { timers.delete(t); clearInterval(t); },
  _gdJourneyCard: j => cards.push(j), refreshBenchmarkJourney(){},
  buildPartialReport(){ calls.push('buildPartialReport'); },
  handleEvent(evt){ if (evt.score !== undefined) { ctx.reportData = evt; calls.push('complete-report'); } else if (evt.id) ctx.partialResults.push(evt); },
};
ctx.fetch = async (url, opts) => {
  let n = 0;
  const chunk = 'data: ' + JSON.stringify({id: '1.1', label: 'x', status: 'PASS'}) + '\\n\\n'
              + 'data: ' + JSON.stringify({score: 80, journey: {status: 'pending'}}) + '\\n\\n';
  return {ok: true, body: {getReader: () => ({
    read: () => n++ === 0 ? Promise.resolve({done: false, value: new TextEncoder().encode(chunk)})
      : new Promise((res, rej) => opts.signal.addEventListener('abort', () => rej(new Error('The operation was aborted.')))),
    cancel: async () => {},
  })}};
};
vm.createContext(ctx);
vm.runInContext(CODE + '\\nthis.__run = runAssessment; this.__stop = stopAssessment;', ctx);
const run = ctx.__run();
setTimeout(() => { calls.push('Stop clicked'); ctx.__stop(); }, 50);
run.then(() => { process.stdout.write(JSON.stringify({status, calls, cards, score: ctx.reportData.score, timers: timers.size})); process.exit(0); });
""".replace("CODE", json.dumps(code))
    f = tmp_path / "h.js"
    f.write_text(harness, encoding="utf-8")
    out = json.loads(subprocess.run(["node", str(f)], capture_output=True, text=True, check=True, timeout=30).stdout)
    assert out["calls"] == ["complete-report", "Stop clicked"], out["calls"]
    assert out["score"] == 80
    assert "Every check had finished" in out["status"][-1][0] and "queued" not in out["status"][-1][0], out["status"]
    assert out["cards"] and out["cards"][-1]["status"] == "error", out["cards"]
    assert out["timers"] == 0, "the watchdog keeps ticking after Stop"


def test_a_new_assessment_never_redraws_the_previous_runs_checks():
    html = _read("static/index.html")
    assert "partialResults = [];" in _fn(html, "function resetForm()", "}\n")


def test_a_path_analyzer_link_never_runs_by_itself():
    page = _read("static/report_path.html")
    assert "tenantChoices().then(run)" not in page and "q.get('run')" not in page


def test_the_digest_schedule_tile_follows_the_real_schedule(monkeypatch):
    page = _read("static/report_digest.html")
    assert "n.interval_hours || 6" not in page and "sc.enabled && n.interval_hours > 0" in page
    assert "set DLP_CHECK_CONTINUOUS_EVAL_HOURS to opt in" in page
    import continuous_eval as ce
    monkeypatch.delenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", raising=False)
    assert not ce.notification_settings()["interval_hours"]
    monkeypatch.setenv("DLP_CHECK_CONTINUOUS_EVAL_HOURS", "2")
    assert ce.notification_settings()["interval_hours"] == 2.0
