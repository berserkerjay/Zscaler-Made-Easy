"""Path analyzer: Stop really stops the tenant reads, and only what is in
scope on the Scope page is ever read.

- Stop is checked between every read step (Client Connector, each ZIA
  section, each catalogue page, the URL lookup) and inside a request
  that waits out ZIA's rate limit: once pressed nothing more is sent and
  the job ends as stopped, never with a partial read shown as a result.
- The scope (ticked scopes and the channels marked Zscaler) decides what
  is read. A part out of scope is not read, and its hop, channel, verdict
  and motion say "not in scope", never "no rule" and never "could not
  read". A kept read is reused only for the same scope.

No real tenant: fakes only (a fake transport under the real assessment
Client for the rate-limit case).
"""
from __future__ import annotations

import json
import shutil
import threading
import time

import pytest

import data_flow as df
import path_analyzer as pa
from test_data_flow import ROUTES
from test_ssl_flow import CATALOGUE, FakeCl

ZCC_EPS = ("/zcc/webPolicies", "/zcc/forwardingProfiles", "/zcc/trustedNetworks", "/zia/pacFiles")
LOOKUP = {"chat.openai.com": {"urlClassifications": ["AI_ML_APPS"], "application": "CHATGPT_AI"},
          "mail.example.com": {"urlClassifications": ["WEB_MAIL"]},
          "casino.example": {"urlClassifications": ["GAMBLING"]}}
ALL_CHANNELS = {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "email_dlp": "zscaler", "saas_casb": "zscaler",
                "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"}


class Tenant(FakeCl):
    """The Data Flow fixture tenant that records every request it answers
    (GETs, catalogue pages and URL lookups) and can run a hook on each."""

    def __init__(self, on_request=None):
        super().__init__(ROUTES, CATALOGUE)
        self.requests = []
        self.on_request = on_request
        apps = self._zs.zia.cloud_applications
        real = apps.list_cloud_app_policy

        def paged(*a, **kw):
            self._count("catalogue:" + str((kw.get("query_params") or {}).get("app_class")))
            return real(*a, **kw)
        apps.list_cloud_app_policy = paged

    def _count(self, what):
        self.requests.append(what)
        if self.on_request:
            self.on_request(self, what)

    def get(self, ep, p=None):
        self._count(ep)
        return super().get(ep, p)

    def post(self, ep, body=None):
        self._count("lookup:" + str(body[0]))
        return [dict(LOOKUP.get(body[0], {"urlClassifications": []}), url=body[0])], 200

    def gets(self):
        return [r for r in self.requests if r.startswith("/")]


def _scope(scopes, channels):
    return df.path_scope(scopes, channels)


# Every part the path reads in scope (getattr: so each test reports on its own on a build without scopes).
FULL = getattr(df, "full_path_scope", dict)()


# ── Stop ──────────────────────────────────────────────────────────────

def test_stop_inside_the_zia_read_sends_nothing_more_and_returns_no_result():
    """Stop pressed while ZIA is being read: the next section is never
    asked, there is no catalogue page and no URL lookup, and the analysis
    ends as stopped instead of returning what it had."""
    ev = threading.Event()

    def stop_after_web_dlp(t, what):
        if what == "/zia/webDlpRules":
            ev.set()
    c = Tenant(stop_after_web_dlp)
    logs = []
    with pytest.raises(pa.Stopped, match="You clicked Stop"):
        pa.analyze(c, "chat.openai.com", "off", "windows", scope=FULL, log=logs.append, cancel=ev)
    assert c.requests[-1] == "/zia/webDlpRules", c.requests
    after = c.requests[c.requests.index("/zia/webDlpRules") + 1:]
    assert after == [], f"requests after Stop: {after}"
    assert not any(r.startswith(("catalogue:", "lookup:")) for r in c.requests)
    assert logs[-1].startswith("STOPPED") and not any(l.startswith("Verdict") for l in logs)


def test_stop_inside_the_client_connector_read_sends_nothing_more():
    ev = threading.Event()
    c = Tenant(lambda t, what: ev.set() if what == "/zcc/webPolicies" else None)
    with pytest.raises(pa.Stopped):
        pa.analyze(c, "chat.openai.com", "off", "windows", scope=FULL, cancel=ev)
    assert c.requests == ["/zcc/webPolicies"], c.requests


def test_stop_between_catalogue_pages_sends_no_further_page():
    ev = threading.Event()
    c = Tenant(lambda t, what: ev.set() if what.startswith("catalogue:") else None)
    with pytest.raises(pa.Stopped):
        pa.analyze(c, "chat.openai.com", "off", "windows", scope=FULL, cancel=lambda: ev.is_set())
    assert sum(1 for r in c.requests if r.startswith("catalogue:")) == 1 and c.requests[-1].startswith("catalogue:"), c.requests


def test_a_read_cut_short_is_never_handed_on_as_a_finished_one():
    """read_zia itself raises on Stop, also after its last request, so no
    caller can take a partial read for the tenant's policy."""
    ev = threading.Event()
    c = Tenant(lambda t, what: ev.set() if what == "/zia/urlCategories" else None)
    with pytest.raises(df.ReadStopped):
        df.read_zia(c, scope=FULL, cancel=ev)
    assert c.requests[-1] == "/zia/urlCategories"


class _Resp:
    def __init__(self, status, headers=None, body=b"[]"):
        import requests
        r = requests.models.Response()
        r.status_code = status
        r.headers.update(headers or {})
        r._content = body
        self.r = r


class _RateLimitedAdapter:
    """A transport that answers every request 429 with a 30 s Retry-After."""

    def __init__(self):
        self.sent = []

    def send(self, request, **kw):
        self.sent.append(request.url)
        resp = _Resp(429, {"Retry-After": "30"}, b'{"message": "Rate Limit (1/SECOND) exceeded"}').r
        resp.request, resp.url = request, request.url
        return resp

    def close(self):
        pass


def test_stop_while_waiting_out_a_rate_limit_ends_at_once_and_sends_nothing_more():
    """The assessment Client pauses 30 s after a 429 and retries. A Stop
    pressed during that pause ends the wait at once: no retry is sent and
    the job ends as stopped (before, the read slept the pause out and
    retried three times)."""
    from dlp_assessment_full_auto import Client
    cl = Client("cid12345678", "secret-secret", "acme", "production")
    cl.token, cl.exp = "t", time.time() + 3600
    adapter = _RateLimitedAdapter()
    cl.sess.mount("https://", adapter)
    ev = threading.Event()
    box = {}

    def run():
        try:
            pa.analyze(cl, "chat.openai.com", "off", "windows", scope=df.path_scope(["zcc"], {}), cancel=ev)
        except BaseException as e:  # noqa: BLE001
            box["e"] = e

    th = threading.Thread(target=run, daemon=True)
    th.start()
    deadline = time.time() + 5
    while not adapter.sent and time.time() < deadline:
        time.sleep(0.02)
    assert adapter.sent, "the first request went out"
    time.sleep(0.3)          # now inside the 30 s pause
    ev.set()
    th.join(timeout=5)
    assert not th.is_alive(), "Stop did not end the rate-limit wait"
    assert isinstance(box.get("e"), pa.Stopped), box
    assert len(adapter.sent) == 1, adapter.sent


def test_zia_rate_pacing_honours_stop_inside_a_wait():
    """A request paced by zia_rate (a write waiting out a hold) is not sent
    once Stop is pressed during the wait: the wait sleeps in short steps
    and raises Cancelled."""
    import zia_rate
    zia_rate.hold(120)
    ev = threading.Event()
    naps = []

    def nap(s):
        naps.append(s)
        ev.set()
    old = zia_rate._sleep
    zia_rate._sleep = nap
    try:
        with zia_rate.stopping_on(ev.is_set):
            with pytest.raises(zia_rate.Cancelled):
                zia_rate.wait("POST", "/zia/urlLookup")
    finally:
        zia_rate._sleep = old
    assert naps and all(s <= zia_rate.CANCEL_STEP for s in naps) and len(naps) == 1, naps


def _fake_clock(monkeypatch):
    """A fake clock under zia_rate: each nap moves it on by the nap."""
    import zia_rate
    t, naps = [1000.0], []

    def nap(s):
        naps.append(s)
        t[0] += s
    monkeypatch.setattr(zia_rate, "_now", lambda: t[0])
    monkeypatch.setattr(zia_rate, "_sleep", nap)
    return t, naps


def test_a_stoppable_write_waits_out_the_whole_hold_when_stop_is_not_pressed(monkeypatch):
    """Stop armed but never pressed: a write inside stopping_on sleeps in
    CANCEL_STEP steps, yet still waits out all of ZIA's hold before it is
    sent (every assessment and path-analyzer write runs this way). Not a
    read: reads do not wait for a hold by design."""
    import zia_rate
    t, naps = _fake_clock(monkeypatch)
    end = zia_rate.hold(120)
    with zia_rate.stopping_on(lambda: False):
        waited = zia_rate.wait("POST", "/zia/api/v1/webDlpRules")
    assert waited >= 119.5 and t[0] >= end, (waited, t[0], end)
    assert naps and all(s <= zia_rate.CANCEL_STEP for s in naps), naps


def test_a_stoppable_paced_write_waits_the_whole_delay_when_stop_is_not_pressed(monkeypatch):
    """The same for a paced (non-hold) wait longer than CANCEL_STEP: the
    write waits until the bucket has room again."""
    import zia_rate
    monkeypatch.setenv("DLP_CHECK_ZIA_LIMIT_WRITE", "1/m")
    t, naps = _fake_clock(monkeypatch)
    zia_rate.wait("POST", "/zia/api/v1/webDlpRules")   # fills the write bucket
    first = t[0]
    with zia_rate.stopping_on(lambda: False):
        waited = zia_rate.wait("POST", "/zia/api/v1/webDlpRules")
    assert waited >= 59.5 and t[0] - first >= 60, (waited, t[0] - first)
    assert naps and all(s <= zia_rate.CANCEL_STEP for s in naps), naps


class _Req:
    def __init__(self, method, url):
        self.method, self.url = method, url


class _Session:
    """A fake requests session: records what it would send."""
    def __init__(self):
        self.sent = []

    def send(self, request, **kwargs):
        self.sent.append((request.method, request.url))
        return "ok"


ZIA_URL = "https://api.zsapi.net/zia/api/v1"


@pytest.mark.parametrize("req", [_Req("POST", ZIA_URL + "/webDlpRules"),
                                 _Req("POST", ZIA_URL + "/authenticatedSession")],
                         ids=["prepaced", "authenticatedsession"])
def test_a_paced_session_sends_nothing_after_stop_even_for_a_request_it_would_not_pace(req):
    """A request just paced by its caller (wait() marks it) or an
    authenticatedSession request skips the session's own wait(), but it is
    still not sent once Stop is pressed."""
    import zia_rate
    s = _Session()
    zia_rate._pace_session(s, "k")
    zia_rate._ctx.prepaced = zia_rate._now()
    try:
        with zia_rate.stopping_on(lambda: True):
            with pytest.raises(zia_rate.Cancelled):
                s.send(req)
    finally:
        zia_rate._ctx.prepaced = None
    assert s.sent == []


def test_a_caller_paced_mark_lets_only_one_request_skip_the_session_wait(monkeypatch):
    """wait() marks the one request it paced; the next request the session
    sends is paced again (the mark is used up)."""
    import zia_rate
    calls = []
    real_wait = zia_rate.wait
    monkeypatch.setattr(zia_rate, "wait", lambda *a, **k: (calls.append(a), real_wait(*a, **k))[1])
    s = _Session()
    zia_rate._pace_session(s, "k")
    zia_rate.wait("POST", "/webDlpRules", key="k")   # the caller paces its request
    calls.clear()
    s.send(_Req("POST", ZIA_URL + "/webDlpRules"))
    assert calls == [], "the request its caller just paced is not paced twice"
    s.send(_Req("POST", ZIA_URL + "/webDlpRules"))
    assert len(calls) == 1, "the next request is paced again"
    assert len(s.sent) == 2


def test_stop_ends_the_job_as_stopped_with_no_result_and_no_kept_read(monkeypatch):
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    gate, entered = threading.Event(), threading.Event()

    def hold_on_ssl(t, what):
        if what == "/zia/sslInspectionRules":
            entered.set()
            gate.wait(10)
    c = Tenant(hold_on_ssl)
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret",
            "destination": "chat.openai.com", "scopes": ["dlp", "zia_extras", "zcc"], "channels": ALL_CHANNELS}
    r = t.post("/api/path-analyzer/start", json=body)
    assert r.status_code == 200, r.text
    job = r.json()["job_id"]
    assert entered.wait(10)
    assert t.post(f"/api/dlp-packs/jobs/{job}/cancel").status_code == 200
    n = len(c.requests)
    gate.set()
    deadline = time.time() + 15
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            break
        time.sleep(0.05)
    assert snap["status"] == "cancelled", snap
    res = snap.get("result") or {}
    assert res.get("stopped") and "verdict" not in res and "trace" not in res and "report_id" not in res, res
    assert len(c.requests) == n, f"requests after Stop: {c.requests[n:]}"
    assert any("nothing more is read" in l for l in snap["logs"])


# ── Scope ─────────────────────────────────────────────────────────────

def test_the_scope_page_selection_decides_what_the_path_reads():
    sc = _scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "endpoint_dlp": "gap",
                          "email_dlp": {"choice": "alternative", "note": "Proofpoint"}})
    assert sc["read"] == ["cac", "url", "ssl", "ftc", "dlp"] and sc["lookup"]
    nis = sc["not_in_scope"]
    assert "ZCC is not ticked" in nis["zcc"] and "ZCC is not ticked" in nis["pac"]
    assert "Endpoint DLP is not marked Zscaler" in nis["endpoint"]
    assert "alternative solution (Proofpoint)" in nis["email"]
    assert "SaaS Security (CASB) is not marked Zscaler" in nis["saas"], "an undeclared channel is out of scope"
    assert "cac" not in nis, "Cloud App Control is a mandatory DLP analysis dependency"
    assert all(v.startswith("Not in scope:") for v in nis.values())
    nothing = _scope(["zpa", "rbac"], {"web_dlp": "zscaler"})
    assert nothing["read"] == [] and not nothing["lookup"]
    with pytest.raises(ValueError, match="Nothing the Path analyzer reads is in scope"):
        pa.analyze(Tenant(), "chat.openai.com", scope=nothing)
    with pytest.raises(ValueError, match="in scope"):
        pa.analyze(Tenant(), "chat.openai.com")
    assert _scope(["dlp", "zia_extras", "zcc"], ALL_CHANNELS)["key"] == FULL["key"]


def test_out_of_scope_parts_are_not_read_and_say_not_in_scope_never_no_rule():
    c = Tenant()
    sc = _scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "endpoint_dlp": "gap",
                          "email_dlp": "alternative"})
    r = pa.analyze(c, "chat.openai.com", "off", "windows", scope=sc)
    read = c.requests
    for ep in ZCC_EPS + ("/zia/endPointDlpRules", "/zia/emailDlpRules", "/zia/casbDlpRules/all"):
        assert ep not in read, ep
    assert any(x.startswith("catalogue:") for x in read), "the required Cloud App Control dependency reads its catalogue"
    assert {"/zia/sslInspectionRules", "/zia/webDlpRules", "/zia/urlFilteringRules", "/zia/fileTypeRules", "/zia/cloudApplicationRules"} <= set(read)
    t, v = r["trace"], r["verdict"]
    hop = {h["key"]: h for h in t["hops"]}
    for k in ("zcc", "forwarding"):
        assert hop[k]["status"] == "out_of_scope" and "Not in scope" in hop[k]["detail"], hop[k]
    for k in ("endpoint", "email", "saas"):
        ch = t["channels"][k]
        assert ch["status"] == "out_of_scope" and ch["detail"].startswith("Not in scope"), ch
        assert "No enabled" not in ch["detail"] and "could not" not in ch["detail"].lower()
    assert hop["dlp"]["status"] == "enforce", "Web DLP and SSL are in scope: still assessed"
    texts = " ".join(h["detail"] for h in t["hops"] if h["status"] == "out_of_scope")
    assert "could not be read" not in texts and "No Cloud App Control rule" not in texts
    assert {i["hop"] for i in v["not_in_scope"]} >= {"zcc", "forwarding", "endpoint", "email", "saas"}
    assert not any(i["status"] in ("unknown", "out_of_scope") for i in v["impacts"])
    assert r["scope"]["key"] == sc["key"] and r["scope"]["not_in_scope"] == sc["not_in_scope"]
    assert any("not in scope" in a for a in r["assumptions"])
    for p in t["packs"]:
        for rr in p["rules"]:
            if rr["channel"] in ("endpoint", "email", "saas"):
                assert rr["state"] == "not_in_scope", rr


def test_ssl_inspection_comes_with_web_dlp_as_its_prerequisite():
    # Inline Web DLP on Zscaler, SSL/TLS Inspection not ticked: SSL inspection
    # is Web DLP's prerequisite (channel_scope.PREREQUISITES), so it is read
    # and traced like any part in scope, never "not in scope".
    c = Tenant()
    sc = _scope(["dlp", "zcc"], {"web_dlp": "zscaler", "endpoint_dlp": "zscaler"})
    assert "ssl" in sc["read"] and "ssl" not in sc["not_in_scope"]
    r = pa.analyze(c, "chat.openai.com", "off", "windows", scope=sc)
    assert "/zia/sslInspectionRules" in c.requests
    ssl = next(h for h in r["trace"]["hops"] if h["key"] == "ssl")
    assert ssl["status"] != "out_of_scope", ssl
    dlp = next(h for h in r["trace"]["hops"] if h["key"] == "dlp")
    assert dlp["status"] != "out_of_scope", dlp


def test_endpoint_dlp_retains_required_ssl_without_reading_excluded_web_rules():
    # SSL stays mandatory for DLP assessment, while unselected Web DLP rules are still not read.
    c = Tenant()
    sc = _scope(["dlp", "zcc"], {"web_dlp": "gap", "endpoint_dlp": "zscaler"})
    r = pa.analyze(c, "chat.openai.com", "off", "windows", scope=sc)
    assert "/zia/sslInspectionRules" in c.requests and "/zia/webDlpRules" not in c.requests
    v = r["verdict"]
    assert v["outcome"] == "out_of_scope", v["outcome"]
    assert "not in scope" in v["headline"] and "no DLP rule" not in v["headline"] and "could not" not in v["headline"]
    ssl = next(h for h in r["trace"]["hops"] if h["key"] == "ssl")
    assert ssl["status"] != "out_of_scope" and "not marked Zscaler" not in ssl["detail"]
    dlp = next(h for h in r["trace"]["hops"] if h["key"] == "dlp")
    assert dlp["status"] == "out_of_scope"


def test_client_connector_only_reads_no_zia_policy_and_asks_no_lookup():
    c = Tenant()
    r = pa.analyze(c, "updates.vendor.com", "off", "windows", scope=_scope(["zcc"], {}))
    assert set(c.gets()) == set(ZCC_EPS), c.requests
    assert not any(x.startswith(("lookup:", "catalogue:")) for x in c.requests)
    assert r["lookup"]["not_in_scope"] and r["verdict"]["outcome"] == "bypassed"


def test_a_kept_read_is_reused_only_for_the_same_scope():
    c = Tenant()
    narrow = _scope(["dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler"})
    first = pa.analyze(c, "chat.openai.com", "off", "windows", scope=narrow)
    snap = first["snapshot_for_cache"]
    assert snap["path_scope"] == narrow["key"]
    n = len(c.gets())
    same = pa.analyze(c, "mail.example.com", "off", "windows", scope=narrow, snapshot=snap)
    assert not same["fresh_read"] and len(c.gets()) == n
    logs = []
    wider = pa.analyze(c, "chat.openai.com", "off", "windows", scope=FULL, snapshot=snap, log=logs.append)
    assert wider["fresh_read"] and len(c.gets()) > n and any("different scope" in l for l in logs)
    assert next(h for h in wider["trace"]["hops"] if h["key"] == "zcc")["status"] != "out_of_scope"
    m = len(c.gets())
    narrower = pa.analyze(c, "chat.openai.com", "off", "windows", scope=narrow, snapshot=wider["snapshot_for_cache"])
    assert narrower["fresh_read"] and len(c.gets()) > m
    assert next(h for h in narrower["trace"]["hops"] if h["key"] == "zcc")["status"] == "out_of_scope"
    assert not pa.reusable({"client_connector": {}, "snapshot": {}}, narrow), "a read that names no scope is never reused"


def _start(t, body):
    return t.post("/api/path-analyzer", json=body)


def test_the_endpoint_uses_the_page_scope_else_the_profile_and_refuses_nothing(monkeypatch):
    import dlp_api_server as srv
    import tenant_profiles
    from fastapi.testclient import TestClient
    built = []
    c = Tenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or c)
    monkeypatch.setattr(tenant_profiles, "get", lambda pid, **kw: {"id": pid, "name": "Acme", "scopes": ["zcc"], "channels": {}} if pid == "p1" else None)
    t = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "destination": "chat.openai.com"}
    # Nothing in scope: refused before signing in, nothing read.
    r = _start(t, creds)
    assert r.status_code == 400 and "in scope" in r.json()["detail"] and not built and not c.requests
    r = _start(t, dict(creds, scopes=[], channels={}, from_page=True, profile_id="p1"))
    assert r.status_code == 400 and not built, "the page's ticks (none) are never widened by the profile"
    # The profile's saved selection when the page sent none.
    r = _start(t, dict(creds, profile_id="p1"))
    assert r.status_code == 200, r.text
    assert set(c.gets()) == set(ZCC_EPS) and r.json()["scope"]["read"] == ["zcc", "pac"]
    assert any("from the saved profile Acme" in l for l in r.json()["logs"])
    # The page's selection wins over the profile's, never mixed.
    c.requests.clear()
    r = _start(t, dict(creds, profile_id="p1", scopes=["dlp"], channels={"web_dlp": "zscaler", "ssl_inspection": "zscaler"}))
    assert r.status_code == 200 and not any(x in c.requests for x in ZCC_EPS), c.requests
    rid = r.json()["report_id"]
    # Reused for the same scope, read again for another.
    c.requests.clear()
    same = _start(t, dict(creds, scopes=["dlp"], channels={"web_dlp": "zscaler", "ssl_inspection": "zscaler"}, report_id=rid)).json()
    assert not same["fresh_read"] and not c.gets()
    other = _start(t, dict(creds, scopes=["dlp", "zcc"], channels={"web_dlp": "zscaler", "ssl_inspection": "zscaler"}, report_id=rid)).json()
    assert other["fresh_read"] and other["report_id"] != rid and "/zcc/webPolicies" in c.gets()


def test_the_page_sends_the_scope_page_selection():
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    html = open(os.path.join(root, "static", "report_path.html"), encoding="utf-8").read()
    assert "credBody(), scopeSelection()," in html
    assert "op.getSelectedScopes()" in html and "op.__dbChannelScope()" in html and "from_page: true" in html
    assert "<h2 class=\"df-h\">Not in scope</h2>" in html
    js = open(os.path.join(root, "static", "data_flow.js"), encoding="utf-8").read()
    assert "out_of_scope: ['Not in scope'" in js


@pytest.mark.skipif(shutil.which("node") is None, reason="node not available")
def test_the_motion_says_not_in_scope_never_a_break_or_an_unread_mark():
    import os
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    r = pa.analyze(Tenant(), "chat.openai.com", "off", "windows",
                   scope=_scope(["dlp", "zcc"], {"web_dlp": "gap", "endpoint_dlp": "gap", "email_dlp": "alternative"}))
    r.pop("snapshot_for_cache", None)
    res = json.loads(json.dumps(r, default=str))
    script = (
        "const vm=require('vm'),fs=require('fs');const ctx={window:{}};vm.createContext(ctx);"
        f"vm.runInContext(fs.readFileSync({json.dumps(os.path.join(root, 'static', 'path_motion.js'))},'utf8'),ctx);"
        "const R=JSON.parse(fs.readFileSync(0,'utf8'));const m=ctx.pmModel(R);"
        "process.stdout.write(JSON.stringify({stops:m.stops,summary:m.summary,mark:ctx.PM_MARK||null}));")
    p = subprocess.run(["node", "-e", script], input=json.dumps(res), capture_output=True, text=True, encoding="utf-8")
    assert p.returncode == 0, p.stderr
    m = json.loads(p.stdout)
    assert m["stops"] == [], "configuration context has no observed animated stops"
    lines = [line for line in m["summary"] if "not in scope" in line.lower()]
    assert lines
    assert not any("no enabled" in line.lower() or "could not be read" in line.lower() for line in lines)
