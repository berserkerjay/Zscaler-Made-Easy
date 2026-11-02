"""Stop on a page really stops (rule 4): the Live DLP feed makes no tenant
read after Stop, even when Stop is pressed while a poll is answering, and
Stop then Start never leaves two polling chains; a Stop pressed before a
job's id arrives (deployment, removal, export, path read) is not lost: the
job is cancelled the moment its id is known and is not followed."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = pytest.mark.skipif(shutil.which("node") is None, reason="node not available")


def _read(rel):
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def _node(tmp_path, harness):
    f = tmp_path / "h.js"
    f.write_text(harness, encoding="utf-8")
    p = subprocess.run(["node", str(f)], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


# ── Live DLP feed ────────────────────────────────────────────────────────

LIVE_HARNESS = r"""
const vm = require('vm');
const SRC = __SRC__;
const els = {};
const mk = id => ({id, value: '', hidden: false, textContent: '', innerHTML: '', _h: {},
  addEventListener(t, f) { (this._h[t] = this._h[t] || []).push(f); },
  click() { return Promise.all((this._h.click || []).map(f => f())); },
  querySelectorAll() { return []; }, querySelector() { return null; }, setAttribute() {}, appendChild() {},
  classList: {toggle() {}, add() {}, remove() {}}});
// A manual clock: timers fire only when the test advances it.
let now = 0, nextId = 1; const timers = new Map();
const clock = {
  setTimeout(f, ms) { const id = nextId++; timers.set(id, {at: now + ms, f}); return id; },
  clearTimeout(id) { timers.delete(id); },
};
async function advance(ms) {
  const end = now + ms;
  for (;;) {
    let best = null;
    for (const [id, t] of timers) if (t.at <= end && (!best || t.at < best[1].at)) best = [id, t];
    if (!best) break;
    timers.delete(best[0]); now = best[1].at; best[1].f();
    await flush();
  }
  now = end;
}
const flush = () => new Promise(r => setImmediate(r));
const reads = []; const pending = [];
const answer = () => ({ok: true, status: 200, json: async () => ({incidents: [], next_since: 'x', stats: {}, errors: [], read_at: '2026-10-02T00:00:00Z'})});
let hold = false;
const ctx = {
  document: {getElementById: id => els[id] || (els[id] = mk(id)), createElement: () => mk('x'), querySelector: () => null, querySelectorAll: () => []},
  localStorage: {getItem: () => null, setItem() {}}, location: {search: ''}, console, URLSearchParams,
  setTimeout: clock.setTimeout, clearTimeout: clock.clearTimeout, setInterval() { return 0; }, clearInterval() {},
  fetch(u) {
    if (u === '/api/live-feed') {
      reads.push(now);
      if (hold) return new Promise(r => pending.push(() => r(answer())));
      return Promise.resolve(answer());
    }
    return Promise.resolve({ok: true, status: 200, json: async () => ({profiles: []})});
  },
};
ctx.window = ctx; ctx.window.opener = null;
vm.createContext(ctx);
vm.runInContext(SRC, ctx);
const POLL = 15000;
const out = {};
(async () => {
  await flush();
  // 1. Stop while the first poll is answering: no read afterwards.
  hold = true; els.lfStart.click(); await flush();
  els.lfStop.click(); const atStop = reads.length;
  hold = false; pending.splice(0).forEach(f => f()); await flush(); await flush();
  await advance(POLL * 4);
  out.afterStop = reads.length - atStop; out.timersAfterStop = timers.size;
  // 2. Stop then Start while the first poll is answering: one chain only.
  reads.length = 0;
  hold = true; els.lfStart.click(); await flush();
  els.lfStop.click(); els.lfStart.click(); await flush();
  hold = false; pending.splice(0).forEach(f => f()); await flush(); await flush();
  const base = reads.length;
  await advance(POLL * 3);
  out.chainReads = reads.length - base; out.timersRunning = timers.size;
  // 3. Stop then Start while a timer-driven poll is answering: one chain only.
  hold = true; await advance(POLL); const inFlight = reads.length;
  els.lfStop.click(); els.lfStart.click(); await flush();
  hold = false; pending.splice(0).forEach(f => f()); await flush(); await flush();
  const base3 = reads.length;
  await advance(POLL * 3);
  out.chainReads3 = reads.length - base3; out.timers3 = timers.size; out.inFlight = inFlight;
  els.lfStop.click(); await flush();
  const end = reads.length; await advance(POLL * 3);
  out.afterFinalStop = reads.length - end;
  process.stdout.write(JSON.stringify(out));
})();
"""


def _live_script():
    html = _read("static/report_live.html")
    scripts = re.findall(r"<script>([\s\S]*?)</script>", html)
    return scripts[-1]


@NODE
def test_live_feed_stop_during_a_poll_reads_nothing_more_and_restart_keeps_one_chain(tmp_path):
    out = _node(tmp_path, LIVE_HARNESS.replace("__SRC__", json.dumps(_live_script())))
    assert out["afterStop"] == 0 and out["timersAfterStop"] == 0, out
    assert out["chainReads"] == 3 and out["timersRunning"] == 1, out
    assert out["chainReads3"] == 3 and out["timers3"] == 1, out
    assert out["afterFinalStop"] == 0, out


# ── A Stop pressed before the job id arrives (server) ────────────────────

CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}


class RecordingClient:
    """A fake tenant client: every call made through it, at any depth, is recorded."""

    def __init__(self, calls=None, path=""):
        self._calls = calls if calls is not None else []
        self._path = path

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return RecordingClient(self._calls, f"{self._path}.{name}")

    def __call__(self, *a, **k):
        self._calls.append(self._path)
        return [], None, None


def _wait(t, job):
    import time
    deadline = time.time() + 20
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("the job never ended")


def _client(monkeypatch, token):
    """The test client, with the tenant sign-in replaced by a fake that
    (like a page's early Stop) asks to stop this start while it signs in."""
    import dlp_api_server as srv
    import pack_jobs
    import security
    from fastapi.testclient import TestClient
    calls = []

    def sign_in(*a, **k):
        if token:
            pack_jobs.stop_before_start(token)   # Stop arrives while the start request is signing in
        return RecordingClient(calls)
    monkeypatch.setattr(srv, "_build_sdk_client", sign_in)
    monkeypatch.setattr(srv, "_build_client", sign_in)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(srv._security, "require_writer", lambda *a, **k: None)
    t = TestClient(srv.app)
    t.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return t, calls


START_CASES = {
    "deploy": ("/api/dlp-packs/apply/start", dict(CREDS, pack_ids=["zbp_enterprise_baseline"], plan_hash="h", confirm=True, assessor="Pat")),
    "removal": ("/api/dlp-packs/removal/apply/start", dict(CREDS, pack_ids=["zbp_enterprise_baseline"], plan_hash="h", confirm=True, assessor="Jane Doe",
                                                           confirm_phrase="DELETE 1 OBJECTS")),
    "export": ("/api/dlp-packs/export/start", dict(CREDS, rules={"web": "all"}, scopes=["dlp"], channels={"web_dlp": "zscaler"}, from_page=True)),
    "path": ("/api/path-analyzer/start", dict(CREDS, destination="chat.openai.com", scopes=["dlp"], channels={"web_dlp": "zscaler"})),
    "terraform": ("/api/dlp-packs/terraform/start", dict(CREDS, pack_ids=["zbp_enterprise_baseline"], mode="gap", assessor="Pat")),
}


@pytest.mark.parametrize("kind", sorted(START_CASES))
def test_a_stop_sent_while_the_start_signs_in_starts_the_job_stopped_with_no_tenant_call(monkeypatch, kind):
    url, body = START_CASES[kind]
    token = "tok" + kind + "0123456789"
    t, calls = _client(monkeypatch, token)
    r = t.post(url, json=body, headers={"X-Start-Token": token})
    assert r.status_code == 200, r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["cancel_requested"] is True, snap
    assert calls == [], f"{kind}: the tenant was called after Stop: {calls}"
    assert (snap.get("result") or {}).get("status") == "stopped" or snap["status"] == "cancelled", snap
    assert any("before the run started" in line for line in snap["logs"]), snap["logs"]


def test_without_an_early_stop_the_same_start_runs():
    import time
    import pack_jobs
    ran = []
    job = pack_jobs.start("path", lambda log, cancel: ran.append(cancel.is_set()) or {"status": "done"}, start_token="tok-norun-0123")
    deadline = time.time() + 5
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.01)
    assert ran == [False] and job.status == pack_jobs.DONE


def test_a_stop_sent_for_a_start_whose_job_already_exists_cancels_that_job():
    import time
    import pack_jobs

    def fn(log, cancel):
        cancel.wait(5)
        return {"status": "stopped", "stopped": "You clicked Stop."}
    job = pack_jobs.start("path", fn, start_token="tok-late-0123456")
    out = pack_jobs.stop_before_start("tok-late-0123456")
    assert out["job_id"] == job.id and out["cancelled"] is True and job.cancel.is_set()
    deadline = time.time() + 5
    while job.status == pack_jobs.RUNNING and time.time() < deadline:
        time.sleep(0.01)
    assert job.status == pack_jobs.CANCELLED


def test_the_stop_before_start_endpoint_refuses_a_malformed_token(monkeypatch):
    t, _calls = _client(monkeypatch, None)
    assert t.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": "x"}).status_code == 400
    r = t.post("/api/dlp-packs/jobs/stop-before-start", json={"start_token": "tok-endpoint-0123"})
    assert r.status_code == 200 and r.json()["pending"] is True


# ── A Stop pressed before the job id arrives (pages) ─────────────────────

DZ_HARNESS = r"""
const vm = require('vm');
const SRC = __SRC__;
const requests = []; let release;
const ctx = {
  console, setTimeout, clearTimeout, setInterval, clearInterval, URL, encodeURIComponent,
  announce() {}, addEventListener() {}, dispatchEvent() {}, crypto: {randomUUID: () => '11111111-2222-3333-4444-555555555555'},
  document: {getElementById: () => null, addEventListener() {}, querySelector: () => null, querySelectorAll: () => []},
  localStorage: {getItem: () => null, setItem() {}},
  fetch(url, opts) {
    requests.push([url, (opts && opts.headers) || {}, opts && opts.body ? JSON.parse(opts.body) : null]);
    if (/\/start$/.test(url)) return new Promise(r => { release = () => r({ok: true, json: async () => ({job_id: 'J1'})}); });
    if (/\/jobs\/J1\?/.test(url)) return Promise.resolve({ok: true, json: async () => ({status: 'cancelled', logs: [], next: 0, result: {status: 'stopped'}})});
    return Promise.resolve({ok: true, json: async () => ({})});
  },
};
ctx.window = ctx;
vm.createContext(ctx);
vm.runInContext(SRC + ';this.__DZ = DZ;', ctx);
(async () => {
  ctx.__DZ.job = null;
  const run = vm.runInContext("_dzRunJob('/api/dlp-packs/apply/start', {})", ctx);
  await new Promise(r => setImmediate(r));
  const stopAsked = vm.runInContext('_dzStopAsked()', ctx);
  await vm.runInContext('_dzCancelJob()', ctx);
  const afterClick = vm.runInContext('_dzStopAsked()', ctx);
  release();
  const snap = await run;
  process.stdout.write(JSON.stringify({requests, stopAsked, afterClick, cancelRequested: ctx.__DZ.job.cancelRequested, status: snap.status}));
})();
"""


@NODE
def test_deploy_studio_stop_before_the_job_id_reaches_the_job(tmp_path):
    out = _node(tmp_path, DZ_HARNESS.replace("__SRC__", json.dumps(_read("static/deploy_studio.js"))))
    urls = [u for u, _h, _b in out["requests"]]
    start = out["requests"][0]
    assert start[0] == "/api/dlp-packs/apply/start" and start[1].get("X-Start-Token") == "11111111222233334444555555555555"
    assert out["stopAsked"] is False and out["afterClick"] is True and out["cancelRequested"] is True
    early = [b for u, _h, b in out["requests"] if u == "/api/dlp-packs/jobs/stop-before-start"]
    assert early == [{"start_token": "11111111222233334444555555555555"}], out["requests"]
    assert "/api/dlp-packs/jobs/J1/cancel" in urls, urls
    assert urls.index("/api/dlp-packs/jobs/stop-before-start") < urls.index("/api/dlp-packs/jobs/J1/cancel")


def test_the_path_page_sends_an_early_stop_with_its_start_token():
    html = _read("static/report_path.html")
    stop = html[html.index("async function stop()"):html.index("async function run()")]
    assert "if (!job) return;" not in stop
    assert "/api/dlp-packs/jobs/stop-before-start" in stop and "start_token: startToken" in stop
    run = html[html.index("async function run()"):html.index("function fail(")]
    assert "'X-Start-Token': startToken" in run and "if (stopAsked)" in run
