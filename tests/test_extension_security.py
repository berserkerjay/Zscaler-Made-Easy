"""T8: the companion browser extension and the app's narrow trust in it.

The app trusts one origin, chrome-extension://<the fixed id>, and only for
POSTs to the read-only allow-list (security.EXTENSION_POST_PATHS, plus
stopping the export it started). Every other origin, extension id, method,
path variant and endpoint is refused. On the extension side, each message is
accepted only from the sender it is meant for, page text never reaches an
object prototype, badges live in a closed shadow root, and browser storage
holds no secret.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading

import pytest
from starlette.routing import Route

import pack_jobs
import security

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EXT_DIR = os.path.join(ROOT, "browser_extension")
NODE = shutil.which("node")
EXT = security.extension_origin()
EXT_ID = EXT.split("//", 1)[1]
WEB_UI = "http://127.0.0.1:8000"
node_only = pytest.mark.skipif(NODE is None, reason="node is not installed")


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.delenv("DLP_CHECK_EXTENSION_ID", raising=False)
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    return TestClient(srv.app)


def _app():
    import dlp_api_server as srv
    return srv.app


def _concrete(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "x1", path)


def _extension_allowed(path: str) -> bool:
    return path in security.EXTENSION_POST_PATHS or bool(security._EXTENSION_CANCEL.fullmatch(path))


def _state_changing_routes():
    out = []
    for r in _app().routes:
        if isinstance(r, Route):
            for m in sorted((r.methods or set()) - {"GET", "HEAD", "OPTIONS"}):
                out.append((m, _concrete(r.path)))
    return out


STATE_CHANGING = _state_changing_routes()
GET_PATHS = {_concrete(r.path) for r in _app().routes if isinstance(r, Route) and "GET" in (r.methods or set())}


def _refused(r) -> bool:
    return r.status_code == 403 and "not allowed" in r.text


# ── App side: origins ────────────────────────────────────────────────

@pytest.mark.parametrize("method,path", [mp for mp in STATE_CHANGING if not _extension_allowed(mp[1])],
                         ids=lambda v: str(v))
def test_the_extension_origin_is_refused_on_every_other_state_changing_route(client, method, path):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the extension gets no write or other endpoint, route by route."""
    # Arrange: the real extension origin, on a route outside its allow-list.
    headers = {"Origin": EXT}
    # Act
    r = client.request(method, path, json={}, headers=headers)
    # Assert: refused by the origin check, before any handler ran.
    assert _refused(r), (method, path, r.status_code, r.text[:120])


def test_the_allow_list_is_only_read_only_endpoints():
    """ASVS V4.1.3 · CWE-269 · WSTG-ATHZ-02: the extension's allow-list names no write endpoint."""
    # Arrange
    allowed = [p for _, p in STATE_CHANGING if _extension_allowed(p)]
    # Act / Assert: exactly the console index, Export from tenant and Stop.
    assert sorted(set(allowed)) == sorted(list(security.EXTENSION_POST_PATHS) + ["/api/dlp-packs/jobs/x1/cancel"])
    assert not any(re.search(r"apply|deploy|remov|write|import|undo|delete|upload|enable|approve", p) for p in allowed)


BAD_ORIGINS = [
    "https://evil.example", "null", "http://localhost:9999", "http://127.0.0.1.evil.example", "file://",
    "chrome-extension://" + "a" * 32,                      # another extension
    "chrome-extension://" + EXT_ID[:-1],                    # one character short
    "chrome-extension://" + EXT_ID + "a",                   # one character long
    EXT + ".evil.example", EXT + "@evil.example", EXT + ":443", EXT + "/panel.html",
    "moz-extension://" + EXT_ID, "safari-web-extension://" + EXT_ID, "chrome-extensions://" + EXT_ID,
    EXT + ", " + WEB_UI, " " + EXT,
]


@pytest.mark.parametrize("origin", BAD_ORIGINS)
def test_only_the_fixed_extension_id_is_trusted(client, origin):
    """ASVS V4.2.2 · CWE-346 · WSTG-SESS-05: any other origin, the null origin or another extension id is refused."""
    # Arrange / Act
    r = client.post("/api/console-index", json={}, headers={"Origin": origin})
    # Assert
    assert _refused(r), (origin, r.status_code)


@pytest.mark.parametrize("referer", ["chrome-extension://" + "a" * 32 + "/panel.html", "https://evil.example/x", "moz-extension://" + EXT_ID + "/p"])
def test_a_foreign_referer_without_origin_is_refused(client, referer):
    """ASVS V4.2.2 · CWE-346 · WSTG-SESS-05: with no Origin header the Referer decides, and a foreign one is refused."""
    r = client.post("/api/console-index", json={}, headers={"Referer": referer})
    assert r.status_code == 403 and "Referer not allowed" in r.text


@pytest.mark.parametrize("headers", [{"Origin": EXT}, {"Origin": EXT.upper()}, {"Origin": EXT + "/"},
                                     {"Referer": EXT + "/panel.html"}, {}])
def test_the_extension_and_non_browser_callers_reach_the_allow_listed_endpoint(client, headers):
    """ASVS V4.2.2 · CWE-346 · WSTG-SESS-05: the real extension (or a caller with no Origin, behind the UI token) is let through."""
    # Act: an empty body: the handler answers 400 (nothing to read), proving the origin check passed.
    r = client.post("/api/console-index", json={}, headers=headers)
    # Assert
    assert r.status_code != 403 and r.status_code < 500, (headers, r.status_code, r.text[:120])


def test_switching_the_trust_off_refuses_the_extension(client, monkeypatch):
    """ASVS V4.1.5 · CWE-863 · WSTG-ATHZ-02: DLP_CHECK_EXTENSION_ID=off denies the extension everywhere (fail closed)."""
    monkeypatch.setenv("DLP_CHECK_EXTENSION_ID", "off")
    assert _refused(client.post("/api/console-index", json={}, headers={"Origin": EXT}))
    monkeypatch.setenv("DLP_CHECK_EXTENSION_ID", "not-a-valid-id")
    assert _refused(client.post("/api/console-index", json={}, headers={"Origin": EXT}))


# ── App side: methods ────────────────────────────────────────────────

@pytest.mark.parametrize("header", ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"])
def test_method_override_headers_cannot_turn_a_refused_post_into_a_get(client, header):
    """ASVS V14.5.1 · CWE-650 · WSTG-CONF-06: an override header never bypasses the origin check."""
    # Arrange
    body = {"enable": True, "confirm": security.WRITE_CONFIRM_PHRASE}
    # Act
    r = client.post("/api/write-mode", json=body, headers={"Origin": EXT, header: "GET"})
    # Assert
    assert _refused(r) and not security.writes_enabled()


@pytest.mark.parametrize("header", ["X-HTTP-Method-Override", "X-HTTP-Method", "X-Method-Override"])
def test_method_override_headers_cannot_turn_a_get_into_a_write(client, header):
    """ASVS V14.5.1 · CWE-650 · WSTG-CONF-06: a GET with an override header stays a read."""
    before = client.get("/api/write-mode").json()
    r = client.request("GET", "/api/write-mode", content=json.dumps({"enable": True, "confirm": security.WRITE_CONFIRM_PHRASE}),
                       headers={"Origin": EXT, header: "POST", "Content-Type": "application/json"})
    assert r.status_code == 200 and r.json() == before and not security.writes_enabled()


@pytest.mark.parametrize("method,path", STATE_CHANGING, ids=lambda v: str(v))
def test_head_never_runs_a_state_changing_handler(client, method, path):
    """ASVS V14.5.1 · CWE-650 · WSTG-CONF-06: HEAD (exempt from the origin check) reaches only a GET handler, if any."""
    r = client.head(path, headers={"Origin": "https://evil.example"})
    assert r.status_code == 405 or (path in GET_PATHS and r.status_code != 405), (path, r.status_code)


@pytest.mark.parametrize("origin", [EXT, "https://evil.example", "null"])
@pytest.mark.parametrize("path", ["/api/console-index", "/api/write-mode", "/api/dlp-packs/apply"])
def test_options_and_preflight_never_run_a_handler_or_grant_cors(client, origin, path):
    """ASVS V14.5.3 · CWE-942 · WSTG-CLNT-07: OPTIONS gets no handler, and no CORS grant beyond the app's own origins."""
    plain = client.options(path, headers={"Origin": origin})
    pre = client.options(path, headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
    assert plain.status_code == 405
    assert pre.status_code == 400 and "access-control-allow-origin" not in {k.lower() for k in pre.headers}


@pytest.mark.parametrize("method", ["PUT", "DELETE", "PATCH"])
@pytest.mark.parametrize("path", list(security.EXTENSION_POST_PATHS) + ["/api/dlp-packs/jobs/x1/cancel"])
def test_other_methods_on_the_allow_list_have_no_handler(client, method, path):
    """ASVS V14.5.1 · CWE-650 · WSTG-CONF-06: the allow-list is a POST allow-list; no other verb runs anything there."""
    r = client.request(method, path, json={}, headers={"Origin": EXT})
    assert r.status_code == 405, (method, path, r.status_code)


# ── App side: path tricks ────────────────────────────────────────────

PATH_TRICKS = [
    "/api/console-index/", "/api/console-index//", "//api/console-index", "/API/console-index", "/api/Console-Index",
    "/api/console-index%2F", "/api/console-index;x", "/api/console-index%00", "/api/console-index%0A", "/api/console-index%0D",
    "/api/console-index%09", "/api/console%09-index", "/api/dlp-packs/export/start/", "/api/dlp-packs/export/start%0A",
    "/api/dlp-packs/jobs/x1/cancel/", "/api/dlp-packs/jobs/x1/cancel%0A",
    "/api/dlp-packs/jobs/stop-before-start", "/api/dlp-packs/jobs/x1/cancel%2F..%2F..%2Fapply",
]


@pytest.mark.parametrize("path", PATH_TRICKS)
def test_path_variants_of_the_allow_list_are_refused(client, path):
    """ASVS V4.1.3 · CWE-436 · WSTG-ATHZ-01: a trailing slash, case, encoded or whitespace variant is not an allow-listed path."""
    # Act
    r = client.post(path, json={}, headers={"Origin": EXT})
    # Assert: refused by the origin check (never 2xx, never the handler's 400/404).
    assert _refused(r), (path, r.status_code, r.text[:120])


@pytest.mark.parametrize("path", ["/api/dlp-packs/jobs/abc/cancel\n", "/api/console-index\n", "/api/dlp-packs/jobs/abc/cancel\t",
                                  "/api/dlp-packs/jobs/" + "a" * 65 + "/cancel", "/api/dlp-packs/jobs//cancel"])
def test_the_allow_list_match_is_exact(path):
    """ASVS V4.1.3 · CWE-185 · WSTG-ATHZ-02: the allow-list regex is anchored at both ends (no trailing-newline match)."""
    assert not security.extension_may_post(EXT, path)


@pytest.mark.parametrize("path", ["/api/dlp-packs/jobs/abc/cancel", "/api/dlp-packs/jobs/" + "a" * 64 + "/cancel", "/api/console-index"])
def test_the_allow_list_still_matches_its_own_paths(path):
    """ASVS V4.1.3 · CWE-185 · WSTG-ATHZ-02: boundary: the exact paths (a 64-character job id) stay allowed."""
    assert security.extension_may_post(EXT, path)


@pytest.mark.parametrize("path,allowed", [("/api/console-index?x=/api/write-mode", True), ("/api/write-mode?p=/api/console-index", False),
                                          ("/api/dlp-packs/apply?next=/api/dlp-packs/export/start", False)])
def test_a_query_string_never_changes_the_decision(client, path, allowed):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: only the path decides; a query string naming an allowed path does not."""
    r = client.post(path, json={}, headers={"Origin": EXT})
    assert _refused(r) is (not allowed), (path, r.status_code)


# ── App side: Stop only on the extension's own export ────────────────

def _blocked_job(kind: str, started_by=None):
    gate = threading.Event()
    job = pack_jobs.start(kind, lambda log, cancel: gate.wait(2) or {"status": "ready"}, label="t8")
    job.started_by = started_by
    return job, gate


def _finish(job, gate):
    gate.set()
    if job.thread is not None:
        job.thread.join(2)


@pytest.mark.parametrize("kind,started_by", [("deploy", None), ("removal", None), ("ops_apply", None), ("export", None),
                                             ("deploy", "extension"), ("path", None)])
def test_the_extension_may_not_stop_a_job_it_did_not_start(client, kind, started_by):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: Stop from the extension reaches only the read-only export it started."""
    # Arrange: a running job the extension may not stop (a write, or someone else's export).
    job, gate = _blocked_job(kind, started_by)
    try:
        # Act
        r = client.post(f"/api/dlp-packs/jobs/{job.id}/cancel", headers={"Origin": EXT})
        by_referer = client.post(f"/api/dlp-packs/jobs/{job.id}/cancel", headers={"Referer": EXT + "/panel.html"})
        # Assert: refused, and the job keeps running.
        assert r.status_code == 403 and by_referer.status_code == 403, (r.status_code, r.text)
        assert not job.cancel.is_set() and job.status == pack_jobs.RUNNING
    finally:
        _finish(job, gate)


@pytest.mark.parametrize("headers", [{"Origin": WEB_UI}, {}])
def test_the_app_itself_still_stops_any_job(client, headers):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the narrowing applies to the extension only; the app's Stop is unchanged."""
    job, gate = _blocked_job("deploy")
    try:
        r = client.post(f"/api/dlp-packs/jobs/{job.id}/cancel", headers=headers)
        assert r.status_code == 200 and r.json()["cancelled"] is True and job.cancel.is_set()
    finally:
        _finish(job, gate)


def test_the_extension_stops_the_export_it_started(client):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: happy path: the extension's own export can be stopped."""
    job, gate = _blocked_job("export", "extension")
    try:
        r = client.post(f"/api/dlp-packs/jobs/{job.id}/cancel", headers={"Origin": EXT})
        assert r.status_code == 200 and r.json()["cancelled"] is True
    finally:
        _finish(job, gate)


def test_an_export_started_from_the_extension_is_marked_as_its_own(client, monkeypatch):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: Export from tenant records who started it, so Stop can be narrowed."""
    import dlp_api_server as srv
    from test_pack_export import ALL_DLP_IN_SCOPE, ReadOnly, _source
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: ReadOnly(_source()))
    body = dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s" * 20}, parts=["engines"], **ALL_DLP_IN_SCOPE)
    ext = client.post("/api/dlp-packs/export/start", json=body, headers={"Origin": EXT})
    app = client.post("/api/dlp-packs/export/start", json=body, headers={"Origin": WEB_UI})
    assert ext.status_code == 200 and app.status_code == 200, (ext.text, app.text)
    jobs = [pack_jobs.get(ext.json()["job_id"]), pack_jobs.get(app.json()["job_id"])]
    for j in jobs:
        j.thread.join(5)
    assert [j.started_by for j in jobs] == ["extension", None]


# ── Extension side (node) ────────────────────────────────────────────

_BG_HARNESS = r"""
import { pathToFileURL } from 'node:url';
const ID = 'febekapiipbdccnkbelfpajhillaplbe';
const fixture = JSON.parse(process.argv[2]);
let listener = null; const sent = []; const stored = []; const opened = [];
const ev = () => ({ addListener() {} });
globalThis.chrome = {
  runtime: { id: ID, getURL: p => `chrome-extension://${ID}/${p}`, onInstalled: ev(), onStartup: ev(),
             onMessage: { addListener(fn) { listener = fn; } } },
  contextMenus: { onClicked: ev() }, permissions: { onAdded: ev(), onRemoved: ev() },
  storage: { session: { get: async () => ({ index: fixture.index }), set: v => { stored.push(v); return Promise.resolve(); } } },
  tabs: { query: async () => [{ id: 7 }], sendMessage: (id, m) => { sent.push(m.type); return Promise.resolve(); } },
  sidePanel: { open: o => { opened.push(o.tabId); return Promise.resolve(); } },
};
await import(pathToFileURL(process.argv[1]).href);
const out = [];
for (const c of fixture.cases) {
  const replies = [];
  const ret = listener(c.msg, c.sender, r => replies.push(r));
  await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r));
  out.push({ async: ret === true, replies, sent: sent.splice(0), stored: stored.splice(0).length, opened: opened.splice(0).length });
}
console.log(JSON.stringify(out));
"""

CONSOLE = {"id": EXT_ID, "tab": {"id": 3}, "url": "https://admin.zscalertwo.net/#policy/dlp"}
PANEL = {"id": EXT_ID, "url": f"chrome-extension://{EXT_ID}/panel.html"}
INDEX = {"objects": [{"kind": "engine", "name": n, "key": f"engine:{n}", "counts": {"rules": 1}}
                     for n in ("constructor", "__proto__", "toString", "Board Leak")]}


def _background(cases, index=INDEX):
    r = subprocess.run([NODE, "--input-type=module", "-e", _BG_HARNESS, os.path.join(EXT_DIR, "background.js"),
                        json.dumps({"cases": cases, "index": index})], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


SENDER_CASES = [
    # (message, sender, accepted)
    ({"type": "names"}, CONSOLE, True),
    ({"type": "names"}, dict(CONSOLE, url="https://evil.example/"), False),
    ({"type": "names"}, dict(CONSOLE, url="https://admin.zscaler.net.evil.example/"), False),
    ({"type": "names"}, dict(CONSOLE, id="a" * 32), False),
    ({"type": "names"}, PANEL, False),
    ({"type": "focus", "key": "engine:Board Leak"}, CONSOLE, True),
    ({"type": "focus", "key": "engine:Board Leak"}, dict(CONSOLE, url="http://admin.zscaler.net/"), False),
    ({"type": "focus", "key": "engine:Board Leak"}, PANEL, False),
    ({"type": "index-updated"}, PANEL, True),
    ({"type": "index-updated"}, CONSOLE, False),
    ({"type": "index-updated"}, dict(PANEL, id="a" * 32), False),
    ({"type": "index-updated"}, dict(PANEL, url="https://evil.example/panel.html"), False),
]


@node_only
@pytest.mark.parametrize("msg,sender,accepted", SENDER_CASES, ids=[f"{m['type']}-{i}" for i, (m, _, _) in enumerate(SENDER_CASES)])
def test_the_background_accepts_each_message_only_from_its_sender(msg, sender, accepted):
    """ASVS V5.1.3 · CWE-346 · WSTG-CLNT-11: names and focus only from a console tab, index-updated only from the panel."""
    # Act
    [out] = _background([{"msg": msg, "sender": sender}])
    # Assert: an accepted message has its effect; a refused one has none.
    effect = bool(out["replies"]) or bool(out["sent"]) or bool(out["stored"]) or bool(out["opened"])
    assert effect is accepted, out


@node_only
def test_object_names_never_reach_the_prototype_in_the_background():
    """ASVS V5.1.3 · CWE-1321 · WSTG-CLNT-11: objects named "constructor" or "__proto__" are names like any other."""
    # Act
    [out] = _background([{"msg": {"type": "names"}, "sender": CONSOLE}])
    # Assert: one reply, each name an own entry with its badge.
    assert len(out["replies"]) == 1
    names = out["replies"][0]["names"]
    assert sorted(names) == ["Board Leak", "__proto__", "constructor", "toString"]
    assert all(isinstance(v, list) and v[0]["key"] == f"engine:{k}" for k, v in names.items())


_CONSOLE_HARNESS = r"""
const vm = require('node:vm'); const fs = require('node:fs');
const [file, namesJson, textsJson, msgsJson] = process.argv.slice(1);
const names = JSON.parse(namesJson), texts = JSON.parse(textsJson), msgs = JSON.parse(msgsJson);
const ID = 'febekapiipbdccnkbelfpajhillaplbe';
const badges = []; const modes = []; let timer = null; let onMsg = null; let asked = 0;
function el(tag) {
  return { tagName: tag, style: {}, attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, hasAttribute(k) { return k in this.attrs; },
           addEventListener() {}, append() {}, attachShadow(o) { modes.push(o.mode); return { append() {} }; } };
}
const nodes = texts.map(t => { const p = el('SPAN'); Object.assign(p, { textContent: t, isConnected: true, nextElementSibling: null,
  closest: () => null, querySelector: () => null, after: h => badges.push(t) }); return { nodeValue: t, parentElement: p }; });
const ctx = {
  NodeFilter: { SHOW_TEXT: 4, FILTER_ACCEPT: 1, FILTER_REJECT: 2 },
  MutationObserver: class { observe() {} },
  setTimeout: fn => { timer = fn; return 1; },
  document: { body: {}, documentElement: {}, querySelectorAll: () => [], createElement: el,
              createTreeWalker: (root, what, f) => { let i = 0; return { nextNode() { while (i < nodes.length) { const n = nodes[i++]; if (f.acceptNode(n) === 1) return n; } return null; } }; } },
  chrome: { runtime: { id: ID, sendMessage: async m => { asked++; return { names: JSON.parse(JSON.stringify(names)) }; },
                       onMessage: { addListener(fn) { onMsg = fn; } } } },
};
ctx.window = ctx; ctx.window.matchMedia = () => ({ matches: false });
vm.createContext(ctx);
vm.runInContext(fs.readFileSync(file, 'utf8'), ctx);
(async () => {
  await new Promise(r => setImmediate(r));
  let error = null;
  try { timer && timer(); } catch (e) { error = String(e); }
  const replies = msgs.map(([m, s]) => { const got = []; onMsg(m, s, r => got.push(r)); return got.length; });
  await new Promise(r => setImmediate(r));
  console.log(JSON.stringify({ badges, modes, error, replies, asked }));
})();
"""


def _console(names, texts, msgs=()):
    r = subprocess.run([NODE, "-e", _CONSOLE_HARNESS, os.path.join(EXT_DIR, "console.js"), json.dumps(names), json.dumps(texts),
                        json.dumps(list(msgs))], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


BADGE = [{"key": "engine:Board Leak", "kind": "DLP engine", "label": "used in 1 rule", "sev": "info"}]


@node_only
@pytest.mark.parametrize("hostile", ["constructor", "__proto__", "toString", "hasOwnProperty", "valueOf", "__defineGetter__"])
def test_page_text_never_reaches_the_prototype_in_the_badge_script(hostile):
    """ASVS V5.1.3 · CWE-1321 · WSTG-CLNT-11: console text such as "constructor" is not a name and does not stop the badges."""
    # Arrange: the hostile text comes first on the page, a real name after it.
    texts = [hostile, "Board Leak", "x"]
    # Act
    out = _console({"Board Leak": BADGE}, texts)
    # Assert: no error, only the real name badged, in a closed shadow root.
    assert out["error"] is None and out["badges"] == ["Board Leak"] and out["modes"] == ["closed"], out


@node_only
def test_the_badge_script_ignores_a_malformed_names_answer():
    """ASVS V5.1.3 · CWE-20 · WSTG-CLNT-11: boundary: a non-array entry or an empty list is never badged."""
    out = _console({"Board Leak": BADGE, "Bad": "not a list", "Empty": [], "Obj": {"0": BADGE[0]}}, ["Bad", "Empty", "Obj", "Board Leak"])
    assert out["error"] is None and out["badges"] == ["Board Leak"], out


@node_only
def test_the_badge_script_answers_only_the_extension():
    """ASVS V5.1.3 · CWE-346 · WSTG-CLNT-11: list and refresh come from the extension's own pages, never a tab or another id."""
    own = {"id": EXT_ID, "url": f"chrome-extension://{EXT_ID}/panel.html"}
    msgs = [[{"type": "list"}, own], [{"type": "list"}, dict(own, id="a" * 32)], [{"type": "list"}, dict(own, tab={"id": 1})],
            [{"type": "list"}, None]]
    out = _console({"Board Leak": BADGE}, ["Board Leak"], msgs)
    assert out["replies"] == [1, 0, 0, 0], out


def test_browser_storage_holds_only_the_app_address():
    """ASVS V8.2.2 · CWE-922 · WSTG-CLNT-12: persistent storage keeps the app address only; session data stays out of content scripts."""
    # Arrange
    texts = {n: open(os.path.join(EXT_DIR, n), encoding="utf-8").read() for n in os.listdir(EXT_DIR) if n.endswith(".js")}
    # Act
    persistent = [m for t in texts.values() for m in re.findall(r"chrome\.storage\.(?:sync|local)\.set\(([^)]*)\)", t)]
    # Assert: one write, of the app address; nothing widens session storage to content scripts; no cookie or token is read.
    assert persistent == ["{ app: base }"], persistent
    assert not any("setAccessLevel" in t or "chrome.cookies" in t or "document.cookie" in t or "localStorage" in t for t in texts.values())
    assert "storage.session" not in texts["console.js"] and "storage." not in texts["console.js"]


def test_extension_pages_have_a_csp_and_load_no_remote_code():
    """ASVS V14.4.3 · CWE-829 · WSTG-CONF-12: the extension CSP allows only its own scripts, and nothing is fetched as code."""
    m = json.load(open(os.path.join(EXT_DIR, "manifest.json"), encoding="utf-8"))
    csp = dict(d.strip().split(" ", 1) for d in m["content_security_policy"]["extension_pages"].split(";") if d.strip())
    assert csp["script-src"] == "'self'" and csp["object-src"] == "'none'" and csp["base-uri"] == "'none'"
    for name in os.listdir(EXT_DIR):
        if name.endswith((".js", ".html")):
            text = open(os.path.join(EXT_DIR, name), encoding="utf-8").read()
            assert not re.search(r"importScripts|import\(\s*['\"`]https?:|<script[^>]+src=['\"]https?:|eval\(|new Function", text), name
