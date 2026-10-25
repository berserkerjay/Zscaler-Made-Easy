"""Workspace notes (workspace_notes.py + /api/workspace/notes): tags,
comments and to-dos on any object, kept per tenant in the app's own store.

They are local writes, never tenant writes, but they still need the UI
token, record who wrote them (the server's view of the caller), land in the
audit log (without the text, which may hold customer data), are capped in
size, kept apart per tenant, never turn a request value into a path, and
cannot be written from the browser extension's origin. Also the To-do list
page and its catalogue entry."""
from __future__ import annotations

import json
import os
import re
import stat

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security
import sso
import tenant_profiles
import workspace_notes as wn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
A = "acme (production)"
B = "globex (zscalertwo)"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "notes" / "workspace_notes.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    for k in ("ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET", "ZSCALER_VANITY_DOMAIN", "ZSCALER_CLOUD"):
        monkeypatch.delenv(k, raising=False)
    yield


def _client():
    return TestClient(srv.app)


def _post(c, **body):
    return c.post("/api/workspace/notes", json=body)


def _audit():
    p = os.environ["DLP_CHECK_AUDIT"]
    return [json.loads(x) for x in open(p, encoding="utf-8") if x.strip()] if os.path.exists(p) else []


# ── the store ───────────────────────────────────────────────────────────
def test_tags_todos_and_comments_round_trip_and_the_store_is_owner_only_and_atomic(tmp_path):
    n = wn.apply(A, "rule", "rule:web:Block SSN", "add_tag", by="alice", tag="urgent", label="DLP rule: Block SSN", href="/report/shadow")
    assert n["tags"] == ["urgent"] and n["label"] == "DLP rule: Block SSN" and n["href"] == "/report/shadow" and n["created_by"] == "alice"
    wn.apply(A, "rule", "rule:web:Block SSN", "add_tag", by="alice", tag="URGENT")      # same tag, any case: kept once
    todo = wn.apply(A, "rule", "rule:web:Block SSN", "add_todo", by="bob", text="Move above the catch-all")["todos"][0]
    assert todo["done"] is False and todo["by"] == "bob" and re.fullmatch(r"[a-f0-9]{16}", todo["id"])
    wn.apply(A, "rule", "rule:web:Block SSN", "add_comment", by="bob", text="Customer agreed\non Tuesday")
    done = wn.apply(A, "rule", "rule:web:Block SSN", "set_todo", by="carol", item_id=todo["id"], done=True)["todos"][0]
    assert done["done"] and done["done_by"] == "carol" and done["done_at"]
    got = wn.get(A, "rule", "rule:web:Block SSN")
    assert got["tags"] == ["urgent"] and got["comments"][0]["text"] == "Customer agreed\non Tuesday" and got["updated_by"] == "carol"
    p = wn.store_path()
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600
    folder = os.path.dirname(p)
    assert sorted(f for f in os.listdir(folder) if not f.endswith(".last-good")) == ["workspace_notes.json", "workspace_notes.json.lock"], "no temporary file is left behind"
    # Emptying a note removes it.
    wn.apply(A, "rule", "rule:web:Block SSN", "remove_tag", by="alice", tag="Urgent")
    wn.apply(A, "rule", "rule:web:Block SSN", "delete_todo", by="alice", item_id=todo["id"])
    c_id = got["comments"][0]["id"]
    assert wn.apply(A, "rule", "rule:web:Block SSN", "delete_comment", by="alice", item_id=c_id) is None
    assert wn.get(A, "rule", "rule:web:Block SSN") is None and wn.tenants() == []


def test_the_default_store_sits_beside_the_tenant_profiles(monkeypatch, tmp_path):
    monkeypatch.delenv("DLP_CHECK_WORKSPACE_NOTES")
    assert wn.store_path() == os.path.join(str(tmp_path), "workspace_notes.json")
    assert os.path.dirname(wn.store_path()) == os.path.dirname(os.path.abspath(tenant_profiles.store_path()))


def test_sizes_are_validated_and_capped(monkeypatch):
    with pytest.raises(wn.NotesError, match="at most 20 tags"):
        wn.apply(A, "rule", "r", "set_tags", by="a", tags=[f"t{i}" for i in range(21)])
    with pytest.raises(wn.NotesError, match="too long"):
        wn.apply(A, "rule", "r", "add_tag", by="a", tag="x" * (wn.MAX_TAG_LEN + 1))
    for bad in ("", "  ", "-starts-with-dash", "quote\"d", "<b>", "a;b"):
        with pytest.raises(wn.NotesError):
            wn.apply(A, "rule", "r", "add_tag", by="a", tag=bad)
    with pytest.raises(wn.NotesError, match="too long"):
        wn.apply(A, "rule", "r", "add_comment", by="a", text="x" * (wn.MAX_COMMENT_LEN + 1))
    with pytest.raises(wn.NotesError, match="too long"):
        wn.apply(A, "rule", "r", "add_todo", by="a", text="x" * (wn.MAX_TODO_LEN + 1))
    with pytest.raises(wn.NotesError, match="write something"):
        wn.apply(A, "rule", "r", "add_todo", by="a", text=" \x00\x07 ")
    monkeypatch.setattr(wn, "MAX_TODOS", 2)
    wn.apply(A, "rule", "r", "add_todo", by="a", text="one")
    wn.apply(A, "rule", "r", "add_todo", by="a", text="two")
    with pytest.raises(wn.NotesError, match="at most 2 to-dos") as e:
        wn.apply(A, "rule", "r", "add_todo", by="a", text="three")
    assert e.value.status == 409
    monkeypatch.setattr(wn, "MAX_NOTES_PER_TENANT", 2)
    wn.apply(A, "rule", "s", "add_tag", by="a", tag="x")
    with pytest.raises(wn.NotesError, match="at most 2 notes"):
        wn.apply(A, "rule", "third", "add_tag", by="a", tag="x")
    wn.apply(B, "rule", "third", "add_tag", by="a", tag="x")    # the cap is per tenant
    monkeypatch.setattr(wn, "MAX_TENANTS", 2)
    with pytest.raises(wn.NotesError, match="at most 2 tenants"):
        wn.apply("initech (production)", "rule", "r", "add_tag", by="a", tag="x")
    with pytest.raises(wn.NotesError, match="unknown action"):
        wn.apply(A, "rule", "r", "rm -rf", by="a")
    with pytest.raises(wn.NotesError, match="who is writing"):
        wn.apply(A, "rule", "r", "add_tag", by="", tag="x")
    with pytest.raises(wn.NotesError, match="path in this app"):
        wn.apply(A, "rule", "r", "add_tag", by="a", tag="x", href="https://evil.example/")
    with pytest.raises(wn.NotesError, match="path in this app"):
        wn.apply(A, "rule", "r", "add_tag", by="a", tag="x", href="//evil.example/")
    with pytest.raises(wn.NotesError, match="its id"):
        wn.apply(A, "rule", "r", "set_todo", by="a", item_id="../x")


def test_tenants_are_kept_apart():
    wn.apply(A, "dictionary", "dictionary:SSN", "add_tag", by="a", tag="acme-only")
    wn.apply(B, "dictionary", "dictionary:SSN", "add_todo", by="a", text="Globex work")
    assert wn.get(A, "dictionary", "dictionary:SSN")["tags"] == ["acme-only"] and not wn.get(A, "dictionary", "dictionary:SSN")["todos"]
    assert wn.get(B, "dictionary", "dictionary:SSN")["tags"] == [] and wn.get(B, "dictionary", "dictionary:SSN")["todos"][0]["text"] == "Globex work"
    assert [n["tenant"] for n in wn.list_notes(A)] == [A] and [n["tenant"] for n in wn.list_notes(B)] == [B]
    assert sorted(n["tenant"] for n in wn.list_notes(None)) == sorted([A, B])
    assert [t["tenant"] for t in wn.tenants()] == [A, B] and wn.tenants()[1]["open_todos"] == 1
    assert [n["ref"] for n in wn.list_notes(None, tag="ACME-ONLY")] == ["dictionary:SSN"]


def test_no_request_value_ever_becomes_a_path(tmp_path):
    evil = ["../../etc/passwd", "..\\..\\windows\\win.ini", "/etc/passwd", "a/../../b", "C:\\x"]
    for ref in evil:
        wn.apply("../../outside", "rule", ref, "add_tag", by="a", tag="x")
    for kind in ("../rule", "rule/x", "", "a" * 41, "1rule"):
        with pytest.raises(wn.NotesError, match="kind"):
            wn.apply(A, kind, "r", "add_tag", by="a", tag="x")
    with pytest.raises(wn.NotesError):
        wn.apply(A, "rule", "x" * (wn.MAX_REF_LEN + 1), "add_tag", by="a", tag="x")
    with pytest.raises(wn.NotesError):
        wn.apply("t" * (wn.MAX_TENANT_LEN + 1), "rule", "r", "add_tag", by="a", tag="x")
    # Everything is a key inside the one store; nothing else was created anywhere.
    created = sorted(os.path.relpath(os.path.join(d, f), tmp_path) for d, _, fs in os.walk(tmp_path) for f in fs if f != "audit.log" and not f.endswith(".last-good"))
    assert created == [os.path.join("notes", "workspace_notes.json"), os.path.join("notes", "workspace_notes.json.lock")]
    data = json.load(open(wn.store_path(), encoding="utf-8"))
    notes = data["tenants"]["../../outside"]["notes"]
    assert sorted(n["ref"] for n in notes.values()) == sorted(evil)
    assert all(re.fullmatch(r"[a-f0-9]{32}", k) for k in notes)


# ── the endpoints ───────────────────────────────────────────────────────
def test_every_notes_call_needs_the_ui_token(monkeypatch):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_UI_TOKEN", "notes-token-123")
    c = _client()
    assert c.get(f"/api/workspace/notes?tenant={A}").status_code == 401
    assert c.get("/api/workspace/notes?all_tenants=1").status_code == 401
    assert _post(c, tenant=A, kind="rule", ref="r", action="add_tag", tag="x").status_code == 401
    assert c.delete(f"/api/workspace/notes?tenant={A}&kind=rule&ref=r").status_code == 401
    assert c.get("/api/console-index/cached").status_code == 401
    assert wn.tenants() == [], "nothing was written without the token"
    hdr = {"X-DLP-Check-Token": "notes-token-123"}
    assert c.post("/api/workspace/notes", json={"tenant": A, "kind": "rule", "ref": "r", "action": "add_tag", "tag": "x"}, headers=hdr).status_code == 200
    assert c.get(f"/api/workspace/notes?tenant={A}&kind=rule&ref=r", headers=hdr).json()["note"]["tags"] == ["x"]
    assert c.delete(f"/api/workspace/notes?tenant={A}&kind=rule&ref=r", headers=hdr).json() == {"tenant": A, "deleted": True}


def test_writes_record_who_from_the_session_and_go_to_the_audit_log_without_the_text(monkeypatch):
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "https://idp.example.test/oauth2/default")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_ID", "client-123")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_SECRET", "s3cret")
    monkeypatch.setenv("ZSCALER_SSO_REDIRECT_URL", "http://testserver/api/auth/sso/callback")
    sid = sso.create_session({"sub": "alice@example.com", "email": "alice@example.com", "groups": []})
    c = _client()
    c.cookies.set(security.SSO_SESSION_COOKIE, sid)
    r = _post(c, tenant=A, kind="finding", ref="5.20", action="add_todo", text="Card 4111 1111 1111 1111 seen in Bob's upload",
              label="Finding [5.20]", by="mallory")   # a page cannot say who it is
    assert r.status_code == 200, r.text
    note = r.json()["note"]
    assert note["created_by"] == "alice@example.com" and note["todos"][0]["by"] == "alice@example.com"
    lines = _audit()
    step = [e for e in lines if e.get("event") == "workspace_note"]
    assert step and step[-1]["actor"] == "alice@example.com" and step[-1]["action"] == "add_todo"
    assert step[-1]["tenant"] == A and step[-1]["kind"] == "finding" and step[-1]["ref"] == "5.20"
    api = [e for e in lines if e.get("event") == "api" and e.get("path") == "/api/workspace/notes"]
    assert api and api[-1]["actor"] == "alice@example.com"
    raw = open(os.environ["DLP_CHECK_AUDIT"], encoding="utf-8").read()
    assert "4111" not in raw and "Bob's upload" not in raw, "a note's text never reaches the audit log"
    rid = note["todos"][0]["id"]
    assert _post(c, tenant=A, kind="finding", ref="5.20", action="set_todo", item_id=rid, done=True).json()["note"]["todos"][0]["done_by"] == "alice@example.com"
    assert c.delete(f"/api/workspace/notes?tenant={A}&kind=finding&ref=5.20").status_code == 200
    assert [e["action"] for e in _audit() if e.get("event") == "workspace_note"] == ["add_todo", "set_todo", "delete_note"]


def test_the_extension_may_read_notes_but_never_write_them(monkeypatch):
    c = _client()
    _post(c, tenant=A, kind="rule", ref="rule:web:X", action="add_tag", tag="x")
    ext = {"Origin": security.extension_origin()}
    assert security.extension_origin().startswith("chrome-extension://")
    r = c.post("/api/workspace/notes", json={"tenant": A, "kind": "rule", "ref": "rule:web:X", "action": "add_tag", "tag": "y"}, headers=ext)
    assert r.status_code == 403
    assert c.delete(f"/api/workspace/notes?tenant={A}&kind=rule&ref=rule:web:X", headers=ext).status_code == 403
    assert c.get(f"/api/workspace/notes?tenant={A}&kind=rule&ref=rule:web:X", headers=ext).json()["note"]["tags"] == ["x"]
    assert not any("workspace" in p for p in security.EXTENSION_POST_PATHS)
    assert c.post("/api/workspace/notes", json={"tenant": A, "kind": "rule", "ref": "r", "action": "add_tag", "tag": "y"},
                  headers={"Origin": "http://evil.example"}).status_code == 403


def test_the_tenant_comes_from_the_label_a_profile_or_the_sign_in_and_never_needs_a_secret(monkeypatch):
    c = _client()
    p = tenant_profiles.upsert({"name": "Acme", "vanity_domain": "acme", "cloud": "zscalertwo", "client_id": "cid-1", "auth_method": "oneapi"})
    r = _post(c, profile_id=p["id"], kind="rule", ref="r", action="add_tag", tag="from-profile")
    assert r.status_code == 200 and r.json()["tenant"] == "acme (zscalertwo)"
    assert c.get("/api/workspace/notes", params={"vanity_domain": "acme", "cloud": "zscalertwo", "kind": "rule", "ref": "r"}).json()["note"]["tags"] == ["from-profile"]
    assert c.get("/api/workspace/notes", params={"tenant": "acme (zscalertwo)"}).json()["notes"][0]["ref"] == "r"
    assert c.get("/api/workspace/notes", params={"auth_method": "legacy", "cloud": "zscaler"}).json()["tenant"] == "classic API (zscaler)"
    assert c.get("/api/workspace/notes", params={"profile_id": "nope"}).status_code == 404
    r = c.get("/api/workspace/notes")
    assert r.status_code == 400 and "pick a tenant" in r.json()["detail"]
    monkeypatch.setenv("ZSCALER_CLIENT_ID", "env-cid")
    monkeypatch.setenv("ZSCALER_CLIENT_SECRET", "env-secret")
    monkeypatch.setenv("ZSCALER_VANITY_DOMAIN", "envco")
    assert c.get("/api/workspace/notes").json()["tenant"].startswith("envco (")
    everything = c.get("/api/workspace/notes", params={"all_tenants": 1}).json()
    assert everything["tenants"][0]["tenant"] == "acme (zscalertwo)" and everything["limits"]["tags"] == wn.MAX_TAGS
    assert "env-secret" not in json.dumps(everything)


def test_refusals_are_plain_and_nothing_reads_the_tenant(monkeypatch):
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("notes never read the tenant")))
    c = _client()
    r = _post(c, tenant=A, kind="rule", ref="r", action="add_tag", tag="x" * 99)
    assert r.status_code == 400 and "too long" in r.json()["detail"]
    r = _post(c, tenant=A, kind="rule", ref="r", action="set_todo", item_id="0123456789abcdef")
    assert r.status_code == 404
    assert c.delete(f"/api/workspace/notes?tenant={A}&kind=rule&ref=gone").status_code == 404


def test_the_cached_console_index_is_returned_without_a_tenant_read(monkeypatch):
    import console_index as ci
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("no tenant read")))
    ci.cache_clear()
    c = _client()
    assert c.get("/api/console-index/cached", params={"profile_id": "p1"}).json() == {"index": None, "profile_id": "p1"}
    ci.cache_put(ci.cache_key("p1", ["web"]), {"tenant_label": A, "objects": [{"kind": "rule", "name": "R"}], "read_at": 1})
    ci.cache_put(ci.cache_key("p2", ["web"]), {"tenant_label": B, "objects": [], "read_at": 2})
    got = c.get("/api/console-index/cached", params={"profile_id": "p1"}).json()["index"]
    assert got["tenant_label"] == A and got["cached_at"]
    assert c.get("/api/console-index/cached").json()["index"] is None, "the server's own tenant has no index kept"
    ci.cache_clear()


# ── the page ────────────────────────────────────────────────────────────
def test_the_todo_page_follows_the_report_page_conventions():
    c = _client()
    r = c.get("/report/todo")
    assert r.status_code == 200 and "no-cache" in r.headers["cache-control"]
    html = r.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', 'href="/">← Back to the assessment',
                   '<main class="rp-card" id="main-content">', 'class="skip-link"', 'role="status" aria-live="polite"',
                   '/api/workspace/notes?all_tenants=1', "action: 'set_todo'", "h('th', { scope: 'col'", 'id="tdTag"', 'id="tdShowDone"',
                   "No to-dos yet, so the list is empty.", "<title>To-do list — Zscaler Made Easy</title>"):
        assert needle in html, needle
    order = [html.index(f'<script src="/static/{s}"></script>') for s in
             ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js", "find_anything.js")]
    assert order == sorted(order)
    style = html.split("<style>")[1].split("</style>")[0]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style) and "gradient" not in style and "box-shadow" not in style
    assert "innerHTML" not in html, "every value is set as text"
    explain = open(os.path.join(STATIC, "explain.js"), encoding="utf-8").read()
    assert "X.todo = {" in explain and "group: 'Close the gaps', name: 'To-do list', href: '/report/todo'" in explain
    assert "'/report/todo': 'todo'" in explain and "'queue', 'todo'," in explain
    index = open(os.path.join(STATIC, "index.html"), encoding="utf-8").read()
    assert 'onclick="openTodoTab()"' in index and "window.open('/report/todo', '_blank')" in index
    overview = open(os.path.join(ROOT, "docs", "OVERVIEW.md"), encoding="utf-8").read()
    assert "**To-do list** (`/report/todo`)" in overview
    for ig in (".gitignore", ".dockerignore"):
        assert "workspace_notes.json" in open(os.path.join(ROOT, ig), encoding="utf-8").read().split(), ig
