"""ZIdentity users and API clients on the Bulk changes engine (ops_zid).

Every test runs against the stateful fake in tests/admin_identity_fake.py
(SDK 1.11.3 method names, models and answers; every write's wire body):
no network, no clock, state files in tmp_path. A canary secret stands in
for every secret ZIdentity answers: it must reach no sink but the one
reveal."""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zid as oz  # noqa: E402
from admin_identity_fake import CANARY_SECRET, Client  # noqa: E402
from zscaler.zid.models.api_client import APIClientRecords, ClientAuthentication, ClientResources  # noqa: E402
from zscaler.zid.models.users import UserRecord  # noqa: E402

ZID = ao.scope_for(["zidentity"], {})
NO_ZID = ao.scope_for(["zia_extras", "zpa", "zcc"], {})
ASSESSOR = "Jane Doe"
CREATE = {"type": "zid_api_clients", "action": "create", "name": "Probe client", "description": "reads only",
          "scopes": [{"resource": "rs-1", "scope": "sc-ro"}]}


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(oz, "_SECRETS", {})
    ao.load_plugins()
    return tmp_path


def plan(c, spec, scope=ZID):
    return ao.plan(c, spec, scope=scope, tenant_label="acme")


def apply(c, spec, *, phrase=None, prepared=None):
    p = prepared or plan(c, spec)
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=(p.get("confirm_phrase") or "") if phrase is None else phrase)
    return p, r


def keys(model) -> set:
    return set(model({}).request_format()) | set(model().request_format())


def _sinks(tmp_path, *objs, extra=""):
    files = "".join(open(os.path.join(tmp_path, f), encoding="utf-8").read() for f in os.listdir(tmp_path) if os.path.isfile(os.path.join(tmp_path, f)))
    return json.dumps(objs, default=str) + files + extra


# ── registration, scope, what is not possible ───────────────────────────

def test_both_types_are_registered_for_zidentity_with_their_form():
    """ASVS V1.14.1 · CWE-1059: users and API clients are Day-to-day admin types of the product ZIdentity, with the page script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in ("zid_users", "zid_api_clients"):
        assert cat[t]["product"] == "zidentity" and cat[t]["group"] == "Day-to-day admin" and cat[t]["script"] == "ops_zid.js"


@pytest.mark.parametrize("spec", [{"type": "zid_users", "changes": [{"action": "disable", "id": "u-1"}]}, CREATE])
def test_out_of_scope_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZIdentity ticked the plan, the apply and the picker are refused; nothing is read."""
    c = Client()
    with pytest.raises(ao.OperationError, match="ZIdentity is not ticked"):
        plan(c, spec, NO_ZID)
    with pytest.raises(ao.OperationError):
        ao.execute(c, spec, plan_hash="0" * 64, scope=NO_ZID, writes_enabled=True, assessor=ASSESSOR)
    with pytest.raises(ao.OperationError):
        ao.read_objects(c, oz.FAMILY, NO_ZID)
    assert c.tenant.reads == [] and c.tenant.sent == []


def test_a_classic_zia_sign_in_has_no_zidentity_and_reads_nothing():
    """ASVS V4.1.3 · CWE-284: a sign-in without the ZIdentity service (the classic ZIA API) is refused in words."""
    class Legacy:
        zia = object()
    with pytest.raises(ao.OperationError, match="OneAPI"):
        plan(Legacy(), CREATE)


@pytest.mark.parametrize("action", ["reset_password", "reset_mfa", "skip_mfa"])
def test_password_and_mfa_resets_are_not_possible_with_the_sdk_and_say_so(action):
    """ASVS V2.5.1 · CWE-640: the installed SDK has no password or MFA call (checked on the SDK itself); asking for one is refused in words."""
    from zscaler.zid.users import UsersAPI
    from zscaler.zid.models.users import UserRecord as Model
    methods = {m for m in vars(UsersAPI) if not m.startswith("_")}
    assert methods == {"list_users", "get_user", "add_user", "update_user", "delete_user", "list_user_group_details"}, methods
    assert not [m for m in dir(UsersAPI) if "password" in m.lower() or "mfa" in m.lower()]
    assert not any("password" in k.lower() or "mfa" in k.lower() for k in Model({}).request_format())
    with pytest.raises(ao.OperationError, match="installed Zscaler SDK"):
        plan(Client(), {"type": "zid_users", "changes": [{"action": action, "id": "u-1"}]})
    assert any("password" in n for n in ao.read_objects(Client(), oz.FAMILY, ZID)["not_possible"])


# ── users ──────────────────────────────────────────────────────────────

def test_a_new_user_is_created_disabled_with_user_record_fields_only():
    """ASVS V5.1.3 · V4.1.3 · CWE-1188 · CWE-20: a new user is disabled unless asked, the body has only UserRecord fields and no password; Undo deletes it."""
    c = Client()
    spec = {"type": "zid_users", "changes": [{"action": "create", "login_name": "sam@acme.example", "display_name": "Sam Lee", "first_name": "Sam"}]}
    p, r = apply(c, spec)
    assert p["items"][0]["value"] == "disabled" and r["status"] == "applied" and r["verification"]["confirmed"] == 1
    body = next(s for s in c.tenant.writes() if s[:2] == ("POST", "zid/users"))[2]
    assert set(body) <= keys(UserRecord) and body["status"] is False and not any("pass" in k.lower() for k in body)
    inv = r["inverse"]
    assert ao.is_undo_only(inv) and inv["changes"][0]["action"] == "delete"
    p2, r2 = apply(c, inv)
    assert p2["confirm_phrase"] == "DELETE SAM@ACME.EXAMPLE" and r2["status"] == "applied"
    assert "sam@acme.example" not in [u["loginName"] for u in c.tenant.zid_users.values()]


def test_disable_puts_the_user_back_as_read_with_status_false_and_undo_enables():
    """ASVS V5.1.3 · V11.1.1 · CWE-840: disable sends the user as read with status false; its Undo enables the user again."""
    c = Client()
    p, r = apply(c, {"type": "zid_users", "changes": [{"action": "disable", "id": "u-2"}]})
    put = next(s for s in c.tenant.writes() if s[0] == "PUT")
    assert set(put[2]) <= keys(UserRecord) and put[2]["status"] is False and put[2]["loginName"] == "rowan@acme.example"
    assert r["inverse"] == {"type": "zid_users", "action": "undo", "changes": [{"action": "enable", "id": "u-2"}]}
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.zid_users["u-2"]["status"] is True


@pytest.mark.parametrize("uid, why", [("u-3", "administrator"), ("u-4", "SCIM")])
def test_administrators_and_scim_users_are_left_alone(uid, why):
    """ASVS V4.1.3 · CWE-269: an administrator or a user from SCIM is excluded with the reason (no lockout, no fight with the IdP)."""
    for action in ("disable", "delete"):
        p = plan(Client(), {"type": "zid_users", "changes": [{"action": action, "id": uid}]})
        assert p["counts"]["change"] == 0 and why in p["items"][0]["reason"], action


def test_deleting_a_user_needs_the_login_typed_and_cannot_be_undone():
    """ASVS V11.1.1 · CWE-841: a delete asks DELETE <login>; wrong text writes nothing; the preview says it cannot be undone; no inverse."""
    c = Client()
    spec = {"type": "zid_users", "changes": [{"action": "delete", "id": "u-1"}]}
    p = plan(c, spec)
    assert p["confirm_phrase"] == "DELETE AVERY@ACME.EXAMPLE" and any("Cannot be undone" in w for w in p["warnings"])
    _p, r = apply(c, spec, phrase="DELETE AVERY", prepared=p)
    assert r["status"] == "refused" and c.tenant.writes() == []
    _p, r = apply(c, spec, prepared=p)
    assert r["status"] == "applied" and "u-1" not in c.tenant.zid_users and r["inverse"] is None


def test_the_picker_searches_users_and_lists_clients_scopes_without_a_secret():
    """ASVS V8.3.4 · CWE-200: the picker searches users by login name, lists API clients with their scopes (full access flagged, this app's own client marked); no secret value."""
    c = Client()
    out = ao.read_objects(c, oz.FAMILY, ZID, query="row")
    assert [u["login_name"] for u in out["users"]] == ["rowan@acme.example"]
    rep = next(x for x in out["api_clients"] if x["name"] == "Reporting")
    assert rep["scopes"][0]["name"].endswith("Read Only") and not rep["own"]
    assert next(x for x in out["api_clients"] if x["id"] == "c-self")["own"] is True
    assert [s["broad"] for s in out["resource_servers"][0]["scopes"]] == [False, True]
    assert CANARY_SECRET not in json.dumps(out)


# ── API clients ────────────────────────────────────────────────────────

def test_a_client_needs_a_scope_and_nothing_is_preselected():
    """ASVS V4.1.3 · CWE-250 · CWE-272: least privilege: a client with no scope is refused; the page ticks none for you."""
    with pytest.raises(ao.OperationError, match="least privilege"):
        plan(Client(), dict(CREATE, scopes=[]))
    js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_zid.js"), encoding="utf-8").read()
    assert "scopes: new Set()" in js and "Nothing is ticked for you" in js


def test_a_full_access_scope_is_named_in_the_preview():
    """ASVS V4.1.3 · CWE-250: picking a Super Admin scope is warned about in plain words."""
    p = plan(Client(), dict(CREATE, scopes=[{"resource": "rs-1", "scope": "sc-sa"}]))
    assert any("full administrative access" in w for w in p["warnings"])


def test_create_sends_model_fields_disabled_and_the_secret_reaches_no_sink(isolated, caplog):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-312 · CWE-200: the client is created disabled with SDK-model fields; its secret (and one in the create's answer) is in no result, record, log, audit entry or file; it is revealed once."""
    caplog.set_level(logging.DEBUG)
    c = Client()
    import pack_ops as ops
    with ops.audit_scope(actor="alice"):
        p, r = apply(c, CREATE)
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    body = next(s for s in c.tenant.writes() if s[:2] == ("POST", "zid/api-clients"))[2]
    assert set(body) <= keys(APIClientRecords) and body["status"] is False
    assert set(body["clientAuthentication"]) <= keys(ClientAuthentication) and set(body["clientResources"][0]) <= keys(ClientResources) | {"selectedScopes"}
    assert body["clientResources"][0]["selectedScopes"] == [{"id": "sc-ro", "name": "zs:config:zia:acme:Read Only"}]
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 3
    plans_again = [plan(c, {"type": "zid_api_clients", "action": "rotate", "id": r["created"][0]["id"]}), ao.read_objects(c, oz.FAMILY, ZID)]
    blob = _sinks(isolated, p, r, rec, plans_again, extra=caplog.text)
    assert CANARY_SECRET not in blob
    token = r["one_time_secrets"][0]["token"]
    assert oz.reveal(token, actor="bob") is None, "bound to who ran the apply"
    assert oz.reveal(token, actor="alice") == {"name": "Probe client", "secret": CANARY_SECRET}
    assert oz.reveal(token, actor="alice") is None
    assert ao.is_undo_only(r["inverse"]) and r["inverse"]["delete"]["name"] == "Probe client"


def test_rotation_makes_the_new_secret_first_then_deletes_the_old_and_cannot_be_undone():
    """ASVS V11.1.1 · CWE-841 · CWE-1188: rotate asks ROTATE <name>; the new secret is made before any old one is deleted; the preview says it cannot be undone."""
    c = Client()
    spec = {"type": "zid_api_clients", "action": "rotate", "id": "c-1"}
    p = plan(c, spec)
    assert p["confirm_phrase"] == "ROTATE REPORTING" and any("Cannot be undone" in w for w in p["warnings"])
    _p, r = apply(c, spec, phrase="", prepared=p)
    assert r["status"] == "refused" and c.tenant.writes() == []
    _p, r = apply(c, spec, prepared=p)
    order = [s[0] for s in c.tenant.writes()]
    assert order == ["POST", "DELETE"] and [s["id"] for s in c.tenant.secrets["c-1"]] != ["s-old"] and len(c.tenant.secrets["c-1"]) == 1
    assert r["status"] == "applied" and r["inverse"] is None and len(r["one_time_secrets"]) == 1
    assert CANARY_SECRET not in json.dumps(r, default=str)


def test_when_the_new_secret_fails_the_old_ones_stay():
    """ASVS V11.1.1 · CWE-460: if ZIdentity refuses the new secret, no old secret is deleted (no lockout)."""
    c = Client()
    c.tenant.refuse[("add", "secret")] = '{"status": 400, "message": "refused"}'
    _p, r = apply(c, {"type": "zid_api_clients", "action": "rotate", "id": "c-1"})
    assert [s["id"] for s in c.tenant.secrets["c-1"]] == ["s-old"] and not [s for s in c.tenant.writes() if s[0] == "DELETE"]
    assert {u["status"] for u in r["items"]} == {"failed", "skipped"}


def test_keep_old_secrets_only_adds_one():
    """ASVS V11.1.1 · CWE-1188: with the old secrets kept, only the new one is made."""
    c = Client()
    _p, r = apply(c, {"type": "zid_api_clients", "action": "rotate", "id": "c-1", "delete_old": False})
    assert r["status"] == "applied" and len(c.tenant.secrets["c-1"]) == 2


@pytest.mark.parametrize("action", ["rotate", "disable", "delete"])
def test_the_api_client_this_app_signs_in_with_is_never_changed(action):
    """ASVS V4.1.3 · CWE-284: rotating, disabling or deleting this app's own API client is excluded (it would lock the app out)."""
    c = Client()
    p = plan(c, {"type": "zid_api_clients", "action": action, "id": "c-self"})
    assert p["counts"]["change"] == 0 and "signed in with" in p["items"][0]["reason"]


def test_deleting_a_client_needs_its_name_and_disable_is_undone_by_enable():
    """ASVS V11.1.1 · CWE-841 · CWE-840: delete asks DELETE <name> and cannot be undone; disable sends the client as read with status false and its Undo enables it."""
    c = Client()
    p = plan(c, {"type": "zid_api_clients", "action": "delete", "id": "c-1"})
    assert p["confirm_phrase"] == "DELETE REPORTING" and any("Cannot be undone" in w for w in p["warnings"])
    _p, r = apply(c, {"type": "zid_api_clients", "action": "disable", "id": "c-1"})
    put = next(s for s in c.tenant.writes() if s[0] == "PUT")
    assert set(put[2]) <= keys(APIClientRecords) and put[2]["status"] is False and put[2]["clientResources"][0]["selectedScopes"][0]["id"] == "sc-ro"
    assert r["inverse"] == {"type": "zid_api_clients", "action": "enable", "id": "c-1"}
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.clients["c-1"]["status"] is True


def test_a_client_changed_since_the_preview_writes_nothing():
    """ASVS V11.1.6 · CWE-367: a client whose scopes changed after the preview changes the plan: nothing is written."""
    c = Client()
    spec = {"type": "zid_api_clients", "action": "disable", "id": "c-1"}
    p = plan(c, spec)
    c.tenant.clients["c-1"]["clientResources"][0]["selectedScopes"].append({"id": "sc-sa", "name": "x"})
    _p, r = apply(c, spec, prepared=p)
    assert r["status"] == "plan_changed" and c.tenant.writes() == []


def test_the_one_time_secret_expires_and_the_store_stays_small():
    """ASVS V8.3.4 · V3.3.1 · CWE-613: a secret not fetched within ten minutes is gone; the store keeps at most 20."""
    tok = oz.stash("v-1", "x", "alice", now=1000.0)
    assert oz.reveal(tok, "alice", now=1000.0 + oz.SECRET_TTL + 1) is None
    for i in range(30):
        oz.stash(f"v{i}", "x", None, now=2000.0 + i)
    assert len(oz._SECRETS) <= oz.MAX_SECRETS
    assert oz.reveal("short", None) is None and oz.reveal("<script>" * 5, None) is None


# ── Through the app's routes: preview, gated apply as a job, the one-time reveal ──

API_CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
API_SCOPE = {"scopes": ["zidentity"], "channels": {}, "from_page": True}


def test_the_secret_through_the_api_is_in_no_job_record_or_audit_and_is_revealed_once(isolated, monkeypatch, caplog):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: the secret is absent from the job's logs and result, the change history, the Undo preview and the audit log; the reveal answers it once with no-store."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import pack_jobs
    import security
    caplog.set_level(logging.DEBUG)
    client = Client()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(security, "_write_override", True)
    real_start = pack_jobs.start

    def start_and_finish(*a, **k):
        job = real_start(*a, **k)
        job.thread.join(20)
        return job
    monkeypatch.setattr(pack_jobs, "start", start_and_finish)
    api = TestClient(srv.app)
    objects = api.post("/api/operations/objects", json=dict(API_CREDS, **API_SCOPE, family=oz.FAMILY, query="avery"))
    assert objects.status_code == 200 and [u["login_name"] for u in objects.json()["users"]] == ["avery@acme.example"]
    prev = api.post("/api/operations/preview", json=dict(API_CREDS, **API_SCOPE, operation=CREATE))
    assert prev.status_code == 200, prev.text
    started = api.post("/api/operations/apply/start", json=dict(API_CREDS, **API_SCOPE, operation=CREATE, plan_hash=prev.json()["plan_hash"],
                                                                confirm=True, assessor=ASSESSOR))
    snap = api.get(f"/api/dlp-packs/jobs/{started.json()['job_id']}")
    res = snap.json()["result"]
    assert res["status"] == "applied", res
    history = api.get("/api/operations").text + api.get(f"/api/operations/{res['operation_id']}").text
    undo = api.post(f"/api/operations/{res['operation_id']}/undo/preview", json=dict(API_CREDS, **API_SCOPE))
    assert undo.status_code == 200 and undo.json()["confirm_phrase"] == "DELETE PROBE CLIENT"
    blob = _sinks(isolated, res, extra=caplog.text + snap.text + history + prev.text + started.text + undo.text + objects.text)
    assert CANARY_SECRET not in blob
    token = res["one_time_secrets"][0]["token"]
    first = api.post("/api/operations/zidentity/secret", json={"token": token})
    second = api.post("/api/operations/zidentity/secret", json={"token": token})
    assert first.status_code == 200 and first.json()["secret"] == CANARY_SECRET and "no-store" in first.headers["cache-control"]
    assert second.status_code == 404 and CANARY_SECRET not in second.text
    assert CANARY_SECRET not in open(os.path.join(isolated, "audit.log"), encoding="utf-8").read()
    assert '"event":"admin_operation"' in open(os.path.join(isolated, "audit.log"), encoding="utf-8").read()


def test_the_reveal_route_needs_a_writer_and_a_known_token(monkeypatch):
    """ASVS V4.1.3 · CWE-862 · CWE-639: the reveal is refused to a reader and answers 404 for an unknown token, saying nothing about it."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    api = TestClient(srv.app)
    r = api.post("/api/operations/zidentity/secret", json={"token": "x" * 40})
    assert r.status_code == 404 and "shown once" in r.json()["detail"]
    import security

    def no_writer():
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="not a writer")
    monkeypatch.setattr(security, "require_writer", no_writer)
    monkeypatch.setattr(srv._security, "require_writer", no_writer)
    tok = oz.stash("v", "x", None)
    assert api.post("/api/operations/zidentity/secret", json={"token": tok}).status_code == 403
    assert oz.reveal(tok) == {"name": "x", "secret": "v"}, "a refused reveal does not spend the secret"
