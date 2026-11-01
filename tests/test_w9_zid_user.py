"""One ZIdentity user (ops_zid_user): edit its attributes and groups, reset
its password or let it skip MFA, on the Bulk changes engine.

Every test runs against the stateful fake in tests/admin_identity_fake.py
(SDK 1.11.3 method names and models; every write's wire body; the raw
requests the SDK's executor would send): no network, no clock, state files
in tmp_path. A canary stands in for any temporary password ZIdentity might
answer: it must reach no sink but the one reveal."""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zid as oz  # noqa: E402
import ops_zid_user as ou  # noqa: E402
from admin_identity_fake import Client  # noqa: E402

ZID = ao.scope_for(["zidentity"], {})
NO_ZID = ao.scope_for(["zia_extras", "zpa"], {})
ASSESSOR = "Jane Doe"
CANARY_PW = "CANARY-TEMP-PASSWORD-91be"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(oz, "_SECRETS", {})
    ao.load_plugins()
    return tmp_path


def client():
    c = Client()
    c.tenant.zid_users["u-1"]["department"] = {"id": "d-1", "name": "Finance"}
    c.tenant.zid_users["u-1"]["primaryEmail"] = "avery@acme.example"
    c.tenant.zid_users["u-2"]["department"] = {"id": "d-2", "name": "Engineering"}
    return c


def apply(c, spec, *, phrase=None, assessor=ASSESSOR):
    p = ao.plan(c, spec, scope=ZID, tenant_label="acme")
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=assessor, tenant_label="acme",
                   confirm_text=(p.get("confirm_phrase") or "") if phrase is None else phrase)
    return p, r


def sinks(tmp_path, *objs, extra=""):
    files = "".join(open(os.path.join(tmp_path, f), encoding="utf-8").read() for f in os.listdir(tmp_path) if os.path.isfile(os.path.join(tmp_path, f)))
    return json.dumps(objs, default=str) + files + extra


# ── registration and scope ─────────────────────────────────────────────

def test_both_types_are_registered_for_zidentity_with_their_form():
    """ASVS V1.14.1 · CWE-1059: the user edit and the reset are Day-to-day admin types of ZIdentity on the one engine, with their page script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in (ou.T_EDIT, ou.T_RESET):
        assert cat[t]["product"] == "zidentity" and cat[t]["group"] == "Day-to-day admin" and cat[t]["script"] == "ops_zid_user.js"
    assert os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_zid_user.js"))


@pytest.mark.parametrize("spec", [{"type": ou.T_EDIT, "id": "u-1", "set": {"display_name": "A"}},
                                  {"type": ou.T_RESET, "id": "u-1", "action": "reset_password"}])
def test_out_of_scope_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZIdentity ticked the plan, the apply and the picker are refused; nothing is read."""
    c = client()
    with pytest.raises(ao.OperationError, match="ZIdentity is not ticked"):
        ao.plan(c, spec, scope=NO_ZID)
    with pytest.raises(ao.OperationError):
        ao.execute(c, spec, plan_hash="0" * 64, scope=NO_ZID, writes_enabled=True, assessor=ASSESSOR)
    with pytest.raises(ao.OperationError):
        ao.read_objects(c, ou.FAMILY, NO_ZID)
    assert c.tenant.reads == [] and c.tenant.sent == []


def test_the_picker_lists_users_departments_and_groups_and_names_the_raw_calls():
    """ASVS V8.3.4 · CWE-200: the picker reads users, the departments they carry and the groups (dynamic marked); it states the raw calls."""
    out = ao.read_objects(client(), ou.FAMILY, ZID)
    assert {d["name"] for d in out["departments"]} == {"Finance", "Engineering"}
    assert {g["name"]: g["dynamic"] for g in out["groups"]}["Everyone (dynamic)"] is True
    assert next(u for u in out["users"] if u["id"] == "u-1")["department"] == "Finance"
    assert all("raw call to zidentity's public api" in n.lower() and "assumed" in n for n in out["raw_calls"])


# ── zid_user_edit ──────────────────────────────────────────────────────

def test_edit_sends_the_user_as_read_with_only_the_changed_fields_and_undo_puts_them_back(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle: the PUT carries every UserRecord field as read and only display name and department changed; read back; Undo restores."""
    c = client()
    spec = {"type": ou.T_EDIT, "id": "u-1", "set": {"display_name": "Avery Q. Quinn", "department": {"id": "d-2", "name": "Engineering"}}}
    p, r = apply(c, spec)
    assert p["confirm_phrase"] == ""      # two field changes: no typed phrase needed (the default rule)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == r["verification"]["checked"] == 2
    puts = [s for s in c.tenant.sent if s[0] == "PUT"]
    assert puts == [("PUT", "zid/users/u-1", {"loginName": "avery@acme.example", "displayName": "Avery Q. Quinn", "primaryEmail": "avery@acme.example",
                                              "status": True, "department": {"id": "d-2", "name": "Engineering"}})]
    ao.record(r, by=ASSESSOR, actor="alice")
    inv = r["inverse"]
    assert inv["undo"] is True and ao.is_undo_only(inv) and inv["set"] == {"display_name": "Avery Quinn", "department": {"id": "d-1", "name": "Finance"}}
    _p2, r2 = apply(c, inv)
    assert r2["status"] == "applied"
    row = c.tenant.zid_users["u-1"]
    assert row["displayName"] == "Avery Quinn" and row["department"] == {"id": "d-1", "name": "Finance"}
    audit = [json.loads(x) for x in (isolated / "audit.log").read_text(encoding="utf-8").splitlines() if x.strip()]
    assert any(e.get("event") == "admin_operation" and e.get("actor") == "alice" for e in audit)


def test_the_email_is_edited_as_primary_email_and_undo_puts_it_back():
    """ASVS V1.4.1 · CWE-841: payload oracle: the PUT carries primaryEmail changed and every other field as read; read back; Undo restores the email."""
    c = client()
    p, r = apply(c, {"type": ou.T_EDIT, "id": "u-1", "set": {"primary_email": "avery.quinn@acme.example"}})
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1
    put = [s for s in c.tenant.sent if s[0] == "PUT"][0][2]
    assert put["primaryEmail"] == "avery.quinn@acme.example" and put["loginName"] == "avery@acme.example" and put["displayName"] == "Avery Quinn"
    assert r["inverse"]["set"] == {"primary_email": "avery@acme.example"}
    _p2, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and c.tenant.zid_users["u-1"]["primaryEmail"] == "avery@acme.example"


@pytest.mark.parametrize("email", ["", "not-an-address", "a b@acme.example", "<x>@acme.example", "x@acme", "x@@acme.example", "x" * 250 + "@acme.example"])
def test_a_bad_email_is_refused_before_anything_is_read(email):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an empty, malformed or oversized email is refused before any read or write."""
    c = client()
    with pytest.raises(ao.OperationError, match="one address like"):
        ao.plan(c, {"type": ou.T_EDIT, "id": "u-1", "set": {"primary_email": email}}, scope=ZID)
    assert c.tenant.sent == []


def test_clearing_the_department_drops_it_from_the_put():
    """ASVS V5.1.3 · CWE-20: an empty department clears it; the PUT carries no department."""
    c = client()
    _p, r = apply(c, {"type": ou.T_EDIT, "id": "u-1", "set": {"department": None}})
    assert r["status"] == "applied" and "department" not in [s for s in c.tenant.sent if s[0] == "PUT"][0][2]


def test_group_changes_need_edit_login_typed_and_undo_reverses_them():
    """ASVS V4.1.3 · CWE-862: adding or removing a group grants or takes access, so EDIT <login> is typed; Undo makes the opposite change."""
    c = client()
    spec = {"type": ou.T_EDIT, "id": "u-1", "groups": {"add": ["g-2"], "remove": ["g-1"]}}
    p = ao.plan(c, spec, scope=ZID)
    assert p["confirm_phrase"] == "EDIT AVERY@ACME.EXAMPLE"
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=ASSESSOR, confirm_text="yes")
    assert r["status"] == "refused" and not [s for s in c.tenant.sent if s[0] in ("POST", "DELETE")]
    _p, r = apply(c, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 2
    assert ("POST", "zid/groups/g-2/users/u-1", {}) in c.tenant.sent and ("DELETE", "zid/groups/g-1/users/u-1", {}) in c.tenant.sent
    assert r["inverse"]["groups"] == {"add": ["g-1"], "remove": ["g-2"]}
    _p, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and "u-1" in c.tenant.zid_members["g-1"] and "u-1" not in c.tenant.zid_members["g-2"]


def test_a_dynamic_group_is_refused_and_admins_and_scim_users_are_left_alone():
    """ASVS V4.1.3 · CWE-284: a dynamic group's rule decides membership; administrators and SCIM users are changed elsewhere."""
    c = client()
    p = ao.plan(c, {"type": ou.T_EDIT, "id": "u-2", "groups": {"add": ["g-dyn"]}}, scope=ZID)
    assert p["status"] == "nothing_to_do" or p["counts"]["change"] == 0
    assert [u["reason"] for u in p["items"] if u["kind"] == "zid_user_group"][0].startswith("a dynamic group")
    for uid in ("u-3", "u-4"):
        p = ao.plan(c, {"type": ou.T_EDIT, "id": uid, "set": {"display_name": "X"}}, scope=ZID)
        assert p["counts"]["change"] == 0 and p["items"][0]["status"] == "excluded"
    assert not [s for s in c.tenant.sent if s[0] in ("POST", "PUT", "DELETE")]


def test_a_user_changed_after_the_preview_is_not_overwritten():
    """ASVS V11.1.4 · CWE-367: a change in ZIdentity since the preview gives plan_changed; nothing is sent."""
    c = client()
    spec = {"type": ou.T_EDIT, "id": "u-1", "set": {"display_name": "New"}}
    p = ao.plan(c, spec, scope=ZID)
    c.tenant.zid_users["u-1"]["displayName"] = "Someone else's edit"
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=ASSESSOR)
    assert r["status"] == "plan_changed" and not [s for s in c.tenant.sent if s[0] == "PUT"]


@pytest.mark.parametrize("bad", [{"set": {"login_name": "x@y.z"}}, {"set": {"display_name": ""}}, {"set": {"display_name": "a\x00b"}},
                                 {"set": {"display_name": "x" * 300}}, {"groups": {"add": ["g-1"], "remove": ["g-1"]}}, {},
                                 {"set": {"department": "Finance"}}, {"groups": {"add": [f"g{i}" for i in range(30)]}}])
def test_bad_edits_are_refused_before_anything_is_read(bad):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unknown fields, an empty or oversized name, control characters, a group both ways, nothing to do: 400."""
    c = client()
    with pytest.raises(ao.OperationError):
        ao.plan(c, dict({"type": ou.T_EDIT, "id": "u-1"}, **bad), scope=ZID)
    assert c.tenant.sent == []


# ── zid_user_reset (raw calls) ─────────────────────────────────────────

def test_the_sdk_still_has_no_password_or_mfa_call_so_the_raw_call_is_needed():
    """ASVS V1.14.1 · CWE-1104: the installed SDK has no password or MFA method; the raw paths follow the published reference exactly."""
    from zscaler.zid.users import UsersAPI
    assert not [m for m in dir(UsersAPI) if "password" in m.lower() or "mfa" in m.lower()]
    assert ou.action_path("u-1", "reset_password") == "/ziam/admin/api/v1/users/u-1:resetpassword"
    assert ou.action_path("u-1", "skip_mfa") == "/ziam/admin/api/v1/users/u-1:setskipmfa"
    assert ou.action_body("skip_mfa", now=1730000000.9) == {"timestamp": 1730000000} and ou.action_body("reset_password") == {}
    for bad in ("../u-1", "u-1/x", "u:1", "u 1", ""):
        with pytest.raises(ValueError):
            ou.action_path(bad, "reset_password")
    with pytest.raises(ValueError):
        ou.action_path("u-1", "updatepassword")
    assert "RAW CALLS" in ou.__doc__ and "ASSUMED" in ou.__doc__


def test_reset_needs_reset_login_typed_and_the_named_assessor():
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: no assessor, no write mode or the wrong phrase sends nothing; RESET <login> is the phrase."""
    c = client()
    spec = {"type": ou.T_RESET, "id": "u-1", "action": "reset_password"}
    p = ao.plan(c, spec, scope=ZID)
    assert p["confirm_phrase"] == "RESET AVERY@ACME.EXAMPLE" and p["status"] == "ready"
    assert any("Cannot be undone" in w for w in p["warnings"]) and any("raw call to ZIdentity's public API" in n for n in p["notes"])
    with pytest.raises(ao.OperationError, match="assessor"):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor="  ", confirm_text=p["confirm_phrase"])
    with pytest.raises(PermissionError):
        ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=False, assessor=ASSESSOR, confirm_text=p["confirm_phrase"])
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=ASSESSOR, confirm_text="RESET rowan@acme.example")
    assert r["status"] == "refused"
    assert not [s for s in c.tenant.sent if s[0] == "POST"]


def test_reset_sends_the_published_raw_call_once_and_the_temporary_password_reaches_no_sink(isolated, caplog):
    """ASVS V2.5.2 · CWE-532 · CWE-312: payload oracle for POST /users/{id}:resetpassword; a temporary password answered is in no plan, result, log, audit or record, and is revealed once to its owner."""
    import pack_ops as ops
    c = client()
    c.tenant.reset_answer = {"temporaryPassword": CANARY_PW}
    spec = {"type": ou.T_RESET, "id": "u-1", "action": "reset_password"}
    logs = []
    caplog.set_level(logging.DEBUG)
    with ops.audit_scope(actor="alice"):
        p, r = apply(c, spec)
    assert r["status"] == "applied"
    raw = [s for s in c.tenant.sent if s[0] == "POST"]
    assert raw == [("POST", "/ziam/admin/api/v1/users/u-1:resetpassword", {})]     # once: never retried
    assert r["inverse"] is None
    rec = ao.record(r, by=ASSESSOR, actor="alice")
    tok = r["one_time_secrets"][0]["token"]
    assert CANARY_PW not in sinks(isolated, p, r, rec, extra=caplog.text + "".join(logs))
    assert oz.reveal(tok, actor="mallory") is None
    got = oz.reveal(tok, actor="alice")
    assert got == {"name": "avery@acme.example", "secret": CANARY_PW}
    assert oz.reveal(tok, actor="alice") is None
    # After the one reveal it is still in no result, job log, audit entry or record.
    assert CANARY_PW not in sinks(isolated, p, r, rec, extra=caplog.text)


def test_a_plain_reset_answer_still_never_lands_in_a_log():
    """ASVS V7.1.1 · CWE-532: a reset answered with a bare string is treated as possibly secret: stashed, not logged."""
    c = client()
    c.tenant.reset_answer = CANARY_PW
    _p, r = apply(c, {"type": ou.T_RESET, "id": "u-1", "action": "reset_password"})
    assert r["status"] == "applied" and CANARY_PW not in json.dumps(r, default=str) and r["one_time_secrets"]


def test_skip_mfa_sends_the_timestamp_body_and_cannot_be_undone(monkeypatch):
    """ASVS V2.8.1 · CWE-308: payload oracle for POST /users/{id}:setskipmfa with SkipMfaDto {timestamp}; a warning says it weakens sign-in; no Undo."""
    monkeypatch.setattr(ou.time, "time", lambda: 1730000000.0)
    c = client()
    p, r = apply(c, {"type": ou.T_RESET, "id": "u-1", "action": "skip_mfa"})
    assert any("weakens" in w for w in p["warnings"]) and p["confirm_phrase"] == "RESET AVERY@ACME.EXAMPLE"
    assert r["status"] == "applied" and r["inverse"] is None and "one_time_secrets" not in r
    assert [s for s in c.tenant.sent if s[0] == "POST"] == [("POST", "/ziam/admin/api/v1/users/u-1:setskipmfa", {"timestamp": 1730000000})]


def test_a_refused_raw_call_is_reported_failed_in_words():
    """ASVS V7.4.1 · CWE-755: ZIdentity refusing the action marks it failed with the reason; nothing is stashed."""
    c = client()
    c.tenant.refuse[("raw", "resetpassword")] = '{"status": 400, "message": "password policy"}'
    _p, r = apply(c, {"type": ou.T_RESET, "id": "u-1", "action": "reset_password"})
    assert r["status"] in ("failed", "nothing_applied") and r["items"][0]["status"] == "failed" and not r.get("one_time_secrets")


def test_reset_leaves_admins_and_scim_users_alone_and_a_changed_user_is_not_reset():
    """ASVS V4.1.3 · CWE-367: administrators and SCIM users are excluded; a user changed since the preview gives plan_changed and no POST."""
    c = client()
    for uid in ("u-3", "u-4"):
        p = ao.plan(c, {"type": ou.T_RESET, "id": uid, "action": "reset_password"}, scope=ZID)
        assert p["counts"]["change"] == 0 and p["items"][0]["status"] == "excluded"
    spec = {"type": ou.T_RESET, "id": "u-2", "action": "skip_mfa"}
    p = ao.plan(c, spec, scope=ZID)
    c.tenant.zid_users["u-2"]["status"] = False
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZID, writes_enabled=True, assessor=ASSESSOR, confirm_text=p["confirm_phrase"])
    assert r["status"] == "plan_changed" and not [s for s in c.tenant.sent if s[0] == "POST"]


def test_a_user_id_unsafe_in_a_path_is_refused_before_any_read():
    """ASVS V5.3.4 · CWE-74 · WSTG-INPV-12: an id with ':' or '.' cannot reach the raw path; refused before anything is read."""
    c = client()
    for uid in ("u:1", "u..1"):
        with pytest.raises(ao.OperationError):
            ao.plan(c, {"type": ou.T_RESET, "id": uid, "action": "reset_password"}, scope=ZID)
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": ou.T_RESET, "id": "u-1", "action": "update_password"}, scope=ZID)
    assert c.tenant.reads == []
