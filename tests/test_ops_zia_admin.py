"""Day-to-day ZIA admin on the Bulk changes engine: users, groups and
departments (ops_zia_directory) and hosted PAC files (ops_zia_pac).

Every test runs against the stateful fake in tests/admin_identity_fake.py
(the SDK 1.11.3 method names, arguments, models and answers; each write's
wire body as the SDK would send it): no network, no clock, state files in
tmp_path. Payload oracles compare each body with the SDK model's own
request_format keys."""
from __future__ import annotations

import inspect
import json
import os
import sys

import pytest
from conftest import read_store_text

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zia_directory as od  # noqa: E402
import ops_zia_pac as op  # noqa: E402
import pack_channels as pc  # noqa: E402
from admin_identity_fake import PAC_V2, Client, Tenant  # noqa: E402
from zscaler.zia.models.pac_files import PacFiles  # noqa: E402
from zscaler.zia.models.user_management import Department, Groups, UserManagement  # noqa: E402

ZIA = ao.scope_for(["zia_extras"], {})
NO_ZIA = ao.scope_for(["zcc", "zidentity", "zpa"], {})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()
    return acts


def plan(c, spec, scope=ZIA):
    return ao.plan(c, spec, scope=scope, tenant_label="acme")


def apply(c, spec, *, phrase=None, prepared=None):
    p = prepared or plan(c, spec)
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZIA, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") or "" if phrase is None else phrase)
    return p, r


def model_keys(model) -> set:
    return set(model({}).request_format()) | set(model().request_format())


EDIT = {"type": "zia_directory", "changes": [
    {"kind": "user", "action": "edit", "id": 41, "groups_add": [34], "groups_remove": [33], "department": 23},
    {"kind": "group", "action": "create", "name": "Contractors", "comments": "temporary staff"},
    {"kind": "user", "action": "create", "name": "Sam Lee", "email": "sam@acme.example", "department": 21, "groups": [31, 32]}]}


# ── registration and scope ──────────────────────────────────────────────

def test_both_types_are_registered_as_day_to_day_admin_with_their_form():
    """ASVS V1.14.1 · CWE-1059: the users and PAC types are on the shared engine, grouped as Day-to-day admin, with a page script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in ("zia_directory", "zia_pac"):
        assert cat[t]["product"] == "zia" and cat[t]["group"] == "Day-to-day admin" and cat[t]["script"] == "ops_zia_admin.js"
    js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_zia_admin.js"), encoding="utf-8").read()
    assert "type: 'zia_directory'" in js and "type: 'zia_pac'" in js


@pytest.mark.parametrize("spec", [EDIT, {"type": "zia_pac", "action": "validate", "content": PAC_V2}])
def test_out_of_scope_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZIA platform ticked the plan, the apply and the picker are refused and nothing is read."""
    c = Client()
    with pytest.raises(ao.OperationError, match="ZIA platform"):
        plan(c, spec, NO_ZIA)
    with pytest.raises(ao.OperationError):
        ao.execute(c, spec, plan_hash="0" * 64, scope=NO_ZIA, writes_enabled=True, assessor=ASSESSOR)
    with pytest.raises(ao.OperationError):
        ao.read_objects(c, ao.PLUGINS[spec["type"]]["family"], NO_ZIA)
    assert c.tenant.reads == [] and c.tenant.sent == []


@pytest.mark.parametrize("change, match", [
    ({"kind": "user", "action": "disable", "id": 41}, "not possible"),
    ({"kind": "user", "action": "create", "name": "x", "email": "not-an-email", "department": 21}, "email"),
    ({"kind": "user", "action": "create", "name": "x\u0007", "email": "x@acme.example", "department": 21}, "control character"),
    ({"kind": "user", "action": "edit", "id": "41; DROP"}, "ZIA id"),
    ({"kind": "user", "action": "edit", "id": 41}, "must change"),
    ({"kind": "user", "action": "edit", "id": 41, "groups_add": [31], "groups_remove": [31]}, "added and removed"),
    ({"kind": "role", "action": "create", "name": "x"}, "Unknown kind"),
])
def test_a_bad_change_is_refused_before_anything_is_read(change, match):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a change the API cannot take (a disable, a bad email, a control character, a bad id, an empty edit) is a 400 before any read."""
    c = Client()
    with pytest.raises(ao.OperationError, match=match):
        plan(c, {"type": "zia_directory", "changes": [change]})
    assert c.tenant.reads == []


def test_more_than_100_changes_is_refused():
    """ASVS V11.1.4 · CWE-770: one plan takes at most 100 changes."""
    with pytest.raises(ao.OperationError, match="At most 100"):
        plan(Client(), {"type": "zia_directory", "changes": [{"kind": "group", "action": "create", "name": f"g{i}"} for i in range(101)]})


# ── users, groups and departments ──────────────────────────────────────

def test_the_preview_reads_only_and_lists_every_item_before_and_after():
    """ASVS V11.1.1 · CWE-1188: the preview writes nothing and shows each field before and after, by name."""
    c = Client()
    p = plan(c, EDIT)
    assert c.tenant.writes() == [] and p["status"] == "ready" and p["counts"]["change"] == 5
    rows = {(u["object"]["name"], u["field"], u.get("value")): (u["before"], u["after"]) for u in p["items"]}
    assert rows[("Avery Quinn", "department", None)] == ("Finance", "Engineering")
    assert rows[("Avery Quinn", "group", "Developers")] == ("not a member", "member")
    assert rows[("Avery Quinn", "group", "Finance Team")] == ("member", "not a member")
    assert rows[("Sam Lee", "exists", "department Operations; groups All Staff, Drivers")] == (False, True)
    assert p["confirm_phrase"] == "" and p["needs_activation"] is True


@pytest.mark.parametrize("change, why", [
    ({"kind": "user", "action": "edit", "id": 43, "groups_add": [31]}, "admin account"),
    ({"kind": "user", "action": "delete", "id": 43}, "admin account"),
    ({"kind": "group", "action": "delete", "id": 35}, "identity provider"),
    ({"kind": "group", "action": "edit", "id": 36, "name": "x"}, "predefined"),
])
def test_admins_predefined_and_identity_provider_objects_are_left_alone(change, why):
    """ASVS V4.1.3 · CWE-269 · CWE-284: admin accounts, predefined groups and IdP groups are excluded with the reason; nothing is written."""
    c = Client()
    p = plan(c, {"type": "zia_directory", "changes": [change]})
    assert p["counts"]["change"] == 0 and p["items"][0]["status"] == "excluded" and why in p["items"][0]["reason"]


def test_apply_sends_sdk_shaped_bodies_activates_once_and_reads_back(isolated):
    """ASVS V5.1.3 · V11.1.1 · CWE-20: each body has only fields of the SDK model (or of the user as read), never a password; one activation; every item read back."""
    c = Client()
    p, r = apply(c, EDIT)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 5 and isolated == [1]
    sent = {(s[0], s[1]): s[-1] for s in c.tenant.writes()}
    group_body, user_body = sent[("POST", "groups")], sent[("POST", "users")]
    assert set(group_body) <= model_keys(Groups) and group_body == {"name": "Contractors", "comments": "temporary staff"}
    assert set(user_body) <= model_keys(UserManagement) and "password" not in user_body
    assert user_body["department"] == {"id": 21, "name": "Operations"} and [g["id"] for g in user_body["groups"]] == [31, 32]
    put = sent[("PUT", "users")]
    assert set(put) <= model_keys(UserManagement) | {"authMethods"} and "password" not in put and "id" not in put
    assert put["authMethods"] == ["BASIC"], "a PUT replaces the user: fields the model drops are sent back as read"
    assert put["department"]["id"] == 23 and sorted(g["id"] for g in put["groups"]) == [34]


def test_every_write_goes_through_the_shared_audited_path(monkeypatch, isolated):
    """ASVS V7.1.3 · CWE-778: each write is a pack_ops.call with one object_write audit entry carrying the actor."""
    import pack_ops as ops
    seen, audits = [], []
    real_call, real_audit = ops.call, ops._audit_write
    monkeypatch.setattr(ops, "call", lambda fn, *a, **k: seen.append(k["kind"]) or real_call(fn, *a, **k))
    monkeypatch.setattr(ops, "_audit_write", lambda *a, **k: audits.append(a[:2]) or real_audit(*a, **k))
    with ops.audit_scope(actor="alice"):
        apply(Client(), EDIT)
    assert sorted(seen) == ["zia_group", "zia_user", "zia_user"] and sorted(a[1] for a in audits) == sorted(seen)
    log = read_store_text(os.environ["DLP_CHECK_AUDIT"])
    assert log.count('"event":"object_write"') == 3 and '"actor":"alice"' in log


def test_a_delete_needs_its_name_typed_and_says_it_cannot_be_undone():
    """ASVS V11.1.1 · CWE-841 · CWE-1188: a delete asks DELETE <name> whatever the count; blank or wrong text writes nothing; the preview says it cannot be undone."""
    c = Client()
    spec = {"type": "zia_directory", "changes": [{"kind": "department", "action": "delete", "id": 24}]}
    p = plan(c, spec)
    assert p["confirm_phrase"] == "DELETE CUSTOMER SERVICE" and any("cannot be undone" in w for w in p["warnings"])
    assert "Cannot be undone" in p["items"][0]["reason"]
    for wrong in ("", "APPLY 1 CHANGES", "DELETE CUSTOMER", "DELETE CUSTOMER SERVİCE"):
        _p, r = apply(c, spec, phrase=wrong, prepared=p)
        assert r["status"] == "refused", wrong
    assert c.tenant.writes() == []
    _p, r = apply(c, spec, phrase="delete customer service", prepared=p)
    assert r["status"] == "applied" and "24" not in c.tenant.zia["departments"] and r["inverse"] is None


def test_several_deletes_ask_the_count():
    """ASVS V11.1.1 · CWE-841: two deletes ask DELETE 2 OBJECTS."""
    p = plan(Client(), {"type": "zia_directory", "changes": [{"kind": "user", "action": "delete", "id": 42},
                                                             {"kind": "group", "action": "delete", "id": 32}]})
    assert p["confirm_phrase"] == "DELETE 2 OBJECTS"


def test_undo_deletes_what_was_created_and_puts_edits_back():
    """ASVS V11.1.1 · CWE-840: the inverse is an Undo-only form; applied, it deletes the created user and group and restores Avery's department and groups."""
    c = Client()
    _p, r = apply(c, EDIT)
    inv = r["inverse"]
    assert ao.is_undo_only(inv) and inv["action"] == "undo"
    p2, r2 = apply(c, inv)
    assert p2["confirm_phrase"] == "DELETE 2 OBJECTS" and r2["status"] == "applied"
    avery = c.tenant.zia["users"]["41"]
    assert avery["department"]["id"] == 22 and [g["id"] for g in avery["groups"]] == [33]
    assert "Contractors" not in [g["name"] for g in c.tenant.zia["groups"].values()]
    assert "Sam Lee" not in [u["name"] for u in c.tenant.zia["users"].values()]


def test_a_tenant_that_moved_after_the_preview_gets_nothing_written():
    """ASVS V11.1.6 · CWE-367: a user changed between preview and apply changes the plan hash: plan_changed, no write."""
    c = Client()
    p = plan(c, EDIT)
    c.tenant.zia["users"]["41"]["groups"] = []
    _p, r = apply(c, EDIT, prepared=p)
    assert r["status"] == "plan_changed" and c.tenant.writes() == []


def test_a_user_changed_right_before_its_write_is_a_conflict(monkeypatch):
    """ASVS V11.1.6 · CWE-367: the re-read right before the PUT finds someone else's change: the item is a conflict, never overwritten."""
    c = Client()
    spec = {"type": "zia_directory", "changes": [EDIT["changes"][0]]}
    p = plan(c, spec)
    real = od._get
    calls = {"n": 0}

    def moved(client, kind, oid):
        calls["n"] += 1
        if calls["n"] == 2:   # the handler's re-read (the first is the re-plan)
            c.tenant.zia["users"]["41"]["comments"] = "changed by someone else"
        return real(client, kind, oid)
    monkeypatch.setattr(od, "_get", moved)
    _p, r = apply(c, spec, prepared=p)
    assert {u["status"] for u in r["items"]} == {"conflict"} and c.tenant.writes() == []


def test_write_mode_off_refuses_before_reading():
    """ASVS V4.1.3 · CWE-1188: write mode off refuses the apply before anything is read."""
    c = Client()
    with pytest.raises(PermissionError):
        ao.execute(c, EDIT, plan_hash="0" * 64, scope=ZIA, writes_enabled=False, assessor=ASSESSOR)
    assert c.tenant.reads == []


def test_the_picker_searches_users_by_name_and_lists_groups_and_departments():
    """ASVS V11.1.4 · CWE-400: the picker reads users by ZIA's name search (never the whole directory), with groups, departments and what is not possible."""
    c = Client()
    out = ao.read_objects(c, od.FAMILY, ZIA, query="row")
    assert [u["name"] for u in out["users"]] == ["Rowan Ellis"] and out["query"] == "row"
    assert any(r[1] == "users" and r[2].get("name") == "row" for r in c.tenant.reads)
    assert {g["name"] for g in out["groups"]} >= {"All Staff", "Okta Engineering"} and len(out["departments"]) == 4
    assert next(g for g in out["groups"] if g["name"] == "Okta Engineering")["locked"]
    assert any("not possible" in n for n in out["not_possible"])
    long_q = ao.read_objects(Client(), od.FAMILY, ZIA, query="x" * 500)
    assert len(long_q["query"]) == 100


def test_a_reader_without_a_query_parameter_is_called_as_before(monkeypatch):
    """ASVS V1.14.1 · CWE-1059: the engine hands the search only to a reader that takes it; other readers keep their four parameters."""
    got = []
    monkeypatch.setitem(ao.PLUGIN_FAMILIES, od.FAMILY, dict(ao.PLUGIN_FAMILIES[od.FAMILY], read_objects=lambda c, s, say, cancel: got.append(1) or {}))
    ao.read_objects(Client(), od.FAMILY, ZIA, query="abc")
    assert got == [1] and ao._takes_query(od.read_objects) and not ao._takes_query(lambda c, s, say, cancel: None)


# ── PAC files ──────────────────────────────────────────────────────────

NEW_TEXT = PAC_V2.replace('return "PROXY', 'if (shExpMatch(host, "*.partner.example")) { return "DIRECT"; }\n  return "PROXY')


def test_validate_writes_nothing_and_reports_both_checks_and_the_diff():
    """ASVS V5.2.4 · CWE-94: validate parses the PAC without running it and asks ZIA's validator; no change item, no write."""
    c = Client()
    p = plan(c, {"type": "zia_pac", "action": "validate", "pac_id": 61, "content": NEW_TEXT})
    assert p["status"] == "nothing_to_do" and c.tenant.writes() == []
    assert p["pac_check"]["local"]["ok"] and p["pac_check"]["local"]["has_function"] and "*.partner.example" in p["pac_check"]["local"]["direct"]
    assert p["pac_check"]["zia"]["success"] is True
    assert p["diff"]["added"] == 1 and p["diff"]["removed"] == 0 and any(x.startswith("+") and "partner" in x for x in p["diff"]["lines"])


def test_a_pac_is_never_run_even_when_it_loops_forever():
    """ASVS V5.2.4 · V12.3.1 · CWE-94 · CWE-835: a PAC with a loop is reported as outside the parsed subset, quickly; nothing executes it."""
    import time
    looping = "function FindProxyForURL(url, host) { while (true) {} return 'DIRECT'; }"
    started = time.monotonic()
    p = plan(Client(), {"type": "zia_pac", "action": "validate", "content": looping})
    assert time.monotonic() - started < 5
    assert p["pac_check"]["local"]["ok"] is False and "could not evaluate safely" in p["pac_check"]["local"]["error"]
    src = open(op.__file__, encoding="utf-8").read()
    assert "eval(" not in src and "subprocess" not in src and "js2py" not in src and "quickjs" not in src


def test_zias_validator_refusing_the_pac_blocks_the_plan():
    """ASVS V5.1.3 · CWE-20: a PAC ZIA's validator refuses is a blocker, with ZIA's line and message."""
    p = plan(Client(), {"type": "zia_pac", "action": "new_version", "pac_id": 61, "version": 2, "content": PAC_V2 + "\nSYNTAX ERROR"})
    assert p["status"] == "blocked" and any("line 3" in b for b in p["blockers"])


@pytest.mark.parametrize("content, match", [("x" * (op.MAX_CONTENT + 1), "longer than"), ("function FindProxyForURL(u,h){}\x00", "control character"),
                                            ("   ", "Paste")])
def test_oversized_or_binary_pac_text_is_refused_before_anything_is_read(content, match):
    """ASVS V5.1.3 · V12.1.1 · CWE-400 · CWE-20: PAC text over 256 KB, with a control character, or empty is a 400 before any read."""
    c = Client()
    with pytest.raises(ao.OperationError, match=match):
        plan(c, {"type": "zia_pac", "action": "validate", "content": content})
    assert c.tenant.reads == []


def test_a_new_version_is_staged_with_the_sdks_clone_arguments_and_cannot_be_undone(isolated):
    """ASVS V5.1.3 · V11.1.1 · CWE-1188: a new version goes in STAGED (nothing uses it), through clone_pac_file's own arguments; the preview says Undo is not possible."""
    c = Client()
    spec = {"type": "zia_pac", "action": "new_version", "pac_id": 61, "version": 2, "content": NEW_TEXT, "commit_message": "partner direct"}
    p, r = apply(c, spec)
    assert any("Cannot be undone" in w for w in p["warnings"]) and p["items"][0]["after"] == "STAGE"
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and r["inverse"] is None and isolated == [1]
    post = next(s for s in c.tenant.writes() if s[1] == "pacFiles/61/version/2")
    assert post[2] == {"pacContent": NEW_TEXT, "pacVerificationStatus": "VERIFY_NOERR", "pacCommitMessage": "partner direct", "pacVersionStatus": "STAGE"}
    import zscaler.zia.pac_files as sdk_pac
    params = set(inspect.signature(sdk_pac.PacFilesAPI.clone_pac_file).parameters)
    assert {"pac_content", "pac_version_status", "pac_verification_status", "pac_commit_message"} <= params
    assert [v["pacVersionStatus"] for v in c.tenant.pac if v["pacVersion"] == 3] == ["STAGE"]


def test_switching_the_active_version_is_undone_by_switching_back():
    """ASVS V11.1.1 · CWE-840: deploy switches the active version, shows the diff, and its Undo deploys the version that was active."""
    c = Client()
    p, r = apply(c, {"type": "zia_pac", "action": "deploy", "pac_id": 61, "version": 1})
    assert p["items"][0]["before"] == 2 and p["items"][0]["after"] == 1 and p["diff"]["removed"] >= 1
    assert r["status"] == "applied" and r["inverse"] == {"type": "zia_pac", "action": "deploy", "pac_id": "61", "version": 2}
    put = next(s for s in c.tenant.writes() if s[0] == "PUT")
    assert put[1] == "pacFiles/61/version/1/action/DEPLOY" and set(put[2]) <= model_keys(PacFiles) and put[2]["pacContent"].startswith("function")
    _p2, r2 = apply(c, r["inverse"])
    assert r2["status"] == "applied" and next(v for v in c.tenant.pac if v["pacVersionStatus"] == "DEPLOYED")["pacVersion"] == 2


def test_create_and_clone_make_a_new_file_from_model_fields_and_undo_deletes_it():
    """ASVS V5.1.3 · V11.1.1 · CWE-840: create sends only PacFiles fields; clone copies a version's text; each Undo is an Undo-only delete asking the name typed."""
    c = Client()
    _p, r = apply(c, {"type": "zia_pac", "action": "create", "name": "branch.pac", "domain": "acme.example", "content": NEW_TEXT, "description": "branches"})
    body = next(s for s in c.tenant.writes() if s[:2] == ("POST", "pacFiles"))[2]
    assert set(body) <= model_keys(PacFiles) and body["pacVersionStatus"] == "DEPLOYED" and body["pacContent"] == NEW_TEXT
    inv = r["inverse"]
    assert ao.is_undo_only(inv) and inv["delete"]["name"] == "branch.pac"
    p2 = plan(c, inv)
    assert p2["confirm_phrase"] == "DELETE BRANCH.PAC"
    _p, r2 = apply(c, inv, prepared=p2)
    assert r2["status"] == "applied" and not [v for v in c.tenant.pac if v["name"] == "branch.pac"]
    _p, r3 = apply(c, {"type": "zia_pac", "action": "clone", "pac_id": 61, "version": 1, "name": "copy.pac", "domain": "acme.example"})
    made = [v for v in c.tenant.pac if v["name"] == "copy.pac"]
    assert r3["status"] == "applied" and made[0]["pacContent"] == c.tenant.pac[0]["pacContent"] and "Cloned from corp.pac version 1" in made[0]["pacCommitMessage"]


def test_deleting_a_pac_file_needs_its_name_typed_and_cannot_be_undone():
    """ASVS V11.1.1 · CWE-841: delete asks DELETE <name>; the preview says it cannot be undone; there is no inverse."""
    c = Client()
    p = plan(c, {"type": "zia_pac", "action": "delete", "pac_id": 61})
    assert p["confirm_phrase"] == "DELETE CORP.PAC" and any("Cannot be undone" in w for w in p["warnings"])
    _p, r = apply(c, {"type": "zia_pac", "action": "delete", "pac_id": 61}, phrase="", prepared=p)
    assert r["status"] == "refused" and c.tenant.writes() == []
    _p, r = apply(c, {"type": "zia_pac", "action": "delete", "pac_id": 61}, prepared=p)
    assert r["status"] == "applied" and c.tenant.pac == [] and r["inverse"] is None


def test_versions_that_moved_since_the_preview_write_nothing():
    """ASVS V11.1.6 · CWE-367: a version added by someone else between preview and apply changes the plan: nothing is written."""
    c = Client()
    spec = {"type": "zia_pac", "action": "new_version", "pac_id": 61, "version": 2, "content": NEW_TEXT}
    p = plan(c, spec)
    c.tenant.pac[1]["pacContent"] = PAC_V2 + "// edited in the portal\n"
    _p, r = apply(c, spec, prepared=p)
    assert r["status"] == "plan_changed" and c.tenant.writes() == []


def test_the_picker_lists_files_versions_and_text_without_running_it():
    """ASVS V5.3.3 · CWE-79: the picker carries each file's versions and the active text as data (the page sets it as text)."""
    out = ao.read_objects(Client(), op.FAMILY, ZIA)
    f = out["pac_files"][0]
    assert f["name"] == "corp.pac" and f["version"] == 2 and [v["version"] for v in f["versions"]] == [1, 2] and f["content"] == PAC_V2
    assert "never run" in out["never_run"]
    js = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_zia_admin.js"), encoding="utf-8").read()
    assert "view.textContent = f.content" in js and "s.textContent = line" in js and "innerHTML = f.content" not in js


def test_the_sample_tenant_takes_a_users_change_through_the_real_sdk(monkeypatch, tmp_path):
    """ASVS V5.1.3 · CWE-20: on the in-memory sample tenant the real SDK services carry the change; the stored body has only UserManagement fields."""
    import offline_tenant as ot
    st = ot.sample_store(reset=True)
    try:
        c = ot.client_for(ot.creds_for(st), "sdk")
        spec = {"type": "zia_directory", "changes": [{"kind": "user", "action": "edit", "id": 41, "groups_add": [34], "department": 23}]}
        _p, r = apply(c, spec)
        assert r["status"] == "applied" and r["verification"]["confirmed"] == 2
        row = next(u for u in st.responses["/zia/api/v1/users"]["body"] if u["id"] == 41)
        assert set(row) <= model_keys(UserManagement) | {"id"} and row["department"]["id"] == 23
    finally:
        ot.sample_store(reset=True)
