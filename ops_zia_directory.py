"""ZIA users, groups and departments: day-to-day admin on the Bulk changes engine.

One operation type on the shared engine (admin_ops.register), so every
change takes the same path as any bulk change: the scope check before
anything is read (ZIA platform ticked on the Scope page), a plan that only
reads, the plan hash, the re-plan before writing, write mode, the writer,
the named assessor and the confirmation, a re-read of each object right
before its write (a change made meanwhile is a conflict and is skipped),
one ZIA activation, the read-back, the record, the audit log with the actor,
and Undo where one exists.

  zia_directory   up to MAX_CHANGES changes, each one of
                  user        create (name, email, department, groups),
                              edit (department, groups added or removed,
                              comments), delete
                  group       create, edit (name, comments), delete
                  department  create, edit (name, comments), delete

A delete asks its own typed confirmation every time ("DELETE <name>", or
"DELETE <n> OBJECTS" for several) and cannot be undone: the preview says so.
Undo of a create deletes what was created (an Undo-only form, applied only
as the Undo of its recorded operation); Undo of an edit puts the fields back.

What is left alone, with the reason in the preview: admin accounts (change
them in the ZIA Admin Portal), predefined groups, and groups or departments
that come from the identity provider (SCIM or SAML: the next sync would put
them back). No password is ever set: a hosted-database user gets one from
the ZIA Admin Portal.

Not possible: disabling a ZIA user. The installed SDK's user model
(zscaler/zia/models/user_management.py, UserManagement.request_format) has
no enabled, disabled or status field, so the API offers no switch to send;
delete is the only way to stop an account here.

SDK calls, verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zia/user_management.py, service client.zia.user_management):
list_users (query name, dept, group, page, page_size), get_user, add_user,
update_user (PUT /users/{id}: the whole user, so the body is the user as
read with the change), delete_user, list_groups / list_departments (search,
page, page_size <= 1000), get_group / get_department, add_group /
add_department, update_group / update_department, delete_group /
delete_department. ASSUMED (not checkable without a tenant): that ZIA
refuses a second user with the same email (the preview's own check reads
users by name only), that a group or department PUT accepts name and
comments with the other fields as read, and that a missing object answers
404 on its get.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import pack_ops as ops

TYPE = "zia_directory"
FAMILY = "zia_directory_objects"
SCRIPT = "ops_zia_admin.js"
MAX_CHANGES = 100
MAX_GROUPS_PER_USER = 100
PAGE = 1000
MAX_PAGES = 10            # groups and departments: up to 10 000 each
MAX_USER_ROWS = 2000      # the picker's user list (a search narrows it)
MAX_QUERY = 100
KINDS = ("user", "group", "department")
ACTIONS = ("create", "edit", "delete")
LABEL = {"user": "ZIA user", "group": "ZIA group", "department": "ZIA department"}
OP_KIND = {"user": "zia_user", "group": "zia_group", "department": "zia_department"}
ADMIN_TYPES = {"SUPERADMIN", "ADMIN", "AUDITOR", "REPORT_USER"}
NOT_IN_SCOPE = ("Not in scope: users, groups and departments are ZIA platform objects; tick ZIA platform on the Scope page. "
                "Nothing was read.")
NO_DISABLE = ("Disabling a ZIA user is not possible through the API: the installed Zscaler SDK's user model has no enabled or "
              "status field. Delete the user here, or block sign-in at the identity provider.")
NO_UNDO_DELETE = ("Cannot be undone: a deleted {what} is gone from ZIA, with its id. Undo does not bring it back; "
                  "it would have to be created again by hand.")
IDP_NOTE = "comes from the identity provider (SCIM or SAML): change it there, or the next sync puts it back"
_ID = re.compile(r"^[0-9]{1,19}$")
_EMAIL = re.compile(r"^[^@\s<>\"'`]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")

LogFn = Callable[[str], None]


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def _svc(client: Any) -> Any:
    zia = getattr(client, "zia", None)
    svc = getattr(zia, "user_management", None) if zia is not None else None
    if svc is None:
        raise ao.OperationError("This sign-in has no ZIA user management service (zscaler-sdk-python user_management), so nothing was read.")
    return svc


def plain(obj: Any) -> Any:
    """An SDK model or answer as plain data with snake_case keys."""
    import pack_export
    if isinstance(obj, list):
        return [plain(x) for x in obj]
    if isinstance(obj, dict):
        return {pack_export._snake(k): plain(v) for k, v in obj.items()}
    as_dict = getattr(obj, "as_dict", None)
    if callable(as_dict):
        try:
            return plain(as_dict())
        except Exception:  # noqa: BLE001 — an odd model is read as empty, never a crash
            return {}
    return obj


def _err(e: Any) -> str:
    return str(e)[:300] if not isinstance(e, BaseException) else f"{type(e).__name__}: {str(e)[:250]}"


def raw_body(data: Any, resp: Any) -> Any:
    """The answer as the API sent it when the response has it, else the SDK's
    model: some 1.11.3 models drop fields a read needs (a resource server's
    scopes, a user's fields a PUT must send back)."""
    getter = getattr(resp, "get_body", None)
    if callable(getter):
        try:
            body = getter()
        except Exception:  # noqa: BLE001 — the model still answers
            body = None
        if isinstance(body, (dict, list)):
            return body
    return data


def _call(fn: Callable[..., Any], *a: Any, **k: Any) -> Tuple[Any, Optional[str]]:
    """(the answer, error) of one SDK read; never raises."""
    try:
        ret = fn(*a, **k)
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return None, _err(e)
    if isinstance(ret, tuple):
        data, err = (ret[0], ret[2]) if len(ret) >= 3 else (ret[0], ret[1] if len(ret) > 1 else None)
        if err:
            return None, _err(err)
        return raw_body(data, ret[1] if len(ret) >= 3 else None), None
    return ret, None


def _paged(fn: Callable[..., Any], params: Dict[str, Any], cap_rows: int, cancel: Optional[threading.Event]) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
    """Every page of a list call, PAGE rows at a time, up to cap_rows: (rows, error, truncated)."""
    out: List[Dict[str, Any]] = []
    for page in range(1, MAX_PAGES + 1):
        ao._check_stop(cancel)
        data, err = _call(fn, query_params=dict(params, page=page, page_size=PAGE))
        if err:
            return out, err, False
        rows = [r for r in (plain(data) or []) if isinstance(r, dict)]
        out.extend(rows)
        if len(out) >= cap_rows:
            return out[:cap_rows], None, True
        if len(rows) < PAGE:
            return out, None, False
    return out, None, True


def is_missing(err: Optional[str]) -> bool:
    low = str(err or "").lower()
    return "404" in low or "not found" in low or "not_found" in low or "does not exist" in low


def _rid(v: Any) -> str:
    return "" if v in (None, "") else str(v)


def _ref(row: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not isinstance(row, dict) or row.get("id") in (None, ""):
        return None
    return {"id": row.get("id"), "name": str(row.get("name") or "")}


def user_state(row: Dict[str, Any]) -> Dict[str, Any]:
    """What a change compares: department, groups (ids) and comments."""
    dept = row.get("department") if isinstance(row.get("department"), dict) else None
    return {"department": _rid((dept or {}).get("id")), "groups": sorted({_rid(g.get("id")) for g in row.get("groups") or [] if isinstance(g, dict)} - {""}),
            "comments": str(row.get("comments") or ""), "name": str(row.get("name") or ""), "email": str(row.get("email") or "")}


def is_admin(row: Dict[str, Any]) -> bool:
    return ao._truthy(row.get("admin_user")) or str(row.get("type") or "").upper() in ADMIN_TYPES


def user_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    st = user_state(row)
    dept = row.get("department") if isinstance(row.get("department"), dict) else {}
    return {"id": _rid(row.get("id")), "name": st["name"], "email": st["email"], "department": str((dept or {}).get("name") or ""),
            "department_id": st["department"], "groups": [str(g.get("name") or g.get("id")) for g in row.get("groups") or [] if isinstance(g, dict)],
            "group_ids": st["groups"], "comments": st["comments"],
            "locked": "an admin account: change it in the ZIA Admin Portal" if is_admin(row) else ""}


def group_summary(kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": _rid(row.get("id")), "name": str(row.get("name") or ""), "comments": str(row.get("comments") or ""),
            "locked": lock_reason(kind, row) or ""}


def lock_reason(kind: str, row: Dict[str, Any]) -> Optional[str]:
    if kind == "group" and ao._truthy(row.get("is_system_defined")):
        return "a predefined group: ZIA keeps it as it is"
    if kind == "department" and ao._truthy(row.get("deleted")):
        return "marked deleted in ZIA"
    if row.get("idp_id") not in (None, "", 0, "0"):
        return IDP_NOTE
    return None


def read_lists(client: Any, cancel: Optional[threading.Event], say: LogFn) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str], Dict[str, bool]]:
    svc = _svc(client)
    out: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    cut: Dict[str, bool] = {}
    for kind, fn in (("group", svc.list_groups), ("department", svc.list_departments)):
        say(f"Reading the ZIA {kind}s…")
        rows, err, truncated = _paged(fn, {}, PAGE * MAX_PAGES, cancel)
        out[kind] = rows
        cut[kind] = truncated
        if err:
            errors[f"zia_{kind}s"] = err
    return out, errors, cut


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event], query: str = "") -> Dict[str, Any]:
    """The picker: users (by name, or the first MAX_USER_ROWS), every group and
    department, read-only. `query` searches users by name (ZIA: starts with)."""
    q = _query(query)
    lists, errors, cut = read_lists(client, cancel, say)
    say("Reading the ZIA users" + (f" whose name starts with '{q}'…" if q else "…"))
    users, err, users_cut = _paged(_svc(client).list_users, {"name": q} if q else {}, MAX_USER_ROWS, cancel)
    if err:
        errors["zia_users"] = err
    return {"users": [user_summary(u) for u in sorted(users, key=lambda r: str(r.get("name") or "").lower())],
            "users_truncated": users_cut, "query": q,
            "groups": [group_summary("group", g) for g in sorted(lists["group"], key=lambda r: str(r.get("name") or "").lower())],
            "departments": [group_summary("department", d) for d in sorted(lists["department"], key=lambda r: str(r.get("name") or "").lower())],
            "truncated": {k: v for k, v in cut.items() if v}, "errors": errors, "not_possible": [NO_DISABLE],
            "limits": {"changes": MAX_CHANGES, "user_rows": MAX_USER_ROWS}}


def _query(raw: Any) -> str:
    q = str(raw or "").strip()[:MAX_QUERY]
    if ao._has_control(q):
        raise ao.OperationError("The search contains a control character.")
    return q


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not _ID.match(s):
        raise ao.OperationError(f"{what} must be a ZIA id (digits only).")
    return s


def _ids(v: Any, what: str) -> List[str]:
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise ao.OperationError(f"'{what}' must be a list of ids.")
    if len(v) > MAX_GROUPS_PER_USER:
        raise ao.OperationError(f"At most {MAX_GROUPS_PER_USER} groups in '{what}'.")
    return sorted({_id(x, what) for x in v})


def _text(v: Any, what: str, limit: int = 255, required: bool = False) -> Optional[str]:
    if v is None:
        if required:
            raise ao.OperationError(f"The {what} is required.")
        return None
    s = ao._object_name(v, what) if limit == 255 else str(v).strip()
    if limit != 255 and (ao._has_control(s.replace("\n", " ").replace("\t", " ")) or len(s) > limit):
        raise ao.OperationError(f"The {what} must be at most {limit} characters with no control character.")
    if required and not s:
        raise ao.OperationError(f"The {what} is required.")
    return s


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The spec in its one accepted shape, or OperationError (the 400)."""
    action = str(spec.get("action") or "").strip().lower()
    undo = action == "undo"
    if action not in ("", "undo"):
        raise ao.OperationError("'action' is only used by Undo.")
    raw = ao._list_field(spec, "changes", objects=True, cap=MAX_CHANGES)
    if not raw:
        raise ao.OperationError("Add at least one change.")
    out: List[Dict[str, Any]] = []
    for c in raw:
        kind = str(c.get("kind") or "").strip().lower()
        act = str(c.get("action") or "").strip().lower()
        if kind not in KINDS:
            raise ao.OperationError(f"Unknown kind '{str(kind)[:20]}': use user, group or department.")
        if act == "disable" and kind == "user":
            raise ao.OperationError(NO_DISABLE)
        if act not in ACTIONS:
            raise ao.OperationError(f"Unknown action '{str(act)[:20]}': use create, edit or delete.")
        n: Dict[str, Any] = {"kind": kind, "action": act}
        if act != "create":
            n["id"] = _id(c.get("id"), f"The {kind} to {act}")
        if kind == "user":
            if act == "create":
                n["name"] = _text(c.get("name"), "user name", required=True)
                email = str(c.get("email") or "").strip()
                if not _EMAIL.match(email) or len(email) > 254:
                    raise ao.OperationError("The user's email must look like name@domain (the domain must belong to the organisation).")
                n["email"] = email
                n["department"] = _id(c.get("department"), "The user's department")
                n["groups"] = _ids(c.get("groups"), "groups")
                n["comments"] = _text(c.get("comments") or "", "comments", limit=10240) or ""
            elif act == "edit":
                if c.get("department") not in (None, ""):
                    n["department"] = _id(c.get("department"), "The new department")
                n["groups_add"] = _ids(c.get("groups_add"), "groups_add")
                n["groups_remove"] = _ids(c.get("groups_remove"), "groups_remove")
                if set(n["groups_add"]) & set(n["groups_remove"]):
                    raise ao.OperationError("A group cannot be added and removed in the same change.")
                if c.get("comments") is not None:
                    n["comments"] = _text(c.get("comments"), "comments", limit=10240)
                if not (n.get("department") or n["groups_add"] or n["groups_remove"] or "comments" in n):
                    raise ao.OperationError("An edit must change the department, the groups or the comments.")
        else:
            if act == "create":
                n["name"] = _text(c.get("name"), f"{kind} name", required=True)
                n["comments"] = _text(c.get("comments") or "", "comments", limit=10240) or ""
            elif act == "edit":
                if c.get("name") is not None:
                    n["name"] = _text(c.get("name"), f"{kind} name", required=True)
                if c.get("comments") is not None:
                    n["comments"] = _text(c.get("comments"), "comments", limit=10240)
                if "name" not in n and "comments" not in n:
                    raise ao.OperationError(f"An edit of a {kind} must change its name or comments.")
        out.append(n)
    keys = [(c["kind"], c.get("id")) for c in out if c.get("id")]
    if len(keys) != len(set(keys)):
        raise ao.OperationError("Each existing object may appear once per operation.")
    spec_out: Dict[str, Any] = {"type": TYPE, "changes": out}
    if undo:
        spec_out["action"] = "undo"
    return spec_out


# ---------------------------------------------------------------------------
# Planning (reads only)
# ---------------------------------------------------------------------------

def _get(client: Any, kind: str, oid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    svc = _svc(client)
    fn = {"user": svc.get_user, "group": svc.get_group, "department": svc.get_department}[kind]
    data, err = _call(fn, oid)
    if err:
        return None, err
    row = plain(data)
    return (row if isinstance(row, dict) and row else None), (None if row else "no answer")


def _names(rows: Sequence[Dict[str, Any]]) -> Dict[str, str]:
    return {_rid(r.get("id")): str(r.get("name") or "") for r in rows}


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    lists, errors, _cut = read_lists(client, cancel, say)
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers = [f"Could not read the {k.replace('zia_', '').rstrip('s')}s: {v}" for k, v in errors.items()]
    gname, dname = _names(lists["group"]), _names(lists["department"])
    by_id = {"group": {_rid(r.get("id")): r for r in lists["group"]}, "department": {_rid(r.get("id")): r for r in lists["department"]}}
    deletes: List[str] = []
    order = {("create", "group"): 0, ("create", "department"): 0, ("edit", "group"): 1, ("edit", "department"): 1,
             ("create", "user"): 2, ("edit", "user"): 3, ("delete", "user"): 4, ("delete", "group"): 5, ("delete", "department"): 5}
    for i, c in sorted(enumerate(n["changes"]), key=lambda ic: (order[(ic[1]["action"], ic[1]["kind"])], ic[0])):
        ao._check_stop(cancel)
        kind, act, key = c["kind"], c["action"], f"c{i}"
        obj = {"type": OP_KIND[kind], "kind": kind, "policy_label": LABEL[kind], "name": c.get("name") or c.get("id")}
        if act == "create":
            plan_create(client, c, key, obj, lists, gname, dname, items, groups, warnings, cancel)
            continue
        if kind in ("group", "department") and c["id"] in by_id[kind]:
            row: Optional[Dict[str, Any]] = by_id[kind][c["id"]]
            err = None
        else:
            row, err = _get(client, kind, c["id"])
        if row is None:
            halt = ao._read_halt(err)
            if halt:
                blockers.append(halt)
                break
            items.append(ao._unit(key, key, OP_KIND[kind], dict(obj, id=c["id"]), "exists", None, None, status="excluded" if act == "edit" else "noop",
                                  reason=f"not found in ZIA ({err})" if act == "edit" else "already gone"))
            continue
        obj.update(id=c["id"], name=str(row.get("name") or c["id"]))
        lock = ("an admin account: change it in the ZIA Admin Portal" if kind == "user" and is_admin(row) else
                lock_reason(kind, row) if kind != "user" else None)
        if lock:
            items.append(ao._unit(key, key, OP_KIND[kind], obj, "exists" if act == "delete" else "fields", None, None, status="excluded", reason=lock))
            continue
        if act == "delete":
            target = {"kind": kind, "action": "delete", "id": c["id"], "name": obj["name"],
                      "before": user_state(row) if kind == "user" else {"name": obj["name"]}}
            if kind == "user":
                obj["email"] = str(row.get("email") or "")
            groups.append({"key": key, "handler": "zia_dir_write", "target": target})
            items.append(ao._unit(key, key, OP_KIND[kind], obj, "exists", True, False,
                                  reason=NO_UNDO_DELETE.format(what=kind) if n.get("action") != "undo" else "Undo deletes what the operation created"))
            deletes.append(obj["name"])
            if kind != "user":
                warnings.append(f"Rules and users that name the {kind} '{obj['name']}' lose it when it is deleted: check them first.")
            continue
        if kind == "user":
            plan_user_edit(c, key, obj, row, gname, dname, items, groups)
        else:
            changed = [(f, str(row.get(f) or ""), c[f]) for f in ("name", "comments") if f in c and str(row.get(f) or "") != c[f]]
            if not changed:
                items.append(ao._unit(key, key, OP_KIND[kind], obj, "fields", None, None, status="noop", reason="already as asked"))
                continue
            if "name" in c and any(_rid(r.get("id")) != c["id"] and str(r.get("name") or "").lower() == c["name"].lower()
                                   for r in lists[kind]):
                items.append(ao._unit(key, key, OP_KIND[kind], obj, "name", row.get("name"), c["name"], status="excluded",
                                      reason=f"another {kind} is already named '{c['name']}'"))
                continue
            groups.append({"key": key, "handler": "zia_dir_write",
                           "target": {"kind": kind, "action": "edit", "id": c["id"], "name": obj["name"],
                                      "before": {f: b for f, b, _a in changed}, "after": {f: a for f, _b, a in changed}}})
            for f, b, a in changed:
                items.append(ao._unit(f"{key}:{f}", key, OP_KIND[kind], obj, f, b, a))
    confirm = None
    if deletes:
        confirm = f"DELETE {deletes[0]}" if len(deletes) == 1 and len(deletes[0]) <= 60 and deletes[0].isprintable() else f"DELETE {len(deletes)} OBJECTS"
        warnings.insert(0, f"This deletes {len(deletes)} object{'s' if len(deletes) != 1 else ''}; type {confirm.upper()} to confirm. "
                           + ("Undo deletes only what the recorded operation created." if n.get("action") == "undo" else
                              "A delete cannot be undone."))
    title = "Undo a ZIA users and groups change" if n.get("action") == "undo" else "ZIA users, groups and departments"
    return {"type": TYPE, "product": "zia", "title": title, "spec": n, "items": items, "groups": groups, "warnings": warnings,
            "blockers": blockers, "confirm_always": confirm,
            "notes": ["No password is set or read here; admin accounts, predefined groups and identity-provider groups are left alone.",
                      NO_DISABLE]}


def plan_create(client: Any, c: Dict[str, Any], key: str, obj: Dict[str, Any], lists: Dict[str, List[Dict[str, Any]]],
                gname: Dict[str, str], dname: Dict[str, str], items: List[Dict[str, Any]], groups: List[Dict[str, Any]],
                warnings: List[str], cancel: Optional[threading.Event]) -> None:
    kind = c["kind"]
    if kind != "user":
        if any(str(r.get("name") or "").lower() == c["name"].lower() for r in lists[kind]):
            items.append(ao._unit(key, key, OP_KIND[kind], obj, "exists", True, True, status="noop", reason=f"a {kind} with this name exists"))
            return
        groups.append({"key": key, "handler": "zia_dir_write", "target": {"kind": kind, "action": "create", "name": c["name"], "comments": c["comments"]}})
        items.append(ao._unit(key, key, OP_KIND[kind], obj, "exists", False, True, value=c["comments"] or None))
        return
    obj["email"] = c["email"]
    missing = [g for g in c["groups"] if g not in gname]
    if c["department"] not in dname or missing:
        what = (["the department " + c["department"]] if c["department"] not in dname else []) + [f"the group {g}" for g in missing]
        items.append(ao._unit(key, key, "zia_user", obj, "exists", False, True, status="excluded",
                              reason=f"{', '.join(what)} is not in ZIA (create it in an earlier change first)"))
        return
    same, err = _paged(_svc(client).list_users, {"name": c["name"]}, 200, cancel)[:2]
    if any(str(u.get("email") or "").lower() == c["email"].lower() for u in same):
        items.append(ao._unit(key, key, "zia_user", obj, "exists", True, True, status="noop", reason="a user with this email exists"))
        return
    if err:
        warnings.append(f"Could not check that the email {c['email']} is new ({err}); ZIA refuses a duplicate.")
    desc = f"department {dname[c['department']]}" + (f"; groups {', '.join(gname[g] for g in c['groups'])}" if c["groups"] else "")
    groups.append({"key": key, "handler": "zia_dir_write",
                   "target": {"kind": "user", "action": "create", "name": c["name"], "email": c["email"], "comments": c["comments"],
                              "department": {"id": int(c["department"]), "name": dname[c["department"]]},
                              "groups": [{"id": int(g), "name": gname[g]} for g in c["groups"]]}})
    items.append(ao._unit(key, key, "zia_user", obj, "exists", False, True, value=desc))


def plan_user_edit(c: Dict[str, Any], key: str, obj: Dict[str, Any], row: Dict[str, Any], gname: Dict[str, str], dname: Dict[str, str],
                   items: List[Dict[str, Any]], groups: List[Dict[str, Any]]) -> None:
    st = user_state(row)
    names = dict(gname)
    names.update({_rid(g.get("id")): str(g.get("name") or "") for g in row.get("groups") or [] if isinstance(g, dict)})
    units: List[Dict[str, Any]] = []
    bad = [g for g in c["groups_add"] if g not in gname]
    if c.get("department") and c["department"] not in dname:
        bad.append("department " + c["department"])
    if bad:
        items.append(ao._unit(key, key, "zia_user", obj, "fields", None, None, status="excluded", reason=f"not in ZIA: {', '.join(bad)}"))
        return
    if c.get("department") and c["department"] != st["department"]:
        dept = row.get("department") if isinstance(row.get("department"), dict) else {}
        units.append(ao._unit(f"{key}:department", key, "zia_user", obj, "department", str((dept or {}).get("name") or st["department"] or "none"),
                              dname[c["department"]]))
    for g in c["groups_add"]:
        status = "noop" if g in st["groups"] else "change"
        units.append(ao._unit(f"{key}:g+{g}", key, "zia_user", obj, "group", "member" if status == "noop" else "not a member", "member",
                              value=names.get(g, g), status=status, reason="already a member" if status == "noop" else ""))
    for g in c["groups_remove"]:
        status = "change" if g in st["groups"] else "noop"
        units.append(ao._unit(f"{key}:g-{g}", key, "zia_user", obj, "group", "member" if status == "change" else "not a member", "not a member",
                              value=names.get(g, g), status=status, reason="" if status == "change" else "not a member"))
    if "comments" in c and c["comments"] != st["comments"]:
        units.append(ao._unit(f"{key}:comments", key, "zia_user", obj, "comments", st["comments"], c["comments"]))
    if not any(u["status"] == "change" for u in units):
        items.extend(units or [ao._unit(key, key, "zia_user", obj, "fields", None, None, status="noop", reason="already as asked")])
        return
    want = {"department": c.get("department") or st["department"],
            "groups": sorted((set(st["groups"]) | set(c["groups_add"])) - set(c["groups_remove"])),
            "comments": c["comments"] if "comments" in c else st["comments"]}
    groups.append({"key": key, "handler": "zia_dir_write",
                   "target": {"kind": "user", "action": "edit", "id": c["id"], "name": obj["name"], "before": st,
                              "want": want, "names": {g: names.get(g, "") for g in want["groups"]},
                              "department_name": dname.get(want["department"], "")}})
    items.extend(units)


# ---------------------------------------------------------------------------
# Payloads (snake_case: the SDK sends them camelCase)
# ---------------------------------------------------------------------------

def create_payload(t: Dict[str, Any]) -> Dict[str, Any]:
    """The add_user / add_group / add_department body: only fields the SDK's model knows."""
    if t["kind"] == "user":
        return {"name": t["name"], "email": t["email"], "comments": t["comments"], "department": dict(t["department"]),
                "groups": [dict(g) for g in t["groups"]]}
    return {"name": t["name"], "comments": t["comments"]}


_DROP = ("id", "password")


def user_update_payload(fresh: Dict[str, Any], t: Dict[str, Any]) -> Dict[str, Any]:
    """The user as read (a PUT replaces it) with the planned department, groups
    and comments; never a password."""
    body = {k: v for k, v in fresh.items() if k not in _DROP and v is not None}
    want = t["want"]
    body["department"] = {"id": int(want["department"]), "name": t.get("department_name") or ""} if want["department"] else None
    if body["department"] is None:
        body.pop("department")
    body["groups"] = [{"id": int(g), "name": t["names"].get(g, "")} for g in want["groups"]]
    body["comments"] = want["comments"]
    return body


def group_update_payload(fresh: Dict[str, Any], t: Dict[str, Any]) -> Dict[str, Any]:
    body = {k: v for k, v in fresh.items() if k not in _DROP and v is not None}
    body.update(t["after"])
    return body


# ---------------------------------------------------------------------------
# The write handler (pack_ops.call: pacing, retries, Stop, audit)
# ---------------------------------------------------------------------------

def _write(run: Any, fn: Callable[..., Any], *args: Any, op: str, kind: str, name: str, kw: Optional[Dict[str, Any]] = None,
           exists: Optional[Callable[[], Any]] = None) -> ops.Outcome:
    out = ops.call(fn, *args, op=op, kind=kind, name=name, log=run.log, kw=kw, zia=run.zia, exists=exists)
    ops._audit_write(op, kind, out.id if op == "create" else (args[0] if args else None), name, None, out)
    return out


def _halt_or_fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _find_user_by_email(run: Any, name: str, email: str) -> Callable[[], Any]:
    def check() -> Any:
        rows, err, _ = _paged(_svc(run.client).list_users, {"name": name}, 200, None)
        if err:
            raise RuntimeError(err)
        hit = next((r for r in rows if str(r.get("email") or "").lower() == email.lower()), None)
        return hit.get("id") if hit else None
    return check


def h_write(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind, act = t["kind"], t["action"]
    svc = _svc(run.client)
    op_kind = OP_KIND[kind]
    if act == "create":
        fn = {"user": svc.add_user, "group": svc.add_group, "department": svc.add_department}[kind]
        exists = _find_user_by_email(run, t["name"], t["email"]) if kind == "user" else None
        out = _write(run, fn, op="create", kind=op_kind, name=t["name"], kw=create_payload(t), exists=exists)
        if run.outcome(units, out, "create"):
            run.wrote_zia = True
            oid = str(out.id or "")
            for u in units:
                u["object"] = dict(u["object"], id=oid)
            run.created.append({"type": op_kind, "kind": kind, "id": oid, "name": t["name"]})
            run.log(f"[{LABEL[kind]}] {t['name']}: created")
        return
    fresh, err = _get(run.client, kind, t["id"])
    if fresh is None:
        if is_missing(err) and act == "delete":
            run.mark(units, "noop", "already gone")
            return
        _halt_or_fail(run, units, err, f"the {kind} '{t['name']}'")
        return
    if act == "delete":
        before = t["before"]
        now = user_state(fresh) if kind == "user" else {"name": str(fresh.get("name") or "")}
        if now != before:
            run.mark(units, "conflict", f"the {kind} changed in ZIA since the preview; it was not deleted")
            run.counts["skipped"] += len(units)
            return
        fn = {"user": svc.delete_user, "group": svc.delete_group, "department": svc.delete_department}[kind]
        out = _write(run, fn, t["id"], op="delete", kind=op_kind, name=t["name"])
        if run.outcome(units, out, "delete"):
            run.wrote_zia = True
            run.log(f"[{LABEL[kind]}] {t['name']}: deleted")
        return
    if kind == "user":
        if user_state(fresh) != t["before"]:
            run.mark(units, "conflict", "the user changed in ZIA since the preview; left as it is")
            run.counts["skipped"] += len(units)
            return
        payload = user_update_payload(fresh, t)
        out = _write(run, svc.update_user, t["id"], op="update", kind=op_kind, name=t["name"], kw=payload)
    else:
        if any(str(fresh.get(f) or "") != b for f, b in t["before"].items()):
            run.mark(units, "conflict", f"the {kind} changed in ZIA since the preview; left as it is")
            run.counts["skipped"] += len(units)
            return
        fn = svc.update_group if kind == "group" else svc.update_department
        out = _write(run, fn, t["id"], op="update", kind=op_kind, name=t["name"], kw=group_update_payload(fresh, t))
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[{LABEL[kind]}] {t['name']}: changed")


HANDLERS = {"zia_dir_write": h_write}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for u in run.p["items"]:
        if u["status"] == "applied":
            by_group.setdefault(u["group"], []).append(u)
    targets = {g["key"]: g["target"] for g in run.p["groups"]}
    for key, units in by_group.items():
        t = targets.get(key) or {}
        kind, oid = t.get("kind"), units[0]["object"].get("id")
        out["checked"] += len(units)
        row, err = _get(run.client, kind, str(oid)) if oid not in (None, "") else (None, "no id")
        if t.get("action") == "delete":
            ok = row is None and is_missing(err)
        elif row is None:
            for u in units:
                u["verified"] = None
            out["unread"].append(f"{t.get('name')}: {err}")
            out["checked"] -= len(units)
            continue
        elif t.get("action") == "create":
            ok = str(row.get("name") or "") == t["name"]
            if kind == "user":
                st = user_state(row)
                ok = ok and st["department"] == str(t["department"]["id"]) and st["groups"] == sorted(str(g["id"]) for g in t["groups"])
        elif kind == "user":
            st = user_state(row)
            ok = all(st[f] == v for f, v in t["want"].items())
        else:
            ok = all(str(row.get(f) or "") == v for f, v in t["after"].items())
        for u in units:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(units)
        else:
            out["mismatched"].append(f"{t.get('name')}: not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Deletes what was created and puts edited fields back. Deletes have no
    inverse (ZIA keeps no copy). An Undo-only form: applied only as the Undo
    of its recorded operation."""
    applied = {u["group"] for u in result.get("items") or [] if u.get("status") == "applied"}
    if not applied:
        return None
    changes: List[Dict[str, Any]] = []
    for g in result.get("groups") or []:
        t = g.get("target") or {}
        if g.get("key") not in applied:
            continue
        if t.get("action") == "edit" and t.get("kind") == "user":
            b, w = t["before"], t["want"]
            c: Dict[str, Any] = {"kind": "user", "action": "edit", "id": t["id"],
                                 "groups_add": sorted(set(b["groups"]) - set(w["groups"])), "groups_remove": sorted(set(w["groups"]) - set(b["groups"]))}
            if b["department"] and b["department"] != w["department"]:
                c["department"] = b["department"]
            if b["comments"] != w["comments"]:
                c["comments"] = b["comments"]
            changes.append(c)
        elif t.get("action") == "edit":
            changes.append(dict({"kind": t["kind"], "action": "edit", "id": t["id"]}, **t["before"]))
    for c in result.get("created") or []:
        if c.get("type") in OP_KIND.values() and c.get("id"):
            changes.append({"kind": c["kind"], "action": "delete", "id": str(c["id"])})
    if not changes:
        return None
    return {"type": TYPE, "action": "undo", "changes": changes}


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zia_extras" in (scope.get("scopes") or []) else NOT_IN_SCOPE


ao.register(TYPE, family=FAMILY, product="zia", label="ZIA users, groups and departments", group="Day-to-day admin",
            hint=("Find users by name and create, edit (department, groups, comments) or delete users, groups and departments; "
                  "a delete asks its name typed and cannot be undone. Needs ZIA platform ticked on the Scope page."),
            in_scope=in_scope, plan=plan, read_objects=read_objects, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT)
