"""One ZIdentity user: edit its attributes and groups, reset its password or
let it skip MFA, on the Bulk changes engine (admin_ops plugin).

Two operation types on /report/operations ("Day-to-day admin"), with the
path every bulk change takes: the scope check before anything is read
(ZIdentity ticked on the Scope page), a plan that only reads, the plan hash,
the re-plan before writing, write mode, the writer, the named assessor, the
typed confirmation, a re-read right before each write, the read-back where
ZIdentity lets one be made, the record, the audit log with the actor, and
Undo where one exists. ZIdentity saves each change at once (no activation).

  zid_user_edit   one user: display name, first and last name and
                  department (picked from the departments the directory's
                  users already carry, or cleared), and the ZIdentity groups
                  it is in (add or remove; dynamic groups are refused: their
                  rule decides). The user is sent back as read with only
                  those fields changed (PUT, SDK users.update_user); a group
                  change is the SDK's add_user_to_group or
                  remove_user_from_group. Undo puts every field and group
                  back. A group change needs "EDIT <login>" typed (membership
                  grants access).
  zid_user_reset  one user, one action: reset its password, or set "skip
                  MFA". Both need the named assessor and "RESET <login>"
                  typed, and cannot be undone. Any temporary password
                  ZIdentity answers is shown once, to the person who ran the
                  apply only (the single-use, ten-minute, in-memory store of
                  ops_zid: stash / reveal), and never put in a plan, a
                  result, a log, the audit log, the change record or an
                  export.

Administrators and users that come from SCIM are left alone by both
(ops_zid.user_lock): change them in the ZIdentity Admin Portal or the
identity provider.

SDK calls, verified against zscaler-sdk-python 1.11.3 (client.zid; base
/ziam/admin/api/v1): users.list_users, get_user, update_user (PUT
/users/{id}, the model's fields: login_name, display_name, first_name,
last_name, primary_email, secondary_email, status, department {id, name,
display_name}, idp, custom_attrs_info), list_user_group_details (GET
/users/{id}/groups); groups.list_groups, get_group, add_user_to_group (POST
/groups/{id}/users/{userId}), remove_user_from_group (DELETE the same path).

RAW CALLS (not in the SDK: zscaler-sdk-python 1.11.3 zid/users.py has no
password or MFA method; a test checks that on the installed SDK). Sent
through the SDK's own request executor for the ZIdentity service (the same
sign-in, base URL and retries policy the SDK uses), by zid_user_action()
below, and only from the write handler through pack_ops.call:

    POST /ziam/admin/api/v1/users/{id}:resetpassword   no body
    POST /ziam/admin/api/v1/users/{id}:setskipmfa      {"timestamp": <epoch seconds>}

Their path, method and body are taken from Zscaler's published ZIdentity API
reference (automate.zscaler.com, API reference → ZID → Users: "Users Ops
Reset Password": "Initiates a password reset for a specific user ID",
answers 200 with a string; "Users Ops Mfa": "Sets a flag to skip
Multi-Factor Authentication (MFA) for a specified user ID", body SkipMfaDto
{timestamp: int32, required, "the timestamp indicating when the MFA skip
action was set, usually represented in epoch time"}), as published on
2026-10-30. help.zscaler.com and automate.zscaler.com could not be reached
from this build machine, so ASSUMED (not verified against a live tenant):
that the colon form of the path is the one ZIdentity accepts; that the
timestamp is the current time in epoch seconds (ZIdentity's own setting
decides how long the skip lasts); that the reset's string answer may be a
temporary password (it is treated as one: shown once, never kept); that
neither action can be read back or reversed through the API.
"""
from __future__ import annotations

import re
import threading
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import ops_zid as oz
import pack_ops as ops

T_EDIT = "zid_user_edit"
T_RESET = "zid_user_reset"
FAMILY = "zid_user_admin"
PRODUCT = "zidentity"
SCRIPT = "ops_zid_user.js"
BASE = "/ziam/admin/api/v1"
MAX_GROUP_CHANGES = 25
MAX_GROUPS = 500
MAX_USERS = 2000
NAME_MAX = 255
RESET_ACTIONS = {"reset_password": "resetpassword", "skip_mfa": "setskipmfa"}
ACTION_WORDS = {"reset_password": "Reset the password", "skip_mfa": "Skip MFA"}
# A user id that goes into a raw path: letters, digits, _ and - only (no '.', ':' or '/').
_PATH_ID = re.compile(r"^[A-Za-z0-9_-]{1,80}$")
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
ATTRS = ("display_name", "first_name", "last_name", "department")
ATTR_WORDS = {"display_name": "Display name", "first_name": "First name", "last_name": "Last name", "department": "Department"}
NOT_IN_SCOPE = oz.NOT_IN_SCOPE
NO_UNDO_RESET = ("Cannot be undone: ZIdentity starts the password reset at once; the user's old password stops working and the user "
                 "must set a new one.")
NO_UNDO_MFA = ("Cannot be undone through the API: ZIdentity records that this user may skip MFA, for as long as ZIdentity's own "
               "setting allows; there is no call to clear it.")
RAW_NOTE = ("Sent as a raw request: the Zscaler SDK (1.11.3) has no call for it. Path and body follow Zscaler's published ZIdentity "
            "API reference (Users → {what}); not verified against a live tenant from this build (assumed).")
PASSWORD_ONCE = ("If ZIdentity answers with a temporary password, it is shown once, right after the apply, to you only; this app never "
                 "stores, logs or exports it.")

LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zidentity" in (scope.get("scopes") or []) else NOT_IN_SCOPE


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def _txt(v: Any, n: int = NAME_MAX) -> str:
    return "".join(ch for ch in ("" if v is None else str(v)) if ch.isprintable())[:n]


def dept_of(row: Dict[str, Any]) -> Optional[Dict[str, str]]:
    d = row.get("department")
    if not isinstance(d, dict) or d.get("id") in (None, ""):
        return None
    return {"id": _txt(d.get("id"), 80), "name": _txt(d.get("name") or d.get("display_name") or d.get("id"))}


def attrs_of(row: Dict[str, Any]) -> Dict[str, Any]:
    """The managed fields as the preview shows them."""
    d = dept_of(row)
    return {"display_name": _txt(row.get("display_name")), "first_name": _txt(row.get("first_name")), "last_name": _txt(row.get("last_name")),
            "department": d["name"] if d else ""}


def user_groups(svc: Any, uid: str) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """{group id: group name} the user is in (every page), or (None, why)."""
    out: Dict[str, str] = {}
    offset = 0
    for _ in range(10):
        data, err, _resp = oz._call(svc.users.list_user_group_details, uid, query_params={"limit": oz.LIMIT, "offset": offset})
        if err:
            return None, err
        rows = oz.records(data)
        for r in rows:
            if r.get("id") not in (None, ""):
                out[_txt(r.get("id"), 80)] = _txt(r.get("name") or r.get("id"))
        if len(rows) < oz.LIMIT:
            return out, None
        offset += oz.LIMIT
    return None, "more groups than this app reads for one user"


def get_group(svc: Any, gid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    data, err, _ = oz._call(svc.groups.get_group, gid)
    if err:
        return None, err
    rows = oz.records(data)
    return (rows[0] if rows else None), (None if rows else "no answer")


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event], query: str = "") -> Dict[str, Any]:
    """Users (searched by login name), the departments those users carry and
    the ZIdentity groups (name, id, dynamic) to pick from. Read-only."""
    import ops_zia_directory as od
    svc = oz.zid(client)
    q = od._query(query)
    errors: Dict[str, str] = {}
    say("Reading the ZIdentity users" + (f" whose login name contains '{q}'…" if q else "…"))
    users, err, cut = oz._paged(svc.users.list_users, {"login_name[like]": q} if q else {}, MAX_USERS, cancel)
    if err:
        errors["zidentity_users"] = err
    depts: Dict[str, str] = {}
    for u in users:
        d = dept_of(u)
        if d:
            depts[d["id"]] = d["name"]
    say("Reading the ZIdentity groups…")
    groups, gerr, _ = oz._paged(svc.groups.list_groups, {}, MAX_GROUPS, cancel)
    if gerr:
        errors["zidentity_groups"] = gerr
    return {"users": [dict(oz.user_summary(u), **attrs_of(u), department_id=(dept_of(u) or {}).get("id", ""))
                      for u in sorted(users, key=lambda r: str(r.get("login_name") or "").lower())],
            "users_truncated": cut, "query": q,
            "departments": [{"id": k, "name": v} for k, v in sorted(depts.items(), key=lambda kv: kv[1].lower())],
            "groups": sorted([{"id": _txt(g.get("id"), 80), "name": _txt(g.get("name") or g.get("id")), "dynamic": bool(g.get("is_dynamic_group")),
                               "source": _txt(g.get("source"), 20)} for g in groups if g.get("id") not in (None, "")], key=lambda g: g["name"].lower()),
            "errors": errors, "password_once": PASSWORD_ONCE, "limits": {"group_changes": MAX_GROUP_CHANGES},
            "raw_calls": [RAW_NOTE.format(what="Users Ops Reset Password"), RAW_NOTE.format(what="Users Ops Mfa")]}


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not _ID.match(s):
        raise ao.OperationError(f"{what} must be a ZIdentity id.")
    return s


def _name(v: Any, what: str, required: bool) -> str:
    s = " ".join(str(v if v is not None else "").split())
    if ao._has_control(s) or len(s) > NAME_MAX:
        raise ao.OperationError(f"The {what} must be at most {NAME_MAX} characters, with no control character.")
    if required and not s:
        raise ao.OperationError(f"The {what} cannot be empty.")
    return s


def normalize_edit(spec: Dict[str, Any]) -> Dict[str, Any]:
    n: Dict[str, Any] = {"type": T_EDIT, "id": _id(spec.get("id"), "The user")}
    want = spec.get("set") if isinstance(spec.get("set"), dict) else {}
    unknown = sorted(set(want) - set(ATTRS))
    if unknown:
        raise ao.OperationError(f"Only {', '.join(ATTRS)} can be changed here, not {', '.join(unknown[:3])}.")
    s: Dict[str, Any] = {}
    for f in ("display_name", "first_name", "last_name"):
        if f in want:
            # An Undo may put back an empty display name it found; an ordinary edit may not empty it.
            s[f] = _name(want[f], ATTR_WORDS[f].lower(), f == "display_name" and spec.get("undo") is not True)
    if "department" in want:
        d = want["department"]
        if d in (None, "", {}):
            s["department"] = None
        elif isinstance(d, dict):
            s["department"] = {"id": _id(d.get("id"), "The department"), "name": _name(d.get("name") or d.get("id"), "department name", True)}
        else:
            raise ao.OperationError("The department is {\"id\": ..., \"name\": ...} from the list, or empty to clear it.")
    n["set"] = s
    g = spec.get("groups") if isinstance(spec.get("groups"), dict) else {}
    add = sorted({_id(x, "A group") for x in ao._list_field(g, "add", cap=MAX_GROUP_CHANGES)})
    rem = sorted({_id(x, "A group") for x in ao._list_field(g, "remove", cap=MAX_GROUP_CHANGES)})
    if set(add) & set(rem):
        raise ao.OperationError("A group cannot be added and removed in the same change.")
    if len(add) + len(rem) > MAX_GROUP_CHANGES:
        raise ao.OperationError(f"At most {MAX_GROUP_CHANGES} group changes at once. Split it.")
    n["groups"] = {"add": add, "remove": rem}
    if not s and not add and not rem:
        raise ao.OperationError("Change at least one field or group.")
    if spec.get("undo") is True:
        n["undo"] = True
    return n


def normalize_reset(spec: Dict[str, Any]) -> Dict[str, Any]:
    act = str(spec.get("action") or "").strip().lower()
    if act not in RESET_ACTIONS:
        raise ao.OperationError("Pick what to do: reset_password or skip_mfa.")
    uid = _id(spec.get("id"), "The user")
    if not _PATH_ID.match(uid):
        raise ao.OperationError("This user's id cannot be put in a request path safely; reset it in the ZIdentity Admin Portal.")
    return {"type": T_RESET, "id": uid, "action": act}


# ---------------------------------------------------------------------------
# zid_user_edit
# ---------------------------------------------------------------------------

def _obj(row: Optional[Dict[str, Any]], uid: str) -> Dict[str, Any]:
    return {"type": "zid_user", "policy_label": "ZIdentity user", "id": uid, "name": _txt((row or {}).get("login_name") or uid)}


def _fingerprint(row: Dict[str, Any]) -> Dict[str, Any]:
    """What the conflict guard compares right before the write."""
    return dict(attrs_of(row), department_id=(dept_of(row) or {}).get("id", ""), status=oz._status(row.get("status")),
                login_name=_txt(row.get("login_name")))


def _blocked(t: str, title: str, n: Dict[str, Any], why: str) -> Dict[str, Any]:
    return {"type": t, "product": PRODUCT, "title": title, "spec": n, "items": [], "groups": [], "warnings": [], "blockers": [why],
            "apply_note": "ZIdentity applies each change as it is saved; there is no activation step."}


def plan_edit(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize_edit(spec)
    svc = oz.zid(client)
    uid = n["id"]
    say("Reading the user…")
    row, err = oz._get_user(svc, uid)
    title = "Undo a ZIdentity user edit" if n.get("undo") else "Edit a ZIdentity user"
    if row is None:
        return _blocked(T_EDIT, title, n, ao._read_halt(err) or f"The user {uid} could not be read: {err}.")
    obj = _obj(row, uid)
    login = obj["name"]
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    lock = oz.user_lock(row)
    if lock:
        items.append(ao._unit("user", "user", "zid_user", obj, "attributes", None, None, status="excluded", reason=lock))
        return {"type": T_EDIT, "product": PRODUCT, "title": f"{title}: {login}", "spec": n, "items": items, "groups": [], "warnings": [],
                "blockers": [], "apply_note": "ZIdentity applies each change as it is saved; there is no activation step."}
    cur = attrs_of(row)
    cur_dept = dept_of(row)
    changed: Dict[str, Any] = {}
    for f, v in n["set"].items():
        if f == "department":
            before, after = cur["department"], (v or {}).get("name", "")
            same = (cur_dept or {}).get("id") == (v or {}).get("id") if v else cur_dept is None
        else:
            before, after = cur[f], v
            same = before == after
        key = f"attr:{f}"
        if same:
            items.append(ao._unit(key, "user", "zid_user", obj, f, before, after, status="noop", reason="already as asked"))
        else:
            items.append(ao._unit(key, "user", "zid_user", obj, f, before, after))
            changed[f] = v
    if changed:
        groups.append({"key": "user", "handler": "zid_user_attrs",
                       "target": {"id": uid, "name": login, "set": changed, "before": _fingerprint(row),
                                  "undo_set": {f: (cur_dept if f == "department" else cur[f]) for f in changed}}})
    if n["groups"]["add"] or n["groups"]["remove"]:
        say("Reading the user's groups…")
        have, gerr = user_groups(svc, uid)
        if have is None:
            return _blocked(T_EDIT, f"{title}: {login}", n, ao._read_halt(gerr) or f"The groups of {login} could not be read: {gerr}.")
        for gid, want in [(g, True) for g in n["groups"]["add"]] + [(g, False) for g in n["groups"]["remove"]]:
            ao._check_stop(cancel)
            key = f"grp:{gid}"
            grow, gerr = get_group(svc, gid)
            gname = _txt((grow or {}).get("name") or have.get(gid) or gid)
            gobj = dict(obj, group=gid, group_name=gname)
            before = gid in have
            if grow is None:
                if ao._read_halt(gerr):
                    return _blocked(T_EDIT, f"{title}: {login}", n, str(ao._read_halt(gerr)))
                items.append(ao._unit(key, key, "zid_user_group", gobj, "member", before, want, status="excluded" if want else "noop",
                                      reason=f"the group could not be read ({gerr})" if want else "the group is gone"))
                continue
            if grow.get("is_dynamic_group"):
                items.append(ao._unit(key, key, "zid_user_group", gobj, "member", before, want, status="excluded",
                                      reason="a dynamic group: its rule decides who is in it"))
                continue
            if before is want:
                items.append(ao._unit(key, key, "zid_user_group", gobj, "member", before, want, status="noop",
                                      reason="already in the group" if want else "not in the group"))
                continue
            if want and not ao._truthy(row.get("status", True)):
                warnings.append(f"{login} is disabled: the group applies once the user is enabled.")
            if str(grow.get("source") or "").upper() in ("SCIM", "IDP", "SAML"):
                warnings.append(f"The group '{gname}' is synced from the identity provider: its next sync may undo this.")
            items.append(ao._unit(key, key, "zid_user_group", gobj, "member", before, want,
                                  reason="grants what the group is entitled to" if want else "takes away what the group is entitled to"))
            groups.append({"key": key, "handler": "zid_user_group", "target": {"id": uid, "name": login, "group": gid, "group_name": gname,
                                                                               "add": want}})
    group_change = any(g["handler"] == "zid_user_group" for g in groups)
    notes = [f"The user is sent back as read with only the changed fields (PUT {BASE}/users/{{id}}, SDK users.update_user).",
             "Undo puts every changed field and group back, previewed and confirmed like this change."]
    if group_change:
        notes.append(f"A group is changed with POST or DELETE {BASE}/groups/{{id}}/users/{{userId}} (SDK groups.add_user_to_group / "
                     "remove_user_from_group).")
    return {"type": T_EDIT, "product": PRODUCT, "title": f"{title}: {login}", "spec": n, "items": items, "groups": groups, "warnings": warnings,
            "blockers": [], "confirm_always": (f"EDIT {login}" if len(login) <= 60 else "EDIT USER") if group_change else "",
            "apply_note": "ZIdentity applies each change as it is saved; there is no activation step.", "notes": notes}


def edit_payload(fresh: Dict[str, Any], changes: Dict[str, Any]) -> Dict[str, Any]:
    """The user as read (the SDK model's fields) with the changed fields set."""
    body = {k: fresh[k] for k in oz._USER_PUT if fresh.get(k) is not None}
    for f, v in changes.items():
        if f == "department":
            if v:
                body["department"] = {"id": v["id"], "name": v["name"]}
            else:
                body.pop("department", None)
        else:
            body[f] = v
    return body


def h_attrs(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = oz.zid(run.client)
    fresh, err = oz._get_user(svc, t["id"])
    if fresh is None:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the user '{t['name']}'")
        return
    if _fingerprint(fresh) != t["before"] or oz.user_lock(fresh):
        oz._conflict(run, units, "the user changed in ZIdentity since the preview; left as it is")
        return
    out = oz._write(run, svc.users.update_user, t["id"], op="update", kind="zid_user", name=t["name"], kw=edit_payload(fresh, t["set"]), oid=t["id"])
    if run.outcome(units, out, "update"):
        run.log(f"[ZIdentity user] {t['name']}: {', '.join(ATTR_WORDS[f].lower() for f in t['set'])} changed")


def h_group(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = oz.zid(run.client)
    have, err = user_groups(svc, t["id"])
    if have is None:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the groups of '{t['name']}'")
        return
    now = t["group"] in have
    if now is t["add"]:
        run.mark(units, "noop", "already as asked (someone made the same change)")
        return
    fn = svc.groups.add_user_to_group if t["add"] else svc.groups.remove_user_from_group
    label = f"{t['group_name']}: user {t['id']}"
    out = oz._write(run, fn, t["group"], t["id"], op="update", kind="zid_group_member", name=label, oid=t["group"])
    if run.outcome(units, out, "update"):
        run.log(f"[ZIdentity] {t['group_name']}: {'added' if t['add'] else 'removed'} {t['name']}")


# ---------------------------------------------------------------------------
# zid_user_reset (raw calls: see the module docstring)
# ---------------------------------------------------------------------------

def action_path(user_id: str, action: str) -> str:
    """The raw path of one user action; ValueError for an id or action that is not allowed."""
    if not _PATH_ID.match(str(user_id or "")):
        raise ValueError("the user id is not safe in a request path; nothing was sent")
    verb = RESET_ACTIONS.get(action)
    if verb is None:
        raise ValueError("unknown user action; nothing was sent")
    return f"{BASE}/users/{urllib.parse.quote(user_id, safe='')}:{verb}"


def action_body(action: str, now: Optional[float] = None) -> Dict[str, Any]:
    """SkipMfaDto {timestamp} (ASSUMED: now, epoch seconds); no body for a reset."""
    return {"timestamp": int(time.time() if now is None else now)} if action == "skip_mfa" else {}


def zid_user_action(users_api: Any, user_id: str, action: str) -> Tuple[Any, Any, Any]:
    """RAW CALL (not in zscaler-sdk-python 1.11.3): POST one ZIdentity user
    action through the SDK's own request executor. Returns the SDK's
    (data, response, error) shape so pack_ops.call reads it like any write.
    The answer's body is returned as data for the handler to take at once."""
    ex = getattr(users_api, "_request_executor", None)
    if ex is None:
        return None, None, "the installed zscaler-sdk-python exposes no ZIdentity request executor; nothing was sent"
    try:
        path = action_path(user_id, action)
    except ValueError as e:
        return None, None, str(e)
    req, err = ex.create_request(method="POST", endpoint=path, body=action_body(action), headers={}, params={})
    if err:
        return None, None, err
    resp, err = ex.execute(req)
    if err:
        return None, resp, err
    body = resp.get_body() if hasattr(resp, "get_body") else None
    return {"answer": body}, None, None


def plan_reset(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize_reset(spec)
    svc = oz.zid(client)
    act = n["action"]
    title = ACTION_WORDS[act]
    say("Reading the user…")
    row, err = oz._get_user(svc, n["id"])
    if row is None:
        return _blocked(T_RESET, title, n, ao._read_halt(err) or f"The user {n['id']} could not be read: {err}.")
    obj = _obj(row, n["id"])
    login = obj["name"]
    P: Dict[str, Any] = {"type": T_RESET, "product": PRODUCT, "title": f"{title}: {login}", "spec": n, "items": [], "groups": [],
                         "warnings": [], "blockers": [], "apply_note": "ZIdentity applies each change as it is saved; there is no activation step.",
                         "notes": [RAW_NOTE.format(what="Users Ops Reset Password" if act == "reset_password" else "Users Ops Mfa"),
                                   f"POST {BASE}/users/{{id}}:{RESET_ACTIONS[act]}" + (" with the time it was set (epoch seconds)." if act == "skip_mfa" else ", no body."),
                                   "ZIdentity gives no way to read this back, so the result says it was accepted, not checked."]}
    lock = oz.user_lock(row)
    if lock:
        P["items"].append(ao._unit("act", "act", "zid_user", obj, act, None, None, status="excluded", reason=lock))
        return P
    if not ao._truthy(row.get("status", True)):
        P["warnings"].append(f"{login} is disabled: it cannot sign in until it is enabled.")
    before = _fingerprint(row)
    P["groups"].append({"key": "act", "handler": "zid_user_reset", "target": {"id": n["id"], "name": login, "action": act, "before": before}})
    P["items"].append(ao._unit("act", "act", "zid_user", obj, act, "as it is", "reset" if act == "reset_password" else "may skip MFA",
                               reason=NO_UNDO_RESET if act == "reset_password" else NO_UNDO_MFA))
    P["warnings"].insert(0, NO_UNDO_RESET if act == "reset_password" else NO_UNDO_MFA)
    if act == "reset_password":
        P["notes"].append(PASSWORD_ONCE)
    else:
        P["warnings"].append("Skipping MFA weakens this user's sign-in: use it only to let someone who lost their second factor enrol a new one.")
    P["confirm_always"] = f"RESET {login}" if len(login) <= 60 else "RESET USER"
    return P


def _take_answer(out: ops.Outcome) -> str:
    """The text the action answered (possibly a temporary password); the answer is emptied."""
    data, out.data = out.data, None
    v = data.get("answer") if isinstance(data, dict) else None
    if isinstance(v, dict):
        v = next((v[k] for k in ("password", "temporaryPassword", "temporary_password", "tempPassword", "value") if isinstance(v.get(k), str)), "")
    return v.strip()[:500] if isinstance(v, str) else ""


def h_reset(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = oz.zid(run.client)
    fresh, err = oz._get_user(svc, t["id"])
    if fresh is None:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the user '{t['name']}'")
        return
    if _fingerprint(fresh) != t["before"] or oz.user_lock(fresh):
        oz._conflict(run, units, "the user changed in ZIdentity since the preview; nothing was sent")
        return
    # Never retried: a second reset would end the first one's temporary password.
    out = ops.call(zid_user_action, svc.users, t["id"], t["action"], op="update", kind="zid_user_" + t["action"], name=t["name"],
                   log=run.log, max_attempts=1)
    answer = _take_answer(out)
    ops._audit_write("update", "zid_user_" + t["action"], t["id"], t["name"], None, out)
    if not run.outcome(units, out, "update"):
        return
    for u in units:
        u["verified"] = None
    if t["action"] == "reset_password":
        if answer:
            run.p.setdefault("one_time_secrets", []).append({"name": t["name"], "kind": "temporary_password",
                                                              "token": oz.stash(answer, t["name"], oz._actor()),
                                                              "expires_in_seconds": int(oz.SECRET_TTL)})
            run.log(f"[ZIdentity user] {t['name']}: password reset; ZIdentity's answer is shown once on the page")
        else:
            run.log(f"[ZIdentity user] {t['name']}: password reset started (ZIdentity sends the user its reset message)")
    else:
        run.log(f"[ZIdentity user] {t['name']}: may skip MFA")


HANDLERS = {"zid_user_attrs": h_attrs, "zid_user_group": h_group, "zid_user_reset": h_reset}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    if run.p["type"] == T_RESET:
        return out     # ZIdentity offers no read of either action
    svc = oz.zid(run.client)
    uid = run.p["spec"]["id"]
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    row, err = oz._get_user(svc, uid)
    have, gerr = (user_groups(svc, uid) if any(u["kind"] == "zid_user_group" for u in applied) else ({}, None))
    for u in applied:
        out["checked"] += 1
        if u["kind"] == "zid_user_group":
            if have is None:
                out["checked"] -= 1
                out["unread"].append(f"groups: {gerr}")
                u["verified"] = None
                continue
            ok = (u["object"]["group"] in have) is u["after"]
        elif row is None:
            out["checked"] -= 1
            out["unread"].append(f"{u['object'].get('name')}: {err}")
            u["verified"] = None
            continue
        else:
            ok = attrs_of(row).get(u["field"]) == u["after"]
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object'].get('name')}: {u['field']} not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """zid_user_edit: every applied field and group back as it was. A reset
    or skip MFA has none."""
    if result.get("type") != T_EDIT:
        return None
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    back: Dict[str, Any] = {}
    add, rem = [], []
    for g in result.get("groups") or []:
        t = g.get("target") or {}
        if not any(u["group"] == g["key"] for u in applied):
            continue
        if g["handler"] == "zid_user_attrs":
            for f, v in (t.get("undo_set") or {}).items():
                back[f] = v
        elif g["handler"] == "zid_user_group":
            (rem if t.get("add") else add).append(t["group"])
    uid = (result.get("spec") or {}).get("id")
    return {"type": T_EDIT, "id": uid, "set": back, "groups": {"add": sorted(add), "remove": sorted(rem)}, "undo": True} if uid and (back or add or rem) else None


_COMMON = dict(family=FAMILY, product=PRODUCT, in_scope=in_scope, read_objects=read_objects, handlers=HANDLERS, verify=verify, inverse=inverse,
               script=SCRIPT, group="Day-to-day admin")
ao.register(T_EDIT, label="Edit a ZIdentity user", plan=plan_edit,
            hint=("Change one user's display name, first and last name, department and groups; the user is sent back as read with only "
                  "those fields changed, and Undo puts them back. Needs ZIdentity ticked on the Scope page."), **_COMMON)
ao.register(T_RESET, label="Reset a ZIdentity user's password or MFA", plan=plan_reset,
            hint=("Reset one user's password, or let the user skip MFA once, through ZIdentity's API (raw calls: the Zscaler SDK has none). "
                  "Needs the assessor's name and RESET <login> typed; cannot be undone. Needs ZIdentity ticked on the Scope page."), **_COMMON)
