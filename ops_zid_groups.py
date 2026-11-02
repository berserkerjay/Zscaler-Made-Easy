"""ZIdentity group membership on the Bulk changes engine (admin_ops plugin).

One operation type on /report/operations, under "Change":

  zid_group_members  add people to, or remove people from, one ZIdentity
                     group. The operator types the sign-in names (at most
                     MAX_PEOPLE per side); the page never lists the
                     directory (personal data is counted, not listed: the
                     picker shows group names and member counts only).

The engine (admin_ops) supplies the scope check before any read, the plan
hash and the re-plan before writing, write mode, the writer, assessor and
typed-confirmation gates (the typed phrase is always the group's name:
membership grants access), the record, the audit log and Undo. Each change
is checked again right before it is sent (a person added or removed by
someone else meanwhile is a conflict, left alone), read back after, and
Undo is the opposite change, previewed and confirmed like any other.

Refused: a dynamic group (its rule decides membership), a sign-in name
that is not in the directory, adding a disabled account. A group synced
from the identity provider (SCIM) is allowed with a warning: the next sync
may undo the change.

API calls (zscaler-sdk-python 1.11.3, zscaler/zid/groups.py and users.py), verified there:

    groups.list_groups                  GET    /ziam/admin/api/v1/groups
    groups.get_group                    GET    /ziam/admin/api/v1/groups/{id}
    groups.list_group_users_details     GET    /ziam/admin/api/v1/groups/{id}/users
    users.list_users                    GET    /ziam/admin/api/v1/users (login_name filter)
    groups.add_user_to_group            POST   /ziam/admin/api/v1/groups/{id}/users/{userId}
    groups.remove_user_from_group       DELETE /ziam/admin/api/v1/groups/{id}/users/{userId}

Assumed (ASSUMED): the member list pages with offset / limit as the user
list does; a sign-in name is unique in the directory.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import sdk_read

TYPE = "zid_group_members"
FAMILY = "zid_groups"
PRODUCT = "zidentity"
MAX_PEOPLE = 50
MAX_GROUPS = 200
MAX_COUNTED = 50          # groups whose members are counted for the picker (one read each); the rest show no count
PAGE = 1000
MAX_PAGES = 10
NOT_IN_SCOPE = "Not in scope: tick ZIdentity on the Scope page, then try again. Nothing was read."
ASSUMED = [
    "The group member list pages with offset and limit, as the user list does (zscaler/zid/groups.py documents limit up to 1000).",
    "A sign-in name (loginName) is unique in the ZIdentity directory.",
]
LOGIN_RE = re.compile(r"^[A-Za-z0-9._%+'\-]{1,128}(@[A-Za-z0-9.\-]{1,253})?$")
_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")


class Stopped(ao.Stopped):
    pass


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """ZIdentity is read and changed only when it is ticked on the Scope page."""
    return None if "zidentity" in (scope.get("scopes") or []) else NOT_IN_SCOPE


def _zid(sdk: Any) -> Any:
    # The SDK client names the service both ways (oneapi_client.Client.zidentity and .zid).
    z = getattr(sdk, "zidentity", None) or getattr(sdk, "zid", None)
    if z is None:
        raise ao.OperationError("This sign-in has no ZIdentity API. Sign in with a OneAPI API client.")
    return z


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise Stopped("You clicked Stop, so nothing more was read or sent to the tenant.")


def _txt(v: Any, n: int = 120) -> str:
    return "".join(ch for ch in ("" if v is None else str(v)) if ch.isprintable())[:n]


def _gid(row: Dict[str, Any]) -> str:
    return _txt(row.get("id"), 64)


def read_groups(sdk: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    body, err = sdk_read.call(_zid(sdk).groups.list_groups, query_params={"limit": PAGE})
    return sdk_read.items(body, "records")[:MAX_GROUPS], err


def read_members(sdk: Any, gid: str, cancel: Optional[threading.Event] = None) -> Tuple[Optional[set], Optional[str]]:
    """The user ids in one group (every page), or (None, why)."""
    ids: set = set()
    for page in range(MAX_PAGES):
        _check_stop(cancel)
        body, err = sdk_read.call(_zid(sdk).groups.list_group_users_details, gid, query_params={"limit": PAGE, "offset": page * PAGE})
        if err:
            return None, err
        rows = sdk_read.items(body, "records")
        ids.update(_txt(r.get("id"), 64) for r in rows if r.get("id") not in (None, ""))
        if len(rows) < PAGE:
            return ids, None
    return None, f"more than {PAGE * MAX_PAGES} members: the list was not read to the end"


def _find_user(sdk: Any, login: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    body, err = sdk_read.call(_zid(sdk).users.list_users, query_params={"login_name": login, "limit": 100})
    if err:
        return None, err
    hits = [u for u in sdk_read.items(body, "records") if str(u.get("loginName") or "").strip().lower() == login.lower()]
    return (hits[0] if len(hits) == 1 else None), (None if len(hits) <= 1 else "more than one account has that sign-in name")


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """What the form picks from: the groups (name, id, source, dynamic) and
    how many members each has. No person is listed."""
    say("Reading the ZIdentity groups…")
    rows, err = read_groups(client)
    out = []
    for i, g in enumerate(rows):
        _check_stop(cancel)
        gid = _gid(g)
        if not _ID_RE.match(gid):
            continue
        members, _merr = read_members(client, gid, cancel) if i < MAX_COUNTED else (None, None)
        out.append({"id": gid, "name": _txt(g.get("name") or gid, 128), "source": _txt(g.get("source"), 20),
                    "dynamic": bool(g.get("isDynamicGroup")), "members": len(members) if members is not None else None})
    out.sort(key=lambda g: g["name"].lower())
    return {"groups": out, "max_people": MAX_PEOPLE, "errors": {"zid_groups": err} if err else {}}


def _logins(raw: Any, what: str) -> List[str]:
    if raw in (None, ""):
        return []
    if isinstance(raw, str):
        raw = re.split(r"[\s,;]+", raw)
    if not isinstance(raw, list):
        raise ao.OperationError(f"The people to {what} must be a list of sign-in names.")
    out, seen = [], set()
    for x in raw:
        s = _txt(x, 260).strip()
        if not s:
            continue
        if not LOGIN_RE.match(s):
            raise ao.OperationError(f"Not a sign-in name: {s[:60]!r} (letters, digits and . _ % + ' - with an optional @domain).")
        if s.lower() not in seen:
            seen.add(s.lower())
            out.append(s)
    if len(out) > MAX_PEOPLE:
        raise ao.OperationError(f"At most {MAX_PEOPLE} people to {what} in one operation; this one names {len(out)}. Split it.")
    return out


def normalize(spec: Any) -> Dict[str, Any]:
    if not isinstance(spec, dict):
        raise ao.OperationError("The operation must be an object.")
    gid = _txt(spec.get("group"), 64).strip()
    if not _ID_RE.match(gid):
        raise ao.OperationError("Pick the group.")
    add, remove = _logins(spec.get("add"), "add"), _logins(spec.get("remove"), "remove")
    both = {x.lower() for x in add} & {x.lower() for x in remove}
    if both:
        raise ao.OperationError("A person cannot be added and removed in the same operation: " + ", ".join(sorted(both)[:5]) + ".")
    if not add and not remove:
        raise ao.OperationError("Type at least one sign-in name to add or remove.")
    return {"type": TYPE, "group": gid, "add": add, "remove": remove}


def plan(client: Any, spec: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Preview: reads only. Each person is one item (member: before → after)."""
    spec = normalize(spec)
    gid = spec["group"]
    say("Reading the group…")
    gbody, gerr = sdk_read.call(_zid(client).groups.get_group, gid)
    if gerr or not isinstance(gbody, dict) or not gbody:
        # A blocked preview, not an error: the page shows why and nothing can be applied.
        why = f"The group could not be read: {gerr or 'no such group'}."
        return {"type": TYPE, "product": PRODUCT, "title": "Group members", "spec": spec, "items": [], "groups": [],
                "blockers": [why], "warnings": [], "notes": [], "confirm_always": ""}
    gname = _txt(gbody.get("name") or gid, 128)
    say("Reading its members…")
    members, merr = read_members(client, gid, cancel)
    blockers, warnings = [], []
    if gbody.get("isDynamicGroup"):
        blockers.append(f"\"{gname}\" is a dynamic group: its rule decides who is in it, so members are not added or removed by hand.")
    if merr:
        blockers.append(f"The members of \"{gname}\" could not be read, so no change can be checked: {merr}.")
    if str(gbody.get("source") or "").upper() in ("SCIM", "IDP", "SAML"):
        warnings.append(f"\"{gname}\" is synced from the identity provider ({_txt(gbody.get('source'), 20)}): the next sync may undo a change made here. "
                        "Change it in the identity provider to make it last.")
    items, groups = [], []
    obj_base = {"type": "zid_group_member", "group": gid, "group_name": gname}
    for i, (login, want) in enumerate([(x, True) for x in spec["add"]] + [(x, False) for x in spec["remove"]]):
        _check_stop(cancel)
        key = f"m{i}"
        user, uerr = _find_user(client, login)
        obj = dict(obj_base, name=login, user_id=_txt((user or {}).get("id"), 64))
        if uerr:
            items.append(ao._unit(key, key, "zid_group_member", obj, "member", None, want, status="excluded", reason=f"could not be checked: {uerr}"))
            continue
        if user is None or not _ID_RE.match(obj["user_id"]):
            items.append(ao._unit(key, key, "zid_group_member", obj, "member", None, want, status="excluded", reason="no account has that sign-in name"))
            continue
        before = obj["user_id"] in members if members is not None else None
        active = str(user.get("status", True)).strip().lower() not in ("false", "0", "disabled", "inactive")
        if want and not active:
            items.append(ao._unit(key, key, "zid_group_member", obj, "member", before, want, status="excluded", reason="the account is disabled"))
        elif before is want:
            items.append(ao._unit(key, key, "zid_group_member", obj, "member", before, want, status="noop",
                                  reason="already in the group" if want else "not in the group"))
        else:
            items.append(ao._unit(key, key, "zid_group_member", obj, "member", before, want))
            groups.append({"key": key, "handler": "zid_member_add" if want else "zid_member_remove",
                           "target": {"group": gid, "group_name": gname, "user_id": obj["user_id"], "name": login}})
    n_add = sum(1 for u in items if u["status"] == "change" and u["after"] is True)
    n_rem = sum(1 for u in items if u["status"] == "change" and u["after"] is False)
    title = f"Group \"{gname}\": " + ", ".join(x for x in (f"add {n_add}" if n_add else "", f"remove {n_rem}" if n_rem else "") if x) if (n_add or n_rem) else f"Group \"{gname}\""
    notes = [f"POST /ziam/admin/api/v1/groups/{gid}/users/{{userId}} (SDK zid.groups.add_user_to_group) adds a person; "
             f"DELETE on the same path (SDK zid.groups.remove_user_from_group) removes one.",
             "Each person's membership is read again right before the change; one changed by someone else meanwhile is left alone.",
             "Undo makes the opposite change, previewed and confirmed like this one."]
    return {"type": TYPE, "product": PRODUCT, "title": title, "spec": spec, "items": items, "groups": groups,
            "blockers": blockers, "warnings": warnings, "notes": notes, "confirm_always": gname,
            "apply_note": "ZIdentity applies each change as it is saved; there is no activation step."}


def _h_member(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    import pack_ops as ops
    t = g["target"]
    want = g["handler"] == "zid_member_add"
    members, err = read_members(run.client, t["group"])
    if err:
        halt = ao._read_halt(err)
        if halt:
            run.halt = halt
            run.mark(units, "skipped", f"not attempted: {halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the group's members again right before the change: {err}"[:300])
            run.counts["failed"] += 1
        return
    now = t["user_id"] in members
    if now is want:
        run.mark(units, "noop", "already as asked (someone made the same change)")
        return
    if now is not units[0]["before"]:
        run.mark(units, "conflict", "changed in the tenant since the preview; left as it is")
        return
    z = _zid(run.client)
    fn = z.groups.add_user_to_group if want else z.groups.remove_user_from_group
    # The audit names the group and the user's id, never the sign-in name.
    label = f"{t['group_name']}: user {t['user_id']}"
    out = ops.call(fn, t["group"], t["user_id"], op="update", kind="zid_group_member", name=label, log=run.log)
    ops._audit_write("update", "zid_group_member", t["group"], label, None, out)
    if run.outcome(units, out, "update"):
        run.log(f"[ZIdentity] {t['group_name']}: {'added' if want else 'removed'} one person")


def verify(run: Any) -> Dict[str, Any]:
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    cache: Dict[str, Tuple[Optional[set], Optional[str]]] = {}
    for u in applied:
        o = u["object"]
        if o["group"] not in cache:
            cache[o["group"]] = read_members(run.client, o["group"])
        members, err = cache[o["group"]]
        out["checked"] += 1
        if err or members is None:
            u["verified"] = None
            out["unread"].append(f"{o['group_name']}: {err}")
            continue
        u["verified"] = (o["user_id"] in members) is u["after"]
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o['group_name']}: one membership is not as asked")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied" and u.get("kind") == "zid_group_member"]
    if not applied:
        return None
    gid = applied[0]["object"]["group"]
    return {"type": TYPE, "group": gid,
            "add": [u["object"]["name"] for u in applied if u["after"] is False],
            "remove": [u["object"]["name"] for u in applied if u["after"] is True]}


ao.register(TYPE, family=FAMILY, product=PRODUCT, label="ZIdentity group members",
            hint=("Add people to, or remove them from, one ZIdentity group: type their sign-in names (the directory is never listed). "
                  "Dynamic groups are refused; you type the group's name to confirm. Needs ZIdentity ticked on the Scope page."),
            in_scope=in_scope, plan=plan, read_objects=read_objects,
            handlers={"zid_member_add": _h_member, "zid_member_remove": _h_member}, verify=verify, inverse=inverse, script="ops_zid_groups.js")
