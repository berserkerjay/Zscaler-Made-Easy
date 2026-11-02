"""ZIdentity users and API clients on the Bulk changes engine.

Two operation types on the shared engine (admin_ops.register), with the
same path as any bulk change: the scope check before anything is read
(ZIdentity ticked on the Scope page), a plan that only reads, the plan
hash, the re-plan before writing, write mode, the writer, the named
assessor and the confirmation, a re-read right before each write, the
read-back, the record, the audit log with the actor, and Undo where one
exists. ZIdentity saves each change at once (no activation).

  zid_users        up to MAX_USER_CHANGES changes: create a user (created
                   disabled unless the operator ticks enabled; no password
                   is set here), disable or enable, delete (typed
                   "DELETE <login>", cannot be undone). Administrators and
                   users that come from SCIM are left alone.
  zid_api_clients  one action: create an API client with the scopes picked
                   (least privilege: no scope is preselected, and a
                   full-access scope is named in the preview), created
                   disabled unless asked, plus its first secret; rotate a
                   client's secret (a new secret, then the old ones
                   deleted: typed "ROTATE <name>", cannot be undone); delete
                   a client (typed "DELETE <name>", cannot be undone);
                   disable or enable a client. The API client this app is
                   signed in with is never changed here (it would lock the
                   app out).

Secrets. A new API client secret is shown once: the answer that carries it
is emptied at once and the value goes to an in-memory, single-use,
ten-minute store bound to the person who ran the apply (stash / reveal);
the page fetches it once (POST /api/operations/zidentity/secret). It is never
put in a plan, a result, a log, the audit log, the change record or an
export, and every read of a client's secrets drops their values.

Password and MFA: the installed SDK (zscaler-sdk-python 1.11.3,
zscaler/zid/users.py) has no call for them (UsersAPI has list_users,
get_user, add_user, update_user, delete_user and list_user_group_details
only; UserRecord carries no password or MFA field). Resetting a user's
password and letting a user skip MFA are the operation type zid_user_reset
(ops_zid_user.py), which sends ZIdentity's published ":resetpassword" and
":setskipmfa" actions as clearly marked raw calls behind the assessor and
"RESET <login>". Editing a user's attributes and groups is zid_user_edit
there. This type refuses those actions and names the other one.

SDK calls, verified against zscaler-sdk-python 1.11.3 (client.zid, alias
client.zidentity; base /ziam/admin/api/v1): users.list_users (limit <=
1000, offset, login_name, login_name[like]), get_user, add_user,
update_user (PUT), delete_user; api_client.list_api_clients (limit,
offset, name[like]), get_api_client, add_api_client (name, description,
status, access_token_life_time, client_authentication {auth_type},
client_resources [{id, name, default_api, selected_scopes [{id, name}]}]),
update_api_client (PUT), delete_api_client, get_api_client_secret,
add_api_client_secret, delete_api_client_secret;
resource_servers.list_resource_servers (records with service_scopes
[{service, scopes [{id, name}]}]). ASSUMED (not checkable without a tenant):
that a new client has no secret until one is added (any secret-like field
in the create's answer is dropped unread), that the secrets list answers a
list or {records} (read from the raw answer: the SDK's single-object model
would drop it), that the user and client PUTs take the object as read with
the status changed, that the OAuth client ID this app signs in with is the
API client's id in ZIdentity, and that a missing object answers 404.
"""
from __future__ import annotations

import re
import secrets
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import pack_ops as ops

T_USERS = "zid_users"
T_CLIENTS = "zid_api_clients"
FAMILY = "zid_directory"
SCRIPT = "ops_zid.js"
MAX_USER_CHANGES = 50
MAX_SCOPES = 50
LIMIT = 1000
MAX_USER_ROWS = 2000
MAX_CLIENTS = 500
SECRET_TTL = 600.0
MAX_SECRETS = 20
TOKEN_LIFE = (300, 86400, 3600)          # seconds: least, most, default
_ID = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
_LOGIN = re.compile(r"^[^@\s<>\"'`]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
_CLIENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,127}$")
_SECRET_KEYS = re.compile(r"^(value|secret|client_?secret|key_?value|cert_?content|private_?key|password)$", re.I)
_BROAD = re.compile(r"super ?admin|full ?access|fullaccess", re.I)
NOT_IN_SCOPE = "Not in scope: ZIdentity is not ticked on the Scope page, so nothing is read from ZIdentity or changed in it."
NO_ZID = "This sign-in has no ZIdentity service: ZIdentity needs a OneAPI (ZIdentity) API client. Nothing was read."
OWN_CLIENT = "the API client this app is signed in with: changing it here could lock the app out; change it in the ZIdentity Admin Portal"
NOT_POSSIBLE = [
    "Resetting a user's password: the installed Zscaler SDK (1.11.3) has no call for it, so it is its own operation, \"Reset a ZIdentity "
    "user's password or MFA\" (a raw call to ZIdentity's published API, behind the assessor and RESET <login>).",
    "Resetting an MFA factor is not in ZIdentity's published API: change it in the ZIdentity Admin Portal. Letting a user skip MFA is "
    "\"Reset a ZIdentity user's password or MFA\".",
]
NO_UNDO_USER = "Cannot be undone: a deleted ZIdentity user is gone with its id, groups and entitlements; Undo does not bring it back."
NO_UNDO_CLIENT = "Cannot be undone: a deleted API client is gone with its secrets; every script or tool that signs in with it stops working."
NO_UNDO_ROTATE = ("Cannot be undone: a deleted secret cannot be brought back. Every script or tool that signs in with an old secret "
                  "stops working once it is deleted: give them the new secret first.")
SECRET_ONCE = "The new secret is shown once, right after the apply, to you only; this app never stores, logs or exports it."

LogFn = Callable[[str], None]


# ---------------------------------------------------------------------------
# Reading (GET only); every value under a secret's name is dropped
# ---------------------------------------------------------------------------

def zid(client: Any) -> Any:
    svc = getattr(client, "zid", None) if client is not None else None
    if svc is None:
        svc = getattr(client, "zidentity", None) if client is not None else None
    if svc is None:
        raise ao.OperationError(NO_ZID)
    return svc


def scrub(obj: Any) -> Any:
    """Plain data with every secret-named field removed, at any depth."""
    import ops_zia_directory as od
    d = od.plain(obj)

    def walk(x: Any) -> Any:
        if isinstance(x, list):
            return [walk(v) for v in x]
        if isinstance(x, dict):
            return {k: walk(v) for k, v in x.items() if not _SECRET_KEYS.match(str(k))}
        return x
    return walk(d)


def _call(fn: Callable[..., Any], *a: Any, **k: Any) -> Tuple[Any, Optional[str], Any]:
    """(data, error, response) of one SDK read; never raises."""
    import ops_zia_directory as od
    try:
        ret = fn(*a, **k)
    except Exception as e:  # noqa: BLE001
        return None, od._err(e), None
    if isinstance(ret, tuple) and len(ret) >= 3:
        return (None, od._err(ret[2]), ret[1]) if ret[2] else (od.raw_body(ret[0], ret[1]), None, ret[1])
    return ret, None, None


def records(data: Any) -> List[Dict[str, Any]]:
    d = scrub(data)
    if isinstance(d, dict):
        d = d.get("records") if isinstance(d.get("records"), list) else [d] if d.get("id") is not None else []
    return [r for r in d or [] if isinstance(r, dict)]


def _paged(fn: Callable[..., Any], params: Dict[str, Any], cap: int, cancel: Optional[threading.Event]) -> Tuple[List[Dict[str, Any]], Optional[str], bool]:
    out: List[Dict[str, Any]] = []
    offset = 0
    while True:
        ao._check_stop(cancel)
        data, err, _ = _call(fn, query_params=dict(params, limit=LIMIT, offset=offset))
        if err:
            return out, err, False
        rows = records(data)
        out.extend(rows)
        if len(out) >= cap:
            return out[:cap], None, True
        if len(rows) < LIMIT:
            return out, None, False
        offset += LIMIT


def _rid(v: Any) -> str:
    return "" if v in (None, "") else str(v)


def is_missing(err: Optional[str]) -> bool:
    import ops_zia_directory as od
    return od.is_missing(err)


def _status(v: Any) -> str:
    return "enabled" if ao._truthy(v) else "disabled"


def user_summary(r: Dict[str, Any]) -> Dict[str, Any]:
    lock = user_lock(r)
    return {"id": _rid(r.get("id")), "login_name": str(r.get("login_name") or ""), "display_name": str(r.get("display_name") or ""),
            "email": str(r.get("primary_email") or ""), "status": _status(r.get("status")), "source": str(r.get("source") or ""),
            "admin": ao._truthy(r.get("admin_entitlement_enabled")), "locked": lock or ""}


def user_lock(r: Dict[str, Any]) -> Optional[str]:
    if ao._truthy(r.get("admin_entitlement_enabled")):
        return "an administrator: change it in the ZIdentity Admin Portal"
    if str(r.get("source") or "").upper() == "SCIM":
        return "comes from the identity provider (SCIM): change it there, or the next sync puts it back"
    return None


def scopes_of(c: Dict[str, Any]) -> List[Dict[str, str]]:
    out = []
    for res in c.get("client_resources") or []:
        if not isinstance(res, dict):
            continue
        for s in res.get("selected_scopes") or []:
            if isinstance(s, dict):
                out.append({"resource": str(res.get("name") or res.get("id") or ""), "id": _rid(s.get("id")), "name": str(s.get("name") or "")})
    return out


def own_client_id(client: Any) -> str:
    """The OAuth client ID this app signed in with (the SDK's OneAPI client keeps it)."""
    for attr in ("_client_id", "dlp_check_client_id"):
        v = getattr(client, attr, None)
        if isinstance(v, str) and v:
            return v
    return ""


def client_summary(c: Dict[str, Any], own: str) -> Dict[str, Any]:
    auth = c.get("client_authentication") if isinstance(c.get("client_authentication"), dict) else {}
    sc = scopes_of(c)
    return {"id": _rid(c.get("id")), "name": str(c.get("name") or ""), "description": str(c.get("description") or ""),
            "status": _status(c.get("status")), "auth_type": str((auth or {}).get("auth_type") or ""),
            "token_lifetime": c.get("access_token_life_time"), "scopes": sc, "broad": [s["name"] for s in sc if _BROAD.search(s["name"])],
            "own": bool(own) and _rid(c.get("id")) == own, "locked": OWN_CLIENT if own and _rid(c.get("id")) == own else ""}


def list_secrets(api: Any, cid: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """A client's secrets: id, created, expires; never the value."""
    data, err, _resp = _call(api.get_api_client_secret, cid)
    if err:
        return [], err
    rows = records(data)
    return [{"id": _rid(r.get("id")), "created_at": r.get("created_at"), "expires_at": r.get("expires_at")} for r in rows if r.get("id")], None


def resource_servers(svc: Any, cancel: Optional[threading.Event]) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    rows, err, _ = _paged(svc.resource_servers.list_resource_servers, {}, 200, cancel)
    out = []
    for r in rows:
        scopes = []
        for ss in r.get("service_scopes") or []:
            if not isinstance(ss, dict):
                continue
            service = ss.get("service") if isinstance(ss.get("service"), dict) else {}
            for s in ss.get("scopes") or []:
                if isinstance(s, dict) and s.get("id"):
                    scopes.append({"id": _rid(s.get("id")), "name": str(s.get("name") or ""),
                                   "service": str((service or {}).get("display_name") or (service or {}).get("name") or ""),
                                   "broad": bool(_BROAD.search(str(s.get("name") or "")))})
        out.append({"id": _rid(r.get("id")), "name": str(r.get("name") or r.get("display_name") or ""), "default_api": bool(r.get("default_api")),
                    "scopes": scopes})
    return out, err


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event], query: str = "") -> Dict[str, Any]:
    """Users (searched by login name), API clients with their scopes, and the
    resource servers' scopes to pick from. Read-only; no secret value."""
    import ops_zia_directory as od
    svc = zid(client)
    q = od._query(query)
    errors: Dict[str, str] = {}
    say("Reading the ZIdentity users" + (f" whose login name contains '{q}'…" if q else "…"))
    users, err, cut = _paged(svc.users.list_users, {"login_name[like]": q} if q else {}, MAX_USER_ROWS, cancel)
    if err:
        errors["zidentity_users"] = err
    say("Reading the API clients and their scopes…")
    own = own_client_id(client)
    clients, err, _ = _paged(svc.api_client.list_api_clients, {}, MAX_CLIENTS, cancel)
    if err:
        errors["zidentity_api_clients"] = err
    servers, err = resource_servers(svc, cancel)
    if err:
        errors["zidentity_resource_servers"] = err
    return {"users": [user_summary(u) for u in sorted(users, key=lambda r: str(r.get("login_name") or "").lower())], "users_truncated": cut,
            "query": q, "api_clients": [client_summary(c, own) for c in sorted(clients, key=lambda r: str(r.get("name") or "").lower())],
            "resource_servers": servers, "errors": errors, "not_possible": NOT_POSSIBLE, "secret_once": SECRET_ONCE,
            "limits": {"user_changes": MAX_USER_CHANGES, "scopes": MAX_SCOPES, "token_lifetime": list(TOKEN_LIFE[:2])}}


# ---------------------------------------------------------------------------
# zid_users
# ---------------------------------------------------------------------------

def _id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if not _ID.match(s):
        raise ao.OperationError(f"{what} must be a ZIdentity id.")
    return s


def _name(v: Any, what: str, required: bool = True) -> str:
    s = ao._object_name(v, what)
    if required and not s:
        raise ao.OperationError(f"The {what} is required.")
    return s


def normalize_users(spec: Dict[str, Any]) -> Dict[str, Any]:
    action = str(spec.get("action") or "").strip().lower()
    if action not in ("", "undo"):
        raise ao.OperationError("'action' is only used by Undo.")
    raw = ao._list_field(spec, "changes", objects=True, cap=MAX_USER_CHANGES)
    if not raw:
        raise ao.OperationError("Add at least one change.")
    out = []
    for c in raw:
        act = str(c.get("action") or "").strip().lower()
        if act in ("reset_password", "reset_mfa", "skip_mfa"):
            raise ao.OperationError(NOT_POSSIBLE[0] if act == "reset_password" else NOT_POSSIBLE[1])
        if act not in ("create", "disable", "enable", "delete"):
            raise ao.OperationError("Each change is create, disable, enable or delete.")
        if act == "create":
            login = str(c.get("login_name") or "").strip()
            if not _LOGIN.match(login) or len(login) > 254:
                raise ao.OperationError("The login name must look like name@domain.")
            email = str(c.get("primary_email") or login).strip()
            if not _LOGIN.match(email) or len(email) > 254:
                raise ao.OperationError("The email must look like name@domain.")
            out.append({"action": "create", "login_name": login, "display_name": _name(c.get("display_name"), "display name"),
                        "first_name": _name(c.get("first_name") or "", "first name", False), "last_name": _name(c.get("last_name") or "", "last name", False),
                        "primary_email": email, "enable": c.get("enable") is True})
        else:
            out.append({"action": act, "id": _id(c.get("id"), f"The user to {act}")})
    ids = [c["id"] for c in out if c.get("id")]
    logins = [c["login_name"].lower() for c in out if c.get("login_name")]
    if len(ids) != len(set(ids)) or len(logins) != len(set(logins)):
        raise ao.OperationError("Each user may appear once per operation.")
    n: Dict[str, Any] = {"type": T_USERS, "changes": out}
    if action == "undo":
        n["action"] = "undo"
    return n


def _get_user(svc: Any, uid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    data, err, _ = _call(svc.users.get_user, uid)
    if err:
        return None, err
    rows = records(data)
    return (rows[0] if rows else None), (None if rows else "no answer")


def _user_by_login(svc: Any, login: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    rows, err, _ = _paged(svc.users.list_users, {"login_name": login}, 50, None)
    return next((r for r in rows if str(r.get("login_name") or "").lower() == login.lower()), None), err


def plan_users(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize_users(spec)
    svc = zid(client)
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    deletes: List[str] = []
    say("Reading the ZIdentity users the change names…")
    rank = {"create": 0, "enable": 1, "disable": 1, "delete": 2}
    for i, c in sorted(enumerate(n["changes"]), key=lambda ic: (rank[ic[1]["action"]], ic[0])):
        ao._check_stop(cancel)
        key = f"u{i}"
        if c["action"] == "create":
            obj = {"type": "zid_user", "policy_label": "ZIdentity user", "name": c["login_name"]}
            hit, err = _user_by_login(svc, c["login_name"])
            if err and ao._read_halt(err):
                blockers.append(str(ao._read_halt(err)))
                break
            if hit is not None:
                items.append(ao._unit(key, key, "zid_user", dict(obj, id=_rid(hit.get("id"))), "exists", True, True, status="noop",
                                      reason="a user with this login name exists"))
                continue
            if err:
                warnings.append(f"Could not check that {c['login_name']} is new ({err}); ZIdentity refuses a duplicate.")
            groups.append({"key": key, "handler": "zid_user_write", "target": dict(c)})
            items.append(ao._unit(key, key, "zid_user", obj, "exists", False, True, value=_status(c["enable"]),
                                  reason="" if c["enable"] else "created disabled: enable it when the person needs it"))
            continue
        row, err = _get_user(svc, c["id"])
        obj = {"type": "zid_user", "policy_label": "ZIdentity user", "name": str((row or {}).get("login_name") or c["id"]), "id": c["id"]}
        if row is None:
            if ao._read_halt(err):
                blockers.append(str(ao._read_halt(err)))
                break
            items.append(ao._unit(key, key, "zid_user", obj, "exists", None, None, status="noop" if c["action"] == "delete" else "excluded",
                                  reason="already gone" if c["action"] == "delete" else f"not found in ZIdentity ({err})"))
            continue
        lock = user_lock(row)
        if lock:
            items.append(ao._unit(key, key, "zid_user", obj, "status" if c["action"] != "delete" else "exists", None, None, status="excluded", reason=lock))
            continue
        cur = _status(row.get("status"))
        before = {"status": cur, "login_name": obj["name"]}
        if c["action"] == "delete":
            groups.append({"key": key, "handler": "zid_user_write", "target": {"action": "delete", "id": c["id"], "name": obj["name"], "before": before}})
            items.append(ao._unit(key, key, "zid_user", obj, "exists", True, False,
                                  reason="Undo deletes what the operation created" if n.get("action") == "undo" else NO_UNDO_USER))
            deletes.append(obj["name"])
            continue
        want = "enabled" if c["action"] == "enable" else "disabled"
        if cur == want:
            items.append(ao._unit(key, key, "zid_user", obj, "status", cur, want, status="noop", reason="already as asked"))
            continue
        groups.append({"key": key, "handler": "zid_user_write", "target": {"action": "status", "id": c["id"], "name": obj["name"], "before": before,
                                                                            "to": want}})
        items.append(ao._unit(key, key, "zid_user", obj, "status", cur, want,
                              reason="the person can no longer sign in" if want == "disabled" else ""))
    confirm = None
    if deletes:
        confirm = f"DELETE {deletes[0]}" if len(deletes) == 1 and len(deletes[0]) <= 60 else f"DELETE {len(deletes)} USERS"
        if n.get("action") != "undo":
            warnings.insert(0, NO_UNDO_USER)
    return {"type": T_USERS, "product": "zidentity", "title": "Undo a ZIdentity users change" if n.get("action") == "undo" else "ZIdentity users",
            "spec": n, "items": items, "groups": groups, "warnings": warnings, "blockers": blockers, "confirm_always": confirm,
            "apply_note": "ZIdentity applies each change as it is saved; there is no activation step.",
            "notes": ["No password is set or read here; a new user signs in through the identity provider or sets a password from ZIdentity's "
                      "own invitation."] + NOT_POSSIBLE}


_USER_PUT = ("login_name", "display_name", "first_name", "last_name", "primary_email", "secondary_email", "status", "department", "idp",
             "custom_attrs_info")


def user_create_payload(t: Dict[str, Any]) -> Dict[str, Any]:
    p = {"login_name": t["login_name"], "display_name": t["display_name"], "primary_email": t["primary_email"], "status": bool(t["enable"])}
    for k in ("first_name", "last_name"):
        if t.get(k):
            p[k] = t[k]
    return p


def user_status_payload(fresh: Dict[str, Any], to: str) -> Dict[str, Any]:
    body = {k: fresh[k] for k in _USER_PUT if fresh.get(k) is not None}
    body["status"] = to == "enabled"
    return body


# ---------------------------------------------------------------------------
# zid_api_clients
# ---------------------------------------------------------------------------

CLIENT_ACTIONS = ("create", "rotate", "delete", "disable", "enable")


def normalize_clients(spec: Dict[str, Any]) -> Dict[str, Any]:
    action = str(spec.get("action") or "").strip().lower()
    if action == "undo":
        d = spec.get("delete") if isinstance(spec.get("delete"), dict) else {}
        return {"type": T_CLIENTS, "action": "undo", "delete": {"id": _id(d.get("id"), "The API client"), "name": _name(d.get("name"), "API client name")}}
    if action not in CLIENT_ACTIONS:
        raise ao.OperationError(f"Pick what to do with the API client: {', '.join(CLIENT_ACTIONS)}.")
    n: Dict[str, Any] = {"type": T_CLIENTS, "action": action}
    if action != "create":
        n["id"] = _id(spec.get("id"), "The API client")
        if action == "rotate":
            n["delete_old"] = spec.get("delete_old") is not False
        return n
    name = str(spec.get("name") or "").strip()
    if not _CLIENT_NAME.match(name):
        raise ao.OperationError("Name the API client: up to 128 letters, digits, spaces and . _ ( ) -, starting with a letter or digit.")
    n["name"] = name
    desc = str(spec.get("description") or "").strip()[:500]
    if ao._has_control(desc):
        raise ao.OperationError("The description contains a control character.")
    n["description"] = desc
    life = spec.get("token_lifetime", TOKEN_LIFE[2])
    try:
        life = int(life)
    except (TypeError, ValueError):
        raise ao.OperationError("The token lifetime is a number of seconds.")
    if not TOKEN_LIFE[0] <= life <= TOKEN_LIFE[1]:
        raise ao.OperationError(f"The token lifetime must be {TOKEN_LIFE[0]} to {TOKEN_LIFE[1]} seconds.")
    n["token_lifetime"] = life
    picks = ao._list_field(spec, "scopes", objects=True, cap=MAX_SCOPES)
    if not picks:
        raise ao.OperationError("Pick at least one scope: an API client with no scope can do nothing (least privilege: pick only what it needs).")
    n["scopes"] = sorted({(_id(p.get("resource"), "A scope's resource"), _id(p.get("scope"), "A scope")) for p in picks})
    n["scopes"] = [{"resource": r, "scope": s} for r, s in n["scopes"]]
    n["enable"] = spec.get("enable") is True
    return n


def _clients(svc: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    rows, err, _ = _paged(svc.api_client.list_api_clients, {}, MAX_CLIENTS, None)
    return rows, err


def _get_client(svc: Any, cid: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    data, err, _ = _call(svc.api_client.get_api_client, cid)
    if err:
        return None, err
    rows = records(data)
    return (rows[0] if rows else None), (None if rows else "no answer")


def client_state(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": str(c.get("name") or ""), "status": _status(c.get("status")),
            "scopes": sorted(s["id"] for s in scopes_of(c))}


def plan_clients(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize_clients(spec)
    svc = zid(client)
    act = n["action"]
    P: Dict[str, Any] = {"type": T_CLIENTS, "product": "zidentity", "spec": n, "items": [], "groups": [], "warnings": [], "blockers": [],
                         "apply_note": "ZIdentity applies each change as it is saved; there is no activation step.", "notes": []}
    P["title"] = {"create": "New ZIdentity API client", "rotate": "Rotate an API client's secret", "delete": "Delete an API client",
                  "disable": "Disable an API client", "enable": "Enable an API client", "undo": "Undo: delete the API client this app made"}[act]
    own = own_client_id(client)
    say("Reading the API clients…")
    if act == "create":
        rows, err = _clients(svc)
        if err:
            P["blockers"].append(ao._read_halt(err) or f"The API clients could not be read: {err}")
            return P
        obj = {"type": "zid_api_client", "policy_label": "API client", "name": n["name"]}
        if any(str(r.get("name") or "").lower() == n["name"].lower() for r in rows):
            P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "exists", True, True, status="excluded",
                                       reason="an API client with this name exists: pick another name"))
            return P
        servers, err = resource_servers(svc, cancel)
        if err:
            P["blockers"].append(f"The resource servers (the scopes to pick from) could not be read: {err}")
            return P
        by_res = {s["id"]: s for s in servers}
        resources: Dict[str, Dict[str, Any]] = {}
        for p in n["scopes"]:
            res = by_res.get(p["resource"])
            sc = next((s for s in (res or {}).get("scopes") or [] if s["id"] == p["scope"]), None)
            if sc is None:
                P["blockers"].append(f"The scope {p['scope']} of resource {p['resource']} is not in ZIdentity (read the tenant again).")
                continue
            r = resources.setdefault(res["id"], {"id": res["id"], "name": res["name"], "default_api": res["default_api"], "selected_scopes": []})
            r["selected_scopes"].append({"id": sc["id"], "name": sc["name"]})
            if sc["broad"]:
                P["warnings"].append(f"The scope '{sc['name']}' gives full administrative access: least privilege picks the narrowest role "
                                     "that does the job.")
        if P["blockers"]:
            return P
        target = {"action": "create", "name": n["name"], "description": n["description"], "token_lifetime": n["token_lifetime"],
                  "enable": n["enable"], "resources": list(resources.values())}
        P["groups"].append({"key": "client", "handler": "zid_client_write", "target": target})
        names = [s["name"] for r in resources.values() for s in r["selected_scopes"]]
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "exists", False, True, value=_status(n["enable"]),
                                   reason="Undo deletes it" + ("" if n["enable"] else "; created disabled: enable it when its secret is in place")))
        P["items"].append(ao._unit("client:scopes", "client", "zid_api_client", obj, "scopes", None, "; ".join(names)))
        P["items"].append(ao._unit("client:secret", "client", "zid_api_client", obj, "secret", None, "new, shown once", reason=SECRET_ONCE))
        P["notes"].append(SECRET_ONCE)
        return P
    target_id = n["delete"]["id"] if act == "undo" else n["id"]
    row, err = _get_client(svc, target_id)
    if row is None:
        if ao._read_halt(err):
            P["blockers"].append(str(ao._read_halt(err)))
        elif act in ("delete", "undo") and is_missing(err):
            P["items"].append(ao._unit("client", "client", "zid_api_client", {"type": "zid_api_client", "name": target_id, "id": target_id}, "exists",
                                       None, False, status="noop", reason="already gone"))
        else:
            P["blockers"].append(f"API client {target_id} could not be read: {err}")
        return P
    st = client_state(row)
    obj = {"type": "zid_api_client", "policy_label": "API client", "name": st["name"], "id": target_id}
    if own and target_id == own and act not in ("enable",):
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "exists" if act in ("delete", "undo") else "status", None, None,
                                   status="excluded", reason=OWN_CLIENT))
        return P
    if act == "undo" and st["name"] != n["delete"]["name"]:
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "exists", True, False, status="excluded",
                                   reason=f"its name is now '{st['name']}', not '{n['delete']['name']}': it is left as it is"))
        return P
    if act in ("delete", "undo"):
        P["groups"].append({"key": "client", "handler": "zid_client_write", "target": {"action": "delete", "id": target_id, "name": st["name"], "before": st}})
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "exists", True, False,
                                   reason="Undo deletes the API client the operation made" if act == "undo" else NO_UNDO_CLIENT))
        P["confirm_always"] = f"DELETE {st['name']}" if len(st["name"]) <= 60 else "DELETE API CLIENT"
        if act == "delete":
            P["warnings"].append(NO_UNDO_CLIENT)
        return P
    if act in ("disable", "enable"):
        want = "enabled" if act == "enable" else "disabled"
        if st["status"] == want:
            P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "status", want, want, status="noop", reason="already as asked"))
            return P
        P["groups"].append({"key": "client", "handler": "zid_client_write", "target": {"action": "status", "id": target_id, "name": st["name"],
                                                                                        "before": st, "to": want}})
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "status", st["status"], want,
                                   reason="every script or tool that signs in with it stops working" if want == "disabled" else ""))
        return P
    # rotate
    auth = row.get("client_authentication") if isinstance(row.get("client_authentication"), dict) else {}
    if str((auth or {}).get("auth_type") or "SECRET").upper() != "SECRET":
        P["items"].append(ao._unit("client", "client", "zid_api_client", obj, "secret", None, None, status="excluded",
                                   reason="this client signs in with a key or certificate, not a secret"))
        return P
    old, err = list_secrets(svc.api_client, target_id)
    if err:
        P["blockers"].append(f"The secrets of '{st['name']}' could not be read: {err}")
        return P
    olds = [s["id"] for s in old] if n["delete_old"] else []
    P["groups"].append({"key": "client", "handler": "zid_client_write",
                        "target": {"action": "rotate", "id": target_id, "name": st["name"], "before": st, "secret_ids": sorted(s["id"] for s in old),
                                   "delete": sorted(olds)}})
    P["items"].append(ao._unit("client:new", "client", "zid_api_client", obj, "secret", None, "new, shown once", reason=SECRET_ONCE))
    for s in old:
        P["items"].append(ao._unit(f"client:old:{s['id']}", "client", "zid_api_client", dict(obj, secret_id=s["id"]), "secret", "exists", "deleted" if n["delete_old"] else "exists",
                                   value=f"secret {s['id']}" + (f", expires {s['expires_at']}" if s.get("expires_at") else ""),
                                   status="change" if n["delete_old"] else "noop",
                                   reason=NO_UNDO_ROTATE if n["delete_old"] else "kept: delete it later, once every tool has the new secret"))
    P["confirm_always"] = f"ROTATE {st['name']}" if len(st["name"]) <= 60 else "ROTATE API CLIENT"
    P["warnings"].append(NO_UNDO_ROTATE if olds else "The old secrets are kept: delete them once every tool has the new secret.")
    P["notes"].append(SECRET_ONCE)
    return P


def client_create_payload(t: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": t["name"], "description": t["description"], "status": bool(t["enable"]), "access_token_life_time": t["token_lifetime"],
            "client_authentication": {"auth_type": "SECRET"},
            "client_resources": [{"id": r["id"], "name": r["name"], "default_api": r["default_api"],
                                  "selected_scopes": [dict(s) for s in r["selected_scopes"]]} for r in t["resources"]]}


_CLIENT_PUT = ("name", "description", "status", "access_token_life_time", "client_authentication", "client_resources")


def client_status_payload(fresh: Dict[str, Any], to: str) -> Dict[str, Any]:
    body = {k: fresh[k] for k in _CLIENT_PUT if fresh.get(k) is not None}
    body["status"] = to == "enabled"
    return body


# ---------------------------------------------------------------------------
# Writes (pack_ops.call: pacing, retries, Stop, audit); the secret is taken
# out of its answer at once and stashed
# ---------------------------------------------------------------------------

def _write(run: Any, fn: Callable[..., Any], *args: Any, op: str, kind: str, name: str, kw: Optional[Dict[str, Any]] = None,
           oid: Any = None, exists: Optional[Callable[[], Any]] = None) -> ops.Outcome:
    out = ops.call(fn, *args, op=op, kind=kind, name=name, log=run.log, kw=kw, exists=exists)
    ops._audit_write(op, kind, out.id if op == "create" else oid, name, None, out)
    return out


def _take_secret(out: ops.Outcome) -> str:
    """The secret value from add_api_client_secret's answer; the answer is emptied."""
    data, out.data = out.data, None
    if isinstance(data, dict):
        v = data.get("value") or data.get("secret")
    else:
        v = getattr(data, "value", None)
    return str(v) if isinstance(v, (str, int)) and str(v) else ""


def _secret_id(out: ops.Outcome) -> str:
    data = out.data
    if isinstance(data, dict):
        return _rid(data.get("id"))
    return _rid(getattr(data, "id", None))


def _actor() -> Optional[str]:
    try:
        return ops.audit_context().get("actor") or None
    except Exception:  # noqa: BLE001
        return None


def _add_secret(run: Any, api: Any, cid: str, name: str, units: List[Dict[str, Any]]) -> bool:
    out = _write(run, api.add_api_client_secret, cid, op="create", kind="zid_api_client_secret", name=name, oid=cid)
    sid = _secret_id(out) if out.ok else ""
    value = _take_secret(out)
    if not run.outcome(units, out, "create"):
        return False
    for u in units:
        u["object"] = dict(u["object"], secret_id=sid)
    if value:
        run.p.setdefault("one_time_secrets", []).append({"name": name, "kind": "api_client_secret", "token": stash(value, name, _actor()),
                                                          "expires_in_seconds": int(SECRET_TTL)})
        run.log(f"[API client] {name}: new secret made; it is shown once on the page")
    else:
        run.p.setdefault("warnings", []).append(f"ZIdentity did not return the new secret of '{name}': make one in the ZIdentity Admin Portal.")
    run.created.append({"type": "zid_api_client_secret", "id": sid, "client": cid, "name": name})
    return True


def _conflict(run: Any, units: List[Dict[str, Any]], why: str) -> None:
    run.mark(units, "conflict", why)
    run.counts["skipped"] += len(units)


def h_user(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = zid(run.client)
    if t["action"] == "create":
        def exists() -> Any:
            hit, err = _user_by_login(svc, t["login_name"])
            if err:
                raise RuntimeError(err)
            return hit.get("id") if hit else None
        out = _write(run, svc.users.add_user, op="create", kind="zid_user", name=t["login_name"], kw=user_create_payload(t), exists=exists)
        if run.outcome(units, out, "create"):
            oid = _rid(out.id)
            for u in units:
                u["object"] = dict(u["object"], id=oid)
            run.created.append({"type": "zid_user", "id": oid, "name": t["login_name"]})
            run.log(f"[ZIdentity user] {t['login_name']}: created ({_status(t['enable'])})")
        return
    fresh, err = _get_user(svc, t["id"])
    if fresh is None:
        if t["action"] == "delete" and is_missing(err):
            run.mark(units, "noop", "already gone")
            return
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the user '{t['name']}'")
        return
    if {"status": _status(fresh.get("status")), "login_name": str(fresh.get("login_name") or t["id"])} != t["before"] or user_lock(fresh):
        _conflict(run, units, "the user changed in ZIdentity since the preview; left as it is")
        return
    if t["action"] == "delete":
        out = _write(run, svc.users.delete_user, t["id"], op="delete", kind="zid_user", name=t["name"], oid=t["id"])
        if run.outcome(units, out, "delete"):
            run.log(f"[ZIdentity user] {t['name']}: deleted")
        return
    out = _write(run, svc.users.update_user, t["id"], op="update", kind="zid_user", name=t["name"], kw=user_status_payload(fresh, t["to"]), oid=t["id"])
    if run.outcome(units, out, "update"):
        run.log(f"[ZIdentity user] {t['name']}: {t['to']}")


def h_client(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    svc = zid(run.client)
    api = svc.api_client
    if t["action"] == "create":
        rows, err = _clients(svc)
        if err:
            import ops_zia_directory as od
            od._halt_or_fail(run, units, err, "the API clients")
            return
        if any(str(r.get("name") or "").lower() == t["name"].lower() for r in rows):
            _conflict(run, units, "an API client with this name was made since the preview; nothing was created")
            return
        main = [u for u in units if u["field"] != "secret"]
        sec = [u for u in units if u["field"] == "secret"]
        out = _write(run, api.add_api_client, op="create", kind="zid_api_client", name=t["name"], kw=client_create_payload(t))
        out.data = None   # an answer that carried a secret anyway is dropped unread
        if not run.outcome(main, out, "create"):
            run.mark(sec, "skipped", "not attempted: the API client was not created")
            return
        cid = _rid(out.id)
        for u in units:
            u["object"] = dict(u["object"], id=cid)
        run.created.append({"type": "zid_api_client", "id": cid, "name": t["name"]})
        run.log(f"[API client] {t['name']}: created ({_status(t['enable'])})")
        if not _add_secret(run, api, cid, t["name"], sec):
            run.p.setdefault("warnings", []).append(f"'{t['name']}' was created without a secret: rotate it here, or add one in ZIdentity.")
        return
    fresh, err = _get_client(svc, t["id"])
    if fresh is None:
        if t["action"] == "delete" and is_missing(err):
            run.mark(units, "noop", "already gone")
            return
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the API client '{t['name']}'")
        return
    if client_state(fresh) != t["before"]:
        _conflict(run, units, "the API client changed in ZIdentity since the preview; left as it is")
        return
    if t["action"] == "delete":
        out = _write(run, api.delete_api_client, t["id"], op="delete", kind="zid_api_client", name=t["name"], oid=t["id"])
        if run.outcome(units, out, "delete"):
            run.log(f"[API client] {t['name']}: deleted")
        return
    if t["action"] == "status":
        out = _write(run, api.update_api_client, t["id"], op="update", kind="zid_api_client", name=t["name"], kw=client_status_payload(fresh, t["to"]),
                     oid=t["id"])
        if run.outcome(units, out, "update"):
            run.log(f"[API client] {t['name']}: {t['to']}")
        return
    # rotate: the new secret first; the old ones only once it exists
    old, err = list_secrets(api, t["id"])
    if err:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, f"the secrets of '{t['name']}'")
        return
    if sorted(s["id"] for s in old) != t["secret_ids"]:
        _conflict(run, units, "the client's secrets changed since the preview; nothing was rotated")
        return
    new = [u for u in units if u["key"] == "client:new"]
    if not _add_secret(run, api, t["id"], t["name"], new):
        run.mark([u for u in units if u["key"] != "client:new"], "skipped", "not attempted: the new secret was not made, so the old ones stay")
        return
    for sid in t["delete"]:
        us = [u for u in units if u["key"] == f"client:old:{sid}"]
        if not us:
            continue
        out = _write(run, api.delete_api_client_secret, t["id"], sid, op="delete", kind="zid_api_client_secret", name=t["name"], oid=sid)
        run.outcome(us, out, "delete")


HANDLERS = {"zid_user_write": h_user, "zid_client_write": h_client}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    svc = zid(run.client)
    targets = {g["key"]: g["target"] for g in run.p["groups"]}
    for u in [u for u in run.p["items"] if u["status"] == "applied"]:
        t = targets.get(u["group"]) or {}
        oid = str(u["object"].get("id") or "")
        is_user = run.p["type"] == T_USERS
        row, err = (_get_user(svc, oid) if is_user else _get_client(svc, oid)) if oid else (None, "no id")
        out["checked"] += 1
        if u["field"] == "exists" and u["after"] is False:
            ok = row is None and is_missing(err)
        elif row is None:
            out["checked"] -= 1
            out["unread"].append(f"{u['object'].get('name')}: {err}")
            u["verified"] = None
            continue
        elif u["field"] == "status":
            ok = _status(row.get("status")) == u["after"]
        elif u["field"] == "secret":
            sec, serr = list_secrets(svc.api_client, oid)
            ids = {s["id"] for s in sec}
            ok = not serr and ((u["object"].get("secret_id") in ids) == (u["after"] != "deleted"))
        elif u["field"] == "scopes":
            ok = "; ".join(sorted(s["name"] for s in scopes_of(row))) == "; ".join(sorted(str(u["after"]).split("; ")))
        else:   # created
            ok = str(row.get("login_name" if is_user else "name") or "") == str(u["object"].get("name"))
            if ok and t.get("action") == "create":
                ok = _status(row.get("status")) == _status(t.get("enable"))
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object'].get('name')}: {u['field']} not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """zid_users: delete what was created, put each status back; deletes have
    none. zid_api_clients: a created client is deleted (an Undo-only form), a
    status change is turned back; a rotation or delete has none."""
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    if result.get("type") == T_USERS:
        changes: List[Dict[str, Any]] = []
        for g in result.get("groups") or []:
            t = g.get("target") or {}
            if t.get("action") == "status" and any(u["group"] == g["key"] for u in applied):
                changes.append({"action": "enable" if t["to"] == "disabled" else "disable", "id": t["id"]})
        changes += [{"action": "delete", "id": str(c["id"])} for c in result.get("created") or [] if c.get("type") == "zid_user" and c.get("id")]
        return {"type": T_USERS, "action": "undo", "changes": changes} if changes else None
    t = ((result.get("groups") or [{}])[0] or {}).get("target") or {}
    if t.get("action") == "create":
        made = next((c for c in result.get("created") or [] if c.get("type") == "zid_api_client" and c.get("id")), None)
        return {"type": T_CLIENTS, "action": "undo", "delete": {"id": str(made["id"]), "name": made["name"]}} if made else None
    if t.get("action") == "status":
        return {"type": T_CLIENTS, "action": "enable" if t["to"] == "disabled" else "disable", "id": t["id"]}
    return None


# ---------------------------------------------------------------------------
# The secret, shown once: an in-memory, single-use, ten-minute store
# ---------------------------------------------------------------------------

_SECRETS: Dict[str, Tuple[str, str, float, Optional[str]]] = {}
_SECRETS_LOCK = threading.Lock()


def _prune(now: float) -> None:
    for k in [k for k, v in _SECRETS.items() if v[2] <= now]:
        del _SECRETS[k]
    while len(_SECRETS) > MAX_SECRETS:
        del _SECRETS[min(_SECRETS, key=lambda k: _SECRETS[k][2])]


def stash(secret: str, name: str, actor: Optional[str], now: Optional[float] = None) -> str:
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(32)
    with _SECRETS_LOCK:
        _SECRETS[token] = (secret, name, now + SECRET_TTL, actor)
        _prune(now)
    return token


def reveal(token: Any, actor: Optional[str] = None, now: Optional[float] = None) -> Optional[Dict[str, str]]:
    """{name, secret} once, for a valid unexpired token asked for by the person
    whose apply made it; None otherwise. The value is gone after."""
    now = time.time() if now is None else now
    t = str(token or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", t):
        return None
    with _SECRETS_LOCK:
        _prune(now)
        got = _SECRETS.get(t)
        if got is None or (got[3] and got[3] != actor):
            return None
        del _SECRETS[t]
    return {"name": got[1], "secret": got[0]}


# ---------------------------------------------------------------------------
# Scope and registration
# ---------------------------------------------------------------------------

def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if "zidentity" in (scope.get("scopes") or []) else NOT_IN_SCOPE


_COMMON = dict(family=FAMILY, product="zidentity", in_scope=in_scope, read_objects=read_objects, handlers=HANDLERS, verify=verify,
               inverse=inverse, script=SCRIPT, group="Day-to-day admin")
ao.register(T_USERS, label="ZIdentity users", plan=plan_users,
            hint=("Find users by login name; create users (disabled unless you tick enabled), disable, enable or delete them. "
                  "To edit a user or reset its password or MFA, use Edit a ZIdentity user or Reset a ZIdentity user's password or MFA. "
                  "Needs ZIdentity ticked on the Scope page."), **_COMMON)
ao.register(T_CLIENTS, label="ZIdentity API clients", plan=plan_clients,
            hint=("List the API clients and their scopes; create one with only the scopes it needs (its secret is shown once), rotate a "
                  "secret, disable, enable or delete a client. Needs ZIdentity ticked on the Scope page."), **_COMMON)
