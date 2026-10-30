"""Team server mode: several named people on one server, each with a role
and per-tenant-profile entitlements. OFF by default: unless
ZSCALER_TEAM_MODE is set, nothing in this module runs and the app is the
single-user, localhost-bound, UI-token app it always was.

    ZSCALER_TEAM_MODE          "1" turns it on. Then the UI token is refused
                               in every form; each person signs in with a
                               local account (password) or, with SSO also
                               configured (sso.py), through the identity
                               provider, matched to an account.
    ZSCALER_TEAM_IDLE_MINUTES  a session unused this long ends (default 15)
    ZSCALER_TEAM_SESSION_HOURS every session ends after this long (default 8,
                               at most 12)
    ZSCALER_TEAM_LOCKOUT_ATTEMPTS  wrong passwords in a row before an
                               account is locked (default 5)
    ZSCALER_TEAM_LOCKOUT_MINUTES   how long it stays locked (default 15)
    DLP_CHECK_TEAM_STORE       the account store (default team_server.json
                               beside the tenant profiles, owner-only)

Roles say the most a person may ever do; entitlements say on which tenant
profiles they may do it:

    viewer    read
    operator  read, plan, apply       (the "writer")
    approver  read, approve
    admin     everything, on every tenant profile, and manages the server

A grant gives a user or a group some of read / plan / apply / approve on
one tenant profile (or "*", every profile). What a person may do on a
profile is their role's actions AND the actions granted to them or to a
group they are in. Deny by default: no grant, nothing.

Every route has an access rule in team_routes.py, enforced by
TeamAccessMiddleware on every request: a route with no rule is refused.
Every read of a tenant names a tenant profile, checked again where the
credentials are resolved (dlp_api_server._tenant_creds). Reports and jobs a
request makes are bound to the person and the profile (bind); another
person reaches one only with the same right on that profile.

Passwords are hashed with scrypt (hashlib.scrypt, the standard library's
binding to OpenSSL; no hand-made crypto). The SCIM bearer token is a
256-bit random value stored as its SHA-256 (it is not a password: it has
full entropy) and shown once.
"""
from __future__ import annotations

import base64
import contextvars
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import threading
import time
import unicodedata
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

import safe_files
import store_crypto

# ── settings ────────────────────────────────────────────────────────────
ROLES = ("viewer", "operator", "approver", "admin")
ACTIONS = ("read", "plan", "apply", "approve")
ROLE_ACTIONS: Dict[str, Tuple[str, ...]] = {
    "viewer": ("read",),
    "operator": ("read", "plan", "apply"),
    "approver": ("read", "approve"),
    "admin": ACTIONS,
}
ROLE_LABELS = {"viewer": "Viewer (read only)", "operator": "Operator (read, plan and apply changes)",
               "approver": "Approver (read and approve changes)", "admin": "Administrator (everything, and manages this server)"}
ALL_PROFILES = "*"
STORE_FILE = "team_server.json"
MIN_PASSWORD = 12
MAX_PASSWORD = 1024
USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9._@+-]{0,99}$")
_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
MAX_USERS = 5000
MAX_GROUPS = 2000
MAX_GRANTS = 20000
MAX_TEXT = 200

# scrypt: N=2^15, r=8, p=1 (32 MiB, OWASP's recommended minimum work factor).
SCRYPT_LOG_N = 15
SCRYPT_R = 8
SCRYPT_P = 1
_SCRYPT_MAXMEM = 128 * 1024 * 1024

# Per client address: at most this many sign-in attempts in the window (429 after).
LOGIN_IP_ATTEMPTS = 20
LOGIN_IP_WINDOW = 300.0


def enabled() -> bool:
    return os.environ.get("ZSCALER_TEAM_MODE", "0").strip().lower() in ("1", "true", "yes", "on")


def _num_env(name: str, default: float, lo: float, hi: float) -> float:
    try:
        v = float(os.environ.get(name, "") or default)
    except ValueError:
        v = default
    if not math.isfinite(v):
        v = default
    return min(max(lo, v), hi)


def idle_seconds() -> int:
    return int(_num_env("ZSCALER_TEAM_IDLE_MINUTES", 15, 1, 12 * 60) * 60)


def session_seconds() -> int:
    return int(_num_env("ZSCALER_TEAM_SESSION_HOURS", 8, 0.25, 12) * 3600)


def lockout_attempts() -> int:
    return int(_num_env("ZSCALER_TEAM_LOCKOUT_ATTEMPTS", 5, 1, 100))


def lockout_seconds() -> int:
    return int(_num_env("ZSCALER_TEAM_LOCKOUT_MINUTES", 15, 1, 24 * 60) * 60)


class TeamError(ValueError):
    """A refusal the page can show as it is; `status` is the HTTP status."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(text: Any, limit: int = MAX_TEXT) -> str:
    s = "".join(c for c in str(text or "") if c >= " " and c not in "\x7f")
    return s.strip()[:limit]


def normalize_username(name: Any) -> str:
    """One spelling per person: NFKC, trimmed, lower case."""
    return unicodedata.normalize("NFKC", str(name or "")).strip().lower()


# ── passwords (hashlib.scrypt) ───────────────────────────────────────────
PBKDF2_ITERATIONS = 600_000   # NIST SP 800-132 / OWASP for PBKDF2-HMAC-SHA256 (FIPS mode)


def hash_password(password: str) -> str:
    """scrypt, or in FIPS mode (store_crypto.fips_mode) PBKDF2-HMAC-SHA256,
    the FIPS-approved password-based key derivation."""
    salt = secrets.token_bytes(16)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    if store_crypto.fips_mode():
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)
        return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${b64(salt)}${b64(dk)}"
    dk = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2 ** SCRYPT_LOG_N, r=SCRYPT_R, p=SCRYPT_P,
                        maxmem=_SCRYPT_MAXMEM, dklen=32)
    b64 = lambda b: base64.b64encode(b).decode("ascii")  # noqa: E731
    return f"scrypt${SCRYPT_LOG_N}${SCRYPT_R}${SCRYPT_P}${b64(salt)}${b64(dk)}"


def verify_password(password: str, stored: Any) -> bool:
    """Constant-time check of `password` against a stored scrypt hash. A
    malformed or empty hash never matches (and never raises)."""
    try:
        parts = str(stored or "").split("$")
        if parts[0] == "pbkdf2_sha256" and len(parts) == 4:
            iters = int(parts[1])
            if not 100_000 <= iters <= 10_000_000:
                return False
            salt_b, want_b = base64.b64decode(parts[2], validate=True), base64.b64decode(parts[3], validate=True)
            got = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8", "surrogatepass"), salt_b, iters, dklen=len(want_b))
            return hmac.compare_digest(got, want_b)
        if store_crypto.fips_mode():
            return False   # FIPS mode: an scrypt hash is not an approved one; an administrator resets the password
        kind, log_n, r, p, salt, want = parts
        if kind != "scrypt":
            return False
        log_n, r, p = int(log_n), int(r), int(p)
        if not (10 <= log_n <= 20 and 1 <= r <= 32 and 1 <= p <= 16):
            return False
        salt_b, want_b = base64.b64decode(salt, validate=True), base64.b64decode(want, validate=True)
        got = hashlib.scrypt(str(password).encode("utf-8", "surrogatepass"), salt=salt_b, n=2 ** log_n, r=r, p=p,
                             maxmem=_SCRYPT_MAXMEM, dklen=len(want_b))
        return hmac.compare_digest(got, want_b)
    except (ValueError, TypeError, UnicodeError):
        return False


_DUMMY_HASH: Optional[str] = None


def _burn_time(password: str) -> None:
    """The same work as a real check, for a name with no account: the
    answer's timing does not tell which names exist."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(16))
    verify_password(password, _DUMMY_HASH)


def check_password_policy(password: Any, username: str = "") -> str:
    if not isinstance(password, str):
        raise TeamError("The password must be text.")
    if len(password) < MIN_PASSWORD:
        raise TeamError(f"Use a password of at least {MIN_PASSWORD} characters (a passphrase of a few words is easiest).")
    if len(password) > MAX_PASSWORD:
        raise TeamError(f"The password is longer than {MAX_PASSWORD} characters.")
    if username and normalize_username(password) == normalize_username(username):
        raise TeamError("The password must not be the user name.")
    return password


# ── the store ───────────────────────────────────────────────────────────
_LOCK = threading.RLock()
_CACHE: Dict[str, Any] = {"key": None, "data": None}


def store_path() -> str:
    env = os.environ.get("DLP_CHECK_TEAM_STORE")
    if env:
        return env
    try:
        import tenant_profiles
        folder = os.path.dirname(os.path.abspath(tenant_profiles.store_path()))
    except Exception:  # noqa: BLE001
        folder = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(folder, STORE_FILE)


def _empty() -> Dict[str, Any]:
    return {"version": 1, "users": {}, "groups": {}, "grants": [], "scim": {}}


def _read() -> Dict[str, Any]:
    p = store_path()
    try:
        st = os.stat(p)
        key = (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return _empty()
    with _LOCK:
        if _CACHE["key"] == key and _CACHE["data"] is not None:
            return json.loads(json.dumps(_CACHE["data"]))
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = safe_files.strict_json_loads(store_crypto.open_text(f.read()))
        except (OSError, ValueError, RecursionError, store_crypto.StoreLocked):
            data = None
        if not isinstance(data, dict):
            # A damaged store is no store: nobody signs in (fail closed),
            # and the file is left for the operator to inspect.
            return _empty()
        for k, empty in (("users", {}), ("groups", {}), ("grants", []), ("scim", {})):
            if not isinstance(data.get(k), type(empty)):
                data[k] = empty
        _CACHE.update(key=key, data=data)
        return json.loads(json.dumps(data))


def _write(data: Dict[str, Any]) -> None:
    with _LOCK:
        safe_files.write_private_atomic(store_path(), store_crypto.seal_text(json.dumps(data, indent=1, sort_keys=True)))
        _CACHE.update(key=None, data=None)


def _new_id() -> str:
    return secrets.token_hex(8)


def _audit(event: str, **fields: Any) -> None:
    try:
        import audit
        audit.record(event, **fields)
    except Exception:  # noqa: BLE001 - auditing never breaks the call; audit reports its own failures
        pass


# ── users ───────────────────────────────────────────────────────────────
def public_user(u: Dict[str, Any]) -> Dict[str, Any]:
    """A user as the admin page sees it: never the password hash."""
    now = time.time()
    return {"id": u.get("id"), "username": u.get("username"), "display_name": u.get("display_name") or "",
            "email": u.get("email") or "", "role": u.get("role"), "active": bool(u.get("active")),
            "source": u.get("source") or "local", "has_password": bool(u.get("password")),
            "groups": list(u.get("groups") or []), "created": u.get("created"), "updated": u.get("updated"),
            "password_algorithm": str(u.get("password") or "").split("$", 1)[0] or None,
            "needs_password_reset": bool(store_crypto.fips_mode() and str(u.get("password") or "").startswith("scrypt$")),
            "locked": float(u.get("locked_until") or 0) > now,
            "locked_until": u.get("locked_until") if float(u.get("locked_until") or 0) > now else None,
            "failed_logins": int(u.get("failed") or 0), "sso_linked": bool(u.get("oidc_sub"))}


def list_users() -> List[Dict[str, Any]]:
    return sorted((public_user(u) for u in _read()["users"].values()), key=lambda u: u["username"] or "")


def get_user(uid: Any) -> Optional[Dict[str, Any]]:
    u = _read()["users"].get(str(uid or ""))
    return u if isinstance(u, dict) else None


def find_user(username: Any) -> Optional[Dict[str, Any]]:
    want = normalize_username(username)
    if not want:
        return None
    for u in _read()["users"].values():
        if isinstance(u, dict) and normalize_username(u.get("username")) == want:
            return u
    return None


def _check_role(role: Any) -> str:
    role = str(role or "").strip().lower()
    if role not in ROLES:
        raise TeamError(f"role must be one of {', '.join(ROLES)}.")
    return role


def _check_username(name: Any) -> str:
    n = normalize_username(name)
    if not USERNAME_RE.fullmatch(n):
        raise TeamError("A user name is 1 to 100 characters: letters, digits and . _ @ + - (an email address works).")
    return n


def _active_admins(data: Dict[str, Any], *, except_id: str = "") -> int:
    return sum(1 for u in data["users"].values() if isinstance(u, dict) and u.get("role") == "admin"
               and u.get("active") and u.get("id") != except_id)


def create_user(*, username: Any, role: Any = "viewer", password: Any = None, display_name: Any = "", email: Any = "",
                source: str = "local", external_id: Any = "", active: bool = True, by: str = "") -> Dict[str, Any]:
    name = _check_username(username)
    role = _check_role(role)
    pw_hash = ""
    if password not in (None, ""):
        pw_hash = hash_password(check_password_policy(password, name))
    with _LOCK:
        data = _read()
        if len(data["users"]) >= MAX_USERS:
            raise TeamError("This server already holds the most accounts it keeps.", 409)
        if any(normalize_username(u.get("username")) == name for u in data["users"].values() if isinstance(u, dict)):
            raise TeamError(f"There is already an account named {name}.", 409)
        uid = _new_id()
        now = _now_iso()
        data["users"][uid] = {"id": uid, "username": name, "display_name": _clean(display_name), "email": _clean(email).lower(),
                              "role": role, "active": bool(active), "password": pw_hash, "groups": [], "source": source,
                              "external_id": _clean(external_id), "created": now, "updated": now, "failed": 0, "locked_until": 0}
        _write(data)
    _audit("team_user_created", actor=by or None, user=name, role=role, source=source)
    return get_user(uid) or {}


def update_user(uid: str, *, by: str = "", **fields: Any) -> Dict[str, Any]:
    with _LOCK:
        data = _read()
        u = data["users"].get(uid)
        if not isinstance(u, dict):
            raise TeamError("No such account.", 404)
        changed: Dict[str, Any] = {}
        if "role" in fields and fields["role"] is not None:
            role = _check_role(fields["role"])
            if u.get("role") == "admin" and role != "admin" and u.get("active") and _active_admins(data, except_id=uid) == 0:
                raise TeamError("This is the last active administrator: make someone else an administrator first.", 409)
            if role != u.get("role"):
                changed["role"] = role
        if "active" in fields and fields["active"] is not None:
            act = bool(fields["active"])
            if not act and u.get("role") == "admin" and u.get("active") and _active_admins(data, except_id=uid) == 0:
                raise TeamError("This is the last active administrator: it cannot be turned off.", 409)
            if act != bool(u.get("active")):
                changed["active"] = act
        for k in ("display_name", "email", "external_id"):
            if k in fields and fields[k] is not None:
                v = _clean(fields[k]).lower() if k == "email" else _clean(fields[k])
                if v != (u.get(k) or ""):
                    changed[k] = v
        if "username" in fields and fields["username"] is not None:
            name = _check_username(fields["username"])
            if name != u.get("username"):
                if any(normalize_username(o.get("username")) == name for o in data["users"].values() if isinstance(o, dict) and o.get("id") != uid):
                    raise TeamError(f"There is already an account named {name}.", 409)
                changed["username"] = name
        if not changed:
            return u
        u.update(changed)
        u["updated"] = _now_iso()
        _write(data)
    if changed.get("active") is False or "role" in changed or "username" in changed:
        _end_sessions(uid)
    _audit("team_user_updated", actor=by or None, user=u.get("username"), changes=sorted(changed))
    return u


def set_password(uid: str, password: Any, *, by: str = "") -> None:
    u = get_user(uid)
    if not u:
        raise TeamError("No such account.", 404)
    h = hash_password(check_password_policy(password, u.get("username") or ""))
    with _LOCK:
        data = _read()
        rec = data["users"].get(uid)
        if not isinstance(rec, dict):
            raise TeamError("No such account.", 404)
        rec.update(password=h, failed=0, locked_until=0, updated=_now_iso())
        _write(data)
    _end_sessions(uid)
    _audit("team_password_set", actor=by or None, user=u.get("username"))


def unlock_user(uid: str, *, by: str = "") -> None:
    with _LOCK:
        data = _read()
        rec = data["users"].get(uid)
        if not isinstance(rec, dict):
            raise TeamError("No such account.", 404)
        rec.update(failed=0, locked_until=0)
        _write(data)
    _FAILURES.pop(normalize_username(rec.get("username")), None)
    _audit("team_user_unlocked", actor=by or None, user=rec.get("username"))


def delete_user(uid: str, *, by: str = "") -> None:
    with _LOCK:
        data = _read()
        u = data["users"].get(uid)
        if not isinstance(u, dict):
            raise TeamError("No such account.", 404)
        if u.get("role") == "admin" and u.get("active") and _active_admins(data, except_id=uid) == 0:
            raise TeamError("This is the last active administrator: it cannot be deleted.", 409)
        data["users"].pop(uid, None)
        for g in data["groups"].values():
            if isinstance(g, dict):
                g["members"] = [m for m in g.get("members") or [] if m != uid]
        data["grants"] = [g for g in data["grants"] if g.get("principal") != f"user:{uid}"]
        _write(data)
    _end_sessions(uid)
    _audit("team_user_deleted", actor=by or None, user=u.get("username"))


# ── groups ──────────────────────────────────────────────────────────────
def list_groups() -> List[Dict[str, Any]]:
    data = _read()
    return sorted(({"id": g.get("id"), "display_name": g.get("display_name"), "members": list(g.get("members") or []),
                    "external_id": g.get("external_id") or ""} for g in data["groups"].values() if isinstance(g, dict)),
                  key=lambda g: str(g["display_name"] or "").lower())


def _user_groups(data: Dict[str, Any], uid: str, token_groups: Iterable[str] = ()) -> Set[str]:
    """The group ids a user is in: by membership, and the groups whose
    display name the identity provider's sign-in listed (token_groups)."""
    names = {str(t).strip().lower() for t in token_groups or () if str(t).strip()}
    out = set()
    for g in data["groups"].values():
        if not isinstance(g, dict):
            continue
        if uid in (g.get("members") or []) or (names and str(g.get("display_name") or "").strip().lower() in names):
            out.add(g.get("id"))
    return out


# ── grants and entitlements ─────────────────────────────────────────────
def list_grants() -> List[Dict[str, Any]]:
    return [dict(g) for g in _read()["grants"] if isinstance(g, dict)]


def set_grant(principal: Any, profile: Any, actions: Any, *, by: str = "") -> Dict[str, Any]:
    """Give `principal` ("user:<id>" or "group:<id>") exactly `actions` on
    `profile` (a tenant profile id, or "*" for every profile). No actions
    removes the grant."""
    principal = str(principal or "")
    kind, _, pid = principal.partition(":")
    if kind not in ("user", "group") or not _ID_RE.fullmatch(pid):
        raise TeamError("principal is user:<id> or group:<id>.")
    profile = str(profile or "").strip()
    if profile != ALL_PROFILES:
        import tenant_profiles
        if not tenant_profiles._PROFILE_ID_RE.match(profile) or tenant_profiles.get(profile) is None:
            raise TeamError("No such tenant profile.", 404)
    if not isinstance(actions, (list, tuple)) or not all(isinstance(a, str) for a in actions):
        raise TeamError(f"actions is a list of {', '.join(ACTIONS)}.")
    acts = sorted({a for a in actions}, key=ACTIONS.index) if all(a in ACTIONS for a in actions) else None
    if acts is None:
        raise TeamError(f"actions is a list of {', '.join(ACTIONS)}.")
    with _LOCK:
        data = _read()
        bucket = data["users"] if kind == "user" else data["groups"]
        if pid not in bucket:
            raise TeamError(f"No such {kind}.", 404)
        grants = [g for g in data["grants"] if not (g.get("principal") == principal and g.get("profile") == profile)]
        rec = {"principal": principal, "profile": profile, "actions": acts, "by": by, "at": _now_iso()}
        if acts:
            if len(grants) >= MAX_GRANTS:
                raise TeamError("Too many grants.", 409)
            grants.append(rec)
        data["grants"] = grants
        _write(data)
    _audit("team_grant_set", actor=by or None, principal=principal, profile=profile, actions=acts)
    return rec


def actions_on(user: Optional[Dict[str, Any]], profile: Any, token_groups: Iterable[str] = ()) -> Set[str]:
    """What `user` may do on tenant profile `profile`: their role's actions
    AND what is granted to them or one of their groups there (an
    administrator: every action, every profile). Inactive: nothing."""
    if not user or not user.get("active"):
        return set()
    role_acts = set(ROLE_ACTIONS.get(str(user.get("role")), ()))
    if user.get("role") == "admin":
        return role_acts
    profile = str(profile or "")
    if not profile:
        return set()
    data = _read()
    mine = {f"user:{user.get('id')}"} | {f"group:{g}" for g in _user_groups(data, str(user.get("id")), token_groups)}
    granted: Set[str] = set()
    for g in data["grants"]:
        if isinstance(g, dict) and g.get("principal") in mine and g.get("profile") in (profile, ALL_PROFILES):
            granted |= set(g.get("actions") or ())
    return role_acts & granted


def profiles_with(user: Optional[Dict[str, Any]], action: str, token_groups: Iterable[str] = ()) -> Optional[Set[str]]:
    """The tenant profile ids `user` may `action` on; None means every profile
    (an administrator, or a "*" grant)."""
    if not user or not user.get("active") or action not in ROLE_ACTIONS.get(str(user.get("role")), ()):
        return set()
    if user.get("role") == "admin":
        return None
    data = _read()
    mine = {f"user:{user.get('id')}"} | {f"group:{g}" for g in _user_groups(data, str(user.get("id")), token_groups)}
    out: Set[str] = set()
    for g in data["grants"]:
        if isinstance(g, dict) and g.get("principal") in mine and action in (g.get("actions") or ()):
            if g.get("profile") == ALL_PROFILES:
                return None
            out.add(str(g.get("profile")))
    return out


# ── the request's identity and context ──────────────────────────────────
# Set by TeamAccessMiddleware for every request in team mode; carried into
# the background jobs a request starts (pack_jobs) by capture/restore.
_CTX: "contextvars.ContextVar[Optional[Dict[str, Any]]]" = contextvars.ContextVar("dlp_check_team", default=None)


def context() -> Optional[Dict[str, Any]]:
    return _CTX.get()


def capture() -> Optional[Dict[str, Any]]:
    c = _CTX.get()
    return dict(c) if c else None


def restore(ctx: Optional[Dict[str, Any]]):
    """Install a captured context in this thread; returns the token to reset."""
    return _CTX.set(dict(ctx) if ctx else None)


def reset(token) -> None:
    try:
        _CTX.reset(token)
    except (ValueError, RuntimeError):
        pass


def session_user(session: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """The live account behind a session (re-read every request: a role
    change or a disabled account takes effect at once); None when the
    account is gone or turned off."""
    if not session or not session.get("team_user"):
        return None
    u = get_user(session["team_user"])
    if not u or not u.get("active"):
        return None
    return u


def current_user() -> Optional[Dict[str, Any]]:
    c = _CTX.get()
    return get_user(c["user"]) if c and c.get("user") else None


def current_token_groups() -> List[str]:
    c = _CTX.get()
    return list((c or {}).get("token_groups") or [])


def current_profile() -> str:
    c = _CTX.get()
    return str((c or {}).get("profile") or "")


def may(action: str, profile: Any = None) -> bool:
    """May the person making this request `action` (on `profile`, or on any
    profile when None)? Outside team mode, and outside a request (the app's
    own background work), always yes: the other checks decide."""
    if not enabled():
        return True
    c = _CTX.get()
    if c is None:
        return True
    u = current_user()
    if not u:
        return False
    if profile is None:
        return action in ROLE_ACTIONS.get(str(u.get("role")), ()) and profiles_with(u, action, c.get("token_groups") or ()) != set()
    return action in actions_on(u, profile, c.get("token_groups") or ())


def is_admin() -> bool:
    if not enabled():
        return True
    c = _CTX.get()
    if c is None:
        return True
    u = current_user()
    return bool(u and u.get("role") == "admin")


def _http(status: int, detail: str):
    from fastapi import HTTPException
    return HTTPException(status_code=status, detail=detail)


def require_tenant_profile(profile_id: Any) -> None:
    """Called where a request's tenant credentials are resolved: in team
    mode the tenant must be a saved tenant profile the person holds the
    route's action on (read at least), and the same profile the access
    check passed. Raises a 403 HTTPException otherwise."""
    if not enabled():
        return
    c = _CTX.get()
    if c is None:
        return   # the app's own background work (continuous evaluation), not a person's request
    pid = str(profile_id or "").strip()
    if not pid:
        raise _http(403, "This is a team server: pick one of the saved tenant profiles you have access to (Connect to the "
                         "tenant, Tenant profiles). Typed sign-in details are not used on their own here.")
    action = c.get("action") if c.get("action") in ACTIONS else "read"
    if c.get("profile") and c["profile"] != pid:
        raise _http(403, "This request names two different tenant profiles.")
    if not may(action, pid):
        raise _http(403, f"You ({c.get('username') or 'not signed in'}) may not {action} on the tenant profile '{pid[:48]}'. "
                         "Ask a team server administrator for access.")


# ── resources a request made (reports, jobs, plans) ─────────────────────
_RESOURCES: Dict[str, Tuple[str, str, float]] = {}   # id -> (user id, profile id, at)
_RES_LOCK = threading.Lock()
_RES_MAX = 20000


def bind(resource_id: Any) -> None:
    """Record that the person making this request (and the tenant profile it
    named) owns `resource_id`. Team mode only; a no-op otherwise."""
    if not enabled():
        return
    c = _CTX.get()
    if not c or not resource_id:
        return
    with _RES_LOCK:
        _RESOURCES[str(resource_id)] = (str(c.get("user") or ""), str(c.get("profile") or ""), time.time())
        while len(_RESOURCES) > _RES_MAX:
            _RESOURCES.pop(next(iter(_RESOURCES)))


def bound(resource_id: Any) -> Optional[Tuple[str, str]]:
    with _RES_LOCK:
        hit = _RESOURCES.get(str(resource_id or ""))
    return (hit[0], hit[1]) if hit else None


# Persistent records (change requests, deployments, operations, saved
# snapshots, proposal queues) name their tenant themselves: a resolver per
# path parameter turns an id into the tenant profiles it belongs to (None:
# no such record). Registered by the server at startup.
_RESOLVERS: Dict[str, Callable[[str, Dict[str, str]], Optional[Set[str]]]] = {}


def register_resolver(param: str, fn: Callable[[str, Dict[str, str]], Optional[Set[str]]]) -> None:
    _RESOLVERS[param] = fn


RESOURCE_PARAMS = ("report_id", "job_id", "fix_id", "op_id", "dep_id", "rid", "snapshot_id", "digest_id", "tenant")


def profile_keys(profile_id: str) -> Set[str]:
    """Every key a record may carry for this tenant profile's tenant: the
    proposal and change-queue key, the deployment key, the classic-API
    fingerprint, and the profile id itself."""
    out = {profile_id}
    try:
        import proposals
        import tenant_auth
        import tenant_fingerprint
        import tenant_profiles
        prof = tenant_profiles.get(profile_id)
        if not prof:
            return out
        creds = tenant_auth.normalize(tenant_profiles.creds_from(prof))
        label = tenant_auth.record_label(creds)
        for k in (proposals.tenant_key(tenant_fingerprint.proposal_key(creds, label)),
                  proposals.tenant_key(tenant_fingerprint.proposal_key(creds, profile_id)),
                  tenant_fingerprint.tenant_key(creds), tenant_fingerprint.fingerprint(creds)):
            if k:
                out.add(str(k))
    except Exception:  # noqa: BLE001 - a key that cannot be worked out matches nothing
        pass
    return out


def profiles_for_keys(keys: Iterable[Any]) -> Set[str]:
    """The tenant profiles whose tenant one of `keys` names."""
    want = {str(k) for k in keys if k}
    if not want:
        return set()
    try:
        import tenant_profiles
        ids = [p.get("id") for p in tenant_profiles.list_profiles()]
    except Exception:  # noqa: BLE001
        return set()
    return {pid for pid in ids if pid and profile_keys(pid) & want}


def record_profiles(rec: Dict[str, Any]) -> Set[str]:
    """The tenant profiles a stored record (deployment, operation, change
    request, audit entry) belongs to."""
    if not isinstance(rec, dict):
        return set()
    if rec.get("profile_id"):
        return {str(rec["profile_id"])}
    if rec.get("profile"):
        return {str(rec["profile"])}
    return profiles_for_keys(rec.get(k) for k in ("tenant", "tenant_key", "tenant_fp"))


def visible(records: Iterable[Dict[str, Any]], action: str = "read") -> List[Dict[str, Any]]:
    """Of `records`, the ones the person making this request may `action`
    on (by their tenant profile). An administrator, or outside team mode,
    sees them all; a record naming no tenant only an administrator sees."""
    records = list(records or [])
    if not enabled() or _CTX.get() is None or is_admin():
        return records
    u = current_user()
    allowed = profiles_with(u, action, current_token_groups())
    if allowed is None:
        return records
    out = []
    for r in records:
        if record_profiles(r) & allowed:
            out.append(r)
    return out


def filter_audit_entries(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Audit log entries a person may see: an administrator all of them;
    anyone else only the entries made for a tenant profile they may read
    (an entry naming no tenant profile is the server's own business)."""
    entries = list(entries or [])
    if not enabled() or _CTX.get() is None or is_admin():
        return entries
    allowed = profiles_with(current_user(), "read", current_token_groups())
    if allowed is None:
        return entries
    return [e for e in entries if isinstance(e, dict) and str(e.get("profile") or "") in allowed]


# ── sign-in: lockout and rate limiting ──────────────────────────────────
_FAILURES: Dict[str, Tuple[int, float]] = {}       # username -> (failures, locked_until) for names with no account
_IP_ATTEMPTS: Dict[str, List[float]] = {}
_LOGIN_LOCK = threading.Lock()
_clock = time.time   # tests replace it


def _ip_allowed(ip: str) -> bool:
    now = _clock()
    with _LOGIN_LOCK:
        recent = [t for t in _IP_ATTEMPTS.get(ip, []) if now - t < LOGIN_IP_WINDOW]
        if len(recent) >= LOGIN_IP_ATTEMPTS:
            _IP_ATTEMPTS[ip] = recent
            return False
        recent.append(now)
        _IP_ATTEMPTS[ip] = recent
        if len(_IP_ATTEMPTS) > 4096:
            for k in [k for k, v in _IP_ATTEMPTS.items() if not v or now - v[-1] > LOGIN_IP_WINDOW]:
                _IP_ATTEMPTS.pop(k, None)
        return True


class LoginRefused(Exception):
    def __init__(self, message: str, status: int, reason: str):
        super().__init__(message)
        self.status = status
        self.reason = reason


GENERIC_FAILURE = "That user name and password do not match an account on this server."
LOCKED = "Too many wrong passwords: this account is locked for a while. Try again later, or ask an administrator to unlock it."


def authenticate(username: Any, password: Any, client_ip: str) -> Dict[str, Any]:
    """Check a local sign-in. Returns the account; raises LoginRefused
    (401, 423 or 429) with a message that never says whether the name
    exists. Lockout is enforced: a locked account is refused even with the
    right password, until the lock runs out or an administrator unlocks it."""
    if not _ip_allowed(client_ip or "?"):
        raise LoginRefused("Too many sign-in attempts from this address. Wait a few minutes and try again.", 429, "rate limited")
    name = normalize_username(username)[:200]
    pw = password if isinstance(password, str) else ""
    if not name or not pw or len(pw) > MAX_PASSWORD:
        raise LoginRefused(GENERIC_FAILURE, 401, "missing or oversized user name or password")
    now = _clock()
    u = find_user(name)
    if u is None:
        _burn_time(pw)
        with _LOGIN_LOCK:
            n, until = _FAILURES.get(name, (0, 0.0))
            if until > now:
                raise LoginRefused(LOCKED, 423, "locked (no such account)")
            n = n + 1
            _FAILURES[name] = (0, now + lockout_seconds()) if n >= lockout_attempts() else (n, 0.0)
            if len(_FAILURES) > 10000:
                _FAILURES.pop(next(iter(_FAILURES)))
        raise LoginRefused(GENERIC_FAILURE, 401, "no such account")
    if float(u.get("locked_until") or 0) > now:
        _burn_time(pw)
        raise LoginRefused(LOCKED, 423, "account locked")
    ok = bool(u.get("password")) and verify_password(pw, u.get("password"))
    if not ok or not u.get("active"):
        if not u.get("password"):
            _burn_time(pw)
        with _LOCK:
            data = _read()
            rec = data["users"].get(u["id"])
            if isinstance(rec, dict):
                rec["failed"] = int(rec.get("failed") or 0) + 1
                locked = rec["failed"] >= lockout_attempts()
                if locked:
                    rec["locked_until"] = now + lockout_seconds()
                    rec["failed"] = 0
                _write(data)
                if locked:
                    _audit("team_account_locked", actor=u.get("username"), user=u.get("username"), minutes=lockout_seconds() // 60,
                           client=client_ip)
        why = "account turned off" if not u.get("active") else "wrong password"
        if store_crypto.fips_mode() and str(u.get("password") or "").startswith("scrypt$"):
            why = "password saved before FIPS mode (scrypt): an administrator must set it again"
        raise LoginRefused(GENERIC_FAILURE, 401, why)
    if int(u.get("failed") or 0) or u.get("locked_until"):
        with _LOCK:
            data = _read()
            rec = data["users"].get(u["id"])
            if isinstance(rec, dict):
                rec.update(failed=0, locked_until=0)
                _write(data)
    return u


def link_oidc(claims: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The account an identity-provider sign-in belongs to: the one already
    linked to its subject, else the one whose user name or email is the
    token's VERIFIED email (then linked to the subject). None: no account,
    or it is turned off. An email the provider did not verify matches nothing."""
    import sso
    sub = str(claims.get("sub") or "")
    data = _read()
    for u in data["users"].values():
        if isinstance(u, dict) and sub and u.get("oidc_sub") == sub:
            return u if u.get("active") else None
    if not sso.email_verified(claims):
        return None
    email = normalize_username(claims.get("email"))
    if not email:
        return None
    for u in data["users"].values():
        if isinstance(u, dict) and (normalize_username(u.get("username")) == email or (u.get("email") or "") == email):
            if not u.get("active") or (u.get("oidc_sub") and u.get("oidc_sub") != sub):
                return None
            with _LOCK:
                d2 = _read()
                rec = d2["users"].get(u["id"])
                if isinstance(rec, dict):
                    rec["oidc_sub"] = sub
                    _write(d2)
            return get_user(u["id"])
    return None


def start_session(user: Dict[str, Any], *, via: str, previous_sid: Optional[str] = None, token_groups: Iterable[str] = ()) -> str:
    """A fresh session for `user` (rotation: the browser's earlier session,
    if any, ends here). Returns the new random id, the cookie's only content."""
    import sso
    if previous_sid:
        sso.end_session(previous_sid)
    return sso.create_session({"sub": user.get("id"), "email": user.get("email") or None},
                              team_user=user.get("id"), via=via, groups=list(token_groups or ()),
                              idle=idle_seconds(), max_seconds=session_seconds())


def _end_sessions(uid: str) -> None:
    try:
        import sso
        sso.end_sessions_for(uid)
    except Exception:  # noqa: BLE001
        pass


# ── SCIM 2.0 ────────────────────────────────────────────────────────────
SCIM_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCIM_LIST = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"
SCIM_PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCIM_ROLES = ("viewer", "operator", "approver")   # SCIM never makes an administrator


def scim_new_token(*, by: str = "") -> str:
    token = "zme-scim-" + secrets.token_urlsafe(32)
    with _LOCK:
        data = _read()
        data["scim"] = {"token_sha256": hashlib.sha256(token.encode("ascii")).hexdigest(), "created": _now_iso(), "created_by": by}
        _write(data)
    _audit("team_scim_token_created", actor=by or None)
    return token


def scim_revoke(*, by: str = "") -> None:
    with _LOCK:
        data = _read()
        data["scim"] = {}
        _write(data)
    _audit("team_scim_token_revoked", actor=by or None)


def scim_status() -> Dict[str, Any]:
    s = _read().get("scim") or {}
    return {"configured": bool(s.get("token_sha256")), "created": s.get("created"), "created_by": s.get("created_by")}


def scim_token_ok(authorization: Any) -> bool:
    auth = str(authorization or "")
    if not auth.lower().startswith("bearer "):
        return False
    offered = auth[7:].strip()
    want = (_read().get("scim") or {}).get("token_sha256")
    if not offered or not want or len(offered) > 512:
        return False
    got = hashlib.sha256(offered.encode("utf-8", "surrogateescape")).hexdigest()
    return hmac.compare_digest(got.encode("ascii"), str(want).encode("ascii", "ignore"))


class ScimError(Exception):
    def __init__(self, status: int, detail: str, scim_type: str = ""):
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type

    def body(self) -> Dict[str, Any]:
        out = {"schemas": [SCIM_ERROR], "status": str(self.status), "detail": self.detail}
        if self.scim_type:
            out["scimType"] = self.scim_type
        return out


def _scim_user(u: Dict[str, Any], base: str) -> Dict[str, Any]:
    data = _read()
    groups = [{"value": g.get("id"), "display": g.get("display_name")} for g in data["groups"].values()
              if isinstance(g, dict) and u.get("id") in (g.get("members") or [])]
    out = {"schemas": [SCIM_USER], "id": u.get("id"), "userName": u.get("username"), "active": bool(u.get("active")),
           "displayName": u.get("display_name") or "", "roles": [{"value": u.get("role"), "primary": True}],
           "groups": groups, "meta": {"resourceType": "User", "created": u.get("created"), "lastModified": u.get("updated"),
                                      "location": f"{base}/Users/{u.get('id')}"}}
    if u.get("email"):
        out["emails"] = [{"value": u.get("email"), "primary": True}]
    if u.get("external_id"):
        out["externalId"] = u.get("external_id")
    return out


def _scim_group(g: Dict[str, Any], base: str) -> Dict[str, Any]:
    data = _read()
    members = [{"value": m, "display": (data["users"].get(m) or {}).get("username")} for m in g.get("members") or [] if m in data["users"]]
    out = {"schemas": [SCIM_GROUP], "id": g.get("id"), "displayName": g.get("display_name"), "members": members,
           "meta": {"resourceType": "Group", "location": f"{base}/Groups/{g.get('id')}"}}
    if g.get("external_id"):
        out["externalId"] = g.get("external_id")
    return out


_FILTER_RE = re.compile(r'^\s*([A-Za-z.]+)\s+eq\s+"((?:[^"\\]|\\.){0,256})"\s*$')


def _scim_filter(flt: Any, allowed: Dict[str, Callable[[Dict[str, Any]], Any]]) -> Optional[Tuple[Callable[[Dict[str, Any]], Any], str]]:
    if not flt:
        return None
    m = _FILTER_RE.match(str(flt)[:400])
    if not m or m.group(1) not in allowed:
        raise ScimError(400, "Only the filters " + ", ".join(f'{a} eq "..."' for a in allowed) + " are supported.", "invalidFilter")
    return allowed[m.group(1)], m.group(2).replace('\\"', '"').replace("\\\\", "\\")


def _page(items: List[Dict[str, Any]], start: Any, count: Any) -> Dict[str, Any]:
    try:
        s = max(1, int(start or 1))
    except (TypeError, ValueError):
        s = 1
    try:
        c = max(0, min(200, int(count if count not in (None, "") else 100)))
    except (TypeError, ValueError):
        c = 100
    page = items[s - 1:s - 1 + c]
    return {"schemas": [SCIM_LIST], "totalResults": len(items), "startIndex": s, "itemsPerPage": len(page), "Resources": page}


def scim_list_users(base: str, flt: Any = None, start: Any = 1, count: Any = None) -> Dict[str, Any]:
    f = _scim_filter(flt, {"userName": lambda u: normalize_username(u.get("username")),
                           "externalId": lambda u: u.get("external_id") or "",
                           "emails.value": lambda u: u.get("email") or ""})
    users = [u for u in _read()["users"].values() if isinstance(u, dict)]
    if f:
        fn, val = f
        users = [u for u in users if str(fn(u)).lower() == normalize_username(val)]
    users.sort(key=lambda u: u.get("username") or "")
    return _page([_scim_user(u, base) for u in users], start, count)


def scim_get_user(uid: str, base: str) -> Dict[str, Any]:
    u = get_user(uid)
    if not u:
        raise ScimError(404, "User not found.")
    return _scim_user(u, base)


def _scim_role(body: Dict[str, Any], default: str) -> str:
    roles = body.get("roles")
    if roles is None:
        return default
    if not isinstance(roles, list):
        raise ScimError(400, "roles is a list.", "invalidValue")
    vals = [str(r.get("value") if isinstance(r, dict) else r).strip().lower() for r in roles]
    vals = [v for v in vals if v]
    if not vals:
        return "viewer"
    for v in vals:
        if v not in SCIM_ROLES:
            raise ScimError(400, f"roles may be {', '.join(SCIM_ROLES)} (an administrator is made on the server itself).", "invalidValue")
    return max(vals, key=SCIM_ROLES.index)


def _scim_email(body: Dict[str, Any]) -> str:
    emails = body.get("emails")
    if isinstance(emails, list):
        prim = [e for e in emails if isinstance(e, dict) and e.get("primary")] or [e for e in emails if isinstance(e, dict)]
        if prim:
            return _clean(prim[0].get("value")).lower()
    return ""


def scim_create_user(body: Dict[str, Any], base: str) -> Dict[str, Any]:
    if not isinstance(body, dict) or not isinstance(body.get("userName"), str):
        raise ScimError(400, "userName is required.", "invalidValue")
    if find_user(body["userName"]):
        raise ScimError(409, "A user with that userName exists.", "uniqueness")
    name_obj = body.get("name")
    display = body.get("displayName") or (name_obj.get("formatted") if isinstance(name_obj, dict) else "") or ""
    try:
        u = create_user(username=body["userName"], role=_scim_role(body, "viewer"), password=None,
                        display_name=display, email=_scim_email(body), source="scim", external_id=body.get("externalId") or "",
                        active=bool(body.get("active", True)), by="SCIM provisioning")
    except TeamError as e:
        raise ScimError(409 if e.status == 409 else 400, str(e), "uniqueness" if e.status == 409 else "invalidValue")
    return _scim_user(u, base)


def scim_replace_user(uid: str, body: Dict[str, Any], base: str) -> Dict[str, Any]:
    u = get_user(uid)
    if not u:
        raise ScimError(404, "User not found.")
    if not isinstance(body, dict):
        raise ScimError(400, "A User object is required.", "invalidValue")
    if u.get("role") == "admin" and body.get("roles") is not None:
        role = None   # SCIM never demotes or promotes an administrator
    else:
        role = _scim_role(body, u.get("role") or "viewer")
    try:
        update_user(uid, by="SCIM provisioning", username=body.get("userName"), display_name=body.get("displayName"),
                    email=_scim_email(body) if "emails" in body else None, external_id=body.get("externalId"),
                    active=bool(body.get("active", True)), role=role)
    except TeamError as e:
        raise ScimError(e.status if e.status in (404, 409) else 400, str(e))
    return _scim_user(get_user(uid) or u, base)


def scim_patch_user(uid: str, body: Dict[str, Any], base: str) -> Dict[str, Any]:
    u = get_user(uid)
    if not u:
        raise ScimError(404, "User not found.")
    ops = _patch_ops(body)
    fields: Dict[str, Any] = {}
    for op, path, value in ops:
        if op not in ("replace", "add"):
            raise ScimError(400, "Only add and replace are supported on a User.", "invalidValue")
        items = [(path, value)] if path else (list(value.items()) if isinstance(value, dict) else [])
        for p, v in items:
            p = str(p or "")
            if p == "active":
                fields["active"] = v if isinstance(v, bool) else str(v).lower() == "true"
            elif p == "displayName":
                fields["display_name"] = v
            elif p == "userName":
                fields["username"] = v
            elif p == "externalId":
                fields["external_id"] = v
            elif p.startswith("emails"):
                fields["email"] = _scim_email({"emails": v if isinstance(v, list) else [{"value": v, "primary": True}]})
            elif p == "roles":
                if u.get("role") != "admin":
                    fields["role"] = _scim_role({"roles": v if isinstance(v, list) else [v]}, u.get("role") or "viewer")
            else:
                raise ScimError(400, f"The attribute {p[:40]!r} cannot be changed here.", "invalidPath")
    try:
        update_user(uid, by="SCIM provisioning", **fields)
    except TeamError as e:
        raise ScimError(e.status if e.status in (404, 409) else 400, str(e))
    return _scim_user(get_user(uid) or u, base)


def scim_delete_user(uid: str) -> None:
    u = get_user(uid)
    if not u:
        raise ScimError(404, "User not found.")
    if u.get("role") == "admin":
        raise ScimError(403, "An administrator is removed on the server itself, not by provisioning.")
    delete_user(uid, by="SCIM provisioning")


def _patch_ops(body: Any) -> List[Tuple[str, str, Any]]:
    if not isinstance(body, dict) or SCIM_PATCH not in (body.get("schemas") or []):
        raise ScimError(400, "A PatchOp message is required.", "invalidSyntax")
    ops = body.get("Operations")
    if not isinstance(ops, list) or not ops or len(ops) > 100:
        raise ScimError(400, "Operations is a list of 1 to 100 operations.", "invalidSyntax")
    out = []
    for o in ops:
        if not isinstance(o, dict):
            raise ScimError(400, "Each operation is an object.", "invalidSyntax")
        out.append((str(o.get("op") or "").lower(), str(o.get("path") or ""), o.get("value")))
    return out


def scim_list_groups(base: str, flt: Any = None, start: Any = 1, count: Any = None) -> Dict[str, Any]:
    f = _scim_filter(flt, {"displayName": lambda g: g.get("display_name") or "", "externalId": lambda g: g.get("external_id") or ""})
    groups = [g for g in _read()["groups"].values() if isinstance(g, dict)]
    if f:
        fn, val = f
        groups = [g for g in groups if str(fn(g)).lower() == val.lower()]
    groups.sort(key=lambda g: str(g.get("display_name") or "").lower())
    return _page([_scim_group(g, base) for g in groups], start, count)


def scim_get_group(gid: str, base: str) -> Dict[str, Any]:
    g = _read()["groups"].get(gid)
    if not isinstance(g, dict):
        raise ScimError(404, "Group not found.")
    return _scim_group(g, base)


def _member_ids(data: Dict[str, Any], members: Any) -> List[str]:
    if members is None:
        return []
    if not isinstance(members, list) or len(members) > MAX_USERS:
        raise ScimError(400, "members is a list.", "invalidValue")
    out = []
    for m in members:
        v = str((m or {}).get("value") if isinstance(m, dict) else m or "")
        if v not in data["users"]:
            raise ScimError(400, "A member is not a known user.", "invalidValue")
        if v not in out:
            out.append(v)
    return out


def scim_create_group(body: Dict[str, Any], base: str) -> Dict[str, Any]:
    name = _clean((body or {}).get("displayName") if isinstance(body, dict) else "")
    if not name:
        raise ScimError(400, "displayName is required.", "invalidValue")
    with _LOCK:
        data = _read()
        if len(data["groups"]) >= MAX_GROUPS:
            raise ScimError(409, "This server already holds the most groups it keeps.")
        if any(str(g.get("display_name") or "").lower() == name.lower() for g in data["groups"].values() if isinstance(g, dict)):
            raise ScimError(409, "A group with that displayName exists.", "uniqueness")
        gid = _new_id()
        data["groups"][gid] = {"id": gid, "display_name": name, "members": _member_ids(data, body.get("members")),
                               "external_id": _clean(body.get("externalId"))}
        _write(data)
    _audit("team_group_created", actor="SCIM provisioning", group=name)
    return scim_get_group(gid, base)


def scim_replace_group(gid: str, body: Dict[str, Any], base: str) -> Dict[str, Any]:
    with _LOCK:
        data = _read()
        g = data["groups"].get(gid)
        if not isinstance(g, dict):
            raise ScimError(404, "Group not found.")
        if not isinstance(body, dict):
            raise ScimError(400, "A Group object is required.", "invalidValue")
        name = _clean(body.get("displayName")) or g.get("display_name")
        g.update(display_name=name, members=_member_ids(data, body.get("members")), external_id=_clean(body.get("externalId") or g.get("external_id")))
        _write(data)
    _audit("team_group_updated", actor="SCIM provisioning", group=name)
    return scim_get_group(gid, base)


_MEMBER_PATH = re.compile(r'^members\[value eq "([a-z0-9-]{1,64})"\]$')


def scim_patch_group(gid: str, body: Dict[str, Any], base: str) -> Dict[str, Any]:
    ops = _patch_ops(body)
    with _LOCK:
        data = _read()
        g = data["groups"].get(gid)
        if not isinstance(g, dict):
            raise ScimError(404, "Group not found.")
        members = list(g.get("members") or [])
        for op, path, value in ops:
            m = _MEMBER_PATH.match(path)
            if path == "members" or (not path and isinstance(value, dict) and "members" in value):
                vals = value.get("members") if (not path and isinstance(value, dict)) else value
                ids = _member_ids(data, vals if isinstance(vals, list) else [vals] if vals else [])
                if op == "add":
                    members += [i for i in ids if i not in members]
                elif op == "replace":
                    members = ids
                elif op == "remove":
                    members = [x for x in members if x not in ids] if ids else []
                else:
                    raise ScimError(400, "op is add, replace or remove.", "invalidSyntax")
            elif m and op == "remove":
                members = [x for x in members if x != m.group(1)]
            elif path == "displayName" or (not path and isinstance(value, dict) and "displayName" in value):
                if op not in ("add", "replace"):
                    raise ScimError(400, "displayName can only be replaced.", "invalidSyntax")
                g["display_name"] = _clean(value.get("displayName") if isinstance(value, dict) else value) or g.get("display_name")
            elif path == "externalId":
                g["external_id"] = _clean(value)
            else:
                raise ScimError(400, f"The attribute {path[:40]!r} cannot be changed here.", "invalidPath")
        g["members"] = members
        _write(data)
    _audit("team_group_updated", actor="SCIM provisioning", group=g.get("display_name"), members=len(members))
    return scim_get_group(gid, base)


def scim_delete_group(gid: str) -> None:
    with _LOCK:
        data = _read()
        g = data["groups"].pop(gid, None)
        if not isinstance(g, dict):
            raise ScimError(404, "Group not found.")
        data["grants"] = [x for x in data["grants"] if x.get("principal") != f"group:{gid}"]
        _write(data)
    _audit("team_group_deleted", actor="SCIM provisioning", group=g.get("display_name"))


def scim_service_provider_config(base: str) -> Dict[str, Any]:
    return {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
            "documentationUri": "", "patch": {"supported": True}, "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
            "filter": {"supported": True, "maxResults": 200}, "changePassword": {"supported": False},
            "sort": {"supported": False}, "etag": {"supported": False},
            "authenticationSchemes": [{"type": "oauthbearertoken", "name": "Bearer token", "primary": True,
                                       "description": "The token an administrator creates on the Team server page (shown once)."}],
            "meta": {"resourceType": "ServiceProviderConfig", "location": f"{base}/ServiceProviderConfig"}}


def scim_resource_types(base: str) -> Dict[str, Any]:
    items = [{"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "User", "name": "User", "endpoint": "/Users",
              "schema": SCIM_USER, "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/User"}},
             {"schemas": ["urn:ietf:params:scim:schemas:core:2.0:ResourceType"], "id": "Group", "name": "Group", "endpoint": "/Groups",
              "schema": SCIM_GROUP, "meta": {"resourceType": "ResourceType", "location": f"{base}/ResourceTypes/Group"}}]
    return {"schemas": [SCIM_LIST], "totalResults": len(items), "startIndex": 1, "itemsPerPage": len(items), "Resources": items}


# ── the access check on every request ───────────────────────────────────
LOGIN_PATH = "/login"
_BODY_ID_PARAMS = tuple(p for p in RESOURCE_PARAMS if p != "tenant")


def _signed_in_session() -> Optional[Dict[str, Any]]:
    try:
        import security
        return (security._CALLER.get() or {}).get("session")
    except Exception:  # noqa: BLE001
        return None


class TeamAccessMiddleware:
    """Team mode only (a pass-through otherwise). For every request: find
    the route, look up its rule (team_routes; none: 403), and check the
    signed-in person against it: the role, the tenant profile the request
    names (path, query or JSON body `profile_id`) and every stored report,
    job or record it names. Sets the request's team context (who, which
    profile, which action) for the handler, the audit log and the jobs it
    starts. Every refusal is audited. Sits inside UIAuthMiddleware, which
    has already turned the session cookie into the caller."""

    def __init__(self, app, routes: Callable[[], Iterable[Any]]):
        self.app = app
        self.routes = routes

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http" or not enabled():
            await self.app(scope, receive, send)
            return
        from starlette.routing import Match, Mount
        import team_routes
        method = str(scope.get("method") or "GET").upper()
        route, params = None, {}
        for r in self.routes():
            m, child = r.matches(scope)
            if m == Match.FULL:
                route, params = r, dict((child or {}).get("path_params") or {})
                break
        if route is None:
            await self.app(scope, receive, send)   # the router answers 404 or 405
            return
        if isinstance(route, Mount):
            mrule = team_routes.MOUNT_RULES.get(route.path)
            rule = (mrule, False) if mrule else None
            template = route.path + "/…"
        else:
            template = getattr(route, "path", "")
            rule = team_routes.rule_for(method, template)
        session = _signed_in_session()
        user = session_user(session)
        groups = list((session or {}).get("groups") or []) if user else []
        ctx = {"user": user.get("id") if user else None, "username": user.get("username") if user else None,
               "role": user.get("role") if user else None, "action": rule[0] if rule else None, "profile": "",
               "token_groups": groups}

        async def deny(status: int, detail: str, reason: str, extra: Optional[Dict[str, Any]] = None):
            from fastapi.responses import JSONResponse
            _audit("team_access_denied", actor=(user or {}).get("username") or None, method=method, path=scope.get("path"),
                   route=template, rule=rule[0] if rule else None, reason=reason,
                   client=str((scope.get("client") or ("?",))[0]))
            body = {"detail": detail}
            if extra:
                body.update(extra)
            await JSONResponse(body, status_code=status)(scope, receive, send)

        if rule is None:
            await deny(403, "This route has no access rule on a team server, so it is refused (deny by default).", "no access rule")
            return
        action, needs_profile = rule
        if action == "public":
            await self._run(ctx, scope, receive, send)
            return
        if action == "scim":
            headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
            if not scim_token_ok(headers.get("authorization")):
                from fastapi.responses import JSONResponse
                _audit("scim_denied", actor="SCIM provisioning", method=method, path=scope.get("path"),
                       reason="missing or wrong bearer token", client=str((scope.get("client") or ("?",))[0]))
                await JSONResponse(ScimError(401, "A valid SCIM bearer token is required.").body(), status_code=401,
                                   media_type="application/scim+json", headers={"WWW-Authenticate": 'Bearer realm="scim"'})(scope, receive, send)
                return
            ctx.update(user=None, username="SCIM provisioning", role=None)
            await self._run(ctx, scope, receive, send)
            return
        if user is None:
            await deny(401, "Sign in required.", "not signed in",
                       {"token_required": True, "sso_required": True, "sso_login_url": LOGIN_PATH})
            return
        admin = user.get("role") == "admin"
        if action == "admin" and not admin:
            await deny(403, f"Only a team server administrator may do this; you are signed in as {user.get('username')} "
                            f"({user.get('role')}).", "not an administrator")
            return
        need = action if action in ACTIONS else "read"
        if action in ACTIONS and need not in ROLE_ACTIONS.get(str(user.get("role")), ()):
            await deny(403, f"Your role ({user.get('role')}) may not {need} on this server. Ask an administrator.", f"role lacks {need}")
            return
        body, receive = await _buffered(scope, receive, method)
        query = _query(scope)
        named = {str(v) for v in (params.get("profile_id"), query.get("profile_id"), (body or {}).get("profile_id")) if isinstance(v, str) and v}
        if len(named) > 1:
            await deny(400, "This request names two different tenant profiles.", "two profiles named")
            return
        profile = next(iter(named), "")
        if profile:
            if need not in actions_on(user, profile, groups):
                await deny(403, f"You ({user.get('username')}) may not {need} on the tenant profile '{profile[:48]}'. "
                                "Ask a team server administrator for access.", f"no {need} on the profile", )
                return
            ctx["profile"] = profile
        elif needs_profile and not admin:
            await deny(403, "Name one of the tenant profiles you have access to (choose it on Connect to the tenant).", "no profile named")
            return
        elif action in ACTIONS and profiles_with(user, need, groups) == set():
            await deny(403, f"You ({user.get('username')}) may not {need} on any tenant profile yet. Ask a team server administrator "
                            "for access.", f"no {need} anywhere")
            return
        names: List[Tuple[str, str]] = []
        for name in RESOURCE_PARAMS:
            for src in (params, query):
                v = src.get(name)
                if isinstance(v, str) and v:
                    names.append((name, v))
        for name in _BODY_ID_PARAMS:
            v = (body or {}).get(name)
            if isinstance(v, str) and v:
                names.append((name, v))
        if not admin:
            for name, value in names:
                if not _may_reach(name, value, need, user, groups, params):
                    await deny(404, "Not found, or not yours to see.", f"{name} not reachable")
                    return
        await self._run(ctx, scope, receive, send)

    async def _run(self, ctx, scope, receive, send):
        token = _CTX.set(ctx)
        try:
            await self.app(scope, receive, send)
        finally:
            reset(token)


def _query(scope) -> Dict[str, str]:
    from urllib.parse import parse_qsl
    try:
        pairs = parse_qsl((scope.get("query_string") or b"").decode("latin-1"), keep_blank_values=True)
    except ValueError:
        return {}
    out: Dict[str, str] = {}
    for k, v in pairs[:200]:
        out.setdefault(k, v)
    return out


async def _buffered(scope, receive, method: str):
    """(the JSON object body or None, a receive that replays it). Only a
    JSON body of a non-GET request is read; the body-size cap outside has
    already bounded it."""
    if method in ("GET", "HEAD", "OPTIONS"):
        return None, receive
    headers = {k.decode("latin-1").lower(): v.decode("latin-1") for k, v in scope.get("headers") or []}
    if "json" not in headers.get("content-type", "").lower():
        return None, receive
    chunks = []
    more = True
    while more:
        msg = await receive()
        if msg.get("type") != "http.request":
            break
        chunks.append(msg.get("body", b""))
        more = msg.get("more_body", False)
    raw = b"".join(chunks)
    replayed = {"done": False}

    async def replay():
        if not replayed["done"]:
            replayed["done"] = True
            return {"type": "http.request", "body": raw, "more_body": False}
        return await receive()
    try:
        parsed = safe_files.strict_json_loads(raw.decode("utf-8")) if raw else None
    except (ValueError, UnicodeDecodeError, RecursionError):
        parsed = None
    return (parsed if isinstance(parsed, dict) else None), replay


def _may_reach(name: str, value: str, action: str, user: Dict[str, Any], groups: List[str], params: Dict[str, str]) -> bool:
    """May `user` reach the stored thing `value` names? Its owner may; so
    may anyone holding `action` on its tenant profile. Unknown: no."""
    hit = bound(value)
    if hit is not None:
        owner, prof = hit
        if name == "report_id" and str(value).startswith("plan-"):
            return may_use("plan", value)   # a saved plan: its owner, or whom it is shared with (and who may read its profile)
        return owner == user.get("id") or (bool(prof) and action in actions_on(user, prof, groups))
    fn = _RESOLVERS.get(name)
    if fn is None:
        return False
    try:
        profs = fn(value, params)
    except Exception:  # noqa: BLE001 - a record that cannot be resolved is not reachable
        return False
    if not profs:
        return False
    return any(action in actions_on(user, p, groups) for p in profs)


# ── ownership and sharing (templates, saved plans) ──────────────────────
SHARE_KINDS = ("template", "plan")


def _share_key(kind: str, rid: Any) -> str:
    if kind not in SHARE_KINDS or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", str(rid or "")):
        raise TeamError("Share a template or a saved plan by its id.", 400)
    return f"{kind}:{rid}"


def set_owner(kind: str, rid: Any) -> None:
    """Record the person making this request as the owner of a template or a
    saved plan (team mode only)."""
    if not enabled():
        return
    c = _CTX.get()
    if not c or not c.get("user"):
        return
    key = _share_key(kind, rid)
    with _LOCK:
        data = _read()
        shares = data.setdefault("shares", {})
        shares[key] = {"owner": c["user"], "principals": [], "at": _now_iso()}
        _write(data)


def sharing(kind: str, rid: Any) -> Optional[Dict[str, Any]]:
    s = (_read().get("shares") or {}).get(_share_key(kind, rid))
    return dict(s) if isinstance(s, dict) else None


def share(kind: str, rid: Any, principals: Any, *, by: str = "") -> Dict[str, Any]:
    """Share a template or saved plan with these users and groups (the whole
    list; empty: only the owner). Only its owner or an administrator may.
    Sharing a plan never lets anyone past the tenant profile it was made
    for: they must still be allowed to read that profile."""
    key = _share_key(kind, rid)
    if not isinstance(principals, list) or len(principals) > 200:
        raise TeamError("principals is a list of user:<id> and group:<id>.")
    with _LOCK:
        data = _read()
        for p in principals:
            k, _, pid = str(p).partition(":")
            if k not in ("user", "group") or pid not in (data["users"] if k == "user" else data["groups"]):
                raise TeamError("Every principal is an existing user:<id> or group:<id>.", 400)
        shares = data.setdefault("shares", {})
        rec = shares.get(key)
        owner = (rec or {}).get("owner")
        if owner is None and kind == "plan":
            hit = bound(rid)
            owner = hit[0] if hit else None
        me = current_user()
        if not me or not (me.get("role") == "admin" or (owner and owner == me.get("id"))):
            raise TeamError("Only its owner or an administrator may share this.", 403)
        rec = {"owner": owner, "principals": sorted(set(str(p) for p in principals)), "at": _now_iso(), "by": by}
        shares[key] = rec
        _write(data)
    _audit("team_shared", actor=by or None, item=key, principals=rec["principals"])
    return rec


def may_use(kind: str, rid: Any) -> bool:
    """May the person making this request see and use this template or saved
    plan? Outside team mode, an administrator, its owner, or someone it is
    shared with; a template from before team mode (no owner) is everyone's.
    A plan also needs read on its tenant profile, shared or not."""
    if not enabled() or _CTX.get() is None or is_admin():
        return True
    u = current_user()
    if not u:
        return False
    rec = sharing(kind, rid) or {}
    owner = rec.get("owner")
    hit = bound(rid) if kind == "plan" else None
    if kind == "plan" and hit:
        owner = owner or hit[0]
    if owner is None:
        return kind == "template"
    if owner == u.get("id"):
        return True
    data = _read()
    mine = {f"user:{u.get('id')}"} | {f"group:{g}" for g in _user_groups(data, str(u.get("id")), current_token_groups())}
    if not mine & set(rec.get("principals") or []):
        return False
    if kind == "plan":
        return bool(hit and hit[1]) and "read" in actions_on(u, hit[1], current_token_groups())
    return True


# ── the first administrator (command line) ──────────────────────────────
def bootstrap_needed() -> bool:
    return enabled() and _active_admins(_read()) == 0


def _cli(argv: Optional[List[str]] = None) -> int:
    """python team_server.py add-admin <user name>   (asks for the password twice)
    python team_server.py reset-password <user name>
    python team_server.py unlock <user name>"""
    import getpass
    import sys
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) != 2 or args[0] not in ("add-admin", "reset-password", "unlock"):
        print(_cli.__doc__)
        return 2
    cmd, name = args
    if cmd == "unlock":
        u = find_user(name)
        if not u:
            print("No such account.")
            return 1
        unlock_user(u["id"], by="command line")
        print(f"{u['username']} is unlocked.")
        return 0
    pw = getpass.getpass("New password: ")
    if pw != getpass.getpass("Again: "):
        print("The two passwords differ; nothing changed.")
        return 1
    try:
        if cmd == "add-admin":
            u = create_user(username=name, role="admin", password=pw, by="command line")
            print(f"Administrator {u['username']} created in {store_path()}.")
        else:
            u = find_user(name)
            if not u:
                print("No such account.")
                return 1
            set_password(u["id"], pw, by="command line")
            print(f"Password of {u['username']} changed; their sessions ended.")
    except TeamError as e:
        print(str(e))
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - command line
    raise SystemExit(_cli())
