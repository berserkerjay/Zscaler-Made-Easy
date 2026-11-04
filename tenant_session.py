"""The signed-in tenant: one verified sign-in, remembered in server memory
for the person and browser that made it, so every page (the expert
pages, the guide and Simple mode) can read the tenant without asking for
the sign-in details again.

What is kept, where, and for how long (SECURITY.md, "Signed-in tenant"):

  * After a successful sign-in check (POST /api/tenant/check) or a
    successful assessment sign-in (POST /api/assess), the credentials that
    signed in are kept in this process's memory only: never written to
    disk, browser storage, a log, an audit entry or a response. A server
    restart forgets them.
  * They are bound to the caller: the UI session (the local UI token, or
    the SSO / team server session and, on a team server, the signed-in
    account) AND this browser (a random, HttpOnly, SameSite=Strict cookie
    that holds only a handle, never a credential). Another browser,
    another SSO session or another team account never finds them.
  * They end after IDLE_SECONDS without use (30 minutes) and, used or not,
    HARD_SECONDS after the sign-in (8 hours); on DELETE /api/tenant/session
    ("Sign out of the tenant"); on signing out of the app; when a sign-in
    check fails; and when another tenant is signed in to (one per caller).
  * Only tenant READS fall back to them (routes whose team_routes rule is
    `read`), and only when the request carries no complete sign-in of its
    own. Writes never do: every write still needs its own sign-in details
    and every existing gate (write mode, a writer, the assessor, the typed
    confirmation, the plan hash, the re-read). Signing in never turns on
    writes.

Clock: `_clock` (monotonic seconds), replaced in tests.
"""
from __future__ import annotations

import contextvars
import hashlib
import secrets
import threading
import time
from typing import Any, Callable, Dict, Iterable, Optional

COOKIE = "zme_signed_in"
IDLE_SECONDS = 30 * 60          # forgotten after 30 minutes without use
HARD_SECONDS = 8 * 3600         # and 8 hours after the sign-in, used or not
TOMBSTONE_SECONDS = 12 * 3600   # how long "your sign-in ended" is remembered (no credentials)
MAX_ENTRIES = 2000              # callers remembered at once; the least recently used goes first
# The routes that sign in and may start remembering a tenant: the cookie
# (a handle) is minted before the response starts, since /api/assess
# signs in inside its stream, after the headers are sent.
SIGN_IN_PATHS = frozenset({("POST", "/api/tenant/check"), ("POST", "/api/assess")})
HANDLE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

_clock: Callable[[], float] = time.monotonic

# This request's caller context: {"handle", "send_cookie", "scope", "routes", "rule"}.
_REQ: "contextvars.ContextVar[Optional[Dict[str, Any]]]" = contextvars.ContextVar("zme_signed_in", default=None)


class _Entry:
    """One remembered sign-in. Its repr never shows a credential."""
    __slots__ = ("owner", "creds", "profile_id", "label", "method", "created", "last_used", "ended")

    def __init__(self, owner: str, creds: Dict[str, str], profile_id: str, label: str, method: str, now: float):
        self.owner = owner
        self.creds: Optional[Dict[str, str]] = dict(creds)
        self.profile_id = profile_id
        self.label = label
        self.method = method
        self.created = now
        self.last_used = now
        self.ended = ""          # "", "idle" or "hard": why it ended (the credentials are then gone)

    def __repr__(self) -> str:   # never the credentials
        return f"<signed-in tenant {self.label!r} ({self.method}){' ended' if self.ended else ''}>"

    def deadline(self) -> float:
        return min(self.last_used + IDLE_SECONDS, self.created + HARD_SECONDS)

    def expire_if_due(self, now: float) -> None:
        if self.ended or now < self.deadline():
            return
        self.ended = "hard" if now >= self.created + HARD_SECONDS else "idle"
        self.creds = None        # the secret is dropped the moment the sign-in ends


_STORE: Dict[str, _Entry] = {}
_LOCK = threading.Lock()


def _h(*parts: str) -> str:
    return hashlib.sha256("\0".join(parts).encode("utf-8", "surrogateescape")).hexdigest()


def _cookie(scope: Dict[str, Any], name: str) -> str:
    """One cookie's value from the raw headers (pair by pair, as offline_tenant)."""
    for k, v in scope.get("headers") or []:
        if k != b"cookie":
            continue
        for pair in v.decode("latin-1").split(";"):
            n, sep, val = pair.partition("=")
            if sep and n.strip() == name:
                return val.strip().strip('"')
    return ""


def _valid_handle(v: str) -> bool:
    return 32 <= len(v) <= 64 and set(v) <= HANDLE_CHARS


class Middleware:
    """Pure ASGI: puts this browser's handle and the request's route in the
    request context, and sets the handle cookie when one was minted for a
    sign-in that succeeded (a status below 400)."""

    def __init__(self, app: Any, routes: Callable[[], Iterable[Any]]):
        self.app = app
        self.routes = routes

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        handle = _cookie(scope, COOKIE)
        ctx: Dict[str, Any] = {"handle": handle if _valid_handle(handle) else "", "send_cookie": False,
                               "scope": scope, "routes": self.routes, "rule": None}
        if not ctx["handle"] and (str(scope.get("method") or "").upper(), scope.get("path")) in SIGN_IN_PATHS:
            ctx["handle"] = secrets.token_urlsafe(32)
            ctx["send_cookie"] = True

        async def _send(message):
            if message.get("type") == "http.response.start" and ctx["send_cookie"] and int(message.get("status", 500)) < 400:
                secure = scope.get("scheme") == "https" or any(
                    k == b"x-forwarded-proto" and v.decode("latin-1").lower() == "https" for k, v in scope.get("headers") or [])
                cookie = (f"{COOKIE}={ctx['handle']}; HttpOnly; SameSite=Strict; Path=/; Max-Age={HARD_SECONDS}"
                          + ("; Secure" if secure else ""))
                message = dict(message)
                message["headers"] = list(message.get("headers") or []) + [(b"set-cookie", cookie.encode("latin-1"))]
            await send(message)

        token = _REQ.set(ctx)
        try:
            await self.app(scope, receive, _send)
        finally:
            _REQ.reset(token)


def _route_rule(ctx: Dict[str, Any]) -> str:
    """The team_routes rule of this request's route ('read', 'apply', ...), '' when none."""
    if ctx.get("rule") is None:
        rule = ""
        try:
            from starlette.routing import Match
            import team_routes
            scope = ctx["scope"]
            for r in ctx["routes"]():
                m, _child = r.matches(scope)
                if m == Match.FULL:
                    found = team_routes.rule_for(str(scope.get("method") or "GET"), getattr(r, "path", ""))
                    rule = found[0] if found else ""
                    break
        except Exception:  # noqa: BLE001 — no rule: no fallback (fail closed)
            rule = ""
        ctx["rule"] = rule
    return ctx["rule"]


def _identity(ctx: Dict[str, Any]) -> str:
    """Who is asking, as an opaque string: the team account and its session,
    the SSO session, or the local UI token. '' when nobody is signed in."""
    import security
    import sso
    import team_server
    sid = _cookie(ctx["scope"], security.SSO_SESSION_COOKIE)
    if team_server.enabled():
        c = team_server.context() or {}
        return f"team\0{c['user']}\0{sid}" if c.get("user") and sid else ""
    caller = security._CALLER.get() or {}
    if sso.sso_enabled():
        return f"sso\0{sid}" if caller.get("session") and sid else ""
    if security.ui_auth_enabled():
        return "local\0" + _h(security.ui_token()) if caller.get("actor") == security.LOCAL_TOKEN_ACTOR else ""
    return "local-open"


def _keys() -> Optional[tuple]:
    """(store key, owner) for this request's caller and browser, or None."""
    ctx = _REQ.get()
    if not ctx or not ctx.get("handle"):
        return None
    who = _identity(ctx)
    if not who:
        return None
    return _h(who, ctx["handle"]), _h(who)


def _sweep(now: float) -> None:
    for k in [k for k, e in _STORE.items() if e.ended and now - e.deadline() > TOMBSTONE_SECONDS]:
        _STORE.pop(k, None)
    for e in _STORE.values():
        e.expire_if_due(now)


def _same(a: Dict[str, str], b: Dict[str, str]) -> bool:
    keys = ("auth_method", "cloud", "vanity_domain", "client_id", "client_secret", "username", "password", "api_key")
    return all(str(a.get(k) or "") == str(b.get(k) or "") for k in keys)


def remember(creds: Dict[str, str], *, profile_id: str = "", label: str = "", method: str = "") -> bool:
    """Keep a sign-in that just succeeded, for this caller and browser
    (replacing another tenant's). Outside a browser request (the assistant,
    a background job) nothing is kept. True when kept."""
    keys = _keys()
    if keys is None:
        return False
    key, owner = keys
    now = _clock()
    with _LOCK:
        _sweep(now)
        old = _STORE.get(key)
        if old is not None and not old.ended and old.creds is not None and _same(old.creds, creds):
            old.last_used = now   # the same sign-in again: still bound to its first sign-in's hard limit
            if profile_id:
                old.profile_id = profile_id
            return True
        _STORE[key] = _Entry(owner, creds, profile_id, label, method, now)
        while len(_STORE) > MAX_ENTRIES:
            oldest = min(_STORE, key=lambda k: _STORE[k].last_used)
            _STORE.pop(oldest, None)
    return True


def _live(touch: bool) -> Optional[_Entry]:
    keys = _keys()
    if keys is None:
        return None
    key, owner = keys
    now = _clock()
    with _LOCK:
        e = _STORE.get(key)
        if e is None or e.owner != owner:
            return None
        e.expire_if_due(now)
        if e.ended or e.creds is None:
            return None
        if touch:
            e.last_used = now
        return e


def for_read() -> Optional[Dict[str, Any]]:
    """This caller's live sign-in, when the request is a tenant read
    (team_routes rule `read`): {"creds", "profile_id"}. None otherwise:
    a write, a route with no rule, or outside a browser request."""
    ctx = _REQ.get()
    if not ctx or _route_rule(ctx) != "read":
        return None
    e = _live(touch=False)
    if e is None or e.creds is None:
        return None
    return {"creds": dict(e.creds), "profile_id": e.profile_id}


def touch() -> None:
    """The sign-in was used: its idle time starts again."""
    _live(touch=True)


def withheld_from_write() -> bool:
    """True when this request is not a read and its caller has a live
    sign-in: the request had to bring its own sign-in details (writes
    never use the remembered one), so a missing field is explained."""
    ctx = _REQ.get()
    if not ctx or _route_rule(ctx) == "read":
        return False
    return _live(touch=False) is not None


def status() -> Dict[str, Any]:
    """What GET /api/tenant/session answers. Never a credential."""
    out: Dict[str, Any] = {"connected": False, "expired": False, "tenant_label": "", "auth_method": "", "profile_id": "",
                           "expires_in": 0, "idle_minutes": IDLE_SECONDS // 60, "max_hours": HARD_SECONDS // 3600}
    keys = _keys()
    if keys is None:
        return out
    key, owner = keys
    now = _clock()
    with _LOCK:
        e = _STORE.get(key)
        if e is None or e.owner != owner:
            return out
        e.expire_if_due(now)
        out.update(tenant_label=e.label, auth_method=e.method, profile_id=e.profile_id)
        if e.ended:
            out["expired"] = True
            out["ended"] = e.ended
        else:
            out["connected"] = True
            out["expires_in"] = max(0, int(e.deadline() - now))
    return out


def forget() -> bool:
    """Forget this caller's sign-in in this browser. True when one was kept."""
    keys = _keys()
    if keys is None:
        return False
    with _LOCK:
        return _STORE.pop(keys[0], None) is not None


def forget_caller() -> int:
    """Signing out of the app: forget every sign-in this caller kept, in
    every browser. Returns how many."""
    ctx = _REQ.get()
    if not ctx:
        return 0
    who = _identity(ctx)
    if not who:
        return 0
    owner = _h(who)
    with _LOCK:
        gone = [k for k, e in _STORE.items() if e.owner == owner]
        for k in gone:
            _STORE.pop(k, None)
    return len(gone)


def clear_all() -> None:
    """Forget every sign-in (tests; a restart does the same)."""
    with _LOCK:
        _STORE.clear()
