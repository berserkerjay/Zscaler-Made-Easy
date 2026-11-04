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
    that holds only a handle, never a credential; `__Host-` prefixed and
    Secure over HTTPS). Another browser, another SSO session or another
    team account never finds them.
  * Every successful sign-in gets a NEW handle from the server: the one the
    browser brought is never kept (session fixation, CWE-384: a page on
    another port of this computer can plant a cookie, since cookies are
    not separated by port). The kept sign-in moves to the new handle and
    the old one finds nothing from then on.
  * A read uses them only when the request came from this app's own page:
    a request another site's page made the browser send (an Origin that is
    not this server's, or Sec-Fetch-Site other than same-origin / none)
    never does, nor, with the UI token gate off, one whose Host header is
    not this computer's loopback.
  * They end after IDLE_SECONDS without use (30 minutes) and, used or not,
    HARD_SECONDS after the sign-in (8 hours), and their secret is dropped
    then: at once on any request, and within REAP_SECONDS by a timer when
    no request comes; on DELETE /api/tenant/session
    ("Sign out of the tenant"); on signing out of the app; when a sign-in
    check or an assessment sign-in fails; and when another tenant is signed
    in to (one per caller).
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
# Over HTTPS: the __Host- prefix makes the browser refuse the cookie unless
# this very host set it with Secure and Path=/ (no sibling host, no plain-HTTP page).
SECURE_COOKIE = "__Host-" + COOKIE
IDLE_SECONDS = 30 * 60          # forgotten after 30 minutes without use
HARD_SECONDS = 8 * 3600         # and 8 hours after the sign-in, used or not
TOMBSTONE_SECONDS = 12 * 3600   # how long "your sign-in ended" is remembered (no credentials)
MAX_ENTRIES = 2000              # callers remembered at once; the least recently used goes first
REAP_SECONDS = 30               # the timer that drops ended sign-ins' secrets when no request comes
# The routes that sign in and may start remembering a tenant: the cookie
# (a handle) is minted before the response starts, since /api/assess
# signs in inside its stream, after the headers are sent.
SIGN_IN_PATHS = frozenset({("POST", "/api/tenant/check"), ("POST", "/api/assess")})
# Sign-ins whose answer starts before the sign-in itself (a stream): the new
# handle is taken when the answer starts. The others take it on success only.
STREAM_SIGN_IN_PATHS = frozenset({("POST", "/api/assess")})
HANDLE_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")

_clock: Callable[[], float] = time.monotonic

# This request's caller context: {"handle", "fresh", "rotated", "send_cookie",
# "cookie", "who", "scope", "routes", "rule"}.
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
_LOCK = threading.RLock()
_REAPER: Optional[threading.Thread] = None


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


def _header(scope: Dict[str, Any], name: bytes) -> str:
    for k, v in scope.get("headers") or []:
        if k == name:
            return v.decode("latin-1").strip()
    return ""


def _https(scope: Dict[str, Any]) -> bool:
    return scope.get("scheme") == "https" or _header(scope, b"x-forwarded-proto").lower() == "https"


def cookie_name(scope: Dict[str, Any]) -> str:
    """The handle cookie's name for this request: `__Host-` prefixed over HTTPS."""
    return SECURE_COOKIE if _https(scope) else COOKIE


def _from_this_app(ctx: Dict[str, Any]) -> bool:
    """Did this app's own page (or a script that is no page at all) send the
    request? A page of another origin, another port of this computer
    included, makes the browser send its Origin and Sec-Fetch-Site; such a
    request never reads with the remembered sign-in. With the UI token gate
    off, the Host header must also name this computer's loopback (DNS
    rebinding)."""
    scope = ctx["scope"]
    site = _header(scope, b"sec-fetch-site").lower()
    if site and site not in ("same-origin", "none"):
        return False
    origin = _header(scope, b"origin").lower().rstrip("/")
    if origin:
        import security
        host = _header(scope, b"host").lower()
        if origin not in security.ALLOWED_ORIGINS and not (host and origin == f"{scope.get('scheme') or 'http'}://{host}"):
            return False
    if ctx.get("who") == "local-open":
        import security
        from starlette.requests import Request
        if not security._loopback_host_header(Request(scope)):
            return False
    return True


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
        name = cookie_name(scope)
        handle = _cookie(scope, name)
        route = (str(scope.get("method") or "").upper(), scope.get("path"))
        ctx: Dict[str, Any] = {"handle": handle if _valid_handle(handle) else "", "fresh": "", "rotated": False,
                               "send_cookie": False, "cookie": name, "who": "",
                               "scope": scope, "routes": self.routes, "rule": None}
        if route in SIGN_IN_PATHS:
            # Every sign-in gets a new handle, never the one the browser
            # brought (it may have been planted: session fixation). Until
            # the sign-in succeeds, the old one is still this browser's.
            ctx["fresh"] = secrets.token_urlsafe(32)

        async def _send(message):
            if (message.get("type") == "http.response.start" and ctx["fresh"] and int(message.get("status", 500)) < 400
                    and (ctx["rotated"] or route in STREAM_SIGN_IN_PATHS)):
                _rotate(ctx)
                cookie = (f"{name}={ctx['handle']}; HttpOnly; SameSite=Strict; Path=/; Max-Age={HARD_SECONDS}"
                          + ("; Secure" if _https(scope) else ""))
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


def _who(ctx: Dict[str, Any]) -> str:
    """The caller's identity, kept for the rest of the request: the answer
    may start after the layers that name the caller have finished."""
    if not ctx.get("who"):
        ctx["who"] = _identity(ctx)
    return ctx["who"]


def _rotate(ctx: Dict[str, Any]) -> None:
    """This request signs in: from now on the browser's handle is the new
    one (the cookie carries it), and a sign-in kept under the old handle
    moves to it, so the old handle finds nothing any more. Once per request."""
    if not ctx.get("fresh") or ctx.get("rotated"):
        return
    who = _who(ctx)
    with _LOCK:
        if who and ctx.get("handle"):
            e = _STORE.pop(_h(who, ctx["handle"]), None)
            if e is not None and e.owner == _h(who):
                _STORE[_h(who, ctx["fresh"])] = e
        ctx["handle"] = ctx["fresh"]
        ctx["rotated"] = True
        ctx["send_cookie"] = True


def _keys() -> Optional[tuple]:
    """(store key, owner) for this request's caller and browser, or None."""
    ctx = _REQ.get()
    if not ctx or not ctx.get("handle"):
        return None
    who = _who(ctx)
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


def reap() -> None:
    """Drop the secret of every sign-in that has ended (and forget long-ended
    ones): what the timer does every REAP_SECONDS, and every request too."""
    with _LOCK:
        _sweep(_clock())


def _reap_forever() -> None:  # pragma: no cover - the timer thread; reap() is tested
    while True:
        time.sleep(REAP_SECONDS)
        try:
            reap()
        except Exception:  # noqa: BLE001 — the next round tries again
            pass


def _start_reaper() -> None:
    global _REAPER
    with _LOCK:
        if _REAPER is None or not _REAPER.is_alive():
            _REAPER = threading.Thread(target=_reap_forever, name="signed-in-tenant-reaper", daemon=True)
            _REAPER.start()


def remember(creds: Dict[str, str], *, profile_id: str = "", label: str = "", method: str = "") -> bool:
    """Keep a sign-in that just succeeded, for this caller and browser
    (replacing another tenant's), under a new handle (_rotate). Outside a
    browser request (the assistant, a background job) nothing is kept.
    True when kept."""
    ctx = _REQ.get()
    if ctx is not None and _who(ctx):
        _rotate(ctx)
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
    _start_reaper()
    return True


def _live(touch: bool) -> Optional[_Entry]:
    keys = _keys()
    if keys is None:
        return None
    key, owner = keys
    now = _clock()
    with _LOCK:
        _sweep(now)              # every ended sign-in's secret goes, not only this caller's
        e = _STORE.get(key)
        if e is None or e.owner != owner:
            return None
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
    if e is not None and not _from_this_app(ctx):
        return None
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
        _sweep(now)
        e = _STORE.get(key)
        if e is None or e.owner != owner:
            return out
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
