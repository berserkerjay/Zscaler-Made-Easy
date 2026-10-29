"""Tenant credentials: the two ways Zscaler Made Easy can sign in to a ZIA tenant.

    oneapi   ZIdentity API client (client id, client secret, vanity domain)
             through OneAPI: <vanity>.zslogin.net and api.zsapi.net.
             The default, and the only way to reach ZPA, ZCC and ZDX.
    legacy   The classic ZIA API (admin username, password and the API key
             from ZIA Administration > API Key Management) against
             zsapi.<cloud>.net. For tenants that have not enabled ZIdentity
             / OneAPI. ZIA only.

One credential dict, the same nine keys everywhere (`CRED_KEYS`), flows
from the form, a saved profile, the environment or tenant_config.json to
the two client stacks: the raw-HTTP assessment client
(dlp_assessment_full_auto.Client) and the Zscaler SDK client the policy
packs use (dlp_api_server._build_sdk_client, sdk_client.SdkClient). This
module owns the shape, the method rules, the environment names, the API
key obfuscation the classic sign-in needs and the SDK legacy client.
"""
from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple

ONEAPI = "oneapi"
LEGACY = "legacy"
METHODS = (ONEAPI, LEGACY)

# Spellings accepted for a method (forms, profiles, environment, scripts).
_METHOD_ALIASES = {
    "oneapi": ONEAPI, "one_api": ONEAPI, "one-api": ONEAPI, "zidentity": ONEAPI, "oauth": ONEAPI, "oauth2": ONEAPI, "api_client": ONEAPI,
    "legacy": LEGACY, "legacy_api": LEGACY, "legacy-api": LEGACY, "classic": LEGACY, "zia": LEGACY, "zia_api": LEGACY,
    "apikey": LEGACY, "api_key": LEGACY, "api-key": LEGACY, "username": LEGACY,
}

CRED_KEYS = ("auth_method", "cloud", "vanity_domain", "client_id", "client_secret", "customer_id", "username", "password", "api_key")
SECRET_KEYS = ("client_secret", "password", "api_key")
# What each method cannot do without.
REQUIRED = {ONEAPI: ("vanity_domain", "client_id", "client_secret"), LEGACY: ("username", "password", "api_key")}
# The identity fields: typed, they say which method the person means.
IDENTITY = {ONEAPI: "client_id", LEGACY: "username"}
LABELS = {"vanity_domain": "vanity domain", "client_id": "API client ID", "client_secret": "API client secret",
          "username": "admin username", "password": "password", "api_key": "API key", "cloud": "cloud"}
# Environment variable per key (local_settings.env / .bat, the container's .env).
ENV = {"auth_method": "ZSCALER_AUTH_METHOD", "cloud": "ZSCALER_CLOUD", "vanity_domain": "ZSCALER_VANITY_DOMAIN",
       "client_id": "ZSCALER_CLIENT_ID", "client_secret": "ZSCALER_CLIENT_SECRET", "customer_id": "ZSCALER_CUSTOMER_ID",
       "username": "ZSCALER_USERNAME", "password": "ZSCALER_PASSWORD", "api_key": "ZSCALER_API_KEY"}

LEGACY_SESSION_PATH = "/api/v1/authenticatedSession"


# ---------------------------------------------------------------------------
# The credential dict
# ---------------------------------------------------------------------------

def normalize_method(value: Any) -> str:
    """'oneapi', 'legacy' or '' (not stated) for any accepted spelling;
    ValueError, naming the two methods, for anything else."""
    v = str(value or "").strip().lower()
    if not v:
        return ""
    if v in _METHOD_ALIASES:
        return _METHOD_ALIASES[v]
    raise ValueError(f"Unknown sign-in method '{str(value)[:40]}'. Use 'oneapi' (ZIdentity API client) or 'legacy' (ZIA admin username, password and API key).")


def method_of(creds: Dict[str, Any]) -> str:
    """The method the credentials are for: the stated one, else legacy when
    a username or API key is given and no client id, else oneapi."""
    stated = normalize_method(creds.get("auth_method"))
    if stated:
        return stated
    if (creds.get("username") or creds.get("api_key")) and not creds.get("client_id"):
        return LEGACY
    return ONEAPI


def normalize(creds: Optional[Dict[str, Any]]) -> Dict[str, str]:
    """Every key of CRED_KEYS as a stripped string, `auth_method` resolved."""
    creds = creds or {}
    out = {k: str(creds.get(k) or "").strip() for k in CRED_KEYS}
    out["auth_method"] = method_of(out)
    return out


def missing(creds: Dict[str, Any]) -> List[str]:
    """The required fields the method still lacks (keys of CRED_KEYS)."""
    c = normalize(creds)
    return [k for k in REQUIRED[c["auth_method"]] if not c[k]]


def complete(creds: Dict[str, Any]) -> bool:
    """True when the method has everything it needs to sign in."""
    return not missing(creds)


def started(creds: Dict[str, Any]) -> bool:
    """True when the person has typed the identity of a tenant (a client id
    or a username), even if the rest is missing."""
    c = normalize(creds)
    return bool(c[IDENTITY[c["auth_method"]]])


def without_identity(creds: Dict[str, Any]) -> Dict[str, str]:
    """The dict with the identity and secret fields blanked (cloud, vanity
    domain and customer id kept): what may be combined with credentials
    from another source without pairing a typed id with a stored secret."""
    c = normalize(creds)
    for k in ("client_id", "client_secret", "username", "password", "api_key"):
        c[k] = ""
    c["auth_method"] = str(creds.get("auth_method") or "")
    return c


def merge(primary: Dict[str, Any], fallback: Dict[str, Any]) -> Dict[str, str]:
    """`primary` wins; blanks are filled from `fallback`. The method stays
    as stated (blank when neither states one): call normalize() to resolve
    it once every source has been consulted."""
    p = {k: str((primary or {}).get(k) or "").strip() for k in CRED_KEYS}
    f = {k: str((fallback or {}).get(k) or "").strip() for k in CRED_KEYS}
    return {k: p[k] or f[k] for k in CRED_KEYS}


def from_env(environ: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Credentials from the ZSCALER_* environment variables."""
    env = os.environ if environ is None else environ
    return normalize({k: env.get(v, "") for k, v in ENV.items()})


def label(creds: Dict[str, Any]) -> str:
    """How the tenant is named in messages: 'acme (zscalerten)' for OneAPI,
    'classic API (zscalerten)' for the legacy sign-in. The same as
    record_label: a label is shown, returned and often kept (a Beacon
    snapshot, a report), so the classic API's admin login and any vanity
    domain left in the form are never part of it (user rule 3)."""
    return record_label(creds)


# The form label() gave a classic-API tenant before it stopped naming the
# admin login: '<login> (<cloud>, classic API)'. Only used to find and
# scrub it in what was kept before (scrub_classic_login).
_OLD_CLASSIC_LABEL = re.compile(r"[^\s()\[\]{}\"']+ \(([^(),]+), classic API\)")


def scrub_classic_login(text: Any) -> Any:
    """`text` with every '<admin login> (<cloud>, classic API)' label the
    app wrote before replaced by 'classic API (<cloud>)'. Anything that is
    not a string is returned as it is."""
    if not isinstance(text, str) or ", classic API)" not in text:
        return text
    return _OLD_CLASSIC_LABEL.sub(lambda m: f"classic API ({m.group(1).strip()})", text)


def record_label(creds: Dict[str, Any]) -> str:
    """How a pack deployment names its tenant on screen and in the
    deployment record: 'acme (zscalerten)' for OneAPI, 'classic API
    (zscalerten)' for the legacy sign-in. The classic API signs in with an
    admin login and no vanity domain, so neither appears here (a stale
    vanity domain left in the form or profile included)."""
    c = normalize(creds)
    cloud = c["cloud"] or "production"
    if c["client_id"].startswith("offline-") and c["vanity_domain"].endswith(".offline.invalid"):
        import offline_tenant   # the sample tenant or a snapshot: named as such, never as a real tenant
        return offline_tenant.label_for(c)
    if c["auth_method"] == LEGACY:
        return f"classic API ({cloud})"
    return f"{c['vanity_domain'] or '?'} ({cloud})"


def record_labels(creds: Dict[str, Any]) -> Tuple[str, ...]:
    """Every label a deployment of this tenant may carry: record_label and,
    for the classic API, the '<vanity or ?> (cloud)' form records were
    written with before."""
    c = normalize(creds)
    cloud = c["cloud"] or "production"
    out = [record_label(c)]
    if c["auth_method"] == LEGACY:
        out.append(f"{c['vanity_domain'] or '?'} ({cloud})")
    return tuple(out)


def identity(creds: Dict[str, Any]) -> str:
    """The masked identity for an error message. The classic API's admin
    login is masked like a client id: an error message can end up in a
    job log or a report, where the login never appears (user rule 3)."""
    c = normalize(creds)
    if c["auth_method"] == LEGACY:
        return f"username={_mask(c['username']) if c['username'] else '?'}"
    return f"client_id={_mask(c['client_id'])}"


def _mask(value: str, keep: int = 3) -> str:
    v = value or ""
    if len(v) <= keep * 2 + 2:
        return "•" * max(3, len(v))
    return f"{v[:keep]}…{v[-keep:]} (len={len(v)})"


# A bearer credential a request carries and an error page can echo back: the
# OneAPI access token (a JWT, "Authorization: Bearer ..."), the classic API's
# JSESSIONID session cookie, an OAuth token field, HTTP Basic credentials.
# None is in `creds`, so they are found by shape. A separator may arrive
# URL-encoded (%20, %3A, %3D, %22, +) when the echo is of a URL.
_SEP = r"(?:[\s:=\"']|%20|%3[aAdD]|%22|\+)+"
# The start of a word: no letter before it. A digit may be (the '0' of an
# escaped space, '%20Basic'), so this is not \b.
_WORD = r"(?<![A-Za-z])"
_TOKEN_ECHO = (
    (re.compile(r"(?i)(" + _WORD + r"bearer" + _SEP + r")[A-Za-z0-9._~+/=-]{8,}"), r"\1[redacted token]"),
    (re.compile(r"(?i)(" + _WORD + r"JSESSIONID" + _SEP + r")[A-Za-z0-9._~+/=-]{8,}"), r"\1[redacted session]"),
    (re.compile(r"(?i)(" + _WORD + r"(?:access|refresh|id)_token[\"']?" + _SEP + r")[A-Za-z0-9._~+/=-]{8,}"), r"\1[redacted token]"),
)
_BASIC = re.compile(r"(?i)(" + _WORD + r"basic" + _SEP + r")([A-Za-z0-9+/_-]{6,}={0,2})")
# A JSON Web Token: found in each run of token characters separately (see
# _redact_jwt_run), never by one regex over the whole text, which takes time
# quadratic in a long run such as "-eyJ-eyJ-eyJ..." (CWE-1333).
_JWT_RUN = re.compile(r"[A-Za-z0-9_.-]+")
_JWT_START = re.compile(r"(?<!\w)eyJ")   # a word boundary before it, as \b


def _redact_basic(m: "re.Match[str]") -> str:
    """HTTP Basic credentials (base64 of 'id:secret'); an English word after
    "basic" ("basic settings") is not base64 of a pair and stays."""
    import base64
    import binascii
    raw = m.group(2)
    try:
        decoded = base64.b64decode(raw.replace("-", "+").replace("_", "/") + "=" * (-len(raw) % 4), validate=True)
    except (binascii.Error, ValueError):
        return m.group(0)
    return m.group(1) + "[redacted credentials]" if b":" in decoded else m.group(0)


def _redact_jwt_run(m: "re.Match[str]") -> str:
    """One run of token characters with every JSON Web Token in it replaced:
    'eyJ' at a word boundary, at least 6 more characters, a dot, at least 6
    characters, a dot, and the signature (any length). Within one
    dot-separated part only its first such start can match (every later one
    reaches the same part end and the same parts after it, with less before
    it), so each part is looked at once: linear in the run's length."""
    run = m.group(0)
    if "eyJ" not in run:
        return run
    # The character before the run (a non-token one) can still be a word
    # character ('é'): then the run's first 'eyJ' is not at a word boundary.
    glued = m.start() > 0 and bool(re.match(r"\w", m.string[m.start() - 1]))
    parts = run.split(".")
    out: List[str] = []
    i = 0
    while i < len(parts):
        p = parts[i]
        s = _JWT_START.search(p)
        if s and i == 0 and s.start() == 0 and glued:
            s = _JWT_START.search(p, 1)
        if s and len(p) - s.start() >= 9 and i + 2 < len(parts) and len(parts[i + 1]) >= 6:
            out.append(p[:s.start()] + "[redacted token]")
            i += 3
            continue
        out.append(p)
        i += 1
    return ".".join(out)


def redact_tokens(text: str) -> str:
    """`text` with every bearer access token, JSON Web Token, OAuth token
    field, HTTP Basic credential and classic session id replaced by a fixed
    marker: an API error page (a gateway, a proxy) may echo the request's
    Authorization header or cookie, and that text then reaches a job log, a
    result, an export or a POV file."""
    out = str(text or "")
    for rx, repl in _TOKEN_ECHO:
        out = rx.sub(repl, out)
    out = _BASIC.sub(_redact_basic, out)
    return _JWT_RUN.sub(_redact_jwt_run, out)


def mask_secrets(text: str, creds: Dict[str, Any]) -> str:
    """`text` with every secret value of `creds` replaced by a fixed
    '[redacted <field>]', so an error can be shown without leaking a
    password or a key. No character and no length of a secret is kept;
    partial masking (_mask) is only for identifiers such as client_id.
    A secret echoed back in an error is masked in the forms a request
    carries it too: as typed, form/URL-encoded (the OAuth token request is
    a form post), JSON-escaped (the classic sign-in is a JSON body),
    base64 (alone, or as HTTP Basic '<id>:<secret>'), and any piece of
    SECRET_FRAGMENT or more characters of it (an echo cut short). Bearer
    tokens, JSON Web Tokens and session ids are masked by shape
    (redact_tokens)."""
    # Tokens first, while their shape is whole (a secret masked inside one
    # would leave the rest of it unrecognised).
    out = redact_tokens(str(text or ""))
    c = creds or {}
    # HTTP Basic: base64 of '<id>:<secret>' (OAuth client_secret_basic, a
    # classic admin login), which contains neither value as typed.
    for ident, k in (("client_id", "client_secret"), ("username", "password")):
        v, who = str(c.get(k) or ""), str(c.get(ident) or "")
        if v:
            for form in sorted(_base64_forms(f"{who}:{v}"), key=len, reverse=True):
                out = out.replace(form, f"[redacted {k}]")
    for k in SECRET_KEYS:
        v = str(c.get(k) or "")
        if not v:
            continue
        forms = sorted(secret_forms(v), key=len, reverse=True)
        # A piece of base64 also starts every other base64 text that begins
        # with the same bytes: only whole base64 forms are masked.
        b64 = _base64_forms(v)
        for form in forms:
            if form in out:
                out = out.replace(form, f"[redacted {k}]")
        out = _mask_fragments(out, [f for f in forms if f not in b64], f"[redacted {k}]")
    return redact_tokens(out)


# A piece of a secret this long or longer is masked too: an error that cuts
# the echoed request short ("...secret=S3cr3t-Val…") or starts in the middle
# of it still shows no part of the secret worth having.
SECRET_FRAGMENT = 8


def _mask_fragments(text: str, forms: List[str], marker: str) -> str:
    """`text` with every run of SECRET_FRAGMENT or more characters that is
    part of one of `forms` replaced by `marker` (one marker per run)."""
    hit = bytearray(len(text))
    n = SECRET_FRAGMENT
    for form in forms:
        if len(form) <= n:
            continue
        for w in {form[j:j + n] for j in range(len(form) - n + 1)}:
            at = text.find(w)
            while at != -1:
                hit[at:at + n] = b"\x01" * n
                at = text.find(w, at + 1)
    if not any(hit):
        return text
    out, i = [], 0
    while i < len(text):
        if hit[i]:
            while i < len(text) and hit[i]:
                i += 1
            out.append(marker)
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


def _base64_forms(value: str) -> set:
    """`value` base64-encoded (standard and URL-safe, padded and not)."""
    import base64
    raw = value.encode("utf-8", "surrogatepass")
    std = base64.b64encode(raw).decode("ascii")
    url = base64.urlsafe_b64encode(raw).decode("ascii")
    return {f for f in (std, url, std.rstrip("="), url.rstrip("=")) if f}


def secret_forms(value: str) -> set:
    """`value` as typed and in the encodings a request may carry it in
    (URL path/query with every character escaped or only the reserved ones,
    form body, JSON string, base64), each of which an error that echoes the
    request can show."""
    from urllib.parse import quote, quote_plus
    import json as _json
    v = str(value or "")
    if not v:
        return set()
    every = "".join(f"%{b:02X}" for b in v.encode("utf-8", "surrogatepass"))   # a client that escapes every byte
    forms = {v, quote(v, safe=""), quote_plus(v, safe=""), every, _json.dumps(v)[1:-1], _json.dumps(v, ensure_ascii=False)[1:-1]}
    forms |= {re.sub(r"%[0-9A-F]{2}", lambda m: m.group(0).lower(), f) for f in forms}   # %2b as well as %2B
    forms |= _base64_forms(v)
    return {f for f in forms if f}


# ---------------------------------------------------------------------------
# The classic ZIA sign-in
# ---------------------------------------------------------------------------

def obfuscate_api_key(api_key: str, now_ms: Optional[int] = None) -> Tuple[int, str]:
    """The (timestamp, obfuscated key) pair the classic ZIA API expects in
    POST /api/v1/authenticatedSession: the key is rebuilt from the API
    key's characters picked by the digits of the timestamp's last six
    digits and of that number halved, exactly as Zscaler documents it."""
    now = int(now_ms if now_ms is not None else time.time() * 1000)
    seed = list(api_key or "")
    if len(seed) < 12:
        raise ValueError("The ZIA API key is 12 characters; this one is shorter.")
    n = str(now)[-6:]
    r = str(int(n) >> 1).zfill(6)
    key = "".join(seed[int(ch)] for ch in n)
    for ch in r:
        key += seed[int(ch) + 2]
    return now, key


def legacy_login_payload(username: str, password: str, api_key: str, now_ms: Optional[int] = None) -> Dict[str, Any]:
    """The JSON body of the classic sign-in."""
    ts, key = obfuscate_api_key(api_key, now_ms)
    return {"apiKey": key, "username": username, "password": password, "timestamp": ts}


# OneAPI-only ZIA services (not on the SDK's legacy helper) that the app
# uses: built on the helper's own request executor, which rewrites the
# OneAPI path prefix to the classic /api/v1 one.
_ONEAPI_ONLY_SERVICES = {
    "endpoint_dlp_rules": ("zscaler.zia.endpoint_dlp_rules", "EndpointDLPRulesAPI"),
    "endpoint_dlp_sub_rules": ("zscaler.zia.endpoint_dlp_sub_rules", "EndpointDLPSubRulesAPI"),
    "outbound_email_dlp_rules": ("zscaler.zia.outbound_email_dlp_rules", "OutboundEmailDLPRulesAPI"),
    "endpoint_application_groups": ("zscaler.zia.endpoint_application_groups", "EndpointApplicationGroupsAPI"),
    "endpoint_applications": ("zscaler.zia.endpoint_applications", "EndpointApplicationsAPI"),
    "end_user_notification_templates": ("zscaler.zia.end_user_notification_templates", "EndUserNotificationTemplatesAPI"),
    "dlp_endpoint_resource": ("zscaler.zia.dlp_endpoint_resource", "DLPEndpointResourceAPI"),
}


class LegacyZiaServices:
    """`client.zia` for the classic sign-in: every service the SDK's legacy
    helper has, plus the OneAPI-only ones built on the same executor."""

    def __init__(self, helper: Any):
        self._helper = helper

    def __getattr__(self, name: str) -> Any:
        helper = self.__dict__.get("_helper")
        if helper is not None and hasattr(helper, name):
            return getattr(helper, name)
        spec = _ONEAPI_ONLY_SERVICES.get(name)
        if spec is None or helper is None:
            raise AttributeError(f"{name} is not available through the classic ZIA API sign-in")
        import importlib
        module = importlib.import_module(spec[0])
        return getattr(module, spec[1])(helper.request_executor)


class LegacyZiaClient:
    """The object the rest of the app expects from the SDK: `.zia` with the
    ZIA services, `authenticate()` and `close()`. Everything the policy
    packs do goes through `.zia.<service>` with the same (data, response,
    error) answers as the OneAPI client."""

    use_legacy_client = True

    def __init__(self, helper: Any):
        self._helper = helper
        self.zia = LegacyZiaServices(helper)

    def authenticate(self) -> bool:
        """The helper signed in when it was built; make sure the session is
        still valid (it idles out after five minutes)."""
        ensure = getattr(self._helper, "ensure_valid_session", None)
        if callable(ensure):
            ensure()
        return True

    def set_session(self, session: Any) -> None:
        """The requests.Session every classic-API request is sent on
        (zia_rate.attach_client gives it a paced one)."""
        self._helper._dlp_check_session = session

    def close(self) -> None:
        end = getattr(self._helper, "deauthenticate", None)
        if callable(end):
            try:
                end()
            except Exception:  # noqa: BLE001 — best effort
                pass

    def __getattr__(self, name: str) -> Any:
        # ZPA, ZCC, ZDX and the rest have no classic client: say so plainly.
        raise AttributeError(f"{name} is not available with the classic ZIA API sign-in; it covers ZIA only")


# The SDK's OneAPI sign-in (zscaler.oneapi_oauth_client) posts the client
# secret with the module-level requests.post and no timeout at all, so a
# sign-in host that accepts the connection and never answers holds the
# request thread forever (its requestTimeout covers API calls only).
# bound_sdk_sign_in() gives that module a requests whose calls carry
# SDK_SIGN_IN_TIMEOUT whenever the SDK passes none; nothing else changes.
SDK_SIGN_IN_TIMEOUT = (10, 30)   # (connect, read) seconds


class _BoundedRequests:
    """The requests module, with a timeout on every call that has none."""

    def __init__(self, module: Any) -> None:
        self._requests = module

    def __getattr__(self, name: str) -> Any:
        return getattr(self._requests, name)

    def _bounded(self, call: str, *args: Any, **kwargs: Any) -> Any:
        if kwargs.get("timeout") is None:
            kwargs["timeout"] = SDK_SIGN_IN_TIMEOUT
        return getattr(self._requests, call)(*args, **kwargs)

    def request(self, *args: Any, **kwargs: Any) -> Any:
        return self._bounded("request", *args, **kwargs)

    def get(self, *args: Any, **kwargs: Any) -> Any:
        return self._bounded("get", *args, **kwargs)

    def post(self, *args: Any, **kwargs: Any) -> Any:
        return self._bounded("post", *args, **kwargs)


def bound_sdk_sign_in() -> None:
    """Make the SDK's OneAPI token request time out (idempotent; a no-op
    when the SDK is not installed)."""
    try:
        import zscaler.oneapi_oauth_client as oauth
    except ImportError:
        return
    if not isinstance(oauth.requests, _BoundedRequests):
        oauth.requests = _BoundedRequests(oauth.requests)


def build_legacy_sdk_client(creds: Dict[str, Any], *, timeout: int = 90, max_retries: int = 2,
                            max_retry_seconds: int = 30) -> LegacyZiaClient:
    """Sign in to the classic ZIA API through the Zscaler SDK's legacy
    helper (it signs in as it is built, so a bad password raises here).
    Every request it then sends goes through _legacy_send: paced, stoppable
    and with the same bounded 429 waits as the OneAPI client."""
    from zscaler.zia.legacy import LegacyZIAClientHelper
    import zscaler_clouds
    c = normalize(creds)
    helper = LegacyZIAClientHelper(cloud=zscaler_clouds.legacy_cloud_name(c["cloud"]), timeout=timeout,
                                   username=c["username"], password=c["password"], api_key=c["api_key"],
                                   override_url=zscaler_clouds.legacy_api_base(c["cloud"]))
    install_legacy_send(helper, max_retries=max_retries, max_retry_seconds=max_retry_seconds)
    return LegacyZiaClient(helper)


# ---------------------------------------------------------------------------
# The classic API's requests: paced, stoppable, bounded 429 waits
# ---------------------------------------------------------------------------
#
# The SDK's own LegacyZIAClientHelper.send retries a 429 by itself up to five
# times, sleeping ZIA's whole Retry-After (an hour on the hourly limit) with
# no cap and no Stop check, then sends again; and it calls the module-level
# requests.request, so no paced session (zia_rate.attach) ever sees it. The
# helper's send is replaced by _legacy_send, which:
#   - checks the thread's Stop hook (zia_rate.stopping_on, bound by
#     pack_ops.call around every pack write) before every request and during
#     every wait (user rule 4); the activation and read-back after Stop go out;
#   - sends through a requests.Session that zia_rate.attach_client paces at
#     ZIA's read and write limits, like the OneAPI client's session;
#   - waits a short 429 out (Retry-After up to max_retry_seconds) at most
#     max_retries times, and answers a longer one with the SDK's RetryTooLong
#     ("Retry wait time N seconds exceeds configured maxRetrySeconds M."),
#     exactly as the OneAPI client does, so pack_ops / pack_export wait it
#     out in their own stoppable steps or stop the run with the reason.

LEGACY_NETWORK_RETRY_SECONDS = 5.0
_STOP_STEP = 0.5
_sleep = time.sleep   # patched by tests


def _legacy_stop_requested() -> bool:
    """Stop for a classic-API request: only the thread's stop hook
    (zia_rate.stopping_on), exactly as the OneAPI client's paced session.
    pack_ops.call binds that hook around every pack write, so a write is not
    sent (nor sent again after a 429 wait) once the run is stopped. The
    run's stop state alone never refuses a request: after Stop or a fatal
    stop the run still activates what was written and reads it back
    (pack_jobs.cancel: "activation and the read-back still run"), which
    would otherwise stay pending in the tenant (B2-2)."""
    import zia_rate
    return zia_rate.stop_requested()


def _legacy_not_sent() -> Exception:
    import zia_rate
    return zia_rate.Cancelled("stopped before it went out; the request was not sent")


def _legacy_wait(seconds: float) -> None:
    """Sleep `seconds` in short steps; Stop ends the wait (Cancelled)."""
    left = max(0.0, float(seconds))
    while left > 0:
        if _legacy_stop_requested():
            raise _legacy_not_sent()
        step = min(_STOP_STEP, left)
        _sleep(step)
        left -= step


def _retry_after_seconds(headers: Any) -> int:
    """ZIA's Retry-After ('3300 seconds', '0 seconds' or '12'), at least 1
    and at most RETRY_AFTER_CAP: the header is the server's text, and a
    number too large for a float (inf) would raise instead of waiting."""
    raw = ""
    try:
        raw = str((headers or {}).get("Retry-After") or "")[:64]
    except Exception:  # noqa: BLE001
        raw = ""
    m = re.search(r"\d+(?:\.\d+)?", raw)
    if not m:
        return 2
    secs = float(m.group(0))
    return max(1, int(min(secs, RETRY_AFTER_CAP))) if secs == secs else 2


RETRY_AFTER_CAP = 7 * 24 * 3600   # longer than any limit ZIA has: still RetryTooLong, never an OverflowError


def install_legacy_send(helper: Any, *, max_retries: int = 2, max_retry_seconds: int = 30) -> Any:
    """Replace `helper.send` (the one door every SDK service on the classic
    client goes through) with _legacy_send, and give the helper the session
    it sends on (LegacyZiaClient.set_session swaps in the paced one)."""
    import types
    import requests
    helper._dlp_check_session = requests.Session()
    helper._dlp_check_limits = (max(0, int(max_retries)), max(0, int(max_retry_seconds)))
    helper.send = types.MethodType(_legacy_send, helper)
    return helper


def _legacy_send(helper: Any, method: str, path: str, json: Optional[Dict[str, Any]] = None,
                 params: Optional[Dict[str, Any]] = None, data: Any = None,
                 headers: Optional[Dict[str, str]] = None) -> Tuple[Any, Dict[str, Any]]:
    """LegacyZIAClientHelper.send, with Stop, pacing and bounded 429 waits
    (see above). Returns (response, request info) like the SDK's."""
    import requests
    from zscaler.errors.response_checker import check_response_for_error
    session = getattr(helper, "_dlp_check_session", None) or requests.Session()
    max_retries, max_retry_seconds = getattr(helper, "_dlp_check_limits", (2, 30))
    url = f"{helper.url}/{path.lstrip('/')}"
    retries = 0
    while True:
        if _legacy_stop_requested():
            raise _legacy_not_sent()
        helper.ensure_valid_session()
        sent_headers = dict(helper.headers or {})
        sent_headers.update(headers or {})
        sent_headers["Cookie"] = f"JSESSIONID={helper.session_id}"
        kwargs: Dict[str, Any] = {"method": method, "url": url, "data": data, "params": params,
                                  "headers": sent_headers, "timeout": helper.timeout}
        if "/pacFiles/validate" not in path:   # PAC validation is sent as raw data (as the SDK does)
            kwargs["json"] = json
        try:
            resp = session.request(**kwargs)
        except requests.RequestException:
            if retries >= max_retries:
                raise
            retries += 1
            _legacy_wait(LEGACY_NETWORK_RETRY_SECONDS)
            continue
        if resp.status_code == 429:
            secs = _retry_after_seconds(resp.headers)
            if secs > max_retry_seconds:
                from zscaler.exceptions.exceptions import RetryTooLong
                raise RetryTooLong(f"Retry wait time {secs} seconds exceeds configured maxRetrySeconds {max_retry_seconds}.")
            if retries < max_retries:
                retries += 1
                _legacy_wait(secs)
                continue
        _, err = check_response_for_error(url, resp, resp.text)
        if err:
            raise err
        return resp, {"method": method, "url": url, "params": params or {}, "headers": sent_headers, "json": json or {}}


def describe(method: str) -> str:
    """One line for messages and docs."""
    return ("the classic ZIA API (admin username, password and API key at zsapi.<cloud>.net; ZIA only)" if method == LEGACY
            else "OneAPI (a ZIdentity API client: client ID, client secret and vanity domain)")


def keys_for(method: str) -> Iterable[str]:
    return REQUIRED[normalize_method(method) or ONEAPI]
