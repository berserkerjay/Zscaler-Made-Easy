#!/usr/bin/env python3
"""
Zscaler DLP Assessment Automation Engine — Full Auto
=====================================================
Zero-touch tenant assessment against DLP Assessment Checklist v3.0.
Every check automated via OneAPI — no manual steps.

Requirements: pip install requests rich
Usage:
    python dlp_assessment_full_auto.py
    python dlp_assessment_full_auto.py --config tenant.json
    python dlp_assessment_full_auto.py --config tenant.json --output report.json
"""

import argparse, json, os, sys, time
from datetime import datetime, timezone

try:
    import requests
except ImportError:
    print("ERROR: pip install requests"); sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.prompt import Prompt, Confirm
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

import tenant_auth
import zscaler_clouds

CLOUDS = list(zscaler_clouds.CLOUDS)

# What the classic ZIA API sign-in answers for the services it does not
# cover (ZPA, ZCC, ZDX, ZIdentity): a clear "not here", not a guess.
_LEGACY_ZIA_ONLY = ({"error": "not available with the classic ZIA API sign-in (it covers ZIA only); use a ZIdentity API client for this scope",
                     "status": 404, "legacy": True}, 404)

def _base_url(cloud):
    """The OneAPI gateway for the tenant's cloud: api.zsapi.net for every
    commercial cloud (zscaler.net ... zscalerten.net), the beta gateway for
    zscalerbeta, the FedRAMP gateways for zscalergov.net / zscalergov.us."""
    return zscaler_clouds.api_base(cloud)

def _token_url(vd, cloud):
    """The OAuth2 token endpoint for the tenant's cloud (zslogin.net for
    commercial clouds, the government identity provider for FedRAMP)."""
    return zscaler_clouds.token_url(vd, cloud)

# OneAPI service path prefixes (confirmed via SDK source + Postman)
# ZCC OneAPI uses function-style endpoints (not REST collections)
# A value may be a list of candidate paths: the first that does not answer
# 400/404/405 wins (the app-profile path differs between API generations).
_ZCC_MAP = {
    "appProfiles":        ["web/policy/listByCompany", "webPolicy/listByCompany", "webPolicies/listByCompany"],
    "webPolicies":        ["web/policy/listByCompany", "webPolicy/listByCompany", "webPolicies/listByCompany"],
    "forwardingProfiles": "webForwardingProfile/listByCompany",
    "forwardingProfile":  "webForwardingProfile/listByCompany",
    "devices":            "getDevices",
    "deviceDetails":      "getDeviceDetails",
    "deviceStats":        "web/getDeviceStats",
    "deviceLookup":       "web/device/Lookup/udid",
    "trustedNetworks":    "webTrustedNetwork/listByCompany",
    "failOpenPolicy":     "webFailOpenPolicy/listByCompany",
    "companyInfo":        "getCompanyInfo",
    "webAppService":      "webAppService/listByCompany",
    "postureProfiles":    "appPostureInfo/listByCompany",
    "machineTunnel":      "webMachineTunnel/listByCompany",
    "browserProtection":  "webBrowserProtectionProfile/listByCompany",
    "pacFiles":           "getPacFiles",
    "zpnModuleMode":      "webZPNModuleMode/listByCompany",
    "appBypass":          "webBypassAppConfig/listByCompany",
    "privacyInfo":        ["getWebPrivacyInfo", "webPrivacyInfo/listByCompany"],
    "deviceCleanup":      "getDeviceCleanupInfo",
    "deviceGroups":       "webDeviceGroups/listByCompany",
    "lastPostureFields":  "web/getLastAppPostureFields",
    "downloadStatus":     "downloadServiceStatus",
    # Confirmed from zscaler-sdk-python/master/zscaler/zcc/*.py
    "adminUsers":         "getAdminUsers",
    "adminRoles":         "getAdminRoles",
    "adminUsersSyncInfo": "getAdminUsersSyncInfo",
    "zdxEntitlements":    "getZdxGroupEntitlements",
    "zpaEntitlements":    "getZpaGroupEntitlements",
    "downloadDevices":    "downloadDevices",
    "downloadDisableReasons": "downloadDisableReasons",
    "getDeviceCleanupInfo":   "getDeviceCleanupInfo",
}

# ZDX endpoints — zscaler-sdk-python zdx/, verified on a tenant: the
# configured applications are /apps and the device list is /devices.
_ZDX_MAP = {
    "administration/apps":     "apps",
    "troubleshooting/devices": "devices",
}

# ZPA endpoints — zscaler-sdk-python zpa/, verified on a tenant. Most live
# on the v1 customer base; IdPs, trusted networks, posture profiles, SAML
# attributes and log streaming are on v2, and policy rules are listed per
# policy type (/policySet/rules/policyType/{type}).
_ZPA_MAP = {
    "idp":                            ("v2", "idp"),
    "trustedNetwork":                 ("v2", "network"),
    "postureProfile":                 ("v2", "posture"),
    "samlAttribute":                  ("v2", "samlAttribute"),
    "lssConfig":                      ("v2", "lssConfig"),
    "applicationSegments":            ("v1", "application"),
    "appConnectors":                  ("v1", "connector"),
    "policySet/rules/ACCESS_POLICY":  ("v1", "policySet/rules/policyType/ACCESS_POLICY"),
    "policySet/rules/TIMEOUT_POLICY": ("v1", "policySet/rules/policyType/TIMEOUT_POLICY"),
}

# ZIdentity endpoints — from zscaler-sdk-python/zid/, served at
# /ziam/admin/api/v1 on the OneAPI gateway. Entitlements are per user
# (/users/{id}/service-entitlements); there is no list of all of them.
_ZID_MAP = {
    "users":             "users",
    "groups":            "groups",
    "resourceServers":   "resource-servers",
}

def _resolve_candidates(ep, customer_id="", legacy=False):
    """Every real OneAPI path a short endpoint may live at, best first."""
    if legacy:
        return [_resolve_ep(ep, customer_id, legacy=True)]
    if ep.startswith("/zcc/"):
        suffix = ep[5:]
        mapped = _ZCC_MAP.get(suffix, suffix)
        if isinstance(mapped, (list, tuple)):
            return ["/zcc/papi/public/v1/" + m for m in mapped]
        return ["/zcc/papi/public/v1/" + mapped]
    return [_resolve_ep(ep, customer_id)]


def _resolve_ep(ep, customer_id="", legacy=False):
    """Translate a short endpoint like /zia/webDlpRules to the real OneAPI path.

    Prefix 'raw:' to send the path verbatim (no /zia/api/v1/ rewrite) —
    useful for probing alternative OneAPI path conventions.

    With `legacy` (the classic ZIA API at zsapi.<cloud>.net) a ZIA path
    becomes /api/v1/…; every other service has no classic path, so None.
    """
    if ep.startswith("raw:"):
        return ep[4:]  # bypass resolver
    if legacy:
        return "/api/v1/" + ep[5:] if ep.startswith("/zia/") else None
    if ep.startswith("/zia/"):
        return "/zia/api/v1/" + ep[5:]
    if ep.startswith("/zcc/"):
        suffix = ep[5:]
        mapped = _ZCC_MAP.get(suffix, suffix)
        if isinstance(mapped, (list, tuple)):
            mapped = mapped[0]
        return "/zcc/papi/public/v1/" + mapped
    if ep.startswith("/zdx/"):
        suffix = ep[5:]
        mapped = _ZDX_MAP.get(suffix, suffix)
        return "/zdx/v1/" + mapped
    if ep.startswith("/zid/"):
        suffix = ep[5:]
        mapped = _ZID_MAP.get(suffix, suffix)
        return "/ziam/admin/api/v1/" + mapped
    if ep.startswith("/zpa/"):
        version, suffix = _ZPA_MAP.get(ep[5:], ("v1", ep[5:]))
        if customer_id:
            return f"/zpa/mgmtconfig/{version}/admin/customers/{customer_id}/" + suffix
        return f"/zpa/mgmtconfig/{version}/" + suffix
    return ep

# What a read answers once the run is stopped (Client.stop): nothing was sent.
_STOPPED = ({"error": "run stopped", "status": 0}, 0)
# Answers that mean the tenant did not answer a read (channel_scope.ScopedClient.UNANSWERED).
_UNANSWERED_CODES = frozenset({0, 429, 502, 503, 504})


class _RateLimiter:
    """One request pacer shared by every thread of a Client: keeps a minimum
    gap between requests (the API's rate limit is per tenant, not per
    thread) and, after a 429, holds every thread until Retry-After has
    passed instead of letting them each hit the limit in turn."""
    def __init__(s, min_gap):
        import threading
        s.min_gap = float(min_gap); s._lock = threading.Lock(); s._next = 0.0; s._pause_until = 0.0
    def wait(s, stopped=None):
        while True:
            if stopped is not None and stopped.is_set():
                return                      # the run was stopped: the caller sends nothing
            with s._lock:
                now = time.time()
                at = max(now, s._next, s._pause_until)
                if at - now < 5:            # short waits are booked inside the lock
                    s._next = at + s.min_gap
                    delay = at - now
                    break
            time.sleep(1)                   # long pause (429): re-check every second
        if delay > 0:
            time.sleep(delay)
    def pause(s, seconds):
        with s._lock:
            s._pause_until = max(s._pause_until, time.time() + float(seconds))


class Client:
    """One signed-in session against the tenant, a bounded response cache and
    a request pacer shared by every check.

    Two sign-ins (tenant_auth): OneAPI, an OAuth2 client-credentials token
    from ZIdentity used against api.zsapi.net (the default; ZPA, ZCC and
    ZDX are reachable); or the classic ZIA API, a JSESSIONID session opened
    with the admin username, password and obfuscated API key against
    zsapi.<cloud>.net (`auth_method="legacy"`; ZIA only, every other
    service answers 404 with a plain reason). Short endpoints such as
    /zia/webDlpRules work the same on both."""
    # Bound the response cache so a long-lived client process can't grow unbounded.
    # Each entry is a small dict; 512 is plenty for an assessment run (~250 checks max).
    _CACHE_MAX = 512
    # Minimum gap between requests across all threads (ZSCALER_MIN_GAP seconds).
    # 0.15 s ≈ 6-7 requests/s, well inside the tenant limits with 429 handling as the backstop.
    MIN_GAP = float(os.environ.get("ZSCALER_MIN_GAP", "0.15") or 0.15)
    # (connect, read) timeouts: a black-holed tenant fails in 10 s, a slow listing gets 40 s.
    TIMEOUT = (10, 40)

    # The classic session idles out after five minutes; sign in again before that.
    LEGACY_SESSION_SECONDS = 240

    def __init__(s, cid, sec, vd, cloud, customer_id="", *, auth_method="", username="", password="", api_key=""):
        import threading
        s.cid, s.sec, s.vd, s.cloud = cid, sec, vd, cloud
        s.username, s.password, s.api_key = str(username or ""), str(password or ""), str(api_key or "")
        s.method = tenant_auth.method_of({"auth_method": auth_method, "client_id": cid, "username": s.username, "api_key": s.api_key})
        s.legacy = s.method == tenant_auth.LEGACY
        s.token = None; s.exp = 0
        s.base = zscaler_clouds.legacy_api_base(cloud) if s.legacy else _base_url(cloud)
        s.customer_id = str(customer_id or "")
        s.sess = requests.Session(); s.sess.headers.update({"Accept":"application/json"})
        import zia_rate   # every ZIA answer on this session counts toward the tenant's next preflight rate check
        import tenant_fingerprint   # the classic API's key is its keyed fingerprint: no hash of the admin login is kept
        s.rate_key = tenant_fingerprint.tenant_key({"auth_method": s.method, "cloud": cloud, "vanity_domain": vd, "client_id": cid,
                                                    "username": s.username})
        zia_rate.attach(s.sess, s.rate_key)
        # Use OrderedDict for O(1) LRU eviction
        from collections import OrderedDict
        s._c = OrderedDict()
        # Checks run on several threads at once: the cache and the token are shared.
        s._lock = threading.RLock()
        s._limiter = _RateLimiter(s.MIN_GAP)
        s.requests_made = 0
        # Set when the run ends (Stop, the browser gone, the checks in): no
        # further request reaches the tenant, not even a pending retry.
        s.stopped = threading.Event()

    def _cache_set(s, k, v):
        with s._lock:
            s._c[k] = v
            s._c.move_to_end(k)
            if len(s._c) > s._CACHE_MAX:
                s._c.popitem(last=False)  # evict least-recently-used
    def auth(s):
        """Sign in. True, or (False, reason). The reason never carries a secret."""
        with s._lock:
            try:
                if s.legacy:
                    return s._auth_legacy()
                url = _token_url(s.vd, s.cloud)
                r = s.sess.post(url, data={"grant_type":"client_credentials","client_id":s.cid,"client_secret":s.sec,"audience":"https://api.zscaler.com"}, headers={"Content-Type":"application/x-www-form-urlencoded"}, timeout=30)
                r.raise_for_status(); d = r.json(); s.token = d["access_token"]; s.exp = time.time()+d.get("expires_in",3600)-60
                s.sess.headers["Authorization"] = f"Bearer {s.token}"
                return True
            except Exception as e: return (False, s._safe(str(e)))
    def _auth_legacy(s):
        """The classic sign-in: POST the username, password and obfuscated
        API key to /api/v1/authenticatedSession; the JSESSIONID cookie the
        answer sets rides on every later request of this session."""
        payload = tenant_auth.legacy_login_payload(s.username, s.password, s.api_key)
        r = s.sess.post(f"{s.base}{tenant_auth.LEGACY_SESSION_PATH}", json=payload, headers={"Content-Type": "application/json"}, timeout=30)
        if r.status_code != 200:
            body = (r.text or "")[:200]
            raise RuntimeError(f"HTTP {r.status_code} from {s.base}{tenant_auth.LEGACY_SESSION_PATH}: {body or 'the classic API refused the sign-in'}")
        if not s.sess.cookies.get("JSESSIONID"):
            raise RuntimeError("the classic API accepted the sign-in but set no JSESSIONID cookie")
        s.token = "session"; s.exp = time.time() + s.LEGACY_SESSION_SECONDS
        return True
    def _safe(s, text):
        """An error message with every secret masked."""
        return tenant_auth.mask_secrets(text, {"client_secret": s.sec, "password": s.password, "api_key": s.api_key})
    def stop(s):
        """End the run's reads: every later get() (a retry, a fan-out part,
        a check still running) answers "run stopped" without a request."""
        s.stopped.set()
    def close(s):
        """End a classic session (best effort); a OneAPI token just expires."""
        if s.legacy and s.token:
            try: s.sess.delete(f"{s.base}{tenant_auth.LEGACY_SESSION_PATH}", timeout=10)
            except Exception: pass
            s.token = None
    def _ensure_token(s):
        """Re-auth once when the token is stale; other threads wait for it."""
        with s._lock:
            if not s.token or time.time() >= s.exp:
                a = s.auth()
                if a is not True:
                    return ({"error":str(a),"status":401}, 401)
        return None
    def get(s, ep, p=None, _retry=0):
        if ep in _FAN_OUT and _retry == 0:
            return s._fan_out(ep, p)
        # Self-healing: skip ZPA calls if no customer_id provided
        if s.legacy and _resolve_ep(ep, s.customer_id, legacy=True) is None:
            return _LEGACY_ZIA_ONLY
        if ep.startswith("/zpa/") and not s.customer_id:
            return ({"error":"ZPA customer ID not configured","status":404}, 404)
        candidates = _resolve_candidates(ep, s.customer_id, s.legacy)
        if len(candidates) > 1 and _retry == 0:
            # An endpoint that lives at different paths across API
            # generations: the first path that is not "no such route" wins,
            # and the answer is cached under the short endpoint.
            k = f"{ep}|{json.dumps(p or {},sort_keys=True)}"
            with s._lock:
                if k in s._c:
                    s._c.move_to_end(k)
                    return s._c[k]
            tried = []
            res = None
            for cand in candidates:
                res = s.get("raw:" + cand, p)
                tried.append(f"{cand} -> HTTP {res[1]}")
                if res[1] not in (400, 404, 405):
                    break
            if res is not None and res[1] not in (200, 204) and isinstance(res[0], dict):
                res = (dict(res[0], path=candidates[0], tried=tried), res[1])
            s._cache_set(k, res)
            return res
        real_ep = _resolve_ep(ep, s.customer_id, s.legacy)
        k = f"{real_ep}|{json.dumps(p or {},sort_keys=True)}"
        with s._lock:
            if k in s._c:
                s._c.move_to_end(k)
                return s._c[k]
        if s.stopped.is_set():
            return _STOPPED
        # Self-healing: re-auth if token is stale or missing
        bad = s._ensure_token()
        if bad:
            return bad
        try:
            s._limiter.wait(s.stopped)
            if s.stopped.is_set():
                return _STOPPED
            s.requests_made += 1   # every GET sent, whether it is answered, times out or is retried
            r = s.sess.get(f"{s.base}{real_ep}", params=p, timeout=s.TIMEOUT)
            if r.status_code == 200:
                try: res = (r.json(), 200)
                except Exception: res = ([], 200)
            elif r.status_code == 204:
                res = ([], 204)
            elif r.status_code == 429:
                # Self-healing: honor Retry-After with cap, and hold every thread for it
                try: wait = min(int(r.headers.get("Retry-After", 5)), 30)
                except ValueError: wait = 5
                s._limiter.pause(wait)
                if _retry < 3: return s.get(ep, p, _retry+1)
                res = ({"error":"rate limited","status":429}, 429)
            elif r.status_code == 401:
                # Self-healing: token expired mid-flight, force re-auth and retry
                if _retry < 2:
                    s.token = None
                    return s.get(ep, p, _retry+1)
                res = ({"error":"unauthorized","status":401}, 401)
            elif r.status_code in (502, 503, 504):
                # Self-healing: transient server error, retry with backoff
                if _retry < 2:
                    time.sleep(2 ** _retry)
                    return s.get(ep, p, _retry+1)
                res = ({"error":"service unavailable","status":r.status_code}, r.status_code)
            else:
                res = ({"error":r.text[:200] if r.text else "error","status":r.status_code,"path":real_ep}, r.status_code)
        except requests.exceptions.Timeout:
            # One retry: a second 40 s read timeout on the same listing is not going to help.
            if _retry < 1: return s.get(ep, p, _retry+1)
            res = ({"error":"request timeout","status":0,"path":real_ep}, 0)
        except requests.exceptions.ConnectionError as e:
            if _retry < 2:
                time.sleep(2 ** _retry)
                return s.get(ep, p, _retry+1)
            res = ({"error":f"connection error: {str(e)[:100]}","status":0}, 0)
        except Exception as e:
            res = ({"error":str(e)[:200],"status":0}, 0)
        s._cache_set(k, res); return res

    def _fan_out(s, ep, p=None):
        """An endpoint the API only lists in parts (_FAN_OUT): every part,
        each item tagged with the part it came from, as one list. HTTP 200
        when any part answered 200, otherwise the first part's status. A
        part the tenant did not answer (rate limited, unavailable, timed
        out) makes the whole read unanswered: a partial list is never
        passed off as the tenant's whole configuration."""
        k = f"{ep}|{json.dumps(p or {},sort_keys=True)}"
        with s._lock:
            if k in s._c:
                s._c.move_to_end(k)
                return s._c[k]
        items, answered, first, missed = [], False, None, None
        for part, params, tag in _FAN_OUT[ep]:
            d, c = s.get(part, dict(p or {}, **params))
            if first is None:
                first = (d, c)
            if c in _UNANSWERED_CODES:
                missed = (dict(d, part=part) if isinstance(d, dict) else {"error": "not answered", "status": c, "part": part}, c)
                break   # the read is incomplete either way: no further part is asked for
            if c in (200, 204):
                answered = True
                for x in _ls(d):
                    if isinstance(x, dict):
                        x = dict(x); x.setdefault(*tag)
                    items.append(x)
        res = missed or ((items, 200) if answered else first)
        s._cache_set(k, res)
        return res

    def _write(s, method, ep, body=None, _retry=0):
        """Shared write path for POST / PUT / DELETE with self-healing."""
        real_ep = _resolve_ep(ep, s.customer_id, s.legacy)
        if real_ep is None:
            return _LEGACY_ZIA_ONLY
        bad = s._ensure_token()
        if bad:
            return bad
        try:
            kwargs = {"timeout": 30}
            if body is not None:
                kwargs["json"] = body
            if ep.startswith("/zia/"):
                import zia_rate
                zia_rate.wait(method, ep, key=s.rate_key)   # ZIA's per-endpoint write limits, for this tenant
            s._limiter.wait()
            s.requests_made += 1   # every request sent, answered or not
            r = s.sess.request(method, f"{s.base}{real_ep}", **kwargs)
            if r.status_code in (200, 201):
                try: return (r.json(), r.status_code)
                except Exception: return ({}, r.status_code)
            if r.status_code == 204:
                return ({}, 204)
            if r.status_code == 429 and _retry < 3:
                time.sleep(min(int(r.headers.get("Retry-After", 5)), 30))
                return s._write(method, ep, body, _retry + 1)
            if r.status_code == 401 and _retry < 2:
                s.token = None
                return s._write(method, ep, body, _retry + 1)
            if r.status_code in (502, 503, 504) and _retry < 2:
                time.sleep(2 ** _retry)
                return s._write(method, ep, body, _retry + 1)
            return ({"error": r.text[:200] if r.text else "error", "status": r.status_code}, r.status_code)
        except requests.exceptions.Timeout:
            if _retry < 2: return s._write(method, ep, body, _retry + 1)
            return ({"error": "request timeout", "status": 0}, 0)
        except requests.exceptions.ConnectionError as e:
            if _retry < 2:
                time.sleep(2 ** _retry)
                return s._write(method, ep, body, _retry + 1)
            return ({"error": f"connection error: {str(e)[:100]}", "status": 0}, 0)
        except Exception as e:
            return ({"error": str(e)[:200], "status": 0}, 0)

    def post(s, ep, body=None):   return s._write("POST", ep, body)
    def put(s, ep, body=None):    return s._write("PUT", ep, body)
    def delete(s, ep, body=None): return s._write("DELETE", ep, body)


class R:
    """One check result: a status (PASS / FAIL / REVIEW / INFO / ERROR), a
    plain-language detail and optional data for the report."""
    PASS="PASS"; FAIL="FAIL"; WARN="REVIEW"; INFO="INFO"; ERROR="ERROR"
    def __init__(s, st, det="", data=None): s.status,s.detail,s.data = st,det,data or {}

# Human-readable explanations for HTTP errors
_HTTP_EXPLAIN = {
    0:   "Could not connect to the Zscaler API. Check network connectivity.",
    401: "API credentials lack permission for this resource. Verify API role scope.",
    403: "Access denied. The API client role does not include this feature.",
    404: "This feature is not available on your tenant or is not licensed.",
    429: "Rate limited. Too many API requests.",
}

def _explain(label, code, path=None, tried=None):
    """A friendly explanation that still names the call that failed, so a
    wrong path and a missing scope can be told apart."""
    reason = _HTTP_EXPLAIN.get(code, f"Unexpected response (HTTP {code}).")
    where = f" (HTTP {code} on {path})" if path else f" (HTTP {code})"
    if tried and len(tried) > 1:
        where = " (tried " + "; ".join(tried) + ")"
    return R(R.INFO, f"{label}: not readable{where}. {reason}")

def _ls(d):
    if isinstance(d,list): return d
    if isinstance(d,dict):
        # Handle paginated responses like {"list": [...]} or {"data": [...]}
        for key in ("list","data","items","rules","records"):
            if key in d and isinstance(d[key],list): return d[key]
        # If dict has an "error" key, it's not real data
        if "error" in d or "status" in d: return []
    return [d] if d else []

def _nk(k):
    import re as _re
    return _re.sub(r"[^a-z0-9]", "", str(k).lower())

def _fv(x, *names, default=None):
    """A field by any of its names, camelCase or snake_case: the raw API and
    the SDK's as_dict() spell the same field differently."""
    if not isinstance(x, dict): return default
    for n in names:
        if x.get(n) is not None: return x[n]
    idx = {_nk(k): v for k, v in x.items()}
    for n in names:
        v = idx.get(_nk(n))
        if v is not None: return v
    return default

def _enabled(r):
    """A rule is live unless its state says otherwise (DISABLED)."""
    return str(_fv(r, "state") or "ENABLED").upper() not in ("DISABLED", "0", "FALSE")

def _names(v):
    """Ids and names of a list of references ({id, name} dicts or bare values), upper case."""
    out = []
    for e in v or []:
        if isinstance(e, dict):
            for k in ("id", "name", "val"):
                if e.get(k) not in (None, ""): out.append(str(e[k]).upper())
        elif e not in (None, ""):
            out.append(str(e).upper())
    return out

def _set(v):
    """True when a scoping list holds something other than ANY."""
    if isinstance(v, (list, tuple)):
        return any(str(x.get("id") if isinstance(x, dict) else x).upper() not in ("ANY", "") for x in v)
    return bool(v)

def _g(cl, path, label):
    d,c = cl.get(path)
    if c not in (200,204):
        info = d if isinstance(d, dict) else {}
        return None, _explain(label, c, info.get("path") or _resolve_ep(path, getattr(cl, "customer_id", "")), info.get("tried"))
    items = _ls(d)
    return items, None

HR = ["chatgpt","openai","claude","gemini","copilot","dropbox","wetransfer","drive.google","onedrive","icloud","mega.nz","pastebin","github"]

# === Section 1 ===
def c_1_1(cl):
    """Check 1.1 (1 — CC Portal): ZCC Portal accessible."""
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles"); return e or R(R.PASS,f"ZCC Portal OK. {len(d)} profile(s).")
def _split(v):
    """A bypass list as the API gives it: a comma, semicolon or newline
    separated string, or a list (of values or {id, name} objects)."""
    if v is None or v == "": return []
    if isinstance(v, (list, tuple)):
        out = []
        for x in v:
            out += [str(x.get("name") or x.get("id") or x)] if isinstance(x, dict) else _split(x)
        return out
    import re as _re
    return [s.strip() for s in _re.split(r"[,;\n]+", str(v)) if s.strip()]

def _bypasses(p):
    """The bypass lists of a folded app profile, by kind. The fields are the
    ones the API returns (zscaler-sdk-python zcc/models/webpolicy.py:
    policyExtension vpnGateways, packetTunnel*List, sourcePortBasedBypasses;
    top-level bypassAppIds / bypassCustomAppIds)."""
    return {
        "VPN gateway": _split(_fv(p, "vpnGateways")),
        "Destination inclusion": _split(_fv(p, "packetTunnelIncludeList")) + _split(_fv(p, "packetTunnelIncludeListForIpv6")),
        "Destination exclusion": _split(_fv(p, "packetTunnelExcludeList")) + _split(_fv(p, "packetTunnelExcludeListForIpv6")),
        "Domain inclusion": _split(_fv(p, "packetTunnelDnsIncludeList")),
        "Domain exclusion": _split(_fv(p, "packetTunnelDnsExcludeList")),
        "Port bypass": _split(_fv(p, "sourcePortBasedBypasses")),
        "App bypass": _split(_fv(p, "bypassAppIds")) + _split(_fv(p, "bypassCustomAppIds")),
    }

_BYPASS_REF = " Ref: https://help.zscaler.com/zscaler-client-connector/best-practices-adding-bypasses-z-tunnel-2.0"

def c_1_2(cl):
    """Check 1.2 (1 — CC Portal): VPN GW Bypasses."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    b=[x for p in d for x in _bypasses(p)["VPN gateway"]]
    return R(R.PASS,"No VPN gateway bypasses.") if not b else R(R.WARN,f"{len(b)} VPN gateway bypass(es): {', '.join(b[:5])}. Each is traffic Client Connector sends around Zscaler; keep only the VPN concentrators."+_BYPASS_REF)
def c_1_3(cl):
    """Check 1.3 (1 — CC Portal): IP Inclusions."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    inc=[x for p in d for x in _bypasses(p)["Destination inclusion"]]
    if inc:
        full=any(x.startswith("0.0.0.0/0") for x in inc)
        return R(R.PASS,f"{len(inc)} destination inclusion(s) in the Z-Tunnel 2.0 app profiles" + (" (0.0.0.0/0: every destination is tunnelled)." if full else f": {', '.join(inc[:5])}."))
    return R(R.WARN,"No destination inclusions reported on the app profiles (packetTunnelIncludeList). Check Destination Inclusions for Z-Tunnel 2.0 in the portal: 0.0.0.0/0 tunnels every destination."+_BYPASS_REF)
def c_1_4(cl):
    """Check 1.4 (1 — CC Portal): IP Exclusions."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    x=[b for p in d for b in _bypasses(p)["Destination exclusion"]]
    return R(R.PASS,"No destination exclusions.") if not x else R(R.WARN,f"{len(x)} destination exclusion(s) need justification: {', '.join(x[:5])}."+_BYPASS_REF)
def c_1_5(cl):
    """Check 1.5 (1 — CC Portal): App Bypasses."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    apps=[b for p in d for b in _bypasses(p)["App bypass"]]
    ports=[b for p in d for b in _bypasses(p)["Port bypass"]]
    if not apps and not ports: return R(R.PASS,"No application or port bypasses.")
    return R(R.WARN,f"{len(apps)} application bypass(es) and {len(ports)} port bypass(es); an application bypass sends a whole process around Zscaler, so keep each one justified."+_BYPASS_REF)
def _app_profiles_flat(cl, active_only=False):
    """App profiles with policyExtension and the per-platform policies folded
    in (zcc_evaluation.flatten_profile): most Client Connector settings
    (enableZdpService, prioritizeDnsExclusions, installCerts …) live there,
    not at the top level (zscaler-sdk-python zcc/models/webpolicy.py).
    active_only drops profiles switched off (active 0), as the strict
    Client Connector checks do."""
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles")
    if e: return None, e
    try:
        from zcc_evaluation import flatten_profile, _active
    except Exception:  # noqa: BLE001
        flatten_profile = lambda p: p
        _active = lambda p: True
    out=[flatten_profile(p) for p in d if isinstance(p, dict)]
    return ([p for p in out if _active(p)] if active_only else out), None

def _zt2(p):
    """True when a forwarding profile sends some network through Z-Tunnel 2.0.
    The mode sits in forwardingProfileActions[].actionType, not a top-level field."""
    try:
        from data_flow import forwarding_actions
        if any(a.get("mode_label")=="Z-Tunnel 2.0" for a in forwarding_actions(p).values()): return True
    except Exception:  # noqa: BLE001
        pass
    t=str(p.get("tunnelType",p.get("tunnelDriverType","")))
    return "2.0" in t or "PACKET" in t.upper()

def c_1_6(cl):
    """Check 1.6 (1 — CC Portal): Forwarding Profile listener."""
    d,e=_g(cl,"/zcc/forwardingProfiles","FwdProfiles");
    if e: return e
    zt=[p for p in d if isinstance(p, dict) and _zt2(p)]
    return R(R.PASS,f"{len(zt)} of {len(d)} profile(s) use Z-Tunnel 2.0.") if zt else R(R.WARN,"No forwarding profile uses Z-Tunnel 2.0. Best Practice: forward with Z-Tunnel 2.0 (DTLS, TLS fallback) so every port and protocol reaches ZIA, not only proxied web traffic. Ref: https://help.zscaler.com/zscaler-client-connector/best-practices-deploying-z-tunnel-2.0")

_APP_PROFILE_REF = " Ref: https://help.zscaler.com/zscaler-client-connector/configuring-zscaler-client-connector-app-profiles"

def _truthy(v):
    try:
        from zcc_evaluation import _truthy as t
        return t(v)
    except Exception:  # noqa: BLE001
        return v in _ON

def c_1_7(cl):
    """Check 1.7 (1 — CC Portal): DNS exclusion priority.

    Prioritize DNS Exclusions over Z-Tunnel 2.0 (prioritizeDnsExclusions,
    app-profile policyExtension) is on by default in new app profiles and
    Zscaler recommends it. It applies only to Client Connector 4.6 and later
    for Windows, so other platforms are not assessed."""
    d,e=_app_profiles_flat(cl, active_only=True)
    if e: return e
    try:
        from zcc_evaluation import _plat
    except Exception:  # noqa: BLE001
        _plat = lambda p: "?"
    win=[p for p in d if _plat(p) in ("Windows","?","")]
    if not win: return R(R.INFO,"No Windows app profile: Prioritize DNS Exclusions over Z-Tunnel 2.0 applies only to Client Connector 4.6 and later for Windows."+_APP_PROFILE_REF)
    rep=[p for p in win if _fv(p,"prioritizeDnsExclusions") is not None]
    off=[str(p.get("name","?")) for p in rep if not _truthy(_fv(p,"prioritizeDnsExclusions"))]
    if off:
        return R(R.WARN,f"Prioritize DNS Exclusions over Z-Tunnel 2.0 is off on {len(off)} Windows app profile(s): {', '.join(off[:5])}. Zscaler recommends it (on by default in new profiles) so DNS requests for excluded domains are not sent to ZIA."+_APP_PROFILE_REF)
    if rep: return R(R.PASS,f"Prioritize DNS Exclusions over Z-Tunnel 2.0 is on for {len(rep)} Windows app profile(s), as Zscaler recommends.")
    return R(R.INFO,"The Windows app profiles do not report Prioritize DNS Exclusions over Z-Tunnel 2.0; check it in the portal (App Profiles). Zscaler recommends it on, the default in new profiles."+_APP_PROFILE_REF)
def c_1_8(cl):
    """Check 1.8 (1 — CC Portal): Strict Enforcement."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    if d and not any(k in p for p in d for k in ("strictEnforcement","strictMode")):
        return R(R.WARN,"Strict Enforcement is an install option (STRICTENFORCEMENT=1 for the MSI or EXE), not an app-profile setting; check the install command or MDM package, and 6.8 for the per-device state. Ref: https://help.zscaler.com/zscaler-client-connector/customizing-zscaler-client-connector-install-options-msi")
    off=[p.get("name","?") for p in d if not (p.get("strictEnforcement") in _ON or p.get("strictMode") in _ON)]
    return R(R.FAIL,f"Strict mode OFF on: {', '.join(off[:5])}") if off else R(R.PASS,"Strict Enforcement on all profiles.")

def _pw(p, *keys):
    """A password field, whatever its spelling (disablePassword on macOS and
    Linux, disable_password on the Windows policy: zscaler-sdk-python
    zcc/_serialize.py). _fv ignores case and underscores."""
    return str(_fv(p, *keys) or "").strip()

def c_1_9(cl):
    """Check 1.9 (1 — CC Portal): Pre-enrollment gap.

    Strict enforcement is an install option that the devices report
    (devices.strictEnforcement, as 6.8 reads it); the disable password is
    on the active app profiles."""
    d,e=_app_profiles_flat(cl, active_only=True)
    if e: return e
    dv,c=cl.get("/zcc/devices"); devs=[x for x in (_ls(dv) if c in(200,204) else []) if isinstance(x, dict)]
    rep=[x for x in devs if _fv(x,"strictEnforcement") is not None]
    strict=None if not rep else all(_truthy(_fv(x,"strictEnforcement")) for x in rep)
    tamper=bool(d) and all(_pw(p,"disablePassword","passwordToDisable") for p in d)
    if strict and tamper: return R(R.PASS,f"Strict enforcement on all {len(rep)} reporting device(s) and a disable password on every active app profile mitigate the pre-enrollment gap.")
    parts=[]
    if strict is None: parts.append("no device reports strict enforcement (check the install option STRICTENFORCEMENT=1; see 1.8 and 6.8)")
    elif not strict: parts.append(f"{sum(1 for x in rep if not _truthy(_fv(x,'strictEnforcement')))} device(s) run without strict enforcement")
    if not tamper: parts.append("an active app profile has no disable password")
    return R(R.WARN,"Pre-enrollment gap elevated: "+"; ".join(parts)+".")
def c_1_10(cl):
    """Check 1.10 (1 — CC Portal): Tamper passwords."""
    d,e=_app_profiles_flat(cl, active_only=True)
    if e: return e
    m=[p.get("name","?") for p in d if not(_pw(p,"disablePassword","passwordToDisable") and _pw(p,"uninstallPassword","passwordToUninstall"))]
    return R(R.FAIL,f"Missing tamper passwords: {', '.join(m[:5])}") if m else R(R.PASS,"Tamper passwords set.")
def c_1_11(cl):
    """Check 1.11 (1 — CC Portal): Machine Tunnel."""
    d,e=_g(cl,"/zcc/appProfiles","AppProfiles");
    if e: return e
    mt=[p for p in d if p.get("machineTunnelEnabled") or p.get("machineTunnel")]
    return R(R.PASS,f"Machine tunnel on {len(mt)} profile(s).") if mt else R(R.WARN,"Machine tunnel not detected.")
def c_1_12(cl):
    """Check 1.12 (1 — CC Portal): ZCC Telemetry.

    Telemetry is a company setting (getCompanyInfo enableGlobalZCCTelemetry,
    zscaler-sdk-python zcc/models/company_info.py), not an app-profile field."""
    try:
        from zcc_evaluation import _one
        c=_one(cl,"/zcc/companyInfo")
    except Exception:  # noqa: BLE001
        c={}
    if not c: return R(R.INFO,"Company settings are not readable (getCompanyInfo), so Client Connector telemetry cannot be checked; see 1.27.")
    v=_fv(c,"enableGlobalZCCTelemetry")
    if v is None: return R(R.INFO,"The company settings do not report Client Connector telemetry (enableGlobalZCCTelemetry); check it in the Client Connector portal.")
    return R(R.PASS,"Client Connector telemetry is on for the company.") if _truthy(v) else R(R.WARN,"Client Connector telemetry is off for the company, so Zscaler cannot flag crashing builds or connection problems. Turn on global telemetry in the Client Connector portal.")
def c_1_13(cl):
    """Check 1.13 (1 — CC Portal): Posture Profiles."""
    d,c=cl.get("/zcc/postureProfiles")
    if c==404: return R(R.INFO,"Posture profiles are not in the public Client Connector API; check them in the Client Connector portal.")
    items=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(items)} Posture Profile(s).") if items else R(R.WARN,"No Posture Profiles.")
def c_1_14(cl):
    """Check 1.14 (1 — CC Portal): Posture-linked policies."""
    d,c=cl.get("/zia/urlFilteringRules"); rules=_ls(d) if c in(200,204) else []
    pr=[r for r in rules if r.get("devicePostureProfiles") or r.get("deviceTrustLevels")]
    return R(R.PASS,f"{len(pr)} posture-linked rule(s).") if pr else R(R.WARN,"No posture-linked access policies.")

# === Section 2 ===
def c_2_1(cl):
    """Check 2.1 (2 — Bypass Inventory): App Profile inventory."""
    d,e=_g(cl,"/zcc/appProfiles","AP"); return e or R(R.PASS,f"{len(d)} profile(s): {', '.join(p.get('name','?') for p in d[:10])}")
def c_2_2(cl):
    """Check 2.2 (2 — Bypass Inventory): Forwarding listeners."""
    d,e=_g(cl,"/zcc/forwardingProfiles","FP"); return e or R(R.PASS,f"{len(d)} Forwarding Profile(s).")
def c_2_3(cl):
    """Check 2.3 (2 — Bypass Inventory): PAC statements."""
    d,c=cl.get("/zia/pacFiles"); p=_ls(d) if c in(200,204) else []
    return R(R.WARN,f"{len(p)} PAC file(s) — review for DIRECT entries.") if p else R(R.PASS,"No PAC files.")
def c_2_4(cl):
    """Check 2.4 (2 — Bypass Inventory): DNS handling."""
    return c_1_7(cl)
def c_2_5(cl):
    """Check 2.5 (2 — Bypass Inventory): Bypass register."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    reg=[]
    for p in d:
        n=p.get("name","?")
        for kind,vals in _bypasses(p).items():
            if kind in ("Destination inclusion","Domain inclusion"): continue
            reg.extend((kind,str(b),n) for b in vals)
    return R(R.PASS,"Zero bypasses.") if not reg else R(R.WARN,f"Bypass register: {len(reg)} entries.",{"register":reg})
def c_2_6(cl):
    """Check 2.6 (2 — Bypass Inventory): Bypass risk scoring.

    Hostnames are bypassed in the VPN gateway list and the domain
    exclusions (packetTunnelDnsExcludeList), so those are matched against
    the sensitive GenAI and file-sharing domains."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    all_b=[]; hosts=[]
    for p in d:
        bp=_bypasses(p)
        for kind,vals in bp.items():
            if kind in ("Destination inclusion","Domain inclusion"): continue
            all_b.extend(str(b).lower() for b in vals)
        hosts.extend(str(b).lower() for b in bp["VPN gateway"]+bp["Domain exclusion"])
    flagged=[b for b in hosts if any(h in b for h in HR)]
    if flagged: return R(R.FAIL,f"{len(flagged)} bypass(es) match sensitive domains: {', '.join(flagged[:5])}")
    return R(R.PASS,f"{len(all_b)} bypass entries — none match GenAI/file-sharing.") if all_b else R(R.PASS,"No bypasses.")
def c_2_7(cl):
    """Check 2.7 (2 — Bypass Inventory): Sensitive domain cross-ref."""
    return c_2_6(cl)
def c_2_8(cl):
    """Check 2.8 (2 — Bypass Inventory): Review cadence."""
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    h=[p for p in d if p.get("description") and any(k in p["description"].lower() for k in ["review","quarterly","cadence","owner"])]
    return R(R.PASS,f"{len(h)} profile(s) have review notes.") if h else R(R.WARN,"No bypass review cadence detected in descriptions.")

# === Section 3 ===
def c_3_1(cl):
    """Check 3.1 (3 — App Profile): Z-Tunnel 2.0/DTLS."""
    return c_1_6(cl)
_ON = (True, 1, "1", "true", "True", "TRUE")

def c_3_2(cl):
    """Check 3.2 (3 — App Profile): Install Endpoint DLP."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    # The app-profile switch is enableZdpService (policyExtension); the older names are kept for old exports.
    keys=("enableZdpService","installEndpointDlp","endpointDlpEnabled","zdpEnabled")
    z=[p for p in d if any(p.get(k) in _ON for k in keys)]
    if z: return R(R.PASS,f"Endpoint DLP (Install Endpoint DLP / enableZdpService) on {len(z)}/{len(d)} app profile(s).")
    if any(k in p for p in d for k in keys):
        return R(R.FAIL,"Install Endpoint DLP (enableZdpService) is off on every app profile — the Endpoint DLP module is never installed, so no Endpoint DLP rule can fire. Best Practice: turn it on in the app profiles of the users in scope for Endpoint DLP. Ref: https://help.zscaler.com/zia/about-endpoint-dlp")
    return R(R.WARN,"The app profiles do not report the Install Endpoint DLP switch (enableZdpService); check it in the Client Connector portal (App Profiles).")
def c_3_3(cl):
    """Check 3.3 (3 — App Profile): SSL cert toggle."""
    d,e=_app_profiles_flat(cl)
    if e: return e
    # The switch sits in the per-platform policy: install_ssl_certs on
    # windowsPolicy, installCerts on macOS, Linux and Android
    # (zscaler-sdk-python zcc/models/webpolicy.py). _fv ignores case and "_".
    try:
        from zcc_evaluation import _plat
    except Exception:  # noqa: BLE001
        _plat = lambda p: "?"
    mac=[p for p in d if _plat(p)=="macOS"]
    rest=[p for p in d if _plat(p)!="macOS"]
    mac_note=(f" {len(mac)} macOS app profile(s) are not assessed: Install Zscaler SSL Certificate is not supported on macOS Big Sur (11) and later, so push the root certificate with MDM there." if mac else "")
    ref=" Ref: https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-deployment"
    if not rest: return R(R.INFO,"Only macOS app profiles."+mac_note+ref)
    keys=("installCerts","installSslCerts","sslCertInstall","installSslCert","sslCertificateEnabled")
    s=[p for p in rest if any(_truthy(_fv(p,k)) for k in keys)]
    return R(R.PASS,f"SSL cert on {len(s)}/{len(rest)}."+mac_note) if s else R(R.WARN,"Install Zscaler SSL Certificate is not on in any app profile. Without the root certificate on the device, SSL inspection breaks HTTPS unless the certificate is pushed another way (MDM, GPO)."+mac_note+ref)
def c_3_4(cl):
    """Check 3.4 (3 — App Profile): EUNs enabled."""
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    e2=[p for p in d if p.get("eunEnabled") or p.get("endUserNotifications") or p.get("notificationEnabled")]
    return R(R.PASS,f"EUNs on {len(e2)}/{len(d)}.") if e2 else R(R.WARN,"EUNs not detected — blocks look like network errors.")
def c_3_5(cl):
    """Check 3.5 (3 — App Profile): Pilot targeting."""
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    s=[p for p in d if p.get("groups") or p.get("users") or p.get("deviceGroups")]
    return R(R.PASS,f"{len(s)} profile(s) scoped.") if s else R(R.WARN,"All profiles globally scoped.")
def c_3_6(cl):
    """Check 3.6 (3 — App Profile): Split tunneling."""
    return c_1_6(cl)
def _dictify(x):
    if isinstance(x, dict): return x
    for m in ("as_dict", "to_dict"):
        f = getattr(x, m, None)
        if callable(f):
            try: return f() or {}
            except Exception: pass
    return dict(getattr(x, "__dict__", {}) or {})

def _cbi_profiles(cl):
    """Browser Isolation profiles (empty list when the feature is not licensed or the API says no)."""
    d,c=cl.get("/zia/browserIsolation/profiles"); return [_dictify(p) for p in (_ls(d) if c in(200,204) else [])], c

_CAC_TYPES = ("AI_ML","BUSINESS_PRODUCTIVITY","CONSUMER","CUSTOM_CAPP","DNS_OVER_HTTPS","ENTERPRISE_COLLABORATION","FILE_SHARE","FINANCE",
              "HEALTH_CARE","HOSTING_PROVIDER","HUMAN_RESOURCES","INSTANT_MESSAGING","IT_SERVICES","LEGAL","SALES_AND_MARKETING",
              "SOCIAL_NETWORKING","STREAMING_MEDIA","SYSTEM_AND_DEVELOPMENT","WEBMAIL")

# Endpoints the API only lists in parts; Client.get asks every part and
# returns one list, each item tagged with its part. Cloud App Control
# rules are listed per rule type (/webApplicationRules/{type}); ZCC admin
# users per userType (1 ZIA, 2 ZPA, 3 ZIdentity, 4 ZDX: the API refuses
# the call without it).
_FAN_OUT = {
    "/zia/cloudApplicationRules": tuple((f"/zia/webApplicationRules/{t}", {}, ("type", t)) for t in _CAC_TYPES),
    "/zcc/adminUsers": tuple(("/zcc/getAdminUsers", {"userType": n}, ("userType", n)) for n in (1, 2, 3, 4)),
}

def _cac_rules_all_types(cl):
    """Cloud App Control rules across every rule type (the API lists them per type)."""
    zs = getattr(cl, "_zs", None)
    svc = getattr(getattr(zs, "zia", None), "cloudappcontrol", None) if zs else None
    out=[]
    if svc is not None:
        for t in _CAC_TYPES:
            try:
                rules, _, err = svc.list_rules(t)
            except Exception: rules, err = None, "x"
            if err or not rules: continue
            for r in rules:
                d=_dictify(r); d.setdefault("type", t); out.append(d)
        return out
    d,c=cl.get("/zia/cloudApplicationRules"); return [_dictify(r) for r in (_ls(d) if c in(200,204) else [])]

def _isolate_rules(cl):
    """Enabled rules that send traffic to Browser Isolation: URL Filtering
    rules with action ISOLATE and Cloud App Control rules with ISOLATE_ actions."""
    d,c=cl.get("/zia/urlFilteringRules"); url=[_dictify(r) for r in (_ls(d) if c in(200,204) else [])]
    def on(r): return str(r.get("state") or "ENABLED").upper()=="ENABLED"
    url_iso=[r for r in url if on(r) and str(r.get("action") or "").upper()=="ISOLATE"]
    cac_iso=[r for r in _cac_rules_all_types(cl) if on(r) and any(str(a).upper().startswith("ISOLATE") for a in (r.get("actions") or []))]
    return url_iso, cac_iso

def c_3_7(cl):
    """Browser Isolation: profiles exist AND policy actually routes traffic to them."""
    profiles, code = _cbi_profiles(cl)
    if not profiles:
        if code in (403, 404):
            return R(R.INFO, "Browser Isolation (now Zscaler Zero Trust Browser) is not licensed or not enabled on this tenant (API returned no profiles). Without it, unsanctioned SaaS and AI tools can only be allowed or blocked; isolation is the middle ground that permits viewing while stopping upload, download and clipboard.")
        return R(R.WARN, "No Browser Isolation profiles configured. Best practice: create a profile with upload, download and clipboard disabled and route unsanctioned file-sharing, webmail and AI categories through it (URL Filtering action ISOLATE, or Cloud App Control ISOLATE_ actions). Ref: https://help.zscaler.com/zero-trust-browser/configuring-internet-and-saas-for-zero-trust-browser")
    url_iso, cac_iso = _isolate_rules(cl)
    names = [r.get("name","?") for r in url_iso[:4]] + [f"{r.get('name','?')} (CAC {r.get('type','')})" for r in cac_iso[:4]]
    if url_iso or cac_iso:
        return R(R.PASS, f"{len(profiles)} isolation profile(s) and {len(url_iso)} URL Filtering + {len(cac_iso)} Cloud App Control rule(s) enabled with an ISOLATE action: {', '.join(names)}. Isolation needs SSL inspection on the same traffic to apply upload/download controls.",
                 data={"profiles": len(profiles), "url_rules": len(url_iso), "cac_rules": len(cac_iso)})
    return R(R.WARN, f"{len(profiles)} isolation profile(s) exist but no enabled URL Filtering or Cloud App Control rule uses an ISOLATE action, so nothing is actually isolated. Add ISOLATE rules for unsanctioned file-sharing, webmail and AI categories (view allowed, upload/download/clipboard blocked).",
             data={"profiles": len(profiles), "url_rules": 0, "cac_rules": 0})

def c_a17(cl):
    """Isolation coverage of the risky data-exfiltration channels."""
    profiles, code = _cbi_profiles(cl)
    if not profiles:
        return c_3_7(cl)
    url_iso, cac_iso = _isolate_rules(cl)
    risky = {"FILE_SHARE","WEBMAIL","AI_ML","SOCIAL_NETWORKING","CONSUMER"}
    covered = sorted({str(r.get("type","")) for r in cac_iso if str(r.get("type","")) in risky})
    url_cats = sorted({str(c) for r in url_iso for c in (r.get("urlCategories") or r.get("url_categories") or [])})
    if covered or url_cats:
        return R(R.PASS, f"Isolation covers Cloud App Control classes {', '.join(covered) or 'none'} and URL categories {', '.join(url_cats[:8]) or 'none'}. Missing risky classes: {', '.join(sorted(risky - set(covered))) or 'none'}.",
                 data={"cac_classes": covered, "url_categories": url_cats})
    return R(R.WARN, "No ISOLATE rule targets the risky channels (file sharing, webmail, AI, social, consumer apps). Isolation is most valuable exactly there: users keep access, data cannot leave.")
def c_3_8(cl):
    """Check 3.8 (3 — App Profile): Isolation controls."""
    d,c=cl.get("/zia/browserIsolation/profiles"); p=_ls(d) if c in(200,204) else []
    if not p: return R(R.WARN,"No isolation profiles.")
    ctrl=[x for x in p if x.get("uploadControl") or x.get("downloadControl") or x.get("clipboardControl") or x.get("settings")]
    return R(R.PASS,f"{len(ctrl)} profile(s) with content controls.") if ctrl else R(R.WARN,"Isolation without content controls.")

# === Section 4 ===
# An SSL Inspection rule's action is an object in the ZIA API
# ({"type": "DECRYPT" | "DO_NOT_DECRYPT" | "BLOCK", ...sub-actions}, as in
# zscaler-sdk-python and terraform zia_ssl_inspection_rules); older exports
# carried a plain string. Reading it with .upper() crashed every SSL check.
_SSL_INSPECT = {"DECRYPT", "INSPECT", "SSL_INSPECT"}
_SSL_DNI = {"DO_NOT_DECRYPT", "DO_NOT_INSPECT", "SSL_DO_NOT_INSPECT", "EXEMPT"}

def _ssl_action(r):
    """The action type of an SSL Inspection rule, upper case, whatever its shape."""
    a = r.get("action") if isinstance(r, dict) else None
    if isinstance(a, dict):
        a = a.get("type") or a.get("name") or ""
    return str(a or "").upper()

def _ssl_enabled(r):
    return str(r.get("state") or "ENABLED").upper() != "DISABLED"

# The criteria that scope an SSL Inspection rule (zscaler-sdk-python
# zia/models/ssl_inspection_rules.py). A rule with none of them applies to
# all traffic; Zscaler's predefined rules (predefined / defaultRule: the
# Default rule, Zscaler Recommended Exemptions, the One Click rules) are
# part of the recommended policy and are not held against the tenant.
_SSL_SCOPE = ("urlCategories","cloudApplications","users","groups","departments","locations","locationGroups","devices","deviceGroups",
              "platforms","sourceIpGroups","destIpGroups","userAgentTypes","deviceTrustLevels","workloadGroups","zpaAppSegments",
              "proxyGateways","urls")
_SSL_GUIDE = " Ref: https://help.zscaler.com/zscaler-deployments-operations/zia-ssl-inspection-leading-practices-guide"

def _builtin(r):
    """A Zscaler predefined or default rule."""
    return _truthy(_fv(r,"predefined")) or _truthy(_fv(r,"defaultRule"))

def _ssl_scoped(r):
    return any(_set(_fv(r,f)) for f in _SSL_SCOPE)

def _by_order(d):
    def o(r):
        try: return int(_fv(r,"order") or 0)
        except (TypeError, ValueError): return 0
    return sorted([r for r in d if isinstance(r, dict)], key=o)

def _catch_all_decrypt(d):
    """Enabled custom Decrypt rules with no criteria: the final Inspect-All rule."""
    return [r for r in d if isinstance(r, dict) and _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT and not _builtin(r) and not _ssl_scoped(r)]

def c_4_1(cl):
    """Check 4.1 (4 — SSL Policy): Inspection scope.

    The SSL Inspection Leading Practices Guide builds the policy opt-out:
    a final Inspect-All rule with no criteria above the Default (Do Not
    Inspect) rule, so new users, apps and categories are inspected."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    i=[r for r in d if _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT]
    dn=[r for r in d if _ssl_enabled(r) and _ssl_action(r) in _SSL_DNI]
    if not i: return R(R.FAIL,"No enabled SSL Inspection rule decrypts traffic — zero HTTPS visibility for DLP, Cloud App Control and threat scanning. Best Practice: decrypt everything except the documented exemptions (Zscaler Recommended Exemptions, privacy categories) with a catch-all DECRYPT rule."+_SSL_GUIDE)
    ca=_catch_all_decrypt(d)
    if ca: return R(R.PASS,f"{len(i)} enabled Decrypt rule(s), {len(dn)} Do Not Decrypt; catch-all Inspect rule: {ca[0].get('name','?')}.")
    return R(R.WARN,f"{len(i)} enabled Decrypt rule(s), {len(dn)} Do Not Decrypt, but none inspects everything not exempted; new users, apps and categories stay uninspected. Best Practice: a final Inspect-All rule with no criteria above the Default (Do Not Inspect) rule."+_SSL_GUIDE)
def _is_mac(x):
    o=str(_fv(x,"osType","platform") or "").lower()
    return "mac" in o or "darwin" in o or str(_fv(x,"type") or "")=="4"
def c_4_2(cl):
    """Check 4.2 (4 — SSL Policy): Cert deployment."""
    d,c=cl.get("/zcc/devices"); devs=[x for x in (_ls(d) if c in(200,204) else []) if isinstance(x, dict)]
    if not devs: return R(R.WARN,"No device data for cert check.")
    plat={}
    for dv in devs[:500]:
        o="macos" if _is_mac(dv) else str(_fv(dv,"osType","platform") or "?").lower(); plat[o]=plat.get(o,0)+1
    mac=sum(1 for dv in devs[:500] if _is_mac(dv))
    return R(R.WARN if mac else R.PASS, f"Platforms: {plat}." + (f" {mac} macOS device(s): the Install Zscaler SSL Certificate option does not work on macOS Big Sur (11) and later, so push the Zscaler root (or your custom) certificate as a trusted root with your MDM. Ref: https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-deployment" if mac else ""))
def c_4_3(cl):
    """Check 4.3 (4 — SSL Policy): Rule order.

    Rules are evaluated in ascending order; a custom Do Not Decrypt rule
    with no criteria at all above the first custom Decrypt rule shadows it.
    Source-based exemptions (locations, device groups …) are scoped, as in
    the guide's recommended order."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    fd=fi=None
    for r in _by_order(d):
        if not _ssl_enabled(r) or _builtin(r): continue
        a=_ssl_action(r); broad=not _ssl_scoped(r)
        if a in _SSL_DNI and broad and fd is None: fd=r
        if a in _SSL_INSPECT and fi is None: fi=r
    if fd is not None and fi is not None and _by_order([fd,fi])[0] is fd:
        return R(R.FAIL,f"Broad DNI '{fd.get('name','?')}' (order {fd.get('order','?')}) shadows Inspect '{fi.get('name','?')}' (order {fi.get('order','?')}).")
    return R(R.PASS,"SSL rule order valid.")
def c_4_4(cl):
    """Check 4.4 (4 — SSL Policy): Recommended Exemptions."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    def rec(r): return "recommend" in str(r.get("name") or "").lower()
    zr=[r for r in d if isinstance(r, dict) and _builtin(r) and rec(r)] or [r for r in d if isinstance(r, dict) and "zscaler" in str(r.get("name") or "").lower() and rec(r)]
    if not zr: return R(R.WARN,"Recommended Exemptions not found by name.")
    on=[r for r in zr if _ssl_enabled(r)]
    if on: return R(R.PASS,f"Zscaler Recommended Exemptions found and enabled ({len(on)}).")
    return R(R.WARN,"The Zscaler-Recommended Exemptions rule is disabled; destinations that cannot be inspected (certificate pinning, Zscaler-owned domains) will break. Best Practice: keep it enabled and add higher-order Inspect rules for specific domains if needed. Ref: https://help.zscaler.com/zia/about-ssltls-inspection-policy")
def _custom_dni(d):
    return [r for r in d if isinstance(r, dict) and _ssl_enabled(r) and _ssl_action(r) in _SSL_DNI and not _builtin(r)]
def c_4_5(cl):
    """Check 4.5 (4 — SSL Policy): DNI entries.

    Zscaler's recommended policy always has Do Not Decrypt rules (the
    Default rule, Zscaler Recommended Exemptions, the One Click rules), so
    only custom exemptions are reviewed, and only one with no criteria at
    all is a finding."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    cu=_custom_dni(d)
    broad=[r.get("name","?") for r in cu if not _ssl_scoped(r)]
    if broad: return R(R.WARN,f"{len(broad)} custom Do Not Decrypt rule(s) with no criteria exempt all traffic from inspection: {', '.join(broad[:5])}. Scope each exemption to the categories, apps or sources that need it."+_SSL_GUIDE)
    if cu: return R(R.INFO,f"{len(cu)} custom Do Not Decrypt rule(s): {', '.join(str(r.get('name','?')) for r in cu[:5])}. Review each exemption and its scope at least annually."+_SSL_GUIDE)
    return R(R.PASS,"No custom Do Not Decrypt rules; only Zscaler's predefined and default rules exempt traffic.")
def c_4_6(cl):
    """Check 4.6 (4 — SSL Policy): Duplicate rules."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    names=[r.get("name","") for r in d]; dupes=[n for n in set(names) if n and names.count(n)>1]
    return R(R.WARN,f"Duplicates: {', '.join(dupes[:5])}") if dupes else R(R.PASS,"No duplicate SSL rules.")
def _cac_live(r):
    """Enabled custom Cloud App Control rules. Zscaler ships predefined
    'Allow Unauthenticated Traffic for IoT Classifications' rules for every
    category, disabled and undeletable, so they are left out."""
    return [x for x in r if isinstance(x, dict) and str(_fv(x,"state") or "").upper()=="ENABLED" and not _truthy(_fv(x,"predefined"))]
def c_4_7(cl):
    """Check 4.7 (4 — SSL Policy): Cloud App Control."""
    d,c=cl.get("/zia/cloudApplicationRules"); r=_ls(d) if c in(200,204) else []
    live=_cac_live(r)
    if live: return R(R.PASS,f"{len(live)} enabled Cloud App Control rule(s).")
    if r: return R(R.WARN,"Only Zscaler's predefined rules (disabled by default) or disabled rules exist, so no Cloud App Control rule is in force.")
    return R(R.WARN,"No Cloud App Control rules.")
def c_4_8(cl):
    """Check 4.8 (4 — SSL Policy): Prompt/Confirm actions."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    # CONFIRM is the web DLP action (terraform zia_dlp_web_rules 4.1.1+); the other names are kept for old exports.
    cf=[r for r in d if str(r.get("state") or "").upper()=="ENABLED" and str((r.get("action") or {}).get("type") if isinstance(r.get("action"), dict) else r.get("action") or "").upper() in("CONFIRM","PROMPT","ALLOW_WITH_CONFIRM")]
    return R(R.PASS,f"{len(cf)} enabled Prompt/Confirm rule(s).") if cf else R(R.WARN,"No enabled web DLP rule uses the Confirm action. Confirm lets the user justify the transaction or cancel it (a timeout cancels it), with the wording from a User Confirmation Notification template; it suits data that may leave for a business reason, while Block stays for data that must never leave. Ref: https://help.zscaler.com/zia/about-user-confirmation-notification-templates")
def c_4_9(cl):
    """Check 4.9 (4 — SSL Policy): EUN templates."""
    d,c=cl.get("/zia/dlpNotificationTemplates")
    t=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(t)} notification template(s).") if t else R(R.WARN,"No notification templates.")
def c_4_10(cl):
    """Check 4.10 (4 — SSL Policy): Handshake errors."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    eh=[r for r in d if "error" in (r.get("name") or "").lower() or "handshake" in (r.get("name") or "").lower()]
    return R(R.PASS,f"{len(eh)} error-handling rule(s).") if eh else R(R.WARN,"No handshake-error handling rules.")
def c_4_11(cl):
    """Check 4.11 (4 — SSL Policy): SSL + device trust."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    pl=[r for r in d if r.get("devicePostureProfiles") or r.get("deviceTrustLevels")]
    return R(R.PASS,f"{len(pl)} SSL rule(s) linked to posture.") if pl else R(R.WARN,"No SSL rules tied to device posture.")
def c_4_12(cl):
    """Check 4.12 (4 — SSL Policy): ECH handling.

    Zscaler's guidance handles Encrypted Client Hello in DNS Control, not in
    SSL Inspection rules: block the HTTPS and SVCB DNS record types so the
    browser never learns the ECH config (and does not try HTTP/3 over QUIC).
    Ref: https://help.zscaler.com/zia/best-practices-dns-control-rules"""
    d,e=_g(cl,"/zia/firewallDnsRules","DNS Control")
    if e: return e
    def types(r): return {str(t).upper() for t in (r.get("dnsRuleRequestTypes") or r.get("dns_rule_request_types") or [])}
    blk=[r for r in d if isinstance(r, dict) and str(r.get("state") or "ENABLED").upper()=="ENABLED"
         and str(r.get("action") or "").upper().startswith("BLOCK") and {"HTTPS","SVCB"} & types(r)]
    both=[r for r in blk if {"HTTPS","SVCB"} <= types(r)] or ([r for r in blk if "HTTPS" in types(r)] and [r for r in blk if "SVCB" in types(r)])
    names=", ".join(str(r.get("name","?")) for r in blk[:3])
    if both: return R(R.PASS,f"DNS Control blocks the HTTPS and SVCB record types ({names}), which suppresses ECH and HTTP/3 over QUIC.")
    if blk: return R(R.WARN,f"DNS Control blocks only one of the HTTPS / SVCB record types ({names}). Best Practice: block both so the browser cannot learn an ECH config. Ref: https://help.zscaler.com/zia/best-practices-dns-control-rules")
    return R(R.WARN,"No DNS Control rule blocks the HTTPS and SVCB record types, so browsers can use Encrypted Client Hello (and HTTP/3 over QUIC) and hide the real destination from SSL inspection. Best Practice: a DNS Control rule with request types HTTPS and SVCB, action Block with response code Server Failure. Ref: https://help.zscaler.com/zia/best-practices-dns-control-rules")
def c_4_13(cl):
    """Check 4.13 (4 — SSL Policy): TLS 1.3."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT]
    return R(R.PASS,"SSL active — ZIA supports TLS 1.3 natively.") if i else R(R.FAIL,"No SSL inspection.")

def c_4_14(cl):
    """Check 4.14 (4 — SSL Policy): Decrypt rule hardening.

    The sub-actions of the catch-all Decrypt rule (no criteria, not
    predefined) against the Internet & SaaS TLS and SSL Inspection Leading
    Practices Guide: block untrusted server certificates, OCSP revocation
    check on, block undecryptable traffic, and no TLS version below 1.2.
    Fields are action.decryptSubActions (serverCertificates, ocspCheck,
    blockUndecrypt, minClientTLSVersion, minServerTLSVersion —
    zscaler-sdk-python / terraform zia_ssl_inspection_rules). The guide's
    own policy has narrow Decrypt rules with weaker settings (the Smart
    Isolation One Click rule, specific exception rules for legacy
    services), so predefined rules are skipped and narrow rules are listed
    as exceptions to review, not findings. A sub-action the API does not
    return is not counted against the rule."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL")
    if e: return e
    dec=[r for r in d if isinstance(r, dict) and _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT and not _builtin(r)]
    if not dec: return R(R.INFO,"No enabled custom Decrypt rule to review (see 4.1).")
    def sub(r):
        a=r.get("action") if isinstance(r.get("action"), dict) else {}
        return a.get("decryptSubActions") or a.get("decrypt_sub_actions") or {}
    def tls_below_12(v):
        import re as _re
        m=_re.search(r"(\d)[_.](\d)$", str(v or ""))
        return bool(m) and (int(m.group(1)), int(m.group(2))) < (1, 2)
    def weak(r):
        s_=sub(r); bad=[]
        if "serverCertificates" in s_ and str(s_.get("serverCertificates")).upper()!="BLOCK": bad.append(f"untrusted server certificates {str(s_.get('serverCertificates')).upper()}")
        if "ocspCheck" in s_ and s_.get("ocspCheck") is not True: bad.append("OCSP revocation check off")
        if "blockUndecrypt" in s_ and s_.get("blockUndecrypt") is not True: bad.append("undecryptable traffic allowed")
        for k,lbl in (("minClientTLSVersion","client"),("minServerTLSVersion","server")):
            if tls_below_12(s_.get(k)): bad.append(f"minimum {lbl} TLS {s_.get(k)}")
        return f"{r.get('name','?')}: {', '.join(bad)}" if bad else ""
    ca=[r for r in dec if not _ssl_scoped(r)]; narrow=[r for r in dec if _ssl_scoped(r)]
    issues=[w for w in map(weak, ca) if w]; exc=[w for w in map(weak, narrow) if w]
    exc_note=(f" {len(exc)} narrow Decrypt rule(s) use weaker settings ({'; '.join(exc[:3])}); narrow exception rules for legacy services are expected, so review them." if exc else "")
    if issues:
        return R(R.WARN,f"{len(issues)} catch-all Decrypt rule(s) are weaker than Zscaler's leading practice: {'; '.join(issues[:4])}. Best Practice: the final Inspect-All rule should block untrusted server certificates, run the OCSP check, block undecryptable traffic and require TLS 1.2 for client and server (review the TLS versions in use first and add narrow exceptions for legacy services)."+exc_note+_SSL_GUIDE,
                 data={"rules": len(dec), "weak": len(issues)})
    if exc:
        return R(R.INFO,"The catch-all Decrypt rule(s) meet Zscaler's leading practice (where the API reports these settings)."+exc_note+_SSL_GUIDE if ca else "No catch-all Decrypt rule (see 4.1)."+exc_note+_SSL_GUIDE,
                 data={"rules": len(dec), "weak": 0, "exceptions": len(exc)})
    return R(R.PASS,f"All {len(dec)} Decrypt rule(s) block untrusted certificates and undecryptable traffic, check OCSP and require TLS 1.2 or later (where the API reports these settings)."+_SSL_GUIDE,
             data={"rules": len(dec), "weak": 0})

# === Section 5 ===
def c_5_1(cl):
    """Check 5.1 (5 — Endpoint DLP): ZDP install."""
    return c_3_2(cl)
def c_5_2(cl):
    """Check 5.2 (5 — Endpoint DLP): DLP Resources."""
    return R(R.INFO,"Endpoint DLP resources are not listed by the ZIA API; check them in the ZIA Admin Portal.")
def c_5_3(cl):
    """Check 5.3 (5 — Endpoint DLP): Web DLP rules."""
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    if not a: return R(R.FAIL,"No active Web DLP rules.")
    acts={}
    for r in a: k=r.get("action","?"); acts[k]=acts.get(k,0)+1
    return R(R.PASS,f"{len(a)} active: {', '.join(f'{v}x{k}' for k,v in acts.items())}")
def c_5_4(cl):
    """Check 5.4 (5 — Endpoint DLP): Scan allowlists."""
    return R(R.INFO,"Manual check: Endpoint DLP reaches Zscaler's cloud through Client Connector, so confirm the network firewall and any upstream proxy do not block the Client Connector and Endpoint DLP destinations Zscaler lists for your cloud. Not readable via the ZIA API.")
_PRIVACY_CATS = ("FINANCE","HEALTH","BANK","INSURANCE","MEDIC")
_DLP_DEST = ("FILE_HOST","FILE_SHAR","FILESHAR","WEBMAIL","WEB_MAIL","EMAIL","AI_ML","GENERAL_AI","STORAGE","DROPBOX","ONEDRIVE","GOOGLE_DRIVE","GDRIVE","WETRANSFER","ICLOUD")
def c_5_5(cl):
    """Check 5.5 (5 — Endpoint DLP): SSL DNI cats.

    Do Not Decrypt rules that matter to DLP: custom rules that cover
    data-loss destinations (file sharing, webmail, Generative AI, personal
    cloud storage) or that have no criteria at all. Zscaler's predefined and
    default rules, and exemptions scoped to privacy categories (Finance,
    Health) or endpoint security apps, are expected by the SSL Inspection
    Leading Practices Guide."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL")
    if e: return e
    cu=_custom_dni(d); risky=[]
    for r in cu:
        tg=_names(_fv(r,"urlCategories"))+_names(_fv(r,"cloudApplications"))
        if not _ssl_scoped(r): risky.append(f"{r.get('name','?')} (no criteria)")
        elif any(k in t for t in tg for k in _DLP_DEST): risky.append(f"{r.get('name','?')} ({', '.join(t for t in tg if any(k in t for k in _DLP_DEST))[:80]})")
    if risky: return R(R.WARN,f"{len(risky)} Do Not Decrypt rule(s) hide data-loss destinations from DLP: {'; '.join(risky[:5])}. Inline DLP cannot inspect traffic that is not decrypted. Best Practice: decrypt file sharing, webmail, Generative AI and personal cloud storage; keep exemptions to privacy categories and apps that cannot be inspected."+_SSL_GUIDE)
    return R(R.PASS,f"No Do Not Decrypt rule covers a data-loss destination ({len(cu)} custom exemption(s); see 4.5).")
def c_5_6(cl):
    """Check 5.6 (5 — Endpoint DLP): URL filter bypasses.

    URL Filtering Allow and Caution rules do not bypass DLP: the web modules
    run in order (SSL Inspection, ATP, AV, Cloud App Control, URL Control,
    File Type Control, DLP, Sandbox) and only a policy violation stops the
    transaction before DLP. What hides traffic from DLP is Do Not Decrypt
    (4.5, 5.5). Enabled Block rules on data-loss destinations are reported
    as information: those transactions end before DLP, so no DLP incident
    or auditor notice fires for them."""
    d,c=cl.get("/zia/urlFilteringRules"); r=[x for x in (_ls(d) if c in(200,204) else []) if isinstance(x, dict)]
    ref=" Ref: https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide"
    blk=[x for x in r if _enabled(x) and str(_fv(x,"action") or "").upper()=="BLOCK" and any(k in t for t in _names(_fv(x,"urlCategories")) for k in _DLP_DEST)]
    if blk:
        return R(R.INFO,f"{len(blk)} enabled URL Filtering Block rule(s) on data-loss destinations: {', '.join(str(x.get('name','?')) for x in blk[:5])}. They stop the transaction before DLP runs, so DLP incidents and auditor notices never fire for them. URL Filtering Allow and Caution rules do not bypass DLP; Do Not Decrypt rules do (see 4.5 and 5.5)."+ref)
    return R(R.PASS,"No URL Filtering rule keeps traffic from DLP: Allow and Caution rules do not bypass DLP, which runs after URL Filtering. Do Not Decrypt rules are reviewed in 4.5 and 5.5."+ref)
def c_5_7(cl):
    """Check 5.7 (5 — Endpoint DLP): Rule exceptions."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    ex=[r for r in d if r.get("excludedUsers") or r.get("excludedGroups") or r.get("excludedDepartments")]
    return R(R.WARN,f"{len(ex)} rule(s) with exceptions.") if ex else R(R.PASS,"No rule-level exceptions.")
def _web_dlp_on(d):
    return [r for r in d if isinstance(r, dict) and str(r.get("state") or "").upper()=="ENABLED"]
def c_5_9(cl):
    """Check 5.9 (5 — Endpoint DLP): Rule scope.

    An empty dlpEngines means Any (all engines) when the rule inspects
    content; a rule with withoutContentInspection uses no engine by design
    (it filters on file type, size, users). So the split is information."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    a=_web_dlp_on(d)
    if not a: return R(R.INFO,"No enabled web DLP rules (see 5.3).")
    noci=[r for r in a if _truthy(_fv(r,"withoutContentInspection"))]
    spec=[r for r in a if r not in noci and _fv(r,"dlpEngines")]
    anye=[r for r in a if r not in noci and not _fv(r,"dlpEngines")]
    return R(R.INFO,f"{len(a)} enabled web DLP rule(s): {len(spec)} on specific DLP engines, {len(anye)} on Any engine (all engines), {len(noci)} without content inspection (filter only). Ref: https://help.zscaler.com/zia/configuring-dlp-policy-rules-content-inspection",
             data={"specific": len(spec), "any": len(anye), "no_inspection": len(noci)})
def c_5_10(cl):
    """Check 5.10 (5 — Endpoint DLP): Dictionaries."""
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    if not dicts: return R(R.ERROR,"Cannot get dictionaries.")
    cust=[x for x in dicts if x.get("custom")]; po=[x for x in cust if x.get("phrases") and not x.get("patterns")]
    det=f"{len(dicts)} total, {len(cust)} custom."
    return R(R.WARN,det+f" {len(po)} phrase-only (high FP).") if po else R(R.PASS,det)
def c_5_11(cl):
    """Check 5.11 (5 — Endpoint DLP): Custom dict FP."""
    return c_5_10(cl)
# A DLP dictionary says what it is in dictionaryType (PATTERNS_AND_PHRASES,
# EXACT_DATA_MATCH, INDEXED_DATA_MATCH, MIP_TAG — terraform zia_dlp_dictionaries);
# EDM carries exactDataMatchDetails and IDM idmProfileMatchAccuracy(Details).
def _is_edm(x):
    return str(x.get("dictionaryType") or "").upper()=="EXACT_DATA_MATCH" or bool(x.get("exactDataMatchDetails")) or "EDM" in (x.get("name") or "").upper()
def _is_idm(x):
    return (str(x.get("dictionaryType") or "").upper()=="INDEXED_DATA_MATCH" or bool(x.get("idmProfileMatchAccuracyDetails") or x.get("idmProfileMatchAccuracy") or x.get("idmProfile"))
            or "IDM" in (x.get("name") or "").upper())

def c_5_12(cl):
    """Check 5.12 (5 — Endpoint DLP): Detection methods."""
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    m=[n for n,t in [("regex",any(x.get("patterns") for x in dicts)),("phrase",any(x.get("phrases") for x in dicts)),("EDM",any(_is_edm(x) for x in dicts)),("IDM",any(_is_idm(x) for x in dicts))] if t]
    return R(R.PASS,f"Methods: {', '.join(m)}.") if len(m)>=2 else R(R.WARN,f"Only {', '.join(m) or 'none'} — add more.")

# Web DLP rule file types are FTCATEGORY_* enums (terraform-provider-zia
# zia/validator.go); older exports carried bare names. fileTypeCategories
# (ids) replaces fileTypes on newer rules, and a rule uses one or the other.
_FT_LEGACY = {"PDF": "PDF_DOCUMENT", "DOC": "MS_WORD", "DOCX": "MS_WORD", "WORD": "MS_WORD", "XLS": "MS_EXCEL", "XLSX": "MS_EXCEL",
              "EXCEL": "MS_EXCEL", "PPT": "MS_POWERPOINT", "PPTX": "MS_POWERPOINT", "POWERPOINT": "MS_POWERPOINT"}
def _ft(t):
    u=str(t.get("id") or t.get("name") if isinstance(t, dict) else t).upper()
    u=u[len("FTCATEGORY_"):] if u.startswith("FTCATEGORY_") else u
    return _FT_LEGACY.get(u, u)
def _ft_has(fts, group):
    if "ALL_OUTBOUND" in fts: return True
    if group=="archives": return any(("ZIP" in x or "RAR" in x or x in ("TAR","7Z") or "ARCHIVE" in x) for x in fts)
    return {"PDF":"PDF_DOCUMENT","Word":"MS_WORD","Excel":"MS_EXCEL","PowerPoint":"MS_POWERPOINT","CSV":"CSV"}[group] in fts
def _ft_split(a):
    """(rules on any file type, rules with file types, rules set by category)."""
    anyft=[]; typed=[]; bycat=[]
    for r in a:
        fts={_ft(t) for t in (_fv(r,"fileTypes") or [])}
        if fts and "ALL_OUTBOUND" not in fts: typed.append((r,fts))
        elif fts: anyft.append(r)
        elif _fv(r,"fileTypeCategories"): bycat.append(r)
        else: anyft.append(r)
    return anyft, typed, bycat
def c_5_13(cl):
    """Check 5.13 (5 — Endpoint DLP): Content types."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    a=_web_dlp_on(d)
    if not a: return R(R.INFO,"No enabled web DLP rules (see 5.3).")
    anyft,typed,bycat=_ft_split(a)
    cat_note=(f" {len(bycat)} rule(s) set file types by category: review them in the portal." if bycat else "")
    if anyft: return R(R.PASS,f"Key types covered: {len(anyft)} enabled rule(s) apply to any file type."+cat_note)
    if not typed: return R(R.INFO,"File types are set by category on every enabled rule; review them in the portal.")
    fts=set().union(*(f for _,f in typed))
    miss=[g for g in ("PDF","Word","Excel","CSV") if not _ft_has(fts,g)]
    return R(R.PASS,"Key types covered (PDF, Word, Excel, CSV)."+cat_note) if not miss else R(R.WARN,f"Missing: {', '.join(miss)}."+cat_note)
def c_5_14(cl):
    """Check 5.14 (5 — Endpoint DLP): EDM."""
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    edm=[x for x in dicts if _is_edm(x)]
    return R(R.PASS,f"{len(edm)} EDM dict(s).") if edm else R(R.WARN,"No Exact Data Match dictionary. EDM matches your own records (customer, patient or employee data indexed with the Index Tool) instead of patterns, which cuts false positives on regulated data. Ref: https://help.zscaler.com/zia/about-exact-data-match")
def c_5_15(cl):
    """Check 5.15 (5 — Endpoint DLP): IDM."""
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    idm=[x for x in dicts if _is_idm(x)]
    return R(R.PASS,f"{len(idm)} IDM profile(s).") if idm else R(R.WARN,"No Indexed Document Match dictionary. IDM fingerprints your sensitive documents and forms (indexed with the Index Tool) so copies and fragments are detected. Ref: https://help.zscaler.com/zia/about-indexed-document-match")
def c_5_16(cl):
    """Check 5.16 (5 — Endpoint DLP): Confirm/Prompt."""
    return c_4_8(cl)
_DLP_ADV_REF=" Ref: https://help.zscaler.com/zia/configuring-dlp-advanced-settings"
def c_5_17(cl):
    """Check 5.17 (5 — Endpoint DLP): Exemptions.

    Per-rule exceptions (5.7) and the tenant-wide exemptions of DLP Advanced
    Settings (/webDlpGlobalOptions applications, urls, urlCategories,
    exemptUrlEncodedData — zscaler-sdk-python 1.11.0), which override every
    DLP rule: the service does not inspect those transactions."""
    per_rule=c_5_7(cl)
    g,gc=cl.get("/zia/webDlpGlobalOptions")
    if gc!=200 or not isinstance(g, dict): return per_rule
    parts=[]
    for k,lbl in (("applications","cloud app(s)"),("urls","URL(s)"),("urlCategories","URL categor(ies)")):
        v=_split(_fv(g,k))
        if v: parts.append(f"{len(v)} {lbl} ({', '.join(str(x) for x in v[:4])})")
    if _truthy(_fv(g,"exemptUrlEncodedData")): parts.append("URL-encoded form data")
    if not parts: return per_rule
    return R(R.WARN,f"DLP Advanced Settings exempts {'; '.join(parts)} from all DLP evaluation; these exemptions override every DLP rule. Keep the list minimal and documented. Per-rule exceptions: {per_rule.detail}"+_DLP_ADV_REF)

_TENANT_REF=" Ref: https://help.zscaler.com/zia/about-tenant-profiles"
def _tenancy(cl, extra=""):
    """Tenancy restriction has two parts: Tenant Profiles, and enabled Cloud
    App Control rules that apply them (tenancyProfileIds —
    zscaler-sdk-python zia/models/cloudappcontrol.py)."""
    rules=_cac_live(_cac_rules_all_types(cl))
    p,pc=cl.get("/zia/tenancyRestrictionProfile")
    profiles=[x for x in (_ls(p) if pc in(200,204) else []) if isinstance(x, dict)]
    used=[(r,_names(_fv(r,"tenancyProfileIds"))) for r in rules]
    used=[(r,ids) for r,ids in used if ids]
    ids_used={i for _,ids in used for i in ids}
    if used:
        det=", ".join(f"{r.get('name','?')} ({', '.join(_names(_fv(r,'applications'))[:3]) or r.get('type','?')})" for r,_ in used[:4])
        idle=[str(x.get("name") or x.get("id")) for x in profiles if str(x.get("id")).upper() not in ids_used and str(x.get("name") or "").upper() not in ids_used]
        return R(R.PASS,f"{len(used)} enabled Cloud App Control rule(s) apply a Tenant Profile: {det}."+(f" Not attached to any rule: {', '.join(idle[:4])}." if idle else ""))
    if profiles:
        return R(R.WARN,f"Tenant profile(s) exist but no enabled Cloud App Control rule uses them: {', '.join(str(x.get('name') or x.get('id')) for x in profiles[:5])}. A tenant profile does nothing until a rule applies it."+extra+_TENANT_REF)
    return R(R.WARN,"No Cloud App Control rule applies a Tenant Profile, so users can sign in to personal accounts of sanctioned apps (for example personal OneDrive or Google Drive) and move data there. Best Practice: create Tenant Profiles (Data Security > Inline CASB > Tenant Profiles) for sanctioned apps and attach them to the Allow rules for those apps."+extra+_TENANT_REF)
def c_5_18(cl):
    """Check 5.18 (5 — Endpoint DLP): Tenancy."""
    return _tenancy(cl)
_OCR_REF="Ref: https://help.zscaler.com/zia/configuring-dlp-advanced-settings"

def c_5_19(cl):
    """Check 5.19 (5 — Endpoint DLP): OCR.

    OCR is an organisation-wide switch in DLP Advanced Settings (Inline DLP,
    SaaS Security API, Outbound Email DLP), read from /webDlpGlobalOptions
    (zscaler-sdk-python 1.11.0 zia/web_dlp_global_options.py). The per-rule
    ocrEnabled flag is deprecated and no longer accepted by the API
    (terraform-provider-zia 2.9.0), so a leftover flag proves nothing."""
    g,gc=cl.get("/zia/webDlpGlobalOptions")
    if gc==200 and isinstance(g, dict) and "enableInlineDlpOcr" in g:
        on=lambda k: g.get(k) in (True,1,"1","true","True")
        off=[n for k,n in (("enableCasbOcr","SaaS Security API"),("enableEmailDlpOcr","Outbound Email DLP")) if k in g and not on(k)]
        tail=(f" Also off for: {', '.join(off)}." if off else "")
        if on("enableInlineDlpOcr"):
            return R(R.PASS,"OCR is on for inline DLP: text in PNG, JPEG, TIFF and BMP images is scanned."+tail,data={"inline_ocr":True})
        return R(R.WARN,"OCR is off for inline DLP (DLP Advanced Settings): DLP rules do not apply to image files, so a screenshot or scan of a record passes unscanned."+tail+" Best Practice: enable Optical Character Recognition for Inline DLP (and for SaaS Security API and Outbound Email DLP where licensed). "+_OCR_REF,data={"inline_ocr":False})
    d,c=cl.get("/zia/webDlpRules"); rules=_ls(d) if c in(200,204) else []
    stale=[r for r in rules if isinstance(r, dict) and r.get("ocrEnabled")]
    note=(f" {len(stale)} rule(s) still carry the legacy per-rule ocrEnabled flag, which no longer controls OCR; the organisation setting (DLP Advanced Settings > Optical Character Recognition > Inline DLP) must be on." if stale else "")
    return R(R.INFO,"OCR is set once for the organisation in DLP Advanced Settings (Optical Character Recognition), not per rule, and that setting was not readable here. Check that OCR is on for Inline DLP."+note+" "+_OCR_REF)
_EVAL_ALL_TAIL=("Under Evaluate All Rules, rule order matters only between matching rules with the same action; across actions the most restrictive one is enforced. "
                "Switching mode requires deleting all existing inline DLP rules first, so export them, have the account team enable the mode, then re-create them "
                "(use exception rules for workflow carve-outs instead of higher-ordered Allow rules).")
def c_5_20(cl):
    """Inline DLP rule evaluation mode: Evaluate All Rules (every matching
    rule fires) or By Rule Order (first match wins). Uses the same probe as
    the Rule Migration wizard, so the answer matches what it shows. Rule
    order is not a readiness signal: under Evaluate All Rules it matters only
    between matching rules with the same action
    (https://help.zscaler.com/zia/configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled)."""
    try:
        from rule_migrator import assess_current_status
        st = assess_current_status(cl)
    except Exception as e:  # noqa: BLE001
        return R(R.INFO, f"Could not determine the DLP rule evaluation mode ({str(e)[:80]}). Check Data Security > Common Resources > DLP Advanced Settings (Inline DLP Rule Evaluation) in the portal."+_DLP_ADV_REF)
    on = st.get("evaluate_all_enabled")
    via = st.get("found_via") or ""
    n_rules = st.get("rule_count", 0); n_on = st.get("enabled_rules", 0)
    if on is True:
        return R(R.PASS, f"Evaluate All Rules is ON (seen at {via}). Every rule is evaluated and the matching rule with the most restrictive action is enforced, so a broad monitor rule and a narrow block rule can coexist. {n_on}/{n_rules} web DLP rules enabled.",
                 data={"evaluate_all": True, "found_via": via})
    if on is False:
        return R(R.WARN, f"Evaluate All Rules is OFF: the tenant is in By Rule Order mode (seen at {via}). Only the first matching rule fires, so a monitor rule near the top silently shadows every block rule below it. With Evaluate All Rules the most restrictive matching action wins, which suits a layered DLP policy. {_EVAL_ALL_TAIL} {n_on}/{n_rules} web DLP rules enabled. Ref: https://help.zscaler.com/zia/configuring-dlp-advanced-settings ; https://help.zscaler.com/zia/configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled",
                 data={"evaluate_all": False, "found_via": via})
    feat = st.get("feature_available")
    feat_note = (" The capability flag says the feature is available on this tenant." if feat is True
                 else " The capability flag says the feature is not enabled on this tenant; the Zscaler account team enables it." if feat is False else "")
    return R(R.INFO, "The API does not expose the DLP rule evaluation mode on this tenant." + feat_note
             + " Read it in the portal under Data Security > Common Resources > DLP Advanced Settings (Inline DLP Rule Evaluation), or declare it in the Rule Migration wizard. Ref: https://help.zscaler.com/zia/configuring-dlp-advanced-settings",
             data={"evaluate_all": None, "feature_available": feat})
# Zscaler's AI/ML classification is built into predefined ML-based
# dictionaries (https://help.zscaler.com/zia/understanding-predefined-dlp-dictionaries).
_ML_DICTS = ("corporate finance document","corporate legal document","court document","financial statements","hr document","id card",
             "immigration document","insurance document","invoice document","legal document","medical document","medical imaging",
             "credit card image","satellite data","schematic data")
def _is_ml_dict(x):
    n=str(_fv(x,"name","nameL10nTag") or "").strip().lower()
    return any(n==m or n.startswith(m+" ") or n.startswith(m+"(") for m in _ML_DICTS)
def c_5_21(cl):
    """Check 5.21 (5 — Endpoint DLP): AI classification.

    PASS when an enabled web DLP rule uses a DLP engine whose expression
    includes one of Zscaler's ML-based document dictionaries (engine
    expressions name dictionaries by id, e.g. ((D63.S > 1)))."""
    import re as _re
    ref=" Ref: https://help.zscaler.com/zia/understanding-predefined-dlp-dictionaries"
    d,c=cl.get("/zia/dlpDictionaries"); dicts=[x for x in (_ls(d) if c in(200,204) else []) if isinstance(x, dict)]
    ml={str(x.get("id")): str(x.get("name") or "?") for x in dicts if _is_ml_dict(x) and x.get("id") is not None}
    miss=R(R.WARN,"No DLP rule uses Zscaler's ML-based document dictionaries (for example Financial Statements, Legal Document, Medical Document). Add them to an engine used by an inline DLP rule to catch sensitive documents that have no fixed pattern."+ref)
    if not dicts: return R(R.INFO,"DLP dictionaries are not readable, so the use of ML-based dictionaries cannot be checked."+ref)
    if not ml: return miss
    en,ec=cl.get("/zia/dlpEngines"); engines=[x for x in (_ls(en) if ec in(200,204) else []) if isinstance(x, dict)]
    if not engines: return R(R.INFO,f"The ML-based dictionaries exist ({', '.join(list(ml.values())[:3])}), but DLP engines are not readable, so their use in a rule cannot be checked."+ref)
    ml_eng={}
    for eg in engines:
        ids=set(_re.findall(r"D(\d+)", str(_fv(eg,"engineExpression") or "")))
        hit=[ml[i] for i in ids if i in ml]
        if hit: ml_eng[str(eg.get("id"))]=(str(eg.get("name") or "?"), hit)
    w,wc=cl.get("/zia/webDlpRules"); rules=_web_dlp_on(_ls(w) if wc in(200,204) else [])
    used=[(r, ml_eng[i]) for r in rules for i in {str(x.get("id") if isinstance(x, dict) else x) for x in (_fv(r,"dlpEngines") or [])} if i in ml_eng]
    if used:
        r,(en_name,hit)=used[0]
        return R(R.PASS,f"{len(used)} enabled web DLP rule(s) use ML-based dictionaries, e.g. {r.get('name','?')} via engine {en_name} ({', '.join(hit[:3])}).")
    return miss
def c_5_22(cl):
    """Check 5.22 (5 — Endpoint DLP): AI discovery."""
    return R(R.INFO,"Endpoint Data Scan runs daily on endpoints with Endpoint DLP and needs no scheduling; review Analytics > Endpoint Data Scan for users and files with sensitive data (DLP engines and AI & ML categories). Not readable via the ZIA API. Ref: https://help.zscaler.com/zia/about-endpoint-data-scan")

# === Multi-Channel ===
def c_mc1(cl):
    """Check MC.1 (Multi-Channel): Inline Web DLP."""
    return c_5_3(cl)
def c_mc2(cl):
    """Check MC.2 (Multi-Channel): Endpoint DLP."""
    d,c=cl.get("/zia/endPointDlpRules")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} endpoint DLP rule(s).") if r else R(R.WARN,"No endpoint DLP rules via API.")
def c_mc3(cl):
    """Check MC.3 (Multi-Channel): CASB."""
    d,c=cl.get("/zia/casbDlpRules/all")
    if c==404: return R(R.WARN,"CASB not licensed.")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} CASB rule(s).") if r else R(R.WARN,"No CASB rules.")
def c_mc4(cl):
    """Check MC.4 (Multi-Channel): Email DLP."""
    r,err=_email_rules(cl)
    if err: return err
    on=[x for x in r if str(x.get("state") or "").upper()=="ENABLED"]
    if not r: return R(R.WARN,"No email DLP rules.")
    if not on: return R(R.WARN,f"{len(r)} email DLP rule(s), none enabled: a disabled rule is not enforced.")
    return R(R.PASS,f"{len(r)} email DLP rule(s), {len(on)} enabled.")
def _email_rules(cl):
    """Outbound Email DLP rules, or the reason they cannot be read: 404 means
    not licensed or not enabled (INFO), a refusal or other code is an ERROR,
    as in saas_email_checks."""
    d,c=cl.get("/zia/emailDlpRules")
    if c in (200,204): return [x for x in _ls(d) if isinstance(x, dict)], None
    if c==404: return [], R(R.INFO,"Outbound Email DLP is not licensed or not enabled on this tenant (the API answered 404).")
    if c in (401,403): return [], R(R.ERROR,f"The API client's role cannot read Outbound Email DLP rules (HTTP {c}); grant it read access to see this result.")
    return [], R(R.ERROR,f"Outbound Email DLP rules could not be read (HTTP {c}).")
def c_mc5(cl):
    """Check MC.5 (Multi-Channel): Browser Isolation."""
    return c_3_7(cl)
def c_mc6(cl):
    """Check MC.6 (Multi-Channel): Data Discovery."""
    return R(R.WARN,"Data Discovery needs GraphQL.")
def c_mc7(cl):
    """Check MC.7 (Multi-Channel): GenAI Report."""
    return R(R.WARN,"GenAI Report needs GraphQL.")
def c_mc8(cl):
    """Check MC.8 (Multi-Channel): Endpoint Report."""
    return R(R.WARN,"Endpoint Report needs GraphQL.")
def c_mc9(cl):
    """Check MC.9 (Multi-Channel): Email Report."""
    return R(R.WARN,"Email Report needs GraphQL.")
def c_mc10(cl):
    """Check MC.10 (Multi-Channel): CASB Report."""
    return R(R.WARN,"CASB Report needs GraphQL.")
def c_mc11(cl):
    """Check MC.11 (Multi-Channel): DSPM."""
    return R(R.WARN,"Zscaler DSPM (Data Security Posture Management) is a separate license and console; not assessed through the ZIA API.")
def c_mc12(cl):
    """Check MC.12 (Multi-Channel): Executive summary."""
    d1,_=cl.get("/zia/webDlpRules"); d2,_=cl.get("/zia/sslInspectionRules")
    return R(R.PASS,f"Summary data: {len(_ls(d1))} DLP rules, {len(_ls(d2))} SSL rules.")

# === Section 6 ===
def c_6_1(cl):
    """Check 6.1 (6 — Versions): ZCC versions.

    The device list reports the client version as agentVersion
    (zscaler-sdk-python zcc/models/devices.py). Zscaler supports the latest
    release, the two before it and the current LTS, per platform; the
    minimums are kept in zcc_evaluation.ZCC_MIN_SUPPORTED and versions are
    compared as numbers. Ref: https://help.zscaler.com/product-usage-terms/supported-versions"""
    from zcc_evaluation import device_platform, zcc_unsupported, ZCC_MIN_SUPPORTED
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    def ver(x): return str(x.get("agentVersion") or x.get("zccVersion") or x.get("clientConnectorVersion") or x.get("zappVersion") or "")
    old=[x for x in devs[:500] if isinstance(x, dict) and zcc_unsupported(device_platform(x), ver(x))]
    by={}
    for x in old: by[device_platform(x)]=by.get(device_platform(x),0)+1
    mins="; ".join(f"{p} {'.'.join(map(str,v))}" + (" (Linux also 4.2+)" if p=="Linux" else "") for p,v in ZCC_MIN_SUPPORTED.items())
    return R(R.FAIL,f"{len(old)} device(s) run a Client Connector release Zscaler no longer supports ({', '.join(f'{k}: {v}' for k,v in by.items())}). Supported: the latest release, the two before it and the current LTS; today's minimums are {mins}. Unsupported releases can be refused enrollment. Ref: https://help.zscaler.com/product-usage-terms/supported-versions") if old else R(R.PASS,f"{len(devs)} device(s) OK.")
def c_6_2(cl):
    """Check 6.2 (6 — Versions): Phased rollout."""
    d,e=_g(cl,"/zcc/appProfiles","AP"); 
    if e: return e
    ph=[p for p in d if p.get("phasedRollout") or p.get("appStoreEnabled")]
    return R(R.PASS,f"Phased rollout on {len(ph)}.") if ph else R(R.WARN,"No phased rollout.")
def c_6_3(cl):
    """Check 6.3 (6 — Versions): Device hygiene."""
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    orph=[x for x in devs if (x.get("state") or x.get("status") or "").lower() in("removed","orphaned","inactive")]
    return R(R.WARN,f"{len(orph)} orphaned device(s).") if orph else R(R.PASS,"Device states clean.")
def c_6_4(cl):
    """Check 6.4 (6 — Versions): Inspect list."""
    return c_4_1(cl)
def c_6_5(cl):
    """Check 6.5 (6 — Versions): DNI list."""
    return c_4_5(cl)
def c_6_6(cl):
    """Check 6.6 (6 — Versions): Registers."""
    return c_2_5(cl)
def _is_win10(x):
    """Windows 10, not 11. Both report version 10.0; Windows 11 is build
    22000 and later, so "10" in the version string is not enough."""
    os_=str(x.get("osType") or x.get("platform") or x.get("type") or "").lower()
    ver=str(x.get("osVersion") or "")
    if "windows" not in os_ and "windows" not in ver.lower() and os_ not in ("3",): return False
    low=ver.lower()
    if "windows 11" in low: return False
    if "windows 10" in low: return True
    import re as _re
    m=_re.search(r"10\.0\.(\d{5})", ver)
    return bool(m) and int(m.group(1)) < 22000

def c_6_7(cl):
    """Check 6.7 (6 — Versions): Win10 count."""
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    w10=[x for x in devs if isinstance(x, dict) and _is_win10(x)]
    return R(R.WARN,f"{len(w10)} Windows 10 device(s). Microsoft ended Windows 10 support on 14 October 2025; only devices enrolled in Extended Security Updates still get security fixes, and Zscaler supports Client Connector on Windows 10 for a limited time only. Plan the move to Windows 11. Ref: https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro ; https://help.zscaler.com/product-usage-terms/supported-versions") if w10 else R(R.PASS,"No Win10.")

# === Section 7 ===
def c_7_1(cl):
    """Check 7.1 (7 — SSL Alignment): Cert per platform."""
    return c_4_2(cl)
def c_7_2(cl):
    """Check 7.2 (7 — SSL Alignment): Pinned apps."""
    return c_4_4(cl)
def c_7_3(cl):
    """Check 7.3 (7 — SSL Alignment): Cert expiration."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL"); 
    if e: return e
    i=[r for r in d if _ssl_action(r) in _SSL_INSPECT and _ssl_enabled(r)]
    return R(R.PASS,f"SSL active ({len(i)} rules) — valid certs implied.") if i else R(R.WARN,"No enabled SSL rules.")

# === Section 8 — Pilot Tests via log/rule inference ===
def _pilot(cl, kw, ch):
    d,e=_g(cl,"/zia/webDlpRules","DLP")
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    m=[r for r in a if kw.lower() in json.dumps(r).lower()]
    if m: return R(R.PASS,f"{len(m)} rule(s) cover {ch}. Verify logs via Analytics.")
    if not a: return R(R.WARN,f"No active DLP rules to cover {ch}. Configure Web DLP rules first.")
    return R(R.WARN,f"No rules specifically target {ch} — may still be covered by generic rules.")

def _values_text(o):
    """Every value in a rule, lower case, without the keys: a key such as
    cloudApplications must not count as a match for "cloud"."""
    if isinstance(o, dict): return " ".join(_values_text(v) for v in o.values())
    if isinstance(o, (list, tuple)): return " ".join(_values_text(v) for v in o)
    return str(o).lower() if o is not None else ""

# Endpoint DLP channels (Printing, Removable Storage Devices, Network Share,
# Personal Cloud Storage — https://help.zscaler.com/zia/about-endpoint-dlp)
# are Endpoint DLP rules (/endPointDlpRules), not web DLP rules: a web rule
# can never see a USB copy or a print job.
def _ep_rules(cl):
    """Endpoint DLP rules (all, enabled) or the INFO that says they are not readable."""
    d,c=cl.get("/zia/endPointDlpRules")
    if c not in (200,204): return None, None, c
    rules=[r for r in _ls(d) if isinstance(r, dict)]
    return rules, [r for r in rules if _enabled(r)], c

def _action(r):
    a=_fv(r,"action")
    if isinstance(a, dict): a=a.get("type") or a.get("name")
    return str(a or "").upper()

def _pilot_endpoint(cl, kws, ch, methods=()):
    """Every Endpoint DLP rule has one channel, in dataTransferMethod
    (zscaler-sdk-python EndpointDlpRules.data_transfer_method; terraform
    zia_endpoint_dlp_rules). It is compared exactly; keywords are matched
    on whole words only for a rule that does not report it. Sub-rules
    inherit the channel from the parent."""
    import re as _re
    rules,a,c=_ep_rules(cl)
    if rules is None:
        return R(R.INFO,f"Endpoint DLP rules are not readable (HTTP {c}); check the {ch} channel in the portal (Data Security > Endpoint DLP). Ref: https://help.zscaler.com/zia/about-endpoint-dlp")
    def covers(r):
        m=str(_fv(r,"dataTransferMethod") or "").upper()
        if m: return m in methods
        txt=_values_text(r)
        return any(_re.search(r"\b"+_re.escape(k), txt) for k in kws)
    m=[r for r in a if covers(r)]
    if m: return R(R.PASS,f"{len(m)} enabled Endpoint DLP rule(s) cover {ch}: {', '.join(str(r.get('name','?')) for r in m[:4])}. Verify with a pilot device.")
    if not a: return R(R.WARN,f"No enabled Endpoint DLP rules, so {ch} is not covered. Best Practice: add an Endpoint DLP rule for the {ch} channel (monitor first, then Block or Confirm). Ref: https://help.zscaler.com/zia/about-endpoint-dlp")
    return R(R.WARN,f"None of the {len(a)} enabled Endpoint DLP rule(s) covers {ch}. Add a rule for that channel. Ref: https://help.zscaler.com/zia/about-endpoint-dlp")

def c_8_1(cl):
    """Check 8.1 (8 — Pilot Tests): USB/Removable."""
    return _pilot_endpoint(cl,("removable","usb"),"USB/Removable",("REMOVABLE_DRIVE_TRANSFER",))
def c_8_2(cl):
    """Check 8.2 (8 — Pilot Tests): Printer."""
    return _pilot_endpoint(cl,("print",),"Printer",("PRINTING",))
def c_8_3(cl):
    """Check 8.3 (8 — Pilot Tests): Network Share."""
    return _pilot_endpoint(cl,("network_share","network share","network_drive","network drive"),"Network Share",("NETWORK_DRIVE_TRANSFER",))
def c_8_4(cl):
    """Check 8.4 (8 — Pilot Tests): Personal Cloud."""
    return _pilot_endpoint(cl,("personal_cloud","personal cloud","cloud storage","cloud_storage"),"Personal Cloud",("PERSONAL_CLOUD_STORAGE",))
def c_8_5(cl):
    """Check 8.5 (8 — Pilot Tests): Inline Web DLP."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    return R(R.PASS,f"{len([r for r in d if r.get('state','').upper()=='ENABLED'])} inline rules active.")

_IR_REF=" Ref: https://help.zscaler.com/zia/about-zscaler-incident-receiver"
def _evidence(cl):
    """ICAP servers and Zscaler Incident Receivers (separate lists: SDK
    dlp_resources list_dlp_icap_servers / list_dlp_incident_receiver), and
    the enabled rules that send content to them: web DLP rules with
    zscalerIncidentReceiver or an icapServer, Endpoint DLP rules with a
    receiver (terraform zia_dlp_web_rules, zia_endpoint_dlp_rules)."""
    i,ic=cl.get("/zia/icapServers"); r_,rc=cl.get("/zia/incidentReceiverServers")
    icap=[x for x in _ls(i) if isinstance(x, dict)] if ic in (200,204) else []
    irs=[x for x in _ls(r_) if isinstance(x, dict)] if rc in (200,204) else []
    w,wc=cl.get("/zia/webDlpRules"); web=_web_dlp_on(_ls(w) if wc in (200,204) else [])
    fwd_web=[r for r in web if _truthy(_fv(r,"zscalerIncidentReceiver")) or _set(_fv(r,"icapServer"))]
    _,ep,_c=_ep_rules(cl)
    fwd_ep=[r for r in (ep or []) if _set(_fv(r,"receiver"))]
    return {"icap": icap, "irs": irs, "fwd_web": fwd_web, "fwd_ep": fwd_ep, "readable": ic in (200,204) or rc in (200,204)}

def _evidence_result(cl):
    ev=_evidence(cl); n=len(ev["icap"])+len(ev["irs"])
    if not ev["readable"]: return R(R.INFO,"ICAP servers and Incident Receivers are not readable; check evidence capture in the portal (Data Security > Common Resources)."+_IR_REF)
    srv=f"{len(ev['icap'])} ICAP server(s) and {len(ev['irs'])} Incident Receiver(s)"
    if n and (ev["fwd_web"] or ev["fwd_ep"]):
        return R(R.PASS,f"{srv}; {len(ev['fwd_web'])} enabled web DLP rule(s) and {len(ev['fwd_ep'])} Endpoint DLP rule(s) send matched content to them.")
    if n: return R(R.WARN,f"{srv} configured, but no enabled DLP rule sends content to them, so no evidence is captured. Set the Incident Receiver (or ICAP server) on the rules whose evidence you need."+_IR_REF)
    return R(R.WARN,"No ICAP server or Incident Receiver: no evidence capture."+_IR_REF)

def c_8_6(cl):
    """Check 8.6 (8 — Pilot Tests): Evidence (ICAP)."""
    return _evidence_result(cl)
def c_8_7(cl):
    """Check 8.7 (8 — Pilot Tests): Browser Isolation."""
    return c_3_8(cl)
def c_8_8(cl):
    """Check 8.8 (8 — Pilot Tests): GenAI prompt."""
    return _pilot(cl,"genai","GenAI")
_EMAIL_ENFORCE={"BLOCK","QUARANTINE","CUSTOMHEADERINSERTION","CUSTOM_HEADER_INSERTION"}
def c_8_9(cl):
    """Check 8.9 (8 — Pilot Tests): Email DLP.

    The pilot is a test email with test data sent to an external domain,
    checking that the mail server acts on the X-Zscaler header."""
    r,err=_email_rules(cl)
    if err: return err
    on=[x for x in r if str(x.get("state") or "").upper()=="ENABLED"]
    enf=[x for x in on if _action(x) in _EMAIL_ENFORCE or _fv(x,"customHeader")]
    pilot=" Pilot: send a test email with test data to an external domain and check that the mail server's transport rules act on the X-Zscaler-Block / X-Zscaler-Quarantine (or custom) header. Ref: https://help.zscaler.com/zia/configuring-outbound-email-policy-rules"
    if enf: return R(R.PASS,f"{len(enf)} enabled Email DLP rule(s) enforce ({', '.join(sorted({_action(x) or 'custom header' for x in enf}))}): {', '.join(str(x.get('name','?')) for x in enf[:4])}."+pilot)
    if on: return R(R.WARN,f"{len(on)} enabled Email DLP rule(s), none with an enforcing action (Block, Quarantine or Custom Header Insertion)."+pilot)
    return R(R.WARN,"No enabled Email DLP rule to pilot (see MC.4)."+pilot)
def c_8_10(cl):
    """Check 8.10 (8 — Pilot Tests): CASB API."""
    return c_mc3(cl)
def c_8_11(cl):
    """Check 8.11 (8 — Pilot Tests): EDM."""
    return c_5_14(cl)
def c_8_12(cl):
    """Check 8.12 (8 — Pilot Tests): OCR."""
    return c_5_19(cl)

# === Section 9 ===
def c_9_1(cl):
    """Check 9.1 (9 — Troubleshooting): ZDP allowlists."""
    return c_5_4(cl)
def c_9_2(cl):
    """Check 9.2 (9 — Troubleshooting): Handshake triage."""
    return c_4_10(cl)
def c_9_3(cl):
    """Check 9.3 (9 — Troubleshooting): Web Insights."""
    return c_4_1(cl)
def c_9_4(cl):
    """Check 9.4 (9 — Troubleshooting): ZCC Diagnostics."""
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(devs)} device(s) — diagnostics collectible.") if devs else R(R.WARN,"No devices.")

# === Section 10 — macOS ===
def c_10_1(cl):
    """Check 10.1 (10 — macOS): Full Disk Access."""
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    macs=[x for x in devs if "mac" in str(x.get("osType") or x.get("platform") or "").lower()]
    if not macs: return R(R.PASS,"No macOS devices.")
    zdp=[x for x in macs if x.get("zdpInstalled") or x.get("endpointDlpInstalled")]
    return R(R.PASS,f"{len(zdp)} macOS with ZDP — FDA implied.") if zdp else R(R.WARN,f"{len(macs)} macOS — verify FDA via MDM.")
def c_10_2(cl):
    """Check 10.2 (10 — macOS): SSL cert MDM."""
    return c_4_2(cl)
def c_10_3(cl):
    """Check 10.3 (10 — macOS): Platform versions."""
    d,c=cl.get("/zcc/devices"); devs=_ls(d) if c in(200,204) else []
    return R(R.PASS,"macOS version prereqs met if ZCC reporting.") if any("mac" in str(x.get("osType","")).lower() for x in devs) else R(R.PASS,"No macOS.")
def c_10_4(cl):
    """Check 10.4 (10 — macOS): Sys/Net Extensions."""
    return R(R.PASS,"Sys/Net Extension approval inferred from macOS devices reporting to ZCC.")

# === Section 11 — Rollback ===
def c_11_1(cl):
    """Check 11.1 (11 — Rollback): Disable path."""
    return R(R.WARN,"Rollback doc: confirm disable-path exists (ZDP off → ZCC revert → targeting removed).")
def c_11_2(cl):
    """Check 11.2 (11 — Rollback): Comms plan."""
    return R(R.WARN,"Comms plan: confirm helpdesk templates prepared.")
def c_11_3(cl):
    """Check 11.3 (11 — Rollback): Staging test."""
    return R(R.WARN,"Staging test: confirm clean ZDP removal on test device.")

# === Section 12 — Incident Management ===
def c_12_1(cl):
    """Check 12.1 (12 — Incident Mgmt): ICAP/IR deployed."""
    return _evidence_result(cl)
def c_12_2(cl):
    """Check 12.2 (12 — Incident Mgmt): Secure ICAP mTLS.

    An ICAP server object has only id, name, url and status (SDK
    DLPICAPServer; terraform zia_dlp_icap_servers): secure ICAP shows in the
    URL scheme, icaps://. Zscaler Incident Receivers are Zscaler-managed."""
    d,c=cl.get("/zia/icapServers"); s=[x for x in (_ls(d) if c in(200,204) else []) if isinstance(x, dict)]
    r_,rc=cl.get("/zia/incidentReceiverServers"); irs=[x for x in (_ls(r_) if rc in(200,204) else []) if isinstance(x, dict)]
    live=[x for x in s if str(_fv(x,"status") or "ENABLED").upper()!="DISABLED"]
    off=len(s)-len(live)
    if not live:
        if irs: return R(R.PASS,f"No third-party ICAP server in use; {len(irs)} Zscaler Incident Receiver(s), which are Zscaler-managed.")
        return R(R.WARN,"No ICAP servers.")
    clear=[str(x.get("name") or x.get("id")) for x in live if not str(_fv(x,"url") or "").lower().startswith("icaps://")]
    tail=(f" {off} disabled ICAP server(s) not assessed." if off else "")
    if clear: return R(R.FAIL,f"{len(clear)} ICAP server(s) use a cleartext icap:// URL: {', '.join(clear[:5])}. Use secure ICAP (icaps://) so the matched content is encrypted on its way to the server."+tail)
    return R(R.PASS,f"All {len(live)} enabled ICAP server(s) use secure ICAP (icaps://)."+tail)
def c_12_3(cl):
    """Check 12.3 (12 — Incident Mgmt): Incident content."""
    return _forwarding_result(cl)
def _forwarding_result(cl):
    """Whether enabled DLP rules actually forward matched content (12.3, 12.12)."""
    ev=_evidence(cl); n=len(ev["icap"])+len(ev["irs"])
    if ev["fwd_web"] or ev["fwd_ep"]:
        names=[str(r.get("name","?")) for r in (ev["fwd_web"]+ev["fwd_ep"])[:4]]
        return R(R.PASS,f"{len(ev['fwd_web'])} enabled web DLP rule(s) and {len(ev['fwd_ep'])} Endpoint DLP rule(s) forward matched content to an ICAP server or Incident Receiver: {', '.join(names)}.")
    if n: return R(R.WARN,f"{n} ICAP server(s) or Incident Receiver(s) exist, but no enabled DLP rule forwards content to them, so no incident content is kept."+_IR_REF)
    return R(R.WARN,"No ICAP server or Incident Receiver, so no incident content is kept (see 12.1)."+_IR_REF)
def c_12_4(cl):
    """Check 12.4 (12 — Incident Mgmt): Workflow Automation."""
    return R(R.INFO,"Workflow Automation is its own API (ZWA), not part of ZIA; FP/TP Detection Ratio reads its incidents. Check the workflows in the Workflow Automation portal.")
def c_12_5(cl):
    """Check 12.5 (12 — Incident Mgmt): Remediation workflows."""
    return c_12_4(cl)
def c_12_6(cl):
    """Check 12.6 (12 — Incident Mgmt): User justification."""
    return c_4_8(cl)
def c_12_7(cl):
    """Check 12.7 (12 — Incident Mgmt): ITSM integration."""
    return R(R.WARN,"ITSM integration — verify ServiceNow connector in portal.")
# Cloud NSS feeds carry their log type and status (SDK NssFeeds nssLogType,
# feedStatus; terraform zia_cloud_nss_feed: WEBLOG, FWLOG, DNSLOG,
# MULTIFEEDLOG, ADMIN_AUDIT, ENDPOINT_DLP, EMAIL_DLP …). Web and DLP
# transactions, GenAI included, are in the web log. A feed that reports
# no type (older exports) is read as a web feed.
def _feeds(cl):
    d,c=cl.get("/zia/nssFeeds"); return [f for f in (_ls(d) if c in(200,204) else []) if isinstance(f, dict)]
def _feed_type(f): return str(_fv(f,"nssLogType") or "").upper()
def _feed_on(f): return str(_fv(f,"feedStatus") or "ENABLED").upper()=="ENABLED"
def _web_feed(f, multi=True): return _feed_type(f) in (("", "WEBLOG", "MULTIFEEDLOG") if multi else ("", "WEBLOG"))
def _feed_types(fs):
    t={}
    for f in fs: k=_feed_type(f) or "type not reported"; t[k]=t.get(k,0)+1
    return ", ".join(f"{k} {v}" for k,v in t.items())
def c_12_8(cl):
    """Check 12.8 (12 — Incident Mgmt): NSS/SIEM."""
    f=_feeds(cl); on=[x for x in f if _feed_on(x)]
    if on: return R(R.PASS,f"{len(on)} enabled NSS feed(s) streaming ({_feed_types(on)}).")
    if f: return R(R.WARN,f"{len(f)} NSS feed(s), none enabled: nothing is streamed to the SIEM. Enable the web (and DLP) feed.")
    return R(R.WARN,"No NSS or Cloud NSS feed: transaction logs stay in ZIA and only incidents are visible outside it. Recommended, not required: a feed gives the full transaction baseline (normal business traffic and what no rule caught) for SIEM correlation and continuous evaluation; without it, Workflow Automation incidents and analyst verdicts are the near-real-time source. Best Practice: Configure a Cloud NSS feed (web + DLP logs) to your SIEM or a collector, with the DLP fields in the format string. Ref: https://help.zscaler.com/zia/about-cloud-nss-feeds")
def c_12_9(cl):
    """Check 12.9 (12 — Incident Mgmt): NSS DLP fields.

    Only web-log feeds carry the DLP fields (NSS Feed Output Format: Web
    Logs); firewall, DNS, tunnel, audit, CASB, Endpoint and Email DLP feeds
    have formats of their own. %s{dlprulename} only names Allow rules;
    %s{trig_dlprulename} names the rule that triggered, allowed or blocked."""
    feeds=_feeds(cl); web=[f for f in feeds if _web_feed(f, multi=False)]
    ref=" Ref: https://help.zscaler.com/zia/nss-feed-output-format-web-logs"
    if not feeds: return R(R.INFO,"No NSS feed to check (see 12.8; a feed is a recommendation, not a requirement).")
    if not web: return R(R.INFO,f"No web-log NSS feed ({_feed_types(feeds)}); the DLP fields are carried in the Web log feed."+ref)
    dlp_flds=["dlpeng","dlpdict","dlpmd5"]; short=[]; old=[]
    for f in web:
        fmt=(f.get("formatString") or f.get("format") or f.get("feedOutputFormat") or _fv(f,"feedOutputFormat") or "").lower()
        miss=[x for x in dlp_flds if "{"+x+"}" not in fmt and x not in fmt]
        if "trig_dlprulename" not in fmt and "dlprulename" not in fmt: miss.append("trig_dlprulename")
        if miss: short.append(f"'{f.get('name','?')}' missing: {', '.join(miss)}")
        elif "trig_dlprulename" not in fmt: old.append(str(f.get("name","?")))
    if short: return R(R.WARN,f"{len(short)} web feed(s) lack DLP fields: {'; '.join(short[:4])}. Use %s{{trig_dlprulename}} for the rule name: %s{{dlprulename}} only names Allow rules."+ref)
    if old: return R(R.WARN,f"Web feed(s) {', '.join(old[:4])} name the DLP rule with %s{{dlprulename}}, which is filled only for Allow rules; add %s{{trig_dlprulename}} so blocked transactions carry their rule too."+ref)
    return R(R.PASS,f"All {len(web)} web feed(s) include the DLP fields.")
def c_12_10(cl):
    """Check 12.10 (12 — Incident Mgmt): SIEM correlation."""
    return R(R.WARN,"SIEM correlation rules live outside Zscaler.")
def _web_retention(cl, what):
    f=_feeds(cl); on=[x for x in f if _feed_on(x)]; web=[x for x in on if _web_feed(x)]
    if web: return R(R.PASS,f"{len(web)} enabled web-log NSS feed(s): {what} are kept in the SIEM beyond ZIA's six-month log window.")
    if on: return R(R.WARN,f"Enabled NSS feeds stream {_feed_types(on)}, but web and DLP transactions are not among them, so {what} stay in ZIA only for its six-month log window (180 days). Add a web-log feed. Ref: https://help.zscaler.com/zia/about-insights-logs")
    return None
def c_12_11(cl):
    """Check 12.11 (12 — Incident Mgmt): Log retention beyond 180 days (NSS export)."""
    return _web_retention(cl,"web and DLP transactions") or R(R.WARN,"No enabled NSS feed: ZIA keeps transaction logs for a rolling six months (180 days in the Nanolog) and nothing longer. Recommended, not required: stream logs out for longer retention and evidence. Best Practice: Send web and DLP logs to a SIEM through Cloud NSS or an NSS VM and retain them for at least 12 months. Ref: https://help.zscaler.com/zia/about-insights-logs ; https://help.zscaler.com/zia/about-nss-feeds")
def c_12_12(cl):
    """Check 12.12 (12 — Incident Mgmt): Evidence storage."""
    return _forwarding_result(cl)
def c_12_13(cl):
    """Check 12.13 (12 — Incident Mgmt): Admin role segregation."""
    d,c=cl.get("/zia/adminRoles")
    r=_ls(d) if c in(200,204) else []
    return R(R.PASS,f"{len(r)} admin roles.") if len(r)>=2 else R(R.WARN,f"Only {len(r)} role(s).")
def c_12_14(cl):
    """Check 12.14 (12 — Incident Mgmt): C2C forwarding."""
    return R(R.WARN,"C2C forwarding — verify in portal.")

# === Channel A ===
def c_a1(cl):
    """Check A.1 (Ch.A — Inline Web): Rule count."""
    return c_mc1(cl)
def c_a2(cl):
    """Check A.2 (Ch.A — Inline Web): SSL+DNI."""
    return c_4_1(cl)
def c_a3(cl):
    """Check A.3 (Ch.A — Inline Web): Rule verbs."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]; dl=[r for r in a if r.get("dlpDownloadScanEnabled")]
    return R(R.INFO,f"{len(a)} enabled web DLP rule(s): {len(a)-len(dl)} inspect uploads only, {len(dl)} also inspect downloads (Inspect Downloads). Inspect Downloads needs URL Categories set to Any and at least one cloud app, and does not apply to EDM or IDM engines. Ref: https://help.zscaler.com/zia/configuring-dlp-policy-rules-content-inspection")
def c_a4(cl):
    """Check A.4 (Ch.A — Inline Web): File type scope.

    Enabled rules with no file type apply to any file type; a rule that
    restricts file types should still cover the common document types
    (PDF, Office, CSV, archives). fileTypes are FTCATEGORY_* enums."""
    d,e=_g(cl,"/zia/webDlpRules","DLP");
    if e: return e
    a=_web_dlp_on(d)
    if not a: return R(R.INFO,"No enabled web DLP rules (see 5.3).")
    anyft,typed,bycat=_ft_split(a)
    groups=("PDF","Word","Excel","CSV","archives")
    gaps=[]
    for r,fts in typed:
        miss=[g for g in groups if not _ft_has(fts,g)]
        if miss: gaps.append(f"{r.get('name','?')} (no {', '.join(miss)})")
    base=f"{len(anyft)} enabled rule(s) apply to any file type, {len(typed)} restrict file types"+(f", {len(bycat)} set file types by category (review in the portal)" if bycat else "")+"."
    if gaps: return R(R.WARN,base+f" {len(gaps)} restricted rule(s) leave out common document types: {'; '.join(gaps[:4])}. Ref: https://help.zscaler.com/zia/configuring-dlp-policy-rules-content-inspection")
    return R(R.PASS,base+(f" Restricted rules: {', '.join(str(r.get('name','?')) for r,_ in typed[:4])}." if typed else ""))
def c_a5(cl):
    """Check A.5 (Ch.A — Inline Web): URL scope."""
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    a=[r for r in d if r.get("state","").upper()=="ENABLED"]
    us=[r for r in a if r.get("urlCategories") or r.get("cloudApplications")]
    return R(R.PASS,f"{len(us)}/{len(a)} scoped to URL cats.") if us else R(R.WARN,"No URL category scoping.")
def c_a6(cl):
    """Check A.6 (Ch.A — Inline Web): CAC actions."""
    return c_4_7(cl)
def c_a7(cl):
    """Check A.7 (Ch.A — Inline Web): Tenancy."""
    return _tenancy(cl)
def c_a8(cl):
    """Check A.8 (Ch.A — Inline Web): Prompt/Confirm."""
    return c_4_8(cl)
def c_a9(cl):
    """Check A.9 (Ch.A — Inline Web): Evaluate all."""
    return c_5_20(cl)
def c_a10(cl):
    """Check A.10 (Ch.A — Inline Web): Test upload."""
    return c_8_5(cl)
def c_a11(cl):
    """Check A.11 (Ch.A — Inline Web): Web Insights."""
    return R(R.INFO,"Manual review: open Analytics > Web Insights, filter on DLP, and check that triggered rules show the expected users, destinations and actions. Not readable via the ZIA API.")
def c_a12(cl):
    """Check A.12 (Ch.A — Inline Web): Incident report."""
    return R(R.INFO,"Manual review: the DLP incident report is in Analytics (Web Insights and the DLP dashboards); review incidents by rule, engine and user there. Not readable via the ZIA API.")
def c_a13(cl):
    """Check A.13 (Ch.A — Inline Web): FP rate."""
    return c_5_10(cl)
def c_a14(cl):
    """Check A.14 (Ch.A — Inline Web): ICAP evidence."""
    return c_12_1(cl)
def c_a15(cl):
    """Check A.15 (Ch.A — Inline Web): C2C forwarding."""
    return c_12_14(cl)
def c_a16(cl):
    """Check A.16 (Ch.A — Inline Web): Notification template."""
    return c_4_9(cl)

# === Channel B ===
def c_b1(cl):
    """Check B.1 (Ch.B — Endpoint): ZDP installed."""
    return c_3_2(cl)
def c_b2(cl):
    """Check B.2 (Ch.B — Endpoint): ZCC versions."""
    return c_6_1(cl)
def c_b3(cl):
    """Check B.3 (Ch.B — Endpoint): macOS FDA."""
    return c_10_1(cl)
def c_b4(cl):
    """Check B.4 (Ch.B — Endpoint): Scan allowlists."""
    return c_5_4(cl)
def c_b5(cl):
    """Check B.5 (Ch.B — Endpoint): Rule count."""
    return c_mc2(cl)
def c_b6(cl):
    """Check B.6 (Ch.B — Endpoint): Printer coverage."""
    return c_8_2(cl)
def c_b7(cl):
    """Check B.7 (Ch.B — Endpoint): USB coverage."""
    return c_8_1(cl)
def c_b8(cl):
    """Check B.8 (Ch.B — Endpoint): Share coverage."""
    return c_8_3(cl)
def c_b9(cl):
    """Check B.9 (Ch.B — Endpoint): Cloud coverage."""
    return c_8_4(cl)
def c_b10(cl):
    """Check B.10 (Ch.B — Endpoint): OCR."""
    return c_8_12(cl)
def c_b11(cl):
    """Check B.11 (Ch.B — Endpoint): EUN templates.

    Endpoint DLP End User Notifications are set per rule (eunEnabled,
    eunTemplateId — SDK EndpointDlpRules; terraform eun_enabled,
    eun_template_id). /dlpNotificationTemplates holds the auditor email
    templates, not end-user notifications."""
    rules,a,c=_ep_rules(cl)
    ref=" Ref: https://help.zscaler.com/zia/configuring-endpoint-dlp-policy-rules"
    if rules is None: return R(R.INFO,f"Endpoint DLP rules are not readable (HTTP {c}); check End User Notification on the Endpoint DLP rules in the portal."+ref)
    if not a: return R(R.INFO,"No enabled Endpoint DLP rules (see B.5).")
    on=[r for r in a if _truthy(_fv(r,"eunEnabled"))]
    hidden=[r for r in a if r not in on and _action(r) not in ("ALLOW","NONE","ANY","")]
    custom=[r for r in on if _fv(r,"eunTemplateId")]
    if hidden: return R(R.WARN,f"{len(hidden)} enabled Endpoint DLP rule(s) that act on the data hide the End User Notification: {', '.join(str(r.get('name','?')) for r in hidden[:5])}. Endpoint DLP rules show an End User Notification on the device only when End User Notification is set to Show; set it on Block, Confirm and Protect rules so users know why the action stopped."+ref)
    return R(R.PASS,f"{len(on)} of {len(a)} enabled Endpoint DLP rule(s) show an End User Notification ({len(custom)} with a custom template, {len(on)-len(custom)} with the channel default); the rest only monitor.")
def c_b12(cl):
    """Check B.12 (Ch.B — Endpoint): Disable password.

    The app profile's Password to Disable Endpoint DLP (policyExtension
    zdpDisablePassword — zscaler-sdk-python zcc/models/webpolicy.py) on
    every active profile that installs Endpoint DLP (enableZdpService)."""
    d,e=_app_profiles_flat(cl, active_only=True)
    if e: return e
    ref=_APP_PROFILE_REF
    zdp=[p for p in d if _truthy(_fv(p,"enableZdpService"))]
    if not zdp: return R(R.INFO,"No active app profile installs Endpoint DLP (see B.1).")
    rep=[p for p in zdp if _fv(p,"zdpDisablePassword") is not None]
    if not rep: return R(R.WARN,"The app profiles do not report Password to Disable Endpoint DLP (the API may omit password values); check it in the portal (App Profiles)."+ref)
    miss=[str(p.get("name","?")) for p in zdp if not _pw(p,"zdpDisablePassword")]
    if miss: return R(R.FAIL,f"No Password to Disable Endpoint DLP on {len(miss)} app profile(s) that install Endpoint DLP: {', '.join(miss[:5])}. Set it on every app profile that installs Endpoint DLP, so users cannot switch the module off."+ref)
    return R(R.PASS,f"Password to Disable Endpoint DLP is set on all {len(zdp)} app profile(s) that install Endpoint DLP.")
def c_b13(cl):
    """Check B.13 (Ch.B — Endpoint): Endpoint Report."""
    return R(R.WARN,"Endpoint Report needs Analytics.")
def c_b14(cl):
    """Check B.14 (Ch.B — Endpoint): Discovery scan."""
    return c_5_22(cl)
def c_b15(cl):
    """Check B.15 (Ch.B — Endpoint): Workflow Automation."""
    return c_12_4(cl)
def c_b16(cl):
    """Check B.16 (Ch.B — Endpoint): User coaching.

    Endpoint DLP has its own Confirm action (terraform zia_endpoint_dlp_rules
    action CONFIRM) and User Confirmation template (ucTemplateId)."""
    rules,a,c=_ep_rules(cl)
    ref=" Ref: https://help.zscaler.com/zia/configuring-endpoint-dlp-policy-rules"
    note=" Confirm is supported only on the Removable Storage, Network Share, Printing and Personal Cloud Storage channels; on macOS printing, users can justify but not cancel."
    if rules is None: return R(R.INFO,f"Endpoint DLP rules are not readable (HTTP {c}); check the Confirm action on the Endpoint DLP rules in the portal."+ref)
    cf=[r for r in a if _action(r)=="CONFIRM"]
    if cf:
        wt=[r for r in cf if _fv(r,"ucTemplateId")]
        return R(R.PASS,f"{len(cf)} enabled Endpoint DLP rule(s) use Confirm ({len(wt)} with a User Confirmation template): {', '.join(str(r.get('name','?')) for r in cf[:4])}."+note)
    return R(R.WARN,"No enabled Endpoint DLP rule uses Confirm, so users are never asked to justify a transfer. Use Confirm for data that may leave for a business reason and keep Block for data that must never leave."+note+ref)

# === Channel E ===
# The predefined GenAI URL categories: Generative AI and ML Applications
# (AI_ML_APPS) and General AI and ML Applications (GENERAL_AI_ML), as
# ssl_flow.py and terraform zia_url_filtering_rules name them
# (https://help.zscaler.com/zia/about-url-categories). Custom categories
# count when their name says AI as a whole word.
GENAI_CATS = {"AI_ML_APPS", "GENERAL_AI_ML"}
_GENAI_WORDS = r"\b(ai|genai|gen ai|llm|llms|chatgpt|copilot|openai|gemini|claude|artificial intelligence|machine learning)\b"

def genai_category_ids(cl):
    """The predefined GenAI category ids plus the ids of custom categories named for AI."""
    import re as _re
    d,c=cl.get("/zia/urlCategories"); cats=[x for x in (_ls(d) if c in(200,204) else []) if isinstance(x, dict)]
    ids=set(GENAI_CATS)
    for x in cats:
        if _truthy(_fv(x,"customCategory")) and _re.search(_GENAI_WORDS, str(_fv(x,"configuredName","name") or ""), _re.I):
            if x.get("id") is not None: ids.add(str(x["id"]).upper())
    return ids

def targets_genai(r, ids):
    return any(n in ids for n in _names(_fv(r,"urlCategories")))

def _cac_ai(cl):
    """Enabled Cloud App Control rules of type AI & ML Applications (AI_ML)."""
    return [r for r in _cac_live(_cac_rules_all_types(cl)) if str(_fv(r,"type") or "").upper()=="AI_ML"]

def c_e1(cl):
    """Check E.1 (Ch.E — GenAI): GenAI categories.

    Every tenant has the predefined AI categories, so their existence says
    nothing; they count once an enabled URL Filtering rule uses them or an
    enabled Cloud App Control rule of type AI & ML Applications exists."""
    ids=genai_category_ids(cl)
    d,c=cl.get("/zia/urlFilteringRules"); url=[r for r in (_ls(d) if c in(200,204) else []) if isinstance(r, dict) and _enabled(r) and targets_genai(r, ids)]
    cac=_cac_ai(cl)
    if url or cac:
        return R(R.PASS,f"GenAI is governed: {len(url)} enabled URL Filtering rule(s) on the AI categories ({', '.join(str(r.get('name','?')) for r in url[:3]) or 'none'}) and {len(cac)} enabled AI & ML Applications Cloud App Control rule(s).")
    return R(R.WARN,"No enabled URL Filtering rule uses the Generative AI and ML Applications or General AI and ML Applications categories, and no enabled Cloud App Control rule of type AI & ML Applications exists. Every tenant has these predefined categories; they only protect once a rule uses them. Ref: https://help.zscaler.com/zia/about-url-categories")
def c_e2(cl):
    """Check E.2 (Ch.E — GenAI): SSL for GenAI."""
    d,e=_g(cl,"/zia/sslInspectionRules","SSL");
    if e: return e
    i=[r for r in d if _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT]
    if not i: return R(R.FAIL,"No SSL — GenAI invisible.")
    if _catch_all_decrypt(d): return R(R.PASS,"SSL on — the catch-all Inspect rule covers GenAI.")
    ai=[r for r in i if any(n in GENAI_CATS for n in _names(_fv(r,"urlCategories")))]
    if ai: return R(R.PASS,f"SSL on — {len(ai)} Decrypt rule(s) cover the AI categories: {', '.join(str(r.get('name','?')) for r in ai[:3])}.")
    return R(R.WARN,"Decrypt rules exist, but there is no catch-all Inspect rule and no Decrypt rule on the AI categories, so GenAI prompts and uploads may not be decrypted (see 4.1)."+_SSL_GUIDE)
def c_e3(cl):
    """Check E.3 (Ch.E — GenAI): CAC actions."""
    ai=_cac_ai(cl)
    if ai:
        acts=sorted({str(a) for r in ai for a in (_fv(r,"actions") or [])})
        return R(R.PASS,f"{len(ai)} enabled AI & ML Applications Cloud App Control rule(s): {', '.join(str(r.get('name','?')) for r in ai[:3])}. Actions: {', '.join(acts[:6]) or 'none listed'}.")
    return R(R.WARN,"No Cloud App Control rule of type AI & ML Applications. Use it to allow sanctioned GenAI apps and caution, block or isolate the rest, and to control granular actions (e.g. ChatGPT uploading, Copilot uploading) with SSL/TLS inspection enabled. Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control")
def c_e4(cl):
    """Check E.4 (Ch.E — GenAI): Prompt/upload/download."""
    return c_a3(cl)
def c_e5(cl):
    """Check E.5 (Ch.E — GenAI): Source code rule."""
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    cr=[r for r in d if r.get("state","").upper()=="ENABLED" and any(k in (r.get("name") or "").lower() for k in ["source","code","exfil","github","repo"])]
    return R(R.PASS,f"Code rules: {', '.join(r.get('name','?') for r in cr[:3])}") if cr else R(R.WARN,"No source-code rules by name.")
def c_e6(cl):
    """Check E.6 (Ch.E — GenAI): PII/PAN/PHI rule."""
    d,e=_g(cl,"/zia/webDlpRules","DLP"); 
    if e: return e
    pr=[r for r in d if r.get("state","").upper()=="ENABLED" and any(k in (r.get("name") or "").lower() for k in ["pii","ssn","pan","phi","pci","hipaa","personal"])]
    return R(R.PASS,f"PII rules: {', '.join(r.get('name','?') for r in pr[:3])}") if pr else R(R.WARN,"No PII-named rules.")
def c_e7(cl):
    """Check E.7 (Ch.E — GenAI): Prompt/Confirm EUN."""
    return c_4_8(cl)
def c_e8(cl):
    """Check E.8 (Ch.E — GenAI): Shadow GenAI."""
    return c_e1(cl)
def c_e9(cl):
    """Check E.9 (Ch.E — GenAI): AUP enforcement."""
    return c_e1(cl)
def c_e10(cl):
    """Check E.10 (Ch.E — GenAI): GenAI Report."""
    return R(R.WARN,"GenAI Report needs Analytics.")
def c_e11(cl):
    """Check E.11 (Ch.E — GenAI): FP review."""
    return c_5_10(cl)
def c_e12(cl):
    """Check E.12 (Ch.E — GenAI): Adversarial patterns."""
    d,c=cl.get("/zia/dlpDictionaries"); dicts=_ls(d) if c in(200,204) else []
    adv=[x for x in dicts if any(k in (x.get("name") or "").lower() for k in ["adversarial","injection","jailbreak","prompt inject"])]
    return R(R.PASS,f"Adversarial dicts: {', '.join(x.get('name','?') for x in adv[:3])}") if adv else R(R.WARN,"No adversarial prompt patterns.")
def c_e13(cl):
    """Browser Isolation applied to GenAI apps."""
    profiles, code = _cbi_profiles(cl)
    if not profiles: return c_3_7(cl)
    url_iso, cac_iso = _isolate_rules(cl)
    ai_cac=[r for r in cac_iso if str(r.get("type",""))=="AI_ML"]
    ai_url=[r for r in url_iso if any("AI" in str(c).upper() for c in (r.get("urlCategories") or r.get("url_categories") or []))]
    if ai_cac or ai_url:
        return R(R.PASS, f"{len(ai_cac)} Cloud App Control (AI_ML) and {len(ai_url)} URL Filtering rule(s) isolate GenAI traffic: users can use the tools, uploads and clipboard are controlled by the profile.")
    return R(R.WARN, f"{len(profiles)} isolation profile(s) exist but none is applied to GenAI (no AI_ML Cloud App Control rule or AI-category URL rule with ISOLATE). Best practice: isolate unsanctioned AI tools instead of blocking them outright.")
def c_e14(cl):
    """Check E.14 (Ch.E — GenAI): Copilot oversharing."""
    return R(R.WARN,"Copilot oversharing — requires M365/Entra review.")
def c_e15(cl):
    """Check E.15 (Ch.E — GenAI): GenAI logging."""
    return _web_retention(cl,"GenAI prompts and transactions") or R(R.WARN,"No enabled NSS feed — GenAI events stay in ZIA only for its six-month log window (180 days). Ref: https://help.zscaler.com/zia/about-insights-logs")

# === FULL REGISTRY ===
REG = [
    ("1.1","1 — CC Portal","ZCC Portal accessible",c_1_1),("1.2","1 — CC Portal","VPN GW Bypasses",c_1_2),("1.3","1 — CC Portal","IP Inclusions",c_1_3),("1.4","1 — CC Portal","IP Exclusions",c_1_4),("1.5","1 — CC Portal","App Bypasses",c_1_5),("1.6","1 — CC Portal","Forwarding Profile listener",c_1_6),("1.7","1 — CC Portal","DNS exclusion priority",c_1_7),("1.8","1 — CC Portal","Strict Enforcement",c_1_8),("1.9","1 — CC Portal","Pre-enrollment gap",c_1_9),("1.10","1 — CC Portal","Tamper passwords",c_1_10),("1.11","1 — CC Portal","Machine Tunnel",c_1_11),("1.12","1 — CC Portal","ZCC Telemetry",c_1_12),("1.13","1 — CC Portal","Posture Profiles",c_1_13),("1.14","1 — CC Portal","Posture-linked policies",c_1_14),
    ("2.1","2 — Bypass Inventory","App Profile inventory",c_2_1),("2.2","2 — Bypass Inventory","Forwarding listeners",c_2_2),("2.3","2 — Bypass Inventory","PAC statements",c_2_3),("2.4","2 — Bypass Inventory","DNS handling",c_2_4),("2.5","2 — Bypass Inventory","Bypass register",c_2_5),("2.6","2 — Bypass Inventory","Bypass risk scoring",c_2_6),("2.7","2 — Bypass Inventory","Sensitive domain cross-ref",c_2_7),("2.8","2 — Bypass Inventory","Review cadence",c_2_8),
    ("3.1","3 — App Profile","Z-Tunnel 2.0/DTLS",c_3_1),("3.2","3 — App Profile","Install Endpoint DLP",c_3_2),("3.3","3 — App Profile","SSL cert toggle",c_3_3),("3.4","3 — App Profile","EUNs enabled",c_3_4),("3.5","3 — App Profile","Pilot targeting",c_3_5),("3.6","3 — App Profile","Split tunneling",c_3_6),("3.7","3 — App Profile","BYOD Browser Isolation",c_3_7),("3.8","3 — App Profile","Isolation controls",c_3_8),
    ("4.1","4 — SSL Policy","Inspection scope",c_4_1),("4.2","4 — SSL Policy","Cert deployment",c_4_2),("4.3","4 — SSL Policy","Rule order",c_4_3),("4.4","4 — SSL Policy","Recommended Exemptions",c_4_4),("4.5","4 — SSL Policy","DNI entries",c_4_5),("4.6","4 — SSL Policy","Duplicate rules",c_4_6),("4.7","4 — SSL Policy","Cloud App Control",c_4_7),("4.8","4 — SSL Policy","Prompt/Confirm actions",c_4_8),("4.9","4 — SSL Policy","EUN templates",c_4_9),("4.10","4 — SSL Policy","Handshake errors",c_4_10),("4.11","4 — SSL Policy","SSL + device trust",c_4_11),("4.12","4 — SSL Policy","ECH handling",c_4_12),("4.13","4 — SSL Policy","TLS 1.3",c_4_13),("4.14","4 — SSL Policy","Decrypt rule hardening",c_4_14),
    ("5.1","5 — Endpoint DLP","ZDP install",c_5_1),("5.2","5 — Endpoint DLP","DLP Resources",c_5_2),("5.3","5 — Endpoint DLP","Web DLP rules",c_5_3),("5.4","5 — Endpoint DLP","Scan allowlists",c_5_4),("5.5","5 — Endpoint DLP","SSL DNI cats",c_5_5),("5.6","5 — Endpoint DLP","URL filter bypasses",c_5_6),("5.7","5 — Endpoint DLP","Rule exceptions",c_5_7),("5.9","5 — Endpoint DLP","Rule scope",c_5_9),("5.10","5 — Endpoint DLP","Dictionaries",c_5_10),("5.11","5 — Endpoint DLP","Custom dict FP",c_5_11),("5.12","5 — Endpoint DLP","Detection methods",c_5_12),("5.13","5 — Endpoint DLP","Content types",c_5_13),("5.14","5 — Endpoint DLP","EDM",c_5_14),("5.15","5 — Endpoint DLP","IDM",c_5_15),("5.16","5 — Endpoint DLP","Confirm/Prompt",c_5_16),("5.17","5 — Endpoint DLP","Exemptions",c_5_17),("5.18","5 — Endpoint DLP","Tenancy",c_5_18),("5.19","5 — Endpoint DLP","OCR",c_5_19),("5.20","5 — Endpoint DLP","Evaluate all rules",c_5_20),("5.21","5 — Endpoint DLP","AI classification",c_5_21),("5.22","5 — Endpoint DLP","AI discovery",c_5_22),
    ("MC.1","Multi-Channel","Inline Web DLP",c_mc1),("MC.2","Multi-Channel","Endpoint DLP",c_mc2),("MC.3","Multi-Channel","CASB",c_mc3),("MC.4","Multi-Channel","Email DLP",c_mc4),("MC.5","Multi-Channel","Browser Isolation",c_mc5),("MC.6","Multi-Channel","Data Discovery",c_mc6),("MC.7","Multi-Channel","GenAI Report",c_mc7),("MC.8","Multi-Channel","Endpoint Report",c_mc8),("MC.9","Multi-Channel","Email Report",c_mc9),("MC.10","Multi-Channel","CASB Report",c_mc10),("MC.11","Multi-Channel","DSPM",c_mc11),("MC.12","Multi-Channel","Executive summary",c_mc12),
    ("6.1","6 — Versions","ZCC versions",c_6_1),("6.2","6 — Versions","Phased rollout",c_6_2),("6.3","6 — Versions","Device hygiene",c_6_3),("6.4","6 — Versions","Inspect list",c_6_4),("6.5","6 — Versions","DNI list",c_6_5),("6.6","6 — Versions","Registers",c_6_6),("6.7","6 — Versions","Win10 count",c_6_7),
    ("7.1","7 — SSL Alignment","Cert per platform",c_7_1),("7.2","7 — SSL Alignment","Pinned apps",c_7_2),("7.3","7 — SSL Alignment","Cert expiration",c_7_3),
    ("8.1","8 — Pilot Tests","USB/Removable",c_8_1),("8.2","8 — Pilot Tests","Printer",c_8_2),("8.3","8 — Pilot Tests","Network Share",c_8_3),("8.4","8 — Pilot Tests","Personal Cloud",c_8_4),("8.5","8 — Pilot Tests","Inline Web DLP",c_8_5),("8.6","8 — Pilot Tests","Evidence (ICAP)",c_8_6),("8.7","8 — Pilot Tests","Browser Isolation",c_8_7),("8.8","8 — Pilot Tests","GenAI prompt",c_8_8),("8.9","8 — Pilot Tests","Email DLP",c_8_9),("8.10","8 — Pilot Tests","CASB API",c_8_10),("8.11","8 — Pilot Tests","EDM",c_8_11),("8.12","8 — Pilot Tests","OCR",c_8_12),
    ("9.1","9 — Troubleshooting","ZDP allowlists",c_9_1),("9.2","9 — Troubleshooting","Handshake triage",c_9_2),("9.3","9 — Troubleshooting","Web Insights",c_9_3),("9.4","9 — Troubleshooting","ZCC Diagnostics",c_9_4),
    ("10.1","10 — macOS","Full Disk Access",c_10_1),("10.2","10 — macOS","SSL cert MDM",c_10_2),("10.3","10 — macOS","Platform versions",c_10_3),("10.4","10 — macOS","Sys/Net Extensions",c_10_4),
    ("11.1","11 — Rollback","Disable path",c_11_1),("11.2","11 — Rollback","Comms plan",c_11_2),("11.3","11 — Rollback","Staging test",c_11_3),
    ("12.1","12 — Incident Mgmt","ICAP/IR deployed",c_12_1),("12.2","12 — Incident Mgmt","Secure ICAP mTLS",c_12_2),("12.3","12 — Incident Mgmt","Incident content",c_12_3),("12.4","12 — Incident Mgmt","Workflow Automation",c_12_4),("12.5","12 — Incident Mgmt","Remediation workflows",c_12_5),("12.6","12 — Incident Mgmt","User justification",c_12_6),("12.7","12 — Incident Mgmt","ITSM integration",c_12_7),("12.8","12 — Incident Mgmt","NSS/SIEM",c_12_8),("12.9","12 — Incident Mgmt","NSS DLP fields",c_12_9),("12.10","12 — Incident Mgmt","SIEM correlation",c_12_10),("12.11","12 — Incident Mgmt","Log retention beyond 180 days (NSS export)",c_12_11),("12.12","12 — Incident Mgmt","Evidence storage",c_12_12),("12.13","12 — Incident Mgmt","Admin role segregation",c_12_13),("12.14","12 — Incident Mgmt","C2C forwarding",c_12_14),
    ("A.1","Ch.A — Inline Web","Rule count",c_a1),("A.2","Ch.A — Inline Web","SSL+DNI",c_a2),("A.3","Ch.A — Inline Web","Rule verbs",c_a3),("A.4","Ch.A — Inline Web","File type scope",c_a4),("A.5","Ch.A — Inline Web","URL scope",c_a5),("A.6","Ch.A — Inline Web","CAC actions",c_a6),("A.7","Ch.A — Inline Web","Tenancy",c_a7),("A.8","Ch.A — Inline Web","Prompt/Confirm",c_a8),("A.9","Ch.A — Inline Web","Evaluate all",c_a9),("A.10","Ch.A — Inline Web","Test upload",c_a10),("A.11","Ch.A — Inline Web","Web Insights",c_a11),("A.12","Ch.A — Inline Web","Incident report",c_a12),("A.13","Ch.A — Inline Web","FP rate",c_a13),("A.14","Ch.A — Inline Web","ICAP evidence",c_a14),("A.15","Ch.A — Inline Web","C2C forwarding",c_a15),("A.16","Ch.A — Inline Web","Notification template",c_a16),("A.17","Ch.A — Inline Web","Browser Isolation coverage",c_a17),
    ("B.1","Ch.B — Endpoint","ZDP installed",c_b1),("B.2","Ch.B — Endpoint","ZCC versions",c_b2),("B.3","Ch.B — Endpoint","macOS FDA",c_b3),("B.4","Ch.B — Endpoint","Scan allowlists",c_b4),("B.5","Ch.B — Endpoint","Rule count",c_b5),("B.6","Ch.B — Endpoint","Printer coverage",c_b6),("B.7","Ch.B — Endpoint","USB coverage",c_b7),("B.8","Ch.B — Endpoint","Share coverage",c_b8),("B.9","Ch.B — Endpoint","Cloud coverage",c_b9),("B.10","Ch.B — Endpoint","OCR",c_b10),("B.11","Ch.B — Endpoint","EUN templates",c_b11),("B.12","Ch.B — Endpoint","Disable password",c_b12),("B.13","Ch.B — Endpoint","Endpoint Report",c_b13),("B.14","Ch.B — Endpoint","Discovery scan",c_b14),("B.15","Ch.B — Endpoint","Workflow Automation",c_b15),("B.16","Ch.B — Endpoint","User coaching",c_b16),
    ("E.1","Ch.E — GenAI","GenAI categories",c_e1),("E.2","Ch.E — GenAI","SSL for GenAI",c_e2),("E.3","Ch.E — GenAI","CAC actions",c_e3),("E.4","Ch.E — GenAI","Prompt/upload/download",c_e4),("E.5","Ch.E — GenAI","Source code rule",c_e5),("E.6","Ch.E — GenAI","PII/PAN/PHI rule",c_e6),("E.7","Ch.E — GenAI","Prompt/Confirm EUN",c_e7),("E.8","Ch.E — GenAI","Shadow GenAI",c_e8),("E.9","Ch.E — GenAI","AUP enforcement",c_e9),("E.10","Ch.E — GenAI","GenAI Report",c_e10),("E.11","Ch.E — GenAI","FP review",c_e11),("E.12","Ch.E — GenAI","Adversarial patterns",c_e12),("E.13","Ch.E — GenAI","Browser Isolation",c_e13),("E.14","Ch.E — GenAI","Copilot oversharing",c_e14),("E.15","Ch.E — GenAI","GenAI logging",c_e15),
]

# SaaS Security (Ch.C) and Email DLP (Ch.D) as scored channel sections,
# beside Inline Web, Endpoint and GenAI.
try:
    import saas_email_checks as _saas_email
    REG = _saas_email.splice(REG)
except Exception as _e:  # noqa: BLE001
    print(f"[warn] SaaS / Email checks not loaded: {_e}")

# Strict Client Connector evaluation (app profiles, forwarding profiles,
# trusted networks, fail-open, privacy, company, devices, notification
# templates), spliced into sections 1, 6 and 12.
try:
    import zcc_evaluation as _zcc_eval
    REG = _zcc_eval.splice(REG)
except Exception as _e:  # noqa: BLE001
    print(f"[warn] strict ZCC checks not loaded: {_e}")

# === RUNNER ===
def run(client, con=None):
    """Run the DLP checks (backwards compatible)."""
    return run_checks(client, REG, con)

def _plain(row):
    """Attach the plain-English block (plain_english.explain) to a result."""
    try:
        import plain_english
        return plain_english.enrich(row)
    except Exception:  # noqa: BLE001
        return row


def run_checks(client, checks, con=None):
    """Run an arbitrary list of checks."""
    results=[]
    if HAS_RICH and con:
        with Progress(SpinnerColumn(),TextColumn("[progress.description]{task.description}"),BarColumn(),TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),console=con) as prog:
            task=prog.add_task("Scanning...",total=len(checks))
            for id,sec,label,fn in checks:
                prog.update(task,description=f"[cyan]{id}[/] {label}")
                try: r=fn(client)
                except Exception as ex: r=R(R.ERROR,f"{label}: Could not complete check. {str(ex)[:120]}")  # "Could not be checked", never "Not configured"
                results.append(_plain({"id":id,"sec":sec,"label":label,"status":r.status,"detail":r.detail}))
                prog.advance(task)
    else:
        for i,(id,sec,label,fn) in enumerate(checks,1):
            print(f"  [{i}/{len(checks)}] {id}: {label}...",end=" ",flush=True)
            try: r=fn(client)
            except Exception as ex: r=R(R.ERROR,f"{label}: Could not complete check. {str(ex)[:120]}")  # "Could not be checked", never "Not configured"
            results.append(_plain({"id":id,"sec":sec,"label":label,"status":r.status,"detail":r.detail}))
            print(r.status)
    return results

# The score (docs/SCORING.md): configured ÷ (configured + action required +
# needs review), as a percentage. INFO and ERROR results — a feature that
# is not licensed, a call the API client was not allowed to make, a check
# that could not complete — are not in either side of that division, so
# they neither raise nor lower the score. When nothing at all was
# scoreable the score is None ("Not assessed"), never 100: an empty set is
# not a perfect one.
NOT_ASSESSED = "Not assessed"

def maturity(p):
    if p is None: return NOT_ASSESSED
    if p>=90: return "Optimized"
    if p>=75: return "Managed"
    if p>=50: return "Developing"
    if p>=25: return "Initial"
    return "Ad Hoc"

def pct_text(p):
    """'37%' or 'n/a' — never 'None%'."""
    return "n/a" if p is None else f"{p}%"

def compute(results):
    _map={"PASS":"pass","FAIL":"fail","REVIEW":"warn","INFO":"info","ERROR":"info"}
    secs={}
    for r in results:
        s=r.get("sec") or r.get("section") or "Other"
        if s not in secs: secs[s]={"total":0,"pass":0,"fail":0,"warn":0,"info":0}
        secs[s]["total"]+=1
        secs[s][_map.get(r["status"],"info")]+=1
    for s in secs:
        scored=secs[s]["total"]-secs[s]["info"]  # INFO checks don't count against score
        secs[s]["scored"]=scored
        secs[s]["pct"]=round(secs[s]["pass"]/scored*100) if scored else None   # nothing scoreable: not measured
    scored_total=sum(s["total"]-s["info"] for s in secs.values())
    passed=sum(s["pass"] for s in secs.values())
    return secs, (round(passed/scored_total*100) if scored_total else None)

def coverage(results):
    """How much of the run was actually assessed (permissions.assessment_summary):
    the same numbers the GUI and the Word report show."""
    import permissions
    return permissions.assessment_summary(results)

def coverage_text(cov):
    """'Assessed 180 of 206 checks · 20 not permitted · 6 could not be checked'."""
    parts=[f"Assessed {cov['assessed']} of {cov['total']} checks"]
    if cov["not_permitted"]: parts.append(f"{cov['not_permitted']} not permitted to the API client")
    if cov["errors"]: parts.append(f"{cov['errors']} could not be checked")
    if cov["not_in_scope"]: parts.append(f"{cov['not_in_scope']} not in scope")
    return " · ".join(parts)

def partial_banner(cov):
    """The warning a partial run carries next to its score, or ''."""
    if cov["state"]!="partial": return ""
    return (f"PARTIAL COVERAGE: the score covers only what could be checked. {cov['not_permitted']} check(s) were refused to the API client "
            f"and {cov['errors']} could not be completed; they are left out of the score, so it may look better than the tenant is.")

def report(results, cfg, con=None):
    secs,overall=compute(results); mat=maturity(overall)
    cov=coverage(results); banner=partial_banner(cov)
    if HAS_RICH and con:
        con.print("\n")
        o=overall if overall is not None else 0
        con.print(Panel.fit(f"[bold]{cfg.get('org_name','')}[/] · {datetime.now().strftime('%Y-%m-%d')}\n[bold {'dim' if overall is None else 'green' if o>=75 else 'yellow' if o>=50 else 'red'}]{pct_text(overall)} — {mat}[/]\n[dim]{coverage_text(cov)} · zero manual[/]",border_style="cyan",title="[bold cyan]DLP ASSESSMENT[/]"))
        if banner: con.print(Panel.fit(f"[bold yellow]{banner}[/]",border_style="yellow"))
        t=Table(title="Scorecard",show_lines=True)
        t.add_column("Section",style="bold"); t.add_column("Score",justify="center"); t.add_column("P",style="green",justify="center"); t.add_column("F",style="red",justify="center"); t.add_column("R",style="yellow",justify="center")
        for s,d in secs.items():
            p=d["pct"]
            c="dim" if p is None else "green" if p>=75 else "yellow" if p>=50 else "red"
            t.add_row(s,f"[{c}]{pct_text(p)}[/]",str(d["pass"]),str(d["fail"]),str(d["warn"]))
        con.print(t)
        con.print("\n[bold cyan]FINDINGS[/]")
        cur=""
        for r in results:
            if r["sec"]!=cur: cur=r["sec"]; con.print(f"\n[bold underline]{cur}[/]")
            sc={"PASS":"green","FAIL":"red","REVIEW":"yellow","ERROR":"red"}.get(r["status"],"dim")
            con.print(f"  [{sc}]{r['status']:>7}[/] [cyan]{r['id']:>5}[/] {r['label']}")
            if r["detail"]: con.print(f"          [dim]{r['detail']}[/]")
        fails=[r for r in results if r["status"]==R.FAIL]
        if fails:
            con.print(f"\n[bold red]CRITICAL ({len(fails)})[/]")
            for r in fails: con.print(f"  [red]✗[/] {r['id']}: {r['label']} — {r['detail']}")
    else:
        print(f"\n{'='*64}\n  {cfg.get('org_name','')} · {pct_text(overall)} {mat} · {coverage_text(cov)}\n{'='*64}")
        if banner: print(f"  !! {banner}\n{'='*64}")
        for r in results: print(f"  {r['status']:>7} {r['id']:>5} {r['label']}")

def save(results, cfg, path):
    secs,overall=compute(results)
    rpt={"metadata":{"tool":"DLP Assessment Full Auto","version":"3.0","ts":datetime.now(timezone.utc).isoformat(),"org":cfg.get("org_name",""),"assessor":cfg.get("assessor",""),"cloud":cfg.get("cloud",""),"checks":len(results)},"score":overall,"maturity":maturity(overall),"coverage":coverage(results),"sections":secs,"checks":[{"id":r["id"],"sec":r["sec"],"label":r["label"],"status":r["status"],"detail":r["detail"]} for r in results],"critical":[r for r in results if r["status"]==R.FAIL],"review":[r for r in results if r["status"]==R.WARN]}
    with open(path,"w") as f: json.dump(rpt,f,indent=2,default=str)

class ConfigError(ValueError):
    """A tenant configuration file that cannot be used, with the reason."""


REQUIRED_CONFIG_KEYS = ("client_id", "client_secret", "vanity_domain")


def load_config_file(path: str) -> dict:
    """Read a tenant configuration JSON file (see tenant_config_sample.json).

    Raises ConfigError, in plain words, when the file is missing, is not
    valid JSON, is not a JSON object, or lacks client_id, client_secret or
    vanity_domain. `cloud` defaults to "production" when absent."""
    try:
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    except FileNotFoundError:
        raise ConfigError(f"the configuration file {path} does not exist (copy tenant_config_sample.json and fill it in)")
    except OSError as e:
        raise ConfigError(f"the configuration file {path} could not be read: {e}")
    except json.JSONDecodeError as e:
        raise ConfigError(f"the configuration file {path} is not valid JSON (line {e.lineno}, column {e.colno}: {e.msg})")
    if not isinstance(cfg, dict):
        raise ConfigError(f"the configuration file {path} must contain a JSON object with the tenant details")
    missing = [k for k in REQUIRED_CONFIG_KEYS if not str(cfg.get(k) or "").strip()]
    if missing:
        raise ConfigError(f"the configuration file {path} is missing {', '.join(missing)}")
    cfg.setdefault("cloud", "production")
    return cfg


def main():
    """Command-line entry point: run the assessment against one tenant and
    write the JSON (and Word) report. Exit code 0 on success, 1 when the
    tenant refuses the credentials, 2 for a configuration or file error."""
    ap=argparse.ArgumentParser(description="Zscaler Assessment — Full Auto")
    ap.add_argument("--config"); ap.add_argument("--output")
    ap.add_argument("--scope", default="dlp", choices=["dlp","full","zia","zpa","zcc","all"],
                    help="Assessment scope: dlp (default), full (dlp+platform), zia, zpa, zcc, or all")
    args=ap.parse_args(); con=Console() if HAS_RICH else None
    def prompt_config():
        print("\n"+"="*64+"\n  ZSCALER ASSESSMENT — FULL AUTO\n"+"="*64)
        c={}; c["org_name"]=input("  Org: ").strip(); c["assessor"]=input("  Assessor: ").strip()
        print("  Clouds: "+", ".join(f"{i+1}.{k}" for i,k in enumerate(CLOUDS)))
        try: c["cloud"]=CLOUDS[int(input("  Select: ").strip())-1]
        except: c["cloud"]="production"
        c["vanity_domain"]=input("  Vanity domain: ").strip()
        c["client_id"]=input("  Client ID: ").strip(); c["client_secret"]=input("  Client Secret: ").strip()
        if input("  Run? (y/n): ").strip().lower()!="y": sys.exit(0)
        return c
    def prompt_config_rich(con):
        con.print(Panel.fit("[bold cyan]ZSCALER ASSESSMENT — FULL AUTO[/]\n[dim]Zero manual checks[/]",border_style="cyan"))
        c={}; c["org_name"]=Prompt.ask("[bold]Org"); c["assessor"]=Prompt.ask("[bold]Assessor")
        t=Table(show_header=False,box=None)
        for i,k in enumerate(CLOUDS,1): t.add_row(f"  {i}.",k)
        con.print(t); ch=Prompt.ask("Cloud",choices=[str(i) for i in range(1,len(CLOUDS)+1)],default="1")
        c["cloud"]=CLOUDS[int(ch)-1]; c["vanity_domain"]=Prompt.ask("[bold]Vanity domain",default="acme")
        c["client_id"]=Prompt.ask("[bold]Client ID"); c["client_secret"]=Prompt.ask("[bold]Secret",password=True)
        if not Confirm.ask("[bold]Run?"): sys.exit(0)
        return c
    if args.config:
        try:
            cfg = load_config_file(args.config)
        except ConfigError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(2)
    else:
        cfg = prompt_config_rich(con) if HAS_RICH else prompt_config()

    # Build check registry based on scope
    check_reg = list(REG)
    if args.scope != "dlp":
        try:
            from zscaler_full_checks import PLATFORM_REG
            if args.scope == "full" or args.scope == "all":
                check_reg = list(REG) + PLATFORM_REG
            elif args.scope == "zia":
                check_reg = list(REG) + [c for c in PLATFORM_REG if c[1].startswith("ZIA")]
            elif args.scope == "zpa":
                check_reg = [c for c in PLATFORM_REG if c[1].startswith("ZPA")]
            elif args.scope == "zcc":
                check_reg = [c for c in PLATFORM_REG if c[1].startswith("ZCC")]
        except ImportError:
            print("WARNING: zscaler_full_checks.py not found, running DLP checks only.")

    cl=Client(cfg["client_id"],cfg["client_secret"],cfg["vanity_domain"],cfg["cloud"])
    (con.print("[bold]Authenticating...[/]",end=" ") if con else print("  Auth...",end=" ",flush=True))
    a=cl.auth()
    if a is True: (con.print("[green]OK[/]") if con else print("OK"))
    else: print(f"FAIL: {a}"); sys.exit(1)
    (con.print(f"\n[bold]{len(check_reg)} automated checks ({args.scope} scope)...[/]\n") if con else print(f"\n  {len(check_reg)} checks ({args.scope} scope)...\n"))
    results=run_checks(cl, check_reg, con); report(results,cfg,con)
    ts=datetime.now().strftime('%Y%m%d_%H%M%S')
    base_name=f"zscaler_{cfg.get('org_name','').replace(' ','_')}_{ts}"
    json_out=args.output or f"{base_name}.json"
    try:
        save(results,cfg,json_out)
    except OSError as e:
        print(f"Error: the report could not be written to {json_out}: {e}", file=sys.stderr)
        sys.exit(2)
    # Generate Word doc
    docx_out=json_out.replace(".json",".docx") if json_out.endswith(".json") else f"{base_name}.docx"
    try:
        from report_docx import generate_report
        generate_report(results,cfg,docx_out,compute,maturity)
        (con.print(f"\n[green]JSON:  {json_out}[/]\n[green]Word:  {docx_out}[/]\n") if con else print(f"\n  JSON: {json_out}\n  Word: {docx_out}\n"))
    except ImportError:
        (con.print(f"\n[green]Report: {json_out}[/]\n[dim](pip install python-docx for Word report)[/]\n") if con else print(f"\n  Report: {json_out}\n  (pip install python-docx for Word report)\n"))
    except Exception as ex:
        (con.print(f"\n[green]JSON: {json_out}[/]\n[yellow]Word failed: {ex}[/]\n") if con else print(f"\n  JSON: {json_out}\n  Word failed: {ex}\n"))

if __name__=="__main__": main()
