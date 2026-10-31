"""ZDX probe setup: Zscaler Digital Experience applications and probes as
three operation types on the Bulk changes engine (admin_ops.register).

ZDX measures how fast users reach the applications they depend on with
*probes* that Client Connector runs on each device: a Web probe fetches a
URL, a CloudPath probe traces the network path to the host. Probes belong
to an *application*: a predefined one (Zscaler's own definition of, for
example, Microsoft 365 sign-in or Zoom, often with the customer's tenant
prefix in its host) or a custom one (any URL).

  zdx_probes         set up apps and probes from a template: predefined
                     apps (ZDX adds their Web and CloudPath probes) and
                     custom apps by URL (a Web probe and, by default, a
                     CloudPath probe that follows it), for all users. An
                     app that already exists is skipped, or gets only what
                     it lacks. A custom app whose setup fails half way is
                     removed again (its probes first).
  zdx_probe_state    turn apps and probes on or off.
  zdx_probe_delete   delete custom apps (their probes first, CloudPath
                     before Web) and custom probes. Each target carries the
                     object's name as the operator typed it: a name that
                     does not match the tenant excludes the target. The
                     undo of a setup is one of these (with `turn_off`).

The engine gives every type the same path as any bulk change: the scope
check (`in_scope`: ZDX ticked on the Scope page) before anything is read,
a plan that only reads, the plan hash, the re-plan before writing, write
mode, the writer, the assessor and the typed confirmation, a re-read right
before each write (in the handlers here), the read-back (`verify`), the
record, the audit log and Undo (`inverse`). Writes go through
pack_ops.create / update / delete (kinds zdx_app, zdx_probe,
zdx_collection), which pace, retry, stop and audit them.

Tiers
-----
A setup can follow a tier (`tier`: strict, balanced, permissive or
healthcare, the same names as the ZIA security baseline; balanced when the
form names none): Strict monitors the most apps (the Microsoft 365 set,
Zoom, Webex, Okta, Salesforce, ServiceNow and Box) every 5 minutes with a
CloudPath probe on each; Balanced the Microsoft 365 core (sign-in, Outlook,
Teams) every 10 minutes with CloudPath; Permissive Microsoft 365 sign-in
every 15 minutes, Web probes only; Healthcare the Microsoft 365 core and
Zoom (telehealth) every 5 minutes with CloudPath. The interval applies to
the custom apps' probes (a predefined app keeps the probes ZDX makes for
it). A choice looser than the tier (a longer interval, a CloudPath probe
left out) is a warning in the preview, never a block. These defaults are
this app's recommendation, not a Zscaler setting.

What is verified and what is assumed
------------------------------------
VERIFIED against the installed zscaler-sdk-python 1.11.3 (tests/
test_ops_zdx.py and tests/test_health_diag.py read the SDK):

  * the ZDX API prefix /zdx/v1 (zscaler/zdx/*.py, `_zdx_base_endpoint`);
  * the SDK's request executor signs "/zdx" paths with the OneAPI token,
    routes them to the OneAPI gateway as ZDX requests (get_service_type)
    and sends ZDX bodies as given, without the camelCase conversion of
    other products (request_executor._prepare_body);
  * the SDK has no ZDX *configuration* service: zscaler/zdx/ covers only
    the read-only analytics API (apps, devices with their web-probes and
    cloudpath-probes, alerts, inventory, troubleshooting, users, admin),
    so nothing below can be checked against it.

ASSUMED (not in the SDK, and not checked against a live tenant from here):

  GET    /zdx/v1/config/applications                       configured apps
  GET    /zdx/v1/config/applications/supported?type=PREDEFINED   catalogue
  GET    /zdx/v1/config/applications/{key}                 one app
  POST   /zdx/v1/config/applications                       create (with collection {id, name})
  PUT    /zdx/v1/config/applications/{key}/activate|deactivate
  DELETE /zdx/v1/config/applications/{id}                  custom apps only
  GET    /zdx/v1/config/monitors                           every probe
  GET    /zdx/v1/config/applications/{key}/monitors        an app's probes
  POST   /zdx/v1/config/applications/{key}/monitors        create a probe
  PUT    /zdx/v1/config/applications/{key}/monitors/{id}/activate|deactivate
  DELETE /zdx/v1/config/applications/{key}/monitors/{id}
  GET    /zdx/v1/config/collections
  POST   /zdx/v1/config/collections                        {name, type END_USER, ...}

``{key}`` is a custom app's numeric id and a predefined app's provider (for
example MICROSOFT_LOGIN). The order (a custom app created off, its Web
probe, its CloudPath probe following the Web probe, then the app turned on;
a predefined app created with its prefix, which makes ZDX add its own Web
and CloudPath probes, then turned on with them; CloudPath before Web when
turning off or deleting), the probe bodies, the intervals and the
"Custom Apps Collection" a new ZDX tenant lacks are assumed the same way.
"""
from __future__ import annotations

import ipaddress
import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple
from urllib.parse import quote, urlsplit

import admin_ops as ao
import pack_ops as ops

ZDX_BASE = "/zdx/v1"                # verified: zscaler-sdk-python 1.11.3 zdx/*.py _zdx_base_endpoint
CONFIG = ZDX_BASE + "/config"      # ASSUMED: the /config part (no configuration service in the SDK)
FAMILY = "zdx_apps"
T_SETUP, T_STATE, T_DELETE = "zdx_probes", "zdx_probe_state", "zdx_probe_delete"
INTERVALS_MIN = (5, 10, 15, 30)    # ASSUMED: the probe intervals ZDX offers between 5 and 30 minutes
PROTOCOLS = ("ADAPTIVE", "ICMP", "TCP", "UDP")
PROTOCOL_LABELS = {"ADAPTIVE": "Adaptive", "ICMP": "ICMP", "TCP": "TCP", "UDP": "UDP"}
WEB_TYPES = ("WEB",)
PATH_TYPES = ("TRACERT", "TRACERT_V2", "HIFI_MTR")
MAX_CUSTOM = 20
MAX_PREDEFINED = 20
MAX_TARGETS = 100
NAME_MAX = 64                      # ASSUMED: ZDX app and probe names
URL_MAX = 1024
NAME_RE = re.compile(r"^[\w .()\-:/&+]{1,64}$")
PREFIX_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.I)
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$", re.I)
_ID_RE = re.compile(r"^(?!\.+$)[A-Za-z0-9_.-]{1,80}$")

CUSTOM_COLLECTION = {"name": "Custom Apps Collection", "description": "Custom applications"}
PREDEFINED_COLLECTION = {"name": "Predefined Apps Collection", "description": "Predefined applications"}
ASSESSOR_PLACEHOLDER = "<assessor>"
NOT_IN_SCOPE = "Not in scope: ZDX is not ticked on the Scope page, so ZDX is not read or changed."

LABELS = {"custom": "ZDX custom app", "predefined": "ZDX predefined app", "web": "ZDX Web probe", "cloudpath": "ZDX CloudPath probe",
          "other": "ZDX probe", "collection": "ZDX collection"}

# Friendly words for the predefined apps ZDX offers. The catalogue itself is
# read from the tenant: an app the tenant does not offer is refused in the
# plan, and one not listed here keeps ZDX's own name.
PREDEFINED: Dict[str, Dict[str, str]] = {
    "MICROSOFT_LOGIN": {"label": "Microsoft 365 sign-in", "about": "The Microsoft 365 and Entra ID sign-in page (login.microsoftonline.com)."},
    "OUTLOOK": {"label": "Microsoft 365 Outlook", "about": "Outlook on the web (outlook.office365.com)."},
    "MICROSOFT_TEAMS": {"label": "Microsoft Teams", "about": "The Teams web app (teams.microsoft.com)."},
    "SHAREPOINT": {"label": "SharePoint Online", "about": "The customer's SharePoint (needs the tenant prefix)."},
    "ONEDRIVE": {"label": "OneDrive for Business", "about": "The customer's OneDrive (needs the tenant prefix)."},
    "ZOOM": {"label": "Zoom", "about": "The customer's Zoom account (needs the account prefix)."},
    "OKTA": {"label": "Okta", "about": "The customer's Okta org (needs the org prefix)."},
    "BOX": {"label": "Box", "about": "The Box web app (app.box.com)."},
    "SALESFORCE_CLASSIC": {"label": "Salesforce", "about": "The customer's Salesforce org (needs the org prefix)."},
    "SALESFORCE_LIGHTENING": {"label": "Salesforce Lightning", "about": "The customer's Salesforce Lightning org (needs the org prefix)."},
    "SERVICENOW": {"label": "ServiceNow", "about": "The customer's ServiceNow instance (needs the instance prefix)."},
    "WEBEX": {"label": "Webex", "about": "The customer's Webex site (needs the site prefix)."},
}

TEMPLATES: Dict[str, Dict[str, Any]] = {
    "best_practice": {
        "id": "best_practice", "name": "Best practice",
        "about": ("The probes to turn on first: Microsoft 365 sign-in (a predefined app) and one custom app, each with a Web "
                  "probe and a CloudPath probe, for all users. Replace the custom app with the site that matters most to the customer."),
        "predefined": [{"provider": "MICROSOFT_LOGIN", "web": True, "cloudpath": True}],
        "custom": [{"name": "Zscaler", "url": "https://www.zscaler.com/", "cloudpath": True}],
        "interval_minutes": 5, "protocol": "ADAPTIVE",
    },
    "microsoft_365": {
        "id": "microsoft_365", "name": "Microsoft 365",
        "about": ("Microsoft 365 sign-in, Outlook, Teams, SharePoint and OneDrive (SharePoint and OneDrive need the customer's "
                  "tenant prefix), each with its Web and CloudPath probes, for all users."),
        "predefined": [{"provider": p, "web": True, "cloudpath": True}
                       for p in ("MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS", "SHAREPOINT", "ONEDRIVE")],
        "custom": [], "interval_minutes": 5, "protocol": "ADAPTIVE",
    },
    # Federal POVs (pov_build.PRESET_DEFAULTS["federal"]): the Microsoft 365 core plus the federal sites staff sign in to,
    # as custom apps. The hosts are templates to review: Login.gov's sign-in host, USAJOBS and SAM.gov are public
    # sites; a GCC or GCC High Microsoft 365 tenant signs in at other hosts than the predefined Microsoft apps probe
    # (assumed), and agencies add their own portals.
    "federal": {
        "id": "federal", "name": "Federal",
        "about": ("Microsoft 365 sign-in, Outlook and Teams, plus Login.gov, USAJOBS and SAM.gov as custom apps, each with Web and "
                  "CloudPath probes, for all users. The hosts are templates to review with the agency (a GCC or GCC High Microsoft 365 "
                  "tenant may sign in elsewhere)."),
        "predefined": [{"provider": p, "web": True, "cloudpath": True} for p in ("MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS")],
        "custom": [{"name": "Login.gov", "url": "https://secure.login.gov/", "cloudpath": True},
                   {"name": "USAJOBS", "url": "https://www.usajobs.gov/", "cloudpath": True},
                   {"name": "SAM.gov", "url": "https://sam.gov/", "cloudpath": True}],
        "keep_custom": True, "review": "The custom app hosts are templates: confirm them with the agency before the POV.",
        "interval_minutes": 5, "protocol": "ADAPTIVE",
    },
    "empty": {
        "id": "empty", "name": "Start empty",
        "about": "Nothing picked: choose predefined apps and add custom apps (for example an internal portal) yourself.",
        "predefined": [], "custom": [], "interval_minutes": 5, "protocol": "ADAPTIVE",
    },
}

# The tiers (this app's recommendation, see the module docstring). Keys
# are the ZIA security baseline's tiers, so one choice fits both builders.
TIERS: Dict[str, Dict[str, Any]] = {
    "strict": {"key": "strict", "label": "Strict", "interval_minutes": 5, "cloudpath": True, "protocol": "ADAPTIVE",
               "predefined": ["MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS", "SHAREPOINT", "ONEDRIVE", "ZOOM", "WEBEX", "OKTA",
                              "SALESFORCE_CLASSIC", "SERVICENOW", "BOX"],
               "what": ("The most apps (Microsoft 365, Zoom, Webex, Okta, Salesforce, ServiceNow, Box), every 5 minutes, each with a "
                        "CloudPath probe: problems show within minutes.")},
    "balanced": {"key": "balanced", "label": "Balanced", "interval_minutes": 10, "cloudpath": True, "protocol": "ADAPTIVE",
                 "predefined": ["MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS"],
                 "what": "The Microsoft 365 core (sign-in, Outlook, Teams) every 10 minutes, with CloudPath probes."},
    "permissive": {"key": "permissive", "label": "Permissive", "interval_minutes": 15, "cloudpath": False, "protocol": "ADAPTIVE",
                   "predefined": ["MICROSOFT_LOGIN"],
                   "what": "Microsoft 365 sign-in every 15 minutes, Web probes only: the lightest load on devices."},
    "healthcare": {"key": "healthcare", "label": "Healthcare", "interval_minutes": 5, "cloudpath": True, "protocol": "ADAPTIVE",
                   "predefined": ["MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS", "ZOOM"],
                   "what": ("The Microsoft 365 core and Zoom for telehealth, every 5 minutes with CloudPath probes; add the EHR "
                            "portal as a custom app.")},
}
DEFAULT_TIER = "balanced"


def tier_template(tier: str) -> Dict[str, Any]:
    """The apps, interval and protocol a tier starts from (the form's
    "start from the tier"): its predefined apps with Web probes and, when
    the tier has them, CloudPath probes; no custom app."""
    t = TIERS[tier]
    return {"id": f"tier_{t['key']}", "name": f"{t['label']} tier", "about": t["what"], "tier": t["key"],
            "predefined": [{"provider": p, "web": True, "cloudpath": t["cloudpath"]} for p in t["predefined"]],
            "custom": [], "interval_minutes": t["interval_minutes"], "protocol": t["protocol"]}


ASSUMED_NOTE = ("The ZDX configuration API is not in the Zscaler SDK this app uses: its paths, bodies and step order are "
                "assumed from Zscaler's public descriptions, not verified against your tenant. Check the result in the ZDX portal.")
ALL_USERS_NOTE = "Probes run for all users: no department, location or group is singled out."


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """Why ZDX may not be read or changed (None when it is ticked)."""
    return None if "zdx" in (scope.get("scopes") or []) else NOT_IN_SCOPE


# ---------------------------------------------------------------------------
# Errors from ZDX, in words
# ---------------------------------------------------------------------------

def error_parts(err: Any) -> Dict[str, Any]:
    """{status, code, message} from what the SDK's executor handed back
    (its ZscalerAPIError, an HTTP error, an exception or a dict)."""
    if isinstance(err, dict):
        st = err.get("status") or err.get("status_code")
        try:
            st = int(st) if st is not None else None
        except (TypeError, ValueError):
            st = None
        return {"status": st, "code": str(err["code"])[:80] if err.get("code") else None,
                "message": str(err.get("message") or err.get("error") or "")[:300]}
    status = getattr(err, "status_code", None)
    message = getattr(err, "error_message", None)
    if status is not None or message is not None:
        code = getattr(err, "error_code", None)
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        return {"status": status, "code": str(code)[:80] if code else None, "message": str(message or "")[:300]}
    msg, code, status = ops._error_parts(err)
    return {"status": status, "code": code, "message": str(msg)[:300]}


_HOST_WORDS = ("host", "url", "domain", "fqdn", "address", "destination", "target")


def explain(status: Optional[int], code: Optional[str] = None, message: Optional[str] = None) -> str:
    """One plain sentence for a ZDX refusal."""
    m = f"{code or ''} {message or ''}".lower()
    if status == 401:
        return "ZDX did not accept the sign-in (it expired, or the API client's secret changed). Reconnect, then try again."
    if status == 403:
        return ("ZDX refused it: the API client may not change ZDX configuration (in ZIdentity, give it a role with ZDX "
                "configuration write access), or the object is Zscaler's own and can only be turned off.")
    if status == 404:
        return "ZDX does not have this object: it was deleted meanwhile, or the ZDX configuration API is not available to this API client."
    if status == 409:
        return "ZDX refused it as a conflict: an object with this name already exists, or it is already in that state."
    if status == 429:
        return "ZDX's rate limit: too many requests in a short time. Wait a minute, then preview again to finish."
    if status is not None and 500 <= status < 600:
        return "ZDX's side failed or was busy. Wait a few minutes, then preview again to finish."
    if status == 400 and any(w in m for w in _HOST_WORDS):
        return ("ZDX refused the host or URL. Use a host name or URL users really reach (a CloudPath probe takes the host name "
                "only); ZDX does not probe some hosts, such as reserved or Zscaler addresses.")
    if status == 400:
        return "ZDX rejected the request as sent (a name, a value or a limit it does not accept)."
    return ""


def describe(parts: Dict[str, Any]) -> str:
    """'HTTP 400 · INVALID_HOST: the host is not allowed', as ZDX said it."""
    head = " · ".join(x for x in (f"HTTP {parts['status']}" if parts.get("status") else "", parts.get("code") or "") if x)
    msg = parts.get("message") or ""
    return f"{head}: {msg}" if head and msg else (head or msg or "ZDX gave no reason")


# ---------------------------------------------------------------------------
# The ZDX configuration API, on the SDK's request executor
# ---------------------------------------------------------------------------

def _items(body: Any) -> List[Dict[str, Any]]:
    if isinstance(body, list):
        return [x for x in body if isinstance(x, dict)]
    if isinstance(body, dict):
        for k in ("items", "list", "content", "applications", "monitors", "collections", "data"):
            if isinstance(body.get(k), list):
                return [x for x in body[k] if isinstance(x, dict)]
    return []


_DOT_SEGMENT = re.compile(r"(?:^|/)\.{1,2}(?:/|$)")


def _seg(v: Any) -> str:
    return quote(str(v), safe="")


class ZdxApi:
    """The ZDX configuration API (ASSUMED paths) on the signed-in client's
    request executor. Reads are paced with the app's request pacer; the
    write methods are called only by pack_ops (create / update / delete)."""

    def __init__(self, client: Any) -> None:
        svc = getattr(client, "zdx", None)
        self.ex = getattr(svc, "_request_executor", None) if svc is not None else None
        if self.ex is None:
            self.ex = getattr(client, "_request_executor", None)
        self.reads = 0

    def send(self, method: str, path: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Tuple[Any, Optional[Dict[str, Any]]]:
        """(payload, None) or (None, {status, code, message})."""
        if self.ex is None:
            return None, {"status": None, "code": None, "message": "this sign-in has no ZDX access (ZDX needs a OneAPI API client)"}
        if _DOT_SEGMENT.search(path):
            # An id of "." or ".." would move the request to another path (CWE-22): refused, never sent.
            return None, {"status": None, "code": None, "message": "an application or probe id is not an id; nothing was sent"}
        if method == "GET":
            import zia_rate
            self.reads += 1
            zia_rate.wait("GET", "", what="ZDX read")
        try:
            made = self.ex.create_request(method, CONFIG + path, body if body is not None else {}, {}, params=params or {})
            req, err = (made[0], made[1]) if isinstance(made, tuple) and len(made) >= 2 else (made, None)
            if err:
                return None, error_parts(err)
            got = self.ex.execute(req)
            resp, err = (got[0], got[1]) if isinstance(got, tuple) and len(got) >= 2 else (got, None)
            if err:
                return None, error_parts(err)
        except Exception as e:  # noqa: BLE001 — one failed request is reported, never raised
            return None, {"status": None, "code": None, "message": f"{type(e).__name__}: {str(e)[:240]}"}
        if resp is None:
            return {}, None
        data = resp.get_body() if hasattr(resp, "get_body") else resp
        if isinstance(data, (bytes, str)):
            try:
                data = json.loads(data) if data else {}
            except ValueError:
                data = {}
        return data, None

    # reads
    def apps(self):
        d, e = self.send("GET", "/applications")
        return _items(d), e

    def supported(self):
        d, e = self.send("GET", "/applications/supported", params={"type": "PREDEFINED"})
        return _items(d), e

    def get_app(self, key: Any):
        d, e = self.send("GET", f"/applications/{_seg(key)}")
        return (d if isinstance(d, dict) else None), e

    def monitors(self):
        d, e = self.send("GET", "/monitors")
        return _items(d), e

    def app_monitors(self, key: Any):
        d, e = self.send("GET", f"/applications/{_seg(key)}/monitors")
        return _items(d), e

    def collections(self):
        d, e = self.send("GET", "/collections")
        return _items(d), e

    # writes: pack_ops only
    def zdx_create_app(self, body: Dict[str, Any]):
        return self.send("POST", "/applications", body)

    def zdx_create_probe(self, key: Any, body: Dict[str, Any]):
        return self.send("POST", f"/applications/{_seg(key)}/monitors", body)

    def zdx_create_collection(self, body: Dict[str, Any]):
        return self.send("POST", "/collections", body)

    def zdx_set_app_state(self, key: Any, action: str):
        return self.send("PUT", f"/applications/{_seg(key)}/{'activate' if action == 'activate' else 'deactivate'}")

    def zdx_set_probe_state(self, key: Any, mid: Any, action: str):
        return self.send("PUT", f"/applications/{_seg(key)}/monitors/{_seg(mid)}/{'activate' if action == 'activate' else 'deactivate'}")

    def zdx_delete_app(self, aid: Any):
        return self.send("DELETE", f"/applications/{_seg(aid)}")

    def zdx_delete_probe(self, key: Any, mid: Any):
        return self.send("DELETE", f"/applications/{_seg(key)}/monitors/{_seg(mid)}")


def api_for(client: Any) -> ZdxApi:
    """One ZdxApi per client (the run and the plan share it)."""
    api = getattr(client, "_zdx_api", None)
    if isinstance(api, ZdxApi):
        return api
    api = ZdxApi(client)
    try:
        setattr(client, "_zdx_api", api)
    except Exception:  # noqa: BLE001 — a client that takes no attributes gets a new one each time
        pass
    return api


# ---------------------------------------------------------------------------
# Normalised objects and the tenant's state
# ---------------------------------------------------------------------------

def _f(obj: Any, *keys: str, default: Any = None) -> Any:
    if not isinstance(obj, dict):
        return default
    for k in keys:
        if obj.get(k) is not None:
            return obj[k]
    return default


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes", "enabled", "active")


def _same(a: Any, b: Any) -> bool:
    return a is not None and b is not None and str(a) == str(b)


def norm_app(a: Dict[str, Any]) -> Dict[str, Any]:
    typ = str(_f(a, "type", default="") or "").upper() or "CUSTOM"
    provider = str(_f(a, "provider", default="") or "").upper() or None
    aid = _f(a, "id")
    col = _f(a, "collection") or {}
    return {"id": aid, "key": provider if typ == "PREDEFINED" and provider else aid, "name": str(_f(a, "name", default="") or ""),
            "type": typ, "provider": provider, "active": _truthy(_f(a, "active", "enabled", default=False)), "host": _f(a, "host"),
            "prefix": _f(a, "prefix"), "collection_id": _f(col, "id") if isinstance(col, dict) else None}


def probe_kind(typ: Any) -> str:
    t = str(typ or "").upper()
    return "web" if t in WEB_TYPES else "cloudpath" if t in PATH_TYPES else "other"


def norm_probe(m: Dict[str, Any]) -> Dict[str, Any]:
    app = _f(m, "application", "app") or {}
    follow = _f(m, "followWebMonitor", "follow_web_monitor") or {}
    freq = _f(m, "frequencyInSeconds", "frequency_in_seconds")
    try:
        freq = int(freq) if freq is not None else None
    except (TypeError, ValueError):
        freq = None
    return {"id": _f(m, "id"), "name": str(_f(m, "name", default="") or ""), "type": str(_f(m, "type", default="") or "").upper(),
            "kind": probe_kind(_f(m, "type")), "active": _truthy(_f(m, "active", "enabled", default=False)),
            "target": str(_f(m, "url", "host", default="") or ""), "frequency": freq, "protocol": _f(m, "protocol"),
            "follows": _f(follow, "id") if isinstance(follow, dict) else None,
            "app_id": _f(app, "id") if isinstance(app, dict) else None,
            "klass": str(_f(m, "class", "monitorClass", default="") or "").upper() or None}


def host_of(url: Any) -> Optional[str]:
    try:
        u = urlsplit(str(url or "").strip())
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    return u.hostname.lower()


def read_state(api: ZdxApi, *, catalogue: bool = True, say: Callable[[str], None] = lambda m: None,
               cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Apps (each with its probes), probes, collections and, with
    `catalogue`, the predefined apps ZDX offers. Never writes. A list that
    could not be read is in `errors` (a plan is then blocked, never guessed)."""
    out: Dict[str, Any] = {"apps": [], "probes": [], "collections": [], "supported": [], "errors": {}, "error_parts": {}}
    reads = [("apps", api.apps, "the configured applications"), ("probes", api.monitors, "the probes"),
             ("collections", api.collections, "the collections")]
    if catalogue:
        reads.append(("supported", api.supported, "the predefined applications ZDX offers"))
    for key, fn, what in reads:
        ao._check_stop(cancel)
        say(f"Reading {what}…")
        rows, err = fn()
        if err:
            out["errors"][key] = describe(err)
            out["error_parts"][key] = err
            say(f"{what[0].upper() + what[1:]} could not be read: {describe(err)}")
            continue
        out[key] = rows
    out["apps"] = [norm_app(a) for a in out["apps"]]
    out["probes"] = [norm_probe(m) for m in out["probes"]]
    by_app: Dict[str, List[Dict[str, Any]]] = {}
    for p in out["probes"]:
        by_app.setdefault(str(p["app_id"]), []).append(p)
    for a in out["apps"]:
        a["probes"] = sorted(by_app.get(str(a["id"]), []), key=lambda p: ({"web": 0, "cloudpath": 1}.get(p["kind"], 2), p["name"].lower()))
    out["collections"] = [{"id": _f(c, "id"), "name": str(_f(c, "name", default="") or "")} for c in out["collections"]]
    out["supported"] = [{"provider": str(_f(s, "provider", default="") or "").upper(), "name": str(_f(s, "name", default="") or ""),
                         "host": str(_f(s, "host", default="") or "")} for s in out["supported"] if _f(s, "provider")]
    ao._check_stop(cancel)
    say(f"ZDX: {len(out['apps'])} application(s), {len(out['probes'])} probe(s).")
    return out


def not_available(state: Dict[str, Any]) -> Optional[str]:
    """Why the ZDX configuration cannot be read at all, in words."""
    err = (state.get("error_parts") or {}).get("apps")
    if not err:
        return None
    return f"The ZDX configuration could not be read ({describe(err)}). {explain(err.get('status'), err.get('code'), err.get('message'))}".strip()


def _catalogue(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for s in state.get("supported") or []:
        prov = s["provider"]
        cfg = next((a for a in state["apps"] if a["type"] == "PREDEFINED" and a["provider"] == prov), None)
        info = PREDEFINED.get(prov, {})
        out.append({"provider": prov, "label": info.get("label") or s["name"] or prov,
                    "about": info.get("about") or (f"{s['name']} ({s['host']})" if s["host"] else s["name"]), "host": s["host"],
                    "needs_prefix": "<prefix>" in s["host"], "known": prov in PREDEFINED, "configured": cfg is not None,
                    "active": bool(cfg and cfg["active"]), "prefix": cfg["prefix"] if cfg else None})
    return sorted(out, key=lambda x: (not x["known"], x["label"].lower()))


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """What the form shows: every app with its probes (and what may be
    deleted), the predefined catalogue with the tenant's state, the
    templates and the choices. Read-only."""
    say("Reading ZDX applications and probes. Nothing is written.")
    state = read_state(api_for(client), say=say, cancel=cancel)
    apps = sorted(state["apps"], key=lambda a: (a["type"] != "PREDEFINED", a["name"].lower()))
    for a in apps:
        a["deletable"] = a["type"] != "PREDEFINED"
        for p in a["probes"]:
            p["deletable"] = a["type"] != "PREDEFINED" or p.get("klass") == "CUSTOM"
    return {"zdx": {"apps": apps, "catalogue": _catalogue(state), "collections": state["collections"],
                    "not_available": not_available(state),
                    "counts": {"apps": len(apps), "apps_on": sum(1 for a in apps if a["active"]), "probes": len(state["probes"]),
                               "probes_on": sum(1 for p in state["probes"] if p["active"])},
                    "templates": [dict(t) for t in TEMPLATES.values()], "intervals": list(INTERVALS_MIN), "protocols": list(PROTOCOLS),
                    "tiers": [dict(tier_template(k), label=t["label"], interval_minutes=t["interval_minutes"], cloudpath=t["cloudpath"])
                              for k, t in TIERS.items()],
                    "default_tier": DEFAULT_TIER,
                    "assumed": ASSUMED_NOTE},
            "errors": {f"zdx_{k}": v for k, v in state["errors"].items()}}


# ---------------------------------------------------------------------------
# Request validation (before any read)
# ---------------------------------------------------------------------------

def _str(v: Any, limit: int = 200) -> str:
    s = str(v if v is not None else "").strip()
    if len(s) > limit:
        raise ao.OperationError(f"A value is longer than {limit} characters.")
    return s


def _id(v: Any) -> str:
    s = _str(v, 80)
    if not _ID_RE.match(s):
        raise ao.OperationError("An application or probe id is missing or is not an id.")
    return s


def _bool(v: Any, default: bool) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    raise ao.OperationError("A yes/no field must be true or false.")


def clean_url(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """(url, None) or (None, why) for a custom app's URL."""
    s = str(raw or "").strip()
    if not s:
        return None, "enter the app's URL, starting with https:// or http://."
    if len(s) > URL_MAX:
        return None, f"the URL is longer than {URL_MAX} characters."
    if any(c.isspace() or ord(c) < 32 for c in s):
        return None, "the URL contains spaces or control characters."
    try:
        u = urlsplit(s)
        port = u.port
    except ValueError:
        return None, "the URL cannot be read; enter it as https://host/path."
    if u.scheme not in ("http", "https"):
        return None, "the URL must start with https:// or http://."
    if u.username or u.password or "@" in u.netloc:
        return None, "the URL must not carry a user name or password."
    host = (u.hostname or "").lower()
    if not host:
        return None, "the URL has no host name."
    try:
        ip = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        ip = None
    if ip is not None:
        why = _unprobeable_ip(ip)
        if why:
            return None, f"{host} is {why}, not the address of an app a device can be probed against. Use the app's host name or address."
    else:
        if not host.isascii():
            try:
                ascii_host = host.encode("idna").decode("ascii")
            except UnicodeError:
                return None, f"'{host}' is not a valid host name."
            # ZDX gets the host in its ASCII (punycode) form, as DNS resolves it.
            s = u._replace(netloc=ascii_host + (f":{port}" if port is not None else "")).geturl()
            host = ascii_host
        labels = host.rstrip(".").split(".")
        if len(host) > 253 or len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
            return None, f"'{host}' is not a valid host name."
        if re.fullmatch(r"\d+|0x[0-9a-f]*", labels[-1]):
            # A last label that is a number makes the whole name an IPv4 address to a browser (0x7f.1 is 127.0.0.1).
            return None, f"'{host}' is not a valid host name (it ends in a number; write an IP address as a.b.c.d)."
        if labels[-1] == "localhost":
            return None, f"{host} is the device itself, not the address of an app a device can be probed against."
    if port is not None and not 0 < port < 65536:
        return None, "the URL's port is out of range."
    return s, None


def _unprobeable_ip(ip: Any) -> str:
    """Why an IP address names no app a probe can measure ("" when it can):
    loopback, link-local (also the cloud metadata address 169.254.169.254),
    unspecified, multicast or reserved. Private (RFC 1918, ULA) addresses
    are allowed: an internal app is a normal ZDX target, and the probe runs
    on the devices, never from this app."""
    ip = getattr(ip, "ipv4_mapped", None) or ip
    if ip.is_loopback:
        return "a loopback address"
    if ip.is_link_local:
        return "a link-local address (such as a cloud metadata address)"
    if ip.is_unspecified:
        return "the unspecified address"
    if ip.is_multicast:
        return "a multicast address"
    if ip.is_reserved:
        return "a reserved address"
    return ""


def _clean_setup(spec: Dict[str, Any]) -> Dict[str, Any]:
    pre, cus = spec.get("predefined") or [], spec.get("custom") or []
    if not isinstance(pre, list) or not isinstance(cus, list):
        raise ao.OperationError("predefined and custom must be lists.")
    if len(pre) > MAX_PREDEFINED or len(cus) > MAX_CUSTOM:
        raise ao.OperationError(f"At most {MAX_PREDEFINED} predefined and {MAX_CUSTOM} custom apps in one setup.")
    if not pre and not cus:
        raise ao.OperationError("Pick at least one predefined app or add a custom app.")
    tier = _str(spec.get("tier"), 20).lower()
    if tier and tier not in TIERS:
        raise ao.OperationError(f"Unknown tier: pick one of {', '.join(t['label'] for t in TIERS.values())}.")
    try:
        interval = int(spec.get("interval_minutes", TIERS[tier]["interval_minutes"] if tier else 5))
    except (TypeError, ValueError):
        raise ao.OperationError("The interval must be a number of minutes.")
    if interval not in INTERVALS_MIN:
        raise ao.OperationError(f"The interval must be one of {', '.join(str(i) for i in INTERVALS_MIN)} minutes.")
    proto = str(spec.get("protocol") or "ADAPTIVE").upper()
    if proto not in PROTOCOLS:
        raise ao.OperationError(f"The CloudPath protocol must be one of {', '.join(PROTOCOL_LABELS.values())}.")
    tid = _str(spec.get("template"), 40)
    if tid and tid not in TEMPLATES:
        raise ao.OperationError("Unknown template.")
    out_pre, seen = [], set()
    for p in pre:
        if not isinstance(p, dict):
            raise ao.OperationError("Each predefined app must be an object.")
        prov = _str(p.get("provider"), 64).upper()
        if not re.fullmatch(r"[A-Z0-9_]{2,64}", prov):
            raise ao.OperationError("A predefined app needs its provider (for example MICROSOFT_LOGIN).")
        if prov in seen:
            continue
        seen.add(prov)
        out_pre.append({"provider": prov, "web": _bool(p.get("web"), True), "cloudpath": _bool(p.get("cloudpath"), True),
                        "prefix": _str(p.get("prefix"), 63).lower()})
    out_cus = []
    for c in cus:
        if not isinstance(c, dict):
            raise ao.OperationError("Each custom app must be an object.")
        out_cus.append({"name": _str(c.get("name"), 200), "url": _str(c.get("url"), URL_MAX + 10), "cloudpath": _bool(c.get("cloudpath"), True)})
    out = {"type": T_SETUP, "template": tid, "predefined": out_pre, "custom": out_cus, "interval_minutes": interval, "protocol": proto}
    if tier:
        out["tier"] = tier
    return out


def _clean_targets(raw: Any, *, with_to: bool, with_name: bool, allow_empty: bool = False) -> List[Dict[str, Any]]:
    if not isinstance(raw, list) or (not raw and not allow_empty):
        raise ao.OperationError("Pick at least one app or probe.")
    if len(raw) > MAX_TARGETS:
        raise ao.OperationError(f"At most {MAX_TARGETS} apps or probes in one change.")
    out, seen = [], set()
    for x in raw:
        if not isinstance(x, dict):
            raise ao.OperationError("Each target must be an object.")
        t = {"app": _id(x.get("app")), "probe": _id(x.get("probe")) if x.get("probe") not in (None, "") else None}
        if with_to:
            to = str(x.get("to") or "").lower()
            if to not in ("on", "off"):
                raise ao.OperationError("Each target says whether to turn it on or off (to: on or off).")
            t["to"] = to
        if with_name:
            t["name"] = _str(x.get("name"), 200)
        k = (t["app"], t["probe"])
        if k in seen:
            continue
        seen.add(k)
        out.append(t)
    return out


# ---------------------------------------------------------------------------
# Probe and app bodies (ASSUMED: the shape the ZDX portal stores)
# ---------------------------------------------------------------------------

def _all_users() -> Dict[str, List[Any]]:
    out: Dict[str, List[Any]] = {}
    for k in ("Users", "Groups", "Locations", "LocationGroups", "Geolocations", "Devices", "Departments", "OsTypes"):
        out[f"on{k}"] = []
        out[f"excluded{k}"] = []
    return out   # empty include and exclude lists: every user


def probe_name(app_name: str, kind: str) -> str:
    suffix = " Web probe" if kind == "web" else " CloudPath probe"
    return str(app_name).strip()[: NAME_MAX - len(suffix)] + suffix


def web_body(app_name: str, url: str, interval_min: int) -> Dict[str, Any]:
    body = {"name": probe_name(app_name, "web"), "type": "WEB", "active": True, "class": "CUSTOM", "timeoutSeconds": 60,
            "expiresAtTimestamp": 0, "frequencyInSeconds": int(interval_min) * 60, "url": url, "requestMethods": ["GET"],
            "requestHeaders": [], "retries": 1, "requestTimeoutSeconds": 60, "followRedirects": True, "maxRedirects": 5,
            "responseCodes": ["200-299", "304"], "responseHeaders": []}
    body.update(_all_users())
    return body


def cloudpath_body(app_name: str, host: str, interval_min: int, protocol: str, follow_web: Any) -> Dict[str, Any]:
    body = {"name": probe_name(app_name, "cloudpath"), "type": "TRACERT", "active": True, "class": "CUSTOM", "timeoutSeconds": 60,
            "expiresAtTimestamp": 0, "frequencyInSeconds": int(interval_min) * 60, "host": host, "protocol": protocol,
            "requestTimeoutSeconds": 60, "maxPacketCount": 5, "packetIntervalMs": 1000, "packetTimeoutMs": 1000, "udpPort": 33434,
            "tcpPort": 443, "reverseLookupEnabled": True, "followWebMonitor": {"id": follow_web}}
    if protocol in ("ADAPTIVE", "TCP"):
        body["tcpType"] = "RESILIENT_TCP"
    body.update(_all_users())
    return body


def _collection(cols: Sequence[Dict[str, Any]], kind: str) -> Optional[Dict[str, Any]]:
    want = (CUSTOM_COLLECTION if kind == "custom" else PREDEFINED_COLLECTION)["name"].lower()
    return (next((c for c in cols if c["name"].lower() == want), None) or next((c for c in cols if kind in c["name"].lower()), None))


# ---------------------------------------------------------------------------
# Plans (read only)
# ---------------------------------------------------------------------------

class _Plan:
    """Items (admin_ops._unit) and groups in the order they are written."""

    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []
        self.notes: List[str] = []
        self.n = 0

    def group(self, handler: str, target: Dict[str, Any]) -> str:
        key = f"g{len(self.groups) + 1}"
        self.groups.append({"key": key, "handler": handler, "target": target})
        return key

    def item(self, group: Optional[str], kind: str, obj: Dict[str, Any], field: str, before: Any, after: Any, *, status: str = "change",
             reason: str = "", depends_on: Sequence[str] = (), value: Any = None) -> str:
        self.n += 1
        key = f"z{self.n}"
        self.items.append(ao._unit(key, group or "", kind, obj, field, before, after, value=value, status=status, reason=reason,
                                   depends_on=depends_on))
        return key


def _obj(name: str, label_kind: str, **kw: Any) -> Dict[str, Any]:
    return dict({"name": name, "type": "zdx", "policy_label": LABELS[label_kind]}, **kw)


def _state_word(on: bool) -> str:
    return "on" if on else "off"


def _read_or_block(client: Any, P: _Plan, say, cancel, *, catalogue: bool) -> Dict[str, Any]:
    state = read_state(api_for(client), catalogue=catalogue, say=say, cancel=cancel)
    na = not_available(state)
    if na:
        P.blockers.append(na)
    for k in ("probes", "collections") + (("supported",) if catalogue else ()):
        if k in state["errors"] and not na:
            P.blockers.append(f"The ZDX {k} could not be read ({state['errors'][k]}), so the plan cannot tell what exists.")
    c = {"apps": len(state["apps"]), "on": sum(1 for a in state["apps"] if a["active"]), "probes": len(state["probes"]),
         "probes_on": sum(1 for p in state["probes"] if p["active"])}
    if not na:
        P.notes.append(f"In the tenant now: {c['apps']} ZDX app(s), {c['on']} on; {c['probes']} probe(s), {c['probes_on']} on.")
    return state


def _finish(t: str, title: str, spec: Dict[str, Any], P: _Plan) -> Dict[str, Any]:
    return {"type": t, "product": "zdx", "title": title, "spec": spec, "items": P.items, "groups": P.groups,
            "warnings": P.warnings, "blockers": P.blockers, "notes": P.notes + [ALL_USERS_NOTE, ASSUMED_NOTE] if t == T_SETUP
            else P.notes + [ASSUMED_NOTE]}


def plan_setup(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    spec = _clean_setup(spec)
    P = _Plan()
    state = _read_or_block(client, P, say, cancel, catalogue=bool(spec["predefined"]))
    interval, proto = spec["interval_minutes"], spec["protocol"]
    _tier_notes(P, spec)
    supported = {s["provider"]: s for s in state["supported"]}
    cols = {"custom": _collection(state["collections"], "custom"), "predefined": _collection(state["collections"], "predefined")}
    col_items: Dict[str, str] = {}

    def need_collection(kind: str) -> Tuple[Dict[str, Any], List[str]]:
        """The collection an app goes into, or the step that creates it first."""
        if cols[kind] is not None:
            return {"id": cols[kind]["id"], "name": cols[kind]["name"]}, []
        d = CUSTOM_COLLECTION if kind == "custom" else PREDEFINED_COLLECTION
        if kind not in col_items:
            g = P.group("zdx_collection", {"kind": kind, "body": {"name": d["name"], "type": "END_USER", "active": True,
                                                                   "description": d["description"], "tags": [], "filters": {}}})
            col_items[kind] = P.item(g, "zdx_collection", _obj(d["name"], "collection"), "exists", False, True,
                                     reason="this tenant has none yet (a new ZDX tenant): created first")
        return {"id": f"$collection:{kind}", "name": d["name"]}, [col_items[kind]]

    for p in spec["predefined"]:
        prov = p["provider"]
        sup = supported.get(prov)
        label = PREDEFINED.get(prov, {}).get("label") or (sup or {}).get("name") or prov
        if sup is None:
            if "supported" not in state["errors"] and not P.blockers:
                P.item(None, "zdx_app", _obj(label, "predefined"), "exists", None, True, status="excluded",
                       reason="ZDX does not offer this predefined app to this tenant")
            continue
        want_web = p["web"]
        want_path = p["cloudpath"] and want_web
        if p["cloudpath"] and not want_web:
            P.warnings.append(f"{label}: a CloudPath probe follows the Web probe, so it is turned on only with the Web probe.")
        needs_prefix = "<prefix>" in sup["host"]
        existing = next((a for a in state["apps"] if a["type"] == "PREDEFINED" and a["provider"] == prov), None)
        if existing is None:
            prefix = p["prefix"] if needs_prefix else ""
            if needs_prefix and not prefix:
                P.item(None, "zdx_app", _obj(label, "predefined"), "exists", False, True, status="excluded",
                       reason=f"left out: enter the customer's prefix (the part before {sup['host'].replace('<prefix>', '')})")
                continue
            if needs_prefix and not PREFIX_RE.match(prefix):
                P.blockers.append(f"{label}: '{prefix}' is not a tenant prefix (letters, digits and hyphens, as in a host name).")
                continue
            host = sup["host"].replace("<prefix>", prefix) if needs_prefix else sup["host"]
            col, deps = need_collection("predefined")
            body = {"type": "PREDEFINED", "provider": prov, "name": label, "active": False, "collection": col}
            if prefix:
                body["prefix"] = prefix
            g = P.group("zdx_predefined_app", {"provider": prov, "name": label, "host": host, "body": body, "web": want_web, "cloudpath": want_path})
            obj = _obj(label, "predefined", app=prov, host=host)
            k = P.item(g, "zdx_app", obj, "exists", False, True, depends_on=deps, reason=f"set up for {host}; ZDX adds its own Web and CloudPath probes")
            if want_web:
                P.item(g, "zdx_probe_state", _obj(f"{label} Web probe (ZDX creates it)", "web", app=prov, probe="$web"), "state", "off", "on", depends_on=[k])
            if want_path:
                P.item(g, "zdx_probe_state", _obj(f"{label} CloudPath probe (ZDX creates it)", "cloudpath", app=prov, probe="$cloudpath"),
                       "state", "off", "on", depends_on=[k])
            P.item(g, "zdx_app_state", obj, "state", "off", "on", depends_on=[k])
            continue
        if needs_prefix and p["prefix"] and existing.get("prefix") and p["prefix"] != str(existing["prefix"]).lower():
            P.warnings.append(f"{label} is already set up with the prefix '{existing['prefix']}'; it is kept (the prefix entered is not used).")
        obj = _obj(label, "predefined", app=existing["key"], id=existing["id"])
        P.item(None, "zdx_app", obj, "exists", True, True, status="noop", reason="already set up")
        _turn_on_existing(P, existing, label, want_web, want_path)

    seen: set = set()
    for c in spec["custom"]:
        name = c["name"]
        if not NAME_RE.match(name):
            P.blockers.append(f"Custom app '{name or '(no name)'}': use 1 to {NAME_MAX} letters, digits, spaces or - _ . ( ) : / & +.")
            continue
        if name.lower() in seen:
            P.blockers.append(f"Custom app '{name}' is listed twice.")
            continue
        seen.add(name.lower())
        url, why = clean_url(c["url"])
        if why:
            P.blockers.append(f"Custom app '{name}': {why}")
            continue
        host = host_of(url)
        clash = next((a for a in state["apps"] if a["name"].lower() == name.lower()), None)
        if clash is not None and clash["type"] == "PREDEFINED":
            P.blockers.append(f"Custom app '{name}': a predefined app has this name. Choose another name.")
            continue
        others = [p for p in state["probes"] if p["kind"] == "web" and host_of(p["target"]) == host
                  and not (clash is not None and _same(p["app_id"], clash["id"]))]
        if others:
            P.warnings.append(f"{host} is already probed by '{others[0]['name']}' in another app; this app probes it too.")
        if clash is not None:
            _complete_existing_custom(P, clash, name, url, host, c["cloudpath"], interval, proto)
            continue
        col, deps = need_collection("custom")
        target = {"name": name, "url": url, "host": host, "cloudpath": c["cloudpath"],
                  "app_body": {"type": "CUSTOM", "name": name, "description": f"ZDX probe setup by {ASSESSOR_PLACEHOLDER}", "active": False,
                               "collection": col},
                  "web_body": web_body(name, url, interval),
                  "cloudpath_body": cloudpath_body(name, host, interval, proto, "$web") if c["cloudpath"] else None}
        g = P.group("zdx_custom_app", target)
        obj = _obj(name, "custom", url=url)
        k = P.item(g, "zdx_app", obj, "exists", False, True, depends_on=deps, reason="created off; turned on after its probes")
        P.item(g, "zdx_probe", _obj(target["web_body"]["name"], "web", target=url), "exists", False, True, depends_on=[k],
               reason=f"{url}, every {interval} minutes, all users")
        if c["cloudpath"]:
            P.item(g, "zdx_probe", _obj(target["cloudpath_body"]["name"], "cloudpath", target=host), "exists", False, True, depends_on=[k],
                   reason=f"to {host}, {PROTOCOL_LABELS[proto]}, following the Web probe")
        P.item(g, "zdx_app_state", obj, "state", "off", "on", depends_on=[k])
    what = TEMPLATES[spec['template']]['name'] if spec['template'] else 'custom'
    if spec.get("tier"):
        what = f"{TIERS[spec['tier']]['label']} tier, {what}"
    title = f"ZDX probe setup ({what})"
    return _finish(T_SETUP, title, spec, P)


def _tier_notes(P: _Plan, spec: Dict[str, Any]) -> None:
    """What the tier asks for, and each choice looser than it (a warning, never a block)."""
    tier = spec.get("tier")
    if not tier:
        return
    t = TIERS[tier]
    P.notes.append(f"Tier: {t['label']}. {t['what']}")
    if spec["interval_minutes"] > t["interval_minutes"]:
        P.warnings.append(f"Weaker than the {t['label']} tier: the custom apps' probes run every {spec['interval_minutes']} minutes; "
                          f"the tier runs them every {t['interval_minutes']} minutes.")
    if t["cloudpath"]:
        off = [PREDEFINED.get(p["provider"], {}).get("label") or p["provider"] for p in spec["predefined"] if not p["cloudpath"]]
        off += [c["name"] or c["url"] for c in spec["custom"] if not c["cloudpath"]]
        if off:
            P.warnings.append(f"Weaker than the {t['label']} tier: no CloudPath probe for {', '.join(off[:6])}"
                              f"{' and more' if len(off) > 6 else ''}; the tier traces the network path to every app.")
    missing = [PREDEFINED.get(p, {}).get("label") or p for p in t["predefined"] if p not in {x["provider"] for x in spec["predefined"]}]
    if missing:
        P.notes.append(f"The {t['label']} tier also monitors: {', '.join(missing)} (not picked in this setup).")


def _turn_on_existing(P: _Plan, app: Dict[str, Any], label: str, want_web: bool, want_path: bool) -> None:
    web = next((x for x in app["probes"] if x["kind"] == "web"), None)
    path = next((x for x in app["probes"] if x["kind"] == "cloudpath"), None)
    for want, p, kind in ((want_web, web, "web"), (want_path, path, "cloudpath")):
        if not want:
            continue
        if p is None:
            P.warnings.append(f"{label} has no {'Web' if kind == 'web' else 'CloudPath'} probe in this tenant; ZDX normally creates it "
                              "with the app. Check it in the ZDX portal.")
            continue
        obj = _obj(p["name"], kind, app=app["key"], probe=p["id"])
        if p["active"]:
            P.item(None, "zdx_probe_state", obj, "state", "on", "on", status="noop", reason="already on")
        else:
            g = P.group("zdx_state", {"app": app["key"], "probe": p["id"], "name": p["name"], "app_name": app["name"], "to": "on", "kind": kind})
            P.item(g, "zdx_probe_state", obj, "state", "off", "on")
    obj = _obj(app["name"], "predefined" if app["type"] == "PREDEFINED" else "custom", app=app["key"], id=app["id"])
    if app["active"]:
        P.item(None, "zdx_app_state", obj, "state", "on", "on", status="noop", reason="already on")
    else:
        g = P.group("zdx_state", {"app": app["key"], "probe": None, "name": app["name"], "app_name": app["name"], "to": "on", "kind": "app"})
        P.item(g, "zdx_app_state", obj, "state", "off", "on")


def _complete_existing_custom(P: _Plan, app: Dict[str, Any], name: str, url: str, host: str, want_path: bool, interval: int, proto: str) -> None:
    web = next((x for x in app["probes"] if x["kind"] == "web"), None)
    path = next((x for x in app["probes"] if x["kind"] == "cloudpath"), None)
    if web is not None and host_of(web["target"]) != host:
        P.blockers.append(f"Custom app '{name}' already exists and probes {web['target'] or 'another URL'}, not {url}. Choose another name, "
                          "or change that app in the ZDX portal.")
        return
    P.item(None, "zdx_app", _obj(name, "custom", app=app["key"], id=app["id"]), "exists", True, True, status="noop",
           reason=f"already exists (id {app['id']}): only what it lacks is added")
    web_key = None
    if web is None:
        g = P.group("zdx_add_probe", {"app": app["key"], "app_name": name, "kind": "web", "body": web_body(name, url, interval)})
        web_key = P.item(g, "zdx_probe", _obj(probe_name(name, "web"), "web", target=url), "exists", False, True, reason="it has no Web probe")
    if want_path and path is None:
        follow = web["id"] if web is not None else "$web"
        g = P.group("zdx_add_probe", {"app": app["key"], "app_name": name, "kind": "cloudpath",
                                      "body": cloudpath_body(name, host, interval, proto, follow)})
        P.item(g, "zdx_probe", _obj(probe_name(name, "cloudpath"), "cloudpath", target=host), "exists", False, True,
               depends_on=[web_key] if web_key else (), reason="it has no CloudPath probe")
    _turn_on_existing(P, app, name, web is not None, want_path and path is not None)


def _find_app(state: Dict[str, Any], key: Any) -> Optional[Dict[str, Any]]:
    k = str(key)
    return next((a for a in state["apps"] if str(a["key"]) == k or str(a["id"]) == k or (a["provider"] and a["provider"] == k.upper())), None)


def plan_state(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    targets = _clean_targets(spec.get("targets"), with_to=True, with_name=False)
    spec = {"type": T_STATE, "targets": targets}
    P = _Plan()
    state = _read_or_block(client, P, say, cancel, catalogue=False)
    rows = []
    for t in targets:
        app = _find_app(state, t["app"])
        if app is None:
            P.item(None, "zdx_app_state", _obj(t["app"], "custom", app=t["app"]), "state", None, t["to"], status="excluded",
                   reason="not in the tenant (deleted meanwhile?)")
            continue
        if t["probe"] is None:
            rows.append((t, app, None))
            continue
        p = next((x for x in app["probes"] if str(x["id"]) == t["probe"]), None)
        if p is None:
            P.item(None, "zdx_probe_state", _obj(t["probe"], "other", app=app["key"]), "state", None, t["to"], status="excluded",
                   reason=f"this probe is no longer in '{app['name']}'")
            continue
        rows.append((t, app, p))
    # Turning off: CloudPath probes, then Web probes, then apps. Turning on: apps, Web probes, CloudPath probes.
    rank_off = {"cloudpath": 0, "web": 1, "other": 1, "app": 2}
    rank_on = {"app": 0, "web": 1, "other": 1, "cloudpath": 2}
    kind_of = lambda r: r[2]["kind"] if r[2] else "app"  # noqa: E731
    ordered = sorted([r for r in rows if r[0]["to"] == "off"], key=lambda r: rank_off[kind_of(r)]) + \
        sorted([r for r in rows if r[0]["to"] == "on"], key=lambda r: rank_on[kind_of(r)])
    picked = {(str(r[1]["key"]), str(r[2]["id"]) if r[2] else None): r[0]["to"] for r in rows}
    for t, app, p in ordered:
        on_now = (p or app)["active"]
        kind = kind_of((t, app, p))
        label_kind = kind if p else ("predefined" if app["type"] == "PREDEFINED" else "custom")
        obj = _obj(p["name"] if p else app["name"], label_kind, app=app["key"], probe=p["id"] if p else None, app_name=app["name"])
        field = "state"
        if on_now == (t["to"] == "on"):
            P.item(None, "zdx_probe_state" if p else "zdx_app_state", obj, field, _state_word(on_now), t["to"], status="noop", reason=f"already {t['to']}")
            continue
        g = P.group("zdx_state", {"app": app["key"], "probe": p["id"] if p else None, "name": obj["name"], "app_name": app["name"],
                                  "to": t["to"], "kind": kind})
        P.item(g, "zdx_probe_state" if p else "zdx_app_state", obj, field, _state_word(on_now), t["to"])
        if p and p["kind"] == "cloudpath" and t["to"] == "on":
            web = next((x for x in app["probes"] if _same(x["id"], p["follows"])), None)
            if web is not None and not web["active"] and picked.get((str(app["key"]), str(web["id"]))) != "on":
                P.warnings.append(f"'{p['name']}' follows the Web probe '{web['name']}', which stays off: turn both on.")
        if p and p["kind"] == "web" and t["to"] == "off":
            for x in app["probes"]:
                if x["kind"] == "cloudpath" and _same(x["follows"], p["id"]) and x["active"] and picked.get((str(app["key"]), str(x["id"]))) != "off":
                    P.warnings.append(f"'{x['name']}' follows '{p['name']}' and stays on: ZDX may refuse to turn the Web probe off first. Turn both off.")
    on = sum(1 for r in rows if r[0]["to"] == "on")
    title = "Turn ZDX apps and probes " + ("on" if on == len(rows) else "off" if on == 0 else "on or off")
    return _finish(T_STATE, title, spec, P)


def plan_delete(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    targets = _clean_targets(spec.get("targets") or [], with_to=False, with_name=True, allow_empty=bool(spec.get("turn_off")))
    turn_off = _clean_targets(spec.get("turn_off") or [], with_to=False, with_name=True, allow_empty=True)
    spec = {"type": T_DELETE, "targets": targets, "turn_off": turn_off}
    P = _Plan()
    state = _read_or_block(client, P, say, cancel, catalogue=False)
    for t in turn_off:   # an undo of a setup: what it turned on goes off first (probes, then apps)
        app = _find_app(state, t["app"])
        p = next((x for x in (app or {}).get("probes", []) if str(x["id"]) == str(t["probe"])), None) if t["probe"] else None
        if app is None or (t["probe"] and p is None):
            P.item(None, "zdx_app_state", _obj(t["name"] or t["app"], "other"), "state", None, "off", status="noop", reason="already gone")
            continue
        o = p or app
        obj = _obj(o["name"], p["kind"] if p else ("predefined" if app["type"] == "PREDEFINED" else "custom"), app=app["key"],
                   probe=p["id"] if p else None, app_name=app["name"])
        if not o["active"]:
            P.item(None, "zdx_probe_state" if p else "zdx_app_state", obj, "state", "off", "off", status="noop", reason="already off")
            continue
        g = P.group("zdx_state", {"app": app["key"], "probe": p["id"] if p else None, "name": o["name"], "app_name": app["name"], "to": "off",
                                  "kind": p["kind"] if p else "app"})
        P.item(g, "zdx_probe_state" if p else "zdx_app_state", obj, "state", "on", "off")
    for t in targets:
        app = _find_app(state, t["app"])
        if app is None:
            P.item(None, "zdx_app", _obj(t["name"] or t["app"], "custom"), "exists", None, False, status="noop", reason="already gone")
            continue
        if t["probe"] is None:
            obj = _obj(app["name"], "predefined" if app["type"] == "PREDEFINED" else "custom", app=app["id"])
            if app["type"] == "PREDEFINED":
                P.item(None, "zdx_app", obj, "exists", True, False, status="excluded",
                       reason="a Zscaler predefined app cannot be deleted; turn it off instead")
                continue
            if t["name"] != app["name"]:
                P.item(None, "zdx_app", obj, "exists", True, False, status="excluded",
                       reason=f"the name typed ('{t['name']}') is not the app's exact name ('{app['name']}')")
                continue
            probes = sorted(app["probes"], key=lambda p: 0 if p["kind"] == "cloudpath" else 1)
            g = P.group("zdx_delete_app", {"app": app["id"], "name": app["name"],
                                           "probes": [{"id": p["id"], "name": p["name"], "kind": p["kind"]} for p in probes]})
            for p in probes:
                P.item(g, "zdx_probe", _obj(p["name"], p["kind"], app=app["id"], probe=p["id"], app_name=app["name"]), "exists", True, False,
                       reason="an app's probes are deleted first (CloudPath before Web)")
            P.item(g, "zdx_app", obj, "exists", True, False, reason="this cannot be undone: the app's history in ZDX goes with it")
            continue
        p = next((x for x in app["probes"] if str(x["id"]) == t["probe"]), None)
        if p is None:
            P.item(None, "zdx_probe", _obj(t["name"] or t["probe"], "other"), "exists", None, False, status="noop", reason="already gone")
            continue
        obj = _obj(p["name"], p["kind"], app=app["key"], probe=p["id"], app_name=app["name"])
        if app["type"] == "PREDEFINED" and p.get("klass") != "CUSTOM":
            P.item(None, "zdx_probe", obj, "exists", True, False, status="excluded",
                   reason="one of Zscaler's own probes of a predefined app: it cannot be deleted; turn it off instead")
            continue
        if t["name"] != p["name"]:
            P.item(None, "zdx_probe", obj, "exists", True, False, status="excluded",
                   reason=f"the name typed ('{t['name']}') is not the probe's exact name ('{p['name']}')")
            continue
        followers = [x for x in app["probes"] if x["kind"] == "cloudpath" and _same(x["follows"], p["id"])
                     and not any(str(o["probe"]) == str(x["id"]) for o in targets)]
        if followers:
            P.item(None, "zdx_probe", obj, "exists", True, False, status="excluded",
                   reason=f"the CloudPath probe '{followers[0]['name']}' follows it: delete the CloudPath probe first (or both together)")
            continue
        g = P.group("zdx_delete_probe", {"app": app["key"], "app_name": app["name"], "probe": p["id"], "name": p["name"], "kind": p["kind"]})
        P.item(g, "zdx_probe", obj, "exists", True, False, reason="this cannot be undone: the probe's history in ZDX goes with it")
    # Probes before apps, CloudPath probes before Web probes.
    rank = {"zdx_state": 0, "zdx_delete_probe": 1, "zdx_delete_app": 2}
    P.groups.sort(key=lambda g: (rank.get(g["handler"], 3), 0 if g["target"].get("kind") == "cloudpath" else 1))
    pos = {g["key"]: i for i, g in enumerate(P.groups)}
    P.items.sort(key=lambda u: pos.get(u["group"], len(pos)))   # the items read in the order they are written
    return _finish(T_DELETE, "Undo a ZDX probe setup" if turn_off else "Delete ZDX apps and probes", spec, P)


# ---------------------------------------------------------------------------
# Handlers (write through pack_ops; re-read right before each write)
# ---------------------------------------------------------------------------

def _ctx(run: Any) -> Dict[str, Any]:
    c = getattr(run, "_zdx", None)
    if c is None:
        c = {"collections": {}, "units": {}, "turned_on": []}
        run._zdx = c
    return c


def _ok(run: Any, units: List[Dict[str, Any]], out: Any, verb: str) -> bool:
    """Mark the units from one pack_ops Outcome, with ZDX's words on a refusal."""
    if out.ok or out.code == ops.STOPPED:
        return run.outcome(units, out, verb)
    parts = {"status": out.http_status, "code": out.code, "message": out.error or "Unknown error"}
    run.mark(units, "failed", "", error=describe(parts)[:300], explanation=explain(out.http_status, out.code, out.error) or None,
             http_status=out.http_status)
    run.counts["failed"] += 1
    run.log(f"ZDX refused it: {describe(parts)}" + (f" — {explain(out.http_status, out.code, out.error)}" if explain(out.http_status, out.code, out.error) else ""))
    return False


def _conflict(run: Any, units: List[Dict[str, Any]], why: str) -> None:
    run.mark(units, "conflict", why)
    run.counts["skipped"] += len(units)
    run.log(f"Not sent: {why}.")


def _fill(run: Any, body: Any, unit_ctx: Dict[str, Any]) -> Any:
    """The body with what only the run knows: new ids and the assessor."""
    if isinstance(body, dict):
        out = {}
        for k, v in body.items():
            if k == "collection" and isinstance(v, dict) and str(v.get("id", "")).startswith("$collection:"):
                col = _ctx(run)["collections"].get(str(v["id"]).split(":", 1)[1]) or {}
                out[k] = {"id": col.get("id"), "name": col.get("name") or v.get("name")}
            elif k == "followWebMonitor" and isinstance(v, dict):
                fid = unit_ctx.get("web") if v.get("id") == "$web" else v.get("id")
                try:
                    out[k] = {"id": int(fid)}
                except (TypeError, ValueError):
                    out[k] = {"id": fid}
            elif k == "description" and isinstance(v, str):
                out[k] = v.replace(ASSESSOR_PLACEHOLDER, run.assessor or "the assessor")
            else:
                out[k] = _fill(run, v, unit_ctx)
        return out
    if isinstance(body, list):
        return [_fill(run, x, unit_ctx) for x in body]
    return body


def _h_collection(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    api, t = api_for(run.client), g["target"]
    cols, err = api.collections()
    if err:
        return _conflict(run, units, f"the collections could not be re-read ({describe(err)})")
    hit = next((c for c in cols if str(_f(c, "name", default="")).lower() == t["body"]["name"].lower()), None)
    if hit is not None:
        _ctx(run)["collections"][t["kind"]] = {"id": _f(hit, "id"), "name": _f(hit, "name")}
        run.mark(units, "noop", "created by someone else since the preview: used as it is")
        return
    out = ops.create(api, "zdx_collection", dict(t["body"]), name=t["body"]["name"], log=run.log)
    if _ok(run, units, out, "create"):
        _ctx(run)["collections"][t["kind"]] = {"id": out.id, "name": t["body"]["name"]}
        run.created.append({"type": "zdx_collection", "id": out.id, "name": t["body"]["name"]})


def _app_exists(api: ZdxApi, *, name: str = "", provider: str = "") -> Tuple[Optional[bool], Optional[str]]:
    apps, err = api.apps()
    if err:
        return None, describe(err)
    for a in (norm_app(x) for x in apps):
        if (name and a["name"].lower() == name.lower()) or (provider and a["type"] == "PREDEFINED" and a["provider"] == provider):
            return True, None
    return False, None


def _rollback(run: Any, app_id: Any, name: str, made: List[Tuple[str, Any, str]], sent: Sequence[Tuple[str, str]] = ()) -> Dict[str, Any]:
    """Remove what this run created for a custom app whose setup failed
    half way: the CloudPath probe, the Web probe, then the app. `sent` are
    the (kind, name) of probes ZDX accepted without answering an id: they
    are looked up on the app by name, so they are removed too."""
    api = api_for(run.client)
    res = {"app": name, "removed": [], "left": []}
    if ops.stop_reason():
        # The run stopped (a refusal no later write gets past): nothing more is sent, so the app is reported, not removed.
        res["left"].append(f"'{name}' (id {app_id}) was not removed: {ops.stop_reason()}")
        run.log(f"NOT removed: {res['left'][0]}. Undo, or the ZDX portal, removes it.")
        return res
    made = [m for m in made if m[1] is not None]
    if sent:
        mons, _err = api.app_monitors(app_id)
        known = {str(m[1]) for m in made}
        for m in (norm_probe(x) for x in mons or []):
            if m["id"] is not None and str(m["id"]) not in known and (m["kind"], m["name"]) in set(sent):
                made.append((m["kind"], m["id"], m["name"]))
    for kind, pid, pname in sorted(made, key=lambda m: 0 if m[0] == "cloudpath" else 1):
        o = ops.delete(api, {"kind": "zdx_probe", "id": pid, "parent_id": app_id, "name": pname}, log=run.log)
        (res["removed"] if o.ok else res["left"]).append(pname if o.ok else f"{pname} (id {pid}): {o.error}")
    o = ops.delete(api, {"kind": "zdx_app", "id": app_id, "name": name}, log=run.log)
    (res["removed"] if o.ok else res["left"]).append(f"the app '{name}'" if o.ok else f"the app '{name}' (id {app_id}): {o.error}")
    run.log(f"Removed what was created for '{name}': {', '.join(res['removed']) or 'nothing'}"
            + (f"; NOT removed: {'; '.join(res['left'])}" if res["left"] else "") + ".")
    return res


def _h_custom_app(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Create the app off, its Web probe, its CloudPath probe, then turn
    it on; on any refusal remove what was created (probes first)."""
    api, t = api_for(run.client), g["target"]
    app_u = next(u for u in units if u["kind"] == "zdx_app")
    web_u = next((u for u in units if u["kind"] == "zdx_probe" and u["object"]["policy_label"] == LABELS["web"]), None)
    path_u = next((u for u in units if u["kind"] == "zdx_probe" and u["object"]["policy_label"] == LABELS["cloudpath"]), None)
    on_u = next((u for u in units if u["kind"] == "zdx_app_state"), None)
    exists, err = _app_exists(api, name=t["name"])
    if exists is None or exists:
        return _conflict(run, units, f"the applications could not be re-read ({err})" if exists is None
                         else f"an app named '{t['name']}' was created since the preview; preview again")
    uc: Dict[str, Any] = {}
    body = _fill(run, t["app_body"], uc)
    if body["collection"].get("id") is None:
        return _conflict(run, units, "the collection this app belongs in was not created")
    out = ops.create(api, "zdx_app", body, name=t["name"], log=run.log)
    if not out.ok or out.id is None:
        if out.ok:
            out = ops.Outcome(False, error="ZDX accepted the app but returned no id")
        _ok(run, [app_u], out, "create")
        run.mark([u for u in units if u is not app_u], "skipped", "not attempted: the app was not created")
        return
    run.outcome([app_u], out, "create")
    app_id = out.id
    app_u["object"]["id"] = app_id
    made: List[Tuple[str, Any, str]] = []
    rest = [u for u in (web_u, path_u, on_u) if u is not None]

    sent: List[Tuple[str, str]] = []

    def give_up(failed: Dict[str, Any], o: Any, verb: str) -> None:
        _ok(run, [failed], o, verb)
        run.mark([u for u in rest if u["status"] == "change"], "skipped", "not attempted: an earlier step for this app failed")
        rb = _rollback(run, app_id, t["name"], made, sent)
        if not rb["left"]:
            for u in units:
                if u["status"] == "applied":
                    u.update(status="rolled_back", reason="removed again because a later step failed")
        else:
            run.created.append({"type": "zdx_custom_app", "id": app_id, "key": app_id, "name": t["name"], "left_behind": True})

    if web_u is not None:
        wb = _fill(run, t["web_body"], uc)
        o = ops.create(api, "zdx_probe", wb, parent_id=app_id, name=wb["name"], log=run.log)
        if not o.ok or o.id is None:
            if o.ok:
                sent.append(("web", wb["name"]))
            return give_up(web_u, o if not o.ok else ops.Outcome(False, error="ZDX accepted the Web probe but returned no id"), "create")
        uc["web"] = o.id
        made.append(("web", o.id, wb["name"]))
        web_u["object"]["probe"] = o.id
        run.outcome([web_u], o, "create")
    if path_u is not None and t.get("cloudpath_body"):
        pb = _fill(run, t["cloudpath_body"], uc)
        o = ops.create(api, "zdx_probe", pb, parent_id=app_id, name=pb["name"], log=run.log)
        if not o.ok or o.id is None:
            if o.ok:
                sent.append(("cloudpath", pb["name"]))
            return give_up(path_u, o if not o.ok else ops.Outcome(False, error="ZDX accepted the CloudPath probe but returned no id"), "create")
        made.append(("cloudpath", o.id, pb["name"]))
        path_u["object"]["probe"] = o.id
        run.outcome([path_u], o, "create")
    if on_u is not None:
        o = ops.update(api, "zdx_app", app_id, {}, name=t["name"], log=run.log, action="activate")
        if not o.ok:
            return give_up(on_u, o, "update")
        run.outcome([on_u], o, "update")
    run.created.append({"type": "zdx_custom_app", "id": app_id, "key": app_id, "name": t["name"], "web": uc.get("web"),
                        "probes": [m[1] for m in made]})


def _h_predefined_app(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Set up a predefined app (off), find the probes ZDX made for it,
    turn them on, then the app. ZDX keeps a predefined app once set up (it
    cannot be deleted): when a later step fails, the app is left off."""
    api, t = api_for(run.client), g["target"]
    app_u = next(u for u in units if u["kind"] == "zdx_app")
    exists, err = _app_exists(api, provider=t["provider"])
    if exists is None or exists:
        return _conflict(run, units, f"the applications could not be re-read ({err})" if exists is None
                         else f"{t['name']} was set up since the preview; preview again")
    body = _fill(run, t["body"], {})
    if body["collection"].get("id") is None:
        return _conflict(run, units, "the collection this app belongs in was not created")
    out = ops.create(api, "zdx_app", body, name=t["name"], log=run.log)
    if not _ok(run, [app_u], out, "create"):
        run.mark([u for u in units if u is not app_u], "skipped", "not attempted: the app was not set up")
        return
    run.created.append({"type": "zdx_predefined_app", "id": out.id, "key": t["provider"], "name": t["name"]})
    mons, err = api.app_monitors(t["provider"])
    found = {}
    for m in (norm_probe(x) for x in (mons or [])):
        if m["kind"] in ("web", "cloudpath") and m["kind"] not in found:
            found[m["kind"]] = m
    rest = [u for u in units if u is not app_u]
    for u in rest:
        if u["status"] != "change":
            continue
        if u["kind"] == "zdx_probe_state":
            kind = "web" if u["object"]["probe"] == "$web" else "cloudpath"
            m = found.get(kind)
            if m is None:
                why = f"ZDX did not create a {'Web' if kind == 'web' else 'CloudPath'} probe with {t['name']}" + (f" ({describe(err)})" if err else "")
                run.mark([u], "failed", "", error=why, explanation="Turn the probe on in the ZDX portal, or preview again to see it.")
                run.counts["failed"] += 1
                continue
            u["object"].update(probe=m["id"], name=m["name"])
            o = ops.update(api, "zdx_probe", m["id"], {}, parent_id=t["provider"], name=m["name"], log=run.log, action="activate")
            if _ok(run, [u], o, "update"):
                _ctx(run)["turned_on"].append({"app": t["provider"], "probe": m["id"], "name": m["name"]})
        else:
            o = ops.update(api, "zdx_app", t["provider"], {}, name=t["name"], log=run.log, action="activate")
            _ok(run, [u], o, "update")
    if any(u["status"] == "failed" for u in units):
        run.log(f"{t['name']} stays set up (ZDX keeps a predefined app once it is set up); what failed is listed.")


def _h_add_probe(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Add a missing probe to an app that already exists (re-read first)."""
    api, t = api_for(run.client), g["target"]
    mons, err = api.app_monitors(t["app"])
    if err:
        return _conflict(run, units, f"the app's probes could not be re-read ({describe(err)})")
    if any(probe_kind(_f(m, "type")) == t["kind"] for m in mons):
        return _conflict(run, units, f"'{t['app_name']}' got a {'Web' if t['kind'] == 'web' else 'CloudPath'} probe since the preview; preview again")
    uc = _ctx(run)["units"].setdefault(str(t["app"]), {})
    body = _fill(run, t["body"], uc)
    if t["kind"] == "cloudpath" and (body.get("followWebMonitor") or {}).get("id") is None:
        return _conflict(run, units, "the Web probe this CloudPath probe follows was not created")
    out = ops.create(api, "zdx_probe", body, parent_id=t["app"], name=body["name"], log=run.log)
    if _ok(run, units, out, "create"):
        if t["kind"] == "web":
            uc["web"] = out.id
        for u in units:
            u["object"]["probe"] = out.id
        run.created.append({"type": f"zdx_{t['kind']}_probe", "id": out.id, "app": t["app"], "app_name": t["app_name"], "name": body["name"]})


def _h_state(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Turn one app or probe on or off; re-read it first."""
    api, t = api_for(run.client), g["target"]
    want = t["to"] == "on"
    if t.get("probe") is None:
        a, err = api.get_app(t["app"])
        if err or not a:
            return _conflict(run, units, f"the app is not there any more ({describe(err) if err else 'not found'})")
        a = norm_app(a)
        if a["name"] != t["app_name"]:
            return _conflict(run, units, f"the app is now called '{a['name']}', not '{t['app_name']}'")
        now = a["active"]
    else:
        mons, err = api.app_monitors(t["app"])
        if err:
            return _conflict(run, units, f"the app's probes could not be re-read ({describe(err)})")
        m = next((norm_probe(x) for x in mons if _same(_f(x, "id"), t["probe"])), None)
        if m is None:
            return _conflict(run, units, "the probe is not there any more")
        if m["name"] != t["name"]:
            return _conflict(run, units, f"the probe is now called '{m['name']}', not '{t['name']}'")
        now = m["active"]
    if now == want:
        run.mark(units, "noop", f"already {t['to']} when re-read")
        return
    action = "activate" if want else "deactivate"
    if t.get("probe") is None:
        out = ops.update(api, "zdx_app", t["app"], {}, name=t["name"], log=run.log, action=action)
    else:
        out = ops.update(api, "zdx_probe", t["probe"], {}, parent_id=t["app"], name=t["name"], log=run.log, action=action)
    if _ok(run, units, out, "update") and want:
        _ctx(run)["turned_on"].append({"app": t["app"], "probe": t.get("probe"), "name": t["name"]})


def _h_delete_probe(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    api, t = api_for(run.client), g["target"]
    mons, err = api.app_monitors(t["app"])
    if err:
        return _conflict(run, units, f"the app's probes could not be re-read ({describe(err)})")
    m = next((norm_probe(x) for x in mons if _same(_f(x, "id"), t["probe"])), None)
    if m is None:
        run.mark(units, "noop", "already gone when re-read")
        return
    if m["name"] != t["name"]:
        return _conflict(run, units, f"the probe is now called '{m['name']}', not '{t['name']}'")
    out = ops.delete(api, {"kind": "zdx_probe", "id": t["probe"], "parent_id": t["app"], "name": t["name"]}, log=run.log)
    _ok(run, units, out, "delete")


def _h_delete_app(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Delete a custom app: re-read it and its probes, delete every probe
    (CloudPath first), then the app. A probe added since the preview stops it."""
    api, t = api_for(run.client), g["target"]
    a, err = api.get_app(t["app"])
    if err or not a:
        run.mark(units, "noop" if not err or (err.get("status") == 404) else "conflict",
                 "already gone when re-read" if not err or err.get("status") == 404 else f"could not re-read the app ({describe(err)})")
        return
    a = norm_app(a)
    if a["name"] != t["name"]:
        return _conflict(run, units, f"the app is now called '{a['name']}', not '{t['name']}'")
    mons, err = api.app_monitors(t["app"])
    if err:
        return _conflict(run, units, f"the app's probes could not be re-read ({describe(err)})")
    planned = {str(p["id"]) for p in t["probes"]}
    now = [norm_probe(x) for x in mons]
    extra = [p for p in now if str(p["id"]) not in planned]
    if extra:
        return _conflict(run, units, f"'{t['name']}' got the probe '{extra[0]['name']}' since the preview; preview again")
    app_u = next(u for u in units if u["kind"] == "zdx_app")
    for u in [u for u in units if u["kind"] == "zdx_probe"]:
        if not any(_same(p["id"], u["object"]["probe"]) for p in now):
            run.mark([u], "noop", "already gone when re-read")
            continue
        o = ops.delete(api, {"kind": "zdx_probe", "id": u["object"]["probe"], "parent_id": t["app"], "name": u["object"]["name"]}, log=run.log)
        if not _ok(run, [u], o, "delete"):
            run.mark([app_u], "skipped", "not attempted: a probe of the app could not be deleted")
            return
    o = ops.delete(api, {"kind": "zdx_app", "id": t["app"], "name": t["name"]}, log=run.log)
    _ok(run, [app_u], o, "delete")


HANDLERS = {"zdx_collection": _h_collection, "zdx_custom_app": _h_custom_app, "zdx_predefined_app": _h_predefined_app,
            "zdx_add_probe": _h_add_probe, "zdx_state": _h_state, "zdx_delete_probe": _h_delete_probe, "zdx_delete_app": _h_delete_app}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    """Read every applied item back: {checked, confirmed, mismatched, unread}."""
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    api = api_for(run.client)
    apps, err = api.apps()
    mons, err2 = api.monitors()
    if err or err2:
        out["unread"].append(f"ZDX: {describe(err or err2)}")
        for u in applied:
            u["verified"] = None
        return out
    apps = [norm_app(a) for a in apps]
    probes = [norm_probe(m) for m in mons]
    for u in applied:
        o = u["object"]
        out["checked"] += 1
        if u["kind"] == "zdx_collection":
            ok = True   # the apps that went into it are checked below
        elif u["kind"] == "zdx_app":
            hit = next((a for a in apps if _same(a["id"], o.get("id")) or _same(a["key"], o.get("app"))
                        or (o.get("app") is None and o.get("id") is None and a["name"] == o["name"])), None)
            ok = (hit is not None) == bool(u["after"])
        elif u["kind"] == "zdx_probe":
            hit = next((p for p in probes if _same(p["id"], o.get("probe"))), None)
            ok = (hit is not None) == bool(u["after"])
            if ok and hit is not None and o.get("target") and o["policy_label"] == LABELS["web"]:
                ok = host_of(hit["target"]) == host_of(o["target"])
        elif u["kind"] == "zdx_app_state":
            hit = next((a for a in apps if _same(a["key"], o.get("app")) or _same(a["id"], o.get("app")) or _same(a["id"], o.get("id"))
                        or (a["name"] == o["name"] and a["type"] != "PREDEFINED" and o.get("app") is None)), None)
            ok = hit is not None and _state_word(hit["active"]) == u["after"]
        else:
            hit = next((p for p in probes if _same(p["id"], o.get("probe"))), None)
            ok = hit is not None and _state_word(hit["active"]) == u["after"]
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o['name']}: {u['field']} is not {u['after'] if u['field'] == 'state' else ('there' if u['after'] else 'gone')} when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The operation that reverses what was applied: a setup is undone by a
    delete (what it created) that first turns off what it turned on; a state
    change by the opposite one; a delete has none (ZDX keeps no copy)."""
    t = result.get("type")
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    if t == T_STATE:
        targets = [{"app": str(u["object"]["app"]), "probe": str(u["object"]["probe"]) if u["object"].get("probe") else None,
                    "to": "off" if u["after"] == "on" else "on"} for u in applied]
        return {"type": T_STATE, "targets": targets}
    if t != T_SETUP:
        return None
    created = [c for c in result.get("created") or [] if c.get("type", "").startswith("zdx_")]
    new_apps = {str(c["id"]) for c in created if c["type"] == "zdx_custom_app"}
    targets: List[Dict[str, Any]] = []
    turn_off: List[Dict[str, Any]] = []
    for c in created:
        if c["type"] in ("zdx_web_probe", "zdx_cloudpath_probe") and str(c["app"]) not in new_apps:
            targets.append({"app": str(c["app"]), "probe": str(c["id"]), "name": c["name"]})
    targets.sort(key=lambda x: 0 if "CloudPath" in x["name"] else 1)
    for c in created:
        if c["type"] == "zdx_custom_app":
            targets.append({"app": str(c["id"]), "probe": None, "name": c["name"]})
        elif c["type"] == "zdx_predefined_app":
            turn_off.append({"app": str(c["key"]), "probe": None, "name": c["name"]})
    for u in applied:   # what the setup turned on in apps that already existed
        o = u["object"]
        if u["kind"] in ("zdx_app_state", "zdx_probe_state") and u["after"] == "on" and o.get("app") not in (None, "") \
                and not str(o.get("probe") or "").startswith("$") and str(o.get("app")) not in new_apps \
                and not any(str(c.get("key")) == str(o.get("app")) for c in created if c["type"] == "zdx_predefined_app"):
            turn_off.append({"app": str(o["app"]), "probe": str(o["probe"]) if o.get("probe") else None, "name": o["name"]})
    for u in applied:   # the probes of a predefined app this setup created
        o = u["object"]
        if u["kind"] == "zdx_probe_state" and any(str(c.get("key")) == str(o.get("app")) for c in created if c["type"] == "zdx_predefined_app") \
                and o.get("probe") not in (None, "") and not str(o["probe"]).startswith("$"):
            turn_off.append({"app": str(o["app"]), "probe": str(o["probe"]), "name": o["name"]})
    turn_off.sort(key=lambda x: (x["probe"] is None, 0 if "CloudPath" in x["name"] else 1))
    if not targets and not turn_off:
        return None
    return {"type": T_DELETE, "targets": targets, "turn_off": turn_off}


def _register() -> None:
    common = dict(family=FAMILY, product="zdx", in_scope=in_scope, read_objects=read_objects, handlers=HANDLERS, verify=verify,
                  inverse=inverse, script="ops_zdx.js")
    ao.register(T_SETUP, label="ZDX probe setup",
                hint=("Set up ZDX apps and probes from a template: Microsoft 365 and other predefined apps, and your own URLs, each with "
                      "a Web probe and a CloudPath probe, for all users. Apps that exist are skipped or get only what they lack. "
                      "Needs ZDX ticked on the Scope page."), plan=plan_setup, **common)
    ao.register(T_STATE, label="Turn ZDX apps and probes on or off",
                hint="Every ZDX app and probe in the tenant, with its state; turn the ones you pick on or off. Needs ZDX ticked on the Scope page.",
                plan=plan_state, **common)
    ao.register(T_DELETE, label="Delete ZDX apps and probes",
                hint=("Delete custom ZDX apps (their probes first) and custom probes; type each name to confirm. Zscaler's predefined "
                      "apps can only be turned off. Cannot be undone. Needs ZDX ticked on the Scope page."), plan=plan_delete, **common)


_register()
