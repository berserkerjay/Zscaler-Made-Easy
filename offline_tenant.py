"""Offline tenants: the sample tenant and saved snapshots, served to every
reader of the app without a network.

Two kinds of offline tenant, one mechanism:

  sample     Larkspur Freight (sample_tenant.py), a made-up company to
             try the app with. Its writes change an in-memory copy only.
  snapshot   A tenant read saved to a file (only what was in scope on the
             Scope page, no credentials) and opened later, offline. Read-only.

An offline tenant is a table of API answers keyed by OneAPI path
("/zia/api/v1/webDlpRules", "/zpa/mgmtconfig/v1/admin/customers/{customerId}/application").
The app's two client stacks read it unchanged:

  OfflineRawClient   the raw-HTTP assessment client's interface (auth, get,
                     get_text, post, put, delete, stop): the short endpoints
                     are resolved with the same maps (dlp_assessment_full_auto).
  OfflineSdkClient   the SDK client's interface (.zia, .zpa, .zcc, .zdx, ...):
                     the SDK's own service and model classes, given an
                     in-memory request executor (OfflineExecutor) instead of
                     the SDK's HTTP one.

Neither class has any network code: no socket, no HTTP session, no sign-in.
The client factories in dlp_api_server (_raw_client, _build_sdk_client) hand
them out for offline credentials (creds_for) before any network client is
built, so a sample or a snapshot can never reach a real tenant. Every
request that is not a GET is refused with a plain message, except the
sample's in-memory writes.

Which tenant a browser is using is a cookie (COOKIE), set by "Try with a
sample tenant" or "Open a snapshot" and cleared by "Leave"; SourceMiddleware
puts it in a context variable for the request, and dlp_api_server._tenant_creds
then answers with the offline credentials instead of the form's, the saved
profile's or the server's. A snapshot file is untrusted when it is opened:
parse_snapshot checks its size, nesting depth, node count, schema and every
path, and takes no file path, id or credential from it.
"""
from __future__ import annotations

import contextlib
import contextvars
import copy
import json
import re
import secrets
import threading
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import safe_files

FORMAT = "zscaler-made-easy-snapshot"
VERSION = 1
MAX_SNAPSHOT_BYTES = 8 * 1024 * 1024      # an opened file larger than this is refused unread
MAX_DEPTH = 40                            # JSON nesting (the API answers need about 8)
MAX_NODES = 1_500_000                     # JSON values in one file
MAX_PATHS = 2000                          # API answers in one file
MAX_PATH_LEN = 300
MAX_OPEN = 8                              # snapshots held in memory at once (the sample is extra)
MAX_LIST_PAGES = 20                       # pages read per paginated list when saving

COOKIE = "zme_tenant_source"
SAMPLE = "sample"
SOURCE_RE = re.compile(r"\A(sample|snap-[0-9a-f]{16}|file-[0-9a-f]{16})\Z")   # \Z: "$" would also take a trailing newline
CLIENT_ID_PREFIX = "offline-"
OFFLINE_DOMAIN = ".offline.invalid"       # RFC 6761: .invalid never resolves (defence in depth)
OFFLINE_SECRET = "offline-no-secret"      # a fixed marker so the creds are "complete"; not a credential
CUSTOMER_ID = "72000000000000001"         # the ZPA customer id the offline SDK client builds paths with

READ_ONLY = ("This is an offline snapshot: it is read-only, and nothing is sent to a tenant. "
             "Open the live tenant to make changes.")
GONE = ("The offline tenant this page was using is no longer open (the server restarted or it was closed). "
        "Open the sample or the snapshot again, or choose Leave to use the live tenant.")

KNOWN_SCOPES = ("dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac", "insights", "aiguard", "ztw",
                "ztb", "easm", "zbi", "zcell", "zms")
_PATH_RE = re.compile(r"^/(zia|zpa|zcc|zdx|ziam|zins|zwa|ztw|aiguard|ztb|easm|bi|zcell|zms)/[A-Za-z0-9_\-./{}~]{1,%d}$" % MAX_PATH_LEN)
_CUSTOMER_SEG = re.compile(r"(/zpa/(?:mgmtconfig|waap-pra-config)/v[0-9]+/admin/customers/)[^/]+")
# The ZCell customer id in a Zero Trust Cellular path (zscaler/zcell/*.py:
# /zcell/config/api/v1/customers/{id}/...) is keyed as {zcellCustomerId},
# as the ZPA customer id is, so a snapshot opens with any id.
_ZCELL_SEG = re.compile(r"(/zcell/config/api/v1/customers/)[^/]+")
ZCELL_CUSTOMER_ID = "zc-72000001"          # the ZCell customer id the offline reads use when none is given
# A Microsegmentation read is a GraphQL query (POST /zms/graphql); offline it
# is answered from /zms/graphql/<operationName> (other_products.ZMS_OPERATIONS).
_ZMS_GRAPHQL = "/zms/graphql"
_ZMS_OP = re.compile(r"\A[A-Za-z]{1,60}\Z")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# Names of fields that hold a secret (a ZCC exit/uninstall password, a VPN
# pre-shared key, an API key...). A saved snapshot never keeps their values:
# only whether one is set.
_SECRET_KEY = re.compile(r"password|passwd|passcode|passphrase|secret|api_?key|private_?key|pre_?shared_?key|(^|_)psk$|(^|_)otp$|"
                         r"access_?token|refresh_?token|bearer|cookie|cert(ificate)?_?data", re.I)
_PASS_SUFFIX = re.compile(r"(?:^pass|(?<![A-Za-z])pass|[a-z0-9_]Pass)$")
# Text values under a token or key name are secrets too: a Client Connector
# app profile's policyToken (ops_zcc.INSTALL_PARAMS marks it secret), the
# company info's machineToken, a cloud NSS feed's authenticationToken, a ZPA
# provisioningKey (zscaler/zcc/models, zscaler/zia/models/cloud_nss.py,
# zscaler/zpa/models/provisioning_keys.py). Only text is masked, so a
# switch such as sendDefaultPolicyForInvalidPolicyToken (true/false) stays.
_TOKEN_KEY = re.compile(r"token|provision(ing)?_?key|enrollment_?key|config_?key", re.I)
# A token's lifetime in seconds is not a secret: a ZPA API key's
# tokenExpiryTimeInSec (zpa/models/api_keys.py) is kept when it is a number.
_TOKEN_LIFETIME = re.compile(r"(expiry|expiration|lifetime|validity)(_?time)?(_?in)?_?(sec|secs|seconds)$", re.I)
# One-time passwords and stored credentials under camelCase names: a Client
# Connector device's deviceOtpArray (zscaler/zcc/models/devices.py), the OTPs
# to exit, uninstall or turn off a service (exitOtp, uninstallOtp, zpaDisableOtp,
# zcc/models/secrets_otp.py), a cloud-to-cloud incident receiver's credJson and
# tempAuthCode (zia/models/cloud_to_cloud_ir.py), an API key's keyValue
# (zid/models/api_client.py), an LLM provider's apiCredentials
# (aiguard/models/llm_provider_credentials.py), an encrypted session key
# (zpa/models/enrollment_certificates.py). Any value type is masked.
# A Cloud & Branch Connector provisioning URL (it enrols a connector; its
# provUrlData block is configuration, kept for the Terraform export) and an
# admin's mobile app tokens (zscaler/ztw/models/provisioning_url.py,
# admin_users.py execMobileAppTokens) are masked the same way.
_OTP_KEY = re.compile(r"otp$|otp_?array$|cred_?json|temp_?auth_?code|key_?value$|api_?credentials|session_?key|"
                      r"prov(isioning)?_?url$|mobile_?app_?tokens$", re.I)
# Settings whose names say "password" but hold no secret: the admin password
# expiry switch and its number of days (zia/models/admin_roles.py
# PasswordExpiry). Kept only as a true/false or a whole number; any text
# under these names is masked like every other secret-named field.
_NOT_SECRET = frozenset({"passwordexpirationenabled", "password_expiration_enabled", "passwordexpirydays", "password_expiry_days"})
# Reads the APIs ask for with a POST that changes nothing (zscaler/zwa:
# dlp_incident_search POST /zwa/dlp/v1/incidents/search, audit_logs POST
# /zwa/dlp/v1/customer/audit): offline they are answered from the saved list
# (its first page), on the sample and on a snapshot alike.
ZWA_BASE = "/zwa/dlp/v1"
READ_POSTS = {f"{ZWA_BASE}/incidents/search": f"{ZWA_BASE}/incidents", f"{ZWA_BASE}/customer/audit": f"{ZWA_BASE}/customer/audit"}
_ZWA_WRITE = re.compile(r"\A/zwa/dlp/v1/incidents/([A-Za-z0-9][A-Za-z0-9_.:-]{0,79})/(close|labels|notes)\Z")
_VOLATILE = re.compile(r"(modified|lastseen|last_seen|lastsync|updated|creation|created)(time|at|date|_time|_at)?$|^(modifiedBy|lastModifiedBy)$", re.I)


# Settings objects the sample replaces whole on a PUT (anything else not modelled is refused).
_SETTINGS_PUT = frozenset({"/zia/api/v1/behavioralAnalysisAdvancedSettings"})


class OfflineError(Exception):
    """A refusal to show as it is; `status` is the HTTP status to answer."""

    def __init__(self, message: str, status: int = 409):
        super().__init__(message)
        self.status = status


class SnapshotInvalid(OfflineError):
    """A snapshot file this app will not open; the message says why."""

    def __init__(self, message: str):
        super().__init__(message, 400)


class OfflineRefused(Exception):
    """What an offline SDK call answers instead of an API error. `status`
    is the HTTP status the API would have used."""

    def __init__(self, status: int, message: str):
        super().__init__(f"{message} (HTTP {status}, offline)")
        self.status = status
        self.status_code = status


# ── paths ──────────────────────────────────────────────────────────────

def normalize_path(url: str) -> str:
    """The table key of a request URL: no scheme, host or query, no doubled
    or trailing slash, and the ZPA customer id as {customerId}."""
    u = str(url or "")
    if "://" in u:
        rest = u.split("://", 1)[1]
        u = "/" + rest.split("/", 1)[1] if "/" in rest else "/"
    u = u.split("?", 1)[0].split("#", 1)[0]
    u = re.sub(r"/{2,}", "/", u)
    if len(u) > 1:
        u = u.rstrip("/")
    u = _ZCELL_SEG.sub(r"\1{zcellCustomerId}", u)
    return _CUSTOMER_SEG.sub(r"\1{customerId}", u)


def valid_path(path: Any) -> bool:
    """A table key a snapshot may carry: an API path of a Zscaler service, no
    '..', no doubled slash, at most MAX_PATH_LEN characters."""
    return (isinstance(path, str) and len(path) <= MAX_PATH_LEN and bool(_PATH_RE.match(path))
            and ".." not in path and "//" not in path)


def _items(body: Any) -> Optional[List[Any]]:
    """The list inside an answer (a list, or ZPA's / ZCC's / ZIdentity's envelope)."""
    if isinstance(body, list):
        return body
    if isinstance(body, dict):
        for key in ("list", "records", "devices", "trustedNetworkContracts", "items", "policies", "alerts", "appIdentities", "customAppContracts"):
            if isinstance(body.get(key), list):
                return body[key]
    return None


def _empty_page(body: Any) -> Any:
    if isinstance(body, list):
        return []
    if isinstance(body, dict):
        out = dict(body)
        for key in ("list", "records", "devices", "trustedNetworkContracts", "items", "policies", "alerts", "appIdentities", "customAppContracts"):
            if isinstance(out.get(key), list):
                out[key] = []
        return out
    return body


def scrub(value: Any, depth: int = 0) -> Any:
    """A copy of an API answer with the value of every secret-named field
    replaced by "(set)" or "(not set)"."""
    if depth > MAX_DEPTH:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k)
            lifetime = _TOKEN_LIFETIME.search(key) and isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).isdigit()
            if key.lower() in _NOT_SECRET and isinstance(v, (bool, int)):
                out[key] = v
            elif (_SECRET_KEY.search(key) or _PASS_SUFFIX.search(key) or _OTP_KEY.search(key)
                    or (isinstance(v, str) and _TOKEN_KEY.search(key) and not lifetime)):
                out[key] = "(set)" if v not in (None, "", [], {}, False) else "(not set)"
            else:
                out[key] = scrub(v, depth + 1)
        return out
    if isinstance(value, list):
        return [scrub(x, depth + 1) for x in value]
    return value


# ── the table of answers ───────────────────────────────────────────────

class OfflineStore:
    """One offline tenant: its answers, what it says about itself, and
    (the sample only) its in-memory writes."""

    def __init__(self, source_id: str, kind: str, responses: Dict[str, Dict[str, Any]], meta: Dict[str, Any], *, writable: bool = False):
        self.id = source_id
        self.kind = kind
        self.responses = responses
        self.meta = dict(meta)
        self.writable = writable
        self.writes = 0
        self._lock = threading.RLock()

    @property
    def label(self) -> str:
        return str(self.meta.get("tenant_label") or ("Sample tenant" if self.kind == SAMPLE else "Offline snapshot"))

    def describe(self) -> Dict[str, Any]:
        """What the status, the banner and the page show (no answers)."""
        m = self.meta
        return {"mode": self.kind, "source": self.id, "tenant_label": self.label, "company": m.get("company") or "",
                "saved_at": m.get("saved_at") or "", "profile_name": m.get("profile_name") or "",
                "scopes": list(m.get("scopes") or []), "answers": len(self.responses), "writable": self.writable,
                "changes": self.writes}

    def _missing(self, path: str) -> str:
        if self.kind == SAMPLE:
            return f"The sample tenant has no data for {path}."
        return f"Not in this snapshot: {path} (it was not in scope, or not readable, when the snapshot was saved)."

    def _lookup(self, path: str) -> Optional[Dict[str, Any]]:
        entry = self.responses.get(path)
        if entry is not None:
            return entry
        for a, b in (("/mgmtconfig/v2/", "/mgmtconfig/v1/"), ("/mgmtconfig/v1/", "/mgmtconfig/v2/")):
            if a in path and path.replace(a, b) in self.responses:
                return self.responses[path.replace(a, b)]
        if path.endswith("/lite") and path[:-5] in self.responses:
            return self.responses[path[:-5]]
        return None

    def _item(self, path: str) -> Tuple[Optional[Dict[str, Any]], Optional[List[Any]], int]:
        """(the object, its list, its index) for a '<collection>/<id>' path."""
        if "/" not in path:
            return None, None, -1
        parent, last = path.rsplit("/", 1)
        entry = self._lookup(parent)
        items = _items(entry["body"]) if entry else None
        if items is None:
            return None, None, -1
        for i, x in enumerate(items):
            if isinstance(x, dict) and str(x.get("id", x.get("instanceId", x.get("tenantId", "")))) == last:   # instanceId: cloud app instances
                return x, items, i
        return None, items, -1

    def answer_get(self, url: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """(status, body) of a GET, as the API would answer it."""
        path = normalize_path(url)
        params = params or {}
        with self._lock:
            entry = self._lookup(path)
            if entry is not None:
                status, body = int(entry.get("status") or 200), copy.deepcopy(entry.get("body"))
                if "text" in entry and entry.get("body") is None:
                    body = entry["text"]
                try:
                    page = int(params.get("page") or params.get("pageNumber") or 1)
                except (TypeError, ValueError):
                    page = 1
                if page > 1:
                    return status, _empty_page(body)
                if path.endswith("/cloudApplications/policy") and (params.get("app_class") or params.get("appClass")):
                    # The catalogue for one application class (ssl_flow, pack_channels): only rows that
                    # carry their class can answer it; otherwise there is no answer for one class.
                    cls = str(params.get("app_class") or params.get("appClass"))
                    rows = [x for x in (_items(body) or []) if isinstance(x, dict) and ("appClass" in x or "app_class" in x)]
                    if not rows:
                        return 404, {"code": "NOT_FOUND", "message": self._missing(f"{path}?app_class={cls[:40]}")}
                    return status, [x for x in rows if str(x.get("appClass", x.get("app_class"))) == cls]
                if path.endswith("/getDeviceDetails") and isinstance(body, list):
                    # One device per udid (zscaler/zcc/devices.py get_device_details): the sample keeps them as a list.
                    want = str(params.get("udid") or "")
                    hit = next((x for x in body if isinstance(x, dict) and want and str(x.get("udid")) == want), None)
                    return (200, hit) if hit is not None else (404, {"code": "NOT_FOUND", "message": self._missing(f"{path}?udid")})
                dt = params.get("deviceType")
                items = _items(body)
                # The platform is device_type on an app profile (zscaler/zcc/models/webpolicy.py), deviceType on older answers.
                field = next((f for f in ("device_type", "deviceType") if items and all(isinstance(x, dict) and f in x for x in items)), None)
                if dt not in (None, "") and isinstance(body, list) and field:
                    body = [x for x in items if str(x.get(field)) == str(dt)]
                return status, body
            item, _, _ = self._item(path)
            if item is not None:
                return 200, copy.deepcopy(item)
        return 404, {"code": "NOT_FOUND", "message": self._missing(path)}

    def _answer_graphql(self, body: Any) -> Tuple[int, Any]:
        """A Microsegmentation GraphQL read (a query, never a mutation),
        answered from /zms/graphql/<operationName>; read-only on the sample
        and on a snapshot alike."""
        import other_products
        op = body.get("operationName") if isinstance(body, dict) else None
        query = str(body.get("query") or "") if isinstance(body, dict) else ""
        if not isinstance(op, str) or not _ZMS_OP.match(op) or op not in other_products.ZMS_OPERATIONS \
                or not query.lstrip().startswith("query "):
            return 403, {"code": "READ_ONLY", "message": READ_ONLY}
        with self._lock:
            entry = self.responses.get(f"{_ZMS_GRAPHQL}/{op}")
            if entry is not None:
                return int(entry.get("status") or 200), copy.deepcopy(entry.get("body"))
        return 404, {"code": "NOT_FOUND", "message": self._missing(f"{_ZMS_GRAPHQL}/{op}")}

    def answer_read_post(self, path: str, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """(status, body) of a read the API asks for with a POST (READ_POSTS):
        the saved list as the search answers it, its first page only."""
        key = READ_POSTS[path]
        params = params or {}
        try:
            page = int(params.get("page") or 1)
        except (TypeError, ValueError):
            page = 1
        with self._lock:
            entry = self._lookup(key)
            if entry is None:
                return 404, {"code": "NOT_FOUND", "message": self._missing(key)}
            body = copy.deepcopy(entry.get("body"))
        if key.endswith("/incidents"):
            rows = body if isinstance(body, list) and page == 1 else []
            return 200, {"cursor": {"currentPageNumber": page, "totalPages": 1, "totalElements": len(rows)},
                         "incidents": [{"incidents": rows}] if rows else []}
        if page > 1:
            return 200, _empty_page(body) if not isinstance(body, dict) else dict(body, logs=[])
        return 200, body

    def _zwa_write(self, m: "re.Match", body: Any) -> Tuple[int, Any]:
        """The sample's in-memory answer to a Workflow Automation incident
        close, label or note (zscaler/zwa/dlp_incidents.py incident_close,
        assign_labels, incident_notes): the incident changes, nothing else."""
        iid, what = m.group(1), m.group(2)
        entry = self._lookup(f"{ZWA_BASE}/incidents")
        items = _items(entry["body"]) if entry else None
        inc = next((x for x in items or [] if isinstance(x, dict) and str(x.get("id")) == iid), None)
        if inc is None:
            return 404, {"code": "NOT_FOUND", "message": self._missing(f"{ZWA_BASE}/incidents/{iid}")}
        b = body if isinstance(body, dict) else {}
        hist = self.responses.setdefault(f"{ZWA_BASE}/incidents/{iid}/change-history", {"status": 200, "body": {"changeHistory": []}})
        log = hist["body"].setdefault("changeHistory", []) if isinstance(hist.get("body"), dict) else []
        if what == "close":
            inc["status"] = "CLOSED"
            inc["resolution"] = inc["closedCode"] = str(b.get("resolutionCode") or "FALSE_POSITIVE")[:40]
            lab = b.get("resolutionLabel")
            if isinstance(lab, dict) and lab.get("key"):
                inc.setdefault("labels", []).append({"key": str(lab["key"])[:60], "value": str(lab.get("value") or "")[:120]})
            if b.get("notes"):
                inc.setdefault("notes", []).append({"body": str(b["notes"])[:1000], "createdBy": "api"})
            log.append(f"Status changed to CLOSED ({inc['resolution']}) through the API")
        elif what == "labels":
            for lab in b.get("labels") or []:
                if isinstance(lab, dict) and lab.get("key"):
                    inc.setdefault("labels", []).append({"key": str(lab["key"])[:60], "value": str(lab.get("value") or "")[:120]})
            log.append("Labels added through the API")
        else:
            inc.setdefault("notes", []).append({"body": str(b.get("notes") or "")[:1000], "createdBy": "api"})
            log.append("Note added through the API")
        self.writes += 1
        return 200, copy.deepcopy(inc)

    def answer_write(self, method: str, url: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Tuple[int, Any]:
        """(status, body) of a POST / PUT / PATCH / DELETE: refused on a
        snapshot; on the sample, applied to its in-memory copy. A read the
        API asks for with a POST (READ_POSTS) is answered on both."""
        method = str(method or "").upper()
        path = normalize_path(url)
        if method == "POST" and path == _ZMS_GRAPHQL:
            return self._answer_graphql(body)
        if method == "POST" and path == "/zins/graphql":
            # Z-Insights asks every question with a POST: the sample and a snapshot
            # keep one answer per GraphQL operation (offline the window is not applied).
            with self._lock:
                answer = self._zins_answer(body)
            if answer is not None:
                return answer
        if method == "PUT" and path.endswith("/cloudApplications/bulkUpdate") and self.writable:
            with self._lock:
                return self._sanction(body)
        if method == "POST" and path in READ_POSTS:
            return self.answer_read_post(path, params)
        lookup = path.endswith(("/urlLookup", "/auditlogEntryReport")) or path.startswith("/zins/")
        if lookup and not (self.writable and path.endswith("/urlLookup")):
            # A read the API asks for with a POST (URL lookup, Insights, audit log report): offline it has no answer.
            what = "the sample tenant has no such data" if self.kind == SAMPLE else "a snapshot holds only the lists it saved"
            return 404, {"code": "NOT_OFFLINE", "message": f"This lookup needs the live tenant ({path}): {what}. Nothing was sent to a tenant."}
        if not self.writable:
            return 403, {"code": "READ_ONLY", "message": READ_ONLY}
        import sample_tenant
        with self._lock:
            if method == "POST" and path.endswith("/urlLookup"):
                return 200, sample_tenant.url_lookup(body if isinstance(body, list) else [])
            if method == "POST" and path.endswith("/status/activate"):
                return 200, {"status": "ACTIVE"}
            if method == "POST" and path.endswith("/dlpEngines/validateDlpExpr"):
                return 200, {"status": "VALID"}
            if method == "POST" and path.endswith("/pacFiles/validate"):
                # ZIA's PAC validator, as the sample answers it: text only, never run.
                ok = isinstance(body, str) and "FindProxyForURL" in body
                return 200, {"success": ok, "message": "" if ok else "FindProxyForURL is missing", "errorCount": 0 if ok else 1,
                             "warningCount": 0, "messages": [] if ok else [{"line": 1, "column": 1, "severity": "ERROR",
                                                                            "message": "FindProxyForURL is missing", "fatal": True}]}
            # The security policy lists (zia/security_policy_settings.py): the
            # denylist changes by ADD_TO_LIST / REMOVE_FROM_LIST, the allowlist
            # is replaced whole (PUT /security).
            if method == "POST" and path.endswith("/security/advanced/blacklistUrls"):
                entry = self._lookup(path[: -len("/blacklistUrls")])
                from urllib.parse import parse_qs, urlsplit
                action = str((params or {}).get("action") or (parse_qs(urlsplit(str(url)).query).get("action") or [""])[0])
                urls = [str(u) for u in ((body or {}).get("blacklistUrls") or []) if isinstance(u, (str, int))] if isinstance(body, dict) else []
                if entry is None or not isinstance(entry.get("body"), dict) or action not in ("ADD_TO_LIST", "REMOVE_FROM_LIST"):
                    return 400, {"code": "NOT_MODELLED", "message": "The sample tenant takes ADD_TO_LIST or REMOVE_FROM_LIST here."}
                cur = [str(u) for u in entry["body"].get("blacklistUrls") or []]
                entry["body"]["blacklistUrls"] = ([u for u in cur if u not in urls] if action == "REMOVE_FROM_LIST"
                                                  else cur + [u for u in urls if u not in cur])
                self.writes += 1
                return 204, {}
            if method == "PUT" and (path.endswith("/security") or path.endswith("/security/advanced")) and isinstance(body, dict):
                entry = self._lookup(path)
                key = "whitelistUrls" if path.endswith("/security") else "blacklistUrls"
                if entry is None or not isinstance(entry.get("body"), dict) or not isinstance(body.get(key), list):
                    return 400, {"code": "NOT_MODELLED", "message": f"The sample tenant takes {key} here."}
                entry["body"][key] = [str(u) for u in body[key] if isinstance(u, (str, int))]
                self.writes += 1
                return 200, copy.deepcopy(entry["body"])
            zm = _ZWA_WRITE.match(path) if method == "POST" else None
            if zm:
                return self._zwa_write(zm, body)
            if method == "PUT" and path.endswith("/web/policy/activate") and isinstance(body, dict):
                # Switches one app profile's state (zscaler/zcc/web_policy.py activate_web_policy; the toggle is assumed, see ops_zcc_live).
                lst = self._lookup(path.rsplit("/", 1)[0] + "/listByCompany")
                rows = _items(lst["body"]) if lst else None
                hit = next((x for x in rows or [] if isinstance(x, dict) and str(x.get("id")) == str(body.get("policyId"))), None)
                if hit is None:
                    return 404, {"code": "NOT_FOUND", "message": "No such app profile in the sample tenant."}
                on = str(hit.get("active")).strip().lower() in ("1", "true")
                hit["active"] = (0 if on else 1) if isinstance(hit.get("active"), int) else ("0" if on else "1")
                self.writes += 1
                return 200, {"success": "true"}
            if method == "PATCH" and "/application-profiles/" in path and isinstance(body, dict):
                # update_application_profile: the allowlisted fields live in policyExtension (zscaler/zcc/models/application_profiles.py).
                item, _coll, _idx = self._item(path)
                if item is None:
                    return 404, {"code": "NOT_FOUND", "message": "No such app profile in the sample tenant."}
                pe = item.setdefault("policyExtension", {})
                for k, v in body.items():
                    if k != "policyId" and not re.search(r"password|passcode|secret|token", k, re.I):
                        pe[k] = copy.deepcopy(v)
                self.writes += 1
                return 200, copy.deepcopy(item)
            entry = self._lookup(path)
            items = _items(entry["body"]) if entry else None
            if method == "POST" and items is not None:
                # A deep copy: the caller's payload must never alias the in-memory tenant.
                obj = copy.deepcopy(body) if isinstance(body, dict) else {}
                ids = [int(x.get("id")) for x in items if isinstance(x, dict) and str(x.get("id", "")).isdigit()]
                new_id = max(ids + [90000]) + 1
                obj["id"] = str(new_id) if path.startswith("/zpa/") else new_id
                if path.endswith("/cloudApplicationInstances"):
                    obj["instanceId"] = new_id      # a cloud app instance's id is instanceId (zia/models/cloud_app_instances.py)
                items.append(obj)
                self.writes += 1
                return 200, copy.deepcopy(obj)
            if method == "PUT" and path in _SETTINGS_PUT and entry is not None and isinstance(body, dict):
                # A settings object replaced whole (the Cloud Sandbox hash list: sandbox.add_hash_to_custom_list).
                entry["body"] = copy.deepcopy(body)
                count = self._lookup(path + "/fileHashCount")
                if count is not None and isinstance(count.get("body"), dict) and isinstance(body.get("md5HashValueList"), list):
                    used = len(body["md5HashValueList"])
                    total = int(count["body"].get("blockedFileHashesCount") or 0) + int(count["body"].get("remainingFileHashes") or 0)
                    count["body"] = {"blockedFileHashesCount": used, "remainingFileHashes": max(0, total - used)}
                self.writes += 1
                return 200, copy.deepcopy(body)
            item, coll, idx = self._item(path)
            if method == "POST" and item is None and coll is not None and path.startswith("/ziam/") and "/groups/" in path:
                # ZIdentity adds a member by POST /groups/{id}/users/{userId} (zscaler/zid/groups.py add_user_to_group).
                coll.append({"id": path.rsplit("/", 1)[1]})
                self.writes += 1
                return 200, {"id": path.split("/groups/", 1)[1].split("/", 1)[0]}
            if method in ("PUT", "PATCH") and item is not None:
                new = dict(item)
                new.update(copy.deepcopy(body) if isinstance(body, dict) else {})
                new["id"] = item.get("id")
                coll[idx] = new
                self.writes += 1
                return 200, copy.deepcopy(new)
            if method == "DELETE" and item is not None:
                coll.pop(idx)
                self.writes += 1
                return 204, {}
        return 400, {"code": "NOT_MODELLED",
                     "message": f"The sample tenant does not model this change ({method} {path}); nothing was sent to a tenant."}


    def _zins_answer(self, body: Any) -> Optional[Tuple[int, Any]]:
        """(status, body) kept for a Z-Insights operation, or None. Shadow IT
        apps honour the application name filter (`in` / `eq`) as Insights does."""
        op = body.get("operationName") if isinstance(body, dict) else None
        if not isinstance(op, str) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9]{1,63}", op):
            return None
        entry = self.responses.get(f"/zins/graphql/{op}")
        if entry is None:
            return None
        out = copy.deepcopy(entry.get("body"))
        filt = ((body.get("variables") or {}).get("filterBy") or {}) if isinstance(body.get("variables"), dict) else {}
        app = filt.get("application") if isinstance(filt, dict) else None
        if op == "ShadowITApps" and isinstance(app, dict):
            names = app.get("in") if isinstance(app.get("in"), list) else [app.get("eq")] if app.get("eq") is not None else None
            try:
                ents = out["data"]["SHADOW_IT"]["apps"]["entries"]
            except (KeyError, TypeError):
                ents = None
            if names is not None and isinstance(ents, list):
                want = {str(n) for n in names}
                out["data"]["SHADOW_IT"]["apps"]["entries"] = [e for e in ents if isinstance(e, dict) and str(e.get("application")) in want]
        return int(entry.get("status") or 200), out

    def _sanction(self, body: Any) -> Tuple[int, Any]:
        """The sample's cloud application bulk update (PUT /cloudApplications/bulkUpdate):
        the named apps take the new state in the sample's Shadow IT answer."""
        body = body if isinstance(body, dict) else {}
        state = {"SANCTIONED": "Sanctioned", "UN_SANCTIONED": "Unsanctioned"}.get(str(body.get("sanctionedState") or "").upper())
        ids = body.get("applicationIds") if isinstance(body.get("applicationIds"), list) else None
        if state is None or not ids:
            return 400, {"code": "INVALID_INPUT", "message": "sanctionedState must be SANCTIONED or UN_SANCTIONED and applicationIds a list."}
        apps = _items((self._lookup(normalize_path("/zia/api/v1/cloudApplications/lite")) or {}).get("body")) or []
        names = {str(a.get("id")): str(a.get("name")) for a in apps if isinstance(a, dict)}
        unknown = [str(i) for i in ids if str(i) not in names]
        if unknown:
            return 400, {"code": "INVALID_INPUT", "message": f"No cloud application with id {unknown[0]}."}
        entry = self.responses.get("/zins/graphql/ShadowITApps")
        try:
            ents = entry["body"]["data"]["SHADOW_IT"]["apps"]["entries"] if entry else []
        except (KeyError, TypeError):
            ents = []
        want = {names[str(i)] for i in ids}
        for e in ents:
            if isinstance(e, dict) and str(e.get("application")) in want:
                e["sanctioned_state"] = state
        self.writes += 1
        return 204, {}


# ── the raw-HTTP client's interface ────────────────────────────────────

class OfflineRawClient:
    """dlp_assessment_full_auto.Client's interface over an OfflineStore.
    No network code: every answer comes from the table."""

    offline = True
    legacy = False
    method = "oneapi"

    def __init__(self, store: OfflineStore, creds: Dict[str, Any]):
        import time
        self.store = store
        self.cid = str(creds.get("client_id") or "")
        self.vd = str(creds.get("vanity_domain") or "")
        self.cloud = str(creds.get("cloud") or "production")
        self.customer_id = CUSTOMER_ID
        self.base = f"offline ({store.label})"
        self.token = "offline"
        self.exp = time.time() + 3600
        self.rate_key = f"offline:{store.id}"
        self.stopped = threading.Event()
        self.stop_check: Optional[Callable[[], bool]] = None
        self.requests_made = 0

    def _stopped(self) -> bool:
        if self.stopped.is_set():
            return True
        fn = self.stop_check
        try:
            return bool(fn and fn())
        except Exception:  # noqa: BLE001
            return False

    def auth(self):
        return True

    def stop(self) -> None:
        self.stopped.set()

    def close(self) -> None:
        return None

    def _candidates(self, ep: str) -> List[str]:
        from dlp_assessment_full_auto import _resolve_candidates
        return [c for c in _resolve_candidates(ep, self.customer_id, False) if c]

    def get(self, ep, p=None):
        from dlp_assessment_full_auto import _FAN_OUT, _STOPPED, _ls
        if self._stopped():
            return _STOPPED
        if ep in _FAN_OUT:
            items, answered, first = [], False, None
            for part, params, tag in _FAN_OUT[ep]:
                d, c = self.get(part, dict(p or {}, **params))
                first = first or (d, c)
                if c in (200, 204):
                    answered = True
                    for x in _ls(d):
                        if isinstance(x, dict):
                            x = dict(x)
                            x.setdefault(*tag)
                        items.append(x)
            return (items, 200) if answered else first
        res = ({"error": "not found", "status": 404}, 404)
        for cand in self._candidates(str(ep)):
            self.requests_made += 1
            status, body = self.store.answer_get(cand, p)
            res = (body, status) if status < 400 else (dict(body if isinstance(body, dict) else {}, status=status, path=cand), status)
            if status not in (400, 404, 405):
                break
        return res

    def get_text(self, ep, p=None, accept="*/*", max_bytes=64 * 1024 * 1024, _retry=0):
        body, status = self.get(ep, p)
        if status >= 400:
            return body, status
        text = body if isinstance(body, str) else json.dumps(body)
        return text[:max_bytes], status

    def _write(self, method: str, ep: str, body: Any = None):
        from dlp_assessment_full_auto import _resolve_ep
        real = _resolve_ep(str(ep), self.customer_id, False) or str(ep)
        status, data = self.store.answer_write(method, real, body)
        return data, status

    def post(self, ep, body=None):
        return self._write("POST", ep, body)

    def put(self, ep, body=None):
        return self._write("PUT", ep, body)

    def delete(self, ep, body=None):
        return self._write("DELETE", ep, body)


# ── the SDK client's interface ─────────────────────────────────────────

class _Answer:
    """What the SDK reads from an HTTP answer: status, headers, text."""

    def __init__(self, status: int, body: Any):
        self.status_code = int(status)
        self.headers = {"Content-Type": "application/json"}
        self.text = body if isinstance(body, str) else json.dumps(body)
        self.content = self.text.encode("utf-8")
        self.reason = "OK" if status < 400 else "Offline"
        self.ok = status < 400

    def json(self) -> Any:
        return json.loads(self.text)


class OfflineExecutor:
    """The SDK's RequestExecutor contract (create_request, execute,
    fire_request) answered from an OfflineStore. No network code."""

    use_legacy_client = False

    def __init__(self, store: OfflineStore):
        self._store = store
        self._default_headers: Dict[str, str] = {}
        self._custom_headers: Dict[str, str] = {}
        self._config: Dict[str, Any] = {"client": {"customerId": CUSTOMER_ID}}

    @staticmethod
    def get_service_type(url: str) -> str:
        u = str(url or "")
        for marker, kind in (("/aiguard/", "aiguard"), ("/ziam/admin/api/v1", "ziam"), ("/zia", "zia"), ("/ztw", "ztw"), ("/zcc", "zcc"), ("/zdx", "zdx"),
                             ("/zwa", "zwa"), ("/zpa", "zpa"), ("/mgmtconfig", "zpa"), ("/zins", "zins")):
            if marker in u:
                return kind
        return "zia"

    def create_request(self, method: str, endpoint: str, body: Any = None, headers: Optional[Dict[str, Any]] = None,
                       params: Optional[Dict[str, Any]] = None, use_raw_data_for_body: bool = False):
        from urllib.parse import parse_qsl
        endpoint = str(endpoint or "")
        query = dict(params or {})
        if "?" in endpoint:
            endpoint, qs = endpoint.split("?", 1)
            for k, v in parse_qsl(qs):
                query.setdefault(k, v)
        req = {"method": str(method or "GET").upper(), "url": endpoint, "params": query, "headers": dict(headers or {}),
               "uuid": secrets.token_hex(8), "service_type": self.get_service_type(endpoint)}
        if isinstance(body, dict) and body and not use_raw_data_for_body and "/zdx/" not in endpoint:
            from zscaler.helpers import convert_keys_to_camel_case   # as the SDK's own executor sends it
            body = convert_keys_to_camel_case(body)
        req["data" if use_raw_data_for_body else "json"] = body
        return req, None

    def fire_request(self, request: Dict[str, Any]):
        method = str(request.get("method") or "GET").upper()
        if method == "GET":
            status, body = self._store.answer_get(request.get("url", ""), request.get("params") or {})
        else:
            payload = request.get("json") if request.get("json") is not None else request.get("data")
            url = request.get("url", "")
            params = request.get("params") or {}
            if params:   # a write's query (the denylist's ?action=) rides on the URL: answer_write reads it from there
                from urllib.parse import urlencode
                url = f"{url}{'&' if '?' in url else '?'}{urlencode(params)}"
            status, body = self._store.answer_write(method, url, payload, params)
        answer = _Answer(status, body)
        if status >= 400:
            msg = body.get("message") if isinstance(body, dict) else str(body)
            return request, answer, answer.text, OfflineRefused(status, str(msg or "Refused offline"))
        return request, answer, answer.text, None

    def execute(self, request: Dict[str, Any], response_type: Any = None, return_raw_response: bool = False):
        req, answer, text, error = self.fire_request(request)
        if error is not None:
            return None, error
        if return_raw_response:
            return answer, None
        from zscaler.oneapi_response import ZscalerAPIResponse
        return ZscalerAPIResponse(request_executor=self, req=req, res_details=answer, response_body=text if answer.status_code != 204 else "{}",
                                  data_type=response_type, service_type=req.get("service_type", "")), None

    # The executor's other entry points: nothing to do offline.
    def set_session(self, session: Any) -> None:
        return None

    def set_custom_headers(self, headers: Dict[str, Any]) -> None:
        self._custom_headers.update(headers or {})

    def clear_custom_headers(self) -> None:
        self._custom_headers = {}

    def get_custom_headers(self) -> Dict[str, Any]:
        return dict(self._custom_headers)

    def get_default_headers(self) -> Dict[str, Any]:
        return dict(self._default_headers)

    def deauthenticate(self, *a: Any, **k: Any) -> None:
        return None

    def has_mutations_occurred(self) -> bool:
        return self._store.writes > 0


class OfflineSdkClient:
    """The zscaler-sdk-python client's interface (.zia, .zpa, .zcc, .zdx,
    .zid / .zidentity, .zins, .zwa, .ztw, .aiguard) over an OfflineStore: the SDK's
    service and model classes with OfflineExecutor as their executor."""

    offline = True
    use_legacy_client = False

    def __init__(self, store: OfflineStore, creds: Dict[str, Any]):
        self._store = store
        self._request_executor = OfflineExecutor(store)
        self._config = {"client": {"customerId": CUSTOMER_ID, "vanityDomain": str(creds.get("vanity_domain") or ""), "cloud": "PRODUCTION"}}
        self._services: Dict[str, Any] = {}
        # As zia_rate.attach_client stamps a live client (without its HTTP session).
        self._zia_rate_key = f"offline:{store.id}"
        self._zia_rate_label = store.label
        self._zia_rate_labels = (store.label,)

    def get_request_executor(self) -> "OfflineExecutor":
        """As the SDK's OneAPI client (oneapi_client.Client.get_request_executor):
        the fleet's service-status CSV is asked through it."""
        return self._request_executor

    def _svc(self, name: str, build: Callable[[], Any]) -> Any:
        if name not in self._services:
            self._services[name] = build()
        return self._services[name]

    @property
    def zia(self):
        from zscaler.zia.zia_service import ZIAService
        return self._svc("zia", lambda: ZIAService(self._request_executor))

    @property
    def zpa(self):
        from zscaler.zpa.zpa_service import ZPAService
        return self._svc("zpa", lambda: ZPAService(self._request_executor, self._config))

    @property
    def zcc(self):
        from zscaler.zcc.zcc_service import ZCCService
        return self._svc("zcc", lambda: ZCCService(self))

    @property
    def zdx(self):
        from zscaler.zdx.zdx_service import ZDXService
        return self._svc("zdx", lambda: ZDXService(self))

    @property
    def zid(self):
        from zscaler.zid.zid_service import ZIdService
        return self._svc("zid", lambda: ZIdService(self._request_executor))

    zidentity = zid

    @property
    def zins(self):
        from zscaler.zins.zins_service import ZInsService
        return self._svc("zins", lambda: ZInsService(self._request_executor))

    @property
    def zwa(self):
        from zscaler.zwa.zwa_service import ZWAService
        return self._svc("zwa", lambda: ZWAService(self))

    @property
    def aiguard(self):
        from zscaler.aiguard.aiguard_service import AIGuardService
        return self._svc("aiguard", lambda: AIGuardService(self._request_executor))

    @property
    def ztw(self):
        from zscaler.ztw.ztw_service import ZTWService
        return self._svc("ztw", lambda: ZTWService(self._request_executor))

    @property
    def aiguard(self):
        # AI Guard's OneAPI configuration services (zscaler/aiguard/aiguard_service.py), as ZscalerClient.aiguard.
        from zscaler.aiguard.aiguard_service import AIGuardService
        return self._svc("aiguard", lambda: AIGuardService(self._request_executor))

    def authenticate(self) -> None:
        return None

    def deauthenticate(self) -> None:
        return None

    def __enter__(self):
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


# ── which offline tenant a request uses ────────────────────────────────

_LOCK = threading.RLock()
_OPEN: "OrderedDict[str, OfflineStore]" = OrderedDict()
_CURRENT: contextvars.ContextVar = contextvars.ContextVar("zme_offline_source", default=None)


def sample_store(reset: bool = False) -> OfflineStore:
    """The sample tenant (one per server, in memory); `reset` starts it afresh."""
    import sample_tenant
    with _LOCK:
        s = _OPEN.get(SAMPLE)
        if s is None or reset:
            responses = {normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()}
            s = OfflineStore(SAMPLE, SAMPLE, responses, sample_tenant.meta(), writable=True)
            _OPEN[SAMPLE] = s
        return s


def register(store: OfflineStore) -> OfflineStore:
    """Hold an opened snapshot in memory (at most MAX_OPEN; the oldest goes)."""
    with _LOCK:
        _OPEN[store.id] = store
        _OPEN.move_to_end(store.id)
        snaps = [k for k in _OPEN if k != SAMPLE]
        while len(snaps) > MAX_OPEN:
            _OPEN.pop(snaps.pop(0), None)
        return store


def forget(source_id: str) -> None:
    """Drop an opened snapshot from memory (the sample is kept)."""
    with _LOCK:
        if source_id != SAMPLE:
            _OPEN.pop(source_id, None)


def store(source_id: str) -> Optional[OfflineStore]:
    """The open offline tenant `source_id`; a saved snapshot that is not
    in memory (the server restarted) is opened again from its file."""
    if not isinstance(source_id, str) or not SOURCE_RE.match(source_id):
        return None
    if source_id == SAMPLE:
        return sample_store()
    with _LOCK:
        s = _OPEN.get(source_id)
    if s is not None:
        return s
    if source_id.startswith("snap-"):
        try:
            return open_saved(source_id)
        except OfflineError:
            return None
    return None


def current_source() -> Optional[str]:
    return _CURRENT.get()


@contextlib.contextmanager
def using(source_id: Optional[str]):
    """Run with `source_id` as the request's offline tenant (or none)."""
    token = _CURRENT.set(source_id)
    try:
        yield
    finally:
        _CURRENT.reset(token)


def creds_for(st: OfflineStore) -> Dict[str, str]:
    """The credentials that name an offline tenant: complete for a OneAPI
    sign-in, so every route works, but pointing at a domain that never
    resolves and carrying no secret. The client factories recognise them
    (store_for_creds) before any network client is built."""
    slug = st.id if st.id != SAMPLE else "larkspur-freight-sample"
    return {"auth_method": "oneapi", "cloud": "production", "vanity_domain": f"{slug}{OFFLINE_DOMAIN}",
            "client_id": f"{CLIENT_ID_PREFIX}{st.id}", "client_secret": OFFLINE_SECRET, "customer_id": CUSTOMER_ID,
            "username": "", "password": "", "api_key": ""}


def is_offline_creds(creds: Any) -> bool:
    if not isinstance(creds, dict):
        return False
    return (str(creds.get("client_id") or "").startswith(CLIENT_ID_PREFIX)
            and str(creds.get("vanity_domain") or "").lower().endswith(OFFLINE_DOMAIN))


def store_for_creds(creds: Any) -> Optional[OfflineStore]:
    """The offline tenant these credentials name; None for real
    credentials. OfflineError when it names one that is no longer open."""
    if not is_offline_creds(creds):
        return None
    sid = str(creds.get("client_id"))[len(CLIENT_ID_PREFIX):]
    st = store(sid)
    if st is None:
        raise OfflineError(GONE, 409)
    return st


def label_for(creds: Any) -> str:
    """How an offline tenant is named in records and messages."""
    sid = str((creds or {}).get("client_id") or "")[len(CLIENT_ID_PREFIX):]
    with _LOCK:
        st = _OPEN.get(sid)
    if st is not None:
        return st.label
    return "Sample tenant: Larkspur Freight" if sid == SAMPLE else "Offline snapshot"


def current_creds() -> Optional[Dict[str, str]]:
    """The offline credentials of this request's tenant, None when it uses
    the live tenant. OfflineError (fail closed: never the live tenant
    instead) when its offline tenant is no longer open."""
    sid = _CURRENT.get()
    if not sid:
        return None
    st = store(sid)
    if st is None:
        raise OfflineError(GONE, 409)
    return creds_for(st)


def client_for(creds: Any, kind: str):
    """The offline client for offline credentials (kind 'raw' or 'sdk'),
    None for real ones."""
    st = store_for_creds(creds)
    if st is None:
        return None
    return OfflineRawClient(st, creds) if kind == "raw" else OfflineSdkClient(st, creds)


def status() -> Dict[str, Any]:
    """What this request's browser is using: the live tenant, the sample or a snapshot."""
    sid = _CURRENT.get()
    if not sid:
        return {"mode": "live"}
    st = store(sid)
    if st is None:
        return {"mode": "gone", "message": GONE}
    return st.describe()


def source_from_cookie_header(header: str) -> Optional[str]:
    """The offline tenant the browser's COOKIE names, else None. Read pair by
    pair (RFC 6265 section 5.4: "; " separates them), not with SimpleCookie,
    which drops every cookie once one value it cannot parse appears (another
    localhost app's JSON or spaced value): that would silently put a browser
    that chose the sample or a snapshot back on the live tenant."""
    if not header or COOKIE not in header:
        return None
    for pair in str(header).split(";"):
        name, sep, value = pair.partition("=")
        if not sep or name.strip() != COOKIE:
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        if SOURCE_RE.match(value):
            return value
    return None


class SourceMiddleware:
    """Puts the browser's offline tenant (the COOKIE) in the request's
    context, for _tenant_creds. Pure ASGI: the context is the request's own."""

    def __init__(self, app: Any):
        self.app = app

    async def __call__(self, scope: Dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        header = ""
        for k, v in scope.get("headers") or []:
            if k == b"cookie":
                header += (v.decode("latin-1") + "; ")
        token = _CURRENT.set(source_from_cookie_header(header))
        try:
            await self.app(scope, receive, send)
        finally:
            _CURRENT.reset(token)


# ── snapshot files ─────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _text(v: Any, n: int = 200) -> str:
    return _CONTROL.sub(" ", str(v if v is not None else ""))[:n].strip()


def _clean_meta(meta: Any) -> Dict[str, Any]:
    m = meta if isinstance(meta, dict) else {}
    channels = {}
    if isinstance(m.get("channels"), dict):
        for k, v in list(m["channels"].items())[:60]:
            if isinstance(v, dict):   # channel_scope.normalize's {choice, note, name}: only the choice is kept
                v = v.get("choice")
            if isinstance(k, str) and re.match(r"^[a-z0-9_]{1,40}$", k) and isinstance(v, str) and v in ("zscaler", "alternative", "gap", "none", ""):
                channels[k] = v
    counts = {}
    if isinstance(m.get("counts"), dict):
        for k, v in list(m["counts"].items())[:40]:
            if isinstance(k, str) and re.match(r"^[a-z_]{1,40}$", k) and isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10**9:
                counts[k] = v
    scopes = [s for s in (m.get("scopes") or []) if isinstance(s, str) and s in KNOWN_SCOPES] if isinstance(m.get("scopes"), list) else []
    return {"tenant_label": _text(m.get("tenant_label")), "profile_name": _text(m.get("profile_name")),
            "saved_at": _text(m.get("saved_at"), 40), "auth_method": "legacy" if m.get("auth_method") == "legacy" else "oneapi",
            "scopes": sorted(set(scopes)), "channels": channels, "counts": counts,
            "unread": [_text(x, 160) for x in (m.get("unread") or [])[:200]] if isinstance(m.get("unread"), list) else []}


def build_snapshot(responses: Dict[str, Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    """The snapshot document: format, version, cleaned meta and the
    (scrubbed) answers. Nothing else, and never a credential."""
    out = {}
    for path, entry in responses.items():
        if valid_path(path) and isinstance(entry, dict):
            out[path] = {"status": int(entry.get("status") or 200), "body": scrub(entry.get("body"))}
    return {"format": FORMAT, "version": VERSION, "meta": _clean_meta(meta), "responses": out}


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _nesting(text: str) -> int:
    """The deepest [ / { nesting of JSON text (strings skipped), in one pass."""
    depth = deepest = 0
    in_str = esc = False
    for ch in text:
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > MAX_DEPTH:
                    return deepest
        elif ch in "]}":
            depth -= 1
    return deepest


def _count_nodes(value: Any) -> int:
    n, stack = 0, [value]
    while stack:
        v = stack.pop()
        n += 1
        if n > MAX_NODES:
            return n
        if isinstance(v, dict):
            stack.extend(v.values())
        elif isinstance(v, list):
            stack.extend(v)
    return n


def parse_snapshot(raw: Any) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Check an untrusted snapshot file and return (answers, meta). Refuses
    (SnapshotInvalid, in words) a file that is too large, not UTF-8 JSON,
    nested too deeply, too big, of another format or version, with an
    unknown field, or with an answer under a path that is not an API path.
    Secret-named fields are scrubbed again. Nothing in the file names a
    file, a folder, an id or a credential the app uses."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if not isinstance(raw, (bytes, bytearray)):
        raise SnapshotInvalid("The snapshot is not a file.")
    if len(raw) > MAX_SNAPSHOT_BYTES:
        raise SnapshotInvalid(f"The snapshot is larger than {MAX_SNAPSHOT_BYTES // (1024 * 1024)} MB; it was not opened.")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise SnapshotInvalid("The snapshot is not a UTF-8 text file; it was not opened.")
    if _nesting(text) > MAX_DEPTH:
        raise SnapshotInvalid(f"The snapshot is nested more than {MAX_DEPTH} levels deep; it was not opened.")
    try:
        # Strict JSON (RFC 8259): NaN, Infinity and a number too large for a
        # double are refused here; opened, they would make every answer the
        # app sends from this snapshot invalid JSON.
        doc = safe_files.strict_json_loads(text)
    except (ValueError, RecursionError):
        raise SnapshotInvalid("The snapshot is not valid JSON; it was not opened.")
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise SnapshotInvalid("This file is not a Zscaler Made Easy snapshot.")
    if doc.get("version") != VERSION:
        raise SnapshotInvalid(f"This snapshot was saved in format version {str(doc.get('version'))[:10]}; this app opens version {VERSION}.")
    extra = set(doc) - {"format", "version", "meta", "responses"}
    if extra:
        raise SnapshotInvalid(f"The snapshot has fields this app does not know ({', '.join(sorted(_text(x, 40) for x in extra)[:5])}); it was not opened.")
    if _count_nodes(doc) > MAX_NODES:
        raise SnapshotInvalid("The snapshot holds too many values; it was not opened.")
    responses = doc.get("responses")
    if not isinstance(responses, dict) or not responses:
        raise SnapshotInvalid("The snapshot holds no tenant answers.")
    if len(responses) > MAX_PATHS:
        raise SnapshotInvalid(f"The snapshot holds more than {MAX_PATHS} answers; it was not opened.")
    out: Dict[str, Dict[str, Any]] = {}
    for path, entry in responses.items():
        if not valid_path(path):
            raise SnapshotInvalid(f"The snapshot has an answer under a path that is not a Zscaler API path ({_text(path, 80)!r}); it was not opened.")
        if not isinstance(entry, dict) or set(entry) - {"status", "body"} or "status" not in entry:
            raise SnapshotInvalid(f"The answer for {_text(path, 80)} is not in the snapshot format; it was not opened.")
        st = entry.get("status")
        if not isinstance(st, int) or isinstance(st, bool) or not 200 <= st <= 299:
            raise SnapshotInvalid(f"The answer for {_text(path, 80)} has an unexpected status; it was not opened.")
        out[normalize_path(path)] = {"status": st, "body": scrub(entry.get("body"))}
    return out, _clean_meta(doc.get("meta"))


def open_document(raw: Any, source_id: Optional[str] = None) -> OfflineStore:
    """Open an untrusted snapshot (parse_snapshot) as a read-only offline
    tenant. A file opened from the browser gets a fresh random id."""
    responses, meta = parse_snapshot(raw)
    # Never the sample's id: a snapshot registered as "sample" would replace it.
    sid = source_id if source_id and source_id != SAMPLE and SOURCE_RE.match(source_id) else f"file-{secrets.token_hex(8)}"
    if not meta.get("tenant_label"):
        meta["tenant_label"] = "Offline snapshot"
    meta["tenant_label"] = f"Snapshot of {meta['tenant_label']}" if not meta["tenant_label"].startswith("Snapshot of ") else meta["tenant_label"]
    return register(OfflineStore(sid, "snapshot", responses, meta, writable=False))


def open_saved(snapshot_id: str) -> OfflineStore:
    """Open a snapshot saved beside the tenant profiles (by its id only)."""
    import tenant_profiles
    try:
        raw = tenant_profiles.read_snapshot(snapshot_id, MAX_SNAPSHOT_BYTES)
    except ValueError as e:
        raise OfflineError(str(e), 404)
    return open_document(raw, snapshot_id)


# ── saving a tenant read ───────────────────────────────────────────────
# (scopes, short endpoint): read when any of the scopes is ticked; the
# channel guard (dlp_analysis.ScopedClient) also refuses a channel that is
# not on Zscaler and a service that is not ticked.
_DLP = ("dlp", "genai")
_ZIA = ("zia_extras",)
_WEB_POLICY = ("dlp", "zia_extras", "genai")
PER_OBJECT_ZDX = "/zdx/:per-application-and-alert"
PER_OBJECT_ZID = "/zid/:per-admin-and-group"
CAPTURE: Tuple[Tuple[Tuple[str, ...], str], ...] = tuple(
    [(_DLP, f"/zia/{x}") for x in ("dlpDictionaries", "dlpEngines", "dlpNotificationTemplates", "incidentReceiverServers", "icapServers",
                                   "webDlpRules", "endPointDlpRules", "emailDlpRules", "casbDlpRules/all", "casbTenant/lite")]
    + [(_WEB_POLICY, f"/zia/{x}") for x in ("urlFilteringRules", "urlCategories", "sslInspectionRules", "cloudApplicationRules",
                                            "fileTypeRules", "pacFiles")]
    + [(_ZIA, f"/zia/{x}") for x in ("firewallFilteringRules", "firewallDnsRules", "firewallIpsRules", "networkServices", "ipDestinationGroups",
                                     "ipSourceGroups", "locations", "advancedSettings", "authSettings", "departments", "groups", "ruleLabels",
                                     "nssFeeds", "browserIsolation/profiles", "sandboxRules", "bandwidthClasses", "bandwidthControlRules",
                                     "tenancyRestrictionProfile", "cyberThreatProtection/advancedThreatSettings",
                                     "cyberThreatProtection/malwareSettings",
                                     # governance and audit (zscaler_full_checks GOV.*)
                                     "configAudit", "alertSubscriptions", "nssServers", "nssCollectors", "subscriptions",
                                     # threat protection and SaaS Security hygiene (zscaler_full_checks THR / UF / SAAS);
                                     # the SaaS Security ones pass the channel guard only when SaaS Security is on Zscaler
                                     "behavioralAnalysisAdvancedSettings", "behavioralAnalysisAdvancedSettings/fileHashCount",
                                     "ipsSignatureRules", "mobileAdvanceThreatSettings", "ftpSettings", "eun",
                                     "alertRuleConfiguration/uebaRules", "alertDefinitions", "customFileTypes", "riskProfiles/lite",
                                     "adaptiveAccessProfiles", "advancedUrlFilterAndCloudAppSettings", "browserControlSettings",
                                     "casbMalwareRules/all", "quarantineTombstoneTemplate/lite", "casbTenant/scanInfo",
                                     "cloudToCloudIR/lite")]
    # Forwarding and traffic path (zia_forwarding; the FWD.* checks and the
    # Path analyzer's Forwarding control step).
    + [(_ZIA, f"/zia/{x}") for x in ("forwardingRules", "proxyGateways", "zpaGateways", "datacenters", "dcExclusions", "greTunnels", "vips",
                                     "ipv6config", "ipv6config/nat64prefix", "dedicatedIPGateways/lite", "dnatRules", "virtualZenClusters",
                                     "virtualZenNodes", "dnsGateways")]
    + [(("zia_extras", "rbac"), f"/zia/{x}") for x in ("adminRoles", "adminUsers")]
    + [(("rbac",), f"/zia/{x}") for x in ("passwordExpiry/settings", "remoteAssistance")]
    + [(("zcc",), f"/zcc/{x}") for x in ("forwardingProfiles", "trustedNetworks", "devices", "failOpenPolicy", "companyInfo", "pacFiles",
                                         "webAppService", "appBypass", "zpaEntitlements", "zdxEntitlements", "deviceGroups",
                                         "customIpBasedApps", "predefinedIpBasedApps", "process-based-apps", "custom-ip-based-apps")]
    + [(("zpa",), f"/zpa/{x}") for x in ("application", "segmentGroup", "serverGroup", "appConnectorGroup", "connector", "serviceEdgeGroup",
                                         "serviceEdge", "idp", "samlAttribute", "postureProfile", "trustedNetwork", "machineGroup",
                                         "policySet/rules/ACCESS_POLICY", "policySet/rules/TIMEOUT_POLICY",
                                         "policySet/rules/policyType/CLIENT_FORWARDING_POLICY", "policySet/rules/policyType/INSPECTION_POLICY",
                                         "policySet/rules/policyType/ISOLATION_POLICY",
                                         # ZPA policy completeness: the other policy types, AppProtection and the
                                         # infrastructure behind the ZPA diagnostics (zpa_reader.COLLECTIONS).
                                         "policySet/rules/policyType/REDIRECTION_POLICY", "policySet/rules/policyType/CREDENTIAL_POLICY",
                                         "policySet/rules/policyType/CAPABILITIES_POLICY",
                                         "policySet/rules/policyType/CLIENTLESS_SESSION_PROTECTION_POLICY",
                                         "inspectionProfile", "inspectionControls/custom", "server", "businessContinuitySettings",
                                         "privateCloud", "privateCloudControllerGroup", "privateCloudController",
                                         "branchConnectorGroup", "branchConnector", "cloudConnectorGroup", "cloudConnector")]
    # ZPA administration, for the RBAC checks: read only with RBAC ticked (and
    # ZPA, which the service guard requires). Saved scrubbed: no password,
    # client secret, token or provisioning-key value is ever in the file.
    + [(("rbac",), f"/zpa/{x}") for x in ("administrators", "roles", "ssoLoginOptions", "apiKeys", "emergencyAccess/users", "microtenants",
                                          "associationType/CONNECTOR_GRP/provisioningKey", "associationType/SERVICE_EDGE_GRP/provisioningKey",
                                          "credential", "credential-pool", "approval")]
    + [(("zdx",), f"/zdx/{x}") for x in ("administration/apps", "troubleshooting/devices", "administration/departments",
                                         "administration/locations")]
    + [(("zidentity",), f"/zid/{x}") for x in ("users", "groups", "resourceServers")]
    # What the builders (Build new, the POV build) plan against, so a snapshot can rehearse them offline:
    # the ZIA catalogues and certificates, proxy chaining, ZPA's enrollment certificates, keys and
    # inspection catalogue, the ZDX configuration (assumed API, ops_zdx) and AI Guard's lists.
    + [(_ZIA, f"/zia/{x}") for x in ("urlCategories/lite", "networkApplications", "cloudApplications/policy", "dnsGateways",
                                     "intermediateCaCertificate/readyToUse", "rootCertificates", "proxies", "proxyGateways",
                                     "forwardingRules", "advancedUrlFilterAndCloudAppSettings", "subscriptions")]
    + [(("zpa",), f"/zpa/{x}") for x in ("enrollmentCert", "associationType/CONNECTOR_GRP/provisioningKey", "inspectionProfile",
                                         "inspectionControls/predefined", "inspectionControls/predefined/versions", "praConsole",
                                         "praPortal", "clientlessCertificate/issued", "isolation/profiles")]
    + [(("zdx",), f"raw:/zdx/v1/config/{x}") for x in ("applications", "applications/supported", "monitors", "collections")]
    + [(("aiguard",), f"raw:/aiguard/v1/{x}") for x in ("detections/policies", "detections/policy-match-rules", "llm-providers")]
    # ZIA Insights: the licences (the Insights checks' N/A) and the cloud application
    # list (the sanction change); the Insights answers themselves are POSTs, kept by
    # insights.capture under /zins/graphql/<operation>.
    + [(("insights",), "/zia/subscriptions"), (("insights",), "/zia/cloudApplications/lite")]
    # Cloud & Branch Connector: ztw_overview.PATHS (the SDK's paths, read as they are)
    + [(("ztw",), f"/ztw/api/v1/{x}") for x in ("ecgroup", "ecRules/ecRdr", "workloadGroups", "ipSourceGroups", "ipDestinationGroups",
                                                 "gateways", "location", "locationTemplate", "ecAdminActivateStatus", "adminRoles",
                                                 "adminUsers", "apiKeys", "publicCloudAccountDetails", "publicCloudInfo")]
    + [(_DLP, f"/zia/{x}") for x in ("dlpExactDataMatchSchemas", "idmprofile")]
    # AI Guard (zscaler/aiguard: list_policies, list_rules, list_providers, list_applications, list_credentials)
    + [(("aiguard",), f"/aiguard/v1/{x}") for x in ("detections/policies", "detections/policy-match-rules", "llm-providers",
                                                     "llm-applications", "llm-application-credentials")]
    # Workflow Automation: read through ZWA_CAPTURE (a POST search, then each incident's GETs), DLP ticked and
    # Workflow Automation marked Zscaler on the Scope page.
    + [(_DLP, "/zwa/incidents")]
    # Reads per object (2026-10-31): the ZDX alert history and per-alert affected devices
    # (ids only), each application's week of score and metrics, every admin's
    # entitlements and every group's member ids. See _capture_per_object.
    + [(("zdx",), "/zdx/alerts/historical"), (("zdx",), PER_OBJECT_ZDX), (("zidentity",), PER_OBJECT_ZID)]
)
# Read as one answer, not page by page (a list of strings, a list of groups, a settings object).
_UNPAGED = {"/zpa/inspectionControls/predefined", "/zpa/inspectionControls/predefined/versions"}
_PARAMS = {"raw:/zdx/v1/config/applications/supported": {"type": "PREDEFINED"},
           "/zia/rootCertificates": {"certTypes": "PROXY_CHAINING"}}   # ai_guard.CERT_TYPE: the certificates proxy chaining uses
_ZIA_PAGED = {"/zia/users", "/zia/groups", "/zia/departments", "/zia/cloudApplications/policy"}
# ZPA reads that are one answer, not a paged list: a settings object, and the
# emergency access list, which pages by page id (zpa/emergency_access.py).
_ZPA_SINGLE = {"/zpa/ssoLoginOptions", "/zpa/emergencyAccess/users"}
ZWA_CAPTURE_DAYS = 30
ZWA_CAPTURE_INCIDENTS = 25                # incidents whose triggers, history and tickets are saved (metadata only; never evidence)
_UNANSWERED = (0, 429, 502, 503, 504)


def capture_plan(scopes: Iterable[str]) -> List[str]:
    """The short endpoints a snapshot reads for the ticked `scopes`."""
    sc = set(scopes or [])
    out = [ep for tags, ep in CAPTURE if sc & set(tags)]
    if "zcc" in sc:
        out.append("/zcc/webPolicies")
    # The other products (other_products.py): one marker each, read by
    # other_products.snapshot_answers with the SDK's own requests.
    import other_products
    out.extend(f"other:{k}" for k in other_products.SCOPE_KEYS if k in sc)
    # An endpoint two parts need (the ZPA builders' catalogue and the RBAC
    # checks, say) is read once.
    return list(dict.fromkeys(out))


def _paths_for(ep: str) -> List[str]:
    from dlp_assessment_full_auto import _resolve_candidates
    return [normalize_path(p) for p in _resolve_candidates(ep, CUSTOMER_ID, False) if p]


def capture(client: Any, scopes: Iterable[str], channels: Any, log: Callable[[str], None], cancel: Any = None) -> Dict[str, Any]:
    """Read the tenant for a snapshot: only the endpoints of the ticked
    scopes, through the Scope page's channel guard. Returns {responses,
    counts, unread, stopped}. Read-only (GET only)."""
    import dlp_analysis
    scopes = [s for s in (scopes or []) if s in KNOWN_SCOPES]
    guard = dlp_analysis.ScopedClient(client, channels or {}, scopes)
    responses: Dict[str, Dict[str, Any]] = {}
    unread: List[str] = []
    counts = {"answers": 0, "objects": 0, "not_read": 0, "out_of_scope": 0}

    def stopped() -> bool:
        return bool(cancel is not None and getattr(cancel, "is_set", lambda: False)())

    def keep(ep: str, body: Any) -> None:
        for p in _paths_for(ep):
            responses[p] = {"status": 200, "body": body}
        items = _items(body)
        counts["objects"] += len(items) if items is not None else 1

    plan = capture_plan(scopes)
    log(f"Saving a snapshot: {len(plan)} lists to read, only what is in scope on the Scope page.")
    for ep in plan:
        if stopped():
            log("Stopped: nothing more is read, and no snapshot is saved.")
            return {"responses": responses, "counts": counts, "unread": unread, "stopped": True}
        if ep.startswith("other:"):
            import other_products
            got, miss = other_products.snapshot_answers(guard, ep[6:], other_products.ids_for(client), cancel)
            for path, body in got.items():
                responses[normalize_path(path)] = {"status": 200, "body": scrub(body)}
                items = _items(body)
                counts["objects"] += len(items) if items is not None else 1
            counts["answers"] += len(got)
            counts["not_read"] += len(miss)
            unread.extend(_text(m, 160) for m in miss[:8])
        if ep == "/zwa/incidents":
            got = _capture_zwa(client, guard, responses, log, stopped)
            if got is None:
                counts["out_of_scope"] += 1
            else:
                counts["answers"] += got[0]
                counts["objects"] += got[1]
                unread.extend(got[2][:4])
            continue
        if ep == "/zcc/webPolicies":
            import zcc_profiles
            items, errors, _st = zcc_profiles.read_app_profiles(guard.get)
            if items or not errors:
                keep(ep, items)
                counts["answers"] += 1
            for e in errors[:4]:
                unread.append(_text(e, 160))
            continue
        if ep in (PER_OBJECT_ZDX, PER_OBJECT_ZID):
            _capture_per_object(guard, ep, keep, counts, unread, stopped)
            continue
        if ep == "/zdx/alerts/historical":
            import zscaler_zdx_checks
            body, code = guard.get(ep, zscaler_zdx_checks.window(336))
        elif ep in _PARAMS or ep in _UNPAGED or ep in _ZPA_SINGLE:
            body, code = guard.get(ep, dict(_PARAMS[ep])) if ep in _PARAMS else guard.get(ep)
        elif ep.startswith("/zpa/"):
            body, code = _read_zpa(guard, ep)
        elif ep in _ZIA_PAGED:
            body, code = _read_zia_pages(guard, ep)
        elif ep.startswith("/zdx/"):
            body, code = guard.get(ep, {"since": 24})
        else:
            body, code = guard.get(ep)
        if ep == "/zia/cloudApplicationRules" and code in (200, 204):
            from dlp_assessment_full_auto import _CAC_TYPES
            rows = body if isinstance(body, list) else []
            for t in _CAC_TYPES:
                responses[normalize_path(f"/zia/api/v1/webApplicationRules/{t}")] = {"status": 200, "body": [r for r in rows if isinstance(r, dict) and r.get("type") == t]}
            counts["answers"] += 1
            counts["objects"] += len(rows)
            continue
        if code in (200, 204):
            keep(ep, body if code == 200 else [])
            counts["answers"] += 1
        elif code == 0 and isinstance(body, dict) and body.get("error") in ("not in scope", "required evidence unavailable"):
            counts["out_of_scope"] += 1
        else:
            counts["not_read"] += 1
            unread.append(f"{ep}: HTTP {code}")
            if code in _UNANSWERED:
                log(f"Saving a snapshot: {ep} was not answered (HTTP {code}).")
    if "insights" in scopes and not stopped():
        import insights
        kept = insights.capture(guard, log, cancel)
        responses.update(kept)
        counts["answers"] += len(kept)
        counts["objects"] += len(kept)
        if stopped():
            log("Stopped: nothing more is read, and no snapshot is saved.")
            return {"responses": responses, "counts": counts, "unread": unread, "stopped": True}
    log(f"Saving a snapshot: read {counts['answers']} lists ({counts['objects']} objects); {counts['not_read']} could not be read.")
    return {"responses": responses, "counts": counts, "unread": unread, "stopped": False}


# ZPA lists read in one call: the SDK's list method takes no paging parameters.
# (Not _ZPA_SINGLE above: those are kept as answered, not turned into a list.)
_ZPA_ONE_CALL = {"/zpa/businessContinuitySettings"}


# What a snapshot keeps of an incident: its metadata. The user, the file name,
# the client IP, the metadata file link, note text and ticket links are
# personal or point at content: never saved (counted where it matters).
_ZWA_KEEP = ("id", "internalId", "transactionId", "integrationType", "sourceType", "sourceSubType", "sourceActions", "severity", "priority",
             "matchCount", "createdAt", "lastUpdatedAt", "sourceFirstObservedAt", "sourceLastObservedAt", "status", "resolution", "closedCode",
             "assignedAdmin", "labels", "matchingPolicies", "incidentGroupIds")


def _zwa_minimal(r: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: r[k] for k in _ZWA_KEEP if k in r}
    out.setdefault("id", r.get("internalId"))
    app = r.get("applicationInfo") if isinstance(r.get("applicationInfo"), dict) else {}
    out["applicationInfo"] = {k: app[k] for k in ("url", "name", "hostnameOrApplication", "category") if k in app}
    content = r.get("contentInfo") if isinstance(r.get("contentInfo"), dict) else {}
    out["contentInfo"] = {k: content[k] for k in ("fileType",) if k in content}
    user = r.get("userInfo") if isinstance(r.get("userInfo"), dict) else {}
    out["userInfo"] = {k: user[k] for k in ("department",) if k in user}
    out["notes"] = [{} for _ in (r.get("notes") or [])][:50]
    out["dlpIncidentTickets"] = [dict({k: t[k] for k in ("ticketType", "ticketingSystemName", "projectName") if k in t},
                                      ticketInfo={k: v for k, v in (t.get("ticketInfo") or {}).items() if k in ("ticketId", "state")})
                                 for t in (r.get("dlpIncidentTickets") or []) if isinstance(t, dict)][:20]
    return out


def _zwa_part(part: str, body: Any) -> Any:
    """An incident's triggers, history or tickets as a snapshot keeps them:
    names with counts, masked history lines, tickets without links."""
    import zwa_incidents as zi
    if part == "triggers":
        return {"matches": [{"name": t["name"], "matchCount": t["matches"]} for t in zi.summarize_triggers(body)]}
    if part == "change-history":
        return {"changeHistory": zi.summarize_history(body)}
    return {"tickets": [{"ticketingSystemName": t["system"], "projectName": t["project"], "ticketInfo": {"ticketId": t["ticket"], "state": t["state"]}}
                        for t in zi.summarize_tickets(body)]}


def _capture_zwa(client: Any, guard: Any, responses: Dict[str, Dict[str, Any]], log: Callable[[str], None],
                 stopped: Callable[[], bool]) -> Optional[Tuple[int, int, List[str]]]:
    """Workflow Automation for a snapshot: the incident list of the last
    ZWA_CAPTURE_DAYS, the triggers, change history and tickets of the newest
    ZWA_CAPTURE_INCIDENTS, and a week of the audit log. None when Workflow
    Automation is not marked Zscaler (nothing is read). Read-only: the two
    searches are POSTs that change nothing; the evidence is never read."""
    import channel_scope
    if not channel_scope.group_in_scope(("workflow_automation",), getattr(guard, "_scope", {}) or {}):
        return None
    post = getattr(guard, "post_read", None)
    if not callable(post):
        return 0, 0, ["Workflow Automation: this client cannot read the incident search."]
    from datetime import datetime, timedelta, timezone
    end = datetime.now(timezone.utc)
    tr = {"startTime": (end - timedelta(days=ZWA_CAPTURE_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "endTime": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    body, code = post(f"{ZWA_BASE}/incidents/search?page=1&pageSize=100", {"fields": [], "timeRange": tr})
    if code not in (200, 204):
        return 0, 0, [f"Workflow Automation incidents: HTTP {code}"]
    rows: List[Dict[str, Any]] = []
    for group in (body or {}).get("incidents") or [] if isinstance(body, dict) else []:
        inner = group.get("incidents") if isinstance(group, dict) else None
        rows.extend(x for x in (inner if isinstance(inner, list) else [group]) if isinstance(x, dict))
    rows = [_zwa_minimal(r) for r in rows]
    responses[f"{ZWA_BASE}/incidents"] = {"status": 200, "body": rows}
    answers, objects, unread = 1, len(rows), []
    for r in rows[:ZWA_CAPTURE_INCIDENTS]:
        iid = str(r.get("id") or "")
        if stopped() or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}", iid):
            continue
        for part in ("triggers", "change-history", "tickets"):
            b, c = guard.get(f"{ZWA_BASE}/incidents/{iid}/{part}")
            if c in (200, 204):
                responses[f"{ZWA_BASE}/incidents/{iid}/{part}"] = {"status": 200, "body": _zwa_part(part, b if c == 200 else {})}
                answers += 1
    body, code = post(f"{ZWA_BASE}/customer/audit?page=1&pageSize=100",
                      {"fields": [], "timeRange": {"startTime": (end - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S.000Z"), "endTime": tr["endTime"]}})
    if code in (200, 204):
        responses[f"{ZWA_BASE}/customer/audit"] = {"status": 200, "body": body if code == 200 else {"logs": []}}
        answers += 1
    else:
        unread.append(f"Workflow Automation audit log: HTTP {code}")
    log(f"Saving a snapshot: {len(rows)} Workflow Automation incident(s), metadata only.")
    return answers, objects, unread


MAX_PER_OBJECT = 50   # objects read one by one per list (applications, alerts, admins, groups)


def _capture_per_object(guard: Any, ep: str, keep: Callable[[str, Any], None], counts: Dict[str, int], unread: List[str],
                        stopped: Callable[[], bool]) -> None:
    """The reads a snapshot makes per object, so the ZDX score, metrics and
    alert checks and the ZIdentity entitlement checks and group picker work
    offline. Personal data is not kept: affected devices and group members
    are stored as ids only."""
    import zscaler_zdx_checks as zx

    def one(path: str, params: Any = None, shape: Optional[Callable[[Any], Any]] = None) -> None:
        if stopped():
            return
        body, code = guard.get(path, params) if params is not None else guard.get(path)
        if code in (200, 204):
            keep(path, shape(body) if shape else body)
            counts["answers"] += 1
        else:
            counts["not_read"] += 1
            unread.append(f"{path}: HTTP {code}")

    def ids_only(key: str) -> Callable[[Any], Any]:
        def f(body: Any) -> Any:
            rows = _items(body) or []
            return {key: [{"id": x.get("id")} for x in rows if isinstance(x, dict) and x.get("id") not in (None, "")], "next_offset": None}
        return f

    def ok_id(v: Any) -> bool:
        t = str(v or "")
        return bool(t) and len(t) <= 64 and bool(re.fullmatch(r"[A-Za-z0-9_.\-]+", t))

    if ep == PER_OBJECT_ZDX:
        apps, code = guard.get("/zdx/administration/apps", zx.window(168))
        for a in ([x for x in _items(apps) or [] if isinstance(x, dict)] if code in (200, 204) else [])[:MAX_PER_OBJECT]:
            if ok_id(a.get("id")):
                one(f"/zdx/apps/{a['id']}/score", zx.window(168))
                one(f"/zdx/apps/{a['id']}/metrics", zx.window(168))
        hist, code = guard.get("/zdx/alerts/historical", zx.window(336))
        for al in ([x for x in _items(hist) or [] if isinstance(x, dict)] if code in (200, 204) else [])[:MAX_PER_OBJECT]:
            if ok_id(al.get("id")):
                one(f"/zdx/alerts/{al['id']}/affected_devices", zx.window(336), ids_only("devices"))
        return
    users, code = guard.get("/zid/users")
    for u in ([x for x in _items(users) or [] if isinstance(x, dict)] if code in (200, 204) else []):
        if u.get("adminEntitlementEnabled") is True and ok_id(u.get("id")):
            one(f"/zid/users/{u['id']}/admin-entitlements")
    groups, code = guard.get("/zid/groups")
    for g in ([x for x in _items(groups) or [] if isinstance(x, dict)] if code in (200, 204) else [])[:MAX_PER_OBJECT]:
        if ok_id(g.get("id")):
            one(f"/zid/groups/{g['id']}/users", None, lambda b: {"records": [{"id": x.get("id")} for x in (_items(b) or [])
                                                                          if isinstance(x, dict) and x.get("id") not in (None, "")]})


def _read_zpa(guard: Any, ep: str) -> Tuple[Any, int]:
    if ep in _ZPA_ONE_CALL:
        body, code = guard.get(ep)
        if code not in (200, 204):
            return body, code
        rows = _items(body) or []
        return {"list": rows, "totalPages": "1", "totalCount": str(len(rows))}, 200
    rows: List[Any] = []
    for page in range(1, MAX_LIST_PAGES + 1):
        body, code = guard.get(ep, {"page": page, "pagesize": 500})
        if code not in (200, 204):
            return (body, code) if page == 1 else ({"list": rows, "totalPages": "1", "totalCount": str(len(rows))}, 200)
        items = _items(body) or []
        rows.extend(items)
        try:
            total = int((body or {}).get("totalPages") or 1) if isinstance(body, dict) else 1
        except (TypeError, ValueError):
            total = 1
        if page >= total or not items:
            break
    return {"list": rows, "totalPages": "1", "totalCount": str(len(rows))}, 200


def _read_zia_pages(guard: Any, ep: str, size: int = 1000) -> Tuple[Any, int]:
    rows: List[Any] = []
    for page in range(1, MAX_LIST_PAGES + 1):
        body, code = guard.get(ep, {"page": page, "pageSize": size})
        if code not in (200, 204):
            return (body, code) if page == 1 else (rows, 200)
        items = body if isinstance(body, list) else []
        rows.extend(items)
        if len(items) < size:
            break
    return rows, 200


# ── comparing a snapshot with the live tenant ──────────────────────────

_NAMES = {"webDlpRules": "Inline Web DLP rules", "endPointDlpRules": "Endpoint DLP rules", "emailDlpRules": "Email DLP rules",
          "casbDlpRules/all": "SaaS DLP rules", "casbDlpRules": "SaaS DLP rules", "dlpDictionaries": "DLP dictionaries",
          "dlpEngines": "DLP engines", "urlFilteringRules": "URL filtering rules", "sslInspectionRules": "SSL inspection rules",
          "firewallFilteringRules": "Cloud Firewall rules", "fileTypeRules": "File Type Control rules", "urlCategories": "URL categories",
          "application": "ZPA application segments", "policyType/ACCESS_POLICY": "ZPA access policy", "connector": "App Connectors",
          "webForwardingProfile/listByCompany": "Client Connector forwarding profiles", "application-profiles": "Client Connector app profiles",
          "apps": "ZDX applications", "locations": "Locations", "pacFiles": "PAC files",
          "administrators": "ZPA administrators", "roles": "ZPA roles", "ssoLoginOptions": "ZPA admin SSO login options",
          "apiKeys": "ZPA API keys", "emergencyAccess/users": "ZPA emergency access accounts", "microtenants": "ZPA microtenants",
          "CONNECTOR_GRP/provisioningKey": "ZPA App Connector provisioning keys",
          "SERVICE_EDGE_GRP/provisioningKey": "ZPA Service Edge provisioning keys", "credential": "PRA credentials",
          "credential-pool": "PRA credential pools", "approval": "PRA approvals"}


def friendly(path: str) -> str:
    name = next((n for suffix, n in _NAMES.items() if path.endswith("/" + suffix)), None)
    if name is None and "/webApplicationRules/" in path:
        name = f"Cloud App Control rules ({path.rsplit('/', 1)[-1].replace('_', ' ').lower()})"
    if name is None:
        name = path.rsplit("/", 1)[-1]
    # ZDX has locations and departments too: never one name for two products' lists.
    if path.startswith("/zdx/") and not name.startswith("ZDX"):
        name = "ZDX " + name[:1].lower() + name[1:]
    return name


def _key(x: Any) -> str:
    if isinstance(x, dict):
        for k in ("id", "tenantId", "udid"):
            if x.get(k) not in (None, ""):
                return f"id:{x[k]}"
        return f"name:{x.get('name') or x.get('configuredName') or json.dumps(x, sort_keys=True)[:80]}"
    return f"value:{json.dumps(x, sort_keys=True)[:80]}"


def _stable(x: Any) -> Any:
    if isinstance(x, dict):
        return {k: _stable(v) for k, v in x.items() if not _VOLATILE.search(str(k))}
    if isinstance(x, list):
        return [_stable(v) for v in x]
    return x


def _name(x: Any) -> str:
    if isinstance(x, dict):
        return _text(x.get("name") or x.get("configuredName") or x.get("tenantName") or x.get("machineHostname") or _key(x), 120)
    return _text(x, 120)


def compare(old: Dict[str, Dict[str, Any]], new: Dict[str, Dict[str, Any]], limit: int = 50) -> Dict[str, Any]:
    """What changed between a snapshot's answers (`old`) and the live
    tenant's (`new`), per list: objects added, removed and changed (by id,
    else name; times of change are ignored). Lists read only on one side
    are named, never counted as emptied."""
    rows, totals = [], {"added": 0, "removed": 0, "changed": 0}
    seen_names = set()
    for path in sorted(set(old) & set(new)):
        # Both sides scrubbed first: the live answer is not, and an object with
        # no id or name is keyed and named by its own JSON (_key).
        ob, nb = scrub(old[path].get("body")), scrub(new[path].get("body"))
        oi, ni = _items(ob), _items(nb)
        if oi is None or ni is None:
            if _stable(ob) != _stable(nb):
                rows.append({"path": path, "what": friendly(path), "added": [], "removed": [], "changed": ["(settings)"],
                             "counts": {"added": 0, "removed": 0, "changed": 1}})
                totals["changed"] += 1
            continue
        om = {_key(x): x for x in oi}
        nm = {_key(x): x for x in ni}
        added = [_name(nm[k]) for k in nm if k not in om]
        removed = [_name(om[k]) for k in om if k not in nm]
        changed = [_name(nm[k]) for k in nm if k in om and _stable(nm[k]) != _stable(om[k])]
        what = friendly(path)
        # One list the API serves on two paths (casbDlpRules and casbDlpRules/all)
        # is counted once: same name, same objects. Anything else is its own row.
        seen = (what, tuple(sorted(added)), tuple(sorted(removed)), tuple(sorted(changed)))
        if (added or removed or changed) and seen not in seen_names:
            seen_names.add(seen)
            rows.append({"path": path, "what": what, "added": added[:limit], "removed": removed[:limit], "changed": changed[:limit],
                         "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)}})
            totals["added"] += len(added)
            totals["removed"] += len(removed)
            totals["changed"] += len(changed)
    only_old = sorted({friendly(p) for p in set(old) - set(new)})
    only_new = sorted({friendly(p) for p in set(new) - set(old)})
    return {"lists": rows, "totals": totals, "same": not rows, "compared": len(set(old) & set(new)),
            "only_in_snapshot": only_old[:100], "only_live": only_new[:100]}
