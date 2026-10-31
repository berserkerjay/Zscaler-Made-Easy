"""ZPA day-to-day administration on the Bulk changes engine (admin_ops.register).

Four operation types on /report/operations, under "Day-to-day admin", each
planned from the tenant as it is now, previewed item by item, approved by its
plan hash and applied through the engine's gates (write mode, a writer, the
assessor, the typed confirmation), with a re-read of every object right
before its write, a read-back, the change record, the audit log and Undo
where one exists (every preview says when there is none):

  zpa_infra_update          rename, turn on or off, move an App Connector to
                            another App Connector group, and the software
                            update schedule (day, hour, version profile) of
                            App Connector groups and Service Edge groups; turn
                            Privileged Remote Access portals and consoles and
                            user portals on or off (and rename them).
                            Undo puts every changed field back.
  zpa_infra_delete          delete App Connectors, App Connector groups,
                            Private Service Edges, Service Edge groups and
                            PRA portals and consoles, user portals, Browser
                            Access certificates, and revoke
                            provisioning keys. The typed confirmation always
                            names what goes ("DELETE <NAME>", or the count);
                            each target carries the name the operator picked
                            and is excluded if the tenant's name differs; an
                            object still connected or still used is excluded
                            and named. No Undo: a deleted object is gone.
  zpa_provisioning_key_new  a provisioning key for an App Connector group or
                            a Service Edge group, created turned off unless
                            the operator turns it on. ZPA answers the key
                            once; it goes to the same in-memory, single-use,
                            ten-minute store as the ZPA builder's key
                            (ops_zpa.stash / reveal) and is never in a plan, a
                            result, a log, the audit log or a record. Undo
                            revokes (deletes) it.
  zpa_ba_certificate        upload a Browser Access certificate with its
                            private key and point Browser Access applications
                            at it (or point them at a certificate ZPA already
                            has). The key is a secret: it reaches this app
                            once (POST /api/operations/zpa/ba-certificate),
                            is held in memory for ten minutes for the person
                            who uploaded it, sent to ZPA once and dropped; the
                            operation names it only by a token. Undo points
                            the applications back and deletes the uploaded
                            certificate.

Health (read-only, the object picker): each App Connector and Service Edge
with its control-channel status, current and expected version, update status
and last connection; each group with its members, schedule and version
profile; each certificate with its expiry; each provisioning key with its
usage, never its value.

SDK calls, verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zpa):

  app_connectors        list_connectors, get_connector, update_connector
                        (PUT /connector/{id}), delete_connector
  app_connector_groups  list_connector_groups, get_connector_group,
                        update_connector_group (PUT /appConnectorGroup/{id}),
                        delete_connector_group
  service_edges         list_service_edges, get_service_edge,
                        update_service_edge (PUT /serviceEdge/{id}),
                        delete_service_edge
  service_edge_group    list_service_edge_groups, get_service_edge_group,
                        update_service_edge_group (PUT /serviceEdgeGroup/{id};
                        service_edge_ids and trusted_network_ids become the
                        serviceEdges and trustedNetworks references)
  provisioning          list_provisioning_keys / get_provisioning_key /
                        add_provisioning_key / delete_provisioning_key with
                        key_type "connector" (CONNECTOR_GRP) or
                        "service_edge" (SERVICE_EDGE_GRP)
  enrollment_certificates.list_enrolment  ("Connector", "Service Edge")
  certificates          list_certificates (GET /certificate: Browser Access
                        certificates), get_certificate, add_certificate (POST
                        /certificate), delete_certificate
  pra_portal            list_portals, get_portal, update_portal (PUT /praPortal/{id}), delete_portal
  pra_console           list_consoles, get_console, update_console (PUT /praConsole/{id}), delete_console
  user_portal_controller list_user_portals, get_user_portal, update_user_portal (PUT /userPortal/{id}),
                        delete_user_portal
  application_segment   list_segments, get_segment, update_segment (the
                        segment as read, with its clientlessApps and the
                        application's certificateId changed)

Version profiles: default, previous_default and new_release are
versionProfileId 0, 1 and 2 with overrideVersionProfile true
(zscaler/utils.py pick_version_profile).

ASSUMED (not verifiable without a tenant; see ASSUMED below and every plan's
notes): that PUT /connector/{id} with appConnectorGroupId moves an App
Connector to that group; that ZPA keeps a group's members when its PUT sends
them back as read; that the software update hour is set in whole
hours here (upgradeTimeInSecs = hour x 3600); that a
Browser Access certificate is uploaded as certBlob holding the certificate
and its private key in PEM (the SDK's example names a `pem` field; the
Zscaler Terraform provider's zpa_ba_certificate sends cert_blob); that
revoking a key does not unenroll what already enrolled with it; and that a
connected App Connector or Service Edge should be turned off before it is
deleted (this app excludes one that is connected: a product safety rule).
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets as _secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import ops_zpa
import pack_ops as ops
import zpa_reader as zr

FAMILY = "zpa_admin"
T_UPDATE, T_DELETE, T_KEY, T_CERT = "zpa_infra_update", "zpa_infra_delete", "zpa_provisioning_key_new", "zpa_ba_certificate"
GROUP = "Day-to-day admin"
NOT_IN_SCOPE = "Not in scope: ZPA is not ticked on the Scope page, so nothing is read from ZPA or changed in it."
MAX_TARGETS = 50
MAX_DELETE = 20
MAX_ASSIGN = 20
MAX_LIST = 5000
NAME_MAX = 128
_NAME_RE = re.compile(r"^[^\x00-\x1f\x7f<>]{1,128}$")
_ID_RE = re.compile(r"^\d{1,24}$")
DAYS = ("SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY")
VERSION_PROFILES = {"default": "0", "previous_default": "1", "new_release": "2"}   # zscaler/utils.py pick_version_profile
VERSION_LABELS = {"0": "Default", "1": "Previous default", "2": "New release"}
KEY_TYPES = {"connector": ("connector_group", "Connector", "App Connector group"),
             "service_edge": ("service_edge_group", "Service Edge", "Service Edge group")}
CERT_TTL = 600.0
MAX_CERTS = 10
MAX_CERT_PEM = 64 * 1024
MAX_KEY_PEM = 16 * 1024
EXPIRY_WARN_DAYS = 30

ASSUMED = [
    "Moving an App Connector sends PUT /connector/{id} with the target group's id (appConnectorGroupId); assumed, not in the SDK's docstring.",
    "A group's PUT sends its members (connectors, Service Edges, trusted networks) back as read, so ZPA keeps them; assumed.",
    "The page offers the software update time in whole hours (upgradeTimeInSecs = hour x 3600); a time read with minutes (ZPA's "
    "default is 66600, 18:30) is shown and put back as it is; assumed.",
    "A Browser Access certificate is uploaded as certBlob: the certificate and its private key in PEM (Zscaler's Terraform provider "
    "sends cert_blob; the SDK's example names pem); assumed.",
    "Revoking a provisioning key stops new enrollments with it; what already enrolled keeps working; assumed.",
]

# kind -> label, SDK service, list / get / update / delete methods, the API path the preview names
KINDS: Dict[str, Dict[str, str]] = {
    "connector": {"label": "App Connector", "svc": "app_connectors", "list": "list_connectors", "get": "get_connector",
                  "update": "update_connector", "delete": "delete_connector", "path": "/connector"},
    "connector_group": {"label": "App Connector group", "svc": "app_connector_groups", "list": "list_connector_groups",
                        "get": "get_connector_group", "update": "update_connector_group", "delete": "delete_connector_group",
                        "path": "/appConnectorGroup"},
    "service_edge": {"label": "Private Service Edge", "svc": "service_edges", "list": "list_service_edges", "get": "get_service_edge",
                     "update": "update_service_edge", "delete": "delete_service_edge", "path": "/serviceEdge"},
    "service_edge_group": {"label": "Service Edge group", "svc": "service_edge_group", "list": "list_service_edge_groups",
                           "get": "get_service_edge_group", "update": "update_service_edge_group", "delete": "delete_service_edge_group",
                           "path": "/serviceEdgeGroup"},
    "certificate": {"label": "Browser Access certificate", "svc": "certificates", "list": "list_certificates", "get": "get_certificate",
                    "update": "", "delete": "delete_certificate", "path": "/certificate"},
    "pra_portal": {"label": "PRA portal", "svc": "pra_portal", "list": "list_portals", "get": "get_portal", "update": "update_portal",
                   "delete": "delete_portal", "path": "/praPortal"},
    "pra_console": {"label": "PRA console", "svc": "pra_console", "list": "list_consoles", "get": "get_console", "update": "update_console",
                    "delete": "delete_console", "path": "/praConsole"},
    "user_portal": {"label": "User portal", "svc": "user_portal_controller", "list": "list_user_portals", "get": "get_user_portal",
                    "update": "update_user_portal", "delete": "delete_user_portal", "path": "/userPortal"},
    "segment": {"label": "Application segment", "svc": "application_segment", "list": "list_segments", "get": "get_segment",
                "update": "update_segment", "delete": "", "path": "/application"},
}
UPDATABLE = ("connector", "connector_group", "service_edge", "service_edge_group", "pra_portal", "pra_console", "user_portal")
PORTAL_KINDS = ("pra_portal", "pra_console", "user_portal")
GROUP_KINDS = ("connector_group", "service_edge_group")
DELETABLE = ("pra_console", "pra_portal", "user_portal", "certificate", "provisioning_key", "connector", "service_edge", "connector_group",
             "service_edge_group")  # delete order: what uses an object goes before it

# Fields of the objects this app never shows or keeps: secrets, and bulky values nobody needs here.
_SECRET_KEY = re.compile(r"(?i)^(provisioning_?key|private_?key|cert_?blob|pem|password|secret|token)$")


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    """ZPA objects are read and changed only when ZPA is ticked on the Scope page."""
    return None if scope.get("zpa") else NOT_IN_SCOPE


def _scrub(row: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in row.items() if not _SECRET_KEY.match(str(k))}


# ---------------------------------------------------------------------------
# Reading (GET only; paced and Stop-able through zpa_reader's gate)
# ---------------------------------------------------------------------------

def _zpa(client: Any):
    return ops_zpa._zpa(client)


def _gate(cancel: Optional[threading.Event]) -> Any:
    return zr._Gate(cancel, zr.PACE_SECONDS)


def _lister(zpa: Any, kind: str, key_type: str = "") -> Callable[[Dict[str, Any]], Any]:
    if kind == "provisioning_key":
        return lambda q: zpa.provisioning.list_provisioning_keys(key_type, query_params=q)
    k = KINDS[kind]
    return lambda q: getattr(getattr(zpa, k["svc"]), k["list"])(query_params=q)


def list_kind(zpa: Any, kind: str, gate: Any, key_type: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of a kind, without its secret fields; (rows, error). A
    list that cannot be read completely is an error, never a partial list."""
    try:
        rows, complete = zr.list_all(_lister(zpa, kind, key_type), gate, zr.MAX_PAGES)
    except zr.Stopped:
        raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], zr._err_text(e)
    if not complete:
        return [], f"the list is longer than {zr.MAX_PAGES * zr.PAGE_SIZE:,} objects, so it could not be read completely and is not used"
    return [_scrub(r) for r in rows if isinstance(r, dict)], None


def get_one(zpa: Any, kind: str, oid: Any, key_type: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object read fresh, without its secret fields; (None, error) when it cannot be read."""
    try:
        if kind == "provisioning_key":
            ret = zpa.provisioning.get_provisioning_key(str(oid), key_type)
        else:
            k = KINDS[kind]
            ret = getattr(getattr(zpa, k["svc"]), k["get"])(str(oid))
        data, resp, err = zr._triple(ret)
        if err:
            return None, zr._err_text(err)
        if data is None:
            return None, "not found"
        raw = None
        getter = getattr(resp, "get_body", None)
        if callable(getter):
            try:
                body = getter()
                raw = body if isinstance(body, dict) else None
            except Exception:  # noqa: BLE001 — the model below
                raw = None
        row = raw if raw is not None else zr._plain(data)
        return _scrub(dict(row)), None
    except Exception as e:  # noqa: BLE001
        return None, zr._err_text(e)


_gone = ops_zpa._gone


def _name(row: Dict[str, Any]) -> str:
    return zr.as_str(zr.get(row, "name"))


def _oid(row: Dict[str, Any]) -> str:
    return zr.as_str(zr.get(row, "id"))


def _b(v: Any, default: bool = True) -> bool:
    x = zr.as_bool(v)
    return default if x is None else x


def _secs(v: Any) -> Optional[int]:
    try:
        n = int(str(v).strip())
    except (TypeError, ValueError):
        return None
    return n if 0 <= n < 86400 else None


def state(kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """The fields this app manages, as read (compared, shown and put back)."""
    g = lambda k, d=None: zr.get(row, k, d)  # noqa: E731
    out: Dict[str, Any] = {"name": _name(row), "enabled": _b(g("enabled"))}
    if kind == "connector":
        out["group_id"] = zr.as_str(g("appConnectorGroupId"))
    if kind in GROUP_KINDS:
        out.update(upgrade_day=zr.as_str(g("upgradeDay")).upper(), upgrade_time=_secs(g("upgradeTimeInSecs")),
                   version_profile_id=zr.as_str(g("versionProfileId")), override_version_profile=_b(g("overrideVersionProfile"), False))
    return out


def _show(field: str, v: Any, names: Optional[Dict[str, str]] = None) -> str:
    if v is None or v == "":
        return "(not set)"
    if field == "enabled":
        return "on" if v else "off"
    if field == "upgrade_time":
        return f"{int(v) // 3600:02d}:{(int(v) % 3600) // 60:02d}"
    if field == "version_profile_id":
        return VERSION_LABELS.get(str(v), str(v))
    if field == "override_version_profile":
        return "overridden" if v else "tenant default"
    if field == "group_id":
        return (names or {}).get(str(v)) or str(v)
    if field == "upgrade_day":
        return str(v).title()
    return str(v)


def connector_health(c: Dict[str, Any]) -> Dict[str, Any]:
    n = zr.normalize_connector(c)
    words = "turned off" if not n["enabled"] else ("connected" if n["connected"] else ("disconnected" if n["connected"] is False else "unknown"))
    behind = bool(n["current_version"] and n["expected_version"] and n["current_version"] != n["expected_version"])
    seen = n["last_connect"]
    return {"id": n["id"], "name": n["name"], "enabled": n["enabled"], "group_id": n["group_id"], "group_name": n["group_name"],
            "health": words, "connected": n["connected"], "status_raw": n["status_raw"], "current_version": n["current_version"],
            "expected_version": n["expected_version"], "update_pending": behind, "upgrade_status": n["upgrade_status"],
            "last_connect": datetime.fromtimestamp(seen, timezone.utc).isoformat(timespec="minutes") if seen else ""}


def edge_health(e: Dict[str, Any]) -> Dict[str, Any]:
    n = zr.normalize_service_edge(e)
    words = "turned off" if not n["enabled"] else ("connected" if n["connected"] else ("disconnected" if n["connected"] is False else "unknown"))
    return {"id": n["id"], "name": n["name"], "enabled": n["enabled"], "group_id": n["group_id"], "health": words, "connected": n["connected"],
            "status_raw": n["status_raw"], "current_version": n["current_version"],
            "expected_version": zr.as_str(zr.get(e, "expectedVersion")), "upgrade_status": zr.as_str(zr.get(e, "upgradeStatus"))}


def group_summary(kind: str, row: Dict[str, Any], members: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    st = state(kind, row)
    up = sum(1 for m in members if m.get("connected"))
    return {"id": _oid(row), "name": st["name"], "enabled": st["enabled"], "members": len(members), "members_connected": up,
            "upgrade_day": st["upgrade_day"], "upgrade_time": st["upgrade_time"], "upgrade_time_label": _show("upgrade_time", st["upgrade_time"]),
            "version_profile_id": st["version_profile_id"], "override_version_profile": st["override_version_profile"],
            "version_profile_label": VERSION_LABELS.get(st["version_profile_id"], "") if st["override_version_profile"] else "Tenant default",
            "location": zr.as_str(zr.get(row, "location")), "server_groups": len(zr._ref_ids(zr.get(row, "serverGroups") or []))}


def cert_summary(row: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    now = time.time() if now is None else now
    to = zr.epoch_seconds(zr.get(row, "validToInEpochSec"))
    days = int((to - now) // 86400) if to else None
    status = "unknown" if days is None else ("expired" if to <= now else (f"expires in {days} day{'' if days == 1 else 's'}"))
    return {"id": _oid(row), "name": _name(row), "cname": zr.as_str(zr.get(row, "cName")), "issued_to": zr.as_str(zr.get(row, "issuedTo")),
            "issued_by": zr.as_str(zr.get(row, "issuedBy")), "san": [zr.as_str(x) for x in zr._items(zr.get(row, "san"))][:50],
            "valid_to": datetime.fromtimestamp(to, timezone.utc).date().isoformat() if to else "", "days_left": days, "expiry": status,
            "expiring": days is not None and days <= EXPIRY_WARN_DAYS}


def key_summary(row: Dict[str, Any], key_type: str) -> Dict[str, Any]:
    return {"id": _oid(row), "name": _name(row), "key_type": key_type, "enabled": _b(zr.get(row, "enabled")),
            "group_id": zr.as_str(zr.get(row, "zcomponentId")), "group_name": zr.as_str(zr.get(row, "zcomponentName")),
            "usage": zr.as_str(zr.get(row, "usageCount")) or "0", "max_usage": zr.as_str(zr.get(row, "maxUsage"))}


def portal_summary(kind: str, row: Dict[str, Any], data: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Any]:
    """A PRA portal, PRA console or user portal as the page lists it, with what uses it."""
    out = {"id": _oid(row), "name": _name(row), "enabled": _b(zr.get(row, "enabled")), "domain": zr.as_str(zr.get(row, "domain"))}
    if kind == "pra_console":
        app = zr.get(row, "praApplication") or {}
        out["application"] = zr.as_str(zr.get(app, "name") or zr.get(app, "domain")) if isinstance(app, dict) else ""
        out["portals"] = len(zr._ref_ids(zr.get(row, "praPortals") or []))
    else:
        why = in_use(kind, row, data)
        out["in_use"] = why or ""
    return out


def ba_apps(segments: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Every Browser Access application of the segments: segment, app id, domain, port, certificate."""
    out = []
    for s in segments:
        for a in zr._items(zr.get(s, "clientlessApps")):
            if isinstance(a, dict):
                out.append({"segment_id": _oid(s), "segment_name": _name(s), "app_id": zr.as_str(a.get("id")),
                            "domain": zr.as_str(a.get("domain")).lower(), "port": zr.as_str(a.get("applicationPort")),
                            "certificate_id": zr.as_str(zr.get(a, "certificateId")), "certificate_name": zr.as_str(zr.get(a, "certificateName"))})
    return out


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """Read-only: App Connectors and groups, Service Edges and groups with
    their health, provisioning keys (never their value), Browser Access
    certificates with their expiry, and the Browser Access applications."""
    zpa = _zpa(client)
    gate = _gate(cancel)
    data: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    reads = [("connector", "", "App Connectors"), ("connector_group", "", "App Connector groups"), ("service_edge", "", "Private Service Edges"),
             ("service_edge_group", "", "Service Edge groups"), ("provisioning_key", "connector", "App Connector provisioning keys"),
             ("provisioning_key", "service_edge", "Service Edge provisioning keys"), ("certificate", "", "Browser Access certificates"),
             ("segment", "", "application segments"), ("pra_portal", "", "PRA portals"), ("pra_console", "", "PRA consoles"),
             ("user_portal", "", "user portals")]
    for kind, kt, label in reads:
        say(f"Reading ZPA {label}…")
        rows, err = list_kind(zpa, kind, gate, kt)
        data[f"{kind}:{kt}"] = rows
        if err:
            errors[label] = err
    conns = [connector_health(c) for c in data["connector:"]]
    edges = [edge_health(e) for e in data["service_edge:"]]
    cgs = [group_summary("connector_group", g, [c for c in conns if c["group_id"] == _oid(g)]) for g in data["connector_group:"]]
    for g, row in zip(cgs, data["connector_group:"]):
        if not g["members"]:   # a list of connectors without their group id: count the group's own embedded list
            emb = zr._ref_ids(zr.get(row, "connectors") or [])
            g["members"] = len(emb)
    names = {g["id"]: g["name"] for g in cgs}
    for c in conns:
        c["group_name"] = c["group_name"] or names.get(c["group_id"], "")
    sgs = []
    for g in data["service_edge_group:"]:
        mine = [e for e in edges if e["group_id"] == _oid(g)]
        if not mine:
            mine = [{"connected": x.get("connected")} for x in zr.normalize_service_edge_group(g)["service_edges"]]
        sgs.append(group_summary("service_edge_group", g, mine))
    certs = [cert_summary(c) for c in data["certificate:"]]
    apps = ba_apps(data["segment:"])
    used = {}
    for a in apps:
        used.setdefault(a["certificate_id"], []).append(f"{a['segment_name']} ({a['domain']})")
    for c in certs:
        c["used_by"] = used.get(c["id"], [])[:20]
    keys = [key_summary(k, "connector") for k in data["provisioning_key:connector"]] + \
           [key_summary(k, "service_edge") for k in data["provisioning_key:service_edge"]]
    portals = [portal_summary("pra_portal", r, data) for r in data["pra_portal:"]]
    consoles = [portal_summary("pra_console", r, data) for r in data["pra_console:"]]
    uportals = [portal_summary("user_portal", r, data) for r in data["user_portal:"]]
    say(f"{len(conns)} App Connectors, {len(edges)} Service Edges, {len(certs)} certificates, {len(keys)} provisioning keys, "
        f"{len(portals)} PRA portals, {len(consoles)} PRA consoles, {len(uportals)} user portals.")
    return {"connectors": conns[:MAX_LIST], "connector_groups": cgs[:MAX_LIST], "service_edges": edges[:MAX_LIST],
            "service_edge_groups": sgs[:MAX_LIST], "certificates": certs[:MAX_LIST], "provisioning_keys": keys[:MAX_LIST],
            "ba_apps": apps[:MAX_LIST], "pra_portals": portals[:MAX_LIST], "pra_consoles": consoles[:MAX_LIST],
            "user_portals": uportals[:MAX_LIST], "days": list(DAYS), "version_profiles": [{"id": k, "label": VERSION_LABELS[v]} for k, v in VERSION_PROFILES.items()],
            "truncated": any(len(x) > MAX_LIST for x in (conns, edges, certs, keys, apps)),
            "errors": errors, "assumed": list(ASSUMED), "limits": {"targets": MAX_TARGETS, "delete": MAX_DELETE, "assign": MAX_ASSIGN}}


# ---------------------------------------------------------------------------
# Validating what the page sends
# ---------------------------------------------------------------------------

def check_id(v: Any, what: str) -> str:
    s = str(v if v is not None else "").strip()
    if isinstance(v, bool) or not _ID_RE.match(s):
        raise _err(f"{what} is not a ZPA id (digits only).")
    return s


def check_name(v: Any, what: str = "The name") -> str:
    s = re.sub(r"\s+", " ", str(v or "")).strip() if isinstance(v, (str, int)) and not isinstance(v, bool) else ""
    if not s or len(s) > NAME_MAX or not _NAME_RE.match(s):
        raise _err(f"{what} must be 1 to {NAME_MAX} characters, without control characters or < >.")
    return s


def _bool(v: Any, what: str) -> bool:
    if isinstance(v, bool):
        return v
    raise _err(f"{what} must be true or false.")


def _clean_set(kind: str, raw: Any) -> Dict[str, Any]:
    """The fields to change on one object, validated (pure)."""
    if not isinstance(raw, dict) or not raw:
        raise _err("Say what to change on each object.")
    allowed = {"name", "enabled"} | ({"group_id"} if kind == "connector" else set()) | \
              ({"upgrade_day", "upgrade_time", "upgrade_hour", "version_profile", "version_profile_id", "override_version_profile"}
               if kind in GROUP_KINDS else set())
    extra = sorted(set(raw) - allowed)
    if extra:
        raise _err(f"These cannot be changed on a {KINDS[kind]['label']} here: {', '.join(str(x)[:30] for x in extra[:5])}.")
    out: Dict[str, Any] = {}
    if "name" in raw:
        out["name"] = check_name(raw["name"], f"The {KINDS[kind]['label']}'s new name")
    if "enabled" in raw:
        out["enabled"] = _bool(raw["enabled"], "On or off")
    if "group_id" in raw:
        out["group_id"] = check_id(raw["group_id"], "The App Connector group to move to")
    if "upgrade_day" in raw:
        d = str(raw["upgrade_day"] or "").strip().upper()
        if d not in DAYS:
            raise _err("The update day must be a day of the week (SUNDAY to SATURDAY).")
        out["upgrade_day"] = d
    if "upgrade_hour" in raw:
        h = raw["upgrade_hour"]
        if isinstance(h, bool) or not isinstance(h, int) or not 0 <= h <= 23:
            raise _err("The update hour must be a whole hour from 0 to 23.")
        out["upgrade_time"] = h * 3600
    if "upgrade_time" in raw:
        t = raw["upgrade_time"]
        if isinstance(t, bool) or not isinstance(t, int) or not 0 <= t < 86400 or t % 60:
            raise _err("The update time must be whole minutes, in seconds after midnight (0 to 86340).")
        out["upgrade_time"] = t
    if "version_profile" in raw:
        vp = str(raw["version_profile"] or "").strip().lower()
        if vp not in VERSION_PROFILES:
            raise _err("The version profile must be default, previous_default or new_release.")
        out.update(version_profile_id=VERSION_PROFILES[vp], override_version_profile=True)
    if "version_profile_id" in raw:   # the form an Undo uses: the exact values read before
        vid = str(raw["version_profile_id"] if raw["version_profile_id"] is not None else "").strip()
        if vid not in ("",) + tuple(VERSION_PROFILES.values()):
            raise _err("The version profile id must be 0, 1 or 2.")
        out["version_profile_id"] = vid
    if "override_version_profile" in raw:
        out["override_version_profile"] = _bool(raw["override_version_profile"], "Override the version profile")
    if not out:
        raise _err("Say what to change on each object.")
    return out


def _targets(spec: Dict[str, Any], limit: int) -> List[Dict[str, Any]]:
    raw = spec.get("targets")
    if not isinstance(raw, list) or not raw:
        raise _err("Pick at least one object.")
    if len(raw) > limit:
        raise _err(f"At most {limit} objects in one operation.")
    if not all(isinstance(t, dict) for t in raw):
        raise _err("Each object must name its kind and id.")
    return raw


# ---------------------------------------------------------------------------
# Building a prepared operation
# ---------------------------------------------------------------------------

def _obj(kind: str, oid: str, name: str, **extra: Any) -> Dict[str, Any]:
    label = "Provisioning key" if kind == "provisioning_key" else KINDS[kind]["label"]
    return dict({"type": f"zpa_{kind}", "kind": kind, "label": label, "id": oid or None, "name": name}, **extra)


def _done(t: str, title: str, spec: Dict[str, Any], items: List[Dict[str, Any]], groups: List[Dict[str, Any]], *, warnings: Sequence[str] = (),
          blockers: Sequence[str] = (), undo: str, notes: Sequence[str] = (), **extra: Any) -> Dict[str, Any]:
    return dict({"type": t, "product": "zpa", "title": title, "spec": spec, "items": items, "groups": groups,
                 "warnings": list(dict.fromkeys(warnings)), "blockers": list(blockers), "undo_note": undo,
                 "notes": [undo] + list(notes)}, apply_note="ZPA applies each change as it is saved; there is no activation step.", **extra)


# ── zpa_infra_update ───────────────────────────────────────────────────

def plan_update(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    raw = _targets(spec, MAX_TARGETS)
    clean = []
    for t in raw:
        kind = str(t.get("kind") or "")
        if kind not in UPDATABLE:
            raise _err(f"Pick App Connectors, Service Edges, their groups, PRA portals, PRA consoles or user portals (not {kind[:30]!r}).")
        clean.append({"kind": kind, "id": check_id(t.get("id"), f"The {KINDS[kind]['label']}"), "set": _clean_set(kind, t.get("set"))})
    if len({(c["kind"], c["id"]) for c in clean}) != len(clean):
        raise _err("Each object may appear once in one operation.")
    undo = bool(spec.get("undo") is True)
    nspec = {"type": T_UPDATE, "targets": clean}
    if undo:
        nspec["undo"] = True
    zpa = _zpa(client)
    gate = _gate(cancel)
    need = sorted({c["kind"] for c in clean} | ({"connector_group"} if any("group_id" in c["set"] for c in clean) else set()))
    data: Dict[str, List[Dict[str, Any]]] = {}
    for k in need:
        say(f"Reading ZPA {KINDS[k]['label']}s…")
        rows, err = list_kind(zpa, k, gate)
        if err:
            raise _err(f"ZPA {KINDS[k]['label']}s could not be read, so nothing was planned: {err}")
        data[k] = rows
    group_names = {_oid(g): _name(g) for g in data.get("connector_group", [])}
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    for c in clean:
        kind, label = c["kind"], KINDS[c["kind"]]["label"]
        row = next((r for r in data[kind] if _oid(r) == c["id"]), None)
        gkey = f"upd:{kind}:{c['id']}"
        if row is None:
            items.append(ao._unit(f"{gkey}:missing", gkey, kind, _obj(kind, c["id"], c["id"]), "exists", False, True, status="excluded",
                                  reason=f"no {label} with this id in ZPA now; read the tenant again"))
            continue
        cur = state(kind, row)
        name = cur["name"]
        want = dict(c["set"])
        if "group_id" in want and want["group_id"] not in group_names:
            items.append(ao._unit(f"{gkey}:group_id", gkey, kind, _obj(kind, c["id"], name), "group_id", _show("group_id", cur["group_id"], group_names),
                                  want["group_id"], status="excluded", reason="the App Connector group to move to is not in ZPA now"))
            want.pop("group_id")
        if "name" in want and want["name"] != name and any(_name(r) == want["name"] for r in data[kind]):
            items.append(ao._unit(f"{gkey}:name", gkey, kind, _obj(kind, c["id"], name), "name", name, want["name"], status="excluded",
                                  reason=f"another {label} is already named '{want['name']}'"))
            want.pop("name")
        changed = {}
        for f, v in want.items():
            before = cur.get(f)
            if before == v:
                items.append(ao._unit(f"{gkey}:{f}", gkey, kind, _obj(kind, c["id"], name), f, _show(f, before, group_names), _show(f, v, group_names),
                                      status="noop", reason="already as asked"))
            else:
                changed[f] = v
                items.append(ao._unit(f"{gkey}:{f}", gkey, kind, _obj(kind, c["id"], name), f, _show(f, before, group_names), _show(f, v, group_names),
                                      reason=f"Updates it in place: PUT {KINDS[kind]['path']}/{{id}}."))
        if changed:
            groups.append({"key": gkey, "handler": "zpa_adm_update", "target": {"kind": kind, "id": c["id"], "name": name, "desired": changed,
                                                                               "before": {f: cur.get(f) for f in changed}}})
            if changed.get("enabled") is False and kind in ("connector", "service_edge"):
                warnings.append(f"Turning off {label} '{name}' moves its users' traffic to the other members of its group; a group with no other "
                                "connected member stops serving its applications.")
            if changed.get("enabled") is False and kind in GROUP_KINDS:
                warnings.append(f"Turning off {label} '{name}' stops every member from serving: check the applications it serves first.")
            if changed.get("enabled") is False and kind in PORTAL_KINDS:
                warnings.append(f"Turning off {label} '{name}' takes it away from its users until it is turned on again.")
            if "group_id" in changed:
                warnings.append(f"Moving App Connector '{name}' changes which applications it serves (those of its new group's server groups).")
    return _done(T_UPDATE, ("Undo: put back " if undo else "Change ") + f"{len(clean)} ZPA object{'' if len(clean) == 1 else 's'}", nspec, items, groups,
                 warnings=warnings, undo="Undo: puts every changed field back as it was read before this change (previewed first).",
                 notes=[a for a in ASSUMED[:3]])


def _update_payload(kind: str, fresh: Dict[str, Any], want: Dict[str, Any]) -> Dict[str, Any]:
    """The object as read with the managed fields set to `want` (ZPA's PUT
    replaces the object, so what is not managed goes back as read)."""
    g = lambda k, d=None: zr.get(fresh, k, d)  # noqa: E731
    cur = state(kind, fresh)
    w = dict(cur, **want)
    if kind in ("connector", "service_edge"):
        body = {"name": w["name"], "description": zr.as_str(g("description")), "enabled": w["enabled"]}
        if kind == "connector" and "group_id" in want:
            body["app_connector_group_id"] = want["group_id"]   # ASSUMED: PUT /connector/{id} moves it
        mt = zr.as_str(g("microtenantId"))
        if mt:
            body["microtenant_id"] = mt
        return body
    if kind == "pra_console":
        body = ops_zpa.update_payload("pra_console", fresh, {"enabled": w["enabled"]})
        body["name"] = w["name"]
        mt = zr.as_str(g("microtenantId"))
        if mt:
            body["microtenant_id"] = mt
        return body
    if kind in ("pra_portal", "user_portal"):
        fields = ("name", "description", "enabled", "domain", "certificate_id", "user_notification", "user_notification_enabled",
                  "ext_domain", "ext_domain_name", "ext_domain_translation", "ext_label", "user_portal_gid", "microtenant_id")
        body = {k: g(ops_zpa._camel(k)) for k in fields if g(ops_zpa._camel(k)) not in (None, "")}
        body.update(name=w["name"], enabled=w["enabled"])
        return body
    if kind == "connector_group":
        body = {k: g(ops_zpa._camel(k)) for k in ops_zpa._CG_FIELDS if g(ops_zpa._camel(k)) not in (None, "")}
        members = zr._ref_ids(g("connectors") or [])
        if members:
            body["connectors"] = [{"id": i} for i in members]   # ASSUMED: sent back as read, so they stay
    else:
        fields = ("name", "description", "enabled", "location", "latitude", "longitude", "city_country", "country_code", "upgrade_day",
                  "upgrade_time_in_secs", "version_profile_id", "override_version_profile", "is_public", "enrollment_cert_id",
                  "grace_distance_enabled", "grace_distance_value", "grace_distance_value_unit", "use_in_dr_mode", "microtenant_id")
        body = {k: g(ops_zpa._camel(k)) for k in fields if g(ops_zpa._camel(k)) not in (None, "")}
        body["service_edge_ids"] = zr._ref_ids(g("serviceEdges") or [])
        body["trusted_network_ids"] = zr._ref_ids(g("trustedNetworks") or [])
    body.update(name=w["name"], enabled=w["enabled"])
    if "upgrade_day" in want:
        body["upgrade_day"] = want["upgrade_day"]
    if "upgrade_time" in want:
        body["upgrade_time_in_secs"] = str(want["upgrade_time"])
    if "version_profile_id" in want:
        if want["version_profile_id"] == "":
            body.pop("version_profile_id", None)
        else:
            body["version_profile_id"] = want["version_profile_id"]
    if "override_version_profile" in want:
        body["override_version_profile"] = want["override_version_profile"]
    return body


# ── zpa_infra_delete ───────────────────────────────────────────────────

def _key_type(t: Dict[str, Any]) -> str:
    kt = str(t.get("key_type") or "")
    if kt not in KEY_TYPES:
        raise _err("A provisioning key's type must be connector or service_edge.")
    return kt


def plan_delete(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    raw = _targets(spec, MAX_DELETE)
    clean = []
    for t in raw:
        kind = str(t.get("kind") or "")
        if kind not in DELETABLE:
            raise _err("Pick App Connectors, App Connector groups, Service Edges, Service Edge groups, PRA portals or consoles, user "
                       "portals, Browser Access certificates or provisioning keys to delete.")
        c = {"kind": kind, "id": check_id(t.get("id"), "The object to delete"), "name": check_name(t.get("name"), "The name of the object to delete")}
        if kind == "provisioning_key":
            c["key_type"] = _key_type(t)
        clean.append(c)
    if len({(c["kind"], c["id"]) for c in clean}) != len(clean):
        raise _err("Each object may appear once in one operation.")
    undo = bool(spec.get("undo") is True)
    clean.sort(key=lambda c: DELETABLE.index(c["kind"]))
    nspec = {"type": T_DELETE, "targets": clean}
    if undo:
        nspec["undo"] = True
    zpa = _zpa(client)
    gate = _gate(cancel)
    kinds = {c["kind"] for c in clean}
    need = set()
    if kinds & {"connector", "connector_group"}:
        need |= {("connector", ""), ("connector_group", "")}
    if kinds & {"service_edge", "service_edge_group"}:
        need |= {("service_edge", ""), ("service_edge_group", "")}
    if "certificate" in kinds:
        need |= {("certificate", ""), ("segment", "")}
    if kinds & {"pra_portal", "pra_console", "user_portal"}:
        need |= {(k, "") for k in kinds & {"pra_portal", "pra_console", "user_portal"}}
    if "pra_portal" in kinds:
        need.add(("pra_console", ""))
    if "user_portal" in kinds:
        need.add(("pra_portal", ""))
    need |= {("provisioning_key", c["key_type"]) for c in clean if c["kind"] == "provisioning_key"}
    if "connector_group" in kinds:
        need.add(("provisioning_key", "connector"))
    if "service_edge_group" in kinds:
        need.add(("provisioning_key", "service_edge"))
    data: Dict[str, List[Dict[str, Any]]] = {}
    for k, kt in sorted(need):
        say(f"Reading ZPA {('provisioning keys' if k == 'provisioning_key' else KINDS[k]['label'] + 's')}…")
        rows, err = list_kind(zpa, k, gate, kt)
        if err:
            raise _err(f"ZPA could not be read, so nothing was planned (a delete is never planned from a partial read): {err}")
        data[f"{k}:{kt}"] = rows
    items, groups, warnings = [], [], []
    going: set = set()
    for c in clean:
        kind, kt = c["kind"], c.get("key_type", "")
        row = next((r for r in data[f"{kind}:{kt}"] if _oid(r) == c["id"]), None)
        key = f"del:{kind}:{c['id']}"
        o = _obj(kind, c["id"], c["name"])
        if row is None:
            items.append(ao._unit(key, key, kind, o, "exists", False, False, status="noop", reason="already gone"))
            continue
        why = in_use(kind, row, data, going)
        if _name(row) != c["name"]:
            why = f"its name in ZPA is '{_name(row)}', not '{c['name']}': read the tenant again and pick it"
        if why:
            items.append(ao._unit(key, key, kind, o, "exists", True, True, status="excluded", reason=why))
            continue
        verb = "Revokes it" if kind == "provisioning_key" else "Deletes it"
        path = f"/associationType/{'CONNECTOR_GRP' if kt == 'connector' else 'SERVICE_EDGE_GRP'}/provisioningKey" if kind == "provisioning_key" else KINDS[kind]["path"]
        deps = [f"del:{k}:{i}" for k, i in sorted(going) if _depends(kind, row, k, i, data)]
        items.append(ao._unit(key, key, kind, o, "exists", True, False, reason=f"{verb}: DELETE {path}/{{id}}.", depends_on=deps))
        groups.append({"key": key, "handler": "zpa_adm_delete", "target": dict(c, check=_delete_guard(kind, row, going))})
        going.add((kind, c["id"]))
        if kind == "provisioning_key":
            used = zr.as_str(zr.get(row, "usageCount")) or "0"
            if used not in ("", "0"):
                warnings.append(f"Provisioning key '{c['name']}' enrolled {used} component(s): they keep working; no new one can enroll with it.")
    n = sum(1 for u in items if u["status"] == "change")
    names = [u["object"]["name"] for u in items if u["status"] == "change"]
    phrase = ""
    if n == 1 and re.fullmatch(r"[A-Za-z0-9 ._()\-]{1,60}", names[0]):
        phrase = f"DELETE {names[0].upper()}"
    elif n:
        phrase = f"DELETE {n} ZPA OBJECTS"
    title = ("Undo: revoke " if undo else "Delete ") + f"{len(clean)} ZPA object{'' if len(clean) == 1 else 's'}"
    return _done(T_DELETE, title, nspec, items, groups, warnings=warnings, confirm_always=phrase,
                 undo="No Undo: a deleted App Connector or Service Edge must enroll again with a provisioning key, a deleted group, "
                      "portal, console or certificate must be made again, and a revoked key cannot be restored.",
                 notes=["You type the confirmation whatever the count: a delete always asks for it."] + [ASSUMED[4]])


def in_use(kind: str, row: Dict[str, Any], data: Dict[str, List[Dict[str, Any]]], going: Optional[set] = None) -> Optional[str]:
    """Why this object is not deleted: still connected or still used (None
    when it may go). `going`: (kind, id) deleted earlier in the same run,
    which no longer count as users."""
    oid = _oid(row)
    gone = going or set()
    data = {k: [r for r in rows if (k.split(":")[0], _oid(r)) not in gone] for k, rows in data.items()}
    if kind in ("connector", "service_edge"):
        _raw, up = zr._status(row)
        if up and _b(zr.get(row, "enabled")):
            return "it is connected and serving right now: turn it off first (Change ZPA objects), then delete it"
    if kind == "connector_group":
        members = [c for c in data.get("connector:", []) if zr.as_str(zr.get(c, "appConnectorGroupId")) == oid] or \
            [i for i in zr._ref_ids(zr.get(row, "connectors") or []) if ("connector", i) not in gone]
        if members:
            return f"{len(members)} App Connector(s) are still in it: move or delete them first"
        if zr._ref_ids(zr.get(row, "serverGroups") or []):
            return "a server group still uses it: remove it from the server group first"
        keys = [k for k in data.get("provisioning_key:connector", []) if ("provisioning_key", _oid(k)) not in gone and zr.as_str(zr.get(k, "zcomponentId")) == oid]
        if keys:
            return f"provisioning key '{_name(keys[0])}' still enrolls into it: revoke it first"
    if kind == "service_edge_group":
        members = [e for e in data.get("service_edge:", []) if zr.as_str(zr.get(e, "serviceEdgeGroupId")) == oid] or \
            [i for i in zr._ref_ids(zr.get(row, "serviceEdges") or []) if ("service_edge", i) not in gone]
        if members:
            return f"{len(members)} Service Edge(s) are still in it: move or delete them first"
        keys = [k for k in data.get("provisioning_key:service_edge", []) if ("provisioning_key", _oid(k)) not in gone and zr.as_str(zr.get(k, "zcomponentId")) == oid]
        if keys:
            return f"provisioning key '{_name(keys[0])}' still enrolls into it: revoke it first"
    if kind == "pra_portal":
        cons = [c for c in data.get("pra_console:", []) if oid in zr._ref_ids(zr.get(c, "praPortals") or [])]
        if cons:
            return f"PRA console '{_name(cons[0])}' still uses it: delete the console or take the portal out of it first"
    if kind == "user_portal":
        users = [p for p in data.get("pra_portal:", []) if zr.as_str(zr.get(p, "userPortalGid")) == oid]
        if users:
            return f"PRA portal '{_name(users[0])}' is still linked to it: unlink or delete it first"
    if kind == "certificate":
        apps = [a for a in ba_apps(data.get("segment:", [])) if a["certificate_id"] == oid]
        if apps:
            return f"Browser Access application {apps[0]['domain']} in '{apps[0]['segment_name']}' still uses it: point it at another certificate first"
    return None


def _depends(kind: str, row: Dict[str, Any], dk: str, did: str, data: Dict[str, List[Dict[str, Any]]]) -> bool:
    """Is (dk, did), deleted earlier in the run, one of this object's users?"""
    one = {(dk, did)}
    return in_use(kind, row, data) is not None and in_use(kind, row, data, one) != in_use(kind, row, data)


def _delete_guard(kind: str, row: Dict[str, Any], going: Optional[set] = None) -> Dict[str, Any]:
    """What must still hold right before the delete (the re-read compares
    it); members deleted earlier in the same run are not expected."""
    out = {"name": _name(row)}
    gone = going or set()
    if kind in ("connector", "service_edge"):
        out["connected"] = bool(zr._status(row)[1] and _b(zr.get(row, "enabled")))
    if kind == "connector_group":
        out["members"] = sorted(i for i in zr._ref_ids(zr.get(row, "connectors") or []) if ("connector", i) not in gone)
    if kind == "service_edge_group":
        out["members"] = sorted(i for i in zr._ref_ids(zr.get(row, "serviceEdges") or []) if ("service_edge", i) not in gone)
    return out


# ── zpa_provisioning_key_new ───────────────────────────────────────────

def plan_key(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    kt = _key_type(spec)
    gkind, cert_name, glabel = KEY_TYPES[kt]
    gid = check_id(spec.get("group_id"), f"The {glabel}")
    name = check_name(spec.get("name"), "The key's name")
    mu = spec.get("max_usage", 1)
    if isinstance(mu, bool) or not isinstance(mu, int) or not 1 <= mu <= 500:
        raise _err("How many may enroll with the key: a whole number from 1 to 500.")
    enabled = spec.get("enabled", False)
    enabled = _bool(enabled, "Turn the key on")
    nspec = {"type": T_KEY, "key_type": kt, "group_id": gid, "name": name, "max_usage": mu, "enabled": enabled}
    zpa = _zpa(client)
    gate = _gate(cancel)
    say(f"Reading ZPA {glabel}s and provisioning keys…")
    grows, err = list_kind(zpa, gkind, gate)
    if err:
        raise _err(f"ZPA {glabel}s could not be read, so nothing was planned: {err}")
    keys, err = list_kind(zpa, "provisioning_key", gate, kt)
    if err:
        raise _err(f"ZPA provisioning keys could not be read, so nothing was planned: {err}")
    try:
        gate.before()
        data_, resp_, err_ = zr._triple(zpa.enrollment_certificates.list_enrolment(query_params={"search": cert_name}))
        rows = [] if err_ else zr.raw_items(data_, resp_)
    except zr.Stopped:
        raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")
    except Exception:  # noqa: BLE001 — no certificate is reported below
        rows = []
    cert = next((r for r in rows if isinstance(r, dict) and _name(r) == cert_name), None)
    group = next((g for g in grows if _oid(g) == gid), None)
    blockers = []
    if group is None:
        blockers.append(f"The {glabel} you picked is not in ZPA now. Read the tenant again and pick it.")
    if cert is None:
        blockers.append(f"ZPA has no enrollment certificate named '{cert_name}', which a provisioning key needs.")
    o = _obj("provisioning_key", "", name, key_type=kt, new=True)
    key = f"key:{kt}:{name}"
    items, groups = [], []
    if any(_name(k) == name for k in keys):
        items.append(ao._unit(key, key, "provisioning_key", o, "exists", True, True, status="excluded",
                              reason="a provisioning key with this name exists: pick another name (its value is never shown again)"))
    else:
        path = f"/associationType/{'CONNECTOR_GRP' if kt == 'connector' else 'SERVICE_EDGE_GRP'}/provisioningKey"
        items.append(ao._unit(key, key, "provisioning_key", o, "exists", False, True,
                              value=f"{glabel} '{_name(group) if group else gid}', up to {mu}, {'on' if enabled else 'off'}",
                              reason=f"Creates it: POST {path} (provisioning.add_provisioning_key)."))
        if not blockers:
            groups.append({"key": key, "handler": "zpa_adm_key", "target": {"key_type": kt, "group_id": gid, "name": name, "max_usage": mu,
                                                                           "enabled": enabled, "enrollment_cert_id": _oid(cert) if cert else ""}})
    warnings = ["The key is shown once, right after it is created: copy it then. It is not kept, logged, recorded or exported."]
    if not enabled:
        warnings.append("The key is created turned off (nothing can enroll with it) until you turn it on here or in the ZPA Admin Portal.")
    return _done(T_KEY, f"New provisioning key '{name}' for {glabel} '{_name(group) if group else gid}'", nspec, items, groups,
                 warnings=warnings, blockers=blockers, undo="Undo: revokes (deletes) the new key, previewed first.")


# ── zpa_ba_certificate ─────────────────────────────────────────────────

_CERTS: Dict[str, Dict[str, Any]] = {}
_CERTS_LOCK = threading.Lock()
_PEM_BLOCK = re.compile(r"-----BEGIN [A-Z0-9 ]{1,40}-----.*?-----END [A-Z0-9 ]{1,40}-----", re.S)
_CERT_BLOCK = re.compile(r"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]{1,%d}?-----END CERTIFICATE-----" % MAX_CERT_PEM)
_KEY_BLOCK = re.compile(r"-----BEGIN ((?:RSA |EC )?PRIVATE KEY)-----[A-Za-z0-9+/=\s]{1,%d}?-----END \1-----" % MAX_KEY_PEM)
_LONG_B64 = re.compile(r"[A-Za-z0-9+/=]{48,}")


class CertificateError(ValueError):
    """An uploaded certificate or key that is not used (the upload's 400)."""


def _prune(now: float) -> None:
    for k in [k for k, v in _CERTS.items() if v["expires"] <= now]:
        del _CERTS[k]
    while len(_CERTS) > MAX_CERTS:
        del _CERTS[min(_CERTS, key=lambda k: _CERTS[k]["expires"])]


def inspect_upload(cert_pem: Any, key_pem: Any, now: Optional[float] = None) -> Dict[str, Any]:
    """The facts of an uploaded certificate and key, checked (pure). The key
    is parsed only to prove it matches the certificate; nothing of it is
    returned. CertificateError for anything not usable."""
    if not isinstance(cert_pem, str) or not isinstance(key_pem, str):
        raise CertificateError("Paste or choose the certificate and its private key as PEM text.")
    if len(cert_pem.encode("utf-8", "ignore")) > MAX_CERT_PEM or len(key_pem.encode("utf-8", "ignore")) > MAX_KEY_PEM:
        raise CertificateError(f"The certificate must be at most {MAX_CERT_PEM // 1024} KB and the key {MAX_KEY_PEM // 1024} KB.")
    if "PRIVATE KEY" in cert_pem:
        raise CertificateError("The certificate field holds a private key: put the key in its own field.")
    certs = [m.group(0) for m in _CERT_BLOCK.finditer(cert_pem)]
    if not certs or len(certs) > 5:
        raise CertificateError("The certificate must be PEM (-----BEGIN CERTIFICATE-----), the server certificate first, with at most four in its chain.")
    keys = [m.group(0) for m in _KEY_BLOCK.finditer(key_pem)]
    if len(keys) != 1:
        raise CertificateError("The private key must be one unencrypted PEM key (-----BEGIN PRIVATE KEY-----); an encrypted key is refused.")
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.oid import ExtensionOID, NameOID
    except ImportError:   # pragma: no cover — pyjwt[crypto] installs it
        raise CertificateError("The certificate cannot be checked here (the cryptography package is missing), so it is not uploaded.")
    try:
        leaf = x509.load_pem_x509_certificate(certs[0].encode("ascii"))
    except Exception:  # noqa: BLE001 — never echo the input
        raise CertificateError("The certificate could not be read as a PEM X.509 certificate.")
    try:
        key = serialization.load_pem_private_key(keys[0].encode("ascii"), password=None)
    except Exception:  # noqa: BLE001 — never echo the key or the parser's words about it
        raise CertificateError("The private key could not be read (an encrypted or malformed key is refused).")
    pub = lambda k: k.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    if pub(key.public_key()) != pub(leaf.public_key()):
        raise CertificateError("The private key does not belong to this certificate.")
    del key
    now = time.time() if now is None else now
    try:
        not_after = leaf.not_valid_after_utc.timestamp()
        not_before = leaf.not_valid_before_utc.timestamp()
    except AttributeError:   # pragma: no cover — older cryptography
        not_after = leaf.not_valid_after.replace(tzinfo=timezone.utc).timestamp()
        not_before = leaf.not_valid_before.replace(tzinfo=timezone.utc).timestamp()
    cn = [a.value for a in leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)]
    try:
        sans = [str(x).lower() for x in leaf.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value.get_values_for_type(x509.DNSName)]
    except Exception:  # noqa: BLE001 — no SAN extension
        sans = []
    return {"subject": str(cn[0])[:200] if cn else "", "sans": sans[:100], "not_after": not_after, "not_before": not_before,
            "valid_to": datetime.fromtimestamp(not_after, timezone.utc).date().isoformat(),
            "days_left": int((not_after - now) // 86400), "expired": not_after <= now, "not_yet_valid": not_before > now,
            "fingerprint_sha256": leaf.fingerprint(hashes.SHA256()).hex(), "chain": len(certs),
            "_cert": "\n".join(certs), "_key": keys[0]}


def stash_upload(cert_pem: str, key_pem: str, actor: Optional[str], now: Optional[float] = None) -> Dict[str, Any]:
    """Check and hold an uploaded certificate and key for one use within
    CERT_TTL, bound to `actor`: {token, facts, expires_in_seconds}. The key
    never leaves this store except in the one write to ZPA."""
    facts = inspect_upload(cert_pem, key_pem, now)
    cert, key = facts.pop("_cert"), facts.pop("_key")
    now = time.time() if now is None else now
    token = _secrets.token_urlsafe(32)
    with _CERTS_LOCK:
        _CERTS[token] = {"cert": cert, "key": key, "facts": facts, "expires": now + CERT_TTL, "actor": actor}
        _prune(now)
    return {"token": token, "facts": {k: v for k, v in facts.items() if k not in ("not_after", "not_before")}, "expires_in_seconds": int(CERT_TTL)}


def peek_upload(token: Any, actor: Optional[str], now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    """The facts of a held upload (never the key), or None."""
    t = str(token or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", t):
        return None
    now = time.time() if now is None else now
    with _CERTS_LOCK:
        _prune(now)
        got = _CERTS.get(t)
        if got is None or (got["actor"] and got["actor"] != actor):
            return None
        return dict(got["facts"])


def _take_upload(token: str, actor: Optional[str]) -> Optional[Tuple[str, str]]:
    """The held certificate and key, removed from the store (sent once)."""
    with _CERTS_LOCK:
        _prune(time.time())
        got = _CERTS.get(token)
        if got is None or (got["actor"] and got["actor"] != actor):
            return None
        del _CERTS[token]
    return got["cert"], got["key"]


def scrub_secret(text: Any, *secrets_: str) -> str:
    """`text` without any PEM block, any line of the given secrets, or any
    long base64 run: an error answer that echoes the request never carries
    the key into a result, a log or the audit log."""
    s = _PEM_BLOCK.sub("[PEM hidden]", str(text or ""))
    for sec in secrets_:
        for line in str(sec or "").splitlines():
            line = line.strip()
            if len(line) >= 16 and "-----" not in line:
                s = s.replace(line, "[hidden]")
    return _LONG_B64.sub("[hidden]", s)


def _covers(names: Sequence[str], domain: str) -> bool:
    d = domain.lower().rstrip(".")
    for n in names:
        n = n.lower().rstrip(".")
        if n == d or (n.startswith("*.") and d.endswith(n[1:]) and d.count(".") == n.count(".")):
            return True
    return False


def _actor() -> Optional[str]:
    return ops_zpa._actor()


def plan_cert(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    undo = bool(spec.get("undo") is True)
    if undo:
        return _plan_cert_undo(client, spec, say, cancel)
    token = str(spec.get("upload_token") or "")
    existing = spec.get("certificate_id")
    if bool(token) == bool(existing not in (None, "")):
        raise _err("Upload a new certificate or pick one ZPA already has (one of the two).")
    raw_assign = spec.get("assign") or []
    if not isinstance(raw_assign, list) or len(raw_assign) > MAX_ASSIGN or not all(isinstance(a, dict) for a in raw_assign):
        raise _err(f"Pick up to {MAX_ASSIGN} Browser Access applications.")
    assign = [{"segment_id": check_id(a.get("segment_id"), "The application segment"), "app_id": check_id(a.get("app_id"), "The Browser Access application")}
              for a in raw_assign]
    if len({(a["segment_id"], a["app_id"]) for a in assign}) != len(assign):
        raise _err("Each Browser Access application may appear once.")
    if existing not in (None, "") and not assign:
        raise _err("Pick the Browser Access applications to point at this certificate.")
    nspec: Dict[str, Any] = {"type": T_CERT, "assign": assign}
    facts = None
    name = ""
    if token:
        if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", token):
            raise _err("The upload is not valid: upload the certificate again.")
        name = check_name(spec.get("name"), "The certificate's name")
        desc = re.sub(r"[\x00-\x1f\x7f<>]", "", str(spec.get("description") or ""))[:255]
        nspec.update(upload_token=token, name=name, description=desc)
        facts = peek_upload(token, _actor())
    else:
        nspec["certificate_id"] = check_id(existing, "The certificate")
    zpa = _zpa(client)
    gate = _gate(cancel)
    say("Reading the ZPA Browser Access certificates…")
    certs, err = list_kind(zpa, "certificate", gate)
    if err:
        raise _err(f"ZPA certificates could not be read, so nothing was planned: {err}")
    items, groups, warnings, blockers = [], [], [], []
    target_ref: Any = None
    sans: List[str] = []
    cert_label = ""
    if token:
        ckey = f"cert:{name}"
        if facts is None:
            blockers.append("The uploaded certificate is no longer held (it is kept ten minutes, for the person who uploaded it). Upload it again.")
        elif facts["expired"]:
            blockers.append(f"The certificate expired on {facts['valid_to']}: ZPA would serve an expired certificate. Upload a valid one.")
        elif facts["not_yet_valid"]:
            blockers.append("The certificate is not valid yet: browsers would refuse it.")
        if os.environ.get("ZSCALER_SDK_LOG", "").strip().lower() == "true":
            blockers.append("The Zscaler SDK's request log is on (ZSCALER_SDK_LOG=true): it writes request bodies, so the private key would be "
                            "logged. Turn it off and restart the app, then upload again.")
        if any(_name(c) == name for c in certs):
            blockers.append(f"A certificate named '{name}' exists in ZPA: pick another name.")
        if facts and not facts["expired"] and facts["days_left"] <= EXPIRY_WARN_DAYS:
            warnings.append(f"The certificate expires in {facts['days_left']} day(s) ({facts['valid_to']}).")
        sans = (facts or {}).get("sans") or ([facts["subject"]] if facts and facts.get("subject") else [])
        cert_label = f"new: {name}"
        fp = (facts or {}).get("fingerprint_sha256", "")
        items.append(ao._unit(ckey, ckey, "certificate", _obj("certificate", "", name, new=True), "exists", False, True,
                              value=f"{(facts or {}).get('subject') or '?'}, valid to {(facts or {}).get('valid_to') or '?'}, SHA-256 {fp[:16]}…",
                              reason="Creates it: POST /certificate (certificates.add_certificate), the certificate and its private key sent once."))
        if not blockers:
            groups.append({"key": ckey, "handler": "zpa_adm_cert_create", "target": {"name": name, "description": nspec["description"],
                                                                                    "token": token, "fingerprint": fp}})
        target_ref = {"ref": ckey}
    else:
        row = next((c for c in certs if _oid(c) == nspec["certificate_id"]), None)
        if row is None:
            blockers.append("The certificate you picked is not in ZPA now. Read the tenant again and pick it.")
        else:
            cs = cert_summary(row)
            if cs["expiry"] == "expired":
                blockers.append(f"Certificate '{cs['name']}' expired on {cs['valid_to']}: pick a valid one.")
            sans = cs["san"] or ([cs["cname"]] if cs["cname"] else [])
            cert_label = cs["name"]
        target_ref = nspec["certificate_id"]
    cert_names = {_oid(c): _name(c) for c in certs}
    for a in assign:
        say("Reading the application segment…")
        seg, err = get_one(zpa, "segment", a["segment_id"])
        key = f"assign:{a['segment_id']}:{a['app_id']}"
        if seg is None:
            if not _gone(err):
                raise _err(f"The application segment could not be read, so nothing was planned: {err}")
            items.append(ao._unit(key, key, "ba_app", {"type": "zpa_ba_app", "id": a["app_id"], "name": a["app_id"]}, "certificate", "", cert_label,
                                  status="excluded", reason="the application segment is not in ZPA now"))
            continue
        app = next((x for x in ba_apps([seg]) if x["app_id"] == a["app_id"]), None)
        o = {"type": "zpa_ba_app", "kind": "ba_app", "label": "Browser Access application", "id": a["app_id"],
             "name": f"{app['domain'] if app else a['app_id']} ({_name(seg)})", "segment_id": a["segment_id"]}
        if app is None:
            items.append(ao._unit(key, key, "ba_app", o, "certificate", "", cert_label, status="excluded",
                                  reason="this segment has no such Browser Access application now"))
            continue
        before = app["certificate_id"]
        if before and before == str(target_ref):
            items.append(ao._unit(key, key, "ba_app", o, "certificate", cert_names.get(before, before), cert_label, status="noop", reason="already uses it"))
            continue
        if sans and not _covers(sans, app["domain"]):
            items.append(ao._unit(key, key, "ba_app", o, "certificate", cert_names.get(before, before), cert_label, status="excluded",
                                  reason=f"the certificate does not cover {app['domain']} (it names {', '.join(sans[:5])}): browsers would refuse it"))
            continue
        items.append(ao._unit(key, key, "ba_app", o, "certificate", cert_names.get(before, before) or "(none)", cert_label,
                              reason="Points it at the certificate: PUT /application/{id} with the segment as read.",
                              depends_on=[f"cert:{name}"] if token else []))
        groups.append({"key": key, "handler": "zpa_adm_cert_assign", "target": {"segment_id": a["segment_id"], "app_id": a["app_id"],
                                                                               "certificate": target_ref, "before": before, "name": o["name"]}})
    title = f"Browser Access certificate {'upload ' + repr(name) if token else repr(cert_label)}" + (f" for {len(assign)} application(s)" if assign else "")
    return _done(T_CERT, title, nspec, items, groups, warnings=warnings, blockers=blockers,
                 undo="Undo: points the applications back at the certificates they used and deletes an uploaded certificate (previewed first).",
                 notes=["The private key is sent to ZPA once and is never kept, logged, recorded or shown: the plan names the upload by a token only.",
                        ASSUMED[3]])


def _plan_cert_undo(client: Any, spec: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    raw = spec.get("restore") or []
    if not isinstance(raw, list) or len(raw) > MAX_ASSIGN or not all(isinstance(r, dict) for r in raw):
        raise _err("The Undo names the applications to point back.")
    restore = [{"segment_id": check_id(r.get("segment_id"), "The application segment"), "app_id": check_id(r.get("app_id"), "The application"),
                "certificate_id": check_id(r.get("certificate_id"), "The certificate") if r.get("certificate_id") not in (None, "") else "",
                "from_id": check_id(r.get("from_id"), "The certificate") if r.get("from_id") not in (None, "") else ""} for r in raw]
    dc = spec.get("delete_certificate")
    delete = None
    if isinstance(dc, dict) and dc:
        delete = {"id": check_id(dc.get("id"), "The certificate"), "name": check_name(dc.get("name"), "The certificate's name")}
    nspec = {"type": T_CERT, "undo": True, "restore": restore, "delete_certificate": delete}
    zpa = _zpa(client)
    items, groups = [], []
    for r in restore:
        key = f"assign:{r['segment_id']}:{r['app_id']}"
        seg, err = get_one(zpa, "segment", r["segment_id"])
        app = next((x for x in ba_apps([seg]) if x["app_id"] == r["app_id"]), None) if seg else None
        o = {"type": "zpa_ba_app", "kind": "ba_app", "label": "Browser Access application", "id": r["app_id"],
             "name": app["domain"] if app else r["app_id"], "segment_id": r["segment_id"]}
        if app is None:
            items.append(ao._unit(key, key, "ba_app", o, "certificate", "", r["certificate_id"], status="excluded", reason="not in ZPA now"))
            continue
        if not r["certificate_id"]:
            items.append(ao._unit(key, key, "ba_app", o, "certificate", app["certificate_id"], "(none)", status="excluded",
                                  reason="it had no certificate before, and ZPA needs one: point it at a certificate by hand"))
            continue
        if app["certificate_id"] == r["certificate_id"]:
            items.append(ao._unit(key, key, "ba_app", o, "certificate", app["certificate_id"], r["certificate_id"], status="noop", reason="already as it was"))
            continue
        items.append(ao._unit(key, key, "ba_app", o, "certificate", app["certificate_id"], r["certificate_id"], reason="Points it back."))
        groups.append({"key": key, "handler": "zpa_adm_cert_assign", "target": {"segment_id": r["segment_id"], "app_id": r["app_id"],
                                                                               "certificate": r["certificate_id"], "before": r["from_id"] or app["certificate_id"],
                                                                               "name": o["name"]}})
    warnings = []
    if delete:
        key = f"del:certificate:{delete['id']}"
        row, err = get_one(zpa, "certificate", delete["id"])
        o = _obj("certificate", delete["id"], delete["name"])
        if row is None:
            items.append(ao._unit(key, key, "certificate", o, "exists", False, False, status="noop", reason="already gone"))
        elif _name(row) != delete["name"]:
            items.append(ao._unit(key, key, "certificate", o, "exists", True, True, status="excluded", reason="renamed in ZPA since; kept"))
        else:
            items.append(ao._unit(key, key, "certificate", o, "exists", True, False, reason="Deletes the uploaded certificate: DELETE /certificate/{id}.",
                                  depends_on=[u["key"] for u in items if u["status"] == "change"]))
            groups.append({"key": key, "handler": "zpa_adm_delete", "target": {"kind": "certificate", "id": delete["id"], "name": delete["name"],
                                                                              "check": {"name": delete["name"]}}})
    return _done(T_CERT, "Undo: Browser Access certificate", nspec, items, groups, warnings=warnings,
                 undo="No Undo of this Undo: upload the certificate again if you need it.")


# ---------------------------------------------------------------------------
# Writes (the engine calls one handler per group, in order)
# ---------------------------------------------------------------------------

def _write(fn: Callable[..., Any], *args: Any, op: str, kind: str, name: str, log, oid: Any = None, kw: Optional[Dict[str, Any]] = None,
           hide: Sequence[str] = ()) -> ops.Outcome:
    """One SDK write through pack_ops.call (pacing, retries, Stop, the run's
    fatal refusals) with one object_write audit entry. The answer's data is
    reduced to its id; with `hide`, any error text is scrubbed of those
    secrets first, so it never reaches a log, a result or the audit log."""
    def sdk_call(*a: Any, **k: Any) -> Any:
        try:
            ret = fn(*a, **k)
        except Exception as e:  # noqa: BLE001 — reported as the write's error
            import tenant_auth   # an exception may quote the request (its Authorization header): redacted like pack_ops.call does
            msg = tenant_auth.redact_tokens(f"{type(e).__name__}: {str(e)[:2000]}")[:300]
            return (None, None, scrub_secret(msg, *hide) if hide else msg)
        data, resp, err = zr._triple(ret)
        if err:
            return (None, resp, scrub_secret(err, *hide) if hide else err)
        rid = None
        if isinstance(data, dict):
            rid = data.get("id")
        elif data is not None:
            rid = getattr(data, "id", None)
        if rid is None and resp is not None and callable(getattr(resp, "get_body", None)):
            try:
                body = resp.get_body()
                rid = body.get("id") if isinstance(body, dict) else None
            except Exception:  # noqa: BLE001
                rid = None
        return ({"id": rid}, resp, None)

    out = ops.call(sdk_call, *args, op=op, kind=kind, name=name, log=log, kw=kw)
    ops._audit_write(op, kind, out.id if op == "create" else oid, name, None, out)
    return out


def _halt_or_fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    ops_zpa._halt_or_fail(run, units, err, what)


def _h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind = t["kind"]
    fresh, err = get_one(run.zpa, kind, t["id"])
    if fresh is None:
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    cur = state(kind, fresh)
    if any(cur.get(f) != v for f, v in t["before"].items()):
        run.mark(units, "conflict", "changed in ZPA since the preview; left as it is")
        return
    k = KINDS[kind]
    svc = getattr(run.zpa, k["svc"])
    out = _write(getattr(svc, k["update"]), t["id"], op="update", kind=f"zpa_{kind}", name=t["name"], log=run.log, oid=t["id"],
                 kw=_update_payload(kind, fresh, t["desired"]))
    if run.outcome(units, out, "update"):
        run.log(f"[ZPA {k['label']}] {t['name']}: {', '.join(sorted(t['desired']))} updated")


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind, kt = t["kind"], t.get("key_type", "")
    fresh, err = get_one(run.zpa, kind, t["id"], kt)
    if fresh is None:
        if _gone(err):
            run.mark(units, "noop", "already gone")
            return
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    now = _delete_guard(kind, fresh)
    want = t.get("check") or {}
    if now.get("name") != want.get("name") or any(now.get(k) != v for k, v in want.items() if k != "name"):
        run.mark(units, "conflict", "it changed in ZPA since the preview (renamed, connected or its members changed), so it is kept")
        return
    label = "Provisioning key" if kind == "provisioning_key" else KINDS[kind]["label"]
    if kind == "provisioning_key":
        out = _write(run.zpa.provisioning.delete_provisioning_key, t["id"], kt, op="delete", kind="zpa_provisioning_key", name=t["name"],
                     log=run.log, oid=t["id"])
    else:
        k = KINDS[kind]
        out = _write(getattr(getattr(run.zpa, k["svc"]), k["delete"]), t["id"], op="delete", kind=f"zpa_{kind}", name=t["name"], log=run.log, oid=t["id"])
    if run.outcome(units, out, "delete"):
        run.log(f"[ZPA {label}] {t['name']}: {'revoked' if kind == 'provisioning_key' else 'deleted'}")


def _h_key(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = list_kind(run.zpa, "provisioning_key", _gate(None), t["key_type"])
    if err:
        _halt_or_fail(run, units, err, "the provisioning keys")
        return
    if any(_name(r) == t["name"] for r in rows):
        run.mark(units, "conflict", f"a key named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    secret_box: Dict[str, str] = {}

    def add(key_type: str, **kw: Any) -> Any:
        ret = run.zpa.provisioning.add_provisioning_key(key_type, **kw)
        data, resp, err2 = zr._triple(ret)
        if not err2:
            v = data.get("provisioningKey") or data.get("provisioning_key") if isinstance(data, dict) else getattr(data, "provisioning_key", None)
            secret_box["v"] = str(v or "")
        return ret

    out = _write(add, t["key_type"], op="create", kind="zpa_provisioning_key", name=t["name"], log=run.log,
                 kw={"name": t["name"], "max_usage": str(t["max_usage"]), "enrollment_cert_id": t["enrollment_cert_id"], "component_id": t["group_id"],
                     "enabled": t["enabled"]})
    out.data = None
    secret = secret_box.pop("v", "")
    if run.outcome(units, out, "create"):
        oid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=oid)
        run.created.append({"type": "zpa_provisioning_key", "kind": "provisioning_key", "key_type": t["key_type"], "id": oid, "name": t["name"]})
        run.log(f"[ZPA provisioning key] {t['name']}: created")
        if secret:
            run.p.setdefault("one_time_secrets", []).append({"name": t["name"], "token": ops_zpa.stash(secret, t["name"], _actor()),
                                                             "expires_in_seconds": int(ops_zpa.SECRET_TTL)})
        else:
            run.p.setdefault("warnings", []).append(f"ZPA did not return the value of '{t['name']}': copy it from the ZPA Admin Portal.")
    secret = ""


def _h_cert_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = list_kind(run.zpa, "certificate", _gate(None))
    if err:
        _halt_or_fail(run, units, err, "the certificates")
        return
    if any(_name(r) == t["name"] for r in rows):
        run.mark(units, "conflict", f"a certificate named '{t['name']}' now exists (made since the preview); nothing was uploaded")
        return
    held = _take_upload(t["token"], _actor())
    if held is None:
        run.mark(units, "skipped", "not attempted: the uploaded certificate is no longer held (ten minutes, one use); upload it again")
        return
    cert, key = held
    held = None
    out = _write(run.zpa.certificates.add_certificate, op="create", kind="zpa_certificate", name=t["name"], log=run.log,
                 kw={"name": t["name"], "description": t["description"], "cert_blob": cert + "\n" + key}, hide=(key, cert))
    key = ""
    out.data = None
    if run.outcome(units, out, "create"):
        oid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=oid)
        run.created.append({"type": "zpa_certificate", "kind": "certificate", "id": oid, "name": t["name"]})
        run.log(f"[ZPA Browser Access certificate] {t['name']}: uploaded")


def _h_cert_assign(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    cid = t["certificate"]
    if isinstance(cid, dict):
        u = run.units.get(cid.get("ref"))
        cid = (u or {}).get("object", {}).get("id")
        if not cid:
            run.mark(units, "skipped", "not attempted: the new certificate was not created")
            return
    fresh, err = get_one(run.zpa, "segment", t["segment_id"])
    if fresh is None:
        _halt_or_fail(run, units, err, "the application segment")
        return
    apps = [a for a in zr._items(zr.get(fresh, "clientlessApps")) if isinstance(a, dict)]
    app = next((a for a in apps if zr.as_str(a.get("id")) == t["app_id"]), None)
    if app is None or zr.as_str(zr.get(app, "certificateId")) != zr.as_str(t["before"]):
        run.mark(units, "conflict", "its certificate changed in ZPA since the preview; left as it is")
        return
    body = ao.segment_body(fresh)
    body["clientless_apps"] = [dict(a, certificateId=str(cid)) if a is app else dict(a) for a in apps]
    for a in body["clientless_apps"]:
        a.pop("certificateName", None)
        a.pop("certificate_name", None)
    out = _write(run.zpa.application_segment.update_segment, t["segment_id"], op="update", kind="zpa_segment", name=_name(fresh), log=run.log,
                 oid=t["segment_id"], kw=body)
    if run.outcome(units, out, "update"):
        t["applied_certificate"], t["applied_before"] = str(cid), zr.as_str(t["before"])
        run.log(f"[ZPA Browser Access] {t['name']}: certificate changed")


HANDLERS = {"zpa_adm_update": _h_update, "zpa_adm_delete": _h_delete, "zpa_adm_key": _h_key, "zpa_adm_cert_create": _h_cert_create,
            "zpa_adm_cert_assign": _h_cert_assign}


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def verify(run: Any) -> Dict[str, Any]:
    """Read back every object a write touched."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t, h = g["target"], g["handler"]
        out["checked"] += len(applied)
        ok, err, label = False, None, t.get("name") or ""
        if h == "zpa_adm_update":
            row, err = get_one(run.zpa, t["kind"], t["id"])
            ok = row is not None and all(state(t["kind"], row).get(f) == v for f, v in t["desired"].items())
        elif h == "zpa_adm_delete":
            row, err = get_one(run.zpa, t["kind"], t["id"], t.get("key_type", ""))
            ok = row is None and _gone(err)
            err = None if ok or row is not None else err
        elif h == "zpa_adm_key":
            oid = applied[0]["object"].get("id")
            row, err = get_one(run.zpa, "provisioning_key", oid, t["key_type"])
            ok = row is not None and _name(row) == t["name"] and zr.as_str(zr.get(row, "zcomponentId")) == t["group_id"] and \
                _b(zr.get(row, "enabled")) == t["enabled"]
        elif h == "zpa_adm_cert_create":
            oid = applied[0]["object"].get("id")
            row, err = get_one(run.zpa, "certificate", oid)
            ok = row is not None and _name(row) == t["name"]
        elif h == "zpa_adm_cert_assign":
            row, err = get_one(run.zpa, "segment", t["segment_id"])
            app = next((a for a in ba_apps([row]) if a["app_id"] == t["app_id"]), None) if row else None
            ok = app is not None and app["certificate_id"] == t.get("applied_certificate")
        if not ok and err and h != "zpa_adm_delete":
            out["unread"].append(f"{label}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{label}: not as expected when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Undo of what was applied (None for a delete: there is none)."""
    t = result.get("type")
    groups = result.get("groups") or []
    items = result.get("items") or []
    applied = lambda g: [u for u in items if u.get("group") == g["key"] and u.get("status") == "applied"]  # noqa: E731
    if t == T_UPDATE:
        targets = []
        for g in groups:
            if g["handler"] == "zpa_adm_update" and applied(g):
                tg = g["target"]
                targets.append({"kind": tg["kind"], "id": tg["id"], "set": {f: v for f, v in tg["before"].items() if v not in (None, "")}})
        targets = [x for x in targets if x["set"]]
        return {"type": T_UPDATE, "undo": True, "targets": targets} if targets else None
    if t == T_KEY:
        made = [c for c in result.get("created") or [] if c.get("kind") == "provisioning_key" and c.get("id")]
        return {"type": T_DELETE, "undo": True, "targets": [{"kind": "provisioning_key", "id": c["id"], "name": c["name"], "key_type": c["key_type"]}
                                                            for c in made]} if made else None
    if t == T_CERT and not (result.get("spec") or {}).get("undo"):
        restore = []
        for g in groups:
            if g["handler"] == "zpa_adm_cert_assign" and applied(g):
                tg = g["target"]
                restore.append({"segment_id": tg["segment_id"], "app_id": tg["app_id"], "certificate_id": tg.get("applied_before") or "",
                                "from_id": tg.get("applied_certificate") or ""})
        made = next((c for c in result.get("created") or [] if c.get("kind") == "certificate" and c.get("id")), None)
        if not restore and not made:
            return None
        return {"type": T_CERT, "undo": True, "restore": restore, "delete_certificate": {"id": made["id"], "name": made["name"]} if made else None}
    return None


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

_COMMON = dict(family=FAMILY, product="zpa", in_scope=in_scope, read_objects=read_objects, verify=verify, inverse=inverse,
               script="ops_admin.js", group=GROUP)

ao.register(T_UPDATE, label="Change ZPA App Connectors, Service Edges and portals", plan=plan_update, handlers=HANDLERS,
            hint="Rename, turn on or off, move an App Connector to another group, and set the software update day, hour and version profile "
                 "of App Connector and Service Edge groups; turn PRA portals, PRA consoles and user portals on or off. Shows each one's health "
                 "first. Undo puts it back.", **_COMMON)
ao.register(T_DELETE, label="Delete ZPA connectors, groups, portals, certificates or keys", plan=plan_delete, handlers=HANDLERS,
            hint="Delete App Connectors, Service Edges, their groups, PRA portals and consoles, user portals and Browser Access certificates, "
                 "or revoke provisioning keys. Anything "
                 "connected or still used is kept and named; you type the confirmation every time. No Undo.", **_COMMON)
ao.register(T_KEY, label="New ZPA provisioning key", plan=plan_key, handlers=HANDLERS,
            hint="A provisioning key for an App Connector group or a Service Edge group, created off unless you turn it on; shown once. "
                 "Undo revokes it.", **_COMMON)
ao.register(T_CERT, label="ZPA Browser Access certificate", plan=plan_cert, handlers=HANDLERS,
            hint="Upload a certificate with its private key (sent to ZPA once, never kept) and point Browser Access applications at it, or "
                 "at a certificate ZPA has. Shows each certificate's expiry. Undo points them back.", **_COMMON)
