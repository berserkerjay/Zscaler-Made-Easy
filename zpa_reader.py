"""Read a tenant's ZPA configuration once, read-only, and normalize it.

What is read (zscaler-sdk-python `client.zpa.*`, each list method answers
`(items, response, error)`; verified against the installed SDK):

  application_segment.list_segments      app segments (/mgmtconfig/v1/.../application)
  segment_groups.list_groups             segment groups
  server_groups.list_groups              server groups (servers, connector groups)
  app_connector_groups.list_connector_groups
  app_connectors.list_connectors         connectors (controlChannelStatus, versions, last seen)
  service_edge_group.list_service_edge_groups
  service_edges.list_service_edges
  idp.list_idps                          identity providers (SCIM / SAML policy switches)
  saml_attributes.list_saml_attributes
  posture_profiles.list_posture_profiles
  trusted_networks.list_trusted_networks
  machine_groups.list_machine_groups
  servers.list_servers                   application servers (/server)
  app_protection.list_profiles           AppProtection inspection profiles (/inspectionProfile)
  app_protection.list_custom_controls    AppProtection custom controls (/inspectionControls/custom)
  private_cloud.list_private_clouds      Private Cloud sites (/privateCloud)
  private_cloud_group.list_cloud_groups  Private Cloud Controller groups (/privateCloudControllerGroup)
  private_cloud_controller.list_cloud_controllers   Private Cloud Controllers (/privateCloudController)
  branch_connector_group.list_branch_connector_groups / branch_connectors.list_branch_connectors
  cloud_connector_groups.list_cloud_connector_groups / cloud_connector_controller.list_cloud_connectors
  business_continuity.list_business_continuity_settings   one page, no query parameters (the SDK takes none)
  policies.list_rules(t)                 t in access, timeout, client_forwarding, inspection, isolation,
                                         redirection, credential, capabilities, clientless (browser protection)
  scim_groups.list_scim_groups(idp_id)   only for the IdPs the access rules name in SCIM_GROUP conditions

The policy-group model (policy_group*) is not read: it is not documented
well enough to analyze yet.

Business continuity settings carry SAML private keys and certificates
(zscaler/zpa/models/business_continuity.py); only the switches and timers
below are kept, never a key, certificate or metadata value.

The SDK returns one page per call (oneapi_response: "The initial call to
the API returns only one page"), so every list is read page by page with
`page` / `page_size` (max 500, the SDK's documented ZPA maximum) until a
short page. Where the response object carries the page's raw JSON
(`response.get_results()`), that is kept: the SDK models drop fields the
analysis needs (ServerGroup has no `servers`; ApplicationSegments
overwrites `inspection_apps` with `clientlessApps`). Otherwise the model's
`as_dict()` (snake_case) is used; every normalizer reads both spellings.

Pacing: ZPA's API limits are not ZIA's (zia_rate paces only ZIA paths), so
the reader waits `pace` seconds between calls (PACE_SECONDS, a
conservative assumption, not a documented ZPA figure) on top of the SDK's
own 429 retries. Stop (`cancel`, a threading.Event) is honoured before
every call and during every wait: nothing more is read and `Stopped` is
raised, so no partial configuration is ever analyzed.

Nothing here writes: only `list_*` methods are called (tests enforce it).
"""
from __future__ import annotations

import math
import re
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

PACE_SECONDS = 0.6      # assumption: about 16 calls per 10 s, under any ZPA GET limit we know of
PAGE_SIZE = 500         # SDK docstrings: "The max page size is 500"
MAX_PAGES = 40          # 20 000 objects per list; beyond that the list is marked incomplete
SCIM_MAX_PAGES = 10

STOPPED_REASON = ("You clicked Stop before the ZPA read finished, so it was abandoned: nothing more was read "
                  "from the tenant and no partial result is shown.")

POLICY_TYPES = (("access", "access policy"), ("timeout", "timeout policy"), ("client_forwarding", "client forwarding policy"),
                ("inspection", "inspection (AppProtection) policy"), ("isolation", "isolation policy"),
                # SDK PoliciesAPI.POLICY_MAP keys: REDIRECTION_POLICY, CREDENTIAL_POLICY,
                # CAPABILITIES_POLICY, CLIENTLESS_SESSION_PROTECTION_POLICY.
                ("redirection", "redirection policy"), ("credential", "privileged credential policy"),
                ("capabilities", "privileged capabilities policy"), ("clientless", "browser protection policy"))

# (key, label, service attribute, list method)
COLLECTIONS = (
    ("segments", "application segments", "application_segment", "list_segments"),
    ("segment_groups", "segment groups", "segment_groups", "list_groups"),
    ("server_groups", "server groups", "server_groups", "list_groups"),
    ("connector_groups", "App Connector groups", "app_connector_groups", "list_connector_groups"),
    ("connectors", "App Connectors", "app_connectors", "list_connectors"),
    ("service_edge_groups", "Private Service Edge groups", "service_edge_group", "list_service_edge_groups"),
    ("service_edges", "Private Service Edges", "service_edges", "list_service_edges"),
    ("idps", "identity providers", "idp", "list_idps"),
    ("saml_attributes", "SAML attributes", "saml_attributes", "list_saml_attributes"),
    ("posture_profiles", "posture profiles", "posture_profiles", "list_posture_profiles"),
    ("trusted_networks", "trusted networks", "trusted_networks", "list_trusted_networks"),
    ("machine_groups", "machine groups", "machine_groups", "list_machine_groups"),
    ("servers", "application servers", "servers", "list_servers"),
    ("inspection_profiles", "inspection profiles", "app_protection", "list_profiles"),
    ("custom_controls", "inspection custom controls", "app_protection", "list_custom_controls"),
    ("private_clouds", "Private Cloud sites", "private_cloud", "list_private_clouds"),
    ("private_cloud_groups", "Private Cloud Controller groups", "private_cloud_group", "list_cloud_groups"),
    ("private_cloud_controllers", "Private Cloud Controllers", "private_cloud_controller", "list_cloud_controllers"),
    ("branch_connector_groups", "Branch Connector groups", "branch_connector_group", "list_branch_connector_groups"),
    ("branch_connectors", "Branch Connectors", "branch_connectors", "list_branch_connectors"),
    ("cloud_connector_groups", "Cloud Connector groups", "cloud_connector_groups", "list_cloud_connector_groups"),
    ("cloud_connectors", "Cloud Connectors", "cloud_connector_controller", "list_cloud_connectors"),
)
# What only ZPA analysis needs (read when `extended`): the Path analyzer and
# Device posture read the rest and skip these, so their reads stay as short.
EXTENDED_KEYS = frozenset({"servers", "inspection_profiles", "custom_controls", "private_clouds", "private_cloud_groups",
                           "private_cloud_controllers", "branch_connector_groups", "branch_connectors", "cloud_connector_groups",
                           "cloud_connectors", "business_continuity"})
EXTENDED_POLICIES = frozenset({"redirection", "credential", "capabilities", "clientless"})
# Lists whose SDK method takes no query parameters: one call, no paging.
SINGLE_CALL = (
    ("business_continuity", "business continuity settings", "business_continuity", "list_business_continuity_settings"),
)

# Connector and Private Service Edge status (controlChannelStatus), as
# zscaler_full_checks reads it: ZPN_STATUS_AUTHENTICATED is connected.
ZPN_UP = "ZPN_STATUS_AUTHENTICATED"


class Stopped(RuntimeError):
    """The operator clicked Stop: nothing more is read."""


class ReadError(RuntimeError):
    """One list could not be read (the SDK answered an error)."""


# ── small value helpers ─────────────────────────────────────────────────
def _snake(key: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()


def get(d: Any, key: str, default: Any = None) -> Any:
    """`key` (the API's camelCase) or its snake_case spelling (SDK as_dict)."""
    if not isinstance(d, dict):
        return default
    if key in d and d[key] is not None:
        return d[key]
    s = _snake(key)
    if s in d and d[s] is not None:
        return d[s]
    return default


def as_bool(v: Any) -> Optional[bool]:
    """True / False from the API's booleans and "true"/"1" strings; None when absent."""
    if v is None or v == "":
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    if s in ("true", "1", "yes", "y", "on"):
        return True
    if s in ("false", "0", "no", "n", "off"):
        return False
    return None


def as_str(v: Any) -> str:
    return "" if v is None else str(v).strip()


def epoch_seconds(v: Any) -> Optional[float]:
    """ZPA times are epoch strings; connectors' broker times have been seen in
    seconds, milliseconds and microseconds, so the unit is taken from the
    magnitude (assumption). None when absent or unparseable."""
    try:
        n = float(str(v).strip())
    except (TypeError, ValueError):
        return None
    if not math.isfinite(n) or n <= 0:
        return None
    if n > 1e17:
        return n / 1e9
    if n > 1e14:
        return n / 1e6
    if n > 1e11:
        return n / 1e3
    return n


def _items(v: Any) -> List[Any]:
    """A list the API sends as a list: one string sent bare is one item
    (never its characters); a number, true or an object where a list
    belongs is no item, never a crash."""
    if isinstance(v, str):
        return [v] if v else []
    return list(v) if isinstance(v, (list, tuple)) else []


def _ref_ids(v: Any) -> List[str]:
    """Ids of a list of references ([{id, name}], ["id"], [model])."""
    out = []
    for x in _items(v):
        if isinstance(x, dict):
            i = as_str(x.get("id"))
        else:
            i = as_str(getattr(x, "id", x) if not isinstance(x, (str, int)) else x)
        if i:
            out.append(i)
    return out


def _refs(v: Any) -> List[Dict[str, str]]:
    out = []
    for x in _items(v):
        if isinstance(x, dict):
            i = as_str(x.get("id"))
            if i:
                out.append({"id": i, "name": as_str(x.get("name"))})
        elif isinstance(x, (str, int)):
            out.append({"id": str(x), "name": ""})
    return out


def _port(v: Any) -> Optional[int]:
    """A port from a tenant string: ASCII digits, 0-65535; None otherwise
    (int() would accept "²" or thousands of digits and then fail)."""
    s = as_str(v)
    return int(s) if re.fullmatch(r"[0-9]{1,5}", s) and int(s) <= 65535 else None


def port_ranges(seg: Dict[str, Any], proto: str) -> Tuple[List[List[int]], Any]:
    """[[from, to], ...] of a segment for "tcp" / "udp", and the raw value.
    The legacy form is a flat list of from/to strings (["80", "80", "443",
    "443"]); the new form a list of {from, to} (SDK add_segment docstring)."""
    legacy = get(seg, f"{proto}PortRanges") or []
    new = get(seg, f"{proto}PortRange") or []
    out: List[List[int]] = []
    vals = [as_str(v) for v in legacy] if isinstance(legacy, list) else []
    for a, b in zip(vals[0::2], vals[1::2]):
        lo, hi = _port(a), _port(b or a)
        if lo is not None and hi is not None:
            out.append([min(lo, hi), max(lo, hi)])
    for p in new if isinstance(new, list) else []:
        lo = _port(p.get("from")) if isinstance(p, dict) else None
        if lo is not None:
            hi = _port(p.get("to"))
            hi = lo if hi is None else hi
            r = [min(lo, hi), max(lo, hi)]
            if r not in out:
                out.append(r)
    out.sort()
    return out, {"legacy": legacy, "ranges": new} if (legacy or new) else []


# ── normalizers (pure; raw values kept beside interpretations) ──────────
def _app_types(seg: Dict[str, Any]) -> List[str]:
    common = get(seg, "commonAppsDto") or {}
    types = []
    for cfg in _items(get(common, "appsConfig")):
        for t in _items(get(cfg, "appTypes")):
            types.append(as_str(t).upper())
    return types


def normalize_segment(s: Dict[str, Any]) -> Dict[str, Any]:
    tcp, tcp_raw = port_ranges(s, "tcp")
    udp, udp_raw = port_ranges(s, "udp")
    types = _app_types(s)
    bypass = as_str(get(s, "bypassType")).upper()
    hr = as_str(get(s, "healthReporting")).upper()
    return {
        "id": as_str(get(s, "id")), "name": as_str(get(s, "name")) or as_str(get(s, "id")),
        "enabled": as_bool(get(s, "enabled")) is not False,
        "domains": [as_str(d) for d in _items(get(s, "domainNames")) if as_str(d)],
        "tcp": tcp, "udp": udp, "tcp_raw": tcp_raw, "udp_raw": udp_raw,
        "segment_group_id": as_str(get(s, "segmentGroupId")), "segment_group_name": as_str(get(s, "segmentGroupName")),
        "server_groups": _refs(get(s, "serverGroups")),
        "bypass_type": bypass, "bypass": bypass in ("ALWAYS", "ON_NET"),
        "health_reporting": hr, "health_check_type": as_str(get(s, "healthCheckType")).upper(),
        "double_encrypt": as_bool(get(s, "doubleEncrypt")),
        "inspect_traffic_with_zia": as_bool(get(s, "inspectTrafficWithZia")),
        "match_style": as_str(get(s, "matchStyle")).upper(),
        "microtenant_id": as_str(get(s, "microtenantId")),
        "flags": {
            "inspection": bool(get(s, "inspectionApps")) or "INSPECT" in types,
            "pra": bool(get(s, "praApps")) or "SECURE_REMOTE_ACCESS" in types,
            "browser_access": bool(get(s, "clientlessApps")) or "BROWSER_ACCESS" in types,
        },
        "app_types_raw": types,
        "description": as_str(get(s, "description"))[:300],
    }


def normalize_segment_group(g: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(g, "id")), "name": as_str(get(g, "name")) or as_str(get(g, "id")),
            "enabled": as_bool(get(g, "enabled")) is not False,
            "application_ids": _ref_ids(get(g, "applications")),
            "applications_listed": get(g, "applications") is not None}


def normalize_server_group(g: Dict[str, Any]) -> Dict[str, Any]:
    servers = []
    for x in _items(get(g, "servers")):
        if isinstance(x, dict):
            servers.append({"id": as_str(x.get("id")), "name": as_str(x.get("name")), "address": as_str(get(x, "address")),
                            "enabled": as_bool(get(x, "enabled")) is not False})
    dd_raw = get(g, "dynamicDiscovery")
    return {"id": as_str(get(g, "id")), "name": as_str(get(g, "name")) or as_str(get(g, "id")),
            "enabled": as_bool(get(g, "enabled")) is not False,
            "dynamic_discovery": as_bool(dd_raw), "dynamic_discovery_raw": dd_raw,
            "servers": servers, "servers_listed": get(g, "servers") is not None,
            "connector_groups": _refs(get(g, "appConnectorGroups")),
            "application_ids": _ref_ids(get(g, "applications"))}


def _status(x: Dict[str, Any]) -> Tuple[str, Optional[bool]]:
    raw = as_str(get(x, "controlChannelStatus") or get(x, "ctrlChannelStatus")).upper()
    if not raw:
        return "", None
    return raw, raw == ZPN_UP


def normalize_connector(c: Dict[str, Any]) -> Dict[str, Any]:
    raw, up = _status(c)
    return {"id": as_str(get(c, "id")), "name": as_str(get(c, "name")) or as_str(get(c, "id")),
            "enabled": as_bool(get(c, "enabled")) is not False,
            "group_id": as_str(get(c, "appConnectorGroupId")), "group_name": as_str(get(c, "appConnectorGroupName")),
            "status_raw": raw, "connected": up,
            "current_version": as_str(get(c, "currentVersion")), "expected_version": as_str(get(c, "expectedVersion")),
            "upgrade_status": as_str(get(c, "upgradeStatus")),
            "last_connect": epoch_seconds(get(c, "lastBrokerConnectTime")),
            "last_disconnect": epoch_seconds(get(c, "lastBrokerDisconnectTime")),
            "last_connect_raw": get(c, "lastBrokerConnectTime"), "last_disconnect_raw": get(c, "lastBrokerDisconnectTime")}


def normalize_connector_group(g: Dict[str, Any]) -> Dict[str, Any]:
    embedded = [normalize_connector(x) for x in _items(get(g, "connectors")) if isinstance(x, dict)]
    return {"id": as_str(get(g, "id")), "name": as_str(get(g, "name")) or as_str(get(g, "id")),
            "enabled": as_bool(get(g, "enabled")) is not False,
            "version_profile": as_str(get(g, "versionProfileName")), "location": as_str(get(g, "location")),
            "embedded_connectors": embedded, "server_group_ids": _ref_ids(get(g, "serverGroups"))}


def normalize_service_edge_group(g: Dict[str, Any]) -> Dict[str, Any]:
    edges = []
    for x in _items(get(g, "serviceEdges")):
        if isinstance(x, dict):
            raw, up = _status(x)
            edges.append({"id": as_str(x.get("id")), "name": as_str(x.get("name")), "status_raw": raw, "connected": up,
                          "enabled": as_bool(get(x, "enabled")) is not False})
    return {"id": as_str(get(g, "id")), "name": as_str(get(g, "name")) or as_str(get(g, "id")),
            "enabled": as_bool(get(g, "enabled")) is not False, "is_public": as_bool(get(g, "isPublic")),
            "service_edges": edges, "edges_listed": get(g, "serviceEdges") is not None}


def normalize_service_edge(e: Dict[str, Any]) -> Dict[str, Any]:
    raw, up = _status(e)
    return {"id": as_str(get(e, "id")), "name": as_str(get(e, "name")) or as_str(get(e, "id")),
            "enabled": as_bool(get(e, "enabled")) is not False,
            "group_id": as_str(get(e, "serviceEdgeGroupId")), "status_raw": raw, "connected": up,
            "current_version": as_str(get(e, "currentVersion"))}


def normalize_idp(i: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(i, "id")), "name": as_str(get(i, "name")) or as_str(get(i, "id")),
            "enabled": as_bool(get(i, "enabled")) is not False,
            "scim_enabled": as_bool(get(i, "scimEnabled")),
            "scim_policy": as_bool(get(i, "enableScimBasedPolicy")),
            "saml_policy_disabled": as_bool(get(i, "disableSamlBasedPolicy")),
            "sso_type": [as_str(x) for x in (get(i, "ssoType") or [])] if isinstance(get(i, "ssoType"), list) else as_str(get(i, "ssoType"))}


def normalize_simple(x: Dict[str, Any], *extra: str) -> Dict[str, Any]:
    out = {"id": as_str(get(x, "id")), "name": as_str(get(x, "name")) or as_str(get(x, "id"))}
    if get(x, "enabled") is not None:
        out["enabled"] = as_bool(get(x, "enabled")) is not False
    for k in extra:
        out[_snake(k)] = as_str(get(x, k))
    return out


def _operand_tokens(o: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One operand as one or more {type, lhs, rhs, name, idp_id}: v1 rules
    carry objectType/lhs/rhs; v2-shaped operands carry `values` or
    `entryValues` instead (SDK _create_conditions_v2) and are expanded."""
    t = as_str(get(o, "objectType")).upper()
    name, idp = as_str(get(o, "name")), as_str(get(o, "idpId"))
    if get(o, "lhs") is not None or get(o, "rhs") is not None:
        return [{"type": t, "lhs": as_str(get(o, "lhs")), "rhs": as_str(get(o, "rhs")), "name": name, "idp_id": idp}]
    out = []
    for v in _items(get(o, "values")):
        out.append({"type": t, "lhs": "id", "rhs": as_str(v), "name": name, "idp_id": idp})
    for ev in _items(get(o, "entryValues")):
        if isinstance(ev, dict):
            out.append({"type": t, "lhs": as_str(ev.get("lhs")), "rhs": as_str(ev.get("rhs")), "name": name, "idp_id": idp})
    return out


def normalize_rule(r: Dict[str, Any], index: int, policy: str) -> Dict[str, Any]:
    conds = []
    for c in _items(get(r, "conditions")):
        if not isinstance(c, dict):
            continue
        ops = []
        for o in _items(get(c, "operands")):
            if isinstance(o, dict):
                ops.extend(_operand_tokens(o))
        conds.append({"operator": (as_str(get(c, "operator")) or "OR").upper(), "negated": bool(as_bool(get(c, "negated"))),
                      "operands": ops})
    order_raw = get(r, "ruleOrder")
    try:
        order = int(str(order_raw).strip())
    except (TypeError, ValueError):
        order = None
    action_raw = get(r, "action")
    return {"id": as_str(get(r, "id")), "name": as_str(get(r, "name")) or as_str(get(r, "id")), "policy": policy,
            "order": order, "order_raw": order_raw, "index": index,
            "action": as_str(action_raw).upper(), "action_raw": action_raw,
            "disabled": bool(as_bool(get(r, "disabled"))), "disabled_raw": get(r, "disabled"),
            "default_rule": bool(as_bool(get(r, "defaultRule"))),
            "operator": (as_str(get(r, "operator")) or "AND").upper(),
            "conditions": conds,
            "server_group_ids": _ref_ids(get(r, "appServerGroups")),
            "connector_group_ids": _ref_ids(get(r, "appConnectorGroups")),
            # Redirection rules name Private Service Edge groups (PolicySetControllerV1.serviceEdgeGroups).
            "service_edge_group_ids": _ref_ids(get(r, "serviceEdgeGroups")),
            "service_edge_group_names": {x["id"]: x["name"][:200] for x in _refs(get(r, "serviceEdgeGroups")) if x["name"]},
            "inspection_profile_id": as_str(get(r, "zpnInspectionProfileId")),
            "inspection_profile_name": as_str(get(r, "zpnInspectionProfileName")),
            "isolation_profile_id": as_str(get(r, "zpnIsolationProfileId")),
            # Privileged capabilities (CAPABILITIES_POLICY): privilegedCapabilities.capabilities,
            # e.g. CLIPBOARD_COPY, FILE_DOWNLOAD, INSPECT_FILE_UPLOAD, RECORD_SESSION
            # (SDK add_capabilities_rule_v2). None when the rule carries no such block.
            "capabilities": _capabilities(get(r, "privilegedCapabilities")),
            # Credential rules (CREDENTIAL_POLICY) name a credential or a credential pool by
            # reference only; the credential itself is never read.
            "credential": _one_ref(get(r, "credential")), "credential_pool": _one_ref(get(r, "credentialPool")),
            "microtenant_id": as_str(get(r, "microtenantId")),
            "description": as_str(get(r, "description"))[:300]}


def _capabilities(v: Any) -> Optional[List[str]]:
    if not isinstance(v, dict):
        return None
    caps = get(v, "capabilities")
    return sorted({as_str(c).upper() for c in _items(caps) if as_str(c)})[:50] if caps is not None else []


def _one_ref(v: Any) -> Optional[Dict[str, str]]:
    if isinstance(v, dict) and as_str(v.get("id")):
        return {"id": as_str(v.get("id")), "name": as_str(v.get("name"))[:200]}
    return None


# AppProtection actions (SDK add_profile docstring: PASS, BLOCK or REDIRECT).
# PASS lets the request through and logs it, so a profile whose every known
# action is PASS only monitors. Global actions are "<CONTROLS>:<ACTION>"
# strings (globalControlActions, e.g. "PREDEFINED:PASS"; the shape is
# assumed from the values ZPA shows, the SDK types them only as strings).
INSPECTION_ACTIONS = ("PASS", "BLOCK", "REDIRECT")
_CONTROL_LISTS = ("predefinedControls", "customControls", "threatlabzControls", "websocketControls",
                  "predefinedADPControls", "predefinedApiControls")


def _name(x: Dict[str, Any]) -> str:
    """An object's name (else its id), capped: names are tenant text."""
    return (as_str(get(x, "name")) or as_str(get(x, "id")))[:300]


def normalize_inspection_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    actions: List[str] = []
    for g in _items(get(p, "globalControlActions")):
        word = as_str(g).upper().rsplit(":", 1)[-1]
        if word in INSPECTION_ACTIONS:
            actions.append(word)
    custom_ids: List[str] = []
    for key in _CONTROL_LISTS:
        for c in _items(get(p, key)):
            if not isinstance(c, dict):
                continue
            word = as_str(get(c, "action")).upper()
            if word in INSPECTION_ACTIONS:
                actions.append(word)
            if key == "customControls" and as_str(c.get("id")):
                custom_ids.append(as_str(c.get("id")))
    found = sorted(set(actions))
    return {"id": as_str(get(p, "id")), "name": _name(p),
            "paranoia_level": as_str(get(p, "paranoiaLevel")), "actions": found,
            "monitor_only": (found == ["PASS"]) if found else None,
            "custom_control_ids": custom_ids}


def normalize_custom_control(c: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(c, "id")), "name": _name(c),
            "action": as_str(get(c, "action")).upper(), "default_action": as_str(get(c, "defaultAction")).upper(),
            "severity": as_str(get(c, "severity")).upper(), "control_type": as_str(get(c, "controlType")).upper(),
            "profiles": _refs(get(c, "associatedInspectionProfileNames"))}


def normalize_server(x: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(x, "id")), "name": _name(x),
            "address": as_str(get(x, "address"))[:300], "enabled": as_bool(get(x, "enabled")) is not False,
            "server_group_ids": _ref_ids(get(x, "appServerGroupIds"))}


def normalize_business_continuity(x: Dict[str, Any]) -> Dict[str, Any]:
    """Only switches and timers: the settings also carry SAML private keys,
    certificates and IdP metadata, which are never kept."""
    return {"id": as_str(get(x, "id")),
            "backup_enabled": as_bool(get(x, "backupEnabled")),
            "switch_time_enabled": as_bool(get(x, "switchTimeEnabled")),
            "max_down_time": as_str(get(x, "maxAllowedDownTime"))[:20],
            "max_down_time_unit": as_str(get(x, "maxAllowedDownTimeUnit"))[:20],
            "new_user_support": as_bool(get(x, "newUserSupport")),
            "use_existing_idp": as_bool(get(x, "useExistingIdp"))}


def normalize_private_cloud(x: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(x, "id")), "name": _name(x),
            "enabled": as_bool(get(x, "enabled")) is not False, "fire_drill_enabled": as_bool(get(x, "fireDrillEnabled")),
            "controller_group_ids": _ref_ids(get(x, "siteControllerGroupIds"))}


def normalize_private_cloud_group(g: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(g, "id")), "name": _name(g),
            "enabled": as_bool(get(g, "enabled")) is not False, "site_id": as_str(get(g, "siteId")),
            "site_name": as_str(get(g, "siteName")), "location": as_str(get(g, "location"))[:200]}


def normalize_private_cloud_controller(c: Dict[str, Any]) -> Dict[str, Any]:
    raw, up = _status(c)
    return {"id": as_str(get(c, "id")), "name": _name(c),
            "enabled": as_bool(get(c, "enabled")) is not False,
            "group_id": as_str(get(c, "privateCloudControllerGroupId")), "status_raw": raw, "connected": up,
            "current_version": as_str(get(c, "currentVersion")), "expected_version": as_str(get(c, "expectedVersion"))}


def normalize_edge_connector(c: Dict[str, Any], group_key: str) -> Dict[str, Any]:
    """A Branch or Cloud Connector as ZPA lists it (no status field in the
    SDK models): name, switch and group only; enrollment certificates,
    fingerprints and IP ACLs are not kept."""
    return {"id": as_str(get(c, "id")), "name": _name(c),
            "enabled": as_bool(get(c, "enabled")) is not False, "group_id": as_str(get(c, group_key))}


def order_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rules in evaluation order: ruleOrder ascending, then as listed; the
    default rule (defaultRule) last."""
    big = 10 ** 9
    return sorted(rules, key=lambda r: (1 if r.get("default_rule") else 0, r["order"] if r.get("order") is not None else big, r.get("index", 0)))


# ── the read ────────────────────────────────────────────────────────────
def _triple(res: Any) -> Tuple[Any, Any, Any]:
    if isinstance(res, tuple):
        if len(res) == 3:
            return res
        if len(res) == 2:
            return res[0], None, res[1]
    return res, None, None


def _plain(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return item
    fn = getattr(item, "as_dict", None)
    if callable(fn):
        try:
            d = fn()
            if isinstance(d, dict):
                return d
        except Exception:  # noqa: BLE001 — a model that cannot render itself is skipped below
            pass
    return dict(getattr(item, "__dict__", {}) or {})


def raw_items(result: Any, resp: Any) -> List[Dict[str, Any]]:
    """The page's raw JSON objects when the response holds them (same count
    as the models), else the models as dicts."""
    items = list(result or [])
    getter = getattr(resp, "get_results", None)
    if callable(getter):
        try:
            raw = getter()
            if isinstance(raw, list) and len(raw) == len(items) and all(isinstance(x, dict) for x in raw):
                return [dict(x) for x in raw]
        except Exception:  # noqa: BLE001 — fall back to the models
            pass
    return [_plain(x) for x in items]


class _Gate:
    """Paces calls and honours Stop before each one."""

    def __init__(self, cancel: Optional[threading.Event], pace: float):
        self.cancel, self.pace, self.last = cancel, max(0.0, float(pace or 0)), None
        self.calls = 0

    def stopped(self) -> bool:
        return bool(self.cancel is not None and self.cancel.is_set())

    def before(self) -> None:
        if self.stopped():
            raise Stopped(STOPPED_REASON)
        if self.last is not None and self.pace:
            left = self.pace - (time.monotonic() - self.last)
            if left > 0:
                if self.cancel is not None:
                    if self.cancel.wait(left):
                        raise Stopped(STOPPED_REASON)
                else:
                    time.sleep(left)
        if self.stopped():
            raise Stopped(STOPPED_REASON)
        self.last = time.monotonic()
        self.calls += 1


_SECRET_WORDS = re.compile(r"(?i)(bearer|basic|token|secret|password|provisioning_?key|api_?key)\S*\s*[:=]?\s*\S+")
# A ZPA provisioning key's shape: "<n>|<cloud host>|<key>" (assumed from the
# values ZPA shows; the SDK does not document it).
_PROVISIONING_KEY = re.compile(r"\b\d{1,2}\|[^\s|\"']{3,}\|[^\s\"']{8,}")


def _err_text(err: Any) -> str:
    s = re.sub(r"\s+", " ", str(err or "")[:4000]).strip()
    s = _PROVISIONING_KEY.sub("[hidden]", s)
    s = _SECRET_WORDS.sub(r"\1 [hidden]", s)
    return s[:200] or "the API answered an error"


def _total_pages(resp: Any) -> Optional[int]:
    """totalPages as the page's JSON states it; None when it does not say.
    The SDK's own `_total_pages` defaults to 1 when the body omits it, so it
    is used only for a response that has no body to look at."""
    getter = getattr(resp, "get_body", None)
    if callable(getter):
        try:
            body = getter()
        except Exception:  # noqa: BLE001 — unknown, so the short-page rule decides
            return None
        if not isinstance(body, dict) or body.get("totalPages") in (None, ""):
            return None
        try:
            return int(str(body["totalPages"]).strip())
        except ValueError:
            return None
    total = getattr(resp, "_total_pages", None)
    return total if isinstance(total, int) and not isinstance(total, bool) else None


def list_all(call: Callable[[Dict[str, Any]], Any], gate: _Gate, max_pages: int = MAX_PAGES) -> Tuple[List[Dict[str, Any]], bool]:
    """Every page of one list: (items, complete). An empty page ends it;
    otherwise the stated totalPages decides (a server that answers fewer
    than PAGE_SIZE per page is still read to the end), and only when no
    total is stated does a short page end it."""
    out: List[Dict[str, Any]] = []
    for page in range(1, max_pages + 1):
        gate.before()
        result, resp, err = _triple(call({"page": str(page), "page_size": str(PAGE_SIZE)}))
        if err:
            raise ReadError(_err_text(err))
        items = raw_items(result, resp)
        out.extend(items)
        total = _total_pages(resp)
        if not items or (page >= total if total is not None else len(items) < PAGE_SIZE):
            return out, True
    return out, False


def customer_id_problem(client: Any) -> Optional[str]:
    """Why ZPA must not be called with this client, or None. An SDK client
    whose configuration carries no valid customer ID would build every ZPA
    path as /customers/None/...; the check is made before any ZPA call. A
    client with no SDK configuration (offline snapshots, test fakes) is not
    judged here: its own customer ID is fixed."""
    cfg = getattr(client, "_config", None)
    if not isinstance(cfg, dict) or not isinstance(cfg.get("client"), dict):
        return None
    cid = as_str(cfg["client"].get("customerId"))
    if not cid:
        return "The ZPA customer ID is missing (Connect to the tenant → Customer ID), so nothing was read from ZPA."
    if len(cid) > 64 or not re.fullmatch(r"[A-Za-z0-9]+", cid):
        return "The ZPA customer ID is not valid (letters and digits, at most 64), so nothing was read from ZPA."
    return None


def read(client: Any, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
         pace: Optional[float] = None, extended: bool = True) -> Dict[str, Any]:
    """Read the ZPA configuration once (see the module docstring). Returns
    the normalized snapshot; raises Stopped when Stop is clicked. Without
    `extended` the lists only ZPA analysis uses (EXTENDED_KEYS,
    EXTENDED_POLICIES) are not read: they are absent from the snapshot's
    collections, so anything that needs them says "not read"."""
    def _log(line: str) -> None:
        if log:
            log(line)

    zpa = getattr(client, "zpa", None)
    if zpa is None:
        raise ReadError("This sign-in has no ZPA API (the classic ZIA API reaches ZIA only).")
    problem = customer_id_problem(client)
    if problem:
        raise ReadError(problem)
    gate = _Gate(cancel, PACE_SECONDS if pace is None else pace)
    snap: Dict[str, Any] = {"read_at": time.time(), "collections": {}, "policies": {}, "scim_groups": {}}
    raw_lists: Dict[str, List[Dict[str, Any]]] = {}

    def one(key: str, label: str, call: Callable[[Dict[str, Any]], Any], max_pages: int = MAX_PAGES) -> Optional[List[Dict[str, Any]]]:
        _log(f"Reading ZPA {label}…")
        try:
            items, complete = list_all(call, gate, max_pages)
        except Stopped:
            raise
        except ReadError as e:
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False, "error": str(e)}
            _log(f"Could not read {label}: {e}")
            return None
        except Exception as e:  # noqa: BLE001 — one failed list never ends the read
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False, "error": _err_text(e)}
            _log(f"Could not read {label}: {_err_text(e)}")
            return None
        snap["collections"][key] = {"label": label, "read": True, "count": len(items), "complete": complete, "error": None}
        _log(f"Read {len(items)} {label}{'' if complete else ' (stopped at the page limit: the list is incomplete)'}.")
        return items

    for key, label, svc_name, method in COLLECTIONS:
        if not extended and key in EXTENDED_KEYS:
            continue
        svc = getattr(zpa, svc_name, None)
        fn = getattr(svc, method, None) if svc is not None else None
        if not callable(fn):
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False,
                                        "error": "not available in this SDK version"}
            continue
        raw_lists[key] = one(key, label, lambda q, _fn=fn: _fn(query_params=q)) or []
        if snap["collections"][key]["read"] is False:
            raw_lists.pop(key, None)

    for key, label, svc_name, method in SINGLE_CALL if extended else ():
        svc = getattr(zpa, svc_name, None)
        fn = getattr(svc, method, None) if svc is not None else None
        if not callable(fn):
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False,
                                        "error": "not available in this SDK version"}
            continue
        # One call (max_pages=1); the SDK method takes no paging parameters.
        raw_lists[key] = one(key, label, lambda q, _fn=fn: _fn(), 1) or []
        if snap["collections"][key]["read"] is False:
            raw_lists.pop(key, None)
        else:
            snap["collections"][key]["complete"] = True

    policies = getattr(zpa, "policies", None)
    for ptype, label in POLICY_TYPES:
        if not extended and ptype in EXTENDED_POLICIES:
            continue
        fn = getattr(policies, "list_rules", None) if policies is not None else None
        key = f"policy:{ptype}"
        if not callable(fn):
            snap["collections"][key] = {"label": label, "read": False, "count": 0, "complete": False, "error": "not available in this SDK version"}
            continue
        items = one(key, label, lambda q, _fn=fn, _t=ptype: _fn(_t, query_params=q))
        if items is not None:
            snap["policies"][ptype] = order_rules([normalize_rule(r, i, ptype) for i, r in enumerate(items)])

    norm = {"segments": normalize_segment, "segment_groups": normalize_segment_group, "server_groups": normalize_server_group,
            "connector_groups": normalize_connector_group, "connectors": normalize_connector,
            "service_edge_groups": normalize_service_edge_group, "service_edges": normalize_service_edge, "idps": normalize_idp,
            "saml_attributes": lambda x: dict(normalize_simple(x, "idpId", "samlName", "userAttribute"), idp_name=as_str(get(x, "idpName"))),
            "posture_profiles": lambda x: normalize_simple(x, "postureUdid", "platform"),
            "trusted_networks": lambda x: normalize_simple(x, "networkId"),
            "machine_groups": lambda x: normalize_simple(x),
            "servers": normalize_server, "inspection_profiles": normalize_inspection_profile,
            "custom_controls": normalize_custom_control, "business_continuity": normalize_business_continuity,
            "private_clouds": normalize_private_cloud, "private_cloud_groups": normalize_private_cloud_group,
            "private_cloud_controllers": normalize_private_cloud_controller,
            "branch_connector_groups": lambda x: normalize_simple(x), "cloud_connector_groups": lambda x: normalize_simple(x),
            "branch_connectors": lambda x: normalize_edge_connector(x, "branchConnectorGroupId"),
            "cloud_connectors": lambda x: normalize_edge_connector(x, "edgeConnectorGroupId")}
    for key, fn in norm.items():
        if key in raw_lists:
            snap[key] = [fn(x) for x in raw_lists[key]]
        else:
            snap[key] = None   # not read: the analysis says "not assessed", never "none"

    # SCIM groups: only for the IdPs the access rules name (lhs of SCIM_GROUP).
    sg = getattr(zpa, "scim_groups", None)
    fn = getattr(sg, "list_scim_groups", None) if sg is not None else None
    idp_ids = sorted({o["lhs"] for r in snap["policies"].get("access") or [] for c in r["conditions"] for o in c["operands"]
                      if o["type"] == "SCIM_GROUP" and o["lhs"]})
    for idp_id in idp_ids:
        if not callable(fn):
            break
        items = one(f"scim_groups:{idp_id}", f"SCIM groups of IdP {idp_id}", lambda q, _id=idp_id: fn(_id, query_params=q), SCIM_MAX_PAGES)
        if items is not None:
            snap["scim_groups"][idp_id] = {"complete": snap["collections"][f"scim_groups:{idp_id}"]["complete"],
                                           "groups": [normalize_simple(x, "idpGroupId") for x in items]}
    snap["calls"] = gate.calls
    _log(f"ZPA read finished: {gate.calls} API call{'' if gate.calls == 1 else 's'}.")
    return snap


def readable(snap: Dict[str, Any]) -> bool:
    """Whether anything at all was read."""
    return any(v.get("read") for v in (snap.get("collections") or {}).values())


def summary(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Counts per collection, for the page header."""
    out = {}
    for k in ("segments", "segment_groups", "server_groups", "connector_groups", "connectors", "service_edge_groups", "idps",
              "servers", "inspection_profiles", "custom_controls", "private_cloud_groups", "private_cloud_controllers",
              "branch_connector_groups", "branch_connectors", "cloud_connector_groups", "cloud_connectors"):
        v = snap.get(k)
        out[k] = None if v is None else len(v)
    out["rules"] = {k: len(v) for k, v in (snap.get("policies") or {}).items()}
    return out


def iter_rules(snap: Dict[str, Any], policy: str) -> Iterable[Dict[str, Any]]:
    return snap.get("policies", {}).get(policy) or []
