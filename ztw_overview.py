"""Cloud & Branch Connector (ZTW): read the connector configuration once,
show it in plain words and assess it. Read-only.

What is read (zscaler-sdk-python `client.ztw.*`, version 1.11.3; every
service, method and path below was checked in the installed SDK,
zscaler/ztw/*.py; each answers `(result, response, error)`):

  ec_groups.list_ec_groups                    GET /ztw/api/v1/ecgroup
  forwarding_rules.list_rules                 GET /ztw/api/v1/ecRules/ecRdr
  workload_groups.list_groups                 GET /ztw/api/v1/workloadGroups
  ip_source_groups.list_ip_source_groups      GET /ztw/api/v1/ipSourceGroups
  ip_destination_groups.list_ip_destination_groups  GET /ztw/api/v1/ipDestinationGroups
  forwarding_gateways.list_gateways           GET /ztw/api/v1/gateways
  location_management.list_locations          GET /ztw/api/v1/location
  location_template.list_location_templates   GET /ztw/api/v1/locationTemplate
  activate.get_status                         GET /ztw/api/v1/ecAdminActivateStatus
  admin_roles.list_roles                      GET /ztw/api/v1/adminRoles
  admin_users.list_admins                     GET /ztw/api/v1/adminUsers
  api_keys.list_api_keys                      GET /ztw/api/v1/apiKeys
  account_details.list_public_account_details GET /ztw/api/v1/publicCloudAccountDetails
  public_cloud_info.list_public_cloud_info    GET /ztw/api/v1/publicCloudInfo

The first five are the Path analyzer's workload read (workload_path.LISTS),
so one read here also serves "Traffic from a workload" there. Nothing is
written: no provisioning URL is read (provisioning_url is never called),
no API key is regenerated, nothing is activated.

Field names are the SDK models' (ztw/models/ecgroup.py ECGroup with ecVMs
{name, buildVersion, operationalStatus, status, upgradeStatus};
forwarding_rules.py ForwardingControlRule; forwarding_gateways.py
ForwardingGateways.failClosed; location_management.py LocationManagement
ofwEnabled / ipsControl; location_templates.py LocationTemplate.template;
activation.py Activation orgEditStatus / adminActivateStatus; admin_users.py,
admin_roles.py, api_keys.py ApiKeys {enabled, keyValue, lastModifiedTime};
public_cloud_info.py PublicCloudInfo permissionStatus / regionStatus).

Secrets and people: an API key's value, any password, token or
provisioning URL is masked before anything is kept (offline_tenant.scrub
plus PROTECTED below); admins are counted, never listed; location IP
addresses and VPN credentials are counted, never listed.

Assumed, not documented in the SDK (said on the page):
  * A connector instance is serving when its operationalStatus is ACTIVE
    (or, without one, its status list holds ACTIVE or ENABLED).
  * Activation: changes are pending when orgEditStatus or
    adminActivateStatus says EDITS_PRESENT, PENDING or IN_PROGRESS; done
    when it says EDITS_CLEARED, ACTIVE or DONE; anything else is unknown.
  * A location template's settings use the API's camelCase names
    (ofwEnabled, ipsControl) inside `template`; the SDK documents their
    snake_case spelling (location_template.add_location_template).
  * A forwarding rule with none of the destination criteria the SDK model
    names (addresses, IP groups, countries, categories, services,
    applications, ZPA segments) matches every destination.
  * A provisioning API key not changed for 365 days is due for rotation
    (Zscaler's guidance for API credentials; the age comes from
    lastModifiedTime, epoch seconds or milliseconds).
"""
from __future__ import annotations

import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

import offline_tenant
import workload_path
import zpa_reader
from zpa_reader import as_str, get

PRODUCT = "Cloud & Branch Connector"
SECTION = "ZTW — Cloud & Branch Connector"
BASE = "/ztw/api/v1"

EXTRA_LISTS = (
    ("forwarding_gateways", "forwarding gateways", "forwarding_gateways", "list_gateways"),
    ("locations", "connector locations", "location_management", "list_locations"),
    ("location_templates", "location templates", "location_template", "list_location_templates"),
    ("activation", "activation status", "activate", "get_status", "one"),
    ("admin_roles", "admin roles", "admin_roles", "list_roles"),
    ("admin_users", "admin users", "admin_users", "list_admins"),
    ("api_keys", "provisioning API keys", "api_keys", "list_api_keys"),
    ("account_details", "public cloud account details", "account_details", "list_public_account_details"),
    ("public_cloud_info", "public cloud accounts", "public_cloud_info", "list_public_cloud_info"),
)
LISTS = tuple(workload_path.LISTS) + EXTRA_LISTS

# The assessment's REST paths for the same collections (the snapshot's
# offline_tenant.CAPTURE entries and the checks below read these).
PATHS = {
    "ec_groups": f"{BASE}/ecgroup", "forwarding_rules": f"{BASE}/ecRules/ecRdr", "workload_groups": f"{BASE}/workloadGroups",
    "ip_source_groups": f"{BASE}/ipSourceGroups", "ip_destination_groups": f"{BASE}/ipDestinationGroups",
    "forwarding_gateways": f"{BASE}/gateways", "locations": f"{BASE}/location", "location_templates": f"{BASE}/locationTemplate",
    "activation": f"{BASE}/ecAdminActivateStatus", "admin_roles": f"{BASE}/adminRoles", "admin_users": f"{BASE}/adminUsers",
    "api_keys": f"{BASE}/apiKeys", "account_details": f"{BASE}/publicCloudAccountDetails", "public_cloud_info": f"{BASE}/publicCloudInfo",
}

NOTHING_IN_SCOPE = ("Cloud & Branch Connector is not ticked on the Scope page, so nothing was read. Tick it under Scope assessment "
                    "(OneAPI sign-in), then read again.")
NEEDS_ONEAPI = "The classic ZIA API sign-in cannot read Cloud & Branch Connector: sign in with a OneAPI (ZIdentity) API client."
STOPPED_REASON = workload_path.STOPPED_REASON
Stopped = workload_path.Stopped

MASK = "********"
# Masked on top of offline_tenant.scrub: a provisioning URL (it enrols a
# connector), a mobile app token list, VPN credentials and the location IP
# addresses (counted, not listed).
PROTECTED = re.compile(r"prov(isioning)?_?ur[il]|prov_?template_?url|mobile_?app_?tokens|vpn_?credentials|pre_?shared", re.I)
ROTATE_DAYS = 365
MAX_ROWS = 2000

ASSUMPTIONS = [
    "A connector is serving when its operational status is ACTIVE; the API does not document the other values.",
    "Activation is pending when the status says edits are present or pending; any other value is reported as unknown.",
    "A forwarding rule with no destination criteria matches every destination.",
    "A provisioning API key not changed for 365 days is due for rotation.",
    "Admins are counted, never listed; an API key's value, passwords, tokens and provisioning URLs are never read into the report.",
]

WHAT = {
    "ZTW.1": ("Every connector group has more than one connector",
              "A group with one connector is a single point of failure: when it is upgraded or fails, every workload behind it loses its "
              "path to Zscaler (or falls back to whatever the cloud route allows).",
              "Deploy a second connector in the group (another availability zone in the cloud, a second appliance or VM at a branch) and "
              "put both behind the load balancer. Where: Cloud & Branch Connector Admin Portal → Administration → Cloud Connector Groups."),
    "ZTW.2": ("Connectors are serving and on one software version",
              "A connector that is not active forwards nothing, and connectors on different versions behave differently and miss fixes.",
              "Bring the inactive connectors back (check the VM, its management and service networks), and let the upgrade window move every "
              "connector to the current version. Where: Administration → Cloud Connector Groups → the group → its connectors."),
    "ZTW.3": ("Workload traffic is not sent direct to the internet",
              "A DIRECT forwarding rule sends workload traffic straight out: it is never inspected by ZIA, so no threat protection, "
              "URL filtering or DLP applies to it.",
              "Change the rule's forward method to ZIA (or ZPA for private apps), or narrow it to the destinations that must bypass "
              "inspection and record why. Where: Forwarding Control → Forwarding rules."),
    "ZTW.4": ("Forwarding gateways fail closed",
              "A gateway that does not fail closed lets workload traffic out uninspected when the Zscaler service edges cannot be reached.",
              "Turn on Fail Closed for each ZIA forwarding gateway unless the business has accepted the risk for availability. "
              "Where: Forwarding Control → Gateways."),
    "ZTW.5": ("Connector configuration changes are activated",
              "Changes saved but not activated do not apply: the connectors keep forwarding by the old rules while the portal shows the new ones.",
              "Review the pending changes and activate them, or discard them. Where: the Activation button at the top of the Cloud & Branch "
              "Connector Admin Portal."),
    "ZTW.6": ("Connector locations have the firewall and IPS on",
              "A connector location without the Cloud Firewall or IPS lets non-web workload traffic through without the firewall policy or "
              "intrusion prevention.",
              "Turn on Enable Firewall and IPS Control on the connector locations and on the location templates new connectors use. "
              "Where: Administration → Location Templates, and ZIA → Administration → Locations for existing connector locations."),
    "ZTW.7": ("Connector admins: enough, not too many, least privilege",
              "One admin is a lock-out risk; many admins, password sign-in or no read-only role make it hard to see who changed the "
              "forwarding of workload traffic.",
              "Keep at least two named admins, remove the ones not needed, sign in through SSO rather than passwords, and give auditors a "
              "read-only role. Where: Administration → Admin Management."),
    "ZTW.8": ("Provisioning API keys are few and rotated",
              "A provisioning API key lets automation deploy connectors; an old or unused enabled key is a standing credential someone can misuse.",
              "Disable the keys nobody uses and regenerate the rest at least once a year (update the automation that uses them). "
              "Where: Administration → API Key Management."),
}


# ── the read ────────────────────────────────────────────────────────────
def read(client: Any, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
         pace: Optional[float] = None) -> Dict[str, Any]:
    """Read every connector collection once (workload_path.read's paging,
    pacing and Stop) and mask what must never be kept. Raises Stopped."""
    snap = workload_path.read(client, log=log, cancel=cancel, pace=pace, lists=LISTS)
    return sanitize(snap)


def _mask(value: Any, depth: int = 0) -> Any:
    if depth > 40:
        return None
    if isinstance(value, dict):
        return {k: (MASK if value[k] not in (None, "", [], {}) else value[k]) if PROTECTED.search(str(k)) else _mask(value[k], depth + 1)
                for k in value}
    if isinstance(value, list):
        return [_mask(x, depth + 1) for x in value]
    return value


def _seq(v: Any) -> List[Any]:
    return list(v) if isinstance(v, (list, tuple)) else []


def _dicts(v: Any) -> List[Dict[str, Any]]:
    return [x for x in _seq(v) if isinstance(x, dict)][:MAX_ROWS]


def _admin_row(a: Dict[str, Any]) -> Dict[str, Any]:
    """An admin without who they are: role and switches only."""
    role = get(a, "role")
    return {"role": as_str(get(role, "name") if isinstance(role, dict) else role), "disabled": bool(get(a, "disabled")),
            "isAuditor": bool(get(a, "isAuditor")), "isDefaultAdmin": bool(get(a, "isDefaultAdmin")),
            "isPasswordLoginAllowed": bool(get(a, "isPasswordLoginAllowed")), "isPasswordExpired": bool(get(a, "isPasswordExpired"))}


def _key_row(k: Dict[str, Any]) -> Dict[str, Any]:
    """An API key without its value."""
    by = get(k, "lastModifiedBy")
    return {"id": as_str(get(k, "id")), "enabled": bool(get(k, "enabled")), "lastModifiedTime": get(k, "lastModifiedTime"),
            "partner": bool(get(k, "partner")), "lastModifiedBy": as_str(get(by, "name")) if isinstance(by, dict) else "",
            "keyValue": MASK if get(k, "keyValue") else ""}


def _location_row(loc: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in loc.items() if not re.search(r"ipAddresses|vpnCredentials|ip_addresses|vpn_credentials", str(k))}
    out["ipAddressCount"] = len(_seq(get(loc, "ipAddresses")))
    out["vpnCredentialCount"] = len(_seq(get(loc, "vpnCredentials")))
    return out


def sanitize(snap: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of a read with secrets masked and people reduced to counts."""
    out = dict(snap)
    for key in [k for k, *_ in LISTS]:
        items = snap.get(key)
        if items is None:
            continue
        # Admins and keys are cut down to safe fields first: the generic
        # scrub would turn a switch named like a secret (isPasswordLoginAllowed)
        # into "(set)".
        if key == "admin_users":
            items = [_admin_row(a) for a in _dicts(items)]
        elif key == "api_keys":
            items = [_key_row(k) for k in _dicts(items)]
        elif key == "locations":
            # Counted from the answer, then the rest masked like any list.
            items = _mask(offline_tenant.scrub([_location_row(x) for x in _dicts(items)]))
        else:
            items = _mask(offline_tenant.scrub(_dicts(items)))
        out[key] = items
    return out


def from_rest(cl: Any, keys: Tuple[str, ...]) -> Tuple[Dict[str, Any], Dict[str, int]]:
    """The same collections through the assessment's REST client (cl.get):
    ({key: [items] or None}, {key: HTTP status}). Masked like a read."""
    data: Dict[str, Any] = {}
    codes: Dict[str, int] = {}
    for key in keys:
        d, c = cl.get(PATHS[key])
        codes[key] = c
        if c not in (200, 204):
            data[key] = None
            continue
        if key == "activation":
            data[key] = [d] if isinstance(d, dict) else []
        elif isinstance(d, list):
            data[key] = d
        elif isinstance(d, dict) and isinstance(d.get("list"), list):
            data[key] = d["list"]
        else:
            data[key] = []
    return sanitize(data), codes


# ── the analysis ────────────────────────────────────────────────────────
def _name(x: Any) -> str:
    return as_str(get(x, "name")) or as_str(get(x, "id")) if isinstance(x, dict) else as_str(x)


def _on(v: Any) -> Optional[bool]:
    return zpa_reader.as_bool(v)


def instances_of(g: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The connectors (VMs) of a group: {name, version, operational, status, upgrade, serving}."""
    out = []
    for vm in _dicts(get(g, "ecVMs")):
        op = as_str(get(vm, "operationalStatus")).upper()
        st = [as_str(s).upper() for s in _seq(get(vm, "status")) or ([get(vm, "status")] if get(vm, "status") else [])]
        serving = (op == "ACTIVE") if op else any(s in ("ACTIVE", "ENABLED") for s in st)
        out.append({"name": as_str(get(vm, "name")) or as_str(get(vm, "id")), "version": as_str(get(vm, "buildVersion")),
                    "operational": op or "not reported", "status": ", ".join(st), "upgrade": as_str(get(vm, "upgradeStatus")),
                    "serving": serving})
    return out


def groups_table(ec_groups: Any) -> List[Dict[str, Any]]:
    rows = []
    for g in _dicts(ec_groups):
        inst = instances_of(g)
        count = len(inst) or len(_seq(get(g, "ecInstances")))
        rows.append({"id": as_str(get(g, "id")), "name": _name(g), "deploy_type": as_str(get(g, "deployType")),
                     "platform": as_str(get(g, "platform")), "location": _name(get(g, "location")), "form_factor": as_str(get(g, "formFactor")),
                     "instances": count, "serving": sum(1 for i in inst if i["serving"]),
                     "versions": sorted({i["version"] for i in inst if i["version"]}), "connectors": inst,
                     "upgrade_window": " ".join(x for x in (as_str(get(g, "upgradeDayOfWeek")), as_str(get(g, "upgradeStartTime"))) if x),
                     "tunnel_mode": as_str(get(g, "tunnelMode"))})
    return rows


DEST_CRITERIA = ("destAddresses", "destIpGroups", "destIpv6Groups", "destCountries", "destIpCategories", "resCategories", "nwServices",
                 "nwServiceGroups", "nwApplications", "nwApplicationGroups", "appServiceGroups", "destWorkloadGroups", "zpaAppSegments",
                 "zpaApplicationSegments", "zpaApplicationSegmentGroups")
SRC_CRITERIA = ("srcIps", "srcIpGroups", "srcWorkloadGroups", "ecGroups", "locations", "locationGroups")


def _enabled_rule(r: Dict[str, Any]) -> bool:
    return as_str(get(r, "state")).upper() != "DISABLED"


def _rule_key(ir: Tuple[int, Dict[str, Any]]) -> Tuple[int, int, int]:
    """workload_path.order_rules' order: numbered rules, then the predefined
    negative ones (-2 before -1), then rules without an order."""
    i, r = ir
    try:
        o = int(get(r, "order"))
    except (TypeError, ValueError):
        return (2, 0, i)
    return (0, o, i) if o >= 0 else (1, o, i)


def _trace_destination(entry: str) -> str:
    """One destination the Path analyzer can trace for a rule's address
    entry: an address as it is, the first host of a network or range, a
    host name as it is; "" for anything else."""
    import ipaddress
    e = entry.strip()[:255]
    if not e:
        return ""
    try:
        return str(ipaddress.ip_address(e))
    except ValueError:
        pass
    try:
        net = ipaddress.ip_network(e, strict=False)
        return str(next(iter(net.hosts()), net.network_address))
    except ValueError:
        pass
    if "-" in e:
        return _trace_destination(e.split("-", 1)[0])
    e = e[2:] if e.startswith("*.") else e.lstrip(".")
    return e if re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", e) else ""


def rules_table(rules: Any) -> List[Dict[str, Any]]:
    rows = []
    for _i, r in sorted(enumerate(_dicts(rules)), key=_rule_key):
        method = as_str(get(r, "forwardMethod")).upper()
        dest = [k for k in DEST_CRITERIA if _seq(get(r, k))]
        src = [k for k in SRC_CRITERIA if _seq(get(r, k))]
        first_dest = _trace_destination(next((as_str(x) for x in _seq(get(r, "destAddresses")) if isinstance(x, str)), ""))
        rows.append({"id": as_str(get(r, "id")), "name": _name(r), "order": get(r, "order"), "enabled": _enabled_rule(r),
                     "forward_method": method or "not set", "goes": workload_path._forward(method)[1],
                     "broad": not dest, "destinations": ", ".join(_name(x) for k in dest for x in _seq(get(r, k))[:5])[:300],
                     "sources": ", ".join(_name(x) for k in src for x in _seq(get(r, k))[:5])[:300],
                     "connector_groups": [_name(x) for x in _seq(get(r, "ecGroups"))][:20],
                     "workload_groups": [_name(x) for x in _seq(get(r, "srcWorkloadGroups"))][:20],
                     "gateway": _name(get(r, "proxyGateway")) if get(r, "proxyGateway") else "", "first_destination": first_dest})
    return rows


def _status_word(v: Any) -> str:
    return as_str(v).upper().replace("-", "_").replace(" ", "_")


def activation_state(act: Any) -> Tuple[str, str]:
    """('pending' | 'done' | 'unknown', words) from the activation status (assumed values)."""
    a = (_dicts(act) or [{}])[0]
    vals = [_status_word(get(a, k)) for k in ("orgEditStatus", "adminActivateStatus", "orgLastActivateStatus") if get(a, k) not in (None, "")]
    if not vals:
        return "unknown", "The activation status was not reported."
    shown = ", ".join(vals)
    if any(any(w in v for w in ("EDITS_PRESENT", "PENDING", "IN_PROGRESS", "INPROGRESS")) for v in vals):
        return "pending", f"Changes are waiting to be activated (status: {shown})."
    if any(any(w in v for w in ("EDITS_CLEARED", "ACTIVE", "DONE")) for v in vals):
        return "done", f"Every saved change is active (status: {shown})."
    return "unknown", f"The activation status ({shown}) is not one this tool knows."


def _template_settings(t: Dict[str, Any]) -> Dict[str, Any]:
    tm = get(t, "template")
    return tm if isinstance(tm, dict) else {}


def _days_old(v: Any, now: float) -> Optional[int]:
    s = zpa_reader.epoch_seconds(v)
    return None if s is None else max(0, int((now - s) // 86400))


# ── the checks (shared by the page and the assessment) ──────────────────
# Each takes {key: [items] or None} and answers (status, detail, objects);
# status is PASS, FAIL, REVIEW or INFO (INFO = not applicable).
def _na_groups(data: Dict[str, Any]) -> Optional[Tuple[str, str, List[str]]]:
    if data.get("ec_groups") is None:
        return ("INFO", "The connector groups could not be read, so Cloud & Branch Connector is not licensed, not reachable or not "
                        "permitted to this API client: not assessed.", [])
    if not _dicts(data.get("ec_groups")):
        return ("INFO", "No Cloud or Branch Connector group is deployed on this tenant (not applicable).", [])
    return None


def check_single_instance(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    groups = groups_table(data.get("ec_groups"))
    single = [g["name"] for g in groups if g["instances"] < 2]
    if single:
        return ("REVIEW", f"{len(single)} of {len(groups)} connector group(s) have fewer than two connectors: {', '.join(single[:10])}. "
                          "Best Practice: run at least two connectors per group, in different availability zones, behind the load balancer.", single)
    return ("PASS", f"All {len(groups)} connector group(s) have two or more connectors.", [])


def check_health_versions(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    groups = groups_table(data.get("ec_groups"))
    inst = [dict(i, group=g["name"]) for g in groups for i in g["connectors"]]
    if not inst:
        return ("INFO", "The connector groups list no connectors with a status or version, so health and versions could not be assessed.", [])
    down = [f"{i['name']} ({i['group']}: {i['operational']})" for i in inst if not i["serving"]]
    versions = sorted({i["version"] for i in inst if i["version"]})
    failed = [f"{i['name']} ({i['upgrade']})" for i in inst if "FAIL" in i["upgrade"].upper()]
    if down:
        return ("FAIL", f"{len(down)} of {len(inst)} connector(s) are not serving: {', '.join(down[:10])}. "
                        "Best Practice: every connector in a group is active, so the group keeps its capacity and redundancy.", down)
    if len(versions) > 1 or failed:
        msg = []
        if len(versions) > 1:
            msg.append(f"{len(versions)} software versions are running ({', '.join(versions[:6])})")
        if failed:
            msg.append(f"upgrades failed on {', '.join(failed[:10])}")
        text = "; ".join(msg)
        return ("REVIEW", text[:1].upper() + text[1:] + ". Best Practice: one current version on every connector, kept there by the upgrade window.",
                failed or versions)
    return ("PASS", f"All {len(inst)} connector(s) are serving" + (f" on version {versions[0]}." if versions else "."), [])


def check_direct(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    if data.get("forwarding_rules") is None:
        return ("INFO", "The connector forwarding rules could not be read: not assessed.", [])
    rows = [r for r in rules_table(data.get("forwarding_rules")) if r["enabled"]]
    direct = [r for r in rows if r["forward_method"] == "DIRECT"]
    broad = [r["name"] for r in direct if r["broad"]]
    if broad:
        return ("FAIL", f"{len(broad)} enabled forwarding rule(s) send workload traffic DIRECT for every destination: {', '.join(broad[:10])}. "
                        "Best Practice: forward workload traffic to ZIA (or ZPA for private apps); a DIRECT rule names only the destinations "
                        "that must bypass inspection.", broad)
    if direct:
        names = [r["name"] for r in direct]
        return ("REVIEW", f"{len(direct)} enabled forwarding rule(s) send some workload traffic DIRECT, never inspected: {', '.join(names[:10])}. "
                          "Best Practice: keep each DIRECT rule to destinations with a recorded reason and review them regularly.", names)
    return ("PASS", f"None of the {len(rows)} enabled forwarding rule(s) sends workload traffic DIRECT.", [])


def check_fail_closed(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    if data.get("forwarding_gateways") is None:
        return ("INFO", "The forwarding gateways could not be read: not assessed.", [])
    gws = _dicts(data.get("forwarding_gateways"))
    if not gws:
        return ("INFO", "No forwarding gateway is configured (the connectors use the default ZIA gateway): not applicable.", [])
    open_ = [_name(g) for g in gws if _on(get(g, "failClosed")) is not True]
    if open_:
        return ("REVIEW", f"{len(open_)} of {len(gws)} forwarding gateway(s) do not fail closed: {', '.join(open_[:10])}. "
                          "Best Practice: fail closed, so workload traffic is held rather than sent out uninspected when Zscaler cannot be reached.", open_)
    return ("PASS", f"All {len(gws)} forwarding gateway(s) fail closed.", [])


def check_activation(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    if data.get("activation") is None:
        return ("INFO", "The activation status could not be read: not assessed.", [])
    state, words = activation_state(data.get("activation"))
    if state == "pending":
        return ("REVIEW", words + " Best Practice: activate reviewed changes promptly, so the connectors run what the portal shows.", [])
    if state == "done":
        return ("PASS", words, [])
    return ("INFO", words, [])


def check_location_security(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    locs = _dicts(data.get("locations"))
    tmpls = _dicts(data.get("location_templates"))
    if data.get("locations") is None and data.get("location_templates") is None:
        return ("INFO", "The connector locations and location templates could not be read: not assessed.", [])
    if not locs and not tmpls:
        return ("INFO", "No connector location or location template is listed: not applicable.", [])
    weak = []
    for x in locs:
        miss = [w for k, w in (("ofwEnabled", "firewall"), ("ipsControl", "IPS")) if _on(get(x, k)) is not True]
        if miss:
            weak.append(f"location {_name(x)} ({' and '.join(miss)} off)")
    for t in tmpls:
        s = _template_settings(t)
        miss = [w for k, w in (("ofwEnabled", "firewall"), ("ipsControl", "IPS")) if _on(get(s, k)) is not True]
        if miss:
            weak.append(f"template {_name(t)} ({' and '.join(miss)} off)")
    if weak:
        return ("REVIEW", f"{len(weak)} connector location(s) or template(s) leave the firewall or IPS off: {', '.join(weak[:10])}. "
                          "Best Practice: Enable Firewall and IPS Control on every connector location and template.", weak)
    return ("PASS", f"The firewall and IPS are on for {len(locs)} connector location(s) and {len(tmpls)} template(s).", [])


def check_admins(data: Dict[str, Any]) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    if data.get("admin_users") is None:
        return ("INFO", "The connector admin users could not be read: not assessed.", [])
    admins = [a for a in _dicts(data.get("admin_users")) if not a.get("disabled")]
    roles = _dicts(data.get("admin_roles"))
    issues = []
    if len(admins) < 2:
        issues.append(f"only {len(admins)} enabled admin(s)")
    if len(admins) > 20:
        issues.append(f"{len(admins)} enabled admins")
    pw = sum(1 for a in admins if a.get("isPasswordLoginAllowed"))
    if pw:
        issues.append(f"{pw} admin(s) may sign in with a password")
    readonly = [r for r in roles if _on(get(r, "isAuditor")) or as_str(get(r, "policyAccess")).upper() in ("READ_ONLY", "NONE")]
    if data.get("admin_roles") is not None and not readonly:
        issues.append("no read-only or auditor role")
    if issues:
        return ("REVIEW", "Connector admins: " + "; ".join(issues) + ". Best Practice: two to twenty named admins signing in through SSO, "
                          "and a read-only role for auditors.", [])
    return ("PASS", f"{len(admins)} enabled connector admin(s), SSO sign-in and a read-only role.", [])


def check_api_keys(data: Dict[str, Any], now: Optional[float] = None) -> Tuple[str, str, List[str]]:
    na = _na_groups(data)
    if na:
        return na
    if data.get("api_keys") is None:
        return ("INFO", "The provisioning API keys could not be read: not assessed.", [])
    now = time.time() if now is None else now
    keys = [k for k in _dicts(data.get("api_keys")) if k.get("enabled")]
    if not keys:
        return ("PASS", "No enabled provisioning API key.", [])
    old = []
    for k in keys:
        age = _days_old(k.get("lastModifiedTime"), now)
        if age is None or age > ROTATE_DAYS:
            old.append(f"key {k.get('id') or '?'} ({'age unknown' if age is None else f'{age} days'})")
    if old:
        return ("REVIEW", f"{len(old)} of {len(keys)} enabled provisioning API key(s) have not been changed for over {ROTATE_DAYS} days: "
                          f"{', '.join(old[:10])}. Best Practice: disable unused keys and regenerate the rest yearly. (Key values are never read into this report.)", old)
    return ("PASS", f"{len(keys)} enabled provisioning API key(s), all changed within {ROTATE_DAYS} days.", [])


CHECKS: Tuple[Tuple[str, Callable[..., Tuple[str, str, List[str]]], Tuple[str, ...]], ...] = (
    ("ZTW.1", check_single_instance, ("ec_groups",)),
    ("ZTW.2", check_health_versions, ("ec_groups",)),
    ("ZTW.3", check_direct, ("ec_groups", "forwarding_rules")),
    ("ZTW.4", check_fail_closed, ("ec_groups", "forwarding_gateways")),
    ("ZTW.5", check_activation, ("ec_groups", "activation")),
    ("ZTW.6", check_location_security, ("ec_groups", "locations", "location_templates")),
    ("ZTW.7", check_admins, ("ec_groups", "admin_users", "admin_roles")),
    ("ZTW.8", check_api_keys, ("ec_groups", "api_keys")),
)
SEVERITY = {"FAIL": "high", "REVIEW": "medium", "INFO": "info", "PASS": "pass"}


def assess(data: Dict[str, Any], now: Optional[float] = None) -> List[Dict[str, Any]]:
    """Every check as {id, title, status, severity, detail, why, fix, objects}."""
    out = []
    for cid, fn, _keys in CHECKS:
        st, detail, objs = fn(data, now) if fn is check_api_keys else fn(data)
        title, why, fix = WHAT[cid]
        out.append({"id": cid, "title": title, "status": st, "severity": SEVERITY[st], "detail": detail, "why": why, "fix": fix,
                    "objects": list(objs)[:50]})
    return out


# ── the report ──────────────────────────────────────────────────────────
def _yn(v: Any) -> str:
    return {True: "Yes", False: "No"}.get(_on(v), "Not set")


def analyse(snap: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    """The page's report from a (sanitized) read: summary counts, tables,
    findings, assumptions. Never a secret, never a person."""
    now = time.time() if now is None else now
    groups = groups_table(snap.get("ec_groups"))
    rules = rules_table(snap.get("forwarding_rules"))
    findings = assess(snap, now)
    gateways = [{"name": _name(g), "fail_closed": _yn(get(g, "failClosed")), "primary": as_str(get(g, "primaryType")),
                 "secondary": as_str(get(g, "secondaryType")), "description": as_str(get(g, "description"))[:200]}
                for g in _dicts(snap.get("forwarding_gateways"))]
    locations = [{"name": _name(x), "firewall": _yn(get(x, "ofwEnabled")), "ips": _yn(get(x, "ipsControl")),
                  "ssl_scan": _yn(get(x, "sslScanEnabled")), "xff": _yn(get(x, "xffForwardEnabled")),
                  "auth_required": _yn(get(x, "authRequired")), "cloud_account": as_str(get(x, "publicCloudAccountId")),
                  "ip_addresses": x.get("ipAddressCount", 0), "vpn_credentials": x.get("vpnCredentialCount", 0)}
                 for x in _dicts(snap.get("locations"))]
    templates = []
    for t in _dicts(snap.get("location_templates")):
        s = _template_settings(t)
        templates.append({"name": _name(t), "prefix": as_str(get(s, "templatePrefix")), "firewall": _yn(get(s, "ofwEnabled")),
                          "ips": _yn(get(s, "ipsControl")), "xff": _yn(get(s, "xffForwardEnabled")), "auth_required": _yn(get(s, "authRequired")),
                          "editable": _yn(get(t, "editable"))})
    admins = _dicts(snap.get("admin_users"))
    enabled = [a for a in admins if not a.get("disabled")]
    roles = [{"name": _name(r), "type": as_str(get(r, "roleType")), "policy_access": as_str(get(r, "policyAccess")),
              "auditor": _yn(get(r, "isAuditor")), "admins": sum(1 for a in admins if a.get("role") == _name(r))}
             for r in _dicts(snap.get("admin_roles"))]
    keys = _dicts(snap.get("api_keys"))
    key_rows = [{"id": k.get("id"), "enabled": _yn(k.get("enabled")), "age_days": _days_old(k.get("lastModifiedTime"), now),
                 "partner": _yn(k.get("partner")), "value": MASK if k.get("keyValue") else "not read"} for k in keys]
    clouds = []
    for c in _dicts(snap.get("public_cloud_info")):
        regions = _dicts(get(c, "regionStatus"))
        clouds.append({"name": _name(c), "cloud": as_str(get(c, "cloudType")), "permission_status": as_str(get(c, "permissionStatus")) or "not reported",
                       "regions": len(regions), "regions_ok": sum(1 for r in regions if _on(get(r, "status")) is True),
                       "account_groups": ", ".join(_name(x) for x in _dicts(get(c, "accountGroups"))[:10])})
    accounts = len(_dicts(snap.get("account_details")))
    act_state, act_words = activation_state(snap.get("activation")) if snap.get("activation") is not None else ("unknown", "Not read.")
    inst = [i for g in groups for i in g["connectors"]]
    counts = {"groups": len(groups), "connectors": sum(g["instances"] for g in groups), "serving": sum(1 for i in inst if i["serving"]),
              "single_instance_groups": sum(1 for g in groups if g["instances"] < 2),
              "versions": len({i["version"] for i in inst if i["version"]}),
              "rules": len(rules), "direct_rules": sum(1 for r in rules if r["enabled"] and r["forward_method"] == "DIRECT"),
              "gateways": len(gateways), "locations": len(locations), "templates": len(templates),
              "admins": len(admins), "admins_enabled": len(enabled), "admins_password": sum(1 for a in enabled if a.get("isPasswordLoginAllowed")),
              "roles": len(roles), "api_keys": len(keys), "api_keys_enabled": sum(1 for k in keys if k.get("enabled")),
              "cloud_accounts": len(clouds), "account_details": accounts,
              "fail": sum(1 for f in findings if f["status"] == "FAIL"), "review": sum(1 for f in findings if f["status"] == "REVIEW"),
              "pass": sum(1 for f in findings if f["status"] == "PASS"), "na": sum(1 for f in findings if f["status"] == "INFO")}
    return {"kind": "ztw", "product": PRODUCT, "counts": counts, "findings": findings, "groups": groups, "rules": rules,
            "gateways": gateways, "locations": locations, "templates": templates, "activation": {"state": act_state, "words": act_words},
            "roles": roles, "api_keys": key_rows, "cloud_accounts": clouds,
            "collections": dict(snap.get("collections") or {}), "assumptions": list(ASSUMPTIONS)}


def summary_lines(rep: Dict[str, Any]) -> List[str]:
    """The overview in plain sentences."""
    c = rep.get("counts") or {}
    out = [f"{c.get('groups', 0)} connector group(s) with {c.get('connectors', 0)} connector(s); {c.get('serving', 0)} serving."]
    if c.get("single_instance_groups"):
        out.append(f"{c['single_instance_groups']} group(s) have a single connector: no redundancy.")
    if c.get("versions", 0) > 1:
        out.append(f"{c['versions']} software versions are running.")
    out.append(f"{c.get('rules', 0)} forwarding rule(s); {c.get('direct_rules', 0)} enabled rule(s) send workload traffic DIRECT, never inspected.")
    out.append(f"Activation: {(rep.get('activation') or {}).get('words') or 'not read.'}")
    out.append(f"{c.get('admins_enabled', 0)} enabled connector admin(s) (counted, not listed); {c.get('api_keys_enabled', 0)} enabled provisioning API key(s) (values never read).")
    return out


def workbook(rep: Dict[str, Any]) -> bytes:
    """The report as an Excel workbook (xlsx_writer escapes every cell)."""
    import xlsx_writer
    wb = xlsx_writer.Workbook(title=f"{PRODUCT} {rep.get('tenant_label') or ''}".strip(), subject=f"Zscaler Made Easy: {PRODUCT}")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([["Tenant", rep.get("tenant_label") or ""], ["Generated", rep.get("generated_at") or ""]])
    for k, v in (rep.get("counts") or {}).items():
        s.append([k.replace("_", " ").capitalize(), v])
    for line in summary_lines(rep):
        s.append(["Overview", line])
    for k, v in (rep.get("collections") or {}).items():
        s.append([f"Read: {v.get('label') or k}", f"{v.get('count')} read" if v.get("read") else f"not read: {v.get('error') or ''}"])
    f = wb.add_sheet("Findings", columns=["ID", "Status", "Severity", "Title", "What was found", "Why it matters", "How to fix"])
    for x in rep.get("findings") or []:
        f.append([x["id"], x["status"], x["severity"], x["title"], x["detail"], x["why"], x["fix"]])
    g = wb.add_sheet("Connector groups", columns=["Group", "Deploy type", "Platform", "Location", "Connectors", "Serving", "Versions", "Upgrade window"])
    for x in rep.get("groups") or []:
        g.append([x["name"], x["deploy_type"], x["platform"], x["location"], x["instances"], x["serving"], ", ".join(x["versions"]), x["upgrade_window"]])
    i = wb.add_sheet("Connectors", columns=["Group", "Connector", "Version", "Operational status", "Upgrade status", "Serving"])
    for x in rep.get("groups") or []:
        for c in x["connectors"]:
            i.append([x["name"], c["name"], c["version"], c["operational"], c["upgrade"], "Yes" if c["serving"] else "No"])
    r = wb.add_sheet("Forwarding rules", columns=["Order", "Rule", "Enabled", "Forward method", "Where it goes", "Destinations", "Sources", "Gateway"])
    for x in rep.get("rules") or []:
        r.append([x["order"], x["name"], "Yes" if x["enabled"] else "No", x["forward_method"], x["goes"],
                  x["destinations"] or "every destination", x["sources"] or "every source", x["gateway"]])
    gw = wb.add_sheet("Gateways", columns=["Gateway", "Fail closed", "Primary", "Secondary", "Description"])
    for x in rep.get("gateways") or []:
        gw.append([x["name"], x["fail_closed"], x["primary"], x["secondary"], x["description"]])
    lo = wb.add_sheet("Locations", columns=["Kind", "Name", "Firewall", "IPS", "XFF", "Authentication", "IP addresses (count)", "VPN credentials (count)"])
    for x in rep.get("locations") or []:
        lo.append(["Location", x["name"], x["firewall"], x["ips"], x["xff"], x["auth_required"], x["ip_addresses"], x["vpn_credentials"]])
    for x in rep.get("templates") or []:
        lo.append(["Template", x["name"], x["firewall"], x["ips"], x["xff"], x["auth_required"], "", ""])
    ad = wb.add_sheet("Admin roles", columns=["Role", "Type", "Policy access", "Auditor", "Admins (count)"])
    for x in rep.get("roles") or []:
        ad.append([x["name"], x["type"], x["policy_access"], x["auditor"], x["admins"]])
    k = wb.add_sheet("API keys", columns=["Key ID", "Enabled", "Age (days)", "Partner key", "Value"])
    for x in rep.get("api_keys") or []:
        k.append([x["id"], x["enabled"], x["age_days"] if x["age_days"] is not None else "unknown", x["partner"], x["value"]])
    pc = wb.add_sheet("Cloud accounts", columns=["Account", "Cloud", "Permission status", "Regions", "Regions OK", "Account groups"])
    for x in rep.get("cloud_accounts") or []:
        pc.append([x["name"], x["cloud"], x["permission_status"], x["regions"], x["regions_ok"], x["account_groups"]])
    a = wb.add_sheet("Assumptions", columns=["Assumption"], autofilter=False)
    for line in rep.get("assumptions") or []:
        a.append([line])
    return wb.to_bytes()
