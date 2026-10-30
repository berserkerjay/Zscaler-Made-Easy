"""The rule editor's forms: which fields each ZIA rule type takes, how they
are checked, how they become the SDK's add_rule / update_rule payload, how
a rule is placed (order and admin rank) and the plain sentence the preview
shows. Pure: nothing here reads or writes a tenant (ops_rule_editor does,
through the Bulk changes engine).

Rule types (POLICY keys) and their zscaler-sdk-python 1.11.3 services and
models, verified against the installed SDK:

  url_filtering      zia.url_filtering            models/url_filtering_rules.py   URLFilteringRule
  firewall           zia.cloud_firewall_rules     models/cloud_firewall_rules.py  FirewallRule
  ssl_inspection     zia.ssl_inspection_rules     models/ssl_inspection_rules.py  SSLInspectionRules
  forwarding         zia.forwarding_control       models/forwarding_control_policy.py ForwardingControlRule
  web_dlp            zia.dlp_web_rules            models/dlp_web_rules.py         DLPWebRules
  dns_control        zia.cloud_firewall_dns       models/cloud_firewall_dns_rules.py FirewallDNSRules
  firewall_ips       zia.cloud_firewall_ips       models/cloud_firewall_ips_rules.py FirewallIPSrules
  file_type_control  zia.file_type_control_rule   models/filetyperules.py         FileTypeControlRules
  sandbox            zia.sandbox_rules            models/sandboxrules.py          SandboxRules
  cloud_app_control  zia.cloudappcontrol          models/cloudappcontrol.py       CloudApplicationControl

Each service has list_rules, get_rule, add_rule(**kw), update_rule(id,
**kw) and delete_rule(id) (Cloud App Control takes the rule type first).
The SDK turns the snake_case keyword arguments into the API's camelCase
and, for the reference fields in zscaler/utils.py reformat_params
(locations, groups, users, nw_services, ...), a list of ids into
[{"id": ...}]; this module sends references as [{"id": ...}] already, so
the payload is the same either way. A form offers only fields the SDK
model has (tests/test_rule_editor.py builds every model from a full
payload and checks each field survives), and only the common ones: a
field the form does not offer is kept as the tenant has it on an edit.

Enumerations come from the SDK docstrings (add_rule "Supported values")
and from ops_zia_baseline, which uses them on real tenants; where neither
says, the value is marked assumed below and the tenant refuses what it
does not take (the preview cannot know, the apply reports ZIA's answer).

Placement (order and admin rank) follows the rank inheritance approach
of the app's rank work (admin_rank): with the tenant's Admin Ranking on, a
new rule takes the rank of the rule it sits above (going last, of the rule
just above it), so asking for order N really puts it at N; with Admin
Ranking off, or not read, it takes rank 7, as every builder did before. A
duplicate keeps its source's rank and sits right below it.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import admin_rank

MAX_NAME = 31            # ZIA refuses rule names longer than 31 characters (ops_zia_baseline; assumed for forwarding and IPS)
MAX_NAME_DLP = 127       # Web DLP rules took longer names on a real tenant (pack_channels.RULE_NAME_MAX); 127 is assumed
DESC_MAX = 255           # bytes; ZIA refuses longer descriptions on several objects (ops_zia_baseline.DESC_MAX)
MAX_LIST = 1000          # entries per list field
MAX_ADDR_LEN = 255
LEGACY_RANK = admin_rank.LOWEST

_UNSAFE_TEXT = re.compile("[\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]")
_UNSAFE_NAME = re.compile("[<>\x00-\x1f\x7f-\x9f​-‏‪-‮⁠-⁩﻿]")
_ENUM = re.compile(r"^[A-Z][A-Z0-9_]{0,79}$")
_COUNTRY = re.compile(r"^COUNTRY_[A-Z]{2}$")
_CAC_ACTION = re.compile(r"^(ALLOW|BLOCK|CAUTION|ISOLATE|DENY)_[A-Z0-9_]{1,76}$")
_HOST = re.compile(r"^(\*\.)?(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z][a-z0-9-]{0,62}$")


class FormError(ValueError):
    """A form value this rule type cannot take; the message says which and why."""


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------
METHODS = ("CONNECT", "DELETE", "GET", "HEAD", "OPTIONS", "OTHER", "POST", "PUT", "TRACE")      # url_filtering.add_rule docstring
USER_AGENTS = ("OPERA", "FIREFOX", "MSIE", "MSEDGE", "CHROME", "SAFARI", "OTHER", "MSCHREDGE")  # url_filtering.add_rule docstring
TRUST = ("UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST")                 # url_filtering.add_rule docstring
URL_PROTOCOLS = ("ANY_RULE", "HTTPS_RULE", "HTTP_RULE", "FTP_RULE", "TUNNEL_RULE", "TUNNELSSL_RULE",
                 "SSL_RULE", "FOHTTP_RULE", "WEBSOCKETSSL_RULE", "WEBSOCKET_RULE")                # assumed (Zscaler's protocol list)
SSL_PLATFORMS = ("SCAN_IOS", "SCAN_ANDROID", "SCAN_MACOS", "SCAN_WINDOWS", "NO_CLIENT_CONNECTOR", "SCAN_LINUX")  # pack_channels.SSL_PLATFORMS
FTC_PROTOCOLS = ("ANY_RULE", "FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE")             # assumed
SANDBOX_PROTOCOLS = ("FOHTTP_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE")                      # ops_zia_baseline
SANDBOX_CATEGORIES = ("ADWARE_BLOCK", "BOTMAL_BLOCK", "ANONYP2P_BLOCK", "RANSOMWARE_BLOCK", "OFFSEC_TOOLS_BLOCK", "SUSPICIOUS_BLOCK")
DLP_PROTOCOLS = ("ANY_RULE", "FTP_RULE", "HTTPS_RULE", "HTTP_RULE")                              # assumed
DNS_PROTOCOLS = ("ANY_RULE", "TCP_RULE", "UDP_RULE", "DOHTTPS_RULE")                             # assumed
SEVERITY = ("RULE_SEVERITY_HIGH", "RULE_SEVERITY_MEDIUM", "RULE_SEVERITY_LOW", "RULE_SEVERITY_INFO")  # assumed (the API's names)
FWD_METHODS = ("DIRECT", "PROXYCHAIN", "ZIA", "ZPA", "ECZPA", "ECSELF", "DROP", "ENATDEDIP", "GEOIP")  # forwarding add_rule docstring

ACTIONS: Dict[str, Dict[str, str]] = {
    "url_filtering": {"ALLOW": "allow", "CAUTION": "show a caution page before", "BLOCK": "block"},
    "firewall": {"ALLOW": "allow", "BLOCK_DROP": "block (drop silently)", "BLOCK_RESET": "block (reset the connection)",
                 "BLOCK_ICMP": "block (send ICMP unreachable)", "EVAL_NWAPP": "evaluate the network application of"},
    "ssl_inspection": {"DECRYPT": "inspect (decrypt)", "DO_NOT_DECRYPT": "not inspect", "BLOCK": "block"},
    "web_dlp": {"ALLOW": "allow and log (monitor)", "BLOCK": "block", "ICAP_RESPONSE": "send to the ICAP server"},
    "dns_control": {"ALLOW": "allow", "BLOCK": "block"},
    "firewall_ips": {"ALLOW": "allow", "BLOCK_DROP": "block (drop silently)", "BLOCK_RESET": "block (reset the connection)",
                     "BYPASS_IPS": "skip IPS inspection for"},
    "file_type_control": {"ALLOW": "allow", "CAUTION": "show a caution page before", "BLOCK": "block"},
    "sandbox": {"ALLOW_SCAN": "allow, then scan in the Sandbox,", "QUARANTINE": "hold (quarantine) until the Sandbox has scanned",
                "ALLOW_NOSCAN": "allow without a Sandbox scan", "QUARANTINE_ISOLATE": "hold and open in isolation until scanned"},
    "forwarding": {"DIRECT": "send directly (no Zscaler proxy)", "PROXYCHAIN": "forward through a proxy gateway",
                   "ZIA": "forward to ZIA", "ZPA": "forward to ZPA through a ZPA gateway", "DROP": "drop",
                   "ECZPA": "forward to ZPA through Cloud Connector", "ECSELF": "forward through Cloud Connector itself",
                   "ENATDEDIP": "forward through a dedicated IP gateway", "GEOIP": "forward by geolocation"},
}
# Monitor-only defaults: what a new rule gets until the person picks an action.
DEFAULT_ACTION = {"url_filtering": "ALLOW", "firewall": "ALLOW", "ssl_inspection": "DO_NOT_DECRYPT", "web_dlp": "ALLOW",
                  "dns_control": "ALLOW", "firewall_ips": "ALLOW", "file_type_control": "ALLOW", "sandbox": "ALLOW_SCAN",
                  "forwarding": "DIRECT"}

# ---------------------------------------------------------------------------
# References: objects a form picks by name (read through these SDK calls)
# ---------------------------------------------------------------------------
# key: (label, service, method, value key, label keys, kind) — kind "id":
# sent as {"id": n}; "value": the object's own value is sent (an
# enumeration string such as a URL category id or an application name).
REFS: Dict[str, Dict[str, Any]] = {
    "locations": {"label": "Locations", "call": ("locations", "list_locations_lite"), "kind": "id"},
    "location_groups": {"label": "Location groups", "call": ("locations", "list_location_groups_lite"), "kind": "id"},
    "groups": {"label": "Groups", "call": ("user_management", "list_groups"), "kind": "id"},
    "departments": {"label": "Departments", "call": ("user_management", "list_departments"), "kind": "id"},
    "users": {"label": "Users", "call": ("user_management", "list_users"), "kind": "id"},
    "labels": {"label": "Rule labels", "call": ("rule_labels", "list_labels"), "kind": "id"},
    "time_windows": {"label": "Time intervals", "call": ("cloud_firewall", "list_time_windows_lite"), "kind": "id"},
    "dlp_engines": {"label": "DLP engines", "call": ("dlp_engine", "list_dlp_engines"), "kind": "id"},
    "dlp_dictionaries": {"label": "DLP dictionaries", "call": ("dlp_dictionary", "list_dicts_lite"), "kind": "id"},
    "src_ip_groups": {"label": "Source IP groups", "call": ("cloud_firewall", "list_ip_source_groups_lite"), "kind": "id"},
    "dest_ip_groups": {"label": "Destination IP groups", "call": ("cloud_firewall", "list_ip_destination_groups_lite"), "kind": "id"},
    "nw_services": {"label": "Network services", "call": ("cloud_firewall", "list_network_services_lite"), "kind": "id"},
    "nw_service_groups": {"label": "Network service groups", "call": ("cloud_firewall", "list_network_svc_groups_lite"), "kind": "id"},
    "proxy_gateways": {"label": "Proxy gateways", "call": ("proxies", "list_proxy_gateway_lite"), "kind": "id"},
    "zpa_gateways": {"label": "ZPA gateways", "call": ("zpa_gateway", "list_gateways"), "kind": "id"},
    "dns_gateways": {"label": "DNS gateways", "call": ("dns_gatways", "list_dns_gateways"), "kind": "id"},
    "url_categories": {"label": "URL categories", "call": ("url_categories", "list_categories_lite"), "kind": "value",
                       "value": ("id",), "name": ("configured_name", "id")},
    "cloud_apps": {"label": "Cloud applications", "call": ("cloud_applications", "list_cloud_app_policy"), "kind": "value",
                   "value": ("app",), "name": ("app_name", "app")},
    "nw_applications": {"label": "Network applications", "call": ("cloud_firewall", "list_network_apps"), "kind": "value",
                        "value": ("id",), "name": ("description", "id")},
}
MAX_REF_ROWS = 5000        # rows kept per reference list (a larger list is cut, and the picker says so)


# ---------------------------------------------------------------------------
# Fields
# ---------------------------------------------------------------------------
# kind: text | longtext | enum | enums | refs | ref | names | addrs | countries | bool | int | ssl_action | cac_actions
def _f(kind: str, label: str, **kw: Any) -> Dict[str, Any]:
    return dict(kind=kind, label=label, **kw)


def _who(*, labels: bool = True, time: bool = True, users: bool = True) -> Dict[str, Dict[str, Any]]:
    out = {"locations": _f("refs", "Locations", ref="locations", who=True),
           "location_groups": _f("refs", "Location groups", ref="location_groups", who=True),
           "groups": _f("refs", "Groups", ref="groups", who=True),
           "departments": _f("refs", "Departments", ref="departments", who=True)}
    if users:
        out["users"] = _f("refs", "Users", ref="users", who=True)
    if time:
        out["time_windows"] = _f("refs", "Time intervals", ref="time_windows", when=True)
    if labels:
        out["labels"] = _f("refs", "Rule labels", ref="labels")
    return out


def _base() -> Dict[str, Dict[str, Any]]:
    return {"name": _f("text", "Name", required=True), "description": _f("longtext", "Description")}


POLICY: Dict[str, Dict[str, Any]] = {
    "url_filtering": {
        "label": "URL filtering", "service": "url_filtering", "channel": "url", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("enum", "Action", values=tuple(ACTIONS["url_filtering"]), required=True),
                   "url_categories": _f("names", "URL categories", ref="url_categories", what=True, required=True),
                   "protocols": _f("enums", "Protocols", values=URL_PROTOCOLS, default=["ANY_RULE"], required=True),
                   "request_methods": _f("enums", "HTTP methods", values=METHODS),
                   "user_agent_types": _f("enums", "Browsers (user agents)", values=USER_AGENTS),
                   "device_trust_levels": _f("enums", "Device trust levels", values=TRUST),
                   "block_override": _f("bool", "Let users override a Block"),
                   **_who()}},
    "firewall": {
        "label": "Cloud Firewall", "service": "cloud_firewall_rules", "channel": "firewall", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("enum", "Action", values=tuple(ACTIONS["firewall"]), required=True),
                   "nw_services": _f("refs", "Network services", ref="nw_services", what=True),
                   "nw_service_groups": _f("refs", "Network service groups", ref="nw_service_groups", what=True),
                   "nw_applications": _f("names", "Network applications", ref="nw_applications", what=True),
                   "dest_addresses": _f("addrs", "Destination addresses (IP, range, CIDR or FQDN)", what=True),
                   "dest_ip_groups": _f("refs", "Destination IP groups", ref="dest_ip_groups", what=True),
                   "dest_ip_categories": _f("names", "Destination URL categories", ref="url_categories", what=True),
                   "dest_countries": _f("countries", "Destination countries", what=True),
                   "src_ips": _f("addrs", "Source IP addresses", who=True, ip_only=True),
                   "src_ip_groups": _f("refs", "Source IP groups", ref="src_ip_groups", who=True),
                   "enable_full_logging": _f("bool", "Full logging"),
                   **_who(labels=False)}},
    "ssl_inspection": {
        "label": "SSL inspection", "service": "ssl_inspection_rules", "channel": "ssl", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("ssl_action", "Action", values=tuple(ACTIONS["ssl_inspection"]), required=True),
                   "url_categories": _f("names", "URL categories", ref="url_categories", what=True),
                   "cloud_applications": _f("names", "Cloud applications", ref="cloud_apps", what=True),
                   "dest_ip_groups": _f("refs", "Destination IP groups", ref="dest_ip_groups", what=True),
                   "platforms": _f("enums", "Platforms", values=SSL_PLATFORMS, default=list(SSL_PLATFORMS)),
                   "user_agent_types": _f("enums", "Browsers (user agents)", values=USER_AGENTS),
                   "device_trust_levels": _f("enums", "Device trust levels", values=TRUST),
                   "road_warrior_for_kerberos": _f("bool", "Apply to road warriors signed in with Kerberos"),
                   "source_ip_groups": _f("refs", "Source IP groups", ref="src_ip_groups", who=True),
                   **_who()}},
    "forwarding": {
        "label": "Forwarding control", "service": "forwarding_control", "kind": "forwarding_rule", "action_field": "forward_method",
        "fields": {**_base(),
                   "forward_method": _f("enum", "Forward method", values=FWD_METHODS, required=True),
                   "proxy_gateway": _f("ref", "Proxy gateway (Proxy chaining)", ref="proxy_gateways", needs={"forward_method": "PROXYCHAIN"}),
                   "zpa_gateway": _f("ref", "ZPA gateway", ref="zpa_gateways", needs={"forward_method": "ZPA"}),
                   "dest_addresses": _f("addrs", "Destination addresses (IP, range, CIDR or FQDN)", what=True),
                   "dest_ip_groups": _f("refs", "Destination IP groups", ref="dest_ip_groups", what=True),
                   "dest_ip_categories": _f("names", "Destination URL categories", ref="url_categories", what=True),
                   "dest_countries": _f("countries", "Destination countries", what=True),
                   "nw_services": _f("refs", "Network services", ref="nw_services", what=True),
                   "nw_service_groups": _f("refs", "Network service groups", ref="nw_service_groups", what=True),
                   "src_ips": _f("addrs", "Source IP addresses", who=True, ip_only=True),
                   "src_ip_groups": _f("refs", "Source IP groups", ref="src_ip_groups", who=True),
                   **_who()}},
    "web_dlp": {
        "label": "Inline Web DLP", "service": "dlp_web_rules", "channel": "web", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("enum", "Action", values=tuple(ACTIONS["web_dlp"]), required=True),
                   "dlp_engines": _f("refs", "DLP engines", ref="dlp_engines", what=True),
                   "protocols": _f("enums", "Protocols", values=DLP_PROTOCOLS, default=["ANY_RULE"]),
                   "cloud_applications": _f("names", "Cloud applications", ref="cloud_apps", what=True),
                   "severity": _f("enum", "Severity", values=SEVERITY),
                   "without_content_inspection": _f("bool", "Match without content inspection"),
                   "min_size": _f("int", "Smallest file to inspect (KB)", min=0, max=409600),
                   **_who(time=False)}},   # SDK 1.11.3's DLPWebRules model has no time_windows
    "dns_control": {
        "label": "DNS Control", "service": "cloud_firewall_dns", "channel": "dns", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("enum", "Action", values=tuple(ACTIONS["dns_control"]), required=True),
                   "dest_ip_categories": _f("names", "Domain categories", ref="url_categories", what=True),
                   "res_categories": _f("names", "Resolved IP categories", ref="url_categories", what=True),
                   "dest_addresses": _f("addrs", "Destination addresses (IP, range, CIDR or FQDN)", what=True),
                   "dest_ip_groups": _f("refs", "Destination IP groups", ref="dest_ip_groups", what=True),
                   "dest_countries": _f("countries", "Destination countries", what=True),
                   "protocols": _f("enums", "Protocols", values=DNS_PROTOCOLS),
                   "dns_gateway": _f("ref", "DNS gateway", ref="dns_gateways"),
                   "src_ips": _f("addrs", "Source IP addresses", who=True, ip_only=True),
                   "src_ip_groups": _f("refs", "Source IP groups", ref="src_ip_groups", who=True),
                   **_who()}},
    "firewall_ips": {
        "label": "IPS (Cloud Firewall)", "service": "cloud_firewall_ips", "channel": "ips", "action_field": "action",
        "fields": {**_base(),
                   "action": _f("enum", "Action", values=tuple(ACTIONS["firewall_ips"]), required=True),
                   "dest_addresses": _f("addrs", "Destination addresses (IP, range, CIDR or FQDN)", what=True),
                   "dest_ip_groups": _f("refs", "Destination IP groups", ref="dest_ip_groups", what=True),
                   "dest_ip_categories": _f("names", "Destination URL categories", ref="url_categories", what=True),
                   "dest_countries": _f("countries", "Destination countries", what=True),
                   "nw_services": _f("refs", "Network services", ref="nw_services", what=True),
                   "nw_service_groups": _f("refs", "Network service groups", ref="nw_service_groups", what=True),
                   "src_ips": _f("addrs", "Source IP addresses", who=True, ip_only=True),
                   "src_ip_groups": _f("refs", "Source IP groups", ref="src_ip_groups", who=True),
                   "enable_full_logging": _f("bool", "Full logging"),
                   "capture_pcap": _f("bool", "Capture packets (PCAP)"),
                   **_who()}},
    "file_type_control": {
        "label": "File Type Control", "service": "file_type_control_rule", "channel": "file_type", "action_field": "filtering_action",
        "fields": {**_base(),
                   "filtering_action": _f("enum", "Action", values=tuple(ACTIONS["file_type_control"]), required=True),
                   "operation": _f("enum", "Applies to", values=("UPLOAD", "DOWNLOAD", "UPLOAD_DOWNLOAD"), required=True, default="UPLOAD_DOWNLOAD"),
                   "file_types": _f("enums_free", "File types (Zscaler names, e.g. FTCATEGORY_ZIP)", what=True, required=True),
                   "url_categories": _f("names", "URL categories", ref="url_categories", what=True),
                   "cloud_applications": _f("names", "Cloud applications", ref="cloud_apps", what=True),
                   "protocols": _f("enums", "Protocols", values=FTC_PROTOCOLS, default=["ANY_RULE"]),
                   "device_trust_levels": _f("enums", "Device trust levels", values=TRUST),
                   "password_protected": _f("bool", "Only password-protected files"),
                   "active_content": _f("bool", "Only files with active content"),
                   "unscannable": _f("bool", "Only files that cannot be scanned"),
                   **_who()}},
    "sandbox": {
        "label": "Sandbox", "service": "sandbox_rules", "channel": "sandbox", "action_field": "first_time_operation",
        "fields": {**_base(),
                   "first_time_operation": _f("enum", "First time a file is seen", values=tuple(ACTIONS["sandbox"]), required=True),
                   "ba_rule_action": _f("enum", "Known malicious files", values=("BLOCK", "ALLOW"), required=True, default="BLOCK"),
                   "ba_policy_categories": _f("enums", "Threat categories", values=SANDBOX_CATEGORIES, default=list(SANDBOX_CATEGORIES), required=True),
                   "file_types": _f("enums_free", "File types (Zscaler names, e.g. FTCATEGORY_P7Z)", what=True),
                   "protocols": _f("enums", "Protocols", values=SANDBOX_PROTOCOLS, default=list(SANDBOX_PROTOCOLS)),
                   "url_categories": _f("names", "URL categories", ref="url_categories", what=True),
                   "first_time_enable": _f("bool", "Apply the first-time action", default=True),
                   "ml_action_enabled": _f("bool", "Use AI instant verdicts"),
                   **_who(time=False, users=True)}},
    "cloud_app_control": {
        "label": "Cloud App Control", "service": "cloudappcontrol", "channel": "cloud_app", "action_field": "actions",
        "fields": {**_base(),
                   "actions": _f("cac_actions", "Actions (e.g. BLOCK_FILE_SHARE_UPLOAD)", required=True),
                   "applications": _f("names", "Cloud applications", ref="cloud_apps", what=True, required=True),
                   "device_trust_levels": _f("enums", "Device trust levels", values=TRUST),
                   "user_agent_types": _f("enums", "Browsers (user agents)", values=USER_AGENTS),
                   **_who()}},
}
ORDER = ("url_filtering", "firewall", "ssl_inspection", "forwarding", "web_dlp", "dns_control", "firewall_ips",
         "file_type_control", "sandbox", "cloud_app_control")
PLATFORM = frozenset({"forwarding", "dns_control", "firewall_ips", "sandbox"})   # gated on ZIA platform (zia_extras)
NAME_MAX = {p: (MAX_NAME_DLP if p == "web_dlp" else MAX_NAME) for p in POLICY}
# Fields a rule carries that the form never changes: the editor keeps them as read.
UNMANAGED = frozenset({"id", "order", "rank", "state", "default_rule", "predefined", "access_control", "last_modified_by",
                       "last_modified_time", "rule_type", "type"})


def fields_of(policy: str) -> Dict[str, Dict[str, Any]]:
    return POLICY[policy]["fields"]


def refs_needed(policy: str) -> List[str]:
    return sorted({f["ref"] for f in fields_of(policy).values() if f.get("ref")})


# ---------------------------------------------------------------------------
# Canonical values (the conflict guard, the read-back and the preview compare these)
# ---------------------------------------------------------------------------

def _id_of(x: Any) -> str:
    if isinstance(x, dict):
        x = x.get("id", x.get("value"))
    return "" if x is None else str(x)


def canon(spec: Dict[str, Any], v: Any) -> Any:
    k = spec["kind"]
    if k == "refs":
        return sorted({_id_of(x) for x in (v or []) if _id_of(x)}, key=lambda s: (len(s), s))
    if k == "ref":
        return _id_of(v) if v not in (None, "", {}) else ""
    if k in ("enums", "enums_free", "names", "addrs", "countries", "cac_actions"):
        return sorted({str(x) for x in (v or []) if str(x).strip()})
    if k == "bool":
        return v is True or str(v).strip().lower() in ("true", "1", "yes")
    if k == "int":
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    if k == "ssl_action":
        return str((v or {}).get("type") or "") if isinstance(v, dict) else str(v or "")
    return "" if v is None else str(v)


def current(policy: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """Every form field's canonical value on a rule as read."""
    return {k: canon(f, (row or {}).get(k)) for k, f in fields_of(policy).items()}


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _text(v: Any, label: str, limit: int, *, name: bool = False) -> str:
    if v is not None and not isinstance(v, str):
        raise FormError(f"{label} must be text.")
    s = str(v or "").strip()
    if (_UNSAFE_NAME if name else _UNSAFE_TEXT).search(s):
        raise FormError(f"{label} contains a control character{' or < >' if name else ''}; type it again without them.")
    if name and len(s) > limit:
        raise FormError(f"{label} is longer than {limit} characters (ZIA's limit for this rule type).")
    if not name and len(s.encode("utf-8")) > limit:
        raise FormError(f"{label} is longer than {limit} bytes.")
    return s


def _list(v: Any, label: str) -> List[Any]:
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise FormError(f"{label} must be a list.")
    if len(v) > MAX_LIST:
        raise FormError(f"{label}: at most {MAX_LIST} entries; this has {len(v)}.")
    return v


def norm_addr(raw: Any, *, ip_only: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """(address as ZIA takes it, None) or (None, why not): an IP address,
    a CIDR range, a range a-b, or (destinations) an FQDN or *.domain."""
    s = str(raw or "").strip().lower()
    if not s:
        return None, "empty"
    if len(s) > MAX_ADDR_LEN or _UNSAFE_TEXT.search(s) or any(c.isspace() for c in s):
        return None, "is too long or contains a space or a control character"
    try:
        if "/" in s:
            return str(ipaddress.ip_network(s, strict=False)), None
        if "-" in s and all(p.strip() for p in s.split("-", 1)) and ":" not in s:
            a, b = (ipaddress.ip_address(p.strip()) for p in s.split("-", 1))
            if a.version != b.version or int(a) > int(b):
                return None, "is not a valid range (low-high, one IP version)"
            return f"{a}-{b}", None
        return str(ipaddress.ip_address(s)), None
    except ValueError:
        pass
    if ip_only:
        return None, "is not an IP address, range or CIDR block"
    if _HOST.match(s):
        return s, None
    return None, "is not an IP address, range, CIDR block or domain name"


def validate(policy: str, fields: Any, *, partial: bool = False) -> Dict[str, Any]:
    """The form's values checked and normalized (raises FormError naming
    the field). `partial` (an edit) checks only the fields given; a create
    needs every required field. Unknown fields are refused: the form only
    sends fields the SDK model has."""
    if policy not in POLICY:
        raise FormError(f"Unknown rule type '{str(policy)[:40]}'. Use one of: {', '.join(ORDER)}.")
    if not isinstance(fields, dict):
        raise FormError("The rule's fields must be an object.")
    specs = fields_of(policy)
    unknown = sorted(str(k)[:40] for k in fields if k not in specs)
    if unknown:
        raise FormError(f"{POLICY[policy]['label']} rules have no field {', '.join(unknown[:5])} in this editor.")
    out: Dict[str, Any] = {}
    for key, f in specs.items():
        if key not in fields:
            if partial:
                continue
            if f.get("default") is not None:
                out[key] = canon(f, f["default"])
            continue
        v, lab = fields[key], f["label"]
        k = f["kind"]
        if k == "text":
            out[key] = _text(v, lab, NAME_MAX[policy], name=True)
        elif k == "longtext":
            out[key] = _text(v, lab, DESC_MAX)
        elif k in ("enum", "ssl_action"):
            s = str(v or "").strip().upper()
            if s and s not in f["values"]:
                raise FormError(f"{lab}: '{s[:40]}' is not one of {', '.join(f['values'])}.")
            out[key] = s
        elif k == "enums":
            vals = [str(x).strip().upper() for x in _list(v, lab)]
            bad = [x for x in vals if x not in f["values"]]
            if bad:
                raise FormError(f"{lab}: {', '.join(b[:40] for b in bad[:5])} not one of {', '.join(f['values'])}.")
            out[key] = canon(f, vals)
        elif k in ("enums_free", "names"):
            vals = [str(x).strip() for x in _list(v, lab)]
            bad = [x for x in vals if not re.fullmatch(r"[A-Za-z0-9_.\- ]{1,128}", x)]
            if bad:
                raise FormError(f"{lab}: {', '.join(repr(b[:40]) for b in bad[:5])} is not a valid name.")
            out[key] = canon(f, vals)
        elif k == "countries":
            vals = [str(x).strip().upper() for x in _list(v, lab)]
            vals = [x if x.startswith("COUNTRY_") else f"COUNTRY_{x}" for x in vals]
            bad = [x for x in vals if not _COUNTRY.match(x)]
            if bad:
                raise FormError(f"{lab}: {', '.join(b[:40] for b in bad[:5])} is not a country code (two letters, e.g. US or COUNTRY_US).")
            out[key] = canon(f, vals)
        elif k == "cac_actions":
            vals = [str(x).strip().upper() for x in _list(v, lab)]
            bad = [x for x in vals if not _CAC_ACTION.match(x)]
            if bad:
                raise FormError(f"{lab}: {', '.join(b[:40] for b in bad[:5])} is not a Cloud App Control action (e.g. BLOCK_FILE_SHARE_UPLOAD).")
            out[key] = canon(f, vals)
        elif k == "addrs":
            got, bad = [], []
            for x in _list(v, lab):
                a, why = norm_addr(x, ip_only=bool(f.get("ip_only")))
                (got.append(a) if a else bad.append(f"{str(x)[:60]!r} {why}"))
            if bad:
                raise FormError(f"{lab}: " + "; ".join(bad[:5]) + ".")
            out[key] = canon(f, got)
        elif k == "refs":
            ids = []
            for x in _list(v, lab):
                i = _id_of(x)
                if not re.fullmatch(r"[0-9]{1,20}", i):
                    raise FormError(f"{lab}: '{i[:40]}' is not an id; pick it from the list.")
                ids.append(i)
            out[key] = canon(f, ids)
        elif k == "ref":
            i = _id_of(v) if v not in (None, "", {}) else ""
            if i and not re.fullmatch(r"[0-9]{1,20}", i):
                raise FormError(f"{lab}: '{i[:40]}' is not an id; pick it from the list.")
            out[key] = i
        elif k == "bool":
            if v not in (True, False, None, "", "true", "false"):
                raise FormError(f"{lab} must be yes or no.")
            out[key] = v is True or v == "true"
        elif k == "int":
            if v in (None, ""):
                out[key] = None
                continue
            try:
                n = int(v)
            except (TypeError, ValueError):
                raise FormError(f"{lab} must be a whole number.")
            if not f.get("min", 0) <= n <= f.get("max", 2 ** 31):
                raise FormError(f"{lab} must be between {f.get('min', 0)} and {f.get('max')}.")
            out[key] = n
    if not partial:
        missing = [specs[k]["label"] for k, f in specs.items() if f.get("required") and out.get(k) in (None, "", [])]
        if missing:
            raise FormError("Fill in: " + ", ".join(missing) + ".")
    return out


def check_rule(policy: str, values: Dict[str, Any]) -> List[str]:
    """What the rule as a whole needs (after an edit is merged into the
    rule as read): [] when it can be saved, else one sentence per problem."""
    specs = fields_of(policy)
    out = []
    for k, f in specs.items():
        if f.get("required") and values.get(k) in (None, "", []):
            out.append(f"{f['label']} is required.")
        for dep, want in (f.get("needs") or {}).items():
            if values.get(k) not in (None, "", []) and values.get(dep) != want:
                out.append(f"{f['label']} is used only when {specs[dep]['label']} is {want}.")
    if policy == "forwarding":
        m = values.get("forward_method")
        if m == "PROXYCHAIN" and not values.get("proxy_gateway"):
            out.append("Forwarding by proxy chaining needs a proxy gateway (Proxy gateway).")
        if m == "ZPA" and not values.get("zpa_gateway"):
            out.append("Forwarding to ZPA needs a ZPA gateway.")
    if policy == "cloud_app_control" and any(str(a).startswith("CAUTION_") for a in values.get("actions") or []) \
            and not values.get("user_agent_types"):
        out.append("A Caution action applies only to named browsers: pick the browsers (user agents).")
    if policy == "file_type_control" and values.get("filtering_action") == "CAUTION" and values.get("operation") != "DOWNLOAD":
        out.append("ZIA shows a Caution page for downloads only: set Applies to Download, or pick Allow or Block.")   # assumed
    return out


# ---------------------------------------------------------------------------
# Payload
# ---------------------------------------------------------------------------

def _wire_id(i: str) -> Any:
    return int(i) if i.isdigit() else i


def ssl_action(kind: str) -> Dict[str, Any]:
    """The SSL inspection action object for a type, with the sub-actions
    ops_zia_baseline sends on real tenants (TLS 1.2 minimum when inspecting)."""
    if kind == "DECRYPT":
        return {"type": "DECRYPT", "override_default_certificate": False,
                "decrypt_sub_actions": {"server_certificates": "BLOCK", "ocsp_check": True, "block_ssl_traffic_with_no_sni_enabled": True,
                                        "min_client_tls_version": "CLIENT_TLS_1_2", "min_server_tls_version": "SERVER_TLS_1_2",
                                        "block_undecrypt": True, "http2_enabled": False}}
    if kind == "BLOCK":
        return {"type": "BLOCK"}
    return {"type": "DO_NOT_DECRYPT", "do_not_decrypt_sub_actions": {"server_certificates": "ALLOW", "bypass_other_policies": False,
                                                                    "ocsp_check": False, "block_ssl_traffic_with_no_sni_enabled": False}}


def wire(policy: str, key: str, value: Any, *, refnames: Optional[Dict[str, Dict[str, str]]] = None, old: Any = None) -> Any:
    """One field as the SDK's add_rule / update_rule takes it."""
    f = fields_of(policy)[key]
    k = f["kind"]
    if k == "refs":
        names = (refnames or {}).get(f["ref"], {})
        return [dict({"id": _wire_id(i)}, **({"name": names[i]} if names.get(i) else {})) for i in value]
    if k == "ref":
        if not value:
            return None
        nm = (refnames or {}).get(f["ref"], {}).get(value)
        return dict({"id": _wire_id(value)}, **({"name": nm} if nm else {}))
    if k == "ssl_action":
        if isinstance(old, dict) and str(old.get("type") or "") == value:
            return old              # the type is unchanged: its sub-actions stay as the tenant has them
        return ssl_action(value)
    if isinstance(value, list):
        return list(value)
    return value


def payload(policy: str, values: Dict[str, Any], *, refnames=None, state: str = "DISABLED", order: Optional[int] = None,
            rank: Optional[int] = None, rule_type: str = "") -> Dict[str, Any]:
    """A new rule as add_rule takes it: only the fields with a value."""
    body: Dict[str, Any] = {}
    for k in fields_of(policy):
        v = values.get(k)
        if v in (None, "", []) and k != "name":
            continue
        w = wire(policy, k, v, refnames=refnames)
        if w is not None:
            body[k] = w
    body["state"] = state
    if order is not None:
        body["order"] = order
    if rank is not None:
        body["rank"] = rank
    if policy == "cloud_app_control":
        body["type"] = rule_type
    if policy == "forwarding":
        body["type"] = "FORWARDING"   # forwarding_control_policy.ForwardingControlRule.type; FORWARDING is the rule kind ZIA lists (assumed)
    return body


def apply_changes(policy: str, body: Dict[str, Any], changes: Dict[str, Any], *, refnames=None) -> Dict[str, Any]:
    """The rule as read (`body`, from admin_ops._body) with the changed
    fields set: everything else, including fields the form does not show,
    is sent back as the tenant has it (an update replaces the rule)."""
    out = dict(body)
    for k, v in changes.items():
        w = wire(policy, k, v, refnames=refnames, old=body.get(k))
        if w in (None, "", []):
            out[k] = [] if fields_of(policy)[k]["kind"] in ("refs", "names", "enums", "enums_free", "addrs", "countries") else None
            if out[k] is None:
                out.pop(k, None)
        else:
            out[k] = w
    return out


# ---------------------------------------------------------------------------
# Placement
# ---------------------------------------------------------------------------

def _order(r: Dict[str, Any]) -> int:
    try:
        return int(r.get("order"))
    except (TypeError, ValueError):
        return 0


def is_default(r: Dict[str, Any]) -> bool:
    v = r.get("default_rule")
    return v is True or str(v).lower() == "true" or _order(r) <= 0


def live(rows: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The rules in policy order, the Default rule left out."""
    return sorted([r for r in rows if not is_default(r)], key=lambda r: (_order(r), str(r.get("id"))))


def rank_reason(setting: Dict[str, Any]) -> str:
    st = admin_rank.state_of(setting)
    if st == admin_rank.OFF:
        return "Admin Ranking is off in this tenant, so the rank does not change the evaluation order"
    if st == admin_rank.OUT_OF_SCOPE:
        return "ZIA platform is not ticked on the Scope page, so the Admin Ranking setting was not read; the lowest rank (7) is used"
    if st == admin_rank.UNKNOWN:
        return f"the Admin Ranking setting could not be read ({setting.get('why') or 'no answer'}); the lowest rank (7) is used"
    return ""


def place(rows: Sequence[Dict[str, Any]], where: Dict[str, Any], setting: Dict[str, Any]) -> Dict[str, Any]:
    """Where a new rule goes: {order, rank, anchor, why, warnings}.

    where: {"at": "top"} | {"at": "bottom"} (the default) | {"at": "order",
    "order": N} | {"at": "below", "id": rule id}. The order is clamped to
    1 .. (last rule's order + 1), above the Default rule. The rank: with
    Admin Ranking on, the rank of the rule it sits above (the rule now at
    that order), or, going last, of the rule just above it; otherwise 7."""
    rules = live(rows)
    last = _order(rules[-1]) if rules else 0
    at = str((where or {}).get("at") or "bottom")
    warnings: List[str] = []
    if at == "top":
        order = 1
    elif at == "order":
        try:
            order = int((where or {}).get("order"))
        except (TypeError, ValueError):
            raise FormError("Give the order as a whole number (1 is the top).")
        if order < 1:
            raise FormError("The order starts at 1 (the top).")
        order = min(order, last + 1)
    elif at == "below":
        ref = next((r for r in rules if str(r.get("id")) == str((where or {}).get("id"))), None)
        if ref is None:
            raise FormError("The rule to place it below is not in this policy now; read the rules again.")
        order = _order(ref) + 1
    elif at == "bottom":
        order = last + 1
    else:
        raise FormError("Place the rule at the top, the bottom, an order number or below a rule.")
    above = next((r for r in rules if _order(r) >= order), None)        # the rule it will sit above
    anchor = above or (rules[-1] if rules else None)
    st = admin_rank.state_of(setting)
    if st == admin_rank.ON and anchor is not None:
        rank = admin_rank.rank_of(anchor)
        why = (f"rank {rank}, the rank of '{anchor.get('name')}', the rule it sits {'above' if above else 'below'} "
               "(Admin Ranking is on: a rule is evaluated by rank first, so it takes its neighbour's rank to really sit here)")
        if str(anchor.get("access_control") or "").upper() == "READ_ONLY":
            warnings.append(f"'{anchor.get('name')}' is read-only for this API client, so its rank {rank} may be above this client's admin "
                            "rank and ZIA may refuse the new rule ('Rule rank is higher than the admin rank'). Place it lower if it does.")
    else:
        rank = LEGACY_RANK
        why = f"rank {rank}: " + (rank_reason(setting) or "the policy has no rule yet")
    if above is not None and str(above.get("predefined")).lower() == "true":
        warnings.append(f"'{above.get('name')}' is a predefined rule; ZIA may keep predefined rules first and place this one below it.")
    return {"order": order, "rank": rank, "why": why, "warnings": warnings,
            "anchor": {"id": anchor.get("id"), "name": anchor.get("name"), "order": anchor.get("order"),
                       "rank": admin_rank.shown_rank(anchor)} if anchor else None,
            "above_id": above.get("id") if above else None}


# ---------------------------------------------------------------------------
# The plain-language preview
# ---------------------------------------------------------------------------

def _names(policy: str, key: str, value: Any, refnames: Dict[str, Dict[str, str]], limit: int = 6) -> str:
    f = fields_of(policy)[key]
    vals = value if isinstance(value, list) else ([value] if value not in (None, "") else [])
    if f.get("ref"):
        names = refnames.get(f["ref"], {})
        vals = [names.get(str(v)) or (f"#{v}" if f["kind"] in ("refs", "ref") else str(v)) for v in vals]
    elif f["kind"] == "countries":
        vals = [str(v).replace("COUNTRY_", "") for v in vals]
    vals = [str(v) for v in vals]
    more = len(vals) - limit
    return ", ".join(vals[:limit]) + (f" and {more} more" if more > 0 else "")


def show(policy: str, key: str, value: Any, refnames: Dict[str, Dict[str, str]]) -> str:
    """A field's value in plain words for the preview table."""
    f = fields_of(policy)[key]
    if f["kind"] == "bool":
        return "yes" if value else "no"
    if value in (None, "", []):
        return "—"
    return _names(policy, key, value, refnames, limit=12)


def _lab(label: str) -> str:
    """A field label inside a sentence: 'Network services' -> 'network services', 'URL categories' stays."""
    lab = label.split(" (")[0]
    return lab if lab[:2].isupper() else lab[:1].lower() + lab[1:]


def sentence(policy: str, values: Dict[str, Any], refnames: Dict[str, Dict[str, str]], *, order: Any, rank: Any,
             state: str, verb_tense: str = "will") -> str:
    """'This rule will block … for …, placed at order N, rank R.'"""
    p = POLICY[policy]
    specs = fields_of(policy)
    act_field = p["action_field"]
    if policy == "cloud_app_control":
        acts = values.get("actions") or []
        verb = f"apply {', '.join(str(a).replace('_', ' ').lower() for a in acts[:4])}{' and more' if len(acts) > 4 else ''} to"
    else:
        a = values.get(act_field) or ""
        verb = ACTIONS.get(policy, {}).get(a) or (str(a).replace("_", " ").lower() if a else "match")
        if policy == "file_type_control":
            op = {"UPLOAD": "uploads of", "DOWNLOAD": "downloads of", "UPLOAD_DOWNLOAD": "uploads and downloads of"}.get(values.get("operation") or "", "")
            verb = f"{verb} {op}".strip()
        if policy == "forwarding":
            gw = values.get("proxy_gateway") or values.get("zpa_gateway")
            if gw:
                verb += f" ({_names(policy, 'proxy_gateway' if values.get('proxy_gateway') else 'zpa_gateway', gw, refnames)})"
    what = [f"the {_lab(specs[k]['label'])} {_names(policy, k, values[k], refnames)}"
            for k, f in specs.items() if f.get("what") and values.get(k) not in (None, "", [])]
    if policy == "file_type_control" and values.get("file_types"):
        what = [w for w in what if not w.startswith("the file types")]
        what.insert(0, f"the file types {_names(policy, 'file_types', values['file_types'], refnames)}")
    who = [f"the {_lab(specs[k]['label'])} {_names(policy, k, values[k], refnames)}"
           for k, f in specs.items() if f.get("who") and values.get(k) not in (None, "", [])]
    when = [_names(policy, k, values[k], refnames) for k, f in specs.items() if f.get("when") and values.get(k)]
    target = "; ".join(what) if what else "all traffic this policy sees"
    people = ("for " + "; ".join(who)) if who else "for everyone"
    s = f"This rule {verb_tense} {verb} {target} {people}"
    if when:
        s += f", during {'; '.join(when)}"
    s += f", placed at order {order}, rank {rank}." if verb_tense == "will" else f", at order {order}, rank {rank}."
    s += " It is created disabled: nothing changes for users until it is enabled." if state == "DISABLED" and verb_tense == "will" \
        else (" It is enabled: it applies as soon as ZIA activates the change." if state == "ENABLED" else "")
    return s
