"""Configuration backups, field-level diffs and portable templates for ZIA,
ZPA and Client Connector.

A backup is a read of one tenant's configuration, product by product and
object type by object type, through the installed zscaler-sdk-python's own
list calls (read-only), kept as one owner-only file beside the tenant
profiles (``config_backups/`` next to the profile store: folder 0700, files
0600, named by the app ``bk-<16 hex>.json``), with an index of what each
holds. It is built on the snapshot feature (offline_tenant.py):

  - the same secret rule: every secret-named field (passwords, pre-shared
    keys, API keys, tokens, private keys, OTPs) keeps only "(set)" or
    "(not set)" (offline_tenant.scrub), on the read and again on every
    file that is opened;
  - the same untrusted-file checks (size, nesting depth, node count,
    format, version, every type key and row shape);
  - a saved snapshot (tenant_snapshots/) or the sample tenant can be read
    into a backup through the offline SDK client, which has no network code:
    that is how restore, clone and templates are rehearsed (plan only).

What a backup covers is the catalogue TYPES below: every object type of the
other configuration tools' lists that zscaler-sdk-python 1.11.3 can read,
each with what this app does with it (``level``):

  full       backed up, compared, restored and cloned: create, update and,
             in "full" mode only, delete
  update     backed up, compared and restored by updating what exists
             (settings singletons, Client Connector policies)
  read       backed up and compared only, with the reason it is never
             written here (identity comes from the IdP, a location is bound
             to the tenant's IP addresses, ZPA policy conditions cannot be
             rebuilt exactly through the SDK, ...)

``coverage()`` lists it for the page and the docs. Writes are never made
from here: restore, clone and template apply are operation types on the Bulk
changes engine (ops_config_restore.py), which plans, previews with a plan
hash, re-reads before each write, reads back, activates and records an Undo.

Diff (``diff``) compares two backups, or a backup and the live tenant read
into the same form, field by field: objects are matched by id within one
tenant and by name across tenants, references are compared by the name of
what they point at (so a clone's new ids are not differences), and volatile
fields (ids, change times, who changed it, counters) are ignored, plus any
field pattern the caller adds.

Templates (``make_template`` / ``template_source``) are selected objects of a
backup with their ids removed, references kept by name, and the names of the
template's own objects parameterised with ``{{prefix}}``; applied through the
same restore plan to any tenant.

Scheduled backups (``schedule`` / ``run_due``) are read-only, so they are
safe to run unattended: a profile that remembers its secret is read on the
profile's own Scope page selection every N hours, and its newest ``keep``
backups are kept. Nothing scheduled ever writes to a tenant.

SDK calls: every service and method name in TYPES is verified against the
installed zscaler-sdk-python 1.11.3 (tests/test_config_backup.py checks each
one exists). Assumed, not verifiable without a tenant: that the SDK's add_ /
update_ calls accept the snake_case fields its own list calls return (the
assumption pack_ops already makes for DLP rules), that predefined objects
(predefined URL categories, network services, DLP dictionaries and engines)
carry the same name in every tenant, and that a custom URL category id has
the form CUSTOM_nn.
"""
from __future__ import annotations

import copy
import fnmatch
import hashlib
import json
import os
import re
import secrets
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import safe_files
import store_crypto

FORMAT = "zscaler-made-easy-config-backup"
TEMPLATE_FORMAT = "zscaler-made-easy-config-template"
VERSION = 1
PRODUCTS = ("zia", "zpa", "zcc")
PRODUCT_LABELS = {"zia": "ZIA", "zpa": "ZPA", "zcc": "Client Connector"}
BACKUP_DIR = "config_backups"
BACKUP_ID = re.compile(r"\Abk-[0-9a-f]{16}\Z")
TEMPLATE_ID = re.compile(r"\Atpl-[0-9a-f]{16}\Z")
OWNER_ID = re.compile(r"\A[0-9a-f]{16}\Z")
# A sealed file (store_crypto: DLP_CHECK_STORE_ENCRYPTION) is base64 of the
# AES-GCM ciphertext plus a short header, so it may be about 4/3 of the plain size.
def _sealed_cap(limit: int) -> int:
    return limit * 4 // 3 + 256
MAX_BACKUP_BYTES = 16 * 1024 * 1024
MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_ROWS_PER_TYPE = 20000
MAX_TEMPLATE_OBJECTS = 500
MAX_ZPA_PAGES = 200
DEFAULT_KEEP = 10
MAX_KEEP = 100
MIN_EVERY_HOURS, MAX_EVERY_HOURS = 1, 168
PREFIX_TOKEN = "{{prefix}}"
PREFIX_RE = re.compile(r"\A[A-Za-z0-9 _.\-]{0,20}\Z")
MASKS = ("(set)", "(not set)")
KINDS = ("manual", "scheduled", "pre-restore", "snapshot", "sample")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# A DLP engine's expression names dictionaries by id: "((D63.S > 1) AND (D64.S > 0))".
EXPR_ID = re.compile(r"\bD(\d+)\.")
_LOCK = threading.RLock()


class BackupError(ValueError):
    """A request or a file this module refuses, in words (the routes' 400/404)."""


# ---------------------------------------------------------------------------
# The catalogue: what is read, how, and what may be written back
# ---------------------------------------------------------------------------
# Reference fields: a field of this name (top level) points at objects of
# that type. A type that is not in the catalogue ("zia.users", ...) is not
# backed up: on the same tenant its ids are kept, across tenants an object
# that names one cannot be cloned (it is listed with the reason).
ZIA_REFS = {
    "locations": "zia.locations", "location_groups": "zia.location_groups", "groups": "zia.groups",
    "departments": "zia.departments", "users": "zia.users", "labels": "zia.rule_labels",
    "time_windows": "zia.time_intervals", "url_categories": "zia.url_categories", "url_categories2": "zia.url_categories",
    "src_ip_groups": "zia.ip_source_groups", "src_ipv6_groups": "zia.ip_source_groups",
    "dest_ip_groups": "zia.ip_destination_groups", "cert": "zia.root_certificates", "dest_ipv6_groups": "zia.ip_destination_groups",
    "nw_services": "zia.network_services", "nw_service_groups": "zia.network_service_groups",
    "nw_application_groups": "zia.network_app_groups", "services": "zia.network_services",
    "dlp_engines": "zia.dlp_engines", "notification_template": "zia.dlp_notification_templates",
    "icap_server": "zia.icap_servers", "source_ip_groups": "zia.ip_source_groups", "eun_template_id": "zia.eun_templates",
    "excluded_groups": "zia.groups", "excluded_departments": "zia.departments", "excluded_users": "zia.users",
    "override_users": "zia.users", "override_groups": "zia.groups", "auditor": "zia.users",
    "devices": "zia.devices", "device_groups": "zia.device_groups", "workload_groups": "zia.workload_groups",
    "cbi_profile": "zia.isolation_profiles", "cloud_app_instances": "zia.cloud_app_instances",
    "tenancy_restriction_profile": "zia.tenancy_restriction_profiles", "proxy_gateway": "zia.proxy_gateways",
    "zpa_gateway": "zia.zpa_gateways", "zpa_app_segments": "zia.zpa_app_segments",
}
ZPA_REFS = {
    "segment_group_id": "zpa.segment_groups", "server_groups": "zpa.server_groups",
    "app_connector_groups": "zpa.connector_groups", "servers": "zpa.servers",
}
ZCC_REFS = {"trusted_network_ids": "zcc.trusted_networks"}
REFS = {"zia": ZIA_REFS, "zpa": ZPA_REFS, "zcc": ZCC_REFS}

# Fields that are never compared nor sent back: ids, change times, who
# changed it, counters, read-only markers and names the API derives.
VOLATILE = ("id", "last_modified_time", "last_modified_by", "modified_time", "modified_by", "creation_time", "created_time",
            "created_by", "creation_date", "last_modified_date", "edited_by", "edited_timestamp", "last_updated*", "last_sync*",
            "*_count", "num_*", "access_control", "config_space", "microtenant_name", "read_only", "zscaler_managed",
            "segment_group_name", "inconsistent_config_details", "company_id", "guid", "val", "is_deletable", "is_editable")
WORDS_VOLATILE = "ids, change times, who changed it, counters and read-only markers"


def _t(key: str, label: str, svc: str, ls: Optional[str], get: Optional[str] = None, add: Optional[str] = None,
       upd: Optional[str] = None, rm: Optional[str] = None, **kw: Any) -> Dict[str, Any]:
    t = {"key": key, "product": key.split(".", 1)[0], "label": label, "svc": svc, "ls": ls, "get": get, "add": add, "upd": upd,
         "rm": rm, "q": None, "name": "name", "keep": None, "level": "full", "why": "", "clone_why": "", "singleton": False,
         "state": None, "scopes": (), "policy": "", "per_type": False, "add_pos": (), "upd_body": False, "add_via_upd": False,
         "strip": (), "uses": None, "expr": None, "raw": "", "flat": False, "manual": "", "global_id": None, "secret_prompt": "", "no_delete": "", "exclude_if": None, "zpa_paged": False}
    t.update(kw)
    if t["level"] == "read":
        t["add"] = t["upd"] = t["rm"] = None
    if t["singleton"] and t["uses"] is None:
        t["uses"] = ()
    return t


def _custom(row: Dict[str, Any]) -> bool:
    """A customer's own object, not one Zscaler predefines."""
    if _truthy(row.get("predefined")) or _truthy(row.get("default_rule")) or _truthy(row.get("read_only")):
        return False
    typ = str(row.get("type") or "").upper()
    return typ not in ("PREDEFINED", "STANDARD")


def _custom_category(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom_category")) or str(row.get("id") or "").startswith("CUSTOM_")


def _custom_dictionary(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom")) and _custom(row)


def _custom_engine(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom_dlp_engine")) and _custom(row)


def _custom_rule(row: Dict[str, Any]) -> bool:
    """A rule the customer made: not the Default rule (order -1 or 0, or
    flagged), not predefined."""
    try:
        if int(row.get("order")) <= 0:
            return False
    except (TypeError, ValueError):
        pass
    return _custom(row)


def _zpa_special_segment(row: Dict[str, Any]) -> Optional[str]:
    for f in ("clientless_apps", "pra_apps", "inspection_apps", "common_apps_dto"):
        if row.get(f):
            return ("a Browser Access, Privileged Remote Access or inspection segment carries application objects the SDK's "
                    "segment call cannot rebuild exactly: restore it in the ZPA Admin Portal")
    return None


_Z = ("zia_extras",)
_DLP = ("dlp", "genai")
_WEB = ("dlp", "zia_extras", "genai")
_ID_READ = "identity comes from the identity provider (SCIM or SAML), so it is never written here"
_TENANT_BOUND = "it is bound to the tenant's own IP addresses, tunnels or credentials, so it is never written or cloned here"
_ZPA_POLICY = ("ZPA policy conditions are sent to the SDK as simple tuples, which cannot carry every nested AND / OR / NOT "
               "block exactly; restoring one could change who gets access. Rebuild it in the ZPA Admin Portal")
_ADMIN = "administrators and their roles are never changed from here"

TYPES: List[Dict[str, Any]] = [
    # ── ZIA: objects that rules use ──
    _t("zia.rule_labels", "Rule labels", "rule_labels", "list_labels", "get_label", "add_label", "update_label", "delete_label", scopes=_Z + _DLP, uses=()),
    _t("zia.time_intervals", "Time intervals", "time_intervals", "list_time_intervals", "get_time_intervals", "add_time_intervals",
       "update_time_intervals", "delete_time_intervals", scopes=_Z, uses=()),
    _t("zia.url_categories", "Custom URL categories", "url_categories", "list_categories", "get_category", "add_url_category",
       "update_url_category", "delete_category", q={"custom_only": True}, name="configured_name", keep=_custom_category, scopes=_WEB,
       add_pos=("super_category", "urls", "configured_name"), global_id=lambda v: not str(v).startswith("CUSTOM_"),
       strip=("custom_category", "editable", "db_categorized_urls", "custom_urls_count", "urls_retaining_parent_category_count",
              "custom_ip_ranges_count", "ip_ranges_retaining_parent_category_count"), uses=()),
    _t("zia.ip_destination_groups", "IP destination groups", "cloud_firewall", "list_ip_destination_groups", "get_ip_destination_group",
       "add_ip_destination_group", "update_ip_destination_group", "delete_ip_destination_group", scopes=_Z, keep=_custom, uses=()),
    _t("zia.ip_source_groups", "IP source groups", "cloud_firewall", "list_ip_source_groups", "get_ip_source_group", "add_ip_source_group",
       "update_ip_source_group", "delete_ip_source_group", scopes=_Z, keep=_custom, uses=()),
    _t("zia.network_services", "Network services", "cloud_firewall", "list_network_services", "get_network_service", "add_network_service",
       "update_network_service", "delete_network_service", scopes=_Z, keep=_custom, uses=()),
    _t("zia.network_service_groups", "Network service groups", "cloud_firewall", "list_network_svc_groups", "get_network_svc_group",
       "add_network_svc_group", "update_network_svc_group", "delete_network_svc_group", scopes=_Z, keep=_custom, uses=("services",)),
    _t("zia.network_app_groups", "Network application groups", "cloud_firewall", "list_network_app_groups", "get_network_app_group",
       "add_network_app_group", "update_network_app_group", "delete_network_app_group", scopes=_Z, keep=_custom, uses=()),
    # ── ZIA: DLP ──
    _t("zia.dlp_dictionaries", "DLP dictionaries", "dlp_dictionary", "list_dicts", "get_dict", "add_dict", "update_dict", "delete_dict",
       scopes=_DLP, keep=_custom_dictionary, add_pos=("name", "custom_phrase_match_type", "dictionary_type"), uses=()),
    _t("zia.dlp_engines", "DLP engines", "dlp_engine", "list_dlp_engines", "get_dlp_engines", "add_dlp_engine", "update_dlp_engine",
       "delete_dlp_engine", scopes=_DLP, keep=_custom_engine, expr=("engine_expression", "zia.dlp_dictionaries"), uses=()),
    _t("zia.dlp_notification_templates", "DLP notification templates", "dlp_templates", "list_dlp_templates", "get_dlp_templates",
       "add_dlp_template", "update_dlp_template", "delete_dlp_template", scopes=_DLP, uses=()),
    _t("zia.icap_servers", "DLP ICAP servers", "dlp_resources", "list_dlp_icap_servers", level="read", scopes=_DLP,
       why="the SDK can read ICAP servers but not create them"),
    _t("zia.incident_receivers", "DLP incident receivers", "dlp_resources", "list_dlp_incident_receiver", level="read", scopes=_DLP,
       why="the SDK can read incident receivers but not create them"),
    # ── ZIA: policies (rules) ──
    _t("zia.url_filtering_rules", "URL filtering rules", "url_filtering", "list_rules", "get_rule", "add_rule", "update_rule", "delete_rule",
       policy="url_filtering", keep=_custom_rule, state="state"),
    _t("zia.ssl_inspection_rules", "SSL inspection rules", "ssl_inspection_rules", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", policy="ssl_inspection", keep=_custom_rule, state="state"),
    _t("zia.firewall_rules", "Cloud Firewall rules", "cloud_firewall_rules", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", policy="firewall", keep=_custom_rule, state="state"),
    _t("zia.firewall_dns_rules", "DNS Control rules", "cloud_firewall_dns", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", scopes=_Z, keep=_custom_rule, state="state"),
    _t("zia.firewall_ips_rules", "IPS Control rules", "cloud_firewall_ips", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", scopes=_Z, keep=_custom_rule, state="state"),
    _t("zia.file_type_rules", "File Type Control rules", "file_type_control_rule", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", policy="file_type_control", keep=_custom_rule, state="state"),
    _t("zia.sandbox_rules", "Sandbox rules", "sandbox_rules", "list_rules", "get_rule", "add_rule", "update_rule", "delete_rule",
       scopes=_Z, keep=_custom_rule, state="state"),
    _t("zia.cloud_app_control_rules", "Cloud App Control rules", "cloudappcontrol", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", policy="cloud_app_control", keep=_custom_rule, state="state", per_type=True),
    _t("zia.web_dlp_rules", "Inline Web DLP rules", "dlp_web_rules", "list_rules", "get_rule", "add_rule", "update_rule", "delete_rule",
       policy="web_dlp", keep=_custom_rule, state="state"),
    _t("zia.email_dlp_rules", "Outbound Email DLP rules", "outbound_email_dlp_rules", "list_rules", "get_rule", "add_rule", "update_rule",
       "delete_rule", policy="email_dlp", keep=_custom_rule, state="state"),
    _t("zia.endpoint_dlp_rules", "Endpoint DLP rules", "endpoint_dlp_rules", "list_rules", level="read", policy="endpoint_dlp",
       why="an Endpoint DLP rule carries sub-rules and application groups the restore plan does not rebuild"),
    _t("zia.saas_dlp_rules", "SaaS Security API DLP rules", "casb_dlp_rules", "list_all_rules", level="read", policy="saas_dlp",
       why="a SaaS Security API rule is bound to the tenant's SaaS tenants and needs its rule type on every write"),
    _t("zia.forwarding_rules", "Forwarding control rules", "forwarding_control", "list_rules", level="read", scopes=_Z,
       why="forwarding rules name the tenant's gateways and ZPA segments; change them in the portal"),
    _t("zia.bandwidth_classes", "Bandwidth classes", "bandwidth_classes", "list_classes", level="read", scopes=_Z,
       why="bandwidth control is sized to the tenant's links"),
    _t("zia.bandwidth_control_rules", "Bandwidth control rules", "bandwidth_control_rules", "list_rules", level="read", scopes=_Z,
       why="bandwidth control is sized to the tenant's links"),
    # ── ZIA: settings (one object each) ──
    _t("zia.advanced_settings", "Advanced settings", "advanced_settings", None, "get_advanced_settings", None, "update_advanced_settings",
       singleton=True, level="update", scopes=_Z),
    _t("zia.url_and_app_settings", "URL and Cloud App Control settings", "url_filtering", None, "get_url_and_app_settings", None,
       "update_url_and_app_settings", singleton=True, level="update", scopes=_WEB),
    _t("zia.browser_control_settings", "Browser Control settings", "browser_control_settings", None, "get_browser_control_settings", None,
       "update_browser_control_settings", singleton=True, level="update", scopes=_Z),
    _t("zia.atp_settings", "Advanced Threat Protection settings", "atp_policy", None, "get_atp_settings", None, "update_atp_settings",
       singleton=True, level="update", scopes=_Z),
    _t("zia.malware_settings", "Malware Protection settings", "malware_protection_policy", None, "get_malware_settings", singleton=True,
       level="read", scopes=_Z, why="the SDK's update takes a settings object, not fields; change it in the portal"),
    _t("zia.auth_settings", "Authentication settings", "authentication_settings", None, "get_authentication_settings", singleton=True,
       level="read", scopes=_Z, why="sign-in settings are never changed from here"),
    # ── ZIA: tenant-bound, identity and reference lists (read only) ──
    _t("zia.vpn_credentials", "VPN credentials", "traffic_vpn_credentials", "list_vpn_credentials", "get_vpn_credential",
       "add_vpn_credential", None, None, scopes=_Z, name="fqdn", level="full", secret_prompt="pre_shared_key", strip=("location", "managed_by"),
       no_delete="a location may depend on it, so a VPN credential is never deleted here",
       why="created only with a pre-shared key you type (the backup never holds one); never updated or deleted here", uses=()),
    _t("zia.static_ips", "Static IP addresses", "traffic_static_ip", "list_static_ips", level="read", scopes=_Z, name="ip_address",
       why=_TENANT_BOUND, clone_why="a static IP address belongs to one organisation",
       manual="add the target's own static IP addresses in the ZIA Admin Portal"),
    _t("zia.gre_tunnels", "GRE tunnels", "gre_tunnel", "list_gre_tunnels", level="read", scopes=_Z, name="source_ip",
       why=_TENANT_BOUND, clone_why="a GRE tunnel is bound to the tenant's static IP address",
       manual="set up GRE tunnels from the target's own static IP addresses"),
    _t("zia.locations", "Locations", "locations", "list_locations", level="read", scopes=_Z, why=_TENANT_BOUND,
       clone_why="a location is bound to the tenant's IP addresses and VPN credentials",
       manual="add the target's locations and sub-locations with their own IP addresses and VPN credentials"),
    _t("zia.location_groups", "Location groups", "locations", "list_location_groups", level="read", scopes=_Z, why=_TENANT_BOUND),
    _t("zia.groups", "Groups", "user_management", "list_groups", level="read", scopes=_Z, why=_ID_READ),
    _t("zia.departments", "Departments", "user_management", "list_departments", level="read", scopes=_Z, why=_ID_READ),
    _t("zia.admin_roles", "Admin roles", "admin_roles", "list_roles", level="read", scopes=("zia_extras", "rbac"), why=_ADMIN),
    _t("zia.admin_users", "Admin users", "admin_users", "list_admin_users", level="read", scopes=("zia_extras", "rbac"), name="login_name",
       why=_ADMIN),
    _t("zia.isolation_profiles", "Browser isolation profiles", "cloud_browser_isolation", "list_isolation_profiles", level="read", scopes=_Z,
       why="isolation profiles are made in the Cloud Browser Isolation portal"),
    _t("zia.cloud_app_instances", "Cloud application instances", "cloud_app_instances", "list_cloud_app_instances", level="read", scopes=_Z,
       why="instances name the customer's own SaaS tenants"),
    _t("zia.tenancy_restriction_profiles", "Tenancy restriction profiles", "tenancy_restriction_profile", "list_restriction_profile",
       level="read", scopes=_Z, why="restriction profiles name the customer's own SaaS tenants"),
    _t("zia.workload_groups", "Workload groups", "workload_groups", "list_groups", level="read", scopes=_Z,
       why="workload groups describe the tenant's own cloud workloads"),
    _t("zia.pac_files", "PAC files", "pac_files", "list_pac_files", level="read", scopes=_WEB,
       why="PAC files are versioned and verified in the portal"),
    _t("zia.nss_feeds", "Cloud NSS feeds", "cloud_nss", "list_nss_feed", level="read", scopes=_Z,
       why="a feed carries the SIEM's address and token; set it up in the portal"),
    _t("zia.root_certificates", "Root certificates (proxy chaining)", "proxies", None, None, "raw", None, "raw", raw="/rootCertificates",
       scopes=_Z, why="zscaler-sdk-python 1.11.3 has no root certificate service: read, created and deleted through the request "
       "path /rootCertificates (assumed); never updated", uses=()),
    _t("zia.proxies", "Proxies (proxy chaining)", "proxies", "list_proxies", "get_proxy", "add_proxy", "update_proxy", "delete_proxy",
       scopes=_Z, manual="proxy chaining also needs its proxy gateway and a PROXYCHAIN forwarding rule: add them in the ZIA Admin Portal", uses=("cert",)),
    _t("zia.subscriptions", "Subscriptions", "organization_information", "get_subscriptions", level="read", scopes=_Z, flat=True,
       name="sku", why="what the tenant is licensed for; compared before a clone, never written"),
    _t("zia.org_info", "Organisation information", "organization_information", None, "get_organization_information", singleton=True,
       level="read", scopes=_Z, why="read-only details of the organisation"),
    _t("zia.sub_clouds", "Sub-clouds", "sub_clouds", "list_sub_clouds", level="read", scopes=_Z, why="sub-clouds are arranged with Zscaler"),
    # ── ZPA ──
    _t("zpa.connector_groups", "App Connector groups", "app_connector_groups", "list_connector_groups", "get_connector_group",
       "add_connector_group", "update_connector_group", "delete_connector_group", scopes=("zpa",), state="enabled", zpa_paged=True,
       strip=("connectors", "server_groups", "lss_app_connector_group", "site_name"), uses=()),
    _t("zpa.servers", "Application servers", "servers", "list_servers", "get_server", "add_server", "update_server", "delete_server",
       scopes=("zpa",), state="enabled", zpa_paged=True, strip=("app_server_group_ids",), uses=()),
    _t("zpa.server_groups", "Server groups", "server_groups", "list_groups", "get_group", "add_group", "update_group", "delete_group",
       scopes=("zpa",), state="enabled", zpa_paged=True, strip=("applications",), uses=("app_connector_groups", "servers")),
    _t("zpa.segment_groups", "Segment groups", "segment_groups", "list_groups", "get_group", "add_group", "update_group", "delete_group",
       scopes=("zpa",), state="enabled", zpa_paged=True, strip=("applications",), uses=()),
    _t("zpa.application_segments", "Application segments", "application_segment", "list_segments", "get_segment", "add_segment",
       "update_segment", "delete_segment", scopes=("zpa",), state="enabled", zpa_paged=True, exclude_if=_zpa_special_segment,
       strip=("tcp_port_range", "udp_port_range", "tcp_ports", "udp_ports", "segment_group_name", "clientless_apps", "pra_apps",
              "inspection_apps", "common_apps_dto", "shared_micro_tenant_details", "shared_microtenant_details"), uses=("segment_group_id", "server_groups")),
    _t("zpa.connectors", "App Connectors", "app_connectors", "list_connectors", level="read", scopes=("zpa",), zpa_paged=True,
       why="an App Connector enrols itself with a provisioning key; it is never created here"),
    _t("zpa.service_edge_groups", "Service Edge groups", "service_edge_group", "list_service_edge_groups", level="read", scopes=("zpa",),
       zpa_paged=True, why="Private Service Edges are enrolled on the customer's own hosts"),
    _t("zpa.provisioning_keys", "Provisioning keys", "provisioning", "list_provisioning_keys", level="read", scopes=("zpa",),
       q={"__arg": "connector"}, why="a provisioning key is a secret: the backup keeps only whether one is set"),
    _t("zpa.idps", "Identity providers", "idp", "list_idps", level="read", scopes=("zpa",), zpa_paged=True, why=_ID_READ),
    _t("zpa.saml_attributes", "SAML attributes", "saml_attributes", "list_saml_attributes", level="read", scopes=("zpa",), zpa_paged=True,
       why=_ID_READ),
    _t("zpa.posture_profiles", "Posture profiles", "posture_profiles", "list_posture_profiles", level="read", scopes=("zpa",),
       zpa_paged=True, why="posture profiles are made in the Client Connector Portal"),
    _t("zpa.trusted_networks", "ZPA trusted networks", "trusted_networks", "list_trusted_networks", level="read", scopes=("zpa",),
       zpa_paged=True, why="trusted networks are made in the Client Connector Portal"),
    _t("zpa.machine_groups", "Machine groups", "machine_groups", "list_machine_groups", level="read", scopes=("zpa",), zpa_paged=True,
       why="machine groups are made with machine tunnels"),
    _t("zpa.certificates", "Browser Access certificates", "certificates", "list_issued_certificates", level="read", scopes=("zpa",),
       zpa_paged=True, why="a certificate's private key never leaves ZPA"),
    _t("zpa.lss_configs", "Log streaming (LSS)", "lss", "list_configs", level="read", scopes=("zpa",), zpa_paged=True,
       why="log streaming names the customer's own receivers"),
    _t("zpa.pra_portals", "PRA portals", "pra_portal", "list_portals", level="read", scopes=("zpa",), zpa_paged=True,
       why="a portal is bound to the customer's own certificate and domain"),
    _t("zpa.pra_consoles", "PRA consoles", "pra_console", "list_consoles", level="read", scopes=("zpa",), zpa_paged=True,
       why="consoles follow their PRA segments"),
    _t("zpa.microtenants", "Microtenants", "microtenants", "list_microtenants", level="read", scopes=("zpa",), zpa_paged=True,
       why="microtenants are arranged with Zscaler"),
    _t("zpa.access_rules", "Access policy rules", "policies", "list_rules", level="read", scopes=("zpa",), zpa_paged=True,
       q={"__arg": "access"}, why=_ZPA_POLICY),
    _t("zpa.timeout_rules", "Timeout policy rules", "policies", "list_rules", level="read", scopes=("zpa",), zpa_paged=True,
       q={"__arg": "timeout"}, why=_ZPA_POLICY),
    _t("zpa.forwarding_rules", "Client forwarding policy rules", "policies", "list_rules", level="read", scopes=("zpa",), zpa_paged=True,
       q={"__arg": "client_forwarding"}, why=_ZPA_POLICY),
    _t("zpa.inspection_rules", "Inspection policy rules", "policies", "list_rules", level="read", scopes=("zpa",), zpa_paged=True,
       q={"__arg": "inspection"}, why=_ZPA_POLICY),
    _t("zpa.isolation_rules", "Isolation policy rules", "policies", "list_rules", level="read", scopes=("zpa",), zpa_paged=True,
       q={"__arg": "isolation"}, why=_ZPA_POLICY),
    # ── Client Connector ──
    _t("zcc.trusted_networks", "Trusted networks", "trusted_networks", "list_by_company", None, "add_trusted_network",
       "update_trusted_network", "delete_trusted_network", scopes=("zcc",), name="network_name", upd_body=True, uses=()),
    _t("zcc.forwarding_profiles", "Forwarding profiles", "forwarding_profile", "list_by_company", None, "update_forwarding_profile",
       "update_forwarding_profile", None, scopes=("zcc",), upd_body=True, add_via_upd=True,
       no_delete="an app profile may link to it: delete a forwarding profile in Bulk changes → Delete a Client Connector profile", uses=("trusted_network_ids",)),
    _t("zcc.fail_open_policy", "Fail-open settings", "fail_open_policy", "list_by_company", None, None, "update_failopen_policy", None,
       scopes=("zcc",), level="update", upd_body=True, name="id", uses=()),
    _t("zcc.web_privacy", "Privacy settings", "web_privacy", None, "get_web_privacy", None, "set_web_privacy_info", singleton=True,
       level="update", scopes=("zcc",)),
    _t("zcc.device_cleanup", "Device cleanup settings", "devices", None, "get_device_cleanup_info", None, "update_device_cleanup_info",
       singleton=True, level="update", scopes=("zcc",)),
    _t("zcc.app_profiles", "App profiles", "web_policy", "list_by_company", level="read", scopes=("zcc",),
       why="an app profile carries passwords and a policy token the backup never holds; build one in Bulk changes → Build new"),
    _t("zcc.zpa_entitlements", "ZPA entitlements", "entitlements", None, "get_zpa_group_entitlements", singleton=True, level="read",
       scopes=("zcc",), why="the SDK's entitlement update takes no settings"),
    _t("zcc.zdx_entitlements", "ZDX entitlements", "entitlements", None, "get_zdx_group_entitlements", singleton=True, level="read",
       scopes=("zcc",), why="the SDK's entitlement update takes no settings"),
    _t("zcc.web_app_services", "Web app services", "web_app_service", "list_by_company", level="read", scopes=("zcc",),
       why="the SDK can only list them"),
    _t("zcc.company_info", "Company information", "company", None, "get_company_info", singleton=True, level="read", scopes=("zcc",),
       why="company information is read-only"),
    _t("zcc.admin_roles", "Client Connector admin roles", "admin_user", "list_admin_roles", level="read", scopes=("zcc",), why=_ADMIN),
]
BY_KEY: Dict[str, Dict[str, Any]] = {t["key"]: t for t in TYPES}
# What the other tools' lists name that is deliberately not backed up here.
NOT_COVERED = [
    ("zia.users", "ZIA users", "identity comes from the identity provider, and a backup of every user is personal data"),
    ("zia.proxy_gateways", "Proxy gateways", "a gateway is set up in the portal (a manual step the clone report names)"),
    ("zpa.scim_groups", "SCIM groups", "identity comes from the identity provider"),
    ("zpa.enrollment_certs", "Enrollment certificates", "a certificate's private key never leaves ZPA"),
    ("zcc.devices", "Client Connector devices", "an inventory of devices and people, not configuration"),
    ("zcc.ip_apps", "IP-based and process-based app bypasses", "the SDK can read them one by one only"),
]


def types_for(product: str) -> List[Dict[str, Any]]:
    return [t for t in TYPES if t["product"] == product]


def writable(t: Dict[str, Any]) -> bool:
    return t["level"] in ("full", "update")


def allowed(t: Dict[str, Any], scope: Dict[str, Any]) -> bool:
    """Is this type in scope on the Scope page (admin_ops.scope_for's
    answer)? A rule type follows its policy (and so its channel)."""
    if t["policy"]:
        return t["policy"] in (scope.get("policies") or [])
    return bool(set(t["scopes"]) & set(scope.get("scopes") or []))


def coverage() -> Dict[str, Any]:
    """What is backed up and what can be written back, per product."""
    out = {}
    for p in PRODUCTS:
        out[p] = [{"key": t["key"], "label": t["label"], "level": t["level"], "why": t["why"], "clone": not t["clone_why"],
                   "clone_why": t["clone_why"], "singleton": t["singleton"]} for t in types_for(p)]
    return {"products": out, "not_covered": [{"key": k, "label": lab, "why": w} for k, lab, w in NOT_COVERED],
            "volatile": WORDS_VOLATILE}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _text(v: Any, n: int = 200) -> str:
    return _CONTROL.sub(" ", str(v if v is not None else ""))[:n].strip()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=False)


def digest(v: Any) -> str:
    return hashlib.sha256(canonical(v).encode("utf-8")).hexdigest()


def name_of(t: Dict[str, Any], row: Dict[str, Any]) -> str:
    if t["singleton"]:
        return t["label"]
    for f in (t["name"], "name", "configured_name", "network_name", "fqdn", "ip_address"):
        v = row.get(f)
        if v not in (None, ""):
            return _text(v, 255)
    return f"#{_text(row.get('id'), 60)}"


def rid(row: Dict[str, Any]) -> str:
    v = row.get("id")
    return "" if v is None else str(v)


def is_secret_key(key: str) -> bool:
    """A field the snapshot rule treats as a secret (offline_tenant.scrub)."""
    import offline_tenant as ot
    k = str(key)
    return bool(ot._SECRET_KEY.search(k) or ot._PASS_SUFFIX.search(k) or ot._OTP_KEY.search(k) or ot._TOKEN_KEY.search(k))


def mask(value: Any) -> Any:
    """A copy with every secret-named field's value replaced by "(set)" or
    "(not set)" (the snapshot rule, offline_tenant.scrub)."""
    import offline_tenant as ot
    return ot.scrub(value)


def _volatile(path: str, extra: Sequence[str] = ()) -> bool:
    leaf = path.rsplit(".", 1)[-1]
    for pat in tuple(VOLATILE) + tuple(extra):
        if fnmatch.fnmatchcase(leaf, pat) or fnmatch.fnmatchcase(path, pat):
            return True
    return False


# ---------------------------------------------------------------------------
# Reading (GET only, through the SDK's own list calls)
# ---------------------------------------------------------------------------

def _root(client: Any, product: str) -> Any:
    try:
        return getattr(client, product, None)
    except Exception:  # noqa: BLE001 - a client without this product (the classic ZIA sign-in has no ZPA)
        return None


def _service(client: Any, t: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
    root = _root(client, t["product"])
    if root is None:
        return None, f"this sign-in has no {PRODUCT_LABELS[t['product']]} service"
    svc = getattr(root, t["svc"], None)
    if svc is None:
        return None, f"the installed zscaler-sdk-python has no {t['svc']} service"
    return svc, None


def _plain_rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    import pack_export
    return pack_export._rows(ret)


def _one(ret: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    import pack_export
    return pack_export.one_row(ret)


def _stopped(cancel: Any) -> bool:
    return bool(cancel is not None and getattr(cancel, "is_set", lambda: False)())


def _list_zpa(fn: Callable[..., Any], args: Tuple[Any, ...], q: Dict[str, Any], cancel: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    import pack_export
    ret = fn(*args, query_params=dict(q, page_size="500"))
    rows, err = _plain_rows(ret)
    if err:
        return [], err
    resp = ret[1] if isinstance(ret, tuple) and len(ret) >= 3 else None
    pages = 0
    while resp is not None and callable(getattr(resp, "has_next", None)) and resp.has_next() and pages < MAX_ZPA_PAGES:
        if _stopped(cancel):
            break
        data, _r, perr = resp.next()
        if perr:
            return rows, str(perr)[:200]
        rows.extend(pack_export._plain(x) for x in data or [])
        pages += 1
    return rows, None


def read_type(client: Any, t: Dict[str, Any], cancel: Any = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of one type as plain snake_case dicts, secrets masked.
    (rows, error). Read-only."""
    svc, err = _service(client, t)
    if err:
        return [], err
    try:
        if t["singleton"]:
            row, err = _one(getattr(svc, t["get"])())
            return ([mask(row)] if row else []), err
        if t["raw"]:
            import pack_channels as pc
            import pack_export
            data, err = pc.raw_get(_root(client, t["product"]), t["raw"])
            if err:
                return [], str(err)[:200]
            items = data if isinstance(data, list) else []
            return [mask(pack_export._plain(x)) for x in items if isinstance(x, dict)][:MAX_ROWS_PER_TYPE], None
        fn = getattr(svc, t["ls"])
        if t["flat"]:
            import pack_export
            from dlp_importer import _nx
            data, err = _nx(fn())
            if err:
                return [], str(err)[:200]
            items = data if isinstance(data, list) else ([data] if data is not None else [])
            return [mask(pack_export._plain(x)) for x in items][:MAX_ROWS_PER_TYPE], None
        q = dict(t["q"] or {})
        args: Tuple[Any, ...] = ()
        if "__arg" in q:
            args = (q.pop("__arg"),)
        if t["per_type"]:
            import pack_channels as pc
            rows: List[Dict[str, Any]] = []
            for rt in pc.CLOUD_APP_TYPES:
                if _stopped(cancel):
                    break
                got, err = _plain_rows(fn(rt))
                if err:
                    return [mask(r) for r in rows], err
                for r in got:
                    r["type"] = str(r.get("type") or rt)
                rows.extend(got)
        elif t["zpa_paged"]:
            rows, err = _list_zpa(fn, args, q, cancel)
        else:
            rows, err = _plain_rows(fn(*args, query_params=q) if q else fn(*args))
        if len(rows) > MAX_ROWS_PER_TYPE:
            return [mask(r) for r in rows[:MAX_ROWS_PER_TYPE]], f"more than {MAX_ROWS_PER_TYPE} objects; the first {MAX_ROWS_PER_TYPE} were kept"
        return [mask(r) for r in rows], err
    except Exception as e:  # noqa: BLE001 - reported as the read error of this type
        import tenant_auth
        return [], tenant_auth.redact_tokens(f"{type(e).__name__}: {str(e)[:200]}")


def get_one(client: Any, t: Dict[str, Any], oid: Any, rule_type: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object read fresh (the re-read before a write and the read-back),
    secrets masked. A type without a get call is found in its list."""
    if t["singleton"]:
        rows, err = read_type(client, t)
        return (rows[0] if rows else None), err
    svc, err = _service(client, t)
    if err:
        return None, err
    if not t["get"]:
        rows, err = read_type(client, t)
        if err:
            return None, err
        hit = next((r for r in rows if rid(r) == str(oid)), None)
        return hit, None if hit else "not found"
    try:
        fn = getattr(svc, t["get"])
        row, err = _one(fn(rule_type, oid) if t["per_type"] else fn(oid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    if row is not None and t["per_type"]:
        row["type"] = str(row.get("type") or rule_type)
    return (mask(row) if row is not None else None), err


def write_call(root: Any, key: str, op: str, oid: Any = None, body: Optional[Dict[str, Any]] = None,
               rule_type: str = "") -> Tuple[Optional[Callable[..., Any]], Tuple[Any, ...], Dict[str, Any], Optional[str]]:
    """The SDK call a restore write makes for one object of type `key`:
    (fn, args, kwargs, error). Used by pack_ops (create / update / delete),
    which runs it with its retries, rate-limit handling, Stop and audit."""
    t = BY_KEY.get(key)
    if t is None or not writable(t):
        return None, (), {}, f"'{str(key)[:60]}' is not an object type a restore writes"
    if root is None:
        return None, (), {}, f"this sign-in has no {PRODUCT_LABELS[t['product']]} service"
    body = dict(body or {})
    method = {"create": t["add"], "update": t["upd"], "delete": t["rm"]}.get(op)
    if op == "create" and t["add_via_upd"]:
        method = t["upd"]
    if not method:
        return None, (), {}, f"{t['label']} cannot be {op}d here"
    if method == "raw":
        import pack_channels as pc
        if op == "create":
            return pc.raw_request, (root, "POST", t["raw"], body), {}, None
        if pc.path_id(oid) is None:
            return None, (), {}, f"'{str(oid)[:40]}' is not a ZIA id (a number); nothing was sent"
        return pc.raw_request, (root, "DELETE", f"{t['raw']}/{oid}"), {}, None
    svc = getattr(root, t["svc"], None)
    fn = getattr(svc, method, None) if svc is not None else None
    if not callable(fn):
        return None, (), {}, f"the installed zscaler-sdk-python has no {t['svc']}.{method}"
    lead: Tuple[Any, ...] = (rule_type or str(body.pop("type", "") or ""),) if t["per_type"] else ()
    if op == "delete":
        return fn, lead + (oid,), {}, None
    if op == "update":
        if t["singleton"]:
            return fn, (), body, None
        if t["upd_body"]:
            return fn, (), dict(body, id=oid), None
        return fn, lead + (oid,), body, None
    args = tuple(body.pop(k, None) for k in t["add_pos"])
    return fn, lead + args, body, None


def capture(client: Any, products: Iterable[str], scope: Dict[str, Any], log: Optional[Callable[[str], None]] = None,
            cancel: Any = None, only: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Read every type of `products` that is in scope (or only the type keys
    `only`). {types, unread, out_of_scope, counts, stopped}. Read-only."""
    say = log or (lambda m: None)
    want = set(only) if only is not None else None
    out: Dict[str, Any] = {"types": {}, "unread": {}, "out_of_scope": [], "counts": {"types": 0, "objects": 0}, "stopped": False}
    for p in products:
        if p not in PRODUCTS:
            continue
        for t in types_for(p):
            if want is not None and t["key"] not in want:
                continue
            if not allowed(t, scope):
                out["out_of_scope"].append(t["key"])
                continue
            if _stopped(cancel):
                out["stopped"] = True
                say("Stopped: nothing more is read.")
                return out
            rows, err = read_type(client, t, cancel)
            if err and not rows:
                out["unread"][t["key"]] = _text(err, 200)
                say(f"{PRODUCT_LABELS[p]} {t['label']}: not read ({_text(err, 120)}).")
                continue
            if err:
                out["unread"][t["key"]] = _text(err, 200)
            out["types"][t["key"]] = rows
            out["counts"]["types"] += 1
            out["counts"]["objects"] += len(rows)
            say(f"{PRODUCT_LABELS[p]} {t['label']}: {len(rows)}.")
    return out


# ---------------------------------------------------------------------------
# The backup document (untrusted when opened)
# ---------------------------------------------------------------------------

def _clean_meta(meta: Any) -> Dict[str, Any]:
    m = meta if isinstance(meta, dict) else {}
    prods = [p for p in (m.get("products") or []) if p in PRODUCTS] if isinstance(m.get("products"), list) else []
    kind = m.get("kind") if m.get("kind") in KINDS else "manual"
    out = {"tenant_label": _text(m.get("tenant_label")), "saved_at": _text(m.get("saved_at"), 40), "products": sorted(set(prods)),
           "kind": kind, "profile_id": _text(m.get("profile_id"), 48), "note": _text(m.get("note"), 200),
           "scopes": [_text(s, 40) for s in (m.get("scopes") or [])[:20]] if isinstance(m.get("scopes"), list) else [],
           "unread": {k: _text(v, 200) for k, v in list((m.get("unread") or {}).items())[:200] if k in BY_KEY}
           if isinstance(m.get("unread"), dict) else {}}
    for k in ("tenant_key", "tenant_fp"):
        v = m.get(k)
        if isinstance(v, str) and re.fullmatch(r"[A-Za-z0-9:_\-]{1,128}", v):
            out[k] = v
    own = m.get("owner_id")
    if isinstance(own, str) and OWNER_ID.match(own):
        out["owner_id"] = own   # team mode: the account that kept it (team_server.current_owner_id)
    return out


def build_doc(types: Dict[str, List[Dict[str, Any]]], meta: Dict[str, Any]) -> Dict[str, Any]:
    """The backup document: format, version, cleaned meta and the masked
    objects of known types. Never a credential."""
    body = {k: [mask(r) for r in rows if isinstance(r, dict)][:MAX_ROWS_PER_TYPE] for k, rows in (types or {}).items() if k in BY_KEY}
    m = _clean_meta(meta)
    m["counts"] = {k: len(v) for k, v in body.items()}
    return {"format": FORMAT, "version": VERSION, "meta": m, "types": body}


def dumps(doc: Dict[str, Any]) -> str:
    return json.dumps(doc, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str)


def _load_untrusted(raw: Any, limit: int, what: str) -> Any:
    import offline_tenant as ot
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogatepass")
    if not isinstance(raw, (bytes, bytearray)):
        raise BackupError(f"The {what} is not a file.")
    if len(raw) > limit:
        raise BackupError(f"The {what} is larger than {limit // (1024 * 1024)} MB; it was not opened.")
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError:
        raise BackupError(f"The {what} is not a UTF-8 text file; it was not opened.")
    if ot._nesting(text) > ot.MAX_DEPTH:
        raise BackupError(f"The {what} is nested more than {ot.MAX_DEPTH} levels deep; it was not opened.")
    try:
        doc = safe_files.strict_json_loads(text)
    except (ValueError, RecursionError):
        raise BackupError(f"The {what} is not valid JSON; it was not opened.")
    if ot._count_nodes(doc) > ot.MAX_NODES:
        raise BackupError(f"The {what} holds too many values; it was not opened.")
    return doc


def _check_rows(rows: Any, key: str, what: str) -> List[Dict[str, Any]]:
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise BackupError(f"The {what} has objects of {_text(key, 60)} that are not in the expected form; it was not opened.")
    if len(rows) > MAX_ROWS_PER_TYPE:
        raise BackupError(f"The {what} holds more than {MAX_ROWS_PER_TYPE} objects of one type; it was not opened.")
    return [mask(r) for r in rows]


def parse_doc(raw: Any) -> Dict[str, Any]:
    """Check an untrusted backup file and return the document: size,
    nesting, node count, format, version, only known fields and type keys,
    every object a JSON object; secrets masked again."""
    doc = _load_untrusted(raw, MAX_BACKUP_BYTES, "backup")
    if not isinstance(doc, dict) or doc.get("format") != FORMAT:
        raise BackupError("This file is not a Zscaler Made Easy configuration backup.")
    if doc.get("version") != VERSION:
        raise BackupError(f"This backup was saved in format version {_text(doc.get('version'), 10)}; this app opens version {VERSION}.")
    extra = set(doc) - {"format", "version", "meta", "types"}
    if extra:
        raise BackupError("The backup has fields this app does not know; it was not opened.")
    types = doc.get("types")
    if not isinstance(types, dict):
        raise BackupError("The backup holds no configuration.")
    unknown = [k for k in types if k not in BY_KEY]
    if unknown:
        raise BackupError(f"The backup has object types this app does not know ({', '.join(_text(k, 40) for k in unknown[:3])}); it was not opened.")
    out = {k: _check_rows(v, k, "backup") for k, v in types.items()}
    meta = _clean_meta(doc.get("meta"))
    meta["counts"] = {k: len(v) for k, v in out.items()}
    return {"format": FORMAT, "version": VERSION, "meta": meta, "types": out}


# ---------------------------------------------------------------------------
# Storage beside the tenant profiles (owner-only)
# ---------------------------------------------------------------------------

def backups_dir() -> str:
    import tenant_profiles
    return os.path.join(os.path.dirname(os.path.abspath(tenant_profiles.store_path())), BACKUP_DIR)


def _index_path() -> str:
    return os.path.join(backups_dir(), "index.json")


def _read_index() -> Dict[str, Any]:
    try:
        with open(_index_path(), "rb") as f:
            data = safe_files.strict_json_loads(store_crypto.open_text(f.read(_sealed_cap(4 * 1024 * 1024)).decode("utf-8")))
    except store_crypto.StoreLocked as e:
        # A sealed index whose key is not here is not an empty index: the
        # next save would otherwise replace the list of every backup.
        raise BackupError(f"The backup list is encrypted and cannot be opened here: {e}")
    except (OSError, ValueError, UnicodeDecodeError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    for k in ("backups", "templates", "schedules"):
        if not isinstance(data.get(k), dict):
            data[k] = {}
    return data


def _write_index(data: Dict[str, Any]) -> None:
    safe_files.private_makedirs(backups_dir())
    safe_files.write_private_atomic(_index_path(), store_crypto.seal_text(json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True)))


def _file(oid: str) -> str:
    if not (BACKUP_ID.match(str(oid)) or TEMPLATE_ID.match(str(oid))):
        raise BackupError("No such backup or template.")
    return os.path.join(backups_dir(), oid + ".json")


def _unlink(oid: str) -> None:
    try:
        os.unlink(_file(oid))
    except (OSError, BackupError):
        pass


def _summary(doc: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    m = doc["meta"]
    s = {k: m.get(k) for k in ("tenant_label", "saved_at", "products", "kind", "profile_id", "note", "tenant_key", "tenant_fp", "owner_id")
         if m.get(k) not in (None, "")}
    s["objects"] = sum(len(v) for v in doc["types"].values())
    s["types"] = len(doc["types"])
    s["unread"] = len(m.get("unread") or {})
    s.update(extra)
    return s


def save_backup(doc: Dict[str, Any], *, keep: Optional[int] = None) -> Dict[str, Any]:
    """Write a backup (owner-only) under a new id and keep the profile's
    newest `keep` (its schedule's keep, else DEFAULT_KEEP)."""
    text = dumps(doc)
    if len(text.encode("utf-8")) > MAX_BACKUP_BYTES:
        raise BackupError("The configuration read is larger than a backup may be; untick some products and save again.")
    bid = "bk-" + secrets.token_hex(8)
    with _LOCK:
        data = _read_index()
        pid = doc["meta"].get("profile_id") or ""
        safe_files.private_makedirs(backups_dir())
        safe_files.write_private_atomic(_file(bid), store_crypto.seal_text(text))
        data["backups"][bid] = _summary(doc, {"bytes": len(text.encode("utf-8"))})
        if keep is None:
            keep = int((data["schedules"].get(pid) or {}).get("keep") or DEFAULT_KEEP)
        _prune(data, pid, keep)
        _write_index(data)
        return dict(data["backups"].get(bid) or {}, id=bid)


def _prune(data: Dict[str, Any], pid: str, keep: int) -> List[str]:
    keep = max(1, min(MAX_KEEP, int(keep)))
    mine = sorted((k for k, v in data["backups"].items() if isinstance(v, dict) and (v.get("profile_id") or "") == pid),
                  key=lambda k: (str(data["backups"][k].get("saved_at") or ""), k))
    gone = mine[:-keep] if len(mine) > keep else []
    for old in gone:
        _unlink(old)
        data["backups"].pop(old, None)
    return gone


def list_backups(profile_id: Optional[str] = None) -> List[Dict[str, Any]]:
    with _LOCK:
        data = _read_index()
    rows = [dict(v, id=k) for k, v in data["backups"].items() if BACKUP_ID.match(k) and isinstance(v, dict)]
    if profile_id is not None:
        rows = [r for r in rows if (r.get("profile_id") or "") == profile_id]
    return sorted(rows, key=lambda r: str(r.get("saved_at") or ""), reverse=True)


def _read_file(oid: str, limit: int) -> bytes:
    """The plain bytes of a kept backup or template: a sealed file
    (store_crypto) is opened with its key first, then held to `limit`."""
    path = _file(oid)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            raw = f.read(_sealed_cap(limit) + 1)
    except OSError:
        raise BackupError("The file is missing.")
    raw = _opened(raw)
    if len(raw) > limit:
        raise BackupError("The file is too large.")
    return raw


def _opened(raw: bytes) -> bytes:
    try:
        return store_crypto.open_bytes(raw)
    except store_crypto.StoreLocked as e:
        raise BackupError(f"The file is encrypted and cannot be opened here: {e}")


def read_backup_raw(bid: str) -> bytes:
    if not BACKUP_ID.match(str(bid)):
        raise BackupError("No such backup.")
    with _LOCK:
        if bid not in _read_index()["backups"]:
            raise BackupError("No such backup.")
    return _read_file(bid, MAX_BACKUP_BYTES)


def load_backup(bid: str) -> Dict[str, Any]:
    """A saved backup, checked as untrusted (it is a file on disk)."""
    doc = parse_doc(read_backup_raw(bid))
    doc["id"] = bid
    return doc


def delete_backup(bid: str) -> bool:
    if not BACKUP_ID.match(str(bid)):
        raise BackupError("No such backup.")
    with _LOCK:
        data = _read_index()
        if bid not in data["backups"]:
            return False
        _unlink(bid)
        data["backups"].pop(bid, None)
        _write_index(data)
        return True


def backup_meta(bid: str) -> Optional[Dict[str, Any]]:
    if not BACKUP_ID.match(str(bid)):
        return None
    with _LOCK:
        got = _read_index()["backups"].get(bid)
    return dict(got, id=bid) if isinstance(got, dict) else None


# ---------------------------------------------------------------------------
# Scheduled backups (read-only, so safe unattended)
# ---------------------------------------------------------------------------

def schedule(profile_id: str, *, enabled: bool, every_hours: Any = 24, keep: Any = DEFAULT_KEEP, products: Any = PRODUCTS) -> Dict[str, Any]:
    """Set a profile's backup schedule. Validated; returns it."""
    import tenant_profiles
    if not tenant_profiles.get(profile_id):
        raise BackupError("Pick a saved tenant profile: a schedule belongs to one.")
    try:
        hours, kept = int(every_hours), int(keep)
    except (TypeError, ValueError):
        raise BackupError("Every and keep must be whole numbers.")
    if not MIN_EVERY_HOURS <= hours <= MAX_EVERY_HOURS:
        raise BackupError(f"Back up every {MIN_EVERY_HOURS} to {MAX_EVERY_HOURS} hours.")
    if not 1 <= kept <= MAX_KEEP:
        raise BackupError(f"Keep 1 to {MAX_KEEP} backups.")
    prods = [p for p in (products or []) if p in PRODUCTS] if isinstance(products, list) else []
    if enabled and not prods:
        raise BackupError("Pick at least one product to back up.")
    with _LOCK:
        data = _read_index()
        old = data["schedules"].get(profile_id) or {}
        entry = {"enabled": bool(enabled), "every_hours": hours, "keep": kept, "products": prods,
                 "last_run": old.get("last_run") or "", "last_result": old.get("last_result") or "", "updated_at": _now()}
        data["schedules"][profile_id] = entry
        _prune(data, profile_id, kept)
        _write_index(data)
    return dict(entry, profile_id=profile_id)


def schedules() -> Dict[str, Dict[str, Any]]:
    with _LOCK:
        return dict(_read_index()["schedules"])


def due(now: Optional[datetime] = None) -> List[str]:
    """Profiles whose schedule is on and whose last run is older than its interval."""
    now = now or datetime.now(timezone.utc)
    out = []
    for pid, s in schedules().items():
        if not isinstance(s, dict) or not s.get("enabled"):
            continue
        try:
            last = datetime.fromisoformat(str(s.get("last_run"))) if s.get("last_run") else None
        except ValueError:
            last = None
        if last is None or now - last >= timedelta(hours=int(s.get("every_hours") or 24)):
            out.append(pid)
    return sorted(out)


def _note_run(pid: str, result: str, now: datetime) -> None:
    with _LOCK:
        data = _read_index()
        s = data["schedules"].get(pid)
        if isinstance(s, dict):
            s.update(last_run=now.isoformat(timespec="seconds"), last_result=_text(result, 300))
            _write_index(data)


def run_due(build_client: Callable[[Dict[str, str]], Any], now: Optional[datetime] = None,
            log: Optional[Callable[[str], None]] = None) -> List[Dict[str, Any]]:
    """Back up every profile that is due: read-only, only what the
    profile's own Scope page selection puts in scope, only when the profile
    remembers its secret. Never writes to a tenant. One line per profile."""
    import admin_ops
    import pack_jobs
    import tenant_auth
    import tenant_fingerprint
    import tenant_profiles
    now = now or datetime.now(timezone.utc)
    say = log or (lambda m: None)
    out = []
    for pid in due(now):
        s = schedules().get(pid) or {}
        prof = tenant_profiles.get(pid, with_secret=True) or {}
        if not prof:
            _note_run(pid, "skipped: the profile no longer exists", now)
            continue
        creds = tenant_profiles.creds_from(prof)
        if not tenant_auth.complete(creds):
            _note_run(pid, "skipped: the profile does not remember its secret, so it cannot be read unattended", now)
            out.append({"profile_id": pid, "status": "skipped"})
            continue
        scope = admin_ops.scope_for(prof.get("scopes") or [], prof.get("channels") or {})
        prods = [p for p in s.get("products") or [] if any(allowed(t, scope) for t in types_for(p))]
        if not prods:
            _note_run(pid, "skipped: nothing the schedule names is in the profile's scope", now)
            out.append({"profile_id": pid, "status": "skipped"})
            continue
        try:
            client = build_client(creds)
            got = capture(client, prods, scope, say)
            meta = {"tenant_label": tenant_auth.record_label(creds), "saved_at": now.isoformat(timespec="seconds"), "products": prods,
                    "kind": "scheduled", "profile_id": pid, "scopes": scope.get("scopes"), "unread": got["unread"]}
            meta.update(tenant_fingerprint.record_ids(creds))
            entry = save_backup(build_doc(got["types"], meta), keep=int(s.get("keep") or DEFAULT_KEEP))
            refresh_cache(pid, got["types"], meta)   # the scheduled read refreshes the cache too
            _note_run(pid, f"saved {entry['id']}: {entry.get('objects', 0)} objects", now)
            pack_jobs.write_audit("config_backup", actor="the app itself (schedule)", profile=pid, backup=entry["id"],
                                  tenant=meta["tenant_label"], kind="scheduled", objects=entry.get("objects", 0))
            out.append({"profile_id": pid, "status": "saved", "id": entry["id"]})
        except Exception as e:  # noqa: BLE001 - one profile never stops the others
            msg = tenant_auth.mask_secrets(f"{type(e).__name__}: {str(e)[:200]}", creds)
            _note_run(pid, f"failed: {msg}", now)
            out.append({"profile_id": pid, "status": "failed"})
    return out


def interval_minutes() -> int:
    """How often the schedule is checked (DLP_CHECK_BACKUP_SCHEDULE_MINUTES,
    15 by default, 0 off)."""
    try:
        return max(0, int(os.environ.get("DLP_CHECK_BACKUP_SCHEDULE_MINUTES", "15")))
    except ValueError:
        return 15


# ---------------------------------------------------------------------------
# References, normal form and the field-level diff
# ---------------------------------------------------------------------------

def index(types: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, str]]:
    """{type key: {id: name}} of a set of objects."""
    out: Dict[str, Dict[str, str]] = {}
    for k, rows in (types or {}).items():
        t = BY_KEY.get(k)
        if t is None:
            continue
        out[k] = {rid(r): name_of(t, r) for r in rows if rid(r)}
    return out


def ref_items(value: Any) -> Tuple[List[Tuple[str, str]], str]:
    """The (id, name-if-given) pairs of a reference value and its shape:
    'scalar', 'list', 'dict' or 'dicts'."""
    if isinstance(value, bool):
        return [], "scalar"
    if isinstance(value, dict):
        return ([(str(value.get("id")), str(value.get("name") or ""))] if value.get("id") not in (None, "") else []), "dict"
    if isinstance(value, list):
        out = []
        dicts = any(isinstance(x, dict) for x in value)
        for x in value:
            if isinstance(x, dict):
                if x.get("id") not in (None, ""):
                    out.append((str(x.get("id")), str(x.get("name") or "")))
            elif x not in (None, ""):
                out.append((str(x), ""))
        return out, "dicts" if dicts else "list"
    if value in (None, "", 0, "0"):
        return [], "scalar"
    return [(str(value), "")], "scalar"


def refs_of(t: Dict[str, Any]) -> Dict[str, str]:
    """The reference fields of a type: its own list (`uses`), else every
    reference field of its product (rules)."""
    allr = REFS[t["product"]]
    if t["uses"] is None:
        return dict(allr)
    return {f: allr[f] for f in t["uses"] if f in allr}


def _ref_names(value: Any, target: str, idx: Dict[str, Dict[str, str]]) -> List[str]:
    t = BY_KEY.get(target)
    names = []
    for i, n in ref_items(value)[0]:
        if t is not None and t["global_id"] and t["global_id"](i):
            names.append(f"={i}")
        else:
            names.append(n or (idx.get(target) or {}).get(i) or f"#{i}")
    return sorted(names)


def normal(t: Dict[str, Any], row: Dict[str, Any], idx: Dict[str, Dict[str, str]], ignore: Sequence[str] = ()) -> Dict[str, Any]:
    """The comparable form of an object: no volatile, ignored or stripped
    fields, references as the sorted names of what they point at, lists of
    plain values sorted, so the same configuration reads the same in any
    tenant."""
    refs = refs_of(t)
    out: Dict[str, Any] = {}
    for k, v in row.items():
        if k in t["strip"] or _volatile(k, ignore):
            continue
        if k in refs:
            out[k] = _ref_names(v, refs[k], idx)
        elif t["expr"] and k == t["expr"][0] and isinstance(v, str):
            names = idx.get(t["expr"][1]) or {}
            out[k] = EXPR_ID.sub(lambda m: f"D[{names.get(m.group(1), '#' + m.group(1))}].", v)
        else:
            out[k] = _norm_value(v, k, ignore)
    return out


def _norm_value(v: Any, path: str, ignore: Sequence[str]) -> Any:
    if isinstance(v, dict):
        return {k: _norm_value(x, f"{path}.{k}", ignore) for k, x in v.items() if not _volatile(f"{path}.{k}", ignore)}
    if isinstance(v, list):
        items = [_norm_value(x, path, ignore) for x in v]
        try:
            return sorted(items, key=canonical)
        except TypeError:
            return items
    return v


def _flat(v: Any, prefix: str = "") -> Dict[str, Any]:
    if isinstance(v, dict) and v:
        out: Dict[str, Any] = {}
        for k, x in v.items():
            out.update(_flat(x, f"{prefix}.{k}" if prefix else str(k)))
        return out
    return {prefix: v}


def field_diff(a: Dict[str, Any], b: Dict[str, Any]) -> List[Dict[str, Any]]:
    """[{path, old, new}] between two normal forms, sorted by path. A field
    that is empty on one side and absent on the other is no difference."""
    fa, fb = _flat(a), _flat(b)
    empty = (None, "", [], {})
    out = []
    for p in sorted(set(fa) | set(fb)):
        x, y = fa.get(p), fb.get(p)
        if canonical(x) != canonical(y) and not (x in empty and y in empty):
            out.append({"path": p, "old": x, "new": y})
    return out


def _keyed(t: Dict[str, Any], rows: List[Dict[str, Any]], by: str) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    if t["singleton"]:
        return {"(settings)": rows[0]} if rows else {}
    for r in rows:
        k = rid(r) if by == "id" and rid(r) else name_of(t, r)
        base, n = k, 2
        while k in out:
            k, n = f"{base} #{n}", n + 1
        out[k] = r
    return out


def diff(old: Dict[str, Any], new: Dict[str, Any], *, ignore: Sequence[str] = (), by: str = "name", limit: int = 500) -> Dict[str, Any]:
    """Field-level diff of two backups' `types` (old → new): per type the
    objects added, removed and changed with each changed field's old and
    new value. Objects are matched by `by` ("id" within one tenant, "name"
    across tenants); volatile fields and the `ignore` patterns (field names
    or dotted paths, * wildcards) are left out. Types read on one side only
    are named, never counted as emptied."""
    ign = tuple(str(x)[:80] for x in (ignore or [])[:50])
    ot, nt = (old or {}).get("types") or {}, (new or {}).get("types") or {}
    oi, ni = index(ot), index(nt)
    rows, totals = [], {"added": 0, "removed": 0, "changed": 0}
    for key in [t["key"] for t in TYPES if t["key"] in ot and t["key"] in nt]:
        t = BY_KEY[key]
        om, nm = _keyed(t, ot[key], by), _keyed(t, nt[key], by)
        label = (lambda m, k: name_of(t, m[k]) if by == "id" else k)
        added = [label(nm, k) for k in nm if k not in om]
        removed = [label(om, k) for k in om if k not in nm]
        changed = []
        for k in nm:
            if k in om:
                fd = field_diff(normal(t, om[k], oi, ign), normal(t, nm[k], ni, ign))
                if fd:
                    changed.append({"name": label(nm, k), "fields": fd[:100]})
        if added or removed or changed:
            rows.append({"type": key, "label": t["label"], "product": t["product"], "added": sorted(added)[:limit],
                         "removed": sorted(removed)[:limit], "changed": changed[:limit],
                         "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)}})
            totals["added"] += len(added)
            totals["removed"] += len(removed)
            totals["changed"] += len(changed)
    only_old = sorted(BY_KEY[k]["label"] for k in set(ot) - set(nt))
    only_new = sorted(BY_KEY[k]["label"] for k in set(nt) - set(ot))
    return {"types": rows, "totals": totals, "same": not rows, "compared": len(set(ot) & set(nt)), "only_in_old": only_old,
            "only_in_new": only_new, "matched_by": by, "ignored": list(VOLATILE) + list(ign)}


# ---------------------------------------------------------------------------
# Templates: selected objects, ids removed, names parameterised
# ---------------------------------------------------------------------------

def _closure(types: Dict[str, List[Dict[str, Any]]], picks: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """The picked objects (type, id) and every writable object they refer
    to, transitively."""
    by_id = {(k, rid(r)): r for k, rows in types.items() for r in rows}
    seen, todo = [], list(picks)
    while todo:
        k, i = todo.pop(0)
        if (k, i) in seen or (k, i) not in by_id:
            continue
        seen.append((k, i))
        t = BY_KEY[k]
        for f, target in refs_of(t).items():
            tt = BY_KEY.get(target)
            if tt is None or tt["level"] != "full" or f not in by_id[(k, i)]:
                continue
            for ref_id, _n in ref_items(by_id[(k, i)][f])[0]:
                ref = by_id.get((target, ref_id))
                if ref is not None and (tt["keep"] is None or tt["keep"](ref)):
                    todo.append((target, ref_id))
        if t["expr"] and isinstance(by_id[(k, i)].get(t["expr"][0]), str):
            for ref_id in EXPR_ID.findall(by_id[(k, i)][t["expr"][0]]):
                ref = by_id.get((t["expr"][1], ref_id))
                if ref is not None and (BY_KEY[t["expr"][1]]["keep"] is None or BY_KEY[t["expr"][1]]["keep"](ref)):
                    todo.append((t["expr"][1], ref_id))
    return seen


def make_template(doc: Dict[str, Any], picks: Sequence[Dict[str, Any]], *, name: str, description: str = "", strip_prefix: str = "",
                  with_dependencies: bool = True) -> Dict[str, Any]:
    """A portable template from a backup: the picked objects ({type, name}),
    with what they use when `with_dependencies`, ids removed, references by
    name, every own object's name starting with {{prefix}} (a leading
    `strip_prefix` is replaced by it), secret fields dropped."""
    nm = _text(name, 80)
    if not nm:
        raise BackupError("Give the template a name.")
    if strip_prefix and not PREFIX_RE.match(strip_prefix):
        raise BackupError("The prefix to replace may be up to 20 letters, digits, spaces and . _ -.")
    types = {k: [mask(r) for r in rows] for k, rows in (doc.get("types") or {}).items() if k in BY_KEY}
    want: List[Tuple[str, str]] = []
    for p in list(picks or [])[:MAX_TEMPLATE_OBJECTS]:
        if not isinstance(p, dict):
            continue
        k, n = str(p.get("type") or ""), str(p.get("name") or "")
        t = BY_KEY.get(k)
        if t is None or t["level"] != "full" or t["singleton"] or t["clone_why"] or t["secret_prompt"]:
            raise BackupError(f"{_text(k, 60)} cannot go into a template: only objects that can be cloned can.")
        hit = next((r for r in types.get(k) or [] if name_of(t, r) == n), None)
        if hit is None:
            raise BackupError(f"The backup has no {t['label'].lower()} named {_text(n, 80)!r}.")
        if t["keep"] and not t["keep"](hit):
            raise BackupError(f"{_text(n, 80)!r} is predefined by Zscaler: it is in every tenant already.")
        want.append((k, rid(hit)))
    if not want:
        raise BackupError("Pick at least one object for the template.")
    chosen = _closure(types, want) if with_dependencies else want
    if len(chosen) > MAX_TEMPLATE_OBJECTS:
        raise BackupError(f"A template holds at most {MAX_TEMPLATE_OBJECTS} objects.")
    idx = index(types)
    inside = set(chosen)
    objects: Dict[str, List[Dict[str, Any]]] = {}
    for k, i in chosen:
        t = BY_KEY[k]
        row = next(r for r in types[k] if rid(r) == i)
        obj: Dict[str, Any] = {}
        for f, v in row.items():
            if f in t["strip"] or _volatile(f) or is_secret_key(f) or v in MASKS:
                continue
            target = refs_of(t).get(f)
            if t["expr"] and f == t["expr"][0] and isinstance(v, str):
                obj[f] = _template_expr(v, t["expr"][1], idx, inside, strip_prefix, name_of(t, row))
                continue
            if target is not None:
                ids, shape = ref_items(v)
                tt = BY_KEY.get(target)
                refs = []
                for ref_id, ref_name in ids:
                    if tt is not None and tt["global_id"] and tt["global_id"](ref_id):
                        refs.append({"$global": ref_id})
                    else:
                        n = ref_name or (idx.get(target) or {}).get(ref_id) or ""
                        if not n:
                            raise BackupError(f"{name_of(t, row)!r} refers to an object the backup does not name; it cannot go into a template.")
                        own = (target, ref_id) in inside
                        refs.append({"$ref": target, "name": _own_name(n, strip_prefix) if own else n, "own": own})
                obj[f] = {"$refs": refs, "shape": shape}
            else:
                obj[f] = copy.deepcopy(v)
        obj[t["name"]] = _own_name(name_of(t, row), strip_prefix)
        objects.setdefault(k, []).append(obj)
    meta = {"name": nm, "description": _text(description, 300), "created_at": _now(), "source": _text((doc.get("meta") or {}).get("tenant_label")),
            "products": sorted({BY_KEY[k]["product"] for k in objects}), "objects": sum(len(v) for v in objects.values())}
    return {"format": TEMPLATE_FORMAT, "version": VERSION, "meta": meta, "objects": objects}


def _template_expr(text: str, target: str, idx: Dict[str, Dict[str, str]], inside: Any, strip_prefix: str, who: str) -> Dict[str, Any]:
    """An expression naming objects by id, as {"$expr": text with D@<n>.
    markers, "$refs": the referenced objects by name}."""
    refs: List[Dict[str, Any]] = []

    def one(m: "re.Match[str]") -> str:
        i = m.group(1)
        n = (idx.get(target) or {}).get(i)
        if not n:
            raise BackupError(f"{who!r} uses a dictionary the backup does not name; it cannot go into a template.")
        own = (target, i) in inside
        refs.append({"$ref": target, "name": _own_name(n, strip_prefix) if own else n, "own": own})
        return f"D@{len(refs) - 1}."
    return {"$expr": EXPR_ID.sub(one, text), "$refs": refs}


def _own_name(n: str, strip_prefix: str) -> str:
    if strip_prefix and n.startswith(strip_prefix):
        n = n[len(strip_prefix):]
    return PREFIX_TOKEN + n


def parse_template(raw: Any) -> Dict[str, Any]:
    """Check an untrusted template file: size, nesting, format, version,
    known type keys, only writable types, names that carry {{prefix}},
    reference shapes; secret fields dropped."""
    doc = _load_untrusted(raw, MAX_TEMPLATE_BYTES, "template")
    if not isinstance(doc, dict) or doc.get("format") != TEMPLATE_FORMAT:
        raise BackupError("This file is not a Zscaler Made Easy configuration template.")
    if doc.get("version") != VERSION:
        raise BackupError(f"This template is format version {_text(doc.get('version'), 10)}; this app opens version {VERSION}.")
    if set(doc) - {"format", "version", "meta", "objects"}:
        raise BackupError("The template has fields this app does not know; it was not opened.")
    objs = doc.get("objects")
    if not isinstance(objs, dict) or not objs:
        raise BackupError("The template holds no objects.")
    out: Dict[str, List[Dict[str, Any]]] = {}
    total = 0
    for k, rows in objs.items():
        t = BY_KEY.get(k)
        if t is None or t["level"] != "full" or t["singleton"] or t["clone_why"] or t["secret_prompt"]:
            raise BackupError(f"The template names an object type that templates cannot carry ({_text(k, 40)}); it was not opened.")
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise BackupError("The template's objects are not in the expected form; it was not opened.")
        clean = []
        for r in rows:
            n = r.get(t["name"])
            if not isinstance(n, str) or not n.startswith(PREFIX_TOKEN) or len(n) > 255 or _CONTROL.search(n):
                raise BackupError("Every object in a template is named {{prefix}}…; this one is not. It was not opened.")
            row = {}
            for f, v in r.items():
                if not isinstance(f, str) or len(f) > 80 or f == "id" or is_secret_key(f) or v in MASKS:
                    continue
                if isinstance(v, dict) and "$expr" in v:
                    v = _check_expr(v)
                elif isinstance(v, dict) and "$refs" in v:
                    v = _check_refs(v)
                row[f] = v
            clean.append(row)
        total += len(clean)
        out[k] = clean
    if total > MAX_TEMPLATE_OBJECTS:
        raise BackupError(f"A template holds at most {MAX_TEMPLATE_OBJECTS} objects; this one was not opened.")
    m = doc.get("meta") if isinstance(doc.get("meta"), dict) else {}
    meta = {"name": _text(m.get("name"), 80) or "Imported template", "description": _text(m.get("description"), 300),
            "created_at": _text(m.get("created_at"), 40), "source": _text(m.get("source")),
            "products": sorted({BY_KEY[k]["product"] for k in out}), "objects": total}
    return {"format": TEMPLATE_FORMAT, "version": VERSION, "meta": meta, "objects": out}


def _check_expr(v: Dict[str, Any]) -> Dict[str, Any]:
    if set(v) != {"$expr", "$refs"} or not isinstance(v["$expr"], str) or len(v["$expr"]) > 10000:
        raise BackupError("An expression in the template is not in the expected form; it was not opened.")
    refs = _check_refs({"$refs": v["$refs"], "shape": "list"})["$refs"]
    if any("$global" in r for r in refs) or any(int(n) >= len(refs) for n in re.findall(r"D@(\d+)\.", v["$expr"])):
        raise BackupError("An expression in the template names an object it does not list; it was not opened.")
    return {"$expr": v["$expr"], "$refs": refs}


def _check_refs(v: Dict[str, Any]) -> Dict[str, Any]:
    if set(v) - {"$refs", "shape"} or v.get("shape") not in ("scalar", "list", "dict", "dicts") or not isinstance(v.get("$refs"), list):
        raise BackupError("A reference in the template is not in the expected form; it was not opened.")
    refs = []
    for r in v["$refs"][:5000]:
        if isinstance(r, dict) and set(r) == {"$global"} and isinstance(r["$global"], (str, int)):
            refs.append({"$global": _text(r["$global"], 120)})
        elif isinstance(r, dict) and set(r) == {"$ref", "name", "own"} and r["$ref"] in BY_KEY and isinstance(r["name"], str) \
                and isinstance(r["own"], bool) and not _CONTROL.search(r["name"]) and len(r["name"]) <= 255:
            if r["own"] and not r["name"].startswith(PREFIX_TOKEN):
                raise BackupError("A reference to one of the template's own objects must name it {{prefix}}…; it was not opened.")
            refs.append(dict(r))
        else:
            raise BackupError("A reference in the template is not in the expected form; it was not opened.")
    return {"$refs": refs, "shape": v["shape"]}


def apply_prefix(name: str, prefix: str) -> str:
    return prefix + name[len(PREFIX_TOKEN):] if name.startswith(PREFIX_TOKEN) else name


def template_source(tpl: Dict[str, Any], prefix: str) -> Dict[str, Any]:
    """A template as a restore source: its objects with synthetic ids and
    {{prefix}} replaced; references to its own objects by those ids, and
    references to anything else as named stubs the plan finds by name in the
    target (never created). {"types": ..., "own": set of (type, id)}."""
    if not PREFIX_RE.match(prefix or ""):
        raise BackupError("The prefix may be up to 20 letters, digits, spaces and . _ -.")
    types: Dict[str, List[Dict[str, Any]]] = {}
    own_ids: Dict[Tuple[str, str], str] = {}
    n = 0
    for k, rows in (tpl.get("objects") or {}).items():
        t = BY_KEY[k]
        for r in rows:
            n += 1
            own_ids[(k, r[t["name"]])] = _synthetic(k, n, own=True)
    stubs: Dict[Tuple[str, str], str] = {}
    for k, rows in (tpl.get("objects") or {}).items():
        t = BY_KEY[k]
        for r in rows:
            row: Dict[str, Any] = {}
            def resolve(ref: Dict[str, Any]) -> Any:
                if "$global" in ref:
                    return ref["$global"]
                if ref["own"]:
                    sid = own_ids.get((ref["$ref"], ref["name"]))
                    if sid is None:
                        raise BackupError(f"The template refers to its own object {ref['name']!r}, which it does not hold.")
                    return sid
                key = (ref["$ref"], ref["name"])
                if key not in stubs:
                    stubs[key] = _synthetic(key[0], len(stubs) + 1, own=False)
                return stubs[key]
            for f, v in r.items():
                if isinstance(v, dict) and "$expr" in v:
                    ids = [resolve(ref) for ref in v["$refs"]]
                    row[f] = re.sub(r"D@(\d+)\.", lambda m: f"D{ids[int(m.group(1))]}.", v["$expr"])
                elif isinstance(v, dict) and "$refs" in v:
                    row[f] = _shape([resolve(ref) for ref in v["$refs"]], v["shape"])
                else:
                    row[f] = copy.deepcopy(v)
            row["id"] = own_ids[(k, r[t["name"]])]
            nm = apply_prefix(r[t["name"]], prefix)
            if len(nm) > 255:
                raise BackupError("A name is longer than 255 characters with the prefix.")
            row[t["name"]] = nm
            types.setdefault(k, []).append(row)
    for (k, nm), sid in stubs.items():
        t = BY_KEY.get(k)
        types.setdefault(k, []).append({"id": sid, (t["name"] if t else "name"): nm, "$stub": True})
    return {"types": types, "own": {(k, sid) for (k, _n), sid in own_ids.items()}}


def _synthetic(key: str, n: int, *, own: bool) -> str:
    """A template object's stand-in id: digits (as an engine expression's
    D<id> needs), or CUSTOM_… for a URL category (any other category id is a
    predefined one, the same in every tenant)."""
    if key == "zia.url_categories":
        return f"CUSTOM_{'T' if own else 'X'}{n}"
    return str((9_100_000_000 if own else 9_200_000_000) + n)


def _shape(ids: List[Any], shape: str) -> Any:
    if shape == "scalar":
        return ids[0] if ids else None
    if shape == "dict":
        return {"id": ids[0]} if ids else None
    if shape == "dicts":
        return [{"id": i} for i in ids]
    return list(ids)


def save_template(tpl: Dict[str, Any], *, profile_id: str = "", owner_id: str = "", tenant_ids: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Keep a template (owner-only, sealed when store encryption is on).
    The index entry names the tenant profile it was made from (its source
    backup's) and the account that kept it, for the team access check; the
    template file itself stays portable and names neither."""
    text = dumps(tpl)
    if len(text.encode("utf-8")) > MAX_TEMPLATE_BYTES:
        raise BackupError("The template is too large; pick fewer objects.")
    tid = "tpl-" + secrets.token_hex(8)
    bind = _clean_meta(dict(tenant_ids or {}, profile_id=profile_id, owner_id=owner_id))
    entry = dict(tpl["meta"], bytes=len(text.encode("utf-8")))
    for k in ("profile_id", "owner_id", "tenant_key", "tenant_fp"):
        if bind.get(k):
            entry[k] = bind[k]
    with _LOCK:
        data = _read_index()
        safe_files.private_makedirs(backups_dir())
        safe_files.write_private_atomic(_file(tid), store_crypto.seal_text(text))
        data["templates"][tid] = entry
        _write_index(data)
    return dict(entry, id=tid)


def template_meta(tid: str) -> Optional[Dict[str, Any]]:
    """A kept template's index entry (who and which tenant profile it is
    bound to), or None."""
    if not TEMPLATE_ID.match(str(tid)):
        return None
    with _LOCK:
        got = _read_index()["templates"].get(tid)
    return dict(got, id=tid) if isinstance(got, dict) else None


def list_templates() -> List[Dict[str, Any]]:
    with _LOCK:
        data = _read_index()
    rows = [dict(v, id=k) for k, v in data["templates"].items() if TEMPLATE_ID.match(k) and isinstance(v, dict)]
    return sorted(rows, key=lambda r: str(r.get("created_at") or ""), reverse=True)


def read_template_raw(tid: str) -> bytes:
    if not TEMPLATE_ID.match(str(tid)):
        raise BackupError("No such template.")
    with _LOCK:
        if tid not in _read_index()["templates"]:
            raise BackupError("No such template.")
    return _read_file(tid, MAX_TEMPLATE_BYTES)


def load_template(tid: str) -> Dict[str, Any]:
    return parse_template(read_template_raw(tid))


# ---------------------------------------------------------------------------
# Templates as a scheduled sync source (sync_jobs.register_template_source)
# ---------------------------------------------------------------------------
# A sync job may read its source rules from a template instead of a tenant.
# The template's objects are served through a read-only stand-in for the
# SDK client: only the list calls of the types this module knows answer
# (the template's rows, or none), as (rows, None, None) like the SDK; every
# other attribute (an add, update or delete) does not exist, so nothing can
# be written through it. Names are kept as the template holds them (no
# prefix): a sync matches rules by name.

class _TemplateService:
    def __init__(self, lists: Dict[str, Tuple[Dict[str, Any], List[Dict[str, Any]]]]):
        self._lists = lists

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name not in self._lists:
            raise AttributeError(name)
        t, rows = self._lists[name]

        def lister(*args: Any, **_kw: Any) -> Tuple[List[Dict[str, Any]], None, None]:
            # A rule list holds the template's own rules; another list also
            # answers with the named stand-ins its rules refer to (so a name
            # lookup finds them), without the stand-in marker.
            rules = bool(t.get("policy")) or t["key"].endswith("_rules")
            out = [{k: copy.deepcopy(v) for k, v in r.items() if k != "$stub"} for r in rows if not (rules and r.get("$stub"))]
            if t.get("per_type") and args and isinstance(args[0], str):
                out = [r for r in out if str(r.get("type") or r.get("rule_type") or "") == args[0]]
            return out, None, None
        return lister


class _TemplateProduct:
    def __init__(self, services: Dict[str, _TemplateService]):
        self._services = services

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name not in self._services:
            raise AttributeError(name)
        return self._services[name]


class TemplateClient:
    """A read-only, SDK-shaped client over a template's objects."""

    def __init__(self, types: Dict[str, List[Dict[str, Any]]]):
        by_product: Dict[str, Dict[str, Dict[str, Tuple[Dict[str, Any], List[Dict[str, Any]]]]]] = {}
        for t in TYPES:
            if t.get("ls"):
                by_product.setdefault(t["product"], {}).setdefault(t["svc"], {})[t["ls"]] = (t, list(types.get(t["key"]) or []))
        self._products = {p: _TemplateProduct({svc: _TemplateService(ls) for svc, ls in svcs.items()}) for p, svcs in by_product.items()}

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_") or name not in self._products:
            raise AttributeError(name)
        return self._products[name]


# The Scope page keys that put a template's products in scope for a sync
# (the template is local data: nothing is read from a tenant through it).
_TEMPLATE_SCOPES = {"zia": ["zia_extras"], "zpa": ["zpa"], "zcc": ["zcc"]}


def template_sources() -> List[Dict[str, Any]]:
    """The saved templates as sync sources: {id, name, scopes}."""
    out = []
    for m in list_templates():
        products = [str(p) for p in m.get("products") or [] if isinstance(p, str)]
        out.append({"id": m["id"], "name": m.get("name") or m["id"],
                    "scopes": sorted({sc for p in products for sc in _TEMPLATE_SCOPES.get(p, [])})})
    return out


def template_client(tid: str) -> TemplateClient:
    """A read-only client over one saved template (its own names, no prefix)."""
    return TemplateClient(template_source(load_template(tid), "")["types"])


def delete_template(tid: str) -> bool:
    if not TEMPLATE_ID.match(str(tid)):
        raise BackupError("No such template.")
    with _LOCK:
        data = _read_index()
        if tid not in data["templates"]:
            return False
        _unlink(tid)
        data["templates"].pop(tid, None)
        _write_index(data)
        return True


# ---------------------------------------------------------------------------
# Snapshots and the sample tenant as backups (offline, no network)
# ---------------------------------------------------------------------------

def from_offline(store: Any, products: Iterable[str] = PRODUCTS) -> Dict[str, Any]:
    """Read an offline tenant (a saved snapshot or the sample) into a backup
    document through the offline SDK client: it has no network code, so this
    never reaches a tenant. Every type is in scope: the snapshot holds only
    what was in scope when it was saved."""
    import admin_ops
    import offline_tenant as ot
    client = ot.OfflineSdkClient(store, ot.creds_for(store))
    scope = admin_ops.scope_for(list(ot.KNOWN_SCOPES), {k: "zscaler" for k in ("web_dlp", "endpoint_dlp", "saas_dlp", "email_dlp",
                                                                              "web", "endpoint", "saas", "email")})
    scope["policies"] = sorted({t["policy"] for t in TYPES if t["policy"]})
    got = capture(client, products, scope)
    kind = "sample" if store.kind == ot.SAMPLE else "snapshot"
    meta = {"tenant_label": store.label, "saved_at": str(store.meta.get("saved_at") or _now()), "products": list(products), "kind": kind,
            "unread": {k: v for k, v in got["unread"].items()}}
    doc = build_doc(got["types"], meta)
    doc["meta"]["unread"] = {k: v for k, v in got["unread"].items() if k in BY_KEY}
    return doc


# ---------------------------------------------------------------------------
# The local configuration cache: one per profile, object by object, with a
# hash per object so a refresh says exactly what changed since the last one
# and a diff against a backup needs no tenant read.
# ---------------------------------------------------------------------------
CACHE_FORMAT = "zscaler-made-easy-config-cache"
CACHE_KEY = re.compile(r"\A[a-z0-9][a-z0-9-]{0,47}\Z")


def object_hash(t: Dict[str, Any], row: Dict[str, Any]) -> str:
    """The hash an object is tracked by: its comparable form (no ids, change
    times or counters; references by id), so an unchanged object keeps it."""
    refs = refs_of(t)
    form = {k: (sorted(i for i, _n in ref_items(v)[0]) if k in refs else _norm_value(v, k, ()))
            for k, v in row.items() if k not in t["strip"] and not _volatile(k)}
    return digest(form)[:32]


def _cache_path(key: str) -> str:
    if not CACHE_KEY.match(str(key)):
        raise BackupError("A cache belongs to a saved tenant profile.")
    return os.path.join(backups_dir(), f"cache-{key}.json")


def read_cache(key: str) -> Optional[Dict[str, Any]]:
    """The cache of a profile (checked as untrusted), or None."""
    path = _cache_path(key)
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "rb") as f:
            raw = f.read(_sealed_cap(MAX_BACKUP_BYTES) + 1)
    except OSError:
        return None
    try:
        doc = _load_untrusted(_opened(raw), MAX_BACKUP_BYTES, "cache")
    except BackupError:
        return None
    if not isinstance(doc, dict) or doc.get("format") != CACHE_FORMAT or not isinstance(doc.get("objects"), dict):
        return None
    objects = {}
    for k, entries in doc["objects"].items():
        if k in BY_KEY and isinstance(entries, dict):
            objects[k] = {str(i): {"hash": str(e.get("hash") or "")[:64], "name": _text(e.get("name"), 255), "row": mask(e.get("row") or {})}
                          for i, e in list(entries.items())[:MAX_ROWS_PER_TYPE] if isinstance(e, dict) and isinstance(e.get("row"), dict)}
    return {"format": CACHE_FORMAT, "meta": _clean_meta(doc.get("meta")), "objects": objects,
            "refreshed_at": _text(doc.get("refreshed_at"), 40), "changes": doc.get("changes") if isinstance(doc.get("changes"), dict) else {}}


def refresh_cache(key: str, types: Dict[str, List[Dict[str, Any]]], meta: Dict[str, Any]) -> Dict[str, Any]:
    """Store a fresh read in the profile's cache and say, per type, which
    objects were added, removed or changed since the last refresh (by
    hash). Types not read this time keep what the cache held. No secret
    is kept (the read is masked)."""
    with _LOCK:
        old = read_cache(key) or {"objects": {}}
        objects = dict(old["objects"])
        changes: Dict[str, Dict[str, List[str]]] = {}
        for k, rows in (types or {}).items():
            t = BY_KEY.get(k)
            if t is None:
                continue
            before = old["objects"].get(k) or {}
            now: Dict[str, Dict[str, Any]] = {}
            for r in rows:
                ident = rid(r) or name_of(t, r)
                now[ident] = {"hash": object_hash(t, r), "name": name_of(t, r), "row": mask(r)}
            ch = {"added": sorted(now[i]["name"] for i in now if i not in before),
                  "removed": sorted(before[i]["name"] for i in before if i not in now),
                  "changed": sorted(now[i]["name"] for i in now if i in before and before[i]["hash"] != now[i]["hash"])}
            if old["objects"] and any(ch.values()):
                changes[k] = ch
            objects[k] = now
        doc = {"format": CACHE_FORMAT, "version": VERSION, "meta": _clean_meta(meta), "objects": objects, "refreshed_at": _now(),
               "changes": changes, "first": not old["objects"]}
        safe_files.private_makedirs(backups_dir())
        text = dumps(doc)
        if len(text.encode("utf-8")) > MAX_BACKUP_BYTES:
            raise BackupError("The configuration read is larger than the cache may be; untick some products.")
        safe_files.write_private_atomic(_cache_path(key), store_crypto.seal_text(text))
    return {"refreshed_at": doc["refreshed_at"], "changes": changes, "first": doc["first"],
            "objects": sum(len(v) for v in objects.values()), "types": len(objects)}


def cache_as_backup(key: str) -> Optional[Dict[str, Any]]:
    """The cache in the backup form, for a diff that reads no tenant."""
    c = read_cache(key)
    if c is None:
        return None
    meta = dict(c["meta"], saved_at=c["refreshed_at"], kind="manual")
    return {"format": FORMAT, "version": VERSION, "meta": meta,
            "types": {k: [e["row"] for e in v.values()] for k, v in c["objects"].items()}}


def cache_summary(key: str) -> Optional[Dict[str, Any]]:
    c = read_cache(key)
    if c is None:
        return None
    return {"refreshed_at": c["refreshed_at"], "objects": sum(len(v) for v in c["objects"].values()), "types": len(c["objects"]),
            "changes": c["changes"], "tenant_label": c["meta"].get("tenant_label") or ""}


def store_files() -> List[str]:
    """Every file this module keeps (index, backups, templates, caches), for
    store_crypto's seal_all and key rotation."""
    import glob
    d = backups_dir()
    out = [os.path.join(d, "index.json")]
    for pat in ("bk-*.json", "tpl-*.json", "cache-*.json"):
        out.extend(sorted(glob.glob(os.path.join(d, pat))))
    return [p for p in out if os.path.isfile(p) and not os.path.islink(p)]
