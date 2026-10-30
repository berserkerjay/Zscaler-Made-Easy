#!/usr/bin/env python3
"""
Export a whole tenant to Terraform: ZIA, ZPA and Cloud & Branch Connector.

Reads the live tenant (or the sample tenant, or an opened snapshot: the
same SDK client interface, offline_tenant.py) within the Scope rule and
writes one Terraform root module per product for the official providers:

    zscaler/zia  ~> 4.8     ZIA (58 resource types)
    zscaler/zpa  ~> 4.4     ZPA (31 resource types)
    zscaler/ztc  ~> 0.2     Cloud & Branch Connector (11 resource types)

so a platform team can adopt an existing tenant into Terraform state
without recreating anything: every exported object has an `import {}`
block (Terraform 1.5+) with its tenant id, and the first `terraform plan`
after `terraform init` should show imports and few or no changes.

Layout of the zip (all paths are made here; none comes from a tenant name):

    <root>/README.md               what was exported, what was not and why
    <root>/export_report.json      the same as data (counts, references, not exported)
    <root>/zia/ | zpa/ | ztc/      one workspace per product read:
        terraform.tf               required_version, provider pin, optional S3 backend
        providers.tf               OneAPI credentials from variables or ZSCALER_* env vars
        variables.tf               credentials and secret maps (sensitive), typed and described
        <area>.tf                  one resource per tenant object, grouped by area
        datasource.tf              lookups by name for what is referenced but not exported
        imports.tf                 one import block per resource
        outputs.tf                 name => id per resource type, each described
        terraform.tfvars.example, .gitignore, README.md

How a tenant object becomes HCL (`render_resource`): the provider's
configurable arguments for the resource type (tenant_terraform_schema) are
filled from the object as the SDK reads it (snake_case), each argument by
its kind; empty values are left out (the provider's own default then
applies, which is what the tenant holds after the import). A reference to
another object is written as that object's Terraform address
(`zia_rule_labels.finance.id`) when both are exported, as a data source
looked up by name (`data.zia_group_management.drivers.id`) when the
provider has one and the name is known, else as the tenant id with the
reference counted as unresolved in the report. A user is never looked up
by name (personal data): its id stays.

What is never written:
  - secrets: every secret-named field is masked as it is read
    (offline_tenant.scrub), and an argument the provider marks sensitive
    (a VPN credential's pre-shared key, a PRA credential's password,
    passphrase or private key) is a `lookup()` in a sensitive map variable
    the operator fills; the tenant's value is never read into the file;
  - personal data, by default: ZIA users and admins are not exported;
    alert subscriptions (email addresses) and PRA approvals (email
    addresses) only with include_personal_data;
  - predefined and default objects (the Default rule, predefined network
    services, dictionaries, engines, URL categories): they exist in every
    tenant, so a rule that names one looks it up by name.

Every type not exported, and every object skipped, is listed with the
reason; nothing is left out silently.

Reading: `read_tenant` is the one reader, GET only, through the SDK's own
list and get calls (verified against zscaler-sdk-python 1.11.3: every
service and method named in TYPES exists in zscaler/zia, zscaler/zpa and
zscaler/ztw). It returns {"types": {key: [rows]}, "unread": {key: why}},
the same shape config_backup.capture (the configuration backups on
another branch) returns, with the same type keys where the two overlap
("zia.firewall_rules", "zpa.segment_groups", ...), so the backup's reader
can feed generate() unchanged once both are merged.

Assumed, not verifiable without a tenant:
  - the ZPA policy rules the SDK reads in the v1 form (operands with lhs /
    rhs) map to the v2 resources' form by putting an operand whose lhs is
    "id" into `values` and every other operand into `entry_values`
    {lhs, rhs}, grouped by object type within a condition;
  - Cloud & Branch Connector gateways of type ZIA, ECSELF or PROXYCHAIN are
    the provider's ztc_forwarding_gateway; other gateway types (DNS) are
    listed as not exported;
  - a bandwidth class is predefined when the API marks it so (type
    BANDWIDTH_CAT_*), as for network services.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import md_safe
from pack_terraform import (GENERATED_MARK, GITIGNORE, TERRAFORM_VERSION, hcl_comment, hcl_fmt, hcl_list, hcl_str, one_line,
                            slug)
from tenant_terraform_schema import SCHEMAS

PRODUCTS = ("zia", "zpa", "ztc")
PRODUCT_LABELS = {"zia": "ZIA", "zpa": "ZPA", "ztc": "Cloud & Branch Connector"}
# The SDK's product for each provider (Cloud & Branch Connector is `ztw` in zscaler-sdk-python).
SDK_ROOT = {"zia": "zia", "zpa": "zpa", "ztc": "ztw"}
PROVIDERS = {
    "zia": {"version": "~> 4.8", "docs": "https://registry.terraform.io/providers/zscaler/zia/latest/docs"},
    "zpa": {"version": "~> 4.4", "docs": "https://registry.terraform.io/providers/zscaler/zpa/latest/docs"},
    "ztc": {"version": "~> 0.2", "docs": "https://registry.terraform.io/providers/zscaler/ztc/latest/docs"},
}
DEFAULT_NAMESPACE = "zscaler"
# A private registry mirror ("registry.example.com/zscaler"): a host name, then one namespace.
NAMESPACE_RE = re.compile(r"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+(?::[0-9]{1,5})?/)?[a-z0-9][a-z0-9_-]{0,63}\Z")
PREFIX_RE = re.compile(r"\A[a-z][a-z0-9_]{0,19}\Z")
MICROTENANT_RE = re.compile(r"\A[0-9]{1,20}\Z")
MAX_ROWS_PER_TYPE = 20000
MAX_ZPA_PAGES = 200
MAX_TYPES_ASKED = 200
ROOT_DIR = "tenant-terraform"

NOTHING_IN_SCOPE = ("Nothing this export reads is in scope on the Scope page: tick DLP or ZIA platform (ZIA), ZPA, or "
                    "Cloud & Branch Connector, and pick at least one product. Nothing was read.")


class ExportRefused(ValueError):
    """A request this export refuses before anything is read (the route's 400)."""


# ---------------------------------------------------------------------------
# References: which attribute names point at which object type
# ---------------------------------------------------------------------------
# A reference to an exported object becomes its Terraform address; to one
# that is not exported, a data source looked up by name when DATA names one
# for the target (and the reference carries a name); else the tenant id.
REFS: Dict[str, Dict[str, str]] = {
    "zia": {
        "locations": "zia.locations", "location_groups": "zia.location_groups", "dynamic_location_groups": "zia.location_groups",
        "static_location_groups": "zia.location_groups", "groups": "zia.groups", "excluded_groups": "zia.groups",
        "override_groups": "zia.groups", "smart_isolation_groups": "zia.groups", "departments": "zia.departments",
        "excluded_departments": "zia.departments", "users": "zia.users", "excluded_users": "zia.users", "override_users": "zia.users",
        "smart_isolation_users": "zia.users", "auditor": "zia.users", "labels": "zia.rule_labels", "time_windows": "zia.time_intervals",
        "src_ip_groups": "zia.ip_source_groups", "source_ip_groups": "zia.ip_source_groups", "src_ipv6_groups": "zia.ip_source_groups",
        "dest_ip_groups": "zia.ip_destination_groups", "dest_ipv6_groups": "zia.ip_destination_groups",
        "nw_services": "zia.network_services", "services": "zia.network_services", "nw_service_groups": "zia.network_service_groups",
        "nw_application_groups": "zia.network_app_groups", "application_groups": "zia.dns_app_groups",
        "dlp_engines": "zia.dlp_engines", "notification_template": "zia.dlp_notification_templates",
        "device_groups": "zia.device_groups", "workload_groups": "zia.workload_groups", "zpa_gateway": "zia.zpa_gateways",
        "bandwidth_classes": "zia.bandwidth_classes", "http_header_profiles": "zia.http_header_profiles",
        "http_header_action_profiles": "zia.http_header_action_profiles", "virtual_zen_clusters": "zia.vzen_clusters",
        "virtual_zens": "zia.vzen_nodes", "cloud_app_instances": "zia.cloud_app_instances",
        "tenancy_profile_ids": "zia.tenancy_restriction_profiles", "cloud_app_risk_profile": "zia.risk_profiles",
        "vpn_credentials": "zia.vpn_credentials", "parent_rule": "zia.web_dlp_rules",
    },
    "zpa": {
        "segment_group_id": "zpa.segment_groups", "server_groups": "zpa.server_groups", "app_server_groups": "zpa.server_groups",
        "app_server_group_ids": "zpa.server_groups", "servers": "zpa.servers", "app_connector_groups": "zpa.connector_groups",
        "app_connector_group_id": "zpa.connector_groups", "connector_groups": "zpa.connector_groups",
        "zpn_inspection_profile_id": "zpa.inspection_profiles", "banner_id": "zpa.cbi_banners", "certificate_ids": "zpa.cbi_certificates",
        "application_id": "zpa.application_segments", "user_portals": "zpa.user_portals", "pra_portals": "zpa.pra_portals",
        "credentials": "zpa.pra_credentials", "service_edges": "zpa.service_edges", "trusted_networks": "zpa.trusted_networks",
        "zpn_isolation_profile_id": "zpa.isolation_profiles",
    },
    "ztc": {
        "src_ip_groups": "ztc.ip_source_groups", "dest_ip_groups": "ztc.ip_destination_groups", "nw_services": "ztc.network_services",
        "services": "ztc.network_services", "nw_service_groups": "ztc.network_service_groups", "proxy_gateway": "ztc.forwarding_gateways",
        "public_cloud_accounts": "ztc.public_cloud_info", "location_template": "ztc.location_templates",
    },
}
# Lookups by name for objects that are not exported: (data source, lookup argument).
# Every data source and its `name` argument is in the provider's schema
# (zia 4.8.17: zia_group_management, zia_department_management, ...).
DATA: Dict[str, Tuple[str, str]] = {
    "zia.groups": ("zia_group_management", "name"), "zia.departments": ("zia_department_management", "name"),
    "zia.locations": ("zia_location_management", "name"), "zia.location_groups": ("zia_location_groups", "name"),
    "zia.time_intervals": ("zia_firewall_filtering_time_window", "name"), "zia.device_groups": ("zia_device_groups", "name"),
    "zia.rule_labels": ("zia_rule_labels", "name"), "zia.dlp_engines": ("zia_dlp_engines", "name"),
    "zia.dlp_dictionaries": ("zia_dlp_dictionaries", "name"), "zia.dlp_notification_templates": ("zia_dlp_notification_templates", "name"),
    "zia.network_services": ("zia_firewall_filtering_network_service", "name"),
    "zia.network_service_groups": ("zia_firewall_filtering_network_service_groups", "name"),
    "zia.network_app_groups": ("zia_firewall_filtering_network_application_groups", "name"),
    "zia.ip_source_groups": ("zia_firewall_filtering_ip_source_groups", "name"),
    "zia.ip_destination_groups": ("zia_firewall_filtering_destination_groups", "name"),
    "zia.workload_groups": ("zia_workload_groups", "name"), "zia.bandwidth_classes": ("zia_bandwidth_classes", "name"),
    "zpa.segment_groups": ("zpa_segment_group", "name"), "zpa.server_groups": ("zpa_server_group", "name"),
    "zpa.connector_groups": ("zpa_app_connector_group", "name"), "zpa.servers": ("zpa_application_server", "name"),
    "zpa.service_edge_groups": ("zpa_service_edge_group", "name"), "zpa.inspection_profiles": ("zpa_inspection_profile", "name"),
    "zpa.isolation_profiles": ("zpa_isolation_profile", "name"), "zpa.trusted_networks": ("zpa_trusted_network", "name"),
}
# Reference targets that are personal data: the id stays, the name is never written.
PERSONAL_TARGETS = {"zia.users"}
# The attribute a resource exposes its numeric id as, when a reference needs the number (not the string id).
ID_ATTR = {"zia_traffic_forwarding_vpn_credentials": "vpn_id"}


class _Ref:
    """A reference a read hook found inside a value (a ZPA policy operand's
    application id, an engine's dictionary): resolved like an attribute's."""
    __slots__ = ("target", "ident", "name")

    def __init__(self, target: str, ident: Any, name: Any = None):
        self.target, self.ident, self.name = target, ident, name


class _Raw:
    """An HCL expression this module built itself (never tenant text)."""
    __slots__ = ("hcl",)

    def __init__(self, hcl: str):
        self.hcl = hcl


# ---------------------------------------------------------------------------
# The schema tokens (tenant_terraform_schema)
# ---------------------------------------------------------------------------

def parse_schema(text: str) -> List[Tuple[str, str, bool, Any]]:
    """`name:kind` tokens -> [(name, kind, required, sub-schema or None)]."""
    out: List[Tuple[str, str, bool, Any]] = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i] == " ":
            i += 1
        if i >= n:
            break
        j = text.index(":", i)
        name = text[i:j]
        k = j + 1
        if text.startswith("blk(", k):
            depth, m = 0, k + 3
            while True:
                if text[m] == "(":
                    depth += 1
                elif text[m] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                m += 1
            sub = parse_schema(text[k + 4:m])
            k = m + 1
            req = k < n and text[k] == "!"
            out.append((name, "blk", req, sub))
            i = k + (1 if req else 0)
            continue
        m = k
        while m < n and text[m] not in " ":
            m += 1
        kind = text[k:m]
        req = kind.endswith("!")
        out.append((name, kind.rstrip("!"), req, None))
        i = m
    return out


_SCHEMA_CACHE: Dict[str, List[Tuple[str, str, bool, Any]]] = {}


def schema_of(resource: str) -> List[Tuple[str, str, bool, Any]]:
    if resource not in _SCHEMA_CACHE:
        _SCHEMA_CACHE[resource] = parse_schema(" ".join(str(SCHEMAS[resource]).split()))
    return _SCHEMA_CACHE[resource]


# ---------------------------------------------------------------------------
# The catalogue: what is read, how, and which resource it becomes
# ---------------------------------------------------------------------------

def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() == "true"


def _custom(row: Dict[str, Any]) -> bool:
    """A customer's own object, not one Zscaler predefines."""
    if _truthy(row.get("predefined")) or _truthy(row.get("default_rule")) or _truthy(row.get("read_only")):
        return False
    typ = str(row.get("type") or "").upper()
    return typ not in ("PREDEFINED", "STANDARD")


def _custom_rule(row: Dict[str, Any]) -> bool:
    """A rule the customer made: not the Default rule (order 0 or less, or
    flagged), not predefined."""
    try:
        if int(row.get("order")) <= 0:
            return False
    except (TypeError, ValueError):
        pass
    return _custom(row)


def _keep_dictionary(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom")) and _custom(row)


def _keep_engine(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom_dlp_engine")) and _custom(row)


def _keep_category(row: Dict[str, Any]) -> bool:
    return _truthy(row.get("custom_category")) or str(row.get("id") or "").startswith("CUSTOM_")


def _keep_bandwidth_class(row: Dict[str, Any]) -> bool:
    return _custom(row) and not str(row.get("type") or "").upper().startswith("BANDWIDTH_CAT_")


_ZTC_GATEWAY_TYPES = ("ZIA", "ECSELF", "PROXYCHAIN", "")


def _keep_ztc_gateway(row: Dict[str, Any]) -> bool:
    return str(row.get("type") or "").upper() in _ZTC_GATEWAY_TYPES


_ZPA_SPECIAL = ("clientless_apps", "pra_apps", "inspection_apps", "common_apps_dto")


def _ba_segment(row: Dict[str, Any]) -> bool:
    return bool(row.get("clientless_apps"))


def _app_types(row: Dict[str, Any]) -> set:
    """The app types of a segment's common_apps_dto.apps_config (PRA: SECURE_REMOTE_ACCESS, inspection: INSPECT)."""
    dto = row.get("common_apps_dto")
    apps = dto.get("apps_config") if isinstance(dto, dict) else None
    out: set = set()
    for a in apps if isinstance(apps, list) else []:
        if isinstance(a, dict):
            out.update(str(x).upper() for x in (a.get("app_types") or []) if isinstance(x, str))
    return out


def _pra_segment(row: Dict[str, Any]) -> bool:
    return bool(row.get("pra_apps")) or "SECURE_REMOTE_ACCESS" in _app_types(row)


def _inspection_segment(row: Dict[str, Any]) -> bool:
    return bool(row.get("inspection_apps")) or "INSPECT" in _app_types(row)


def _zpa_rule(row: Dict[str, Any]) -> bool:
    """A ZPA policy rule the customer made: not the policy's default rule."""
    return not _truthy(row.get("default_rule")) and not _truthy(row.get("read_only"))


def _plain_segment(row: Dict[str, Any]) -> bool:
    """A plain application segment: the Browser Access, PRA and inspection
    segments are read from their own lists and exported as their own types."""
    return not any(row.get(f) for f in _ZPA_SPECIAL)


def _t(key: str, resource: str, label: str, area: str, svc: str, method: Optional[str], *, gate: Tuple[str, str],
       args: Tuple[Any, ...] = (), singleton: bool = False, import_id: Optional[str] = None, name: str = "name",
       keep: Optional[Callable[[Dict[str, Any]], bool]] = None, per_type: bool = False, zpa_paged: bool = False,
       personal: bool = False, hook: Optional[str] = None, import_fmt: str = "{id}", secrets: Optional[Dict[str, str]] = None,
       keep_why: str = "", extra: Optional[List[Tuple[str, Tuple[Any, ...]]]] = None) -> Dict[str, Any]:
    product = key.split(".", 1)[0]
    return {"key": key, "product": product, "resource": resource, "label": label, "area": area, "svc": svc, "method": method,
            "gate": gate, "args": args, "singleton": singleton, "import_id": import_id, "name": name, "keep": keep,
            "per_type": per_type, "zpa_paged": zpa_paged, "personal": personal, "hook": hook, "import_fmt": import_fmt,
            "secrets": secrets or {}, "keep_why": keep_why, "extra": extra or []}


_P = ("scope", "zia_extras")
_DLP = ("scope", "dlp")
_ZPA = ("scope", "zpa")
_ZTC = ("scope", "ztw")
_PREDEF = "predefined or default: it exists in every tenant, so what names it looks it up by name"
_NOT_THIS_KIND = "listed by this call but not a segment of this kind (it is exported with its own kind)"

TYPES: List[Dict[str, Any]] = [
    # ── ZIA: settings (one object each; the import id is the provider's fixed one) ──
    _t("zia.advanced_settings", "zia_advanced_settings", "Advanced settings", "settings", "advanced_settings", "get_advanced_settings",
       gate=_P, singleton=True, import_id="advanced_settings"),
    _t("zia.atp_settings", "zia_advanced_threat_settings", "Advanced Threat Protection settings", "threat_protection", "atp_policy",
       "get_atp_settings", gate=_P, singleton=True, import_id="advanced_threat_settings"),
    _t("zia.atp_malicious_urls", "zia_atp_malicious_urls", "Advanced Threat Protection malicious URLs", "threat_protection", "atp_policy",
       "get_atp_malicious_urls", gate=_P, singleton=True, import_id="all_urls"),
    _t("zia.atp_security_exceptions", "zia_atp_security_exceptions", "Advanced Threat Protection security exceptions", "threat_protection",
       "atp_policy", "get_atp_security_exceptions", gate=_P, singleton=True, import_id="bypass_url"),
    _t("zia.malware_inspection", "zia_atp_malware_inspection", "Malware Protection inspection", "threat_protection",
       "malware_protection_policy", "get_atp_malware_inspection", gate=_P, singleton=True, import_id="inspection"),
    _t("zia.malware_policy", "zia_atp_malware_policy", "Malware Protection policy", "threat_protection", "malware_protection_policy",
       "get_atp_malware_policy", gate=_P, singleton=True, import_id="policy"),
    _t("zia.malware_protocols", "zia_atp_malware_protocols", "Malware Protection protocols", "threat_protection",
       "malware_protection_policy", "get_atp_malware_protocols", gate=_P, singleton=True, import_id="protocol"),
    _t("zia.malware_settings", "zia_atp_malware_settings", "Malware Protection settings", "threat_protection", "malware_protection_policy",
       "get_malware_settings", gate=_P, singleton=True, import_id="malware_settings"),
    _t("zia.mobile_malware", "zia_mobile_malware_protection_policy", "Mobile Malware Protection", "threat_protection",
       "mobile_threat_settings", "get_mobile_advanced_settings", gate=_P, singleton=True, import_id="mobile_settings"),
    _t("zia.sandbox_settings", "zia_sandbox_behavioral_analysis", "Sandbox behavioral analysis (blocked hashes)", "threat_protection",
       "sandbox", "get_behavioral_analysis", gate=_P, singleton=True, import_id="sandbox_settings"),
    _t("zia.security_settings", "zia_security_settings", "Security policy allow and deny lists", "threat_protection",
       "security_policy_settings", "get_whitelist", gate=_P, singleton=True, import_id="all_urls", hook="security_lists"),
    _t("zia.auth_exempt_urls", "zia_auth_settings_urls", "Authentication exempted URLs", "settings", "authentication_settings",
       "get_exempted_urls", gate=_P, singleton=True, import_id="all_urls"),
    _t("zia.eun", "zia_end_user_notification", "End user notification", "settings", "end_user_notification", "get_eun_settings",
       gate=_P, singleton=True, import_id="enduser_notification"),
    _t("zia.ftp_control", "zia_ftp_control_policy", "FTP control", "settings", "ftp_control_policy", "get_ftp_settings", gate=_P,
       singleton=True, import_id="ftp_control"),
    _t("zia.browser_control", "zia_browser_control_policy", "Browser Control settings", "settings", "browser_control_settings",
       "get_browser_control_settings", gate=_P, singleton=True, import_id="browser_settings"),
    _t("zia.url_and_app_settings", "zia_url_filtering_and_cloud_app_settings", "URL and Cloud App Control settings", "settings",
       "url_filtering", "get_url_and_app_settings", gate=("policy", "url_filtering"), singleton=True, import_id="app_setting"),
    # ── ZIA: objects rules use ──
    _t("zia.rule_labels", "zia_rule_labels", "Rule labels", "objects", "rule_labels", "list_labels", gate=("any", "zia")),
    _t("zia.url_categories", "zia_url_categories", "Custom URL categories", "url_filtering", "url_categories", "list_categories",
       gate=("any", "zia"), name="configured_name", keep=_keep_category, keep_why=_PREDEF),
    _t("zia.ip_destination_groups", "zia_firewall_filtering_destination_groups", "IP destination groups", "firewall_objects",
       "cloud_firewall", "list_ip_destination_groups", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.ip_source_groups", "zia_firewall_filtering_ip_source_groups", "IP source groups", "firewall_objects", "cloud_firewall",
       "list_ip_source_groups", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.network_services", "zia_firewall_filtering_network_service", "Network services", "firewall_objects", "cloud_firewall",
       "list_network_services", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.network_service_groups", "zia_firewall_filtering_network_service_groups", "Network service groups", "firewall_objects",
       "cloud_firewall", "list_network_svc_groups", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.network_app_groups", "zia_firewall_filtering_network_application_groups", "Network application groups", "firewall_objects",
       "cloud_firewall", "list_network_app_groups", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.dns_app_groups", "zia_dns_application_groups", "DNS application groups", "firewall_objects", "dns_application_groups",
       "list_groups", gate=_P, keep=_custom, keep_why=_PREDEF),
    _t("zia.workload_groups", "zia_workload_groups", "Workload groups", "objects", "workload_groups", "list_groups", gate=_P),
    _t("zia.http_header_profiles", "zia_http_header_profile", "HTTP header profiles", "objects", "http_header_control",
       "list_http_header_profiles", gate=_P),
    _t("zia.http_header_action_profiles", "zia_http_header_action_profile", "HTTP header action profiles", "objects",
       "http_header_control", "list_http_header_action_profiles", gate=_P),
    _t("zia.risk_profiles", "zia_risk_profiles", "Cloud app risk profiles", "objects", "risk_profiles", "list_risk_profiles", gate=_P,
       name="profile_name"),
    _t("zia.cloud_app_instances", "zia_cloud_application_instance", "Cloud application instances", "objects", "cloud_app_instances",
       "list_cloud_app_instances", gate=_P),
    _t("zia.tenancy_restriction_profiles", "zia_tenant_restriction_profile", "Tenancy restriction profiles", "objects",
       "tenancy_restriction_profile", "list_restriction_profile", gate=_P),
    _t("zia.bandwidth_classes", "zia_bandwidth_classes", "Bandwidth classes", "bandwidth", "bandwidth_classes", "list_classes", gate=_P,
       keep=_keep_bandwidth_class, keep_why=_PREDEF),
    # ── ZIA: DLP ──
    _t("zia.dlp_dictionaries", "zia_dlp_dictionaries", "DLP dictionaries", "dlp", "dlp_dictionary", "list_dicts", gate=_DLP,
       keep=_keep_dictionary, keep_why=_PREDEF),
    _t("zia.dlp_engines", "zia_dlp_engines", "DLP engines", "dlp", "dlp_engine", "list_dlp_engines", gate=_DLP, keep=_keep_engine,
       keep_why=_PREDEF, hook="engine_expression"),
    _t("zia.dlp_notification_templates", "zia_dlp_notification_templates", "DLP notification templates", "dlp", "dlp_templates",
       "list_dlp_templates", gate=_DLP),
    _t("zia.web_dlp_rules", "zia_dlp_web_rules", "Inline Web DLP rules", "dlp_rules", "dlp_web_rules", "list_rules",
       gate=("channel", "web"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.endpoint_dlp_rules", "zia_endpoint_dlp_rules", "Endpoint DLP rules", "dlp_rules", "endpoint_dlp_rules", "list_rules",
       gate=("channel", "endpoint"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.email_dlp_rules", "zia_outbound_email_dlp", "Outbound Email DLP rules", "dlp_rules", "outbound_email_dlp_rules", "list_rules",
       gate=("channel", "email"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.saas_dlp_rules", "zia_casb_dlp_rules", "SaaS Security API DLP rules", "dlp_rules", "casb_dlp_rules", "list_all_rules",
       gate=("channel", "saas"), keep=_custom_rule, keep_why=_PREDEF, import_fmt="{type}:{id}"),
    # ── ZIA: policies (rules) ──
    _t("zia.url_filtering_rules", "zia_url_filtering_rules", "URL filtering rules", "url_filtering", "url_filtering", "list_rules",
       gate=("policy", "url_filtering"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.ssl_inspection_rules", "zia_ssl_inspection_rules", "SSL inspection rules", "ssl_inspection", "ssl_inspection_rules",
       "list_rules", gate=("policy", "ssl_inspection"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.file_type_rules", "zia_file_type_control_rules", "File Type Control rules", "file_type_control", "file_type_control_rule",
       "list_rules", gate=("policy", "file_type_control"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.cloud_app_control_rules", "zia_cloud_app_control_rule", "Cloud App Control rules", "cloud_app_control", "cloudappcontrol",
       "list_rules", gate=("policy", "cloud_app_control"), keep=_custom_rule, keep_why=_PREDEF, per_type=True, import_fmt="{type}:{id}"),
    _t("zia.firewall_rules", "zia_firewall_filtering_rule", "Cloud Firewall rules", "firewall", "cloud_firewall_rules", "list_rules",
       gate=("policy", "firewall"), keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.firewall_dns_rules", "zia_firewall_dns_rule", "DNS Control rules", "firewall", "cloud_firewall_dns", "list_rules", gate=_P,
       keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.firewall_ips_rules", "zia_firewall_ips_rule", "IPS Control rules", "firewall", "cloud_firewall_ips", "list_rules", gate=_P,
       keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.nat_rules", "zia_nat_control_rules", "NAT control rules", "firewall", "nat_control_policy", "list_rules", gate=_P,
       keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.sandbox_rules", "zia_sandbox_rules", "Sandbox rules", "threat_protection", "sandbox_rules", "list_rules", gate=_P,
       keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.bandwidth_rules", "zia_bandwidth_control_rule", "Bandwidth control rules", "bandwidth", "bandwidth_control_rules", "list_rules",
       gate=_P, keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.forwarding_rules", "zia_forwarding_control_rule", "Forwarding control rules", "forwarding", "forwarding_control", "list_rules",
       gate=_P, keep=_custom_rule, keep_why=_PREDEF),
    _t("zia.zpa_gateways", "zia_forwarding_control_zpa_gateway", "ZPA gateways", "forwarding", "zpa_gateway", "list_gateways", gate=_P),
    _t("zia.proxies", "zia_forwarding_control_proxies", "Proxies (proxy chaining)", "forwarding", "proxies", "list_proxies", gate=_P),
    # ── ZIA: traffic forwarding and locations ──
    _t("zia.locations", "zia_location_management", "Locations", "traffic_forwarding", "locations", "list_locations", gate=_P),
    _t("zia.static_ips", "zia_traffic_forwarding_static_ip", "Static IP addresses", "traffic_forwarding", "traffic_static_ip",
       "list_static_ips", gate=_P, name="ip_address"),
    _t("zia.gre_tunnels", "zia_traffic_forwarding_gre_tunnel", "GRE tunnels", "traffic_forwarding", "gre_tunnel", "list_gre_tunnels",
       gate=_P, name="source_ip"),
    _t("zia.vpn_credentials", "zia_traffic_forwarding_vpn_credentials", "VPN credentials", "traffic_forwarding", "traffic_vpn_credentials",
       "list_vpn_credentials", gate=_P, name="fqdn", secrets={"pre_shared_key": "vpn_pre_shared_keys"}),
    _t("zia.vzen_clusters", "zia_virtual_service_edge_cluster", "Virtual Service Edge clusters", "traffic_forwarding", "vzen_clusters",
       "list_vzen_clusters", gate=_P),
    _t("zia.vzen_nodes", "zia_virtual_service_edge_node", "Virtual Service Edge nodes", "traffic_forwarding", "vzen_nodes", "list_zen_nodes",
       gate=_P),
    _t("zia.subscription_alerts", "zia_subscription_alert", "Alert subscriptions", "settings", "alert_subscriptions",
       "list_alert_subscriptions", gate=_P, name="email", personal=True),
    # ── ZPA ──
    _t("zpa.segment_groups", "zpa_segment_group", "Segment groups", "segments", "segment_groups", "list_groups", gate=_ZPA, zpa_paged=True),
    _t("zpa.server_groups", "zpa_server_group", "Server groups", "segments", "server_groups", "list_groups", gate=_ZPA, zpa_paged=True),
    _t("zpa.servers", "zpa_application_server", "Application servers", "segments", "servers", "list_servers", gate=_ZPA, zpa_paged=True),
    _t("zpa.application_segments", "zpa_application_segment", "Application segments", "segments", "application_segment", "list_segments",
       gate=_ZPA, zpa_paged=True, keep=_plain_segment,
       keep_why="a Browser Access, PRA or inspection segment: exported as its own type from its own list"),
    _t("zpa.ba_segments", "zpa_application_segment_browser_access", "Browser Access segments", "segments", "app_segments_ba",
       "list_segments_ba", gate=_ZPA, zpa_paged=True, keep=_ba_segment, keep_why=_NOT_THIS_KIND),
    _t("zpa.pra_segments", "zpa_application_segment_pra", "Privileged Remote Access segments", "segments", "app_segments_pra",
       "list_segments_pra", gate=_ZPA, zpa_paged=True, keep=_pra_segment, keep_why=_NOT_THIS_KIND),
    _t("zpa.inspection_segments", "zpa_application_segment_inspection", "Inspection (AppProtection) segments", "segments",
       "app_segments_inspection", "list_segment_inspection", gate=_ZPA, zpa_paged=True, keep=_inspection_segment,
       keep_why=_NOT_THIS_KIND),
    _t("zpa.connector_groups", "zpa_app_connector_group", "App Connector groups", "infrastructure", "app_connector_groups",
       "list_connector_groups", gate=_ZPA, zpa_paged=True),
    _t("zpa.service_edge_groups", "zpa_service_edge_group", "Service Edge groups", "infrastructure", "service_edge_group",
       "list_service_edge_groups", gate=_ZPA, zpa_paged=True),
    _t("zpa.provisioning_keys", "zpa_provisioning_key", "Provisioning keys", "infrastructure", "provisioning", "list_provisioning_keys",
       gate=_ZPA, args=("connector",), extra=[("service_edge", ("service_edge",))], hook="provisioning_key"),
    _t("zpa.private_cloud_groups", "zpa_private_cloud_group", "Private cloud groups", "infrastructure", "private_cloud_group",
       "list_cloud_groups", gate=_ZPA, zpa_paged=True),
    _t("zpa.c2c_ip_ranges", "zpa_c2c_ip_ranges", "Client-to-client IP ranges", "infrastructure", "c2c_ip_ranges", "list_ip_ranges", gate=_ZPA),
    _t("zpa.lss_configs", "zpa_lss_config_controller", "Log streaming (LSS) configurations", "infrastructure", "lss", "list_configs",
       gate=_ZPA, zpa_paged=True, hook="lss_name"),
    _t("zpa.microtenants", "zpa_microtenant_controller", "Microtenants", "infrastructure", "microtenants", "list_microtenants", gate=_ZPA,
       zpa_paged=True),
    _t("zpa.access_rules", "zpa_policy_access_rule_v2", "Access policy rules", "policies", "policies", "list_rules", gate=_ZPA,
       args=("access",), zpa_paged=True, hook="policy_v2", keep=_zpa_rule,
       keep_why=_PREDEF),
    _t("zpa.timeout_rules", "zpa_policy_timeout_rule_v2", "Timeout policy rules", "policies", "policies", "list_rules", gate=_ZPA,
       args=("timeout",), zpa_paged=True, hook="policy_v2", keep=_zpa_rule,
       keep_why=_PREDEF),
    _t("zpa.forwarding_rules", "zpa_policy_forwarding_rule_v2", "Client forwarding policy rules", "policies", "policies", "list_rules",
       gate=_ZPA, args=("client_forwarding",), zpa_paged=True, hook="policy_v2", keep=_zpa_rule,
       keep_why=_PREDEF),
    _t("zpa.inspection_rules", "zpa_policy_inspection_rule_v2", "Inspection policy rules", "policies", "policies", "list_rules",
       gate=_ZPA, args=("inspection",), zpa_paged=True, hook="policy_v2", keep=_zpa_rule,
       keep_why=_PREDEF),
    _t("zpa.isolation_rules", "zpa_policy_isolation_rule_v2", "Isolation policy rules", "policies", "policies", "list_rules", gate=_ZPA,
       args=("isolation",), zpa_paged=True, hook="policy_v2", keep=_zpa_rule,
       keep_why=_PREDEF),
    _t("zpa.inspection_profiles", "zpa_inspection_profile", "Inspection profiles", "inspection", "app_protection", "list_profiles",
       gate=_ZPA, zpa_paged=True),
    _t("zpa.inspection_custom_controls", "zpa_inspection_custom_controls", "Inspection custom controls", "inspection", "app_protection",
       "list_custom_controls", gate=_ZPA, zpa_paged=True),
    _t("zpa.pra_portals", "zpa_pra_portal_controller", "PRA portals", "pra", "pra_portal", "list_portals", gate=_ZPA, zpa_paged=True),
    _t("zpa.pra_consoles", "zpa_pra_console_controller", "PRA consoles", "pra", "pra_console", "list_consoles", gate=_ZPA, zpa_paged=True,
       hook="pra_console"),
    _t("zpa.pra_credentials", "zpa_pra_credential_controller", "PRA credentials", "pra", "pra_credential", "list_credentials", gate=_ZPA,
       zpa_paged=True, secrets={"password": "pra_credential_passwords", "passphrase": "pra_credential_passphrases",
                                "private_key": "pra_credential_private_keys"}),
    _t("zpa.pra_credential_pools", "zpa_pra_credential_pool", "PRA credential pools", "pra", "pra_credential_pool", "list_credential_pool",
       gate=_ZPA, zpa_paged=True),
    _t("zpa.pra_approvals", "zpa_pra_approval_controller", "PRA approvals", "pra", "pra_approval", "list_approval", gate=_ZPA,
       zpa_paged=True, personal=True, name="id"),
    _t("zpa.user_portals", "zpa_user_portal_controller", "User portals", "portals", "user_portal_controller", "list_user_portals", gate=_ZPA,
       zpa_paged=True),
    _t("zpa.user_portal_links", "zpa_user_portal_link", "User portal links", "portals", "user_portal_link", "list_portal_link", gate=_ZPA,
       zpa_paged=True),
    _t("zpa.cbi_banners", "zpa_cloud_browser_isolation_banner", "Isolation banners", "isolation", "cbi_banner", "list_cbi_banners",
       gate=_ZPA),
    _t("zpa.cbi_certificates", "zpa_cloud_browser_isolation_certificate", "Isolation certificates", "isolation", "cbi_certificate",
       "list_cbi_certificates", gate=_ZPA),
    _t("zpa.cbi_profiles", "zpa_cloud_browser_isolation_external_profile", "Isolation profiles", "isolation", "cbi_profile",
       "list_cbi_profiles", gate=_ZPA, secrets={"file_password": "cbi_debug_file_passwords"}),
    # ── Cloud & Branch Connector (zscaler-sdk-python's ztw) ──
    _t("ztc.ip_source_groups", "ztc_ip_source_groups", "IP source groups", "objects", "ip_source_groups", "list_ip_source_groups", gate=_ZTC,
       keep=_custom, keep_why=_PREDEF),
    _t("ztc.ip_destination_groups", "ztc_ip_destination_groups", "IP destination groups", "objects", "ip_destination_groups",
       "list_ip_destination_groups", gate=_ZTC, keep=_custom, keep_why=_PREDEF),
    _t("ztc.ip_pool_groups", "ztc_ip_pool_groups", "IP pool groups", "objects", "ip_groups", "list_ip_groups", gate=_ZTC),
    _t("ztc.network_services", "ztc_network_services", "Network services", "objects", "nw_service", "list_network_services", gate=_ZTC,
       keep=_custom, keep_why=_PREDEF),
    _t("ztc.network_service_groups", "ztc_network_service_groups", "Network service groups", "objects", "nw_service_groups",
       "list_network_svc_groups", gate=_ZTC, keep=_custom, keep_why=_PREDEF),
    _t("ztc.forwarding_gateways", "ztc_forwarding_gateway", "Forwarding gateways", "forwarding", "forwarding_gateways", "list_gateways",
       gate=_ZTC, keep=_keep_ztc_gateway, keep_why="a gateway type the provider's ztc_forwarding_gateway does not take (ZIA, ECSELF or PROXYCHAIN)"),
    _t("ztc.forwarding_rules", "ztc_traffic_forwarding_rule", "Traffic forwarding rules", "forwarding", "forwarding_rules", "list_rules",
       gate=_ZTC, keep=_custom_rule, keep_why=_PREDEF),
    _t("ztc.location_templates", "ztc_location_template", "Location templates", "provisioning", "location_template",
       "list_location_templates", gate=_ZTC),
    _t("ztc.provisioning_urls", "ztc_provisioning_url", "Provisioning URLs", "provisioning", "provisioning_url", "list_provisioning_url",
       gate=_ZTC),
    _t("ztc.public_cloud_info", "ztc_public_cloud_info", "Public cloud accounts", "provisioning", "public_cloud_info",
       "list_public_cloud_info", gate=_ZTC),
    _t("ztc.account_groups", "ztc_account_groups", "Account groups", "provisioning", "account_groups", "list_account_groups", gate=_ZTC),
]
BY_KEY: Dict[str, Dict[str, Any]] = {t["key"]: t for t in TYPES}

# What the providers can express but this export deliberately leaves out.
NOT_COVERED: List[Tuple[str, str, str]] = [
    ("zia", "ZIA users and admin users", "personal data; identity comes from the identity provider (SCIM or SAML)"),
    ("zia", "Admin roles", "who may administer the tenant is never exported"),
    ("zia", "Sub-locations", "bound to the parent location's own addresses; add them after the parent is in state"),
    ("zia", "Cloud NSS feeds and NSS servers", "a feed carries the SIEM's address and token"),
    ("zia", "Custom file types, endpoint DLP resources and sub-rules", "not read by this export yet"),
    ("zpa", "App Connectors and Service Edges", "they enrol themselves with a provisioning key; their groups are exported"),
    ("zpa", "Identity providers, SAML and SCIM attributes, posture profiles, trusted networks, machine groups",
     "made in the identity provider and the Client Connector Portal; policy conditions keep their ids"),
    ("zpa", "Browser Access certificates and enrollment certificates", "a certificate's private key never leaves ZPA"),
    ("zpa", "Policy rule order", "the v2 policy resources take no order; zpa_policy_access_rule_reorder sets it after import"),
    ("ztc", "Cloud & Branch Connector groups, locations and DNS / log forwarding rules",
     "zscaler-sdk-python 1.11.3 cannot read them as the provider writes them"),
]


# ---------------------------------------------------------------------------
# Scope (the Scope page): which types may be read
# ---------------------------------------------------------------------------

def gates(scopes: Any, channels: Any) -> Dict[str, Any]:
    """What the Scope page's selection allows: the ticked scope keys, the
    rule policies admin_ops.scope_for puts in scope and the DLP pack
    channels marked Zscaler (channel_scope.pack_targets). Pure."""
    import admin_ops
    import channel_scope
    sc = {str(s) for s in (scopes or [])} if isinstance(scopes, (list, tuple, set)) else set()
    ch = channels if isinstance(channels, dict) else {}
    pol = set(admin_ops.scope_for(sorted(sc), ch).get("policies") or [])
    dlp_channels = set(channel_scope.pack_targets(ch)) if "dlp" in sc else set()
    return {"scopes": sc, "policies": pol, "channels": dlp_channels}


_GATE_WORDS = {"zia_extras": "ZIA platform", "dlp": "DLP", "zpa": "ZPA", "ztw": "Cloud & Branch Connector"}
_CHANNEL_WORDS = {"web": "Inline Web DLP", "endpoint": "Endpoint DLP", "saas": "SaaS DLP", "email": "Email DLP"}


def in_scope(t: Dict[str, Any], g: Dict[str, Any]) -> Optional[str]:
    """None when the type may be read; else why not, in words."""
    kind, val = t["gate"]
    if kind == "scope":
        return None if val in g["scopes"] else f"not in scope: tick {_GATE_WORDS[val]} on the Scope page"
    if kind == "any":   # ZIA objects any ZIA policy uses
        return None if ({"zia_extras", "dlp"} & g["scopes"]) else "not in scope: tick ZIA platform or DLP on the Scope page"
    if kind == "policy":
        return None if val in g["policies"] else "not in scope: its policy is not in scope on the Scope page"
    if kind == "channel":
        return None if val in g["channels"] else f"not in scope: tick DLP and mark {_CHANNEL_WORDS[val]} as Zscaler on the Scope page"
    return "not in scope"


def normalize_options(products: Any = None, types: Any = None, exclude: Any = None, prefix: Any = "", namespace: Any = "",
                      microtenant_id: Any = "") -> Dict[str, Any]:
    """The export's options, checked (ExportRefused names what is wrong)."""
    prods = [str(p).strip().lower() for p in (products or PRODUCTS)] if isinstance(products, (list, tuple)) or products is None else None
    if prods is None or not prods or any(p not in PRODUCTS for p in prods):
        raise ExportRefused("Products must be a list of zia, zpa and ztc.")
    lists = []
    for what, v in (("types", types), ("exclude", exclude)):
        if v in (None, ""):
            lists.append([])
            continue
        if not isinstance(v, (list, tuple)) or len(v) > MAX_TYPES_ASKED:
            raise ExportRefused(f"{what} must be a list of object type keys (at most {MAX_TYPES_ASKED}).")
        bad = [str(x)[:60] for x in v if str(x) not in BY_KEY]
        if bad:
            raise ExportRefused(f"Unknown object type in {what}: {', '.join(bad[:5])}.")
        lists.append([str(x) for x in v])
    pre = str(prefix or "").strip()
    if pre and not PREFIX_RE.match(pre):
        raise ExportRefused("The resource-label prefix must start with a lowercase letter and hold only lowercase letters, digits and _ "
                            "(at most 20 characters).")
    ns = str(namespace or "").strip()
    if ns and not NAMESPACE_RE.match(ns):
        raise ExportRefused("The provider namespace must look like zscaler or registry.example.com/zscaler.")
    mt = str(microtenant_id or "").strip()
    if mt and not MICROTENANT_RE.match(mt):
        raise ExportRefused("The ZPA microtenant id is a number.")
    return {"products": [p for p in PRODUCTS if p in prods], "types": lists[0], "exclude": lists[1], "prefix": pre,
            "namespace": ns or DEFAULT_NAMESPACE, "microtenant_id": mt}


def plan(scopes: Any, channels: Any, opts: Dict[str, Any], *, include_personal: bool = False) -> Dict[str, Any]:
    """Which types to read for these options and the Scope page's selection:
    {read: [keys], not_in_scope: {key: why}, left_out: {key: why}}. A type
    asked for by name that is out of scope, or nothing at all in scope, is
    refused (ExportRefused) before anything is read (the Scope rule)."""
    g = gates(scopes, channels)
    asked = set(opts["types"])
    read: List[str] = []
    nis: Dict[str, str] = {}
    left: Dict[str, str] = {}
    for t in TYPES:
        if t["product"] not in opts["products"]:
            continue
        if asked and t["key"] not in asked:
            continue
        why = in_scope(t, g)
        if why:
            nis[t["key"]] = why
            continue
        if t["key"] in opts["exclude"]:
            left[t["key"]] = "left out: excluded in the export options"
            continue
        if t["personal"] and not include_personal:
            left[t["key"]] = "left out: it holds personal data (email addresses); tick Include personal data to export it"
            continue
        read.append(t["key"])
    out_asked = sorted(k for k in asked if k in nis)
    if out_asked:
        raise ExportRefused("Not in scope on the Scope page: " + "; ".join(f"{BY_KEY[k]['label']} ({nis[k]})" for k in out_asked[:6])
                            + ". Leave them out of the export or tick their scope. Nothing was read.")
    if not read:
        raise ExportRefused(NOTHING_IN_SCOPE if not left else "Every object type in scope was left out by the export options. Nothing was read.")
    return {"read": read, "not_in_scope": nis, "left_out": left}


def catalogue() -> Dict[str, Any]:
    """The types per product, for the page and the docs."""
    out: Dict[str, Any] = {}
    for p in PRODUCTS:
        out[p] = [{"key": t["key"], "label": t["label"], "resource": t["resource"], "personal": t["personal"],
                   "gate": t["gate"][0], "needs": _GATE_WORDS.get(t["gate"][1], t["gate"][1])} for t in TYPES if t["product"] == p]
    return {"products": out, "labels": PRODUCT_LABELS, "not_covered": [{"product": p, "what": w, "why": y} for p, w, y in NOT_COVERED],
            "providers": {p: {"source": f"{DEFAULT_NAMESPACE}/{p}", "version": PROVIDERS[p]["version"]} for p in PRODUCTS}}


# ---------------------------------------------------------------------------
# Reading (GET only, through the SDK's own calls)
# ---------------------------------------------------------------------------

_CAMEL = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")


def _snake(key: str) -> str:
    return _CAMEL.sub("_", str(key)).lower()


def _deep_snake(v: Any, depth: int = 0) -> Any:
    """Every dict key in snake_case (the SDK's models keep nested answers
    as the API wrote them, in camelCase)."""
    if depth > 30:
        return None
    if isinstance(v, dict):
        return {_snake(k): _deep_snake(x, depth + 1) for k, x in v.items()}
    if isinstance(v, list):
        return [_deep_snake(x, depth + 1) for x in v]
    return v


def _clean(rows: Iterable[Any]) -> List[Dict[str, Any]]:
    """Rows as plain snake_case dicts with every secret-named field masked."""
    import offline_tenant
    out = []
    for r in rows:
        if isinstance(r, dict):
            out.append(offline_tenant.scrub(_deep_snake(r)))
    return out


def _stopped(cancel: Any) -> bool:
    return bool(cancel is not None and getattr(cancel, "is_set", lambda: False)())


def _service(client: Any, t: Dict[str, Any]) -> Tuple[Any, Optional[str]]:
    try:
        root = getattr(client, SDK_ROOT[t["product"]], None)
    except Exception:  # noqa: BLE001 - a client without this product (the classic ZIA sign-in has no ZPA)
        root = None
    if root is None:
        return None, f"this sign-in has no {PRODUCT_LABELS[t['product']]} API"
    svc = getattr(root, t["svc"], None)
    fn = getattr(svc, t["method"], None) if svc is not None else None
    if not callable(fn):
        return None, f"the installed zscaler-sdk-python has no {t['svc']}.{t['method']}"
    return svc, None


def _zpa_list(fn: Callable[..., Any], args: Tuple[Any, ...], q: Dict[str, Any], cancel: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every page of a ZPA list (the SDK's own paging), at most MAX_ZPA_PAGES."""
    import pack_export
    ret = fn(*args, query_params=dict(q, page_size="500"))
    rows, err = pack_export._rows(ret)
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


def read_type(client: Any, t: Dict[str, Any], *, cancel: Any = None, microtenant_id: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of one type: (rows, error). Read-only."""
    import pack_export
    import pack_channels as pc
    svc, err = _service(client, t)
    if err:
        return [], err
    fn = getattr(svc, t["method"])
    q = {"microtenant_id": microtenant_id} if (microtenant_id and t["product"] == "zpa") else {}
    if t["singleton"]:
        row, err = pack_export.one_row(fn())
        if t["hook"] == "security_lists" and not err:
            deny, err = pack_export.one_row(svc.get_blacklist())
            row = dict(row or {}, **(deny or {}))
        return ([row] if row else []), err
    if t["per_type"]:
        rows: List[Dict[str, Any]] = []
        for rt in pc.CLOUD_APP_TYPES:
            if _stopped(cancel):
                break
            got, err = pack_export._rows(fn(rt))
            if err:
                return rows, err
            for r in got:
                r["type"] = str(r.get("type") or rt)
            rows.extend(got)
        return rows, None
    calls = [t["args"]] + [a for _n, a in t["extra"]]
    rows = []
    for args in calls:
        if _stopped(cancel):
            break
        if t["zpa_paged"]:
            got, err = _zpa_list(fn, args, q, cancel)
        else:
            got, err = pack_export._rows(fn(*args, query_params=q) if q else fn(*args))
        if err:
            return rows, err
        if args:
            for r in got:
                r.setdefault("_read_as", str(args[0]))
        rows.extend(got)
    return rows, None


def read_tenant(client: Any, keys: Sequence[str], *, log: Optional[Callable[[str], None]] = None, cancel: Any = None,
                microtenant_id: str = "") -> Dict[str, Any]:
    """Read the object types `keys`, GET only. {types: {key: rows}, unread:
    {key: why}, stopped, refused}: the shape config_backup.capture returns,
    so either reader can feed generate(). Rows are snake_case with every
    secret-named field masked. A read ZIA refuses for its rate is waited out
    and retried (pack_export._read); still refused, nothing more is read."""
    import pack_export
    say = log or (lambda m: None)
    out: Dict[str, Any] = {"types": {}, "unread": {}, "stopped": False, "refused": None}
    for key in keys:
        t = BY_KEY[key]
        if _stopped(cancel):
            out["stopped"] = True
            say("Stopped: nothing more is read, and no file is made.")
            return out
        say(f"Reading {PRODUCT_LABELS[t['product']]} {t['label']}…")
        rows, err, rate = pack_export._read(t["label"], lambda t=t: read_type(client, t, cancel=cancel, microtenant_id=microtenant_id),
                                            say, cancel)
        if _stopped(cancel):
            out["stopped"] = True
            say("Stopped: nothing more is read, and no file is made.")
            return out
        if err:
            out["unread"][key] = one_line(err)[:200]
            say(f"{PRODUCT_LABELS[t['product']]} {t['label']}: not read ({one_line(err)[:120]}).")
            if rate:
                out["refused"] = {"what": t["label"], "error": one_line(err)[:200]}
                say("ZIA still refuses reads for its rate limit: nothing more is read.")
                return out
            if not rows:
                continue
        rows = _clean(rows or [])
        if len(rows) > MAX_ROWS_PER_TYPE:
            out["unread"][key] = f"more than {MAX_ROWS_PER_TYPE} objects; the first {MAX_ROWS_PER_TYPE} were kept"
            rows = rows[:MAX_ROWS_PER_TYPE]
        out["types"][key] = rows
        say(f"{PRODUCT_LABELS[t['product']]} {t['label']}: {len(rows)}.")
    return out


# ---------------------------------------------------------------------------
# Read hooks: the provider's shape for what the API writes differently
# ---------------------------------------------------------------------------

_DICT_REF = re.compile(r"\bD(\d+)(?=\.)")


def _hook_engine_expression(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """An engine's expression names dictionaries by id ("D63.S > 1"): each
    becomes the dictionary's address (a custom one exported here) or a
    lookup by name (a predefined one), inside one HCL template string."""
    expr = row.get("engine_expression")
    if not isinstance(expr, str) or not expr:
        return row
    names = ctx.names.get("zia.dlp_dictionaries", {})
    parts: List[str] = []
    last = 0
    for m in _DICT_REF.finditer(expr):
        ref = ctx.resolve(_Ref("zia.dlp_dictionaries", m.group(1), names.get(m.group(1))), counted="engine expression")
        if not ref.startswith(("zia_", "data.")):
            continue
        parts.append(hcl_str(expr[last:m.start() + 1])[1:-1])
        parts.append("${" + ref + "}")
        last = m.end()
    parts.append(hcl_str(expr[last:])[1:-1])
    return dict(row, engine_expression=_Raw('"' + "".join(parts) + '"'))


def _hook_policy_v2(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """A ZPA policy rule as the v2 resources take its conditions: within a
    condition, operands grouped by object type; an operand whose lhs is
    "id" goes into `values` (an application or segment group becomes its
    address), any other into `entry_values` {lhs, rhs} (assumed mapping,
    see the module docstring)."""
    conds = []
    for c in row.get("conditions") or []:
        if not isinstance(c, dict):
            continue
        by_type: Dict[str, Dict[str, Any]] = {}
        for op in c.get("operands") or []:
            if not isinstance(op, dict) or not op.get("object_type"):
                continue
            ot = str(op["object_type"])
            slot = by_type.setdefault(ot, {"object_type": ot, "values": [], "entry_values": []})
            lhs, rhs = op.get("lhs"), op.get("rhs")
            if str(lhs) == "id":
                target = {"APP": "zpa.application_segments", "APP_GROUP": "zpa.segment_groups"}.get(ot)
                slot["values"].append(_Ref(target, rhs, op.get("name")) if target else rhs)
            elif lhs is not None:
                slot["entry_values"].append({"lhs": lhs, "rhs": rhs})
        if by_type:
            conds.append({"operator": c.get("operator") or "OR", "operands": list(by_type.values())})
    out = dict(row, conditions=conds)
    for k in ("app_server_groups", "app_connector_groups"):
        if isinstance(row.get(k), list):
            out[k] = [{"id": x.get("id"), "name": x.get("name")} for x in row[k] if isinstance(x, dict)]
    return out


def _hook_provisioning_key(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """A provisioning key names its association by the list it was read from."""
    assoc = {"connector": "CONNECTOR_GRP", "service_edge": "SERVICE_EDGE_GRP"}.get(str(row.get("_read_as") or ""), row.get("association_type"))
    return dict(row, association_type=row.get("association_type") or assoc)


def _hook_lss_name(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """An LSS configuration's name is inside its `config` block."""
    cfg = row.get("config") if isinstance(row.get("config"), dict) else {}
    return dict(row, name=row.get("name") or cfg.get("name"))


def _hook_pra_console(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    app = row.get("pra_application")
    if isinstance(app, dict):
        row = dict(row, pra_application=[app])
    return row


def _hook_security_lists(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    return row


HOOKS = {"engine_expression": _hook_engine_expression, "policy_v2": _hook_policy_v2, "provisioning_key": _hook_provisioning_key,
         "lss_name": _hook_lss_name, "pra_console": _hook_pra_console, "security_lists": _hook_security_lists}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def _rid(row: Dict[str, Any]) -> str:
    v = row.get("id")
    return "" if v is None else str(v)


def _ident(x: Any) -> Tuple[Any, Any]:
    """(id, name) of one reference element: {id, name}, or a bare id."""
    if isinstance(x, dict):
        return x.get("id", x.get("external_id")), x.get("name")
    return x, None


def _num(v: Any) -> Optional[str]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return str(v)
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, str) and re.fullmatch(r"-?[0-9]{1,18}", v.strip()):
        return str(int(v.strip()))
    return None


def _float(v: Any) -> Optional[str]:
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if f != f or f in (float("inf"), float("-inf")):
        return None
    return repr(f) if not f.is_integer() else str(int(f))


def _bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    if isinstance(v, str) and v.strip().lower() in ("true", "false"):
        return v.strip().lower() == "true"
    return None


def _empty(v: Any) -> bool:
    return v is None or v == "" or v == [] or v == {} or v in ("(not set)",)


class _Ctx:
    """One product's generation: addresses of exported objects, names for
    lookups, the data sources and variables needed, and the counts."""

    def __init__(self, product: str, prefix: str):
        self.product = product
        self.prefix = prefix
        self.addr: Dict[Tuple[str, str], Tuple[str, str]] = {}     # (type key, id) -> (resource, label)
        self.names: Dict[str, Dict[str, str]] = {}                 # type key -> id -> name
        self.labels: Dict[str, set] = {}                           # resource -> labels given
        self.data: Dict[Tuple[str, str], str] = {}                 # (data source, name) -> label
        self.data_labels: Dict[str, set] = {}
        self.secret_vars: Dict[str, str] = {}                      # variable -> what
        self.refs = {"resource": 0, "data": 0, "id": 0}
        self.unresolved: Dict[str, int] = {}
        self.dropped: Dict[str, Dict[str, int]] = {}               # resource -> attribute -> count
        self.singleton = False

    def label(self, resource: str, name: str) -> str:
        taken = self.labels.setdefault(resource, set())
        base = slug(f"{self.prefix}_{name}" if self.prefix else name)[:60].rstrip("_") or "x"
        cand, n = base, 2
        while cand in taken:
            cand, n = f"{base}_{n}", n + 1
        taken.add(cand)
        return cand

    def drop(self, resource: str, attr: str) -> None:
        d = self.dropped.setdefault(resource, {})
        d[attr] = d.get(attr, 0) + 1

    def resolve(self, ref: _Ref, counted: str = "") -> str:
        """The HCL for a reference: an address, a data lookup, or the id."""
        ident = "" if ref.ident is None else str(ref.ident)
        if ref.target:
            hit = self.addr.get((ref.target, ident))
            if hit:
                self.refs["resource"] += 1
                res, lab = hit
                return f"{res}.{lab}.{ID_ATTR.get(res, 'id')}"
            name = ref.name if ref.name not in (None, "") else self.names.get(ref.target, {}).get(ident)
            spec = DATA.get(ref.target)
            if spec and name and ref.target not in PERSONAL_TARGETS:
                ds, arg = spec
                key = (ds, str(name))
                if key not in self.data:
                    taken = self.data_labels.setdefault(ds, set())
                    base = slug(str(name))[:60].rstrip("_") or "x"
                    cand, n = base, 2
                    while cand in taken:
                        cand, n = f"{base}_{n}", n + 1
                    taken.add(cand)
                    self.data[key] = cand
                self.refs["data"] += 1
                return f"data.{ds}.{self.data[key]}.id"
            self.unresolved[ref.target] = self.unresolved.get(ref.target, 0) + 1
        self.refs["id"] += 1
        n = _num(ident)
        return n if n is not None else hcl_str(ident)


def _ref_target(ctx: _Ctx, attr: str) -> Optional[str]:
    return REFS.get(ctx.product, {}).get(attr)


def _scalar(kind: str, v: Any, ctx: _Ctx, attr: str, ref: Optional[str]) -> Optional[str]:
    if isinstance(v, _Raw):
        return v.hcl
    if isinstance(v, _Ref):
        return ctx.resolve(v)
    if ref is not None and kind in ("s", "n") and not isinstance(v, (dict, list, bool)) and not _empty(v):
        return ctx.resolve(_Ref(ref, v))
    if kind == "s":
        if isinstance(v, bool) or isinstance(v, (dict, list)):
            return None
        return hcl_str(v)
    if kind == "n":
        return _num(v)
    if kind == "f":
        return _float(v)
    if kind == "b":
        b = _bool(v)
        if b is None or (b is False and not ctx.singleton):
            return None
        return "true" if b else "false"
    return None


def _list(kind: str, v: Any, ctx: _Ctx, ref: Optional[str]) -> Optional[str]:
    items = v if isinstance(v, list) else ([v] if isinstance(v, (str, int)) and not isinstance(v, bool) else None)
    if items is None:
        return None
    out = []
    for x in items:
        if isinstance(x, _Ref):
            out.append(ctx.resolve(x))
        elif ref is not None and not isinstance(x, (dict, list, bool)):
            out.append(ctx.resolve(_Ref(ref, x)))
        elif isinstance(x, dict) and ref is not None and x.get("id") is not None:
            out.append(ctx.resolve(_Ref(ref, x.get("id"), x.get("name"))))
        elif isinstance(x, (dict, list)) or isinstance(x, bool) or x is None:
            return None
        elif kind == "ln":
            n = _num(x)
            if n is None:
                return None
            out.append(n)
        else:
            out.append(hcl_str(x))
    return hcl_list(out, raw=True) if out else None


def _render_attrs(schema: List[Tuple[str, str, bool, Any]], row: Dict[str, Any], ctx: _Ctx, t: Dict[str, Any], label: str,
                  indent: int, nested: bool = False) -> Tuple[List[str], List[str]]:
    """(lines, missing required) for one object or nested block."""
    pad = "  " * indent
    lines: List[str] = []
    missing: List[str] = []
    for attr, kind, req, sub in schema:
        v = row.get(attr)
        if kind == "secret":
            var = t["secrets"].get(attr)
            if var and not nested or var:
                if var:
                    ctx.secret_vars[var] = attr
                    lines.append(f"{pad}{attr} = lookup(var.{var}, {hcl_str(label)}, null)")
            continue
        if isinstance(v, str) and v in ("(set)", "(not set)"):
            ctx.drop(t["resource"], attr)    # a secret-named field the read masked: never written
            continue
        if _empty(v):
            if req:
                missing.append(attr)
            continue
        ref = _ref_target(ctx, attr)
        if kind in ("s", "n", "f", "b"):
            val = _scalar(kind, v, ctx, attr, ref)
            if val is None:
                if not (kind == "b" and _bool(v) is False):
                    if req:
                        missing.append(attr)
                    elif _bool(v) is None:
                        ctx.drop(t["resource"], attr)
                continue
            lines.append(f"{pad}{attr} = {val}")
        elif kind in ("ls", "ln"):
            val = _list(kind, v, ctx, ref)
            if val is None:
                if req:
                    missing.append(attr)
                else:
                    ctx.drop(t["resource"], attr)
                continue
            lines.append(f"{pad}{attr} = {val}")
        elif kind in ("ids", "sids"):
            items = v if isinstance(v, list) else [v]
            vals = []
            for x in items:
                ident, name = _ident(x)
                if ident is None or isinstance(ident, (dict, list, bool)):
                    continue
                if kind == "ids" and _num(ident) is None:
                    vals = None
                    break
                vals.append(ctx.resolve(_Ref(ref, ident, name)) if ref else (_num(ident) if kind == "ids" else hcl_str(ident)))
            if not vals:
                if vals is None:
                    ctx.drop(t["resource"], attr)
                if req:
                    missing.append(attr)
                continue
            lines.append(f"{pad}{attr} {{\n{pad}  id = {hcl_list(vals, raw=True)}\n{pad}}}")
        elif kind in ("idb", "sidb"):
            items = v if isinstance(v, list) else [v]
            n_out = 0
            for x in items:
                ident, name = _ident(x)
                if ident is None or isinstance(ident, (dict, list, bool)):
                    continue
                if kind == "idb" and not ref and _num(ident) is None:
                    continue
                val = ctx.resolve(_Ref(ref, ident, name)) if ref else (_num(ident) if kind == "idb" else hcl_str(ident))
                lines.append(f"{pad}{attr} {{\n{pad}  id = {val}\n{pad}}}")
                n_out += 1
            if not n_out and req:
                missing.append(attr)
        elif kind == "extid":
            items = v if isinstance(v, list) else [v]
            for x in items:
                if isinstance(x, dict) and x.get("external_id") not in (None, "") and x.get("name") not in (None, ""):
                    lines.append(f"{pad}{attr} {{\n{pad}  external_id = {hcl_str(x['external_id'])}\n{pad}  name = {hcl_str(x['name'])}\n{pad}}}")
        elif kind == "blk":
            items = v if isinstance(v, list) else [v]
            n_out = 0
            for x in items:
                if not isinstance(x, dict):
                    continue
                inner, miss = _render_attrs(sub, x, ctx, t, label, indent + 1, nested=True)
                if miss or not inner:
                    if miss:
                        ctx.drop(t["resource"], attr)
                    continue
                lines.append(f"{pad}{attr} {{\n" + "\n".join(inner) + f"\n{pad}}}")
                n_out += 1
            if not n_out and req:
                missing.append(attr)
    return lines, missing


def _import_id(t: Dict[str, Any], row: Dict[str, Any]) -> str:
    if t["import_id"]:
        return t["import_id"]
    return t["import_fmt"].format(id=_rid(row), type=str(row.get("type") or ""))


def _display_name(t: Dict[str, Any], row: Dict[str, Any]) -> str:
    v = row.get(t["name"])
    if v in (None, "") and t["name"] != "name":
        v = row.get("name")
    if v in (None, ""):
        v = row.get("ip_address") or row.get("id") or t["label"]
    return str(v)


def render_resource(t: Dict[str, Any], row: Dict[str, Any], label: str, ctx: _Ctx) -> Tuple[Optional[str], List[str]]:
    """(HCL of one resource, missing required arguments). None when a
    required argument is missing (the object is then listed as not exported)."""
    hook = HOOKS.get(t["hook"] or "")
    if hook:
        row = hook(row, ctx)
    ctx.singleton = t["singleton"]
    body, missing = _render_attrs(schema_of(t["resource"]), row, ctx, t, label, 1)
    if missing:
        return None, missing
    head = f"# {hcl_comment(one_line(_display_name(t, row)))[:200]}\n" if not t["singleton"] else ""
    return head + f'resource "{t["resource"]}" "{label}" {{\n' + "\n".join(body) + ("\n" if body else "") + "}\n", []


# ---------------------------------------------------------------------------
# Files
# ---------------------------------------------------------------------------

_AREA_FILES = {"settings": "settings.tf", "threat_protection": "threat_protection.tf", "objects": "objects.tf",
               "url_filtering": "url_filtering.tf", "firewall_objects": "firewall_objects.tf", "firewall": "firewall.tf",
               "bandwidth": "bandwidth.tf", "dlp": "dlp.tf", "dlp_rules": "dlp_rules.tf", "ssl_inspection": "ssl_inspection.tf",
               "file_type_control": "file_type_control.tf", "cloud_app_control": "cloud_app_control.tf", "forwarding": "forwarding.tf",
               "traffic_forwarding": "traffic_forwarding.tf", "segments": "segments.tf", "infrastructure": "infrastructure.tf",
               "policies": "policies.tf", "inspection": "inspection.tf", "pra": "pra.tf", "portals": "portals.tf",
               "isolation": "isolation.tf", "provisioning": "provisioning.tf"}

_SECRET_WORDS = {
    "vpn_pre_shared_keys": "Pre-shared key per VPN credential (by resource label). The export never reads or writes one: fill them in before an apply that creates or changes a credential.",
    "pra_credential_passwords": "Password per PRA credential (by resource label). Never exported: fill in before an apply that creates or changes one.",
    "pra_credential_passphrases": "Private-key passphrase per PRA credential (by resource label). Never exported.",
    "pra_credential_private_keys": "Private key per PRA credential (by resource label). Never exported.",
    "cbi_debug_file_passwords": "Debug file password per isolation profile (by resource label). Never exported.",
}


def _provider_block(product: str) -> str:
    lines = [f"{GENERATED_MARK}. Credentials come from variables (see terraform.tfvars.example) or, when",
             "# the variables are left null, from the provider's ZSCALER_* environment variables.",
             "# Nothing secret is written into this workspace.", "",
             f'provider "{product}" {{', "  client_id     = var.zscaler_client_id", "  client_secret = var.zscaler_client_secret",
             "  vanity_domain = var.zscaler_vanity_domain", "  zscaler_cloud = var.zscaler_cloud"]
    if product == "zpa":
        lines += ["  customer_id    = var.zpa_customer_id", "  microtenant_id = var.zpa_microtenant_id"]
    lines.append("}")
    return hcl_fmt("\n".join(lines)) + "\n"


def _terraform_tf(product: str, namespace: str) -> str:
    src = f"{namespace}/{product}"
    return (f"{GENERATED_MARK}. Terraform {TERRAFORM_VERSION} for import blocks; the provider pinned to a minor line.\n\n"
            f"terraform {{\n  required_version = {hcl_str(TERRAFORM_VERSION)}\n\n  required_providers {{\n"
            f"    {product} = {{\n      source  = {hcl_str(src)}\n      version = {hcl_str(PROVIDERS[product]['version'])}\n    }}\n  }}\n\n"
            "  # Remote state (recommended for shared use). Uncomment and fill in, or pass\n"
            "  # -backend-config=... on `terraform init`.\n"
            '  # backend "s3" {\n  #   bucket         = "my-terraform-state"\n'
            f'  #   key            = "zscaler/{product}/tenant.tfstate"\n'
            '  #   region         = "us-east-1"\n  #   encrypt        = true\n  #   dynamodb_table = "terraform-locks"\n  # }\n}\n')


def _variables_tf(product: str, secret_vars: Dict[str, str]) -> str:
    rows = [
        ("zscaler_client_id", "string", "null", True, "OneAPI client ID. Leave null to use ZSCALER_CLIENT_ID."),
        ("zscaler_client_secret", "string", "null", True, "OneAPI client secret. Leave null to use ZSCALER_CLIENT_SECRET."),
        ("zscaler_vanity_domain", "string", "null", False, "ZIdentity vanity domain (acme for acme.zslogin.net). Leave null to use ZSCALER_VANITY_DOMAIN."),
        ("zscaler_cloud", "string", "null", False, "Leave null (or empty) for commercial production; beta, gov or govus otherwise. Env: ZSCALER_CLOUD."),
    ]
    if product == "zpa":
        rows += [("zpa_customer_id", "string", "null", False, "ZPA customer ID. Leave null to use ZPA_CUSTOMER_ID."),
                 ("zpa_microtenant_id", "string", "null", False, "ZPA microtenant ID, when the objects belong to one. Leave null for the parent tenant.")]
    out = [f"{GENERATED_MARK}. Every variable is typed and described; secrets are sensitive and have no value here.\n\n"]
    for name, typ, default, sens, desc in rows:
        out.append(f'variable "{name}" {{\n  description = {hcl_str(desc)}\n  type        = {typ}\n  default     = {default}\n'
                   + ("  sensitive   = true\n" if sens else "") + "}\n\n")
    for var in sorted(secret_vars):
        out.append(f'variable "{var}" {{\n  description = {hcl_str(_SECRET_WORDS.get(var, "Secret values by resource label. Never exported."))}\n'
                   "  type        = map(string)\n  default     = {}\n  nullable    = false\n  sensitive   = true\n}\n\n")
    return hcl_fmt("".join(out).rstrip("\n") + "\n") + ("" if "".join(out).endswith("\n") else "")


def _tfvars_example(product: str, secret_vars: Dict[str, str]) -> str:
    out = ["# Written by Zscaler Made Easy. Copy to terraform.tfvars (git-ignored). Credentials may instead be exported:\n",
           '#   export ZSCALER_CLIENT_ID="..." ZSCALER_CLIENT_SECRET="..." ZSCALER_VANITY_DOMAIN="acme" ZSCALER_CLOUD=""\n\n',
           '# zscaler_client_id     = "..."\n# zscaler_client_secret = "..."\n# zscaler_vanity_domain = "acme"\n# zscaler_cloud         = ""\n']
    if product == "zpa":
        out.append('# zpa_customer_id       = "..."\n')
    for var in sorted(secret_vars):
        out.append(f'\n# {var} = {{\n#   "<resource label>" = "..."\n# }}\n')
    return "".join(out)


def _outputs_tf(by_resource: Dict[str, List[Tuple[str, str]]]) -> str:
    out = [f"{GENERATED_MARK}. Name => id of every object this workspace manages, per resource type.\n\n"]
    for res in sorted(by_resource):
        items = by_resource[res]
        names = hcl_list([name for name, _lab in items])
        ids = hcl_list([f"{res}.{lab}.id" for _name, lab in items], raw=True)
        out.append(f'output "{res}" {{\n  description = {hcl_str(f"Name => id of each {res} in this workspace.")}\n'
                   f"  value       = zipmap({names}, {ids})\n}}\n\n")
    return "".join(out).rstrip("\n") + "\n"


def _data_tf(ctx: _Ctx) -> str:
    out = [f"{GENERATED_MARK}. Objects the exported ones name but that are not exported (predefined,\n"
           "# out of scope or made elsewhere), looked up by name in the tenant at plan time.\n\n"]
    for (ds, name), lab in sorted(ctx.data.items(), key=lambda kv: (kv[0][0], kv[1])):
        out.append(f'data "{ds}" "{lab}" {{\n  name = {hcl_str(name)}\n}}\n\n')
    return "".join(out).rstrip("\n") + "\n"


def _readme_product(product: str, counts: Dict[str, int], ctx: _Ctx, not_exported: List[Dict[str, str]], namespace: str,
                    tenant_label: str) -> str:
    rows = "".join(f"| `{res}` | {n} |\n" for res, n in sorted(counts.items()))
    nx = "".join(f"| {md_safe.text(x['what'])} | {md_safe.text(x['why'])} |\n" for x in not_exported) or "| (nothing) | |\n"
    secrets = "".join(f"| `{v}` | {md_safe.text(_SECRET_WORDS.get(v, ''))} |\n" for v in sorted(ctx.secret_vars))
    return (f"# {PRODUCT_LABELS[product]} as Terraform\n\n"
            f"Exported by Zscaler Made Easy from {md_safe.text(tenant_label or 'the tenant')}, read-only, for the "
            f"[`{namespace}/{product}`]({PROVIDERS[product]['docs']}) provider ({PROVIDERS[product]['version']}).\n\n"
            "## Adopt the tenant without recreating anything\n\n```bash\nterraform init\n"
            "terraform plan -out=tfplan   # imports every object below; review any change it proposes\nterraform apply tfplan\n```\n\n"
            "`imports.tf` holds one `import` block per resource (Terraform 1.5 or later), with the object's tenant id, so the first apply "
            "brings the tenant's objects into state instead of creating new ones. Values the provider fills in on its own (defaults, "
            "computed ids) may show as an in-place update on the first plan; read it before you apply.\n\n"
            "## What is in this workspace\n\n| Resource type | Objects |\n|---|---|\n" + (rows or "| (none) | 0 |\n") + "\n"
            f"References: {ctx.refs['resource']} by Terraform address, {ctx.refs['data']} by a lookup by name (`datasource.tf`), "
            f"{ctx.refs['id']} by tenant id (the object is not exported and has no lookup, or is a user).\n\n"
            "## Not exported\n\n| What | Why |\n|---|---|\n" + nx + "\n"
            + ("## Secrets\n\nNo secret is in these files. Each secret the provider needs is a sensitive map variable keyed by resource label; "
               "set it in `terraform.tfvars` (git-ignored) or with `TF_VAR_...`.\n\n| Variable | Holds |\n|---|---|\n" + secrets + "\n" if secrets else "")
            + "## Verify\n\n```bash\nterraform fmt -check -recursive   # the files are written fmt-clean\nterraform validate\n```\n\n"
            "State, saved plans and `terraform.tfvars` carry tenant ids and, if you put them there, credentials: `.gitignore` keeps them out of git. "
            "Commit `.terraform.lock.hcl` after the first `terraform init`.\n")


def generate(snapshot: Dict[str, Any], opts: Dict[str, Any], *, tenant_label: str = "", plan_info: Optional[Dict[str, Any]] = None,
             generated_at: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """The workspace files ({path: content}, paths under ROOT_DIR/) and the
    report (counts, references, not exported). Pure: reads nothing."""
    when = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    types = snapshot.get("types") or {}
    unread = snapshot.get("unread") or {}
    plan_info = plan_info or {}
    files: Dict[str, str] = {}
    report: Dict[str, Any] = {"generated_at": when, "tenant_label": tenant_label, "products": {}, "not_exported": [],
                              "not_covered": [{"product": p, "what": w, "why": y} for p, w, y in NOT_COVERED]}
    for key, why in sorted((plan_info.get("not_in_scope") or {}).items()):
        report["not_exported"].append({"product": BY_KEY[key]["product"], "type": key, "what": BY_KEY[key]["label"], "why": why})
    for key, why in sorted((plan_info.get("left_out") or {}).items()):
        report["not_exported"].append({"product": BY_KEY[key]["product"], "type": key, "what": BY_KEY[key]["label"], "why": why})
    for key, why in sorted(unread.items()):
        if key in BY_KEY:
            report["not_exported"].append({"product": BY_KEY[key]["product"], "type": key, "what": BY_KEY[key]["label"],
                                           "why": f"could not be read: {one_line(why)[:200]}"})
    for product in opts["products"]:
        keys = [t["key"] for t in TYPES if t["product"] == product and t["key"] in types]
        if not keys:
            continue
        ctx = _Ctx(product, opts.get("prefix") or "")
        kept: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
        skipped: List[Dict[str, str]] = []
        # 1. every object's id and name (for lookups), and a label for each one exported
        for key in keys:
            t = BY_KEY[key]
            for row in types[key]:
                rid = _rid(row)
                ctx.names.setdefault(key, {})[rid] = _display_name(t, row)
            for row in types[key]:
                if t["keep"] and not t["keep"](row):
                    skipped.append({"what": f"{t['label']}: {one_line(_display_name(t, row))[:120]}", "why": t["keep_why"] or "not exported"})
                    continue
                lab = ctx.label(t["resource"], t["resource"].split("_", 1)[1] if t["singleton"] else _display_name(t, row))
                if not t["singleton"] and _rid(row):
                    ctx.addr[(key, _rid(row))] = (t["resource"], lab)
                kept.setdefault(key, []).append((row, lab))
        # 2. the resources, area by area
        by_area: Dict[str, List[str]] = {}
        imports: List[str] = []
        by_resource: Dict[str, List[Tuple[str, str]]] = {}
        counts: Dict[str, int] = {}
        for key in keys:
            t = BY_KEY[key]
            for row, lab in kept.get(key, []):
                hcl, missing = render_resource(t, row, lab, ctx)
                if hcl is None:
                    skipped.append({"what": f"{t['label']}: {one_line(_display_name(t, row))[:120]}",
                                    "why": "the tenant's answer lacks what the provider requires (" + ", ".join(missing[:4]) + ")"})
                    ctx.addr.pop((key, _rid(row)), None)
                    continue
                by_area.setdefault(_AREA_FILES[t["area"]], []).append(hcl)
                imports.append(f"import {{\n  to = {t['resource']}.{lab}\n  id = {hcl_str(_import_id(t, row))}\n}}\n")
                counts[t["resource"]] = counts.get(t["resource"], 0) + 1
                if not t["singleton"]:
                    by_resource.setdefault(t["resource"], []).append((_display_name(t, row), lab))
        if not counts:
            report["products"][product] = {"resources": {}, "references": dict(ctx.refs), "skipped": skipped}
            continue
        base = f"{ROOT_DIR}/{product}"
        for fname, blocks in by_area.items():
            files[f"{base}/{fname}"] = hcl_fmt(f"{GENERATED_MARK}. Read from the tenant; do not edit by hand before the first import.\n\n"
                                               + "\n".join(blocks))
        files[f"{base}/imports.tf"] = (f"{GENERATED_MARK}. Adopt the tenant's objects into state on the first apply (Terraform 1.5+).\n\n"
                                       + "\n".join(imports))
        if ctx.data:
            files[f"{base}/datasource.tf"] = _data_tf(ctx)
        files[f"{base}/terraform.tf"] = _terraform_tf(product, opts.get("namespace") or DEFAULT_NAMESPACE)
        files[f"{base}/providers.tf"] = _provider_block(product)
        files[f"{base}/variables.tf"] = _variables_tf(product, ctx.secret_vars)
        files[f"{base}/outputs.tf"] = _outputs_tf(by_resource) if by_resource else f"{GENERATED_MARK}. No listed objects.\n"
        files[f"{base}/terraform.tfvars.example"] = _tfvars_example(product, ctx.secret_vars)
        files[f"{base}/.gitignore"] = GITIGNORE
        files[f"{base}/README.md"] = _readme_product(product, counts, ctx, skipped + [x for x in report["not_exported"] if x["product"] == product],
                                                     opts.get("namespace") or DEFAULT_NAMESPACE, tenant_label)
        report["products"][product] = {"resources": counts, "imports": len(imports), "data_sources": len(ctx.data),
                                       "references": dict(ctx.refs), "unresolved": dict(ctx.unresolved),
                                       "secret_variables": sorted(ctx.secret_vars), "skipped": skipped,
                                       "dropped_attributes": {r: dict(v) for r, v in ctx.dropped.items()}}
    files[f"{ROOT_DIR}/README.md"] = _readme_root(report, opts)
    files[f"{ROOT_DIR}/export_report.json"] = json.dumps(report, indent=1, sort_keys=True) + "\n"
    return files, report


def _readme_root(report: Dict[str, Any], opts: Dict[str, Any]) -> str:
    lines = [f"# {md_safe.text(report.get('tenant_label') or 'Tenant')} as Terraform\n\n",
             f"Exported read-only by Zscaler Made Easy on {md_safe.text(report['generated_at'])}. One workspace per product; "
             "each has its own README, provider pin, variables and import blocks.\n\n| Workspace | Resources | Imports | Lookups by name |\n|---|---|---|---|\n"]
    for p in PRODUCTS:
        info = report["products"].get(p)
        if not info:
            continue
        n = sum(info.get("resources", {}).values())
        lines.append(f"| `{p}/` ({PRODUCT_LABELS[p]}) | {n} | {info.get('imports', 0)} | {info.get('data_sources', 0)} |\n")
    lines.append("\n## Not exported\n\n| Product | What | Why |\n|---|---|---|\n")
    for x in report["not_exported"]:
        lines.append(f"| {PRODUCT_LABELS.get(x['product'], '')} | {md_safe.text(x['what'])} | {md_safe.text(x['why'])} |\n")
    for x in report["not_covered"]:
        if x["product"] in opts["products"]:
            lines.append(f"| {PRODUCT_LABELS[x['product']]} | {md_safe.text(x['what'])} | {md_safe.text(x['why'])} |\n")
    lines.append("\nNo secret is in these files: secrets the providers need are sensitive variables you fill in. "
                 "`export_report.json` holds the same summary as data.\n")
    return "".join(lines)


def zip_files(files: Dict[str, str]) -> bytes:
    """The workspace as one zip; every path was made by generate()."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path in sorted(files):
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.external_attr = 0o600 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[path])
    return buf.getvalue()


def export(client: Any, opts: Dict[str, Any], keys: Sequence[str], *, tenant_label: str = "", plan_info: Optional[Dict[str, Any]] = None,
           log: Optional[Callable[[str], None]] = None, cancel: Any = None) -> Dict[str, Any]:
    """Read, generate and zip. {status: ready | stopped | refused, ...}."""
    say = log or (lambda m: None)
    snap = read_tenant(client, keys, log=say, cancel=cancel, microtenant_id=opts.get("microtenant_id") or "")
    if snap["stopped"] or _stopped(cancel):
        return {"status": "stopped", "stopped": "You clicked Stop before the export finished: no file was made."}
    if snap["refused"]:
        return {"status": "refused", "error": f"ZIA refused the read of the {snap['refused']['what']} for its rate limit, so no file was "
                                              "made (a workspace with a type missing would plan to leave it unmanaged). Try again after "
                                              "the hourly limit resets."}
    say("Writing the Terraform workspaces…")
    files, report = generate(snap, opts, tenant_label=tenant_label, plan_info=plan_info)
    data = zip_files(files)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M")
    name = f"tenant-terraform-{stamp}.zip"
    say(f"Ready: {name} ({max(1, len(data) // 1024)} KB).")
    return {"status": "ready", "filename": name, "bytes": len(data), "report": report, "artifact": (name, "application/zip", data)}
