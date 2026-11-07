#!/usr/bin/env python3
"""
Export a whole tenant to Terraform: ZIA, ZPA, Cloud & Branch Connector and
Client Connector.

Reads the live tenant (or the sample tenant, or an opened snapshot: the
same SDK client interface, offline_tenant.py) within the Scope rule and
writes one Terraform root module per product for the official providers:

    zscaler/zia  ~> 4.8     ZIA (58 resource types)
    zscaler/zpa  ~> 4.4     ZPA (31 resource types)
    zscaler/ztc  ~> 0.2     Cloud & Branch Connector (10 resource types)
    zscaler/zcc  0.1.2-beta.3  Client Connector (beta provider: trusted networks, forwarding
                            profiles, fail-open policy, device cleanup, web privacy,
                            notification templates, ZIA posture profiles)

The Client Connector provider (registry.terraform.io/providers/zscaler/zcc,
github.com/zscaler/terraform-provider-zcc) has published pre-releases only
(0.1.0-beta.1, 0.1.1-beta.2, 0.1.2-beta.3). Terraform selects a pre-release
only with an exact version constraint (`~> 0.1` matches none of them), so
the pin is exact and the workspace is labelled beta. The provider signs in
with ZIdentity OneAPI only, and OneAPI is not offered on the zscalergov and
zscalerten clouds: for those tenants, and for a classic (legacy) ZIA sign-in,
the zcc workspace is skipped with the reason (zcc_unavailable).

Two modes:

  adopt (default)  every exported object has an `import {}` block
                   (Terraform 1.5+) with its tenant id, and keeps the state
                   the tenant gave it, so a platform team adopts the tenant
                   into Terraform state without recreating or changing
                   anything (an enabled rule stays enabled);
  clone            no import blocks: new objects for another tenant. Every
                   rule is written DISABLED and every ZPA application
                   segment disabled (so ZPA policy, which has no switch in
                   the provider, grants nothing) unless keep_rule_state is
                   asked for; settings and objects bound to this tenant
                   (locations, tunnels, connectors, cloud accounts) are left
                   out with the reason.

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

Client Connector notification templates and ZIA posture profiles have no
call in zscaler-sdk-python 1.11.3, so they are read raw (GET only) through
the signed-in client's own request executor, at the paths the zcc provider
0.1.2-beta.3 manages them with (ZCC_RAW_PATHS; the provider's resource docs
and schema).

Assumed, not verifiable without a tenant:
  - GET /zcc/papi/public/v2/notification-templates and
    /zcc/papi/public/v2/zia-posture-profiles answer every object at once,
    as a JSON array (or an envelope holding one), without paging, in the
    camelCase the provider's docs name (isDefaultTemplate,
    ziaNotificationTemplate, highTrustCriteria {cs: [{cn: [...]}]}, a
    posture profile's platform as 1..5). The posture list is NOT assumed
    complete: the zcc provider documents that it can be cut short silently,
    so every export says it may be incomplete (MAY_BE_INCOMPLETE);
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

import copy
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import md_safe
from pack_terraform import (GENERATED_MARK, GITIGNORE, NAMESPACE_RE as _PT_NAMESPACE_RE, TERRAFORM_VERSION, hcl_comment, hcl_fmt, hcl_list,
                            hcl_str, one_line, slug)
from tenant_terraform_schema import SCHEMAS

PRODUCTS = ("zia", "zpa", "ztc", "zcc")
PRODUCT_LABELS = {"zia": "ZIA", "zpa": "ZPA", "ztc": "Cloud & Branch Connector", "zcc": "Client Connector"}
# The SDK's product for each provider (Cloud & Branch Connector is `ztw` in zscaler-sdk-python).
SDK_ROOT = {"zia": "zia", "zpa": "zpa", "ztc": "ztw", "zcc": "zcc"}
PROVIDERS = {
    "zia": {"version": "~> 4.8", "docs": "https://registry.terraform.io/providers/zscaler/zia/latest/docs"},
    "zpa": {"version": "~> 4.4", "docs": "https://registry.terraform.io/providers/zscaler/zpa/latest/docs"},
    "ztc": {"version": "~> 0.2", "docs": "https://registry.terraform.io/providers/zscaler/ztc/latest/docs"},
    # Exact: the provider has pre-releases only, and a pre-release is selected only by an exact constraint.
    "zcc": {"version": "0.1.2-beta.3", "docs": "https://registry.terraform.io/providers/zscaler/zcc/latest/docs", "beta": True},
}
# The Client Connector provider signs in with ZIdentity OneAPI only; OneAPI is
# not offered on these clouds (zscaler_clouds keys).
ZCC_NO_ONEAPI_CLOUDS = ("zscalergov", "zscalergovus", "zscalerten")
ZCC_BETA_NOTE = ("The zscaler/zcc provider is a beta (pre-release 0.1.2-beta.3, pinned exactly): check every plan before you apply, "
                 "and expect its arguments to change before 1.0.")


def zcc_unavailable(creds: Optional[Dict[str, Any]]) -> Optional[str]:
    """Why the Client Connector workspace cannot be used for this sign-in, or
    None. The zcc provider signs in with ZIdentity OneAPI only (no classic
    ZCC API keys), and OneAPI is not offered on zscalergov or zscalerten."""
    import tenant_auth
    import zscaler_clouds
    c = creds or {}
    if str(c.get("auth_method") or "") == tenant_auth.LEGACY:
        return ("skipped: the Client Connector provider (zscaler/zcc) signs in with a ZIdentity OneAPI client only, and this is a classic "
                "ZIA sign-in")
    try:
        cloud = zscaler_clouds.normalize(c.get("cloud"))
    except Exception:  # noqa: BLE001 - an unknown cloud is refused elsewhere
        cloud = str(c.get("cloud") or "")
    if cloud in ZCC_NO_ONEAPI_CLOUDS:
        return (f"skipped: the Client Connector provider (zscaler/zcc) signs in with ZIdentity OneAPI only, and OneAPI is not offered "
                f"on {cloud}")
    return None
MODES = ("adopt", "clone")
DEFAULT_NAMESPACE = "zscaler"
# A private registry mirror ("registry.example.com/zscaler"): a host name, then one namespace.
NAMESPACE_RE = _PT_NAMESPACE_RE   # one rule for the packs and the whole-tenant export
PREFIX_RE = re.compile(r"\A[a-z][a-z0-9_]{0,19}\Z")
MICROTENANT_RE = re.compile(r"\A[0-9]{1,20}\Z")
MAX_ROWS_PER_TYPE = 20000
MAX_ZPA_PAGES = 200
MAX_TYPES_ASKED = 200
MAX_LOG_LINES = 2000
ROOT_DIR = "tenant-terraform"

NOTHING_IN_SCOPE = ("Nothing this export reads is in scope on the Scope page: tick DLP or ZIA platform (ZIA), ZPA, "
                    "Cloud & Branch Connector or ZCC, and pick at least one product. Nothing was read.")


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
    "zcc": {"trusted_network_ids": "zcc.trusted_networks", "trusted_network_ids_selected": "zcc.trusted_networks"},
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
# Where the SDK's answer names an argument differently from the provider
# (zscaler-sdk-python 1.11.3 models): provider argument <- the row's field.
RENAMES: Dict[str, Dict[str, str]] = {
    "zia_cloud_application_instance": {"name": "instance_name"},
    "zia_sandbox_behavioral_analysis": {"file_hashes_to_be_blocked": "md5_hash_value_list"},
    "zpa_pra_credential_controller": {"username": "user_name"},
    "zpa_inspection_profile": {"threat_labz_controls": "threatlabz_controls"},
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

_NESTED = ("blk", "objs", "obj")   # nested blocks; one nested object attribute (`x = {..}`); a list of them (`x = [{..}]`)


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
        nested = next((w for w in _NESTED if text.startswith(w + "(", k)), None)
        if nested:
            depth, m = 0, k + len(nested)
            while True:
                if text[m] == "(":
                    depth += 1
                elif text[m] == ")":
                    depth -= 1
                    if depth == 0:
                        break
                m += 1
            sub = parse_schema(text[k + len(nested) + 1:m])
            k = m + 1
            req = k < n and text[k] == "!"
            out.append((name, nested, req, sub))
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


# The forward methods zscaler/ztc's ztc_traffic_forwarding_rule accepts (its
# forward_method validator, 0.2.0). The API also answers ZPA, PROXYCHAIN,
# ECSELF and others, which that resource cannot express.
_ZTC_FORWARD_METHODS = ("DIRECT", "LOCAL_SWITCH", "ZIA", "ECZPA", "DROP")


def _keep_ztc_forwarding_rule(row: Dict[str, Any]) -> bool:
    return _custom_rule(row) and str(row.get("forward_method") or "").upper() in _ZTC_FORWARD_METHODS


def _why_ztc_forwarding_rule(row: Dict[str, Any]) -> str:
    if not _custom_rule(row):
        return _PREDEF
    return (f"forward method {one_line(str(row.get('forward_method') or 'none'))[:40]}, which the provider's "
            f"ztc_traffic_forwarding_rule does not take (it takes {', '.join(_ZTC_FORWARD_METHODS)})")


def _keep_ztc_ip_pool(row: Dict[str, Any]) -> bool:
    # ztc_ip_pool_groups holds exactly one address range (ip_addresses: required, at most 1 item, 0.2.0).
    return isinstance(row.get("ip_addresses"), list) and len(row["ip_addresses"]) == 1


def _why_ztc_ip_pool(row: Dict[str, Any]) -> str:
    n = len(row.get("ip_addresses") or []) if isinstance(row.get("ip_addresses"), list) else 0
    return f"{n} address ranges; the provider's ztc_ip_pool_groups holds exactly one"


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
       keep_why: Any = "", extra: Optional[List[Tuple[str, Tuple[Any, ...]]]] = None, bound: bool = False,
       raw: Optional[str] = None) -> Dict[str, Any]:
    product = key.split(".", 1)[0]
    return {"key": key, "product": product, "resource": resource, "label": label, "area": area, "svc": svc, "method": method,
            "gate": gate, "args": args, "singleton": singleton, "import_id": import_id, "name": name, "keep": keep,
            "per_type": per_type, "zpa_paged": zpa_paged, "personal": personal, "hook": hook, "import_fmt": import_fmt,
            "secrets": secrets or {}, "keep_why": keep_why, "extra": extra or [], "bound": bound, "raw": raw}


# Client Connector reads the SDK has no call for: the paths the zcc provider
# 0.1.2-beta.3 manages these resources at (its resource docs and schema
# descriptions). assumed: answered in one GET (no paging), as a JSON array or
# an envelope holding one. Not assumed complete for ZIA posture profiles: see
# MAY_BE_INCOMPLETE.
ZCC_RAW_PATHS = {"zcc.notification_templates": "/zcc/papi/public/v2/notification-templates",
                 "zcc.zia_posture": "/zcc/papi/public/v2/zia-posture-profiles"}

# Lists the API is known to cut short without saying so. The zcc provider's
# own docs (docs/data-sources/zcc_zia_posture.md, CLAUDE.md) say the
# /zia-posture-profiles list endpoint "mishandles pagination and silently
# returns a truncated set"; the provider pages nothing there (its data source
# looks a profile up by id only), and neither the provider nor the SDK
# offers a paging form that is known to work, so the export cannot get
# every profile for certain. It never implies completeness: every export
# that reads such a list says, in its report and both READMEs, that the
# list may be incomplete, with the count it got.
MAY_BE_INCOMPLETE = {
    "zcc.zia_posture": ("the Client Connector API's ZIA posture profile list (/zia-posture-profiles) is known to cut its answer "
                        "short without saying so (the zscaler/zcc provider's documentation); compare the count with the Client "
                        "Connector portal and add any missing profile by hand (import it by its numeric id)"),
}


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
    _t("zia.locations", "zia_location_management", "Locations", "traffic_forwarding", "locations", "list_locations", gate=_P, bound=True),
    _t("zia.static_ips", "zia_traffic_forwarding_static_ip", "Static IP addresses", "traffic_forwarding", "traffic_static_ip",
       "list_static_ips", gate=_P, name="ip_address", bound=True),
    _t("zia.gre_tunnels", "zia_traffic_forwarding_gre_tunnel", "GRE tunnels", "traffic_forwarding", "gre_tunnel", "list_gre_tunnels",
       gate=_P, name="source_ip", bound=True),
    _t("zia.vpn_credentials", "zia_traffic_forwarding_vpn_credentials", "VPN credentials", "traffic_forwarding", "traffic_vpn_credentials",
       "list_vpn_credentials", gate=_P, name="fqdn", secrets={"pre_shared_key": "vpn_pre_shared_keys"}, bound=True),
    _t("zia.vzen_clusters", "zia_virtual_service_edge_cluster", "Virtual Service Edge clusters", "traffic_forwarding", "vzen_clusters",
       "list_vzen_clusters", gate=_P, bound=True),
    _t("zia.vzen_nodes", "zia_virtual_service_edge_node", "Virtual Service Edge nodes", "traffic_forwarding", "vzen_nodes", "list_zen_nodes",
       gate=_P, bound=True),
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
       "list_connector_groups", gate=_ZPA, zpa_paged=True, bound=True),
    _t("zpa.service_edge_groups", "zpa_service_edge_group", "Service Edge groups", "infrastructure", "service_edge_group",
       "list_service_edge_groups", gate=_ZPA, zpa_paged=True, bound=True),
    _t("zpa.provisioning_keys", "zpa_provisioning_key", "Provisioning keys", "infrastructure", "provisioning", "list_provisioning_keys",
       gate=_ZPA, args=("connector",), extra=[("service_edge", ("service_edge",))], hook="provisioning_key", bound=True),
    _t("zpa.private_cloud_groups", "zpa_private_cloud_group", "Private cloud groups", "infrastructure", "private_cloud_group",
       "list_cloud_groups", gate=_ZPA, zpa_paged=True, bound=True),
    _t("zpa.c2c_ip_ranges", "zpa_c2c_ip_ranges", "Client-to-client IP ranges", "infrastructure", "c2c_ip_ranges", "list_ip_ranges", gate=_ZPA),
    _t("zpa.lss_configs", "zpa_lss_config_controller", "Log streaming (LSS) configurations", "infrastructure", "lss", "list_configs",
       gate=_ZPA, zpa_paged=True, hook="lss_name"),
    _t("zpa.microtenants", "zpa_microtenant_controller", "Microtenants", "infrastructure", "microtenants", "list_microtenants", gate=_ZPA,
       zpa_paged=True, bound=True),
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
    _t("ztc.ip_pool_groups", "ztc_ip_pool_groups", "IP pool groups", "objects", "ip_groups", "list_ip_groups", gate=_ZTC,
       keep=_keep_ztc_ip_pool, keep_why=_why_ztc_ip_pool),
    _t("ztc.network_services", "ztc_network_services", "Network services", "objects", "nw_service", "list_network_services", gate=_ZTC,
       keep=_custom, keep_why=_PREDEF),
    _t("ztc.network_service_groups", "ztc_network_service_groups", "Network service groups", "objects", "nw_service_groups",
       "list_network_svc_groups", gate=_ZTC, keep=_custom, keep_why=_PREDEF),
    _t("ztc.forwarding_gateways", "ztc_forwarding_gateway", "Forwarding gateways", "forwarding", "forwarding_gateways", "list_gateways",
       gate=_ZTC, keep=_keep_ztc_gateway, keep_why="a gateway type the provider's ztc_forwarding_gateway does not take (ZIA, ECSELF or PROXYCHAIN)"),
    _t("ztc.forwarding_rules", "ztc_traffic_forwarding_rule", "Traffic forwarding rules", "forwarding", "forwarding_rules", "list_rules",
       gate=_ZTC, keep=_keep_ztc_forwarding_rule, keep_why=_why_ztc_forwarding_rule),
    _t("ztc.location_templates", "ztc_location_template", "Location templates", "provisioning", "location_template",
       "list_location_templates", gate=_ZTC),
    _t("ztc.provisioning_urls", "ztc_provisioning_url", "Provisioning URLs", "provisioning", "provisioning_url", "list_provisioning_url",
       gate=_ZTC, bound=True),
    _t("ztc.public_cloud_info", "ztc_public_cloud_info", "Public cloud accounts", "provisioning", "public_cloud_info",
       "list_public_cloud_info", gate=_ZTC, bound=True),
    # ── Client Connector (zscaler/zcc) ──
    _t("zcc.trusted_networks", "zcc_trusted_network", "Trusted networks", "client_connector", "trusted_networks", "list_by_company",
       gate=("scope", "zcc"), name="network_name", hook="zcc_trusted_network"),
    _t("zcc.forwarding_profiles", "zcc_forwarding_profile", "Forwarding profiles", "client_connector", "forwarding_profile",
       "list_by_company", gate=("scope", "zcc")),
    # Settings, one record each. The SDK reads them (zscaler/zcc fail_open_policy.list_by_company,
    # devices.get_device_cleanup_info, web_privacy.get_web_privacy); the field names are the provider's
    # arguments in snake_case (zcc 0.1.2 docs/resources). The fail-open policy is imported by its own id
    # (GetFailOpenPolicyByID); device cleanup and web privacy re-read their record whatever the id.
    _t("zcc.failopen_policy", "zcc_failopen_policy", "Fail-open policy", "client_connector", "fail_open_policy", "list_by_company",
       gate=("scope", "zcc"), singleton=True, hook="zcc_flags"),
    _t("zcc.device_cleanup", "zcc_device_cleanup", "Device cleanup", "client_connector", "devices", "get_device_cleanup_info",
       gate=("scope", "zcc"), singleton=True, import_id="device_cleanup", hook="zcc_flags"),
    _t("zcc.web_privacy", "zcc_web_privacy", "Web privacy (end-user and device data collection)", "client_connector", "web_privacy",
       "get_web_privacy", gate=("scope", "zcc"), singleton=True, import_id="web_privacy", hook="zcc_flags"),
    # Read raw (no SDK call): ZCC_RAW_PATHS. Imported by numeric id (the provider's ImportState takes an id or a name).
    _t("zcc.notification_templates", "zcc_notification_template", "Notification templates", "client_connector", "", None,
       gate=("scope", "zcc"), raw=ZCC_RAW_PATHS["zcc.notification_templates"]),
    _t("zcc.zia_posture", "zcc_zia_posture", "ZIA posture profiles", "client_connector", "", None,
       gate=("scope", "zcc"), hook="zcc_posture", raw=ZCC_RAW_PATHS["zcc.zia_posture"]),
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
    ("ztc", "Account groups", "zscaler-sdk-python 1.11.3 cannot read them: its account group model names a class the SDK "
     "does not have (CommonIDNameExternalID), so every read fails"),
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


_GATE_WORDS = {"zia_extras": "ZIA platform", "dlp": "DLP", "zpa": "ZPA", "ztw": "Cloud & Branch Connector", "zcc": "ZCC"}
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


OUTPUT_DIR_RE = re.compile(r"\A[a-z][a-z0-9_-]{0,39}\Z")
_SELECTOR_RE = re.compile(r"\A[A-Za-z0-9_.*?-]{1,80}\Z")


def resolve_selectors(items: Sequence[Any], what: str) -> List[str]:
    """Object type keys for a selection. Each item is a type key
    ("zia.locations"), a provider resource name ("zia_location_management")
    or a shell-style pattern over either ("zia.*", "zpa_policy_*"). An item
    that matches nothing is refused by name. Pure."""
    import fnmatch
    out: List[str] = []
    bad: List[str] = []
    for raw in items:
        sel = str(raw).strip()
        if not _SELECTOR_RE.match(sel):
            bad.append(sel[:60])
            continue
        hit = [t["key"] for t in TYPES if fnmatch.fnmatchcase(t["key"], sel) or fnmatch.fnmatchcase(t["resource"], sel)]
        if not hit:
            bad.append(sel[:60])
        out.extend(k for k in hit if k not in out)
    if bad:
        raise ExportRefused(f"Unknown object type in {what}: {', '.join(bad[:5])}.")
    return out


def normalize_options(products: Any = None, types: Any = None, exclude: Any = None, prefix: Any = "", namespace: Any = "",
                      microtenant_id: Any = "", mode: Any = "adopt", keep_rule_state: Any = False, output_dir: Any = "",
                      support_log: Any = False) -> Dict[str, Any]:
    """The export's options, checked (ExportRefused names what is wrong).
    `types` and `exclude` take type keys, provider resource names or
    patterns (resolve_selectors); `output_dir` names the folder the
    workspaces are written under (default tenant-terraform); `support_log`
    adds a masked log of the run to the zip."""
    prods = [str(p).strip().lower() for p in (products or PRODUCTS)] if isinstance(products, (list, tuple)) or products is None else None
    if prods is None or not prods or any(p not in PRODUCTS for p in prods):
        raise ExportRefused("Products must be a list of zia, zpa, ztc and zcc.")
    lists = []
    for what, v in (("types", types), ("exclude", exclude)):
        if v in (None, ""):
            lists.append([])
            continue
        if not isinstance(v, (list, tuple)) or len(v) > MAX_TYPES_ASKED:
            raise ExportRefused(f"{what} must be a list of object type keys (at most {MAX_TYPES_ASKED}).")
        lists.append(resolve_selectors(v, what))
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
    od = str(output_dir or "").strip()
    if od and not OUTPUT_DIR_RE.match(od):
        raise ExportRefused("The output folder name must start with a lowercase letter and hold only lowercase letters, digits, - and _ "
                            "(at most 40 characters).")
    md = str(mode or "adopt").strip().lower()
    if md not in MODES:
        raise ExportRefused("The mode is adopt (import this tenant's objects) or clone (new objects for another tenant).")
    return {"products": [p for p in PRODUCTS if p in prods], "types": lists[0], "exclude": lists[1], "prefix": pre,
            "namespace": ns or DEFAULT_NAMESPACE, "microtenant_id": mt, "mode": md, "keep_rule_state": bool(keep_rule_state),
            "output_dir": od or ROOT_DIR, "support_log": bool(support_log)}


def plan(scopes: Any, channels: Any, opts: Dict[str, Any], *, include_personal: bool = False,
         skip_products: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
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
        if (skip_products or {}).get(t["product"]):
            left[t["key"]] = str(skip_products[t["product"]])
            continue
        if opts.get("mode") == "clone" and t["singleton"]:
            left[t["key"]] = ("left out in clone mode: a setting exists in every tenant, so applying it would overwrite the target's own "
                              "settings; export in adopt mode to manage it")
            continue
        if opts.get("mode") == "clone" and t["bound"]:
            left[t["key"]] = ("left out in clone mode: it is bound to this tenant's own addresses, tunnels, connectors or cloud accounts; "
                              "set it up in the target tenant")
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
        skipped = sorted({str(v) for p, v in (skip_products or {}).items() if v and p in opts["products"]})
        if left and skipped and all(BY_KEY[k]["product"] in (skip_products or {}) for k in left):
            raise ExportRefused("Nothing can be exported: " + "; ".join(s[0].upper() + s[1:] for s in skipped) + ". Nothing was read.")
        raise ExportRefused(NOTHING_IN_SCOPE if not left else "Every object type in scope was left out by the export options. Nothing was read.")
    return {"read": read, "not_in_scope": nis, "left_out": left}


_POLICY_WORDS = {"url_filtering": "DLP or ZIA platform", "file_type_control": "DLP or ZIA platform", "firewall": "ZIA platform",
                 "ssl_inspection": "SSL inspection marked Zscaler", "cloud_app_control": "Cloud App Control marked Zscaler"}


def _needs(t: Dict[str, Any]) -> str:
    """The Scope page tick a type needs, in the page's words."""
    kind, val = t["gate"]
    if kind == "scope":
        return _GATE_WORDS.get(val, val)
    if kind == "any":
        return "ZIA platform or DLP"
    if kind == "policy":
        return _POLICY_WORDS.get(val, "its policy in scope")
    return f"DLP, {_CHANNEL_WORDS.get(val, val)} marked Zscaler"


def catalogue() -> Dict[str, Any]:
    """The types per product, for the page and the docs."""
    out: Dict[str, Any] = {}
    for p in PRODUCTS:
        out[p] = [{"key": t["key"], "label": t["label"], "resource": t["resource"], "personal": t["personal"],
                   "gate": t["gate"][0], "needs": _needs(t)} for t in TYPES if t["product"] == p]
    return {"products": out, "labels": PRODUCT_LABELS, "not_covered": [{"product": p, "what": w, "why": y} for p, w, y in NOT_COVERED],
            "providers": {p: {"source": f"{DEFAULT_NAMESPACE}/{p}", "version": PROVIDERS[p]["version"], "beta": bool(PROVIDERS[p].get("beta"))}
                          for p in PRODUCTS},
            "beta_note": {"zcc": ZCC_BETA_NOTE}}


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


# Provider arguments whose names look secret but hold a switch or a rating,
# never a secret (Advanced Threat Protection's cookie stealing, Malware
# Protection's password-protected archives, a risk profile's password
# strength rating, a location's cookies-and-proxy switch).
_NOT_SECRET = {"cookie_stealing_blocked", "cookie_stealing_pcap_enabled", "block_password_protected_archive_files",
               "password_strength", "cookies_and_proxy"}


def _mask(value: Any, depth: int = 0) -> Any:
    """offline_tenant.scrub's rule (every secret-named field becomes "(set)"
    or "(not set)"), except a true / false switch (never a secret) and the
    _NOT_SECRET arguments."""
    import offline_tenant as ot
    if depth > 30:
        return None
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            key = str(k)
            secretish = (ot._SECRET_KEY.search(key) or ot._PASS_SUFFIX.search(key) or ot._OTP_KEY.search(key)
                         or (isinstance(v, str) and ot._TOKEN_KEY.search(key)))
            if secretish and not isinstance(v, bool) and key not in _NOT_SECRET:
                out[key] = "(set)" if v not in (None, "", [], {}, False) else "(not set)"
            else:
                out[key] = _mask(v, depth + 1)
        return out
    if isinstance(value, list):
        return [_mask(x, depth + 1) for x in value]
    return value


def _clean(rows: Iterable[Any]) -> List[Dict[str, Any]]:
    """Rows as plain snake_case dicts with every secret-named field masked."""
    return [_mask(_deep_snake(r)) for r in rows if isinstance(r, dict)]


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


def _raw_rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str], Any]:
    """(rows, error, response) of one list call: the API's own answer for
    the page (the SDK's response.get_results()), which carries every field
    the provider takes; the SDK's models (as plain dicts) only when the
    answer is not there."""
    import pack_export
    from dlp_importer import _nx
    data, err = _nx(ret)
    resp = ret[1] if isinstance(ret, tuple) and len(ret) >= 3 else None
    if err:
        return [], str(err)[:200], resp
    getter = getattr(resp, "get_results", None)
    raw = None
    if callable(getter):
        try:
            raw = getter()
        except Exception:  # noqa: BLE001 - the models below still export
            raw = None
    items = data if isinstance(data, list) else ([] if data is None else [data])
    if isinstance(raw, list) and all(isinstance(r, dict) for r in raw) and len(raw) == len(items):
        return [dict(r) for r in raw], None, resp
    return [pack_export._plain(x) for x in items], None, resp


_ENVELOPES = ("trustedNetworkContracts", "trusted_network_contracts", "list", "records", "items")


def _unwrap(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The objects of an answer the SDK handed back as one envelope
    (Client Connector's {"trustedNetworkContracts": [...]})."""
    if len(rows) == 1 and isinstance(rows[0], dict) and "id" not in rows[0]:
        for key in _ENVELOPES:
            inner = rows[0].get(key)
            if isinstance(inner, list):
                return [dict(x) for x in inner if isinstance(x, dict)]
    return rows


def _list_all(fn: Callable[..., Any], args: Tuple[Any, ...], q: Dict[str, Any], cancel: Any, paged: bool) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every page of a list (the SDK's own paging), at most MAX_ZPA_PAGES."""
    try:
        import inspect
        takes_query = "query_params" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        takes_query = False
    if not takes_query:   # cbi_banner.list_cbi_banners() and the like take no query (and so no microtenant)
        paged, q = False, {}
    if paged:
        ret = fn(*args, query_params=dict(q, page_size="500"))
    else:
        ret = fn(*args, query_params=q) if q else fn(*args)
    rows, err, resp = _raw_rows(ret)
    if err or not paged:
        return rows, err
    pages = 0
    while resp is not None and callable(getattr(resp, "has_next", None)) and resp.has_next() and pages < MAX_ZPA_PAGES:
        if _stopped(cancel):
            break
        data, _r, perr = resp.next()
        if perr:
            return rows, str(perr)[:200]
        page = resp.get_results() if callable(getattr(resp, "get_results", None)) else data
        rows.extend(dict(x) for x in page or [] if isinstance(x, dict))
        pages += 1
    return rows, None


_RAW_ENVELOPES = ("list", "records", "items", "content", "data", "notificationTemplates", "ziaPostureProfiles", "profiles", "templates")


def _raw_list(client: Any, path: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object at one fixed Client Connector path, GET only, through
    the signed-in client's own request executor (the SDK's signing and
    gateway routing; the offline client answers it from its store).
    (rows, error). Paced like every Client Connector read."""
    import zia_rate
    svc = None
    try:
        svc = getattr(client, "zcc", None)
    except Exception:  # noqa: BLE001 - a client without Client Connector
        svc = None
    ex = getattr(svc, "_request_executor", None) if svc is not None else None
    if ex is None:
        ex = getattr(client, "_request_executor", None)
    if ex is None:
        return [], "this sign-in has no Client Connector API (it needs a OneAPI API client)"
    zia_rate.wait("GET", "", what="Client Connector read")
    try:
        made = ex.create_request("GET", path, {}, {}, params={})
        req, err = (made[0], made[1]) if isinstance(made, tuple) and len(made) >= 2 else (made, None)
        if err:
            return [], one_line(str(err))[:200]
        got = ex.execute(req)
        resp, err = (got[0], got[1]) if isinstance(got, tuple) and len(got) >= 2 else (got, None)
        if err:
            return [], one_line(str(err))[:200]
        data = resp.get_body() if resp is not None and hasattr(resp, "get_body") else resp
        if isinstance(data, (bytes, str)):
            data = json.loads(data) if data else []
    except Exception as e:  # noqa: BLE001 - one failed read is reported, never raised
        return [], f"{type(e).__name__}: {one_line(str(e))[:180]}"
    if isinstance(data, dict):
        inner = next((data[k] for k in _RAW_ENVELOPES if isinstance(data.get(k), list)), None)
        data = inner if inner is not None else ([data] if "id" in data else [])
    if not isinstance(data, list):
        return [], "the answer was not a list"
    return [dict(x) for x in data if isinstance(x, dict)], None


def _nx_data(ret: Any) -> Any:
    from dlp_importer import _nx
    return _nx(ret)[0]


def read_type(client: Any, t: Dict[str, Any], *, cancel: Any = None, microtenant_id: str = "") -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of one type: (rows, error). Read-only."""
    import pack_export
    import pack_channels as pc
    if t.get("raw"):
        return _raw_list(client, t["raw"])
    svc, err = _service(client, t)
    if err:
        return [], err
    fn = getattr(svc, t["method"])
    q = {"microtenant_id": microtenant_id} if (microtenant_id and t["product"] == "zpa") else {}
    if t["singleton"]:
        ret = fn()
        if t["method"].startswith("list") and isinstance(_nx_data(ret), list):   # a list call that answers the one record (Client Connector's fail-open policy)
            got, err, _resp = _raw_rows(ret)
            got = _unwrap(got)
            return got[:1], err
        row, err = pack_export.one_row(ret)
        if t["hook"] == "security_lists" and not err:
            deny, err = pack_export.one_row(svc.get_blacklist())
            row = dict(row or {}, **(deny or {}))
        return ([row] if row else []), err
    if t["per_type"]:
        rows: List[Dict[str, Any]] = []
        for rt in pc.CLOUD_APP_TYPES:
            if _stopped(cancel):
                break
            got, err, _resp = _raw_rows(fn(rt))
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
        got, err = _list_all(fn, args, q, cancel, t["zpa_paged"])
        got = _unwrap(got)
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
    out: Dict[str, Any] = {"types": {}, "unread": {}, "stopped": False, "refused": None, "log": []}

    def say(msg: str) -> None:   # progress goes to the caller and, bounded, to the snapshot (the support log)
        if len(out["log"]) < MAX_LOG_LINES:
            out["log"].append(one_line(msg)[:300])
        if log:
            log(msg)
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


def _csv(v: Any) -> List[str]:
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v or "").split(",") if x.strip()]


_ZCC_TN = {"dns_server_ips": "dns_servers", "dns_search_domains": "dns_search_domains", "resolved_ips_for_hostname": "resolved_ips_for_hostname",
           "trusted_dhcp_servers_ips": "trusted_dhcp_servers", "trusted_egress_ips": "trusted_egress_ips",
           "trusted_gateway_ips": "trusted_gateways", "trusted_subnet_ips": "trusted_subnets"}


def _hook_zcc_trusted_network(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """A Client Connector trusted network as the zcc provider takes it: the
    public API's v1 answer (networkName, comma-separated addresses,
    conditionType 0 / 1) in the provider's v2 form (name, lists, ALL / ANY),
    the mapping the provider itself applies (its trusted-network backend)."""
    out = dict(row)
    out["name"] = row.get("name") or row.get("network_name")
    out["hostname"] = row.get("hostname") or row.get("hostnames")
    out["ssid"] = row.get("ssid") or row.get("ssids")
    for new, old in _ZCC_TN.items():
        v = row.get(new) if not _empty(row.get(new)) else row.get(old)
        out[new] = _csv(v) if not _empty(v) else None
    ct = row.get("condition_type")
    out["condition_type"] = {"0": "ALL", "1": "ANY"}.get(str(ct), ct if isinstance(ct, str) and ct else None)
    return out


def _hook_zcc_flags(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """Client Connector settings write their switches as 0 / 1 (numbers or
    strings: device cleanup's `active` is "1"); the provider takes true /
    false (its device cleanup docs: "Mirrors the API's 0/1 integer-as-string
    flag"). Only the provider's boolean arguments are changed."""
    out = dict(row)
    for name, kind, _req, _sub in schema_of(ctx.resource) if getattr(ctx, "resource", None) else []:
        v = out.get(name)
        if kind == "b" and not isinstance(v, bool) and str(v).strip() in ("0", "1"):
            out[name] = str(v).strip() == "1"
    return out


# The zcc provider's platform names for the API's numeric platform (its helpers.PlatformIntToName).
_ZCC_PLATFORMS = {"1": "ios", "2": "android", "3": "windows", "4": "macos", "5": "linux"}


def _hook_zcc_posture(row: Dict[str, Any], ctx: "_Ctx") -> Dict[str, Any]:
    """A ZIA posture profile as the zcc provider takes it: the platform by
    name (ios, android, windows, macos, linux) where the API answers 1..5; a
    platform this app does not know is left out (the profile is then listed
    as not exported, never written with a guess)."""
    out = dict(row)
    p = str(row.get("platform") if row.get("platform") is not None else "").strip().lower()
    out["platform"] = _ZCC_PLATFORMS.get(p, p if p in _ZCC_PLATFORMS.values() else None)
    return out


HOOKS = {"zcc_flags": _hook_zcc_flags, "zcc_posture": _hook_zcc_posture, "zcc_trusted_network": _hook_zcc_trusted_network, "engine_expression": _hook_engine_expression, "policy_v2": _hook_policy_v2, "provisioning_key": _hook_provisioning_key,
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

    def __init__(self, product: str, prefix: str, mode: str = "adopt", keep_rule_state: bool = False):
        self.product = product
        self.prefix = prefix
        self.clone = mode == "clone"
        self.keep_rule_state = keep_rule_state
        self.disabled = 0
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
    norm: Optional[Dict[str, str]] = None
    for attr, kind, req, sub in schema:
        v = row.get(attr)
        if v is None:
            # The API's camelCase does not always snake back to the provider's
            # name (zscalerClientConnector1AndPac..., enableLWFDriver): match
            # on the letters and digits alone.
            if norm is None:
                norm = {str(k).replace("_", ""): k for k in row}
            alt = norm.get(attr.replace("_", ""))
            v = row.get(alt) if alt is not None else None
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
            if val is None and kind == "b" and req and _bool(v) is False:
                val = "false"   # a required switch that is off is still written
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
        elif kind == "obj":   # one nested object attribute: `name = { .. }`
            if not isinstance(v, dict):
                ctx.drop(t["resource"], attr)
                continue
            inner, miss = _render_attrs(sub, v, ctx, t, label, indent + 1, nested=True)
            if miss:
                ctx.drop(t["resource"], attr)
                if req:
                    missing.append(attr)
                continue
            if inner:
                lines.append(f"{pad}{attr} = {{\n" + "\n".join(inner) + f"\n{pad}}}")
        elif kind == "objs":   # a list of nested objects: `name = [{ .. }, ..]`
            items = v if isinstance(v, list) else [v]
            elems = []
            for x in items:
                if not isinstance(x, dict):
                    continue
                inner, miss = _render_attrs(sub, x, ctx, t, label, indent + 2, nested=True)
                if miss:
                    ctx.drop(t["resource"], attr)
                    continue
                elems.append(f"{pad}  {{\n" + "\n".join(inner) + f"\n{pad}  }},")
            if elems:
                lines.append(f"{pad}{attr} = [\n" + "\n".join(elems) + f"\n{pad}]")
            elif req:
                missing.append(attr)
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
    if t["singleton"] and not _rid(row):   # a one-record setting without an id: the provider's sentinel (its resource name)
        return t["resource"].split("_", 1)[1]
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
        ctx.resource = t["resource"]
        row = hook(row, ctx)
    for attr, alt in RENAMES.get(t["resource"], {}).items():
        if _empty(row.get(attr)) and not _empty(row.get(alt)):
            row = dict(row, **{attr: row[alt]})
    if ctx.clone and not ctx.keep_rule_state:
        # A clone creates new objects in another tenant: every rule arrives
        # DISABLED and every ZPA application segment disabled (a ZPA access
        # rule then grants nothing until someone enables its segments).
        attrs = {a for a, _k, _r, _s in schema_of(t["resource"])}
        if "state" in attrs and t["key"].endswith("_rules"):
            row = dict(row, state=_Raw('"DISABLED"'))
            ctx.disabled += 1
        elif "enabled" in attrs and t["resource"].startswith("zpa_application_segment"):
            row = dict(row, enabled=_Raw("false"))
            ctx.disabled += 1
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
               "isolation": "isolation.tf", "provisioning": "provisioning.tf", "client_connector": "client_connector.tf"}

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
    pin = ("the provider is a beta (pre-releases only), pinned exactly: Terraform selects a pre-release only by an exact version"
           if PROVIDERS[product].get("beta") else "the provider pinned to a minor line")
    return (f"{GENERATED_MARK}. Terraform {TERRAFORM_VERSION} for import blocks; {pin}.\n\n"
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


_USE_ADOPT = ("## Adopt the tenant without recreating anything\n\n```bash\nterraform init\n"
              "terraform plan -out=tfplan   # imports every object below; review any change it proposes\nterraform apply tfplan\n```\n\n"
              "`imports.tf` holds one `import` block per resource (Terraform 1.5 or later), with the object's tenant id, so the first apply "
              "brings the tenant's objects into state instead of creating new ones. Every object keeps the state the tenant gave it "
              "(an enabled rule stays enabled): adopting changes nothing for users. Values the provider fills in on its own (defaults, "
              "computed ids) may show as an in-place update on the first plan; read it before you apply.\n\n")
_USE_CLONE = ("## Build these objects in another tenant\n\n```bash\nterraform init\n"
              "terraform plan -out=tfplan   # creates every object below in the tenant the credentials name\nterraform apply tfplan\n```\n\n"
              "Clone mode: there are no import blocks, so `apply` creates new objects. {n} rule(s) and application segment(s) were written "
              "DISABLED so nothing changes for the target's users until someone enables them in the portal"
              "{keep}. ZPA policy rules have no on/off switch in the provider: they reach only segments, which arrive disabled. "
              "Settings and objects bound to this tenant (locations, tunnels, connectors, cloud accounts) are left out.\n\n")


def _incomplete_md(rows: List[Dict[str, Any]], with_product: bool = False) -> str:
    """The "May be incomplete" README section (empty when nothing is)."""
    if not rows:
        return ""
    head = "| Product | What | Why |\n|---|---|---|\n" if with_product else "| What | Why |\n|---|---|\n"
    body = "".join((f"| {PRODUCT_LABELS.get(x['product'], '')} " if with_product else "")
                   + f"| {md_safe.text(x['what'])} | {md_safe.text(x['why'])} |\n" for x in rows)
    return ("## May be incomplete\n\nThe API answers these lists in a way that can leave objects out without saying so: "
            "what was read is exported, but do not treat the list as the whole tenant.\n\n" + head + body + "\n")


def _readme_product(product: str, counts: Dict[str, int], ctx: _Ctx, not_exported: List[Dict[str, str]], namespace: str,
                    tenant_label: str, incomplete: Optional[List[Dict[str, Any]]] = None) -> str:
    rows = "".join(f"| `{res}` | {n} |\n" for res, n in sorted(counts.items()))
    nx = "".join(f"| {md_safe.text(x['what'])} | {md_safe.text(x['why'])} |\n" for x in not_exported) or "| (nothing) | |\n"
    for res, attrs in sorted(ctx.dropped.items()):
        for attr, n in sorted(attrs.items()):
            nx += (f"| `{res}.{attr}` on {n} object{'s' if n != 1 else ''} | the tenant's value is not in the form the provider takes, "
                   "or is a secret: left out, so Terraform does not manage it |\n")
    secrets = "".join(f"| `{v}` | {md_safe.text(_SECRET_WORDS.get(v, ''))} |\n" for v in sorted(ctx.secret_vars))
    beta = (f"> **Beta provider.** {ZCC_BETA_NOTE} It signs in with a ZIdentity OneAPI client only (not the classic Client Connector "
            "API keys), and OneAPI is not offered on zscalergov or zscalerten.\n\n") if PROVIDERS[product].get("beta") else ""
    return (f"# {PRODUCT_LABELS[product]} as Terraform{' (beta provider)' if beta else ''}\n\n"
            f"Exported by Zscaler Made Easy from {md_safe.text(tenant_label or 'the tenant')}, read-only, for the "
            f"[`{namespace}/{product}`]({PROVIDERS[product]['docs']}) provider ({PROVIDERS[product]['version']}).\n\n" + beta
            + (_USE_CLONE.format(n=ctx.disabled, keep=" (Keep each rule's state was ticked: rules keep the source tenant's state)"
                                 if ctx.keep_rule_state else "") if ctx.clone else _USE_ADOPT)
            + "## What is in this workspace\n\n| Resource type | Objects |\n|---|---|\n" + (rows or "| (none) | 0 |\n") + "\n"
            f"References: {ctx.refs['resource']} by Terraform address, {ctx.refs['data']} by a lookup by name (`datasource.tf`), "
            f"{ctx.refs['id']} by tenant id (the object is not exported and has no lookup, or is a user).\n\n"
            + _incomplete_md(incomplete or [])
            + "## Not exported\n\n| What | Why |\n|---|---|\n" + nx + "\n"
            + ("## Secrets\n\nNo secret is in these files. Each secret the provider needs is a sensitive map variable keyed by resource label; "
               "set it in `terraform.tfvars` (git-ignored) or with `TF_VAR_...`.\n\n| Variable | Holds |\n|---|---|\n" + secrets + "\n" if secrets else "")
            + "## Verify\n\n```bash\nterraform fmt -check -recursive   # the files are written fmt-clean\nterraform validate\n```\n\n"
            "State, saved plans and `terraform.tfvars` carry tenant ids and, if you put them there, credentials: `.gitignore` keeps them out of git. "
            "Commit `.terraform.lock.hcl` after the first `terraform init`.\n")


# ---------------------------------------------------------------------------
# Static check of the written files, the validate script and the support log
# ---------------------------------------------------------------------------
_STR_RE = re.compile(r'"(?:\\.|[^"\\\n])*"')
_RES_RE = re.compile(r'^(resource|data) "([a-z0-9_]+)" "([A-Za-z0-9_-]+)" \{', re.M)
_IMPORT_RE = re.compile(r'^import \{\n  to = ([a-z0-9_]+)\.([A-Za-z0-9_-]+)\n', re.M)


def validate_files(files: Dict[str, str]) -> Dict[str, Any]:
    """A local check of the generated workspaces, done without Terraform
    (nothing is run): braces balance outside strings, no resource address is
    written twice, and every import block names a resource written in the
    same workspace. {ok, workspaces, problems}. The real `terraform
    validate` is a step the operator runs (validate.sh in the zip)."""
    problems: List[str] = []
    work: Dict[str, Dict[str, str]] = {}
    for path, text in files.items():
        if path.endswith(".tf"):
            work.setdefault(path.rsplit("/", 1)[0], {})[path] = text
    for d, fs in sorted(work.items()):
        defined: Dict[Tuple[str, str], str] = {}
        for path, text in sorted(fs.items()):
            bare = _STR_RE.sub('""', "\n".join(ln for ln in text.split("\n") if not ln.lstrip().startswith("#")))
            if bare.count("{") != bare.count("}") or bare.count("[") != bare.count("]") or bare.count("(") != bare.count(")"):
                problems.append(f"{path}: unbalanced braces or brackets")
            if '"' in bare.replace('""', ""):
                problems.append(f"{path}: an unterminated string")
            for kind, typ, lab in _RES_RE.findall(text):
                if kind == "resource":
                    if (typ, lab) in defined:
                        problems.append(f"{path}: {typ}.{lab} is written twice")
                    defined[(typ, lab)] = path
        for path, text in sorted(fs.items()):
            for typ, lab in _IMPORT_RE.findall(text):
                if (typ, lab) not in defined:
                    problems.append(f"{path}: import of {typ}.{lab}, which this workspace does not write")
    return {"ok": not problems, "workspaces": sorted(work), "problems": problems[:100]}


def _validate_sh(products: Sequence[str]) -> str:
    """A script the operator runs themselves (it is only written here)."""
    dirs = " ".join(products)
    return ("#!/usr/bin/env bash\n# Written by Zscaler Made Easy; the app never runs it. Checks every workspace without touching the tenant:\n"
            "# terraform init -backend=false downloads the provider only; validate and fmt read the files only. Nothing is planned or applied.\n"
            "set -euo pipefail\ncd \"$(dirname \"$0\")\"\n"
            f"for d in {dirs}; do\n  echo \"== $d\"\n  (cd \"$d\" && terraform init -backend=false -input=false >/dev/null "
            "&& terraform fmt -check && terraform validate)\ndone\n")


_TOKENISH = re.compile(r"\b[A-Za-z0-9_\-+/=]{24,}\b")
_KEYED = re.compile(r"(?i)\b(bearer|secret|token|password|passwd|passphrase|api[_-]?key|client[_-]?secret|authorization|psk)\b(\s*[=:]?\s*)\S+")


def mask_text(text: str) -> str:
    """A line of log with credentials and long token-like runs masked."""
    return _TOKENISH.sub("<masked>", _KEYED.sub(lambda m: f"{m.group(1)}{m.group(2)}<masked>", text))


def _support_log(snapshot: Dict[str, Any], report: Dict[str, Any], opts: Dict[str, Any]) -> str:
    """What a helper needs to see why an export looks as it does: the
    options, the progress lines, the counts per product and the types that
    could not be read. No object value from the tenant, and every line is
    masked."""
    lines = [f"{GENERATED_MARK}. Support log: progress and counts only; no object values. Share this file, never the tfvars.",
             f"generated_at: {report['generated_at']}", f"mode: {report['mode']}",
             f"products: {', '.join(opts['products'])}", f"types asked: {', '.join(opts.get('types') or []) or 'all in scope'}",
             f"types excluded: {', '.join(opts.get('exclude') or []) or 'none'}", f"prefix: {opts.get('prefix') or '(none)'}",
             f"namespace: {opts.get('namespace')}", "", "== Progress"]
    lines += [mask_text(str(m)) for m in (snapshot.get("log") or [])]
    lines += ["", "== Resources per product"]
    for p, info in sorted(report["products"].items()):
        lines.append(f"{p}: " + ", ".join(f"{r}={n}" for r, n in sorted((info.get('resources') or {}).items())))
    lines += ["", "== Not read"] + [mask_text(f"{k}: {v}") for k, v in sorted((snapshot.get("unread") or {}).items())]
    lines += ["", "== Static check", "ok" if report["validation"]["ok"] else "; ".join(report["validation"]["problems"][:20])]
    return "\n".join(lines) + "\n"


def generate(snapshot: Dict[str, Any], opts: Dict[str, Any], *, tenant_label: str = "", plan_info: Optional[Dict[str, Any]] = None,
             generated_at: Optional[str] = None) -> Tuple[Dict[str, str], Dict[str, Any]]:
    """The workspace files ({path: content}, paths under ROOT_DIR/) and the
    report (counts, references, not exported). Pure: reads nothing."""
    when = generated_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    root = opts.get("output_dir") or ROOT_DIR
    types = snapshot.get("types") or {}
    unread = snapshot.get("unread") or {}
    plan_info = plan_info or {}
    files: Dict[str, str] = {}
    report: Dict[str, Any] = {"generated_at": when, "tenant_label": tenant_label, "mode": opts.get("mode") or "adopt",
                              "rules_disabled": opts.get("mode") == "clone" and not opts.get("keep_rule_state"), "products": {}, "not_exported": [],
                              "not_covered": [{"product": p, "what": w, "why": y} for p, w, y in NOT_COVERED], "may_be_incomplete": []}
    for key, why in sorted(MAY_BE_INCOMPLETE.items()):
        if key in types and BY_KEY[key]["product"] in opts["products"]:
            n = len(types[key] or [])
            report["may_be_incomplete"].append({"product": BY_KEY[key]["product"], "type": key, "what": BY_KEY[key]["label"], "read": n,
                                                "why": f"{n} read, but the list may be incomplete: {why}"})
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
        ctx = _Ctx(product, opts.get("prefix") or "", opts.get("mode") or "adopt", bool(opts.get("keep_rule_state")))
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
                    why = t["keep_why"](row) if callable(t["keep_why"]) else t["keep_why"]
                    skipped.append({"what": f"{t['label']}: {one_line(_display_name(t, row))[:120]}", "why": why or "not exported"})
                    continue
                lab = ctx.label(t["resource"], t["resource"].split("_", 1)[1] if t["singleton"] else _display_name(t, row))
                if not t["singleton"] and _rid(row):
                    ctx.addr[(key, _rid(row))] = (t["resource"], lab)
                kept.setdefault(key, []).append((row, lab))
        # 2. objects the provider cannot take (a required argument missing) lose their address before
        #    anything is rendered, so no other resource refers to a resource that is never written:
        #    it is looked up by name or written as its id instead (a dry run on copies; rendering has side effects)
        scratch = copy.deepcopy(ctx)
        for key in keys:
            t = BY_KEY[key]
            for row, lab in kept.get(key, []):
                if render_resource(t, copy.deepcopy(row), lab, scratch)[1]:
                    ctx.addr.pop((key, _rid(row)), None)
        # 3. the resources, area by area
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
                if not ctx.clone:
                    imports.append(f"import {{\n  to = {t['resource']}.{lab}\n  id = {hcl_str(_import_id(t, row))}\n}}\n")
                counts[t["resource"]] = counts.get(t["resource"], 0) + 1
                if not t["singleton"]:
                    by_resource.setdefault(t["resource"], []).append((_display_name(t, row), lab))
        if not counts:
            report["products"][product] = {"resources": {}, "references": dict(ctx.refs), "skipped": skipped}
            continue
        base = f"{root}/{product}"
        for fname, blocks in by_area.items():
            files[f"{base}/{fname}"] = hcl_fmt(f"{GENERATED_MARK}. Read from the tenant; do not edit by hand before the first import.\n\n"
                                               + "\n".join(blocks))
        if imports:
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
                                                     opts.get("namespace") or DEFAULT_NAMESPACE, tenant_label,
                                                     [x for x in report["may_be_incomplete"] if x["product"] == product])
        report["products"][product] = {"resources": counts, "imports": len(imports), "data_sources": len(ctx.data), "disabled": ctx.disabled,
                                       "references": dict(ctx.refs), "unresolved": dict(ctx.unresolved),
                                       "secret_variables": sorted(ctx.secret_vars), "skipped": skipped,
                                       "dropped_attributes": {r: dict(v) for r, v in ctx.dropped.items()}}
    report["validation"] = validate_files(files)
    files[f"{root}/README.md"] = _readme_root(report, opts)
    files[f"{root}/validate.sh"] = _validate_sh(sorted(report["products"]))
    if opts.get("support_log"):
        files[f"{root}/support/export_log.txt"] = _support_log(snapshot, report, opts)
    files[f"{root}/export_report.json"] = json.dumps(report, indent=1, sort_keys=True) + "\n"
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
    lines.append("\n" + _incomplete_md(report.get("may_be_incomplete") or [], with_product=True).rstrip("\n") + "\n"
                 if report.get("may_be_incomplete") else "")
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
