"""Other Zscaler products, read-only: Zero Trust Branch (ZTB), External
Attack Surface Management (EASM), Business Insights (ZBI), Zero Trust
Cellular (ZCell) and Microsegmentation (ZMS).

Each product has its own Scope page key (ztb, easm, zbi, zcell, zms), off
by default, and is read only when it is ticked. What a product's lists
hold is listed in plain words, and a handful of best-practice checks turn
it into findings (each with why it matters, what to do and its source, or
"assumed" where the recommendation is this app's own reading).

How a read is sent. Every request is built by the installed Zscaler SDK's
own method (zscaler-sdk-python 1.11.3) with a capturing executor
(`sdk_request`): the SDK method fills in the HTTP method, the OneAPI path,
its query parameters (camelCased as the SDK's executor sends them) and, for
Microsegmentation, the GraphQL query and operation name. The captured
request is then sent through the app's own raw client (`cl.get`, or
`cl.post` for a GraphQL read), so the same code reads the live tenant, the
sample tenant and a saved snapshot, behind the Scope page's service guard.
Only list_* and get_* methods are used; every write method of these
packages is listed in SDK_INVENTORY as never called (tests enforce it).

What is read (SDK service.attribute.method → path):

ZTB (client.ztb)
  site.list_sites                        GET /ztb/api/v2/Site/
  template_router.list_templates         GET /ztb/api/v3/templates
  groups_router.list_groups              GET /ztb/api/v2/groups
  alarms.list_alarms                     GET /ztb/api/v2/alarm
  api_keys.list_api_keys                 GET /ztb/api/v3/api-key-auth/list   (names and dates; never the key)
  site2site_vpn.list_hubs                GET /ztb/api/v3/CloudGateway/hubs
  devices.list_operating_systems         GET /ztb/api/v3/device/operating-systems (counts per OS; no device)
  ransomware_kill.get_state              GET /ztb/api/v3/ransomware-kill/state/ (tokens dropped)
EASM (client.zeasm)
  organizations.list_organizations       GET /easm/easm-ui/v1/organizations
  findings.list_findings(org)            GET /easm/easm-ui/v1/organizations/{org}/findings
  lookalike_domains.list_lookalike_domains(org)  .../organizations/{org}/lookalike-domains
ZBI (client.zbi)
  custom_apps.list_custom_apps           GET /bi/api/v1/customapps
  report_configs.list_report_configs     GET /bi/api/v1/reports/customapps   (recipients counted, never listed)
  reports.list_reports                   GET /bi/api/v1/report/all
ZCell (client.zcell; needs the ZCell customer ID)
  customer_data_handling.get_customer_data_handling   GET /zcell/config/api/v1/customers/{id}
  customer_region_handling.list_regions               .../customers/{id}/regions
  sim_location_groups.list_sim_location_groups        .../customers/{id}/sim-location-groups (devices counted)
  anomaly_policy.list_anomaly_policy                  .../customers/{id}/anomaly-policy (last 30 days; recipients counted)
  sim_analytics.list_sim_analytics_summary            .../customers/{id}/sim/analytics/summary (counts only)
ZMS (client.zms; GraphQL POST /zms/graphql; needs the customer ID)
  agents.list_agents, agents.get_agent_connection_status_statistics,
  agents.get_agent_version_statistics, agent_groups.list_agent_groups,
  nonces.list_nonces (the provisioning key is dropped on arrival),
  policy_rules.list_policy_rules, policy_rules.list_default_policy_rules,
  resources.get_resource_protection_status, app_zones.list_app_zones,
  resource_groups.list_resource_groups

Never read: ZMS agent_groups.get_agent_group_totp_secrets and nonces.get_nonce
(they return secrets), ZTB policy comments, logs, device details and DHCP
history (personal data), ZCell SIM details and network events (ICCIDs,
IMSIs, locations), EASM finding evidence and scan output.

Never output: a key, secret, token, password, activation code, QR code,
WireGuard key or provisioning key value (normalizers copy only listed
fields and `scrub` drops anything secret-shaped again), the people a report
or an alert goes to (counted), a device or a SIM (counted).

Assumed (not answerable from the SDK alone, marked in each finding): the
wire field names of list rows where the SDK model is the only evidence (both
the SDK's camelCase and snake_case spellings are read), the status words of
ZTB sites and alarms, the ZMS customer ID being the ZPA customer ID when no
other is given, and the thresholds this app uses (365-day key age, 80%
protected resources, 20% idle SIMs).
"""
from __future__ import annotations

import re
import threading
import time
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

PRODUCT = "Zscaler Made Easy"
SEVERITIES = ("high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
MAX_ROWS = 500           # rows kept per list (one page of at most this many is read)
MAX_ORGS = 10            # EASM organizations read
ANOMALY_DAYS = 30        # ZCell anomaly policy window
KEY_MAX_AGE_DAYS = 365   # assumed threshold: rotate ZTB API keys yearly
PROTECTED_MIN = 80.0     # assumed threshold: share of ZMS resources protected
IDLE_SIM_MAX = 20.0      # assumed threshold: share of inactive SIMs
_TEXT_MAX = 200

# ── the five products ──────────────────────────────────────────────────
PRODUCTS: "OrderedDict[str, Dict[str, Any]]" = OrderedDict([
    ("ztb", {"label": "Zero Trust Branch", "short": "ZTB", "section": "ZTB — Zero Trust Branch",
             "what": ("Zero Trust Branch connects branch offices and factories to the Zero Trust Exchange without a firewall or "
                      "site-to-site VPN mesh: each site's gateway sends traffic to Zscaler and isolates the devices on the LAN "
                      "from each other."),
             "needs": "", "license": "Zero Trust Branch (Zero Trust SD-WAN) subscription"}),
    ("easm", {"label": "External attack surface (EASM)", "short": "EASM", "section": "EASM — External attack surface",
              "what": ("External Attack Surface Management scans what the organization exposes on the internet (servers, "
                       "domains, certificates, open services) and lists the weaknesses found and the lookalike domains "
                       "registered to imitate the brand."),
              "needs": "", "license": "Zscaler External Attack Surface Management subscription"}),
    ("zbi", {"label": "Business Insights", "short": "ZBI", "section": "ZBI — Business Insights",
             "what": ("Business Insights turns traffic into business reports: which SaaS applications are used and how much, "
                      "office utilisation and custom applications the organization defines by signature."),
             "needs": "", "license": "Zscaler Business Insights subscription"}),
    ("zcell", {"label": "Zero Trust Cellular", "short": "ZCell", "section": "ZCell — Zero Trust Cellular",
               "what": ("Zero Trust Cellular puts SIM-connected devices (IoT, OT, mobile) behind the Zero Trust Exchange: "
                        "their cellular traffic goes through Zscaler, and anomaly policies watch where and how SIMs are used."),
               "needs": "zcell", "license": "Zscaler Zero Trust Cellular subscription"}),
    ("zms", {"label": "Microsegmentation", "short": "ZMS", "section": "ZMS — Microsegmentation",
             "what": ("Microsegmentation places an agent on servers and workloads and allows only the traffic between them "
                      "that a policy rule names, so an attacker on one server cannot move freely to the rest."),
             "needs": "zms", "license": "Zscaler Microsegmentation (Workload Segmentation) subscription"}),
])
SCOPE_KEYS = tuple(PRODUCTS)
SCOPE_LABELS = {k: v["label"] for k, v in PRODUCTS.items()}

NOTHING_IN_SCOPE = ("No other Zscaler product is in scope: on the Scope page tick Zero Trust Branch, External attack surface "
                    "(EASM), Business Insights, Zero Trust Cellular or Microsegmentation, then read again. Nothing was read.")
STOPPED_REASON = ("You clicked Stop before the read finished, so it was abandoned: nothing more was read from the tenant "
                  "and no partial result is shown.")
NEEDS_ONEAPI = ("These products are reached only through a ZIdentity (OneAPI) API client; the classic ZIA sign-in reaches ZIA only. "
                "Nothing was read for them.")
NEEDS_ZCELL_ID = ("Zero Trust Cellular is ticked, but no ZCell customer ID was given: every ZCell API path carries it "
                  "(the ZCell admin portal shows it). Give it on this page and read again.")
NEEDS_ZMS_ID = ("Microsegmentation is ticked, but no customer ID was given: every Microsegmentation query carries it. "
                "Give the ZPA customer ID on Connect to the tenant, or the Microsegmentation customer ID on this page.")
NOT_LICENSED = ("N/A — not licensed or not in use: the API answered that {what} is not available on this tenant "
                "(HTTP {code}). Nothing to fix if the customer does not own it; otherwise check the subscription with Zscaler.")

ASSUMPTIONS = [
    "Every request is built by the installed Zscaler SDK's own list or get method; the fields of a list row come from the SDK's "
    "model of that row, and both its camelCase and snake_case spellings are read (assumed: the API sends one of them).",
    "The Microsegmentation customer ID is assumed to be the ZPA customer ID when no other is given on this page.",
    "ZTB site and alarm status words (for example 'online', 'acknowledged') are assumed from the SDK's field names; a status "
    "this app does not recognise is shown as it is and not judged.",
    f"Thresholds are this app's own: API keys older than {KEY_MAX_AGE_DAYS} days, fewer than {PROTECTED_MIN:.0f}% of "
    f"Microsegmentation resources protected, more than {IDLE_SIM_MAX:.0f}% of SIMs inactive.",
    "The EASM remediation windows (critical 15 days, high 30 days) follow CISA Binding Operational Directive 19-02 for "
    "internet-facing systems; the customer's own policy may be stricter.",
]

GLOSSARY = [
    ("Zero Trust Branch (ZTB)", "A gateway at each branch that sends the site's traffic to Zscaler and keeps LAN devices apart, "
                                "replacing the branch firewall and the VPN mesh."),
    ("Site", "One branch, factory or office with a ZTB gateway (or a pair for high availability)."),
    ("Template", "A saved ZTB site configuration (DNS, DHCP, NAT, deployment type) applied to many sites so they stay alike."),
    ("Hub", "A ZTB cloud gateway that sites connect to for site-to-site traffic."),
    ("Ransomware kill switch", "A ZTB control that cuts lateral traffic inside a site at once when ransomware is suspected."),
    ("Alarm", "A ZTB health or security event for a site or gateway that waits for someone to acknowledge it."),
    ("EASM finding", "A weakness EASM found on an internet-facing asset (an outdated server, an exposed service, an expiring "
                     "certificate), with a risk level."),
    ("Lookalike domain", "A domain registered to look like the organization's own (typos, swapped letters) and used for phishing."),
    ("Business Insights custom app", "An application the organization defines by its signatures (domains, URLs) so Business "
                                     "Insights can count its use."),
    ("SIM", "The subscriber identity module in a cellular device; Zero Trust Cellular routes its traffic through Zscaler."),
    ("Anomaly policy", "A Zero Trust Cellular rule that raises an alert when a SIM leaves a geofence or behaves unusually."),
    ("SIM location group", "A geofence (centre and radius) with the SIMs tracked in it."),
    ("Microsegmentation agent", "Software on a server or workload that enforces which connections it may make and accept."),
    ("Agent group", "A set of Microsegmentation agents sharing upgrade, tamper protection and policy settings."),
    ("Provisioning key (nonce)", "The key a new agent uses to enrol; this page shows its name and usage, never the key."),
    ("Default policy rule", "What Microsegmentation does with traffic no rule names; zero trust wants it to deny."),
    ("Protected resource", "A server or workload whose traffic Microsegmentation policy enforces."),
]

# ── the SDK inventory: every method of the five packages ───────────────
# (attribute.method, verb, used here). Writes are never called; reads not
# used say why. Verified against zscaler-sdk-python 1.11.3 (tests compare
# this list with the installed SDK).
_R, _N, _W = "read here", "read not used", "write: never called"
SDK_INVENTORY: Dict[str, List[Tuple[str, str, str]]] = {
    "ztb": [
        ("alarms.list_alarms", "GET", _R), ("alarms.get_alarm", "GET", _N), ("alarms.create_alarm", "POST", _W),
        ("alarms.update_alarm_patch", "PATCH", _W), ("alarms.update_alarm_put", "PUT", _W), ("alarms.delete_alarm", "DELETE", _W),
        ("alarms.bulk_acknowledge", "PATCH", _W), ("alarms.bulk_acknowledge_all", "PATCH", _W), ("alarms.bulk_ignore", "DELETE", _W),
        ("alarms.bulk_ignore_all", "DELETE", _W),
        ("api_keys.list_api_keys", "GET", _R), ("api_keys.create_api_key", "POST", _W), ("api_keys.revoke_api_key", "PUT", _W),
        ("app_connector_config.get_app_connector_config", "GET", _N), ("app_connector_config.create_app_connector_config", "POST", _W),
        ("app_connector_config.delete_app_connector", "DELETE", _W),
        ("devices.list_active_devices", "GET", _N), ("devices.list_devices_by_category", "GET", _N), ("devices.get_device_tags", "GET", _N),
        ("devices.get_group_by_list", "GET", _N), ("devices.list_operating_systems", "GET", _R), ("devices.get_dhcp_history", "GET", _N),
        ("devices.get_device_details_v3", "GET", _N), ("devices.get_filter_values", "GET", _N), ("devices.list_devices_group_by", "GET", _N),
        ("devices.get_device_details_v2", "GET", _N),
        ("groups_router.list_groups", "GET", _R), ("groups_router.get_group", "GET", _N), ("groups_router.create_group", "POST", _W),
        ("groups_router.update_group_patch", "PATCH", _W), ("groups_router.update_group_put", "PUT", _W),
        ("groups_router.delete_group", "DELETE", _W),
        ("logs.get_visibility_chart", "GET", _N),
        ("policy_comments.list_comments", "GET", _N), ("policy_comments.create_comment", "POST", _W),
        ("policy_comments.update_comment", "PUT", _W), ("policy_comments.delete_comment", "DELETE", _W),
        ("ransomware_kill.get_email_template", "GET", _N), ("ransomware_kill.save_email_template", "POST", _W),
        ("ransomware_kill.get_state", "GET", _R), ("ransomware_kill.update_state", "PUT", _W),
        ("site.list_sites", "GET", _R), ("site.get_site_by_id", "GET", _N), ("site.get_site_by_name", "GET", _N),
        ("site.create_site", "POST", _W), ("site.update_site", "PUT", _W), ("site.delete_site", "DELETE", _W), ("site.get_md5", "GET", _N),
        ("site.list_app_segments", "GET", _N), ("site.update_app_segments", "POST", _W), ("site.create_cloud_site", "POST", _W),
        ("site.get_hostname_config", "GET", _N), ("site.list_site_names", "GET", _N), ("site.get_site_overview", "GET", _N),
        ("site.update_static_ips_mapping", "PUT", _W), ("site.update_site_template", "PUT", _W),
        ("site2site_vpn.list_hubs", "GET", _R), ("site2site_vpn.get_s2s_connections", "GET", _N),
        ("site2site_vpn.create_s2s_connections", "POST", _W), ("site2site_vpn.update_s2s_connections", "PUT", _W),
        ("site2site_vpn.delete_s2s_connections", "DELETE", _W), ("site2site_vpn.get_s2s_gateways", "GET", _N),
        ("site2site_vpn.list_s2s_hubs", "GET", _N),
        ("template_router.list_templates", "GET", _R), ("template_router.get_template", "GET", _N),
        ("template_router.create_template", "POST", _W), ("template_router.update_template_put", "PUT", _W),
        ("template_router.delete_template", "DELETE", _W), ("template_router.list_template_interfaces", "GET", _N),
        ("template_router.list_template_names", "GET", _N),
    ],
    "easm": [
        ("organizations.list_organizations", "GET", _R), ("findings.list_findings", "GET", _R),
        ("findings.get_finding_details", "GET", _N), ("findings.get_finding_evidence", "GET", _N),
        ("findings.get_finding_scan_output", "GET", _N), ("lookalike_domains.list_lookalike_domains", "GET", _R),
        ("lookalike_domains.get_lookalike_domain", "GET", _N),
    ],
    "zbi": [
        ("custom_apps.list_custom_apps", "GET", _R), ("custom_apps.get_custom_app", "GET", _N), ("custom_apps.create_custom_app", "POST", _W),
        ("custom_apps.update_custom_app", "PUT", _W), ("custom_apps.delete_custom_app", "DELETE", _W),
        ("report_configs.list_report_configs", "GET", _R), ("report_configs.get_report_config", "GET", _N),
        ("report_configs.create_report_config", "POST", _W), ("report_configs.update_report_config", "PUT", _W),
        ("report_configs.delete_report_config", "DELETE", _W),
        ("reports.list_reports", "GET", _R), ("reports.download_report", "POST", _N),
    ],
    "zcell": [
        ("anomaly_policy.list_anomaly_policy", "GET", _R), ("anomaly_policy.create_anomaly_policy", "POST", _W),
        ("anomaly_policy.update_anomaly_policy", "PATCH", _W), ("anomaly_policy.delete_anomaly_policy", "DELETE", _W),
        ("anomaly_policy.list_anomaly_policy_logs", "GET", _N), ("anomaly_policy.update_anomaly_policy_status", "PATCH", _W),
        ("anomaly_policy.list_anomaly_policy_violations", "GET", _N), ("anomaly_policy.get_anomaly_policy_violations", "GET", _N),
        ("audit_data_handling.list_audit_customers_search", "POST", _N), ("audit_data_handling.list_audit_metadata", "GET", _N),
        ("customer_data_handling.get_customer_data_handling", "GET", _R), ("customer_data_handling.update_customer_data_handling", "PUT", _W),
        ("customer_region_handling.list_regions", "GET", _R), ("customer_region_handling.update_regions", "PUT", _W),
        ("customer_region_handling.list_regions_operational_status", "GET", _N),
        ("network_events.list_network_events_search", "POST", _N),
        ("sim_analytics.list_sim_analytics_map", "POST", _N), ("sim_analytics.list_sim_analytics_summary", "GET", _R),
        ("sim_analytics.list_sim_analytics_usage_countries", "GET", _N), ("sim_analytics.list_sim_analytics_usage_day", "GET", _N),
        ("sim_analytics.list_sim_analytics_usage_sims", "GET", _N),
        ("sim_handling.list_sims_details", "GET", _N), ("sim_handling.create_sims_download", "POST", _N),
        ("sim_handling.update_sims_assign_tag", "PATCH", _W), ("sim_handling.update_sims_lock", "PATCH", _W),
        ("sim_handling.create_sims_search", "POST", _N), ("sim_handling.update_sims_status", "PATCH", _W),
        ("sim_handling.update_sims_assign", "PATCH", _W), ("sim_handling.update_sims_state", "PATCH", _W),
        ("sim_location_groups.list_sim_location_groups", "GET", _R), ("sim_location_groups.get_sim_location_group", "GET", _N),
        ("sim_location_groups.add_location_group", "POST", _W), ("sim_location_groups.update_sim_location_group", "PUT", _W),
        ("sim_location_groups.delete_sim_location_group", "DELETE", _W),
        ("tag_handling.list_tag", "GET", _N), ("tag_handling.create_tag", "POST", _W),
    ],
    "zms": [
        ("agents.list_agents", "POST", _R), ("agents.get_agent_connection_status_statistics", "POST", _R),
        ("agents.get_agent_version_statistics", "POST", _R), ("agent_groups.list_agent_groups", "POST", _R),
        ("agent_groups.get_agent_group_totp_secrets", "POST", "secret: never called"),
        ("app_catalog.list_app_catalog", "POST", _N), ("app_zones.list_app_zones", "POST", _R),
        ("nonces.list_nonces", "POST", _R), ("nonces.get_nonce", "POST", "secret: never called"),
        ("policy_rules.list_policy_rules", "POST", _R), ("policy_rules.list_default_policy_rules", "POST", _R),
        ("resource_groups.list_resource_groups", "POST", _R), ("resource_groups.get_resource_group_members", "POST", _N),
        ("resource_groups.get_resource_group_protection_status", "POST", _N),
        ("resources.list_resources", "POST", _N), ("resources.get_resource_protection_status", "POST", _R),
        ("resources.get_metadata", "POST", _N),
        ("tags.list_tag_namespaces", "POST", _N), ("tags.list_tag_keys", "POST", _N), ("tags.list_tag_values", "POST", _N),
    ],
}
SDK_PACKAGE = {"ztb": "ztb", "easm": "zeasm", "zbi": "zbi", "zcell": "zcell", "zms": "zms"}
# The GraphQL operations a Microsegmentation read may send (all are queries).
ZMS_OPERATIONS = ("ListAgents", "AgentConnectionStatusStats", "AgentVersionStats", "ListAgentGroups", "ListNonces",
                  "ListPolicyRules", "ListDefaultPolicyRules", "ResourceProtectionStatus", "ListAppZones", "ListResourceGroups")


class Stopped(RuntimeError):
    """The operator clicked Stop: nothing more is read."""


# ── building a request with the SDK's own method ───────────────────────
class _Captured(Exception):
    """Raised (as the executor's error) to stop the SDK method once its request is built."""


class _Capture:
    """The SDK RequestExecutor contract, enough for create_request: it keeps
    the request the SDK method builds and answers with an error, so the SDK
    never sends anything. No network code."""

    use_legacy_client = False

    def __init__(self) -> None:
        self.request: Optional[Dict[str, Any]] = None

    def get_request_executor(self) -> "_Capture":   # ZTBService(client) asks its client for the executor
        return self

    def create_request(self, method: str, endpoint: str, body: Any = None, headers: Any = None, params: Any = None, **_: Any):
        from zscaler.helpers import convert_keys_to_camel_case
        q = dict(params or {})
        # As the SDK's executor sends them (_prepare_params): non-ZPA query keys camelCased.
        q = convert_keys_to_camel_case(q) if q else {}
        self.request = {"method": str(method or "GET").upper(), "url": str(endpoint or ""), "params": q,
                        "body": body if isinstance(body, dict) and body else None}
        return None, _Captured("captured")


def _service(product: str, cap: _Capture, ids: Dict[str, str]) -> Any:
    if product == "ztb":
        from zscaler.ztb.ztb_service import ZTBService
        return ZTBService(cap)
    if product == "easm":
        from zscaler.zeasm.zeasm_service import ZEASMService
        return ZEASMService(cap)
    if product == "zbi":
        from zscaler.zbi.zbi_service import ZBIService
        return ZBIService(cap)
    if product == "zcell":
        from zscaler.zcell.zcell_service import ZCellService
        return ZCellService(cap, {"client": {"zcellCustomerId": ids.get("zcell") or ""}})
    if product == "zms":
        from zscaler.zms.zms_service import ZMSService
        return ZMSService(cap)
    raise ValueError(f"unknown product {product!r}")


def sdk_request(product: str, call: Callable[[Any], Any], ids: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """The request the SDK method `call(service)` would send: {method, url,
    params, body}. Nothing is sent."""
    cap = _Capture()
    call(_service(product, cap, ids or {}))
    if cap.request is None:
        raise RuntimeError("the SDK method built no request")
    return cap.request


# ── the reads ──────────────────────────────────────────────────────────
# (key, plain label, SDK method name for the inventory, call(service, ids)).
def _now_epoch() -> int:
    return int(time.time())


READS: Dict[str, List[Tuple[str, str, str, Callable[[Any, Dict[str, str]], Any]]]] = {
    "ztb": [
        ("sites", "Sites", "site.list_sites", lambda s, i: s.site.list_sites(query_params={"page": 1, "limit": MAX_ROWS})),
        ("templates", "Site templates", "template_router.list_templates",
         lambda s, i: s.template_router.list_templates(query_params={"page": 1, "size": MAX_ROWS})),
        ("groups", "Groups", "groups_router.list_groups", lambda s, i: s.groups_router.list_groups(query_params={"page": 1, "size": MAX_ROWS})),
        ("alarms", "Alarms", "alarms.list_alarms", lambda s, i: s.alarms.list_alarms(query_params={"page": 1, "size": MAX_ROWS})),
        ("api_keys", "API keys", "api_keys.list_api_keys", lambda s, i: s.api_keys.list_api_keys(query_params={"page": 1, "limit": MAX_ROWS})),
        ("hubs", "Cloud gateway hubs", "site2site_vpn.list_hubs", lambda s, i: s.site2site_vpn.list_hubs()),
        ("operating_systems", "Device operating systems", "devices.list_operating_systems", lambda s, i: s.devices.list_operating_systems()),
        ("ransomware", "Ransomware kill switch", "ransomware_kill.get_state", lambda s, i: s.ransomware_kill.get_state()),
    ],
    "easm": [
        ("organizations", "Organizations", "organizations.list_organizations", lambda s, i: s.organizations.list_organizations()),
        ("findings", "Findings", "findings.list_findings", lambda s, i: s.findings.list_findings(org_id=i["org"])),
        ("lookalikes", "Lookalike domains", "lookalike_domains.list_lookalike_domains",
         lambda s, i: s.lookalike_domains.list_lookalike_domains(org_id=i["org"])),
    ],
    "zbi": [
        ("custom_apps", "Custom applications", "custom_apps.list_custom_apps", lambda s, i: s.custom_apps.list_custom_apps()),
        ("report_configs", "Scheduled reports", "report_configs.list_report_configs",
         lambda s, i: s.report_configs.list_report_configs(report_type="customapps")),
        ("reports", "Generated reports", "reports.list_reports", lambda s, i: s.reports.list_reports()),
    ],
    "zcell": [
        ("customer", "Customer settings", "customer_data_handling.get_customer_data_handling",
         lambda s, i: s.customer_data_handling.get_customer_data_handling(id=i["zcell"])),
        ("regions", "Regions", "customer_region_handling.list_regions", lambda s, i: s.customer_region_handling.list_regions(id=i["zcell"])),
        ("location_groups", "SIM location groups", "sim_location_groups.list_sim_location_groups",
         lambda s, i: s.sim_location_groups.list_sim_location_groups(id=i["zcell"], query_params={"page": 0, "size": 100})),
        ("anomaly_policies", "Anomaly policies", "anomaly_policy.list_anomaly_policy",
         lambda s, i: s.anomaly_policy.list_anomaly_policy(id=i["zcell"], start_date_time=_now_epoch() - ANOMALY_DAYS * 86400,
                                                          end_date_time=_now_epoch(), query_params={"page": 0, "size": 100})),
        ("sim_summary", "SIM summary", "sim_analytics.list_sim_analytics_summary",
         lambda s, i: s.sim_analytics.list_sim_analytics_summary(id=i["zcell"])),
    ],
    "zms": [
        ("agents", "Agents", "agents.list_agents", lambda s, i: s.agents.list_agents(customer_id=i["zms"], page=1, page_size=MAX_ROWS)),
        ("connection_stats", "Agent connection statistics", "agents.get_agent_connection_status_statistics",
         lambda s, i: s.agents.get_agent_connection_status_statistics(customer_id=i["zms"])),
        ("version_stats", "Agent version statistics", "agents.get_agent_version_statistics",
         lambda s, i: s.agents.get_agent_version_statistics(customer_id=i["zms"])),
        ("agent_groups", "Agent groups", "agent_groups.list_agent_groups",
         lambda s, i: s.agent_groups.list_agent_groups(customer_id=i["zms"], page=1, page_size=MAX_ROWS)),
        ("nonces", "Provisioning keys", "nonces.list_nonces", lambda s, i: s.nonces.list_nonces(customer_id=i["zms"], page=1, page_size=MAX_ROWS)),
        ("policy_rules", "Policy rules", "policy_rules.list_policy_rules",
         lambda s, i: s.policy_rules.list_policy_rules(customer_id=i["zms"], page_num=1, page_size=MAX_ROWS)),
        ("default_rules", "Default policy rules", "policy_rules.list_default_policy_rules",
         lambda s, i: s.policy_rules.list_default_policy_rules(customer_id=i["zms"], page_num=1, page_size=100)),
        ("protection", "Resource protection", "resources.get_resource_protection_status",
         lambda s, i: s.resources.get_resource_protection_status(customer_id=i["zms"])),
        ("app_zones", "App zones", "app_zones.list_app_zones", lambda s, i: s.app_zones.list_app_zones(customer_id=i["zms"], page_size=MAX_ROWS)),
        ("resource_groups", "Resource groups", "resource_groups.list_resource_groups",
         lambda s, i: s.resource_groups.list_resource_groups(customer_id=i["zms"], page_size=MAX_ROWS)),
    ],
}
# The GraphQL data field each Microsegmentation operation answers under (the SDK's own get("data").get(...)).
_ZMS_FIELD = {"ListAgents": "agents", "AgentConnectionStatusStats": "agentConnectionStatusStatistics",
              "AgentVersionStats": "agentVersionStatistics", "ListAgentGroups": "agentGroups", "ListNonces": "nonces",
              "ListPolicyRules": "policyRules", "ListDefaultPolicyRules": "defaultPolicyRules",
              "ResourceProtectionStatus": "resourceProtectionStatus", "ListAppZones": "appZones", "ListResourceGroups": "resourceGroups"}


# ── small helpers ──────────────────────────────────────────────────────
_CAMEL = re.compile(r"(?<=[a-z0-9])([A-Z])")
# A field whose value is (or carries) a secret: dropped wherever it appears.
_SECRET = re.compile(r"(^|_)key$|(^|_)keys$|secret|token|password|passwd|passcode|activation_?code|qr_?code|totp|(^|_)otp|"
                     r"credential|wireguard|api_?key|private|psk|cert(ificate)?_?(body|data|pem)", re.I)


def snake(name: Any) -> str:
    return _CAMEL.sub(r"_\1", str(name)).lower()


def _clean(v: Any, depth: int = 0) -> Any:
    """A copy of an API value with snake_case keys and every secret-named field dropped."""
    if depth > 12:
        return None
    if isinstance(v, dict):
        out = {}
        for k, x in v.items():
            sk = snake(k)
            if _SECRET.search(sk):
                continue
            out[sk] = _clean(x, depth + 1)
        return out
    if isinstance(v, list):
        return [_clean(x, depth + 1) for x in v[:MAX_ROWS]]
    if isinstance(v, str):
        return v[:2000]
    return v


def scrub(obj: Any, depth: int = 0) -> Any:
    """A report with anything secret-shaped dropped again (second guard)."""
    if depth > 40:
        return None
    if isinstance(obj, dict):
        return {k: scrub(v, depth + 1) for k, v in obj.items() if not _SECRET.search(snake(k))}
    if isinstance(obj, list):
        return [scrub(x, depth + 1) for x in obj]
    return obj


def _text(v: Any, n: int = _TEXT_MAX) -> str:
    s = re.sub(r"[\x00-\x1f\x7f]+", " ", "" if v is None else str(v)).strip()
    return s[:n]


def _num(v: Any) -> Optional[float]:
    try:
        if isinstance(v, bool) or v in (None, ""):
            return None
        return float(v)
    except (TypeError, ValueError):
        return None


def _bool(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    s = str(v or "").strip().lower()
    if s in ("true", "yes", "on", "enabled", "1", "enable"):
        return True
    if s in ("false", "no", "off", "disabled", "0", "disable"):
        return False
    return None


def _when(v: Any) -> Optional[datetime]:
    """A time from epoch seconds or milliseconds, or ISO 8601 text."""
    n = _num(v)
    try:
        if n is not None:
            if n > 1e11:
                n /= 1000.0
            return datetime.fromtimestamp(n, tz=timezone.utc)
        s = str(v or "").strip()
        if not s:
            return None
        d = datetime.fromisoformat(s.replace("Z", "+00:00"))
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _age_days(v: Any, now: Optional[datetime] = None) -> Optional[int]:
    d = _when(v)
    if d is None:
        return None
    return max(0, int(((now or datetime.now(timezone.utc)) - d).total_seconds() // 86400))


def _items(product: str, body: Any, field: str = "") -> Tuple[List[Dict[str, Any]], Optional[int]]:
    """(rows, total the API says it has) from an answer, per product envelope
    (zscaler/oneapi_response.py: ZTB {"result": {...: [...]}} or rows;
    EASM {"results": [...]}; ZBI a list or {"reports": [...]}; ZCell
    {"content": [...]} or one object; ZMS {"data": {field: {"nodes": [...]}}})."""
    total: Optional[int] = None
    rows: Any = []
    if product == "zms":
        data = body.get("data") if isinstance(body, dict) else None
        node = data.get(field) if isinstance(data, dict) else None
        if isinstance(node, dict):
            rows = node.get("nodes") if isinstance(node.get("nodes"), list) else [node]
            pi = node.get("pageInfo") if isinstance(node.get("pageInfo"), dict) else {}
            total = int(_num(pi.get("totalCount")) or 0) or None
    elif isinstance(body, list):
        rows = body
    elif isinstance(body, dict):
        if product == "ztb":
            res = body.get("result")
            if isinstance(res, list):
                rows = res
            elif isinstance(res, dict):
                rows = next((v for v in res.values() if isinstance(v, list)), None)
                if rows is None:
                    rows = [res]
                total = int(_num(res.get("count") or res.get("totalAlarmsCount")) or 0) or None
            else:
                rows = next((v for v in body.values() if isinstance(v, list)), [])
                total = int(_num(body.get("count")) or 0) or None
        elif product == "easm":
            rows = body.get("results") if isinstance(body.get("results"), list) else []
            total = int(_num(body.get("total_results") or body.get("totalResults")) or 0) or None
        elif product == "zbi":
            rows = body.get("reports") if isinstance(body.get("reports"), list) else [body]
        elif product == "zcell":
            if isinstance(body.get("content"), list):
                rows = body["content"]
                total = int(_num(body.get("totalElements")) or 0) or None
            else:
                rows = [body]
    rows = [r for r in (rows or []) if isinstance(r, dict)]
    return [_clean(r) for r in rows[:MAX_ROWS]], total


def _err(body: Any, code: int) -> str:
    if isinstance(body, dict):
        msg = body.get("message") or body.get("error") or body.get("detail") or ""
    else:
        msg = body
    return f"HTTP {code}" + (f": {_text(msg, 160)}" if msg else "")


def _send(cl: Any, req: Dict[str, Any]) -> Tuple[Any, int]:
    """Send one captured SDK request through the raw client: a GET, or a
    Microsegmentation GraphQL query (a read sent as a POST, only for the
    operations in ZMS_OPERATIONS)."""
    if req["method"] == "GET":
        return cl.get(req["url"], req["params"] or None)
    body = req.get("body") or {}
    if req["method"] == "POST" and req["url"] == "/zms/graphql" and body.get("operationName") in ZMS_OPERATIONS \
            and str(body.get("query") or "").lstrip().startswith("query "):
        return cl.post(req["url"], body)
    raise RuntimeError(f"refused: {req['method']} {req['url']} is not a read")   # never reached by READS


# ── scope ──────────────────────────────────────────────────────────────
def scope_for(scopes: Any) -> Dict[str, Any]:
    """What this page may read for the Scope page's ticked scopes: each
    product only when its own key is ticked. Pure."""
    sc = {str(s).strip() for s in scopes} if isinstance(scopes, (list, tuple, set)) else set()
    on = [k for k in SCOPE_KEYS if k in sc]
    nis = {k: f"Not in scope: {PRODUCTS[k]['label']} is not ticked on the Scope page, so it was not read." for k in SCOPE_KEYS if k not in sc}
    summary = ("Reads only what is in scope on the Scope page: " + ", ".join(PRODUCTS[k]["label"] for k in on) + ".") if on else NOTHING_IN_SCOPE
    return {"products": on, "read": bool(on), "not_in_scope": nis, "summary": summary}


def ids_for(cl: Any, zcell_id: str = "", zms_id: str = "") -> Dict[str, str]:
    """The per-product customer IDs: ZCell's as given (or set on the
    client), ZMS's as given, else the ZPA customer ID (assumed)."""
    zc = str(zcell_id or getattr(cl, "zcell_customer_id", "") or "").strip()
    zm = str(zms_id or getattr(cl, "zms_customer_id", "") or getattr(cl, "customer_id", "") or "").strip()
    if not zc and getattr(cl, "offline", False):
        import offline_tenant
        zc = offline_tenant.ZCELL_CUSTOMER_ID
    return {"zcell": zc if valid_id(zc) else "", "zms": zm if valid_id(zm) else ""}


_ID_RE = re.compile(r"\A[A-Za-z0-9_-]{1,64}\Z")


def valid_id(v: Any) -> bool:
    """A customer ID that may go into a path or a query: letters, digits, - and _."""
    return isinstance(v, str) and bool(_ID_RE.match(v))


# ── reading one product ────────────────────────────────────────────────
def read_product(cl: Any, product: str, ids: Optional[Dict[str, str]] = None, log: Optional[Callable[[str], None]] = None,
                 cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read every list of `product` through `cl`. Returns {product, label,
    status (read | not_licensed | needs | not_permitted | error), note,
    lists: {key: {label, method, read, count, total, error, rows}}}."""
    say = log or (lambda m: None)
    ids = dict(ids or {})
    p = PRODUCTS[product]
    out: Dict[str, Any] = {"product": product, "label": p["label"], "status": "read", "note": "", "lists": {}}

    def stop_point() -> None:
        if cancel is not None and cancel.is_set():
            raise Stopped(STOPPED_REASON)

    if getattr(cl, "legacy", False):
        out.update(status="needs", note=NEEDS_ONEAPI)
        return out
    need = p["needs"]
    if need == "zcell" and not ids.get("zcell"):
        out.update(status="needs", note=NEEDS_ZCELL_ID)
        return out
    if need == "zms" and not ids.get("zms"):
        out.update(status="needs", note=NEEDS_ZMS_ID)
        return out
    say(f"{p['label']}: reading (read-only)…")
    specs = READS[product]
    if product == "easm":
        return _read_easm(cl, out, specs, say, stop_point)
    for key, label, method, call in specs:
        stop_point()
        body, code = _send(cl, sdk_request(product, lambda s, c=call: c(s, ids), ids))
        out["lists"][key] = _list_entry(product, key, label, method, body, code)
        if key == specs[0][0] and code in (404, 410):
            out.update(status="not_licensed", note=NOT_LICENSED.format(what=p["label"], code=code))
            return out
    _settle(out)
    return out


def _list_entry(product: str, key: str, label: str, method: str, body: Any, code: int, field: str = "") -> Dict[str, Any]:
    if code in (200, 204):
        if product == "zms":
            req_field = next((f for op, f in _ZMS_FIELD.items() if op == _OP_OF.get(key)), "")
            rows, total = _items(product, body if code == 200 else {}, req_field)
        else:
            rows, total = _items(product, body if code == 200 else [], field)
        return {"label": label, "method": method, "read": True, "count": len(rows), "total": total or len(rows), "rows": rows, "error": ""}
    return {"label": label, "method": method, "read": False, "count": 0, "total": 0, "rows": [], "error": _err(body, code), "code": code}


_OP_OF = {"agents": "ListAgents", "connection_stats": "AgentConnectionStatusStats", "version_stats": "AgentVersionStats",
          "agent_groups": "ListAgentGroups", "nonces": "ListNonces", "policy_rules": "ListPolicyRules",
          "default_rules": "ListDefaultPolicyRules", "protection": "ResourceProtectionStatus", "app_zones": "ListAppZones",
          "resource_groups": "ListResourceGroups"}


def _settle(out: Dict[str, Any]) -> None:
    lists = out["lists"].values()
    if lists and all(not x["read"] for x in lists):
        codes = {x.get("code") for x in lists}
        if codes <= {401, 403}:
            out.update(status="not_permitted", note=f"The API client may not read {out['label']} (HTTP 403): give its role "
                                                    f"read access to {out['label']}, then read again.")
        else:
            out.update(status="error", note=next((x["error"] for x in lists if x["error"]), "Not read."))


def _read_easm(cl: Any, out: Dict[str, Any], specs: List[Any], say: Callable[[str], None], stop_point: Callable[[], None]) -> Dict[str, Any]:
    key, label, method, call = specs[0]
    stop_point()
    body, code = _send(cl, sdk_request("easm", lambda s: call(s, {})))
    org_entry = _list_entry("easm", key, label, method, body, code)
    out["lists"][key] = org_entry
    if code in (404, 410):
        out.update(status="not_licensed", note=NOT_LICENSED.format(what=out["label"], code=code))
        return out
    for k, lab, meth, _ in specs[1:]:
        out["lists"][k] = {"label": lab, "method": meth, "read": org_entry["read"], "count": 0, "total": 0, "rows": [],
                           "error": "" if org_entry["read"] else org_entry["error"]}
    orgs = [o for o in org_entry["rows"] if valid_id(str(o.get("id") or ""))][:MAX_ORGS]
    for org in orgs:
        oid, oname = str(org["id"]), _text(org.get("name") or org["id"], 80)
        for k, lab, meth, c in specs[1:]:
            stop_point()
            b, cd = _send(cl, sdk_request("easm", lambda s, c=c, oid=oid: c(s, {"org": oid})))
            e = _list_entry("easm", k, lab, meth, b, cd)
            tgt = out["lists"][k]
            if e["read"]:
                for r in e["rows"]:
                    r["organization"] = oname
                tgt["rows"].extend(e["rows"][: MAX_ROWS - len(tgt["rows"])])
                tgt["count"] = len(tgt["rows"])
                tgt["total"] += e["total"]
            else:
                tgt["error"] = e["error"]
    _settle(out)
    return out


def read(cl: Any, scope: Dict[str, Any], ids: Optional[Dict[str, str]] = None, log: Optional[Callable[[str], None]] = None,
         cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read every product `scope` (scope_for) puts in scope. Raises Stopped."""
    snap: Dict[str, Any] = {"products": {}, "not_in_scope": dict(scope.get("not_in_scope") or {})}
    for product in scope.get("products") or []:
        if cancel is not None and cancel.is_set():
            raise Stopped(STOPPED_REASON)
        snap["products"][product] = read_product(cl, product, ids, log, cancel)
    return snap


# ── normalizing what each list holds ───────────────────────────────────
def _f(r: Dict[str, Any], *names: str) -> Any:
    for n in names:
        v = r.get(snake(n))
        if v not in (None, ""):
            return v
    return None


def _rows(prod: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    e = (prod.get("lists") or {}).get(key) or {}
    return list(e.get("rows") or [])


def _read_ok(prod: Dict[str, Any], key: str) -> bool:
    return bool(((prod.get("lists") or {}).get(key) or {}).get("read"))


def inventory(product: str, prod: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, List[Dict[str, Any]]]:
    """Plain rows per list for the page and the workbook. Only the listed
    fields are copied: never a secret, a person, a device or a SIM."""
    now = now or datetime.now(timezone.utc)
    inv: Dict[str, List[Dict[str, Any]]] = {}
    if product == "ztb":
        tmpl = {str(_f(t, "id")): _text(_f(t, "name")) for t in _rows(prod, "templates")}
        inv["sites"] = [{"name": _text(_f(s, "display_name", "name")), "status": _text(_f(s, "site_status")),
                         "gateway_type": _text(_f(s, "gateway_type")), "template": tmpl.get(str(_f(s, "template_id")), _text(_f(s, "template_id"))),
                         "gateways": len(_f(s, "clusters") or [])} for s in _rows(prod, "sites")]
        inv["templates"] = [{"name": _text(_f(t, "name")), "deployment": _text(_f(t, "deployment_type")), "platform": _text(_f(t, "platform_type")),
                             "default": bool(_bool(_f(t, "is_default"))), "sites": int(_num(_f(t, "sites_count")) or 0),
                             "nat": _bool(_f(t, "nat_enabled")), "dhcp": _text(_f(t, "dhcp_service"))} for t in _rows(prod, "templates")]
        inv["groups"] = [{"name": _text(_f(g, "display_name", "name")), "type": _text(_f(g, "type")), "members": int(_num(_f(g, "members_count")) or 0),
                          "policies": int(_num(_f(g, "policy_count")) or 0)} for g in _rows(prod, "groups")]
        inv["alarms"] = [{"site": _text(_f(a, "site_name")), "severity": _text(_f(a, "severity")), "status": _text(_f(a, "status")),
                          "service": _text(_f(a, "service")), "description": _text(_f(a, "description")),
                          "recommended": _text(_f(a, "recommended_action")), "age_days": _age_days(_f(a, "created_at"), now)}
                         for a in _rows(prod, "alarms")]
        inv["api_keys"] = [{"name": _text(_f(k, "name")), "age_days": _age_days(_f(k, "created_at"), now)} for k in _rows(prod, "api_keys")]
        inv["hubs"] = [{"location": _text(_f(h, "location_display_name", "location")), "region": _text(_f(h, "region")),
                        "sites": len(_f(h, "sites") or []) if isinstance(_f(h, "sites"), list) else int(_num(_f(h, "sites")) or 0),
                        "gateways": len(((_f(h, "cluster_info") or {}).get("gateways") or [])) if isinstance(_f(h, "cluster_info"), dict) else 0}
                       for h in _rows(prod, "hubs")]
        inv["operating_systems"] = [{"os": _text(_f(o, "os_name")), "devices": int(_num(_f(o, "devices")) or 0),
                                     "versions": len(_f(o, "versions") or [])} for o in _rows(prod, "operating_systems")]
        inv["ransomware"] = [_ransomware_state(r) for r in _rows(prod, "ransomware")]
    elif product == "easm":
        inv["organizations"] = [{"name": _text(_f(o, "name") or _f(o, "id"))} for o in _rows(prod, "organizations")]
        inv["findings"] = [{"organization": _text(f.get("organization")), "name": _text(_f(f, "name")), "category": _text(_f(f, "category")),
                            "risk": _risk_word(_f(f, "risk_level"), _f(f, "risk_score", "severity_score")),
                            "asset": _text(_f(f, "impacted_asset_name")), "status": _text(_f(f, "status")),
                            "age_days": _age_days(_f(f, "first_seen"), now), "stale": bool(_bool(_f(f, "is_stale"))),
                            "exploited": _exploited(f)} for f in _rows(prod, "findings")]
        inv["lookalikes"] = [{"organization": _text(d.get("organization")), "domain": _text(_f(d, "lookalike_raw")),
                              "imitates": _text(_f(d, "original_domain")), "registered": _bool(_f(d, "is_registered")),
                              "risk": _risk_word(_f(d, "risk_category"), _f(d, "risk_score")), "method": _text(_f(d, "deception_method")),
                              "status": _text(_f(d, "status"))} for d in _rows(prod, "lookalikes")]
    elif product == "zbi":
        inv["custom_apps"] = [{"name": _text(_f(a, "name")), "category": _text(_f(a, "associated_app_category")),
                               "signatures": len(_f(a, "signatures") or [])} for a in _rows(prod, "custom_apps")]
        inv["report_configs"] = [{"name": _text(_f(c, "name")), "type": _text(_f(c, "sub_type")), "enabled": _bool(_f(c, "enabled")),
                                  "frequency": _text((_f(c, "schedule_params") or {}).get("frequency") if isinstance(_f(c, "schedule_params"), dict) else ""),
                                  "recipients": _recipients(c)} for c in _rows(prod, "report_configs")]
        inv["reports"] = [{"name": _text(_f(r, "file_name", "name")), "type": _text(_f(r, "report_type", "type"))} for r in _rows(prod, "reports")]
    elif product == "zcell":
        cust = (_rows(prod, "customer") or [{}])[0]
        inv["customer"] = [{"name": _text(_f(cust, "name")), "activated": _bool(_f(cust, "is_activated")),
                            "zia_linked": bool(_f(cust, "zia")), "zpa_linked": bool(_f(cust, "zpa")),
                            "total_sims": _num(_f(cust, "total_sims")), "active_sims": _num(_f(cust, "active_sims")),
                            "inactive_sims": _num(_f(cust, "inactive_sims"))}] if cust else []
        inv["regions"] = [{"region": _text(_f(r, "region")), "configured": _bool(_f(r, "configured"))} for r in _rows(prod, "regions")]
        inv["location_groups"] = [{"name": _text(_f(g, "name")), "tracked_sims": len(_f(g, "tracked_devices") or [])} for g in _rows(prod, "location_groups")]
        inv["anomaly_policies"] = [{"name": _text(_f(p, "policy_name")), "type": _text(_f(p, "policy_type")), "enabled": _bool(_f(p, "enabled")),
                                    "running": _text(_f(p, "running_status")), "violations": int(_num(_f(p, "violations")) or 0),
                                    "recipients": _alert_recipients(p)} for p in _rows(prod, "anomaly_policies")]
        summ = (_rows(prod, "sim_summary") or [{}])[0]
        inv["sim_summary"] = [{"total": _num(_f(summ, "total")), "used": _num(_f(summ, "used")), "active": _num(_f(summ, "active")),
                               "inactive": _num(_f(summ, "inactive"))}] if summ else []
    elif product == "zms":
        inv["agents"] = [{"name": _text(_f(a, "name")), "status": _text(_f(a, "connection_status")), "type": _text(_f(a, "agent_type")),
                          "os": _text(_f(a, "host_os")), "version": _text(_f(a, "current_software_version")),
                          "upgrade": _text(_f(a, "upgrade_status")), "group": _text(_f(a, "agent_group_name")),
                          "admin": _text(_f(a, "admin_status"))} for a in _rows(prod, "agents")]
        inv["agent_groups"] = [{"name": _text(_f(g, "name")), "type": _text(_f(g, "agent_group_type")), "agents": int(_num(_f(g, "agent_count")) or 0),
                                "tamper_protection": _text(_f(g, "tamper_protection_status")), "auto_upgrade": _bool(_f(g, "agent_auto_upgrade")),
                                "policy": _text(_f(g, "policy_status")), "version_profile": _text(_f(g, "version_profile_name"))}
                               for g in _rows(prod, "agent_groups")]
        inv["nonces"] = [{"name": _text(_f(n, "name")), "group": _text(_f(n, "agent_group_name")), "max_usage": _num(_f(n, "max_usage")),
                          "used": int(_num(_f(n, "usage_count")) or 0)} for n in _rows(prod, "nonces")]
        inv["policy_rules"] = [{"name": _text(_f(r, "name")), "action": _text(_f(r, "action")), "priority": _num(_f(r, "priority")),
                                "source": _text(_f(r, "source_target_type")), "destination": _text(_f(r, "destination_target_type")),
                                "last_hit": _text(_f(r, "last_hit")), "deleted": bool(_bool(_f(r, "deleted")))}
                               for r in _rows(prod, "policy_rules")]
        inv["default_rules"] = [{"name": _text(_f(r, "name")), "action": _text(_f(r, "action")), "direction": _text(_f(r, "direction")),
                                 "scope": _text(_f(r, "scope_type"))} for r in _rows(prod, "default_rules")]
        pr = (_rows(prod, "protection") or [{}])[0]
        inv["protection"] = [{"protected_pct": _num(_f(pr, "protected_percentage")), "protected": _num(_f(pr, "protected_resources_count")),
                              "unprotected": _num(_f(pr, "unprotected_resources_count")), "total": _num(_f(pr, "total_resources"))}] if pr else []
        inv["app_zones"] = [{"name": _text(_f(z, "app_zone_name")), "members": int(_num(_f(z, "member_count")) or 0)} for z in _rows(prod, "app_zones")]
        inv["resource_groups"] = [{"name": _text(_f(g, "name")), "type": _text(_f(g, "type")), "members": int(_num(_f(g, "resource_member_count")) or 0)}
                                  for g in _rows(prod, "resource_groups")]
        cs = (_rows(prod, "connection_stats") or [{}])[0]
        inv["connection_stats"] = [{"type": _text(s.get("agent_type")), "status": _text(s.get("connection_status")), "count": int(_num(s.get("count")) or 0)}
                                   for s in (cs.get("agent_statuses") or []) if isinstance(s, dict)]
        vs = (_rows(prod, "version_stats") or [{}])[0]
        inv["version_stats"] = [{"type": _text(s.get("agent_type")), "version": _text(s.get("version")), "count": int(_num(s.get("count")) or 0)}
                                for s in (vs.get("agent_versions") or []) if isinstance(s, dict)]
    return inv


def _ransomware_state(r: Dict[str, Any]) -> Dict[str, Any]:
    st = r.get("result") if isinstance(r.get("result"), (dict, list, str)) else r
    if isinstance(st, dict):
        st = st.get("state") or st.get("color") or st.get("status") or ", ".join(f"{k}={_text(v, 30)}" for k, v in list(st.items())[:6])
    elif isinstance(st, list):
        st = ", ".join(_text(x.get("color") or x.get("state") or x, 30) if isinstance(x, dict) else _text(x, 30) for x in st[:10])
    return {"state": _text(st, 120)}


def _recipients(c: Dict[str, Any]) -> int:
    di = c.get("delivery_information")
    if isinstance(di, dict):
        return len(di.get("emails") or [])
    return 0


def _alert_recipients(p: Dict[str, Any]) -> int:
    jd = p.get("json_data") if isinstance(p.get("json_data"), dict) else {}
    n = 0
    for a in jd.get("alerts") or []:
        if isinstance(a, dict):
            n += len(a.get("recipients") or [])
    return n


def _risk_word(level: Any, score: Any) -> str:
    s = str(level or "").strip().lower()
    for w in ("critical", "high", "medium", "low", "info"):
        if w in s:
            return w
    n = _num(score)
    if n is None:
        return "unknown"
    if n > 10:   # assumed: a 0-100 score
        n /= 10.0
    return "critical" if n >= 9 else "high" if n >= 7 else "medium" if n >= 4 else "low"


def _exploited(f: Dict[str, Any]) -> bool:
    c = str(_f(f, "cisa_likelihood") or "").lower()
    e = _num(_f(f, "epss_likelihood"))
    return c in ("high", "true", "yes", "known", "critical") or (e is not None and (e >= 0.5 if e <= 1 else e >= 50))


# ── the checks ─────────────────────────────────────────────────────────
# Each check: (id, product, title, fn(inventory, product read) -> list of
# results). A result is {status: PASS|FAIL|REVIEW|INFO, severity, detail,
# why, fix, source}. The page turns non-PASS results into findings; the
# assessment (zscaler_other_products_checks) scores them.
_OPEN = re.compile(r"acknowledg|ignored|resolved|closed|cleared|done|fixed|taken_?down|remediated|false_?positive|accepted", re.I)
_ONLINE = re.compile(r"online|active|up|connected|healthy|running|deployed|green|ok", re.I)


def _res(status: str, severity: str, detail: str, why: str, fix: str, source: str) -> Dict[str, Any]:
    return {"status": status, "severity": severity, "detail": detail, "why": why, "fix": fix, "source": source}


def _names(rows: Iterable[Dict[str, Any]], key: str = "name", n: int = 5) -> str:
    xs = [str(r.get(key) or "?") for r in rows]
    return ", ".join(xs[:n]) + (f" and {len(xs) - n} more" if len(xs) > n else "")


def _ztb_sites(inv, prod):
    sites = inv.get("sites") or []
    if not sites:
        return _res("REVIEW", "low", "No ZTB site is set up yet.", "A Zero Trust Branch subscription protects nothing until sites are deployed.",
                    "Deploy the first site's gateway from the ZTB admin portal (Sites > Add site).", "Assumed: this app's reading of an empty site list.")
    down = [s for s in sites if s["status"] and not _ONLINE.search(s["status"])]
    if down:
        return _res("REVIEW", "medium", f"{len(down)} of {len(sites)} site(s) do not report as online: {_names(down)}.",
                    "A site whose gateway is offline or not yet deployed sends its traffic nowhere, or around Zscaler.",
                    "Open each site in the ZTB admin portal, check the gateway's health and finish or fix its deployment.",
                    "Assumed: site status words from the SDK field site_status.")
    return _res("PASS", "info", f"{len(sites)} site(s), all reporting as online.", "", "", "")


def _ztb_templates(inv, prod):
    sites = inv.get("sites") or []
    loose = [s for s in sites if not s["template"]]
    if not sites:
        return None
    if loose:
        return _res("REVIEW", "low", f"{len(loose)} of {len(sites)} site(s) use no site template: {_names(loose)}.",
                    "Sites built one by one drift apart (DNS, DHCP, NAT), and a fix made on one is easily missed on the others.",
                    "Create a site template for each kind of branch and apply it (Sites > the site > Template).",
                    "Assumed: configuration-baseline practice (CIS Control 4.1 secure configuration process).")
    return _res("PASS", "info", f"Every site uses a site template ({len(inv.get('templates') or [])} template(s)).", "", "", "")


def _ztb_alarms(inv, prod):
    al = [a for a in inv.get("alarms") or [] if not _OPEN.search(a["status"] or "")]
    hi = [a for a in al if re.search(r"critical|high|major", a["severity"] or "", re.I)]
    if hi:
        return _res("FAIL", "high", f"{len(hi)} critical or high alarm(s) are not acknowledged (sites: {_names(hi, 'site')}).",
                    "An unhandled critical alarm can mean a gateway down, a tunnel lost or a security event nobody is looking at.",
                    "Work through Alarms in the ZTB admin portal: follow each alarm's recommended action, then acknowledge it.",
                    "Assumed: alarm severity and status words from the SDK fields severity and status.")
    if al:
        return _res("REVIEW", "low", f"{len(al)} alarm(s) are not acknowledged.", "Unacknowledged alarms hide new ones in the noise.",
                    "Review and acknowledge the open alarms in the ZTB admin portal.", "Assumed: as above.")
    return _res("PASS", "info", "No open alarm.", "", "", "")


def _ztb_keys(inv, prod):
    keys = inv.get("api_keys") or []
    old = [k for k in keys if k["age_days"] is not None and k["age_days"] > KEY_MAX_AGE_DAYS]
    if old:
        return _res("REVIEW", "medium", f"{len(old)} ZTB API key(s) are older than {KEY_MAX_AGE_DAYS} days: {_names(old)}.",
                    "A long-lived API key that leaks gives lasting access to the branch configuration.",
                    "Create a new key, move the integration to it, then revoke the old one (Administration > API keys).",
                    f"NIST SP 800-57 Part 1 Rev. 5 (cryptoperiods); the {KEY_MAX_AGE_DAYS}-day threshold is assumed.")
    return _res("PASS", "info", f"{len(keys)} API key(s), none older than {KEY_MAX_AGE_DAYS} days." if keys else "No ZTB API key.", "", "", "")


def _ztb_ransomware(inv, prod):
    st = inv.get("ransomware") or []
    if not _read_ok(prod, "ransomware"):
        return None
    txt = "; ".join(s["state"] for s in st if s.get("state"))
    if re.search(r"red|engaged|kill|isolat", txt, re.I):
        return _res("REVIEW", "high", f"The ransomware kill switch reports: {txt}.",
                    "The kill switch cuts traffic inside a site; left on after an incident it stops the site working, and on by mistake it hides a real problem.",
                    "Confirm with the security team why it is engaged; release it in the ZTB admin portal once the site is clean.",
                    "Assumed: state words from the SDK's RansomwareKillState.")
    return _res("INFO", "info", f"Ransomware kill switch state: {txt or 'not engaged'}. Make sure the team knows how to engage it.",
                "", "Rehearse engaging the kill switch in the incident response plan.", "Assumed: incident-readiness practice (NIST SP 800-61r3).")


def _easm_orgs(inv, prod):
    if not inv.get("organizations"):
        return _res("REVIEW", "medium", "EASM has no organization to scan.", "With no organization (seed domains and IP ranges), EASM finds nothing.",
                    "Add the organization and its seed domains in the EASM admin portal.", "Assumed: this app's reading of an empty organization list.")
    return _res("PASS", "info", f"{len(inv['organizations'])} organization(s) scanned.", "", "", "")


def _easm_findings(inv, prod):
    fs = [f for f in inv.get("findings") or [] if not _OPEN.search(f["status"] or "")]
    crit = [f for f in fs if f["risk"] == "critical" and (f["age_days"] or 0) > 15]
    high = [f for f in fs if f["risk"] == "high" and (f["age_days"] or 0) > 30]
    late = crit + high
    if late:
        return _res("FAIL", "high", f"{len(late)} open finding(s) are past the remediation window "
                                    f"({len(crit)} critical older than 15 days, {len(high)} high older than 30 days): {_names(late, 'asset')}.",
                    "Internet-facing weaknesses are found by attackers' scanners within days; old critical findings are the most likely way in.",
                    "Fix or take offline each affected asset (open the finding in EASM for the evidence), then let EASM re-scan.",
                    "CISA Binding Operational Directive 19-02 (critical within 15 days, high within 30 days).")
    open_hi = [f for f in fs if f["risk"] in ("critical", "high")]
    if open_hi:
        return _res("REVIEW", "medium", f"{len(open_hi)} critical or high finding(s) are open, still within the window.",
                    "They will be overdue soon.", "Plan their remediation now.", "CISA BOD 19-02.")
    return _res("PASS", "info", f"No open critical or high finding ({len(inv.get('findings') or [])} finding(s) in total).", "", "", "")


def _easm_exploited(inv, prod):
    ex = [f for f in inv.get("findings") or [] if f["exploited"] and not _OPEN.search(f["status"] or "")]
    if ex:
        return _res("FAIL", "high", f"{len(ex)} open finding(s) are likely or known to be exploited: {_names(ex, 'asset')}.",
                    "A weakness attackers already exploit in the wild is the first to fix, whatever its score.",
                    "Patch or take these assets off the internet first.",
                    "CISA Known Exploited Vulnerabilities catalog; FIRST EPSS (likelihood 0.5 or more assumed as high).")
    return _res("PASS", "info", "No open finding is marked as likely exploited.", "", "", "")


def _easm_lookalikes(inv, prod):
    reg = [d for d in inv.get("lookalikes") or [] if d["registered"] and not _OPEN.search(d["status"] or "")]
    if reg:
        return _res("REVIEW", "medium", f"{len(reg)} registered lookalike domain(s) imitate the organization: {_names(reg, 'domain')}.",
                    "Lookalike domains carry phishing pages and fake invoices sent to staff and customers.",
                    "Block them in ZIA (a custom URL category in a Block URL filtering rule) and ask the registrar for a takedown.",
                    "CISA and NSA phishing guidance (Phishing Guidance: Stopping the Attack Cycle at Phase One, 2023).")
    return _res("PASS", "info", f"No registered lookalike domain is open ({len(inv.get('lookalikes') or [])} seen).", "", "", "")


def _zbi_apps(inv, prod):
    apps = inv.get("custom_apps") or []
    empty = [a for a in apps if not a["signatures"]]
    if empty:
        return _res("REVIEW", "low", f"{len(empty)} custom application(s) have no signature: {_names(empty)}.",
                    "A custom application with no signature matches no traffic, so its reports always read zero.",
                    "Add the application's domains or URLs as signatures (Business Insights > Custom applications).",
                    "SDK model CustomApp.signatures; the recommendation is assumed.")
    return _res("PASS", "info", f"{len(apps)} custom application(s), each with signatures." if apps else "No custom application defined.", "", "", "")


def _zbi_reports(inv, prod):
    cfg = inv.get("report_configs") or []
    on = [c for c in cfg if c["enabled"] is not False]
    if not on:
        return _res("REVIEW", "low", "No scheduled Business Insights report is enabled.",
                    "Insights nobody receives change nothing: SaaS spend, unused licences and office use go unseen.",
                    "Schedule a monthly report to the application owners (Business Insights > Reports > Schedule).",
                    "Assumed: this app's reading of an empty report schedule.")
    return _res("PASS", "info", f"{len(on)} scheduled report(s) enabled.", "", "", "")


def _zcell_policies(inv, prod):
    pol = inv.get("anomaly_policies") or []
    on = [p for p in pol if p["enabled"]]
    if not on:
        return _res("FAIL", "medium", "No anomaly policy is enabled for the SIMs.",
                    "Without one, a SIM moved out of its site or swapped into another device goes unnoticed.",
                    "Create a geofence anomaly policy for each SIM location group and enable it (Policies > Anomaly).",
                    "Assumed: anomaly detection for cellular IoT (NIST IR 8259A device security capabilities).")
    quiet = [p for p in on if not p["recipients"]]
    if quiet:
        return _res("REVIEW", "low", f"{len(quiet)} enabled anomaly policy(ies) alert nobody: {_names(quiet)}.",
                    "An alert with no recipient is never seen.", "Add the operations team as alert recipients.", "Assumed.")
    return _res("PASS", "info", f"{len(on)} anomaly policy(ies) enabled, each alerting someone.", "", "", "")


def _zcell_idle(inv, prod):
    s = (inv.get("sim_summary") or inv.get("customer") or [{}])[0]
    total = _num(s.get("total") if "total" in s else s.get("total_sims"))
    inactive = _num(s.get("inactive") if "inactive" in s else s.get("inactive_sims"))
    if not total:
        return None
    pct = 100.0 * (inactive or 0) / total
    if pct > IDLE_SIM_MAX:
        return _res("REVIEW", "low", f"{int(inactive or 0)} of {int(total)} SIMs ({pct:.0f}%) are inactive.",
                    "Idle SIMs cost money and can be moved to an unknown device unnoticed.",
                    "Suspend or retire SIMs that are not in use (SIMs > select > Status).",
                    f"Assumed: asset-inventory practice (CIS Control 1); the {IDLE_SIM_MAX:.0f}% threshold is this app's.")
    return _res("PASS", "info", f"{int(total)} SIMs, {pct:.0f}% inactive.", "", "", "")


def _zcell_link(inv, prod):
    c = (inv.get("customer") or [None])[0]
    if not c:
        return None
    if not c["zia_linked"]:
        return _res("FAIL", "high", "The Zero Trust Cellular account is not linked to a ZIA tenant.",
                    "Without ZIA, the SIMs' internet traffic is not inspected by Zscaler's security and data protection policies.",
                    "Link the ZIA tenant in the ZCell admin portal (Account > Zscaler clouds).",
                    "Assumed: from the SDK field CustomerDataHandling.zia.")
    return _res("PASS", "info", "Linked to ZIA" + (" and ZPA." if c["zpa_linked"] else "."), "", "", "")


def _zms_agents(inv, prod):
    ag = inv.get("agents") or []
    if not ag:
        return _res("REVIEW", "low", "No Microsegmentation agent is installed.", "Microsegmentation protects only servers that run its agent.",
                    "Install agents with a provisioning key on the servers to protect.", "Assumed.")
    down = [a for a in ag if a["status"] and not _ONLINE.search(a["status"])]
    if down:
        return _res("REVIEW", "medium", f"{len(down)} of {len(ag)} agent(s) are not connected: {_names(down)}.",
                    "A disconnected agent stops receiving policy changes and reporting traffic.",
                    "Check the servers are up and can reach Zscaler; remove agents of servers that are gone.",
                    "Assumed: connection status words from the SDK field connectionStatus.")
    return _res("PASS", "info", f"{len(ag)} agent(s), all connected.", "", "", "")


def _zms_tamper(inv, prod):
    gs = inv.get("agent_groups") or []
    off = [g for g in gs if re.search(r"disabl|off|false", g["tamper_protection"] or "", re.I)]
    if off:
        return _res("FAIL", "high", f"Tamper protection is off in {len(off)} agent group(s): {_names(off)}.",
                    "An attacker with admin rights on a server can stop or remove an unprotected agent and move on unseen.",
                    "Turn tamper protection on for every agent group (Agent groups > the group > Tamper protection).",
                    "MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools).")
    return _res("PASS", "info", f"Tamper protection on in all {len(gs)} agent group(s)." if gs else "No agent group.", "", "", "")


def _zms_upgrade(inv, prod):
    gs = [g for g in inv.get("agent_groups") or [] if g["auto_upgrade"] is False]
    vers = {v["version"] for v in inv.get("version_stats") or [] if v["version"]}
    if gs or len(vers) > 2:
        return _res("REVIEW", "low", (f"Automatic upgrade is off in {len(gs)} agent group(s): {_names(gs)}. " if gs else "")
                    + (f"{len(vers)} agent versions are running." if len(vers) > 2 else ""),
                    "Old agents miss fixes and new enforcement features; many versions make problems hard to reproduce.",
                    "Turn on automatic upgrade with a maintenance window, or upgrade the old agents.",
                    "Assumed: patch management practice (CIS Control 7.4).")
    return _res("PASS", "info", "Agents upgrade automatically" + (f"; {len(vers)} version(s) running." if vers else "."), "", "", "")


def _zms_nonces(inv, prod):
    ns = inv.get("nonces") or []
    unlimited = [n for n in ns if not n["max_usage"]]
    if unlimited:
        return _res("REVIEW", "medium", f"{len(unlimited)} provisioning key(s) have no usage limit: {_names(unlimited)}.",
                    "A provisioning key with no limit that leaks lets anyone enrol rogue agents into a trusted group.",
                    "Give each key a usage limit close to the servers it is meant for, and delete keys no longer needed.",
                    "Assumed: least-privilege enrolment (NIST SP 800-207 zero trust principle 6).")
    return _res("PASS", "info", f"{len(ns)} provisioning key(s), each with a usage limit." if ns else "No provisioning key.", "", "", "")


def _zms_default(inv, prod):
    allow = [r for r in inv.get("default_rules") or [] if re.search(r"allow|permit", r["action"] or "", re.I)]
    if allow:
        return _res("REVIEW", "medium", f"{len(allow)} default rule(s) allow traffic no rule names: {_names(allow)}.",
                    "With an allowing default, segmentation only blocks what someone thought of; zero trust denies by default.",
                    "Once the policy rules cover the needed flows (watch the traffic first), set the default rules to deny or block.",
                    "NIST SP 800-207 (zero trust architecture: deny by default, least privilege).")
    return _res("PASS", "info", "The default rules deny traffic no rule names." if inv.get("default_rules") else "No default rule read.", "", "", "")


def _zms_protection(inv, prod):
    p = (inv.get("protection") or [None])[0]
    if not p or p.get("protected_pct") is None:
        return None
    pct = p["protected_pct"] * 100 if p["protected_pct"] <= 1 else p["protected_pct"]
    if pct < PROTECTED_MIN:
        return _res("REVIEW", "medium", f"Only {pct:.0f}% of resources are protected ({int(p.get('unprotected') or 0)} unprotected).",
                    "Unprotected servers can still be reached from anywhere inside the network.",
                    "Add the unprotected resources to app zones and policy rules (Resources > Unprotected).",
                    f"Assumed: {PROTECTED_MIN:.0f}% threshold is this app's.")
    return _res("PASS", "info", f"{pct:.0f}% of resources protected.", "", "", "")


CHECKS: Dict[str, List[Tuple[str, str, Callable[..., Optional[Dict[str, Any]]]]]] = {
    "ztb": [("ZTB.1", "Sites online", _ztb_sites), ("ZTB.2", "Site templates", _ztb_templates), ("ZTB.3", "Open alarms", _ztb_alarms),
            ("ZTB.4", "API key age", _ztb_keys), ("ZTB.5", "Ransomware kill switch", _ztb_ransomware)],
    "easm": [("EASM.1", "Organizations scanned", _easm_orgs), ("EASM.2", "Findings past the remediation window", _easm_findings),
             ("EASM.3", "Exploited weaknesses", _easm_exploited), ("EASM.4", "Registered lookalike domains", _easm_lookalikes)],
    "zbi": [("ZBI.1", "Custom applications with signatures", _zbi_apps), ("ZBI.2", "Scheduled reports", _zbi_reports)],
    "zcell": [("ZCELL.1", "Linked to ZIA", _zcell_link), ("ZCELL.2", "Anomaly policies", _zcell_policies),
              ("ZCELL.3", "Inactive SIMs", _zcell_idle)],
    "zms": [("ZMS.1", "Agents connected", _zms_agents), ("ZMS.2", "Tamper protection", _zms_tamper),
            ("ZMS.3", "Agent upgrades", _zms_upgrade), ("ZMS.4", "Provisioning key limits", _zms_nonces),
            ("ZMS.5", "Default deny", _zms_default), ("ZMS.6", "Resources protected", _zms_protection)],
}


def evaluate(product: str, prod: Dict[str, Any], now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Every check of `product` on its read: [{id, title, status, severity,
    detail, why, fix, source}]. A product not read, not licensed or blocked
    gives one N/A (INFO) result per check, saying why."""
    out = []
    status = prod.get("status")
    inv = inventory(product, prod, now) if status == "read" else {}
    for cid, title, fn in CHECKS[product]:
        if status != "read":
            out.append({"id": cid, "title": title, "status": "INFO", "severity": "info", "detail": prod.get("note") or "Not read.",
                        "why": "", "fix": "", "source": ""})
            continue
        try:
            r = fn(inv, prod)
        except Exception as e:  # noqa: BLE001 — one check's surprise never sinks the rest
            r = _res("ERROR", "info", f"The check could not evaluate this answer ({type(e).__name__}).", "", "", "")
        if r is None:
            r = _res("INFO", "info", "Not enough data was read to judge this.", "", "", "")
        out.append(dict(r, id=cid, title=title))
    return out


# ── the report ─────────────────────────────────────────────────────────
def analyse(snap: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
    """The page's report from a read: per product its status, plain
    explanation, inventory, what was read, check results; findings (every
    non-PASS check) sorted by severity; counts. Never a secret."""
    products, findings = {}, []
    for key, prod in (snap.get("products") or {}).items():
        p = PRODUCTS[key]
        results = evaluate(key, prod, now)
        lists = [{"key": k, "label": e["label"], "method": e["method"], "read": e["read"], "count": e["count"], "total": e["total"],
                  "error": e.get("error", "")} for k, e in (prod.get("lists") or {}).items()]
        products[key] = {"label": p["label"], "what": p["what"], "status": prod.get("status"), "note": prod.get("note", ""),
                         "license": p["license"], "lists": lists, "inventory": inventory(key, prod, now) if prod.get("status") == "read" else {},
                         "checks": results}
        for r in results:
            if r["status"] in ("FAIL", "REVIEW"):
                findings.append({"id": r["id"], "product": p["label"], "severity": r["severity"], "title": r["title"], "status": r["status"],
                                 "detail": r["detail"], "why": r["why"], "fix": r["fix"], "source": r["source"]})
    findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["id"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    counts["total"] = len(findings)
    return scrub({"products": products, "findings": findings, "counts": counts, "not_in_scope": snap.get("not_in_scope") or {},
                  "assumptions": ASSUMPTIONS, "glossary": [{"term": a, "meaning": b} for a, b in GLOSSARY],
                  "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")})


def run(cl: Any, scope: Dict[str, Any], ids: Optional[Dict[str, str]] = None, log: Optional[Callable[[str], None]] = None,
        cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read what is in scope and analyse it (raises Stopped)."""
    return analyse(read(cl, scope, ids, log, cancel))


# ── exports ────────────────────────────────────────────────────────────
_SHEETS = {
    "ztb": [("sites", "Sites", ["name", "status", "gateway_type", "template", "gateways"]),
            ("templates", "Templates", ["name", "deployment", "platform", "default", "sites", "nat", "dhcp"]),
            ("alarms", "Alarms", ["site", "severity", "status", "service", "description", "recommended", "age_days"]),
            ("api_keys", "API keys", ["name", "age_days"]), ("hubs", "Hubs", ["location", "region", "sites", "gateways"]),
            ("groups", "Groups", ["name", "type", "members", "policies"]),
            ("operating_systems", "Operating systems", ["os", "devices", "versions"])],
    "easm": [("findings", "Findings", ["organization", "name", "category", "risk", "asset", "status", "age_days", "exploited"]),
             ("lookalikes", "Lookalike domains", ["organization", "domain", "imitates", "registered", "risk", "method", "status"])],
    "zbi": [("custom_apps", "Custom apps", ["name", "category", "signatures"]),
            ("report_configs", "Scheduled reports", ["name", "type", "enabled", "frequency", "recipients"])],
    "zcell": [("anomaly_policies", "Anomaly policies", ["name", "type", "enabled", "running", "violations", "recipients"]),
              ("location_groups", "SIM location groups", ["name", "tracked_sims"]), ("regions", "Regions", ["region", "configured"])],
    "zms": [("agents", "Agents", ["name", "status", "type", "os", "version", "upgrade", "group", "admin"]),
            ("agent_groups", "Agent groups", ["name", "type", "agents", "tamper_protection", "auto_upgrade", "policy", "version_profile"]),
            ("nonces", "Provisioning keys", ["name", "group", "max_usage", "used"]),
            ("policy_rules", "Policy rules", ["name", "action", "priority", "source", "destination", "last_hit"]),
            ("default_rules", "Default rules", ["name", "action", "direction", "scope"]),
            ("app_zones", "App zones", ["name", "members"])],
}


def _cell(v: Any) -> Any:
    if isinstance(v, bool):
        return "Yes" if v else "No"
    return "" if v is None else v


def workbook(report: Dict[str, Any]) -> bytes:
    """The report as an Excel workbook (xlsx_writer escapes formulas): Summary,
    Findings, one sheet per list. Never a secret."""
    import xlsx_writer
    rep = scrub(report)
    wb = xlsx_writer.Workbook(title=f"Other Zscaler products {rep.get('tenant_label') or ''}".strip(), subject=f"{PRODUCT}: other products")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    c = rep.get("counts") or {}
    s.extend([["Tenant", rep.get("tenant_label") or ""], ["Generated", rep.get("generated_at") or ""], ["Findings", c.get("total", 0)]])
    for k, p in (rep.get("products") or {}).items():
        s.append([p.get("label"), p.get("note") or ("Read" if p.get("status") == "read" else p.get("status"))])
    for k, v in (rep.get("not_in_scope") or {}).items():
        s.append([f"Not in scope ({SCOPE_LABELS.get(k, k)})", v])
    f = wb.add_sheet("Findings", columns=["Severity", "ID", "Product", "Title", "Detail", "Why it matters", "What to do", "Source"])
    for x in rep.get("findings") or []:
        f.append([x.get("severity"), x.get("id"), x.get("product"), x.get("title"), x.get("detail"), x.get("why"), x.get("fix"), x.get("source")])
    for k, p in (rep.get("products") or {}).items():
        inv = p.get("inventory") or {}
        for key, title, cols in _SHEETS.get(k, []):
            rows = inv.get(key) or []
            if not rows:
                continue
            sh = wb.add_sheet(f"{PRODUCTS[k]['short']} {title}"[:31], columns=[x.replace("_", " ").capitalize() for x in cols])
            for r in rows:
                sh.append([_cell(r.get(col)) for col in cols])
    a = wb.add_sheet("Assumptions", columns=["Assumption"], autofilter=False)
    for line in rep.get("assumptions") or []:
        a.append([line])
    return wb.to_bytes()
