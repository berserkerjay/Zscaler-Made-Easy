#!/usr/bin/env python3
"""
Zscaler Digital Experience (ZDX) Assessment Checks
===================================================
Checks against the ZDX OneAPI surface documented at
https://automate.zscaler.com/docs/docs/api-reference-and-guides/api-reference/zdx
and the zscaler-sdk-go/zdx/services module tree.

ZDX service modules:
  - administration (apps, departments, geolocations, locations, users)
  - alerts (configured alerts + triggered alerts)
  - inventory (software inventory across enrolled devices)
  - reports (performance, trends, analytics)
  - troubleshooting (deep-path, trace-route, system events)

Checks are read-only and use the same Client interface as the other
zscaler_*_checks modules. All failures gracefully degrade to INFO.
"""

from dlp_assessment_full_auto import R, _ls


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Administration
# ═══════════════════════════════════════════════════════════════════════

def zdx_admin_apps(cl):
    """ZDX monitored applications — SaaS + internal apps under ZDX scoring"""
    d, c = cl.get("/zdx/administration/apps")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX apps endpoint not accessible — ZDX subscription may not be active.")
    if not items:
        return R(R.WARN, "No applications configured under ZDX. Best Practice: Add the top 10 SaaS apps your users depend on (O365, Salesforce, Zoom, ServiceNow, etc.) so ZDX can score their health.")
    return R(R.PASS, f"{len(items)} application(s) monitored by ZDX.")


def zdx_admin_locations(cl):
    """ZDX location coverage"""
    d, c = cl.get("/zdx/administration/locations")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX locations endpoint not accessible.")
    if not items:
        return R(R.INFO, "No locations defined in ZDX. ZDX auto-derives locations from device telemetry; explicit locations improve reporting.")
    return R(R.PASS, f"{len(items)} location(s) tracked in ZDX.")


def zdx_admin_departments(cl):
    """ZDX department segmentation for scoped reporting"""
    d, c = cl.get("/zdx/administration/departments")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX departments endpoint not accessible.")
    if not items:
        return R(R.WARN, "No departments defined. Best Practice: Populate departments from your IdP so ZDX dashboards show per-team health — Finance hitting SAP, Engineering hitting GitHub, etc.")
    return R(R.PASS, f"{len(items)} department(s) visible in ZDX.")


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Alerts
# ═══════════════════════════════════════════════════════════════════════

def zdx_alert_rules(cl):
    """Configured ZDX alert rules"""
    # The ZDX API lists alerts (ongoing, historical), not the rules that raise them.
    return R(R.INFO, "ZDX alert rules are not listed by the ZDX API; check them in the ZDX Admin Portal (Alerts > Rules). "
                     "Best Practice: alert on every critical app (app score < 70) so the SOC hears before users open tickets.")

def zdx_alert_triggered(cl):
    """ZDX triggered alerts (ongoing + historical)"""
    d, c = cl.get("/zdx/alerts/ongoing")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX ongoing alerts endpoint not accessible.")
    if items:
        return R(R.WARN, f"{len(items)} ZDX alert(s) currently firing. Best Practice: Review and either remediate or suppress with a business justification — unresolved firing alerts are SOC noise and reduce signal.")
    return R(R.PASS, "No ongoing ZDX alerts.")


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Inventory
# ═══════════════════════════════════════════════════════════════════════

def zdx_inventory_software(cl):
    """Software inventory from ZDX endpoint telemetry"""
    d, c = cl.get("/zdx/inventory/software")
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX software inventory not accessible.")
    if not items:
        return R(R.INFO, "No software inventory data. If ZDX has been running for 24+ hours, software should be populated.")
    return R(R.PASS, f"{len(items)} software record(s) collected by ZDX — usable for vuln tracking and license audits.")


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Reports
# ═══════════════════════════════════════════════════════════════════════

def zdx_reports_available(cl):
    """ZDX reports endpoint reachable"""
    return R(R.INFO, "ZDX reports are not part of the ZDX API; schedule them in the ZDX Admin Portal. "
                     "Best Practice: weekly app-score reports to executives for visibility.")


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Troubleshooting
# ═══════════════════════════════════════════════════════════════════════

def zdx_troubleshoot(cl):
    """ZDX troubleshooting (deep-path trace) reachable"""
    d, c = cl.get("/zdx/troubleshooting/devices")
    if c in (401, 403):
        return R(R.INFO, "ZDX troubleshooting endpoint not accessible.")
    if c in (200, 204):
        return R(R.PASS, "ZDX troubleshooting reachable. Gives the helpdesk deep-path (hop-by-hop) visibility — a huge MTTR win vs. legacy network tools.")
    return R(R.INFO, f"ZDX troubleshooting endpoint returned HTTP {c}.")


# ═══════════════════════════════════════════════════════════════════════
# Register
# ═══════════════════════════════════════════════════════════════════════

ZDX_REG = [
    ("ZDX.1", "ZDX — Administration", "Monitored applications",          zdx_admin_apps),
    ("ZDX.2", "ZDX — Administration", "Location coverage",               zdx_admin_locations),
    ("ZDX.3", "ZDX — Administration", "Department segmentation",         zdx_admin_departments),
    ("ZDX.4", "ZDX — Alerts",         "Configured alert rules",          zdx_alert_rules),
    ("ZDX.5", "ZDX — Alerts",         "Ongoing triggered alerts",        zdx_alert_triggered),
    ("ZDX.6", "ZDX — Inventory",      "Software inventory from ZDX",     zdx_inventory_software),
    ("ZDX.7", "ZDX — Reports",        "Reports endpoint reachable",      zdx_reports_available),
    ("ZDX.8", "ZDX — Troubleshooting","Deep-path troubleshoot reachable",zdx_troubleshoot),
]
