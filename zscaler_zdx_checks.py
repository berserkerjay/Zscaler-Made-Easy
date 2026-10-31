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

from zscaler_full_checks import guard_registry
from dlp_assessment_full_auto import R, _ls

# The administration, apps and devices endpoints return only active data and
# default to the previous 2 hours ("If not entered, returns the data for the
# last 2 hours" — zscaler-sdk-python 1.11.0 zdx/apps.py, admin.py,
# devices.py), so the checks ask for the last 24 hours.
_SINCE = {"since": 24}


def _wrapped(d, key):
    """A ZDX list wrapped in an object ({"next_offset": …, key: [...]}); _ls
    would read the wrapper itself as a one-item list."""
    if isinstance(d, dict) and isinstance(d.get(key), list):
        return d[key]
    return _ls(d) if not isinstance(d, dict) or key not in d else []


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Administration
# ═══════════════════════════════════════════════════════════════════════

def zdx_admin_apps(cl):
    """ZDX monitored applications — SaaS + internal apps under ZDX scoring"""
    d, c = cl.get("/zdx/administration/apps", _SINCE)
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX apps endpoint not accessible — ZDX subscription may not be active.")
    if not items:
        return R(R.WARN, "No applications with ZDX activity in the last 24 hours. Best Practice: monitor the top 10 SaaS apps your users depend on (O365, Salesforce, Zoom, ServiceNow, etc.) so ZDX can score their health.")
    return R(R.PASS, f"{len(items)} application(s) with ZDX activity in the last 24 hours.")


def zdx_admin_locations(cl):
    """ZDX location coverage"""
    d, c = cl.get("/zdx/administration/locations", _SINCE)
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX locations endpoint not accessible.")
    if not items:
        return R(R.INFO, "No locations seen by ZDX in the last 24 hours. ZDX auto-derives locations from device telemetry; explicit locations improve reporting.")
    return R(R.PASS, f"{len(items)} location(s) seen by ZDX in the last 24 hours.")


def zdx_admin_departments(cl):
    """ZDX department segmentation for scoped reporting"""
    d, c = cl.get("/zdx/administration/departments", _SINCE)
    items = _ls(d) if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX departments endpoint not accessible.")
    if not items:
        return R(R.WARN, "No departments seen by ZDX in the last 24 hours. Best Practice: Populate departments from your IdP so ZDX dashboards show per-team health — Finance hitting SAP, Engineering hitting GitHub, etc.")
    return R(R.PASS, f"{len(items)} department(s) seen by ZDX in the last 24 hours.")


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
    # The body is {"next_offset": …, "alerts": [...]} (SDK zdx/models/alerts.py Alerts).
    items = _wrapped(d, "alerts") if c in (200, 204) else []
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
    # The body is {"next_offset": …, "software": [...]} (SDK zdx/models/software_inventory.py SoftwareList).
    items = _wrapped(d, "software") if c in (200, 204) else []
    if c in (401, 403):
        return R(R.INFO, "ZDX software inventory not accessible.")
    if not items:
        return R(R.INFO, "No software inventory data. If ZDX has been running for 24+ hours, software should be populated.")
    more = " (first page; more records follow)" if isinstance(d, dict) and d.get("next_offset") else ""
    return R(R.PASS, f"{len(items)} software record(s) collected by ZDX{more} — usable for vuln tracking and license audits.")


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
    """ZDX device telemetry reachable (active devices; deep traces are per device)"""
    d, c = cl.get("/zdx/troubleshooting/devices", _SINCE)
    if c in (401, 403):
        return R(R.INFO, "ZDX devices endpoint not accessible.")
    if c in (200, 204):
        # The body is {"next_offset": …, "devices": [...]} (SDK zdx/models/devices.py Devices).
        devs = _wrapped(d, "devices")
        return R(R.PASS, f"ZDX device telemetry reachable: {len(devs)} active device(s) seen in the last 24 hours. Deep traces are per device (/devices/{{id}}/deeptraces) and are not read here.")
    return R(R.INFO, f"ZDX devices endpoint returned HTTP {c}.")


# ═══════════════════════════════════════════════════════════════════════
# ZDX — Alert history, application scores and metrics (2026-10-31)
# ═══════════════════════════════════════════════════════════════════════
# SDK 1.11.3 (verified): alerts.list_historical      GET /zdx/v1/alerts/historical (max 14 days back)
#                        alerts.list_affected_devices GET /zdx/v1/alerts/{id}/affected_devices
#                        apps.get_app_score          GET /zdx/v1/apps/{id}/score   ({metric, unit, datapoints[{timestamp, value}]})
#                        apps.get_app_metrics        GET /zdx/v1/apps/{id}/metrics ([{metric, unit, datapoints}]; metric_name pft|dns|availability)
# Personal data is counted, never listed: affected devices are a number.

POOR_SCORE = 66            # ZDX scores 66-100 as good; below is okay or poor (ZDX Admin Portal legend)
_HISTORY = {"since": 336}  # 14 days, the documented limit for the alert history
_WEEK = {"since": 168}
MAX_APPS = 25              # applications whose score and metrics are read in one run
MAX_ALERTS = 20            # alerts whose affected devices are counted
AVAILABILITY_MIN = 99.0    # assumed target: an app available less than 99% of the week needs a look
PFT_MAX_MS = 5000.0        # assumed target: a page fetch time above 5 s is slow for users


def _not_licensed(c, what):
    """N/A (outside the score) when the tenant has no ZDX: the API answers 404."""
    if c == 404:
        return R(R.INFO, f"Not applicable: {what} is not available, so ZDX is probably not licensed on this tenant.")
    return None


def _num(v):
    if isinstance(v, bool):
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if f == f and abs(f) != float("inf") else None   # no NaN or infinity from an untrusted answer


def _values(series):
    """The numeric values of one {metric, unit, datapoints} series (capped)."""
    pts = series.get("datapoints") if isinstance(series, dict) else None
    out = []
    for p in (pts if isinstance(pts, list) else [])[:2000]:
        v = _num(p.get("value")) if isinstance(p, dict) else None
        # ZDX marks an hour with no data as -1 (assumed); it is not a score.
        if v is not None and v >= 0:
            out.append(v)
    return out


def _apps(cl):
    d, c = cl.get("/zdx/administration/apps", _WEEK)
    if c not in (200, 204):
        return None, c
    return [a for a in _ls(d) if isinstance(a, dict) and a.get("id") not in (None, "")][:MAX_APPS], c


def _app_name(a):
    return str(a.get("name") or a.get("id"))[:80]


def zdx_alert_history(cl):
    """ZDX alert history (14 days) and the devices each alert touched, counted"""
    d, c = cl.get("/zdx/alerts/historical", _HISTORY)
    na = _not_licensed(c, "the ZDX alert history")
    if na:
        return na
    if c in (401, 403):
        return R(R.INFO, "ZDX alert history endpoint not accessible.")
    if c not in (200, 204):
        return R(R.INFO, f"ZDX alert history returned HTTP {c}.")
    alerts = [a for a in _wrapped(d, "alerts") if isinstance(a, dict)]
    if not alerts:
        return R(R.PASS, "No ZDX alert ended in the last 14 days.")
    sev = {}
    for a in alerts:
        k = str(a.get("severity") or "unknown").lower()[:20]
        sev[k] = sev.get(k, 0) + 1
    devices, unread = set(), 0
    for a in alerts[:MAX_ALERTS]:
        aid = str(a.get("id") or "")
        if not aid or not aid.replace("-", "").isalnum() or len(aid) > 40:
            continue
        dd, dc = cl.get(f"/zdx/alerts/{aid}/affected_devices", _HISTORY)
        if dc not in (200, 204):
            unread += 1
            continue
        for dev in _wrapped(dd, "devices"):
            if isinstance(dev, dict) and dev.get("id") not in (None, ""):
                devices.add(str(dev["id"]))
    mix = ", ".join(f"{n} {k}" for k, n in sorted(sev.items()))
    more = f" (devices counted for the first {MAX_ALERTS} alerts)" if len(alerts) > MAX_ALERTS else ""
    gap = f" The affected devices of {unread} alert(s) could not be read." if unread else ""
    return R(R.WARN, f"{len(alerts)} ZDX alert(s) ended in the last 14 days ({mix}), touching {len(devices)} device(s){more}.{gap} "
                     "Why it matters: alerts that keep coming back point at an application, a network or a location that hurts users every week. "
                     "Best Practice: review the repeat alerts with the application owner and fix the cause (the alert's application and location say where), "
                     "then tune the alert rule so it fires only for what someone acts on.",
             {"alerts": len(alerts), "severity": sev, "affected_devices": len(devices)})


def zdx_app_scores(cl):
    """Applications whose ZDX score stayed below 66 for the last 7 days"""
    apps, c = _apps(cl)
    if apps is None:
        na = _not_licensed(c, "the ZDX application list")
        if na:
            return na
        return R(R.INFO, "ZDX applications endpoint not accessible." if c in (401, 403) else f"ZDX applications returned HTTP {c}.")
    if not apps:
        return R(R.INFO, "No application with ZDX activity in the last 7 days, so no score to judge.")
    poor, read, unread = [], 0, 0
    for a in apps:
        aid = str(a["id"])
        if not aid.isdigit() or len(aid) > 20:
            continue
        d, sc = cl.get(f"/zdx/apps/{aid}/score", _WEEK)
        if sc not in (200, 204):
            unread += 1
            continue
        series = d if isinstance(d, dict) else (next((x for x in d if isinstance(x, dict)), {}) if isinstance(d, list) else {})
        vals = _values(series)
        if not vals:
            continue
        read += 1
        if max(vals) < POOR_SCORE:
            poor.append((_app_name(a), round(sum(vals) / len(vals), 1)))
    gap = f" {unread} application score(s) could not be read." if unread else ""
    if not read:
        return R(R.INFO, "No ZDX score trend was available for the last 7 days." + gap)
    if poor:
        names = "; ".join(f"{n} (average {v})" for n, v in poor[:10])
        return R(R.WARN, f"{len(poor)} of {read} application(s) never reached a ZDX score of {POOR_SCORE} in the last 7 days: {names}.{gap} "
                         "Why it matters: users of these applications have had a slow or failing experience all week, and the tickets usually blame Zscaler. "
                         "Best Practice: open the application in ZDX, find the leg that is slow (device, Wi-Fi, ISP, Zscaler, or the application itself) "
                         "and fix it there; run a ZDX score analysis on an affected device to get the root cause.",
                 {"poor": len(poor), "read": read})
    return R(R.PASS, f"Every application with a score trend ({read}) reached a ZDX score of {POOR_SCORE} or more at some point in the last 7 days.{gap}")


def zdx_app_metrics(cl):
    """Application availability and page fetch time over the last 7 days"""
    apps, c = _apps(cl)
    if apps is None:
        na = _not_licensed(c, "the ZDX application list")
        if na:
            return na
        return R(R.INFO, "ZDX applications endpoint not accessible." if c in (401, 403) else f"ZDX applications returned HTTP {c}.")
    if not apps:
        return R(R.INFO, "No application with ZDX activity in the last 7 days, so no metric to judge.")
    low, slow, read, unread = [], [], 0, 0
    for a in apps:
        aid = str(a["id"])
        if not aid.isdigit() or len(aid) > 20:
            continue
        d, mc = cl.get(f"/zdx/apps/{aid}/metrics", _WEEK)
        if mc not in (200, 204):
            unread += 1
            continue
        rows = d if isinstance(d, list) else ([d] if isinstance(d, dict) else [])
        got = False
        for s in rows[:20]:
            if not isinstance(s, dict):
                continue
            vals = _values(s)
            if not vals:
                continue
            got = True
            avg = sum(vals) / len(vals)
            m = str(s.get("metric") or "").lower()
            if m == "availability" and avg < AVAILABILITY_MIN:
                low.append((_app_name(a), round(avg, 1)))
            elif m == "pft" and avg > PFT_MAX_MS:
                slow.append((_app_name(a), round(avg / 1000.0, 1)))
        read += 1 if got else 0
    gap = f" The metrics of {unread} application(s) could not be read." if unread else ""
    if not read:
        return R(R.INFO, "No ZDX application metric was available for the last 7 days." + gap)
    if low or slow:
        parts = []
        if low:
            parts.append(f"available less than {AVAILABILITY_MIN:g}% of the time: " + "; ".join(f"{n} ({v}%)" for n, v in low[:10]))
        if slow:
            parts.append(f"page fetch time above {PFT_MAX_MS / 1000:g} s on average: " + "; ".join(f"{n} ({v} s)" for n, v in slow[:10]))
        return R(R.WARN, f"Of {read} application(s) with metrics in the last 7 days, " + "; ".join(parts) + f".{gap} "
                         "Why it matters: an application that is often unreachable or slow costs working hours and gets blamed on the security stack. "
                         "Best Practice: compare the CloudPath of a good and a bad location in ZDX; fix DNS, the ISP or the application's own hosting, "
                         "or move users to a closer Zscaler data centre.",
                 {"low_availability": len(low), "slow": len(slow), "read": read})
    return R(R.PASS, f"All {read} application(s) with metrics were available {AVAILABILITY_MIN:g}% of the time or more, with an average page fetch time under {PFT_MAX_MS / 1000:g} s, in the last 7 days.{gap}")


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
    ("ZDX.8", "ZDX — Troubleshooting","ZDX device telemetry reachable",  zdx_troubleshoot),
    ("ZDX.9", "ZDX — Alerts",         "Alert history and affected devices (14 days)", zdx_alert_history),
    ("ZDX.10", "ZDX — Experience",    "Applications below a ZDX score of 66 for 7 days", zdx_app_scores),
    ("ZDX.11", "ZDX — Experience",    "Application availability and page fetch time", zdx_app_metrics),
]
ZDX_REG = guard_registry(ZDX_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged
