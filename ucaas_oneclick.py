"""ZIA's UCaaS one-click configuration: what the API exposes, and how the
Path analyzer reads the predefined rules it turns on.

What the API exposes (zscaler-sdk-python 1.11.3, zia/url_filtering.py
get_url_and_app_settings / update_url_and_app_settings, GET and PUT
/advancedUrlFilterAndCloudAppSettings; model
zia/models/url_filter_cloud_app_settings.py
AdvancedUrlFilterAndCloudAppSettings): one switch per UCaaS provider,
"Automatically permit secure breakout for <provider> traffic":
enableUcaasZoom, enableUcaasWebex, enableUcaasRingCentral,
enableUcaasLogMeIn (GoTo) and enableUcaasTalkdesk. Microsoft Teams has no
UCaaS switch of its own: it is part of the Microsoft 365 one-click
configuration, enableOffice365 ("Enables Microsoft Office 365
configuration in the policy"). The SDK has no call that creates the
one-click rules themselves: they are Zscaler's predefined rules, which ZIA
adds and keeps while a switch is on.

The predefined rules (as ZIA shows them; names and fields assumed from
the admin portal, not from the SDK): a Cloud Firewall rule "UCaaS One Click
Rule" (Allow, predefined, its appServiceGroups naming the providers, such
as ZOOM and WEBEX), the matching DNS Control rule, an SSL inspection rule
that does not inspect the providers' cloud applications, and the
"Office 365 One Click Rule" for Microsoft 365. Matching their app service
groups by domain and address is another module's work (the app service
groups); here a predefined one-click rule gets one more criterion, the
switch behind it: on, the rule is live for that provider; off for every
provider it names, ZIA does not apply it (assumed: the switch turns the
rule off), so it is never a match; not read, no criterion is added and the
rule's own state decides.

Zscaler's guidance is to let real-time voice and video break out without
inspection (latency-sensitive media, often pinned or over UDP). The
baseline builder therefore pre-sets every switch on for the Balanced,
Permissive and Healthcare zero trust tiers, and off for Strict, whose
promise is to inspect all TLS (this tool's choice, said in the review).
Pure: nothing here reads or writes a tenant.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

ENDPOINT = "/zia/advancedUrlFilterAndCloudAppSettings"
SOURCE = ("zscaler-sdk-python 1.11.3: zia.url_filtering.get_url_and_app_settings / update_url_and_app_settings "
          "(GET and PUT /advancedUrlFilterAndCloudAppSettings)")

# (field, label, the app service group / cloud application names a
# predefined one-click rule uses for it: names assumed, compared without
# case or separators).
SETTINGS: List[Tuple[str, str, Tuple[str, ...]]] = [
    ("enableUcaasZoom", "Zoom", ("ZOOM",)),
    ("enableOffice365", "Microsoft Teams (Microsoft 365 one-click)", ("OFFICE365", "MICROSOFT365", "MICROSOFTTEAMS", "MSTEAMS", "M365")),
    ("enableUcaasWebex", "Webex", ("WEBEX",)),
    ("enableUcaasRingCentral", "RingCentral", ("RINGCENTRAL",)),
    ("enableUcaasLogMeIn", "GoTo (LogMeIn)", ("LOGMEIN", "GOTO", "GOTOMEETING", "GOTOCONNECT")),
    ("enableUcaasTalkdesk", "Talkdesk", ("TALKDESK",)),
]
KEYS = tuple(k for k, _, _ in SETTINGS)
LABEL = {k: label for k, label, _ in SETTINGS}
# The tiers whose baseline pre-sets every switch on (see the docstring).
TIERS_ON = ("balanced", "permissive", "healthcare")
_NAME = re.compile(r"one[\s_-]*click", re.I)


def _n(s: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(s or "").upper())


_BY_NAME = {_n(n): k for k, _, names in SETTINGS for n in names}


def default_on(tier: str) -> bool:
    return str(tier or "").lower() in TIERS_ON


def setting_for(name: Any) -> Optional[str]:
    """The switch behind an app service group or cloud application name, or None."""
    return _BY_NAME.get(_n(name))


def values(settings: Any) -> Optional[Dict[str, bool]]:
    """{field: on} for every switch the settings object carries, or None
    when there is no settings object."""
    if not isinstance(settings, dict):
        return None
    out = {}
    for k in KEYS:
        snake = re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()
        v = settings.get(k, settings.get(snake))
        if isinstance(v, bool):
            out[k] = v
    return out


def _names(v: Any) -> List[str]:
    out = []
    for x in v if isinstance(v, (list, tuple)) else []:
        if isinstance(x, dict):
            x = x.get("name") or x.get("id")
        if x not in (None, ""):
            out.append(str(x))
    return out


def oneclick_switches(rule: Dict[str, Any]) -> List[str]:
    """The switches behind a predefined one-click rule (from the app
    service groups or cloud applications it names), or [] for any other
    rule."""
    if not isinstance(rule, dict) or not (rule.get("predefined") is True and _NAME.search(str(rule.get("name") or ""))):
        return []
    names = _names(rule.get("appServiceGroups") or rule.get("app_service_groups")) + _names(rule.get("appServices") or rule.get("app_services")) \
        + _names(rule.get("cloudApplications") or rule.get("cloud_applications"))
    keys = [setting_for(n) for n in names]
    found = list(dict.fromkeys(k for k in keys if k))
    if not found and re.search(r"office\s*365|microsoft", str(rule.get("name") or ""), re.I):
        found = ["enableOffice365"]
    return found


def criterion(rule: Dict[str, Any], settings: Optional[Dict[str, bool]]) -> Optional[Dict[str, str]]:
    """The one-click switch as a criterion of a predefined one-click rule:
    match when a switch it depends on is on, no match when every one is
    off, nothing when the switches were not read (or it is not such a rule)."""
    keys = oneclick_switches(rule)
    if not keys or settings is None:
        return None
    known = {k: settings[k] for k in keys if k in settings}
    if not known:
        return None
    on = [LABEL[k] for k, v in known.items() if v]
    if on:
        return {"name": "One-click setting", "state": "match",
                "detail": f"The one-click configuration is on for {', '.join(on)} (URL and Cloud App Control advanced settings)."}
    if len(known) == len(keys):
        return {"name": "One-click setting", "state": "no_match",
                "detail": f"The one-click configuration is off for {', '.join(LABEL[k] for k in keys)}, so ZIA does not apply this predefined rule (assumed)."}
    return None


def summary(settings: Optional[Dict[str, bool]]) -> Optional[str]:
    """One line naming each switch on or off, for the Path analyzer's notes."""
    if not settings:
        return None
    parts = [f"{LABEL[k]} {'on' if settings[k] else 'off'}" for k in KEYS if k in settings]
    return ("UCaaS one-click (URL and Cloud App Control advanced settings): " + ", ".join(parts) + ".") if parts else None
