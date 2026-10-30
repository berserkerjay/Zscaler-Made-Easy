"""Which fields of a policy rule each Path analyzer module reads, which
are known not to restrict the match, and therefore which conditions are
"unknown".

The rule is inverted on purpose. Each module lists the fields its
evaluator DOES evaluate (EVALUATED) and the fields known to be neutral:
metadata (id, name, order, rank, description, state, last modified, labels)
and what happens after a match (an action's options, a notification, a
logging switch) (NEUTRAL). A condition this tool knows it does not
evaluate (a user, a time window, device trust, ...) has a name and a reason
in zia_path_modules.UNEVALUATED (or LABELLED here). ANY other non-empty
field on a rule is an unknown condition automatically: a field a newer API
adds, or one this tool has never heard of, is never silently ignored, so a
rule that carries it can never be a definite match.

Field names are compared without case or underscores, so the raw API's
camelCase (destIpGroups), the SDK's snake_case (dest_ip_groups) and
capitalisation drift (capturePCAP / capturePcap) are one field.

Every field of the zscaler-sdk-python 1.11.3 models is classified (the
test tests/test_rule_fields.py holds a copy of each model's field list and
checks it against the installed SDK when that is 1.11.3):
  url       zia/models/url_filtering_rules.py URLFilteringRule
  cac       zia/models/cloudappcontrol.py CloudApplicationControl
  ssl       zia/models/ssl_inspection_rules.py SSLInspectionRules
  ftc       zia/models/filetyperules.py FileTypeControlRules
  dlp       zia/models/dlp_web_rules.py DLPWebRules
  firewall  zia/models/cloud_firewall_rules.py FirewallRule
  dns       zia/models/cloud_firewall_dns_rules.py FirewallDNSRules
  sandbox   zia/models/sandboxrules.py SandboxRules
  atp       zia/models/advanced_threat_settings.py AdvancedThreatProtectionSettings
  zpa       zpa/models/policyset_controller_v1.py PolicySetControllerV1 and
            policyset_controller_v2.py PolicySetControllerV2 (access and
            client forwarding policy rules)

Pure: nothing here reads or writes a tenant.
"""
from __future__ import annotations

import re
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Tuple

MODULES = ("url", "cac", "ssl", "ftc", "dlp", "firewall", "dns", "sandbox", "atp", "zpa")


def norm(field: Any) -> str:
    """A field name without case or separators: destIpGroups, dest_ip_groups
    and DESTIPGROUPS are one field."""
    return re.sub(r"[^a-z0-9]", "", str(field or "").lower())


def _set(*names: str) -> FrozenSet[str]:
    return frozenset(norm(n) for n in names)


# Metadata every rule carries: never a condition.
_META = ("id", "name", "order", "rank", "description", "state", "lastModifiedTime", "lastModifiedBy", "labels", "accessControl",
         "predefined", "defaultRule", "readOnly", "createdBy", "creationTime", "modifiedBy", "modifiedTime")

# ── What each evaluator reads ────────────────────────────────────────
# url, cac, ssl, ftc, dlp: data_flow.trace with ssl_flow's normalisation
# and zia_path_modules._generic_criteria; firewall, dns, sandbox, atp:
# zia_path_modules._firewall, _dns, _sandbox, _atp; zpa: zpa_analysis.
# evaluate_rule (the operands it cannot evaluate are named by operand type).
EVALUATED: Dict[str, FrozenSet[str]] = {
    # (applications, cloudApplications and cloudAppClasses: data_flow.
    # _norm_generic reads all three for the URL, Cloud App Control and File
    # Type Control rules; cloudAppClasses is not an SDK 1.11.3 field.)
    "url": _set("urlCategories", "protocols", "requestMethods", "action", "enforceTimeValidity", "validityStartTime",
                "validityEndTime", "validityTimeZoneId", "applications", "cloudApplications", "cloudAppClasses"),
    "cac": _set("applications", "cloudApplications", "cloudAppClasses", "type", "actions", "action", "enforceTimeValidity",
                "validityStartTime", "validityEndTime", "validityTimeZoneId"),
    "ssl": _set("urlCategories", "cloudApplications", "action"),
    "ftc": _set("urlCategories", "applications", "cloudApplications", "cloudAppClasses", "fileTypes", "operation", "filteringAction",
                "action", "protocols"),
    "dlp": _set("urlCategories", "cloudApplications", "protocols", "dlpEngines", "action", "withoutContentInspection"),
    "firewall": _set("srcIps", "srcIpGroups", "srcIpv6Groups", "destAddresses", "destIpCategories", "destCountries", "destIpGroups",
                     "destIpv6Groups", "nwServices", "nwServiceGroups", "nwApplications", "nwApplicationGroups", "action"),
    "dns": _set("srcIps", "srcIpGroups", "srcIpv6Groups", "destAddresses", "destIpCategories", "destCountries", "destIpGroups",
                "destIpv6Groups", "protocols", "dnsRuleRequestTypes", "resCategories", "applications", "applicationGroups", "action"),
    "sandbox": _set("urlCategories", "protocols", "fileTypes", "baPolicyCategories", "byThreatScore", "baRuleAction",
                    "firstTimeEnable", "firstTimeOperation"),
    # ATP settings: the category toggles zia_path_modules.ATP_CATEGORIES maps,
    # the blocked countries and the page risk tolerance (a note).
    "atp": _set("malwareSitesBlocked", "knownPhishingSitesBlocked", "suspectedPhishingSitesBlocked", "cmdCtlServerBlocked",
                "suspectAdwareSpywareSitesBlocked", "adSpywareSitesBlocked", "webspamBlocked", "potentialMaliciousRequestsBlocked",
                "browserExploitsBlocked", "cryptoMiningBlocked", "anonymizerBlocked", "bitTorrentBlocked", "torBlocked",
                "dgaDomainsBlocked", "blockedCountries", "riskTolerance"),
    "zpa": _set("conditions", "operator", "action", "actionId", "disabled", "ruleOrder", "priority"),
}

# ── Known not to restrict the match ──────────────────────────────────
# Metadata, and what a rule does after it matches (an isolation profile, a
# notification, a block override, logging): the match is the same with or
# without them.
NEUTRAL: Dict[str, FrozenSet[str]] = {
    "url": _set(*_META, "blockOverride", "overrideUsers", "overrideGroups", "cbiProfile", "ciparule", "endUserNotificationUrl",
                "httpHeaderActionProfiles"),
    "cac": _set(*_META, "cbiProfile", "eunEnabled", "eunTemplateId", "browserEunTemplateId", "tenancyProfileIds"),
    "ssl": _set(*_META),
    "ftc": _set(*_META, "capturePCAP"),
    "dlp": _set(*_META, "auditor", "externalAuditorEmail", "icapServer", "notificationTemplate", "eunTemplateId", "severity",
                "matchOnly", "zccNotificationsEnabled", "zscalerIncidentReceiver", "parentRule", "subRules",
                "dlpDownloadScanEnabled", "inspectHttpGetEnabled"),
    "firewall": _set(*_META, "enableFullLogging", "capturePCAP", "excludeSrcCountries"),
    "dns": _set(*_META, "blockResponseCode", "capturePCAP", "defaultDnsRuleNameUsed", "dnsGateway", "ednsEcsObject",
                "isWebEunEnabled", "redirectIp", "zpaIpGroup"),
    "sandbox": _set(*_META, "mlActionEnabled", "cbiProfile", "cbiProfileId"),
    # ATP: the packet-capture switches, an alert-only switch, and toggles
    # whose detection acts on the traffic's content at run time (named in
    # the module's notes as such, never predicted from configuration).
    "atp": _set("activeXCapture", "adSpywareSitesCapture", "anonymizerCapture", "bitTorrentCapture", "blockCountriesCapture",
                "browserExploitsCapture", "cmdCtlServerCapture", "cmdCtlTrafficCapture", "cookieStealingPCAPEnabled", "cryptoMiningCapture",
                "dgaDomainsCapture", "fileFormatVunerabilitesCapture", "googleTalkCapture", "ircTunnellingCapture", "knownPhishingSitesCapture",
                "maliciousUrlsCapture", "malwareSitesCapture", "potentialMaliciousRequestsCapture", "riskToleranceCapture",
                "sshTunnellingCapture", "suspectAdwareSpywareSitesCapture", "suspectedPhishingSitesCapture", "torCapture", "webspamCapture",
                "alertForUnknownOrSuspiciousC2Traffic"),
    # ZPA: what the rule does once it matches (connector and server groups,
    # inspection, isolation and credential profiles, messages, re-auth
    # timers) and metadata. restrictionType is taken as metadata (assumed:
    # the SDK documents it only as "the restriction type").
    "zpa": _set(*_META, "microtenantId", "microtenantName", "policySetId", "policyType", "zscalerManaged", "version", "customMsg",
                "reauthIdleTimeout", "reauthTimeout", "devicePostureFailureNotificationEnabled", "appServerGroups", "appConnectorGroups",
                "serviceEdgeGroups", "zpnInspectionProfileId", "zpnInspectionProfileName", "zpnIsolationProfileId", "credential",
                "credentialPool", "privilegedCapabilities", "privilegedPortalCapabilities", "postActions", "postActionTypes",
                "desktopPolicyMappings", "restrictionType", "buttonText", "url"),
}

# ATP toggles whose detection runs on the content at run time: named in the
# module's notes when on (never a configuration-time match).
ATP_CONTENT = (("activeXBlocked", "ActiveX controls"), ("cmdCtlTrafficBlocked", "command-and-control traffic"),
               ("cookieStealingBlocked", "cookie stealing"), ("fileFormatVunerabilitesBlocked", "file format vulnerabilities"),
               ("googleTalkBlocked", "Google Talk"), ("ircTunnellingBlocked", "IRC tunnelling"), ("sshTunnellingBlocked", "SSH tunnelling"))
NEUTRAL["atp"] = NEUTRAL["atp"] | _set(*(k for k, _ in ATP_CONTENT))

# ── Conditions known not to be evaluated, beyond zia_path_modules.UNEVALUATED
# field -> (label, why). Each present on a rule is an unknown criterion.
LABELLED: Dict[str, Tuple[str, str]] = {
    "urlCategories2": ("Second URL category set", "the rule also needs a category from a second set (the two sets are joined by AND), which is not evaluated here"),
    "httpHeaderProfiles": ("HTTP header profile", "the request's HTTP headers are not part of the trace"),
    "sizeQuota": ("Size quota", "how much the user has already transferred is not known"),
    "timeQuota": ("Time quota", "how long the user has already browsed is not known"),
    "cloudAppInstances": ("Cloud app instances", "which instance (tenant) of the application is used is not known"),
    "cloudAppRiskProfile": ("Cloud app risk profile", "the application's risk attributes are not evaluated here"),
    "sharingDomainProfiles": ("Sharing domain profile", "who a file is shared with is not part of the trace"),
    "formSharingDomainProfiles": ("Form sharing domain profile", "who a form is shared with is not part of the trace"),
    "cascadingEnabled": ("Cascading to URL filtering", "with cascading on, URL filtering also applies after this rule; this tool assumes Cloud App Control decides alone"),
    "proxyGateways": ("Proxy gateways", "whether the traffic is chained to a third-party proxy is not part of the trace"),
    "roadWarriorForKerberos": ("Kerberos road warriors", "whether the user authenticates with Kerberos off the corporate network is not known"),
    "activeContent": ("Active content", "whether the file holds active content (macros) is decided on the file itself"),
    "unscannable": ("Unscannable file", "whether the file can be scanned is decided on the file itself"),
    "passwordProtected": ("Password-protected file", "whether the file is password protected is decided on the file itself"),
    "minSize": ("Minimum file size", "the size of the file is not part of the trace"),
    "maxSize": ("Maximum file size", "the size of the file is not part of the trace"),
    "includedDomainProfiles": ("Included domain profile", "the destination domains a profile lists are not evaluated here"),
    "excludedDomainProfiles": ("Excluded domain profile", "the destination domains a profile lists are not evaluated here"),
    "dlpContentLocationsScopes": ("Content location", "where the content sits in the application is not part of the trace"),
    "extranetEnabled": ("Extranet", "whether the request comes over an extranet is not part of the trace"),
    "extranetDTO": ("Extranet", "whether the request comes over an extranet is not part of the trace"),
    "browserPostureName": ("Browser posture", "the browser's posture is not known"),
    "browserPostureProfileId": ("Browser posture", "the browser's posture is not known"),
}
# Web DLP's file type condition: decided on the content, never on the URL.
LABELLED_PER_MODULE: Dict[str, Dict[str, Tuple[str, str]]] = {
    "dlp": {"fileTypes": ("File type", "which file the upload carries is decided on the content")},
    # An SSL rule's destination IP groups: ssl_flow counts them as a target
    # but matches on categories and applications only.
    "ssl": {"destIpGroups": ("Destination IP groups", "the destination's IP address is not resolved here")},
}

_EMPTY_WORDS = {"", "ANY", "ALL", "NONE", "ANY_RULE", "NULL"}


def empty(v: Any) -> bool:
    """A value that sets no condition: None, False, 0, an empty string,
    list or object, ANY / ALL / NONE, or an object or list of only such."""
    if v is None or v is False:
        return True
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return v == 0
    if isinstance(v, str):
        return v.strip().upper() in _EMPTY_WORDS
    if isinstance(v, dict):
        return all(empty(x) for x in v.values())
    if isinstance(v, (list, tuple, set)):
        return all(empty(x) for x in v)
    return False


def classify(module: str, field: str, labelled: Iterable[str] = ()) -> str:
    """'evaluated', 'neutral', 'labelled' (a named unknown condition) or
    'unknown' (a field this tool does not know)."""
    k = norm(field)
    if k in EVALUATED.get(module, frozenset()):
        return "evaluated"
    if k in NEUTRAL.get(module, frozenset()):
        return "neutral"
    if k in {norm(x) for x in labelled} or k in _LABELLED_N or k in _PER_MODULE_N.get(module, {}):
        return "labelled"
    return "unknown"


_LABELLED_N = {norm(k): v for k, v in LABELLED.items()}
_PER_MODULE_N = {m: {norm(k): v for k, v in d.items()} for m, d in LABELLED_PER_MODULE.items()}


def label_of(module: str, field: str) -> Optional[Tuple[str, str]]:
    k = norm(field)
    return _PER_MODULE_N.get(module, {}).get(k) or _LABELLED_N.get(k)


def _shown(v: Any) -> List[str]:
    """What a value names, for the criterion's words."""
    if isinstance(v, dict):
        x = v.get("name") or v.get("id") or v.get("value")
        return [str(x)] if x not in (None, "") else ([f"{len(v)} setting(s)"] if v else [])
    if isinstance(v, (list, tuple, set)):
        out: List[str] = []
        for x in v:
            if not empty(x):
                out += _shown(x)
        return out
    if v is True:
        return ["on"]
    return [str(v)[:80]]


def other_fields(rule: Dict[str, Any], module: str, labelled: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """The non-empty fields of `rule` that `module` neither evaluates nor
    knows to be neutral, and that are not in `labelled` (the caller's own
    named list): [{field, label, why, values, kind: labelled | unknown}],
    one per field, in the rule's own order. A field this tool has never
    heard of is kind "unknown"."""
    if not isinstance(rule, dict):
        return []
    skip = {norm(x) for x in labelled}
    seen = set()
    out: List[Dict[str, Any]] = []
    for field, value in rule.items():
        if not isinstance(field, str) or field.startswith("_") or empty(value):
            continue
        k = norm(field)
        if k in seen or k in skip:
            continue
        seen.add(k)
        c = classify(module, field)
        if c in ("evaluated", "neutral"):
            continue
        lab = label_of(module, field)
        if lab:
            out.append({"field": field, "label": lab[0], "why": lab[1], "values": _shown(value)[:6], "kind": "labelled"})
        else:
            out.append({"field": field, "label": f"Other condition ({field[:60]})",
                        "why": "this tool does not evaluate that field, so the rule is never treated as a definite match",
                        "values": _shown(value)[:6], "kind": "unknown"})
    return out
