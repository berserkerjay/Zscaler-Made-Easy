#!/usr/bin/env python3
"""
DLP policy channels — how each rule type is listed, built, created, and
what it needs from the tenant before it can exist.

A pack policy picks its channel with ``"channel"`` (default ``web``):

    web       Inline web DLP            zia.dlp_web_rules            /webDlpRules
    endpoint  Endpoint DLP (ZCC)        zia.endpoint_dlp_rules       /endPointDlpRules
    saas      SaaS Security API (CASB)  zia.casb_dlp_rules           /casbDlpRules
    email     Outbound Email DLP        zia.outbound_email_dlp_rules /emailDlpRules

Every channel shares the dictionary → engine chain. On top of that each
one has tenant prerequisites that a pack cannot ship — they are resolved
by name against the live tenant during preflight and reported as
dependencies, so a rule is never created half-wired:

    endpoint  the Endpoint DLP rule API must answer (feature licensed and
              Zscaler Client Connector deployed); optional notification
              template / rule labels by name
    saas      at least one SaaS application tenant onboarded whose app
              matches the rule type (Box for OFLCASB_DLP_FILE, Slack for
              OFLCASB_DLP_COLLAB, ...); optional labels
    email     an email tenant (Microsoft 365 / Gmail) onboarded under
              SaaS Security; optional notification template / labels

Payloads follow the ZIA API wire schema: the SDK camel-cases keys and
sends the body verbatim for these services, so ID references are passed
as ``[{"id": ...}]`` objects (the web-rule service does that conversion
itself; the others do not).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

WEB, ENDPOINT, SAAS, EMAIL = "web", "endpoint", "saas", "email"
# Containment channels: rules that restrict the CHANNEL or PAYLOAD rather
# than inspect content. They have no dictionary/engine dependency.
CLOUD_APP, FILE_TYPE, URL, SSL = "cloud_app", "file_type", "url", "ssl"

CHANNELS: Dict[str, Dict[str, Any]] = {
    WEB: {
        "label": "Web DLP",
        "long": "Inline web DLP (ZIA)",
        "service": "dlp_web_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CONFIRM", "ICAP_RESPONSE"},
        "rule_cap": 127,
        "needs_casb": False,
        "engines": True,
    },
    ENDPOINT: {
        "label": "Endpoint DLP",
        "long": "Endpoint DLP (Zscaler Client Connector)",
        "service": "endpoint_dlp_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CONFIRM"},
        "rule_cap": None,
        "needs_casb": False,
        "engines": True,
    },
    SAAS: {
        "label": "SaaS Security API",
        "long": "SaaS Security API (out-of-band CASB) DLP",
        "service": "casb_dlp_rules",
        "monitor_actions": {"OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW"},
        "enforcing_actions": None,  # anything that is not a monitor action
        "rule_cap": None,
        "needs_casb": True,
        "engines": True,
    },
    EMAIL: {
        "label": "Email DLP",
        "long": "Outbound Email DLP",
        "service": "outbound_email_dlp_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CUSTOMHEADERINSERTION"},
        "rule_cap": None,
        "needs_casb": True,
        "engines": True,
    },
    CLOUD_APP: {
        "label": "Cloud App Control",
        "long": "Cloud App Control (per-application actions: upload, share, send...)",
        "service": "cloudappcontrol",
        "monitor_actions": set(),        # decided per action: any BLOCK_/ISOLATE_ action enforces
        "enforcing_actions": None,
        "rule_cap": None,
        "needs_casb": False,
        "engines": False,
    },
    FILE_TYPE: {
        "label": "File Type Control",
        "long": "File Type Control (upload/download of file categories)",
        "service": "file_type_control_rule",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CAUTION"},
        "rule_cap": None,
        "needs_casb": False,
        "engines": False,
    },
    URL: {
        "label": "URL Filtering",
        "long": "URL Filtering (categories, methods, protocols)",
        "service": "url_filtering",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CAUTION", "ISOLATE", "ICAP_RESPONSE"},
        "rule_cap": None,
        "needs_casb": False,
        "engines": False,
    },
    SSL: {
        "label": "SSL Inspection",
        "long": "SSL Inspection (decrypt / do not decrypt / block)",
        "service": "ssl_inspection_rules",
        "monitor_actions": {"DO_NOT_DECRYPT"},
        "enforcing_actions": {"DECRYPT", "BLOCK"},
        "rule_cap": None,
        "needs_casb": False,
        "engines": False,
    },
}
CONTROL_CHANNELS = {CLOUD_APP, FILE_TYPE, URL, SSL}

# Cloud App Control rule types (application categories). A pack rule's
# "type" must be one of these; "cloud_app_classes" defaults to [type].
CLOUD_APP_TYPES = (
    "AI_ML", "BUSINESS_PRODUCTIVITY", "CONSUMER", "CUSTOM_CAPP", "DNS_OVER_HTTPS", "ENTERPRISE_COLLABORATION",
    "FILE_SHARE", "FINANCE", "HEALTH_CARE", "HOSTING_PROVIDER", "HUMAN_RESOURCES", "INSTANT_MESSAGING",
    "IT_SERVICES", "LEGAL", "SALES_AND_MARKETING", "SOCIAL_NETWORKING", "STREAMING_MEDIA",
    "SYSTEM_AND_DEVELOPMENT", "WEBMAIL",
)
CLOUD_APP_TRUST_LEVELS = ("UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST")
SSL_PLATFORMS = ("SCAN_IOS", "SCAN_ANDROID", "SCAN_MACOS", "SCAN_WINDOWS", "NO_CLIENT_CONNECTOR", "SCAN_LINUX")


def _preview(names: Sequence[Any], limit: int = 6) -> str:
    """'A, B, C, … (+n more)' for dependency labels."""
    names = [str(n) for n in names]
    if len(names) <= limit:
        return ", ".join(names)
    return ", ".join(names[:limit]) + f", … (+{len(names) - limit} more)"


def has_engines(channel: str) -> bool:
    return bool(CHANNELS.get(channel, {}).get("engines", True))


def policy_action(p: Dict[str, Any]) -> str:
    """The comparable 'action' of a pack policy, whatever its channel."""
    ch = channel_of(p)
    if ch == FILE_TYPE:
        return str(p.get("filtering_action", "ALLOW"))
    if ch == SSL:
        return str((p.get("action") or {}).get("type", "DO_NOT_DECRYPT")) if isinstance(p.get("action"), dict) else str(p.get("action", "DO_NOT_DECRYPT"))
    if ch == CLOUD_APP:
        if p.get("actions"):
            return ",".join(sorted(str(a) for a in p["actions"]))
        verbs = p.get("actions_by_verb") or {}
        return ",".join(f"{k}={v}" for k, v in sorted(verbs.items()))
    return str(p.get("action", default_action(ch)))


def _verb_choice(action_name: str, verbs: Dict[str, str]) -> Optional[str]:
    """Which prefix (ALLOW/BLOCK) a pack wants for an available action such
    as BLOCK_FILE_SHARE_UPLOAD, from {"UPLOAD": "BLOCK", "*": "ALLOW"}.
    Longest matching verb wins; '*' is the default; None = leave out."""
    body = action_name.split("_", 1)[1] if "_" in action_name else action_name
    best = None
    for verb, want in verbs.items():
        if verb == "*":
            continue
        if body.endswith(verb.upper()) and (best is None or len(verb) > len(best[0])):
            best = (verb, want)
    if best:
        return str(best[1]).upper()
    return str(verbs["*"]).upper() if "*" in verbs else None


def choose_cloud_app_actions(available: Iterable[str], verbs: Dict[str, str]) -> List[str]:
    """Pick one ALLOW_/BLOCK_ variant per action family from the tenant's
    available actions, per the pack's verb mapping. ISOLATE_ actions are
    never chosen (they need a CBI profile; list them explicitly)."""
    families: Dict[str, Dict[str, str]] = {}
    for a in available:
        a = str(a)
        for prefix in ("ALLOW_", "BLOCK_", "ISOLATE_"):
            if a.startswith(prefix):
                families.setdefault(a[len(prefix):], {})[prefix[:-1]] = a
                break
    chosen: List[str] = []
    for body, variants in sorted(families.items()):
        want = _verb_choice("X_" + body, verbs)
        if want and want in variants:
            chosen.append(variants[want])
        elif want and want == "BLOCK" and "ALLOW" in variants and "BLOCK" not in variants:
            chosen.append(variants["ALLOW"])   # nothing to block; keep the family consistent
    return chosen

SAAS_RULE_TYPES = (
    "OFLCASB_DLP_FILE", "OFLCASB_DLP_EMAIL", "OFLCASB_DLP_CRM", "OFLCASB_DLP_ITSM",
    "OFLCASB_DLP_COLLAB", "OFLCASB_DLP_REPO", "OFLCASB_DLP_STORAGE", "OFLCASB_DLP_GENAI",
)

# Which onboarded SaaS applications a CASB rule type can apply to. The
# tenant reports the application as an identifier such as "BOX",
# "GOOGLE_DRIVE", "OFFICE_365" or "SLACK"; matching is by keyword on the
# upper-cased identifier so minor naming differences between clouds do
# not break resolution. Packs can always pin tenants by name instead.
SAAS_TYPE_APPS: Dict[str, Tuple[str, ...]] = {
    "OFLCASB_DLP_FILE": ("BOX", "DROPBOX", "GDRIVE", "GOOGLE_DRIVE", "GOOGLEDRIVE", "ONEDRIVE", "ONE_DRIVE",
                         "SHAREPOINT", "EGNYTE", "SHAREFILE", "CITRIX"),
    "OFLCASB_DLP_EMAIL": ("GMAIL", "GOOGLE_MAIL", "OFFICE365", "OFFICE_365", "O365", "EXCHANGE", "OUTLOOK", "MICROSOFT_365"),
    "OFLCASB_DLP_COLLAB": ("SLACK", "TEAMS", "WEBEX", "ZOOM", "GOOGLE_CHAT", "GCHAT"),
    "OFLCASB_DLP_CRM": ("SALESFORCE", "HUBSPOT", "DYNAMICS"),
    "OFLCASB_DLP_ITSM": ("SERVICENOW", "SERVICE_NOW", "JIRA", "ZENDESK", "FRESHDESK", "FRESHSERVICE"),
    "OFLCASB_DLP_REPO": ("GITHUB", "GITLAB", "BITBUCKET", "AZURE_DEVOPS", "DEVOPS"),
    "OFLCASB_DLP_STORAGE": ("AWS", "S3", "AZURE", "BLOB", "GCP", "GCS", "GOOGLE_CLOUD"),
    "OFLCASB_DLP_GENAI": ("CHATGPT", "OPENAI", "GEMINI", "COPILOT", "CLAUDE", "ANTHROPIC", "GENAI", "PERPLEXITY"),
}
EMAIL_APPS = SAAS_TYPE_APPS["OFLCASB_DLP_EMAIL"]

ENDPOINT_TRUST_LEVELS = ("UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST")


def channel_of(policy_def: Dict[str, Any]) -> str:
    ch = str(policy_def.get("channel") or WEB).strip().lower()
    return ch if ch in CHANNELS else ch  # unknown channels are reported by validate()


def label(channel: str) -> str:
    return CHANNELS.get(channel, {}).get("label", channel)


def is_enforcing(channel: str, action: Optional[str]) -> bool:
    spec = CHANNELS.get(channel)
    if not spec:
        return False
    action = action or ""
    if channel == CLOUD_APP:
        # "BLOCK_..." actions or verb mappings with a BLOCK value enforce.
        return any(part.startswith("BLOCK_") or part.startswith("ISOLATE_") or part.endswith("=BLOCK") or part.endswith("=ISOLATE")
                   for part in action.split(","))
    if spec["enforcing_actions"] is None:
        return bool(action) and action not in spec["monitor_actions"]
    return action in spec["enforcing_actions"]


def default_action(channel: str) -> str:
    return {SAAS: "OFLCASB_DLP_REPORT_INCIDENT", SSL: "DO_NOT_DECRYPT", CLOUD_APP: ""}.get(channel, "ALLOW")


def validate(policy_def: Dict[str, Any]) -> Optional[str]:
    """Static pack-level validation. Returns an error string or None."""
    ch = channel_of(policy_def)
    if ch not in CHANNELS:
        return f"unknown channel '{ch}' (use one of {', '.join(CHANNELS)})"
    if ch == SAAS:
        t = policy_def.get("saas_type")
        if not t:
            return "SaaS rules need 'saas_type' (e.g. OFLCASB_DLP_FILE)"
        if t not in SAAS_RULE_TYPES:
            return f"unknown saas_type '{t}' (use one of {', '.join(SAAS_RULE_TYPES)})"
    if ch == CLOUD_APP:
        t = policy_def.get("type")
        if not t:
            return "Cloud App Control rules need 'type' (the application category, e.g. FILE_SHARE, WEBMAIL, AI_ML)"
        if t not in CLOUD_APP_TYPES:
            return f"unknown Cloud App Control type '{t}' (use one of {', '.join(CLOUD_APP_TYPES)})"
        if not policy_def.get("actions") and not policy_def.get("actions_by_verb"):
            return ("Cloud App Control rules need 'actions' (explicit list) or 'actions_by_verb' "
                    "(e.g. {\"UPLOAD\": \"BLOCK\", \"*\": \"ALLOW\"})")
    if ch == FILE_TYPE:
        if not policy_def.get("file_types"):
            return "File Type Control rules need 'file_types' (e.g. [\"FTCATEGORY_MS_EXCEL\"])"
        if policy_def.get("operation", "UPLOAD") not in ("UPLOAD", "DOWNLOAD", "UPLOAD_DOWNLOAD"):
            return "File Type Control 'operation' must be UPLOAD, DOWNLOAD or UPLOAD_DOWNLOAD"
        if policy_def.get("filtering_action", "ALLOW") not in ("ALLOW", "CAUTION", "BLOCK"):
            return "File Type Control 'filtering_action' must be ALLOW, CAUTION or BLOCK"
    if ch == URL:
        if not policy_def.get("url_categories"):
            return "URL Filtering rules need 'url_categories' (e.g. [\"GAMBLING\"] or [\"ANY\"])"
        if policy_def.get("action", "ALLOW") not in ("ALLOW", "CAUTION", "BLOCK", "ISOLATE", "ICAP_RESPONSE"):
            return "URL Filtering 'action' must be ALLOW, CAUTION, BLOCK, ISOLATE or ICAP_RESPONSE"
    if ch == SSL:
        a = policy_def.get("action")
        if not isinstance(a, dict) or a.get("type") not in ("DECRYPT", "DO_NOT_DECRYPT", "BLOCK"):
            return "SSL Inspection rules need 'action': {\"type\": \"DECRYPT\" | \"DO_NOT_DECRYPT\" | \"BLOCK\", ...}"
    return None


# ---------------------------------------------------------------------------
# Tenant-side state
# ---------------------------------------------------------------------------

def _nx(ret):
    """SDK calls return (data, response, error) or (data, error)."""
    if isinstance(ret, tuple):
        if len(ret) == 3:
            return ret[0], ret[2]
        if len(ret) == 2:
            return ret[0], ret[1]
    return ret, None


def _field(obj: Any, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if isinstance(obj, dict) and k in obj and obj[k] is not None:
            return obj[k]
        if hasattr(obj, k) and getattr(obj, k) is not None:
            return getattr(obj, k)
    return default


def engine_ids_of(r: Any) -> List[Any]:
    """IDs of the DLP engines a tenant rule references, whatever shape the
    SDK returned them in ([{id}], [Obj], or bare ids)."""
    out = []
    for e in _field(r, "dlp_engines", "dlpEngines", default=[]) or []:
        eid = e if isinstance(e, (int, str)) else _field(e, "id")
        if eid is not None:
            out.append(eid)
    return sorted(out, key=str)


def _rule_summary(r: Any, channel: Optional[str] = None) -> Dict[str, Any]:
    action = _field(r, "action")
    if channel == FILE_TYPE:
        action = _field(r, "filtering_action", "filteringAction", default=action)
    elif channel == SSL and isinstance(action, dict):
        action = action.get("type")
    elif channel == SSL and action is not None and not isinstance(action, str):
        action = _field(action, "type")
    elif channel == CLOUD_APP:
        acts = _field(r, "actions", default=[]) or []
        action = ",".join(sorted(str(a) for a in acts))
    return {
        "id": _field(r, "id"),
        "name": str(_field(r, "name", default="") or "").strip(),
        "order": int(_field(r, "order", default=0) or 0),
        "rank": _field(r, "rank"),
        "action": action,
        "state": _field(r, "state"),
        "type": _field(r, "type"),
        # Content fields used for baseline drift detection.
        "engine_ids": engine_ids_of(r),
        "severity": _field(r, "severity"),
        "description": _field(r, "description"),
        "applications": sorted(str(a) for a in (_field(r, "applications", "cloud_applications", "cloudApplications", default=[]) or [])),
        "url_categories": sorted(str(a) for a in (_field(r, "url_categories", "urlCategories", default=[]) or [])),
        "file_types": sorted(str(a) for a in (_field(r, "file_types", "fileTypes", default=[]) or [])),
        "operation": _field(r, "operation"),
    }


def needs(policy_defs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """What tenant state the plan has to read for these policies."""
    out = {"channels": set(), "casb": False, "templates": False, "labels": False, "app_classes": set(),
           "cloud_app_types": set(), "cloud_app_actions": []}
    for p in policy_defs:
        ch = channel_of(p)
        out["channels"].add(ch)
        if CHANNELS.get(ch, {}).get("needs_casb"):
            out["casb"] = True
        if p.get("notification_template"):
            out["templates"] = True
        if p.get("labels"):
            out["labels"] = True
        for cls in p.get("cloud_app_classes") or []:
            out["app_classes"].add(str(cls).upper())
        if ch == CLOUD_APP and p.get("type"):
            out["cloud_app_types"].add(str(p["type"]).upper())
            if not p.get("applications") and not p.get("cloud_app_classes"):
                out["app_classes"].add(str(p["type"]).upper())
            if p.get("actions_by_verb") and not p.get("actions"):
                out["cloud_app_actions"].append({
                    "type": str(p["type"]).upper(),
                    "applications": [str(a) for a in (p.get("applications") or [])],
                    "classes": [str(c).upper() for c in (p.get("cloud_app_classes") or [str(p["type"])])],
                })
    return out


def fetch_channel_state(zia, need: Dict[str, Any]) -> Dict[str, Any]:
    """Read the rule lists for every non-web channel the packs use, plus
    the shared prerequisites (SaaS tenants, notification templates,
    labels) they reference. Never raises; errors are recorded per item so
    one unlicensed feature only blocks the rules that need it."""
    state: Dict[str, Any] = {
        "rules": {},          # channel -> [rule summaries]
        "errors": {},         # channel -> error string
        "casb_tenants": None, # list of {id, name, app, status} or None when not needed
        "casb_error": None,
        "templates": None,    # name -> id
        "templates_error": None,
        "labels": None,       # name -> id
        "labels_error": None,
        "app_classes": {},    # class -> [application identifiers] (dynamic scoping, e.g. AI_ML)
        "app_class_errors": {},
    }
    for cls in sorted(need.get("app_classes") or ()):
        try:
            svc = getattr(zia, "cloud_applications", None)
            if svc is None:
                raise RuntimeError("cloud_applications is not available in the installed zscaler-sdk-python")
            data, err = _nx(svc.list_cloud_app_policy(query_params={"app_class": cls, "page_size": 1000}))
            if err:
                raise RuntimeError(str(err))
            apps = []
            for a in data or []:
                ident = _field(a, "app", "app_name", "appName", "name")
                if ident:
                    apps.append(str(ident))
            state["app_classes"][cls] = sorted(set(apps))
        except Exception as e:  # noqa: BLE001
            state["app_classes"][cls] = []
            state["app_class_errors"][cls] = str(e)[:200]
    for ch in sorted(need["channels"]):
        if ch == WEB or ch not in CHANNELS:
            continue
        svc = getattr(zia, CHANNELS[ch]["service"], None)
        if svc is None:
            state["errors"][ch] = f"{CHANNELS[ch]['service']} is not available in the installed zscaler-sdk-python"
            continue
        try:
            if ch == SAAS:
                lister = getattr(svc, "list_all_rules", None)
                data, err = _nx(lister()) if lister else _nx(svc.list_rules("ANY"))
            elif ch == CLOUD_APP:
                # Cloud App Control rules are listed per application category.
                data = []
                for t in sorted(need.get("cloud_app_types") or ()):
                    part, err = _nx(svc.list_rules(t))
                    if err:
                        raise RuntimeError(f"{t}: {err}")
                    for r in part or []:
                        if isinstance(r, dict):
                            r.setdefault("type", t)
                        elif not getattr(r, "type", None):
                            try:
                                setattr(r, "type", t)
                            except Exception:  # noqa: BLE001
                                pass
                    data.extend(part or [])
                err = None
            else:
                data, err = _nx(svc.list_rules())
            if err:
                raise RuntimeError(str(err))
            state["rules"][ch] = sorted((_rule_summary(r, ch) for r in (data or [])), key=lambda r: r["order"])
        except Exception as e:  # noqa: BLE001 — surfaced as a dependency failure
            state["errors"][ch] = str(e)[:200]

    # Cloud App Control: the actions a rule may carry depend on the type and
    # the applications, so packs that map verbs ("UPLOAD": "BLOCK") are
    # resolved against the tenant's own list of available actions.
    state["cloud_app_actions"] = {}
    state["cloud_app_action_errors"] = {}
    svc = getattr(zia, CHANNELS[CLOUD_APP]["service"], None)
    for spec in need.get("cloud_app_actions") or []:
        apps = spec["applications"] or sorted({a for c in spec["classes"] for a in (state["app_classes"].get(c) or [])})
        key = f"{spec['type']}:{','.join(apps)}"
        if key in state["cloud_app_actions"] or key in state["cloud_app_action_errors"]:
            continue
        try:
            if svc is None:
                raise RuntimeError("cloudappcontrol is not available in the installed zscaler-sdk-python")
            if not apps:
                raise RuntimeError("no applications resolved for this rule type")
            data, err = _nx(svc.list_available_actions(spec["type"], apps))
            if err:
                raise RuntimeError(str(err))
            state["cloud_app_actions"][key] = [str(a) for a in (data or [])]
        except Exception as e:  # noqa: BLE001
            state["cloud_app_action_errors"][key] = str(e)[:200]

    if need["casb"]:
        try:
            svc = getattr(zia, "saas_security_api", None)
            if svc is None:
                raise RuntimeError("saas_security_api is not available in the installed zscaler-sdk-python")
            data, err = _nx(svc.list_casb_tenant_lite(query_params={"active_only": True}))
            if err:
                raise RuntimeError(str(err))
            tenants = []
            for t in data or []:
                tid = _field(t, "tenant_id", "tenantId", "id")
                name = str(_field(t, "tenant_name", "tenantName", "name", default="") or "").strip()
                if tid is None or not name:
                    continue
                tenants.append({
                    "id": tid, "name": name,
                    "app": str(_field(t, "saas_application", "saasApplication", default="") or "").upper(),
                    "status": _field(t, "status", default=[]),
                })
            state["casb_tenants"] = tenants
        except Exception as e:  # noqa: BLE001
            state["casb_tenants"] = []
            state["casb_error"] = str(e)[:200]

    if need["templates"]:
        try:
            svc = getattr(zia, "dlp_templates", None)
            if svc is None:
                raise RuntimeError("dlp_templates is not available in the installed zscaler-sdk-python")
            data, err = _nx(svc.list_dlp_templates())
            if err:
                raise RuntimeError(str(err))
            state["templates"] = {str(_field(t, "name", default="")).strip(): _field(t, "id") for t in (data or []) if _field(t, "name")}
        except Exception as e:  # noqa: BLE001
            state["templates"] = {}
            state["templates_error"] = str(e)[:200]

    if need["labels"]:
        try:
            svc = getattr(zia, "rule_labels", None)
            if svc is None:
                raise RuntimeError("rule_labels is not available in the installed zscaler-sdk-python")
            data, err = _nx(svc.list_labels())
            if err:
                raise RuntimeError(str(err))
            state["labels"] = {str(_field(t, "name", default="")).strip(): _field(t, "id") for t in (data or []) if _field(t, "name")}
        except Exception as e:  # noqa: BLE001
            state["labels"] = {}
            state["labels_error"] = str(e)[:200]
    return state


# ---------------------------------------------------------------------------
# Resolution — pack names → tenant IDs
# ---------------------------------------------------------------------------

def _match_tenants(tenants: Sequence[Dict[str, Any]], keywords: Tuple[str, ...]) -> List[Dict[str, Any]]:
    return [t for t in tenants if any(k in t["app"] for k in keywords)]


def _tenant_list(tenants: Sequence[Dict[str, Any]]) -> str:
    return ", ".join(f"{t['name']} ({t['app'] or 'app unknown'})" for t in tenants) or "none"


def resolve(channel: str, policy_def: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve a policy's tenant prerequisites.

    Returns {"resolved": {...ids...}, "missing": [reasons], "depends": [(kind, label)],
             "deps": [dependency rows]} where dependency rows feed the report."""
    resolved: Dict[str, Any] = {}
    missing: List[str] = []
    depends: List[Tuple[str, str]] = []
    rows: List[Dict[str, Any]] = []
    name = policy_def.get("name", "?")

    # Channel API reachability (non-web).
    if channel != WEB:
        err = state["errors"].get(channel)
        if err:
            missing.append(f"the {label(channel)} rule API could not be read ({err}); the feature is probably not licensed or enabled on this tenant")

    # SaaS / Email tenants.
    if channel in (SAAS, EMAIL):
        want = policy_def.get("tenants", "any")
        tenants = state.get("casb_tenants") or []
        if state.get("casb_error"):
            missing.append(f"SaaS application tenants could not be listed ({state['casb_error']})")
        elif isinstance(want, list) and want:
            by_name = {t["name"].lower(): t for t in tenants}
            chosen, absent = [], []
            for w in want:
                t = by_name.get(str(w).strip().lower())
                (chosen if t else absent).append(t if t else str(w))
            if absent:
                missing.append(f"SaaS application tenant(s) not onboarded: {', '.join(absent)} (available: {_tenant_list(tenants)})")
            resolved["tenants"] = chosen
        else:
            keywords = SAAS_TYPE_APPS.get(policy_def.get("saas_type", ""), ()) if channel == SAAS else EMAIL_APPS
            chosen = _match_tenants(tenants, keywords) if keywords else list(tenants)
            if not tenants:
                what = "an email tenant (Microsoft 365 or Gmail)" if channel == EMAIL else "a SaaS application tenant"
                missing.append(f"no SaaS application tenant is onboarded; {what} must be added under "
                               "Administration > SaaS Application Tenants before this rule can be scoped")
            elif not chosen:
                kind = "email" if channel == EMAIL else policy_def.get("saas_type", "this rule type")
                missing.append(f"none of the onboarded SaaS tenants match {kind} (onboarded: {_tenant_list(tenants)}); "
                               "onboard a matching application or pin tenants by name with \"tenants\": [\"<tenant name>\"]")
            resolved["tenants"] = chosen
        for t in resolved.get("tenants") or []:
            depends.append(("resource", f"SaaS tenant: {t['name']}"))

    # Notification template by name.
    tpl = policy_def.get("notification_template")
    if tpl:
        templates = state.get("templates") or {}
        if state.get("templates_error"):
            missing.append(f"notification templates could not be listed ({state['templates_error']})")
        elif tpl in templates:
            resolved["notification_template"] = templates[tpl]
            depends.append(("resource", f"Notification template: {tpl}"))
        else:
            missing.append(f"notification template '{tpl}' does not exist in the tenant (Administration > DLP Notification Templates)")
            depends.append(("missing", f"Notification template: {tpl}"))

    # Dynamic cloud-application scope by application class (e.g. AI_ML):
    # resolved against the tenant's current catalogue at plan time, so new
    # applications Zscaler classifies later are picked up on the next deploy.
    classes = [str(c).upper() for c in (policy_def.get("cloud_app_classes") or [])]
    if channel == CLOUD_APP and not classes and not policy_def.get("applications") and policy_def.get("type"):
        classes = [str(policy_def["type"]).upper()]
    if classes:
        apps: List[str] = []
        for cls in classes:
            err = (state.get("app_class_errors") or {}).get(cls)
            found = (state.get("app_classes") or {}).get(cls) or []
            if err:
                missing.append(f"cloud applications of class {cls} could not be listed ({err})")
                depends.append(("missing", f"Cloud applications: {cls}"))
            elif not found:
                missing.append(f"the tenant exposes no cloud applications of class {cls}; set \"applications\" explicitly instead")
                depends.append(("missing", f"Cloud applications: {cls}"))
            else:
                apps.extend(found)
                depends.append(("resource", f"Cloud applications: {cls} ({len(found)}): {_preview(found)}"))
        resolved["cloud_applications"] = sorted(set(apps))

    # Cloud App Control actions: explicit, or chosen from the tenant's
    # available actions per the pack's verb mapping.
    if channel == CLOUD_APP:
        if policy_def.get("actions"):
            resolved["actions"] = [str(a) for a in policy_def["actions"]]
        elif policy_def.get("actions_by_verb"):
            apps = [str(a) for a in (policy_def.get("applications") or [])] or resolved.get("cloud_applications") or []
            key = f"{str(policy_def['type']).upper()}:{','.join(apps)}"
            err = (state.get("cloud_app_action_errors") or {}).get(key)
            available = (state.get("cloud_app_actions") or {}).get(key)
            if err:
                missing.append(f"available Cloud App Control actions could not be read ({err})")
                depends.append(("missing", f"Cloud App Control actions: {policy_def['type']}"))
            elif not available:
                missing.append(f"the tenant reports no Cloud App Control actions for type {policy_def['type']} and these applications")
                depends.append(("missing", f"Cloud App Control actions: {policy_def['type']}"))
            else:
                chosen = choose_cloud_app_actions(available, policy_def["actions_by_verb"])
                if not chosen:
                    missing.append("the verb mapping selected no actions from the tenant's available Cloud App Control actions")
                resolved["actions"] = chosen
                depends.append(("resource", f"Cloud App Control actions: {policy_def['type']} ({len(chosen)} of {len(available)} available): {_preview(chosen, 8)}"))

    # Rule labels by name.
    labels = policy_def.get("labels") or []
    if labels:
        known = state.get("labels") or {}
        if state.get("labels_error"):
            missing.append(f"rule labels could not be listed ({state['labels_error']})")
        else:
            absent = [lb for lb in labels if lb not in known]
            if absent:
                missing.append(f"rule label(s) missing from the tenant: {', '.join(absent)}")
                depends.extend(("missing", f"Label: {lb}") for lb in absent)
            resolved["labels"] = [known[lb] for lb in labels if lb in known]
            depends.extend(("resource", f"Label: {lb}") for lb in labels if lb in known)

    return {"resolved": resolved, "missing": missing, "depends": depends, "rows": rows, "policy": name}


# ---------------------------------------------------------------------------
# Dependency report (what the UI lists per channel)
# ---------------------------------------------------------------------------

def dependency_report(policy_items: Sequence[Dict[str, Any]], state: Dict[str, Any], tenant_web_rules: int) -> List[Dict[str, Any]]:
    """One row per prerequisite, with status ok | missing | error | info and
    the rules that need it. Rows are ordered by channel."""
    by_channel: Dict[str, List[Dict[str, Any]]] = {}
    for it in policy_items:
        by_channel.setdefault(channel_of(it["definition"]), []).append(it)
    rows: List[Dict[str, Any]] = []

    def names(items):
        return [i["name"] for i in items]

    for ch in CHANNELS:
        items = by_channel.get(ch)
        if not items:
            continue
        spec = CHANNELS[ch]
        # Shared chain.
        if spec.get("engines", True):
            rows.append({
                "channel": ch, "label": spec["label"], "status": "info",
                "requirement": "DLP dictionaries and engines referenced by these rules",
                "detail": "Resolved per rule in the plan (created by the pack or reused from the tenant).",
                "rules": names(items),
            })
        if ch in CONTROL_CHANNELS:
            err = state["errors"].get(ch)
            rows.append({
                "channel": ch, "label": spec["label"], "status": "error" if err else "ok",
                "requirement": f"{spec['label']} rule API reachable",
                "detail": err or f"{len(state['rules'].get(ch, []))} existing rule(s). Containment rules run BEFORE DLP: a block here stops the transaction before content inspection.",
                "rules": names(items),
            })
        if ch == WEB:
            rows.append({
                "channel": ch, "label": spec["label"], "status": "ok",
                "requirement": "Web DLP rule API reachable",
                "detail": f"{tenant_web_rules} existing rule(s); API cap {spec['rule_cap']}.",
                "rules": names(items),
            })
        elif ch not in CONTROL_CHANNELS:
            err = state["errors"].get(ch)
            rows.append({
                "channel": ch, "label": spec["label"], "status": "error" if err else "ok",
                "requirement": {
                    ENDPOINT: "Endpoint DLP rule API reachable (feature licensed; Zscaler Client Connector with Endpoint DLP deployed)",
                    SAAS: "SaaS Security API rule API reachable (feature licensed)",
                    EMAIL: "Email DLP rule API reachable (feature licensed)",
                }[ch],
                "detail": err or f"{len(state['rules'].get(ch, []))} existing rule(s).",
                "rules": names(items),
            })
        if ch in (SAAS, EMAIL):
            tenants = state.get("casb_tenants") or []
            if state.get("casb_error"):
                st, detail = "error", state["casb_error"]
            elif ch == EMAIL:
                em = _match_tenants(tenants, EMAIL_APPS)
                st = "ok" if em else "missing"
                detail = f"Email tenant(s): {_tenant_list(em)}." if em else f"No Microsoft 365 / Gmail tenant onboarded (onboarded: {_tenant_list(tenants)})."
            else:
                st = "ok" if tenants else "missing"
                detail = f"Onboarded: {_tenant_list(tenants)}." if tenants else "No SaaS application tenant onboarded."
            rows.append({
                "channel": ch, "label": spec["label"], "status": st,
                "requirement": ("Email tenant onboarded under SaaS Security (Administration > SaaS Application Tenants)"
                                if ch == EMAIL else "SaaS application tenant(s) onboarded (Administration > SaaS Application Tenants)"),
                "detail": detail, "rules": names(items),
            })
        if ch == ENDPOINT:
            rows.append({
                "channel": ch, "label": spec["label"], "status": "info",
                "requirement": "Zscaler Client Connector on endpoints with Endpoint DLP enabled in the app profile",
                "detail": "Cannot be verified through the ZIA API; rules are created but only enforced on enrolled devices.",
                "rules": names(items),
            })
        # Per-rule named prerequisites.
        for it in items:
            for kind, lab in it.get("depends_on", []):
                if kind in ("resource", "missing") and not lab.startswith("SaaS tenant:"):
                    rows.append({
                        "channel": ch, "label": spec["label"], "status": "ok" if kind == "resource" else "missing",
                        "requirement": lab,
                        "detail": ("Resolved live from the tenant during preflight and again on every deploy, so newly classified applications are picked up automatically."
                                   if lab.startswith(("Cloud applications:", "Cloud App Control actions:")) else "Referenced by name in the pack."),
                        "rules": [it["name"]],
                    })
    # De-duplicate identical requirement rows, merging rule lists.
    merged: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rows:
        key = (r["channel"], r["requirement"])
        if key in merged:
            merged[key]["rules"] = sorted(set(merged[key]["rules"]) | set(r["rules"]))
        else:
            merged[key] = dict(r)
    return list(merged.values())


# ---------------------------------------------------------------------------
# Payloads
# ---------------------------------------------------------------------------

def _ids(values: Iterable[Any]) -> List[Dict[str, Any]]:
    return [{"id": v} for v in values if v is not None]


def build_payload(channel: str, p: Dict[str, Any], engine_ids: List[Any], resolved: Dict[str, Any], *, use_rank_0: bool = False) -> Dict[str, Any]:
    """Translate one pack policy into `add_rule` kwargs for its channel.
    New rules always go to order 1 (top of the policy)."""
    if channel == WEB:
        from dlp_importer import build_policy_payload
        if resolved.get("cloud_applications") and not p.get("cloud_applications"):
            p = dict(p, cloud_applications=list(resolved["cloud_applications"]))
        return build_policy_payload(p, engine_ids, use_rank_0=use_rank_0)

    if channel in CONTROL_CHANNELS:
        return _build_control_payload(channel, p, resolved, use_rank_0=use_rank_0)

    body: Dict[str, Any] = {
        "name": p["name"],
        "order": 1,
        "state": p.get("state", "ENABLED"),
        "action": p.get("action", default_action(channel)),
        "dlp_engines": _ids(engine_ids),
        "without_content_inspection": bool(p.get("without_content_inspection", False)),
    }
    if p.get("description"):
        body["description"] = p["description"]
    if p.get("severity"):
        body["severity"] = p["severity"]
    if channel != EMAIL:
        body["rank"] = 0 if use_rank_0 else p.get("rank", 7)
    if p.get("file_types"):
        body["file_types"] = list(p["file_types"])
    if resolved.get("labels"):
        body["labels"] = _ids(resolved["labels"])
    if resolved.get("notification_template") is not None:
        body["notification_template"] = {"id": resolved["notification_template"]}

    if channel == ENDPOINT:
        body["device_trust_levels"] = list(p.get("device_trust_levels") or ENDPOINT_TRUST_LEVELS)
        for opt in ("user_risk_score_levels", "network_type", "data_transfer_method", "min_size"):
            if p.get(opt):
                body[opt] = p[opt]
    elif channel == SAAS:
        body["type"] = p["saas_type"]
        body["cloud_app_tenants"] = _ids(t["id"] for t in resolved.get("tenants", []))
        body["collaboration_scope"] = list(p.get("collaboration_scope") or ["ANY"])
        for opt in ("components", "content_location", "recipient", "domains"):
            if p.get(opt):
                body[opt] = p[opt]
    elif channel == EMAIL:
        body["email_tenants"] = _ids(t["id"] for t in resolved.get("tenants", []))
        for opt in ("user_risk_score_levels", "content_locations", "min_size", "custom_header"):
            if p.get(opt):
                body[opt] = p[opt]
    return body


def _build_control_payload(channel: str, p: Dict[str, Any], resolved: Dict[str, Any], *, use_rank_0: bool = False) -> Dict[str, Any]:
    """Containment rules: Cloud App Control, File Type Control, URL
    Filtering, SSL Inspection. Field names follow the ZIA API / SDK."""
    body: Dict[str, Any] = {
        "name": p["name"],
        "order": 1,
        "state": p.get("state", "ENABLED"),
        "rank": 0 if use_rank_0 else p.get("rank", 7),
    }
    if p.get("description"):
        body["description"] = p["description"]
    apps = [str(a) for a in (p.get("applications") or [])] or list(resolved.get("cloud_applications") or [])
    if channel == CLOUD_APP:
        body["type"] = str(p["type"]).upper()
        body["actions"] = list(resolved.get("actions") or p.get("actions") or [])
        body["applications"] = apps
        body["device_trust_levels"] = list(p.get("device_trust_levels") or CLOUD_APP_TRUST_LEVELS)
        for opt in ("user_agent_types", "user_risk_score_levels", "time_quota", "size_quota"):
            if p.get(opt):
                body[opt] = p[opt]
    elif channel == FILE_TYPE:
        body["filtering_action"] = p.get("filtering_action", "ALLOW")
        body["operation"] = p.get("operation", "UPLOAD")
        body["file_types"] = list(p["file_types"])
        body["protocols"] = list(p.get("protocols") or ["ANY_RULE"])
        if apps:
            body["cloud_applications"] = apps
        for opt in ("url_categories", "device_trust_levels", "min_size", "max_size", "active_content", "unscannable"):
            if p.get(opt) is not None and p.get(opt) != []:
                body[opt] = p[opt]
    elif channel == URL:
        body["action"] = p.get("action", "ALLOW")
        body["protocols"] = list(p.get("protocols") or ["ANY_RULE"])
        body["url_categories"] = list(p["url_categories"])
        for opt in ("request_methods", "device_trust_levels", "user_agent_types", "user_risk_score_levels",
                    "end_user_notification_url", "block_override"):
            if p.get(opt) is not None and p.get(opt) != []:
                body[opt] = p[opt]
    elif channel == SSL:
        body["action"] = dict(p["action"])
        body["platforms"] = list(p.get("platforms") or SSL_PLATFORMS)
        if apps:
            body["cloud_applications"] = apps
        for opt in ("url_categories", "device_trust_levels", "user_agent_types", "road_warrior_for_kerberos"):
            if p.get(opt) is not None and p.get(opt) != []:
                body[opt] = p[opt]
    if resolved.get("labels"):
        body["labels"] = _ids(resolved["labels"])
    return body


def add_rule(zia, channel: str, payload: Dict[str, Any]):
    svc = getattr(zia, CHANNELS[channel]["service"])
    if channel == CLOUD_APP:
        return svc.add_rule(payload["type"], **payload)
    return svc.add_rule(**payload)


def update_rule(zia, channel: str, rule_id: Any, payload: Dict[str, Any]):
    """Overwrite an existing rule with a full baseline payload (PUT semantics)."""
    svc = getattr(zia, CHANNELS[channel]["service"])
    if channel == CLOUD_APP:
        return svc.update_rule(payload["type"], rule_id, **payload)
    return svc.update_rule(rule_id, **payload)


def list_rule_names(zia, channel: str, types: Optional[Iterable[str]] = None) -> Tuple[Optional[set], Optional[str]]:
    """Fresh name set for post-deploy verification. Cloud App Control rules
    are listed per type; pass the types the pack uses."""
    svc = getattr(zia, CHANNELS[channel]["service"], None)
    if svc is None:
        return None, "service unavailable"
    try:
        if channel == SAAS:
            lister = getattr(svc, "list_all_rules", None)
            data, err = _nx(lister()) if lister else _nx(svc.list_rules("ANY"))
        elif channel == CLOUD_APP:
            data = []
            for t in sorted(set(types or ())):
                part, err = _nx(svc.list_rules(t))
                if err:
                    return None, str(err)[:200]
                data.extend(part or [])
            err = None
        else:
            data, err = _nx(svc.list_rules())
        if err:
            return None, str(err)[:200]
        return {str(_field(r, "name", default="") or "").strip() for r in (data or [])}, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]


def policy_signature_extra(p: Dict[str, Any]) -> Dict[str, Any]:
    """Channel-specific fields that make two same-named policies differ."""
    ch = channel_of(p)
    extra: Dict[str, Any] = {"channel": ch}
    if ch == SAAS:
        extra.update({"saas_type": p.get("saas_type"), "tenants": p.get("tenants", "any"),
                      "collaboration_scope": sorted(p.get("collaboration_scope") or ["ANY"]),
                      "components": sorted(p.get("components") or [])})
    elif ch == EMAIL:
        extra.update({"tenants": p.get("tenants", "any")})
    elif ch == ENDPOINT:
        extra.update({"device_trust_levels": sorted(p.get("device_trust_levels") or ENDPOINT_TRUST_LEVELS)})
    if p.get("notification_template"):
        extra["notification_template"] = p["notification_template"]
    if p.get("labels"):
        extra["labels"] = sorted(p["labels"])
    if p.get("file_types"):
        extra["file_types"] = sorted(p["file_types"])
    if p.get("cloud_app_classes"):
        extra["cloud_app_classes"] = sorted(str(c).upper() for c in p["cloud_app_classes"])
    if ch in CONTROL_CHANNELS:
        for k in ("type", "applications", "actions", "actions_by_verb", "filtering_action", "operation", "file_types",
                  "url_categories", "request_methods", "platforms", "protocols"):
            if p.get(k) is not None:
                extra[k] = p[k]
        extra["action"] = policy_action(p)
    return extra
