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

import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple


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
# Containment channels carved out of every pack and baseline: a pack
# deploys detection only — Web, Endpoint, SaaS and Email DLP. Cloud App
# Control, File Type Control, URL Filtering and SSL Inspection are managed
# separately, not by a pack. Override with DLP_CHECK_CARVED_CHANNELS
# (comma list of channel keys, or "none") if a deployment wants a
# different split.
def _carved_channels() -> set:
    import os
    raw = os.environ.get("DLP_CHECK_CARVED_CHANNELS")
    if raw is None:
        return set(CONTROL_CHANNELS)
    if raw.strip().lower() in ("", "none"):
        return set()
    return {c.strip().lower() for c in raw.split(",") if c.strip().lower() in CONTROL_CHANNELS}


CARVED_CHANNELS = set(CONTROL_CHANNELS)

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


# ---------------------------------------------------------------------------
# Endpoint DLP extras: application groups and sub-rules
# ---------------------------------------------------------------------------
# The SDK covers endpoint rules but not endpoint application groups
# (/endPointApplicationGroups) or the sub-rule endpoints
# (/endPointDlpRules/{parent}/subRule[/{id}]); those go through the SDK's
# own request executor so authentication and camelCase conversion are
# shared. Tests replace raw_request().

ZIA_BASE = "/zia/api/v1"
APP_GROUPS_PATH = "/endPointApplicationGroups"


def activation_status(zia) -> Tuple[Optional[str], Optional[str]]:
    """Current activation status ('ACTIVE' / 'PENDING' / …), or an error."""
    data, err = raw_request(zia, "GET", "/status")
    if err:
        return None, err
    return (str((data or {}).get("status") or "").upper() or None), None


def wait_active(zia, seconds: float = 45.0, log=None) -> Optional[str]:
    """Poll the activation status until ZIA reports ACTIVE (or `seconds`
    pass, or the status cannot be read), so a verification read sees the
    saved configuration. Returns the last status seen."""
    import time as _t
    _log = log or (lambda m: None)
    deadline = _t.monotonic() + max(0.0, float(seconds or 0))
    while True:
        status, err = activation_status(zia)
        if err or status in (None, "ACTIVE"):
            return status
        if _t.monotonic() >= deadline:
            _log(f"Activation still {status} after {int(seconds)}s; reading anyway.")
            return status
        _t.sleep(3)


def activate(zia) -> Dict[str, Any]:
    """Activate pending ZIA configuration (POST /status/activate). ZIA saves
    every create/delete as pending until this runs, so a deploy or removal
    is not live for users until it does. Returns {activated, status, error}."""
    before, _ = activation_status(zia)
    import zia_rate
    zia_rate.wait("POST", "/status/activate")   # 10 a minute, 40 an hour
    data, err = raw_request(zia, "POST", "/status/activate")
    if err:
        return {"activated": False, "status": before, "error": err}
    return {"activated": True, "status": str((data or {}).get("status") or "ACTIVE").upper(), "error": None}


def raw_request(zia, method: str, path: str, body: Optional[Dict[str, Any]] = None) -> Tuple[Any, Optional[str]]:
    """(payload, error) for a ZIA call the SDK has no method for."""
    svc = getattr(zia, "endpoint_dlp_rules", None) or getattr(zia, "dlp_web_rules", None)
    ex = getattr(svc, "_request_executor", None)
    if ex is None:
        return None, "the installed zscaler-sdk-python exposes no request executor"
    try:
        req, err = ex.create_request(method.upper(), f"{ZIA_BASE}{path}", body or {}, {}, params={})
        if err:
            return None, str(err)[:200]
        resp, err = ex.execute(req)
        if err:
            return None, str(err)[:200]
        data = resp.get_body() if hasattr(resp, "get_body") else resp
        if isinstance(data, (bytes, str)):
            import json as _json
            try:
                data = _json.loads(data) if data else {}
            except ValueError:
                pass
        return data, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]


def list_app_groups(zia) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """name -> {id, resources, description} of endpoint application groups."""
    data, err = raw_request(zia, "GET", APP_GROUPS_PATH)
    if err:
        return {}, err
    items = data if isinstance(data, list) else (data or {}).get("list") or []
    out: Dict[str, Dict[str, Any]] = {}
    for g in items:
        name = str(_field(g, "name", default="") or "").strip()
        if name:
            out[name] = {"id": _field(g, "id", "groupId", "group_id"), "description": _field(g, "description", default=""),
                         "resources": sorted(str(x) for x in (_field(g, "resources", default=[]) or []))}
    return out, None


def add_app_group(zia, definition: Dict[str, Any]):
    """Create an endpoint application group from a pack definition (name,
    description, resource ids). Called through pack_ops.create."""
    body = {"name": definition["name"], "description": definition.get("description", ""),
            "resources": [str(x) for x in (definition.get("resources") or [])]}
    if definition.get("channel"):
        body["channel"] = definition["channel"]
    return raw_request(zia, "POST", APP_GROUPS_PATH, body)


def update_app_group(zia, group_id: Any, definition: Dict[str, Any]):
    """Overwrite an endpoint application group. Called through pack_ops.update."""
    body = {"id": group_id, "name": definition["name"], "description": definition.get("description", ""),
            "resources": [str(x) for x in (definition.get("resources") or [])]}
    return raw_request(zia, "PUT", f"{APP_GROUPS_PATH}/{group_id}", body)


def add_sub_rule(zia, parent_id: Any, payload: Dict[str, Any]):
    """Create an endpoint sub-rule under `parent_id`. Called through pack_ops.create."""
    body = dict(payload)
    body.pop("order", None) if body.get("order") is None else None
    return raw_request(zia, "POST", f"/endPointDlpRules/{parent_id}/subRule", body)


def update_sub_rule(zia, parent_id: Any, sub_id: Any, payload: Dict[str, Any]):
    """Overwrite an endpoint sub-rule. Called through pack_ops.update."""
    return raw_request(zia, "PUT", f"/endPointDlpRules/{parent_id}/subRule/{sub_id}", dict(payload, id=sub_id))


def is_sub_rule(policy_def: Dict[str, Any]) -> bool:
    """True for an endpoint rule that lives under a parent rule."""
    return bool(policy_def.get("parent_rule"))


def expand_sub_rules(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Endpoint rules may carry ``sub_rules`` (exceptions evaluated under the
    parent). Flatten them into standalone policy definitions that carry
    ``parent_rule`` and an ``order`` among their siblings, right after the
    parent, so every planner treats them as rules."""
    out: List[Dict[str, Any]] = []
    for p in policies:
        subs = p.get("sub_rules") or []
        parent = dict(p)
        parent.pop("sub_rules", None)
        out.append(parent)
        for i, sr in enumerate(subs, 1):
            child = dict(sr)
            child.setdefault("channel", p.get("channel", ENDPOINT))
            child["parent_rule"] = p["name"]
            child.setdefault("order", i)
            child.setdefault("state", p.get("state", "ENABLED"))
            child.setdefault("rank", p.get("rank", 7))
            out.append(child)
    return out


# ---------------------------------------------------------------------------
# Channel targets: which DLP channels a pack is deployed into
# ---------------------------------------------------------------------------
# The operator can decide per pack which of the four DLP channels receive
# the pack's engines. A channel the pack already has rules for is deployed
# as packed; a channel the pack has no rules for gets monitor-only
# extension rules carrying the pack's engines, one rule per engine on
# every channel — the same methodology as every shipped pack (Endpoint DLP
# on the removable-media channel; ZIA allows at most ENDPOINT_MAX_ENGINES
# engines on an Endpoint DLP rule: "Exceeded maximum number of DLP
# engines: 4"); a channel that is deselected is skipped. Containment
# rules (Cloud App Control, File Type, URL, SSL) carry no engines and are
# not part of the choice.

DLP_CHANNELS = (WEB, ENDPOINT, SAAS, EMAIL)
EXTENSION_TAG = {WEB: "Web DLP Monitor", ENDPOINT: "Endpoint DLP Monitor", SAAS: "SaaS DLP Monitor", EMAIL: "Email DLP Monitor"}


def normalize_targets(targets: Any) -> Optional[List[str]]:
    """A list of DLP channel names, or None when no choice was made
    (deploy the pack exactly as packed)."""
    if targets is None:
        return None
    out: List[str] = []
    for t in targets or []:
        t = str(t).strip().lower()
        if t in DLP_CHANNELS and t not in out:
            out.append(t)
    return out


def extension_name(channel: str, prefix: str, pack_name: str) -> str:
    """Name of the monitor rule the channel selection adds when a pack ships
    no rule on `channel`, within the channel's name limit."""
    tag = EXTENSION_TAG[channel]
    prefix = prefix or ""
    if prefix.endswith("_"):
        return prefix + tag.upper().replace(" ", "_")
    if prefix:
        return prefix + tag
    stem = "".join(ch for ch in (pack_name or "Pack") if ch.isalnum() or ch in " -")[:24].strip()
    return fit_rule_name(stem, channel, f" {tag}").strip()


def extension_policy(channel: str, *, pack_name: str, prefix: str, engine_names: Sequence[str],
                     pack_id: str = "", engine: Optional[str] = None, name: Optional[str] = None) -> Dict[str, Any]:
    """A monitor-only rule that puts the pack's engines into a channel the
    pack has no rules for. Disabled, INFO severity, monitor action, so it
    only ever adds visibility until the operator enables it. With `engine`
    the rule carries that one engine (the shape every shipped pack uses on
    every channel; see extension_policies), named `name`."""
    if engine is not None:
        name = name or f"{extension_name(channel, prefix, pack_name)} - {engine}"
        where = "on removable media" if channel == ENDPOINT else "on this channel"
        desc = (f"{label(channel)}: monitor the {pack_name} engine '{engine}' {where}. Added by the channel selection "
                f"in Deploy Policy Packs (the pack ships no {label(channel)} rule); one engine per rule. Monitor-only; enable when incidents look right.")
        engines = [engine]
    else:
        name = name or extension_name(channel, prefix, pack_name)
        desc = (f"{label(channel)}: monitor the {pack_name} engines on this channel. Added by the channel selection "
                f"in Deploy Policy Packs (the pack ships no {label(channel)} rule). Monitor-only; enable when incidents look right.")
        engines = list(engine_names)
    p: Dict[str, Any] = {
        "name": name,
        "channel": channel,
        "description": desc,
        "action": default_action(channel),
        "state": "DISABLED",
        "severity": "RULE_SEVERITY_INFO",
        "engines": engines,
        "extension": True,
    }
    if channel == WEB:
        from dlp_importer import WEB_RULE_PROTOCOLS
        p["protocols"] = list(WEB_RULE_PROTOCOLS)
        p["rank"] = 0
    elif channel == ENDPOINT:
        p.update({"data_transfer_method": ENDPOINT_DEFAULT_TRANSFER_METHOD, "device_trust_levels": list(ENDPOINT_TRUST_LEVELS),
                  "user_risk_score_levels": list(ENDPOINT_RISK_LEVELS), "without_content_inspection": False, "eun_enabled": False, "rank": 0})
    elif channel == SAAS:
        p.update({"saas_type": "OFLCASB_DLP_FILE", "tenants": "any", "collaboration_scope": ["ANY"], "rank": 0})
    elif channel == EMAIL:
        p.update({"tenants": "any"})
    return p


# The channel word every shipped pack's mirror rules end with ("Fed-US PII
# [Endpoint]"); the extension rules follow the same convention.
EXTENSION_SUFFIX = {WEB: "Web", ENDPOINT: "Endpoint", SAAS: "SaaS", EMAIL: "Email"}


def extension_policies(channel: str, *, pack_name: str, prefix: str, engine_names: Sequence[str],
                       pack_id: str = "") -> List[Dict[str, Any]]:
    """The extension rules for `channel`: one disabled, monitor-only rule
    per engine, on every channel — the same methodology as every shipped
    pack (one rule per engine, equal counts on Web, Endpoint, SaaS and
    Email; Endpoint on the removable-media channel). ZIA refuses more than
    ENDPOINT_MAX_ENGINES engines on one Endpoint DLP rule, and one engine
    per rule keeps every rule's incidents attributable. Names are
    `<prefix><engine> [<Channel>]`, fitted to the channel's name limit
    (31 on SaaS) and made unique within the pack."""
    seen: List[str] = []
    for e in engine_names:
        if e and e not in seen:
            seen.append(e)
    taken: set = set()
    out: List[Dict[str, Any]] = []
    for e in seen:
        stem = f"{prefix or ''}{e}"
        name = fit_rule_name(stem, channel, f" [{EXTENSION_SUFFIX[channel]}]")
        n = 2
        while name in taken:
            name = fit_rule_name(stem, channel, f" {n} [{EXTENSION_SUFFIX[channel]}]")
            n += 1
        taken.add(name)
        out.append(extension_policy(channel, pack_name=pack_name, prefix=prefix, engine_names=engine_names, pack_id=pack_id,
                                    engine=e, name=name))
    return out


def apply_channel_targets(policies: List[Dict[str, Any]], targets: Optional[Sequence[str]], *, pack_name: str,
                          prefix: str, engine_names: Sequence[str], pack_id: str = "") -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Filter a pack's policies to the chosen DLP channels and add an
    extension rule for every chosen channel the pack has no rule for.
    Returns (policies, note) where note lists what was skipped and added."""
    norm = normalize_targets(targets)
    note: Dict[str, Any] = {"targets": norm, "skipped_channels": [], "skipped_rules": [], "extended": [], "warnings": [],
                            "carved_out": [], "carved_channels": []}
    # A pack deploys detection only. Carve the containment channels out
    # before anything else, whatever the channel choice, so they never
    # reach a plan, a Terraform workspace or the tenant.
    carve = _carved_channels()
    if carve:
        content, carved = [], []
        for p in policies:
            (carved if channel_of(p) in carve else content).append(p)
        if carved:
            note["carved_out"] = [p.get("name", "?") for p in carved]
            note["carved_channels"] = sorted({channel_of(p) for p in carved})
        policies = content
    if norm is None:
        return list(policies), note
    present = {channel_of(p) for p in policies}
    kept: List[Dict[str, Any]] = []
    for p in policies:
        ch = channel_of(p)
        if ch in DLP_CHANNELS and ch not in norm:
            note["skipped_rules"].append(p.get("name", "?"))
            if ch not in note["skipped_channels"]:
                note["skipped_channels"].append(ch)
            continue
        kept.append(p)
    for ch in norm:
        if ch in present:
            continue
        if not engine_names:
            note["warnings"].append(f"{label(ch)} was selected but the pack has no engines to put on that channel; nothing added.")
            continue
        for p in extension_policies(ch, pack_name=pack_name, prefix=prefix, engine_names=engine_names, pack_id=pack_id):
            kept.append(p)
            note["extended"].append({"name": p["name"], "channel": ch})
    return kept, note


def has_engines(channel: str) -> bool:
    """True for the DLP channels whose rules carry DLP engines (not the containment channels)."""
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
    # Keywords matched against the onboarded tenant's application name, so
    # a rule of this SaaS type finds a tenant it can scan. Suite names
    # (Microsoft 365, Google Workspace) appear under every type the suite
    # carries.
    "OFLCASB_DLP_FILE": ("BOX", "DROPBOX", "GDRIVE", "GOOGLE_DRIVE", "GOOGLEDRIVE", "GOOGLE_WORKSPACE", "ONEDRIVE", "ONE_DRIVE",
                         "SHAREPOINT", "MICROSOFT_365", "M365", "EGNYTE", "SHAREFILE", "CITRIX", "SMARTSHEET"),
    "OFLCASB_DLP_EMAIL": ("GMAIL", "GOOGLE_MAIL", "GOOGLE_WORKSPACE", "GSUITE", "G_SUITE", "OFFICE365", "OFFICE_365", "O365", "EXCHANGE",
                          "EXCHANGE_ONLINE", "OUTLOOK", "MICROSOFT_365", "M365", "EMAIL", "MAIL", "SMTP"),
    "OFLCASB_DLP_COLLAB": ("SLACK", "TEAMS", "MICROSOFT_365", "M365", "WEBEX", "WEBEX_TEAMS", "ZOOM", "GOOGLE_CHAT", "GCHAT", "CONFLUENCE"),
    "OFLCASB_DLP_CRM": ("SALESFORCE", "HUBSPOT", "DYNAMICS"),
    "OFLCASB_DLP_ITSM": ("SERVICENOW", "SERVICE_NOW", "JIRA", "ATLASSIAN", "CONFLUENCE", "ZENDESK", "FRESHDESK", "FRESHSERVICE"),
    "OFLCASB_DLP_REPO": ("GITHUB", "GITLAB", "BITBUCKET", "AZURE_DEVOPS", "DEVOPS"),
    "OFLCASB_DLP_STORAGE": ("AWS", "S3", "AZURE", "BLOB", "GCP", "GCS", "GOOGLE_CLOUD"),
    "OFLCASB_DLP_GENAI": ("CHATGPT", "OPENAI", "GEMINI", "COPILOT", "CLAUDE", "ANTHROPIC", "GENAI", "PERPLEXITY"),
}
EMAIL_APPS = SAAS_TYPE_APPS["OFLCASB_DLP_EMAIL"]
# Email DLP tenants are Exchange, Gmail or a secure email gateway (SEG).
# "SEG" and "GATEWAY" are matched as whole name parts, not substrings.
EMAIL_APP_TOKENS = ("SEG", "GATEWAY", "EMAIL_GATEWAY", "SECURE_EMAIL_GATEWAY")


def _is_email_tenant(t: Dict[str, Any]) -> bool:
    app = str(t.get("app") or "")
    parts = set(re.split(r"[^A-Z0-9]+", app))
    return any(k in app for k in EMAIL_APPS) or any(tok in parts or tok == app for tok in EMAIL_APP_TOKENS)

# The SaaS Security API caps a rule name at 31 characters ("Name exceeds
# the max length 31 characters" from a real tenant); Web, Endpoint and
# Email rules took longer names on the same tenant.
RULE_NAME_MAX: Dict[str, int] = {SAAS: 31}


def fit_rule_name(name: str, channel: str, suffix: str = "") -> str:
    """`name + suffix` within the channel's name limit: the name is shortened
    at a word boundary where one is near, never the suffix."""
    limit = RULE_NAME_MAX.get(channel)
    full = f"{name}{suffix}"
    if not limit or len(full) <= limit:
        return full
    room = max(1, limit - len(suffix))
    cut = name[:room]
    sep = max(cut.rfind(" "), cut.rfind("-"))
    if sep >= room * 0.55:   # whole words when enough of the name survives
        cut = cut[:sep]
    return cut.rstrip(" -_") + suffix


ENDPOINT_TRUST_LEVELS = ("UNKNOWN_DEVICETRUSTLEVEL", "LOW_TRUST", "MEDIUM_TRUST", "HIGH_TRUST")
ENDPOINT_RISK_LEVELS = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
# An Endpoint DLP rule applies to exactly one transfer method ("channel" in
# the portal): a real tenant answered "Channel is mandatory" for a rule
# without one, and the zscaler/zia provider accepts only these four (no
# "ANY"). Pack mirrors watch removable media; add a rule per method for more.
ENDPOINT_TRANSFER_METHODS = ("REMOVABLE_DRIVE_TRANSFER", "NETWORK_DRIVE_TRANSFER", "APPLICATION_FILE_ACCESS", "PRINTING")
ENDPOINT_DEFAULT_TRANSFER_METHOD = "REMOVABLE_DRIVE_TRANSFER"
# ZIA refuses an Endpoint DLP rule with more engines than this
# ("Exceeded maximum number of DLP engines: 4"). Pack rules and the
# channel-selection extension rules carry one engine each.
ENDPOINT_MAX_ENGINES = 4


def channel_of(policy_def: Dict[str, Any]) -> str:
    """The channel a pack policy targets (`channel` field, default web), lower-cased."""
    ch = str(policy_def.get("channel") or WEB).strip().lower()
    return ch if ch in CHANNELS else ch  # unknown channels are reported by validate()


def label(channel: str) -> str:
    """The channel's display name (for example "Endpoint DLP")."""
    return CHANNELS.get(channel, {}).get("label", channel)


def is_enforcing(channel: str, action: Optional[str]) -> bool:
    """True when `action` blocks, confirms, quarantines or otherwise enforces on `channel` (monitoring actions are False)."""
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
    """The monitor-only action every pack rule is created with on `channel`."""
    return {SAAS: "OFLCASB_DLP_REPORT_INCIDENT", SSL: "DO_NOT_DECRYPT", CLOUD_APP: ""}.get(channel, "ALLOW")


def target_action(p: Dict[str, Any]) -> str:
    """The action a rule is designed to reach once tuned: `target_action`
    when the pack carries one, otherwise the action it ships with."""
    return str(p.get("target_action") or policy_action(p))


def ship_monitor(policies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """DLP-Check's convention, applied to every pack (built-in or uploaded)
    the moment it is loaded: every rule ships DISABLED, and every DLP rule
    (Web, Endpoint, SaaS, Email) ships with the channel's monitor action
    (ALLOW / report incident). A rule designed to block or confirm keeps
    that as `target_action`: the data-governance journey names it as the
    step to harden to once incidents have been reviewed. Containment rules
    (Cloud App Control, File Type, URL, SSL) have no monitor form and are
    left as designed. The DISABLED state is forced where the rule is
    created (build_payload and the web payload builder), so an existing
    rule the customer enabled still compares as their progress. The
    originals are never modified."""
    out: List[Dict[str, Any]] = []
    for p in policies:
        q = dict(p)
        ch = channel_of(q)
        if has_engines(ch):
            action = policy_action(q)
            if is_enforcing(ch, action):
                q["target_action"] = q.get("target_action") or action
                q["action"] = default_action(ch)
        out.append(q)
    return out


def validate(policy_def: Dict[str, Any]) -> Optional[str]:
    """Static pack-level validation. Returns an error string or None."""
    ch = channel_of(policy_def)
    if ch not in CHANNELS:
        return f"unknown channel '{ch}' (use one of {', '.join(CHANNELS)})"
    from dlp_importer import RULE_DESCRIPTION_MAX
    if len(str(policy_def.get("description") or "")) > RULE_DESCRIPTION_MAX:
        return f"description is {len(str(policy_def.get('description')))} characters; ZIA allows {RULE_DESCRIPTION_MAX}"
    if ch == WEB:
        from dlp_importer import web_protocol_problems
        problems = web_protocol_problems(policy_def.get("protocols") or ["ANY_RULE"])
        if problems:
            return problems[0]
    if ch == ENDPOINT:
        dtm = policy_def.get("data_transfer_method")
        if dtm and dtm not in ENDPOINT_TRANSFER_METHODS:
            return (f"unknown data_transfer_method '{dtm}' (an Endpoint DLP rule applies to one transfer method; "
                    f"use one of {', '.join(ENDPOINT_TRANSFER_METHODS)})")
        n_eng = len(policy_def.get("engines") or [])
        if n_eng > ENDPOINT_MAX_ENGINES:
            return (f"carries {n_eng} engines; ZIA allows at most {ENDPOINT_MAX_ENGINES} on an Endpoint DLP rule "
                    f"('Exceeded maximum number of DLP engines: {ENDPOINT_MAX_ENGINES}') — split it one engine per rule")
        for sr in policy_def.get("sub_rules") or []:
            if not sr.get("name"):
                return "every sub_rule needs a name"
    elif policy_def.get("sub_rules") or policy_def.get("parent_rule") or policy_def.get("endpoint_application_groups"):
        return "sub_rules, parent_rule and endpoint_application_groups apply to the endpoint channel only"
    if ch == SAAS:
        n = str(policy_def.get("name") or "")
        if len(n) > RULE_NAME_MAX[SAAS]:
            return (f"SaaS rule name '{n}' is {len(n)} characters; the SaaS Security API allows {RULE_NAME_MAX[SAAS]} "
                    "('Name exceeds the max length 31 characters')")
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

from dlp_importer import _nx, _obj_to_dict  # noqa: E402 - one (data, error) reader for every SDK return shape


def _field(obj: Any, *keys: str, default: Any = None) -> Any:
    """Read a field from an SDK object or dict, trying every spelling in
    `keys` (snake_case and camelCase: the SDK returns both depending on
    the call). Objects with to_dict()/as_dict() are read through it first."""
    d = obj if isinstance(obj, dict) else _obj_to_dict(obj)
    if isinstance(d, dict):
        for k in keys:
            if k in d and d[k] is not None:
                return d[k]
    for k in keys:
        v = getattr(obj, k, None)
        if v is not None:
            return v
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
        "data_transfer_method": _field(r, "data_transfer_method", "dataTransferMethod"),
        "parent_id": _field(r, "parent_rule", "parentRule"),
    }


def count_rules(zia, channel: str) -> Tuple[Optional[int], Optional[str]]:
    """How many rules the tenant has on one DLP channel (top-level rules;
    Endpoint sub-rules are not counted), with the same listing calls the
    deploy uses. Returns (count, error)."""
    svc = getattr(zia, CHANNELS[channel]["service"], None)
    if svc is None:
        return None, f"{CHANNELS[channel]['service']} is not available in the installed zscaler-sdk-python"
    try:
        if channel == SAAS:
            lister = getattr(svc, "list_all_rules", None)
            data, err = _nx(lister()) if lister else _nx(svc.list_rules("ANY"))
        else:
            data, err = _nx(svc.list_rules())
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]
    if err:
        return None, str(err)[:200]
    return len(data or []), None


def needs(policy_defs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """What tenant state the plan has to read for these policies."""
    out = {"channels": set(), "casb": False, "templates": False, "labels": False, "app_classes": set(),
           "cloud_app_types": set(), "cloud_app_actions": [], "endpoint_app_groups": False}
    for p in policy_defs:
        ch = channel_of(p)
        out["channels"].add(ch)
        if ch == ENDPOINT and (p.get("endpoint_application_groups") or p.get("sub_rules")):
            out["endpoint_app_groups"] = True
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


def fetch_channel_state(zia, need: Dict[str, Any], log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Read the rule lists for every non-web channel the packs use, plus
    the shared prerequisites (SaaS tenants, notification templates,
    labels) they reference. Never raises; errors are recorded per item so
    one unlicensed feature only blocks the rules that need it. `log` gets
    one line per read, so a long tenant read is never silent."""
    _log = log or (lambda m: None)
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
        "app_groups": {},     # endpoint application group name -> {id, resources}
        "app_groups_error": None,
        "planned_app_groups": set(),
    }
    if need.get("endpoint_app_groups"):
        _log("Reading the tenant: endpoint application groups…")
        state["app_groups"], state["app_groups_error"] = list_app_groups(zia)
    for cls in sorted(need.get("app_classes") or ()):
        _log(f"Reading the tenant: cloud applications of class {cls}…")
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
        _log(f"Reading the tenant: {label(ch)} rules…")
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
            rules = sorted((_rule_summary(r, ch) for r in (data or [])), key=lambda r: r["order"])
            if ch == ENDPOINT:
                # Sub-rules live inside their parent; flatten them so packs can
                # match them by name (names are unique tenant-wide).
                flat = []
                for r, raw in zip(rules, sorted((data or []), key=lambda x: int(_field(x, "order", default=0) or 0))):
                    flat.append(r)
                    for sr in (_field(raw, "sub_rules", "subRules", default=[]) or []):
                        srs = _rule_summary(sr, ch)
                        srs["parent_id"] = r["id"]
                        srs["parent_name"] = r["name"]
                        flat.append(srs)
                rules = flat
            if ch == EMAIL:
                # An Exchange (or Gmail / SEG) integration used for Email DLP is
                # an email tenant the SaaS tenant list does not return (seen on a
                # live tenant: casbTenant/lite listed only SharePoint while an
                # Email DLP rule was scoped to the Exchange tenant). The rules
                # that already use one are the reliable way to find it.
                seen_ids = set()
                found = []
                for raw in data or []:
                    for t in (_field(raw, "email_tenants", "emailTenants", default=[]) or []):
                        tid, tname = _field(t, "id"), str(_field(t, "name", default="") or "").strip()
                        if tid is not None and str(tid) not in seen_ids:
                            seen_ids.add(str(tid))
                            found.append({"id": tid, "name": tname or str(tid), "app": "EMAIL",
                                          "status": [], "from_rule": str(_field(raw, "name", default="") or "").strip()})
                state["email_tenants_in_rules"] = found
            state["rules"][ch] = rules
            _log(f"Reading the tenant: {label(ch)} rules: {len(rules)} found.")
        except Exception as e:  # noqa: BLE001 — surfaced as a dependency failure
            state["errors"][ch] = str(e)[:200]
            _log(f"Reading the tenant: {label(ch)} rules could not be listed: {str(e)[:120]}")

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
        _log("Reading the tenant: SaaS application tenants…")
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
            # Zscaler's own answer to "which of these are email tenants"
            # (Exchange, Gmail, secure email gateway), whatever the
            # application is called; the name match is the fallback.
            try:
                edata, eerr = _nx(svc.list_casb_tenant_lite(query_params={"active_only": True, "app_type": "EMAIL"}))
                if not eerr:
                    ids = {_field(t, "tenant_id", "tenantId", "id") for t in (edata or [])}
                    state["email_tenant_ids"] = sorted(str(i) for i in ids if i is not None)
                    known = {str(t["id"]) for t in tenants}
                    for t in edata or []:
                        tid = _field(t, "tenant_id", "tenantId", "id")
                        name = str(_field(t, "tenant_name", "tenantName", "name", default="") or "").strip()
                        if tid is not None and name and str(tid) not in known:
                            tenants.append({"id": tid, "name": name,
                                            "app": str(_field(t, "saas_application", "saasApplication", default="") or "").upper(),
                                            "status": _field(t, "status", default=[])})
            except Exception:  # noqa: BLE001 — the name match still applies
                pass
        except Exception as e:  # noqa: BLE001
            state["casb_tenants"] = []
            state["casb_error"] = str(e)[:200]

    if need["templates"]:
        _log("Reading the tenant: DLP notification templates…")
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


def email_tenants(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The onboarded email tenants (Exchange, Gmail, secure email gateway):
    the ones Zscaler lists as EMAIL, any whose application name says so, and
    the email tenants existing Email DLP rules are scoped to (an Exchange
    integration the SaaS tenant list does not return)."""
    tenants = state.get("casb_tenants") or []
    by_type = set(state.get("email_tenant_ids") or [])
    out = [t for t in tenants if str(t["id"]) in by_type or _is_email_tenant(t)]
    have = {str(t["id"]) for t in out}
    out += [t for t in (state.get("email_tenants_in_rules") or []) if str(t["id"]) not in have]
    return out


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
            if channel == EMAIL:
                by_name.update({t["name"].lower(): t for t in email_tenants(state)})
            chosen, absent = [], []
            for w in want:
                t = by_name.get(str(w).strip().lower())
                (chosen if t else absent).append(t if t else str(w))
            if absent:
                missing.append(f"SaaS application tenant(s) not onboarded: {', '.join(absent)} (available: {_tenant_list(tenants)})")
            resolved["tenants"] = chosen
        elif channel == EMAIL:
            # ZIA refuses an Email DLP rule without an email tenant ("One or
            # more Email tenants is required", HTTP 400, seen on a live
            # tenant), whatever the SDK's example suggests. With "any", scope
            # it to the onboarded Exchange / Gmail / secure email gateway
            # tenants; with none, the rule is a gap found here, before any
            # request: a run of refused writes makes ZIA block the API client
            # (Resource Access Blocked) and stops the rest of the deploy.
            chosen = email_tenants(state)
            if not chosen:
                missing.append(
                    "ZIA requires at least one email tenant on an Email DLP rule, and no Exchange, Gmail or secure email "
                    "gateway tenant is onboarded" + (f" (onboarded: {_tenant_list(tenants)})" if tenants else "")
                    + "; onboard one under Administration > SaaS Application Tenants, then deploy the Email channel")
            resolved["tenants"] = chosen
        else:
            keywords = SAAS_TYPE_APPS.get(policy_def.get("saas_type", ""), ())
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

    # Endpoint DLP: application groups by name (created by the pack or already
    # in the tenant) and the parent rule of a sub-rule.
    if channel == ENDPOINT:
        groups = policy_def.get("endpoint_application_groups") or []
        if groups:
            if state.get("app_groups_error"):
                missing.append(f"endpoint application groups could not be listed ({state['app_groups_error']})")
            known = state.get("app_groups") or {}
            planned = state.get("planned_app_groups") or set()
            ids = []
            for g in groups:
                if g in known and known[g].get("id") is not None:
                    ids.append(known[g]["id"])
                    depends.append(("resource", f"Endpoint application group: {g}"))
                elif g in planned:
                    depends.append(("app_group", g))
                else:
                    missing.append(f"endpoint application group '{g}' exists in neither the pack nor the tenant")
            resolved["app_group_ids"] = ids
        if policy_def.get("parent_rule"):
            depends.append(("policy", str(policy_def["parent_rule"])))

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
                em = email_tenants(state)
                st = "ok" if em else "missing"
                from_rules = [t for t in em if t.get("from_rule")]
                detail = (f"Email tenant(s): {_tenant_list(em)}."
                          + (f" Found on existing Email DLP rules ({', '.join(sorted({t['from_rule'] for t in from_rules}))}); "
                             "the SaaS tenant list does not return them." if from_rules else "")
                          if em else
                          f"No Exchange, Gmail or secure email gateway tenant in the SaaS tenant list (listed: {_tenant_list(tenants)}) or on an "
                          "existing Email DLP rule. ZIA requires at least one email tenant on an Email DLP rule; onboard one, then deploy the Email channel.")
            else:
                st = "ok" if tenants else "missing"
                detail = f"Onboarded: {_tenant_list(tenants)}." if tenants else "No SaaS application tenant onboarded."
            rows.append({
                "channel": ch, "label": spec["label"], "status": st,
                "requirement": ("An email tenant (required by ZIA: Exchange, Gmail or a secure email gateway)"
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
        # Labels and the notification template are named in the pack and
        # resolved to this tenant's ids in preflight, as on every channel.
        p = dict(p, labels=list(resolved.get("labels") or []))
        payload = build_policy_payload(p, engine_ids, use_rank_0=use_rank_0)
        if resolved.get("notification_template") is not None:
            payload["notification_template"] = {"id": resolved["notification_template"]}
        return payload

    if channel in CONTROL_CHANNELS:
        return _build_control_payload(channel, p, resolved, use_rank_0=use_rank_0)

    body: Dict[str, Any] = {
        "name": p["name"],
        "order": 1,
        # Every rule is created DISABLED and monitor-only, whatever the pack says.
        "state": "DISABLED",
        "action": p.get("action", default_action(channel)) if not is_enforcing(channel, str(p.get("action") or "")) else default_action(channel),
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
        # ZIA: "Channel is mandatory" — every endpoint rule names one transfer method.
        body["data_transfer_method"] = p.get("data_transfer_method") or ENDPOINT_DEFAULT_TRANSFER_METHOD
        for opt in ("user_risk_score_levels", "network_type", "min_size"):
            if p.get(opt):
                body[opt] = p[opt]
        if p.get("eun_enabled") is not None:
            body["eun_enabled"] = bool(p["eun_enabled"])
        if resolved.get("app_group_ids"):
            body["end_point_application_groups"] = _ids(resolved["app_group_ids"])
        if resolved.get("uc_template_id") is not None and str(p.get("action", "")).upper() == "CONFIRM":
            body["uc_template_id"] = resolved["uc_template_id"]
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
        "state": "DISABLED",   # every rule is created disabled, containment rules included
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
    """Create a rule on `channel` through the SDK service for that channel
    (SaaS rules also pass their type). Called through pack_ops.create."""
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


def saas_rule_type(zia, rule_id: Any) -> Optional[str]:
    """The ruleType of one SaaS Security API rule, looked up by id (the
    delete API needs it). None when it cannot be found."""
    svc = getattr(zia, CHANNELS[SAAS]["service"], None)
    if svc is None:
        return None
    try:
        lister = getattr(svc, "list_all_rules", None)
        data, err = _nx(lister()) if lister else _nx(svc.list_rules("ANY"))
    except Exception:  # noqa: BLE001
        return None
    if err:
        return None
    for r in data or []:
        if str(_field(r, "id")) == str(rule_id):
            t = _field(r, "type", "rule_type", "ruleType")
            return str(t) if t else None
    return None


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
        names = {str(_field(r, "name", default="") or "").strip() for r in (data or [])}
        if channel == ENDPOINT:
            for r in data or []:
                for sr in (_field(r, "sub_rules", "subRules", default=[]) or []):
                    names.add(str(_field(sr, "name", default="") or "").strip())
        return names, None
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
        extra.update({"device_trust_levels": sorted(p.get("device_trust_levels") or ENDPOINT_TRUST_LEVELS),
                      "data_transfer_method": p.get("data_transfer_method"), "parent_rule": p.get("parent_rule"),
                      "endpoint_application_groups": sorted(p.get("endpoint_application_groups") or [])})
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
