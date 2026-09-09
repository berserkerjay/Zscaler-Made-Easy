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

CHANNELS: Dict[str, Dict[str, Any]] = {
    WEB: {
        "label": "Web DLP",
        "long": "Inline web DLP (ZIA)",
        "service": "dlp_web_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CONFIRM", "ICAP_RESPONSE"},
        "rule_cap": 127,
        "needs_casb": False,
    },
    ENDPOINT: {
        "label": "Endpoint DLP",
        "long": "Endpoint DLP (Zscaler Client Connector)",
        "service": "endpoint_dlp_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CONFIRM"},
        "rule_cap": None,
        "needs_casb": False,
    },
    SAAS: {
        "label": "SaaS Security API",
        "long": "SaaS Security API (out-of-band CASB) DLP",
        "service": "casb_dlp_rules",
        "monitor_actions": {"OFLCASB_DLP_REPORT_INCIDENT", "OFLCASB_DLP_ALLOW"},
        "enforcing_actions": None,  # anything that is not a monitor action
        "rule_cap": None,
        "needs_casb": True,
    },
    EMAIL: {
        "label": "Email DLP",
        "long": "Outbound Email DLP",
        "service": "outbound_email_dlp_rules",
        "monitor_actions": {"ALLOW"},
        "enforcing_actions": {"BLOCK", "CUSTOMHEADERINSERTION"},
        "rule_cap": None,
        "needs_casb": True,
    },
}

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
    if spec["enforcing_actions"] is None:
        return bool(action) and action not in spec["monitor_actions"]
    return action in spec["enforcing_actions"]


def default_action(channel: str) -> str:
    return "OFLCASB_DLP_REPORT_INCIDENT" if channel == SAAS else "ALLOW"


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


def _rule_summary(r: Any) -> Dict[str, Any]:
    return {
        "id": _field(r, "id"),
        "name": str(_field(r, "name", default="") or "").strip(),
        "order": int(_field(r, "order", default=0) or 0),
        "rank": _field(r, "rank"),
        "action": _field(r, "action"),
        "state": _field(r, "state"),
        "type": _field(r, "type"),
        # Content fields used for baseline drift detection.
        "engine_ids": engine_ids_of(r),
        "severity": _field(r, "severity"),
        "description": _field(r, "description"),
    }


def needs(policy_defs: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """What tenant state the plan has to read for these policies."""
    out = {"channels": set(), "casb": False, "templates": False, "labels": False, "app_classes": set()}
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
            else:
                data, err = _nx(svc.list_rules())
            if err:
                raise RuntimeError(str(err))
            state["rules"][ch] = sorted((_rule_summary(r) for r in (data or [])), key=lambda r: r["order"])
        except Exception as e:  # noqa: BLE001 — surfaced as a dependency failure
            state["errors"][ch] = str(e)[:200]

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
    if classes:
        apps: List[str] = []
        for cls in classes:
            err = (state.get("app_class_errors") or {}).get(cls)
            found = (state.get("app_classes") or {}).get(cls) or []
            if err:
                missing.append(f"cloud applications of class {cls} could not be listed ({err})")
                depends.append(("missing", f"Cloud applications: {cls}"))
            elif not found:
                missing.append(f"the tenant exposes no cloud applications of class {cls}; set \"cloud_applications\" explicitly instead")
                depends.append(("missing", f"Cloud applications: {cls}"))
            else:
                apps.extend(found)
                depends.append(("resource", f"Cloud applications: {cls} ({len(found)})"))
        resolved["cloud_applications"] = sorted(set(apps))

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

    for ch in (WEB, ENDPOINT, SAAS, EMAIL):
        items = by_channel.get(ch)
        if not items:
            continue
        spec = CHANNELS[ch]
        # Shared chain.
        rows.append({
            "channel": ch, "label": spec["label"], "status": "info",
            "requirement": "DLP dictionaries and engines referenced by these rules",
            "detail": "Resolved per rule in the plan (created by the pack or reused from the tenant).",
            "rules": names(items),
        })
        if ch == WEB:
            rows.append({
                "channel": ch, "label": spec["label"], "status": "ok",
                "requirement": "Web DLP rule API reachable",
                "detail": f"{tenant_web_rules} existing rule(s); API cap {spec['rule_cap']}.",
                "rules": names(items),
            })
        else:
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
                        "requirement": lab, "detail": "Referenced by name in the pack.", "rules": [it["name"]],
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


def add_rule(zia, channel: str, payload: Dict[str, Any]):
    svc = getattr(zia, CHANNELS[channel]["service"])
    return svc.add_rule(**payload)


def update_rule(zia, channel: str, rule_id: Any, payload: Dict[str, Any]):
    """Overwrite an existing rule with a full baseline payload (PUT semantics)."""
    svc = getattr(zia, CHANNELS[channel]["service"])
    return svc.update_rule(rule_id, **payload)


def list_rule_names(zia, channel: str) -> Tuple[Optional[set], Optional[str]]:
    """Fresh name set for post-deploy verification."""
    svc = getattr(zia, CHANNELS[channel]["service"], None)
    if svc is None:
        return None, "service unavailable"
    try:
        if channel == SAAS:
            lister = getattr(svc, "list_all_rules", None)
            data, err = _nx(lister()) if lister else _nx(svc.list_rules("ANY"))
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
    return extra
