"""Native Zscaler JSON → pack definitions.

The ZIA API (and the admin portal's exports) hand back dictionaries,
engines and rules in their own shape: camelCase fields, numeric ids,
engine expressions written as `D<id>.S > n`, rules that reference
engines, templates, labels, locations and tenants by id. A pack keeps
everything by name so it can be deployed to any tenant and rendered as
Terraform.

This module recognises those native objects inside an upload and
rewrites them into the pack schema:

  dlpDictionaries  → dictionaries (custom ones; predefined ones only lend
                     their names to engine expressions)
  dlpEngines       → engines with `D:<dictionary name>` expressions
  webDlpRules      → web policies
  endpointDlpRules → endpoint policies (sub-rules kept)
  casbDlpRules     → saas policies (tenants → "any")
  emailDlpRules    → email policies (tenants → "any")

Tenant-specific scope (location, group, department and user ids, tenant
ids) cannot travel between tenants and is dropped with a warning that
says so; rule order is dropped too (a pack always inserts at the top).
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

_NATIVE_DICT_KEYS = {"dictionaryType", "customPhraseMatchType", "confidenceThreshold", "predefinedClone", "dictTemplateName", "nameL10nTag"}
_NATIVE_ENGINE_KEYS = {"engineExpression", "predefinedEngineName", "customDlpEngine"}
_NATIVE_RULE_KEYS = {"dlpEngines", "urlCategories", "cloudApplications", "fileTypes", "minSize", "ocrEnabled", "zscalerIncidentReceiver",
                     "withoutContentInspection", "dataTransferMethod", "deviceTrustLevels", "cloudAppTenants", "collaborationScope",
                     "emailTenants", "endPointApplicationGroups", "userRiskScoreLevels", "eunEnabled", "matchOnly"}

_SCOPE_FIELDS = ("locations", "locationGroups", "groups", "departments", "users", "excludedGroups", "excludedDepartments", "excludedUsers",
                 "timeWindows", "workloadGroups")
_TERM_RE = re.compile(r"D(\d+)\.S")
# The only custom match type ZIA accepts a proximity window on.
PROXIMITY_MATCH_TYPE = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
_EMAIL_ACTIONS = {"ALLOW", "BLOCK", "CUSTOMHEADERINSERTION", "CUSTOM_HEADER_INSERTION"}


def is_native(obj: Any) -> bool:
    if not isinstance(obj, dict):
        return False
    keys = set(obj.keys())
    if keys & _NATIVE_ENGINE_KEYS or keys & _NATIVE_DICT_KEYS:
        return True
    if "dlpEngines" in keys or (keys & _NATIVE_RULE_KEYS and "engines" not in keys and "expression" not in keys):
        return True
    return False


def kind_of(obj: Dict[str, Any]) -> Optional[str]:
    keys = set(obj.keys())
    if keys & _NATIVE_ENGINE_KEYS:
        return "engines"
    if keys & _NATIVE_DICT_KEYS or ("phrases" in keys and "custom" in keys):
        return "dictionaries"
    if "dlpEngines" in keys or keys & _NATIVE_RULE_KEYS:
        return "policies"
    return None


def _names(items: Any) -> List[str]:
    out = []
    for x in items or []:
        if isinstance(x, dict):
            v = x.get("name") or x.get("id")
        else:
            v = x
        if v is not None:
            out.append(str(v))
    return out


def _channel(rule: Dict[str, Any], hint: str = "") -> str:
    keys = set(rule.keys())
    h = hint.lower()
    if keys & {"dataTransferMethod", "deviceTrustLevels", "endPointApplicationGroups", "subRules"} or "endpoint" in h:
        return "endpoint"
    t = str(rule.get("type") or "")
    if keys & {"cloudAppTenants", "collaborationScope", "components", "contentLocation"} or t.startswith("OFLCASB") or "casb" in h or "saas" in h:
        return "saas"
    if "emailTenants" in keys or "email" in h:
        return "email"
    return "web"


# ── dictionaries ───────────────────────────────────────────────────────
def convert_dictionary(d: Dict[str, Any], warnings: List[str]) -> Optional[Dict[str, Any]]:
    """A native dictionary → pack dictionary, or None for a predefined one."""
    name = str(d.get("name") or "").strip()
    if not name:
        return None
    custom = bool(d.get("custom") or d.get("customDictionary")) or str(d.get("dictionaryType") or "").upper() not in ("PREDEFINED", "PATTERN_BASED_PREDEFINED", "")
    if not custom or (not d.get("phrases") and not d.get("patterns") and not d.get("predefinedClone") and not d.get("dictTemplateName")):
        return None
    out: Dict[str, Any] = {"name": name}
    if d.get("description"):
        out["description"] = str(d["description"])
    if d.get("customPhraseMatchType"):
        out["custom_phrase_match_type"] = d["customPhraseMatchType"]
    if d.get("dictionaryType") and str(d["dictionaryType"]).upper() not in ("PATTERNS_AND_PHRASES",):
        out["dictionary_type"] = d["dictionaryType"]
    if d.get("confidenceThreshold"):
        out["confidence_threshold"] = d["confidenceThreshold"]
    if d.get("proximityLengthEnabled") or d.get("proximity"):
        try:
            prox = int(d.get("proximity") or 0)
            if prox:
                out["proximity"] = prox
        except (TypeError, ValueError):
            pass
    out["phrases"] = [{"action": p.get("action") or "PHRASE_COUNT_TYPE_ALL", "phrase": p.get("phrase")} for p in (d.get("phrases") or []) if isinstance(p, dict) and p.get("phrase")]
    out["patterns"] = [{"action": p.get("action") or "PATTERN_COUNT_TYPE_ALL", "pattern": p.get("pattern")} for p in (d.get("patterns") or []) if isinstance(p, dict) and p.get("pattern")]
    if out.get("proximity") and not d.get("predefinedClone") and out.get("custom_phrase_match_type", PROXIMITY_MATCH_TYPE) != PROXIMITY_MATCH_TYPE:
        # ZIA accepts a proximity window on a custom dictionary only with
        # "Match any Patterns and any Phrases"; anything else is refused on
        # create, so the pack is made deployable here and the change named.
        if out["phrases"] and out["patterns"]:
            warnings.append(f"dictionary '{name}': proximity {out['proximity']} is only accepted on {PROXIMITY_MATCH_TYPE}; match type changed from {out.get('custom_phrase_match_type')}")
            out["custom_phrase_match_type"] = PROXIMITY_MATCH_TYPE
        else:
            warnings.append(f"dictionary '{name}': proximity {out['proximity']} dropped; it needs both patterns and phrases on {PROXIMITY_MATCH_TYPE}")
            out.pop("proximity", None)
    if d.get("predefinedClone"):
        out["predefined_clone"] = True
    if d.get("dictTemplateName"):
        out["dict_template_name"] = d["dictTemplateName"]
    if d.get("exactDataMatchDetails") or str(d.get("dictionaryType") or "").upper() in ("EXACT_DATA_MATCH", "INDEXED_DATA_MATCH"):
        warnings.append(f"dictionary '{name}' is an EDM/IDM dictionary: its index lives in the source tenant and is not carried over")
    return out


# ── engines ────────────────────────────────────────────────────────────
def convert_engine(e: Dict[str, Any], id_to_name: Dict[str, str], warnings: List[str]) -> Optional[Dict[str, Any]]:
    name = str(e.get("name") or e.get("predefinedEngineName") or "").strip()
    if not name:
        return None
    if e.get("predefinedEngineName") and not e.get("customDlpEngine"):
        return None   # predefined engines exist in every tenant; rules reference them by name
    expr = str(e.get("engineExpression") or e.get("expression") or "").strip()
    if not expr:
        warnings.append(f"engine '{name}' has no expression and was left out")
        return None
    unresolved: List[str] = []

    def sub(m):
        did = m.group(1)
        n = id_to_name.get(did)
        if n is None:
            unresolved.append(did)
            return f"D:UNKNOWN_DICTIONARY_{did}"
        return f"D:{n}"
    out_expr = _TERM_RE.sub(sub, expr)
    if unresolved:
        warnings.append(f"engine '{name}' references dictionary id(s) {', '.join(sorted(set(unresolved)))} that are not in the upload; "
                        "add the dlpDictionaries export (predefined dictionaries included) so the ids can be named")
    out = {"name": name, "expression": out_expr}
    if e.get("description"):
        out["description"] = str(e["description"])
    return out


# ── rules ──────────────────────────────────────────────────────────────
def _common(rule: Dict[str, Any], warnings: List[str]) -> Dict[str, Any]:
    name = str(rule.get("name") or "").strip()
    out: Dict[str, Any] = {"name": name}
    if rule.get("description"):
        out["description"] = str(rule["description"])
    act = rule.get("action")
    if isinstance(act, dict):
        act = act.get("type")
    if act:
        out["action"] = str(act)
    out["state"] = str(rule.get("state") or "ENABLED")
    if rule.get("rank") is not None:
        try:
            out["rank"] = int(rule["rank"])
        except (TypeError, ValueError):
            pass
    engines = _names(rule.get("dlpEngines") or rule.get("dlp_engines"))
    if engines:
        out["engines"] = engines
    if rule.get("severity"):
        out["severity"] = rule["severity"]
    if rule.get("fileTypes"):
        out["file_types"] = list(rule["fileTypes"])
    if rule.get("labels"):
        out["labels"] = _names(rule["labels"])
    tpl = rule.get("notificationTemplate")
    if isinstance(tpl, dict) and tpl.get("name"):
        out["notification_template"] = tpl["name"]
    if rule.get("withoutContentInspection"):
        out["without_content_inspection"] = True
    if rule.get("userRiskScoreLevels"):
        out["user_risk_score_levels"] = list(rule["userRiskScoreLevels"])
    dropped = [k for k in _SCOPE_FIELDS if rule.get(k)]
    if dropped:
        warnings.append(f"rule '{name}': tenant-specific scope ({', '.join(dropped)}) was dropped; scope it again in the target tenant")
    if rule.get("order") is not None:
        pass   # a pack inserts at the top; the original order is not kept
    return out


def convert_rule(rule: Dict[str, Any], warnings: List[str], hint: str = "") -> Optional[Dict[str, Any]]:
    if not rule.get("name"):
        return None
    ch = _channel(rule, hint)
    out = _common(rule, warnings)
    out["channel"] = ch
    if ch == "web":
        out["protocols"] = list(rule.get("protocols") or ["ANY_RULE"])
        for src, dst in (("minSize", "min_size"), ("cloudApplications", "cloud_applications"), ("urlCategories", "url_categories")):
            v = rule.get(src)
            if v:
                out[dst] = _names(v) if isinstance(v, list) else v
        for src, dst in (("ocrEnabled", "ocr_enabled"), ("zscalerIncidentReceiver", "zscaler_incident_receiver"), ("matchOnly", "match_only")):
            if rule.get(src):
                out[dst] = True
        if rule.get("icapServer") or rule.get("auditor") or rule.get("externalAuditorEmail"):
            warnings.append(f"rule '{out['name']}': ICAP server / auditor settings are tenant-specific and were dropped")
    elif ch == "endpoint":
        if rule.get("dataTransferMethod"):
            out["data_transfer_method"] = rule["dataTransferMethod"]
        if rule.get("deviceTrustLevels"):
            out["device_trust_levels"] = list(rule["deviceTrustLevels"])
        if rule.get("eunEnabled") is not None:
            out["eun_enabled"] = bool(rule["eunEnabled"])
        if rule.get("networkType"):
            out["network_type"] = rule["networkType"]
        if rule.get("minSize"):
            out["min_size"] = rule["minSize"]
        groups = _names(rule.get("endPointApplicationGroups"))
        if groups:
            out["endpoint_application_groups"] = groups
        subs = []
        for sr in rule.get("subRules") or []:
            if isinstance(sr, dict) and sr.get("name"):
                c = convert_rule(dict(sr, dataTransferMethod=sr.get("dataTransferMethod") or rule.get("dataTransferMethod")), warnings, "endpoint")
                if c:
                    c.pop("channel", None)
                    subs.append(c)
        if subs:
            out["sub_rules"] = subs
    elif ch == "saas":
        out["saas_type"] = str(rule.get("type") or "OFLCASB_DLP_FILE")
        out["tenants"] = "any"
        if rule.get("cloudAppTenants"):
            warnings.append(f"rule '{out['name']}': SaaS tenant ids ({', '.join(_names(rule['cloudAppTenants']))}) were dropped; the pack scopes the rule to any matching onboarded tenant")
        out["collaboration_scope"] = list(rule.get("collaborationScope") or ["ANY"])
        for src, dst in (("components", "components"), ("contentLocation", "content_location"), ("recipient", "recipient"), ("domains", "domains")):
            if rule.get(src):
                out[dst] = rule[src]
    elif ch == "email":
        out["tenants"] = "any"
        if rule.get("emailTenants"):
            warnings.append(f"rule '{out['name']}': email tenant ids were dropped; the pack scopes the rule to any onboarded email tenant")
        for src, dst in (("contentLocations", "content_locations"), ("customHeader", "custom_header"), ("minSize", "min_size")):
            if rule.get(src):
                out[dst] = rule[src]
    return out


# ── whole upload ───────────────────────────────────────────────────────
def convert_parts(parts: Dict[str, List[Any]], hints: Optional[Dict[str, List[str]]] = None) -> Tuple[Dict[str, List[Any]], List[str], Dict[str, int]]:
    """Rewrite the native objects inside `parts` (dictionaries, engines,
    policies, app_groups lists as collected from the upload). Objects
    already in the pack schema pass through. Returns (parts, warnings,
    counts of converted objects)."""
    warnings: List[str] = []
    counts = {"dictionaries": 0, "engines": 0, "policies": 0, "predefined_dictionaries": 0, "predefined_engines": 0}
    id_to_name: Dict[str, str] = {}
    for d in parts.get("dictionaries") or []:
        if isinstance(d, dict) and d.get("id") is not None and d.get("name"):
            id_to_name[str(d["id"])] = str(d["name"])
    dicts: List[Any] = []
    for d in parts.get("dictionaries") or []:
        if is_native(d):
            c = convert_dictionary(d, warnings)
            if c:
                dicts.append(c); counts["dictionaries"] += 1
            else:
                counts["predefined_dictionaries"] += 1
        else:
            dicts.append(d)
    engines: List[Any] = []
    for e in parts.get("engines") or []:
        if is_native(e):
            c = convert_engine(e, id_to_name, warnings)
            if c:
                engines.append(c); counts["engines"] += 1
            else:
                counts["predefined_engines"] += 1
        else:
            engines.append(e)
    policies: List[Any] = []
    hint_by_id = {}
    for h, items in (hints or {}).items():
        for n in items:
            hint_by_id[n] = h
    for r in parts.get("policies") or []:
        if is_native(r):
            c = convert_rule(r, warnings, hint_by_id.get(str(r.get("name")), ""))
            if c:
                policies.append(c); counts["policies"] += 1
        else:
            policies.append(r)
    if counts["predefined_dictionaries"]:
        warnings.append(f"{counts['predefined_dictionaries']} predefined dictionar{'y' if counts['predefined_dictionaries'] == 1 else 'ies'} left out (every tenant has them; engines reference them by name)")
    if counts["predefined_engines"]:
        warnings.append(f"{counts['predefined_engines']} predefined engine(s) left out (every tenant has them; rules reference them by name)")
    out = dict(parts)
    out["dictionaries"], out["engines"], out["policies"] = dicts, engines, policies
    return out, warnings, counts
