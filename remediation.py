#!/usr/bin/env python3
"""
Guided Auto-Remediation Framework
===================================
For a finding surfaced by the assessment, generate the API call(s)
that would fix it — based on user-supplied criteria collected via a
guided prompt (form wizard) in the GUI.

Design principles
-----------------
1. **Declarative recipes.** Every remediation is a dict in REMEDIATIONS
   keyed by check_id or check_pattern. No imperative code per recipe.
   Adding a new remediation = adding a dict entry.

2. **Guided input, not blank form.** Each recipe lists the FIELDS the
   user must fill in (with label, type, hint, default, validation).
   The GUI builds the form from this spec — no hand-crafted HTML
   per recipe.

3. **Dry-run first.** Every execute() call defaults to dry_run=True.
   Users see the exact body + endpoint that WOULD be sent before
   anything hits the tenant.

4. **Writes-enabled gate.** dry_run=False PUT/POST/DELETE require the
   same ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND env var as the migration
   wizard. Otherwise returns status='blocked'.

5. **Read-only by default.** A recipe that wants to change the tenant
   MUST explicitly set 'destructive': True. Omitting it means the
   recipe only DESCRIBES the fix without offering to apply.

6. **Module independence.** Does not import or invoke any other
   module's main entry point. Only dependency is the Client.
"""
from __future__ import annotations
import json
from typing import Any, Dict, List, Optional


# ─────────────────────────────────────────────────────────────────
# Remediation catalog
#
# Each recipe:
#   check_id        : the recipe's own id (also matched as an exact id or prefix)
#   checks          : assessment check ids this recipe answers ("4.1", "A.2" …);
#                     the Review & Remediate flow matches on these
#   label           : short human name for the Remediate button
#   summary         : 1-sentence description of what this will do
#   destructive     : True if it writes to the tenant
#   fields          : list of input-field specs the GUI renders
#   endpoint        : API path to hit
#   method          : GET / POST / PUT / PATCH / DELETE
#   body_template   : Python format dict with {placeholders} for fields
#   success_msg     : shown after a successful live execute
# ─────────────────────────────────────────────────────────────────

REMEDIATIONS: List[Dict[str, Any]] = [
    {
        "check_id": "FW-01",
        "checks": [],   # the assessment has no Cloud Firewall check yet
        "label": "Add Cloud Firewall Rule",
        "summary": "Creates a new Cloud Firewall rule from the criteria you provide. Best for the common 'no firewall rules configured' finding.",
        "destructive": True,
        "fields": [
            {"key": "name",        "label": "Rule name",
             "type": "text",       "required": True, "max_length": 128,
             "hint": "Human-readable name — use underscores, not spaces, for Terraform compatibility."},
            {"key": "description", "label": "Description",
             "type": "textarea",   "required": True, "max_length": 512,
             "hint": "Business justification — auditors require this. What does this rule protect?"},
            {"key": "action",      "label": "Action",
             "type": "enum",       "required": True,
             "options": ["ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP"],
             "default": "BLOCK_DROP",
             "hint": "Default deny-all starts with BLOCK_DROP on a catch-all rule."},
            {"key": "state",       "label": "Rule state",
             "type": "enum",       "required": True,
             "options": ["ENABLED", "DISABLED"],
             "default": "DISABLED",
             "hint": "Disabled by default: review the rule in the admin portal, then enable it."},
            {"key": "order",       "label": "Order (position)",
             "type": "number",     "required": True, "default": 1, "min": 1, "max": 999,
             "hint": "Lower = higher priority. Start with order=1 for a default rule; reorder later."},
            {"key": "rank",        "label": "Admin rank (0-7)",
             "type": "number",     "required": False, "default": 7, "min": 0, "max": 7,
             "hint": "Zscaler admin-rank field; 7 = lowest priority. Keep at 7 unless you know why."},
        ],
        "endpoint":    "/zia/firewallFilteringRules",
        "method":      "POST",
        "body_template": {
            "name":        "{name}",
            "description": "{description}",
            "action":      "{action}",
            "state":       "{state}",
            "order":       "{order:int}",
            "rank":        "{rank:int}",
        },
        "success_msg": "Cloud Firewall rule created. Re-run Step 1 to confirm and set scope (users/groups/locations) in the admin portal.",
    },

    {
        "check_id": "URL-01",
        # E.1/E.8/E.9: no GenAI URL categories governed, shadow GenAI, no AUP enforcement.
        "checks": ["E.1", "E.8", "E.9"],
        "label": "Add URL Filtering Rule",
        "summary": "Creates a URL filtering rule that blocks or allows a set of categories. Use to implement the finding 'no default URL-filter block rule exists'.",
        "destructive": True,
        "fields": [
            {"key": "name",              "label": "Rule name",
             "type": "text",             "required": True, "max_length": 128,
             "hint": "HCL-safe name (letters, numbers, underscores, dashes)."},
            {"key": "description",       "label": "Description",
             "type": "textarea",         "required": True,
             "hint": "Business justification for auditors."},
            {"key": "action",            "label": "Action",
             "type": "enum",             "required": True,
             # ISOLATE is not offered: it needs a Cloud Browser Isolation profile this form cannot pick.
             "options": ["BLOCK", "ALLOW", "CAUTION"],
             "default": "BLOCK"},
            {"key": "url_categories",    "label": "URL categories (comma-separated IDs)",
             "type": "csv",              "required": True,
             "hint": "Example: ADULT_MATERIAL,GAMBLING,MALICIOUS_SITES — paste category IDs from ZIA Admin → URL Categories."},
            {"key": "state",             "label": "Rule state",
             "type": "enum",             "required": True,
             "options": ["ENABLED", "DISABLED"], "default": "DISABLED",
             "hint": "Disabled by default: review the rule in the admin portal, then enable it."},
            {"key": "order",             "label": "Order",
             "type": "number",           "required": True, "default": 1, "min": 1, "max": 999},
            {"key": "rank",              "label": "Admin rank",
             "type": "number",           "required": False, "default": 7, "min": 0, "max": 7},
        ],
        "endpoint":      "/zia/urlFilteringRules",
        "method":        "POST",
        "body_template": {
            "name":          "{name}",
            "description":   "{description}",
            "action":        "{action}",
            "urlCategories": "{url_categories:csv}",
            "protocols":     ["ANY_RULE"],   # the SDK's add_rule names protocols as required
            "state":         "{state}",
            "order":         "{order:int}",
            "rank":          "{rank:int}",
        },
        "success_msg": "URL Filtering rule created. Set scope (users/groups/locations) in the admin portal to tighten least-privilege.",
    },

    {
        "check_id": "RULE-DESC",
        "checks": [],   # offered from the catalogue; no check flags a missing rule description yet
        "label": "Add Description to a Rule",
        "summary": "Updates an existing rule to include a description so it stops showing up as 'Needs Review'.",
        "destructive": True,
        "fields": [
            {"key": "rule_type",  "label": "Rule type",
             "type": "enum",       "required": True,
             "options": ["webDlpRules", "urlFilteringRules", "firewallFilteringRules", "sslInspectionRules"],
             "hint": "Which endpoint the rule lives on."},
            {"key": "rule_id",    "label": "Rule ID",
             "type": "text",       "required": True,
             "hint": "The numeric ID of the rule. From assessment results or the admin portal."},
            {"key": "description","label": "Description text",
             "type": "textarea",   "required": True, "max_length": 512,
             "hint": "Document business justification, owner, and review date."},
        ],
        "endpoint":      "/zia/{rule_type}/{rule_id}",
        # ZIA updates a rule with PUT, which replaces the whole rule: the
        # rule is read first and sent back whole with only its description
        # changed ("merge"), never as a body that holds the description alone.
        "method":        "PUT",
        "merge":         True,
        "body_template": {"description": "{description}"},
        "success_msg":   "Description updated. The rule should PASS this check on the next assessment run.",
    },

    {
        "check_id": "SSL-01",
        # 4.1 inspection scope, A.2 SSL+DNI, E.2 SSL for GenAI, 6.4 inspect list, 7.3 no enabled SSL rules.
        "checks": ["4.1", "A.2", "E.2", "6.4", "7.3"],
        "label": "Add SSL Inspection Rule",
        "summary": "Creates an SSL inspection rule with an explicit action. Addresses 'SSL inspection not configured' findings.",
        "destructive": True,
        "fields": [
            {"key": "name",        "label": "Rule name",
             "type": "text",       "required": True, "max_length": 128,
             "hint": "HCL-safe name — underscores, no spaces."},
            {"key": "description", "label": "Description",
             "type": "textarea",   "required": True,
             "hint": "Business justification — auditors require this."},
            {"key": "action_type", "label": "Action type",
             "type": "enum",       "required": True,
             "options": ["DECRYPT", "DO_NOT_DECRYPT"],
             "default": "DECRYPT",
             "hint": "DECRYPT for full inspection; DO_NOT_DECRYPT for documented exemptions (banking, healthcare)."},
            {"key": "state",       "label": "Rule state",
             "type": "enum",       "required": True,
             "options": ["ENABLED", "DISABLED"], "default": "DISABLED",
             "hint": "Disabled by default: review the rule in the admin portal, then enable it."},
            {"key": "order",       "label": "Order",
             "type": "number",     "required": True, "default": 1, "min": 1, "max": 999},
            {"key": "rank",        "label": "Admin rank",
             "type": "number",     "required": False, "default": 7, "min": 0, "max": 7},
        ],
        "endpoint":      "/zia/sslInspectionRules",
        "method":        "POST",
        "body_template": {
            "name":        "{name}",
            "description": "{description}",
            "action":      {"type": "{action_type}"},
            "state":       "{state}",
            "order":       "{order:int}",
            "rank":        "{rank:int}",
        },
        "success_msg": "SSL Inspection rule created. Set user/location scoping in the admin portal to complete the policy.",
    },

    {
        "check_id": "DLP-01",
        # 5.3 / A.1 / MC.1 no active Web DLP rules, E.5 no source-code rule, E.6 no PII rule, 8.5 inline pilot.
        "checks": ["5.3", "A.1", "MC.1", "E.5", "E.6", "8.5"],
        "label": "Add Inline Web DLP Rule",
        "summary": "Creates a new Inline Web DLP rule with the action and scope you specify. Use to satisfy 'no DLP rules configured' findings.",
        "destructive": True,
        "fields": [
            {"key": "name",        "label": "Rule name",
             "type": "text",       "required": True, "max_length": 128},
            {"key": "description", "label": "Description",
             "type": "textarea",   "required": True,
             "hint": "What data class + user population this rule protects."},
            {"key": "action",      "label": "Action",
             "type": "enum",       "required": True,
             # The Web DLP actions ZIA takes (pack_channels.CHANNELS["web"]): ALLOW is monitor only.
             "options": ["ALLOW", "BLOCK", "CONFIRM"],
             "default": "ALLOW",
             "hint": "ALLOW (monitor only) during initial rollout so you gather signal; move to BLOCK after validation."},
            {"key": "state",       "label": "Rule state",
             "type": "enum",       "required": True,
             "options": ["ENABLED", "DISABLED"], "default": "DISABLED",
             "hint": "Disabled by default: review the rule in the admin portal, then enable it."},
            {"key": "order",       "label": "Order",
             "type": "number",     "required": True, "default": 1, "min": 1, "max": 999},
            {"key": "rank",        "label": "Admin rank",
             "type": "number",     "required": False, "default": 7, "min": 0, "max": 7},
        ],
        "endpoint":      "/zia/webDlpRules",
        "method":        "POST",
        "body_template": {
            "name":        "{name}",
            "description": "{description}",
            "action":      "{action}",
            "state":       "{state}",
            "order":       "{order:int}",
            "rank":        "{rank:int}",
        },
        "success_msg": "Inline Web DLP rule created. Attach DLP engines + scope (users/groups/locations) in the admin portal before moving the action from ALLOW (monitor) to BLOCK.",
    },
]


# ─────────────────────────────────────────────────────────────────
# Lookup
# ─────────────────────────────────────────────────────────────────

def get_catalog() -> List[Dict[str, Any]]:
    """Return the remediation catalog (public-facing schema only —
    no body_template or endpoint details, so the client can render
    the form UI without seeing the underlying API shape)."""
    return [
        {
            "check_id":    r["check_id"],
            "checks":      list(r.get("checks") or []),
            "label":       r["label"],
            "summary":     r["summary"],
            "destructive": r.get("destructive", False),
            "fields":      r["fields"],
        }
        for r in REMEDIATIONS
    ]


def get_recipe(check_id: str) -> Optional[Dict[str, Any]]:
    """Find the recipe for a check: the recipe's own id, an assessment
    check id it lists in `checks`, or a prefix of the recipe id."""
    check_id = str(check_id or "")
    for r in REMEDIATIONS:
        if r["check_id"] == check_id:
            return r
    for r in REMEDIATIONS:
        if check_id in (r.get("checks") or []):
            return r
    # Prefix match (e.g. check "FW-01.dns" matches recipe "FW-01")
    for r in REMEDIATIONS:
        if check_id.startswith(r["check_id"]):
            return r
    return None


def remediable_checks() -> Dict[str, str]:
    """{assessment check id: recipe id} for every check a recipe answers."""
    return {c: r["check_id"] for r in REMEDIATIONS for c in (r.get("checks") or [])}


# ─────────────────────────────────────────────────────────────────
# Planner + executor
# ─────────────────────────────────────────────────────────────────

def _resolve_field(value: Any, spec: str):
    """Apply {field:type} coercion: int, csv, str (default)."""
    if spec.endswith(":int"):
        try:
            return int(value)
        except Exception:
            raise ValueError(f"Field '{spec[:-4]}' must be an integer.")
    if spec.endswith(":csv"):
        # Split comma-separated into list + strip whitespace
        return [x.strip() for x in ("" if value is None else str(value)).split(",") if x.strip()]
    return "" if value is None else str(value)


def _render_template(template: Any, criteria: Dict[str, Any]) -> Any:
    """Recursively substitute {field} / {field:type} placeholders from criteria."""
    if isinstance(template, dict):
        return {k: _render_template(v, criteria) for k, v in template.items()}
    if isinstance(template, list):
        return [_render_template(v, criteria) for v in template]
    if isinstance(template, str):
        s = template
        # Match {name} or {name:type}
        import re as _re
        matches = _re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)(:[a-z]+)?\}", s)
        if len(matches) == 1 and s == f"{{{matches[0][0]}{matches[0][1]}}}":
            # Whole value is a single placeholder — preserve type
            field, typ = matches[0]
            val = criteria.get(field)
            if typ == ":int":    return _resolve_field(val, ":int")
            if typ == ":csv":    return _resolve_field(val, ":csv")
            return _resolve_field(val, "")
        # Otherwise string-substitute
        for field, typ in matches:
            val = _resolve_field(criteria.get(field, ""), typ)
            s = s.replace(f"{{{field}{typ}}}", str(val))
        return s
    return template


def _render_endpoint(endpoint_tpl: str, criteria: Dict[str, Any]) -> str:
    """Endpoints can have {field} placeholders too (e.g. /zia/{rule_type}/{rule_id})."""
    import re as _re
    out = endpoint_tpl
    from urllib.parse import quote as _quote
    for m in _re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", endpoint_tpl):
        # Encoded as one path segment: a value can never add "/", "..",
        # "?" or "#" and so never retarget the write (validated as well).
        val = _quote(str(criteria.get(m, "")), safe="")
        out = out.replace(f"{{{m}}}", val)
    return out


_PATH_PARAM = __import__("re").compile(r"^[A-Za-z0-9_-]{1,64}$")
# A free-text field with no max_length of its own is still capped (assumed:
# well above what ZIA keeps for a rule's name or description).
MAX_TEXT = 2048
# A list of ids (URL categories): ZIA ids are upper-case words such as
# GAMBLING or CUSTOM_01 (assumed: a little wider here, the tenant refuses the rest).
MAX_CSV_ITEMS = 256
_CSV_ITEM = __import__("re").compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _with_defaults(recipe: Dict[str, Any], criteria: Dict[str, Any]) -> Dict[str, Any]:
    """The criteria with each field's default filled in where it was left
    out, so an optional field never reaches the body as nothing.
    Note: this runs before _validate_criteria, so a field marked "required"
    that HAS a default (a rule's state, DISABLED) is filled here, never
    refused: "required" only refuses a field with no default. An omitted
    state is therefore planned DISABLED, never left for the tenant to choose."""
    out = dict(criteria or {})
    for f in recipe.get("fields", []):
        if out.get(f["key"]) in (None, "") and "default" in f:
            out[f["key"]] = f["default"]
    return out


def _validate_criteria(recipe: Dict[str, Any], criteria: Dict[str, Any]) -> List[str]:
    """Return a list of validation errors. Empty list = valid."""
    errors: List[str] = []
    import re as _re
    for name in _re.findall(r"\{([a-zA-Z_][a-zA-Z0-9_]*)\}", str(recipe.get("endpoint") or "")):
        val = criteria.get(name)
        if val not in (None, "") and not _PATH_PARAM.match(str(val)):
            errors.append(f"{name}: only letters, digits, '_' and '-' are allowed (it becomes part of the API path).")
    for f in recipe.get("fields", []):
        key = f["key"]
        val = criteria.get(key)
        if f.get("required") and (val is None or val == ""):
            errors.append(f"'{f['label']}' is required.")
            continue
        if val is None or val == "":
            if "{" + key + ":int}" in json.dumps(recipe.get("body_template") or {}):
                errors.append(f"'{f['label']}' must be a number.")
            continue
        if isinstance(val, (dict, list, tuple, set)) or (isinstance(val, float) and not val.is_integer()):
            errors.append(f"'{f['label']}' must be a single value, not a list or an object.")
            continue
        if f.get("type") == "number":
            if isinstance(val, bool):
                errors.append(f"'{f['label']}' must be a number.")
                continue
            try:
                n = int(val)
                if "min" in f and n < f["min"]:
                    errors.append(f"'{f['label']}' must be ≥ {f['min']}.")
                if "max" in f and n > f["max"]:
                    errors.append(f"'{f['label']}' must be ≤ {f['max']}.")
            except Exception:
                errors.append(f"'{f['label']}' must be a number.")
        if f.get("type") == "enum":
            if str(val) not in (f.get("options") or []):
                errors.append(f"'{f['label']}' must be one of: {', '.join(f['options'])}.")
        if f.get("type") == "csv":
            parts = [x.strip() for x in str(val).split(",") if x.strip()]
            if len(parts) > MAX_CSV_ITEMS or not all(_CSV_ITEM.match(x) for x in parts):
                errors.append(f"'{f['label']}' must be up to {MAX_CSV_ITEMS} comma-separated ids (letters, digits, '_', '.', '-').")
        limit = f.get("max_length") or MAX_TEXT
        if len(str(val)) > limit:
            errors.append(f"'{f['label']}' exceeds {limit} chars.")
    return errors


def plan(check_id: str, criteria: Dict[str, Any]) -> Dict[str, Any]:
    """Build the planned request WITHOUT sending it. Returns:
       {ok, recipe, endpoint, method, body, errors}
    """
    recipe = get_recipe(check_id)
    if not recipe:
        return {"ok": False, "errors": [f"No remediation recipe registered for check '{check_id}'."]}
    if not isinstance(criteria, dict):
        return {"ok": False, "errors": ["The criteria must be an object of field values."], "recipe_label": recipe["label"]}
    criteria = _with_defaults(recipe, criteria)
    errors = _validate_criteria(recipe, criteria)
    if errors:
        return {"ok": False, "errors": errors, "recipe_label": recipe["label"]}
    endpoint = _render_endpoint(recipe["endpoint"], criteria)
    body     = _render_template(recipe.get("body_template") or {}, criteria)
    out = {
        "ok": True,
        "recipe_label": recipe["label"],
        "destructive":  recipe.get("destructive", False),
        "endpoint":     endpoint,
        "method":       recipe["method"],
        "body":         body,
        "success_msg":  recipe.get("success_msg", ""),
    }
    if recipe.get("merge"):
        # The body shown is only what changes: say so, or a reader who knows
        # that a PUT replaces the object would take it for a wipe.
        out["merge"] = True
        out["note"] = MERGE_NOTE
    return out


MERGE_NOTE = ("Reads the rule and sends it back whole: the request is a PUT of the rule as the tenant has it now, "
              "with only the fields shown here changed.")


def execute(client, check_id: str, criteria: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Plan then (optionally) execute. Writes are gated on
    ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND env var, same as the
    migration wizard."""
    p = plan(check_id, criteria)
    if not p.get("ok"):
        return {"status": "invalid", **p}

    if dry_run:
        would = (f"read {p['endpoint']} and send it back whole ({p['method']}) with only the fields shown changed" if p.get("merge")
                 else f"{p['method']} {p['endpoint']}")
        return {"status": "dry_run", **p,
                "message": f"DRY RUN: Would {would}. Set dry_run=false + ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND to actually apply."}

    # Deny by default: any live call is a tenant write, whatever the recipe's
    # `destructive` flag says (a recipe without it must not slip past write mode).
    if not __import__("security").writes_enabled():
        return {"status": "blocked", **p,
                "reason": "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND. To turn them on, " + __import__("security").write_enable_hint() + "."}

    method = p["method"].upper()
    endpoint = p["endpoint"]
    body = p["body"]
    if get_recipe(check_id).get("merge"):
        # Read-modify-write: the object as the tenant has it now, with only
        # the recipe's fields changed (a PUT replaces the whole object).
        try:
            cur, code = client.get(endpoint)
        except Exception as e:
            return {"status": "error", "error": f"{type(e).__name__}: {str(e)[:200]}", **p}
        if code != 200 or not isinstance(cur, dict) or not cur or "error" in cur:
            return {"status": "failed", "http_status": code, **p,
                    "error": f"The object could not be read before the change (HTTP {code}), so nothing was sent."}
        body = dict(cur)
        body.update(p["body"])

    try:
        if method == "POST":
            resp, code = client.post(endpoint, body)
        elif method == "PUT":
            resp, code = client.put(endpoint, body)
        # No PATCH: ZIA updates a rule with a PUT of the whole rule (assumed:
        # the API has no PATCH), so a recipe that changes some fields is a
        # "merge" PUT (the read-modify-write above, which fails closed). A
        # PATCH recipe is refused below as an unsupported method, nothing sent.
        elif method == "DELETE":
            resp, code = client.delete(endpoint, body)
        else:
            return {"status": "error", "error": f"Unsupported method: {method}", **p}
    except Exception as e:
        return {"status": "error", "error": f"{type(e).__name__}: {str(e)[:200]}", **p}

    if code in (200, 201, 204):
        return {"status": "completed", "http_status": code,
                "response": resp if isinstance(resp, dict) else None,
                "message": p.get("success_msg") or "Remediation applied.",
                **{k: v for k, v in p.items() if k not in ("ok", "success_msg")}}
    return {"status": "failed", "http_status": code,
            "error": (resp.get("error") if isinstance(resp, dict) else str(resp)[:200]),
            **{k: v for k, v in p.items() if k != "ok"}}
