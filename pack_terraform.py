#!/usr/bin/env python3
"""
Terraform workspace generator for DLP policy packs and baselines.

Turns a pack (the same JSON Deploy Studio deploys) into a self-contained
Terraform workspace for the official ``zscaler/zia`` provider from the
Terraform Registry (https://registry.terraform.io/providers/zscaler/zia),
so a pack can be owned by Terraform state: plan shows the diff, apply
converges, destroy removes exactly what the pack created.

Two modes:

* **static** — the pack as declared. Every object is a resource; apply on
  an empty tenant creates all of it.
* **gap** — given a preflight report from ``pack_deploy.preflight`` (i.e.
  after assessing a live tenant), objects that already exist get
  ``import {}`` blocks (Terraform >= 1.5) with their tenant IDs, so the
  first ``terraform plan`` shows exactly the gap: in-sync objects import
  with no change, customized objects import and would be updated in place, and
  missing objects are created. Nothing is destroyed. After apply the whole
  baseline is in state.

Files produced (a dict of path -> content; write them with write_workspace):

    versions.tf        provider pin, required_version, optional S3 backend
    provider.tf        provider "zia" from variables or ZSCALER_* env vars
    variables.tf       credentials (sensitive), rule order, rank, activate
    dictionaries.tf    data lookups for predefined templates + resources
    engines.tf         resources with D${...}.S expressions
    rules.tf           one resource per rule, per channel
    activation.tf      zia_activation_status (count = var.activate ? 1 : 0)
    imports.tf         (gap mode only) import blocks for existing objects
    outputs.tf         names and IDs
    terraform.tfvars.example, .gitignore, README.md
"""
from __future__ import annotations

import io
import json
import os
import re
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pack_channels as pc
from dlp_importer import DICT_DESCRIPTION_MAX, _load_json, _resolve_configs, fit_description, load_pack_metadata

PROVIDER_SOURCE = "zscaler/zia"
PROVIDER_VERSION = "~> 4.8"
TERRAFORM_VERSION = ">= 1.5.0"
REGISTRY_URL = "https://registry.terraform.io/providers/zscaler/zia/latest/docs"

RESOURCE_BY_CHANNEL = {
    pc.WEB: "zia_dlp_web_rules",
    pc.ENDPOINT: "zia_endpoint_dlp_rules",
    pc.SAAS: "zia_casb_dlp_rules",
    pc.EMAIL: "zia_outbound_email_dlp",
    pc.CLOUD_APP: "zia_cloud_app_control_rule",
    pc.FILE_TYPE: "zia_file_type_control_rules",
    pc.URL: "zia_url_filtering_rules",
    pc.SSL: "zia_ssl_inspection_rules",
}


def _hcl_value(v: Any, indent: int) -> str:
    """Render a JSON-ish value as HCL (scalars, lists, nested blocks)."""
    pad = "  " * indent
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return hcl_list(v)
    if isinstance(v, dict):
        inner = "".join(f"{pad}  {k.ljust(22)} = {_hcl_value(val, indent + 1)}\n" if not isinstance(val, dict)
                        else f"{pad}  {k} {_hcl_value(val, indent + 1)}" for k, val in v.items())
        return "{\n" + inner + pad + "}\n"
    return hcl_str(v)


# Attributes the zscaler/zia provider accepts inside an SSL Inspection rule's
# ``action`` block (checked against the 4.8 schema). Other keys a pack may
# carry from the API (``default_certificate`` on the certificate reference,
# for example) are emitted as comments so the workspace validates.
SSL_ACTION_SCHEMA: Dict[str, Any] = {
    "type": None, "override_default_certificate": None, "show_eun": None, "show_eunatp": None,
    "ssl_interception_cert": {"id": None},
    "decrypt_sub_actions": {"server_certificates": None, "ocsp_check": None, "block_ssl_traffic_with_no_sni_enabled": None,
                            "min_client_tls_version": None, "min_server_tls_version": None, "block_undecrypt": None,
                            "http2_enabled": None},
    "do_not_decrypt_sub_actions": {"server_certificates": None, "ocsp_check": None, "block_ssl_traffic_with_no_sni_enabled": None,
                                   "min_tls_version": None, "bypass_other_policies": None},
}


def _filter_schema(value: Dict[str, Any], schema: Dict[str, Any], path: str = "action") -> Tuple[Dict[str, Any], List[str]]:
    """Keep only keys the provider schema knows; report the dropped ones."""
    clean: Dict[str, Any] = {}
    dropped: List[str] = []
    for k, v in value.items():
        if k not in schema:
            dropped.append(f"{path}.{k} = {json.dumps(v)}")
            continue
        sub = schema[k]
        if isinstance(sub, dict) and isinstance(v, dict):
            inner, d2 = _filter_schema(v, sub, f"{path}.{k}")
            clean[k] = inner
            dropped.extend(d2)
        else:
            clean[k] = v
    return clean, dropped


def _apps_expr(p: Dict[str, Any], lookups: List[str], app_classes: Dict[str, str], *, ssl: bool = False,
               default_classes: Optional[List[str]] = None) -> Optional[str]:
    """HCL expression for a rule's cloud applications: explicit list, or a
    live lookup by application class. None when the rule has neither."""
    if p.get("applications") or p.get("cloud_applications"):
        return hcl_list(p.get("applications") or p.get("cloud_applications"))
    classes = [str(c).upper() for c in (p.get("cloud_app_classes") or default_classes or [])]
    if not classes:
        return None
    refs = []
    policy_type = "cloud_application_ssl_policy" if ssl else "cloud_application_policy"
    for cls in classes:
        key = ("ssl_" if ssl else "") + cls
        if key not in app_classes:
            app_classes[key] = slug(cls, "apps_ssl_" if ssl else "apps_")
            lookups.append(f'data "zia_cloud_applications" "{app_classes[key]}" {{\n  policy_type = "{policy_type}"\n  app_class   = [{hcl_str(cls)}]\n}}\n\n')
        refs.append(f"[for a in data.zia_cloud_applications.{app_classes[key]}.applications : a.app]")
    return "sort(distinct(concat(" + ", ".join(refs) + ")))"


def _control_rule_hcl(channel: str, res: str, label: str, p: Dict[str, Any], meta: Dict[str, Any], pack_id: str,
                      order_expr: str, lookups: List[str], app_classes: Dict[str, str]) -> str:
    """Terraform for a containment rule (Cloud App Control, File Type
    Control, URL Filtering, SSL Inspection)."""
    r = [f'resource "{res}" "{label}" {{\n']
    r.append(_attr("name", hcl_str(p["name"])))
    r.append(_attr("description", hcl_str(_provenance(meta, pack_id, p.get("description", "")))))
    r.append(_attr("order", order_expr))
    r.append(_attr("rank", "var.policy_rank"))
    r.append(_attr("state", hcl_str(p.get("state", "ENABLED"))))
    if channel == pc.CLOUD_APP:
        apps = _apps_expr(p, lookups, app_classes, default_classes=[str(p["type"]).upper()])
        r.append(_attr("type", hcl_str(str(p["type"]).upper())))
        r.append(_attr("applications", apps or "[]"))
        if p.get("actions"):
            r.append(_attr("actions", hcl_list(p["actions"])))
        else:
            verbs = {str(k).upper(): str(v).upper() for k, v in (p.get("actions_by_verb") or {}).items()}
            default = verbs.pop("*", "ALLOW")
            block = [f"_{v}" for v, want in verbs.items() if want == "BLOCK"]
            allow = [f"_{v}" for v, want in verbs.items() if want == "ALLOW"]
            alabel = f"{label}_actions"
            lookups.append(f'data "zia_cloud_app_control_rule_actions" "{alabel}" {{\n  type       = {hcl_str(str(p["type"]).upper())}\n  cloud_apps = {apps or "[]"}\n}}\n\n')
            cond = (f"(anytrue([for v in {hcl_list(block)} : endswith(a, v)]) ? startswith(a, \"BLOCK_\") : "
                    f"(anytrue([for v in {hcl_list(allow)} : endswith(a, v)]) ? startswith(a, \"ALLOW_\") : startswith(a, \"{default}_\")))")
            r.append(_attr("actions", f"[for a in data.zia_cloud_app_control_rule_actions.{alabel}.available_actions_without_isolate : a if {cond}]"))
        r.append(_attr("device_trust_levels", hcl_list(p.get("device_trust_levels") or list(pc.CLOUD_APP_TRUST_LEVELS))))
        for opt in ("user_agent_types", "user_risk_score_levels"):
            if p.get(opt):
                r.append(_attr(opt, hcl_list(p[opt])))
        for opt in ("time_quota", "size_quota"):
            if p.get(opt):
                r.append(_attr(opt, str(int(p[opt]))))
    elif channel == pc.FILE_TYPE:
        r.append(_attr("filtering_action", hcl_str(p.get("filtering_action", "ALLOW"))))
        r.append(_attr("operation", hcl_str(p.get("operation", "UPLOAD"))))
        r.append(_attr("file_types", hcl_list(p["file_types"])))
        r.append(_attr("protocols", hcl_list(p.get("protocols") or ["ANY_RULE"])))
        apps = _apps_expr(p, lookups, app_classes)
        if apps:
            r.append(_attr("cloud_applications", apps))
        for opt in ("url_categories", "device_trust_levels"):
            if p.get(opt):
                r.append(_attr(opt, hcl_list(p[opt])))
        for opt in ("min_size", "max_size"):
            if p.get(opt):
                r.append(_attr(opt, str(int(p[opt]))))
        for opt in ("active_content", "unscannable"):
            if p.get(opt) is not None:
                r.append(_attr(opt, "true" if p[opt] else "false"))
    elif channel == pc.URL:
        r.append(_attr("action", hcl_str(p.get("action", "ALLOW"))))
        r.append(_attr("protocols", hcl_list(p.get("protocols") or ["ANY_RULE"])))
        r.append(_attr("url_categories", hcl_list(p["url_categories"])))
        for opt in ("request_methods", "device_trust_levels", "user_agent_types", "user_risk_score_levels"):
            if p.get(opt):
                r.append(_attr(opt, hcl_list(p[opt])))
        if p.get("end_user_notification_url"):
            r.append(_attr("end_user_notification_url", hcl_str(p["end_user_notification_url"])))
        if p.get("block_override") is not None:
            r.append(_attr("block_override", "true" if p["block_override"] else "false"))
    elif channel == pc.SSL:
        r.append(_attr("platforms", hcl_list(p.get("platforms") or list(pc.SSL_PLATFORMS))))
        if p.get("road_warrior_for_kerberos") is not None:
            r.append(_attr("road_warrior_for_kerberos", "true" if p["road_warrior_for_kerberos"] else "false"))
        apps = _apps_expr(p, lookups, app_classes, ssl=True)
        if apps:
            r.append(_attr("cloud_applications", apps))
        for opt in ("url_categories", "device_trust_levels", "user_agent_types"):
            if p.get(opt):
                r.append(_attr(opt, hcl_list(p[opt])))
        action, dropped = _filter_schema(p["action"], SSL_ACTION_SCHEMA)
        for d in dropped:
            r.append(f"  # not in the zscaler/zia provider schema (set in the Admin Portal if needed): {d}\n")
        r.append("  action " + _hcl_value(action, 1))
    r.append("}\n\n")
    return "".join(r)

# Matches a symbolic `D:<name>` reference. The name may contain parentheses
# ("Social Security Numbers (US)"); it ends at the comparison operator that
# follows every dictionary term in a ZIA expression, at AND/OR, or at a
# closing paren that closes the group rather than the name.
_REF_RE = re.compile(r"D:(.+?)(?=\s*(?:[<>=]|\bAND\b|\bOR\b|\)\s*(?:AND\b|OR\b|\)|$)|$))")


# ---------------------------------------------------------------------------
# HCL helpers
# ---------------------------------------------------------------------------

def hcl_str(s: Any, *, interpolate: bool = False) -> str:
    """Quote a string for HCL, escaping backslashes, quotes and template
    sequences so regex patterns and literal ${ survive verbatim. With
    interpolate=True, ${...} references are left live (engine expressions)."""
    s = "" if s is None else str(s)
    s = s.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n").replace("\r", "")
    if not interpolate:
        s = s.replace("${", "$${")
    s = s.replace("%{", "%%{")
    return f'"{s}"'


def hcl_list(items: Iterable[Any], *, raw: bool = False) -> str:
    items = list(items)
    if not items:
        return "[]"
    body = ", ".join(str(i) if raw else hcl_str(i) for i in items)
    return f"[{body}]"


def slug(name: str, prefix: str = "") -> str:
    s = re.sub(r"[^a-z0-9]+", "_", name.lower()).strip("_") or "x"
    if s[0].isdigit():
        s = "_" + s
    return f"{prefix}{s}"


class Slugger:
    """Unique, stable resource labels per resource type."""
    def __init__(self) -> None:
        self.used: Dict[str, Dict[str, str]] = {}

    def get(self, kind: str, name: str) -> str:
        table = self.used.setdefault(kind, {})
        if name in table:
            return table[name]
        base = slug(name)
        cand, n = base, 2
        while cand in table.values():
            cand, n = f"{base}_{n}", n + 1
        table[name] = cand
        return cand


def _attr(name: str, value: str, width: int = 28) -> str:
    return f"  {name.ljust(width)} = {value}\n"


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------

def load_pack(pack: Dict[str, Any], channel_targets: Optional[Sequence[str]] = None) -> Dict[str, Any]:
    """`channel_targets` (web/endpoint/saas/email) narrows or extends the
    pack's rules per channel exactly as Deploy Policy Packs does."""
    configs = _resolve_configs(pack["dir"])
    meta = load_pack_metadata(pack["dir"])
    engines = _load_json(configs, "dlp_engines.json")
    policies = pc.expand_sub_rules(_load_json(configs, "dlp_policies.json"))
    b = meta.get("baseline") or {}
    policies, note = pc.apply_channel_targets(policies, channel_targets, pack_name=meta.get("name", pack["id"]),
                                              prefix=b.get("prefix") or "", engine_names=[e.get("name") for e in engines if e.get("name")],
                                              pack_id=pack["id"])
    return {
        "id": pack["id"],
        "meta": meta,
        "dictionaries": _load_json(configs, "dlp_dictionaries.json"),
        "engines": engines,
        "policies": policies,
        "app_groups": _load_json(configs, "endpoint_application_groups.json"),
        "channel_note": note,
    }


def _provenance(meta: Dict[str, Any], pack_id: str, base: str, *, limit: Optional[int] = None) -> str:
    b = meta.get("baseline")
    tag = f"[DLP-Check {'baseline' if b else 'pack'} {pack_id}{(' v' + str(meta.get('version'))) if meta.get('version') else ''}] Terraform-managed."
    if limit:
        return fit_description(base, tag, limit)
    base = (base or "").strip()
    return f"{base} {tag}".strip()


def generate(pack: Dict[str, Any], *, report: Optional[Dict[str, Any]] = None,
             backend: Optional[Dict[str, str]] = None, channel_targets: Optional[Sequence[str]] = None) -> Dict[str, str]:
    """Build the workspace files for one pack. `report` (a public preflight
    report for exactly this pack) switches on gap mode. `channel_targets`
    applies the same per-channel choice as Deploy Policy Packs."""
    src = load_pack(pack, channel_targets)
    meta, pack_id = src["meta"], src["id"]
    S = Slugger()
    files: Dict[str, str] = {}

    # Index of the preflight plan, when given.
    plan: Dict[Tuple[str, str], Dict[str, Any]] = {}
    if report:
        for it in report.get("items", []):
            plan[(it["kind"], it["name"])] = it

    # ---- dictionaries -----------------------------------------------------
    dict_names = {d["name"] for d in src["dictionaries"]}
    templates: Dict[str, str] = {}          # template name -> data label
    predefined_refs: Dict[str, str] = {}    # predefined dictionary referenced by engines -> data label

    def template_label(name: str) -> str:
        if name not in templates:
            templates[name] = S.get("tpl", name)
        return templates[name]

    out = ["# Dictionaries — generated from the pack; predefined Zscaler dictionaries are looked up by name.\n\n"]
    for d in src["dictionaries"]:
        label = S.get("dict", d["name"])
        out.append(f'resource "zia_dlp_dictionaries" "{label}" {{\n')
        out.append(_attr("name", hcl_str(d["name"])))
        out.append(_attr("description", hcl_str(_provenance(meta, pack_id, d.get("description", ""), limit=DICT_DESCRIPTION_MAX))))
        out.append(_attr("dictionary_type", hcl_str("PATTERNS_AND_PHRASES")))
        out.append(_attr("custom", "true"))
        out.append(_attr("custom_phrase_match_type", hcl_str(d.get("custom_phrase_match_type", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"))))
        if d.get("predefined_clone"):
            tpl = d.get("dict_template_name")
            if d.get("dict_template_id"):
                out.append(_attr("dict_template_id", str(int(d["dict_template_id"]))))
            elif tpl:
                out.append(_attr("dict_template_id", f"data.zia_dlp_dictionaries.{template_label(tpl)}.id"))
            if d.get("confidence_level_for_predefined_dict"):
                out.append(_attr("confidence_level_for_predefined_dict", hcl_str(d["confidence_level_for_predefined_dict"])))
        if d.get("confidence_threshold"):
            out.append(_attr("confidence_threshold", hcl_str(d["confidence_threshold"])))
        prox = int(d.get("proximity") or 0)
        if prox > 0:
            out.append(_attr("proximity", str(prox)))
            if not d.get("predefined_clone"):
                out.append(_attr("proximity_enabled_for_custom_dictionary", "true"))
        if d.get("include_bin_numbers"):
            out.append(_attr("include_bin_numbers", "true"))
        if d.get("include_ssn_numbers"):
            # Accepted by the ZIA API (and the in-app deploy) but not exposed by provider 4.8.x.
            out.append("  # include_ssn_numbers = true  (not supported by the zscaler/zia provider; set in the portal)\n")
        if d.get("hierarchical_identifiers"):
            out.append(_attr("hierarchical_identifiers", hcl_list(d["hierarchical_identifiers"])))
        for p in d.get("patterns") or []:
            out.append(f"  patterns {{\n    action  = {hcl_str(p.get('action', 'PATTERN_COUNT_TYPE_ALL'))}\n    pattern = {hcl_str(p['pattern'])}\n  }}\n")
        for p in d.get("phrases") or []:
            out.append(f"  phrases {{\n    action = {hcl_str(p.get('action', 'PHRASE_COUNT_TYPE_ALL'))}\n    phrase = {hcl_str(p['phrase'])}\n  }}\n")
        out.append("}\n\n")

    # ---- engines ------------------------------------------------------------
    eng = ["# Engines — expressions reference dictionaries by resource, or by data lookup for predefined ones.\n\n"]
    for e in src["engines"]:
        label = S.get("engine", e["name"])
        expr = e["expression"]
        # Pack dictionaries first (longest name first, so a name that is a
        # prefix of another cannot clobber it, and parentheses inside names
        # never confuse the parser); whatever is left is a predefined
        # Zscaler dictionary looked up by name.
        for name in sorted(dict_names, key=len, reverse=True):
            if f"D:{name}" in expr:
                expr = expr.replace(f"D:{name}", f"D${{zia_dlp_dictionaries.{S.get('dict', name)}.id}}.S")
        for name in sorted({m.group(1).strip() for m in _REF_RE.finditer(expr)}, key=len, reverse=True):
            if name not in predefined_refs:
                predefined_refs[name] = S.get("pre", name)
            expr = expr.replace(f"D:{name}", f"D${{data.zia_dlp_dictionaries.{predefined_refs[name]}.id}}.S")
        # ZIA compares every term to a count; a bare term means "at least one match".
        expr = re.sub(r"(D\$\{[^}]+\}\.S)(?!\s*[<>=])", r"\1 > 0", expr)
        eng.append(f'resource "zia_dlp_engines" "{label}" {{\n')
        eng.append(_attr("name", hcl_str(e["name"])))
        eng.append(_attr("description", hcl_str(_provenance(meta, pack_id, e.get("description", "")))))
        eng.append(_attr("custom_dlp_engine", "true"))
        eng.append(_attr("engine_expression", hcl_str(expr, interpolate=True)))
        eng.append("}\n\n")

    # Data sources go at the top of dictionaries.tf now that we know them all.
    data = []
    for name, label in templates.items():
        data.append(f'data "zia_dlp_dictionaries" "{label}" {{\n  name = {hcl_str(name)}\n}}\n\n')
    for name, label in predefined_refs.items():
        data.append(f'data "zia_dlp_dictionaries" "{label}" {{\n  name = {hcl_str(name)}\n}}\n\n')
    files["dictionaries.tf"] = out[0] + "".join(data) + "".join(out[1:])
    files["engines.tf"] = "".join(eng)

    # ---- rules ----------------------------------------------------------------
    engine_labels = {e["name"]: S.get("engine", e["name"]) for e in src["engines"]}
    rules = ["# Rules — one resource per pack policy. New rules take var.rule_starting_order + N in their channel.\n\n"]
    group_labels: Dict[str, str] = {}
    for g in src.get("app_groups") or []:
        lbl = S.get("appgroup", g["name"])
        group_labels[g["name"]] = lbl
        rules.append(f'resource "zia_endpoint_dlp_application_group" "{lbl}" {{\n'
                     + _attr("name", hcl_str(g["name"]))
                     + _attr("description", hcl_str(_provenance(meta, pack_id, g.get("description", ""))))
                     + _attr("resources", hcl_list([str(x) for x in (g.get("resources") or [])]))
                     + "}\n\n")
    lookups: List[str] = []
    variables_extra: List[str] = []
    rule_refs: List[str] = []
    app_classes: Dict[str, str] = {}
    per_channel_index: Dict[str, int] = {}
    for p in src["policies"]:
        channel = pc.channel_of(p)
        res = RESOURCE_BY_CHANNEL.get(channel)
        if not res:
            continue
        sub = bool(p.get("parent_rule")) and channel == pc.ENDPOINT
        if sub:
            res = "zia_endpoint_dlp_sub_rules"
        label = S.get("rule", p["name"])
        rule_refs.append(f"{res}.{label}")
        idx = per_channel_index.get(channel, 0)
        if not sub:
            per_channel_index[channel] = idx + 1
        item = plan.get(("policy", p["name"]))
        existing_order = ((item or {}).get("tenant") or {}).get("order")
        if sub:
            existing_order = existing_order or int(p.get("order") or 1)
        order_expr = str(int(existing_order)) if existing_order else f"var.rule_starting_order + {idx}"

        if channel in pc.CONTROL_CHANNELS:
            rules.append(_control_rule_hcl(channel, res, label, p, meta, pack_id, order_expr, lookups, app_classes))
            continue

        engine_ids = []
        for n in p.get("engines", []):
            if n in engine_labels:
                engine_ids.append(f"zia_dlp_engines.{engine_labels[n]}.id")
            else:
                lbl = S.get("preeng", n)
                lookups.append(f'data "zia_dlp_engines" "{lbl}" {{\n  name = {hcl_str(n)}\n}}\n\n')
                engine_ids.append(f"data.zia_dlp_engines.{lbl}.id")

        r = [f'resource "{res}" "{label}" {{\n']
        r.append(_attr("name", hcl_str(p["name"])))
        r.append(_attr("description", hcl_str(_provenance(meta, pack_id, p.get("description", "")))))
        if sub:
            r.append(_attr("parent_rule", f"zia_endpoint_dlp_rules.{S.get('rule', str(p['parent_rule']))}.rule_id"))
        # Keep an existing rule where the admin placed it (gap mode); otherwise stack new rules from the start order.
        r.append(_attr("order", str(int(existing_order)) if existing_order else f"var.rule_starting_order + {idx}"))
        if channel != pc.EMAIL:
            r.append(_attr("rank", "var.policy_rank"))
        r.append(_attr("state", hcl_str(p.get("state", "ENABLED"))))
        r.append(_attr("action", hcl_str(p.get("action", pc.default_action(channel)))))
        if p.get("severity"):
            r.append(_attr("severity", hcl_str(p["severity"])))
        r.append(_attr("without_content_inspection", "true" if p.get("without_content_inspection") else "false"))
        if p.get("min_size"):
            r.append(_attr("min_size", str(int(p["min_size"]))))
        if p.get("file_types"):
            r.append(_attr("file_types", hcl_list(p["file_types"])))

        if channel == pc.WEB:
            r.append(_attr("protocols", hcl_list(p.get("protocols", ["ANY_RULE"]))))
            for flag in ("match_only", "zscaler_incident_receiver"):
                if p.get(flag):
                    r.append(_attr(flag, "true"))
            if p.get("ocr_enabled"):
                # Documented for zia_dlp_web_rules but absent from the 4.8.x schema; the API path applies it.
                r.append("  # ocr_enabled = true  (not in provider 4.8.x schema; enable OCR on this rule in the portal)\n")
            classes = [str(c).upper() for c in (p.get("cloud_app_classes") or [])]
            if p.get("cloud_applications"):
                r.append(_attr("cloud_applications", hcl_list(p["cloud_applications"])))
            elif classes:
                refs = []
                for cls in classes:
                    if cls not in app_classes:
                        app_classes[cls] = slug(cls, "apps_")
                        lookups.append(f'data "zia_cloud_applications" "{app_classes[cls]}" {{\n  policy_type = "cloud_application_policy"\n  app_class   = [{hcl_str(cls)}]\n}}\n\n')
                    refs.append(f"[for a in data.zia_cloud_applications.{app_classes[cls]}.applications : a.app]")
                r.append(_attr("cloud_applications", "sort(distinct(concat(" + ", ".join(refs) + ")))"))
                r.append("  lifecycle {\n    precondition {\n"
                         f"      condition     = length(sort(distinct(concat({', '.join(refs)})))) > 0\n"
                         f"      error_message = \"No cloud applications of class {', '.join(classes)} resolved on this tenant; set cloud_applications explicitly.\"\n"
                         "    }\n  }\n")
        elif channel == pc.ENDPOINT:
            r.append(_attr("device_trust_levels", hcl_list(p.get("device_trust_levels") or list(pc.ENDPOINT_TRUST_LEVELS))))
            for opt in ("data_transfer_method", "network_type"):
                if p.get(opt):
                    r.append(_attr(opt, hcl_str(p[opt])))
            if p.get("user_risk_score_levels"):
                r.append(_attr("user_risk_score_levels", hcl_list(p["user_risk_score_levels"])))
            if p.get("eun_enabled") is not None:
                r.append(_attr("eun_enabled", "true" if p["eun_enabled"] else "false"))
            if str(p.get("action", "")).upper() == "CONFIRM":
                # ZIA requires a user confirmation template for CONFIRM; resolve the tenant's ENDPOINT_DLP one.
                lookups.append('data "zia_eun_user_confirmation_template_product" "endpoint_dlp" {\n  product = "ENDPOINT_DLP"\n  name    = var.endpoint_dlp_user_confirmation_template_name\n}\n\n')
                if not any('endpoint_dlp_user_confirmation_template_name' in v for v in variables_extra):
                    variables_extra.append('variable "endpoint_dlp_user_confirmation_template_name" {\n  description = "User Confirmation template for Endpoint DLP CONFIRM rules. Leave null to use the tenant default ENDPOINT_DLP template."\n  type        = string\n  default     = null\n}\n\n')
                r.append(_attr("uc_template_id", "data.zia_eun_user_confirmation_template_product.endpoint_dlp.id"))
            groups = [g for g in (p.get("endpoint_application_groups") or [])]
            if groups:
                refs = [f"tostring(zia_endpoint_dlp_application_group.{group_labels[g]}.group_id)" for g in groups if g in group_labels]
                if refs:
                    r.append(f"  end_point_application_groups {{\n    group_id = {hcl_list(refs, raw=True)}\n  }}\n")
                    # ZIA accepts the association but does not always return it on read (provider-documented).
                    r.append("  lifecycle {\n    ignore_changes = [end_point_application_groups]\n  }\n")
        elif channel == pc.SAAS:
            r.append(_attr("type", hcl_str(p["saas_type"])))
            r.append(_attr("collaboration_scope", hcl_list(p.get("collaboration_scope") or ["ANY"])))
            for opt in ("components", "content_location", "domains"):
                if p.get(opt):
                    r.append(_attr(opt, hcl_list(p[opt]) if isinstance(p[opt], list) else hcl_str(p[opt])))
        elif channel == pc.EMAIL:
            if p.get("user_risk_score_levels"):
                r.append(_attr("user_risk_score_levels", hcl_list(p["user_risk_score_levels"])))
            if p.get("content_locations"):
                r.append(_attr("content_locations", hcl_list(p["content_locations"])))
            if p.get("custom_header"):
                r.append(_attr("custom_header", hcl_str(p["custom_header"])))

        r.append(f"  dlp_engines {{\n    id = {hcl_list(engine_ids, raw=True)}\n  }}\n")

        # SaaS / email tenants: pinned by name in the pack, resolved in gap mode, or a variable to fill in.
        if channel in (pc.SAAS, pc.EMAIL):
            want = p.get("tenants", "any")
            names: List[str] = []
            if isinstance(want, list) and want:
                names = [str(w) for w in want]
            elif item and (item.get("detail") or {}).get("tenants"):
                names = list(item["detail"]["tenants"])
            block = "cloud_app_tenants" if channel == pc.SAAS else "email_tenants"
            if names:
                ids = []
                for n in names:
                    lbl = S.get("tenant", n)
                    lookups.append(f'data "zia_casb_tenant" "{lbl}" {{\n  tenant_name = {hcl_str(n)}\n}}\n\n')
                    ids.append(f"data.zia_casb_tenant.{lbl}.tenant_id")
                r.append(f"  {block} {{\n    id = {hcl_list(ids, raw=True)}\n  }}\n")
            else:
                var = f"saas_tenant_ids_{label}"
                variables_extra.append(
                    f'variable "{var}" {{\n  description = "IDs of the onboarded SaaS application tenants rule {hcl_str(p["name"])[1:-1]} applies to '
                    f'(Administration > SaaS Application Tenants). Run a preflight in DLP-Check to have these resolved automatically."\n'
                    f"  type        = list(number)\n}}\n\n")
                r.append(f"  {block} {{\n    id = var.{var}\n  }}\n")

        if p.get("notification_template"):
            lbl = S.get("tpl_notif", p["notification_template"])
            lookups.append(f'data "zia_dlp_notification_templates" "{lbl}" {{\n  name = {hcl_str(p["notification_template"])}\n}}\n\n')
            r.append(f"  notification_template {{\n    id = data.zia_dlp_notification_templates.{lbl}.id\n  }}\n")
        if p.get("labels"):
            ids = []
            for lb in p["labels"]:
                lbl = S.get("label", lb)
                lookups.append(f'data "zia_rule_labels" "{lbl}" {{\n  name = {hcl_str(lb)}\n}}\n\n')
                ids.append(f"data.zia_rule_labels.{lbl}.id")
            r.append(f"  labels {{\n    id = {hcl_list(ids, raw=True)}\n  }}\n")
        r.append("}\n\n")
        rules.append("".join(r))
    # De-duplicate lookups while keeping order.
    seen = set()
    uniq = [x for x in lookups if not (x in seen or seen.add(x))]
    files["rules.tf"] = rules[0] + "".join(uniq) + "".join(rules[1:])

    # ---- activation, versions, provider, variables, outputs ------------------
    files["activation.tf"] = (
        "# Activate pending ZIA configuration once every rule is in place.\n\n"
        'resource "zia_activation_status" "this" {\n  count  = var.activate ? 1 : 0\n  status = "ACTIVE"\n\n'
        "  depends_on = [\n" + "".join(f"    {ref},\n" for ref in rule_refs) + "  ]\n}\n"
    )
    files["versions.tf"] = _versions_tf(backend)
    files["provider.tf"] = (
        "# Credentials come from variables (see terraform.tfvars.example) or, when the\n"
        "# variables are left null, from ZSCALER_CLIENT_ID / ZSCALER_CLIENT_SECRET /\n"
        "# ZSCALER_VANITY_DOMAIN / ZSCALER_CLOUD in the environment.\n\n"
        'provider "zia" {\n  client_id     = var.zscaler_client_id\n  client_secret = var.zscaler_client_secret\n'
        "  vanity_domain = var.zscaler_vanity_domain\n  zscaler_cloud = var.zscaler_cloud\n}\n"
    )
    files["variables.tf"] = _variables_tf(meta, variables_extra)
    files["outputs.tf"] = (
        'output "dictionaries" {\n  value = { for k, r in {\n'
        + "".join(f"    {S.get('dict', d['name'])} = zia_dlp_dictionaries.{S.get('dict', d['name'])}\n" for d in src["dictionaries"])
        + "  } : r.name => r.id }\n}\n\n"
        'output "engines" {\n  value = { for k, r in {\n'
        + "".join(f"    {S.get('engine', e['name'])} = zia_dlp_engines.{S.get('engine', e['name'])}\n" for e in src["engines"])
        + "  } : r.name => r.id }\n}\n\n"
        'output "rules" {\n  value = [\n' + "".join(f"    {ref}.name,\n" for ref in rule_refs) + "  ]\n}\n"
    )
    files["terraform.tfvars.example"] = _tfvars_example(variables_extra)
    files[".gitignore"] = ".terraform/\n*.tfstate\n*.tfstate.*\nterraform.tfvars\n*.auto.tfvars\ncrash.log\n"

    # ---- gap mode: import blocks ---------------------------------------------
    gap_summary: Dict[str, Any] = {}
    if report:
        imports = ["# Generated from a DLP-Check preflight against " + hcl_str(report.get("tenant_label", "the tenant"))[1:-1] + ".\n"
                   "# Objects that already exist are imported into state on the first apply, so\n"
                   "# `terraform plan` shows exactly the gap: in-sync objects import with no change,\n"
                   "# customized objects import too (apply would overwrite them: delete their import block to keep the customer's version),\n# missing objects are created.\n\n"]
        counts = {"in_sync": 0, "customized": 0, "missing": 0, "blocked": 0}
        for kind, key_kind, res in (("dictionary", "dict", "zia_dlp_dictionaries"), ("engine", "engine", "zia_dlp_engines")):
            for obj in (src["dictionaries"] if kind == "dictionary" else src["engines"]):
                it = plan.get((kind, obj["name"]))
                _gap_import(imports, counts, it, res, S.get(key_kind, obj["name"]))
        for g in src.get("app_groups") or []:
            _gap_import(imports, counts, plan.get(("app_group", g["name"])), "zia_endpoint_dlp_application_group", S.get("appgroup", g["name"]))
        for p in src["policies"]:
            channel = pc.channel_of(p)
            res = RESOURCE_BY_CHANNEL.get(channel)
            if not res:
                continue
            sub = bool(p.get("parent_rule")) and channel == pc.ENDPOINT
            if sub:
                res = "zia_endpoint_dlp_sub_rules"
            it = plan.get(("policy", p["name"]))
            import_id = None
            if it and (it.get("tenant") or {}).get("id") is not None:
                tid = it["tenant"]["id"]
                if channel == pc.SAAS:
                    import_id = f"{p['saas_type']}:{tid}"
                elif channel == pc.CLOUD_APP:
                    import_id = f"{str(p['type']).upper()}:{tid}"
                elif sub:
                    import_id = f"{(it['tenant'] or {}).get('parent_id', '?')}:{tid}"
                else:
                    import_id = str(tid)
            _gap_import(imports, counts, it, res, S.get("rule", p["name"]), import_id=import_id)
        files["imports.tf"] = "".join(imports)
        gap_summary = counts
    files["README.md"] = _readme(meta, pack_id, src, bool(report), gap_summary, report)
    return files


def _gap_import(imports: List[str], counts: Dict[str, int], item: Optional[Dict[str, Any]], res: str, label: str,
                import_id: Optional[str] = None) -> None:
    if not item:
        counts["missing"] += 1
        return
    status = item.get("status")
    tid = (item.get("tenant") or {}).get("id")
    if status in ("reuse", "reuse_differs", "restore", "noop") and tid is not None:
        customized = bool(item.get("drift")) or status == "restore"
        counts["customized" if customized else "in_sync"] += 1
        note = ("customized in the tenant: " + ", ".join(item.get("drift") or ["content"])
                + " — terraform apply would overwrite this with the baseline; delete this import block to leave the customer's version alone"
                if customized else "in sync")
        imports.append(f"# {item['name']} — {note}\nimport {{\n  to = {res}.{label}\n  id = {hcl_str(import_id if import_id is not None else str(tid))}\n}}\n\n")
    elif status == "create":
        counts["missing"] += 1
    else:
        counts["blocked"] += 1
        imports.append(f"# {item['name']} — {status}: {item.get('reason', '')}\n\n")


def _versions_tf(backend: Optional[Dict[str, str]]) -> str:
    out = [f"terraform {{\n  required_version = {hcl_str(TERRAFORM_VERSION)}\n\n  required_providers {{\n"
           f"    zia = {{\n      source  = {hcl_str(PROVIDER_SOURCE)}\n      version = {hcl_str(PROVIDER_VERSION)}\n    }}\n  }}\n"]
    if backend:
        out.append('\n  backend "s3" {\n' + "".join(f"    {k.ljust(14)} = {hcl_str(v)}\n" for k, v in backend.items()) + "  }\n")
    else:
        out.append('\n  # Remote state (recommended for shared use). Uncomment and fill in, or pass\n'
                   '  # -backend-config=... on `terraform init`.\n'
                   '  # backend "s3" {\n  #   bucket         = "my-terraform-state"\n  #   key            = "zscaler/dlp/<pack>.tfstate"\n'
                   '  #   region         = "us-east-1"\n  #   encrypt        = true\n  #   dynamodb_table = "terraform-locks"\n  # }\n')
    out.append("}\n")
    return "".join(out)


def _variables_tf(meta: Dict[str, Any], extra: List[str]) -> str:
    return (
        'variable "zscaler_client_id" {\n  description = "OneAPI client ID. Leave null to use ZSCALER_CLIENT_ID."\n  type        = string\n  default     = null\n  sensitive   = true\n}\n\n'
        'variable "zscaler_client_secret" {\n  description = "OneAPI client secret. Leave null to use ZSCALER_CLIENT_SECRET."\n  type        = string\n  default     = null\n  sensitive   = true\n}\n\n'
        'variable "zscaler_vanity_domain" {\n  description = "ZIdentity vanity domain (acme for acme.zslogin.net). Leave null to use ZSCALER_VANITY_DOMAIN."\n  type        = string\n  default     = null\n}\n\n'
        'variable "zscaler_cloud" {\n  description = "Leave null (or empty) for commercial production; beta, gov or govus otherwise. Env: ZSCALER_CLOUD."\n  type        = string\n  default     = null\n}\n\n'
        'variable "rule_starting_order" {\n  description = "Order given to the first NEW rule of each channel; further new rules follow contiguously. Existing rules imported in gap mode keep their current order."\n  type        = number\n  default     = 1\n}\n\n'
        'variable "policy_rank" {\n  description = "Admin rank for the rules (0-7). 0 takes precedence over rules made by lower-ranked admins."\n  type        = number\n  default     = 7\n}\n\n'
        'variable "activate" {\n  description = "Activate pending ZIA changes after apply (zia_activation_status)."\n  type        = bool\n  default     = true\n}\n\n'
        + "".join(extra)
    )


def _tfvars_example(extra: List[str]) -> str:
    out = ["# Copy to terraform.tfvars (git-ignored). Credentials may instead be exported:\n",
           '#   export ZSCALER_CLIENT_ID="..." ZSCALER_CLIENT_SECRET="..." ZSCALER_VANITY_DOMAIN="acme" ZSCALER_CLOUD=""\n\n',
           '# zscaler_client_id     = "..."\n# zscaler_client_secret = "..."\n# zscaler_vanity_domain = "acme"\n# zscaler_cloud         = ""\n\n',
           "rule_starting_order = 1\npolicy_rank         = 7\nactivate            = true\n"]
    for v in extra:
        m = re.search(r'variable "([^"]+)"', v)
        if m:
            out.append(f"# {m.group(1)} = [123456]\n")
    return "".join(out)


def _readme(meta: Dict[str, Any], pack_id: str, src: Dict[str, Any], gap: bool, counts: Dict[str, Any],
            report: Optional[Dict[str, Any]]) -> str:
    b = meta.get("baseline")
    lines = [f"# {meta.get('name', pack_id)} — Terraform\n\n",
             f"Generated by DLP-Check from pack `{pack_id}`"
             + (f" v{meta.get('version')}" if meta.get("version") else "") + " for the official "
             f"[zscaler/zia]({REGISTRY_URL}) provider ({PROVIDER_VERSION}).\n\n",
             f"{len(src['dictionaries'])} dictionaries · {len(src['engines'])} engines · {len(src['policies'])} rules"
             + (" · **baseline**" if b else "") + "\n\n"]
    if b:
        lines.append("This pack is a baseline: the reference a tenant is measured against on its data-governance journey. "
                     "Terraform is convergent by nature, so once objects are in state `terraform plan` shows every way the tenant "
                     "differs from the reference and `terraform apply` would make them match. Use `plan` to assess; `apply` only "
                     "when the customer wants the tenant converged (an enabled rule or a hardened action is usually progress to keep, "
                     "not something to revert — update the pack instead). Objects the baseline does not define are never touched.\n\n")
    if gap:
        lines.append(f"## Gap against {report.get('tenant_label', 'the tenant') if report else 'the tenant'}\n\n"
                     f"| In sync | Customized | Missing | Blocked |\n|---|---|---|---|\n"
                     f"| {counts.get('in_sync', 0)} | {counts.get('customized', 0)} | {counts.get('missing', 0)} | {counts.get('blocked', 0)} |\n\n"
                     "`imports.tf` adopts every existing object into state on the first apply. In-sync objects import with no "
                     "change; customized objects import and would be updated in place (delete their import block to keep the "
                     "customer's version); missing objects are created; blocked objects are listed as comments with their reason. "
                     "The first `terraform plan` is the gap.\n\n")
    lines.append("## Use\n\n```bash\nterraform init\nterraform plan      # review: creates, in-place updates, imports\nterraform apply\n```\n\n"
                 "Credentials: `terraform.tfvars` (copy the example) or `ZSCALER_*` environment variables. "
                 "The client needs a ZIA role with write access to DLP dictionaries, engines and the rule types in this pack.\n\n"
                 "Ordering: new rules are inserted starting at `rule_starting_order` and push existing rules down. "
                 "Run `terraform apply -parallelism=1` if the tenant reports ordering conflicts.\n\n"
                 "`terraform destroy` removes exactly the objects in state, in dependency order.\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# Packaging
# ---------------------------------------------------------------------------

def write_workspace(files: Dict[str, str], out_dir: str) -> List[str]:
    os.makedirs(out_dir, exist_ok=True)
    written = []
    for name, content in files.items():
        path = os.path.join(out_dir, name)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
        written.append(path)
    return written


def zip_workspaces(workspaces: Dict[str, Dict[str, str]]) -> bytes:
    """{pack_id: files} -> zip bytes with one folder per pack."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for pack_id, files in workspaces.items():
            for name, content in files.items():
                z.writestr(f"{pack_id}/{name}", content)
    return buf.getvalue()


def split_report(report: Dict[str, Any], pack_id: str) -> Dict[str, Any]:
    """Restrict a multi-pack preflight report to the items of one pack."""
    items = [i for i in report.get("items", []) if pack_id in (i.get("packs") or [])]
    return dict(report, items=items)


if __name__ == "__main__":  # pragma: no cover — small CLI for local use
    import argparse
    import sys
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from dlp_importer import discover_packs

    ap = argparse.ArgumentParser(description="Generate Terraform workspaces for DLP packs.")
    ap.add_argument("packs", nargs="*", help="pack ids (default: all)")
    ap.add_argument("--out", default="terraform", help="output root (one folder per pack)")
    args = ap.parse_args()
    known = {p["id"]: p for p in discover_packs()}
    ids = args.packs or sorted(known)
    for pid in ids:
        if pid not in known:
            sys.exit(f"unknown pack: {pid}")
        files = generate({"id": pid, "dir": known[pid]["dir"]})
        write_workspace(files, os.path.join(args.out, pid))
        print(f"{pid}: {len(files)} files -> {os.path.join(args.out, pid)}")
