"""Export from tenant as a pack.

Reads a tenant's DLP rules on every channel the app deploys (Web,
Endpoint, SaaS Security API, Email) and writes them, with every engine
they use and every dictionary those engines use, as an ordinary policy
pack: pack.json plus configs/dlp_dictionaries.json, dlp_engines.json and
dlp_policies.json, the layout dlp_importer and pack_library read. Deploy
Policy Packs can then put the same rules into another tenant (or back
into this one), and the pack library accepts the zip as an upload.

What travels, and how:

  custom dictionaries   full definition: phrases, patterns, match type,
                        proximity
  clones                as clones: dict_template_name names the predefined
                        dictionary (its tenant name), plus confidence,
                        identifiers and the other clone settings
  predefined            not in the pack; engines name them (D:<name>) and
  dictionaries          the planner resolves the name in the target tenant
  custom engines        expression rewritten from D<id>.S to D:<name>
  predefined engines    not in the pack; rules name them
  rules                 channel order, then the tenant's order; action and
                        state as the tenant has them; labels, notification
                        templates, SaaS / email tenants and endpoint
                        application groups by name

Anything a pack cannot carry (users, groups, departments, locations,
custom URL categories, ICAP servers, auditors, ...) is left out and listed
in pack.json under `not_exported` with the reason, never dropped
silently. Nothing is written to the tenant, and no credential reaches the
pack.

Reads go through the client's ZIA services, the same list calls the
deploy planner makes (so the app's read pacing and rate limits apply).
Where the SDK's model leaves out a field a pack needs (a clone's
dictTemplateId), the raw answer of the same call fills it in.
"""
from __future__ import annotations

import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pack_channels as pc
from dlp_importer import _nx, _obj_to_dict

LogFn = Optional[Callable[[str], None]]

EXPORT_VERSION = "1.0"
DISABLED_NOTE = ("Deploy Policy Packs creates every rule DISABLED and monitor-only, whatever state and action it had in the "
                 "tenant it came from; the pack keeps the original action and state, and a blocking action becomes the "
                 "target the data-governance journey names. Enable each rule once it has been reviewed.")
ORDER_NOTE = ("Rules are listed per channel in the order the tenant had them (also in rule_order). Deploy Policy Packs "
              "adds the new rules above the rules already in the target, in this order, so check where they sit after a deploy.")
ONE_CHANNEL_NOTE = ("Install one channel at a time. Deploy Web DLP first, check it, then Endpoint DLP, then SaaS, then Email, "
                    "one channel per run. A small run is easy to verify and avoids the burst of requests that makes ZIA block "
                    "the API client (Resource Access Blocked).")

_TERM_RE = re.compile(r"D(\d+)\.S")
_CAMEL_RE = re.compile(r"(?<!^)(?=[A-Z])")
_MARK_RE = re.compile(r"\s*\[DLP-Check (?:baseline|pack) [^\]]*\].*$", re.S)

# Fields a rule carries that say nothing about what it does.
_HOUSEKEEPING = {"id", "name", "order", "rank", "state", "action", "description", "dlp_engines", "access_control", "last_modified_by",
                 "last_modified_time", "pid", "deleted", "mod_uid", "z_ver_id_md32", "type", "rule_type", "sub_rules", "parent_rule",
                 "predefined", "default_rule", "tenant", "version", "versions", "severity"}
# Scope that names objects of the source tenant: the ids mean nothing in another one.
_TENANT_SCOPE = {
    "locations": "locations", "location_groups": "location groups", "groups": "groups", "departments": "departments",
    "users": "users", "excluded_groups": "excluded groups", "excluded_departments": "excluded departments",
    "excluded_users": "excluded users", "time_windows": "time windows", "workload_groups": "workload groups",
    "source_ip_groups": "source IP groups", "included_domain_profiles": "domain profiles", "excluded_domain_profiles": "domain profiles",
    "criteria_domain_profiles": "domain profiles", "email_recipient_profiles": "email recipient profiles", "entity_groups": "entity groups",
    "zpa_app_segments": "ZPA application segments", "icap_server": "ICAP server", "auditor": "auditor", "receiver": "incident receiver",
    "devices": "devices", "device_groups": "device groups", "buckets": "buckets", "redaction_profile": "redaction profile",
    "watermark_profile": "watermark profile", "casb_email_label": "email label", "casb_tombstone_template": "tombstone template",
    "quarantine_location": "quarantine location", "resource_groups": "endpoint resource groups", "resources": "endpoint resources",
    "end_point_applications": "endpoint applications",
}
_SCOPE_REASON = ("names {what} of the source tenant by id; ids differ between tenants and a pack carries no such scope, so the "
                 "rule arrives without it (it applies more widely until it is scoped again in the target tenant)")
_NOT_CARRIED = "Deploy Policy Packs does not set this field, so the pack cannot carry it; set it again in the target tenant"
_PRIVATE = {"external_auditor_email"}   # a person's address: named, never copied

# Per channel: the rule fields a pack carries as they are (build_payload sends them).
_PLAIN = {
    pc.WEB: ("protocols", "min_size", "file_types", "cloud_applications"),
    pc.ENDPOINT: ("data_transfer_method", "device_trust_levels", "user_risk_score_levels", "network_type", "min_size", "file_types"),
    pc.SAAS: ("collaboration_scope", "components", "content_location", "recipient", "domains", "file_types"),
    pc.EMAIL: ("user_risk_score_levels", "content_locations", "min_size", "custom_header", "file_types"),
}
_FLAGS = {pc.WEB: ("match_only", "without_content_inspection", "ocr_enabled", "zscaler_incident_receiver"),
          pc.ENDPOINT: ("without_content_inspection",), pc.SAAS: ("without_content_inspection",), pc.EMAIL: ("without_content_inspection",)}


def _f(obj: Any, *keys: str, default: Any = None) -> Any:
    """A field in snake_case or camelCase, whatever shape the read returned."""
    alts = []
    for k in keys:
        alts.append(k)
        parts = k.split("_")
        alts.append(parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:]))
    return pc._field(obj, *alts, default=default)


def _snake(key: str) -> str:
    return _CAMEL_RE.sub("_", str(key)).lower()


def _plain(obj: Any) -> Dict[str, Any]:
    d = obj if isinstance(obj, dict) else _obj_to_dict(obj)
    return {_snake(k): v for k, v in (d or {}).items()} if isinstance(d, dict) else {}


def _strip_mark(text: Any) -> str:
    """A description without the provenance tag a DLP-Check deploy added."""
    return _MARK_RE.sub("", str(text or "")).strip()


def _names(items: Any) -> Tuple[List[str], List[str]]:
    """(names, ids without a name) of a list of {id, name} references."""
    names, bare = [], []
    for x in items if isinstance(items, list) else ([items] if items else []):
        n = _f(x, "name") if not isinstance(x, (str, int)) else None
        if n:
            names.append(str(n))
        else:
            bare.append(str(x if isinstance(x, (str, int)) else _f(x, "id")))
    return names, bare


# ---------------------------------------------------------------------------
# Reading the tenant
# ---------------------------------------------------------------------------

def _rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Rows of a list call as plain snake_case dicts: the SDK's models,
    with any field they leave out taken from the raw answer."""
    data, err = _nx(ret)
    if err:
        return [], str(err)[:200]
    raw_by_id: Dict[str, Dict[str, Any]] = {}
    resp = ret[1] if isinstance(ret, tuple) and len(ret) >= 3 else None
    getter = getattr(resp, "get_results", None)
    if callable(getter):
        try:
            for r in getter() or []:
                if isinstance(r, dict) and r.get("id") is not None:
                    raw_by_id[str(r["id"])] = _plain(r)
        except Exception:  # noqa: BLE001 - the models alone still export
            raw_by_id = {}
    out = []
    for item in data or []:
        row = _plain(item)
        for k, v in raw_by_id.get(str(row.get("id")), {}).items():
            if row.get(k) in (None, "", [], {}):
                row[k] = v
        out.append(row)
    return out, None


def _list_rules(zia, channel: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every rule of one DLP channel, with the listing call the planner uses."""
    svc = getattr(zia, pc.CHANNELS[channel]["service"], None)
    if svc is None:
        return [], f"{pc.CHANNELS[channel]['service']} is not available in the installed zscaler-sdk-python"
    try:
        if channel == pc.SAAS:
            lister = getattr(svc, "list_all_rules", None)
            return _rows(lister() if lister else svc.list_rules("ANY"))
        return _rows(svc.list_rules())
    except Exception as e:  # noqa: BLE001 - reported, the other channels still export
        return [], str(e)[:200]


def read_tenant(client, channels: Iterable[str] = pc.DLP_CHANNELS, log: LogFn = None) -> Dict[str, Any]:
    """Dictionaries, engines and the rules of `channels`. Read-only; never
    raises: what could not be read is in `errors`."""
    _log = log or (lambda m: None)
    zia = client.zia
    snap: Dict[str, Any] = {"dictionaries": [], "engines": [], "rules": {}, "errors": {}}
    _log("Reading the tenant: DLP dictionaries (custom and predefined)…")
    try:
        snap["dictionaries"], err = _rows(zia.dlp_dictionary.list_dicts())
    except Exception as e:  # noqa: BLE001
        err = str(e)[:200]
    if err:
        snap["errors"]["dictionaries"] = err
    _log(f"Reading the tenant: DLP dictionaries: {len(snap['dictionaries'])} found.")
    _log("Reading the tenant: DLP engines…")
    try:
        lister = getattr(zia.dlp_engine, "list_dlp_engines", None) or zia.dlp_engine.list_dlp_engines_lite
        snap["engines"], err = _rows(lister())
    except Exception as e:  # noqa: BLE001
        err = str(e)[:200]
    if err:
        snap["errors"]["engines"] = err
    _log(f"Reading the tenant: DLP engines: {len(snap['engines'])} found.")
    for ch in pc.DLP_CHANNELS:
        if ch not in channels:
            continue
        _log(f"Reading the tenant: {pc.label(ch)} rules…")
        rules, err = _list_rules(zia, ch)
        if err:
            snap["errors"][ch] = err
            _log(f"Reading the tenant: {pc.label(ch)} rules could not be listed: {err[:120]}")
            continue
        snap["rules"][ch] = sorted(rules, key=lambda r: int(r.get("order") or 0))
        _log(f"Reading the tenant: {pc.label(ch)} rules: {len(rules)} found.")
    return snap


# ---------------------------------------------------------------------------
# Selection
# ---------------------------------------------------------------------------

def normalize_selection(selection: Any) -> Optional[Dict[str, Optional[set]]]:
    """None (every rule on every channel) or {channel: None (every rule) |
    set of rule ids}. Accepts {channel: [ids] | "all"} or a list of
    {channel, id} picks. Unknown channels raise ValueError."""
    if not selection:
        return None
    out: Dict[str, Optional[set]] = {}
    if isinstance(selection, dict):
        items = selection.items()
    else:
        picked: Dict[str, List[Any]] = {}
        for s in selection:
            picked.setdefault(str((s or {}).get("channel") or pc.WEB).lower(), []).append((s or {}).get("id"))
        items = picked.items()
    for ch, ids in items:
        ch = str(ch).strip().lower()
        if ch not in pc.DLP_CHANNELS:
            raise ValueError(f"unknown channel '{ch}' (use one of {', '.join(pc.DLP_CHANNELS)})")
        out[ch] = None if ids in (None, "all", "*") else {str(i) for i in ids if i is not None}
    return out


# ---------------------------------------------------------------------------
# Building the pack
# ---------------------------------------------------------------------------

def _is_predefined_dict(d: Dict[str, Any]) -> bool:
    return not d.get("custom") and not d.get("predefined_clone") and not d.get("dict_template_id")


def _is_predefined_engine(e: Dict[str, Any]) -> bool:
    """Zscaler's own engines carry predefinedEngineName. The SDK reports
    customDlpEngine False when the answer left it out, so False alone only
    counts for an engine without an expression of its own."""
    if e.get("custom_dlp_engine"):
        return False
    return bool(e.get("predefined_engine_name")) or not str(e.get("engine_expression") or e.get("expression") or "").strip()


def _items(values: Any, key: str) -> List[Dict[str, str]]:
    out = []
    for v in values or []:
        if isinstance(v, (list, tuple)) and len(v) >= 2:
            out.append({"action": str(v[0]), key: str(v[1])})
            continue
        v = _plain(v)
        if v.get(key):
            out.append({"action": str(v.get("action") or f"{key.upper()}_COUNT_TYPE_ALL"), key: str(v[key])})
    return out


def _dictionary(d: Dict[str, Any], template_names: Dict[str, str]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """A tenant dictionary as a pack definition, or (None, why not)."""
    # Every pack dictionary names its match type (the deploy sends it); ZIA's default when the tenant gave none.
    out: Dict[str, Any] = {"name": str(d.get("name") or "").strip(), "description": _strip_mark(d.get("description")),
                           "custom_phrase_match_type": d.get("custom_phrase_match_type") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"}
    patterns, phrases = _items(d.get("patterns"), "pattern"), _items(d.get("phrases"), "phrase")
    prox = int(d.get("proximity") or 0)
    if d.get("predefined_clone") or d.get("dict_template_id"):
        template = template_names.get(str(d.get("dict_template_id"))) if d.get("dict_template_id") is not None else None
        template = template or d.get("dict_template_name")
        if not template:
            return None, ("a clone of a predefined dictionary, but the tenant did not say which one (no template id in its answer), "
                          "so it cannot be recreated as a clone")
        out.update({"predefined_clone": True, "dict_template_name": str(template)})
        for k in ("confidence_threshold", "confidence_level_for_predefined_dict"):
            if d.get(k):
                out[k] = d[k]
        if d.get("hierarchical_identifiers"):
            out["hierarchical_identifiers"] = list(d["hierarchical_identifiers"])
        for k in ("hierarchical_dictionary", "include_bin_numbers", "include_ssn_numbers"):
            if d.get(k):
                out[k] = True
        if prox and d.get("proximity_length_enabled") is not False:
            out["proximity"] = prox
    else:
        kind = str(d.get("dictionary_type") or "").upper()
        if kind and kind != "PATTERNS_AND_PHRASES":
            return None, (f"a {kind.replace('_', ' ').lower()} dictionary: its index or model lives in the source tenant and a pack "
                          "cannot carry it; engines keep naming it, and Deploy Policy Packs deploys them without that term where the "
                          "target tenant has no dictionary of this name")
        if not patterns and not phrases:
            return None, "has no patterns or phrases, so there is nothing a pack could recreate"
        if prox and (d.get("proximity_enabled_for_custom_dictionary") is not False) and (d.get("proximity_length_enabled") is not False):
            out["proximity"] = prox
    if patterns:
        out["patterns"] = patterns
    if phrases:
        out["phrases"] = phrases
    return out, None


class _Builder:
    def __init__(self, snap: Dict[str, Any]):
        self.snap = snap
        self.not_exported: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.dicts_by_id = {str(d.get("id")): d for d in snap["dictionaries"] if d.get("id") is not None}
        self.engines_by_id = {str(e.get("id")): e for e in snap["engines"] if e.get("id") is not None}
        self.template_names = {i: str(d.get("name")) for i, d in self.dicts_by_id.items() if _is_predefined_dict(d) and d.get("name")}
        self.dictionaries: Dict[str, Dict[str, Any]] = {}     # name -> pack definition, in first-use order
        self.engines: Dict[str, Dict[str, Any]] = {}
        self.engine_verdict: Dict[str, Optional[str]] = {}   # engine id -> name to reference, or None
        self.predefined_dicts: List[str] = []
        self.predefined_engines: List[str] = []
        self.dict_done: set = set()
        self.app_group_names: List[str] = []

    def drop(self, kind: str, name: str, reason: str, **extra: Any) -> None:
        self.not_exported.append({"kind": kind, "name": name, "reason": reason, **{k: v for k, v in extra.items() if v not in (None, [], "")}})

    # dictionaries -----------------------------------------------------
    def dictionary(self, did: str) -> Optional[str]:
        """The name an engine expression uses for dictionary `did`, adding
        the dictionary to the pack when it belongs there."""
        d = self.dicts_by_id.get(did)
        if d is None:
            return None
        name = str(d.get("name") or "").strip()
        if did in self.dict_done:
            return name
        self.dict_done.add(did)
        if _is_predefined_dict(d):
            self.predefined_dicts.append(name)
            return name
        definition, why = _dictionary(d, self.template_names)
        if definition is None:
            self.drop("dictionary", name, why)
        else:
            self.dictionaries[name] = definition
        return name

    # engines ----------------------------------------------------------
    def engine(self, eid: str, fallback_name: str = "") -> Optional[str]:
        if eid in self.engine_verdict:
            return self.engine_verdict[eid]
        e = self.engines_by_id.get(eid)
        if e is None:
            self.engine_verdict[eid] = None
            self.drop("engine", fallback_name or f"id {eid}", "a rule uses this engine but the tenant's engine list does not have it")
            return None
        name = str(e.get("name") or e.get("predefined_engine_name") or "").strip()
        if _is_predefined_engine(e):
            self.predefined_engines.append(name)
            self.engine_verdict[eid] = name
            return name
        expr = str(e.get("engine_expression") or e.get("expression") or "").strip()
        if not expr:
            self.engine_verdict[eid] = None
            self.drop("engine", name, "a custom engine with no expression in the tenant's answer")
            return None
        unknown: List[str] = []

        def sub(m: "re.Match") -> str:
            n = self.dictionary(m.group(1))
            if n is None:
                unknown.append(m.group(1))
                return m.group(0)
            return f"D:{n}"
        out_expr = _TERM_RE.sub(sub, expr)
        if unknown:
            self.engine_verdict[eid] = None
            self.drop("engine", name, f"its expression uses dictionary id(s) {', '.join(sorted(set(unknown)))}, which the tenant's "
                                      "dictionary list does not have, so they cannot be named")
            return None
        definition = {"name": name, "description": _strip_mark(e.get("description")), "expression": out_expr}
        self.engines[name] = definition
        self.engine_verdict[eid] = name
        return name

    # rules ------------------------------------------------------------
    def rule(self, r: Dict[str, Any], channel: str, *, sub_rule: bool = False) -> Optional[Dict[str, Any]]:
        name = str(r.get("name") or "").strip()
        if not name:
            return None
        action = r.get("action")
        if isinstance(action, dict):
            action = action.get("type")
        p: Dict[str, Any] = {"name": name}
        if not sub_rule:
            p["channel"] = channel
        p["description"] = _strip_mark(r.get("description"))
        p["action"] = str(action or pc.default_action(channel))
        p["state"] = str(r.get("state") or "ENABLED")
        if r.get("severity"):
            p["severity"] = r["severity"]
        if channel != pc.EMAIL and r.get("rank") is not None:
            try:
                p["rank"] = int(r["rank"])
            except (TypeError, ValueError):
                pass
        engines, used = [], []
        for ref in r.get("dlp_engines") or []:
            eid = str(ref if isinstance(ref, (int, str)) else _f(ref, "id"))
            n = self.engine(eid, str(_f(ref, "name") or "") if not isinstance(ref, (int, str)) else "")
            used.append(eid)
            if n:
                engines.append(n)
        if used and not engines:
            self.drop("rule", name, "none of its engines could be exported (see the engines listed here)", channel=channel)
            return None
        if len(engines) < len(used):
            self.drop("reference", name, "one or more of its engines could not be exported (see the engines listed here); the rule "
                                         "keeps the others", channel=channel, field="dlp_engines")
        if engines:
            p["engines"] = engines
        elif pc.has_engines(channel):
            self.warnings.append(f"{pc.label(channel)} rule '{name}' has no engines; Deploy Policy Packs will not create a rule that matches on nothing")
        for k in _PLAIN.get(channel, ()):
            v = r.get(k)
            if v not in (None, "", [], {}):
                p[k] = list(v) if isinstance(v, (list, tuple)) else v
        for k in _FLAGS.get(channel, ()):
            if r.get(k):
                p[k] = True
        taken = set(p) | set(_PLAIN.get(channel, ())) | set(_FLAGS.get(channel, ())) | {"dlp_engines"}
        if channel == pc.WEB and r.get("url_categories"):
            cats = [str(c) for c in r["url_categories"]]
            portable = [c for c in cats if not c.upper().startswith("CUSTOM_")]
            custom = [c for c in cats if c.upper().startswith("CUSTOM_")]
            if portable:
                p["url_categories"] = portable
            if custom:
                self.drop("reference", name, "custom URL categories exist only in the source tenant (their ids differ between tenants); "
                                             "the rule keeps the predefined categories", channel=channel, field="url_categories", values=custom)
            taken.add("url_categories")
        for field, pack_key in (("labels", "labels"),):
            if r.get(field):
                names, bare = _names(r[field])
                if names:
                    p[pack_key] = names
                if bare:
                    self.drop("reference", name, "rule labels the tenant answered without a name cannot be matched in another tenant",
                              channel=channel, field=field, values=bare)
                taken.add(field)
        tpl = r.get("notification_template")
        if tpl:
            names, bare = _names(tpl)
            if names:
                p["notification_template"] = names[0]
            else:
                self.drop("reference", name, "the notification template came back without a name, so it cannot be matched in another tenant",
                          channel=channel, field="notification_template", values=bare)
            taken.add("notification_template")
        if channel == pc.SAAS:
            p["saas_type"] = str(r.get("type") or r.get("rule_type") or "OFLCASB_DLP_FILE")
            tenants, bare = _names(r.get("cloud_app_tenants"))
            p["tenants"] = tenants or "any"
            if bare:
                self.drop("reference", name, "SaaS application tenants without a name cannot be matched in another tenant; the rule is "
                                             "scoped to any matching onboarded tenant instead", channel=channel, field="cloud_app_tenants", values=bare)
            taken.add("cloud_app_tenants")
        if channel == pc.EMAIL:
            tenants, bare = _names(r.get("email_tenants"))
            p["tenants"] = tenants or "any"
            if bare:
                self.drop("reference", name, "email tenants without a name cannot be matched in another tenant; the rule is scoped to "
                                             "any onboarded email tenant instead", channel=channel, field="email_tenants", values=bare)
            taken.add("email_tenants")
        if channel == pc.ENDPOINT:
            if r.get("eun_enabled") is not None:
                p["eun_enabled"] = bool(r["eun_enabled"])
            groups, bare = _names(r.get("end_point_application_groups") or r.get("endpoint_application_groups"))
            if groups:
                p["endpoint_application_groups"] = groups
                self.app_group_names.extend(g for g in groups if g not in self.app_group_names)
            if bare:
                self.drop("reference", name, "endpoint application groups without a name cannot be matched in another tenant",
                          channel=channel, field="end_point_application_groups", values=bare)
            taken |= {"eun_enabled", "end_point_application_groups", "endpoint_application_groups"}
            subs = []
            for sr in r.get("sub_rules") or []:
                c = self.rule(dict(_plain(sr), data_transfer_method=_f(sr, "data_transfer_method") or r.get("data_transfer_method")),
                              channel, sub_rule=True)
                if c:
                    subs.append(c)
            if subs:
                p["sub_rules"] = subs
        elif r.get("sub_rules"):
            self.drop("reference", name, "sub-rules (exceptions) travel in a pack for Endpoint DLP only; recreate them in the target tenant",
                      channel=channel, field="sub_rules", values=[str(_f(s, "name") or _f(s, "id")) for s in r["sub_rules"]])
        self._leftovers(r, channel, name, taken)
        return p

    def _leftovers(self, r: Dict[str, Any], channel: str, name: str, taken: set) -> None:
        """Every other field that is set: named in not_exported with the reason."""
        for k in sorted(r):
            v = r[k]
            if k in taken or k in _HOUSEKEEPING or v in (None, "", [], {}, False, 0):
                continue
            if k in _PRIVATE:
                self.drop("reference", name, "an external auditor's email address is not copied into a pack", channel=channel, field=k)
                continue
            if k in _TENANT_SCOPE:
                names, bare = _names(v)
                self.drop("reference", name, _SCOPE_REASON.format(what=_TENANT_SCOPE[k]), channel=channel, field=k, values=names + bare)
                continue
            self.drop("reference", name, _NOT_CARRIED, channel=channel, field=k)


def build_pack(snap: Dict[str, Any], *, selection: Any = None, name: str = "", tenant_label: str = "",
               app_groups: Optional[Dict[str, Dict[str, Any]]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The pack from a tenant read (read_tenant). Returns {"meta",
    "dictionaries", "engines", "policies", "app_groups", "not_exported",
    "warnings"}; meta is pack.json."""
    sel = normalize_selection(selection)
    b = _Builder(snap)
    policies: List[Dict[str, Any]] = []
    rule_order: Dict[str, List[str]] = {}
    renamed: List[Dict[str, str]] = []
    seen: set = set()
    missing_ids: List[str] = []
    for ch in pc.DLP_CHANNELS:
        if sel is not None and ch not in sel:
            continue
        want = None if sel is None else sel[ch]
        rules = snap["rules"].get(ch) or []
        if want is not None:
            have = {str(r.get("id")) for r in rules}
            missing_ids.extend(f"{pc.label(ch)} id {i}" for i in sorted(want - have))
        for r in rules:
            if want is not None and str(r.get("id")) not in want:
                continue
            p = b.rule(r, ch)
            if p is None:
                continue
            if p["name"] in seen:
                new = pc.fit_rule_name(p["name"], ch, f" [{pc.EXTENSION_SUFFIX[ch]}]")
                renamed.append({"channel": ch, "from": p["name"], "to": new})
                b.warnings.append(f"{pc.label(ch)} rule '{p['name']}' has the same name as a rule on another channel; in the pack it is '{new}'")
                p["name"] = new
            seen.add(p["name"])
            seen.update(s["name"] for s in p.get("sub_rules") or [])
            policies.append(p)
            rule_order.setdefault(ch, []).append(p["name"])
    for miss in missing_ids:
        b.drop("rule", miss, "picked for the export but not in the tenant's rule list any more")
    for ch, err in (snap.get("errors") or {}).items():
        if ch in pc.DLP_CHANNELS and (sel is None or ch in sel):
            b.drop("rule", f"every {pc.label(ch)} rule", f"the {pc.label(ch)} rules could not be read ({err})", channel=ch)
        elif ch in ("dictionaries", "engines"):
            b.warnings.append(f"The tenant's {ch} could not be read ({err}); rules that need them are listed under not_exported.")
    groups: List[Dict[str, Any]] = []
    known = app_groups or {}
    for g in b.app_group_names:
        if g in known and known[g].get("resources"):
            groups.append({"name": g, "description": _strip_mark(known[g].get("description")), "resources": list(known[g]["resources"])})
        else:
            b.drop("app_group", g, "an Endpoint DLP rule uses this application group but its applications could not be read; the target "
                                   "tenant needs a group of this name before the rule can be deployed")

    stamp = (now or datetime.now(timezone.utc)).replace(microsecond=0)
    label = tenant_label or "the tenant"
    dicts = list(b.dictionaries.values())
    by_channel = {ch: len(n) for ch, n in rule_order.items()}
    n_rules = sum(1 + len(p.get("sub_rules") or []) for p in policies)
    meta = {
        "name": (name or "").strip()[:120] or f"Exported from {label} {stamp.date().isoformat()}",
        "version": EXPORT_VERSION,
        "description": (f"Exported from {label} on {stamp.date().isoformat()}: {n_rules} DLP rule(s) "
                        f"({', '.join(f'{n} {pc.label(ch)}' for ch, n in by_channel.items()) or 'none'}) with the "
                        f"{len(b.engines)} custom engine(s) and {len(dicts)} dictionar{'y' if len(dicts) == 1 else 'ies'} they use."),
        "exported_from": label,
        "exported_at": stamp.isoformat().replace("+00:00", "Z"),
        "counts": {"rules": n_rules, "rules_by_channel": by_channel, "engines": len(b.engines), "dictionaries": len(dicts),
                   "clones": sum(1 for d in dicts if d.get("predefined_clone")), "app_groups": len(groups),
                   "not_exported": len(b.not_exported)},
        "deploy_note": f"Every rule arrives DISABLED: {DISABLED_NOTE} {ONE_CHANNEL_NOTE}",
        "rules_state_note": DISABLED_NOTE,
        "rule_order": rule_order,
        "predefined_dictionaries": sorted(set(b.predefined_dicts)),
        "predefined_engines": sorted(set(b.predefined_engines)),
        "not_exported": b.not_exported,
        "notes": [ORDER_NOTE,
                  "Predefined dictionaries and engines are named, not copied: every tenant has them, under ids that differ, and "
                  "Deploy Policy Packs finds them by name in the target tenant."],
    }
    if renamed:
        meta["renamed_rules"] = renamed
    return {"meta": meta, "dictionaries": dicts, "engines": list(b.engines.values()), "policies": policies,
            "app_groups": groups, "not_exported": b.not_exported, "warnings": b.warnings}


def export_pack(client, *, selection: Any = None, name: str = "", tenant_label: str = "", log: LogFn = None,
                cancel: Any = None) -> Dict[str, Any]:
    """Read the tenant and build the pack (see build_pack), with the pack
    library's own validation of the result. Read-only."""
    _log = log or (lambda m: None)
    sel = normalize_selection(selection)
    channels = pc.DLP_CHANNELS if sel is None else tuple(ch for ch in pc.DLP_CHANNELS if ch in sel)
    snap = read_tenant(client, channels, log=_log)
    if cancel is not None and cancel.is_set():
        return {"status": "stopped", "stopped": "You clicked Stop."}
    if snap["errors"].get("dictionaries") and snap["errors"].get("engines") and all(ch in snap["errors"] for ch in channels):
        return {"status": "error", "error": "Could not read the tenant: " + "; ".join(f"{k}: {v}" for k, v in snap["errors"].items())}
    pack = build_pack(snap, selection=sel, name=name, tenant_label=tenant_label)
    groups = None
    if any(p.get("endpoint_application_groups") for p in pack["policies"]):
        _log("Reading the tenant: endpoint application groups…")
        groups, err = pc.list_app_groups(client.zia)
        if err:
            _log(f"Reading the tenant: endpoint application groups could not be listed: {str(err)[:120]}")
        pack = build_pack(snap, selection=sel, name=name, tenant_label=tenant_label, app_groups=groups)
    import pack_library
    validation = pack_library.validate_pack(pack)
    c = pack["meta"]["counts"]
    _log(f"Pack built: {c['rules']} rule(s), {c['engines']} engine(s), {c['dictionaries']} dictionar{'y' if c['dictionaries'] == 1 else 'ies'}"
         f"; {c['not_exported']} item(s) could not be exported (listed in pack.json).")
    for w in pack["warnings"]:
        _log(f"Note: {w}")
    return {"status": "ready", "pack": pack, "validation": validation}


def pack_files(pack: Dict[str, Any]) -> Dict[str, str]:
    """The pack as files: pack.json and configs/dlp_*.json (plus the
    endpoint application groups when it has any)."""
    dump = lambda obj: json.dumps(obj, indent=2, ensure_ascii=False) + "\n"  # noqa: E731
    files = {"pack.json": dump(pack["meta"]),
             "configs/dlp_dictionaries.json": dump(pack["dictionaries"]),
             "configs/dlp_engines.json": dump(pack["engines"]),
             "configs/dlp_policies.json": dump(pack["policies"])}
    if pack.get("app_groups"):
        files["configs/endpoint_application_groups.json"] = dump(pack["app_groups"])
    return files


def zip_pack(pack: Dict[str, Any], folder: str = "") -> Tuple[str, bytes]:
    """(filename, zip bytes): one folder named after the pack."""
    from pack_library import slugify
    folder = folder or slugify(pack["meta"].get("name") or "") or "exported_pack"
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for path, text in pack_files(pack).items():
            z.writestr(f"{folder}/{path}", text)
    return f"{folder}.zip", buf.getvalue()
