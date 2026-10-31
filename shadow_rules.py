"""Shadowed and unreachable rules: rules that can never match, or never act.

Given each policy type's rules in evaluation order, `analyse` finds:

  shadowed         an earlier enabled rule with a terminal action matches
                   everything the later rule matches (every criterion is a
                   superset), so the later rule is never reached;
  after_catch_all  everything below an enabled rule with no criteria at all
                   (any / any) and a terminal action;
  duplicate        the same criteria and the same action as an earlier rule;
  superseded       (evaluate-all channels) whenever the rule matches, an
                   enabled rule that covers it matches too and its stricter
                   action wins, so this rule's action never applies;
  disabled         a disabled rule (information);
  missing_reference  a rule naming DLP engines or URL categories the tenant
                   no longer has (never acts when all of them are gone).

Each finding is {policy, policy_label, rule, rule_id, order, kind,
shadowed_by: {name, order} | None, reason (one plain sentence), severity,
fix}. `analyse` is pure: rules in, findings out, no tenant call.
`read_policies` is the tenant reader (only what is in scope, Stop honoured,
paced by the assessment client and zia_rate) and reuses ssl_flow's rule
reader and the data_flow / ssl_flow normalizers.

Never a false positive: a rule is only reported as shadowed when every
criterion either rule carries can be compared safely. A criterion this
module does not know, or knows but cannot compare with certainty, means
"not shadowed". The assumptions behind each comparison are stated where
the comparison is made.

How each policy type is evaluated (what the analysis assumes):

* URL filtering, SSL inspection, Cloud Firewall, Cloud App Control: top
  down by rule order, first match wins (ZIA's documented model; the
  Default rule is always last). Cloud App Control rules are ordered per
  application type, so they are compared only within one type, and a
  rule only covers another for the activities (actions) it names.
* Inline Web DLP: first match by rule order (the default, "By Rule
  Order"), unless the tenant runs "Evaluate All Rules" (DLP Advanced
  Settings, read from /zia/webDlpGlobalOptions enableEvaluateAllDlpRules
  as the SDK's web_dlp_global_options models it; the full probe the
  Evaluate-All migration uses lives in rule_migrator.assess_current_status
  / POST /api/migrate/status). Under Evaluate All every rule sees the
  transaction and the most restrictive action wins (Block > Confirm >
  Allow; the same action: the lower order wins), so position cannot shadow
  a rule; "superseded" is reported instead. Child rules (exceptions,
  parentRule) are first match among their siblings in both modes.
* Endpoint DLP evaluates all rules, the most restrictive action wins and
  a tie executes the lower order (static/reference/portfolio-map.html,
  Endpoint DLP card): superseded only, never shadowed.
* Outbound Email DLP is per recipient, most restrictive wins (ties are
  documented only loosely, "highest order breaks ties"): superseded only
  when strictly more restrictive.
* SaaS Security API DLP scans data at rest; its rule-order semantics are
  not documented in the reference this app follows, so it is checked only
  for disabled rules, duplicates and missing engines.
"""
from __future__ import annotations

import io
import json
import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import csv_safe

# ── Policy types ─────────────────────────────────────────────────────
# key -> label, the Scope section that puts it in scope (data_flow.
# PATH_SECTIONS keys, plus "firewall"), the endpoint, how it is evaluated.
POLICIES: Dict[str, Dict[str, str]] = {
    "web_dlp": {"label": "Inline Web DLP", "section": "dlp", "endpoint": "/zia/webDlpRules", "read_label": "Web DLP rules", "eval": "web_dlp"},
    "endpoint_dlp": {"label": "Endpoint DLP", "section": "endpoint", "endpoint": "/zia/endPointDlpRules", "read_label": "Endpoint DLP rules", "eval": "evaluate_all"},
    "email_dlp": {"label": "Outbound Email DLP", "section": "email", "endpoint": "/zia/emailDlpRules", "read_label": "Outbound Email DLP rules", "eval": "per_recipient"},
    "saas_dlp": {"label": "SaaS Security API DLP", "section": "saas", "endpoint": "/zia/casbDlpRules/all", "read_label": "SaaS Security API DLP rules", "eval": "unordered"},
    "url_filtering": {"label": "URL filtering", "section": "url", "endpoint": "/zia/urlFilteringRules", "read_label": "URL filtering rules", "eval": "first_match"},
    "cloud_app_control": {"label": "Cloud App Control", "section": "cac", "endpoint": "/zia/cloudApplicationRules", "read_label": "Cloud App Control rules", "eval": "first_match"},
    "ssl_inspection": {"label": "SSL inspection", "section": "ssl", "endpoint": "/zia/sslInspectionRules", "read_label": "SSL inspection rules", "eval": "first_match"},
    "firewall": {"label": "Cloud Firewall", "section": "firewall", "endpoint": "/zia/firewallFilteringRules", "read_label": "Cloud Firewall rules", "eval": "first_match"},
}
DLP_POLICIES = ("web_dlp", "endpoint_dlp", "email_dlp", "saas_dlp")
# Cloud Firewall is not a DLP channel and has no Scope page channel: it is
# read when ZIA platform is ticked.
FIREWALL_SCOPES = ("zia_extras",)

KINDS = ("shadowed", "after_catch_all", "duplicate", "superseded", "missing_reference", "disabled")
SEVERITIES = ("high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

NOTHING_IN_SCOPE = ("Nothing the shadowed-rule analysis reads is in scope: on the Scope page tick DLP (and mark the DLP channels, "
                    "SSL inspection and Cloud App Control as Zscaler) or ZIA platform, then run it again.")
STOPPED_REASON = ("You clicked Stop before the analysis finished, so it was abandoned: nothing more was read from the tenant "
                  "and no partial result is shown.")

MODE_RULE_ORDER, MODE_EVAL_ALL, MODE_UNKNOWN = "rule_order", "evaluate_all", "unknown"


class Stopped(RuntimeError):
    """The operator clicked Stop."""


# ── Field handling ───────────────────────────────────────────────────
def _canon(key: Any) -> str:
    """camelCase API keys and snake_case SDK keys compare the same."""
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


_ANY_TOKENS = {"ANY", "ALL", "ANY_RULE"}


def _empty(v: Any) -> bool:
    return v is None or v is False or v == 0 or v == "" or v == [] or v == {} or v == ()


def _token(x: Any) -> Optional[str]:
    if isinstance(x, dict):
        for k in ("id", "name", "val", "url"):
            if x.get(k) not in (None, ""):
                return str(x[k])
        return json.dumps(x, sort_keys=True, default=str)
    if x is None or x == "":
        return None
    return str(x)


# While analyse() runs, each criterion list is turned into its set of
# tokens once, not once per pair of rules compared (thousands of rules make
# millions of pairs). Per thread, so two analyses never share it.
_MEMO = threading.local()


def _tokens(v: Any) -> frozenset:
    """A list criterion as a set of ids (or names). 'ANY' style values
    are dropped: they mean the same as an empty list (everything)."""
    if v is None:
        return frozenset()
    cache = getattr(_MEMO, "tokens", None)
    if cache is not None and isinstance(v, list):
        hit = cache.get(id(v))
        if hit is not None and hit[0] is v:
            return hit[1]
        out = _tokens_of(v)
        cache[id(v)] = (v, out)   # the list is held, so its id is not reused while the cache lives
        return out
    return _tokens_of(v)


def _tokens_of(v: Any) -> frozenset:
    items = v if isinstance(v, (list, tuple, set, frozenset)) else [v]
    out = set()
    for x in items:
        t = _token(x)
        if t is not None and t.upper() not in _ANY_TOKENS:
            out.add(t)
    return frozenset(out)


def _number(v: Any) -> Optional[float]:
    if _empty(v):
        return 0.0
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _stable(v: Any) -> str:
    if isinstance(v, (list, tuple, set, frozenset)):
        return json.dumps(sorted(_tokens(v)))
    return json.dumps(v, sort_keys=True, default=str)


# Field specs. Each entry: (mode, [canonical field names]).
#   group   the fields together say WHO / WHERE / WHAT (users, groups and
#           departments; locations and location groups; URL categories and
#           cloud apps...). ZIA ANDs different criteria; whether it ANDs or
#           ORs the members of such a group is not stated everywhere, so the
#           comparison is safe under both readings: an earlier rule with no
#           value in the whole group covers everything; otherwise each
#           member must be a non-empty subset of the same member of the
#           earlier rule, and a member the earlier rule leaves empty must be
#           empty in the later one too. One field is the plain case: empty
#           (or "ANY") is a superset, else subset.
#   exact   empty in the earlier rule covers everything; otherwise the same
#           set (time windows: a window list is not assumed to be a union).
#   noany   empty does not mean "any" (Cloud App Control applications):
#           both empty, or a non-empty subset.
#   excl    an exclusion list: the earlier rule must exclude no more than
#           the later one (its exclusions a subset of the later's).
#   min     a minimum (size): the earlier rule's minimum is not higher.
#   widen   a switch that widens what a rule inspects (also GET requests,
#           also downloads): the earlier rule must not lack it when the
#           later one has it.
#   eq      must be equal (a type, a single profile, an unexplained switch).
#   flag    a switch whose effect on matching is not modelled (quotas,
#           time validity, CIPA, excluded source countries): set on either
#           rule, the pair is not compared (unless the rules are identical).
IDENT = [("group", ["users", "groups", "departments"]), ("excl", ["excludedusers"]), ("excl", ["excludedgroups"]),
         ("excl", ["excludeddepartments"])]
WHERE = [("group", ["locations", "locationgroups"])]
DEVICE = [("group", ["devices", "devicegroups"]), ("group", ["devicetrustlevels"])]
TIME = [("exact", ["timewindows"])]
CONTENT = [("content", ["dlpengines", "withoutcontentinspection"])]

SPECS: Dict[str, List[Tuple[str, List[str]]]] = {
    "web_dlp": IDENT + WHERE + DEVICE + TIME + CONTENT + [
        ("group", ["urlcategories", "cloudapplications"]), ("group", ["protocols"]), ("group", ["filetypes"]), ("min", ["minsize"]),
        ("group", ["userriskscorelevels"]), ("group", ["sourceipgroups"]), ("group", ["workloadgroups"]), ("group", ["zpaappsegments"]),
        ("group", ["includeddomainprofiles"]), ("excl", ["excludeddomainprofiles"]), ("exact", ["dlpcontentlocationsscopes"]),
        ("widen", ["inspecthttpgetenabled"]), ("widen", ["dlpdownloadscanenabled"]), ("widen", ["ocrenabled"]), ("eq", ["matchonly"]),
        ("eq", ["type"])],
    "endpoint_dlp": IDENT + DEVICE + TIME + CONTENT + [
        ("group", ["filetypes"]), ("min", ["minsize"]), ("group", ["userriskscorelevels"]), ("exact", ["datatransfermethod"]),
        ("exact", ["endpointapplications"]), ("exact", ["endpointapplicationgroups"]), ("eq", ["networktype"]), ("exact", ["ostype"]),
        ("eq", ["type"]), ("flag", ["deleted"])],
    "email_dlp": IDENT + TIME + CONTENT + [
        ("group", ["filetypes"]), ("min", ["minsize"]), ("group", ["userriskscorelevels"]), ("exact", ["emailrecipientprofiles"]),
        ("exact", ["emailtenants"]), ("group", ["includeddomainprofiles"]), ("excl", ["excludeddomainprofiles"]),
        ("exact", ["contentlocations"]), ("eq", ["customheader"])],
    "saas_dlp": [],   # not compared for coverage (see the module docstring)
    "url_filtering": IDENT + WHERE + DEVICE + TIME + [
        ("group", ["useragenttypes"]), ("group", ["sourceipgroups"]), ("group", ["workloadgroups"]), ("group", ["userriskscorelevels"]),
        ("group", ["urlcategories"]), ("group", ["protocols"]), ("group", ["requestmethods"]),
        ("flag", ["enforcetimevalidity"]), ("flag", ["ciparule"]), ("flag", ["sizequota"]), ("flag", ["timequota"])],
    "cloud_app_control": IDENT + WHERE + DEVICE + TIME + [
        ("group", ["useragenttypes"]), ("group", ["userriskscorelevels"]), ("noany", ["applications"]), ("eq", ["type"]),
        ("exact", ["cloudappinstances"]), ("exact", ["tenancyprofileids"]), ("eq", ["cloudappriskprofile"]),
        ("exact", ["sharingdomainprofiles"]), ("exact", ["formsharingdomainprofiles"]),
        ("flag", ["enforcetimevalidity"]), ("flag", ["sizequota"]), ("flag", ["timequota"])],
    "ssl_inspection": IDENT + WHERE + DEVICE + TIME + [
        ("group", ["platforms"]), ("group", ["useragenttypes"]), ("group", ["sourceipgroups"]), ("group", ["workloadgroups"]),
        ("group", ["zpaappsegments"]), ("group", ["proxygateways"]), ("group", ["urlcategories", "cloudapplications", "destipgroups"]),
        ("eq", ["roadwarriorforkerberos"]), ("eq", ["type"])],
    "firewall": IDENT + WHERE + DEVICE + TIME + [
        ("group", ["workloadgroups"]), ("group", ["zpaappsegments"]), ("group", ["srcips", "srcipgroups"]),
        ("group", ["sourcecountries"]), ("flag", ["excludesrccountries"]),
        ("group", ["destaddresses", "destipcategories", "destcountries", "destipgroups"]),
        ("group", ["nwservices", "nwservicegroups"]), ("group", ["nwapplications", "nwapplicationgroups"]),
        ("group", ["appservices", "appservicegroups"])],
}

# Fields that never change what a rule matches: identity, bookkeeping,
# the action and its settings, notifications and evidence routing. The
# action is compared separately.
_HARMLESS = {_canon(k) for k in (
    "id", "name", "order", "rank", "description", "state", "action", "actions", "labels", "last_modified_time", "last_modified_by",
    "modified_by", "modified_time", "access_control", "predefined", "default_rule", "severity", "eun_template_id", "eun_enabled",
    "browser_eun_template_id", "notification_template", "auditor", "icap_server", "external_auditor_email", "zscaler_incident_receiver",
    "zcc_notifications_enabled", "enable_full_logging", "end_user_notification_url", "block_override", "override_users",
    "override_groups", "cbi_profile", "cbi_profile_id",
    "cascading_enabled", "sub_rules", "parent_rule", "uc_template_id", "mod_u_id", "version", "versions", "threat_level_updated",
    # SSL inspection action settings that the SDK models beside the rule.
    "block_ssl_traffic_with_no_sni_enabled", "ocsp_check", "server_certificates", "default_certificate",
    "override_default_certificate", "block_undecrypt", "bypass_other_policies",
    # Cloud application catalogue fields the SDK models on the rule's apps.
    "val", "backend_name", "original_name", "deprecated", "misc", "app_not_ready", "app_cat_modified", "under_migration",
    "web_application_class",
)}


def _criteria(policy: str, raw: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(known criteria, unknown non-empty fields) of a raw rule, keyed canonically."""
    known_names = {f for _, fields in SPECS.get(policy, []) for f in fields}
    known: Dict[str, Any] = {}
    unknown: Dict[str, Any] = {}
    for k, v in (raw or {}).items():
        c = _canon(k)
        if c in _HARMLESS:
            continue
        if c in known_names:
            known[c] = v
        elif not _empty(v):
            unknown[c] = v
    return known, unknown


def _signature(rule: Dict[str, Any]) -> str:
    """Everything a rule matches on, for equality (duplicates)."""
    crit = {k: _stable(v) for k, v in rule["criteria"].items() if not _empty(v)}
    crit.update({k: _stable(v) for k, v in rule["unknown"].items()})
    return json.dumps(crit, sort_keys=True)


# ── Normalisation (reusing the data_flow / ssl_flow normalisers) ─────
def _int_order(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return 10 ** 9


def normalize(policy: str, raw: Dict[str, Any]) -> Dict[str, Any]:
    """A raw rule (camelCase API or snake_case SDK dict) → the shape the
    analysis uses: the common fields from the existing normalisers, plus
    every criterion by canonical name."""
    from ssl_flow import normalize_dlp_rule, normalize_ssl_rule, _action_type, _bool, _f
    from data_flow import _norm_generic
    if policy == "ssl_inspection":
        n = normalize_ssl_rule(raw)
        base = {"action": n["action"], "decision": n["decision"], "default_rule": n["default_rule"],
                # Zscaler's predefined exemption lists keep their targets out of the API.
                "hidden_criteria": n["zscaler_maintained"]}
    elif policy in DLP_POLICIES:
        n = normalize_dlp_rule(raw)
        base = {"action": n["action"], "engines": n["engines"], "without_content_inspection": n["without_content_inspection"],
                "parent_rule": _parent_id(n.get("parent_rule")), "default_rule": False, "hidden_criteria": False}
    else:
        n = _norm_generic(raw)
        base = {"action": n["action"] or _action_type(raw), "actions": n["actions"], "type": n["type"],
                "default_rule": _bool(_f(raw, "default_rule", "defaultRule", default=False)), "hidden_criteria": False}
    known, unknown = _criteria(policy, raw)
    rule = {"policy": policy, "id": raw.get("id"), "name": n["name"], "order": n.get("order"), "rank": _f(raw, "rank", default=None),
            "state": n["state"], "enabled": n["enabled"],
            "criteria": known, "unknown": unknown, "sub_rules": [_parent_id(x) for x in _as_list(_f(raw, "sub_rules", "subRules", default=[]))]}
    rule.update(base)
    rule.setdefault("parent_rule", None)
    rule["sig"] = _signature(rule)
    return rule


def _as_list(v: Any) -> List[Any]:
    """A list field of a raw rule; anything else (untrusted tenant JSON) is empty."""
    return list(v) if isinstance(v, (list, tuple)) else []


def _parent_id(v: Any) -> Optional[str]:
    if isinstance(v, dict):
        v = v.get("id") if v.get("id") is not None else v.get("name")
    return None if v in (None, "", 0) else str(v)


def _sort_key(rule: Dict[str, Any]) -> Tuple[int, int, str]:
    # The Default rule is always evaluated last, whatever its order says.
    return (1 if rule.get("default_rule") else 0, _int_order(rule.get("order")), str(rule.get("id") or ""))


def _rank_sort_key(rule: Dict[str, Any]) -> Tuple[Any, ...]:
    """Evaluation order with admin ranking on (admin_rank): the Default rule
    last, then admin rank (0 first), then rule order."""
    import admin_rank
    return admin_rank.key(lambda r: _sort_key(r)[1:], True, lambda r: bool(r.get("default_rule")))(rule)


# ── Coverage: does rule A match everything rule B matches? ───────────
def _group_covers(a: Dict[str, Any], b: Dict[str, Any], fields: Sequence[str]) -> bool:
    at = {f: _tokens(a.get(f)) for f in fields}
    bt = {f: _tokens(b.get(f)) for f in fields}
    if not any(at.values()):
        return True
    for f in fields:
        if not at[f]:
            if bt[f]:
                return False
        elif not bt[f] or not bt[f] <= at[f]:
            return False
    return True


def _content_covers(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """DLP content: a rule without content inspection matches any content.
    Engines are compared as equal sets only: whether ZIA fires a rule when
    any of its engines matches (then a superset would also cover) is not
    assumed, so only the same engines count as the same content."""
    wa, wb = bool(a.get("withoutcontentinspection")), bool(b.get("withoutcontentinspection"))
    if wa:
        return True
    if wb:
        return False
    ea, eb = _tokens(a.get("dlpengines")), _tokens(b.get("dlpengines"))
    return bool(ea) and ea == eb


def _field_covers(mode: str, fields: List[str], a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    if mode == "group":
        return _group_covers(a, b, fields)
    if mode == "content":
        return _content_covers(a, b)
    f = fields[0]
    va, vb = a.get(f), b.get(f)
    if mode == "exact":
        ta, tb = _tokens(va), _tokens(vb)
        return not ta or ta == tb
    if mode == "noany":
        ta, tb = _tokens(va), _tokens(vb)
        return (not ta and not tb) or (bool(ta) and bool(tb) and tb <= ta)
    if mode == "excl":
        return _tokens(va) <= _tokens(vb)
    if mode == "min":
        na, nb = _number(va), _number(vb)
        return na is not None and nb is not None and na <= nb
    if mode == "widen":
        return not (bool(vb) and not bool(va))
    if mode == "eq":
        return _stable(va if not _empty(va) else None) == _stable(vb if not _empty(vb) else None)
    if mode == "flag":
        return _empty(va) and _empty(vb)
    return False


def covers(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[bool, str]:
    """(True, "") when every transaction rule `b` matches is matched by
    rule `a` too, judged on criteria only (not state, order or action);
    (True, how) when that rests on Microsoft's published Microsoft 365
    endpoint list (_app_service_covers). (False, why) otherwise; why names
    the first criterion that is not covered or could not be compared."""
    if a["sig"] == b["sig"] and not a.get("hidden_criteria") and not b.get("hidden_criteria"):
        return True, ""   # the same criteria, whatever they mean
    if a.get("hidden_criteria") or b.get("hidden_criteria"):
        return False, "targets maintained by Zscaler are not exposed"
    if a["unknown"] or b["unknown"]:
        names = sorted(set(a["unknown"]) | set(b["unknown"]))
        return False, "cannot compare " + ", ".join(names)
    how = ""
    for mode, fields in SPECS.get(a["policy"], []):
        if not _field_covers(mode, fields, a["criteria"], b["criteria"]):
            if a["policy"] == "firewall" and fields == APP_SERVICE_FIELDS:
                ok, how = _app_service_covers(a, b)
                if ok:
                    continue
            return False, "/".join(fields)
    if not SPECS.get(a["policy"]):
        return False, "not compared for this policy type"
    return True, how


# ── App service groups (app_services): an earlier Cloud Firewall rule on
# a Microsoft 365 app service group (the Office 365 One Click rule) covers
# a later rule only when every destination the later rule names is a
# published Microsoft 365 endpoint on every port it allows, by a current
# list; the later rule's ports come from the network services read with
# the rules. Anything else: not covered (never a guess).
APP_SERVICE_FIELDS = ["appservices", "appservicegroups"]


def _app_list() -> Any:
    return getattr(_MEMO, "app_list", None)


def _app_rule(crit: Dict[str, Any]) -> Dict[str, Any]:
    return {"appServiceGroups": crit.get("appservicegroups") or [], "appServices": crit.get("appservices") or []}


def _m365_only(r: Dict[str, Any]) -> bool:
    """Every app service the rule names is a Microsoft 365 one (a current list is in use)."""
    import app_services
    named = app_services.named(_app_rule(r["criteria"]))
    return bool(named) and all(app_services.m365_areas(n) is not None for _, n in named)


def _ports_of(b: Dict[str, Any]) -> Optional[List[Tuple[str, int, int]]]:
    """[(tcp|udp, first, last)] the later rule's network services allow, or
    None when it names none (any port) or one whose ports were not read."""
    svc = getattr(_MEMO, "services", None)
    groups = getattr(_MEMO, "service_groups", None)
    if svc is None:
        return None
    tokens = set(_tokens(b["criteria"].get("nwservices")))
    for g in _tokens(b["criteria"].get("nwservicegroups")):
        if groups is None or g not in groups:
            return None
        tokens |= groups[g]
    if not tokens:
        return None
    out: List[Tuple[str, int, int]] = []
    for t in tokens:
        if t not in svc or not svc[t]:
            return None
        out += svc[t]
    return out


def _app_service_covers(a: Dict[str, Any], b: Dict[str, Any]) -> Tuple[bool, str]:
    import app_services
    bc = b["criteria"]
    if _tokens(bc.get("appservices")) or _tokens(bc.get("appservicegroups")):
        return False, "app services"
    if any(_tokens(bc.get(f)) for f in ("destipcategories", "destcountries", "destipgroups")):
        return False, "destination groups, categories or countries"
    dests = [str(_token(x) or "") for x in (bc.get("destaddresses") or []) if not isinstance(x, dict)]
    return app_services.covers(_app_rule(a["criteria"]), dests, _ports_of(b), _app_list())


def _service_index(services: Optional[Iterable[Any]], groups: Optional[Iterable[Any]]) -> None:
    """Network services by id and name -> their destination port ranges;
    groups -> their services' ids and names. Unread: None (no coverage)."""
    if services is None:
        _MEMO.services = _MEMO.service_groups = None
        return
    svc: Dict[str, List[Tuple[str, int, int]]] = {}
    for s in services:
        if not isinstance(s, dict):
            continue
        ranges: List[Tuple[str, int, int]] = []
        for proto, key in (("tcp", "destTcpPorts"), ("udp", "destUdpPorts")):
            for p in s.get(key) or s.get(re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower()) or []:
                lo = p.get("start") if isinstance(p, dict) else p
                hi = (p.get("end") if isinstance(p, dict) else None) or lo
                try:
                    lo, hi = int(lo), int(hi)
                except (TypeError, ValueError):
                    ranges = []
                    break
                ranges.append((proto, lo, hi))
        for k in ("id", "name"):
            if s.get(k) not in (None, ""):
                svc[str(s[k])] = ranges
    _MEMO.services = svc
    gi: Dict[str, set] = {}
    for g in groups or []:
        if isinstance(g, dict):
            members = {str(_token(x)) for x in g.get("services") or [] if _token(x) is not None}
            for k in ("id", "name"):
                if g.get(k) not in (None, ""):
                    gi[str(g[k])] = members
    _MEMO.service_groups = gi if groups is not None else None


def is_catch_all(a: Dict[str, Any], b: Optional[Dict[str, Any]] = None) -> bool:
    """Rule `a` has no criterion at all (any user, location, destination,
    time and content), so it matches every transaction of its policy type,
    whatever the later rule `b` carries (even criteria this module cannot
    compare: nothing is wider than everything). The few criteria that are
    not filters (a rule type, a switch that widens inspection) are still
    compared with `b`."""
    if a.get("hidden_criteria") or a["unknown"]:
        return False
    if a["policy"] == "cloud_app_control":
        return False   # an application list is always required; coverage is per activity
    crit = a["criteria"]
    if a["policy"] in DLP_POLICIES and not bool(crit.get("withoutcontentinspection")):
        return False   # with engines it matches only the content they find
    other = (b or {}).get("criteria") or {}
    for mode, fields in SPECS.get(a["policy"], []):
        if mode == "content":
            continue
        if mode in ("eq", "widen"):
            if b is None or not _field_covers(mode, fields, crit, other):
                return False
            continue
        if mode == "min":
            if (_number(crit.get(fields[0])) or 0) > 0:
                return False
            continue
        if any(_tokens(crit.get(f)) if mode != "flag" else not _empty(crit.get(f)) for f in fields):
            return False
    return bool(SPECS.get(a["policy"]))


# ── Actions ──────────────────────────────────────────────────────────
_TERMINAL = {
    "url_filtering": {"ALLOW", "BLOCK", "CAUTION", "ISOLATE"},
    "firewall": {"ALLOW", "BLOCK", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP"},   # EVAL_NWAPP hands over: not terminal
    "web_dlp": {"ALLOW", "BLOCK", "CONFIRM", "CAUTION", "ISOLATE"},
}
# How strict an action is, for "a stricter rule wins" (DLP evaluate-all)
# and for how bad a shadowed rule is. Unknown actions: None (no claim).
_STRICT = {"BLOCK": 3, "BLOCK_DROP": 3, "BLOCK_RESET": 3, "BLOCK_ICMP": 3, "DROP": 3, "DENY": 3,
           "CONFIRM": 2, "CAUTION": 2, "QUARANTINE": 2, "ISOLATE": 2, "DECRYPT": 2, "INSPECT": 2, "SSL_INSPECT": 2,
           "ALLOW": 1, "DO_NOT_DECRYPT": 1, "DO_NOT_INSPECT": 1, "SSL_DO_NOT_INSPECT": 1, "EXEMPT": 1, "BYPASS": 1}
# Under evaluate-all the documented order is Block > Confirm > Allow (and
# Block > Quarantine for email); only these are ranked there.
_DLP_STRICT = {"BLOCK": 3, "CONFIRM": 2, "QUARANTINE": 2, "ALLOW": 1}

_VERB = {"ALLOW": "allows", "BLOCK": "blocks", "BLOCK_DROP": "blocks (drop)", "BLOCK_RESET": "blocks (reset)", "BLOCK_ICMP": "blocks (ICMP)",
         "CAUTION": "shows a caution page", "CONFIRM": "asks the user to confirm", "ISOLATE": "isolates", "DECRYPT": "decrypts",
         "INSPECT": "decrypts", "SSL_INSPECT": "decrypts", "DO_NOT_DECRYPT": "leaves it encrypted", "DO_NOT_INSPECT": "leaves it encrypted",
         "SSL_DO_NOT_INSPECT": "leaves it encrypted", "BYPASS": "bypasses it", "QUARANTINE": "quarantines"}


def _activity(action: str) -> Optional[str]:
    m = re.match(r"^(ALLOW|BLOCK|CAUTION|ISOLATE|DENY|CONFIRM)_(.+)$", str(action or "").upper())
    return m.group(2) if m else None


def _activities(rule: Dict[str, Any]) -> Optional[Dict[str, str]]:
    """Cloud App Control: {activity: verb} from the rule's actions, or None
    when an action cannot be read (the rule is then not compared)."""
    acts = rule.get("actions") or []
    if not acts:
        return None
    out: Dict[str, str] = {}
    for a in acts:
        act = _activity(a)
        if act is None:
            return None
        out[act] = str(a).upper().split("_", 1)[0]
    return out


def _terminal(rule: Dict[str, Any]) -> bool:
    p = rule["policy"]
    if p == "ssl_inspection":
        return rule.get("decision") in ("inspected", "not_inspected", "blocked")
    if p == "cloud_app_control":
        return _activities(rule) is not None
    return rule.get("action") in _TERMINAL.get(p, set())


def _verb(rule: Dict[str, Any]) -> str:
    if rule["policy"] == "cloud_app_control":
        acts = _activities(rule) or {}
        return "decides " + ", ".join(sorted(a.lower().replace("_", " ") for a in acts)) if acts else "acts"
    a = rule.get("action") or ""
    return _VERB.get(a, f"applies {a.lower().replace('_', ' ')}" if a else "acts")


def _cac_covers_actions(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    """Cloud App Control: the earlier rule decides every activity the later
    one names (rules are assumed to be first match per application and
    activity; an activity the earlier rule does not name may still reach
    the later one)."""
    aa, bb = _activities(a), _activities(b)
    return aa is not None and bb is not None and set(bb) <= set(aa)


def _severity(winner: Dict[str, Any], lost: Dict[str, Any]) -> str:
    """How bad it is that `lost` never applies because of `winner`: the
    later rule was stricter (its control never happens) is high; a
    different, laxer action is medium; the same action is low (dead
    weight)."""
    if lost["policy"] == "cloud_app_control":
        wa, la = _activities(winner) or {}, _activities(lost) or {}
        rank = {"BLOCK": 3, "DENY": 3, "CAUTION": 2, "ISOLATE": 2, "CONFIRM": 2, "ALLOW": 1}
        diffs = [(rank.get(la[k], 0), rank.get(wa.get(k, ""), 0)) for k in la]
        if any(l > w for l, w in diffs):
            return "high"
        return "low" if all(la[k] == wa.get(k) for k in la) else "medium"
    if winner.get("action") == lost.get("action"):
        return "low"
    sw, sl = _STRICT.get(winner.get("action") or ""), _STRICT.get(lost.get("action") or "")
    if sw is not None and sl is not None and sl > sw:
        return "high"
    return "medium"


# ── Findings ─────────────────────────────────────────────────────────
def _ref(rule: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": rule["name"], "order": rule.get("order"), "id": rule.get("id")}


def _finding(rule: Dict[str, Any], kind: str, severity: str, reason: str, fix: str,
             by: Optional[Dict[str, Any]] = None, ranked: bool = False, **extra) -> Dict[str, Any]:
    import admin_rank
    f = {"policy": rule["policy"], "policy_label": POLICIES[rule["policy"]]["label"], "rule": rule["name"], "rule_id": rule.get("id"),
         "order": rule.get("order"), "kind": kind, "shadowed_by": {"name": by["name"], "order": by.get("order")} if by else None,
         "reason": reason, "severity": severity, "fix": fix}
    if ranked:
        # Admin ranking is on: the rank decides before the order (admin_rank).
        f["rank"] = admin_rank.shown_rank(rule)
        if f["shadowed_by"] is not None:
            f["shadowed_by"]["rank"] = admin_rank.shown_rank(by)
    f.update(extra)
    return f


def _o(rule: Dict[str, Any], ranked: bool = False) -> str:
    import admin_rank
    o = f"order {rule.get('order')}" if rule.get("order") not in (None, "") else "no order"
    if ranked:
        rk = admin_rank.shown_rank(rule)
        return (f"rank {rk}" if rk is not None else f"no rank, taken as {admin_rank.DEFAULT_RANK}") + ", " + o
    return o


_finding_ranked, _o_ranked = _finding, _o


class _CoverIndex:
    """For a rule B, the rules that can cover it at all (covers() or
    is_catch_all() may be true), in their order. Thousands of rules then
    cost a comparison per plausible pair, not per pair (n²).

    Each criterion group (a "group" or "noany" spec, and the DLP content)
    is a dimension. On a dimension, a rule A can only cover B when A leaves
    the whole group empty (it is "wild" there) or A shares a token with B
    in that group: a non-empty member of A must hold every token of the same
    member of B, which must not be empty. covers() needs every dimension to
    hold, so the candidates of any one dimension are a superset of the
    rules that cover B; the smallest one is used. Rules with the same
    criteria (sig) are always candidates (covers() accepts them whatever
    the criteria mean). The DLP content dimension: a rule without content
    inspection is wild; otherwise only the same non-empty engines can
    cover (_content_covers); B without content inspection is covered only
    by a wild rule."""

    def __init__(self, rules: List[Dict[str, Any]]):
        self.pos = {id(r): k for k, r in enumerate(rules)}
        self.by_sig: Dict[str, List[Dict[str, Any]]] = {}
        for r in rules:
            self.by_sig.setdefault(r["sig"], []).append(r)
        policy = rules[0]["policy"] if rules else ""
        self.dims: List[Tuple[Callable[[Dict[str, Any]], List[Any]], List[Dict[str, Any]], Dict[Any, List[Dict[str, Any]]]]] = []
        m365 = policy == "firewall" and _app_list() is not None and not _app_list().stale()
        for mode, fields in SPECS.get(policy, []):
            if m365 and fields == APP_SERVICE_FIELDS:
                # A rule on Microsoft 365 app services may cover a rule
                # without them (_app_service_covers): wild on this dimension.
                self._dim(rules, lambda r, fs=tuple(fields): [] if _m365_only(r) else [(f, t) for f in fs for t in _tokens(r["criteria"].get(f))])
            elif mode in ("group", "noany"):
                self._dim(rules, lambda r, fs=tuple(fields): [(f, t) for f in fs for t in _tokens(r["criteria"].get(f))])
        if policy in DLP_POLICIES:
            self._dim(rules, _content_keys, wild=lambda r: bool(r["criteria"].get("withoutcontentinspection")))
        self.complete = bool(self.dims)

    def _dim(self, rules, keys, wild=None) -> None:
        wild_rules: List[Dict[str, Any]] = []
        posting: Dict[Any, List[Dict[str, Any]]] = {}
        for r in rules:
            ks = keys(r)
            if (wild(r) if wild else not ks):
                wild_rules.append(r)
            else:
                for k in ks:
                    posting.setdefault(k, []).append(r)
        self.dims.append((keys, wild_rules, posting))

    def candidates(self, b: Dict[str, Any], before: bool = False) -> List[Dict[str, Any]]:
        """The rules that may cover `b` (only those above it with `before`)."""
        best = None
        for keys, wild_rules, posting in self.dims:
            lists = [wild_rules] + [posting.get(k, ()) for k in keys(b)]
            size = sum(len(x) for x in lists)
            if best is None or size < best[0]:
                best = (size, lists)
        pool: Dict[int, Dict[str, Any]] = {}
        for lst in (best[1] if best else []):
            pool.update((id(a), a) for a in lst)
        pool.update((id(a), a) for a in self.by_sig.get(b["sig"], ()))
        limit = self.pos.get(id(b), len(self.pos)) if before else None
        return sorted((a for a in pool.values() if a is not b and (limit is None or self.pos[id(a)] < limit)),
                      key=lambda a: self.pos[id(a)])


def _content_candidates(live: List[Dict[str, Any]]) -> Callable[[Dict[str, Any]], List[Dict[str, Any]]]:
    """For a rule b under evaluate-all, the rules that can cover it at all,
    in their order (_CoverIndex; every rule when the policy has no
    dimension to index on)."""
    index = _CoverIndex(live)
    if not index.complete:
        return lambda b: list(live)
    return index.candidates


def _content_keys(r: Dict[str, Any]) -> List[Any]:
    """The DLP content dimension's key: the rule's engines when it inspects content."""
    if r["criteria"].get("withoutcontentinspection"):
        return []
    eng = _tokens(r["criteria"].get("dlpengines"))
    return [eng] if eng else []


def _first_match(rules: List[Dict[str, Any]], mode_note: str = "", ranked: bool = False) -> List[Dict[str, Any]]:
    """Rules evaluated top down, first match wins: each enabled rule below
    an enabled terminal rule that covers it is reported once, against the
    first such rule. Only the rules above it that can cover it at all
    (_CoverIndex) are compared. `rules` are in evaluation order; `ranked`:
    that order is admin rank first (admin ranking on), and the sentences
    name the rank."""
    out: List[Dict[str, Any]] = []
    above_it = "evaluated before it (admin rank first, then rule order)" if ranked else "above it"

    def _o(r: Dict[str, Any]) -> str:
        return _o_ranked(r, ranked)

    def _finding(*a: Any, **k: Any) -> Dict[str, Any]:
        return _finding_ranked(*a, ranked=ranked, **k)
    live = [r for r in rules if r["enabled"]]
    index = _CoverIndex(live)
    for b in live:
        if b.get("default_rule"):
            # The Default rule is the fallback and cannot be removed or moved.
            continue
        above = index.candidates(b, before=True) if index.complete else live[:index.pos[id(b)]]
        for a in above:
            if not _terminal(a):
                continue
            if b["policy"] == "cloud_app_control" and not _cac_covers_actions(a, b):
                continue
            if is_catch_all(a, b):
                sev = _severity(a, b)
                out.append(_finding(b, "after_catch_all", sev,
                                    f"Rule '{b['name']}' can never match: rule '{a['name']}' ({_o(a)}) {above_it} matches all traffic and {_verb(a)}{mode_note}.",
                                    f"Move the rules that should apply above the catch-all rule '{a['name']}' and keep it last, or delete '{b['name']}'.", a))
                break
            ok, how = covers(a, b)
            if not ok:
                continue
            via = f": {how}" if how else ""
            same_action = (a.get("action") == b.get("action")) if b["policy"] != "cloud_app_control" else (_activities(a) == _activities(b))
            if a["sig"] == b["sig"] and same_action:
                out.append(_finding(b, "duplicate", "low",
                                    f"Rule '{b['name']}' can never match: rule '{a['name']}' ({_o(a)}) {above_it} has the same criteria and the same action{mode_note}.",
                                    f"Delete '{b['name']}'; '{a['name']}' already does the same thing.", a))
            else:
                out.append(_finding(b, "shadowed", _severity(a, b),
                                    f"Rule '{b['name']}' can never match: rule '{a['name']}' ({_o(a)}) {above_it} matches everything it does and {_verb(a)}{mode_note}{via}.",
                                    f"Move '{b['name']}' above '{a['name']}' if it should apply, narrow '{a['name']}' so it no longer covers it, or delete '{b['name']}'.", a,
                                    **({"via": how} if how else {})))
            break
    return out


def _superseded(rules: List[Dict[str, Any]], *, ties: bool, mode_label: str) -> List[Dict[str, Any]]:
    """Evaluate-all: every rule sees the transaction and the strictest
    action wins (`ties`: the same action, the lower order wins). A rule B
    whose every match is also matched by a rule A whose action beats it
    never decides the outcome. Rules with child exceptions are left out:
    a matching child replaces its parent's action in the same pass."""
    out: List[Dict[str, Any]] = []
    live = [r for r in rules if r["enabled"] and not r["sub_rules"]]
    candidates = _content_candidates(live)
    for b in live:
        sb = _DLP_STRICT.get(b.get("action") or "")
        if sb is None:
            continue
        best = None
        for a in candidates(b):
            if a is b:
                continue
            sa = _DLP_STRICT.get(a.get("action") or "")
            if sa is None:
                continue
            stricter = sa > sb
            tie = ties and sa == sb and _sort_key(a) < _sort_key(b)
            if not (stricter or tie):
                continue
            ok, _ = covers(a, b)
            if ok and (best is None or _sort_key(a) < _sort_key(best)):
                best = a
        if best is None:
            continue
        a = best
        if a["sig"] == b["sig"] and a.get("action") == b.get("action"):
            out.append(_finding(b, "duplicate", "low",
                                f"Rule '{b['name']}' never decides the outcome: rule '{a['name']}' ({_o(a)}) has the same criteria and the same action and wins on its lower order under {mode_label}.",
                                f"Delete '{b['name']}'; '{a['name']}' already does the same thing.", a))
        elif (_DLP_STRICT.get(a.get("action") or "") or 0) > sb:
            out.append(_finding(b, "superseded", "low",
                                f"Rule '{b['name']}' never decides the outcome: whenever it matches, rule '{a['name']}' ({_o(a)}) matches too and its stricter action ({a['action'].lower()}) wins under {mode_label}.",
                                f"Delete '{b['name']}' or narrow '{a['name']}'; under {mode_label} moving a rule does not change which one wins, only its criteria and action do.", a))
        else:
            out.append(_finding(b, "superseded", "low",
                                f"Rule '{b['name']}' never decides the outcome: whenever it matches, rule '{a['name']}' ({_o(a)}) matches too with the same action and wins on its lower order under {mode_label}.",
                                f"Delete '{b['name']}' or narrow '{a['name']}' so each rule has a job of its own.", a))
    return out


def _duplicates_only(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for r in rules:
        if not r["enabled"]:
            continue
        key = (r["sig"], r.get("action") or "")
        a = seen.get(key)
        if a is None:
            seen[key] = r
            continue
        out.append(_finding(r, "duplicate", "low",
                            f"Rule '{r['name']}' repeats rule '{a['name']}' ({_o(a)}): the same criteria and the same action.",
                            f"Delete '{r['name']}'; '{a['name']}' already does the same thing.", a))
    return out


def _missing_refs(rules: List[Dict[str, Any]], engines: Optional[Dict[str, str]], categories: Optional[set]) -> List[Dict[str, Any]]:
    """Rules naming DLP engines or URL categories the tenant no longer has.
    Only when that list was read completely (else None: nothing claimed)."""
    out: List[Dict[str, Any]] = []
    for r in rules:
        if not r["enabled"]:
            continue
        crit = r["criteria"]
        if engines is not None and r["policy"] in DLP_POLICIES:
            refs = _ref_items(crit.get("dlpengines"))
            gone = [label for key, label in refs if key not in engines]
            if refs and gone:
                if len(gone) == len(refs) and not crit.get("withoutcontentinspection"):
                    out.append(_finding(r, "missing_reference", "high",
                                        f"Rule '{r['name']}' can never act: none of its DLP engines ({', '.join(gone)}) exist in the tenant any more.",
                                        f"Point '{r['name']}' at engines that exist, or delete it.", None, missing=gone))
                else:
                    out.append(_finding(r, "missing_reference", "medium",
                                        f"Rule '{r['name']}' names DLP engines that no longer exist ({', '.join(gone)}), so it matches less than it was built for.",
                                        f"Replace the missing engines on '{r['name']}' or remove them from it.", None, missing=gone))
        if categories is not None and r["policy"] in ("url_filtering", "ssl_inspection", "web_dlp"):
            refs = [(k, l) for k, l in _ref_items(crit.get("urlcategories")) if k.upper() not in _ANY_TOKENS | {"NONE"}]
            gone = [label for key, label in refs if key not in categories and label not in categories]
            if refs and gone:
                others = any(_tokens(crit.get(f)) for f in ("cloudapplications", "destipgroups"))
                if len(gone) == len(refs) and not others:
                    out.append(_finding(r, "missing_reference", "high",
                                        f"Rule '{r['name']}' can never match: none of its URL categories ({', '.join(gone)}) exist in the tenant any more.",
                                        f"Point '{r['name']}' at categories that exist, or delete it.", None, missing=gone))
                else:
                    out.append(_finding(r, "missing_reference", "medium",
                                        f"Rule '{r['name']}' names URL categories that no longer exist ({', '.join(gone)}), so it matches less than it was built for.",
                                        f"Replace the missing categories on '{r['name']}' or remove them from it.", None, missing=gone))
    return out


def _ref_items(v: Any) -> List[Tuple[str, str]]:
    out = []
    for x in (v or []) if isinstance(v, (list, tuple)) else ([v] if v not in (None, "") else []):
        key = _token(x)
        if key is None:
            continue
        label = str(x.get("name") or key) if isinstance(x, dict) else key
        out.append((key, label))
    return out


def _disabled(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [_finding(r, "disabled", "info", f"Rule '{r['name']}' is disabled, so it never matches.",
                     f"Enable '{r['name']}' if it is still wanted, otherwise delete it so the policy stays readable.")
            for r in rules if not r["enabled"]]


def _web_dlp_note(mode: str) -> Tuple[str, str]:
    """(suffix for each shadowing sentence, a note for the result)."""
    if mode == MODE_RULE_ORDER:
        return "", "Inline Web DLP runs By Rule Order: the first matching rule decides, so a rule below a covering rule is never reached."
    if mode == MODE_EVAL_ALL:
        return "", ("Inline Web DLP runs Evaluate All Rules: every rule sees the transaction and the most restrictive action wins, so a rule "
                    "cannot be shadowed by its position; rules whose action never wins are reported as superseded instead.")
    return (" (if the tenant evaluates Inline Web DLP By Rule Order, the default; the mode could not be read)",
            "The Inline Web DLP evaluation mode could not be read, so rule order (the default) is assumed; if the tenant runs Evaluate All "
            "Rules, choose it under Evaluation mode and run the analysis again.")


def _ranked_first_match(policy: str, rules: List[Dict[str, Any]], mode_note: str, setting: Any) -> List[Dict[str, Any]]:
    """First-match findings in the order ZIA evaluates `rules` (admin_rank):
    a rule is only shadowed by a rule evaluated before it. Admin ranking on:
    admin rank first, then rule order. Off: rule order. Not known (not read,
    not in scope, or `setting` None): rule order, and a finding that holds
    in only one of the two orders says so (never asserted)."""
    import admin_rank
    st = admin_rank.state_of(setting)
    if policy not in admin_rank.RANKED or st == admin_rank.OFF:
        return _first_match(rules, mode_note)
    by_rank = sorted(rules, key=_rank_sort_key)
    if st == admin_rank.ON:
        return _first_match(by_rank, mode_note, ranked=True)
    plain = _first_match(rules, mode_note)
    if [id(r) for r in by_rank] == [id(r) for r in rules]:
        return plain
    ranked = _first_match(by_rank, mode_note)
    key = lambda f: (str(f.get("rule_id")), f["rule"], f["kind"])  # noqa: E731
    in_plain, in_rank = {key(f) for f in plain}, {key(f) for f in ranked}
    by_id = {str(r.get("id")): r for r in rules}
    why = (setting or {}).get("why") if isinstance(setting, dict) else ""
    head = ("Admin ranking was not read" if st == admin_rank.OUT_OF_SCOPE else "Admin ranking could not be read") + (f" ({why})" if why else "")

    def caution(f: Dict[str, Any], holds_when: str) -> Dict[str, Any]:
        f = dict(f)
        b = by_id.get(str(f.get("rule_id"))) or {}
        a = next((r for r in rules if r["name"] == (f.get("shadowed_by") or {}).get("name")), {})
        rel = "after" if holds_when == "off" else "before"
        text = (f"{head}: this holds only if admin ranking is {holds_when}. With it on, rule '{a.get('name')}' ({_o(a, True)}) is evaluated {rel} "
                f"'{b.get('name', f['rule'])}' ({_o(b, True)}).")
        f["admin_rank"] = "depends"
        f["admin_rank_caution"] = text
        f["reason"] = f"{f['reason']} {text}"
        return f
    return [f if key(f) in in_rank else caution(f, "off") for f in plain] + [caution(f, "on") for f in ranked if key(f) not in in_plain]


def _rank_note(setting: Any, policy: str, found: List[Dict[str, Any]]) -> str:
    """The note on how admin ranking was taken for a ranked policy: when it
    is on, and when it is not known and a finding depends on it."""
    import admin_rank
    st = admin_rank.state_of(setting)
    if policy not in admin_rank.RANKED or POLICIES[policy]["eval"] not in ("first_match", "web_dlp"):
        return ""
    if st == admin_rank.ON:
        return " Admin ranking is on, so a rule is compared only with the rules evaluated before it by admin rank first, then rule order."
    if st == admin_rank.OFF or not any(f.get("admin_rank") == "depends" for f in found):
        return ""
    return (" Admin ranking " + ("was not read" if st == admin_rank.OUT_OF_SCOPE else "could not be read")
            + ", so rule order is used; a finding that depends on it says so.")


_UNSET = object()


def analyse(rules_by_policy: Dict[str, List[Dict[str, Any]]], *, web_dlp_mode: str = MODE_UNKNOWN,
            engines: Optional[Iterable[Any]] = None, categories: Optional[Iterable[Any]] = None,
            admin_ranking: Any = None, app_list: Any = _UNSET, network_services: Optional[Iterable[Any]] = None,
            network_service_groups: Optional[Iterable[Any]] = None) -> Dict[str, Any]:
    """Pure: raw rules per policy key (POLICIES) → {findings, counts_by_policy,
    notes}. `engines` / `categories`: the tenant's DLP engines and URL
    categories (dicts or ids) when they were read completely, else None
    (no missing-reference claim). `admin_ranking`: the admin ranking
    setting (admin_rank.read), None when it was not read. `app_list`:
    Microsoft's Microsoft 365 endpoint list (app_services.current(); left
    out: the one kept on disk) and the Cloud Firewall's network services
    and groups, for rules on Microsoft 365 app service groups. Never reads
    a tenant."""
    if app_list is _UNSET:
        import app_services
        app_list = app_services.current()
    _MEMO.tokens = {}
    _MEMO.app_list = app_list
    _service_index(network_services, network_service_groups)
    try:
        res = _analyse(rules_by_policy, web_dlp_mode, engines, categories, admin_ranking)
        if any(f.get("via") for f in res["findings"]) and app_list is not None:
            res["notes"]["firewall"] = (res["notes"].get("firewall", "") + " Rules on Microsoft 365 app service groups are compared with "
                                        f"Microsoft's published endpoint list ({app_list.describe()}).").strip()
        return res
    finally:
        _MEMO.tokens = None
        _MEMO.app_list = None
        _MEMO.services = _MEMO.service_groups = None


def _analyse(rules_by_policy: Dict[str, List[Dict[str, Any]]], web_dlp_mode: str, engines: Optional[Iterable[Any]],
             categories: Optional[Iterable[Any]], admin_ranking: Any = None) -> Dict[str, Any]:
    eng = _lookup(engines) if engines is not None else None
    cats = set(_lookup(categories).keys()) if categories is not None else None
    findings: List[Dict[str, Any]] = []
    counts: Dict[str, Dict[str, Any]] = {}
    notes: Dict[str, str] = {}
    for policy, raw_rules in rules_by_policy.items():
        if policy not in POLICIES or raw_rules is None:
            continue
        rules = sorted((normalize(policy, r) for r in raw_rules if isinstance(r, dict)), key=_sort_key)
        found: List[Dict[str, Any]] = _disabled(rules) + _missing_refs(rules, eng, cats)
        ev = POLICIES[policy]["eval"]
        top = [r for r in rules if not r["parent_rule"]]
        children: Dict[str, List[Dict[str, Any]]] = {}
        for r in rules:
            if r["parent_rule"]:
                children.setdefault(r["parent_rule"], []).append(r)
        if policy == "cloud_app_control":
            by_type: Dict[str, List[Dict[str, Any]]] = {}
            for r in top:
                by_type.setdefault(r.get("type") or "", []).append(r)
            for group in by_type.values():
                found += _ranked_first_match(policy, group, "", admin_ranking)
            notes[policy] = "Cloud App Control rules are ordered per application type; a rule covers another only for the activities it names."
        elif ev == "first_match":
            found += _ranked_first_match(policy, top, "", admin_ranking)
        elif ev == "web_dlp":
            suffix, notes[policy] = _web_dlp_note(web_dlp_mode)
            if web_dlp_mode == MODE_EVAL_ALL:
                found += _superseded(top, ties=True, mode_label="Evaluate All Rules")
            else:
                found += _ranked_first_match(policy, top, suffix, admin_ranking)
        elif ev == "evaluate_all":
            notes[policy] = ("Endpoint DLP evaluates every rule and the most restrictive action wins (a tie runs the lower order), so no rule "
                             "is shadowed by its position; rules whose action never wins are reported as superseded.")
            found += _superseded(top, ties=True, mode_label="Endpoint DLP's evaluate-all model")
        elif ev == "per_recipient":
            notes[policy] = ("Outbound Email DLP is decided per recipient and the most restrictive rule wins, so no rule is shadowed by its "
                             "position; a rule is reported as superseded only when a stricter rule always matches with it.")
            found += _superseded(top, ties=False, mode_label="Email DLP's most-restrictive model")
        else:
            notes[policy] = ("SaaS Security API DLP rules scan data at rest and their order semantics are not documented here, so only "
                             "disabled rules, duplicates and missing engines are reported.")
            found += _duplicates_only(top)
        # Child rules (exceptions) are first match among their siblings.
        for kids in children.values():
            found += _ranked_first_match(policy, sorted(kids, key=_sort_key), "", admin_ranking)
        found = _dedupe(found)
        rn = "" if policy == "web_dlp" and web_dlp_mode == MODE_EVAL_ALL else _rank_note(admin_ranking, policy, found)
        if rn:
            notes[policy] = (notes.get(policy, "") + rn).strip()
        findings += found
        by_kind = {k: sum(1 for f in found if f["kind"] == k) for k in KINDS}
        by_sev = {s: sum(1 for f in found if f["severity"] == s) for s in SEVERITIES}
        uncomparable = sorted({k for r in rules for k in r["unknown"]})
        counts[policy] = {"label": POLICIES[policy]["label"], "rules": len(rules), "enabled": sum(1 for r in rules if r["enabled"]),
                          "findings": len(found), "by_kind": by_kind, "by_severity": by_sev, "fields_not_compared": uncomparable}
    findings.sort(key=lambda f: (list(POLICIES).index(f["policy"]), _SEV_RANK.get(f["severity"], 9), _int_order(f.get("order")), f["rule"]))
    return {"findings": findings, "counts_by_policy": counts, "notes": notes}


def _dedupe(found: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """One finding per rule and kind (a rule can be both disabled and miss an engine)."""
    out, seen = [], set()
    for f in found:
        key = (f["policy"], f.get("rule_id"), f["rule"], f["kind"])
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def _lookup(items: Iterable[Any]) -> Dict[str, str]:
    """{id or name: name} of a tenant object list (dicts, or bare ids)."""
    out: Dict[str, str] = {}
    for x in items or []:
        if isinstance(x, dict):
            name = str(x.get("name") or x.get("configuredName") or x.get("configured_name") or x.get("id") or "")
            for k in ("id", "name", "configuredName", "configured_name"):
                if x.get(k) not in (None, ""):
                    out[str(x[k])] = name
        elif x not in (None, ""):
            out[str(x)] = str(x)
    return out


def index_by_rule(findings: Iterable[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    """{(policy, rule name): [finding, ...]} for showing a rule's findings
    where the rule is shown (the browser extension's console overlay)."""
    out: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    for f in findings or []:
        if isinstance(f, dict) and f.get("policy") and f.get("rule") is not None:
            out.setdefault((str(f["policy"]), str(f["rule"])), []).append(f)
    return out


# ── What is in scope ─────────────────────────────────────────────────
def scope_for(scopes: Any, channels: Any) -> Dict[str, Any]:
    """The policy types the Scope page's selection lets this analysis read:
    data_flow.path_scope for the ZIA and DLP sections, plus Cloud Firewall
    when ZIA platform is ticked. {read: [policy keys], not_in_scope:
    {policy: why}, read_blocked: {policy: why}, summary}. Pure."""
    import data_flow
    ps = data_flow.path_scope(scopes, channels)
    sc = set(ps["scopes"])
    read: List[str] = []
    nis: Dict[str, str] = {}
    blocked: Dict[str, str] = {}
    for key, p in POLICIES.items():
        sec = p["section"]
        if sec == "firewall":
            if any(s in sc for s in FIREWALL_SCOPES):
                read.append(key)
            else:
                nis[key] = "Not in scope: ZIA platform is not ticked on the Scope page, so the Cloud Firewall rules were not read."
            continue
        if sec in ps["read"]:
            read.append(key)
        elif sec in (ps.get("read_blocked") or {}):
            blocked[key] = ps["read_blocked"][sec]
        else:
            nis[key] = ps["not_in_scope"].get(sec) or "Not in scope on the Scope page, so it was not read."
    summary = ("Reads only what is in scope on the Scope page: " + ", ".join(POLICIES[k]["label"] + " rules" for k in read) + "."
               if read else NOTHING_IN_SCOPE)
    return {"scopes": ps["scopes"], "read": read, "not_in_scope": nis, "read_blocked": blocked, "summary": summary}


# ── Tenant reader ────────────────────────────────────────────────────
def read_web_dlp_mode(client) -> Tuple[str, str]:
    """(mode, detail) from DLP Advanced Settings: /zia/webDlpGlobalOptions
    enableEvaluateAllDlpRules (zscaler-sdk-python web_dlp_global_options).
    One request; anything else is "unknown" (the Evaluate-All wizard's
    /api/migrate/status probes every older candidate endpoint)."""
    from rule_migrator import _is_truthy
    try:
        data, code = client.get("/zia/webDlpGlobalOptions")
    except Exception as e:  # noqa: BLE001 — an unreadable setting is "unknown", never a guess
        return MODE_UNKNOWN, f"DLP Advanced Settings could not be read ({type(e).__name__})."
    if code != 200 or not isinstance(data, dict):
        return MODE_UNKNOWN, f"DLP Advanced Settings could not be read (HTTP {code})."
    for k, v in data.items():
        if _canon(k) == "enableevaluatealldlprules" and v is not None:
            on = _is_truthy(v)
            return (MODE_EVAL_ALL if on else MODE_RULE_ORDER), f"Read from DLP Advanced Settings (enableEvaluateAllDlpRules = {str(bool(on)).lower()})."
    return MODE_UNKNOWN, "DLP Advanced Settings did not say which evaluation mode Inline Web DLP uses."


def read_policies(client, scope: Dict[str, Any], *, declared_mode: str = "", log: Optional[Callable[[str], None]] = None,
                  cancel: Any = None) -> Dict[str, Any]:
    """Read the rules of every policy type in `scope["read"]` (scope_for),
    the Inline Web DLP evaluation mode (unless declared), and, for the
    missing-reference check, the DLP engines and URL categories when a
    section that uses them is read. Stop (`cancel`) is checked before every
    request and inside it (data_flow.stop_on): Stopped is raised and
    nothing more is sent. Read-only: GET requests only."""
    import data_flow
    import dlp_efficacy
    from ssl_flow import _fetch_rules
    say = log or (lambda m: None)
    read = [k for k in scope.get("read") or [] if k in POLICIES]

    def stop_point():
        if data_flow.stop_requested(cancel):
            raise Stopped(STOPPED_REASON)

    diagnostics: List[Dict[str, Any]] = []
    rules: Dict[str, List[Dict[str, Any]]] = {}
    read_errors: Dict[str, str] = {k: f"Not read: {why}" for k, why in (scope.get("read_blocked") or {}).items()}
    out: Dict[str, Any] = {"rules": rules, "read_errors": read_errors, "not_in_scope": dict(scope.get("not_in_scope") or {})}
    try:
        with data_flow.stop_on(client, cancel):
            mode, detail, source = MODE_UNKNOWN, "", "not_in_scope"
            if "web_dlp" in read:
                dm = str(declared_mode or "").strip().lower()
                if dm in ("rule_order", "evaluate_all", "evaluate_all_rules"):
                    mode = MODE_EVAL_ALL if dm.startswith("evaluate") else MODE_RULE_ORDER
                    detail, source = "Declared on this page.", "declared"
                    say(f"Inline Web DLP evaluation mode: {'Evaluate All Rules' if mode == MODE_EVAL_ALL else 'By Rule Order'} (declared on this page).")
                else:
                    say("Reading the Inline Web DLP evaluation mode (DLP Advanced Settings)…")
                    stop_point()
                    mode, detail = read_web_dlp_mode(client)
                    source = "read" if mode != MODE_UNKNOWN else "unread"
                    say(detail)
            out["mode"] = {"web_dlp": mode, "source": source, "detail": detail}
            # Admin ranking decides the evaluation order of the ranked
            # policies (admin_rank); read only when ZIA platform is ticked.
            import admin_rank
            if any(k in admin_rank.RANKED for k in read) and admin_rank.in_scope(scope.get("scopes")):
                say("Reading whether admin ranking is on (ZIA advanced settings)…")
                stop_point()
                out["admin_ranking"] = admin_rank.read(client, scope.get("scopes"))
                say(admin_rank.describe(out["admin_ranking"]))
            else:
                out["admin_ranking"] = {"state": admin_rank.OUT_OF_SCOPE, "why": admin_rank.NOT_IN_SCOPE_WHY, "source": admin_rank.SOURCE}
            for key in read:
                p = POLICIES[key]
                say(f"Reading the {p['label']} rules…")
                stop_point()
                before = len(diagnostics)
                items = _fetch_rules(client, p["endpoint"], diagnostics, p["read_label"])
                if len(diagnostics) > before:
                    d = diagnostics[-1]
                    read_errors[key] = " ".join(str(x) for x in (d.get("error_type"), d.get("error")) if x).strip()[:200] or "the read failed"
                    say(f"{p['label']} rules could not be read: {read_errors[key]}.")
                    continue
                rules[key] = items
                say(f"{p['label']} rules: {len(items)} found.")
            # Cloud Firewall rules on Microsoft 365 app service groups: the
            # network services and groups say which ports a later rule
            # allows (_app_service_covers). The same scope as the rules
            # (ZIA platform), the same endpoints the Path analyzer reads.
            out["network_services"] = out["network_service_groups"] = None
            fw = rules.get("firewall") or []
            import app_services
            if any(isinstance(r, dict) and app_services.named(r) for r in fw) and app_services.current(client) is not None:
                say("Reading the network services (to compare rules on Microsoft 365 app service groups)…")
                got_svc = {}
                for key_, ep in (("network_services", "/zia/networkServices"), ("network_service_groups", "/zia/networkServiceGroups")):
                    stop_point()
                    try:
                        data, code = client.get(ep)
                    except Exception as e:  # noqa: BLE001
                        if data_flow.stop_requested(cancel):
                            raise Stopped(STOPPED_REASON) from e
                        data, code = None, 0
                    items = data if isinstance(data, list) and all(isinstance(x, dict) for x in data) else None
                    got_svc[key_] = items if code in (200, 204) and (items is not None or code == 204) else None
                    if code == 204:
                        got_svc[key_] = []
                if got_svc.get("network_services") is not None and got_svc.get("network_service_groups") is not None:
                    out.update(got_svc)
                    say(f"Network services: {len(got_svc['network_services'])} found.")
                else:
                    say("The network services could not be read completely; rules on app service groups are not compared with later rules.")
            out["engines"] = out["categories"] = None
            if any(k in rules for k in DLP_POLICIES):
                say("Reading the DLP engines (to find rules that name engines that no longer exist)…")
                stop_point()
                ev = dlp_efficacy.read_collection(client, "/zia/dlpEngines")
                if ev["status"] == "verified" and ev["items"]:
                    out["engines"] = ev["items"]
                    say(f"DLP engines: {len(ev['items'])} found.")
                else:
                    say(f"DLP engines could not be read completely ({ev.get('reason') or 'no answer'}); missing engines are not checked.")
            if any(k in rules for k in ("url_filtering", "ssl_inspection", "web_dlp")):
                say("Reading the URL categories (to find rules that name categories that no longer exist)…")
                stop_point()
                cv = dlp_efficacy.read_collection(client, "/zia/urlCategories")
                if cv["status"] == "verified" and cv["items"]:
                    out["categories"] = cv["items"]
                    say(f"URL categories: {len(cv['items'])} found.")
                else:
                    say(f"URL categories could not be read completely ({cv.get('reason') or 'no answer'}); missing categories are not checked.")
            stop_point()
    except (data_flow.ReadStopped, dlp_efficacy.CorpusReadStopped) as e:
        raise Stopped(STOPPED_REASON) from e
    except Exception as e:  # noqa: BLE001
        import zia_rate
        if isinstance(e, zia_rate.Cancelled):
            raise Stopped(STOPPED_REASON) from e
        raise
    out["diagnostics"] = diagnostics
    return out


def run(client, scope: Dict[str, Any], *, declared_mode: str = "", log: Optional[Callable[[str], None]] = None,
        cancel: Any = None) -> Dict[str, Any]:
    """Read (only what is in scope) and analyse: {findings, counts_by_policy,
    read_errors, not_in_scope, mode, notes, scope}. Raises Stopped on Stop."""
    say = log or (lambda m: None)
    got = read_policies(client, scope, declared_mode=declared_mode, log=log, cancel=cancel)
    mode = got.get("mode") or {"web_dlp": MODE_UNKNOWN, "source": "not_in_scope", "detail": ""}
    import app_services
    res = analyse(got["rules"], web_dlp_mode=mode["web_dlp"], engines=got.get("engines"), categories=got.get("categories"),
                  admin_ranking=got.get("admin_ranking"), app_list=app_services.current(client),
                  network_services=got.get("network_services"), network_service_groups=got.get("network_service_groups"))
    n = len(res["findings"])
    say(f"Done: {n} finding{'s' if n != 1 else ''} across {len(res['counts_by_policy'])} polic{'ies' if len(res['counts_by_policy']) != 1 else 'y'}.")
    return {"findings": res["findings"], "counts_by_policy": res["counts_by_policy"], "read_errors": got["read_errors"],
            "not_in_scope": got["not_in_scope"], "mode": mode, "notes": res["notes"], "admin_ranking": got.get("admin_ranking"),
            "policy_labels": {k: p["label"] for k, p in POLICIES.items()},
            "missing_checked": {"engines": got.get("engines") is not None, "categories": got.get("categories") is not None},
            "scope": {"read": list(scope.get("read") or []), "summary": scope.get("summary", ""), "source": scope.get("source", "")}}


# ── Exports ──────────────────────────────────────────────────────────
CSV_COLUMNS = ("policy", "severity", "kind", "rule", "order", "shadowed_by", "shadowed_by_order", "reason", "fix")


def to_csv(result: Dict[str, Any]) -> str:
    """The findings as CSV; every cell passes through csv_safe (rule names
    come from the tenant and may start with a formula character)."""
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(CSV_COLUMNS)
    for f in result.get("findings") or []:
        by = f.get("shadowed_by") or {}
        w.writerow([f.get("policy_label") or f.get("policy"), f.get("severity"), f.get("kind"), f.get("rule"), f.get("order"),
                    by.get("name", ""), by.get("order", ""), f.get("reason"), f.get("fix")])
    return buf.getvalue()
