"""Policy exports: one formatted workbook (or PDF review copy) per ZIA
policy, every rule in evaluation order with every column an admin reads
in the portal, names instead of ids, and a usage/notes column carrying
the shadowed-rule findings for that rule.

Policies: URL filtering, Cloud App Control, SSL inspection, Cloud
Firewall (filtering rules, plus the network service, network application
and IP destination groups when they can be read) and File Type Control.

Reading reuses what the app already has: ssl_flow._fetch_rules (the rule
lists, a failed or incomplete read is never an empty policy), data_flow
stop handling (Stop is checked before every request and inside one) and
the shadowed-rule analysis (shadow_rules.analyse on the rules just read,
so nothing is read twice; findings matched to rules with index_by_rule).
Only what the Scope page puts in scope is read (scope_for), GET requests
only: nothing is written to the tenant.

People named in rule scope (users, override users, devices) are counted,
not named, as in the DLP inventory; groups, departments and locations are
named. The admin who last modified a rule is not exported (customer data
the review does not need); the time is.

Export options (options / shape, shared with config_exports): choose
columns, one row per value of multi-value fields, and the separator of
several values in one cell (new line, comma, semicolon). The defaults
make exactly the workbook of before; the PDF review copy keeps its fixed
columns. File Type Control workbooks also list each file type its rules
name (engine_explain.file_type_usage).

`hits` is the hook for hit counts (Insights, later): {policy key: {rule
id or rule name: count}}. With it, every rule sheet gets a Hits column;
without it, the Summary says hit counts are not part of this export.
"""
from __future__ import annotations

import io
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import pdf_writer
import xlsx_writer

XLSX = xlsx_writer.MEDIA_TYPE
PDF = pdf_writer.MEDIA_TYPE
ZIP = "application/zip"
FORMATS = ("xlsx", "pdf")

# key -> label, Scope section (data_flow.PATH_SECTIONS keys, plus
# "firewall": ZIA platform), endpoint, the read label (data_flow's section
# names, so diagnostics read the same everywhere), the shadow_rules key.
POLICIES: Dict[str, Dict[str, Any]] = {
    "url_filtering": {"label": "URL filtering", "section": "url", "endpoint": "/zia/urlFilteringRules",
                      "read_label": "URL filtering rules", "shadow": "url_filtering", "file": "url_filtering"},
    "cloud_app_control": {"label": "Cloud App Control", "section": "cac", "endpoint": "/zia/cloudApplicationRules",
                          "read_label": "Cloud App Control rules", "shadow": "cloud_app_control", "file": "cloud_app_control"},
    "ssl_inspection": {"label": "SSL inspection", "section": "ssl", "endpoint": "/zia/sslInspectionRules",
                       "read_label": "SSL inspection rules", "shadow": "ssl_inspection", "file": "ssl_inspection"},
    "firewall": {"label": "Cloud Firewall", "section": "firewall", "endpoint": "/zia/firewallFilteringRules",
                 "read_label": "Cloud Firewall rules", "shadow": "firewall", "file": "cloud_firewall"},
    "file_type_control": {"label": "File Type Control", "section": "ftc", "endpoint": "/zia/fileTypeRules",
                          "read_label": "File Type Control rules", "shadow": None, "file": "file_type_control"},
}
FIREWALL_SCOPES = ("zia_extras",)
# The Cloud Firewall's own objects, read with its rules (zscaler-sdk-python
# zia/cloud_firewall.py: list_network_svc_groups, list_network_services,
# list_network_app_groups, list_ip_destination_groups).
FIREWALL_GROUPS = (
    ("network_service_groups", "/zia/networkServiceGroups", "Network service groups"),
    ("network_services", "/zia/networkServices", "Network services"),
    ("network_app_groups", "/zia/networkApplicationGroups", "Network application groups"),
    ("ip_destination_groups", "/zia/ipDestinationGroups", "IP destination groups"),
)
# URL category names (zscaler-sdk-python url_categories.list_categories_lite:
# GET /urlCategories/lite), so a rule shows a custom category by its name.
CATEGORIES_LITE = "/zia/urlCategories/lite"

NOTHING_IN_SCOPE = ("Nothing the policy exports read is in scope: on the Scope page tick DLP or ZIA platform (and mark SSL "
                    "inspection and Cloud App Control as Zscaler for those policies), or tick ZIA platform for Cloud Firewall, "
                    "then export again.")
NOTHING_PICKED = "Pick at least one policy to export."
STOPPED_REASON = "You clicked Stop before the export finished: nothing more was read from the tenant and no file was made."
HITS_MISSING = ("Not part of this export: hit counts come from Insights, which this app does not read yet. Rules that never "
                "match by their position are named in the Usage and notes column.")
PEOPLE_NOTE = ("People named in rule scope (users, override users, devices) are counted, not named; groups, departments and "
               "locations are named. The admin who last changed a rule is not exported.")
READ_NOTE = "Read-only: listed from the tenant's API with GET requests; nothing was written. Only the policies in scope on the Scope page were read."


class Stopped(RuntimeError):
    """The operator clicked Stop."""


# ── Values ───────────────────────────────────────────────────────────
def _canon(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def humanize(token: Any) -> str:
    """BLOCK_DROP -> 'Block drop' (sentence case, as the app writes labels)."""
    s = str(token or "").strip()
    if not s:
        return ""
    s = s.replace("_", " ").strip().lower()
    return s[:1].upper() + s[1:]


def _ref_name(x: Any) -> str:
    if isinstance(x, dict):
        for k in ("name", "configuredName", "configured_name", "val"):
            if x.get(k) not in (None, ""):
                return str(x[k])
        if x.get("id") not in (None, ""):
            return f"id {x['id']}"
        return ""
    return "" if x is None else str(x)


def _as_list(v: Any) -> List[Any]:
    if v is None or v == "":
        return []
    return list(v) if isinstance(v, (list, tuple, set)) else [v]


def _when(v: Any) -> str:
    """An epoch time (seconds or milliseconds) as a UTC date and time."""
    try:
        n = float(v)
    except (TypeError, ValueError):
        return str(v or "")
    if n <= 0:
        return ""
    if n > 1e11:
        n /= 1000.0
    try:
        return datetime.fromtimestamp(n, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return str(v)


class Names:
    """Id -> name lookups: URL categories (from /urlCategories/lite)."""

    def __init__(self, categories: Optional[Iterable[Dict[str, Any]]] = None):
        self.categories: Dict[str, str] = {}
        for c in categories or []:
            if isinstance(c, dict) and c.get("id") not in (None, ""):
                name = c.get("configuredName") or c.get("configured_name") or c.get("name")
                if name:
                    self.categories[str(c["id"])] = str(name)

    def category(self, cid: Any) -> str:
        if isinstance(cid, dict):
            return _ref_name(cid)
        s = str(cid or "")
        return self.categories.get(s, s)


# ── Columns ──────────────────────────────────────────────────────────
# (header, [field names], how to show it). Kinds:
#   refs     a list of {id, name} references -> names
#   people   a list of people -> how many
#   cats     URL category ids -> names (custom categories by their name)
#   tokens   enum values -> sentence case
#   text     as is
#   bool     Yes / blank
#   time     epoch -> date
#   sub      a settings object -> "key: value" lines
Col = Tuple[str, Sequence[str], str]
WHO: List[Col] = [("Users", ["users"], "people"), ("Groups", ["groups"], "refs"), ("Departments", ["departments"], "refs"),
                  ("Locations", ["locations"], "refs"), ("Location groups", ["locationGroups"], "refs")]
DEVICE: List[Col] = [("Devices", ["devices"], "people"), ("Device groups", ["deviceGroups"], "refs"),
                     ("Device trust levels", ["deviceTrustLevels"], "tokens")]
WHEN: List[Col] = [("Time windows", ["timeWindows"], "refs")]

COLUMNS: Dict[str, List[Col]] = {
    "url_filtering": WHO + DEVICE + WHEN + [
        ("URL categories", ["urlCategories"], "cats"), ("Protocols", ["protocols"], "tokens"),
        ("Request methods", ["requestMethods"], "tokens"), ("User agent types", ["userAgentTypes"], "tokens"),
        ("User risk score levels", ["userRiskScoreLevels"], "tokens"), ("Source IP groups", ["sourceIpGroups"], "refs"),
        ("Workload groups", ["workloadGroups"], "refs"), ("Block override", ["blockOverride"], "bool"),
        ("Override users", ["overrideUsers"], "people"), ("Override groups", ["overrideGroups"], "refs"),
        ("Isolation profile", ["cbiProfile"], "refs"), ("Size quota (MB)", ["sizeQuota"], "text"),
        ("Time quota (minutes)", ["timeQuota"], "text"), ("Time validity", ["enforceTimeValidity"], "bool"),
        ("Valid from", ["validityStartTime"], "time"), ("Valid until", ["validityEndTime"], "time"),
        ("CIPA rule", ["ciparule"], "bool"), ("Notification URL", ["endUserNotificationUrl"], "text"),
        ("Labels", ["labels"], "refs")],
    "cloud_app_control": WHO + DEVICE + WHEN + [
        ("Application type", ["type"], "tokens"), ("Applications", ["applications"], "tokens"),
        ("Cloud app instances", ["cloudAppInstances"], "refs"), ("Tenancy profiles", ["tenancyProfileIds"], "refs"),
        ("Cloud app risk profile", ["cloudAppRiskProfile"], "refs"), ("Sharing domain profiles", ["sharingDomainProfiles"], "refs"),
        ("Form sharing domain profiles", ["formSharingDomainProfiles"], "refs"), ("User agent types", ["userAgentTypes"], "tokens"),
        ("User risk score levels", ["userRiskScoreLevels"], "tokens"), ("Isolation profile", ["cbiProfile"], "refs"),
        ("Size quota (MB)", ["sizeQuota"], "text"), ("Time quota (minutes)", ["timeQuota"], "text"),
        ("Time validity", ["enforceTimeValidity"], "bool"), ("Valid from", ["validityStartTime"], "time"),
        ("Valid until", ["validityEndTime"], "time"), ("End-user notification", ["eunEnabled"], "bool"),
        ("Labels", ["labels"], "refs")],
    "ssl_inspection": WHO + DEVICE + WHEN + [
        ("URL categories", ["urlCategories"], "cats"), ("Cloud applications", ["cloudApplications"], "tokens"),
        ("Destination IP groups", ["destIpGroups"], "refs"), ("Platforms", ["platforms"], "tokens"),
        ("User agent types", ["userAgentTypes"], "tokens"), ("Source IP groups", ["sourceIpGroups"], "refs"),
        ("Workload groups", ["workloadGroups"], "refs"), ("Proxy gateways", ["proxyGateways"], "refs"),
        ("ZPA app segments", ["zpaAppSegments"], "refs"), ("Road warrior for Kerberos", ["roadWarriorForKerberos"], "bool"),
        ("Labels", ["labels"], "refs")],
    "firewall": WHO + DEVICE + WHEN + [
        ("Source IPs", ["srcIps"], "tokens_raw"), ("Source IP groups", ["srcIpGroups"], "refs"),
        ("Source countries", ["sourceCountries"], "tokens_raw"), ("Exclude source countries", ["excludeSrcCountries"], "bool"),
        ("Destination addresses", ["destAddresses"], "tokens_raw"), ("Destination IP categories", ["destIpCategories"], "cats"),
        ("Destination countries", ["destCountries"], "tokens_raw"), ("Destination IP groups", ["destIpGroups"], "refs"),
        ("Network services", ["nwServices"], "refs"), ("Network service groups", ["nwServiceGroups"], "refs"),
        ("Network applications", ["nwApplications"], "tokens"), ("Network application groups", ["nwApplicationGroups"], "refs"),
        ("App services", ["appServices"], "refs"), ("App service groups", ["appServiceGroups"], "refs"),
        ("Workload groups", ["workloadGroups"], "refs"), ("ZPA app segments", ["zpaAppSegments"], "refs"),
        ("Full logging", ["enableFullLogging"], "bool"), ("Capture PCAP", ["capturePCAP"], "bool"),
        ("Labels", ["labels"], "refs")],
    "file_type_control": WHO + DEVICE + WHEN + [
        ("File types", ["fileTypes"], "tokens"), ("Operation", ["operation"], "tokens"),
        ("URL categories", ["urlCategories"], "cats"), ("Cloud applications", ["cloudApplications"], "tokens"),
        ("Protocols", ["protocols"], "tokens"), ("Minimum size (KB)", ["minSize"], "text"), ("Maximum size (KB)", ["maxSize"], "text"),
        ("Active content", ["activeContent"], "bool"), ("Unscannable", ["unscannable"], "bool"),
        ("Password protected", ["passwordProtected"], "bool"), ("Size quota (MB)", ["sizeQuota"], "text"),
        ("Time quota (minutes)", ["timeQuota"], "text"), ("ZPA app segments", ["zpaAppSegments"], "refs"),
        ("Capture PCAP", ["capturePCAP"], "bool"), ("Labels", ["labels"], "refs")],
}
# Shown in the fixed columns, or deliberately left out (bookkeeping, the
# admin's name, write-only flags), so never repeated under Other settings.
_SHOWN = {_canon(k) for k in (
    "id", "name", "order", "rank", "state", "action", "actions", "filteringAction", "description", "lastModifiedTime",
    "lastModifiedBy", "accessControl", "predefined", "defaultRule", "modifiedBy", "modifiedTime", "decryptSubActions",
    "doNotDecryptSubActions", "sslInterceptionCert", "serverCertificates", "defaultCertificate", "overrideDefaultCertificate",
    "blockSslTrafficWithNoSniEnabled", "ocspCheck", "blockUndecrypt", "bypassOtherPolicies", "showEUN", "showEUNATP",
    "eunTemplateId", "browserEunTemplateId", "cascadingEnabled", "val", "backendName", "originalName", "deprecated", "misc",
    "appNotReady", "appCatModified", "underMigration", "webApplicationClass", "validityTimeZoneId", "accessPrivilege",
)}
_PEOPLE_FIELDS = {"users", "overrideusers", "devices", "excludedusers", "auditor", "externalauditoremail"}


class Rule:
    """A raw rule (camelCase API or snake_case SDK dict), field access by canonical name."""

    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.f = {_canon(k): v for k, v in raw.items()}

    def get(self, *names: str) -> Any:
        for n in names:
            v = self.f.get(_canon(n))
            if v not in (None, ""):
                return v
        return None


def _show(kind: str, v: Any, names: Names) -> Any:
    items = _as_list(v)
    if kind == "people":
        return f"{len(items)} {'person' if len(items) == 1 else 'people'}" if items else ""
    if kind == "refs":
        return [n for n in (_ref_name(x) for x in items) if n]
    if kind == "cats":
        return [names.category(x) for x in items if x not in (None, "")]
    if kind == "tokens":
        return [humanize(_ref_name(x)) if not isinstance(x, dict) else _ref_name(x) for x in items if x not in (None, "")]
    if kind == "tokens_raw":
        return [_ref_name(x) for x in items if x not in (None, "")]
    if kind == "bool":
        return "Yes" if v is True or str(v).lower() == "true" else ""
    if kind == "time":
        return _when(v)
    if kind == "sub":
        return _sub_lines(v)
    if isinstance(v, (dict, list)):
        return _sub_lines(v)
    return "" if v is None else v


def _sub_lines(v: Any, prefix: str = "") -> List[str]:
    """A settings object as 'key: value' lines (nested keys joined)."""
    out: List[str] = []
    if isinstance(v, dict):
        for k, x in v.items():
            if x in (None, "", [], {}) or _canon(k) in _PEOPLE_FIELDS:
                continue
            label = humanize(re.sub(r"(?<!^)(?=[A-Z])", "_", str(k)))
            if isinstance(x, dict):
                out += _sub_lines(x, f"{prefix}{label}: ")
            elif isinstance(x, list):
                out.append(f"{prefix}{label}: " + ", ".join(_ref_name(i) for i in x))
            else:
                out.append(f"{prefix}{label}: {humanize(x) if isinstance(x, str) and x.isupper() else ('Yes' if x is True else ('No' if x is False else x))}")
    elif isinstance(v, list):
        out.append(prefix + ", ".join(_ref_name(i) for i in v))
    elif v not in (None, ""):
        out.append(f"{prefix}{v}")
    return out


def action_of(policy: str, r: Rule) -> Tuple[str, List[str]]:
    """(the action in words, action details lines)."""
    if policy == "cloud_app_control":
        acts = [humanize(a) for a in _as_list(r.get("actions"))]
        return ", ".join(acts), []
    if policy == "file_type_control":
        return humanize(r.get("filteringAction", "action")), []
    a = r.get("action")
    if isinstance(a, dict):
        typ = humanize(a.get("type") or a.get("name") or a.get("actionType") or "")
        details = _sub_lines({k: v for k, v in a.items() if k not in ("type", "name", "actionType")})
        return typ, details
    return humanize(a), []


def state_of(r: Rule) -> str:
    return humanize(r.get("state") or "ENABLED")


def _order_key(r: Rule) -> Tuple[int, int, str]:
    default = r.get("defaultRule") in (True, "true", "True")
    try:
        o = int(r.get("order"))
    except (TypeError, ValueError):
        o = 10 ** 9
    return (1 if default else 0, o, str(r.get("id") or ""))


def _other_settings(policy: str, r: Rule) -> List[str]:
    used = {_canon(f) for _, fields, _ in COLUMNS[policy] for f in fields} | _SHOWN
    out: List[str] = []
    for k, v in r.raw.items():
        c = _canon(k)
        if c in used or v in (None, "", [], {}, False, 0):
            continue
        if c in _PEOPLE_FIELDS:
            n = len(_as_list(v))
            out.append(f"{humanize(re.sub(r'(?<!^)(?=[A-Z])', '_', str(k)))}: {n} {'person' if n == 1 else 'people'}")
            continue
        label = humanize(re.sub(r"(?<!^)(?=[A-Z])", "_", str(k)))
        if isinstance(v, dict):
            out += _sub_lines(v, f"{label}: ")
        elif isinstance(v, list):
            out.append(f"{label}: " + ", ".join(_ref_name(i) for i in v))
        else:
            out.append(f"{label}: {v}")
    return out


# ── Notes (shadowed-rule findings) ───────────────────────────────────
_KIND = {"shadowed": "Shadowed", "after_catch_all": "Below a catch-all", "duplicate": "Duplicate", "superseded": "Superseded",
         "missing_reference": "Missing object", "disabled": "Disabled"}


def notes_for(policy: str, r: Rule, index: Dict[Tuple[str, str], List[Dict[str, Any]]]) -> List[str]:
    """The Usage and notes lines of one rule: what the shadowed-rule
    analysis found (matched by rule id when the finding has one), and that
    it is the Default or a predefined rule."""
    out: List[str] = []
    if r.get("defaultRule") in (True, "true", "True"):
        out.append("Default rule: always evaluated last.")
    elif r.get("predefined") in (True, "true", "True"):
        out.append("Predefined by Zscaler.")
    key = POLICIES[policy]["shadow"]
    name = str(r.get("name") or f"Rule {r.get('id')}")
    rid = r.get("id")
    found = [f for f in index.get((key or policy, name), []) if f.get("rule_id") in (None, rid) or str(f.get("rule_id")) == str(rid)]
    for f in found:
        line = f"{_KIND.get(f.get('kind'), humanize(f.get('kind')))} ({f.get('severity')}): {f.get('reason')}"
        if f.get("fix") and f.get("kind") != "disabled":
            line += f" Fix: {f.get('fix')}"
        out.append(line)
    if key is None and str(r.get("state") or "ENABLED").upper() != "ENABLED":
        out.append("Disabled: it never matches.")
    return out


def _hits_for(hits: Optional[Dict[str, Dict[str, Any]]], policy: str, r: Rule) -> Any:
    per = (hits or {}).get(policy) or {}
    for k in (r.get("id"), r.get("name")):
        if k is not None and str(k) in per:
            return per[str(k)]
        if k is not None and k in per:
            return per[k]
    return ""


# ── Rows ─────────────────────────────────────────────────────────────
def headers(policy: str, with_hits: bool) -> List[str]:
    cols = ["Order", "Rule", "State", "Action"]
    if policy == "ssl_inspection":
        cols.append("Action details")
    cols += [h for h, _, _ in COLUMNS[policy]]
    cols += ["Description", "Admin rank", "Last modified", "Usage and notes"]
    if with_hits:
        cols.append("Hits")
    cols.append("Other settings")
    return cols


def rows(policy: str, raw_rules: Iterable[Dict[str, Any]], *, names: Names,
         index: Dict[Tuple[str, str], List[Dict[str, Any]]], hits: Optional[Dict[str, Dict[str, Any]]] = None) -> List[List[Any]]:
    """Every rule of a policy in evaluation order (the Default rule last),
    one row each, in the order of headers(policy, hits is not None)."""
    out: List[List[Any]] = []
    rules = sorted((Rule(x) for x in raw_rules if isinstance(x, dict)), key=_order_key)
    for r in rules:
        action, details = action_of(policy, r)
        row: List[Any] = [r.get("order"), r.get("name") or f"Rule {r.get('id')}", state_of(r), action]
        if policy == "ssl_inspection":
            row.append(details)
        row += [_show(kind, r.get(*fields), names) for _, fields, kind in COLUMNS[policy]]
        row += [r.get("description") or "", r.get("rank") if r.get("rank") is not None else "", _when(r.get("lastModifiedTime")),
                notes_for(policy, r, index)]
        if hits is not None:
            row.append(_hits_for(hits, policy, r))
        row.append(_other_settings(policy, r))
        out.append(row)
    return out


def _ports(svc: Dict[str, Any]) -> List[str]:
    out = []
    for key, proto in (("destTcpPorts", "TCP"), ("destUdpPorts", "UDP"), ("srcTcpPorts", "TCP source"), ("srcUdpPorts", "UDP source")):
        for p in _as_list(svc.get(key)):
            if isinstance(p, dict):
                s, e = p.get("start"), p.get("end")
                out.append(f"{proto} {s}" + (f"-{e}" if e not in (None, "", s) else ""))
    return out


# ── Export options (every policy export's workbook) ──────────────────
# Columns: the headers to keep per sheet key (a policy key, or a key of
# config_exports' sheets); the identity columns always stay. Layout: flat
# (one row per rule, several values in one cell) or rows (one row per
# value of each multi-value column, the other cells repeated, so a filter
# on one value finds every rule that names it). Separator: how several
# values share a cell. The defaults (every column, flat, new line) give
# exactly the workbook the exports made before options existed.
LAYOUTS = ("flat", "rows")
SEPARATORS: Dict[str, str] = {"newline": "\n", "comma": ", ", "semicolon": "; "}
DEFAULT_OPTIONS: Dict[str, Any] = {"columns": {}, "layout": "flat", "separator": "newline"}
IDENTITY_COLUMNS = ("Order", "Rule", "Name", "Location", "Object")
# Lines of notes, not values: joined, never split into rows.
NOTE_COLUMNS = {"Usage and notes", "Other settings", "Action details", "Description", "Settings", "Dynamic criteria", "Comments"}
MAX_ROWS_PER_RECORD = 500   # rows layout: beyond this a record's remaining multi-value cells are joined instead


def column_catalogue() -> Dict[str, List[str]]:
    """{sheet key: the headers a workbook of it can carry} for the column
    picker: each policy's Rules sheet (no Hits: hit counts are not read)
    and the configuration exports' main sheets (config_exports)."""
    out = {k: headers(k, False) for k in POLICIES}
    try:
        import config_exports
        out.update(config_exports.column_catalogue())
    except ImportError:   # pragma: no cover - the module ships with this one
        pass
    return out


def options(columns: Optional[Dict[str, Sequence[str]]] = None, layout: Any = "flat", separator: Any = "newline") -> Dict[str, Any]:
    """Validated export options (ValueError naming what is wrong). An empty
    column list for a key, or no key, keeps every column."""
    lay = str(layout or "flat").strip().lower()
    if lay not in LAYOUTS:
        raise ValueError("layout must be flat or rows.")
    sep = str(separator or "newline").strip().lower()
    if sep not in SEPARATORS:
        raise ValueError("separator must be newline, comma or semicolon.")
    cat = column_catalogue()
    cols: Dict[str, List[str]] = {}
    for key, want in (columns or {}).items():
        if key not in cat:
            raise ValueError(f"Unknown sheet for columns: {key}. Choose from {', '.join(sorted(cat))}.")
        picked = [str(c) for c in (want or []) if str(c).strip()]
        bad = [c for c in picked if c not in cat[key] and c != "Hits"]
        if bad:
            raise ValueError(f"Unknown column for {key}: {', '.join(bad[:5])}.")
        if picked:
            cols[key] = picked
    return {"columns": cols, "layout": lay, "separator": sep}


def is_default(opts: Optional[Dict[str, Any]]) -> bool:
    return not opts or (not opts.get("columns") and opts.get("layout", "flat") == "flat" and opts.get("separator", "newline") == "newline")


def _join(v: Any, sep: str) -> Any:
    if isinstance(v, (list, tuple)):
        items = [str(x) for x in v if x is not None and str(x) != ""]
        return items if sep == "\n" else sep.join(items)
    return v


def shape(cols: Sequence[str], data: Iterable[Sequence[Any]], opts: Optional[Dict[str, Any]], key: Optional[str] = None) -> Tuple[List[str], List[List[Any]]]:
    """(headers, rows) of one sheet under the export options: the chosen
    columns (identity columns kept), one row per value when the layout is
    rows, several values joined with the separator. Default options
    return the sheet unchanged."""
    cols = list(cols)
    rows_in = [list(r) for r in data]
    if is_default(opts):
        return cols, rows_in
    sep = SEPARATORS[opts.get("separator", "newline")]
    keep = (opts.get("columns") or {}).get(key or "") if key else None
    idx = [i for i, c in enumerate(cols) if not keep or c in keep or c in IDENTITY_COLUMNS]
    cols = [cols[i] for i in idx]
    rows_in = [[r[i] if i < len(r) else "" for i in idx] for r in rows_in]
    out: List[List[Any]] = []
    split = [i for i, c in enumerate(cols) if c not in NOTE_COLUMNS]
    for r in rows_in:
        recs = [r]
        if opts.get("layout") == "rows":
            for i in split:
                vals = r[i] if isinstance(r[i], (list, tuple)) else None
                if vals is None:
                    continue
                vals = [x for x in vals if x is not None and str(x) != ""]
                if len(vals) <= 1:
                    for rec in recs:
                        rec[i] = vals[0] if vals else ""
                    continue
                if len(recs) * len(vals) > MAX_ROWS_PER_RECORD:
                    continue   # joined below
                recs = [rec[:i] + [v] + rec[i + 1:] for rec in recs for v in vals]
        out += [[_join(v, sep) for v in rec] for rec in recs]
    return cols, out


def _sheet(wb: Any, name: str, cols: Sequence[str], data: Iterable[Sequence[Any]], opts: Optional[Dict[str, Any]], key: Optional[str] = None) -> Any:
    c, r = shape(cols, data, opts, key)
    return wb.add_sheet(name, columns=c, rows=r)


# ── Scope ────────────────────────────────────────────────────────────
def scope_for(scopes: Any, channels: Any) -> Dict[str, Any]:
    """The policies the Scope page's selection lets the exports read
    (data_flow.path_scope for the ZIA sections, Cloud Firewall when ZIA
    platform is ticked). {read, not_in_scope, read_blocked, summary}. Pure."""
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
        elif sec in ps["read"]:
            read.append(key)
        elif sec in (ps.get("read_blocked") or {}):
            blocked[key] = ps["read_blocked"][sec]
        else:
            nis[key] = ps["not_in_scope"].get(sec) or "Not in scope on the Scope page, so it was not read."
    summary = ("In scope on the Scope page: " + ", ".join(POLICIES[k]["label"] for k in read) + "." if read else NOTHING_IN_SCOPE)
    return {"scopes": ps["scopes"], "read": read, "not_in_scope": nis, "read_blocked": blocked, "summary": summary,
            "path_scope": ps}


def pick(scope: Dict[str, Any], policies: Optional[Sequence[str]]) -> Tuple[List[str], Dict[str, str]]:
    """(the policies to read: the ones asked for that are in scope, all in
    scope when none is named; {policy: why not} for the ones asked for
    that are not). ValueError for a policy this module does not know."""
    asked = [str(p).strip() for p in (policies or []) if str(p).strip()]
    bad = [p for p in asked if p not in POLICIES]
    if bad:
        raise ValueError(f"Unknown policy: {', '.join(sorted(bad))}. Choose from {', '.join(POLICIES)}.")
    want = asked or list(POLICIES)
    out = [p for p in want if p in scope["read"]]
    why = {p: (scope["not_in_scope"].get(p) or scope["read_blocked"].get(p) or "Not in scope.") for p in want if p not in scope["read"]}
    return out, why


# ── Reading ──────────────────────────────────────────────────────────
def read(client, policies: Sequence[str], *, log: Optional[Callable[[str], None]] = None, cancel: Any = None) -> Dict[str, Any]:
    """GET the rules of `policies` (already filtered to what is in scope),
    the URL category names when a policy names categories, and the Cloud
    Firewall's groups when the firewall is exported. Stop is checked
    before every request (Stopped). A failed read is recorded in
    `read_errors`, never turned into an empty policy."""
    import data_flow
    import dlp_efficacy
    from ssl_flow import _fetch_rules
    say = log or (lambda m: None)

    def stop_point():
        if data_flow.stop_requested(cancel):
            raise Stopped(STOPPED_REASON)

    diagnostics: List[Dict[str, Any]] = []
    out: Dict[str, Any] = {"rules": {}, "read_errors": {}, "categories": None, "groups": {}, "group_errors": {}, "diagnostics": diagnostics}
    try:
        with data_flow.stop_on(client, cancel):
            for key in policies:
                p = POLICIES[key]
                say(f"Reading the {p['label']} rules…")
                stop_point()
                before = len(diagnostics)
                items = _fetch_rules(client, p["endpoint"], diagnostics, p["read_label"])
                if len(diagnostics) > before:
                    d = diagnostics[-1]
                    out["read_errors"][key] = " ".join(str(x) for x in (d.get("error_type"), d.get("error")) if x).strip()[:200] or "the read failed"
                    say(f"{p['label']} rules could not be read: {out['read_errors'][key]}.")
                    continue
                out["rules"][key] = items
                say(f"{p['label']} rules: {len(items)} found.")
            if any(k in out["rules"] for k in ("url_filtering", "ssl_inspection", "file_type_control", "firewall")):
                say("Reading the URL category names…")
                stop_point()
                ev = dlp_efficacy.read_collection(client, CATEGORIES_LITE)
                if ev["status"] == "verified":
                    out["categories"] = ev["items"]
                    say(f"URL categories: {len(ev['items'])} found.")
                else:
                    say(f"URL category names could not be read ({ev.get('reason') or 'no answer'}); categories are shown by id.")
            if "firewall" in out["rules"]:
                for gkey, ep, label in FIREWALL_GROUPS:
                    say(f"Reading the {label[:1].lower() + label[1:]}…")
                    stop_point()
                    ev = dlp_efficacy.read_collection(client, ep)
                    if ev["status"] == "verified":
                        out["groups"][gkey] = ev["items"]
                        say(f"{label}: {len(ev['items'])} found.")
                    else:
                        out["group_errors"][gkey] = ev.get("reason") or "no answer"
                        say(f"{label} could not be read ({out['group_errors'][gkey]}); the sheet is left out.")
            stop_point()
    except (data_flow.ReadStopped, dlp_efficacy.CorpusReadStopped) as e:
        raise Stopped(STOPPED_REASON) from e
    except Exception as e:  # noqa: BLE001
        import zia_rate
        if isinstance(e, zia_rate.Cancelled):
            raise Stopped(STOPPED_REASON) from e
        raise
    return out


def findings_for(got: Dict[str, Any]) -> Dict[str, Any]:
    """The shadowed-rule analysis of the rules just read (no second read).
    Missing categories are checked only with a category list that is
    plainly the whole catalogue (it holds predefined categories too)."""
    import shadow_rules
    by = {POLICIES[k]["shadow"]: rs for k, rs in (got.get("rules") or {}).items() if POLICIES[k]["shadow"]}
    cats = got.get("categories")
    whole = bool(cats) and any(isinstance(c, dict) and not (c.get("customCategory") or str(c.get("id", "")).startswith("CUSTOM_")) for c in cats)
    res = shadow_rules.analyse(by, categories=cats if whole else None)
    res["index"] = shadow_rules.index_by_rule(res["findings"])
    return res


# ── Files ────────────────────────────────────────────────────────────
def _now() -> datetime:
    return datetime.now(timezone.utc)


def _summary_pairs(policy: str, raw_rules: List[Dict[str, Any]], *, tenant_label: str, scope_summary: str,
                   findings: List[Dict[str, Any]], note: str, hits: Optional[dict], extra: Sequence[Tuple[str, Any]] = ()) -> List[Tuple[str, Any]]:
    enabled = sum(1 for r in raw_rules if str(Rule(r).get("state") or "ENABLED").upper() == "ENABLED")
    mine = [f for f in findings if f.get("policy") == POLICIES[policy]["shadow"]]
    by_kind: Dict[str, int] = {}
    for f in mine:
        by_kind[_KIND.get(f.get("kind"), str(f.get("kind")))] = by_kind.get(_KIND.get(f.get("kind"), str(f.get("kind"))), 0) + 1
    pairs: List[Tuple[str, Any]] = [
        ("Tenant", tenant_label or "Not named"), ("Policy", POLICIES[policy]["label"]),
        ("Exported", _now().strftime("%Y-%m-%d %H:%M UTC")), ("Rules", len(raw_rules)), ("Enabled", enabled),
    ]
    if POLICIES[policy]["shadow"]:
        pairs.append(("Shadowed-rule findings", (", ".join(f"{k}: {n}" for k, n in sorted(by_kind.items())) or "None")))
        if note:
            pairs.append(("How rules are evaluated", note))
    else:
        pairs.append(("Shadowed-rule findings", "Not analysed for File Type Control; disabled rules are named in Usage and notes."))
    pairs.append(("Hit counts", "Included (Hits column)." if hits is not None else HITS_MISSING))
    pairs += list(extra)
    pairs += [("Scope", scope_summary), ("How it was read", READ_NOTE), ("People", PEOPLE_NOTE)]
    return pairs


def workbook(policy: str, raw_rules: List[Dict[str, Any]], *, names: Names, analysis: Dict[str, Any], tenant_label: str = "",
             scope_summary: str = "", groups: Optional[Dict[str, List[Dict[str, Any]]]] = None,
             group_errors: Optional[Dict[str, str]] = None, hits: Optional[Dict[str, Dict[str, Any]]] = None,
             opts: Optional[Dict[str, Any]] = None) -> bytes:
    """One policy's workbook: Summary, Rules (every column, or the ones
    `opts` picks, shaped by its layout and separator), for Cloud Firewall
    its network service, application and IP destination groups, and for
    File Type Control the file types its rules name."""
    label = POLICIES[policy]["label"]
    wb = xlsx_writer.Workbook(title=f"{label} policy {tenant_label}".strip(), subject=f"{label} rules in evaluation order")
    extra: List[Tuple[str, Any]] = []
    for gkey, why in sorted((group_errors or {}).items()):
        extra.append((f"Could not be read: {dict((k, l) for k, _, l in FIREWALL_GROUPS).get(gkey, gkey)}", why))
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([[k, v] for k, v in _summary_pairs(policy, raw_rules, tenant_label=tenant_label, scope_summary=scope_summary,
                                                 findings=analysis.get("findings") or [], note=(analysis.get("notes") or {}).get(POLICIES[policy]["shadow"] or "", ""),
                                                 hits=hits, extra=extra)])
    if not is_default(opts):
        s.append(["Export options", options_text(opts)])
    _sheet(wb, "Rules", headers(policy, hits is not None), rows(policy, raw_rules, names=names, index=analysis.get("index") or {}, hits=hits),
           opts, policy)
    if policy == "file_type_control":
        _file_types_sheet(wb, raw_rules, opts)
    if policy == "firewall":
        g = groups or {}
        svc_name = {str(x.get("id")): _ref_name(x) for x in g.get("network_services") or [] if isinstance(x, dict)}
        if "network_service_groups" in g:
            _sheet(wb, "Network service groups", ["Name", "Services", "Description"], opts=opts, data=[[x.get("name"), [svc_name.get(str(i.get("id")) if isinstance(i, dict) else str(i), _ref_name(i)) for i in _as_list(x.get("services"))],
                                x.get("description") or ""] for x in sorted(g["network_service_groups"], key=lambda x: str(x.get("name") or "").lower()) if isinstance(x, dict)])
        if "network_services" in g:
            _sheet(wb, "Network services", ["Name", "Type", "Ports", "Description"], opts=opts, data=[[x.get("name"), humanize(x.get("type")), _ports(x), x.get("description") or ""]
                               for x in sorted(g["network_services"], key=lambda x: str(x.get("name") or "").lower()) if isinstance(x, dict)])
        if "network_app_groups" in g:
            _sheet(wb, "Network application groups", ["Name", "Applications", "Description"], opts=opts, data=[[x.get("name"), [_ref_name(a) for a in _as_list(x.get("networkApplications") or x.get("network_applications"))],
                                x.get("description") or ""] for x in sorted(g["network_app_groups"], key=lambda x: str(x.get("name") or "").lower()) if isinstance(x, dict)])
        if "ip_destination_groups" in g:
            _sheet(wb, "IP destination groups", ["Name", "Type", "Addresses", "IP categories", "Countries", "Description"], opts=opts, data=[[x.get("name"), humanize(x.get("type")), [str(a) for a in _as_list(x.get("addresses"))],
                                [names.category(c) for c in _as_list(x.get("ipCategories"))], [str(c) for c in _as_list(x.get("countries"))],
                                x.get("description") or ""] for x in sorted(g["ip_destination_groups"], key=lambda x: str(x.get("name") or "").lower()) if isinstance(x, dict)])
    return wb.to_bytes()


def options_text(opts: Optional[Dict[str, Any]]) -> str:
    """The export options in words, for the Summary sheet."""
    if is_default(opts):
        return "Every column, one row per rule, several values on separate lines in one cell."
    o = opts or {}
    sep = {"newline": "on separate lines", "comma": "separated by commas", "semicolon": "separated by semicolons"}[o.get("separator", "newline")]
    lay = "one row per value of each multi-value column" if o.get("layout") == "rows" else "one row per rule or object"
    cols = o.get("columns") or {}
    picked = "; ".join(f"{k}: {len(v)} columns" for k, v in sorted(cols.items())) or "every column"
    return f"Columns: {picked}. Layout: {lay}. Several values in one cell are {sep}."


def _file_types_sheet(wb: Any, raw_rules: List[Dict[str, Any]], opts: Optional[Dict[str, Any]]) -> None:
    """File Type Control: each file type its rules name, as people read it,
    whether it is a category, and the rules that use it (engine_explain)."""
    import engine_explain
    usage = engine_explain.file_type_usage({"file_type_control": raw_rules})
    data = [[u["label"], u["kind"], u["token"], u["used_by"].get("file_type_control", []), len(u["used_by"].get("file_type_control", []))]
            for u in usage]
    if not data:
        data = [["No rule names a file type.", "", "", [], 0]]
    _sheet(wb, "File types", ["Name", "Kind", "API name", "File Type Control rules", "Rules"], data, opts)


# The review copy keeps the columns a reviewer reads; the workbook has them all.
def pdf(policy: str, raw_rules: List[Dict[str, Any]], *, names: Names, analysis: Dict[str, Any], tenant_label: str = "",
        scope_summary: str = "", hits: Optional[Dict[str, Dict[str, Any]]] = None, page_size: str = "A4") -> bytes:
    """One policy as a PDF review copy: the summary, then every rule in
    order with its criteria (non-empty ones, one per line) and notes."""
    label = POLICIES[policy]["label"]
    doc = pdf_writer.PdfDocument(title=f"{label} policy: {tenant_label or 'tenant'}", page_size=page_size,
                                 footer=f"DLP-Check policy export · {label} · {tenant_label or 'tenant'}", subject=f"{label} rules for review")
    doc.heading(f"{label} policy")
    doc.key_values(_summary_pairs(policy, raw_rules, tenant_label=tenant_label, scope_summary=scope_summary,
                                  findings=analysis.get("findings") or [], note=(analysis.get("notes") or {}).get(POLICIES[policy]["shadow"] or "", ""),
                                  hits=hits), size=9)
    doc.heading("Rules in evaluation order", 2)
    cols = headers(policy, hits is not None)
    full = rows(policy, raw_rules, names=names, index=analysis.get("index") or {}, hits=hits)
    crit_cols = [h for h, _, _ in COLUMNS[policy]] + (["Action details"] if policy == "ssl_inspection" else [])
    out_rows = []
    for row in full:
        d = dict(zip(cols, row))
        crit = []
        for h in crit_cols:
            v = d.get(h)
            text = ", ".join(str(x) for x in v) if isinstance(v, list) else str(v or "")
            if text:
                crit.append(f"{h}: {text}")
        notes = d.get("Usage and notes") or []
        r = [d.get("Order"), d.get("Rule"), d.get("State"), d.get("Action"), "\n".join(crit) or "Any", d.get("Description") or "",
             "\n".join(notes) if isinstance(notes, list) else notes]
        if hits is not None:
            r.append(d.get("Hits"))
        out_rows.append(r)
    head = ["Order", "Rule", "State", "Action", "Criteria", "Description", "Usage and notes"] + (["Hits"] if hits is not None else [])
    if out_rows:
        widths = [0.6, 2.0, 0.9, 1.2, 3.6, 1.8, 3.2] + ([0.6] if hits is not None else [])
        doc.table(head, out_rows, widths=widths, size=7.0)
    else:
        doc.paragraph("The policy has no rules.")
    return doc.to_bytes()


def safe_part(text: Any, fallback: str = "tenant", limit: int = 50) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", str(text or "")).strip("_")[:limit]
    return s or fallback


def filename(policy: str, tenant_label: str, fmt: str) -> str:
    return f"{POLICIES[policy]['file']}_policy_{safe_part(tenant_label)}_{_now().strftime('%Y%m%d')}.{fmt}"


def bundle(files: List[Tuple[str, bytes]], tenant_label: str, fmt: str) -> Tuple[str, str, bytes]:
    """One file as itself; several in one zip."""
    if len(files) == 1:
        name, data = files[0]
        return name, (XLSX if fmt == "xlsx" else PDF), data
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files:
            z.writestr(name, data)
    return f"policy_exports_{safe_part(tenant_label)}_{_now().strftime('%Y%m%d')}_{fmt}.zip", ZIP, buf.getvalue()


def run(client, scope: Dict[str, Any], policies: Sequence[str], fmt: str = "xlsx", *, tenant_label: str = "",
        log: Optional[Callable[[str], None]] = None, cancel: Any = None, hits: Optional[Dict[str, Dict[str, Any]]] = None,
        page_size: str = "A4", opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read the policies (only those in `scope`, already picked), analyse
    them for shadowed rules and build one file per policy that was read.
    Returns {status: ready | error, files, counts, read_errors, artifact}.
    Raises Stopped on Stop."""
    import data_flow
    if fmt not in FORMATS:
        raise ValueError("format must be xlsx or pdf.")
    say = log or (lambda m: None)
    got = read(client, policies, log=say, cancel=cancel)
    analysis = findings_for(got)
    names = Names(got.get("categories"))
    files: List[Tuple[str, bytes]] = []
    counts: Dict[str, Any] = {}
    for key in policies:
        if key not in got["rules"]:
            continue
        if data_flow.stop_requested(cancel):
            raise Stopped(STOPPED_REASON)
        rs = got["rules"][key]
        if fmt == "xlsx":
            data = workbook(key, rs, names=names, analysis=analysis, tenant_label=tenant_label, scope_summary=scope.get("summary", ""),
                            groups=got["groups"], group_errors=got["group_errors"], hits=hits, opts=opts)
        else:
            data = pdf(key, rs, names=names, analysis=analysis, tenant_label=tenant_label, scope_summary=scope.get("summary", ""),
                       hits=hits, page_size=page_size)
        name = filename(key, tenant_label, fmt)
        files.append((name, data))
        counts[key] = {"label": POLICIES[key]["label"], "rules": len(rs),
                       "findings": sum(1 for f in analysis["findings"] if f.get("policy") == POLICIES[key]["shadow"])}
        say(f"{POLICIES[key]['label']}: {name} ({max(1, len(data) // 1024)} KB).")
    out = {"counts": counts, "read_errors": got["read_errors"], "group_errors": got["group_errors"],
           "files": [n for n, _ in files], "format": fmt}
    if not files:
        out.update(status="error", error="Nothing could be read, so no file was made: " +
                   "; ".join(f"{POLICIES[k]['label']}: {v}" for k, v in got["read_errors"].items()))
        return out
    out["artifact"] = bundle(files, tenant_label, fmt)
    out.update(status="ready", filename=out["artifact"][0])
    say(f"Ready: {out['artifact'][0]}.")
    return out
