"""ZPA analysis templates and ZPA diagnostics: pure functions over the
snapshot zpa_reader.read returns. Nothing here reads or writes a tenant.

`analyze(snapshot)` runs every template in CATALOG and returns
{findings, catalog, counts, not_assessed}. Each finding is
{template, title, severity, object, object_type, object_id, reason, fix}:
one plain sentence of reason, one of fix. A template whose input was not
read (the list failed, or is incomplete where completeness matters) is
"not assessed", never "no finding".

`diagnose(snapshot, user, destination, port, protocol)` answers, for one
user context and one destination, which app segment matches, which server
groups and connector groups serve it, and which access rule decides, with
every rule before it and why it did not match.

ZPA semantics assumed (stated here and in every diagnosis):
- Access policy rules are evaluated in rule order (ruleOrder ascending);
  the first rule whose conditions all match decides (ALLOW, DENY or
  REQUIRE_APPROVAL), later rules are not evaluated. A disabled rule is
  skipped.
- When no access rule matches, ZPA denies access (deny by default).
- A rule's `operator` (default AND) joins its conditions; a condition's
  `operator` (default OR) joins its operands; `negated` inverts a
  condition. A rule with no APP / APP_GROUP operand applies to every
  application.
- Segment match: among the enabled segments whose domain list matches the
  destination and whose TCP (or UDP) port ranges contain the port, ZPA
  uses the most specific domain match: an exact FQDN beats a wildcard,
  a longer wildcard suffix beats a shorter one, and for IP destinations
  the longest prefix wins. A wildcard "*.example.com" matches subdomains
  of example.com, not example.com itself. Among equally specific domains
  the narrowest port range containing the port is taken; a remaining tie
  is reported as ambiguous. Segments set to INCLUSIVE (multimatch) are
  noted: ZPA may evaluate them together, which this tool does not model.
- Connector status ZPN_STATUS_AUTHENTICATED (controlChannelStatus) is
  connected; anything else reported is not.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SEVERITIES = ("high", "medium", "low", "info")
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}
TERMINAL_ACCESS = ("ALLOW", "DENY", "REQUIRE_APPROVAL")
APP_TYPES = ("APP", "APP_GROUP")
STALE_DAYS = 7
WIDE_PORT_SPAN = 1000
# Ports whose segments are treated as critical for health reporting:
# directory, DNS, Kerberos, SMB, RDP, SSH and common databases.
CRITICAL_PORTS = (22, 53, 88, 135, 389, 445, 636, 1433, 1521, 3268, 3269, 3306, 3389, 5432)
CRITICAL_NAME = re.compile(r"\b(prod|production|critical|core|domain controller|active directory)\b", re.I)
# Cleartext protocols: FTP, Telnet, HTTP, POP3, IMAP, SNMP, LDAP.
CLEARTEXT_PORTS = {21: "FTP", 23: "Telnet", 80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 389: "LDAP"}
WEB_PORTS = (80, 443, 8080, 8443)
CLIENT_TYPES = {
    "zpn_client_type_zapp": "Client Connector",
    "zpn_client_type_exporter": "Browser Access",
    "zpn_client_type_browser_isolation": "Cloud Browser Isolation",
    "zpn_client_type_machine_tunnel": "machine tunnel",
    "zpn_client_type_edge_connector": "Cloud Connector",
    "zpn_client_type_branch_connector": "Branch Connector",
    "zpn_client_type_zapp_partner": "Client Connector (partner)",
}
PLATFORMS = ("windows", "mac", "linux", "ios", "android", "chromeos")

# ── the catalog ─────────────────────────────────────────────────────────
# needs: snapshot collections a template reads ("policy:access" is the
# access policy); if one was not read the template is not assessed.
CATALOG: List[Dict[str, Any]] = [
    {"id": "ZPA-AP-01", "title": "Unreachable access rule", "severity": "high", "scope": "Access policy",
     "checks": "An enabled access rule that an earlier enabled rule always matches first: the earlier rule's conditions are a superset of this rule's, so this rule never decides. Only rules whose every condition can be compared are judged; anything that cannot be compared counts as reachable. High when the actions differ, medium when they agree.",
     "needs": ["policy:access", "segments"]},
    {"id": "ZPA-AP-02", "title": "Access rule names a deleted or disabled object", "severity": "medium", "scope": "Access policy",
     "checks": "Access rule conditions that name an app segment, segment group, SCIM group, SAML attribute, posture profile, trusted network, machine group or IdP that no longer exists or is disabled, and rule server or connector groups that no longer exist.",
     "needs": ["policy:access"]},
    {"id": "ZPA-AP-03", "title": "Identity condition on a disabled IdP", "severity": "medium", "scope": "Access policy",
     "checks": "SCIM group, SCIM attribute, SAML attribute or IdP conditions whose IdP is disabled, has SCIM-based policy off (SCIM conditions) or has SAML-based policy disabled (SAML conditions): the condition can never be met.",
     "needs": ["policy:access", "idps"]},
    {"id": "ZPA-AP-04", "title": "Catch-all allow", "severity": "high", "scope": "Access policy",
     "checks": "An enabled ALLOW rule with no user, group, posture, network or client condition: every authenticated user reaches the applications it names (every application when it names none).",
     "needs": ["policy:access"]},
    {"id": "ZPA-AP-05", "title": "No explicit default deny", "severity": "low", "scope": "Access policy",
     "checks": "The last enabled access rule is not a DENY with no conditions. ZPA denies what no rule allows, but an explicit final deny makes that intent visible and reviewable.",
     "needs": ["policy:access"]},
    {"id": "ZPA-AP-06", "title": "Policy rule with no conditions", "severity": "low", "scope": "Timeout, client forwarding, inspection and isolation policies",
     "checks": "A non-default enabled rule with no conditions in the timeout, client forwarding, inspection or isolation policy: it applies to every user and application, and every rule below it is unreachable. Medium when the action bypasses (inspection, isolation or forwarding).",
     "needs": []},
    {"id": "ZPA-AP-07", "title": "No access rules", "severity": "medium", "scope": "Access policy",
     "checks": "App segments exist but the access policy has no enabled rule, so ZPA denies every private application to everyone.",
     "needs": ["policy:access", "segments"]},
    {"id": "ZPA-AS-01", "title": "App segment no access rule reaches", "severity": "medium", "scope": "App segments",
     "checks": "An enabled app segment that no enabled access rule applies to (by segment, by its segment group, or by having no application condition): nobody can use it.",
     "needs": ["policy:access", "segments"]},
    {"id": "ZPA-AS-02", "title": "App segment only deny rules reach", "severity": "low", "scope": "App segments",
     "checks": "An enabled app segment that only DENY rules apply to: it is configured but always blocked.",
     "needs": ["policy:access", "segments"]},
    {"id": "ZPA-AS-03", "title": "Overlapping app segments", "severity": "medium", "scope": "App segments",
     "checks": "The same domain or address in two enabled segments with overlapping ports on the same protocol: which segment, and so which access rule and server group, applies is ambiguous.",
     "needs": ["segments"]},
    {"id": "ZPA-AS-04", "title": "Over-broad domain or subnet", "severity": "high", "scope": "App segments",
     "checks": "A domain entry of \"*\", a wildcard on a top-level domain (*.com), 0.0.0.0/0 or ::/0, an IPv4 subnet of /16 or wider (/8 or wider is high), or an IPv6 subnet of /48 or wider (/32 or wider is high).",
     "needs": ["segments"]},
    {"id": "ZPA-AS-05", "title": "Very wide port range", "severity": "medium", "scope": "App segments",
     "checks": "A TCP or UDP range of 1-65535 (medium), or one spanning more than 1,000 ports (low).",
     "needs": ["segments"]},
    {"id": "ZPA-AS-06", "title": "Segment bypasses ZPA", "severity": "high", "scope": "App segments",
     "checks": "Bypass type ALWAYS (the client never sends this traffic through ZPA: high) or ON_NET (bypassed on a trusted network: low).",
     "needs": ["segments"]},
    {"id": "ZPA-AS-07", "title": "Health reporting off on a critical segment", "severity": "medium", "scope": "App segments",
     "checks": "Health reporting NONE on an enabled segment that serves directory, DNS, Kerberos, SMB, RDP, SSH or database ports, or whose name says production or critical: an outage is not reported to users or admins.",
     "needs": ["segments"]},
    {"id": "ZPA-AS-08", "title": "App segment with no server group", "severity": "high", "scope": "App segments",
     "checks": "An enabled segment with no server group, or whose every server group was deleted or is disabled: no App Connector serves it.",
     "needs": ["segments"]},
    {"id": "ZPA-AS-09", "title": "Web segment outside AppProtection inspection", "severity": "medium", "scope": "App segments and inspection policy",
     "checks": "The inspection (AppProtection) policy has enabled INSPECT rules, but an enabled segment serving web ports (80, 443, 8080, 8443) is reached by none of them.",
     "needs": ["segments", "policy:inspection"]},
    {"id": "ZPA-AS-10", "title": "Cleartext protocol without double encryption", "severity": "low", "scope": "App segments",
     "checks": "An enabled segment serving FTP, Telnet, HTTP, POP3, IMAP, SNMP or LDAP ports with double encryption off. ZPA's tunnels are already TLS; double encryption also keeps the ZPA cloud from seeing the cleartext.",
     "needs": ["segments"]},
    {"id": "ZPA-SG-01", "title": "Empty or disabled segment group", "severity": "low", "scope": "Segment groups",
     "checks": "A segment group with no app segment, or a disabled one that still holds segments (medium).",
     "needs": ["segment_groups"]},
    {"id": "ZPA-SV-01", "title": "Server group with no servers and dynamic discovery off", "severity": "high", "scope": "Server groups",
     "checks": "Dynamic discovery is off and no enabled server is listed: the segments using it have nothing to connect to.",
     "needs": ["server_groups"]},
    {"id": "ZPA-SV-02", "title": "Server group with no connector group", "severity": "high", "scope": "Server groups",
     "checks": "No App Connector group is attached, or every attached group was deleted: no connector can reach its servers.",
     "needs": ["server_groups"]},
    {"id": "ZPA-CG-01", "title": "Connector group with no connectors", "severity": "high", "scope": "App Connector groups",
     "checks": "An App Connector group with no connector (high when a server group uses it, low otherwise).",
     "needs": ["connector_groups", "connectors"]},
    {"id": "ZPA-CG-02", "title": "Every connector in the group disconnected", "severity": "high", "scope": "App Connector groups",
     "checks": "Every connector of the group reports a status other than ZPN_STATUS_AUTHENTICATED.",
     "needs": ["connector_groups", "connectors"]},
    {"id": "ZPA-CG-03", "title": "Single connector: no redundancy", "severity": "medium", "scope": "App Connector groups",
     "checks": "A connector group with exactly one connector: an upgrade or outage of that one connector takes its applications down (Zscaler recommends N+1).",
     "needs": ["connector_groups", "connectors"]},
    {"id": "ZPA-CG-04", "title": "Mixed or outdated connector versions", "severity": "low", "scope": "App Connector groups",
     "checks": "Connectors in one group run different versions, or a connector's current version differs from its expected version.",
     "needs": ["connector_groups", "connectors"]},
    {"id": "ZPA-AC-01", "title": "Connector not seen recently", "severity": "medium", "scope": "App Connectors",
     "checks": "An enabled connector that is not connected and was last connected more than 7 days ago (or never).",
     "needs": ["connectors"]},
    {"id": "ZPA-SE-01", "title": "Private Service Edge group not serving", "severity": "medium", "scope": "Private Service Edges",
     "checks": "An enabled Private Service Edge group with no service edge, or whose every edge is disconnected.",
     "needs": ["service_edge_groups"]},
]
CATALOG_BY_ID = {c["id"]: c for c in CATALOG}


# ── indexes over a snapshot ─────────────────────────────────────────────
def _lst(snap: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    return snap.get(key) or []


def _by_id(items: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {x["id"]: x for x in items if x.get("id")}


class _Index:
    def __init__(self, snap: Dict[str, Any]):
        self.snap = snap
        self.segments = _by_id(_lst(snap, "segments"))
        self.segment_groups = _by_id(_lst(snap, "segment_groups"))
        self.server_groups = _by_id(_lst(snap, "server_groups"))
        self.connector_groups = _by_id(_lst(snap, "connector_groups"))
        self.idps = _by_id(_lst(snap, "idps"))
        self.saml = _by_id(_lst(snap, "saml_attributes"))
        self.posture = _by_id(_lst(snap, "posture_profiles"))
        self.posture_udid = {p.get("posture_udid"): p for p in _lst(snap, "posture_profiles") if p.get("posture_udid")}
        self.trusted = _by_id(_lst(snap, "trusted_networks"))
        self.trusted_nid = {t.get("network_id"): t for t in _lst(snap, "trusted_networks") if t.get("network_id")}
        self.machine = _by_id(_lst(snap, "machine_groups"))
        self.scim: Dict[str, Dict[str, Any]] = {}
        for idp_id, v in (snap.get("scim_groups") or {}).items():
            for g in v.get("groups") or []:
                self.scim[g["id"]] = dict(g, idp_id=idp_id)
        # Segments per group: the segment's own segmentGroupId, plus the group's
        # applications list when the API gave it.
        self.group_segments: Dict[str, Set[str]] = {}
        for s in self.segments.values():
            if s.get("segment_group_id"):
                self.group_segments.setdefault(s["segment_group_id"], set()).add(s["id"])
        for g in self.segment_groups.values():
            for a in g.get("application_ids") or []:
                self.group_segments.setdefault(g["id"], set()).add(a)
        self.connectors_by_group: Dict[str, List[Dict[str, Any]]] = {}
        for c in _lst(snap, "connectors"):
            if c.get("group_id"):
                self.connectors_by_group.setdefault(c["group_id"], []).append(c)
        for g in self.connector_groups.values():
            if g["id"] not in self.connectors_by_group and g.get("embedded_connectors"):
                self.connectors_by_group[g["id"]] = list(g["embedded_connectors"])

    def read(self, key: str) -> bool:
        c = (self.snap.get("collections") or {}).get(key)
        return bool(c and c.get("read"))

    def complete(self, key: str) -> bool:
        c = (self.snap.get("collections") or {}).get(key)
        return bool(c and c.get("read") and c.get("complete"))

    def segment_name(self, sid: str) -> str:
        s = self.segments.get(sid)
        return s["name"] if s else f"segment {sid}"

    def group_name(self, gid: str) -> str:
        g = self.segment_groups.get(gid)
        return g["name"] if g else f"segment group {gid}"

    def operand_label(self, o: Dict[str, Any]) -> str:
        """A person's words for one operand."""
        t, lhs, rhs, name = o["type"], o["lhs"], o["rhs"], o.get("name") or ""
        if t == "APP":
            return f"app segment {self.segments[rhs]['name'] if rhs in self.segments else (name or rhs)}"
        if t == "APP_GROUP":
            return f"segment group {self.segment_groups[rhs]['name'] if rhs in self.segment_groups else (name or rhs)}"
        if t == "SCIM_GROUP":
            g = self.scim.get(rhs)
            idp = self.idps.get(lhs)
            via = f" ({idp['name']})" if idp else ""
            return f"SCIM group {g['name'] if g else (name or rhs)}{via}"
        if t in ("SAML", "SCIM"):
            a = self.saml.get(lhs) if t == "SAML" else None
            return f"{t} attribute {a['name'] if a else (name or lhs)} = {rhs}"
        if t == "IDP":
            i = self.idps.get(rhs)
            return f"IdP {i['name'] if i else (name or rhs)}"
        if t == "POSTURE":
            p = self.posture_udid.get(lhs) or self.posture.get(lhs)
            return f"posture {p['name'] if p else (name or lhs)} {'passes' if rhs.lower() == 'true' else 'fails'}"
        if t == "TRUSTED_NETWORK":
            n = self.trusted_nid.get(lhs) or self.trusted.get(lhs)
            return f"{'on' if rhs.lower() == 'true' else 'not on'} trusted network {n['name'] if n else (name or lhs)}"
        if t == "CLIENT_TYPE":
            return f"client type {CLIENT_TYPES.get(rhs, rhs)}"
        if t == "PLATFORM":
            return f"platform {lhs}"
        if t == "COUNTRY_CODE":
            return f"country {lhs}"
        if t == "MACHINE_GRP":
            m = self.machine.get(rhs)
            return f"machine group {m['name'] if m else (name or rhs)}"
        return f"{t.lower().replace('_', ' ')} {name or rhs or lhs}".strip()


# ── rule shape helpers ──────────────────────────────────────────────────
def _enabled_rules(snap: Dict[str, Any], policy: str) -> List[Dict[str, Any]]:
    return [r for r in (snap.get("policies") or {}).get(policy) or [] if not r.get("disabled")]


def _tok(o: Dict[str, Any]) -> Tuple[str, ...]:
    if o["type"] in APP_TYPES:
        return (o["type"], o["rhs"])
    return (o["type"], o["lhs"].lower(), o["rhs"].lower())


def _is_app_cond(c: Dict[str, Any]) -> bool:
    return bool(c["operands"]) and all(o["type"] in APP_TYPES for o in c["operands"])


def _has_app_operand(c: Dict[str, Any]) -> bool:
    return any(o["type"] in APP_TYPES for o in c["operands"])


# While analyze() runs, the shape of each rule is worked out once, not once
# per pair of rules or per segment (thousands of access rules would cost
# minutes otherwise). Per thread, so two analyses never share it.
_MEMO = threading.local()


def _memo(kind: str, rule: Dict[str, Any], fn):
    cache = getattr(_MEMO, "cache", None)
    if cache is None:
        return fn(rule)
    key = (kind, id(rule))
    hit = cache.get(key)
    if hit is not None and hit[0] is rule:
        return hit[1]
    out = fn(rule)
    cache[key] = (rule, out)   # the rule is held, so its id is not reused while the cache lives
    return out


def _app_scope(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """{"all": True} when the rule names no application; {"segments", "groups",
    "negated"} otherwise; None when the app conditions are not a plain shape."""
    return _memo("scope", rule, _app_scope_of)


def _app_scope_of(rule: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    conds = [c for c in rule["conditions"] if _has_app_operand(c)]
    if not conds:
        return {"all": True}
    if len(conds) > 1 or not _is_app_cond(conds[0]):
        return None
    c = conds[0]
    if c["operator"] == "AND" and len(c["operands"]) > 1:
        return None
    return {"all": False, "negated": c["negated"], "segments": {o["rhs"] for o in c["operands"] if o["type"] == "APP"},
            "groups": {o["rhs"] for o in c["operands"] if o["type"] == "APP_GROUP"}}


def _reaches(rule: Dict[str, Any], seg: Dict[str, Any]) -> bool:
    """Whether the rule can apply to this segment (generous: an unclear
    shape counts as reaching, so 'unused' is never claimed wrongly)."""
    sc = _app_scope(rule)
    if sc is None or sc.get("all"):
        return True
    named = seg["id"] in sc["segments"] or (seg.get("segment_group_id") and seg["segment_group_id"] in sc["groups"])
    return (not named) if sc["negated"] else bool(named)


def _user_conditions(rule: Dict[str, Any]) -> List[Dict[str, Any]]:
    return _memo("users", rule, lambda r: [c for c in r["conditions"] if not _is_app_cond(c) and c["operands"]])


# ── unreachable rules (strict: anything not comparable is reachable) ────
def _app_superset(a: Dict[str, Any], b: Dict[str, Any], ix: _Index) -> bool:
    """Every application B can apply to, A applies to as well."""
    if a.get("all"):
        return True
    if b.get("all") or a.get("negated") or b.get("negated"):
        return False
    for s in b["segments"]:
        if s in a["segments"]:
            continue
        seg = ix.segments.get(s)
        if seg and seg.get("segment_group_id") and seg["segment_group_id"] in a["groups"]:
            continue
        return False
    return all(g in a["groups"] for g in b["groups"])


def _forced(conds: List[Dict[str, Any]]) -> Set[Tuple[str, ...]]:
    """Tokens every request matching these AND-ed conditions must carry."""
    out: Set[Tuple[str, ...]] = set()
    for c in conds:
        if c["negated"]:
            continue
        toks = {_tok(o) for o in c["operands"]}
        if c["operator"] == "AND" or len(toks) == 1:
            out |= toks
    return out


def _implied(ca: Dict[str, Any], b_conds: List[Dict[str, Any]]) -> bool:
    """Whether every request matching B's (AND-ed) conditions meets A's condition ca."""
    ta = {_tok(o) for o in ca["operands"]}
    if not ta:
        return False
    if ca["negated"]:
        return any(cb["negated"] and cb["operator"] == ca["operator"] and {_tok(o) for o in cb["operands"]} == ta for cb in b_conds)
    forced = _forced(b_conds)
    if ca["operator"] == "AND":
        return ta <= forced
    if ta & forced:
        return True
    return any(not cb["negated"] and cb["operator"] != "AND" and cb["operands"] and {_tok(o) for o in cb["operands"]} <= ta for cb in b_conds)


def shadows(a: Dict[str, Any], b: Dict[str, Any], ix: _Index) -> bool:
    """True only when earlier enabled rule A provably matches every request
    later rule B matches. Every unclear case answers False."""
    if a.get("disabled") or b.get("disabled") or a["action"] not in TERMINAL_ACCESS:
        return False
    if (a.get("microtenant_id") or "") != (b.get("microtenant_id") or ""):
        return False
    sa, sb = _app_scope(a), _app_scope(b)
    if sa is None or sb is None:
        return False
    ua, ub = _user_conditions(a), _user_conditions(b)
    if any(not c["operands"] for c in a["conditions"] + b["conditions"]):
        return False
    # Rule-level OR joins conditions: only the trivial shapes are compared.
    if b["operator"] == "OR" and len(b["conditions"]) > 1:
        return False
    if a["operator"] == "OR" and len(a["conditions"]) > 1:
        return False
    if not _app_superset(sa, sb, ix):
        return False
    return all(_implied(ca, ub) for ca in ua)


def _shadow_candidates(rules: List[Dict[str, Any]], ix: _Index):
    """A function giving, for rule b, the indexes of the rules that can
    cover b's applications at all (what _app_superset needs): those naming
    every application, those naming b's first segment or its segment group,
    or b's first group. Every other earlier rule fails shadows() on its
    applications, so it is not compared: thousands of access rules then
    cost a comparison per plausible pair, not per pair."""
    broad: List[int] = []
    by_seg: Dict[str, List[int]] = {}
    by_group: Dict[str, List[int]] = {}
    plain: List[int] = []
    for k, a in enumerate(rules):
        sc = _app_scope(a)
        if a.get("disabled") or a["action"] not in TERMINAL_ACCESS or sc is None:
            continue
        if sc.get("all"):
            broad.append(k)
            continue
        if sc["negated"]:
            continue
        plain.append(k)
        for x in sc["segments"]:
            by_seg.setdefault(x, []).append(k)
        for g in sc["groups"]:
            by_group.setdefault(g, []).append(k)

    def candidates(b: Dict[str, Any], j: int) -> List[int]:
        sb = _app_scope(b)
        if sb is None:
            return []
        if sb.get("all") or sb["negated"]:
            pool = broad
        elif sb["segments"]:
            first = sorted(sb["segments"])[0]
            seg = ix.segments.get(first)
            pool = broad + by_seg.get(first, []) + (by_group.get(seg["segment_group_id"], []) if seg and seg.get("segment_group_id") else [])
        elif sb["groups"]:
            pool = broad + by_group.get(sorted(sb["groups"])[0], [])
        else:
            pool = broad + plain
        return sorted({k for k in pool if k < j})
    return candidates


def _shadowed(snap: Dict[str, Any], ix: _Index) -> List[Dict[str, Any]]:
    out = []
    rules = _enabled_rules(snap, "access")
    candidates = _shadow_candidates(rules, ix)
    for j, b in enumerate(rules):
        if b.get("default_rule"):
            continue
        for k in candidates(b, j):
            a = rules[k]
            if shadows(a, b, ix):
                differ = a["action"] != b["action"]
                out.append(_finding("ZPA-AP-01", "high" if differ else "medium", b["name"], "access rule", b["id"],
                                    f"Access rule \"{b['name']}\" ({b['action']}) never decides: the earlier rule \"{a['name']}\" ({a['action']}) matches every request it would match"
                                    + (", so it has the opposite effect of what this rule says." if differ else "."),
                                    f"Move \"{b['name']}\" above \"{a['name']}\", narrow \"{a['name']}\", or delete \"{b['name']}\" if it is no longer needed.",
                                    shadowed_by=a["name"]))
                break
    return out


# ── findings helpers ────────────────────────────────────────────────────
def _finding(tid: str, severity: str, obj: str, obj_type: str, obj_id: str, reason: str, fix: str, **extra: Any) -> Dict[str, Any]:
    f = {"template": tid, "title": CATALOG_BY_ID[tid]["title"], "severity": severity, "object": obj, "object_type": obj_type,
         "object_id": obj_id, "reason": reason, "fix": fix}
    f.update(extra)
    return f


def _and_list(items: Iterable[str]) -> str:
    items = [x for x in items if x]
    if not items:
        return ""
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _names(items: Iterable[str], n: int = 4) -> str:
    items = [x for x in items if x]
    head = ", ".join(items[:n])
    return head + (f" and {len(items) - n} more" if len(items) > n else "")


def _ports_text(ranges: List[List[int]]) -> str:
    return ", ".join(f"{a}" if a == b else f"{a}-{b}" for a, b in ranges) or "none"


def _serves_port(seg: Dict[str, Any], ports: Iterable[int], proto: str = "tcp") -> List[int]:
    return [p for p in ports if any(a <= p <= b for a, b in seg.get(proto) or [])]


# ── the templates ───────────────────────────────────────────────────────
def _t_dangling(snap, ix):
    out = []
    checks = {
        "APP": ("segments", ix.segments, "app segment"),
        "APP_GROUP": ("segment_groups", ix.segment_groups, "segment group"),
        "MACHINE_GRP": ("machine_groups", ix.machine, "machine group"),
        "IDP": ("idps", ix.idps, "IdP"),
    }
    for r in _enabled_rules(snap, "access"):
        gone, off = [], []
        for c in r["conditions"]:
            for o in c["operands"]:
                t = o["type"]
                if t in checks:
                    key, idx, label = checks[t]
                    if not ix.complete(key):
                        continue
                    obj = idx.get(o["rhs"])
                    if obj is None:
                        gone.append(f"{label} {o.get('name') or o['rhs']}")
                    elif obj.get("enabled") is False:
                        off.append(f"{label} {obj['name']}")
                elif t == "SCIM_GROUP":
                    v = (snap.get("scim_groups") or {}).get(o["lhs"])
                    if v and v.get("complete") and o["rhs"] not in {g["id"] for g in v.get("groups") or []}:
                        gone.append(f"SCIM group {o.get('name') or o['rhs']}")
                elif t == "SAML" and ix.complete("saml_attributes") and o["lhs"] not in ix.saml:
                    gone.append(f"SAML attribute {o.get('name') or o['lhs']}")
                elif t == "POSTURE" and ix.complete("posture_profiles") and o["lhs"] not in ix.posture_udid and o["lhs"] not in ix.posture:
                    gone.append(f"posture profile {o.get('name') or o['lhs']}")
                elif t == "TRUSTED_NETWORK" and ix.complete("trusted_networks") and o["lhs"] not in ix.trusted_nid and o["lhs"] not in ix.trusted:
                    gone.append(f"trusted network {o.get('name') or o['lhs']}")
        if ix.complete("server_groups"):
            gone += [f"server group {g}" for g in r.get("server_group_ids") or [] if g not in ix.server_groups]
        if ix.complete("connector_groups"):
            gone += [f"connector group {g}" for g in r.get("connector_group_ids") or [] if g not in ix.connector_groups]
        if gone or off:
            parts = ([f"names {_names(gone)}, which no longer exist{'s' if len(gone) == 1 else ''}"] if gone else []) + \
                    ([f"names {_names(off)}, which {'is' if len(off) == 1 else 'are'} disabled"] if off else [])
            out.append(_finding("ZPA-AP-02", "medium", r["name"], "access rule", r["id"],
                                f"Access rule \"{r['name']}\" " + " and ".join(parts) + ", so that part of the rule matches nothing.",
                                f"Edit \"{r['name']}\": remove or replace the missing or disabled objects, or delete the rule if it has no purpose left."))
    return out


def _t_idp(snap, ix):
    out = []
    for r in _enabled_rules(snap, "access"):
        bad = []
        for c in r["conditions"]:
            for o in c["operands"]:
                t, idp = o["type"], None
                if t == "SCIM_GROUP":
                    idp = ix.idps.get(o["lhs"]) or ix.idps.get(o.get("idp_id") or "")
                elif t in ("SAML", "SCIM"):
                    a = ix.saml.get(o["lhs"]) if t == "SAML" else None
                    idp = ix.idps.get((a or {}).get("idp_id") or o.get("idp_id") or "")
                elif t == "IDP":
                    idp = ix.idps.get(o["rhs"])
                if not idp:
                    continue
                if idp.get("enabled") is False:
                    bad.append(f"{ix.operand_label(o)}: IdP {idp['name']} is disabled")
                elif t in ("SCIM_GROUP", "SCIM") and idp.get("scim_policy") is False:
                    bad.append(f"{ix.operand_label(o)}: IdP {idp['name']} has SCIM-based policy off")
                elif t == "SAML" and idp.get("saml_policy_disabled") is True:
                    bad.append(f"{ix.operand_label(o)}: IdP {idp['name']} has SAML-based policy disabled")
        if bad:
            out.append(_finding("ZPA-AP-03", "medium", r["name"], "access rule", r["id"],
                                f"Access rule \"{r['name']}\" depends on {_names(sorted(set(bad)), 3)}, so that condition can never be met.",
                                "Enable the IdP (or its SCIM / SAML-based policy), or change the rule to use an IdP that is in use."))
    return out


def _t_catch_all(snap, ix):
    out = []
    for r in _enabled_rules(snap, "access"):
        if r["action"] != "ALLOW" or _user_conditions(r):
            continue
        sc = _app_scope(r)
        if sc is None:
            continue
        if sc.get("all") or (sc.get("negated")):
            out.append(_finding("ZPA-AP-04", "high", r["name"], "access rule", r["id"],
                                f"Access rule \"{r['name']}\" allows every authenticated user to every application, with no group, posture, network or client condition.",
                                "Add the SCIM groups or SAML attributes that should have access, and a posture or client type condition; keep broad access out of the access policy."))
        else:
            apps = [ix.segment_name(s) for s in sorted(sc["segments"])] + [ix.group_name(g) for g in sorted(sc["groups"])]
            out.append(_finding("ZPA-AP-04", "medium", r["name"], "access rule", r["id"],
                                f"Access rule \"{r['name']}\" allows every authenticated user to {_names(apps)} with no group, posture, network or client condition.",
                                "Limit the rule to the SCIM groups or SAML attributes that need these applications, and add a posture or client type condition."))
    return out


def _t_default_deny(snap, ix):
    rules = _enabled_rules(snap, "access")
    if not rules:
        return []
    last = rules[-1]
    if last["action"] == "DENY" and not [c for c in last["conditions"] if c["operands"]]:
        return []
    return [_finding("ZPA-AP-05", "low", "Access policy", "policy", "access",
                     f"The access policy does not end with a catch-all DENY rule (the last rule is \"{last['name']}\", {last['action']}); ZPA still denies what no rule allows, but nothing in the policy says so.",
                     "Add a last rule with action Block and no conditions, named for what it is (for example \"Default deny\").")]


_BYPASS_ACTIONS = ("BYPASS", "BYPASS_INSPECT", "BYPASS_ISOLATE")


def _t_no_conditions(snap, ix):
    out = []
    labels = {"timeout": "timeout", "client_forwarding": "client forwarding", "inspection": "inspection", "isolation": "isolation"}
    for policy, label in labels.items():
        rules = _enabled_rules(snap, policy)
        for i, r in enumerate(rules):
            if r.get("default_rule") or [c for c in r["conditions"] if c["operands"]]:
                continue
            below = len(rules) - i - 1
            sev = "medium" if r["action"] in _BYPASS_ACTIONS else "low"
            out.append(_finding("ZPA-AP-06", sev, r["name"], f"{label} rule", r["id"],
                                f"The {label} rule \"{r['name']}\" ({r['action'] or 'no action'}) has no conditions, so it applies to every user and application"
                                + (f" and the {below} rule{'s' if below != 1 else ''} below it never apply." if below else "."),
                                f"Add the application and user conditions this {label} rule is meant for, or make it the policy's last rule on purpose."))
    return out


def _t_no_access_rules(snap, ix):
    segs = [s for s in _lst(snap, "segments") if s["enabled"]]
    if not segs or _enabled_rules(snap, "access"):
        return []
    return [_finding("ZPA-AP-07", "medium", "Access policy", "policy", "access",
                     f"There {'is' if len(segs) == 1 else 'are'} {len(segs)} enabled app segment{'s' if len(segs) != 1 else ''} but no enabled access rule, so ZPA denies every private application to everyone.",
                     "Create access rules that allow each user group the segments it needs, ending with a catch-all deny.")]


def _reach_index(rules: List[Dict[str, Any]]):
    """A function giving, for a segment, the rules that reach it, in rule
    order: the same answer as [r for r in rules if _reaches(r, seg)], from
    an index of the segments and groups each rule names, so thousands of
    segments and rules are not compared pair by pair."""
    always: List[int] = []
    negated: List[Tuple[int, Dict[str, Any]]] = []
    by_seg: Dict[str, List[int]] = {}
    by_group: Dict[str, List[int]] = {}
    for k, r in enumerate(rules):
        sc = _app_scope(r)
        if sc is None or sc.get("all"):
            always.append(k)
        elif sc["negated"]:
            negated.append((k, sc))
        else:
            for x in sc["segments"]:
                by_seg.setdefault(x, []).append(k)
            for g in sc["groups"]:
                by_group.setdefault(g, []).append(k)

    def reaching(seg: Dict[str, Any]) -> List[Dict[str, Any]]:
        gid = seg.get("segment_group_id")
        ks = set(always) | set(by_seg.get(seg["id"], ())) | (set(by_group.get(gid, ())) if gid else set())
        ks |= {k for k, sc in negated if not (seg["id"] in sc["segments"] or (gid and gid in sc["groups"]))}
        return [rules[k] for k in sorted(ks)]
    return reaching


def _t_unused(snap, ix):
    out = []
    rules = _enabled_rules(snap, "access")
    if not rules:
        return out   # ZPA-AP-07 says it once
    reaching = _reach_index(rules)
    for s in _lst(snap, "segments"):
        if not s["enabled"]:
            continue
        hits = reaching(s)
        if not hits:
            out.append(_finding("ZPA-AS-01", "medium", s["name"], "app segment", s["id"],
                                f"No enabled access rule applies to app segment \"{s['name']}\" (by the segment or its segment group), so nobody can use it.",
                                "Add the segment (or its segment group) to an access rule for the users who need it, or disable the segment if it is retired."))
        elif all(r["action"] == "DENY" for r in hits):
            out.append(_finding("ZPA-AS-02", "low", s["name"], "app segment", s["id"],
                                f"Only DENY rules apply to app segment \"{s['name']}\" ({_names([r['name'] for r in hits], 3)}), so it is configured but always blocked.",
                                "If the segment is meant to be used, add an ALLOW rule above the deny; otherwise disable it so the intent is clear."))
    return out


def _idna(host: str) -> str:
    """A host name in its ASCII (punycode) form, as ZPA stores it; the text
    unchanged when it is ASCII already or cannot be encoded."""
    if host.isascii():
        return host
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _entry_key(d: str) -> str:
    return _idna(d.strip().lower().rstrip("."))


MAX_OVERLAP_FINDINGS = 200     # overlapping pairs listed; past it one finding says there are more
MAX_OVERLAP_PAIRS = 200_000    # pairs of segments compared at most (a domain shared by thousands of segments)


def _overlap_summary(reason: str) -> Dict[str, Any]:
    return _finding("ZPA-AS-03", "medium", "More app segments", "app segment", "", reason,
                    "Fix the pairs listed (keep each domain and port in one segment), then run the analysis again to see the rest.")


def _t_overlap(snap, ix):
    out, seen = [], set()
    segs = [s for s in _lst(snap, "segments") if s["enabled"]]
    by_domain: Dict[str, List[Dict[str, Any]]] = {}
    for s in segs:
        for d in {_entry_key(x) for x in s["domains"]}:
            by_domain.setdefault(d, []).append(s)
    # Every pair of segments sharing a domain is one finding, so a domain in
    # thousands of segments would make millions: the list stops at
    # MAX_OVERLAP_FINDINGS and the comparing at MAX_OVERLAP_PAIRS, and one
    # more finding says so.
    compared = 0
    for d, group in sorted(by_domain.items()):
        for i, a in enumerate(group):
            for b in group[i + 1:]:
                compared += 1
                if compared > MAX_OVERLAP_PAIRS:
                    out.append(_overlap_summary(f"Comparing stopped after {MAX_OVERLAP_PAIRS:,} pairs of app segments that share a domain: the "
                                                f"{len(out)} overlapping pairs found by then are listed and there may be more."))
                    return out
                for proto in ("tcp", "udp"):
                    ov = [(max(x[0], y[0]), min(x[1], y[1])) for x in a[proto] for y in b[proto] if max(x[0], y[0]) <= min(x[1], y[1])]
                    if not ov:
                        continue
                    key = (min(a["id"], b["id"]), max(a["id"], b["id"]), d)
                    if key in seen:
                        continue
                    if len(out) >= MAX_OVERLAP_FINDINGS:
                        out.append(_overlap_summary(f"More app segments overlap than are listed here: the first {len(out)} overlapping pairs are shown."))
                        return out
                    seen.add(key)
                    multimatch = "INCLUSIVE" in (a.get("match_style"), b.get("match_style"))
                    out.append(_finding("ZPA-AS-03", "medium", f"{a['name']} / {b['name']}", "app segment", a["id"],
                                        f"App segments \"{a['name']}\" and \"{b['name']}\" both contain \"{d}\" with overlapping {proto.upper()} ports ({_ports_text([list(x) for x in ov])}), so which segment, access rule and server group apply is ambiguous"
                                        + (" (one of them is set to INCLUSIVE multimatch)." if multimatch else "."),
                                        "Keep each domain and port in one segment: remove it from one of them or split the port ranges."))
                    break
    return out


_TLDISH = re.compile(r"^\*\.[a-z0-9-]+$|^\.[a-z0-9-]+$")


def _t_broad(snap, ix):
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"]:
            continue
        worst, why = None, []
        for d in s["domains"]:
            k = _entry_key(d)
            sev = None
            if k in ("*", "*.*", "0.0.0.0/0", "::/0"):
                sev, txt = "high", f"\"{d}\" matches everything"
            elif _TLDISH.match(k):
                sev, txt = "high", f"\"{d}\" matches a whole top-level domain"
            else:
                try:
                    net = ipaddress.ip_network(k, strict=False) if "/" in k else None
                except ValueError:
                    net = None
                medium, high = (16, 8) if net is not None and net.version == 4 else (48, 32)
                if net is not None and net.prefixlen <= medium:
                    sev = "high" if net.prefixlen <= high else "medium"
                    txt = f"\"{d}\" covers {net.num_addresses:,} addresses"
            if sev:
                why.append(txt)
                worst = sev if worst is None or SEV_RANK[sev] < SEV_RANK[worst] else worst
        if worst:
            out.append(_finding("ZPA-AS-04", worst, s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" is over-broad: {_names(why, 3)}, so any access rule that allows it opens far more than one application.",
                                "Replace the broad entry with the application's own FQDNs or a narrow subnet; use App Discovery to find what is really used."))
    return out


def _t_ports(snap, ix):
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"]:
            continue
        full, wide = [], []
        for proto in ("tcp", "udp"):
            for a, b in s[proto]:
                if a <= 1 and b >= 65535:
                    full.append(f"{proto.upper()} {a}-{b}")
                elif b - a + 1 > WIDE_PORT_SPAN:
                    wide.append(f"{proto.upper()} {a}-{b}")
        if full or wide:
            out.append(_finding("ZPA-AS-05", "medium" if full else "low", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" opens {_names(full + wide, 3)}, far more ports than one application needs.",
                                "List only the ports the application uses (for example 443, or 3389 for RDP)."))
    return out


def _t_bypass(snap, ix):
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"] or not s["bypass"]:
            continue
        if s["bypass_type"] == "ALWAYS":
            out.append(_finding("ZPA-AS-06", "high", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" has bypass set to ALWAYS, so Client Connector never sends this traffic through ZPA and no access rule applies to it.",
                                "Set bypass to NEVER unless the application is deliberately reached outside ZPA; then remove the segment."))
        else:
            out.append(_finding("ZPA-AS-06", "low", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" has bypass set to ON_NET, so on a trusted network the traffic goes direct and ZPA access rules do not apply there.",
                                "Confirm the on-network path is controlled elsewhere, or set bypass to NEVER so ZPA policy applies everywhere."))
    return out


def _t_health(snap, ix):
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"] or s["health_reporting"] != "NONE":
            continue
        ports = _serves_port(s, CRITICAL_PORTS) + _serves_port(s, CRITICAL_PORTS, "udp")
        named = bool(CRITICAL_NAME.search(s["name"]))
        if not ports and not named:
            continue
        why = f"serves port{'s' if len(set(ports)) > 1 else ''} {_names([str(p) for p in sorted(set(ports))], 5)}" if ports else "is named as production or critical"
        out.append(_finding("ZPA-AS-07", "medium", s["name"], "app segment", s["id"],
                            f"App segment \"{s['name']}\" {why} but has health reporting off, so users and admins are not told when its servers are unreachable.",
                            "Set health reporting to On Access (or Continuous for a small set of critical servers)."))
    return out


def _t_no_server_group(snap, ix):
    out = []
    sg_read = ix.complete("server_groups")
    for s in _lst(snap, "segments"):
        if not s["enabled"]:
            continue
        refs = s["server_groups"]
        if not refs:
            out.append(_finding("ZPA-AS-08", "high", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" has no server group, so no App Connector serves it and users cannot reach it.",
                                "Attach a server group whose connector group can reach the application's servers."))
        elif sg_read:
            live = [r for r in refs if r["id"] in ix.server_groups and ix.server_groups[r["id"]].get("enabled") is not False]
            if not live:
                out.append(_finding("ZPA-AS-08", "high", s["name"], "app segment", s["id"],
                                    f"Every server group of app segment \"{s['name']}\" ({_names([r['name'] or r['id'] for r in refs])}) is deleted or disabled, so no App Connector serves it.",
                                    "Attach an enabled server group, or enable the one it uses."))
    return out


def _t_inspection(snap, ix):
    rules = [r for r in _enabled_rules(snap, "inspection") if r["action"] == "INSPECT"]
    if not rules:
        return []
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"] or not _serves_port(s, WEB_PORTS):
            continue
        if not any(_reaches(r, s) for r in rules):
            out.append(_finding("ZPA-AS-09", "medium", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" serves web ports ({_names([str(p) for p in _serves_port(s, WEB_PORTS)])}) but no enabled INSPECT rule of the AppProtection policy applies to it, so its traffic is not inspected.",
                                "Add the segment or its segment group to an INSPECT rule, or document why it is exempt."))
    return out


def _t_cleartext(snap, ix):
    out = []
    for s in _lst(snap, "segments"):
        if not s["enabled"] or s.get("double_encrypt"):
            continue
        hits = sorted({CLEARTEXT_PORTS[p] for p in _serves_port(s, CLEARTEXT_PORTS) if p != 161} |
                      ({"SNMP"} if _serves_port(s, [161], "udp") else set()))
        if hits:
            out.append(_finding("ZPA-AS-10", "low", s["name"], "app segment", s["id"],
                                f"App segment \"{s['name']}\" carries cleartext {_names(hits)} with double encryption off, so the ZPA cloud handles that traffic unencrypted inside its own TLS tunnels.",
                                "Move the application to its encrypted protocol (HTTPS, LDAPS, SFTP), or turn on double encryption for this segment."))
    return out


def _t_segment_groups(snap, ix):
    out = []
    for g in _lst(snap, "segment_groups"):
        members = ix.group_segments.get(g["id"], set())
        if g.get("enabled") is False and members:
            out.append(_finding("ZPA-SG-01", "medium", g["name"], "segment group", g["id"],
                                f"Segment group \"{g['name']}\" is disabled but still holds {len(members)} app segment{'s' if len(members) != 1 else ''}; access rules that name the group do not give access to them.",
                                "Enable the group if its segments are in use, or move them to an enabled group and delete this one."))
        elif not members and ix.complete("segments"):
            out.append(_finding("ZPA-SG-01", "low", g["name"], "segment group", g["id"],
                                f"Segment group \"{g['name']}\" holds no app segment, so any access rule that names it gives access to nothing.",
                                "Delete the empty group, or move the intended segments into it."))
    return out


def _t_server_groups(snap, ix):
    out = []
    for g in _lst(snap, "server_groups"):
        if g.get("enabled") is False:
            continue
        servers = [s for s in g["servers"] if s["enabled"]]
        if g["dynamic_discovery"] is False and not servers:
            out.append(_finding("ZPA-SV-01", "high", g["name"], "server group", g["id"],
                                f"Server group \"{g['name']}\" has dynamic discovery off and no enabled server, so the segments using it have nothing to connect to.",
                                "Turn dynamic discovery on, or add the application's servers to the group."))
        cgs = g["connector_groups"]
        if not cgs or (ix.complete("connector_groups") and not [c for c in cgs if c["id"] in ix.connector_groups]):
            out.append(_finding("ZPA-SV-02", "high", g["name"], "server group", g["id"],
                                f"Server group \"{g['name']}\" has no {'existing ' if cgs else ''}App Connector group, so no connector can reach its servers.",
                                "Attach the App Connector group that sits next to the application's servers."))
    return out


def _vkey(v: str) -> Tuple:
    """A version as a sort key: numeric parts by value, the rest as text. Each
    part is (0, number) or (1, text), so tenant strings that mix the two
    always compare (int < str raises in Python)."""
    return tuple((0, int(x)) if re.fullmatch(r"[0-9]{1,18}", x) else (1, x) for x in re.split(r"[.\-]", v or ""))


def _t_connector_groups(snap, ix):
    out = []
    used = {c["id"] for g in _lst(snap, "server_groups") for c in g["connector_groups"]}
    for g in _lst(snap, "connector_groups"):
        if g.get("enabled") is False:
            continue
        cons = [c for c in ix.connectors_by_group.get(g["id"], []) if c.get("enabled") is not False]
        if not cons:
            sev = "high" if g["id"] in used else "low"
            out.append(_finding("ZPA-CG-01", sev, g["name"], "connector group", g["id"],
                                f"App Connector group \"{g['name']}\" has no connector" + (", yet a server group sends traffic to it." if sev == "high" else ".") ,
                                "Enroll at least two App Connectors in the group, or remove it from the server groups."))
            continue
        known = [c for c in cons if c["connected"] is not None]
        if known and len(known) == len(cons) and not any(c["connected"] for c in cons):
            out.append(_finding("ZPA-CG-02", "high", g["name"], "connector group", g["id"],
                                f"Every connector of App Connector group \"{g['name']}\" ({_names([c['name'] for c in cons])}) is disconnected, so its applications are down.",
                                "Check the connector hosts, their outbound access to the ZPA cloud and their enrollment certificates."))
        if len(cons) == 1:
            out.append(_finding("ZPA-CG-03", "medium", g["name"], "connector group", g["id"],
                                f"App Connector group \"{g['name']}\" has a single connector ({cons[0]['name']}), so an upgrade or outage of that one connector takes its applications down.",
                                "Add a second connector in the same location (N+1)."))
        versions = sorted({c["current_version"] for c in cons if c["current_version"]}, key=_vkey)
        behind = [c["name"] for c in cons if c["current_version"] and c["expected_version"] and c["current_version"] != c["expected_version"]]
        if len(versions) > 1 or behind:
            parts = ([f"runs {len(versions)} versions ({_names(versions)})"] if len(versions) > 1 else []) + \
                    ([f"has {_names(behind)} not on the expected version"] if behind else [])
            out.append(_finding("ZPA-CG-04", "low", g["name"], "connector group", g["id"],
                                f"App Connector group \"{g['name']}\" " + " and ".join(parts) + ".",
                                "Let the group's upgrade window complete, or check why a connector does not upgrade (disk, outbound access)."))
    return out


def _t_stale(snap, ix, now: float):
    out = []
    for c in _lst(snap, "connectors"):
        if c.get("enabled") is False or c["connected"] is not False:
            continue
        last = c.get("last_connect")
        age = (now - last) / 86400 if last else None
        if age is None or age > STALE_DAYS:
            out.append(_finding("ZPA-AC-01", "medium", c["name"], "connector", c["id"],
                                f"App Connector \"{c['name']}\" is disconnected and " + (f"was last connected {int(age)} days ago." if age is not None else "has no recorded connection time."),
                                "Bring the connector host back, or delete the connector so the group's capacity is not overstated."))
    return out


def _t_service_edges(snap, ix):
    out = []
    by_group: Dict[str, List[Dict[str, Any]]] = {}
    for e in _lst(snap, "service_edges"):
        if e.get("group_id"):
            by_group.setdefault(e["group_id"], []).append(e)
    for g in _lst(snap, "service_edge_groups"):
        if g.get("enabled") is False or g.get("is_public"):
            continue
        edges = [e for e in (by_group.get(g["id"]) or g.get("service_edges") or []) if e.get("enabled") is not False]
        if not edges:
            if not g.get("edges_listed") and not ix.read("service_edges"):
                continue
            out.append(_finding("ZPA-SE-01", "medium", g["name"], "service edge group", g["id"],
                                f"Private Service Edge group \"{g['name']}\" has no service edge, so it brokers nothing.",
                                "Enroll service edges in the group, or delete it."))
        elif all(e.get("connected") is False for e in edges):
            out.append(_finding("ZPA-SE-01", "medium", g["name"], "service edge group", g["id"],
                                f"Every Private Service Edge of group \"{g['name']}\" is disconnected, so clients fall back to the public ZPA cloud or fail.",
                                "Check the service edge hosts and their outbound access to the ZPA cloud."))
    return out


_TEMPLATES = {
    "ZPA-AP-01": _shadowed, "ZPA-AP-02": _t_dangling, "ZPA-AP-03": _t_idp, "ZPA-AP-04": _t_catch_all,
    "ZPA-AP-05": _t_default_deny, "ZPA-AP-06": _t_no_conditions, "ZPA-AP-07": _t_no_access_rules,
    "ZPA-AS-01": _t_unused, "ZPA-AS-03": _t_overlap, "ZPA-AS-04": _t_broad, "ZPA-AS-05": _t_ports,
    "ZPA-AS-06": _t_bypass, "ZPA-AS-07": _t_health, "ZPA-AS-08": _t_no_server_group, "ZPA-AS-09": _t_inspection,
    "ZPA-AS-10": _t_cleartext, "ZPA-SG-01": _t_segment_groups, "ZPA-SV-01": _t_server_groups,
    "ZPA-CG-01": _t_connector_groups, "ZPA-AC-01": _t_stale, "ZPA-SE-01": _t_service_edges,
}
# Templates produced by another template's function (same input).
_PRODUCED_BY = {"ZPA-AS-02": "ZPA-AS-01", "ZPA-SV-02": "ZPA-SV-01", "ZPA-CG-02": "ZPA-CG-01", "ZPA-CG-03": "ZPA-CG-01", "ZPA-CG-04": "ZPA-CG-01"}


def analyze(snap: Dict[str, Any], now: Optional[float] = None) -> Dict[str, Any]:
    """Every template over the snapshot: findings (most severe first),
    the catalog with each template's status, counts and what was not assessed."""
    _MEMO.cache = {}
    try:
        return _analyze(snap, now)
    finally:
        _MEMO.cache = None


def _analyze(snap: Dict[str, Any], now: Optional[float]) -> Dict[str, Any]:
    now = time.time() if now is None else now
    ix = _Index(snap)
    findings: List[Dict[str, Any]] = []
    status: Dict[str, str] = {}
    missing_for: Dict[str, List[str]] = {}
    for c in CATALOG:
        miss = [k for k in c["needs"] if not ix.read(k)]
        if c["id"] == "ZPA-AP-06" and not any(ix.read(f"policy:{p}") for p in ("timeout", "client_forwarding", "inspection", "isolation")):
            miss = ["policy:timeout"]
        missing_for[c["id"]] = miss
        status[c["id"]] = "not_assessed" if miss else "assessed"
    for tid, fn in _TEMPLATES.items():
        if status[tid] == "not_assessed":
            continue
        res = fn(snap, ix, now) if tid == "ZPA-AC-01" else fn(snap, ix)
        for f in res:
            if status.get(f["template"]) == "not_assessed":
                continue
            findings.append(f)
    findings.sort(key=lambda f: (SEV_RANK.get(f["severity"], 9), f["template"], f["object"].lower()))
    by_template: Dict[str, int] = {}
    by_sev = {s: 0 for s in SEVERITIES}
    for f in findings:
        by_template[f["template"]] = by_template.get(f["template"], 0) + 1
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    catalog = []
    for c in CATALOG:
        n = by_template.get(c["id"], 0)
        st = status[c["id"]]
        catalog.append({k: c[k] for k in ("id", "title", "severity", "scope", "checks")} |
                       {"status": "not_assessed" if st == "not_assessed" else ("findings" if n else "clean"), "findings": n,
                        "not_read": [_need_label(snap, k) for k in missing_for[c["id"]]]})
    not_assessed = [c for c in catalog if c["status"] == "not_assessed"]
    return {"findings": findings, "catalog": catalog, "not_assessed": not_assessed,
            "counts": {"total": len(findings), "by_severity": by_sev, "by_template": by_template,
                       "templates": len(CATALOG), "assessed": len(CATALOG) - len(not_assessed),
                       "with_findings": sum(1 for c in catalog if c["status"] == "findings")}}


def _need_label(snap: Dict[str, Any], key: str) -> str:
    c = (snap.get("collections") or {}).get(key) or {}
    return c.get("label") or key.replace("policy:", "").replace("_", " ")


# ── diagnostics ─────────────────────────────────────────────────────────
ASSUMPTIONS = [
    "Access rules are evaluated in rule order; the first enabled rule whose conditions all match decides, and no later rule is evaluated.",
    "When no access rule matches, ZPA denies access (deny by default).",
    "A rule's conditions are joined by the rule's operator (AND unless it says OR); a condition's operands by the condition's operator (OR unless it says AND); a negated condition is inverted.",
    "The app segment is the enabled segment with the most specific domain match (exact FQDN, then the longest wildcard suffix; for an IP address the longest prefix) whose port ranges contain the port; a tie is broken by the narrowest port range.",
    "A wildcard such as *.example.com matches subdomains of example.com, not example.com itself.",
    "SAML and SCIM attribute values are compared exactly, ignoring case; SCIM groups are matched by id or name.",
    "Conditions this tool cannot evaluate (location, risk score, Chrome Enterprise, console, branch or edge connector) are treated as depending on facts you did not give.",
]


def parse_destination(dest: str, port: Any = None, protocol: str = "tcp") -> Dict[str, Any]:
    """{input, host, is_ip, port, protocol, port_assumed}; ValueError with a
    plain message when the destination cannot be used."""
    raw = (dest or "").strip()
    if not raw:
        raise ValueError("Type a destination: an FQDN such as git.corp.example or an IP address.")
    if len(raw) > 300:
        raise ValueError("The destination is too long.")
    proto = (protocol or "tcp").strip().lower()
    if proto not in ("tcp", "udp"):
        raise ValueError("The protocol must be TCP or UDP.")
    scheme = ""
    m = re.match(r"^([a-z][a-z0-9+.-]*)://", raw, re.I)
    rest = raw
    if m:
        scheme, rest = m.group(1).lower(), raw[m.end():]
    rest = rest.split("/")[0].split("?")[0].split("#")[0]
    if "@" in rest:
        rest = rest.split("@", 1)[1]
    host, inline_port = rest, None
    if rest.startswith("["):
        host = rest[1:rest.index("]")] if "]" in rest else rest[1:]
        tail = rest[rest.index("]") + 1:] if "]" in rest else ""
        if re.fullmatch(r":[0-9]{1,6}", tail):
            inline_port = int(tail[1:])
        elif tail:
            raise ValueError("The port must be a number from 1 to 65535.")
    elif rest.count(":") == 1:
        h, p = rest.split(":")
        if re.fullmatch(r"[0-9]{1,6}", p):
            host, inline_port = h, int(p)
    host = host.strip().lower().rstrip(".")
    if not host.isascii():
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(f"\"{host[:80]}\" is not a hostname or IP address.")
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if not re.match(r"^[a-z0-9_*]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$", host):
            raise ValueError(f"\"{host[:80]}\" is not a hostname or IP address.")
    port_assumed = False
    p = None
    if port not in (None, ""):
        try:
            ps = str(port).strip()
            if not re.fullmatch(r"[0-9]{1,6}", ps):
                raise ValueError(ps)
            p = int(ps)
        except ValueError:
            raise ValueError("The port must be a number from 1 to 65535.")
    elif inline_port is not None:
        p = inline_port
    else:
        by_scheme = {"http": 80, "https": 443, "ssh": 22, "rdp": 3389, "ftp": 21}
        p = by_scheme.get(scheme, 443)
        port_assumed = scheme not in by_scheme
    if not 1 <= p <= 65535:
        raise ValueError("The port must be a number from 1 to 65535.")
    return {"input": raw, "host": host, "is_ip": is_ip, "port": p, "protocol": proto, "port_assumed": port_assumed}


def _domain_match(entry: str, host: str, is_ip: bool) -> Optional[Tuple[int, int]]:
    """Specificity of `entry` for `host` (higher is more specific), or None."""
    e = _entry_key(entry)
    if not e:
        return None
    if is_ip:
        try:
            net = ipaddress.ip_network(e, strict=False)
            ip = ipaddress.ip_address(host)
        except ValueError:
            return None
        if ip.version == net.version and ip in net:
            return (3, net.prefixlen)
        return None
    if e == host:
        return (3, 1000)
    if e in ("*", "*.*"):
        return (1, 0)
    suffix = e[2:] if e.startswith("*.") else (e[1:] if e.startswith(".") else None)
    if suffix and host.endswith("." + suffix):
        return (2, suffix.count(".") + 1)
    return None


def match_segment(snap: Dict[str, Any], d: Dict[str, Any]) -> Dict[str, Any]:
    """The app segment ZPA would use for the destination (see ASSUMPTIONS)."""
    host, port, proto = d["host"], d["port"], d["protocol"]
    cands, near, disabled = [], [], []
    for s in _lst(snap, "segments"):
        best = None
        for entry in s["domains"]:
            m = _domain_match(entry, host, d["is_ip"])
            if m and (best is None or m > best[0]):
                best = (m, entry)
        if not best:
            continue
        ranges = [r for r in s.get(proto) or [] if r[0] <= port <= r[1]]
        info = {"id": s["id"], "name": s["name"], "entry": best[1], "specificity": list(best[0]),
                "ports": _ports_text(s.get(proto) or []), "match_style": s.get("match_style") or ""}
        if not s["enabled"]:
            disabled.append(info)
        elif not ranges:
            near.append(info)
        else:
            info["span"] = min(r[1] - r[0] for r in ranges)
            cands.append(info)
    cands.sort(key=lambda c: (-c["specificity"][0], -c["specificity"][1], c["span"], c["name"].lower()))
    chosen = cands[0] if cands else None
    ambiguous = [c for c in cands[1:] if chosen and c["specificity"] == chosen["specificity"] and c["span"] == chosen["span"]]
    return {"match": chosen, "candidates": cands, "near_misses": near, "disabled": disabled, "ambiguous": ambiguous}


def _norm_user(user: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The user context with None for "any" (not given)."""
    u = dict(user or {})

    def lst(v):
        if v is None:
            return None
        if isinstance(v, str):
            v = [x for x in re.split(r"[,\n]", v)]
        out = [str(x).strip() for x in v if str(x).strip()]
        return out

    def one(v):
        s = str(v).strip() if v is not None else ""
        return None if not s or s.lower() == "any" else s

    saml = u.get("saml")
    if isinstance(saml, str):
        pairs = {}
        for line in re.split(r"[\n;]", saml):
            if "=" in line:
                k, v = line.split("=", 1)
                if k.strip():
                    pairs.setdefault(k.strip().lower(), []).append(v.strip())
        saml = pairs
    elif isinstance(saml, dict):
        saml = {str(k).strip().lower(): ([str(x).strip() for x in v] if isinstance(v, list) else [str(v).strip()]) for k, v in saml.items() if str(k).strip()}
    else:
        saml = None
    return {"idp": one(u.get("idp")), "scim_groups": lst(u.get("scim_groups")) if u.get("scim_groups") is not None else None,
            "saml": saml if saml else None, "client_type": one(u.get("client_type")), "platform": one(u.get("platform")),
            "posture_pass": lst(u.get("posture_pass")) if u.get("posture_pass") is not None else None,
            "trusted_networks": lst(u.get("trusted_networks")) if u.get("trusted_networks") is not None else None,
            "country": one(u.get("country")), "machine_group": one(u.get("machine_group"))}


def _ci(a: str, b: str) -> bool:
    return (a or "").strip().lower() == (b or "").strip().lower()


def _eval_operand(o: Dict[str, Any], u: Dict[str, Any], seg: Optional[Dict[str, Any]], ix: _Index) -> Tuple[Optional[bool], str]:
    """(True / False / None for unknown, the fact it turned on)."""
    t, lhs, rhs = o["type"], o["lhs"], o["rhs"]
    if t == "APP":
        return (bool(seg) and seg["id"] == rhs), "app"
    if t == "APP_GROUP":
        return (bool(seg) and seg.get("segment_group_id") == rhs), "app"
    if t == "SCIM_GROUP":
        if u["scim_groups"] is None:
            return None, "SCIM groups"
        g = ix.scim.get(rhs)
        names = {rhs.lower(), (o.get("name") or "").lower(), (g or {}).get("name", "").lower()} - {""}
        return any(x.lower() in names for x in u["scim_groups"]), "SCIM groups"
    if t in ("SAML", "SCIM"):
        if u["saml"] is None:
            return None, "SAML attributes" if t == "SAML" else "SCIM attributes"
        a = ix.saml.get(lhs) if t == "SAML" else None
        keys = {lhs.lower(), (o.get("name") or "").lower()} | ({a["name"].lower(), (a.get("saml_name") or "").lower()} if a else set())
        keys.discard("")
        vals = [v for k, vs in u["saml"].items() if k in keys for v in vs]
        if not vals:
            return None, f"attribute {a['name'] if a else (o.get('name') or lhs)}"
        return any(_ci(v, rhs) for v in vals), f"attribute {a['name'] if a else (o.get('name') or lhs)}"
    if t == "IDP":
        if u["idp"] is None:
            return None, "IdP"
        i = ix.idps.get(rhs)
        return (_ci(u["idp"], rhs) or (bool(i) and _ci(u["idp"], i["name"])) or _ci(u["idp"], o.get("name") or "")), "IdP"
    if t == "POSTURE":
        if u["posture_pass"] is None:
            return None, "device posture"
        p = ix.posture_udid.get(lhs) or ix.posture.get(lhs)
        names = {lhs.lower()} | ({p["name"].lower(), p["id"].lower()} if p else set())
        passes = any(x.lower() in names for x in u["posture_pass"])
        return passes == (rhs.lower() == "true"), "device posture"
    if t == "TRUSTED_NETWORK":
        if u["trusted_networks"] is None:
            return None, "trusted network"
        n = ix.trusted_nid.get(lhs) or ix.trusted.get(lhs)
        names = {lhs.lower()} | ({n["name"].lower(), n["id"].lower()} if n else set())
        on = any(x.lower() in names for x in u["trusted_networks"])
        return on == (rhs.lower() == "true"), "trusted network"
    if t == "CLIENT_TYPE":
        if u["client_type"] is None:
            return None, "client type"
        want = rhs if rhs.startswith("zpn_client_type") else lhs
        return _ci(u["client_type"], want) or _ci(u["client_type"], CLIENT_TYPES.get(want, "")), "client type"
    if t == "PLATFORM":
        if u["platform"] is None:
            return None, "platform"
        return _ci(u["platform"], lhs) == (rhs.lower() != "false"), "platform"
    if t == "COUNTRY_CODE":
        if u["country"] is None:
            return None, "country"
        return _ci(u["country"], lhs) == (rhs.lower() != "false"), "country"
    if t == "MACHINE_GRP":
        if u["machine_group"] is None:
            return None, "machine group"
        m = ix.machine.get(rhs)
        return _ci(u["machine_group"], rhs) or (bool(m) and _ci(u["machine_group"], m["name"])), "machine group"
    return None, t.lower().replace("_", " ")


def _and(vals: List[Optional[bool]]) -> Optional[bool]:
    if any(v is False for v in vals):
        return False
    return None if any(v is None for v in vals) else True


def _or(vals: List[Optional[bool]]) -> Optional[bool]:
    if any(v is True for v in vals):
        return True
    return None if any(v is None for v in vals) else False


def evaluate_rule(rule: Dict[str, Any], u: Dict[str, Any], seg: Optional[Dict[str, Any]], ix: _Index) -> Dict[str, Any]:
    """{status: matched / not_matched / conditional, why, depends_on}."""
    results, depends, unevaluable, failing = [], [], [], []
    for c in rule["conditions"]:
        if not c["operands"]:
            continue
        vals, facts = [], []
        for o in c["operands"]:
            v, fact = _eval_operand(o, u, seg, ix)
            vals.append(v)
            facts.append(fact)
        v = _and(vals) if c["operator"] == "AND" else _or(vals)
        if c["negated"] and v is not None:
            v = not v
        results.append(v)
        labels = [ix.operand_label(o) for o in c["operands"]]
        joined = (" and " if c["operator"] == "AND" else " or ").join(labels[:5]) + (f" (+{len(labels) - 5} more)" if len(labels) > 5 else "")
        if v is None:
            for o, f, x in zip(c["operands"], facts, vals):
                if x is None:
                    (depends if o["type"] in EVALUATED_OPERANDS else unevaluable).append(f)
        elif v is False:
            failing.append({"app": all(o["type"] in APP_TYPES for o in c["operands"]), "negated": bool(c["negated"]), "text": joined})
    any_of = rule["operator"] == "OR" and len(results) > 1
    v = _or(results) if any_of else _and(results)
    if not results:
        v = True
    if v is True:
        return {"status": "matched", "why": "Every condition matches." if results else "It has no conditions, so it matches every request.", "depends_on": []}
    if v is False:
        return {"status": "not_matched", "why": _why_not(failing, seg, any_of), "depends_on": []}
    deps, unev = sorted(set(depends)), sorted(set(unevaluable) - set(depends))
    parts = ([f"its conditions on {_and_list(deps)}, which you left as any"] if deps else []) + \
            ([f"its conditions on {_and_list(unev)}, which this tool cannot evaluate"] if unev else [])
    return {"status": "conditional", "why": f"It matches only if the user meets {' and '.join(parts)}.", "depends_on": deps + unev}


def _why_not(failing: List[Dict[str, Any]], seg: Optional[Dict[str, Any]], any_of: bool) -> str:
    """Why a rule did not match, from the conditions that failed: an
    application condition first (it names where the rule applies), and for
    a rule whose conditions are joined by OR, every one of them."""
    where = ("app segment " + seg["name"]) if seg else "this destination"

    def one(f: Dict[str, Any]) -> str:
        if f["app"]:
            return (f"It applies to every application except {f['text']}, and this destination is {where}." if f["negated"]
                    else f"It applies to {f['text']}, not to {where}.")
        return (f"It excludes {f['text']}, and this user has that." if f["negated"]
                else f"It requires {f['text']}, which this user does not meet.")
    if not failing:
        return "Its conditions do not match."
    if any_of and len(failing) > 1:
        texts = [("not " if f["negated"] else "") + f["text"] for f in failing]
        return f"It matches when any of its conditions is met ({'; or '.join(texts[:5])}), and none is."
    app = [f for f in failing if f["app"]]
    return one(app[0] if app else failing[0])


def _first_match(rules: List[Dict[str, Any]], u, seg, ix, stop_at_match: bool = True) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
    walked, decided = [], None
    for r in rules:
        base = {"id": r["id"], "name": r["name"], "order": r.get("order"), "action": r["action"]}
        if r.get("disabled"):
            walked.append(dict(base, status="disabled", why="It is disabled, so it is skipped.", depends_on=[]))
            continue
        ev = evaluate_rule(r, u, seg, ix)
        walked.append(dict(base, **ev))
        if ev["status"] == "matched":
            decided = r
            if stop_at_match:
                break
    return decided, walked


# The operand types _eval_operand evaluates; any other is a fact this tool
# cannot know (risk score, location, Chrome Enterprise, ...).
EVALUATED_OPERANDS = frozenset({"APP", "APP_GROUP", "SCIM_GROUP", "SAML", "SCIM", "IDP", "POSTURE", "TRUSTED_NETWORK",
                                "CLIENT_TYPE", "PLATFORM", "COUNTRY_CODE", "MACHINE_GRP"})
ACTION_WORDS = {"ALLOW": "allowed", "DENY": "denied", "REQUIRE_APPROVAL": "allowed after approval"}


def diagnose(snap: Dict[str, Any], user: Optional[Dict[str, Any]], destination: str, port: Any = None, protocol: str = "tcp") -> Dict[str, Any]:
    """Which segment, which server and connector groups, and which access
    rule decide for this user and destination (see ASSUMPTIONS)."""
    d = parse_destination(destination, port, protocol)
    ix = _Index(snap)
    u = _norm_user(user)
    assumptions = list(ASSUMPTIONS)
    if d["port_assumed"]:
        assumptions.insert(0, f"No port was given, so port {d['port']} was assumed.")
    any_facts = [k for k, label in (("idp", "IdP"), ("scim_groups", "SCIM groups"), ("saml", "SAML attributes"), ("client_type", "client type"),
                                    ("platform", "platform"), ("posture_pass", "device posture"), ("trusted_networks", "trusted network"),
                                    ("country", "country"), ("machine_group", "machine group")) if u[k] is None]
    any_facts = [label for k, label in (("idp", "IdP"), ("scim_groups", "SCIM groups"), ("saml", "SAML attributes"), ("client_type", "client type"),
                                        ("platform", "platform"), ("posture_pass", "device posture"), ("trusted_networks", "trusted network"),
                                        ("country", "country"), ("machine_group", "machine group")) if k in any_facts]
    if any_facts:
        assumptions.append("Left as any (not known): " + ", ".join(any_facts) + ". Rules that test them are shown as depending on them.")
    hops: List[Dict[str, Any]] = []
    dest_txt = f"{d['host']}:{d['port']}/{d['protocol'].upper()}"
    hops.append({"key": "user", "label": "User and device", "status": "info", "detail": _user_text(u)})

    if not ix.read("segments"):
        return _verdict_only(d, u, assumptions, hops, "unknown", "The app segments could not be read, so the destination cannot be placed.",
                             "Read the tenant again; if it fails again, check the API client's ZPA role.")
    sm = match_segment(snap, d)
    seg_obj = ix.segments.get(sm["match"]["id"]) if sm["match"] else None
    if not seg_obj:
        detail = f"No enabled app segment covers {dest_txt}."
        if sm["near_misses"]:
            detail += " " + "; ".join(f"\"{n['name']}\" has {n['entry']} but not this port ({d['protocol'].upper()} {n['ports']})" for n in sm["near_misses"][:3]) + "."
        if sm["disabled"]:
            detail += " " + "; ".join(f"\"{n['name']}\" would match but is disabled" for n in sm["disabled"][:3]) + "."
        hops.append({"key": "segment", "label": "App segment", "status": "none", "detail": detail})
        out = _verdict_only(d, u, assumptions, hops, "not_zpa",
                            f"ZPA does not carry {dest_txt}: no app segment matches it.",
                            detail + " Client Connector sends this traffic outside ZPA (to ZIA or direct, depending on its forwarding profile).")
        out["segment"] = sm
        return out
    seg_detail = f"\"{seg_obj['name']}\" matches via {sm['match']['entry']} ({d['protocol'].upper()} {sm['match']['ports']})."
    if len(sm["candidates"]) > 1:
        others = [c for c in sm["candidates"][1:] if c not in sm["ambiguous"]]
        if others:
            seg_detail += " Less specific: " + ", ".join(f"\"{c['name']}\" ({c['entry']})" for c in others[:3]) + "."
    if sm["ambiguous"]:
        seg_detail += " Equally specific, so the choice is ambiguous: " + ", ".join(f"\"{c['name']}\"" for c in sm["ambiguous"]) + "."
    if seg_obj.get("match_style") == "INCLUSIVE":
        seg_detail += " This segment is set to INCLUSIVE multimatch, which this tool does not model."
    if seg_obj.get("bypass_type") == "ALWAYS":
        seg_detail += " Its bypass is ALWAYS: Client Connector sends this traffic outside ZPA."
    elif seg_obj.get("bypass_type") == "ON_NET":
        seg_detail += " Its bypass is ON_NET: on a trusted network this traffic goes direct."
    hops.append({"key": "segment", "label": "App segment", "status": "warn" if sm["ambiguous"] or seg_obj.get("bypass") else "ok", "detail": seg_detail,
                 "object": seg_obj["name"]})
    if seg_obj.get("segment_group_id"):
        g = ix.segment_groups.get(seg_obj["segment_group_id"])
        gname = g["name"] if g else (seg_obj.get("segment_group_name") or seg_obj["segment_group_id"])
        hops.append({"key": "segment_group", "label": "Segment group", "status": "warn" if g and g.get("enabled") is False else "ok",
                     "detail": f"\"{gname}\"" + (" is disabled." if g and g.get("enabled") is False else "."), "object": gname})

    # Access policy
    rules = (snap.get("policies") or {}).get("access")
    if rules is None:
        hops.append({"key": "access", "label": "Access policy", "status": "unknown", "detail": "The access policy could not be read."})
        out = _verdict_only(d, u, assumptions, hops, "unknown", f"\"{seg_obj['name']}\" carries {dest_txt}, but the access policy could not be read.",
                            "Read the tenant again to see which rule decides.")
        out["segment"] = sm
        return out
    decided, walked = _first_match(rules, u, seg_obj, ix)
    conditional_before = [w for w in walked if w["status"] == "conditional"]
    if decided:
        act = decided["action"]
        access = {"decision": act.lower(), "rule": {"id": decided["id"], "name": decided["name"], "order": decided.get("order"), "action": act}}
        a_detail = f"Rule {decided.get('order') if decided.get('order') is not None else ''} \"{decided['name']}\" ({act}) is the first rule that matches.".replace("Rule  ", "Rule ")
        a_status = "ok" if act != "DENY" else "blocked"
    else:
        access = {"decision": "conditional" if conditional_before else "default_deny", "rule": None}
        a_detail = "No access rule matches, so ZPA denies access by default." if not conditional_before else "No rule matches for certain with what you gave."
        a_status = "blocked" if not conditional_before else "warn"
    if conditional_before:
        a_detail += (" Before it, " if decided else " ") + "; ".join(
            f"\"{w['name']}\" ({w['action']}) would decide if the user meets its conditions on {_and_list(w['depends_on'])}" for w in conditional_before[:3]) + "."
    hops.append({"key": "access", "label": "Access policy", "status": a_status, "detail": a_detail})
    access["evaluated"] = walked

    # Server groups and connectors
    serve = _serving(seg_obj, ix)
    hops.append({"key": "server_groups", "label": "Server groups", "status": serve["sg_status"], "detail": serve["sg_detail"]})
    hops.append({"key": "connectors", "label": "App Connectors", "status": serve["cg_status"], "detail": serve["cg_detail"]})

    # The other policies, first match each (informational)
    other = {}
    for ptype, label in (("timeout", "Timeout policy"), ("client_forwarding", "Client forwarding policy"), ("inspection", "Inspection policy"), ("isolation", "Isolation policy")):
        prules = (snap.get("policies") or {}).get(ptype)
        if prules is None:
            other[ptype] = {"label": label, "read": False}
            continue
        r, w = _first_match(prules, u, seg_obj, ix)
        cond = [x for x in w if x["status"] == "conditional"]
        other[ptype] = {"label": label, "read": True, "rule": ({"name": r["name"], "action": r["action"], "order": r.get("order")} if r else None),
                        "conditional": [{"name": x["name"], "action": x["action"], "depends_on": x["depends_on"]} for x in cond[:3]]}

    # The verdict
    rule_name = decided["name"] if decided else ""
    reach = serve["reachable"]
    if seg_obj.get("bypass_type") == "ALWAYS":
        outcome, headline = "bypassed", f"Bypassed: \"{seg_obj['name']}\" matches {dest_txt} but its bypass is ALWAYS, so the traffic never goes through ZPA."
    elif decided and decided["action"] == "DENY":
        outcome, headline = "denied", f"Denied by access rule \"{rule_name}\": app segment \"{seg_obj['name']}\" matches {dest_txt} and this is the first rule that applies."
    elif decided:
        word = ACTION_WORDS.get(decided["action"], decided["action"].lower())
        if reach is False:
            outcome = "unreachable"
            headline = f"Allowed by access rule \"{rule_name}\" but unreachable: {serve['why_down']}"
        else:
            outcome = "allowed"
            headline = f"{word[0].upper() + word[1:]} by access rule \"{rule_name}\": app segment \"{seg_obj['name']}\" matches {dest_txt}, served by {serve['short']}."
    elif conditional_before:
        outcome = "conditional"
        first = conditional_before[0]
        headline = f"Depends on the user: \"{first['name']}\" ({first['action']}) decides if the user meets its conditions on {_and_list(first['depends_on'])}; otherwise " + \
                   ("a later rule or the default deny decides." if len(conditional_before) > 1 else "ZPA denies by default.")
    else:
        outcome, headline = "denied", f"Denied by default: app segment \"{seg_obj['name']}\" matches {dest_txt}, but no access rule allows it for this user."
    if decided and conditional_before and outcome in ("allowed", "denied", "unreachable"):
        first = conditional_before[0]
        headline = headline[:-1] + f", unless the user meets the conditions of the earlier rule \"{first['name']}\" ({first['action']}) on {_and_list(first['depends_on'])}."
    summary = _summary(outcome, seg_obj, decided, walked, serve)
    return {"destination": d, "user": u, "assumptions": assumptions, "segment": sm, "access": access, "serving": serve,
            "other_policies": other, "hops": hops,
            "verdict": {"outcome": outcome, "headline": headline, "summary": summary,
                        "segment": seg_obj["name"], "rule": rule_name or None, "reachable": reach}}


def _user_text(u: Dict[str, Any]) -> str:
    parts = []
    if u["idp"]:
        parts.append(f"IdP {u['idp']}")
    if u["scim_groups"] is not None:
        parts.append(f"SCIM groups: {_names(u['scim_groups'], 5) or 'none'}")
    if u["saml"]:
        parts.append("SAML " + "; ".join(f"{k}={','.join(v)}" for k, v in list(u["saml"].items())[:4]))
    if u["client_type"]:
        parts.append(f"client {CLIENT_TYPES.get(u['client_type'], u['client_type'])}")
    if u["platform"]:
        parts.append(f"platform {u['platform']}")
    if u["posture_pass"] is not None:
        parts.append(f"passes posture: {_names(u['posture_pass'], 4) or 'none'}")
    if u["trusted_networks"] is not None:
        parts.append(f"on trusted network: {_names(u['trusted_networks'], 3) or 'none'}")
    if u["country"]:
        parts.append(f"country {u['country']}")
    if u["machine_group"]:
        parts.append(f"machine group {u['machine_group']}")
    return ("; ".join(parts) + ".") if parts else "Any user on any device (nothing was given)."


def _serving(seg: Dict[str, Any], ix: _Index) -> Dict[str, Any]:
    sgs = [ix.server_groups.get(r["id"]) or {"id": r["id"], "name": r["name"] or r["id"], "missing": True} for r in seg["server_groups"]]
    live = [g for g in sgs if not g.get("missing") and g.get("enabled") is not False]
    groups, seen = [], set()
    for g in live:
        for c in g.get("connector_groups") or []:
            if c["id"] in seen:
                continue
            seen.add(c["id"])
            cg = ix.connector_groups.get(c["id"])
            cons = [x for x in ix.connectors_by_group.get(c["id"], []) if x.get("enabled") is not False]
            up = [x for x in cons if x["connected"]]
            known = [x for x in cons if x["connected"] is not None]
            groups.append({"id": c["id"], "name": (cg or {}).get("name") or c["name"] or c["id"], "missing": cg is None and ix.complete("connector_groups"),
                           "connectors": len(cons), "connected": len(up), "status_known": bool(known)})
    if not sgs:
        sg_status, sg_detail = "blocked", "The segment has no server group."
    elif not live:
        sg_status, sg_detail = "blocked", "Every server group of the segment is deleted or disabled: " + _names([g["name"] for g in sgs]) + "."
    else:
        sg_status = "ok"
        def how(g):
            return "dynamic discovery" if g.get("dynamic_discovery") is not False else f"{len(g.get('servers') or [])} server(s)"
        sg_detail = "; ".join(f"\"{g['name']}\" ({how(g)})" for g in live) + "."
        empty = [g for g in live if g.get("dynamic_discovery") is False and not [s for s in g.get("servers") or [] if s.get("enabled")]]
        if empty and len(empty) == len(live):
            sg_status, sg_detail = "blocked", sg_detail + " None has a server to connect to."
    up_total = sum(g["connected"] for g in groups)
    known_any = any(g["status_known"] for g in groups)
    if not groups:
        cg_status, cg_detail, reachable, why = "blocked", "No App Connector group serves the segment's server groups.", False, "no App Connector group serves its server groups."
    elif known_any and up_total == 0:
        cg_status = "blocked"
        cg_detail = "; ".join(f"\"{g['name']}\": 0 of {g['connectors']} connected" for g in groups) + "."
        reachable, why = False, "no App Connector serving it is connected."
    else:
        cg_status = "ok" if all(g["connected"] >= 2 or not g["status_known"] for g in groups) else "warn"
        cg_detail = "; ".join(f"\"{g['name']}\": {g['connected'] if g['status_known'] else '?'} of {g['connectors']} connected" for g in groups) + "."
        reachable, why = (True if known_any else None), ""
    if sg_status == "blocked":
        reachable, why = False, sg_detail[0].lower() + sg_detail[1:]
    quoted = [f"\"{g['name']}\"" for g in groups]
    short = (_names([f"\"{g['name']}\"" for g in live], 2) or "no server group") + \
        (f" through {_names(quoted, 2)} ({up_total} connector{'s' if up_total != 1 else ''} connected)" if groups else "")
    return {"server_groups": [{"id": g["id"], "name": g["name"], "missing": bool(g.get("missing")), "enabled": g.get("enabled", True) is not False,
                               "dynamic_discovery": g.get("dynamic_discovery"), "servers": len(g.get("servers") or [])} for g in sgs],
            "connector_groups": groups, "sg_status": sg_status, "sg_detail": sg_detail, "cg_status": cg_status, "cg_detail": cg_detail,
            "reachable": reachable, "why_down": why, "short": short}


def _summary(outcome: str, seg: Dict[str, Any], decided: Optional[Dict[str, Any]], walked: List[Dict[str, Any]], serve: Dict[str, Any]) -> str:
    before = [w for w in walked if not decided or w["id"] != decided["id"]]
    n_not = sum(1 for w in before if w["status"] == "not_matched")
    n_dis = sum(1 for w in before if w["status"] == "disabled")
    n_cond = sum(1 for w in before if w["status"] == "conditional")
    parts = [f"{len(walked)} access rule{'s' if len(walked) != 1 else ''} evaluated"]
    if n_not:
        parts.append(f"{n_not} did not match")
    if n_cond:
        parts.append(f"{n_cond} depend on facts left as any")
    if n_dis:
        parts.append(f"{n_dis} disabled")
    s = ", ".join(parts) + "."
    if serve.get("reachable") is False and outcome != "denied":
        s += f" The segment cannot be served: {serve['why_down']}"
    return s


def _verdict_only(d, u, assumptions, hops, outcome, headline, summary):
    return {"destination": d, "user": u, "assumptions": assumptions, "segment": None, "access": None, "serving": None,
            "other_policies": {}, "hops": hops, "verdict": {"outcome": outcome, "headline": headline, "summary": summary,
                                                           "segment": None, "rule": None, "reachable": None}}


def choices(snap: Dict[str, Any]) -> Dict[str, Any]:
    """What the Diagnose form can offer from the read (names only)."""
    ix = _Index(snap)
    scim = sorted({g["name"] for g in ix.scim.values() if g.get("name")})[:2000]
    # SCIM group names the access rules use, even when the list was not read.
    for r in (snap.get("policies") or {}).get("access") or []:
        for c in r["conditions"]:
            for o in c["operands"]:
                if o["type"] == "SCIM_GROUP" and o.get("name") and o["name"] not in scim:
                    scim.append(o["name"])
    return {"idps": sorted(i["name"] for i in ix.idps.values()), "scim_groups": sorted(set(scim)),
            "saml_attributes": sorted({a["name"] for a in ix.saml.values()}),
            "posture_profiles": sorted(p["name"] for p in ix.posture.values()),
            "trusted_networks": sorted(t["name"] for t in ix.trusted.values()),
            "machine_groups": sorted(m["name"] for m in ix.machine.values()),
            "client_types": [{"value": k, "label": v} for k, v in CLIENT_TYPES.items()], "platforms": list(PLATFORMS),
            "segments": sorted({dm for s in _lst(snap, "segments") for dm in s["domains"]})[:500]}
