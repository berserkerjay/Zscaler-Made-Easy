"""The ZPA overview: KPI sentences, the infrastructure map and the
inventory tables of the ZPA analysis page, and its Excel workbook.

Pure functions over the snapshot zpa_reader.read returns and the analysis
zpa_analysis.analyze returns: nothing here reads or writes a tenant.

`overview(snap, analysis)` returns
  kpis    one plain sentence each ("3 app segments nobody can reach"), with
          the table and flag the page links it to; None values mean the
          list behind it was not read (never shown as zero);
  tables  segments, segment groups, server groups, connector groups,
          connectors, access rules and IdPs, each row with its flags and the
          analysis findings that name it;
  graph   the map Users/IdP -> access rules -> segment groups -> app segments
          -> server groups -> connector groups -> connectors: the nodes and
          edges to draw (at most `cap` nodes per column; the rest grouped in
          one "N more" node, and the page says so) and the precise links the
          page filters the tables with.

What the map draws, and the simplifications it makes (the page says them):
- A rule is drawn to the segment groups of the app segments it applies to
  (zpa_analysis._reaches: by segment, by segment group, or every segment when
  it names no application). The table filter uses the precise rule -> segment
  relation, so a rule that names one segment of a group does not pull in the
  group's other segments.
- A rule with no SCIM group, SCIM or SAML attribute or IdP condition hangs
  off "Any signed-in user".
- Connector health is controlChannelStatus (ZPN_STATUS_AUTHENTICATED is
  connected, as in zpa_analysis) and "outdated" is currentVersion differing
  from expectedVersion; both are fields of the SDK's AppConnectorController
  model.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import zpa_analysis as za

MAP_CAP = 12            # boxes drawn per map column; the rest are one "N more" box
MAX_LINKS = 60000       # filter links sent to the page; beyond that a click filters to the box itself
MAX_EDGE_ROWS = 100000  # map connections in the workbook

COLUMNS: Tuple[Tuple[str, str, str, str], ...] = (
    # key, column label, one, many
    ("idps", "Users and IdPs", "IdP", "users and IdPs"),
    ("access_rules", "Access rules", "access rule", "access rules"),
    ("segment_groups", "Segment groups", "segment group", "segment groups"),
    ("segments", "App segments", "app segment", "app segments"),
    ("server_groups", "Server groups", "server group", "server groups"),
    ("connector_groups", "Connector groups", "App Connector group", "App Connector groups"),
    ("connectors", "App Connectors", "App Connector", "App Connectors"),
)
COLUMN_KEYS = tuple(c[0] for c in COLUMNS)
COLUMN_LABEL = {c[0]: c[1] for c in COLUMNS}
ONE = {c[0]: c[2] for c in COLUMNS}
MANY = {c[0]: c[3] for c in COLUMNS}
# snapshot list behind each table ("policy:access" for the rules)
SOURCE = {"idps": "idps", "access_rules": "policy:access", "segment_groups": "segment_groups", "segments": "segments",
          "server_groups": "server_groups", "connector_groups": "connector_groups", "connectors": "connectors"}

ANY_USER = "idps:*any"
UNKNOWN_IDP = "idps:*unknown"
NO_GROUP = "segment_groups:*none"
IDENTITY_TYPES = ("SCIM_GROUP", "SCIM", "SAML", "IDP")

# finding object_type -> table
OBJ_TABLE = {"access rule": "access_rules", "app segment": "segments", "segment group": "segment_groups",
             "server group": "server_groups", "connector group": "connector_groups", "connector": "connectors"}
# analysis template -> the row flag it sets
TEMPLATE_FLAGS = {
    "ZPA-AP-01": "unreachable", "ZPA-AP-02": "dangling", "ZPA-AP-03": "idp_off", "ZPA-AP-04": "catch_all",
    "ZPA-AS-01": "no_rule", "ZPA-AS-02": "only_deny", "ZPA-AS-03": "overlap", "ZPA-AS-04": "over_broad",
    "ZPA-AS-05": "wide_ports", "ZPA-AS-06": "bypass", "ZPA-AS-07": "no_health", "ZPA-AS-08": "no_server_group",
    "ZPA-AS-09": "not_inspected", "ZPA-AS-10": "cleartext", "ZPA-SG-01": "empty_or_off", "ZPA-SV-01": "no_servers",
    "ZPA-SV-02": "no_connector_group", "ZPA-CG-01": "no_connectors", "ZPA-CG-02": "all_down",
    "ZPA-CG-03": "single_connector", "ZPA-CG-04": "versions", "ZPA-AC-01": "stale",
}
FLAG_LABELS = {
    "disabled": "Disabled", "no_rule": "No access rule reaches it", "only_deny": "Only deny rules reach it",
    "broad": "Wildcard or subnet", "over_broad": "Over-broad", "overlap": "Overlaps another segment", "wide_ports": "Wide port range",
    "bypass": "Bypasses ZPA", "no_health": "Health reporting off", "no_server_group": "No working server group",
    "not_inspected": "Not inspected", "cleartext": "Cleartext protocol", "empty_or_off": "Empty, or disabled with segments",
    "no_servers": "No servers", "no_connector_group": "No connector group", "no_connectors": "No connectors",
    "all_down": "Every connector disconnected", "single_connector": "Single connector", "versions": "Mixed or outdated versions",
    "stale": "Not seen for over 7 days", "not_connected": "Not connected", "outdated": "Not on the expected version",
    "status_unknown": "Status not reported", "unreachable": "Never decides (an earlier rule matches first)",
    "dangling": "Names deleted or disabled objects", "idp_off": "Depends on a disabled IdP", "catch_all": "Allows every user",
    "no_app": "Reaches no enabled app segment", "not_read": "Not read",
}
# A box is red when one of its findings is high severity or it carries one of
# these computed flags; INFO flags change no colour; anything else is amber.
FAIL_FLAGS = {"no_rule", "not_connected", "no_app"}
INFO_FLAGS = {"disabled", "broad", "status_unknown", "not_read"}
STATUS_ORDER = {"fail": 0, "warn": 1, "unknown": 2, "ok": 3, "off": 4}
STATUS_WORDS = {"fail": "needs attention", "warn": "has a warning", "unknown": "not read", "ok": "no issue found", "off": "disabled"}

MAP_NOTES = [
    "A rule is drawn to the segment groups of the app segments it applies to; clicking it filters the tables to exactly those segments.",
    "A rule with no SCIM group, SCIM or SAML attribute or IdP condition is drawn from \"Any signed-in user\".",
    "A disabled rule is drawn in its place but connects to no segment group: it gives no access.",
    "A connector is connected when it reports ZPN_STATUS_AUTHENTICATED; outdated means its current version differs from its expected version.",
]


# ── small helpers ───────────────────────────────────────────────────────
def _n(n: int, one: str, many: Optional[str] = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _iso(epoch: Optional[float]) -> str:
    if not epoch:
        return ""
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (OverflowError, OSError, ValueError):
        return ""


def _status(enabled: Any, flags: Iterable[str], findings: List[Dict[str, Any]]) -> str:
    if enabled is False:
        return "off"
    fl = set(flags) - INFO_FLAGS
    if fl & FAIL_FLAGS or any(f.get("severity") == "high" for f in findings):
        return "fail"
    if fl or findings:
        return "warn"
    return "ok"


def _uniq(seq: Iterable[str]) -> List[str]:
    out, seen = [], set()
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


class _Model:
    """Every table row, node and link, built once from a snapshot."""

    def __init__(self, snap: Dict[str, Any], analysis: Dict[str, Any]):
        self.snap = snap
        self.ix = za._Index(snap)
        self.findings = list(analysis.get("findings") or [])
        self.catalog = {c["id"]: c for c in analysis.get("catalog") or []}
        self.issues: Dict[str, List[Dict[str, Any]]] = {}
        for f in self.findings:
            t = OBJ_TABLE.get(f.get("object_type"))
            if t and f.get("object_id"):
                self.issues.setdefault(f"{t}:{f['object_id']}", []).append(f)
        self.rows: Dict[str, List[Dict[str, Any]]] = {k: [] for k in COLUMN_KEYS}
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Set[Tuple[str, str]] = set()        # drawn chain edges
        self.links: Set[Tuple[str, str]] = set()        # precise filter links
        self.all_apps: List[str] = []                   # rules that apply to every enabled segment
        self._build()

    # -- what was read ------------------------------------------------------
    def read(self, table: str) -> bool:
        return self.ix.read(SOURCE[table])

    def read_error(self, table: str) -> str:
        c = (self.snap.get("collections") or {}).get(SOURCE[table]) or {}
        return c.get("error") or "not read"

    def assessed(self, tid: str) -> bool:
        c = self.catalog.get(tid)
        return bool(c) and c.get("status") != "not_assessed"

    def _flags_from_findings(self, nid: str) -> List[str]:
        return [TEMPLATE_FLAGS[f["template"]] for f in self.issues.get(nid, []) if f.get("template") in TEMPLATE_FLAGS]

    def _row(self, table: str, oid: str, enabled: Any, flags: List[str], cells: Dict[str, Any]) -> Dict[str, Any]:
        nid = f"{table}:{oid}"
        fs = self.issues.get(nid, [])
        flags = _uniq(flags + self._flags_from_findings(nid))
        if enabled is False and "disabled" not in flags:
            flags.insert(0, "disabled")
        row = dict(cells)
        row.update(_id=oid, _node=nid, _flags=flags, _status=_status(enabled, flags, fs),
                   _issues=_uniq(f"{f['template']} {f['title']}" for f in fs))
        self.rows[table].append(row)
        return row

    def _node(self, nid: str, col: str, label: str, sub: str, status: str, flags: List[str], oid: str = "") -> None:
        self.nodes[nid] = {"id": nid, "col": col, "oid": oid, "label": label or oid, "sub": sub, "status": status,
                           "flags": flags, "issues": len(self.issues.get(nid, []))}

    # -- the build ------------------------------------------------------------
    def _build(self) -> None:
        ix, snap = self.ix, self.snap
        segs = snap.get("segments") or []
        enabled_segs = [s for s in segs if s.get("enabled")]
        access_read = self.read("access_rules")
        rules = list((snap.get("policies") or {}).get("access") or [])
        for i, r in enumerate(rules):
            if not r.get("id"):
                r = dict(r, id=f"rule-{i + 1}")
                rules[i] = r

        # Which enabled segments each rule applies to (zpa_analysis._reaches, with the scope worked out once).
        reach: Dict[str, Optional[List[str]]] = {}
        rules_on_seg: Dict[str, List[Dict[str, Any]]] = {s["id"]: [] for s in segs}
        for r in rules:
            sc = za._app_scope(r)
            if sc is None or sc.get("all"):
                reach[r["id"]] = None
                if not r.get("disabled"):   # a disabled rule gives no access: it links to nothing
                    self.all_apps.append(f"access_rules:{r['id']}")
                hit = [s["id"] for s in enabled_segs]
            else:
                hit = []
                for s in enabled_segs:
                    named = s["id"] in sc["segments"] or bool(s.get("segment_group_id") and s["segment_group_id"] in sc["groups"])
                    if (not named) if sc["negated"] else named:
                        hit.append(s["id"])
                reach[r["id"]] = hit
            if not r.get("disabled"):
                for sid in hit:
                    rules_on_seg[sid].append(r)
        self.reach = reach
        self.rules = rules

        # ── segments
        seg_group: Dict[str, str] = {}
        for s in segs:
            sid = s["id"]
            flags: List[str] = []
            on = rules_on_seg.get(sid, [])
            if s.get("enabled") and access_read and not on:
                flags.append("no_rule")
            if any("*" in d for d in s.get("domains") or []) or any("/" in d for d in s.get("domains") or []):
                flags.append("broad")
            gid = s.get("segment_group_id") or ""
            gnode = f"segment_groups:{gid}" if gid and gid in ix.segment_groups else NO_GROUP
            seg_group[sid] = gnode
            row = self._row("segments", sid, s.get("enabled"), flags, {
                "name": s["name"], "enabled": bool(s.get("enabled")),
                "segment_group": (ix.segment_groups[gid]["name"] if gid in ix.segment_groups else s.get("segment_group_name") or gid),
                "domains": ", ".join(s.get("domains") or []), "tcp": za._ports_text(s.get("tcp") or []) if s.get("tcp") else "",
                "udp": za._ports_text(s.get("udp") or []) if s.get("udp") else "",
                "server_groups": ", ".join(r.get("name") or r["id"] for r in s.get("server_groups") or []),
                "rules": len(on) if access_read else None,
            })
            ports = ", ".join(x for x in (f"TCP {row['tcp']}" if row["tcp"] else "", f"UDP {row['udp']}" if row["udp"] else "") if x)
            doms = s.get("domains") or []
            sub = (doms[0] + (f" +{len(doms) - 1}" if len(doms) > 1 else "")) if doms else (ports or "no domain")
            self._node(f"segments:{sid}", "segments", s["name"], sub, row["_status"], row["_flags"], sid)
            if gnode == NO_GROUP and NO_GROUP not in self.nodes:
                self._node(NO_GROUP, "segment_groups", "No segment group", "segments without a known group", "warn", [])
            self.edges.add((gnode, f"segments:{sid}"))
            self.links.add((gnode, f"segments:{sid}"))
            sg_read = self.read("server_groups")
            for ref in s.get("server_groups") or []:
                tid = f"server_groups:{ref['id']}"
                if ref["id"] in ix.server_groups:
                    pass
                elif not sg_read:
                    if tid not in self.nodes:
                        self._node(tid, "server_groups", ref.get("name") or ref["id"], "not read", "unknown", ["not_read"], ref["id"])
                else:
                    continue   # deleted: ZPA-AS-08 names it
                self.edges.add((f"segments:{sid}", tid))
                self.links.add((f"segments:{sid}", tid))
        self.seg_group = seg_group

        # ── segment groups
        for g in snap.get("segment_groups") or []:
            gid = g["id"]
            members = [m for m in ix.group_segments.get(gid, set()) if m in ix.segments]
            named = [r for r in rules if not r.get("disabled") and (za._app_scope(r) or {}).get("groups") and gid in za._app_scope(r)["groups"]]
            reaching = {r["id"] for m in members for r in rules_on_seg.get(m, [])}
            row = self._row("segment_groups", gid, g.get("enabled"), [], {
                "name": g["name"], "enabled": bool(g.get("enabled")), "segments": len(members),
                "rules_naming": len(named) if access_read else None, "rules_reaching": len(reaching) if access_read else None})
            self._node(f"segment_groups:{gid}", "segment_groups", g["name"], _n(len(members), "segment"), row["_status"], row["_flags"], gid)
            for m in members:   # the group's applications list may name segments listed elsewhere
                self.edges.add((f"segment_groups:{gid}", f"segments:{m}"))
                self.links.add((f"segment_groups:{gid}", f"segments:{m}"))

        # ── access rules (drawn to the groups of what they reach; linked to the segments themselves)
        groups_of_enabled = {seg_group[s["id"]] for s in enabled_segs}
        for idx, r in enumerate(rules):
            rid = r["id"]
            nid = f"access_rules:{rid}"
            sc = za._app_scope(r)
            hit = reach[rid]
            flags: List[str] = []
            n_hit = len(enabled_segs) if hit is None else len(hit)
            if not r.get("disabled") and n_hit == 0 and segs:
                flags.append("no_app")
            if sc is None:
                apps = "Not a plain shape: counted as every application"
            elif sc.get("all"):
                apps = "All applications"
            else:
                names = ([f"app segment {ix.segment_name(x)}" for x in sorted(sc["segments"])]
                         + [f"segment group {ix.group_name(x)}" for x in sorted(sc["groups"])])
                apps = ("Everything except " if sc["negated"] else "") + ", ".join(names)
            who = [ix.operand_label(o) for c in za._user_conditions(r) for o in c["operands"]]
            row = self._row("access_rules", rid, not r.get("disabled"), flags, {
                "order": r.get("order") if r.get("order") is not None else idx + 1, "name": r["name"], "action": r.get("action") or "",
                "enabled": not r.get("disabled"), "applications": apps, "who": "; ".join(_uniq(who)) or "Any signed-in user",
                "segments_reached": n_hit})
            label = f"{row['order']}. {r['name']}"
            self._node(nid, "access_rules", label, (r.get("action") or "no action").replace("_", " ").title(), row["_status"], row["_flags"], rid)
            if r.get("disabled"):
                gset: Set[str] = set()      # drawn, but connected to no application
            elif hit is None:
                gset = set(groups_of_enabled)
            else:
                gset = {seg_group[x] for x in hit}
                for x in hit:
                    self.links.add((nid, f"segments:{x}"))
            if sc and not sc.get("all") and not r.get("disabled"):
                gset |= {f"segment_groups:{g}" for g in sc["groups"] if g in ix.segment_groups}
            for g in gset:
                self.edges.add((nid, g))
            # who
            idps = set()
            ident = [o for c in r["conditions"] for o in c["operands"] if o["type"] in IDENTITY_TYPES]
            for o in ident:
                t = o["type"]
                if t == "SCIM_GROUP":
                    i = o["lhs"] if o["lhs"] in ix.idps else o.get("idp_id")
                elif t == "SAML":
                    i = (ix.saml.get(o["lhs"]) or {}).get("idp_id") or o.get("idp_id")
                elif t == "IDP":
                    i = o["rhs"]
                else:
                    i = o.get("idp_id")
                idps.add(f"idps:{i}" if i and i in ix.idps else UNKNOWN_IDP)
            if not ident:
                idps.add(ANY_USER)
            for i in idps:
                self.edges.add((i, nid))
                self.links.add((i, nid))

        # ── IdPs
        used: Dict[str, int] = {}
        for a, _b in self.edges:
            if a.startswith("idps:"):
                used[a] = used.get(a, 0) + 1
        for i in snap.get("idps") or []:
            nid = f"idps:{i['id']}"
            row = self._row("idps", i["id"], i.get("enabled"), [], {
                "name": i["name"], "enabled": bool(i.get("enabled")),
                "scim_policy": None if i.get("scim_policy") is None else bool(i.get("scim_policy")),
                "rules": used.get(nid, 0) if access_read else None})
            if i.get("enabled") is False and used.get(nid):
                row["_status"] = "warn"
            self._node(nid, "idps", i["name"], _n(used.get(nid, 0), "access rule"), row["_status"], row["_flags"], i["id"])
        if ANY_USER in used:
            self._node(ANY_USER, "idps", "Any signed-in user", _n(used[ANY_USER], "access rule") + " with no identity condition", "ok", [])
        if UNKNOWN_IDP in used:
            self._node(UNKNOWN_IDP, "idps", "IdP not read", _n(used[UNKNOWN_IDP], "access rule"), "unknown", ["not_read"])

        # ── server groups
        cg_read = self.read("connector_groups")
        seg_users: Dict[str, int] = {}
        for a, b in self.edges:
            if a.startswith("segments:") and b.startswith("server_groups:"):
                seg_users[b] = seg_users.get(b, 0) + 1
        for g in snap.get("server_groups") or []:
            nid = f"server_groups:{g['id']}"
            servers = [x for x in g.get("servers") or [] if x.get("enabled")]
            row = self._row("server_groups", g["id"], g.get("enabled"), [], {
                "name": g["name"], "enabled": bool(g.get("enabled")),
                "dynamic_discovery": g.get("dynamic_discovery"), "servers": len(servers),
                "connector_groups": ", ".join(c.get("name") or c["id"] for c in g.get("connector_groups") or []),
                "segments": seg_users.get(nid, 0)})
            sub = "dynamic discovery" if g.get("dynamic_discovery") else _n(len(servers), "server")
            self._node(nid, "server_groups", g["name"], sub, row["_status"], row["_flags"], g["id"])
            for ref in g.get("connector_groups") or []:
                tid = f"connector_groups:{ref['id']}"
                if ref["id"] in ix.connector_groups:
                    pass
                elif not cg_read:
                    if tid not in self.nodes:
                        self._node(tid, "connector_groups", ref.get("name") or ref["id"], "not read", "unknown", ["not_read"], ref["id"])
                else:
                    continue
                self.edges.add((nid, tid))
                self.links.add((nid, tid))

        # ── connectors
        con_read = self.read("connectors")
        for c in snap.get("connectors") or []:
            flags = []
            if c.get("enabled") is not False:
                if c.get("connected") is False:
                    flags.append("not_connected")
                elif c.get("connected") is None:
                    flags.append("status_unknown")
            if c.get("current_version") and c.get("expected_version") and c["current_version"] != c["expected_version"]:
                flags.append("outdated")
            gid = c.get("group_id") or ""
            group_name = ix.connector_groups[gid]["name"] if gid in ix.connector_groups else (c.get("group_name") or gid)
            row = self._row("connectors", c["id"], c.get("enabled"), flags, {
                "name": c["name"], "connector_group": group_name, "enabled": c.get("enabled") is not False,
                "status": c.get("status_raw") or "not reported", "current_version": c.get("current_version") or "",
                "expected_version": c.get("expected_version") or "", "last_connected": _iso(c.get("last_connect"))})
            word = {True: "Connected", False: "Not connected", None: "Status not reported"}[c.get("connected")]
            sub = word + (f" · {c['current_version']}" if c.get("current_version") else "")
            self._node(f"connectors:{c['id']}", "connectors", c["name"], sub, row["_status"], row["_flags"], c["id"])

        # ── connector groups
        server_users: Dict[str, int] = {}
        for a, b in self.edges:
            if b.startswith("connector_groups:"):
                server_users[b] = server_users.get(b, 0) + 1
        for g in snap.get("connector_groups") or []:
            nid = f"connector_groups:{g['id']}"
            cons = ix.connectors_by_group.get(g["id"], [])
            up = sum(1 for c in cons if c.get("connected"))
            versions = sorted({c.get("current_version") for c in cons if c.get("current_version")}, key=za._vkey)
            row = self._row("connector_groups", g["id"], g.get("enabled"), [], {
                "name": g["name"], "enabled": bool(g.get("enabled")), "location": g.get("location") or "",
                "connectors": len(cons), "connected": up if con_read or g.get("embedded_connectors") else None,
                "versions": ", ".join(versions), "server_groups": server_users.get(nid, 0)})
            sub = f"{up}/{len(cons)} connected" if cons else "no connectors"
            self._node(nid, "connector_groups", g["name"], sub, row["_status"], row["_flags"], g["id"])
            for c in cons:
                cid = f"connectors:{c['id']}"
                if cid not in self.nodes:   # embedded in the group only (the connector list was not read)
                    self._node(cid, "connectors", c.get("name") or c["id"], "listed in its group", "unknown" if c.get("connected") is None
                               else ("ok" if c.get("connected") else "fail"), [], c["id"])
                self.edges.add((nid, cid))
                self.links.add((nid, cid))

    # -- outputs ---------------------------------------------------------------
    def count(self, table: str, flag: Optional[str] = None) -> Optional[int]:
        if not self.read(table):
            return None
        rows = self.rows[table]
        return len(rows) if flag is None else sum(1 for r in rows if flag in r["_flags"])


# ── KPIs ────────────────────────────────────────────────────────────────
def _kpi(key: str, value: Optional[int], text: str, table: str, flags: Optional[List[str]] = None, tone: str = "") -> Dict[str, Any]:
    """One sentence; `table` and `flags` say which table rows it links to
    (rows carrying any of the flags; every row when None)."""
    return {"key": key, "value": value, "text": text, "table": table, "flags": flags, "tone": tone if value else ""}


def _with_any(m: _Model, table: str, flags: Iterable[str]) -> int:
    fl = set(flags)
    return sum(1 for r in m.rows[table] if fl & set(r["_flags"]))


def kpis(m: _Model) -> List[Dict[str, Any]]:
    """The overview sentences, in page order. A KPI whose list was not read
    has value None and says so; it is never a zero."""
    out: List[Dict[str, Any]] = []

    def unknown(key: str, table: str, what: str) -> None:
        out.append(_kpi(key, None, f"{what}: unknown, because the {MANY[table]} could not be read ({m.read_error(table)}).", table))

    n = m.count("segments")
    if n is None:
        unknown("segments", "segments", "App segments")
    else:
        off = m.count("segments", "disabled")
        out.append(_kpi("segments", n, _n(n, "app segment") + (f", {off} of them disabled." if off else "."), "segments"))
        if m.read("access_rules"):
            k = m.count("segments", "no_rule")
            out.append(_kpi("segments_no_rule", k, f"{_n(k, 'app segment')} nobody can reach: no enabled access rule applies to "
                                                    f"{'it' if k == 1 else 'them'}.", "segments", ["no_rule"], "fail"))
        else:
            unknown("segments_no_rule", "access_rules", "App segments nobody can reach")
        k, ob = _with_any(m, "segments", ["broad", "over_broad"]), m.count("segments", "over_broad")
        out.append(_kpi("segments_broad", k, f"{_n(k, 'app segment')} {'uses' if k == 1 else 'use'} a wildcard domain or a subnet"
                                             + (f"; {ob} of them {'is' if ob == 1 else 'are'} over-broad." if ob else "."),
                        "segments", ["broad", "over_broad"], "fail" if ob else "warn"))
    for table, bad, words, tone in (
            ("segment_groups", ["empty_or_off"], "empty, or disabled while holding segments", "warn"),
            ("server_groups", ["no_servers", "no_connector_group"], "cannot serve: no servers or no connector group", "fail"),
            ("connector_groups", ["no_connectors", "all_down"], "have no connector, or none connected", "fail")):
        n = m.count(table)
        if n is None:
            unknown(table, table, COLUMN_LABEL[table])
            continue
        k = _with_any(m, table, bad)
        out.append(_kpi(table, n, _n(n, ONE[table], MANY[table]) + (f": {k} {words}." if k else "."), table,
                        bad if k else None, tone if k else ""))
    n = m.count("connectors")
    if n is None:
        unknown("connectors", "connectors", "App Connectors")
    else:
        up = sum(1 for r in m.rows["connectors"] if r["enabled"] and not ({"not_connected", "status_unknown"} & set(r["_flags"])))
        unk = m.count("connectors", "status_unknown")
        out.append(_kpi("connectors", n, f"{_n(n, 'App Connector')}: {up} connected" + (f", {unk} with no status reported." if unk else "."), "connectors"))
        k = m.count("connectors", "not_connected")
        out.append(_kpi("connectors_down", k, f"{_n(k, 'App Connector')} {'is' if k == 1 else 'are'} not connected.",
                        "connectors", ["not_connected"], "fail"))
        k = m.count("connectors", "outdated")
        out.append(_kpi("connectors_outdated", k, f"{_n(k, 'App Connector')} {'is' if k == 1 else 'are'} not on the expected version.",
                        "connectors", ["outdated"], "warn"))
    n = m.count("access_rules")
    if n is None:
        unknown("access_rules", "access_rules", "Access rules")
    else:
        en = sum(1 for r in m.rows["access_rules"] if r["enabled"])
        out.append(_kpi("access_rules", n, f"{_n(n, 'access rule')}, {en} enabled.", "access_rules"))
        if m.assessed("ZPA-AP-01"):
            k = m.count("access_rules", "unreachable")
            out.append(_kpi("rules_unreachable", k, f"{_n(k, 'access rule')} never {'decides' if k == 1 else 'decide'}: an earlier rule always matches first.",
                            "access_rules", ["unreachable"], "fail"))
        k = _with_any(m, "access_rules", ["dangling", "no_app"])
        out.append(_kpi("rules_reference_nothing", k, f"{_n(k, 'access rule')} {'names' if k == 1 else 'name'} deleted or disabled objects, "
                                                      "or reach no enabled app segment.", "access_rules", ["dangling", "no_app"], "warn"))
    return out


# ── tables ──────────────────────────────────────────────────────────────
TABLES: Dict[str, Tuple[str, List[Tuple[str, str]]]] = {
    "segments": ("App segments", [("name", "Name"), ("enabled", "Enabled"), ("segment_group", "Segment group"), ("domains", "Domains and addresses"),
                                  ("tcp", "TCP ports"), ("udp", "UDP ports"), ("server_groups", "Server groups"), ("rules", "Access rules that reach it")]),
    "segment_groups": ("Segment groups", [("name", "Name"), ("enabled", "Enabled"), ("segments", "App segments"),
                                          ("rules_naming", "Access rules naming it"), ("rules_reaching", "Access rules reaching its segments")]),
    "server_groups": ("Server groups", [("name", "Name"), ("enabled", "Enabled"), ("dynamic_discovery", "Dynamic discovery"), ("servers", "Servers"),
                                        ("connector_groups", "Connector groups"), ("segments", "App segments using it")]),
    "connector_groups": ("Connector groups", [("name", "Name"), ("enabled", "Enabled"), ("location", "Location"), ("connectors", "Connectors"),
                                              ("connected", "Connected"), ("versions", "Versions"), ("server_groups", "Server groups using it")]),
    "connectors": ("App Connectors", [("name", "Name"), ("connector_group", "Connector group"), ("enabled", "Enabled"), ("status", "Status"),
                                      ("current_version", "Current version"), ("expected_version", "Expected version"), ("last_connected", "Last connected")]),
    "access_rules": ("Access rules", [("order", "Order"), ("name", "Name"), ("action", "Action"), ("enabled", "Enabled"),
                                      ("applications", "Applications"), ("who", "Who"), ("segments_reached", "App segments reached")]),
    "idps": ("Identity providers", [("name", "Name"), ("enabled", "Enabled"), ("scim_policy", "SCIM-based policy"), ("rules", "Access rules using it")]),
}
TABLE_ORDER = ("segments", "segment_groups", "server_groups", "connector_groups", "connectors", "access_rules", "idps")


def tables(m: _Model) -> Dict[str, Dict[str, Any]]:
    out = {}
    for key in TABLE_ORDER:
        title, cols = TABLES[key]
        rows = m.rows[key]
        if key == "access_rules":
            rows = sorted(rows, key=lambda r: (r["order"] if isinstance(r["order"], int) else 10 ** 9, r["name"].lower()))
        else:
            rows = sorted(rows, key=lambda r: (STATUS_ORDER.get(r["_status"], 9), str(r.get("name", "")).lower()))
        read = m.read(key)
        empty = "" if rows else (f"The {MANY[key]} could not be read ({m.read_error(key)}), so this table is unknown, not empty."
                                 if not read else f"The tenant has no {MANY[key]}.")
        out[key] = {"key": key, "title": title, "columns": [{"key": k, "label": l} for k, l in cols], "rows": rows,
                    "count": len(rows), "read": read, "empty": empty}
    return out


# ── the map ─────────────────────────────────────────────────────────────
def _rank(n: Dict[str, Any], degree: Dict[str, int]) -> Tuple:
    return (STATUS_ORDER.get(n["status"], 9), -degree.get(n["id"], 0), n["label"].lower())


def graph(m: _Model, cap: int = MAP_CAP) -> Dict[str, Any]:
    """The nodes and edges to draw (at most `cap` per column plus one "N
    more" node holding the rest) and the precise filter links."""
    cap = max(1, int(cap))
    degree: Dict[str, int] = {}
    for a, b in m.edges:
        degree[a] = degree.get(a, 0) + 1
        degree[b] = degree.get(b, 0) + 1
    shown: Dict[str, str] = {}      # node id -> drawn node id
    view: List[Dict[str, Any]] = []
    columns = []
    hidden_total = 0
    for col in COLUMN_KEYS:
        ns = sorted((n for n in m.nodes.values() if n["col"] == col), key=lambda n: _rank(n, degree))
        keep, rest = ns[:cap], ns[cap:]
        for n in keep:
            shown[n["id"]] = n["id"]
            view.append(dict(n, degree=degree.get(n["id"], 0)))
        if rest:
            agg = f"{col}:*more"
            worst = min((n["status"] for n in rest), key=lambda s: STATUS_ORDER.get(s, 9))
            bad = sum(1 for n in rest if n["status"] in ("fail", "warn"))
            for n in rest:
                shown[n["id"]] = agg
            view.append({"id": agg, "col": col, "oid": "", "label": f"{len(rest)} more {MANY[col]}",
                         "sub": f"{bad} with issues" if bad else "grouped to keep the map readable", "status": worst, "flags": [],
                         "issues": sum(n["issues"] for n in rest), "aggregate": True, "count": len(rest),
                         "members": [n["id"] for n in rest]})
            hidden_total += len(rest)
        columns.append({"key": col, "label": COLUMN_LABEL[col], "count": len(ns), "shown": len(keep), "hidden": len(rest)})
    edges = sorted({(shown[a], shown[b]) for a, b in m.edges if a in shown and b in shown and shown[a] != shown[b]})
    for v in view:
        v.setdefault("aggregate", False)
    links = sorted(m.links)
    complete = len(links) <= MAX_LINKS
    note = ""
    if hidden_total:
        big = [f"{c['count']} {MANY[c['key']]}" for c in columns if c["hidden"]]
        note = (f"This tenant is large, so each column shows at most {cap} boxes, problems first; the other {hidden_total} objects "
                f"({', '.join(big)} in all) are grouped in the last box of their column. Every object is in the tables below.")
    return {"columns": columns, "nodes": view, "edges": [list(e) for e in edges], "cap": cap, "aggregated": bool(hidden_total),
            "note": note, "notes": MAP_NOTES, "total_nodes": len(m.nodes), "total_edges": len(m.edges),
            "links": {"edges": [list(e) for e in links] if complete else [], "all_apps": m.all_apps if complete else [],
                      "enabled_segments": [f"segments:{s['id']}" for s in m.snap.get("segments") or [] if s.get("enabled")] if complete else [],
                      "complete": complete}}


# ── everything for the page ─────────────────────────────────────────────
def overview(snap: Dict[str, Any], analysis: Dict[str, Any], cap: int = MAP_CAP) -> Dict[str, Any]:
    m = _Model(snap, analysis)
    return {"kpis": kpis(m), "tables": tables(m), "graph": graph(m, cap), "flag_labels": FLAG_LABELS,
            "columns": [{"key": k, "label": COLUMN_LABEL[k], "one": ONE[k], "many": MANY[k]} for k in COLUMN_KEYS]}


# ── the Excel workbook ──────────────────────────────────────────────────
def workbook(snap: Dict[str, Any], analysis: Dict[str, Any], *, tenant_label: str = "", read_at: Any = None,
             findings: Optional[List[Dict[str, Any]]] = None) -> bytes:
    """Every table of the page as one workbook: Overview (the KPI
    sentences, what was not read), one sheet per inventory table with its
    flags and findings, Findings (`findings` when given: the severity
    filter the page applies), Map connections and Not read. Built with
    xlsx_writer: no cell is ever a formula."""
    import xlsx_writer
    m = _Model(snap, analysis)
    wb = xlsx_writer.Workbook(title="ZPA overview", subject=tenant_label or "", creator="Zscaler Made Easy")
    ws = wb.add_sheet("Overview", columns=["Item", "Value"])
    ws.append(["Tenant", tenant_label or ""])
    when = ""
    try:
        when = datetime.fromtimestamp(float(read_at), tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC") if read_at else ""
    except (TypeError, ValueError, OverflowError, OSError):
        when = str(read_at or "")
    ws.append(["Read at", when])
    ws.append(["Note", "Read-only: Zscaler Made Easy read the ZPA configuration once and wrote nothing. A value of \"unknown\" means the list was not read; it is not zero."])
    for k in kpis(m):
        ws.append([k["text"], "unknown" if k["value"] is None else k["value"]])
    for key in TABLE_ORDER:
        title, cols = TABLES[key]
        sh = wb.add_sheet(title, columns=[l for _, l in cols] + ["Status", "Flags", "Findings"])
        rows = tables(m)[key]["rows"]
        if not rows:
            sh.append([tables(m)[key]["empty"]])
        for r in rows:
            sh.append([r.get(k) for k, _ in cols] + [STATUS_WORDS.get(r["_status"], r["_status"]),
                                                     [FLAG_LABELS.get(f, f) for f in r["_flags"]], r["_issues"]])
    fs = wb.add_sheet("Findings", columns=["Severity", "Template", "Title", "Object type", "Object", "What is wrong", "What to do"])
    flist = m.findings if findings is None else findings
    if not flist:
        fs.append(["No finding (or none at the severities chosen)."])
    for f in flist:
        fs.append([f.get("severity"), f.get("template"), f.get("title"), f.get("object_type"), f.get("object"), f.get("reason"), f.get("fix")])
    es = wb.add_sheet("Map connections", columns=["From (type)", "From", "To (type)", "To"])
    for i, (a, b) in enumerate(sorted(m.edges)):
        if i >= MAX_EDGE_ROWS:
            es.append([f"… {len(m.edges) - MAX_EDGE_ROWS} more connections not listed"])
            break
        na, nb = m.nodes.get(a, {}), m.nodes.get(b, {})
        es.append([ONE.get(na.get("col"), ""), na.get("label", a), ONE.get(nb.get("col"), ""), nb.get("label", b)])
    nr = wb.add_sheet("Not read", columns=["List", "Why"])
    missing = [(v.get("label") or k, v.get("error") or "") for k, v in (snap.get("collections") or {}).items() if not v.get("read")]
    if not missing:
        nr.append(["Every list was read."])
    for label, err in missing:
        nr.append([label, err])
    return wb.to_bytes()
