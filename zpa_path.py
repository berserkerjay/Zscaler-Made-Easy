"""ZPA first: before the Path analyzer asks ZIA anything, does ZPA carry
this destination? Pure functions over one ZPA read (zpa_reader, through
device_posture.read so the posture profiles are classified); nothing here
reads or writes a tenant.

The order Client Connector applies, and this module follows:

1. Application segment. Among the enabled segments whose domain list
   matches the destination and whose TCP (or UDP) port ranges contain the
   port, the most specific wins: an exact FQDN, then the longest wildcard
   suffix, then (for an IP address) the longest CIDR prefix
   (zpa_analysis.match_segment). A segment that names the host but not the
   port, a wildcard that covers subdomains but not the apex, an apex that
   does not cover subdomains and a disabled segment are each given as a
   plain hint. No segment: ZPA does not carry it and ZIA applies.
2. The segment's bypass setting (bypassType, verified in the SDK's
   application_segment docstrings: NEVER, ON_NET, ALWAYS). Always: ZPA
   never carries it. On-Net: on a trusted network it goes outside ZPA.
3. The Client Forwarding Policy (policies.list_rules("client_forwarding");
   actions verified in the SDK's add_client_forwarding_rule docstring:
   intercept, intercept_accessible, bypass). Bypass: outside ZPA.
   Intercept accessible: ZPA carries it only when the access policy allows
   this user; otherwise it goes outside ZPA.
4. The Access Policy, first matching rule in rule order, default deny
   (zpa_analysis.evaluate_rule: AND / OR per rule and condition, negated
   conditions, three-valued so a fact nobody gave stays "unknown").

Device posture is evaluated twice, once with every posture profile passing
and once with every one failing, so a rule that depends on posture is
answered both ways. Operand types this tool cannot evaluate (risk score,
Chrome Enterprise, location, connector groups, ...) are flagged by name and
make the answer conditional, never a guess.

When ZPA carries the traffic, ZIA does not apply: the result says so and
the ZIA hops are not traced. When it does not, the caller traces ZIA and
`merge` puts the ZPA stage in front of that result.

Every stage is also returned as a module hop in the shape the Path
analyzer's modules share: {module, verdict, rule: {name, order},
overlaps: [], criteria: [{name, state: match | nomatch | unknown}],
notes: []}. Conditions are worded by device_posture's readable-condition
helpers (Names, plain_sentence).
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

import device_posture
import zpa_analysis
import zpa_reader

BYPASS_LABELS = {"NEVER": "Never", "ON_NET": "On-Net", "ALWAYS": "Always"}
FORWARDING_LABELS = {"INTERCEPT": "Intercept", "INTERCEPT_ACCESSIBLE": "Intercept accessible", "BYPASS": "Bypass"}
ACCESS_EFFECT = {"ALLOW": "allow", "REQUIRE_APPROVAL": "allow", "DENY": "deny"}
# The operand types zpa_analysis can evaluate; any other is flagged.
KNOWN_OPERANDS = frozenset({"APP", "APP_GROUP", "SCIM_GROUP", "SAML", "SCIM", "IDP", "POSTURE", "TRUSTED_NETWORK",
                            "CLIENT_TYPE", "PLATFORM", "COUNTRY_CODE", "MACHINE_GRP"})
# The Path analyzer's platform names to ZPA's PLATFORM operand values.
PLATFORM_TO_ZPA = {"windows": "windows", "macos": "mac", "mac": "mac", "linux": "linux", "ios": "ios", "android": "android"}

ASSUMPTIONS = [
    "ZPA is evaluated first: Client Connector sends a destination that matches a ZPA application segment to ZPA, and ZIA does not see it.",
    "When no Client Forwarding Policy rule matches, Client Connector intercepts the traffic for ZPA (assumed: the SDK does not document the default).",
    "Intercept accessible sends the traffic to ZPA only when the access policy allows this user; otherwise it goes outside ZPA (to ZIA or direct).",
    "On VPN may or may not count as a trusted network for a segment's On-Net bypass; it is answered both ways.",
    "Device posture is evaluated twice: with every posture profile passing and with every one failing. Identity (IdP, SCIM, SAML), country and machine group are left as any user.",
]

VERDICT_WORDS = {"matched": "Matches", "not_matched": "No match", "allowed": "Allowed", "denied": "Denied", "bypassed": "Bypasses",
                 "intercepted": "Intercepted", "forwarded": "Forwarded", "dropped": "Dropped", "conditional": "Conditional",
                 "unknown": "Unable to verify", "not_reached": "Not reached", "not_in_scope": "Not in scope", "carried": "Carried"}


# ── the shared module-hop shape ─────────────────────────────────────────
def module_hop(module: str, verdict: str, rule: Optional[Dict[str, Any]] = None, overlaps: Iterable[str] = (),
               criteria: Iterable[Dict[str, str]] = (), notes: Iterable[str] = (), key: str = "") -> Dict[str, Any]:
    """{module, verdict, rule: {name, order} | None, overlaps, criteria, notes, key}."""
    r = None
    if rule:
        r = {"name": str(rule.get("name") or ""), "order": rule.get("order")}
    return {"key": key, "module": module, "verdict": verdict, "rule": r, "overlaps": [str(x) for x in overlaps if x][:20],
            "criteria": [{"name": str(c["name"]), "state": c["state"]} for c in criteria][:30], "notes": [str(n) for n in notes if n][:12]}


def flow_hop(key: str, label: str, status: str, detail: str, decided_by: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A hop in the Data Flow tracer's shape, for the path diagram."""
    h = {"key": key, "label": label, "status": status, "detail": detail}
    if decided_by:
        h["decided_by"] = {"name": decided_by.get("name"), "order": decided_by.get("order"), "action": decided_by.get("action")}
    return h


# ── destination ─────────────────────────────────────────────────────────
def destination(text: str, port: Any = None, protocol: str = "tcp") -> Dict[str, Any]:
    """zpa_analysis.parse_destination: {input, host, is_ip, port, protocol,
    port_assumed}; ValueError in plain words."""
    return zpa_analysis.parse_destination(text, port if port not in (None, "") else None, protocol or "tcp")


def segment_hints(snap: Dict[str, Any], d: Dict[str, Any], sm: Dict[str, Any]) -> List[str]:
    """Why a near-match did not carry the destination: the port, the apex
    of a wildcard, the subdomains of an apex, a disabled segment."""
    host, proto, port = d["host"], d["protocol"].upper(), d["port"]
    hints: List[str] = []
    for n in sm.get("near_misses") or []:
        hints.append(f"“{n['name']}” lists {n['entry']} but serves {proto} {n['ports'] or 'no port'}, not {port}: add the port to the segment for ZPA to carry it.")
    for n in sm.get("disabled") or []:
        hints.append(f"“{n['name']}” would match through {n['entry']} but is disabled.")
    if not d["is_ip"]:
        apex, sub = [], []
        for s in snap.get("segments") or []:
            for e in s.get("domains") or []:
                k = zpa_analysis._entry_key(e)
                if k in (f"*.{host}", f".{host}"):
                    apex.append(s["name"])
                elif k and not k.startswith(("*", ".")) and host.endswith("." + k) and k != host:
                    sub.append((s["name"], k))
        for name in sorted(set(apex))[:3]:
            hints.append(f"“{name}” lists *.{host}, which covers subdomains only: add {host} itself to the segment for ZPA to carry it.")
        for name, k in sorted(set(sub))[:3]:
            hints.append(f"“{name}” lists {k}, which does not cover its subdomains such as {host}: add *.{k} to the segment for ZPA to carry it.")
    return hints


# ── facts and rule evaluation ───────────────────────────────────────────
def _facts(snap: Dict[str, Any], network: str, platform: str, source: str, posture: str) -> Dict[str, Any]:
    """The user context zpa_analysis evaluates: what the Path analyzer knows
    (platform, Client Connector, trusted network when off network) plus
    one posture scenario ("pass": every profile passes; "fail": none)."""
    if source == "workload":
        # A workload has no Client Connector: posture and trusted networks
        # are Client Connector facts it never presents (assumed).
        return zpa_analysis._norm_user({"posture_pass": [], "trusted_networks": []})
    profiles = [p.get("posture_udid") or p.get("id") for p in snap.get("posture_profiles") or [] if p.get("posture_udid") or p.get("id")]
    return zpa_analysis._norm_user({
        "platform": PLATFORM_TO_ZPA.get(platform),
        "client_type": "zpn_client_type_zapp",
        "trusted_networks": [] if network == "off" else None,
        "posture_pass": profiles if posture == "pass" else [],
    })


def _condition_words(cond: Dict[str, Any], names: device_posture.Names) -> str:
    """One condition in words, from device_posture's operand wording."""
    ops = [names.operand(o) for o in cond.get("operands") or []]
    parts = [("NOT " if o.get("not") else "") + f"{o['type_label']}: {o.get('short') or o.get('text')}" for o in ops[:6]]
    if len(ops) > 6:
        parts.append(f"{len(ops) - 6} more")
    joined = (" and " if (cond.get("operator") or "OR").upper() == "AND" else " or ").join(parts)
    return ("NOT (" + joined + ")") if cond.get("negated") else joined


def _criteria(rule: Dict[str, Any], u: Dict[str, Any], seg: Optional[Dict[str, Any]], ix: Any, names: device_posture.Names) -> List[Dict[str, str]]:
    """Each condition of `rule` with its state for this user and segment."""
    out = []
    for c in rule.get("conditions") or []:
        if not c.get("operands"):
            continue
        vals = [zpa_analysis._eval_operand(o, u, seg, ix)[0] for o in c["operands"]]
        v = zpa_analysis._and(vals) if c["operator"] == "AND" else zpa_analysis._or(vals)
        if c.get("negated") and v is not None:
            v = not v
        out.append({"name": _condition_words(c, names), "state": "unknown" if v is None else ("match" if v else "nomatch")})
    return out


def unknown_operands(rule: Dict[str, Any]) -> List[str]:
    """Operand types in `rule` this tool cannot evaluate."""
    return sorted({o["type"] for c in rule.get("conditions") or [] for o in c.get("operands") or [] if o["type"] not in KNOWN_OPERANDS})


def first_match(rules: List[Dict[str, Any]], u: Dict[str, Any], seg: Optional[Dict[str, Any]], ix: Any,
                effect: Dict[str, str], default: str) -> Dict[str, Any]:
    """The first rule that matches (rule order, disabled rules skipped) and
    every outcome still possible: a rule before it that depends on a fact
    nobody gave could decide instead. {rule, effect, possible: set of
    effects, conditional: [walked rows], walked, flagged}."""
    walked, cond, flagged = [], [], []
    decided = None
    for r in rules:
        base = {"id": r["id"], "name": r["name"], "order": r.get("order"), "action": r["action"]}
        if r.get("disabled"):
            walked.append(dict(base, status="disabled", why="It is disabled, so it is skipped.", depends_on=[]))
            continue
        ev = zpa_analysis.evaluate_rule(r, u, seg, ix)
        row = dict(base, **ev)
        unk = unknown_operands(r)
        if unk and ev["status"] != "not_matched":
            row["unknown_operands"] = unk
            flagged.append({"rule": r["name"], "order": r.get("order"), "types": unk})
        walked.append(row)
        if ev["status"] == "conditional":
            cond.append(row)
        elif ev["status"] == "matched":
            decided = r
            break
    eff = effect.get(decided["action"], decided["action"].lower()) if decided else default
    possible = {effect.get(c["action"], c["action"].lower()) for c in cond} | {eff}
    return {"rule": decided, "effect": eff, "possible": possible, "conditional": cond, "walked": walked, "flagged": flagged}


# ── the stage ───────────────────────────────────────────────────────────
def _outcome(bypass: str, network: str, fwd: Dict[str, Any], acc: Dict[str, Any], vpn_on: bool) -> Set[str]:
    """The possible ends for one posture scenario: zpa_allow, zpa_deny or
    outside (ZPA does not carry it)."""
    if bypass == "ALWAYS":
        return {"outside"}
    if bypass == "ON_NET" and (network == "on" or (network == "vpn" and vpn_on)):
        return {"outside"}
    ends: Set[str] = set()
    for f in fwd["possible"]:
        if f == "bypass":
            ends.add("outside")
            continue
        for a in acc["possible"]:
            if f == "intercept_accessible" and a != "allow":
                ends.add("outside")
            else:
                ends.add("zpa_allow" if a == "allow" else "zpa_deny")
    return ends


def not_read(reason: str, status: str = "unknown") -> Dict[str, Any]:
    """A stage that could not run (not in scope, or the read failed)."""
    verdict = "not_in_scope" if status == "out_of_scope" else "unknown"
    return {"read": False, "status": status, "reason": reason, "carries": None if status != "out_of_scope" else False,
            "outcome": "not_read", "segment": None, "hints": [],
            "modules": [module_hop("ZPA", verdict, notes=[reason], key="zpa")],
            "hops": [flow_hop("zpa_segment", "ZPA app segment", status, reason)],
            "headline": reason, "summary": "", "impacts": [], "assumptions": [], "flagged": []}


def stage(snap: Dict[str, Any], d: Dict[str, Any], *, network: str = "off", platform: str = "windows",
          source: str = "device", profiles: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Whether ZPA carries destination `d` (destination()) for this
    network and platform. `profiles` are device_posture's classified
    posture profiles (for the wording). See the module docstring."""
    ix = zpa_analysis._Index(snap)
    names = device_posture.Names(snap, profiles if profiles is not None else
                                 [dict(p, **device_posture.classify(p.get("name") or "", "")) for p in snap.get("posture_profiles") or []])
    dest_txt = f"{d['host']}:{d['port']}/{d['protocol'].upper()}"
    if not ix.read("segments"):
        return not_read("The ZPA application segments could not be read, so whether ZPA carries this destination is unknown.")
    sm = zpa_analysis.match_segment(snap, d)
    hints = segment_hints(snap, d, sm)
    seg = ix.segments.get(sm["match"]["id"]) if sm["match"] else None
    out: Dict[str, Any] = {"read": True, "status": "read", "segment": sm["match"], "hints": hints, "flagged": [],
                           "candidates": [c["name"] for c in sm["candidates"]], "port_assumed": d.get("port_assumed")}
    seg_overlaps = [f"“{c['name']}” ({c['entry']}, {d['protocol'].upper()} {c['ports']})" + (": equally specific" if c in sm["ambiguous"] else ": less specific")
                    for c in sm["candidates"][1:]]
    if not seg:
        detail = f"No enabled ZPA application segment covers {dest_txt}, so ZPA does not carry it." + (" " + " ".join(hints) if hints else "")
        out.update(carries=False, outcome="not_zpa", headline=f"ZPA does not carry {dest_txt}: no application segment matches it.",
                   summary=detail, impacts=[], assumptions=list(ASSUMPTIONS[:1]),
                   modules=[module_hop("ZPA application segment", "not_matched", notes=[detail], key="zpa_segment")],
                   hops=[flow_hop("zpa_segment", "ZPA app segment", "na", detail)])
        if hints:
            out["impacts"].append({"hop": "zpa_segment", "label": "ZPA app segment", "status": "warn", "rule": None, "severity": "low",
                                   "detail": " ".join(hints), "fix": "If this destination is a private application, fix the segment as the hint says."})
        return out

    m = sm["match"]
    spec = {3: "exact match" if not d["is_ip"] else f"/{m['specificity'][1]} prefix", 2: "wildcard", 1: "catch-all"}.get(m["specificity"][0], "match")
    seg_notes = [f"Matches through {m['entry']} ({spec}), {d['protocol'].upper()} {m['ports']}."]
    if d.get("port_assumed"):
        seg_notes.append(f"No port was given, so port {d['port']} was assumed.")
    if sm["ambiguous"]:
        seg_notes.append("Equally specific segments make the choice ambiguous.")
    if seg.get("match_style") == "INCLUSIVE":
        seg_notes.append("The segment is set to INCLUSIVE multimatch, which this tool does not model.")
    if seg.get("inspect_traffic_with_zia"):
        seg_notes.append("The segment is set to inspect its traffic with ZIA.")
    modules = [module_hop("ZPA application segment", "matched", {"name": seg["name"], "order": None}, seg_overlaps,
                          [{"name": f"Destination {m['entry']}", "state": "match"}, {"name": f"{d['protocol'].upper()} port {d['port']}", "state": "match"}],
                          seg_notes + hints, key="zpa_segment")]
    hops = [flow_hop("zpa_segment", "ZPA app segment", "pass", " ".join(seg_notes), {"name": seg["name"]})]

    # 2. Bypass setting (a Client Connector setting: workloads are not affected)
    bt = (seg.get("bypass_type") or "NEVER").upper() if source == "device" else "NEVER"
    blabel = BYPASS_LABELS.get(bt, bt.title())
    if bt == "ALWAYS":
        bverdict, bnote = "bypassed", f"Bypass is Always: Client Connector never sends {dest_txt} to ZPA."
    elif bt == "ON_NET" and network == "on":
        bverdict, bnote = "bypassed", "Bypass is On-Net and the device is on a trusted network, so the traffic goes outside ZPA."
    elif bt == "ON_NET" and network == "vpn":
        bverdict, bnote = "conditional", "Bypass is On-Net: if the VPN counts as a trusted network the traffic goes outside ZPA, otherwise through it."
    elif bt == "ON_NET":
        bverdict, bnote = "intercepted", "Bypass is On-Net; off a trusted network the traffic goes through ZPA."
    elif source == "workload":
        bverdict, bnote = "intercepted", "Not used: the bypass setting applies to Client Connector, not to workload traffic a connector forwards."
    else:
        bverdict, bnote = "intercepted", "Bypass is Never: Client Connector sends this traffic to ZPA."
    modules.append(module_hop("ZPA segment bypass", bverdict, {"name": f"Bypass: {blabel}", "order": None},
                              criteria=[{"name": f"Network: {network}", "state": "match" if bverdict == "bypassed" else "unknown" if bverdict == "conditional" else "nomatch"}]
                              if bt == "ON_NET" else [], notes=[bnote], key="zpa_bypass"))
    hops.append(flow_hop("zpa_bypass", "ZPA segment bypass", {"bypassed": "bypass", "conditional": "conditional"}.get(bverdict, "pass"), bnote))

    # 3 and 4, once per posture scenario
    scen: Dict[str, Dict[str, Any]] = {}
    pol = snap.get("policies") or {}
    fwd_rules, acc_rules = pol.get("client_forwarding"), pol.get("access")
    for posture in (("pass", "fail") if source == "device" else ("none",)):
        u = _facts(snap, network, platform, source, posture)
        if source == "workload" or fwd_rules is None:
            fwd = {"rule": None, "effect": "intercept", "possible": {"intercept"}, "conditional": [], "walked": [], "flagged": []}
        else:
            fwd = first_match(fwd_rules, u, seg, ix, {k: k.lower() for k in FORWARDING_LABELS}, "intercept")
        if acc_rules is None:
            acc = {"rule": None, "effect": None, "possible": {"allow", "deny"}, "conditional": [], "walked": [], "flagged": []}
        else:
            acc = first_match(acc_rules, u, seg, ix, ACCESS_EFFECT, "deny")
        vpn_cases = (True, False) if (bt == "ON_NET" and network == "vpn") else (False,)
        ends: Set[str] = set()
        for v in vpn_cases:
            ends |= _outcome(bt, network, fwd, acc, v)
        scen[posture] = {"u": u, "fwd": fwd, "acc": acc, "ends": ends}
    first = scen.get("pass") or scen["none"]
    all_ends = set().union(*(s["ends"] for s in scen.values()))
    flagged = {(f["rule"], f["order"], tuple(f["types"])) for s in scen.values() for x in ("fwd", "acc") for f in s[x]["flagged"]}
    out["flagged"] = [{"rule": r, "order": o, "types": list(t)} for r, o, t in sorted(flagged, key=lambda x: (x[1] is None, x[1] or 0, x[0]))]
    posture_matters = source == "device" and scen["pass"]["ends"] != scen["fail"]["ends"]

    # Client Forwarding Policy hop
    f = first["fwd"]
    if source == "workload":
        fv, fnote = "intercepted", "Not used for workload traffic: the connector's forwarding rule sends it to ZPA."
    elif fwd_rules is None:
        fv, fnote = "unknown", "The Client Forwarding Policy could not be read; intercept is assumed."
    else:
        fv = "conditional" if len(f["possible"]) > 1 else ("bypassed" if f["effect"] == "bypass" else "intercepted")
        fnote = (f"Rule “{f['rule']['name']}” decides: {FORWARDING_LABELS.get(f['rule']['action'], f['rule']['action'])}." if f["rule"]
                 else "No rule matches, so Client Connector intercepts it for ZPA (the assumed default).")
        if scen.get("fail") and scen["fail"]["fwd"]["effect"] != f["effect"]:
            fv, fnote = "conditional", fnote + " With device posture failing the answer changes to " + \
                FORWARDING_LABELS.get(scen["fail"]["fwd"]["effect"].upper(), scen["fail"]["fwd"]["effect"]) + "."
    fwd_reached = bverdict != "bypassed"
    modules.append(module_hop("ZPA client forwarding policy", fv if fwd_reached else "not_reached", (f["rule"] or {}) if fwd_reached else None,
                              _overlaps(f) if fwd_reached else [],
                              _criteria(f["rule"], first["u"], seg, ix, names) if (f["rule"] and fwd_reached) else [],
                              ([fnote, device_posture.plain_sentence(f["rule"], names)] if f["rule"] else [fnote]) if fwd_reached else
                              ["Not reached: the segment's bypass sends the traffic outside ZPA first."], key="zpa_forwarding"))
    hops.append(flow_hop("zpa_forwarding", "ZPA client forwarding", ("bypass" if fv == "bypassed" else "conditional" if fv == "conditional" else
                                                                       "unknown" if fv == "unknown" else "pass") if fwd_reached else "not_reached",
                         fnote if fwd_reached else "Not reached.", f["rule"] if fwd_reached else None))

    # Access Policy hop
    a = first["acc"]
    acc_reached = fwd_reached and not (f["effect"] == "bypass" and len(f["possible"]) == 1)
    if acc_rules is None:
        av, anote = "unknown", "The access policy could not be read, so whether ZPA allows this traffic is unknown."
    else:
        av, anote = _access_words(scen, source)
    modules.append(module_hop("ZPA access policy", av if acc_reached else "not_reached", (a["rule"] or {}) if acc_reached else None,
                              _overlaps(a) if acc_reached else [],
                              _criteria(a["rule"], first["u"], seg, ix, names) if (a["rule"] and acc_reached) else [],
                              ([anote] + ([device_posture.plain_sentence(a["rule"], names)] if a["rule"] else [])
                               + [f"Not evaluated: {', '.join(x['types'])} in rule “{x['rule']}”." for x in out["flagged"][:5]]) if acc_reached else
                              ["Not reached: the traffic goes outside ZPA before the access policy."], key="zpa_access"))
    hops.append(flow_hop("zpa_access", "ZPA access policy", ({"allowed": "pass", "denied": "blocked"}.get(av, av if av in ("conditional", "unknown") else "pass"))
                         if acc_reached else "not_reached", anote if acc_reached else "Not reached.", a["rule"] if acc_reached else None))

    # App Connectors (zpa_analysis._serving), only when ZPA may allow it
    if "zpa_allow" in all_ends:
        serve = zpa_analysis._serving(seg, ix)
        cv = "allowed" if serve["reachable"] else ("denied" if serve["reachable"] is False else "unknown")
        modules.append(module_hop("ZPA App Connectors", cv, None, [], [], [serve["sg_detail"], serve["cg_detail"]], key="zpa_connectors"))
        hops.append(flow_hop("zpa_connectors", "App Connectors", {"allowed": "pass", "denied": "blocked"}.get(cv, "unknown"),
                             serve["cg_detail"] if serve["reachable"] is not False else serve["why_down"]))
        out["reachable"] = serve["reachable"]

    out.update(modules=modules, hops=hops, posture_matters=posture_matters,
               ends=sorted(all_ends), assumptions=list(ASSUMPTIONS),
               scenarios={k: {"forwarding": v["fwd"]["effect"], "access": v["acc"]["effect"], "ends": sorted(v["ends"]),
                              "rule": (v["acc"]["rule"] or {}).get("name"), "conditional": [c["name"] for c in v["acc"]["conditional"]][:5]}
                          for k, v in scen.items()})
    _verdict(out, seg, dest_txt, bt, f, a, scen, source)
    return out


def _overlaps(fm: Dict[str, Any]) -> List[str]:
    """Rules before the deciding one that could decide instead (compressed)."""
    return [f"“{c['name']}” (order {c.get('order')}, {c['action']}) could decide instead: it depends on {zpa_analysis._and_list(c['depends_on']) or 'facts not given'}"
            for c in fm["conditional"][:8]]


def _access_words(scen: Dict[str, Dict[str, Any]], source: str) -> Tuple[str, str]:
    def one(s):
        a = s["acc"]
        if a["rule"]:
            word = "allows" if a["effect"] == "allow" else "denies"
            return f"rule “{a['rule']['name']}” {word} it"
        return "no rule allows it, so ZPA denies by default"
    if source == "workload":
        s = scen["none"]
        v = "conditional" if len(s["acc"]["possible"]) > 1 else ("allowed" if s["acc"]["effect"] == "allow" else "denied")
        return v, one(s)[0].upper() + one(s)[1:] + "."
    p, f = scen["pass"], scen["fail"]
    if one(p) == one(f):
        v = "conditional" if len(p["acc"]["possible"]) > 1 else ("allowed" if p["acc"]["effect"] == "allow" else "denied")
        text = one(p)[0].upper() + one(p)[1:] + ", whether device posture passes or fails."
    else:
        v = "conditional"
        text = f"With device posture passing, {one(p)}; with it failing, {one(f)}."
    if len(p["acc"]["possible"]) > 1:
        text += " An earlier rule depends on facts not given (identity, network or an operand this tool cannot evaluate)."
    return v, text


def _verdict(out: Dict[str, Any], seg: Dict[str, Any], dest_txt: str, bt: str, f: Dict[str, Any], a: Dict[str, Any],
             scen: Dict[str, Dict[str, Any]], source: str) -> None:
    ends = set(out["ends"])
    name = seg["name"]
    impacts: List[Dict[str, Any]] = []
    if ends == {"outside"}:
        out["carries"] = False
        if bt == "ALWAYS":
            why = f"segment “{name}” is set to bypass ZPA always"
        elif bt == "ON_NET" and "outside" in ends and f["effect"] != "bypass":
            why = f"segment “{name}” bypasses ZPA on a trusted network"
        elif f["effect"] == "bypass":
            why = f"Client Forwarding Policy rule “{(f['rule'] or {}).get('name')}” bypasses ZPA"
        else:
            why = "the forwarding rule intercepts only accessible applications and the access policy does not allow this user"
        out.update(outcome="outside", headline=f"ZPA matches {dest_txt} but does not carry it: {why}.",
                   summary=f"Application segment “{name}” covers the destination, but {why}, so the traffic is handled as internet traffic: ZIA applies.")
        impacts.append({"hop": "zpa_bypass", "label": "ZPA", "status": "warn", "rule": name, "severity": "medium",
                        "detail": f"A private application segment matches, but {why}; the traffic leaves ZPA.",
                        "fix": "If this is a private application, keep it in ZPA (bypass Never, forwarding Intercept)."})
    elif ends == {"zpa_allow"}:
        out["carries"] = True
        r = a["rule"] or {}
        out.update(outcome="zpa_allowed", headline=f"Carried by ZPA and allowed by access rule “{r.get('name')}”: ZIA does not apply.",
                   summary=f"Application segment “{name}” matches {dest_txt}; ZPA carries it to the App Connectors, so ZIA URL filtering, SSL inspection and Web DLP never see it.")
        if out.get("reachable") is False:
            impacts.append({"hop": "zpa_connectors", "label": "App Connectors", "status": "blocked", "rule": None, "severity": "high",
                            "detail": "ZPA allows it, but no App Connector serving the segment is connected, so the connection fails.",
                            "fix": "Bring an App Connector in the segment's server group online."})
    elif ends == {"zpa_deny"}:
        out["carries"] = True
        r = a["rule"]
        by = f"access rule “{r['name']}”" if r else "ZPA's default deny (no access rule allows it)"
        out.update(outcome="zpa_denied", headline=f"Blocked by ZPA: {by}. ZIA does not apply.",
                   summary=f"Application segment “{name}” matches {dest_txt}; ZPA carries it and the access policy denies it, so the user cannot reach it.")
        impacts.append({"hop": "zpa_access", "label": "ZPA access policy", "status": "blocked", "rule": r["name"] if r else None, "severity": "high",
                        "detail": f"Denied by {by}.", "fix": "If this user should reach the application, add or reorder an access rule that allows them."})
    else:
        out["carries"] = None if "outside" in ends else True
        if out.get("posture_matters"):
            p, fl = scen["pass"], scen["fail"]
            words = {"zpa_allow": "ZPA allows it", "zpa_deny": "ZPA denies it", "outside": "it goes outside ZPA (ZIA applies)"}
            head = (f"Depends on device posture: when posture passes {' or '.join(words[e] for e in sorted(p['ends']))}; "
                    f"when it fails {' or '.join(words[e] for e in sorted(fl['ends']))}.")
        else:
            head = f"Depends on who the user is or on facts not given: ZPA may {'carry or not carry' if 'outside' in ends else 'allow or deny'} {dest_txt}."
        out.update(outcome="zpa_conditional", headline=head,
                   summary=f"Application segment “{name}” matches. " + ("If ZPA carries it, ZIA does not apply; the ZIA path below is what happens otherwise."
                                                                      if "outside" in ends else "Either way ZPA carries it, so ZIA does not apply."))
        impacts.append({"hop": "zpa_access", "label": "ZPA", "status": "conditional", "rule": None, "severity": "medium",
                        "detail": head, "fix": None})
    for x in out["flagged"][:5]:
        impacts.append({"hop": "zpa_access", "label": "ZPA rule not fully evaluated", "status": "unknown", "rule": x["rule"], "severity": "info",
                        "detail": f"Rule “{x['rule']}” uses {', '.join(x['types'])}, which this tool cannot evaluate; it is treated as depending on it.", "fix": None})
    out["impacts"] = impacts


# ── the Path analyzer result ────────────────────────────────────────────
def standalone(pre_hops: List[Dict[str, Any]], modules: List[Dict[str, Any]], *, outcome: str, headline: str, summary: str,
               dest: Dict[str, Any], network: str, platform: str, scope: Dict[str, Any], impacts: List[Dict[str, Any]],
               assumptions: List[str], stops_at: Optional[str], blocked_by: Optional[str], reaches_zscaler: bool,
               mitigations: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """A complete Path analyzer result for a path that ends before ZIA
    (ZPA carries it, or a connector sends it direct or drops it): the same
    keys the page renders, with no ZIA hop, so nothing claims ZIA saw it."""
    trace = {"hops": pre_hops, "outcome": outcome, "reaches_zscaler": reaches_zscaler, "decrypted": False, "channels": {},
             "destination": {"host": dest["host"], "label": dest["host"], "categories": [], "applications": []},
             "network": network, "platform": platform, "weak_points": []}
    verdict = {"outcome": outcome, "headline": headline, "summary": summary, "stops_at": stops_at, "blocked_by": blocked_by,
               "reaches_zscaler": reaches_zscaler, "decrypted": False, "content_inspected": False, "content_inspection_possible": False,
               "evidence_mode": "configuration", "tested_channel": "web", "policy_conditional": outcome.endswith("conditional"),
               "impacts": impacts, "categories": [], "applications": [], "not_in_scope": [], "mitigations": mitigations or []}
    return {"destination": dest, "lookup": {"categories": [], "security_alerts": [], "application": None, "error": None, "not_asked": True},
            "trace": trace, "verdict": verdict, "assumptions": assumptions, "scope": scope, "modules": modules,
            "network": network, "platform": platform, "read_at": time.time(), "fresh_read": True, "zia_applies": False}


def zpa_mitigations(st: Dict[str, Any]) -> List[Dict[str, Any]]:
    """For traffic ZPA carries: ZIA's Web DLP never sees it."""
    if st.get("outcome") != "zpa_allowed":
        return []
    return [{"rank": 1, "channel": "endpoint", "action": "Cover this private application with Endpoint DLP or ZPA inspection",
             "why": "ZPA carries this traffic to the application, so ZIA's Web DLP never inspects it; Endpoint DLP on the device, "
                    "or ZPA AppProtection, are the controls that can see it.", "severity": "info"}]


def merge(zia: Dict[str, Any], pre_hops: List[Dict[str, Any]], modules: List[Dict[str, Any]], impacts: List[Dict[str, Any]],
          assumptions: List[str], note: str = "") -> Dict[str, Any]:
    """The ZIA result with the earlier stages in front: their hops first in
    the path, their module hops, impacts and assumptions added. The ZIA
    verdict stands; `note` (why ZIA applies) leads its summary."""
    out = dict(zia)
    t = dict(out.get("trace") or {})
    t["hops"] = list(pre_hops) + list(t.get("hops") or [])
    out["trace"] = t
    v = dict(out.get("verdict") or {})
    v["impacts"] = list(impacts) + list(v.get("impacts") or [])
    if note:
        v["summary"] = (note + " " + (v.get("summary") or "")).strip()
    out["verdict"] = v
    out["modules"] = list(modules) + list(out.get("modules") or [])
    out["assumptions"] = list(assumptions) + [a for a in out.get("assumptions") or [] if a not in assumptions]
    out["zia_applies"] = True
    return out


def read(client: Any, log: Any = None, cancel: Any = None, pace: Optional[float] = None) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """(ZPA snapshot, classified posture profiles): device_posture.read,
    i.e. zpa_reader.read with the posture profiles' raw JSON kept, no extra
    call. Raises zpa_reader.Stopped / ReadError."""
    snap, raw, _ = device_posture.read(client, log=log, cancel=cancel, zcc=False, pace=pace)
    profiles = [device_posture.normalize_profile(x) for x in raw.get("posture_profiles") or []]
    return snap, profiles


Stopped = zpa_reader.Stopped
ReadError = zpa_reader.ReadError
