"""Device posture: which ZPA posture profiles and trusted networks exist,
what kind of check each one is, which access rules use them (and whether
as "must pass" or "must fail"), and what each access rule's conditions say,
in plain words. Read-only; pure functions over one ZPA read.

What is read (verified against the installed zscaler-sdk-python):

  * The ZPA configuration, through `zpa_reader.read` (application
    segments, segment groups, IdPs, SAML attributes, posture profiles,
    trusted networks, machine groups, SCIM groups and every policy type).
    Its normalized posture profile keeps only id, name, postureUdid and
    platform, so the raw JSON of `posture_profiles.list_posture_profiles`
    and `trusted_networks.list_trusted_networks` is taken as the reader
    reads it (`_Tap`): no extra API call. The SDK model PostureProfile
    carries `postureType`, `platform`, `crlCheckEnabled`,
    `nonExportablePrivateKeyEnabled`, `applyToMachineTunnelEnabled`,
    `zscalerCloud` and `rootCert`; TrustedNetwork carries `networkId`,
    `domain` and `zscalerCloud`.
  * Only when Client Connector is also ticked on the Scope page: the
    Client Connector trusted networks (`zcc.trusted_networks.
    list_by_company`, GET /zcc/papi/public/v1/webTrustedNetwork/
    listByCompany), for the criteria each network is defined by. The SDK
    has no Client Connector device posture list, so none is read.

Assumed, not verifiable from the SDK (stated on the page and in exports):

  * The `postureType` values. The SDK types the field as a plain string
    with no list of values; the classifier matches it by keywords
    (CROWDSTRIKE, DOMAIN_JOIN, CERT, DISK_ENCRYPTION, OS_VERSION, ...), so
    a spelling variant still lands in the right family. A type no keyword
    matches falls back to the name, and says so.
  * A POSTURE operand's `lhs` is the profile's postureUdid and `rhs` is
    "true" (the device must pass) or "false" (must fail); a
    TRUSTED_NETWORK operand's `lhs` is the network's networkId and `rhs`
    "true" (on it) or "false" (off it). The condition's `negated` inverts
    the whole condition. (The same reading zpa_analysis uses.)
  * A ZPA trusted network's networkId is the Client Connector trusted
    network's guid.

Reusable by other pages: `Names(snapshot)` resolves operand ids to names,
`condition_tree(rule, names)` gives nested AND / OR / NOT groups,
`condition_html(tree)` renders them as accessible nested lists,
`condition_text(tree)` as indented text, and `plain_sentence(rule, names)`
says the rule in one sentence. `readable_rule(rule, names)` returns all of
them at once.
"""
from __future__ import annotations

import html
import ipaddress
import re
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import zpa_analysis
import zpa_reader
from zpa_reader import as_bool, as_str, get

# ── families ────────────────────────────────────────────────────────────
# (id, label, enforces device health). A marker or override proves only
# that a file, registry key or variable is present; it is never counted as
# EDR, domain join or any other enforcement.
FAMILIES: Tuple[Tuple[str, str, bool], ...] = (
    ("domain_join", "Domain join", True),
    ("edr", "EDR or antivirus", True),
    ("certificate", "Client certificate", True),
    ("disk_hygiene", "Disk encryption and device hygiene", True),
    ("os_version", "OS version", True),
    ("mobile_integrity", "Mobile integrity (jailbreak or root)", True),
    ("mdm", "MDM enrollment", True),
    ("firewall", "Firewall", True),
    ("process", "Process running", True),
    ("marker", "Marker or override", False),
    ("unknown", "Unknown", False),
)
FAMILY_LABEL = {f: label for f, label, _ in FAMILIES}


def lower_label(label: str) -> str:
    """A family label inside a sentence: lower case, acronyms kept (EDR, OS, MDM)."""
    first, _, rest = (label or "").partition(" ")
    first = first if first.isupper() else first.lower()
    return (first + (" " + rest if rest else "")).strip()


def with_article(text: str) -> str:
    return ("an " if text[:1].lower() in "aeiou" or text.split(" ")[0] in ("EDR", "MDM", "OS") else "a ") + text
ENFORCES = {f: e for f, _, e in FAMILIES}

# postureType keywords, first match wins (the type is uppercased and every
# run of other characters becomes "_").
TYPE_RULES: Tuple[Tuple[str, str], ...] = (
    ("marker", r"FILE_?PATH|FILE_CHECK|REGISTRY|REG_?KEY|OWNERSHIP|MARKER|OVERRIDE|VARIABLE"),
    ("edr", r"CROWDSTRIKE|SENTINEL|CARBON_?BLACK|DEFENDER|EDR|XDR|ANTI_?VIRUS|ANTI_?MALWARE|CYLANCE|TANIUM|ZTA_?SCORE|RISK_?SCORE"),
    ("domain_join", r"DOMAIN_?JOIN|AZURE_?AD|ENTRA|HYBRID_?JOIN"),
    ("certificate", r"CERT"),
    ("disk_hygiene", r"DISK|ENCRYPT|BITLOCKER|FILEVAULT|CLIENT_CONNECTOR_VERSION|ZCC_VERSION|SCREEN_?LOCK|PATCH|HYGIENE"),
    ("os_version", r"OS_VERSION|OPERATING_SYSTEM"),
    ("mobile_integrity", r"JAIL|ROOT|UNAUTHORI[SZ]ED_MODIFICATION|INTEGRITY|TAMPER"),
    ("mdm", r"MDM|INTUNE|JAMF|WORKSPACE_?ONE|AIRWATCH|MOBILEIRON"),
    ("firewall", r"FIREWALL"),
    ("process", r"PROCESS"),
)
# Name heuristics (case-insensitive), first match wins: marker words first,
# so "CrowdStrike override" is a marker, never EDR.
NAME_RULES: Tuple[Tuple[str, str], ...] = (
    ("marker", r"\b(marker|override|bypass|exception|exempt|always[ _-]?(pass|true|allow)|dummy|placeholder|file[ _-]?path|registry|reg[ _-]?key|ownership)\b"),
    ("edr", r"\b(crowd ?strike|falcon|sentinel ?one|s1|carbon ?black|defender|mde|edr|xdr|anti[ -]?virus|av|anti[ -]?malware|cylance|sophos|trend ?micro|symantec|mcafee|trellix|cortex|tanium|zta)\b"),
    ("domain_join", r"\b(domain[ _-]?join(ed)?|ad[ _-]?join(ed)?|azure ?ad|entra|hybrid[ _-]?join(ed)?|domain)\b"),
    ("certificate", r"\b(cert|certs|certificate|certificates|pki|ca)\b"),
    ("disk_hygiene", r"\b(disk|encryption|encrypted|bitlocker|filevault|fde|hygiene|screen ?lock|patch(ed|level)?|zcc version|client connector version)\b"),
    ("mobile_integrity", r"\b(jail ?break|jail ?broken|root|rooted|integrity|unauthori[sz]ed modification|tamper(ed)?)\b"),
    ("os_version", r"\b(os version|os|windows 1[01]|macos|ios version|android version|os build)\b"),
    ("mdm", r"\b(mdm|intune|jamf|workspace ?one|airwatch|mobileiron|managed device|managed)\b"),
    ("firewall", r"\b(firewall|fw)\b"),
    ("process", r"\b(process|running|service running)\b"),
)
_TYPE_RX = [(f, re.compile(rx)) for f, rx in TYPE_RULES]
_NAME_RX = [(f, re.compile(rx, re.I)) for f, rx in NAME_RULES]

# Posture phrases for the plain-English reading: (passes, fails).
FAMILY_PHRASES = {
    "domain_join": ("the device is domain-joined", "the device is not domain-joined"),
    "edr": ("the device passes the EDR or antivirus check", "the device fails the EDR or antivirus check"),
    "certificate": ("the device has the client certificate", "the device lacks the client certificate"),
    "disk_hygiene": ("the device passes the disk encryption or hygiene check", "the device fails the disk encryption or hygiene check"),
    "os_version": ("the device runs an allowed OS version", "the device does not run an allowed OS version"),
    "mobile_integrity": ("the device passes the jailbreak and root check", "the device fails the jailbreak and root check"),
    "mdm": ("the device is MDM-enrolled", "the device is not MDM-enrolled"),
    "firewall": ("the device firewall is on", "the device firewall is not on"),
    "process": ("the required process runs on the device", "the required process does not run on the device"),
    "marker": ("the device carries the marker", "the device does not carry the marker"),
    "unknown": ("the device passes the posture check", "the device fails the posture check"),
}

# ── operands ────────────────────────────────────────────────────────────
TYPE_LABELS = {
    "APP": "Application segment", "APP_GROUP": "Segment group", "IDP": "Identity provider", "SCIM_GROUP": "SCIM group",
    "SCIM": "SCIM attribute", "SAML": "SAML attribute", "POSTURE": "Device posture", "TRUSTED_NETWORK": "Trusted network",
    "PLATFORM": "Platform", "CLIENT_TYPE": "Client type", "COUNTRY_CODE": "Country", "MACHINE_GRP": "Machine group",
    "LOCATION": "Location", "RISK_FACTOR_TYPE": "Risk", "CHROME_ENTERPRISE": "Chrome Enterprise",
    "CHROME_POSTURE_PROFILE": "Chrome posture profile", "USER_PORTAL": "User portal",
    "BRANCH_CONNECTOR_GROUP": "Branch Connector group", "EDGE_CONNECTOR_GROUP": "Cloud Connector group",
}
PLATFORM_LABELS = {"windows": "Windows", "mac": "macOS", "linux": "Linux", "ios": "iOS", "android": "Android", "chromeos": "ChromeOS"}
APP_TYPES = ("APP", "APP_GROUP")
ACTION_VERBS = {"ALLOW": "Allow", "DENY": "Block", "REQUIRE_APPROVAL": "Allow, after approval,"}
GRANTING = ("ALLOW", "REQUIRE_APPROVAL")

# Sensitive and broad segments (for "no posture" findings).
SENSITIVE_NAME = re.compile(
    r"\b(hr|human resources|payroll|finance|financial|accounting|billing|prod|production|critical|core|admin|administration|"
    r"privileged|pam|database|databases|db|sql|oracle|sap|erp|crm|domain controllers?|active directory|ldap|rdp|ssh|"
    r"jump ?hosts?|bastion|vault|secrets?|pci|phi|pii|health|legal|backups?)\b", re.I)

POLICY_LABELS = dict(zpa_reader.POLICY_TYPES)

ASSUMPTIONS = [
    "Posture families come from the profile's posture type where the type is recognised (reliable). Otherwise they are "
    "inferred from the profile's name and marked as inferred. The posture type values are matched by keyword: the SDK "
    "types the field as free text and lists no values.",
    "A marker or override (a file path, registry key or ownership variable check, or a profile named as an override) "
    "proves only that something is present on the device. It is never counted as EDR, domain join or any other "
    "enforcement, even when its name mentions one.",
    "A posture operand says \"true\" when the device must pass the profile and \"false\" when it must fail it; a "
    "negated condition inverts that. A trusted network operand reads the same way for being on or off the network.",
    "Access rules are evaluated in rule order; a rule's operator (default AND) joins its conditions, a condition's "
    "operator (default OR) joins its operands. Disabled rules are listed but not counted in the findings.",
    "A segment is treated as sensitive when its name, segment group or domains name HR, payroll, finance, production, "
    "admin, databases, directory, remote access and similar, or when it serves a directory, remote-access or database "
    "port. A segment is broad when it has a wildcard domain, an IPv4 range of /16 or wider, or more than "
    f"{zpa_analysis.WIDE_PORT_SPAN} ports.",
    "Client Connector trusted networks are matched to ZPA trusted networks by the ZPA network ID, assumed to be the "
    "Client Connector network's GUID.",
]

STOPPED_REASON = zpa_reader.STOPPED_REASON
ZCC_PAGE_SIZE = 500     # assumption: the SDK documents page / page_size but no maximum for this list
ZCC_MAX_PAGES = 10


# ── classification ──────────────────────────────────────────────────────
def _type_key(t: str) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", (t or "").upper()).strip("_")


def family_from_type(posture_type: str) -> Optional[str]:
    key = _type_key(posture_type)
    if not key:
        return None
    for fam, rx in _TYPE_RX:
        if rx.search(key):
            return fam
    return None


def family_from_name(name: str) -> Optional[str]:
    text = re.sub(r"[_]+", " ", name or "")
    for fam, rx in _NAME_RX:
        if rx.search(text):
            return fam
    return None


def classify(name: str, posture_type: str = "") -> Dict[str, Any]:
    """{family, label, source, confidence, enforces, why, name_family}.
    source "type" (reliable), "name" (inferred) or "none" (unknown)."""
    by_type = family_from_type(posture_type)
    by_name = family_from_name(name)
    if by_type:
        fam, source, conf = by_type, "type", "reliable"
        why = f"Posture type {posture_type} is {with_article(lower_label(FAMILY_LABEL[fam]))} check."
        if by_name and by_name != fam and fam == "marker":
            why += (f" The name suggests {lower_label(FAMILY_LABEL[by_name])}, but the check only proves that a file, registry key "
                    "or variable is present, so it is not counted as that enforcement.")
    elif by_name:
        fam, source, conf = by_name, "name", "inferred"
        why = (f"Posture type {posture_type} is not one this page recognises; " if posture_type else "The posture type was not given; ") + \
              f"the name suggests {lower_label(FAMILY_LABEL[fam])}."
    else:
        fam, source, conf = "unknown", "none", "unknown"
        why = (f"Neither the posture type {posture_type} nor the name says what the check is." if posture_type
               else "No posture type was given and the name does not say what the check is.")
    return {"family": fam, "label": FAMILY_LABEL[fam], "source": source, "confidence": conf, "enforces": ENFORCES[fam],
            "why": why, "name_family": by_name}


def normalize_profile(raw: Dict[str, Any]) -> Dict[str, Any]:
    """One posture profile from the API's JSON (camelCase) or the SDK model's
    as_dict (snake_case). The root certificate itself is never kept."""
    plat = get(raw, "platform")
    platforms = [as_str(p) for p in plat] if isinstance(plat, list) else ([as_str(plat)] if as_str(plat) else [])
    p = {"id": as_str(get(raw, "id")), "name": as_str(get(raw, "name")) or as_str(get(raw, "id")),
         "posture_udid": as_str(get(raw, "postureUdid")), "posture_type": as_str(get(raw, "postureType")),
         "platforms": [x for x in platforms if x],
         "crl_check": as_bool(get(raw, "crlCheckEnabled")), "non_exportable_key": as_bool(get(raw, "nonExportablePrivateKeyEnabled")),
         "machine_tunnel": as_bool(get(raw, "applyToMachineTunnelEnabled")), "has_root_cert": bool(get(raw, "rootCert")),
         "zscaler_cloud": as_str(get(raw, "zscalerCloud"))}
    p.update(classify(p["name"], p["posture_type"]))
    return p


def normalize_trusted(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(raw, "id")), "name": as_str(get(raw, "name")) or as_str(get(raw, "id")),
            "network_id": as_str(get(raw, "networkId")), "domain": as_str(get(raw, "domain")), "zscaler_cloud": as_str(get(raw, "zscalerCloud"))}


ZCC_CRITERIA = (("dnsServers", "DNS servers"), ("dnsSearchDomains", "DNS search domains"), ("hostnames", "hostnames"),
                ("trustedSubnets", "subnets"), ("trustedGateways", "gateways"), ("trustedDhcpServers", "DHCP servers"),
                ("trustedEgressIps", "egress IPs"), ("ssids", "Wi-Fi networks"))


def normalize_zcc_network(raw: Dict[str, Any]) -> Dict[str, Any]:
    crit = []
    for key, label in ZCC_CRITERIA:
        v = get(raw, key)
        if (isinstance(v, (list, tuple)) and any(as_str(x) for x in v)) or (isinstance(v, str) and v.strip()):
            crit.append(label)
    return {"id": as_str(get(raw, "id")), "guid": as_str(get(raw, "guid")), "name": as_str(get(raw, "networkName")) or as_str(get(raw, "id")),
            "active": as_bool(get(raw, "active")), "condition_type": as_str(get(raw, "conditionType")), "criteria": crit}


# ── names ───────────────────────────────────────────────────────────────
class Names:
    """Operand ids to names, from a zpa_reader snapshot (plus the classified
    posture profiles, when given)."""

    def __init__(self, snap: Dict[str, Any], profiles: Optional[List[Dict[str, Any]]] = None):
        def by_id(key):
            return {x["id"]: x for x in (snap.get(key) or []) if x.get("id")}
        self.segments = by_id("segments")
        self.segment_groups = by_id("segment_groups")
        self.idps = by_id("idps")
        self.saml = by_id("saml_attributes")
        self.machine = by_id("machine_groups")
        plist = profiles if profiles is not None else (snap.get("posture_profiles") or [])
        self.posture = {p["id"]: p for p in plist if p.get("id")}
        self.posture_udid = {p["posture_udid"]: p for p in plist if p.get("posture_udid")}
        tl = snap.get("trusted_networks") or []
        self.trusted = {t["id"]: t for t in tl if t.get("id")}
        self.trusted_nid = {t["network_id"]: t for t in tl if t.get("network_id")}
        self.scim: Dict[str, Dict[str, Any]] = {}
        for idp_id, v in (snap.get("scim_groups") or {}).items():
            for g in (v or {}).get("groups") or []:
                self.scim[g["id"]] = dict(g, idp_id=idp_id)

    def profile(self, ref: str) -> Optional[Dict[str, Any]]:
        return self.posture_udid.get(ref) or self.posture.get(ref)

    def network(self, ref: str) -> Optional[Dict[str, Any]]:
        return self.trusted_nid.get(ref) or self.trusted.get(ref)

    def operand(self, o: Dict[str, Any]) -> Dict[str, Any]:
        """{kind: operand, type, type_label, name, ref, resolved, not, text,
        family?}: `not` is the operand's own negative (posture must fail,
        off a trusted network, platform false); `text` is the positive
        reading, so NOT is always said explicitly beside it."""
        t, lhs, rhs, given = o.get("type") or "", o.get("lhs") or "", o.get("rhs") or "", o.get("name") or ""
        out: Dict[str, Any] = {"kind": "operand", "type": t, "type_label": TYPE_LABELS.get(t, t.replace("_", " ").capitalize() or "Condition"),
                               "not": False, "resolved": True}
        q = "“{}”".format
        if t == "APP":
            s = self.segments.get(rhs)
            out.update(name=s["name"] if s else (given or rhs), ref=rhs, resolved=bool(s))
            out["text"] = f"application segment {q(out['name'])}"
        elif t == "APP_GROUP":
            g = self.segment_groups.get(rhs)
            out.update(name=g["name"] if g else (given or rhs), ref=rhs, resolved=bool(g))
            out["text"] = f"segment group {q(out['name'])}"
        elif t == "SCIM_GROUP":
            g, idp = self.scim.get(rhs), self.idps.get(lhs)
            out.update(name=g["name"] if g else (given or rhs), ref=rhs, resolved=bool(g), idp=idp["name"] if idp else lhs)
            out["text"] = f"member of SCIM group {q(out['name'])}" + (f" ({idp['name']})" if idp else "")
        elif t in ("SAML", "SCIM"):
            a = self.saml.get(lhs) if t == "SAML" else None
            out.update(name=a["name"] if a else (given or lhs), ref=lhs, value=rhs, resolved=bool(a) or t == "SCIM")
            out["text"] = f"{t} attribute {q(out['name'])} is {q(rhs)}"
        elif t == "IDP":
            i = self.idps.get(rhs)
            out.update(name=i["name"] if i else (given or rhs), ref=rhs, resolved=bool(i))
            out["text"] = f"signed in through IdP {q(out['name'])}"
        elif t == "POSTURE":
            p = self.profile(lhs)
            out.update(name=p["name"] if p else (given or lhs), ref=lhs, resolved=bool(p))
            out["family"] = p["family"] if p else "unknown"
            out["family_label"] = FAMILY_LABEL[out["family"]]
            out["not"] = rhs.strip().lower() == "false"
            out["text"] = f"device passes posture {q(out['name'])} ({lower_label(out['family_label'])})"
        elif t == "TRUSTED_NETWORK":
            n = self.network(lhs)
            out.update(name=n["name"] if n else (given or lhs), ref=lhs, resolved=bool(n))
            out["not"] = rhs.strip().lower() == "false"
            out["text"] = f"device is on trusted network {q(out['name'])}"
        elif t == "PLATFORM":
            out.update(name=PLATFORM_LABELS.get(lhs.lower(), lhs), ref=lhs)
            out["not"] = rhs.strip().lower() == "false"
            out["text"] = f"platform is {out['name']}"
        elif t == "CLIENT_TYPE":
            want = rhs if rhs.startswith("zpn_client_type") else (lhs if lhs.startswith("zpn_client_type") else rhs or lhs)
            out.update(name=zpa_analysis.CLIENT_TYPES.get(want, want), ref=want)
            out["text"] = f"client type is {out['name']}"
        elif t == "COUNTRY_CODE":
            out.update(name=lhs.upper(), ref=lhs)
            out["not"] = rhs.strip().lower() == "false"
            out["text"] = f"country is {out['name']}"
        elif t == "MACHINE_GRP":
            m = self.machine.get(rhs)
            out.update(name=m["name"] if m else (given or rhs), ref=rhs, resolved=bool(m))
            out["text"] = f"machine group {q(out['name'])}"
        else:
            val = given or rhs or lhs
            out.update(name=val, ref=rhs or lhs)
            out["text"] = f"{out['type_label'].lower()} is {q(val)}" if val else out["type_label"].lower()
        out["short"] = _short(out)
        return out


def _short(op: Dict[str, Any]) -> str:
    """The operand's value without its kind (the kind is shown beside it)."""
    t, n = op["type"], op.get("name") or ""
    q = "\u201c{}\u201d".format(n)
    if t in ("APP", "APP_GROUP", "IDP", "MACHINE_GRP"):
        return q
    if t == "SCIM_GROUP":
        return q + (f" ({op['idp']})" if op.get("idp") and op.get("idp") != op.get("ref") else "")
    if t in ("SAML", "SCIM"):
        return f"{q} is \u201c{op.get('value') or ''}\u201d"
    if t == "POSTURE":
        return f"passes {q} ({lower_label(op['family_label'])})"
    if t == "TRUSTED_NETWORK":
        return f"on {q}"
    if t in ("PLATFORM", "CLIENT_TYPE", "COUNTRY_CODE"):
        return n
    return op.get("text") or n


# ── readable conditions ─────────────────────────────────────────────────
GROUP_WORDS = {  # (op, negated): (visible label, aria-label)
    ("AND", False): ("All of these", "All of these must be true"),
    ("OR", False): ("Any of these", "At least one of these must be true"),
    ("AND", True): ("NOT all of these", "NOT: these must not all be true"),
    ("OR", True): ("NOT any of these", "NOT: none of these may be true"),
}


def condition_tree(rule: Dict[str, Any], names: Names) -> Dict[str, Any]:
    """A zpa_reader rule's conditions as nested groups: the rule's operator
    over its conditions, each condition's operator over its operands, a
    negated condition as a NOT group. A single, non-negated operand is
    lifted out of its one-item group."""
    kids = []
    for c in rule.get("conditions") or []:
        ops = [names.operand(o) for o in c.get("operands") or []]
        if not ops:
            continue
        neg = bool(c.get("negated"))
        if len(ops) == 1 and not neg:
            kids.append(ops[0])
            continue
        op = "AND" if (c.get("operator") or "OR").upper() == "AND" else "OR"
        lab, aria = GROUP_WORDS[(op, neg)]
        kids.append({"kind": "group", "op": op, "negated": neg, "label": lab, "aria": aria, "children": ops})
    op = "OR" if (rule.get("operator") or "AND").upper() == "OR" else "AND"
    lab, aria = GROUP_WORDS[(op, False)]
    return {"kind": "group", "op": op, "negated": False, "label": lab, "aria": aria, "children": kids, "root": True}


def _e(s: Any) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def condition_html(tree: Dict[str, Any]) -> str:
    """Accessible HTML for a condition tree: each group a list with
    role="group" and an aria-label saying how its items combine; NOT is a
    visible word, never only a colour. Every value is escaped. Classes:
    ct, ct-g, ct-h, ct-op, ct-not, ct-k, ct-x (unresolved)."""
    if not tree.get("children"):
        return '<p class="ct ct-none">No conditions: the rule matches every request.</p>'

    def node(n: Dict[str, Any]) -> str:
        if n.get("kind") == "group":
            items = "".join(f"<li>{node(c)}</li>" for c in n.get("children") or [])
            cls = f"ct-g ct-{n['op'].lower()}{' ct-negated' if n.get('negated') else ''}"
            return (f'<div class="{cls}"><span class="ct-h" aria-hidden="true">{_e(n["label"])}</span>'
                    f'<ul role="group" aria-label="{_e(n["aria"])}">{items}</ul></div>')
        miss = "" if n.get("resolved", True) else ' <span class="ct-x">(not found in the tenant)</span>'
        neg = '<strong class="ct-not">NOT</strong> ' if n.get("not") else ""
        return f'<span class="ct-op">{neg}<span class="ct-k">{_e(n.get("type_label"))}:</span> {_e(n.get("short") or n.get("text"))}{miss}</span>'

    return f'<div class="ct">{node(tree)}</div>'


def condition_text(tree: Dict[str, Any], indent: int = 0) -> str:
    """The same tree as indented plain text (exports)."""
    if not tree.get("children"):
        return "No conditions: the rule matches every request."
    pad = "  " * indent
    lines = [f"{pad}{tree['label']}:"]
    for c in tree["children"]:
        if c.get("kind") == "group":
            lines.append(condition_text(c, indent + 1))
        else:
            lines.append(f"{pad}  - {'NOT ' if c.get('not') else ''}{c['type_label']}: {c.get('short') or c['text']}"
                         + ("" if c.get("resolved", True) else " (not found in the tenant)"))
    return "\n".join(lines)


# Plain English: each operand as (category, positive phrase, negative phrase).
def _phrases(op: Dict[str, Any]) -> Tuple[str, str, str]:
    t, n = op["type"], op.get("name") or ""
    q = "“{}”".format(n)
    if t == "SCIM_GROUP":
        return "who", f"in group {q}", f"not in group {q}"
    if t in ("SAML", "SCIM"):
        v = "“{}”".format(op.get("value") or "")
        return "who", f"whose {n} is {v}", f"whose {n} is not {v}"
    if t == "IDP":
        return "who", f"signed in through {q}", f"not signed in through {q}"
    if t == "MACHINE_GRP":
        return "who", f"from machine group {q}", f"not from machine group {q}"
    if t == "PLATFORM":
        return "platform", f"on {n}", f"not on {n}"
    if t == "CLIENT_TYPE":
        return "client", f"using {n}", f"not using {n}"
    if t == "COUNTRY_CODE":
        return "platform", f"in country {n}", f"outside country {n}"
    if t == "POSTURE":
        yes, no = FAMILY_PHRASES.get(op.get("family") or "unknown", FAMILY_PHRASES["unknown"])
        return "when", f"{yes} ({q})", f"{no} ({q})"
    if t == "TRUSTED_NETWORK":
        return "when", f"the device is on trusted network {q}", f"the device is off trusted network {q}"
    if t in APP_TYPES:
        word = q if t == "APP" else f"segment group {q}"
        return "app", word, f"anything but {word}"
    text = op.get("text") or ""
    return "when", text, f"not {text}"


def _join(items: List[str], word: str) -> str:
    items = [x for x in items if x]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {word} " + items[-1]


def _clause(cond: Dict[str, Any], names: Names) -> List[Tuple[str, str]]:
    """[(category, phrase)] for one condition; De Morgan for a negated one,
    so each phrase says exactly what must hold. Operands that must all hold
    (AND, or a negated OR) become separate phrases; alternatives (OR, or a
    negated AND) stay one phrase, in parentheses when they mix kinds."""
    ops = [names.operand(o) for o in cond.get("operands") or []]
    neg = bool(cond.get("negated"))
    op_and = (cond.get("operator") or "OR").upper() == "AND"
    pairs = []
    for o in ops:
        cat, yes, no = _phrases(o)
        positive = not o.get("not")
        if neg:
            positive = not positive
        pairs.append((cat, yes if positive else no))
    all_hold = op_and != neg
    cats = {c for c, _ in pairs}
    if cats == {"app"}:
        if neg:   # NOT (A or B): every application but these
            return [("app", "every application except " + _join([("\u201c{}\u201d".format(o["name"]) if o["type"] == "APP" else
                                                                   "segment group \u201c{}\u201d".format(o["name"])) for o in ops], "and"))]
        return [("app", _join([t for _, t in pairs], "and" if all_hold else "or"))]
    if all_hold or len(pairs) == 1:
        return pairs
    text = _join([t for _, t in pairs], "or")
    if len(cats) == 1:
        return [(cats.pop(), text)]
    return [("mixed", f"({text})")]


def plain_sentence(rule: Dict[str, Any], names: Names) -> str:
    """One sentence a person reads: "Allow “HR app” for people in group
    “HR”, on Windows, when the device is domain-joined (“Corp AD”)."""
    action = (rule.get("action") or "").upper()
    verb = ACTION_VERBS.get(action) or (f"Apply {action.replace('_', ' ').lower()} to" if action else "Match")
    conds = [c for c in rule.get("conditions") or [] if c.get("operands")]
    pre = "This rule is disabled. " if rule.get("disabled") else ""
    if not conds:
        return f"{pre}{verb} every application for everyone: the rule has no conditions."
    if (rule.get("operator") or "AND").upper() == "OR" and len(conds) > 1:
        parts = [_join([t for _, t in _clause(c, names)], "and") for c in conds]
        return f"{pre}{verb} the request when any one of these holds: " + "; or ".join(parts) + "."
    by: Dict[str, List[str]] = {}
    for c in conds:
        for cat, text in _clause(c, names):
            by.setdefault(cat, []).append(text)
    apps = _join(by.get("app") or [], "and") or "every application"
    bits = [f"{verb} {apps}" + (" for people " + _join(by["who"], "and") if by.get("who") else "")]
    if by.get("platform"):
        bits.append(_join(by["platform"], "and"))
    if by.get("client"):
        bits.append(_join(by["client"], "and"))
    when = (by.get("when") or []) + (by.get("mixed") or [])
    text = ", ".join(bits)
    if when:
        text += (", when " if len(bits) > 1 else " when ") + _join(when, "and")
    return pre + text + "."


def readable_rule(rule: Dict[str, Any], names: Names) -> Dict[str, Any]:
    """{tree, html, text, sentence} for one rule."""
    tree = condition_tree(rule, names)
    return {"tree": tree, "html": condition_html(tree), "text": condition_text(tree), "sentence": plain_sentence(rule, names)}


# ── usage and findings ──────────────────────────────────────────────────
def _uses(rule: Dict[str, Any], otype: str) -> List[Dict[str, Any]]:
    """Each operand of `otype` with its effective sense: must_pass (or "on")
    when the device must pass, must_fail when it must fail, and why."""
    out = []
    for ci, c in enumerate(rule.get("conditions") or []):
        ops = c.get("operands") or []
        for o in ops:
            if o.get("type") != otype:
                continue
            op_true = (o.get("rhs") or "").strip().lower() != "false"
            neg = bool(c.get("negated"))
            sense = op_true != neg
            if not op_true and neg:
                via = "the operand says it must fail and the condition is negated, so it must pass"
            elif neg:
                via = "the condition is negated"
            elif not op_true:
                via = "the operand says it must fail"
            else:
                via = ""
            others = [x for x in ops if x.get("type") != otype]
            optional = ((c.get("operator") or "OR").upper() != "AND" and bool(others)) or \
                       ((rule.get("operator") or "AND").upper() == "OR" and len([x for x in rule.get("conditions") or [] if x.get("operands")]) > 1)
            out.append({"ref": o.get("lhs") or "", "sense": "must_pass" if sense else "must_fail", "via": via, "optional": optional,
                        "condition": ci})
    return out


def _segment_flags(seg: Dict[str, Any], group_name: str) -> Tuple[List[str], List[str]]:
    """(sensitive reasons, broad reasons) for one normalized segment."""
    sens, broad = [], []
    hay = " ".join([seg.get("name") or "", group_name or "", seg.get("segment_group_name") or ""] + list(seg.get("domains") or []))
    m = SENSITIVE_NAME.search(re.sub(r"[._-]+", " ", hay))
    if m:
        sens.append(f"its name or domains say {m.group(0).lower()}")
    ports = [p for p in zpa_analysis.CRITICAL_PORTS if any(lo <= p <= hi for lo, hi in (seg.get("tcp") or []))]
    if ports:
        sens.append("it serves port " + ", ".join(str(p) for p in ports[:4]))
    for d in seg.get("domains") or []:
        if d.startswith("*.") or d.startswith("."):
            broad.append(f"wildcard domain {d}")
            break
        try:
            net = ipaddress.ip_network(d, strict=False)
            if net.version == 4 and net.prefixlen <= 16:
                broad.append(f"address range {d}")
                break
        except ValueError:
            pass
    span = sum(hi - lo + 1 for lo, hi in (seg.get("tcp") or [])) + sum(hi - lo + 1 for lo, hi in (seg.get("udp") or []))
    if span > zpa_analysis.WIDE_PORT_SPAN:
        broad.append(f"{span} ports")
    return sens, broad


def _rule_segments(rule: Dict[str, Any], names: Names) -> Optional[List[Dict[str, Any]]]:
    """The enabled segments a rule can apply to; None for every application."""
    conds = [c for c in rule.get("conditions") or [] if any(o.get("type") in APP_TYPES for o in c.get("operands") or [])]
    if not conds:
        return None
    segs = [s for s in names.segments.values() if s.get("enabled", True)]
    chosen = set(x["id"] for x in segs)
    for c in conds:
        ids = {o["rhs"] for o in c["operands"] if o.get("type") == "APP"}
        gids = {o["rhs"] for o in c["operands"] if o.get("type") == "APP_GROUP"}
        for g in gids:
            ids |= {s["id"] for s in segs if s.get("segment_group_id") == g}
            ids |= set((names.segment_groups.get(g) or {}).get("application_ids") or [])
        named = {s["id"] for s in segs if s["id"] in ids}
        chosen &= (set(x["id"] for x in segs) - named) if c.get("negated") else named
    return [s for s in segs if s["id"] in chosen]


def _finding(fid: str, severity: str, title: str, obj: str, obj_type: str, obj_id: str, reason: str, fix: str) -> Dict[str, Any]:
    return {"id": fid, "severity": severity, "title": title, "object": obj, "object_type": obj_type, "object_id": obj_id,
            "reason": reason, "fix": fix}


FINDING_TITLES = {
    "DP-01": "Access rules to sensitive or broad apps with no posture check",
    "DP-02": "Allow rules that let in devices that fail posture",
    "DP-03": "Allow rules whose only posture checks are markers",
    "DP-04": "Allow rules where posture is optional",
    "DP-05": "Posture profiles no rule uses",
    "DP-06": "Trusted networks no rule uses",
    "DP-07": "Rules naming a posture profile or trusted network that no longer exists",
    "DP-08": "Posture profiles this page could not classify",
    "DP-09": "Rules that depend on an inactive Client Connector trusted network",
}
SEV_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _names_list(items: Iterable[str], n: int = 4) -> str:
    items = list(items)
    q = ["“{}”".format(x) for x in items[:n]]
    more = f" and {len(items) - n} more" if len(items) > n else ""
    return (_join(q, "and") if not more else ", ".join(q)) + more


def analyze(snap: Dict[str, Any], raw_profiles: Optional[List[Dict[str, Any]]] = None,
            raw_trusted: Optional[List[Dict[str, Any]]] = None, zcc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The device posture report over one ZPA read: profiles (classified),
    families, trusted networks, usage, the access rules made readable and
    the findings. `raw_profiles` / `raw_trusted` are the lists' raw JSON
    (None: fall back to the snapshot's normalized lists, names only)."""
    cols = snap.get("collections") or {}
    read = lambda k: bool((cols.get(k) or {}).get("read"))  # noqa: E731
    complete = lambda k: bool((cols.get(k) or {}).get("read") and (cols.get(k) or {}).get("complete"))  # noqa: E731
    not_assessed: List[str] = []

    if raw_profiles is not None:
        profiles = [normalize_profile(x) for x in raw_profiles]
    else:
        profiles = [normalize_profile({"id": p.get("id"), "name": p.get("name"), "postureUdid": p.get("posture_udid"),
                                       "platform": [p["platform"]] if p.get("platform") else []})
                    for p in snap.get("posture_profiles") or []]
    profiles.sort(key=lambda p: p["name"].lower())
    if raw_trusted is not None:
        trusted = [normalize_trusted(x) for x in raw_trusted]
    else:
        trusted = [{"id": t.get("id"), "name": t.get("name"), "network_id": t.get("network_id"), "domain": "", "zscaler_cloud": ""}
                   for t in snap.get("trusted_networks") or []]
    trusted.sort(key=lambda t: t["name"].lower())
    tsnap = dict(snap, trusted_networks=trusted)
    names = Names(tsnap, profiles)

    zcc = zcc or {"read": False, "networks": [], "reason": "Client Connector is not ticked on the Scope page, so its trusted networks were not read."}
    zcc_by_guid = {n["guid"]: n for n in zcc.get("networks") or [] if n.get("guid")}
    for t in trusted:
        z = zcc_by_guid.get(t["network_id"])
        t["zcc"] = z
    # usage across every policy read
    policies = snap.get("policies") or {}
    p_use: Dict[str, List[Dict[str, Any]]] = {p["id"]: [] for p in profiles}
    t_use: Dict[str, List[Dict[str, Any]]] = {t["id"]: [] for t in trusted}
    dangling: List[Tuple[Dict[str, Any], str, str]] = []
    for ptype, rules in policies.items():
        for r in rules or []:
            base = {"rule_id": r["id"], "rule": r["name"], "policy": ptype, "policy_label": POLICY_LABELS.get(ptype, ptype),
                    "order": r.get("order"), "action": r.get("action"), "disabled": bool(r.get("disabled"))}
            for u in _uses(r, "POSTURE"):
                p = names.profile(u["ref"])
                if p:
                    p_use[p["id"]].append(dict(base, sense=u["sense"], via=u["via"], optional=u["optional"]))
                else:
                    dangling.append((r, "posture profile", u["ref"]))
            for u in _uses(r, "TRUSTED_NETWORK"):
                n = names.network(u["ref"])
                if n:
                    t_use[n["id"]].append(dict(base, sense="on" if u["sense"] == "must_pass" else "off", via=u["via"], optional=u["optional"]))
                else:
                    dangling.append((r, "trusted network", u["ref"]))
    for p in profiles:
        p["used_by"] = p_use.get(p["id"], [])
    for t in trusted:
        t["used_by"] = t_use.get(t["id"], [])

    findings: List[Dict[str, Any]] = []
    access_read = "access" in policies
    if not access_read:
        not_assessed.append("The access policy could not be read, so no rule is checked and nothing is called unused.")
    access = [r for r in policies.get("access") or []]
    rules_out = []
    for r in access:
        rr = readable_rule(r, names)
        posture = []
        for u in _uses(r, "POSTURE"):
            p = names.profile(u["ref"])
            posture.append({"name": p["name"] if p else u["ref"], "family": p["family"] if p else "unknown",
                            "family_label": FAMILY_LABEL[p["family"] if p else "unknown"], "source": p["source"] if p else "none",
                            "sense": u["sense"], "via": u["via"], "optional": u["optional"], "resolved": bool(p)})
        networks = []
        for u in _uses(r, "TRUSTED_NETWORK"):
            n = names.network(u["ref"])
            networks.append({"name": n["name"] if n else u["ref"], "sense": "on" if u["sense"] == "must_pass" else "off", "resolved": bool(n)})
        segs = _rule_segments(r, names)
        rules_out.append({"id": r["id"], "name": r["name"], "order": r.get("order"), "action": r.get("action"), "disabled": bool(r.get("disabled")),
                          "sentence": rr["sentence"], "html": rr["html"], "text": rr["text"], "tree": rr["tree"],
                          "posture": posture, "trusted_networks": networks, "flags": [],
                          "_segs": segs})

    def flag(rule_out, fid):
        if fid not in rule_out["flags"]:
            rule_out["flags"].append(fid)

    for ro in rules_out:
        if ro["disabled"] or ro["action"] not in GRANTING:
            continue
        segs = ro["_segs"]
        posture = ro["posture"]
        # DP-01: sensitive or broad apps with no posture condition at all
        if not posture:
            if segs is None:
                reach_s, reach_b = ["every application (the rule names none)"], []
                sev = "high"
            else:
                reach_s, reach_b = [], []
                for s in segs:
                    sens, broad = _segment_flags(s, (names.segment_groups.get(s.get("segment_group_id") or "") or {}).get("name", ""))
                    if sens:
                        reach_s.append(f"“{s['name']}” ({sens[0]})")
                    elif broad:
                        reach_b.append(f"“{s['name']}” ({broad[0]})")
                sev = "high" if reach_s else "medium"
            if reach_s or reach_b:
                what = reach_s + reach_b
                more = f" and {len(what) - 3} more" if len(what) > 3 else ""
                tn = " It checks a trusted network, which says where the device is, not whether it is healthy." if ro["trusted_networks"] else ""
                findings.append(_finding("DP-01", sev, FINDING_TITLES["DP-01"], ro["name"], "access rule", ro["id"],
                                         f"It grants access to {', '.join(what[:3])}{more} without checking the device's posture.{tn}",
                                         "Add a posture condition that must pass (domain join, EDR or a client certificate) to this rule, "
                                         "or split the sensitive apps into a rule that has one."))
                flag(ro, "DP-01")
            continue
        fails = [p for p in posture if p["sense"] == "must_fail"]
        if fails:
            findings.append(_finding("DP-02", "high", FINDING_TITLES["DP-02"], ro["name"], "access rule", ro["id"],
                                     f"It allows the device when it fails {_names_list(p['name'] for p in fails)} ({fails[0]['via']}), so a "
                                     "device that does not meet that check gets in.",
                                     "Make the posture condition one that must pass, or turn the rule into a block rule if it is meant to "
                                     "keep failing devices out."))
            flag(ro, "DP-02")
        passes = [p for p in posture if p["sense"] == "must_pass"]
        if passes and all(p["family"] == "marker" for p in passes):
            findings.append(_finding("DP-03", "medium", FINDING_TITLES["DP-03"], ro["name"], "access rule", ro["id"],
                                     f"Its only posture checks are {_names_list(p['name'] for p in passes)}: markers that prove a file, "
                                     "registry key or variable is present, which anyone with the device can create.",
                                     "Add a real enforcement check (EDR, domain join, client certificate or disk encryption) beside the marker."))
            flag(ro, "DP-03")
        opt = [p for p in passes if p["optional"]]
        if opt and len(opt) == len(passes):
            findings.append(_finding("DP-04", "medium", FINDING_TITLES["DP-04"], ro["name"], "access rule", ro["id"],
                                     f"Posture {_names_list(p['name'] for p in opt)} is joined with OR to other conditions, so a device "
                                     "that fails it still gets in when the other condition matches.",
                                     "Put the posture check in a condition of its own, joined to the rest with AND."))
            flag(ro, "DP-04")

    every_policy = all(pt in policies for pt, _ in zpa_reader.POLICY_TYPES)
    scope_word = "" if every_policy else " in the policies that could be read"
    if not read("posture_profiles"):
        not_assessed.append("Posture profiles could not be read, so none is classified and none is called unused.")
    elif access_read:
        for p in profiles:
            if not p["used_by"]:
                findings.append(_finding("DP-05", "low", FINDING_TITLES["DP-05"], p["name"], "posture profile", p["id"],
                                         f"No rule{scope_word} uses this {lower_label(p['label'])} profile, so it checks devices for nothing.",
                                         "Use it in the access rules that should require it, or delete it so nobody thinks it protects anything."))
        for p in profiles:
            if p["family"] == "unknown":
                findings.append(_finding("DP-08", "info", FINDING_TITLES["DP-08"], p["name"], "posture profile", p["id"], p["why"],
                                         "Check what the profile tests in the Client Connector portal, and give it a name that says so."))
    if not read("trusted_networks"):
        not_assessed.append("Trusted networks could not be read, so none is called unused.")
    elif access_read:
        for t in trusted:
            if not t["used_by"]:
                findings.append(_finding("DP-06", "low", FINDING_TITLES["DP-06"], t["name"], "trusted network", t["id"],
                                         f"No rule{scope_word} uses this trusted network.",
                                         "Use it where a rule should depend on the corporate network, or remove it from ZPA."))
            z = t.get("zcc")
            if z and z.get("active") is False and any(not u["disabled"] for u in t["used_by"]):
                findings.append(_finding("DP-09", "medium", FINDING_TITLES["DP-09"], t["name"], "trusted network", t["id"],
                                         "Client Connector marks this trusted network inactive, but enabled rules depend on it, so they never "
                                         "see a device on it.", "Activate the network in Client Connector or remove it from the rules."))
    for r, what, ref in dangling:
        okey = "posture_profiles" if what == "posture profile" else "trusted_networks"
        if complete(okey):
            findings.append(_finding("DP-07", "low", FINDING_TITLES["DP-07"], r["name"], f"{POLICY_LABELS.get(r.get('policy'), 'access policy')} rule", r["id"],
                                     f"It names a {what} ({ref}) that is not in the tenant, so that condition can never be met as intended.",
                                     f"Edit the rule to name an existing {what}, or remove the condition."))
    findings.sort(key=lambda f: (SEV_ORDER.get(f["severity"], 9), f["id"], f["object"].lower()))

    families = []
    for fid, label, enf in FAMILIES:
        members = [p for p in profiles if p["family"] == fid]
        families.append({"id": fid, "label": label, "enforces": enf, "count": len(members),
                         "reliable": sum(1 for p in members if p["source"] == "type"),
                         "inferred": sum(1 for p in members if p["source"] == "name"),
                         "used": sum(1 for p in members if p["used_by"]),
                         "profiles": [p["name"] for p in members]})
    for ro in rules_out:
        ro.pop("_segs", None)
    by_sev = {s: sum(1 for f in findings if f["severity"] == s) for s in SEV_ORDER}
    enforced = [ro for ro in rules_out if not ro["disabled"] and ro["action"] in GRANTING
                and any(p["sense"] == "must_pass" and ENFORCES.get(p["family"]) and not p["optional"] for p in ro["posture"])]
    counts = {"profiles": len(profiles), "trusted_networks": len(trusted), "access_rules": len(rules_out),
              "allow_rules": sum(1 for ro in rules_out if not ro["disabled"] and ro["action"] in GRANTING),
              "allow_rules_enforced": len(enforced),
              "reliable": sum(1 for p in profiles if p["source"] == "type"), "inferred": sum(1 for p in profiles if p["source"] == "name"),
              "unknown": sum(1 for p in profiles if p["source"] == "none"),
              "findings": len(findings), "by_severity": by_sev}
    return {"profiles": profiles, "families": families, "trusted_networks": trusted, "rules": rules_out, "findings": findings,
            "counts": counts, "not_assessed": not_assessed, "titles": FINDING_TITLES, "assumptions": ASSUMPTIONS,
            "zcc": {"read": bool(zcc.get("read")), "count": len(zcc.get("networks") or []), "reason": zcc.get("reason") or ""}}


# ── the read ────────────────────────────────────────────────────────────
TAPPED = ("posture_profiles", "trusted_networks")


class _TapService:
    """A ZPA service whose list_* calls also hand their page's raw JSON to `sink`."""

    def __init__(self, svc: Any, sink: List[Dict[str, Any]]):
        self._svc, self._sink = svc, sink

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._svc, name)
        if not name.startswith("list_") or not callable(attr):
            return attr

        def call(*a: Any, **k: Any) -> Any:
            res = attr(*a, **k)
            if isinstance(res, tuple) and len(res) == 3:
                result, resp, err = res
            elif isinstance(res, tuple) and len(res) == 2:
                (result, err), resp = res, None
            else:
                result, resp, err = res, None, None
            if not err:
                self._sink.extend(zpa_reader.raw_items(result, resp))
            return res
        return call


class _TapZpa:
    def __init__(self, zpa: Any, sinks: Dict[str, List[Dict[str, Any]]]):
        self._zpa, self._sinks = zpa, sinks

    def __getattr__(self, name: str) -> Any:
        svc = getattr(self._zpa, name)
        if name in TAPPED and svc is not None:
            return _TapService(svc, self._sinks[name])
        return svc


class _Tap:
    """The client as zpa_reader sees it: the same services, with the posture
    profile and trusted network lists' raw JSON kept on the side."""

    def __init__(self, client: Any):
        self.sinks: Dict[str, List[Dict[str, Any]]] = {k: [] for k in TAPPED}
        zpa = getattr(client, "zpa", None)
        self.zpa = _TapZpa(zpa, self.sinks) if zpa is not None else None


def read_zcc_networks(client: Any, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
                      pace: float = zpa_reader.PACE_SECONDS) -> Dict[str, Any]:
    """Client Connector trusted networks (zcc.trusted_networks.list_by_company,
    paged). Stop is honoured before every call and during every wait."""
    svc = getattr(getattr(client, "zcc", None), "trusted_networks", None)
    fn = getattr(svc, "list_by_company", None) if svc is not None else None
    if not callable(fn):
        return {"read": False, "networks": [], "reason": "This SDK version has no Client Connector trusted network list."}
    out: List[Dict[str, Any]] = []
    for page in range(1, ZCC_MAX_PAGES + 1):
        if cancel is not None and cancel.is_set():
            raise zpa_reader.Stopped(STOPPED_REASON)
        if page > 1 and pace:
            if cancel is not None and cancel.wait(pace):
                raise zpa_reader.Stopped(STOPPED_REASON)
            if cancel is None:
                time.sleep(pace)
        try:
            res = fn(query_params={"page": page, "page_size": ZCC_PAGE_SIZE})
        except Exception as e:  # noqa: BLE001 — an unreadable list is reported, the ZPA part still stands
            return {"read": False, "networks": [], "reason": f"Client Connector trusted networks could not be read: {zpa_reader._err_text(e)}"}
        result, resp, err = res if isinstance(res, tuple) and len(res) == 3 else (res, None, None)
        if err:
            return {"read": False, "networks": [], "reason": f"Client Connector trusted networks could not be read: {zpa_reader._err_text(err)}"}
        items = zpa_reader.raw_items(result, resp)
        out.extend(items)
        if len(items) < ZCC_PAGE_SIZE:
            break
    if log:
        log(f"Read {len(out)} Client Connector trusted network{'' if len(out) == 1 else 's'}.")
    return {"read": True, "networks": [normalize_zcc_network(x) for x in out], "reason": ""}


def read(client: Any, log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
         zcc: bool = False, pace: Optional[float] = None) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
    """(snapshot, raw lists {posture_profiles, trusted_networks}, zcc read).
    Read-only: zpa_reader.read plus, with `zcc`, one Client Connector list.
    Raises zpa_reader.Stopped on Stop and zpa_reader.ReadError when the
    sign-in has no ZPA API."""
    tap = _Tap(client)
    snap = zpa_reader.read(tap, log=log, cancel=cancel, pace=pace)
    raw = {k: list(v) for k, v in tap.sinks.items()}
    for k in TAPPED:   # a list that failed keeps nothing (the read says "not read")
        if not (snap.get("collections") or {}).get(k, {}).get("read"):
            raw[k] = None
    if zcc:
        if log:
            log("Reading Client Connector trusted networks…")
        zout = read_zcc_networks(client, log=log, cancel=cancel, pace=zpa_reader.PACE_SECONDS if pace is None else pace)
        if not zout["read"] and log:
            log(zout["reason"])
    else:
        zout = {"read": False, "networks": [], "reason": "Client Connector is not ticked on the Scope page, so its trusted networks were not read."}
    return snap, raw, zout


# ── Excel ───────────────────────────────────────────────────────────────
SOURCE_WORDS = {"type": "From the posture type (reliable)", "name": "From the name (inferred)", "none": "Unknown"}
SENSE_WORDS = {"must_pass": "Must pass", "must_fail": "Must fail", "on": "Must be on", "off": "Must be off"}


def workbook(report: Dict[str, Any]) -> bytes:
    """The report as an Excel workbook: Summary, Findings, Profiles,
    Families, Usage, Trusted networks, Access rules."""
    import xlsx_writer
    label = report.get("tenant_label") or ""
    wb = xlsx_writer.Workbook(title=f"Device posture {label}".strip(), subject="ZPA posture profiles, usage and access rule conditions",
                              creator="Zscaler Made Easy")
    c = report.get("counts") or {}
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([["Tenant", label], ["Read at", report.get("generated_at") or ""],
              ["Posture profiles", c.get("profiles", 0)], ["  classified from the type (reliable)", c.get("reliable", 0)],
              ["  classified from the name (inferred)", c.get("inferred", 0)], ["  unknown", c.get("unknown", 0)],
              ["Trusted networks", c.get("trusted_networks", 0)], ["Access rules", c.get("access_rules", 0)],
              ["Enabled allow rules", c.get("allow_rules", 0)], ["  of which enforce device posture", c.get("allow_rules_enforced", 0)],
              ["Findings", c.get("findings", 0)]])
    for k, v in (c.get("by_severity") or {}).items():
        s.append([f"  {k}", v])
    for n in report.get("not_assessed") or []:
        s.append(["Not assessed", n])
    zcc = report.get("zcc") or {}
    s.append(["Client Connector trusted networks", f"{zcc.get('count', 0)} read" if zcc.get("read") else (zcc.get("reason") or "not read")])
    for a in report.get("assumptions") or []:
        s.append(["Assumption", a])
    wb.add_sheet("Findings", columns=["Severity", "Check", "Title", "Object type", "Object", "What is wrong", "What to do"],
                 rows=[[f["severity"], f["id"], f["title"], f["object_type"], f["object"], f["reason"], f["fix"]] for f in report.get("findings") or []])
    wb.add_sheet("Profiles", columns=["Name", "Family", "Classified", "Posture type", "Why", "Platforms", "Enforces device health",
                                      "Rules using it", "CRL check", "Non-exportable key", "Machine tunnel"],
                 rows=[[p["name"], p["label"], SOURCE_WORDS.get(p["source"], p["source"]), p.get("posture_type") or "", p["why"],
                        ", ".join(p.get("platforms") or []), "yes" if p["enforces"] else "no", len(p.get("used_by") or []),
                        _yn(p.get("crl_check")), _yn(p.get("non_exportable_key")), _yn(p.get("machine_tunnel"))]
                       for p in report.get("profiles") or []])
    wb.add_sheet("Families", columns=["Family", "Counts as enforcement", "Profiles", "From the type", "From the name", "Used by a rule", "Names"],
                 rows=[[f["label"], "yes" if f["enforces"] else "no", f["count"], f["reliable"], f["inferred"], f["used"], ", ".join(f["profiles"])]
                       for f in report.get("families") or []])
    usage = []
    for p in report.get("profiles") or []:
        for u in p.get("used_by") or []:
            usage.append(["Posture profile", p["name"], p["label"], u["policy_label"], u.get("order"), u["rule"], u.get("action"),
                          SENSE_WORDS.get(u["sense"], u["sense"]), u.get("via") or "", "yes" if u.get("optional") else "no", "yes" if u.get("disabled") else "no"])
    for t in report.get("trusted_networks") or []:
        for u in t.get("used_by") or []:
            usage.append(["Trusted network", t["name"], "", u["policy_label"], u.get("order"), u["rule"], u.get("action"),
                          SENSE_WORDS.get(u["sense"], u["sense"]), u.get("via") or "", "yes" if u.get("optional") else "no", "yes" if u.get("disabled") else "no"])
    wb.add_sheet("Usage", columns=["Object", "Name", "Family", "Policy", "Rule order", "Rule", "Action", "Sense", "Why", "Optional (OR)", "Rule disabled"], rows=usage)
    wb.add_sheet("Trusted networks", columns=["Name", "Network ID", "Rules using it", "Client Connector criteria", "Active in Client Connector"],
                 rows=[[t["name"], t.get("network_id") or "", len(t.get("used_by") or []),
                        ", ".join((t.get("zcc") or {}).get("criteria") or []) if t.get("zcc") else "",
                        _yn((t.get("zcc") or {}).get("active")) if t.get("zcc") else ""] for t in report.get("trusted_networks") or []])
    wb.add_sheet("Access rules", columns=["Order", "Rule", "Action", "Enabled", "In plain words", "Conditions", "Posture", "Findings"],
                 rows=[[r.get("order"), r["name"], r.get("action"), "no" if r.get("disabled") else "yes", r["sentence"], r["text"],
                        "; ".join(f"{p['name']} ({p['family_label']}, {SENSE_WORDS.get(p['sense'], p['sense']).lower()})" for p in r.get("posture") or []),
                        ", ".join(r.get("flags") or [])] for r in report.get("rules") or []])
    return wb.to_bytes()


def _yn(v: Any) -> str:
    return "" if v is None else ("yes" if v else "no")
