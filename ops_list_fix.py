"""Fix selected, wider: the Path analyzer's Test a list rows that missed
their expected outcome, fixed as concrete Bulk changes operations.

One operation type on the Bulk changes engine (admin_ops.register), so it
shares the engine's scope check before any read, the preview with its plan
hash, the four write gates, the re-plan before writing, the re-read of
every object right before its write (conflict guard), writes through
pack_ops only, one ZIA activation, the read-back, a recorded Undo and the
audit log.

list_fix
    `fixes`: one entry per area and purpose (block or allow), each with the
    destinations to change and the rows of the tested list they come from:

    firewall / dns   IPv4 addresses, CIDR blocks and ranges go into an IP
                     destination group of type DSTN_IP; host names into one
                     of type DSTN_FQDN (or an existing DSTN_DOMAIN group,
                     assumed to take a host name too). Each is an existing
                     group (`{"id": ...}`) or a new one (`{"new": name}`,
                     split into numbered groups above the per-group limit).
                     `action` remove takes them out of existing groups
                     instead. Then, optionally, `rule`: add the group(s)
                     (and, for the Cloud Firewall, network `services`) to
                     an existing Cloud Firewall or DNS Control rule whose
                     action matches the purpose, or create a new rule
                     DISABLED (`enabled` true only when the operator asks,
                     which then needs the typed phrase), placed above the
                     rule that decided the rows.
    atp              host names, URLs and addresses go onto, or come off,
                     the security policy denylist (block) or allowlist
                     (allow): the lists the Path analyzer's ATP step reads.
    url              URLs and host names (URL filtering and Cloud App
                     Control rows) go into a custom URL category: an
                     existing one (`category: {"id": ...}`) or a new one
                     (`{"new": name}`). Then, optionally, `rule`: add the
                     category to an existing URL filtering rule whose
                     action matches the purpose (Block or Allow), or create
                     a new URL filtering rule DISABLED (enabled only when
                     asked, which then needs the typed phrase) placed above
                     the rule that decided the rows. Without a rule, the
                     preview warns when no URL filtering rule with that
                     action names the category: the URLs alone change
                     nothing.

    ip_group_edit (standalone, no Test a list needed)
    `group`: {"id": n} or {"new": name, "group_type": "DSTN_IP" |
    "DSTN_FQDN"}; `add` and `remove`: the entries. Planned and applied as
    a list_fix on that one group (same checks, limits, re-read, Undo).
atp_list_edit (standalone)
    `list`: denylist or allowlist; `add` and `remove`: the URLs.

    IPv6 destinations are refused: zscaler-sdk-python 1.11.3 (zia/
    cloud_firewall.py list_ipv6_destination_groups) says user-defined IPv6
    destination groups are not supported, only the predefined one.

The preview explains every change in plain words (`explain`) and names the
rows it fixes (`rows`); after an apply the page re-runs those rows through
the Path analyzer (bulk_test.prove) to show which ones now do what was
expected.

Verified against zscaler-sdk-python 1.11.3:
  cloud_firewall.list_ip_destination_groups / get_ip_destination_group
      GET /ipDestinationGroups[/{id}]; add_ip_destination_group (POST),
      update_ip_destination_group (PUT, replaces `addresses` by default:
      query param override true), delete_ip_destination_group (DELETE);
      model IPDestinationGroups: id, name, description, type (DSTN_IP,
      DSTN_FQDN, DSTN_DOMAIN, DSTN_OTHER), is_non_editable, addresses,
      ip_categories, countries.
  cloud_firewall.list_network_services (GET /networkServices).
  cloud_firewall_rules list_rules / get_rule / add_rule / update_rule /
      delete_rule (/firewallFilteringRules): name "max 31 chars", order,
      rank, state ENABLED / DISABLED, action, dest_ip_groups, nw_services
      (lists of ids, turned into [{"id": n}] by transform_common_id_fields).
  cloud_firewall_dns the same (/firewallDnsRules): action ALLOW, BLOCK,
      REDIR_* ..., dest_ip_groups.
  security_policy_settings get_whitelist (GET /security, whitelistUrls),
      get_blacklist (GET /security/advanced, blacklistUrls),
      add_urls_to_blacklist / delete_urls_from_blacklist (POST
      /security/advanced/blacklistUrls?action=ADD_TO_LIST|REMOVE_FROM_LIST),
      replace_whitelist (PUT /security: the allowlist has no incremental
      call, so the list read right before the write is sent back with the
      change; a change someone makes in between those two calls is lost,
      as with the SDK's own add_urls_to_whitelist).
  url_categories list_categories / get_category / add_url_category /
      add_urls_to_category (PUT ?action=ADD_TO_LIST) /
      delete_urls_from_category (REMOVE_FROM_LIST) / delete_category, as
      admin_ops' URL category operation uses them (pack_ops kind
      url_category); url_filtering list_rules / get_rule / add_rule /
      update_rule / delete_rule (/urlFilteringRules): url_categories (ids),
      action ALLOW / BLOCK / CAUTION / ISOLATE, state, order, rank,
      protocols, request_methods.
Assumed (marked where used): the per-group, organisation and list limits
below, BLOCK_DROP as the new Cloud Firewall block action (the SDK lists it
for IPS rules; ops_zia_baseline uses it for filtering rules), BLOCK as the
DNS one without a block response code, rank 7 for a new rule (as
ops_zia_baseline), and that the security lists take the URL forms a custom
URL category takes (admin_ops.normalize_url).
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Callable, Dict, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import ops_zia_baseline as zb
import pack_ops as ops

TYPE = "list_fix"
GROUP_TYPE = "ip_group_edit"
LIST_TYPE = "atp_list_edit"
TYPES = (TYPE, GROUP_TYPE, LIST_TYPE)
FAMILY = "list_fix_targets"

AREAS: Dict[str, Dict[str, Any]] = {
    "firewall": {"label": "Cloud Firewall", "channel": "firewall", "rules": "Cloud Firewall rule"},
    "dns": {"label": "DNS Control", "channel": "dns", "rules": "DNS Control rule"},
    "atp": {"label": "Advanced Threat Protection lists", "channel": None, "rules": ""},
    "url": {"label": "URL filtering", "channel": zb.AREAS["url"]["channel"], "rules": "URL filtering rule"},
}
AREA_ORDER = ("firewall", "dns", "atp", "url")
CAT_NAME_MAX = 255          # assumed, as admin_ops._object_name
LISTS: Dict[str, Dict[str, str]] = {
    "denylist": {"label": "security policy denylist", "field": "blacklist_urls", "kind": "security_denylist", "purpose": "block"},
    "allowlist": {"label": "security policy allowlist", "field": "whitelist_urls", "kind": "security_allowlist", "purpose": "allow"},
}

# Limits. Assumed: Zscaler's ZIA "Ranges & Limitations" help page
# (help.zscaler.com/zia/ranges-limitations), as summarised by a web search
# on 2026-10-30, gives 8,000 IP address or FQDN entries per destination
# group and 16,000 IP entries per organisation across source and
# destination groups by default (Support can raise it); the page itself was
# not reachable from here. A tenant with other limits refuses the write and
# the item is reported failed.
MAX_GROUP_ADDRESSES = 8000
ORG_IP_ENTRIES = 16000
# Assumed: no published size for the security policy lists was found; the
# tenant refuses past its own limit.
ATP_LIST_MAX = 25000
MAX_ENTRIES = 5000          # destinations per operation (bulk_test.MAX_FIX_ROWS)
MAX_FIXES = 12
MAX_SERVICES = 20
MAX_ROWS_PER_ENTRY = 50     # row numbers kept per destination (for the preview's links)
RULE_NAME_MAX = 31          # SDK 1.11.3 cloud_firewall_rules.add_rule: "Name of the rule, max 31 chars"
GROUP_NAME_MAX = 128        # assumed: ZIA's own form caps names; refused by the tenant past its limit
DESC_MAX = 255
NEW_RULE_RANK = 7           # assumed, as ops_zia_baseline
IP_TYPES = ("DSTN_IP",)
HOST_TYPES = ("DSTN_FQDN", "DSTN_DOMAIN")
NEW_ACTION = {("firewall", "block"): "BLOCK_DROP", ("firewall", "allow"): "ALLOW", ("dns", "block"): "BLOCK", ("dns", "allow"): "ALLOW",
              ("url", "block"): "BLOCK", ("url", "allow"): "ALLOW"}
# The field of each area's rule that names what the fix puts things in.
REF_FIELD = {"firewall": "dest_ip_groups", "dns": "dest_ip_groups", "url": "url_categories"}
ACTION_WORDS = {"BLOCK_DROP": "Block (drop)", "BLOCK_RESET": "Block (reset)", "BLOCK_ICMP": "Block (ICMP unreachable)", "BLOCK": "Block",
                "ALLOW": "Allow", "BLOCK_WITH_RESPONSE": "Block with a response"}
IPV6_WHY = ("an IPv6 destination: ZIA's API supports no user-defined IPv6 destination group (zscaler-sdk-python 1.11.3), "
            "only the predefined one. Add its host name instead, or use the ATP list")

LogFn = Optional[Callable[[str], None]]


# ---------------------------------------------------------------------------
# Scope (checked by the engine before sign-in and before any read)
# ---------------------------------------------------------------------------

def areas_in_scope(scope: Dict[str, Any]) -> Tuple[List[str], Dict[str, str]]:
    """(areas the Scope page puts in scope, {area: why not})."""
    pols = set(scope.get("policies") or [])
    platform = "zia_extras" in set(scope.get("scopes") or [])
    read, why = [], {}
    for a in AREA_ORDER:
        ok = ("firewall" in pols) if a == "firewall" else ("url_filtering" in pols) if a == "url" else platform
        if ok:
            read.append(a)
        elif a == "url":
            why[a] = ("Not in scope: URL filtering is not in scope on the Scope page (tick DLP or ZIA platform), so custom URL categories "
                      "and URL filtering rules are not read or changed.")
        else:
            why[a] = (f"Not in scope: ZIA platform is not ticked on the Scope page, so the {AREAS[a]['label']} "
                      f"{'rules and IP destination groups are' if a != 'atp' else 'are'} not read or changed.")
    return read, why


def _spec_areas(spec: Dict[str, Any]) -> List[str]:
    t = str(spec.get("type") or "")
    if t == GROUP_TYPE:
        return ["firewall"]     # the IP destination groups are read and changed with the Cloud Firewall
    if t == LIST_TYPE:
        return ["atp"]
    if str(spec.get("action") or "") == "revert":
        steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
        return [str(s.get("area") or "") for s in steps if isinstance(s, dict)]
    fixes = spec.get("fixes") if isinstance(spec.get("fixes"), list) else []
    return [str(f.get("area") or "") for f in fixes if isinstance(f, dict)]


def _in_scope(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    """Why the operation is out of scope, or None. Given the spec, every area
    it names (or its Undo touches) must be in scope: deny by default."""
    read, _why = areas_in_scope(scope)
    if not read:
        return ("Nothing this fix changes is in scope on the Scope page: tick ZIA platform (Cloud Firewall rules and IP destination "
                "groups, DNS Control rules, the ATP lists) or DLP (URL filtering and custom URL categories). Nothing was read.")
    if not isinstance(spec, dict):
        return None
    want = _spec_areas(spec)
    out = [AREAS[a]["label"] for a in AREA_ORDER if a in want and a not in read]
    if out:
        return f"Not in scope on the Scope page: {', '.join(out)}. Leave them out or tick their scope. Nothing was read."
    return None


# ---------------------------------------------------------------------------
# Destinations
# ---------------------------------------------------------------------------

def classify(raw: Any) -> Tuple[str, Optional[str], Optional[str]]:
    """(kind, value, why refused): kind ip (an IPv4 address, CIDR block or
    a-b range), ipv6, host (a host name) or bad."""
    s = str(raw or "").strip()
    if not s:
        return "bad", None, "empty"
    if len(s) > 255 or ao._has_control(s) or any(c.isspace() for c in s):
        return "bad", None, "longer than 255 characters, or contains a space or a control character"
    if "-" in s and all(re.fullmatch(r"[0-9.]+", p or "x") for p in s.split("-", 1)):
        try:
            a, b = (ipaddress.IPv4Address(p) for p in s.split("-", 1))
        except ValueError:
            return "bad", None, "is not a valid IPv4 range (a.b.c.d-e.f.g.h)"
        if int(a) > int(b):
            return "bad", None, "is a range whose first address is after its last"
        return "ip", (str(a) if a == b else f"{a}-{b}"), None
    try:
        net = ipaddress.ip_network(s, strict=True)
    except ValueError as e:
        if "/" in s and "has host bits set" in str(e):
            return "bad", None, f"is not a network address (did you mean {ipaddress.ip_network(s, strict=False)}?)"
        net = None
    if net is not None:
        if net.version == 6:
            return "ipv6", str(net.network_address if net.prefixlen == 128 else net), IPV6_WHY
        return "ip", str(net.network_address) if net.prefixlen == 32 else str(net), None
    u, why = ao.normalize_url(s)
    if why:
        return "bad", None, why
    host = u.split("/", 1)[0].split(":", 1)[0].lstrip(".")
    if "/" in u or ":" in u.split("/", 1)[0] or u.startswith("."):
        return "bad", None, "a group takes a host name only (no port, path or leading dot)"
    return "host", host, None


def _ip_span(entry: str) -> Optional[Tuple[int, int]]:
    e = str(entry or "").strip()
    try:
        if "-" in e:
            a, b = (ipaddress.IPv4Address(p.strip()) for p in e.split("-", 1))
            return int(a), int(b)
        n = ipaddress.ip_network(e, strict=False)
        if n.version != 4:
            return None
        return int(n.network_address), int(n.broadcast_address)
    except ValueError:
        return None


def covered_by(value: str, have: Sequence[str]) -> Optional[str]:
    """The entry of `have` that already covers `value` (an IPv4 entry inside
    a block or range; a host under '.domain' or '*.domain'), or None."""
    span = _ip_span(value)
    for h in have:
        hs = str(h or "").strip()
        if not hs:
            continue
        if span is not None:
            other = _ip_span(hs)
            if other and other[0] <= span[0] and span[1] <= other[1]:
                return hs
        else:
            hl = hs.lower()
            if hl == value.lower():
                return hs
            dom = hl[1:] if hl.startswith("*.") else hl
            if dom.startswith(".") and value.lower().endswith(dom):
                return hs
    return None


def collapse(entries: List[Tuple[str, List[int]]]) -> List[Tuple[str, List[int]]]:
    """Single IPv4 addresses and blocks merged into the fewest CIDR blocks
    (a /16 of single rows is one group entry, not 65,536); ranges as given.
    Each result keeps the rows of the entries it covers."""
    nets, other = [], []
    for v, rows in entries:
        if "-" in v:
            other.append((v, rows))
        else:
            nets.append((ipaddress.ip_network(v, strict=False), rows))
    out: List[Tuple[str, List[int]]] = []
    for n in ipaddress.collapse_addresses([n for n, _ in nets]):
        rows: List[int] = []
        for m, r in nets:
            if m.subnet_of(n):
                rows.extend(r)
        out.append((str(n.network_address) if n.prefixlen == 32 else str(n), sorted(set(rows))[:MAX_ROWS_PER_ENTRY]))
    seen = set()
    for v, r in other:
        if v not in seen:
            seen.add(v)
            out.append((v, r))
    return out


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _rows_of(v: Any) -> List[int]:
    if not isinstance(v, list):
        return []
    return sorted({int(x) for x in v if isinstance(x, int) and not isinstance(x, bool) and 0 < x <= 10_000_000})[:MAX_ROWS_PER_ENTRY]


def _oid(v: Any, what: str) -> Any:
    s = str(v if v is not None else "").strip()
    if not re.fullmatch(r"[0-9]{1,19}", s):
        raise ao.OperationError(f"{what} must be the id of an existing object (a number).")
    return int(s)


def _name(v: Any, what: str, limit: int) -> str:
    n = " ".join(str(v or "").split())
    if not n:
        raise ao.OperationError(f"Give the {what} a name.")
    if ao._has_control(n) or len(n) > limit:
        raise ao.OperationError(f"The {what} name must be at most {limit} characters, with no control character.")
    return n


def _group_ref(v: Any, what: str) -> Optional[Dict[str, Any]]:
    if v in (None, "", {}):
        return None
    if not isinstance(v, dict):
        raise ao.OperationError(f"'{what}' must be an object: {{\"id\": ...}} or {{\"new\": \"name\"}}.")
    if v.get("new") not in (None, ""):
        return {"new": _name(v["new"], "new group", GROUP_NAME_MAX)}
    return {"id": _oid(v.get("id"), f"The {what.replace('_', ' ')}")}


def _entries(spec: Dict[str, Any], key: str) -> List[Dict[str, Any]]:
    return [{"value": str(v)[:300], "rows": []} for v in ao._raw_entries(ao._list_field(spec, key, cap=MAX_ENTRIES)
                                                                         if isinstance(spec.get(key), list) else spec.get(key))][:MAX_ENTRIES]


def _rule_ref(rule: Any, action: str) -> Optional[Dict[str, Any]]:
    """The rule sub-spec: None, {"id": n} or {"new": {name, above, enabled}}."""
    if rule in (None, "", {}):
        return None
    if not isinstance(rule, dict):
        raise ao.OperationError("'rule' must be an object: {\"id\": ...} or {\"new\": {\"name\": ...}}.")
    if action == "remove":
        raise ao.OperationError("Removing destinations from a group changes no rule: leave the rule out.")
    if isinstance(rule.get("new"), dict):
        nr = rule["new"]
        above = nr.get("above")
        return {"new": {"name": _name(nr.get("name"), "new rule", RULE_NAME_MAX),
                        "above": None if above in (None, "") else _oid(above, "The rule to place it above"),
                        "enabled": nr.get("enabled") is True}}
    return {"id": _oid(rule.get("id"), "The rule")}


# A custom category id: CUSTOM_nn as ZIA names them (any upper-case id is
# taken), or a number (the offline sample store numbers what it creates).
_CAT_ID = re.compile(r"^(?:[A-Z][A-Z0-9_]{1,63}|[0-9]{1,20})$")


def _cat_ref(v: Any) -> Optional[Dict[str, Any]]:
    """A custom URL category: {"id": "CUSTOM_01"} or {"new": name}."""
    if v in (None, "", {}):
        return None
    if not isinstance(v, dict):
        raise ao.OperationError("'category' must be an object: {\"id\": ...} or {\"new\": \"name\"}.")
    if v.get("new") not in (None, ""):
        return {"new": _name(v["new"], "new category", CAT_NAME_MAX)}
    cid = str(v.get("id") or "").strip()
    if not _CAT_ID.match(cid):
        raise ao.OperationError("The category must be the id of a custom URL category (such as CUSTOM_01).")
    return {"id": cid}


def standalone(spec: Dict[str, Any]) -> Dict[str, Any]:
    """An ip_group_edit or atp_list_edit as the list_fix it is planned as."""
    t = str(spec.get("type") or "")
    add, remove = _entries(spec, "add"), _entries(spec, "remove")
    if not add and not remove:
        raise ao.OperationError("List at least one entry to add or to remove.")
    if len(add) + len(remove) > MAX_ENTRIES:
        raise ao.OperationError(f"At most {MAX_ENTRIES:,} entries per operation. Split it.")
    fixes = []
    if t == LIST_TYPE:
        lst = str(spec.get("list") or "")
        if lst not in LISTS:
            raise ao.OperationError("list must be denylist or allowlist.")
        for action, dests in (("add", add), ("remove", remove)):
            if dests:
                fixes.append({"area": "atp", "purpose": LISTS[lst]["purpose"], "action": action, "list": lst, "destinations": dests})
        return {"type": TYPE, "fixes": fixes}
    g = spec.get("group")
    if not isinstance(g, dict):
        raise ao.OperationError("'group' must be an object: {\"id\": ...} or {\"new\": \"name\", \"group_type\": \"DSTN_IP\" or \"DSTN_FQDN\"}.")
    if g.get("new") not in (None, ""):
        gt = str(g.get("group_type") or "")
        if gt not in ("DSTN_IP", "DSTN_FQDN"):
            raise ao.OperationError("A new group's group_type is DSTN_IP (addresses) or DSTN_FQDN (host names).")
        if remove:
            raise ao.OperationError("A new group has nothing to remove.")
        ref = {"new": g["new"]}
        fixes.append({"area": "firewall", "purpose": "block", "action": "add", "destinations": add,
                      "ip_group": ref if gt == "DSTN_IP" else None, "fqdn_group": ref if gt == "DSTN_FQDN" else None})
        return {"type": TYPE, "fixes": fixes}
    ref = {"id": g.get("id")}
    for action, dests in (("add", add), ("remove", remove)):
        if dests:
            fixes.append({"area": "firewall", "purpose": "block", "action": action, "destinations": dests, "ip_group": ref, "fqdn_group": ref})
    return {"type": TYPE, "fixes": fixes}


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """The operation as it is planned (and hashed), every field checked; an
    OperationError (the endpoint's 400) says what is wrong."""
    if str(spec.get("type") or "") in (GROUP_TYPE, LIST_TYPE):
        return normalize(standalone(spec))
    if str(spec.get("action") or "") == "revert":
        return _normalize_revert(spec)
    fixes = ao._list_field(spec, "fixes", objects=True, cap=MAX_FIXES)
    if not fixes:
        raise ao.OperationError("Name at least one fix: an area (firewall, dns or atp), a purpose and the destinations.")
    out, total = [], 0
    for f in fixes:
        area = str(f.get("area") or "")
        if area not in AREAS:
            raise ao.OperationError(f"Unknown area '{area[:20]}': use firewall, dns, atp or url.")
        purpose = str(f.get("purpose") or "")
        if purpose not in ("block", "allow"):
            raise ao.OperationError("purpose must be block or allow.")
        action = str(f.get("action") or "add")
        if action not in ("add", "remove"):
            raise ao.OperationError("action must be add or remove.")
        dests = ao._list_field(f, "destinations", objects=True, cap=MAX_ENTRIES)
        total += len(dests)
        if total > MAX_ENTRIES:
            raise ao.OperationError(f"At most {MAX_ENTRIES:,} destinations per operation. Split it.")
        d = [{"value": str(x.get("value") or "")[:300], "rows": _rows_of(x.get("rows"))} for x in dests]
        if not d:
            raise ao.OperationError(f"The {AREAS[area]['label']} fix lists no destination.")
        n: Dict[str, Any] = {"area": area, "purpose": purpose, "action": action, "destinations": d,
                             "decided_by": [str(x)[:80] for x in (f.get("decided_by") or [])[:5] if isinstance(f.get("decided_by"), list)]}
        if area == "url":
            if action == "remove":
                raise ao.OperationError("A URL fix adds the rows' URLs to a custom URL category; remove URLs with the URL category change.")
            n["category"] = _cat_ref(f.get("category"))
            if n["category"] is None:
                raise ao.OperationError("Pick the custom URL category the URLs go into, or name a new one.")
            n["rule"] = _rule_ref(f.get("rule"), action)
            out.append(n)
            continue
        if area == "atp":
            want = LISTS["denylist" if purpose == "block" else "allowlist"]
            lst = str(f.get("list") or ("denylist" if purpose == "block" else "allowlist"))
            if lst not in LISTS:
                raise ao.OperationError("list must be denylist or allowlist.")
            if action == "add" and LISTS[lst]["purpose"] != purpose:
                raise ao.OperationError(f"Adding rows to {purpose} to the {LISTS[lst]['label']} would do the opposite: use the {want['label']}.")
            n["list"] = lst
        else:
            n["ip_group"] = _group_ref(f.get("ip_group"), "ip_group")
            n["fqdn_group"] = _group_ref(f.get("fqdn_group"), "fqdn_group")
            if action == "remove" and any(g and "new" in g for g in (n["ip_group"], n["fqdn_group"])):
                raise ao.OperationError("Removing destinations works on an existing group only.")
            n["rule"] = _rule_ref(f.get("rule"), action)
            svcs = ao._list_field(f, "services", cap=MAX_SERVICES)
            if svcs and area != "firewall":
                raise ao.OperationError("Network services go on a Cloud Firewall rule only.")
            if svcs and not n["rule"]:
                raise ao.OperationError("Network services need a rule to go on: pick a rule or create one.")
            n["services"] = sorted({_oid(s, "A network service") for s in svcs})
        out.append(n)
    return {"type": TYPE, "fixes": out}


def _normalize_revert(spec: Dict[str, Any]) -> Dict[str, Any]:
    steps = ao._list_field(spec, "steps", objects=True, cap=500)
    if not steps:
        raise ao.OperationError("This Undo has no step.")
    out = []
    for s in steps:
        op, area = str(s.get("op") or ""), str(s.get("area") or "")
        if area not in AREAS:
            raise ao.OperationError("Every Undo step names its area.")
        if op in ("delete_rule", "rule_refs") and area == "atp":
            raise ao.OperationError("An ATP step changes no rule.")
        if op in ("group", "delete_group") and area in ("atp", "url"):
            raise ao.OperationError("An IP destination group step is in the firewall or dns area.")
        if op == "delete_rule":
            out.append({"op": op, "area": area, "id": _oid(s.get("id"), "The rule"), "name": str(s.get("name") or "")[:255]})
        elif op == "rule_refs":
            refs = {}
            for field in ("dest_ip_groups", "nw_services"):
                v = s.get(field) if isinstance(s.get(field), dict) else {}
                refs[field] = {k: sorted({_oid(x, "A reference") for x in (v.get(k) or [])[:500]}) for k in ("add", "remove")}
            v = s.get("url_categories") if isinstance(s.get("url_categories"), dict) else {}
            refs["url_categories"] = {k: sorted({(_cat_ref({"id": x}) or {}).get("id") for x in (v.get(k) or [])[:500]}) for k in ("add", "remove")}
            out.append(dict({"op": op, "area": area, "id": _oid(s.get("id"), "The rule"), "name": str(s.get("name") or "")[:255]}, **refs))
        elif op == "atp":
            lst = str(s.get("list") or "")
            if lst not in LISTS:
                raise ao.OperationError("An ATP Undo step names its list.")
            out.append({"op": op, "area": "atp", "list": lst, "add": [str(x)[:1100] for x in (s.get("add") or [])[:MAX_ENTRIES]],
                        "remove": [str(x)[:1100] for x in (s.get("remove") or [])[:MAX_ENTRIES]]})
        elif op == "group":
            out.append({"op": op, "area": area, "id": _oid(s.get("id"), "The group"), "name": str(s.get("name") or "")[:255],
                        "add": [str(x)[:300] for x in (s.get("add") or [])[:MAX_GROUP_ADDRESSES]],
                        "remove": [str(x)[:300] for x in (s.get("remove") or [])[:MAX_GROUP_ADDRESSES]]})
        elif op == "delete_group":
            out.append({"op": op, "area": area, "id": _oid(s.get("id"), "The group"), "name": str(s.get("name") or "")[:255],
                        "addresses": [str(x)[:300] for x in (s.get("addresses") or [])[:MAX_GROUP_ADDRESSES]]})
        elif op in ("category", "delete_category"):
            if area != "url":
                raise ao.OperationError("A URL category Undo step is in the url area.")
            cid = _cat_ref({"id": s.get("id")})["id"]
            if op == "category":
                out.append({"op": op, "area": area, "id": cid, "name": str(s.get("name") or "")[:255],
                            "add": [str(x)[:1100] for x in (s.get("add") or [])[:ao.MAX_URLS]],
                            "remove": [str(x)[:1100] for x in (s.get("remove") or [])[:ao.MAX_URLS]]})
            else:
                out.append({"op": op, "area": area, "id": cid, "name": str(s.get("name") or "")[:255],
                            "urls": [str(x)[:1100] for x in (s.get("urls") or [])[:ao.MAX_URLS]]})
        else:
            raise ao.OperationError(f"Unknown Undo step '{op[:20]}'.")
    return {"type": TYPE, "action": "revert", "steps": out}


# ---------------------------------------------------------------------------
# Reading the tenant (GET only)
# ---------------------------------------------------------------------------

def _fw(zia):
    svc = getattr(zia, "cloud_firewall", None)
    if svc is None:
        raise ao.OperationError("The installed zscaler-sdk-python has no cloud_firewall service.")
    return svc


def read_groups(zia) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every IP destination group with its addresses (GET /ipDestinationGroups)."""
    try:
        rows, err = ao._rows(_fw(zia).list_ip_destination_groups())
    except ao.OperationError:
        raise
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    return [zb._deep_snake(r) for r in rows], err


def get_group(zia, gid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        row, err = ao._one(_fw(zia).get_ip_destination_group(gid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    return (zb._deep_snake(row) if row else None), err


def read_services(zia) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    try:
        rows, err = ao._rows(_fw(zia).list_network_services())
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    return [zb._deep_snake(r) for r in rows], err


def read_list(zia, lst: str) -> Tuple[Optional[List[str]], Optional[str]]:
    """One security policy list (GET /security or /security/advanced)."""
    svc = getattr(zia, "security_policy_settings", None)
    if svc is None:
        return None, "the installed zscaler-sdk-python has no security_policy_settings service"
    try:
        row, err = ao._one(svc.get_blacklist() if lst == "denylist" else svc.get_whitelist())
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"
    if row is None:
        return None, err or "no answer"
    v = row.get(LISTS[lst]["field"])
    return [str(x) for x in v if isinstance(x, (str, int))] if isinstance(v, list) else [], None


def _addresses(g: Optional[Dict[str, Any]]) -> List[str]:
    v = (g or {}).get("addresses")
    return [str(x) for x in v if isinstance(x, (str, int))] if isinstance(v, list) else []


def _ids(rule: Optional[Dict[str, Any]], field: str) -> List[str]:
    out = []
    for x in (rule or {}).get(field) or []:
        v = x.get("id") if isinstance(x, dict) else x
        if v not in (None, ""):
            out.append(str(v))
    return out


def _gtype(g: Dict[str, Any]) -> str:
    return str(g.get("type") or "").upper()


def _rule_kind(area: str, action: Any) -> str:
    a = str(action or "").upper()
    if area == "url":
        return "block" if a == "BLOCK" else "allow" if a == "ALLOW" else "other"   # Caution and Isolate neither block nor allow
    if a.startswith("BLOCK") or a in ("DROP", "RESET"):
        return "block"
    if a == "ALLOW":
        return "allow"
    return "other"


def _rows_text(rows: Sequence[int]) -> str:
    rows = list(rows)
    if not rows:
        return ""
    shown = ", ".join(str(r) for r in rows[:8])
    return f"row{'s' if len(rows) > 1 else ''} {shown}{' and more' if len(rows) > 8 else ''}"


def _num(v: Any) -> Any:
    s = str(v)
    return int(s) if s.isdigit() else v


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

class _Planner:
    def __init__(self, client, say, cancel):
        self.zia = client.zia
        self.say, self.cancel = say, cancel
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []
        self.impact: List[Dict[str, Any]] = []
        self.confirm_always = False
        self.cache: Dict[str, Any] = {}
        self.n = 0

    def key(self, prefix: str) -> str:
        self.n += 1
        return f"{prefix}{self.n}"

    def unit(self, group: str, kind: str, obj: Dict[str, Any], field: str, before: Any, after: Any, *, value: Any = None,
             status: str = "change", reason: str = "", depends_on: Sequence[str] = (), rows: Sequence[int] = (), explain: str = "",
             prefix: str = "u") -> Dict[str, Any]:
        u = ao._unit(self.key(prefix), group, kind, obj, field, before, after, value=value, status=status, reason=reason, depends_on=depends_on)
        u["rows"] = list(rows)[:MAX_ROWS_PER_ENTRY]
        u["explain"] = explain
        self.items.append(u)
        return u

    def read(self, what: str, fn: Callable[[], Tuple[Any, Optional[str]]], label: str) -> Any:
        if what not in self.cache:
            ao._check_stop(self.cancel)
            self.say(f"Reading {label}…")
            val, err = fn()
            if err:
                raise ao.OperationError(f"{label[0].upper() + label[1:]} could not be read: {err}. Nothing was written.")
            self.cache[what] = val
        return self.cache[what]

    def all_groups(self) -> List[Dict[str, Any]]:
        return self.read("groups", lambda: read_groups(self.zia), "the IP destination groups")

    def rules(self, area: str) -> List[Dict[str, Any]]:
        return self.read(f"rules:{area}", lambda: zb.read_area(self.zia, area, cancel=self.cancel), f"the {AREAS[area]['label']} rules")

    def services(self) -> List[Dict[str, Any]]:
        return self.read("services", lambda: read_services(self.zia), "the network services")

    def atp_list(self, lst: str) -> List[str]:
        return self.read(f"list:{lst}", lambda: read_list(self.zia, lst), f"the {LISTS[lst]['label']}")

    def categories(self) -> List[Dict[str, Any]]:
        return self.read("categories", lambda: ao.read_categories(self.zia), "the custom URL categories")


def _rule_obj(area: str, r: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "rule", "area": area, "policy_label": AREAS[area]["label"], "id": r.get("id"), "name": str(r.get("name") or ""),
            "order": r.get("order"), "state": ao._state(r)}


def _group_obj(g: Dict[str, Any], area: str) -> Dict[str, Any]:
    return {"type": "ip_group", "area": area, "policy_label": "IP destination group", "id": g.get("id"), "name": str(g.get("name") or ""),
            "group_type": _gtype(g)}


def _plan(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    t = str(spec.get("type") or TYPE)
    n = normalize(spec)
    if n.get("action") == "revert":
        return _plan_revert(client, n, say, cancel)
    out = _plan_fixes(client, n, say, cancel)
    if t != TYPE:
        out["type"] = t
        out["title"] = _standalone_title(t, spec, out["items"])
    return out


def _standalone_title(t: str, spec: Dict[str, Any], items: List[Dict[str, Any]]) -> str:
    adds = sum(1 for u in items if u["status"] == "change" and u["after"] is True and u["kind"] in ("address", "list_entry"))
    drops = sum(1 for u in items if u["status"] == "change" and u["after"] is False)
    if t == LIST_TYPE:
        return f"ATP {LISTS.get(str(spec.get('list')), {}).get('label', 'list')}: add {adds}, remove {drops}"
    name = next((u["object"].get("name") for u in items if u["kind"] in ("address", "create_group") and u["object"].get("name")), "group")
    return f"IP destination group '{name}': add {adds}, remove {drops}"


def _plan_fixes(client, n: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    P = _Planner(client, say, cancel)
    add_groups: List[Dict[str, Any]] = []      # creates and updates of groups first
    atp_groups: List[Dict[str, Any]] = []
    rule_groups: List[Dict[str, Any]] = []
    total_new_ip = 0
    for fx in n["fixes"]:
        area, purpose, action = fx["area"], fx["purpose"], fx["action"]
        verb = "block" if purpose == "block" else "allow"
        if area == "atp":
            atp_groups += _plan_atp(P, fx)
            continue
        if area == "url":
            made, target = _plan_url_category(P, fx)
            add_groups += made
            if target is not None:
                if fx["rule"] is not None:
                    rule_groups += _plan_rule(P, fx, [target])
                else:
                    _warn_no_rule(P, fx, target)
            continue
        # Split the destinations by what can hold them.
        ips: List[Tuple[str, List[int]]] = []
        hosts: List[Tuple[str, List[int]]] = []
        for d in fx["destinations"]:
            kind, val, why = classify(d["value"])
            if kind == "ip":
                ips.append((val, d["rows"]))
            elif kind == "host":
                hosts.append((val.lower(), d["rows"]))
            else:
                P.unit("refused", "address", {"type": "destination", "name": d["value"][:120], "area": area}, "addresses", None, None,
                       value=d["value"][:120], status="excluded", reason=f"not changed: it {why}" if kind == "bad" else f"not changed: {why}",
                       rows=d["rows"], explain=f"{d['value'][:120]} cannot go into an IP destination group.")
        if action == "add":
            ips = collapse(ips)
        merged: Dict[str, List[int]] = {}
        for v, r in hosts:
            merged[v] = sorted(set(merged.get(v, []) + r))[:MAX_ROWS_PER_ENTRY]
        hosts = list(merged.items())
        targets: List[Tuple[str, List[str]]] = []      # (group key or "id:<id>", the unit keys of its create) for the rule step
        for which, entries, types_ok, word in (("ip_group", ips, IP_TYPES, "addresses"), ("fqdn_group", hosts, HOST_TYPES, "host names")):
            if not entries:
                continue
            ref = fx[which]
            if ref is None:
                for v, rows in entries:
                    P.unit("refused", "address", {"type": "destination", "name": v, "area": area}, "addresses", None, None, value=v,
                           status="excluded", reason=f"not changed: no group was picked for the {word}", rows=rows,
                           explain=f"{v}: pick a group for the {word} to change it.")
                continue
            if "new" in ref:
                created = _plan_new_groups(P, area, purpose, ref["new"], "DSTN_IP" if which == "ip_group" else "DSTN_FQDN", entries, fx)
                add_groups += [g for g, _k in created]
                targets += [("new:" + k, [k]) for _g, k in created]
                if which == "ip_group":
                    total_new_ip += sum(len(g["target"]["addresses"]) for g, _k in created)
            else:
                g, gkey, added = _plan_group_change(P, area, purpose, action, ref["id"], types_ok, entries, word)
                if g is not None:
                    add_groups.append(g)
                if gkey:
                    targets.append((gkey, []))
                if which == "ip_group":
                    total_new_ip += added
        if action == "add" and fx["rule"] is not None and targets:
            rule_groups += _plan_rule(P, fx, targets)
    if total_new_ip:
        held = sum(len(_addresses(g)) for g in P.cache.get("groups") or [] if _gtype(g) in IP_TYPES)
        if held + total_new_ip > ORG_IP_ENTRIES:
            P.warnings.append(f"The IP destination groups would hold about {held + total_new_ip:,} IP entries; ZIA's default limit is "
                              f"{ORG_IP_ENTRIES:,} per organisation across source and destination groups (assumed; Support can raise it). "
                              "The tenant refuses a write past its limit.")
    groups = add_groups + atp_groups + rule_groups
    live_groups = {str(i.get("group_id")) for i in P.impact if any(r.get("state") == "ENABLED" for r in i.get("rules") or [])}
    return {"type": TYPE, "product": "zia", "spec": n, "items": P.items, "groups": groups, "warnings": P.warnings, "blockers": P.blockers,
            "impact": P.impact, "title": _title(n), "explanations": _explanations(P.items),
            "confirm_always": _typed(P.items, groups, live_groups, P.confirm_always)}


def _typed(items: List[Dict[str, Any]], groups: List[Dict[str, Any]], live_groups: Set[str], always: bool = False) -> str:
    """The phrase every apply must type whatever the count of changes
    (admin_ops._finish `confirm_always`), or "" to keep the count rule:
    asked when a change acts on traffic as soon as ZIA activates (which the
    app does right after the writes): the ATP lists, an existing rule, a
    group an enabled rule uses, a rule created enabled; and for any new
    rule, as the ZIA baseline does."""
    changes = sum(1 for u in items if u.get("status") == "change")
    risky = always or any(g["handler"] in ("lf_atp", "lf_rule", "lf_rule_create", "lf_rule_delete")
                          or (g["handler"] == "lf_group" and str(g["target"].get("id")) in live_groups) for g in groups)
    return f"APPLY {changes} CHANGE{'' if changes == 1 else 'S'}" if risky and changes else ""


def _title(n: Dict[str, Any]) -> str:
    parts = []
    for fx in n["fixes"]:
        lab = AREAS[fx["area"]]["label"] if fx["area"] != "atp" else "ATP lists"
        parts.append(f"{lab} ({'remove' if fx['action'] == 'remove' else fx['purpose']}, {len(fx['destinations'])})")
    return "Fix selected rows: " + "; ".join(parts)


def _explanations(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The preview's plain-word list: one sentence per write, with the rows it fixes."""
    by_group: Dict[str, Dict[str, Any]] = {}
    for u in items:
        if u["status"] != "change":
            continue
        g = by_group.setdefault(u["group"], {"group": u["group"], "sentences": [], "rows": set()})
        if u.get("explain") and u["explain"] not in g["sentences"]:
            g["sentences"].append(u["explain"])
        g["rows"].update(u.get("rows") or [])
    return [{"group": k, "text": " ".join(v["sentences"][:3]) + (f" (and {len(v['sentences']) - 3} more)" if len(v["sentences"]) > 3 else ""),
             "rows": sorted(v["rows"])[:200]} for k, v in by_group.items()]


def _plan_new_groups(P: _Planner, area: str, purpose: str, name: str, gtype: str, entries: List[Tuple[str, List[int]]],
                     fx: Dict[str, Any]) -> List[Tuple[Dict[str, Any], str]]:
    """New groups for `entries`, MAX_GROUP_ADDRESSES each: name, name (2), ..."""
    groups = P.all_groups()
    taken = {str(g.get("name") or "").strip().lower() for g in groups}
    chunks = [entries[i:i + MAX_GROUP_ADDRESSES] for i in range(0, len(entries), MAX_GROUP_ADDRESSES)]
    if len(chunks) > 1:
        P.warnings.append(f"{len(entries):,} entries are more than one IP destination group holds ({MAX_GROUP_ADDRESSES:,}, assumed): "
                          f"they are split over {len(chunks)} new groups, '{name}' to '{name} ({len(chunks)})', each added to the rule.")
    out = []
    for i, chunk in enumerate(chunks):
        gname = name if i == 0 else f"{name} ({i + 1})"[:GROUP_NAME_MAX]
        gkey = P.key("g")
        obj = {"type": "ip_group", "area": area, "policy_label": "IP destination group (new)", "id": None, "name": gname, "group_type": gtype}
        rows = sorted({r for _v, rs in chunk for r in rs})
        if gname.lower() in taken:
            P.blockers.append(f"An IP destination group named '{gname}' already exists: pick it as an existing group, or give the new one "
                              "another name.")
        cu = ao._unit(gkey, gkey, "create_group", dict(obj), "exists", False, True, value=gname)
        cu["rows"] = rows[:MAX_ROWS_PER_ENTRY]
        cu["explain"] = (f"Create the IP destination group '{gname}' (type {'IP addresses' if gtype == 'DSTN_IP' else 'FQDN'}) with "
                         f"{len(chunk):,} entr{'y' if len(chunk) == 1 else 'ies'}" + (f" for the {AREAS[area]['label']} rows to {purpose}." if rows else "."))
        P.items.append(cu)
        for v, rs in chunk:
            P.unit(gkey, "address", dict(obj), "addresses", False, True, value=v, depends_on=[gkey], rows=rs,
                   explain=f"Put {v} in the new group '{gname}'.")
        out.append(({"key": gkey, "handler": "lf_group_create", "target": {"key": gkey, "area": area, "name": gname, "type": gtype,
                                                                            "addresses": [v for v, _ in chunk]}}, gkey))
    return out


def _plan_group_change(P: _Planner, area: str, purpose: str, action: str, gid: Any, types_ok: Sequence[str],
                       entries: List[Tuple[str, List[int]]], word: str) -> Tuple[Optional[Dict[str, Any]], str, int]:
    """(the write group, the group's reference for a rule, entries added)."""
    groups = P.all_groups()
    g = next((x for x in groups if str(x.get("id")) == str(gid)), None)
    if g is None:
        P.blockers.append(f"IP destination group {gid} is not in the tenant (deleted since it was picked?). Read again and pick another.")
        return None, "", 0
    obj = _group_obj(g, area)
    gname = obj["name"]
    if ao._truthy(g.get("is_non_editable")):
        P.blockers.append(f"IP destination group '{gname}' is maintained by Zscaler and cannot be changed: pick another or a new one.")
        return None, "", 0
    if _gtype(g) not in types_ok:
        P.blockers.append(f"IP destination group '{gname}' is of type {_gtype(g) or 'unknown'}, which does not hold {word}: pick a group of "
                          f"type {' or '.join(types_ok)}, or a new one.")
        return None, "", 0
    have = _addresses(g)
    have_l = {h.lower() for h in have}
    gkey = P.key("gu")
    room = MAX_GROUP_ADDRESSES - len(have)
    added = 0
    for v, rows in entries:
        present = v.lower() in have_l
        if action == "remove":
            if present:
                P.unit(gkey, "address", dict(obj), "addresses", True, False, value=v, rows=rows,
                       explain=f"Take {v} out of the group '{gname}'.")
            else:
                cov = covered_by(v, have)
                P.unit(gkey, "address", dict(obj), "addresses", False, False, value=v, rows=rows,
                       status="excluded" if cov else "noop",
                       reason=(f"not changed: it is inside {cov} in this group; change that entry in the portal" if cov else "not in this group"))
            continue
        cov = covered_by(v, have)
        if cov:
            P.unit(gkey, "address", dict(obj), "addresses", True, True, value=v, rows=rows, status="noop",
                   reason="already in this group" if cov.lower() == v.lower() else f"already covered by {cov} in this group")
        elif added >= room:
            P.unit(gkey, "address", dict(obj), "addresses", False, True, value=v, rows=rows, status="excluded",
                   reason=f"not changed: '{gname}' would hold more than {MAX_GROUP_ADDRESSES:,} entries (ZIA's per-group limit, assumed). "
                          "Put the rest in a new group.")
        else:
            added += 1
            P.unit(gkey, "address", dict(obj), "addresses", False, True, value=v, rows=rows,
                   explain=f"Add {v} to the IP destination group '{gname}'.")
    _group_impact(P, g, area)
    if not any(u["group"] == gkey and u["status"] == "change" for u in P.items):
        return None, f"id:{g.get('id')}", added
    return {"key": gkey, "handler": "lf_group", "target": {"id": g.get("id"), "name": gname, "area": area}}, f"id:{g.get('id')}", added


def _group_impact(P: _Planner, g: Dict[str, Any], area: str) -> None:
    """Which rules (of the areas this operation reads) use the group."""
    gid = str(g.get("id"))
    if any(i.get("group_id") == gid for i in P.impact):
        return
    users = []
    for a in ("firewall", "dns"):
        if f"rules:{a}" not in P.cache and a != area:
            continue
        for r in P.rules(a):
            if gid in _ids(r, "dest_ip_groups"):
                users.append({"name": str(r.get("name") or ""), "policy_label": AREAS[a]["label"], "order": r.get("order"),
                              "state": ao._state(r), "action": r.get("action")})
    P.impact.append({"category": f"IP destination group '{g.get('name')}'", "group_id": gid, "rules": users,
                     "detail": "No rule read here uses this group yet." if not users else ""})


def _plan_rule(P: _Planner, fx: Dict[str, Any], targets: List[Tuple[str, List[str]]]) -> List[Dict[str, Any]]:
    area, purpose = fx["area"], fx["purpose"]
    rules = P.rules(area)
    rows_all = sorted({r for d in fx["destinations"] for r in d["rows"]})
    names = {str(r.get("name") or ""): r for r in rules}
    deciding = [names[x] for x in fx.get("decided_by") or [] if x in names]
    field = REF_FIELD[area]
    word = "category" if area == "url" else "group"
    gnames = []
    for ref, _deps in targets:
        if ref.startswith("new:"):
            gnames.append(next((u["value"] for u in P.items if u["key"] == ref[4:]), f"the new {word}"))
        elif area == "url":
            gnames.append(next((ao._cat_ref(c)["name"] for c in P.cache.get("categories") or [] if f"id:{ao._cat_ref(c)['id']}" == ref), ref[3:]))
        else:
            gnames.append(next((str(g.get("name")) for g in P.cache.get("groups") or [] if f"id:{g.get('id')}" == ref), ref[3:]))
    svc_ids = fx.get("services") or []
    svc_names = {}
    if svc_ids:
        have = {str(s.get("id")): str(s.get("name") or s.get("id")) for s in P.services()}
        for s in svc_ids:
            if str(s) not in have:
                P.blockers.append(f"Network service {s} is not in the tenant: read again and pick another.")
            svc_names[str(s)] = have.get(str(s), str(s))
    rule = fx["rule"]
    if "new" in rule:
        nr = rule["new"]
        if any(str(r.get("name") or "").strip().lower() == nr["name"].lower() for r in rules):
            P.blockers.append(f"A {AREAS[area]['rules']} named '{nr['name']}' already exists: pick it as an existing rule, or give the new "
                              "one another name.")
        above = next((r for r in rules if str(r.get("id")) == str(nr["above"])), None) if nr["above"] is not None else None
        if nr["above"] is not None and above is None:
            P.blockers.append(f"The rule to place the new one above ({nr['above']}) is not in the tenant: read again.")
        if above is not None and ao._is_default(above):
            above = None   # the Default rule is always last: the new rule goes just before it
        if above is None and deciding and not ao._is_default(deciding[0]):
            P.warnings.append(f"The new rule goes last (above the Default rule), below '{deciding[0].get('name')}', which decided "
                              f"{_rows_text(rows_all)}: those rows stay as they are until it is moved above that rule.")
        if nr["enabled"]:
            P.confirm_always = True
            P.warnings.append(f"The new {AREAS[area]['rules']} '{nr['name']}' is created ENABLED, as you asked: it acts on traffic as soon "
                              "as ZIA activates, which the app does right after the writes.")
        state = "ENABLED" if nr["enabled"] else "DISABLED"
        act = NEW_ACTION[(area, purpose)]
        rkey = P.key("r")
        deps = [k for _ref, ks in targets for k in ks]
        where = f"above '{above.get('name')}' (order {above.get('order')})" if above is not None else "last, above the Default rule"
        cu = ao._unit(rkey, rkey, "create_rule", {"type": "rule", "area": area, "policy_label": AREAS[area]["label"], "id": None,
                                                   "name": nr["name"], "state": state}, "exists", False, True, value=nr["name"],
                      depends_on=deps)
        cu["rows"] = rows_all[:MAX_ROWS_PER_ENTRY]
        cu["explain"] = (f"Create the {AREAS[area]['rules']} '{nr['name']}', {state.lower()}, action {ACTION_WORDS.get(act, act)}, "
                         f"{'URL category' if area == 'url' else 'destination'} {', '.join(repr(x) for x in gnames)}"
                         + (f", services {', '.join(svc_names.values())}" if svc_names else "") + f", placed {where}. "
                         + ("It fixes the rows once you enable it." if not nr["enabled"] else "It fixes the rows after activation."))
        P.items.append(cu)
        payload = {"name": nr["name"], "state": state, "action": act, "rank": NEW_RULE_RANK, field: [ref for ref, _ in targets]}
        if area == "url":
            # Every protocol (ANY_RULE, as the ZIA baseline's URL rules). No
            # request_methods: the SDK documents "if not specified, the rule
            # will apply to all methods" (url_filtering.add_rule), and the
            # Path analyzer then reads the rule as unconditional, so the fix
            # it proposes is the one it evaluates.
            payload.update(protocols=["ANY_RULE"], block_override=False)
        if svc_ids:
            payload["nw_services"] = list(svc_ids)
        return [{"key": rkey, "handler": "lf_rule_create", "target": {"area": area, "name": nr["name"], "payload": payload,
                                                                        "above": above.get("id") if above is not None else None}}]
    r = next((x for x in rules if str(x.get("id")) == str(rule["id"])), None)
    if r is None:
        P.blockers.append(f"The {AREAS[area]['rules']} {rule['id']} is not in the tenant (deleted since it was picked?): read again.")
        return []
    obj = _rule_obj(area, r)
    lock = ao.lock_reason("url_filtering" if area == "url" else "firewall", r)
    if lock:
        P.blockers.append(f"{AREAS[area]['rules']} '{obj['name']}' is {lock}.")
        return []
    kind = _rule_kind(area, r.get("action"))
    if kind != purpose:
        P.blockers.append(f"{AREAS[area]['rules']} '{obj['name']}' has action {r.get('action')}: adding the rows to {purpose} to it would "
                          f"not {purpose} them. Pick a rule whose action is {'Block' if purpose == 'block' else 'Allow'}, or create one.")
        return []
    if obj["state"] != "ENABLED":
        P.warnings.append(f"{AREAS[area]['rules']} '{obj['name']}' is disabled: adding the {word} changes nothing until it is enabled.")
    for d in deciding:
        if str(d.get("id")) != str(r.get("id")) and not ao._is_default(d) and ao._int(d.get("order"), 0) < ao._int(r.get("order"), 0):
            P.warnings.append(f"'{obj['name']}' (order {r.get('order')}) is below '{d.get('name')}' (order {d.get('order')}), which decided "
                              f"{_rows_text(rows_all)}: those rows stay as they are until '{obj['name']}' is moved above it.")
    rkey = P.key("ru")
    have_g, have_s = set(_ids(r, field)), set(_ids(r, "nw_services"))
    for (ref, deps), gname in zip(targets, gnames):
        gid = ref[3:] if ref.startswith("id:") else ref
        present = gid in have_g
        P.unit(rkey, "rule_ref", dict(obj), field, present, True, value=gid, depends_on=deps, rows=rows_all,
               status="noop" if present else "change", reason=f"the rule already uses this {word}" if present else "",
               explain=f"Add the {word} '{gname}' to {AREAS[area]['rules']} '{obj['name']}' (order {r.get('order')}, "
                       f"{ACTION_WORDS.get(str(r.get('action')), r.get('action'))}).")
    for s in svc_ids:
        present = str(s) in have_s
        P.unit(rkey, "rule_ref", dict(obj), "nw_services", present, True, value=str(s), rows=rows_all,
               status="noop" if present else "change", reason="the rule already names this service" if present else "",
               explain=f"Add the network service {svc_names.get(str(s), s)} to '{obj['name']}'.")
    if not any(u["group"] == rkey and u["status"] == "change" for u in P.items):
        return []
    return [{"key": rkey, "handler": "lf_rule", "target": {"area": area, "id": r.get("id"), "name": obj["name"]}}]


def _cat_obj(c: Dict[str, Any]) -> Dict[str, Any]:
    ref = ao._cat_ref(c)
    return {"type": "url_category", "area": "url", "policy_label": "Custom URL category", "id": ref["id"], "name": ref["name"]}


def _plan_url_category(P: _Planner, fx: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Optional[Tuple[str, List[str]]]]:
    """The URLs into the custom URL category: (the writes, the category's
    reference for the rule step: ("id:<id>" or "new:<key>", create keys))."""
    cats = P.categories()
    urls: List[Tuple[str, List[int]]] = []
    seen: Dict[str, int] = {}
    for d in fx["destinations"]:
        u, why = ao.normalize_url(d["value"])
        if why:
            P.unit("refused", "cat_url", {"type": "destination", "name": d["value"][:120], "area": "url"}, "urls", None, None,
                   value=d["value"][:120], status="excluded", reason=f"not changed: it {why}", rows=d["rows"],
                   explain=f"{d['value'][:120]} cannot go into a custom URL category.")
            continue
        if u.lower() in seen:
            urls[seen[u.lower()]][1].extend(d["rows"])
            continue
        seen[u.lower()] = len(urls)
        urls.append((u, list(d["rows"])))
    if len(urls) > ao.MAX_URLS:
        P.warnings.append(f"{len(urls):,} URLs are more than one operation changes ({ao.MAX_URLS:,}): the first {ao.MAX_URLS:,} are planned; "
                          "fix the rest in another run.")
        urls = urls[:ao.MAX_URLS]
    if not urls:
        return [], None
    ref = fx["category"]
    purpose = fx["purpose"]
    if "new" in ref:
        name = ref["new"]
        if any(ao._cat_ref(c)["name"].strip().lower() == name.lower() for c in cats):
            P.blockers.append(f"A URL category named '{name}' already exists: pick it as an existing category, or give the new one another name.")
        gkey = P.key("c")
        obj = {"type": "url_category", "area": "url", "policy_label": "Custom URL category (new)", "id": None, "name": name}
        rows = sorted({r for _u, rs in urls for r in rs})
        cu = ao._unit(gkey, gkey, "create_category", dict(obj), "exists", False, True, value=name)
        cu["rows"] = rows[:MAX_ROWS_PER_ENTRY]
        cu["explain"] = f"Create the custom URL category '{name}' with {len(urls):,} URL{'' if len(urls) == 1 else 's'} for the URL filtering rows to {purpose}."
        P.items.append(cu)
        for u, rs in urls:
            P.unit(gkey, "cat_url", dict(obj), "urls", False, True, value=u, depends_on=[gkey], rows=rs, explain=f"Put {u} in the new category '{name}'.")
        return [{"key": gkey, "handler": "lf_cat_create", "target": {"key": gkey, "name": name, "urls": [u for u, _ in urls]}}], ("new:" + gkey, [gkey])
    c = next((x for x in cats if str(ao._cat_ref(x)["id"]) == ref["id"]), None)
    if c is None:
        P.blockers.append(f"The custom URL category {ref['id']} is not in the tenant (deleted since it was picked?). Read again and pick another.")
        return [], None
    obj = _cat_obj(c)
    have = ao._url_set(c)
    gkey = P.key("cu")
    for u, rs in urls:
        if u.lower() in have:
            P.unit(gkey, "cat_url", dict(obj), "urls", True, True, value=u, rows=rs, status="noop", reason="already in this category")
        else:
            P.unit(gkey, "cat_url", dict(obj), "urls", False, True, value=u, rows=rs, explain=f"Add {u} to the custom URL category '{obj['name']}'.")
    target = (f"id:{obj['id']}", [])
    if not any(u["group"] == gkey and u["status"] == "change" for u in P.items):
        return [], target
    return [{"key": gkey, "handler": "lf_cat", "target": {"id": obj["id"], "name": obj["name"]}}], target


def _warn_no_rule(P: _Planner, fx: Dict[str, Any], target: Tuple[str, List[str]]) -> None:
    """A category change alone changes nothing unless a URL filtering rule
    with the purpose's action names the category: said in the preview."""
    ref = target[0]
    if ref.startswith("new:"):
        P.warnings.append("The new URL category is not named by any URL filtering rule: adding the URLs changes nothing until a "
                          f"{'Block' if fx['purpose'] == 'block' else 'Allow'} rule names it. Pick a rule or create one under Then.")
        return
    cid = ref[3:]
    want = fx["purpose"]
    users = [r for r in P.rules("url") if cid in set(_ids(r, "url_categories")) and _rule_kind("url", r.get("action")) == want
             and ao._state(r) == "ENABLED"]
    if not users:
        P.warnings.append(f"No enabled URL filtering rule with action {'Block' if want == 'block' else 'Allow'} names the category {cid}: "
                          "adding the URLs changes nothing for these rows. Pick a rule or create one under Then.")
        return
    # Rules are evaluated by order: a rule naming the category below the
    # rule that decided the rows never sees them.
    names = {str(r.get("name") or ""): r for r in P.rules("url")}
    deciding = [names[x] for x in fx.get("decided_by") or [] if x in names and not ao._is_default(names[x])]
    top = min((ao._int(d.get("order"), 0) for d in deciding), default=None)
    if top is not None and all(ao._int(r.get("order"), 0) > top for r in users):
        first = min(deciding, key=lambda d: ao._int(d.get("order"), 0))
        P.warnings.append(f"Every enabled {'Block' if want == 'block' else 'Allow'} URL filtering rule that names the category {cid} "
                          f"({', '.join(repr(str(r.get('name'))) for r in users[:3])}) is below '{first.get('name')}' (order {first.get('order')}), "
                          f"which decided {_rows_text(sorted({r for d in fx['destinations'] for r in d['rows']})) or 'the rows'}: adding the URLs changes "
                          "nothing for these rows. Create a rule above it under Then, or move that rule up.")


def _plan_atp(P: _Planner, fx: Dict[str, Any]) -> List[Dict[str, Any]]:
    lst, action = fx["list"], fx["action"]
    have = P.atp_list(lst)
    have_l = {h.lower() for h in have}
    other = "allowlist" if lst == "denylist" else "denylist"
    obj = {"type": "atp_list", "area": "atp", "policy_label": "Advanced Threat Protection", "id": lst, "name": LISTS[lst]["label"]}
    gkey = P.key("a")
    adds = 0
    for d in fx["destinations"]:
        v, why = ao.normalize_url(d["value"])
        if why:
            P.unit("refused", "list_entry", dict(obj), "urls", None, None, value=d["value"][:120], status="excluded",
                   reason=f"not changed: it {why}", rows=d["rows"])
            continue
        present = v.lower() in have_l
        if action == "remove":
            P.unit(gkey, "list_entry", dict(obj), "urls", present, False, value=v, rows=d["rows"], status="change" if present else "noop",
                   reason="" if present else "not on this list", explain=f"Take {v} off the {LISTS[lst]['label']}.")
            continue
        if present:
            P.unit(gkey, "list_entry", dict(obj), "urls", True, True, value=v, rows=d["rows"], status="noop", reason="already on this list")
            continue
        if len(have) + adds >= ATP_LIST_MAX:
            P.unit(gkey, "list_entry", dict(obj), "urls", False, True, value=v, rows=d["rows"], status="excluded",
                   reason=f"not changed: the list would hold more than {ATP_LIST_MAX:,} entries (assumed limit)")
            continue
        adds += 1
        P.unit(gkey, "list_entry", dict(obj), "urls", False, True, value=v, rows=d["rows"],
               explain=f"Add {v} to the {LISTS[lst]['label']}, which ATP applies to every user and location.")
    if action == "add" and lst == "denylist":
        try:
            allow = {h.lower() for h in P.atp_list(other)}
        except ao.OperationError:
            allow = set()
        both = [u["value"] for u in P.items if u["group"] == gkey and u["status"] == "change" and u["value"].lower() in allow]
        if both:
            P.warnings.append(f"{', '.join(both[:5])}{' and more' if len(both) > 5 else ''} {'is' if len(both) == 1 else 'are'} on the "
                              "security policy allowlist too, which wins over the denylist (as the Path analyzer assumes): take "
                              f"{'it' if len(both) == 1 else 'them'} off the allowlist as well.")
    if not any(u["group"] == gkey and u["status"] == "change" for u in P.items):
        return []
    return [{"key": gkey, "handler": "lf_atp", "target": {"list": lst}}]


def _plan_revert(client, n: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """The Undo of an applied fix: rules first (a group in use cannot be
    deleted), then the lists and groups, created groups last."""
    P = _Planner(client, say, cancel)
    order = {"delete_rule": 0, "rule_refs": 1, "atp": 2, "group": 3, "category": 3, "delete_group": 4, "delete_category": 4}
    groups: List[Dict[str, Any]] = []
    for st in sorted(n["steps"], key=lambda s: order[s["op"]]):
        ao._check_stop(cancel)
        op, area = st["op"], st["area"]
        if op == "delete_rule":
            r, err = zb.get_one(P.zia, area, st["id"])
            obj = {"type": "rule", "area": area, "policy_label": AREAS[area]["label"], "id": st["id"], "name": st["name"]}
            k = P.key("x")
            if r is None and err and ao._read_halt(err):
                raise ao.OperationError(f"The rule could not be read: {err}. Nothing was written.")
            if r is None:
                P.items.append(dict(ao._unit(k, k, "delete_rule", obj, "exists", False, False, status="noop", reason="already gone"), rows=[], explain=""))
                continue
            if str(r.get("name") or "") != st["name"]:
                P.items.append(dict(ao._unit(k, k, "delete_rule", obj, "exists", True, True, status="excluded",
                                             reason=f"renamed since (now '{r.get('name')}'): not deleted"), rows=[], explain=""))
                continue
            P.items.append(dict(ao._unit(k, k, "delete_rule", obj, "exists", True, False), rows=[],
                                explain=f"Delete the {AREAS[area]['rules']} '{st['name']}' this fix created."))
            groups.append({"key": k, "handler": "lf_rule_delete", "target": {"area": area, "id": st["id"], "name": st["name"]}})
        elif op == "rule_refs":
            r, err = zb.get_one(P.zia, area, st["id"])
            if r is None:
                P.warnings.append(f"The {AREAS[area]['rules']} '{st['name']}' could not be read ({err or 'gone'}): it is left as it is.")
                continue
            obj = _rule_obj(area, r)
            k = P.key("xr")
            for field in ("dest_ip_groups", "nw_services", "url_categories"):
                if field not in st:
                    continue
                have = set(_ids(r, field))
                for after, vals in ((True, st[field]["add"]), (False, st[field]["remove"])):
                    for v in vals:
                        now = str(v) in have
                        P.unit(k, "rule_ref", dict(obj), field, now, after, value=str(v), status="noop" if now == after else "change",
                               reason="already as before the fix" if now == after else "",
                               explain=f"{'Put back' if after else 'Take'} {field.replace('dest_ip_groups', 'group').replace('nw_services', 'service').replace('url_categories', 'category')} "
                                       f"{v} {'on' if after else 'off'} '{obj['name']}'.")
            if any(u["group"] == k and u["status"] == "change" for u in P.items):
                groups.append({"key": k, "handler": "lf_rule", "target": {"area": area, "id": st["id"], "name": obj["name"]}})
        elif op == "atp":
            have = {h.lower() for h in P.atp_list(st["list"])}
            obj = {"type": "atp_list", "area": "atp", "policy_label": "Advanced Threat Protection", "id": st["list"],
                   "name": LISTS[st["list"]]["label"]}
            k = P.key("xa")
            for after, vals in ((True, st["add"]), (False, st["remove"])):
                for v in vals:
                    now = v.lower() in have
                    P.unit(k, "list_entry", dict(obj), "urls", now, after, value=v, status="noop" if now == after else "change",
                           reason="already as before the fix" if now == after else "",
                           explain=f"{'Put' if after else 'Take'} {v} {'back on' if after else 'off'} the {LISTS[st['list']]['label']}.")
            if any(u["group"] == k and u["status"] == "change" for u in P.items):
                groups.append({"key": k, "handler": "lf_atp", "target": {"list": st["list"]}})
        elif op == "group":
            g, err = get_group(P.zia, st["id"])
            if g is None:
                P.warnings.append(f"IP destination group '{st['name']}' could not be read ({err or 'gone'}): it is left as it is.")
                continue
            obj = _group_obj(g, area)
            have = {h.lower() for h in _addresses(g)}
            k = P.key("xg")
            for after, vals in ((True, st["add"]), (False, st["remove"])):
                for v in vals:
                    now = v.lower() in have
                    P.unit(k, "address", dict(obj), "addresses", now, after, value=v, status="noop" if now == after else "change",
                           reason="already as before the fix" if now == after else "",
                           explain=f"{'Put' if after else 'Take'} {v} {'back in' if after else 'out of'} the group '{obj['name']}'.")
            if any(u["group"] == k and u["status"] == "change" for u in P.items):
                groups.append({"key": k, "handler": "lf_group", "target": {"id": st["id"], "name": obj["name"], "area": area}})
        elif op == "category":
            c, err = ao.get_category(P.zia, st["id"])
            if c is None:
                P.warnings.append(f"Custom URL category '{st['name']}' could not be read ({err or 'gone'}): it is left as it is.")
                continue
            obj = _cat_obj(c)
            have = ao._url_set(c)
            k = P.key("xc")
            for after, vals in ((True, st["add"]), (False, st["remove"])):
                for v in vals:
                    now = v.lower() in have
                    P.unit(k, "cat_url", dict(obj), "urls", now, after, value=v, status="noop" if now == after else "change",
                           reason="already as before the fix" if now == after else "",
                           explain=f"{'Put' if after else 'Take'} {v} {'back in' if after else 'out of'} the category '{obj['name']}'.")
            if any(u["group"] == k and u["status"] == "change" for u in P.items):
                groups.append({"key": k, "handler": "lf_cat", "target": {"id": st["id"], "name": obj["name"]}})
        elif op == "delete_category":
            c, err = ao.get_category(P.zia, st["id"])
            obj = {"type": "url_category", "area": "url", "policy_label": "Custom URL category", "id": st["id"], "name": st["name"]}
            k = P.key("xk")
            if c is None and err and ao._read_halt(err):
                raise ao.OperationError(f"The category could not be read: {err}. Nothing was written.")
            if c is None:
                P.items.append(dict(ao._unit(k, k, "delete_category", obj, "exists", False, False, status="noop", reason="already gone"), rows=[], explain=""))
                continue
            if ao._url_set(c) != {u.lower() for u in st["urls"]} or str(ao._cat_ref(c)["name"]) != st["name"]:
                P.items.append(dict(ao._unit(k, k, "delete_category", obj, "exists", True, True, status="excluded",
                                             reason="its name or URLs changed since the fix: kept"), rows=[], explain=""))
                continue
            P.items.append(dict(ao._unit(k, k, "delete_category", obj, "exists", True, False), rows=[],
                                explain=f"Delete the custom URL category '{st['name']}' this fix created."))
            groups.append({"key": k, "handler": "lf_cat_delete", "target": {"id": st["id"], "name": st["name"], "urls": st["urls"]}})
        else:   # delete_group
            g, err = get_group(P.zia, st["id"])
            obj = {"type": "ip_group", "area": area, "policy_label": "IP destination group", "id": st["id"], "name": st["name"]}
            k = P.key("xd")
            if g is None and err and ao._read_halt(err):
                raise ao.OperationError(f"The group could not be read: {err}. Nothing was written.")
            if g is None:
                P.items.append(dict(ao._unit(k, k, "delete_group", obj, "exists", False, False, status="noop", reason="already gone"), rows=[], explain=""))
                continue
            if sorted(h.lower() for h in _addresses(g)) != sorted(h.lower() for h in st["addresses"]) or str(g.get("name")) != st["name"]:
                P.items.append(dict(ao._unit(k, k, "delete_group", obj, "exists", True, True, status="excluded",
                                             reason="its name or entries changed since the fix: kept"), rows=[], explain=""))
                continue
            P.items.append(dict(ao._unit(k, k, "delete_group", obj, "exists", True, False), rows=[],
                                explain=f"Delete the IP destination group '{st['name']}' this fix created."))
            groups.append({"key": k, "handler": "lf_group_delete", "target": {"id": st["id"], "name": st["name"], "addresses": st["addresses"]}})
    return {"type": TYPE, "product": "zia", "spec": n, "items": P.items, "groups": groups, "warnings": P.warnings, "blockers": P.blockers,
            "title": "Undo a fix from Test a list", "explanations": _explanations(P.items), "confirm_always": _typed(P.items, groups, set())}


# ---------------------------------------------------------------------------
# Writes (through pack_ops only), each after a re-read of its object
# ---------------------------------------------------------------------------

def _resolve(run, v: Any) -> Optional[str]:
    """A group reference: an id, or 'new:<key>' of a group this run created."""
    s = str(v)
    if s.startswith("new:"):
        u = run.units.get(s[4:])
        gid = (u or {}).get("object", {}).get("id")
        return str(gid) if gid not in (None, "") else None
    return s[3:] if s.startswith("id:") else s


def _conflicts(run, units: List[Dict[str, Any]], present: Callable[[Dict[str, Any]], bool], what: str) -> List[Dict[str, Any]]:
    ok = []
    for u in units:
        now = present(u)
        if now != u["before"]:
            run.mark([u], "conflict", f"changed in the tenant since the preview: {u['value']} is {'now' if now else 'no longer'} {what}; left as it is")
        else:
            ok.append(u)
    return ok


def _h_group_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    rows, err = read_groups(run.zia)
    if err:
        zb._halt_or_fail(run, units, err, "the IP destination groups")
        return
    if any(str(x.get("name") or "").strip().lower() == t["name"].lower() for x in rows):
        run.mark(units, "conflict", f"a group named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    payload = {"name": t["name"], "type": t["type"], "addresses": list(t["addresses"]),
               "description": zb._fit_bytes(f"Created by {run.assessor or 'the assessor'} with Bulk changes (Fix selected, Test a list)", DESC_MAX)}
    out = ops.create(run.zia, "ip_destination_group", payload, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": "ip_group", "area": t["area"], "id": out.id, "name": t["name"], "addresses": list(t["addresses"])})
        run.log(f"[IP destination group] {t['name']}: created with {len(t['addresses'])} entr{'y' if len(t['addresses']) == 1 else 'ies'}")


def _h_group(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_group(run.zia, t["id"])
    if fresh is None:
        zb._halt_or_fail(run, units, err or "not found", "the IP destination group")
        return
    have = _addresses(fresh)
    have_l = {h.lower() for h in have}
    ok = _conflicts(run, units, lambda u: u["value"].lower() in have_l, "in this group")
    if not ok:
        return
    adds = [u["value"] for u in ok if u["after"]]
    drop = {u["value"].lower() for u in ok if not u["after"]}
    new = [h for h in have if h.lower() not in drop] + adds
    if len(new) > MAX_GROUP_ADDRESSES:
        run.mark(ok, "failed", "", error=f"the group would hold {len(new):,} entries, over ZIA's per-group limit of {MAX_GROUP_ADDRESSES:,} "
                                         "(assumed); nothing was sent")
        run.counts["failed"] += 1
        return
    payload = {"name": fresh.get("name"), "type": fresh.get("type"), "description": fresh.get("description"), "addresses": new,
               "ip_categories": fresh.get("ip_categories"), "countries": fresh.get("countries")}
    payload = {k: v for k, v in payload.items() if v is not None}
    out = ops.update(run.zia, "ip_destination_group", t["id"], payload, name=str(fresh.get("name") or t["name"]), log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        run.log(f"[IP destination group] {t['name']}: {len(adds)} added, {len(drop)} removed")


def _h_group_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_group(run.zia, t["id"])
    if fresh is None:
        if err and ao._read_halt(err):
            zb._halt_or_fail(run, units, err, "the IP destination group")
        else:
            run.mark(units, "noop", "already gone")
        return
    if sorted(h.lower() for h in _addresses(fresh)) != sorted(h.lower() for h in t["addresses"]) or str(fresh.get("name")) != t["name"]:
        run.mark(units, "conflict", "its name or entries changed since the preview, so it is kept")
        return
    out = ops.delete(run.zia, {"kind": "ip_destination_group", "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[IP destination group] {t['name']}: deleted")


def _h_atp(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    lst = g["target"]["list"]
    have, err = read_list(run.zia, lst)
    if have is None:
        zb._halt_or_fail(run, units, err, f"the {LISTS[lst]['label']}")
        return
    have_l = {h.lower() for h in have}
    ok = _conflicts(run, units, lambda u: u["value"].lower() in have_l, f"on the {LISTS[lst]['label']}")
    if not ok:
        return
    adds = [u for u in ok if u["after"]]
    drops = [u for u in ok if not u["after"]]
    name = LISTS[lst]["label"]
    if lst == "denylist":
        for part, action in ((adds, "ADD_TO_LIST"), (drops, "REMOVE_FROM_LIST")):
            if not part or run.halt:
                continue
            out = ops.update(run.zia, "security_denylist", None, {"urls": [u["value"] for u in part]}, action=action, name=name, log=run.log)
            if run.outcome(part, out, "update"):
                run.wrote_zia = True
    else:
        drop = {u["value"].lower() for u in drops}
        new = [h for h in have if h.lower() not in drop] + [u["value"] for u in adds]
        out = ops.update(run.zia, "security_allowlist", None, {"urls": new}, name=name, log=run.log)
        if run.outcome(ok, out, "update"):
            run.wrote_zia = True
    run.log(f"[ATP] {name}: {len(adds)} added, {len(drops)} removed")


def _h_rule(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    fresh, err = zb.get_one(run.zia, area, t["id"])
    if fresh is None:
        zb._halt_or_fail(run, units, err or "not found", "the rule")
        return
    ok = []
    for u in units:
        gid = _resolve(run, u["value"])
        if gid is None:
            run.mark([u], "skipped", "not attempted: the new group it names was not created")
            continue
        u["resolved"] = gid
        now = gid in set(_ids(fresh, u["field"]))
        if now != u["before"]:
            run.mark([u], "conflict", f"changed in the tenant since the preview: the rule {'now' if now else 'no longer'} names {gid}; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    body = zb._deep_snake(ao._body(fresh))
    for field in ("dest_ip_groups", "nw_services", "url_categories"):
        mine = [u for u in ok if u["field"] == field]
        if not mine and field not in body:
            continue
        ids = _ids(fresh, field)
        drop = {u["resolved"] for u in mine if not u["after"]}
        ids = [i for i in ids if i not in drop] + [u["resolved"] for u in mine if u["after"] and u["resolved"] not in ids]
        body[field] = [_num(i) for i in ids]
    out = ops.update(run.zia, "policy", t["id"], body, channel=AREAS[area]["channel"], name=t["name"], log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        run.log(f"[{AREAS[area]['label']}] {t['name']}: {len([u for u in ok if u['after']])} reference(s) added, "
                f"{len([u for u in ok if not u['after']])} removed")


def _h_rule_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    rows, err = zb.read_area(run.zia, area)
    if err:
        zb._halt_or_fail(run, units, err, f"the {AREAS[area]['label']} rules")
        return
    if any(str(r.get("name") or "").strip().lower() == t["name"].lower() for r in rows):
        run.mark(units, "conflict", "a rule with this name appeared in the tenant since the preview; nothing was created")
        return
    body = dict(t["payload"])
    field = REF_FIELD[area]
    groups = [_resolve(run, x) for x in body.get(field) or []]
    if any(x is None for x in groups):
        run.mark(units, "skipped", f"not attempted: a new {'category' if area == 'url' else 'group'} it names was not created")
        return
    body[field] = [_num(x) for x in groups]
    if body.get("nw_services"):
        body["nw_services"] = [_num(x) for x in body["nw_services"]]
    above = next((r for r in rows if t["above"] is not None and str(r.get("id")) == str(t["above"])), None)
    body["order"] = ao._int(above.get("order"), 1) if above is not None and not ao._is_default(above) else zb._last_order(rows) + 1
    body["description"] = zb._fit_bytes(f"Created by {run.assessor or 'the assessor'} with Bulk changes (Fix selected, Test a list)", DESC_MAX)
    out = ops.create(run.zia, "policy", body, channel=AREAS[area]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": "rule", "area": area, "id": out.id, "name": t["name"]})
        run.log(f"[{AREAS[area]['label']}] {t['name']}: created at order {body['order']} ({str(body.get('state')).lower()})")


def _h_rule_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    area = t["area"]
    fresh, err = zb.get_one(run.zia, area, t["id"])
    if fresh is None:
        if err and ao._read_halt(err):
            zb._halt_or_fail(run, units, err, "the rule")
        else:
            run.mark(units, "noop", "already gone")
        return
    if str(fresh.get("name") or "") != t["name"]:
        run.mark(units, "conflict", f"renamed since the preview (now '{fresh.get('name')}'); left as it is")
        return
    out = ops.delete(run.zia, {"kind": "policy", "id": t["id"], "name": t["name"], "channel": AREAS[area]["channel"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{AREAS[area]['label']}] {t['name']}: deleted")


def _h_cat_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    cats, err = ao.read_categories(run.zia)
    if err:
        zb._halt_or_fail(run, units, err, "the custom URL categories")
        return
    if any(ao._cat_ref(c)["name"].strip().lower() == t["name"].lower() for c in cats):
        run.mark(units, "conflict", f"a category named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    payload = {"super_category": "USER_DEFINED", "configured_name": t["name"], "urls": list(t["urls"]), "custom_category": True,
               "description": zb._fit_bytes(f"Created by {run.assessor or 'the assessor'} with Bulk changes (Fix selected, Test a list)", DESC_MAX)}
    out = ops.create(run.zia, "url_category", payload, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": "url_category", "area": "url", "id": out.id, "name": t["name"], "urls": list(t["urls"])})
        run.log(f"[URL category] {t['name']}: created with {len(t['urls'])} URL(s)")


def _h_cat(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = ao.get_category(run.zia, t["id"])
    if fresh is None:
        zb._halt_or_fail(run, units, err or "not found", "the custom URL category")
        return
    have = ao._url_set(fresh)
    ok = _conflicts(run, units, lambda u: u["value"].lower() in have, "in this category")
    if not ok:
        return
    name = str(ao._cat_ref(fresh)["name"])
    for part, action in (([u for u in ok if u["after"]], "ADD_TO_LIST"), ([u for u in ok if not u["after"]], "REMOVE_FROM_LIST")):
        if not part or run.halt:
            continue
        out = ops.update(run.zia, "url_category", t["id"], {"configured_name": name, "urls": [u["value"] for u in part]}, action=action,
                         name=name, log=run.log)
        if run.outcome(part, out, "update"):
            run.wrote_zia = True
    run.log(f"[URL category] {name}: {sum(1 for u in ok if u['after'])} added, {sum(1 for u in ok if not u['after'])} removed")


def _h_cat_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = ao.get_category(run.zia, t["id"])
    if fresh is None:
        if err and ao._read_halt(err):
            zb._halt_or_fail(run, units, err, "the custom URL category")
        else:
            run.mark(units, "noop", "already gone")
        return
    if ao._url_set(fresh) != {u.lower() for u in t["urls"]} or str(ao._cat_ref(fresh)["name"]) != t["name"]:
        run.mark(units, "conflict", "its name or URLs changed since the preview, so it is kept")
        return
    out = ops.delete(run.zia, {"kind": "url_category", "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[URL category] {t['name']}: deleted")


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def _verify(run) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    cache: Dict[str, Tuple[Any, Optional[str]]] = {}
    for u in [x for x in run.p["items"] if x["status"] == "applied"]:
        o, kind = u["object"], u["kind"]
        out["checked"] += 1
        if kind in ("address", "create_group", "delete_group"):
            k = f"g:{o.get('id')}"
            if k not in cache:
                cache[k] = get_group(run.zia, o.get("id")) if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            ok = (row is None) if kind == "delete_group" else (row is not None) if kind == "create_group" else \
                row is not None and ((u["value"].lower() in {h.lower() for h in _addresses(row)}) == u["after"])
        elif kind in ("cat_url", "create_category", "delete_category"):
            k = f"c:{o.get('id')}"
            if k not in cache:
                cache[k] = ao.get_category(run.zia, o.get("id")) if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            ok = (row is None) if kind == "delete_category" else (row is not None) if kind == "create_category" else \
                row is not None and ((u["value"].lower() in ao._url_set(row)) == u["after"])
        elif kind == "list_entry":
            k = f"l:{o.get('id')}"
            if k not in cache:
                cache[k] = read_list(run.zia, o.get("id"))
            have, err = cache[k]
            ok = have is not None and ((u["value"].lower() in {h.lower() for h in have}) == u["after"])
        elif kind in ("rule_ref", "create_rule", "delete_rule"):
            k = f"r:{o.get('area')}:{o.get('id')}"
            if k not in cache:
                cache[k] = zb.get_one(run.zia, o.get("area"), o.get("id")) if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            ok = (row is None) if kind == "delete_rule" else (row is not None) if kind == "create_rule" else \
                row is not None and ((str(u.get("resolved") or u["value"]) in set(_ids(row, u["field"]))) == u["after"])
        else:
            continue
        if not ok and err and kind not in ("delete_group", "delete_rule", "delete_category"):
            out["unread"].append(f"{o.get('name')}: {err}")
            u["verified"] = None
            continue
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o.get('name')}: {u.get('value') or u['field']} is not as planned when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    created = result.get("created") or []
    new_rules = {(c["area"], str(c["id"])) for c in created if c.get("type") == "rule"}
    new_groups = {str(c["id"]) for c in created if c.get("type") == "ip_group"}
    new_cats = {str(c["id"]) for c in created if c.get("type") == "url_category"}
    cats: Dict[str, Dict[str, Any]] = {}
    steps: List[Dict[str, Any]] = []
    for c in created:
        if c.get("type") == "rule":
            steps.append({"op": "delete_rule", "area": c["area"], "id": c["id"], "name": c["name"]})
    refs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    lists: Dict[str, Dict[str, List[str]]] = {}
    grp: Dict[str, Dict[str, Any]] = {}
    for u in applied:
        o = u["object"]
        if u["kind"] == "rule_ref" and (o.get("area"), str(o.get("id"))) not in new_rules:
            s = refs.setdefault((o["area"], str(o["id"])), {"op": "rule_refs", "area": o["area"], "id": o["id"], "name": o.get("name"),
                                                            "dest_ip_groups": {"add": [], "remove": []}, "nw_services": {"add": [], "remove": []},
                                                            "url_categories": {"add": [], "remove": []}})
            s[u["field"]]["remove" if u["after"] else "add"].append(_num(u.get("resolved") or u["value"]))
        elif u["kind"] == "cat_url" and str(o.get("id")) not in new_cats:
            d = cats.setdefault(str(o["id"]), {"op": "category", "area": "url", "id": o["id"], "name": o.get("name"), "add": [], "remove": []})
            d["remove" if u["after"] else "add"].append(u["value"])
        elif u["kind"] == "list_entry":
            d = lists.setdefault(str(o["id"]), {"add": [], "remove": []})
            d["remove" if u["after"] else "add"].append(u["value"])
        elif u["kind"] == "address" and str(o.get("id")) not in new_groups:
            d = grp.setdefault(str(o["id"]), {"op": "group", "area": o.get("area") or "firewall", "id": o["id"], "name": o.get("name"),
                                              "add": [], "remove": []})
            d["remove" if u["after"] else "add"].append(u["value"])
    steps += list(refs.values())
    steps += [{"op": "atp", "area": "atp", "list": k, "add": v["add"], "remove": v["remove"]} for k, v in sorted(lists.items())]
    steps += list(grp.values())
    steps += list(cats.values())
    for c in created:
        if c.get("type") == "ip_group":
            steps.append({"op": "delete_group", "area": c.get("area") or "firewall", "id": c["id"], "name": c["name"], "addresses": c["addresses"]})
        elif c.get("type") == "url_category":
            steps.append({"op": "delete_category", "area": "url", "id": c["id"], "name": c["name"], "urls": c["urls"]})
    return {"type": TYPE, "action": "revert", "steps": steps} if steps else None


# ---------------------------------------------------------------------------
# The object picker
# ---------------------------------------------------------------------------

def _read_targets(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """What a fix can pick, read-only and only what is in scope: the IP
    destination groups, the Cloud Firewall, DNS Control and URL filtering
    rules, the custom URL categories, the network services and the size of
    the ATP lists."""
    zia = client.zia
    read, why = areas_in_scope(scope)
    out: Dict[str, Any] = {"areas": read, "not_in_scope_areas": why, "errors": {},
                           "limits": {"group_addresses": MAX_GROUP_ADDRESSES, "org_ip_entries": ORG_IP_ENTRIES, "atp_list": ATP_LIST_MAX,
                                      "rule_name": RULE_NAME_MAX, "entries": MAX_ENTRIES}}
    if "firewall" in read or "dns" in read:
        ao._check_stop(cancel)
        say("Reading the IP destination groups…")
        rows, err = read_groups(zia)
        if err:
            out["errors"]["ip_groups"] = err
        out["ip_groups"] = sorted([{"id": g.get("id"), "name": str(g.get("name") or ""), "type": _gtype(g), "count": len(_addresses(g)),
                                    "editable": not ao._truthy(g.get("is_non_editable"))} for g in rows], key=lambda g: g["name"].lower())
    for a in ("firewall", "dns", "url"):
        if a not in read:
            continue
        ao._check_stop(cancel)
        say(f"Reading the {AREAS[a]['label']} rules…")
        rows, err = zb.read_area(zia, a, cancel=cancel)
        if err:
            out["errors"][f"{a}_rules"] = err
        out[f"{a}_rules"] = [{"id": r.get("id"), "name": str(r.get("name") or ""), "order": r.get("order"), "action": r.get("action"),
                              "state": ao._state(r), "kind": _rule_kind(a, r.get("action")),
                              "locked": ao.lock_reason("url_filtering" if a == "url" else "firewall", r)}
                             for r in sorted(rows, key=ao._sort_key)]
    if "url" in read:
        ao._check_stop(cancel)
        say("Reading the custom URL categories…")
        rows, err = ao.read_categories(zia)
        if err:
            out["errors"]["url_categories"] = err
        out["url_categories"] = sorted([{"id": ao._cat_ref(c)["id"], "name": ao._cat_ref(c)["name"], "count": len(ao._urls_of(c))} for c in rows],
                                       key=lambda c: str(c["name"]).lower())
    if "firewall" in read:
        ao._check_stop(cancel)
        say("Reading the network services…")
        rows, err = read_services(zia)
        if err:
            out["errors"]["services"] = err
        out["services"] = sorted([{"id": s.get("id"), "name": str(s.get("name") or s.get("id"))} for s in rows], key=lambda s: s["name"].lower())
    if "atp" in read:
        out["atp_lists"] = {}
        for lst in LISTS:
            ao._check_stop(cancel)
            have, err = read_list(zia, lst)
            if err:
                out["errors"][lst] = err
            out["atp_lists"][lst] = {"label": LISTS[lst]["label"], "count": len(have or [])}
    say("Read.")
    return out


HANDLERS = {"lf_group_create": _h_group_create, "lf_group": _h_group, "lf_group_delete": _h_group_delete, "lf_atp": _h_atp,
            "lf_rule": _h_rule, "lf_rule_create": _h_rule_create, "lf_rule_delete": _h_rule_delete,
            "lf_cat_create": _h_cat_create, "lf_cat": _h_cat, "lf_cat_delete": _h_cat_delete}
ao.register(TYPE, family=FAMILY, product="zia", label="Fix rows from Test a list",
            hint="Turn rows of the Path analyzer's Test a list that missed what you expected into changes: IP destination groups, "
                 "Cloud Firewall and DNS Control rules, custom URL categories and URL filtering rules (new rules arrive disabled) "
                 "and the ATP allow and deny lists.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_targets, handlers=HANDLERS,
            verify=_verify, inverse=_inverse, group="Change", script="ops_list_fix.js")
ao.register(GROUP_TYPE, family=FAMILY, product="zia", label="IP destination group change",
            hint="Add or remove IPv4 addresses, CIDR blocks, ranges or host names on an IP destination group, or make a new group, "
                 "within ZIA's per-group limit.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_targets, handlers=HANDLERS,
            verify=_verify, inverse=_inverse, group="Change", script="ops_list_fix.js")
ao.register(LIST_TYPE, family=FAMILY, product="zia", label="ATP allow and deny lists",
            hint="Add or remove URLs on the security policy allowlist or denylist, which Advanced Threat Protection applies to every user.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_targets, handlers=HANDLERS,
            verify=_verify, inverse=_inverse, group="Change", script="ops_list_fix.js")
