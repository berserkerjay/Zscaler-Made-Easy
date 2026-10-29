"""Configuration exports: the ZIA locations and the Client Connector
profiles as formatted workbooks, next to the policy exports
(policy_exports), with the same export options (columns, one row per
value, the separator of several values in a cell).

Locations (`locations_export`): every location and sub-location with its
settings, the location groups, and which URL filtering, Cloud Firewall,
SSL inspection, File Type Control and Web DLP rules name each location or
location group (policy usage), directly or through a location group the
location belongs to. Fields are the ones zscaler-sdk-python models
(zia/models/location_management.py LocationManagement, VPNCredentials;
zia/models/location_group.py LocationGroup), read from the endpoints its
zia/locations.py service uses: GET /locations (page, pageSize up to 1000),
GET /locations/{id}/sublocations, GET /locations/groups. The rules'
`locations` / `locationGroups` fields are modelled on every one of those
rule types (url_filtering_rules, cloud_firewall_rules,
ssl_inspection_rules, filetyperules, dlp_web_rules). IP addresses and VPN
credentials are counted, never listed: a VPN credential can carry a
pre-shared key (zia/models/traffic_vpn_credentials.py preSharedKey), and
no field outside the fixed columns is exported, so a secret the API adds
later cannot slip in.

Client Connector (`client_connector_export`): app profiles (web
policies), forwarding profiles and PAC files, read with
data_flow.read_client_connector (the reader the Path analyzer and the
URLs export use, with keep_raw for the settings), which profiles use which
forwarding profile and which use each PAC URL. Every setting whose name
says password, passcode, secret, token, key material or OTP is left out
(app profiles carry several: zcc/models/webpolicy.py uninstallPassword,
disablePassword, exitPassword, logoutPassword, zccRevertPassword, ...);
people (users, login names) are counted, not named.

Read-only (GET only), only what the Scope page puts in scope, Stop
checked before every request.
"""
from __future__ import annotations

import io
import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import policy_exports as pe
import xlsx_writer

XLSX = xlsx_writer.MEDIA_TYPE
STOPPED_REASON = pe.STOPPED_REASON
LOCATION_PAGE_SIZE = 1000          # the SDK's documented maximum for GET /locations
MAX_LOCATION_PAGES = 50
MAX_SUBLOCATION_READS = 2000
_LOCATION_ID = re.compile(r"[0-9]{1,20}")

NOTHING_IN_SCOPE_LOCATIONS = ("Locations are ZIA platform configuration: on the Scope page tick ZIA platform, then export again. "
                              "Nothing was read.")
NOTHING_IN_SCOPE_ZCC = ("Client Connector profiles are read only when ZCC is ticked on the Scope page: tick it, then export again. "
                        "Nothing was read.")
LOCATION_PEOPLE_NOTE = ("IP addresses and VPN credentials are counted, never listed: a VPN credential can carry a pre-shared key. "
                        "Only the settings in the columns are exported.")
ZCC_SECRET_NOTE = ("Passwords, passcodes, tokens, keys and one-time passwords the profiles carry are never exported; people "
                   "(users, login names) are counted, not named.")


class Stopped(pe.Stopped):
    """The operator clicked Stop."""


# ── Secrets and people ───────────────────────────────────────────────
_SECRET_PARTS = ("password", "passcode", "passwd", "secret", "token", "nonce", "presharedkey", "credential", "rsapubkey",
                 "thumbprint", "privatekey", "apikey", "cookie")
# "pass" as a word of its own: zcc/models/manage_pass.py names the passwords
# exitPass, logoutPass, uninstallPass, ziaDisablePass, zpaDisablePass ... (a
# bypass is one word, so it stays).
_SECRET_WORDS = {"otp", "psk", "pwd", "pin", "key", "pass", "passphrase"}
_PEOPLE = {"users", "userids", "usernames", "loginname", "devices", "deviceids", "excludedusers", "auditor"}
_PEOPLE_SUFFIXES = ("username", "loginname")   # zpaAuthUsername: a person's login


def _words(key: Any) -> List[str]:
    return [w.lower() for w in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", str(key))]


def is_secret(key: Any) -> bool:
    """A setting whose name says it holds a secret (never exported)."""
    c = pe._canon(key)
    return any(p in c for p in _SECRET_PARTS) or bool(set(_words(key)) & _SECRET_WORDS)


def _is_people(key: Any) -> bool:
    c = pe._canon(key)
    return c in _PEOPLE or c.endswith(_PEOPLE_SUFFIXES)


def _label(key: Any) -> str:
    return pe.humanize(re.sub(r"(?<!^)(?=[A-Z])", "_", str(key)))


def settings_lines(raw: Dict[str, Any], skip: Iterable[str] = (), limit: int = 200) -> List[str]:
    """A profile's settings as 'Setting: value' lines, nested objects
    joined with ': ', without secrets, with people counted and without the
    fields in `skip` (shown in their own columns)."""
    skipped = {pe._canon(k) for k in skip}
    out: List[str] = []

    def walk(obj: Any, prefix: str, depth: int) -> None:
        if len(out) >= limit or depth > 4:
            return
        if not isinstance(obj, dict):
            return
        for k, v in obj.items():
            if len(out) >= limit:
                return
            if is_secret(k) or (depth == 0 and pe._canon(k) in skipped) or v in (None, "", [], {}):
                continue
            label = f"{prefix}{_label(k)}"
            if _is_people(k):
                n = len(v) if isinstance(v, (list, tuple)) else 1
                out.append(f"{label}: {n} {'person' if n == 1 else 'people'}")
            elif isinstance(v, dict):
                walk(v, f"{label}: ", depth + 1)
            elif isinstance(v, list):
                if all(isinstance(x, dict) for x in v):
                    names = [pe._ref_name(x) for x in v if isinstance(x, dict) and any(x.get(n) for n in ("name", "configuredName", "val"))]
                    if names:
                        out.append(f"{label}: " + ", ".join(names)[:300])
                    else:
                        for i, x in enumerate(v[:12], 1):
                            walk(x, f"{label} {i}: ", depth + 1)
                else:
                    out.append(f"{label}: " + ", ".join(str(x) for x in v)[:300])
            else:
                val = "Yes" if v is True else "No" if v is False else str(v)
                out.append(f"{label}: {val[:300]}")
    walk(raw or {}, "", 0)
    return out


# ── Scope ────────────────────────────────────────────────────────────
# The policies whose rules name locations: key -> (label, path_scope
# section or None for ZIA platform, endpoint, data_flow's read label).
USAGE_POLICIES: Dict[str, Tuple[str, Optional[str], str, str]] = {
    "url_filtering": ("URL filtering", "url", "/zia/urlFilteringRules", "URL filtering rules"),
    "firewall": ("Cloud Firewall", None, "/zia/firewallFilteringRules", "Cloud Firewall rules"),
    "ssl_inspection": ("SSL inspection", "ssl", "/zia/sslInspectionRules", "SSL inspection rules"),
    "file_type_control": ("File Type Control", "ftc", "/zia/fileTypeRules", "File Type Control rules"),
    "web_dlp": ("Web DLP", "dlp", "/zia/webDlpRules", "Web DLP rules"),
}


def locations_scope(scopes: Any, channels: Any) -> Dict[str, Any]:
    """{in_scope, usage: [policy keys read for policy usage], not_in_scope:
    {policy: why}, summary}. Locations need ZIA platform; each policy's
    rules are read for usage only when that policy is in scope. Pure."""
    import data_flow
    ps = data_flow.path_scope(scopes, channels)
    ok = "zia_extras" in ps["scopes"]
    usage: List[str] = []
    nis: Dict[str, str] = {}
    for key, (label, sec, _, what) in USAGE_POLICIES.items():
        if sec is None:
            if ok:
                usage.append(key)
            else:
                nis[key] = "Not in scope: ZIA platform is not ticked on the Scope page."
        elif sec in ps["read"]:
            usage.append(key)
        else:
            nis[key] = (ps.get("read_blocked") or {}).get(sec) or ps["not_in_scope"].get(sec) or f"Not in scope, so the {what} were not read."
    summary = (("In scope on the Scope page: locations and location groups (ZIA platform); policy usage from "
                + ", ".join(USAGE_POLICIES[k][0] for k in usage) + ".") if ok else NOTHING_IN_SCOPE_LOCATIONS)
    return {"in_scope": ok, "usage": usage if ok else [], "not_in_scope": nis, "summary": summary}


def zcc_scope(scopes: Any, channels: Any) -> Dict[str, Any]:
    """{in_scope, path_scope, summary}: ZCC ticked on the Scope page. Pure."""
    import data_flow
    ps = data_flow.path_scope(scopes, channels)
    ok = "zcc" in ps["read"]
    return {"in_scope": ok, "path_scope": ps,
            "summary": "In scope on the Scope page: Client Connector app profiles, forwarding profiles and PAC files (ZCC)." if ok else NOTHING_IN_SCOPE_ZCC}


# ── Reading ──────────────────────────────────────────────────────────
def _stop_point(cancel: Any) -> None:
    import data_flow
    if data_flow.stop_requested(cancel):
        raise Stopped(STOPPED_REASON)


def _items(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for k in ("list", "items", "data", "results"):
            if isinstance(data.get(k), list):
                return [x for x in data[k] if isinstance(x, dict)]
    return []


def _read_list(client, endpoint: str, *, paged: bool = False, cancel: Any = None,
               params: Optional[Dict[str, Any]] = None) -> Tuple[Optional[List[Dict[str, Any]]], str]:
    """(items, '') or (None, why). Paged: page / pageSize until a short
    page (a page that only repeats ids already read also ends it). When
    MAX_LOCATION_PAGES full pages still leave more, the items read come
    back with why naming the cut, never as the whole list."""
    out: List[Dict[str, Any]] = []
    seen: set = set()
    for page in range(1, (MAX_LOCATION_PAGES if paged else 1) + 1):
        _stop_point(cancel)
        try:
            if paged:
                data, code = client.get(endpoint, dict(params or {}, page=page, pageSize=LOCATION_PAGE_SIZE))
            else:
                data, code = client.get(endpoint, params) if params else client.get(endpoint)
        except Exception as e:  # noqa: BLE001 - the text can hold credentials
            return None, f"the read failed ({type(e).__name__})"
        if code == 204:
            return out, ""
        if code != 200:
            return None, {401: "authentication failed", 403: "permission denied (HTTP 403)", 404: "not available (HTTP 404)",
                          429: "rate limited (HTTP 429)"}.get(code, f"HTTP {code}")
        if not (isinstance(data, list) or (isinstance(data, dict) and any(isinstance(data.get(k), list) for k in ("list", "items", "data", "results")))):
            return None, "a malformed answer"
        batch = _items(data)
        fresh = [x for x in batch if x.get("id") in (None, "") or str(x.get("id")) not in seen]
        if paged and batch and not fresh:
            break   # the API repeated a page: everything was already read
        seen.update(str(x.get("id")) for x in fresh if x.get("id") not in (None, ""))
        out += fresh
        if not paged or len(batch) < LOCATION_PAGE_SIZE:
            return out, ""
    return out, (f"only the first {MAX_LOCATION_PAGES * LOCATION_PAGE_SIZE} were read ({MAX_LOCATION_PAGES} pages of "
                 f"{LOCATION_PAGE_SIZE}); the tenant has more, and the rest are not in this file")


def read_locations(client, scope: Dict[str, Any], *, log: Optional[Callable[[str], None]] = None, cancel: Any = None) -> Dict[str, Any]:
    """GET the locations (paged), the sub-locations of every location that
    has some, the location groups and the rules of the policies in scope.
    {locations, sublocations: {parent id: [..]}, groups, rules: {policy:
    [..]}, errors: {what: why}}. Raises Stopped on Stop."""
    import data_flow
    from ssl_flow import _fetch_rules
    say = log or (lambda m: None)
    out: Dict[str, Any] = {"locations": [], "sublocations": {}, "groups": None, "rules": {}, "errors": {}}
    try:
        with data_flow.stop_on(client, cancel):
            say("Reading the locations…")
            locs, why = _read_list(client, "/zia/locations", paged=True, cancel=cancel)
            if locs is None:
                out["errors"]["locations"] = why
                say(f"The locations could not be read: {why}.")
                return out
            out["locations"] = locs
            if why:
                out["errors"]["locations (incomplete)"] = why
            say(f"Locations: {len(locs)} found." + (f" Not all of them: {why}." if why else ""))
            parents = [x for x in locs if _num(x.get("childCount") if "childCount" in x else x.get("child_count")) > 0]
            if parents:
                say(f"Reading the sub-locations of {len(parents)} location{'s' if len(parents) != 1 else ''}…")
            for p in parents[:MAX_SUBLOCATION_READS]:
                pid = str(p.get("id") if p.get("id") is not None else "")
                if not _LOCATION_ID.fullmatch(pid):
                    # The id goes into the request path: a tenant answer with
                    # anything but digits there ("1/../../adminUsers") is not sent.
                    out["errors"][f"sub-locations of {p.get('name') or 'a location'}"] = "the location id is not a number, so they were not read"
                    continue
                subs, why = _read_list(client, f"/zia/locations/{pid}/sublocations", cancel=cancel)
                if subs is None:
                    out["errors"][f"sub-locations of {p.get('name') or p.get('id')}"] = why
                    continue
                out["sublocations"][str(p.get("id"))] = subs
            if len(parents) > MAX_SUBLOCATION_READS:
                out["errors"]["sub-locations"] = f"only the first {MAX_SUBLOCATION_READS} locations' sub-locations were read"
            say("Reading the location groups…")
            # fetchLocations: the SDK documents it (list_location_groups
            # query_params.fetch_locations) as returning each group's locations.
            groups, why = _read_list(client, "/zia/locations/groups", paged=True, cancel=cancel, params={"fetchLocations": "true"})
            if groups is None:
                out["errors"]["location groups"] = why
                say(f"The location groups could not be read: {why}.")
            else:
                out["groups"] = groups
                if why:
                    out["errors"]["location groups (incomplete)"] = why
                say(f"Location groups: {len(groups)} found.")
            for key in scope.get("usage") or []:
                label, _, endpoint, what = USAGE_POLICIES[key]
                say(f"Reading the {what} for policy usage…")
                _stop_point(cancel)
                diags: List[Dict[str, Any]] = []
                items = _fetch_rules(client, endpoint, diags, what)
                if diags:
                    out["errors"][what] = " ".join(str(x) for x in (diags[-1].get("error_type"), diags[-1].get("error")) if x).strip()[:200] or "the read failed"
                    say(f"{what} could not be read: {out['errors'][what]}.")
                    continue
                out["rules"][key] = items
            _stop_point(cancel)
    except (data_flow.ReadStopped,) as e:
        raise Stopped(STOPPED_REASON) from e
    except pe.Stopped:
        raise
    except Exception as e:  # noqa: BLE001
        import zia_rate
        if isinstance(e, zia_rate.Cancelled):
            raise Stopped(STOPPED_REASON) from e
        raise
    return out


def _num(v: Any) -> int:
    try:
        return int(v)
    except (TypeError, ValueError, OverflowError):
        return 0


# ── Locations workbook ───────────────────────────────────────────────
def _f(x: Dict[str, Any], *names: str) -> Any:
    """A field by its API (camelCase) or SDK (snake_case) name."""
    idx = {pe._canon(k): v for k, v in x.items()}
    for n in names:
        v = idx.get(pe._canon(n))
        if v not in (None, ""):
            return v
    return None


def _yes(v: Any) -> str:
    return "Yes" if v is True or str(v).lower() == "true" else ("No" if v is False or str(v).lower() == "false" else "")


# (header, fields, kind): yes = Yes / No, text, refs (names), count, tokens.
LOCATION_SETTINGS: List[Tuple[str, Sequence[str], str]] = [
    ("Country", ["country"], "text"), ("Time zone", ["tz"], "text"), ("Profile", ["profile"], "tokens"),
    ("IP addresses", ["ipAddresses"], "count"), ("VPN credentials", ["vpnCredentials"], "count"), ("Ports", ["ports"], "list"),
    ("Authentication required", ["authRequired"], "yes"), ("Basic authentication", ["basicAuthEnabled"], "yes"),
    ("Digest authentication", ["digestAuthEnabled"], "yes"), ("Kerberos authentication", ["kerberosAuth"], "yes"),
    ("SSL scan (legacy setting)", ["sslScanEnabled"], "yes"), ("Client Connector SSL scan", ["zappSslScanEnabled"], "yes"),
    ("Firewall enabled", ["ofwEnabled"], "yes"), ("IPS control", ["ipsControl"], "yes"), ("XFF forwarding", ["xffForwardEnabled"], "yes"),
    ("Upload bandwidth", ["upBandwidth"], "text"), ("Download bandwidth", ["dnBandwidth"], "text"),
    ("Surrogate IP", ["surrogateIP", "surrogateIp", "surrogate_ip"], "yes"),
    ("Surrogate IP for known browsers", ["surrogateIPEnforcedForKnownBrowsers", "surrogateIpEnforcedForKnownBrowsers"], "yes"),
    ("Surrogate refresh time", ["surrogateRefreshTimeInMinutes"], "minutes"), ("Idle time to disassociate", ["idleTimeInMinutes"], "minutes"),
    ("Acceptable use policy", ["aupEnabled"], "yes"), ("AUP timeout (days)", ["aupTimeoutInDays"], "text"),
    ("AUP blocks internet until accepted", ["aupBlockInternetUntilAccepted"], "yes"), ("AUP forces SSL inspection", ["aupForceSslInspection"], "yes"),
    ("Caution", ["cautionEnabled"], "yes"), ("IoT discovery", ["iotDiscoveryEnabled"], "yes"), ("IPv6", ["ipv6Enabled"], "yes"),
    ("Other sub-location", ["otherSubLocation"], "yes"), ("Cloud or Branch Connector location", ["ecLocation"], "yes"),
    ("Excluded from manual groups", ["excludeFromManualGroups"], "yes"), ("Excluded from dynamic groups", ["excludeFromDynamicGroups"], "yes"),
    ("Static location groups", ["staticLocationGroups"], "refs"), ("Dynamic location groups", ["dynamiclocationGroups", "dynamicLocationGroups"], "refs"),
    ("Sub-location scope", ["subLocScope"], "tokens"), ("Sub-location scope values", ["subLocScopeValues"], "list"),
]


def _setting(x: Dict[str, Any], fields: Sequence[str], kind: str) -> Any:
    v = _f(x, *fields)
    if kind == "yes":
        return _yes(v)
    if kind == "count":
        return len(v) if isinstance(v, list) else (0 if v in (None, "") else 1)
    if kind == "list":
        return [str(i) for i in pe._as_list(v)]
    if kind == "refs":
        return [n for n in (pe._ref_name(i) for i in pe._as_list(v)) if n]
    if kind == "tokens":
        return pe.humanize(v) if isinstance(v, str) and v.isupper() else ("" if v is None else str(v))
    if kind == "minutes":
        return "" if v in (None, "") else f"{v} minutes"
    return "" if v is None else v


def _usage(rules: Dict[str, List[Dict[str, Any]]]) -> Dict[str, Dict[str, Dict[str, List[str]]]]:
    """{"location"|"group": {id or name: {policy: [rule names in order]}}}."""
    out: Dict[str, Dict[str, Dict[str, List[str]]]] = {"location": {}, "group": {}}
    for policy, rs in rules.items():
        for r in sorted((pe.Rule(x) for x in rs if isinstance(x, dict)), key=pe._order_key):
            name = str(r.get("name") or f"Rule {r.get('id')}")
            for kind, field in (("location", "locations"), ("group", "locationGroups")):
                for ref in pe._as_list(r.get(field)):
                    keys = [str(ref.get("id"))] if isinstance(ref, dict) and ref.get("id") not in (None, "") else []
                    keys.append("name:" + (pe._ref_name(ref) if isinstance(ref, dict) else str(ref)))
                    for k in keys:
                        lst = out[kind].setdefault(k, {}).setdefault(policy, [])
                        if name not in lst:
                            lst.append(name)
    return out


def _used(table: Dict[str, Dict[str, List[str]]], obj: Dict[str, Any]) -> Dict[str, List[str]]:
    by_id = table.get(str(obj.get("id")), {}) if obj.get("id") not in (None, "") else {}
    by_name = table.get("name:" + str(obj.get("name") or ""), {})
    merged: Dict[str, List[str]] = {}
    for src in (by_id, by_name):
        for p, names in src.items():
            lst = merged.setdefault(p, [])
            lst += [n for n in names if n not in lst]
    return merged


def location_headers(usage: Sequence[str]) -> List[str]:
    return (["Name", "Type", "Parent location", "Description"] + [h for h, _, _ in LOCATION_SETTINGS]
            + [f"{USAGE_POLICIES[k][0]} rules" for k in usage] + ["Through location groups", "Rules using it"])


def group_headers(usage: Sequence[str]) -> List[str]:
    return (["Name", "Group type", "Predefined", "Locations", "Location count", "Dynamic criteria", "Comments", "Last modified"]
            + [f"{USAGE_POLICIES[k][0]} rules" for k in usage] + ["Rules using it"])


USAGE_HEADERS = ["Object", "Object type", "Policy", "Rule", "How"]


def location_rows(got: Dict[str, Any], usage: Sequence[str]) -> Tuple[List[List[Any]], List[List[Any]], List[List[Any]]]:
    """(location rows, location group rows, usage rows)."""
    use = _usage(got.get("rules") or {})
    groups = [g for g in got.get("groups") or [] if isinstance(g, dict)]
    # Static membership from each group's own list; a location's own
    # staticLocationGroups (the SDK models both) completes it.
    member_of: Dict[str, List[Dict[str, Any]]] = {}
    for g in groups:
        for loc in pe._as_list(g.get("locations")):
            if isinstance(loc, dict):
                for k in (str(loc.get("id")), "name:" + str(loc.get("name") or "")):
                    member_of.setdefault(k, []).append(g)
    g_by_id = {str(g.get("id")): g for g in groups}
    loc_rows: List[List[Any]] = []
    usage_rows: List[List[Any]] = []

    def one(x: Dict[str, Any], parent: Optional[Dict[str, Any]]) -> None:
        name = str(x.get("name") or f"Location {x.get('id')}")
        direct = _used(use["location"], x)
        mine = list(member_of.get(str(x.get("id")), [])) + member_of.get("name:" + name, [])
        for ref in pe._as_list(_f(x, "staticLocationGroups")):
            g = g_by_id.get(str(ref.get("id"))) if isinstance(ref, dict) else None
            mine.append(g or (ref if isinstance(ref, dict) else {"name": str(ref)}))
        seen, via = set(), []
        for g in mine:
            gk = str(g.get("id") or g.get("name"))
            if gk in seen:
                continue
            seen.add(gk)
            for p, names in _used(use["group"], g).items():
                for n in names:
                    via.append(f"{USAGE_POLICIES[p][0]}: {n} (via {g.get('name') or g.get('id')})")
                    usage_rows.append([name, "Sub-location" if parent else "Location", USAGE_POLICIES[p][0], n, f"Through location group {g.get('name') or g.get('id')}"])
        for p, names in direct.items():
            for n in names:
                usage_rows.append([name, "Sub-location" if parent else "Location", USAGE_POLICIES[p][0], n, "Named in the rule"])
        total = sum(len(v) for v in direct.values()) + len(via)
        loc_rows.append([name, "Sub-location" if parent else "Location", (parent or {}).get("name") or "", x.get("description") or ""]
                        + [_setting(x, f, k) for _, f, k in LOCATION_SETTINGS]
                        + [direct.get(k, []) for k in usage] + [via, total])

    for x in sorted((x for x in got.get("locations") or [] if isinstance(x, dict)), key=lambda x: str(x.get("name") or "").lower()):
        one(x, None)
        for s in sorted(got.get("sublocations", {}).get(str(x.get("id")), []), key=lambda s: str(s.get("name") or "").lower()):
            if isinstance(s, dict):
                one(s, x)
    g_rows: List[List[Any]] = []
    for g in sorted(groups, key=lambda g: str(g.get("name") or "").lower()):
        locs = [pe._ref_name(loc) for loc in pe._as_list(g.get("locations")) if pe._ref_name(loc)]
        crit = _f(g, "dynamicLocationGroupCriteria")
        direct = _used(use["group"], g)
        for p, names in direct.items():
            for n in names:
                usage_rows.append([str(g.get("name") or g.get("id")), "Location group", USAGE_POLICIES[p][0], n, "Named in the rule"])
        g_rows.append([g.get("name"), pe.humanize(_f(g, "groupType")), _yes(_f(g, "predefined")) or "No", locs, len(locs),
                       pe._sub_lines(crit) if isinstance(crit, dict) else [], _f(g, "comments") or "", pe._when(_f(g, "lastModTime"))]
                      + [direct.get(k, []) for k in usage] + [sum(len(v) for v in direct.values())])
    return loc_rows, g_rows, usage_rows


def locations_workbook(got: Dict[str, Any], scope: Dict[str, Any], *, tenant_label: str = "", opts: Optional[Dict[str, Any]] = None) -> bytes:
    usage = [k for k in scope.get("usage") or [] if k in (got.get("rules") or {})]
    loc_rows, g_rows, u_rows = location_rows(got, usage)
    wb = xlsx_writer.Workbook(title=f"Locations {tenant_label}".strip(), subject="ZIA locations, location groups and the rules that use them")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    subs = sum(len(v) for v in (got.get("sublocations") or {}).values())
    s.extend([["Tenant", tenant_label or "Not named"], ["Exported", pe._now().strftime("%Y-%m-%d %H:%M UTC")],
              ["Locations", len(got.get("locations") or [])], ["Sub-locations", subs],
              ["Location groups", len(got.get("groups") or []) if got.get("groups") is not None else "Not read"],
              ["Policy usage read from", ", ".join(USAGE_POLICIES[k][0] for k in usage) or "No policy (none in scope or readable)"]])
    for k, why in sorted((scope.get("not_in_scope") or {}).items()):
        s.append([f"Not in scope: {USAGE_POLICIES[k][0]}", why])
    for what, why in sorted((got.get("errors") or {}).items()):
        s.append([f"Could not be read: {what}", why])
    s.extend([["Dynamic location groups", "A rule naming a dynamic location group reaches every location its criteria match; "
                                          "membership is shown only where the tenant lists it."],
              ["Bandwidth", "Upload and download bandwidth as the API returns them (the ZIA API reference gives Kbps)."],
              ["Export options", pe.options_text(opts)], ["Scope", scope.get("summary", "")],
              ["How it was read", pe.READ_NOTE], ["Secrets", LOCATION_PEOPLE_NOTE]])
    if not loc_rows:
        loc_rows = [["The tenant has no location." if not (got.get("errors") or {}).get("locations") else "The locations could not be read."]
                    + [""] * (len(location_headers(usage)) - 1)]
    pe._sheet(wb, "Locations", location_headers(usage), loc_rows, opts, "locations")
    if got.get("groups") is not None:
        pe._sheet(wb, "Location groups", group_headers(usage), g_rows or [["The tenant has no location group."] + [""] * (len(group_headers(usage)) - 1)],
                  opts, "location_groups")
    pe._sheet(wb, "Policy usage", USAGE_HEADERS, u_rows or [["No rule read names a location or a location group.", "", "", "", ""]], opts)
    return wb.to_bytes()


def locations_export(client, scope: Dict[str, Any], *, tenant_label: str = "", log: Optional[Callable[[str], None]] = None,
                     cancel: Any = None, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read and build the locations workbook. {status, counts, errors,
    artifact, filename}. Raises Stopped on Stop."""
    say = log or (lambda m: None)
    got = read_locations(client, scope, log=say, cancel=cancel)
    if got["errors"].get("locations"):
        return {"status": "error", "error": f"The locations could not be read ({got['errors']['locations']}), so no file was made.",
                "errors": got["errors"]}
    _stop_point(cancel)
    data = locations_workbook(got, scope, tenant_label=tenant_label, opts=opts)
    name = f"locations_{pe.safe_part(tenant_label)}_{pe._now().strftime('%Y%m%d')}.xlsx"
    say(f"Ready: {name}.")
    return {"status": "ready", "filename": name, "artifact": (name, XLSX, data), "errors": got["errors"],
            "counts": {"locations": len(got["locations"]), "sublocations": sum(len(v) for v in got["sublocations"].values()),
                       "groups": len(got["groups"] or []), "usage": [USAGE_POLICIES[k][0] for k in got["rules"]]},
            "not_in_scope": {USAGE_POLICIES[k][0]: v for k, v in (scope.get("not_in_scope") or {}).items()}}


# ── Client Connector workbook ────────────────────────────────────────
APP_HEADERS = ["Name", "Platform", "Active", "Rule order", "Forwarding profile", "PAC URL", "Strict enforcement", "Endpoint DLP",
               "Installs the SSL certificate", "Groups", "Bypassed domains", "Bypassed applications", "Bypassed processes",
               "Bypassed IP ranges", "VPN gateways", "Settings"]
FWD_HEADERS = ["Name", "Used by app profiles", "On trusted network", "Off trusted network", "VPN trusted network", "Every network",
               "PAC URLs", "Trusted networks", "Settings"]
PAC_HEADERS = ["Name", "PAC URL", "Used by app profiles", "Used by forwarding profiles", "Hosts sent DIRECT", "Host count"]
_APP_SHOWN = ("id", "name", "policyName", "deviceType", "active", "ruleOrder", "forwardingProfileId", "pacUrl", "customPacUrl",
              "groups", "groupNames", "groupIds", "onNetPolicy", "policyExtension", "description", "lastModification", "lastModifiedBy",
              "windowsPolicy", "macPolicy", "linuxPolicy", "iosPolicy", "androidPolicy", "companyId")
_FWD_SHOWN = ("id", "name", "trustedNetworks", "trustedNetworkNames", "trustedNetworkIds", "pacUrl", "customPacUrl",
              "forwardingProfileActions", "unifiedTunnel", "forwardingProfileZpaActions", "lastModifiedBy", "lastModification")
_NETWORKS = (("on", "On trusted network"), ("off", "Off trusted network"), ("vpn", "VPN trusted network"), ("any", "Every network"))
_PLATFORM = {"windows": "Windows", "macos": "macOS", "linux": "Linux", "ios": "iOS", "android": "Android", "all": "All"}


def _url_key(u: Any) -> str:
    return str(u or "").strip().rstrip("/").lower()


def client_connector_rows(zcc: Dict[str, Any]) -> Dict[str, List[List[Any]]]:
    """{"app": rows, "fwd": rows, "pac": rows, "usage": rows}."""
    fwds = zcc.get("forwarding_profiles") or []
    fwd_by_key = {}
    for f in fwds:
        fwd_by_key[str(f.get("id"))] = f
        fwd_by_key["name:" + str(f.get("name"))] = f

    def fwd_of(a: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        v = a.get("forwarding_profile")
        if v in (None, "", 0, "0"):
            return None
        return fwd_by_key.get(str(v)) or fwd_by_key.get("name:" + str(v))

    apps = sorted(zcc.get("app_profiles") or [], key=lambda a: (str(a.get("platform")), _num(a.get("priority")) or 10 ** 6, str(a.get("name")).lower()))
    app_rows, usage = [], []
    users_of: Dict[str, List[str]] = {}
    pac_apps: Dict[str, List[str]] = {}
    for a in apps:
        f = fwd_of(a)
        label = f"{a.get('name')} ({_PLATFORM.get(str(a.get('platform')), a.get('platform'))})"
        if f is not None:
            users_of.setdefault(str(f.get("id")), []).append(label)
        if a.get("pac_url"):
            pac_apps.setdefault(_url_key(a["pac_url"]), []).append(label)
        b = a.get("bypass") or {}
        fwd_text = (f.get("name") if f else (f"forwarding profile {a.get('forwarding_profile')} (not listed)" if a.get("forwarding_profile") not in (None, "", 0, "0") else ""))
        app_rows.append([a.get("name"), _PLATFORM.get(str(a.get("platform")), a.get("platform")), "Yes" if a.get("active") else "No",
                         a.get("priority") if a.get("priority") is not None else "", fwd_text or "", a.get("pac_url") or "",
                         "Yes" if a.get("strict_enforcement") else "", "Yes" if a.get("endpoint_dlp") else "", "Yes" if a.get("ssl_cert") else "",
                         list(a.get("groups") or []), list(b.get("domains") or []), list(b.get("apps") or []), list(b.get("processes") or []),
                         list(b.get("ips") or []), list(b.get("vpn_gateways") or []), settings_lines(a.get("raw") or {}, _APP_SHOWN)])
        if fwd_text:
            usage.append([label, "App profile", "Forwarding profile", fwd_text])
        if a.get("pac_url"):
            usage.append([label, "App profile", "PAC URL", a["pac_url"]])
    fwd_rows = []
    pac_fwds: Dict[str, List[str]] = {}
    for f in sorted(fwds, key=lambda f: str(f.get("name")).lower()):
        acts = f.get("actions") or {}
        pacs = sorted({str(x) for x in [f.get("pac_url")] + [a.get("pac_url") for a in acts.values()] if x})
        for u in pacs:
            pac_fwds.setdefault(_url_key(u), []).append(str(f.get("name")))
            usage.append([str(f.get("name")), "Forwarding profile", "PAC URL", u])
        fwd_rows.append([f.get("name"), users_of.get(str(f.get("id")), [])]
                        + [((acts.get(k) or {}).get("mode_label") or "") for k, _ in _NETWORKS]
                        + [pacs, list(f.get("trusted_networks") or []), settings_lines(f.get("raw") or {}, _FWD_SHOWN)])
    pac_rows = []
    for p in sorted(zcc.get("pac_files") or [], key=lambda p: str(p.get("name")).lower()):
        k = _url_key(p.get("url"))
        hosts = list(p.get("direct_hosts") or [])
        pac_rows.append([p.get("name"), p.get("url") or "", pac_apps.get(k, []) if k else [], pac_fwds.get(k, []) if k else [], hosts, len(hosts)])
    return {"app": app_rows, "fwd": fwd_rows, "pac": pac_rows, "usage": usage}


def client_connector_workbook(zcc: Dict[str, Any], scope: Dict[str, Any], *, tenant_label: str = "", opts: Optional[Dict[str, Any]] = None) -> bytes:
    r = client_connector_rows(zcc)
    wb = xlsx_writer.Workbook(title=f"Client Connector profiles {tenant_label}".strip(), subject="App profiles, forwarding profiles and PAC files")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([["Tenant", tenant_label or "Not named"], ["Exported", pe._now().strftime("%Y-%m-%d %H:%M UTC")],
              ["App profiles", len(r["app"])], ["Forwarding profiles", len(r["fwd"])], ["PAC files", len(r["pac"])]])
    for e in zcc.get("errors") or []:
        s.append(["Could not be read", str(e)[:300]])
    for k, why in sorted((zcc.get("not_in_scope") or {}).items()):
        s.append([f"Not in scope: {k}", why])
    s.extend([["PAC usage", "A PAC file is used by a profile whose PAC URL is the file's URL (compared without case or a trailing slash)."],
              ["Export options", pe.options_text(opts)], ["Scope", scope.get("summary", "")],
              ["How it was read", pe.READ_NOTE], ["Secrets and people", ZCC_SECRET_NOTE]])
    pe._sheet(wb, "App profiles", APP_HEADERS, r["app"] or [["No app profile was read."] + [""] * (len(APP_HEADERS) - 1)], opts, "app_profiles")
    pe._sheet(wb, "Forwarding profiles", FWD_HEADERS, r["fwd"] or [["No forwarding profile was read."] + [""] * (len(FWD_HEADERS) - 1)], opts, "forwarding_profiles")
    pe._sheet(wb, "PAC files", PAC_HEADERS, r["pac"] or [["No PAC file was read (none, or PAC files are out of scope)."] + [""] * (len(PAC_HEADERS) - 1)],
              opts, "pac_files")
    pe._sheet(wb, "Profile usage", ["Profile", "Profile type", "Uses", "Name or URL"],
              r["usage"] or [["No profile names a forwarding profile or a PAC URL.", "", "", ""]], opts)
    return wb.to_bytes()


def client_connector_export(client, scope: Dict[str, Any], *, tenant_label: str = "", log: Optional[Callable[[str], None]] = None,
                            cancel: Any = None, opts: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Read (data_flow.read_client_connector) and build the workbook."""
    import data_flow
    say = log or (lambda m: None)
    say("Reading the Client Connector app profiles, forwarding profiles and PAC files…")
    try:
        zcc = data_flow.read_client_connector(client, scope=scope["path_scope"], cancel=cancel, keep_raw=True)
    except data_flow.ReadStopped as e:
        raise Stopped(STOPPED_REASON) from e
    _stop_point(cancel)
    status = zcc.get("read_status") or {}
    if status.get("app_profiles") != "read" and status.get("forwarding_profiles") != "read" and not zcc.get("app_profiles") and not zcc.get("forwarding_profiles"):
        return {"status": "error", "error": "Neither the app profiles nor the forwarding profiles could be read, so no file was made: "
                + "; ".join(str(e)[:200] for e in zcc.get("errors") or []) , "errors": zcc.get("errors") or []}
    say(f"App profiles: {len(zcc['app_profiles'])}; forwarding profiles: {len(zcc['forwarding_profiles'])}; PAC files: {len(zcc['pac_files'])}.")
    data = client_connector_workbook(zcc, scope, tenant_label=tenant_label, opts=opts)
    name = f"client_connector_profiles_{pe.safe_part(tenant_label)}_{pe._now().strftime('%Y%m%d')}.xlsx"
    say(f"Ready: {name}.")
    return {"status": "ready", "filename": name, "artifact": (name, XLSX, data), "errors": [str(e)[:200] for e in zcc.get("errors") or []],
            "counts": {"app_profiles": len(zcc["app_profiles"]), "forwarding_profiles": len(zcc["forwarding_profiles"]), "pac_files": len(zcc["pac_files"])}}


def column_catalogue() -> Dict[str, List[str]]:
    """The configuration exports' main sheets and their columns (every
    policy-usage column included), for the column picker."""
    every = list(USAGE_POLICIES)
    return {"locations": location_headers(every), "location_groups": group_headers(every), "app_profiles": list(APP_HEADERS),
            "forwarding_profiles": list(FWD_HEADERS), "pac_files": list(PAC_HEADERS)}
