"""Data Flow Map: the path the tenant's configuration gives web traffic.

For a destination (a cloud application, a URL category or a hostname) and
a device context (platform, on or off a trusted network), the tracer walks
the data security hops of the tenant's configuration, for any user (rules
scoped to users, groups or locations make a hop conditional, never
decide it), and says what happens at each one, using the same objects the
portal uses:

  device ─ Client Connector app profile (bypasses, Endpoint DLP, cert)
         ─ forwarding profile for that network (tunnel / PAC / none)
         ─ PAC file (evaluated by pac_eval, never run)
         ─ Cloud App Control (per-action controls for the app)
         ─ URL filtering (allow / block / caution / isolate)
         ─ ZIA SSL inspection (decrypt / leave encrypted / block)
         ─ File Type Control (upload of bulk formats)
         ─ Inline Web DLP (which rules are configured to see the content,
           monitor or enforce)
         ─ Logs & incidents (which rules name an incident receiver or an
           ICAP server; delivery is not verified)

and, beside it, an inventory of the channels that do not ride the tunnel
(rules counted, nothing tested): Endpoint DLP on the device, SaaS
Security API at rest, Outbound Email DLP. Browser Control, Malware
Protection, Advanced Threat Protection, the Cloud Firewall and DNS Control
are not read here (the Path analyzer reads the ZIA modules). It is the
configuration's answer: no transaction is observed.

Every hop carries the rule that decided it and, when it weakens the
policy set, a weak point with a severity and a fix. Policy packs are
overlaid: for each pack, which of its rules sit on the path and whether
they are enforcing, monitoring, disabled or missing.

Read-only. The schema of Client Connector profiles varies by tenant and
version, so the profile readers are keyword based (like bypass_report)
and the raw value is kept next to every interpretation.
"""
from __future__ import annotations

import md_safe
import pac_eval
import contextlib
import fnmatch
import ipaddress
import json
import re
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

from bypass_report import _fetch_url_category_lookup, _rules_to_list
from zcc_profiles import read_profiles, read_app_profiles
from zcc_evaluation import flatten_profile, _v, _truthy
import zia_path_modules as _zpm
from zia_path_modules import SECTIONS as _ZIA_MODULE_SECTIONS, unevaluated as _unevaluated
from path_whatif import scope_items
from ssl_flow import (TRAFFIC_CLASSES, _fetch_app_catalogue, _fetch_rules, _matches, _names, _scope, _sort_key,
                      _upper, normalize_dlp_rule, normalize_ssl_rule)

# ── Contexts ──────────────────────────────────────────────────────────
NETWORKS = [
    {"key": "off", "label": "Off network (remote)", "what": "Not on a trusted network and no VPN: the forwarding profile's off-trusted-network action applies."},
    {"key": "on", "label": "On trusted network (office)", "what": "The device sees a trusted network: the on-trusted-network action applies (often tunnel, sometimes none with a GRE/IPsec site tunnel)."},
    {"key": "vpn", "label": "On VPN", "what": "A VPN trusted network is detected: the VPN action applies."},
]
PLATFORMS = ["windows", "macos", "ios", "android", "linux"]

DECRYPT_ACTIONS = {"DECRYPT"}
NO_DECRYPT_ACTIONS = {"DO_NOT_DECRYPT", "DO_NOT_INSPECT", "BYPASS"}
BLOCK_ACTIONS = {"BLOCK", "BLOCK_RESET", "DROP"}

UPLOAD_VERBS = ("UPLOAD", "SHARE", "SEND", "ATTACHMENT_SEND", "POST", "EDIT", "CREATE")


# ── What is in scope ──────────────────────────────────────────────────
# The app never reads the tenant implicitly, and reads only what the Scope
# page puts in scope: the ticked scopes (dlp, zia_extras, zcc, ...) and the
# channels marked Zscaler. Each part of the tenant the path is traced
# through, with the scopes that put it in scope (any one of them) and the
# Scope page channel that must be on Zscaler for it (None: the scope is
# enough). A part out of scope is not read, and its hop says "not in
# scope" — never "no rule", never "could not read".
PATH_SECTIONS: Dict[str, Tuple[str, Tuple[str, ...], Optional[str]]] = {
    "zcc": ("Client Connector app and forwarding profiles", ("zcc",), None),
    "pac": ("PAC files", ("zcc",), None),
    # Advanced Threat Protection, Cloud Firewall, DNS Control and Sandbox
    # (zia_path_modules.SECTIONS): read by the Path analyzer when ZIA
    # platform is ticked; they are ZIA platform controls, not DLP channels.
    **_ZIA_MODULE_SECTIONS,
    "cac": ("Cloud App Control rules", ("dlp", "zia_extras"), "cloud_app_control"),
    "url": ("URL filtering rules", ("dlp", "zia_extras"), None),
    "ssl": ("SSL inspection rules", ("dlp", "zia_extras"), "ssl_inspection"),
    "ftc": ("File Type Control rules", ("dlp", "zia_extras"), None),
    "dlp": ("Web DLP rules", ("dlp",), "web_dlp"),
    "endpoint": ("Endpoint DLP rules", ("dlp",), "endpoint_dlp"),
    "saas": ("SaaS Security API DLP rules", ("dlp",), "saas_casb"),
    "email": ("Outbound Email DLP rules", ("dlp",), "email_dlp"),
}
# The ZIA policy sections that place the destination: the URL categories
# list and ZIA's URL lookup are read only when one of them is in scope.
_PLACING = ("cac", "url", "ssl", "ftc", "dlp")
SCOPE_KEYS = ("dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac", "insights", "aiguard", "ztw")
SCOPE_LABELS = {"dlp": "DLP", "zia_extras": "ZIA platform", "zpa": "ZPA", "zcc": "ZCC", "genai": "GenAI & prompts",
                "automation": "Automation readiness", "zdx": "ZDX", "zidentity": "ZIdentity", "rbac": "RBAC",
                "insights": "ZIA Insights (traffic data)", "aiguard": "AI Guard",
                "ztw": "Cloud & Branch Connector"}
NOTHING_IN_SCOPE = ("Nothing the Path analyzer reads is in scope — on the Scope page tick ZCC, DLP or ZIA platform "
                    "and mark the channels you run on Zscaler, then analyze again.")
MAP_NOTHING_IN_SCOPE = ("Nothing the Data Flow Map reads is in scope — on the Scope page tick ZCC, DLP or ZIA platform "
                        "and mark the channels you run on Zscaler, then run the map again.")


def path_scope(scopes: Any, channels: Any) -> Dict[str, Any]:
    """What the Path analyzer may read for the Scope page's selection:
    `scopes` (the ticked scope keys) and `channels` (the channel
    declaration, {id: choice or {choice, note, name}}). A channel counts
    when marked Zscaler or added as an assessment prerequisite. Explicit
    alternative-vendor declarations remain excluded, and service scopes
    always gate reads even for prerequisites. Returns {scopes,
    channels, read: [section keys], not_in_scope: {key: why}, lookup,
    key, summary}. `key` names what is read, so a cached read is reused
    only for the same scope. Pure: never reads a tenant."""
    import channel_scope
    given = {str(s).strip() for s in scopes} if isinstance(scopes, (list, tuple, set)) else set()
    sc = [k for k in SCOPE_KEYS if k in given]
    import dlp_analysis
    ch = dlp_analysis.channels(channels, sc)
    required = dlp_analysis.requirements(sc, channels)
    required_by_key = {r["key"]: r for r in required}
    blocked: Dict[str, str] = {}
    read: List[str] = []
    out: Dict[str, str] = {}
    for key, (what, need, cid) in PATH_SECTIONS.items():
        if not any(s in sc for s in need):
            names = " or ".join(SCOPE_LABELS[s] for s in need)
            out[key] = f"Not in scope: {names} is not ticked on the Scope page, so the {what} were not read."
            continue
        if cid:
            decl = ch.get(cid) or {}
            name = decl.get("name") or channel_scope.CHANNELS.get(cid, cid)
            if decl.get("choice") == "alternative":
                note = f" ({decl['note']})" if decl.get("note") else ""
                if key in required_by_key:
                    blocked[key] = required_by_key[key]["detail"]
                else:
                    out[key] = f"Not in scope: {name} is covered by an alternative solution{note}, as declared on the Scope page, so the {what} were not read."
                continue
            if decl.get("choice") != "zscaler":
                out[key] = f"Not in scope: {name} is not marked Zscaler on the Scope page, so the {what} were not read."
                continue
        read.append(key)
    lookup = any(k in read for k in _PLACING)
    if read:
        summary = ("Reads only what is in scope on the Scope page: " + ", ".join(PATH_SECTIONS[k][0] for k in read)
                   + (", the URL categories and ZIA's URL lookup" if lookup else "") + ".")
    else:
        summary = NOTHING_IN_SCOPE
    return {"scopes": sc, "channels": {k: v["choice"] for k, v in ch.items()}, "read": read, "not_in_scope": out,
            "lookup": lookup, "key": ",".join(sorted(read)) + ("|required-dlp-v1:" + dlp_analysis.scope_key(sc, channels) if required else ""), "summary": summary,
            "declaration": channels, "read_blocked": blocked, "required_controls": required}


def full_path_scope() -> Dict[str, Any]:
    """Every part in scope (a caller that declared every channel on
    Zscaler and ticked every scope the path reads): for tests and tools."""
    return path_scope(**{k: v for k, v in full_path_scope_request().items() if k != "from_page"})


def full_path_scope_request() -> Dict[str, Any]:
    """The Scope page selection (a request body's scopes, channels and
    from_page) that puts every part the path reads in scope."""
    return {"scopes": ["dlp", "zia_extras", "zcc"], "channels": {cid: "zscaler" for _, _, cid in PATH_SECTIONS.values() if cid},
            "from_page": True}


# ── Stop ──────────────────────────────────────────────────────────────
class ReadStopped(RuntimeError):
    """The operator clicked Stop: the read ended between two requests and
    nothing more is sent."""


def stop_requested(cancel: Any) -> bool:
    """True once `cancel` (a threading.Event, or a callable answering
    whether to stop) says so."""
    if cancel is None:
        return False
    is_set = getattr(cancel, "is_set", None)
    try:
        return bool(is_set() if callable(is_set) else cancel())
    except Exception:  # noqa: BLE001 — a broken cancel hook never stops a read by itself
        return False


def _stop_point(cancel: Any) -> None:
    if stop_requested(cancel):
        raise ReadStopped("stopped before the read finished")


@contextlib.contextmanager
def stop_on(client: Any, cancel: Any) -> Iterator[None]:
    """While inside, `cancel` also stops what happens inside one request:
    the client (its `stop_check`, honoured by the assessment Client between
    paged calls, in its 429 pauses and retries) and ZIA's rate-limit pacing
    on this thread (zia_rate.stopping_on) send nothing more once it is
    set. None changes nothing."""
    if cancel is None:
        yield
        return
    import zia_rate

    def should_stop() -> bool:
        return stop_requested(cancel)

    bound, before = False, None
    try:
        before = getattr(client, "stop_check", None)
        client.stop_check = should_stop
        bound = True
    except Exception:  # noqa: BLE001 — a client that takes no hook is still stopped between steps
        pass
    try:
        with zia_rate.stopping_on(should_stop):
            yield
    finally:
        if bound:
            try:
                client.stop_check = before
            except Exception:  # noqa: BLE001
                pass


# ── Client Connector readers ──────────────────────────────────────────
_LOCAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16",
                                                 "100.64.0.0/10", "fc00::/7", "fe80::/10", "::1/128")]


def _family(entry: str) -> Optional[int]:
    p = _zpm._parse_entry(str(entry).strip())
    return None if p is None else p[1].version


def _non_public(entry: str) -> bool:
    """Whether an IP bypass entry lies wholly in private, loopback,
    link-local or shared address space, where a public host name never
    resolves (the assumption pac_eval's "assume_public" states too)."""
    try:
        if "-" in entry:
            ends = [ipaddress.ip_network(x.strip()) for x in entry.split("-", 1)]
        else:
            ends = [ipaddress.ip_network(entry, strict=False)]
        return all(any(e.version == n.version and e.subnet_of(n) for n in _LOCAL_NETS) for e in ends)
    except (ValueError, TypeError):
        return False


def _rule_order(v: Any) -> Optional[int]:
    """An app profile's ruleOrder as a number ("1" and 1 alike); one that is
    not a whole number has no order (it sorts last), never a TypeError."""
    if isinstance(v, bool):
        return None
    try:
        return int(str(v).strip())
    except (TypeError, ValueError):
        return None


def _hostname_of(dest: str) -> str:
    d = (dest or "").strip().lower()
    d = re.sub(r"^[a-z]+://", "", d)
    return d.split("/")[0].split(":")[0]


def _domain_hit(patterns: Iterable[str], host: str) -> Optional[str]:
    if not host:
        return None
    for p in patterns:
        pat = str(p or "").strip().lower()
        if not pat:
            continue
        pat_host = _zpm.entry_host(_hostname_of(pat))   # an IDN entry in punycode, as the host is
        if fnmatch.fnmatch(host, pat_host) or host == pat_host.lstrip("*.") or host.endswith("." + pat_host.lstrip("*.")):
            return str(p)
    return None


_MODE_RULES = [
    (re.compile(r"tunnel.*2|z ?tunnel ?2|packet|ztunnel2|tunnel2", re.I), "Z-Tunnel 2.0", "tunnel"),
    (re.compile(r"local ?proxy|twlp|tunnel.*proxy", re.I), "Tunnel with local proxy", "tunnel"),
    (re.compile(r"tunnel.*1|ztunnel1|tunnel1|^tunnel$", re.I), "Z-Tunnel 1.0", "tunnel"),
    (re.compile(r"enforce.*proxy|proxy.*enforce|\bpac\b", re.I), "Enforce proxy (PAC)", "pac"),
    (re.compile(r"^none$|^off$|disable|no ?forward|direct", re.I), "None (direct)", "none"),
]
# Numeric codes seen in the Client Connector portal API.
_MODE_CODES = {"0": ("None (direct)", "none"), "1": ("Z-Tunnel 1.0", "tunnel"), "2": ("Enforce proxy (PAC)", "pac"),
               "3": ("Tunnel with local proxy", "tunnel"), "4": ("Z-Tunnel 2.0", "tunnel")}


def classify_mode(raw: Any) -> Tuple[str, str]:
    """('Z-Tunnel 2.0', 'tunnel') from whatever the profile says."""
    s = str(raw if raw is not None else "").strip()
    if s in _MODE_CODES:
        return _MODE_CODES[s]
    for rx, label, kind in _MODE_RULES:
        if rx.search(s):
            return label, kind
    return (f"unknown ({s})" if s else "not set"), "unknown"


_NET_RULES = [(re.compile(r"vpn", re.I), "vpn"), (re.compile(r"off|untrust|not ?trust", re.I), "off"), (re.compile(r"on|trust", re.I), "on")]
_NET_CODES = {"0": "off", "1": "on", "2": "vpn"}


def classify_network(raw: Any) -> str:
    s = str(raw if raw is not None else "").strip()
    if s in _NET_CODES:
        return _NET_CODES[s]
    for rx, key in _NET_RULES:
        if rx.search(s):
            return key
    return "any"


def forwarding_actions(profile: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    """{network key: {mode_label, mode_kind, raw}} from a forwarding
    profile, reading any list of dicts that pairs a network type with a
    tunnel/action/proxy setting. A profile with a single top-level mode
    applies it to every network."""
    out: Dict[str, Dict[str, Any]] = {}
    for k, v in profile.items():
        unified = _truthy(_v(profile, "enableUnifiedTunnel"))
        if re.sub(r"[^a-z]", "", k.lower()) == "unifiedtunnel" and not unified:
            continue
        if re.sub(r"[^a-z]", "", k.lower()) == "forwardingprofileactions" and unified:
            continue
        # The ZPA action list (forwardingProfileZpaActions) describes the
        # private-access tunnel, not how web traffic reaches ZIA: skip it.
        if isinstance(v, list) and v and all(isinstance(x, dict) for x in v) and re.search(r"action|forward|network|tunnel", str(k), re.I) and not re.search(r"zpa", str(k), re.I):
            for entry in v:
                net_raw = next((entry[kk] for kk in entry if re.search(r"network", str(kk), re.I)), None)
                mode_raw = _v(entry, "actionTypeZIA", "actionType", "tunnelType", "mode")
                if mode_raw is None:
                    mode_raw = next((entry[kk] for kk in entry if re.search(r"tunnel|action|forward|proxy|mode", str(kk), re.I) and not re.search(r"network|dns|timeout|port|id$", str(kk), re.I)), None)
                if mode_raw is None:
                    continue
                label, kind = classify_mode(mode_raw)
                if str(mode_raw) == "1" and _truthy(_v(entry, "enablePacketTunnel")):
                    label, kind = "Z-Tunnel 2.0", "tunnel"
                proxy = _v(entry, "systemProxyData", default={})
                proxy = proxy if isinstance(proxy, dict) else {}
                out[classify_network(net_raw)] = {"mode_label": label, "mode_kind": kind,
                    "pac_url": _v(proxy, "pacURL") or _v(entry, "customPac"),
                    "raw": {k: v for k, v in entry.items() if re.sub(r"[^a-z0-9]", "", k.lower()) in
                            {"networktype", "actiontype", "actiontypezia", "tunneltype", "enablepackettunnel", "systemproxy", "systemproxydata", "custompac", "primarytransport", "allowtlsfallback", "tunnel2fallbacktype"}}}
    if not out:
        for kk in profile:
            if re.search(r"tunnel|forward|mode", str(kk), re.I) and not isinstance(profile[kk], (list, dict)) and profile[kk] not in (None, ""):
                label, kind = classify_mode(profile[kk])
                if kind != "unknown":
                    out["any"] = {"mode_label": label, "mode_kind": kind, "raw": {"field": kk, "mode": profile[kk]}}
                    break
    return out


def read_client_connector(client, *, scope: Optional[Dict[str, Any]] = None, cancel: Any = None, platform: Optional[str] = None,
                          keep_raw: bool = False) -> Dict[str, Any]:
    """App profiles, forwarding profiles, trusted networks and PAC files in
    one normalised structure. Errors are recorded, never raised. With a
    `scope` (path_scope) only what is in scope is read; the rest is
    recorded in `not_in_scope`. `cancel` (the operator's Stop) is checked
    before every request: once set, ReadStopped is raised and nothing more
    is sent. `keep_raw` keeps each app and forwarding profile as read
    (`raw`, the app profile flattened) for a caller that exports its
    settings; that caller must leave out secrets (config_exports does)."""
    out: Dict[str, Any] = {"app_profiles": [], "forwarding_profiles": [], "trusted_networks": [], "pac_files": [], "errors": [], "not_in_scope": {}}
    nis = (scope or {}).get("not_in_scope") or {}
    out["read_status"] = {}
    out["profile_schema"] = 4
    out["profile_platform"] = None
    for k in ("zcc", "pac"):
        if k in nis:
            out["not_in_scope"][k] = nis[k]
    if "zcc" not in nis:
        _stop_point(cancel)
        try:
            data, errors, statuses = read_app_profiles(client.get, cancel=lambda: _stop_point(cancel))
            out["errors"].extend(errors)
            out["platform_read_status"] = statuses
            out["read_status"]["app_profiles"] = "unverified" if errors else "read"
            for p in data:
                if not isinstance(p, dict):
                    continue
                linked_policy = _v(p, "onNetPolicy", default={})
                p = flatten_profile(p)
                plat = str(_v(p, "deviceType", "os", "platform", "osType", default="")).lower()
                plat = plat.removeprefix("device_type_")
                # The Client Connector API numbers the platforms: 1 iOS, 2 Android, 3 Windows, 4 macOS, 5 Linux.
                plat = {"win": "windows", "windows": "windows", "mac": "macos", "macos": "macos", "osx": "macos", "ios": "ios", "android": "android", "linux": "linux",
                        "1": "ios", "2": "android", "3": "windows", "4": "macos", "5": "linux"}.get(plat, plat or "all")
                domains, apps, processes, ips, vpn = [], [], [], [], []
                for k, v in p.items():
                    kl = str(k).lower()
                    if not isinstance(v, list) or not v:
                        continue
                    vals = [x.get("name") or x.get("url") or x.get("domain") or x.get("ip") or x.get("path") or json.dumps(x)[:80] if isinstance(x, dict) else str(x) for x in v]
                    if re.search(r"vpn", kl):
                        vpn += vals
                    elif re.search(r"process", kl):
                        processes += vals
                    elif re.search(r"bypassapp|appbypass|applicationbypass|predefinedbypass|custombypass", kl):
                        apps += vals
                    elif re.search(r"ipexclu|excludeip|bypassip|ipbypass|destinationexclu|nonzscaler", kl):
                        ips += vals
                    elif re.search(r"domain|hostname|bypassurl|url|tunnelbypass", kl) and re.search(r"bypass|exclu|exempt", kl):
                        domains += vals
                out["app_profiles"].append({
                    "id": p.get("id"), "name": _v(p, "name", "policyName") or f"Profile {p.get('id', '?')}",
                    "platform": plat, "active": _truthy(_v(p, "active", default=True)), "priority": _v(p, "ruleOrder", "priority"),
                    "forwarding_profile": _v(p, "forwardingProfileId", "forwardingProfileName", "forwardingProfile") or _v(linked_policy, "id", "name"),
                    "pac_url": p.get("pacUrl") or p.get("customPacUrl") or p.get("pac_url"),
                    "strict_enforcement": _truthy(_v(p, "strictEnforcement", "strictMode")),
                    "endpoint_dlp": _truthy(_v(p, "installEndpointDlp", "endpointDlpEnabled", "zdpEnabled")),
                    "ssl_cert": _truthy(_v(p, "sslCertInstall", "installSslCert", "sslCertificateEnabled")),
                    "bypass": {"domains": domains, "apps": apps, "processes": processes, "ips": ips, "vpn_gateways": vpn},
                    "groups": _names(p.get("groups") or p.get("groupNames") or []),
                    "users": _names(p.get("users") or p.get("userNames") or []),
                    # Z-Tunnel 2.0's IP lists (zscaler-sdk-python 1.11.3 zcc/web_policy.py:
                    # packet_tunnel_exclude_list / _include_list, comma-separated CIDRs).
                    "tunnel": {k: _cidrs(_v(p, f)) + _cidrs(_v(p, f + "ForIPv6"))
                               for k, f in (("exclude", "packetTunnelExcludeList"), ("include", "packetTunnelIncludeList"))},
                })
                if keep_raw:
                    out["app_profiles"][-1]["raw"] = p
        except ReadStopped:
            raise
        except Exception as e:  # noqa: BLE001
            out["read_status"]["app_profiles"] = "unverified"
            out["errors"].append(f"/zcc/webPolicies: {e}")
        _stop_point(cancel)
        try:
            data, code = read_profiles(client.get, "/zcc/forwardingProfiles", cancel=lambda: _stop_point(cancel))
            out["read_status"]["forwarding_profiles"] = "read" if code == 200 else "unverified"
            if code != 200:
                out["errors"].append(f"/zcc/forwardingProfiles: HTTP {code}" + (f" ({data.get('error')})" if isinstance(data, dict) and data.get('error') else ""))
            for p in _rules_to_list(data) if code == 200 else []:
                if isinstance(p, dict):
                    out["forwarding_profiles"].append({"id": p.get("id"), "name": p.get("name") or f"Forwarding profile {p.get('id', '?')}",
                                                       "actions": forwarding_actions(p),
                                                       "trusted_networks": _names(p.get("trustedNetworks") or p.get("trustedNetworkNames") or []),
                                                       "pac_url": p.get("pacUrl") or p.get("customPacUrl") or p.get("forwardingProfilePacUrl")})
                    if keep_raw:
                        out["forwarding_profiles"][-1]["raw"] = p
        except ReadStopped:
            raise
        except Exception as e:  # noqa: BLE001
            out["read_status"]["forwarding_profiles"] = "unverified"
            out["errors"].append(f"/zcc/forwardingProfiles: {e}")
        _stop_point(cancel)
        try:
            data, code = client.get("/zcc/trustedNetworks")
            for t in _rules_to_list(data) if code == 200 else []:
                if isinstance(t, dict):
                    out["trusted_networks"].append({"id": t.get("id"), "name": t.get("name") or t.get("networkName"),
                                                    "conditions": {k: v for k, v in t.items() if re.search(r"dns|ssid|ip|hostname|server|condition", str(k), re.I) and v}})
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"/zcc/trustedNetworks: {e}")
    if "pac" not in nis:
        _stop_point(cancel)
        try:
            data, code = read_profiles(client.get, "/zia/pacFiles", cancel=lambda: _stop_point(cancel))
            out["read_status"]["pac_files"] = "read" if code == 200 else "unverified"
            if code != 200:
                out["errors"].append(f"/zia/pacFiles: HTTP {code}")
            for f in _rules_to_list(data) if code in (200, 204) else []:
                if isinstance(f, dict):
                    content = str(_v(f, "pacContent", "content", "pacScript", default=""))
                    out["pac_files"].append({"id": f.get("id"), "name": f.get("name"), "url": _v(f, "pacUrl", "pacUrlObfuscated", "url"),
                                             "direct_hosts": _pac_direct_hosts(content), "has_content": bool(content),
                                             "source": content[:pac_eval.MAX_SOURCE + 1]})
        except ReadStopped:
            raise
        except Exception as e:  # noqa: BLE001
            out["errors"].append(f"/zia/pacFiles: {e}")
    return out


def _cidrs(v: Any) -> List[str]:
    """A comma-separated CIDR list (or a list) as entries; anything else is none."""
    items = re.split(r"[,;\s]+", v) if isinstance(v, str) else v if isinstance(v, (list, tuple)) else []
    return [str(x).strip() for x in items if isinstance(x, (str, int)) and str(x).strip()][:2000]


def _pac_direct_hosts(content: str) -> List[str]:
    """Hostname and network patterns a PAC file sends DIRECT (never to
    Zscaler), read by pac_eval from its parse; never run."""
    return pac_eval.direct_hosts(content)


# ── ZIA readers ───────────────────────────────────────────────────────
def _norm_generic(r: Dict[str, Any]) -> Dict[str, Any]:
    """URL filtering / File Type Control / Cloud App Control rule → common shape."""
    action = r.get("action")
    if isinstance(action, dict):
        action = action.get("type") or action.get("name")
    actions = [str(a).upper() for a in (r.get("actions") or [])]
    state = str(r.get("state") or "ENABLED").upper()
    return {
        "id": r.get("id"), "name": r.get("name") or f"rule {r.get('id')}", "order": r.get("order"), "rank": r.get("rank"),
        "state": state, "enabled": state == "ENABLED",
        "action": str(action or r.get("filteringAction") or r.get("filtering_action") or "").upper(), "actions": actions,
        "url_categories": _upper(_names(r.get("urlCategories") or r.get("url_categories") or [])),
        "cloud_applications": _upper(_names(r.get("applications") or r.get("cloudApplications") or r.get("cloud_applications") or [])),
        "app_classes": _upper(_names(r.get("cloudAppClasses") or r.get("cloud_app_classes") or [])),
        "type": str(r.get("type") or "").upper(),
        "file_types": _upper(_names(r.get("fileTypes") or r.get("file_types") or [])),
        "operation": str(r.get("operation") or "").upper(),
        "request_methods": _upper(_names(r.get("requestMethods") or r.get("request_methods") or [])),
        "scope": _scope(r), "scoped": bool(_scope(r)), "scope_items": scope_items(r),
        "protocols": _upper(_names(r.get("protocols") or [])),
        # Conditions the Path analyzer cannot evaluate (time window, device
        # trust, risk score, ...), shown there as "unknown" criteria.
        "conditions": _unevaluated(r),
    }


def read_zia(client, *, scope: Optional[Dict[str, Any]] = None, cancel: Any = None) -> Dict[str, Any]:
    """The ZIA policy the path runs through. With a `scope` (path_scope)
    only the sections in scope are read: a section out of scope is an
    empty list recorded in `not_in_scope` with the reason, never an
    unread (failed) section. `scope` None reads every section (the Data
    Flow Map). `cancel` (the operator's Stop) is checked before every
    section and every catalogue page, and while a request waits out ZIA's
    rate limit: once set, ReadStopped is raised and nothing more is sent."""
    diagnostics: List[Dict[str, Any]] = []
    nis = dict((scope or {}).get("not_in_scope") or {})
    z: Dict[str, Any] = {"diagnostics": diagnostics, "not_in_scope": {k: v for k, v in nis.items() if k not in ("zcc", "pac")}}
    blocked = dict((scope or {}).get("read_blocked") or {})
    import dlp_analysis
    client = dlp_analysis.read_once(client)
    import dlp_efficacy
    _stop_point(cancel)
    try:
        z["required_controls"] = dlp_analysis.inspect(client, (scope or {}).get("scopes", []), (scope or {}).get("declaration", {}))
    except dlp_efficacy.CorpusReadStopped as exc:
        raise ReadStopped(str(exc)) from exc

    def rules(key: str, endpoint: str, label: str) -> List[Dict[str, Any]]:
        if key in nis:
            return []
        if key in blocked:
            diagnostics.append({"section": label, "endpoint": endpoint, "error": blocked[key], "error_type": "unmet_dependency"})
            return []
        _stop_point(cancel)
        return _fetch_rules(client, endpoint, diagnostics, label)

    z["ssl"] = sorted((dict(normalize_ssl_rule(r), conditions=_unevaluated(r)) for r in rules("ssl", "/zia/sslInspectionRules", "SSL inspection rules")), key=_sort_key)
    z["dlp"] = [dict(normalize_dlp_rule(r), conditions=_unevaluated(r)) for r in rules("dlp", "/zia/webDlpRules", "Web DLP rules")]
    z["url"] = [_norm_generic(r) for r in rules("url", "/zia/urlFilteringRules", "URL filtering rules")]
    z["cac"] = [_norm_generic(r) for r in rules("cac", "/zia/cloudApplicationRules", "Cloud App Control rules")]
    z["ftc"] = [_norm_generic(r) for r in rules("ftc", "/zia/fileTypeRules", "File Type Control rules")]
    for key, ep, label in (("endpoint", "/zia/endPointDlpRules", "Endpoint DLP rules"), ("saas", "/zia/casbDlpRules/all", "SaaS Security API DLP rules"),
                           ("email", "/zia/emailDlpRules", "Outbound Email DLP rules")):
        z[key] = [{"id": r.get("id"), "name": r.get("name"), "state": str(r.get("state") or "ENABLED").upper(),
                   "action": str((r.get("action") or {}).get("type") if isinstance(r.get("action"), dict) else r.get("action") or "").upper(),
                   "engines": _names(r.get("dlpEngines") or r.get("dlp_engines") or r.get("engines") or [])} for r in rules(key, ep, label) if isinstance(r, dict)]
    # The application catalogue serves Cloud App Control only; the URL
    # categories place the destination for the ZIA policy sections.
    if "cac" not in nis and "cac" not in blocked:
        classes = {cls for k in TRAFFIC_CLASSES for cls in k["app_classes"]}
        _stop_point(cancel)
        z["catalogue"] = _fetch_app_catalogue(client, classes, diagnostics, cancel=lambda: stop_requested(cancel))
    else:
        z["catalogue"] = {}
    if scope is None or any(k not in nis for k in _PLACING):
        _stop_point(cancel)
        try:
            z["categories"] = _fetch_url_category_lookup(client)
        except Exception as e:  # noqa: BLE001
            z["categories"] = {}
            diagnostics.append({"section": "URL categories", "endpoint": "/zia/urlCategories", "error_type": type(e).__name__, "error": str(e)[:200]})
    else:
        z["categories"] = {}
    _stop_point(cancel)   # a read cut short by Stop is never handed on as a finished one
    for r in z["dlp"] + z["url"] + z["cac"] + z["ftc"] + z["ssl"]:
        r.setdefault("order", None)
    z["unread"] = unread_sections(diagnostics)
    return z


# A rule list that failed to read (HTTP 429, 403, a timeout) is not an empty
# rule list: the trace says "could not read" for it, never "no rule".
_SECTION_KEYS = {"SSL inspection rules": "ssl", "Web DLP rules": "dlp", "URL filtering rules": "url", "Cloud App Control rules": "cac",
                 "File Type Control rules": "ftc", "Endpoint DLP rules": "endpoint", "SaaS Security API DLP rules": "saas",
                 "Outbound Email DLP rules": "email"}


def unread_sections(diagnostics: Any) -> Dict[str, str]:
    """{zia key: why} for each rule section whose read failed, from the
    read's diagnostics."""
    out: Dict[str, str] = {}
    for d in diagnostics or []:
        if not isinstance(d, dict):
            continue
        key = _SECTION_KEYS.get(str(d.get("section") or ""))
        if key and key not in out:
            why = " ".join(str(x) for x in (d.get("error_type"), d.get("error")) if x).strip()
            out[key] = why[:200] or "the read failed"
    return out


def _unread_why(unread: Dict[str, str], key: str, label: str) -> str:
    return f"The {label} could not be read ({unread[key]}), so whether one applies here is unknown; run the analysis again once the API answers."


# ── Destination resolution ────────────────────────────────────────────
def resolve_destination(dest: str, zia: Dict[str, Any], path: Optional[str] = None) -> Dict[str, Any]:
    """A cloud app name, a URL category id/name, a traffic class key or a
    hostname (or IP address; `path`, the URL path when one was typed) →
    {label, kind, categories, applications, app_classes, host}."""
    d = (dest or "").strip()
    du = d.upper().replace(" ", "_")
    for k in TRAFFIC_CLASSES:
        if d.lower() == k["key"] or d.lower() == k["label"].lower():
            apps = sorted({a for cls in k["app_classes"] for a in zia.get("catalogue", {}).get(cls, [])})
            return {"label": k["label"], "kind": "class", "categories": list(k["url_categories"]), "applications": apps,
                    "app_classes": list(k["app_classes"]), "host": "", "why": k.get("why", ""), "class": k["key"]}
    cats = zia.get("categories") or {}
    if du in cats or d in cats:
        c = cats.get(du) or cats.get(d)
        cid = c.get("id") or du
        return {"label": c.get("configured_name") or c.get("name") or du, "kind": "category", "categories": [str(cid).upper()],
                "applications": [], "app_classes": [], "host": "", "class": ""}
    for cls, apps in (zia.get("catalogue") or {}).items():
        if du in apps:
            return {"label": d, "kind": "application", "categories": [], "applications": [du], "app_classes": [cls], "host": "", "class": ""}
    try:   # an IP address (IPv6 has no dot): the host itself
        literal: Optional[str] = str(ipaddress.ip_address(d.strip("[]")))
    except ValueError:
        literal = None
    if "." in d or literal:
        host = literal or _hostname_of(d)
        # ZIA's URL list semantics (zia_path_modules.url_hit): "example.com"
        # is that host only, ".example.com" the domain and its subdomains;
        # an entry with a path places only that path (`path`, when given).
        where = {"host": host, "path": path or "/"}
        matched_cats = []
        for key, c in cats.items():
            if not isinstance(c, dict):
                continue
            entries = list(c.get("urls") or []) + list(c.get("db_categorized_urls") or c.get("dbCategorizedUrls") or [])
            if _zpm.url_hit(entries, where, bool(path and path != "/"))[0] == "match":
                matched_cats.append(str(c.get("id") or key).upper())
        return {"label": host, "kind": "host", "categories": sorted(set(matched_cats)), "applications": [], "app_classes": [], "host": host, "class": ""}
    return {"label": d, "kind": "unknown", "categories": [du] if du else [], "applications": [du] if du else [], "app_classes": [], "host": "", "class": ""}


# ── Matching helpers ──────────────────────────────────────────────────
def _generic_matches(rule: Dict[str, Any], dest: Dict[str, Any]) -> Optional[str]:
    cats = set(dest["categories"]); apps = set(dest["applications"]); classes = set(dest["app_classes"])
    if rule["cloud_applications"] and apps & set(rule["cloud_applications"]):
        return "application"
    if rule["app_classes"] and classes & set(rule["app_classes"]):
        return "application class"
    if rule["url_categories"]:
        if cats & set(rule["url_categories"]):
            return "URL category"
        if "ANY" in rule["url_categories"] or "ALL" in rule["url_categories"]:
            return "any category"
        return None
    if not rule["cloud_applications"] and not rule["app_classes"] and not rule["url_categories"]:
        return "catch-all"
    return None


def _cac_matches(rule: Dict[str, Any], dest: Dict[str, Any]) -> Optional[str]:
    apps = set(dest["applications"]); classes = set(dest["app_classes"])
    if rule["cloud_applications"] and apps & set(rule["cloud_applications"]):
        return "application"
    if rule["app_classes"] and classes & set(rule["app_classes"]):
        return "application class"
    if rule["type"] and rule["type"] in classes and not rule["cloud_applications"]:
        return "application type"
    return None


def _hop(key: str, label: str, status: str, decided_by: Optional[Dict[str, Any]], detail: str,
         weak: Optional[Dict[str, Any]] = None, **extra) -> Dict[str, Any]:
    h = {"key": key, "label": label, "status": status, "decided_by": decided_by, "detail": detail, "weak_point": weak}
    h.update(extra)
    return h


def _weak(severity: str, title: str, fix: str) -> Dict[str, Any]:
    return {"severity": severity, "title": title, "fix": fix}


def _policy_order(rule: Dict[str, Any]) -> Tuple[int, str]:
    try:
        order = int(rule.get("order"))
    except (TypeError, ValueError):
        order = 10 ** 9
    return order, str(rule.get("id") or "")


FLOW_CONTROLS = (("cac", "Cloud App Control"), ("url", "URL filtering"),
                 ("ssl", "SSL inspection"), ("ftc", "File Type Control"),
                 ("dlp", "Inline Web DLP"), ("incident", "Logs & incidents"))


def _retain_controls(hops: List[Dict[str, Any]], ends: Optional[str], nis: Dict[str, str]) -> None:
    """Keep the architecture visible without evaluating a stopped branch."""
    stop = next((h for h in hops if h["key"] == ends), None)
    source = ({"key": stop["key"], "label": stop["label"],
               "object_id": (stop.get("decided_by") or {}).get("id"),
               "object_name": (stop.get("decided_by") or {}).get("name")} if stop else None)
    for key, label in FLOW_CONTROLS:
        if any(h["key"] == key for h in hops):
            continue
        detail = (f"Not reached: the path stopped at {source['label']}. This control was not evaluated."
                  if source else "This control was not evaluated by this analysis.")
        hops.append(_hop(key, label, "not_reached" if source else "unknown", None, detail,
                         stopped_by=source, why=f"stopped at {source['label']}" if source else "not evaluated",
                         scope_status="out_of_scope" if key in nis else "in_scope"))


def connector_references(zcc: Dict[str, Any]) -> Dict[str, Any]:
    """Public configuration context, never a claim about an incident's actual route."""
    refs = []
    for app in zcc.get("app_profiles", []):
        ref = app.get("forwarding_profile")
        if isinstance(ref, dict):
            ref = ref.get("id") if ref.get("id") is not None else ref.get("name")
        fwd = next((f for f in zcc.get("forwarding_profiles", []) if ref is not None and
                    (str(f.get("id")) == str(ref) or str(f.get("name")) == str(ref))), None)
        refs.append({"app_profile": {"id": app.get("id"), "name": app.get("name"), "platform": app.get("platform"), "active": app.get("active", True)},
                     "forwarding_profile": {"id": fwd.get("id"), "name": fwd.get("name")} if fwd else None,
                     "forwarding_reference": ref, "status": "linked" if fwd else "unverified",
                     "networks": {k: {"mode": a.get("mode_label"), "kind": a.get("mode_kind"), "pac_url": a.get("pac_url")}
                                  for k, a in (fwd or {}).get("actions", {}).items()}})
    return {"profiles": refs, "forwarding_profiles": zcc.get("forwarding_profiles", []), "pac_files": [{k: v for k, v in f.items() if k != "source"} for f in zcc.get("pac_files", [])], "errors": zcc.get("errors", []), "read_status": zcc.get("read_status", {}),
            "note": "Tenant configuration context. The incident feed does not establish which app profile or network a device used."}


# ── The trace ─────────────────────────────────────────────────────────
def trace(dest: Dict[str, Any], network: str, platform: str, zcc: Dict[str, Any], zia: Dict[str, Any],
          packs: Optional[List[Dict[str, Any]]] = None, scope: Optional[Dict[str, Any]] = None,
          context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Pure: destination + context + tenant snapshot → hops, channels, packs.
    `scope` (path_scope) says what was put out of scope on the Scope page;
    without it, what the snapshot itself recorded as not in scope. A part
    out of scope is drawn as "not in scope" (status out_of_scope), never
    as "no rule" and never as "could not read"."""
    hops: List[Dict[str, Any]] = []
    host = dest.get("host") or ""
    unread = zia.get("unread") or {}
    if scope is not None:
        nis: Dict[str, str] = dict(scope.get("not_in_scope") or {})
    else:
        nis = dict(zcc.get("not_in_scope") or {})
        nis.update(zia.get("not_in_scope") or {})
    unread = {k: v for k, v in unread.items() if k not in nis}
    reaches_zscaler = True
    decrypted = False
    ends = None
    context = context or {}
    if context.get("channel") not in (None, "", "web"):
        raise ValueError("This tracer models inline web traffic; separate-channel inventory is not a tested Endpoint, SaaS or Email path.")
    operation = str(context.get("operation") or "").upper()
    request_method = str(context.get("request_method") or "").upper()
    # Plain HTTP (the Path analyzer's TCP/80 or http:// traffic) carries no
    # TLS: SSL inspection does not apply and every control sees the content.
    # Without it the trace is for HTTPS, as the Data Flow Map draws it.
    plaintext = bool(context.get("plaintext"))
    web_protocol = "HTTP_RULE" if plaintext else "HTTPS_RULE"
    proto_ok = lambda r: _zpm.protocol_applies(r.get("protocols") or [], web_protocol)  # noqa: E731
    # A filename extension is not a ZIA file-category classification. Do
    # not silently treat `pdf` versus FTCATEGORY_* as a proven non-match.
    file_types = {str(x).upper() for x in (context.get("file_types") or []) if str(x).upper().startswith("FTCATEGORY_")}
    if context.get("file_type"):
        supplied_type = str(context["file_type"]).upper()
        if supplied_type.startswith("FTCATEGORY_"):
            file_types.add(supplied_type)

    try:
        dest_ip: Any = ipaddress.ip_address(host)
    except ValueError:
        dest_ip = None

    # 1. Client Connector app profile
    profiles = [p for p in zcc.get("app_profiles", []) if p.get("active", True) and (p["platform"] in (platform, "all", ""))]
    ordered = sorted(profiles, key=lambda p: (_rule_order(p.get("priority")) is None, _rule_order(p.get("priority")) or 0))
    # The first profile in order whose users and groups include the user
    # applies; one with neither applies to everyone. For any user, a scoped
    # profile ahead of the first unscoped one decides only for its own users
    # and groups: the answer depends on who the user is, unless every one of
    # them treats this destination as the unscoped one does.
    scoped = lambda p: bool(p.get("groups") or p.get("users"))  # noqa: E731
    everyone = next((p for p in ordered if not scoped(p)), None)
    ahead = ordered[:ordered.index(everyone)] if everyone is not None else list(ordered)

    def treats(p: Optional[Dict[str, Any]]) -> Tuple[Any, ...]:
        if p is None:
            return (None,)
        hit_app = any(dest["label"].lower() in str(a).lower() or str(a).lower() in dest["label"].lower()
                      for a in p["bypass"]["apps"]) if dest["kind"] in ("application", "unknown") else False
        tl = p.get("tunnel") or {}
        ip_side = tuple(any(_zpm._ip_rel(dest_ip, str(e).strip()) for e in lst or []) for lst in
                        (p["bypass"].get("ips"), tl.get("exclude"), tl.get("include"))) if dest_ip is not None else ()
        return (str(p.get("forwarding_profile")), bool(_domain_hit(p["bypass"]["domains"], host)) if host else False, hit_app,
                p.get("pac_url"), bool(p.get("ssl_cert")), ip_side, bool(tl.get("include")))
    by_user = [p for p in ahead if treats(p) != treats(everyone)]
    # The hops below follow the unscoped profile (else the first scoped one).
    prof = everyone if everyone is not None else (ordered[0] if ordered else None)
    zcc_out = "zcc" in nis
    if zcc_out:
        prof = None
        hops.append(_hop("zcc", "Client Connector app profile", "out_of_scope", None,
                         nis["zcc"] + " Whether the client bypasses this destination is not assessed; the hops below assume it reaches Zscaler.",
                         None, why="not in scope"))
    elif by_user:
        who = lambda p: _zpm._short([f"group {g}" for g in p.get("groups") or []] + [f"user {u}" for u in p.get("users") or []], 3)  # noqa: E731
        hops.append(_hop("zcc", "Client Connector app profile", "conditional", None,
                         "Which app profile applies depends on who the user is: "
                         + "; ".join(f"'{p['name']}' applies to {who(p)}" for p in by_user[:3])
                         + (f"; everyone else gets '{everyone['name']}'" if everyone else f"; a user outside them has no {platform} app profile")
                         + ", and they treat this destination differently. Unable to verify how the device reaches it for any user.",
                         None, why="app profile depends on the user", candidate_rules=[{"id": p["id"], "name": p["name"]} for p in by_user + ([everyone] if everyone else [])],
                         missing_context=["identity / app profile assignment"]))
    elif not prof and (zcc.get("read_status", {}).get("app_profiles") == "unverified" or
                       any("/zcc/webPolicies" in e or "/zcc/appProfiles" in e for e in zcc.get("errors", []))):
        hops.append(_hop("zcc", "Client Connector app profile", "unknown", None,
                         f"Unable to verify the {platform} app profile: " + "; ".join(zcc.get("errors") or []) +
                         ". This does not establish that Client Connector is undeployed.",
                         None, why="app profiles not readable"))
    elif not prof:
        hops.append(_hop("zcc", "Client Connector app profile", "warn", None,
                         f"The profile inventory was read successfully, but no active app profile was found for {platform}.",
                         _weak("medium", "No Client Connector profile for this platform", "Deploy Client Connector with an app profile for this platform, or confirm the device reaches ZIA another way (GRE/IPsec site, PAC)."),
                         why=f"no app profile for {platform}" + (": profile list could not be read" if zcc.get("errors") else "")))
    else:
        b = prof["bypass"]
        hit_domain = _domain_hit(b["domains"], host) if host else None
        # IP bypasses (destination exclusions): an address in one never
        # enters the tunnel. A host name is not resolved: it is assumed to
        # resolve outside them, and that assumption is said.
        ip_entries = [str(x).strip() for x in b.get("ips") or [] if _zpm._is_ip_entry(str(x).strip())]
        hit_ip = next((e for e in ip_entries if _zpm._ip_rel(dest_ip, e)), None) if dest_ip is not None else None
        hit_domain = hit_domain or (_domain_hit([x for x in b.get("ips") or [] if not _zpm._is_ip_entry(str(x).strip())], host) if host and dest_ip is None else None)
        hit_app = next((a for a in b["apps"] if dest["label"].lower() in str(a).lower() or str(a).lower() in dest["label"].lower()), None) if dest["kind"] in ("application", "unknown") else None
        notes = []
        if not prof["strict_enforcement"]:
            notes.append("strict enforcement off (a user can disable the client)")
        if not prof["ssl_cert"]:
            notes.append("Zscaler root certificate not pushed by this profile (decryption fails unless deployed by MDM)")
        public = [e for e in ip_entries if not _non_public(e)]
        if public and dest_ip is None and host:
            notes.append(f"{len(public)} IP bypass entr{'y' if len(public) == 1 else 'ies'} ({_zpm._short(public, 3)}) apply if {host} resolves into them; "
                         "it is not resolved and is assumed to resolve outside them")
        if hit_domain or hit_app or hit_ip:
            reaches_zscaler = False
            ends = "zcc"
            what = f"domain {hit_domain}" if hit_domain else f"IP {hit_ip}" if hit_ip else f"application {hit_app}"
            hops.append(_hop("zcc", "Client Connector app profile", "bypass", {"name": prof["name"], "id": prof["id"]},
                             f"'{prof['name']}' bypasses this destination ({what}): the traffic leaves the device directly and never reaches Zscaler.",
                             _weak("high", "Bypassed at the client", "Remove the bypass from the app profile, or accept that only Endpoint DLP can see this traffic and make sure it is enabled."),
                             profile=prof["name"], notes=notes))
        else:
            n_bypass = sum(len(v) for v in b.values())
            hops.append(_hop("zcc", "Client Connector app profile", "pass", {"name": prof["name"], "id": prof["id"]},
                             f"'{prof['name']}' ({prof['platform']}) forwards this destination; {n_bypass} bypass entries on the profile do not match it."
                             + (" Notes: " + "; ".join(notes) + "." if notes else ""),
                             _weak("medium", "Client can be disabled by the user", "Turn on strict enforcement (and a tamper/uninstall password) so a user cannot switch the client off.") if not prof["strict_enforcement"] else None,
                             profile=prof["name"], notes=notes))

    # 2. Forwarding profile
    fwd = None
    if prof:
        ref = prof.get("forwarding_profile")
        fps = zcc.get("forwarding_profiles", [])
        if isinstance(ref, dict):
            ref = ref.get("id") if ref.get("id") is not None else ref.get("name")
        fwd = next((f for f in fps if ref is not None and (str(f.get("id")) == str(ref) or str(f.get("name")) == str(ref))), None)
    mode_kind = "tunnel"
    if reaches_zscaler and zcc_out:
        hops.append(_hop("forwarding", "Forwarding profile", "out_of_scope", None,
                         nis["zcc"] + " How the device forwards this traffic is not assessed; a tunnel to ZIA is assumed.", None, why="not in scope"))
    elif reaches_zscaler:
        if not fwd:
            fps_n = len(zcc.get("forwarding_profiles", []))
            if prof:
                text = (f"The app profile '{prof['name']}' does not name a forwarding profile the tool could match"
                        + (f" (the tenant has {fps_n} forwarding profiles, so none can be assumed)" if fps_n > 1 else (" and the forwarding profile list could not be read" if fps_n == 0 else ""))
                        + ". Unable to verify forwarding; downstream policy results are conditional on traffic reaching ZIA. Check the app profile's Forwarding Profile field in the Client Connector portal.")
                why = "no forwarding profile linked" if fps_n else "forwarding profiles not readable"
            else:
                text = (f"No app profile for {platform}, so no forwarding profile can be linked"
                        + (f" (the tenant has {fps_n} forwarding profile(s))" if fps_n else " and the forwarding profile list could not be read")
                        + ". Unable to verify forwarding; downstream policy results are conditional on traffic reaching ZIA.")
                why = f"no app profile for {platform}"
            hops.append(_hop("forwarding", "Forwarding profile", "unknown", None, text, None, why=why))
        else:
            act = fwd["actions"].get(network) or fwd["actions"].get("any") or {}
            mode_kind = act.get("mode_kind", "unknown")
            label = act.get("mode_label", "not set")
            net_label = next(n["label"] for n in NETWORKS if n["key"] == network)
            if mode_kind == "none":
                reaches_zscaler = False; ends = "forwarding"
                hops.append(_hop("forwarding", "Forwarding profile", "bypass", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}' sets '{label}' for {net_label}: web traffic is not forwarded by the client on this network. Unless the site has a GRE/IPsec tunnel or a system PAC, it goes direct.",
                                 _weak("high" if network == "off" else "medium", f"No forwarding on {net_label.lower()}",
                                       "Set the forwarding action to Z-Tunnel 2.0 (or Tunnel with local proxy) for this network, or confirm the site tunnel covers it."),
                                 mode=label, raw=act.get("raw")))
            elif mode_kind == "pac":
                hops.append(_hop("forwarding", "Forwarding profile", "warn", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}' sets '{label}' for {net_label}: only proxied traffic reaches Zscaler; anything the PAC returns DIRECT for, and non-browser traffic, does not.",
                                 _weak("medium", "PAC-based forwarding", "Move to Z-Tunnel 2.0 so every port and protocol is forwarded, not just what the PAC catches."),
                                 mode=label, raw=act.get("raw")))
            elif mode_kind == "unknown":
                hops.append(_hop("forwarding", "Forwarding profile", "unknown", {"name": fwd["name"], "id": fwd["id"]},
                                 f"'{fwd['name']}': the forwarding mode for {net_label} is '{label}', which this tool does not recognise as tunnel, PAC or none. Downstream policy results are conditional on traffic reaching ZIA. Raw value kept for review.",
                                 None, mode=label, raw=act.get("raw"), why=f"mode '{label}' not recognised for {net_label.lower()}"))
            else:
                # Z-Tunnel 2.0 tunnels by address: the app profile's packet
                # tunnel exclusions leave it, and with an inclusion list of its
                # address family only those addresses enter it.
                tl = (prof or {}).get("tunnel") or {}
                outside = None
                if label == "Z-Tunnel 2.0" and dest_ip is not None:
                    ex = next((e for e in tl.get("exclude") or [] if _zpm._ip_rel(dest_ip, e)), None)
                    inc = [e for e in tl.get("include") or [] if _family(e) == dest_ip.version]
                    if ex:
                        outside = f"the app profile '{prof['name']}' excludes {ex} from the packet tunnel"
                    elif inc and not any(_zpm._ip_rel(dest_ip, e) for e in inc):
                        outside = f"the app profile '{prof['name']}' tunnels only {_zpm._short(inc, 3)}"
                if outside:
                    reaches_zscaler = False; ends = "forwarding"
                    hops.append(_hop("forwarding", "Forwarding profile", "bypass", {"name": fwd["name"], "id": fwd["id"]},
                                     f"'{fwd['name']}' sets '{label}' for {net_label}, but {outside}: traffic to {host} leaves the device directly and never reaches Zscaler.",
                                     _weak("high", "Outside the packet tunnel", "Remove the address from the app profile's packet tunnel exclusions (or add it to its inclusions), or accept that only Endpoint DLP sees it."),
                                     mode=label, raw=act.get("raw")))
                else:
                    hops.append(_hop("forwarding", "Forwarding profile", "pass", {"name": fwd["name"], "id": fwd["id"]},
                                     f"'{fwd['name']}' sets '{label}' for {net_label}: all traffic is tunnelled to ZIA.", None, mode=label, raw=act.get("raw")))

    # 3. PAC file DIRECT statements
    if reaches_zscaler and "pac" in nis and not zcc_out and (mode_kind == "pac" or (prof and prof.get("pac_url")) or (fwd and fwd.get("pac_url"))):
        hops.append(_hop("pac", "PAC file", "out_of_scope", None, nis["pac"] + " Whether the PAC file sends this destination DIRECT is not assessed.", None, why="not in scope"))
    elif reaches_zscaler and (mode_kind == "pac" or (prof and prof.get("pac_url")) or (fwd and fwd.get("pac_url"))):
        direct = []
        pac_url = (act.get("pac_url") if fwd else None) or (prof or {}).get("pac_url") or (fwd or {}).get("pac_url")
        pacs = [f for f in zcc.get("pac_files", []) if pac_url and f.get("url") == pac_url]
        # Evaluated by pac_eval (parsed and interpreted, never run); a PAC
        # it cannot evaluate safely is unverified, not "no DIRECT clause".
        pev = pac_eval.path_hop(pacs, host, dest.get("pac_url") or dest.get("url") or (f"https://{host}/" if host else ""))
        if pev is not None:
            pacs = []
            if pev["status"] == "bypass":
                reaches_zscaler = False; ends = "pac"
            hops.append(_hop("pac", "PAC file", "unknown" if pev["status"] == "error" else pev["status"], pev["decided_by"], pev["detail"],
                             pev.get("weak_point"), module_hop=pev["module_hop"], pac_outcomes=pev["evaluation"]["outcomes"],
                             depends_on=pev["evaluation"]["depends_on"]))
        for f in pacs:
            hit = _domain_hit(f.get("direct_hosts") or [], host) if host else None
            if hit:
                direct.append((f, hit))
        if direct:
            reaches_zscaler = False; ends = "pac"
            f, hit = direct[0]
            hops.append(_hop("pac", "PAC file", "bypass", {"name": f.get("name"), "id": f.get("id")},
                             f"PAC '{f.get('name')}' returns DIRECT for {hit}: the browser connects without Zscaler.",
                             _weak("high", "PAC sends this destination DIRECT", "Remove the DIRECT clause or narrow it; Zscaler recommends returning the ZIA proxy for everything except RFC1918 and explicit local hosts.")))
        elif pev is None:
            verified = bool(pacs) and all(f.get("has_content") for f in pacs)
            hops.append(_hop("pac", "PAC file", "pass" if verified else "unknown", None,
                             (f"{len(pacs)} linked PAC file(s) read; no DIRECT pattern found for this destination" + (" (host-level check needs a hostname)." if not host else ".")) if verified else "The referenced PAC URL could not be linked to readable content. PAC routing is unverified.", None))

    if not reaches_zscaler:
        hops.append(_hop("zia", "ZIA", "skipped", None, "Never reached: nothing below applies to this traffic.", None))
    else:
        # Inside ZIA the order follows Zscaler's "Understanding Policy
        # Enforcement" for a web request: Browser Control, FTP Control,
        # URL & Cloud App Control (Cloud App Control takes precedence), SSL
        # inspection, Malware Protection and Advanced Threat Protection,
        # upload File Type Control, upload Bandwidth Control, DLP and
        # finally Firewall & DNS Control; the response walks the same list
        # in reverse. Only the data security controls are traced here
        # (app control, URL filtering, SSL, file type control, DLP); the
        # others are not data-leak controls and this tool does not read
        # them, so they are left out of the path rather than drawn as
        # unreadable boxes. The reference diagram in the report shows the
        # full order. The first violation ends the transaction.
        cats = dest["categories"]; apps = dest["applications"]
        klass = {"catch_all": dest["kind"] == "class" and dest.get("class") == "general", "key": dest.get("class") or "custom"}

        # The SSL decision is known from the rules before it is applied:
        # it decides what the app and URL controls can see (domain only
        # until decryption) and whether content inspection is possible.
        matching = [(r, _matches(r, klass, cats, apps)) for r in sorted(zia["ssl"], key=_sort_key) if r["enabled"]] if not plaintext else []
        matching = [(r, h) for r, h in matching if h]
        decided = next((r for r, h in matching if not r["scoped"]), None)
        exceptions = []
        for r, _ in matching:
            if r is decided:
                break
            if r["scoped"]:
                exceptions.append(r)
        # A scoped rule ahead of the deciding one makes the decision depend
        # on who the user is only when it decides differently (no matching
        # rule leaves the traffic encrypted).
        everyone = decided["decision"] if decided else "not_inspected"
        ssl_conditional = any(e["decision"] != everyone for e in exceptions)
        decrypted = plaintext or (decided is not None and decided["decision"] == "inspected" and not ssl_conditional)
        ssl_out = "ssl" in nis and not plaintext
        ssl_unknown = decided is not None and decided["decision"] == "unknown"
        if plaintext:
            unread.pop("ssl", None)   # no TLS: the SSL rules decide nothing here

        # 5. Cloud App Control: evaluated with URL Filtering before SSL
        # inspection; when a rule matches the application, URL Filtering
        # is not applied.
        cac = [(r, _cac_matches(r, dest)) for r in sorted(zia["cac"], key=_policy_order) if r["enabled"]]
        cac = [(r, m) for r, m in cac if m]
        cac_hit = cac[0][0] if cac else None
        if "cac" in nis:
            hops.append(_hop("cac", "Cloud App Control", "out_of_scope", None,
                             nis["cac"] + " Whether an app control blocks or allows this application is not assessed; URL filtering is traced as if none matched.", None, why="not in scope"))
        elif ssl_conditional and cac:
            hops.append(_hop("cac", "Cloud App Control", "conditional", None,
                             "Higher-precedence scoped SSL rules leave decryption conditional on identity; per-action application control is not established.",
                             None, candidate_rules=[r for r, _ in cac]))
        elif ssl_unknown and cac:
            hops.append(_hop("cac", "Cloud App Control", "unknown", None,
                             "An unrecognized SSL action leaves content visibility unresolved; per-action application controls are not established.",
                             None, candidate_rules=[r for r, _ in cac]))
        elif not decrypted and cac and not ssl_out:
            hops.append(_hop("cac", "Cloud App Control", "blind", {"name": cac[0][0]["name"], "id": cac[0][0]["id"]},
                             f"{len(cac)} rule(s) target this application ('{cac[0][0]['name']}' …) but without decryption Zscaler sees only the domain and cannot tell upload from browse: the per-action controls do not apply.",
                             _weak("high", "App controls need decryption", "Decrypt this application class so upload/share/post controls take effect.")))
        elif cac:
            r, m = cac[0]
            ssl_note = (" Per-action controls apply only to decrypted traffic, and SSL inspection is not in scope on the Scope page, so whether they take effect is not assessed."
                        if ssl_out else "")
            blocks = [a for a in r["actions"] if any(v in a for v in UPLOAD_VERBS) and (a.startswith("BLOCK") or a.startswith("ISOLATE"))]
            allows = [a for a in r["actions"] if any(v in a for v in UPLOAD_VERBS) and a.startswith("ALLOW")]
            if r.get("scoped") or (blocks and (not operation or ssl_out)):
                hops.append(_hop("cac", "Cloud App Control", "conditional", None,
                                 f"'{r['name']}' is a candidate application rule; its identity, operation and decryption prerequisites are not all established. No block is confirmed.",
                                 None, candidate_rules=[r], actions=r["actions"]))
            elif blocks and any(operation in a for a in blocks):
                ends = "cac"
                hops.append(_hop("cac", "Cloud App Control", "blocked", {"name": r["name"], "id": r["id"], "action": r.get("action") or r.get("actions")},
                                 f"'{r['name']}' (matched on {m}) is configured to block the selected {operation.lower()} operation." + ssl_note, None, actions=r["actions"]))
            else:
                hops.append(_hop("cac", "Cloud App Control", "warn" if allows else "pass", {"name": r["name"], "id": r["id"], "action": r.get("action") or r.get("actions")},
                                 f"'{r['name']}' (matched on {m}) allows {', '.join(a.replace('ALLOW_', '').lower() for a in allows) or 'the actions it lists'}: uploads are not stopped here, so content inspection is the last line. Cloud App Control can also gate on a user risk profile (risk score levels)." + ssl_note,
                                 _weak("medium", "Uploads allowed by app control", "Block upload/share on personal instances of this application, or use tenancy restrictions.") if allows else None, actions=r["actions"]))
        elif "cac" in unread:
            hops.append(_hop("cac", "Cloud App Control", "unknown", None, _unread_why(unread, "cac", "Cloud App Control rules"), None))
        else:
            hops.append(_hop("cac", "Cloud App Control", "none", None, "No Cloud App Control rule targets this application, so URL Filtering decides; every action is allowed unless URL filtering or DLP stops it. Cloud App Control is a data security control: it can block upload/share/post per application, and can gate on a user risk profile (risk score levels).",
                             _weak("medium", "No app-level control", "Add a Cloud App Control rule for this application class (block upload/share on unsanctioned instances); it can also gate on a user risk profile.") if dest["app_classes"] or dest["applications"] else None))

        # 6. URL filtering: first matching rule in order; skipped when Cloud
        # App Control already matched the application.
        if cac_hit and next(h for h in hops if h["key"] == "cac")["status"] in ("conditional", "blind", "unknown"):
            hops.append(_hop("url", "URL filtering", "conditional", None,
                             "Cloud App Control applicability is unresolved; whether it takes precedence over URL Filtering is conditional.", None))
        elif cac_hit:
            hops.append(_hop("url", "URL filtering", "na", {"name": cac_hit["name"], "id": cac_hit["id"]},
                             f"Not evaluated: Cloud App Control rule '{cac_hit['name']}' matched this application, and Cloud App Control takes precedence over URL Filtering for the transaction.", None))
        elif "url" in nis:
            hops.append(_hop("url", "URL filtering", "out_of_scope", None,
                             nis["url"] + " Whether URL filtering blocks or cautions this destination is not assessed.", None, why="not in scope"))
        else:
            url_rules = sorted([r for r in zia["url"] if r["enabled"] and proto_ok(r)], key=_policy_order)
            matching_url = [(r, m) for r in url_rules for m in [_generic_matches(r, dest)] if m
                            and (not request_method or not r["request_methods"] or request_method in r["request_methods"] or "ANY" in r["request_methods"])]
            unresolved = lambda r: r["scoped"] or (bool(r["request_methods"]) and "ANY" not in r["request_methods"] and not request_method)
            hit = next(((r, m) for r, m in matching_url if not unresolved(r)), None)
            scoped_before = []
            for r, _ in matching_url:
                if not unresolved(r):
                    break
                scoped_before.append(r)
            # Only a rule that would act differently makes the result depend on it.
            everyone_action = (hit[0]["action"] or "ALLOW") if hit else "ALLOW"
            scoped_before = [r for r in scoped_before if (r["action"] or "ALLOW") != everyone_action]
            if scoped_before:
                hops.append(_hop("url", "URL filtering", "conditional", None,
                                 "Higher-precedence URL rules depend on an unverified identity or request method. No later global rule is treated as a confirmed decision.",
                                 None, candidate_rules=[r for r, _ in matching_url],
                                 missing_context=(["identity / rule scope"] if any(r["scoped"] for r in scoped_before) else [])
                                                 + (["request method"] if any(r["request_methods"] and "ANY" not in r["request_methods"] and not request_method for r in scoped_before) else [])))
            elif hit:
                r, m = hit
                if r["action"] in BLOCK_ACTIONS:
                    ends = "url"
                    hops.append(_hop("url", "URL filtering", "blocked", {"name": r["name"], "id": r["id"], "order": r["order"], "action": r["action"]},
                                     f"'{r['name']}' blocks it (matched on {m}); first matching rule in order.", None))
                else:
                    hops.append(_hop("url", "URL filtering", "pass" if r["action"] in ("ALLOW",) else "warn", {"name": r["name"], "id": r["id"], "order": r["order"], "action": r["action"]},
                                     f"'{r['name']}' → {r['action'] or 'ALLOW'} (matched on {m}; first matching rule in order)" + (f", methods {', '.join(r['request_methods'])}" if r["request_methods"] else "") + ".",
                                     None))
            elif "url" in unread:
                hops.append(_hop("url", "URL filtering", "unknown", None, _unread_why(unread, "url", "URL filtering rules"), None))
            else:
                hops.append(_hop("url", "URL filtering", "pass", None, "No URL filtering rule matches; the default action applies (ALLOW unless the default rule was changed). URL Filtering is a data security control too: it can block or caution posts to a category, and can gate on a user risk profile.", None))

        # 7. SSL inspection
        if ends not in ("url", "cac"):
            if plaintext:
                hops.append(_hop("ssl", "SSL inspection", "na", None,
                                 "Not applicable: plain HTTP carries no TLS, so there is nothing to decrypt; every later control sees the full URL and the content.",
                                 None, why="plain HTTP"))
            elif ssl_out:
                hops.append(_hop("ssl", "SSL inspection", "out_of_scope", None,
                                 nis["ssl"] + " Whether this traffic is decrypted, and so whether DLP can see its content, is not assessed.", None, why="not in scope"))
            elif ssl_conditional:
                hops.append(_hop("ssl", "SSL inspection", "conditional", None,
                                 "Higher-precedence scoped SSL rules require identity evidence. Whether this traffic is decrypted, passed encrypted or blocked is conditional.",
                                 None, candidate_rules=exceptions + ([decided] if decided else []), missing_context=["identity / rule scope"]))
            elif decided is None and "ssl" in unread:
                hops.append(_hop("ssl", "SSL inspection", "unknown", None, _unread_why(unread, "ssl", "SSL inspection rules")
                                 + " Until then it is not known whether this traffic is decrypted.", None))
            elif decided is None:
                hops.append(_hop("ssl", "SSL inspection", "blind", None, "No enabled SSL inspection rule matches: the traffic is passed through encrypted and inline DLP cannot see its content.",
                                 _weak("high", "Not decrypted", "Add a DECRYPT rule for this traffic (or a catch-all decrypt rule after Zscaler Recommended Exemptions).")))
            elif ssl_unknown:
                hops.append(_hop("ssl", "SSL inspection", "unknown", {"id": decided["id"], "name": decided["name"], "action": decided["action"]},
                                 f"SSL rule '{decided['name']}' has unrecognized action '{decided['action']}'. Its decryption or blocking behavior is unknown; it is not assumed to pass encrypted.",
                                 None, why="SSL action not recognized"))
            elif decided["decision"] == "inspected":
                hops.append(_hop("ssl", "SSL inspection", "pass", {"name": decided["name"], "id": decided["id"], "order": decided["order"], "action": decided["action"]},
                                 f"'{decided['name']}' (order {decided['order']}) decrypts this traffic." + (f" Scoped exemptions ahead of it: {', '.join(e['name'] for e in exceptions)}." if exceptions else ""),
                                 _weak("medium", "Some users are exempt from decryption", "Confirm each exempted group is intended; Endpoint DLP should cover them.") if exceptions else None))
            elif decided["decision"] == "blocked":
                ends = "ssl"
                hops.append(_hop("ssl", "SSL inspection", "blocked", {"name": decided["name"], "id": decided["id"], "order": decided["order"], "action": decided["action"]},
                                 f"'{decided['name']}' blocks this traffic at the TLS handshake; nothing leaves.", None))
            else:
                hops.append(_hop("ssl", "SSL inspection", "blind", {"name": decided["name"], "id": decided["id"], "order": decided["order"], "action": decided["action"]},
                                 f"'{decided['name']}' (order {decided['order']}, {decided['action']}) leaves this traffic encrypted: inline DLP sees only the destination, not the content.",
                                 _weak("high" if dest.get("class") not in ("privacy",) else "info", "Left encrypted",
                                       "Move a DECRYPT rule above this exemption, or narrow the exemption to the categories it is meant for.")))

        # 9. File Type Control
        if ends not in ("ssl", "url", "cac"):
            ftc = [(r, _generic_matches(r, dest)) for r in sorted(zia["ftc"], key=_policy_order) if r["enabled"] and proto_ok(r)
                   and (not operation or r["operation"] in (operation, "", "ANY") or (r["operation"] == "UPLOAD_DOWNLOAD" and operation in ("UPLOAD", "DOWNLOAD")))
                   and (not file_types or not r["file_types"] or "ANY" in r["file_types"] or bool(file_types & set(r["file_types"])))]
            ftc = [(r, m) for r, m in ftc if m]
            if "ftc" in nis:
                hops.append(_hop("ftc", "File Type Control", "out_of_scope", None,
                                 nis["ftc"] + " Whether a file type rule limits uploads here is not assessed.", None, why="not in scope"))
            elif "ftc" in unread:
                hops.append(_hop("ftc", "File Type Control", "unknown", None, _unread_why(unread, "ftc", "File Type Control rules"), None))
            elif ssl_conditional:
                hops.append(_hop("ftc", "File Type Control", "conditional", None,
                                 "SSL applicability is conditional; file-type content inspection is not established.", None))
            elif ssl_out or ssl_unknown or (decided is None and "ssl" in unread):
                hops.append(_hop("ftc", "File Type Control", "unknown", None,
                                 "Whether file content is visible is not established; File Type Control is not evaluated.", None))
            elif not decrypted:
                hops.append(_hop("ftc", "File Type Control", "blind", None,
                                 "The traffic remains encrypted. File-type content inspection cannot be established.", None))
            elif ftc:
                r, m = ftc[0]
                missing = (["operation"] if not operation else []) + (["file type"] if not file_types else []) + (["identity / rule scope"] if r["scoped"] else [])
                if missing:
                    hops.append(_hop("ftc", "File Type Control", "conditional", None,
                                     f"'{r['name']}' is a candidate ({r['action']}); missing applicability evidence: {', '.join(missing)}. No file-type block is confirmed.",
                                     None, candidate_rules=[r for r, _ in ftc], missing_context=missing))
                else:
                    if r["action"] in BLOCK_ACTIONS:
                        ends = "ftc"
                    hops.append(_hop("ftc", "File Type Control", "blocked" if r["action"] in BLOCK_ACTIONS else "pass" if r["action"] == "ALLOW" else "warn",
                                     {"name": r["name"], "id": r["id"], "order": r.get("order"), "action": r["action"]},
                                     f"'{r['name']}' → {r['action']} for {', '.join(sorted(file_types))} on {operation.lower()} (matched on {m}; configuration prediction).", None))
            else:
                hops.append(_hop("ftc", "File Type Control", "none", None, "No File Type Control rule limits uploads here; bulk formats (spreadsheets, archives, databases) rely on DLP alone. File Type Control is a data security control: allow, caution or block whole file categories on upload/download.", None))

        # 11. Inline Web DLP
        covering: List[Dict[str, Any]] = []
        if ends not in ("ssl", "url", "cac", "ftc"):
            for r in zia["dlp"]:
                if not r["enabled"] or not proto_ok(r):
                    continue
                if r["catch_all"] or (set(r["url_categories"]) & set(cats)) or (set(r["cloud_applications"]) & set(apps)):
                    covering.append(r)
            ssl_unread = decided is None and "ssl" in unread
            if "dlp" in nis:
                hops.append(_hop("dlp", "Inline Web DLP", "out_of_scope", None,
                                 nis["dlp"] + " Whether a DLP rule inspects this content is not assessed.", None, why="not in scope"))
            elif ssl_out:
                hops.append(_hop("dlp", "Inline Web DLP", "out_of_scope", None,
                                 (f"{len(covering)} enabled Web DLP rule(s) would apply" if covering else "No enabled Web DLP rule targets this traffic")
                                 + ", but SSL inspection is not in scope on the Scope page, so whether the engines ever see the content is not assessed.",
                                 None, why="SSL inspection not in scope"))
            elif ssl_conditional:
                hops.append(_hop("dlp", "Inline Web DLP", "conditional", None,
                                 "SSL applicability depends on unresolved identity conditions; no content inspection is established.", None))
            elif not covering and "dlp" in unread and (decrypted or ssl_unread):
                hops.append(_hop("dlp", "Inline Web DLP", "unknown", None, _unread_why(unread, "dlp", "Web DLP rules"),
                                 _weak("medium", "Web DLP rules could not be read", "Check that the API role can read Web DLP rules (and is not rate-limited), then run the analysis again.")))
            elif ssl_unknown:
                hops.append(_hop("dlp", "Inline Web DLP", "unknown", None,
                                 "The SSL rule action is not recognized, so whether its content becomes available to DLP is unknown.", None))
            elif ssl_unread:
                hops.append(_hop("dlp", "Inline Web DLP", "unknown", None,
                                 f"{len(covering)} enabled Web DLP rule(s) would apply, but the SSL inspection rules could not be read, so whether the engines see the content is unknown." if covering
                                 else "The SSL inspection rules could not be read, so whether this content is decrypted, and so inspected, is unknown.", None))
            elif not decrypted:
                hops.append(_hop("dlp", "Inline Web DLP", "blind", None,
                                 f"{len(covering)} enabled Web DLP rule(s) would apply, but the content is encrypted: engines never see it." if covering
                                 else ("Encrypted: engines never see this content (the Web DLP rules could not be read either)." if "dlp" in unread else "Encrypted, and no Web DLP rule applies either."),
                                 _weak("high", "Inline DLP is blind here", "Decrypt this traffic first; the DLP rules are in place but cannot run.") if covering
                                 else _weak("high", "Inline DLP is blind here", "Decrypt this traffic first, then run the analysis again so the Web DLP rules can be read.") if "dlp" in unread else _weak("high", "Blind and ungoverned", "Decrypt this traffic and deploy a policy pack so a Web DLP rule covers it.")))
            elif not covering:
                hops.append(_hop("dlp", "Inline Web DLP", "none", None, "Decrypted, but no enabled Web DLP rule targets this traffic.",
                                 _weak("medium", "Ungoverned", "Deploy a policy pack (Deploy Policy Packs) or scope a Web DLP rule to this traffic; start in monitor mode.")))
            else:
                eligible = [r for r in covering if not r.get("scope")]
                enforcing = [r for r in eligible if r["enforcing"]]
                content = [r for r in eligible if not r["without_content_inspection"] and r.get("engines")]
                status = "conditional" if not eligible else "metadata_only" if not content else "enforce" if enforcing else "monitor"
                hops.append(_hop("dlp", "Inline Web DLP", status, {"name": eligible[0]["name"], "id": eligible[0]["id"], "action": eligible[0]["action"]} if eligible else None,
                                 f"{len(covering)} configured candidate rule(s): " + ", ".join(f"{r['name']} ({r['action']})" for r in covering[:5]) + ("…" if len(covering) > 5 else "")
                                 + (" No unscoped rule has both a referenced engine and content inspection enabled (check without-content-inspection)." if not content else "")
                                 + (" Identity-scoped rules are conditional until the applicable identity is established." if len(eligible) != len(covering) else "")
                                 + " No payload was submitted or scanned by this configuration analysis."
                                 + " Rules are evaluated in order and the first match applies, unless 'Evaluate all DLP rules' is on, in which case the most restrictive action wins and order only breaks ties.",
                                 _weak("low", "Monitor only", "Once tuned, move the high-confidence rules to BLOCK.") if not enforcing else (_weak("medium", "Rules run without content inspection", "Clear the without-content-inspection flag on at least one rule with an engine.") if not content else None),
                                 content_inspection_possible=bool(content),
                                 rules=[{"id": r["id"], "name": r["name"], "order": r.get("order"), "action": r["action"], "enforcing": r["enforcing"], "engines": r.get("engines") or [],
                                         "scope": r.get("scope") or [], "scope_items": r.get("scope_items") or {}, "without_content_inspection": r.get("without_content_inspection", False),
                                         "incident_receiver": bool(r.get("incident_receiver")), "icap_server": r.get("icap_server"), "notification_template": r.get("notification_template")} for r in covering]))

        # 13. After the match: logs, the incident receiver and Workflow Automation
        if ends not in ("ssl", "url", "cac", "ftc"):
            dlp_hop = next((h for h in hops if h["key"] == "dlp"), None)
            if dlp_hop and dlp_hop["status"] == "out_of_scope":
                hops.append(_hop("incident", "Logs & incidents", "out_of_scope", None,
                                 "Not assessed: the hops this depends on are not in scope on the Scope page, so whether a DLP match is logged or forwarded here is not traced.", None))
            elif dlp_hop and dlp_hop["status"] == "unknown":
                hops.append(_hop("incident", "Logs & incidents", "unknown", None,
                                 "Unknown: the rules this depends on could not be read, so whether a DLP rule logs or forwards a match here is not known.", None))
            elif not dlp_hop or dlp_hop["status"] in ("blind", "none"):
                hops.append(_hop("incident", "Logs & incidents", "none", None,
                                 "Only the web transaction log is written (Nanolog → Web Insights, and NSS / Cloud NSS feeds to your SIEM): no DLP rule fires here, so there is no DLP log line, no copy to the Incident Receiver and no Workflow Automation incident.", None))
            else:
                forwarders = [r for r in covering if r.get("incident_receiver")]
                icap = [r for r in covering if r.get("icap_server")]
                notifiers = [r for r in covering if r.get("notification_template") or r.get("auditor") or r.get("external_auditor_email")]
                hops.append(_hop("incident", "Logs & incidents", "conditional" if forwarders or icap else "warn",
                                 {"name": forwarders[0]["name"], "id": forwarders[0]["id"]} if forwarders else None,
                                 f"On a qualifying match, channel logs and configured forwarding may be produced. {len(forwarders)} candidate rule(s) enable Zscaler Incident Receiver; {len(icap)} name an ICAP server. "
                                 "An ICAP reference alone does not establish a supported Workflow Automation delivery path. Receiver, storage, event and WA integration readiness were not read; no delivery was observed. "
                                 f"{len(notifiers)} have auditor notification settings.",
                                 None if forwarders or icap else _weak("medium", "No evidence forwarding configured", "Verify a supported Incident Receiver delivery integration and its storage/event configuration before relying on Workflow Automation incidents."),
                                 forwarders=[r["name"] for r in forwarders], icap_forwarders=[r["name"] for r in icap],
                                 delivery_status="unverified", observed=False, notifiers=[r["name"] for r in notifiers]))

    # These are separate-channel inventories, never tests of the web payload.
    channels = {}
    labels = {"endpoint": "Endpoint DLP (on the device)", "saas": "SaaS Security API (at rest)", "email": "Outbound Email DLP"}
    for key, label in labels.items():
        rules = zia.get(key, [])
        enabled = [r for r in rules if r["state"] == "ENABLED"]
        state = "out_of_scope" if key in nis else "unknown" if key in unread else "inventory"
        detail = (nis[key] if key in nis else _unread_why(unread, key, label + " rules") if key in unread else
                  f"Inventory: {len(enabled)} enabled rule(s), {len(rules)} total. No {label} operation was tested; applicability and evidence delivery are unverified.")
        channels[key] = {"label": label, "status": state, "detail": detail, "weak_point": None,
                         "rules": [r["name"] for r in enabled] if state == "inventory" else [],
                         "rule_objects": [dict(r) for r in rules] if state == "inventory" else [],
                         "enabled_count": len(enabled) if state == "inventory" else None,
                         "evidence_mode": "inventory", "tested": False, "coverage": "unverified",
                         "forwarding_status": "unverified"}

    # Retain required controls even after an upstream stop; no extra reads.
    _retain_controls(hops, ends, nis)
    ssl_hop = next(h for h in hops if h["key"] == "ssl")
    if ssl_hop["status"] == "not_reached":
        decrypted = False
    for h in hops:
        h["evidence_mode"] = "configuration"
        h["observed"] = False

    # Policy pack overlay
    pack_rows = []
    for pk in packs or []:
        rows = []
        for pol in pk.get("policies", []):
            ch = pol.get("channel", "web")
            name = pol["name"]
            found = None
            pool = {"web": zia["dlp"], "endpoint": zia.get("endpoint", []), "saas": zia.get("saas", []), "email": zia.get("email", []),
                    "ssl": zia["ssl"], "url": zia["url"], "cloud_app": zia["cac"], "file_type": zia["ftc"]}.get(ch, [])
            for r in pool:
                if str(r.get("name")) == name:
                    found = r; break
            if _PACK_SECTION.get(ch) in nis:
                state = "not_in_scope"   # not read: never reported as missing
            elif not found:
                state = "missing"
            else:
                st = str(found.get("state") or "").upper()
                if st != "ENABLED":
                    state = "disabled"
                else:
                    act = str(found.get("action") or "").upper()
                    if ch == "web":
                        state = "enforcing" if found.get("enforcing") else "monitoring"
                    elif ch == "ssl":
                        state = "enforcing" if found.get("decision") == "inspected" else "monitoring"
                    elif ch == "cloud_app":
                        state = "enforcing" if any(a.startswith(("BLOCK", "ISOLATE")) for a in found.get("actions", [])) else "monitoring"
                    else:
                        state = "enforcing" if act in ("BLOCK", "CONFIRM", "CAUTION", "ISOLATE", "CUSTOMHEADERINSERTION") or (act.startswith("OFLCASB") and "REPORT" not in act and "ALLOW" not in act) else "monitoring"
            on_path = any(h["key"] in ("dlp", "ssl", "url", "cac", "ftc", "incident") and h.get("decided_by") and h["decided_by"].get("name") == name for h in hops) \
                or (ch == "web" and any(name == rr["name"] for h in hops if h["key"] == "dlp" for rr in h.get("rules", [])))
            rows.append({"name": name, "channel": ch, "state": state, "on_path": on_path and state != "not_in_scope"})
        counts = {}
        for r in rows:
            counts[r["state"]] = counts.get(r["state"], 0) + 1
        weak = None
        if counts.get("missing"):
            weak = f"{counts['missing']} rule(s) not deployed"
        elif counts.get("disabled"):
            weak = f"{counts['disabled']} rule(s) still disabled"
        elif not any(r["on_path"] for r in rows if r["channel"] == "web") and reaches_zscaler and decrypted:
            weak = "no rule of this pack sees this traffic"
        pack_rows.append({"id": pk["id"], "name": pk.get("name") or pk["id"], "rules": rows, "counts": counts, "weak_point": weak,
                          "coverage": "not_in_scope" if rows and counts.get("not_in_scope") == len(rows) else
                                      "enforcing" if counts.get("enforcing") and not counts.get("missing") else ("monitoring" if counts.get("monitoring") and not counts.get("missing") else ("partial" if counts.get("enforcing") or counts.get("monitoring") else ("deployed" if not counts.get("missing") else "missing")))})

    weak_points = [dict(h["weak_point"], hop=h["key"], hop_label=h["label"]) for h in hops if h.get("weak_point")]
    weak_points += [dict(c["weak_point"], hop=k, hop_label=c["label"]) for k, c in channels.items() if c.get("weak_point")]
    sev_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    weak_points.sort(key=lambda w: sev_order.get(w["severity"], 9))
    conditional = any(h["key"] in ("zcc", "forwarding") and h["status"] in ("unknown", "warn", "conditional") and not h.get("decided_by") for h in hops)
    conditional = conditional or any(h["key"] == "forwarding" and h["status"] == "unknown" for h in hops)
    conditional = conditional or any(h["key"] == "pac" and h["status"] == "unknown" for h in hops)
    outcome = ("bypassed" if not reaches_zscaler else "unknown" if conditional else "blocked" if ends in ("ssl", "url", "cac", "ftc") else
               "unknown" if any(h["key"] == "dlp" and h["status"] == "unknown" for h in hops) else
               "out_of_scope" if any(h["key"] == "dlp" and h["status"] == "out_of_scope" for h in hops) else
               "conditional" if any(h["key"] == "dlp" and h["status"] == "conditional" for h in hops) else
               "blind" if not decrypted else next((h["status"] for h in hops if h["key"] == "dlp"), "none"))
    return {"destination": dest, "network": network, "platform": platform, "hops": hops, "channels": channels, "packs": pack_rows,
            "weak_points": weak_points, "outcome": outcome, "reaches_zscaler": reaches_zscaler, "decrypted": decrypted,
            "not_in_scope": nis, "conditional": conditional, "plaintext": plaintext,
            "policy_conditional": any(h["status"] == "conditional" and h["key"] != "incident" for h in hops),
            "tested_channel": "web", "evidence_mode": "configuration", "content_inspected": False,
            "content_inspection_possible": bool(decrypted and not ends and any(h.get("content_inspection_possible") for h in hops)),
            "connector_inventory": connector_references(zcc), "required_controls": zia.get("required_controls", (scope or {}).get("required_controls", []))}


# A policy pack rule's channel → the section of the read it would be found in.
_PACK_SECTION = {"web": "dlp", "endpoint": "endpoint", "saas": "saas", "email": "email", "ssl": "ssl", "url": "url",
                 "cloud_app": "cac", "file_type": "ftc"}


# ── Report ────────────────────────────────────────────────────────────
def load_packs() -> List[Dict[str, Any]]:
    try:
        from dlp_importer import discover_packs
        out = []
        for p in discover_packs():
            try:
                with open(f"{p['dir']}/configs/dlp_policies.json", encoding="utf-8") as fh:
                    pols = json.load(fh)
            except Exception:  # noqa: BLE001
                pols = []
            out.append({"id": p["id"], "name": p.get("name") or p["id"], "policies": [{"name": x.get("name"), "channel": x.get("channel", "web")} for x in pols]})
        return out
    except Exception:  # noqa: BLE001
        return []


VISIBILITY = ("blocked", "unverified", "bypassed", "blind", "enforce", "monitor", "decrypted")


def visibility(t: Dict[str, Any]) -> str:
    """The one visibility class of a traced path, in the order the Data
    Flow Map's page decides it (static/data_flow.js _dfVisibility):
    blocked, unverified (routing or inspection evidence unavailable, out of
    scope or conditional), bypassed, blind (reaches ZIA encrypted),
    enforce, monitor, else decrypted (no DLP decision either way)."""
    if t.get("outcome") == "blocked":
        return "blocked"
    if t.get("conditional") or t.get("policy_conditional") or any(
            h.get("key") == "ssl" and h.get("status") in ("unknown", "out_of_scope", "conditional") for h in t.get("hops") or []):
        return "unverified"
    if not t.get("reaches_zscaler"):
        return "bypassed"
    if not t.get("decrypted"):
        return "blind"
    return {"enforce": "enforce", "monitor": "monitor"}.get(t.get("outcome"), "decrypted")


def generate_data_flow_report(client, destinations: Optional[Sequence[str]] = None, platform: str = "windows", *,
                              scope: Optional[Dict[str, Any]] = None, cancel: Any = None) -> Dict[str, Any]:
    """Read the tenant once, trace every traffic class (or the given
    destinations) for every network context, and summarise. With a
    `scope` (path_scope: the Scope page's selection) only what is in scope
    is read, and every part out of scope is drawn "not in scope"; None
    reads every section (tests and tools only, the server always passes
    the Scope page's). `cancel` (Stop) ends the read between requests."""
    with stop_on(client, cancel):
        zcc = read_client_connector(client, scope=scope, cancel=cancel, platform=platform)
        zia = read_zia(client, scope=scope, cancel=cancel)
    packs = load_packs()
    dests = list(destinations) if destinations else [k["key"] for k in TRAFFIC_CLASSES]
    traces = []
    failed: List[Dict[str, Any]] = []
    for d in dests:
        rd = resolve_destination(d, zia)
        for net in NETWORKS:
            # One destination the tracer cannot handle must not take the
            # whole map down: it is reported in the diagnostics instead.
            try:
                traces.append(trace(rd, net["key"], platform, zcc, zia, packs, scope=scope))
            except Exception as e:  # noqa: BLE001
                failed.append({"section": f"trace {rd.get('label') or d} ({net['key']})", "error_type": type(e).__name__, "error": str(e)[:200]})
    if not traces and failed:
        raise RuntimeError(f"no path could be traced: {failed[0]['error_type']}: {failed[0]['error']}")
    # Every path in exactly one visibility class (the page's own classes,
    # static/data_flow.js _dfVisibility), so the counts add up to `traces`.
    vis = [visibility(t) for t in traces]
    summary = {
        "destinations": len(dests), "traces": len(traces),
        "bypassed": vis.count("bypassed"),
        # Left encrypted: an SSL rule (or no rule) passes it through. SSL
        # inspection not in scope, unread or conditional, and a path whose
        # policy depends on who the user is, are "unverified" instead.
        "blind": vis.count("blind"),
        "enforced": vis.count("enforce"),
        "monitored": vis.count("monitor"),
        "blocked": vis.count("blocked"), "unverified": vis.count("unverified"), "decrypted_other": vis.count("decrypted"),
        "high": sum(1 for t in traces for w in t["weak_points"] if w["severity"] == "high"),
        "app_profiles": len(zcc["app_profiles"]), "forwarding_profiles": len(zcc["forwarding_profiles"]),
        "trusted_networks": len(zcc["trusted_networks"]), "pac_files": len(zcc["pac_files"]),
    }
    return {"summary": summary, "required_controls": zia.get("required_controls", []), "platform": platform, "networks": NETWORKS, "platforms": PLATFORMS,
            "destinations": [{"key": k["key"], "label": k["label"], "why": k.get("why", "")} for k in TRAFFIC_CLASSES],
            "traces": traces, "client_connector": zcc, "packs": [{"id": p["id"], "name": p["name"], "rules": len(p["policies"])} for p in packs],
            "diagnostics": zia.get("diagnostics", []) + [{"section": "Client Connector", "error": e} for e in zcc.get("errors", [])] + failed,
            # The scope the read was made for: its key (so the Path analyzer
            # reuses this read only for the same scope) and what it says.
            "path_scope": (scope or {}).get("key"),
            "scope": ({"summary": scope.get("summary"), "read": list(scope.get("read") or []), "not_in_scope": dict(scope.get("not_in_scope") or {}),
                       "source": scope.get("source") or "", "required_controls": zia.get("required_controls", []), "read_blocked": dict(scope.get("read_blocked") or {})} if scope else None),
            "snapshot": {"zia": dict({k: zia[k] for k in ("ssl", "dlp", "url", "cac", "ftc", "endpoint", "saas", "email", "catalogue")},
                                     not_in_scope=zia.get("not_in_scope") or {}, required_controls=zia.get("required_controls", [])),
                         "categories": {k: {"id": v.get("id"), "name": v.get("configured_name") or v.get("name"), "urls": v.get("urls"), "db_categorized_urls": v.get("db_categorized_urls") or v.get("dbCategorizedUrls")}
                                        for k, v in (zia.get("categories") or {}).items() if isinstance(v, dict)}},
            "sources": {"client_connector": "/zcc/webPolicies, /zcc/forwardingProfiles, /zcc/trustedNetworks", "pac": "/zia/pacFiles",
                        "zia": "/zia/sslInspectionRules, /zia/urlFilteringRules, /zia/cloudApplicationRules, /zia/fileTypeRules, /zia/webDlpRules, /zia/endPointDlpRules, /zia/casbDlpRules/all, /zia/emailDlpRules, /zia/cloudApplications/policy, /zia/urlCategories",
                        "order": "Zscaler, Understanding Policy Enforcement (help.zscaler.com/zia/understanding-policy-enforcement): request = Browser Control, FTP Control, URL & Cloud App Control, SSL inspection, Malware Protection, Advanced Threat Protection, upload File Type Control, upload Bandwidth Control, DLP, Firewall & DNS Control; response in reverse; first violation ends the transaction"}}


def trace_from_report(report: Dict[str, Any], destination: str, network: str, platform: str) -> Dict[str, Any]:
    """Trace a destination the user typed against a stored report (no tenant call)."""
    zia = dict(report["snapshot"]["zia"])
    zia["categories"] = report["snapshot"].get("categories") or {}
    zia.setdefault("unread", unread_sections(report.get("diagnostics")))
    for r in zia.get("dlp", []):
        r.setdefault("enforcing", str(r.get("action", "")).upper() in ("BLOCK", "CONFIRM", "ICAP_RESPONSE"))
        r.setdefault("without_content_inspection", False)
    rd = resolve_destination(destination, zia)
    if network not in {n["key"] for n in NETWORKS}:
        network = "off"
    return trace(rd, network, platform if platform in PLATFORMS else "windows", report["client_connector"], zia, load_packs())


def to_markdown(report: Dict[str, Any], label: str = "") -> str:
    raw = report
    report, label = md_safe.escape_data(report), md_safe.text(label)   # destination and tenant names: inert text
    s = report["summary"]
    lines = [f"# Data Flow Map{' — ' + label if label else ''}", "",
             f"{s['traces']} paths traced ({s['destinations']} destinations × {len(report['networks'])} network contexts, {report['platform']}). "
             f"Never reach Zscaler: {s['bypassed']}. Reach ZIA, left encrypted: {s['blind']}. Decrypted, a DLP rule can block: {s['enforced']}. "
             f"Decrypted, DLP monitors only: {s['monitored']}. High-severity weak points: {s['high']}. Configuration only: no traffic was observed.", ""]
    for t in report["traces"]:
        net = next(n["label"] for n in NETWORKS if n["key"] == t["network"])
        lines.append(f"## {t['destination']['label']} · {net} → {t['outcome']}")
        for h in t["hops"]:
            lines.append(f"- **{h['label']}** [{h['status']}] {h['detail']}")
            if h.get("weak_point"):
                lines.append(f"  - Weak point ({h['weak_point']['severity']}): {h['weak_point']['title']} — {h['weak_point']['fix']}")
        for k, c in t["channels"].items():
            lines.append(f"- *{c['label']}* [{c['status']}] {c['detail']}")
        for p in t["packs"]:
            lines.append(f"- Pack {p['name']}: {p['coverage']}" + (f" — {p['weak_point']}" if p.get("weak_point") else ""))
        lines.append("")
    import dlp_analysis
    lines.extend(dlp_analysis.markdown(raw))
    return "\n".join(lines)
