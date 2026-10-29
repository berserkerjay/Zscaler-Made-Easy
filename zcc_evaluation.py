"""Strict Client Connector evaluation against Zscaler best practice.

Section 1 of the assessment already asks the basic questions (portal
reachable, bypass counts, strict enforcement, tamper passwords). These
checks read the same objects field by field, with the names the Client
Connector API actually uses (web/policy, webForwardingProfile,
webTrustedNetwork, webFailOpenPolicy, getWebPrivacyInfo, getCompanyInfo,
getDevices) and the ZIA DLP notification templates, and fail a profile
for every setting Zscaler's deployment, Z-Tunnel 2.0, bypass, PAC, update
and VPN-interoperability guidance says should be on.

Every check names the profiles or objects at fault and the setting to
change, and cites the guidance it applies. Read-only.
"""
from __future__ import annotations

import functools
import json
import re
from typing import Any, Dict, List, Optional, Tuple

# Zscaler guidance the checks apply (keys of zscaler_best_practices).
_BP_FALLBACK = {
    "zcc_deployment": "https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-deployment",
    "zcc_ztunnel2": "https://help.zscaler.com/zscaler-client-connector/best-practices-deploying-z-tunnel-2.0",
    "zcc_bypass": "https://help.zscaler.com/zscaler-client-connector/best-practices-adding-bypasses-z-tunnel-2.0",
    "zcc_pac": "https://help.zscaler.com/zscaler-client-connector/best-practices-using-pac-files-zscaler-client-connector",
    "zcc_updates": "https://help.zscaler.com/zscaler-client-connector/best-practices-updating-latest-version-zscaler-client-connector-application",
    "zcc_vpn_interop": "https://help.zscaler.com/zscaler-client-connector/best-practices-zscaler-client-connector-and-vpn-client-interoperability",
    "zia_ssl_leading": "https://help.zscaler.com/zscaler-deployments-operations/zia-ssl-inspection-leading-practices-guide",
    "zia_policy_leading": "https://help.zscaler.com/zscaler-deployments-operations/zia-policy-leading-practices-guide",
}


def _bp(key: str) -> str:
    try:
        from zscaler_best_practices import BEST_PRACTICES
        for e in BEST_PRACTICES:
            if e.get("key") == key and e.get("url"):
                return str(e["url"])
    except Exception:  # noqa: BLE001
        pass
    return _BP_FALLBACK.get(key, "")


def _ref(key: str) -> str:
    u = _bp(key)
    return f" Best practice: {u}" if u else ""


# ── field access ───────────────────────────────────────────────────────
_NON_ALNUM = re.compile(r"[^a-z0-9]")


@functools.lru_cache(maxsize=8192)
def _norm_text(k: str) -> str:
    return _NON_ALNUM.sub("", k.lower())


def _norm(k: Any) -> str:
    """A field name compared without case or punctuation. Cached: a large
    fleet repeats the same few dozen names on every device record."""
    return _norm_text(k if isinstance(k, str) else str(k))


def _truthy(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    return str(v).strip().lower() in ("1", "true", "yes", "on", "enabled", "enable")


def _falsy_set(v: Any) -> bool:
    """The field is present and explicitly off (distinct from unknown)."""
    return v is not None and not _truthy(v)


def flatten_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    """One flat dict per app profile: the top-level fields, whatever the
    platform sub-policies (windowsPolicy, macPolicy …) carry, and the
    policyExtension blob (a JSON string on most tenants) — top level wins."""
    out: Dict[str, Any] = {}
    ext = p.get("policyExtension") or p.get("policy_extension")
    if isinstance(ext, str):
        try:
            ext = json.loads(ext)
        except Exception:  # noqa: BLE001
            ext = None
    if isinstance(ext, dict):
        out.update(ext)
    for k, v in p.items():
        if isinstance(v, dict) and re.search(r"policy$|config$", str(k), re.I) and not re.search(r"extension", str(k), re.I):
            for kk, vv in v.items():
                out.setdefault(kk, vv)
    for k, v in p.items():
        if not (isinstance(v, dict) and re.search(r"policy$|config$", str(k), re.I)):
            out[k] = v
    return out


class FieldIndex(dict):
    """A record's fields keyed by their normalised name, built once so the
    many _v lookups on one device of a large fleet do not rebuild it."""


def field_index(d: Dict[str, Any]) -> FieldIndex:
    return d if isinstance(d, FieldIndex) else FieldIndex((_norm(k), v) for k, v in d.items())


def _v(d: Dict[str, Any], *names: str, default: Any = None) -> Any:
    idx = field_index(d)
    for n in names:
        v = idx.get(_norm(n))
        if v is not None and v != "":
            return v
    return default


_PLAT = {"1": "iOS", "2": "Android", "3": "Windows", "4": "macOS", "5": "Linux", "ios": "iOS", "android": "Android", "windows": "Windows", "win": "Windows",
         "mac": "macOS", "macos": "macOS", "linux": "Linux"}


def code_text(v: Any) -> str:
    """A state or type code as the API may send it, as plain lower-case
    text: 3, "3", 3.0, "3.0" and " 3 " are all "3"; "DEVICE_TYPE_WINDOWS"
    is "windows"."""
    if v is None or isinstance(v, bool):
        return "" if v is None else str(v).lower()
    s = str(v).strip().lower()
    m = re.fullmatch(r"(\d+)\.0*", s)
    if m:
        return str(int(m.group(1)))
    return s.removeprefix("device_type_")


def _plat(p: Dict[str, Any]) -> str:
    raw = _v(p, "device_type", "deviceType", "os", "platform", "osType", default="")
    return _PLAT.get(code_text(raw), str(raw) or "?")


def device_platform(d: Dict[str, Any]) -> str:
    """The platform of an enrolled device: the numeric device type (1 iOS,
    2 Android, 3 Windows, 4 macOS, 5 Linux — zscaler-sdk-python
    utils.zcc_param_map, as a number, a string or DEVICE_TYPE_<OS>), else
    the OS text."""
    t = code_text(_v(d, "type", "device_type", "deviceType", default=""))
    if t in _PLAT:
        return _PLAT[t]
    txt = str(_v(d, "osType", "platform", "os", "osVersion", default="") or "").lower()
    # "darwin" holds "win": the Apple names are matched first, Windows only at a word start.
    for k, v in (("darwin", "macOS"), ("mac", "macOS"), ("iphone", "iOS"), ("ipad", "iOS"), ("ios", "iOS"), ("android", "Android"),
                 ("linux", "Linux")):
        if k in txt:
            return v
    if re.search(r"\bwin", txt):
        return "Windows"
    return "?"


# The oldest Client Connector release Zscaler still supports on each
# platform (the latest release, the two before it and the current LTS), from
# https://help.zscaler.com/product-usage-terms/supported-versions — Windows
# 4.7 (LTS), macOS 4.5.2 (LTS), Linux 3.7.2 (LTS) and 4.2, iOS 4.4.4,
# Android 4.0. The LTS moves: keep these in step with that page.
ZCC_MIN_SUPPORTED = {"Windows": (4, 7), "macOS": (4, 5, 2), "Linux": (3, 7, 2), "iOS": (4, 4, 4), "Android": (4, 0)}
ZCC_SUPPORTED_REF = "https://help.zscaler.com/product-usage-terms/supported-versions"


VERSION_PARTS = 4


def version_tuple(v: Any) -> Tuple[int, ...]:
    """A version as a tuple that compares semantically: up to four numeric
    parts, padded with zeros (so 4.7 and 4.7.0 are equal and 4.10 is newer
    than 4.9); () when there is no number. Each part keeps at most nine
    digits, so a hostile string cannot exhaust int() (CWE-400)."""
    parts = [int(x[:9]) for x in re.findall(r"\d+", str(v if v is not None else "")[:200])[:VERSION_PARTS]]
    return tuple(parts + [0] * (VERSION_PARTS - len(parts))) if parts else ()


def zcc_unsupported(platform: str, version: Any) -> bool:
    """True when this client version is older than every release Zscaler
    supports on the platform. Linux supports only the 3.7.2 LTS and 4.2+."""
    t = version_tuple(version)
    mn = ZCC_MIN_SUPPORTED.get(platform)
    if not t or not mn:
        return False
    if platform == "Linux":
        return not (t[:3] == (3, 7, 2) or t[:2] >= (4, 2))
    return t < mn


def _name(p: Dict[str, Any]) -> str:
    return f"{_v(p, 'name', 'policyName', default='?')} ({_plat(p)})"


def _active(p: Dict[str, Any]) -> bool:
    a = _v(p, "active", "enabled", "state")
    return True if a is None else _truthy(a) or str(a).upper() == "ENABLED"


def _rt():
    from dlp_assessment_full_auto import R, _g, _ls
    return R, _g, _ls


def _profiles(cl):
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/appProfiles", "AppProfiles")
    if e:
        return None, e
    out = [flatten_profile(p) for p in d if isinstance(p, dict) and _active(flatten_profile(p))]
    if not out:
        # Nothing to assess is not a pass: "all 0 profile(s)" never counts as configured.
        return None, R(R.INFO, "No active Client Connector app profile was returned, so this setting could not be assessed.")
    return out, None


def _fwd_profiles(cl):
    """The forwarding profiles, or (None, result) when they cannot be read
    or none was returned (nothing to assess is not a pass)."""
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/forwardingProfiles", "FwdProfiles")
    if e:
        return None, e
    fps = [x for x in d if isinstance(x, dict)]
    if not fps:
        return None, R(R.INFO, "No Client Connector forwarding profile was returned, so this setting could not be assessed.")
    return fps, None


def _list(cl, ep: str) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    _, _, _ls = _rt()
    d, c = cl.get(ep)
    return ([x for x in _ls(d) if isinstance(x, dict)] if c in (200, 204) else []), c


def _read_one(cl, ep: str) -> Tuple[Dict[str, Any], Optional[int]]:
    """(the object, HTTP code) of a single-object read; {} when it was not answered."""
    _, _, _ls = _rt()
    d, c = cl.get(ep)
    if c not in (200, 204):
        return {}, c
    items = [x for x in _ls(d) if isinstance(x, dict)]
    return (items[0] if items else d if isinstance(d, dict) else {}), c


def _one(cl, ep: str) -> Dict[str, Any]:
    return _read_one(cl, ep)[0]


def _unreadable(what: str, call: str, code: Optional[int]) -> str:
    """'<what>: not readable (<call>) (HTTP 403).': the status is named, so a refused read is classed as not permitted."""
    return f"{what}: not readable ({call})" + (f" (HTTP {code})" if code not in (200, 204, None) else "") + "."


def _verdict(R, fails: List[str], warns: List[str], ok: str, ref: str, fail_status=None):
    if fails:
        return R(fail_status or R.FAIL, "; ".join(fails) + "." + (" Also: " + "; ".join(warns) + "." if warns else "") + ref)
    if warns:
        return R(R.WARN, "; ".join(warns) + "." + ref)
    return R(R.PASS, ok + ref)


# ── app profile checks ─────────────────────────────────────────────────
def z_anti_tampering(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    # Enable Anti-tampering is a Windows app-profile setting only; the other
    # platforms have no such switch, so they are not applicable here.
    win = [p for p in profiles if _plat(p) in ("Windows", "?")]
    other = len(profiles) - len(win)
    na = f" {other} non-Windows profile(s) not applicable (anti-tampering is a Windows setting)." if other else ""
    off = [_name(p) for p in win if not _truthy(_v(p, "enableAntiTampering", "antiTampering"))]
    company = _one(cl, "/zcc/companyInfo")
    warns = []
    if company and _falsy_set(_v(company, "enableAntiTampering")):
        warns.append("anti-tampering is off at the company level")
    if not win and not warns:
        return R(R.INFO, "No Windows app profile: anti-tampering is a Windows setting." + _ref("zcc_deployment"))
    return _verdict(R, [f"anti-tampering OFF on {len(off)} Windows profile(s): {', '.join(off[:6])}"] if off else [], warns,
                    f"Anti-tampering on all {len(win)} Windows profile(s): the client cannot be stopped or its files altered by the user.{na}", _ref("zcc_deployment"))


# disablePassword (disable_password on the Windows policy) is the "Disable
# Password ZIA" field; the app-profile models have no ziaDisablePassword
# (zscaler-sdk-python zcc/models/webpolicy.py).
_PW = [("uninstallPassword", "uninstall"), ("disablePassword", "disable"),
       ("zpaDisablePassword", "disable Private Access"), ("zdpDisablePassword", "disable Data Protection"), ("zdxDisablePassword", "disable Digital Experience"),
       ("exitPassword", "exit"), ("logoutPassword", "logout")]


def z_disable_passwords(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    fails, warns = [], []
    for p in profiles:
        missing = [label for key, label in _PW if not str(_v(p, key, key.replace("Password", "_password"), key.replace("Password", "Pass"), default="") or "").strip()]
        core = [m for m in missing if m in ("uninstall", "disable")]
        if core:
            fails.append(f"{_name(p)}: no {', '.join(core)} password")
        elif missing:
            warns.append(f"{_name(p)}: no {', '.join(missing)} password")
    return _verdict(R, fails, warns, f"Every service on all {len(profiles)} profile(s) needs a password to be disabled, exited or uninstalled.", _ref("zcc_deployment"))


def z_log_level(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    debug = [_name(p) for p in profiles if "debug" in str(_v(p, "logLevel", "logMode", default="")).lower() or _truthy(_v(p, "enableVerboseLog"))]
    big = [_name(p) for p in profiles if isinstance(_v(p, "logFileSize"), (int, float)) and _v(p, "logFileSize") > 100]
    return _verdict(R, [], ([f"debug or verbose logging left on: {', '.join(debug[:6])} (fills disks, slows the client; use Info outside a troubleshooting window)"] if debug else [])
                    + ([f"log file size above 100 MB on {', '.join(big[:4])}"] if big else []),
                    f"Log level is Info or lower on all {len(profiles)} profile(s).", _ref("zcc_deployment"))


def _quic_blocked(cl) -> str:
    """How ZIA blocks QUIC for Z-Tunnel 2.0 traffic, or "": an enabled
    Firewall Filtering rule that blocks the QUIC network service, or a DNS
    Control rule that blocks the HTTPS record type
    (https://help.zscaler.com/zia/managing-quic-protocol)."""
    def on(r):
        return str(_v(r, "state", default="ENABLED")).upper() == "ENABLED" and str(_v(r, "action", default="")).upper().startswith("BLOCK")
    fw, _ = _list(cl, "/zia/firewallFilteringRules")
    for r in fw:
        svc = [str((x.get("name") or x.get("id")) if isinstance(x, dict) else x).upper() for x in (_v(r, "nwServices", default=[]) or []) + (_v(r, "nwServiceGroups", default=[]) or [])]
        if on(r) and any("QUIC" in s for s in svc):
            return f"Firewall Filtering rule '{_v(r, 'name', default='?')}' blocks QUIC"
    dns, _ = _list(cl, "/zia/firewallDnsRules")
    for r in dns:
        if on(r) and "HTTPS" in {str(t).upper() for t in (_v(r, "dnsRuleRequestTypes", default=[]) or [])}:
            return f"DNS Control rule '{_v(r, 'name', default='?')}' blocks the HTTPS record type"
    return ""


def z_quic(cl):
    """Drop QUIC Traffic is an iOS and Android app-profile setting for
    Z-Tunnel 1.0. With Z-Tunnel 2.0 (Windows, macOS), Zscaler blocks QUIC
    with a Firewall Filtering rule or a DNS Control HTTPS-record block."""
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    fps = {str(fp.get("id")): fp for fp in _list(cl, "/zcc/forwardingProfiles")[0]}

    def zt1(p):
        fp = fps.get(str(_v(p, "forwardingProfileId", default="")))
        return True if not fp else any(a.get("mode_label") == "Z-Tunnel 1.0" for a in _actions(fp).values())
    mobile = [p for p in profiles if _plat(p) in ("iOS", "Android")]
    desktop = [p for p in profiles if p not in mobile]
    off = [_name(p) for p in mobile if zt1(p) and not _truthy(_v(p, "dropQuicTraffic", "blockQuic"))]
    fails = [f"Drop QUIC Traffic is off on {len(off)} iOS/Android profile(s) using Z-Tunnel 1.0: {', '.join(off[:6])} (HTTP/3 over UDP is not decrypted, so inline DLP and SSL inspection miss it)"] if off else []
    warns, how = [], ""
    if desktop:
        how = _quic_blocked(cl)
        if not how:
            warns.append(f"{len(desktop)} Windows/macOS profile(s) rely on ZIA to block QUIC, but no enabled Firewall Filtering rule blocks the QUIC network service (UDP 443 and 80) and no DNS Control rule blocks the HTTPS record type; add one ahead of broad allow rules")
    ok = "QUIC is blocked" + (f": {how}" if how else "") + (f"; Drop QUIC Traffic on all {len(mobile)} iOS/Android profile(s)" if mobile else "") + "."
    return _verdict(R, fails, warns, ok, " Ref: https://help.zscaler.com/zia/managing-quic-protocol")


def z_fail_open(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    fails, warns = [], []
    for p in profiles:
        tf = _v(p, "zccTunnelFailPolicy", "tunnelFailPolicy")
        af = _v(p, "zccAppFailOpenPolicy", "appFailOpenPolicy")
        if _truthy(af) and _truthy(_v(p, "strictEnforcement", "strictMode")):
            warns.append(f"{_name(p)}: strict enforcement with app fail-open (the device goes direct when the client fails)")
        if tf is not None and str(tf) in ("0", "FAIL_OPEN", "fail_open", "open"):
            warns.append(f"{_name(p)}: tunnel failure policy is fail-open")
        if _truthy(_v(p, "zccFailCloseSettingsLockdownOnTunnelProcessExit")) is False and _truthy(_v(p, "enableZCCFailCloseSettingsForSEMode")):
            warns.append(f"{_name(p)}: fail-close does not lock down when the tunnel process exits")
    pol = _one(cl, "/zcc/failOpenPolicy")
    if pol:
        if _truthy(_v(pol, "enableFailOpen")):
            warns.append("company fail-open policy is ON: when the tunnel cannot be built the device goes direct")
        if _falsy_set(_v(pol, "enableWebSecOnTunnelFailure")):
            fails.append("web security is disabled on tunnel failure (traffic bypasses ZIA when the tunnel drops)")
        if _falsy_set(_v(pol, "enableWebSecOnProxyUnreachable")):
            warns.append("web security is disabled when the proxy is unreachable")
        m = _v(pol, "captivePortalWebSecDisableMinutes")
        try:
            if m is not None and int(m) > 10:
                warns.append(f"captive-portal detection disables web security for {int(m)} minutes (keep it at or below 10)")
        except (TypeError, ValueError):
            pass
        if _falsy_set(_v(pol, "enableStrictEnforcementPrompt")):
            warns.append("strict-enforcement prompt is off, so users get no explanation when the client blocks the network")
    return _verdict(R, fails, warns, "Fail-close: the device does not go direct when the tunnel or the proxy fails, and captive-portal windows are short.", _ref("zcc_deployment"))


def z_revert(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    fails = [f"{_name(p)}: users can revert to the previous client version without a password" for p in profiles
             if _truthy(_v(p, "enableZCCRevert")) and not str(_v(p, "zccRevertPassword", default="") or "").strip()]
    return _verdict(R, fails, [], "Client revert is either off or password-protected on every profile.", _ref("zcc_updates"))


def z_adapters(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    warns = []
    for p in profiles:
        if _falsy_set(_v(p, "interceptZIATrafficAllAdapters")):
            warns.append(f"{_name(p)}: ZIA traffic is not intercepted on all adapters (a VPN adapter can carry traffic around Zscaler)")
        if _falsy_set(_v(p, "enableSetProxyOnVPNAdapters")) and _v(p, "vpnGateways"):
            warns.append(f"{_name(p)}: VPN gateways are bypassed but the proxy is not set on VPN adapters")
        gws = _v(p, "vpnGateways", "vpnGatewayBypasses", default=[]) or []
        if isinstance(gws, list) and len(gws) > 5:
            warns.append(f"{_name(p)}: {len(gws)} VPN gateway bypasses (review each against the VPN interoperability guidance)")
    return _verdict(R, [], warns, f"Traffic is intercepted on every adapter on all {len(profiles)} profile(s).", _ref("zcc_vpn_interop"))


def z_disable_window(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    warns, fails = [], []
    for p in profiles:
        m = _v(p, "reactivateWebSecurityMinutes")
        try:
            if m is not None and int(m) > 60:
                fails.append(f"{_name(p)}: web security can stay disabled for {int(m)} minutes")
        except (TypeError, ValueError):
            pass
        if _truthy(_v(p, "allowZiaDisableWithoutPassword")) or _truthy(_v(p, "allowZpaDisableWithoutPassword")):
            fails.append(f"{_name(p)}: a service can be disabled without a password")
        if _falsy_set(_v(p, "sendDisableServiceReason")):
            warns.append(f"{_name(p)}: users are not asked for a reason when they disable a service")
        a = _v(p, "reactivateAntiTamperingTime")
        try:
            if a is not None and int(a) > 60:
                warns.append(f"{_name(p)}: anti-tampering can stay off for {int(a)} minutes")
        except (TypeError, ValueError):
            pass
    return _verdict(R, fails, warns, "A disabled service re-enables itself within the hour and every disable needs a password.", _ref("zcc_deployment"))


def z_bypass_hygiene(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    warns, fails = [], []
    for p in profiles:
        excl = _v(p, "packetTunnelExcludeList", default="") or ""
        excl_l = [x.strip() for x in (excl.split(",") if isinstance(excl, str) else excl) if str(x).strip()]
        # Wider than a /16 and not one of the private ranges Zscaler itself excludes.
        private = re.compile(r"^(10\.0\.0\.0/8|172\.16\.0\.0/12|192\.168\.0\.0/16|100\.64\.0\.0/10|169\.254\.0\.0/16|127\.0\.0\.0/8|224\.0\.0\.0/4|fc00::/7|fe80::/10)$", re.I)
        broad = [x for x in excl_l if re.search(r"/([0-9]|1[0-5])$|^0\.0\.0\.0", str(x)) and not private.match(str(x).strip())]
        if broad:
            fails.append(f"{_name(p)}: destination exclusions wider than a /16: {', '.join(broad[:4])}")
        elif len(excl_l) > 20:
            warns.append(f"{_name(p)}: {len(excl_l)} destination exclusions (each is traffic Zscaler never sees; keep the list to RFC1918 and named exceptions)")
        apps = (_v(p, "bypassCustomAppIds", "bypassCustomApps", default=[]) or []) + (_v(p, "bypassAppIds", "bypassApps", default=[]) or [])
        if isinstance(apps, list) and len(apps) > 10:
            warns.append(f"{_name(p)}: {len(apps)} application bypasses")
        if _truthy(_v(p, "allowPacExclusionsOnly")) is False and _v(p, "pac_url", "pacUrl", "customPacUrl"):
            warns.append(f"{_name(p)}: a PAC file is configured on the app profile; PAC DIRECT statements bypass the tunnel unless exclusions-only is set")
    return _verdict(R, fails, warns, "Bypasses are narrow: no destination exclusion wider than a /16, short application lists.", _ref("zcc_bypass"))


# ── forwarding profiles and trusted networks ───────────────────────────
def _actions(fp: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    try:
        from data_flow import forwarding_actions
        return forwarding_actions(fp)
    except Exception:  # noqa: BLE001
        return {}


def _net_entries(fp: Dict[str, Any]) -> List[Tuple[str, Dict[str, Any]]]:
    """(network, entry) for every per-network block of a forwarding profile:
    forwardingProfileActions[] and unifiedTunnel[] carry primaryTransport,
    allowTLSFallback, useTunnel2ForProxiedWebTraffic, the IPv6 and
    unreachable-domain settings and systemProxyData (zscaler-sdk-python
    zcc/models/forwardingprofile.py)."""
    out = []
    for key in ("forwardingProfileActions", "unifiedTunnel"):
        for a in (_v(fp, key, default=[]) or []):
            if isinstance(a, dict):
                out.append((str(_v(a, "networkType", default="network")), a))
    return out


def _net_values(fp: Dict[str, Any], *names: str, proxy: bool = False) -> List[Tuple[str, Any]]:
    """[(network, value)] of a per-network setting; proxy=True reads the
    entry's systemProxyData. A top-level value (older exports) counts as
    one entry when no network carries the setting."""
    vals = []
    for lbl, a in _net_entries(fp):
        src = _v(a, "systemProxyData", default={}) if proxy else a
        v = _v(src, *names) if isinstance(src, dict) else None
        if v is not None:
            vals.append((lbl, v))
    if not vals and _v(fp, *names) is not None:
        vals.append(("profile", _v(fp, *names)))
    return vals


def _tunnels_2(a: Dict[str, Any]) -> bool:
    """True unless the network entry says it forwards with something other than Z-Tunnel 2.0."""
    raw = _v(a, "actionType")
    if raw is None:
        return True
    try:
        from data_flow import classify_mode
        return classify_mode(raw)[0] == "Z-Tunnel 2.0"
    except Exception:  # noqa: BLE001
        return True


def z_forwarding_modes(cl):
    R, _g, _ = _rt()
    fps, e = _fwd_profiles(cl)
    if e:
        return e
    fails, warns = [], []
    for fp in fps:
        name = str(_v(fp, "name", default=f"profile {fp.get('id')}"))
        acts = _actions(fp)
        off = acts.get("off") or acts.get("any") or {}
        on = acts.get("on") or acts.get("any") or {}
        vpn = acts.get("vpn") or {}
        if off.get("mode_kind") == "none":
            fails.append(f"{name}: off-trusted-network action is None (remote devices go direct)")
        elif off.get("mode_kind") == "pac":
            fails.append(f"{name}: off-trusted-network uses a PAC / enforce-proxy (only browser traffic reaches ZIA)")
        elif off.get("mode_label") == "Z-Tunnel 1.0":
            warns.append(f"{name}: off-trusted-network uses Z-Tunnel 1.0 (move to Z-Tunnel 2.0 so every port and protocol is forwarded)")
        elif not off:
            warns.append(f"{name}: no off-trusted-network action found")
        if on.get("mode_kind") == "none":
            warns.append(f"{name}: on-trusted-network action is None (fine only if the site has a GRE/IPsec tunnel)")
        if vpn and vpn.get("mode_kind") == "none":
            warns.append(f"{name}: no forwarding on VPN (traffic inside the VPN is not inspected)")
        # Z-Tunnel 2.0 settings are per network (forwardingProfileActions[]).
        z2 = {lbl for lbl, a in _net_entries(fp) if _tunnels_2(a)} | {"profile"}
        for lbl, v in _net_values(fp, "primaryTransport"):
            pt = str(v or "").upper()
            if lbl in z2 and pt and "DTLS" not in pt and "UDP" not in pt and "0" != pt:
                warns.append(f"{name} ({lbl}): primary transport is {pt} (DTLS gives Z-Tunnel 2.0 its throughput; keep TLS as the fallback)")
        for lbl, v in _net_values(fp, "allowTLSFallback", "allowTlsFallback"):
            if lbl in z2 and _falsy_set(v):
                warns.append(f"{name} ({lbl}): TLS fallback is off (Z-Tunnel 2.0 cannot recover where UDP is blocked)")
        if _falsy_set(_v(fp, "enableLWFDriver")):
            warns.append(f"{name}: the lightweight filter driver is off (needed for Z-Tunnel 2.0 packet capture on Windows)")
        for lbl, v in _net_values(fp, "useTunnel2ForProxiedWebTraffic"):
            if lbl in z2 and _falsy_set(v):
                warns.append(f"{name} ({lbl}): proxied web traffic is not sent through Z-Tunnel 2.0")
    return _verdict(R, fails, warns, f"All {len(fps)} forwarding profile(s) tunnel off-network traffic with Z-Tunnel 2.0 over DTLS with TLS fallback.", _ref("zcc_ztunnel2"))


def z_forwarding_hygiene(cl):
    R, _g, _ = _rt()
    fps, e = _fwd_profiles(cl)
    if e:
        return e
    warns = []
    for fp in fps:
        name = str(_v(fp, "name", default=f"profile {fp.get('id')}"))
        entries = _net_entries(fp) or [("profile", fp)]
        for lbl, a in entries:
            src = a if _v(a, "dropIpv6Traffic", "dropIpv6IncludeTrafficInT2") is not None else fp
            if _falsy_set(_v(src, "dropIpv6Traffic")) and _falsy_set(_v(src, "dropIpv6IncludeTrafficInT2")) and not _truthy(_v(src, "dropIpv6TrafficInIpv6Network")):
                warns.append(f"{name} ({lbl}): IPv6 is neither dropped nor tunnelled (dual-stack hosts can reach IPv6 destinations around Zscaler)")
        for lbl, v in _net_values(fp, "bypassProxyForPrivateIP", proxy=True):
            if _falsy_set(v):
                warns.append(f"{name} ({lbl}): private IP ranges are proxied (RFC1918 should go direct)")
        pac = [lbl for lbl, v in _net_values(fp, "enablePAC", proxy=True) if _truthy(v)] + [lbl for lbl, v in _net_values(fp, "pacURL", "pacUrl", proxy=True) if v]
        pac += [lbl for lbl, v in _net_values(fp, "customPac") if v]
        if pac:
            warns.append(f"{name} ({', '.join(sorted(set(pac)))}): a PAC file is part of forwarding (review it for DIRECT statements)")
        if _truthy(_v(fp, "skipTrustedCriteriaMatch")):
            warns.append(f"{name}: trusted-network criteria matching is skipped")
        for lbl, v in _net_values(fp, "blockUnreachableDomainsTraffic"):
            if _falsy_set(v):
                warns.append(f"{name} ({lbl}): traffic to unreachable domains is not blocked")
    return _verdict(R, [], warns, "Forwarding profiles drop or tunnel IPv6, send RFC1918 direct, use no PAC and evaluate trusted-network criteria.", _ref("zcc_ztunnel2"))


# Trusted-network criteria (https://help.zscaler.com/zscaler-client-connector/configuring-trusted-networks-zscaler-client-connector):
# DNS Server, DNS Search Domains, Hostname and IP, Network Range, Default
# Gateway, DHCP Server, Egress IP. Hostname and resolved IP count as one.
_CRITERIA = (("dnsServers",), ("dnsSearchDomains",), ("hostnames", "hostname", "resolvedIpsForHostname"), ("trustedSubnets",),
             ("trustedGateways",), ("trustedDhcpServers",), ("trustedEgressIps",), ("ssids",))


def _criteria(o: Dict[str, Any]) -> int:
    n = 0
    for names in _CRITERIA:
        v = _v(o, *names)
        if v and (not isinstance(v, (list, str)) or len(v)):
            n += 1
    return n


def z_trusted_networks(cl):
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/forwardingProfiles", "FwdProfiles")
    if e:
        return e
    nets, code = _list(cl, "/zcc/trustedNetworks")
    fps = [fp for fp in d if isinstance(fp, dict)]
    if not fps and not nets:
        # Neither a forwarding profile nor a trusted network: nothing to assess is not a pass.
        return R(R.INFO, "No Client Connector forwarding profile or trusted network was returned"
                 + (f" (trusted networks: HTTP {code})" if code not in (200, 204) else "") + ", so the criteria could not be assessed.")
    fails, warns = [], []
    uses_on_none = [str(_v(fp, "name", default="?")) for fp in fps if (_actions(fp).get("on") or {}).get("mode_kind") == "none"]
    weak = []
    for n in nets:
        name = str(_v(n, "networkName", "name", default=f"network {n.get('id')}"))
        crit = _criteria(n)
        if crit <= 1:
            weak.append(f"{name} ({crit} criterion)")
    # A forwarding profile can define its trusted network inline (dnsServers,
    # trustedSubnets … on the profile itself — SDK ForwardingProfile) or
    # reference trusted networks by id.
    inline, refs = 0, 0
    for fp in fps:
        crit = _criteria(fp)
        if crit:
            inline += 1
            if crit <= 1:
                weak.append(f"{_v(fp, 'name', default='?')} (inline, {crit} criterion)")
        if _v(fp, "trustedNetworkIds", "predefinedTrustedNetworks", "trustedNetworks"):
            refs += 1
    if uses_on_none and not nets and not inline and not refs:
        fails.append(f"{', '.join(uses_on_none[:4])} stop forwarding on the trusted network but no trusted network is defined (code {code})")
    if weak:
        (fails if uses_on_none else warns).append(f"trusted network(s) relying on a single criterion, which a hostile network can spoof: {', '.join(weak[:6])} (combine DNS server + search domain, gateway or egress IP)")
    return _verdict(R, fails, warns, f"{len(nets)} trusted network(s) and {inline} forwarding profile(s) with inline criteria, each defined by more than one criterion.", _ref("zcc_deployment"))


# ── company, privacy, devices ──────────────────────────────────────────
def z_company(cl):
    R, _, _ = _rt()
    c, code = _read_one(cl, "/zcc/companyInfo")
    if not c:
        return R(R.INFO, _unreadable("Company settings", "getCompanyInfo", code))
    # Rollout, cleanup and FIPS live in the nested webAppConfig (SDK CompanyInfo.WebAppConfig).
    wac = _v(c, "webAppConfig", default={})
    if isinstance(wac, str):
        try:
            wac = json.loads(wac)
        except Exception:  # noqa: BLE001
            wac = {}
    wac = wac if isinstance(wac, dict) else {}

    def cv(*names):
        v = _v(wac, *names)
        return v if v is not None else _v(c, *names)
    warns, fails, ok = [], [], []
    if _falsy_set(_v(c, "dlpEnabled")):
        fails.append("Endpoint Data Protection is not enabled for the company")
    if _falsy_set(_v(c, "enableAntiTampering")):
        warns.append("anti-tampering is off company-wide")
    if not (_truthy(cv("slowRolloutZCC")) or _truthy(cv("enableZccSlowRolloutByDefault"))):
        warns.append("slow (phased) rollout of new client versions is off")
    if _falsy_set(_v(c, "enableGlobalZCCTelemetry")):
        warns.append("client telemetry is off (Zscaler cannot flag crashing builds)")
    cleanup = cv("inactiveDeviceCleanup", "deviceCleanup", "autoPurgeDays")
    if cleanup is None or str(cleanup) in ("0", "False", "false"):
        warns.append("inactive devices are never removed automatically (stale devices inflate licences and the device view)")
    if _truthy(cv("enableFipsMode")):
        ok.append("FIPS mode on")
    if _falsy_set(_v(c, "restrictAdminAccess")):
        warns.append("admin access to the Client Connector portal is not restricted")
    return _verdict(R, fails, warns, "Company settings: Endpoint Data Protection on, anti-tampering on, phased rollout, telemetry, inactive-device cleanup" + (f" ({', '.join(ok)})" if ok else "") + ".", _ref("zcc_deployment"))


def z_privacy(cl):
    R, _, _ = _rt()
    p, code = _read_one(cl, "/zcc/privacyInfo")
    if not p:
        return R(R.INFO, _unreadable("Web privacy settings", "getWebPrivacyInfo", code))
    warns = []
    if _falsy_set(_v(p, "collectUserInfo")):
        warns.append("user information is not collected (incidents and user-based policy lose the user)")
    if _falsy_set(_v(p, "collectMachineHostname")):
        warns.append("machine hostname is not collected (device-level incidents cannot be attributed)")
    if _truthy(_v(p, "enablePacketCapture")) and _falsy_set(_v(p, "restrictRemotePacketCapture")):
        warns.append("packet capture is enabled and not restricted to admins")
    if _truthy(_v(p, "grantAccessToZscalerLogFolder")):
        warns.append("users have access to the Zscaler log folder")
    if _truthy(_v(p, "exportLogsForNonAdmin")):
        warns.append("non-admin users can export client logs")
    return _verdict(R, [], warns, "Privacy settings: user and hostname collected for attribution; packet capture and log access restricted.", _ref("zcc_deployment"))


def z_device_fleet(cl):
    R, _, _ = _rt()
    devs, code = _list(cl, "/zcc/devices")
    if not devs:
        return R(R.INFO, f"Devices: not readable (getDevices, HTTP {code}).")
    n = len(devs)
    from dlp_assessment_full_auto import _ZCC_ORPHANED, _zcc_state
    reg = [d for d in devs if _zcc_state(_v(d, "registrationState", "state", default="")) in ("registered", "active", "") and _zcc_state(_v(d, "state")) not in _ZCC_ORPHANED]
    strict_off = [d for d in reg if _falsy_set(_v(d, "strictEnforcement"))]
    tamper_off = [d for d in reg if _falsy_set(_v(d, "antiTamperingStatus"))]
    t1 = [d for d in reg if str(_v(d, "tunnelVersion", "zccTunnelVersion", default="")).strip() in ("1", "1.0", "ZSCALER_TUNNEL_1", "TUNNEL1")]
    zdp_off = [d for d in reg if _falsy_set(_v(d, "zdpEnabled"))]
    fails, warns = [], []
    def pct(x): return round(100 * len(x) / max(1, len(reg)))
    if strict_off and pct(strict_off) > 20:
        fails.append(f"{len(strict_off)} of {len(reg)} devices ({pct(strict_off)}%) run without strict enforcement")
    elif strict_off:
        warns.append(f"{len(strict_off)} device(s) without strict enforcement")
    if tamper_off:
        (fails if pct(tamper_off) > 20 else warns).append(f"{len(tamper_off)} device(s) with anti-tampering off")
    if t1:
        warns.append(f"{len(t1)} device(s) still on Z-Tunnel 1.0")
    if zdp_off and pct(zdp_off) > 20:
        warns.append(f"{len(zdp_off)} device(s) without Endpoint Data Protection running")
    return _verdict(R, fails, warns, f"{len(reg)} registered device(s) of {n}: strict enforcement, anti-tampering, Z-Tunnel 2.0 and Endpoint DLP reported on all of them.", _ref("zcc_deployment"))


def z_version_spread(cl):
    """Client versions per platform and release (major.minor). Each
    platform has its own supported releases: the latest, the two before it
    and the LTS (ZCC_MIN_SUPPORTED); a device is behind only when its
    release is older than all of them. A platform the device list does not
    name falls back to the three newest releases seen in the fleet."""
    R, _, _ = _rt()
    devs, code = _list(cl, "/zcc/devices")
    if not devs:
        return R(R.INFO, f"Devices: not readable (getDevices, HTTP {code}).")
    groups: Dict[str, Dict[str, int]] = {}
    rows = []
    for d in devs:
        v = str(_v(d, "agentVersion", "clientConnectorVersion", "zccVersion", default="") or "").strip()
        if not v:
            continue
        plat = device_platform(d)
        rel = ".".join(str(x) for x in version_tuple(v)[:2])
        groups.setdefault(plat, {})
        groups[plat][rel] = groups[plat].get(rel, 0) + 1
        rows.append((plat, rel, v))
    if not rows:
        return R(R.INFO, "Devices list no client version.")
    fleet_ok = {p: set(sorted(g, key=version_tuple, reverse=True)[:3]) for p, g in groups.items() if p not in ZCC_MIN_SUPPORTED}
    behind: Dict[str, int] = {}
    for plat, rel, v in rows:
        late = zcc_unsupported(plat, v) if plat in ZCC_MIN_SUPPORTED else rel not in fleet_ok.get(plat, set())
        if late:
            behind[plat] = behind.get(plat, 0) + 1
    n, nb = len(rows), sum(behind.values())
    warns = []
    if nb and 100 * nb / n > 20:
        warns.append(f"{nb} of {n} devices ({round(100 * nb / n)}%) run a release older than every one Zscaler supports on their platform ({', '.join(f'{p}: {c}' for p, c in behind.items())}; supported are the latest release, the two before it and the LTS: {ZCC_SUPPORTED_REF})")
    wide = [f"{p} {len(g)}" for p, g in groups.items() if len(g) > 4]
    if wide:
        warns.append(f"many client releases in the fleet ({', '.join(wide)})")
    mism = [d for d in devs if _v(d, "expectedZCCVersion") and str(_v(d, "expectedZCCVersion")) != str(_v(d, "agentVersion", "clientConnectorVersion", default=""))
            and str(_v(d, "zccUpgradeStatus", default="")).lower() in ("failed", "error", "3")]
    if mism:
        warns.append(f"{len(mism)} device(s) failed to upgrade to the version the portal expects")
    summary = "; ".join(f"{p}: {', '.join(sorted(g, key=version_tuple, reverse=True)[:3])}" for p, g in groups.items())
    return _verdict(R, [], warns, f"{n} device(s), {n - nb} on a supported release ({summary}).", _ref("zcc_updates"))


# ── DLP notification templates ─────────────────────────────────────────
_PLACEHOLDERS = ("${RULENAME}", "${ENGINES}", "${DICTIONARIES}", "${USER}", "${URL}", "${TRANSACTION_ID}", "${SEVERITY}", "${TYPE}", "${TRIGGERS}")


def z_notification_templates(cl):
    R, _, _ls = _rt()
    d, c = cl.get("/zia/dlpNotificationTemplates")
    if c not in (200, 204):
        return R(R.INFO, f"DLP notification templates: not readable (HTTP {c}).")
    tpls = [t for t in _ls(d) if isinstance(t, dict)]
    rules, _ = _list(cl, "/zia/webDlpRules")
    fails, warns = [], []
    used = set()
    for r in rules:
        t = r.get("notificationTemplate") or r.get("notification_template")
        if isinstance(t, dict) and t.get("id") is not None:
            used.add(str(t["id"]))
        elif t:
            used.add(str(t))
    for t in tpls:
        name = str(t.get("name") or t.get("id"))
        if _falsy_set(t.get("tlsEnabled", t.get("tls_enabled"))):
            fails.append(f"{name}: TLS off (the notification, which names the user, rule and match, travels in clear)")
        if _truthy(t.get("attachContent", t.get("attach_content"))):
            warns.append(f"{name}: attaches the matched content to the e-mail (the sensitive data leaves the platform again; keep it in the Incident Receiver)")
        body = f"{t.get('subject') or ''} {t.get('htmlMessage') or t.get('html_message') or ''} {t.get('plainTextMessage') or t.get('plain_text_message') or ''}"
        if not (t.get("subject") or "").strip():
            warns.append(f"{name}: empty subject")
        if not any(ph in body for ph in _PLACEHOLDERS):
            warns.append(f"{name}: no placeholder (${{RULENAME}}, ${{USER}}, ${{ENGINES}} …), so the auditor cannot tell which rule or user fired")
        if not (t.get("plainTextMessage") or t.get("plain_text_message") or "").strip():
            warns.append(f"{name}: no plain-text body (mail clients that block HTML show nothing)")
        if str(t.get("id")) not in used and tpls:
            warns.append(f"{name}: not attached to any Web DLP rule")
    enforcing = [r for r in rules if str(r.get("state") or "").upper() == "ENABLED"
                 and str((r.get("action") or {}).get("type") if isinstance(r.get("action"), dict) else r.get("action") or "").upper() in ("BLOCK", "CONFIRM", "ISOLATE", "CAUTION")]
    silent = [str(r.get("name")) for r in enforcing if not (r.get("notificationTemplate") or r.get("notification_template") or r.get("auditor") or r.get("externalAuditorEmail"))]
    if silent:
        warns.append(f"{len(silent)} enforcing rule(s) notify nobody: {', '.join(silent[:5])}")
    if not tpls:
        return R(R.WARN, "No DLP notification template exists: auditors and users are never told about a match." + _ref("zia_policy_leading"))
    return _verdict(R, fails, warns, f"{len(tpls)} notification template(s): TLS on, placeholders present, content not attached, every enforcing rule notifies someone.", _ref("zia_policy_leading"))


# ── registration ───────────────────────────────────────────────────────
REG_EXTRA = [
    ("1.15", "1 — CC Portal", "Anti-tampering", z_anti_tampering),
    ("1.16", "1 — CC Portal", "Service-disable passwords", z_disable_passwords),
    ("1.17", "1 — CC Portal", "Log level", z_log_level),
    ("1.18", "1 — CC Portal", "QUIC dropped", z_quic),
    ("1.19", "1 — CC Portal", "Fail-close policy", z_fail_open),
    ("1.20", "1 — CC Portal", "Revert protection", z_revert),
    ("1.21", "1 — CC Portal", "Intercept on all adapters", z_adapters),
    ("1.22", "1 — CC Portal", "Disable window", z_disable_window),
    ("1.23", "1 — CC Portal", "Bypass hygiene", z_bypass_hygiene),
    ("1.24", "1 — CC Portal", "Forwarding modes per network", z_forwarding_modes),
    ("1.25", "1 — CC Portal", "Forwarding hygiene", z_forwarding_hygiene),
    ("1.26", "1 — CC Portal", "Trusted network criteria", z_trusted_networks),
    ("1.27", "1 — CC Portal", "Company settings", z_company),
    ("1.28", "1 — CC Portal", "Privacy settings", z_privacy),
    ("6.8", "6 — Versions", "Device fleet strictness", z_device_fleet),
    ("6.9", "6 — Versions", "Version spread", z_version_spread),
    ("12.15", "12 — Incident Mgmt", "Notification templates (strict)", z_notification_templates),
]


def splice(reg: List[tuple]) -> List[tuple]:
    """Insert the extra checks after the last entry of their section."""
    out = list(reg)
    for entry in REG_EXTRA:
        if any(e[0] == entry[0] for e in out):
            continue
        idx = max((i for i, e in enumerate(out) if e[1] == entry[1]), default=len(out) - 1)
        out.insert(idx + 1, entry)
    return out
