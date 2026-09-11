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

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

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
def _norm(k: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


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


def _v(d: Dict[str, Any], *names: str, default: Any = None) -> Any:
    idx = {_norm(k): v for k, v in d.items()}
    for n in names:
        v = idx.get(_norm(n))
        if v is not None and v != "":
            return v
    return default


_PLAT = {"1": "iOS", "2": "Android", "3": "Windows", "4": "macOS", "5": "Linux", "ios": "iOS", "android": "Android", "windows": "Windows", "win": "Windows",
         "mac": "macOS", "macos": "macOS", "linux": "Linux"}


def _plat(p: Dict[str, Any]) -> str:
    raw = _v(p, "device_type", "deviceType", "os", "platform", "osType", default="")
    return _PLAT.get(str(raw).lower(), str(raw) or "?")


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
    return [flatten_profile(p) for p in d if isinstance(p, dict) and _active(flatten_profile(p))], None


def _list(cl, ep: str) -> Tuple[List[Dict[str, Any]], Optional[int]]:
    _, _, _ls = _rt()
    d, c = cl.get(ep)
    return ([x for x in _ls(d) if isinstance(x, dict)] if c in (200, 204) else []), c


def _one(cl, ep: str) -> Dict[str, Any]:
    items, _ = _list(cl, ep)
    if items:
        return items[0]
    d, c = cl.get(ep)
    return d if c in (200, 204) and isinstance(d, dict) else {}


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
    off = [_name(p) for p in profiles if not _truthy(_v(p, "enableAntiTampering", "antiTampering"))]
    company = _one(cl, "/zcc/companyInfo")
    warns = []
    if company and _falsy_set(_v(company, "enableAntiTampering")):
        warns.append("anti-tampering is off at the company level")
    return _verdict(R, [f"anti-tampering OFF on {len(off)} profile(s): {', '.join(off[:6])}"] if off else [], warns,
                    f"Anti-tampering on all {len(profiles)} profile(s): the client cannot be stopped or its files altered by the user.", _ref("zcc_deployment"))


_PW = [("uninstallPassword", "uninstall"), ("disablePassword", "disable"), ("ziaDisablePassword", "disable Internet Security"),
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
        core = [m for m in missing if m in ("uninstall", "disable", "disable Internet Security")]
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


def z_quic(cl):
    R, _, _ = _rt()
    profiles, e = _profiles(cl)
    if e:
        return e
    off = [_name(p) for p in profiles if not _truthy(_v(p, "dropQuicTraffic", "blockQuic"))]
    return _verdict(R, [f"QUIC not dropped on {len(off)} profile(s): {', '.join(off[:6])} (HTTP/3 over UDP is not decrypted, so inline DLP and SSL inspection miss it)"] if off else [], [],
                    f"QUIC is dropped on all {len(profiles)} profile(s), so browsers fall back to TCP and SSL inspection applies.", _ref("zia_ssl_leading"))


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
        if _truthy(_v(p, "prioritizeDnsExclusions")):
            warns.append(f"{_name(p)}: DNS exclusions take priority over the tunnel include list")
        if _truthy(_v(p, "allowPacExclusionsOnly")) is False and _v(p, "pac_url", "pacUrl", "customPacUrl"):
            warns.append(f"{_name(p)}: a PAC file is configured on the app profile; PAC DIRECT statements bypass the tunnel unless exclusions-only is set")
    return _verdict(R, fails, warns, "Bypasses are narrow: no destination exclusion wider than a /16, short application lists, DNS exclusions not prioritised.", _ref("zcc_bypass"))


# ── forwarding profiles and trusted networks ───────────────────────────
def _actions(fp: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    try:
        from data_flow import forwarding_actions
        return forwarding_actions(fp)
    except Exception:  # noqa: BLE001
        return {}


def z_forwarding_modes(cl):
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/forwardingProfiles", "FwdProfiles")
    if e:
        return e
    fps = [x for x in d if isinstance(x, dict)]
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
        pt = str(_v(fp, "primaryTransport", default="") or "").upper()
        if pt and "DTLS" not in pt and "UDP" not in pt and "0" != pt:
            warns.append(f"{name}: primary transport is {pt} (DTLS gives Z-Tunnel 2.0 its throughput; keep TLS as the fallback)")
        if _falsy_set(_v(fp, "allowTLSFallback", "allowTlsFallback")):
            warns.append(f"{name}: TLS fallback is off (Z-Tunnel 2.0 cannot recover where UDP is blocked)")
        if _falsy_set(_v(fp, "enableLWFDriver")):
            warns.append(f"{name}: the lightweight filter driver is off (needed for Z-Tunnel 2.0 packet capture on Windows)")
        if _falsy_set(_v(fp, "useTunnel2ForProxiedWebTraffic")):
            warns.append(f"{name}: proxied web traffic is not sent through Z-Tunnel 2.0")
    return _verdict(R, fails, warns, f"All {len(fps)} forwarding profile(s) tunnel off-network traffic with Z-Tunnel 2.0 over DTLS with TLS fallback.", _ref("zcc_ztunnel2"))


def z_forwarding_hygiene(cl):
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/forwardingProfiles", "FwdProfiles")
    if e:
        return e
    warns = []
    for fp in [x for x in d if isinstance(x, dict)]:
        name = str(_v(fp, "name", default=f"profile {fp.get('id')}"))
        if _falsy_set(_v(fp, "dropIpv6Traffic")) and _falsy_set(_v(fp, "dropIpv6IncludeTrafficInT2")) and not _truthy(_v(fp, "dropIpv6TrafficInIpv6Network")):
            warns.append(f"{name}: IPv6 is neither dropped nor tunnelled (dual-stack hosts can reach IPv6 destinations around Zscaler)")
        if _falsy_set(_v(fp, "bypassProxyForPrivateIP")):
            warns.append(f"{name}: private IP ranges are proxied (RFC1918 should go direct)")
        if _truthy(_v(fp, "enablePAC")) or _v(fp, "pacURL", "pacUrl", "customPac"):
            warns.append(f"{name}: a PAC file is part of forwarding (review it for DIRECT statements)")
        if _truthy(_v(fp, "skipTrustedCriteriaMatch")):
            warns.append(f"{name}: trusted-network criteria matching is skipped")
        if _falsy_set(_v(fp, "blockUnreachableDomainsTraffic")):
            warns.append(f"{name}: traffic to unreachable domains is not blocked")
    return _verdict(R, [], warns, "Forwarding profiles drop or tunnel IPv6, send RFC1918 direct, use no PAC and evaluate trusted-network criteria.", _ref("zcc_ztunnel2"))


def z_trusted_networks(cl):
    R, _g, _ = _rt()
    d, e = _g(cl, "/zcc/forwardingProfiles", "FwdProfiles")
    if e:
        return e
    nets, code = _list(cl, "/zcc/trustedNetworks")
    fails, warns = [], []
    uses_on_none = [str(_v(fp, "name", default="?")) for fp in d if isinstance(fp, dict) and (_actions(fp).get("on") or {}).get("mode_kind") == "none"]
    weak = []
    for n in nets:
        name = str(_v(n, "networkName", "name", default=f"network {n.get('id')}"))
        crit = 0
        for k in ("dnsServers", "dnsSearchDomains", "trustedGateways", "trustedSubnets", "trustedEgressIps", "trustedDhcpServers", "hostnames", "ssids"):
            v = _v(n, k)
            if v and (not isinstance(v, (list, str)) or len(v)):
                crit += 1
        if crit <= 1:
            weak.append(f"{name} ({crit} criterion)")
    if uses_on_none and not nets:
        fails.append(f"{', '.join(uses_on_none[:4])} stop forwarding on the trusted network but no trusted network is defined (code {code})")
    if weak:
        (fails if uses_on_none else warns).append(f"trusted network(s) relying on a single criterion, which a hostile network can spoof: {', '.join(weak[:6])} (combine DNS server + search domain, gateway or egress IP)")
    return _verdict(R, fails, warns, f"{len(nets)} trusted network(s), each defined by more than one criterion.", _ref("zcc_deployment"))


# ── company, privacy, devices ──────────────────────────────────────────
def z_company(cl):
    R, _, _ = _rt()
    c = _one(cl, "/zcc/companyInfo")
    if not c:
        return R(R.INFO, "Company settings: not readable (getCompanyInfo).")
    warns, fails, ok = [], [], []
    if _falsy_set(_v(c, "dlpEnabled")):
        fails.append("Endpoint Data Protection is not enabled for the company")
    if _falsy_set(_v(c, "enableAntiTampering")):
        warns.append("anti-tampering is off company-wide")
    if not (_truthy(_v(c, "slowRolloutZCC")) or _truthy(_v(c, "enableZccSlowRolloutByDefault"))):
        warns.append("slow (phased) rollout of new client versions is off")
    if _falsy_set(_v(c, "enableGlobalZCCTelemetry")):
        warns.append("client telemetry is off (Zscaler cannot flag crashing builds)")
    cleanup = _v(c, "inactiveDeviceCleanup", "deviceCleanup", "autoPurgeDays")
    if cleanup is None or str(cleanup) in ("0", "False", "false"):
        warns.append("inactive devices are never removed automatically (stale devices inflate licences and the device view)")
    if _truthy(_v(c, "enableFipsMode")):
        ok.append("FIPS mode on")
    if _falsy_set(_v(c, "restrictAdminAccess")):
        warns.append("admin access to the Client Connector portal is not restricted")
    return _verdict(R, fails, warns, "Company settings: Endpoint Data Protection on, anti-tampering on, phased rollout, telemetry, inactive-device cleanup" + (f" ({', '.join(ok)})" if ok else "") + ".", _ref("zcc_deployment"))


def z_privacy(cl):
    R, _, _ = _rt()
    p = _one(cl, "/zcc/privacyInfo")
    if not p:
        return R(R.INFO, "Web privacy settings: not readable (getWebPrivacyInfo).")
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
    reg = [d for d in devs if str(_v(d, "registrationState", "state", default="")).lower() in ("registered", "1", "active", "") and not str(_v(d, "state", default="")).lower() in ("removed", "orphaned", "inactive")]
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
    R, _, _ = _rt()
    devs, code = _list(cl, "/zcc/devices")
    if not devs:
        return R(R.INFO, f"Devices: not readable (getDevices, HTTP {code}).")
    versions: Dict[str, int] = {}
    for d in devs:
        v = str(_v(d, "agentVersion", "clientConnectorVersion", "zccVersion", default="") or "").strip()
        if v:
            versions[v] = versions.get(v, 0) + 1
    if not versions:
        return R(R.INFO, "Devices list no client version.")
    def key(v):
        return tuple(int(x) if x.isdigit() else 0 for x in re.split(r"[.\-]", v)[:4])
    ordered = sorted(versions, key=key, reverse=True)
    newest = ordered[:2]
    behind = sum(versions[v] for v in ordered[2:])
    n = sum(versions.values())
    warns = []
    if behind and 100 * behind / n > 20:
        warns.append(f"{behind} of {n} devices ({round(100 * behind / n)}%) are more than two versions behind ({', '.join(f'{v}: {versions[v]}' for v in ordered[2:6])})")
    if len(versions) > 6:
        warns.append(f"{len(versions)} distinct client versions in the fleet")
    mism = [d for d in devs if _v(d, "expectedZCCVersion") and str(_v(d, "expectedZCCVersion")) != str(_v(d, "agentVersion", "clientConnectorVersion", default=""))
            and str(_v(d, "zccUpgradeStatus", default="")).lower() in ("failed", "error", "3")]
    if mism:
        warns.append(f"{len(mism)} device(s) failed to upgrade to the version the portal expects")
    return _verdict(R, [], warns, f"{n} device(s) on {len(versions)} version(s); {n - behind} on the two newest ({', '.join(newest)}).", _ref("zcc_updates"))


# ── DLP notification templates ─────────────────────────────────────────
_PLACEHOLDERS = ("${RULENAME}", "${ENGINES}", "${DICTIONARIES}", "${USER}", "${URL}", "${TRANSACTION_ID}", "${SEVERITY}", "${TYPE}", "${TRIGGERS}")


def z_notification_templates(cl):
    R, _, _ls = _rt()
    d, c = cl.get("/zia/dlpNotificationTemplates")
    if c == 404:
        d, c = cl.get("/zia/notificationTemplates")
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
