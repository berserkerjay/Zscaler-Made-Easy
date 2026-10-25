"""Browser security: Zscaler Zero Trust Browser (cloud browser isolation),
the ZPA browser side (Browser Access, managed browser posture, browser
protection, Privileged Remote Access, user portals) and ZIA Browser
Control, read once, read-only, and turned into plain-English findings
about data protection.

What is read (zscaler-sdk-python 1.9.44; the browser APIs are the same in
1.11.3). Every call below was checked in the installed SDK (service,
method, endpoint path and model fields):

ZIA (only when ZIA platform is ticked on the Scope page), paced by zia_rate
through pack_export._read (rate refusals are waited out, Stop ends it):
  cloud_browser_isolation.list_isolation_profiles   /zia/api/v1/browserIsolation/profiles
                                                    (id, name, url, defaultProfile)
  secure_browsing.get_browser_control_settings      /zia/api/v1/browserControlSettings
  secure_browsing.get_supported_browser_versions    /zia/api/v1/browserControlSettings/supportedBrowserVersions
  url_filtering.list_rules                          /zia/api/v1/urlFilteringRules (action, cbiProfile)
  cloudappcontrol.list_rules(rule_type)             /zia/api/v1/webApplicationRules/{type} (actions, cbiProfile)

ZPA (only when ZPA is ticked; OneAPI with the ZPA customer id), paced by
zpa_reader's gate, page by page where the API pages:
  cbi_profile.list_cbi_profiles / get_cbi_profile   /zpa/cbiconfig/cbi/api/customers/{id}/profiles[/{pid}]
  cbi_banner.list_cbi_banners                       .../banners       (names and default only)
  cbi_certificate.list_cbi_certificates             .../certificates  (names, enabled, default; never the PEM)
  cbi_region.list_cbi_regions                       .../regions
  cbi_zpa_profile.list_isolation_profiles           /zpa/mgmtconfig/v1/admin/customers/{id}/isolation/profiles
  managed_browser_profile.list_managed_browser_profiles   .../managedBrowserProfile/search
  browser_protection.list_browser_protection_profile      .../browserProtectionProfile
  browser_protection.list_active_browser_protection_profile .../activeBrowserProtectionProfile
  app_segments_ba_v2.list_segments_ba               .../application (every segment; Browser Access ones carry clientlessApps)
  pra_portal.list_portals / pra_console.list_consoles / user_portal_controller.list_user_portals
  policies.list_rules("access" | "isolation")       .../policySet/rules/policyType/ACCESS_POLICY | ISOLATION_POLICY

Never output: the isolation profile's debug-mode file password, any
certificate body (PEM), banner logos, portal images, the people named as
PRA approval reviewers or smart-isolation users. Normalizers copy only the
fields listed in this module; `scrub` drops anything secret-shaped again
before a report is kept, as a second guard.

There is no public API in the SDK for the standalone Zscaler Enterprise
Browser (the hardened Chromium browser) or its own policies, so nothing
here reads or claims anything about it.

Nothing here writes: only list_* and get_* methods are called (tests
enforce it).
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import zpa_reader as zr
from zpa_reader import as_bool, as_str, get

SEVERITIES = ("high", "medium", "low", "info")
_SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

PRODUCT = "Zscaler Made Easy"
NO_ENTERPRISE_BROWSER_API = ("The Zscaler API has no endpoints for the standalone Zscaler Enterprise Browser or its own policies, "
                             "so this page cannot read or check them.")
NOTHING_IN_SCOPE = ("Browser security is not in scope: on the Scope page tick ZIA platform (isolation profiles, Browser Control and the "
                    "rules that isolate) or ZPA (isolation controls, Browser Access, managed browsers and Privileged Remote Access), "
                    "then run it again. Nothing was read.")
STOPPED_REASON = ("You clicked Stop before the read finished, so it was abandoned: nothing more was read from the tenant "
                  "and no partial result is shown.")
ZPA_NEEDS_ONEAPI = ("ZPA is ticked, but the classic ZIA sign-in reaches ZIA only: the ZPA side (isolation controls, Browser Access, "
                    "managed browsers, Privileged Remote Access) needs a ZIdentity (OneAPI) API client with a ZPA role.")
ZPA_NEEDS_CUSTOMER_ID = ("ZPA is ticked, but no ZPA customer ID was given (Connect to the tenant → Customer ID, or the saved profile): "
                         "every ZPA API path carries it.")

MAX_PROFILE_DETAILS = 100     # get_cbi_profile calls at most (one per isolation profile)
PAGE_MAX = zr.MAX_PAGES

# Cloud App Control types and URL categories that hold the apps data most
# often leaves through: GenAI, file sharing, webmail, chat, social, consumer.
RISKY_CAC_TYPES = {"AI_ML": "GenAI", "FILE_SHARE": "file sharing", "WEBMAIL": "webmail", "INSTANT_MESSAGING": "instant messaging",
                   "SOCIAL_NETWORKING": "social networking", "CONSUMER": "consumer apps"}
_RISKY_CATEGORY = re.compile(
    r"(^|_)(AI|GENAI|GENERATIVE)(_|$)|AI_ML|FILE_?SHAR|FILEHOST|ONLINE_STORAGE|WEB_?MAIL|SOCIAL_NETWORK|INSTANT_MESSAG|"
    r"PERSONAL_(SITES|CLOUD|STORAGE)|NEWLY_REG|UNKNOWN|MISCELLANEOUS|OTHER_MISC", re.I)
_UNSANCTIONED = re.compile(r"unsanction|shadow\s*it|unapproved|personal", re.I)

# Browser Control: supported browser type -> the blocked-versions field.
BLOCKED_FIELDS = {"CHROME": "blockedChromeVersions", "FIREFOX": "blockedFirefoxVersions", "MSIE": "blockedInternetExplorerVersions",
                  "SAFARI": "blockedSafariVersions", "OPERA": "blockedOperaVersions"}
BROWSER_NAMES = {"CHROME": "Chrome", "FIREFOX": "Firefox", "MSIE": "Internet Explorer", "SAFARI": "Safari", "OPERA": "Opera",
                 "MSEDGE": "Edge (legacy)", "MSCHREDGE": "Edge", "OTHER": "Other"}

ASSUMPTIONS = [
    "Isolation profiles are matched across ZIA, ZPA and the isolation (cbiconfig) API by id, then by isolation URL, then by name. "
    "The SDK does not document that the ids are shared; a profile that cannot be matched is shown on its own.",
    "copyPaste and uploadDownload are read as the API returns them: \"none\" means nothing is allowed; any other value (\"all\" "
    "or a one-way value) allows something and is reported with the value shown.",
    "Local rendering, browser-in-browser, session persistence, forward to ZIA and debug mode are explained from the setting "
    "names, the SDK docstrings and Zscaler's help pages, not from a documented API contract; each finding says so.",
    "A profile counts as used for sensitive, GenAI or unsanctioned apps when a rule that uses it isolates a Cloud App Control "
    "type such as AI & ML, file sharing or webmail, a URL category such as generative AI, file sharing, webmail, newly "
    "registered or unknown, or names \"unsanctioned\"; ZPA isolation rules protect private apps and count as sensitive.",
    "Access rules use a managed browser profile through a CHROME_POSTURE_PROFILE condition. Its value is matched against both the "
    "managed browser profile id and its Chrome posture profile id, since the SDK does not say which one the rule stores.",
    "A PRA console's praApplication.appId is taken to be the id of the app segment it opens.",
    "Browser versions are compared as the API returns them: an older version the tenant does not list as blocked counts as "
    "not blocked. Edge has no blocked-versions field in the API, so Edge versions cannot be checked.",
]

# What each control means, in plain words (the page and the workbook).
CONTROL_GLOSSARY: List[Tuple[str, str]] = [
    ("Browser isolation", "The website runs in Zscaler's cloud, not on the user's computer. The user sees a picture of the page, "
                          "so files and code from the site do not reach the device unless the isolation profile allows it."),
    ("Isolation profile", "The settings an isolated session uses: what may cross between the isolated page and the device "
                          "(copy and paste, files, printing), the watermark, and how the session behaves."),
    ("Copy and paste", "Whether text can be copied between the isolated page and the user's computer. \"none\" keeps text inside isolation."),
    ("Upload and download", "Whether files can move between the isolated page and the user's computer. \"none\" keeps files inside isolation."),
    ("Printing", "Whether the user can print from the isolated page."),
    ("Watermark", "Text drawn over isolated pages, such as the user's ID and the time, so a screenshot or a photo of the screen "
                  "can be traced back to who saw it and when."),
    ("Document viewer", "Shows office files and PDFs inside isolation, so users can read them without downloading them."),
    ("Restrict keystrokes", "Makes the isolated page read-only: the user cannot type into it."),
    ("Local rendering", "Lets the user's own browser draw some of the page instead of receiving pixels only. More of the page reaches the device."),
    ("Session persistence", "Keeps cookies and sign-ins between isolation sessions, so users stay signed in next time."),
    ("Debug mode", "Lets users switch on debugging in the isolated browser and save debug files. Meant for troubleshooting with Zscaler support."),
    ("Smart isolation", "ZIA opens websites it finds suspicious, such as likely phishing pages, in isolation automatically, "
                        "for the users and groups you choose."),
    ("Browser Control", "ZIA checks which browser and version a user has and can block or warn on outdated ones."),
    ("Browser Access", "ZPA publishes an internal web app so users reach it from any browser, without Client Connector."),
    ("Privileged Remote Access", "ZPA gives admins and third parties RDP or SSH sessions to servers through a web portal, "
                                 "without a VPN and without the server being exposed."),
    ("Managed browser profile", "A ZPA access-rule condition that checks the browser itself, for example that Chrome is managed "
                                "by the company through Chrome Enterprise."),
    ("Zscaler Enterprise Browser", "Zscaler's own hardened browser. " + NO_ENTERPRISE_BROWSER_API),
]

_SECRET_KEY = re.compile(r"password|passwd|secret|pem$|^pem|certificate_?body|cert_?blob|private_?key|logo|image_?data|token", re.I)


class Stopped(RuntimeError):
    """The operator clicked Stop: nothing more is read."""


# ── scope ──────────────────────────────────────────────────────────────
def scope_for(scopes: Any) -> Dict[str, Any]:
    """What this page may read for the Scope page's ticked scopes: ZIA
    when ZIA platform is ticked, ZPA when ZPA is. Pure."""
    sc = {str(s).strip() for s in scopes} if isinstance(scopes, (list, tuple, set)) else set()
    zia, zpa = "zia_extras" in sc, "zpa" in sc
    nis = {}
    if not zia:
        nis["zia"] = ("Not in scope: ZIA platform is not ticked on the Scope page, so ZIA isolation profiles, Browser Control "
                      "and the URL filtering and Cloud App Control rules that isolate were not read.")
    if not zpa:
        nis["zpa"] = ("Not in scope: ZPA is not ticked on the Scope page, so the isolation controls, Browser Access, managed "
                      "browsers, browser protection, Privileged Remote Access and user portals were not read.")
    parts = [p for p, on in (("ZIA (isolation profiles, Browser Control, rules that isolate)", zia),
                             ("ZPA (isolation controls, Browser Access, managed browsers, PRA, user portals)", zpa)) if on]
    summary = ("Reads only what is in scope on the Scope page: " + " and ".join(parts) + ".") if parts else NOTHING_IN_SCOPE
    return {"zia": zia, "zpa": zpa, "read": bool(parts), "not_in_scope": nis, "summary": summary}


# ── small helpers ──────────────────────────────────────────────────────
def _err_text(err: Any) -> str:
    s = re.sub(r"\s+", " ", str(err or "")).strip()
    s = re.sub(r"(?i)(bearer|token|secret|password|pem)\S*\s*[:=]?\s*\S+", r"\1 [hidden]", s)
    s = re.sub(r"-----BEGIN[^-]*-----.*?(-----END[^-]*-----|$)", "[certificate hidden]", s)
    return s[:200] or "the API answered an error"


def _upper(v: Any) -> str:
    return as_str(v).upper()


def _names(v: Any) -> List[str]:
    out = []
    for x in v or []:
        if isinstance(x, dict):
            n = as_str(get(x, "name") or get(x, "id"))
        else:
            n = as_str(getattr(x, "name", None) or x)
        if n:
            out.append(n)
    return out


def _ref(v: Any) -> Optional[Dict[str, str]]:
    """{id, name} of a reference ({id, name} dict or model), None when empty."""
    if v is None:
        return None
    if not isinstance(v, dict):
        fn = getattr(v, "as_dict", None)
        v = fn() if callable(fn) else {}
    i, n = as_str(get(v, "id")), as_str(get(v, "name"))
    if (not i or i == "0") and not n:
        return None
    return {"id": "" if i == "0" else i, "name": n}


def scrub(obj: Any) -> Any:
    """A copy of `obj` without any key that looks like a secret or a blob
    (password, PEM, logo, image data, token)."""
    if isinstance(obj, dict):
        return {k: scrub(v) for k, v in obj.items() if not _SECRET_KEY.search(str(k))}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    if isinstance(obj, tuple):
        return [scrub(x) for x in obj]
    return obj


def _plain(item: Any) -> Dict[str, Any]:
    return zr._plain(item)


def _one_object(ret: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(raw JSON object, error) of a get_* call: the response body when the
    response holds it (the models drop fields), else the model as a dict."""
    result, resp, err = zr._triple(ret)
    if err:
        return None, _err_text(err)
    body = None
    getter = getattr(resp, "get_body", None)
    if callable(getter):
        try:
            b = getter()
            if isinstance(b, dict):
                body = b
        except Exception:  # noqa: BLE001 — fall back to the model
            body = None
    if body is None and result is not None:
        body = _plain(result)
    return (body if isinstance(body, dict) else None), None


# ── ZIA ────────────────────────────────────────────────────────────────
def normalize_zia_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")),
            "url": as_str(get(p, "url")), "default": bool(as_bool(get(p, "defaultProfile")))}


def _risk(policy: str, rtype: str, cats: List[str], apps: List[str], name: str) -> str:
    """Why a rule's traffic is sensitive, GenAI or unsanctioned ("" when not)."""
    if policy == "cloud_app_control" and rtype in RISKY_CAC_TYPES:
        return f"Cloud App Control {RISKY_CAC_TYPES[rtype]} apps"
    hits = [c for c in cats if _RISKY_CATEGORY.search(c) or _UNSANCTIONED.search(c)]
    if hits:
        return "URL categories " + ", ".join(hits[:4])
    if _UNSANCTIONED.search(name or ""):
        return "apps the rule name calls unsanctioned"
    return ""


def normalize_zia_rule(r: Dict[str, Any], policy: str, rtype: str = "") -> Dict[str, Any]:
    action = get(r, "action")
    if isinstance(action, dict):
        action = get(action, "type") or get(action, "name")
    acts = [_upper(a) for a in (get(r, "actions") or []) if as_str(a)]
    if as_str(action):
        acts.insert(0, _upper(action))
    prof = _ref(get(r, "cbiProfile"))
    pid = as_str(get(r, "cbiProfileId"))
    if pid and pid != "0":
        prof = prof or {"id": pid, "name": ""}
        prof["id"] = prof.get("id") or pid
    state = _upper(get(r, "state") or "ENABLED")
    cats = _names(get(r, "urlCategories"))
    apps = _names(get(r, "applications"))
    rtype = _upper(rtype or get(r, "type"))
    name = as_str(get(r, "name")) or f"rule {as_str(get(r, 'id'))}"
    order = get(r, "order")
    return {"policy": policy, "id": as_str(get(r, "id")), "name": name, "order": order, "state": state, "enabled": state == "ENABLED",
            "actions": acts, "isolate": any(a.startswith("ISOLATE") for a in acts), "profile": prof, "type": rtype,
            "url_categories": cats, "applications": apps, "risky": _risk(policy, rtype, cats, apps, name)}


def normalize_browser_control(d: Dict[str, Any]) -> Dict[str, Any]:
    prof = _ref(get(d, "smartIsolationProfile"))
    pid = as_str(get(d, "smartIsolationProfileId"))
    if pid and pid != "0" and not prof:
        prof = {"id": pid, "name": ""}
    blocked = {b: [as_str(v) for v in (get(d, f) or []) if as_str(v)] for b, f in BLOCKED_FIELDS.items()}
    return {"allow_all_browsers": as_bool(get(d, "allowAllBrowsers")), "bypass_all_browsers": as_bool(get(d, "bypassAllBrowsers")),
            "enable_warnings": as_bool(get(d, "enableWarnings")), "smart_isolation": as_bool(get(d, "enableSmartBrowserIsolation")),
            "smart_isolation_profile": prof,
            "smart_isolation_users": len(get(d, "smartIsolationUsers") or []), "smart_isolation_groups": len(get(d, "smartIsolationGroups") or []),
            "plugin_check_frequency": as_str(get(d, "pluginCheckFrequency")),
            "bypass_applications": [as_str(x) for x in (get(d, "bypassApplications") or []) if as_str(x)][:50],
            "bypass_plugins": [as_str(x) for x in (get(d, "bypassPlugins") or []) if as_str(x)][:50],
            "blocked": blocked}


def normalize_supported(x: Dict[str, Any]) -> Dict[str, Any]:
    return {"browser": _upper(get(x, "browserType")), "versions": [as_str(v) for v in (get(x, "versions") or []) if as_str(v)],
            "older": [as_str(v) for v in (get(x, "olderVersions") or []) if as_str(v)]}


def read_zia(client: Any, log: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """ZIA's side (see the module docstring). Raises Stopped on Stop."""
    import pack_export as pe
    from dlp_assessment_full_auto import _CAC_TYPES
    zia = getattr(client, "zia", None)
    out: Dict[str, Any] = {"sections": {}, "profiles": None, "browser_control": None, "supported": None,
                           "rules": {"url_filtering": None, "cloud_app_control": None}}
    refused = {"what": ""}

    def section(key: str, label: str, read: bool, count: int = 0, error: str = "", complete: bool = True) -> None:
        out["sections"][key] = {"label": label, "read": read, "count": count, "error": error or None, "complete": complete}

    def one(what: str, fn: Callable[[], Tuple[Any, Optional[str]]]) -> Tuple[Any, Optional[str]]:
        if pe._stopped(cancel):
            raise Stopped(STOPPED_REASON)
        if refused["what"]:
            return None, f"not read: ZIA refused the read of the {refused['what']} for its rate limit, so no more ZIA reads were sent"
        data, err, rate = pe._read(what, fn, log, cancel)
        if pe._stopped(cancel):
            raise Stopped(STOPPED_REASON)
        if err and rate:
            refused["what"] = what
        return data, (_err_text(err) if err else None)

    if zia is None:
        for key, label in (("zia_profiles", "ZIA isolation profiles"), ("browser_control", "Browser Control settings"),
                           ("supported_versions", "supported browser versions"), ("url_filtering", "URL filtering rules"),
                           ("cloud_app_control", "Cloud App Control rules")):
            section(key, label, False, error="This sign-in has no ZIA API.")
        return out

    svc = getattr(zia, "cloud_browser_isolation", None)
    log("Reading ZIA isolation profiles…")
    if svc is None or not callable(getattr(svc, "list_isolation_profiles", None)):
        section("zia_profiles", "ZIA isolation profiles", False, error="not available in this SDK version")
    else:
        rows, err = one("isolation profiles", lambda: pe._rows(svc.list_isolation_profiles()))
        if err:
            section("zia_profiles", "ZIA isolation profiles", False, error=err)
            log(f"Could not read the ZIA isolation profiles: {err}")
        else:
            out["profiles"] = [normalize_zia_profile(x) for x in rows or []]
            section("zia_profiles", "ZIA isolation profiles", True, len(out["profiles"]))
            log(f"ZIA isolation profiles: {len(out['profiles'])} found.")

    sb = getattr(zia, "secure_browsing", None) or getattr(zia, "browser_control_settings", None)
    log("Reading ZIA Browser Control settings…")
    if sb is None or not callable(getattr(sb, "get_browser_control_settings", None)):
        section("browser_control", "Browser Control settings", False, error="not available in this SDK version")
    else:
        body, err = one("Browser Control settings", lambda: _one_object(sb.get_browser_control_settings()))
        if err or not isinstance(body, dict):
            err = err or "the API returned no settings"
            section("browser_control", "Browser Control settings", False, error=err)
            log(f"Could not read the Browser Control settings: {err}")
        else:
            out["browser_control"] = normalize_browser_control(body)
            section("browser_control", "Browser Control settings", True, 1)
            log("Browser Control settings read.")
    sv = getattr(zia, "secure_browsing", None)
    if sv is None or not callable(getattr(sv, "get_supported_browser_versions", None)):
        section("supported_versions", "supported browser versions", False, error="not available in this SDK version")
    else:
        log("Reading the browser versions ZIA knows…")
        rows, err = one("supported browser versions", lambda: pe._rows(sv.get_supported_browser_versions()))
        if err:
            section("supported_versions", "supported browser versions", False, error=err)
            log(f"Could not read the supported browser versions: {err}")
        else:
            out["supported"] = [normalize_supported(x) for x in rows or [] if isinstance(x, dict)]
            section("supported_versions", "supported browser versions", True, len(out["supported"]))

    uf = getattr(zia, "url_filtering", None)
    log("Reading the URL filtering rules…")
    if uf is None:
        section("url_filtering", "URL filtering rules", False, error="not available in this SDK version")
    else:
        rows, err = one("URL filtering rules", lambda: pe._rows(uf.list_rules()))
        if err:
            section("url_filtering", "URL filtering rules", False, error=err)
            log(f"Could not read the URL filtering rules: {err}")
        else:
            out["rules"]["url_filtering"] = [normalize_zia_rule(r, "url_filtering") for r in rows or [] if isinstance(r, dict)]
            section("url_filtering", "URL filtering rules", True, len(out["rules"]["url_filtering"]))
            log(f"URL filtering rules: {len(out['rules']['url_filtering'])} found.")

    cac = getattr(zia, "cloudappcontrol", None)
    log(f"Reading the Cloud App Control rules ({len(_CAC_TYPES)} rule types, one request each)…")
    if cac is None:
        section("cloud_app_control", "Cloud App Control rules", False, error="not available in this SDK version")
    else:
        rules: List[Dict[str, Any]] = []
        failed: List[str] = []
        first_err = ""
        for t in _CAC_TYPES:
            rows, err = one(f"Cloud App Control {t} rules", lambda t=t: pe._rows(cac.list_rules(t)))
            if err:
                failed.append(t)
                first_err = first_err or err
                continue
            rules.extend(normalize_zia_rule(r, "cloud_app_control", t) for r in rows or [] if isinstance(r, dict))
        if len(failed) == len(_CAC_TYPES):
            section("cloud_app_control", "Cloud App Control rules", False, error=first_err)
            log(f"Could not read the Cloud App Control rules: {first_err}")
        else:
            out["rules"]["cloud_app_control"] = rules
            err = (f"{len(failed)} of {len(_CAC_TYPES)} rule types could not be read ({', '.join(failed[:6])}"
                   f"{'…' if len(failed) > 6 else ''}): {first_err}") if failed else ""
            section("cloud_app_control", "Cloud App Control rules", True, len(rules), error=err, complete=not failed)
            log(f"Cloud App Control rules: {len(rules)} found" + (f"; {err}" if err else "."))
    return out


# ── ZPA ────────────────────────────────────────────────────────────────
def _onoff(v: Any) -> Optional[bool]:
    return as_bool(v)


def normalize_cbi_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    """Only the controls that matter; never debugMode.filePassword."""
    sc = get(p, "securityControls") or {}
    ux = get(p, "userExperience") or {}
    dm = get(p, "debugMode") or {}
    wm = get(sc, "watermark") or {}
    dl = get(sc, "deepLink") or {}
    fz = get(ux, "forwardToZia")
    fz_on = as_bool(get(fz, "enabled")) if isinstance(fz, dict) else as_bool(fz)
    regions = _names(get(p, "regions")) or [as_str(x) for x in (get(p, "regionIds") or [])]
    certs = _names(get(p, "certificates"))
    banner = get(p, "banner")
    return {
        "id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")), "url": as_str(get(p, "cbiUrl")),
        "is_default": bool(as_bool(get(p, "isDefault"))),
        "regions": regions[:20], "certificates": certs[:20], "certificate_count": len(get(p, "certificateIds") or certs),
        "banner": as_str(get(banner, "name")) if isinstance(banner, dict) else "",
        "controls_read": bool(sc) or bool(ux),
        "copy_paste": as_str(get(sc, "copyPaste")).lower() or None,
        "upload_download": as_str(get(sc, "uploadDownload")).lower() or None,
        "allow_printing": _onoff(get(sc, "allowPrinting")),
        "watermark": {"enabled": as_bool(get(wm, "enabled")), "show_user_id": as_bool(get(wm, "showUserId")),
                      "show_timestamp": as_bool(get(wm, "showTimestamp")), "show_message": as_bool(get(wm, "showMessage"))},
        "restrict_keystrokes": _onoff(get(sc, "restrictKeystrokes")), "camera_and_mic": _onoff(get(sc, "cameraAndMic")),
        "document_viewer": _onoff(get(sc, "documentViewer")), "flattened_pdf": _onoff(get(sc, "flattenedPdf")),
        "local_render": _onoff(get(sc, "localRender")),
        "deep_link": {"enabled": as_bool(get(dl, "enabled")), "applications": len(get(dl, "applications") or [])},
        "session_persistence": _onoff(get(ux, "sessionPersistence")), "browser_in_browser": _onoff(get(ux, "browserInBrowser")),
        "forward_to_zia": fz_on, "persist_isolation_bar": _onoff(get(ux, "persistIsolationBar")),
        "translate": _onoff(get(ux, "translate")), "zgpu": _onoff(get(ux, "zgpu")),
        "debug_mode_allowed": as_bool(get(dm, "allowed")),
    }


def normalize_zpa_isolation_profile(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")),
            "enabled": as_bool(get(p, "enabled")) is not False,
            "cbi_profile_id": as_str(get(p, "cbiProfileId") or get(p, "isolationProfileId")),
            "url": as_str(get(p, "cbiUrl") or get(p, "isolationUrl"))}


def normalize_managed_browser(p: Dict[str, Any]) -> Dict[str, Any]:
    cpp = get(p, "chromePostureProfile") or {}
    return {"id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")),
            "browser_type": _upper(get(p, "browserType")),
            "chrome_posture_id": as_str(get(cpp, "id")) if isinstance(cpp, dict) else "",
            "crowdstrike_agent": as_bool(get(cpp, "crowdStrikeAgent")) if isinstance(cpp, dict) else None}


def _true_keys(d: Any) -> List[str]:
    return sorted(str(k) for k, v in (d or {}).items() if as_bool(v)) if isinstance(d, dict) else []


def normalize_browser_protection(p: Dict[str, Any], active_ids: Iterable[str] = ()) -> Dict[str, Any]:
    crit = get(p, "criteria") or {}
    fp = get(crit, "fingerPrintCriteria") or {}
    loc = get(fp, "location") or {}
    pid = as_str(get(p, "id"))
    return {"id": pid, "name": as_str(get(p, "name")) or pid, "active": pid in set(active_ids),
            "default_csp": as_bool(get(p, "defaultCSP")),
            "browser_criteria": _true_keys(get(fp, "browser")), "system_criteria": _true_keys(get(fp, "system")),
            "location": bool(_true_keys(loc)) or bool(as_bool(get(fp, "collect_location") or get(fp, "collectLocation"))),
            "fingerprint_timeout": as_str(get(fp, "fingerprint_timeout") or get(fp, "fingerprintTimeout"))}


def normalize_ba_segment(s: Dict[str, Any]) -> Dict[str, Any]:
    n = zr.normalize_segment(s)
    apps = [x for x in (get(s, "clientlessApps") or []) if isinstance(x, dict)]
    return {"id": n["id"], "name": n["name"], "enabled": n["enabled"], "segment_group_id": n["segment_group_id"],
            "browser_access": n["flags"]["browser_access"], "pra": n["flags"]["pra"],
            "ba_apps": len(apps), "ba_http": sum(1 for a in apps if _upper(get(a, "applicationProtocol")) == "HTTP")}


def normalize_pra_portal(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")),
            "enabled": as_bool(get(p, "enabled")) is not False, "user_portal": as_str(get(p, "userPortalName")),
            "user_notification": bool(as_bool(get(p, "userNotificationEnabled")))}


def normalize_pra_console(c: Dict[str, Any]) -> Dict[str, Any]:
    app = get(c, "praApplication") or {}
    return {"id": as_str(get(c, "id")), "name": as_str(get(c, "name")) or as_str(get(c, "id")),
            "enabled": as_bool(get(c, "enabled")) is not False,
            "segment_id": as_str(get(app, "appId")) if isinstance(app, dict) else "",
            "application": as_str(get(app, "name")) if isinstance(app, dict) else "",
            "portal_ids": [as_str(get(x, "id")) for x in (get(c, "praPortals") or []) if isinstance(x, dict) and as_str(get(x, "id"))]}


def normalize_user_portal(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": as_str(get(p, "id")), "name": as_str(get(p, "name")) or as_str(get(p, "id")),
            "enabled": as_bool(get(p, "enabled")) is not False, "managed_by_zscaler": as_bool(get(p, "managedByZs"))}


def normalize_simple(x: Dict[str, Any], *flags: str) -> Dict[str, Any]:
    """Name, id and the listed booleans only (banners, certificates, regions)."""
    out = {"id": as_str(get(x, "id")), "name": as_str(get(x, "name")) or as_str(get(x, "id"))}
    for f in flags:
        out[zr._snake(f)] = as_bool(get(x, f))
    return out


ZPA_PAGED = (   # key, label, service, method, normalizer
    ("zpa_profiles", "ZPA isolation profiles", "cbi_zpa_profile", "list_isolation_profiles", normalize_zpa_isolation_profile),
    ("managed_browsers", "managed browser profiles", "managed_browser_profile", "list_managed_browser_profiles", normalize_managed_browser),
    ("browser_protection", "browser protection profiles", "browser_protection", "list_browser_protection_profile", None),
    ("segments", "app segments (to find Browser Access and PRA ones)", "app_segments_ba_v2", "list_segments_ba", normalize_ba_segment),
    ("pra_portals", "Privileged Remote Access portals", "pra_portal", "list_portals", normalize_pra_portal),
    ("pra_consoles", "Privileged Remote Access consoles", "pra_console", "list_consoles", normalize_pra_console),
    ("user_portals", "user portals", "user_portal_controller", "list_user_portals", normalize_user_portal),
)
ZPA_SINGLE = (   # one call, no paging: key, label, service, method, normalizer
    ("cbi_profiles", "isolation profiles (Zero Trust Browser)", "cbi_profile", "list_cbi_profiles", None),
    ("cbi_banners", "isolation banners", "cbi_banner", "list_cbi_banners", lambda x: normalize_simple(x, "isDefault")),
    ("cbi_certificates", "isolation certificates", "cbi_certificate", "list_cbi_certificates", lambda x: normalize_simple(x, "isDefault", "enabled")),
    ("cbi_regions", "isolation regions", "cbi_region", "list_cbi_regions", lambda x: normalize_simple(x)),
    ("active_protection", "active browser protection profile", "browser_protection", "list_active_browser_protection_profile", None),
)


def read_zpa(client: Any, log: Callable[[str], None], cancel: Optional[threading.Event], pace: Optional[float] = None) -> Dict[str, Any]:
    """ZPA's side (see the module docstring). Raises Stopped on Stop."""
    zpa = getattr(client, "zpa", None)
    out: Dict[str, Any] = {"sections": {}, "policies": {}}
    if zpa is None:
        for key, label, *_ in ZPA_PAGED + ZPA_SINGLE:
            out["sections"][key] = {"label": label, "read": False, "count": 0, "error": "This sign-in has no ZPA API.", "complete": False}
            out[key] = None
        return out
    gate = zr._Gate(cancel, zr.PACE_SECONDS if pace is None else pace)
    raw: Dict[str, List[Dict[str, Any]]] = {}

    def fail(key: str, label: str, err: str) -> None:
        out["sections"][key] = {"label": label, "read": False, "count": 0, "error": err, "complete": False}
        log(f"Could not read the ZPA {label}: {err}")

    def done(key: str, label: str, items: List[Dict[str, Any]], complete: bool = True) -> None:
        out["sections"][key] = {"label": label, "read": True, "count": len(items), "error": None, "complete": complete}
        log(f"ZPA {label}: {len(items)} found{'' if complete else ' (stopped at the page limit: the list is incomplete)'}.")
        raw[key] = items

    def method(svc: str, name: str) -> Optional[Callable[..., Any]]:
        s = getattr(zpa, svc, None)
        fn = getattr(s, name, None) if s is not None else None
        return fn if callable(fn) else None

    try:
        for key, label, svc, name, _n in ZPA_SINGLE:
            fn = method(svc, name)
            log(f"Reading ZPA {label}…")
            if fn is None:
                fail(key, label, "not available in this SDK version")
                continue
            gate.before()
            try:
                result, resp, err = zr._triple(fn())
            except Exception as e:  # noqa: BLE001 — one failed list never ends the read
                fail(key, label, _err_text(e))
                continue
            if err:
                fail(key, label, _err_text(err))
                continue
            done(key, label, zr.raw_items(result, resp))
        for key, label, svc, name, _n in ZPA_PAGED:
            fn = method(svc, name)
            log(f"Reading ZPA {label}…")
            if fn is None:
                fail(key, label, "not available in this SDK version")
                continue
            try:
                items, complete = zr.list_all(lambda q, _fn=fn: _fn(query_params=q), gate, PAGE_MAX)
            except zr.Stopped:
                raise
            except Exception as e:  # noqa: BLE001
                fail(key, label, _err_text(e))
                continue
            done(key, label, items, complete)
        for ptype, label in (("access", "access policy rules"), ("isolation", "isolation policy rules")):
            key = f"policy:{ptype}"
            fn = method("policies", "list_rules")
            log(f"Reading ZPA {label}…")
            if fn is None:
                fail(key, label, "not available in this SDK version")
                continue
            try:
                items, complete = zr.list_all(lambda q, _fn=fn, _t=ptype: _fn(_t, query_params=q), gate, PAGE_MAX)
            except zr.Stopped:
                raise
            except Exception as e:  # noqa: BLE001
                fail(key, label, _err_text(e))
                continue
            done(key, label, items, complete)
            out["policies"][ptype] = zr.order_rules([
                dict(zr.normalize_rule(r, i, ptype), isolation_profile_id=as_str(get(r, "zpnIsolationProfileId")))
                for i, r in enumerate(items) if isinstance(r, dict)])
        # The isolation profiles' controls: the list may carry them; else one get per profile.
        details: List[Dict[str, Any]] = []
        prof_fn = method("cbi_profile", "get_cbi_profile")
        listed = raw.get("cbi_profiles") or []
        if listed:
            log(f"Reading the controls of {min(len(listed), MAX_PROFILE_DETAILS)} isolation profile(s)…")
        for i, p in enumerate(listed):
            if get(p, "securityControls") or i >= MAX_PROFILE_DETAILS or prof_fn is None or not as_str(get(p, "id")):
                details.append(p)
                continue
            gate.before()
            try:
                body, err = _one_object(prof_fn(as_str(get(p, "id"))))
            except Exception as e:  # noqa: BLE001
                body, err = None, _err_text(e)
            if err or not body:
                log(f"Could not read the controls of isolation profile \"{as_str(get(p, 'name'))}\": {err or 'empty answer'}")
                details.append(p)
            else:
                details.append(dict(p, **body))
        if "cbi_profiles" in raw:
            raw["cbi_profiles"] = details
    except zr.Stopped as e:
        raise Stopped(STOPPED_REASON) from e

    active_ids = [as_str(get(x, "id")) for x in raw.get("active_protection") or []]
    norm: Dict[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
        k: n for k, _l, _s, _m, n in ZPA_SINGLE + ZPA_PAGED if n is not None}
    norm["cbi_profiles"] = normalize_cbi_profile
    norm["browser_protection"] = lambda x: normalize_browser_protection(x, active_ids)
    norm["active_protection"] = lambda x: {"id": as_str(get(x, "id")), "name": as_str(get(x, "name"))}
    for key, fn in norm.items():
        out[key] = [fn(x) for x in raw[key] if isinstance(x, dict)] if key in raw else None
    out["calls"] = gate.calls
    return out


# ── the read ───────────────────────────────────────────────────────────
def read(client: Any, scope: Dict[str, Any], log: Optional[Callable[[str], None]] = None,
         cancel: Optional[threading.Event] = None, pace: Optional[float] = None, zpa_blocked: str = "") -> Dict[str, Any]:
    """Read what `scope` (scope_for) puts in scope. `zpa_blocked` (a reason)
    skips ZPA although it is ticked (no OneAPI / no customer id). Returns
    the normalized snapshot; raises Stopped when Stop is clicked."""
    say = log or (lambda m: None)

    def stop_point() -> None:
        if cancel is not None and cancel.is_set():
            raise Stopped(STOPPED_REASON)

    snap: Dict[str, Any] = {"scope": {"zia": bool(scope.get("zia")), "zpa": bool(scope.get("zpa")) and not zpa_blocked},
                            "not_in_scope": dict(scope.get("not_in_scope") or {}), "zia": None, "zpa": None}
    if zpa_blocked:
        snap["not_in_scope"]["zpa"] = zpa_blocked
    stop_point()
    if scope.get("zia"):
        snap["zia"] = read_zia(client, say, cancel)
    stop_point()
    if scope.get("zpa") and not zpa_blocked:
        snap["zpa"] = read_zpa(client, say, cancel, pace)
    stop_point()
    return snap


# ── the analysis ───────────────────────────────────────────────────────
def _finding(fid: str, severity: str, area: str, title: str, obj_type: str, obj: str, reason: str, fix: str,
             assumption: str = "", **extra: Any) -> Dict[str, Any]:
    f = {"id": fid, "severity": severity, "area": area, "title": title, "object_type": obj_type, "object": obj,
         "reason": reason, "fix": fix}
    if assumption:
        f["assumption"] = assumption
    f.update(extra)
    return f


def _lc(s: Any) -> str:
    return as_str(s).lower()


def _names_list(items: Iterable[str], n: int = 3) -> str:
    items = [x for x in items if x]
    if not items:
        return ""
    head = ", ".join(f"\"{x}\"" for x in items[:n])
    return head + (f" and {len(items) - n} more" if len(items) > n else "")


def _entries(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One entry per isolation profile, matched across the isolation API
    (cbiconfig), ZIA and ZPA (see ASSUMPTIONS)."""
    zia = snap.get("zia") or {}
    zpa = snap.get("zpa") or {}
    cbi = zpa.get("cbi_profiles") or []
    ziap = zia.get("profiles") or []
    zpap = zpa.get("zpa_profiles") or []
    entries: List[Dict[str, Any]] = []
    taken_zia, taken_zpa = set(), set()

    def match(a_id: str, a_url: str, a_name: str, b_id: str, b_url: str, b_name: str) -> bool:
        return bool((a_id and a_id == b_id) or (a_url and a_url == b_url) or (a_name and _lc(a_name) == _lc(b_name)))

    for c in cbi:
        e = {"name": c["name"], "cbi": c, "zia": None, "zpa": [], "sources": ["isolation (Zero Trust Browser)"]}
        for i, z in enumerate(ziap):
            if i not in taken_zia and match(c["id"], c["url"], c["name"], z["id"], z["url"], z["name"]):
                e["zia"] = z
                taken_zia.add(i)
                e["sources"].append("ZIA")
                break
        for i, p in enumerate(zpap):
            if i not in taken_zpa and match(c["id"], c["url"], c["name"], p["cbi_profile_id"], p["url"], p["name"]):
                e["zpa"].append(p)
                taken_zpa.add(i)
        if e["zpa"]:
            e["sources"].append("ZPA")
        entries.append(e)
    for i, z in enumerate(ziap):
        if i not in taken_zia:
            entries.append({"name": z["name"], "cbi": None, "zia": z, "zpa": [], "sources": ["ZIA"]})
    for i, p in enumerate(zpap):
        if i not in taken_zpa:
            entries.append({"name": p["name"], "cbi": None, "zia": None, "zpa": [p], "sources": ["ZPA"]})
    return entries


def _zia_rules(snap: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], bool]:
    """Every ZIA rule read and whether both rule lists were read completely."""
    zia = snap.get("zia") or {}
    rules = zia.get("rules") or {}
    secs = zia.get("sections") or {}
    out = (rules.get("url_filtering") or []) + (rules.get("cloud_app_control") or [])
    complete = bool(snap.get("scope", {}).get("zia")) and all(
        (secs.get(k) or {}).get("read") and (secs.get(k) or {}).get("complete", True) for k in ("url_filtering", "cloud_app_control"))
    return out, complete


def _uses_zia(rule: Dict[str, Any], e: Dict[str, Any]) -> bool:
    p = rule.get("profile")
    if not p:
        return False
    ids = {x for x in ((e.get("zia") or {}).get("id"), (e.get("cbi") or {}).get("id")) if x}
    names = {_lc(x) for x in ((e.get("zia") or {}).get("name"), (e.get("cbi") or {}).get("name"), e["name"]) if x}
    return bool((p.get("id") and p["id"] in ids) or (not p.get("id") and p.get("name") and _lc(p["name"]) in names))


def _usage(snap: Dict[str, Any], entries: List[Dict[str, Any]]) -> None:
    zia_rules, zia_known = _zia_rules(snap)
    zpa = snap.get("zpa") or {}
    iso_rules = (zpa.get("policies") or {}).get("isolation")
    zpa_known = iso_rules is not None and ((zpa.get("sections") or {}).get("policy:isolation") or {}).get("complete", False)
    bc = (snap.get("zia") or {}).get("browser_control") or {}
    smart = bc.get("smart_isolation_profile") if bc.get("smart_isolation") else None
    cbi_read = zpa.get("cbi_profiles") is not None
    for e in entries:
        e["zia_rules"] = [r for r in zia_rules if r["enabled"] and r["isolate"] and _uses_zia(r, e)]
        ids = {p["id"] for p in e["zpa"]}
        e["zpa_rules"] = [r for r in iso_rules or [] if not r.get("disabled") and r.get("isolation_profile_id") in ids
                          and r.get("action") in ("ISOLATE", "")]
        e["smart"] = bool(smart and _uses_zia({"profile": smart}, e))
        used = bool(e["zia_rules"] or e["zpa_rules"] or e["smart"])
        # Which side could still use it, and was that side read? ZIA rules
        # name ZIA (or isolation API) profiles; ZPA rules name ZPA isolation
        # profiles. A ZPA-only profile could still be a ZIA one when the
        # isolation API's list (which ties them together) was not read.
        could_zia = not (e["cbi"] is None and e["zia"] is None and cbi_read)
        could_zpa = bool(e["zpa"])
        known = (not could_zia or zia_known) and (not could_zpa or zpa_known)
        e["used"] = True if used else (False if known else None)
        why = [r["risky"] for r in e["zia_rules"] if r.get("risky")]
        if e["zpa_rules"]:
            why.append("private apps (ZPA isolation policy)")
        e["risky_why"] = why
        e["risky"] = bool(why)


def _ctx(e: Dict[str, Any]) -> str:
    rules = [r["name"] for r in e["zia_rules"]] + [r["name"] for r in e["zpa_rules"]]
    if e["risky"]:
        return f" It isolates {e['risky_why'][0]} (rule {_names_list(rules, 2)}), where this matters most."
    if rules:
        return f" Rules using it: {_names_list(rules, 3)}."
    if e["used"] is False:
        return " No rule uses this profile today, so this is a risk only once a rule starts using it."
    return ""


def _sev(e: Dict[str, Any], risky: str = "high", used: str = "medium", unused: str = "low") -> str:
    if e["risky"]:
        return risky
    if e["used"] is False:
        return unused
    return used


def _control_findings(e: Dict[str, Any]) -> List[Dict[str, Any]]:
    c = e["cbi"]
    if not c or not c.get("controls_read"):
        return []
    out: List[Dict[str, Any]] = []
    n, ctx = c["name"], _ctx(e)
    area = "Isolation controls"
    cp = c.get("copy_paste")
    if cp and cp != "none":
        out.append(_finding("BS-C1", _sev(e), area, "Copy and paste is allowed", "isolation profile", n,
                            f"Isolation profile \"{n}\" lets users copy and paste between the isolated page and their own computer "
                            f"(copyPaste = \"{cp}\"). Text copied out of an isolated app lands on the device, outside Zscaler's control.{ctx}",
                            "Set copy and paste to none in this isolation profile, or give the rules that isolate sensitive, GenAI or "
                            "unsanctioned apps their own stricter profile."))
    ud = c.get("upload_download")
    if ud and ud != "none":
        out.append(_finding("BS-C2", _sev(e), area, "File upload or download is allowed", "isolation profile", n,
                            f"Isolation profile \"{n}\" lets files move between the isolated page and the device (uploadDownload = "
                            f"\"{ud}\"). Downloads put the app's files on the device; uploads send local files into the app.{ctx}",
                            "Set file transfer to none for this profile. If users need to read documents, turn on the document viewer, "
                            "which shows files inside isolation without downloading them."))
    if c.get("allow_printing") is True:
        out.append(_finding("BS-C3", _sev(e, "medium", "low", "low"), area, "Printing is allowed", "isolation profile", n,
                            f"Isolation profile \"{n}\" lets users print isolated pages, which takes the content out on paper or to a PDF "
                            f"printer.{ctx}",
                            "Turn printing off in this profile unless the isolated apps need it; use a separate profile for those."))
    wm = c.get("watermark") or {}
    if wm.get("enabled") is False:
        out.append(_finding("BS-C4", _sev(e, "medium", "low", "low"), area, "No watermark", "isolation profile", n,
                            f"Isolated pages in profile \"{n}\" carry no watermark, so a screenshot or a photo of sensitive data on the "
                            f"screen cannot be traced to a user or a time.{ctx}",
                            "Turn on the watermark with the user ID and the timestamp."))
    elif wm.get("enabled") is True and wm.get("show_user_id") is False:
        out.append(_finding("BS-C4", "info", area, "Watermark without the user ID", "isolation profile", n,
                            f"Profile \"{n}\" shows a watermark but not the user's ID, so a leaked screenshot shows when, not who.",
                            "Tick Show user ID in the watermark settings."))
    if c.get("session_persistence") is True:
        out.append(_finding("BS-C5", "low", area, "Session persistence is on", "isolation profile", n,
                            f"Profile \"{n}\" keeps cookies and sign-ins between isolation sessions, so users stay signed in to isolated "
                            "apps next time. It is a convenience setting: more session state is kept, and a shared or stolen device "
                            "reopens signed-in sessions more easily.",
                            "Turn session persistence off for profiles that isolate sensitive or unsanctioned apps.",
                            "Explained from the setting name and Zscaler's help pages; the API does not document its exact behaviour."))
    if c.get("debug_mode_allowed") is True:
        out.append(_finding("BS-C6", "medium", area, "Debug mode is allowed", "isolation profile", n,
                            f"Profile \"{n}\" lets users switch on debug mode in the isolated browser and save debug files. Debug files "
                            "can hold what the page showed, and they leave isolation. (The debug file password set in the profile is "
                            f"never read out by {PRODUCT}.)",
                            "Turn debug mode off and switch it on only while Zscaler support is troubleshooting.",
                            "That debug files can carry page content is our reading of the feature, not documented in the API."))
    if c.get("local_render") is True:
        out.append(_finding("BS-C7", _sev(e, "medium", "low", "low"), area, "Local rendering is on", "isolation profile", n,
                            f"Profile \"{n}\" lets the user's own browser draw some of the page instead of receiving pixels only, so more "
                            f"of the page (and its data) reaches the device. That weakens isolation for data protection.{ctx}",
                            "Turn local rendering off for profiles that isolate sensitive, GenAI or unsanctioned apps; keep it only where "
                            "a site does not work without it.",
                            "Explained from the setting name and Zscaler's help pages; check the exact behaviour in the Zero Trust Browser "
                            "admin portal before changing it."))
    if c.get("browser_in_browser") is True:
        out.append(_finding("BS-C8", "info", area, "Browser-in-browser is on", "isolation profile", n,
                            f"Profile \"{n}\" shows isolated sessions as a browser inside the browser tab. On its own this changes how "
                            "the session looks, not what data can leave; it is listed so you can confirm it is intended.",
                            "No change is needed for data protection; confirm the setting is intended.",
                            "We found no documentation that browser-in-browser weakens isolation; this is not a gap by itself."))
    if c.get("forward_to_zia") is False and e["zpa_rules"]:
        out.append(_finding("BS-C9", "low", area, "Isolated traffic is not forwarded to ZIA", "isolation profile", n,
                            f"Profile \"{n}\" isolates private apps but does not forward the isolation session's internet traffic to "
                            "ZIA, so ZIA policy (URL filtering, inline DLP) does not see what users reach from inside it.",
                            "Turn on Forward to ZIA in the profile so ZIA policy applies to internet traffic from isolation.",
                            "Explained from the setting name and the SDK docstring (organization, cloud and PAC file to forward to)."))
    return out


def _version_key(v: str) -> Tuple:
    return tuple(int(x) if x.isdigit() else x for x in re.findall(r"\d+|[A-Za-z]+", v))


def outdated_not_blocked(bc: Dict[str, Any], supported: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per browser: the older versions ZIA lists that the tenant does not block."""
    out = []
    for s in supported or []:
        b = s["browser"]
        if b not in BLOCKED_FIELDS or not s["older"]:
            continue
        blocked = {_lc(x) for x in (bc.get("blocked") or {}).get(b) or []}
        missing = [v for v in s["older"] if _lc(v) not in blocked]
        if missing:
            out.append({"browser": b, "name": BROWSER_NAMES.get(b, b), "not_blocked": sorted(missing, key=_version_key)[:40],
                        "count": len(missing), "older": len(s["older"])})
    return out


def _zia_findings(snap: Dict[str, Any], entries: List[Dict[str, Any]], not_assessed: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    zia = snap.get("zia")
    if not zia:
        return out
    secs = zia.get("sections") or {}
    profiles = zia.get("profiles")
    known_ids = {p["id"] for p in profiles or []}
    known_names = {_lc(p["name"]) for p in profiles or []}
    zia_rules, _complete = _zia_rules(snap)
    label = {"url_filtering": "URL filtering rule", "cloud_app_control": "Cloud App Control rule"}
    for r in zia_rules:
        if not (r["enabled"] and r["isolate"]):
            continue
        what = label[r["policy"]]
        if not r["profile"]:
            out.append(_finding("BS-R1", "high", "Rules that isolate", "Isolate action without an isolation profile", what, r["name"],
                                f"{what} \"{r['name']}\" has an isolate action but names no isolation profile, so the "
                                "isolation it promises has no controls behind it (or ZIA cannot apply it).",
                                "Edit the rule and pick the isolation profile it should use, ideally one with copy and paste, file "
                                "transfer and printing off."))
        elif profiles is not None and not ((r["profile"].get("id") and r["profile"]["id"] in known_ids)
                                           or (not r["profile"].get("id") and _lc(r["profile"].get("name")) in known_names)):
            out.append(_finding("BS-R2", "medium", "Rules that isolate", "Rule names an isolation profile that does not exist", what,
                                r["name"], f"{what} \"{r['name']}\" uses isolation profile "
                                f"\"{r['profile'].get('name') or r['profile'].get('id')}\", which is not in the tenant's list of "
                                "isolation profiles.", "Pick an existing isolation profile in the rule."))
    bc = zia.get("browser_control")
    if bc is None:
        if (secs.get("browser_control") or {}).get("error"):
            not_assessed.append("Browser Control (allow all browsers, outdated versions, smart isolation): the settings could not be read.")
        return out
    area = "Browser Control"
    if bc.get("smart_isolation") is False:
        out.append(_finding("BS-B1", "low", area, "Smart isolation is off", "setting", "Smart Browser Isolation",
                            "ZIA does not open suspicious sites (such as likely phishing pages) in isolation automatically, so users "
                            "reach them directly in their own browser.",
                            "Turn on smart isolation in Browser Control, pick a strict isolation profile and the users or groups it covers.",
                            "Smart isolation's behaviour is described from Zscaler's help pages; the API only exposes on/off, the profile and who it covers."))
    elif bc.get("smart_isolation") is True and not bc.get("smart_isolation_profile"):
        out.append(_finding("BS-B2", "medium", area, "Smart isolation has no isolation profile", "setting", "Smart Browser Isolation",
                            "Smart isolation is on but names no isolation profile, so the controls applied to suspicious sites are not set.",
                            "Pick an isolation profile for smart isolation in Browser Control."))
    if bc.get("allow_all_browsers") is True:
        out.append(_finding("BS-B3", "medium", area, "Every browser and version is allowed", "setting", "Allow all browsers",
                            "Browser Control allows every browser and version (allowAllBrowsers = true), so outdated browsers with known "
                            "security holes reach the internet and the blocked-version lists do not apply.",
                            "Turn off Allow all browsers and block the outdated versions of each browser.",
                            "That allowAllBrowsers overrides the blocked-version lists is our reading of the setting."))
    if bc.get("bypass_all_browsers") is True:
        out.append(_finding("BS-B4", "medium", area, "Browser Control bypasses every browser", "setting", "Bypass all browsers",
                            "Browser Control is set to bypass all browsers (bypassAllBrowsers = true): as we read the setting, no browser "
                            "is checked.", "Turn the bypass off so Browser Control checks browsers again.",
                            "The API exposes bypassAllBrowsers without a description; this reading comes from its name."))
    supported = zia.get("supported")
    if supported is None:
        not_assessed.append("Outdated browser versions: the list of browser versions ZIA knows could not be read, so blocked versions were not compared.")
    elif bc.get("allow_all_browsers") is not True:
        for o in outdated_not_blocked(bc, supported):
            out.append(_finding("BS-B5", "low", area, f"Older {o['name']} versions are not blocked", "browser", o["name"],
                                f"ZIA lists {o['older']} older {o['name']} version(s), and the tenant does not block {o['count']} of them: "
                                f"{', '.join(o['not_blocked'][:6])}{'…' if o['count'] > 6 else ''}. Old browsers have known security holes.",
                                f"Block the older {o['name']} versions in Browser Control, or confirm the users who need them.",
                                "Versions are compared exactly as the API returns them."))
    if any(s["browser"] in ("MSEDGE", "MSCHREDGE") and s["older"] for s in supported or []):
        not_assessed.append("Edge versions: the API has no blocked-versions field for Edge, so outdated Edge versions cannot be checked.")
    if bc.get("enable_warnings") is False:
        out.append(_finding("BS-B6", "info", area, "No warnings for outdated browsers", "setting", "Enable warnings",
                            "Users of an outdated browser are not warned, so they do not learn they should update.",
                            "Turn on warnings in Browser Control."))
    return out


def _unused_findings(entries: List[Dict[str, Any]], not_assessed: List[str]) -> List[Dict[str, Any]]:
    out, unknown = [], []
    for e in entries:
        if e["used"] is False:
            where = " or ".join(s for s in ("ZIA" if (e["cbi"] or e["zia"]) else "", "ZPA" if (e["cbi"] or e["zpa"]) else "") if s)
            out.append(_finding("BS-U1", "low", "Isolation profiles", "Isolation profile not used by any rule", "isolation profile", e["name"],
                                f"No enabled {where} rule{', and not smart isolation,' if e['cbi'] or e['zia'] else ''} uses isolation profile "
                                f"\"{e['name']}\". An unused profile is not a risk by itself, but it is easy to pick by mistake and hides "
                                "which profile really protects users.",
                                "Delete the profile if nothing should use it, or point the rules that isolate risky apps at it if it is "
                                "the strict one."))
        elif e["used"] is None:
            unknown.append(e["name"])
    if unknown:
        not_assessed.append(f"Whether {_names_list(unknown, 4)} {'is' if len(unknown) == 1 else 'are'} used by a rule: the rules that could use "
                            "it were not read (not in scope or could not be read).")
    return out


def _zpa_findings(snap: Dict[str, Any], entries: List[Dict[str, Any]], not_assessed: List[str]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    zpa = snap.get("zpa")
    if not zpa:
        return out
    secs = zpa.get("sections") or {}
    pol = zpa.get("policies") or {}
    zpa_ids = {p["id"] for p in zpa.get("zpa_profiles") or []}
    for r in pol.get("isolation") or []:
        if r.get("disabled") or r.get("action") not in ("ISOLATE",):
            continue
        if not r.get("isolation_profile_id"):
            out.append(_finding("BS-R3", "high", "Rules that isolate", "ZPA isolation rule without an isolation profile", "ZPA isolation rule",
                                r["name"], f"ZPA isolation rule \"{r['name']}\" isolates but names no isolation profile, so the "
                                "isolation it promises has no controls behind it.",
                                "Edit the rule in ZPA (Policies → Isolation) and pick the isolation profile it should use."))
        elif zpa.get("zpa_profiles") is not None and r["isolation_profile_id"] not in zpa_ids:
            out.append(_finding("BS-R4", "medium", "Rules that isolate", "ZPA isolation rule names a profile that does not exist",
                                "ZPA isolation rule", r["name"], f"ZPA isolation rule \"{r['name']}\" uses isolation profile id "
                                f"{r['isolation_profile_id']}, which is not in the ZPA isolation profile list.",
                                "Pick an existing isolation profile in the rule."))
    # Browser Access segments nobody can reach.
    import zpa_analysis
    segs = zpa.get("segments")
    access = pol.get("access")
    ba = [s for s in segs or [] if s["browser_access"] and s["enabled"]]
    if segs is None:
        not_assessed.append("Browser Access segments: the app segments could not be read.")
    elif access is None:
        if ba:
            not_assessed.append("Whether Browser Access segments have an access rule: the access policy could not be read.")
    else:
        enabled = [r for r in access if not r.get("disabled")]
        for s in ba:
            seg = {"id": s["id"], "segment_group_id": s["segment_group_id"]}
            hits = [r for r in enabled if zpa_analysis._reaches(r, seg)]
            s["reached_by"] = [r["name"] for r in hits]
            if not hits:
                out.append(_finding("BS-A1", "medium", "Browser Access", "Browser Access app with no access rule", "app segment", s["name"],
                                    f"Browser Access segment \"{s['name']}\" publishes {s['ba_apps']} web app(s), but no enabled access "
                                    "rule applies to it (by the segment or its segment group), so nobody can use it, or it was left "
                                    "behind when the app moved.",
                                    "Add the segment to an access rule for the users who need it, ideally with a managed-browser or posture "
                                    "condition, or disable the segment if it is retired."))
    # Managed browser profiles.
    mbs = zpa.get("managed_browsers")
    if mbs is not None and access is not None:
        refs = set()
        chrome_managed = []
        for r in access:
            if r.get("disabled"):
                continue
            for c in r.get("conditions") or []:
                for o in c.get("operands") or []:
                    if o["type"] == "CHROME_POSTURE_PROFILE":
                        refs.update(x for x in (o.get("rhs"), o.get("lhs")) if x and x != "id")
                    elif o["type"] == "CHROME_ENTERPRISE":
                        chrome_managed.append(r["name"])
        for m in mbs:
            m["used_by"] = sorted({r["name"] for r in access if not r.get("disabled") and any(
                o["type"] == "CHROME_POSTURE_PROFILE" and ({o.get("rhs"), o.get("lhs")} & {m["id"], m["chrome_posture_id"]} - {""})
                for c in r.get("conditions") or [] for o in c.get("operands") or [])})
            if not m["used_by"]:
                out.append(_finding("BS-M1", "low", "Managed browsers", "Managed browser profile not used by any access rule",
                                    "managed browser profile", m["name"],
                                    f"No enabled access rule checks managed browser profile \"{m['name']}\", so it does not decide anything.",
                                    "Add it as a condition to the access rules for sensitive Browser Access apps, or delete it.",
                                    "Rules are matched on CHROME_POSTURE_PROFILE conditions (see the assumptions)."))
        if ba and not refs and not chrome_managed:
            out.append(_finding("BS-M2", "low", "Managed browsers", "No access rule checks the browser", "access policy", "Access policy",
                                f"{len(ba)} Browser Access segment(s) exist, but no access rule checks the browser (Chrome Enterprise or a "
                                "managed browser profile). As far as the browser is concerned, an unmanaged or personal browser can reach them.",
                                "Add a managed browser condition to the access rules of sensitive Browser Access apps.",
                                "Other posture conditions (device posture, trusted networks) may still restrict access; this finding is about the browser only."))
    elif mbs is not None and access is None and mbs:
        not_assessed.append("Whether managed browser profiles are used: the access policy could not be read.")
    if secs.get("cbi_profiles", {}).get("read") is False:
        not_assessed.append("Isolation controls (copy and paste, file transfer, printing, watermark): the isolation profiles could not be read through the ZPA isolation API.")
    return out


def _isolation_rule_rows(snap: Dict[str, Any], entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    zia_rules, _ = _zia_rules(snap)
    label = {"url_filtering": "URL filtering", "cloud_app_control": "Cloud App Control"}
    for r in zia_rules:
        if not r["isolate"]:
            continue
        target = (f"type {r['type']}" + (f": {', '.join(r['applications'][:4])}" if r["applications"] else "")) if r["policy"] == "cloud_app_control" \
            else ", ".join(r["url_categories"][:6])
        rows.append({"product": "ZIA", "policy": label[r["policy"]], "rule": r["name"], "order": r["order"], "enabled": r["enabled"],
                     "action": ", ".join(a for a in r["actions"] if a.startswith("ISOLATE")) or "ISOLATE",
                     "profile": (r["profile"] or {}).get("name") or (r["profile"] or {}).get("id") or "",
                     "targets": target, "sensitive": r["risky"]})
    zpa = snap.get("zpa") or {}
    names = {p["id"]: p["name"] for p in zpa.get("zpa_profiles") or []}
    for r in (zpa.get("policies") or {}).get("isolation") or []:
        rows.append({"product": "ZPA", "policy": "Isolation policy", "rule": r["name"], "order": r.get("order"), "enabled": not r.get("disabled"),
                     "action": r.get("action") or "", "profile": names.get(r.get("isolation_profile_id"), r.get("isolation_profile_id") or ""),
                     "targets": "private apps", "sensitive": "private apps" if r.get("action") == "ISOLATE" else ""})
    return rows


def _profile_rows(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for e in entries:
        c = e["cbi"] or {}
        rules = [r["name"] for r in e.get("zia_rules") or []] + [r["name"] for r in e.get("zpa_rules") or []]
        rows.append({
            "name": e["name"], "sources": e["sources"], "default": bool(c.get("is_default") or (e["zia"] or {}).get("default")),
            "controls_read": bool(c.get("controls_read")),
            "copy_paste": c.get("copy_paste"), "upload_download": c.get("upload_download"), "printing": c.get("allow_printing"),
            "watermark": (c.get("watermark") or {}).get("enabled"), "watermark_user_id": (c.get("watermark") or {}).get("show_user_id"),
            "document_viewer": c.get("document_viewer"), "restrict_keystrokes": c.get("restrict_keystrokes"),
            "local_render": c.get("local_render"), "session_persistence": c.get("session_persistence"),
            "browser_in_browser": c.get("browser_in_browser"), "forward_to_zia": c.get("forward_to_zia"),
            "debug_mode_allowed": c.get("debug_mode_allowed"), "camera_and_mic": c.get("camera_and_mic"),
            "regions": c.get("regions") or [], "certificate_count": c.get("certificate_count") or 0, "banner": c.get("banner") or "",
            "used": e["used"], "smart_isolation": e.get("smart", False), "rules": rules, "sensitive": e["risky_why"][:3]})
    return rows


def analyze(snap: Dict[str, Any]) -> Dict[str, Any]:
    """Findings, inventory tables and what could not be assessed. Never
    reads a tenant (it notes on the snapshot's segments and managed
    browsers which access rules reach them)."""
    entries = _entries(snap)
    _usage(snap, entries)
    not_assessed: List[str] = []
    findings: List[Dict[str, Any]] = []
    for e in entries:
        findings.extend(_control_findings(e))
    if snap.get("zia") is not None or snap.get("zpa") is not None:
        if not (snap.get("zpa") or {}).get("cbi_profiles"):
            if snap.get("zpa") is None and any(e["zia"] for e in entries):
                not_assessed.append("Isolation controls (copy and paste, file transfer, printing, watermark): they are read through the ZPA "
                                    "isolation API, and ZPA was not read, so ZIA's isolation profiles are listed by name only.")
    findings.extend(_zia_findings(snap, entries, not_assessed))
    findings.extend(_unused_findings(entries, not_assessed))
    findings.extend(_zpa_findings(snap, entries, not_assessed))
    findings.sort(key=lambda f: (_SEV_RANK.get(f["severity"], 9), f["area"], f["object"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    counts["total"] = len(findings)
    zia = snap.get("zia") or {}
    zpa = snap.get("zpa") or {}
    bc = zia.get("browser_control")
    seg_names = {s["id"]: s["name"] for s in zpa.get("segments") or []}
    portals = {p["id"]: p["name"] for p in zpa.get("pra_portals") or []}
    inventory = {
        "isolation_profiles": _profile_rows(entries),
        "isolation_rules": _isolation_rule_rows(snap, entries),
        "browser_control": bc,
        "outdated": outdated_not_blocked(bc, zia.get("supported") or []) if bc else [],
        "ba_segments": [dict(s, reached_by=s.get("reached_by")) for s in zpa.get("segments") or [] if s["browser_access"]],
        "pra_segments": [s["name"] for s in zpa.get("segments") or [] if s["pra"]],
        "managed_browsers": zpa.get("managed_browsers"),
        "browser_protection": zpa.get("browser_protection"),
        "pra_portals": zpa.get("pra_portals"),
        "pra_consoles": [dict(c, segment=seg_names.get(c["segment_id"], c.get("application") or c["segment_id"]),
                              portals=[portals.get(p, p) for p in c["portal_ids"]]) for c in zpa.get("pra_consoles") or []]
        if zpa.get("pra_consoles") is not None else None,
        "user_portals": zpa.get("user_portals"),
        "certificates": zpa.get("cbi_certificates"), "banners": zpa.get("cbi_banners"), "regions": zpa.get("cbi_regions"),
    }
    sections = {}
    for side in ("zia", "zpa"):
        for k, v in ((snap.get(side) or {}).get("sections") or {}).items():
            sections[f"{side}:{k}"] = dict(v, product=side.upper())
    return {"findings": findings, "counts": counts, "inventory": inventory, "sections": sections,
            "not_assessed": not_assessed, "not_in_scope": dict(snap.get("not_in_scope") or {}),
            "assumptions": list(ASSUMPTIONS), "glossary": [{"term": t, "meaning": m} for t, m in CONTROL_GLOSSARY],
            "no_api_note": NO_ENTERPRISE_BROWSER_API, "scope": dict(snap.get("scope") or {})}


def run(client: Any, scope: Dict[str, Any], log: Optional[Callable[[str], None]] = None, cancel: Optional[threading.Event] = None,
        pace: Optional[float] = None, zpa_blocked: str = "") -> Dict[str, Any]:
    """Read and analyse; the result never holds the raw read. Raises Stopped."""
    snap = read(client, scope, log=log, cancel=cancel, pace=pace, zpa_blocked=zpa_blocked)
    out = analyze(snap)
    out["readable"] = any(v.get("read") for v in out["sections"].values())
    return scrub(out)


# ── Excel ──────────────────────────────────────────────────────────────
def _yn(v: Any) -> str:
    return "" if v is None else ("Yes" if v else "No")


def workbook(report: Dict[str, Any]) -> bytes:
    """The report as an Excel workbook (xlsx_writer): Summary, Findings,
    Isolation profiles, Rules that isolate, Browser Control, Browser
    Access, Privileged Remote Access, Glossary. Never a secret."""
    import xlsx_writer
    rep = scrub(report)
    inv = rep.get("inventory") or {}
    wb = xlsx_writer.Workbook(title=f"Browser security {rep.get('tenant_label') or ''}".strip(), subject=f"{PRODUCT}: browser security")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    c = rep.get("counts") or {}
    s.extend([["Tenant", rep.get("tenant_label") or ""], ["Generated", rep.get("generated_at") or ""],
              ["Findings", c.get("total", 0)], ["High", c.get("high", 0)], ["Medium", c.get("medium", 0)],
              ["Low", c.get("low", 0)], ["Info", c.get("info", 0)], ["Zscaler Enterprise Browser", rep.get("no_api_note") or NO_ENTERPRISE_BROWSER_API]])
    for k, v in (rep.get("not_in_scope") or {}).items():
        s.append([f"Not in scope ({k.upper()})", v])
    for line in rep.get("not_assessed") or []:
        s.append(["Not assessed", line])
    s.append([])
    s.append(["What was read", "Result"], bold=True)
    for sec in (rep.get("sections") or {}).values():
        s.append([f"{sec.get('product')}: {sec.get('label')}", f"{sec.get('count')} read" if sec.get("read") else f"not read: {sec.get('error') or ''}"])
    f = wb.add_sheet("Findings", columns=["Severity", "ID", "Area", "Title", "Object type", "Object", "Why", "What to do", "Assumption"])
    for x in rep.get("findings") or []:
        f.append([x.get("severity"), x.get("id"), x.get("area"), x.get("title"), x.get("object_type"), x.get("object"),
                  x.get("reason"), x.get("fix"), x.get("assumption", "")])
    p = wb.add_sheet("Isolation profiles", columns=["Profile", "Found in", "Default", "Controls read", "Copy and paste", "Upload and download",
                                                    "Printing", "Watermark", "Watermark user ID", "Document viewer", "Restrict keystrokes",
                                                    "Local rendering", "Session persistence", "Browser-in-browser", "Forward to ZIA",
                                                    "Debug mode allowed", "Used", "Rules", "Sensitive use"])
    for r in inv.get("isolation_profiles") or []:
        p.append([r["name"], ", ".join(r["sources"]), _yn(r["default"]), _yn(r["controls_read"]), r.get("copy_paste") or "",
                  r.get("upload_download") or "", _yn(r.get("printing")), _yn(r.get("watermark")), _yn(r.get("watermark_user_id")),
                  _yn(r.get("document_viewer")), _yn(r.get("restrict_keystrokes")), _yn(r.get("local_render")),
                  _yn(r.get("session_persistence")), _yn(r.get("browser_in_browser")), _yn(r.get("forward_to_zia")),
                  _yn(r.get("debug_mode_allowed")), {True: "Yes", False: "No", None: "Unknown"}[r.get("used")],
                  ", ".join(r.get("rules") or []), "; ".join(r.get("sensitive") or [])])
    ru = wb.add_sheet("Rules that isolate", columns=["Product", "Policy", "Rule", "Order", "Enabled", "Action", "Isolation profile", "Targets", "Sensitive"])
    for r in inv.get("isolation_rules") or []:
        ru.append([r["product"], r["policy"], r["rule"], r.get("order"), _yn(r["enabled"]), r["action"], r["profile"], r["targets"], r["sensitive"]])
    bc = inv.get("browser_control")
    b = wb.add_sheet("Browser Control", columns=["Setting", "Value"], autofilter=False)
    if bc:
        prof = bc.get("smart_isolation_profile") or {}
        b.extend([["Allow all browsers", _yn(bc.get("allow_all_browsers"))], ["Bypass all browsers", _yn(bc.get("bypass_all_browsers"))],
                  ["Warn on outdated browsers", _yn(bc.get("enable_warnings"))], ["Smart isolation", _yn(bc.get("smart_isolation"))],
                  ["Smart isolation profile", prof.get("name") or prof.get("id") or ""],
                  ["Smart isolation users (count)", bc.get("smart_isolation_users", 0)], ["Smart isolation groups (count)", bc.get("smart_isolation_groups", 0)]])
        for name, field in BLOCKED_FIELDS.items():
            b.append([f"Blocked {BROWSER_NAMES[name]} versions", ", ".join((bc.get("blocked") or {}).get(name) or []) or "none"])
        for o in inv.get("outdated") or []:
            b.append([f"Older {o['name']} versions not blocked", ", ".join(o["not_blocked"])])
    else:
        b.append(["Browser Control", "Not read (ZIA platform not in scope, or the settings could not be read)."])
    ba = wb.add_sheet("Browser Access", columns=["Kind", "Name", "Enabled", "Detail", "Used by"])
    for sgm in inv.get("ba_segments") or []:
        ba.append(["Browser Access segment", sgm["name"], _yn(sgm["enabled"]), f"{sgm['ba_apps']} web app(s)",
                   ", ".join(sgm.get("reached_by") or []) if sgm.get("reached_by") is not None else "access policy not read"])
    for m in inv.get("managed_browsers") or []:
        ba.append(["Managed browser profile", m["name"], "", f"{m['browser_type']}; CrowdStrike agent check: {_yn(m.get('crowdstrike_agent')) or 'not set'}",
                   ", ".join(m.get("used_by") or [])])
    for bp in inv.get("browser_protection") or []:
        ba.append(["Browser protection profile", bp["name"], "Active" if bp["active"] else "", f"browser: {', '.join(bp['browser_criteria']) or 'none'}; "
                   f"system: {', '.join(bp['system_criteria']) or 'none'}; location: {_yn(bp['location'])}", ""])
    for u in inv.get("user_portals") or []:
        ba.append(["User portal", u["name"], _yn(u["enabled"]), "", ""])
    pra = wb.add_sheet("Privileged Remote Access", columns=["Kind", "Name", "Enabled", "Segment or portal", "Detail"])
    for pp in inv.get("pra_portals") or []:
        pra.append(["Portal", pp["name"], _yn(pp["enabled"]), pp.get("user_portal") or "", f"user notification: {_yn(pp.get('user_notification'))}"])
    for pc_ in inv.get("pra_consoles") or []:
        pra.append(["Console", pc_["name"], _yn(pc_["enabled"]), pc_.get("segment") or "", ", ".join(pc_.get("portals") or [])])
    g = wb.add_sheet("Glossary", columns=["Term", "What it means"])
    for x in rep.get("glossary") or []:
        g.append([x["term"], x["meaning"]])
    a = wb.add_sheet("Assumptions", columns=["Assumption"])
    for x in rep.get("assumptions") or []:
        a.append([x])
    return wb.to_bytes()
