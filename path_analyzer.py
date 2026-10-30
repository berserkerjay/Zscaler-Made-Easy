"""Path Analyzer: the path a user's traffic takes through the tenant to one
destination, live, with what blocks or impacts it.

You give it what a user would type (a URL, a hostname or an IP address);
it reads the tenant as it is now and walks the same hops the Data Flow
Map walks (data_flow.trace): the Client Connector app profile and its
bypasses, the forwarding profile for the network, the PAC file, then in
ZIA Cloud App Control, URL filtering, SSL inspection, File Type Control
and inline Web DLP, and what happens after a match. On top of the trace
it asks ZIA itself which categories the destination belongs to
(POST /urlLookup, the same lookup the portal's URL Lookup uses) so a
hostname the tenant's own category lists do not mention is still placed
correctly, and it turns the hops into one verdict in plain words: where
the traffic stops (or that it reaches the destination), which object
decides that, whether the content is inspected, and every point that
impacts the traffic on the way.

Assumptions are stated, not hidden: the trace is for any user, group and
location (rules scoped to specific users decide nothing here), browser
traffic over HTTPS from a managed device with Client Connector, at the
time of the read. It is the configuration's answer, not a log line.
"""
from __future__ import annotations

import ipaddress
import re
import time
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlsplit

import zia_path_modules
from data_flow import (NETWORKS, NOTHING_IN_SCOPE, PATH_SECTIONS, PLATFORMS, ReadStopped, full_path_scope, load_packs,  # noqa: F401
                       path_scope, read_client_connector, read_zia, resolve_destination, stop_on, stop_requested, trace, unread_sections)

LogFn = Optional[Callable[[str], None]]

ASSUMPTIONS: List[str] = [
    "Any user, group, department and location: rules scoped to specific users, groups, departments or locations are named where they apply but do not decide the path.",
    "Browser traffic over HTTPS from a managed device running Client Connector on the platform you chose, on the network you chose.",
    "The tenant's configuration as it is right now (a live read), not a log of past transactions; time-of-day, device posture and user risk score are not evaluated.",
    "ZIA's own URL category lookup places the destination; a destination in a custom category is matched against that category's URL list as well.",
]

_PRIVATE_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "::1/128", "fe80::/10")]


def _is_private(ip) -> bool:
    """RFC 1918, loopback and link-local only: an address a user reaches
    without leaving the site. (Python's is_private also flags the
    documentation ranges such as 203.0.113.0/24, which are routed.) An
    IPv4-mapped IPv6 address (::ffff:10.0.0.1) is its IPv4 address."""
    if ip is not None and getattr(ip, "ipv4_mapped", None) is not None:
        ip = ip.ipv4_mapped
    return ip is not None and any(ip.version == n.version and ip in n for n in _PRIVATE_NETS)


STOPPED_REASON = ("You clicked Stop before the analysis finished, so it was abandoned: nothing more was read from the tenant and no partial result is shown. "
                  "Nothing was written.")


class Stopped(RuntimeError):
    """The operator clicked Stop; the analysis ended between two read steps."""


_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
_USERINFO = re.compile(r"^((?:[a-z][a-z0-9+.-]*://)?)[^/?#@]*@", re.I)


def _shown(raw: str) -> str:
    """What the user typed, as the result and its messages repeat it: any
    user name and password in the URL (https://user:pass@host/) left out.
    They are never needed to place a destination."""
    return _USERINFO.sub(r"\1", raw)


def parse_destination(text: str) -> Dict[str, Any]:
    """What the user typed → the host the tenant will see (and whether it
    is an IP address), the scheme, port and path. Raises ValueError with
    a plain sentence for anything that is not a URL, hostname or IP."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Enter a URL, a hostname or an IP address.")
    try:   # a bare IPv6 address (2001:db8::1) is a host, not host:port
        if raw.count(":") >= 2 and "[" not in raw and "/" not in raw:
            raw = str(ipaddress.ip_address(raw))
            raw_in = f"[{raw}]"
        else:
            raw_in = raw
    except ValueError:
        raw_in = raw
    s = raw_in if re.match(r"^[a-z][a-z0-9+.-]*://", raw_in, re.I) else "https://" + raw_in
    try:
        u = urlsplit(s)
        host = (u.hostname or "").lower().strip(".")
        port = u.port
    except ValueError as e:
        raise ValueError(f"'{_shown(raw)}' is not a URL, hostname or IP address ({e}).")
    if not host:
        raise ValueError(f"'{_shown(raw)}' is not a URL, hostname or IP address.")
    if port == 0:
        raise ValueError("The port must be a whole number from 1 to 65535.")
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = zia_path_modules.ascii_host(host)   # an internationalised name, as ZIA holds it (punycode)
        except ValueError:
            pass
    if ip is None and not _HOST_RE.match(host):
        raise ValueError(f"'{_shown(raw)}' is not a URL, hostname or IP address. Examples: https://drive.google.com/file/d/…, dropbox.com, 203.0.113.10.")
    kind = "ip" if ip is not None else ("url" if (u.path and u.path != "/") or u.query else "host")
    return {"input": _shown(raw), "host": host, "is_ip": ip is not None, "private": _is_private(ip),
            "scheme": (u.scheme or "https").lower(), "port": port, "path": u.path or "/", "query": u.query or "", "kind": kind}


def _url_host(host: str) -> str:
    return f"[{host}]" if ":" in host else host


def pac_url(d: Dict[str, Any], traffic: Dict[str, Any]) -> str:
    """The URL a browser hands the PAC file's FindProxyForURL for this
    destination: plain HTTP keeps its path and query; HTTPS (and anything
    else) is cut to scheme, host and port, as Chrome and Firefox strip
    https:// URLs before they call the PAC file (browser behaviour,
    assumed for traffic that is not web). A default port is left out."""
    plain = bool(traffic.get("web")) and traffic.get("encrypted") is False
    scheme = "http" if plain else "https"
    port = traffic.get("port")
    shown = f":{port}" if port and port != (80 if plain else 443) else ""
    tail = (d.get("path") or "/") + (f"?{d['query']}" if d.get("query") else "") if plain else "/"
    return f"{scheme}://{_url_host(d['host'])}{shown}{tail}"


def labels(v: Any) -> List[str]:
    """A list of category names from ZIA's lookup answer, upper case and
    sorted: one string is one name; a value of another type (a number, an
    object) is none, never a crash."""
    items = [v] if isinstance(v, str) else v if isinstance(v, (list, tuple)) else []
    return sorted({str(c).upper() for c in items if c and isinstance(c, (str, int))})


def lookup_answer(entry: Dict[str, Any]) -> Dict[str, Any]:
    """One /urlLookup entry → {categories, security_alerts, application, error}."""
    app = entry.get("application") or entry.get("app")
    return {"categories": labels(entry.get("urlClassifications") or entry.get("url_classifications")),
            "security_alerts": labels(entry.get("urlClassificationsWithSecurityAlert") or entry.get("url_classifications_with_security_alert")),
            "application": str(app).upper() if app and isinstance(app, (str, int)) else None, "error": None}


def lookup_categories(client, host: str) -> Dict[str, Any]:
    """Ask ZIA which categories `host` belongs to (POST /urlLookup). Returns
    {categories, security_alerts, application, error}; a lookup that
    cannot run is reported, never invented."""
    out: Dict[str, Any] = {"categories": [], "security_alerts": [], "application": None, "error": None}
    post = getattr(client, "post", None)
    if not callable(post):
        out["error"] = "this client cannot run a URL lookup"
        return out
    try:
        data, status = post("/zia/urlLookup", [host])
    except Exception as e:  # noqa: BLE001
        out["error"] = f"URL lookup failed: {str(e)[:160]}"
        return out
    if status not in (200, 201) or not isinstance(data, list):
        detail = data.get("error") if isinstance(data, dict) else ""
        out["error"] = f"URL lookup answered HTTP {status}" + (f": {str(detail)[:160]}" if detail else "")
        return out
    return lookup_answer(next((e for e in data if isinstance(e, dict)), {}))


def _snapshot_zia(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    zia = dict(snapshot["snapshot"]["zia"])
    zia["categories"] = snapshot["snapshot"].get("categories") or {}
    zia.setdefault("unread", unread_sections(snapshot.get("diagnostics")))
    for r in zia.get("dlp", []):
        r.setdefault("enforcing", str(r.get("action", "")).upper() in ("BLOCK", "CONFIRM", "ICAP_RESPONSE"))
        r.setdefault("without_content_inspection", False)
    return zia


def snapshot_scope_key(snapshot: Optional[Dict[str, Any]]) -> Optional[str]:
    """The scope a kept tenant read was made for (path_scope's `key`), or
    None for a read that does not say (a Data Flow Map read of everything,
    or one from before reads were scoped)."""
    if not isinstance(snapshot, dict):
        return None
    k = snapshot.get("path_scope")
    return k if isinstance(k, str) else None


def reusable(snapshot: Optional[Dict[str, Any]], scope: Dict[str, Any], platform: Optional[str] = None) -> bool:
    """Whether a kept tenant read may answer for `scope`: only a read made
    for exactly the same parts of the tenant. A read for a wider scope
    would show what is now out of scope; one for a narrower scope would
    say "not in scope" for what is now in it."""
    return (bool(snapshot) and snapshot_scope_key(snapshot) == scope.get("key") and zia_path_modules.snapshot_ready(snapshot, scope) and
            ("zcc" not in scope.get("read", []) or
             ((snapshot.get("client_connector") or {}).get("profile_schema") == 4 and
              (snapshot.get("client_connector") or {}).get("profile_platform") in (None, platform))))


def analyze(client, destination: str, network: str = "off", platform: str = "windows", *,
            scope: Optional[Dict[str, Any]] = None, snapshot: Optional[Dict[str, Any]] = None, log: LogFn = None,
            cancel: Any = None, context: Optional[Dict[str, Any]] = None, lookup: Optional[Dict[str, Any]] = None,
            protocol: Optional[str] = None, port: Optional[int] = None,
            packs: Optional[List[Dict[str, Any]]] = None,
            identity: Any = None) -> Dict[str, Any]:
    """The live analysis. `scope` (data_flow.path_scope: the Scope page's
    ticked scopes and the channels marked Zscaler) is required, and only
    the parts of the tenant in it are read; every other hop says "not in
    scope". `snapshot` (an earlier read for the same scope, see
    `reusable`) skips the tenant read; the URL lookup is always live when
    in scope. `cancel` (a threading.Event or a callable) is the operator's
    Stop: it is checked between every read step, between paged calls and
    while a request waits out ZIA's rate limit; once set nothing more is
    sent and Stopped is raised: a partial read is never returned as a
    result. Returns the destination, the lookup, the trace, the verdict,
    the scope and the assumptions, plus `snapshot_for_cache` so the
    caller can keep the tenant read for the next destination. `lookup`
    (lookup_many's answer for this host) stands in for the live URL
    lookup, so a batch asks ZIA once per hundred hosts. `protocol` (tcp or
    udp) and `port` trace traffic other than HTTPS (zia_path_modules:
    every ZIA module in order, `zia_modules` in the result; the steps
    before ZIA, such as the evaluated PAC file, are `modules`). `packs`
    (data_flow.load_packs(), read once by a caller that traces many
    destinations) saves reading the pack library again for each one."""
    _log = log or (lambda m: None)

    def _stopped() -> Stopped:
        _log("STOPPED — you clicked Stop; the analysis was abandoned and nothing more was read. Nothing is ever written by this page.")
        return Stopped(STOPPED_REASON)

    def _check() -> None:
        if stop_requested(cancel):
            raise _stopped()

    if not scope or not scope.get("read"):
        raise ValueError(NOTHING_IN_SCOPE)
    if (context or {}).get("channel") not in (None, "", "web"):
        raise ValueError("The Path analyzer models inline web traffic; use channel-specific evidence for Endpoint, SaaS or Email operations.")
    d = parse_destination(destination)
    traffic = zia_path_modules.traffic_context(d, protocol, port)
    network = network if network in {n["key"] for n in NETWORKS} else "off"
    platform = platform if platform in PLATFORMS else "windows"
    if snapshot and not reusable(snapshot, scope, platform):
        _log("The tenant read kept from before was made for a different scope; reading again for what is in scope now.")
        snapshot = None
    try:
        with stop_on(client, cancel):
            _check()
            if snapshot:
                zcc = snapshot["client_connector"]
                zia = _snapshot_zia(snapshot)
                _log("Using the tenant configuration read a moment ago for the same scope (Refresh reads it again).")
            else:
                _log(scope["summary"])
                if "zcc" in scope["read"]:
                    _log("Reading Client Connector: app profiles and their bypasses, forwarding profiles, trusted networks"
                         + (", PAC files…" if "pac" in scope["read"] else "…"))
                zcc = read_client_connector(client, scope=scope, cancel=cancel, platform=platform)
                _check()
                zia_parts = [PATH_SECTIONS[k][0] for k in scope["read"] if k not in ("zcc", "pac")]
                if zia_parts:
                    _log("Reading ZIA policy: " + ", ".join(zia_parts) + (", URL categories…" if scope["lookup"] else "…"))
                zia = read_zia(client, scope=scope, cancel=cancel)
                _check()
                zia["modules"] = zia_path_modules.read(client, scope, cancel, _log)
            _check()
            if scope["lookup"] and lookup is not None:
                lk = dict(lookup)
            elif scope["lookup"]:
                _log(f"Asking ZIA which categories {d['host']} belongs to…")
                lk = lookup_categories(client, d["host"])
                _check()
            else:
                lk = {"categories": [], "security_alerts": [], "application": None, "error": None, "not_in_scope": True}
    except ReadStopped:
        raise _stopped()
    if lk.get("not_in_scope"):
        _log("ZIA's URL lookup is not in scope (no ZIA policy section is), so it was not asked.")
    elif lk["error"]:
        _log(f"The URL lookup could not run ({lk['error']}); the tenant's own category lists decide the categories.")
    else:
        _log("ZIA says: " + (", ".join(lk["categories"]) if lk["categories"] else "no category") + (f"; application {lk['application']}" if lk["application"] else "")
              + (f"; security alert: {', '.join(lk['security_alerts'])}" if lk["security_alerts"] else "") + ".")
    rd = resolve_destination(d["host"], zia, d["path"])
    rd["kind"] = "ip" if d["is_ip"] else "host"
    rd["label"] = d["host"]
    rd["host"] = d["host"]
    rd["categories"] = sorted(set(rd.get("categories") or []) | set(lk["categories"]))
    if lk["application"]:
        rd["applications"] = sorted(set(rd.get("applications") or []) | {lk["application"]})
        for cls, apps in (zia.get("catalogue") or {}).items():
            if lk["application"] in apps and cls not in rd["app_classes"]:
                rd["app_classes"].append(cls)
    rd["lookup"] = lk
    rd["url"] = f"{d['scheme']}://{_url_host(d['host'])}{':' + str(d['port']) if d['port'] else ''}{d['path']}{'?' + d['query'] if d['query'] else ''}"
    rd["pac_url"] = pac_url(d, traffic)
    if traffic["web"] and traffic["encrypted"] is False:
        context = dict(context or {}, plaintext=True)   # plain HTTP: no TLS on this path
    # What-if (path_whatif): rules scoped to the identity given apply, the
    # others are skipped; the PAC file is evaluated by pac_eval, never run.
    import path_whatif
    ident = path_whatif.normalize_identity(identity)
    zia_t, wcounts = path_whatif.apply_identity(zia, ident)
    if ident:
        _log(f"Evaluating rules scoped to the identity you gave: {wcounts['applies']} apply, {wcounts['skipped']} are for others, {wcounts['open']} still depend on something not given.")
    _log("Tracing the path hop by hop…")
    t = trace(rd, network, platform, zcc, zia_t, load_packs() if packs is None else packs, scope=scope, context=context)
    zm = zia_path_modules.evaluate(t, d, traffic, zia_t, lk, context)
    zia_path_modules.extend_trace(t, zm)
    verdict = derive_verdict(t, d, lk)
    zia_path_modules.annotate_verdict(verdict, zm, d["host"])
    _log(f"Verdict: {verdict['headline']}")
    sc = {"summary": scope["summary"], "read": list(scope["read"]), "not_in_scope": dict(scope["not_in_scope"]), "key": scope["key"],
          "scopes": list(scope.get("scopes") or []), "channels": dict(scope.get("channels") or {})}
    assumptions = [a if traffic["web"] and traffic["encrypted"] or not a.startswith("Browser traffic over HTTPS") else
                   f"{traffic['label']} traffic from a managed device running Client Connector on the platform you chose, on the network you chose."
                   for a in ASSUMPTIONS] + zia_path_modules.ASSUMPTIONS + traffic["notes"]
    if ident:
        assumptions[0] = path_whatif.assumption(ident)
    if scope["not_in_scope"]:
        assumptions.append("Only what is in scope on the Scope page was read; these parts are not in scope and their hops are not assessed: "
                           + ", ".join(PATH_SECTIONS[k][0] for k in PATH_SECTIONS if k in scope["not_in_scope"]) + ".")
    out = {"required_controls": zia.get("required_controls", []), "destination": d, "lookup": lk, "trace": t, "verdict": verdict, "assumptions": assumptions, "scope": sc,
           "zia_modules": zm,
           # The steps before ZIA in the shared hop shape (the evaluated PAC
           # file here; zpa_path.merge puts ZPA and the connector in front).
           "modules": [h["module_hop"] for h in t.get("hops") or [] if h.get("module_hop")],
           "network": network, "platform": platform, "read_at": time.time(), "fresh_read": snapshot is None,
           "whatif": path_whatif.whatif(zia_t, t["destination"], ident, wcounts, scope.get("not_in_scope"))}
    # Recent traffic to this destination: only when ZIA Insights is in
    # scope, and never faked. Z-Insights cannot filter by host or domain,
    # so this says so without asking the tenant anything.
    import insights
    out["recent_traffic"] = insights.recent_traffic_for_host(d["host"], "insights" in (scope.get("scopes") or []))
    if snapshot is None:
        out["snapshot_for_cache"] = {"client_connector": zcc, "path_scope": scope["key"],
                                     "snapshot": {"zia": {k: zia[k] for k in ("ssl", "dlp", "url", "cac", "ftc", "endpoint", "saas", "email", "catalogue", "not_in_scope", "required_controls", "modules")},
                                                  "categories": {k: {"id": v.get("id"), "name": v.get("configured_name") or v.get("name"), "urls": v.get("urls"),
                                                                     "db_categorized_urls": v.get("db_categorized_urls") or v.get("dbCategorizedUrls")}
                                                                 for k, v in (zia.get("categories") or {}).items() if isinstance(v, dict)}},
                                     "diagnostics": zia.get("diagnostics", []) + [{"section": "Client Connector", "error": e} for e in zcc.get("errors", [])]}
    return out


_STOP = ("bypass", "blocked")
_IMPACT = ("bypass", "blocked", "blind", "warn", "assumed", "unknown")


def derive_verdict(t: Dict[str, Any], d: Dict[str, Any], lk: Dict[str, Any]) -> Dict[str, Any]:
    """One answer in plain words from the hops: where the traffic ends,
    what decides it, whether the content is inspected, and every point
    that impacts the traffic on the way (blocking first, then blind
    spots, then warnings), each naming the object behind it."""
    hops = t["hops"]
    stop = next((h for h in hops if h["status"] in _STOP), None)
    outcome = t["outcome"]
    host = d["host"]
    rule = lambda h: (h.get("decided_by") or {}).get("name")  # noqa: E731
    seen = "unencrypted (plain HTTP)" if t.get("plaintext") else "decrypted"
    if t.get("conditional"):
        headline = f"Unable to verify how the device reaches {host}."
        summary = "The app profile or its linked forwarding settings could not be verified. Downstream policy results apply only if this traffic reaches ZIA; they do not establish that the device is protected."
    elif outcome == "bypassed" and stop:
        headline = f"Never reaches Zscaler: {stop['label'].lower()} sends {host} direct."
        summary = f"{stop['detail']} Nothing in ZIA applies; only Endpoint DLP on the device can see this traffic."
    elif outcome == "blocked" and stop:
        headline = f"Blocked by {stop['label']}" + (f" rule '{rule(stop)}'" if rule(stop) else "") + "."
        summary = f"{stop['detail']} The user gets the block page; no content leaves."
    elif outcome == "blind":
        ssl = next((h for h in hops if h["key"] == "ssl"), None)
        headline = f"Reaches {host} encrypted: Zscaler sees the hostname, never the content."
        summary = (ssl["detail"] if ssl else "No SSL inspection decision could be found.") + " DLP rules cannot inspect what is uploaded or posted here."
    elif outcome == "enforce":
        dlp = next((h for h in hops if h["key"] == "dlp"), None)
        n = len((dlp or {}).get("rules") or [])
        headline = f"Reaches {host} {seen}; {n} DLP rule(s) are configured to inspect content and can block a qualifying match."
        summary = (dlp or {}).get("detail", "")
    elif outcome == "unknown":
        unread = [h["label"] for h in hops if h["status"] == "unknown" and h["key"] != "incident"]
        unsupported = next((h for h in hops if h.get("why") == "SSL action not recognized"), None)
        headline = (f"Reaches {host}; inspection is unverified because the SSL rule action is not recognized." if unsupported else
                    f"Reaches {host}; whether DLP inspects it is unknown: the {' and '.join(unread) or 'policy'} rules could not be read.")
        summary = unsupported["detail"] if unsupported else "A failed or rate-limited read is not an empty rule list, so this is not reported as 'no DLP rule'. Run the analysis again (Refresh) once the API answers."
    elif outcome == "out_of_scope":
        dlp = next((h for h in hops if h["key"] == "dlp"), None)
        headline = f"Reaches {host}; whether DLP inspects it is not assessed: it is not in scope on the Scope page."
        summary = ((dlp or {}).get("detail") or "") + " Nothing was read for it, so this is neither 'no DLP rule' nor 'could not read'. Put it in scope on the Scope page and analyze again to assess it."
    elif outcome in ("conditional", "metadata_only"):
        headline = (f"Reaches {host}; DLP applicability is conditional on missing identity or content evidence." if outcome == "conditional"
                    else f"Reaches {host}; no eligible content-inspecting DLP engine was established.")
        summary = next((h["detail"] for h in hops if h["key"] == "dlp"), "No payload was scanned.")
    elif outcome == "monitor":
        dlp = next((h for h in hops if h["key"] == "dlp"), None)
        n = len((dlp or {}).get("rules") or [])
        headline = f"Reaches {host} {seen}; {n} DLP rule(s) are configured to monitor qualifying content."
        summary = (dlp or {}).get("detail", "") + " Nothing is stopped: a match is logged and, where configured, forwarded as an incident."
    else:
        headline = f"Reaches {host} {seen}; no DLP rule covers this traffic."
        summary = "Uploads and posts go through with nothing inspecting the content."
    impacts: List[Dict[str, Any]] = []
    if lk.get("security_alerts"):
        impacts.append({"hop": "lookup", "label": "URL lookup", "status": "alert", "severity": "high", "rule": None,
                        "detail": f"ZIA flags {host} with a security alert ({', '.join(lk['security_alerts'])}); threat protection normally blocks it before any data control runs."})
    order = {"bypass": 0, "blocked": 1, "blind": 2, "warn": 3, "assumed": 4, "unknown": 5}
    for h in sorted((h for h in hops if h["status"] in _IMPACT), key=lambda h: order.get(h["status"], 9)):
        w = h.get("weak_point") or {}
        impacts.append({"hop": h["key"], "label": h["label"], "status": h["status"], "rule": rule(h), "detail": h["detail"],
                        "severity": w.get("severity") or ("high" if h["status"] in _STOP else "medium"), "fix": w.get("fix")})
    for k, c in (t.get("channels") or {}).items():
        w = c.get("weak_point")
        if w:
            impacts.append({"hop": k, "label": c["label"], "status": c["status"], "rule": None, "detail": c["detail"], "severity": w["severity"], "fix": w["fix"]})
    categories = list(t["destination"].get("categories") or [])
    applications = list(t["destination"].get("applications") or [])
    v = {"outcome": outcome, "headline": headline, "summary": summary,
         "stops_at": stop["label"] if stop else None, "blocked_by": rule(stop) if stop else None,
         "reaches_zscaler": t["reaches_zscaler"], "decrypted": t["decrypted"],
         "content_inspected": False,
         "content_inspection_possible": bool(t.get("content_inspection_possible")),
         "evidence_mode": "configuration", "tested_channel": "web",
         "policy_conditional": bool(t.get("policy_conditional")),
         "impacts": impacts, "categories": categories, "applications": applications,
         # What was not read (out of scope on the Scope page): said, never scored as a gap.
         "not_in_scope": [{"hop": h["key"], "label": h["label"], "detail": h["detail"]} for h in hops if h["status"] == "out_of_scope"]
                         + [{"hop": k, "label": c["label"], "detail": c["detail"]} for k, c in (t.get("channels") or {}).items() if c.get("status") == "out_of_scope"]}
    v["mitigations"] = recommend_mitigations(t, v)
    return v


_MAIL_CATEGORIES = {"WEB_MAIL", "WEBMAIL", "PERSONAL_MAIL"}


def recommend_mitigations(t: Dict[str, Any], v: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What to turn on, across every DLP channel, to close the gap this
    destination exposes — reasoned, not a checklist. Endpoint DLP is the
    device's own control: it runs regardless of whether this transaction
    ever reaches Zscaler, so it is weighed first whenever the network path
    gives no visibility (bypassed or blind). SaaS Security API and Email
    DLP are recommended only when the destination is actually shaped like
    a sanctioned SaaS app or webmail — recommending them for an arbitrary
    website would be noise, not a fix. Returns a ranked list; each item
    names the channel, the one action, why, and how urgent it is."""
    chans = t.get("channels") or {}
    ep, sa, em = chans.get("endpoint") or {}, chans.get("saas") or {}, chans.get("email") or {}
    out: List[Dict[str, Any]] = []
    # Bypassed or encrypted: the network path sees nothing. With SSL
    # inspection out of scope whether it is encrypted is not known, so it
    # is not called encrypted.
    ssl_out = any(h["key"] == "ssl" and h["status"] == "out_of_scope" for h in t.get("hops") or [])
    blind_here = v["outcome"] in ("bypassed", "blind") and not ssl_out
    if blind_here:
        reason = "never reaches Zscaler" if not v["reaches_zscaler"] else "reaches Zscaler encrypted, so the content can never be inspected here"
        if ep.get("status") == "out_of_scope":
            out.append({"rank": 1, "channel": "endpoint", "action": "Endpoint DLP is not in scope",
                        "why": f"This traffic {reason}, so Endpoint DLP is the only control that could see it, but it is not in scope on the Scope page, so it was not read: {ep.get('detail', '')}",
                        "severity": "info"})
        elif ep.get("status") == "unknown":
            out.append({"rank": 1, "channel": "endpoint", "action": "Read the Endpoint DLP rules again",
                        "why": f"This traffic {reason}, so Endpoint DLP is the only control that could see it, but its rules could not be read: run the analysis again once the API answers.",
                        "severity": "medium"})
        elif ep.get("status") in ("none", "off"):
            why = "the app profile does not install it on this device" if ep.get("status") == "off" else "no Endpoint DLP rule is enabled"
            out.append({"rank": 1, "channel": "endpoint", "action": "Enable Endpoint DLP for this device",
                        "why": f"This traffic {reason}: Endpoint DLP is the only control that ever sees it, and {why}.",
                        "severity": "high"})
        else:
            out.append({"rank": 1, "channel": "endpoint", "action": "Verify Endpoint DLP applicability on this device",
                        "why": "The separate-channel rule inventory does not establish device assignment, operation coverage or a content match.",
                        "severity": "info"})
    elif v["outcome"] == "none":
        out.append({"rank": 1, "channel": "web", "action": "Deploy a Web DLP rule that covers this traffic",
                    "why": "The content reaches Zscaler decrypted, but no enabled DLP rule inspects it, so nothing is stopped or logged.",
                    "severity": "high"})
    elif v["outcome"] == "monitor":
        dlp = next((h for h in t["hops"] if h["key"] == "dlp"), None)
        name = ((dlp or {}).get("decided_by") or {}).get("name")
        out.append({"rank": 1, "channel": "web", "action": f"Promote '{name}' from monitor to block" if name else "Promote the monitoring rule to block",
                    "why": "The content is inspected but only logged; once the incidents look right, blocking stops the leak instead of recording it.",
                    "severity": "medium"})
    if categories_mail := (set(v["categories"]) & _MAIL_CATEGORIES):
        if em.get("status") in ("none",):
            out.append({"rank": len(out) + 1, "channel": "email", "action": "Onboard Email DLP for this traffic",
                        "why": f"ZIA places this destination in {', '.join(sorted(c.replace('_', ' ').title() for c in categories_mail))}, and no Email DLP rule is enabled, so outbound mail through it is never inspected.",
                        "severity": "medium"})
    if v["applications"] and sa.get("status") in ("none",):
        out.append({"rank": len(out) + 1, "channel": "saas", "action": f"Onboard {v['applications'][0]} to SaaS Security API",
                    "why": "ZIA recognises this as a sanctioned cloud application, but no SaaS Security API rule scans it at rest, so data already stored there is never checked.",
                    "severity": "low"})
    return out


# ── Batch: every host a HAR file names, against one tenant read ──────────
#
# The Path analyzer page parses a HAR file in the browser (static/har_parse.js)
# and sends only the host names with their request counts: never a header,
# cookie, URL path or body. The batch reads the tenant once (or reuses a
# kept read for the same scope), asks ZIA's URL lookup once per hundred
# hosts (the chunk size zscaler-sdk-python's url_categories.lookup uses)
# and traces each host against that read with analyze(). Stop is honoured
# between hosts and inside every read; the hosts already analyzed are kept
# and the rest are listed as not analyzed.

BATCH_MAX = 200
LOOKUP_CHUNK = 100

# The outcome a results table shows, from the verdict's outcome.
BATCH_OUTCOMES: Dict[str, str] = {
    "bypassed": "bypassed", "blocked": "blocked", "blind": "blind", "enforce": "inspected", "monitor": "monitor-only",
    "none": "no DLP", "conditional": "conditional", "metadata_only": "no content scan", "unknown": "unverified",
    "out_of_scope": "not in scope",
}


def _lookup_key(value: Any) -> str:
    s = str(value or "").strip().lower()
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    return s.split("/", 1)[0].rstrip(".")


def lookup_many(client, hosts: List[str], cancel: Any = None) -> Dict[str, Dict[str, Any]]:
    """ZIA's URL lookup (POST /urlLookup) for many hosts, a hundred per
    request. {host: the same dict lookup_categories returns}. A chunk the
    lookup could not answer gives each of its hosts the error, never an
    invented category. Raises ReadStopped once `cancel` is set."""
    out: Dict[str, Dict[str, Any]] = {}
    post = getattr(client, "post", None)
    for i in range(0, len(hosts), LOOKUP_CHUNK):
        if stop_requested(cancel):
            raise ReadStopped("stopped")
        chunk = hosts[i:i + LOOKUP_CHUNK]
        blank = lambda err: {"categories": [], "security_alerts": [], "application": None, "error": err}  # noqa: E731
        if not callable(post):
            out.update({h: blank("this client cannot run a URL lookup") for h in chunk})
            continue
        try:
            data, status = post("/zia/urlLookup", list(chunk))
        except ReadStopped:
            raise
        except Exception as e:  # noqa: BLE001
            out.update({h: blank(f"URL lookup failed: {str(e)[:160]}") for h in chunk})
            continue
        if stop_requested(cancel):
            raise ReadStopped("stopped")
        if status not in (200, 201) or not isinstance(data, list):
            detail = data.get("error") if isinstance(data, dict) else ""
            err = f"URL lookup answered HTTP {status}" + (f": {str(detail)[:160]}" if detail else "")
            out.update({h: blank(err) for h in chunk})
            continue
        entries = [e for e in data if isinstance(e, dict)]
        by_url = {_lookup_key(e.get("url")): e for e in entries if e.get("url")}
        for pos, h in enumerate(chunk):
            # Matched by the url ZIA echoes; by position only when it echoes none.
            e = by_url.get(_lookup_key(h)) if by_url else (entries[pos] if pos < len(entries) else None)
            if e is None:
                out[h] = blank("the URL lookup returned no answer for this host")
                continue
            out[h] = lookup_answer(e)
    return out


def _hop(res: Dict[str, Any], key: str) -> Dict[str, Any]:
    return next((h for h in (res.get("trace") or {}).get("hops") or [] if h.get("key") == key), {})


def batch_row(host: str, res: Dict[str, Any], stats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """One results-table row for an analysed host: the outcome in a word,
    where it stops, the rule or profile that decides it and the DLP rules
    on the path. `stats` are the HAR counts the page sent."""
    v = res.get("verdict") or {}
    outcome = v.get("outcome") or ""
    name = lambda h: (h.get("decided_by") or {}).get("name") if h else None  # noqa: E731
    if outcome in ("bypassed", "blocked"):
        deciding = v.get("blocked_by") or next((name(h) for h in (res.get("trace") or {}).get("hops") or []
                                                if h.get("status") in ("bypass", "blocked") and name(h)), None)
    elif outcome == "blind":
        deciding = name(_hop(res, "ssl"))
    elif outcome in ("enforce", "monitor"):
        deciding = name(_hop(res, "dlp"))
    else:
        deciding = None
    dlp = _hop(res, "dlp")
    rules = [str(r.get("name")) for r in (dlp.get("rules") or []) if isinstance(r, dict) and r.get("name")] \
        if dlp.get("status") not in ("out_of_scope", "skipped", "not_reached") else []
    s = stats or {}
    return {"host": host, "requests": int(s.get("requests") or 0), "uploads": int(s.get("uploads") or 0),
            "bytes_sent": int(s.get("bytes_sent") or 0), "methods": list(s.get("methods") or []),
            "outcome": BATCH_OUTCOMES.get(outcome, outcome or "unverified"), "outcome_key": outcome,
            "stops_at": v.get("stops_at") or ("reaches the destination" if outcome not in ("bypassed", "blocked") else ""),
            "deciding_rule": deciding or "", "dlp_rules": rules, "headline": v.get("headline") or "",
            "categories": list(v.get("categories") or [])}


def analyze_batch(client, hosts: List[str], network: str = "off", platform: str = "windows", *,
                  scope: Optional[Dict[str, Any]] = None, snapshot: Optional[Dict[str, Any]] = None, log: LogFn = None,
                  cancel: Any = None, stats: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Trace every host against one tenant read. Returns {rows, analyses
    ({host: the full analyze() result}), snapshot_for_cache (a fresh read,
    for the next run), stopped (the reason, or None), not_analyzed (hosts
    Stop left out), errors ({host: reason} for a host that could not be
    traced)}. Hosts must already be valid (parse_destination); at most
    BATCH_MAX. Nothing is written to the tenant."""
    _log = log or (lambda m: None)
    if not scope or not scope.get("read"):
        raise ValueError(NOTHING_IN_SCOPE)
    if len(hosts) > BATCH_MAX:
        raise ValueError(f"At most {BATCH_MAX} hosts per batch; {len(hosts)} were sent.")
    rows: List[Dict[str, Any]] = []
    analyses: Dict[str, Dict[str, Any]] = {}
    errors: Dict[str, str] = {}
    cache = None
    out: Dict[str, Any] = {"rows": rows, "analyses": analyses, "errors": errors, "stopped": None, "not_analyzed": [], "fresh_read": snapshot is None}

    def _stop(at: int) -> Dict[str, Any]:
        _log(f"STOPPED — you clicked Stop after {at} of {len(hosts)} host(s); the rest were not analyzed. Nothing is ever written by this page.")
        out["stopped"] = (f"You clicked Stop after {at} of {len(hosts)} host(s): the hosts already analyzed are shown, "
                          "the rest were not analyzed and nothing more was read from the tenant. Nothing was written.")
        out["not_analyzed"] = list(hosts[at:])
        out["snapshot_for_cache"] = None
        return out

    lookups: Dict[str, Dict[str, Any]] = {}
    if scope.get("lookup") and hosts:
        _log(f"Asking ZIA which categories {len(hosts)} host(s) belong to ({(len(hosts) + LOOKUP_CHUNK - 1) // LOOKUP_CHUNK} lookup request(s))…")
        try:
            with stop_on(client, cancel):
                lookups = lookup_many(client, hosts, cancel)
        except ReadStopped:
            return _stop(0)
        failed = sum(1 for v in lookups.values() if v.get("error"))
        if failed:
            _log(f"The URL lookup could not answer for {failed} host(s); the tenant's own category lists decide their categories.")
    for i, host in enumerate(hosts):
        if stop_requested(cancel):
            return _stop(i)
        if i == 0 and snapshot is None:
            _log("Reading the tenant once for every host (only what is in scope)…")
        try:
            res = analyze(client, host, network, platform, scope=scope, snapshot=snapshot, log=_log if i == 0 else None,
                          cancel=cancel, lookup=lookups.get(host) if scope.get("lookup") else None)
        except Stopped:
            return _stop(i)
        except ValueError as e:
            errors[host] = str(e)[:200]
            _log(f"{host}: not analyzed ({str(e)[:160]})")
            continue
        fresh = res.pop("snapshot_for_cache", None)
        if fresh is not None:
            cache = fresh
            snapshot = fresh   # every later host is traced against this read
        analyses[host] = res
        row = batch_row(host, res, (stats or {}).get(host))
        rows.append(row)
        _log(f"Tracing {i + 1} of {len(hosts)}: {host} — {row['outcome']}")
    if stop_requested(cancel):
        return _stop(len(hosts))
    out["snapshot_for_cache"] = cache
    return out
