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

from data_flow import NETWORKS, PLATFORMS, load_packs, read_client_connector, read_zia, resolve_destination, trace

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
    documentation ranges such as 203.0.113.0/24, which are routed.)"""
    return ip is not None and any(ip in n for n in _PRIVATE_NETS)


STOPPED_REASON = "You clicked Stop before the analysis finished, so it was abandoned. Nothing was written."


class Stopped(RuntimeError):
    """The operator clicked Stop; the analysis ended between two read steps."""


_HOST_RE = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def parse_destination(text: str) -> Dict[str, Any]:
    """What the user typed → the host the tenant will see (and whether it
    is an IP address), the scheme, port and path. Raises ValueError with
    a plain sentence for anything that is not a URL, hostname or IP."""
    raw = (text or "").strip()
    if not raw:
        raise ValueError("Enter a URL, a hostname or an IP address.")
    s = raw if re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I) else "https://" + raw
    try:
        u = urlsplit(s)
        host = (u.hostname or "").lower().strip(".")
        port = u.port
    except ValueError as e:
        raise ValueError(f"'{raw}' is not a URL, hostname or IP address ({e}).")
    if not host:
        raise ValueError(f"'{raw}' is not a URL, hostname or IP address.")
    ip = None
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        pass
    if ip is None and not _HOST_RE.match(host):
        raise ValueError(f"'{raw}' is not a URL, hostname or IP address. Examples: https://drive.google.com/file/d/…, dropbox.com, 203.0.113.10.")
    kind = "ip" if ip is not None else ("url" if (u.path and u.path != "/") or u.query else "host")
    return {"input": raw, "host": host, "is_ip": ip is not None, "private": _is_private(ip),
            "scheme": (u.scheme or "https").lower(), "port": port, "path": u.path or "/", "query": u.query or "", "kind": kind}


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
    entry = next((e for e in data if isinstance(e, dict)), {})
    cats = entry.get("urlClassifications") or entry.get("url_classifications") or []
    alerts = entry.get("urlClassificationsWithSecurityAlert") or entry.get("url_classifications_with_security_alert") or []
    out["categories"] = sorted({str(c).upper() for c in cats if c})
    out["security_alerts"] = sorted({str(c).upper() for c in alerts if c})
    app = entry.get("application") or entry.get("app")
    out["application"] = str(app).upper() if app else None
    return out


def _snapshot_zia(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    zia = dict(snapshot["snapshot"]["zia"])
    zia["categories"] = snapshot["snapshot"].get("categories") or {}
    for r in zia.get("dlp", []):
        r.setdefault("enforcing", str(r.get("action", "")).upper() in ("BLOCK", "CONFIRM", "ICAP_RESPONSE"))
        r.setdefault("without_content_inspection", False)
    return zia


def analyze(client, destination: str, network: str = "off", platform: str = "windows", *,
            snapshot: Optional[Dict[str, Any]] = None, log: LogFn = None,
            cancel: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """The live analysis. `snapshot` (a Data Flow Map report: client
    connector + ZIA policy) skips the tenant read; the URL lookup is
    always live. `cancel()` is asked between the read steps: once it is
    true the analysis stops with a plain sentence (nothing is written at
    any point, so stopping loses only the read). Returns the destination,
    the lookup, the trace, the verdict and the assumptions, plus
    `snapshot_for_cache` so the caller can keep the tenant read for the
    next destination."""
    _log = log or (lambda m: None)

    def _check() -> None:
        if cancel and cancel():
            _log("STOPPED — you clicked Stop; the analysis was abandoned. Nothing is ever written by this page.")
            raise Stopped(STOPPED_REASON)

    d = parse_destination(destination)
    network = network if network in {n["key"] for n in NETWORKS} else "off"
    platform = platform if platform in PLATFORMS else "windows"
    if snapshot:
        zcc = snapshot["client_connector"]
        zia = _snapshot_zia(snapshot)
        _log("Using the tenant configuration read a moment ago (Refresh reads it again).")
    else:
        _log("Reading Client Connector: app profiles and their bypasses, forwarding profiles, trusted networks, PAC files…")
        zcc = read_client_connector(client)
        _check()
        _log("Reading ZIA policy: SSL inspection, URL filtering, Cloud App Control, File Type Control, DLP rules on every channel, URL categories…")
        zia = read_zia(client)
    _check()
    _log(f"Asking ZIA which categories {d['host']} belongs to…")
    lk = lookup_categories(client, d["host"])
    if lk["error"]:
        _log(f"The URL lookup could not run ({lk['error']}); the tenant's own category lists decide the categories.")
    else:
        _log("ZIA says: " + (", ".join(lk["categories"]) if lk["categories"] else "no category") + (f"; application {lk['application']}" if lk["application"] else "")
              + (f"; security alert: {', '.join(lk['security_alerts'])}" if lk["security_alerts"] else "") + ".")
    rd = resolve_destination(d["host"], zia)
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
    _log("Tracing the path hop by hop…")
    t = trace(rd, network, platform, zcc, zia, load_packs())
    verdict = derive_verdict(t, d, lk)
    _log(f"Verdict: {verdict['headline']}")
    out = {"destination": d, "lookup": lk, "trace": t, "verdict": verdict, "assumptions": list(ASSUMPTIONS),
           "network": network, "platform": platform, "read_at": time.time(), "fresh_read": snapshot is None}
    if snapshot is None:
        out["snapshot_for_cache"] = {"client_connector": zcc,
                                     "snapshot": {"zia": {k: zia[k] for k in ("ssl", "dlp", "url", "cac", "ftc", "endpoint", "saas", "email", "catalogue")},
                                                  "categories": {k: {"id": v.get("id"), "name": v.get("configured_name") or v.get("name"), "urls": v.get("urls"),
                                                                     "db_categorized_urls": v.get("db_categorized_urls") or v.get("dbCategorizedUrls")}
                                                                 for k, v in (zia.get("categories") or {}).items() if isinstance(v, dict)}},
                                     "diagnostics": zia.get("diagnostics", []) + [{"section": "Client Connector", "error": e} for e in zcc.get("errors", [])]}
    return out


_STOP = ("bypass", "blocked")
_IMPACT = ("bypass", "blocked", "blind", "warn", "assumed")


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
    if outcome == "bypassed" and stop:
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
        headline = f"Reaches {host} decrypted; {n} DLP rule(s) inspect the content and can block it."
        summary = (dlp or {}).get("detail", "")
    elif outcome == "monitor":
        dlp = next((h for h in hops if h["key"] == "dlp"), None)
        n = len((dlp or {}).get("rules") or [])
        headline = f"Reaches {host} decrypted; {n} DLP rule(s) see the content but only monitor it."
        summary = (dlp or {}).get("detail", "") + " Nothing is stopped: a match is logged and, where configured, forwarded as an incident."
    else:
        headline = f"Reaches {host} decrypted; no DLP rule covers this traffic."
        summary = "Uploads and posts go through with nothing inspecting the content."
    impacts: List[Dict[str, Any]] = []
    if lk.get("security_alerts"):
        impacts.append({"hop": "lookup", "label": "URL lookup", "status": "alert", "severity": "high", "rule": None,
                        "detail": f"ZIA flags {host} with a security alert ({', '.join(lk['security_alerts'])}); threat protection normally blocks it before any data control runs."})
    order = {"bypass": 0, "blocked": 1, "blind": 2, "warn": 3, "assumed": 4}
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
         "content_inspected": bool(t["decrypted"] and outcome in ("enforce", "monitor")),
         "impacts": impacts, "categories": categories, "applications": applications}
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
    blind_here = not v["reaches_zscaler"] or not v["decrypted"]   # bypassed or encrypted: the network path sees nothing
    if blind_here:
        reason = "never reaches Zscaler" if not v["reaches_zscaler"] else "reaches Zscaler encrypted, so the content can never be inspected here"
        if ep.get("status") in ("none", "off"):
            why = "the app profile does not install it on this device" if ep.get("status") == "off" else "no Endpoint DLP rule is enabled"
            out.append({"rank": 1, "channel": "endpoint", "action": "Enable Endpoint DLP for this device",
                        "why": f"This traffic {reason}: Endpoint DLP is the only control that ever sees it, and {why}.",
                        "severity": "high"})
        else:
            out.append({"rank": 1, "channel": "endpoint", "action": "Endpoint DLP already covers this device",
                        "why": f"This traffic {reason}, but Endpoint DLP runs locally regardless of the network path and is already {ep.get('status')}.",
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
