"""SSL coverage investigation: how much traffic is NOT inspected, why, and
what to change to fix it, in plain language.

Two parts:

1. Causes, from configuration (always available when the SSL inspection
   rules are in scope). Every enabled SSL inspection rule that leaves
   traffic encrypted (Do not decrypt / bypass), the catch-all or default
   rule when it does not decrypt, Zscaler's certificate-pinned exemptions,
   and, when ZCC is in scope, the Client Connector bypass lists (domains,
   IPs, applications, processes), forwarding profiles that send a network
   direct, and hosted PAC files that return DIRECT. Each becomes a cause
   record: what is not inspected, which rule or setting causes it, how
   risky that is, and a recovery step. The causes are ordered into a
   recovery plan, biggest risk reduction first, each with a "safe to
   change?" note (certificate-pinned applications break when decrypted).

2. Volume, from ZIA Insights (Z-Insights GraphQL through the installed
   zscaler-sdk-python, `client.zins`), only when ZIA Insights is ticked on
   the Scope page and the sign-in is a OneAPI API client. What the SDK can
   and cannot answer was checked in zscaler/zins/*.py (1.9.44):

   * WEB_TRAFFIC.protocols (get_protocols): traffic grouped by protocol
     name, in transactions or bytes. The protocol names are NOT documented
     in the SDK; PROTOCOL_BUCKETS below maps the names this app expects to
     SSL/TLS inspected, SSL/TLS not inspected, HTTP, or other. Any name the
     table does not know is listed back to the user, never guessed into a
     bucket, and "other" is never folded into a percentage silently.
   * WEB_TRAFFIC.no_grouping with include_trend and trend_interval DAY: all
     web traffic per day (context; not split by inspection status).
   * SHADOW_IT.apps: bytes per cloud application. An exempted application
     is matched to it by name (approximate) and the bytes are an upper
     bound: all traffic to that application, inspected or not.
   * There is no SSL inspection or decryption dimension, no grouping by
     URL category and none by policy rule: a category or rule exemption
     cannot be given a traffic volume, and the page says so.

Read-only. Never reads what is not in scope. No secrets in results, logs
or files. Each run's summary (counts by risk and kind, the class coverage
and the inspected share) is kept in a small local history file so the page
can show the trend across runs.
"""
from __future__ import annotations

import json
import os
import math
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

import ssl_flow
from ssl_flow import TRAFFIC_CLASSES, normalize_ssl_rule
import safe_files


# ── Messages ────────────────────────────────────────────────────────────
OUT_OF_SCOPE = ("SSL coverage is not in scope: it reads the SSL inspection rules. On the Scope page tick DLP or "
                "ZIA platform and mark SSL/TLS Inspection as Zscaler, then run it again. Nothing was read.")
STOPPED_REASON = ("You clicked Stop before the SSL coverage read finished, so it was abandoned: nothing more was "
                  "read and no partial result is shown. Nothing is ever written to the tenant by this page.")
BYPASS_NOTE = ("Traffic that a PAC file or Client Connector sends around Zscaler never reaches the Zero Trust "
               "Exchange, so it is not in these numbers: see the Client Connector and PAC causes below.")
PROTOCOL_NOTE = "Based on ZIA's protocol names; check against your Web Insights."
WINDOWS = {"7d": "last 7 days", "30d": "last 30 days"}
RISK_ORDER = {"high": 0, "medium": 1, "low": 2, "expected": 3}
RISK_LABEL = {"high": "High", "medium": "Medium", "low": "Low", "expected": "Expected"}
SAFE_LABEL = {"yes": "Safe to change", "test": "Test with a pilot group first", "no": "Do not change", "keep": "No change needed"}

SSL_CONSOLE = "ZIA Admin Portal → Policy → SSL/TLS Inspection"
ZCC_APP_CONSOLE = "Client Connector Portal → App Profiles → the profile → bypass lists"
ZCC_FWD_CONSOLE = "Client Connector Portal → Forwarding Profile → the profile → forwarding action per network"
PAC_CONSOLE = "ZIA Admin Portal → Hosted PAC Files → the PAC file"

# ── Protocol name → bucket (Z-Insights WEB_TRAFFIC.protocols) ───────────
# The SDK does not document which names WEB_TRAFFIC.protocols returns.
# This one table is the app's reading of ZIA's protocol names; the page
# says "based on ZIA's protocol names; check against your Web Insights" and
# lists every name the table does not know. Names are compared upper case
# with spaces and hyphens as underscores.
#   ssl_inspected      HTTPS that Zscaler decrypted and inspected
#   ssl_not_inspected  TLS that passed through without decryption
#   http               cleartext HTTP: inspected once it reaches the Zero Trust Exchange
#   other              known, but neither (tunnels, FTP): shown apart, never in a percentage
PROTOCOL_BUCKETS: Dict[str, str] = {
    "HTTPS": "ssl_inspected",
    "SSL": "ssl_not_inspected",
    "TUNNEL_SSL": "ssl_not_inspected",
    "HTTP": "http",
    "HTTP_PROXY": "http",
    "TUNNEL": "other",
    "FTP": "other",
    "FTP_OVER_HTTP": "other",
    "NATIVE_FTP": "other",
}
BUCKET_LABEL = {"ssl_inspected": "SSL/TLS inspected", "ssl_not_inspected": "SSL/TLS not inspected",
                "http": "HTTP (cleartext)", "other": "Other / not classified"}

# ── Risk of a traffic class when it is left encrypted ──────────────────
CLASS_RISK = {"file_share": "high", "webmail": "high", "ai_ml": "high", "unknown": "high",
              "social": "medium", "collab": "medium", "forums": "medium", "remote": "medium",
              "privacy": "expected", "general": "high"}
CLASS_LABEL = {k["key"]: k["label"] for k in TRAFFIC_CLASSES}
CATEGORY_CLASS = {c: k["key"] for k in TRAFFIC_CLASSES for c in k["url_categories"]}

# Cloud application identifiers → class, when the Cloud App Control
# catalogue is not read (not in scope). A heuristic on the identifier.
APP_KEYWORDS: List[Tuple[str, Tuple[str, ...]]] = [
    ("ai_ml", ("CHATGPT", "OPENAI", "GEMINI", "BARD", "CLAUDE", "ANTHROPIC", "COPILOT", "PERPLEXITY", "MISTRAL", "DEEPSEEK", "JASPER")),
    ("file_share", ("DROPBOX", "BOX", "WETRANSFER", "ONEDRIVE", "GOOGLE_DRIVE", "GDRIVE", "MEGA", "SHAREFILE", "EGNYTE", "MEDIAFIRE", "SENDSPACE")),
    ("webmail", ("GMAIL", "YAHOO_MAIL", "OUTLOOK", "HOTMAIL", "PROTONMAIL", "AOL_MAIL", "ZOHO_MAIL", "WEBMAIL")),
    ("collab", ("SLACK", "TEAMS", "DISCORD", "WHATSAPP", "TELEGRAM", "SIGNAL", "ZOOM", "WEBEX", "SKYPE")),
    ("social", ("FACEBOOK", "TWITTER", "LINKEDIN", "INSTAGRAM", "REDDIT", "TIKTOK")),
]
# Applications whose desktop or mobile clients commonly pin their server
# certificate, so they stop working when decrypted. A heuristic: the plan
# says to test, never that decrypting them is safe.
PINNED_KEYWORDS = ("ZOOM", "WEBEX", "SKYPE", "GOTOMEETING", "APPLE", "ICLOUD", "ITUNES", "APP_STORE", "WHATSAPP", "SIGNAL", "DROPBOX")
# Destination words that put a bypassed host in a high-risk class.
HIGH_HOST_WORDS = ("dropbox", "box.com", "wetransfer", "drive.google", "docs.google", "onedrive", "sharepoint", "mega.nz",
                   "chatgpt", "openai", "claude.ai", "anthropic", "gemini.google", "copilot", "perplexity",
                   "mail.google", "gmail", "outlook.live", "mail.yahoo", "proton.me", "pastebin", "github", "gitlab")
_INTERNAL_HOST = re.compile(r"(^localhost$|\.local$|\.lan$|\.corp$|\.internal$|\.intranet$|\.home$|^10\.|^192\.168\.|^172\.(1[6-9]|2\d|3[01])\.|^127\.|^[^.]+$)", re.I)

HISTORY_KEEP = 30        # runs kept per tenant
HISTORY_TENANTS = 20     # tenants kept
_HISTORY_LOCK = threading.Lock()
VALUES_MAX = 50          # values listed per cause


class Stopped(Exception):
    """The operator clicked Stop: nothing more is read."""


# ── Small helpers ───────────────────────────────────────────────────────
def _norm(s: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(s or "").upper())


def _tokens(ident: str) -> List[str]:
    return [t for t in re.split(r"[^A-Z0-9]+", ident.upper()) if t]


def _kw_hit(ident: str, kw: str) -> bool:
    up = ident.upper()
    return up == kw or kw in _tokens(up) or ("_" in kw and kw in up) or (len(kw) >= 6 and up.startswith(kw))


def app_class(ident: str, catalogue: Optional[Mapping[str, List[str]]] = None) -> Optional[str]:
    """Traffic class key of a cloud application identifier: from the Cloud
    App Control catalogue when it was read, else by keyword."""
    up = str(ident or "").upper()
    for k in TRAFFIC_CLASSES:
        for cls in k["app_classes"]:
            if up in (catalogue or {}).get(cls, []):
                return k["key"]
    for key, words in APP_KEYWORDS:
        if any(_kw_hit(up, w) for w in words):
            return key
    return None


def is_pinned(ident: str) -> bool:
    return any(_kw_hit(str(ident or ""), w) for w in PINNED_KEYWORDS)


def _host_risky(value: str) -> bool:
    v = str(value or "").lower()
    return any(w in v for w in HIGH_HOST_WORDS)


def _internal(value: str) -> bool:
    v = str(value or "").strip().lstrip("*.").strip("/").lower()
    return bool(_INTERNAL_HOST.search(v))


def _max_risk(risks: Iterable[str]) -> str:
    rs = [r for r in risks if r in RISK_ORDER]
    return min(rs, key=lambda r: RISK_ORDER[r]) if rs else "medium"


def _f(r: Mapping[str, Any], *names: str) -> Any:
    for n in names:
        if isinstance(r, Mapping) and r.get(n) is not None:
            return r[n]
    return None


def _bypass_other_policies(raw: Mapping[str, Any]) -> bool:
    a = raw.get("action")
    if not isinstance(a, Mapping):
        return False
    sub = _f(a, "doNotDecryptSubActions", "do_not_decrypt_sub_actions") or {}
    return ssl_flow._bool(_f(sub, "bypassOtherPolicies", "bypass_other_policies"))


def _cat_name(cat: str, lookup: Mapping[str, Any]) -> str:
    e = (lookup or {}).get(cat) or {}
    return str(e.get("configured_name") or cat)


def _list(values: Iterable[str], n: int = 6) -> str:
    vs = [str(v) for v in values if v]
    return ", ".join(vs[:n]) + (f" and {len(vs) - n} more" if len(vs) > n else "")


# ── Causes from configuration ───────────────────────────────────────────
def _cause(**kw: Any) -> Dict[str, Any]:
    base = {"id": "", "kind": "", "kind_label": "", "what": "", "source": {}, "scope": "everyone", "risk": "medium",
            "risk_reason": "", "effect": "", "recovery": "", "console": "", "safe": "test", "safe_note": "",
            "classes": [], "values": [], "apps": [], "categories": [], "bypass_other_policies": False,
            "never_reaches_zscaler": False, "volume": None}
    base.update(kw)
    base["risk_label"] = RISK_LABEL.get(base["risk"], base["risk"])
    base["safe_label"] = SAFE_LABEL.get(base["safe"], base["safe"])
    return base


def ssl_rule_causes(ssl_rules: List[Mapping[str, Any]], lookup: Optional[Mapping[str, Any]] = None,
                    catalogue: Optional[Mapping[str, List[str]]] = None) -> List[Dict[str, Any]]:
    """One cause per enabled SSL inspection rule that leaves traffic
    encrypted. Pure."""
    lookup = lookup or {}
    out: List[Dict[str, Any]] = []
    raw_by_id = {str(r.get("id")): r for r in ssl_rules if isinstance(r, Mapping)}
    rules = sorted((normalize_ssl_rule(r) for r in ssl_rules if isinstance(r, Mapping)), key=ssl_flow._sort_key)
    for r in rules:
        if not r["enabled"] or r["decision"] != "not_inspected":
            continue
        raw = raw_by_id.get(str(r["id"]), {})
        scope = ", ".join(r["scope"]) or "everyone"
        src = {"setting": "SSL inspection rule", "name": r["name"], "order": r.get("order"), "id": r.get("id"), "action": r["action"]}
        bop = _bypass_other_policies(raw)
        bop_note = (" It also has 'Bypass other policies' set, so URL filtering, Cloud App Control and DLP are skipped for it too."
                    if bop else "")
        who = "" if scope == "everyone" else f" for {scope} only"
        cid = f"ssl-{r.get('id')}"
        if r["zscaler_maintained"]:
            out.append(_cause(id=cid, kind="pinned_exemptions", kind_label="Certificate-pinned exemptions", source=src, scope=scope,
                              what="Applications Zscaler maintains as certificate-pinned (they break when decrypted)",
                              risk="expected", risk_reason="Zscaler keeps this list for apps that refuse a replaced certificate; leaving them encrypted is expected.",
                              effect="Traffic to these applications is not decrypted, so DLP and malware scanning see only the destination.",
                              recovery="Keep this rule enabled and above your decrypt rules. Cover these applications with Endpoint DLP or a SaaS Security API scan instead.",
                              console=SSL_CONSOLE, safe="no", safe_note="Turning it off breaks the pinned applications for every user."))
            continue
        if r["catch_all"]:
            what = ("Everything no earlier rule decrypts (the default rule)" if r["default_rule"] else "Every destination") + who
            risk = "high"
            out.append(_cause(id=cid, kind="catch_all" if scope == "everyone" else "scoped_catch_all",
                              kind_label="Default or catch-all rule" if scope == "everyone" else "Whole groups left encrypted",
                              source=src, scope=scope, what=what, risk=risk, bypass_other_policies=bop, classes=["general"],
                              risk_reason=("All web traffic that no earlier rule decrypts stays encrypted: DLP is blind to ordinary uploads and forms."
                                           if scope == "everyone" else f"All HTTPS traffic of {scope} stays encrypted, whatever the destination.") + bop_note,
                              effect="Inline DLP, malware and sandbox scanning cannot see the content of this traffic.",
                              recovery=(f"Change '{r['name']}' to Inspect (decrypt), keeping Zscaler's recommended exemptions and your privacy exemptions above it."
                                        if scope == "everyone" else
                                        f"Narrow '{r['name']}' to the categories those users really need left encrypted, or delete it, so their traffic falls through to a decrypt rule."),
                              console=SSL_CONSOLE, safe="test",
                              safe_note="Deploy the Zscaler root certificate to every device first (Client Connector can install it), then enable for a pilot group; pinned apps break."))
            continue
        cats = list(r["url_categories"])
        apps = list(r["cloud_applications"])
        dests = ssl_flow._names(_f(raw, "dest_ip_groups", "destIpGroups") or []) + ssl_flow._names(_f(raw, "urls") or [])
        classes: List[str] = []
        unclassified: List[str] = []
        custom: List[str] = []
        for c in cats:
            k = CATEGORY_CLASS.get(c)
            if k:
                classes.append(k)
            else:
                unclassified.append(c)
                if (lookup.get(c) or {}).get("custom"):
                    custom.append(c)
        for a in apps:
            k = app_class(a, catalogue)
            classes.append(k) if k else unclassified.append(a)
        classes = sorted(set(classes), key=lambda k: [x["key"] for x in TRAFFIC_CLASSES].index(k))
        risks = [CLASS_RISK.get(k, "medium") for k in classes]
        if unclassified or dests:
            risks.append("medium")
        risk = _max_risk(risks)
        if bop and risk == "medium":
            risk = "high"
        pinned = [a for a in apps if is_pinned(a)]
        names = [_cat_name(c, lookup) for c in cats] + apps + dests
        what = _list(names) + who
        if risk == "expected":
            reason = ("Banking, health and government sites are commonly left encrypted for employee privacy. That is expected; "
                      "write the decision down and cover regulated data there with Endpoint DLP.")
            recovery = "No change. Record this privacy exemption in the DLP standard and confirm Endpoint DLP covers the regulated data."
            safe, safe_note = "keep", "Decrypting personal banking or health traffic may break privacy law or works-council agreements."
        else:
            high_classes = [CLASS_LABEL[k] for k in classes if CLASS_RISK.get(k) == "high"]
            reason = (f"{_list(high_classes, 4)} {'is' if len(high_classes) == 1 else 'are'} where data most often leaves; left encrypted, DLP cannot see uploads or pasted text."
                      if high_classes else
                      "Left encrypted, DLP and malware scanning see only the destination, never the content.")
            if custom:
                reason += f" Custom URL categor{'y' if len(custom) == 1 else 'ies'} {_list(custom, 3)}: check which sites it holds."
            reason += bop_note
            keep = [a for a in pinned]
            change = [n for n in names if n not in keep]
            recovery = (f"In rule '{r['name']}', remove {_list(change, 4)} (or move a rule that decrypts them above it)"
                        + (f"; keep {_list(keep, 3)} exempt and cover {'it' if len(keep) == 1 else 'them'} with Endpoint DLP" if keep and change else "")
                        + "." if change else
                        f"Keep {_list(keep, 3)} exempt (commonly certificate-pinned) and cover {'it' if len(keep) == 1 else 'them'} with Endpoint DLP or a SaaS Security API scan.")
            if pinned and not change:
                safe, safe_note = "no", "These applications commonly pin their certificate and stop working when decrypted."
            elif pinned:
                safe, safe_note = "test", f"{_list(pinned, 3)} commonly pin{'s' if len(pinned) == 1 else ''} certificates: leave {'it' if len(pinned) == 1 else 'them'} exempt and test the rest with a pilot group."
            else:
                safe, safe_note = "test", "Usually safe once the Zscaler root certificate is on every device; enable for a pilot group first and watch for broken apps."
        out.append(_cause(id=cid, kind="ssl_rule" if scope == "everyone" else "ssl_rule_scoped",
                          kind_label="SSL inspection exemption" if scope == "everyone" else "SSL inspection exemption for some users",
                          source=src, scope=scope, what=what, risk=risk, risk_reason=reason, bypass_other_policies=bop,
                          effect="Traffic to these destinations is not decrypted: inline DLP, malware and sandbox scanning see only where it goes.",
                          recovery=recovery, console=SSL_CONSOLE, safe=safe, safe_note=safe_note,
                          classes=classes, apps=apps, categories=[_cat_name(c, lookup) for c in cats], values=dests[:VALUES_MAX]))
    return out


def zcc_causes(cc: Optional[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    """Causes from Client Connector (data_flow.read_client_connector):
    app-profile bypass lists, forwarding profiles that send a network
    direct, PAC files that return DIRECT. Traffic sent this way never
    reaches Zscaler at all. Pure."""
    if not cc:
        return []
    out: List[Dict[str, Any]] = []
    kinds = (("domains", "Client Connector domain bypass", "domains"), ("ips", "Client Connector IP bypass", "IP addresses or subnets"),
             ("apps", "Client Connector application bypass", "applications"), ("processes", "Client Connector process bypass", "processes"),
             ("vpn_gateways", "Client Connector VPN gateway bypass", "VPN gateways"))
    for key, label, noun in kinds:
        vals: Dict[str, set] = {}
        for p in cc.get("app_profiles") or []:
            for v in ((p.get("bypass") or {}).get(key) or []):
                vals.setdefault(str(v), set()).add(str(p.get("name") or p.get("id")))
        if not vals:
            continue
        values = sorted(vals)
        if len(values) == 1:
            noun = {"domains": "domain", "IP addresses or subnets": "IP address or subnet", "applications": "application",
                    "processes": "process", "VPN gateways": "VPN gateway"}.get(noun, noun)
        profiles = sorted({n for s in vals.values() for n in s})
        external = [v for v in values if not _internal(v)] if key in ("domains", "ips") else values
        risky = [v for v in values if _host_risky(v)]
        if key == "vpn_gateways":
            risk, reason = "low", "VPN gateways are bypassed so the VPN can connect; only the VPN's own traffic skips Zscaler."
            safe, safe_note = "keep", "Removing them stops the VPN from connecting."
            recovery = "No change, as long as the list holds only your own VPN gateways."
        elif risky:
            risk, reason = "high", f"File-sharing, webmail or AI destinations are sent around Zscaler: {_list(risky, 4)}."
            safe, safe_note = "test", "Remove one entry at a time for a pilot group; collaboration apps added for call quality may need a split-tunnel exception instead."
            recovery = f"Remove {_list(risky, 4)} from the bypass list so this traffic goes through Zscaler and can be inspected."
        elif key in ("domains", "ips") and not external:
            risk, reason = "expected", "Only internal names and private addresses are bypassed; that is expected."
            safe, safe_note = "keep", "Internal destinations do not need to reach Zscaler."
            recovery = "No change. Keep the list to internal destinations."
        else:
            risk = "medium"
            reason = (f"{len(values)} {noun} skip Zscaler entirely: whatever is sent to or by them is never inspected."
                      + (" Applications and processes are usually bypassed for call quality or because they pin certificates." if key in ("apps", "processes") else ""))
            safe, safe_note = "test", "Each entry was usually added for a reason (call quality, a pinned app): check with its owner and test with a pilot group."
            recovery = f"Review each of the {len(values)} {noun}: keep only those a business owner can justify, and cover the rest with Endpoint DLP."
        out.append(_cause(id=f"zcc-{key}", kind=f"zcc_{key}", kind_label=label, source={"setting": "Client Connector app profile", "name": _list(profiles, 3)},
                          scope=f"devices on {len(profiles)} app profile{'s' if len(profiles) != 1 else ''}", what=f"{len(values)} {noun}: {_list(values, 5)}",
                          risk=risk, risk_reason=reason, never_reaches_zscaler=True,
                          effect="This traffic never reaches Zscaler: no SSL inspection, no DLP, no malware scanning.",
                          recovery=recovery, console=ZCC_APP_CONSOLE, safe=safe, safe_note=safe_note, values=values[:VALUES_MAX],
                          apps=values[:VALUES_MAX] if key in ("apps", "processes") else []))
    net_label = {"off": "off a trusted network (remote)", "on": "on a trusted network (office)", "vpn": "on VPN", "any": "on every network"}
    for fp in cc.get("forwarding_profiles") or []:
        for net, act in sorted((fp.get("actions") or {}).items()):
            if (act or {}).get("mode_kind") != "none":
                continue
            office = net == "on"
            out.append(_cause(id=f"fwd-{fp.get('id')}-{net}", kind="forwarding_none", kind_label="Forwarding profile sends traffic direct",
                              source={"setting": "Client Connector forwarding profile", "name": fp.get("name"), "id": fp.get("id")},
                              scope=f"devices {net_label.get(net, net)}", what=f"All web traffic of devices {net_label.get(net, net)}",
                              risk="medium" if office else "high", never_reaches_zscaler=True,
                              risk_reason=("On the office network Client Connector forwards nothing; that is fine only if the site's GRE or IPsec tunnel sends the traffic to Zscaler."
                                           if office else "Client Connector forwards nothing on this network, so every user there is completely uninspected."),
                              effect="This traffic never reaches Zscaler through Client Connector.",
                              recovery=("Confirm the office forwards web traffic to Zscaler through a GRE or IPsec tunnel; if not, set the forwarding action to Tunnel."
                                        if office else "Set the forwarding action for this network to Tunnel (Z-Tunnel 2.0) so the traffic reaches Zscaler."),
                              console=ZCC_FWD_CONSOLE, safe="test", safe_note="Change it for a pilot group of devices first and check sign-in and VPN behaviour."))
    for pf in cc.get("pac_files") or []:
        hosts = [str(h) for h in (pf.get("direct_hosts") or [])]
        if not hosts:
            continue
        external = [h for h in hosts if not _internal(h)]
        risky = [h for h in hosts if _host_risky(h)]
        risk = "high" if risky else "medium" if external else "expected"
        out.append(_cause(id=f"pac-{pf.get('id')}", kind="pac_direct", kind_label="PAC file sends sites direct",
                          source={"setting": "Hosted PAC file", "name": pf.get("name"), "id": pf.get("id")},
                          scope="browsers using this PAC file", what=f"{len(hosts)} host pattern{'s' if len(hosts) != 1 else ''} returned DIRECT: {_list(hosts, 5)}",
                          risk=risk, never_reaches_zscaler=True, values=hosts[:VALUES_MAX],
                          risk_reason=(f"File-sharing, webmail or AI sites go direct: {_list(risky, 4)}." if risky else
                                       f"{len(external)} external host pattern{'s' if len(external) != 1 else ''} skip Zscaler." if external else
                                       "Only internal names and private addresses go direct; that is expected."),
                          effect="Browsers send this traffic straight to the internet, never to Zscaler.",
                          recovery=(f"Remove {_list(risky or external, 4)} from the DIRECT statements of this PAC file." if external else
                                    "No change. Keep DIRECT for internal destinations only."),
                          console=PAC_CONSOLE, safe="test" if external else "keep",
                          safe_note=("Edit a copy and point a pilot group at it first; a PAC syntax error sends everything direct or nowhere."
                                     if external else "Internal destinations do not need to reach Zscaler.")))
    return out


# ── Recovery plan ───────────────────────────────────────────────────────
def _impact(c: Mapping[str, Any]) -> Tuple[int, int, float, int]:
    """Sort key: risk first; then whole-traffic causes (the catch-all rule,
    a network sent direct, whole groups left encrypted), whose volume
    Insights cannot measure but which cover everything; then measured
    volume; then breadth."""
    tier = {"catch_all": 3, "forwarding_none": 2, "scoped_catch_all": 1}.get(str(c.get("kind")), 0)
    vol = float(((c.get("volume") or {}).get("bytes")) or 0)
    breadth = (1 if c.get("scope") == "everyone" else 0) + (1 if c.get("bypass_other_policies") else 0)
    return (RISK_ORDER.get(c.get("risk"), 9), -tier, -vol, -breadth)


def recovery_plan(causes: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Ordered changes, biggest risk reduction first, then one step that
    documents the expected exemptions. Pure."""
    acting = sorted([c for c in causes if c["risk"] != "expected" and c["safe"] not in ("keep", "no")], key=_impact)
    held = [c for c in causes if c["risk"] != "expected" and c["safe"] in ("keep", "no")]
    steps: List[Dict[str, Any]] = []
    for c in acting:
        steps.append({"n": len(steps) + 1, "cause_id": c["id"], "risk": c["risk"], "risk_label": c["risk_label"],
                      "title": f"{c['kind_label']}: {c['source'].get('name') or ''}".strip(": "),
                      "change": c["recovery"], "where": c["console"],
                      "effect": ("Traffic that skipped Zscaler reaches it, so it is decrypted and inspected by DLP." if c["never_reaches_zscaler"]
                                 else "This traffic is decrypted, so inline DLP and malware scanning see its content."),
                      "safe": c["safe"], "safe_label": c["safe_label"], "safe_note": c["safe_note"],
                      "volume": c.get("volume")})
    keep = [c for c in causes if c["risk"] == "expected"] + held
    if keep:
        steps.append({"n": len(steps) + 1, "cause_id": ",".join(c["id"] for c in keep), "risk": "expected", "risk_label": "Expected",
                      "title": "Write down the exemptions you keep",
                      "change": "Record why each is kept: " + "; ".join(f"{c['kind_label']} ({c['source'].get('name') or c['what']})" for c in keep[:8])
                                + (" and more" if len(keep) > 8 else "") + ". Cover regulated data there with Endpoint DLP or a SaaS Security API scan.",
                      "where": "Your DLP standard or exception register (no console change)",
                      "effect": "Auditors see a documented, owned exception instead of an unexplained blind spot.",
                      "safe": "keep", "safe_label": SAFE_LABEL["keep"], "safe_note": "Nothing changes in the tenant.", "volume": None})
    prereq = []
    if any(c["kind"].startswith("ssl") or c["kind"] in ("catch_all", "scoped_catch_all") for c in acting):
        prereq = ["Deploy the Zscaler root certificate to every device before decrypting more (Client Connector can install it).",
                  "Keep Zscaler's recommended exemptions for certificate-pinned applications above your decrypt rules.",
                  "Make each change for a pilot group first, then widen it once nothing breaks."]
    return {"steps": steps, "prerequisites": prereq}


# ── Volume from Z-Insights ──────────────────────────────────────────────
def bucket_of(name: Any) -> Tuple[str, bool]:
    """(bucket, recognised) of a WEB_TRAFFIC.protocols entry name. An
    unknown name is ("other", False): shown as not classified, listed back
    to the user, never guessed."""
    key = re.sub(r"[\s\-]+", "_", str(name or "").strip().upper())
    if key in PROTOCOL_BUCKETS:
        return PROTOCOL_BUCKETS[key], True
    return "other", False


def _pct(part: float, whole: float) -> Optional[float]:
    return round(100.0 * part / whole, 1) if whole else None


def protocol_split(rows: Iterable[Mapping[str, Any]]) -> Dict[str, Any]:
    """Totals per bucket and the inspected shares from WEB_TRAFFIC.protocols
    rows ({name, total}). Pure. A share with nothing to divide is None
    (never 0% or 100% made up). "Other" is never part of a percentage; the
    lower bound `total_pct_if_other_not_inspected` says what the total
    would be if all of it were left uninspected."""
    b = {k: 0.0 for k in BUCKET_LABEL}
    unrecognised: Dict[str, float] = {}
    by_name: List[Dict[str, Any]] = []
    for r in rows or []:
        if not isinstance(r, Mapping):
            continue
        try:
            total = float(r.get("total"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(total) or total < 0:   # NaN, an infinity or a negative count is not a volume
            continue
        bucket, known = bucket_of(r.get("name"))
        b[bucket] += total
        name = str(r.get("name") or "(unnamed)")[:80]
        by_name.append({"name": name, "total": total, "bucket": bucket, "recognised": known})
        if not known:
            unrecognised[name] = unrecognised.get(name, 0.0) + total
    ssl_total = b["ssl_inspected"] + b["ssl_not_inspected"]
    inspected = b["ssl_inspected"] + b["http"]
    return {"buckets": b, "ssl_total": ssl_total, "http_total": b["http"], "other_total": b["other"],
            "ssl_pct": _pct(b["ssl_inspected"], ssl_total),
            "http_pct": 100.0 if b["http"] else None,
            "total_pct": _pct(inspected, ssl_total + b["http"]),
            "total_pct_if_other_not_inspected": _pct(inspected, ssl_total + b["http"] + b["other"]) if b["other"] else None,
            "unrecognised": [{"name": k, "total": v} for k, v in sorted(unrecognised.items(), key=lambda x: -x[1])],
            "by_name": by_name}


def _trend_rows(entries: Any) -> List[Dict[str, Any]]:
    """[{day_ms, total}] from WEB_TRAFFIC.no_grouping entries carrying a DAY trend."""
    out: List[Dict[str, Any]] = []
    for e in entries if isinstance(entries, list) else []:
        t = e.get("trend") if isinstance(e, Mapping) else None
        if not isinstance(t, Mapping):
            continue
        try:
            start = int(t.get("trend_start_time"))
        except (TypeError, ValueError):
            continue
        vals = t.get("trend_values") if isinstance(t.get("trend_values"), list) else []
        for i, v in enumerate(vals[:120]):
            try:
                out.append({"day_ms": start + i * 86_400_000, "total": float(v)})
            except (TypeError, ValueError):
                continue
    return out


def _match_name(a: str, b: str) -> bool:
    a, b = _norm(a), _norm(b)
    if not a or not b:
        return False
    if a == b:
        return True
    short, long_ = sorted((a, b), key=len)
    return len(short) >= 5 and long_.startswith(short)


def _host_label(h: str) -> str:
    parts = [p for p in re.split(r"[.*]+", str(h or "").lower()) if p]
    return parts[-2] if len(parts) >= 2 else (parts[0] if parts else "")


def attach_app_volume(causes: List[Dict[str, Any]], apps: List[Mapping[str, Any]]) -> None:
    """Give each cause that names cloud applications (or bypassed hosts)
    the Shadow IT bytes of the applications it matches by name. An upper
    bound: all traffic to the application, whether the rule's scope
    applied or not. Causes on URL categories get no volume (Insights
    cannot group by category). In place."""
    for c in causes:
        names = list(c.get("apps") or [])
        hosts = [_host_label(v) for v in (c.get("values") or []) if c.get("kind") in ("zcc_domains", "pac_direct")]
        matched, total = [], 0.0
        for a in apps:
            app = str(a.get("application") or "")
            if any(_match_name(n, app) for n in names) or any(len(h) >= 4 and _norm(h) == _norm(app)[:len(_norm(h))] and _match_name(h, app) for h in hosts):
                b = float(a.get("data_consumed") or 0)
                matched.append({"application": app, "bytes": b, "category": a.get("application_category") or ""})
                total += b
        if matched:
            c["volume"] = {"bytes": total, "apps": matched[:10], "basis": "Shadow IT bytes of the matched applications (upper bound)"}
        elif names or hosts:
            c["volume"] = {"bytes": None, "apps": [], "basis": "No matching application in Shadow IT for this window"}
        else:
            c["volume"] = {"bytes": None, "apps": [], "basis": "Not measurable: Insights cannot group traffic by URL category or rule"}


def read_volume(zins: Any, window_key: str, *, log: Callable[[str], None], cancel: Any = None,
                scrub: Optional[Callable[[str], str]] = None, pace: Optional[float] = None) -> Dict[str, Any]:
    """Ask Z-Insights, one query at a time and paced: protocols in
    transactions and in bytes, all web traffic per day (bytes), and Shadow
    IT applications. Stop raises Stopped. One failing query never fails
    the others."""
    import insights
    from data_flow import stop_requested
    _scrub = scrub or (lambda s: s)
    win = insights.window(window_key)
    s, e = win["start_ms"], win["end_ms"]
    gap = insights.PACE_SECONDS if pace is None else max(0.0, float(pace))
    asked = {"n": 0}

    def turn() -> None:
        if stop_requested(cancel):
            raise Stopped(STOPPED_REASON)
        if asked["n"] and gap:
            w = getattr(cancel, "wait", None)
            w(gap) if callable(w) else time.sleep(gap)
            if stop_requested(cancel):
                raise Stopped(STOPPED_REASON)
        asked["n"] += 1

    raw_rows = lambda x: [dict(r) for r in x if isinstance(r, Mapping)] if isinstance(x, list) else []  # noqa: E731
    out: Dict[str, Any] = {"status": "ok", "window": dict(win, key=window_key), "protocols": {}, "errors": [], "note": PROTOCOL_NOTE,
                           "bypass_note": BYPASS_NOTE}
    for unit in ("TRANSACTIONS", "BYTES"):
        turn()
        log(f"Asking Insights for web traffic by protocol ({unit.lower()}, {win['label']})…")
        r = insights._ask(lambda u=unit: zins.web_traffic.get_protocols(start_time=s, end_time=e, traffic_unit=u, limit=100),
                          ("WEB_TRAFFIC", "protocols"), _scrub, parse=lambda x: insights.rows_of(x, 100))
        if r["status"] == "error":
            out["errors"].append(f"Protocols ({unit.lower()}): {r.get('error')}")
            out["protocols"][unit] = None
        else:
            out["protocols"][unit] = dict(protocol_split(r.get("rows") or []), status=r["status"])
    turn()
    log("Asking Insights for all web traffic per day (bytes)…")
    r = insights._ask(lambda: zins.web_traffic.get_no_grouping(start_time=s, end_time=e, traffic_unit="BYTES", include_trend=True, trend_interval="DAY"),
                      ("WEB_TRAFFIC", "no_grouping"), _scrub, parse=raw_rows)
    if r["status"] == "error":
        out["errors"].append(f"Daily web traffic: {r.get('error')}")
    out["daily"] = _trend_rows(r.get("rows") or [])
    out["daily_note"] = "All web traffic per day, in bytes. Insights cannot split it by inspection status."
    turn()
    log("Asking Insights for cloud applications (Shadow IT)…")
    r = insights._ask(lambda: zins.shadow_it.get_apps(start_time=s, end_time=e, limit=200), ("SHADOW_IT", "apps"), _scrub,
                      parse=lambda x: insights.app_rows(x, 200))
    if r["status"] == "error":
        out["errors"].append(f"Shadow IT applications: {r.get('error')}")
    out["apps"] = r.get("rows") or []
    if stop_requested(cancel):
        raise Stopped(STOPPED_REASON)
    out["queries"] = asked["n"]
    if out["errors"]:
        out["status"] = "error" if len(out["errors"]) >= 4 else "partial"
    return out


VOLUME_UNAVAILABLE = [
    "Traffic by SSL inspection status per rule or destination: Z-Insights has no SSL inspection or decryption dimension, so the protocol split above is tenant-wide.",
    "Traffic by URL category: no Z-Insights query groups web traffic by URL category, so a category exemption gets no volume.",
    "Traffic per policy rule: no Z-Insights query returns a rule name for traffic.",
    "A daily trend of uninspected traffic: the daily trend is of all web traffic.",
]


# ── Coverage summary ────────────────────────────────────────────────────
def summarise(causes: List[Dict[str, Any]], classes: List[Mapping[str, Any]], volume: Optional[Mapping[str, Any]]) -> Dict[str, Any]:
    by_risk = {k: sum(1 for c in causes if c["risk"] == k) for k in RISK_ORDER}
    by_kind: Dict[str, int] = {}
    for c in causes:
        by_kind[c["kind"]] = by_kind.get(c["kind"], 0) + 1
    known = [c for c in classes if c.get("decision") != "unknown"]
    covered = [c for c in known if c.get("decision") in ("inspected", "blocked")]
    blind = [c for c in known if c.get("decision") in ("not_inspected", "no_rule")]
    out = {"causes": len(causes), "by_risk": by_risk, "by_kind": by_kind,
           "classes_total": len(known), "classes_covered": len(covered), "classes_not_inspected": len(blind),
           "class_coverage_pct": _pct(len(covered), len(known)),
           "not_inspected_classes": [c.get("label") for c in blind],
           "never_reach_zscaler": sum(1 for c in causes if c["never_reaches_zscaler"] and c["risk"] != "expected")}
    p = ((volume or {}).get("protocols") or {})
    for unit in ("TRANSACTIONS", "BYTES"):
        sp = p.get(unit)
        if sp:
            out[f"inspected_pct_{unit.lower()}"] = sp.get("total_pct")
            out[f"ssl_inspected_pct_{unit.lower()}"] = sp.get("ssl_pct")
    return out


def headline(summary: Mapping[str, Any], volume: Optional[Mapping[str, Any]]) -> str:
    """The one plain sentence the page opens with."""
    parts = []
    pct = summary.get("inspected_pct_bytes")
    if pct is None:
        pct = summary.get("inspected_pct_transactions")
    if pct is not None:
        parts.append(f"About {pct:g}% of the web traffic that reaches Zscaler is inspected")
    if summary.get("classes_total"):
        parts.append(f"{summary['classes_not_inspected']} of {summary['classes_total']} kinds of web traffic are left encrypted by the SSL rules")
    hi = summary["by_risk"].get("high", 0)
    tail = (f"; {hi} high-risk cause{'s' if hi != 1 else ''} below. Start with step 1 of the recovery plan."
            if hi else ". No high-risk cause was found; check the medium ones in the recovery plan.")
    return ("; ".join(parts) or "The causes of uninspected traffic are listed below") + tail


# ── Run ─────────────────────────────────────────────────────────────────
def analyse(ssl_rules: List[Mapping[str, Any]], *, lookup: Optional[Mapping[str, Any]] = None,
            catalogue: Optional[Mapping[str, List[str]]] = None, cc: Optional[Mapping[str, Any]] = None,
            volume: Optional[Mapping[str, Any]] = None, read_errors: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """Pure: tenant data in, report body out."""
    causes = ssl_rule_causes(ssl_rules, lookup, catalogue) + zcc_causes(cc)
    if volume and volume.get("apps") is not None:
        attach_app_volume(causes, volume.get("apps") or [])
    causes.sort(key=_impact)
    flow = ssl_flow.analyse(list(ssl_rules), [], dict(catalogue or {}), dict(lookup or {}), dlp_in_scope=False,
                            read_errors=dict(read_errors or {}))
    classes = [{"key": c["key"], "label": c["label"], "decision": c["decision"], "relevance": c["relevance"],
                "risk": CLASS_RISK.get(c["key"], "medium"),
                "decided_by": (c.get("decided_by") or {}).get("name"), "exceptions": [e.get("name") for e in c.get("exceptions") or []]}
               for c in flow["classes"]]
    summary = summarise(causes, classes, volume)
    return {"summary": summary, "headline": headline(summary, volume), "causes": causes, "plan": recovery_plan(causes),
            "classes": classes}


def run(client: Any, scope: Mapping[str, Any], *, zins: Any = None, volume_plan: Optional[Mapping[str, Any]] = None,
        log: Optional[Callable[[str], None]] = None, cancel: Any = None, scrub: Optional[Callable[[str], str]] = None) -> Dict[str, Any]:
    """Read only what `scope` (data_flow.path_scope) puts in scope, then
    analyse. Stop returns {stopped} with no partial result."""
    import data_flow
    from bypass_report import _fetch_url_category_lookup
    logs: List[str] = []

    def _log(m: str) -> None:
        logs.append(m)
        if log:
            log(m)

    read = set(scope.get("read") or [])
    nis = dict(scope.get("not_in_scope") or {})
    if "ssl" not in read:
        raise ValueError(OUT_OF_SCOPE)
    vp = dict(volume_plan or {})
    if scope.get("source"):
        _log(f"In scope, from {scope['source']}: SSL inspection rules" + (", Client Connector profiles and PAC files" if "zcc" in read else "")
             + (", ZIA Insights traffic numbers" if vp.get("ask") else "") + ".")
    diagnostics: List[Dict[str, Any]] = []
    try:
        with data_flow.stop_on(client, cancel):
            data_flow._stop_point(cancel)
            _log("Reading the SSL inspection rules…")
            ssl_rules = ssl_flow._fetch_rules(client, "/zia/sslInspectionRules", diagnostics, "SSL inspection rules")
            _log(f"  {len(ssl_rules)} SSL inspection rule{'s' if len(ssl_rules) != 1 else ''}.")
            data_flow._stop_point(cancel)
            _log("Reading the URL categories (names only)…")
            try:
                lookup = _fetch_url_category_lookup(client)
            except Exception as e:  # noqa: BLE001
                lookup = {}
                diagnostics.append({"section": "URL categories", "endpoint": "/zia/urlCategories", "error_type": type(e).__name__, "error": str(e)[:200]})
            catalogue: Dict[str, List[str]] = {}
            if "cac" in read:
                _log("Reading the cloud application catalogue…")
                classes = {cls for k in TRAFFIC_CLASSES for cls in k["app_classes"]}
                catalogue = ssl_flow._fetch_app_catalogue(client, classes, diagnostics, cancel=lambda: data_flow.stop_requested(cancel))
            cc = None
            if "zcc" in read or "pac" in read:
                _log("Reading the Client Connector app and forwarding profiles and the PAC files…")
                cc = data_flow.read_client_connector(client, scope=scope, cancel=cancel)
                for err in cc.get("errors") or []:
                    diagnostics.append({"section": "Client Connector", "endpoint": "", "error_type": "read", "error": str(err)[:200]})
            data_flow._stop_point(cancel)
    except data_flow.ReadStopped:
        _log("STOPPED — you clicked Stop; the read was abandoned and nothing more was read.")
        return {"stopped": STOPPED_REASON, "status": "stopped", "logs": logs}
    volume: Dict[str, Any]
    if vp.get("ask") and zins is not None:
        try:
            volume = read_volume(zins, vp.get("window") or "7d", log=_log, cancel=cancel, scrub=scrub)
            volume["available"] = True
        except Stopped:
            _log("STOPPED — you clicked Stop; the Insights read was abandoned and nothing more was asked.")
            return {"stopped": STOPPED_REASON, "status": "stopped", "logs": logs}
    else:
        volume = {"available": False, "reason": vp.get("reason") or "Traffic numbers were not asked for.", "bypass_note": BYPASS_NOTE}
    volume["unavailable"] = VOLUME_UNAVAILABLE
    errors = data_flow.unread_sections(diagnostics)
    rep = analyse(ssl_rules, lookup=lookup, catalogue=catalogue, cc=cc, volume=volume if volume.get("available") else None, read_errors=errors)
    if volume.get("available"):
        volume.pop("apps", None)   # only the matches on each cause are kept
    rep.update(volume=volume, diagnostics=diagnostics, read_errors=errors,
               not_in_scope={k: v for k, v in nis.items() if k in ("zcc", "pac", "cac")},
               sources={"ssl_rules": "/zia/sslInspectionRules", "url_categories": "/zia/urlCategories",
                        "client_connector": "/zcc/webPolicies, /zcc/forwardingProfiles, /zia/pacFiles" if cc is not None else "",
                        "insights": "Z-Insights WEB_TRAFFIC.protocols, WEB_TRAFFIC.no_grouping (DAY trend), SHADOW_IT.apps" if volume.get("available") else ""},
               evidence_mode="configuration" + (" and Insights traffic numbers" if volume.get("available") else ""), status="done", logs=logs)
    if "ssl" in errors:
        rep["headline"] = f"The SSL inspection rules could not be read ({errors['ssl']}), so coverage is unknown; run it again once the API answers."
    return rep


# ── History (one small local file, beside the app's cache) ──────────────
def history_path() -> str:
    env = os.environ.get("DLP_CHECK_SSL_COVERAGE_STATE")
    if env:
        return env
    from zscaler_update_check import _cache_path
    return os.path.join(os.path.dirname(_cache_path()), "ssl_coverage_history.json")


def _load_all(path: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
    try:
        with open(path or history_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    t = data.get("tenants") if isinstance(data, dict) else None
    return {str(k): [e for e in v if isinstance(e, dict)] for k, v in t.items() if isinstance(v, list)} if isinstance(t, dict) else {}


def history_entry(rep: Mapping[str, Any]) -> Dict[str, Any]:
    s = rep.get("summary") or {}
    return {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "class_coverage_pct": s.get("class_coverage_pct"), "classes_covered": s.get("classes_covered"),
            "classes_total": s.get("classes_total"), "causes": s.get("causes"),
            "by_risk": dict(s.get("by_risk") or {}), "by_kind": dict(s.get("by_kind") or {}),
            "inspected_pct_bytes": s.get("inspected_pct_bytes"), "inspected_pct_transactions": s.get("inspected_pct_transactions"),
            "plan_steps": len(((rep.get("plan") or {}).get("steps")) or [])}


def load_history(tenant: str, path: Optional[str] = None) -> List[Dict[str, Any]]:
    """This tenant's kept runs, oldest first; a missing file is no history."""
    import tenant_auth
    return list(_load_all(path).get(tenant_auth.scrub_classic_login(str(tenant or "tenant"))[:120], []))


def _owner_only(path: str) -> int:
    """A file descriptor for writing `path`, owner-only (0600) from the
    first byte whatever the umask: the file holds tenant data."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.fchmod(fd, 0o600)
    except (AttributeError, OSError):   # Windows: no fchmod; the folder's own access rules apply
        pass
    return fd


def record(tenant: str, rep: Mapping[str, Any], path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Append this run's summary for `tenant` (a record label, never a
    login) and return that tenant's history, oldest first."""
    import tenant_auth
    key = tenant_auth.scrub_classic_login(str(tenant or "tenant"))[:120]
    p = path or history_path()
    with _HISTORY_LOCK:
        data = _load_all(p)
        hist = (data.pop(key, []) + [history_entry(rep)])[-HISTORY_KEEP:]
        data[key] = hist
        while len(data) > HISTORY_TENANTS:
            data.pop(next(iter(data)))
        safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)))
        # A unique owner-only (0600) temporary file: the history names tenants.
        fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(p) + ".", suffix=".tmp", dir=os.path.dirname(os.path.abspath(p)))
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump({"version": 1, "tenants": data}, f, indent=1)
            for attempt in range(20):
                try:
                    os.replace(tmp, p)
                    break
                except PermissionError:
                    if attempt == 19:
                        raise
                    time.sleep(0.05)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return hist


# ── Excel export ────────────────────────────────────────────────────────
def _gb(n: Any) -> Any:
    try:
        return round(float(n) / 1e9, 3)
    except (TypeError, ValueError):
        return ""


def to_xlsx(rep: Mapping[str, Any]) -> bytes:
    """Summary, traffic and inspection, causes, recovery plan, traffic
    classes and history as one workbook (xlsx_writer: no formulas)."""
    import xlsx_writer
    s = rep.get("summary") or {}
    wb = xlsx_writer.Workbook(title=f"SSL coverage {rep.get('tenant_label') or ''}".strip(), subject="Uninspected traffic, causes and recovery plan")
    sm = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    sm.extend([["Tenant", rep.get("tenant_label") or ""], ["Generated", rep.get("generated_at") or ""], ["In short", rep.get("headline") or ""],
               ["Traffic classes decrypted or blocked", f"{s.get('classes_covered', 0)} of {s.get('classes_total', 0)}"],
               ["Causes", s.get("causes", 0)]] + [[f"Causes: {RISK_LABEL[k]}", (s.get("by_risk") or {}).get(k, 0)] for k in RISK_ORDER]
              + [["Evidence", rep.get("evidence_mode") or "configuration"], ["Made with", "Zscaler Made Easy (read-only)"]])
    vol = rep.get("volume") or {}
    tr = wb.add_sheet("Traffic and inspection", columns=["Unit", "Bucket", "Total", "Share inspected (%)", "Note"])
    if vol.get("available"):
        for unit in ("TRANSACTIONS", "BYTES"):
            sp = (vol.get("protocols") or {}).get(unit)
            if not sp:
                tr.append([unit.lower(), "", "", "", "Could not be read"])
                continue
            b = sp["buckets"]
            tr.append([unit.lower(), "SSL/TLS", sp["ssl_total"], sp.get("ssl_pct") if sp.get("ssl_pct") is not None else "", "inspected = decrypted"])
            tr.append([unit.lower(), "HTTP", sp["http_total"], sp.get("http_pct") if sp.get("http_pct") is not None else "", "cleartext"])
            tr.append([unit.lower(), "Other / not classified", sp["other_total"], "", "not in any percentage"])
            tr.append([unit.lower(), "Total (SSL/TLS + HTTP)", sp["ssl_total"] + sp["http_total"], sp.get("total_pct") if sp.get("total_pct") is not None else "", ""])
            for k in BUCKET_LABEL:
                tr.append([unit.lower(), f"  {BUCKET_LABEL[k]}", b.get(k, 0), "", ""])
            for u in sp.get("unrecognised") or []:
                tr.append([unit.lower(), f"Unrecognised protocol name: {u['name']}", u["total"], "", "shown as other / not classified"])
        tr.append(["", "", "", "", PROTOCOL_NOTE])
        tr.append(["", "", "", "", BYPASS_NOTE])
    else:
        tr.append(["", "", "", "", "Not read: " + str(vol.get("reason") or "traffic numbers were not asked for")])
    wb.add_sheet("Causes", columns=["Risk", "Kind", "What is not inspected", "Caused by", "Order", "Scope", "Why this risk", "Recovery", "Where",
                                    "Safe to change?", "Note", "Bytes (upper bound, GB)", "Never reaches Zscaler"],
                 rows=[[c["risk_label"], c["kind_label"], c["what"], (c.get("source") or {}).get("name") or "", (c.get("source") or {}).get("order") or "",
                        c["scope"], c["risk_reason"], c["recovery"], c["console"], c["safe_label"], c["safe_note"],
                        _gb((c.get("volume") or {}).get("bytes")) if (c.get("volume") or {}).get("bytes") is not None else "",
                        "yes" if c["never_reaches_zscaler"] else "no"] for c in rep.get("causes") or []])
    plan = rep.get("plan") or {}
    ps = wb.add_sheet("Recovery plan", columns=["Step", "Risk", "Change", "Where", "Expected effect", "Safe to change?", "Note"])
    for p in plan.get("prerequisites") or []:
        ps.append(["Before you start", "", p, "", "", "", ""])
    ps.extend([[st["n"], st["risk_label"], f"{st['title']}: {st['change']}", st["where"], st["effect"], st["safe_label"], st["safe_note"]]
               for st in plan.get("steps") or []])
    wb.add_sheet("Traffic classes", columns=["Traffic", "SSL decision", "Decided by", "Risk if left encrypted"],
                 rows=[[c["label"], str(c["decision"]).replace("_", " "), c.get("decided_by") or "", RISK_LABEL.get(c["risk"], c["risk"])]
                       for c in rep.get("classes") or []])
    hist = rep.get("history") or []
    if hist:
        wb.add_sheet("Run history", columns=["Run", "Classes covered (%)", "Inspected (% bytes)", "Inspected (% transactions)", "High", "Medium", "Low", "Expected"],
                     rows=[[h.get("at"), h.get("class_coverage_pct") if h.get("class_coverage_pct") is not None else "",
                            h.get("inspected_pct_bytes") if h.get("inspected_pct_bytes") is not None else "",
                            h.get("inspected_pct_transactions") if h.get("inspected_pct_transactions") is not None else ""]
                           + [(h.get("by_risk") or {}).get(k, 0) for k in RISK_ORDER] for h in hist])
    return wb.to_bytes()
