"""Zscaler AI Guard: what it needs, read-only.

AI Guard inspects the prompts people type into GenAI apps and the answers
they get back. ZIA sends the apps' traffic to it by proxy chaining: a root
certificate for the chain, a proxy pointing at AI Guard's forwarder, a
proxy gateway that uses that proxy, and a forwarding rule for the apps.
AI Guard then applies a detection policy chosen by a policy match rule.

This module is the read-only half, shared by the Bulk changes builders in
ops_aiguard.py (the writes) and any readiness check:

  readiness(client)      is AI Guard licensed and reachable, does ZIA
                         already have an AI Guard proxy and gateway, what
                         is still a portal step; one dict, never a write
  AI_APPS / PROFILES     the GenAI apps that can be routed and the
                         compliance profiles a detection policy is built from
  read_*()               small readers, each returning (rows, error)

What is verified against zscaler-sdk-python 1.11.3 and what is assumed is
listed in VERIFIED and ASSUMED below, and the page shows the assumptions.
"""
from __future__ import annotations

import json
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import pack_channels as pc

LogFn = Optional[Callable[[str], None]]

SCOPE_KEY = "aiguard"
SCOPE_LABEL = "AI Guard"
BUILDER_PAGE = "/report/operations"

VERIFIED = (
    "AI Guard over OneAPI: client.aiguard.policies (list_policies, get_policy, add_policy, update_policy, delete_policy at "
    "/aiguard/v1/detections/policies), client.aiguard.policy_match_rules (list_rules, get_rule, add_rule, update_rule, delete_rule at "
    "/aiguard/v1/detections/policy-match-rules) and client.aiguard.llm_providers.list_providers.",
    "Policy detection (/v1/detection/execute-policy) is legacy only: it needs an AI Guard API key, not the OneAPI client, so this app "
    "does not call it.",
    "ZIA: proxies (list_proxies, list_proxy_gateways, add_proxy, delete_proxy), forwarding_control (list_rules, get_rule, add_rule, "
    "update_rule, delete_rule), cloud_firewall (IP destination groups, network services), cloud_firewall_rules, ssl_inspection_rules, "
    "cloudappcontrol, url_filtering (rules and get/update_url_and_app_settings), url_categories (lookup, add, delete), "
    "organization_information.get_subscriptions.",
    "Detection policy fields: name, description, inputDetectorPolicies and outputDetectorPolicies, each detector with detector, "
    "enabled, severity and configuration (action, threshold, entities with action and entityType, defaultAction, anonymization).",
    "Proxy gateway fields read: name, primaryProxy, secondaryProxy, failClosed. The SDK has no method to create a proxy gateway.",
)
ASSUMED = (
    "Root certificates: the SDK has no service for them. The app reads GET /rootCertificates?certTypes=PROXY_CHAINING and uploads with "
    "POST /rootCertificates through the SDK's request executor; the path and body are not verified.",
    "AI Guard's forwarder is forward.prod.zsaiguard.net on port 9443 (Zscaler's AI Guard integration guide); older tenants use "
    "forward.zseclipse.net.",
    "The GenAI apps' domains, their ZIA cloud application names and their AI Guard LLM provider names come from Zscaler's AI Guard "
    "guide, not from the SDK.",
    "Detector names (prompt_injection, pii, pii_deepscan, toxicity, malicious_url, invisible_text, personal_data), PII entity types and "
    "the DISABLE entity action are not listed in the SDK; the SDK examples show toxicity, prompt_injection and pii with BLOCK and DETECT.",
    "A policy match rule of type APPLICATION with llmProviders is not in the SDK's MatchCriteria model (which lists llmApplications, "
    "sourceIpAddresses, applicationGroups, customRequestHeaders); the SDK sends the body as given.",
    "The Gen AI Security subscription is recognised by a subscription id or SKU containing GEN_AI (ZS_DP_GEN_AI on the tenants seen).",
    "The prompt-capture switches enableChatGptPrompt, enableMicrosoftCoPilotPrompt, enableGeminiPrompt and enablePerPlexityPrompt are "
    "in the SDK model; enableClaudePrompt, enableGrokPrompt and enableMistralAIPrompt are used only when the tenant's settings carry them.",
    "Blocking QUIC uses the predefined QUIC network service and the Block/ICMP firewall action, so browsers fall back to TCP 443.",
)

AI_GUARD_HOST = "forward.prod.zsaiguard.net"
AI_GUARD_PORT = 9443
AIG_HOST = re.compile(r"^forward(\.[a-z0-9-]+)*\.(zsaiguard|zseclipse)\.net$", re.I)
CERT_TYPE = "PROXY_CHAINING"
GENAI_SKU = re.compile(r"GEN_?AI", re.I)

# The GenAI apps that can be sent to AI Guard: wildcard domains for the
# destination group, the ZIA prompt-capture switch, the ZIA cloud
# applications (Cloud App Control) and AI Guard's LLM provider names.
AI_APPS: List[Dict[str, Any]] = [
    {"id": "chatgpt", "name": "ChatGPT (OpenAI)", "default": True, "domains": [".chatgpt.com", ".chat.openai.com"],
     "prompt": "enableChatGptPrompt", "cloud_apps": ["CHATGPT_AI", "OPENAI"], "providers": ["Default OpenAI Provider"]},
    {"id": "m365copilot", "name": "Microsoft 365 Copilot", "default": True,
     "domains": [".substrate.office.com", ".substrate.svc.cloud.microsoft", ".copilot.microsoft.com", ".augloop.office.com", "www.copilot.com"],
     "prompt": "enableMicrosoftCoPilotPrompt", "cloud_apps": ["MICROSOFT_COPILOT"],
     "providers": ["Default Microsoft 365 Copilot Provider", "Default Microsoft Copilot Provider"]},
    {"id": "claude", "name": "Claude (Anthropic)", "default": True, "domains": [".claude.ai", ".api.anthropic.com"],
     "prompt": "enableClaudePrompt", "cloud_apps": ["CLAUDE_AI", "ANTHROPIC_AI"], "providers": ["Default Anthropic Provider"]},
    {"id": "gemini", "name": "Gemini (Google)", "default": True, "domains": [".gemini.google.com"], "prompt": "enableGeminiPrompt",
     "cloud_apps": ["GOOGLE_GEMINI"],
     "providers": ["Default Google Gemini Provider", "Default Google Gemini Workspace Provider", "Default Google Gemini Enterprise Provider"]},
    {"id": "githubcopilot", "name": "GitHub Copilot", "default": False,
     "domains": [".api.business.githubcopilot.com", ".api.enterprise.githubcopilot.com", ".api.individual.githubcopilot.com"],
     "prompt": "", "cloud_apps": ["GITHUB_COPILOT"], "providers": []},
    {"id": "perplexity", "name": "Perplexity", "default": False, "domains": [".perplexity.ai"], "prompt": "enablePerPlexityPrompt",
     "cloud_apps": ["PERPLEXITY", "PERPLEXITY_AI_APP"], "providers": ["Default PerplexityAI Provider"]},
    {"id": "grok", "name": "Grok (xAI)", "default": False, "domains": [".grok.com"], "prompt": "enableGrokPrompt",
     "cloud_apps": ["GROK_AI"], "providers": ["Default xAI Provider"]},
    {"id": "mistral", "name": "Mistral", "default": False, "domains": [".mistral.ai"], "prompt": "enableMistralAIPrompt",
     "cloud_apps": ["MISTRAL"], "providers": []},
]
APPS_BY_ID = {a["id"]: a for a in AI_APPS}

PII_ENTITIES = ("CREDIT_CARD", "CRYPTO", "EMAIL_ADDRESS", "IP_ADDRESS", "LOCATION", "IBAN_CODE", "US_BANK_NUMBER", "US_DRIVER_LICENSE",
                "US_ITIN", "US_PASSPORT", "US_SSN", "DATE_TIME", "URL", "MEDICAL_LICENSE", "SWIFT_CODE", "STREET_ADDRESS",
                "DATE_OF_BIRTH", "US_DEA_NUMBER", "PERSON", "PHONE_NUMBER")

# Compliance profiles: `block` identifiers are blocked in Block mode and
# detected in Monitor mode; `detect` ones are always detected only; `deep`
# adds the context-aware PII detectors.
PROFILES: Dict[str, Dict[str, Any]] = {
    "HIPAA": {"name": "HIPAA (health information)", "why": "The identifiers that turn health information into PHI.",
              "block": ["US_SSN", "DATE_OF_BIRTH", "MEDICAL_LICENSE", "US_DEA_NUMBER", "STREET_ADDRESS", "US_DRIVER_LICENSE", "CREDIT_CARD",
                        "US_BANK_NUMBER"], "detect": ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "IP_ADDRESS", "URL"], "deep": True},
    "HITRUST": {"name": "HITRUST (health and personal data)", "why": "HITRUST CSF privacy controls: PHI identifiers plus financial and government IDs.",
                "block": ["US_SSN", "DATE_OF_BIRTH", "MEDICAL_LICENSE", "US_DEA_NUMBER", "STREET_ADDRESS", "US_DRIVER_LICENSE", "US_PASSPORT",
                          "CREDIT_CARD", "US_BANK_NUMBER"], "detect": ["PERSON", "PHONE_NUMBER", "EMAIL_ADDRESS", "IP_ADDRESS"], "deep": True},
    "PCI": {"name": "PCI DSS (cardholder data)", "why": "Card numbers and bank details.",
            "block": ["CREDIT_CARD", "US_BANK_NUMBER", "IBAN_CODE", "SWIFT_CODE"], "detect": ["PERSON"], "deep": False},
    "GDPR": {"name": "GDPR (personal data)", "why": "Personal data of people who can be identified.",
             "block": ["IBAN_CODE", "CREDIT_CARD", "US_PASSPORT", "DATE_OF_BIRTH"],
             "detect": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "STREET_ADDRESS", "LOCATION", "IP_ADDRESS"], "deep": True},
    "CJIS": {"name": "CJIS (criminal justice information)", "why": "Identifiers that link a person to criminal justice information.",
             "block": ["US_SSN", "US_DRIVER_LICENSE", "US_PASSPORT", "DATE_OF_BIRTH"], "detect": ["PERSON", "STREET_ADDRESS", "LOCATION"], "deep": True},
    "FERPA": {"name": "FERPA (student records)", "why": "Student identifiers in education records.",
              "block": ["US_SSN", "DATE_OF_BIRTH"], "detect": ["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "STREET_ADDRESS"], "deep": True},
    "SOX": {"name": "SOX (financial data)", "why": "Financial account and taxpayer identifiers.",
            "block": ["CREDIT_CARD", "US_BANK_NUMBER", "IBAN_CODE", "SWIFT_CODE", "US_ITIN", "US_SSN"], "detect": ["PERSON"], "deep": False},
    "GENERAL": {"name": "General (high-risk personal data)", "why": "Card, bank and government IDs every organisation protects.",
                "block": ["US_SSN", "CREDIT_CARD", "US_BANK_NUMBER", "US_PASSPORT", "US_DRIVER_LICENSE", "US_ITIN"], "detect": ["PERSON"], "deep": False},
}
MODES = ("monitor", "block")

GATEWAY_STEPS = (
    "In the ZIA Admin Portal open Infrastructure > Internet & SaaS > Network Policies > Proxies and Gateways > Proxy Gateways.",
    "Add a gateway: give it the name the plan shows, set Primary Proxy to the AI Guard proxy, Secondary Proxy to None, and turn Fail Close on.",
    "Save and activate, then preview the AI Guard routing again: the forwarding rule is planned once the gateway exists.",
)
PORTAL_STEPS = (
    "In the AI Guard portal, Tenant Settings > Security: turn on Store Prompts/Responses.",
    "In the AI Guard portal, Tenant Settings > Integrations: turn on ZIA User and Group Sync and ZIA Domain Sync.",
    "In the AI Guard portal, Tenant Settings > Integrations: download the Proxy Chain certificate (the root CA ZIA needs).",
    "Microsoft 365 Copilot also needs WebSocket inspection: ask Zscaler Support to enable it for the tenant.",
)


class Stopped(RuntimeError):
    """The operator clicked Stop: nothing more is read."""


def app_ids(raw: Any) -> List[str]:
    """The known app ids in `raw`, in catalogue order (the default apps when none is given)."""
    given = {str(x).strip().lower() for x in raw} if isinstance(raw, (list, tuple)) else set()
    ids = [a["id"] for a in AI_APPS if a["id"] in given]
    return ids or [a["id"] for a in AI_APPS if a["default"]]


def domains_for(ids: List[str]) -> List[str]:
    out: List[str] = []
    for i in ids:
        for d in APPS_BY_ID[i]["domains"]:
            if d not in out:
                out.append(d)
    return out


def catalog() -> Dict[str, Any]:
    """The apps and profiles for a form: no tenant read."""
    return {"apps": [{"id": a["id"], "name": a["name"], "default": a["default"], "domains": a["domains"]} for a in AI_APPS],
            "profiles": [{"id": k, "name": v["name"], "why": v["why"]} for k, v in PROFILES.items()], "modes": list(MODES),
            "gateway_steps": list(GATEWAY_STEPS), "portal_steps": list(PORTAL_STEPS), "assumed": list(ASSUMED)}


# ── field helpers (SDK rows are snake_case, raw answers camelCase) ───────
def _snake(k: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", str(k)).lower()


def _camel(k: str) -> str:
    parts = str(k).split("_")
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:])


def get(row: Any, path: str, default: Any = None) -> Any:
    """A field by a dotted path, each step tried in snake_case and camelCase."""
    cur = row
    for step in path.split("."):
        if not isinstance(cur, dict):
            return default
        nxt = None
        for k in (step, _camel(step), _snake(step)):
            if k in cur and cur[k] is not None:
                nxt = cur[k]
                break
        if nxt is None:
            return default
        cur = nxt
    return cur


def ref_ids(v: Any) -> List[str]:
    """The ids (or names) in a reference list such as destIpGroups or nwServices."""
    out = []
    for x in v if isinstance(v, list) else ([v] if v not in (None, "", {}) else []):
        out.append(str(x.get("id") if isinstance(x, dict) and x.get("id") is not None else (x.get("name") if isinstance(x, dict) else x)))
    return sorted(out)


def _plain(obj: Any) -> Dict[str, Any]:
    import pack_export
    return pack_export._plain(obj)


def rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Rows of an SDK list call as snake_case dicts, or the error."""
    import pack_export
    try:
        if isinstance(ret, tuple) and len(ret) == 2:     # lookup-style (data, error)
            data, err = ret
            if err:
                return [], str(err)[:200]
            return [_plain(x) for x in (data or []) if x is not None], None
        return pack_export._rows(ret)
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def one(ret: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object of an SDK get call as a snake_case dict; None when absent."""
    data, err = pc._nx(ret)
    if err:
        return None, ("not found" if is_gone(err) else str(err)[:200])
    if data is None or isinstance(data, (list, tuple)) or data == {}:
        return None, "not found"
    d = _plain(data)
    return (d or None), (None if d else "not found")


def is_gone(err: Any) -> bool:
    """Whether a read error says the object does not exist (HTTP 404)."""
    st = err.get("status") if isinstance(err, dict) else None
    return str(st) == "404" or bool(re.search(r"\b404\b|not found|does not exist", str(err or ""), re.I))


def raw_body(ret: Any) -> Optional[Dict[str, Any]]:
    """The raw JSON body of an SDK call (every field the tenant sent, also
    the ones the SDK model leaves out), or None."""
    resp = ret[1] if isinstance(ret, tuple) and len(ret) >= 3 else None
    getter = getattr(resp, "get_body", None)
    if not callable(getter):
        return None
    try:
        body = getter()
        if isinstance(body, (bytes, str)):
            body = json.loads(body) if body else None
        return body if isinstance(body, (dict, list)) else None
    except Exception:  # noqa: BLE001
        return None


def _call(fn: Callable[[], Any]) -> Any:
    try:
        return fn()
    except Exception as e:  # noqa: BLE001 — one read never stops the rest
        return (None, None, f"{type(e).__name__}: {str(e)[:200]}")


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise Stopped("You clicked Stop: nothing more was read and nothing was written.")


# ── readers ──────────────────────────────────────────────────────────────
def aiguard_service(client: Any) -> Tuple[Any, Optional[str]]:
    """client.aiguard, or why it is not there (the classic ZIA API sign-in has no AI Guard)."""
    try:
        svc = getattr(client, "aiguard", None)
    except Exception:  # noqa: BLE001 — the legacy client refuses the property
        svc = None
    if svc is None:
        return None, ("AI Guard is reached only through a OneAPI (ZIdentity) API client; this sign-in is the classic ZIA API, "
                      "which has no AI Guard.")
    return svc, None


def read_root_certs(zia: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Root certificates for proxy chaining (raw GET, assumed path)."""
    data, err = pc.raw_get(zia, f"/rootCertificates?certTypes={CERT_TYPE}")
    if err:
        return [], err
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict) and isinstance(data.get("list"), list):
        items = data["list"]
    else:
        items = []
    out = []
    for c in items:
        if isinstance(c, dict) and c.get("id") is not None:
            d = _plain(c)
            out.append({"id": d.get("id"), "name": str(d.get("name") or d.get("display_name") or d.get("id")),
                        "expiry": d.get("expiry_time") or d.get("not_after")})
    return out, None


def read_proxies(zia: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return rows(_call(lambda: zia.proxies.list_proxies()))


def read_gateways(zia: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    return rows(_call(lambda: zia.proxies.list_proxy_gateways()))


def is_aiguard_proxy(p: Dict[str, Any]) -> bool:
    return str(get(p, "type") or "").upper() == "PROXYCHAIN" and bool(AIG_HOST.match(str(get(p, "address") or "").strip()))


def gateway_for(gateways: List[Dict[str, Any]], proxy_id: Any) -> Optional[Dict[str, Any]]:
    for g in gateways:
        if proxy_id is not None and str(get(g, "primary_proxy.id")) == str(proxy_id):
            return g
    return None


def read_subscriptions(zia: Any) -> Tuple[Optional[bool], List[str], Optional[str]]:
    """(Gen AI Security licensed?, subscription ids, error)."""
    ret = _call(lambda: zia.organization_information.get_subscriptions())
    data, err = pc._nx(ret)
    if err:
        return None, [], str(err)[:200]
    body = raw_body(ret)
    items = body if isinstance(body, list) else (body.get("list") if isinstance(body, dict) and isinstance(body.get("list"), list) else None)
    if items is None:
        items = data if isinstance(data, list) else []
    ids = []
    for s in items:
        d = s if isinstance(s, dict) else _plain(s)
        if d.get("subscribed") is False or re.search(r"EXPIRED|CANCEL", str(d.get("status") or ""), re.I):
            continue
        ids.append(" ".join(str(d[k]) for k in ("id", "sku") if d.get(k)))   # a numeric id with the SKU beside it is still recognised
    return any(GENAI_SKU.search(i) for i in ids), ids, None


def read_app_settings(zia: Any) -> Tuple[Optional[Dict[str, Any]], bool, Optional[str]]:
    """(the URL and Cloud App Control advanced settings as the tenant sent
    them, whether that is the complete object, error). Only a complete
    object may be written back (a partial PUT could reset other settings)."""
    ret = _call(lambda: zia.url_filtering.get_url_and_app_settings())
    data, err = pc._nx(ret)
    if err:
        return None, False, str(err)[:200]
    body = raw_body(ret)
    if isinstance(body, dict) and body:
        return body, True, None
    fmt = getattr(data, "request_format", None)
    if callable(fmt):
        try:
            return {k: v for k, v in fmt().items() if v is not None}, False, None
        except Exception:  # noqa: BLE001
            pass
    if isinstance(data, dict):
        return data, False, None
    return None, False, "no answer"


def prompt_fields(settings: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    """The prompt-capture switches the tenant's settings carry, on or off."""
    return {k: bool(v) for k, v in (settings or {}).items() if isinstance(k, str) and re.fullmatch(r"enable\w+Prompt", k)}


def read_aiguard(aig: Any) -> Dict[str, Any]:
    """Detection policies, policy match rules and LLM providers, each (rows, error)."""
    out = {}
    for key, fn in (("policies", lambda: aig.policies.list_policies()), ("rules", lambda: aig.policy_match_rules.list_rules()),
                    ("providers", lambda: aig.llm_providers.list_providers())):
        out[key] = rows(_call(fn))
    return out


def classify_aiguard_error(err: str) -> str:
    """The AI Guard read error in plain words."""
    e = str(err or "")
    if re.search(r"\b40[13]\b|unauthori|forbidden|not authori|access denied", e, re.I):
        return ("The API client cannot reach AI Guard: the tenant has no AI Guard subscription linked to it, or the API client's role in "
                "ZIdentity lacks AI Guard access.")
    if re.search(r"\b404\b|not found", e, re.I):
        return "AI Guard is not provisioned for this tenant (not licensed, or not linked to ZIA by Zscaler Support)."
    return f"AI Guard did not answer: {e[:160]}"


# ── readiness ────────────────────────────────────────────────────────────
def readiness(client: Any, *, zia: bool = True, aiguard: bool = True, log: LogFn = None,
              cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Is AI Guard licensed and reachable, and is ZIA ready to send GenAI
    apps to it? Reads only (`zia` / `aiguard` say which side may be read:
    the caller passes what the Scope page puts in scope). Returns
    {checks: [{id, name, status (pass, warn, fail, info, not_read), detail,
    fix}], aiguard: {...}, zia: {...}, gateway_steps, portal_steps,
    verified, assumed}. Never writes and never raises on a tenant answer."""
    say = log or (lambda m: None)
    checks: List[Dict[str, Any]] = []

    def check(cid: str, name: str, status: str, detail: str, fix: str = "") -> None:
        checks.append({"id": cid, "name": name, "status": status, "detail": detail, "fix": fix})

    ag: Dict[str, Any] = {"read": False, "reachable": None, "policies": [], "rules": [], "providers": [], "error": None}
    if aiguard:
        _check_stop(cancel)
        svc, why = aiguard_service(client)
        if svc is None:
            ag["error"] = why
            check("aiguard.api", "AI Guard API", "fail", why, "Sign in with a OneAPI (ZIdentity) API client whose role includes AI Guard.")
        else:
            say("Reading AI Guard: detection policies, policy match rules and LLM providers…")
            got = read_aiguard(svc)
            ag["read"] = True
            perr = got["policies"][1]
            if perr:
                ag["reachable"] = False
                ag["error"] = classify_aiguard_error(perr)
                check("aiguard.api", "AI Guard API", "fail", ag["error"],
                      "Ask Zscaler Support to link the AI Guard subscription to this ZIA tenant, then give the ZIdentity API client a role with AI Guard access.")
            else:
                ag["reachable"] = True
                ag["policies"] = [{"id": get(p, "id"), "name": get(p, "name")} for p in got["policies"][0]]
                ag["rules"] = [{"id": get(r, "id"), "name": get(r, "name"), "policy_id": get(r, "policy_id"), "enabled": get(r, "enabled"),
                                "order": get(r, "rule_order")} for r in got["rules"][0]]
                ag["providers"] = sorted(str(get(p, "name")) for p in got["providers"][0] if get(p, "name"))
                n = len(ag["policies"])
                check("aiguard.api", "AI Guard API", "pass",
                      f"Reachable and licensed: {n} detection polic{'y' if n == 1 else 'ies'} and {len(ag['rules'])} policy match rule(s).")
                if not ag["policies"]:
                    check("aiguard.policy", "AI Guard detection policy", "warn", "AI Guard has no detection policy yet, so nothing is inspected.",
                          "Build one from a compliance profile: Bulk changes > Build new > AI Guard detection policy.")
    else:
        check("aiguard.api", "AI Guard API", "not_read", f"Not in scope: {SCOPE_LABEL} is not ticked on the Scope page, so AI Guard was not read.")

    zs: Dict[str, Any] = {"read": False, "genai_licensed": None, "certificates": [], "proxies": [], "gateways": [], "forwarding_rules": [],
                          "prompt_fields": {}, "o365_one_click": None, "errors": {}}
    z = getattr(client, "zia", None) if zia else None
    if zia and z is not None:
        zs["read"] = True
        _check_stop(cancel)
        say("Reading ZIA: subscriptions, root certificates, proxies, proxy gateways, forwarding rules and the GenAI settings…")
        lic, _subs, serr = read_subscriptions(z)
        zs["genai_licensed"] = lic
        if serr:
            zs["errors"]["subscriptions"] = serr
        _check_stop(cancel)
        certs, cerr = read_root_certs(z)
        zs["certificates"] = certs
        if cerr:
            zs["errors"]["certificates"] = cerr
        _check_stop(cancel)
        proxies, perr = read_proxies(z)
        gws, gerr = read_gateways(z)
        for k, e in (("proxies", perr), ("gateways", gerr)):
            if e:
                zs["errors"][k] = e
        aig = [p for p in proxies if is_aiguard_proxy(p)]
        zs["proxies"] = [{"id": get(p, "id"), "name": get(p, "name"), "address": get(p, "address"), "port": get(p, "port"),
                          "cert_id": get(p, "cert.id"), "gateway": (get(gateway_for(gws, get(p, "id")) or {}, "name"))} for p in aig]
        zs["gateways"] = [{"id": get(g, "id"), "name": get(g, "name"), "primary_proxy": get(g, "primary_proxy.name"),
                           "primary_proxy_id": get(g, "primary_proxy.id"), "fail_closed": get(g, "fail_closed")} for g in gws]
        _check_stop(cancel)
        fwd, ferr = rows(_call(lambda: z.forwarding_control.list_rules()))
        if ferr:
            zs["errors"]["forwarding_rules"] = ferr
        gw_ids = {str(get(g, "id")) for g in gws if any(str(get(g, "primary_proxy.id")) == str(p["id"]) for p in zs["proxies"])}
        zs["forwarding_rules"] = [{"id": get(r, "id"), "name": get(r, "name"), "state": get(r, "state"), "order": get(r, "order")}
                                  for r in fwd if str(get(r, "forward_method") or "").upper() == "PROXYCHAIN"
                                  and str(get(r, "proxy_gateway.id")) in gw_ids]
        _check_stop(cancel)
        settings, _complete, aerr = read_app_settings(z)
        if aerr:
            zs["errors"]["settings"] = aerr
        zs["prompt_fields"] = prompt_fields(settings)
        zs["o365_one_click"] = None if settings is None else bool(get(settings, "enable_msft_o365") or get(settings, "enableMsftO365"))

        if lic is None:
            check("zia.genai_license", "Gen AI Security subscription (prompt capture)", "info", f"The subscriptions could not be read: {serr}")
        else:
            check("zia.genai_license", "Gen AI Security subscription (prompt capture)", "pass" if lic else "info",
                  "Licensed: ZIA can capture GenAI prompts." if lic else "No Gen AI Security subscription: ZIA prompt capture stays off; AI Guard still inspects.")
        if cerr:
            check("zia.root_ca", "AI Guard root certificate in ZIA", "info", f"The root certificates could not be read: {cerr}",
                  "Check in the ZIA portal (Administration > Root Certificates) or upload the AI Guard certificate in the builder.")
        else:
            check("zia.root_ca", "AI Guard root certificate in ZIA", "pass" if certs else "warn",
                  f"{len(certs)} proxy-chaining root certificate(s): {', '.join(c['name'] for c in certs[:3])}." if certs
                  else "No proxy-chaining root certificate: ZIA cannot trust AI Guard's inspection yet.",
                  "" if certs else "Download the Proxy Chain certificate from the AI Guard portal and upload it in the AI Guard routing builder.")
        # A list that could not be read is a warning, never a pass: readiness
        # does not say ready on what it could not see (fail closed).
        if perr:
            check("zia.proxy", "AI Guard proxy in ZIA", "warn", f"The proxies could not be read, so it is not known whether one points at "
                  f"AI Guard: {perr}", "Check that the API client's role can read Proxies and Gateways, then check again.")
        else:
            check("zia.proxy", "AI Guard proxy in ZIA", "pass" if aig else "warn",
                  ("Found: " + ", ".join(f"{p['name']} ({p['address']}:{p['port']})" for p in zs["proxies"])) if aig
                  else f"No proxy points at AI Guard ({AI_GUARD_HOST}:{AI_GUARD_PORT}).",
                  "" if aig else "The AI Guard routing builder creates it (it needs the root certificate).")
        with_gw = [p for p in zs["proxies"] if p["gateway"]]
        if gerr:
            check("zia.gateway", "AI Guard proxy gateway in ZIA", "warn", f"The proxy gateways could not be read: {gerr}",
                  "Check that the API client's role can read Proxies and Gateways, then check again.")
        elif with_gw:
            g = next(x for x in zs["gateways"] if x["name"] == with_gw[0]["gateway"])
            ok = g["fail_closed"] is not False
            check("zia.gateway", "AI Guard proxy gateway in ZIA", "pass" if ok else "warn",
                  f"Gateway {g['name']} uses the AI Guard proxy {g['primary_proxy']}" + ("." if ok else ", but Fail Close is off: if AI Guard is down, prompts go uninspected."),
                  "" if ok else "Turn Fail Close on for the gateway in the ZIA portal.")
        else:
            check("zia.gateway", "AI Guard proxy gateway in ZIA", "fail",
                  "No proxy gateway uses an AI Guard proxy. The API cannot create proxy gateways: this is a ZIA portal step.",
                  " ".join(GATEWAY_STEPS))
        if ferr:
            check("zia.forwarding", "Forwarding rule to AI Guard", "warn", f"The forwarding rules could not be read: {ferr}",
                  "Check that the API client's role can read Forwarding Control, then check again.")
        else:
            check("zia.forwarding", "Forwarding rule to AI Guard", "pass" if zs["forwarding_rules"] else "warn",
                  f"{len(zs['forwarding_rules'])} proxy-chaining rule(s) send traffic to AI Guard." if zs["forwarding_rules"]
                  else "No forwarding rule sends GenAI apps to AI Guard, so AI Guard sees no traffic.",
                  "" if zs["forwarding_rules"] else "Use the AI Guard routing builder once the proxy gateway exists.")
        if zs["o365_one_click"]:
            check("zia.o365", "Microsoft 365 one-click bypass", "info",
                  "On: Microsoft 365 traffic is not decrypted by default, so Microsoft 365 Copilot reaches AI Guard only with an SSL Inspect rule above it.",
                  "The AI Guard routing builder adds that rule at the top of SSL inspection.")
    elif zia:
        check("zia.proxy", "AI Guard proxy in ZIA", "not_read", "This client has no ZIA service.")
    else:
        check("zia.proxy", "AI Guard proxy in ZIA", "not_read", "Not in scope: ZIA platform is not ticked on the Scope page, so ZIA was not read.")
    required = ("aiguard.api", "zia.root_ca", "zia.proxy", "zia.gateway", "zia.forwarding")
    ready = {c["id"] for c in checks} >= set(required) and all(c["status"] in ("pass", "info") for c in checks if c["id"] in required)
    return {"ready": ready, "checks": checks, "aiguard": ag, "zia": zs, "gateway_steps": list(GATEWAY_STEPS), "portal_steps": list(PORTAL_STEPS),
            "builder": BUILDER_PAGE, "verified": list(VERIFIED), "assumed": list(ASSUMED)}
