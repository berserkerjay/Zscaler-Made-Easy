#!/usr/bin/env python3
"""
Zscaler GenAI / Prompt Governance Assessment Checks
=====================================================
Dedicated checks for Generative AI controls, prompt governance,
shadow AI detection, and Copilot oversharing prevention.

Based on Zscaler best practices for securing GenAI:
  - Zscaler Securing Generative AI solutions guide
  - Zscaler GenAI Data Protection Deployment Guide
  - ThreatLabz 2025 Data@Risk Report (3,464% YoY growth in AI traffic)
  - Microsoft Copilot Deployment Wizard guidance
  - Zscaler AI/ML Applications URL category
"""

import re

from zscaler_full_checks import guard_registry
from dlp_assessment_full_auto import (R, _ls, _ssl_action, _ssl_enabled, _SSL_INSPECT, _SSL_DNI, _fv, _names, _enabled, _truthy,
                                      GENAI_CATS, genai_category_ids, targets_genai)

# Known GenAI/LLM/AI vendor indicators (expand as new tools emerge)
GENAI_KEYWORDS = [
    # General AI terms
    "ai", "genai", "gen-ai", "artificial intelligence", "llm", "ml ", "machine learning",
    # Vendor/product names
    "chatgpt", "openai", "gpt-3", "gpt-4", "gpt 4", "gpt",
    "claude", "anthropic",
    "gemini", "bard", "google ai", "google bard",
    "copilot", "microsoft copilot", "m365 copilot", "github copilot",
    "perplexity", "you.com",
    "dall-e", "midjourney", "stable diffusion",
    "huggingface", "hugging face",
    "mistral", "llama", "meta ai",
    "grok", "x.ai", "deepseek",
    "ollama",
    "jasper", "writesonic", "copy.ai",
    "notion ai", "notionai",
]
# Whole words only: a bare "ai" substring matches Email, Webmail, Domain, Maintenance.
_GENAI_RE = re.compile(r"\b(" + "|".join(re.escape(k.strip()) for k in GENAI_KEYWORDS) + r")\b", re.I)

# Sensitive data types that should not leak to GenAI
SENSITIVE_PATTERNS = [
    "pii", "pci", "phi", "hipaa", "ssn", "pan",
    "source", "code", "github", "repo",
    "confidential", "internal", "proprietary",
    "secret", "credential", "api key", "api_key",
    "salary", "hr ", "human resources",
    "customer data", "client data",
    "financial", "earnings", "revenue",
    "merger", "acquisition",
    "prompt inject", "jailbreak", "adversarial",
]


def _has_any(text, keywords):
    """Return True if text contains any of the keywords as whole words
    (case-insensitive): a bare substring finds "repo" in Report, "pan" in
    Company and "code" in Barcode, and would pass a check on a rule's name."""
    if not text:
        return False
    return bool(re.search(r"\b(?:" + "|".join(re.escape(k.strip()) for k in keywords) + r")\b", text, re.I))


def _genai_rules(rules, field="name", ids=None):
    """Rules that target GenAI by what they apply to: a GenAI URL category
    (AI_ML_APPS, GENERAL_AI_ML, or a custom category named for AI), a Cloud
    App Control rule of type AI_ML, or an AI cloud application. The rule
    name and description are a fallback, matched on whole words."""
    ids = ids or GENAI_CATS
    out = []
    for r in rules:
        if not isinstance(r, dict):
            continue
        apps = " ".join(n.replace("_", " ") for n in _names(_fv(r, "cloudApplications")))
        text = str(r.get(field, "")) + " " + str(r.get("description", ""))
        if targets_genai(r, ids) or str(_fv(r, "type") or "").upper() == "AI_ML" or _GENAI_RE.search(apps) or _GENAI_RE.search(text):
            out.append(r)
    return out


def _rules(cl, path):
    d, c = cl.get(path)
    return [r for r in (_ls(d) if c in (200, 204) else []) if isinstance(r, dict)]


# ═══════════════════════════════════════════════════════════════════════
# SHADOW AI DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

def ai_1(cl):
    """GenAI URL categories are being used"""
    ids = genai_category_ids(cl)
    used = {}
    for path, lbl in (("/zia/urlFilteringRules", "URL Filtering"), ("/zia/sslInspectionRules", "SSL Inspection"), ("/zia/webDlpRules", "web DLP")):
        used[lbl] = [r for r in _rules(cl, path) if _enabled(r) and targets_genai(r, ids)]
    if any(used.values()):
        parts = ", ".join(f"{len(v)} {k}" for k, v in used.items())
        return R(R.PASS, f"The AI URL categories are used by enabled rules ({parts}). Zscaler's 'Generative AI and ML Applications' and 'General AI and ML Applications' categories are the foundation for GenAI governance; review which AI apps you allow or block periodically. Ref: https://help.zscaler.com/zia/about-url-categories")
    return R(R.FAIL, "No enabled URL Filtering, SSL Inspection or DLP rule uses the AI URL categories. Every tenant has the predefined 'Generative AI and ML Applications' (formerly 'AI and ML Applications') and 'General AI and ML Applications' categories, covering ChatGPT, Claude, Gemini, Copilot and other AI tools; they protect only once a rule uses them. Use them in URL Filtering, SSL Inspection and DLP rules as the first line of GenAI governance. Ref: https://help.zscaler.com/zia/about-url-categories")


def ai_2(cl):
    """AI/ML traffic has URL filtering rules"""
    rules = _rules(cl, "/zia/urlFilteringRules")
    ai_rules = _genai_rules(rules, ids=genai_category_ids(cl))
    enabled = [r for r in ai_rules if (r.get("state") or "").upper() == "ENABLED"]
    if not enabled:
        return R(R.WARN, "No enabled URL filtering rule targets GenAI (the AI URL categories or AI apps). Best Practice: Create a dedicated URL filtering rule for the Generative AI and ML Applications category. Zscaler recommends starting with Block or Caution, then selectively allowing sanctioned AI tools for specific user groups. Ref: Zscaler Securing Generative AI.")
    return R(R.PASS, f"{len(enabled)} active URL filter rule(s) target GenAI.")


def ai_3(cl):
    """Shadow AI detection via Cloud App Control"""
    rules = _rules(cl, "/zia/cloudApplicationRules")
    # The client lists Cloud App Control rules per type (/webApplicationRules/AI_ML) and tags each with it.
    ai_rules = [r for r in rules if str(_fv(r, "type") or "").upper() == "AI_ML" and str(r.get("state") or "ENABLED").upper() != "DISABLED" and not _truthy(_fv(r, "predefined"))]
    if ai_rules:
        return R(R.PASS, f"{len(ai_rules)} AI & ML Applications Cloud App Control rule(s). This enables granular actions (prompt/upload/download control) on sanctioned vs unsanctioned AI tools.")
    return R(R.WARN, "No Cloud App Control rules for AI apps. Best Practice: Cloud App Control enables granular inspection of GenAI activities (prompt submission, file upload, download, share). Without CAC, you can only block the URL, not the specific activity. Create CAC rules using rule_type='AI_ML' to govern each AI tool individually. Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control")


def ai_4(cl):
    """Zero Trust Browser (formerly Browser Isolation) available for risky AI tools"""
    profiles = _rules(cl, "/zia/browserIsolation/profiles")
    if profiles:
        return R(R.PASS, f"{len(profiles)} isolation profile(s) available (Zero Trust Browser, formerly Browser Isolation). Best Practice: Route unsanctioned AI tools through isolation with upload/download/clipboard disabled — users can still use the tools but can't exfiltrate sensitive data. This is Zscaler's recommended 'coach, don't block' approach.")
    return R(R.WARN, "No isolation profiles (Zero Trust Browser, formerly Browser Isolation). Best Practice: isolation is the middle ground for AI tools — it allows access without enabling data exfiltration. Configure isolation profiles with clipboard/download/upload restrictions for AI categories. Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control")


# ═══════════════════════════════════════════════════════════════════════
# SSL INSPECTION FOR AI TRAFFIC
# ═══════════════════════════════════════════════════════════════════════

def ai_5(cl):
    """SSL inspection enabled for AI traffic"""
    d, c = cl.get("/zia/sslInspectionRules")
    rules = _ls(d) if c in (200, 204) else []
    inspect_rules = [r for r in rules if _ssl_enabled(r) and _ssl_action(r) in _SSL_INSPECT]
    if not inspect_rules:
        return R(R.FAIL, "No SSL inspection rules. Best Practice: SSL inspection is MANDATORY for GenAI governance. Without it, Zscaler sees only the domain (chat.openai.com) but cannot inspect prompts, uploads, or DLP content. All AI traffic is HTTPS — you need SSL inspection to see inside.")
    return R(R.PASS, f"{len(inspect_rules)} SSL inspect rule(s) enabled. GenAI prompts and uploads can be inspected for DLP violations.")


_AI_EXEMPT_WORDS = ["chatgpt", "openai", "claude", "anthropic", "gemini", "copilot", "huggingface", "perplexity", "deepseek", "mistral", "grok"]


def ai_6(cl):
    """AI domains are NOT in SSL Do-Not-Inspect lists"""
    d, c = cl.get("/zia/sslInspectionRules")
    rules = _ls(d) if c in (200, 204) else []
    dni = [r for r in rules if _ssl_enabled(r) and _ssl_action(r) in _SSL_DNI]
    risky = []
    for r in dni:
        # A category exemption is stored as its id (AI_ML_APPS), which no keyword matches.
        if any(n in GENAI_CATS for n in _names(_fv(r, "urlCategories"))):
            risky.append(r.get("name", "?"))
            continue
        text = str(r).lower()
        if any(k in text for k in _AI_EXEMPT_WORDS):
            risky.append(r.get("name", "?"))
    if risky:
        return R(R.FAIL, f"{len(risky)} SSL DNI rule(s) exempt AI domains or the AI categories: {', '.join(risky[:3])}. Best Practice: NEVER exempt GenAI from SSL inspection — for the granular actions to work, SSL/TLS inspection must be enabled for the application, and uninspected prompts and uploads bypass DLP. Remove these exemptions. Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control")
    return R(R.PASS, "No AI domains exempted from SSL inspection.")


# ═══════════════════════════════════════════════════════════════════════
# PROMPT & UPLOAD GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════

def ai_7(cl):
    """DLP rules target AI destinations"""
    rules = _rules(cl, "/zia/webDlpRules")
    ai_rules = _genai_rules(rules, ids=genai_category_ids(cl))
    enabled = [r for r in ai_rules if (r.get("state") or "").upper() == "ENABLED"]
    if not ai_rules:
        return R(R.FAIL, "No DLP rules target GenAI (the AI URL categories or AI apps). Best Practice: Create dedicated DLP rules with URL category 'Generative AI and ML Applications' as the destination. Scan prompts and file uploads for PII, source code, credentials, and confidential data before they reach LLMs.")
    return R(R.PASS, f"{len(enabled)} active DLP rule(s) target GenAI destinations.")


def ai_8(cl):
    """User coaching on AI tools (Caution / Confirm)

    Coaching for GenAI is the Caution action (a browser EUN) on the AI & ML
    Applications Cloud App Control rule (CAUTION_AI_ML_WEB_USE) and on URL
    Filtering rules for the AI categories; web DLP Confirm is a secondary
    signal (web DLP actions are ANY, NONE, BLOCK, CONFIRM, ALLOW,
    ICAP_RESPONSE — terraform zia_dlp_web_rules)."""
    ids = genai_category_ids(cl)
    cac = [r for r in _rules(cl, "/zia/cloudApplicationRules") if str(_fv(r, "type") or "").upper() == "AI_ML"
           and str(r.get("state") or "ENABLED").upper() != "DISABLED" and any("CAUTION" in str(a).upper() for a in (_fv(r, "actions") or []))]
    url = [r for r in _rules(cl, "/zia/urlFilteringRules") if _enabled(r) and str(_fv(r, "action") or "").upper() == "CAUTION" and targets_genai(r, ids)]
    dlp = [r for r in _genai_rules(_rules(cl, "/zia/webDlpRules"), ids=ids) if _enabled(r)
           and str((r.get("action") or {}).get("type") if isinstance(r.get("action"), dict) else r.get("action") or "").upper() == "CONFIRM"]
    if cac or url:
        return R(R.PASS, f"Users are coached before using AI tools: {len(cac)} AI & ML Applications Cloud App Control rule(s) and {len(url)} URL Filtering rule(s) use Caution" + (f", and {len(dlp)} web DLP rule(s) on AI destinations use Confirm." if dlp else "."))
    if dlp:
        return R(R.PASS, f"{len(dlp)} web DLP rule(s) on AI destinations use Confirm, so users justify sensitive uploads. Consider also the Caution action on the AI & ML Applications Cloud App Control rule or on URL Filtering rules for the AI categories.")
    return R(R.WARN, "No Caution or Confirm coaching on AI tools. Best Practice: Instead of hard-blocking AI tools (which drives users to personal devices), use the Caution action (browser EUN) on the AI & ML Applications Cloud App Control rule or on URL Filtering rules for the AI categories; it explains the AI data risks and asks the user to acknowledge before access. Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control")


def ai_9(cl):
    """Source code exfiltration rules for AI"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    code_rules = []
    for r in rules:
        if (r.get("state") or "").upper() != "ENABLED":
            continue
        text = (r.get("name") or "") + " " + (r.get("description") or "")
        if _has_any(text, ["source code", "source", "code", "github", "repo", "repository", "repositories", "snippet", "codebase"]):
            code_rules.append(r)
    if code_rules:
        names = ", ".join(r.get("name", "?") for r in code_rules[:3])
        return R(R.PASS, f"Source code DLP rule(s): {names}. Best Practice: Prevents developers from pasting proprietary code into ChatGPT/Copilot (a top GenAI data loss vector per ThreatLabz 2025).")
    return R(R.FAIL, "No source-code-specific DLP rules. Best Practice: Developers pasting proprietary code into AI tools is one of the top data loss vectors. Create a DLP rule using Zscaler's 'Source Code' dictionary targeting AI/ML Applications category.")


def ai_10(cl):
    """PII/PHI/PCI protection on AI destinations"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    pii_rules = []
    for r in rules:
        if (r.get("state") or "").upper() != "ENABLED":
            continue
        text = (r.get("name") or "") + " " + (r.get("description") or "")
        if _has_any(text, ["pii", "ssn", "pan", "phi", "pci", "hipaa", "personal"]):
            pii_rules.append(r)
    if pii_rules:
        names = ", ".join(r.get("name", "?") for r in pii_rules[:3])
        return R(R.PASS, f"PII/PHI/PCI rule(s): {names}. Ensure these rules include AI/ML Applications in their URL category scope.")
    return R(R.FAIL, "No PII/PHI/PCI DLP rules. Best Practice: GenAI tools training on your prompts is a severe regulatory risk (GDPR, HIPAA, PCI). Configure DLP with pre-defined dictionaries (U.S. SSN, Credit Card, Healthcare ICD-10) targeting AI destinations.")


def ai_11(cl):
    """Credentials and secrets protection"""
    d, c = cl.get("/zia/dlpDictionaries")
    dicts = _ls(d) if c in (200, 204) else []
    cred_dicts = []
    for d_ in dicts:
        name = (d_.get("name") or "").lower()
        if any(k in name for k in ["credential", "secret", "api key", "apikey", "token", "aws key", "azure key"]):
            cred_dicts.append(d_)
    if cred_dicts:
        return R(R.PASS, f"{len(cred_dicts)} credential/secret dictionary/ies defined.")
    return R(R.WARN, "No credential/secret DLP dictionaries detected. Best Practice: Developers frequently paste API keys, AWS secrets, and connection strings into AI tools. Create custom dictionaries for AWS Access Keys, Azure Client Secrets, Google API Keys, and generic high-entropy tokens.")


# ═══════════════════════════════════════════════════════════════════════
# DLP ENGINE & DICTIONARY QUALITY
# ═══════════════════════════════════════════════════════════════════════

def ai_12(cl):
    """AI classification dictionaries (LLM-based)"""
    d, c = cl.get("/zia/dlpDictionaries")
    dicts = _ls(d) if c in (200, 204) else []
    ai_class = []
    for d_ in dicts:
        name = (d_.get("name") or "").lower()
        if any(k in name for k in ["ai class", "llm class", "ml class", "intent", "llm "]):
            ai_class.append(d_)
    if ai_class:
        return R(R.PASS, f"{len(ai_class)} AI/LLM-based classification dictionary/ies. Best Practice: Zscaler's LLM Classification goes beyond regex — it understands content sensitivity without keywords. Use for nuanced use cases where regex misses context.")
    return R(R.WARN, "No AI/LLM-based classification dictionaries. Best Practice: Zscaler offers LLM Classification that reads content in real-time using NLP (no keywords needed). Ideal for identifying sensitive business content that traditional regex misses. Enable via Admin > DLP > Dictionaries.")


def ai_13(cl):
    """Adversarial prompt pattern detection"""
    d, c = cl.get("/zia/dlpDictionaries")
    dicts = _ls(d) if c in (200, 204) else []
    adv = []
    for d_ in dicts:
        name = (d_.get("name") or "").lower()
        if any(k in name for k in ["prompt inject", "jailbreak", "adversarial", "dan mode", "ignore instructions"]):
            adv.append(d_)
    if adv:
        return R(R.PASS, f"{len(adv)} adversarial prompt dictionary/ies. Detects prompt injection and jailbreak attempts.")
    return R(R.WARN, "No adversarial prompt pattern dictionaries. Best Practice: Create a custom dictionary matching known prompt injection patterns ('ignore previous instructions', 'you are DAN', 'act as unrestricted AI'). Part of OWASP LLM Top 10 coverage.")


# ═══════════════════════════════════════════════════════════════════════
# COPILOT / M365 SPECIFIC
# ═══════════════════════════════════════════════════════════════════════

def ai_14(cl):
    """Copilot oversharing — tenant restriction awareness

    Tenant profiles say which app they restrict in appType (zscaler-sdk-python
    tenancy_restriction_profile: MSLOGINSERVICES, CHATGPT_AI …); the name is
    free text. A ChatGPT tenant profile works only when attached
    (tenancyProfileIds) to an AI & ML Applications Cloud App Control rule."""
    profiles = _rules(cl, "/zia/tenancyRestrictionProfile")
    def app(p): return str(_fv(p, "appType") or "").upper()
    ms = [p for p in profiles if app(p) == "MSLOGINSERVICES"]
    chat = [p for p in profiles if app(p) == "CHATGPT_AI"]
    attached = {n for r in _rules(cl, "/zia/cloudApplicationRules") if str(_fv(r, "type") or "").upper() == "AI_ML" and _enabled(r)
                for n in _names(_fv(r, "tenancyProfileIds"))}
    chat_on = [p for p in chat if str(p.get("id")).upper() in attached or str(p.get("name") or "").upper() in attached]
    note = (f" ChatGPT tenant profile(s): {len(chat)}, {len(chat_on)} attached to an AI & ML Applications rule, so users reach only the corporate ChatGPT workspace." if chat
            else " No ChatGPT tenant profile (CHATGPT_AI): attach one to the AI & ML Applications rule to allow only the corporate ChatGPT workspace.")
    ref = " Ref: https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control"
    if ms:
        return R(R.PASS, f"{len(ms)} Microsoft Login Services tenant profile(s) (appType MSLOGINSERVICES). Prevents users from accessing personal Copilot/M365 instances from corporate devices." + note)
    return R(R.WARN, "No Microsoft Login Services tenant profile (appType MSLOGINSERVICES). Best Practice: Prevent data exfiltration to personal Microsoft accounts via Copilot. Create a tenant profile listing only your corporate M365 tenant and attach it to the Cloud App Control rule." + note + ref)


def ai_15(cl):
    """Copilot access control via Cloud App Control"""
    rules = _rules(cl, "/zia/cloudApplicationRules")
    copilot = []
    for r in rules:
        text = str(r).lower()
        if any(k in text for k in ["copilot", "m365 copilot", "microsoft 365 copilot"]):
            copilot.append(r)
    if copilot:
        return R(R.PASS, f"{len(copilot)} Copilot-specific CAC rule(s). Enables granular controls on Copilot prompts and data access.")
    return R(R.WARN, "No Copilot-specific Cloud App Control rules. Best Practice: Create an AI & ML Applications Cloud App Control rule for Microsoft Copilot (granular actions: Chatting, Deleting, Renaming, Sharing, Uploading). To inspect Copilot with DLP and capture its prompts, have Zscaler Support enable WebSocket inspection, then create a custom URL category for substrate.office.com and copilot.microsoft.com with an SSL/TLS Inspection rule above the OneClick rule. DLP inspection and prompt capture cover Microsoft Copilot Chat only, not Copilot embedded in Office apps. Ref: https://help.zscaler.com/zia/configuring-advanced-policy-settings")


# ═══════════════════════════════════════════════════════════════════════
# MONITORING & REPORTING
# ═══════════════════════════════════════════════════════════════════════

def ai_16(cl):
    """NSS streaming captures GenAI events beyond ZIA's six-month log window

    GenAI prompts and transactions are in the web log, so only an enabled
    WEBLOG (or MULTIFEEDLOG) Cloud NSS feed keeps them (SDK NssFeeds
    nssLogType, feedStatus)."""
    feeds = _rules(cl, "/zia/nssFeeds")
    def typ(f): return str(_fv(f, "nssLogType") or "").upper()
    web = [f for f in feeds if typ(f) in ("", "WEBLOG", "MULTIFEEDLOG") and str(_fv(f, "feedStatus") or "ENABLED").upper() == "ENABLED"]
    if web:
        return R(R.PASS, f"{len(web)} enabled web-log NSS feed(s) streaming. GenAI events retained in SIEM beyond ZIA's six-month log window.")
    found = sorted({typ(f) or "unknown" for f in feeds})
    lead = (f"No enabled web-log NSS feed (found: {', '.join(found)}; GenAI prompts and transactions are in the web log). " if feeds else "No NSS feeds. ")
    return R(R.FAIL, lead + "Best Practice: ZIA keeps web logs for a rolling six months (180 days) and no longer (https://help.zscaler.com/zia/about-insights-logs). Given GenAI usage is a top data loss vector, stream web logs to SIEM (Splunk/Sentinel/QRadar) for longer retention and threat hunting. Critical for incident investigations weeks/months later.")


def ai_17(cl):
    """Rule scoping for AI policies (user-aware)"""
    rules = _rules(cl, "/zia/webDlpRules")
    ai_rules = _genai_rules(rules, ids=genai_category_ids(cl))
    scoped = [r for r in ai_rules if r.get("departments") or r.get("groups") or r.get("users")]
    if not ai_rules:
        return R(R.INFO, "No GenAI DLP rules to assess for scoping.")
    if scoped:
        return R(R.PASS, f"{len(scoped)}/{len(ai_rules)} GenAI rule(s) scoped to users/groups. Enables differentiated policies (e.g., Dev team allowed, HR blocked).")
    return R(R.WARN, "GenAI DLP rules are globally scoped. Best Practice: Different teams have different AI needs. Scope rules by department — devs may need Copilot for code, while HR should have stricter controls on AI (PII concerns).")


def ai_18(cl):
    """File type control for AI uploads"""
    rules = _rules(cl, "/zia/webDlpRules")
    ai_rules = _genai_rules(rules, ids=genai_category_ids(cl))
    file_scoped = []
    for r in ai_rules:
        if r.get("fileTypes") or r.get("fileTypeCategories"):
            file_scoped.append(r)
    if ai_rules and file_scoped:
        return R(R.PASS, f"{len(file_scoped)}/{len(ai_rules)} AI rule(s) scope to specific file types. Precision-targeted (PDF, DOCX, XLSX, source code).")
    if ai_rules:
        return R(R.WARN, "AI DLP rules don't specify file types. Best Practice: Scope rules to risky file types commonly leaked to AI: PDF, DOCX, XLSX, CSV, source code files (.py, .js, .java). Reduces false positives while catching high-risk uploads.")
    return R(R.INFO, "No AI DLP rules to assess for file type scoping.")


# ═══════════════════════════════════════════════════════════════════════
# ZERO TRUST BROWSER (FORMERLY BROWSER ISOLATION) FOR AI
# ═══════════════════════════════════════════════════════════════════════

def ai_19(cl):
    """Zero Trust Browser (formerly Browser Isolation) with restricted controls for AI"""
    profiles = _rules(cl, "/zia/browserIsolation/profiles")
    restricted = []
    for p in profiles:
        if p.get("uploadControl") or p.get("downloadControl") or p.get("clipboardControl"):
            restricted.append(p)
    if not profiles:
        return R(R.WARN, "No isolation profiles (Zero Trust Browser, formerly Browser Isolation). Best Practice: For uncategorized/emerging AI tools, isolation with upload/download/clipboard disabled is the gold standard — allows access, prevents exfiltration.")
    if restricted:
        return R(R.PASS, f"{len(restricted)}/{len(profiles)} isolation profile(s) have restricted controls (upload/download/clipboard). Ideal for AI tool access.")
    return R(R.WARN, f"{len(profiles)} isolation profile(s) exist (Zero Trust Browser) but none restrict upload/download/clipboard. Best Practice: Create a dedicated isolation profile for AI tools with all data egress disabled.")


def ai_20(cl):
    """Device posture gates AI access

    URL Filtering rules (and AI & ML Cloud App Control rules) gate on
    deviceTrustLevels (ANY, UNKNOWN_DEVICETRUSTLEVEL, LOW_TRUST,
    MEDIUM_TRUST, HIGH_TRUST — terraform zia_url_filtering_rules); a rule
    that lists ANY or the unknown level applies to all traffic."""
    ids = genai_category_ids(cl)
    rules = _genai_rules(_rules(cl, "/zia/urlFilteringRules"), ids=ids) + [r for r in _rules(cl, "/zia/cloudApplicationRules") if str(_fv(r, "type") or "").upper() == "AI_ML" and _enabled(r)]
    def gated(r):
        lv = {str(x).upper() for x in (_fv(r, "deviceTrustLevels") or [])}
        return bool(lv) and not lv & {"ANY", "UNKNOWN_DEVICETRUSTLEVEL"}
    posture_gated = [r for r in rules if gated(r)]
    if not rules:
        return R(R.INFO, "No GenAI URL or AI & ML Cloud App Control rules to check for device posture.")
    if posture_gated:
        return R(R.PASS, f"{len(posture_gated)} AI rule(s) gated by device trust level. Only trusted devices can access AI tools.")
    return R(R.WARN, "AI access not gated by device posture. Best Practice: Only allow AI tool access from managed, compliant devices. Set device trust levels (from Client Connector posture) on the AI URL Filtering and AI & ML Cloud App Control rules, leaving out Unknown, which applies to all traffic.")


# ═══════════════════════════════════════════════════════════════════════
# AI GUARD: the findings the Bulk changes AI Guard builders address
# ═══════════════════════════════════════════════════════════════════════

AI_GUARD_ROUTING = "/report/operations?build=aiguard_routing"
AI_GUARD_POLICY = "/report/operations?build=aiguard_detection_policy"
# check id -> (builder link, what the builder does about it)
AI_GUARD_LINKS = {
    "AI.5": (AI_GUARD_ROUTING, "The AI Guard routing builder adds an SSL Inspect rule for the GenAI apps at the top of SSL inspection."),
    "AI.6": (AI_GUARD_ROUTING, "The AI Guard routing builder adds an SSL Inspect rule for the GenAI apps above every Do Not Decrypt rule."),
    "AI.7": (AI_GUARD_POLICY, "An AI Guard detection policy inspects every prompt and answer of the routed GenAI apps."),
    "AI.10": (AI_GUARD_POLICY, "The AI Guard detection policy builder turns HIPAA, PCI, GDPR and other profiles into prompt inspection."),
    "AI.13": (AI_GUARD_POLICY, "AI Guard detects prompt injection and jailbreak attempts; build its detection policy."),
    "AI.15": (AI_GUARD_ROUTING, "The AI Guard routing builder sends Microsoft 365 Copilot through AI Guard, with the SSL rule above the one-click bypass."),
}


def tool_link(check_id, status):
    """{href, label, why} of the AI Guard builder that addresses a GenAI
    finding, or None (a pass, or a check AI Guard does not address)."""
    hit = AI_GUARD_LINKS.get(str(check_id or ""))
    if not hit or str(status or "").upper() in ("PASS", "INFO", "ERROR"):
        return None
    href, why = hit
    label = "Build the AI Guard routing" if href == AI_GUARD_ROUTING else "Build an AI Guard detection policy"
    return {"href": href, "build": href.split("build=", 1)[1], "label": label, "why": why}


# ═══════════════════════════════════════════════════════════════════════
# GENAI REGISTRY
# ═══════════════════════════════════════════════════════════════════════

GENAI_REG = [
    # Shadow AI Discovery
    ("AI.1", "GenAI — Discovery", "AI/ML URL categories in use", ai_1),
    ("AI.2", "GenAI — Discovery", "URL filter rules target GenAI", ai_2),
    ("AI.3", "GenAI — Discovery", "Cloud App Control for AI", ai_3),
    ("AI.4", "GenAI — Discovery", "Zero Trust Browser (formerly Browser Isolation) availability", ai_4),

    # SSL Inspection
    ("AI.5", "GenAI — SSL Inspection", "SSL inspection enabled", ai_5),
    ("AI.6", "GenAI — SSL Inspection", "No AI domains exempt from SSL", ai_6),

    # Prompt & Upload Governance
    ("AI.7", "GenAI — Prompt Governance", "DLP rules target AI destinations", ai_7),
    ("AI.8", "GenAI — Prompt Governance", "User coaching (Caution/Confirm)", ai_8),
    ("AI.9", "GenAI — Prompt Governance", "Source code exfiltration rules", ai_9),
    ("AI.10", "GenAI — Prompt Governance", "PII/PHI/PCI on AI destinations", ai_10),
    ("AI.11", "GenAI — Prompt Governance", "Credentials & secrets dictionaries", ai_11),

    # Detection Quality
    ("AI.12", "GenAI — Detection", "AI/LLM classification in use", ai_12),
    ("AI.13", "GenAI — Detection", "Adversarial prompt patterns", ai_13),

    # Copilot / M365
    ("AI.14", "GenAI — Copilot", "Microsoft tenancy restrictions", ai_14),
    ("AI.15", "GenAI — Copilot", "Copilot-specific CAC rules", ai_15),

    # Monitoring & Reporting
    ("AI.16", "GenAI — Monitoring", "NSS streaming for AI events", ai_16),
    ("AI.17", "GenAI — Monitoring", "AI rules scoped by user/group", ai_17),
    ("AI.18", "GenAI — Monitoring", "File type scoping on AI rules", ai_18),

    # Browser Isolation & Posture
    ("AI.19", "GenAI — Isolation & Posture", "Zero Trust Browser with restricted controls", ai_19),
    ("AI.20", "GenAI — Isolation & Posture", "Device posture gates AI access", ai_20),
]
GENAI_REG = guard_registry(GENAI_REG)   # a refused read (HTTP 401/403) is "Not permitted", never judged


# ═══════════════════════════════════════════════════════════════════════
# AI GUARD: its own configuration, scored (read only when AI Guard is ticked
# on the Scope page; zscaler/aiguard over OneAPI: /aiguard/v1/...). Promoted
# from the AI Guard readiness shown on the builders' forms.
# ═══════════════════════════════════════════════════════════════════════
_AIG = "/aiguard/v1"
_AIG_REF = " Ref: https://help.zscaler.com/ai-guard"
AIG_NA = ("AI Guard is not licensed or not linked to this tenant (the API answered 404): nothing to assess (N/A). It is reached only "
          "through a OneAPI (ZIdentity) API client.")


def _aig(cl, path):
    """(rows, code) of an AI Guard list; AI Guard wraps lists in {"items": [...]}."""
    d, c = cl.get(f"{_AIG}/{path}")
    rows = _ls(d) if c in (200, 204) else []
    if not rows and isinstance(d, dict) and isinstance(d.get("items"), list):
        rows = d["items"]
    return [x for x in rows if isinstance(x, dict)], c


def _aig_unread(c, what):
    if c == 404:
        return R(R.INFO, AIG_NA)
    if c == 0:
        return R(R.INFO, f"AI Guard {what} were not read: AI Guard is not ticked on the Scope page, or this sign-in has no OneAPI client.")
    return R(R.INFO, f"AI Guard {what} could not be read (HTTP {c}).")


def _detectors(p, side):
    key = "inputDetectorPolicies" if side == "input" else "outputDetectorPolicies"
    out = []
    for d in p.get(key) or p.get("input_detector_policies" if side == "input" else "output_detector_policies") or []:
        if isinstance(d, dict) and d.get("enabled") is not False:
            cfg = d.get("configuration") if isinstance(d.get("configuration"), dict) else {}
            out.append((str(d.get("detector") or "").lower(), str(cfg.get("action") or cfg.get("defaultAction") or "").upper()))
    return out


def aig_1(cl):
    """AI Guard has a detection policy that a policy match rule uses"""
    pols, c = _aig(cl, "detections/policies")
    if c not in (200, 204):
        return _aig_unread(c, "detection policies")
    if not pols:
        return R(R.FAIL, "AI Guard has no detection policy, so it inspects nothing even when GenAI traffic reaches it. Fix: build one from "
                 "a compliance profile in Bulk changes → Build new → AI Guard detection policy." + _AIG_REF)
    rules, rc = _aig(cl, "detections/policy-match-rules")
    if rc not in (200, 204):
        return _aig_unread(rc, "policy match rules")
    ids = {str(p.get("id")) for p in pols}
    live = [r for r in rules if r.get("enabled") is not False]
    used = [r for r in live if str(r.get("policyId") or r.get("policy_id")) in ids]
    dangling = [str(r.get("name")) for r in live if str(r.get("policyId") or r.get("policy_id")) not in ids]
    if dangling:
        return R(R.FAIL, f"{len(dangling)} enabled policy match rule(s) point at a detection policy that does not exist: {', '.join(dangling[:5])}. "
                 "The traffic they match is not inspected as intended. Fix: point each rule at an existing detection policy." + _AIG_REF)
    if not used:
        return R(R.FAIL, f"{len(pols)} detection polic{'y' if len(pols) == 1 else 'ies'}, but no enabled policy match rule uses one, so no "
                 "GenAI traffic is matched to a policy. Fix: add a policy match rule for the LLM providers your people use." + _AIG_REF)
    return R(R.PASS, f"{len(pols)} detection polic{'y' if len(pols) == 1 else 'ies'}; {len(used)} enabled policy match rule(s) use them.")


def aig_2(cl):
    """AI Guard detects prompt injection"""
    pols, c = _aig(cl, "detections/policies")
    if c not in (200, 204):
        return _aig_unread(c, "detection policies")
    if not pols:
        return R(R.INFO, "No detection policy (check AIG.1).")
    miss = [str(p.get("name")) for p in pols if not any(d == "prompt_injection" for d, _a in _detectors(p, "input"))]
    if miss:
        return R(R.WARN, f"{len(miss)} of {len(pols)} detection polic{'y does' if len(pols) == 1 else 'ies do'} not detect prompt injection "
                 f"on prompts: {', '.join(miss[:5])}. A prompt that tells the model to ignore its rules is not noticed. Fix: turn on the "
                 "prompt_injection input detector." + _AIG_REF)
    return R(R.PASS, f"Every detection policy ({len(pols)}) detects prompt injection on prompts.")


def aig_3(cl):
    """AI Guard blocks, not only detects"""
    pols, c = _aig(cl, "detections/policies")
    if c not in (200, 204):
        return _aig_unread(c, "detection policies")
    if not pols:
        return R(R.INFO, "No detection policy (check AIG.1).")
    blocking = [str(p.get("name")) for p in pols if any(a == "BLOCK" for _d, a in _detectors(p, "input") + _detectors(p, "output"))]
    if not blocking:
        return R(R.WARN, f"Every detection policy ({len(pols)}) only detects: nothing is blocked, so a prompt carrying card numbers or an "
                 "injection still reaches the model. Monitor first is right; once the detections look right, preview the policy again with "
                 "Block (Bulk changes → AI Guard detection policy, mode Block)." + _AIG_REF)
    return R(R.PASS, f"{len(blocking)} detection polic{'y blocks' if len(blocking) == 1 else 'ies block'} on at least one detector.")


def aig_4(cl):
    """AI Guard inspects the model's answers, not only the prompts"""
    pols, c = _aig(cl, "detections/policies")
    if c not in (200, 204):
        return _aig_unread(c, "detection policies")
    if not pols:
        return R(R.INFO, "No detection policy (check AIG.1).")
    blind = [str(p.get("name")) for p in pols if not _detectors(p, "output")]
    if blind:
        return R(R.WARN, f"{len(blind)} of {len(pols)} detection polic{'y has' if len(pols) == 1 else 'ies have'} no output detector: "
                 f"{', '.join(blind[:5])}. Answers that carry personal data or a malicious link reach the user unchecked. Fix: add output "
                 "detectors (pii, malicious_url, toxicity) to the policy." + _AIG_REF)
    return R(R.PASS, f"Every detection policy ({len(pols)}) also inspects the model's answers.")


def aig_5(cl):
    """LLM applications that keep prompts keep them encrypted"""
    apps, c = _aig(cl, "llm-applications")
    if c not in (200, 204):
        return _aig_unread(c, "LLM applications")
    if not apps:
        return R(R.INFO, "No LLM application is registered in AI Guard: nothing to check (N/A).")
    plain = []
    for a in apps:
        st = a.get("applicationSettings") or a.get("application_settings") or {}
        keeps = st.get("includeEventContents", st.get("include_event_contents"))
        enc = st.get("encryptEventContents", st.get("encrypt_event_contents"))
        if keeps is True and enc is not True:
            plain.append(str(a.get("name")))
    if plain:
        return R(R.WARN, f"{len(plain)} of {len(apps)} LLM application(s) keep the prompts and answers without encrypting them: "
                 f"{', '.join(plain[:5])}. What people typed (which can be personal or confidential data) is stored readable. Fix: turn on "
                 "Encrypt Event Contents for each application in the AI Guard portal, or stop keeping the contents." + _AIG_REF)
    return R(R.PASS, f"No LLM application ({len(apps)}) keeps prompts unencrypted.")


def aig_6(cl):
    """Every LLM application has a credential to its provider"""
    apps, c = _aig(cl, "llm-applications")
    if c not in (200, 204):
        return _aig_unread(c, "LLM applications")
    if not apps:
        return R(R.INFO, "No LLM application is registered in AI Guard: nothing to check (N/A).")
    creds, cc = _aig(cl, "llm-application-credentials")
    if cc not in (200, 204):
        return _aig_unread(cc, "LLM application credentials")
    with_cred = {str(x.get("applicationId") or x.get("application_id")) for x in creds}
    none = [str(a.get("name")) for a in apps if str(a.get("id")) not in with_cred]
    if none:
        return R(R.WARN, f"{len(none)} of {len(apps)} LLM application(s) have no application credential: {', '.join(none[:5])}. Their "
                 "traffic cannot be sent through AI Guard, so it is not inspected, or the application is left over. Fix: create a credential "
                 "for each in the AI Guard portal, or remove the unused application." + _AIG_REF)
    return R(R.PASS, f"Every LLM application ({len(apps)}) has a credential ({len(creds)} in all; key values are never read).")


# Provider credential age (assumed thresholds: a key older than a year with no
# expiry is due for rotation; one expiring within 30 days needs planning).
CRED_ROTATE_DAYS = 365
CRED_SOON_DAYS = 30
_DAY_MS = 86400 * 1000


def _now_ms():
    """The clock AIG.7 judges ages by (one seam, so tests inject the time)."""
    import time
    return int(time.time() * 1000)


def _ms(v):
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return None
    return n * 1000 if 0 < n < 10 ** 11 else (n if n > 0 else None)   # seconds or milliseconds


def aig_7(cl):
    """LLM provider credentials are not expired, expiring soon or unrotated

    client.aiguard.llm_provider_credentials.list_credentials() GET
    /aiguard/v1/llm-provider-credentials (LlmProviderCredentials: providerId,
    name, expireTimeMillis, apiCredentials). Only names and dates are kept
    (ai_guard.provider_credential_metadata): the key under apiCredentials
    never reaches this check, a result, a log or a snapshot."""
    import ai_guard
    rows, c = _aig(cl, "llm-provider-credentials")
    if c not in (200, 204):
        return _aig_unread(c, "LLM provider credentials")
    creds = ai_guard.provider_credential_metadata(rows)
    if not creds:
        return R(R.INFO, "No LLM provider credential is stored in AI Guard: nothing to check (N/A).")
    now = _now_ms()

    def nm(x):
        s = "".join(ch for ch in str(x.get("name") or x.get("id") or "?") if ch.isprintable())
        return s[:60]
    expired, soon, old, unknown = [], [], [], []
    for x in creds:
        exp, made = _ms(x.get("expireTimeMillis")), _ms(x.get("createTimeMillis"))
        if exp:
            if exp <= now:
                expired.append(nm(x))
            elif exp - now <= CRED_SOON_DAYS * _DAY_MS:
                soon.append(f"{nm(x)} ({max(0, (exp - now) // _DAY_MS)} day(s) left)")
        elif made:
            if now - made > CRED_ROTATE_DAYS * _DAY_MS:
                old.append(f"{nm(x)} ({(now - made) // _DAY_MS} days old, no expiry)")
        else:
            unknown.append(nm(x))
    few = lambda xs: ", ".join(xs[:5]) + (f" and {len(xs) - 5} more" if len(xs) > 5 else "")
    if expired:
        return R(R.FAIL, f"{len(expired)} of {len(creds)} LLM provider credential(s) have expired: {few(expired)}. Applications that use them "
                 "cannot reach their model through AI Guard. Fix: issue a new key at the provider and replace the credential in AI Guard "
                 "(key values are never read by this app)." + _AIG_REF)
    if soon or old:
        parts = ([f"expiring within {CRED_SOON_DAYS} days: {few(soon)}"] if soon else []) + \
                ([f"older than {CRED_ROTATE_DAYS} days with no expiry: {few(old)}"] if old else [])
        return R(R.WARN, f"LLM provider credential(s) {'; '.join(parts)}. Fix: rotate the provider key and update the credential in AI Guard "
                 "before it lapses, and give new keys an expiry." + _AIG_REF)
    if unknown:
        return R(R.INFO, f"Unknown: {len(unknown)} of {len(creds)} LLM provider credential(s) state no expiry or creation date ({few(unknown)}); "
                 f"the other {len(creds) - len(unknown)} are current. Not judged as current.")
    return R(R.PASS, f"All {len(creds)} LLM provider credential(s) are current (none expired, expiring within {CRED_SOON_DAYS} days "
             f"or older than {CRED_ROTATE_DAYS} days without expiry). Key values are never read.")


AIGUARD_REG = guard_registry([
    ("AIG.1", "AI Guard — Detection", "A detection policy is in use", aig_1),
    ("AIG.2", "AI Guard — Detection", "Prompt injection detected", aig_2),
    ("AIG.3", "AI Guard — Detection", "Blocks, not only detects", aig_3),
    ("AIG.4", "AI Guard — Detection", "Answers inspected too", aig_4),
    ("AIG.5", "AI Guard — Applications", "Stored prompts encrypted", aig_5),
    ("AIG.6", "AI Guard — Applications", "Applications have a credential", aig_6),
    ("AIG.7", "AI Guard — Applications", "Provider credentials current (metadata only)", aig_7),
])
