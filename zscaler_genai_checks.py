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

from dlp_assessment_full_auto import R, _ls

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
    "grok", "x.ai",
    "ollama",
    "jasper", "writesonic", "copy.ai",
    "notion ai", "notionai",
]

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
    """Return True if text contains any of the keywords (case-insensitive)."""
    if not text:
        return False
    t = text.lower()
    return any(k in t for k in keywords)


def _genai_rules(rules, field="name"):
    """Return rules whose name/description mentions GenAI/AI keywords."""
    out = []
    for r in rules:
        text = str(r.get(field, "")) + " " + str(r.get("description", ""))
        if _has_any(text, GENAI_KEYWORDS):
            out.append(r)
    return out


# ═══════════════════════════════════════════════════════════════════════
# SHADOW AI DISCOVERY
# ═══════════════════════════════════════════════════════════════════════

def ai_1(cl):
    """GenAI URL categories are being used"""
    d, c = cl.get("/zia/urlCategories")
    cats = _ls(d) if c in (200, 204) else []
    ai_cats = []
    for cat in cats:
        name = (cat.get("configuredName") or cat.get("val") or "")
        if _has_any(name, ["ai", "ml", "genai", "chatgpt", "copilot", "llm", "artificial"]):
            ai_cats.append(cat)
    if ai_cats:
        names = ", ".join(c.get("configuredName", c.get("val", "?")) for c in ai_cats[:5])
        return R(R.PASS, f"Found {len(ai_cats)} AI/ML URL categor(ies): {names}. Best Practice: Zscaler's 'AI and ML Applications' URL category provides a foundation for GenAI governance. Periodically review which AI apps you allow/block — this list grew 3,464% YoY per ThreatLabz 2025.")
    return R(R.FAIL, "No AI/ML URL categories configured. Best Practice: Zscaler provides the 'AI and ML Applications' URL category covering ChatGPT, Claude, Gemini, Copilot, and 500+ other AI tools. Enable this category as your first line of defense for GenAI governance. Ref: Zscaler Securing Generative AI guide.")


def ai_2(cl):
    """AI/ML traffic has URL filtering rules"""
    d, c = cl.get("/zia/urlFilteringRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    enabled = [r for r in ai_rules if (r.get("state") or "").upper() == "ENABLED"]
    if not ai_rules:
        return R(R.WARN, "No URL filtering rules target GenAI by name. Best Practice: Create a dedicated URL filtering rule for AI/ML Applications. Zscaler recommends starting with Block or Caution, then selectively allowing sanctioned AI tools for specific user groups. Ref: Zscaler Securing Generative AI.")
    return R(R.PASS, f"{len(enabled)} active URL filter rule(s) target GenAI.")


def ai_3(cl):
    """Shadow AI detection via Cloud App Control"""
    d, c = cl.get("/zia/cloudApplicationRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    if ai_rules:
        return R(R.PASS, f"{len(ai_rules)} Cloud App Control rule(s) target AI apps. This enables granular actions (prompt/upload/download control) on sanctioned vs unsanctioned AI tools.")
    return R(R.WARN, "No Cloud App Control rules for AI apps. Best Practice: Cloud App Control enables granular inspection of GenAI activities (prompt submission, file upload, download, share). Without CAC, you can only block the URL, not the specific activity. Create CAC rules using rule_type='AI_ML' to govern each AI tool individually.")


def ai_4(cl):
    """Browser Isolation available for risky AI tools"""
    d, c = cl.get("/zia/isolationProfile")
    profiles = _ls(d) if c in (200, 204) else []
    if profiles:
        return R(R.PASS, f"{len(profiles)} Browser Isolation profile(s) available. Best Practice: Route unsanctioned AI tools through Browser Isolation with upload/download/clipboard disabled — users can still use the tools but can't exfiltrate sensitive data. This is Zscaler's recommended 'coach, don't block' approach.")
    return R(R.WARN, "No Browser Isolation profiles. Best Practice: Browser Isolation is the ideal middle-ground for AI tools — it allows access without enabling data exfiltration. Configure profiles with clipboard/download/upload restrictions for AI categories.")


# ═══════════════════════════════════════════════════════════════════════
# SSL INSPECTION FOR AI TRAFFIC
# ═══════════════════════════════════════════════════════════════════════

def ai_5(cl):
    """SSL inspection enabled for AI traffic"""
    d, c = cl.get("/zia/sslInspectionRules")
    rules = _ls(d) if c in (200, 204) else []
    inspect_rules = [r for r in rules if (r.get("action") or "").upper() in ("INSPECT", "SSL_INSPECT")]
    if not inspect_rules:
        return R(R.FAIL, "No SSL inspection rules. Best Practice: SSL inspection is MANDATORY for GenAI governance. Without it, Zscaler sees only the domain (chat.openai.com) but cannot inspect prompts, uploads, or DLP content. All AI traffic is HTTPS — you need SSL inspection to see inside.")
    return R(R.PASS, f"{len(inspect_rules)} SSL inspect rule(s) enabled. GenAI prompts and uploads can be inspected for DLP violations.")


def ai_6(cl):
    """AI domains are NOT in SSL Do-Not-Inspect lists"""
    d, c = cl.get("/zia/sslInspectionRules")
    rules = _ls(d) if c in (200, 204) else []
    dni = [r for r in rules if (r.get("action") or "").upper() in ("DO_NOT_INSPECT", "SSL_DO_NOT_INSPECT", "EXEMPT")]
    risky = []
    for r in dni:
        text = str(r).lower()
        if any(k in text for k in ["chatgpt", "openai", "claude", "anthropic", "gemini", "copilot", "huggingface"]):
            risky.append(r.get("name", "?"))
    if risky:
        return R(R.FAIL, f"{len(risky)} SSL DNI rule(s) exempt AI domains: {', '.join(risky[:3])}. Best Practice: NEVER exempt GenAI domains from SSL inspection — this creates a blind spot where sensitive data can flow unchecked. Remove these exemptions immediately.")
    return R(R.PASS, "No AI domains exempted from SSL inspection.")


# ═══════════════════════════════════════════════════════════════════════
# PROMPT & UPLOAD GOVERNANCE
# ═══════════════════════════════════════════════════════════════════════

def ai_7(cl):
    """DLP rules target AI destinations"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    enabled = [r for r in ai_rules if (r.get("state") or "").upper() == "ENABLED"]
    if not ai_rules:
        return R(R.FAIL, "No DLP rules target GenAI by name. Best Practice: Create dedicated DLP rules with URL category 'AI and ML Applications' as the destination. Scan prompts and file uploads for PII, source code, credentials, and confidential data before they reach LLMs.")
    return R(R.PASS, f"{len(enabled)} active DLP rule(s) target GenAI destinations.")


def ai_8(cl):
    """Prompt/Confirm user coaching on AI tools"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    confirm = [r for r in ai_rules if (r.get("action") or "").upper() in ("CONFIRM", "PROMPT", "ALLOW_WITH_CONFIRM", "CAUTION")]
    if confirm:
        return R(R.PASS, f"{len(confirm)} AI DLP rule(s) use Prompt/Confirm actions — users are coached before risky AI interactions. Aligns with Zscaler 'coach, don't block' best practice.")
    return R(R.WARN, "No Prompt/Confirm actions on AI DLP rules. Best Practice: Instead of hard-blocking AI tools (which drives users to personal devices), use Prompt/Confirm. This displays a warning message explaining AI data risks and requires user acknowledgment before access. Significantly reduces shadow AI usage.")


def ai_9(cl):
    """Source code exfiltration rules for AI"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    code_rules = []
    for r in rules:
        if (r.get("state") or "").upper() != "ENABLED":
            continue
        text = (r.get("name") or "") + " " + (r.get("description") or "")
        if _has_any(text, ["source", "code", "github", "repo", "snippet", "codebase"]):
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
    """Copilot oversharing — tenant restriction awareness"""
    d, c = cl.get("/zia/tenancyRestrictionProfile")
    profiles = _ls(d) if c in (200, 204) else []
    ms_profiles = []
    for p in profiles:
        name = (p.get("name") or "").lower()
        if any(k in name for k in ["microsoft", "m365", "o365", "office", "copilot", "azure"]):
            ms_profiles.append(p)
    if ms_profiles:
        return R(R.PASS, f"{len(ms_profiles)} Microsoft tenancy restriction profile(s). Prevents users from accessing personal Copilot/M365 instances from corporate devices.")
    return R(R.WARN, "No Microsoft tenancy restriction profiles. Best Practice: Prevent data exfiltration to personal Microsoft accounts via Copilot. Create tenancy restrictions listing only your corporate M365 tenant. Critical for Copilot governance per Zscaler Copilot Deployment Wizard guidance.")


def ai_15(cl):
    """Copilot access control via Cloud App Control"""
    d, c = cl.get("/zia/cloudApplicationRules")
    rules = _ls(d) if c in (200, 204) else []
    copilot = []
    for r in rules:
        text = str(r).lower()
        if any(k in text for k in ["copilot", "m365 copilot", "microsoft 365 copilot"]):
            copilot.append(r)
    if copilot:
        return R(R.PASS, f"{len(copilot)} Copilot-specific CAC rule(s). Enables granular controls on Copilot prompts and data access.")
    return R(R.WARN, "No Copilot-specific Cloud App Control rules. Best Practice: Create a CAC rule specifically for Microsoft Copilot. Zscaler can detect Copilot prompts and inspect them for sensitive data. Without this, Copilot inherits broad Microsoft 365 policies that may not address AI-specific risks.")


# ═══════════════════════════════════════════════════════════════════════
# MONITORING & REPORTING
# ═══════════════════════════════════════════════════════════════════════

def ai_16(cl):
    """NSS streaming captures GenAI events beyond 30 days"""
    d, c = cl.get("/zia/nssFeeds")
    feeds = _ls(d) if c in (200, 204) else []
    if feeds:
        return R(R.PASS, f"{len(feeds)} NSS feed(s) streaming. GenAI events retained in SIEM beyond the 30-day ZIA default.")
    return R(R.FAIL, "No NSS feeds. Best Practice: Zscaler retains web logs for only 30 days by default. Given GenAI usage is a top data loss vector, stream logs to SIEM (Splunk/Sentinel/QRadar) for longer retention and threat hunting. Critical for incident investigations weeks/months later.")


def ai_17(cl):
    """Rule scoping for AI policies (user-aware)"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    scoped = [r for r in ai_rules if r.get("departments") or r.get("groups") or r.get("users")]
    if not ai_rules:
        return R(R.INFO, "No GenAI DLP rules to assess for scoping.")
    if scoped:
        return R(R.PASS, f"{len(scoped)}/{len(ai_rules)} GenAI rule(s) scoped to users/groups. Enables differentiated policies (e.g., Dev team allowed, HR blocked).")
    return R(R.WARN, "GenAI DLP rules are globally scoped. Best Practice: Different teams have different AI needs. Scope rules by department — devs may need Copilot for code, while HR should have stricter controls on AI (PII concerns).")


def ai_18(cl):
    """File type control for AI uploads"""
    d, c = cl.get("/zia/webDlpRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
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
# BROWSER ISOLATION FOR AI
# ═══════════════════════════════════════════════════════════════════════

def ai_19(cl):
    """Browser Isolation with restricted controls for AI"""
    d, c = cl.get("/zia/isolationProfile")
    profiles = _ls(d) if c in (200, 204) else []
    restricted = []
    for p in profiles:
        if p.get("uploadControl") or p.get("downloadControl") or p.get("clipboardControl"):
            restricted.append(p)
    if not profiles:
        return R(R.WARN, "No Browser Isolation profiles. Best Practice: For uncategorized/emerging AI tools, Browser Isolation with upload/download/clipboard disabled is the gold standard — allows access, prevents exfiltration.")
    if restricted:
        return R(R.PASS, f"{len(restricted)}/{len(profiles)} BI profile(s) have restricted controls (upload/download/clipboard). Ideal for AI tool access.")
    return R(R.WARN, f"{len(profiles)} Browser Isolation profile(s) exist but none restrict upload/download/clipboard. Best Practice: Create a dedicated BI profile for AI tools with all data egress disabled.")


def ai_20(cl):
    """Device posture gates AI access"""
    d, c = cl.get("/zia/urlFilteringRules")
    rules = _ls(d) if c in (200, 204) else []
    ai_rules = _genai_rules(rules)
    posture_gated = [r for r in ai_rules if r.get("devicePostureProfiles") or r.get("deviceTrustLevels")]
    if not ai_rules:
        return R(R.INFO, "No GenAI URL rules to check for device posture.")
    if posture_gated:
        return R(R.PASS, f"{len(posture_gated)} AI rule(s) gated by device posture. Only compliant devices can access AI tools.")
    return R(R.WARN, "AI access not gated by device posture. Best Practice: Only allow AI tool access from managed, compliant devices. Link AI URL rules to Device Posture Profiles that verify disk encryption, OS version, EDR running, etc.")


# ═══════════════════════════════════════════════════════════════════════
# GENAI REGISTRY
# ═══════════════════════════════════════════════════════════════════════

GENAI_REG = [
    # Shadow AI Discovery
    ("AI.1", "GenAI — Discovery", "AI/ML URL categories in use", ai_1),
    ("AI.2", "GenAI — Discovery", "URL filter rules target GenAI", ai_2),
    ("AI.3", "GenAI — Discovery", "Cloud App Control for AI", ai_3),
    ("AI.4", "GenAI — Discovery", "Browser Isolation availability", ai_4),

    # SSL Inspection
    ("AI.5", "GenAI — SSL Inspection", "SSL inspection enabled", ai_5),
    ("AI.6", "GenAI — SSL Inspection", "No AI domains exempt from SSL", ai_6),

    # Prompt & Upload Governance
    ("AI.7", "GenAI — Prompt Governance", "DLP rules target AI destinations", ai_7),
    ("AI.8", "GenAI — Prompt Governance", "User coaching (Prompt/Confirm)", ai_8),
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
    ("AI.19", "GenAI — Isolation & Posture", "BI with restricted controls", ai_19),
    ("AI.20", "GenAI — Isolation & Posture", "Device posture gates AI access", ai_20),
]
