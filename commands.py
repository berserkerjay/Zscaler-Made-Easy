#!/usr/bin/env python3
"""
Deterministic Command Parser for the Text-Prompt GUI
=====================================================
Maps natural-language inputs from the GUI's text prompt into an
explicit, auditable action dispatch. NO LLMs, NO free-form eval.
Every recognized command maps to one of a closed set of actions.

Design principles
-----------------
1. Explicit > clever. Every verb+noun combination is spelled out in
   COMMAND_PATTERNS. Unknown input returns {action: "unknown"}.
2. Client-side execution preferred. The server returns the parsed
   command, the GUI executes by calling the matching API endpoint
   that already exists.
3. Safe by construction. No shell, no eval, no SQL. Parameters are
   enumerated (scope keys, sections, check IDs). Any value outside
   the allowlist is rejected with a structured error.
4. Self-documenting. GET /api/commands returns the full catalog so
   the UI can render autocomplete and help without hardcoding.

Examples
--------
  "check dlp"            → {action: "run_assessment", scopes: ["dlp"]}
  "assess all"           → {action: "run_assessment", scopes: ["dlp","zia_extras","zpa","zcc","genai","automation"]}
  "bypass report"        → {action: "open_bypass_report"}
  "check for updates"    → {action: "open_update_check"}
  "why FW-01"            → {action: "explain", check_id: "FW-01"}
  "score cloud firewall" → {action: "filter", keyword: "firewall"}
  "migrate"              → {action: "goto", anchor: "migration"}
  "help"                 → {action: "show_help"}
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


# ── Allowlisted scopes & sections ───────────────────────────────────
ALLOWED_SCOPES = {
    "dlp", "zia_extras", "zia", "zpa", "zcc", "genai",
    "automation", "zdx", "zidentity", "compliance",
}
# Friendly aliases the user might type
SCOPE_ALIASES = {
    "zia_extras": {"zia", "zia platform", "zia extras", "platform"},
    "dlp":        {"dlp", "data loss", "data loss prevention", "web dlp"},
    "zpa":        {"zpa", "private access", "zscaler private access"},
    "zcc":        {"zcc", "client connector", "zapp", "mobile portal", "mobile", "connector"},
    "genai":      {"genai", "gen ai", "ai", "llm", "prompts", "ai security"},
    "automation": {"automation", "sdk", "terraform", "ansible", "iac", "automation readiness"},
    "zdx":        {"zdx", "digital experience", "experience"},
    "zidentity":  {"zidentity", "zid", "identity", "zscaler identity", "users", "groups"},
    "compliance": {"compliance", "audit", "nist", "pci", "hipaa", "gdpr", "soc 2", "iso"},
}

# Keywords that map to sections (for filtering results)
SECTION_KEYWORDS = {
    "firewall": "Firewall",
    "url": "URL",
    "ssl": "SSL",
    "tls": "SSL",
    "engine": "DLP",
    "dictionary": "DLP",
    "dlp": "DLP",
    "sandbox": "Sandbox",
    "location": "Location",
    "user": "User",
    "admin": "Admin",
    "cloud app": "Cloud App",
    "zpa": "ZPA",
    "zcc": "ZCC",
    "genai": "GenAI",
    "ai": "GenAI",
    "bypass": "bypass",
}

# Verb → canonical action name
VERB_ACTIONS = {
    "check":     "run_assessment",
    "run":       "run_assessment",
    "assess":    "run_assessment",
    "audit":     "run_assessment",
    "score":     "run_assessment",
    "validate":  "run_assessment",
    "scan":      "run_assessment",
    "show":      "filter",
    "filter":    "filter",
    "find":      "filter",
    "list":      "filter",
    "search":    "filter",
    "explain":   "explain",
    "why":       "explain",
    "details":   "explain",
    "open":      "open",
    "goto":      "goto",
    "navigate":  "goto",
    "jump":      "goto",
    "help":      "show_help",
    "commands":  "show_help",
    "clear":     "clear_form",
    "reset":     "clear_form",
    "export":    "export",
    "download":  "export",
    "migrate":   "goto",
    "migration": "goto",
    "update":    "open_update_check",
    "updates":   "open_update_check",
    "bypass":    "open_bypass_report",
    "exempt":    "open_bypass_report",
    "exemption": "open_bypass_report",
    "report":    "goto",
}

# Canonical commands the GUI can execute. Each entry describes its
# intent, required params, and a human-friendly example.
COMMAND_CATALOG = [
    {
        "action": "run_assessment",
        "description": "Run the assessment against the given scope(s).",
        "params": ["scopes"],
        "examples": ["check dlp", "assess all", "score zia firewall", "run zcc", "audit genai"],
    },
    {
        "action": "filter",
        "description": "Filter the current results to checks containing a keyword.",
        "params": ["keyword"],
        "examples": ["show ssl", "find bypass", "filter firewall"],
    },
    {
        "action": "explain",
        "description": "Show why a specific check matters — best practice, actual config, business impact.",
        "params": ["check_id_or_keyword"],
        "examples": ["why FW-01", "explain ZCC.11", "details DLP-05"],
    },
    {
        "action": "open_bypass_report",
        "description": "Open the Bypass / Non-Inspected Traffic Inventory report.",
        "params": [],
        "examples": ["bypass", "list bypass", "show exemptions", "bypass report"],
    },
    {
        "action": "open_update_check",
        "description": "Open the Zscaler SDK + docs update checker.",
        "params": [],
        "examples": ["check for updates", "updates", "sdk update"],
    },
    {
        "action": "goto",
        "description": "Scroll to a named section of the app (migration / results / config).",
        "params": ["anchor"],
        "examples": ["migrate", "goto results", "jump to migration wizard"],
    },
    {
        "action": "show_help",
        "description": "Show the command catalog.",
        "params": [],
        "examples": ["help", "?", "commands"],
    },
    {
        "action": "clear_form",
        "description": "Reset the configuration form.",
        "params": [],
        "examples": ["clear", "reset"],
    },
    {
        "action": "export",
        "description": "Download the current assessment in a format.",
        "params": ["format"],
        "examples": ["export json", "download word", "export docx"],
    },
    {
        "action": "validate_against_sdk",
        "description": "Check the tool's endpoint list against the latest zscaler-sdk-python.",
        "params": [],
        "examples": ["validate sdk", "check sdk alignment"],
    },
]


@dataclass
class ParseResult:
    action: str = "unknown"
    params: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.0
    matched_text: str = ""
    original_input: str = ""
    suggestion: Optional[str] = None  # human-friendly suggestion when confidence is low


_POLITENESS = {
    "please", "pls", "kindly", "could you", "can you", "would you",
    "will you", "i want to", "i'd like to", "id like to", "i want",
    "i need to", "i need", "let me", "help me", "can i", "may i",
    "hey", "hi", "hello", "thanks", "thank you", "tell me",
    "show me", "i wanna", "wanna",
}


def _strip_politeness(s: str) -> str:
    """Remove leading politeness phrases so the parser can focus on intent."""
    changed = True
    while changed:
        changed = False
        for phrase in sorted(_POLITENESS, key=len, reverse=True):
            if s.startswith(phrase + " "):
                s = s[len(phrase) + 1:].strip()
                changed = True
                break
            if s == phrase:
                return ""
    return s


_QUESTION_REWRITES = [
    # Map common question phrasings to imperative commands the parser already handles.
    (re.compile(r"^is\s+my\s+(.+?)\s+(?:configured|set up|ok|good|right|secure|compliant)\b.*$"), r"check \1"),
    (re.compile(r"^are\s+my\s+(.+?)\s+(?:configured|set up|ok|good|right|secure|compliant)\b.*$"), r"check \1"),
    (re.compile(r"^how\s+is\s+my\s+(.+?)\s+(?:doing|looking|configured).*$"), r"check \1"),
    (re.compile(r"^what(?:'s| is)\s+wrong\s+with\s+(.+?)$"),                r"explain \1"),
    (re.compile(r"^what(?:'s| is)\s+the\s+status\s+of\s+(.+?)$"),           r"check \1"),
    (re.compile(r"^do\s+i\s+have\s+(.+?)\s+(?:configured|set up)\b.*$"),    r"check \1"),
    (re.compile(r"^(?:tell|show)\s+me\s+about\s+(.+?)$"),                   r"explain \1"),
    (re.compile(r"^(?:find|list|show|get)\s+all\s+(.+?)\s+(?:rules|policies|settings)\b.*$"), r"filter \1"),
    (re.compile(r"^does\s+my\s+(.+?)\s+(?:follow|match|meet)\s+best\s+practice\b.*$"), r"check \1"),
    (re.compile(r"^(.+)\s+best\s+practice[s]?\b.*$"),                       r"check \1"),
]


def _rewrite_questions(s: str) -> str:
    for pattern, replacement in _QUESTION_REWRITES:
        new_s = pattern.sub(replacement, s)
        if new_s != s:
            return new_s.strip()
    return s


def _normalize(s: str) -> str:
    s = (s or "").strip().lower()
    s = re.sub(r"\s+", " ", s)
    # Solo "?" is our help alias — preserve it
    if s == "?":
        return s
    # Strip terminal punctuation before politeness/question handling
    s = re.sub(r"[!.,;:]+$", "", s).strip()
    s = re.sub(r"\?+$", "", s).strip() if len(s) > 1 else s
    # Strip politeness prefixes ("please check my dlp" → "check my dlp")
    s = _strip_politeness(s)
    # Rewrite common question phrasings to imperative commands
    s = _rewrite_questions(s)
    # Remove filler words that carry no intent signal
    filler = {"the", "a", "an", "my", "our", "your", "is", "are",
              "to", "of", "on", "for", "please", "just"}
    tokens = [t for t in s.split() if t not in filler]
    if tokens:
        s = " ".join(tokens)
    return s


def _scope_from_token(token: str) -> Optional[str]:
    """Resolve a token (or short phrase) to a canonical scope key."""
    t = token.strip().lower()
    if t in ALLOWED_SCOPES:
        return t
    for scope, aliases in SCOPE_ALIASES.items():
        if t in aliases:
            return scope
    return None


def _extract_scopes(text: str) -> List[str]:
    """Pull every recognizable scope from the text. Returns empty
    list if none found; caller decides whether to default to 'all'.
    Handles multi-word aliases like 'client connector'."""
    text = " " + text + " "
    found = []
    for scope, aliases in SCOPE_ALIASES.items():
        for alias in aliases:
            if f" {alias} " in text or f" {alias}," in text or f" {alias}." in text:
                if scope not in found:
                    found.append(scope)
                break
    # Single-token fallback
    if not found:
        for tok in text.strip().split():
            s = _scope_from_token(tok)
            if s and s not in found:
                found.append(s)
    return found


def _looks_like_check_id(token: str) -> bool:
    """Matches patterns like 'FW-01', 'DLP-05', 'ZCC.11', 'AUTO-TF-01'."""
    return bool(re.match(r"^(?:[A-Z]{2,5}(?:-[A-Z]{1,4})?[-.][A-Z0-9.]{1,6})$", token.upper()))


def parse(user_input: str) -> ParseResult:
    """Parse a user text prompt into a structured action. Never raises —
    unknown input returns action='unknown' with a suggestion."""
    original = user_input or ""
    text = _normalize(original)
    result = ParseResult(original_input=original)

    if not text:
        result.action = "noop"
        return result

    # Help trigger — any of these go straight to help
    if text in ("help", "?", "commands", "command", "list commands", "what can i do", "h"):
        result.action = "show_help"
        result.confidence = 1.0
        result.matched_text = text
        return result

    # SDK-alignment validator (must come before generic "validate" handling)
    if ("sdk" in text and ("validate" in text or "align" in text or "check" in text)) or \
       text in ("validate sdk", "sdk alignment", "sdk check"):
        result.action = "validate_against_sdk"
        result.confidence = 0.95
        result.matched_text = text
        return result

    # Explain / why <ID or keyword>
    tokens = text.split()
    if tokens[0] in ("why", "explain", "details"):
        target = " ".join(tokens[1:]).strip()
        if not target:
            result.action = "explain"
            result.params = {"target": ""}
            result.suggestion = "Provide a check ID or keyword, e.g. 'why FW-01' or 'explain ssl'."
            return result
        target_upper = target.upper().strip(".,;:")
        if _looks_like_check_id(target_upper):
            result.action = "explain"
            result.params = {"check_id": target_upper}
            result.confidence = 0.95
        else:
            result.action = "explain"
            result.params = {"keyword": target}
            result.confidence = 0.75
        result.matched_text = tokens[0] + " " + target
        return result

    # Bypass report
    if "bypass" in text or "non-inspected" in text or "exempt" in text or "exemption" in text:
        # If it's part of 'why bypass' we already handled above
        result.action = "open_bypass_report"
        result.confidence = 0.9
        result.matched_text = text
        return result

    # Updates
    if "update" in text or ("check" in text and "sdk" in text):
        if "validate" in text or "align" in text:
            result.action = "validate_against_sdk"
            result.confidence = 0.9
            return result
        result.action = "open_update_check"
        result.confidence = 0.9
        result.matched_text = text
        return result

    # Migrate / migration / wizard
    if "migrat" in text or "wizard" in text or "eval all" in text:
        result.action = "goto"
        result.params = {"anchor": "migration"}
        result.confidence = 0.9
        result.matched_text = text
        return result

    # Export / download
    if tokens[0] in ("export", "download"):
        fmt = "json"
        if "csv" in text: fmt = "csv"
        elif "markdown" in text or "md" in text: fmt = "markdown"
        elif "word" in text or "docx" in text or "doc" in text: fmt = "docx"
        elif "json" in text: fmt = "json"
        result.action = "export"
        result.params = {"format": fmt}
        result.confidence = 0.9
        return result

    # Clear / reset
    if text in ("clear", "reset", "clear form", "reset form", "start over"):
        result.action = "clear_form"
        result.confidence = 1.0
        return result

    # Filter / show / find
    if tokens[0] in ("show", "filter", "find", "list", "search"):
        kw = " ".join(tokens[1:]).strip()
        if kw:
            result.action = "filter"
            result.params = {"keyword": kw}
            result.confidence = 0.8
            return result

    # Run / check / assess — the big one. Extract scopes.
    if any(v in text for v in ("check", "run", "assess", "audit", "score", "validate", "scan")):
        scopes = _extract_scopes(text)
        if "all" in tokens or "everything" in tokens or "full" in tokens:
            scopes = sorted(ALLOWED_SCOPES - {"zia"})  # 'zia' is an alias of zia_extras
        # If no scope detected but user mentioned a section keyword
        # (ssl, firewall, url, sandbox...), imply ZIA scope + filter.
        if not scopes:
            for sec_kw in SECTION_KEYWORDS:
                if sec_kw in text:
                    result.action = "run_assessment"
                    result.params = {"scopes": ["zia_extras", "dlp"], "filter": sec_kw}
                    result.confidence = 0.85
                    result.matched_text = text
                    result.suggestion = (
                        f"Running ZIA + DLP and filtering to '{sec_kw}'. "
                        f"Say 'check zia' for the full scope."
                    )
                    return result
        if not scopes:
            result.action = "run_assessment"
            result.params = {"scopes": []}
            result.suggestion = (
                "Include a scope: dlp, zia, zpa, zcc, genai, automation, zdx, or zidentity. "
                "Or say 'run all'."
            )
            result.confidence = 0.4
            return result
        result.action = "run_assessment"
        result.params = {"scopes": scopes}
        result.confidence = 0.95
        return result

    # Last-chance keyword matches to existing sections — treat as filter
    for kw, _sec in SECTION_KEYWORDS.items():
        if kw in text:
            result.action = "filter"
            result.params = {"keyword": kw}
            result.confidence = 0.55
            result.suggestion = f"Interpreted as 'filter {kw}'. Say 'check {kw}' to run the assessment."
            return result

    # Unknown — suggest help
    result.action = "unknown"
    result.suggestion = (
        f"Didn't recognize '{original}'. Try 'help' for the command list, or "
        "'check dlp' / 'check all' / 'bypass' / 'updates'."
    )
    return result


def to_dict(r: ParseResult) -> Dict[str, Any]:
    d = asdict(r)
    # Drop empty fields for cleaner JSON
    return {k: v for k, v in d.items() if v not in (None, "", {}, [])}
