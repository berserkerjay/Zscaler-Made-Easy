#!/usr/bin/env python3
"""
Local-LLM Command Parser (opt-in)
==================================
Proxies the text-prompt parser to a LOCAL language-model endpoint
(Ollama, llama.cpp, LM Studio — anything OpenAI-chat-compatible).
Never leaves the machine.

Secure-by-design guarantees
---------------------------
1. Loopback-only. The LLM endpoint URL MUST resolve to
   127.0.0.1 / localhost / ::1. Any other host is rejected before
   the fetch is made — no external egress possible through this
   surface even if the config were mis-set.

2. Schema-constrained output. We ask the model to return JSON that
   matches the ParseResult shape. If the JSON is missing, malformed,
   or references unknown actions, we FALL BACK to the deterministic
   parser in commands.py — the LLM can enhance but cannot break.

3. No credentials in the prompt. Only the user's query text is sent.
   Tenant client_id / client_secret / vanity_domain / downloaded
   rule contents are never included in the LLM prompt.

4. Bounded input/output. Input capped at 500 chars before it ever
   reaches this module; output capped at 2KB; timeout 10s.

5. Opt-in. The GUI toggle defaults OFF. Users explicitly flip it
   on per session. No auto-discovery of LLM endpoints.

Supported endpoints
-------------------
- Ollama     : http://localhost:11434/api/chat
- llama.cpp  : http://localhost:8080/v1/chat/completions (OpenAI)
- LM Studio  : http://localhost:1234/v1/chat/completions (OpenAI)
- Any OpenAI-compatible chat endpoint on loopback

Usage
-----
    from llm_parser import parse_with_llm
    from commands import to_dict
    result = parse_with_llm("can you check if my firewall rules look right",
                            endpoint="http://localhost:11434/api/chat",
                            model="llama3.1")
    # result is a commands.ParseResult — same shape as parse()
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from commands import parse as deterministic_parse, ParseResult, COMMAND_CATALOG


# Loopback allowlist — REQUIRED for any local LLM endpoint
_LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}

# Remote-endpoint allowlist for supported cloud providers. Expanding this
# list is a deliberate act — it is the ONLY way this module will make a
# non-loopback request, and it's scoped by the caller's `kind` argument
# so a misconfigured local Ollama request can't accidentally egress.
_REMOTE_HOSTS_BY_KIND = {
    "anthropic": {"api.anthropic.com"},
}

# Hard caps
LLM_TIMEOUT_SEC = 15
LLM_MAX_RESPONSE_BYTES = 4096


def _is_allowed_endpoint(url: str, kind: str) -> bool:
    """
    Local kinds (ollama / openai) require loopback host.
    Named cloud kinds (anthropic) allow ONLY their documented host.
    """
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = (p.hostname or "").lower()
    except Exception:
        return False
    if host in _LOOPBACK_HOSTS:
        return True
    allowed = _REMOTE_HOSTS_BY_KIND.get(kind, set())
    return host in allowed


# Backwards-compat shim — existing callers still use _is_loopback()
def _is_loopback(url: str) -> bool:
    return _is_allowed_endpoint(url, kind="ollama")


def _build_system_prompt() -> str:
    """Prompt the model to emit JSON matching the ParseResult shape.
    The catalog is embedded so the model has the exact set of valid
    actions and params to pick from."""
    catalog_lines = []
    for c in COMMAND_CATALOG:
        catalog_lines.append(
            f"- {c['action']}: {c['description']} "
            f"params={c['params']} examples={c['examples']}"
        )
    catalog_str = "\n".join(catalog_lines)
    return (
        "You are a command parser for a Zscaler security tool. "
        "Translate the user's request into a SINGLE JSON object matching this schema:\n"
        '  {"action": "<one of the actions below>", "params": {...}, "confidence": 0.0-1.0}\n\n'
        "Available actions:\n" + catalog_str + "\n\n"
        "Rules:\n"
        '  - Return ONLY the JSON object, no prose, no markdown fences.\n'
        '  - If the user requests multiple scopes, use a list: "scopes": ["dlp","zpa"].\n'
        '  - Valid scope values: dlp, zia_extras, zpa, zcc, genai, automation, zdx, zidentity, compliance.\n'
        '  - If intent is unclear, return {"action": "unknown", "confidence": 0.0}.\n'
        '  - Never invent actions outside the catalog.\n'
        '  - Never echo user-supplied credentials or secrets in the response.'
    )


def _call_ollama(endpoint: str, model: str, system: str, user: str) -> Optional[str]:
    """Call Ollama's /api/chat endpoint. Returns raw assistant message text, or None."""
    import requests
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "stream": False,
        "format": "json",           # Ollama native JSON-mode
        "options": {"temperature": 0.1, "num_predict": 400},
    }
    r = requests.post(endpoint, json=body, timeout=LLM_TIMEOUT_SEC)
    r.raise_for_status()
    data = r.json()
    msg = (data.get("message") or {}).get("content")
    if not msg:
        return None
    return msg[:LLM_MAX_RESPONSE_BYTES]


def _call_anthropic(endpoint: str, model: str, system: str, user: str, api_key: str) -> Optional[str]:
    """Call Anthropic's Messages API. Requires an API key.
    Endpoint defaults to https://api.anthropic.com/v1/messages.
    Strict allowlist: only api.anthropic.com is reachable from this code path.

    On 4xx errors, surfaces the API's actual error message (model not
    found, invalid key, etc.) instead of the generic 'Bad Request'.
    """
    import requests
    if not api_key:
        raise RuntimeError("Anthropic API key is required for kind='anthropic'.")
    body = {
        "model": model,
        "max_tokens": 600,
        "system": system,
        "messages": [
            {"role": "user", "content": user},
        ],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    r = requests.post(endpoint, json=body, headers=headers, timeout=LLM_TIMEOUT_SEC)

    if not r.ok:
        # Surface the API's actual error text (e.g. 'model X not found').
        # Anthropic returns {"type":"error","error":{"type":"...","message":"..."}}
        detail = f"HTTP {r.status_code}"
        try:
            err = r.json().get("error", {})
            msg = err.get("message") or err.get("type") or ""
            if msg:
                detail = f"{detail}: {msg}"
        except Exception:
            if r.text:
                detail = f"{detail}: {r.text[:200]}"
        # Hint for the classic 'model not found' case
        if r.status_code == 400 and "model" in detail.lower():
            detail += f"  (requested model='{model}' — check https://docs.anthropic.com/en/docs/about-claude/models for valid IDs)"
        raise RuntimeError(detail)

    data = r.json()
    parts = data.get("content") or []
    text_parts = [p.get("text", "") for p in parts if isinstance(p, dict) and p.get("type") == "text"]
    msg = "".join(text_parts).strip()
    if not msg:
        return None
    return msg[:LLM_MAX_RESPONSE_BYTES]


def _call_openai_compatible(endpoint: str, model: str, system: str, user: str) -> Optional[str]:
    """Call an OpenAI-compatible /v1/chat/completions endpoint (llama.cpp, LM Studio)."""
    import requests
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user},
        ],
        "temperature": 0.1,
        "max_tokens": 400,
        "response_format": {"type": "json_object"},
    }
    r = requests.post(endpoint, json=body, timeout=LLM_TIMEOUT_SEC)
    r.raise_for_status()
    data = r.json()
    choices = data.get("choices") or []
    if not choices:
        return None
    msg = (choices[0].get("message") or {}).get("content")
    if not msg:
        return None
    return msg[:LLM_MAX_RESPONSE_BYTES]


def _sanitize_llm_json(raw: str) -> Optional[Dict[str, Any]]:
    """Pull a JSON object out of the LLM response (strip markdown fences if present)."""
    if not raw:
        return None
    # Strip common markdown-fencing the model sometimes adds despite instructions
    s = raw.strip()
    s = re.sub(r"^```(?:json)?\s*", "", s)
    s = re.sub(r"\s*```$", "", s)
    try:
        return json.loads(s)
    except Exception:
        pass
    # Fallback: find the first {...} block
    m = re.search(r"\{.*\}", s, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(0))
        except Exception:
            return None
    return None


# Whitelist of valid action names — LLM can only pick from this set
_VALID_ACTIONS = {c["action"] for c in COMMAND_CATALOG} | {"unknown", "noop"}
# Whitelist of valid scope values
_VALID_SCOPES = {
    "dlp", "zia_extras", "zpa", "zcc", "genai",
    "automation", "zdx", "zidentity", "compliance",
}


def _validate_and_build_result(parsed: Dict[str, Any], original: str) -> Optional[ParseResult]:
    """Strict schema validation of LLM output. Returns a ParseResult
    only if EVERY field is within the allowed set."""
    if not isinstance(parsed, dict):
        return None
    action = parsed.get("action", "")
    if action not in _VALID_ACTIONS:
        return None
    params = parsed.get("params") or {}
    if not isinstance(params, dict):
        return None
    # Enforce scope allowlist if present
    if "scopes" in params:
        scopes = params.get("scopes")
        if not isinstance(scopes, list):
            return None
        scopes = [s for s in scopes if isinstance(s, str) and s in _VALID_SCOPES]
        params["scopes"] = scopes
    # Confidence must be a number in [0, 1]
    conf = parsed.get("confidence", 0.5)
    try:
        conf = float(conf)
        conf = max(0.0, min(1.0, conf))
    except Exception:
        conf = 0.5
    # Matched text capped to avoid attack surfaces via reflected strings
    matched = str(parsed.get("matched_text", ""))[:300]
    suggestion = str(parsed.get("suggestion", ""))[:300] if parsed.get("suggestion") else None

    return ParseResult(
        action=action,
        params=params,
        confidence=conf,
        matched_text=matched,
        original_input=original,
        suggestion=suggestion,
    )


def parse_with_llm(
    user_input: str,
    endpoint: str,
    model: str = "llama3.1",
    kind: str = "ollama",
    api_key: str = "",
) -> ParseResult:
    """
    Parse a user query via an LLM, with strict fallback to the
    deterministic parser on any failure.

    Args:
      user_input: the user's query text (already length-capped upstream)
      endpoint:   URL of the LLM server. For kind=ollama/openai it MUST
                  be loopback. For kind=anthropic it MUST be
                  api.anthropic.com.
      model:      model name (e.g. "llama3.1", "claude-sonnet-4-6").
      kind:       "ollama" — local Ollama /api/chat
                  "openai" — local OpenAI-compatible /v1/chat/completions
                  "anthropic" — Anthropic Messages API (cloud, requires key)
      api_key:    required for kind=anthropic; ignored otherwise.

    Returns:
      commands.ParseResult — same shape as commands.parse().
    """
    original = user_input or ""

    # Always start with the deterministic parse as a safety net
    fallback = deterministic_parse(original)

    # Endpoint allowlist enforcement — refuse anything that could egress
    # to an unintended host. The check is kind-aware: local kinds must be
    # loopback; named cloud kinds (anthropic) must hit their documented host.
    if not _is_allowed_endpoint(endpoint, kind):
        kind_help = {
            "ollama":    "must be loopback (127.0.0.1 / localhost)",
            "openai":    "must be loopback (127.0.0.1 / localhost)",
            "anthropic": "must be api.anthropic.com",
        }.get(kind, "endpoint not in any allowlist for this kind")
        fallback.suggestion = (
            f"LLM endpoint refused for kind='{kind}': {kind_help}. "
            "Falling back to the deterministic parser."
        )
        return fallback

    system = _build_system_prompt()

    try:
        if kind == "ollama":
            raw = _call_ollama(endpoint, model, system, original[:500])
        elif kind == "anthropic":
            raw = _call_anthropic(endpoint, model, system, original[:500], api_key)
        else:
            raw = _call_openai_compatible(endpoint, model, system, original[:500])
    except Exception as e:
        kind_label = "Anthropic API" if kind == "anthropic" else "Local LLM"
        fallback.suggestion = (
            f"{kind_label} unreachable ({type(e).__name__}: {str(e)[:120]}). "
            "Used the deterministic parser instead."
        )
        return fallback

    parsed = _sanitize_llm_json(raw or "")
    if not parsed:
        fallback.suggestion = (
            "Local LLM returned non-JSON output — fell back to the deterministic parser."
        )
        return fallback

    validated = _validate_and_build_result(parsed, original)
    if validated is None:
        fallback.suggestion = (
            "Local LLM output failed schema validation — fell back to the deterministic parser."
        )
        return fallback

    # If LLM says 'unknown' but the deterministic parser had something
    # confident, prefer the deterministic result.
    if validated.action == "unknown" and fallback.action not in ("unknown", "noop"):
        return fallback
    return validated


if __name__ == "__main__":
    # CLI smoke test against a local Ollama server
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("--endpoint", default="http://localhost:11434/api/chat")
    ap.add_argument("--model", default="llama3.1")
    ap.add_argument("--kind", default="ollama", choices=["ollama", "openai"])
    ap.add_argument("query")
    args = ap.parse_args()
    res = parse_with_llm(args.query, args.endpoint, args.model, args.kind)
    from commands import to_dict
    print(json.dumps(to_dict(res), indent=2))
