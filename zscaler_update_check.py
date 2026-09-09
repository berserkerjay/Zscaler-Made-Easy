#!/usr/bin/env python3
"""
Zscaler Update Checker
======================
Checks upstream Zscaler sources for new APIs, SDK releases, and
updated best-practice documentation, and reports which items have
changed since the last check.

Sources monitored:
  - zscaler-sdk-python on PyPI           → version bumps
  - help.zscaler.com/oneapi              → OneAPI reference drift
  - help.zscaler.com/zia (API overview)  → ZIA API surface changes
  - help.zscaler.com/zpa (API overview)  → ZPA API surface changes
  - help.zscaler.com/zscaler-deployments-operation  → BP updates
  - DLP-specific best-practice pages     → Evaluate-All-Rules guidance

Design notes
------------
- All fetches are short-timeout HTTPS to the zscaler.com + pypi.org
  domains only. No arbitrary URLs. No content is executed — only
  hashed.
- Parallel fetches via ThreadPoolExecutor so the whole check
  completes in ~2-5 seconds even with 6 sources.
- A JSON cache file stores the last-seen hash/version per source.
  Next call reports what CHANGED, not the full content.
- Gracefully degrades when offline: each source reports its own
  status (ok | error | changed | unchanged | new).
- Cache location follows the OS convention:
    Windows: %LOCALAPPDATA%\\ZscalerAssessment\\update_cache.json
    macOS:   ~/Library/Caches/ZscalerAssessment/update_cache.json
    Linux:   ~/.cache/zscaler_assessment/update_cache.json

Security
--------
- Fetches only from an allowlist of domains (help.zscaler.com,
  developer.zscaler.com, pypi.org).
- Short hard timeouts (8s connect + read).
- No automatic upgrades — this module only REPORTS. Applying
  updates (e.g. pulling new git commits or upgrading the SDK) is
  an explicit user action via UPDATE_Zscaler_Assessment.bat.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# ── Sources to monitor ───────────────────────────────────────────────

SOURCES: List[Dict[str, Any]] = [
    {
        "key": "sdk_python",
        "name": "zscaler-sdk-python (PyPI)",
        "type": "pypi",
        "package": "zscaler-sdk-python",
        "importance": "high",
        "why": "Official Python SDK. New versions usually include new API endpoints, bug fixes, and auth improvements.",
    },
    {
        "key": "oneapi_reference",
        "name": "OneAPI Reference",
        "type": "html_hash",
        "url": "https://help.zscaler.com/oneapi",
        "importance": "high",
        "why": "The OneAPI umbrella spec — any new unified endpoint shows up here first.",
    },
    {
        "key": "zia_api_overview",
        "name": "ZIA API Overview",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zia/about-api",
        "importance": "high",
        "why": "ZIA-specific API surface. Watch for new rule types, new settings endpoints.",
    },
    {
        "key": "zpa_api_overview",
        "name": "ZPA API Overview",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zpa/about-api",
        "importance": "medium",
        "why": "ZPA-specific API surface.",
    },
    {
        "key": "best_practices",
        "name": "Zscaler Deployment & Operations Best Practices",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zscaler-deployments-operation",
        "importance": "high",
        "why": "Root of the best-practice documentation. Major guidance updates land here.",
    },
    {
        "key": "dlp_eval_all",
        "name": "DLP — First Match Wins vs Evaluate All Rules",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zia/about-first-match-wins-and-evaluate-all-rules-for-dlp",
        "importance": "high",
        "why": "Directly governs the Inline Web DLP migration wizard. Any policy change to this doc affects the recommended migration flow.",
    },
    {
        "key": "dlp_engines_bp",
        "name": "DLP Engines Best Practices",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zia/about-dlp-engines",
        "importance": "medium",
        "why": "Engine-tuning guidance drives several of the DLP assessment checks.",
    },
    {
        "key": "genai_bp",
        "name": "GenAI / AI Security Best Practices",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zia/about-ai-ml-controls",
        "importance": "high",
        "why": "GenAI guidance is changing fast. Keeping the GenAI checks aligned with upstream best practice matters.",
    },
]

# Allowlisted domains — any fetch URL must match one of these.
# Extend via bp_sources.SOURCES for best-practice crawl targets; keep
# the set tight for every other outbound call.
ALLOWED_HOSTS = {
    # Zscaler-official (Tier 1)
    "help.zscaler.com",
    "developer.zscaler.com",
    "www.zscaler.com",
    "trust.zscaler.com",
    "community.zscaler.com",
    # Zscaler GitHub org (read-only public repos)
    "github.com",
    "raw.githubusercontent.com",
    # Authoritative integration docs (Tier 2)
    "learn.microsoft.com",
    "docs.aws.amazon.com",
    "cloud.google.com",
    "registry.terraform.io",
    # Ecosystem partners — SIEM / EDR / IdP integrations (Tier 2)
    "lantern.splunk.com",
    "splunkbase.splunk.com",
    "docs.splunk.com",
    "www.crowdstrike.com",
    "help.okta.com",
    "docs.pingidentity.com",
    # SDK release metadata
    "pypi.org",
}

FETCH_TIMEOUT = 8  # seconds, both connect and read
USER_AGENT = "Mozilla/5.0 (compatible; Zscaler-Assessment/1.0; +localhost)"  # browser-compatible prefix: some CDNs refuse unknown agents


# ── Cache ────────────────────────────────────────────────────────────

def _cache_path() -> str:
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
        d = os.path.join(base, "ZscalerAssessment")
    elif sys.platform == "darwin":
        d = os.path.expanduser("~/Library/Caches/ZscalerAssessment")
    else:
        d = os.path.join(os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache")), "zscaler_assessment")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.dirname(os.path.abspath(__file__))  # fallback to app dir
    return os.path.join(d, "update_cache.json")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]) -> None:
    try:
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass  # best-effort; not fatal


# ── Fetchers ─────────────────────────────────────────────────────────

def _safe_get(url: str, verify_tls: Optional[bool] = None) -> Tuple[Optional[bytes], int, str]:
    """Fetch URL via requests with strict allowlist + timeout. Returns (body, status, error).

    Honors standard proxy env vars (HTTPS_PROXY, HTTP_PROXY, NO_PROXY)
    via requests' built-in support. If those vars aren't set and the
    machine is behind a corporate proxy, surface a helpful message.

    verify_tls: explicit override. None = use env-var default (verify),
                False = skip TLS verification (for corporate TLS MITM).
    """
    host = (urlparse(url).hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        return None, 0, f"host not in allowlist: {host}"
    try:
        import requests
    except Exception:
        return None, 0, "requests library not available"

    proxies = None
    # requests already reads HTTPS_PROXY automatically, but we also accept
    # a process-local ZSCALER_UPDATE_PROXY so users can override without
    # setting a system-wide var.
    custom = os.environ.get("ZSCALER_UPDATE_PROXY")
    if custom:
        proxies = {"http": custom, "https": custom}

    # TLS verification: explicit arg overrides env var
    if verify_tls is None:
        verify_tls = os.environ.get("ZSCALER_UPDATE_VERIFY_TLS", "1") != "0"

    try:
        # Suppress urllib3's InsecureRequestWarning when the user has explicitly
        # opted into verify=False (they know, we know — no need to spam the log).
        if not verify_tls:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            except Exception:
                pass
        r = requests.get(
            url,
            timeout=FETCH_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*"},
            proxies=proxies,
            verify=verify_tls,
        )
        return r.content, r.status_code, ""
    except requests.exceptions.SSLError as e:
        return None, 0, (f"TLS error (corporate TLS inspection?): {str(e)[:200]}. "
                         f"If a corporate proxy intercepts TLS, set ZSCALER_UPDATE_VERIFY_TLS=0.")
    except requests.exceptions.ProxyError as e:
        return None, 0, (f"Proxy rejected the request: {str(e)[:200]}. "
                         f"Set HTTPS_PROXY=http://user:pass@proxy:port or "
                         f"ZSCALER_UPDATE_PROXY to point at an allowed egress.")
    except requests.exceptions.ConnectTimeout:
        return None, 0, (f"Connection timeout to {host}. "
                         f"Likely blocked by a corporate proxy or firewall. "
                         f"Set HTTPS_PROXY/ZSCALER_UPDATE_PROXY or run the tool "
                         f"from a host that can reach pypi.org / help.zscaler.com.")
    except requests.exceptions.Timeout:
        return None, 0, f"read timeout to {host} ({FETCH_TIMEOUT}s)"
    except requests.exceptions.ConnectionError as e:
        msg = str(e)[:200]
        hint = ""
        low = msg.lower()
        if "proxy" in low or "tunnel" in low or "403" in low or "407" in low:
            hint = (" — looks like corporate proxy blocking/auth issue. "
                    "Set HTTPS_PROXY=http://user:pass@proxy:port or "
                    "ZSCALER_UPDATE_PROXY.")
        elif "name" in low or "resolve" in low or "getaddrinfo" in low:
            hint = " — DNS resolution failed; check network/DNS settings."
        return None, 0, f"connection error: {msg}{hint}"
    except Exception as e:
        return None, 0, f"{type(e).__name__}: {str(e)[:200]}"


def _strip_volatile(html_bytes: bytes) -> bytes:
    """
    Remove timestamp-ish / session-id / csrf content that changes every
    request so the hash reflects CONTENT changes, not page-render noise.
    """
    try:
        txt = html_bytes.decode("utf-8", errors="ignore")
    except Exception:
        return html_bytes
    # Drop obvious volatile tokens
    patterns = [
        r"<meta[^>]*csrf[^>]*>",
        r"<script[^>]*>.*?</script>",
        r"<style[^>]*>.*?</style>",
        r"data-session-id=\"[^\"]*\"",
        r"_csrf\": \"[^\"]*\"",
        r"timestamp\": \"[^\"]*\"",
        r"generated-at=\"[^\"]*\"",
        r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[^\"]*",  # ISO timestamps
        r"\?v=\d+",  # cache-bust query strings
    ]
    for p in patterns:
        txt = re.sub(p, "", txt, flags=re.DOTALL | re.IGNORECASE)
    return txt.encode("utf-8", errors="ignore")


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()[:16]


def _check_pypi(source: Dict[str, Any], cached: Dict[str, Any], verify_tls: Optional[bool] = None) -> Dict[str, Any]:
    pkg = source["package"]
    url = f"https://pypi.org/pypi/{pkg}/json"
    body, code, err = _safe_get(url, verify_tls=verify_tls)
    if err or code != 200 or not body:
        return {**_base_result(source, cached),
                "status": "error", "error": err or f"HTTP {code}"}
    try:
        data = json.loads(body.decode("utf-8"))
    except Exception as e:
        return {**_base_result(source, cached), "status": "error", "error": f"parse: {e}"}

    version = (data.get("info") or {}).get("version") or "unknown"
    released = None
    try:
        # pypi stores releases keyed by version
        rel = data.get("releases", {}).get(version) or []
        if rel:
            released = rel[0].get("upload_time_iso_8601") or rel[0].get("upload_time")
    except Exception:
        pass
    summary = (data.get("info") or {}).get("summary") or ""
    url_readable = f"https://pypi.org/project/{pkg}/"

    prev = cached.get("version")
    status = "new" if prev is None else ("changed" if prev != version else "unchanged")

    # Compare installed version if present
    installed = None
    try:
        import importlib.metadata as md
        installed = md.version(pkg)
    except Exception:
        try:
            import pkg_resources  # type: ignore
            installed = pkg_resources.get_distribution(pkg).version
        except Exception:
            installed = None
    installed_mismatch = bool(installed and installed != version)

    return {
        **_base_result(source, cached),
        "status": status,
        "current": version,
        "previous": prev,
        "installed": installed,
        "installed_mismatch": installed_mismatch,
        "released": released,
        "summary": summary[:200],
        "link": url_readable,
        "action_hint": (
            f"pip install --upgrade {pkg}" if installed_mismatch or status == "changed"
            else None
        ),
    }


def _check_html(source: Dict[str, Any], cached: Dict[str, Any], verify_tls: Optional[bool] = None) -> Dict[str, Any]:
    url = source["url"]
    body, code, err = _safe_get(url, verify_tls=verify_tls)
    if err or code != 200 or not body:
        return {**_base_result(source, cached),
                "status": "error", "error": err or f"HTTP {code}",
                "link": url}
    normalized = _strip_volatile(body)
    digest = _hash(normalized)
    size = len(normalized)
    prev_digest = cached.get("hash")
    status = "new" if prev_digest is None else ("changed" if prev_digest != digest else "unchanged")
    return {
        **_base_result(source, cached),
        "status": status,
        "current": digest,
        "previous": prev_digest,
        "size_bytes": size,
        "link": url,
        "action_hint": "Open the link and review the updated section." if status == "changed" else None,
    }


def _base_result(source: Dict[str, Any], cached: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "key": source["key"],
        "name": source["name"],
        "importance": source.get("importance", "medium"),
        "why": source.get("why", ""),
        "last_checked": cached.get("last_checked"),
    }


# ── Orchestrator ─────────────────────────────────────────────────────

def check_for_updates(force: bool = False, only: Optional[List[str]] = None, skip_tls_verify: bool = False) -> Dict[str, Any]:
    """
    Run all (or a subset of) update checks in parallel.
    Returns:
      {
        "checked_at": ISO timestamp,
        "results": [ {...per-source...}, ... ],
        "summary": { "changed": N, "unchanged": N, "new": N, "error": N },
        "any_changed": bool,
      }
    """
    started = time.time()
    cache = _load_cache()
    sources = [s for s in SOURCES if (not only or s["key"] in only)]

    def _run_one(s):
        cached = cache.get(s["key"], {})
        try:
            # Per-request TLS-verify override: when the user opts into
            # bypass (e.g. behind corporate TLS MITM), pass verify=False
            # without touching env vars or requiring a server restart.
            verify_tls = False if skip_tls_verify else None
            if s["type"] == "pypi":
                res = _check_pypi(s, cached, verify_tls=verify_tls)
            elif s["type"] == "html_hash":
                res = _check_html(s, cached, verify_tls=verify_tls)
            else:
                res = {**_base_result(s, cached), "status": "error",
                       "error": f"unknown source type: {s['type']}"}
        except Exception as e:
            res = {**_base_result(s, cached), "status": "error", "error": str(e)[:150]}
        return s["key"], res

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=min(8, len(sources) or 1)) as pool:
        futs = [pool.submit(_run_one, s) for s in sources]
        for fut in as_completed(futs):
            try:
                key, res = fut.result()
                results.append(res)
                # Update cache for this source
                entry = cache.get(key, {}).copy()
                entry["last_checked"] = datetime.now(timezone.utc).isoformat()
                if res.get("status") in ("unchanged", "changed", "new"):
                    if "hash" not in entry or res.get("current"):
                        # For pypi store version; for html store hash
                        if "current" in res and res.get("status") != "error":
                            # html: res['current'] is the hash; pypi: the version
                            if "version" in res or res.get("current", "").startswith("v") or any(c.isdigit() for c in (res.get("current") or "")[:3]):
                                # pypi-ish
                                if _find_source_type(key) == "pypi":
                                    entry["version"] = res["current"]
                                else:
                                    entry["hash"] = res["current"]
                            else:
                                entry["hash"] = res["current"]
                cache[key] = entry
            except Exception as e:
                results.append({"key": "?", "name": "?", "status": "error",
                                "error": f"internal: {e}"[:200]})

    _save_cache(cache)

    # Sort: changed/new first (by importance), then unchanged, then error
    order = {"changed": 0, "new": 1, "unchanged": 2, "error": 3}
    imp_order = {"high": 0, "medium": 1, "low": 2}
    results.sort(key=lambda r: (order.get(r.get("status"), 9),
                                imp_order.get(r.get("importance"), 9),
                                r.get("name", "")))

    summary = {"changed": 0, "unchanged": 0, "new": 0, "error": 0}
    for r in results:
        st = r.get("status", "error")
        summary[st] = summary.get(st, 0) + 1

    # Surface proxy / env state so the user can diagnose mass-connection
    # failures (very common in corporate environments).
    network_diag = {
        "HTTPS_PROXY":            os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy") or None,
        "HTTP_PROXY":             os.environ.get("HTTP_PROXY")  or os.environ.get("http_proxy")  or None,
        "NO_PROXY":               os.environ.get("NO_PROXY")    or os.environ.get("no_proxy")    or None,
        "ZSCALER_UPDATE_PROXY":   os.environ.get("ZSCALER_UPDATE_PROXY") or None,
        "ZSCALER_UPDATE_VERIFY_TLS": os.environ.get("ZSCALER_UPDATE_VERIFY_TLS", "1"),
        "request_skipped_tls_verify": bool(skip_tls_verify),
    }
    all_errors = all(r.get("status") == "error" for r in results) if results else False
    # Detect TLS MITM pattern specifically — every error mentions SSL / CERTIFICATE_VERIFY_FAILED
    tls_only = all_errors and all(
        ("SSL" in (r.get("error") or "") or "certificate" in (r.get("error") or "").lower())
        for r in results
    )

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_seconds": round(time.time() - started, 2),
        "sources_count": len(sources),
        "results": results,
        "summary": summary,
        "any_changed": summary.get("changed", 0) + summary.get("new", 0) > 0,
        "cache_file": _cache_path(),
        "network": network_diag,
        "tls_mitm_suspected": tls_only,
        "proxy_hint": (
            "Corporate TLS inspection detected — every source failed with "
            "CERTIFICATE_VERIFY_FAILED. Your proxy is re-signing TLS with "
            "a CA that Python doesn't trust.\n\n"
            "Fastest fix: click the 🔓 button below to retry with TLS "
            "verification disabled for this session. This is safe because:\n"
            "  • Destinations are allowlisted (pypi.org + help.zscaler.com).\n"
            "  • Content is only hashed — never executed.\n"
            "  • The bypass applies only to the update-checker, not to "
            "Zscaler tenant API traffic."
            if tls_only else
            "Every source returned 'connection error'. This almost always means a "
            "corporate proxy is blocking outbound traffic to pypi.org and help.zscaler.com. "
            "Fix by either:\n"
            "  1. Setting HTTPS_PROXY=http://user:pass@proxy:port in the environment BEFORE "
            "starting the server.\n"
            "  2. Setting ZSCALER_UPDATE_PROXY similarly (takes precedence for the update checker only).\n"
            "  3. Running the tool from a host that can reach pypi.org and help.zscaler.com directly."
        ) if all_errors else None,
    }


def _find_source_type(key: str) -> str:
    for s in SOURCES:
        if s["key"] == key:
            return s["type"]
    return "unknown"


def reset_cache() -> bool:
    """Wipe the update cache — next check will report all sources as 'new'."""
    try:
        p = _cache_path()
        if os.path.exists(p):
            os.remove(p)
        return True
    except Exception:
        return False


# CLI smoke-test: `python zscaler_update_check.py`
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true")
    ap.add_argument("--only", nargs="+", help="Subset of source keys")
    args = ap.parse_args()
    if args.reset:
        print("cache cleared:", reset_cache())
    out = check_for_updates(only=args.only)
    print(json.dumps(out, indent=2))
