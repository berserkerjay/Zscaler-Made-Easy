#!/usr/bin/env python3
"""
Zscaler Update Checker
======================
Checks upstream Zscaler sources for new APIs, SDK releases, and
updated best-practice documentation, and reports which items have
changed since the last check.

Sources monitored (SOURCES below):
  - zscaler-sdk-python on PyPI           → version bumps
  - help.zscaler.com/oneapi              → OneAPI reference drift
  - help.zscaler.com/zia (API overview)  → ZIA API surface changes
  - help.zscaler.com/zpa (API key management) → ZPA API surface changes
  - help.zscaler.com/zscaler-deployments-operations  → BP updates
  - DLP / GenAI pages (Evaluate All Rules, DLP engines, AI/ML rules)

help.zscaler.com renders its pages in the browser: every URL answers
the same empty shell, and the article comes from /zapi/fetch-data. So a
help.zscaler.com page is read through that answer (help_api_url,
help_article, read_page), and its title and body are what get hashed.

Design notes
------------
- All fetches are short-timeout HTTPS to the zscaler.com + pypi.org
  domains only. No arbitrary URLs. No content is executed — only
  hashed.
- Parallel fetches via ThreadPoolExecutor so the whole check
  completes in ~2-5 seconds even with 8 sources.
- A JSON cache file stores the last-seen hash/version per source.
  Next call reports what CHANGED, not the full content.
- Gracefully degrades when offline: each source reports its own
  status (ok | error | changed | unchanged | new).
- Cache location follows the OS convention (see data_dir()):
    Windows: %LOCALAPPDATA%\\ZscalerMadeEasy\\update_cache.json
    macOS:   ~/Library/Caches/ZscalerMadeEasy/update_cache.json
    Linux:   ~/.cache/zscaler_made_easy/update_cache.json

Security
--------
- Fetches only from an allowlist of domains (help.zscaler.com,
  developer.zscaler.com, pypi.org), over https only, with no user name
  in the URL and no character URL parsers read differently; redirects
  are followed by _safe_get itself and every hop is checked the same way.
- Short hard timeouts (8s connect + read).
- No automatic upgrades — this module only REPORTS. Applying
  updates (e.g. pulling new git commits or upgrading the SDK) is
  an explicit user action via UPDATE_Zscaler_Made_Easy.bat.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, unquote, urljoin, urlparse

import safe_files

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
        "url": "https://help.zscaler.com/zpa/about-api-key-management",
        "importance": "medium",
        "why": "ZPA-specific API surface.",
    },
    {
        "key": "best_practices",
        "name": "Zscaler Deployment & Operations Best Practices",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zscaler-deployments-operations",
        "importance": "high",
        "why": "Root of the best-practice documentation. Major guidance updates land here.",
    },
    {
        "key": "dlp_eval_all",
        "name": "DLP — First Match Wins vs Evaluate All Rules",
        "type": "html_hash",
        "url": "https://help.zscaler.com/zia/configuring-dlp-policy-rules-evaluate-all-rules-mode-enabled",
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
        "url": "https://help.zscaler.com/zia/adding-ai-ml-applications-rule-cloud-app-control",
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
    "automate.zscaler.com",   # the API reference (upstream_check probes it)
    "www.zscaler.com",
    "trust.zscaler.com",
    "community.zscaler.com",
    # SDK wheels for the upstream check (upstream_check.download_sdk,
    # SHA-256 checked against PyPI's JSON before anything is unpacked)
    "files.pythonhosted.org",
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
    # Integration partners watched by the continuous evaluation (Tier 2)
    "help.proofpoint.com",
    "docs.servicenow.com",
    "support.atlassian.com",
    "www.sentinelone.com",
    # SDK release metadata
    "pypi.org",
}

FETCH_TIMEOUT = 8  # seconds, both connect and read
MAX_REDIRECTS = 5  # each hop is checked against the allowlist before it is fetched
USER_AGENT = "Mozilla/5.0 (compatible; Zscaler-Made-Easy/1.0; +localhost)"  # browser-compatible prefix: some CDNs refuse unknown agents


# ── Cache ────────────────────────────────────────────────────────────

# The per-user folder for the caches and the Beacon history: (current name,
# name before the rename to Zscaler Made Easy). The old folder is moved to
# the new name once, so the Beacon history and the crawler's finds are kept.
DATA_DIR_NAMES = {"win32": ("ZscalerMadeEasy", "ZscalerAssessment"),
                  "darwin": ("ZscalerMadeEasy", "ZscalerAssessment"),
                  "other": ("zscaler_made_easy", "zscaler_assessment")}


def data_dir() -> str:
    """The per-user cache folder, owner-only (0700): under %LOCALAPPDATA% on
    Windows, ~/Library/Caches on macOS, $XDG_CACHE_HOME or ~/.cache elsewhere.
    A folder left under the old name is renamed to the new one; while it
    cannot be (a file in it is open), it is used as it is. Falls back to the
    app folder when no folder can be made."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~\\AppData\\Local")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
    name, legacy_name = DATA_DIR_NAMES.get(sys.platform, DATA_DIR_NAMES["other"])
    d, legacy = os.path.join(base, name), os.path.join(base, legacy_name)
    if not os.path.lexists(d) and os.path.isdir(legacy) and not os.path.islink(legacy):
        try:
            os.rename(legacy, d)
        except OSError:
            if not os.path.lexists(d):   # not moved by another process meanwhile
                d = legacy
    try:
        safe_files.private_makedirs(d)   # the per-user cache folder: owner-only (0700)
    except Exception:
        d = os.path.dirname(os.path.abspath(__file__))  # fallback to app dir
    return d


def _cache_path() -> str:
    return os.path.join(data_dir(), "update_cache.json")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(data: Dict[str, Any]) -> None:
    try:
        with safe_files.private_open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass  # best-effort; not fatal


# ── Fetchers ─────────────────────────────────────────────────────────

def _allowed_url(url: str) -> Tuple[str, str]:
    """(host, "") when `url` may be fetched, else (host, why not): https
    only, a host on ALLOWED_HOSTS, no user name or password, and no
    character two URL parsers could read differently (a backslash,
    whitespace or a control character). The host is checked as both
    urllib.parse and urllib3 (the parser requests connects with) read it,
    so 'https://127.0.0.1\\@help.zscaler.com/' cannot pass the check as
    help.zscaler.com and then connect to 127.0.0.1."""
    url = str(url or "")
    if re.search(r"[\\\s\x00-\x1f\x7f]", url):
        return "", "URL refused: it contains a backslash, a space or a control character"
    try:
        from urllib3.util import parse_url
        parsed, other = urlparse(url), parse_url(url)
    except Exception:  # noqa: BLE001 — a URL neither parser can read is refused
        return "", "URL refused: it cannot be parsed"
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or (other.scheme or "").lower() != "https":
        return host, f"only https:// URLs are fetched (got {parsed.scheme or 'none'}://)"
    if parsed.username is not None or parsed.password is not None or other.auth:
        return host, "URL refused: it carries a user name or password"
    if host != (other.host or "").lower():
        return host, "URL refused: its host is ambiguous"
    if host not in ALLOWED_HOSTS:
        return host, f"host not in allowlist: {host}"
    return host, ""


def _safe_get(url: str, verify_tls: Optional[bool] = None) -> Tuple[Optional[bytes], int, str]:
    """Fetch URL via requests with strict allowlist + timeout. Returns (body, status, error).

    Honors standard proxy env vars (HTTPS_PROXY, HTTP_PROXY, NO_PROXY)
    via requests' built-in support. If those vars aren't set and the
    machine is behind a corporate proxy, surface a helpful message.

    verify_tls: explicit override. None = use env-var default (verify),
                False = skip TLS verification (for corporate TLS MITM).
    """
    host, refusal = _allowed_url(url)
    if refusal:
        return None, 0, refusal
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
        # Redirects are followed here, not by requests: every hop must pass
        # the same allowlist (an allowlisted page that redirects to
        # 127.0.0.1, 169.254.169.254 or another site is refused, not read).
        for _hop in range(MAX_REDIRECTS + 1):
            r = requests.get(
                url,
                timeout=FETCH_TIMEOUT,
                headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/json,*/*"},
                proxies=proxies,
                verify=verify_tls,
                allow_redirects=False,
            )
            location = (r.headers or {}).get("Location") if getattr(r, "is_redirect", False) else None
            if not location:
                return r.content, r.status_code, ""
            url = urljoin(url, location)
            host, refusal = _allowed_url(url)
            if refusal:
                return None, 0, f"redirect refused ({refusal})"
        return None, 0, f"more than {MAX_REDIRECTS} redirects"
    except requests.exceptions.SSLError as e:
        return None, 0, (f"TLS error (corporate TLS inspection?): {str(e)[:200]}. "
                         f"If a corporate proxy intercepts TLS, point REQUESTS_CA_BUNDLE at its root "
                         f"certificate (.pem), or put it in certs/ for the container. "
                         f"ZSCALER_UPDATE_VERIFY_TLS=0 is a last resort: it accepts any certificate.")
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


# ── Is there a page behind the link? ─────────────────────────────────
# help.zscaler.com answers 200 with a "page not found" page for a slug
# that has moved, and a plain fetch of a page that only renders in the
# browser has no text. Neither is a link worth handing to the user.
_EMPTY_TITLES = re.compile(r"page not found|not found|access denied|error|no longer available|moved", re.I)
_MIN_TEXT_CHARS = 400


def page_quality(body: Optional[bytes], code: int) -> Dict[str, Any]:
    """{ok, reason, title, text_chars} for a fetched page."""
    if code in (404, 410):
        return {"ok": False, "reason": f"HTTP {code}: the page no longer exists", "title": "", "text_chars": 0}
    if code == 403:
        return {"ok": False, "reason": "HTTP 403: the page cannot be read from here", "title": "", "text_chars": 0}
    if not body:
        return {"ok": False, "reason": "empty response", "title": "", "text_chars": 0}
    txt = body.decode("utf-8", errors="ignore")
    m = re.search(r"<title[^>]*>(.*?)</title>", txt, re.I | re.S)
    title = re.sub(r"\s+", " ", m.group(1)).strip() if m else ""
    main = re.sub(r"<(script|style|noscript|header|footer|nav)[^>]*>.*?</\1>", " ", txt, flags=re.I | re.S)
    text = re.sub(r"<[^>]+>", " ", main)
    text = re.sub(r"&[a-z#0-9]+;", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if title and _EMPTY_TITLES.search(title) and len(text) < 3000:
        return {"ok": False, "reason": f'the page says "{title}"', "title": title, "text_chars": len(text)}
    if re.search(r"page (you are looking for|you requested) (could not be found|does not exist|has moved)", text, re.I):
        return {"ok": False, "reason": "the page says it could not be found", "title": title, "text_chars": len(text)}
    if len(text) < _MIN_TEXT_CHARS:
        return {"ok": False, "reason": f"the page has no readable content ({len(text)} characters of text; it may render only in a browser)", "title": title, "text_chars": len(text)}
    return {"ok": True, "reason": "", "title": title, "text_chars": len(text)}


def section_root(url: str) -> str:
    """The section index of a help page (https://help.zscaler.com/zia for
    /zia/...): the fallback link when the page itself is gone."""
    u = urlparse(url)
    parts = [p for p in u.path.split("/") if p]
    return f"{u.scheme}://{u.netloc}/{parts[0]}" if parts else f"{u.scheme}://{u.netloc}/"


# ── help.zscaler.com renders in the browser ──────────────────────────
# Every help.zscaler.com URL answers the same empty JavaScript shell; the
# page reads its article from /zapi/fetch-data. So do we: the article's
# title and body are what gets checked and hashed, not the shell.
HELP_HOST = "help.zscaler.com"


def help_api_url(url: str) -> Optional[str]:
    """The /zapi/fetch-data URL that carries a help.zscaler.com page's
    article, or None for any other host."""
    u = urlparse(url)
    if (u.hostname or "").lower() != HELP_HOST:
        return None
    # unquote first: a URL that is already percent-encoded keeps its octets.
    alias = quote(unquote(u.path.rstrip("/") or "/"), safe="/")
    return (f"https://{HELP_HOST}/zapi/fetch-data?url_alias={alias}&view_type=full&cloud=null&domain=zscaler"
            "&applicable_category=&applicable_version=&applicable_parent_version=&applicable_product=&keyword=&language=en&_format=json")


def _help_index_html(categories: List[Any]) -> str:
    """A documentation index's categories and their articles as HTML: a
    heading per category, a link per article, in the order given."""
    parts = []
    for c in categories:
        if not isinstance(c, dict):
            continue
        parts.append(f"<h2>{html.escape(str(c.get('title') or ''))}</h2><ul>")
        articles = c.get("articles")
        for a in articles if isinstance(articles, list) else []:
            if isinstance(a, dict):
                parts.append(f"<li><a href=\"{html.escape(str(a.get('url') or ''))}\">{html.escape(str(a.get('title') or ''))}</a></li>")
        parts.append("</ul>")
    return "".join(parts)


def help_article(body: Optional[bytes]) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """(content to hash, page_quality-shaped verdict) from a fetch-data
    answer; None when the answer is not one (the caller then reports a
    failed read, never raises). A missing or locked article answers 200 with its
    own status inside: 404 "Page Not Found", 403 "Help Article in
    Maintenance". The verdict carries basis "article" and the article's
    status, so a hash is only ever compared with one read the same way."""
    try:
        data = json.loads(body.decode("utf-8", errors="ignore") if isinstance(body, bytes) else (body or ""))["data"]
        info, art = data["info"], data.get("body") or {}
        status = int(info["status"])
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, RecursionError):
        # Not an article answer: junk, a status of 1e999 / Infinity, JSON
        # nested too deep to parse. One bad answer never stops a crawl.
        return None
    if not isinstance(art, dict):
        return None
    title = re.sub(r"\s+", " ", str(art.get("title") or "")).strip()
    if status != 200:
        if status in (404, 410):
            why = f'HTTP {status}: the page no longer exists (the help center says "{title or "Page Not Found"}")'
        else:
            msg = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", str(art.get("message") or ""))).strip()
            msg = re.split(r"(?<=[.!?])\s", msg, maxsplit=1)[0][:200]
            why = f'HTTP {status}: the help center says "{title or "not available"}"' + (f" ({msg})" if msg else "")
        return b"", {"ok": False, "reason": why, "title": title, "text_chars": 0, "basis": "article", "article_status": status}
    content = str(art.get("content") or "")
    if not content.strip() and isinstance(art.get("categories"), list):
        # A documentation index (e.g. /zscaler-deployments-operations) has no
        # body of its own: its content is the list of guides under it, so a
        # guide added, renamed or removed is what changes.
        content = _help_index_html(art["categories"])
    # The help center said 200, so the article is there: its title is not
    # searched for "not found" / "error" wording (an article titled
    # "Viewing Removed Devices" or "About Error Codes" is real). Only the
    # body is judged.
    # errors="replace": a lone surrogate escape in the JSON (half an emoji,
    # a title cut short) cannot be encoded as UTF-8 and is not worth a raise.
    q = page_quality(f"<html><body><main>{content}</main></body></html>".encode("utf-8", errors="replace"), 200)
    return _strip_volatile(f"{title}\n{content}".encode("utf-8", errors="replace")), {**q, "title": title, "basis": "article", "article_status": 200}


def read_page(url: str, get: Callable[[str], Tuple[Optional[bytes], int, str]]) -> Tuple[Optional[bytes], Optional[Dict[str, Any]], int, str]:
    """(content to hash, verdict, status, error) for a watched page: a
    help.zscaler.com article through its fetch-data answer, anything else
    as the page itself. The verdict is None when nothing usable answered;
    then content is the error body (if any), status the HTTP status and
    error what went wrong.

    A help.zscaler.com page is never read as the page itself: every URL
    there answers the same empty browser shell, so after a fetch-data
    answer that is not an article (a 5xx, a 429, a proxy's block page, a
    network error) the shell would only read as "no readable content" and
    the page would look gone. The failed read is passed on as it is: no
    verdict, the page's own link kept, and no second request to a host
    that just failed."""
    api = help_api_url(url)
    if api:
        body, code, err = get(api)
        if err and not code:
            return None, None, 0, err
        art = help_article(body) if not err and code == 200 and body else None
        if art:
            return art[0], art[1], 200, ""
        if code == 200 and not err:
            err = "the help center's article API answered something that is not an article"
        return body, None, code, err
    body, code, err = get(url)
    if err or code != 200 or not body:
        return body, None, code, err
    return _strip_volatile(body), {**page_quality(body, code), "basis": "page"}, code, ""


def _gone_note(url: str, name: str, reason: str) -> Tuple[str, str]:
    """(link, note) for a page that is not there: the section index when
    there is one above the page, else the page itself."""
    root = section_root(url)
    if root.rstrip("/") == url.rstrip("/"):
        return url, f"{url} — {reason}."
    return root, f"{url} — {reason}. The link opens the section index instead; search there for \"{name}\"."


def _check_html(source: Dict[str, Any], cached: Dict[str, Any], verify_tls: Optional[bool] = None) -> Dict[str, Any]:
    url = source["url"]
    normalized, q, code, err = read_page(url, lambda u: _safe_get(u, verify_tls=verify_tls))
    if q is None:
        res = {**_base_result(source, cached), "status": "error", "error": err or f"HTTP {code}", "link": url}
        if code in (403, 404, 410):
            q = page_quality(normalized, code)
            link, note = _gone_note(url, source["name"], q["reason"])
            res.update({"link": link, "link_fallback": link != url, "page": q, "link_note": note})
        return res
    normalized = normalized or b""
    digest = _hash(normalized)
    size = len(normalized)
    basis = q.get("basis") or "page"
    # A hash is only compared with one taken the same way from the same
    # URL: the first read of a help.zscaler.com article (or of a page
    # whose URL moved) is a new baseline, not a change.
    same_way = cached.get("basis", "page") == basis and cached.get("url", url) == url
    prev_digest = cached.get("hash") if same_way else None
    status = "new" if prev_digest is None else ("changed" if prev_digest != digest else "unchanged")
    res = {
        **_base_result(source, cached),
        "status": status,
        "current": digest,
        "previous": prev_digest,
        "size_bytes": size,
        "link": url,
        "url": url,
        "basis": basis,
        "page": q,
        "action_hint": "Open the link and review the updated section." if status == "changed" else None,
    }
    if cached.get("hash") and not same_way:
        res["action_hint"] = ("First reading of this page as it is now read (the help center's article, or a new address): "
                              "a new baseline, not a change. Later checks compare against it.")
    if not q["ok"]:
        if basis == "article" and q.get("article_status") not in (200, 404, 410):
            # A locked article (403 "Help Article in Maintenance") is still
            # there and comes back: not readable now, its own link kept.
            res.update({"status": "unreadable", "link": url, "link_fallback": False, "action_hint": None,
                        "link_note": f"{url} — {q['reason']}. The page is still there but cannot be read right now; "
                                     "the next check reads it again."})
            return res
        link, note = _gone_note(url, source["name"], q["reason"])
        res.update({"status": "dead_link", "link": link, "link_fallback": link != url, "action_hint": None, "link_note": note})
    return res


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
                    if res.get("basis"):  # how the hash was taken, and of what (html_hash only)
                        entry["basis"], entry["url"] = res["basis"], res.get("url")
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
