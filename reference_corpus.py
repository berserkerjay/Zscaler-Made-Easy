"""Reference corpus: grounded lookups and on-demand citations.

The corpus is what the app already holds locally: the curated and crawled
best-practice catalogue (title, URL, source tier, topics), the benchmark
guidance text (report_docx's best-practice fallbacks, which benchmarks.py
shows with their reference link) and plain_english's outcome sentences.

* `lookup(question)` ranks those entries by word overlap and answers from
  them with their sources. No network.
* `cite(topic | finding_id, fetch=False)` returns the matching best-practice
  entries with source URL, title, tier, retrieved date and a quoted excerpt
  from the local excerpt cache (or the benchmark guidance text). Fetching a
  page for a fresh excerpt is off by default; when on, it goes through the
  update checker's fetcher (zscaler_update_check._safe_get), which refuses
  any host that is not on its allowlist, and only Zscaler help and docs
  hosts (CITE_HOSTS) are accepted here on top of that.
"""
from __future__ import annotations

import html as _html
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import safe_files

CITE_HOSTS = ("help.zscaler.com", "developer.zscaler.com", "automate.zscaler.com", "www.zscaler.com", "trust.zscaler.com")
MAX_RESULTS = 8
MAX_QUERY = 300
MAX_EXCERPT = 400
MAX_FETCH_BYTES = 400_000
_WORD = re.compile(r"[a-z0-9]{3,}")
_STOP = {"the", "and", "for", "are", "how", "what", "does", "with", "our", "this", "that", "from", "have", "can", "why", "not"}


class CiteError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _words(text: Any) -> set:
    return {w for w in _WORD.findall(str(text or "").lower()) if w not in _STOP}


def _cache_path() -> str:
    env = os.environ.get("DLP_CHECK_CITATIONS")
    if env:
        return env
    from zscaler_update_check import data_dir
    return os.path.join(data_dir(), "citation_excerpts.json")


def _load_cache() -> Dict[str, Any]:
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_cache(d: Dict[str, Any]) -> None:
    try:
        with safe_files.private_open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(d, f, indent=1)
    except Exception:  # noqa: BLE001 - a cache that cannot be saved is only a cache
        pass


def _catalogue() -> List[Dict[str, Any]]:
    from zscaler_best_practices import list_all
    return [e for e in list_all() if e.get("url") and e.get("title")]


def _guidance() -> List[Tuple[str, str, str]]:
    from report_docx import _BP_FALLBACKS
    return [(n, t, u) for n, t, u in _BP_FALLBACKS]


def _outcomes() -> List[Tuple[Tuple[str, ...], str]]:
    import plain_english
    return list(plain_english.OUTCOMES)


def _clip(text: str, n: int = MAX_EXCERPT) -> str:
    t = re.sub(r"\s+", " ", str(text or "")).strip()
    return t if len(t) <= n else t[: n - 1] + "…"


def _score(q: set, *fields: Any) -> int:
    return len(q & _words(" ".join(str(f or "") for f in fields)))


def lookup(question: str, limit: int = 5) -> Dict[str, Any]:
    """Answer from the local corpus: ranked passages, each with its source."""
    q = _words(str(question or "")[:MAX_QUERY])
    if not q:
        raise CiteError("ask a question of at least one word of three letters or more")
    passages: List[Dict[str, Any]] = []
    for needle, text, url in _guidance():
        s = _score(q, needle, text)
        if s:
            passages.append({"score": s, "kind": "benchmark guidance", "text": _clip(text, 600), "source_url": url, "source": "benchmarks (best-practice guidance)"})
    for keys, text in _outcomes():
        s = _score(q, " ".join(keys), text)
        if s:
            passages.append({"score": s, "kind": "plain-English outcome", "text": text, "source_url": None, "source": "plain_english (what the control is for)"})
    for e in _catalogue():
        s = _score(q, e.get("title"), e.get("service"), " ".join(e.get("topics") or []))
        if s:
            passages.append({"score": s, "kind": "best-practice article", "text": e["title"], "source_url": e["url"],
                             "source": f"{e.get('source', 'help_zscaler')} ({e.get('tier', 'unverified')})"})
    passages.sort(key=lambda p: (-p["score"], p["kind"]))
    top = [{k: v for k, v in p.items() if k != "score"} for p in passages[: max(1, min(int(limit), MAX_RESULTS))]]
    return {"question": _clip(question, 120), "passages": top, "answered": bool(top),
            "note": "Answers come only from the app's local corpus; where nothing matches it says so instead of guessing."}


def _topic_for(topic: str, finding_id: str) -> Tuple[str, str]:
    """(query text, plain-English outcome) for a topic or a finding id (looked up in the last assessment)."""
    outcome = ""
    if finding_id:
        fid = str(finding_id)[:60]
        row = None
        try:
            import mcp_tools
            row = next((r for r in mcp_tools._LAST_ASSESSMENT.get("checks") or [] if str(r.get("id")) == fid), None)
        except Exception:  # noqa: BLE001
            row = None
        if row:
            import plain_english
            outcome = plain_english.outcome_for(fid, str(row.get("section") or row.get("sec") or ""))
            return f"{row.get('label') or ''} {row.get('section') or row.get('sec') or ''} {fid}", outcome
        return fid.replace("_", " ").replace(".", " "), outcome
    return str(topic or "")[:MAX_QUERY], outcome


def _excerpt_from_html(body: bytes) -> str:
    text = body[:MAX_FETCH_BYTES].decode("utf-8", "replace")
    m = re.search(r'<meta[^>]+name=["\']description["\'][^>]+content=["\']([^"\']{20,})["\']', text, re.I)
    if m:
        return _clip(_html.unescape(m.group(1)))
    for p in re.findall(r"<p[^>]*>(.*?)</p>", text, re.I | re.S):
        t = _html.unescape(re.sub(r"<[^>]+>", " ", p))
        if len(t.strip()) >= 60:
            return _clip(t)
    return ""


def fetch_excerpt(url: str, getter: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    """Fetch one page for its excerpt (explicit fetch only). Refuses a host
    outside CITE_HOSTS before any request, then uses the update checker's
    allowlisted fetcher."""
    p = urlparse(str(url or ""))
    if p.scheme != "https" or (p.hostname or "").lower() not in CITE_HOSTS:
        raise CiteError(f"Refused: {p.hostname or 'that address'} is not a Zscaler help or docs host the citation tool may fetch.", 403)
    if getter is None:
        from zscaler_update_check import _safe_get as getter  # type: ignore[assignment]
    body, status, err = getter(url)
    if not body or err:
        return {"error": err or f"HTTP {status}"}
    ex = _excerpt_from_html(body)
    if not ex:
        return {"error": "no readable paragraph on that page"}
    rec = {"excerpt": ex, "retrieved": datetime.now(timezone.utc).date().isoformat()}
    cache = _load_cache()
    cache[url] = rec
    _save_cache(cache)
    return rec


def cite(topic: str = "", finding_id: str = "", fetch: bool = False, limit: int = 3, getter: Optional[Callable[..., Any]] = None) -> Dict[str, Any]:
    query, outcome = _topic_for(topic, finding_id)
    q = _words(query)
    if not q:
        raise CiteError("give a topic (a few words) or a finding id")
    cache = _load_cache()
    guidance = _guidance()
    scored = sorted(((_score(q, e.get("title"), e.get("service"), " ".join(e.get("topics") or [])), e) for e in _catalogue()), key=lambda t: -t[0])
    out: List[Dict[str, Any]] = []
    notes: List[str] = []
    for s, e in scored:
        if s == 0 or len(out) >= max(1, min(int(limit), MAX_RESULTS)):
            break
        url = e["url"]
        cached = cache.get(url) if isinstance(cache.get(url), dict) else None
        if fetch and not cached:
            try:
                got = fetch_excerpt(url, getter)
            except CiteError as err:
                notes.append(str(err))
                got = {}
            if got.get("excerpt"):
                cached = got
            elif got.get("error"):
                notes.append(f"{url}: {got['error']}")
        excerpt, retrieved, basis = "", None, "none"
        if cached:
            excerpt, retrieved, basis = cached.get("excerpt", ""), cached.get("retrieved"), "page excerpt (cached)"
        else:
            have = _words(" ".join([str(e.get("title")), str(e.get("service")), " ".join(e.get("topics") or []).replace("_", " ")]))
            g = next((x for x in guidance if x[2] == url), None) or next((x for x in guidance if _words(x[0]) and _words(x[0]) <= have and urlparse(x[2]).hostname == urlparse(url).hostname), None)
            if g:
                excerpt, basis = _clip(g[1]), "benchmark guidance text"
        out.append({"title": e["title"], "source_url": url, "service": e.get("service"), "tier": e.get("tier"), "source": e.get("source"),
                    "retrieved": retrieved, "excerpt": excerpt or None, "excerpt_basis": basis})
    if not out:
        notes.append("No best-practice entry matches; nothing is cited rather than guessed.")
    if not fetch:
        notes.append("Fetching is off: excerpts come from the local cache and benchmark guidance only.")
    return {"query": _clip(query, 120), "citations": out, "outcome": outcome or None, "fetched": bool(fetch), "notes": notes}
