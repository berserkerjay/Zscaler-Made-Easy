"""Beacon: what changed upstream since the last run — the Zscaler SDK, the
Zscaler API and the Terraform provider — and, when asked, whether the
tenant still answers the endpoints that are in scope on the Scope page.

Three watchers make one snapshot:

  - SDK: the installed zscaler-sdk-python against PyPI's latest release
    and prerelease, whether the latest changes any module the app calls
    (upstream_check diffs them), the SDK's changelog head, and the SDK
    drift findings.
  - API: the 2.x SDK's machine-readable ZIA service definition against
    the endpoints the app writes to (upstream_check), whether Zscaler's
    API reference answers, and the help-center / OneAPI pages
    zscaler_update_check watches, hashed the same way. Optionally, the
    tenant API watch: a GET-only probe, about one request a second, of
    the endpoints that belong to what is in scope on the Scope page (the
    ticked scopes and the channels marked Zscaler; beacon_scope.py picks
    them), recording what each answered (OK, 403, 404, 429, timeout,
    error) and how many items. Every GET counts against the tenant's
    ZIA API rate limit, so nothing out of scope is ever read.
  - Terraform: the zscaler/zia provider pin against the registry's
    latest, attribute drift against the provider's schema and docs, and
    the provider's changelog head.

Each snapshot is kept (the last 30) in beacon_state.json in the same
per-user cache folder zscaler_update_check uses, and compared with the
previous one: versions that moved, drift that is new or cleared, doc
pages whose content changed, tenant endpoints whose answer changed (only
the endpoints read both times; a changed scope is said). The comparison
is in plain words.

Nothing here writes anywhere but that state file. Every upstream fetch
goes through zscaler_update_check._safe_get's host allowlist (via
upstream_check.default_fetch); the tenant probe can only GET — any other
method is refused before a request is built. Offline, the watchers say
what they could not read instead of failing.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

ROOT = os.path.dirname(os.path.abspath(__file__))
HISTORY_KEEP = 30
STATE_FILE = "beacon_state.json"
PROBE_GAP_SECONDS = 1.0          # about one request a second against the tenant
PROBE_BUDGET_SECONDS = 900       # a tenant that answers very slowly stops the probe here

# The modules whose GET calls make up the tenant API watch: the
# assessment's checks and the features that read the tenant. Not
# discover_endpoints.py (guesses tried on purpose to find paths) and not
# scope_permissions.py (a catalogue of what a scope could need).
TENANT_WATCH_MODULES = (
    "dlp_assessment_full_auto.py", "zscaler_full_checks.py", "zscaler_genai_checks.py", "zscaler_automation_checks.py",
    "zscaler_zdx_checks.py", "zscaler_zidentity_checks.py", "zscaler_rbac_checks.py", "zcc_evaluation.py",
    "bypass_report.py", "data_flow.py", "ssl_flow.py", "dlp_efficacy.py", "rule_migrator.py", "path_analyzer.py",
)
# A literal short endpoint handed to a read: cl.get("/zia/x"), _g(cl, "/zia/x", …),
# _one / _list (zcc_evaluation) and _fetch_rules (data_flow, ssl_flow).
_GET_CALL = re.compile(r"""(?:\.get|\b_g|\b_one|\b_list|\b_fetch_rules)\(\s*(?:[a-z_]+,\s*)?["'](/(?:zia|zcc|zpa|zdx|zid)/[A-Za-z0-9_/\-]*)["']""")

Fetch = Callable[[str], Tuple[Optional[str], str]]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# State: the last HISTORY_KEEP snapshots
# ---------------------------------------------------------------------------

def state_path() -> str:
    """DLP_CHECK_BEACON_STATE, else beacon_state.json beside
    zscaler_update_check's cache (%LOCALAPPDATA%\\ZscalerAssessment on
    Windows, ~/Library/Caches/ZscalerAssessment on macOS,
    ~/.cache/zscaler_assessment on Linux)."""
    env = os.environ.get("DLP_CHECK_BEACON_STATE")
    if env:
        return env
    from zscaler_update_check import _cache_path
    return os.path.join(os.path.dirname(_cache_path()), STATE_FILE)


def load_history(path: Optional[str] = None) -> List[Dict[str, Any]]:
    """The kept snapshots, oldest first. A missing or unreadable file is an empty history."""
    try:
        with open(path or state_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    snaps = data.get("snapshots") if isinstance(data, dict) else None
    kept = [s for s in snaps if isinstance(s, dict)] if isinstance(snaps, list) else []
    clean = _scrub(kept)
    if clean != kept:
        # A classic-API tenant's admin login, kept in a label by an older
        # version: rewritten as 'classic API (cloud)' on disk too, so the
        # login is gone from the history and the next watch of the same
        # tenant still finds its baseline (user rule 3).
        try:
            save_history(clean, path)
        except OSError:
            pass
    return clean


def _scrub(value: Any) -> Any:
    """`value` (a snapshot, a list of them, or any part) with every
    classic-API admin login label replaced (tenant_auth.scrub_classic_login)."""
    import tenant_auth
    if isinstance(value, str):
        return tenant_auth.scrub_classic_login(value)
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()}
    return value


def save_history(snapshots: List[Dict[str, Any]], path: Optional[str] = None) -> str:
    """Keep the newest HISTORY_KEEP snapshots; written to a temporary file
    and moved into place so a crash never leaves half a file."""
    p = path or state_path()
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    tmp = f"{p}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "snapshots": _scrub(snapshots[-HISTORY_KEEP:])}, f, indent=1)
    # On Windows the move fails while another thread (GET /api/beacon's
    # load_history) has the file open: retry briefly, so a run's snapshot is
    # not lost to a poll that happened to read at the same moment.
    for attempt in range(20):
        try:
            os.replace(tmp, p)
            break
        except PermissionError:
            if attempt == 19:
                raise
            time.sleep(0.05)
    return p


# ---------------------------------------------------------------------------
# The upstream watchers (SDK, API, Terraform)
# ---------------------------------------------------------------------------

# upstream_check's findings from the 2.x service definition read as API
# findings: they are about the ZIA API's operations, not the 1.x SDK.
_SERVICE_DEF = re.compile(r"service definition|in its request body", re.I)


def _split_findings(findings: Iterable[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {"sdk": [], "api": [], "terraform": []}
    for f in findings or []:
        area = f.get("area")
        if area == "api" or (area == "sdk" and _SERVICE_DEF.search(f.get("text") or "")):
            out["api"].append(f)
        elif area == "terraform":
            out["terraform"].append(f)
        else:   # sdk, and app (a pack rule that could not become an SDK payload)
            out["sdk"].append(f)
    return out


def _sdk_watcher(rep: Dict[str, Any], online: bool, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    sdk = rep.get("sdk") or {}
    pypi = sdk.get("pypi") or {}
    pre = sdk.get("prerelease") or {}
    w: Dict[str, Any] = {"status": "ok", "reason": "", "installed": (sdk.get("installed") or {}).get("version"),
                         "latest": pypi.get("latest"), "latest_uploaded": pypi.get("latest_uploaded"),
                         "prerelease": pypi.get("latest_prerelease"), "prerelease_uploaded": pypi.get("prerelease_uploaded"),
                         "latest_diff": sdk.get("latest_diff"), "changelog_head": sdk.get("changelog_head"), "findings": findings}
    if pre and not pre.get("operations") and "changed" in pre:
        w["prerelease_diff"] = {"version": pre.get("version"), "changed": pre.get("changed") or [], "missing": pre.get("missing") or []}
    if not online:
        w["status"], w["reason"] = "offline", "Offline run: only the installed SDK was read (PyPI and the SDK's changelog were not)."
    elif pypi.get("error"):
        w["status"], w["reason"] = "unreachable", f"PyPI could not be read: {pypi['error']}"
    return w


def _page_entry(source: Dict[str, Any], fetch: Fetch) -> Dict[str, Any]:
    """One help-center page, read and hashed exactly as zscaler_update_check
    reads and hashes it (a help.zscaler.com article through its fetch-data
    answer, since the page itself is an empty browser shell)."""
    import zscaler_update_check as zu
    e: Dict[str, Any] = {"key": source["key"], "name": source["name"], "url": source["url"],
                         "importance": source.get("importance", "medium"), "hash": None, "ok": False, "reason": ""}

    def get(url: str):
        text, err = fetch(url)
        if text:
            return text.encode("utf-8", "ignore"), 200, ""
        # Keep an HTTP status the fetcher reports ("HTTP 404"): the site
        # answered. Status 0 is a network error (read_page then stops).
        m = re.match(r"HTTP (\d{3})\b", err or "")
        return None, int(m.group(1)) if m else (0 if err else 200), err or "no answer"
    content, q, _code, err = zu.read_page(source["url"], get)
    if q is None:
        e["reason"] = err or "no answer"
        return e
    e["hash"] = zu._hash(content or b"")
    e["ok"] = bool(q.get("ok"))
    e["reason"] = q.get("reason") or ""
    e["title"] = q.get("title") or ""
    e["basis"] = q.get("basis") or "page"  # a hash is only compared with one taken the same way
    if q.get("article_status") is not None:
        e["article_status"] = q["article_status"]
    return e


def watch_pages(fetch: Fetch) -> List[Dict[str, Any]]:
    """The help-center and OneAPI pages zscaler_update_check watches
    (its html_hash sources). Beacon keeps its own hashes, so running it
    never changes what the Zscaler SDK & docs updates tab reports."""
    import zscaler_update_check as zu
    out = []
    for s in zu.SOURCES:
        if s.get("type") != "html_hash":
            continue
        try:
            out.append(_page_entry(s, fetch))
        except Exception as e:  # noqa: BLE001 — one page never stops the others
            out.append({"key": s["key"], "name": s["name"], "url": s["url"], "importance": s.get("importance", "medium"),
                        "hash": None, "ok": False, "reason": f"{type(e).__name__}: {str(e)[:150]}"})
    return out


def _api_watcher(rep: Dict[str, Any], online: bool, findings: List[Dict[str, Any]], pages: List[Dict[str, Any]]) -> Dict[str, Any]:
    pre = (rep.get("sdk") or {}).get("prerelease") or {}
    sdef = None
    if pre.get("operations") is not None:
        sdef = {"version": pre.get("version"), "api_version": pre.get("api_version"), "operations": pre.get("operations"),
                "endpoints": pre.get("endpoints") or {}}
    ref = rep.get("api_reference") or {}
    w: Dict[str, Any] = {"status": "ok", "reason": "", "service_definition": sdef, "reference": ref or None,
                         "pages": pages, "findings": findings}
    if not online:
        w["status"], w["reason"] = "offline", "Offline run: the service definition, the API reference and the help-center pages were not read."
    elif pages and all(not p.get("hash") for p in pages) and not ref.get("reachable"):
        w["status"], w["reason"] = "unreachable", "Neither the API reference nor any help-center page could be read (proxy or TLS inspection?)."
    return w


def _terraform_watcher(rep: Dict[str, Any], online: bool, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    tf = rep.get("terraform") or {}
    reg = tf.get("registry") or {}
    pinned, latest = tf.get("pinned"), reg.get("latest")
    allows = None
    if pinned and latest:
        import upstream_check
        allows = upstream_check.constraint_allows(pinned, latest)
    undocumented = {r: d.get("undocumented") for r, d in (tf.get("docs") or {}).items() if isinstance(d, dict) and d.get("undocumented")}
    w: Dict[str, Any] = {"status": "ok", "reason": "", "pinned": pinned, "latest": latest, "published": reg.get("published"),
                         "pin_allows_latest": allows, "changelog_head": tf.get("changelog_head"),
                         "schema": {k: v for k, v in (tf.get("schema") or {}).items() if k in ("available", "error")} or None,
                         "docs_undocumented": undocumented, "findings": findings}
    if not online:
        w["status"], w["reason"] = "offline", "Offline run: only the committed workspaces' pin was read (the registry, schema and docs were not)."
    elif reg.get("error"):
        w["status"], w["reason"] = "unreachable", f"The Terraform registry could not be read: {reg['error']}"
    return w


def run_upstream(online: bool, fetch: Optional[Fetch] = None, upstream: Optional[Callable[..., Dict[str, Any]]] = None
                 ) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """The three upstream watchers from one upstream_check run (and the
    help-center pages when online). Returns (watchers, error)."""
    import upstream_check
    fetch = fetch or upstream_check.default_fetch
    upstream = upstream or upstream_check.run
    work = tempfile.mkdtemp(prefix="beacon_sdk_")
    try:
        rep = upstream(offline=not online, fetch=fetch, workdir=work)
        error = None
    except Exception as e:  # noqa: BLE001 — a failed check is reported, never raised
        rep, error = {}, f"the upstream check failed: {type(e).__name__}: {str(e)[:200]}"
    finally:
        shutil.rmtree(work, ignore_errors=True)   # the downloaded SDK wheels
    split = _split_findings(rep.get("findings") or [])
    pages = watch_pages(fetch) if online else []
    watchers = {"sdk": _sdk_watcher(rep, online, split["sdk"]), "api": _api_watcher(rep, online, split["api"], pages),
                "terraform": _terraform_watcher(rep, online, split["terraform"])}
    if error:
        for w in watchers.values():
            w["status"], w["reason"] = "error", error
    return watchers, error


# ---------------------------------------------------------------------------
# The tenant API watch (GET only)
# ---------------------------------------------------------------------------

def tenant_endpoints(root: str = ROOT) -> Dict[str, List[str]]:
    """endpoint -> the modules that read it, from the literal GET calls in
    TENANT_WATCH_MODULES. Read from the code each time, so a new check
    is watched without a list to keep in step. This is everything the
    watch could read; beacon_scope.select narrows it to what is in scope,
    and only that is ever read."""
    out: Dict[str, List[str]] = {}
    for name in TENANT_WATCH_MODULES:
        try:
            src = open(os.path.join(root, name), encoding="utf-8").read()
        except OSError:
            continue
        for m in _GET_CALL.finditer(src):
            mods = out.setdefault(m.group(1), [])
            if name not in mods:
                mods.append(name)
    return dict(sorted(out.items()))


class ReadOnlyClient:
    """The tenant client with everything but GET taken away. `get` passes
    through; post, put, patch, delete, request and every other attribute
    raise, so no code path in the watch can write to the tenant."""
    _READABLE = ("legacy", "customer_id", "requests_made")

    def __init__(self, client: Any):
        object.__setattr__(self, "_client", client)

    def get(self, ep: str, p: Optional[Dict[str, Any]] = None):
        return self._client.get(ep, p)

    def __getattr__(self, name: str):
        if name in self._READABLE:
            return getattr(self._client, name, None)
        raise PermissionError(f"Beacon's tenant watch only reads (GET); '{name}' is not available to it.")

    def __setattr__(self, name: str, value: Any):
        raise PermissionError("Beacon's tenant watch client cannot be changed.")


def _items(data: Any) -> Optional[int]:
    if isinstance(data, list):
        return len(data)
    if isinstance(data, dict):
        for k in ("list", "items", "data", "content", "rules"):
            if isinstance(data.get(k), list):
                return len(data[k])
        return 1
    return None


def _status_of(data: Any, code: int) -> str:
    if code in (200, 204):
        return "OK"
    if code in (403, 404, 429):
        return str(code)
    err = str(data.get("error") if isinstance(data, dict) else data or "").lower()
    if code == 0 and "timeout" in err:
        return "timeout"
    return "error"


def probe_endpoint(client: Any, ep: str, method: str = "GET") -> Dict[str, Any]:
    """One read of one endpoint. Anything but GET is refused here, before
    the client is touched."""
    if str(method or "").upper() != "GET":
        raise ValueError(f"Beacon's tenant watch only sends GET; {method!r} was refused for {ep}.")
    ro = client if isinstance(client, ReadOnlyClient) else ReadOnlyClient(client)
    try:
        data, code = ro.get(ep)
    except PermissionError:
        raise
    except Exception as e:  # noqa: BLE001
        return {"endpoint": ep, "status": "error", "http": 0, "items": None, "error": f"{type(e).__name__}: {str(e)[:150]}"}
    code = int(code or 0)
    st = _status_of(data, code)
    e: Dict[str, Any] = {"endpoint": ep, "status": st, "http": code, "items": _items(data) if st == "OK" else None}
    if st != "OK" and isinstance(data, dict) and data.get("error"):
        e["error"] = str(data["error"])[:200]
    return e


def probe_tenant(client: Any, endpoints: Optional[Dict[str, List[str]]] = None, *, method: str = "GET",
                 gap: float = PROBE_GAP_SECONDS, budget: float = PROBE_BUDGET_SECONDS,
                 sleep: Callable[[float], None] = time.sleep, clock: Callable[[], float] = time.time,
                 on_progress: Optional[Callable[[int, int], None]] = None,
                 stop: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """GET each of `endpoints` (the ones in scope, from
    beacon_scope.select), one about every `gap` seconds. There is no
    default: without a list nothing is read. A ZPA path without a ZPA
    customer id, and anything but ZIA on the classic ZIA API sign-in, is
    skipped (the client would answer for it without asking the tenant).

    One endpoint can cost more than one GET (an endpoint the client lists
    in parts, a path with candidate spellings). When the client has a
    request pacer (dlp_assessment_full_auto.Client._limiter), its gap is
    raised to `gap` for the watch, so every HTTP GET is paced; otherwise
    the wait after an endpoint grows with the GETs it took. `requests` is
    the HTTP GETs the client sent when it counts them (requests_made).

    `stop` (the operator's Stop) is checked before every endpoint and,
    through the client's stop_check and zia_rate.stopping_on, inside a
    request that pages or waits out ZIA's rate limit: once it says so
    nothing more is sent and every endpoint left is "not probed"."""
    if str(method or "").upper() != "GET":
        raise ValueError(f"Beacon's tenant watch only sends GET; {method!r} was refused.")
    if endpoints is None:
        import beacon_scope
        raise ValueError(beacon_scope.NOTHING_IN_SCOPE)
    import permissions
    ro = ReadOnlyClient(client)
    eps = endpoints
    legacy, customer_id = bool(ro.legacy), str(ro.customer_id or "")
    limiter = getattr(client, "_limiter", None)
    old_gap = getattr(limiter, "min_gap", None)
    paced = isinstance(old_gap, (int, float)) and not isinstance(old_gap, bool)
    if paced:
        limiter.min_gap = max(float(old_gap), float(gap))
    should_stop = _stop_hook(stop)
    bound, before = False, None
    if should_stop is not None:
        try:
            before = getattr(client, "stop_check", None)
            client.stop_check = should_stop
            bound = True
        except Exception:  # noqa: BLE001 — a client that takes no hook is still stopped between endpoints
            pass
    import zia_rate
    try:
        with zia_rate.stopping_on(should_stop):
            return _probe_rows(ro, eps, legacy, customer_id, paced, gap, budget, sleep, clock, on_progress, permissions, should_stop)
    finally:
        if paced:
            limiter.min_gap = old_gap
        if bound:
            try:
                client.stop_check = before
            except Exception:  # noqa: BLE001
                pass


STOPPED_BY_OPERATOR = "you clicked Stop; nothing more was read"


def _stop_hook(stop: Optional[Callable[[], bool]]) -> Optional[Callable[[], bool]]:
    """`stop` as a hook that never raises (a broken hook never stops a watch by itself)."""
    if stop is None:
        return None

    def should_stop() -> bool:
        try:
            return bool(stop())
        except Exception:  # noqa: BLE001
            return False
    return should_stop


def _gets(ro: "ReadOnlyClient") -> Optional[int]:
    n = ro.requests_made
    return n if isinstance(n, int) and not isinstance(n, bool) else None


def _probe_rows(ro: "ReadOnlyClient", eps: Dict[str, List[str]], legacy: bool, customer_id: str, paced: bool, gap: float,
                budget: float, sleep: Callable[[float], None], clock: Callable[[], float],
                on_progress: Optional[Callable[[int, int], None]], permissions: Any,
                should_stop: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    started = clock()
    rows: List[Dict[str, Any]] = []
    stopped = None
    sent = 0
    first = _gets(ro)
    last_cost = 1
    for i, (ep, mods) in enumerate(eps.items()):
        base = {"endpoint": ep, "used_by": list(mods), "permission": permissions.permission_for_endpoint(ep).get("permission")}
        if legacy and not ep.startswith("/zia/"):
            rows.append({**base, "status": "skipped", "http": None, "items": None, "error": "the classic ZIA API sign-in reaches ZIA only"})
            continue
        if ep.startswith("/zpa/") and not customer_id:
            rows.append({**base, "status": "skipped", "http": None, "items": None, "error": "no ZPA customer id was given"})
            continue
        if not stopped and should_stop is not None and should_stop():
            stopped = STOPPED_BY_OPERATOR
        if stopped or clock() - started > budget:
            stopped = stopped or f"the {int(budget)}-second budget ran out"
            rows.append({**base, "status": "not probed", "http": None, "items": None})
            continue
        if sent and not paced:
            sleep(gap * max(1, last_cost))
            if should_stop is not None and should_stop():
                stopped = STOPPED_BY_OPERATOR
                rows.append({**base, "status": "not probed", "http": None, "items": None})
                continue
        before = _gets(ro)
        row = probe_endpoint(ro, ep, "GET")
        if should_stop is not None and should_stop() and row.get("status") not in ("OK", "403", "404", "429"):
            # Cut short by Stop (a paged read or a rate-limit wait ended
            # by it): not an answer from the tenant.
            stopped = STOPPED_BY_OPERATOR
            row = {"endpoint": ep, "status": "not probed", "http": None, "items": None}
        rows.append({**base, **row})
        after = _gets(ro)
        last_cost = (after - before) if before is not None and after is not None else 1
        sent += 1
        if on_progress:
            on_progress(i + 1, len(eps))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    last = _gets(ro)
    requests = (last - first) if first is not None and last is not None else sent
    return {"endpoints": rows, "counts": counts, "requests": requests, "stopped": stopped,
            "seconds": round(clock() - started, 1), "method": "GET"}


# ---------------------------------------------------------------------------
# What changed since the last run
# ---------------------------------------------------------------------------

_HTTP_WORDS = {"OK": "OK", "403": "403 (not permitted)", "404": "404 (not found)", "429": "429 (rate limited)",
               "timeout": "a timeout", "error": "an error"}


def _answer_words(e: Dict[str, Any]) -> str:
    words = _HTTP_WORDS.get(e.get("status"), str(e.get("status")))
    return f"{words} (HTTP {e['http']})" if e.get("status") == "error" and e.get("http") else words


def _baseline(history: List[Dict[str, Any]], pred: Callable[[Dict[str, Any]], bool]) -> Optional[Dict[str, Any]]:
    for s in reversed(history):
        if pred(s):
            return s
    return None


def _drift_set(w: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {f"{f.get('area')}|{f.get('text')}": f for f in (w or {}).get("findings") or [] if f.get("level") == "drift"}


def _usable(w: Optional[Dict[str, Any]]) -> bool:
    return bool(w) and w.get("status") in ("ok", "offline")


def _page_state(p: Dict[str, Any]) -> str:
    """"ok", "unreadable" (the help center answered a status other than
    200/404/410, e.g. 403 "Help Article in Maintenance": the page is still
    there) or "gone" (404/410, or no readable content). The same split as
    the page table's chip in static/beacon.js and the Updates tab."""
    if p.get("ok"):
        return "ok"
    st = p.get("article_status")
    return "unreadable" if st is not None and st not in (200, 404, 410) else "gone"


def _answered(e: Dict[str, Any]) -> bool:
    """The tenant answered this read over HTTP (any status code). A
    transport error or a timeout (HTTP 0) is no answer."""
    if e.get("status") in ("skipped", "not probed"):
        return False
    try:
        return int(e.get("http") or 0) > 0
    except (TypeError, ValueError):
        return False


def _watch_read(t: Optional[Dict[str, Any]]) -> bool:
    """Whether a tenant watch read anything: not one that failed (the
    probe raised), skipped or left every endpoint unread, or where not one
    GET got an HTTP answer (the tenant could not be reached)."""
    if not t or t.get("failed"):
        return False
    return any(_answered(e) for e in t.get("endpoints") or [])


def _watch_complete(t: Optional[Dict[str, Any]]) -> bool:
    """A watch that read and did not stop before reading everything in scope."""
    return _watch_read(t) and not any(e.get("status") == "not probed" for e in (t or {}).get("endpoints") or [])


def watch_problem(t: Optional[Dict[str, Any]]) -> Optional[Tuple[str, str]]:
    """("error", why) for a tenant watch that read nothing, ("partial", why)
    for one that stopped before reading everything in scope, else None."""
    if not t:
        return None
    rows = t.get("endpoints") or []
    if not _watch_read(t):
        why = t.get("stopped") or ("no endpoint got an HTTP answer (the tenant could not be reached)" if rows else "nothing was read")
        return "error", f"The tenant API watch of {t.get('label') or 'the tenant'} read nothing: {why}."
    unread = sum(1 for e in rows if e.get("status") == "not probed")
    if unread:
        return "partial", (f"The tenant API watch of {t.get('label') or 'the tenant'} stopped early ({t.get('stopped') or 'stopped'}): "
                           f"{unread} of {len(rows)} endpoints in scope were not read.")
    return None


def _scope_set(t: Dict[str, Any], rows: Iterable[str]) -> Set[str]:
    """The endpoints a watch had in scope (what the selection picked),
    else, for a watch from before the scope was kept, the rows it read."""
    sc = t.get("scope") or {}
    return set(sc["read"]) if isinstance(sc.get("read"), list) else set(rows)


def _scope_change(prev: Dict[str, Any], cur: Dict[str, Any], prev_eps: Dict[str, Dict[str, Any]]) -> str:
    """One sentence when the tenant watch had a different scope than the
    last watch of the same tenant (the Scope page changed); only the
    endpoints read both times are compared. The scope is the set of
    endpoints the selection picked, not what happened to be answered and
    not its wording: the same endpoints are the same scope."""
    now = _scope_set(cur, (e["endpoint"] for e in cur.get("endpoints") or []))
    before = _scope_set(prev, prev_eps)
    ps, cs = (prev.get("scope") or {}).get("summary"), (cur.get("scope") or {}).get("summary")
    if now == before:
        return ""
    both, added, gone = len(now & before), len(now - before), len(before - now)
    was = ps or f"{len(before)} endpoints, before the watch followed the Scope page"
    now_words = cs or f"{len(now)} endpoints"
    return (f"The scope changed since the last watch of this tenant (was {was}; now {now_words}): "
            f"only the {both} endpoint{'' if both == 1 else 's'} read both times {'is' if both == 1 else 'are'} compared; "
            f"{added} newly in scope, {gone} no longer read.")


def diff(cur: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What changed between `cur` and the snapshots before it. Upstream
    changes are measured against the latest earlier run of the same kind
    (online against online, offline against offline); tenant endpoints
    against the latest earlier watch of the same tenant, endpoint by
    endpoint for the endpoints both watches read (the scope may differ)."""
    changes: List[Dict[str, Any]] = []

    def add(watcher: str, kind: str, text: str, **extra: Any) -> None:
        changes.append({"watcher": watcher, "kind": kind, "text": text, **extra})

    up = _baseline(history, lambda s: bool(s.get("online")) == bool(cur.get("online")) and s.get("id") != cur.get("id"))
    if up:
        # Versions
        for watcher, field, label in (("sdk", "installed", "The installed zscaler-sdk-python"), ("sdk", "latest", "zscaler-sdk-python's latest release"),
                                      ("sdk", "prerelease", "zscaler-sdk-python's newest prerelease"),
                                      ("terraform", "pinned", "The workspaces' zscaler/zia pin"), ("terraform", "latest", "The zscaler/zia provider's latest version")):
            a, b = (up.get(watcher) or {}).get(field), (cur.get(watcher) or {}).get(field)
            if a and b and a != b:
                add(watcher, "version", f"{label} moved from {a} to {b}.", field=field, before=a, after=b)
        for watcher, label in (("sdk", "The SDK's changelog"), ("terraform", "The provider's changelog")):
            a, b = (up.get(watcher) or {}).get("changelog_head"), (cur.get(watcher) or {}).get("changelog_head")
            if a and b and a != b:
                add(watcher, "changelog", f"{label} has a new top entry: {b} (was {a}).", before=a, after=b)
        a = ((up.get("api") or {}).get("service_definition") or {}).get("api_version")
        b = ((cur.get("api") or {}).get("service_definition") or {}).get("api_version")
        if a and b and a != b:
            add("api", "version", f"The ZIA service definition's apiVersion moved from {a} to {b}.", field="api_version", before=a, after=b)
        # Drift that appeared or cleared
        for watcher in ("sdk", "api", "terraform"):
            pw, cw = up.get(watcher), cur.get(watcher)
            if not (_usable(pw) and _usable(cw)):
                continue
            before, after = _drift_set(pw), _drift_set(cw)
            for k in sorted(after.keys() - before.keys()):
                add(watcher, "drift_new", f"New drift: {after[k]['text']}")
            for k in sorted(before.keys() - after.keys()):
                add(watcher, "drift_cleared", f"Cleared: {before[k]['text']}")
        # Help-center pages. A page is only compared with earlier reads
        # taken the same way at the same address (the first run that reads
        # help.zscaler.com's article instead of its empty shell is a new
        # baseline, not a change on every page), and that were read at all:
        # a run where the page could not be fetched, or was read another way
        # once (an earlier run that read the shell), is
        # skipped, not a baseline that hides the next change.
        earlier = [s for s in reversed(history)
                   if bool(s.get("online")) == bool(cur.get("online")) and s.get("id") != cur.get("id")]
        for p in (cur.get("api") or {}).get("pages") or []:
            if not p.get("hash"):
                continue
            same = [e for s in earlier for e in (s.get("api") or {}).get("pages") or []
                    if e.get("key") == p["key"] and e.get("hash") and e.get("basis", "page") == p.get("basis", "page")
                    and e.get("url") == p.get("url")]
            if not same:
                continue
            q = same[0]
            # Gone first: a page that went away also hashes differently.
            # Said when the page's state differs from the read before it, so
            # a page in maintenance (403, still there: "not readable") that
            # is later removed (404) is still reported gone.
            if not p.get("ok"):
                state = _page_state(p)
                if state != _page_state(q):
                    if state == "unreadable":
                        add("api", "doc_unreadable", f"{p['name']} cannot be read right now ({p.get('reason')}); "
                            f"the page is still there and is read again next run: {p['url']}", key=p["key"], url=p["url"])
                    else:
                        add("api", "doc_gone", f"{p['name']} no longer reads as a page ({p.get('reason')}): {p['url']}", key=p["key"], url=p["url"])
            else:
                # Changed against the last time it was readable: a page back
                # from maintenance (or a 404) with the same text is not a change.
                last_ok = next((e for e in same if e.get("ok")), None)
                if last_ok and last_ok["hash"] != p["hash"]:
                    add("api", "doc_changed", f"{p['name']} changed since the last run: {p['url']}", key=p["key"], url=p["url"])

    tb = None
    ct = cur.get("tenant")
    if ct and not _watch_read(ct):
        rows = ct.get("endpoints") or []
        reason = ct.get("stopped") or ("no endpoint got an HTTP answer; the tenant could not be reached" if rows else "")
        why = f" ({reason})" if reason else ""
        add("tenant", "watch_failed", f"The tenant API watch of {ct.get('label') or 'the tenant'} read nothing{why}: nothing was compared, "
            "and the last watch that read the tenant stays the one to compare with.")
    elif ct:
        same = lambda s: (s.get("tenant") or {}).get("label") == ct.get("label") and s.get("id") != cur.get("id")  # noqa: E731
        # A complete watch is the baseline; one that stopped early only when there is no complete one.
        tb = (_baseline(history, lambda s: _watch_complete(s.get("tenant")) and same(s))
              or _baseline(history, lambda s: _watch_read(s.get("tenant")) and same(s)))
        unread = sum(1 for e in ct.get("endpoints") or [] if e.get("status") == "not probed")
        if unread:
            n = len(ct.get("endpoints") or [])
            add("tenant", "watch_partial", f"{unread} of {n} endpoints in scope were not read: {ct.get('stopped') or 'the watch stopped early'}. "
                "Only the endpoints read are compared, and this watch is not the baseline while a complete one is kept.",
                unread=unread, of=n)
        if tb:
            prev_eps = {e["endpoint"]: e for e in (tb.get("tenant") or {}).get("endpoints") or []}
            sc = _scope_change(tb.get("tenant") or {}, ct, prev_eps)
            if sc:
                add("tenant", "scope_changed", sc)
            for e in ct.get("endpoints") or []:
                q = prev_eps.get(e["endpoint"])
                skip = ("skipped", "not probed")
                if not q or e["status"] in skip or q["status"] in skip or e["status"] == q["status"]:
                    continue
                text = f"{e['endpoint']} answered {_answer_words(q)} last time and {_answer_words(e)} now."
                if e["status"] == "403" and e.get("permission"):
                    text += f" The API client needs {e['permission']}."
                elif e["status"] == "404":
                    text += " The endpoint is gone or moved; the checks that read it will say so."
                add("tenant", "endpoint_status", text, endpoint=e["endpoint"], before=q["status"], after=e["status"],
                    before_http=q.get("http"), after_http=e.get("http"))

    summary = []
    if not up and not tb and not changes:
        summary.append("First run of this kind: nothing to compare with yet. This run is the baseline for the next one.")
    elif not changes:
        when = (up or tb or {}).get("at", "")
        summary.append(f"Nothing changed since the last run ({when}).")
    else:
        kinds = {"scope_changed": "scope", "watch_failed": "failed", "watch_partial": "partial"}
        key = lambda c: kinds.get(c["kind"], c["watcher"])  # noqa: E731
        words = {"sdk": ("SDK change", "SDK changes"), "api": ("API change", "API changes"), "terraform": ("Terraform change", "Terraform changes"),
                 "tenant": ("tenant endpoint change", "tenant endpoint changes"), "scope": ("tenant scope change", "tenant scope changes"),
                 "failed": ("tenant watch that read nothing", "tenant watches that read nothing"),
                 "partial": ("tenant watch that stopped early", "tenant watches that stopped early")}
        n = {k: sum(1 for c in changes if key(c) == k) for k in words}
        parts = [f"{v} {words[k][0 if v == 1 else 1]}" for k, v in n.items() if v]
        summary.append(f"{len(changes)} change{'s' if len(changes) != 1 else ''} since the last run: {', '.join(parts)}.")
        summary.extend(c["text"] for c in changes)
    return {"against": {"upstream": (up or {}).get("id"), "upstream_at": (up or {}).get("at"),
                        "tenant": (tb or {}).get("id"), "tenant_at": (tb or {}).get("at")},
            "first_run": not up and not tb, "changes": changes, "summary": summary}


# ---------------------------------------------------------------------------
# One run
# ---------------------------------------------------------------------------

def headline(snap: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The drift worth a notice bar: one line per current drift finding,
    SDK, API and Terraform, with a key that changes when the set does."""
    out = []
    for watcher in ("sdk", "api", "terraform"):
        for f in (snap.get(watcher) or {}).get("findings") or []:
            if f.get("level") == "drift":
                out.append({"watcher": watcher, "text": f.get("text")})
    return out


def run(online: bool = True, fetch: Optional[Fetch] = None, tenant_client: Any = None, tenant_label: str = "", *,
        upstream: Optional[Callable[..., Dict[str, Any]]] = None, trigger: str = "manual", path: Optional[str] = None,
        save: bool = True, probe: Optional[Callable[..., Dict[str, Any]]] = None,
        tenant_scope: Optional[Dict[str, Any]] = None, stop: Optional[Callable[[], bool]] = None) -> Dict[str, Any]:
    """One Beacon snapshot: the three upstream watchers, the tenant API
    watch when a client is given, and what changed since the last run.
    Saved to the history unless `save` is False.

    The tenant API watch reads only `tenant_scope["endpoints"]` (a
    beacon_scope.select result, with an optional "source"); with a client
    and nothing in scope it refuses (ValueError) before anything is read.
    `stop` (the operator's Stop) ends the watch between endpoints and
    inside a request: what was read is kept as a watch that stopped early."""
    import beacon_scope
    if tenant_client is not None and not (tenant_scope or {}).get("endpoints"):
        raise ValueError(beacon_scope.NOTHING_IN_SCOPE)
    started = time.time()
    snap: Dict[str, Any] = {"id": f"beacon-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.urandom(2).hex()}", "at": _now(),
                            "online": bool(online), "trigger": trigger}
    watchers, error = run_upstream(online, fetch, upstream)
    snap.update(watchers)
    if error:
        snap["error"] = error
    snap["tenant"] = None
    if tenant_client is not None:
        client = tenant_client
        if "channels" in tenant_scope:
            # The backstop the assessment has too: a channel's own configuration
            # whose channel is not on Zscaler is refused without touching the
            # tenant, even when the selection listed it.
            import channel_scope
            client = channel_scope.ScopedClient(
                tenant_client, beacon_scope.declaration({c: "zscaler" for c in tenant_scope.get("channels") or ()}))
        try:
            kw = {"stop": stop} if stop is not None else {}
            t = (probe or probe_tenant)(client, endpoints=tenant_scope["endpoints"], **kw)
        except PermissionError:
            raise
        except Exception as e:  # noqa: BLE001
            t = {"endpoints": [], "counts": {}, "requests": 0, "stopped": f"{type(e).__name__}: {str(e)[:200]}", "method": "GET", "failed": True}
        import tenant_auth
        t["label"] = tenant_auth.scrub_classic_login(tenant_label) or "tenant"   # never a classic-API admin login (user rule 3)
        t["scope"] = beacon_scope.describe(tenant_scope, str(tenant_scope.get("source") or ""))
        snap["tenant"] = t
    snap["drift"] = headline(snap)
    snap["seconds"] = round(time.time() - started, 1)
    history = load_history(path)
    snap["diff"] = diff(snap, history)
    if save:
        try:
            save_history(history + [snap], path)
        except OSError as e:
            snap["save_error"] = f"the history could not be saved: {e}"
    return snap


def history_rows(history: List[Dict[str, Any]], limit: int = HISTORY_KEEP) -> List[Dict[str, Any]]:
    """Newest first, one short line per run."""
    rows = []
    for s in reversed(history[-limit:]):
        d = s.get("diff") or {}
        rows.append({"id": s.get("id"), "at": s.get("at"), "online": s.get("online"), "trigger": s.get("trigger"),
                     "tenant": (s.get("tenant") or {}).get("label"),
                     "tenant_scope": ((s.get("tenant") or {}).get("scope") or {}).get("summary"), "drift": len(s.get("drift") or []),
                     "changes": len(d.get("changes") or []), "summary": (d.get("summary") or [""])[0]})
    return rows


# One run at a time, whoever starts it (the page or the timer).
RUN_LOCK = threading.Lock()


if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(description="Beacon: what changed in the Zscaler SDK, API and Terraform provider since the last run.")
    ap.add_argument("--offline", action="store_true", help="no network: the installed SDK and the committed Terraform only")
    args = ap.parse_args()
    s = run(online=not args.offline, trigger="cli")
    print("\n".join(s["diff"]["summary"]))
