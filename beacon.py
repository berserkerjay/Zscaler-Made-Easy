"""Beacon: what changed upstream since the last run — the Zscaler SDK, the
Zscaler API and the Terraform provider — and, when asked, whether the
tenant still answers every endpoint the app reads.

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
    every endpoint the app's checks and features read, recording what
    each answered (OK, 403, 404, 429, timeout, error) and how many items.
  - Terraform: the zscaler/zia provider pin against the registry's
    latest, attribute drift against the provider's schema and docs, and
    the provider's changelog head.

Each snapshot is kept (the last 30) in beacon_state.json in the same
per-user cache folder zscaler_update_check uses, and compared with the
previous one: versions that moved, drift that is new or cleared, doc
pages whose content changed, tenant endpoints whose answer changed. The
comparison is in plain words.

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
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

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
    return [s for s in snaps if isinstance(s, dict)] if isinstance(snaps, list) else []


def save_history(snapshots: List[Dict[str, Any]], path: Optional[str] = None) -> str:
    """Keep the newest HISTORY_KEEP snapshots; written to a temporary file
    and moved into place so a crash never leaves half a file."""
    p = path or state_path()
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    tmp = f"{p}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"version": 1, "snapshots": snapshots[-HISTORY_KEEP:]}, f, indent=1)
    os.replace(tmp, p)
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


def _page_entry(source: Dict[str, Any], text: Optional[str], err: str) -> Dict[str, Any]:
    """One help-center page, hashed exactly as zscaler_update_check hashes it."""
    import zscaler_update_check as zu
    e: Dict[str, Any] = {"key": source["key"], "name": source["name"], "url": source["url"],
                         "importance": source.get("importance", "medium"), "hash": None, "ok": False, "reason": ""}
    if not text:
        e["reason"] = err or "no answer"
        return e
    body = text.encode("utf-8", "ignore")
    q = zu.page_quality(body, 200)
    e["hash"] = zu._hash(zu._strip_volatile(body))
    e["ok"] = bool(q.get("ok"))
    e["reason"] = q.get("reason") or ""
    e["title"] = q.get("title") or ""
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
            text, err = fetch(s["url"])
        except Exception as e:  # noqa: BLE001 — one page never stops the others
            text, err = None, f"{type(e).__name__}: {str(e)[:150]}"
        out.append(_page_entry(s, text, err))
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
    is watched without a list to keep in step."""
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
                 on_progress: Optional[Callable[[int, int], None]] = None) -> Dict[str, Any]:
    """GET every endpoint the app reads, one about every `gap` seconds.
    A ZPA path without a ZPA customer id, and anything but ZIA on the
    classic ZIA API sign-in, is skipped (the client would answer for it
    without asking the tenant)."""
    if str(method or "").upper() != "GET":
        raise ValueError(f"Beacon's tenant watch only sends GET; {method!r} was refused.")
    import permissions
    ro = ReadOnlyClient(client)
    eps = endpoints if endpoints is not None else tenant_endpoints()
    legacy, customer_id = bool(ro.legacy), str(ro.customer_id or "")
    started = clock()
    rows: List[Dict[str, Any]] = []
    stopped = None
    sent = 0
    for i, (ep, mods) in enumerate(eps.items()):
        base = {"endpoint": ep, "used_by": list(mods), "permission": permissions.permission_for_endpoint(ep).get("permission")}
        if legacy and not ep.startswith("/zia/"):
            rows.append({**base, "status": "skipped", "http": None, "items": None, "error": "the classic ZIA API sign-in reaches ZIA only"})
            continue
        if ep.startswith("/zpa/") and not customer_id:
            rows.append({**base, "status": "skipped", "http": None, "items": None, "error": "no ZPA customer id was given"})
            continue
        if stopped or clock() - started > budget:
            stopped = stopped or f"the {int(budget)}-second budget ran out"
            rows.append({**base, "status": "not probed", "http": None, "items": None})
            continue
        if sent:
            sleep(gap)
        rows.append({**base, **probe_endpoint(ro, ep, "GET")})
        sent += 1
        if on_progress:
            on_progress(i + 1, len(eps))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    return {"endpoints": rows, "counts": counts, "requests": sent, "stopped": stopped,
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


def diff(cur: Dict[str, Any], history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """What changed between `cur` and the snapshots before it. Upstream
    changes are measured against the latest earlier run of the same kind
    (online against online, offline against offline); tenant endpoints
    against the latest earlier watch of the same tenant."""
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
        # Help-center pages
        prev_pages = {p["key"]: p for p in (up.get("api") or {}).get("pages") or []}
        for p in (cur.get("api") or {}).get("pages") or []:
            q = prev_pages.get(p["key"])
            if not q:
                continue
            if p.get("hash") and q.get("hash") and p["hash"] != q["hash"]:
                add("api", "doc_changed", f"{p['name']} changed since the last run: {p['url']}", key=p["key"], url=p["url"])
            elif q.get("ok") and p.get("hash") and not p.get("ok"):
                add("api", "doc_gone", f"{p['name']} no longer reads as a page ({p.get('reason')}): {p['url']}", key=p["key"], url=p["url"])

    tb = None
    ct = cur.get("tenant")
    if ct:
        tb = _baseline(history, lambda s: bool(s.get("tenant")) and (s.get("tenant") or {}).get("label") == ct.get("label") and s.get("id") != cur.get("id"))
        if tb:
            prev_eps = {e["endpoint"]: e for e in (tb.get("tenant") or {}).get("endpoints") or []}
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
    if not up and not tb:
        summary.append("First run of this kind: nothing to compare with yet. This run is the baseline for the next one.")
    elif not changes:
        when = (up or tb or {}).get("at", "")
        summary.append(f"Nothing changed since the last run ({when}).")
    else:
        n = {k: sum(1 for c in changes if c["watcher"] == k) for k in ("sdk", "api", "terraform", "tenant")}
        parts = [f"{v} {({'sdk': 'SDK', 'api': 'API', 'terraform': 'Terraform', 'tenant': 'tenant endpoint'})[k]} change{'s' if v != 1 else ''}"
                 for k, v in n.items() if v]
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
        save: bool = True, probe: Optional[Callable[..., Dict[str, Any]]] = None) -> Dict[str, Any]:
    """One Beacon snapshot: the three upstream watchers, the tenant API
    watch when a client is given, and what changed since the last run.
    Saved to the history unless `save` is False."""
    started = time.time()
    snap: Dict[str, Any] = {"id": f"beacon-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{os.urandom(2).hex()}", "at": _now(),
                            "online": bool(online), "trigger": trigger}
    watchers, error = run_upstream(online, fetch, upstream)
    snap.update(watchers)
    if error:
        snap["error"] = error
    snap["tenant"] = None
    if tenant_client is not None:
        try:
            t = (probe or probe_tenant)(tenant_client)
        except PermissionError:
            raise
        except Exception as e:  # noqa: BLE001
            t = {"endpoints": [], "counts": {}, "requests": 0, "stopped": f"{type(e).__name__}: {str(e)[:200]}", "method": "GET"}
        t["label"] = tenant_label or "tenant"
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
                     "tenant": (s.get("tenant") or {}).get("label"), "drift": len(s.get("drift") or []),
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
