"""ZIA Insights traffic data: read-only, paced, Stop-able wrappers over the
Z-Insights GraphQL API (POST /zins/graphql) as the installed
zscaler-sdk-python exposes it (`client.zins`, zscaler/zins/*.py).

What the SDK can ask (verified in zscaler-sdk-python 1.9.44, each query
takes start_time / end_time in epoch milliseconds and returns entries of
{name, total} unless said otherwise):

  WEB_TRAFFIC        location, no_grouping (action_filter ALLOW | BLOCK,
                     dlp_engine_filter), protocols, threat_super_categories,
                     threat_class; traffic_unit TRANSACTIONS | BYTES
  SHADOW_IT          apps (application, category, risk index, sanctioned
                     state, bytes up / down, authenticated users, ...),
                     shadow_it_summary (totals and group_by_* breakdowns)
  SAAS_SECURITY      casb_app
  ZERO_TRUST_FIREWALL action, location_firewall, network_service
  CYBER_SECURITY     incidents (categorize_by THREAT_CATEGORY_ID, APP_ID,
                     USER_ID, TIME, SRC_COUNTRY), cyber_security_location
  IOT                device_stats (no time window)

What it cannot ask, so this module never pretends to (UNAVAILABLE):
traffic by URL category, traffic per user, traffic per policy rule (no
query returns a rule or policy name for traffic) and traffic to one host
or domain (the only filters match the grouped entry's own name).

Only aggregated numbers are read. User names appear only
in the "users with the most security incidents" table, which is shown on
screen and is never logged or exported (`exportable` drops it).
Z-Insights needs a OneAPI (ZIdentity) API client: the SDK refuses the
classic ZIA API sign-in for it.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable, Dict, Iterable, List, Mapping, Optional, Tuple

DAY_MS = 86_400_000
HOUR_MS = 3_600_000
# Time window rules. The SDK states only that start_time and end_time are
# epoch milliseconds (GraphQL Long!). The 92-day ceiling is the Insights
# console's own limit on a custom time frame and the 180-day look-back is
# ZIA's six-month log retention; neither is stated by the SDK, so both are
# this app's assumption about what the API accepts, applied before asking.
MAX_WINDOW_DAYS = 92
MAX_LOOKBACK_DAYS = 180
MIN_WINDOW_MS = 15 * 60 * 1000
FUTURE_SKEW_MS = 5 * 60 * 1000
PRESETS = {"24h": DAY_MS, "7d": 7 * DAY_MS, "14d": 14 * DAY_MS, "30d": 30 * DAY_MS, "90d": 90 * DAY_MS}
PRESET_LABELS = {"24h": "last 24 hours", "7d": "last 7 days", "14d": "last 14 days", "30d": "last 30 days", "90d": "last 90 days"}
TRAFFIC_UNITS = ("TRANSACTIONS", "BYTES")   # zins WebTrafficUnits
ACTIONS = (("ALLOW", "Allowed"), ("BLOCK", "Blocked"))   # zins ActionStatus: only these two exist

ROW_LIMIT = 50        # entries asked per table
USER_LIMIT = 10       # users shown
PACE_SECONDS = 1.0    # pause between two Insights queries (no published Z-Insights rate limit in the SDK)
NAME_MAX = 200

STOPPED_REASON = ("You clicked Stop before the Insights read finished, so it was abandoned: nothing more was asked "
                  "and no partial result is shown. Nothing is ever written by this page.")
OUT_OF_SCOPE = ("ZIA Insights is not in scope: on the Scope page tick ZIA Insights (traffic data), then run it again. "
                "Nothing was read.")
LEGACY_REFUSED = ("ZIA Insights needs a OneAPI (ZIdentity) API client: the classic ZIA API sign-in cannot read "
                  "Z-Insights (the Zscaler SDK refuses it). Sign in with a OneAPI client and run it again. Nothing was read.")

UNAVAILABLE: Dict[str, str] = {
    "url_category": ("Web traffic by URL category: the SDK's Z-Insights web traffic queries group by location, protocol, "
                     "threat super category and threat class only; none groups by URL category."),
    "user_traffic": ("Web traffic per user: no Z-Insights query in the SDK groups traffic by user. The users table on this "
                     "page counts security incidents per user (CYBER_SECURITY incidents grouped by USER_ID), not traffic."),
    "rule_hits": ("Traffic per policy rule: no Z-Insights query in the SDK returns a rule or policy name for traffic, so "
                  "rule hit counts (and \"0 hits: unused\") cannot be measured from Insights."),
    "host": ("Traffic to one host or domain: Z-Insights filters match only the grouped entry's own name (a location, "
             "protocol, application or action), never a host or domain."),
    "other_actions": ("Web actions other than allowed and blocked (caution, isolate, ...): the SDK's action filter "
                      "(ActionStatus) has ALLOW and BLOCK only."),
}


class Stopped(Exception):
    """The operator clicked Stop: nothing more is asked."""


class WindowError(ValueError):
    """A time window the API (or this app's assumption about it) does not accept."""


# ── Time windows ────────────────────────────────────────────────────────
def _now_ms() -> int:
    return int(time.time() * 1000)


def validate_window(start_ms: Any, end_ms: Any, now_ms: Optional[int] = None) -> Tuple[int, int]:
    """(start, end) in epoch milliseconds, checked: whole numbers, start
    before end, at least 15 minutes and at most MAX_WINDOW_DAYS long, end
    not in the future, start within MAX_LOOKBACK_DAYS. WindowError in
    plain words otherwise."""
    now = _now_ms() if now_ms is None else int(now_ms)
    try:
        if isinstance(start_ms, bool) or isinstance(end_ms, bool):
            raise TypeError
        s, e = int(start_ms), int(end_ms)
        if s != start_ms or e != end_ms:
            raise TypeError
    except (TypeError, ValueError, OverflowError):   # OverflowError: an infinity
        raise WindowError("The time window must be two times in epoch milliseconds.")
    if s <= 0 or e <= 0:
        raise WindowError("The time window must be two times in epoch milliseconds.")
    if e <= s:
        raise WindowError("The time window ends before it starts: pick an end after the start.")
    if e > now + FUTURE_SKEW_MS:
        raise WindowError("The time window ends in the future: Insights has no data yet for that time.")
    if e - s < MIN_WINDOW_MS:
        raise WindowError("The time window is shorter than 15 minutes: pick a longer one.")
    if e - s > MAX_WINDOW_DAYS * DAY_MS:
        raise WindowError(f"The time window is longer than {MAX_WINDOW_DAYS} days, the longest Insights allows: pick a shorter one.")
    if s < now - MAX_LOOKBACK_DAYS * DAY_MS:
        raise WindowError(f"The time window starts more than {MAX_LOOKBACK_DAYS} days ago, older than Insights keeps: pick a later start.")
    return s, e


def window(preset: str = "", start_ms: Any = None, end_ms: Any = None, now_ms: Optional[int] = None) -> Dict[str, Any]:
    """The window to ask for: a preset ("24h", "7d", "14d", "30d", "90d")
    ending now, else an explicit start and end. Validated (WindowError)."""
    now = _now_ms() if now_ms is None else int(now_ms)
    if start_ms is not None or end_ms is not None:
        s, e = validate_window(start_ms, end_ms, now)
        label = "custom window"
    else:
        key = str(preset or "7d").strip()
        if key not in PRESETS:
            raise WindowError("Unknown time window: pick one of " + ", ".join(PRESET_LABELS.values()) + ", or a custom window.")
        s, e = validate_window(now - PRESETS[key], now, now)
        label = PRESET_LABELS[key]
    return {"start_ms": s, "end_ms": e, "days": round((e - s) / DAY_MS, 2), "label": label}


# ── Defensive parsing ───────────────────────────────────────────────────
def _text(v: Any) -> str:
    s = "" if v is None else str(v)
    return s.replace("\r", " ").replace("\n", " ").strip()[:NAME_MAX]


def _num(v: Any) -> Optional[float]:
    if isinstance(v, bool) or v is None:
        return None
    if isinstance(v, (int, float)):
        return v if v == v and v not in (float("inf"), float("-inf")) else None
    try:
        f = float(str(v).strip())
    except ValueError:
        return None
    return int(f) if f.is_integer() else f


def rows_of(entries: Any, limit: int = ROW_LIMIT) -> List[Dict[str, Any]]:
    """[{name, total}] from Insights entries, defensively: entries that are
    not objects, or carry no number, are skipped; names are trimmed."""
    out: List[Dict[str, Any]] = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, Mapping):
            continue
        total = _num(e.get("total"))
        if total is None:
            continue
        out.append({"name": _text(e.get("name")) or "(unnamed)", "total": total})
        if len(out) >= limit:
            break
    return out


_APP_TEXT = ("application", "application_category", "sanctioned_state")
_APP_NUM = ("risk_index", "computed_risk_index", "data_consumed", "data_uploaded", "data_downloaded", "authenticated_users",
            "unAuthenticated_location_count", "integration", "last_access_time")


def app_rows(entries: Any, limit: int = ROW_LIMIT) -> List[Dict[str, Any]]:
    """Shadow IT apps (SHADOW_IT.apps entries), the fields the page shows."""
    out: List[Dict[str, Any]] = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, Mapping) or not _text(e.get("application")):
            continue
        row = {k: _text(e.get(k)) for k in _APP_TEXT}
        row.update({k: _num(e.get(k)) for k in _APP_NUM})
        out.append(row)
        if len(out) >= limit:
            break
    return out


_SUMMARY_TOTALS = ("total_apps", "total_bytes", "total_upload_bytes", "total_download_bytes")
_SUMMARY_GROUPS = (("group_by_app_cat_for_app", "Applications by category"),
                   ("group_by_app_cat_for_total_bytes", "Bytes by application category"),
                   ("group_by_app_cat_for_user_count", "Users by application category"),
                   ("group_by_risk_index_for_app", "Applications by risk index"),
                   ("group_by_provisioning_status_for_app", "Applications by provisioning status"),
                   ("group_by_access_for_app", "Applications by access"))


def summary_of(raw: Any) -> Dict[str, Any]:
    """SHADOW_IT.shadow_it_summary: the four totals and each group's rows."""
    raw = raw if isinstance(raw, Mapping) else {}
    groups = []
    for key, title in _SUMMARY_GROUPS:
        g = raw.get(key)
        if isinstance(g, Mapping):
            groups.append({"key": key, "title": title, "rows": rows_of(g.get("entries")), "obfuscated": bool(g.get("obfuscated"))})
    return {"totals": {k: _num(raw.get(k)) for k in _SUMMARY_TOTALS}, "groups": groups}


def _dig(body: Any, path: Iterable[str]) -> Any:
    cur = body
    for k in path:
        if not isinstance(cur, Mapping):
            return None
        cur = cur.get(k)
    return cur


def _messages(err: Any) -> Tuple[str, Optional[str]]:
    """(message, classification) of an SDK error, never its headers."""
    msgs = getattr(err, "all_error_messages", None)
    if isinstance(msgs, list) and msgs:
        return "; ".join(_text(m) for m in msgs[:3]), getattr(err, "classification", None)
    return f"{type(err).__name__}: {_text(err)}", None


# ── The queries this page asks ──────────────────────────────────────────
# key, title, (domain, field) in the GraphQL answer, how to call it, how to read it.
def _web_action(zins, s, e, unit, action):
    return zins.web_traffic.get_no_grouping(start_time=s, end_time=e, traffic_unit=unit, action_filter=action)


SECTIONS: List[Dict[str, Any]] = [
    {"key": "web_action", "title": "Web traffic by action", "source": "WEB_TRAFFIC.no_grouping (action_filter)"},
    {"key": "web_location", "title": "Web traffic by location", "source": "WEB_TRAFFIC.location",
     "path": ("WEB_TRAFFIC", "location"),
     "call": lambda z, s, e, u: z.web_traffic.get_traffic_by_location(start_time=s, end_time=e, traffic_unit=u, limit=ROW_LIMIT)},
    {"key": "cloud_apps", "title": "Cloud applications (Shadow IT)", "source": "SHADOW_IT.apps", "parse": app_rows,
     "path": ("SHADOW_IT", "apps"),
     "call": lambda z, s, e, u: z.shadow_it.get_apps(start_time=s, end_time=e, limit=ROW_LIMIT)},
    {"key": "shadow_summary", "title": "Shadow IT summary", "source": "SHADOW_IT.shadow_it_summary", "summary": True,
     "path": ("SHADOW_IT", "shadow_it_summary"),
     "call": lambda z, s, e, u: z.shadow_it.get_shadow_it_summary(start_time=s, end_time=e)},
    {"key": "casb_apps", "title": "SaaS security (CASB) by application", "source": "SAAS_SECURITY.casb_app",
     "path": ("SAAS_SECURITY", "casb_app"),
     "call": lambda z, s, e, u: z.saas_security.get_casb_app_report(start_time=s, end_time=e, limit=ROW_LIMIT)},
    {"key": "fw_action", "title": "Firewall traffic by action", "source": "ZERO_TRUST_FIREWALL.action",
     "path": ("ZERO_TRUST_FIREWALL", "action"),
     "call": lambda z, s, e, u: z.firewall.get_traffic_by_action(start_time=s, end_time=e, limit=ROW_LIMIT)},
    {"key": "top_users", "title": "Users with the most security incidents", "source": "CYBER_SECURITY.incidents (USER_ID)",
     "users": True, "path": ("CYBER_SECURITY", "incidents"),
     "call": lambda z, s, e, u: z.cyber_security.get_incidents(start_time=s, end_time=e, categorize_by=["USER_ID"], limit=USER_LIMIT)},
]
SECTION_KEYS = tuple(x["key"] for x in SECTIONS)
USER_SECTIONS = tuple(x["key"] for x in SECTIONS if x.get("users"))


def _ask(fn: Callable[[], Any], path: Tuple[str, str], scrub: Callable[[str], str], *, summary: bool = False,
         parse: Callable[[Any], Any] = rows_of) -> Dict[str, Any]:
    """One query through the SDK, read defensively. Returns {status:
    ok | empty | partial | error, rows | summary, error, classification,
    obfuscated}. A GraphQL error that still carries data is `partial`:
    the data is kept and the error is said."""
    try:
        res = fn()
    except Exception as ex:  # noqa: BLE001 — a failed query is reported, never crashes the read
        return {"status": "error", "error": scrub(f"{type(ex).__name__}: {_text(ex)}"), "classification": None}
    if not isinstance(res, tuple) or len(res) != 3:
        return {"status": "error", "error": "The SDK gave an answer of an unexpected shape.", "classification": None}
    data, resp, err = res
    out: Dict[str, Any] = {"classification": None, "error": None}
    body = None
    try:
        body = resp.get_body() if resp is not None and callable(getattr(resp, "get_body", None)) else None
    except Exception:  # noqa: BLE001
        body = None
    container = _dig(body, ("data",) + tuple(path))
    if isinstance(container, Mapping) and "obfuscated" in container:
        out["obfuscated"] = bool(container.get("obfuscated"))
    if err is not None:
        msg, cls = _messages(err)
        out["error"] = scrub(msg)
        out["classification"] = _text(cls) or None
        partial = _dig(getattr(err, "data", None), path)
        if isinstance(partial, Mapping) and isinstance(partial.get("obfuscated"), bool):
            out["obfuscated"] = partial["obfuscated"]
        if summary and isinstance(partial, Mapping) and partial:
            out.update(status="partial", summary=summary_of(partial))
        elif not summary and isinstance(partial, Mapping) and isinstance(partial.get("entries"), list):
            out.update(status="partial", rows=parse(partial.get("entries")))
        else:
            out["status"] = "error"
        return out
    if summary:
        if not isinstance(data, Mapping):
            return dict(out, status="error", error="The answer had no Shadow IT summary.")
        sm = summary_of(data)
        empty = not any(v for v in sm["totals"].values()) and not any(g["rows"] for g in sm["groups"])
        return dict(out, status="empty" if empty else "ok", summary=sm)
    if data is None:
        return dict(out, status="error", error="The answer had no entries.")
    rows = parse(data)
    return dict(out, status="ok" if rows else "empty", rows=rows)


def _hint(sec: Dict[str, Any]) -> Optional[str]:
    cls = (sec.get("classification") or "").upper()
    if cls in ("UNAUTHORIZED", "FORBIDDEN") or "403" in str(sec.get("error") or "") or "401" in str(sec.get("error") or ""):
        return "The API client's role may not include Insights: grant Z-Insights read access in ZIdentity and run again."
    if cls in ("BAD_REQUEST", "VALIDATION_ERROR"):
        return "Insights refused the question (often a time window it does not accept): try a shorter or more recent window."
    err = str(sec.get("error") or "").lower()
    if cls in ("TOO_MANY_REQUESTS", "RATE_LIMITED", "THROTTLED") or re.search(r"\b429\b|rate.?limit|too many requests", err):
        return "Insights is limiting how fast it is asked (rate limit): wait a minute and run it again; this page already asks one query at a time."
    return None


def read(client: Any, start_ms: int, end_ms: int, *, traffic_unit: str = "TRANSACTIONS", include_users: bool = True,
         log: Optional[Callable[[str], None]] = None, cancel: Any = None, scrub: Optional[Callable[[str], str]] = None,
         pace: Optional[float] = None, sleep: Optional[Callable[[float], Any]] = None,
         now_ms: Optional[int] = None) -> Dict[str, Any]:
    """Ask Insights for every section of the Traffic insights page.
    `client` is a OneAPI SDK client (its `.zins`) or the ZInsService
    itself. Queries run one at a time, `pace` seconds apart; `cancel` (a
    threading.Event or a callable) is checked before every query and
    during the pause, and once set Stopped is raised: no partial result.
    One failing section never fails the others. Logs say what is asked,
    never a user name, a secret or a row."""
    from data_flow import stop_requested
    _log = log or (lambda m: None)
    _scrub = scrub or (lambda s: s)
    s, e = validate_window(start_ms, end_ms, now_ms)
    unit = str(traffic_unit or "TRANSACTIONS").upper()
    if unit not in TRAFFIC_UNITS:
        raise WindowError("Traffic unit must be transactions or bytes.")
    gap = PACE_SECONDS if pace is None else max(0.0, float(pace))
    zins = getattr(client, "zins", None) if not hasattr(client, "web_traffic") else client
    if zins is None:
        raise RuntimeError("This sign-in has no Z-Insights client (it needs a OneAPI API client).")

    asked = {"n": 0}

    def _check() -> None:
        if stop_requested(cancel):
            _log("STOPPED — you clicked Stop; the Insights read was abandoned and nothing more was asked.")
            raise Stopped(STOPPED_REASON)

    def _turn() -> None:
        _check()
        if asked["n"] and gap:
            wait = getattr(cancel, "wait", None)
            if callable(wait):
                wait(gap)
            else:
                (sleep or time.sleep)(gap)
            _check()
        asked["n"] += 1

    sections: Dict[str, Any] = {}
    for spec in SECTIONS:
        key = spec["key"]
        if spec.get("users") and not include_users:
            sections[key] = {"key": key, "title": spec["title"], "source": spec["source"], "status": "skipped",
                             "note": "Not asked: Top users was switched off for this run.", "rows": []}
            continue
        if key == "web_action":
            rows, errs, statuses, obf = [], [], [], None
            for code, label in (("", "All web traffic"),) + ACTIONS:
                _turn()
                _log(f"Asking Insights for {label.lower()} ({unit.lower()})…")
                r = _ask(lambda c=code: _web_action(zins, s, e, unit, c or None), ("WEB_TRAFFIC", "no_grouping"), _scrub)
                statuses.append(r["status"])
                obf = obf or r.get("obfuscated")
                if r.get("error"):
                    errs.append(f"{label}: {r['error']}")
                if r["status"] in ("ok", "partial", "empty"):
                    rows.append({"name": label, "action": code or "ANY", "total": sum(x["total"] for x in r.get("rows") or [])})
            status = ("error" if all(x == "error" for x in statuses) else "partial" if any(x in ("error", "partial") for x in statuses)
                      else "empty" if all(x == "empty" for x in statuses) else "ok")
            sec = {"status": status, "rows": rows, "error": "; ".join(errs) or None, "classification": None, "obfuscated": obf,
                   "note": UNAVAILABLE["other_actions"]}
        else:
            _turn()
            _log(f"Asking Insights for {spec['title'].lower()}" + (" (shown on screen only)…" if spec.get("users") else "…"))
            sec = _ask(lambda sp=spec: sp["call"](zins, s, e, unit), spec["path"], _scrub, summary=bool(spec.get("summary")),
                       parse=spec.get("parse") or (lambda x: rows_of(x, USER_LIMIT if spec.get("users") else ROW_LIMIT)))
            if spec.get("users"):
                sec["note"] = ("Security incidents per user (CYBER_SECURITY), not traffic. Shown on this screen only: "
                               "never logged, kept in a report or exported.")
        sec.update(key=key, title=spec["title"], source=spec["source"])
        if sec.get("error"):
            h = _hint(sec)
            if h:
                sec["hint"] = h
        n = len(sec.get("rows") or []) if "rows" in sec else sum(len(g["rows"]) for g in (sec.get("summary") or {}).get("groups", []))
        _log(f"  {spec['title']}: " + {"ok": f"{n} row{'s' if n != 1 else ''}", "empty": "no data in this window",
                                        "partial": f"partial answer ({n} rows) with an error", "error": "could not be read"}.get(sec["status"], sec["status"]))
        sections[key] = sec
    _check()
    errors = [k for k, v in sections.items() if v.get("status") == "error"]
    status = "error" if errors and len(errors) == len([v for v in sections.values() if v.get("status") != "skipped"]) else (
        "partial" if errors or any(v.get("status") == "partial" for v in sections.values()) else "ok")
    return {"status": status, "window": {"start_ms": s, "end_ms": e, "days": round((e - s) / DAY_MS, 2)}, "traffic_unit": unit,
            "sections": sections, "order": list(SECTION_KEYS), "queries": asked["n"],
            "unavailable": [{"key": k, "detail": v} for k, v in UNAVAILABLE.items() if k != "other_actions"],
            "rule_hits": {"available": False, "reason": UNAVAILABLE["rule_hits"]}}


# ── Exports: never the users ────────────────────────────────────────────
def exportable(result: Mapping[str, Any]) -> Dict[str, Any]:
    """The result without any per-user section (user names are shown on
    screen only), safe to keep as a report and to export."""
    out = {k: v for k, v in dict(result).items() if k not in ("sections", "logs")}
    secs = {}
    for k, v in (result.get("sections") or {}).items():
        if k in USER_SECTIONS:
            secs[k] = {"key": k, "title": v.get("title"), "status": "omitted",
                       "note": "Per-user rows are shown on screen only and are never exported."}
        else:
            secs[k] = v
    out["sections"] = secs
    return out


CSV_COLUMNS = ["section", "name", "total", "unit", "category", "risk_index", "sanctioned_state", "data_uploaded",
               "data_downloaded", "authenticated_users", "status"]


def to_csv(result: Mapping[str, Any]) -> str:
    """Every table as CSV rows (csv_safe: a tenant-controlled name is never
    a formula), per-user rows left out."""
    import csv_safe
    import io
    res = exportable(result)
    unit = str(res.get("traffic_unit") or "").lower()
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(CSV_COLUMNS)
    for key in res.get("order") or SECTION_KEYS:
        sec = (res.get("sections") or {}).get(key) or {}
        title = sec.get("title") or key
        st = sec.get("status") or ""
        if key in USER_SECTIONS:
            continue
        if sec.get("summary"):
            sm = sec["summary"]
            for k, v in (sm.get("totals") or {}).items():
                w.writerow([title, k, v, "bytes" if "bytes" in k else "apps", "", "", "", "", "", "", st])
            for g in sm.get("groups") or []:
                for r in g.get("rows") or []:
                    w.writerow([f"{title}: {g.get('title')}", r.get("name"), r.get("total"), "", "", "", "", "", "", "", st])
            continue
        for r in sec.get("rows") or []:
            if key == "cloud_apps":
                w.writerow([title, r.get("application"), r.get("data_consumed"), "bytes", r.get("application_category"), r.get("risk_index"),
                            r.get("sanctioned_state"), r.get("data_uploaded"), r.get("data_downloaded"), r.get("authenticated_users"), st])
            else:
                w.writerow([title, r.get("name"), r.get("total"), unit if key.startswith("web_") else "", "", "", "", "", "", "", st])
        if not sec.get("rows"):
            w.writerow([title, "", "", "", "", "", "", "", "", "", st or "empty"])
    return buf.getvalue()


# ── Rule hit evidence ───────────────────────────────────────────────────
def rule_hits(rows: Any) -> Dict[Tuple[str, str], int]:
    """{(policy, rule_name): hits} from rows shaped {policy, rule (or
    rule_name / name), hits (or total)}. Pure. Rows without a rule name or
    a whole, non-negative count are skipped; the same rule twice sums.

    No Z-Insights query in the SDK groups traffic by rule, so the app
    never feeds Insights data in here (`read` says rule_hits is not
    available); it is the one place any rule-grouped source (a log
    export, a future query) turns into evidence."""
    out: Dict[Tuple[str, str], int] = {}
    for r in rows if isinstance(rows, (list, tuple)) else []:
        if not isinstance(r, Mapping):
            continue
        name = _text(r.get("rule") if r.get("rule") is not None else r.get("rule_name") if r.get("rule_name") is not None else r.get("name"))
        if not name:
            continue
        n = _num(r.get("hits") if r.get("hits") is not None else r.get("total"))
        if n is None or n < 0 or int(n) != n:
            continue
        key = (_text(r.get("policy")), name)
        out[key] = out.get(key, 0) + int(n)
    return out


def describe_rule_hits(hits: Optional[Mapping[Tuple[str, str], int]], policy: str, rule: str, days: float) -> str:
    """One sentence for a rule: "matched N times in 7 days", "0 hits in 7
    days: unused" only when `hits` is a measured map, and "not measured"
    when there is none (None): no data is never read as no hits."""
    span = f"{days:g} day{'s' if days != 1 else ''}"
    if hits is None:
        return f"Hits not measured: no source that counts traffic per rule was read for the last {span}."
    n = int(hits.get((_text(policy), _text(rule)), 0))
    if n == 0:
        return f"0 hits in {span}: unused."
    return f"Matched {n:,} time{'s' if n != 1 else ''} in {span}."


# ── The Path analyzer's "Recent traffic to this destination" ───────────
def recent_traffic_for_host(host: str, in_scope: bool) -> Dict[str, Any]:
    """What the Path analyzer can say about recent traffic to `host`.
    No tenant call: Z-Insights cannot filter by host or domain, so when
    Insights is in scope this says it is not available and why."""
    if not in_scope:
        return {"in_scope": False, "available": False, "host": _text(host),
                "reason": "ZIA Insights is not in scope on the Scope page, so recent traffic was not asked for."}
    return {"in_scope": True, "available": False, "host": _text(host), "days": 7,
            "reason": UNAVAILABLE["host"] + " Recent traffic to this destination by action is therefore not shown; "
                                            "the Traffic insights page has tenant-wide traffic by action, location and application."}
