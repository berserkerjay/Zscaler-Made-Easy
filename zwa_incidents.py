"""Workflow Automation (ZWA) DLP incidents in depth: metadata only.

Three read-only views and the planning half of one write, shared by the
Detection health page, the Bulk changes operation in ops_zwa.py, the
assessment checks (zscaler_full_checks.ZWA_*) and snapshots:

  drilldown(client, id)    one incident: its details, what triggered it
                           (rule, engine and dictionary names with match
                           counts), its change history and the tickets it
                           generated. METADATA ONLY: the evidence (the
                           content that matched) is never fetched, and the
                           user, the file name, the client IP and the
                           metadata file link are withheld (counted, not
                           listed).
  audit_log(client, days)  the Workflow Automation admin audit log: who did
                           what to which resource, newest first.
  open_incidents(...)      the open incidents of a window, optionally of one
                           rule or destination host: what the "close as false
                           positive" operation may close.

What is verified against zscaler-sdk-python 1.11.3 (zscaler/zwa) and what is
assumed is listed in VERIFIED and ASSUMED; the page shows the assumptions.
Nothing here writes to the tenant.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

LogFn = Optional[Callable[[str], None]]

VERIFIED = (
    "client.zwa.dlp_incidents.get_incident_details(id) GET /zwa/dlp/v1/incidents/{id} (IncidentDLPDetails).",
    "client.zwa.dlp_incidents.get_incident_triggers(id) GET /zwa/dlp/v1/incidents/{id}/triggers (IncidentTrigger: a free-form dict).",
    "client.zwa.dlp_incidents.change_history(id) GET /zwa/dlp/v1/incidents/{id}/change-history (ChangeHistory.change_history: a list).",
    "client.zwa.dlp_incidents.get_generated_tickets(id) GET /zwa/dlp/v1/incidents/{id}/tickets (GeneratedTickets).",
    "client.zwa.dlp_incidents.dlp_incident_search(query_params, fields, time_range) POST /zwa/dlp/v1/incidents/search.",
    "client.zwa.audit_logs.audit_logs(query_params, fields, time_range) POST /zwa/dlp/v1/customer/audit (AuditLogs.logs: action, "
    "module, resource).",
    "Writes (ops_zwa.py): incident_close(id, resolution_label, resolution_code='FALSE_POSITIVE', notes) POST .../incidents/{id}/close, "
    "assign_labels(id, labels) POST .../labels, incident_notes(id, notes) POST .../notes.",
    "get_incident_evidence and get_incident_transactions exist in the SDK; this app never calls them.",
)
ASSUMED = (
    "The audit log entry's time and admin are read from the raw answer under time, timestamp or createdAt and admin, adminName or "
    "userName: the SDK's Logs model carries only action, module and resource.",
    "The trigger answer has no fixed shape in the SDK; only names with a match count are kept from it, every other value is dropped.",
    "Workflow Automation has no API to reopen a closed incident: the Undo of a closure records the reversal (a label and a note) and "
    "the reopen itself is a step in the Workflow Automation portal.",
    "An incident is open when its status is not CLOSED or RESOLVED (case-insensitive).",
)

ID_RE = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,79}\Z")
MAX_HISTORY = 50
MAX_TRIGGERS = 60
MAX_TICKETS = 20
MAX_LABELS = 20
TEXT_MAX = 200
AUDIT_MAX_DAYS = 90
AUDIT_PAGE_SIZE = 100
AUDIT_MAX_PAGES = 10
CLOSED = {"CLOSED", "RESOLVED"}
_EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
# Fields of an incident that are withheld from every view (content, identity,
# where it came from): the drill-down says they exist, never what they hold.
WITHHELD = ("evidence (the content that matched: never fetched)", "user", "file name", "client IP address", "metadata file link",
            "note text")


class Unavailable(Exception):
    """The Workflow Automation API is not on this client."""


def clean_id(raw: Any) -> str:
    """An incident id as the SDK puts it in the URL path, or ValueError.
    Letters, digits, '-', '_', '.' and ':' only (no '/', '?', '#', '..')."""
    s = str(raw or "").strip()
    if not ID_RE.match(s) or ".." in s:
        raise ValueError("An incident id has 1 to 80 letters, digits, '-', '_', '.' or ':' (for example 1-152-DFZG-17410647793298599936).")
    return s


def text(v: Any, n: int = TEXT_MAX) -> str:
    """Tenant text made safe to show: control characters removed, e-mail
    addresses and IPv4 addresses masked, length capped."""
    t = _CONTROL.sub(" ", str(v if v is not None else ""))
    t = _EMAIL.sub("[e-mail withheld]", t)
    t = _IPV4.sub("[IP withheld]", t)
    return t[:n]


def name(v: Any, n: int = 120) -> str:
    """An admin's sign-in name as the audit log and the assigned admin carry
    it: control characters removed, length capped (an admin is not personal
    data of the people the incidents are about, so it is shown)."""
    return _CONTROL.sub(" ", str(v if v is not None else ""))[:n]


def _plain(obj: Any) -> Any:
    if obj is None:
        return None
    if hasattr(obj, "as_dict"):
        try:
            return obj.as_dict()
        except Exception:  # noqa: BLE001
            return {}
    return obj


def _g(d: Any, *keys: str, default: Any = None) -> Any:
    """The first of `keys` (camelCase or snake_case) present in dict `d`."""
    if not isinstance(d, dict):
        return default
    for k in keys:
        for kk in (k, re.sub(r"(?<!^)(?=[A-Z])", "_", k).lower()):
            if kk in d and d[kk] not in (None, ""):
                return d[kk]
    return default


def _whole(v: Any) -> int:
    try:
        n = int(float(v))
    except (TypeError, ValueError):
        return 0
    return max(0, min(n, 10**9))


def api(client: Any) -> Any:
    """client.zwa.dlp_incidents, or Unavailable."""
    try:
        zwa = getattr(client, "zwa", None)
        dlp = getattr(zwa, "dlp_incidents", None) if zwa is not None else None
    except Exception:  # noqa: BLE001 — the legacy client refuses the property
        dlp = None
    if dlp is None:
        raise Unavailable("The Workflow Automation API is reached only through a OneAPI (ZIdentity) API client with Workflow Automation "
                          "access; this sign-in has none.")
    return dlp


def audit_api(client: Any) -> Any:
    try:
        zwa = getattr(client, "zwa", None)
        a = getattr(zwa, "audit_logs", None) if zwa is not None else None
    except Exception:  # noqa: BLE001
        a = None
    if a is None:
        raise Unavailable("The Workflow Automation audit log is reached only through a OneAPI (ZIdentity) API client.")
    return a


def _call(fn: Callable[[], Any]) -> Tuple[Any, Any, Optional[str]]:
    try:
        ret = fn()
    except Exception as e:  # noqa: BLE001 — one read never stops the rest
        return None, None, f"{type(e).__name__}: {str(e)[:200]}"
    if isinstance(ret, tuple) and len(ret) == 3:
        data, resp, err = ret
        return data, resp, (str(err)[:200] if err else None)
    return ret, None, None


def _first(data: Any) -> Any:
    if isinstance(data, list):
        return _plain(data[0]) if data else None
    return _plain(data)


# ── one incident ─────────────────────────────────────────────────────────
def summarize_details(d: Any) -> Dict[str, Any]:
    """The incident's metadata as the page shows it. Content, identity and
    origin are withheld; what was withheld is said, not shown."""
    d = d if isinstance(d, dict) else {}
    mp = _g(d, "matchingPolicies", default={}) or {}
    names = lambda key: [text(_g(x, "name"), 120) for x in (_g(mp, key, default=[]) or []) if isinstance(x, dict) and _g(x, "name")][:MAX_TRIGGERS]  # noqa: E731
    dicts = [{"name": text(_g(x, "name"), 120), "matches": _whole(_g(x, "matchCount", default=0))}
             for x in (_g(mp, "dictionaries", default=[]) or []) if isinstance(x, dict) and _g(x, "name")][:MAX_TRIGGERS]
    app = _g(d, "applicationInfo", default={}) or {}
    content = _g(d, "contentInfo", default={}) or {}
    user = _g(d, "userInfo", default={}) or {}
    labels = [{"key": text(_g(x, "key"), 60), "value": text(_g(x, "value"), 120)}
              for x in (_g(d, "labels", default=[]) or []) if isinstance(x, dict)][:MAX_LABELS]
    actions = _g(d, "sourceActions", default=[]) or []
    return {
        "id": text(_g(d, "internalId", "id"), 80),
        "status": text(_g(d, "status"), 40), "resolution": text(_g(d, "resolution"), 80), "closed_code": text(_g(d, "closedCode"), 60),
        "severity": text(_g(d, "severity"), 30), "priority": text(_g(d, "priority"), 30),
        "channel": text(_g(d, "sourceType"), 40), "sub_type": text(_g(d, "sourceSubType"), 40),
        "integration": text(_g(d, "integrationType"), 40),
        "actions": [text(a, 40) for a in (actions if isinstance(actions, list) else [actions])][:10],
        "match_count": _whole(_g(d, "matchCount", default=0)),
        "created_at": text(_g(d, "createdAt"), 40), "updated_at": text(_g(d, "lastUpdatedAt"), 40),
        "first_seen": text(_g(d, "sourceFirstObservedAt"), 40), "last_seen": text(_g(d, "sourceLastObservedAt"), 40),
        "assigned_admin": name(_g(d, "assignedAdmin")),
        "rules": names("rules"), "engines": names("engines"), "dictionaries": dicts,
        "application": text(_g(app, "name", "hostnameOrApplication"), 120), "category": text(_g(app, "category"), 80),
        "file_type": text(_g(content, "fileType"), 40),
        "labels": labels, "tickets": len(_g(d, "dlpIncidentTickets", default=[]) or []),
        "notes": len(_g(d, "notes", default=[]) or []),
        "user_present": bool(user), "department_present": bool(_g(user, "department")),
        "open": str(_g(d, "status") or "").upper() not in CLOSED,
    }


def summarize_triggers(trig: Any) -> List[Dict[str, Any]]:
    """What triggered the incident: names with a match count, from an answer
    of no fixed shape. Only a dict carrying a name and a count is kept; every
    other value (which could quote the content) is dropped."""
    out: List[Dict[str, Any]] = []

    def walk(v: Any, kind: str, depth: int) -> None:
        if depth > 6 or len(out) >= MAX_TRIGGERS:
            return
        if isinstance(v, dict):
            name = _g(v, "name", "ruleName", "engineName", "dictionaryName")
            count = _g(v, "matchCount", "count", "nameMatchCount")
            if name is not None and count is not None:
                out.append({"kind": kind or "match", "name": text(name, 120), "matches": _whole(count)})
            for k, x in v.items():
                if isinstance(x, (dict, list)):
                    walk(x, str(k)[:30] if str(k).isidentifier() else kind, depth + 1)
        elif isinstance(v, list):
            for x in v[:200]:
                walk(x, kind, depth + 1)

    data = _plain(trig)
    if isinstance(data, dict) and isinstance(data.get("triggers"), dict):
        data = data["triggers"]
    walk(data, "", 0)
    return out


def summarize_history(hist: Any) -> List[str]:
    data = _first(hist)
    items = _g(data, "changeHistory", default=None) if isinstance(data, dict) else data
    if not isinstance(items, list):
        return []
    out = []
    for x in items[:MAX_HISTORY]:
        if isinstance(x, dict):
            x = " ".join(f"{k}: {v}" for k, v in list(x.items())[:6] if not isinstance(v, (dict, list)))
        out.append(text(x))
    return out


def summarize_tickets(tk: Any) -> List[Dict[str, Any]]:
    data = _first(tk)
    items = _g(data, "tickets", default=None) if isinstance(data, dict) else data
    if isinstance(data, dict) and items is None and _g(data, "ticketId"):
        items = [data]
    out = []
    for t in (items if isinstance(items, list) else [])[:MAX_TICKETS]:
        t = _plain(t)
        if isinstance(t, dict):
            info = _plain(_g(t, "ticketInfo", default={})) or {}   # common.DLPIncidentTickets: ticketInfo {ticketId, ticketUrl, state}
            out.append({"system": text(_g(t, "ticketingSystemName", "ticketType"), 60), "ticket": text(_g(t, "ticketId") or _g(info, "ticketId"), 80),
                        "project": text(_g(t, "projectName"), 80), "state": text(_g(t, "state", "status") or _g(info, "state"), 40)})
    return out


def details(client: Any, incident_id: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """(the incident's summary, error): one get_incident_details call."""
    dlp = api(client)
    iid = clean_id(incident_id)
    data, _resp, err = _call(lambda: dlp.get_incident_details(iid))
    if err:
        return None, err
    d = _first(data)
    return (summarize_details(d) if isinstance(d, dict) and d else None), (None if d else "not found")


def drilldown(client: Any, incident_id: str, log: LogFn = None) -> Dict[str, Any]:
    """One incident's metadata: details, triggers, change history and the
    tickets it generated, each with its own error. Never fetches evidence."""
    say = log or (lambda m: None)
    iid = clean_id(incident_id)
    dlp = api(client)
    say(f"Reading incident {iid}: details, triggers, change history and tickets (metadata only; the evidence is never fetched)…")
    out: Dict[str, Any] = {"id": iid, "details": None, "triggers": [], "history": [], "tickets": [], "errors": {},
                           "withheld": list(WITHHELD), "verified": list(VERIFIED), "assumed": list(ASSUMED)}
    data, _r, err = _call(lambda: dlp.get_incident_details(iid))
    if err:
        out["errors"]["details"] = text(err)
    else:
        d = _first(data)
        out["details"] = summarize_details(d) if isinstance(d, dict) else None
    data, _r, err = _call(lambda: dlp.get_incident_triggers(iid))
    if err:
        out["errors"]["triggers"] = text(err)
    else:
        out["triggers"] = summarize_triggers(data)
    data, _r, err = _call(lambda: dlp.change_history(iid))
    if err:
        out["errors"]["history"] = text(err)
    else:
        out["history"] = summarize_history(data)
    data, _r, err = _call(lambda: dlp.get_generated_tickets(iid))
    if err:
        out["errors"]["tickets"] = text(err)
    else:
        out["tickets"] = summarize_tickets(data)
    return out


# ── the audit log ────────────────────────────────────────────────────────
def _raw_body(resp: Any) -> Any:
    getter = getattr(resp, "get_body", None)
    if not callable(getter):
        return None
    try:
        body = getter()
        if isinstance(body, (bytes, str)):
            import json
            body = json.loads(body) if body else None
        return body
    except Exception:  # noqa: BLE001
        return None


def summarize_audit_entry(e: Any) -> Dict[str, Any]:
    e = _plain(e) if not isinstance(e, dict) else e
    act = _g(e, "action", default="")
    if isinstance(act, dict):
        act = _g(act, "action", default="")
    return {"time": text(_g(e, "time", "timestamp", "createdAt", "eventTime"), 40), "admin": name(_g(e, "admin", "adminName", "userName")),
            "action": text(act, 80), "module": text(_g(e, "module"), 80), "resource": text(_g(e, "resource"), 160)}


def audit_log(client: Any, days: int = 7, log: LogFn = None, *, now: Optional[datetime] = None,
              max_pages: int = AUDIT_MAX_PAGES) -> Dict[str, Any]:
    """The Workflow Automation admin audit log of the last `days` (1 to
    AUDIT_MAX_DAYS): {entries, pages, truncated, errors}. Read-only (the
    API asks for the search with a POST that changes nothing)."""
    say = log or (lambda m: None)
    a = audit_api(client)
    days = max(1, min(int(days or 7), AUDIT_MAX_DAYS))
    end = now or datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    tr = {"startTime": start.strftime("%Y-%m-%dT%H:%M:%S.000Z"), "endTime": end.strftime("%Y-%m-%dT%H:%M:%S.000Z")}
    entries: List[Dict[str, Any]] = []
    errors: List[str] = []
    truncated = False
    say(f"Reading the Workflow Automation audit log for the last {days} day(s)…")
    for page in range(1, max_pages + 1):
        data, resp, err = _call(lambda: a.audit_logs(query_params={"page": page, "page_size": AUDIT_PAGE_SIZE}, fields=[], time_range=tr))
        if err:
            errors.append(f"page {page}: {text(err)}")
            break
        body = _raw_body(resp)
        rows = body.get("logs") if isinstance(body, dict) and isinstance(body.get("logs"), list) else None
        if rows is None:
            p = _plain(data)
            rows = (p or {}).get("logs") if isinstance(p, dict) else []
        rows = [r for r in (rows or []) if isinstance(r, dict)]
        entries.extend(summarize_audit_entry(r) for r in rows)
        if len(rows) < AUDIT_PAGE_SIZE:
            break
        if page == max_pages:
            truncated = True
    entries.sort(key=lambda x: x["time"], reverse=True)
    admins = len({x["admin"] for x in entries if x["admin"]})
    say(f"Workflow Automation audit log: {len(entries)} entr{'y' if len(entries) == 1 else 'ies'} by {admins} admin(s).")
    return {"days": days, "entries": entries, "count": len(entries), "admins": admins, "truncated": truncated, "errors": errors,
            "verified": list(VERIFIED), "assumed": list(ASSUMED)}


# ── what a bulk close may close ──────────────────────────────────────────
def open_incidents(client: Any, *, days: int = 30, rule: str = "", host: str = "", limit: int = 100, log: LogFn = None,
                   now: Optional[datetime] = None) -> Tuple[List[Dict[str, Any]], List[str]]:
    """The open incidents created in the last `days`, optionally only those
    of `rule` (a rule name) or destination `host`: [{id, rule names, host,
    created_at}], newest first, at most `limit`. Errors returned, never raised."""
    import detection_health
    incs, errors = detection_health.fetch_incidents(client, days=max(1, min(int(days or 30), 180)), log=log, now=now)
    want_rule = str(rule or "").strip().lower()
    want_host = str(host or "").strip().lower()
    out = []
    for i in incs:
        if str(i.get("status") or "").upper() in CLOSED or not i.get("id"):
            continue
        if want_rule and want_rule not in {r.lower() for r in i.get("rules") or []}:
            continue
        if want_host and str(i.get("host") or "").lower() != want_host:
            continue
        out.append({"id": str(i["id"])[:80], "rules": [text(r, 120) for r in (i.get("rules") or [])][:5], "host": text(i.get("host"), 120),
                    "created_at": i.get("created_at") or "", "status": text(i.get("status"), 40)})
    out.sort(key=lambda x: x["created_at"] or "", reverse=True)
    return out[:max(1, int(limit))], errors


def is_open(summary: Optional[Dict[str, Any]]) -> bool:
    return bool(summary) and str(summary.get("status") or "").upper() not in CLOSED


def counts(items: Iterable[Dict[str, Any]]) -> Dict[str, int]:
    rows = list(items)
    return {"incidents": len(rows), "open": sum(1 for x in rows if is_open(x))}
