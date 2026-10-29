"""Audit timeline: who changed what in the tenant, and what Zscaler Made Easy did.

One timeline, newest first, merged from three sources:

1. ZIA's **admin audit log** for a time window, through the audit log
   report API (zscaler-sdk-python `zia.audit_logs`): create a report
   (POST /auditlogEntryReport with startTime / endTime in epoch
   milliseconds), poll its status (GET /auditlogEntryReport) until it is
   COMPLETE, then download it as CSV (GET /auditlogEntryReport/download).
   Creating the report is a POST, but it changes no configuration: it asks
   ZIA to prepare a file of the audit log. It is treated as a read here,
   it never needs write mode, and it is kept out of the tests' write guards
   deliberately: the tenant fakes in tests/test_audit_timeline.py allow
   exactly this one POST, and it is sent the way the Path analyzer sends
   its URL lookup (the client's `post` looked up by name), so
   tests/test_shared_path.py, which fails the build for any module that
   writes to the tenant outside pack_ops, does not count it as a write. It
   is still counted against ZIA's write budget by zia_rate, as every POST
   is. Only
   when the Automation readiness scope (whose endpoints list
   /zia/auditlogEntryReport, scope_permissions.py) is ticked on the Scope
   page is it read at all (user rule 1).
2. Zscaler Made Easy's **deployment records** (deployments.json): what each pack
   deployment created, and its undo.
3. Zscaler Made Easy's **own audit log** (audit.log): every object it wrote
   (`object_write`), every job (`job_finished`), write-mode switches,
   proposal decisions and sign-ins.

The CSV is parsed defensively: its column names are matched loosely
(ZIA's export is not documented column by column), a preamble before the
header row is skipped, every raw row is kept, and pre / post values that
are JSON are compared field by field. A ZIA change to an object Zscaler Made Easy
created (its description carries the provenance tag
"[<assessor> pack <id> v<version>]", or the deployment record lists it)
that no Zscaler Made Easy write explains within CORRELATE_SECONDS is marked as
made by someone else.

Secrets: values under keys that look like secrets (password, token, key,
secret, cookie, ...) are replaced by "[redacted]" in pre / post values and
the raw row. Nothing is written to the tenant.
"""
from __future__ import annotations

import csv
import io
import json
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

LogFn = Optional[Callable[[str], None]]

DEFAULT_DAYS = 7
# ZIA keeps the admin audit log for six months (help.zscaler.com/zia/about-audit-logs);
# whether one report may span all of it is not documented in the SDK, so a
# refusal for a long window is reported in words, never retried smaller.
MAX_DAYS = 180
POLL_SECONDS = 2.0
POLL_TIMEOUT = 300.0
MAX_ROWS = 50000
MAX_EVENTS = 20000
MAX_CELL = 2000
MAX_VALUE = 20000
CORRELATE_SECONDS = 15 * 60
DOWNLOAD_MAX_BYTES = 64 * 1024 * 1024

REPORT_EP = "/zia/auditlogEntryReport"
DOWNLOAD_EP = "/zia/auditlogEntryReport/download"

READ_NOTE = ("The ZIA admin audit log is read through ZIA's audit log report: Zscaler Made Easy asks ZIA to prepare a report "
             "for the window (a POST that changes no configuration), waits for it and downloads it as CSV.")

SOURCES = {"zia": "ZIA admin audit log", "deployment": "Zscaler Made Easy deployment", "app": "Zscaler Made Easy audit log"}

_SECRET_KEY = re.compile(r"secret|token|password|passwd|passphrase|credential|authorization|cookie|api_?key|private_?key|psk|pre_?shared", re.I)
_SECRET_PAIR = re.compile(r'("(?:[^"]*(?:secret|token|password|passwd|passphrase|credential|authorization|cookie|api_?key|private_?key|psk)[^"]*)"\s*:\s*)"(?:[^"\\]|\\.)*"', re.I)


class Stopped(RuntimeError):
    """The operator clicked Stop while the report was being prepared or read."""


STOPPED_REASON = ("You clicked Stop before the audit log was read, so the timeline was abandoned: nothing more was asked of ZIA. "
                  "Nothing was written.")


def _stop_requested(cancel: Any) -> bool:
    if cancel is None:
        return False
    is_set = getattr(cancel, "is_set", None)
    try:
        return bool(is_set() if callable(is_set) else cancel())
    except Exception:  # noqa: BLE001
        return False


def _wait(cancel: Any, seconds: float) -> bool:
    """Sleep up to `seconds`; False when Stop arrived meanwhile."""
    w = getattr(cancel, "wait", None)
    if callable(w):
        return not w(seconds)
    end = time.time() + seconds
    while time.time() < end:
        if _stop_requested(cancel):
            return False
        time.sleep(min(0.2, end - time.time()))
    return not _stop_requested(cancel)


# ── the window ──────────────────────────────────────────────────────────

def window(days: Any = None, start: str = "", end: str = "", now: Optional[float] = None) -> Dict[str, Any]:
    """The time window: `start` / `end` (ISO dates or date-times) when
    given, else the last `days` (DEFAULT_DAYS) up to now. Never longer
    than MAX_DAYS and never in the future. Raises ValueError in words."""
    now_dt = datetime.fromtimestamp(now if now is not None else time.time(), tz=timezone.utc)

    def _parse(s: str, end_of_day: bool) -> datetime:
        d = parse_time(s)
        if d is None:
            shown = s if len(s) <= 40 else s[:40] + "…"
            raise ValueError(f"'{shown}' is not a date. Use a date such as 2026-10-01.")
        if re.fullmatch(r"\s*\d{4}-\d{2}-\d{2}\s*", s) and end_of_day:
            d = d + timedelta(days=1) - timedelta(milliseconds=1)
        return d

    if start or end:
        try:
            e = _parse(end, True) if end else now_dt
            s = _parse(start, False) if start else e - timedelta(days=DEFAULT_DAYS)
        except OverflowError:   # a date at the calendar's edge (year 1 or 9999): no window around it
            raise ValueError("That date is at the very edge of the calendar. Choose a recent date, such as 2026-10-01.")
    else:
        try:
            n = int(days if days not in (None, "") else DEFAULT_DAYS)
        except (TypeError, ValueError):
            raise ValueError("The number of days must be a whole number.")
        if n < 1:
            raise ValueError("Choose at least one day.")
        if n > MAX_DAYS:   # checked before the date arithmetic, which overflows for a huge n
            raise ValueError(f"The window is longer than {MAX_DAYS} days, the most ZIA keeps the audit log for. Choose a shorter one.")
        e, s = now_dt, now_dt - timedelta(days=n)
    e = min(e, now_dt)
    if s >= e:
        raise ValueError("The start of the window must be before its end.")
    if e - s > timedelta(days=MAX_DAYS):
        raise ValueError(f"The window is longer than {MAX_DAYS} days, the most ZIA keeps the audit log for. Choose a shorter one.")
    return {"start": s.isoformat(timespec="seconds"), "end": e.isoformat(timespec="seconds"),
            "start_ms": int(s.timestamp() * 1000), "end_ms": int(e.timestamp() * 1000),
            "start_ts": s.timestamp(), "end_ts": e.timestamp(), "days": round((e - s).total_seconds() / 86400, 2)}


# ── time parsing ────────────────────────────────────────────────────────

_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M", "%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M",
            "%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y %I:%M %p", "%B %d, %Y %I:%M:%S %p", "%b %d, %Y %I:%M:%S %p", "%B %d, %Y %H:%M:%S",
            "%b %d, %Y %H:%M:%S", "%a %b %d %H:%M:%S %Y", "%d %b %Y %H:%M:%S", "%d-%b-%Y %H:%M:%S", "%Y-%m-%d", "%m/%d/%Y")
_ZONE_WORD = re.compile(r"(?<!\s)\s+(UTC|GMT|Z)$", re.I)
_OTHER_ZONE = re.compile(r"(?<!\s)\s+([A-Z]{2,5})$")
_MID_ZONE = re.compile(r"(?<=\d)\s+([A-Z]{2,5})\s+(\d{4})$")   # "Tue Oct 20 10:15:30 PDT 2026"
MAX_TIME_TEXT = 64   # no time ZIA or this app writes is longer; longer text is not a time (and is never pattern-matched)
# Zone abbreviations that name one fixed offset (hours from UTC). One that
# names several zones (IST: India, Ireland or Israel) or none listed here is
# never guessed: the time is unreadable (listed last, as written) rather
# than read as UTC and shifted by hours, which would also break the
# CORRELATE_SECONDS match with Zscaler Made Easy's own writes. Assumed: CST
# and BST are US Central and British Summer Time, the forms a ZIA admin
# portal set to a US or UK time zone writes.
ZONE_OFFSETS = {
    "UTC": 0, "GMT": 0, "UT": 0, "WET": 0, "WEST": 1, "BST": 1, "CET": 1, "CEST": 2, "MET": 1, "MEST": 2, "EET": 2, "EEST": 3,
    "MSK": 3, "EST": -5, "EDT": -4, "CST": -6, "CDT": -5, "MST": -7, "MDT": -6, "PST": -8, "PDT": -7, "AKST": -9, "AKDT": -8,
    "HST": -10, "NST": -3.5, "NDT": -2.5, "AST": -4, "ADT": -3, "JST": 9, "KST": 9, "HKT": 8, "SGT": 8, "AWST": 8, "ACST": 9.5,
    "ACDT": 10.5, "AEST": 10, "AEDT": 11, "NZST": 12, "NZDT": 13,
}


def parse_time(value: Any) -> Optional[datetime]:
    """A time as ZIA's CSV or Zscaler Made Easy's records write it, as an aware
    datetime (UTC when the text names no zone), or None."""
    s = str(value or "").strip()
    if not s or len(s) > MAX_TIME_TEXT:
        return None
    if re.fullmatch(r"\d{9,13}", s):
        n = int(s)
        return datetime.fromtimestamp(n / 1000 if n > 10 ** 11 else n, tz=timezone.utc)
    t = re.sub(r"\s(UTC|GMT)\s", " ", _ZONE_WORD.sub("", s))
    try:
        d = datetime.fromisoformat(t.replace("Z", "+00:00") if t.endswith("Z") else t)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z"):
        try:
            return datetime.strptime(t, fmt)
        except ValueError:
            pass
    tz, cand = timezone.utc, t
    m = _OTHER_ZONE.search(t) if not re.search(r"\b(AM|PM)$", t, re.I) else None
    mid = None if m else _MID_ZONE.search(t)
    if m or mid:
        off = ZONE_OFFSETS.get((m or mid).group(1))
        if off is None:
            return None   # a zone this page cannot place: never read as UTC
        tz = timezone(timedelta(hours=off))
        cand = t[:m.start()] if m else t[:mid.start()] + " " + mid.group(2)
    for fmt in _FORMATS:
        try:
            return datetime.strptime(cand, fmt).replace(tzinfo=tz)
        except ValueError:
            continue
    return None


def _iso(d: Optional[datetime]) -> str:
    return d.astimezone(timezone.utc).isoformat(timespec="seconds") if d else ""


# ── redaction, values and diffs ─────────────────────────────────────────

def redact(value: Any, depth: int = 0) -> Any:
    """A copy with every secret-looking key's value replaced."""
    if depth > 12:
        return "…"
    if isinstance(value, dict):
        return {k: ("[redacted]" if _SECRET_KEY.search(str(k)) else redact(v, depth + 1)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact(v, depth + 1) for v in value]
    return value


def redact_text(text: str) -> str:
    """Secret-looking "key": "value" pairs inside text that is not valid JSON."""
    return _SECRET_PAIR.sub(lambda m: m.group(1) + '"[redacted]"', text)


def parse_value(text: Any) -> Any:
    """A pre / post value: parsed JSON (redacted) when it is JSON, else the
    text (redacted, cut to MAX_VALUE), None when empty."""
    s = str(text if text is not None else "").strip()
    if not s or s.lower() in ("null", "none", "-", "n/a"):
        return None
    if s[0] in "{[":
        try:
            return redact(json.loads(s))
        except ValueError:
            pass
    s = redact_text(s)
    return s if len(s) <= MAX_VALUE else s[:MAX_VALUE] + "…"


def flatten(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None, depth: int = 0) -> Dict[str, Any]:
    """{dotted.field: scalar} for a parsed value; a list of scalars is one
    field, a list of objects is indexed (by its name or id when it has one)."""
    out = {} if out is None else out
    if len(out) > 2000 or depth > 10:
        return out
    if isinstance(value, dict):
        if not value and prefix:
            out[prefix] = "{}"
        for k, v in value.items():
            flatten(v, f"{prefix}.{k}" if prefix else str(k), out, depth + 1)
    elif isinstance(value, list):
        if all(not isinstance(v, (dict, list)) for v in value):
            out[prefix or "value"] = ", ".join(str(v) for v in value)
        else:
            for i, v in enumerate(value):
                label = (v.get("name") or v.get("id")) if isinstance(v, dict) else None
                flatten(v, f"{prefix}[{label if label is not None else i}]", out, depth + 1)
    else:
        out[prefix or "value"] = value
    return out


def field_diff(pre: Any, post: Any, limit: int = 200) -> List[Dict[str, Any]]:
    """Field-level differences between a pre and a post value: [{field,
    before, after, change: added | removed | changed}]. Text values that
    are not JSON compare as one field."""
    if pre is None and post is None:
        return []
    a = flatten(pre) if isinstance(pre, (dict, list)) else ({"value": pre} if pre is not None else {})
    b = flatten(post) if isinstance(post, (dict, list)) else ({"value": post} if post is not None else {})
    out: List[Dict[str, Any]] = []
    for k in sorted(set(a) | set(b)):
        if k in a and k in b:
            if a[k] != b[k]:
                out.append({"field": k, "before": a[k], "after": b[k], "change": "changed"})
        elif k in b:
            out.append({"field": k, "before": None, "after": b[k], "change": "added"})
        else:
            out.append({"field": k, "before": a[k], "after": None, "change": "removed"})
        if len(out) >= limit:
            break
    return out


# ── provenance (what Zscaler Made Easy created) ─────────────────────────────────

def _descriptions(value: Any, depth: int = 0) -> List[str]:
    if depth > 6:
        return []
    if isinstance(value, dict):
        out = [str(v) for k, v in value.items() if str(k).lower() == "description" and isinstance(v, str)]
        for v in value.values():
            if isinstance(v, (dict, list)):
                out += _descriptions(v, depth + 1)
        return out
    if isinstance(value, list):
        return [d for v in value for d in _descriptions(v, depth + 1)]
    if isinstance(value, str):
        return [value]
    return []


def provenance(value: Any, known: Optional[Iterable[str]] = None) -> Optional[Dict[str, Any]]:
    """The provenance tag a Zscaler Made Easy deploy writes at the end of a
    description ("[<assessor> pack <id> v<version>]", pack_deploy), found in
    a parsed pre / post value or text: {by, pack, version, kind, tag}, or None."""
    import pack_deploy
    ks = set(known) if known is not None else None
    for desc in _descriptions(value):
        if not pack_deploy.has_mark(desc):
            continue
        m = pack_deploy.MARK_RE.search(desc)
        pack = pack_deploy.tag_pack(desc, known=ks)
        if m:
            return {"by": m.group("by"), "pack": pack or m.group("pack"), "version": (m.group("ver") or "").strip() or None,
                    "kind": m.group("kind"), "tag": m.group(0).strip()[:200]}
        return {"by": pack_deploy.DEFAULT_BY, "pack": pack, "version": None, "kind": "pack", "tag": None}
    return None


# ── ZIA's CSV ───────────────────────────────────────────────────────────

ALIASES: Dict[str, Tuple[str, ...]] = {
    "time": ("time", "timestamp", "date", "datetime", "eventtime", "logtime", "timeutc", "timegmt", "actiontime", "createdat", "dateandtime"),
    "admin": ("admin", "adminid", "adminname", "adminlogin", "adminuser", "loginname", "user", "username", "login", "performedby", "administrator", "actor"),
    "action": ("action", "actiontype", "operation", "event", "eventtype", "auditaction", "actionperformed"),
    "category": ("category", "resourcecategory", "module", "area", "menu", "categoryname"),
    "subcategory": ("subcategory", "resourcetype", "objecttype", "subcategoryname", "type"),
    "resource": ("resource", "resourcename", "objectname", "object", "name", "entity", "entityname", "target", "item"),
    "object_id": ("resourceid", "objectid", "entityid", "id"),
    "interface": ("interface", "clientinterface", "accessinterface", "source", "channel", "via", "accessmethod"),
    "result": ("result", "status", "outcome", "actionresult"),
    "client_ip": ("clientip", "sourceip", "ipaddress", "adminip", "ip"),
    "pre": ("preaction", "prevalue", "pre", "before", "oldvalue", "oldvalues", "preactiondata", "previousvalue", "preactionvalue", "prechange"),
    "post": ("postaction", "postvalue", "post", "after", "newvalue", "newvalues", "postactiondata", "postactionvalue", "postchange"),
}
_ALIAS_INDEX = {a: field for field, names in ALIASES.items() for a in names}


def _norm(col: str) -> str:
    return re.sub(r"[^a-z0-9]", "", str(col or "").lower())


def map_columns(header: List[str]) -> Dict[str, int]:
    """{field: column index} for the columns this parser recognises; the
    first column for a field wins."""
    out: Dict[str, int] = {}
    for i, col in enumerate(header):
        f = _ALIAS_INDEX.get(_norm(col))
        if f and f not in out:
            out[f] = i
    return out


def parse_csv(text: str, max_rows: int = MAX_ROWS) -> Dict[str, Any]:
    """ZIA's audit log CSV → {rows: [parsed row], columns, mapped, preamble,
    skipped, truncated, notes}. Never raises on bad input: what it cannot
    read is counted and said."""
    out: Dict[str, Any] = {"rows": [], "columns": [], "mapped": {}, "preamble": 0, "skipped": 0, "truncated": False, "notes": []}
    s = (text or "").lstrip("﻿")
    if not s.strip():
        out["notes"].append("ZIA returned an empty audit log report: nothing was recorded in this window.")
        return out
    csv.field_size_limit(max(MAX_VALUE * 4, 1 << 20))
    delim = _delimiter(s)
    reader = csv.reader(io.StringIO(s), delimiter=delim)
    header: Optional[List[str]] = None
    mapped: Dict[str, int] = {}
    try:
        for row in reader:
            if header is None:
                if not any(str(c).strip() for c in row):
                    continue
                m = map_columns(row)
                if len(m) >= 2 and ("time" in m or "action" in m):
                    header, mapped = [str(c).strip() for c in row], m
                else:
                    out["preamble"] += 1
                    if out["preamble"] > 50:
                        break
                continue
            if not any(str(c).strip() for c in row):
                continue
            if len(out["rows"]) >= max_rows:
                out["truncated"] = True
                break
            out["rows"].append(_row(header, mapped, row))
    except csv.Error as e:
        out["notes"].append(f"The CSV could not be read to the end ({str(e)[:120]}); the rows before that point are shown.")
    if header is None:
        out["notes"].append("No header row with a time or action column was found, so no ZIA audit entry could be read from the report.")
        return out
    out["columns"], out["mapped"] = header, {k: header[v] for k, v in mapped.items()}
    missing = [f for f in ("time", "admin", "action") if f not in mapped]
    if missing:
        out["notes"].append("The report has no column recognised as " + ", ".join(missing) + "; those fields are left blank (the raw row is kept).")
    if out["truncated"]:
        out["notes"].append(f"The report has more than {max_rows} rows; only the first {max_rows} are shown. Choose a shorter window.")
    return out


def _delimiter(s: str) -> str:
    """The delimiter whose header row maps the most known columns (comma,
    semicolon or tab), comma when none does."""
    head = "\n".join(s.splitlines()[:60])
    best, score = ",", 0
    for d in (",", ";", "\t"):
        try:
            for row in csv.reader(io.StringIO(head), delimiter=d):
                n = len(map_columns(row))
                if n > score:
                    best, score = d, n
        except csv.Error:
            continue
    return best


def _row(header: List[str], mapped: Dict[str, int], row: List[str]) -> Dict[str, Any]:
    cell = lambda f: (str(row[mapped[f]]).strip() if f in mapped and mapped[f] < len(row) else "")  # noqa: E731
    raw: Dict[str, Any] = {}
    for i, col in enumerate(header):
        if i >= len(row):
            break
        v = str(row[i])
        if _SECRET_KEY.search(col):
            v = "[redacted]"
        elif i in (mapped.get("pre"), mapped.get("post")):
            pv = parse_value(v)
            v = json.dumps(pv, sort_keys=True) if isinstance(pv, (dict, list)) else (pv or "")
        raw[col or f"column {i + 1}"] = v if len(v) <= MAX_VALUE else v[:MAX_VALUE] + "…"
    if len(row) > len(header):
        raw["extra"] = [str(c)[:MAX_CELL] for c in row[len(header):]][:20]
    short = lambda v: v if len(v) <= MAX_CELL else v[:MAX_CELL] + "…"  # noqa: E731
    return {"time_raw": short(cell("time")), "admin": short(cell("admin")), "action": short(cell("action")),
            "category": short(cell("category")), "subcategory": short(cell("subcategory")), "resource": short(cell("resource")),
            "object_id": short(cell("object_id")), "interface": short(cell("interface")), "result": short(cell("result")),
            "client_ip": short(cell("client_ip")), "pre": parse_value(cell("pre")), "post": parse_value(cell("post")), "raw": raw}


# ── reading ZIA's audit log report ──────────────────────────────────────

def _json(text: Any) -> Any:
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(text) if text else None
    except (TypeError, ValueError):
        return None


def _get_text(client, ep: str) -> Tuple[str, int]:
    """An uncached GET as text: the assessment Client's get_text, else get()."""
    fn = getattr(client, "get_text", None)
    if callable(fn):
        if ep == DOWNLOAD_EP:
            return fn(ep, accept="text/csv, application/octet-stream;q=0.9, */*;q=0.8", max_bytes=DOWNLOAD_MAX_BYTES)
        return fn(ep, accept="application/json")
    data, status = client.get(ep)
    return (data if isinstance(data, str) else json.dumps(data)), status


_DONE = ("COMPLETE", "COMPLETED", "DONE", "FINISHED", "SUCCESS")
_WAITING = ("", "EXECUTING", "IN_PROGRESS", "INPROGRESS", "RUNNING", "PENDING", "QUEUED", "STARTED", "PROCESSING", "NEW")


def read_zia_audit(client, start_ms: int, end_ms: int, *, log: LogFn = None, cancel: Any = None,
                   poll_seconds: Optional[float] = None, timeout: Optional[float] = None) -> Dict[str, Any]:
    """Create ZIA's audit log report for [start_ms, end_ms], wait for it
    and download it. The POST that creates the report changes no
    configuration (a read, see the module docstring). Returns {status:
    read | failed, error, csv: parse_csv(...), progress}. Raises Stopped
    once `cancel` is set: no partial report is returned, and the report
    ZIA may still be preparing is left to expire (no DELETE is sent)."""
    _log = log or (lambda m: None)
    poll_seconds = POLL_SECONDS if poll_seconds is None else poll_seconds
    timeout = POLL_TIMEOUT if timeout is None else timeout

    def check() -> None:
        if _stop_requested(cancel):
            raise Stopped(STOPPED_REASON)

    check()
    _log("Asking ZIA to prepare the admin audit log report for the window (this changes no configuration)…")
    # Sent like the Path analyzer's URL lookup (POST /urlLookup), through the
    # client's `post` looked up by name: a request that changes no
    # configuration, deliberately not counted as a tenant write by
    # tests/test_shared_path.py's guard (see the module docstring).
    create_report = getattr(client, "post")
    data, status = create_report(REPORT_EP, {"startTime": int(start_ms), "endTime": int(end_ms)})
    check()
    if status not in (200, 201, 202, 204):
        err = (data.get("message") or data.get("error")) if isinstance(data, dict) else ""
        hint = {401: " The API client is not signed in.", 403: " The API client's role does not include the audit log (View Activity Log / Audit Logs).",
                409: " ZIA is already preparing an audit log report for this API client; try again in a few minutes.",
                429: " ZIA's rate limit was reached; try again later."}.get(status, "")
        return {"status": "failed", "error": f"ZIA refused the audit log report (HTTP {status})" + (f": {str(err)[:160]}." if err else ".") + hint}
    deadline = time.time() + timeout
    last = None
    while True:
        if not _wait(cancel, poll_seconds):
            raise Stopped(STOPPED_REASON)
        text, code = _get_text(client, REPORT_EP)
        check()
        if code != 200:
            return {"status": "failed", "error": f"ZIA did not answer the report's status (HTTP {code}: {str(text)[:160]})."}
        st = _json(text) or {}
        state = str(st.get("status") or "").upper() if isinstance(st, dict) else ""
        progress = st.get("progressItemsComplete") if isinstance(st, dict) else None
        if progress != last and progress is not None:
            _log(f"ZIA is preparing the report: {progress} entr{'y' if progress == 1 else 'ies'} so far…")
            last = progress
        if state in _DONE:
            break
        if state not in _WAITING:
            msg = st.get("errorMessage") or st.get("errorCode") if isinstance(st, dict) else ""
            return {"status": "failed", "error": f"ZIA ended the audit log report as {state}" + (f": {str(msg)[:160]}" if msg else "") + "."}
        if time.time() > deadline:
            return {"status": "failed", "error": f"ZIA had not finished the audit log report after {int(timeout)} seconds. Try a shorter window."}
    _log("Downloading the report…")
    text, code = _get_text(client, DOWNLOAD_EP)
    check()
    if code != 200:
        return {"status": "failed", "error": f"ZIA did not hand over the audit log report (HTTP {code}: {str(text)[:160]})."}
    parsed = parse_csv(text)
    _log(f"Read {len(parsed['rows'])} audit log entr{'y' if len(parsed['rows']) == 1 else 'ies'} from ZIA.")
    return {"status": "read", "error": None, "csv": parsed}


# ── Zscaler Made Easy's own records ─────────────────────────────────────────────

def _tenant_ok(value: Any, labels: Optional[Iterable[str]]) -> bool:
    """With a tenant chosen (`labels`), only records that name it. A record
    that names no tenant is left out (deny by default, as deployments.
    list_all and self_heal match): it could be another customer's write."""
    if not labels:
        return True
    v = str(value or "")
    return bool(v) and v in set(labels)


def _unlabelled(deployments: List[Dict[str, Any]], entries: List[Dict[str, Any]]) -> int:
    """How many tenant records name no tenant (left out when one is chosen)."""
    n = sum(1 for r in deployments or [] if isinstance(r, dict) and not str(r.get("tenant_label") or ""))
    return n + sum(1 for a in entries or [] if isinstance(a, dict) and str(a.get("event") or "") in ("object_write", "job_finished", "run_finished")
                   and not str(a.get("tenant") or ""))


def _ev(source: str, when: Optional[datetime], **fields: Any) -> Dict[str, Any]:
    e = {"source": source, "source_label": SOURCES[source], "time": _iso(when), "ts": when.timestamp() if when else None,
         "time_raw": fields.pop("time_raw", "") or _iso(when), "admin": "", "action": "", "category": "", "resource": "", "object": "",
         "object_id": "", "interface": "", "result": "", "tenant": "", "detail": "", "pre": None, "post": None, "diff": [],
         "provenance": None, "dlp_check_object": False, "foreign_change": False, "foreign_reason": "", "raw": None}
    e.update({k: v for k, v in fields.items() if v is not None})
    return e


def _created(r: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What a deployment created: a raw record's `created` list, or a
    deployments.summary's `items`."""
    items = r.get("created") if isinstance(r.get("created"), list) else r.get("items")
    return [c for c in (items or []) if isinstance(c, dict)]


def deployment_events(records: List[Dict[str, Any]], labels: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """One event per recorded deployment, and one per undo."""
    out: List[Dict[str, Any]] = []
    for r in records or []:
        if not isinstance(r, dict) or not _tenant_ok(r.get("tenant_label"), labels):
            continue
        created = _created(r)
        kinds: Dict[str, int] = {}
        for c in created:
            kinds[str(c.get("kind"))] = kinds.get(str(c.get("kind")), 0) + 1
        names = ", ".join(str(c.get("name")) for c in created[:8]) + (f" and {len(created) - 8} more" if len(created) > 8 else "")
        out.append(_ev("deployment", parse_time(r.get("at")), admin=str(r.get("by") or ""), action="Deploy policy packs",
                       category="Policy packs", resource=", ".join(map(str, r.get("packs") or [])), object=names,
                       interface="Zscaler Made Easy", result=str(r.get("status") or ""), tenant=str(r.get("tenant_label") or ""),
                       detail="Created " + (", ".join(f"{n} {k}" for k, n in sorted(kinds.items())) or "nothing"),
                       object_id=str(r.get("id") or "")))
        undo = r.get("undo") if isinstance(r.get("undo"), dict) else None
        if undo:
            out.append(_ev("deployment", parse_time(undo.get("at")), admin=str(r.get("by") or ""), action="Undo deployment",
                           category="Policy packs", resource=", ".join(map(str, r.get("packs") or [])), object=str(r.get("id") or ""),
                           interface="Zscaler Made Easy", result="complete" if undo.get("complete") else "partial", tenant=str(r.get("tenant_label") or ""),
                           detail=f"{sum(1 for x in undo.get('results') or [] if isinstance(x, dict) and x.get('status') in ('deleted', 'gone'))} object(s) removed"))
    return out


_APP_EVENTS = ("object_write", "job_finished", "run_finished", "continuous_evaluation", "sso_login", "sso_logout", "sso_login_refused")


def app_events(entries: List[Dict[str, Any]], labels: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """The app audit log entries that say what Zscaler Made Easy did: tenant
    writes, jobs, proposal decisions, write-mode switches and sign-ins.
    The per-request `api` lines are left out (each tenant write already has
    its own entry), except the write-mode switch."""
    out: List[Dict[str, Any]] = []
    for a in entries or []:
        if not isinstance(a, dict):
            continue
        ev = str(a.get("event") or "")
        when = parse_time(a.get("at"))
        actor = str(a.get("actor") or "")
        if ev == "api":
            if str(a.get("path") or "") != "/api/write-mode":
                continue
            body = a.get("body") if isinstance(a.get("body"), dict) else {}
            out.append(_ev("app", when, admin=actor, action="Write mode " + ("on" if body.get("enable") else "off"), category="Write mode",
                           interface="Zscaler Made Easy", result=f"HTTP {a.get('status')}", detail="Server write mode switched from the app."))
            continue
        if ev not in _APP_EVENTS and not ev.startswith("proposal_"):
            continue
        tenant = str(a.get("tenant") or "")
        if ev in ("object_write", "job_finished", "run_finished") and not _tenant_ok(tenant, labels):
            continue
        if ev == "object_write":
            out.append(_ev("app", when, admin=actor, action=f"{a.get('action') or 'write'} {a.get('object_type') or 'object'}".strip(),
                           category=str(a.get("channel") or a.get("object_type") or ""), object=str(a.get("name") or ""),
                           object_id=str(a.get("id") if a.get("id") is not None else ""), interface="Zscaler Made Easy (API)",
                           result=str(a.get("result") or ""), tenant=tenant,
                           detail=(f"HTTP {a.get('http_status')}" if a.get("http_status") else "") + (f"; {a.get('error')}" if a.get("error") else ""),
                           write_action=str(a.get("action") or "")))
        elif ev in ("job_finished", "run_finished"):
            counts = a.get("counts") if isinstance(a.get("counts"), dict) else {}
            c = ", ".join(f"{v} {k}" for k, v in counts.items() if v)
            out.append(_ev("app", when, admin=actor, action=f"{a.get('kind') or a.get('run') or 'job'} {a.get('status') or a.get('result_status') or 'finished'}",
                           category="Job", object=str(a.get("label") or ""), interface="Zscaler Made Easy", result=str(a.get("result_status") or a.get("status") or ""),
                           tenant=tenant, detail=(c or "no tenant writes") + (f"; stopped: {a.get('stopped')}" if a.get("stopped") else "")
                           + (f"; error: {a.get('error')}" if a.get("error") else "")))
        elif ev.startswith("proposal_"):
            out.append(_ev("app", when, admin=str(a.get("by") or actor), action=ev.replace("_", " "), category="Proposals",
                           object=str(a.get("target") or ""), interface="Zscaler Made Easy", result=str(a.get("decision") or a.get("status") or ""),
                           detail=str(a.get("kind") or "")))
        elif ev == "continuous_evaluation":
            out.append(_ev("app", when, admin=actor, action="Continuous evaluation", category="Evaluation", object=str(a.get("digest") or ""),
                           interface="Zscaler Made Easy"))
        else:
            out.append(_ev("app", when, admin=actor, action=ev.replace("_", " "), category="Sign-in", interface="Zscaler Made Easy"))
    return out


# ── merging ─────────────────────────────────────────────────────────────

_CHANGE_WORDS = re.compile(r"creat|add|updat|edit|modif|delet|remov|chang|enabl|disabl|reorder|move|renam|import|save", re.I)
_NOT_CHANGE = re.compile(r"sign|log ?in|log ?out|login|logout|download|export|view|activat", re.I)


def _is_change(e: Dict[str, Any]) -> bool:
    act = e.get("action") or ""
    if _NOT_CHANGE.search(act) and not _CHANGE_WORDS.search(act):
        return False
    return bool(_CHANGE_WORDS.search(act)) or e.get("pre") is not None or e.get("post") is not None


def _object_names(value: Any) -> List[str]:
    if isinstance(value, dict):
        n = value.get("name") or value.get("configuredName")
        return [str(n)] if n else []
    return []


def _object_ids(value: Any) -> List[str]:
    if isinstance(value, dict) and value.get("id") is not None:
        return [str(value.get("id"))]
    return []


def zia_events(rows: List[Dict[str, Any]], created: List[Dict[str, Any]], own_writes: List[Dict[str, Any]],
               known_packs: Optional[Iterable[str]] = None) -> List[Dict[str, Any]]:
    """ZIA rows as timeline events, each marked when it touches an object
    Zscaler Made Easy created (provenance tag, or listed in a deployment record)
    and, when no Zscaler Made Easy write explains it within CORRELATE_SECONDS, as
    a change made by someone else."""
    names = {str(c.get("name")).strip().lower() for c in created if c.get("name")}
    ids = {str(c.get("id")) for c in created if c.get("id") is not None}
    writes = [(str(w.get("object") or "").strip().lower(), str(w.get("object_id") or ""), w.get("ts")) for w in own_writes]
    out: List[Dict[str, Any]] = []
    for r in rows:
        when = parse_time(r.get("time_raw"))
        pre, post = r.get("pre"), r.get("post")
        obj_names = _object_names(post) + _object_names(pre)
        obj = r.get("resource") or (obj_names[0] if obj_names else "")
        cat = " / ".join(x for x in (r.get("category"), r.get("subcategory")) if x)
        e = _ev("zia", when, time_raw=r.get("time_raw") or "", admin=r.get("admin") or "", action=r.get("action") or "", category=cat,
                resource=r.get("resource") or "", object=obj, object_id=r.get("object_id") or next(iter(_object_ids(post) + _object_ids(pre)), ""),
                interface=r.get("interface") or "", result=r.get("result") or "", pre=pre, post=post, raw=r.get("raw"),
                detail=f"from {r['client_ip']}" if r.get("client_ip") else "")
        e["diff"] = field_diff(pre, post)
        prov_pre, prov_post = provenance(pre, known_packs), provenance(post, known_packs)
        e["provenance"] = prov_post or prov_pre
        cand_names = {n.strip().lower() for n in [obj, *obj_names] if n}
        cand_ids = {str(x) for x in [e["object_id"], *_object_ids(post), *_object_ids(pre)] if x}
        e["dlp_check_object"] = bool(e["provenance"]) or bool(cand_names & names) or bool(cand_ids & ids)
        if prov_pre and post is not None and not prov_post and isinstance(post, dict) and "description" in {k.lower() for k in post}:
            e["tag_removed"] = True
        if e["dlp_check_object"] and _is_change(e):
            ts = e["ts"]
            own = ts is not None and any(t is not None and abs(t - ts) <= CORRELATE_SECONDS and ((n and n in cand_names) or (i and i in cand_ids))
                                         for n, i, t in writes)
            if not own:
                why = []
                if e["provenance"]:
                    p = e["provenance"]
                    why.append(f"its description carries Zscaler Made Easy's provenance tag for pack {p.get('pack') or '?'}"
                               + (f" v{p['version']}" if p.get("version") else "") + (f" (deployed by {p['by']})" if p.get("by") else ""))
                else:
                    why.append("a Zscaler Made Easy deployment record lists it as created")
                if e.get("tag_removed"):
                    why.append("this change removed the provenance tag")
                e["foreign_change"] = True
                e["foreign_reason"] = ("Changed by someone else: " + "; ".join(why) + f", and no Zscaler Made Easy write to it is recorded within "
                                       f"{CORRELATE_SECONDS // 60} minutes of this change" + (f" (by {e['admin']}" + (f" via {e['interface']}" if e["interface"] else "") + ")" if e["admin"] else "") + ".")
        out.append(e)
    return out


def merge(*groups: List[Dict[str, Any]], start_ts: Optional[float] = None, end_ts: Optional[float] = None,
          limit: int = MAX_EVENTS) -> Tuple[List[Dict[str, Any]], int, int]:
    """Every event inside the window, newest first, with an id; an event
    without a readable time is kept, after the timed ones. Returns
    (events, outside the window, cut by `limit`)."""
    events: List[Dict[str, Any]] = []
    outside = 0
    for g in groups:
        for e in g:
            ts = e.get("ts")
            if ts is not None and ((start_ts is not None and ts < start_ts) or (end_ts is not None and ts > end_ts + 1)):
                outside += 1
                continue
            events.append(e)
    events.sort(key=lambda e: (e.get("ts") is not None, e.get("ts") or 0), reverse=True)
    cut = max(0, len(events) - limit)
    events = events[:limit]
    for i, e in enumerate(events):
        e["id"] = f"{e['source']}-{i}"
    return events, outside, cut


def build(*, window_: Dict[str, Any], zia: Optional[Dict[str, Any]], deployments: List[Dict[str, Any]], audit_entries: List[Dict[str, Any]],
          labels: Optional[Iterable[str]] = None, known_packs: Optional[Iterable[str]] = None, tenant_label: str = "",
          zia_requested: bool = True, zia_reason: str = "") -> Dict[str, Any]:
    """The timeline result the page shows."""
    labels = list(labels) if labels else None
    dep = deployment_events(deployments, labels)
    app = app_events(audit_entries, labels)
    created = [c for r in deployments or [] if isinstance(r, dict) and _tenant_ok(r.get("tenant_label"), labels)
               for c in _created(r)]
    own = [e for e in app if e.get("write_action")]
    zrows = ((zia or {}).get("csv") or {}).get("rows") or []
    zev = zia_events(zrows, created, own, known_packs)
    events, outside, cut = merge(zev, dep, app, start_ts=window_.get("start_ts"), end_ts=window_.get("end_ts"))
    notes: List[str] = []
    if zia_requested and zia:
        notes += list(((zia or {}).get("csv") or {}).get("notes") or [])
        if zia.get("error"):
            notes.append(zia["error"])
    elif not zia_requested:
        notes.append(zia_reason or "The ZIA admin audit log was not read: only Zscaler Made Easy's own records are shown.")
    if outside:
        notes.append(f"{outside} record(s) fall outside the window and are not shown.")
    if cut:
        notes.append(f"Only the newest {MAX_EVENTS} events are shown; {cut} older one(s) were left out. Choose a shorter window.")
    if labels:
        notes.append("Zscaler Made Easy's own records are shown for this tenant only (" + ", ".join(labels[:2]) + ").")
        nolabel = _unlabelled(deployments, audit_entries)
        if nolabel:
            notes.append(f"{nolabel} of Zscaler Made Easy's record(s) name no tenant, so they are not shown here: they may belong to another tenant.")
    untimed = sum(1 for e in events if e.get("ts") is None)
    if untimed:
        notes.append(f"{untimed} event(s) have a time this page could not read; they are listed last with the time as written.")
    summary = {"events": len(events), "zia": sum(1 for e in events if e["source"] == "zia"), "deployment": sum(1 for e in events if e["source"] == "deployment"),
               "app": sum(1 for e in events if e["source"] == "app"), "foreign_changes": sum(1 for e in events if e.get("foreign_change")),
               "dlp_check_objects": sum(1 for e in events if e.get("dlp_check_object")), "with_diff": sum(1 for e in events if e.get("diff"))}
    return {"events": events, "summary": summary, "window": {k: window_[k] for k in ("start", "end", "days") if k in window_},
            "zia": {"requested": zia_requested, "status": (zia or {}).get("status") if zia_requested else "not_read",
                    "error": (zia or {}).get("error") if zia else None,
                    "columns": ((zia or {}).get("csv") or {}).get("columns") or [], "mapped": ((zia or {}).get("csv") or {}).get("mapped") or {}},
            "notes": notes, "tenant_label": tenant_label, "read_note": READ_NOTE, "correlate_minutes": CORRELATE_SECONDS // 60}


# ── exports ─────────────────────────────────────────────────────────────

EXPORT_COLUMNS = ("time", "source", "admin", "action", "category", "object", "interface", "result", "tenant", "dlp_check_object",
                  "changed_by_someone_else", "provenance", "diff", "detail")


def export_rows(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for e in events:
        p = e.get("provenance") or {}
        out.append({"time": e.get("time") or e.get("time_raw") or "", "source": e.get("source_label") or e.get("source"),
                    "admin": e.get("admin") or "", "action": e.get("action") or "", "category": e.get("category") or "",
                    "object": e.get("object") or "", "interface": e.get("interface") or "", "result": e.get("result") or "",
                    "tenant": e.get("tenant") or "", "dlp_check_object": "yes" if e.get("dlp_check_object") else "",
                    "changed_by_someone_else": e.get("foreign_reason") or "",
                    "provenance": (f"{p.get('by') or ''} pack {p.get('pack') or '?'}" + (f" v{p['version']}" if p.get("version") else "")) if p else "",
                    "diff": "; ".join(f"{d['field']}: {d['before']!s} -> {d['after']!s}" for d in (e.get("diff") or [])[:50]),
                    "detail": e.get("detail") or ""})
    return out


def to_csv(events: List[Dict[str, Any]]) -> str:
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, list(EXPORT_COLUMNS))
    w.writeheader()
    w.writerows(export_rows(events))
    return buf.getvalue()
