"""Test a list: many destinations through the Path analyzer at once.

The Path analyzer page's "Test a list" view sends a CSV of destinations
(IP addresses, host names, URLs, CIDR blocks and ranges, with optional
port, protocol, source IP, location, destination country, category,
user, group, department, label and the expected result, block or
allow). This module:

1. parses it defensively (`parse`): the file is untrusted, so it has a
   size cap, a line and cell length cap, no formula is ever evaluated and
   a bad line is skipped with the reason, never fatal. CIDR blocks and
   ranges expand to one row per address, at most a /16 (65,536) per row
   and MAX_ROWS rows in all;
2. asks ZIA which categories each unique destination belongs to
   (`lookup_all`: POST /zia/urlLookup, a hundred per request, the chunk
   size zscaler-sdk-python's url_categories.lookup uses). The assessment
   Client paces every request with zia_rate and waits out a short 429 for
   its Retry-After; on top of that a 429 that persists, a 412 or a 5xx
   is waited out and retried here on a fixed schedule, and ZIA's hourly
   quota (or refusals after earlier lookups worked) stops the lookups
   with the label "rerun later" on every row not looked up. A category
   column in the file overrides the lookup for its row. Answers are kept
   for the run;
3. runs every row through the evaluators (`EVALUATORS`): the Path
   analyzer's own evaluation, the same answer the single-destination
   analyzer gives (one code path, `PathEvaluator`): ZPA first when it is
   in scope (zpa_path: segment, bypass, client forwarding, access
   policy), then path_analyzer.analyze against one tenant read for the
   row's protocol and port (Client Connector, the PAC file evaluated by
   pac_eval, and every ZIA module in order: zia_path_modules), for the
   row's identity when it names a user, group, department or location
   (path_whatif). Nothing is re-implemented here and no reader is added:
   the reads are path_analyzer.analyze's (ZIA, each module only when in
   scope) and zpa_path.read's. More evaluators plug in with `register`,
   and `combine` lets the one that decides first win;
4. sums it up (blocked, allowed, bypassed, isolated, caution, allowed but
   blockable, unverified), names the top deciding rules and categories,
   compares each row with what the file expected and recommends where
   to fix a miss, from the module that decided the row (ATP, Cloud
   Firewall, URL filtering, DNS Control, Client Connector, Cloud App
   Control, ZPA), with per-category advice, exports (csv_safe /
   xlsx_writer, formula-neutralised) and a plain list of destinations per
   area to paste: an IP destination group for the Cloud Firewall, a
   custom URL category for URL filtering, the segment to change for ZPA.

"Fix selected" (`fix_handoff`) only prepares the chosen destinations for
the Bulk changes page's URL category operation (admin_ops), which
previews and applies them behind its own four write gates. Nothing in
this module writes to a tenant.
"""
from __future__ import annotations

import bisect
import csv
import fnmatch
import ipaddress
import io
import re
import secrets
import threading
import time
from array import array
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

LogFn = Optional[Callable[[str], None]]

MAX_TEXT_BYTES = 8 * 1024 * 1024    # the pasted or uploaded list
MAX_LINES = 250_000                 # non-empty lines read
MAX_ROWS = 250_000                  # rows after CIDR and range expansion
MAX_PER_ENTRY = 65_536              # a /16 per row at most
MAX_LINE_CHARS = 4096
MAX_CELL_CHARS = 256
MAX_CATEGORIES = 10                 # per row, from a category column
LOOKUP_CHUNK = 100                  # URLs per POST /urlLookup (the SDK's chunk)
DEFAULT_LOOKUP_REQUESTS = 400       # one hour of ZIA's default POST budget (zia_rate "write": 400/h)
MAX_LOOKUP_REQUESTS = 2500          # 250,000 destinations
PREVIEW_ROWS = 200
SKIPPED_SHOWN = 100
XLSX_MAX_ROWS = 100_000             # the CSV always has every row
MAX_FIX_ROWS = 5000
STOP_EVERY = 200                    # rows between Stop checks (analyze checks inside its own reads)
TRANSIENT_WAITS = (5, 15, 30, 60)   # 412, 5xx, a lost connection
RATE_WAITS = (30, 60, 120)          # a 429 the client could not wait out
REFUSED_WAITS = (60, 120, 300)      # 401/403 after lookups had worked: usually a quota
WAIT_CAP = 900

AREAS = ("ATP", "Firewall", "URL", "DNS", "Client Connector", "Cloud App", "ZPA")
AREA_KEYS = {"atp": "ATP", "firewall": "Firewall", "url": "URL", "dns": "DNS", "client_connector": "Client Connector", "cloud_app": "Cloud App",
             "zpa": "ZPA"}
AREA_LABELS = {"ATP": "Advanced Threat Protection", "Firewall": "Cloud Firewall", "URL": "URL filtering", "DNS": "DNS Control",
               "Client Connector": "Client Connector", "Cloud App": "Cloud App Control", "ZPA": "ZPA"}
AREA_PASTE = {"ATP": "the ATP denylist (Malicious URLs) or, to allow, the ATP security exceptions",
              "Firewall": "an IP destination group (type IP for addresses, FQDN for host names) used by a Cloud Firewall rule",
              "URL": "a custom URL category used by a URL filtering rule",
              "DNS": "a custom URL category used by a DNS Control rule",
              "Client Connector": "the app profile's bypass list (remove them to send them to Zscaler)",
              "Cloud App": "a custom URL category, or name the cloud application in a Cloud App Control rule",
              "ZPA": "the ZPA application segment named for each row: ZPA's access policy decides these, not a ZIA list"}
RESULTS = ("blocked", "allowed", "bypassed", "isolated", "caution", "unverified")
DECIDING = ("blocked", "bypassed", "isolated", "caution")
ROW_FILTERS = ("all", "flagged", "unmet")

STOPPED_REASON = ("You clicked Stop before every row was tested: the rows already tested are shown, the rest are marked "
                  "not tested, and nothing more was read from the tenant. Nothing was written.")
QUOTA_LABEL = "not looked up: ZIA's lookup quota was reached, rerun later"
CAP_LABEL = "not looked up: this run's lookup limit was reached, rerun later"
DENIED_LABEL = "not looked up: this API client may not run URL lookups"
STOPPED_LABEL = "not looked up: you clicked Stop"

# Zscaler's threat categories go to Advanced Threat Protection, not to a
# category rule. Any category ZIA's lookup returns with a security alert
# counts as a threat as well. Verified in the installed SDK (1.11.3,
# cloud_firewall_rules docstrings): BOTNET, MALWARE_SITE, PHISHING,
# SUSPICIOUS_DESTINATION; the others are assumed from ZIA's category list.
THREAT_CATEGORIES = frozenset({"BOTNET", "MALWARE_SITE", "PHISHING", "SUSPICIOUS_DESTINATION", "MALICIOUS_CONTENT", "SPYWARE_OR_ADWARE",
                               "ADSPYWARE_SITES", "WEB_SPAM", "CRYPTOMINING", "BROWSER_EXPLOIT", "UNAUTHORIZED_COMMUNICATION"})
# Categories few legitimate business sites fall in: blocking the whole
# category costs little. Names this app already uses (ssl_flow) or assumed.
LOW_COLLATERAL = frozenset({"MISCELLANEOUS_OR_UNKNOWN", "OTHER_MISCELLANEOUS", "NON_CATEGORIZABLE", "NEWLY_REG_DOMAINS", "NEWLY_REVIVED_DOMAINS",
                            "DYNAMIC_DNS", "ANONYMIZER", "P2P_COMMUNICATION", "PEER_TO_PEER", "PARKED_DOMAINS", "HACKING",
                            "QUESTIONABLE", "OTHER_ILLEGAL_OR_QUESTIONABLE", "REMOTE_ACCESS_TOOLS"})
WEB_PORTS = frozenset({80, 443, 8080, 8443})

ASSUMPTIONS = [
    "Each row is traced as the Path analyzer traces one destination, from a managed device with Client Connector on the network and platform you "
    "chose: ZPA first when it is in scope, then Client Connector and the PAC file (evaluated, never run), then every ZIA module in order "
    "(Advanced Threat Protection, Cloud Firewall, DNS Control, Cloud App Control and URL filtering, Sandbox, File Type Control, DLP) for the "
    "row's protocol and port. A row with no port is HTTPS (TCP/443); a URL's own port or http:// scheme gives its port.",
    "A row with a user, group, department or location is evaluated for that identity: rules scoped to it apply and rules scoped to others are "
    "skipped. Without one the row is for any user. A scoped rule that could still block it (or a rule that depends on a time window, device "
    "trust or anything else not given) makes the row 'allowed but blockable'.",
    "A row's source IP is matched against the Cloud Firewall's source IP conditions, taken as the address ZIA sees for the device. Destination "
    "country is carried into the results but not evaluated: this tool does not geolocate.",
    "ICMP rows are not traced (the Path analyzer evaluates TCP and UDP); a row with the protocol 'any' is traced as TCP.",
    "A URL is tested by its host: URL filtering here decides by host and category, not by path.",
    "A category column in the file overrides ZIA's lookup for its row; rows ZIA could not look up are placed by the tenant's own custom categories only.",
]


class ListError(ValueError):
    """The list cannot be tested at all (too large, nothing to test)."""


class Stopped(RuntimeError):
    """The operator clicked Stop."""


# ── Parsing ─────────────────────────────────────────────────────────────

ALIASES: Dict[str, Tuple[str, ...]] = {
    "destination": ("destination", "dest", "ip", "ipaddress", "address", "host", "hostname", "url", "domain", "fqdn", "target",
                    "cidr", "range", "destip", "destinationip", "destinationaddress"),
    "port": ("port", "destport", "dport", "destinationport"),
    "protocol": ("protocol", "proto"),
    "source_ip": ("sourceip", "srcip", "src", "source", "clientip"),
    "location": ("location", "loc", "site"),
    "dest_country": ("destcountry", "destinationcountry", "country"),
    "category": ("category", "categories", "urlcategory", "urlcategories"),
    "user": ("user", "username", "email", "upn"),
    "group": ("group", "groups", "usergroup", "usergroups"),
    "department": ("department", "departments", "dept"),
    "label": ("label", "name", "note", "notes", "comment", "description", "tag"),
    "expected": ("expected", "expect", "expectation", "should", "desired", "intent", "expectedaction", "expectedresult"),
}
_HEADER = {alias: key for key, names in ALIASES.items() for alias in names}
FIELDS = ("line", "input", "port", "protocol", "source_ip", "location", "dest_country", "category", "user", "group", "department", "label", "expected",
          "notes")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_CATEGORY_ID = re.compile(r"^[A-Z0-9_]{2,64}$")
_PROTOCOLS = {"tcp": "TCP", "udp": "UDP", "icmp": "ICMP", "any": "ANY", "http": "TCP", "https": "TCP"}
_BLOCK_WORDS = {"block", "blocked", "deny", "denied", "drop", "reject", "shouldblock", "bad", "malicious", "ioc"}
_ALLOW_WORDS = {"allow", "allowed", "permit", "permitted", "pass", "shouldallow", "good", "benign"}


def _digits(s: str) -> bool:
    """ASCII digits only: str.isdigit() also takes "²" (which int() refuses)
    and "٣" (which no Zscaler field takes as a number)."""
    return s.isascii() and s.isdigit()


def _cell(v: Any, limit: int = MAX_CELL_CHARS) -> str:
    return _CONTROL.sub("", str(v or "")).strip()[:limit]


def _header_key(cell: str) -> Optional[str]:
    return _HEADER.get(re.sub(r"[\s_\-./]", "", cell.lower()))


def normalize_expected(v: Any) -> str:
    """'BLOCK', 'ALLOW' or '' from what a person wrote in the expected column."""
    s = re.sub(r"[\s_\-]", "", str(v or "").lower())
    return "BLOCK" if s in _BLOCK_WORDS else "ALLOW" if s in _ALLOW_WORDS else ""


def _delimiter(line: str) -> str:
    counts = {d: 0 for d in (",", ";", "\t")}
    quoted = False
    for ch in line:
        if ch == '"':
            quoted = not quoted
        elif not quoted and ch in counts:
            counts[ch] += 1
    best = max(counts, key=lambda d: counts[d])
    return best if counts[best] else ","


def _split(line: str, delim: str) -> Optional[List[str]]:
    try:
        return [_cell(c) for c in next(csv.reader([line], delimiter=delim))]
    except (csv.Error, StopIteration):
        return None


def _entry(cells: Sequence[str], columns: Optional[List[Optional[str]]], line_no: int) -> Dict[str, Any]:
    raw: Dict[str, str] = {}
    if columns is not None:
        for key, value in zip(columns, cells):
            if key and value and key not in raw:
                raw[key] = value
    else:   # no header: destination[, port][, protocol]
        raw["destination"] = cells[0] if cells else ""
        for c in cells[1:3]:
            if _digits(c) and "port" not in raw:
                raw["port"] = c
            elif c.lower() in _PROTOCOLS and "protocol" not in raw:
                raw["protocol"] = c
    notes: List[str] = []
    e: Dict[str, Any] = {"line": line_no, "input": raw.get("destination", "")}
    port = raw.get("port", "")
    if port:
        if _digits(port) and 0 < int(port) < 65536:
            e["port"] = int(port)
        else:
            notes.append(f"port '{port[:20]}' ignored: not 1-65535")
    proto = raw.get("protocol", "")
    if proto:
        if proto.lower() in _PROTOCOLS:
            e["protocol"] = _PROTOCOLS[proto.lower()]
            if proto.lower() in _SCHEME_PROTO_PORTS:   # "http" is TCP/80, "https" TCP/443, unless a port is given
                e["_proto_port"] = _SCHEME_PROTO_PORTS[proto.lower()]
        else:
            notes.append(f"protocol '{proto[:20]}' ignored: use TCP, UDP, ICMP or any")
    src = raw.get("source_ip", "")
    if src:
        try:
            e["source_ip"] = str(ipaddress.ip_address(src))
        except ValueError:
            notes.append("source IP ignored: not an IP address")
    for key in ("location", "dest_country", "user", "group", "department", "label"):
        if raw.get(key):
            e[key] = raw[key][:128]
    if raw.get("category"):
        cats = []
        for c in re.split(r"[;|,\s]+", raw["category"].upper()):
            if _CATEGORY_ID.match(c) and c not in cats:
                cats.append(c)
        if cats:
            e["category"] = tuple(cats[:MAX_CATEGORIES])
        else:
            notes.append("category ignored: use ZIA category IDs such as GAMBLING or CUSTOM_01")
    if raw.get("expected"):
        exp = normalize_expected(raw["expected"])
        if exp:
            e["expected"] = exp
        else:
            notes.append(f"expected '{raw['expected'][:20]}' ignored: use block or allow")
    if notes:
        e["notes"] = tuple(notes)
    return e


def _ip_range(text: str) -> Optional[Tuple[int, int, int]]:
    """(first, last, IP version) for 10.0.0.0/24, 10.0.0.1-10.0.0.9 or
    10.0.0.1-9; None when `text` is not a block or range. ValueError for
    one that is malformed."""
    if "/" in text:
        try:
            net = ipaddress.ip_network(text, strict=False)
        except ValueError:
            if re.match(r"^[0-9a-f:.]+/\d+$", text, re.I):
                raise ValueError("not a valid CIDR block")
            return None
        return int(net.network_address), int(net.broadcast_address), net.version
    if "-" in text:
        a, _, b = text.partition("-")
        a, b = a.strip(), b.strip()
        try:
            first = ipaddress.ip_address(a)
        except ValueError:
            return None
        if _digits(b) and first.version == 4:
            if int(b) > 255:
                raise ValueError("the range's last octet is over 255")
            last = ipaddress.ip_address(".".join(a.split(".")[:3] + [b]))
        else:
            try:
                last = ipaddress.ip_address(b)
            except ValueError:
                raise ValueError("the range's end is not an IP address")
        if last.version != first.version or int(last) < int(first):
            raise ValueError("the range ends before it starts")
        return int(first), int(last), first.version
    return None


_SCHEME_PORTS = {"http": 80, "ftp": 21}
_SCHEME_PROTO_PORTS = {"http": 80, "https": 443}


def _destination(text: str) -> Tuple[str, str, Optional[str], Optional[int]]:
    """(target, kind 'ip' or 'host', note, the URL's port) for one IP
    address, host name or URL; ValueError with the reason otherwise. The
    port is the URL's own (https://x:8443/) or its scheme's when that is
    not HTTPS (http:// is 80), as the single-destination analyzer reads it."""
    import path_analyzer
    t = text.strip()
    note = None
    if t.startswith("*.") or (t.startswith(".") and "/" not in t):
        t = t.lstrip("*.")
        note = f"wildcard tested as {t[:80]}"
    d = path_analyzer.parse_destination(t)
    if d["kind"] == "url":
        note = "tested by its host; the URL path is not evaluated"
    port = d["port"] or (_SCHEME_PORTS.get(d["scheme"]) if re.match(r"^[a-z][a-z0-9+.-]*://", t, re.I) else None)
    return d["host"], ("ip" if d["is_ip"] else "host"), note, port


class ParsedList:
    """The parsed list: entries (one per input line) and rows (one per
    destination after expansion), stored compactly."""

    def __init__(self) -> None:
        self.entries: List[Dict[str, Any]] = []
        self.targets: List[str] = []
        self.entry_of = array("i")
        self.is_ip = bytearray()
        self.row_notes: Dict[int, str] = {}
        self.skipped: List[Dict[str, Any]] = []
        self.skipped_count = 0
        self.lines = 0
        self.columns: List[str] = []

    def skip(self, line: int, text: str, why: str) -> None:
        self.skipped_count += 1
        if len(self.skipped) < SKIPPED_SHOWN:
            self.skipped.append({"line": line, "text": _cell(text, 120), "why": why})

    def __len__(self) -> int:
        return len(self.targets)


def parse(text: str) -> ParsedList:
    """The list as rows. ListError when it cannot be tested at all: too
    large, more than MAX_ROWS rows after expansion, or no destination."""
    if not isinstance(text, str):
        raise ListError("Send the list as text.")
    if len(text.encode("utf-8", errors="replace")) > MAX_TEXT_BYTES:
        raise ListError(f"The list is larger than {MAX_TEXT_BYTES // (1024 * 1024)} MB. Split it into smaller files.")
    out = ParsedList()
    text = text.lstrip("﻿").replace("\x00", "")
    columns: Optional[List[Optional[str]]] = None
    delim = None
    first = True
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        out.lines += 1
        if out.lines > MAX_LINES:
            raise ListError(f"The list has more than {MAX_LINES:,} lines. Split it into smaller files.")
        if len(line) > MAX_LINE_CHARS:
            out.skip(line_no, line, f"longer than {MAX_LINE_CHARS} characters")
            continue
        if delim is None:
            delim = _delimiter(line)
        cells = _split(line, delim)
        if cells is None or not any(cells):
            out.skip(line_no, line, "not a readable CSV line")
            continue
        if first:
            first = False
            keys = [_header_key(c) for c in cells]
            if "destination" in keys:
                columns = keys
                out.columns = sorted({k for k in keys if k})
                continue
        e = _entry(cells, columns, line_no)
        dest = e["input"]
        if not dest:
            out.skip(line_no, line, "no destination")
            continue
        try:
            rng = _ip_range(dest)
            if rng is None:
                target, kind, note, url_port = _destination(dest)
                if url_port and "port" not in e:
                    e["port"] = url_port
        except ValueError as ex:
            out.skip(line_no, dest, str(ex).split(". Examples")[0][:160])
            continue
        proto_port = e.pop("_proto_port", None)
        if proto_port and "port" not in e:
            e["port"] = proto_port
        idx = len(out.entries)
        if rng is not None:
            lo, hi, ver = rng
            n = hi - lo + 1
            if n > MAX_PER_ENTRY:
                out.skip(line_no, dest, f"{n:,} addresses: at most {MAX_PER_ENTRY:,} (a /16) per row")
                continue
            if len(out.targets) + n > MAX_ROWS:
                raise ListError(f"The list expands to more than {MAX_ROWS:,} rows. Split it into smaller files.")
            out.entries.append(e)
            make = ipaddress.IPv4Address if ver == 4 else ipaddress.IPv6Address
            for x in range(lo, hi + 1):
                out.targets.append(str(make(x)))
                out.entry_of.append(idx)
                out.is_ip.append(1)
            continue
        if len(out.targets) + 1 > MAX_ROWS:
            raise ListError(f"The list expands to more than {MAX_ROWS:,} rows. Split it into smaller files.")
        out.entries.append(e)
        if note:
            out.row_notes[len(out.targets)] = note
        out.targets.append(target)
        out.entry_of.append(idx)
        out.is_ip.append(1 if kind == "ip" else 0)
    if not out.targets:
        raise ListError("The list names no destination this view can test: give one IP address, CIDR block, range, host name or URL per line"
                        + (f" ({out.skipped_count} line(s) skipped, the first: {out.skipped[0]['why']})." if out.skipped else "."))
    return out


# ── ZIA's URL lookup, a hundred per request ─────────────────────────────

def _stopped(cancel: Any) -> bool:
    from data_flow import stop_requested
    return stop_requested(cancel)


def _wait(seconds: float, cancel: Any, sleep: Callable[[float], None]) -> None:
    left = max(0.0, min(float(seconds), WAIT_CAP))
    while left > 0:
        if _stopped(cancel):
            raise Stopped(STOPPED_REASON)
        step = min(0.5, left)
        sleep(step)
        left -= step
    if _stopped(cancel):
        raise Stopped(STOPPED_REASON)


def blank_lookup(error: Optional[str] = None) -> Dict[str, Any]:
    return {"categories": [], "security_alerts": [], "application": None, "error": error}


def _answer(entry: Dict[str, Any]) -> Dict[str, Any]:
    from path_analyzer import labels
    app = entry.get("application") or entry.get("app")
    if isinstance(app, dict):
        app = app.get("name") or app.get("id")
    app = str(app).upper() if app and isinstance(app, (str, int)) and str(app).lower() not in ("none", "null") else None
    return {"categories": labels(entry.get("urlClassifications") or entry.get("url_classifications"))[:20],
            "security_alerts": labels(entry.get("urlClassificationsWithSecurityAlert") or entry.get("url_classifications_with_security_alert"))[:20],
            "application": app, "error": None}


def _post(client, chunk: List[str]) -> Tuple[Any, int, Optional[float]]:
    """(data, status, retry-after seconds) of one lookup request; an SDK
    exception becomes its status (0 when it has none)."""
    lookup = getattr(client, "post")   # POST /urlLookup reads categories; it changes nothing (as path_analyzer.lookup_many)
    try:
        data, status = lookup("/zia/urlLookup", list(chunk))
        return data, int(status or 0), None
    except Stopped:
        raise
    except Exception as e:  # noqa: BLE001
        status = getattr(e, "status", None) or getattr(e, "status_code", None) or 0
        ra = getattr(e, "retry_after", None)
        try:
            ra = float(ra) if ra is not None else None
        except (TypeError, ValueError):
            ra = None
        return {"error": type(e).__name__}, int(status) if _digits(str(status)) else 0, ra


def _error_text(data: Any) -> str:
    return str(data.get("error") or data.get("message") or "")[:200] if isinstance(data, dict) else ""


def lookup_all(client, keys: Sequence[str], *, cancel: Any = None, log: LogFn = None, max_requests: int = DEFAULT_LOOKUP_REQUESTS,
               sleep: Callable[[float], None] = time.sleep) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """({key: lookup answer as path_analyzer.lookup_categories gives it},
    state). Every key gets an answer: one ZIA could not give carries the
    reason in `error` (QUOTA_LABEL, CAP_LABEL, DENIED_LABEL, STOPPED_LABEL
    or the HTTP status), never an invented category. Identical answers
    share one dict. Raises Stopped when Stop is clicked."""
    import zia_rate
    say = log or (lambda m: None)
    todo = list(dict.fromkeys(k for k in keys if k))
    out: Dict[str, Dict[str, Any]] = {}
    shared: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    state: Dict[str, Any] = {"destinations": len(todo), "looked_up": 0, "failed": 0, "requests": 0, "ok_requests": 0, "retries": 0,
                             "waited_seconds": 0.0, "stopped": None, "stopped_kind": None, "not_looked_up": 0}
    post = getattr(client, "post", None)
    if not callable(post):
        for k in todo:
            out[k] = blank_lookup("this client cannot run a URL lookup")
        state.update(failed=len(todo), stopped="This client cannot run ZIA's URL lookup.", stopped_kind="denied")
        return out, state
    rate_key = getattr(client, "rate_key", None) or getattr(client, "_zia_rate_key", None)

    def keep(k: str, lk: Dict[str, Any]) -> None:
        sig = (tuple(lk["categories"]), tuple(lk["security_alerts"]), lk["application"], lk["error"])
        out[k] = shared.setdefault(sig, lk)

    def end(kind: str, label: str, why: str, at: int) -> None:
        rest = todo[at:]
        for k in rest:
            keep(k, blank_lookup(label))
        state.update(stopped=why, stopped_kind=kind, not_looked_up=len(rest))

    def pause(seconds: float, why: str) -> None:
        held = max(zia_rate.paused_for(rate_key), zia_rate.paused_for(rate_key, reads=True)) if rate_key else 0.0
        seconds = max(seconds, min(held, WAIT_CAP))
        say(f"{why} Waiting {int(seconds)} s before the next lookup.")
        state["waited_seconds"] += seconds
        _wait(seconds, cancel, sleep)

    queue: List[List[str]] = [todo[i:i + LOOKUP_CHUNK] for i in range(0, len(todo), LOOKUP_CHUNK)]
    done = 0
    transient = rate = refused = 0
    total = len(queue)
    say(f"Asking ZIA which categories {len(todo):,} destination(s) belong to: {total:,} lookup request(s) of up to {LOOKUP_CHUNK}, "
        f"paced for ZIA's rate limit (at most {max_requests:,} in this run).")
    while queue:
        if _stopped(cancel):
            end("stopped", STOPPED_LABEL, STOPPED_REASON, done)
            raise Stopped(STOPPED_REASON)
        chunk = queue[0]
        if state["requests"] >= max_requests:
            end("cap", CAP_LABEL, f"This run's limit of {max_requests:,} lookup requests was reached; {len(todo) - done:,} destination(s) were not "
                                  "looked up. Rerun later, or raise the limit, to look them up.", done)
            say(state["stopped"])
            break
        state["requests"] += 1
        data, status, retry_after = _post(client, chunk)
        if _stopped(cancel):
            end("stopped", STOPPED_LABEL, STOPPED_REASON, done)
            raise Stopped(STOPPED_REASON)
        if status in (200, 201) and isinstance(data, list):
            entries = [e for e in data if isinstance(e, dict)]
            from path_analyzer import _lookup_key
            by_url = {_lookup_key(e.get("url")): e for e in entries if e.get("url")}
            for pos, k in enumerate(chunk):
                e = by_url.get(_lookup_key(k)) if by_url else (entries[pos] if pos < len(entries) else None)
                if e is None:
                    keep(k, blank_lookup("the URL lookup returned no answer for it"))
                    state["failed"] += 1
                else:
                    keep(k, _answer(e))
                    state["looked_up"] += 1
            queue.pop(0)
            done += len(chunk)
            state["ok_requests"] += 1
            transient = rate = refused = 0
            if state["requests"] % 10 == 0 or not queue:
                say(f"Looked up {done:,} of {len(todo):,} destination(s).")
            continue
        err = _error_text(data)
        low = err.lower()
        if status == 429 and ("hour" in low or "quota" in low):
            end("quota", QUOTA_LABEL, f"ZIA's hourly lookup quota was reached after {done:,} destination(s); the other {len(todo) - done:,} were "
                                      "not looked up. Rerun later to look them up.", done)
            say(state["stopped"])
            break
        if status == 429:
            if rate < len(RATE_WAITS):
                state["retries"] += 1
                pause(retry_after or RATE_WAITS[rate], f"ZIA asked to slow down (HTTP 429, retry {rate + 1} of {len(RATE_WAITS)}).")
                rate += 1
                continue
            end("quota", QUOTA_LABEL, f"ZIA kept refusing lookups for its rate limit after {done:,} destination(s); the other {len(todo) - done:,} "
                                      "were not looked up. Rerun later to look them up.", done)
            say(state["stopped"])
            break
        if status in (401, 403):
            if not state["ok_requests"]:
                end("denied", DENIED_LABEL, f"ZIA refused the URL lookup (HTTP {status}): this API client may not run it. The rows are placed by the "
                                            "tenant's own custom categories and the file's category column only.", done)
                say(state["stopped"])
                break
            if refused < len(REFUSED_WAITS):
                state["retries"] += 1
                pause(REFUSED_WAITS[refused], f"ZIA refused a lookup (HTTP {status}) after {state['ok_requests']} worked: probably a lookup quota "
                                              f"(retry {refused + 1} of {len(REFUSED_WAITS)}).")
                refused += 1
                continue
            end("quota", QUOTA_LABEL, f"ZIA kept refusing lookups (HTTP {status}) after {done:,} destination(s), probably a lookup quota; the other "
                                      f"{len(todo) - done:,} were not looked up. Rerun later to look them up.", done)
            say(state["stopped"])
            break
        if status == 400 and len(chunk) > 1:
            half = len(chunk) // 2   # one bad entry refuses the whole request: find it
            queue[0:1] = [chunk[:half], chunk[half:]]
            continue
        if (status in (0, 408, 412) or status >= 500) and transient < len(TRANSIENT_WAITS):
            state["retries"] += 1
            pause(retry_after or TRANSIENT_WAITS[transient], f"ZIA asked to retry the lookup (HTTP {status or 'no answer'}, retry {transient + 1} "
                                                             f"of {len(TRANSIENT_WAITS)}).")
            transient += 1
            continue
        why = f"the URL lookup answered HTTP {status}" + (f": {err}" if err else "") if status else "the URL lookup got no answer"
        for k in chunk:
            keep(k, blank_lookup(why))
        state["failed"] += len(chunk)
        queue.pop(0)
        done += len(chunk)
        transient = 0
        say(f"{len(chunk)} destination(s) not looked up: {why}.")
    return out, state


# ── Evaluators ──────────────────────────────────────────────────────────
#
# An evaluator answers for its policy area(s), one row at a time. It is
# built once per run by a factory called with keyword arguments (client,
# scope, network, platform, snapshot, packs, zpa, log, cancel) and has:
#   key, label        a short id and what it evaluates
#   precedence        lower decides first when two evaluators decide
#   prepare()         reads the tenant once (raises Stopped on Stop)
#   evaluate(row)     a result dict (see _result) or None when the row is
#                     not its business (a web-only evaluator and ICMP, say)
# A row is a dict: target, host, is_ip, private, port, protocol, source_ip,
# location, dest_country, user, group, department, lookup (the lookup
# answer or None).

def _result(**kw: Any) -> Dict[str, Any]:
    r = {"result": "allowed", "area": "", "action": "", "rule": "", "stops_at": "", "inspection": "", "headline": "", "blockable_by": [],
         "categories": [], "security_alerts": [], "application": None, "notes": [], "evaluator": "", "segment": ""}
    r.update(kw)
    return r


# The area a deciding hop belongs to (data_flow.trace's hops and the ZIA
# modules zia_path_modules.extend_trace draws as hops).
_HOP_AREA = {"zcc": "Client Connector", "forwarding": "Client Connector", "pac": "Client Connector", "url": "URL", "cac": "Cloud App",
             "atp": "ATP", "firewall": "Firewall", "dns": "DNS"}
_BLOCKING = ("BLOCK", "BLOCK_RESET", "DROP")
_MODULE_LABEL = {"atp": "Advanced Threat Protection", "firewall": "Cloud Firewall", "dns": "DNS Control"}
ICMP_NOTE = ("ICMP is not traced: the Path analyzer evaluates TCP and UDP. Check the Cloud Firewall's rules for ICMP in the ZIA Admin Portal.")
ANY_NOTE = "Protocol 'any' traced as TCP."
ZIA_NOT_IN_SCOPE = ("Reaches ZIA; what ZIA does with it is not assessed: no ZIA part is in scope. Put ZIA policy in scope on the Scope page "
                    "and test again to assess it.")
_PROTO_ARG = {"TCP": "tcp", "UDP": "udp"}


def _rule_blocks(r: Dict[str, Any]) -> bool:
    act = str(r.get("action") or "").upper()
    acts = [str(a).upper() for a in r.get("actions") or []]
    return act in _BLOCKING or act.startswith("BLOCK") or any(a.startswith("BLOCK") for a in acts)


def _context_only(o: Dict[str, Any]) -> bool:
    """A rule whose every unknown criterion is about who, where, when or
    which device (a user, a location, a time window, device trust, a source
    address): it matches this destination and traffic, but applies only in
    some contexts. A rule unknown on the destination itself (no category
    known, a host name against address ranges) is not counted."""
    from zia_path_modules import UNEVALUATED
    ctx = {label for _, label, _ in UNEVALUATED} | {"Source IP"}
    unknown = [c for c in o.get("criteria") or [] if c.get("state") == "unknown"]
    return bool(unknown) and all(c.get("name") in ctx for c in unknown)


def _module_blockable(mods: Dict[str, Dict[str, Any]]) -> List[str]:
    """Rules of Advanced Threat Protection, the Cloud Firewall and DNS
    Control that could still block a row they did not block: a block an
    earlier rule might override, or an earlier block rule that matches the
    destination but applies only in some contexts (_context_only)."""
    out: List[str] = []
    for k in ("atp", "firewall", "dns"):
        m = mods.get(k) or {}
        if m.get("status") != "evaluated":
            continue
        if m.get("verdict") == "block" and m.get("certainty") == "conditional" and (m.get("rule") or {}).get("name"):
            out.append(str(m["rule"]["name"]))
        elif m.get("verdict") != "block":
            out += [str(o.get("name")) for o in m.get("could_override") or [] if o.get("verdict") == "block" and o.get("name") and _context_only(o)]
    return out


def summarize_analysis(res: Dict[str, Any]) -> Dict[str, Any]:
    """One row's result from a path_analyzer.analyze() answer: the deciding
    module names the area (Client Connector, ATP, Cloud Firewall, DNS
    Control, Cloud App Control, URL filtering)."""
    import path_analyzer
    v = res.get("verdict") or {}
    t = res.get("trace") or {}
    hops = t.get("hops") or []
    outcome = v.get("outcome") or ""
    stop = next((h for h in hops if h.get("status") in ("bypass", "blocked")), None)
    url = next((h for h in hops if h.get("key") == "url"), {})
    name = lambda h: str(((h or {}).get("decided_by") or {}).get("name") or "")  # noqa: E731
    lk = res.get("lookup") or {}
    zm = res.get("zia_modules") or {}
    mods = {m.get("key"): m for m in zm.get("modules") or []}
    traffic = zm.get("traffic") or {}
    web = traffic.get("web", True)
    base = dict(categories=list(v.get("categories") or []), security_alerts=list(lk.get("security_alerts") or []),
                application=lk.get("application"), inspection=path_analyzer.BATCH_OUTCOMES.get(outcome, outcome or "unverified"),
                headline=v.get("headline") or "", evaluator="path")
    blockable = [str(r.get("name")) for h in hops if h.get("status") == "conditional" and h.get("key") in ("url", "cac")
                 for r in h.get("candidate_rules") or [] if isinstance(r, dict) and r.get("name") and _rule_blocks(r)]
    blockable = list(dict.fromkeys(blockable + _module_blockable(mods)))
    if outcome == "bypassed" and stop:
        return _result(result="bypassed", area="Client Connector", action="BYPASS", rule=name(stop), stops_at=stop.get("label") or "", **base)
    if outcome == "blocked" and stop:
        action = str((stop.get("decided_by") or {}).get("action") or "BLOCK")
        return _result(result="blocked", area=_HOP_AREA.get(stop.get("key"), "URL"), action=action if isinstance(action, str) else "BLOCK",
                       rule=name(stop), stops_at=stop.get("label") or "", **base)
    if t.get("conditional"):
        return _result(result="unverified", area="", blockable_by=blockable, notes=["how the device reaches Zscaler could not be verified"], **base)
    if not web:
        # Not web: only the Cloud Firewall decides (DNS Control and ATP
        # block first when they do; that is the `blocked` case above).
        fw = mods.get("firewall") or {}
        r = fw.get("rule") or {}
        label = traffic.get("label") or "this traffic"
        if fw.get("status") == "out_of_scope":
            return _result(result="unverified", area="Firewall", blockable_by=blockable,
                           notes=["Cloud Firewall: not in scope on the Scope page, so not assessed."], **dict(base, inspection="not in scope"))
        if fw.get("verdict") == "unknown" or fw.get("status") != "evaluated":
            return _result(result="unverified", area="Firewall", blockable_by=blockable,
                           notes=[f"Cloud Firewall: {(fw.get('detail') or 'not established').rstrip('.')}."], **base)
        if fw.get("verdict") == "block":   # a block an earlier rule might override: not certain either way
            return _result(result="unverified", area="Firewall", rule=str(r.get("name") or ""), action=str(r.get("action") or ""), blockable_by=blockable,
                           notes=[f"Cloud Firewall: {fw.get('reason') or 'an earlier rule with a condition this tool cannot evaluate could decide instead'}."],
                           **base)
        return _result(result="allowed", area="Firewall", action=str(r.get("action") or "ALLOW"), rule=str(r.get("name") or ""),
                       stops_at="reaches the destination", blockable_by=blockable, **dict(base, inspection=f"not inspected ({label} is not web)"))
    act = str((url.get("decided_by") or {}).get("action") or "").upper()
    if url.get("status") == "warn" and act == "CAUTION":
        return _result(result="caution", area="URL", action="CAUTION", rule=name(url), stops_at="URL filtering", blockable_by=blockable, **base)
    if url.get("status") == "warn" and "ISOLATE" in act:
        return _result(result="isolated", area="URL", action="ISOLATE", rule=name(url), stops_at="URL filtering", blockable_by=blockable, **base)
    if url.get("status") == "unknown":
        return _result(result="unverified", area="URL", action="", rule="", stops_at="", blockable_by=blockable,
                       notes=["the URL filtering rules could not be read"], **base)
    deciding = name(url) if url.get("status") in ("pass", "warn") else ""
    return _result(result="allowed", area="URL" if url else "", action=act or "ALLOW", rule=deciding, stops_at="reaches the destination",
                   blockable_by=blockable, **base)


def summarize_zpa(st: Dict[str, Any], rep: str = "", host: str = "") -> Optional[Dict[str, Any]]:
    """One row's result when ZPA carries it (zpa_path.stage with carries
    True): allowed or denied by the access policy, or unverified when it
    depends on who the user is. None when ZPA does not carry it."""
    if st.get("carries") is not True:
        return None
    seg = str((st.get("segment") or {}).get("name") or "")
    acc = next((m for m in st.get("modules") or [] if m.get("key") == "zpa_access"), {})
    rule = str((acc.get("rule") or {}).get("name") or "")
    head = str(st.get("headline") or "")
    if rep and host and rep != host:
        head = head.replace(rep, host)
    base = dict(area="ZPA", segment=seg, headline=head, inspection="carried by ZPA (ZIA does not apply)", evaluator="zpa")
    if st.get("outcome") == "zpa_allowed":
        notes = ["ZPA allows it, but no App Connector serving the segment is connected, so the connection fails."] if st.get("reachable") is False else []
        return _result(result="allowed", action="ALLOW", rule=rule, stops_at="reaches the application through ZPA", notes=notes, **base)
    if st.get("outcome") == "zpa_denied":
        return _result(result="blocked", action="DENY", rule=rule or "ZPA default deny", stops_at="ZPA access policy", **base)
    return _result(result="unverified", action="", rule="", stops_at="ZPA", notes=[head], **base)


def _net(entry: str) -> Optional[Tuple[int, int, int]]:
    """(IP version, first, last) for an address, CIDR block or a-b range."""
    try:
        if "-" in entry:
            a, b = (ipaddress.ip_address(x.strip()) for x in entry.split("-", 1))
            return (a.version, int(a), int(b)) if a.version == b.version else None
        n = ipaddress.ip_network(entry, strict=False)
        return n.version, int(n.network_address), int(n.broadcast_address)
    except ValueError:
        return None


class _HostIndex:
    """Every host, domain, wildcard and address entry of the tenant's lists
    that name destinations (Client Connector bypasses, PAC DIRECT patterns,
    custom URL categories, the ATP lists, Cloud Firewall and DNS Control
    destinations). `match` answers which entries a destination is related
    to and how (the host itself, a subdomain of it, a wildcard, inside an
    address range): destinations with the same answer are traced alike."""

    def __init__(self, entries: Iterable[Any]) -> None:
        self.names: Dict[str, List[str]] = {}
        self.nets: List[Tuple[int, int, int, str]] = []
        self.globs: List[Tuple[str, str]] = []
        # Every address between two consecutive range ends is in the same
        # entries: one bisect finds that stretch, and its entries are worked
        # out once (a list of 250,000 addresses against a group of thousands
        # of networks is not 250,000 scans of every network).
        self._ends: Dict[int, List[int]] = {}
        self._in: Dict[Tuple[int, int], frozenset] = {}
        for raw in entries:
            self._add(str(raw or "").strip())

    def __bool__(self) -> bool:
        return bool(self.names or self.nets or self.globs)

    def _add(self, raw: str) -> None:
        if not raw:
            return
        low = raw.lower()
        net = _net(low)
        if net is not None:
            self.nets.append((net[0], net[1], net[2], raw))
            return
        h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", low).split("/", 1)[0]
        if h.count(":") == 1:
            h = h.split(":", 1)[0]
        h = h.rstrip(".")   # "example.com." is example.com, as ZIA's lists read it
        body = h[2:] if h.startswith("*.") else h
        if any(ch in body for ch in "*?[]"):
            self.globs.append((h, raw))
            return
        from zia_path_modules import entry_host
        key = entry_host(h.lstrip("*").lstrip("."))   # an IDN entry as rows hold it (punycode)
        if key:
            self.names.setdefault(key, []).append(raw)

    def match(self, host: str, ip: Any = None) -> frozenset:
        out = set()
        if ip is not None and self.nets:
            ver, n = ip.version, int(ip)
            ends = self._ends.get(ver)
            if ends is None:
                ends = self._ends[ver] = sorted({x for v, lo, hi, _ in self.nets if v == ver for x in (lo, hi + 1)})
            stretch = (ver, bisect.bisect_right(ends, n))
            hit = self._in.get(stretch)
            if hit is None:
                hit = self._in[stretch] = frozenset((raw, "in") for v, lo, hi, raw in self.nets if v == ver and lo <= n <= hi)
            out |= hit
        if self.names:
            parts = host.split(".")
            for i in range(len(parts)):
                for raw in self.names.get(".".join(parts[i:]), ()):
                    out.add((raw, "eq" if i == 0 else "sub"))
        for pat, raw in self.globs:
            if fnmatch.fnmatch(host, pat):
                out.add((raw, "glob"))
        return frozenset(out)


def _strings(v: Any) -> List[str]:
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if isinstance(x, (str, int))]
    return []


def _identity_raw(row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The row's identity as the Path analyzer's what-if takes it (a group
    cell may name several groups, separated by ; or |), or None."""
    if not any(row.get(k) for k in ("user", "group", "department", "location")):
        return None
    groups = [g.strip() for g in re.split(r"[;|]", str(row.get("group") or "")) if g.strip()]
    return {"user": row.get("user") or None, "groups": groups, "department": row.get("department") or None, "location": row.get("location") or None}


class PathEvaluator:
    """The Path analyzer's evaluation, the same answer the single-destination
    analyzer gives: ZPA first when it is in scope (zpa_path.stage), then
    path_analyzer.analyze for the row's protocol and port, source IP and
    identity: Client Connector app and forwarding profiles, the PAC file
    (pac_eval), Advanced Threat Protection, Cloud Firewall, DNS Control,
    Cloud App Control, URL filtering, SSL inspection, Sandbox, File Type
    Control and DLP, against one tenant read. Destinations that relate to
    the tenant's destination lists in the same way (_HostIndex), get the
    same PAC answer, share their categories, traffic, identity and source
    address trace identically, so they are traced once and share the
    answer; ZPA's answer is shared per application segment and port."""

    key = "path"
    label = ("Path analyzer: ZPA, Client Connector and PAC, Advanced Threat Protection, Cloud Firewall, DNS Control, Cloud App Control, "
             "URL filtering, SSL inspection, Sandbox, File Type Control, DLP")
    precedence = 50

    def __init__(self, *, client, scope: Dict[str, Any], network: str = "off", platform: str = "windows",
                 snapshot: Optional[Dict[str, Any]] = None, packs: Optional[List[Dict[str, Any]]] = None, log: LogFn = None,
                 cancel: Any = None, zpa: Optional[Dict[str, Any]] = None, **_: Any) -> None:
        self.client, self.scope, self.network, self.platform = client, scope, network, platform
        self.snapshot = snapshot
        self.fresh: Optional[Dict[str, Any]] = None
        self.packs = packs
        self.log = log or (lambda m: None)
        self.cancel = cancel
        # zpa: None (ZPA not in scope), {"problem": why} (in scope, not
        # readable), {"snapshot", "profiles"} (a kept read) or {"client",
        # "mask"} (read it in prepare).
        self.zpa_in = zpa
        self.zsnap: Optional[Dict[str, Any]] = None
        self.zprofiles: Optional[List[Dict[str, Any]]] = None
        self.zpa_fresh: Optional[Dict[str, Any]] = None
        self.zpa_note: Optional[str] = None
        self.zpa_state = "not_in_scope" if not zpa else "not_read"
        self._zpa_cache: Dict[Tuple[Any, ...], Tuple[str, Dict[str, Any]]] = {}
        self._zidx: Optional[_HostIndex] = None
        self._shared: Dict[Tuple[Any, ...], Tuple[str, Dict[str, Any]]] = {}
        self._index: Optional[Tuple[_HostIndex, Optional[_HostIndex], set, List[str]]] = None
        self.traced = 0

    def prepare(self, first_host: str) -> None:
        """Read the tenant once (or take the kept reads), only what is in
        scope: ZPA when it is ticked, then ZIA's parts in scope."""
        import path_analyzer
        self._prepare_zpa()
        if not self.scope.get("read"):
            return
        if self.packs is None:
            from data_flow import load_packs
            self.packs = load_packs()
        if self.snapshot is not None and path_analyzer.reusable(self.snapshot, self.scope, self.platform):
            self.log("Using the tenant configuration read a moment ago for the same scope.")
            return
        self.snapshot = None
        self.log("Reading the tenant once for every row (only what is in scope)…")
        try:
            res = path_analyzer.analyze(self.client, first_host, self.network, self.platform, scope=self.scope, log=self.log,
                                        cancel=self.cancel, lookup=blank_lookup() if self.scope.get("lookup") else None, packs=self.packs)
        except path_analyzer.Stopped:
            raise Stopped(STOPPED_REASON)
        self.fresh = res.pop("snapshot_for_cache", None)
        self.snapshot = self.fresh

    def _prepare_zpa(self) -> None:
        z = self.zpa_in
        if not z:
            return
        import zpa_analysis
        import zpa_path
        if z.get("problem"):
            self.zpa_note = str(z["problem"])
            self.log(self.zpa_note)
            return
        if z.get("snapshot") is not None:
            self.zsnap, self.zprofiles = z["snapshot"], z.get("profiles")
            self.zpa_state = "kept"
            self.log("Using the ZPA configuration read a moment ago.")
        elif z.get("client") is not None:
            mask = z.get("mask") or (lambda s: s)
            self.log("Reading ZPA first: application segments, client forwarding and access policies…")
            try:
                self.zsnap, self.zprofiles = zpa_path.read(z["client"], log=self.log, cancel=self.cancel)
            except zpa_path.Stopped:
                raise Stopped(STOPPED_REASON)
            except zpa_path.ReadError as e:
                self.zpa_note = "ZPA could not be read (" + mask(str(e))[:160] + "), so whether ZPA carries each row is unknown."
                self.log(self.zpa_note)
                return
            self.zpa_fresh = {"snapshot": self.zsnap, "profiles": self.zprofiles}
            self.zpa_state = "read"
        if self.zsnap is not None and not zpa_analysis._Index(self.zsnap).read("segments"):
            self.zpa_note = "The ZPA application segments could not be read, so whether ZPA carries each row is unknown."
            self.zsnap = None
        if self.zsnap is not None:
            # Every segment's domains, so a row no entry can match (zpa_analysis
            # matches the host, a wildcard suffix, an address range or "*")
            # skips the segment walk.
            self._zidx = _HostIndex(e for sg in zpa_analysis._lst(self.zsnap, "segments") for e in sg.get("domains") or [])

    # The lists that make a destination's trace depend on the destination itself.
    def _build_index(self) -> Tuple[_HostIndex, Optional[_HostIndex], set, List[str]]:
        from data_flow import TRAFFIC_CLASSES
        from zia_path_modules import _f
        snap = self.snapshot or {}
        zcc = snap.get("client_connector") or {}
        dest: List[Any] = []
        for p in zcc.get("app_profiles") or []:
            dest += list(((p or {}).get("bypass") or {}).get("domains") or [])
        pacs: List[str] = []
        for f in zcc.get("pac_files") or []:
            dest += list((f or {}).get("direct_hosts") or [])
            src = (f or {}).get("source")
            if isinstance(src, str) and src and src not in pacs:
                pacs.append(src)
        zia = (snap.get("snapshot") or {}).get("zia") or {}
        cats = ((snap.get("snapshot") or {}).get("categories") or {})
        for c in cats.values():
            if isinstance(c, dict):
                dest += list(c.get("urls") or []) + list(c.get("db_categorized_urls") or c.get("dbCategorizedUrls") or [])
        mods = zia.get("modules") or {}
        part = lambda sec, p: (((mods.get(sec) or {}).get("parts") or {}).get(p) or {}).get("data")  # noqa: E731
        for p, k in (("exceptions", "bypassUrls"), ("malicious", "maliciousUrls"), ("allowlist", "whitelistUrls"), ("denylist", "blacklistUrls")):
            d = part("atp", p)
            dest += _strings(_f(d, k)) if isinstance(d, dict) else _strings(d)
        src_entries: List[Any] = []
        for r in part("firewall", "rules") or []:
            dest += _strings(_f(r, "destAddresses"))
            src_entries += _strings(_f(r, "srcIps"))
        for g in part("firewall", "ip_destination_groups") or []:
            dest += _strings(_f(g, "addresses"))
        for g in part("firewall", "ip_source_groups") or []:
            src_entries += _strings(_f(g, "ipAddresses"))
        for r in part("dns", "rules") or []:
            dest += _strings(_f(r, "destAddresses"))
        names = {str(k).upper() for k in cats} | {str(k["key"]).upper() for k in TRAFFIC_CLASSES} | {str(k["label"]).upper() for k in TRAFFIC_CLASSES}
        for lst in (zia.get("catalogue") or {}).values():
            names |= {str(a).upper() for a in lst or []}
        if pacs and not self._pac_in_play():
            pacs = []
        return _HostIndex(dest), (_HostIndex(src_entries) if src_entries else None), names, pacs

    def _pac_in_play(self) -> bool:
        """Whether the PAC file is evaluated on this platform and network at
        all: one trace of a name no tenant list holds (against the read
        already made, no request) says whether the path has a PAC step that
        pac_eval answered. Only then does each row's PAC answer matter."""
        import path_analyzer
        try:
            res = path_analyzer.analyze(self.client, "pac-probe.invalid", self.network, self.platform, scope=self.scope, snapshot=self.snapshot,
                                        cancel=self.cancel, lookup=blank_lookup() if self.scope.get("lookup") else None, packs=self.packs)
        except path_analyzer.Stopped:
            raise Stopped(STOPPED_REASON)
        return any(h.get("key") == "pac" and ("pac_outcomes" in h or h.get("status") in ("unknown", "out_of_scope"))
                   for h in (res.get("trace") or {}).get("hops") or [])

    def _fingerprint(self, host: str, is_ip: bool, protocol: Optional[str] = None, port: Optional[int] = None) -> Tuple[Any, ...]:
        """How `host` relates to the tenant's destination lists, and what
        each PAC file answers for it (pac_eval: evaluated, never run) for
        the URL the browser would hand it on this row's protocol and port
        (path_analyzer.pac_url, as the single-destination analyzer)."""
        import pac_eval
        import path_analyzer
        import zia_path_modules
        if self._index is None:
            self._index = self._build_index()
        dest, _src, names, pacs = self._index
        ip = ipaddress.ip_address(host) if is_ip else None
        named = host.upper() in names or host.upper().replace(" ", "_") in names
        pac: List[Any] = []
        if pacs:
            d = path_analyzer.parse_destination(host)
            url = path_analyzer.pac_url(d, zia_path_modules.traffic_context(d, protocol, port))
        for src in pacs:
            ev = pac_eval.evaluate(src, url, host, dns="none" if pac_eval._is_ipv4(host) else "assume_public")
            pac.append((ev.get("status"), ev.get("error"), tuple((o.get("kind"), o.get("result"), o.get("fallback_direct")) for o in ev.get("outcomes") or []),
                        tuple(ev.get("depends_on") or ()), tuple(ev.get("assumptions") or ())))
        return (dest.match(host, ip), host if named else None, tuple(pac))

    def _source_fp(self, src: Optional[str]) -> Any:
        if not src:
            return None
        if self._index is None:
            self._index = self._build_index()
        idx = self._index[1]
        if idx is None:
            return None    # no source condition anywhere: the address cannot change the answer
        try:
            return idx.match("", ipaddress.ip_address(src))
        except ValueError:
            return None

    def evaluate(self, row: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        proto = row.get("protocol") or ""
        if proto == "ICMP":
            return _result(result="unverified", inspection="not traced", notes=[ICMP_NOTE], evaluator="path")
        p = _PROTO_ARG.get(proto)
        port = row.get("port") or None
        extra = [ANY_NOTE] if proto == "ANY" else []
        out, note = self._zpa(row, p, port)
        if out is None:
            out = self._zia(row, p, port)
        if note:
            extra.append(note)
        if extra:
            out = dict(out, notes=list(out.get("notes") or []) + [n for n in extra if n not in (out.get("notes") or [])])
        return out

    def _zpa(self, row: Dict[str, Any], p: Optional[str], port: Optional[int]) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """(the row's result when ZPA carries it, else None; a note when ZPA
        matched it but does not carry it, may carry it, or was not read)."""
        if self.zsnap is None:
            return None, None   # ZPA not in scope, or not read: said once in the assumptions, not on every row
        import zpa_analysis
        import zpa_path
        host = row["host"]
        if self._zidx is not None and not self._zidx.match(host, ipaddress.ip_address(host) if row.get("is_ip") else None):
            return None, None
        try:
            d = zpa_path.destination(host, port, p or "tcp")
        except ValueError:
            return None, None
        sm = zpa_analysis.match_segment(self.zsnap, d)
        if not sm["match"]:
            return None, None
        key = (sm["match"]["id"], d["protocol"], d["port"], bool(d.get("port_assumed")))
        hit = self._zpa_cache.get(key)
        if hit is None:
            st = zpa_path.stage(self.zsnap, d, network=self.network, platform=self.platform, profiles=self.zprofiles)
            hit = (host, st)
            self._zpa_cache[key] = hit
        rep, st = hit
        out = summarize_zpa(st, rep, host)
        if out is not None:
            return out, None
        head = str(st.get("headline") or "").replace(rep, host)
        if st.get("outcome") == "zpa_conditional":
            return None, "ZPA may carry it (" + head.rstrip(".") + "); when it does not, ZIA applies as shown."
        return None, head

    def _zia(self, row: Dict[str, Any], p: Optional[str], port: Optional[int]) -> Dict[str, Any]:
        import path_analyzer
        import path_whatif
        if not self.scope.get("read"):
            return _result(result="unverified", inspection="not in scope", notes=[ZIA_NOT_IN_SCOPE], evaluator="path")
        host = row["host"]
        is_ip = bool(row.get("is_ip"))
        lk = row.get("lookup")
        lookup = (lk or blank_lookup()) if self.scope.get("lookup") else None
        ident = _identity_raw(row)
        src = row.get("source_ip") or None
        l2 = lookup or {}
        # The address family matters too: an IPv4 address is never in an IPv6
        # group, while an IPv6 one depends on the group's members.
        sig = (ipaddress.ip_address(host).version if is_ip else None, bool(row.get("private")), self._fingerprint(host, is_ip, p, port), tuple(l2.get("categories") or ()), tuple(l2.get("security_alerts") or ()),
               l2.get("application"), bool(l2.get("error")), p or "tcp", port, path_whatif.describe(path_whatif.normalize_identity(ident)),
               self._source_fp(src))
        hit = self._shared.get(sig)
        if hit is not None:
            rep, res = hit
            out = dict(res)
            out["headline"] = res["headline"].replace(rep, host)
            return out
        try:
            res = path_analyzer.analyze(self.client, host, self.network, self.platform, scope=self.scope, snapshot=self.snapshot,
                                        cancel=self.cancel, lookup=lookup, packs=self.packs, protocol=p, port=port, identity=ident,
                                        context={"source_ip": src} if src else None)
        except path_analyzer.Stopped:
            raise Stopped(STOPPED_REASON)
        self.traced += 1
        res.pop("snapshot_for_cache", None)
        out = summarize_analysis(res)
        if lk and lk.get("error"):
            out["notes"] = list(out["notes"]) + [str(lk["error"])]
        self._shared[sig] = (host, out)
        return out


EVALUATORS: List[Callable[..., Any]] = [PathEvaluator]


def register(factory: Callable[..., Any]) -> None:
    """Add an evaluator for another policy area (see the comment above
    _result). It is built for every later run."""
    if factory not in EVALUATORS:
        EVALUATORS.append(factory)


def combine(results: Iterable[Tuple[int, Dict[str, Any]]]) -> Dict[str, Any]:
    """One row's answer from every evaluator's: (precedence, result) pairs.
    The first (lowest precedence) that decides (blocks, bypasses, isolates,
    cautions) wins; else unverified when any could not tell; else
    allowed. Rules that could block an allowed row are kept from all."""
    rs = sorted(((p, r) for p, r in results if r), key=lambda x: x[0])
    if not rs:
        return _result(result="unverified", notes=["no evaluator answered for this row"])
    win = next((r for _, r in rs if r["result"] in DECIDING), None) or next((r for _, r in rs if r["result"] == "unverified"), None) or rs[0][1]
    out = dict(win)
    if out["result"] not in DECIDING:
        out["blockable_by"] = sorted({b for _, r in rs for b in r.get("blockable_by") or []})
    return out


# ── Recommendations ─────────────────────────────────────────────────────

def category_kind(cat: str, alerts: Sequence[str] = ()) -> str:
    """'threat', 'low_collateral', 'broad' or 'none'."""
    if not cat:
        return "none"
    if cat in THREAT_CATEGORIES or cat in alerts:
        return "threat"
    if cat in LOW_COLLATERAL:
        return "low_collateral"
    return "broad"


def _ref(rule: str) -> str:
    return f"'{rule}'" if rule else "the rule that decides it"


def recommend(row: Dict[str, Any]) -> Tuple[str, str, str]:
    """(meets 'yes'/'no'/'', recommended area, recommendation) for one row
    view (expected, result, area, rule, categories, ...). The area is the
    module that decided the row where one did: the Cloud Firewall for
    traffic it decides (an IP destination group), URL filtering for web
    traffic (a custom URL category), ZPA for traffic ZPA carries (its
    segment and access policy)."""
    expected = row.get("expected") or ""
    res = row.get("result") or ""
    if not expected or res in ("", "not tested", "unverified"):
        return "", "", ("" if not expected else "Not decided: " + (row.get("notes") or "the row could not be tested") + ".")
    cats = [c for c in str(row.get("category") or "").split("; ") if c]
    alerts = [c for c in str(row.get("security_alert") or "").split("; ") if c]
    is_ip = bool(row.get("is_ip"))
    port = row.get("port")
    non_web = (row.get("protocol") in ("UDP", "ICMP")) or (isinstance(port, int) and port not in WEB_PORTS)
    rule, area = row.get("rule") or "", row.get("area") or ""
    seg = row.get("segment") or ""
    group = "an IP destination group" if is_ip else "an IP destination group of type FQDN"
    if expected == "BLOCK":
        if res == "blocked":
            return "yes", "", f"Already blocked by {AREA_LABELS.get(area, area)} rule {_ref(rule)}."
        if res == "bypassed":
            if row.get("private"):
                return "no", "Client Connector", ("A private address: Client Connector keeps it on the local network, so ZIA never sees it. If it is an "
                                                  "internal application, publish it in ZPA with an access rule that allows only the right users; otherwise "
                                                  "block it on the internal firewall.")
            return "no", "Client Connector", (f"Client Connector sends it direct ({_ref(rule)}), so ZIA never sees it. Remove it from the bypass, or block "
                                              "it upstream if the bypass must stay.")
        if area == "ZPA":
            return "no", "ZPA", (f"ZPA carries it through application segment '{seg}' and access rule {_ref(rule)} allows it, so ZIA never sees it. "
                                 "Deny it with a ZPA access rule for that segment above that rule, or take it out of the segment so ZIA's policy "
                                 "applies.")
        if res in ("isolated", "caution"):
            return "no", "URL", f"{res.capitalize()}, not blocked, by {_ref(rule)}. Change that rule's action to Block, or add a Block rule above it."
        threat = next((c for c in alerts + cats if category_kind(c, alerts) == "threat"), None)
        if threat:
            return "no", "ATP", (f"ZIA classifies it as a threat ({threat}). Turn on the matching Advanced Threat Protection setting, which blocks it for "
                                 "every user without a list, or add it to the ATP denylist.")
        if row.get("blockable_by"):
            first = row["blockable_by"].split("; ")[0]
            if area == "Firewall":
                return "no", "Firewall", (f"Cloud Firewall rule {_ref(first)} could block it but depends on a condition this tool cannot evaluate (a time "
                                          "window, a user, a location ...). Check that rule's criteria cover this traffic.")
            return "no", "URL", (f"Rule {_ref(first)} would block it but applies only to some users, locations or "
                                 "request methods. Check that rule's criteria cover everyone who should be blocked.")
        broad = f" Do not block the category {cats[0]}: it would block legitimate sites too." if cats else ""
        if area == "Firewall":
            return "no", "Firewall", (f"The Cloud Firewall decides this traffic (it is not web): {_ref(rule)} allows it. Add the destination to {group} "
                                      "used by a Cloud Firewall Block rule above that rule." + broad)
        low = next((c for c in cats if category_kind(c) == "low_collateral"), None)
        if low:
            return "no", "URL", f"Block the category {low} in a URL filtering rule above {_ref(rule)}: few legitimate sites fall in it."
        if row.get("application"):
            return "no", "Cloud App", f"ZIA identifies it as {row['application']}: block that application in a Cloud App Control rule."
        if is_ip:
            return "no", "Firewall", ("Add the address to an IP destination group used by a Cloud Firewall Block rule: that covers every port and "
                                      "protocol, not just web." + broad)
        if non_web:
            return "no", "DNS", ("Traffic that is not web goes past URL filtering: add the host to a custom category used by a DNS Control Block "
                                 "rule so it does not resolve." + broad)
        return "no", "URL", f"Add the host to a custom URL category used by a URL filtering Block rule above {_ref(rule)}." + broad
    # expected ALLOW
    if res in ("allowed", "bypassed"):
        return "yes", "", ("Reaches the destination, but Client Connector sends it direct, so it is not inspected." if res == "bypassed"
                           else "Reaches the application through ZPA." if area == "ZPA" else "Allowed.")
    if area == "ZPA":
        return "no", "ZPA", (f"ZPA carries it through application segment '{seg}' and denies it ({_ref(rule)}). Add or reorder a ZPA access rule "
                             "for that segment that allows the users who need it.")
    threat = next((c for c in alerts if category_kind(c, alerts) == "threat"), None)
    if area == "ATP" or (threat and res == "blocked" and area not in ("URL", "Cloud App")):
        why = f"ZIA classifies it as a threat ({threat})" if threat else f"Advanced Threat Protection blocks it ({_ref(rule)})"
        return "no", "ATP", (f"{why}. Ask the security team first; if it must work, add it to the ATP security "
                             "exceptions rather than turning the protection off for everyone.")
    if area == "Firewall":
        return "no", "Firewall", (f"Blocked by Cloud Firewall rule {_ref(rule)}. Add the destination to {group} used by an Allow rule above that "
                                  "rule, for the port and protocol it needs.")
    if area == "DNS":
        return "no", "DNS", (f"DNS Control rule {_ref(rule)} blocks its lookup. Add the host to a custom URL category used by an Allow DNS Control "
                             "rule above that rule.")
    if area == "Cloud App":
        return "no", "Cloud App", (f"Blocked by Cloud App Control rule {_ref(rule)}. Add an Allow rule above it for this application (and the users "
                                   "who need it), rather than changing the rule for everyone.")
    note = f" Note: ZIA flags it with a security alert ({threat})." if threat else ""
    if res in ("isolated", "caution"):
        return "no", "URL", f"{res.capitalize()} by {_ref(rule)}. Add it to a custom URL category used by an Allow rule above that rule.{note}"
    return "no", "URL", (f"Blocked by {_ref(rule)}. Add it to a custom URL category used by an Allow rule above that rule; do not unblock "
                         f"{('the category ' + cats[0]) if cats else 'its category'} for everyone.{note}")


def category_advice(expected: str, cat: str, kind: str) -> str:
    if expected == "BLOCK":
        return {"threat": "A threat category: block it with Advanced Threat Protection, for every user, not a category rule.",
                "low_collateral": "Block this category: few legitimate sites fall in it.",
                "none": "No category: list the destinations (custom URL category or IP group).",
                }.get(kind, "Do not block the category (broad): list the destinations instead.")
    return {"threat": "Keep it blocked: a threat category. Allow single sites through ATP security exceptions only.",
            }.get(kind, "Allow the destinations through a custom URL category; leave the category rule as it is.")


# ── The run ─────────────────────────────────────────────────────────────

COLUMNS: Tuple[Tuple[str, str], ...] = (
    ("row", "Row"), ("line", "Input line"), ("input", "Input"), ("target", "Destination"), ("port", "Port"), ("protocol", "Protocol"),
    ("source_ip", "Source IP"), ("location", "Location"), ("dest_country", "Destination country"), ("user", "User"), ("group", "Group"),
    ("department", "Department"), ("label", "Label"),
    ("category", "Category"), ("security_alert", "Security alert"), ("application", "Cloud app"), ("category_source", "Category source"),
    ("result", "Result"), ("blockable_by", "Allowed but blockable by"), ("area", "Deciding area"), ("rule", "Deciding rule"),
    ("action", "Action"), ("stops_at", "Stops at"), ("segment", "ZPA segment"), ("inspection", "Inspection"), ("expected", "Expected"),
    ("meets", "Meets expectation"),
    ("recommended_area", "Recommended area"), ("recommendation", "Recommendation"), ("notes", "Notes"),
)


class Run:
    """One tested list, kept in memory for the page's exports and Fix."""

    def __init__(self, parsed: ParsedList, *, tenant_label: str = "", network: str = "off", platform: str = "windows") -> None:
        self.p = parsed
        self.tenant_label, self.network, self.platform = tenant_label, network, platform
        self.evals: List[Dict[str, Any]] = []
        self.eval_of = array("i", [-1]) * len(parsed)
        self.flags = bytearray(len(parsed))    # 1 flagged, 2 not as expected
        self.lookups: Dict[str, Dict[str, Any]] = {}
        self.summary: Dict[str, Any] = {}
        self._lists: Dict[Tuple[str, str], List[str]] = {}
        self.created = time.time()

    def row(self, i: int) -> Dict[str, Any]:
        """Row i (0-based) with every column."""
        import path_analyzer
        p = self.p
        e = p.entries[p.entry_of[i]]
        target = p.targets[i]
        ev = self.evals[self.eval_of[i]] if self.eval_of[i] >= 0 else None
        notes = list(e.get("notes") or ())
        if i in p.row_notes:
            notes.append(p.row_notes[i])
        override = e.get("category")
        lk = self.lookups.get(target)
        if override:
            source = "your file"
        elif lk is None:
            source = "tenant lists only (lookup not in scope)" if self.summary.get("lookup_in_scope") is False else "tenant lists only"
        elif lk.get("error"):
            source = str(lk["error"])
        else:
            source = "ZIA lookup"
        r: Dict[str, Any] = {"row": i + 1, "line": e["line"], "input": e["input"], "target": target, "is_ip": bool(p.is_ip[i]),
                             "private": bool(p.is_ip[i]) and path_analyzer._is_private(ipaddress.ip_address(target)),
                             "port": e.get("port", ""), "protocol": e.get("protocol", ""), "source_ip": e.get("source_ip", ""),
                             "location": e.get("location", ""), "dest_country": e.get("dest_country", ""), "user": e.get("user", ""),
                             "group": e.get("group", ""), "department": e.get("department", ""),
                             "label": e.get("label", ""), "expected": e.get("expected", ""), "category_source": source}
        if ev is None:
            r.update(result="not tested", category="; ".join(override or ()), security_alert="", application="", blockable_by="", area="",
                     rule="", action="", stops_at="", inspection="", segment="")
            notes.append(self.summary.get("not_tested_why") or "not tested")
        else:
            r.update(result=ev["result"], category="; ".join(ev["categories"]), security_alert="; ".join(ev["security_alerts"]),
                     application=ev.get("application") or "", blockable_by="; ".join(ev.get("blockable_by") or []), area=ev["area"],
                     rule=ev["rule"], action=ev["action"], stops_at=ev["stops_at"], inspection=ev["inspection"], segment=ev.get("segment") or "")
            notes += [n for n in ev.get("notes") or [] if n not in notes]
        r["notes"] = " | ".join(notes)
        meets, area, rec = recommend(r)
        r.update(meets=meets, recommended_area=area, recommendation=rec)
        return r

    def rows(self, which: str = "all") -> Iterator[Dict[str, Any]]:
        bit = {"flagged": 1, "unmet": 2}.get(which, 0)
        for i in range(len(self.p)):
            if not bit or self.flags[i] & bit:
                yield self.row(i)


def _row_context(p: ParsedList, i: int, lk: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    import path_analyzer
    e = p.entries[p.entry_of[i]]
    host = p.targets[i]
    ip = bool(p.is_ip[i])
    return {"target": host, "host": host, "is_ip": ip, "private": ip and path_analyzer._is_private(ipaddress.ip_address(host)),
            "port": e.get("port"), "protocol": e.get("protocol"), "source_ip": e.get("source_ip"), "location": e.get("location"),
            "dest_country": e.get("dest_country"), "user": e.get("user"), "group": e.get("group"), "department": e.get("department"), "lookup": lk}


def _row_key(host: str, e: Dict[str, Any]) -> Tuple[Any, ...]:
    """Rows with the same key get the same answer: the destination and every
    column the evaluation uses."""
    return (host, e.get("category"), e.get("port"), e.get("protocol"), e.get("source_ip"), e.get("user"), e.get("group"), e.get("department"),
            e.get("location"))


# Where each row was decided, for the page's live flow (static/flow_anim.js
# listFlowModel): counts only, never a destination, user or rule name.
_FLOW_AREA = {v: k for k, v in AREA_KEYS.items()}
FLOW_EVERY = 40   # a tally at most about this many times a run, plus the last


def _flow_tally(total: int) -> Dict[str, Any]:
    return {"done": 0, "total": total, "phase": "trace", "results": {}, "at": {}}


def _flow_add(tally: Dict[str, Any], r: Dict[str, Any]) -> None:
    """Count one row's answer: its result, and the area that decided it."""
    res = r.get("result") if r.get("result") in RESULTS else "unverified"
    tally["results"][res] = tally["results"].get(res, 0) + 1
    at = tally["at"].setdefault(_FLOW_AREA.get(r.get("area") or "", "none"), {})
    at[res] = at.get(res, 0) + 1


def _flow_copy(tally: Dict[str, Any], **kw: Any) -> Dict[str, Any]:
    out = {"done": tally["done"], "total": tally["total"], "phase": tally["phase"], "results": dict(tally["results"]),
           "at": {k: dict(v) for k, v in tally["at"].items()}}
    out.update(kw)
    return out


def run(client, parsed: ParsedList, *, scope: Dict[str, Any], network: str = "off", platform: str = "windows",
        snapshot: Optional[Dict[str, Any]] = None, tenant_label: str = "", lookup: bool = True,
        max_lookup_requests: int = DEFAULT_LOOKUP_REQUESTS, log: LogFn = None, cancel: Any = None,
        sleep: Callable[[float], None] = time.sleep, evaluators: Optional[Sequence[Callable[..., Any]]] = None,
        zpa: Optional[Dict[str, Any]] = None, progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Run:
    """Test every row. Reads only what `scope` (data_flow.path_scope) puts
    in scope, once; the URL lookup only when it is in scope and `lookup`.
    `zpa` is ZPA in scope (see PathEvaluator: a kept read, an SDK client
    to read it with, or why it cannot be read); None when ZPA is not
    ticked. Stop ends it between rows: the rows tested are kept, the rest
    are marked not tested. Nothing is written. `progress` (optional) gets
    the running tally of where rows were decided (counts only) as rows are
    traced; the last one is also the summary's `flow`."""
    from data_flow import NOTHING_IN_SCOPE, stop_on
    say = log or (lambda m: None)
    if not scope or not (scope.get("read") or zpa):
        raise ValueError(NOTHING_IN_SCOPE)
    rn = Run(parsed, tenant_label=tenant_label, network=network, platform=platform)
    p = parsed
    n = len(p)
    rn.summary.update(lookup_in_scope=bool(scope.get("lookup")))
    stopped: Optional[str] = None
    lookup_state: Dict[str, Any] = {}
    evs = [f(client=client, scope=scope, network=network, platform=platform, snapshot=snapshot, log=say, cancel=cancel, zpa=zpa)
           for f in (evaluators if evaluators is not None else EVALUATORS)]
    say(f"Testing {n:,} row(s) from {p.lines:,} line(s)" + (f"; {p.skipped_count:,} line(s) skipped" if p.skipped_count else "") + ".")
    done = 0
    tally = _flow_tally(n)
    every = max(1, -(-n // FLOW_EVERY))   # ceil: at most FLOW_EVERY tallies while tracing
    tell = progress or (lambda t: None)
    try:
        with stop_on(client, cancel):
            for ev in evs:
                prep = getattr(ev, "prepare", None)
                if callable(prep):
                    prep(p.targets[0])
            if _stopped(cancel):
                raise Stopped(STOPPED_REASON)
            want = scope.get("lookup") and lookup
            tell(_flow_copy(tally, phase="lookup" if want else "trace"))
            if want:
                keys = [p.targets[i] for i in range(n) if not p.entries[p.entry_of[i]].get("category")]
                if keys:
                    rn.lookups, lookup_state = lookup_all(client, keys, cancel=cancel, log=say, max_requests=max_lookup_requests, sleep=sleep)
            elif scope.get("lookup"):
                say("ZIA's URL lookup was turned off for this run: rows are placed by the tenant's own custom categories and the file's category column.")
            else:
                say("ZIA's URL lookup is not in scope (no ZIA policy section is), so it was not asked.")
            say(f"Tracing {n:,} row(s) against the tenant read…")
            cache: Dict[Tuple[Any, ...], int] = {}
            same: Dict[Tuple[Any, ...], int] = {}
            for i in range(n):
                if i % STOP_EVERY == 0 and _stopped(cancel):
                    raise Stopped(STOPPED_REASON)
                e = p.entries[p.entry_of[i]]
                override = e.get("category")
                host = p.targets[i]
                if override:
                    lk: Optional[Dict[str, Any]] = {"categories": list(override), "security_alerts": [], "application": None, "error": None}
                else:
                    lk = rn.lookups.get(host) if want else (blank_lookup("ZIA's URL lookup was turned off for this run") if scope.get("lookup") else None)
                key = _row_key(host, e)
                idx = cache.get(key)
                if idx is None:
                    ctx = _row_context(p, i, lk)
                    answers = []
                    for ev in evs:
                        a = ev.evaluate(ctx)
                        if a is not None:
                            answers.append((getattr(ev, "precedence", 100), a))
                    idx = _keep_eval(rn.evals, same, combine(answers))
                    cache[key] = idx
                rn.eval_of[i] = idx
                done = i + 1
                tally["done"] = done
                _flow_add(tally, rn.evals[idx])
                if done % every == 0 and done < n:
                    tell(_flow_copy(tally))
                if done % 10_000 == 0:
                    say(f"Traced {done:,} of {n:,} row(s).")
    except Stopped as e:
        stopped = str(e)
        say(f"STOPPED — you clicked Stop after {done:,} of {n:,} row(s); the rest were not tested. Nothing is ever written by this view.")
    rn.summary["not_tested_why"] = "not tested: you clicked Stop" if stopped else "not tested"
    rn.summary["flow"] = _flow_copy(tally, phase="stopped" if stopped else "done")
    tell(rn.summary["flow"])
    fresh = zfresh = None
    for ev in evs:
        fresh = fresh or getattr(ev, "fresh", None)
        zfresh = zfresh or getattr(ev, "zpa_fresh", None)
    zstate = next((getattr(ev, "zpa_state") for ev in evs if hasattr(ev, "zpa_state")), "not_in_scope" if not zpa else "")
    znote = next((getattr(ev, "zpa_note") for ev in evs if getattr(ev, "zpa_note", None)), None)
    rn.summary.update(stopped=stopped, lookup=lookup_state, snapshot_for_cache=None if stopped else fresh,
                      zpa_for_cache=None if stopped else zfresh, zpa={"state": zstate, "note": znote},
                      traced=sum(getattr(ev, "traced", 0) for ev in evs),
                      evaluators=[{"key": getattr(ev, "key", ""), "label": getattr(ev, "label", "")} for ev in evs])
    _summarize(rn, scope)
    if not stopped:
        say(f"Done: {n:,} row(s) tested with {rn.summary['traced']:,} trace(s).")
    return rn


def _keep_eval(evals: List[Dict[str, Any]], same: Dict[Tuple[Any, ...], int], res: Dict[str, Any]) -> int:
    """The index of `res` in `evals`, kept once however many rows give the
    same answer: a 250,000-row list of a few hundred answers holds a few
    hundred dicts, not one per row. The headline is not kept: it names the
    destination of one row, and a row is shown from its own columns (Run.row)."""
    res = {k: v for k, v in res.items() if k != "headline"}
    try:
        sig = tuple(sorted((k, tuple(v) if isinstance(v, list) else v) for k, v in res.items()))
        hash(sig)
    except TypeError:   # an evaluator's value that cannot be compared: kept on its own
        sig = None
    idx = same.get(sig) if sig is not None else None
    if idx is None:
        evals.append(res)
        idx = len(evals) - 1
        if sig is not None:
            same[sig] = idx
    return idx


def _top(counter: Dict[Any, int], k: int = 15) -> List[Tuple[Any, int]]:
    return sorted(counter.items(), key=lambda x: (-x[1], str(x[0])))[:k]


def _summarize(rn: Run, scope: Dict[str, Any]) -> None:
    counts = {k: 0 for k in RESULTS}
    counts.update(allowed_but_blockable=0, not_tested=0)
    rules: Dict[Tuple[str, str, str], int] = {}
    cats: Dict[str, int] = {}
    by_area: Dict[Tuple[str, str], Dict[str, Any]] = {}
    cat_adv: Dict[Tuple[str, str], Dict[str, Any]] = {}
    lists: Dict[Tuple[str, str], Dict[str, None]] = {}
    segments: Dict[Tuple[str, str], Dict[str, None]] = {}
    expected_rows = meets = misses = 0
    preview_unmet: List[Dict[str, Any]] = []
    preview_flag: List[Dict[str, Any]] = []
    for i in range(len(rn.p)):
        r = rn.row(i)
        res = r["result"]
        if res == "not tested":
            counts["not_tested"] += 1
        else:
            counts[res] = counts.get(res, 0) + 1
        blockable = res == "allowed" and bool(r["blockable_by"])
        if blockable:
            counts["allowed_but_blockable"] += 1
        if res in DECIDING:
            k = (r["area"], r["rule"] or "(default)", r["action"])
            rules[k] = rules.get(k, 0) + 1
        for c in (r["category"].split("; ") if r["category"] else ["(no category)"]):
            cats[c] = cats.get(c, 0) + 1
        flag = 1 if (res != "allowed" or blockable or r["meets"] == "no") else 0
        if r["expected"]:
            expected_rows += 1
            if r["meets"] == "yes":
                meets += 1
            elif r["meets"] == "no":
                misses += 1
                flag |= 2
                ka = (r["expected"], r["recommended_area"])
                a = by_area.setdefault(ka, {"expected": r["expected"], "area": r["recommended_area"], "area_label": AREA_LABELS.get(r["recommended_area"], ""),
                                            "count": 0, "examples": [], "recommendation": r["recommendation"]})
                a["count"] += 1
                if len(a["examples"]) < 5:
                    a["examples"].append(r["target"])
                lists.setdefault((r["recommended_area"], r["expected"]), {})[r["target"]] = None
                if r["recommended_area"] == "ZPA" and r["segment"]:
                    segments.setdefault((r["recommended_area"], r["expected"]), {})[r["segment"]] = None
                alerts = r["security_alert"].split("; ") if r["security_alert"] else []
                for c in (r["category"].split("; ") if r["category"] else [""]):
                    kind = category_kind(c, alerts)
                    kc = (r["expected"], c or "(no category)")
                    ca = cat_adv.setdefault(kc, {"expected": r["expected"], "category": c or "(no category)", "kind": kind, "count": 0,
                                                 "advice": category_advice(r["expected"], c, kind)})
                    ca["count"] += 1
        rn.flags[i] = flag
        if flag & 2 and len(preview_unmet) < PREVIEW_ROWS:
            preview_unmet.append(r)
        elif flag and len(preview_flag) < PREVIEW_ROWS:
            preview_flag.append(r)
    preview = (preview_unmet + preview_flag)[:PREVIEW_ROWS]
    for (a, e), segs in segments.items():
        for b in by_area.values():
            if (b["area"], b["expected"]) == (a, e):
                b["segments"] = list(segs)[:20]
    s = rn.summary
    s.update(
        rows=len(rn.p), lines=rn.p.lines, skipped=rn.p.skipped, skipped_count=rn.p.skipped_count, columns=rn.p.columns,
        counts=counts, flagged=sum(1 for f in rn.flags if f & 1), unmet=sum(1 for f in rn.flags if f & 2),
        top_rules=[{"area": a, "area_label": AREA_LABELS.get(a, a), "rule": ru, "action": ac, "count": c} for (a, ru, ac), c in _top(rules)],
        top_categories=[{"category": c, "count": n} for c, n in _top(cats)],
        expectations=None if not expected_rows else {
            "rows": expected_rows, "meets": meets, "misses": misses,
            "by_area": sorted(by_area.values(), key=lambda a: -a["count"]),
            "categories": sorted(cat_adv.values(), key=lambda a: -a["count"])[:25]},
        lists=[{"area": a, "area_label": AREA_LABELS.get(a, a), "purpose": "block" if e == "BLOCK" else "allow", "count": len(v),
                "where": AREA_PASTE.get(a, ""), "note": _segment_note(list(segments.get((a, e), {})))} for (a, e), v in sorted(lists.items())],
        preview=preview, preview_total=len(preview), scope={"summary": scope.get("summary"), "key": scope.get("key")},
        assumptions=_assumptions(rn, scope), network=rn.network, platform=rn.platform, tenant_label=rn.tenant_label)
    rn._lists = {k: list(v) for k, v in lists.items()}


def _segment_note(segs: List[str]) -> str:
    """ZPA's paste list is a note, not a list ZIA takes: the segments to change."""
    if not segs:
        return ""
    return ("Change these ZPA application segments or their access rules (in ZPA, not in ZIA): " + ", ".join(segs[:10])
            + (f" and {len(segs) - 10} more" if len(segs) > 10 else "") + ".")


def _assumptions(rn: Run, scope: Dict[str, Any]) -> List[str]:
    """The fixed assumptions plus what was not in scope for this run."""
    from data_flow import PATH_SECTIONS
    out = list(ASSUMPTIONS)
    nis = scope.get("not_in_scope") or {}
    parts = [PATH_SECTIONS[k][0] for k in PATH_SECTIONS if k in nis]
    if parts:
        out.append("Only what is in scope on the Scope page was read; these parts are not in scope and are not assessed for any row: "
                   + ", ".join(parts) + ".")
    z = rn.summary.get("zpa") or {}
    if z.get("state") == "not_in_scope":
        out.append("ZPA is not in scope on the Scope page, so whether ZPA carries a row was not assessed.")
    elif z.get("note"):
        out.append(str(z["note"]))
    else:
        import zpa_path
        out.append(zpa_path.ASSUMPTIONS[0])
    return out


def area_list(rn: Run, area: str, purpose: str) -> List[str]:
    """The destinations to paste for one area and purpose ('block' or 'allow')."""
    a = AREA_KEYS.get(area, area)
    e = "BLOCK" if purpose == "block" else "ALLOW"
    return list(rn._lists.get((a, e), []))


# ── Exports ─────────────────────────────────────────────────────────────

def _cellv(v: Any) -> Any:
    return "" if v is None else v


def csv_lines(rn: Run, which: str = "all") -> Iterator[str]:
    """The results as CSV, one chunk per row, every cell through csv_safe."""
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow([label for _, label in COLUMNS])
    yield buf.getvalue()
    for r in rn.rows(which):
        buf.seek(0)
        buf.truncate()
        w.writerow([_cellv(r.get(k)) for k, _ in COLUMNS])
        yield buf.getvalue()


def workbook(rn: Run, which: str = "all") -> Tuple[bytes, bool]:
    """(the .xlsx, whether its results sheet was cut at XLSX_MAX_ROWS)."""
    import xlsx_writer
    s = rn.summary
    wb = xlsx_writer.Workbook(title="Test a list", subject="Path analyzer: a list of destinations")
    summ = wb.add_sheet("Summary", columns=["What", "Value"])
    summ.append(["Tenant", rn.tenant_label])
    summ.append(["Network / platform", f"{rn.network} / {rn.platform}"])
    summ.append(["Rows tested", s.get("rows", 0)])
    for k, v in (s.get("counts") or {}).items():
        summ.append([k.replace("_", " ").capitalize(), v])
    ex = s.get("expectations") or {}
    if ex:
        summ.append(["Rows with an expected result", ex.get("rows", 0)])
        summ.append(["Meet the expectation", ex.get("meets", 0)])
        summ.append(["Do not", ex.get("misses", 0)])
    if s.get("stopped"):
        summ.append(["Stopped", s["stopped"]])
    lk = s.get("lookup") or {}
    if lk.get("stopped"):
        summ.append(["URL lookup", lk["stopped"]])
    for a in s.get("assumptions") or []:
        summ.append(["Assumption", a])
    ws = wb.add_sheet("Results", columns=[label for _, label in COLUMNS])
    cut = False
    for n, r in enumerate(rn.rows(which)):
        if n >= XLSX_MAX_ROWS:
            cut = True
            break
        ws.append([_cellv(r.get(k)) for k, _ in COLUMNS])
    if cut:
        summ.append(["Results sheet", f"The first {XLSX_MAX_ROWS:,} rows; download the CSV for every row."])
    if ex:
        ba = wb.add_sheet("By area", columns=["Expected", "Recommended area", "Rows", "Examples", "Recommendation"])
        for a in ex.get("by_area") or []:
            ba.append([a["expected"], a["area_label"] or a["area"], a["count"], "; ".join(a["examples"]), a["recommendation"]])
        ca = wb.add_sheet("Categories", columns=["Expected", "Category", "Kind", "Rows", "Advice"])
        for c in ex.get("categories") or []:
            ca.append([c["expected"], c["category"], c["kind"].replace("_", " "), c["count"], c["advice"]])
    tr = wb.add_sheet("Top rules", columns=["Area", "Rule", "Action", "Rows"])
    for t in s.get("top_rules") or []:
        tr.append([t["area_label"], t["rule"], t["action"], t["count"]])
    return wb.to_bytes(), cut


# ── Fix selected: a hand-off to Bulk changes ────────────────────────────

_FIXES: Dict[str, Dict[str, Any]] = {}
_FIX_LOCK = threading.Lock()
FIX_KEEP_SECONDS = 3600
FIX_MAX = 20
# The areas whose fix is a custom URL category the Bulk changes page can change.
FIX_AREAS = ("URL", "DNS", "Cloud App")
_FIX_ID = re.compile(r"^[a-f0-9]{24}$")


def fix_handoff(rn: Run, *, rows: Sequence[int] = (), area: str = "", purpose: str = "block", now: Optional[float] = None) -> Dict[str, Any]:
    """The chosen destinations, as the Bulk changes page's URL category
    operation takes them (admin_ops.normalize_url), kept for an hour under
    a random id. `rows` are 1-based row numbers; without them, every row
    of `area` that is not as expected for `purpose`. Writes nothing:
    Bulk changes previews the change and applies it only behind its four
    write gates (write mode, a writer, the assessor's name, the typed
    confirmation)."""
    import admin_ops
    now = time.time() if now is None else now
    if purpose not in ("block", "allow"):
        raise ListError("purpose must be block or allow.")
    if len(rows) > MAX_FIX_ROWS:
        raise ListError(f"Pick at most {MAX_FIX_ROWS:,} rows.")
    picked: List[str] = []
    if rows:
        n = len(rn.p)
        for x in rows:
            if not isinstance(x, int) or isinstance(x, bool) or not 1 <= x <= n:
                raise ListError(f"Row {str(x)[:20]} is not a row of this run (1 to {n:,}).")
            picked.append(rn.p.targets[x - 1])
    elif area:
        a = AREA_KEYS.get(area, area)
        if a not in AREAS:
            raise ListError(f"Unknown area '{area[:40]}'. Use one of: {', '.join(AREA_KEYS)}.")
        if a not in FIX_AREAS:
            raise ListError(f"{AREA_LABELS[a]} is not changed through a custom URL category here: copy its list and paste it into "
                            f"{AREA_PASTE[a]}.")
        picked = area_list(rn, a, purpose)
    else:
        raise ListError("Pick rows, or an area.")
    urls: List[str] = []
    seen = set()
    excluded: List[Dict[str, str]] = []
    for t in picked:
        u, why = admin_ops.normalize_url(t)
        if why:
            excluded.append({"destination": t[:200], "why": why})
        elif u.lower() not in seen:
            seen.add(u.lower())
            urls.append(u)
    over = max(0, len(urls) - admin_ops.MAX_URLS)
    urls = urls[:admin_ops.MAX_URLS]
    if not urls:
        raise ListError("None of the picked destinations can go into a custom URL category.")
    fid = secrets.token_hex(12)
    rec = {"id": fid, "urls": urls, "excluded": excluded[:100], "over_limit": over, "purpose": purpose, "created": now,
           "tenant_label": rn.tenant_label,
           "note": ("From the Path analyzer's Test a list view: add these to the custom URL category a " + ("Block" if purpose == "block" else "Allow")
                    + " rule uses, or to a new one, then preview. Nothing is written until you apply in write mode and confirm.")}
    with _FIX_LOCK:
        for k in [k for k, v in _FIXES.items() if now - v["created"] > FIX_KEEP_SECONDS]:
            del _FIXES[k]
        _FIXES[fid] = rec
        while len(_FIXES) > FIX_MAX:
            _FIXES.pop(next(iter(_FIXES)))
    return dict(rec)


def get_fix(fid: str, now: Optional[float] = None) -> Optional[Dict[str, Any]]:
    now = time.time() if now is None else now
    if not isinstance(fid, str) or not _FIX_ID.match(fid):
        return None
    with _FIX_LOCK:
        rec = _FIXES.get(fid)
        if rec is None or now - rec["created"] > FIX_KEEP_SECONDS:
            return None
        return dict(rec)
