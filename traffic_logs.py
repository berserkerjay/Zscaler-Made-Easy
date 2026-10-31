"""Session and traffic log analysis: ZPA LSS and ZIA NSS logs, read locally.

An admin uploads log files the customer's log streaming already writes:

* ZPA Log Streaming Service (LSS), JSON lines: User Activity
  (``zpn_trans_log``), User Status (``zpn_auth_log``), App Connector Status
  (``zpn_ast_auth_log``) and Private Service Edge Status
  (``zpn_sys_auth_log``). The log type names are the ones the installed SDK
  maps (zscaler/zpa/lss.py ``source_log_map``); the field names are those of
  Zscaler's published LSS log field lists (LogTimestamp, Username,
  SessionID, SessionStatus, ConnectionID, ConnectionStatus, InternalReason,
  Application, Host, Connector, ClientZEN, ...).
* ZIA Nanolog Streaming Service (NSS) web, firewall and DNS feeds: JSON (one
  object per line, the NSS field names as keys, or the Cloud NSS HTTP shape
  ``{"sourcetype": "zscalernss-web", "event": {...}}``), a CSV or TSV with a
  header row (NSS names or the Insights column names), the feed's own output
  format pasted in (``%s{time}\\t%s{login}\\t...``), or a tab-separated feed
  in the default order (assumed, see DEFAULT_ORDERS).

Everything is untrusted input. It is read in memory, line by line, under
caps: the request body cap, the archive caps of log_analyzer.expand (members,
size per member and in total, one level of nesting), MAX_LINES lines,
MAX_LINE_BYTES per line (a longer line is counted and skipped, never read
whole), MAX_DISTINCT keys per counter, MAX_VALUE characters per value and
MAX_SESSIONS sessions. A line that no format reads is counted as malformed,
never fatal. Nothing is written to disk or logged; the result is kept in the
server's memory until the admin saves it (save_report, owner-only file).
Every value goes back as data; the page and every exporter escape it.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import json
import math
import os
import re
import secrets
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Tuple

import safe_files

KIND = "traffic-logs"
VERSION = 1

MAX_LINES = 2_000_000          # lines read per analysis; the rest is not read (said in the notes)
MAX_LINE_BYTES = 64 * 1024     # a longer line is counted as oversized and skipped
MAX_VALUE = 300                # characters kept per field value
MAX_DISTINCT = 50_000          # distinct keys per counter; the rest count under OTHER
MAX_SESSIONS = 200_000         # ZPA sessions consolidated; the rest are counted only
MAX_TEMPLATE = 4000            # characters of a pasted feed output format
MAX_TEMPLATE_FIELDS = 200
TOP = 100                      # rows kept per top list
SESSION_ROWS = 5000            # consolidated sessions kept for the table and export
MAX_BUCKETS = 96               # points on a time chart (an hour a bar for up to four days)
OTHER = "(other values, past the counting limit)"

# Session consolidation (ZPA User Status). A session shorter than this is a
# sign-in check, not a user session; consecutive sessions of the same user
# closer than SESSION_MERGE_GAP are one connection whose session ID rotated.
SESSION_MIN_SECONDS = 5
SESSION_MERGE_GAP = 60

# Anomaly thresholds (documented on the page and in tests).
SPIKE_FACTOR = 3.0             # a bucket at least 3x the median of non-empty buckets
SPIKE_MIN = 10                 # ...and at least this many events
SPIKE_MIN_BUCKETS = 6          # spikes need this many non-empty buckets to compare against
USER_FAIL_MIN = 10             # failures for one user worth naming
USER_FAIL_SHARE = 0.5          # ...when at least half that user's connections failed
USER_FAIL_ALWAYS = 25          # ...or this many failures whatever the share
NEW_DEST_MIN_SPAN = 2 * 3600   # "new destinations" needs logs spanning at least two hours
NEW_DEST_MAX = 50

EMPTY = {"", "none", "na", "n/a", "null", "-", "(null)", "nan", "unknown"}

LOG_LABELS = {
    "zpa_activity": "ZPA User Activity",
    "zpa_status": "ZPA User Status",
    "zpa_connector": "ZPA App Connector Status",
    "zpa_pse": "ZPA Private Service Edge Status",
    "zia_web": "ZIA web (NSS)",
    "zia_fw": "ZIA firewall (NSS)",
    "zia_dns": "ZIA DNS (NSS)",
}

# Plain names of the ZPA client types (User Status ClientType). Values from
# Zscaler's LSS documentation; the ones marked are assumed from field
# examples and may differ in a tenant (an unknown value is shown as it is).
CLIENT_TYPES = {
    "zpn_client_type_zapp": "Client Connector",
    "zpn_client_type_zapp_partner": "Client Connector (partner tenant)",
    "zpn_client_type_machine_tunnel": "Machine tunnel",
    "zpn_client_type_exporter": "Browser Access",
    "zpn_client_type_browser_isolation": "Cloud Browser Isolation",   # assumed
    "zpn_client_type_edge_connector": "Cloud Connector",
    "zpn_client_type_branch_connector": "Branch Connector",
    "zpn_client_type_ip_anchoring": "ZIA source IP anchoring",
    "zpn_client_type_slogger": "Log streaming (LSS)",
    "zpn_client_type_vdi": "VDI",   # assumed
}
USER_CLIENT_TYPES = {"zpn_client_type_zapp", "zpn_client_type_zapp_partner", "zpn_client_type_machine_tunnel",
                     "zpn_client_type_exporter", "zpn_client_type_browser_isolation", "zpn_client_type_vdi", ""}


# ── ZPA Internal Reason codes ────────────────────────────────────────
# User Activity's InternalReason says why a connection ended or failed.
# Normal ends are not failures. The specific codes below are from Zscaler's
# published list of ZPA connection status and internal reasons (assumed: the
# list is not in the SDK; wording here is our own). Any other code is
# explained by its family (the words in it), never guessed further.
NORMAL_REASONS = {
    "OPEN_OR_ACTIVE_CONNECTION": "The connection was open or still active when the log was written.",
    "BRK_MT_CLOSED_FROM_CLIENT": "The user's device closed the connection. A normal end.",
    "BRK_MT_CLOSED_FROM_ASSISTANT": "The App Connector closed the connection, usually because the application server ended it. A normal end.",
    "BRK_MT_TERMINATED_IDLE_TIMEOUT": "The connection was closed after it sat idle. A normal end.",
    "BRK_MT_TERMINATED_BRK_SWITCHED": "The connection moved to another ZPA Service Edge. A normal end.",
    "MT_CLOSED_TERMINATED": "The connection ended normally.",
}
REASON_TEXT = {
    "BRK_MT_SETUP_FAIL_REJECTED_BY_POLICY": ("policy", "An access policy rule denied it, or no rule allowed it (ZPA denies by default)."),
    "BRK_MT_SETUP_FAIL_APP_NOT_FOUND": ("no_segment", "No application segment covers this host and port, so ZPA does not carry it."),
    "BRK_MT_SETUP_FAIL_CONNECTOR_GROUPS_MISSING": ("connector", "The segment's server group has no App Connector group to send the connection to."),
    "BRK_MT_SETUP_TIMEOUT": ("timeout", "The Service Edge waited too long for the App Connector to set the connection up."),
    "BRK_MT_SETUP_FAIL_CANNOT_SEND_TO_BROKER": ("cloud", "The Service Edge could not pass the connection on inside the ZPA cloud."),
    "BRK_MT_SETUP_FAIL_SAML_EXPIRED": ("auth", "The user's sign-in (SAML assertion) had expired."),
    "BRK_MT_SETUP_FAIL_SCIM_INACTIVE": ("auth", "The user is inactive in the identity provider's SCIM data."),
    "BRK_MT_AUTH_SAML_DECODE_FAIL": ("auth", "The user's SAML assertion could not be read."),
    "BRK_MT_AUTH_SAML_FINGER_PRINT_FAIL": ("auth", "The SAML assertion's signing certificate did not match the IdP configured in ZPA."),
    "BRK_MT_AUTH_NO_SAML_ASSERTION_IN_MSG": ("auth", "The request carried no SAML assertion."),
    "BRK_MT_AUTH_SAML_NO_USER_ID": ("auth", "The SAML assertion carried no user ID."),
    "BRK_MT_AUTH_ALREADY_FAILED": ("auth", "The user's sign-in had already failed for this session."),
    "BRK_MT_AUTH_TWO_SAML_FAILURE": ("auth", "Both SAML checks for this connection failed."),
    "BRK_MT_RESET_FROM_SERVER": ("server", "The application server reset the connection."),
    "AST_MT_SETUP_ERR_OPEN_SERVER_CONN": ("server", "The App Connector could not open a connection to the application server."),
    "AST_MT_SETUP_ERR_OPEN_SERVER_TIMEOUT": ("server", "The App Connector timed out opening a connection to the application server."),
    "AST_MT_SETUP_ERR_OPEN_SERVER_ERROR": ("server", "The application server refused or failed the App Connector's connection."),
    "AST_MT_SETUP_ERR_OPEN_SERVER_CLOSE": ("server", "The application server closed the connection while it was being set up."),
    "AST_MT_SETUP_TIMEOUT_CANNOT_CONN_TO_SERVER": ("server", "The App Connector could not reach the application server in time."),
    "AST_MT_SETUP_ERR_HASH_TBL_FULL": ("capacity", "The App Connector had no room for another connection."),
    "AST_MT_SETUP_ERR_BRK_HASH_TBL_FULL": ("capacity", "The App Connector had no room for another connection from this Service Edge."),
    "AST_MT_SETUP_ERR_NO_SYSTEM_FD": ("capacity", "The App Connector's host ran out of file descriptors."),
    "AST_MT_SETUP_ERR_NO_PROCESS_FD": ("capacity", "The App Connector process ran out of file descriptors."),
    "AST_MT_SETUP_ERR_CONN_PEER": ("tunnel", "The App Connector lost its link to the Service Edge."),
    "AST_MT_SETUP_TIMEOUT": ("timeout", "The App Connector timed out setting the connection up."),
    "AST_MT_SETUP_TIMEOUT_NO_ACK_TO_BIND": ("timeout", "The App Connector got no answer from the Service Edge in time."),
    "CLT_INVALID_DOMAIN": ("no_segment", "Client Connector was asked for a domain it does not send to ZPA."),
    "CLT_PORT_UNREACHABLE": ("client", "Client Connector found the port unreachable."),
    "CLT_PROBE_FAILED": ("client", "Client Connector's check of the application failed."),
    "CLT_DOUBLEENCRYPT_NOT_SUPPORTED": ("client", "The segment asks for double encryption and this client does not support it."),
    "MT_CLOSED_TLS_CONN_GONE": ("tunnel", "The tunnel to the ZPA cloud dropped, so the connection was lost."),
    "MT_CLOSED_DTLS_CONN_GONE": ("tunnel", "The tunnel to the ZPA cloud dropped, so the connection was lost."),
    "MT_CLOSED_INTERNAL_ERROR": ("cloud", "The ZPA cloud ended the connection after an internal error."),
}
# Families: (label, what it means, what to do). Picked from the words in a code.
REASON_FAMILIES = {
    "policy": ("Access policy denied it", "ZPA checked its access policy and no rule allowed this user to this application (or a block rule matched).",
               "Run Diagnose on the ZPA analysis page for this user and host to see which rule decides and why the others do not match."),
    "auth": ("Sign-in problem (SAML or SCIM)", "The user's identity could not be confirmed or is no longer valid.",
             "Ask the user to sign in to Client Connector again; if it keeps failing, check the IdP configuration and its signing certificate in ZPA."),
    "no_segment": ("No application segment for it", "Nothing in ZPA is defined for this host and port, so ZPA does not carry the traffic.",
                   "Check the application segments for this host and port (the Path analyzer shows which segment, if any, matches)."),
    "server": ("The App Connector could not reach the server", "ZPA got as far as the App Connector, which could not open (or keep) a connection to the application server.",
               "From the App Connector's host, test the server's name and port; check the server is up and that no firewall sits between them."),
    "dns": ("The App Connector could not resolve the name", "The App Connector could not look up the application's name in DNS.",
            "Check the DNS servers the App Connector uses can resolve the host."),
    "capacity": ("App Connector at capacity", "The App Connector had no room for more connections.",
                 "Add App Connectors to the group or move load; check the connectors' CPU and memory in the status logs."),
    "timeout": ("Timed out", "A step of setting up the connection took too long.",
                "Look at the App Connector's health and load, and at the path to the server, for the same time."),
    "connector": ("App Connector problem", "The App Connector side could not serve the connection.",
                  "Check the App Connector group serving the segment: connectors up, enrolled and in the server group."),
    "client": ("Client side", "Client Connector on the user's device could not complete the request.",
               "Check Client Connector on the device (version, ZPA tunnel state) and the forwarding profile."),
    "tunnel": ("Tunnel dropped", "The tunnel between the device or the App Connector and the ZPA cloud dropped.",
               "Look for network changes at that time on the device or the connector's site."),
    "cloud": ("Inside the ZPA cloud", "The ZPA cloud could not pass the connection on.",
              "If it repeats, open a case with Zscaler support with the times and session IDs."),
    "other": ("Other reason", "This code is not in the list this page explains.",
              "Look the code up in Zscaler's list of ZPA internal reasons."),
}


def reason_family(code: str) -> str:
    """The family of a ZPA InternalReason code, from the code table or the words in it."""
    c = (code or "").upper()
    if c in REASON_TEXT:
        return REASON_TEXT[c][0]
    rules = (("POLICY", "policy"), ("SAML", "auth"), ("SCIM", "auth"), ("_AUTH_", "auth"), ("APP_NOT_FOUND", "no_segment"),
             ("INVALID_DOMAIN", "no_segment"), ("DNS", "dns"), ("SERVER", "server"), ("HASH_TBL", "capacity"), ("_FD", "capacity"),
             ("RATE_LIMIT", "capacity"), ("TIMEOUT", "timeout"), ("CONN_GONE", "tunnel"), ("CONN_PEER", "tunnel"),
             ("CONNECTOR", "connector"), ("AST_", "connector"), ("CLT_", "client"), ("BRK_", "cloud"))
    for word, fam in rules:
        if word in c:
            return fam
    return "other"


def is_failure(code: str) -> bool:
    """True when a ZPA InternalReason says the connection failed or ended abnormally."""
    c = (code or "").strip().upper()
    if not c or c.lower() in EMPTY or c in NORMAL_REASONS:
        return False
    if "IDLE_TIMEOUT" in c or c.endswith("_CLOSED_FROM_CLIENT") or c.endswith("_CLOSED_FROM_ASSISTANT"):
        return False
    return True


def explain_reason(code: str) -> Dict[str, str]:
    c = (code or "").strip().upper()
    if c in NORMAL_REASONS:
        return {"code": c, "family": "normal", "label": "Normal end", "what": NORMAL_REASONS[c], "do": "Nothing to do."}
    fam = reason_family(c)
    label, means, do = REASON_FAMILIES[fam]
    specific = REASON_TEXT.get(c, (fam, ""))[1]
    return {"code": c, "family": fam, "label": label, "what": specific or means, "do": do}


# ── Small helpers ────────────────────────────────────────────────────
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _s(v: Any) -> str:
    """A field value as bounded text: control characters dropped, at most MAX_VALUE characters."""
    if v is None:
        return ""
    if isinstance(v, (dict, list)):
        try:
            v = json.dumps(v, separators=(",", ":"))[:MAX_VALUE * 2]
        except (TypeError, ValueError):
            v = ""
    s = _CTRL.sub("", str(v)).strip()
    return s[:MAX_VALUE]


def _blank(v: Any) -> bool:
    return _s(v).lower() in EMPTY


def _num(v: Any) -> float:
    try:
        f = float(str(v).strip()) if v is not None and str(v).strip() != "" else 0.0
    except (TypeError, ValueError):
        return 0.0
    return f if math.isfinite(f) and f >= 0 else 0.0


_MONTHS = {m: i + 1 for i, m in enumerate(["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"])}
_CTIME = re.compile(r"^(?:[A-Za-z]{3},?\s+)?([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\.\d+)?\s+(\d{4})$")
_MDY = re.compile(r"^(\d{1,2})/(\d{1,2})/(\d{4})[ ,T]+(\d{1,2}):(\d{2})(?::(\d{2}))?(?:\s*([AP]M))?$", re.I)
_BYD = re.compile(r"^([A-Za-z]{3})\s+(\d{1,2}),?\s+(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})(?:\s+\w+)?$")
_EPOCH = re.compile(r"^\d{9,19}(?:\.\d+)?$")
_LO, _HI = datetime(2000, 1, 1, tzinfo=timezone.utc), datetime(2100, 1, 1, tzinfo=timezone.utc)


def parse_time(v: Any) -> Optional[datetime]:
    """A log timestamp as an aware UTC datetime, or None. Reads ISO 8601,
    the ctime form NSS and LSS write ("Mon Oct 16 22:55:48 2023"), m/d/Y,
    and epoch seconds, milliseconds, microseconds or nanoseconds. A time
    with no zone is taken as written (the feed's own zone) and kept as UTC
    for counting. A time before 2000 or after 2099 is not a time."""
    s = _s(v)
    if not s or s == "0":
        return None
    out: Optional[datetime] = None
    try:
        if _EPOCH.match(s):
            n = float(s)
            for scale in (1e9, 1e6, 1e3, 1.0):
                if n >= 1e9 * scale or scale == 1.0:
                    n = n / scale
                    break
            out = datetime.fromtimestamp(n, tz=timezone.utc)
        elif (m := _CTIME.match(s)) and m.group(1).lower() in _MONTHS:
            out = datetime(int(m.group(6)), _MONTHS[m.group(1).lower()], int(m.group(2)), int(m.group(3)), int(m.group(4)), int(m.group(5)), tzinfo=timezone.utc)
        elif (m := _BYD.match(s)) and m.group(1).lower() in _MONTHS:
            out = datetime(int(m.group(3)), _MONTHS[m.group(1).lower()], int(m.group(2)), int(m.group(4)), int(m.group(5)), int(m.group(6)), tzinfo=timezone.utc)
        elif m := _MDY.match(s):
            hh = int(m.group(4)) % 12 + (12 if (m.group(7) or "").upper() == "PM" else 0) if m.group(7) else int(m.group(4))
            out = datetime(int(m.group(3)), int(m.group(1)), int(m.group(2)), hh, int(m.group(5)), int(m.group(6) or 0), tzinfo=timezone.utc)
        elif re.match(r"^\d{4}-\d{2}-\d{2}", s):
            d = datetime.fromisoformat(s.replace("Z", "+00:00").replace(" UTC", "+00:00"))
            out = d.astimezone(timezone.utc) if d.tzinfo else d.replace(tzinfo=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None
    if out is None or not (_LO <= out < _HI):
        return None
    return out


_HOST_OK = re.compile(r"^[A-Za-z0-9*._-]{1,253}$")


def host_of(url: str) -> str:
    """The host part of an NSS url (which has no scheme) or of a full URL."""
    u = _s(url)
    if "://" in u:
        u = u.split("://", 1)[1]
    u = u.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in u:
        u = u.rsplit("@", 1)[1]
    if u.startswith("["):
        return u[1:u.find("]")] if "]" in u else ""
    if u.count(":") == 1:
        u = u.split(":", 1)[0]
    return u.lower().rstrip(".")


def linkable(dest: str) -> bool:
    """A destination the Path analyzer can take: a host name or an IP address."""
    d = (dest or "").strip()
    if not d or len(d) > 253:
        return False
    try:
        ipaddress.ip_address(d)
        return True
    except ValueError:
        return bool(_HOST_OK.match(d)) and "." in d and not d.startswith((".", "-"))


class BoundedCounter:
    """A Counter that stops taking new keys at MAX_DISTINCT; later new keys
    are counted under OTHER, so a hostile log of a million distinct values
    costs a bounded amount of memory."""

    __slots__ = ("c", "cap", "overflow")

    def __init__(self, cap: int = MAX_DISTINCT) -> None:
        self.c: Counter = Counter()
        self.cap = cap
        self.overflow = 0

    def add(self, key: str, n: int = 1) -> None:
        if not key:
            return
        if key in self.c or len(self.c) < self.cap:
            self.c[key] += n
        else:
            self.c[OTHER] += n
            self.overflow += n

    def top(self, n: int = TOP) -> List[Tuple[str, int]]:
        return self.c.most_common(n)

    def __len__(self) -> int:
        return len(self.c)


# ── Field aliases ────────────────────────────────────────────────────
# Lower-cased source names (NSS field names, the Cloud NSS JSON-for-SIEM
# keys, and the Insights column names) -> the NSS name this module uses.
_WEB_ALIASES = {
    "time": "time", "datetime": "time", "logged time": "time", "epochtime": "epochtime",
    "login": "login", "elogin": "login", "user": "login", "usrname": "login",
    "dept": "dept", "edepartment": "dept", "department": "dept",
    "location": "location", "elocation": "location", "locationname": "location",
    "url": "url", "eurl": "url", "host": "host", "ehost": "host", "hostname": "host",
    "action": "action", "policy action": "action",
    "urlcat": "urlcat", "urlcategory": "urlcat", "url category": "urlcat",
    "urlsupercat": "urlsupercat", "urlsupercategory": "urlsupercat", "url super category": "urlsupercat",
    "urlclass": "urlclass", "url class": "urlclass",
    "appname": "appname", "cloud application": "appname", "appclass": "appclass", "cloud application class": "appclass",
    "rulelabel": "rulelabel", "blocked policy name": "rulelabel", "ruletype": "ruletype", "blocked policy type": "ruletype",
    "urlfilterrulelabel": "urlfilterrulelabel", "url filtering policy name": "urlfilterrulelabel",
    "apprulelabel": "apprulelabel", "cloud application policy name": "apprulelabel",
    "reason": "reason",
    "dlpeng": "dlpeng", "dlpengine": "dlpeng", "dlp engine": "dlpeng",
    "dlpdict": "dlpdict", "dlpdictionaries": "dlpdict", "dlp dictionaries": "dlpdict",
    "trig_dlprulename": "trig_dlprulename", "dlprulename": "dlprulename", "allowed dlp rule name": "dlprulename",
    "threatname": "threatname", "threat name": "threatname",
    "malwarecat": "malwarecat", "threatcategory": "malwarecat", "threat category": "malwarecat",
    "malwareclass": "malwareclass", "threatclass": "malwareclass", "threat super category": "malwareclass",
    "riskscore": "riskscore", "pagerisk": "riskscore", "suspicious content": "riskscore",
    "ssldecrypted": "ssldecrypted", "decrypted": "ssldecrypted", "ssl inspected": "ssldecrypted",
    "externalspr": "externalspr", "ssl policy reason": "externalspr",
    "reqsize": "reqsize", "requestsize": "reqsize", "sent bytes": "reqsize",
    "respsize": "respsize", "responsesize": "respsize", "received bytes": "respsize",
    "cip": "cip", "clientip": "cip", "client ip": "cip", "sip": "sip", "serverip": "sip", "server ip": "sip",
    "reqmethod": "reqmethod", "requestmethod": "reqmethod", "request method": "reqmethod",
    "respcode": "respcode", "response code": "respcode", "proto": "proto", "protocol": "proto",
    "devicehostname": "devicehostname", "device hostname": "devicehostname",
}
_FW_ALIASES = {
    "time": "time", "datetime": "time", "logged time": "time", "epochtime": "epochtime",
    "login": "login", "user": "login", "dept": "dept", "department": "dept",
    "location": "location", "locationname": "location",
    "csip": "csip", "csport": "csport", "cdip": "cdip", "cdport": "cdport", "cdfqdn": "cdfqdn",
    "sdip": "sdip", "sdport": "sdport", "ssip": "ssip", "tsip": "tsip",
    "action": "action", "rulelabel": "rulelabel", "rule name": "rulelabel", "ipsrulelabel": "ipsrulelabel",
    "ipproto": "ipproto", "proto": "ipproto", "nwsvc": "nwsvc", "network service": "nwsvc", "nwapp": "nwapp", "network application": "nwapp",
    "inbytes": "inbytes", "outbytes": "outbytes", "threatcat": "threatcat", "threatname": "threatname",
    "destcountry": "destcountry", "ipcat": "ipcat", "devicehostname": "devicehostname",
}
_DNS_ALIASES = {
    "time": "time", "datetime": "time", "logged time": "time", "epochtime": "epochtime",
    "login": "login", "user": "login", "dept": "dept", "department": "dept", "location": "location", "locationname": "location",
    "reqaction": "reqaction", "request action": "reqaction", "resaction": "resaction", "response action": "resaction",
    "reqrulelabel": "reqrulelabel", "request rule name": "reqrulelabel", "resrulelabel": "resrulelabel", "response rule name": "resrulelabel",
    "req": "req", "dns_req": "req", "dns request": "req", "res": "res", "dns_resp": "res", "dns response": "res",
    "reqtype": "reqtype", "dns_reqtype": "reqtype", "restype": "restype",
    "domcat": "domcat", "category": "domcat", "cip": "cip", "clt_sip": "cip", "sip": "sip", "srv_dip": "sip",
    "error": "error", "dnsapp": "dnsapp", "dnsappcat": "dnsappcat", "durationms": "durationms",
}
_ALIASES = {"zia_web": _WEB_ALIASES, "zia_fw": _FW_ALIASES, "zia_dns": _DNS_ALIASES}
_WEB_ACTIONS = {"allowed", "blocked", "caution", "cautioned", "isolate", "isolated", "allow", "block"}

# The default feed output formats, tab-separated, as NSS fields in order.
# Assumed: these orders are from Zscaler's NSS feed output format pages as
# remembered (they are not in the SDK). A line is read this way only when
# its values fit (a time first, an action where the action goes, addresses
# where addresses go); otherwise paste the feed's own output format.
DEFAULT_ORDERS = {
    "zia_web": ["time", "login", "proto", "url", "action", "appname", "appclass", "reqsize", "respsize", "urlclass",
                "urlsupercat", "urlcat", "malwarecat", "threatname", "riskscore", "dlpeng", "dlpdict", "location", "dept",
                "cip", "sip", "reqmethod", "respcode", "ua", "ruletype", "rulelabel"],
    "zia_fw": ["time", "login", "csip", "csport", "cdip", "cdport", "cdfqdn", "tsip", "action", "rulelabel", "ipproto",
               "nwsvc", "nwapp", "location", "dept", "inbytes", "outbytes", "duration"],
    "zia_dns": ["time", "login", "dept", "location", "reqaction", "reqrulelabel", "resaction", "resrulelabel", "req",
                "reqtype", "res", "restype", "cip", "sip", "durationms", "domcat"],
}


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address((v or "").strip())
        return True
    except ValueError:
        return False


def _fits_default(kind: str, cols: List[str]) -> bool:
    if len(cols) < 8 or parse_time(cols[0]) is None:
        return False
    if kind == "zia_web":
        return cols[4].strip().lower() in _WEB_ACTIONS and cols[2].strip().upper() in {"HTTP", "HTTPS", "FTP", "HTTP_PROXY", "SSL", "TUNNEL", "DNSOVERHTTPS"}
    if kind == "zia_fw":
        return _is_ip(cols[2]) and _is_ip(cols[4]) and bool(re.match(r"^(allow|block|drop|reset)", cols[8].strip(), re.I))
    if kind == "zia_dns":
        return bool(re.match(r"^REQ_", cols[4].strip())) and bool(re.match(r"^(RES_|$)", cols[6].strip()))
    return False


# ── Feed output format templates ─────────────────────────────────────
_TOKEN = re.compile(r"%-?\d*l?[sdfjJo]\{([A-Za-z0-9_]{1,40})(?::[A-Za-z0-9_]{1,20})?\}")


class FeedTemplate:
    """A pasted NSS/LSS feed output format turned into a line reader.

    Each field token becomes a group that cannot run past the first
    character of the literal text after it, so a line is matched in one
    left-to-right pass (no backtracking blow-up, CWE-1333). The template is
    data: only %s{name}-style tokens and literal text are read from it."""

    def __init__(self, text: str) -> None:
        t = str(text or "")
        if len(t) > MAX_TEMPLATE:
            raise ValueError(f"the feed output format is longer than {MAX_TEMPLATE} characters")
        t = t.replace("\\t", "\t").replace("\\n", "").replace("\r", "").replace("\n", "")
        parts: List[Tuple[str, str]] = []   # (literal before, field)
        pos = 0
        for m in _TOKEN.finditer(t):
            parts.append((t[pos:m.start()], m.group(1).lower()))
            pos = m.end()
        tail = t[pos:]
        if not parts:
            raise ValueError("the feed output format has no %s{field} tokens")
        if len(parts) > MAX_TEMPLATE_FIELDS:
            raise ValueError(f"the feed output format has more than {MAX_TEMPLATE_FIELDS} fields")
        self.fields = [f for _, f in parts]
        rx = ["^"]
        for i, (lit, _f) in enumerate(parts):
            rx.append(re.escape(lit))
            nxt = parts[i + 1][0] if i + 1 < len(parts) else tail
            if nxt:
                rx.append("([^" + re.escape(nxt[0]) + "]*)")
            elif i + 1 < len(parts):
                raise ValueError("two fields follow each other with nothing between them; the line cannot be split")
            else:
                rx.append("(.*)")
        rx.append(re.escape(tail.rstrip()) + r"\s*$")
        self.rx = re.compile("".join(rx), re.S)
        names = set(self.fields)
        self.kind = ("zia_dns" if names & {"reqaction", "resaction"} else
                     "zia_fw" if len(names & {"cdip", "csip", "cdport", "nwsvc", "sdip"}) >= 2 else
                     "zia_web" if names & {"url", "eurl", "urlcat", "host"} else "")
        if not self.kind:
            raise ValueError("the feed output format names no web, firewall or DNS fields this page reads")

    def read(self, line: str) -> Optional[Dict[str, str]]:
        m = self.rx.match(line)
        if not m:
            return None
        return {f: v for f, v in zip(self.fields, m.groups())}


# ── Record classification and normalisation ─────────────────────────
def _classify_json(d: Dict[str, Any], hint: str = "") -> str:
    keys = set(d)
    if "ConnectionStatus" in keys or "ConnectionID" in keys or "InternalReason" in keys:
        return "zpa_activity"
    if "SessionStatus" in keys:
        if "Connector" in keys or "ConnectorGroup" in keys:
            return "zpa_connector"
        if "ServiceEdge" in keys or "ServiceEdgeGroup" in keys:
            return "zpa_pse"
        return "zpa_status"
    h = hint.lower()
    if "dns" in h:
        return "zia_dns"
    if "fw" in h or "firewall" in h:
        return "zia_fw"
    if "web" in h:
        return "zia_web"
    low = {str(k).lower() for k in keys}
    if low & {"reqaction", "resaction", "dns_req", "dns_reqtype"}:
        return "zia_dns"
    if len(low & {"cdip", "csip", "cdport", "csport", "nwsvc", "sdip", "cdfqdn"}) >= 2:
        return "zia_fw"
    if low & {"url", "eurl", "urlcat", "urlcategory", "ssldecrypted"} and ("action" in low or "policy action" in low):
        return "zia_web"
    return ""


def normalise(kind: str, raw: Dict[str, Any]) -> Dict[str, str]:
    """A ZIA record's fields under their NSS names (via the alias table), each bounded text."""
    table = _ALIASES.get(kind)
    if table is None:
        return {k: _s(v) for k, v in raw.items() if isinstance(k, str) and len(k) <= 64}
    out: Dict[str, str] = {}
    for k, v in raw.items():
        if not isinstance(k, str):
            continue
        name = table.get(k.strip().lower())
        if name and (name not in out or not out[name]):
            out[name] = _s(v)
    return out


# ── Reading the files ────────────────────────────────────────────────
def _iter_lines(data: bytes, stats: Dict[str, Any]) -> Iterator[Tuple[int, Optional[str]]]:
    """(line number, text) for each line of `data`, read in bounded steps.
    A line longer than MAX_LINE_BYTES yields (n, None): counted, not read."""
    bio = io.BytesIO(data)
    n = 0
    while True:
        raw = bio.readline(MAX_LINE_BYTES + 1)
        if not raw:
            return
        n += 1
        if len(raw) > MAX_LINE_BYTES and not raw.endswith(b"\n"):
            while True:   # skip the rest of the long line without keeping it
                more = bio.readline(MAX_LINE_BYTES)
                if not more or more.endswith(b"\n"):
                    break
            yield n, None
            continue
        if n == 1 and raw.startswith(b"\xef\xbb\xbf"):
            raw = raw[3:]
        yield n, raw.decode("utf-8", errors="replace").rstrip("\r\n")


def _split_header(line: str) -> Tuple[str, List[str]]:
    delim = "\t" if line.count("\t") >= max(2, line.count(",")) else ","
    try:
        cols = next(csv.reader([line], delimiter=delim))
    except (csv.Error, StopIteration):
        return delim, []
    return delim, [c.strip() for c in cols]


def _header_kind(cols: List[str]) -> Tuple[str, List[Optional[str]]]:
    """The log kind a header row names and each column's NSS name (None: not read)."""
    low = [c.strip().strip('"').lower() for c in cols]
    best, mapped = "", []
    for kind, table in _ALIASES.items():
        m = [table.get(c) for c in low]
        hits = sum(1 for x in m if x)
        need = {"zia_web": {"url", "urlcat", "host"}, "zia_fw": {"cdip", "csip", "nwsvc"}, "zia_dns": {"req", "reqaction"}}[kind]
        if hits >= 3 and need & set(x for x in m if x) and hits > sum(1 for x in mapped if x):
            best, mapped = kind, m
    return best, mapped


class _Reader:
    """Turns one file's lines into (kind, record) pairs, counting what it cannot read."""

    def __init__(self, name: str, template: Optional[FeedTemplate], stats: Dict[str, Any]) -> None:
        self.name = name
        self.template = template
        self.stats = stats
        self.header: Optional[Tuple[str, str, List[Optional[str]]]] = None   # (kind, delimiter, column names)
        self.first = True

    def _bad(self, n: int, why: str) -> None:
        st = self.stats
        st["malformed"] += 1
        if len(st["malformed_examples"]) < 10:
            st["malformed_examples"].append({"file": self.name, "line": n, "why": why})

    def read(self, n: int, line: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        s = line.strip()
        if not s:
            return None
        first, self.first = self.first, False
        if s[0] == "[" and s[1:2] in ("{", "") or s.endswith(("},", "}]")):
            s = s.lstrip("[").rstrip("],").strip()   # one record per line of a JSON array feed
            if not s:
                return None
        brace = s.find("{")
        if brace != -1 and (brace == 0 or brace < 200) and s.endswith("}"):
            try:
                d = safe_files.strict_json_loads(s[brace:])
            except ValueError:
                d = None
            if isinstance(d, dict):
                hint = ""
                if isinstance(d.get("event"), dict):
                    hint = _s(d.get("sourcetype"))
                    d = d["event"]
                kind = _classify_json(d, hint)
                if not kind:
                    self.stats["unrecognised"] += 1
                    return None
                return kind, (d if kind.startswith("zpa") else normalise(kind, d))
            self._bad(n, "not valid JSON")
            return None
        if self.template is not None:
            rec = self.template.read(line)
            if rec is not None:
                return self.template.kind, normalise(self.template.kind, rec)
        if first:
            delim, cols = _split_header(line)
            kind, mapped = _header_kind(cols)
            if kind:
                self.header = (kind, delim, mapped)
                return None
        if self.header is not None:
            kind, delim, mapped = self.header
            try:
                cols = next(csv.reader([line], delimiter=delim))
            except (csv.Error, StopIteration):
                self._bad(n, "a row the CSV reader cannot split")
                return None
            if len(cols) != len(mapped):
                self._bad(n, f"{len(cols)} columns where the header has {len(mapped)}")
                return None
            return kind, {f: _s(v) for f, v in zip(mapped, cols) if f}
        cols = line.split("\t")
        for kind, order in DEFAULT_ORDERS.items():
            if _fits_default(kind, cols):
                return kind, {f: _s(v) for f, v in zip(order, cols)}
        self._bad(n, "not JSON, not a row under a header and not a default feed line (paste the feed's output format)")
        return None


def read_records(members: Iterable[Tuple[str, bytes]], template: Optional[FeedTemplate], stats: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    for name, data in members:
        reader = _Reader(name, template, stats)
        stats["files"].append({"name": name[:200], "bytes": len(data)})
        for n, line in _iter_lines(data, stats):
            if stats["lines"] >= MAX_LINES:
                stats["capped"] = True
                return
            stats["lines"] += 1
            if line is None:
                stats["oversized"] += 1
                if len(stats["malformed_examples"]) < 10:
                    stats["malformed_examples"].append({"file": name[:200], "line": n, "why": f"longer than {MAX_LINE_BYTES // 1024} KB, skipped"})
                continue
            got = reader.read(n, line)
            if got is not None:
                yield got


# ── Analysis ─────────────────────────────────────────────────────────
class _Series:
    """Event times per series, kept as counts per minute (bounded by the span)."""

    def __init__(self) -> None:
        self.per_min: Dict[str, Counter] = defaultdict(Counter)

    def add(self, series: str, t: Optional[datetime]) -> None:
        if t is not None:
            self.per_min[series][int(t.timestamp()) // 60] += 1

    def span(self) -> Tuple[Optional[int], Optional[int]]:
        lo = [min(c) for c in self.per_min.values() if c]
        hi = [max(c) for c in self.per_min.values() if c]
        return (min(lo) * 60 if lo else None, (max(hi) + 1) * 60 if hi else None)


_BUCKETS = (300, 900, 3600, 6 * 3600, 86400, 7 * 86400, 30 * 86400, 365 * 86400)


def _bucket_size(lo: int, hi: int) -> int:
    for b in _BUCKETS:
        if (hi - lo) / b <= MAX_BUCKETS:
            return b
    return _BUCKETS[-1]


def timeline(series: _Series, names: List[str]) -> Dict[str, Any]:
    lo, hi = series.span()
    if lo is None or hi is None:
        return {"bucket_seconds": 0, "start": None, "points": [], "series": names}
    size = _bucket_size(lo, hi)
    start = lo - lo % size
    nb = (hi - start + size - 1) // size
    rows = [[0] * len(names) for _ in range(nb)]
    for j, name in enumerate(names):
        for minute, c in series.per_min.get(name, {}).items():
            i = (minute * 60 - start) // size
            if 0 <= i < nb:
                rows[i][j] += c
    points = [{"t": datetime.fromtimestamp(start + i * size, tz=timezone.utc).isoformat().replace("+00:00", "Z"), "v": r} for i, r in enumerate(rows)]
    return {"bucket_seconds": size, "start": points[0]["t"] if points else None, "points": points, "series": names}


def spikes(tl: Dict[str, Any], series: str, label: str) -> List[Dict[str, Any]]:
    """Buckets of `series` at least SPIKE_FACTOR x the median of its non-empty buckets and at least SPIKE_MIN."""
    if series not in tl.get("series", []):
        return []
    j = tl["series"].index(series)
    vals = [p["v"][j] for p in tl["points"]]
    nonzero = [v for v in vals if v > 0]
    if len(nonzero) < SPIKE_MIN_BUCKETS:
        return []
    med = statistics.median(nonzero)
    out = []
    for p in tl["points"]:
        v = p["v"][j]
        if v >= SPIKE_MIN and v >= SPIKE_FACTOR * med:
            out.append({"kind": "spike", "series": series, "what": f"{label}: {v} in the {_bucket_words(tl['bucket_seconds'])} from {p['t']}, "
                        f"{v / med:.1f} times the usual {med:g}", "at": p["t"], "count": v, "median": med})
    return out[:20]


def _bucket_words(sec: int) -> str:
    return {300: "5 minutes", 900: "15 minutes", 3600: "hour", 6 * 3600: "6 hours", 86400: "day", 7 * 86400: "week", 30 * 86400: "30 days"}.get(sec, f"{sec} seconds")


def _new_destinations(first_seen: Dict[str, int], lo: Optional[int], hi: Optional[int], counts: Counter) -> Dict[str, Any]:
    """Destinations first seen in the last part of the window: the last day
    when the logs span two days or more, else the last quarter. Needs a span
    of NEW_DEST_MIN_SPAN at least."""
    if lo is None or hi is None or hi - lo < NEW_DEST_MIN_SPAN:
        return {"computed": False, "why": "The logs cover less than two hours, too short to tell new from usual.", "items": []}
    cut = hi - 86400 if hi - lo >= 2 * 86400 else hi - (hi - lo) // 4
    items = sorted(((d, t) for d, t in first_seen.items() if t >= cut), key=lambda x: (-counts.get(x[0], 0), x[0]))
    since = datetime.fromtimestamp(cut, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    return {"computed": True, "since": since, "total": len(items),
            "items": [{"name": d, "first_seen": datetime.fromtimestamp(t, tz=timezone.utc).isoformat().replace("+00:00", "Z"),
                       "count": counts.get(d, 0), "link": linkable(d)} for d, t in items[:NEW_DEST_MAX]]}


def _rows(c: BoundedCounter, n: int = TOP) -> List[Dict[str, Any]]:
    return [{"name": k, "count": v} for k, v in c.top(n)]


class Analysis:
    """Accumulates every record; result() builds the report."""

    def __init__(self) -> None:
        self.kinds: Counter = Counter()
        self.times = _Series()
        self.first_time: Optional[datetime] = None
        self.last_time: Optional[datetime] = None
        self.untimed = 0
        # ZPA User Activity
        self.za_conn: set = set()
        self.za_conn_overflow = 0
        self.za_connections = 0
        self.za_failed = 0
        self.za_failed_ids: set = set()
        self.za_records = 0
        self.za_fail_records = 0
        self.za_users, self.za_user_fail = BoundedCounter(), BoundedCounter()
        self.za_apps, self.za_app_fail = BoundedCounter(), BoundedCounter()
        self.za_conns, self.za_conn_fail = BoundedCounter(), BoundedCounter()
        self.za_dests, self.za_dest_fail = BoundedCounter(), BoundedCounter()
        self.za_edges, self.za_edge_fail = BoundedCounter(), BoundedCounter()
        self.za_rules = BoundedCounter()
        self.za_reasons = BoundedCounter(2000)
        self.za_reason_users: Dict[str, set] = defaultdict(set)
        self.za_reason_apps: Dict[str, Counter] = defaultdict(Counter)
        self.za_dest_port: Dict[str, Counter] = defaultdict(Counter)
        self.za_dest_first: Dict[str, int] = {}
        # ZPA User Status
        self.zs_sessions: Dict[str, Dict[str, Any]] = {}
        self.zs_overflow = 0
        self.zs_authfail_users = BoundedCounter()
        self.zs_authfail = 0
        self.zs_client_types = BoundedCounter(500)
        self.zs_platforms, self.zs_versions, self.zs_countries = BoundedCounter(500), BoundedCounter(2000), BoundedCounter(500)
        self.zs_edges = BoundedCounter(2000)
        self.zs_posture_miss = BoundedCounter(2000)
        self.zs_trusted = Counter()
        # App Connector / Private Service Edge status
        self.health: Dict[str, Dict[str, Dict[str, Any]]] = {"zpa_connector": {}, "zpa_pse": {}}
        # ZIA
        self.zi = {k: self._zia_acc() for k in ("zia_web", "zia_fw", "zia_dns")}

    @staticmethod
    def _zia_acc() -> Dict[str, Any]:
        return {"records": 0, "actions": Counter(), "users": BoundedCounter(), "user_blocks": BoundedCounter(),
                "dests": BoundedCounter(), "dest_blocks": BoundedCounter(), "dest_port": defaultdict(Counter), "dest_first": {},
                "cats": BoundedCounter(5000), "cat_blocks": BoundedCounter(5000), "apps": BoundedCounter(5000),
                "rules": BoundedCounter(5000), "locations": BoundedCounter(5000), "reasons": BoundedCounter(2000),
                "dlp": 0, "dlp_engines": BoundedCounter(2000), "dlp_dicts": BoundedCounter(2000), "dlp_rules": BoundedCounter(2000),
                "dlp_users": BoundedCounter(), "dlp_actions": Counter(),
                "threats": 0, "threat_names": BoundedCounter(5000), "threat_cats": BoundedCounter(500), "threat_users": BoundedCounter(),
                "threat_dests": BoundedCounter(), "threat_actions": Counter(),
                "ssl": Counter(), "ssl_reasons": BoundedCounter(500), "ssl_dests_no": BoundedCounter(),
                "dns_cats": BoundedCounter(2000)}

    # -- time
    def _when(self, series: str, t: Optional[datetime]) -> None:
        if t is None:
            return
        self.times.add(series, t)
        if self.first_time is None or t < self.first_time:
            self.first_time = t
        if self.last_time is None or t > self.last_time:
            self.last_time = t

    def add(self, kind: str, r: Dict[str, Any]) -> None:
        self.kinds[kind] += 1
        if getattr(self, "_" + kind)(r) is None:
            self.untimed += 1

    @staticmethod
    def _first(seen: Dict[str, int], key: str, t: Optional[datetime]) -> None:
        """Keep the first time `key` was seen (bounded: a new key past MAX_DISTINCT is not kept)."""
        if not key or t is None:
            return
        ts = int(t.timestamp())
        if key in seen:
            seen[key] = min(seen[key], ts)
        elif len(seen) < MAX_DISTINCT:
            seen[key] = ts

    # -- ZPA User Activity
    def _zpa_activity(self, r: Dict[str, Any]) -> Optional[datetime]:
        self.za_records += 1
        t = parse_time(r.get("LogTimestamp")) or parse_time(r.get("TimestampConnectionStart"))
        cid = _s(r.get("ConnectionID"))
        reason = _s(r.get("InternalReason")).upper()
        failed = is_failure(reason)
        user, app = _s(r.get("Username")), _s(r.get("Application"))
        host = _s(r.get("Host")).lower()
        port = _s(r.get("ServicePort"))
        conn, edge = _s(r.get("Connector")), _s(r.get("ClientZEN"))
        new_conn = True
        if cid:
            if cid in self.za_conn:
                new_conn = False
            elif len(self.za_conn) < MAX_SESSIONS:
                self.za_conn.add(cid)
            else:
                self.za_conn_overflow += 1
        if new_conn:
            self.za_connections += 1
            self._when("connections", t)
            self.za_users.add(user)
            self.za_apps.add(app)
            self.za_conns.add(conn)
            self.za_dests.add(host)
            self.za_edges.add(edge)
            self.za_rules.add(_s(r.get("Policy")))
            if host and port and (host in self.za_dest_port or len(self.za_dest_port) < MAX_DISTINCT):
                self.za_dest_port[host][f"{port}/{_s(r.get('IPProtocol')) or '6'}"] += 1
            self._first(self.za_dest_first, host, t)
        if failed:
            self.za_fail_records += 1
            key = cid or f"#{self.za_records}"
            if key in self.za_failed_ids:
                return t
            if len(self.za_failed_ids) < MAX_SESSIONS:
                self.za_failed_ids.add(key)
            self.za_failed += 1
            self._when("failures", t)
            self.za_reasons.add(reason)
            if reason in self.za_reason_users or len(self.za_reason_users) < 2000:
                if len(self.za_reason_users[reason]) < 1000:
                    self.za_reason_users[reason].add(user)
                where = app or host
                if where in self.za_reason_apps[reason] or len(self.za_reason_apps[reason]) < 200:
                    self.za_reason_apps[reason][where] += 1
            self.za_user_fail.add(user)
            self.za_app_fail.add(app)
            self.za_conn_fail.add(conn)
            self.za_dest_fail.add(host)
            self.za_edge_fail.add(edge)
        return t

    # -- ZPA User Status
    def _zpa_status(self, r: Dict[str, Any]) -> Optional[datetime]:
        t = parse_time(r.get("LogTimestamp"))
        status = _s(r.get("SessionStatus")).upper()
        user = _s(r.get("Username"))
        ctype = _s(r.get("ClientType")).lower()
        self.zs_client_types.add(ctype or "(not in the log)")
        if status == "ZPN_STATUS_AUTH_FAILED":
            self.zs_authfail += 1
            self.zs_authfail_users.add(user)
            self._when("auth_failures", t)
            return t
        for p in re.split(r"[,|]", _s(r.get("PosturesMiss"))):
            if p.strip() and p.strip().lower() not in EMPTY:
                self.zs_posture_miss.add(p.strip())
        sid = _s(r.get("SessionID"))
        if not sid:
            return t
        s = self.zs_sessions.get(sid)
        if s is None:
            if len(self.zs_sessions) >= MAX_SESSIONS:
                self.zs_overflow += 1
                return t
            auth = parse_time(r.get("TimestampAuthentication")) or t
            s = self.zs_sessions[sid] = {"user": user, "type": ctype, "start": auth, "end": None, "last": t, "open": True,
                                         "public_ip": "", "private_ip": "", "country": "", "city": "", "device": "", "platform": "",
                                         "version": "", "trusted": "", "edge": "", "rx": 0.0, "tx": 0.0}
            self._when("sessions", auth)
        if not s["open"]:
            return t
        if t is not None and (s["last"] is None or t > s["last"]):
            s["last"] = t
        for key, field in (("public_ip", "PublicIP"), ("private_ip", "PrivateIP"), ("country", "CountryCode"), ("city", "City"),
                           ("device", "Hostname"), ("platform", "Platform"), ("version", "Version"), ("edge", "ZEN")):
            v = _s(r.get(field))
            if v:
                s[key] = v
        tn = r.get("TrustedNetworksNames") or r.get("TrustedNetworks")
        s["trusted"] = _s(tn) if not _blank(tn) else s["trusted"]
        s["rx"] = max(s["rx"], _num(r.get("TotalBytesRx")))
        s["tx"] = max(s["tx"], _num(r.get("TotalBytesTx")))
        if status == "ZPN_STATUS_DISCONNECTED":
            s["open"] = False
            s["end"] = parse_time(r.get("TimestampUnAuthentication")) or t
        return t

    # -- App Connector / Private Service Edge status
    def _health_add(self, kind: str, r: Dict[str, Any], name_key: str, group_key: str) -> Optional[datetime]:
        t = parse_time(r.get("LogTimestamp"))
        self._when("status_events", t)
        name = _s(r.get(name_key)) or "(no name in the log)"
        h = self.health[kind]
        if name not in h:
            if len(h) >= 5000:
                return t
            h[name] = {"name": name, "group": "", "events": 0, "authenticated": 0, "disconnected": 0, "auth_failed": 0,
                       "last_status": "", "last_seen": None, "versions": set(), "cpu_max": 0.0, "mem_max": 0.0, "edges": set(),
                       "public_ip": ""}
        e = h[name]
        e["events"] += 1
        e["group"] = _s(r.get(group_key)) or e["group"]
        st = _s(r.get("SessionStatus")).upper()
        if st == "ZPN_STATUS_AUTHENTICATED":
            e["authenticated"] += 1
        elif st == "ZPN_STATUS_DISCONNECTED":
            e["disconnected"] += 1
        elif st == "ZPN_STATUS_AUTH_FAILED":
            e["auth_failed"] += 1
        if t is not None and (e["last_seen"] is None or t >= e["last_seen"]):
            e["last_seen"] = t
            e["last_status"] = st
        v = _s(r.get("Version") or r.get("PackageVersion"))
        if v and len(e["versions"]) < 20:
            e["versions"].add(v)
        z = _s(r.get("ZEN"))
        if z and len(e["edges"]) < 50:
            e["edges"].add(z)
        e["cpu_max"] = max(e["cpu_max"], min(_num(r.get("CPUUtilization")), 100.0))
        e["mem_max"] = max(e["mem_max"], min(_num(r.get("MemUtilization")), 100.0))
        return t

    def _zpa_connector(self, r: Dict[str, Any]) -> Optional[datetime]:
        return self._health_add("zpa_connector", r, "Connector", "ConnectorGroup")

    def _zpa_pse(self, r: Dict[str, Any]) -> Optional[datetime]:
        return self._health_add("zpa_pse", r, "ServiceEdge", "ServiceEdgeGroup")

    # -- ZIA
    @staticmethod
    def _zia_time(r: Dict[str, Any]) -> Optional[datetime]:
        return parse_time(r.get("time")) or parse_time(r.get("epochtime"))

    def _zia_common(self, kind: str, r: Dict[str, Any], action: str, dest: str, port: str, rules: List[Tuple[str, str]]) -> Tuple[Dict[str, Any], Optional[datetime]]:
        a = self.zi[kind]
        a["records"] += 1
        t = self._zia_time(r)
        blocked = action == "blocked"
        self._when(kind + ":all", t)
        if blocked:
            self._when(kind + ":blocked", t)
        a["actions"][action] += 1
        user = r.get("login", "")
        a["users"].add(user)
        if blocked:
            a["user_blocks"].add(user)
        a["locations"].add(r.get("location", ""))
        if dest:
            a["dests"].add(dest)
            if blocked:
                a["dest_blocks"].add(dest)
            if port and (dest in a["dest_port"] or len(a["dest_port"]) < MAX_DISTINCT):
                a["dest_port"][dest][port] += 1
            self._first(a["dest_first"], dest, t)
        for module, rule in rules:
            if rule and rule.lower() not in EMPTY:
                a["rules"].add(f"{module}\x1f{rule}\x1f{action}")
        return a, t

    @staticmethod
    def _action(v: str) -> str:
        x = (v or "").strip().lower()
        if not x or x in EMPTY:
            return "unknown"
        if "block" in x or "drop" in x or "deny" in x or "reset" in x or "bloc" in x:
            return "blocked"
        if "caution" in x:
            return "cautioned"
        if "isolat" in x:
            return "isolated"
        if "allow" in x or "pass" in x:
            return "allowed"
        return "other"

    def _zia_web(self, r: Dict[str, Any]) -> Optional[datetime]:
        action = self._action(r.get("action", ""))
        dest = (r.get("host") or host_of(r.get("url", ""))).lower()
        proto = (r.get("proto") or "").upper()
        port = "443/tcp" if proto in ("HTTPS", "SSL") else "80/tcp" if proto == "HTTP" else ""
        ruletype = r.get("ruletype", "")
        dlp_rule = r.get("trig_dlprulename") or r.get("dlprulename") or ""
        rules = [(ruletype or "Blocking rule", r.get("rulelabel", "")), ("URL filtering", r.get("urlfilterrulelabel", "")),
                 ("Cloud App Control", r.get("apprulelabel", "")), ("Web DLP", dlp_rule)]
        if (r.get("rulelabel") or "") in (r.get("urlfilterrulelabel"), r.get("apprulelabel"), dlp_rule):
            rules = rules[1:]   # the same rule named twice counts once
        a, t = self._zia_common("zia_web", r, action, dest, port, rules)
        cat = r.get("urlcat", "")
        a["cats"].add(cat)
        if action == "blocked":
            a["cat_blocks"].add(cat)
        if not _blank(r.get("appname")):
            a["apps"].add(r.get("appname", ""))
        if action == "blocked" and not _blank(r.get("reason")):
            a["reasons"].add(r.get("reason", ""))
        eng, dic = r.get("dlpeng", ""), r.get("dlpdict", "")
        if not _blank(eng) or not _blank(dic) or not _blank(dlp_rule):
            a["dlp"] += 1
            a["dlp_actions"][action] += 1
            a["dlp_users"].add(r.get("login", ""))
            for e in ([] if _blank(eng) else eng.split("|")):
                a["dlp_engines"].add(e.strip())
            for d in ([] if _blank(dic) else dic.split("|")):
                a["dlp_dicts"].add(d.strip())
            if not _blank(dlp_rule):
                a["dlp_rules"].add(dlp_rule)
        tn, mc = r.get("threatname", ""), r.get("malwarecat", "")
        if not _blank(tn) or (not _blank(mc) and not re.match(r"^(clean|benign|sandbox benign)", mc.strip().lower())):
            a["threats"] += 1
            a["threat_actions"][action] += 1
            a["threat_names"].add(tn if not _blank(tn) else mc)
            if not _blank(mc):
                a["threat_cats"].add(mc)
            a["threat_users"].add(r.get("login", ""))
            a["threat_dests"].add(dest)
        ssl = (r.get("ssldecrypted") or "").strip().lower()
        if ssl in ("yes", "no", "1", "0", "true", "false"):
            inspected = ssl in ("yes", "1", "true")
            a["ssl"]["inspected" if inspected else "not_inspected"] += 1
            if not inspected:
                a["ssl_reasons"].add(r.get("externalspr") or "(no reason in the log)")
                a["ssl_dests_no"].add(dest)
        elif proto == "HTTP":
            a["ssl"]["plain_http"] += 1
        else:
            a["ssl"]["not_logged"] += 1
        return t

    def _zia_fw(self, r: Dict[str, Any]) -> Optional[datetime]:
        action = self._action(r.get("action", ""))
        dest = (r.get("cdfqdn") if not _blank(r.get("cdfqdn")) else r.get("cdip", "")).lower()
        proto = (r.get("ipproto") or "").strip().lower()
        port = f"{r.get('cdport')}/{proto}" if r.get("cdport") and proto in ("tcp", "udp") else ""
        a, t = self._zia_common("zia_fw", r, action, dest, port, [("Cloud Firewall", r.get("rulelabel", "")), ("IPS", r.get("ipsrulelabel", ""))])
        a["apps"].add(r.get("nwapp") if not _blank(r.get("nwapp")) else r.get("nwsvc", ""))
        tn = r.get("threatname", "")
        if not _blank(tn):
            a["threats"] += 1
            a["threat_actions"][action] += 1
            a["threat_names"].add(tn)
            if not _blank(r.get("threatcat")):
                a["threat_cats"].add(r.get("threatcat", ""))
            a["threat_users"].add(r.get("login", ""))
            a["threat_dests"].add(dest)
        return t

    def _zia_dns(self, r: Dict[str, Any]) -> Optional[datetime]:
        req, res = (r.get("reqaction") or ""), (r.get("resaction") or "")
        action = "blocked" if self._action(req) == "blocked" or self._action(res) == "blocked" else self._action(req or res)
        dest = (r.get("req") or "").lower().rstrip(".")
        a, t = self._zia_common("zia_dns", r, action, dest, "53/udp" if dest else "",
                             [("DNS Control (request)", r.get("reqrulelabel", "")), ("DNS Control (response)", r.get("resrulelabel", ""))])
        a["cats"].add(r.get("domcat", ""))
        if action == "blocked":
            a["cat_blocks"].add(r.get("domcat", ""))
        if not _blank(r.get("dnsapp")):
            a["apps"].add(r.get("dnsapp", ""))
        return t

    # -- result
    def _sessions(self) -> Dict[str, Any]:
        """ZPA User Status sessions consolidated: sign-in checks shorter than
        SESSION_MIN_SECONDS dropped, and consecutive sessions of one user on
        the same day merged when the gap is SESSION_MERGE_GAP or less (ZPA
        rotates session IDs during one connection; the new one can start
        before the old one ends)."""
        per_user: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        probes = 0
        for s in self.zs_sessions.values():
            start = s["start"] or s["last"]
            end = s["end"] or (None if s["open"] else s["last"])
            if start is None:
                continue
            if end is not None and (end - start).total_seconds() < SESSION_MIN_SECONDS:
                probes += 1
                continue
            per_user[(s["user"], s["type"])].append(dict(s, start=start, end=end))
        merged: List[Dict[str, Any]] = []
        for (_user, _type), items in per_user.items():
            items.sort(key=lambda x: x["start"])
            cur: Optional[Dict[str, Any]] = None
            for s in items:
                if cur is not None and cur["start"].date() == s["start"].date() and (
                        cur["end"] is None or (s["start"] - cur["end"]).total_seconds() <= SESSION_MERGE_GAP):
                    cur["parts"] += 1
                    if cur["end"] is not None:
                        cur["end"] = None if s["end"] is None else max(cur["end"], s["end"])
                    for k in ("public_ip", "private_ip", "country", "city", "device", "platform", "version", "trusted", "edge"):
                        if s[k] and s[k] != cur[k]:
                            if k in ("public_ip", "private_ip") and cur[k] and s[k] not in cur["other_" + k] and len(cur["other_" + k]) < 10:
                                cur["other_" + k].append(cur[k])
                            cur[k] = s[k]
                    cur["rx"] += s["rx"]
                    cur["tx"] += s["tx"]
                    continue
                if cur is not None:
                    merged.append(cur)
                cur = dict(s, parts=1, other_public_ip=[], other_private_ip=[])
            if cur is not None:
                merged.append(cur)
        merged.sort(key=lambda x: x["start"], reverse=True)
        durations = [(m["end"] - m["start"]).total_seconds() for m in merged if m["end"] is not None]
        per_user_count = Counter(m["user"] for m in merged)
        rows = []
        for m in merged[:SESSION_ROWS]:
            rows.append({"user": m["user"], "client_type": CLIENT_TYPES.get(m["type"], m["type"] or "not in the log"),
                         "start": m["start"].isoformat().replace("+00:00", "Z"),
                         "end": m["end"].isoformat().replace("+00:00", "Z") if m["end"] else "",
                         "duration_s": int((m["end"] - m["start"]).total_seconds()) if m["end"] else None,
                         "public_ip": m["public_ip"], "other_public_ips": m["other_public_ip"], "private_ip": m["private_ip"],
                         "other_private_ips": m["other_private_ip"], "city": m["city"], "country": m["country"], "device": m["device"],
                         "platform": m["platform"], "version": m["version"], "trusted_network": m["trusted"],
                         "service_edge": m["edge"], "bytes_rx": int(m["rx"]), "bytes_tx": int(m["tx"]), "session_ids": m["parts"]})
        for s in self.zs_sessions.values():
            self.zs_platforms.add(s["platform"] or "(not in the log)")
            self.zs_versions.add(s["version"] or "(not in the log)")
            self.zs_countries.add(s["country"] or "(not in the log)")
            self.zs_edges.add(s["edge"])
            self.zs_trusted["on a trusted network" if s["trusted"] else "off trusted networks"] += 1
        return {"raw_session_ids": len(self.zs_sessions) + self.zs_overflow, "probes_dropped": probes, "sessions": len(merged),
                "still_open": sum(1 for m in merged if m["end"] is None), "users": len(per_user_count),
                "median_minutes": round(statistics.median(durations) / 60, 1) if durations else None,
                "longest_minutes": round(max(durations) / 60, 1) if durations else None,
                "top_users": [{"name": u, "count": c} for u, c in per_user_count.most_common(TOP)],
                "rows": rows, "rows_total": len(merged), "overflow": self.zs_overflow}

    def _health_rows(self, kind: str, last: Optional[datetime]) -> Dict[str, Any]:
        rows, findings = [], []
        groups: Dict[str, set] = defaultdict(set)
        for e in self.health[kind].values():
            for v in e["versions"]:
                groups[e["group"]].add(v)
        what = "App Connector" if kind == "zpa_connector" else "Private Service Edge"
        for e in sorted(self.health[kind].values(), key=lambda x: x["name"]):
            state = "up" if e["last_status"] == "ZPN_STATUS_AUTHENTICATED" else "down" if e["last_status"] == "ZPN_STATUS_DISCONNECTED" else \
                "failing" if e["last_status"] == "ZPN_STATUS_AUTH_FAILED" else "unknown"
            notes = []
            if state == "down":
                notes.append("disconnected at the end of these logs")
            if state == "failing":
                notes.append("its last attempt to sign in to ZPA failed")
            if e["disconnected"] >= 3:
                notes.append(f"disconnected {e['disconnected']} times (flapping)")
            if e["auth_failed"]:
                notes.append(f"{e['auth_failed']} failed sign-ins (certificate, enrolment or clock)")
            if e["cpu_max"] >= 85:
                notes.append(f"CPU reached {e['cpu_max']:g}%")
            if e["mem_max"] >= 85:
                notes.append(f"memory reached {e['mem_max']:g}%")
            if len(groups.get(e["group"], ())) > 1:
                notes.append("its group runs more than one version")
            row = {"name": e["name"], "group": e["group"], "state": state, "events": e["events"], "authenticated": e["authenticated"],
                   "disconnected": e["disconnected"], "auth_failed": e["auth_failed"],
                   "last_seen": e["last_seen"].isoformat().replace("+00:00", "Z") if e["last_seen"] else "",
                   "versions": sorted(e["versions"]), "cpu_max": e["cpu_max"], "mem_max": e["mem_max"],
                   "service_edges": sorted(e["edges"])[:10], "notes": notes}
            rows.append(row)
            if notes:
                findings.append({"name": e["name"], "group": e["group"], "what": f"{what} {e['name']}: " + "; ".join(notes) + "."})
        return {"rows": rows, "findings": findings, "count": len(rows),
                "down": sum(1 for r in rows if r["state"] in ("down", "failing"))}

    def result(self) -> Dict[str, Any]:
        lo, hi = self.times.span()
        rep: Dict[str, Any] = {"kind": KIND, "version": VERSION,
                               "log_types": [{"kind": k, "label": LOG_LABELS[k], "records": n} for k, n in self.kinds.most_common()],
                               "period": {"first": self.first_time.isoformat().replace("+00:00", "Z") if self.first_time else None,
                                          "last": self.last_time.isoformat().replace("+00:00", "Z") if self.last_time else None,
                                          "untimed_records": self.untimed},
                               "anomalies": [], "zpa": None, "zia": None, "health": None}
        anomalies: List[Dict[str, Any]] = []
        if self.kinds["zpa_activity"] or self.kinds["zpa_status"]:
            tl = timeline(self.times, ["connections", "failures", "sessions", "auth_failures"])
            anomalies += spikes(tl, "failures", "ZPA connection failures")
            anomalies += spikes(tl, "connections", "ZPA connections")
            anomalies += spikes(tl, "auth_failures", "ZPA sign-in failures")
            reasons = []
            for code, n in self.za_reasons.top(200):
                x = explain_reason(code)
                x.update({"count": n, "users": len(self.za_reason_users.get(code, ())),
                          "top_apps": [{"name": k, "count": v} for k, v in self.za_reason_apps.get(code, Counter()).most_common(5)]})
                reasons.append(x)
            fam = Counter()
            for x in reasons:
                fam[x["family"]] += x["count"]
            users_fail = []
            for user, nf in self.za_user_fail.top(MAX_DISTINCT):
                total = self.za_users.c.get(user, nf)
                if user and user != OTHER and (nf >= USER_FAIL_ALWAYS or (nf >= USER_FAIL_MIN and nf / max(total, 1) >= USER_FAIL_SHARE)):
                    users_fail.append({"name": user, "failures": nf, "connections": total})
            for u in users_fail[:25]:
                anomalies.append({"kind": "user_failures", "series": "failures", "user": u["name"],
                                  "what": f"{u['failures']} failed ZPA connections for one user (of {u['connections']})", "count": u["failures"]})
            for user, n in self.zs_authfail_users.top(25):
                if n >= 5 and user != OTHER:
                    anomalies.append({"kind": "user_failures", "series": "auth_failures", "user": user,
                                      "what": f"{n} failed ZPA sign-ins for one user", "count": n})
            dest_rows = []
            for d, n in self.za_dests.top(TOP):
                port = self.za_dest_port.get(d, Counter()).most_common(1)
                p, proto = (port[0][0].split("/") + ["6"])[:2] if port else ("", "6")
                dest_rows.append({"name": d, "count": n, "failures": self.za_dest_fail.c.get(d, 0), "port": p,
                                  "proto": "udp" if proto == "17" else "tcp", "link": linkable(d)})
            newd = _new_destinations(self.za_dest_first, lo, hi, self.za_dests.c)
            if newd.get("total"):
                anomalies.append({"kind": "new_destinations", "series": "zpa", "what": f"{newd['total']} ZPA destinations first seen since {newd['since']}",
                                  "count": newd["total"]})
            with_fail = lambda top, fails: [{"name": k, "count": v, "failures": fails.c.get(k, 0)} for k, v in top.top(TOP)]
            rep["zpa"] = {
                "activity": {"records": self.za_records, "connections": self.za_connections,
                             "failed_connections": self.za_failed, "failure_records": self.za_fail_records,
                             "users": with_fail(self.za_users, self.za_user_fail), "apps": with_fail(self.za_apps, self.za_app_fail),
                             "connectors": with_fail(self.za_conns, self.za_conn_fail), "destinations": dest_rows,
                             "service_edges": with_fail(self.za_edges, self.za_edge_fail), "rules": _rows(self.za_rules),
                             "reasons": reasons, "families": [{"family": f, "label": REASON_FAMILIES.get(f, ("Normal end",))[0], "count": n}
                                                              for f, n in fam.most_common()],
                             "users_many_failures": users_fail[:100], "new_destinations": newd} if self.za_records else None,
                "status": None,
                "timeline": tl,
            }
            if self.kinds["zpa_status"]:
                sess = self._sessions()
                rep["zpa"]["status"] = {"records": self.kinds["zpa_status"], "auth_failures": self.zs_authfail,
                                        "auth_failure_users": _rows(self.zs_authfail_users),
                                        "client_types": [{"name": CLIENT_TYPES.get(k, k), "raw": k, "count": v} for k, v in self.zs_client_types.top(50)],
                                        "platforms": _rows(self.zs_platforms, 50), "versions": _rows(self.zs_versions, 50),
                                        "countries": _rows(self.zs_countries, 50), "service_edges": _rows(self.zs_edges, 50),
                                        "posture_misses": _rows(self.zs_posture_miss, 50), "trusted": dict(self.zs_trusted), **sess}
        if self.kinds["zpa_connector"] or self.kinds["zpa_pse"]:
            rep["health"] = {"connectors": self._health_rows("zpa_connector", self.last_time) if self.kinds["zpa_connector"] else None,
                             "service_edges": self._health_rows("zpa_pse", self.last_time) if self.kinds["zpa_pse"] else None}
            for part in ("connectors", "service_edges"):
                for f in ((rep["health"][part] or {}).get("findings") or [])[:25]:
                    anomalies.append({"kind": "health", "series": part, "what": f["what"], "count": 1})
        zia_kinds = [k for k in ("zia_web", "zia_fw", "zia_dns") if self.kinds[k]]
        if zia_kinds:
            names = [f"{k}:{s}" for k in zia_kinds for s in ("all", "blocked")]
            tl = timeline(self.times, names)
            rep["zia"] = {"timeline": tl}
            for k in zia_kinds:
                label = LOG_LABELS[k]
                anomalies += spikes(tl, f"{k}:blocked", f"{label} blocks")
                anomalies += spikes(tl, f"{k}:all", f"{label} transactions")
                a = self.zi[k]
                dest_rows = []
                for d, n in a["dests"].top(TOP):
                    port = a["dest_port"].get(d, Counter()).most_common(1)
                    p, proto = (port[0][0].split("/") + [""])[:2] if port else ("", "")
                    dest_rows.append({"name": d, "count": n, "blocked": a["dest_blocks"].c.get(d, 0), "port": p, "proto": proto, "link": linkable(d)})
                rules = []
                for key, n in a["rules"].top(TOP):
                    if key == OTHER:
                        rules.append({"module": "", "rule": OTHER, "action": "", "count": n})
                        continue
                    module, rule, action = key.split("\x1f")
                    rules.append({"module": module, "rule": rule, "action": action, "count": n})
                newd = _new_destinations(a["dest_first"], lo, hi, a["dests"].c)
                if newd.get("total"):
                    anomalies.append({"kind": "new_destinations", "series": k, "what": f"{newd['total']} {label} destinations first seen since {newd['since']}",
                                      "count": newd["total"]})
                for user, n in a["threat_users"].top(10):
                    if n >= 3 and user and user != OTHER:
                        anomalies.append({"kind": "user_threats", "series": k, "user": user, "what": f"{n} threat events for one user ({label})", "count": n})
                ssl = dict(a["ssl"])
                rep["zia"][k] = {
                    "label": label, "records": a["records"], "actions": dict(a["actions"]),
                    "users": [{"name": u, "count": n, "blocked": a["user_blocks"].c.get(u, 0)} for u, n in a["users"].top(TOP)],
                    "destinations": dest_rows, "categories": [{"name": c, "count": n, "blocked": a["cat_blocks"].c.get(c, 0)} for c, n in a["cats"].top(TOP)],
                    "apps": _rows(a["apps"]), "rules": rules, "locations": _rows(a["locations"]), "block_reasons": _rows(a["reasons"]),
                    "dlp": {"events": a["dlp"], "actions": dict(a["dlp_actions"]), "engines": _rows(a["dlp_engines"]),
                            "dictionaries": _rows(a["dlp_dicts"]), "rules": _rows(a["dlp_rules"]), "users": _rows(a["dlp_users"])} if k == "zia_web" else None,
                    "threats": {"events": a["threats"], "actions": dict(a["threat_actions"]), "names": _rows(a["threat_names"]),
                                "categories": _rows(a["threat_cats"]), "users": _rows(a["threat_users"]), "destinations": _rows(a["threat_dests"])},
                    "ssl": {"inspected": ssl.get("inspected", 0), "not_inspected": ssl.get("not_inspected", 0),
                            "plain_http": ssl.get("plain_http", 0), "not_logged": ssl.get("not_logged", 0),
                            "reasons": _rows(a["ssl_reasons"]), "destinations_not_inspected": _rows(a["ssl_dests_no"])} if k == "zia_web" else None,
                    "new_destinations": newd,
                }
        rep["anomalies"] = anomalies
        return rep


# ── Entry point ──────────────────────────────────────────────────────
def analyze(files: List[Dict[str, Any]], feed_format: str = "") -> Dict[str, Any]:
    """Read the uploaded files (archives opened by log_analyzer.expand, with
    its caps) and return the report. Raises ValueError with a plain reason
    when nothing could be read."""
    import log_analyzer
    if not files:
        raise ValueError("no files were uploaded")
    template = FeedTemplate(feed_format) if (feed_format or "").strip() else None
    members, notes = log_analyzer.expand(files)
    stats: Dict[str, Any] = {"lines": 0, "malformed": 0, "oversized": 0, "unrecognised": 0, "capped": False,
                             "malformed_examples": [], "files": []}
    an = Analysis()
    for kind, rec in read_records(members, template, stats):
        an.add(kind, rec)
    del members
    if not sum(an.kinds.values()):
        why = (f"{stats['malformed']} lines could not be read" if stats["malformed"] else
               f"{stats['unrecognised']} JSON records were not ZPA LSS or ZIA NSS logs" if stats["unrecognised"] else "the files hold no log lines")
        raise ValueError(f"No ZPA or ZIA log records were found ({why}). Upload ZPA LSS JSON (User Activity, User Status, "
                         "App Connector or Private Service Edge Status) or a ZIA NSS web, firewall or DNS feed (JSON, a CSV or TSV with a "
                         "header, or the default tab-separated format); for a custom NSS feed, paste its output format.")
    rep = an.result()
    if stats["capped"]:
        notes.append(f"stopped after {MAX_LINES:,} lines; the rest was not read")
    rep["input"] = {"lines": stats["lines"], "records": sum(an.kinds.values()), "malformed": stats["malformed"],
                    "oversized": stats["oversized"], "unrecognised": stats["unrecognised"], "capped": stats["capped"],
                    "malformed_examples": stats["malformed_examples"], "files": stats["files"][:200], "notes": notes,
                    "template": {"kind": template.kind, "fields": len(template.fields)} if template else None}
    rep["limits"] = {"max_lines": MAX_LINES, "max_line_kb": MAX_LINE_BYTES // 1024, "spike_factor": SPIKE_FACTOR, "spike_min": SPIKE_MIN,
                     "user_fail_min": USER_FAIL_MIN, "user_fail_share": USER_FAIL_SHARE, "user_fail_always": USER_FAIL_ALWAYS,
                     "session_min_seconds": SESSION_MIN_SECONDS, "session_merge_gap": SESSION_MERGE_GAP}
    return rep


# ── Counts only ──────────────────────────────────────────────────────
_PERSONAL_LISTS = ("users", "auth_failure_users", "users_many_failures", "top_users")


def counts_only(rep: Dict[str, Any]) -> Dict[str, Any]:
    """A copy of the report with the people taken out: user names become
    "user 1", "user 2"... (the same person keeps the same number), the
    consolidated sessions (IP addresses, devices, cities) are dropped."""
    names: Dict[str, str] = {}

    def alias(u: Any) -> str:
        u = str(u or "")
        if not u or u == OTHER:
            return u
        if u not in names:
            names[u] = f"user {len(names) + 1}"
        return names[u]

    def walk(x: Any, key: str = "") -> Any:
        if isinstance(x, dict):
            out = {}
            for k, v in x.items():
                if k in ("rows",) and key == "status":
                    out[k] = []
                    continue
                if k == "user":
                    out[k] = alias(v)
                    continue
                if k in _PERSONAL_LISTS and isinstance(v, list):
                    out[k] = [dict(i, name=alias(i.get("name"))) if isinstance(i, dict) else i for i in v]
                    continue
                out[k] = walk(v, k)
            return out
        if isinstance(x, list):
            return [walk(i, key) for i in x]
        return x

    out = walk(json.loads(json.dumps(rep, default=str)))
    if (out.get("zpa") or {}).get("status"):
        out["zpa"]["status"]["rows"] = []
    out["counts_only"] = True
    return out


# ── Flat tables (CSV, Excel, PDF share them) ─────────────────────────
def tables(rep: Dict[str, Any]) -> List[Tuple[str, List[str], List[List[Any]]]]:
    """(title, columns, rows) for every table in the report, in page order."""
    out: List[Tuple[str, List[str], List[List[Any]]]] = []
    inp = rep.get("input") or {}
    out.append(("Summary", ["Item", "Value"], [
        ["Records read", inp.get("records", 0)], ["Lines read", inp.get("lines", 0)], ["Malformed lines (skipped)", inp.get("malformed", 0)],
        ["Lines too long (skipped)", inp.get("oversized", 0)], ["JSON records of another kind", inp.get("unrecognised", 0)],
        ["First event", (rep.get("period") or {}).get("first") or ""], ["Last event", (rep.get("period") or {}).get("last") or ""],
        ["Counts only (no people)", "yes" if rep.get("counts_only") else "no"],
    ] + [[f"{t['label']} records", t["records"]] for t in rep.get("log_types") or []]))
    zpa = rep.get("zpa") or {}
    act = zpa.get("activity") or {}
    if act:
        out.append(("ZPA connections", ["Item", "Value"], [["Connections", act.get("connections", 0)], ["Failed connections", act.get("failed_connections", 0)]]))
        out.append(("ZPA failure reasons", ["Code", "Kind", "Count", "Users", "What it means", "What to do"],
                    [[x["code"], x["label"], x["count"], x["users"], x["what"], x["do"]] for x in act.get("reasons") or []]))
        for key, title in (("users", "ZPA users"), ("apps", "ZPA applications"), ("connectors", "ZPA App Connectors"), ("service_edges", "ZPA Service Edges")):
            out.append((title, ["Name", "Connections", "Failures"], [[x["name"], x["count"], x.get("failures", 0)] for x in act.get(key) or []]))
        out.append(("ZPA destinations", ["Host", "Connections", "Failures", "Port"], [[x["name"], x["count"], x["failures"], x["port"]] for x in act.get("destinations") or []]))
        out.append(("ZPA access rules", ["Rule", "Connections"], [[x["name"], x["count"]] for x in act.get("rules") or []]))
    st = zpa.get("status") or {}
    if st:
        out.append(("ZPA sessions", ["Item", "Value"], [["Sessions (consolidated)", st.get("sessions", 0)], ["Session IDs in the log", st.get("raw_session_ids", 0)],
                                                       ["Sign-in checks dropped", st.get("probes_dropped", 0)], ["Still open", st.get("still_open", 0)],
                                                       ["Users", st.get("users", 0)], ["Median minutes", st.get("median_minutes")],
                                                       ["Sign-in failures", st.get("auth_failures", 0)]]))
        for key, title in (("client_types", "ZPA client types"), ("platforms", "ZPA platforms"), ("versions", "Client Connector versions"),
                           ("countries", "ZPA countries"), ("posture_misses", "Posture checks failed"), ("auth_failure_users", "ZPA sign-in failures by user"),
                           ("top_users", "ZPA sessions by user")):
            out.append((title, ["Name", "Count"], [[x["name"], x["count"]] for x in st.get(key) or []]))
        if st.get("rows"):
            out.append(("ZPA session list", ["User", "Client", "Start", "End", "Seconds", "Public IP", "Other public IPs", "Private IP", "City", "Country",
                                             "Device", "Platform", "Version", "Trusted network", "Service Edge", "Bytes in", "Bytes out", "Session IDs"],
                        [[r["user"], r["client_type"], r["start"], r["end"], r["duration_s"], r["public_ip"], r["other_public_ips"], r["private_ip"], r["city"],
                          r["country"], r["device"], r["platform"], r["version"], r["trusted_network"], r["service_edge"], r["bytes_rx"], r["bytes_tx"],
                          r["session_ids"]] for r in st["rows"]]))
    for part, title in (("connectors", "App Connector health"), ("service_edges", "Private Service Edge health")):
        h = (rep.get("health") or {}).get(part)
        if h:
            out.append((title, ["Name", "Group", "State", "Disconnects", "Failed sign-ins", "Last seen", "Versions", "Max CPU %", "Max memory %", "Notes"],
                        [[r["name"], r["group"], r["state"], r["disconnected"], r["auth_failed"], r["last_seen"], r["versions"], r["cpu_max"], r["mem_max"],
                          "; ".join(r["notes"])] for r in h["rows"]]))
    for k in ("zia_web", "zia_fw", "zia_dns"):
        z = (rep.get("zia") or {}).get(k)
        if not z:
            continue
        lab = z["label"]
        out.append((f"{lab} actions", ["Action", "Count"], [[a, n] for a, n in sorted(z["actions"].items(), key=lambda x: -x[1])]))
        out.append((f"{lab} rules hit", ["Module", "Rule", "Action", "Count"], [[x["module"], x["rule"], x["action"], x["count"]] for x in z["rules"]]))
        out.append((f"{lab} categories", ["Category", "Count", "Blocked"], [[x["name"], x["count"], x["blocked"]] for x in z["categories"]]))
        out.append((f"{lab} destinations", ["Destination", "Count", "Blocked", "Port"], [[x["name"], x["count"], x["blocked"], x["port"]] for x in z["destinations"]]))
        out.append((f"{lab} users", ["User", "Count", "Blocked"], [[x["name"], x["count"], x["blocked"]] for x in z["users"]]))
        out.append((f"{lab} applications", ["Application", "Count"], [[x["name"], x["count"]] for x in z["apps"]]))
        t = z["threats"]
        out.append((f"{lab} threats", ["Threat", "Count"], [[x["name"], x["count"]] for x in t["names"]]))
        if z.get("dlp"):
            d = z["dlp"]
            out.append((f"{lab} DLP", ["Kind", "Name", "Count"], [["engine", x["name"], x["count"]] for x in d["engines"]] +
                        [["dictionary", x["name"], x["count"]] for x in d["dictionaries"]] + [["rule", x["name"], x["count"]] for x in d["rules"]]))
        if z.get("ssl"):
            s = z["ssl"]
            out.append((f"{lab} SSL inspection", ["Item", "Count"], [["Inspected", s["inspected"]], ["Not inspected", s["not_inspected"]],
                                                                     ["Plain HTTP", s["plain_http"]], ["Not in the log", s["not_logged"]]] +
                        [[f"Not inspected: {x['name']}", x["count"]] for x in s["reasons"]]))
    out.append(("Anomalies", ["Kind", "What", "Count"], [[a["kind"], a["what"], a.get("count", "")] for a in rep.get("anomalies") or []]))
    for name, tl in (("ZPA over time", (rep.get("zpa") or {}).get("timeline")), ("ZIA over time", (rep.get("zia") or {}).get("timeline"))):
        if tl and tl.get("points"):
            out.append((name, ["Bucket start (UTC)"] + list(tl["series"]), [[p["t"]] + list(p["v"]) for p in tl["points"]]))
    return out


def to_csv(rep: Dict[str, Any]) -> str:
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(["Section", "Columns / values"])
    for title, cols, rows in tables(rep):
        w.writerow([title] + cols)
        for r in rows:
            w.writerow([title] + [("\n".join(map(str, v)) if isinstance(v, list) else v) for v in r])
    return buf.getvalue()


def to_xlsx(rep: Dict[str, Any]) -> bytes:
    import xlsx_writer
    wb = xlsx_writer.Workbook(title="Traffic and session logs", subject="ZPA LSS and ZIA NSS log analysis")
    for title, cols, rows in tables(rep):
        wb.add_sheet(title[:31], cols, rows[:100_000])
    return wb.to_bytes()


def to_pdf(rep: Dict[str, Any]) -> bytes:
    import pdf_writer
    doc = pdf_writer.PdfDocument("Traffic and session logs", footer="Zscaler Made Easy: traffic and session logs")
    doc.heading("Traffic and session logs")
    p = rep.get("period") or {}
    doc.paragraph(f"From {p.get('first') or 'unknown'} to {p.get('last') or 'unknown'} (times as written in the logs)."
                  + (" Counts only: no user names, addresses or devices." if rep.get("counts_only") else ""))
    for title, cols, rows in tables(rep):
        if not rows or title.endswith("session list") or title.endswith("over time"):
            continue
        doc.heading(title, 2)
        doc.table(cols, [[("; ".join(map(str, v)) if isinstance(v, list) else v) for v in r] for r in rows[:25]])
    return doc.to_bytes()


# ── Saved reports (only when the admin saves one) ────────────────────
SAVED_MAX = 50
SAVED_MAX_BYTES = 30 * 1024 * 1024
_SAVED_NAME = re.compile(r"^\d{8}-\d{6}-[A-Za-z0-9_-]{8}\.json$")


def saved_dir() -> str:
    override = os.environ.get("DLP_CHECK_TRAFFIC_LOG_REPORTS")
    if override:
        return override
    from zscaler_update_check import data_dir
    return os.path.join(data_dir(), "traffic_log_reports")


def _title(t: Any) -> str:
    s = re.sub(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]", "", str(t or "")).strip()
    return s[:80] or "Traffic and session logs"


def save_report(rep: Dict[str, Any], title: str = "", names: bool = False) -> Dict[str, Any]:
    """Write the report as an owner-only file; counts only unless `names`."""
    folder = saved_dir()
    safe_files.private_makedirs(folder)
    existing = [n for n in os.listdir(folder) if _SAVED_NAME.match(n)]
    if len(existing) >= SAVED_MAX:
        raise ValueError(f"{SAVED_MAX} reports are saved already; delete one first")
    body = dict(rep if names else counts_only(rep))
    body.pop("report_id", None)
    stamp = datetime.now(timezone.utc)
    name = f"{stamp.strftime('%Y%m%d-%H%M%S')}-{secrets.token_urlsafe(6)[:8]}.json"
    if not _SAVED_NAME.match(name):   # token_urlsafe can give '-' and '_', both allowed; this never trips
        name = f"{stamp.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.json"
    body["saved"] = {"title": _title(title), "at": stamp.isoformat(timespec="seconds").replace("+00:00", "Z"), "names": bool(names)}
    safe_files.write_private_atomic(os.path.join(folder, name), json.dumps(body, default=str))
    return {"name": name, **body["saved"]}


def _saved_path(name: str) -> str:
    if not _SAVED_NAME.match(str(name or "")):
        raise ValueError("not a saved report name")
    return os.path.join(saved_dir(), name)


def load_saved(name: str) -> Dict[str, Any]:
    p = _saved_path(name)
    if not os.path.isfile(p) or os.path.islink(p):
        raise FileNotFoundError(name)
    if os.path.getsize(p) > SAVED_MAX_BYTES:
        raise ValueError("the saved report is larger than this app reads")
    with open(p, "r", encoding="utf-8") as f:
        data = safe_files.strict_json_loads(f.read())
    if not isinstance(data, dict) or data.get("kind") != KIND or data.get("version") != VERSION:
        raise ValueError("the file is not a saved traffic and session log report")
    return data


def list_saved() -> List[Dict[str, Any]]:
    folder = saved_dir()
    if not os.path.isdir(folder):
        return []
    out = []
    for n in sorted(os.listdir(folder), reverse=True):
        if not _SAVED_NAME.match(n):
            continue
        try:
            d = load_saved(n)
        except (OSError, ValueError):
            out.append({"name": n, "title": "(could not be read)", "at": "", "names": False, "records": None})
            continue
        sv = d.get("saved") or {}
        out.append({"name": n, "title": _title(sv.get("title")), "at": str(sv.get("at") or "")[:40], "names": bool(sv.get("names")),
                    "records": (d.get("input") or {}).get("records"), "period": d.get("period")})
    return out


def delete_saved(name: str) -> bool:
    p = _saved_path(name)
    if os.path.isfile(p) and not os.path.islink(p):
        os.remove(p)
        return True
    return False
