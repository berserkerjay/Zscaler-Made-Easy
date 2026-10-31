"""Rules as a spreadsheet: the CSV round-trip format for ZIA Cloud Firewall
rules, ZIA URL filtering rules and ZPA access policy rules.

Export writes one row per rule, top rule first, with documented columns:
names, never ids (a location, a group, a network service, an application
segment is written by its name), the rule's order and (ZIA) its admin
rank. Lists in one cell are separated by a semicolon ("; "). Every cell is
made safe to open in a spreadsheet: a text cell that starts with = + - @
TAB, CR or LF is written with a leading single quote (csv_safe), and a
cell that itself starts with a quote followed by one of those characters
gets one more, so reading the file back gives exactly what was exported.

Import (parse) is the untrusted side: the file is capped in size, rows,
cell length and values per cell, must be UTF-8 (a byte-order mark is
allowed), must name a known column in every header cell and the `name`
column, and is checked value by value (enumerations, numbers, booleans,
IP addresses, country codes). Nothing here reads or writes a tenant: the
planner (ops_rule_csv) resolves the names against the tenant and plans the
adds, updates, moves and deletes, which go through the Bulk changes
engine's preview, gates, read-back and Undo.

A column left out of the file is not managed: the rules keep whatever the
tenant has for it. A blank `order` keeps a rule where it is (a new rule
goes to the bottom, above the Default rule). The columns a ZIA rule has
that the file does not carry (users, devices, time windows, workload
groups, ...) are always kept as they are.

Zscaler semantics (zscaler-sdk-python 1.11.3): Cloud Firewall rules are
zia.cloud_firewall_rules (firewallFilteringRules; name at most 31
characters per add_rule's docstring), URL filtering rules zia.url_filtering
(urlFilteringRules), ZPA access rules zpa.policies (policySet ACCESS_POLICY,
conditions as AND of OR blocks, add_access_rule / update_access_rule /
delete_rule / bulk_reorder_rules). The action values below are the ones
the ZIA and ZPA admin portals offer; the SDK does not enumerate them
(assumed).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import unicodedata
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import csv_safe

MAX_BYTES = 1_000_000        # a file larger than this is refused unread
MAX_ROWS = 2000              # rules per file
MAX_CELL = 10240             # characters in one cell (ZIA's description limit, assumed)
MAX_VALUES = 500             # values in one list cell
MAX_PROBLEMS = 50            # problems reported per file
SEP = ";"

FORMAT_NOTE = ("UTF-8 CSV with a header row. Lists in one cell are separated by a semicolon. Names, not ids. "
               "A column left out is not changed. Rows are matched to rules by name.")


class CsvError(ValueError):
    """The file cannot be used; `problems` lists why (row, column, message)."""

    def __init__(self, message: str, problems: Optional[List[Dict[str, Any]]] = None):
        super().__init__(message)
        self.problems = list(problems or [])


# ---------------------------------------------------------------------------
# Columns
# ---------------------------------------------------------------------------
# kind:  name | order | rank | state | enum | text | bool | list | refs | readonly
# field: the API field (ZIA snake_case as the SDK reads and writes it); for
#        ZPA the condition family or the rule field.
# check: for kind list, the value rule (ip, addr, country, token, client_type).
# lookup: for kind refs, the object list the names resolve against.

def _col(name: str, kind: str, help_: str, *, field: str = "", values: Sequence[str] = (), check: str = "", lookup: str = "",
         required_new: bool = False) -> Dict[str, Any]:
    return {"name": name, "kind": kind, "field": field or name, "help": help_, "values": list(values), "check": check,
            "lookup": lookup, "required_new": required_new}


_ZIA_COMMON_HEAD = [
    _col("name", "name", "The rule's name. Rows are matched to rules by it (exact, then ignoring case)."),
    _col("order", "order", "The rule's position, 1 at the top. Blank keeps an existing rule where it is; a new rule goes to the bottom."),
    _col("rank", "rank", "The admin rank, 0 (highest) to 7. Blank keeps it (7 for a new rule)."),
    _col("state", "state", "ENABLED or DISABLED. New rules are created DISABLED unless you tick 'create new rules enabled'.",
         values=("ENABLED", "DISABLED")),
]
_ZIA_WHO = [
    _col("locations", "refs", "Location names.", lookup="locations"),
    _col("location_groups", "refs", "Location group names.", lookup="location_groups"),
    _col("departments", "refs", "Department names.", lookup="departments"),
    _col("groups", "refs", "User group names.", lookup="groups"),
    _col("labels", "refs", "Rule label names.", lookup="labels"),
]

POLICIES: Dict[str, Dict[str, Any]] = {
    "firewall": {
        "label": "Cloud Firewall", "product": "zia", "channel": "firewall", "order_field": "order", "name_max": 31,
        "columns": _ZIA_COMMON_HEAD + [
            _col("action", "enum", "ALLOW, BLOCK_DROP, BLOCK_RESET, BLOCK_ICMP or EVAL_NWAPP.",
                 values=("ALLOW", "BLOCK_DROP", "BLOCK_RESET", "BLOCK_ICMP", "EVAL_NWAPP"), required_new=True),
            _col("description", "text", "Free text."),
            _col("src_ips", "list", "Source IP addresses, CIDR blocks or ranges (a-b).", check="addr"),
            _col("dest_addresses", "list", "Destination IP addresses, CIDR blocks, ranges or FQDNs.", check="dest"),
            _col("dest_countries", "list", "Destination countries as ZIA country codes, e.g. COUNTRY_US.", check="country"),
            _col("dest_ip_categories", "list", "Destination URL/IP categories, e.g. BOTNET.", check="token"),
            _col("nw_applications", "list", "Network applications, e.g. SKYPE.", check="token"),
            _col("nw_services", "refs", "Network service names.", lookup="network_services"),
            _col("nw_service_groups", "refs", "Network service group names.", lookup="network_service_groups"),
            _col("src_ip_groups", "refs", "Source IP group names.", lookup="ip_source_groups"),
            _col("dest_ip_groups", "refs", "Destination IP group names.", lookup="ip_destination_groups"),
        ] + _ZIA_WHO + [
            _col("enable_full_logging", "bool", "true or false."),
        ],
    },
    "url_filtering": {
        "label": "URL filtering", "product": "zia", "channel": "url", "order_field": "order", "name_max": 31,
        "columns": _ZIA_COMMON_HEAD + [
            _col("action", "enum", "ALLOW, CAUTION, BLOCK or ISOLATE.", values=("ALLOW", "CAUTION", "BLOCK", "ISOLATE"), required_new=True),
            _col("description", "text", "Free text."),
            _col("url_categories", "refs", "URL categories: a predefined category id (GAMBLING) or a custom category's name.",
                 lookup="url_categories", required_new=True),
            _col("protocols", "list", "Protocols, e.g. ANY_RULE, HTTPS_RULE (ANY_RULE for a new rule when blank).", check="token"),
            _col("request_methods", "list", "HTTP methods, e.g. GET; POST. Blank: any.", check="token"),
        ] + _ZIA_WHO + [
            _col("block_override", "bool", "true or false: an allowed admin may override a block."),
        ],
    },
    "zpa_access": {
        "label": "ZPA access policy", "product": "zpa", "channel": "", "order_field": "rule_order", "name_max": 255,
        "columns": [
            _col("name", "name", "The rule's name. Rows are matched to rules by it (exact, then ignoring case)."),
            _col("order", "order", "The rule's position, 1 at the top. Blank keeps an existing rule where it is; a new rule goes to the bottom.",
                 field="rule_order"),
            _col("action", "enum", "ALLOW or DENY.", values=("ALLOW", "DENY"), required_new=True),
            _col("description", "text", "Free text."),
            _col("custom_msg", "text", "The message a denied user sees."),
            _col("app_segments", "refs", "Application segment names (any of them, or of the segment groups).", field="APP", lookup="zpa_segments"),
            _col("segment_groups", "refs", "Segment group names.", field="APP_GROUP", lookup="zpa_segment_groups"),
            _col("client_types", "list", "Client types, e.g. zpn_client_type_zapp; zpn_client_type_exporter.", field="CLIENT_TYPE",
                 check="client_type"),
            _col("scim_groups", "refs", "SCIM groups as IdP name::group name.", field="SCIM_GROUP", lookup="zpa_scim_groups"),
            _col("other_conditions", "readonly", "Conditions this file cannot express (posture, SAML, trusted networks, negated "
                                                  "blocks ...): shown for reference, always kept as they are, never read on import."),
        ],
    },
}
ZPA_FAMILIES = ("APP", "APP_GROUP", "CLIENT_TYPE", "SCIM_GROUP")


def columns(policy: str) -> List[Dict[str, Any]]:
    return POLICIES[policy]["columns"]


def column_names(policy: str) -> List[str]:
    return [c["name"] for c in columns(policy)]


def column_docs() -> Dict[str, Any]:
    """What the page and the help show about the format (no callables)."""
    return {"format": FORMAT_NOTE, "separator": SEP, "limits": {"bytes": MAX_BYTES, "rows": MAX_ROWS, "cell": MAX_CELL, "values": MAX_VALUES},
            "policies": {p: {"label": d["label"], "product": d["product"], "name_max": d["name_max"],
                             "columns": [{k: c[k] for k in ("name", "kind", "help", "values")} for c in d["columns"]]}
                         for p, d in POLICIES.items()}}


# ---------------------------------------------------------------------------
# Cells: spreadsheet-safe out, exactly back in
# ---------------------------------------------------------------------------
_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def safe_out(value: Any) -> str:
    """One cell for the file: csv_safe's neutralisation (a leading quote on
    a formula trigger), plus one more quote on a value that already starts
    with a quote and a trigger, so read_cell gives the value back."""
    s = "" if value is None else str(value)
    if len(s) >= 2 and s[0] == "'" and s[1] in _TRIGGERS + ("'",):
        return "'" + s
    out = csv_safe.safe_cell(s)
    return out if isinstance(out, str) else s


def read_cell(raw: str) -> str:
    """The value of one cell from the file: one neutralising quote taken off."""
    if len(raw) >= 2 and raw[0] == "'" and raw[1] in _TRIGGERS + ("'",):
        return raw[1:]
    return raw


_BIDI = re.compile("[‪-‮⁦-⁩\ud800-\udfff]")


def name_key(name: Any) -> str:
    """How a name is matched: NFC, trimmed, and the characters the export
    replaces (bidirectional controls, lone surrogates) replaced the same
    way, so an exported rule always finds itself again."""
    return _BIDI.sub("�", unicodedata.normalize("NFC", str(name or "")).strip())


def split_list(cell: str) -> List[str]:
    return [v.strip() for v in str(cell or "").split(SEP) if v.strip()]


def join_list(values: Iterable[Any]) -> str:
    return "; ".join(str(v) for v in values if str(v) != "")


# ---------------------------------------------------------------------------
# Value checks
# ---------------------------------------------------------------------------
_TOKEN = re.compile(r"^[A-Za-z][A-Za-z0-9_]{0,127}$")
_COUNTRY = re.compile(r"^COUNTRY_[A-Z]{2}$")
_CLIENT_TYPE = re.compile(r"^zpn_client_type_[a-z0-9_]{1,60}$")
_FQDN = re.compile(r"^(\*\.)?([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,62})\.)+[A-Za-z]{2,63}\.?$")


def _is_addr(v: str) -> bool:
    try:
        if "-" in v:
            a, b = v.split("-", 1)
            ipaddress.ip_address(a.strip())
            ipaddress.ip_address(b.strip())
            return True
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        return False


def _check_value(check: str, v: str) -> Optional[str]:
    if check == "addr" and not _is_addr(v):
        return f"'{v}' is not an IP address, CIDR block or range"
    if check == "dest" and not (_is_addr(v) or _FQDN.match(v)):
        return f"'{v}' is not an IP address, CIDR block, range or domain name"
    if check == "country" and not _COUNTRY.match(v):
        return f"'{v}' is not a ZIA country code (COUNTRY_ and two letters, e.g. COUNTRY_US)"
    if check == "token" and not _TOKEN.match(v):
        return f"'{v}' is not a valid value (letters, digits and _)"
    if check == "client_type" and not _CLIENT_TYPE.match(v):
        return f"'{v}' is not a ZPA client type (zpn_client_type_...)"
    return None


def _bool(v: str) -> Optional[bool]:
    s = v.strip().lower()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


# ---------------------------------------------------------------------------
# Parse (untrusted)
# ---------------------------------------------------------------------------

def parse(text: Any, policy: str) -> Dict[str, Any]:
    """Validate a CSV file for `policy`. Returns {policy, columns (the
    managed columns, in file order), rows: [{line, values: {column: value}}]}
    where a list column's value is a list of strings, an order or rank an
    int or None, a bool a bool or None. Raises CsvError with every problem
    found (up to MAX_PROBLEMS)."""
    if policy not in POLICIES:
        raise CsvError(f"Unknown policy '{str(policy)[:40]}'. Use one of: {', '.join(POLICIES)}.")
    if isinstance(text, bytes):
        if len(text) > MAX_BYTES:
            raise CsvError(f"The file is larger than {MAX_BYTES // 1000} kB; split it.")
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise CsvError("The file is not UTF-8 text: save it as CSV UTF-8.") from None
    if not isinstance(text, str):
        raise CsvError("The file must be CSV text.")
    if len(text.encode("utf-8", "surrogatepass")) > MAX_BYTES:
        raise CsvError(f"The file is larger than {MAX_BYTES // 1000} kB; split it.")
    if text.startswith("﻿"):
        text = text[1:]
    if "\x00" in text:
        raise CsvError("The file contains a NUL character: it is not a CSV text file.")
    if not text.strip():
        raise CsvError("The file is empty.")
    cols = {c["name"]: c for c in columns(policy)}
    problems: List[Dict[str, Any]] = []

    def bad(line: int, col: str, msg: str) -> None:
        if len(problems) < MAX_PROBLEMS:
            problems.append({"line": line, "column": col, "message": msg})

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        header = next(reader, None)
    except csv.Error as e:
        raise CsvError(f"The header row cannot be read as CSV: {str(e)[:120]}") from None
    if not header:
        raise CsvError("The file has no header row.")
    header = [read_cell(h).strip().lower() for h in header]
    for i, h in enumerate(header):
        if h not in cols:
            bad(1, h[:60] or f"column {i + 1}", f"unknown column '{h[:60]}'. Known columns: {', '.join(cols)}")
    if len(set(header)) != len(header):
        bad(1, "", "a column is named twice")
    if "name" not in header:
        bad(1, "name", "the 'name' column is required")
    if problems:
        raise CsvError("The header row is not valid for this policy.", problems)
    managed = [h for h in header if cols[h]["kind"] != "readonly"]
    rows: List[Dict[str, Any]] = []
    seen: Dict[str, int] = {}
    orders: Dict[int, int] = {}
    try:
        for rec in reader:
            line = reader.line_num
            if not any(str(x).strip() for x in rec):
                continue
            if len(rows) >= MAX_ROWS:
                raise CsvError(f"The file has more than {MAX_ROWS} rules; split it.")
            if len(rec) != len(header):
                bad(line, "", f"this row has {len(rec)} cells, the header has {len(header)}")
                continue
            vals: Dict[str, Any] = {}
            for h, raw in zip(header, rec):
                c = cols[h]
                if c["kind"] == "readonly":
                    continue
                if len(raw) > MAX_CELL:
                    bad(line, h, f"longer than {MAX_CELL} characters")
                    continue
                v = read_cell(raw)
                if c["kind"] != "text" and _CONTROL.search(v):
                    bad(line, h, "contains a control character")
                    continue
                vals[h] = _value(c, v, line, bad)
            name = str(vals.get("name") or "")
            if not name:
                bad(line, "name", "the rule needs a name")
                continue
            k = name_key(name).casefold()
            if k in seen:
                bad(line, "name", f"'{name}' is also on line {seen[k]}: each rule once")
                continue
            seen[k] = line
            o = vals.get("order")
            if isinstance(o, int):
                if o in orders:
                    bad(line, "order", f"order {o} is also on line {orders[o]}: each position once")
                orders[o] = line
            rows.append({"line": line, "values": vals})
    except csv.Error as e:
        bad(reader.line_num, "", f"not valid CSV: {str(e)[:120]}")
    if problems:
        raise CsvError(f"{len(problems)}{'+' if len(problems) >= MAX_PROBLEMS else ''} problem(s) in the file; nothing was planned.", problems)
    if not rows:
        raise CsvError("The file has a header but no rules.")
    return {"policy": policy, "columns": managed, "rows": rows}


def _value(c: Dict[str, Any], v: str, line: int, bad) -> Any:
    kind, name = c["kind"], c["name"]
    s = v.strip()
    if kind == "name":
        if not s:
            return ""
        if len(s) > 255:
            bad(line, name, "longer than 255 characters")
        return unicodedata.normalize("NFC", s)
    if kind == "text":
        return v
    if kind in ("order", "rank"):
        if not s:
            return None
        if not re.fullmatch(r"\d{1,5}", s):
            bad(line, name, f"'{s[:20]}' is not a whole number")
            return None
        n = int(s)
        if kind == "rank" and n > 7:
            bad(line, name, "the admin rank is 0 to 7")
        if kind == "order" and not 1 <= n <= 10000:
            bad(line, name, "the order is 1 to 10000")
        return n
    if kind in ("state", "enum"):
        if not s:
            return None
        u = s.upper()
        if u not in c["values"]:
            bad(line, name, f"'{s[:40]}' is not one of {', '.join(c['values'])}")
            return None
        return u
    if kind == "bool":
        if not s:
            return None
        b = _bool(s)
        if b is None:
            bad(line, name, f"'{s[:20]}' is not true or false")
        return b
    if kind in ("list", "refs"):
        vals = split_list(s)
        if len(vals) > MAX_VALUES:
            bad(line, name, f"more than {MAX_VALUES} values")
            return []
        if len(set(x.casefold() for x in vals)) != len(vals):
            bad(line, name, "a value is listed twice")
        for x in vals:
            if len(x) > 255:
                bad(line, name, "a value is longer than 255 characters")
            why = _check_value(c["check"], x) if kind == "list" else None
            if why:
                bad(line, name, why)
        if c["check"] == "client_type":
            vals = [x.lower() for x in vals]
        elif kind == "list" and c["check"] in ("token", "country"):
            vals = [x.upper() for x in vals] if c["name"] != "nw_applications" else vals
        return vals
    return s


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def to_csv(policy: str, rows: Sequence[Dict[str, Any]]) -> str:
    """Rows ({column: value}, lists as lists) as the file, every cell safe."""
    names = column_names(policy)
    buf = io.StringIO()
    # csv_safe's writer neutralises every cell again; safe_out's cells are already safe, so it changes none of them.
    w = csv_safe.writer(buf, lineterminator="\r\n")
    w.writerow(names)
    for r in rows:
        out = []
        for n in names:
            v = r.get(n)
            if isinstance(v, (list, tuple)):
                v = join_list(v)
            elif isinstance(v, bool):
                v = "true" if v else "false"
            out.append(safe_out(v))
        w.writerow(out)
    return buf.getvalue()


def filename(policy: str, tenant_label: str = "") -> str:
    stem = re.sub(r"[^A-Za-z0-9]+", "_", f"{tenant_label or 'tenant'}_{policy}_rules").strip("_")[:80] or "rules"
    return f"{stem}.csv"
