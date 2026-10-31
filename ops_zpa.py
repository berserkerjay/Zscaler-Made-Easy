"""ZPA builder: operation types on the Bulk changes engine (admin_ops.register).

Four types, each planned from the tenant as it is now, previewed item by
item, approved by its plan hash and applied through the engine's gates
(write mode, a writer, the assessor, the confirmation), with a re-read of
every object right before its write, a read-back and an Undo:

  zpa_connector_group  an App Connector group (or an existing one, reused)
                       and its provisioning key
  zpa_app_segments     a segment group, a server group and application
                       segments: a *.domain wildcard, a vertical preset
                       (healthcare, finance, education, general) or a CSV of
                       up to 500 rows; optionally a Browser Access
                       application and Privileged Remote Access (RDP / SSH)
                       applications with their consoles
  zpa_policies         access, timeout, inspection (an inspection profile
                       made of Zscaler's predefined OWASP controls) and
                       isolation (a chosen isolation profile) rules over the
                       prefixed application segments; the access rule may be
                       limited to SCIM groups and SAML attribute values
                       chosen from what the tenant has (read-only lookups:
                       idp.list_idps, saml_attributes.list_saml_attributes,
                       scim_groups.list_scim_groups / get_scim_group)
  zpa_prefix_delete    re-reads the tenant and deletes only objects whose name
                       carries the prefix, in ZPA's dependency order
                       (policies, inspection profile, PRA consoles, segments,
                       server groups, segment groups, provisioning key,
                       connector groups); anything still used by an object
                       that is not being deleted is kept and named. Also the
                       Undo of a build (it deletes what the build created and
                       puts back what it changed).

Every object is named "<prefix>-..." (prefix: ^[A-Za-z0-9_-]{1,20}$), so a
re-run finds its objects by name and updates them in place instead of
creating them again. Application segments and PRA consoles are created
disabled unless the operator asks otherwise (rules over a disabled segment
decide nothing).

The provisioning key is a secret: ZPA answers it when the key is created
(and on every read of the key). It is never put in a plan, a result, a log,
the audit log, the change record or an export: every read of a key drops the
field at once, and the one answer that carries it (the create) hands it to
an in-memory, single-use, ten-minute store (stash / reveal) from which the
page fetches it once (POST /api/operations/zpa/provisioning-key).

SDK calls, all verified against the installed zscaler-sdk-python 1.11.3
(zscaler/zpa): list_/get_ on app_connector_groups, provisioning
(key_type "connector"), enrollment_certificates.list_enrolment, segment_groups,
server_groups, application_segment, policies (list_rules / get_rule by policy
type), app_protection (list_profiles, get_profile,
list_predef_control_versions), cbi_zpa_profile.list_isolation_profiles,
pra_portal.list_portals, pra_console, certificates.list_issued_certificates;
writes go through pack_ops (ZPA_KINDS). An access rule's identity
conditions are SDK v1 condition tuples (policies._create_conditions_v1):
("scim_group", idp id, SCIM group id) and ("saml", SAML attribute id,
value); the SDK puts the SCIM groups in one OR condition and the SAML
values in another, so they are ANDed with the applications and with each
other. Assumed, not verifiable without a
tenant: that a rule with no operator joins its conditions with AND, that a new rule is added at the bottom of its policy, that a timeout
rule takes action RE_AUTH, that deleting a provisioning key before its group
is accepted, and the vertical presets' host names and ports (templates to
review, not facts about the customer).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
import secrets
import threading
import time
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import admin_ops as ao
import pack_ops as ops
import zia_path_modules
import zpa_reader as zr

FAMILY = "zpa_objects"
PREFIX_RE = re.compile(r"^[A-Za-z0-9_-]{1,20}$")
NOT_IN_SCOPE = "Not in scope: ZPA is not ticked on the Scope page, so nothing is read from ZPA or built in it."
MAX_CSV_BYTES = 256 * 1024
MAX_CSV_ROWS = 500
MAX_DOMAINS_PER_APP = 50
MAX_RANGES = 20
MAX_SEGMENTS = 520
MAX_SELECT = 5000
MAX_INVENTORY = 5000
SECRET_TTL = 600.0
MAX_SECRETS = 20
MAX_RULE_IDENTITIES = 20      # SCIM groups, and SAML values, on one access rule
MAX_SAML_VALUE = 200
MAX_PICK_IDPS = 10            # IdPs whose SCIM groups the form lists
SCIM_PICK_PAGES = 2           # pages of 500 SCIM groups listed per IdP for the form
MAX_PICK_SCIM = 2000          # SCIM groups the form lists in all
MAX_PICK_SAML = 500

# Delete order: dependents before what they use (ZPA refuses to delete an object something still uses).
DELETE_ORDER = ("access_rule", "timeout_rule", "inspection_rule", "isolation_rule", "inspection_profile", "pra_console", "segment",
                "server_group", "segment_group", "provisioning_key", "connector_group")
RULE_KINDS = {"access_rule": "access", "timeout_rule": "timeout", "inspection_rule": "inspection", "isolation_rule": "isolation"}

# kind -> label, pack_ops kind, the call each write makes (shown in the preview)
KINDS: Dict[str, Dict[str, str]] = {
    "connector_group": {"label": "App Connector group", "op": "zpa_connector_group", "svc": "app_connector_groups",
                        "add": "add_connector_group", "path": "/appConnectorGroup"},
    "provisioning_key": {"label": "Provisioning key", "op": "zpa_provisioning_key", "svc": "provisioning",
                         "add": "add_provisioning_key", "path": "/associationType/CONNECTOR_GRP/provisioningKey"},
    "segment_group": {"label": "Segment group", "op": "zpa_segment_group", "svc": "segment_groups", "add": "add_group", "path": "/segmentGroup"},
    "server_group": {"label": "Server group", "op": "zpa_server_group", "svc": "server_groups", "add": "add_group", "path": "/serverGroup"},
    "segment": {"label": "Application segment", "op": "zpa_segment", "svc": "application_segment", "add": "add_segment", "path": "/application"},
    "pra_segment": {"label": "Privileged Remote Access application", "op": "zpa_pra_segment", "svc": "app_segments_pra",
                    "add": "add_segment_pra", "path": "/application"},
    "inspection_profile": {"label": "Inspection profile", "op": "zpa_inspection_profile", "svc": "app_protection", "add": "add_profile",
                           "path": "/inspectionProfile"},
    "pra_console": {"label": "PRA console", "op": "zpa_pra_console", "svc": "pra_console", "add": "add_console", "path": "/praConsole"},
    "access_rule": {"label": "Access policy rule", "op": "zpa_access_rule", "svc": "policies", "add": "add_access_rule", "path": "/policySet/{id}/rule"},
    "timeout_rule": {"label": "Timeout policy rule", "op": "zpa_timeout_rule", "svc": "policies", "add": "add_timeout_rule", "path": "/policySet/{id}/rule"},
    "inspection_rule": {"label": "Inspection policy rule", "op": "zpa_inspection_rule", "svc": "policies", "add": "add_app_protection_rule",
                        "path": "/policySet/{id}/rule"},
    "isolation_rule": {"label": "Isolation policy rule", "op": "zpa_isolation_rule", "svc": "policies", "add": "add_isolation_rule",
                       "path": "/policySet/{id}/rule"},
}
UPDATABLE = ("connector_group", "provisioning_key", "segment_group", "server_group", "segment", "pra_console", "access_rule", "timeout_rule",
             "inspection_rule", "isolation_rule")

LOCATIONS: Dict[str, Dict[str, str]] = {
    "san_jose": {"label": "San Jose, US", "location": "San Jose, CA, USA", "city_country": "San Jose, US", "country_code": "US",
                 "latitude": "37.3382082", "longitude": "-121.8863286"},
    "new_york": {"label": "New York, US", "location": "New York, NY, USA", "city_country": "New York, US", "country_code": "US",
                 "latitude": "40.7127753", "longitude": "-74.0059728"},
    "toronto": {"label": "Toronto, CA", "location": "Toronto, ON, Canada", "city_country": "Toronto, CA", "country_code": "CA",
                "latitude": "43.653226", "longitude": "-79.3831843"},
    "london": {"label": "London, GB", "location": "London, UK", "city_country": "London, GB", "country_code": "GB",
               "latitude": "51.5072178", "longitude": "-0.1275862"},
    "frankfurt": {"label": "Frankfurt, DE", "location": "Frankfurt, Germany", "city_country": "Frankfurt, DE", "country_code": "DE",
                  "latitude": "50.1109221", "longitude": "8.6821267"},
    "mumbai": {"label": "Mumbai, IN", "location": "Mumbai, India", "city_country": "Mumbai, IN", "country_code": "IN",
               "latitude": "19.0759837", "longitude": "72.8776559"},
    "singapore": {"label": "Singapore, SG", "location": "Singapore", "city_country": "Singapore, SG", "country_code": "SG",
                  "latitude": "1.352083", "longitude": "103.819836"},
    "tokyo": {"label": "Tokyo, JP", "location": "Tokyo, Japan", "city_country": "Tokyo, JP", "country_code": "JP",
              "latitude": "35.6764225", "longitude": "139.650027"},
    "sydney": {"label": "Sydney, AU", "location": "Sydney, NSW, Australia", "city_country": "Sydney, AU", "country_code": "AU",
               "latitude": "-33.8688197", "longitude": "151.2092955"},
    "sao_paulo": {"label": "Sao Paulo, BR", "location": "Sao Paulo, Brazil", "city_country": "Sao Paulo, BR", "country_code": "BR",
                  "latitude": "-23.5557714", "longitude": "-46.6395571"},
}

# Vertical presets: application templates under the customer's base domain
# (host, what it is, TCP ports). Templates to review with the customer.
VERTICALS: Dict[str, Dict[str, Any]] = {
    "healthcare": {"label": "Healthcare", "apps": [("ehr", "Electronic health record", "443"), ("pacs", "Imaging (PACS)", "104, 443"),
                                                  ("lis", "Laboratory system", "443"), ("pharmacy", "Pharmacy system", "443"),
                                                  ("hl7", "HL7 interface engine", "2575")]},
    "finance": {"label": "Finance", "apps": [("core", "Core banking", "443"), ("payments", "Payments gateway", "443"),
                                            ("trading", "Trading platform", "443"), ("reporting", "Reporting database", "1433"),
                                            ("files", "File shares", "445")]},
    "education": {"label": "Education", "apps": [("sis", "Student information system", "443"), ("lms", "Learning management system", "443"),
                                                ("library", "Library system", "443"), ("research", "Research file shares", "445"),
                                                ("print", "Campus printing", "631, 9100")]},
    "general": {"label": "General", "apps": [("intranet", "Intranet", "80, 443"), ("files", "File shares", "445"),
                                            ("rdp", "Remote desktop", "3389"), ("ssh", "Server SSH", "22"), ("erp", "ERP", "443")]},
    # Federal and public sector (the POV's federal preset): the internal systems a federal POV usually puts behind ZPA.
    # Host names and ports are templates to review with the agency (assumed: agencies name and port these systems their own way).
    "federal": {"label": "Federal and public sector", "apps": [("casemgmt", "Case management system", "443"),
                                                              ("financial", "Financial management system", "443"),
                                                              ("hr", "HR and payroll system", "443"),
                                                              ("records", "Records and CUI document repository", "443"),
                                                              ("files", "File shares", "445")]},
}
TIMEOUT_CHOICES = {"3600": "1 hour", "28800": "8 hours", "86400": "1 day", "604800": "7 days"}
IDLE_CHOICES = {"900": "15 minutes", "3600": "1 hour", "28800": "8 hours"}
OWASP_VERSION_RE = re.compile(r"^OWASP_CRS/(\d+)\.(\d+)\.(\d+)$")

NOTES = ["Application segments and PRA consoles are created disabled unless you ticked 'create enabled': rules over a disabled "
         "segment decide nothing, so nothing changes for users until you enable them.",
         "Every object is named with the prefix, so running the same build again updates these objects instead of making new ones."]


def _err(msg: str) -> ao.OperationError:
    return ao.OperationError(msg)


# ---------------------------------------------------------------------------
# Validation of what the page sends (pure)
# ---------------------------------------------------------------------------

def check_prefix(v: Any) -> str:
    p = str(v or "").strip()
    if not PREFIX_RE.match(p):
        raise _err("The prefix must be 1 to 20 letters, digits, '-' or '_' (for example pov1). Every object the builder makes starts with it.")
    return p


def parse_ports(v: Any, what: str) -> List[List[int]]:
    """[[from, to], ...] from "80, 443, 8000-8100" (or a list); [] when empty."""
    parts = v if isinstance(v, list) else re.split(r"[\s,;]+", str(v or ""))
    out: List[List[int]] = []
    for raw in parts:
        s = str(raw).strip()
        if not s:
            continue
        m = re.fullmatch(r"(\d{1,5})(?:-(\d{1,5}))?", s)
        if not m:
            raise _err(f"{what}: '{s[:20]}' is not a port or a range like 8000-8100.")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        if not (1 <= a <= b <= 65535):
            raise _err(f"{what}: '{s[:20]}' must be within 1-65535, the start before the end.")
        if [a, b] not in out:
            out.append([a, b])
        if len(out) > MAX_RANGES:
            raise _err(f"{what}: at most {MAX_RANGES} port ranges.")
    return sorted(out)


def _rstr(ranges: Iterable[Sequence[int]]) -> List[str]:
    return [f"{a}-{b}" for a, b in sorted((int(x[0]), int(x[1])) for x in ranges)]


def _flat(ranges: Iterable[Sequence[int]]) -> List[str]:
    return [str(x) for a, b in sorted((int(r[0]), int(r[1])) for r in ranges) for x in (a, b)]


def _overlap(a: Sequence[Sequence[int]], b: Sequence[Sequence[int]]) -> bool:
    return any(max(x[0], y[0]) <= min(x[1], y[1]) for x in a for y in b)


# The widest subnet the builder puts in a segment: anything wider is what the
# analysis reports as over-broad at high severity (ZPA-AS-04), so it is refused.
WIDEST_PREFIX = {4: 9, 6: 33}


def check_domain(v: Any, what: str, *, wildcard_ok: bool = True) -> str:
    raw = str(v or "").strip()
    if not raw.isascii():   # an IDN in the punycode form ZPA stores: the app's one encoder (UTS 46), "*." kept
        raw = zia_path_modules.entry_host(raw)
    d, why = ao.normalize_domain(raw)
    if why:
        raise _err(f"{what}: '{str(v)[:60]}' {why}.")
    if not wildcard_ok and (d.startswith("*.") or "/" in d):
        raise _err(f"{what}: enter one server name or IP address, not a wildcard or a range.")
    if "/" in d:
        net = ipaddress.ip_network(d, strict=False)
        if net.prefixlen < WIDEST_PREFIX[net.version]:
            raise _err(f"{what}: '{d}' covers {net.num_addresses:,} addresses, far more than one application; "
                       f"give its own subnet (/{WIDEST_PREFIX[net.version]} or narrower).")
    return d


def check_base_domain(v: Any, what: str) -> str:
    s = str(v or "").strip().lower().lstrip(".")
    if s.startswith("*."):
        s = s[2:]
    d = check_domain(s, what, wildcard_ok=False)
    if not re.search(r"[a-z]", d):
        raise _err(f"{what}: enter a domain name such as example.com, not an IP address.")
    return d


def _id(v: Any, what: str) -> str:
    s = str(v or "").strip()
    if not re.fullmatch(r"\d{1,24}", s):
        raise _err(f"{what}: pick it from the list read from the tenant.")
    return s


def _clean_text(v: Any, limit: int) -> str:
    return re.sub(r"[\x00-\x1f\x7f]", " ", str(v or "")).strip()[:limit]


def _slug(v: Any) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(v or "").lower()).strip("-")[:40]


def parse_csv(text: Any) -> List[Dict[str, Any]]:
    """Application rows from an uploaded CSV (untrusted): header
    name,domains,tcp_ports,udp_ports[,description]; domains separated by ';'
    or spaces, ports like 443;8000-8100. At most 500 rows and 256 KB; any bad
    row refuses the whole file, naming the first problems."""
    if not isinstance(text, str):
        raise _err("The CSV must be text.")
    if len(text.encode("utf-8", "replace")) > MAX_CSV_BYTES:
        raise _err(f"The CSV is larger than {MAX_CSV_BYTES // 1024} KB.")
    if "\x00" in text:
        raise _err("The CSV contains a NUL byte: it is not a text file.")
    text = text.lstrip("﻿")
    try:
        rows = list(csv.reader(io.StringIO(text), strict=True))
    except csv.Error as e:
        raise _err(f"The CSV could not be read: {str(e)[:120]}.")
    rows = [r for r in rows if any(str(c).strip() for c in r)]
    if not rows:
        raise _err("The CSV is empty.")
    head = [str(c).strip().lower().replace(" ", "_") for c in rows[0]]
    if "name" not in head or "domains" not in head:
        raise _err("The CSV's first line must name the columns: name,domains,tcp_ports,udp_ports,description.")
    col = {k: head.index(k) for k in ("name", "domains", "tcp_ports", "udp_ports", "description") if k in head}
    data = rows[1:]
    if len(data) > MAX_CSV_ROWS:
        raise _err(f"The CSV has {len(data)} rows; at most {MAX_CSV_ROWS}.")
    out: List[Dict[str, Any]] = []
    problems: List[str] = []
    seen: Set[str] = set()
    for n, r in enumerate(data, start=2):
        def cell(k: str) -> str:
            i = col.get(k)
            return str(r[i]).strip()[:4000] if i is not None and i < len(r) else ""
        try:
            name = _slug(cell("name"))
            if not name:
                raise _err("the name is empty (letters and digits)")
            if name in seen:
                raise _err(f"the name '{name}' is used twice")
            doms = [x for x in re.split(r"[;\s|]+", cell("domains")) if x]
            if not doms:
                raise _err("no domain")
            if len(doms) > MAX_DOMAINS_PER_APP:
                raise _err(f"more than {MAX_DOMAINS_PER_APP} domains")
            domains = sorted({check_domain(d, "domain") for d in doms})
            tcp, udp = parse_ports(cell("tcp_ports"), "TCP ports"), parse_ports(cell("udp_ports"), "UDP ports")
            if not tcp and not udp:
                raise _err("no TCP or UDP port")
            seen.add(name)
            out.append({"slug": name, "domains": domains, "tcp": tcp, "udp": udp, "description": _clean_text(cell("description"), 200)})
        except ao.OperationError as e:
            problems.append(f"line {n}: {str(e)[:160]}")
        if len(problems) >= 10:
            break
    if problems:
        raise _err("The CSV was not used. " + "; ".join(problems) + ("; and more." if len(problems) >= 10 else "."))
    return out


# ---------------------------------------------------------------------------
# Reading ZPA (GET only; paced and stoppable like zpa_reader)
# ---------------------------------------------------------------------------

_SECRET_FIELD = re.compile(r"^provisioning_?key$", re.I)


def _scrub(row: Dict[str, Any]) -> Dict[str, Any]:
    """The row without the provisioning key's value (never kept, logged or shown)."""
    return {k: v for k, v in row.items() if not _SECRET_FIELD.match(str(k))}


def _zpa(client: Any):
    z = getattr(client, "zpa", None)
    if z is None:
        raise _err("This sign-in has no ZPA API: ZPA needs a OneAPI API client and the ZPA customer ID.")
    problem = zr.customer_id_problem(client)
    if problem:
        raise _err(problem.replace("nothing was read from ZPA", "nothing was read from or written to ZPA"))
    return z


def _gate(cancel: Optional[threading.Event]) -> Any:
    return zr._Gate(cancel, zr.PACE_SECONDS)


def _lister(zpa: Any, kind: str):
    if kind in RULE_KINDS:
        return lambda q: zpa.policies.list_rules(RULE_KINDS[kind], query_params=q)
    if kind == "provisioning_key":
        return lambda q: zpa.provisioning.list_provisioning_keys("connector", query_params=q)
    svc, fn = {"connector_group": ("app_connector_groups", "list_connector_groups"), "segment_group": ("segment_groups", "list_groups"),
               "server_group": ("server_groups", "list_groups"), "segment": ("application_segment", "list_segments"),
               "inspection_profile": ("app_protection", "list_profiles"), "pra_console": ("pra_console", "list_consoles"),
               "isolation_profiles": ("cbi_zpa_profile", "list_isolation_profiles"), "pra_portals": ("pra_portal", "list_portals"),
               "certificates": ("certificates", "list_issued_certificates"),
               "enrollment": ("enrollment_certificates", "list_enrolment"),
               "idps": ("idp", "list_idps"), "saml_attributes": ("saml_attributes", "list_saml_attributes")}[kind]
    if kind == "enrollment":
        return lambda q: getattr(getattr(zpa, svc), fn)(query_params=dict(q, search="Connector"))
    return lambda q: getattr(getattr(zpa, svc), fn)(query_params=q)


LIST_LABELS = {"connector_group": "App Connector groups", "provisioning_key": "provisioning keys", "segment_group": "segment groups",
               "server_group": "server groups", "segment": "application segments", "inspection_profile": "inspection profiles",
               "pra_console": "PRA consoles", "access_rule": "access policy rules", "timeout_rule": "timeout policy rules",
               "inspection_rule": "inspection policy rules", "isolation_rule": "isolation policy rules",
               "isolation_profiles": "isolation profiles", "pra_portals": "PRA portals", "certificates": "web server certificates",
               "enrollment": "enrollment certificates", "idps": "identity providers", "saml_attributes": "SAML attributes"}


def list_kind(zpa: Any, kind: str, gate: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every object of a kind, scrubbed; (rows, error)."""
    try:
        rows, complete = zr.list_all(_lister(zpa, kind), gate, zr.MAX_PAGES)
    except zr.Stopped:
        raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], zr._err_text(e)
    if not complete:
        # A partial list would plan duplicates (a name not seen is created
        # again) and miss objects to delete: refused, never used.
        return [], (f"the list is longer than {zr.MAX_PAGES * zr.PAGE_SIZE:,} objects, so it could not be read completely "
                    "and is not used")
    return [_scrub(r) for r in rows if isinstance(r, dict)], None


def read(zpa: Any, kinds: Iterable[str], say, cancel, *, optional: Iterable[str] = ()) -> Tuple[Dict[str, List[Dict[str, Any]]], Dict[str, str]]:
    """{kind: rows} for `kinds` (a read error raises: a plan is never made
    from a partial tenant) and for `optional` (errors are returned)."""
    gate = _gate(cancel)
    data: Dict[str, List[Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for k in list(kinds) + [k for k in optional if k not in kinds]:
        say(f"Reading ZPA {LIST_LABELS.get(k, k)}…")
        rows, err = list_kind(zpa, k, gate)
        if err:
            if k in optional:
                errors[k] = err
                data[k] = []
                continue
            raise _err(f"ZPA {LIST_LABELS.get(k, k)} could not be read, so nothing was planned: {err}")
        data[k] = rows
    return data, errors


def _gone(err: Optional[str]) -> bool:
    return bool(re.search(r"\b404\b|not[ _.]?found|does not exist|resource\.not\.found", str(err or ""), re.I))


def get_one(zpa: Any, kind: str, oid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object read fresh, scrubbed; (None, error) when it cannot be read."""
    try:
        if kind in RULE_KINDS:
            ret = zpa.policies.get_rule(RULE_KINDS[kind], str(oid))
        elif kind == "provisioning_key":
            ret = zpa.provisioning.get_provisioning_key(str(oid), "connector")
        else:
            svc, fn = {"connector_group": ("app_connector_groups", "get_connector_group"), "segment_group": ("segment_groups", "get_group"),
                       "server_group": ("server_groups", "get_group"), "segment": ("application_segment", "get_segment"),
                       "pra_segment": ("application_segment", "get_segment"), "inspection_profile": ("app_protection", "get_profile"),
                       "pra_console": ("pra_console", "get_console")}[kind]
            ret = getattr(getattr(zpa, svc), fn)(str(oid))
        data, resp, err = zr._triple(ret)
        if err:
            return None, zr._err_text(err)
        if data is None:
            return None, "not found"
        raw = None
        getter = getattr(resp, "get_body", None)
        if callable(getter):
            try:
                body = getter()
                raw = body if isinstance(body, dict) else None
            except Exception:  # noqa: BLE001 — the model below
                raw = None
        row = raw if raw is not None else zr._plain(data)
        return _scrub(dict(row)), None
    except Exception as e:  # noqa: BLE001
        return None, zr._err_text(e)


# ---------------------------------------------------------------------------
# The managed fields of each kind ("state"), compared and shown in the preview
# ---------------------------------------------------------------------------

def _b(v: Any, default: bool = True) -> bool:
    x = zr.as_bool(v)
    return default if x is None else x


def _name(row: Dict[str, Any]) -> str:
    return zr.as_str(zr.get(row, "name"))


def _oid(row: Dict[str, Any]) -> str:
    return zr.as_str(zr.get(row, "id"))


def rule_apps(row: Dict[str, Any]) -> List[str]:
    out: Set[str] = set()
    for c in zr.get(row, "conditions") or []:
        for o in (zr.get(c, "operands") or []) if isinstance(c, dict) else []:
            if not isinstance(o, dict) or zr.as_str(zr.get(o, "objectType")).upper() != "APP":
                continue
            if zr.get(o, "rhs"):
                out.add(zr.as_str(zr.get(o, "rhs")))
            for v in zr.get(o, "values") or []:
                out.add(zr.as_str(v))
    return sorted(x for x in out if x)


def rule_identities(row: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """(SCIM groups as "idp:group", SAML values as "attribute:value") of a
    rule, as read: v1 operands carry lhs/rhs; a v2 SCIM group operand
    carries idpId and its id in values or entryValues."""
    scim: Set[str] = set()
    saml: Set[str] = set()
    for c in zr.get(row, "conditions") or []:
        for o in (zr.get(c, "operands") or []) if isinstance(c, dict) else []:
            if not isinstance(o, dict):
                continue
            for t in zr._operand_tokens(o):
                if t["type"] == "SCIM_GROUP" and t["rhs"]:
                    idp = t["idp_id"] or (t["lhs"] if t["lhs"] not in ("", "id") else "")
                    scim.add(f"{idp}:{t['rhs']}")
                elif t["type"] == "SAML" and t["lhs"] not in ("", "id"):
                    saml.add(f"{t['lhs']}:{t['rhs']}")
    return sorted(scim), sorted(saml)


def _pra_app_ids(row: Dict[str, Any]) -> List[str]:
    return sorted(zr._ref_ids(zr.get(row, "praApps") or []))


def state(kind: str, row: Dict[str, Any]) -> Dict[str, Any]:
    g = lambda k, d=None: zr.get(row, k, d)  # noqa: E731
    if kind == "connector_group":
        return {"enabled": _b(g("enabled"))}
    if kind == "provisioning_key":
        return {"enabled": _b(g("enabled")), "max_usage": zr.as_str(g("maxUsage")), "connector_group": zr.as_str(g("zcomponentId"))}
    if kind == "segment_group":
        return {"enabled": _b(g("enabled"))}
    if kind == "server_group":
        return {"enabled": _b(g("enabled")), "dynamic_discovery": _b(g("dynamicDiscovery"), False),
                "connector_groups": sorted(zr._ref_ids(g("appConnectorGroups") or []))}
    if kind in ("segment", "pra_segment"):
        return {"enabled": _b(g("enabled")), "domains": sorted(zr.as_str(d).lower().rstrip(".") for d in g("domainNames") or [] if zr.as_str(d)),
                "tcp": _rstr(zr.port_ranges(row, "tcp")[0]), "udp": _rstr(zr.port_ranges(row, "udp")[0]),
                "segment_group": zr.as_str(g("segmentGroupId")), "server_groups": sorted(zr._ref_ids(g("serverGroups") or []))}
    if kind == "pra_console":
        return {"enabled": _b(g("enabled"))}
    if kind in RULE_KINDS:
        out = {"action": zr.as_str(g("action")).upper(), "apps": rule_apps(row)}
        if kind == "access_rule":
            out["scim_groups"], out["saml"] = rule_identities(row)
        if kind == "timeout_rule":
            out.update(reauth_timeout=zr.as_str(g("reauthTimeout")), reauth_idle_timeout=zr.as_str(g("reauthIdleTimeout")))
        if kind == "inspection_rule":
            out["profile"] = zr.as_str(g("zpnInspectionProfileId"))
        if kind == "isolation_rule":
            out["profile"] = zr.as_str(g("zpnIsolationProfileId"))
        return out
    return {}


def _is_ref(v: Any) -> bool:
    return isinstance(v, dict) and set(v) == {"ref"}


def _show(v: Any, names: Dict[str, str]) -> str:
    """A value as the preview shows it."""
    if _is_ref(v):
        return f"new: {names.get(v['ref'], v['ref'])}"
    if isinstance(v, str) and v in names:
        return names[v]   # an access rule's "idp:group" or "attribute:value", by name
    if isinstance(v, bool):
        return "on" if v else "off"
    if isinstance(v, list):
        return ", ".join(_show(x, names) for x in v) if v else "(none)"
    return str(v) if v not in (None, "") else "(none)"


class _Unresolved(Exception):
    pass


def resolve(v: Any, run: Any) -> Any:
    """A desired value with each {"ref": unit key} replaced by the id that
    unit's object has now (created earlier in this run, or existing)."""
    if _is_ref(v):
        u = run.units.get(v["ref"])
        oid = (u or {}).get("object", {}).get("id")
        if not oid:
            raise _Unresolved(f"'{(u or {}).get('object', {}).get('name') or v['ref']}' has no id (it was not created)")
        return str(oid)
    if isinstance(v, list):
        return sorted(resolve(x, run) for x in v) if all(isinstance(x, (str, dict)) for x in v) else [resolve(x, run) for x in v]
    if isinstance(v, dict):
        return {k: resolve(x, run) for k, x in v.items()}
    return v


# ---------------------------------------------------------------------------
# Payloads (snake_case: the SDK turns them into the API's camelCase)
# ---------------------------------------------------------------------------

def _desc(t: Dict[str, Any], assessor: str) -> str:
    return f"{KINDS[t['kind']]['label']} for {t.get('prefix') or 'the build'}, built by {assessor or 'the assessor'} with the ZPA builder."[:255]


def _conditions(apps: Sequence[str], scim: Sequence[str] = (), saml: Sequence[str] = ()) -> List[Tuple[str, str, str]]:
    """SDK v1 condition tuples (policies._create_conditions_v1): the
    applications, then ("scim_group", idp id, group id) and ("saml",
    attribute id, value). The SDK makes one OR condition of each kind."""
    out = [("app", "id", str(a)) for a in apps]
    for x in scim:
        idp, _, gid = str(x).partition(":")
        out.append(("scim_group", idp, gid))
    for x in saml:
        attr, _, value = str(x).partition(":")
        out.append(("saml", attr, value))
    return out


_CG_FIELDS = ("name", "description", "enabled", "location", "latitude", "longitude", "city_country", "country_code", "upgrade_day",
              "upgrade_time_in_secs", "version_profile_id", "override_version_profile", "dns_query_type", "enrollment_cert_id",
              "lss_app_connector_group", "pra_enabled", "waf_disabled", "tcp_quick_ack_app", "tcp_quick_ack_assistant",
              "tcp_quick_ack_read_assistant", "use_in_dr_mode")


def _camel(k: str) -> str:
    return re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k)


def _rule_payload(kind: str, name: str, want: Dict[str, Any], description: str) -> Dict[str, Any]:
    p: Dict[str, Any] = {"name": name, "description": description,
                         "conditions": _conditions(want.get("apps") or [], want.get("scim_groups") or [] if kind == "access_rule" else [],
                                                   want.get("saml") or [] if kind == "access_rule" else [])}
    if kind == "access_rule":
        p["action"] = "allow"
    elif kind == "timeout_rule":
        p.update(action="RE_AUTH", reauth_timeout=want["reauth_timeout"], reauth_idle_timeout=want["reauth_idle_timeout"])
    elif kind == "inspection_rule":
        p.update(action="inspect", zpn_inspection_profile_id=want["profile"])
    elif kind == "isolation_rule":
        p.update(action="isolate", zpn_isolation_profile_id=want["profile"])
    return p


def create_payload(t: Dict[str, Any], want: Dict[str, Any], extra: Dict[str, Any], assessor: str) -> Dict[str, Any]:
    kind, name = t["kind"], t["name"]
    desc = _desc(t, assessor)
    if kind == "connector_group":
        loc = LOCATIONS[extra["location"]]
        return {"name": name, "description": desc, "enabled": True, **{k: loc[k] for k in ("location", "city_country", "country_code", "latitude", "longitude")}}
    if kind == "provisioning_key":
        return {"name": name, "max_usage": want["max_usage"], "enabled": True, "enrollment_cert_id": extra["enrollment_cert_id"],
                "component_id": want["connector_group"]}
    if kind == "segment_group":
        return {"name": name, "description": desc, "enabled": True}
    if kind == "server_group":
        return {"name": name, "description": desc, "enabled": True, "dynamic_discovery": True, "app_connector_group_ids": list(want["connector_groups"])}
    if kind in ("segment", "pra_segment"):
        p = {"name": name, "description": (extra.get("description") or desc)[:255], "enabled": want["enabled"], "domain_names": list(want["domains"]),
             "segment_group_id": want["segment_group"], "server_group_ids": list(want["server_groups"]),
             "tcp_port_ranges": _flat(_parse_rstr(want["tcp"])), "udp_port_ranges": _flat(_parse_rstr(want["udp"])),
             "bypass_type": "NEVER", "health_reporting": "ON_ACCESS", "health_check_type": "DEFAULT", "is_cname_enabled": True,
             "passive_health_enabled": True, "icmp_access_type": "NONE"}
        if extra.get("browser_access"):
            ba = extra["browser_access"]
            p["clientless_app_ids"] = [{"name": ba["domain"], "domain": ba["domain"], "application_port": str(ba["port"]),
                                        "application_protocol": "HTTPS", "certificate_id": ba["certificate_id"], "enabled": True,
                                        "trust_untrusted_cert": False, "allow_options": False}]
        if kind == "pra_segment":
            pra = extra["pra"]
            cfg = {"application_port": str(pra["port"]), "application_protocol": pra["protocol"], "enabled": True,
                   "domain": pra["host"], "name": pra["host"]}
            if pra["protocol"] == "RDP":
                cfg["connection_security"] = "ANY"
            p["common_apps_dto"] = {"apps_config": [cfg]}
        return p
    if kind == "inspection_profile":
        return {"name": name, "description": desc, "paranoia_level": "1", "predefined_controls_version": extra["version"]}
    if kind == "pra_console":
        return {"name": name, "description": desc, "enabled": want["enabled"], "pra_application_id": extra["pra_application_id"],
                "pra_portal_ids": [extra["portal_id"]]}
    if kind in RULE_KINDS:
        return _rule_payload(kind, name, want, desc)
    raise _err(f"unknown kind {kind}")


def _parse_rstr(vals: Sequence[str]) -> List[List[int]]:
    out = []
    for s in vals or []:
        a, _, b = str(s).partition("-")
        out.append([int(a), int(b or a)])
    return out


def update_payload(kind: str, fresh: Dict[str, Any], want: Dict[str, Any]) -> Dict[str, Any]:
    """The object as read, with the managed fields set to `want` (ZPA's PUT
    replaces the object, so what is not managed is sent back as read)."""
    g = lambda k, d=None: zr.get(fresh, k, d)  # noqa: E731
    name = _name(fresh)
    if kind == "connector_group":
        body = {k: g(_camel(k)) for k in _CG_FIELDS if g(_camel(k)) not in (None, "")}
        body["enabled"] = want.get("enabled", body.get("enabled", True))
        return body
    if kind == "provisioning_key":
        return {"name": name, "enabled": want.get("enabled", _b(g("enabled"))), "max_usage": want.get("max_usage", zr.as_str(g("maxUsage"))),
                "enrollment_cert_id": zr.as_str(g("enrollmentCertId")), "zcomponent_id": want.get("connector_group", zr.as_str(g("zcomponentId")))}
    if kind == "segment_group":
        return {"name": name, "description": zr.as_str(g("description")), "enabled": want.get("enabled", _b(g("enabled"))),
                "applications": [{"id": i} for i in zr._ref_ids(g("applications") or [])]}
    if kind == "server_group":
        cur = state(kind, fresh)
        return {"name": name, "enabled": want.get("enabled", cur["enabled"]), "dynamic_discovery": want.get("dynamic_discovery", cur["dynamic_discovery"]),
                "app_connector_group_ids": list(want.get("connector_groups", cur["connector_groups"]))}
    if kind in ("segment", "pra_segment"):
        body = ao.segment_body(fresh)
        cur = state("segment", fresh)
        w = dict(cur, **want)
        body.update(enabled=w["enabled"], domain_names=list(w["domains"]), segment_group_id=w["segment_group"], server_group_ids=list(w["server_groups"]),
                    tcp_port_ranges=_flat(_parse_rstr(w["tcp"])), udp_port_ranges=_flat(_parse_rstr(w["udp"])))
        return body
    if kind == "pra_console":
        app = zr.get(fresh, "praApplication") or {}
        return {"name": name, "description": zr.as_str(g("description")), "enabled": want.get("enabled", _b(g("enabled"))),
                "pra_application_id": zr.as_str(zr.get(app, "id")) if isinstance(app, dict) else "",
                "pra_portal_ids": zr._ref_ids(g("praPortals") or [])}
    if kind in RULE_KINDS:
        w = dict(state(kind, fresh), **want)
        return _rule_payload(kind, name, w, zr.as_str(g("description")))
    raise _err(f"{kind} is not updated by the builder")


# ---------------------------------------------------------------------------
# Building a prepared operation (items and the writes, in order)
# ---------------------------------------------------------------------------

class _Plan:
    def __init__(self, prefix: str):
        self.prefix = prefix
        self.items: List[Dict[str, Any]] = []
        self.groups: List[Dict[str, Any]] = []
        self.warnings: List[str] = []
        self.blockers: List[str] = []
        self.names: Dict[str, str] = {}

    @staticmethod
    def _call(kind: str, verb: str) -> str:
        k = KINDS[kind]
        if verb == "create":
            return f"POST {k['path']} ({k['svc']}.{k['add']})"
        if verb == "update":
            return f"PUT {k['path']}/{{id}}"
        return f"DELETE {k['path']}/{{id}}"

    def obj(self, kind: str, name: str, oid: Any = None, **extra: Any) -> Dict[str, Any]:
        return dict({"type": f"zpa_{kind}", "kind": kind, "label": KINDS.get(kind, {}).get("label", kind), "id": oid or None, "name": name}, **extra)

    def ensure(self, kind: str, name: str, desired: Dict[str, Any], rows: List[Dict[str, Any]], *, create: Optional[Dict[str, Any]] = None,
               summary: str = "", blocked: str = "", update: bool = True, op_kind: str = "") -> str:
        """Create `name` if no object of `kind` carries it, else update the
        managed fields that differ (or nothing). Returns the unit key whose
        object id dependents use."""
        key = f"{kind}:{name}"
        self.names[key] = name
        row = next((r for r in rows if _name(r) == name), None)
        deps = sorted({x["ref"] for x in _walk_refs(desired)} | {x["ref"] for x in _walk_refs(create or {})})
        label = KINDS[kind]["label"]
        summary = f"{label}{' · ' + summary if summary else ''}"
        if not blocked:
            dead = [u for u in self.items if u["key"] in deps and u["status"] == "excluded"]
            if dead:
                blocked = f"not built: it needs '{dead[0]['object']['name']}', which is not built"
        if row is not None and blocked:
            self.items.append(ao._unit(key, key, kind, self.obj(kind, name, _oid(row)), "exists", True, True, value=summary, status="excluded",
                                       reason=blocked))
            return key
        if row is None:
            status, reason = ("excluded", blocked) if blocked else ("change", f"Creates it: {self._call(op_kind or kind, 'create')}.")
            self.items.append(ao._unit(key, key, kind, self.obj(kind, name, new=True), "exists", False, True, value=summary, status=status,
                                       reason=reason, depends_on=deps))
            if not blocked:
                self.groups.append({"key": key, "handler": "zpa_b_create", "target": {"kind": op_kind or kind, "name": name, "prefix": self.prefix,
                                                                                     "desired": desired, "create": create or {}}})
            return key
        oid = _oid(row)
        cur = state(op_kind or kind, row)
        diffs = [f for f in desired if f in cur and _cmp(desired[f]) != _cmp(cur[f])]
        if not diffs:
            self.items.append(ao._unit(key, key, kind, self.obj(kind, name, oid), "exists", True, True, value=summary, status="noop",
                                       reason="already in ZPA as asked"))
            return key
        if not update:
            self.items.append(ao._unit(key, key, kind, self.obj(kind, name, oid), "exists", True, True, value=summary, status="noop",
                                       reason="already in ZPA; the builder does not change this kind of object, so its "
                                       f"{', '.join(diffs)} stay as they are (change them in the ZPA Admin Portal)"))
            self.warnings.append(f"{label} '{name}' exists with different {', '.join(diffs)}; it is left as it is.")
            return key
        gkey = f"upd:{kind}:{oid}"
        for f in diffs:
            self.items.append(ao._unit(f"{key}:{f}", gkey, kind, self.obj(kind, name, oid), f, _show(cur[f], self.names), _show(desired[f], self.names),
                                       reason=f"Updates it in place: {self._call(op_kind or kind, 'update')}.",
                                       depends_on=sorted({x["ref"] for x in _walk_refs(desired[f])})))
        self.groups.append({"key": gkey, "handler": "zpa_b_update", "target": {"kind": op_kind or kind, "id": oid, "name": name, "prefix": self.prefix,
                                                                              "desired": {f: desired[f] for f in diffs},
                                                                              "before": {f: cur[f] for f in diffs}}})
        return key

    def done(self, title: str, type_name: str, spec: Dict[str, Any], *, notes: Sequence[str] = NOTES, **extra: Any) -> Dict[str, Any]:
        return dict({"type": type_name, "product": "zpa", "title": title, "spec": spec, "items": self.items, "groups": self.groups,
                     "warnings": list(dict.fromkeys(self.warnings)), "blockers": self.blockers, "notes": list(notes)}, **extra)


def _walk_refs(v: Any) -> List[Dict[str, str]]:
    if _is_ref(v):
        return [v]
    if isinstance(v, list):
        return [r for x in v for r in _walk_refs(x)]
    if isinstance(v, dict):
        return [r for x in v.values() for r in _walk_refs(x)]
    return []


def _cmp(v: Any) -> Any:
    if _is_ref(v):
        return ("new", v["ref"])
    if isinstance(v, list):
        return sorted((_cmp(x) for x in v), key=repr)
    return v


def _by_name(rows: List[Dict[str, Any]], name: str) -> Optional[Dict[str, Any]]:
    return next((r for r in rows if _name(r) == name), None)


# The names the builder gives one object of these kinds per prefix. A name
# "<q>-<suffix>" in such a list, where q is longer than the prefix p and
# starts with "<p>-", is another build's prefix: its objects start with
# "<p>-" too ("pov" and "pov-2"), and they are never p's.
PREFIX_ANCHORS = {"connector_group": "connector-group", "provisioning_key": "provisioning-key", "segment_group": "segment-group",
                  "server_group": "server-group", "access_rule": "access", "timeout_rule": "timeout", "inspection_rule": "inspection",
                  "isolation_rule": "isolation", "inspection_profile": "owasp-inspection"}


def other_prefixes(p: str, data: Dict[str, List[Dict[str, Any]]]) -> Set[str]:
    """The longer prefixes of other builds found in `data` ({kind: rows})."""
    out: Set[str] = set()
    for kind, suffix in PREFIX_ANCHORS.items():
        for r in data.get(kind) or []:
            n = _name(r)
            q = n[:-len(suffix) - 1] if n.endswith("-" + suffix) else ""
            if q != p and q.startswith(p + "-") and PREFIX_RE.match(q):
                out.add(q)
    return out


def owned(p: str, name: str, others: Iterable[str]) -> bool:
    """Whether `name` is one of prefix p's objects: it starts with "<p>-" and
    not with the "<q>-" of another build's longer prefix q."""
    return name.startswith(p + "-") and not any(name.startswith(q + "-") for q in others)


def _ref_or_id(p: _Plan, key: str, rows: List[Dict[str, Any]], name: str) -> Any:
    """The id an object has now, else a reference to the unit that creates it."""
    row = _by_name(rows, name)
    return _oid(row) if row is not None else {"ref": key}


# ── zpa_connector_group ────────────────────────────────────────────────

def plan_connector_group(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    p = check_prefix(spec.get("prefix"))
    mode = str(spec.get("mode") or "create")
    if mode not in ("create", "existing"):
        raise _err("Create a new App Connector group or reuse an existing one.")
    loc = str(spec.get("location") or "san_jose")
    if loc not in LOCATIONS:
        raise _err("Pick the App Connector group's location from the list.")
    try:
        max_usage = int(spec.get("max_usage") or 5)
    except (TypeError, ValueError):
        raise _err("How many App Connectors may enroll with the key: a number from 1 to 500.")
    if not 1 <= max_usage <= 500:
        raise _err("How many App Connectors may enroll with the key: a number from 1 to 500.")
    gid = _id(spec.get("connector_group_id"), "The existing App Connector group") if mode == "existing" else ""
    nspec = {"type": "zpa_connector_group", "prefix": p, "mode": mode, "location": loc, "max_usage": max_usage, "connector_group_id": gid}
    zpa = _zpa(client)
    data, _ = read(zpa, ("connector_group", "provisioning_key", "enrollment"), say, cancel)
    plan = _Plan(p)
    cg_name, key_name = f"{p}-connector-group", f"{p}-provisioning-key"
    if mode == "existing":
        row = next((r for r in data["connector_group"] if _oid(r) == gid), None)
        if row is None:
            plan.blockers.append("The App Connector group you picked is not in ZPA now. Read the tenant again and pick it.")
            cg: Any = gid
        else:
            plan.items.append(ao._unit(f"connector_group:{_name(row)}", f"connector_group:{_name(row)}", "connector_group",
                                       plan.obj("connector_group", _name(row), gid), "exists", True, True, status="noop",
                                       reason="reused as it is: the builder does not change or delete a group it did not name"))
            cg = gid
    else:
        key = plan.ensure("connector_group", cg_name, {"enabled": True}, data["connector_group"], create={"location": loc},
                          summary=LOCATIONS[loc]["label"])
        cg = _ref_or_id(plan, key, data["connector_group"], cg_name)
    cert = next((r for r in data["enrollment"] if _name(r) == "Connector"), None)
    exists = _by_name(data["provisioning_key"], key_name) is not None
    blocked = "" if cert is not None or exists else "ZPA has no enrollment certificate named 'Connector', which a provisioning key needs."
    if blocked:
        plan.blockers.append(blocked)
    plan.ensure("provisioning_key", key_name, {"enabled": True, "max_usage": str(max_usage), "connector_group": cg}, data["provisioning_key"],
                create={"enrollment_cert_id": _oid(cert) if cert else ""}, summary=f"up to {max_usage} App Connectors", blocked=blocked)
    if _by_name(data["provisioning_key"], key_name) is not None:
        plan.warnings.append(f"The provisioning key '{key_name}' already exists: ZPA keeps its value, and this app never shows it again. "
                             "Copy it from the ZPA Admin Portal if you need it.")
    else:
        plan.warnings.append("The new provisioning key is shown once, right after it is created. Copy it then: it is not kept, logged or exported.")
    return plan.done(f"Build the App Connector group and provisioning key for {p}", "zpa_connector_group", nspec)


# ── zpa_app_segments ───────────────────────────────────────────────────

def _desired_apps(p: str, spec: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """The application segments the spec asks for, validated (pure)."""
    apps: List[Dict[str, Any]] = []
    nspec: Dict[str, Any] = {}
    w = spec.get("wildcard") or {}
    if isinstance(w, dict) and str(w.get("domain") or "").strip():
        d = check_base_domain(w.get("domain"), "Wildcard domain")
        tcp, udp = parse_ports(w.get("tcp"), "Wildcard TCP ports"), parse_ports(w.get("udp"), "Wildcard UDP ports")
        if not tcp and not udp:
            raise _err("Wildcard: give at least one TCP or UDP port (1-65535 for all).")
        apps.append({"name": f"{p}-wildcard-{_slug(d)}", "domains": [f"*.{d}"], "tcp": tcp, "udp": udp, "description": f"Every host under {d}"})
        nspec["wildcard"] = {"domain": d, "tcp": _rstr(tcp), "udp": _rstr(udp)}
    pr = spec.get("preset") or {}
    if isinstance(pr, dict) and str(pr.get("vertical") or "").strip():
        v = str(pr.get("vertical"))
        if v not in VERTICALS:
            raise _err(f"Pick the preset: {', '.join(VERTICALS)}.")
        d = check_base_domain(pr.get("domain"), "Preset base domain")
        for host, label, ports in VERTICALS[v]["apps"]:
            apps.append({"name": f"{p}-{v}-{host}", "domains": [f"{host}.{d}"], "tcp": parse_ports(ports, label), "udp": [], "description": label})
        nspec["preset"] = {"vertical": v, "domain": d}
    text = spec.get("csv")
    if isinstance(text, str) and text.strip():
        rows = parse_csv(text)
        for r in rows:
            apps.append({"name": f"{p}-{r['slug']}", "domains": r["domains"], "tcp": r["tcp"], "udp": r["udp"], "description": r["description"]})
        nspec["csv"] = text
    elif text not in (None, "") and not isinstance(text, str):
        raise _err("The CSV must be text.")
    names: Set[str] = set()
    for a in apps:
        if a["name"] in names:
            raise _err(f"Two applications would be named '{a['name']}': rename one in the CSV.")
        names.add(a["name"])
    if len(apps) > MAX_SEGMENTS:
        raise _err(f"At most {MAX_SEGMENTS} application segments in one build.")
    seen: Dict[str, Tuple[str, List[List[int]], List[List[int]]]] = {}
    for a in apps:
        for d in a["domains"]:
            if d in seen:
                other, t2, u2 = seen[d]
                if _overlap(a["tcp"], t2) or _overlap(a["udp"], u2):
                    raise _err(f"'{d}' is in both '{other}' and '{a['name']}' on overlapping ports; ZPA refuses that. Keep it in one.")
            seen[d] = (a["name"], a["tcp"], a["udp"])
    return apps, nspec


def plan_app_segments(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    p = check_prefix(spec.get("prefix"))
    enable = spec.get("enable") is True
    apps, nspec = _desired_apps(p, spec)
    ba = spec.get("browser_access") or {}
    ba_spec = None
    if isinstance(ba, dict) and str(ba.get("domain") or "").strip():
        port = parse_ports(str(ba.get("port") or "443"), "Browser Access port")
        if len(port) != 1 or port[0][0] != port[0][1]:
            raise _err("Browser Access port: one port, for example 443.")
        ba_spec = {"domain": check_domain(ba.get("domain"), "Browser Access domain", wildcard_ok=False), "port": port[0][0],
                   "certificate_id": _id(ba.get("certificate_id"), "The Browser Access web server certificate")}
    pra = spec.get("pra") or {}
    pra_apps: List[Dict[str, Any]] = []
    portal = ""
    if isinstance(pra, dict):
        for proto, port in (("RDP", 3389), ("SSH", 22)):
            h = str(pra.get(f"{proto.lower()}_host") or "").strip()
            if h:
                pra_apps.append({"protocol": proto, "port": port, "host": check_domain(h, f"PRA {proto} host", wildcard_ok=False)})
        if pra_apps and str(pra.get("portal_id") or "").strip():
            portal = _id(pra.get("portal_id"), "The PRA portal")
    if not apps and not ba_spec and not pra_apps:
        raise _err("Add at least one application: a wildcard domain, a preset, a CSV, Browser Access or a PRA host.")
    cg_pick = str(spec.get("connector_group_id") or "").strip()
    cg_pick = _id(cg_pick, "The App Connector group") if cg_pick else ""
    nspec.update(type="zpa_app_segments", prefix=p, enable=enable, connector_group_id=cg_pick,
                 browser_access=ba_spec, pra={"hosts": pra_apps, "portal_id": portal} if pra_apps else None)
    zpa = _zpa(client)
    need = ["connector_group", "segment_group", "server_group", "segment"] + (["pra_console"] if pra_apps else [])
    opt = (["certificates"] if ba_spec else []) + (["pra_portals"] if pra_apps else [])
    data, errors = read(zpa, need, say, cancel, optional=opt)
    plan = _Plan(p)
    # The connector group: the one picked, else the prefix's own.
    cg_row = next((r for r in data["connector_group"] if _oid(r) == cg_pick), None) if cg_pick else _by_name(data["connector_group"], f"{p}-connector-group")
    # In a POV build, an earlier step of the same plan may create the prefix's group (admin_ops.pending_ref).
    cg_pending = ao.pending_ref("zpa", "connector_group", f"{p}-connector-group") if cg_row is None and not cg_pick else None
    if cg_row is None and cg_pending is None:
        plan.blockers.append("No App Connector group to serve these applications: build the App Connector group first (Build new: ZPA App "
                             f"Connector group), or pick an existing one. Looked for '{p}-connector-group'.")
        cg_id = "0"
    else:
        cg_id = _oid(cg_row) if cg_row is not None else str(cg_pending)
    cg_label = _name(cg_row) if cg_row is not None else (f"{p}-connector-group (built by an earlier step)" if cg_pending else "(none)")
    sg_key = plan.ensure("segment_group", f"{p}-segment-group", {"enabled": True}, data["segment_group"])
    sg = _ref_or_id(plan, sg_key, data["segment_group"], f"{p}-segment-group")
    svg_key = plan.ensure("server_group", f"{p}-server-group", {"enabled": True, "dynamic_discovery": True, "connector_groups": [cg_id]},
                          data["server_group"], summary=f"dynamic discovery, App Connector group {cg_label}")
    svg = _ref_or_id(plan, svg_key, data["server_group"], f"{p}-server-group")
    ours = {a["name"] for a in apps} | ({f"{p}-browser-access"} if ba_spec else set()) | {f"{p}-pra-{x['protocol'].lower()}" for x in pra_apps}
    index: Dict[str, List[Tuple[str, List[List[int]], List[List[int]]]]] = {}
    for s in data["segment"]:
        if _name(s) in ours:
            continue
        st = state("segment", s)
        for d in st["domains"]:
            index.setdefault(d, []).append((_name(s), _parse_rstr(st["tcp"]), _parse_rstr(st["udp"])))

    def clash(domains: Sequence[str], tcp: Sequence[Sequence[int]], udp: Sequence[Sequence[int]]) -> str:
        for d in domains:
            for other, t2, u2 in index.get(d, []):
                if _overlap(tcp, t2) or _overlap(udp, u2):
                    return f"not built: '{d}' is already in segment '{other}' on overlapping ports, and ZPA refuses the same domain twice"
        return ""

    def seg(name: str, domains: List[str], tcp, udp, *, kind: str = "segment", extra: Optional[Dict[str, Any]] = None, update: bool = True,
            summary: str = "") -> str:
        desired = {"enabled": enable, "domains": sorted(domains), "tcp": _rstr(tcp), "udp": _rstr(udp), "segment_group": sg, "server_groups": [svg]}
        why = clash(domains, tcp, udp) or ("no App Connector group" if cg_row is None and cg_pending is None else "")
        return plan.ensure("segment", name, desired, data["segment"], create=extra or {}, update=update, blocked=why, op_kind=kind,
                           summary=summary or f"{', '.join(domains[:3])}{' …' if len(domains) > 3 else ''} · TCP {', '.join(_rstr(tcp)) or '-'}"
                                                  f"{' · UDP ' + ', '.join(_rstr(udp)) if udp else ''}")

    for a in apps:
        seg(a["name"], a["domains"], a["tcp"], a["udp"], extra={"description": a["description"]})
    if ba_spec:
        if errors.get("certificates"):
            plan.warnings.append(f"The web server certificates could not be read ({errors['certificates']}); the one you picked is used as given.")
        elif not any(_oid(c) == ba_spec["certificate_id"] for c in data.get("certificates") or []):
            plan.blockers.append("The Browser Access certificate you picked is not in ZPA now. Read the tenant again and pick it.")
        seg(f"{p}-browser-access", [ba_spec["domain"]], [[ba_spec["port"]] * 2], [], extra={"browser_access": ba_spec}, update=False,
            summary=f"https://{ba_spec['domain']}:{ba_spec['port']} without the client (Browser Access)")
    portals = data.get("pra_portals") or []
    if pra_apps and portal and not errors.get("pra_portals") and not any(_oid(x) == portal for x in portals):
        plan.blockers.append("The PRA portal you picked is not in ZPA now. Read the tenant again and pick it.")
    for x in pra_apps:
        sname = f"{p}-pra-{x['protocol'].lower()}"
        skey = seg(sname, [x["host"]], [[x["port"]] * 2], [], kind="pra_segment", extra={"pra": x}, update=False,
                   summary=f"{x['protocol']} to {x['host']}:{x['port']}")
        cname = f"{sname}-console"
        if not portal:
            plan.items.append(ao._unit(f"pra_console:{cname}", f"pra_console:{cname}", "pra_console", plan.obj("pra_console", cname, new=True),
                                       "exists", False, True, status="excluded",
                                       reason="no PRA portal picked: create a PRA portal (domain and certificate) in the ZPA Admin Portal, then build again"))
            continue
        plan.ensure("pra_console", cname, {"enabled": enable, "segment": _ref_or_id(plan, skey, data["segment"], sname)}, data["pra_console"],
                    create={"portal_id": portal}, summary=f"{x['protocol']} console for {x['host']}")
    if ba_spec or pra_apps:
        plan.warnings.append("Browser Access and PRA applications that already exist are left as they are (the builder only creates them).")
    n = sum(1 for u in plan.items if u["kind"] == "segment" and u["field"] == "exists")
    return plan.done(f"Build {n} ZPA application segment{'s' if n != 1 else ''} for {p}", "zpa_app_segments", nspec)


# ── zpa_policies ───────────────────────────────────────────────────────

def _owasp_latest(versions: Any) -> str:
    vals = [str(v) for v in (versions if isinstance(versions, list) else [])]
    parsed = [(tuple(int(x) for x in m.groups()), v) for v in vals for m in [OWASP_VERSION_RE.match(v)] if m]
    return max(parsed)[1] if parsed else ""


def check_rule_identities(spec: Dict[str, Any]) -> Tuple[List[Dict[str, str]], List[Dict[str, str]]]:
    """The access rule's SCIM groups [{idp_id, id}] and SAML values [{id,
    value}] from what the page sent, checked before anything is read: ids
    as ZPA gives them (digits), a value of at most MAX_SAML_VALUE
    characters with no control character, at most MAX_RULE_IDENTITIES each."""
    scim_raw, saml_raw = spec.get("access_scim_groups") or [], spec.get("access_saml") or []
    if not isinstance(scim_raw, list) or not isinstance(saml_raw, list):
        raise _err("Pick the SCIM groups and SAML attributes from the lists read from the tenant.")
    if len(scim_raw) > MAX_RULE_IDENTITIES or len(saml_raw) > MAX_RULE_IDENTITIES:
        raise _err(f"Pick at most {MAX_RULE_IDENTITIES} SCIM groups and {MAX_RULE_IDENTITIES} SAML values for one access rule.")
    scim, saml = [], []
    for x in scim_raw:
        if not isinstance(x, dict):
            raise _err("Pick the SCIM groups from the list read from the tenant.")
        g = {"idp_id": _id(x.get("idp_id"), "The SCIM group's IdP"), "id": _id(x.get("id"), "The SCIM group")}
        if g not in scim:
            scim.append(g)
    for x in saml_raw:
        if not isinstance(x, dict):
            raise _err("Pick the SAML attribute from the list read from the tenant and type its value.")
        value = str(x.get("value") or "").strip() if isinstance(x.get("value"), (str, int)) else ""
        if not value or len(value) > MAX_SAML_VALUE or re.search(r"[\x00-\x1f\x7f]", value):
            raise _err(f"Type each SAML attribute value: 1 to {MAX_SAML_VALUE} characters, no control characters.")
        a = {"id": _id(x.get("id"), "The SAML attribute"), "value": value}
        if a not in saml:
            saml.append(a)
    return scim, saml


def _plan_identities(zpa: Any, plan: "_Plan", scim: List[Dict[str, str]], saml: List[Dict[str, str]], say, cancel) -> Tuple[List[str], List[str], str]:
    """Each SCIM group and SAML attribute picked, checked against the tenant
    as it is now (read-only): it exists, under the IdP it was picked with.
    Returns ("idp:group" values, "attribute:value" values, who in words);
    what is missing becomes a blocker."""
    data, _ = read(zpa, ("idps",) + (("saml_attributes",) if saml else ()), say, cancel)
    idps = {_oid(r): r for r in data["idps"]}
    attrs = {_oid(r): r for r in data.get("saml_attributes") or []}
    gate = _gate(cancel)
    scim_vals, saml_vals, who = [], [], []
    for g in scim:
        idp = idps.get(g["idp_id"])
        gate.before()
        try:
            row, _r, err = zr._triple(zpa.scim_groups.get_scim_group(g["id"]))
        except zr.Stopped:
            raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")
        except Exception as e:  # noqa: BLE001
            row, err = None, zr._err_text(e)
        row = zr._plain(row) if row is not None else None
        if idp is None:
            plan.blockers.append(f"The IdP {g['idp_id']} of a SCIM group you picked is not in ZPA now. Read the tenant again and pick it.")
            continue
        if row is None or zr.as_str(zr.get(row, "idpId")) not in ("", g["idp_id"]):
            plan.blockers.append(f"SCIM group {g['id']} is not in ZPA under IdP {_name(idp)} now"
                                 f"{' (' + zr._err_text(err) + ')' if err and row is None else ''}. Read the tenant again and pick it.")
            continue
        val = f"{g['idp_id']}:{g['id']}"
        plan.names[val] = f"SCIM group {_name(row) or g['id']} ({_name(idp)})"
        scim_vals.append(val)
        who.append(plan.names[val])
        if zr.as_bool(zr.get(idp, "enableScimBasedPolicy")) is False:
            plan.warnings.append(f"IdP {_name(idp)} has SCIM-based policy off: its SCIM group conditions never match until it is turned on.")
    for a in saml:
        attr = attrs.get(a["id"])
        if attr is None:
            plan.blockers.append(f"SAML attribute {a['id']} is not in ZPA now. Read the tenant again and pick it.")
            continue
        val = f"{a['id']}:{a['value']}"
        plan.names[val] = f"SAML {_name(attr)} = {a['value']}"
        saml_vals.append(val)
        who.append(plan.names[val])
        idp = idps.get(zr.as_str(zr.get(attr, "idpId")))
        if idp is not None and zr.as_bool(zr.get(idp, "disableSamlBasedPolicy")) is True:
            plan.warnings.append(f"IdP {_name(idp)} has SAML-based policy disabled: the condition on {_name(attr)} never matches until it is enabled.")
    words = ""
    if scim_vals or saml_vals:
        parts = ([" or ".join(who[:len(scim_vals)])] if scim_vals else []) + ([" or ".join(who[len(scim_vals):])] if saml_vals else [])
        words = "users in " + " and with ".join(parts)
    return sorted(scim_vals), sorted(saml_vals), words


def plan_policies(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    p = check_prefix(spec.get("prefix"))
    want_access, want_timeout, want_insp = spec.get("access") is True, spec.get("timeout") is True, spec.get("inspection") is True
    scim_pick, saml_pick = check_rule_identities(spec)
    if (scim_pick or saml_pick) and not want_access:
        raise _err("SCIM groups and SAML attributes limit the access rule: tick Access as well, or clear them.")
    iso = str(spec.get("isolation_profile_id") or "").strip()
    iso = _id(iso, "The isolation profile") if iso else ""
    rt, it = str(spec.get("reauth_timeout") or "28800"), str(spec.get("reauth_idle_timeout") or "3600")
    if rt not in TIMEOUT_CHOICES or it not in IDLE_CHOICES:
        raise _err("Pick the re-authentication and idle timeouts from the lists.")
    if not (want_access or want_timeout or want_insp or iso):
        raise _err("Pick at least one policy: access, timeout, inspection or isolation.")
    nspec = {"type": "zpa_policies", "prefix": p, "access": want_access, "timeout": want_timeout, "inspection": want_insp,
             "isolation_profile_id": iso, "reauth_timeout": rt, "reauth_idle_timeout": it,
             "access_scim_groups": scim_pick, "access_saml": saml_pick}
    zpa = _zpa(client)
    kinds = ["segment", "segment_group"] + [k for k, on in (("access_rule", want_access), ("timeout_rule", want_timeout), ("inspection_rule", want_insp),
                                            ("inspection_profile", want_insp), ("isolation_rule", bool(iso))) if on]
    data, errors = read(zpa, kinds, say, cancel, optional=["isolation_profiles"] if iso else [])
    plan = _Plan(p)
    others = other_prefixes(p, data)
    apps = sorted(_oid(s) for s in data["segment"] if owned(p, _name(s), others))
    # In a POV build, the segments an earlier step of the same plan creates (admin_ops.pending_names).
    apps = sorted(apps + [t for n, t in ao.pending_names("zpa", "segment").items()
                          if owned(p, n, others) and _by_name(data["segment"], n) is None])
    if not apps:
        plan.blockers.append(f"No application segment named '{p}-…' in ZPA: build the application segments first (Build new: ZPA application segments).")
    shown = f"{len(apps)} application segment{'s' if len(apps) != 1 else ''} named {p}-…"
    if want_access:
        scim_vals, saml_vals, who = _plan_identities(zpa, plan, scim_pick, saml_pick, say, cancel) if (scim_pick or saml_pick) else ([], [], "")
        plan.ensure("access_rule", f"{p}-access", {"action": "ALLOW", "apps": apps, "scim_groups": scim_vals, "saml": saml_vals},
                    data["access_rule"], summary=f"allow {shown}" + (f" for {who}" if who else " for every user"))
        if scim_vals and saml_vals:
            plan.warnings.append("The access rule needs both: one of the SCIM groups and one of the SAML values (the SDK puts each kind in its "
                                 "own condition, and a rule's conditions are joined with AND).")
    if want_timeout:
        plan.ensure("timeout_rule", f"{p}-timeout", {"action": "RE_AUTH", "apps": apps, "reauth_timeout": rt, "reauth_idle_timeout": it},
                    data["timeout_rule"], summary=f"re-authenticate every {TIMEOUT_CHOICES[rt]}, after {IDLE_CHOICES[it]} idle")
    if want_insp:
        prof_name = f"{p}-owasp-inspection"
        version = ""
        if _by_name(data["inspection_profile"], prof_name) is None:
            try:
                versions, _r, err = zr._triple(zpa.app_protection.list_predef_control_versions())
            except Exception as e:  # noqa: BLE001
                versions, err = None, zr._err_text(e)
            version = _owasp_latest(versions)
            if not version:
                plan.blockers.append("The predefined OWASP control versions could not be read from ZPA"
                                     f"{' (' + zr._err_text(err) + ')' if err else ''}, so the inspection profile cannot be made.")
        pkey = plan.ensure("inspection_profile", prof_name, {}, data["inspection_profile"], create={"version": version},
                           summary=f"Zscaler's predefined OWASP controls{' (' + version + ', paranoia level 1)' if version else ''}")
        plan.ensure("inspection_rule", f"{p}-inspection", {"action": "INSPECT", "apps": apps,
                                                           "profile": _ref_or_id(plan, pkey, data["inspection_profile"], prof_name)},
                    data["inspection_rule"], summary=f"inspect {shown} with {prof_name}")
        plan.warnings.append("Inspection needs AppProtection on the ZPA tenant; it inspects HTTP(S) traffic to the segments.")
    if iso:
        profs = data.get("isolation_profiles") or []
        prof = next((x for x in profs if _oid(x) == iso), None)
        if errors.get("isolation_profiles"):
            plan.blockers.append(f"The isolation profiles could not be read ({errors['isolation_profiles']}).")
        elif prof is None:
            plan.blockers.append("The isolation profile you picked is not in ZPA now. Read the tenant again and pick it.")
        plan.ensure("isolation_rule", f"{p}-isolation", {"action": "ISOLATE", "apps": apps, "profile": iso}, data["isolation_rule"],
                    summary=f"isolate {shown} with {_name(prof) if prof else iso}")
        plan.warnings.append("ZPA isolation applies to Browser Access (clientless) users of these applications.")
    plan.warnings.append("New rules are added at the end of each policy (assumed ZPA behaviour); a rule above them still decides first.")
    return plan.done(f"Build the ZPA policy rules for {p}", "zpa_policies", nspec)


# ── zpa_prefix_delete ──────────────────────────────────────────────────

SELECT_RE = re.compile(r"^([a-z_]{3,30}):(\d{1,24})$")


def _check_restore(v: Any) -> List[Dict[str, Any]]:
    """Restore entries (an Undo of a build puts changed objects back), validated."""
    if v in (None, ""):
        return []
    if not isinstance(v, list) or len(v) > MAX_SELECT:
        raise _err("restore must be a list.")
    out = []
    for e in v:
        if not isinstance(e, dict) or e.get("kind") not in UPDATABLE:
            raise _err("A restore entry names an object the builder does not change.")
        allowed = set(state(e["kind"], {}).keys()) | {"segment", "profile", "apps"}
        before, after = e.get("before"), e.get("after")
        if not isinstance(before, dict) or not isinstance(after, dict) or set(before) - allowed or set(after) != set(before):
            raise _err("A restore entry is malformed.")
        for val in list(before.values()) + list(after.values()):
            if isinstance(val, list):
                if len(val) > 2000 or not all(isinstance(x, str) and len(x) < 300 for x in val):
                    raise _err("A restore entry is malformed.")
            elif not isinstance(val, (str, bool)) or (isinstance(val, str) and len(val) > 300):
                raise _err("A restore entry is malformed.")
        out.append({"kind": e["kind"], "id": _id(e.get("id"), "restore"), "name": _clean_text(e.get("name"), 255), "before": before, "after": after})
    return out


def plan_prefix_delete(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    p = check_prefix(spec.get("prefix"))
    everything = spec.get("everything") is True
    sel_raw = spec.get("select") or []
    if not isinstance(sel_raw, list) or len(sel_raw) > MAX_SELECT:
        raise _err(f"select must be a list of at most {MAX_SELECT} objects.")
    select: List[Tuple[str, str]] = []
    for s in sel_raw:
        m = SELECT_RE.match(str(s))
        if not m or m.group(1) not in DELETE_ORDER:
            raise _err("A selected object is not one the builder deletes.")
        select.append((m.group(1), m.group(2)))
    restore = _check_restore(spec.get("restore"))
    undo = spec.get("undo") is True
    if not everything and not select and not restore:
        raise _err(f"Pick the objects named {p}-… to delete, or tick 'everything with this prefix'.")
    nspec = {"type": "zpa_prefix_delete", "prefix": p, "everything": everything, "select": [f"{k}:{i}" for k, i in select],
             "restore": restore, "undo": undo}
    zpa = _zpa(client)
    data, _ = read(zpa, DELETE_ORDER, say, cancel)
    plan = _Plan(p)
    rows = {(k, _oid(r)): r for k in DELETE_ORDER for r in data[k]}
    others = other_prefixes(p, data)
    st = {key: state(key[0], r) for key, r in rows.items()}
    # An Undo first puts back what the build changed: the states below are those after it.
    restore_units: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    for e in restore:
        key = (e["kind"], e["id"])
        r = rows.get(key)
        if r is None or not owned(p, _name(r), others):
            plan.items.append(ao._unit(f"restore:{e['kind']}:{e['id']}", f"restore:{e['kind']}:{e['id']}", e["kind"], plan.obj(e["kind"], e["name"], e["id"]),
                                       "exists", False, False, status="noop", reason="no longer in ZPA with this prefix, so there is nothing to put back"))
            continue
        cur = {f: st[key].get(f) for f in e["after"]}
        if any(_cmp(cur[f]) != _cmp(e["after"][f]) for f in e["after"]):
            plan.items.append(ao._unit(f"restore:{e['kind']}:{e['id']}", f"restore:{e['kind']}:{e['id']}", e["kind"], plan.obj(e["kind"], _name(r), e["id"]),
                                       "settings", None, None, status="excluded", reason="changed in ZPA since the build, so it is left as it is"))
            continue
        restore_units.append((e, r))
        st[key] = dict(st[key], **e["before"])
    for e, r in restore_units:
        gkey = f"upd:{e['kind']}:{e['id']}"
        for f in e["before"]:
            plan.items.append(ao._unit(f"restore:{e['kind']}:{e['id']}:{f}", gkey, e["kind"], plan.obj(e["kind"], _name(r), e["id"]), f,
                                       _show(e["after"][f], {}), _show(e["before"][f], {}), reason="put back as it was before the build"))
        plan.groups.append({"key": gkey, "handler": "zpa_b_update", "target": {"kind": e["kind"], "id": e["id"], "name": _name(r), "prefix": p,
                                                                              "desired": dict(e["before"]), "before": dict(e["after"])}})
    inventory = {key for key, r in rows.items() if owned(p, _name(r), others)}
    if others:
        plan.warnings.append(f"Objects of the build{'s' if len(others) > 1 else ''} named {', '.join(sorted(others))}-… also start with {p}-; "
                             "they belong to that prefix and are never deleted here.")
    if select:
        chosen = {s for s in select if s in inventory}
        gone = [s for s in select if s not in rows]
        foreign = [s for s in select if s in rows and s not in inventory]
        for k, i in gone:
            plan.items.append(ao._unit(f"del:{k}:{i}", f"del:{k}:{i}", k, plan.obj(k, f"{KINDS[k]['label']} {i}", i), "exists", False, False,
                                       status="noop", reason="already gone from ZPA"))
        if foreign:
            plan.warnings.append(f"{len(foreign)} picked object(s) do not carry the prefix {p}- and are never deleted here.")
    else:
        chosen = set(inventory) if everything else set()
    if everything:
        chosen |= inventory
    # Who uses what (by state, after any restore): an object is kept while something outside the delete uses it.
    users: Dict[Tuple[str, str], List[Tuple[str, str]]] = {k: [] for k in chosen}
    external: Dict[Tuple[str, str], List[str]] = {}
    pra_app_owner: Dict[str, Tuple[str, str]] = {}
    for key, r in rows.items():
        if key[0] == "segment":
            for a in _pra_app_ids(r):
                pra_app_owner[a] = key
    for key, s in st.items():
        kind = key[0]
        refs: List[Tuple[str, str]] = []
        if kind == "provisioning_key" and s.get("connector_group"):
            refs.append(("connector_group", s["connector_group"]))
        if kind == "server_group":
            refs += [("connector_group", g) for g in s.get("connector_groups") or []]
        if kind == "segment":
            refs += [("server_group", g) for g in s.get("server_groups") or []]
            if s.get("segment_group"):
                refs.append(("segment_group", s["segment_group"]))
        if kind in RULE_KINDS:
            refs += [("segment", a) for a in s.get("apps") or []]
            if kind == "inspection_rule" and s.get("profile"):
                refs.append(("inspection_profile", s["profile"]))
        if kind == "pra_console":
            app = zr.get(rows[key], "praApplication") or {}
            owner = pra_app_owner.get(zr.as_str(zr.get(app, "id")) if isinstance(app, dict) else "")
            if owner:
                refs.append(owner)
        for ref in refs:
            if ref in users:
                users[ref].append(key)
    for key in chosen:
        if key[0] == "connector_group":
            n = len(zr.get(rows[key], "connectors") or [])
            if n:
                external.setdefault(key, []).append(f"{n} App Connector{'s are' if n != 1 else ' is'} enrolled in it (delete or move them in the ZPA Admin Portal)")
    blocked: Dict[Tuple[str, str], str] = {}
    changed = True
    while changed:
        changed = False
        for key in sorted(chosen):
            if key in blocked:
                continue
            why = list(external.get(key, []))
            for u in users[key]:
                if u not in chosen and ao.pending_deleted("zpa", u[0], u[1]):
                    continue   # an earlier Undo step of the same plan (a POV build's Undo) deletes it first
                if u not in chosen or u in blocked:
                    label = f"{KINDS[u[0]]['label']} '{_name(rows[u])}'"
                    if u in blocked:
                        why.append(f"{label}, which is kept too")
                    elif owned(p, _name(rows[u]), others):
                        why.append(f"{label}, which is not selected")
                    else:
                        why.append(f"{label}, which was not made with the prefix {p}-")
            if why:
                blocked[key] = "kept: still used by " + "; ".join(why[:5]) + ("; and more" if len(why) > 5 else "")
                changed = True
    for kind in DELETE_ORDER:
        for key in sorted((k for k in chosen if k[0] == kind), key=lambda k: _name(rows[k]).lower()):
            r = rows[key]
            gkey = f"del:{kind}:{key[1]}"
            why = blocked.get(key, "")
            plan.items.append(ao._unit(gkey, gkey, kind, plan.obj(kind, _name(r), key[1]), "exists", True, not not why,
                                       status="excluded" if why else "change",
                                       reason=why or f"Deletes it: {plan._call(kind, 'delete')}."))
            if not why:
                plan.groups.append({"key": gkey, "handler": "zpa_b_delete", "target": {"kind": kind, "id": key[1], "name": _name(r), "prefix": p}})
    flags = sorted({v for v in blocked.values()})
    if flags:
        plan.warnings.append(f"{len(blocked)} object(s) are kept because something that is not being deleted still uses them (see 'Excluded').")
    n = sum(1 for g in plan.groups if g["handler"] == "zpa_b_delete")
    title = f"Undo the ZPA build for {p}" if undo else f"Delete {n} ZPA object{'s' if n != 1 else ''} named {p}-…"
    return plan.done(title, "zpa_prefix_delete", nspec, notes=[
        "Only objects whose name starts with the prefix are deleted, read again from ZPA now: nothing the page sends is deleted by its id alone.",
        "Order: policy rules, the inspection profile, PRA consoles, application segments, server groups, segment groups, the provisioning key, "
        "then App Connector groups. Deleting cannot be undone: build again to recreate."],
        confirm_always=f"DELETE {p.upper()}" if n else "")


# ---------------------------------------------------------------------------
# Handlers (the engine calls one per group, in order) — writes go through pack_ops
# ---------------------------------------------------------------------------

def _halt_or_fail(run: Any, units: List[Dict[str, Any]], err: Optional[str], what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _actor() -> Optional[str]:
    """Who runs this build: the job's actor, or on the synchronous route the
    actor its audit scope names (dlp_api_server._as_actor). A key is bound
    to that person, so another writer holding the token cannot reveal it."""
    try:
        return ops.audit_context().get("actor") or None
    except Exception:  # noqa: BLE001
        return None


def _take_key(out: ops.Outcome) -> str:
    """The provisioning key from the create's answer, removed from the answer."""
    data, out.data = out.data, None
    if isinstance(data, dict):
        return str(data.get("provisioningKey") or data.get("provisioning_key") or "")
    return str(getattr(data, "provisioning_key", "") or "")


def _h_create(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind = t["kind"]
    base = "segment" if kind == "pra_segment" else kind
    try:
        want = resolve(t["desired"], run)
        extra = resolve(t.get("create") or {}, run)
    except _Unresolved as e:
        run.mark(units, "skipped", f"not attempted: {e}")
        return
    rows, err = list_kind(run.zpa, base, _gate(None))
    if err:
        _halt_or_fail(run, units, err, f"the {LIST_LABELS.get(base, base)}")
        return
    if _by_name(rows, t["name"]) is not None:
        run.mark(units, "conflict", f"an object named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    if kind == "pra_console":
        seg, err = get_one(run.zpa, "segment", want.get("segment"))
        apps = _pra_app_ids(seg) if seg else []
        if not apps:
            run.mark(units, "failed", "", error=f"ZPA did not return the PRA application of the segment: {err or 'none listed'}")
            run.counts["failed"] += 1
            return
        extra = dict(extra, pra_application_id=apps[0])
    payload = create_payload(t, want, extra, run.assessor)
    out = ops.create(run.zpa, KINDS[kind]["op"], payload, name=t["name"], log=run.log)
    secret = _take_key(out) if kind == "provisioning_key" else ""
    if run.outcome(units, out, "create"):
        oid = str(out.id or "")
        for u in units:
            u["object"] = dict(u["object"], id=oid)
        run.created.append({"type": f"zpa_{base}", "kind": base, "id": oid, "name": t["name"]})
        t["applied_state"] = want
        run.log(f"[ZPA {KINDS[kind]['label']}] {t['name']}: created")
        if kind == "provisioning_key":
            if secret:
                run.p.setdefault("one_time_secrets", []).append({"name": t["name"], "token": stash(secret, t["name"], _actor()),
                                                                 "expires_in_seconds": int(SECRET_TTL)})
            else:
                run.p.setdefault("warnings", []).append(f"ZPA did not return the value of '{t['name']}': copy it from the ZPA Admin Portal.")


def _h_update(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    kind = t["kind"]
    base = "segment" if kind == "pra_segment" else kind
    fresh, err = get_one(run.zpa, base, t["id"])
    if fresh is None:
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    cur = state(kind, fresh)
    if any(_cmp(cur.get(f)) != _cmp(v) for f, v in t["before"].items()):
        run.mark(units, "conflict", "changed in ZPA since the preview; left as it is")
        return
    try:
        want = resolve(t["desired"], run)
    except _Unresolved as e:
        run.mark(units, "skipped", f"not attempted: {e}")
        return
    out = ops.update(run.zpa, KINDS[kind]["op"], t["id"], update_payload(kind, fresh, want), name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        t["applied_state"], t["before_state"] = want, dict(t["before"])
        run.log(f"[ZPA {KINDS[kind]['label']}] {t['name']}: {', '.join(sorted(want))} updated")


def _h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_one(run.zpa, t["kind"], t["id"])
    if fresh is None:
        if _gone(err):
            run.mark(units, "noop", "already gone")
            return
        _halt_or_fail(run, units, err, f"'{t['name']}'")
        return
    if _name(fresh) != t["name"] or not _name(fresh).startswith(t["prefix"] + "-"):
        run.mark(units, "conflict", "renamed in ZPA since the preview, so it is kept")
        return
    out = ops.delete(run.zpa, {"kind": KINDS[t["kind"]]["op"], "id": t["id"], "name": t["name"], "force_delete": t["kind"] == "segment"}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.log(f"[ZPA {KINDS[t['kind']]['label']}] {t['name']}: deleted")


HANDLERS = {"zpa_b_create": _h_create, "zpa_b_update": _h_update, "zpa_b_delete": _h_delete}


def verify(run: Any) -> Dict[str, Any]:
    """Read back every object a write touched: created or updated objects
    carry the managed fields asked for; deleted ones are gone."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        applied = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not applied:
            continue
        t = g["target"]
        base = "segment" if t["kind"] == "pra_segment" else t["kind"]
        oid = t.get("id") or applied[0]["object"].get("id")
        out["checked"] += len(applied)
        row, err = get_one(run.zpa, base, oid)
        if g["handler"] == "zpa_b_delete":
            ok = row is None and _gone(err)
            if row is None and not ok:
                out["unread"].append(f"{t['name']}: {err}")
                for u in applied:
                    u["verified"] = None
                continue
        elif row is None:
            out["unread"].append(f"{t['name']}: {err}")
            for u in applied:
                u["verified"] = None
            continue
        else:
            cur, want = state(t["kind"], row), t.get("applied_state") or {}
            ok = all(_cmp(cur[f]) == _cmp(want[f]) for f in want if f in cur)
        for u in applied:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(applied)
        else:
            out["mismatched"].append(f"{t['name']}: not as expected when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The Undo of a build: delete what it created (by kind and id, still only
    if it carries the prefix when the Undo is planned) and put back what it
    changed. A delete has no Undo (build again)."""
    if result.get("type") == "zpa_prefix_delete":
        return None
    prefix = (result.get("spec") or {}).get("prefix")
    select, restore = [], []
    for g in result.get("groups") or []:
        applied = [u for u in result.get("items") or [] if u.get("group") == g["key"] and u.get("status") == "applied"]
        if not applied:
            continue
        t = g["target"]
        base = "segment" if t["kind"] == "pra_segment" else t["kind"]
        if g["handler"] == "zpa_b_create" and applied[0]["object"].get("id"):
            select.append(f"{base}:{applied[0]['object']['id']}")
        elif g["handler"] == "zpa_b_update" and t.get("before_state") is not None and base in UPDATABLE:
            restore.append({"kind": base, "id": t["id"], "name": t["name"], "before": t["before_state"], "after": t["applied_state"]})
    if not (select or restore) or not prefix:
        return None
    return {"type": "zpa_prefix_delete", "prefix": prefix, "everything": False, "select": select, "restore": restore, "undo": True}


# ---------------------------------------------------------------------------
# The provisioning key, shown once: an in-memory, single-use store
# ---------------------------------------------------------------------------

_SECRETS: Dict[str, Tuple[str, str, float, Optional[str]]] = {}
_SECRETS_LOCK = threading.Lock()


def _prune(now: float) -> None:
    for k in [k for k, v in _SECRETS.items() if v[2] <= now]:
        del _SECRETS[k]
    while len(_SECRETS) > MAX_SECRETS:
        del _SECRETS[min(_SECRETS, key=lambda k: _SECRETS[k][2])]


def stash(secret: str, name: str, actor: Optional[str], now: Optional[float] = None) -> str:
    """Keep `secret` for one reveal within SECRET_TTL; returns its token."""
    now = time.time() if now is None else now
    token = secrets.token_urlsafe(32)
    with _SECRETS_LOCK:
        _SECRETS[token] = (secret, name, now + SECRET_TTL, actor)
        _prune(now)
    return token


def reveal(token: Any, actor: Optional[str] = None, now: Optional[float] = None) -> Optional[Dict[str, str]]:
    """{name, provisioning_key} once for a valid, unexpired token asked for by
    the person whose run made it; None otherwise. The value is gone after."""
    now = time.time() if now is None else now
    t = str(token or "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", t):
        return None
    with _SECRETS_LOCK:
        _prune(now)
        got = _SECRETS.get(t)
        if got is None or (got[3] and got[3] != actor):
            return None
        del _SECRETS[t]
    return {"name": got[1], "provisioning_key": got[0]}


# ---------------------------------------------------------------------------
# What the forms pick from, scope, registration
# ---------------------------------------------------------------------------

def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if scope.get("zpa") else NOT_IN_SCOPE


def read_objects(client: Any, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """Read-only lists for the forms: App Connector groups, isolation
    profiles, PRA portals, web server certificates, and every object of the
    kinds the builder makes (kind, id, name) so the delete form can show what
    a prefix matches."""
    zpa = _zpa(client)
    kinds = ("connector_group", "isolation_profiles", "pra_portals", "certificates", "idps", "saml_attributes") + DELETE_ORDER
    data, errors = read(zpa, (), say, cancel, optional=kinds)
    idps = [{"id": _oid(r), "name": _name(r), "scim_enabled": zr.as_bool(zr.get(r, "scimEnabled")) is True,
             "scim_policy": zr.as_bool(zr.get(r, "enableScimBasedPolicy")) is not False,
             "saml_policy": zr.as_bool(zr.get(r, "disableSamlBasedPolicy")) is not True} for r in data["idps"] if _oid(r)]
    scim, scim_cut = _pick_scim_groups(zpa, [i for i in idps if i["scim_enabled"]], say, cancel, errors)
    inv = [{"kind": k, "label": KINDS[k]["label"], "id": _oid(r), "name": _name(r)} for k in DELETE_ORDER for r in data[k]]
    pick = lambda rows: [{"id": _oid(r), "name": _name(r)} for r in rows if _oid(r)]  # noqa: E731
    return {"connector_groups": [dict(x, connectors=len(zr.get(r, "connectors") or [])) for x, r in zip(pick(data["connector_group"]), data["connector_group"])],
            "isolation_profiles": pick(data["isolation_profiles"]), "pra_portals": pick(data["pra_portals"]), "certificates": pick(data["certificates"]),
            "inventory": inv[:MAX_INVENTORY], "inventory_truncated": len(inv) > MAX_INVENTORY,
            "locations": [{"id": k, "label": v["label"]} for k, v in LOCATIONS.items()],
            "verticals": [{"id": k, "label": v["label"], "apps": [{"host": h, "label": lab, "tcp": ports} for h, lab, ports in v["apps"]]}
                          for k, v in VERTICALS.items()],
            "timeouts": [{"id": k, "label": v} for k, v in TIMEOUT_CHOICES.items()], "idle_timeouts": [{"id": k, "label": v} for k, v in IDLE_CHOICES.items()],
            "idps": idps[:MAX_PICK_IDPS * 5], "scim_groups": scim, "scim_truncated": scim_cut,
            "saml_attributes": [{"id": _oid(r), "name": _name(r), "idp_id": zr.as_str(zr.get(r, "idpId"))}
                                for r in data["saml_attributes"][:MAX_PICK_SAML] if _oid(r)],
            "errors": {LIST_LABELS.get(k, k): v for k, v in errors.items()},
            "limits": {"csv_rows": MAX_CSV_ROWS, "csv_bytes": MAX_CSV_BYTES, "rule_identities": MAX_RULE_IDENTITIES}}


def _pick_scim_groups(zpa: Any, idps: List[Dict[str, Any]], say, cancel, errors: Dict[str, str]) -> Tuple[List[Dict[str, str]], bool]:
    """The SCIM groups the access rule form offers: the first pages of each
    SCIM-enabled IdP (MAX_PICK_IDPS IdPs, SCIM_PICK_PAGES pages each,
    MAX_PICK_SCIM in all). Read-only; a failure is said, never fatal."""
    out: List[Dict[str, str]] = []
    cut = len(idps) > MAX_PICK_IDPS
    gate = _gate(cancel)
    for idp in idps[:MAX_PICK_IDPS]:
        say(f"Reading the SCIM groups of IdP {idp['name']}…")
        try:
            rows, complete = zr.list_all(lambda q, _id=idp["id"]: zpa.scim_groups.list_scim_groups(_id, query_params=q), gate, SCIM_PICK_PAGES)
        except zr.Stopped:
            raise ao.Stopped("You clicked Stop: nothing more was read and nothing was written.")
        except Exception as e:  # noqa: BLE001
            errors[f"scim:{idp['id']}"] = zr._err_text(e)
            continue
        cut = cut or not complete
        for r in rows:
            if isinstance(r, dict) and _oid(r) and len(out) < MAX_PICK_SCIM:
                out.append({"idp_id": idp["id"], "idp": idp["name"], "id": _oid(r), "name": _name(r)[:200]})
        cut = cut or len(out) >= MAX_PICK_SCIM
    return out, cut


_COMMON = dict(family=FAMILY, product="zpa", in_scope=in_scope, read_objects=read_objects, verify=verify, inverse=inverse,
               script="ops_zpa.js", group="Build new")

ao.register("zpa_connector_group", label="ZPA App Connector group", plan=plan_connector_group, handlers=HANDLERS,
            hint="Create an App Connector group (or reuse one) with a provisioning key, named with your prefix; the key is shown once.", **_COMMON)
ao.register("zpa_app_segments", label="ZPA application segments", plan=plan_app_segments, handlers=HANDLERS,
            hint="A segment group, a server group and application segments from a *.domain wildcard, a preset for your sector or a CSV "
                 "(up to 500 rows); optionally Browser Access and Privileged Remote Access consoles.", **_COMMON)
ao.register("zpa_policies", label="ZPA policy rules", plan=plan_policies, handlers=HANDLERS,
            hint="Access, timeout, inspection (Zscaler's predefined OWASP controls) and isolation rules over your prefixed segments.", **_COMMON)
ao.register("zpa_prefix_delete", label="Delete ZPA objects by prefix", plan=plan_prefix_delete, handlers=HANDLERS,
            hint="Read ZPA again and delete only objects named with your prefix, in dependency order; anything still used elsewhere is kept and named.",
            **_COMMON)
