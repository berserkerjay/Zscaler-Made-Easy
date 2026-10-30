"""Microsoft's published Microsoft 365 endpoint list: kept on disk, checked
as untrusted input, and matched by host name and IP address.

Why: ZIA's predefined "Office 365 One Click" Cloud Firewall rule names
the Zscaler-managed app service group OFFICE365, and the ZIA API returns
only the group's name, never its members (zscaler-sdk-python 1.11.3,
zia/models/cloud_firewall_app_services.py: id, name, isNameL10nTag; the
SDK has no endpoint that lists an app service's or a group's members).
Zscaler builds that group from the list Microsoft publishes, so the
Path analyzer, Test a list and the shadowed-rule analysis match it
against the same list (app_services.py). Without the list the criterion
stays "unknown", as before.

Where the list comes from, both optional:
  * fetched from Microsoft's "Office 365 IP Address and URL web service"
    (worldwide instance): GET https://endpoints.office.com/version/worldwide
    then, when the version changed, /endpoints/worldwide, each with a new
    random clientrequestid (a GUID Microsoft asks for; it carries nothing
    about the tenant or this machine). OFF by default: an operator turns it
    on in Advanced settings. https only, the one host on ALLOWED_HOSTS, no
    redirect followed, a timeout, the answer capped at MAX_BYTES;
  * imported by hand: the same JSON file, saved from that address on a
    machine that can reach it (offline or air-gapped installs).

Either way the file is checked before it is kept (parse: size, JSON,
every set's fields, every host name pattern, address and port) and a
list that fails is refused whole: the list kept before stays. The kept
list is owner-only, beside the app's other caches (zscaler_update_check.
data_dir), with its version, where it came from and when. A list not
confirmed current for MAX_AGE_DAYS is stale: it then settles nothing
(app_services answers "unknown").

Host names are matched as Microsoft writes them: "outlook.office365.com"
is that host; "*.sharepoint.com" is any name below sharepoint.com (one
or more labels) but not sharepoint.com itself; "<tenant>" (Microsoft's
placeholder for the customer's tenant name) and any other "*" stand for
one or more characters inside one label. Destinations and entries are
compared in lower case and punycode (zia_path_modules.ascii_host).
"""
from __future__ import annotations

import datetime as _dt
import functools
import hashlib
import ipaddress
import json
import os
import re
import threading
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple

import safe_files

# ── What may be fetched ──────────────────────────────────────────────
HOST = "endpoints.office.com"
ALLOWED_HOSTS = frozenset({HOST})
INSTANCE = "worldwide"
VERSION_URL = f"https://{HOST}/version/{INSTANCE}"
ENDPOINTS_URL = f"https://{HOST}/endpoints/{INSTANCE}"
SOURCE_NAME = "Microsoft's Office 365 IP Address and URL web service (worldwide instance)"
FETCH_TIMEOUT = 10                     # seconds, connect and read
MAX_BYTES = 2 * 1024 * 1024            # the real list is about 100 KB; anything over 2 MB is refused, not read
MAX_VERSION_BYTES = 4096
MAX_SETS = 2000
MAX_ENTRIES = 50000                    # host names and addresses over all sets
MAX_AGE_DAYS = 30                      # a list not confirmed current for longer is stale
REFRESH_HOURS = 24                     # with fetching on, the version is checked at most this often
RETRY_MINUTES = 60                     # and a failed check is not retried sooner

# The service areas Microsoft publishes (serviceArea), named as its
# documentation names them; another area is kept under its own name.
AREAS = {"Exchange": "Exchange Online", "SharePoint": "SharePoint Online and OneDrive for Business",
         "Skype": "Skype for Business Online and Microsoft Teams", "Common": "Microsoft 365 Common and Office Online"}

_LOCK = threading.RLock()


class ListError(ValueError):
    """A list (fetched or imported) that is refused; the message says why in plain words."""


class FetchDisabled(RuntimeError):
    """Fetching Microsoft's list is off (Advanced settings)."""


# ── Where it is kept ─────────────────────────────────────────────────
def folder() -> str:
    """DLP_CHECK_M365_DIR, else the app's per-user cache folder (owner-only)."""
    env = os.environ.get("DLP_CHECK_M365_DIR")
    if env:
        return env
    import zscaler_update_check
    return zscaler_update_check.data_dir()


def list_path() -> str:
    return os.path.join(folder(), "m365_endpoints.json")


def settings_path() -> str:
    return os.path.join(folder(), "m365_settings.json")


def max_age_days() -> int:
    try:
        n = int(os.environ.get("DLP_CHECK_M365_MAX_AGE_DAYS", MAX_AGE_DAYS))
    except ValueError:
        n = MAX_AGE_DAYS
    return max(1, min(365, n))


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _iso(t: _dt.datetime) -> str:
    return t.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_time(v: Any) -> Optional[_dt.datetime]:
    try:
        return _dt.datetime.strptime(str(v), "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=_dt.timezone.utc)
    except (TypeError, ValueError):
        return None


# ── Checking a list (untrusted) ──────────────────────────────────────
_HOST_PATTERN = re.compile(r"\A[a-z0-9*<>_.-]{1,253}\Z")
_PORTS = re.compile(r"\A[0-9,\- ]{0,600}\Z")
_VERSION = re.compile(r"\A[0-9]{10}\Z")
_AREA = re.compile(r"\A[A-Za-z][A-Za-z0-9 ]{0,39}\Z")


def _ports(v: Any, where: str) -> List[Tuple[int, int]]:
    """'80,443,3478-3481' -> [(80, 80), (443, 443), (3478, 3481)]."""
    if v in (None, ""):
        return []
    if not isinstance(v, str) or not _PORTS.match(v):
        raise ListError(f"{where}: the ports are not a list of port numbers.")
    out = []
    for part in (p.strip() for p in v.split(",")):
        if not part:
            continue
        a, _, b = part.partition("-")
        try:
            lo, hi = int(a), int(b or a)
        except ValueError:
            raise ListError(f"{where}: '{part[:20]}' is not a port or a port range.") from None
        if not (1 <= lo <= hi <= 65535):
            raise ListError(f"{where}: '{part[:20]}' is not a port from 1 to 65535.")
        out.append((lo, hi))
    return out


def _text(v: Any, limit: int) -> str:
    return v[:limit] if isinstance(v, str) else ""


def _host_entry(raw: Any, where: str) -> str:
    if not isinstance(raw, str):
        raise ListError(f"{where}: a URL entry is not text.")
    e = raw.strip().lower().rstrip(".")
    if not _HOST_PATTERN.match(e) or "." not in e or ".." in e or "**" in e or e.startswith(".") or e.endswith("*"):
        raise ListError(f"{where}: '{raw[:60]}' is not a host name pattern.")
    if "<" in e.replace("<tenant>", "") or ">" in e.replace("<tenant>", ""):
        raise ListError(f"{where}: '{raw[:60]}' uses a placeholder other than <tenant>.")
    return e


def parse(data: Any) -> List[Dict[str, Any]]:
    """Microsoft's endpoints JSON (bytes or text) -> the endpoint sets,
    checked and slimmed: [{id, area, area_name, category, required, urls,
    ips, tcp, udp}]. ListError (a plain sentence) for anything that is not
    that list: too large, not JSON, not a list of endpoint sets, a set
    without an id or service area, a host name, address or port that is
    not one, or nothing to match at all. Never partial: one bad set
    refuses the whole list."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ListError("The list is not a file.")
    if len(data) > MAX_BYTES:
        raise ListError(f"The list is larger than {MAX_BYTES // (1024 * 1024)} MB, so it was not read (Microsoft's list is about 100 KB).")
    try:
        doc = safe_files.strict_json_loads(bytes(data).decode("utf-8-sig"))
    except RecursionError:
        raise ListError("The list is nested too deeply to be Microsoft's endpoint list.") from None
    except (ValueError, UnicodeDecodeError):
        raise ListError("The list is not valid JSON.") from None
    if not isinstance(doc, list):
        raise ListError("The list is not Microsoft's endpoint list: it should be a JSON list of endpoint sets "
                        f"(as {ENDPOINTS_URL} answers), not {type(doc).__name__ if not isinstance(doc, dict) else 'an object'}.")
    if not doc:
        raise ListError("The list is empty.")
    if len(doc) > MAX_SETS:
        raise ListError(f"The list has more than {MAX_SETS} endpoint sets, so it is not Microsoft's list.")
    sets: List[Dict[str, Any]] = []
    total = 0
    seen = set()
    for n, item in enumerate(doc, 1):
        where = f"Endpoint set {n}"
        if not isinstance(item, dict):
            raise ListError(f"{where} is not an object.")
        sid = item.get("id")
        if not isinstance(sid, int) or isinstance(sid, bool) or not 0 <= sid <= 10 ** 9:
            raise ListError(f"{where} has no whole-number id.")
        where = f"Endpoint set {sid}"
        if sid in seen:
            raise ListError(f"{where} appears twice.")
        seen.add(sid)
        area = item.get("serviceArea")
        if not isinstance(area, str) or not _AREA.match(area):
            raise ListError(f"{where} has no service area.")
        urls = item.get("urls", [])
        ips = item.get("ips", [])
        if not isinstance(urls, list) or not isinstance(ips, list):
            raise ListError(f"{where}: its urls and ips must be lists.")
        total += len(urls) + len(ips)
        if total > MAX_ENTRIES:
            raise ListError(f"The list has more than {MAX_ENTRIES} host names and addresses, so it is not Microsoft's list.")
        hosts = [_host_entry(u, where) for u in urls]
        nets = []
        for raw in ips:
            try:
                if not isinstance(raw, str) or len(raw) > 64:
                    raise ValueError
                nets.append(str(ipaddress.ip_network(raw.strip(), strict=False)))
            except ValueError:
                raise ListError(f"{where}: '{str(raw)[:60]}' is not an IP address or range.") from None
        for flag in ("required", "expressRoute"):
            if flag in item and not isinstance(item[flag], bool):
                raise ListError(f"{where}: '{flag}' must be true or false.")
        sets.append({"id": sid, "area": area, "area_name": _text(item.get("serviceAreaDisplayName"), 120) or AREAS.get(area, area),
                     "category": _text(item.get("category"), 20), "required": item.get("required") is True,
                     "urls": sorted(set(hosts)), "ips": sorted(set(nets)),
                     "tcp": _ports(item.get("tcpPorts"), where), "udp": _ports(item.get("udpPorts"), where)})
    if not any(s["urls"] or s["ips"] for s in sets):
        raise ListError("The list names no host name and no address.")
    return sets


def parse_version(data: Any) -> str:
    """The version answer ({"instance": "Worldwide", "latest": "YYYYMMDDNN"})
    -> the version. ListError otherwise."""
    if isinstance(data, (bytes, bytearray)):
        if len(data) > MAX_VERSION_BYTES:
            raise ListError("The version answer is too large.")
        data = bytes(data).decode("utf-8-sig", "replace")
    try:
        doc = safe_files.strict_json_loads(data)
    except (ValueError, RecursionError):
        raise ListError("The version answer is not valid JSON.") from None
    latest = doc.get("latest") if isinstance(doc, dict) else None
    if not isinstance(latest, str) or not _VERSION.match(latest):
        raise ListError("The version answer names no version.")
    return latest


def clean_version(v: Any) -> Optional[str]:
    """A version typed with an import: ten digits (YYYYMMDDNN), or None."""
    s = str(v or "").strip()
    if not s:
        return None
    if not _VERSION.match(s):
        raise ListError("The version is Microsoft's ten-digit list version (for example 2026100100), as /version/worldwide answers it.")
    return s


# ── The kept list ────────────────────────────────────────────────────
@functools.lru_cache(maxsize=4096)
def _compile(pattern: str) -> "re.Pattern[str]":
    out, i = [], 0
    if pattern.startswith("*."):
        out.append(r"(?:[a-z0-9_-]+\.)+")
        i = 2
    rest = pattern[i:]
    for tok in re.split(r"(\*|<tenant>)", rest):
        out.append(r"[a-z0-9_-]+" if tok in ("*", "<tenant>") else re.escape(tok))
    return re.compile("".join(out))


class EndpointList:
    """A checked list with its indexes: exact host names, '*.' suffixes,
    the other patterns, and the address ranges per family and prefix
    length (a lookup costs a few dictionary reads, so Test a list's
    250,000 rows stay fast)."""

    def __init__(self, sets: List[Dict[str, Any]], meta: Dict[str, Any]):
        self.sets = sets
        self.meta = dict(meta)
        self.exact: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
        self.suffix: Dict[str, List[Tuple[Dict[str, Any], str]]] = {}
        self.patterns: List[Tuple["re.Pattern[str]", Dict[str, Any], str]] = []
        self.nets: Dict[int, Dict[int, Dict[int, List[Tuple[Dict[str, Any], str]]]]] = {4: {}, 6: {}}
        self.counts = {"sets": len(sets), "urls": 0, "ipv4": 0, "ipv6": 0}
        for s in sets:
            for u in s["urls"]:
                self.counts["urls"] += 1
                if "*" not in u and "<" not in u:
                    self.exact.setdefault(u, []).append((s, u))
                elif u.startswith("*.") and "*" not in u[2:] and "<" not in u:
                    self.suffix.setdefault(u[1:], []).append((s, u))
                else:
                    self.patterns.append((_compile(u), s, u))
            for raw in s["ips"]:
                net = ipaddress.ip_network(raw, strict=False)
                self.counts[f"ipv{net.version}"] += 1
                bits = net.max_prefixlen
                key = int(net.network_address) >> (bits - net.prefixlen) if net.prefixlen else 0
                self.nets[net.version].setdefault(net.prefixlen, {}).setdefault(key, []).append((s, raw))

    # what the list is, in words
    @property
    def version(self) -> Optional[str]:
        return self.meta.get("version")

    def obtained(self) -> Optional[_dt.datetime]:
        return _parse_time(self.meta.get("fetched_at"))

    def checked(self) -> Optional[_dt.datetime]:
        return _parse_time(self.meta.get("checked_at")) or self.obtained()

    def age_days(self, now: Optional[_dt.datetime] = None) -> Optional[float]:
        c = self.checked()
        return None if c is None else max(0.0, ((now or _now()) - c).total_seconds() / 86400)

    def stale(self, now: Optional[_dt.datetime] = None) -> bool:
        if self.meta.get("source") == "sample":
            return False
        age = self.age_days(now)
        return age is None or age > max_age_days()

    def describe(self) -> str:
        """'list version 2026100100, fetched 2026-10-30' (the words every
        result that used the list carries)."""
        src = self.meta.get("source")
        when = self.obtained()
        verb = {"imported": "imported", "sample": "a sample excerpt"}.get(src, "fetched")
        v = f"list version {self.version}" if self.version else "list version not stated"
        if src == "sample":
            return "the sample tenant's short excerpt of Microsoft's list, not the real list"
        return f"{v}, {verb} {when.strftime('%Y-%m-%d') if when else 'on an unknown date'}"

    # matching
    def lookup_host(self, host: str) -> List[Tuple[Dict[str, Any], str]]:
        """The (set, entry) pairs whose host name pattern covers `host`
        (lower case, punycode, no trailing dot)."""
        h = str(host or "").lower().rstrip(".")
        if not h:
            return []
        hits = list(self.exact.get(h, ()))
        labels = h.split(".")
        for i in range(1, len(labels)):
            hits += self.suffix.get("." + ".".join(labels[i:]), ())
        hits += [(s, e) for rx, s, e in self.patterns if rx.fullmatch(h)]
        return hits

    def lookup_ip(self, ip: Any) -> List[Tuple[Dict[str, Any], str]]:
        """The (set, range) pairs that hold the address (an IPv4-mapped
        IPv6 address is looked up as its IPv4 address)."""
        if getattr(ip, "version", None) == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        bits = ip.max_prefixlen
        n = int(ip)
        hits: List[Tuple[Dict[str, Any], str]] = []
        for plen, table in self.nets.get(ip.version, {}).items():
            hits += table.get(n >> (bits - plen) if plen else 0, ())
        return hits

    def covers_net(self, net: Any) -> List[Tuple[Dict[str, Any], str]]:
        """The (set, range) pairs whose range holds the whole of `net` (an
        ip_network): the shadowed-rule analysis asks this of a range."""
        if getattr(net, "version", None) == 6 and net.prefixlen >= 96 and net.network_address.ipv4_mapped is not None:
            net = ipaddress.ip_network(f"{net.network_address.ipv4_mapped}/{net.prefixlen - 96}")
        out = []
        for s, raw in self.lookup_ip(net.network_address):
            pub = ipaddress.ip_network(raw, strict=False)
            if pub.version == net.version and net.subnet_of(pub):
                out.append((s, raw))
        return out

    def subdomains_covered(self, domain: str) -> List[Tuple[Dict[str, Any], str]]:
        """The (set, entry) pairs whose '*.' entry covers every name below
        `domain` (the entry is '*.<domain>' or '*.<a parent of domain>')."""
        labels = str(domain or "").lower().rstrip(".").split(".")
        out: List[Tuple[Dict[str, Any], str]] = []
        for i in range(len(labels) - 1):
            out += self.suffix.get("." + ".".join(labels[i:]), ())
        return out


# ── Reading and writing the kept list ────────────────────────────────
_CACHE: Dict[str, Any] = {"key": None, "list": None}


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES * 2 + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES * 2:
        return None
    try:
        doc = safe_files.strict_json_loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def load() -> Optional[EndpointList]:
    """The kept list, or None (none kept, or the file is damaged: it is
    checked again as untrusted, so a hand-edited file that no longer
    passes is not used). Read again only when the file changed."""
    p = list_path()
    try:
        st = os.stat(p)
        key = (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    with _LOCK:
        if _CACHE["key"] == key:
            return _CACHE["list"]
        doc = _read_json(p)
        lst = None
        if doc is not None and doc.get("format") == 1:
            try:
                sets = parse(json.dumps(_as_microsoft(doc.get("sets"))))
                meta = {k: doc.get(k) for k in ("version", "source", "fetched_at", "checked_at", "sha256")}
                if meta["source"] in ("fetched", "imported") and _parse_time(meta["fetched_at"]):
                    lst = EndpointList(sets, meta)
            except (ListError, TypeError, ValueError):
                lst = None
        _CACHE.update(key=key, list=lst)
        return lst


def _as_microsoft(sets: Any) -> List[Dict[str, Any]]:
    """The kept (slim) sets back in Microsoft's shape, to check them again."""
    out = []
    for s in sets if isinstance(sets, list) else []:
        if not isinstance(s, dict):
            raise ListError("damaged")
        def ports(v):
            return ",".join(f"{a}-{b}" if a != b else str(a) for a, b in v) if isinstance(v, list) and all(isinstance(x, list) and len(x) == 2 for x in v) else v
        out.append({"id": s.get("id"), "serviceArea": s.get("area"), "serviceAreaDisplayName": s.get("area_name"), "category": s.get("category"),
                    "required": bool(s.get("required")), "urls": s.get("urls") or [], "ips": s.get("ips") or [],
                    "tcpPorts": ports(s.get("tcp")) or "", "udpPorts": ports(s.get("udp")) or ""})
    return out


def _store(sets: List[Dict[str, Any]], *, version: Optional[str], source: str, digest: str, now: _dt.datetime) -> None:
    doc = {"format": 1, "instance": "Worldwide", "version": version, "source": source, "fetched_at": _iso(now), "checked_at": _iso(now),
           "sha256": digest, "source_name": SOURCE_NAME,
           "sets": [{**s, "tcp": [list(r) for r in s["tcp"]], "udp": [list(r) for r in s["udp"]]} for s in sets]}
    with _LOCK:
        safe_files.private_makedirs(folder())
        safe_files.write_private_atomic(list_path(), json.dumps(doc, indent=0, separators=(",", ":")))
        _CACHE.update(key=None, list=None)


def _touch_checked(now: _dt.datetime) -> None:
    doc = _read_json(list_path())
    if not doc:
        return
    doc["checked_at"] = _iso(now)
    with _LOCK:
        safe_files.write_private_atomic(list_path(), json.dumps(doc, indent=0, separators=(",", ":")))
        _CACHE.update(key=None, list=None)


def remove() -> Dict[str, Any]:
    """Forget the kept list (the setting stays as it is)."""
    with _LOCK:
        try:
            os.remove(list_path())
        except FileNotFoundError:
            pass
        _CACHE.update(key=None, list=None)
    return status()


def import_file(data: Any, version: Any = None, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Keep a list saved by hand (offline). The same checks as a fetched
    list; the version is optional (Microsoft's file does not carry it).
    ListError when refused; the list kept before stays."""
    v = clean_version(version)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    sets = parse(raw)
    _store(sets, version=v, source="imported", digest=hashlib.sha256(bytes(raw)).hexdigest(), now=now or _now())
    return status(now)


# ── Settings ─────────────────────────────────────────────────────────
def settings() -> Dict[str, Any]:
    """{enabled (default False), last_attempt, last_error}."""
    doc = _read_json(settings_path()) or {}
    err = doc.get("last_error")
    return {"enabled": doc.get("enabled") is True,
            "last_attempt": doc.get("last_attempt") if _parse_time(doc.get("last_attempt")) else None,
            "last_error": str(err)[:300] if isinstance(err, str) and err else None}


def _save_settings(**changes: Any) -> Dict[str, Any]:
    with _LOCK:
        cur = settings()
        cur.update(changes)
        safe_files.private_makedirs(folder())
        safe_files.write_private_atomic(settings_path(), json.dumps(cur, indent=1))
        return cur


def set_enabled(enabled: bool) -> Dict[str, Any]:
    _save_settings(enabled=bool(enabled))
    return status()


def status(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """What Advanced settings shows: the setting, the kept list (version,
    where from, when, how old, stale or not, counts) and the last error."""
    cfg = settings()
    lst = load()
    out: Dict[str, Any] = {"enabled": cfg["enabled"], "present": lst is not None, "destination": f"https://{HOST}",
                           "host": HOST, "source_name": SOURCE_NAME, "max_age_days": max_age_days(), "max_mb": MAX_BYTES // (1024 * 1024),
                           "last_attempt": cfg["last_attempt"], "last_error": cfg["last_error"]}
    if lst is not None:
        age = lst.age_days(now)
        out.update(version=lst.version, source=lst.meta.get("source"), fetched_at=lst.meta.get("fetched_at"),
                   checked_at=lst.meta.get("checked_at"), age_days=None if age is None else round(age, 1), stale=lst.stale(now),
                   counts=dict(lst.counts), describe=lst.describe())
    return out


# ── Fetching (optional, off by default) ──────────────────────────────
def _allowed(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.scheme == "https" and (p.hostname or "").lower() in ALLOWED_HOSTS and p.username is None and p.password is None and p.port in (None, 443)


def _get(url: str, cap: int) -> bytes:
    """One GET to Microsoft's service: https, the allowlisted host, no
    redirect followed, a timeout, TLS verified, at most `cap` bytes read.
    ListError in plain words for anything else."""
    if not _allowed(url.split("?", 1)[0]):
        raise ListError("Only https://endpoints.office.com is fetched.")
    import requests
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True,
                         headers={"Accept": "application/json", "User-Agent": "Zscaler-Made-Easy (Microsoft 365 endpoint list)"})
    except requests.exceptions.SSLError:
        raise ListError(f"TLS error reaching {HOST} (a TLS-inspecting proxy? point REQUESTS_CA_BUNDLE at its root certificate).") from None
    except requests.exceptions.Timeout:
        raise ListError(f"{HOST} did not answer within {FETCH_TIMEOUT} seconds.") from None
    except requests.exceptions.RequestException as e:
        import zscaler_update_check
        raise ListError(f"{HOST} could not be reached ({type(e).__name__}: {zscaler_update_check.redact_url_credentials(str(e))[:120]}).") from None
    try:
        if 300 <= r.status_code < 400:
            raise ListError(f"{HOST} answered with a redirect (HTTP {r.status_code}), which is not followed.")
        if r.status_code != 200:
            raise ListError(f"{HOST} answered HTTP {r.status_code}.")
        declared = str((r.headers or {}).get("Content-Length") or "").strip()
        if declared.isdigit() and int(declared) > cap:
            raise ListError(f"{HOST}'s answer is larger than {max(1, cap // 1024)} KB, so it was not read.")
        if getattr(r, "raw", None) is None:   # an answer already in memory (no stream): measured as it is
            body = r.content or b""
            if len(body) > cap:
                raise ListError(f"{HOST}'s answer is larger than {max(1, cap // 1024)} KB, so it was not read.")
            return body
        out = bytearray()
        for chunk in r.iter_content(chunk_size=64 * 1024):
            out += chunk
            if len(out) > cap:
                raise ListError(f"{HOST}'s answer is larger than {max(1, cap // 1024)} KB, so it was not read.")
        return bytes(out)
    finally:
        try:
            r.close()
        except Exception:  # noqa: BLE001
            pass


def fetch(now: Optional[_dt.datetime] = None, get: Optional[Callable[[str, int], bytes]] = None) -> Dict[str, Any]:
    """Check Microsoft's version and, when it changed (or no list is
    kept), fetch the list. Only when fetching is on (FetchDisabled
    otherwise). A failure is recorded and raised as ListError; the list
    kept before stays. Returns status()."""
    if not settings()["enabled"]:
        raise FetchDisabled("Fetching Microsoft's list is off. Turn it on in Advanced settings, or import the file by hand.")
    now = now or _now()
    get = get or _get
    with _LOCK:
        _save_settings(last_attempt=_iso(now))
        try:
            version = parse_version(get(f"{VERSION_URL}?clientrequestid={uuid.uuid4()}", MAX_VERSION_BYTES))
            cur = load()
            if cur is not None and cur.meta.get("source") == "fetched" and cur.version == version:
                _touch_checked(now)
            else:
                body = get(f"{ENDPOINTS_URL}?clientrequestid={uuid.uuid4()}", MAX_BYTES)
                sets = parse(body)
                _store(sets, version=version, source="fetched", digest=hashlib.sha256(body).hexdigest(), now=now)
        except ListError as e:
            _save_settings(last_error=str(e))
            raise
        _save_settings(last_error=None)
    return status(now)


def refresh_due(now: Optional[_dt.datetime] = None) -> bool:
    """Fetching is on and the list was not confirmed in REFRESH_HOURS (and
    no attempt in the last RETRY_MINUTES)."""
    cfg = settings()
    if not cfg["enabled"]:
        return False
    now = now or _now()
    last = _parse_time(cfg["last_attempt"])
    if last is not None and (now - last).total_seconds() < RETRY_MINUTES * 60:
        return False
    lst = load()
    checked = lst.checked() if lst is not None and lst.meta.get("source") == "fetched" else None
    return checked is None or (now - checked).total_seconds() > REFRESH_HOURS * 3600


def refresh_in_background() -> bool:
    """Start a version check in a background thread when one is due (the
    Path analyzer, Test a list and Shadowed rules ask before they run; the
    run itself uses the list already kept). True when one was started."""
    if not refresh_due():
        return False

    def run():
        try:
            fetch()
        except (ListError, FetchDisabled):
            pass
        except Exception:  # noqa: BLE001 - a background check never raises into the server
            pass
    threading.Thread(target=run, name="m365-endpoints-refresh", daemon=True).start()
    return True
