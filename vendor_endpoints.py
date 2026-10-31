"""Published endpoint lists of other UCaaS providers, for ZIA app service
groups beyond Microsoft 365 (app_services).

ZIA's predefined "UCaaS One Click" Cloud Firewall rule names Zscaler-
managed app service groups such as ZOOM, WEBEX, RINGCENTRAL, LOGMEIN or
GOTO and TALKDESK (ucaas_oneclick.SERVICES). The ZIA API returns only a
group's id and name, never its members (zscaler-sdk-python 1.11.3,
zia/models/cloud_firewall_app_services.py: id, name, isNameL10nTag; the
SDK has no endpoint that lists members), so without a list such a rule's
app service criterion is "unknown". As for Microsoft 365
(m365_endpoints), the provider's own published list settles it.

The providers (PROVIDERS; the group names are ASSUMED: they are the names
the One Click rule is seen to use, not published through the API):

  zoom         Zoom publishes its IP ranges as plain text, one CIDR block
               per line. Fetchable (FETCH_URL, ASSUMED: the address named in
               Zoom's "Zoom network firewall or proxy server settings"
               support article; not reachable from here to verify), only
               when an operator turns fetching on and clicks Fetch now.
  webex        Cisco publishes Webex's ranges and domains in its "Network
               Requirements for Webex Services" article, as a web page, not
               as a machine-readable file (ASSUMED from the article as last
               seen): import by hand only.
  ringcentral  RingCentral's network requirements (a web page and PDF; no
  goto         machine-readable list known, ASSUMED), GoTo's (a support web
  talkdesk     page) and Talkdesk's (a support web page): import only.

Zscaler's own app service groups (any other name) stay "unknown": their
members are not knowable from the tenant or the SDK, and Zscaler's
published data-centre ranges (zscaler_ip_ranges) are not the members of
any app service group, so taking them as such would be a guess.

The list format, fetched or imported: plain text, one entry per line, a
'#' starts a comment. An entry is an IPv4 or IPv6 address or CIDR block
(public unicast, no wider than /8 or /16, as zscaler_ip_ranges.check_cidr
checks Zscaler's own feeds: a tampered list cannot make 0.0.0.0/0 or
10.0.0.0/8 a "member"), or a host name, optionally "*." for every name
below a domain. Anything else refuses the whole list, with the line, and
the list kept before stays. Size, line and entry counts are capped. The
kept list is owner-only beside the Microsoft 365 list
(m365_endpoints.folder()), with where it came from, when and its
SHA-256; a list not confirmed for m365_endpoints.max_age_days() is stale
and settles nothing.

Fetching (zoom only): OFF by default (Advanced settings), and even when on
only on an explicit Fetch now, never on a timer. GET only, https only, the
one allowlisted host, no redirect followed, a timeout, TLS verified, the
answer capped at MAX_BYTES before it is parsed; nothing about the tenant
is sent. The host is listed with the app's other outbound destinations
in SECURITY.md.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import ipaddress
import json
import os
import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import safe_files

MAX_BYTES = 1024 * 1024            # a provider's list is a few KB; over 1 MB is refused, not read
MAX_LINES = 50_000
MAX_ENTRIES = 20_000
FETCH_TIMEOUT = 10
_LOCK = threading.RLock()

PROVIDERS: Dict[str, Dict[str, Any]] = {
    "zoom": {"label": "Zoom", "names": ("ZOOM",), "fetch": "https://assets.zoom.us/docs/ipranges/Zoom.txt",
             "source": "Zoom's published IP ranges (assets.zoom.us)",
             "how": "Zoom publishes its IP ranges as a text file (Zoom.txt, one CIDR block per line, linked from its firewall settings article)."},
    "webex": {"label": "Webex", "names": ("WEBEX", "CISCOWEBEX"), "fetch": None,
              "source": "Cisco's Network Requirements for Webex Services",
              "how": "Cisco publishes Webex's ranges and domains on a web page, not as a file: copy them into a text file, one per line."},
    "ringcentral": {"label": "RingCentral", "names": ("RINGCENTRAL",), "fetch": None,
                    "source": "RingCentral's network requirements",
                    "how": "RingCentral publishes its network requirements as a web page and PDF: copy the ranges and domains into a text file."},
    "goto": {"label": "GoTo", "names": ("GOTO", "LOGMEIN", "GOTOMEETING", "GOTOCONNECT"), "fetch": None,
             "source": "GoTo's network requirements",
             "how": "GoTo publishes its ranges and domains on a support page: copy them into a text file, one per line."},
    "talkdesk": {"label": "Talkdesk", "names": ("TALKDESK",), "fetch": None,
                 "source": "Talkdesk's network requirements",
                 "how": "Talkdesk publishes its ranges and domains on a support page: copy them into a text file, one per line."},
}
FETCH_HOSTS = frozenset(re.sub(r"^https://([^/]+)/.*$", r"\1", p["fetch"]) for p in PROVIDERS.values() if p["fetch"])
_HOST = re.compile(r"\A(?:\*\.)?(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}\Z")


class ListError(ValueError):
    """A list (fetched or imported) that is refused; the message says why."""


class FetchDisabled(RuntimeError):
    """Fetching this provider's list is off, or it has nothing to fetch."""


def _norm(name: Any) -> str:
    return re.sub(r"[^A-Z0-9]", "", str(name or "").upper())


def provider_for(name: Any) -> Optional[str]:
    """The provider an app service or group name belongs to (its name, or
    its name followed by more words, such as ZOOM_PHONE), or None."""
    n = _norm(name)
    if not n:
        return None
    for pid, p in PROVIDERS.items():
        if any(n == x or n.startswith(x) for x in p["names"]):
            return pid
    return None


# ── Where it is kept ─────────────────────────────────────────────────
def folder() -> str:
    import m365_endpoints
    return m365_endpoints.folder()


def list_path(pid: str) -> str:
    return os.path.join(folder(), f"vendor_{pid}.json")


def settings_path() -> str:
    return os.path.join(folder(), "vendor_settings.json")


def _check_pid(pid: Any) -> str:
    if not isinstance(pid, str) or pid not in PROVIDERS:
        raise ListError("Not a provider this app knows: " + ", ".join(p["label"] for p in PROVIDERS.values()) + ".")
    return pid


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
def parse(data: Any) -> Dict[str, List[str]]:
    """The text list -> {ips: [CIDR], hosts: [pattern]}. ListError (a
    sentence naming the line) for anything that is not such a list."""
    import zscaler_ip_ranges
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise ListError("The list is not a file.")
    if len(data) > MAX_BYTES:
        raise ListError(f"The list is larger than {MAX_BYTES // 1024} KB, so it was not read (a provider's list is a few KB).")
    try:
        text = bytes(data).decode("utf-8-sig")
    except UnicodeDecodeError:
        raise ListError("The list is not text (UTF-8).") from None
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ListError(f"The list has more than {MAX_LINES:,} lines.")
    ips: List[str] = []
    hosts: List[str] = []
    for n, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if any(ord(c) < 32 or ord(c) == 127 for c in line) or "‮" in line:
            raise ListError(f"Line {n} holds control characters.")
        for tok in re.split(r"[\s,;]+", line):
            if not tok:
                continue
            if len(tok) > 253:
                raise ListError(f"Line {n}: an entry is longer than 253 characters.")
            looks_ip = bool(re.match(r"\A[0-9a-fA-F:.]+(?:/\d{1,3})?\Z", tok)) and (":" in tok or re.match(r"\A[\d./]+\Z", tok))
            if looks_ip:
                cidr, why = zscaler_ip_ranges.check_cidr(tok, from_feed=True)
                if cidr is None:
                    raise ListError(f"Line {n}: '{tok[:60]}' {why or 'is not a public address range'}.")
                if cidr not in ips:
                    ips.append(cidr)
            else:
                h = tok.lower().rstrip(".")
                if not _HOST.match(h):
                    raise ListError(f"Line {n}: '{tok[:60].encode('unicode_escape').decode('ascii')}' is not an address range or a host name.")
                if h not in hosts:
                    hosts.append(h)
            if len(ips) + len(hosts) > MAX_ENTRIES:
                raise ListError(f"The list has more than {MAX_ENTRIES:,} entries.")
    if not ips and not hosts:
        raise ListError("The list names no address range and no host name.")
    return {"ips": ips, "hosts": hosts}


# ── The kept list ────────────────────────────────────────────────────
class VendorList:
    """One provider's checked list, with its address ranges and host names."""

    def __init__(self, pid: str, entries: Dict[str, List[str]], meta: Dict[str, Any]):
        self.pid = pid
        self.label = PROVIDERS[pid]["label"]
        self.meta = dict(meta)
        self.hosts = list(entries.get("hosts") or [])
        self.nets = [ipaddress.ip_network(c, strict=False) for c in entries.get("ips") or []]
        self.counts = {"ipv4": sum(1 for x in self.nets if x.version == 4), "ipv6": sum(1 for x in self.nets if x.version == 6),
                       "hosts": len(self.hosts)}

    def obtained(self) -> Optional[_dt.datetime]:
        return _parse_time(self.meta.get("fetched_at"))

    def checked(self) -> Optional[_dt.datetime]:
        return _parse_time(self.meta.get("checked_at")) or self.obtained()

    def age_days(self, now: Optional[_dt.datetime] = None) -> Optional[float]:
        c = self.checked()
        return None if c is None else max(0.0, ((now or _now()) - c).total_seconds() / 86400)

    def stale(self, now: Optional[_dt.datetime] = None) -> bool:
        import m365_endpoints
        age = self.age_days(now)
        return age is None or age > m365_endpoints.max_age_days()

    def describe(self) -> str:
        when = self.obtained()
        verb = "imported" if self.meta.get("source") == "imported" else "fetched"
        return f"{self.label}'s list, {verb} {when.strftime('%Y-%m-%d') if when else 'on an unknown date'}"

    def lookup_ip(self, ip: Any) -> Optional[str]:
        if getattr(ip, "version", None) == 6 and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return next((str(n) for n in self.nets if n.version == ip.version and ip in n), None)

    def lookup_host(self, host: str) -> Optional[str]:
        h = str(host or "").lower().rstrip(".")
        if not h:
            return None
        for e in self.hosts:
            if e.startswith("*."):
                if h.endswith(e[1:]):
                    return e
            elif h == e:
                return e
        return None

    def has_family(self, version: int) -> bool:
        return any(n.version == version for n in self.nets)


_CACHE: Dict[str, Any] = {}


def _read_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            raw = f.read(MAX_BYTES * 4 + 1)
    except OSError:
        return None
    if len(raw) > MAX_BYTES * 4:
        return None
    try:
        doc = safe_files.strict_json_loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def load(pid: str) -> Optional[VendorList]:
    """The kept list of one provider, or None (none kept, or damaged: it is
    checked again as untrusted). Read again only when the file changed."""
    _check_pid(pid)
    p = list_path(pid)
    try:
        st = os.stat(p)
        key = (p, st.st_mtime_ns, st.st_size)
    except OSError:
        return None
    with _LOCK:
        hit = _CACHE.get(pid)
        if hit and hit[0] == key:
            return hit[1]
        doc = _read_json(p)
        lst = None
        if doc is not None and doc.get("format") == 1 and doc.get("provider") == pid:
            try:
                entries = parse("\n".join([str(x) for x in (doc.get("ips") or [])] + [str(x) for x in (doc.get("hosts") or [])]))
                meta = {k: doc.get(k) for k in ("source", "fetched_at", "checked_at", "sha256")}
                if meta["source"] in ("fetched", "imported") and _parse_time(meta["fetched_at"]):
                    lst = VendorList(pid, entries, meta)
            except (ListError, TypeError, ValueError):
                lst = None
        _CACHE[pid] = (key, lst)
        return lst


_CURRENT: Dict[str, Any] = {"at": 0.0, "lists": None, "folder": None}
_CURRENT_SECONDS = 2.0     # a run asks per rule; the files are looked at no more often than this


def current() -> Dict[str, VendorList]:
    """{provider: its kept list} for every provider with one."""
    import time
    with _LOCK:
        now = time.monotonic()
        where = folder()
        if _CURRENT["lists"] is not None and _CURRENT["folder"] == where and now - _CURRENT["at"] < _CURRENT_SECONDS:
            return dict(_CURRENT["lists"])
        out = {}
        for pid in PROVIDERS:
            lst = load(pid)
            if lst is not None:
                out[pid] = lst
        _CURRENT.update(at=now, lists=out, folder=where)
        return dict(out)


def _store(pid: str, entries: Dict[str, List[str]], *, source: str, digest: str, now: _dt.datetime) -> None:
    doc = {"format": 1, "provider": pid, "source": source, "fetched_at": _iso(now), "checked_at": _iso(now), "sha256": digest,
           "source_name": PROVIDERS[pid]["source"], "ips": entries["ips"], "hosts": entries["hosts"]}
    with _LOCK:
        safe_files.private_makedirs(folder())
        safe_files.write_private_atomic(list_path(pid), json.dumps(doc, indent=0, separators=(",", ":")))
        _CACHE.pop(pid, None)
        _CURRENT["lists"] = None


def import_file(pid: Any, data: Any, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Keep a list saved by hand. ListError when refused; the list kept before stays."""
    pid = _check_pid(pid)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    entries = parse(raw)
    _store(pid, entries, source="imported", digest=hashlib.sha256(bytes(raw)).hexdigest(), now=now or _now())
    return status(now)


def remove(pid: Any) -> Dict[str, Any]:
    pid = _check_pid(pid)
    with _LOCK:
        try:
            os.remove(list_path(pid))
        except FileNotFoundError:
            pass
        _CACHE.pop(pid, None)
        _CURRENT["lists"] = None
    return status()


# ── Settings ─────────────────────────────────────────────────────────
def settings() -> Dict[str, Any]:
    """{enabled: {provider: bool} (all False by default), last_error: {provider: text}}."""
    doc = _read_json(settings_path()) or {}
    en = doc.get("enabled") if isinstance(doc.get("enabled"), dict) else {}
    errs = doc.get("last_error") if isinstance(doc.get("last_error"), dict) else {}
    return {"enabled": {pid: en.get(pid) is True and bool(p["fetch"]) for pid, p in PROVIDERS.items()},
            "last_error": {pid: str(errs[pid])[:300] for pid in PROVIDERS if isinstance(errs.get(pid), str) and errs.get(pid)}}


def _save_settings(cur: Dict[str, Any]) -> None:
    with _LOCK:
        safe_files.private_makedirs(folder())
        safe_files.write_private_atomic(settings_path(), json.dumps(cur, indent=1))


def set_enabled(pid: Any, enabled: bool) -> Dict[str, Any]:
    pid = _check_pid(pid)
    if enabled and not PROVIDERS[pid]["fetch"]:
        raise FetchDisabled(f"{PROVIDERS[pid]['label']} publishes no file to fetch: import its list by hand. {PROVIDERS[pid]['how']}")
    with _LOCK:
        cur = settings()
        cur["enabled"][pid] = bool(enabled)
        _save_settings(cur)
    return status()


def status(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Every provider: can it be fetched, from where, is fetching on, the kept list (when, how old, stale, counts), the last error."""
    cfg = settings()
    out = []
    for pid, p in PROVIDERS.items():
        lst = load(pid)
        row: Dict[str, Any] = {"id": pid, "label": p["label"], "fetchable": bool(p["fetch"]), "url": p["fetch"],
                               "host": re.sub(r"^https://([^/]+)/.*$", r"\1", p["fetch"]) if p["fetch"] else None,
                               "how": p["how"], "source_name": p["source"], "names": list(p["names"]),
                               "enabled": cfg["enabled"][pid], "present": lst is not None, "last_error": cfg["last_error"].get(pid)}
        if lst is not None:
            age = lst.age_days(now)
            row.update(source=lst.meta.get("source"), fetched_at=lst.meta.get("fetched_at"), checked_at=lst.meta.get("checked_at"),
                       age_days=None if age is None else round(age, 1), stale=lst.stale(now), counts=dict(lst.counts), describe=lst.describe())
        out.append(row)
    import m365_endpoints
    return {"providers": out, "max_age_days": m365_endpoints.max_age_days(), "max_kb": MAX_BYTES // 1024}


# ── Fetching (zoom only; off by default; only on Fetch now) ─────────────
def _allowed(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    return p.scheme == "https" and (p.hostname or "").lower() in FETCH_HOSTS and p.username is None and p.password is None and p.port in (None, 443)


def _get(url: str, cap: int) -> bytes:
    """One GET: https, an allowlisted host, no redirect followed, a timeout, TLS verified, at most `cap` bytes read."""
    if not _allowed(url):
        raise ListError("Only the provider's published address is fetched.")
    import requests
    host = re.sub(r"^https://([^/]+)/.*$", r"\1", url)
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True,
                         headers={"Accept": "text/plain", "User-Agent": "Zscaler-Made-Easy (published endpoint list)"})
    except requests.exceptions.SSLError:
        raise ListError(f"TLS error reaching {host} (a TLS-inspecting proxy? point REQUESTS_CA_BUNDLE at its root certificate).") from None
    except requests.exceptions.Timeout:
        raise ListError(f"{host} did not answer within {FETCH_TIMEOUT} seconds.") from None
    except requests.exceptions.RequestException as e:
        raise ListError(f"{host} could not be reached ({type(e).__name__}).") from None
    try:
        if 300 <= r.status_code < 400:
            raise ListError(f"{host} answered with a redirect (HTTP {r.status_code}), which is not followed.")
        if r.status_code != 200:
            raise ListError(f"{host} answered HTTP {r.status_code}.")
        declared = str((r.headers or {}).get("Content-Length") or "").strip()
        if declared.isdigit() and int(declared) > cap:
            raise ListError(f"{host}'s answer is larger than {cap // 1024} KB, so it was not read.")
        if getattr(r, "raw", None) is None:   # an answer already in memory (no stream): measured as it is
            body = r.content or b""
            if len(body) > cap:
                raise ListError(f"{host}'s answer is larger than {cap // 1024} KB, so it was not read.")
            return body
        out = bytearray()
        for chunk in r.iter_content(chunk_size=64 * 1024):
            out += chunk
            if len(out) > cap:
                raise ListError(f"{host}'s answer is larger than {cap // 1024} KB, so it was not read.")
        return bytes(out)
    finally:
        try:
            r.close()
        except Exception:  # noqa: BLE001
            pass


def fetch(pid: Any, now: Optional[_dt.datetime] = None, get: Optional[Callable[[str, int], bytes]] = None) -> Dict[str, Any]:
    """Fetch one provider's list now (only when it publishes one and
    fetching it is on: FetchDisabled otherwise). ListError when refused;
    the list kept before stays. Returns status()."""
    pid = _check_pid(pid)
    p = PROVIDERS[pid]
    if not p["fetch"]:
        raise FetchDisabled(f"{p['label']} publishes no file to fetch: import its list by hand. {p['how']}")
    if not settings()["enabled"][pid]:
        raise FetchDisabled(f"Fetching {p['label']}'s list is off. Turn it on in Advanced settings, or import the file by hand.")
    now = now or _now()
    with _LOCK:
        cur = settings()
        try:
            body = (get or _get)(p["fetch"], MAX_BYTES)
            entries = parse(body)
            _store(pid, entries, source="fetched", digest=hashlib.sha256(body).hexdigest(), now=now)
        except ListError as e:
            cur["last_error"][pid] = str(e)[:300]
            _save_settings(cur)
            raise
        cur["last_error"].pop(pid, None)
        _save_settings(cur)
    return status(now)
