"""Zscaler's published IP ranges and host names, consolidated into allowlists.

Why: a firewall in front of Client Connector, a Branch Connector, an App
Connector or a GRE/IPsec tunnel must let traffic reach Zscaler's data
centres, and those ranges change. Zscaler publishes them per cloud on its
config portal; this module keeps a checked copy of each feed, then builds
one allowlist per cloud and region: aggregated IPv4 and IPv6 CIDRs (with
the operator's exclusions taken out and extra ranges added) and the host
names, as a plain list, CSV, Palo Alto external dynamic lists, generic
JSON or a Microsoft 365-style endpoint list. Nothing is pushed to any
firewall: the operator downloads the text.

Where the feeds come from, both optional:
  * fetched from Zscaler's config portal, https://config.zscaler.com, only
    when the operator has turned fetching on and clicks Fetch now (OFF by
    default; no timer). GET only, that one host (ALLOWED_HOSTS, also on
    zscaler_update_check.ALLOWED_HOSTS), https only, no redirect followed,
    a timeout, TLS verified, the answer capped at MAX_BYTES before it is
    parsed; the URL is built from fixed tables (cloud names below), never
    from typed text, and nothing about the tenant is sent;
  * imported by hand: the same JSON, saved from the same address on a
    machine that can reach it (offline or air-gapped installs).

Each feed is checked as untrusted input before it is kept: size, JSON
depth, the shape below, every CIDR (a public unicast range no wider than
/8 for IPv4 or /16 for IPv6: a published Zscaler range is never private,
loopback, link-local, multicast, reserved or the whole internet, so a
tampered feed cannot open the firewall to 10.0.0.0/8 or 0.0.0.0/0) and
every host name (an LDH name under one of Zscaler's own domains). A feed
whose shape is wrong is refused whole, and the copy kept before stays; a
single entry that fails is dropped and reported with the reason. The kept
copy is owner-only, beside the app's other caches, with where it came
from, when, its SHA-256 and the previous copy's ranges (for "added" and
"removed"). A feed not fetched or imported is "unknown", never empty; one
older than MAX_AGE_DAYS is marked stale on every allowlist built from it.

The feeds (config portal paths under https://config.zscaler.com/api/):
  cenr              <cloud>/cenr/json
                    {"<cloud>": {"continent : <region>": {"city : <city>":
                    [{"range": CIDR, "hostname": host, "vpn": host,
                    "gre": IP, "latitude": .., "longitude": ..}]}}}
                    the cloud enforcement node ranges (Zscaler's notice
                    "Addition to Zscaler Aggregate & Hub IP Address Ranges"
                    names config.zscaler.com/<cloud>/cenr; the JSON path and
                    the field names are ASSUMED: not reachable from here to
                    verify, and not in the SDK);
  hubs_recommended  <cloud>/hubs/cidr/json/recommended  {"hubPrefixes": [CIDR]}
  hubs_required     <cloud>/hubs/cidr/json/required     {"hubPrefixes": [CIDR]}
                    hub ranges (the same notice names the cloud's /hubs page;
                    JSON paths and key ASSUMED);
  future            <cloud>/future/json   {"prefixes": [CIDR]}   ranges of data
                    centres not yet live (ASSUMED);
  svpn              <cloud>/svpn/json     {"svpnIPs": [IP]}   App Connector
                    tunnel (Tunnel 2.0) addresses (ASSUMED);
  zpa               <zpa cloud>/zpa/json  {"content": [{"IPs": [CIDR], ...}]}
                    the ZPA firewall allow list for private.zscaler.com,
                    zpatwo.net or zpabeta.net (ASSUMED: also an optional
                    service name and host name list per item).
The Zscaler SDK (zscaler-sdk-python 1.11.3) has no client for the config
portal; it is a public, unauthenticated site.
"""
from __future__ import annotations

import csv
import datetime as _dt
import hashlib
import io
import ipaddress
import json
import os
import re
import threading
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Tuple

import csv_safe
import safe_files

# ── What may be fetched ──────────────────────────────────────────────
HOST = "config.zscaler.com"
ALLOWED_HOSTS = frozenset({HOST})
BASE = f"https://{HOST}/api/"
FETCH_TIMEOUT = 10                      # seconds, connect and read
MAX_BYTES = 4 * 1024 * 1024             # a feed is a few hundred KB; anything over 4 MB is refused, not read
MAX_ENTRIES = 20_000                    # ranges or host names in one feed
MAX_REGIONS = 64
MAX_CITIES = 4000
MAX_AGE_DAYS = 30
MAX_EXTRA = 2000                        # operator-typed ranges (added or excluded)
MAX_V4_PREFIX = 8                       # a published range is never wider than /8 (IPv4) or /16 (IPv6)
MAX_V6_PREFIX = 16
MAX_REJECTED_LISTED = 50

# The ZIA clouds the portal serves (zscaler_clouds names -> portal name).
ZIA_CLOUDS: Dict[str, str] = {
    "zscaler": "zscaler.net", "zscalerone": "zscalerone.net", "zscalertwo": "zscalertwo.net",
    "zscalerthree": "zscalerthree.net", "zscloud": "zscloud.net", "zscalerten": "zscalerten.net",
    "zscalerbeta": "zscalerbeta.net", "zscalergov": "zscalergov.net", "zscalergovus": "zscalergov.us",
}
ZPA_CLOUDS: Tuple[str, ...] = ("private.zscaler.com", "zpatwo.net", "zpabeta.net")

# Host names a feed may name: Zscaler's own domains only.
ZSCALER_DOMAINS: Tuple[str, ...] = (
    "zscaler.net", "zscalerone.net", "zscalertwo.net", "zscalerthree.net", "zscloud.net", "zscalerten.net",
    "zscalerbeta.net", "zscalergov.net", "zscalergov.us", "zscaler.com", "zpath.net", "zpatwo.net", "zpabeta.net",
    "zscalerfeed.net", "zsapi.net", "zslogin.net", "zdxcloud.net", "zscalerportal.net",
)

FEEDS: Dict[str, Dict[str, Any]] = {
    "cenr": {"label": "Cloud enforcement node ranges (by region and city)", "product": "zia", "path": "{cloud}/cenr/json", "required": True},
    "hubs_recommended": {"label": "Hub ranges (recommended)", "product": "zia", "path": "{cloud}/hubs/cidr/json/recommended", "required": True},
    "hubs_required": {"label": "Hub ranges (required)", "product": "zia", "path": "{cloud}/hubs/cidr/json/required", "required": True},
    "future": {"label": "Future data centre ranges", "product": "zia", "path": "{cloud}/future/json", "required": False},
    "svpn": {"label": "App Connector tunnel (Tunnel 2.0) addresses", "product": "zia", "path": "{cloud}/svpn/json", "required": True},
    "zpa": {"label": "ZPA firewall allow list", "product": "zpa", "path": "{cloud}/zpa/json", "required": True},
}
GLOBAL = "Global"
ADDED = "Added by you"

_LOCK = threading.RLock()


class FeedError(ValueError):
    """A feed (fetched or imported) or an option that is refused; the message says why in plain words."""


class FetchDisabled(RuntimeError):
    """Fetching from the config portal is off."""


# ── Where the copies are kept ────────────────────────────────────────
def folder() -> str:
    env = os.environ.get("DLP_CHECK_ZSCALER_RANGES_DIR")
    if env:
        return env
    import zscaler_update_check
    return os.path.join(zscaler_update_check.data_dir(), "zscaler_ranges")


def settings_path() -> str:
    return os.path.join(folder(), "settings.json")


def feed_path(feed: str, cloud: str) -> str:
    check_feed_cloud(feed, cloud)
    return os.path.join(folder(), f"{feed}@{cloud}.json")   # both from fixed tables


def max_age_days() -> int:
    try:
        n = int(os.environ.get("DLP_CHECK_ZSCALER_RANGES_MAX_AGE_DAYS", MAX_AGE_DAYS))
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


# ── Names ────────────────────────────────────────────────────────────
def zia_cloud(cloud: Any) -> str:
    """A cloud as the app stores it (or its portal name) -> the portal's
    cloud name. 'production' (Commercial, cloud not named) is zscaler.net."""
    c = str(cloud or "").strip().lower()
    if c in ZIA_CLOUDS.values():
        return c
    try:
        import zscaler_clouds
        n = zscaler_clouds.normalize(c)
    except ValueError:
        raise FeedError(f"Unknown Zscaler cloud '{c[:40]}'. Pick one of: {', '.join(ZIA_CLOUDS.values())}.") from None
    return ZIA_CLOUDS["zscaler" if n == "production" else n]


def check_feed_cloud(feed: Any, cloud: Any) -> Tuple[str, str]:
    """(feed, cloud) when both are in the fixed tables (the ZPA feed takes a
    ZPA cloud, the others a ZIA cloud); FeedError otherwise."""
    f = str(feed or "")
    if f not in FEEDS:
        raise FeedError(f"Unknown feed '{f[:40]}'. Pick one of: {', '.join(FEEDS)}.")
    c = str(cloud or "")
    ok = c in ZPA_CLOUDS if FEEDS[f]["product"] == "zpa" else c in ZIA_CLOUDS.values()
    if not ok:
        raise FeedError(f"'{c[:40]}' is not a {'ZPA' if FEEDS[f]['product'] == 'zpa' else 'ZIA'} cloud the config portal serves.")
    return f, c


def feed_url(feed: str, cloud: str) -> str:
    f, c = check_feed_cloud(feed, cloud)
    return BASE + FEEDS[f]["path"].format(cloud=c)


# ── Checking a feed (untrusted) ──────────────────────────────────────
_HOST = re.compile(r"\A(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
_CTRL = re.compile(r"[\x00-\x1f\x7f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def check_cidr(raw: Any, *, from_feed: bool = True) -> Tuple[Optional[str], str]:
    """One range from a feed (or typed) -> (canonical CIDR, '') or (None,
    why). A bare address is a /32 or /128. Host bits are cleared. From a
    feed, only a public unicast range no wider than /8 (IPv4) or /16
    (IPv6) passes; typed ranges may be private (said in a warning)."""
    if not isinstance(raw, str):
        return None, "not text"
    s = raw.strip()
    if not s or len(s) > 64:
        return None, "empty or too long"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None, "not an IP address or CIDR"
    if net.version == 6 and net.network_address.ipv4_mapped is not None:
        return None, "an IPv4-mapped IPv6 range"
    wide = MAX_V4_PREFIX if net.version == 4 else MAX_V6_PREFIX
    if net.prefixlen < wide:
        return None, f"wider than /{wide}"
    if from_feed:
        first, last = net.network_address, net.broadcast_address
        for a in (first, last):
            if not a.is_global or a.is_multicast or a.is_reserved or a.is_loopback or a.is_link_local or a.is_unspecified:
                return None, "not a public unicast range"
    return str(net), ""


def check_host(raw: Any) -> Tuple[Optional[str], str]:
    """A host name from a feed -> (lower case, no trailing dot) when it is
    an LDH name (optionally '*.' first) under one of Zscaler's domains."""
    if not isinstance(raw, str):
        return None, "not text"
    h = raw.strip().lower().rstrip(".")
    if not h:
        return None, "empty"
    if len(h) > 253 or not _HOST.match(h):
        return None, "not a host name"
    bare = h[2:] if h.startswith("*.") else h
    if not any(bare == d or bare.endswith("." + d) for d in ZSCALER_DOMAINS):
        return None, "not under a Zscaler domain"
    return h, ""


def _name(v: Any, prefix: str) -> str:
    """'continent : EMEA' -> 'EMEA' (printable, at most 80 characters)."""
    s = _CTRL.sub(" ", str(v))
    if s.lower().startswith(prefix):
        s = s[len(prefix):]
    s = " ".join(s.split())[:80]
    return s or "?"


def _load_json(data: Any) -> Any:
    if isinstance(data, str):
        data = data.encode("utf-8")
    if not isinstance(data, (bytes, bytearray)):
        raise FeedError("The feed is not a file.")
    if len(data) > MAX_BYTES:
        raise FeedError(f"The feed is larger than {MAX_BYTES // (1024 * 1024)} MB, so it was not read (Zscaler's feeds are a few hundred KB).")
    try:
        return safe_files.strict_json_loads(bytes(data).decode("utf-8-sig"))
    except RecursionError:
        raise FeedError("The feed is nested too deeply to be a Zscaler feed.") from None
    except UnicodeDecodeError:
        raise FeedError("The feed is not valid JSON.") from None
    except ValueError as e:
        if "nested too deeply" in str(e):
            raise FeedError("The feed is nested too deeply to be a Zscaler feed.") from None
        raise FeedError("The feed is not valid JSON.") from None


class _Collect:
    def __init__(self) -> None:
        self.ranges: List[Dict[str, str]] = []
        self.hosts: List[Dict[str, str]] = []
        self.rejected: List[Dict[str, str]] = []
        self.rejected_total = 0
        self.n = 0

    def _count(self) -> None:
        self.n += 1
        if self.n > MAX_ENTRIES:
            raise FeedError(f"The feed has more than {MAX_ENTRIES} entries, so it is not a Zscaler feed.")

    def reject(self, value: Any, why: str, where: str) -> None:
        self.rejected_total += 1
        if len(self.rejected) < MAX_REJECTED_LISTED:
            self.rejected.append({"value": _CTRL.sub(" ", str(value))[:80], "why": why, "where": where[:120]})

    def cidr(self, value: Any, region: str, city: str = "") -> None:
        self._count()
        c, why = check_cidr(value)
        if c is None:
            self.reject(value, why, f"{region}{' / ' + city if city else ''}")
        else:
            self.ranges.append({"cidr": c, "region": region, "city": city})

    def host(self, value: Any, kind: str, region: str, city: str = "") -> None:
        if value in (None, ""):
            return
        self._count()
        h, why = check_host(value)
        if h is None:
            self.reject(value, why, f"{region}{' / ' + city if city else ''}")
        else:
            self.hosts.append({"host": h, "kind": kind, "region": region, "city": city})


def _list_of(doc: Any, key: str, feed: str) -> List[Any]:
    if not isinstance(doc, dict) or key not in doc:
        raise FeedError(f"This is not the {FEEDS[feed]['label'].lower()} feed: it has no '{key}' list.")
    v = doc[key]
    if not isinstance(v, list):
        raise FeedError(f"'{key}' is not a list.")
    return v


def parse(feed: str, cloud: str, data: Any) -> Dict[str, Any]:
    """A feed's JSON -> {ranges: [{cidr, region, city}], hosts: [{host,
    kind, region, city}], rejected: [...], rejected_total}. FeedError (a
    plain sentence) when the shape is wrong or nothing usable is left."""
    feed, cloud = check_feed_cloud(feed, cloud)
    doc = _load_json(data)
    col = _Collect()
    if feed == "cenr":
        if not isinstance(doc, dict) or not doc:
            raise FeedError("This is not the cloud enforcement node feed: it should be an object keyed by the cloud name.")
        top = doc.get(cloud)
        if top is None and len(doc) == 1:
            only = next(iter(doc))
            raise FeedError(f"This feed is for '{_name(only, '')[:40]}', not {cloud}: pick that cloud, or import {cloud}'s feed.")
        if not isinstance(top, dict):
            raise FeedError(f"This is not the cloud enforcement node feed for {cloud}.")
        if len(top) > MAX_REGIONS:
            raise FeedError(f"The feed has more than {MAX_REGIONS} regions, so it is not a Zscaler feed.")
        cities = 0
        for rkey, rval in top.items():
            region = _name(rkey, "continent :")
            if not isinstance(rval, dict):
                raise FeedError(f"Region '{region}' is not an object of cities.")
            for ckey, nodes in rval.items():
                cities += 1
                if cities > MAX_CITIES:
                    raise FeedError(f"The feed has more than {MAX_CITIES} cities, so it is not a Zscaler feed.")
                city = _name(ckey, "city :")
                if not isinstance(nodes, list):
                    raise FeedError(f"City '{city}' is not a list of nodes.")
                for node in nodes:
                    if not isinstance(node, dict):
                        raise FeedError(f"A node in '{city}' is not an object.")
                    if node.get("range") not in (None, ""):
                        col.cidr(node.get("range"), region, city)
                    col.host(node.get("hostname"), "node", region, city)
                    col.host(node.get("vpn"), "vpn", region, city)
    elif feed in ("hubs_recommended", "hubs_required"):
        for v in _list_of(doc, "hubPrefixes", feed):
            col.cidr(v, GLOBAL)
    elif feed == "future":
        for v in _list_of(doc, "prefixes", feed):
            col.cidr(v, GLOBAL)
    elif feed == "svpn":
        for v in _list_of(doc, "svpnIPs", feed):
            col.cidr(v, GLOBAL)
    elif feed == "zpa":
        items = _list_of(doc, "content", feed)
        for item in items:
            if not isinstance(item, dict):
                raise FeedError("An item of the ZPA allow list is not an object.")
            ips = item.get("IPs", item.get("ips", []))
            if not isinstance(ips, list):
                raise FeedError("An item's 'IPs' is not a list.")
            label = next((item[k] for k in ("Service", "service", "Name", "name") if isinstance(item.get(k), str) and item.get(k).strip()), "")
            region = _name(label, "") if label else GLOBAL
            for v in ips:
                col.cidr(v, region)
            hosts = item.get("Domains", item.get("domains", []))
            if isinstance(hosts, list):
                for h in hosts:
                    col.host(h, "domain", region)
    if not col.ranges and not col.hosts:
        raise FeedError("The feed names no usable range or host name" + (f" ({col.rejected_total} entries refused)." if col.rejected_total else "."))
    return {"ranges": col.ranges, "hosts": col.hosts, "rejected": col.rejected, "rejected_total": col.rejected_total}


# ── The kept copies ──────────────────────────────────────────────────
def _read_json(path: str, cap: int = MAX_BYTES * 3) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            raw = f.read(cap + 1)
    except OSError:
        return None
    if len(raw) > cap:
        return None
    try:
        doc = safe_files.strict_json_loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return doc if isinstance(doc, dict) else None


def load(feed: str, cloud: str) -> Optional[Dict[str, Any]]:
    """The kept copy of one feed, checked again (a hand-edited file that no
    longer passes is not used), or None."""
    try:
        p = feed_path(feed, cloud)
    except FeedError:
        return None
    doc = _read_json(p)
    if not doc or doc.get("format") != 1 or doc.get("feed") != feed or doc.get("cloud") != cloud:
        return None
    if doc.get("source") not in ("fetched", "imported") or _parse_time(doc.get("fetched_at")) is None:
        return None
    ranges, hosts = [], []
    for r in doc.get("ranges") if isinstance(doc.get("ranges"), list) else []:
        c, _ = check_cidr(r.get("cidr") if isinstance(r, dict) else None)
        if c is None:
            return None
        ranges.append({"cidr": c, "region": _name(r.get("region", GLOBAL), ""), "city": _name(r.get("city"), "") if r.get("city") else ""})
    for h in doc.get("hosts") if isinstance(doc.get("hosts"), list) else []:
        n, _ = check_host(h.get("host") if isinstance(h, dict) else None)
        if n is None:
            return None
        hosts.append({"host": n, "kind": str(h.get("kind") or "")[:10], "region": _name(h.get("region", GLOBAL), ""),
                      "city": _name(h.get("city"), "") if h.get("city") else ""})
    if len(ranges) + len(hosts) > MAX_ENTRIES or not (ranges or hosts):
        return None
    prev = doc.get("previous") if isinstance(doc.get("previous"), dict) else {}
    prev_cidrs = [c for c in (check_cidr(x)[0] for x in (prev.get("cidrs") or [])[:MAX_ENTRIES]) if c]
    return {"feed": feed, "cloud": cloud, "source": doc["source"], "fetched_at": doc["fetched_at"], "sha256": str(doc.get("sha256") or "")[:64],
            "ranges": ranges, "hosts": hosts, "rejected": [r for r in (doc.get("rejected") or [])[:MAX_REJECTED_LISTED] if isinstance(r, dict)],
            "rejected_total": int(doc.get("rejected_total") or 0) if str(doc.get("rejected_total") or 0).isdigit() else 0,
            "previous": {"fetched_at": prev.get("fetched_at") if _parse_time(prev.get("fetched_at")) else None, "cidrs": prev_cidrs}}


def _store(feed: str, cloud: str, parsed: Dict[str, Any], *, source: str, digest: str, now: _dt.datetime) -> None:
    old = load(feed, cloud)
    prev = {"fetched_at": old["fetched_at"], "cidrs": sorted({r["cidr"] for r in old["ranges"]})} if old else {"fetched_at": None, "cidrs": []}
    doc = {"format": 1, "feed": feed, "cloud": cloud, "source": source, "fetched_at": _iso(now), "sha256": digest,
           "url": feed_url(feed, cloud), "ranges": parsed["ranges"], "hosts": parsed["hosts"],
           "rejected": parsed["rejected"], "rejected_total": parsed["rejected_total"], "previous": prev}
    with _LOCK:
        safe_files.private_makedirs(folder())
        safe_files.write_private_atomic(feed_path(feed, cloud), json.dumps(doc, separators=(",", ":")))


def import_file(feed: str, cloud: str, data: Any, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """Keep a feed saved by hand. The same checks as a fetched one;
    FeedError when refused (the copy kept before stays)."""
    feed, cloud = check_feed_cloud(feed, cloud)
    raw = data.encode("utf-8") if isinstance(data, str) else data
    parsed = parse(feed, cloud, raw)
    _store(feed, cloud, parsed, source="imported", digest=hashlib.sha256(bytes(raw)).hexdigest(), now=now or _now())
    return feed_status(feed, cloud, now)


def remove(cloud: Optional[str] = None) -> Dict[str, Any]:
    """Forget the kept feeds (of one cloud, or all)."""
    with _LOCK:
        try:
            names = os.listdir(folder())
        except OSError:
            names = []
        for n in names:
            m = re.fullmatch(r"([a-z_]+)@([a-z0-9.]+)\.json", n)
            if m and m.group(1) in FEEDS and (cloud is None or m.group(2) == cloud):
                try:
                    os.remove(os.path.join(folder(), n))
                except OSError:
                    pass
    return status()


# ── Settings ─────────────────────────────────────────────────────────
def settings() -> Dict[str, Any]:
    doc = _read_json(settings_path(), 64 * 1024) or {}
    err = doc.get("last_error")
    return {"enabled": doc.get("enabled") is True,
            "last_attempt": doc.get("last_attempt") if _parse_time(doc.get("last_attempt")) else None,
            "last_error": str(err)[:400] if isinstance(err, str) and err else None}


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


def feed_status(feed: str, cloud: str, now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    kept = load(feed, cloud)
    out: Dict[str, Any] = {"feed": feed, "cloud": cloud, "label": FEEDS[feed]["label"], "url": feed_url(feed, cloud), "present": kept is not None}
    if kept:
        t = _parse_time(kept["fetched_at"])
        age = max(0.0, ((now or _now()) - t).total_seconds() / 86400) if t else None
        v4 = sum(1 for r in kept["ranges"] if ":" not in r["cidr"])
        out.update(source=kept["source"], fetched_at=kept["fetched_at"], age_days=None if age is None else round(age, 1),
                   stale=age is None or age > max_age_days(), ranges=len(kept["ranges"]), ipv4=v4, ipv6=len(kept["ranges"]) - v4,
                   hosts=len({h["host"] for h in kept["hosts"]}), rejected=kept["rejected_total"],
                   regions=sorted({r["region"] for r in kept["ranges"]}))
    return out


def status(now: Optional[_dt.datetime] = None) -> Dict[str, Any]:
    """What the page shows: the switch, the destination, every kept feed
    (when, where from, how old, counts) and the last error."""
    cfg = settings()
    kept = []
    try:
        names = sorted(os.listdir(folder()))
    except OSError:
        names = []
    for n in names:
        m = re.fullmatch(r"([a-z_]+)@([a-z0-9.]+)\.json", n)
        if m and m.group(1) in FEEDS:
            try:
                st = feed_status(m.group(1), m.group(2), now)
            except FeedError:
                continue
            if st["present"]:
                kept.append(st)
    return {"enabled": cfg["enabled"], "host": HOST, "destination": f"https://{HOST}", "last_attempt": cfg["last_attempt"],
            "last_error": cfg["last_error"], "max_age_days": max_age_days(), "max_mb": MAX_BYTES // (1024 * 1024),
            "kept": kept, "feeds": [{"key": k, "label": v["label"], "product": v["product"]} for k, v in FEEDS.items()],
            "zia_clouds": list(ZIA_CLOUDS.values()), "zpa_clouds": list(ZPA_CLOUDS)}


# ── Fetching (optional, off by default, only on request) ─────────────
def _allowed(url: str) -> bool:
    from urllib.parse import urlparse
    p = urlparse(url)
    return (p.scheme == "https" and (p.hostname or "").lower() in ALLOWED_HOSTS and p.username is None and p.password is None
            and p.port in (None, 443) and not p.query and not p.fragment)


def _get(url: str, cap: int) -> bytes:
    """One GET to the config portal: https, the allowlisted host, no
    redirect followed, a timeout, TLS verified, at most `cap` bytes read."""
    if not _allowed(url):
        raise FeedError(f"Only https://{HOST} is fetched.")
    import requests
    try:
        r = requests.get(url, timeout=FETCH_TIMEOUT, allow_redirects=False, stream=True,
                         headers={"Accept": "application/json", "User-Agent": "Zscaler-Made-Easy (published IP ranges)"})
    except requests.exceptions.SSLError:
        raise FeedError(f"TLS error reaching {HOST} (a TLS-inspecting proxy? point REQUESTS_CA_BUNDLE at its root certificate).") from None
    except requests.exceptions.Timeout:
        raise FeedError(f"{HOST} did not answer within {FETCH_TIMEOUT} seconds.") from None
    except requests.exceptions.RequestException as e:
        import zscaler_update_check
        raise FeedError(f"{HOST} could not be reached ({type(e).__name__}: {zscaler_update_check.redact_url_credentials(str(e))[:120]}).") from None
    try:
        if 300 <= r.status_code < 400:
            raise FeedError(f"{HOST} answered with a redirect (HTTP {r.status_code}), which is not followed.")
        if r.status_code != 200:
            raise FeedError(f"{HOST} answered HTTP {r.status_code}.")
        declared = str((r.headers or {}).get("Content-Length") or "").strip()
        too_big = f"{HOST}'s answer is larger than {cap // (1024 * 1024)} MB, so it was not read."
        if declared.isdigit() and int(declared) > cap:
            raise FeedError(too_big)
        if getattr(r, "raw", None) is None:
            body = r.content or b""
            if len(body) > cap:
                raise FeedError(too_big)
            return body
        out = bytearray()
        for chunk in r.iter_content(chunk_size=64 * 1024):
            out += chunk
            if len(out) > cap:
                raise FeedError(too_big)
        return bytes(out)
    finally:
        try:
            r.close()
        except Exception:  # noqa: BLE001
            pass


def fetch(cloud: str, feeds: Sequence[str], zpa_cloud: Optional[str] = None, now: Optional[_dt.datetime] = None,
          get: Optional[Callable[[str, int], bytes]] = None) -> Dict[str, Any]:
    """Fetch the chosen feeds for `cloud` (and `zpa_cloud` for the ZPA
    feed), only when fetching is on (FetchDisabled otherwise). Each feed
    is kept or refused on its own; the copy kept before stays when a feed
    fails. Returns {status, results: [{feed, cloud, ok, error}]}."""
    if not settings()["enabled"]:
        raise FetchDisabled(f"Fetching from {HOST} is off. Turn it on here, or import the feeds by hand.")
    zia = zia_cloud(cloud)
    pairs = _pairs(zia, feeds, zpa_cloud)
    if not pairs:
        raise FeedError("Pick at least one feed.")
    now = now or _now()
    get = get or _get
    results = []
    with _LOCK:
        _save_settings(last_attempt=_iso(now))
        errors = []
        for feed, c in pairs:
            try:
                body = get(feed_url(feed, c), MAX_BYTES)
                parsed = parse(feed, c, body)
                _store(feed, c, parsed, source="fetched", digest=hashlib.sha256(body).hexdigest(), now=now)
                results.append({"feed": feed, "cloud": c, "ok": True, "error": None, "rejected": parsed["rejected_total"]})
            except FeedError as e:
                errors.append(f"{FEEDS[feed]['label']} ({c}): {e}")
                results.append({"feed": feed, "cloud": c, "ok": False, "error": str(e)[:300]})
        _save_settings(last_error=" ".join(errors)[:400] if errors else None)
    return {"status": status(now), "results": results}


def _pairs(zia: str, feeds: Iterable[str], zpa_cloud: Optional[str]) -> List[Tuple[str, str]]:
    out = []
    for f in dict.fromkeys(str(x) for x in (feeds or [])):
        if f not in FEEDS:
            raise FeedError(f"Unknown feed '{f[:40]}'.")
        if FEEDS[f]["product"] == "zpa":
            if not zpa_cloud:
                continue
            if zpa_cloud not in ZPA_CLOUDS:
                raise FeedError(f"'{str(zpa_cloud)[:40]}' is not a ZPA cloud the config portal serves: {', '.join(ZPA_CLOUDS)}.")
            out.append((f, zpa_cloud))
        else:
            out.append((f, zia))
    return out


# ── Aggregating (integer intervals, per address family) ──────────────
def _interval(net: Any) -> Tuple[int, int]:
    return int(net.network_address), int(net.broadcast_address)


def merge_intervals(iv: Iterable[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Sorted, overlapping and touching intervals joined."""
    out: List[List[int]] = []
    for a, b in sorted(iv):
        if out and a <= out[-1][1] + 1:
            out[-1][1] = max(out[-1][1], b)
        else:
            out.append([a, b])
    return [(a, b) for a, b in out]


def subtract_intervals(keep: List[Tuple[int, int]], holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """keep minus holes (both merged and sorted)."""
    out = []
    j = 0
    for a, b in keep:
        cur = a
        while j < len(holes) and holes[j][1] < cur:
            j += 1
        k = j
        while k < len(holes) and holes[k][0] <= b:
            ha, hb = holes[k]
            if ha > cur:
                out.append((cur, ha - 1))
            cur = max(cur, hb + 1)
            if cur > b:
                break
            k += 1
        if cur <= b:
            out.append((cur, b))
    return out


def _cidrs(iv: List[Tuple[int, int]], version: int) -> List[str]:
    cls = ipaddress.IPv4Address if version == 4 else ipaddress.IPv6Address
    out: List[str] = []
    for a, b in iv:
        out += [str(n) for n in ipaddress.summarize_address_range(cls(a), cls(b))]
    return out


def aggregate(cidrs: Iterable[Any], exclude: Iterable[Any] = ()) -> Dict[int, List[str]]:
    """The fewest CIDRs that cover exactly the union of `cidrs` minus the
    union of `exclude`, per family: {4: [...], 6: [...]}, in address
    order. Families are never mixed."""
    nets = {4: [], 6: []}
    holes = {4: [], 6: []}
    for src, dst in ((cidrs, nets), (exclude, holes)):
        for c in src:
            n = c if isinstance(c, (ipaddress.IPv4Network, ipaddress.IPv6Network)) else ipaddress.ip_network(str(c), strict=False)
            dst[n.version].append(_interval(n))
    return {v: _cidrs(subtract_intervals(merge_intervals(nets[v]), merge_intervals(holes[v])), v) for v in (4, 6)}


def parse_typed(text: Any, what: str) -> Tuple[List[str], List[str]]:
    """Ranges the operator typed (one per line or separated by commas;
    '#' starts a comment) -> (CIDRs, warnings). FeedError for a line that
    is not a range."""
    out, warn = [], []
    lines = [ln.split("#", 1)[0] for ln in str(text or "").splitlines()]
    for n, line in enumerate(lines, 1):
        for part in re.split(r"[\s,;]+", line.strip()):
            if not part:
                continue
            c, why = check_cidr(part, from_feed=False)
            if c is None:
                raise FeedError(f"{what}, line {n}: '{part[:40]}' is {why}.")
            net = ipaddress.ip_network(c)
            if not net.is_global:
                warn.append(f"{what}: {c} is not a public range.")
            out.append(c)
            if len(out) > MAX_EXTRA:
                raise FeedError(f"{what}: at most {MAX_EXTRA} ranges.")
    return out, warn[:20]


# ── Building the allowlist ───────────────────────────────────────────
CERT_VALIDATION_FILE = "certificate_validation_endpoints.json"
CERT_REGION = "DigiCert (certificate validation)"


def certificate_validation_endpoints() -> Dict[str, Any]:
    """The static DigiCert list shipped with the app (its source and date are in the file): {hosts, ranges, source, as_of}.
    Every entry is checked like a feed entry; one that fails the check is dropped."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), CERT_VALIDATION_FILE)
    try:
        with open(path, "r", encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, ValueError):
        return {"hosts": [], "ranges": [], "source": "", "as_of": ""}
    hosts = [x.strip().lower() for x in doc.get("hosts") or [] if isinstance(x, str) and _HOST.match(x.strip().lower())]
    ranges = [c for c in (check_cidr(x)[0] for x in doc.get("ranges") or []) if c]
    return {"hosts": hosts, "ranges": ranges, "source": str(doc.get("source") or "")[:600], "as_of": str(doc.get("as_of") or "")[:20]}


def host_form(cidrs: Iterable[str]) -> List[str]:
    """Single-address entries (/32 and /128) as the bare address; every other range unchanged."""
    out = []
    for c in cidrs:
        n = ipaddress.ip_network(str(c), strict=False)
        out.append(str(n.network_address) if n.num_addresses == 1 else str(n))
    return out


def build(cloud: str, feeds: Sequence[str], *, zpa_cloud: Optional[str] = None, regions: Optional[Sequence[str]] = None,
          exclude: Any = "", extra: Any = "", ipv4: bool = True, ipv6: bool = True,
          now: Optional[_dt.datetime] = None, digicert: bool = False, single_hosts: bool = False) -> Dict[str, Any]:
    """The consolidated allowlist from the kept feeds (no fetch): per
    region and overall, aggregated, with the exclusions taken out and the
    extra ranges added; host names; and every source with its date. A
    feed not kept is listed as missing (unknown), never as empty."""
    zia = zia_cloud(cloud)
    pairs = _pairs(zia, feeds, zpa_cloud)
    if not pairs:
        raise FeedError("Pick at least one feed.")
    if not ipv4 and not ipv6:
        raise FeedError("Pick IPv4, IPv6 or both.")
    ex, ex_warn = parse_typed(exclude, "Ranges to leave out")
    add, add_warn = parse_typed(extra, "Ranges to add")
    want_regions = None if not regions else {str(r)[:80] for r in regions}
    now = now or _now()
    sources, records, hosts = [], [], {}
    warnings: List[str] = []
    for feed, c in pairs:
        st = feed_status(feed, c, now)
        kept = load(feed, c) if st["present"] else None
        src = {"feed": feed, "cloud": c, "label": FEEDS[feed]["label"], "url": st["url"], "status": "missing"}
        if kept is None:
            warnings.append(f"{FEEDS[feed]['label']} ({c}) is unknown: fetch it or import it. The allowlist does not hold it.")
        else:
            src.update(status="stale" if st["stale"] else "ok", source=kept["source"], fetched_at=kept["fetched_at"], age_days=st["age_days"],
                       rejected=kept["rejected_total"])
            if st["stale"]:
                warnings.append(f"{FEEDS[feed]['label']} ({c}) was {'fetched' if kept['source'] == 'fetched' else 'imported'} "
                                f"{kept['fetched_at'][:10]}, more than {max_age_days()} days ago: newer ranges may be missing.")
            cur = {r["cidr"] for r in kept["ranges"]}
            if kept["previous"]["fetched_at"]:
                prev = set(kept["previous"]["cidrs"])
                src.update(added=sorted(cur - prev)[:200], removed=sorted(prev - cur)[:200], added_total=len(cur - prev),
                           removed_total=len(prev - cur), previous_at=kept["previous"]["fetched_at"])
            for r in kept["ranges"]:
                if want_regions is not None and r["region"] not in want_regions:
                    continue
                records.append((r["region"], r["cidr"], feed))
            for h in kept["hosts"]:
                if want_regions is not None and h["region"] not in want_regions:
                    continue
                e = hosts.setdefault(h["host"], {"host": h["host"], "feeds": set(), "regions": set()})
                e["feeds"].add(feed)
                e["regions"].add(h["region"])
        sources.append(src)
    cert = certificate_validation_endpoints() if digicert else None
    if cert:
        for c in cert["ranges"]:
            records.append((CERT_REGION, c, "digicert"))
        for h in cert["hosts"]:
            e = hosts.setdefault(h, {"host": h, "feeds": set(), "regions": set()})
            e["feeds"].add("digicert")
            e["regions"].add(CERT_REGION)
        if not cert["ranges"]:
            warnings.append("DigiCert is served from a content delivery network, so it is allowlisted by host name; no address range "
                            "is shipped. Add ranges from DigiCert's current guidance in 'Ranges to add' if your firewall needs them.")
    for c in add:
        records.append((ADDED, c, "added"))
    fams = [v for v, on in ((4, ipv4), (6, ipv6)) if on]
    by_region: Dict[str, List[str]] = {}
    for region, cidr, _f in records:
        by_region.setdefault(region, []).append(cidr)
    region_rows = []
    for region in sorted(by_region, key=lambda r: (r == ADDED, r == GLOBAL, r.lower())):
        agg = aggregate(by_region[region], ex)
        region_rows.append({"region": region, "in": len(by_region[region]), "ipv4": agg[4] if 4 in fams else [], "ipv6": agg[6] if 6 in fams else []})
    total = aggregate([c for _r, c, _f in records], ex)
    if not records:
        warnings.append("No range is left: nothing kept for these feeds" + (" and regions." if want_regions else "."))
    if single_hosts:
        for r in region_rows:
            r["ipv4"], r["ipv6"] = host_form(r["ipv4"]), host_form(r["ipv6"])
        total = {4: host_form(total[4]), 6: host_form(total[6])}
    all_regions = sorted({r["region"] for f, c in pairs for r in ((load(f, c) or {}).get("ranges") or [])})
    return {
        "cloud": zia, "zpa_cloud": zpa_cloud if any(f == "zpa" for f, _ in pairs) else None, "built_at": _iso(now),
        "families": fams, "sources": sources, "complete": all(s["status"] == "ok" for s in sources),
        "regions": region_rows, "available_regions": all_regions, "chosen_regions": sorted(want_regions) if want_regions else None,
        "all": {"ipv4": total[4] if 4 in fams else [], "ipv6": total[6] if 6 in fams else []},
        "counts": {"in": len(records), "ipv4": len(total[4]) if 4 in fams else 0, "ipv6": len(total[6]) if 6 in fams else 0,
                   "hosts": len(hosts), "excluded": len(ex), "added": len(add)},
        "excluded": ex, "added": add, "digicert": ({"source": cert["source"], "as_of": cert["as_of"]} if cert else None),
        "hosts": [{"host": h["host"], "feeds": sorted(h["feeds"]), "regions": sorted(h["regions"])} for h in sorted(hosts.values(), key=lambda x: x["host"])],
        "warnings": warnings + ex_warn + add_warn,
    }


# ── Rendering ────────────────────────────────────────────────────────
FORMATS = {
    "txt": ("Plain list", "txt", "text/plain; charset=utf-8"),
    "csv": ("CSV", "csv", "text/csv; charset=utf-8"),
    "edl_ip": ("Palo Alto EDL (IP list)", "txt", "text/plain; charset=utf-8"),
    "edl_url": ("Palo Alto EDL (URL list)", "txt", "text/plain; charset=utf-8"),
    "json": ("JSON", "json", "application/json"),
    "m365": ("Microsoft 365-style JSON", "json", "application/json"),
}


def _ips(result: Dict[str, Any]) -> List[str]:
    return list(result["all"]["ipv4"]) + list(result["all"]["ipv6"])


def render(result: Dict[str, Any], fmt: str) -> Tuple[str, str, str]:
    """(file name, media type, text) for one output format. Every value
    written is a canonical CIDR, a checked host name, a region name from a
    checked feed (CSV and JSON only, quoted by their writers) or a fixed
    label."""
    if fmt not in FORMATS:
        raise FeedError(f"Unknown format '{str(fmt)[:20]}'. Pick one of: {', '.join(FORMATS)}.")
    _label, ext, media = FORMATS[fmt]
    stem = f"zscaler_{result['cloud'].replace('.', '_')}_{fmt}_{result['built_at'][:10]}"
    if fmt in ("txt", "edl_ip"):
        # One range per line, nothing else: a firewall reads every line as an entry.
        text = "\n".join(_ips(result)) + "\n"
    elif fmt == "edl_url":
        # PAN-OS URL list: one host per line, no scheme; '*.' is a wildcard
        # token (Palo Alto Networks, "Formatting Guidelines for an External
        # Dynamic List": ASSUMED, not verifiable here).
        text = "\n".join(h["host"] for h in result["hosts"]) + "\n"
    elif fmt == "csv":
        buf = io.StringIO()
        w = csv_safe.writer(buf, lineterminator="\n")
        w.writerow(("region", "family", "cidr"))
        for r in result["regions"]:
            for fam in ("ipv4", "ipv6"):
                for c in r[fam]:
                    w.writerow((r["region"], fam, c))
        for h in result["hosts"]:
            w.writerow((";".join(h["regions"]), "host", h["host"]))
        text = buf.getvalue()
    elif fmt == "json":
        text = json.dumps({
            "generator": "Zscaler Made Easy", "built_at": result["built_at"], "cloud": result["cloud"], "zpa_cloud": result["zpa_cloud"],
            "complete": result["complete"], "warnings": result["warnings"],
            "sources": [{k: s.get(k) for k in ("feed", "cloud", "url", "status", "source", "fetched_at")} for s in result["sources"]],
            "ipv4": result["all"]["ipv4"], "ipv6": result["all"]["ipv6"],
            "regions": {r["region"]: {"ipv4": r["ipv4"], "ipv6": r["ipv6"]} for r in result["regions"]},
            "hostnames": [h["host"] for h in result["hosts"]], "excluded": result["excluded"],
        }, indent=1)
    else:   # m365: Microsoft's endpoint-set shape, one set per region (ports are not published by Zscaler, so left out)
        sets = []
        for i, r in enumerate(result["regions"], 1):
            ips = r["ipv4"] + r["ipv6"]
            urls = [h["host"] for h in result["hosts"] if r["region"] in h["regions"]]
            if not ips and not urls:
                continue
            sets.append({"id": i, "serviceArea": "Zscaler", "serviceAreaDisplayName": f"Zscaler {result['cloud']}: {r['region']}",
                         "category": "Default", "required": r["region"] != ADDED, "expressRoute": False, "ips": ips, "urls": urls,
                         "notes": "Built by Zscaler Made Easy from Zscaler's published ranges on " + result["built_at"][:10]})
        text = json.dumps(sets, indent=1)
    return f"{stem}.{ext}", media, text
