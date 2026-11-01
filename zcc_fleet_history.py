"""Client Connector fleet history: counts-only snapshots and their trend.

"Save to history" on the fleet page keeps one small summary of a finished
fleet read (or CSV import) per click, per tenant label, in one local file
beside the app's cache, the way SSL coverage keeps its run summaries
(ssl_coverage.record): written owner-only (0600) through a temporary file
and an atomic replace, at most HISTORY_KEEP snapshots per tenant and
HISTORY_TENANTS tenants.

A snapshot holds counts only: device and registration totals, each
service's active and not-active counts, the alert counts, the last-seen
histogram and the Client Connector versions per platform. Never a user,
a host name, a device ID, a profile or a site name (a site is cut from host
names). The file is read back as untrusted: every field is checked and
anything else is dropped, so a hand-edited file can neither crash the page
nor carry text into it.

Nothing here reads or writes a tenant.
"""
from __future__ import annotations

import json
import math
import os
import re
import tempfile
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import safe_files
import store_crypto
import zcc_fleet as zf

HISTORY_KEEP = 60          # snapshots kept per tenant
HISTORY_TENANTS = 20       # tenants kept
MAX_FILE_BYTES = 4 * 1024 * 1024
MAX_VERSIONS = 12          # versions kept per platform in a snapshot (the most common)
_LOCK = threading.Lock()

PLATFORMS = ("Windows", "macOS", "Linux", "iOS", "Android", "?")
SOURCES = ("live", "import")
ALERT_KEYS = tuple(zf.ALERTS)
BUCKET_KEYS = tuple(b[0] for b in zf.LAST_SEEN_BUCKETS) + ("never",)
_VERSION = re.compile(r"^[0-9][0-9A-Za-z.\-]{0,39}$")
_AT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(\+00:00|Z)?$")

# The figures a trend row and a comparison show, in order: (key, label).
TREND_FIELDS = (
    ("devices", "Device records"), ("registered", "Registered"), ("seen_24h", "Seen in 24 hours"), ("never_seen", "Never seen"),
    ("quarantined", "Quarantined"), ("zia", "ZIA active %"), ("zpa", "ZPA active %"), ("zdx", "ZDX active %"),
)


def history_path() -> str:
    env = os.environ.get("DLP_CHECK_FLEET_HISTORY")
    if env:
        return env
    from zscaler_update_check import _cache_path
    return os.path.join(os.path.dirname(_cache_path()), "zcc_fleet_history.json")


def tenant_key(tenant: Any) -> str:
    import tenant_auth
    return tenant_auth.scrub_classic_login(str(tenant or "tenant"))[:120]


# ── building a snapshot from a finished run (counts only) ─────────────
def entry(result: Mapping[str, Any], *, saved_at: Optional[datetime] = None) -> Dict[str, Any]:
    """The counts-only snapshot of a finished fleet result. Raises
    ValueError when the run has no device figures to keep."""
    k = result.get("kpis")
    if not k:
        raise ValueError("This run has no device figures (configuration only), so there is nothing to keep in the history.")
    services = {}
    for s in zf.SERVICES:
        v = (k.get("services") or {}).get(s) or {}
        services[s] = {"active": v.get("active"), "inactive": v.get("inactive"), "percent": v.get("percent")} if v.get("available") else None
    alerts = {}
    for key in ALERT_KEYS:
        a = (result.get("alerts") or {}).get(key) or {}
        alerts[key] = a.get("count") if a.get("evaluated") else None
    seen = {b["key"]: b["devices"] for b in ((result.get("last_seen") or {}).get("buckets") or [])}
    versions: Dict[str, Dict[str, int]] = {}
    for plat, vs in (k.get("versions") or {}).items():
        top = sorted(vs.items(), key=lambda kv: -kv[1])[:MAX_VERSIONS]
        versions[plat] = dict(top)
    sc = result.get("scores") or {}
    raw = {"at": result.get("read_at"), "saved_at": (saved_at or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
           "source": result.get("source") or "live", "mode": result.get("mode"),
           "devices": k.get("devices"), "registered": k.get("registered"), "seen_24h": k.get("seen_24h"),
           "never_seen": k.get("never_seen"), "quarantined": k.get("quarantined", (k.get("registration_states") or {}).get("quarantined", 0)),
           "services": services, "alerts": alerts, "last_seen": seen, "versions": versions,
           "score_equal": sc.get("equal_weight"), "score_weighted": sc.get("device_weighted")}
    clean = clean_entry(raw)
    if clean is None:
        raise ValueError("This run's figures could not be kept.")
    return clean


# ── reading back: every field checked ─────────────────────────────────
def _count(v: Any) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)):
        return None
    n = int(v)
    return n if 0 <= n <= 10_000_000 else None


def _pct(v: Any) -> Optional[float]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or (isinstance(v, float) and not math.isfinite(v)):
        return None
    return round(float(v), 1) if 0.0 <= float(v) <= 100.0 else None


def _at(v: Any) -> Optional[str]:
    s = str(v or "")[:40]
    if not _AT.match(s):
        return None
    try:
        datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
    return s


def clean_entry(e: Any) -> Optional[Dict[str, Any]]:
    """A snapshot with only known fields of the right type, or None when it
    has no valid time or device count (untrusted: the file may be edited)."""
    if not isinstance(e, Mapping):
        return None
    at = _at(e.get("at"))
    devices = _count(e.get("devices"))
    if at is None or devices is None:
        return None
    services: Dict[str, Optional[Dict[str, Any]]] = {}
    for s in zf.SERVICES:
        v = (e.get("services") or {}).get(s) if isinstance(e.get("services"), Mapping) else None
        services[s] = ({"active": _count(v.get("active")), "inactive": _count(v.get("inactive")), "percent": _pct(v.get("percent"))}
                       if isinstance(v, Mapping) else None)
    al = e.get("alerts") if isinstance(e.get("alerts"), Mapping) else {}
    ls = e.get("last_seen") if isinstance(e.get("last_seen"), Mapping) else {}
    versions: Dict[str, Dict[str, int]] = {}
    vs = e.get("versions") if isinstance(e.get("versions"), Mapping) else {}
    for plat in PLATFORMS:
        pv = vs.get(plat)
        if not isinstance(pv, Mapping):
            continue
        kept = {}
        for ver, n in list(pv.items())[:MAX_VERSIONS]:
            c = _count(n)
            if isinstance(ver, str) and (_VERSION.match(ver) or ver == zf.NOT_REPORTED) and c is not None:
                kept[ver] = c
        if kept:
            versions[plat] = kept
    return {"at": at, "saved_at": _at(e.get("saved_at")), "source": e.get("source") if e.get("source") in SOURCES else "live",
            "mode": e.get("mode") if e.get("mode") in ("full", "devices") else "devices",
            "devices": devices, "registered": _count(e.get("registered")), "seen_24h": _count(e.get("seen_24h")),
            "never_seen": _count(e.get("never_seen")), "quarantined": _count(e.get("quarantined")),
            "services": services, "alerts": {k: _count(al.get(k)) for k in ALERT_KEYS},
            "last_seen": {k: _count(ls.get(k)) for k in BUCKET_KEYS}, "versions": versions,
            "score_equal": _pct(e.get("score_equal")), "score_weighted": _pct(e.get("score_weighted"))}


_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")


def _read_doc(p: str, strict: bool = False) -> Any:
    """The file's JSON (a sealed file, store_crypto, opened first), or None.
    `strict` (a writer): a sealed file whose key is not here raises
    StoreLocked instead of reading as no history, so it is never replaced."""
    try:
        if os.path.getsize(p) > MAX_FILE_BYTES * 4 // 3 + 256:
            return None
        with open(p, "r", encoding="utf-8") as f:
            text = store_crypto.open_text(f.read())
        if len(text) > MAX_FILE_BYTES:
            return None
        return json.loads(text)
    except store_crypto.StoreLocked:
        if strict:
            raise
        return None
    except (OSError, ValueError, RecursionError):
        return None


def _profiles(p: str, strict: bool = False) -> Dict[str, str]:
    """{tenant label: tenant profile id} for the labels a profile was named for."""
    data = _read_doc(p, strict)
    pr = data.get("profiles") if isinstance(data, dict) else None
    if not isinstance(pr, dict):
        return {}
    return {str(k)[:120]: str(v) for k, v in list(pr.items())[:HISTORY_TENANTS] if isinstance(v, str) and _PROFILE_ID.match(v)}


def profile_of(tenant: Any, path: Optional[str] = None) -> str:
    """The tenant profile a tenant label's history was kept for ("" when
    none was named: a history from before, or an upload with no profile)."""
    return _profiles(path or history_path()).get(tenant_key(tenant), "")


def _load_all(path: Optional[str] = None, strict: bool = False) -> Dict[str, List[Dict[str, Any]]]:
    p = path or history_path()
    data = _read_doc(p, strict)
    t = data.get("tenants") if isinstance(data, dict) else None
    if not isinstance(t, dict):
        return {}
    out: Dict[str, List[Dict[str, Any]]] = {}
    for k, v in list(t.items())[:HISTORY_TENANTS]:
        if isinstance(k, str) and isinstance(v, list):
            rows = [c for c in (clean_entry(x) for x in v[-HISTORY_KEEP:]) if c is not None]
            out[k[:120]] = sorted(rows, key=lambda r: r["at"])
    return out


def load(tenant: Any, path: Optional[str] = None) -> List[Dict[str, Any]]:
    """This tenant's kept snapshots, oldest first; a missing or unreadable file is no history."""
    return list(_load_all(path).get(tenant_key(tenant), []))


def record(tenant: Any, snap: Dict[str, Any], path: Optional[str] = None, *, profile_id: str = "") -> List[Dict[str, Any]]:
    """Add a snapshot for `tenant` (a record label, never a login) and
    return that tenant's history, oldest first. The same read saved twice
    (same time and source) is kept once. `profile_id`: the tenant profile
    the read was made with (team mode: who may see this history)."""
    clean = clean_entry(snap)
    if clean is None:
        raise ValueError("The snapshot is not valid.")
    key = tenant_key(tenant)
    p = path or history_path()
    with _LOCK:
        data = _load_all(p, strict=True)
        hist = [h for h in data.pop(key, []) if not (h["at"] == clean["at"] and h["source"] == clean["source"])]
        hist = sorted(hist + [clean], key=lambda r: r["at"])[-HISTORY_KEEP:]
        data[key] = hist
        while len(data) > HISTORY_TENANTS:
            data.pop(next(iter(data)))
        profs = {k: v for k, v in _profiles(p, strict=True).items() if k in data}
        if _PROFILE_ID.match(str(profile_id or "")):
            profs[key] = profile_id
        _write(p, {"version": 1, "tenants": data, "profiles": profs})
    return hist


def forget(tenant: Any, path: Optional[str] = None) -> int:
    """Remove this tenant's fleet history; the number of snapshots removed."""
    key = tenant_key(tenant)
    p = path or history_path()
    with _LOCK:
        data = _load_all(p, strict=True)
        gone = len(data.pop(key, []))
        if gone:
            _write(p, {"version": 1, "tenants": data, "profiles": {k: v for k, v in _profiles(p).items() if k in data}})
    return gone


def _write(p: str, doc: Dict[str, Any]) -> None:
    safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)))
    # A unique owner-only (0600) temporary file, then an atomic replace: the history names tenants.
    fd, tmp = tempfile.mkstemp(prefix="." + os.path.basename(p) + ".", suffix=".tmp", dir=os.path.dirname(os.path.abspath(p)))
    try:
        try:
            os.fchmod(fd, 0o600)
        except (AttributeError, OSError):   # Windows: the folder's own access rules apply
            pass
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(store_crypto.seal_text(json.dumps(doc, indent=1)))   # sealed when store encryption is on
        for attempt in range(20):
            try:
                os.replace(tmp, p)
                break
            except PermissionError:
                if attempt == 19:
                    raise
                time.sleep(0.05)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


# ── trend and comparison ──────────────────────────────────────────────
def _value(e: Dict[str, Any], key: str) -> Optional[float]:
    if key in zf.SERVICES:
        s = (e.get("services") or {}).get(key)
        return s.get("percent") if s else None
    return e.get(key)


def _delta(a: Optional[float], b: Optional[float]) -> Optional[float]:
    if a is None or b is None:
        return None
    d = b - a
    return round(d, 1) if isinstance(d, float) else d


def trend(history: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Each snapshot's figures and their change since the snapshot before
    it (None where either side is unknown), oldest first; plus the alert
    counts the same way."""
    rows = []
    prev: Optional[Dict[str, Any]] = None
    for i, e in enumerate(history):
        vals = {k: _value(e, k) for k, _ in TREND_FIELDS}
        al = dict(e.get("alerts") or {})
        rows.append({"index": i, "at": e["at"], "source": e["source"], "values": vals, "alerts": al,
                     "delta": {k: (_delta(_value(prev, k), v) if prev else None) for k, v in vals.items()},
                     "alert_delta": {k: (_delta((prev.get("alerts") or {}).get(k), v) if prev else None) for k, v in al.items()}})
        prev = e
    return {"fields": [{"key": k, "label": lab} for k, lab in TREND_FIELDS],
            "alerts": [{"key": k, "label": zf.ALERTS[k]["label"]} for k in ALERT_KEYS], "rows": rows}


def compare(history: List[Dict[str, Any]], a: int, b: int) -> Dict[str, Any]:
    """Two kept snapshots side by side: every figure, alert, last-seen
    bucket and version count with its change from A to B. Raises
    ValueError for an index outside the history."""
    n = len(history)
    if not (isinstance(a, int) and isinstance(b, int) and 0 <= a < n and 0 <= b < n):
        raise ValueError("Choose two snapshots from this tenant's history.")
    ea, eb = history[a], history[b]
    rows = [{"group": "Fleet", "item": lab, "a": _value(ea, k), "b": _value(eb, k), "delta": _delta(_value(ea, k), _value(eb, k))}
            for k, lab in TREND_FIELDS]
    for k in ALERT_KEYS:
        va, vb = (ea.get("alerts") or {}).get(k), (eb.get("alerts") or {}).get(k)
        rows.append({"group": "Alerts", "item": zf.ALERTS[k]["label"], "a": va, "b": vb, "delta": _delta(va, vb)})
    labels = {bk[0]: bk[1] for bk in zf.LAST_SEEN_BUCKETS}
    labels["never"] = "Never seen"
    for k in BUCKET_KEYS:
        va, vb = (ea.get("last_seen") or {}).get(k), (eb.get("last_seen") or {}).get(k)
        rows.append({"group": "Last seen", "item": labels[k], "a": va, "b": vb, "delta": _delta(va, vb)})
    for plat in PLATFORMS:
        pa, pb = (ea.get("versions") or {}).get(plat) or {}, (eb.get("versions") or {}).get(plat) or {}
        for ver in sorted(set(pa) | set(pb), key=lambda v: zf._version_key(v)):
            va, vb = pa.get(ver), pb.get(ver)
            rows.append({"group": f"{plat} versions", "item": ver, "a": va, "b": vb,
                         "delta": _delta(va or 0, vb or 0), "change": "new" if va is None else "gone" if vb is None else ""})
    return {"a": {"index": a, "at": ea["at"], "source": ea["source"]}, "b": {"index": b, "at": eb["at"], "source": eb["source"]},
            "rows": rows,
            "note": "Version counts list the most common versions each snapshot kept; a version missing on one side was not among them."}
