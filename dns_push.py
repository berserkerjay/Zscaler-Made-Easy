"""Opt-in push of the generated DNS forwarder file to several resolvers.

The file is the one dns_forward_zones builds from a finished Client Connector
fleet read (Unbound or BIND forward zones). The operator stages one build here;
this module then sends the staged text, unchanged, to every chosen target
through report_delivery, so the same rules hold: off by default, the host must
be in the delivery allowlist, passwords only in the operating system's
credential store, SSH host keys already known. A resolver that cannot be
reached is reported for that host and never stops the others (high availability).

A scheduled push (cron-style) only re-sends the staged file; it never reads a
tenant and never reloads or changes the resolver (the operator does that).
"""
from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import report_delivery as rd
import safe_files

STORE_FILE = "dns_push.json"
FILES = {"unbound": "zcc_client_zones.conf", "bind_forward": "zcc_client_zones.conf"}
DEFAULTS: Dict[str, Any] = {"enabled": False, "targets": [], "file": "unbound", "cron": ""}
MAX_BYTES = 8 * 1024 * 1024
_LOCK = threading.RLock()


def store_path() -> str:
    override = os.environ.get("DLP_CHECK_DNS_PUSH")
    if override:
        return override
    from zscaler_update_check import data_dir
    return os.path.join(data_dir(), STORE_FILE)


def _read() -> Dict[str, Any]:
    import store_crypto
    p = store_path()
    try:
        if os.path.islink(p) or os.path.getsize(p) > MAX_BYTES + 4096:
            return {}
        with open(p, "r", encoding="utf-8") as f:
            d = safe_files.strict_json_loads(store_crypto.open_text(f.read()))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(d: Dict[str, Any]) -> None:
    import store_crypto
    safe_files.write_private_atomic(store_path(), store_crypto.seal_text(json.dumps(d)))


def get_state() -> Dict[str, Any]:
    with _LOCK:
        d = _read()
    s = dict(DEFAULTS)
    s.update({k: d.get("settings", {}).get(k, v) for k, v in DEFAULTS.items()})
    st = d.get("staged") or {}
    return {"settings": s, "staged": {"file": st.get("file"), "at": st.get("at"), "bytes": len(st.get("text") or "")} if st else None,
            "last_push": d.get("last_push")}


def save_settings(fields: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(fields, dict) or set(fields) - set(DEFAULTS):
        raise rd.DeliveryError("Unknown setting.")
    cur = get_state()["settings"]
    known = rd.get_settings()["targets"]
    if "enabled" in fields:
        cur["enabled"] = bool(fields["enabled"])
    if "targets" in fields:
        t = fields["targets"]
        if not isinstance(t, list) or len(t) > 8 or any(x not in known for x in t):
            raise rd.DeliveryError("Pick up to 8 delivery targets that are defined.")
        cur["targets"] = list(dict.fromkeys(t))
    if "file" in fields:
        if fields["file"] not in FILES:
            raise rd.DeliveryError("The file is unbound or bind_forward.")
        cur["file"] = fields["file"]
    if "cron" in fields:
        cur["cron"] = rd.check_cron(fields["cron"])
    with _LOCK:
        d = _read()
        d["settings"] = cur
        _write(d)
    return get_state()


def stage(build_out: Dict[str, Any], which: str) -> Dict[str, Any]:
    """Keep one built file (dns_forward_zones.build()["files"][which]) to be pushed."""
    if which not in FILES:
        raise rd.DeliveryError("The file is unbound or bind_forward.")
    text = str((build_out.get("files") or {}).get(which) or "")
    if not text or len(text.encode("utf-8")) > MAX_BYTES:
        raise rd.DeliveryError("There is no usable file to stage.")
    with _LOCK:
        d = _read()
        d["staged"] = {"file": which, "text": text, "at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        _write(d)
    return get_state()


def push(*, trigger: str = "manual") -> List[Dict[str, Any]]:
    """Send the staged file to every chosen target; one result per host."""
    with _LOCK:
        d = _read()
    s = dict(DEFAULTS)
    s.update(d.get("settings") or {})
    if not s["enabled"]:
        raise rd.DeliveryError("DNS push is off.")
    st = d.get("staged")
    if not st or not st.get("text"):
        raise rd.DeliveryError("Nothing is staged to push.")
    if not s["targets"]:
        raise rd.DeliveryError("No resolver targets are chosen.")
    res = rd.deliver_many(s["targets"], FILES[st["file"]], st["text"].encode("utf-8"), trigger=f"dns-{trigger}")
    with _LOCK:
        d = _read()
        d["last_push"] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "results": res}
        _write(d)
    return res


def tick(now: Optional[datetime] = None) -> Optional[List[Dict[str, Any]]]:
    s = get_state()["settings"]
    if not (s["enabled"] and s["cron"] and rd.get_settings()["enabled"]):
        return None
    if not rd.cron_gate("dns_last_tick", s["cron"], now):
        return None
    try:
        return push(trigger="schedule")
    except rd.DeliveryError:
        return None
