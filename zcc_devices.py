"""Client Connector: one device's details, and the disable-reason report as counts.

device_details(sdk, udid)
    One enrolled device's service state, read when the operator types its
    device id (UDID) on the Client Connector fleet page (only when ZCC is
    ticked on the Scope page). Only technical state is returned, each with
    a plain label: which services are on and healthy (ZIA, ZPA, ZDX,
    Endpoint DLP), when each last checked in, the Client Connector and
    tunnel versions, strict enforcement, anti-tampering and device trust.
    The serial number and other identifiers are hidden; the device's
    one-time passwords (deviceOtpArray) are never read into the answer, not
    even as a count.

disable_reasons(raw_client)
    The disable-reason report (who switched Client Connector off, and why)
    turned into counts: per reason, device type and service, how many
    times it was switched off and by how many people. No user name, email
    or device leaves this module (personal data is counted, not listed).
    `disable_reasons_csv` writes the counts as a CSV with every cell made
    safe for spreadsheets (csv_safe).

API calls (zscaler-sdk-python 1.11.3, zscaler/zcc/devices.py), verified there:

    devices.get_device_details      GET /zcc/papi/public/v1/getDeviceDetails (udid)
    devices.download_disable_reasons
                                    GET /zcc/papi/public/v1/downloadDisableReasons (CSV; the SDK writes it to a
                                    file, so the app reads the same path as text through its own client)

Assumed: the CSV's columns are named as Client Connector's export names them
("User", "Device type", "Disable reason", "Service"); a missing column reads
as "not given". Without a date range the API answers its default period.
"""
from __future__ import annotations

import csv
import io
import re
from typing import Any, Dict, List, Optional, Tuple

ASSUMED = [
    "The disable-reason CSV names its columns User, Device type, Disable reason and Service (the SDK checks only that it begins \"User\",\"Device type\").",
    "Without a date range, downloadDisableReasons answers its default period.",
]

UDID_RE = re.compile(r"^[A-Za-z0-9_.:{}\-]{1,128}$")
MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_ROWS = 100_000
HIDDEN = "hidden"

# (wire field, label, kind) — the only fields a device's details answer shows.
FIELDS: List[Tuple[str, str, str]] = [
    ("ziaEnabled", "Internet security (ZIA) on", "flag"), ("ziaHealth", "Internet security (ZIA) health", "text"),
    ("zpaEnabled", "Private access (ZPA) on", "flag"), ("zpaHealth", "Private access (ZPA) health", "text"),
    ("zpaLastSeenTime", "Private access last checked in", "text"),
    ("zdxEnabled", "Digital experience (ZDX) on", "flag"), ("zdxHealth", "Digital experience (ZDX) health", "text"),
    ("zdxLastSeenTime", "Digital experience last checked in", "text"),
    ("zdpEnabled", "Endpoint DLP on", "flag"), ("zdpHealth", "Endpoint DLP health", "text"), ("zdpVersion", "Endpoint DLP version", "text"),
    ("zdpLastSeenTime", "Endpoint DLP last checked in", "text"),
    ("zdEnabled", "Deception on", "flag"), ("zdHealth", "Deception health", "text"),
    ("zccTunnelVersion", "Tunnel", "text"), ("expectedZCCVersion", "Client Connector version it should run", "text"),
    ("zccUpgradeStatus", "Upgrade status", "text"), ("strictEnforcement", "Strict enforcement", "flag"),
    ("antiTamperingStatus", "Anti-tampering", "text"), ("deviceTrust", "Device trust level", "text"),
    ("vdi", "Virtual desktop", "flag"), ("zccLoggedInUserType", "Signed-in user type", "text"),
    ("internal_model", "Device model", "text"),
]
HIDDEN_FIELDS = (("serialNumber", "Serial number"), ("externalDeviceId", "External device id"))


class DeviceError(ValueError):
    """A request the page can fix (the route's 400)."""


def _text(v: Any, n: int = 80) -> str:
    s = "" if v is None else str(v)
    return "".join(ch for ch in s if ch.isprintable())[:n]


def _flag(v: Any) -> Optional[bool]:
    if isinstance(v, bool):
        return v
    s = str(v).strip().lower()
    if s in ("1", "true", "on", "yes", "enabled"):
        return True
    if s in ("0", "false", "off", "no", "disabled"):
        return False
    return None


def _wire(resp: Any) -> Any:
    fn = getattr(resp, "get_body", None)
    try:
        return fn() if callable(fn) else None
    except Exception:  # noqa: BLE001
        return None


def device_details(sdk: Any, udid: str) -> Dict[str, Any]:
    """The technical state of one device (see the module docstring)."""
    udid = str(udid or "").strip()
    if not UDID_RE.match(udid):
        raise DeviceError("Type the device id (UDID) as the Client Connector Portal shows it: letters, digits and . _ : - { } only.")
    z = getattr(sdk, "zcc", None)
    if z is None:
        raise DeviceError("This sign-in has no Client Connector API. Sign in with a OneAPI API client.")
    try:
        ret = z.devices.get_device_details(query_params={"udid": udid})
    except Exception as e:  # noqa: BLE001
        return {"found": False, "rows": [], "error": f"The device could not be read ({type(e).__name__})."}
    data, resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        import pack_ops
        text = pack_ops.describe_error(err)[:200]
        if "404" in text or "not found" in text.lower():
            return {"found": False, "rows": [], "error": "No enrolled device has that id."}
        return {"found": False, "rows": [], "error": f"The device could not be read: {text}"}
    body = _wire(resp)
    if not isinstance(body, dict):
        fn = getattr(data, "as_dict", None)
        body = fn() if callable(fn) else {}
    rows = []
    for key, label, kind in FIELDS:
        if key not in body or body.get(key) in (None, ""):
            continue
        v = body.get(key)
        if kind == "flag":
            f = _flag(v)
            rows.append({"label": label, "value": "on" if f else ("off" if f is False else _text(v, 20)), "warn": f is False and key in ("strictEnforcement", "ziaEnabled")})
        else:
            t = _text(v)
            low = t.lower()
            rows.append({"label": label, "value": t, "warn": low in ("off", "inactive", "error", "low", "unhealthy", "disabled")})
    for key, label in HIDDEN_FIELDS:
        if body.get(key) not in (None, ""):
            rows.append({"label": label, "value": HIDDEN, "warn": False})
    warn = [r["label"] for r in rows if r["warn"]]
    return {"found": bool(rows), "rows": rows, "error": None,
            "summary": ("Needs a look: " + ", ".join(warn) + ".") if warn else "Every service the device reports is on and healthy.",
            "note": "Identifiers are hidden and the device's one-time passwords are never read into this answer."}


def _col(header: List[str], *names: str) -> Optional[int]:
    low = [h.strip().lower() for h in header]
    for n in names:
        if n in low:
            return low.index(n)
    return None


def parse_disable_reasons(text: Any) -> Dict[str, Any]:
    """Counts from the disable-reason CSV: [{reason, device_type, service, times, people}], newest columns tolerated."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    if not isinstance(text, str):
        raise DeviceError("The disable-reason report was not a CSV.")
    if len(text.encode("utf-8", "ignore")) > MAX_CSV_BYTES:
        raise DeviceError(f"The disable-reason report is larger than {MAX_CSV_BYTES // (1024 * 1024)} MB; it was not read.")
    reader = csv.reader(io.StringIO(text.lstrip("﻿")))
    try:
        header = next(reader)
    except StopIteration:
        return {"rows": [], "events": 0, "people": 0, "skipped": 0}
    except csv.Error as e:
        raise DeviceError(f"The disable-reason report could not be read as CSV ({e}).")
    iu = _col(header, "user", "user name", "username")
    it = _col(header, "device type", "platform", "os")
    ir = _col(header, "disable reason", "reason")
    isv = _col(header, "service", "service type")
    if ir is None:
        raise DeviceError("The disable-reason report has no Disable reason column, so it cannot be counted.")
    groups: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    people_all = set()
    events = skipped = 0
    try:
        for n, row in enumerate(reader):
            if n >= MAX_ROWS:
                skipped += 1
                continue
            if not row or ir >= len(row):
                skipped += 1
                continue
            cell = lambda i: _text(row[i], 120).strip() if i is not None and i < len(row) else ""  # noqa: E731
            key = (cell(ir) or "not given", cell(it) or "not given", cell(isv) or "not given")
            g = groups.setdefault(key, {"times": 0, "people": set()})
            g["times"] += 1
            who = cell(iu).lower()
            if who:
                g["people"].add(who)
                people_all.add(who)
            events += 1
    except csv.Error as e:
        raise DeviceError(f"The disable-reason report could not be read as CSV ({e}).")
    rows = [{"reason": k[0], "device_type": k[1], "service": k[2], "times": v["times"], "people": len(v["people"])}
            for k, v in groups.items()]
    rows.sort(key=lambda r: (-r["times"], r["reason"].lower(), r["device_type"], r["service"]))
    return {"rows": rows, "events": events, "people": len(people_all), "skipped": skipped}


def disable_reasons(raw_client: Any) -> Dict[str, Any]:
    """Read the report (read-only) and count it."""
    getter = getattr(raw_client, "get_text", None)
    if not callable(getter):
        raise DeviceError("This sign-in cannot read the Client Connector disable-reason report.")
    text, status = getter("/zcc/downloadDisableReasons", None, accept="*/*", max_bytes=MAX_CSV_BYTES)
    if status not in (200, 204):
        if status in (401, 403):
            raise DeviceError("The API client is not permitted to read the disable-reason report (Client Connector Portal role).")
        raise DeviceError(f"The disable-reason report could not be read (HTTP {status}).")
    return parse_disable_reasons(text or "")


def disable_reasons_csv(counts: Dict[str, Any]) -> str:
    """The counts as CSV, every cell made safe for spreadsheets."""
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.writer(buf)
    w.writerow(["Disable reason", "Device type", "Service", "Times switched off", "People"])
    for r in counts.get("rows") or []:
        w.writerow([r["reason"], r["device_type"], r["service"], r["times"], r["people"]])
    return buf.getvalue()
