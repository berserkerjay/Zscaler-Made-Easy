"""Client Connector fleet from the portal's CSV exports (offline source).

The fleet page normally reads the enrolled devices through the API, which
needs the Client Connector device permission. Without it, an operator can
export the devices from the Client Connector Portal (Enrolled Devices,
Export: "Device Details" and "Service Status") and import the two files
here. Nothing contacts a tenant; the analysis is the same one a read gets
(zcc_fleet.analyze), with no configuration (no profile checks).

The files are untrusted input:
  * size: each upload is capped before and after decoding, a gzip upload is
    inflated through a bounded read (never all at once), and the request
    body is capped by the server as every request is;
  * shape: rows, columns and each kept cell are capped; the CSV module
    parses it (no eval, no formula); a NUL byte or an undecodable file is
    refused; the header row is found by its column names in the first
    lines, nothing else;
  * names: a file name is used only to read the export time it carries
    (device_export_YYYY_MM_DD-HH-MM-SS.csv, the portal's naming), never as
    a path, and is never echoed back;
  * output: every value is a string or a number; the page escapes it, the
    exports go through csv_safe / xlsx_writer (formula-looking text is
    neutralised) and pdf_writer (WinAnsi text only).

The portal's column names are not documented in zscaler-sdk-python (it
documents only that its CSV downloads start with "User","Device type");
the names this reads are assumed from the portal's exports and matched
loosely by zcc_fleet.portal_columns / service_columns, so an unmatched
column is simply not read and the page says what was used.
"""
from __future__ import annotations

import base64
import binascii
import csv
import gzip
import io
import re
import zlib
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import zcc_fleet as zf

MAX_FILE_BYTES = 48 * 1024 * 1024      # one decoded CSV file
MAX_ENCODED_CHARS = MAX_FILE_BYTES * 4 // 3 + 16
MAX_ROWS = zf.MAX_CSV_ROWS
MAX_COLUMNS = 300
HEADER_SCAN_ROWS = 10                  # the header row is looked for in the first lines only
PAIR_HOURS = 12                        # two exports further apart than this are not one snapshot
MAX_LABEL = 80
DEFAULT_LABEL = "Imported CSV"

_FILE_TIME = re.compile(r"(?<!\d)(\d{4})_(\d{2})_(\d{2})-(\d{2})-(\d{2})-(\d{2})(?!\d)")
_FILE_DAY = re.compile(r"(?<!\d)(\d{4})_(\d{2})_(\d{2})(?!\d)")
_PAREN = re.compile(r"\s*\([^)]*\)")


class ImportRefused(ValueError):
    """The upload cannot be used; the message says why in plain words."""


def clean_label(raw: Any) -> str:
    """The name the import is kept under in the fleet history: letters,
    digits, spaces and . _ - ( ) only, at most MAX_LABEL characters; an
    e-mail address is not kept. Empty is DEFAULT_LABEL."""
    s = zf._EMAIL.sub("", str(raw or ""))
    s = re.sub(r"[^\w .()-]+", "", s, flags=re.UNICODE)
    s = re.sub(r"\s+", " ", s).strip()[:MAX_LABEL].strip()
    return s or DEFAULT_LABEL


def decode_upload(f: Any, what: str) -> str:
    """One uploaded file ({name, content, encoding}) as text. encoding is
    None or "text" (content is the text), "base64" (the raw bytes) or
    "gzip-base64" (the bytes gzip-compressed by the browser, then base64).
    Bytes are UTF-16 with a BOM, else UTF-8 (BOM allowed), else Windows-1252."""
    if not isinstance(f, dict):
        raise ImportRefused(f"The {what} file was not sent as a file.")
    content, enc = f.get("content"), str(f.get("encoding") or "text").strip().lower()
    if not isinstance(content, str) or not content:
        raise ImportRefused(f"The {what} file is empty.")
    if enc in ("", "text", "utf-8", "utf8"):
        if len(content) > MAX_FILE_BYTES:
            raise ImportRefused(f"The {what} file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB; it was not read.")
        text = content
    elif enc in ("base64", "gzip-base64"):
        if len(content) > MAX_ENCODED_CHARS:
            raise ImportRefused(f"The {what} file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB; it was not read.")
        try:
            raw = base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError):
            raise ImportRefused(f"The {what} file did not arrive intact (it is not valid base64).")
        if enc == "gzip-base64":
            try:
                with gzip.GzipFile(fileobj=io.BytesIO(raw)) as g:
                    raw = g.read(MAX_FILE_BYTES + 1)   # bounded: a small upload cannot inflate past the cap
            except (OSError, EOFError, zlib.error):
                raise ImportRefused(f"The {what} file did not arrive intact (the compressed upload is damaged).")
        if len(raw) > MAX_FILE_BYTES:
            raise ImportRefused(f"The {what} file is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB; it was not read.")
        text = _bytes_text(raw)
    else:
        raise ImportRefused("encoding must be text, base64 or gzip-base64.")
    if "\x00" in text:
        raise ImportRefused(f"The {what} file is not a text CSV file (it holds NUL bytes); export it again from the portal as CSV.")
    return text.lstrip("﻿")


def _bytes_text(raw: bytes) -> str:
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return raw.decode("utf-16")
        except UnicodeDecodeError:
            raise ImportRefused("The file starts like UTF-16 text but is not; export it again from the portal as CSV.")
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252", errors="replace")


def file_time(name: Any) -> Optional[datetime]:
    """The export time the portal puts in its file names
    (device_export_2026_04_09-05-57-32.csv), as UTC; a date alone is
    midnight. None when the name carries none or an impossible one."""
    base = re.split(r"[\\/]", str(name or ""))[-1][:200]
    m = _FILE_TIME.search(base)
    try:
        if m:
            return datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
        m = _FILE_DAY.search(base)
        if m:
            return datetime(*(int(x) for x in m.groups()), tzinfo=timezone.utc)
    except ValueError:
        return None
    return None


def _recognised(cols: Dict[str, Optional[str]]) -> int:
    keys = ("user", "udid", "hostname", "version", "registration", "last_seen", "policy") + zf.SERVICES
    return sum(1 for k in keys if cols.get(k))


# A cell longer than this is refused as malformed. The csv module's own field
# limit (131,072 by default) is process-wide and another module may raise it
# (audit_timeline does), so the cap is checked here, independent of it.
MAX_RAW_CELL = 131072


def read_table(text: str, what: str) -> Tuple[List[str], Dict[str, Optional[str]], List[Dict[str, str]]]:
    """(headers, columns used, rows) of one export. The header row is the
    first of the first HEADER_SCAN_ROWS lines in which at least two known
    columns are named. Rows keep only the known columns, each cell cut to
    zcc_fleet.MAX_CELL_CHARS."""
    reader = csv.reader(io.StringIO(text))
    headers: List[str] = []
    cols: Dict[str, Optional[str]] = {}
    try:
        for _ in range(HEADER_SCAN_ROWS):
            row = next(reader, None)
            if row is None:
                break
            if any(len(x) > MAX_RAW_CELL for x in row):
                raise csv.Error("field larger than the import's cell cap")
            if len(row) > MAX_COLUMNS:
                raise ImportRefused(f"The {what} file has more than {MAX_COLUMNS} columns; it is not a Client Connector export.")
            c = zf.service_columns(row)
            if _recognised(c) >= 2:
                headers, cols = row, c
                break
    except csv.Error:
        raise ImportRefused(f"The {what} file could not be read as CSV.")
    if not headers:
        raise ImportRefused(f"The {what} file has no header row this app recognises (it looks for columns such as User, Hostname, "
                            "UDID, Zscaler Client Connector Version and Registration State in the first lines).")
    idx = {k: headers.index(v) for k, v in cols.items() if v is not None}
    rows: List[Dict[str, str]] = []
    try:
        for r in reader:
            if not r or not any(x.strip() for x in r):
                continue
            if any(len(x) > MAX_RAW_CELL for x in r):
                raise csv.Error("field larger than the import's cell cap")
            if len(rows) >= MAX_ROWS:
                raise ImportRefused(f"The {what} file has more than {MAX_ROWS} rows; it was not read.")
            rows.append({k: (r[i].strip()[:zf.MAX_CELL_CHARS] if i < len(r) else "") for k, i in idx.items()})
    except csv.Error:
        raise ImportRefused(f"The {what} file could not be read past a malformed line (a cell may be too long or a quote unclosed).")
    return headers, cols, rows


def _version(v: str) -> str:
    """'4.7.2.5 (64-bit)' -> '4.7.2.5': the bracketed build note would read as a version part."""
    return _PAREN.sub("", v or "").strip()[:40]


def _device(r: Dict[str, str]) -> Dict[str, Any]:
    """A CSV row in the shape the API's device records have (the keys
    zcc_fleet.normalize_devices reads)."""
    plat = r.get("platform") or ""
    return {"user": r.get("user") or "", "machineHostname": r.get("hostname") or "", "type": plat, "osType": plat,
            "osVersion": r.get("os_version") or "", "agentVersion": _version(r.get("version") or ""),
            "policyName": r.get("policy") or "", "registrationState": r.get("registration") or "",
            "last_seen_time": r.get("last_seen") or "", "udid": r.get("udid") or "", "tunnelVersion": r.get("tunnel") or ""}


def _key(r: Dict[str, str]) -> Tuple[str, str, str]:
    return ((r.get("udid") or "").strip().lower(), (r.get("user") or "").strip().lower(), (r.get("hostname") or "").strip().lower())


def build_telemetry(device_text: Optional[str], service_text: Optional[str], *, device_name: Any = "", service_name: Any = "",
                    now: Optional[datetime] = None) -> Dict[str, Any]:
    """What zcc_fleet.analyze takes as telemetry, from one or both exports,
    plus the time the figures describe and the notes the page shows.
    Raises ImportRefused."""
    if not device_text and not service_text:
        raise ImportRefused("Choose the Device Details export, the Service Status export, or both.")
    notes: List[str] = []
    files: List[Dict[str, Any]] = []
    dev_rows: List[Dict[str, str]] = []
    svc_rows: List[Dict[str, str]] = []
    dev_cols: Dict[str, Optional[str]] = {}
    svc_cols: Dict[str, Optional[str]] = {}
    if device_text:
        _, dev_cols, dev_rows = read_table(device_text, "Device Details")
        files.append({"kind": "Device details", "rows": len(dev_rows), "time": file_time(device_name),
                      "columns": {k: v for k, v in dev_cols.items() if v}})
    if service_text:
        _, svc_cols, svc_rows = read_table(service_text, "Service Status")
        if not any(svc_cols.get(s) for s in zf.SERVICES):
            raise ImportRefused("The Service Status file has no ZIA, ZPA or ZDX column this app recognises.")
        files.append({"kind": "Service status", "rows": len(svc_rows), "time": file_time(service_name),
                      "columns": {k: v for k, v in svc_cols.items() if v}})
    elif any(dev_cols.get(s) for s in zf.SERVICES):
        svc_rows, svc_cols = dev_rows, dev_cols   # a device export that carries the service columns itself
        notes.append("The service status was read from the Device Details file's own ZIA, ZPA and ZDX columns.")
    base_rows = dev_rows if device_text else svc_rows
    base_cols = dev_cols if device_text else svc_cols
    if not base_rows:
        raise ImportRefused("The file has a header row but no device rows.")
    if not any(base_cols.get(k) for k in ("udid", "hostname", "user")):
        raise ImportRefused("The file names no device (no UDID, Hostname or User column), so devices cannot be counted.")
    # Fill what the device export lacks from the service export (matched by UDID, else user and host name).
    if device_text and svc_rows is not dev_rows:
        by_udid = {k[0]: r for r in svc_rows for k in [_key(r)] if k[0]}
        by_uh = {(k[1], k[2]): r for r in svc_rows for k in [_key(r)] if k[1] and k[2]}
        for r in dev_rows:
            k = _key(r)
            s = by_udid.get(k[0]) if k[0] else None
            s = s or by_uh.get((k[1], k[2]))
            if s:
                for f in ("last_seen", "version", "registration", "platform", "policy", "os_version"):
                    if not r.get(f) and s.get(f):
                        r[f] = s[f]
    if not any(r.get("registration") for r in base_rows):
        for r in base_rows:
            r["registration"] = "Registered"
        notes.append("No registration state was found in the files, so every device listed is counted as registered "
                     "(the Enrolled Devices exports list enrolled devices).")
    devices = [_device(r) for r in base_rows]
    # The time the figures describe: the export time in a file name, else the newest last-seen time, else now.
    t_dev, t_svc = file_time(device_name) if device_text else None, file_time(service_name) if service_text else None
    as_of, how = None, ""
    if t_dev or t_svc:
        as_of = t_dev or t_svc
        how = "the export time in the file name"
    else:
        seen = [t for t in (zf.parse_time(r.get("last_seen")) for r in base_rows) if t]
        if seen:
            as_of, how = max(seen), "the newest last-seen time in the file (the file names carry no export time)"
    if as_of is None:
        as_of, how = (now or datetime.now(timezone.utc)), "the time of the import (neither the file names nor the rows carry a time)"
    if t_dev and t_svc and abs(t_dev - t_svc) > timedelta(hours=PAIR_HOURS):
        gap = abs(t_dev - t_svc).total_seconds() / 3600.0
        notes.append(f"The two files were exported {gap:.0f} hours apart (more than {PAIR_HOURS}): the service status may not "
                     "describe the same devices. Export both again at the same time for a true snapshot.")
    service: Dict[str, Any] = {"status": "unavailable", "reason": "", "rows": [], "columns": {}}
    if svc_rows:
        service = {"status": "read", "reason": "", "rows": svc_rows, "columns": {k: svc_cols.get(k) for k in zf.SERVICES}}
    else:
        service["reason"] = "No Service Status export was imported, so ZIA, ZPA and ZDX activity is unknown."
    return {"telemetry": {"status": "read" if svc_rows else "partial", "reason": service["reason"], "devices": devices, "service": service},
            "as_of": as_of, "as_of_how": how, "notes": notes,
            "files": [dict(f, time=f["time"].isoformat() if f["time"] else None) for f in files]}


def run_import(device_file: Optional[Dict[str, Any]], service_file: Optional[Dict[str, Any]], *, label: Any = "",
               site: Optional[Dict[str, Any]] = None, now: Optional[datetime] = None) -> Dict[str, Any]:
    """The fleet result for imported exports: zcc_fleet.analyze on what the
    files hold, no configuration, marked as an import. Raises ImportRefused."""
    site_rule = zf.site_rule(site or {"mode": "none"})
    dev_text = decode_upload(device_file, "Device Details") if device_file else None
    svc_text = decode_upload(service_file, "Service Status") if service_file else None
    built = build_telemetry(dev_text, svc_text, device_name=(device_file or {}).get("name"),
                            service_name=(service_file or {}).get("name"), now=now)
    cfg = {"read_status": {}, "app_profiles": [], "forwarding_profiles": [], "raw_app_profiles": [], "raw_pac_files": [], "errors": []}
    out = zf.analyze(cfg, built["telemetry"], now=built["as_of"], site=site_rule)
    devs_word = f"{out['devices_total']} device record{'s' if out['devices_total'] != 1 else ''}"
    out["banner"] = (f"Imported from the Client Connector Portal's CSV exports ({devs_word}); nothing was read from a tenant. "
                     f"The figures describe {built['as_of'].strftime('%Y-%m-%d %H:%M')} UTC, from {built['as_of_how']}. "
                     "No configuration was read, so the profile checks, the PAC comparison and the forwarding profiles are empty. "
                     + ("" if out["mode"] == "full" else built["telemetry"]["service"]["reason"])).strip()
    out["source"] = "import"
    out["unmatched_profiles"] = []   # no app profile was read, so every name would be "not found": not a finding here
    out["import"] = {"files": built["files"], "notes": built["notes"], "as_of_how": built["as_of_how"]}
    out["profile_settings"] = {}
    out["status"] = "done"
    out["tenant_label"] = clean_label(label)
    return out
