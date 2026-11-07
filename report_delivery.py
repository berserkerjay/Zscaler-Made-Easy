"""Opt-in delivery of saved reports to a network share or a remote host.

Off by default. Nothing here runs unless the operator turned it on, named the
host in the allowlist and stored the credential in the operating system's
credential store. What is sent is only an existing, read-only report export
(the CSV of a saved traffic-log report); nothing is read from a tenant and
nothing on a tenant is written.

* transports: ``sftp``, ``scp`` and ``ssh`` (the file is piped to a remote
  ``cat``) through paramiko, and ``smb`` through smbprotocol. Both libraries
  are optional and imported only when a delivery is made; without them the
  feature says so and does nothing else.
* host allowlist: a target's host must equal an entry of ``allowed_hosts``
  (exact name or address, no wildcard). Anything else is refused before any
  connection is opened.
* credentials: the OS credential store only (``keyring``), never a file, a
  setting, a log line, an audit record or a result. With no store the feature
  refuses rather than falling back to a file.
* remote names: the remote folder is fixed in the target, the file name is
  rebuilt from ``[A-Za-z0-9._-]``; no path part can come from a report.
* SSH host keys are checked against the operator's known_hosts; an unknown
  key is refused (never auto-added).
* schedule: a five-field cron expression; a tick delivers the newest saved
  report when the minute matches, once per minute. Scheduled work only reads
  and sends the report; it never changes a tenant.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

import safe_files

STORE_FILE = "report_delivery.json"
KEYRING_SERVICE = "DLP-Check report delivery"
TRANSPORTS = ("sftp", "scp", "ssh", "smb")
DEFAULT_PORTS = {"sftp": 22, "scp": 22, "ssh": 22, "smb": 445}
MAX_TARGETS = 20
MAX_BYTES = 30 * 1024 * 1024
_HOST = re.compile(r"\A(?=.{1,253}\Z)[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?\Z|\A[0-9A-Fa-f:]{2,45}\Z")
_ID = re.compile(r"\A[a-z0-9][a-z0-9_-]{0,31}\Z")
_USER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._@\\$-]{0,63}\Z")
_DIR = re.compile(r"\A[A-Za-z0-9._/ \\-]{0,200}\Z")
_FNAME_BAD = re.compile(r"[^A-Za-z0-9._-]")
_LOCK = threading.RLock()
DEFAULTS: Dict[str, Any] = {"enabled": False, "allowed_hosts": [], "targets": {}, "schedule": {"enabled": False, "cron": "", "target": ""},
                            "known_hosts": ""}


class DeliveryError(ValueError):
    """A setting or send this feature refuses; the message says why and never holds a credential."""


def store_path() -> str:
    override = os.environ.get("DLP_CHECK_REPORT_DELIVERY")
    if override:
        return override
    from zscaler_update_check import data_dir
    return os.path.join(data_dir(), STORE_FILE)


def _read() -> Dict[str, Any]:
    p = store_path()
    try:
        if os.path.islink(p) or os.path.getsize(p) > 256 * 1024:
            return {}
        with open(p, "r", encoding="utf-8") as f:
            d = safe_files.strict_json_loads(f.read())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _write(d: Dict[str, Any]) -> None:
    safe_files.write_private_atomic(store_path(), json.dumps(d, indent=1))


def get_settings() -> Dict[str, Any]:
    with _LOCK:
        d = _read()
    s = json.loads(json.dumps(DEFAULTS))
    for k in s:
        if k in d and isinstance(d[k], type(s[k])):
            s[k] = d[k]
    s["libraries"] = libraries()
    return s


# ── optional libraries, imported only when used ──────────────────────────
def _paramiko() -> Any:
    try:
        import paramiko  # type: ignore
        return paramiko
    except Exception:  # noqa: BLE001
        return None


def _smb() -> Any:
    try:
        import smbclient  # type: ignore
        return smbclient
    except Exception:  # noqa: BLE001
        return None


def _keyring() -> Any:
    try:
        import keyring  # type: ignore
        if keyring is None:
            return None
        keyring.get_keyring()
        return keyring
    except Exception:  # noqa: BLE001
        return None


def libraries() -> Dict[str, bool]:
    return {"ssh": _paramiko() is not None, "smb": _smb() is not None, "credential_store": _keyring() is not None}


# ── settings ─────────────────────────────────────────────────────────────
def _host(v: Any) -> str:
    h = str(v or "").strip().lower()
    if not _HOST.match(h) or "*" in h:
        raise DeliveryError("That is not a host name or address (no wildcards).")
    return h


def check_cron(expr: Any) -> str:
    e = " ".join(str(expr or "").split())
    if not e:
        return ""
    try:
        _parse_cron(e)
    except ValueError:
        raise DeliveryError("The schedule must be five cron fields: minute hour day-of-month month day-of-week.")
    return e


def save_settings(fields: Dict[str, Any]) -> Dict[str, Any]:
    """Validate and store {enabled, allowed_hosts, targets, schedule, known_hosts}. No credential travels here."""
    if not isinstance(fields, dict) or set(fields) - set(DEFAULTS):
        raise DeliveryError("Unknown setting.")
    cur = get_settings()
    cur.pop("libraries", None)
    if "enabled" in fields:
        cur["enabled"] = bool(fields["enabled"])
    if "allowed_hosts" in fields:
        hosts = fields["allowed_hosts"]
        if not isinstance(hosts, list) or len(hosts) > 50:
            raise DeliveryError("allowed_hosts must be a list of at most 50 hosts.")
        cur["allowed_hosts"] = sorted({_host(h) for h in hosts})
    if "known_hosts" in fields:
        kh = str(fields["known_hosts"] or "")
        if len(kh) > 400 or re.search(r"[\x00-\x1f\x7f]", kh):
            raise DeliveryError("The known_hosts path is not valid.")
        cur["known_hosts"] = kh
    if "targets" in fields:
        t = fields["targets"]
        if not isinstance(t, dict) or len(t) > MAX_TARGETS:
            raise DeliveryError(f"At most {MAX_TARGETS} targets.")
        clean: Dict[str, Any] = {}
        for tid, v in t.items():
            if not _ID.match(str(tid)) or not isinstance(v, dict):
                raise DeliveryError("A target id is lower-case letters, digits, '-' or '_' (32 at most).")
            tr = str(v.get("transport") or "")
            if tr not in TRANSPORTS:
                raise DeliveryError("transport must be one of " + ", ".join(TRANSPORTS) + ".")
            user = str(v.get("user") or "")
            rdir = str(v.get("remote_dir") or "")
            if not _USER.match(user) or not _DIR.match(rdir) or ".." in rdir.replace("\\", "/").split("/"):
                raise DeliveryError("The user or remote folder is not valid.")
            port = int(v.get("port") or DEFAULT_PORTS[tr])
            if not 1 <= port <= 65535:
                raise DeliveryError("Port out of range.")
            row = {"transport": tr, "host": _host(v.get("host")), "port": port, "user": user, "remote_dir": rdir}
            if tr == "smb":
                share = str(v.get("share") or "")
                if not re.match(r"\A[A-Za-z0-9._$-]{1,80}\Z", share):
                    raise DeliveryError("An SMB target needs a share name.")
                row["share"] = share
            clean[str(tid)] = row
        cur["targets"] = clean
    if "schedule" in fields:
        sc = fields["schedule"] if isinstance(fields["schedule"], dict) else {}
        tgt = str(sc.get("target") or "")
        if tgt and tgt not in cur["targets"]:
            raise DeliveryError("The scheduled target is not defined.")
        cur["schedule"] = {"enabled": bool(sc.get("enabled")), "cron": check_cron(sc.get("cron")), "target": tgt}
    with _LOCK:
        d = _read()
        d.update({k: cur[k] for k in DEFAULTS})
        _write(d)
    return get_settings()


# ── credentials: OS credential store only ────────────────────────────────
def set_credential(target_id: str, secret: str) -> None:
    kr = _keyring()
    if kr is None:
        raise DeliveryError("No operating-system credential store is available; the password is not kept anywhere else.")
    if not secret or len(secret) > 1024:
        raise DeliveryError("That is not a usable password.")
    kr.set_password(KEYRING_SERVICE, str(target_id), secret)


def _credential(target_id: str) -> str:
    kr = _keyring()
    if kr is None:
        raise DeliveryError("No operating-system credential store is available.")
    try:
        sec = kr.get_password(KEYRING_SERVICE, str(target_id))
    except Exception:  # noqa: BLE001
        sec = None
    if not sec:
        raise DeliveryError("No credential is stored for this target.")
    return sec


# ── sending ──────────────────────────────────────────────────────────────
def remote_name(name: str) -> str:
    n = _FNAME_BAD.sub("_", os.path.basename(str(name or "").replace("\\", "/"))).lstrip(".")
    return n[:100] or "report.csv"


def _gate(s: Dict[str, Any], target_id: str) -> Dict[str, Any]:
    if not s.get("enabled"):
        raise DeliveryError("Report delivery is off.")
    t = (s.get("targets") or {}).get(target_id)
    if not t:
        raise DeliveryError("No such delivery target.")
    if str(t.get("host", "")).lower() not in {h.lower() for h in s.get("allowed_hosts") or []}:
        raise DeliveryError("That host is not in the allowed hosts.")
    return t


def _ssh_client(pm: Any, t: Dict[str, Any], secret: str, known_hosts: str) -> Any:
    c = pm.SSHClient()
    try:
        c.load_system_host_keys()
        if known_hosts:
            c.load_host_keys(known_hosts)
    except OSError:
        pass
    c.set_missing_host_key_policy(pm.RejectPolicy())
    c.connect(t["host"], port=t["port"], username=t["user"], password=secret, timeout=20, banner_timeout=20,
              look_for_keys=False, allow_agent=False)
    return c


def _join(rdir: str, name: str) -> str:
    return (rdir.rstrip("/") + "/" + name) if rdir else name


def _send_scp(chan_client: Any, rdir: str, name: str, data: bytes) -> None:
    stdin, stdout, _ = chan_client.exec_command("scp -t " + shlex.quote(rdir or "."))  # nosec B601 - folder validated, shlex-quoted
    def ack() -> None:
        if stdout.channel.recv(1) != b"\x00":
            raise DeliveryError("The remote side refused the copy.")
    ack()
    stdin.write(f"C0600 {len(data)} {name}\n".encode("ascii"))
    stdin.flush()
    ack()
    stdin.write(data)
    stdin.write(b"\x00")
    stdin.flush()
    ack()


def _send(t: Dict[str, Any], name: str, data: bytes, secret: str, known_hosts: str) -> None:
    tr = t["transport"]
    if tr == "smb":
        sc = _smb()
        if sc is None:
            raise DeliveryError("SMB delivery needs the optional 'smbprotocol' package, which is not installed.")
        sc.register_session(t["host"], username=t["user"], password=secret, port=t["port"])
        base = "\\\\" + t["host"] + "\\" + t["share"] + ("\\" + t["remote_dir"].strip("\\/").replace("/", "\\") if t["remote_dir"].strip("\\/") else "")
        with sc.open_file(base + "\\" + name, mode="wb") as f:
            f.write(data)
        return
    pm = _paramiko()
    if pm is None:
        raise DeliveryError(f"{tr.upper()} delivery needs the optional 'paramiko' package, which is not installed.")
    c = _ssh_client(pm, t, secret, known_hosts)
    try:
        if tr == "sftp":
            sf = c.open_sftp()
            with sf.open(_join(t["remote_dir"], name), "wb") as f:
                f.write(data)
        elif tr == "scp":
            _send_scp(c, t["remote_dir"], name, data)
        else:
            stdin, stdout, _ = c.exec_command("cat > " + shlex.quote(_join(t["remote_dir"], name)))  # nosec B601 - validated, shlex-quoted
            stdin.write(data)
            stdin.channel.shutdown_write()
            if stdout.channel.recv_exit_status() != 0:
                raise DeliveryError("The remote side refused the write.")
    finally:
        c.close()


def _audit(event: str, **kw: Any) -> None:
    try:
        import audit
        audit.record(event, **kw)
    except Exception:  # noqa: BLE001
        pass


def deliver(target_id: str, name: str, data: bytes, *, trigger: str = "manual") -> Dict[str, Any]:
    """Send one export to one target. Raises DeliveryError (never with a credential)."""
    if len(data) > MAX_BYTES:
        raise DeliveryError("The export is larger than this feature sends.")
    s = get_settings()
    t = _gate(s, target_id)
    rn = remote_name(name)
    secret = _credential(target_id)
    try:
        _send(t, rn, data, secret, s.get("known_hosts") or "")
    except DeliveryError:
        raise
    except Exception as e:  # noqa: BLE001 — a network or library error, reported by type only
        _audit("report_delivery", target=target_id, host=t["host"], status="failed", trigger=trigger, error=type(e).__name__)
        raise DeliveryError(f"The delivery failed ({type(e).__name__}).")
    _audit("report_delivery", target=target_id, host=t["host"], status="sent", trigger=trigger, bytes=len(data), name=rn)
    return {"target": target_id, "host": t["host"], "name": rn, "bytes": len(data), "status": "sent"}


def saved_report_csv(name: str) -> Tuple[str, bytes]:
    """The CSV export of a saved traffic-log report (read-only), as (file name, bytes)."""
    import traffic_logs as tl
    try:
        rep = tl.load_saved(name)
    except (OSError, ValueError):
        raise DeliveryError("No such saved report.")
    return (os.path.splitext(name)[0] + ".csv", tl.to_csv(rep).encode("utf-8"))


def deliver_saved(target_id: str, report_name: str, *, trigger: str = "manual") -> Dict[str, Any]:
    fn, data = saved_report_csv(report_name)
    return deliver(target_id, fn, data, trigger=trigger)


# ── cron-style schedule ──────────────────────────────────────────────────
_RANGES = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)]


def _field(spec: str, lo: int, hi: int) -> set:
    out = set()
    for part in spec.split(","):
        m = re.match(r"\A(\*|\d{1,2}(?:-\d{1,2})?)(?:/(\d{1,2}))?\Z", part)
        if not m:
            raise ValueError(spec)
        rng, step = m.group(1), int(m.group(2) or 1)
        if step < 1:
            raise ValueError(spec)
        if rng == "*":
            a, b = lo, hi
        elif "-" in rng:
            a, b = map(int, rng.split("-"))
        else:
            a = b = int(rng)
            if m.group(2):
                b = hi
        if a < lo or b > hi or a > b:
            raise ValueError(spec)
        out.update(range(a, b + 1, step))
    return out


def _parse_cron(expr: str) -> List[set]:
    parts = expr.split()
    if len(parts) != 5:
        raise ValueError(expr)
    return [_field(p, lo, hi) for p, (lo, hi) in zip(parts, _RANGES)]


def cron_matches(expr: str, when: datetime) -> bool:
    mi, h, dom, mo, dow = _parse_cron(expr)
    return (when.minute in mi and when.hour in h and when.day in dom and when.month in mo and (when.isoweekday() % 7) in dow)


def tick(now: Optional[datetime] = None, *, newest: Optional[Callable[[], Optional[str]]] = None) -> Optional[Dict[str, Any]]:
    """Deliver the newest saved report when the schedule matches this minute
    (once per minute). Returns the result, or None when nothing was due."""
    s = get_settings()
    sc = s.get("schedule") or {}
    if not (s.get("enabled") and sc.get("enabled") and sc.get("cron") and sc.get("target")):
        return None
    at = (now or datetime.now(timezone.utc)).replace(second=0, microsecond=0)
    try:
        if not cron_matches(sc["cron"], at):
            return None
    except ValueError:
        return None
    stamp = at.isoformat()
    with _LOCK:
        d = _read()
        if d.get("last_tick") == stamp:
            return None
        d["last_tick"] = stamp
        _write(d)
    if newest is None:
        import traffic_logs as tl
        rows = [r for r in tl.list_saved() if r.get("records") is not None]
        nm = rows[0]["name"] if rows else None
    else:
        nm = newest()
    if not nm:
        return None
    try:
        return deliver_saved(sc["target"], nm, trigger="schedule")
    except DeliveryError as e:
        return {"status": "failed", "error": str(e)}
