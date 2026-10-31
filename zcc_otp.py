"""Client Connector one-time passwords for one device, for help-desk use.

A help-desk admin sometimes needs a device's one-time password: to let a
user uninstall Client Connector, turn a service off or exit it. This is a
sensitive read, guarded like a write except that nothing is written
(dlp_api_server /api/zcc/otp):

  - Client Connector ticked on the Scope page (400 before sign-in),
  - a person allowed to change the tenant (security.require_writer),
  - the named assessor,
  - the typed confirmation "SHOW OTP <device>",
  - at most RATE_PER_ACTOR reads per actor in RATE_WINDOW seconds and
    RATE_GLOBAL in RATE_WINDOW_GLOBAL (429 with Retry-After).

The device is found among the enrolled devices of the user named (SDK
zcc.devices.list_devices, GET /zcc/papi/public/v1/getDevices with
`username`) by its host name or UDID; exactly one must match. Its one-time
passwords come from zcc.secrets.get_otp (GET /zcc/papi/public/v1/getOtp
with `udid`; zscaler-sdk-python 1.11.3 zcc/secrets.py, the response model
zcc/models/secrets_otp.py OtpResponse). The values are returned once, in
the answer (no-store), and never stored, logged or cached: the audit entry
says who asked, when, for which device (its host name and a short hash of
its UDID, the same hash the fleet page uses) and which kinds were shown,
never a value. The page shows them for SHOW_SECONDS and then clears them.
"""
from __future__ import annotations

import collections
import hashlib
import re
import threading
import time
import unicodedata
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

# (the API's field, plain label), in the order the page shows them (OtpResponse in the SDK).
OTP_FIELDS: List[Tuple[str, str]] = [
    ("otp", "One-time password"),
    ("uninstallOtp", "Uninstall Client Connector"),
    ("ziaDisableOtp", "Turn off Internet security (ZIA)"),
    ("zpaDisableOtp", "Turn off Private Access (ZPA)"),
    ("zdxDisableOtp", "Turn off Digital Experience (ZDX)"),
    ("zdpDisableOtp", "Turn off Endpoint DLP"),
    ("antiTemperingDisableOtp", "Turn off anti-tampering"),
    ("logoutOtp", "Log out"),
    ("exitOtp", "Exit Client Connector"),
    ("revertOtp", "Revert Client Connector"),
    ("deceptionSettingsOtp", "Deception settings"),
]
SHOW_SECONDS = 60
RATE_PER_ACTOR = 5
RATE_WINDOW = 600.0
RATE_GLOBAL = 30
RATE_WINDOW_GLOBAL = 3600.0
DEVICE_PAGE_SIZE = 500
MAX_DEVICE_PAGES = 4
TEXT_MAX = 200
SDK_CALLS = {"devices": "zcc.devices.list_devices: GET /zcc/papi/public/v1/getDevices (username, page, page_size)",
             "otp": "zcc.secrets.get_otp: GET /zcc/papi/public/v1/getOtp (udid)"}


class OtpError(Exception):
    """A refusal in words, with the HTTP status the route answers."""

    def __init__(self, status: int, message: str, retry_after: Optional[int] = None):
        super().__init__(message)
        self.status = status
        self.retry_after = retry_after


def phrase(device: str) -> str:
    """The typed confirmation for `device` (as the admin typed it)."""
    return f"SHOW OTP {str(device or '').strip()}"


def clean(text: Any, what: str) -> str:
    """A user or device as typed: 1 to TEXT_MAX characters, no control characters."""
    s = str(text if isinstance(text, str) else "").strip()
    if not s:
        raise OtpError(400, f"Type the {what}.")
    if len(s) > TEXT_MAX or any(unicodedata.category(c) in ("Cc", "Cf", "Zl", "Zp") for c in s):
        raise OtpError(400, f"The {what} must be at most {TEXT_MAX} characters, without control characters.")
    return s


def device_ref(udid: Any) -> str:
    """The short hash of a UDID the fleet page shows (zcc_fleet._hash): names a device without its UDID."""
    s = str(udid or "").strip().lower()
    return hashlib.sha256(s.encode("utf-8")).hexdigest()[:16] if s else ""


# ── Rate limit (in memory, per process) ──────────────────────────────
class Limiter:
    """At most `per_actor` reads per actor in `window` seconds and `total`
    in `window_total`; `take` answers 0 (go) or the seconds to wait."""

    def __init__(self, per_actor: int = RATE_PER_ACTOR, window: float = RATE_WINDOW, total: int = RATE_GLOBAL,
                 window_total: float = RATE_WINDOW_GLOBAL, clock: Callable[[], float] = time.monotonic):
        self.per_actor, self.window, self.total, self.window_total, self.clock = per_actor, window, total, window_total, clock
        self._by: Dict[str, Deque[float]] = {}
        self._all: Deque[float] = collections.deque()
        self._lock = threading.Lock()

    def take(self, actor: str) -> int:
        now = self.clock()
        with self._lock:
            mine = self._by.setdefault(actor or "", collections.deque())
            while mine and mine[0] <= now - self.window:
                mine.popleft()
            while self._all and self._all[0] <= now - self.window_total:
                self._all.popleft()
            if len(mine) >= self.per_actor:
                return max(1, int(mine[0] + self.window - now + 0.999))
            if len(self._all) >= self.total:
                return max(1, int(self._all[0] + self.window_total - now + 0.999))
            mine.append(now)
            self._all.append(now)
            if len(self._by) > 1024:
                self._by = {k: v for k, v in self._by.items() if v}
            return 0


LIMITER = Limiter()


# ── The SDK reads ────────────────────────────────────────────────────
def _plain(x: Any) -> Dict[str, Any]:
    if isinstance(x, dict):
        return x
    fn = getattr(x, "as_dict", None)
    if callable(fn):
        try:
            d = fn()
            return d if isinstance(d, dict) else {}
        except Exception:  # noqa: BLE001
            return {}
    return {}


def _norm(k: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(k).lower())


def _field(d: Dict[str, Any], name: str) -> Any:
    want = _norm(name)
    return next((v for k, v in d.items() if _norm(k) == want), None)


def _err_words(err: Any) -> str:
    """An SDK error in words, without anything it might quote from an answer."""
    import tenant_auth
    m = re.search(r"\b([1-5]\d\d)\b", str(err))
    code = m.group(1) if m else ""
    words = {"401": "the API client was refused (HTTP 401)", "403": "the API client may not read this (HTTP 403): its role needs the "
             "Client Connector device permission", "404": "the tenant answered HTTP 404", "429": "the tenant's rate limit was reached (HTTP 429)"}
    return words.get(code) or tenant_auth.redact_tokens(f"{type(err).__name__}" + (f" (HTTP {code})" if code else ""))


def find_device(sdk: Any, user: str, device: str) -> Dict[str, str]:
    """The one enrolled device of `user` whose host name or UDID is
    `device`: {udid, hostname}. OtpError for none, several, or a refusal."""
    devs = getattr(getattr(sdk, "zcc", None), "devices", None)
    if devs is None:
        raise OtpError(400, "This sign-in has no Client Connector API: sign in with a OneAPI API client.")
    want = device.strip().lower()
    hits: List[Dict[str, str]] = []
    for page in range(1, MAX_DEVICE_PAGES + 1):
        try:
            items, _resp, err = devs.list_devices(query_params={"username": user, "page": page, "page_size": DEVICE_PAGE_SIZE})
        except Exception as e:  # noqa: BLE001 — a refusal in words
            raise OtpError(502, f"The enrolled devices could not be read: {_err_words(e)}.") from None
        if err:
            raise OtpError(502, f"The enrolled devices could not be read: {_err_words(err)}.")
        rows = [_plain(x) for x in items or []]
        for r in rows:
            udid = str(_field(r, "udid") or "").strip()
            host = str(_field(r, "machineHostname") or _field(r, "hostname") or "").strip()
            if udid and (udid.lower() == want or host.lower() == want):
                hits.append({"udid": udid, "hostname": host or "(no host name)"})
        if len(rows) < DEVICE_PAGE_SIZE:
            break
    if not hits:
        raise OtpError(404, "No enrolled device of that user has that host name or UDID. Check both on the fleet page; nothing was shown.")
    if len({h["udid"] for h in hits}) > 1:
        raise OtpError(409, "Several of that user's devices have that host name: type the device's UDID instead. Nothing was shown.")
    return hits[0]


def fetch(sdk: Any, udid: str) -> List[Dict[str, str]]:
    """The device's one-time passwords as the API provides them:
    [{key, label, value}] for every field it answered with a value."""
    sec = getattr(getattr(sdk, "zcc", None), "secrets", None)
    if sec is None or not callable(getattr(sec, "get_otp", None)):
        raise OtpError(400, "This sign-in cannot read one-time passwords (no Client Connector secrets API).")
    try:
        ret = sec.get_otp(query_params={"udid": udid})
    except Exception as e:  # noqa: BLE001
        raise OtpError(502, f"The one-time passwords could not be read: {_err_words(e)}.") from None
    obj, _resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        raise OtpError(502, f"The one-time passwords could not be read: {_err_words(err)}.")
    d = _plain(obj)
    out = []
    for key, label in OTP_FIELDS:
        v = _field(d, key)
        if v is None:
            v = getattr(obj, re.sub(r"(?<!^)(?=[A-Z])", "_", key).lower(), None)
        if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
            out.append({"key": key, "label": label, "value": str(v).strip()[:200]})
    if not out:
        raise OtpError(404, "The tenant answered without a one-time password for this device.")
    return out


def retrieve(sdk: Any, user: str, device: str) -> Dict[str, Any]:
    """Find the device and read its one-time passwords:
    {device: {hostname, ref}, otps: [...], show_seconds}."""
    dev = find_device(sdk, user, device)
    otps = fetch(sdk, dev["udid"])
    return {"device": {"hostname": dev["hostname"], "ref": device_ref(dev["udid"])}, "otps": otps, "show_seconds": SHOW_SECONDS,
            "note": f"Shown once: copy what the user needs now. The page hides them after {SHOW_SECONDS} seconds; they are not kept anywhere."}


def audit(result: str, *, actor: Optional[str], by: str, tenant: str, device: str = "", ref: str = "",
          kinds: Optional[List[str]] = None, reason: str = "") -> None:
    """One `zcc_otp` audit entry: who, when (the entry's time), which device
    and which kinds were shown; never a value."""
    import pack_jobs
    pack_jobs.write_audit("zcc_otp", actor=actor, by=by or None, tenant=tenant or None, device=device[:120] or None, device_ref=ref or None,
                          result=result, kinds=list(kinds or []) or None, reason=str(reason)[:200] or None)
