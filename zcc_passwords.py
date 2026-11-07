"""Client Connector uninstall, turn-off and log-out passwords, revealed on demand.

The app never reads these passwords on its own: a backup, a restore, a
clone, a report, an export or a snapshot never carries one. A help-desk
admin who must let a user uninstall, log out of or turn off Client
Connector can reveal one user's passwords for one operating system, once
(dlp_api_server /api/zcc/passwords), under every one of these rules:

  - off by default: the setting ZSCALER_ZCC_TAMPER_REVEAL=1 turns it on
    (read each time, so the operator can switch it off again),
  - Client Connector ticked on the Scope page (400 before sign-in),
  - a person allowed to change the tenant (security.require_writer); on a
    team server the route rule is admin (team_routes),
  - the named assessor,
  - the typed confirmation "SHOW PASSWORDS <user> <os>",
  - one user and one operating system per request,
  - at most RATE_PER_ACTOR reads per actor in RATE_WINDOW seconds
    (429 with Retry-After).

The values come from zcc.secrets.get_passwords (GET
/zcc/papi/public/v1/getPasswords with username and os_type;
zscaler-sdk-python 1.11.3 zcc/secrets.py, zcc/models/secrets_passwords.py
Passwords). They are returned once in the answer (Cache-Control: no-store)
and are never stored, logged, audited, exported or put in a snapshot or
backup: the audit entry says who asked, when, for which user and operating
system and which kinds were shown, never a value. The page shows them
masked with a reveal button and clears them after SHOW_SECONDS.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

import zcc_otp
from zcc_otp import OtpError as PasswordError, clean

ENV_SETTING = "ZSCALER_ZCC_TAMPER_REVEAL"
OS_TYPES = ("windows", "macos", "linux", "ios", "android")
SHOW_SECONDS = zcc_otp.SHOW_SECONDS
# (the API's field, plain label), in the order the page shows them (Passwords in the SDK).
PASSWORD_FIELDS = [
    ("uninstallPass", "Uninstall Client Connector"),
    ("logoutPass", "Log out"),
    ("exitPass", "Exit Client Connector"),
    ("ziaDisablePass", "Turn off Internet security (ZIA)"),
    ("zpaDisablePass", "Turn off Private Access (ZPA)"),
    ("zdxDisablePass", "Turn off Digital Experience (ZDX)"),
    ("zdSettingsAccessPass", "Open the Endpoint DLP settings"),
]
SDK_CALL = "zcc.secrets.get_passwords: GET /zcc/papi/public/v1/getPasswords (username, os_type)"
LIMITER = zcc_otp.Limiter(per_actor=5, window=600.0, total=30, window_total=3600.0)
OFF_WORDS = ("Revealing tamper-protection passwords is off. The operator turns it on with the setting "
             f"{ENV_SETTING}=1 (in local_settings.env or the server's environment) and restarts the app. Nothing was read.")


def enabled() -> bool:
    """The setting, read each time: off unless exactly 1/true/yes/on."""
    return os.environ.get(ENV_SETTING, "").strip().lower() in ("1", "true", "yes", "on")


def os_type(value: Any) -> str:
    s = str(value if isinstance(value, str) else "").strip().lower()
    if s not in OS_TYPES:
        raise PasswordError(400, f"Choose one operating system: {', '.join(OS_TYPES)}.")
    return s


def phrase(user: str, os_name: str) -> str:
    """The typed confirmation for one user and one operating system."""
    return f"SHOW PASSWORDS {str(user or '').strip()} {str(os_name or '').strip().lower()}"


def retrieve(sdk: Any, user: str, os_name: str) -> Dict[str, Any]:
    """Read the user's passwords for one OS: {user, os, passwords: [{key, label, value}], show_seconds, note}."""
    sec = getattr(getattr(sdk, "zcc", None), "secrets", None)
    if sec is None or not callable(getattr(sec, "get_passwords", None)):
        raise PasswordError(400, "This sign-in cannot read tamper-protection passwords (no Client Connector secrets API).")
    try:
        ret = sec.get_passwords(query_params={"username": user, "os_type": os_name})
    except Exception as e:  # noqa: BLE001
        raise PasswordError(502, f"The passwords could not be read: {zcc_otp._err_words(e)}.") from None
    obj, _resp, err = (tuple(ret) + (None, None, None))[:3] if isinstance(ret, tuple) else (ret, None, None)
    if err:
        raise PasswordError(502, f"The passwords could not be read: {zcc_otp._err_words(err)}.")
    d = zcc_otp._plain(obj)
    out: List[Dict[str, str]] = []
    for key, label in PASSWORD_FIELDS:
        v = zcc_otp._field(d, key)
        if isinstance(v, (str, int)) and not isinstance(v, bool) and str(v).strip():
            out.append({"key": key, "label": label, "value": str(v).strip()[:200]})
    if not out:
        raise PasswordError(404, "The tenant answered without a password for that user and operating system.")
    return {"user": user, "os": os_name, "passwords": out, "show_seconds": SHOW_SECONDS,
            "note": f"Shown once: copy what the user needs now. The page hides them after {SHOW_SECONDS} seconds; they are not kept anywhere."}


def audit(result: str, *, actor: Optional[str], by: str, tenant: str, user: str = "", os_name: str = "",
          kinds: Optional[List[str]] = None, reason: str = "") -> None:
    """One `zcc_passwords` audit entry: who, when (the entry's time), which
    user and operating system, which kinds were shown; never a value."""
    import pack_jobs
    pack_jobs.write_audit("zcc_passwords", actor=actor, by=by or None, tenant=tenant or None, user=user[:120] or None,
                          os=os_name or None, result=result, kinds=list(kinds or []) or None, reason=str(reason)[:200] or None)
