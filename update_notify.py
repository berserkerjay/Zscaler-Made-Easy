"""Update notifications: when the app's update check (app_update.status,
behind Advanced settings > App version and updates and /api/app/update/status)
finds a newer version, optionally say so on the e-mail and webhook channel
the continuous-evaluation digests already use (continuous_eval: SMTP with
DLP_CHECK_SMTP_HOST and DLP_CHECK_DIGEST_TO, or DLP_CHECK_DIGEST_WEBHOOK).

* Off by default: an admin turns it on in Advanced settings (a writer under
  SSO). The setting lives in update_notify.json beside the other local
  settings (owner-only), never in the repository.
* At most once per version: the commit the check found is remembered once
  a notice was sent on at least one channel, so the same version is never
  announced twice, whatever the number of checks. A version that could not
  be sent (no channel configured, the mail server down) is tried again at
  the next check.
* No new outbound destination: the notice goes only to the channels the
  digests already use, and it carries the branch, the installed and the
  new commit and where to update; never a token, a path or a tenant.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional

import safe_files

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.Lock()
KEEP_NOTIFIED = 50
_SHA_RE = re.compile(r"^[0-9a-f]{7,64}$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,80}$")


def settings_path() -> str:
    """update_notify.json beside the posture settings (the app folder on a
    local install, /data in the container), or DLP_CHECK_UPDATE_NOTIFY_FILE."""
    env = os.environ.get("DLP_CHECK_UPDATE_NOTIFY_FILE")
    if env:
        return env
    try:
        import posture_plus
        folder = os.path.dirname(os.path.abspath(posture_plus.settings_path()))
    except Exception:  # noqa: BLE001
        folder = _APP_DIR
    return os.path.join(folder, "update_notify.json")


def _read() -> Dict[str, Any]:
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:  # noqa: BLE001 - missing or unreadable: the defaults (off)
        data = {}
    return data if isinstance(data, dict) else {}


def _clean(data: Dict[str, Any]) -> Dict[str, Any]:
    notified = [str(x) for x in (data.get("notified") or []) if isinstance(x, str) and _SHA_RE.match(x)][-KEEP_NOTIFIED:]
    last = data.get("last") if isinstance(data.get("last"), dict) else None
    return {"enabled": data.get("enabled") is True, "notified": notified,
            "last": {k: str(last.get(k) or "")[:80] for k in ("at", "commit", "result")} if last else None}


def settings() -> Dict[str, Any]:
    """{enabled (default False), notified (commits already announced), last}."""
    return _clean(_read())


def _write(data: Dict[str, Any]) -> Dict[str, Any]:
    clean = _clean(data)
    p = settings_path()
    folder = os.path.dirname(os.path.abspath(p)) or "."
    safe_files.private_makedirs(folder)
    fd, tmp = tempfile.mkstemp(prefix=".update-notify-", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(clean, f, indent=1)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, p)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return clean


def save_settings(enabled: bool) -> Dict[str, Any]:
    with _LOCK:
        data = settings()
        data["enabled"] = enabled is True
        return _write(data)


def channels() -> Dict[str, Any]:
    """Which digest channels are configured (no secret, no webhook path)."""
    import continuous_eval
    cfg = continuous_eval.notification_settings()
    return {"email": bool(cfg["email"]["configured"]), "webhook": bool(cfg["webhook"]["configured"]),
            "webhook_host": cfg["webhook"].get("host"), "email_to": cfg["email"].get("to")}


def message(status: Dict[str, Any]) -> Dict[str, str]:
    """The subject and body of the notice (plain text; nothing secret)."""
    branch = str(status.get("target_branch") or status.get("branch") or "main")
    branch = branch if _BRANCH_RE.match(branch) else "main"
    new = str(status.get("remote_commit") or "")[:12]
    cur = str(status.get("local_commit") or "unknown")[:12]
    how = ("Rebuild the container from the computer that runs Docker (update_container.sh or .ps1)." if status.get("in_container")
           else "Download the new edition." if status.get("standalone")
           else "Open Advanced settings > App version and updates and click Update now, or run UPDATE_Zscaler_Made_Easy.")
    subject = f"Zscaler Made Easy: a newer version is available ({branch} {new})"
    body = (f"# A newer version of Zscaler Made Easy is available\n\n"
            f"- Branch: {branch}\n- Installed: {cur}\n- Available: {new}\n\n{how}\n\n"
            "You get this notice once per version because update notifications are on in Advanced settings. "
            "Turn them off there to stop them.\n")
    return {"subject": subject, "body": body}


def _send(subject: str, body: str) -> List[Dict[str, Any]]:
    import continuous_eval as ce
    cfg = ce.notification_settings()
    out = []
    if cfg["email"]["configured"]:
        out.append(ce._send_email(subject, body, cfg["email"]))
    if cfg["webhook"]["configured"]:
        out.append(ce._send_webhook(subject, body, os.environ.get("DLP_CHECK_DIGEST_WEBHOOK", "").strip()))
    if not out:
        out.append({"channel": "none", "sent": False, "why": "no e-mail or webhook configured (the same settings as the digests)"})
    return out


def maybe_notify(status: Dict[str, Any], *, send: Optional[Callable[[str, str], List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """Send one notice for the newer version `status` (app_update.status)
    found, when notifications are on and that version was not announced
    yet. Returns {sent, why, results}. Never raises."""
    try:
        if not isinstance(status, dict) or status.get("update_available") is not True:
            return {"sent": False, "why": "no newer version"}
        commit = str(status.get("remote_commit") or "").lower()
        if not _SHA_RE.match(commit):
            return {"sent": False, "why": "the newer version has no usable commit id"}
        with _LOCK:
            cfg = settings()
            if not cfg["enabled"]:
                return {"sent": False, "why": "update notifications are off"}
            if any(commit.startswith(x) or x.startswith(commit) for x in cfg["notified"]):
                return {"sent": False, "why": "already announced"}
            msg = message(status)
            results = (send or _send)(msg["subject"], msg["body"])
            ok = any(r.get("sent") for r in results if isinstance(r, dict))
            if ok:
                cfg["notified"].append(commit)
            cfg["last"] = {"at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "commit": commit[:12],
                           "result": "sent" if ok else "not sent"}
            _write(cfg)
        return {"sent": ok, "why": "" if ok else "no channel accepted it", "results": results}
    except Exception as e:  # noqa: BLE001 - a notice never breaks the update check
        return {"sent": False, "why": f"{type(e).__name__}"}


def overview() -> Dict[str, Any]:
    """What Advanced settings shows."""
    s = settings()
    return {"enabled": s["enabled"], "last": s["last"], "announced": len(s["notified"]), "channels": channels()}
