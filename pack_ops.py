"""The shared execution path: every object a policy pack puts into or takes
out of a ZIA tenant goes through this module, whatever the pack.

Deploy Policy Packs, the removal wizard, the undo of a recorded deployment,
the legacy single-pack import endpoint and the continuous-evaluation
proposals all end here. The contract (docs/SHARED_EXECUTION_PATH.md):

  validate(kind, definition)   one validator per kind, run before any
                               write: names, descriptions, ZIA limits
  CREATE_ORDER / DELETE_TIERS  dependencies before dependents on create;
                               dependents before dependencies on delete
  call(fn, ...)                every write goes through call(): the SDK's
                               (data, response, error) and raw (data,
                               error) shapes are normalised into one
                               Outcome, transient refusals (rate limit,
                               5xx, timeouts) are retried with backoff,
                               anything else is reported once
  create() / update() / delete()   the only functions that name an SDK
                               write method; kind-dispatched
  Recorder                     one structured event per write, one log
                               line per event, in the same shape for a
                               deploy, a removal and an undo
  current_names()              the identity check before a delete: an id
                               is only deleted while it still carries the
                               name the pack gave it
  activate_and_settle()        activation plus the wait for ACTIVE
  run_scope() / stop_reason()  run control: a refusal that no later write
                               can get past (the portal's edit lock, the
                               hourly request limit, refused credentials)
                               stops the run at once, in words; a cancel
                               event from the operator does the same

A test (tests/test_shared_path.py) fails the build if any other module
calls an SDK write method directly.
"""
from __future__ import annotations

import contextlib
import json
import logging
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

import pack_channels as pc
from dlp_importer import (ENGINE_DESCRIPTION_MAX, _extract_id, dictionary_limit_problems, dictionary_notes, engine_limit_problems,
                          name_problems)

logger = logging.getLogger("dlp_check.packs")

KINDS = ("dictionary", "engine", "app_group", "policy")
# Dependencies first: a rule needs its engines, an engine its dictionaries,
# an endpoint rule its application group.
CREATE_ORDER = ("dictionary", "engine", "app_group", "policy")
# Dependents first, in tiers: ZIA validates a delete against the activated
# configuration, so each tier is activated before the next one starts.
DELETE_TIERS = (("policy", "app_group"), ("engine",), ("dictionary",))
DELETE_ORDER = tuple(k for tier in DELETE_TIERS for k in tier)
TIER_LABELS = ("rules", "engines", "dictionaries")

# Refusals that time clears. ZIA answers a rate limit with 429, a busy
# tenant with 502/503/504 or a timeout; these are retried with backoff.
TRANSIENT_STATUSES = {429, 502, 503, 504}
TRANSIENT_WORDS = ("rate limit", "too many requests", "429", "502", "503", "504", "timeout", "timed out",
                   "temporarily", "try again", "service unavailable", "gateway")
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = 1.0

_sleep: Callable[[float], None] = time.sleep   # tests replace this

# Outcome.code of a write that was never sent because the run had stopped.
STOPPED = "STOPPED"


# ---------------------------------------------------------------------------
# Run control — stop a run that cannot get anywhere, or that was cancelled
# ---------------------------------------------------------------------------
#
# Some refusals are not about one object but about the whole tenant for the
# rest of the run: an admin session holding the ZIA edit lock refuses every
# write, an exhausted hourly request limit refuses every request until the
# hour turns, refused credentials refuse everything. Trying the next 75
# objects against them takes twenty minutes (the SDK waits for the lock
# twice per write) and looks like a hang. Inside a run_scope(), the first
# such refusal stops the run: every later write returns at once with
# code STOPPED and the reason, the run finishes its bookkeeping (activation,
# read-back) and the reason is reported in words. A cancel event (the
# operator's Stop button) works the same way.

_run = threading.local()

_RETRY_WAIT_RE = re.compile(r"retry wait time (\d+(?:\.\d+)?) seconds", re.I)


def _minutes(seconds: float) -> str:
    m = max(1, int(round(seconds / 60.0)))
    return f"{m} minute" + ("" if m == 1 else "s")


def fatal_reason(message: Optional[str]) -> Optional[str]:
    """The plain-language reason a refusal stops the whole run, or None
    when it is about this one object only."""
    m = (message or "").lower()
    if not m:
        return None
    if "edit_lock_not_available" in m or "edit lock" in m:
        return ("Someone is signed in to the ZIA Admin Portal for this tenant and holds its edit lock (it may be you, in another "
                "tab). ZIA refuses every change from the API while that session is open. Sign out of the portal, or wait for the "
                "session to time out, then run this again.")
    hit = _RETRY_WAIT_RE.search(m)
    if hit:
        return (f"ZIA's request limit for this hour is reached; it accepts requests again in about {_minutes(float(hit.group(1)))}. "
                "Run this again after that: what was already written is kept and only the rest is created.")
    if "unauthorized" in m or "token refresh attempts exhausted" in m or "401" in m.split():
        return "The tenant no longer accepts the credentials (the sign-in expired or the client secret changed). Reconnect, then run this again."
    if "forbidden" in m or "not authorized" in m or "insufficient" in m and "permission" in m:
        return ("The API client is not allowed to change DLP policy in this tenant. Give it the DLP policy write permission in ZIA "
                "administration, then run this again.")
    return None


@contextlib.contextmanager
def run_scope(cancel: Optional[threading.Event] = None) -> Iterator[None]:
    """Mark the current thread as running one deploy / removal / undo, so
    fatal refusals and `cancel` stop the remaining writes."""
    _run.stop = None
    _run.cancel = cancel
    _run.announced = False
    try:
        yield
    finally:
        _run.stop = None
        _run.cancel = None
        _run.announced = False


def stop_reason() -> Optional[str]:
    """Why the current run stopped writing, or None while it is going."""
    return getattr(_run, "stop", None)


def in_run() -> bool:
    return hasattr(_run, "stop")


CANCELLED_REASON = "You clicked Stop, so nothing more was sent to the tenant."


def _stopped_now() -> Optional[str]:
    """The reason no write may be sent now: cancelled, or stopped earlier."""
    ev = getattr(_run, "cancel", None)
    if ev is not None and ev.is_set() and not stop_reason():
        _stop(CANCELLED_REASON, lambda m: None)
    return stop_reason()


def _stop(reason: str, log: Callable[[str], None]) -> None:
    if not in_run() or stop_reason():
        return
    _run.stop = reason
    log(f"STOPPED — nothing more is written. {reason}")
    logger.warning("run stopped", extra={"reason": reason})


# ---------------------------------------------------------------------------
# Validation — one entry point for every kind
# ---------------------------------------------------------------------------

def validate(kind: str, definition: Dict[str, Any], *, channel: Optional[str] = None) -> List[str]:
    """Plain-language reasons ZIA would refuse `definition`, or []. Runs in
    preflight and at upload, so nothing reaches the API that this cannot
    explain first. Warnings (things the deploy corrects) are `notes()`."""
    name = str((definition or {}).get("name") or "").strip()
    if kind == "dictionary":
        return name_problems(name, "dictionary") + dictionary_limit_problems(definition)
    if kind == "engine":
        out = name_problems(name, "engine") + engine_limit_problems(str(definition.get("expression") or definition.get("engine_expression") or ""))
        if not str(definition.get("expression") or definition.get("engine_expression") or "").strip():
            out.append("engine has an empty expression")
        return out
    if kind == "app_group":
        out = [] if name else ["application group has no name"]
        if not (definition.get("resources") or []):
            out.append(f"application group '{name}' lists no resources")
        return out
    if kind == "policy":
        out = [] if name else ["rule has no name"]
        err = pc.validate(definition)
        if err:
            out.append(err)
        return out
    return [f"unknown object kind '{kind}'"]


def notes(kind: str, definition: Dict[str, Any]) -> List[str]:
    """Things the deploy silently corrects, worth telling a pack author."""
    if kind == "dictionary":
        return dictionary_notes(definition)
    if kind == "engine" and len(str(definition.get("description") or "")) > ENGINE_DESCRIPTION_MAX:
        return [f"description longer than {ENGINE_DESCRIPTION_MAX} characters is shortened on deploy"]
    return []


# ---------------------------------------------------------------------------
# Outcome + call(): one shape for every API answer
# ---------------------------------------------------------------------------

@dataclass
class Outcome:
    ok: bool
    id: Any = None
    data: Any = None
    error: Optional[str] = None
    code: Optional[str] = None
    http_status: Optional[int] = None
    attempts: int = 1
    transient: bool = False

    def as_error(self) -> Optional[str]:
        return None if self.ok else (self.error or "Unknown error")


# The SDK often hands back its error as text — a JSON body ('{"status":
# 403, "code": null, "message": "Resource Access Blocked", ...}') or the
# repr of a dict — rather than a dict. These pull the status, code and
# message out of either, so the app can say what the number means.
_ERR_STATUS_RE = re.compile(r"""["']status(?:_code)?["']\s*:\s*["']?([1-5]\d{2})\b""")
_ERR_CODE_RE = re.compile(r"""["']code["']\s*:\s*["']([A-Za-z0-9_]+)["']""")
_ERR_MESSAGE_RE = re.compile(r"""["']message["']\s*:\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')""")
_ERR_HTTP_WORDS_RE = re.compile(r"\b(?:http|status(?:\s+code)?)\W{0,3}([1-5]\d{2})\b", re.I)


def _error_parts(err: Any) -> Tuple[str, Optional[str], Optional[int]]:
    """(message, code, http_status) from whatever the SDK handed back."""
    if isinstance(err, dict):
        msg = err.get("message") or err.get("error") or str(err)
        status = err.get("status") or err.get("status_code")
        try:
            status = int(status) if status is not None else None
        except (TypeError, ValueError):
            status = None
        return str(msg)[:300], (str(err["code"]) if err.get("code") else None), status
    text = str(err)
    hit = _ERR_STATUS_RE.search(text) or _ERR_HTTP_WORDS_RE.search(text)
    status = int(hit.group(1)) if hit else None
    c = _ERR_CODE_RE.search(text)
    code = c.group(1) if c and c.group(1).lower() not in ("null", "none") else None
    msg = text
    m = _ERR_MESSAGE_RE.search(text)
    if m:
        raw = m.group(1) if m.group(1) is not None else m.group(2)
        try:
            msg = json.loads('"' + raw.replace("\\'", "'") + '"') if m.group(1) is not None else raw.replace("\\'", "'")
        except ValueError:
            msg = raw
    return str(msg)[:300], code, status


def http_label(status: Optional[int], message: Optional[str] = None, code: Optional[str] = None) -> Optional[str]:
    """What an HTTP status from ZIA means, in words — above all whether it
    is a 403 (refused: permission, rank or a blocked client) or a 429 (rate
    limit: wait), which look alike in a log and call for opposite fixes."""
    if not status:
        return None
    m = (message or "").lower()
    if status == 403:
        if "resource access blocked" in m:
            return ("HTTP 403 — ZIA blocked the API client's access to this resource (not a rate limit): the client's admin role "
                    "lost access, or ZIA blocked the client after a burst of refused requests")
        if "admin rank" in m:
            return "HTTP 403 — the rule's rank is above the API client's admin rank (Role Management); not a permission or rate-limit problem"
        return "HTTP 403 — ZIA refused access: the API client's role does not allow this (not a rate limit)"
    if status == 429:
        return "HTTP 429 — ZIA's rate limit: too many requests in the window (not a permission problem); the app waits and retries"
    if status == 401:
        return "HTTP 401 — the sign-in was rejected (expired, or the credentials changed)"
    if status == 400:
        return "HTTP 400 — ZIA rejected the request body"
    if status == 404:
        return "HTTP 404 — the object is not in the tenant"
    if status == 409:
        return "HTTP 409 — a conflict: the portal's edit lock, or an object already in that state"
    if 500 <= status < 600:
        return f"HTTP {status} — ZIA's side failed or was busy; the app retries"
    return f"HTTP {status}"


def describe_error(err: Any) -> str:
    """'HTTP 403: Resource Access Blocked' — the status in front of the
    message whenever ZIA gave one, else the message alone."""
    msg, _code, status = _error_parts(err)
    return f"HTTP {status}: {msg}" if status else msg


def is_transient(message: Optional[str], http_status: Optional[int] = None) -> bool:
    if http_status in TRANSIENT_STATUSES:
        return True
    m = (message or "").lower()
    return any(w in m for w in TRANSIENT_WORDS)


def normalize(ret: Any) -> Outcome:
    """Turn an SDK return — (data, response, error), (data, error), a bare
    object or None — into an Outcome."""
    if isinstance(ret, tuple):
        if len(ret) >= 3:
            data, err = ret[0], ret[2]
        elif len(ret) == 2:
            data, err = ret
        else:
            data, err = (ret[0] if ret else None), None
        if err:
            msg, code, status = _error_parts(err)
            return Outcome(False, data=data, error=msg, code=code, http_status=status, transient=is_transient(msg, status))
        oid = _extract_id((data, None, None)) if data is not None else None
        if oid is None and isinstance(data, dict):
            oid = data.get("id")
        return Outcome(True, id=oid, data=data)
    if ret is None:
        return Outcome(False, error="No response")
    oid = getattr(ret, "id", None) if not isinstance(ret, dict) else ret.get("id")
    return Outcome(True, id=oid, data=ret)


def call(fn: Callable[..., Any], *args: Any, op: str = "write", kind: str = "", name: str = "", channel: Optional[str] = None,
         max_attempts: int = MAX_ATTEMPTS, log: Optional[Callable[[str], None]] = None, kw: Optional[Dict[str, Any]] = None) -> Outcome:
    """Run one API write: `fn(*args, **kw)`. A transient refusal is retried
    up to `max_attempts` times with linear backoff; every other answer is
    returned as-is. Exceptions become a failed Outcome, never a crash."""
    _log = log or (lambda m: None)
    kwargs = dict(kw or {})
    halted = _stopped_now()
    if halted:
        if halted == CANCELLED_REASON and not getattr(_run, "announced", False):
            _run.announced = True
            _log(f"STOPPED — nothing more is written. {halted}")
        return Outcome(False, error=f"not attempted: {halted}", code=STOPPED)
    outcome = Outcome(False, error="not attempted")
    for attempt in range(1, max(1, max_attempts) + 1):
        try:
            outcome = normalize(fn(*args, **kwargs))
        except Exception as e:  # noqa: BLE001 — one object never stops the run
            msg = f"{type(e).__name__}: {e}"[:300]
            outcome = Outcome(False, error=msg, transient=is_transient(msg))
        outcome.attempts = attempt
        if outcome.ok or not outcome.transient or attempt == max_attempts:
            break
        if _stopped_now():
            break
        wait = BACKOFF_SECONDS * attempt
        _log(f"[{kind or op}] {name}: ZIA answered '{outcome.error}' (attempt {attempt} of {max_attempts}); waiting {wait:.0f}s and trying again")
        logger.info("retry", extra={"op": op, "kind": kind, "name": name, "channel": channel, "attempt": attempt, "error": outcome.error})
        _sleep(wait)
    if not outcome.ok:
        reason = fatal_reason(outcome.error)
        if reason:
            _stop(reason, _log)
    return outcome


def find_by_name(zia, kind: str, name: str, channel: Optional[str] = None) -> Optional[Any]:
    """The id of the object of `kind` the tenant lists under `name` (case
    and surrounding spaces ignored), or None. Used when ZIA refuses a
    create as a duplicate the plan did not see: the existing object is
    reused instead of failing everything that depends on it."""
    current, _err = current_names(zia, kind, channel)
    if not current:
        return None
    want = " ".join(name.split()).casefold()
    for oid, n in current.items():
        if " ".join(str(n).split()).casefold() == want:
            try:
                return int(oid)
            except (TypeError, ValueError):
                return oid
    return None


def is_duplicate(message: Optional[str]) -> bool:
    """ZIA refused a create because the name is taken."""
    m = (message or "").lower()
    return "duplicate" in m or "already exists" in m


# ---------------------------------------------------------------------------
# Plain-language explanations of the refusals ZIA is known to give
# ---------------------------------------------------------------------------

# (substring of ZIA's message, lower-case) → what it means and what to do,
# in words someone who has never seen the API can act on. Every entry
# comes from a real tenant's answer.
EXPLANATIONS: Tuple[Tuple[str, str], ...] = (
    ("confidence score value is not supported in custom dictionary",
     "ZIA does not allow a confidence score on a custom dictionary. Remove confidence_threshold from this dictionary in the pack; the app does not send it for custom dictionaries."),
    ("confidencethreshold can't be null",
     "A copy of a predefined dictionary needs a confidence score. Add confidence_threshold (for example CONFIDENCE_LEVEL_HIGH) to this dictionary in the pack."),
    ("hierarchical identifier",
     "This copy of a predefined dictionary needs the list of identifiers it should match (for a driver's licence dictionary, the US states). Add hierarchical_identifiers to it in the pack."),
    ("channel is mandatory",
     "An Endpoint DLP rule must name one data transfer method: removable media, network share, printing or application file access. Add data_transfer_method to the rule in the pack."),
    ("resource access blocked",
     "ZIA is refusing this API client access to the resource (a 403, not a rate limit). Either the client's admin role no longer has access to DLP dictionaries, engines or rules, or ZIA blocked the client after a burst of refused requests. Wait a few minutes, click Authenticate, and run again; if it still fails, check the role in ZIA Administration > Role Management."),
    ("rule rank is higher than the admin rank",
     "The rule asks for a rank above the API client's admin rank, so ZIA refuses it (a 403 from role-based administration, not a permission or rate-limit problem). Deploy without 'Use rank 0' so rules get rank 7, or raise the admin's rank in Role Management."),
    ("too many requests",
     "ZIA's rate limit (a 429): too many requests in the window. The app waits and retries; if the whole run stops, run it again after the wait it names."),
    ("rate limit",
     "ZIA's rate limit (a 429): too many requests in the window. The app waits and retries; if the whole run stops, run it again after the wait it names."),
    ("name exceeds the max length 31",
     "SaaS rule names must be 31 characters or fewer. Shorten this rule's name in the pack."),
    ("not allowed at order",
     "ZIA refused the position it was given for this SaaS rule. The app re-reads the tenant's rules and tries the positions ZIA can still accept; if none is accepted, add the rule in the ZIA portal at the bottom of its list."),
    ("request body is invalid",
     "ZIA could not accept one of the values in this rule. The usual cause is a protocol or setting ZIA does not know on this kind of rule (for example NATIVE_FTP_RULE on a Web DLP rule). Compare the rule with a rule that deployed."),
    ("request rejected",
     "The Zscaler API's edge protection blocked this request before the API saw it. That happens when a pattern contains an HTML tag opening such as <script; write the '<' as \\x3c (the same pattern to ZIA)."),
    ("can only have alphanumeric",
     "Names may only contain letters, digits, spaces, underscores, hyphens, dots and parentheses. Rename the object in the pack."),
    ("invalid_name",
     "Names may only contain letters, digits, spaces, underscores, hyphens, dots and parentheses. Rename the object in the pack."),
    ("can not be more than 255 characters",
     "This field is limited to 255 characters. The app shortens descriptions automatically, so the name or another field is what passed the limit; shorten it in the pack."),
    ("proximity can be enabled only",
     "ZIA allows a proximity window only on dictionaries of the type 'Match any patterns and any phrases'. Change the dictionary's match type in the pack, or remove its proximity."),
    ("not a predefined dictionary",
     "The predefined dictionary this copy is based on does not exist in this tenant, so the copy cannot be made here. The engines that use it are created without it."),
    ("already exists",
     "An object with this name already exists in the tenant. The app reuses existing objects by name, so run the plan again and it will be picked up instead of created."),
    ("duplicate",
     "ZIA already has an object with this name. If it is one of Zscaler's predefined dictionaries shown under this display name "
     "(for example CRED_LEAKAGE is shown as 'Private Key'), rename the pack's copy; otherwise run the plan again and the existing object is reused."),
    ("edit_lock",
     "Someone is signed in to the ZIA Admin Portal for this tenant and holds its edit lock. Sign out of the portal, or wait for the session to time out, then run this again."),
    ("edit lock",
     "Someone is signed in to the ZIA Admin Portal for this tenant and holds its edit lock. Sign out of the portal, or wait for the session to time out, then run this again."),
    ("retry wait time",
     "ZIA's request limit for this hour is reached. Wait for the hour to turn, then run this again: what was already written is kept."),
    ("not attempted",
     "This object was never sent to ZIA because the run had already stopped (see the STOPPED line above for why). Run this again once that is fixed."),
    ("in use",
     "ZIA still counts this object as used by a rule that is only waiting to be deleted. The app activates the change and tries again; if it stays, activate in the ZIA portal and run the removal again."),
    ("referenced",
     "ZIA still counts this object as used by a rule that is only waiting to be deleted. The app activates the change and tries again; if it stays, activate in the ZIA portal and run the removal again."),
    ("rate limit",
     "ZIA is limiting how fast it accepts requests. The app waits and tries again on its own."),
    ("too many requests",
     "ZIA is limiting how fast it accepts requests. The app waits and tries again on its own."),
    ("unauthorized",
     "The tenant refused the credentials. Check the client ID and client secret in the connection details, then try again."),
    ("forbidden",
     "The API client is not allowed to make this change. Give it the DLP policy write permission in ZIA administration, then try again."),
    ("request executor",
     "The installed Zscaler SDK cannot make this kind of request, so this step was skipped. Do it in the ZIA portal, or update the app's dependencies."),
)


def explain(message: Optional[str]) -> Optional[str]:
    """A plain sentence for a known ZIA refusal, or None."""
    m = (message or "").lower()
    if not m:
        return None
    for needle, text in EXPLANATIONS:
        if needle in m:
            return text
    return None


# ---------------------------------------------------------------------------
# Recorder — structured events, one log line each
# ---------------------------------------------------------------------------

EVENT_KEYS = ("ts", "run", "op", "kind", "channel", "name", "id", "status", "error", "explanation", "reason", "code", "http_status", "attempts")


@dataclass
class Recorder:
    """Collects the per-object results a run reports (the shape the Deploy
    Studio and the removal wizard render) and the structured events behind
    them, and writes one log line per event."""
    log: Optional[Callable[[str], None]] = None
    run: str = "deploy"
    results: List[Dict[str, Any]] = field(default_factory=list)
    events: List[Dict[str, Any]] = field(default_factory=list)

    def record(self, kind: str, name: str, status: str, *, op: str, channel: Optional[str] = None, outcome: Optional[Outcome] = None,
               entry: Optional[Dict[str, Any]] = None, **extra: Any) -> Dict[str, Any]:
        """Append (or update, when `entry` is given) one result and emit its
        event. `extra` carries what the UI shows (id, reason, drift...)."""
        if entry is None:
            entry = {"kind": kind, "name": name}
            self.results.append(entry)
        if outcome is not None and outcome.code == STOPPED and status == "failed":
            # Never sent: not a failure of this object, a consequence of the stop.
            status = "skipped"
            extra.setdefault("reason", outcome.error)
            extra["error"] = None
        entry["status"] = status
        if channel:
            entry["channel"] = channel
        if outcome is not None:
            if outcome.ok and outcome.id is not None and "id" not in extra:
                entry["id"] = outcome.id
            if not outcome.ok and "error" not in extra:
                entry["error"] = outcome.as_error()
            if outcome.attempts > 1:
                entry["attempts"] = outcome.attempts
            if outcome.code:
                entry["code"] = outcome.code
            if outcome.http_status:
                entry["http_status"] = outcome.http_status
        for k, v in extra.items():
            if v is None:
                entry.pop(k, None)
            else:
                entry[k] = v
        if status not in ("failed", "still_present"):
            entry.pop("error", None)
            entry.pop("explanation", None)
        else:
            # The HTTP status in words first (a 403 and a 429 look alike in a
            # log and call for opposite fixes), then what ZIA's message means.
            label = http_label(entry.get("http_status"), entry.get("error"), entry.get("code"))
            why = explain(entry.get("error"))
            text = ". ".join(x for x in (label, why) if x)
            if text:
                entry["explanation"] = text
        event = {"ts": time.time(), "run": self.run, "op": op, "kind": kind, "channel": channel, "name": name, "id": entry.get("id"),
                 "status": status, "error": entry.get("error"), "explanation": entry.get("explanation"), "reason": entry.get("reason"),
                 "code": entry.get("code"), "http_status": entry.get("http_status"), "attempts": entry.get("attempts", 1)}
        self.events.append(event)
        detail = entry.get("error") or entry.get("reason")
        line = f"[{kind}] {name}: {status}" + (f" — {detail}" if detail else "") + (f" What this means: {entry['explanation']}" if entry.get("explanation") else "")
        if self.log:
            self.log(line)
        logger.info(line, extra={k: v for k, v in event.items() if k != "ts"})
        return entry

    def counts(self) -> Dict[str, int]:
        out: Dict[str, int] = {}
        for r in self.results:
            out[r["status"]] = out.get(r["status"], 0) + 1
        return out


# ---------------------------------------------------------------------------
# Writes — the only place SDK write methods are named
# ---------------------------------------------------------------------------

def create(zia, kind: str, payload: Dict[str, Any], *, channel: Optional[str] = None, parent_id: Any = None,
           name: str = "", log: Optional[Callable[[str], None]] = None) -> Outcome:
    """Create one object of `kind` from its API payload."""
    name = name or str(payload.get("name") or "")
    if kind == "dictionary":
        p = dict(payload)
        return call(zia.dlp_dictionary.add_dict, p.pop("name"), p.pop("custom_phrase_match_type"), p.pop("dictionary_type", "PATTERNS_AND_PHRASES"),
                    op="create", kind=kind, name=name, log=log, kw=p)
    if kind == "engine":
        return call(zia.dlp_engine.add_dlp_engine, op="create", kind=kind, name=name, log=log, kw=payload)
    if kind == "app_group":
        return call(pc.add_app_group, zia, payload, op="create", kind=kind, name=name, log=log)
    if kind == "policy":
        if parent_id is not None:
            return call(pc.add_sub_rule, zia, parent_id, payload, op="create", kind=kind, name=name, channel=channel, log=log)
        return call(pc.add_rule, zia, channel, payload, op="create", kind=kind, name=name, channel=channel, log=log)
    return Outcome(False, error=f"unknown object kind '{kind}'")


def update(zia, kind: str, oid: Any, payload: Dict[str, Any], *, channel: Optional[str] = None, parent_id: Any = None,
           name: str = "", log: Optional[Callable[[str], None]] = None) -> Outcome:
    """Overwrite one existing object of `kind` with its API payload."""
    name = name or str(payload.get("name") or "")
    if kind == "dictionary":
        return call(zia.dlp_dictionary.update_dict, oid, op="update", kind=kind, name=name, log=log, kw=payload)
    if kind == "engine":
        return call(zia.dlp_engine.update_dlp_engine, oid, op="update", kind=kind, name=name, log=log, kw=payload)
    if kind == "app_group":
        return call(pc.update_app_group, zia, oid, payload, op="update", kind=kind, name=name, log=log)
    if kind == "policy":
        if parent_id is not None:
            return call(pc.update_sub_rule, zia, parent_id, oid, payload, op="update", kind=kind, name=name, channel=channel, log=log)
        return call(pc.update_rule, zia, channel, oid, payload, op="update", kind=kind, name=name, channel=channel, log=log)
    return Outcome(False, error=f"unknown object kind '{kind}'")


def delete(zia, item: Dict[str, Any], *, log: Optional[Callable[[str], None]] = None) -> Outcome:
    """Delete one object described by {kind, id, channel, parent_id, type}."""
    kind, channel, oid = item["kind"], item.get("channel"), item["id"]
    name = str(item.get("name") or "")
    if kind == "dictionary":
        return call(zia.dlp_dictionary.delete_dict, oid, op="delete", kind=kind, name=name, log=log)
    if kind == "engine":
        return call(zia.dlp_engine.delete_dlp_engine, oid, op="delete", kind=kind, name=name, log=log)
    if kind == "app_group":
        return call(pc.raw_request, zia, "DELETE", f"{pc.APP_GROUPS_PATH}/{oid}", op="delete", kind=kind, name=name, log=log)
    if kind != "policy":
        return Outcome(False, error=f"unknown object kind '{kind}'")
    if channel == pc.ENDPOINT and item.get("parent_id") is not None:
        return call(pc.raw_request, zia, "DELETE", f"/endPointDlpRules/{item['parent_id']}/subRule/{oid}", op="delete", kind=kind, name=name, channel=channel, log=log)
    if channel == pc.CLOUD_APP:
        return call(zia.cloudappcontrol.delete_rule, str(item.get("type") or "").upper() or "ANY", oid, op="delete", kind=kind, name=name, channel=channel, log=log)
    svc = getattr(zia, pc.CHANNELS[channel]["service"], None)
    if svc is None:
        return Outcome(False, error=f"{pc.CHANNELS[channel]['service']} is not available in the installed zscaler-sdk-python")
    if channel == pc.SAAS:
        # The SaaS Security API delete wants the rule's type (ruleType);
        # without it the API refuses and the rule silently survives.
        rtype = item.get("type") or item.get("saas_type") or pc.saas_rule_type(zia, oid)
        if rtype:
            return call(svc.delete_rule, oid, op="delete", kind=kind, name=name, channel=channel, log=log, kw={"rule_type": rtype})
    return call(svc.delete_rule, oid, op="delete", kind=kind, name=name, channel=channel, log=log)


# ---------------------------------------------------------------------------
# Identity check and activation
# ---------------------------------------------------------------------------

def current_names(zia, kind: str, channel: Optional[str]) -> Tuple[Optional[Dict[str, str]], Optional[str]]:
    """id → name for the objects of a kind/channel as the tenant has them
    now, so a delete only touches an id that still carries the name the
    pack gave it. Sub-rules are read through their parents."""
    try:
        if kind == "dictionary":
            data, err = pc._nx(zia.dlp_dictionary.list_dicts())
        elif kind == "engine":
            data, err = pc._nx(zia.dlp_engine.list_dlp_engines())
        elif kind == "app_group":
            groups, gerr = pc.list_app_groups(zia)
            return ({str(g.get("id")): n for n, g in (groups or {}).items()}, gerr)
        else:
            svc = getattr(zia, pc.CHANNELS[channel]["service"], None)
            if svc is None:
                return None, "service unavailable"
            if channel == pc.SAAS:
                lister = getattr(svc, "list_all_rules", None)
                data, err = pc._nx(lister()) if lister else pc._nx(svc.list_rules("ANY"))
            elif channel == pc.CLOUD_APP:
                data = []
                for t in pc.CLOUD_APP_TYPES:
                    part, perr = pc._nx(svc.list_rules(t))
                    if not perr:
                        data.extend(part or [])
                err = None
            else:
                data, err = pc._nx(svc.list_rules())
        if err:
            return None, str(err)[:200]
        out: Dict[str, str] = {}
        for r in data or []:
            out[str(pc._field(r, "id"))] = str(pc._field(r, "name", default="") or "")
            if channel == pc.ENDPOINT:
                for sr in (pc._field(r, "sub_rules", "subRules", default=[]) or []):
                    out[str(pc._field(sr, "id"))] = str(pc._field(sr, "name", default="") or "")
        return out, None
    except Exception as e:  # noqa: BLE001
        return None, str(e)[:200]


def activate_and_settle(zia, seconds: float, log: Optional[Callable[[str], None]] = None) -> Dict[str, Any]:
    """Activate pending changes and wait for ZIA to report ACTIVE."""
    _log = log or (lambda m: None)
    act = pc.activate(zia)
    _log("Activation " + ("requested." if act.get("activated") else f"could not run: {act.get('error')}"))
    status = pc.wait_active(zia, seconds, _log) if act.get("activated") else None
    act["settled_status"] = status
    if status:
        _log(f"Activation status: {status}.")
    return act
