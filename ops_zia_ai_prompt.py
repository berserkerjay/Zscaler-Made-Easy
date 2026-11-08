"""AI prompt capture on the Bulk changes engine (admin_ops plugin): a dedicated
builder for the GenAI prompt-capture switches, one operation type under
"Build new":

  zia_ai_prompt_capture  Reads the URL and Cloud App Control advanced settings
                         (GET /advancedUrlFilterAndCloudAppSettings through
                         ai_guard.read_app_settings), lists every prompt
                         switch the tenant has (enable<App>Prompt) with the
                         app it belongs to and whether it is on, and turns the
                         ones the operator picks on or off. Nothing is
                         pre-picked: a switch is only changed when named.

Prompt capture records what users type into GenAI apps, so every change asks
the typed phrase CAPTURE PROMPTS, needs the Gen AI Security subscription to
turn a switch ON (turning one off is always allowed), refuses a settings
object it could only read in part (a partial PUT could reset other settings),
and writes the whole object back as re-read with only the picked switches
changed. Undo puts the previous values back. A switch the tenant's settings
do not carry is refused, never invented. The detection rules that use the
captured prompts (AI Guard policies) are the AI Guard builders' work.

ZIA calls: zia.url_filtering.get_url_and_app_settings / update_url_and_app_settings
(SDK 1.11.3), the same path the UCaaS and AI Guard routing builders use.
ASSUMED (the SDK model lists only six prompt fields; the others come from
AI Guard's own app table): the tenant accepts the enable<App>Prompt names it
returns.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, List, Optional

import admin_ops as ao
import ai_guard as ag
import pack_ops as ops

TYPE = "zia_ai_prompt_capture"
FAMILY = "zia_ai_prompt_capture_settings"
SCRIPT = "ops_zia_ai_prompt.js"
PHRASE = "CAPTURE PROMPTS"
ZIA_AREAS = ("dlp", "zia_extras")
SWITCH_RE = re.compile(r"^enable\w+Prompt$")
NOT_IN_SCOPE = "Not in scope: AI prompt capture needs a ZIA area ticked on the Scope page (DLP or ZIA platform)."
PRIVACY = ("Prompt capture records what people type into the GenAI app, so it can hold personal or confidential text. It is live as "
           "soon as ZIA activates the change; agree it with privacy and legal first.")
_REF = {"type": "settings", "area": "ai_prompt", "policy_label": "AI prompt capture", "id": None, "name": "URL and Cloud App Control advanced settings"}
LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    given = set(scope.get("scopes") or [])
    return None if scope.get("policies") or given & set(ZIA_AREAS) else NOT_IN_SCOPE


def _app_of(field: str) -> str:
    for a in ag.AI_APPS:
        if a.get("prompt") == field:
            return a["name"]
    return re.sub(r"(?<!^)(?=[A-Z])", " ", field[len("enable"):-len("Prompt")]) or field


def _read(zia: Any) -> Dict[str, Any]:
    settings, complete, err = ag.read_app_settings(zia)
    if err or settings is None:
        raise ao.OperationError(f"The URL and Cloud App Control settings could not be read ({(err or 'no answer')[:160]}). Nothing was planned.")
    if not complete:
        raise ao.OperationError("Only part of the URL and Cloud App Control settings could be read, so they are not written back. Nothing was planned.")
    return settings


def switches(settings: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [{"key": k, "app": _app_of(k), "on": settings[k] is True} for k in sorted(settings) if SWITCH_RE.match(str(k)) and isinstance(settings[k], bool)]


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    say("Reading the URL and Cloud App Control settings and the subscriptions…")
    out: Dict[str, Any] = {"switches": [], "licensed": None, "errors": {}, "privacy": PRIVACY, "phrase": PHRASE}
    try:
        out["switches"] = switches(_read(client.zia))
    except ao.OperationError as e:
        out["errors"]["settings"] = str(e)
    lic, _ids, err = ag.read_subscriptions(client.zia)
    out["licensed"] = lic
    if err:
        out["errors"]["subscriptions"] = err
    return out


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    extra = sorted(str(k)[:20] for k in spec if k not in ("type", "switches"))
    if extra:
        raise ao.OperationError(f"Unknown setting(s): {', '.join(extra[:3])}.")
    sw = spec.get("switches")
    if not isinstance(sw, dict) or not sw:
        raise ao.OperationError("Name at least one prompt switch and true (capture) or false (do not): nothing is pre-picked.")
    if len(sw) > 50:
        raise ao.OperationError("At most 50 switches at once.")
    for k, v in sw.items():
        if not SWITCH_RE.match(str(k)):
            raise ao.OperationError(f"{str(k)[:40]} is not a prompt-capture switch (enable<App>Prompt).")
        if not isinstance(v, bool):
            raise ao.OperationError(f"{k} must be true or false.")
    return {"type": TYPE, "switches": dict(sw)}


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    say("Reading the URL and Cloud App Control settings…")
    cur = _read(client.zia)
    ao._check_stop(cancel)
    P: Dict[str, Any] = {"type": TYPE, "product": "zia", "title": "AI prompt capture", "spec": n, "items": [], "groups": [], "blockers": [],
                         "warnings": [PRIVACY], "confirm_always": PHRASE,
                         "notes": ["Reads GET /advancedUrlFilterAndCloudAppSettings, then writes the whole object back as re-read with only "
                                   "the picked switches changed, then reads it back. Undo puts the old values back."]}
    fields: Dict[str, bool] = {}
    turning_on = False
    for k, want in sorted(n["switches"].items()):
        if not isinstance(cur.get(k), bool):
            P["items"].append(ao._unit(f"sw:{k}", "prompt", "ai_prompt", dict(_REF), k, None, want, status="excluded",
                                       reason="this tenant's settings have no such switch"))
        elif cur[k] == want:
            P["items"].append(ao._unit(f"sw:{k}", "prompt", "ai_prompt", dict(_REF), k, cur[k], want, status="noop", reason="already so"))
        else:
            P["items"].append(ao._unit(f"sw:{k}", "prompt", "ai_prompt", dict(_REF), k, cur[k], want, value=want))
            fields[k] = want
            turning_on = turning_on or want
    if turning_on:
        lic, _ids, err = ag.read_subscriptions(client.zia)
        if not lic:
            P["blockers"].append("Turning prompt capture on needs the Gen AI Security subscription, " +
                                 (f"and the subscriptions could not be read ({err})." if err else "which this tenant does not have."))
    if not fields:
        P["blockers"].append("Nothing to change: every named switch is already so, or the tenant has no such switch.")
    elif not P["blockers"]:
        P["groups"].append({"key": "prompt", "handler": "prompt_write", "target": {"fields": fields}})
    return P


def h_write(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    try:
        cur = _read(run.zia)
    except ao.OperationError as e:
        run.mark(units, "failed", "", error=f"could not read the settings again before writing: {e}"[:300])
        run.counts["failed"] += 1
        return
    moved = [u["field"] for u in units if cur.get(u["field"]) != u["before"]]
    if moved:
        run.mark(units, "conflict", f"{', '.join(moved)} changed in ZIA since the preview; nothing was sent")
        run.counts["skipped"] += len(units)
        return
    body = dict(cur)
    for u in units:
        body[u["field"]] = u["after"]
    out = ops.update(run.zia, "url_app_settings", None, body, name="AI prompt capture", log=run.log)
    ops._audit_write("update", "url_app_settings", None, "AI prompt capture", None, out)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True


HANDLERS = {"prompt_write": h_write}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    units = [u for u in run.p["items"] if u["status"] == "applied"]
    if not units:
        return out
    try:
        cur = _read(run.zia)
    except ao.OperationError as e:
        out["unread"].append(str(e)[:200])
        for u in units:
            u["verified"] = None
        return out
    for u in units:
        out["checked"] += 1
        u["verified"] = cur.get(u["field"]) == u["after"]
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['field']}: reads back {cur.get(u['field'])}, not {u['after']}")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    back = {u["field"]: u["before"] for u in result.get("items") or [] if u.get("status") == "applied" and isinstance(u.get("before"), bool)}
    return {"type": TYPE, "switches": back} if back else None


ao.register(TYPE, family=FAMILY, product="zia", label="AI prompt capture", plan=plan, read_objects=read_objects, in_scope=in_scope,
            handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Build new",
            hint=("Turns the GenAI prompt-capture switches on or off, one per app, each before and after. Nothing is pre-picked; "
                  "CAPTURE PROMPTS typed every time; turning one on needs the Gen AI Security subscription; Undo puts the old values back. "
                  "Needs DLP or ZIA platform ticked on the Scope page."))
