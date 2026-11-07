"""Apply a block page theme to ZIA's end-user notification settings, on the
Bulk changes engine (admin_ops plugin). One operation type, under "Build new":

  zia_eun_theme  Reads GET /eun, compares it with the settings a saved theme
                 (block_page_theme.py) produces, and lists each field that
                 would change, before and after. Applying sends one
                 PUT /eun carrying the object as read with only those
                 fields changed. Undo puts the old values back.

The preview and the generated HTML are made locally and read-only
(block_page_theme.generate); nothing here runs unless the operator reaches
the engine's apply step: write mode on (it is off by default), a named
assessor, the plan hash matching a fresh re-plan, and the typed phrase
APPLY EUN asked every time (end users see the page as soon as the change is
activated). The logo image is not part of the call: no logo field exists in
the settings (assumed, the SDK lists none).

ZIA calls: GET /eun and PUT /eun, the SDK's end_user_notification service
(zscaler-sdk-python 1.11.3: get_eun_settings, update_eun_settings). Its
get_eun_settings names an undefined model class, so the read
and the write go through pack_channels (get_eun) and pack_ops.update (kind zia_eun). The
camelCase names are the attributes update_eun_settings documents (the
snake_case list in its docstring, camelCased: assumed, not checked against a
live tenant).
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional

import admin_ops as ao
import block_page_theme as bpt
import pack_channels as pc
import pack_ops as ops

TYPE = "zia_eun_theme"
FAMILY = "zia_eun_settings"
SCRIPT = "ops_zia_eun.js"
PHRASE = "APPLY EUN"
ZIA_AREAS = ("dlp", "zia_extras")
BOOLS = ("displayReason", "displayCompName", "displayCompLogo")
STRINGS = {"customText": 600, "supportEmail": 254, "supportPhone": 30, "orgPolicyLink": 300}
NOT_IN_SCOPE = "Not in scope: the block page settings need a ZIA area ticked on the Scope page (DLP or ZIA platform)."
LOGO_NOTE = ("The logo image is not sent: ZIA's API lists no logo field (assumed). Upload it in the ZIA Admin Portal; the display-logo "
             "switch is part of this change.")
VISIBLE = "End users see the new wording as soon as the change is activated."
LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    given = set(scope.get("scopes") or [])
    return None if scope.get("policies") or given & set(ZIA_AREAS) else NOT_IN_SCOPE


def read_eun(zia: Any) -> Dict[str, Any]:
    data, err = pc.get_eun(zia)
    if err:
        raise ao.OperationError(f"ZIA's end-user notification settings could not be read ({str(err)[:200]}). Nothing was planned.")
    if not isinstance(data, dict):
        raise ao.OperationError("ZIA answered end-user notification settings in a shape this app does not know. Nothing was planned.")
    return data


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """The saved themes and ZIA's current settings for the form (read-only)."""
    themes = []
    for n in bpt.names():
        t = bpt.get(n)
        if t:
            themes.append({"id": n, "name": n, "has_logo": bool(t["logo"])})
    say("Reading ZIA's end-user notification settings…")
    errors: Dict[str, str] = {}
    current: Dict[str, Any] = {}
    try:
        current = {k: v for k, v in read_eun(client.zia).items() if k in bpt.EUN_FIELDS}
    except ao.OperationError as e:
        errors["end_user_notification"] = str(e)
    return {"themes": themes, "current": current, "errors": errors, "visible": VISIBLE, "logo_note": LOGO_NOTE}


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    """{"theme": name} (the saved theme's settings) or {"settings": {...}} (an Undo's exact values)."""
    extra = sorted(str(k)[:20] for k in spec if k not in ("type", "theme", "settings"))
    if extra:
        raise ao.OperationError(f"Unknown setting(s): {', '.join(extra[:3])}.")
    if ("theme" in spec) == ("settings" in spec):
        raise ao.OperationError("Give either the name of a saved theme or the exact settings, not both and not neither.")
    if "theme" in spec:
        try:
            return {"type": TYPE, "theme": bpt.clean_name(spec["theme"])}
        except bpt.ThemeError as e:
            raise ao.OperationError(str(e))
    raw = spec["settings"]
    if not isinstance(raw, dict) or not raw:
        raise ao.OperationError("The settings must be a non-empty object.")
    out: Dict[str, Any] = {}
    for k, v in raw.items():
        if k in BOOLS:
            if not isinstance(v, bool):
                raise ao.OperationError(f"{k} must be true or false.")
        elif k in STRINGS:
            if not isinstance(v, str) or len(v) > STRINGS[k]:
                raise ao.OperationError(f"{k} must be text of at most {STRINGS[k]} characters.")
            if k == "orgPolicyLink" and v and not bpt._LINK_RE.match(v):
                raise ao.OperationError("orgPolicyLink must be an https:// address.")
        else:
            raise ao.OperationError(f"{str(k)[:30]} is not a setting this change can set.")
        out[k] = v
    return {"type": TYPE, "settings": out}


def wanted(n: Dict[str, Any]) -> Dict[str, Any]:
    if "settings" in n:
        return dict(n["settings"])
    t = bpt.get(n["theme"])
    if not t:
        raise ao.OperationError(f"There is no saved theme called '{n['theme']}'. Save one first (nothing was read from the tenant).")
    return bpt.settings_for(t["settings"], t["logo"])


def _obj() -> Dict[str, Any]:
    return {"type": "zia_eun", "policy_label": "End-user notification", "id": None, "name": "End-user notification settings"}


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    want = wanted(n)
    say("Reading ZIA's end-user notification settings…")
    now = read_eun(client.zia)
    ao._check_stop(cancel)
    P: Dict[str, Any] = {"type": TYPE, "product": "zia", "title": "Apply the block page theme", "spec": n, "items": [], "groups": [],
                         "warnings": [VISIBLE, LOGO_NOTE], "blockers": [], "confirm_always": PHRASE,
                         "notes": ["Reads GET /eun, then sends one PUT /eun with the object as read and only the listed fields changed, "
                                   "then reads it back. Undo puts the old values back."]}
    for k in sorted(want):
        before = now.get(k)
        if before == want[k]:
            continue
        P["items"].append(ao._unit(f"eun:{k}", "eun", "zia_eun", _obj(), k, before, want[k], value=want[k]))
    if not P["items"]:
        P["blockers"].append("ZIA already holds these settings: nothing to change.")
        return P
    P["groups"].append({"key": "eun", "handler": "eun_write", "target": {"fields": sorted(u["field"] for u in P["items"])}})
    return P


def h_write(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Re-read, refuse if a field moved since the preview, then one PUT of the whole object with only the planned fields changed."""
    try:
        cur = read_eun(run.zia)
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

    out = ops.update(run.zia, "zia_eun", None, body, name="End-user notification settings", log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True


HANDLERS = {"eun_write": h_write}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    units = [u for u in run.p["items"] if u["status"] == "applied"]
    if not units:
        return out
    try:
        cur = read_eun(run.zia)
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
            out["mismatched"].append(f"{u['field']}: reads back differently from what was sent")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The old values of the fields that were applied. A field ZIA did not state before cannot be put back and is left out."""
    back = {u["field"]: u["before"] for u in result.get("items") or []
            if u.get("status") == "applied" and u.get("before") is not None}
    return {"type": TYPE, "settings": back} if back else None


ao.register(TYPE, family=FAMILY, product="zia", label="Block page theme (end-user notification)", plan=plan, read_objects=read_objects,
            in_scope=in_scope, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Build new",
            hint=("Applies a saved block page theme's wording and switches to ZIA's end-user notification settings: each changed field "
                  "before and after, APPLY EUN typed every time, Undo puts the old values back. The preview and the generated HTML "
                  "are local and read-only. Needs DLP or ZIA platform ticked on the Scope page."))
