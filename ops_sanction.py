"""Cloud application sanction: mark cloud applications Sanctioned or
Unsanctioned as one operation type on the Bulk changes engine
(admin_ops.register).

A cloud application's sanction state is the organisation's decision about
whether the business may use it. It is tenant-wide: it changes the Shadow
IT report for every user and every policy or report that groups apps by it,
so the plan always asks for the typed phrase, whatever the count.

  cloud_app_sanction   set up to MAX_TARGETS applications to sanctioned or
                       unsanctioned. Undo sets each application back to the
                       state it had before (read in the plan, checked again
                       right before the write).

The engine gives it the same path as every bulk change: the scope check
(`in_scope`: ZIA platform and ZIA Insights ticked) before anything is read,
a plan that only reads, the plan hash, the re-plan before writing, write
mode, the writer, the assessor and the typed confirmation, a re-read right
before the write (`_h_sanction`: an application whose state moved since the
preview is a conflict and is not sent), the read-back (`verify`), the
record, the audit log with the actor and Undo (`inverse`). The write goes
through pack_ops.update (kind cloud_app_sanction), which paces, retries,
stops and audits it.

What is verified and what is assumed
------------------------------------
Verified in zscaler-sdk-python 1.11.3:
  zia.shadow_it_report.list_apps()           GET /cloudApplications/lite: the
                                             application list (id, name)
  shadow_it_report bulk update (through pack_ops.update, kind
                cloud_app_sanction)          PUT /cloudApplications/bulkUpdate
                                             {sanctionedState: SANCTIONED |
                                             UN_SANCTIONED, applicationIds}
  zins.shadow_it.get_apps(..., filter_by=ShadowITAppsFilterBy(application=
                StringFilter(in_list=[names])))
                                             each application's
                                             sanctioned_state (Z-Insights)

ASSUMED (not stated by the SDK, not checked against a live tenant):
  - the current state: the SDK's list_apps model keeps id and name only, so
    the state is read from the list's raw answer when a row carries one
    (sanctionedState / sanctioned_state / sanctionState) and otherwise from
    Z-Insights' Shadow IT applications (last 30 days), matched by the
    application's name. An application neither source states (no traffic in
    30 days) is excluded: without its state there is no exact Undo;
  - the spelling of the states in those answers (insights.sanction_of);
  - that list_apps without page parameters returns every application;
  - that bulk_update without customTags leaves the applications' tags as
    they are, and that the change waits for activation like other ZIA
    changes (the engine activates once at the end).
"""
from __future__ import annotations

import re
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple

import admin_ops as ao
import insights
import pack_ops as ops

T_SANCTION = "cloud_app_sanction"
FAMILY = "cloud_apps"
MAX_TARGETS = 100
MAX_LISTED = 2000             # applications the picker lists (those with a known state)
STATE_WINDOW = "30d"
STATES = (insights.SANCTIONED, insights.UNSANCTIONED)
STATE_WORD = {insights.SANCTIONED: "Sanctioned", insights.UNSANCTIONED: "Unsanctioned"}
_RAW_STATE_KEYS = ("sanctionedState", "sanctioned_state", "sanctionState")   # ASSUMED field names on the list's raw rows
_NAME_MAX = 200
_ID_RE = re.compile(r"^\d{1,19}$")

NOT_IN_SCOPE = ("Not in scope: cloud application sanction needs ZIA platform (the application list and the change) and "
                "ZIA Insights (each application's current state) ticked on the Scope page. Nothing was read.")
TENANT_WIDE = ("Tenant-wide: an application's sanction state changes the Shadow IT report for every user and every policy or "
               "report that groups applications by it. Marking an app unsanctioned does not block it by itself: block or "
               "isolate it in Cloud App Control.")
ASSUMED_NOTE = ("The current state is read from ZIA Insights' Shadow IT applications (last 30 days), matched by name; the SDK's "
                "application list carries no state. An application with no traffic in that window has no known state and is "
                "not changed here, so every change has an exact Undo.")


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    sc = set(scope.get("scopes") or [])
    return None if {"zia_extras", "insights"} <= sc else NOT_IN_SCOPE


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _text(v: Any) -> str:
    return insights._text(v)[:_NAME_MAX]


def _err(e: Any) -> str:
    try:
        return ops.describe_error(e)[:240]
    except Exception:  # noqa: BLE001
        return f"{type(e).__name__}"


def read_catalogue(zia: Any) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """{id: {id, name, state}} from list_apps; state from the raw row when it
    carries one (ASSUMED field names), else None."""
    svc = getattr(zia, "shadow_it_report", None) if zia is not None else None
    if svc is None:
        return {}, "the cloud application list is not available on this sign-in"
    try:
        ret = svc.list_apps()
    except Exception as e:  # noqa: BLE001
        return {}, _err(e)
    if not isinstance(ret, tuple) or len(ret) != 3:
        return {}, "the SDK gave an answer of an unexpected shape"
    apps, resp, err = ret
    if err is not None:
        return {}, _err(err)
    raw: List[Any] = []
    try:
        body = resp.get_body() if resp is not None and callable(getattr(resp, "get_body", None)) else None
        raw = body if isinstance(body, list) else []
    except Exception:  # noqa: BLE001
        raw = []
    raw_state = {}
    for r in raw:
        if isinstance(r, dict) and r.get("id") is not None:
            st = next((insights.sanction_of(r.get(k)) for k in _RAW_STATE_KEYS if r.get(k) is not None), None)
            raw_state[str(r.get("id"))] = st
    out: Dict[str, Dict[str, Any]] = {}
    for a in apps or []:
        d = a.as_dict() if callable(getattr(a, "as_dict", None)) else a if isinstance(a, dict) else {}
        aid = str(d.get("id") if d.get("id") is not None else "")
        if not _ID_RE.match(aid):
            continue
        out[aid] = {"id": aid, "name": _text(d.get("name")), "state": raw_state.get(aid)}
    return out, None


def read_usage(zins: Any, names: Optional[List[str]] = None, now_ms: Optional[int] = None) -> Tuple[Dict[str, Dict[str, Any]], Optional[str]]:
    """{application name: Shadow IT row} for the last 30 days (optionally only
    `names`), or the reason Insights could not answer. Aggregates only."""
    if zins is None:
        return {}, "ZIA Insights is not available on this sign-in (it needs a OneAPI API client)"
    w = insights.window(STATE_WINDOW, now_ms=now_ms)
    kw: Dict[str, Any] = {"start_time": w["start_ms"], "end_time": w["end_ms"], "limit": MAX_LISTED}
    if names:
        from zscaler.zins.models.inputs import ShadowITAppsFilterBy, StringFilter
        kw.update(filter_by=ShadowITAppsFilterBy(application=StringFilter(in_list=sorted(set(names)))), limit=max(1, len(set(names))))
    try:
        ret = zins.shadow_it.get_apps(**kw)
    except Exception as e:  # noqa: BLE001
        return {}, _err(e)
    if not isinstance(ret, tuple) or len(ret) != 3:
        return {}, "the SDK gave an answer of an unexpected shape"
    data, _resp, err = ret
    if err is not None:
        return {}, insights._messages(err)[0][:240]
    return {r["application"]: r for r in insights.app_rows(data, MAX_LISTED)}, None


def _zins(client: Any) -> Any:
    try:
        return getattr(client, "zins", None)
    except Exception:  # noqa: BLE001 — the classic sign-in has no Z-Insights client
        return None


def current(client: Any, names: Optional[List[str]] = None) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, str]]:
    """{id: {id, name, state, risk_index, data_consumed, ...}} and the read errors."""
    cat, cerr = read_catalogue(getattr(client, "zia", None))
    errors: Dict[str, str] = {}
    if cerr:
        errors["cloud_applications"] = cerr
        return {}, errors
    use, uerr = read_usage(_zins(client), names)
    if uerr:
        errors["insights"] = uerr
    for a in cat.values():
        u = use.get(a["name"]) or {}
        if a["state"] is None:
            a["state"] = insights.sanction_of(u.get("sanctioned_state"))
        a.update({k: u.get(k) for k in ("application_category", "risk_index", "data_consumed", "data_uploaded", "authenticated_users")})
    return cat, errors


def read_objects(client: Any, scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    say("Reading the cloud application list and the Shadow IT applications of the last 30 days (ZIA Insights)…")
    apps, errors = current(client)
    known = [a for a in apps.values() if a["state"] in STATES]
    known.sort(key=lambda a: (-(a.get("risk_index") or 0), -(a.get("data_consumed") or 0), a["name"].lower()))
    say(f"{len(apps)} cloud application(s); {len(known)} with a known sanction state.")
    return {"apps": known[:MAX_LISTED], "catalogue": len(apps), "unknown": len(apps) - len(known), "errors": errors,
            "note": ASSUMED_NOTE, "tenant_wide": TENANT_WIDE}


# ---------------------------------------------------------------------------
# Plan
# ---------------------------------------------------------------------------

def _state(v: Any) -> str:
    s = insights.sanction_of(v)
    if s is None:
        raise ao.OperationError("Each application needs a state: sanctioned or unsanctioned.")
    return s


def _clean_targets(raw: Any) -> List[Dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        raise ao.OperationError("Pick at least one cloud application.")
    if len(raw) > MAX_TARGETS:
        raise ao.OperationError(f"At most {MAX_TARGETS} cloud applications per operation; this one names {len(raw)}. Split it.")
    out, seen = [], set()
    for t in raw:
        if not isinstance(t, dict):
            raise ao.OperationError("Each application must be an object with an id and a state.")
        aid = str(t.get("id") if t.get("id") is not None else "").strip()
        if not _ID_RE.match(aid):
            raise ao.OperationError("A cloud application id must be a number.")
        if aid in seen:
            continue
        seen.add(aid)
        out.append({"id": aid, "name": _text(t.get("name")), "to": _state(t.get("to"))})
    return out


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: Callable[[str], None], cancel: Optional[threading.Event]) -> Dict[str, Any]:
    targets = _clean_targets(spec.get("targets"))
    nspec = {"type": T_SANCTION, "targets": targets}
    say("Reading the cloud application list and each application's current state…")
    cat, cerr = read_catalogue(getattr(client, "zia", None))
    blockers: List[str] = []
    if cerr:
        blockers.append(f"The cloud application list could not be read ({cerr}), so nothing can be planned.")
    names = [cat[t["id"]]["name"] for t in targets if t["id"] in cat]
    use, uerr = ({}, None) if cerr or not names else read_usage(_zins(client), names)
    if uerr and not cerr:
        blockers.append(f"ZIA Insights could not be read ({uerr}), so the applications' current state is unknown and no exact Undo "
                        "is possible. Nothing is planned.")
    items: List[Dict[str, Any]] = []
    groups: Dict[str, Dict[str, Any]] = {}
    for t in targets:
        key = f"app:{t['id']}"
        app = cat.get(t["id"])
        obj = {"type": "cloud_application", "policy_label": "Cloud application", "id": t["id"], "name": (app or {}).get("name") or t["name"]}
        if app is None:
            items.append(ao._unit(key, "", "cloud_app_sanction", obj, "sanction", None, t["to"], status="excluded",
                                  reason="not in the tenant's cloud application list now" if not cerr else "the application list could not be read"))
            continue
        if t["name"] and t["name"] != app["name"]:
            items.append(ao._unit(key, "", "cloud_app_sanction", obj, "sanction", None, t["to"], status="excluded",
                                  reason=f"the application with this id is now called '{app['name']}', not '{t['name']}'"))
            continue
        before = app["state"] if app["state"] is not None else insights.sanction_of((use.get(app["name"]) or {}).get("sanctioned_state"))
        if before is None:
            items.append(ao._unit(key, "", "cloud_app_sanction", obj, "sanction", None, t["to"], status="excluded",
                                  reason="its current state could not be read (ZIA Insights states none for it in the last 30 days), so "
                                         "it would have no exact Undo; change it in the ZIA Admin Portal"))
            continue
        if before == t["to"]:
            items.append(ao._unit(key, "", "cloud_app_sanction", obj, "sanction", before, t["to"], status="noop", reason=f"already {before}"))
            continue
        g = groups.setdefault(t["to"], {"key": f"sanction:{t['to']}", "handler": "cloud_app_sanction", "target": {"to": t["to"], "apps": []}})
        g["target"]["apps"].append({"id": t["id"], "name": app["name"]})
        items.append(ao._unit(key, g["key"], "cloud_app_sanction", obj, "sanction", before, t["to"]))
    n = sum(1 for u in items if u["status"] == "change")
    tos = sorted({t["to"] for t in targets})
    verb = {"sanctioned": "Sanction", "unsanctioned": "Unsanction"}.get(tos[0], "Set the sanction of") if len(tos) == 1 else "Set the sanction of"
    return {"type": T_SANCTION, "product": "zia", "spec": nspec, "items": items, "groups": list(groups.values()),
            "title": f"{verb} {n} cloud application{'s' if n != 1 else ''}", "warnings": [TENANT_WIDE], "blockers": blockers,
            "notes": [ASSUMED_NOTE], "confirm_always": f"CHANGE {n} CLOUD APPS" if n else ""}


# ---------------------------------------------------------------------------
# Write, read-back, Undo
# ---------------------------------------------------------------------------

def _h_sanction(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    """Re-read every application's state right before the one write; an
    application that moved since the preview is a conflict and is not sent."""
    t = g["target"]
    apps, errors = current(run.client, [a["name"] for a in t["apps"]])
    if errors:
        why = "; ".join(f"{k}: {v}" for k, v in errors.items())
        run.mark(units, "failed", "", error=f"could not read the applications again before the change: {why}"[:300])
        run.counts["failed"] += 1
        return
    send: List[Dict[str, Any]] = []
    for u in units:
        now = (apps.get(str(u["object"]["id"])) or {})
        if not now:
            run.mark([u], "conflict", "no longer in the cloud application list; left as it is")
            run.counts["skipped"] += 1
        elif now.get("name") != u["object"]["name"]:
            run.mark([u], "conflict", f"renamed to '{now.get('name')}' since the preview; left as it is")
            run.counts["skipped"] += 1
        elif now.get("state") != u["before"]:
            run.mark([u], "conflict", f"changed in the tenant since the preview: it is {now.get('state') or 'not stated'} now, the preview read "
                                      f"{u['before']}; left as it is")
            run.counts["skipped"] += 1
        else:
            send.append(u)
    if not send:
        return
    ids = [int(u["object"]["id"]) for u in send]
    names = ", ".join(u["object"]["name"] for u in send[:5]) + (f" and {len(send) - 5} more" if len(send) > 5 else "")
    out = ops.update(run.zia, "cloud_app_sanction", ",".join(str(i) for i in ids)[:200], {"application_ids": ids}, name=names, log=run.log,
                     action=t["to"])
    if run.outcome(send, out, "update"):
        run.wrote_zia = True
        run.log(f"{len(send)} cloud application(s) → {STATE_WORD[t['to']]}: {names}")


HANDLERS = {"cloud_app_sanction": _h_sanction}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    apps, errors = current(run.client, [u["object"]["name"] for u in applied])
    if errors:
        out["unread"].append("; ".join(f"{k}: {v}" for k, v in errors.items()))
        for u in applied:
            u["verified"] = None
        return out
    for u in applied:
        out["checked"] += 1
        now = (apps.get(str(u["object"]["id"])) or {}).get("state")
        u["verified"] = now == u["after"]
        if u["verified"]:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{u['object']['name']}: reads {now or 'not stated'} back, not {u['after']} (ZIA Insights may show "
                                     "the new state a little later; read again before acting on it)")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Each applied application back to the state the plan read before."""
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied" and u.get("before") in STATES]
    if not applied:
        return None
    return {"type": T_SANCTION, "targets": [{"id": str(u["object"]["id"]), "name": u["object"]["name"], "to": u["before"]} for u in applied]}


def _register() -> None:
    ao.register(T_SANCTION, family=FAMILY, product="zia", group="Change existing", script="ops_sanction.js",
                label="Sanction or unsanction cloud apps",
                hint=("Mark up to 100 cloud applications Sanctioned or Unsanctioned, with each one's current state, risk and traffic "
                      "from ZIA Insights. Tenant-wide: the typed phrase is always asked, and Undo puts each app back as it was. Needs "
                      "ZIA platform and ZIA Insights ticked on the Scope page."),
                in_scope=in_scope, plan=plan, read_objects=read_objects, handlers=HANDLERS, verify=verify, inverse=inverse)


_register()
