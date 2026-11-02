"""Rule editor: create, edit, duplicate and delete one ZIA rule, on the Bulk
changes engine (admin_ops.register), so it shares the scope check before
any read, the preview with its plan hash, the four write gates, the re-plan
before writing, the re-read right before each write (someone else's change
is never overwritten), writes through pack_ops (audited, with the actor),
one ZIA activation, the read-back and a recorded, previewed Undo.

Rule types: URL filtering, Cloud Firewall, SSL inspection, forwarding
control, Inline Web DLP, DNS Control, IPS, File Type Control, Sandbox and
Cloud App Control (rule_editor.POLICY: the form for each, built from the
SDK model, with its validation, payload, placement and preview sentence).
URL filtering, SSL inspection, Cloud App Control, File Type Control and Web
DLP are in scope as the Scope page puts them (admin_ops.scope_for); Cloud
Firewall, forwarding, DNS Control, IPS and Sandbox when ZIA platform is
ticked.

One operation, `rule_edit`, with an action:

  create     a new rule from the form, placed at the top, the bottom, an
             order number or below a rule, with the rank rule_editor.place
             gives it; DISABLED unless "Create it enabled" is ticked.
  update     the fields the form changed (and optionally the state); the
             rest of the rule is sent back as the tenant has it.
  duplicate  a copy of a rule with a new name, right below it, DISABLED,
             keeping its rank.
  delete     one rule; the typed confirmation is DELETE <rule name>.
  revert     only as the Undo of a recorded run (admin_ops.is_undo_only):
             delete what was created (while it is as created), put back
             each field that was changed (while it holds what was set),
             re-create what was deleted (same fields, order, rank, state).

Never changed here: the Default rule, predefined rules and rules this API
client may only read (admin_ops.lock_reason). Applying a change that is
live at once (a rule created enabled, an edit of an enabled rule, turning
one on) needs the typed phrase whatever the number of changes.

Verified against zscaler-sdk-python 1.11.3 (see rule_editor's docstring for
the services and models); writes go through pack_ops.create / update /
delete: kind "policy" with the URL, SSL, Cloud App Control, File Type
Control and Web DLP channels (pack_channels) or the firewall, dns, ips and
sandbox channels (pack_ops.ADMIN_RULE_SERVICES), kind "forwarding_rule"
for forwarding control. The Admin Ranking setting is read through
zia.advanced_settings.get_advanced_settings (GET /zia/advancedSettings,
enableAdminRankAccess, parsed by admin_rank.parse) only when ZIA platform
is ticked.
"""
from __future__ import annotations

import copy
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import admin_ops as ao
import admin_rank
import pack_channels as pc
import pack_ops as ops
import rule_editor as R

TYPE = "rule_edit"
FAMILY = "rule_editor"
ACTIONS_OK = ("create", "update", "duplicate", "delete", "revert")
CHANNEL = {"url_filtering": pc.URL, "ssl_inspection": pc.SSL, "cloud_app_control": pc.CLOUD_APP, "file_type_control": pc.FILE_TYPE,
           "web_dlp": pc.WEB, "firewall": "firewall", "dns_control": "dns", "firewall_ips": "ips", "sandbox": "sandbox"}
# The rule types admin_ops reads itself (its POLICIES keys); the others are read here.
_AO = {"url_filtering", "ssl_inspection", "cloud_app_control", "file_type_control", "web_dlp", "firewall", "dns_control", "firewall_ips"}
MAX_STEPS = 20


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def editable(scope: Dict[str, Any]) -> Tuple[List[str], Dict[str, str]]:
    """(rule types the Scope page puts in scope, {type: why not})."""
    pols = set(scope.get("policies") or [])
    platform = "zia_extras" in set(scope.get("scopes") or [])
    ok, why = [], {}
    for p in R.ORDER:
        if (p in R.PLATFORM and platform) or (p not in R.PLATFORM and p in pols):
            ok.append(p)
        elif p in R.PLATFORM:
            why[p] = f"Not in scope: ZIA platform is not ticked on the Scope page, so {R.POLICY[p]['label']} rules are not read or changed."
        else:
            why[p] = (scope.get("not_in_scope") or {}).get(p) or f"Not in scope on the Scope page: {R.POLICY[p]['label']}."
    return ok, why


def _spec_policies(spec: Dict[str, Any]) -> List[str]:
    if str(spec.get("action") or "") == "revert":
        steps = spec.get("steps") if isinstance(spec.get("steps"), list) else []
        return [str(s.get("policy") or "") for s in steps if isinstance(s, dict)]
    return [str(spec.get("policy") or "")]


def _in_scope(scope: Dict[str, Any], spec: Any = None) -> Optional[str]:
    """Why the editor is out of scope (None when it may run). Given the
    spec, every rule type it names must be in scope: refused before sign-in."""
    ok, why = editable(scope)
    if not ok:
        return ("No rule type the editor changes is in scope on the Scope page: tick DLP (URL filtering, File Type Control, Web DLP; "
                "mark SSL inspection and Cloud App Control as Zscaler) or ZIA platform (Cloud Firewall, forwarding, DNS Control, IPS, Sandbox).")
    if isinstance(spec, dict):
        out = [p for p in _spec_policies(spec) if p in R.POLICY and p not in ok]
        if out:
            return "Not in scope on the Scope page: " + ", ".join(R.POLICY[p]["label"] for p in out) + ". Nothing was read."
    return None


# ---------------------------------------------------------------------------
# Reading (GET only)
# ---------------------------------------------------------------------------

def _err(e: Exception) -> str:
    return f"{type(e).__name__}: {str(e)[:200]}"


def _svc(zia, policy: str):
    name = R.POLICY[policy]["service"]
    svc = getattr(zia, name, None)
    if svc is None:
        raise ao.OperationError(f"The installed zscaler-sdk-python has no {name} service, so {R.POLICY[policy]['label']} rules cannot be read.")
    return svc


def list_rules(zia, policy: str, rule_type: str = "", cancel=None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every rule of one type as snake_case dicts (Cloud App Control: of one rule type, or every type)."""
    try:
        if policy in _AO:
            return ao.read_rules(zia, policy, rule_type=rule_type, cancel=cancel)
        ao._check_stop(cancel)
        return ao._rows(_svc(zia, policy).list_rules())
    except ao.Stopped:
        raise
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], str(e) if isinstance(e, ao.OperationError) else _err(e)


def get_rule(zia, policy: str, rid: Any, rule_type: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One rule, read fresh (with the fields the SDK model leaves out)."""
    try:
        if policy in _AO:
            return ao.get_rule(zia, policy, rid, rule_type)
        return ao._one(_svc(zia, policy).get_rule(rid))
    except Exception as e:  # noqa: BLE001
        return None, str(e) if isinstance(e, ao.OperationError) else _err(e)


def _call_rows(zia, svc: str, method: str) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    fn = getattr(getattr(zia, svc, None), method, None)
    if not callable(fn):
        return [], f"the installed zscaler-sdk-python has no {svc}.{method}"
    try:
        return ao._rows(fn())
    except Exception as e:  # noqa: BLE001
        return [], _err(e)


def _pick(row: Dict[str, Any], keys: Sequence[str]) -> str:
    for k in keys:
        v = row.get(k)
        if v not in (None, ""):
            return str(v)
    return ""


# Users, groups, departments, locations, time intervals and labels are ZIA
# platform objects: read only when ZIA platform is ticked (the app's identity
# lookup has the same rule), whatever rule type names them.
PLATFORM_REFS = frozenset({"users", "groups", "departments", "locations", "location_groups", "time_windows", "labels"})
REF_NOT_IN_SCOPE = "not read: ZIA platform is not ticked on the Scope page"


def refs_allowed(scope: Dict[str, Any]) -> bool:
    return "zia_extras" in set(scope.get("scopes") or [])


def read_refs(zia, keys: Sequence[str], cancel=None, *, platform: bool = True) -> Dict[str, Dict[str, Any]]:
    """{ref: {rows: [{value, name, note}], error, truncated}} for the pickers.
    A DLP engine's row names the dictionaries its expression uses. Without
    `platform` (ZIA platform not ticked) the platform objects are not read."""
    out: Dict[str, Dict[str, Any]] = {}
    for key in sorted(set(keys)):
        ao._check_stop(cancel)
        if key in PLATFORM_REFS and not platform:
            out[key] = {"rows": [], "error": REF_NOT_IN_SCOPE, "truncated": False, "not_in_scope": True}
            continue
        spec = R.REFS[key]
        rows, err = _call_rows(zia, *spec["call"])
        vk, nk = spec.get("value", ("id",)), spec.get("name", ("name", "id"))
        got = []
        for r in rows:
            v = _pick(r, vk)
            if v:
                got.append({"value": v, "name": _pick(r, nk) or v, "row": r})
        got.sort(key=lambda x: x["name"].lower())
        out[key] = {"rows": got[:R.MAX_REF_ROWS], "error": err, "truncated": len(got) > R.MAX_REF_ROWS}
    if "dlp_engines" in out:
        dicts = out.get("dlp_dictionaries") or read_refs(zia, ["dlp_dictionaries"]).get("dlp_dictionaries") or {"rows": []}
        names = {x["value"]: x["name"] for x in dicts["rows"]}
        for x in out["dlp_engines"]["rows"]:
            ids = re.findall(r"D(\d+)\.", str(x["row"].get("engine_expression") or ""))
            used = [names.get(i, f"#{i}") for i in dict.fromkeys(ids)]
            x["note"] = ("uses " + ", ".join(used[:6]) + (" and more" if len(used) > 6 else "")) if used else ""
    for v in out.values():
        for x in v["rows"]:
            x.pop("row", None)
    return out


def refnames(refs: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, str]]:
    return {k: {x["value"]: x["name"] for x in v.get("rows") or []} for k, v in refs.items()}


def read_rank(zia, scope: Dict[str, Any]) -> Dict[str, Any]:
    """The tenant's Admin Ranking setting: only when ZIA platform is ticked
    (admin_rank.SCOPES); a failed read is unknown, never off."""
    if not admin_rank.in_scope(scope.get("scopes") or []):
        return {"state": admin_rank.OUT_OF_SCOPE, "why": admin_rank.NOT_IN_SCOPE_WHY, "source": admin_rank.SOURCE}
    svc = getattr(zia, "advanced_settings", None)
    try:
        row, err = ao._one(svc.get_advanced_settings()) if svc is not None else (None, "no advanced_settings service")
    except Exception as e:  # noqa: BLE001
        row, err = None, _err(e)
    if row is None:
        return {"state": admin_rank.UNKNOWN, "why": f"the advanced settings could not be read ({str(err)[:120]})", "source": admin_rank.SOURCE}
    return admin_rank.parse(row)


# ---------------------------------------------------------------------------
# The spec
# ---------------------------------------------------------------------------

def _rid(v: Any) -> str:
    s = str(v if v is not None else "").strip()
    if not re.fullmatch(r"[0-9]{1,20}", s):
        raise ao.OperationError("Pick the rule from the list (its id is missing or not a ZIA id).")
    return s


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    act = str(spec.get("action") or "").strip().lower()
    if act not in ACTIONS_OK:
        raise ao.OperationError("Say what to do with the rule: create, update, duplicate or delete.")
    if act == "revert":
        steps = spec.get("steps")
        if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS or not all(isinstance(s, dict) for s in steps):
            raise ao.OperationError("An undo lists its steps.")
        return {"type": TYPE, "action": "revert", "steps": steps}
    pol = str(spec.get("policy") or "")
    if pol not in R.POLICY:
        raise ao.OperationError(f"Pick a rule type: {', '.join(R.POLICY[p]['label'] for p in R.ORDER)}.")
    rtype = str(spec.get("rule_type") or "").strip().upper()
    if pol == "cloud_app_control":
        if rtype not in pc.CLOUD_APP_TYPES:
            raise ao.OperationError("Cloud App Control rules belong to an application type: pick one (for example WEBMAIL).")
    else:
        rtype = ""
    n: Dict[str, Any] = {"type": TYPE, "action": act, "policy": pol, "rule_type": rtype}
    if act in ("update", "duplicate", "delete"):
        n["id"] = _rid(spec.get("id"))
    if act in ("create", "update"):
        if not isinstance(spec.get("fields"), dict):
            raise ao.OperationError("The rule's fields must be an object.")
        try:
            n["fields"] = R.validate(pol, spec["fields"], partial=act == "update")
        except R.FormError as e:
            raise ao.OperationError(str(e))
    if act == "create":
        where = spec.get("place") if isinstance(spec.get("place"), dict) else {"at": "bottom"}
        n["place"] = {k: where[k] for k in ("at", "order", "id") if k in where}
        n["enabled"] = spec.get("enabled") is True
    if act == "update" and spec.get("state") not in (None, ""):
        st = str(spec["state"]).upper()
        if st not in ao.STATES:
            raise ao.OperationError("The state must be ENABLED or DISABLED.")
        n["state"] = st
    if act == "duplicate":
        try:
            n["name"] = R._text(spec.get("name"), "The new rule's name", R.NAME_MAX[pol], name=True)
        except R.FormError as e:
            raise ao.OperationError(str(e))
        if not n["name"]:
            raise ao.OperationError("Give the copy a name.")
    if act == "delete":
        n["name"] = str(spec.get("name") or "")[:255]
    return n


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _ref(policy: str, *, rid: Any = None, name: str = "", rule_type: str = "") -> Dict[str, Any]:
    return {"type": "rule", "policy": policy, "policy_label": R.POLICY[policy]["label"], "id": rid, "name": name, "rule_type": rule_type}


def _name_taken(rows: List[Dict[str, Any]], name: str, *, but: Any = None) -> Optional[Dict[str, Any]]:
    want = " ".join(name.split()).casefold()
    return next((r for r in rows if " ".join(str(r.get("name") or "").split()).casefold() == want and str(r.get("id")) != str(but)), None)


def _check_refs(policy: str, values: Dict[str, Any], refs: Dict[str, Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """(blockers: picked objects the tenant does not have, warnings: lists that could not be read to check)."""
    blockers, warnings = [], []
    for k, f in R.fields_of(policy).items():
        ref, v = f.get("ref"), values.get(k)
        if not ref or v in (None, "", []):
            continue
        r = refs.get(ref) or {}
        if r.get("not_in_scope"):
            blockers.append(f"{f['label']}: not in scope (ZIA platform is not ticked on the Scope page), so they are not read or set here.")
            continue
        if r.get("error") or r.get("truncated"):
            warnings.append(f"{f['label']}: the tenant's list could not be read in full to check the names picked ({str(r.get('error') or 'too long')[:120]}).")
            continue
        have = {x["value"] for x in r.get("rows") or []}
        missing = [x for x in (v if isinstance(v, list) else [v]) if str(x) not in have]
        if missing:
            blockers.append(f"{f['label']}: not in the tenant now: {', '.join(str(m) for m in missing[:8])}. Read again and pick from the list.")
    return blockers, warnings


def _fields_table(policy: str, before: Dict[str, Any], after: Dict[str, Any], names: Dict[str, Dict[str, str]], *,
                  only_changed: bool = False) -> List[Dict[str, str]]:
    rows = []
    for k, f in R.fields_of(policy).items():
        b, a = before.get(k), after.get(k)
        if only_changed and b == a:
            continue
        if not only_changed and a in (None, "", []) and b in (None, "", []):
            continue
        rows.append({"field": f["label"], "before": R.show(policy, k, b, names) if before else "—", "after": R.show(policy, k, a, names)})
    return rows


def _confirm(changes: int, live: bool) -> str:
    return f"APPLY {changes} CHANGE{'' if changes == 1 else 'S'}" if live and changes else ""


def _plan(client, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    n = normalize(spec)
    if n["action"] == "revert":
        return _plan_revert(client, n, scope, say, cancel)
    zia = getattr(client, "zia", None)
    if zia is None:
        raise ao.OperationError("This sign-in has no ZIA service, so ZIA rules cannot be read.")
    pol, rtype, act = n["policy"], n["rule_type"], n["action"]
    label = R.POLICY[pol]["label"]
    say(f"Reading the {label} rules{' (' + rtype + ')' if rtype else ''}…")
    rows, err = list_rules(zia, pol, rtype, cancel)
    if err:
        raise ao.OperationError(f"The {label} rules could not be read, so nothing can be planned: {err}")
    by_id = {str(r.get("id")): r for r in rows}
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    notes: List[str] = []
    summary: List[str] = []
    table: List[Dict[str, str]] = []
    confirm = ""
    if act in ("create", "update"):
        values = n["fields"]
    else:
        values = {}
    src = by_id.get(n.get("id", "")) if act != "create" else None
    if act != "create" and src is None:
        raise ao.OperationError(f"That {label} rule is not in the tenant now: read the rules again.")
    lock = ao.lock_reason("url_filtering", src) if src is not None else None
    # The references the preview names and the plan checks.
    show_vals = dict(R.current(pol, src)) if src is not None else {}
    merged = dict(show_vals, **values) if act == "update" else (values if act == "create" else show_vals)
    keys = [R.fields_of(pol)[k]["ref"] for k, v in merged.items() if R.fields_of(pol).get(k, {}).get("ref") and v not in (None, "", [])]
    say("Reading the objects the rule names…")
    refs = read_refs(zia, keys, cancel, platform=refs_allowed(scope))
    names = refnames(refs)
    gk = f"re:{act}:{pol}:{rtype}:{n.get('id', 'new')}"
    if act == "create":
        problems = R.check_rule(pol, values)
        if problems:
            raise ao.OperationError(" ".join(problems))
        b, w = _check_refs(pol, values, refs)
        blockers += b
        warnings += w
        if _name_taken(rows, values["name"]):
            blockers.append(f"A {label} rule named '{values['name']}' already exists. Pick another name.")
        setting = read_rank(zia, scope)
        try:
            pl = R.place(rows, n["place"], setting)
        except R.FormError as e:
            raise ao.OperationError(str(e))
        warnings += pl["warnings"]
        state = "ENABLED" if n["enabled"] else "DISABLED"
        body = R.payload(pol, values, refnames=names, state=state, order=pl["order"], rank=pl["rank"], rule_type=rtype)
        sent = R.sentence(pol, values, names, order=pl["order"], rank=pl["rank"], state=state)
        summary += [sent, f"Placement: order {pl['order']}, {pl['why']}."]
        items.append(ao._unit(gk + ":rule", gk, "rule_create", _ref(pol, name=values["name"], rule_type=rtype), "rule", "absent",
                              f"new rule at order {pl['order']}, rank {pl['rank']}, {state.lower()}"))
        groups.append({"key": gk, "handler": "re_create", "target": {"policy": pol, "rule_type": rtype, "name": values["name"], "payload": body,
                                                                    "check": dict(values, state=state), "above_id": pl["above_id"],
                                                                    "order": pl["order"], "rank": pl["rank"]}})
        table = _fields_table(pol, {}, values, names) + [{"field": "Order", "before": "—", "after": str(pl["order"])},
                                                         {"field": "Admin rank", "before": "—", "after": str(pl["rank"])},
                                                         {"field": "State", "before": "—", "after": state.lower()}]
        confirm = _confirm(1, n["enabled"])
        title = f"Create {label} rule '{values['name']}'"
    elif act == "update":
        title = f"Edit {label} rule '{src.get('name')}'"
        ref = _ref(pol, rid=src.get("id"), name=str(src.get("name") or ""), rule_type=rtype)
        if lock:
            items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "as it is", "as it is", status="excluded", reason=lock))
        else:
            have = R.current(pol, src)
            changes = {k: v for k, v in values.items() if v != have.get(k)}
            after = dict(have, **changes)
            problems = R.check_rule(pol, after)
            if problems:
                raise ao.OperationError(" ".join(problems))
            b, w = _check_refs(pol, changes, refs)
            blockers += b
            warnings += w
            if "name" in changes and _name_taken(rows, changes["name"], but=src.get("id")):
                blockers.append(f"A {label} rule named '{changes['name']}' already exists. Pick another name.")
            state_now = ao._state(src)
            new_state = n.get("state") or state_now
            for k in changes:
                items.append(ao._unit(f"{gk}:{k}", gk, "rule_field", ref, k, R.show(pol, k, have.get(k), names), R.show(pol, k, changes[k], names)))
            if new_state != state_now:
                items.append(ao._unit(f"{gk}:state", gk, "rule_field", ref, "state", state_now, new_state))
            if not changes and new_state == state_now:
                items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "as asked", "as asked", status="noop",
                                      reason="every field is already as the form says"))
            else:
                expect = {k: have.get(k) for k in changes}
                groups.append({"key": gk, "handler": "re_update", "target": {"policy": pol, "rule_type": rtype, "id": src.get("id"),
                                                                            "name": str(src.get("name") or ""), "changes": changes,
                                                                            "expect": expect, "state": new_state, "expect_state": state_now,
                                                                            # the whole rule as previewed: any change to it since moves the plan hash
                                                                            "previewed": have}})
            order, rank = src.get("order"), admin_rank.shown_rank(src)
            summary.append(R.sentence(pol, after, names, order=order, rank=rank if rank is not None else "not set",
                                      state=new_state, verb_tense="will now"))
            if new_state == "DISABLED" and state_now == "DISABLED":
                summary.append("The rule stays disabled: nothing changes for users until it is enabled.")
            table = _fields_table(pol, have, after, names, only_changed=True)
            if new_state != state_now:
                table.append({"field": "State", "before": state_now.lower(), "after": new_state.lower()})
            live = new_state == "ENABLED"
            confirm = _confirm(sum(1 for u in items if u["status"] == "change"), live)
            if live and groups:
                warnings.append("This rule is enabled after the change: it applies to users as soon as ZIA activates, which the app does "
                                "right after the write.")
    elif act == "duplicate":
        title = f"Duplicate {label} rule '{src.get('name')}'"
        ref = _ref(pol, name=n["name"], rule_type=rtype)
        why = ("the Default rule: it is not copied" if ao._is_default(src) else
               "a predefined rule maintained by Zscaler: not copied" if ao._truthy(src.get("predefined")) else
               "read-only for this API client (its admin rank or role): a copy at its rank would be refused" if
               str(src.get("access_control") or "").upper() == "READ_ONLY" else None)
        if why:
            items.append(ao._unit(gk + ":rule", gk, "rule_create", ref, "rule", "absent", "copy", status="excluded", reason=why))
        else:
            if _name_taken(rows, n["name"]):
                blockers.append(f"A {label} rule named '{n['name']}' already exists. Pick another name for the copy.")
            body = {k: v for k, v in ao._body(src).items() if k not in R.UNMANAGED}
            order = R._order(src) + 1
            rank = admin_rank.rank_of(src)
            body.update(name=n["name"], state="DISABLED", order=order, rank=rank)
            if pol == "cloud_app_control":
                body["type"] = rtype
            check = dict(R.current(pol, src), name=n["name"], state="DISABLED")
            summary += [R.sentence(pol, check, names, order=order, rank=rank, state="DISABLED"),
                        f"A copy of '{src.get('name')}' with every setting it has, placed right below it (order {order}) at its rank ({rank})."]
            items.append(ao._unit(gk + ":rule", gk, "rule_create", ref, "rule", "absent",
                                  f"copy of '{src.get('name')}' at order {order}, rank {rank}, disabled"))
            groups.append({"key": gk, "handler": "re_create", "target": {"policy": pol, "rule_type": rtype, "name": n["name"], "payload": body,
                                                                        "check": check, "source_id": src.get("id"),
                                                                        "expect_source": R.current(pol, src), "order": order, "rank": rank}})
            table = _fields_table(pol, {}, check, names) + [{"field": "Order", "before": "—", "after": str(order)},
                                                            {"field": "Admin rank", "before": "—", "after": str(rank)},
                                                            {"field": "State", "before": "—", "after": "disabled"}]
    else:  # delete
        name = str(src.get("name") or "")
        title = f"Delete {label} rule '{name}'"
        ref = _ref(pol, rid=src.get("id"), name=name, rule_type=rtype)
        if n.get("name") and n["name"] != name:
            raise ao.OperationError(f"That rule is now called '{name}', not '{n['name']}': read the rules again.")
        if lock:
            items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", "exists", "exists", status="excluded", reason=lock))
        else:
            st = ao._state(src)
            snap = ao._body(src)
            items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", f"exists ({st.lower()}, order {src.get('order')})", "deleted"))
            groups.append({"key": gk, "handler": "re_delete", "target": {"policy": pol, "rule_type": rtype, "id": src.get("id"), "name": name,
                                                                        "check": dict(R.current(pol, src), state=st), "snapshot": snap,
                                                                        "order": R._order(src), "rank": admin_rank.rank_of(src), "state": st}})
            summary.append(f"The {label} rule '{name}' (order {src.get('order')}, {st.lower()}) is deleted. Undo re-creates it with the "
                           "same settings, order, rank and state (with a new id).")
            if st == "ENABLED":
                warnings.append("This rule is enabled: deleting it changes what users get as soon as ZIA activates.")
            table = _fields_table(pol, {}, R.current(pol, src), names)
            confirm = f"DELETE {name.upper()}"
    if act in ("create", "duplicate"):
        notes.append("A new rule is created DISABLED unless you ticked Create it enabled: enable it after review (Bulk changes, "
                     "Enable or disable rules, or edit it here).")
    if act == "update":
        notes.append("An edit keeps the rule's order and admin rank; Reorder a policy moves rules.")
    return {"type": TYPE, "product": "zia", "spec": n, "items": items, "groups": groups, "title": title, "warnings": warnings,
            "blockers": blockers, "notes": notes, "summary": summary, "fields_table": table,
            "confirm_always": confirm}


def _plan_revert(client, n: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    """The Undo of a recorded rule edit (see the module docstring)."""
    zia = client.zia
    ok, _ = editable(scope)
    items, groups, warnings = [], [], []
    cache: Dict[str, Tuple[List[Dict[str, Any]], Optional[str]]] = {}
    live = False
    for i, st in enumerate(n["steps"]):
        op, pol = st.get("op"), str(st.get("policy") or "")
        if op not in ("delete", "restore", "recreate") or pol not in R.POLICY:
            raise ao.OperationError("An undo step must delete, restore or re-create a rule of a known type.")
        if pol not in ok:
            raise ao.OperationError(f"Not in scope on the Scope page: {R.POLICY[pol]['label']}. The undo needs it in scope. Nothing was read.")
        rtype = str(st.get("rule_type") or "")
        ck = f"{pol}:{rtype}"
        if ck not in cache:
            say(f"Reading the {R.POLICY[pol]['label']} rules…")
            cache[ck] = list_rules(zia, pol, rtype, cancel)
        rows, err = cache[ck]
        gk = f"rer:{i}"
        name = str(st.get("name") or "")
        cur = next((r for r in rows if str(r.get("id")) == str(st.get("id"))), None) if st.get("id") is not None else None
        ref = _ref(pol, rid=st.get("id"), name=name, rule_type=rtype)
        if err:
            items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", None, None, status="excluded", reason=f"could not be read: {err[:160]}"))
            continue
        if op == "delete":
            if cur is None:
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", "absent", "absent", status="noop", reason="already gone"))
            elif str(cur.get("name") or "") != name or not _matches(pol, st.get("check"), cur):
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", "exists", "deleted", status="excluded",
                                      reason="changed in the tenant since it was created here; left as it is"))
            else:
                items.append(ao._unit(gk + ":rule", gk, "rule_delete", ref, "rule", f"exists ({ao._state(cur).lower()})", "deleted"))
                groups.append({"key": gk, "handler": "re_delete", "target": {"policy": pol, "rule_type": rtype, "id": cur.get("id"), "name": name,
                                                                            "check": _canon_check(pol, st.get("check")), "undo": True}})
        elif op == "restore":
            if cur is None:
                items.append(ao._unit(gk + ":rule", gk, "rule_field", ref, "rule", "absent", "restored", status="excluded", reason="no longer in the tenant"))
                continue
            have = R.current(pol, cur)
            changes, expect = {}, {}
            for k, before in (st.get("fields") or {}).items():
                if k == "state":
                    continue
                if k not in R.fields_of(pol):
                    raise ao.OperationError(f"Unknown field in the undo: {str(k)[:40]}.")
                f = R.fields_of(pol)[k]
                b, want_now, now = R.canon(f, before), R.canon(f, (st.get("expect") or {}).get(k)), have.get(k)
                if now == b:
                    items.append(ao._unit(f"{gk}:{k}", gk, "rule_field", ref, k, R.show(pol, k, now, {}), R.show(pol, k, b, {}), status="noop",
                                          reason="already as before"))
                elif now != want_now:
                    items.append(ao._unit(f"{gk}:{k}", gk, "rule_field", ref, k, R.show(pol, k, now, {}), R.show(pol, k, b, {}), status="excluded",
                                          reason="changed in the tenant since it was edited here; left as it is"))
                else:
                    items.append(ao._unit(f"{gk}:{k}", gk, "rule_field", ref, k, R.show(pol, k, now, {}), R.show(pol, k, b, {})))
                    changes[k], expect[k] = b, now
            st_now = ao._state(cur)
            new_state = st_now
            if "state" in (st.get("fields") or {}):
                b, want_now = str(st["fields"]["state"]), str((st.get("expect") or {}).get("state"))
                if st_now == b:
                    items.append(ao._unit(f"{gk}:state", gk, "rule_field", ref, "state", st_now, b, status="noop", reason="already as before"))
                elif st_now != want_now:
                    items.append(ao._unit(f"{gk}:state", gk, "rule_field", ref, "state", st_now, b, status="excluded",
                                          reason="changed in the tenant since it was edited here; left as it is"))
                else:
                    items.append(ao._unit(f"{gk}:state", gk, "rule_field", ref, "state", st_now, b))
                    new_state = b
            if changes or new_state != st_now:
                live = live or new_state == "ENABLED"
                groups.append({"key": gk, "handler": "re_update", "target": {"policy": pol, "rule_type": rtype, "id": cur.get("id"),
                                                                            "name": str(cur.get("name") or ""), "changes": changes, "expect": expect,
                                                                            "state": new_state, "expect_state": st_now}})
        else:  # recreate
            body = st.get("payload") if isinstance(st.get("payload"), dict) else None
            if body is None or not name:
                raise ao.OperationError("An undo re-creates a rule from what was recorded; this step has no record.")
            if _name_taken(rows, name):
                items.append(ao._unit(gk + ":rule", gk, "rule_create", ref, "rule", "absent", "re-created", status="excluded",
                                      reason=f"a rule named '{name}' exists again; left as it is"))
                continue
            rules = R.live(rows)
            last = R._order(rules[-1]) if rules else 0
            order = max(1, min(int(st.get("order") or last + 1), last + 1))
            state = "ENABLED" if str(st.get("state")) == "ENABLED" else "DISABLED"
            live = live or state == "ENABLED"
            body = {k: v for k, v in copy.deepcopy(body).items() if k not in ("id", "default_rule", "predefined", "access_control",
                                                                              "last_modified_by", "last_modified_time", "rule_type")}
            body.update(name=name, order=order, rank=int(st.get("rank") if st.get("rank") is not None else R.LEGACY_RANK), state=state)
            if pol == "cloud_app_control":
                body["type"] = rtype
            above = next((r for r in rules if R._order(r) >= order), None)
            items.append(ao._unit(gk + ":rule", gk, "rule_create", ref, "rule", "absent", f"re-created at order {order}, {state.lower()}"))
            groups.append({"key": gk, "handler": "re_create", "target": {"policy": pol, "rule_type": rtype, "name": name, "payload": body,
                                                                        "check": _canon_check(pol, dict(R.current(pol, body), state=state)),
                                                                        "above_id": above.get("id") if above else None, "order": order,
                                                                        "rank": body["rank"]}})
    changes = sum(1 for u in items if u["status"] == "change")
    return {"type": TYPE, "product": "zia", "spec": n, "items": items, "groups": groups, "title": "Undo a rule edit", "warnings": warnings,
            "notes": ["Only what the editor did and nobody changed since is reversed; everything else is left as it is."],
            "confirm_always": _confirm(changes, live)}


def _matches(policy: str, check: Any, row: Dict[str, Any]) -> bool:
    """Does the rule still hold every value the editor set (and its state)?
    Fields the editor left empty are not compared: ZIA may fill in its defaults."""
    want = _canon_check(policy, check)
    have = _canon_check(policy, dict(R.current(policy, row), state=ao._state(row)))
    return all(have.get(k) == v for k, v in want.items() if v not in (None, "", [], False))


def _canon_check(policy: str, check: Any) -> Dict[str, Any]:
    c = check if isinstance(check, dict) else {}
    out = {k: R.canon(f, c.get(k)) for k, f in R.fields_of(policy).items()}
    out["state"] = str(c.get("state") or "")
    return out


# ---------------------------------------------------------------------------
# Writes (each one through pack_ops, right after a fresh read)
# ---------------------------------------------------------------------------

def _create(zia, policy: str, body: Dict[str, Any], name: str, log) -> ops.Outcome:
    if policy == "forwarding":
        return ops.create(zia, "forwarding_rule", body, name=name, log=log)
    return ops.create(zia, "policy", body, channel=CHANNEL[policy], name=name, log=log)


def _update(zia, policy: str, rid: Any, body: Dict[str, Any], name: str, log) -> ops.Outcome:
    if policy == "forwarding":
        return ops.update(zia, "forwarding_rule", rid, body, name=name, log=log)
    return ops.update(zia, "policy", rid, body, channel=CHANNEL[policy], name=name, log=log)


def _delete(zia, policy: str, rid: Any, name: str, rule_type: str, log) -> ops.Outcome:
    item = {"kind": "forwarding_rule" if policy == "forwarding" else "policy", "id": rid, "name": name,
            "channel": None if policy == "forwarding" else CHANNEL[policy], "type": rule_type or None}
    return ops.delete(zia, item, log=log)


def _halt_or_fail(run, units, err: Optional[str], what: str) -> None:
    run.halt = ao._read_halt(err)
    if run.halt:
        run.mark(units, "skipped", f"not attempted: {run.halt}")
    else:
        run.mark(units, "failed", "", error=f"could not read {what} again before the change: {err}")
        run.counts["failed"] += 1


def _h_create(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    pol, label = t["policy"], R.POLICY[t["policy"]]["label"]
    rows, err = list_rules(run.zia, pol, t["rule_type"])
    if err:
        _halt_or_fail(run, units, err, f"the {label} rules")
        return
    if _name_taken(rows, t["name"]):
        run.mark(units, "conflict", "a rule with this name appeared in the tenant since the preview; left as it is")
        return
    if t.get("source_id") is not None:
        src = next((r for r in rows if str(r.get("id")) == str(t["source_id"])), None)
        if src is None or R.current(pol, src) != t["expect_source"]:
            run.mark(units, "conflict", "the rule being copied changed (or went) since the preview; nothing was copied")
            return
    elif "above_id" in t:
        above = next((r for r in R.live(rows) if R._order(r) >= int(t["order"])), None)
        if str(above.get("id") if above else None) != str(t.get("above_id")):
            run.mark(units, "conflict", "the policy's order changed since the preview (another rule sits at that place now); nothing was created")
            return
    body = copy.deepcopy(t["payload"])
    out = _create(run.zia, pol, body, t["name"], run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"]["id"] = out.id
        run.created.append({"type": "rule", "policy": pol, "id": out.id, "name": t["name"], "rule_type": t["rule_type"]})
        run.log(f"[{label}] {t['name']}: created at order {body.get('order')}, rank {body.get('rank')} ({str(body.get('state')).lower()})")


def _h_update(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    pol, label = t["policy"], R.POLICY[t["policy"]]["label"]
    fresh, err = get_rule(run.zia, pol, t["id"], t["rule_type"])
    if fresh is None:
        _halt_or_fail(run, units, err or "not found", "the rule")
        return
    have = R.current(pol, fresh)
    ok = []
    for u in units:
        f = u["field"]
        now, want = (ao._state(fresh), t["expect_state"]) if f == "state" else (have.get(f), t["expect"].get(f))
        if now != want:
            run.mark([u], "conflict", f"changed in the tenant since the preview: {f} is {R.show(pol, f, now, {}) if f != 'state' else now} "
                                      "now; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    fields = {u["field"]: t["changes"][u["field"]] for u in ok if u["field"] != "state"}
    body = R.apply_changes(pol, ao._body(fresh), fields)
    body["state"] = t["state"] if any(u["field"] == "state" for u in ok) else ao._state(fresh)
    body.pop("enabled", None)
    if pol == "cloud_app_control":
        body["type"] = t["rule_type"] or fresh.get("rule_type") or fresh.get("type")
    out = _update(run.zia, pol, t["id"], body, t["name"], run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        run.log(f"[{label}] {t['name']}: updated {', '.join(u['field'] for u in ok)}")


def _h_delete(run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    pol, label = t["policy"], R.POLICY[t["policy"]]["label"]
    fresh, err = get_rule(run.zia, pol, t["id"], t["rule_type"])
    if fresh is None:
        if err and ao._read_halt(err):
            _halt_or_fail(run, units, err, "the rule")
        else:
            run.mark(units, "noop", "already gone")
        return
    same = _matches(pol, t["check"], fresh) if t.get("undo") else \
        _canon_check(pol, dict(R.current(pol, fresh), state=ao._state(fresh))) == _canon_check(pol, t["check"])
    if str(fresh.get("name") or "") != str(t["name"]) or not same:
        run.mark(units, "conflict", "changed in the tenant since the preview; it was not deleted")
        return
    out = _delete(run.zia, pol, t["id"], t["name"], t["rule_type"], run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[{label}] {t['name']}: deleted")


# ---------------------------------------------------------------------------
# Read-back and Undo
# ---------------------------------------------------------------------------

def _verify(run) -> Dict[str, Any]:
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    groups = {g["key"]: g for g in run.p["groups"]}
    for u in [x for x in run.p["items"] if x["status"] == "applied"]:
        out["checked"] += 1
        t = (groups.get(u["group"]) or {}).get("target") or {}
        o = u["object"]
        pol = o["policy"]
        row, err = get_rule(run.zia, pol, o.get("id"), o.get("rule_type") or "") if o.get("id") is not None else (None, "no id")
        bad: List[str] = []
        if u["kind"] == "rule_delete":
            ok, err = row is None, None
        elif row is None:
            ok = False
        elif u["kind"] == "rule_create":
            want = _canon_check(pol, t.get("check"))
            want["state"] = want["state"] or "DISABLED"
            have = _canon_check(pol, dict(R.current(pol, row), state=ao._state(row)))
            bad = [R.fields_of(pol)[k]["label"] if k in R.fields_of(pol) else k for k, v in want.items()
                   if v not in (None, "", []) and have.get(k) != v]
            ok = not bad
            if ok and R._order(row) != int(t.get("order") or 0):
                run.log(f"[{R.POLICY[pol]['label']}] {o.get('name')}: ZIA stored it at order {row.get('order')} (asked {t.get('order')})")
        elif u["field"] == "state":
            ok = ao._state(row) == t.get("state")
        else:
            ok = R.current(pol, row).get(u["field"]) == t["changes"].get(u["field"])
        if not ok and err and u["kind"] != "rule_delete":
            out["unread"].append(f"{o.get('name')}: {err}")
            u["verified"] = None
            continue
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o.get('name')}: {', '.join(bad) if bad else u['field']} is not as written when read back")
    return out


def _inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    groups = {g["key"]: g for g in result.get("groups") or []}
    steps: List[Dict[str, Any]] = []
    restore: Dict[str, Dict[str, Any]] = {}
    for u in applied:
        o, t = u["object"], (groups.get(u["group"]) or {}).get("target") or {}
        base = {"policy": o["policy"], "rule_type": o.get("rule_type") or "", "name": o.get("name") or t.get("name") or ""}
        if u["kind"] == "rule_create" and o.get("id") is not None:
            steps.append(dict(base, op="delete", id=o["id"], check=t.get("check")))
        elif u["kind"] == "rule_delete" and t.get("snapshot") is not None:
            steps.append(dict(base, op="recreate", payload=t["snapshot"], order=t.get("order"), rank=t.get("rank"), state=t.get("state")))
        elif u["kind"] == "rule_field":
            r = restore.setdefault(u["group"], dict(base, op="restore", id=o["id"], name=t.get("name") or base["name"], fields={}, expect={}))
            f = u["field"]
            if f == "state":
                r["fields"]["state"], r["expect"]["state"] = t.get("expect_state"), t.get("state")
            else:
                r["fields"][f], r["expect"][f] = (t.get("expect") or {}).get(f), (t.get("changes") or {}).get(f)
    steps = list(reversed(steps)) + list(restore.values())
    return {"type": TYPE, "action": "revert", "steps": steps} if steps else None


# ---------------------------------------------------------------------------
# The object picker: the rules per type, the forms and the named objects
# ---------------------------------------------------------------------------

def forms(policies: Sequence[str]) -> Dict[str, Any]:
    out = {}
    for p in policies:
        out[p] = {"label": R.POLICY[p]["label"], "name_max": R.NAME_MAX[p], "action_field": R.POLICY[p]["action_field"],
                  "fields": [dict({k: v for k, v in f.items() if k in ("kind", "label", "ref", "required", "default", "who", "what", "when",
                                                                         "min", "max", "needs")}, key=k, values=list(f.get("values") or []))
                             for k, f in R.fields_of(p).items()]}
    return out


def _read_objects(client, scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    zia = getattr(client, "zia", None)
    ok, why = editable(scope)
    out: Dict[str, Any] = {"forms": forms(ok), "policies": [], "not_in_scope": why, "errors": {}, "cac_types": list(pc.CLOUD_APP_TYPES),
                           "order": list(ok)}
    if zia is None:
        out["errors"]["zia"] = "this sign-in has no ZIA service"
        return out
    keys = set()
    for p in ok:
        ao._check_stop(cancel)
        say(f"Reading the {R.POLICY[p]['label']} rules…")
        rows, err = list_rules(zia, p, "", cancel)
        if err:
            out["errors"][p] = err
        rows = sorted(rows, key=lambda r: (str(r.get("rule_type") or ""), 1 if R.is_default(r) else 0, R._order(r), str(r.get("id"))))
        out["policies"].append({"policy": p, "label": R.POLICY[p]["label"], "rules": [
            {"id": r.get("id"), "name": str(r.get("name") or ""), "order": r.get("order"), "rank": admin_rank.shown_rank(r),
             "state": ao._state(r), "rule_type": str(r.get("rule_type") or ""), "locked": ao.lock_reason("url_filtering", r),
             "default": R.is_default(r), "values": R.current(p, r)} for r in rows]})
        keys.update(R.refs_needed(p))
    say("Reading the objects rules can name (categories, groups, locations, applications, engines…)…")
    if "dlp_engines" in keys:
        keys.add("dlp_dictionaries")
    out["refs"] = read_refs(zia, sorted(keys), cancel, platform=refs_allowed(scope))
    for k, v in out["refs"].items():
        if v.get("error") and not v.get("not_in_scope"):
            out["errors"][f"{R.REFS[k]['label']}"] = v["error"]
    setting = read_rank(zia, scope)
    out["admin_rank"] = {"state": admin_rank.state_of(setting), "why": setting.get("why") or "",
                         "describe": "Admin Ranking is on: a new rule takes the rank of the rule it sits above." if
                         admin_rank.state_of(setting) == admin_rank.ON else R.rank_reason(setting) + "."}
    say(f"{sum(len(p['rules']) for p in out['policies'])} rules in {len(out['policies'])} rule types.")
    return out


ao.register(TYPE, family=FAMILY, product="zia", label="Edit a rule",
            hint="Create, edit, duplicate or delete one URL filtering, Cloud Firewall, SSL inspection, forwarding, Web DLP, DNS Control, "
                 "IPS, File Type Control, Sandbox or Cloud App Control rule, with a form per rule type, a plain-language preview and "
                 "the placement and rank. New rules arrive disabled.",
            in_scope=_in_scope, plan=_plan, read_objects=_read_objects,
            handlers={"re_create": _h_create, "re_update": _h_update, "re_delete": _h_delete},
            verify=_verify, inverse=_inverse, script="ops_rule_editor.js")
