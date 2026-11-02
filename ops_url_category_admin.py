"""Rename or delete one custom URL category, on the Bulk changes engine
(admin_ops plugin).

One operation type on /report/operations, under "Change":

  url_category_manage
      action rename  a new name for one custom category. The category is
                     sent back as read (its URLs, keywords, IP ranges,
                     description and super category) with only the name
                     changed: a full update (PUT /urlCategories/{id}, SDK
                     url_categories.update_url_category with no action).
                     Rules name a custom category by its id, so they keep
                     using it. Undo renames it back.
      action delete  one custom category, typed "DELETE <name>". Refused
                     while any rule names it: the preview lists those rules
                     (policy, order, name, state). Every policy whose rules
                     can name a URL category is read for that; one that is
                     not in scope on the Scope page cannot be checked, so the
                     delete is blocked until it is ticked (deny by default).
                     A predefined category is never deleted. Undo creates
                     the category again with the same name, super category,
                     URLs, keywords, IP ranges and description (ZIA gives it
                     a new id).

The engine supplies the scope check before any read, the plan hash and the
re-plan before writing, write mode, the writer, the named assessor and the
typed confirmation, the re-read right before each write (a category changed
since the preview is a conflict, left alone), one ZIA activation, the
read-back, the record, the audit log with the actor, and Undo.

SDK calls, verified against zscaler-sdk-python 1.11.3 (zia/url_categories.py):
list_categories (custom_only), get_category, update_url_category
(category_id, action=None, configured_name, urls, db_categorized_urls,
description, ip_ranges, ip_ranges_retaining_parent_category, keywords,
keywords_retaining_parent_category), add_url_category (super_category,
urls, configured_name, **kwargs), delete_category; writes go through
pack_ops (kind url_category). Rules: admin_ops.read_rules per policy.
ASSUMED (not checkable without a tenant): that a full update sent as read
with a new name keeps every other field; that ZIA itself refuses deleting a
category a rule outside the policies read here still uses (forwarding
control, bandwidth control, Sandbox and the like).
"""
from __future__ import annotations

import threading
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import admin_ops as ao
import pack_channels as pc
import pack_ops as ops

TYPE = "url_category_manage"
FAMILY = "url_category_manage_targets"
SCRIPT = "ops_url_category_admin.js"
# Policies whose rules can name a URL category (admin_ops.POLICIES keys).
REF_POLICIES = ("url_filtering", "ssl_inspection", "web_dlp", "file_type_control", "firewall", "dns_control")
REF_FIELDS = ("urlcategories", "destipcategories", "rescategories", "destcategories")
NAME_MAX = 255
# What a full update sends back as read (SDK update_url_category keyword args).
KEEP_FIELDS = ("super_category", "urls", "db_categorized_urls", "description", "ip_ranges", "ip_ranges_retaining_parent_category", "keywords",
               "keywords_retaining_parent_category", "custom_category")
NOT_CHECKED = ("Rules ZIA keeps elsewhere (forwarding control, bandwidth control, Sandbox and similar) are not read here; ZIA refuses the "
               "delete if one of them still uses the category (assumed).")

LogFn = Callable[[str], None]


def in_scope(scope: Dict[str, Any]) -> Optional[str]:
    return None if scope.get("url_categories") else (scope.get("not_in_scope") or {}).get("url_categories") or ao.NOT_IN_SCOPE


def _field(row: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    return pc._field(row, *keys, default=default)


def cat_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": _field(row, "id"), "name": ao._cat_ref(row)["name"], "super_category": str(_field(row, "super_category", "superCategory", default="") or ""),
            "urls": len(ao._urls_of(row)), "description": str(_field(row, "description", default="") or "")[:255]}


def rule_refs(zia: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Tuple[Dict[str, List[Dict[str, Any]]], List[str], List[str]]:
    """({category id: [rules naming it]}, policies that could not be read, policies not in scope)."""
    import shadow_rules
    refs: Dict[str, List[Dict[str, Any]]] = {}
    errors: List[str] = []
    pols = [p for p in REF_POLICIES if p in (scope.get("policies") or [])]
    out = [ao._label(p) for p in REF_POLICIES if p not in (scope.get("policies") or [])]
    for pol in pols:
        ao._check_stop(cancel)
        say(f"Reading the {ao._label(pol)} rules (which rules use the category)…")
        try:
            rows, err = ao.read_rules(zia, pol, cancel=cancel)
        except ao.OperationError as e:     # the SDK has no service for it: cannot be checked
            rows, err = [], str(e)
        if err:
            errors.append(f"{ao._label(pol)}: {err}")
            continue
        for r in rows:
            names: Set[str] = set()
            for k, v in r.items():
                if shadow_rules._canon(k) in REF_FIELDS:
                    names |= set(shadow_rules._tokens(v))
            for n in names:
                refs.setdefault(str(n), []).append({"policy": pol, "policy_label": ao._label(pol), "id": r.get("id"), "name": str(r.get("name") or ""),
                                                    "order": r.get("order"), "state": ao._state(r)})
    return refs, errors, out


def read_objects(client: Any, scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    """The custom URL categories, each with the rules in scope that name it."""
    zia = client.zia
    say("Reading the custom URL categories…")
    cats, err = ao.read_categories(zia)
    refs, rerr, out = rule_refs(zia, scope, say, cancel) if not err else ({}, [], [])
    rows = []
    for c in sorted(cats, key=lambda c: ao._cat_ref(c)["name"].lower()):
        s = cat_summary(c)
        used, seen = [], set()
        for r in refs.get(str(s["id"]), []) + (refs.get(s["name"], []) if s["name"] != str(s["id"]) else []):
            if (r["policy"], str(r["id"])) not in seen:
                seen.add((r["policy"], str(r["id"])))
                used.append(r)
        s["used_by"] = used
        rows.append(s)
    errors = {"url_categories": err} if err else {}
    if rerr:
        errors["rules"] = "; ".join(rerr)
    return {"categories": rows, "errors": errors, "not_checked": out, "note": NOT_CHECKED}


def _name(v: Any) -> str:
    n = " ".join(str(v or "").split())
    if not n:
        raise ao.OperationError("Give the category its new name.")
    if ao._has_control(n) or len(n) > NAME_MAX:
        raise ao.OperationError(f"The name must be at most {NAME_MAX} characters, with no control character.")
    return n


def _cid(v: Any) -> str:
    s = str(v if v is not None else "").strip()
    if not s or len(s) > 64 or not all(ch.isalnum() or ch in "_-" for ch in s):
        raise ao.OperationError("Pick the custom URL category (its id, such as CUSTOM_01).")
    return s


def normalize(spec: Dict[str, Any]) -> Dict[str, Any]:
    act = str(spec.get("action") or "").strip().lower()
    if act == "rename":
        return {"type": TYPE, "action": "rename", "id": _cid(spec.get("id")), "new_name": _name(spec.get("new_name"))}
    if act == "delete":
        return {"type": TYPE, "action": "delete", "id": _cid(spec.get("id"))}
    if act == "recreate" and spec.get("undo") is True:
        c = spec.get("category") if isinstance(spec.get("category"), dict) else {}
        keep = {k: c.get(k) for k in KEEP_FIELDS if c.get(k) not in (None, "", [])}
        urls, bad = ao._clean_urls(keep.get("urls") or [])
        keep["urls"] = urls
        sup = str(keep.get("super_category") or "USER_DEFINED").upper()
        if not ao._SUPER_CATEGORY.match(sup):
            raise ao.OperationError("The super category must be a ZIA super category name such as USER_DEFINED.")
        keep["super_category"] = sup
        for k in ("db_categorized_urls", "ip_ranges", "ip_ranges_retaining_parent_category", "keywords", "keywords_retaining_parent_category"):
            if k in keep:
                keep[k] = [str(x)[:1024] for x in (keep[k] if isinstance(keep[k], list) else [])][:ao.MAX_URLS]
        if "description" in keep:
            keep["description"] = str(keep["description"])[:255]
        keep.pop("custom_category", None)
        return {"type": TYPE, "action": "recreate", "undo": True, "name": _name(c.get("name")), "category": keep, "deleted_id": _cid(spec.get("deleted_id"))}
    raise ao.OperationError("Pick rename or delete.")


def _snapshot(row: Dict[str, Any]) -> Dict[str, Any]:
    """The category as read, in the SDK's keyword names (what a full update or a re-create sends)."""
    out: Dict[str, Any] = {"name": ao._cat_ref(row)["name"]}
    alias = {"super_category": ("super_category", "superCategory"), "urls": ("urls",), "db_categorized_urls": ("db_categorized_urls", "dbCategorizedUrls"),
             "description": ("description",), "ip_ranges": ("ip_ranges", "ipRanges"),
             "ip_ranges_retaining_parent_category": ("ip_ranges_retaining_parent_category", "ipRangesRetainingParentCategory"),
             "keywords": ("keywords",), "keywords_retaining_parent_category": ("keywords_retaining_parent_category", "keywordsRetainingParentCategory"),
             "custom_category": ("custom_category", "customCategory")}
    for k, keys in alias.items():
        v = _field(row, *keys)
        if v not in (None, "", []):
            out[k] = list(v) if isinstance(v, (list, tuple)) else v
    return out


def _obj(row_or_name: Any, cid: Any) -> Dict[str, Any]:
    name = ao._cat_ref(row_or_name)["name"] if isinstance(row_or_name, dict) else str(row_or_name)
    return {"type": "url_category", "policy_label": "Custom URL category", "id": cid, "name": name}


def _done(n: Dict[str, Any], title: str, items, groups, *, warnings=(), blockers=(), impact=(), confirm: str = "", notes=()) -> Dict[str, Any]:
    return {"type": TYPE, "product": "zia", "title": title, "spec": n, "items": list(items), "groups": list(groups), "warnings": list(warnings),
            "blockers": list(blockers), "impact": list(impact), "confirm_always": confirm, "notes": list(notes)}


def plan(client: Any, spec: Dict[str, Any], scope: Dict[str, Any], say: LogFn, cancel: Optional[threading.Event]) -> Dict[str, Any]:
    n = normalize(spec)
    zia = client.zia
    say("Reading the custom URL categories…")
    cats, err = ao.read_categories(zia)
    if err:
        raise ao.OperationError(f"The custom URL categories could not be read: {err}. Nothing was written.")
    by_id = {str(_field(c, "id")): c for c in cats}
    by_name = {ao._cat_ref(c)["name"].strip().lower(): c for c in cats}
    if n["action"] == "recreate":
        obj = _obj(n["name"], None)
        if n["name"].lower() in by_name:
            return _done(n, f"Undo: create '{n['name']}' again", [ao._unit("cat", "cat", "url_category", obj, "exists", True, True, status="excluded",
                                                                          reason="a category with this name exists again; nothing is created")], [])
        return _done(n, f"Undo: create '{n['name']}' again",
                     [ao._unit("cat", "cat", "url_category", obj, "exists", False, True,
                               reason=f"created again with its {len(n['category'].get('urls') or [])} URL(s); ZIA gives it a new id")],
                     [{"key": "cat", "handler": "urlcat_recreate", "target": {"name": n["name"], "category": n["category"]}}],
                     notes=["Rules that named the deleted category were none (the delete was refused otherwise), so none needs changing."])
    row = by_id.get(n["id"])
    if row is None:
        if n["action"] == "delete":
            return _done(n, "Delete a custom URL category", [ao._unit("cat", "cat", "url_category", _obj(n["id"], n["id"]), "exists", False, False,
                                                                      status="noop", reason="already gone")], [])
        raise ao.OperationError(f"{n['id']} is not a custom URL category of this tenant now. Read the categories again.")
    name = ao._cat_ref(row)["name"]
    obj = _obj(row, n["id"])
    snap = _snapshot(row)
    if n["action"] == "rename":
        title = f"Rename the URL category '{name}'"
        if n["new_name"] == name:
            return _done(n, title, [ao._unit("cat", "cat", "url_category", obj, "name", name, n["new_name"], status="noop", reason="already this name")], [])
        clash = by_name.get(n["new_name"].lower())
        if clash is not None and str(_field(clash, "id")) != n["id"]:
            return _done(n, title, [], [], blockers=[f"Another custom category is already named '{n['new_name']}': pick another name."])
        return _done(n, title, [ao._unit("cat", "cat", "url_category", obj, "name", name, n["new_name"],
                                         reason="rules name the category by its id, so they keep using it")],
                     [{"key": "cat", "handler": "urlcat_rename", "target": {"id": n["id"], "name": name, "new_name": n["new_name"], "before": snap}}],
                     notes=[f"The category is sent back as read with only its name changed (PUT /urlCategories/{n['id']}); Undo renames it back."])
    # delete
    title = f"Delete the URL category '{name}'"
    refs, rerr, out = rule_refs(zia, scope, say, cancel)
    users, seen = [], set()
    for r in refs.get(n["id"], []) + (refs.get(name, []) if name != n["id"] else []):
        if (r["policy"], str(r["id"])) not in seen:
            seen.add((r["policy"], str(r["id"])))
            users.append(r)
    blockers: List[str] = []
    if out:
        blockers.append("These policies can name a URL category but are not in scope on the Scope page, so their rules cannot be checked: "
                        + ", ".join(out) + ". Tick them, read again and preview again; nothing was deleted.")
    if rerr:
        blockers.append("These rules could not be read, so the delete cannot be checked: " + "; ".join(rerr) + ".")
    impact = [{"category": name, "id": n["id"], "rules": users,
               "detail": (f"{len(users)} rule{'s' if len(users) != 1 else ''} use{'s' if len(users) == 1 else ''} this category: change "
                          f"{'them' if len(users) != 1 else 'it'} first." if users else "No rule read here names this category.")}]
    if users:
        return _done(n, title, [ao._unit("cat", "cat", "url_category", obj, "exists", True, False, status="excluded",
                                         reason="still used by " + "; ".join(f"{r['policy_label']} rule {r['order']} '{r['name']}' ({r['state'].lower()})"
                                                                             for r in users[:10]) + (f" and {len(users) - 10} more" if len(users) > 10 else ""))],
                     [], blockers=blockers, impact=impact)
    return _done(n, title, [ao._unit("cat", "cat", "url_category", obj, "exists", True, False,
                                     reason=f"its {len(snap.get('urls') or [])} URL(s) go with it; Undo creates it again (with a new id)")],
                 [{"key": "cat", "handler": "urlcat_delete", "target": {"id": n["id"], "name": name, "before": snap}}],
                 blockers=blockers, impact=impact, confirm=(f"DELETE {name}" if len(name) <= 60 else "DELETE URL CATEGORY"),
                 warnings=[NOT_CHECKED], notes=["Undo creates the category again with the same name, URLs, keywords, IP ranges and description."])


def _fresh(run: Any, units: List[Dict[str, Any]], cid: str, *, gone_ok: bool) -> Optional[Dict[str, Any]]:
    """The category read again right before its write, or None (the units marked)."""
    fresh, err = ao.get_category(run.zia, cid)
    if fresh is not None:
        return fresh
    halt = ao._read_halt(err)
    if halt:
        run.halt = halt
        run.mark(units, "skipped", f"not attempted: {halt}")
    elif gone_ok:
        run.mark(units, "noop", "already gone")
    else:
        run.mark(units, "failed", "", error=f"could not read it again before the change: {err}"[:300])
        run.counts["failed"] += 1
    return None


def rename_payload(snap: Dict[str, Any], new_name: str) -> Dict[str, Any]:
    body = {k: v for k, v in snap.items() if k != "name"}
    body["configured_name"] = new_name
    body.setdefault("urls", [])
    return body


def h_rename(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _fresh(run, units, t["id"], gone_ok=False)
    if fresh is None:
        return
    if _snapshot(fresh) != t["before"]:
        run.mark(units, "conflict", "the category changed since the preview; left as it is")
        run.counts["skipped"] += len(units)
        return
    out = ops.update(run.zia, "url_category", t["id"], rename_payload(t["before"], t["new_name"]), name=t["new_name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[URL category] {t['name']}: renamed to {t['new_name']}")


def h_delete(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh = _fresh(run, units, t["id"], gone_ok=True)
    if fresh is None:
        return
    if _snapshot(fresh) != t["before"]:
        run.mark(units, "conflict", "the category changed since the preview, so it is kept")
        run.counts["skipped"] += len(units)
        return
    out = ops.delete(run.zia, {"kind": "url_category", "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True
        run.log(f"[URL category] {t['name']}: deleted")


def h_recreate(run: Any, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    cats, err = ao.read_categories(run.zia)
    if err:
        import ops_zia_directory as od
        od._halt_or_fail(run, units, err, "the custom URL categories")
        return
    if any(ao._cat_ref(c)["name"].strip().lower() == t["name"].lower() for c in cats):
        run.mark(units, "conflict", f"a category named '{t['name']}' exists again; nothing was created")
        run.counts["skipped"] += len(units)
        return
    payload = dict(t["category"], configured_name=t["name"], custom_category=True)
    payload.setdefault("urls", [])
    out = ops.create(run.zia, "url_category", payload, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.created.append({"type": "url_category", "id": out.id, "name": t["name"], "urls": payload["urls"]})
        run.log(f"[URL category] {t['name']}: created again")


HANDLERS = {"urlcat_rename": h_rename, "urlcat_delete": h_delete, "urlcat_recreate": h_recreate}


def verify(run: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    for g in run.p["groups"]:
        units = [u for u in run.p["items"] if u["group"] == g["key"] and u["status"] == "applied"]
        if not units:
            continue
        t = g["target"]
        out["checked"] += len(units)
        if g["handler"] == "urlcat_delete":
            row, err = ao.get_category(run.zia, t["id"])
            ok = row is None and not ao._read_halt(err)
        elif g["handler"] == "urlcat_rename":
            row, err = ao.get_category(run.zia, t["id"])
            ok = row is not None and ao._cat_ref(row)["name"] == t["new_name"] and ao._url_set(row) == {u.lower() for u in t["before"].get("urls") or []}
        else:
            oid = units[0]["object"].get("id")
            row, err = ao.get_category(run.zia, oid) if oid not in (None, "") else (None, "no id")
            ok = row is not None and ao._cat_ref(row)["name"] == t["name"] and ao._url_set(row) == {u.lower() for u in t["category"].get("urls") or []}
        for u in units:
            u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += len(units)
        else:
            out["mismatched"].append(f"{t.get('name')}: not as planned when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """A rename is renamed back; a delete is created again (an Undo-only form)."""
    applied = {u["group"] for u in result.get("items") or [] if u.get("status") == "applied"}
    for g in result.get("groups") or []:
        if g["key"] not in applied:
            continue
        t = g["target"]
        if g["handler"] == "urlcat_rename":
            return {"type": TYPE, "action": "rename", "id": t["id"], "new_name": t["name"]}
        if g["handler"] == "urlcat_delete":
            return {"type": TYPE, "action": "recreate", "undo": True, "deleted_id": t["id"],
                    "category": dict({k: v for k, v in t["before"].items() if k != "name"}, name=t["name"])}
    return None


ao.register(TYPE, family=FAMILY, product="zia", label="Rename or delete a URL category", plan=plan, read_objects=read_objects,
            in_scope=in_scope, handlers=HANDLERS, verify=verify, inverse=inverse, script=SCRIPT, group="Change",
            hint=("Rename a custom URL category (rules keep using it; Undo renames it back) or delete one (DELETE and its name typed; "
                  "refused while a rule uses it, and the rules are listed). Needs URL filtering in scope on the Scope page."))
