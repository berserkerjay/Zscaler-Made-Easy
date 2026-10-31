"""Bulk changes: safe administrative operations on a tenant.

The operations engine behind /report/operations. Each operation is
planned from the tenant as it is now, previewed item by item, approved
by its plan hash and applied through the shared execution path
(pack_ops): the same write mode, writer check, typed confirmation,
retries, rate-limit handling, Stop, audit log and activation as a policy
pack deploy. Nothing here names an SDK write method.

Operation types (`spec["type"]`):

  rule_state      enable or disable up to MAX_TARGETS ZIA rules (URL
                  filtering, SSL inspection, Cloud Firewall, Cloud App
                  Control, File Type Control and the four DLP channels);
                  one field (`state`) per operation.
  reorder         put one policy's rules in a desired order with the
                  fewest moves (the rules outside a longest increasing
                  subsequence move; the others keep their place). Locked
                  rules (the Default rule, predefined and read-only rules,
                  Inline Web DLP exception rules) never move; only the
                  rule's order changes, its content is sent back as read.
  url_categories  add, remove, move or copy URLs on custom URL categories,
                  optionally into a new category; shows which rules in
                  scope reference each category the change touches.
  zpa_domains     move or copy domains between ZPA application segments,
                  or clone a segment's settings with a domain list, with
                  the FQDN and port overlap check.

Cloud application sanction (Sanctioned / Unsanctioned) is the plugin type
cloud_app_sanction (ops_sanction.py): the SDK can write it
(zia.shadow_it_report.bulk_update) and each application's current state is
read from ZIA Insights' Shadow IT applications (the SDK's list_apps keeps
id and name only), so the preview, the conflict guard and an exact Undo
hold; an application whose state cannot be read is excluded.

Every operation goes:

  plan(client, spec)        reads, never writes: per-item before / after,
                            no-ops and exclusions with the reason, impact,
                            warnings and blockers, and the plan_hash (a
                            sha256 over the spec and every item's before
                            and after). Changes above CONFIRM_ABOVE need
                            the typed `confirm_phrase`.
  execute(client, spec, plan_hash=...)
                            plans again: a different hash means the tenant
                            moved since the preview and nothing is written
                            (status plan_changed). Then each write, in
                            order, one at a time: right before it the
                            object is read again and every item's field is
                            compared with the plan's "before"; a mismatch
                            marks the item `conflict` and it is skipped
                            (someone else's change is never overwritten).
                            An item-level refusal is reported and the run
                            goes on; a refusal no later write can get past
                            (rate limit, refused credentials, edit lock)
                            or Stop ends the run and the rest is reported
                            as not attempted. ZIA changes are activated
                            once at the end (pack_ops.activate_once) and
                            every applied item is read back.
  inverse(result)           the operation that reverses exactly what was
                            applied: a new operation, previewed and
                            confirmed like any other (Undo), never a blind
                            rollback.
  to_request(prepared)      the prepared operation as a request object
                            (kind, title, items, before / after,
                            plan_hash) for a shared approval queue.
"""
from __future__ import annotations

import hashlib
import ipaddress
import inspect
import json
import os
import re
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import pack_channels as pc
import pack_ops as ops

LogFn = Optional[Callable[[str], None]]

MAX_TARGETS = 100          # rules per mass enable / disable
CONFIRM_ABOVE = 10         # more changes than this need the typed phrase
MAX_URLS = 1000            # URLs per URL category operation
MAX_DOMAINS = 500          # domains per ZPA operation
URL_MAX_LEN = 1024         # assumed ZIA limit for one custom URL

KIND = "admin_operation"
TYPES = ("rule_state", "reorder", "url_categories", "zpa_domains")

# ---------------------------------------------------------------------------
# Plugins: further operation types, each in its own ops_<name>.py module
# ---------------------------------------------------------------------------
# A builder (Client Connector profiles, ZPA objects, ZDX probes, AI Guard, a
# ZIA baseline, ...) is one more operation type on this same engine and page:
# planned from the tenant as it is now, previewed item by item, approved by
# its plan hash, applied through the same gates with a re-read before every
# write, read back and reversible. A module ops_<name>.py next to this file
# calls register() at import; load_plugins() imports them all once.
PLUGINS: Dict[str, Dict[str, Any]] = {}
PLUGIN_FAMILIES: Dict[str, Dict[str, Any]] = {}
PLUGIN_HANDLERS: Dict[str, Callable[..., None]] = {}
_PLUGIN_NAME = re.compile(r"^[a-z][a-z0-9_]{1,40}$")


def register(type_name: str, *, family: str, product: str, label: str, hint: str, in_scope: Callable[[Dict[str, Any]], Optional[str]],
             plan: Callable[..., Dict[str, Any]], read_objects: Callable[..., Dict[str, Any]], handlers: Dict[str, Callable[..., None]],
             verify: Optional[Callable[..., Dict[str, Any]]] = None, inverse: Optional[Callable[[Dict[str, Any]], Optional[Dict[str, Any]]]] = None,
             group: str = "Build new", script: str = "") -> None:
    """Add an operation type. `in_scope(scope)` returns why it is out of scope
    (None when it may run) and is checked before anything is read;
    `plan(client, spec, scope, say, cancel)` returns the prepared operation
    ({type, product, title, spec, items (see _unit), groups ({key, handler,
    target}), warnings, blockers}) and never writes; `read_objects(client,
    scope, say, cancel)` lists what the page can pick from; each group's
    handler(run, group, units) writes through pack_ops (run.outcome marks the
    units) and sets run.wrote_zia when it changed ZIA; `verify(run)` reads
    back the applied units ({checked, confirmed, mismatched, unread});
    `inverse(result)` is the operation that undoes it. `script` names the
    page's form for it under static/ (ops_<name>.js)."""
    for n in (type_name, family):
        if not isinstance(n, str) or not _PLUGIN_NAME.match(n) or n in TYPES or n in ("rules", "url_categories", "zpa_segments"):
            raise ValueError(f"invalid or reserved operation name: {n!r}")
    # A type and a family share require_scope's namespace: one name, one meaning.
    if type_name == family or type_name in PLUGIN_FAMILIES or family in PLUGINS:
        raise ValueError(f"operation type and family names must differ from every other: {type_name!r} / {family!r}")
    if not isinstance(product, str) or not _PLUGIN_NAME.match(product):
        raise ValueError(f"invalid plugin product: {product!r}")
    if script and not re.fullmatch(r"ops_[a-z0-9_]{1,40}\.js", script):
        raise ValueError(f"invalid plugin script name: {script!r}")
    for what, fn in (("in_scope", in_scope), ("plan", plan), ("read_objects", read_objects)):
        if not callable(fn):
            raise ValueError(f"plugin {type_name!r}: {what} must be callable")
    for what, fn in (("verify", verify), ("inverse", inverse)):
        if fn is not None and not callable(fn):
            raise ValueError(f"plugin {type_name!r}: {what} must be callable or None")
    if not isinstance(handlers, dict) or not handlers:
        raise ValueError(f"plugin {type_name!r}: handlers must name at least one write handler")
    for h, fn in handlers.items():
        if not isinstance(h, str) or not _PLUGIN_NAME.match(h) or not callable(fn):
            raise ValueError(f"invalid plugin handler: {h!r}")
        if h in HANDLERS or (h in PLUGIN_HANDLERS and PLUGIN_HANDLERS[h] is not handlers[h]):
            raise ValueError(f"handler name already taken: {h!r}")
    # A second registration may not swap the scope gate or planner of a type
    # or family another module registered (deny by default: same callables only).
    old = PLUGINS.get(type_name)
    if old is not None and (old["plan"] is not plan or old["in_scope"] is not in_scope):
        raise ValueError(f"operation type already registered: {type_name!r}")
    fam = PLUGIN_FAMILIES.get(family)
    if fam is not None and (fam["in_scope"] is not in_scope or fam["read_objects"] is not read_objects):
        raise ValueError(f"operation family already registered with another scope check or reader: {family!r}")
    PLUGINS[type_name] = {"type": type_name, "family": family, "product": product, "label": label, "hint": hint, "group": group,
                          "script": script, "in_scope": in_scope, "plan": plan, "verify": verify, "inverse": inverse}
    PLUGIN_FAMILIES[family] = {"in_scope": in_scope, "read_objects": read_objects}
    PLUGIN_HANDLERS.update(handlers)


_plugins_loaded = False


def load_plugins() -> None:
    """Import every ops_<name>.py beside this module once (they register themselves)."""
    global _plugins_loaded
    if _plugins_loaded:
        return
    _plugins_loaded = True
    import importlib
    here = os.path.dirname(os.path.abspath(__file__))
    for fn in sorted(os.listdir(here)):
        if fn.startswith("ops_") and fn.endswith(".py") and _PLUGIN_NAME.match(fn[:-3]):
            importlib.import_module(fn[:-3])


def types() -> Tuple[str, ...]:
    load_plugins()
    return TYPES + tuple(sorted(PLUGINS))


def product_of(spec_or_family: Any) -> str:
    """The product an operation type or a family (the classic ZPA types, a
    plugin type, a plugin family) reads and changes: "zpa", "zcc", "zdx" or
    "zia" (the default for the ZIA rule and URL category types)."""
    load_plugins()
    t = spec_or_family if isinstance(spec_or_family, str) else str((spec_or_family or {}).get("type") or "") if isinstance(spec_or_family, dict) else ""
    if t in ("zpa_segments", "zpa_domains"):
        return "zpa"
    if t in PLUGINS:
        return str(PLUGINS[t].get("product") or "zia")
    for p in PLUGINS.values():
        if p.get("family") == t:
            return str(p.get("product") or "zia")
    return "zia"


def plugin_catalog() -> List[Dict[str, Any]]:
    """What the page needs to offer the plugin types: no callables."""
    load_plugins()
    return [{k: p[k] for k in ("type", "family", "product", "label", "hint", "group", "script")} for p in sorted(PLUGINS.values(), key=lambda p: (p["group"], p["label"]))]
STATES = ("ENABLED", "DISABLED")

# Policy types an operation can change: label, the pack_channels channel
# (or pack_ops.ADMIN_RULE_SERVICES key) its writes go through, and whether
# rule order is a thing (SaaS Security API DLP scans data at rest; its
# order semantics are not documented, see shadow_rules).
POLICIES: Dict[str, Dict[str, Any]] = {
    "url_filtering": {"label": "URL filtering", "channel": pc.URL, "ordered": True},
    "ssl_inspection": {"label": "SSL inspection", "channel": pc.SSL, "ordered": True},
    "firewall": {"label": "Cloud Firewall", "channel": "firewall", "ordered": True},
    "cloud_app_control": {"label": "Cloud App Control", "channel": pc.CLOUD_APP, "ordered": True},
    "file_type_control": {"label": "File Type Control", "channel": pc.FILE_TYPE, "ordered": True},
    "web_dlp": {"label": "Inline Web DLP", "channel": pc.WEB, "ordered": True},
    "endpoint_dlp": {"label": "Endpoint DLP", "channel": pc.ENDPOINT, "ordered": True},
    "email_dlp": {"label": "Outbound Email DLP", "channel": pc.EMAIL, "ordered": True},
    "saas_dlp": {"label": "SaaS Security API DLP", "channel": pc.SAAS, "ordered": False},
}
# Rules naming URL categories: the policies read for a URL category change's impact.
CATEGORY_POLICIES = ("url_filtering", "ssl_inspection", "web_dlp", "file_type_control", "firewall")
_CATEGORY_FIELDS = ("urlcategories", "destipcategories")

# Where cloud application sanction lives (read_objects' "sanction" key, kept for its callers).
SANCTION_NOTE = ("Cloud application sanction is its own operation: Sanction or unsanction cloud apps (needs ZIA platform and ZIA "
                 "Insights ticked on the Scope page). Each application's current state comes from ZIA Insights, so the preview, "
                 "the conflict check and an exact Undo hold; an application whose state cannot be read is not changed.")
READ_RATE_STOP = ("ZIA refused a read for its rate limit while the change was running, so nothing more is sent. What was "
                  "already applied is kept and listed; wait a few minutes, then preview again to finish (or Undo).")
REORDER_BROKEN = "the policy's rule order changed while the operation ran, so the remaining moves were not sent"
NOT_IN_SCOPE = "Not in scope on the Scope page, so it is not read or changed here."
LAST_DOMAIN = "ZPA needs at least one domain in a segment, so the last one is not removed"


class OperationError(ValueError):
    """A request an operation cannot be planned from (the endpoint's 400)."""


class Stopped(RuntimeError):
    """Stop was clicked while the plan was being read."""


# ---------------------------------------------------------------------------
# Scope (user rule 1: only what the Scope page puts in scope is read)
# ---------------------------------------------------------------------------

def scope_for(scopes: Any, channels: Any) -> Dict[str, Any]:
    """What Bulk changes may read and change for the Scope page's selection:
    the rule policies shadow_rules reads (plus File Type Control, the
    Path analyzer's `ftc` section), custom URL categories when URL
    filtering is in scope, ZPA segments when ZPA is ticked. Pure."""
    import data_flow
    import shadow_rules
    sr = shadow_rules.scope_for(scopes, channels)
    ps = data_flow.path_scope(scopes, channels)
    read, nis = [], {}
    for key in POLICIES:
        if key == "file_type_control":
            ok = "ftc" in ps["read"]
            why = ps["not_in_scope"].get("ftc") or (ps.get("read_blocked") or {}).get("ftc")
        else:
            ok = key in sr["read"]
            why = sr["not_in_scope"].get(key) or (sr.get("read_blocked") or {}).get(key)
        if ok:
            read.append(key)
        else:
            nis[key] = why or NOT_IN_SCOPE
    given = {str(s) for s in (scopes or [])}
    zpa = "zpa" in given
    urls = "url_filtering" in read
    if not urls:
        nis["url_categories"] = "Not in scope: custom URL categories are changed only when URL filtering is in scope (tick DLP or ZIA platform)."
    if not zpa:
        nis["zpa_segments"] = "Not in scope: ZPA is not ticked on the Scope page, so the application segments are not read."
    return {"policies": read, "url_categories": urls, "zpa": zpa, "not_in_scope": nis,
            # the raw Scope page selection, for plugin types (register) that gate on other keys
            "scopes": sorted(given), "channels": dict(channels) if isinstance(channels, dict) else {}}


def require_scope(spec_or_family: Any, scope: Dict[str, Any]) -> None:
    """OperationError naming what is out of scope, before anything is read."""
    load_plugins()
    t = spec_or_family if isinstance(spec_or_family, str) else str((spec_or_family or {}).get("type") or "")
    if t in ("rules", "rule_state", "reorder"):
        if not scope["policies"]:
            raise OperationError("No rule policy is in scope: on the Scope page tick DLP or ZIA platform and mark the channels you run on Zscaler.")
        if isinstance(spec_or_family, dict):
            targets = spec_or_family.get("targets")
            pols = {str(x.get("policy")) for x in (targets if isinstance(targets, list) else []) if isinstance(x, dict)}
            if spec_or_family.get("policy"):
                pols.add(str(spec_or_family["policy"]))
            out = sorted(p for p in pols if p not in scope["policies"])
            if out:
                raise OperationError("Not in scope on the Scope page: " + ", ".join(POLICIES.get(p, {}).get("label", p) for p in out) + ". Nothing was read.")
    elif t in ("url_categories",):
        if not scope["url_categories"]:
            raise OperationError(scope["not_in_scope"]["url_categories"])
    elif t in ("zpa_segments", "zpa_domains"):
        if not scope["zpa"]:
            raise OperationError(scope["not_in_scope"]["zpa_segments"])
    elif t in PLUGINS or t in PLUGIN_FAMILIES:
        reg = PLUGINS.get(t) or PLUGIN_FAMILIES[t]
        why = _plugin_in_scope(reg["in_scope"], scope, spec_or_family)
        if why:
            raise OperationError(str(why))
    else:
        raise OperationError(f"Unknown operation '{t}'. Use one of: {', '.join(types())}.")


def _plugin_in_scope(fn: Callable[..., Optional[str]], scope: Dict[str, Any], spec: Any) -> Optional[str]:
    """A plugin's scope check. One that takes the spec too (the ZIA
    baseline: the areas it names, or its Undo touches) is given it, so what
    is not ticked is refused here, before sign-in (deny by default)."""
    if isinstance(spec, dict):
        try:
            params = [p for p in inspect.signature(fn).parameters.values()
                      if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD, p.VAR_POSITIONAL)]
        except (TypeError, ValueError):
            params = []
        if len(params) >= 2 or any(p.kind == p.VAR_POSITIONAL for p in params):
            return fn(scope, spec)
    return fn(scope)


# ---------------------------------------------------------------------------
# Readers (GET only; the SDK client's session is paced by zia_rate)
# ---------------------------------------------------------------------------

def _rows(ret: Any) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    import pack_export
    return pack_export._rows(ret)


def _one(ret: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One object of a get call, with the fields the SDK's model leaves out
    taken from the raw answer (pack_export.one_row): the re-read a PUT is
    built from must not drop them."""
    import pack_export
    return pack_export.one_row(ret)


def _service(zia, policy: str):
    ch = POLICIES[policy]["channel"]
    name = pc.CHANNELS[ch]["service"] if ch in pc.CHANNELS else ops.ADMIN_RULE_SERVICES[ch]
    svc = getattr(zia, name, None)
    if svc is None:
        raise OperationError(f"The installed zscaler-sdk-python has no {name} service, so {POLICIES[policy]['label']} rules cannot be read.")
    return svc


def _check_stop(cancel: Optional[threading.Event]) -> None:
    if cancel is not None and cancel.is_set():
        raise Stopped("You clicked Stop: nothing more was read and nothing was written.")


def read_rules(zia, policy: str, *, rule_type: str = "", cancel: Optional[threading.Event] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every rule of one policy as snake_case dicts (Cloud App Control:
    the given type, else every type, each row carrying `rule_type`)."""
    svc = _service(zia, policy)
    try:
        if policy == "cloud_app_control":
            out: List[Dict[str, Any]] = []
            for t in ([rule_type] if rule_type else list(pc.CLOUD_APP_TYPES)):
                _check_stop(cancel)
                rows, err = _rows(svc.list_rules(t))
                if err:
                    return out, err
                for r in rows:
                    r["rule_type"] = str(r.get("type") or t)
                out.extend(rows)
            return out, None
        _check_stop(cancel)
        if policy == "saas_dlp":
            lister = getattr(svc, "list_all_rules", None)
            return _rows(lister() if lister else svc.list_rules("ANY"))
        return _rows(svc.list_rules())
    except Stopped:
        raise
    except Exception as e:  # noqa: BLE001 — reported as the read error
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def get_rule(zia, policy: str, rule_id: Any, rule_type: str = "") -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """One rule, read fresh (the conflict guard's re-read)."""
    svc = _service(zia, policy)
    try:
        if policy == "cloud_app_control":
            row, err = _one(svc.get_rule(rule_type, rule_id))
            if row is not None:
                row["rule_type"] = str(row.get("type") or rule_type)
            return row, err
        if policy == "saas_dlp":
            return _one(svc.get_rule(rule_id, rule_type or None))
        return _one(svc.get_rule(rule_id))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def read_categories(zia) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """The tenant's custom URL categories (urlCategories?customOnly=true)."""
    svc = getattr(zia, "url_categories", None)
    if svc is None:
        return [], "the installed zscaler-sdk-python has no url_categories service"
    try:
        rows, err = _rows(svc.list_categories(query_params={"custom_only": True}))
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"
    return [r for r in rows if _truthy(r.get("custom_category"))], err


def get_category(zia, cid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        return _one(zia.url_categories.get_category(cid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"


def read_segments(zpa, cancel: Optional[threading.Event] = None) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every ZPA application segment, page by page (the SDK returns one
    page per call; 500 is the largest page ZPA serves)."""
    svc = getattr(zpa, "application_segment", None) if zpa is not None else None
    if svc is None:
        return [], "this sign-in has no ZPA service (ZPA needs a OneAPI API client)"
    import pack_export
    try:
        ret = svc.list_segments(query_params={"page_size": "500"})
        rows, err = _rows(ret)
        if err:
            return [], err
        resp = ret[1] if isinstance(ret, tuple) and len(ret) >= 3 else None
        pages = 0
        while resp is not None and callable(getattr(resp, "has_next", None)) and resp.has_next() and pages < 200:
            _check_stop(cancel)
            data, _r, perr = resp.next()
            if perr:
                return rows, str(perr)[:200]
            rows.extend(pack_export._plain(x) for x in data or [])
            pages += 1
        return rows, None
    except Stopped:
        raise
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {str(e)[:200]}"


def get_segment(zpa, sid: Any) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    try:
        return _one(zpa.application_segment.get_segment(sid))
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {str(e)[:200]}"


# ---------------------------------------------------------------------------
# Field helpers
# ---------------------------------------------------------------------------

def _list_field(spec: Dict[str, Any], key: str, *, objects: bool = False, cap: Optional[int] = None) -> List[Any]:
    """spec[key] as a list ([] when absent): a page or script that sends
    another shape gets a plain refusal (400), never a crash. `objects`:
    every entry must be an object; `cap`: at most that many entries."""
    v = spec.get(key)
    if v in (None, ""):
        return []
    if not isinstance(v, list):
        raise OperationError(f"'{key}' must be a list.")
    if objects and not all(isinstance(x, dict) for x in v):
        raise OperationError(f"Every entry of '{key}' must be an object.")
    if cap is not None and len(v) > cap:
        raise OperationError(f"At most {cap} entries in '{key}' per operation; this one has {len(v)}. Split it.")
    return v


def _raw_entries(raw: Any) -> List[Any]:
    """The non-blank entries of a URL or domain list (a list, or text split on spaces and commas)."""
    vals = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
    return [v for v in vals if str(v).strip()]


_SUPER_CATEGORY = re.compile(r"^[A-Z][A-Z0-9_]{1,63}$")


def _object_name(raw: Any, what: str) -> str:
    """A name for an object this operation creates: trimmed, at most 255
    characters, no control characters (it is shown in the portal, the
    audit log and every export)."""
    name = str(raw or "").strip()
    if _has_control(name):
        raise OperationError(f"The {what} name contains a control character.")
    if len(name) > 255:
        raise OperationError(f"The {what} name is longer than 255 characters.")
    return name


def _truthy(v: Any) -> bool:
    return v is True or str(v).strip().lower() in ("true", "1", "yes")


def _int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _state(row: Dict[str, Any]) -> str:
    s = str(pc._field(row, "state", default="") or "").upper()
    if s in STATES:
        return s
    en = pc._field(row, "enabled")
    if en is not None:
        return "ENABLED" if _truthy(en) else "DISABLED"
    return s or "ENABLED"


def _is_default(row: Dict[str, Any]) -> bool:
    return _truthy(pc._field(row, "default_rule", "defaultRule", default=False)) or _int(pc._field(row, "order"), 1) <= 0


def lock_reason(policy: str, row: Dict[str, Any], *, for_order: bool = False) -> Optional[str]:
    """Why a rule is never changed here, or None. The Default rule,
    predefined (Zscaler-maintained) and read-only rules never change; for
    a reorder an Inline Web DLP exception rule (it has a parent) keeps its
    place under its parent."""
    if _is_default(row):
        return "the Default rule: it is always evaluated last and is not changed here"
    if _truthy(pc._field(row, "predefined", default=False)):
        return "a predefined rule maintained by Zscaler: not changed here"
    if str(pc._field(row, "access_control", "accessControl", default="") or "").upper() == "READ_ONLY":
        return "read-only for this API client (its admin rank or role): not changed here"
    if for_order and pc._field(row, "parent_rule", "parentRule") not in (None, "", 0, {}):
        return "an exception rule: it is ordered under its parent rule, not in the policy's list"
    return None


def _body(row: Dict[str, Any]) -> Dict[str, Any]:
    """The rule as the API takes it back on update (proposal_apply's rule:
    read-only bookkeeping fields dropped), so only the changed field differs."""
    import proposal_apply
    body = proposal_apply._body_from(row)
    body.pop("rule_type", None)
    return body


def _sort_key(row: Dict[str, Any]) -> Tuple[int, int, str]:
    return (1 if _is_default(row) else 0, _int(pc._field(row, "order"), 0), str(pc._field(row, "id")))


def _rid(v: Any) -> str:
    return str(v)


def _label(policy: str) -> str:
    return POLICIES.get(policy, {}).get("label", policy)


def _rule_ref(policy: str, row: Dict[str, Any], rule_type: str = "") -> Dict[str, Any]:
    return {"type": "rule", "policy": policy, "policy_label": _label(policy), "id": pc._field(row, "id"),
            "name": str(pc._field(row, "name", default="") or ""), "order": pc._field(row, "order"),
            "rule_type": rule_type or str(row.get("rule_type") or "")}


def rule_summary(policy: str, row: Dict[str, Any]) -> Dict[str, Any]:
    """A rule as the object picker lists it."""
    out = _rule_ref(policy, row)
    out.update(state=_state(row), locked=lock_reason(policy, row), order_locked=lock_reason(policy, row, for_order=True),
               action=str(pc._field(row, "action", default="") or "") if not isinstance(pc._field(row, "action"), dict)
               else str((pc._field(row, "action") or {}).get("type") or ""))
    return out


# ---------------------------------------------------------------------------
# Minimal reordering
# ---------------------------------------------------------------------------

def minimal_moves(current: Sequence[str], desired: Sequence[str], locked: Iterable[str] = ()) -> List[Dict[str, Any]]:
    """The fewest single-rule moves that turn `current` into `desired`.

    The rules kept in place are a longest increasing subsequence of
    `desired` (by position in `current`) that contains every locked rule
    (locked rules weigh more than all others together, and they keep their
    positions, so they are always compatible). Every other rule moves once,
    in desired order, to just after its predecessor in `desired` (to the
    top when it has none): when the last move is made the list is
    `desired`. Each step is {id, index, before: the list before the move,
    after: the list after it}. Pure."""
    cur, want = [str(x) for x in current], [str(x) for x in desired]
    if sorted(cur) != sorted(want) or len(set(cur)) != len(cur):
        raise OperationError("The desired order must list exactly the rules the policy has, each once.")
    lock = {str(x) for x in locked}
    for rid in lock:
        if cur.index(rid) != want.index(rid):
            raise OperationError("A locked rule cannot move (the Default rule, predefined, read-only and exception rules keep their place).")
    pos = {rid: i for i, rid in enumerate(cur)}
    seq = [pos[r] for r in want]
    n = len(seq)
    heavy = n + 1
    weight = [heavy if want[i] in lock else 1 for i in range(n)]
    best = list(weight)
    prev = [-1] * n
    for i in range(n):
        for j in range(i):
            if seq[j] < seq[i] and best[j] + weight[i] > best[i]:
                best[i], prev[i] = best[j] + weight[i], j
    keep: Set[str] = set()
    if n:
        i = max(range(n), key=lambda k: (best[k], -k))
        while i != -1:
            keep.add(want[i])
            i = prev[i]
    sim = list(cur)
    steps: List[Dict[str, Any]] = []
    for i, rid in enumerate(want):
        if rid in keep:
            continue
        before = list(sim)
        sim.remove(rid)
        t = 0 if i == 0 else sim.index(want[i - 1]) + 1
        sim.insert(t, rid)
        steps.append({"id": rid, "index": t, "before": before, "after": list(sim)})
    if sim != want:   # cannot happen (see the docstring); never send a wrong order
        raise OperationError("Internal error: the computed moves do not reach the desired order.")
    return steps


# ---------------------------------------------------------------------------
# URL and domain validation
# ---------------------------------------------------------------------------

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")


def _ascii_host(host: str) -> Optional[str]:
    """An internationalised host name in its ASCII (punycode) form, as the
    API stores it (assumed for ZIA and ZPA: the SDK passes names through),
    through the app's one IDN encoder (zia_path_modules.ascii_host, UTS 46,
    the form browsers send); None when it cannot be encoded."""
    if host.isascii():
        return host
    import zia_path_modules
    try:
        return zia_path_modules.ascii_host(host)
    except ValueError:
        return None


def _has_control(s: str) -> bool:
    return any(ord(c) < 32 or 127 <= ord(c) < 160 for c in s)


def _host_ok(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    labels = host.split(".")
    return len(host) <= 253 and len(labels) >= 2 and all(_LABEL_RE.match(x) for x in labels) and not labels[-1].isdigit()


def normalize_url(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """(url as ZIA lists it, None) or (None, why it is refused). ZIA takes
    a host (".example.com" also covers its subdomains), optionally a port
    and a path, without a scheme; the scheme is dropped and the host
    lower-cased here."""
    s = str(raw or "").strip()
    if not s:
        return None, "empty"
    if any(c.isspace() for c in s):
        return None, "contains a space"
    if _has_control(s):
        return None, "contains a control character"
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s, flags=re.I)
    if len(s) > URL_MAX_LEN:
        return None, f"longer than {URL_MAX_LEN} characters"
    if "*" in s:
        return None, "ZIA does not take '*' wildcards in a custom URL: write .example.com to cover example.com and its subdomains"
    host, sep, rest = s.partition("/")
    lead = "." if host.startswith(".") else ""
    host = host[1:] if lead else host
    port = ""
    if ":" in host and not host.startswith("["):
        host, _, port = host.rpartition(":")
        if not port.isdigit() or not 0 < int(port) < 65536:
            return None, "has an invalid port"
    host = _ascii_host(host.lower().rstrip("."))
    if not host or not _host_ok(host):
        return None, "is not a valid host name or IP address"
    return f"{lead}{host}{':' + port if port else ''}{sep}{rest}", None


def normalize_domain(raw: Any) -> Tuple[Optional[str], Optional[str]]:
    """(domain as ZPA lists it, None) or (None, why it is refused): an
    FQDN, a wildcard *.example.com, an IP address or a CIDR range."""
    s = str(raw or "").strip().lower().rstrip(".")
    if not s:
        return None, "empty"
    if _has_control(s) or any(c.isspace() for c in s):
        return None, "contains a space or a control character"
    if "/" in s:
        try:
            ipaddress.ip_network(s, strict=False)
            return s, None
        except ValueError:
            return None, "is not a valid domain, IP address or CIDR range"
    wild = "*." if s.startswith("*.") else ""
    body = _ascii_host(s[len(wild):])
    if not body or "*" in body or not _host_ok(body):
        return None, "is not a valid domain (FQDN, *.domain, IP address or CIDR range)"
    return wild + body, None


def _ranges(row: Dict[str, Any], proto: str) -> List[Tuple[int, int]]:
    """A segment's port ranges for tcp / udp: the legacy flat list
    ["80", "80", "443", "443"] or the newer [{"from", "to"}] list."""
    out: List[Tuple[int, int]] = []
    flat = pc._field(row, f"{proto}_port_ranges", f"{proto}PortRanges", default=[]) or []
    for i in range(0, len(flat) - 1, 2):
        a, b = _int(flat[i], -1), _int(flat[i + 1], -1)
        if a >= 0 and b >= 0:
            out.append((min(a, b), max(a, b)))
    for r in pc._field(row, f"{proto}_port_range", f"{proto}PortRange", default=[]) or []:
        if isinstance(r, dict):
            a, b = _int(r.get("from"), -1), _int(r.get("to"), -1)
            if a >= 0 and b >= 0 and (min(a, b), max(a, b)) not in out:
                out.append((min(a, b), max(a, b)))
    return out


def _flat(ranges: Sequence[Tuple[int, int]]) -> List[str]:
    return [str(x) for a, b in ranges for x in (a, b)]


def ports_overlap(a: Dict[str, Any], b: Dict[str, Any]) -> List[str]:
    """The protocol/port ranges two segments share ([] when none), e.g. ['TCP 443']."""
    out = []
    for proto in ("tcp", "udp"):
        for a1, a2 in _ranges(a, proto):
            for b1, b2 in _ranges(b, proto):
                lo, hi = max(a1, b1), min(a2, b2)
                if lo <= hi:
                    out.append(f"{proto.upper()} {lo}" + (f"-{hi}" if hi != lo else ""))
    return out


def _domains(row: Dict[str, Any]) -> List[str]:
    return [str(d).strip().lower().rstrip(".") for d in (pc._field(row, "domain_names", "domainNames", default=[]) or []) if str(d).strip()]


def _covers(wild: str, domain: str) -> bool:
    return wild.startswith("*.") and domain != wild and (domain.endswith(wild[1:]))


# ZPA segment fields a domain change sends back as read (update_segment
# replaces the segment, and clears the port ranges it is not given), and
# the ones a clone copies. Port ranges always go in the legacy flat form.
SEGMENT_FIELDS = ("name", "description", "enabled", "segment_group_id", "bypass_type", "health_check_type", "health_reporting",
                  "icmp_access_type", "is_cname_enabled", "ip_anchored", "double_encrypt", "passive_health_enabled",
                  "select_connector_close_to_app", "use_in_dr_mode", "tcp_keep_alive", "config_space", "bypass_on_reauth",
                  "inspect_traffic_with_zia", "match_style", "fqdn_dns_check", "microtenant_id")


def segment_body(row: Dict[str, Any]) -> Dict[str, Any]:
    body: Dict[str, Any] = {}
    for k in SEGMENT_FIELDS:
        v = pc._field(row, k, re.sub(r"_([a-z])", lambda m: m.group(1).upper(), k))
        if v not in (None, ""):
            body[k] = v
    groups = pc._field(row, "server_groups", "serverGroups", default=[]) or []
    body["server_group_ids"] = [str(g.get("id") if isinstance(g, dict) else pc._field(g, "id")) for g in groups if g]
    body["tcp_port_ranges"] = _flat(_ranges(row, "tcp"))
    body["udp_port_ranges"] = _flat(_ranges(row, "udp"))
    body["domain_names"] = _domains(row)
    return body


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------

def _unit(key: str, group: str, kind: str, obj: Dict[str, Any], field: str, before: Any, after: Any, *, value: Any = None,
          status: str = "change", reason: str = "", depends_on: Sequence[str] = ()) -> Dict[str, Any]:
    return {"key": key, "group": group, "kind": kind, "object": obj, "field": field, "value": value, "before": before, "after": after,
            "status": status, "reason": reason, "depends_on": list(depends_on)}


def _canonical(v: Any) -> str:
    return json.dumps(v, sort_keys=True, separators=(",", ":"), default=str)


def plan_hash(prepared: Dict[str, Any]) -> str:
    """sha256 over the operation and every item's before / after and
    status, and the writes in order: a change in the tenant that touches
    the operation changes it."""
    core = {"type": prepared["type"], "spec": prepared["spec"], "product": prepared.get("product"),
            "items": [[u["key"], u["field"], u["before"], u["after"], u["status"], u["depends_on"]] for u in prepared["items"]],
            "groups": [[g["key"], g["handler"], g["target"]] for g in prepared["groups"]]}
    return hashlib.sha256(_canonical(core).encode("utf-8")).hexdigest()


def confirm_phrase(changes: int) -> str:
    return f"APPLY {changes} CHANGES" if changes > CONFIRM_ABOVE else ""


def _finish(prepared: Dict[str, Any], *, tenant_label: str = "") -> Dict[str, Any]:
    # Every write must go through a known handler: a plan naming another is
    # refused here, before anything is written (not a crash halfway through).
    unknown = sorted({str(g.get("handler")) for g in prepared["groups"] if g.get("handler") not in HANDLERS and g.get("handler") not in PLUGIN_HANDLERS})
    if unknown:
        raise OperationError(f"This operation names a write step the app does not have ({', '.join(unknown[:5])}), so nothing was planned.")
    items = prepared["items"]
    n = lambda s: sum(1 for u in items if u["status"] == s)  # noqa: E731
    counts = {"change": n("change"), "noop": n("noop"), "excluded": n("excluded"), "total": len(items)}
    prepared["counts"] = counts
    prepared.setdefault("warnings", [])
    prepared.setdefault("blockers", [])
    prepared.setdefault("impact", [])
    if counts["change"] == 0 and not prepared["blockers"]:
        prepared["warnings"].append("Nothing to change: every item is already as asked or excluded.")
    prepared["status"] = "blocked" if prepared["blockers"] else ("nothing_to_do" if counts["change"] == 0 else "ready")
    # A plugin may name its own typed confirmation (a profile's name), or ask for its
    # phrase whatever the count (`confirm_always`, a delete); upper case, compared case-insensitively.
    # A blank value never hides the other one, nor switches the phrase off.
    own = next((str(v).strip().upper() for v in (prepared.get("confirm_phrase"), prepared.get("confirm_always")) if str(v or "").strip()), "")
    prepared["confirm_phrase"] = own if own and counts["change"] else confirm_phrase(counts["change"])
    prepared["needs_activation"] = prepared.get("product") == "zia"
    prepared["kind"] = KIND
    prepared["tenant_label"] = tenant_label
    prepared["generated_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    prepared["writes"] = len(prepared["groups"])
    prepared["plan_hash"] = plan_hash(prepared)
    product = str(prepared.get("product") or "zpa").upper()   # a plugin's product (ZPA, ZDX, ...) saves each change at once
    prepared["notes"] = list(prepared.get("notes") or []) + (
        ["ZIA keeps every change pending until it is activated: the app activates once, after the last write, as a policy pack deploy does."]
        if prepared["needs_activation"] else [prepared.get("apply_note") or f"{product} applies each change as it is saved; there is no activation step."])
    return prepared


def plan(client, spec: Dict[str, Any], *, scope: Dict[str, Any], tenant_label: str = "", log: LogFn = None,
         cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """Read what the operation touches and return the prepared operation:
    {type, spec, title, items, groups, counts, impact, warnings, blockers,
    status, plan_hash, confirm_phrase, ...}. Never writes. Raises
    OperationError for a request that cannot be planned, Stopped on Stop."""
    if not isinstance(spec, dict):
        raise OperationError("The operation must be an object with a 'type'.")
    require_scope(spec, scope)
    say = log or (lambda m: None)
    t = spec.get("type")
    if t == "rule_state":
        prepared = _plan_rule_state(client.zia, spec, say, cancel)
    elif t == "reorder":
        prepared = _plan_reorder(client.zia, spec, say, cancel)
    elif t == "url_categories":
        prepared = _plan_urls(client.zia, spec, scope, say, cancel)
    elif t == "zpa_domains":
        prepared = _plan_zpa(getattr(client, "zpa", None), spec, say, cancel)
    elif t in PLUGINS:
        prepared = PLUGINS[t]["plan"](client, spec, scope, say, cancel)
        prepared.setdefault("type", t)
        prepared.setdefault("spec", spec)
    else:  # require_scope refused it already
        raise OperationError(f"Unknown operation '{t}'.")
    _check_stop(cancel)
    return _finish(prepared, tenant_label=tenant_label)


# ── rule_state ─────────────────────────────────────────────────────────

def _norm_state(v: Any) -> str:
    s = str(v or "").strip().upper()
    if s in ("ENABLE", "ON", "TRUE"):
        s = "ENABLED"
    if s in ("DISABLE", "OFF", "FALSE"):
        s = "DISABLED"
    if s not in STATES:
        raise OperationError("The state must be ENABLED or DISABLED.")
    return s


def _plan_rule_state(zia, spec: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    targets = [t for t in _list_field(spec, "targets") if isinstance(t, dict)]
    if not targets:
        raise OperationError("Pick at least one rule.")
    if len(targets) > MAX_TARGETS:
        raise OperationError(f"At most {MAX_TARGETS} rules per operation; this one names {len(targets)}. Split it.")
    default_to = _norm_state(spec.get("value")) if spec.get("value") not in (None, "") else None
    norm: List[Dict[str, Any]] = []
    seen = set()
    for t in targets:
        pol = str(t.get("policy") or "")
        if pol not in POLICIES:
            raise OperationError(f"Unknown policy '{pol}'.")
        to = _norm_state(t["to"]) if t.get("to") not in (None, "") else default_to
        if to is None:
            raise OperationError("Say which state to set (value ENABLED or DISABLED).")
        key = (pol, str(t.get("rule_type") or ""), _rid(t.get("id")))
        if key in seen:
            continue
        seen.add(key)
        norm.append({"policy": pol, "rule_type": key[1], "id": t.get("id"), "to": to})
    nspec = {"type": "rule_state", "targets": norm}
    # One list per policy (and Cloud App Control type) the targets name.
    lists: Dict[Tuple[str, str], Dict[str, Dict[str, Any]]] = {}
    errors: Dict[str, str] = {}
    for pol, rtype in sorted({(x["policy"], x["rule_type"]) for x in norm}):
        say(f"Reading the {_label(pol)} rules{' (' + rtype + ')' if rtype else ''}…")
        rows, err = read_rules(zia, pol, rule_type=rtype, cancel=cancel)
        if err:
            errors[pol] = err
        lists[(pol, rtype)] = {_rid(pc._field(r, "id")): r for r in rows}
    items, groups = [], []
    for x in norm:
        rows = lists.get((x["policy"], x["rule_type"])) or {}
        row = rows.get(_rid(x["id"]))
        if row is None and not x["rule_type"] and x["policy"] == "cloud_app_control":
            row = next((r for (p, _t), rs in lists.items() if p == "cloud_app_control" for r in rs.values() if _rid(pc._field(r, "id")) == _rid(x["id"])), None)
        gkey = f"rule:{x['policy']}:{x['rule_type']}:{x['id']}"
        ukey = gkey + ":state"
        if row is None:
            why = (f"the {_label(x['policy'])} rules could not be read: {errors[x['policy']]}" if x["policy"] in errors
                   else "no such rule in the tenant now")
            items.append(_unit(ukey, gkey, "rule_state", {"type": "rule", "policy": x["policy"], "policy_label": _label(x["policy"]),
                                                           "id": x["id"], "name": "", "rule_type": x["rule_type"]},
                               "state", None, x["to"], status="excluded", reason=why))
            continue
        ref = _rule_ref(x["policy"], row, x["rule_type"])
        before = _state(row)
        locked = lock_reason(x["policy"], row)
        if locked:
            items.append(_unit(ukey, gkey, "rule_state", ref, "state", before, x["to"], status="excluded", reason=locked))
        elif before == x["to"]:
            items.append(_unit(ukey, gkey, "rule_state", ref, "state", before, x["to"], status="noop", reason=f"already {before.lower()}"))
        else:
            items.append(_unit(ukey, gkey, "rule_state", ref, "state", before, x["to"]))
            groups.append({"key": gkey, "handler": "rule_state", "target": {"policy": x["policy"], "id": ref["id"], "rule_type": ref["rule_type"],
                                                                           "name": ref["name"]}})
    vals = sorted({x["to"] for x in norm})
    verb = {"ENABLED": "Enable", "DISABLED": "Disable"}.get(vals[0], "Set") if len(vals) == 1 else "Set the state of"
    n = sum(1 for u in items if u["status"] == "change")
    return {"type": "rule_state", "spec": nspec, "product": "zia", "items": items, "groups": groups,
            "title": f"{verb} {n} rule{'s' if n != 1 else ''}", "warnings": [f"{_label(p)}: {e}" for p, e in errors.items()]}


# ── reorder ────────────────────────────────────────────────────────────

def _plan_reorder(zia, spec: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    pol = str(spec.get("policy") or "")
    if pol not in POLICIES:
        raise OperationError(f"Unknown policy '{pol}'.")
    if not POLICIES[pol]["ordered"]:
        raise OperationError(f"{_label(pol)} rules have no documented evaluation order, so they are not reordered here.")
    rtype = str(spec.get("rule_type") or "").upper()
    if pol == "cloud_app_control" and not rtype:
        raise OperationError("Cloud App Control rules are ordered per application type: name the rule_type.")
    desired_movable = [_rid(x) for x in _list_field(spec, "order")]
    if not desired_movable:
        raise OperationError("Give the desired order (the rule ids, top first).")
    say(f"Reading the {_label(pol)} rules{' (' + rtype + ')' if rtype else ''}…")
    rows, err = read_rules(zia, pol, rule_type=rtype, cancel=cancel)
    if err:
        raise OperationError(f"The {_label(pol)} rules could not be read, so no order can be planned: {err}")
    rows = sorted(rows, key=_sort_key)
    by_id = {_rid(pc._field(r, "id")): r for r in rows}
    current = [_rid(pc._field(r, "id")) for r in rows]
    locked = {rid for rid in current if lock_reason(pol, by_id[rid], for_order=True)}
    movable = [rid for rid in current if rid not in locked]
    if len(set(desired_movable)) != len(desired_movable):
        raise OperationError("The desired order names a rule twice.")
    extra = [x for x in desired_movable if x not in by_id]
    fixed = [x for x in desired_movable if x in locked]
    missing = [x for x in movable if x not in desired_movable]
    if extra:
        raise OperationError(f"Not a rule of this policy now: {', '.join(extra[:10])}. Read the rules again.")
    if fixed:
        raise OperationError("These rules never move (Default, predefined, read-only or exception rules): "
                             + ", ".join(str(by_id[x].get("name") or x) for x in fixed[:10]) + ". Leave them out of the order.")
    if missing:
        raise OperationError("The desired order must name every movable rule; missing: "
                             + ", ".join(str(by_id[x].get("name") or x) for x in missing[:10]) + ".")
    it = iter(desired_movable)
    desired = [rid if rid in locked else next(it) for rid in current]
    steps = minimal_moves(current, desired, locked)
    slots = [_int(pc._field(by_id[r], "order"), 0) for r in current]
    pos_after = {rid: i for i, rid in enumerate(desired)}
    by_unit: Dict[str, Dict[str, Any]] = {}
    groups = []
    prev_key = None
    for s_ in steps:
        r = by_id[s_["id"]]
        ref = _rule_ref(pol, r, rtype)
        gkey = f"order:{pol}:{rtype}:{s_['id']}"
        at = pos_after[s_["id"]]
        prev_name = by_id[desired[at - 1]].get("name") if at > 0 else None
        by_unit[s_["id"]] = _unit(gkey, gkey, "rule_order", ref, "order", _int(pc._field(r, "order"), 0), slots[at],
                                  reason=f"moves to just below '{prev_name}'" if prev_name else "moves to the top",
                                  depends_on=[prev_key] if prev_key else [])
        groups.append({"key": gkey, "handler": "rule_order", "target": {"policy": pol, "rule_type": rtype, "id": ref["id"], "name": ref["name"],
                                                                       "send_order": slots[s_["index"]], "expect_before": s_["before"],
                                                                       "expect_after": s_["after"]}})
        prev_key = gkey
    items = []
    for rid in current:   # the items in the policy's current order
        if rid in by_unit:
            items.append(by_unit[rid])
            continue
        r = by_id[rid]
        ref = _rule_ref(pol, r, rtype)
        gkey = f"order:{pol}:{rtype}:{rid}"
        before, after = _int(pc._field(r, "order"), 0), slots[pos_after[rid]]
        if rid in locked:
            items.append(_unit(gkey, gkey, "rule_order", ref, "order", before, before, status="excluded",
                               reason=lock_reason(pol, r, for_order=True) or "locked"))
        else:
            note = "keeps its place" + (f"; its order number becomes {after} as the rules around it move" if after != before else "")
            items.append(_unit(gkey, gkey, "rule_order", ref, "order", before, after, status="noop", reason=note))
    warnings = []
    last = -1
    for rid in desired:
        rk = _int(pc._field(by_id[rid], "rank"), -1)
        if rk < 0 or rid in locked:
            continue
        if rk < last:
            warnings.append(f"'{by_id[rid].get('name')}' (admin rank {rk}) would sit below a rule of a lower rank. ZIA keeps rules of "
                            "a higher rank above lower ones, so it may refuse or adjust this move; the read-back will show it.")
            break
        last = rk
    moved = set(by_unit)
    n = len(steps)
    return {"type": "reorder", "spec": {"type": "reorder", "policy": pol, "rule_type": rtype, "order": desired_movable}, "product": "zia",
            "items": items, "groups": groups, "warnings": warnings,
            "title": f"Reorder {_label(pol)}{' (' + rtype + ')' if rtype else ''}: {n} move{'s' if n != 1 else ''}",
            "order_before": [{"id": by_id[r].get("id"), "name": by_id[r].get("name"), "order": by_id[r].get("order"), "locked": r in locked} for r in current],
            "order_after": [{"id": by_id[r].get("id"), "name": by_id[r].get("name"), "order": slots[i], "locked": r in locked,
                             "moved": r in moved} for i, r in enumerate(desired)],
            "before_order": movable}


# ── url_categories ─────────────────────────────────────────────────────

def _urls_of(row: Optional[Dict[str, Any]]) -> List[str]:
    return [str(u).strip() for u in (pc._field(row or {}, "urls", default=[]) or []) if str(u).strip()]


def _url_set(row: Optional[Dict[str, Any]]) -> Set[str]:
    return {u.lower() for u in _urls_of(row)}


def _cat_ref(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "url_category", "id": pc._field(row, "id"), "name": str(pc._field(row, "configured_name", "configuredName", default="")
                                                                          or pc._field(row, "id") or "")}


def _clean_urls(raw: Any) -> Tuple[List[str], List[Tuple[str, str]]]:
    vals = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
    ok, bad, seen = [], [], set()
    for v in vals:
        if not str(v).strip():
            continue
        u, why = normalize_url(v)
        if why:
            bad.append((str(v)[:200], why))
        elif u.lower() not in seen:
            seen.add(u.lower())
            ok.append(u)
    return ok, bad


def _category_refs(rule: Dict[str, Any]) -> Set[str]:
    import shadow_rules
    out: Set[str] = set()
    for k, v in rule.items():
        if shadow_rules._canon(k) in _CATEGORY_FIELDS:
            out |= set(shadow_rules._tokens(v))
    return out


def _plan_urls(zia, spec: Dict[str, Any], scope: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    action = str(spec.get("action") or "").lower()
    if action not in ("add", "remove", "move", "copy", "revert"):
        raise OperationError("The URL action must be add, remove, move or copy.")
    say("Reading the custom URL categories…")
    _check_stop(cancel)
    cats, err = read_categories(zia)
    if err:
        raise OperationError(f"The custom URL categories could not be read: {err}")
    by_id = {_rid(pc._field(c, "id")): c for c in cats}
    by_name = {str(_cat_ref(c)["name"]).strip().lower(): c for c in cats}

    def cat(cid: Any, what: str) -> Dict[str, Any]:
        c = by_id.get(_rid(cid))
        if c is None:
            raise OperationError(f"The {what} category {cid!r} is not a custom URL category of this tenant now. Read the categories again.")
        return c

    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    excluded: List[Tuple[str, str]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    affected: Dict[str, Dict[str, Any]] = {}
    nspec: Dict[str, Any] = {"type": "url_categories", "action": action}
    # deltas: [(category row or None for new, add urls, remove urls)]
    adds: Dict[str, List[str]] = {}
    removes: Dict[str, List[str]] = {}
    create: Optional[Dict[str, Any]] = None
    deletes: List[Dict[str, Any]] = []
    move_pairs = False
    if action == "revert":
        for d in _list_field(spec, "deltas", objects=True, cap=MAX_URLS):
            c = cat(d.get("category"), "")
            a, bad_a = _clean_urls(d.get("add") or [])
            r, bad_r = _clean_urls(d.get("remove") or [])
            excluded += bad_a + bad_r
            cid = _rid(pc._field(c, "id"))
            adds.setdefault(cid, []).extend(a)
            removes.setdefault(cid, []).extend(r)
        for d in _list_field(spec, "delete_categories", objects=True, cap=MAX_TARGETS):
            deletes.append({"id": d.get("id"), "name": d.get("name"), "urls": [str(u) for u in _list_field(d, "urls")]})
        if sum(len(v) for v in adds.values()) + sum(len(v) for v in removes.values()) > MAX_URLS:
            raise OperationError(f"At most {MAX_URLS} URLs per operation. Split it.")
        nspec.update(deltas=[{"category": k, "add": adds.get(k, []), "remove": removes.get(k, [])} for k in sorted(set(adds) | set(removes))],
                     delete_categories=deletes)
    else:
        if len(_raw_entries(spec.get("urls"))) > MAX_URLS:
            raise OperationError(f"At most {MAX_URLS} URLs per operation; this one lists {len(_raw_entries(spec.get('urls')))}. Split it.")
        urls, bad = _clean_urls(spec.get("urls") or [])
        excluded += bad
        if not urls and not bad:
            raise OperationError("List at least one URL.")
        if len(urls) > MAX_URLS:
            raise OperationError(f"At most {MAX_URLS} URLs per operation; this one lists {len(urls)}. Split it.")
        nspec["urls"] = urls
        src = tgt = None
        if action in ("remove", "move", "copy"):
            src = cat(spec.get("source"), "source")
            nspec["source"] = _rid(pc._field(src, "id"))
        if action in ("add", "move", "copy"):
            new = spec.get("create_target") if isinstance(spec.get("create_target"), dict) else None
            if new and str(new.get("name") or "").strip():
                name = _object_name(new["name"], "new category's")
                if name.lower() in by_name:
                    blockers.append(f"A URL category named '{name}' already exists: pick it as the target instead of creating it.")
                sup = str(new.get("super_category") or "USER_DEFINED").strip().upper()
                if not _SUPER_CATEGORY.match(sup):
                    raise OperationError("The super category must be a ZIA super category name such as USER_DEFINED.")
                create = {"name": name, "super_category": sup}
                nspec["create_target"] = create
            else:
                tgt = cat(spec.get("target"), "target")
                nspec["target"] = _rid(pc._field(tgt, "id"))
        if src is not None and tgt is not None and _rid(pc._field(src, "id")) == _rid(pc._field(tgt, "id")):
            raise OperationError("The source and the target are the same category.")
        if tgt is not None:
            adds[_rid(pc._field(tgt, "id"))] = list(urls)
        if src is not None and action in ("remove", "move"):
            removes[_rid(pc._field(src, "id"))] = list(urls)
        move_pairs = action == "move"
        if create is not None:
            create["urls"] = list(urls)
    for raw, why in excluded:
        items.append(_unit(f"url:invalid:{raw}", "", "url", {"type": "url", "id": None, "name": raw}, "urls", None, None,
                           value=raw, status="excluded", reason=f"not a valid URL: {why}"))
    # Creates first, then additions, then removals (a move never loses a URL).
    add_keys: Dict[str, str] = {}
    if create is not None:
        gkey = f"cat:new:{create['name'].lower()}"
        cref = {"type": "url_category", "id": None, "name": create["name"], "new": True}
        items.append(_unit(gkey + ":exists", gkey, "create_category", cref, "exists", False, True,
                           reason=f"new custom category (super category {create['super_category']})"))
        for u in create["urls"]:
            k = f"{gkey}:+{u.lower()}"
            add_keys[u.lower()] = k
            items.append(_unit(k, gkey, "url", cref, "urls", False, True, value=u, depends_on=[gkey + ":exists"]))
        groups.append({"key": gkey, "handler": "url_create", "target": {"name": create["name"], "super_category": create["super_category"],
                                                                       "urls": create["urls"]}})
        affected[gkey] = {"category": create["name"], "id": None, "new": True}
    for cid in sorted(adds):
        c = by_id[cid]
        cref, have = _cat_ref(c), _url_set(c)
        gkey = f"cat:{cid}:add"
        changed = []
        for u in adds[cid]:
            k = f"cat:{cid}:+{u.lower()}"
            add_keys[u.lower()] = k
            if u.lower() in have:
                items.append(_unit(k, gkey, "url", cref, "urls", True, True, value=u, status="noop", reason="already in this category"))
            else:
                items.append(_unit(k, gkey, "url", cref, "urls", False, True, value=u))
                changed.append(u)
        if changed:
            groups.append({"key": gkey, "handler": "url_add", "target": {"id": cref["id"], "name": cref["name"], "urls": changed}})
        affected[cid] = {"category": cref["name"], "id": cref["id"]}
    for cid in sorted(removes):
        c = by_id[cid]
        cref, have = _cat_ref(c), _url_set(c)
        gkey = f"cat:{cid}:remove"
        changed = []
        for u in removes[cid]:
            k = f"cat:{cid}:-{u.lower()}"
            deps = [add_keys[u.lower()]] if move_pairs and u.lower() in add_keys else []
            if u.lower() not in have:
                items.append(_unit(k, gkey, "url", cref, "urls", False, False, value=u, status="noop" if action != "move" else "excluded",
                                   reason="not in this category" if action != "move" else "not in the source category, so there is nothing to move"))
                continue
            items.append(_unit(k, gkey, "url", cref, "urls", True, False, value=u, depends_on=deps,
                               reason="removed once it is in the target" if deps else ""))
            changed.append(u)
        if changed:
            groups.append({"key": gkey, "handler": "url_remove", "target": {"id": cref["id"], "name": cref["name"], "urls": changed}})
        affected[cid] = {"category": cref["name"], "id": cref["id"]}
    if move_pairs:   # a URL whose copy into the target was excluded is not removed from the source either
        for u in items:
            for d in list(u["depends_on"]):
                dep = next((x for x in items if x["key"] == d), None)
                if dep is not None and dep["status"] == "excluded" and u["status"] == "change":
                    u.update(status="excluded", reason=f"not moved: {dep['reason']}")
    for d in deletes:
        c = by_id.get(_rid(d.get("id")))
        gkey = f"cat:{d.get('id')}:delete"
        cref = _cat_ref(c) if c else {"type": "url_category", "id": d.get("id"), "name": d.get("name") or str(d.get("id"))}
        if c is None:
            items.append(_unit(gkey, gkey, "delete_category", cref, "exists", False, False, status="noop", reason="already gone"))
            continue
        if _url_set(c) != {str(u).lower() for u in d["urls"]}:
            items.append(_unit(gkey, gkey, "delete_category", cref, "exists", True, False, status="excluded",
                               reason="its URLs changed since this operation created it, so it is kept (someone else's change is never removed)"))
            continue
        items.append(_unit(gkey, gkey, "delete_category", cref, "exists", True, False, reason="the category this operation created"))
        groups.append({"key": gkey, "handler": "url_delete", "target": {"id": cref["id"], "name": cref["name"], "urls": sorted(_url_set(c))}})
        affected[_rid(cref["id"])] = {"category": cref["name"], "id": cref["id"], "delete": True}
    # Impact: the rules in scope that name an affected category.
    impact = []
    pols = [p for p in CATEGORY_POLICIES if p in scope.get("policies", [])]
    refs: Dict[str, List[Dict[str, Any]]] = {}
    read_errors = []
    if affected and pols:
        for pol in pols:
            say(f"Reading the {_label(pol)} rules (which rules use these categories)…")
            _check_stop(cancel)
            rows, rerr = read_rules(zia, pol, cancel=cancel)
            if rerr:
                read_errors.append(f"{_label(pol)}: {rerr}")
                continue
            for r in rows:
                names = _category_refs(r)
                for key, a in affected.items():
                    if a.get("id") is not None and (_rid(a["id"]) in names or a["category"] in names):
                        refs.setdefault(key, []).append({"policy": pol, "policy_label": _label(pol), "name": r.get("name"), "order": r.get("order"),
                                                         "state": _state(r)})
    for key, a in affected.items():
        rules = refs.get(key, [])
        impact.append({"category": a["category"], "id": a.get("id"), "new": bool(a.get("new")), "rules": rules,
                       "detail": ("A new category: no rule uses it until one names it." if a.get("new") else
                                  (f"{len(rules)} rule{'s' if len(rules) != 1 else ''} in scope use{'s' if len(rules) == 1 else ''} this category: "
                                   "what they match changes with its URLs." if rules else "No rule in scope names this category."))})
        if a.get("delete") and rules:
            for u in items:
                if u["group"] == f"cat:{a['id']}:delete" and u["status"] == "change":
                    u.update(status="excluded", reason=f"still used by {len(rules)} rule(s): " + ", ".join(str(x['name']) for x in rules[:5]))
            groups[:] = [g for g in groups if g["key"] != f"cat:{a['id']}:delete"]
    if read_errors:
        warnings.append("The impact is incomplete; these rules could not be read: " + "; ".join(read_errors))
    nis = [p for p in CATEGORY_POLICIES if p not in scope.get("policies", [])]
    if nis:
        warnings.append("Rules not in scope are not checked for the categories they use: " + ", ".join(_label(p) for p in nis) + ".")
    # The tenant's URL quota, when it says (urlCategories/urlQuota).
    n_add = sum(1 for u in items if u["kind"] == "url" and u["status"] == "change" and u["after"] is True)
    if n_add:
        try:
            q = zia.url_categories.get_quota()
            left = (q or {}).get("remainingUrlsQuota") if isinstance(q, dict) else None
            if left is not None and _int(left, 10 ** 9) < n_add:
                blockers.append(f"The tenant's custom URL quota has room for {left} more URL(s); this operation adds {n_add}.")
        except Exception:  # noqa: BLE001 — the quota is a courtesy check; ZIA refuses past it anyway
            pass
    n = sum(1 for u in items if u["status"] == "change" and u["kind"] == "url")
    src_name = by_id[nspec["source"]]["configured_name"] if nspec.get("source") in by_id and by_id[nspec["source"]].get("configured_name") else nspec.get("source")
    tgt_name = (create or {}).get("name") or (_cat_ref(by_id[nspec["target"]])["name"] if nspec.get("target") in by_id else nspec.get("target"))
    title = {"add": f"Add {n} URL{'s' if n != 1 else ''} to {tgt_name}", "remove": f"Remove {n} URL{'s' if n != 1 else ''} from {src_name}",
             "move": f"Move URLs from {src_name} to {tgt_name}", "copy": f"Copy {n} URL{'s' if n != 1 else ''} from {src_name} to {tgt_name}",
             "revert": "Undo a URL category change"}[action]
    return {"type": "url_categories", "spec": nspec, "product": "zia", "items": items, "groups": groups, "impact": impact,
            "warnings": warnings, "blockers": blockers, "title": title}


# ── zpa_domains ────────────────────────────────────────────────────────

def _seg_ref(row: Dict[str, Any]) -> Dict[str, Any]:
    return {"type": "zpa_segment", "id": pc._field(row, "id"), "name": str(pc._field(row, "name", default="") or pc._field(row, "id"))}


def segment_summary(row: Dict[str, Any]) -> Dict[str, Any]:
    out = _seg_ref(row)
    out.update(domains=_domains(row), tcp=[f"{a}-{b}" if a != b else str(a) for a, b in _ranges(row, "tcp")],
               udp=[f"{a}-{b}" if a != b else str(a) for a, b in _ranges(row, "udp")], enabled=_truthy(pc._field(row, "enabled", default=True)),
               segment_group=str(pc._field(row, "segment_group_name", "segmentGroupName", default="") or ""))
    return out


def _clean_domains(raw: Any) -> Tuple[List[str], List[Tuple[str, str]]]:
    vals = raw if isinstance(raw, list) else re.split(r"[\s,]+", str(raw or ""))
    ok, bad, seen = [], [], set()
    for v in vals:
        if not str(v).strip():
            continue
        d, why = normalize_domain(v)
        if why:
            bad.append((str(v)[:200], why))
        elif d not in seen:
            seen.add(d)
            ok.append(d)
    return ok, bad


def _plan_zpa(zpa, spec: Dict[str, Any], say, cancel) -> Dict[str, Any]:
    action = str(spec.get("action") or "").lower()
    if action not in ("move", "copy", "clone", "revert"):
        raise OperationError("The ZPA action must be move, copy or clone.")
    say("Reading the ZPA application segments…")
    _check_stop(cancel)
    segs, err = read_segments(zpa, cancel)
    if err:
        raise OperationError(f"The ZPA application segments could not be read: {err}")
    by_id = {_rid(pc._field(s, "id")): s for s in segs}
    names = {str(pc._field(s, "name", default="")).strip().lower() for s in segs}

    def seg(sid: Any, what: str) -> Dict[str, Any]:
        s = by_id.get(_rid(sid))
        if s is None:
            raise OperationError(f"The {what} segment {sid!r} is not in the tenant now. Read the segments again.")
        return s

    nspec: Dict[str, Any] = {"type": "zpa_domains", "action": action}
    items: List[Dict[str, Any]] = []
    groups: List[Dict[str, Any]] = []
    warnings: List[str] = []
    blockers: List[str] = []
    adds: Dict[str, List[str]] = {}
    removes: Dict[str, List[str]] = {}
    clone: Optional[Dict[str, Any]] = None
    deletes: List[Dict[str, Any]] = []
    excluded: List[Tuple[str, str]] = []
    if action == "revert":
        for d in _list_field(spec, "deltas", objects=True, cap=MAX_DOMAINS):
            s = seg(d.get("segment"), "")
            a, ba = _clean_domains(d.get("add") or [])
            r, br = _clean_domains(d.get("remove") or [])
            excluded += ba + br
            sid = _rid(pc._field(s, "id"))
            adds.setdefault(sid, []).extend(a)
            removes.setdefault(sid, []).extend(r)
        for d in _list_field(spec, "delete_segments", objects=True, cap=MAX_TARGETS):
            deletes.append({"id": d.get("id"), "name": d.get("name"), "domains": [str(x).lower() for x in _list_field(d, "domains")]})
        if sum(len(v) for v in adds.values()) + sum(len(v) for v in removes.values()) > MAX_DOMAINS:
            raise OperationError(f"At most {MAX_DOMAINS} domains per operation. Split it.")
        nspec.update(deltas=[{"segment": k, "add": adds.get(k, []), "remove": removes.get(k, [])} for k in sorted(set(adds) | set(removes))],
                     delete_segments=deletes)
    else:
        if len(_raw_entries(spec.get("domains"))) > MAX_DOMAINS:
            raise OperationError(f"At most {MAX_DOMAINS} domains per operation; this one lists {len(_raw_entries(spec.get('domains')))}.")
        doms, bad = _clean_domains(spec.get("domains") or [])
        excluded += bad
        if not doms and not bad:
            raise OperationError("List at least one domain.")
        if len(doms) > MAX_DOMAINS:
            raise OperationError(f"At most {MAX_DOMAINS} domains per operation; this one lists {len(doms)}.")
        src = seg(spec.get("source"), "source")
        sid = _rid(pc._field(src, "id"))
        nspec.update(source=sid, domains=doms)
        if action == "clone":
            name = _object_name(spec.get("name"), "new segment's")
            if not name:
                raise OperationError("Name the new segment.")
            if name.lower() in names:
                blockers.append(f"An application segment named '{name}' already exists.")
            move = bool(spec.get("move"))
            nspec.update(name=name, move=move)
            clone = {"name": name, "source": sid, "domains": doms, "move": move}
            if move:
                removes[sid] = [d for d in doms]
        else:
            tgt = seg(spec.get("target"), "target")
            tid = _rid(pc._field(tgt, "id"))
            if tid == sid:
                raise OperationError("The source and the target are the same segment.")
            nspec["target"] = tid
            adds[tid] = list(doms)
            if action == "move":
                removes[sid] = list(doms)
    for raw, why in excluded:
        items.append(_unit(f"dom:invalid:{raw}", "", "domain", {"type": "domain", "id": None, "name": raw}, "domain_names", None, None,
                           value=raw, status="excluded", reason=f"not valid: {why}"))
    leaving = {(sid, d) for sid, ds in removes.items() for d in ds}
    # Overlap: a domain may sit in two segments only on ports that do not overlap (assumed ZPA rule; ZPA refuses the save otherwise).
    def overlap(target_row: Dict[str, Any], tid: str, d: str) -> Tuple[Optional[str], Optional[str]]:
        for oid, other in by_id.items():
            if oid == tid or (oid, d) in leaving:
                continue
            od = _domains(other)
            shared = ports_overlap(target_row, other)
            if d in od and shared:
                return f"already in segment '{pc._field(other, 'name')}' on overlapping ports ({', '.join(shared[:3])})", None
            wild = next((w for w in od if _covers(w, d)), None)
            if wild and shared:
                return None, f"{d} is also covered by {wild} in segment '{pc._field(other, 'name')}' on overlapping ports; ZPA sends it to the more specific match."
        return None, None

    # Segments this operation deletes (an Undo of a clone) go first: their
    # domains are leaving, so putting them back elsewhere is no overlap.
    leaving_by_delete: Dict[str, str] = {}
    for d in deletes:
        s = by_id.get(_rid(d.get("id")))
        gkey = f"seg:{d.get('id')}:delete"
        ref = _seg_ref(s) if s else {"type": "zpa_segment", "id": d.get("id"), "name": d.get("name") or str(d.get("id"))}
        if s is None:
            items.append(_unit(gkey, gkey, "delete_segment", ref, "exists", False, False, status="noop", reason="already gone"))
        elif set(_domains(s)) != set(d["domains"]):
            items.append(_unit(gkey, gkey, "delete_segment", ref, "exists", True, False, status="excluded",
                               reason="its domains changed since this operation created it, so it is kept"))
        else:
            items.append(_unit(gkey, gkey, "delete_segment", ref, "exists", True, False, reason="the segment this operation created"))
            for dom in _domains(s):
                leaving.add((_rid(d.get("id")), dom))
                leaving_by_delete[dom] = gkey
    remove_keys: Dict[Tuple[str, str], str] = {}
    for sid in sorted(removes):
        s = by_id[sid]
        ref, have = _seg_ref(s), set(_domains(s))
        gkey = f"seg:{sid}"
        for d in removes[sid]:
            k = f"seg:{sid}:-{d}"
            remove_keys[(sid, d)] = k
            if d not in have:
                items.append(_unit(k, gkey, "domain", ref, "domain_names", False, False, value=d, status="excluded",
                                   reason="not in the source segment, so there is nothing to move"))
            else:
                items.append(_unit(k, gkey, "domain", ref, "domain_names", True, False, value=d))
        # ZPA keeps at least one domain in a segment: a removal that would
        # empty it is excluded here, in the preview, not first found while
        # writing (where the move would already have half happened).
        if not (have - set(removes[sid])) and not adds.get(sid):
            for d in removes[sid]:
                u = next(x for x in items if x["key"] == remove_keys[(sid, d)])
                if u["status"] == "change":
                    u.update(status="excluded", reason=LAST_DOMAIN)
    if clone is not None:
        s = by_id[clone["source"]]
        gkey = "seg:new:" + clone["name"].lower()
        ref = {"type": "zpa_segment", "id": None, "name": clone["name"], "new": True}
        items.append(_unit(gkey + ":exists", gkey, "create_segment", ref, "exists", False, True,
                           reason=f"a copy of '{pc._field(s, 'name')}' (its segment group, server groups, ports and settings)"))
        for d in clone["domains"]:
            why, note = overlap(s, "new", d)
            # The clone has the source's ports: a domain moving into it leaves the source first.
            deps = [gkey + ":exists"] + ([remove_keys[(clone["source"], d)]] if (clone["source"], d) in remove_keys else [])
            items.append(_unit(f"{gkey}:+{d}", gkey, "domain", ref, "domain_names", False, True, value=d, status="excluded" if why else "change",
                               reason=why or ("added once it has left the source" if len(deps) > 1 else ""), depends_on=deps))
            if note:
                warnings.append(note)
    for tid in sorted(adds):
        t = by_id[tid]
        ref, have = _seg_ref(t), set(_domains(t))
        gkey = f"seg:{tid}"
        for d in adds[tid]:
            k = f"seg:{tid}:+{d}"
            if d in have:
                items.append(_unit(k, gkey, "domain", ref, "domain_names", True, True, value=d, status="noop", reason="already in this segment"))
                continue
            why, note = overlap(t, tid, d)
            items.append(_unit(k, gkey, "domain", ref, "domain_names", False, True, value=d, status="excluded" if why else "change",
                               reason=why or ("added once the segment that holds it is deleted" if d in leaving_by_delete else ""),
                               depends_on=[leaving_by_delete[d]] if d in leaving_by_delete else []))
            if note:
                warnings.append(note)
            # A domain that leaves one segment for another: when the two
            # segments share ports it leaves first (else ZPA would see it
            # twice on the same ports); otherwise it arrives first, so it is
            # never in neither segment. The second step waits for the first.
            src = next((s2 for (s2, d2) in remove_keys if d2 == d and s2 != tid), None)
            if src is not None:
                rm = next(x for x in items if x["key"] == remove_keys[(src, d)])
                add = items[-1]
                if ports_overlap(by_id[src], t):
                    add["depends_on"].append(rm["key"])
                    add["reason"] = add["reason"] or f"added once it has left '{pc._field(by_id[src], 'name')}' (the two share ports)"
                else:
                    rm["depends_on"].append(add["key"])
                    rm["reason"] = rm["reason"] or f"removed once it is in '{pc._field(t, 'name')}'"
    # A removal whose addition was excluded does not happen either (the domain is never lost).
    if action != "revert":
        for (sid, d), k in remove_keys.items():
            u = next(x for x in items if x["key"] == k)
            partner = next((x for x in items if x["kind"] == "domain" and x["value"] == d and x["after"] is True and x["key"] != k), None)
            if u["status"] == "change" and partner is not None and partner["status"] == "excluded":
                u.update(status="excluded", reason=f"not moved: {partner['reason']}")
            # ...and an addition whose removal cannot happen is not made
            # either: a move never quietly becomes a copy.
            if u["status"] == "excluded" and u["reason"] == LAST_DOMAIN:
                for x in items:
                    if x["kind"] == "domain" and x["value"] == d and x["after"] is True and x["status"] == "change":
                        x.update(status="excluded", reason=f"not moved: {LAST_DOMAIN}")
    # A step that waits for an excluded step is excluded too, so nothing
    # is planned that would only be skipped (or half done) while writing.
    changed = True
    while changed:
        changed = False
        state = {x["key"]: x["status"] for x in items}
        for x in items:
            if x["status"] == "change" and any(state.get(dk) == "excluded" for dk in x["depends_on"]):
                x.update(status="excluded", reason="not done: a step it waits for is excluded")
                changed = True
    # The writes: one per segment (its additions and removals together), the
    # clone, the deletions; ordered so every step comes after the steps it
    # waits for.
    seg_groups: Dict[str, Dict[str, Any]] = {}
    for u in items:
        if u["kind"] == "domain" and u["status"] == "change" and u["group"].startswith("seg:") and not u["group"].startswith("seg:new:"):
            seg_groups.setdefault(u["group"], {"key": u["group"], "handler": "zpa_update", "target": {"id": u["object"]["id"], "name": u["object"]["name"],
                                                                                                     "add": [], "remove": []}})
            seg_groups[u["group"]]["target"]["add" if u["after"] else "remove"].append(u["value"])
    pending = list(seg_groups.values())
    if clone is not None and not blockers:
        doms = [u["value"] for u in items if u["group"].startswith("seg:new:") and u["kind"] == "domain" and u["status"] == "change"]
        if doms:
            pending.append({"key": "seg:new:" + clone["name"].lower(), "handler": "zpa_create",
                            "target": {"name": clone["name"], "source": clone["source"], "domains": doms}})
        else:
            for u in items:
                if u["group"].startswith("seg:new:") and u["status"] == "change":
                    u.update(status="excluded", reason="every domain of the new segment was excluded, so it is not created")
    for u in items:
        if u["kind"] == "delete_segment" and u["status"] == "change":
            pending.append({"key": u["group"], "handler": "zpa_delete", "target": {"id": u["object"]["id"], "name": u["object"]["name"],
                                                                                  "domains": sorted(_domains(by_id[_rid(u['object']['id'])]))}})
    group_of = {u["key"]: u["group"] for u in items}
    needs = {g["key"]: {group_of.get(d) for u in items if u["group"] == g["key"] for d in u["depends_on"]} - {g["key"], None} for g in pending}
    while pending:
        waiting = {p["key"] for p in pending}
        nxt = next((g for g in pending if not (needs[g["key"]] & (waiting - {g["key"]}))), pending[0])
        pending.remove(nxt)
        groups.append(nxt)
    n = sum(1 for u in items if u["kind"] == "domain" and u["status"] == "change" and u["after"] is True)
    sname = pc._field(by_id.get(nspec.get("source", ""), {}), "name") if nspec.get("source") else ""
    tname = pc._field(by_id.get(nspec.get("target", ""), {}), "name") if nspec.get("target") else ""
    title = {"move": f"Move {n} domain{'s' if n != 1 else ''} from {sname} to {tname}", "copy": f"Copy {n} domain{'s' if n != 1 else ''} from {sname} to {tname}",
             "clone": f"Clone {sname} as {(clone or {}).get('name')}", "revert": "Undo a ZPA segment change"}[action]
    notes = ["The overlap check assumes ZPA refuses the same domain in two segments on overlapping ports; a wildcard and a more "
             "specific domain may share ports (the most specific match wins)."]
    return {"type": "zpa_domains", "spec": nspec, "product": "zpa", "items": items, "groups": groups, "warnings": list(dict.fromkeys(warnings)),
            "blockers": blockers, "title": title, "notes": notes}


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

_RATE_READ_WORDS = ("429", "too many requests", "rate limit", "ratelimit", "resource access blocked", "retry wait time")


def _read_halt(err: Optional[str]) -> Optional[str]:
    """A read error no later step can get past: refused credentials, the
    edit lock, or ZIA's rate limit. None for an error about one object."""
    if not err:
        return None
    reason = ops.fatal_reason(err)
    if reason:
        return reason
    low = str(err).lower()
    if any(w in low for w in _RATE_READ_WORDS):
        return READ_RATE_STOP
    return None


class _Run:
    def __init__(self, client, prepared: Dict[str, Any], log: Callable[[str], None], assessor: str):
        self.client = client
        self.zia = getattr(client, "zia", None)
        self.zpa = getattr(client, "zpa", None)
        self.p = prepared
        self.log = log
        self.assessor = assessor
        self.halt: Optional[str] = None
        self.units = {u["key"]: u for u in prepared["items"]}
        self.counts = {"created": 0, "modified": 0, "deleted": 0, "failed": 0, "skipped": 0}
        self.created: List[Dict[str, Any]] = []
        self.order_broken: Dict[str, str] = {}
        self.wrote_zia = False

    def group_units(self, g: Dict[str, Any]) -> List[Dict[str, Any]]:
        return [u for u in self.p["items"] if u["group"] == g["key"] and u["status"] == "change"]

    def mark(self, units: Sequence[Dict[str, Any]], status: str, reason: str = "", **extra: Any) -> None:
        for u in units:
            u["status"] = status
            if reason:
                u["reason"] = reason
            u.update(extra)
        if status in ("skipped",):
            self.counts["skipped"] += len(units)

    def outcome(self, units: Sequence[Dict[str, Any]], out: ops.Outcome, verb: str) -> bool:
        if out.ok:
            self.mark(units, "applied", "")
            self.counts[{"create": "created", "update": "modified", "delete": "deleted"}[verb]] += 1
            return True
        if out.code == ops.STOPPED:
            self.mark(units, "skipped", out.error or "not attempted")
            return False
        label = ops.http_label(out.http_status, out.error, out.code)
        why = ". ".join(x for x in (label, ops.explain(out.error)) if x)
        self.mark(units, "failed", "", error=str(out.error or "Unknown error")[:300], explanation=why or None, http_status=out.http_status)
        self.counts["failed"] += 1
        return False


def _deps_ok(run: _Run, u: Dict[str, Any]) -> Optional[str]:
    for d in u["depends_on"]:
        dep = run.units.get(d)
        if dep is None or dep["group"] == u["group"]:
            continue   # the same write carries both (a new category with its URLs)
        if dep["status"] not in ("applied", "noop"):
            return f"not attempted: it depends on '{dep['object'].get('name')}' {dep.get('value') or dep['field']}, which was {dep['status']}"
    return None


def _h_rule_state(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_rule(run.zia, t["policy"], t["id"], t["rule_type"])
    if fresh is None:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the rule again before the change: {err}")
            run.counts["failed"] += 1
        return
    u = units[0]
    now = _state(fresh)
    if now != u["before"]:
        run.mark(units, "conflict", f"changed in the tenant since the preview: state is {now}, the preview read {u['before']}; left as it is")
        run.log(f"[{_label(t['policy'])}] {t['name']}: conflict — state is {now} now, not {u['before']}; skipped")
        return
    body = _body(fresh)
    body["state"] = u["after"]
    body.pop("enabled", None)
    if t["policy"] == "cloud_app_control":
        body["type"] = t["rule_type"] or fresh.get("rule_type")
    out = ops.update(run.zia, "policy", t["id"], body, channel=POLICIES[t["policy"]]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[{_label(t['policy'])}] {t['name']}: state {u['before']} → {u['after']}")


def _sequence(rows: List[Dict[str, Any]]) -> List[str]:
    return [_rid(pc._field(r, "id")) for r in sorted(rows, key=_sort_key)]


def _h_rule_order(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    pkey = f"{t['policy']}:{t['rule_type']}"
    if pkey in run.order_broken:
        run.mark(units, "skipped", f"not attempted: {run.order_broken[pkey]}")
        return
    rows, err = read_rules(run.zia, t["policy"], rule_type=t["rule_type"])
    if err:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.order_broken[pkey] = f"the rules could not be read again before the move ({err})"
            run.mark(units, "failed", "", error=f"could not read the rules again before the move: {err}")
            run.counts["failed"] += 1
        return
    seq = _sequence(rows)
    if seq != [str(x) for x in t["expect_before"]]:
        run.order_broken[pkey] = REORDER_BROKEN
        run.mark(units, "conflict", "the policy's order is not what the preview expected at this step (someone changed it); this and the remaining moves were skipped")
        run.log(f"[{_label(t['policy'])}] order changed in the tenant during the run; the remaining moves are not sent")
        return
    fresh = next(r for r in rows if _rid(pc._field(r, "id")) == _rid(t["id"]))
    body = _body(fresh)
    body["order"] = t["send_order"]
    if t["policy"] == "cloud_app_control":
        body["type"] = t["rule_type"]
    out = ops.update(run.zia, "policy", t["id"], body, channel=POLICIES[t["policy"]]["channel"], name=t["name"], log=run.log)
    if run.outcome(units, out, "update"):
        run.wrote_zia = True
        run.log(f"[{_label(t['policy'])}] {t['name']}: order {units[0]['before']} → {t['send_order']}")
    else:
        run.order_broken[pkey] = f"the move of '{t['name']}' was not applied"


def _h_url(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]], add: bool) -> None:
    t = g["target"]
    fresh, err = get_category(run.zia, t["id"])
    if fresh is None:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the category again before the change: {err}")
            run.counts["failed"] += 1
        return
    have = _url_set(fresh)
    ok = []
    for u in units:
        now = u["value"].lower() in have
        if now != u["before"]:
            run.mark([u], "conflict", f"changed in the tenant since the preview: {u['value']} is {'now' if now else 'no longer'} in this category; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    name = str(_cat_ref(fresh)["name"])
    out = ops.update(run.zia, "url_category", t["id"], {"configured_name": name, "urls": [u["value"] for u in ok]},
                     action="ADD_TO_LIST" if add else "REMOVE_FROM_LIST", name=name, log=run.log)
    if run.outcome(ok, out, "update"):
        run.wrote_zia = True
        run.log(f"[URL category] {name}: {'added' if add else 'removed'} {len(ok)} URL(s)")


def _h_url_create(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    cats, err = read_categories(run.zia)
    if err:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the categories again before creating one: {err}")
            run.counts["failed"] += 1
        return
    if any(_cat_ref(c)["name"].strip().lower() == t["name"].lower() for c in cats):
        run.mark(units, "conflict", f"a category named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    urls = [u["value"] for u in units if u["kind"] == "url"]
    payload = {"super_category": t["super_category"], "configured_name": t["name"], "urls": urls, "custom_category": True,
               "description": f"Created by {run.assessor or 'the assessor'} with Bulk changes"[:255]}
    out = ops.create(run.zia, "url_category", payload, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.wrote_zia = True
        run.created.append({"type": "url_category", "id": out.id, "name": t["name"], "urls": urls})
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.log(f"[URL category] {t['name']}: created with {len(urls)} URL(s)")


def _h_url_delete(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_category(run.zia, t["id"])
    if fresh is None:
        halt = _read_halt(err)
        if halt:
            run.halt = halt
            run.mark(units, "skipped", f"not attempted: {halt}")
        else:
            run.mark(units, "noop", "already gone")
        return
    if _url_set(fresh) != {u.lower() for u in t["urls"]}:
        run.mark(units, "conflict", "its URLs changed since the preview, so it is kept")
        return
    out = ops.delete(run.zia, {"kind": "url_category", "id": t["id"], "name": t["name"]}, log=run.log)
    if run.outcome(units, out, "delete"):
        run.wrote_zia = True


def _h_zpa_update(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_segment(run.zpa, t["id"])
    if fresh is None:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the segment again before the change: {err}")
            run.counts["failed"] += 1
        return
    have = _domains(fresh)
    ok = []
    for u in units:
        now = u["value"] in have
        if now != u["before"]:
            run.mark([u], "conflict", f"changed in ZPA since the preview: {u['value']} is {'now' if now else 'no longer'} in this segment; left as it is")
        else:
            ok.append(u)
    if not ok:
        return
    rm = {u["value"] for u in ok if not u["after"]}
    add = [u["value"] for u in ok if u["after"]]
    body = segment_body(fresh)
    body["domain_names"] = [d for d in have if d not in rm] + [d for d in add if d not in have]
    if not body["domain_names"]:
        run.mark(ok, "excluded", LAST_DOMAIN)
        return
    out = ops.update(run.zpa, "zpa_segment", t["id"], body, name=str(fresh.get("name") or t["name"]), log=run.log)
    if run.outcome(ok, out, "update"):
        run.log(f"[ZPA segment] {t['name']}: +{len(add)} / -{len(rm)} domain(s)")


def _h_zpa_create(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    segs, err = read_segments(run.zpa)
    if err:
        run.halt = _read_halt(err)
        if run.halt:
            run.mark(units, "skipped", f"not attempted: {run.halt}")
        else:
            run.mark(units, "failed", "", error=f"could not read the segments again before the clone: {err}")
            run.counts["failed"] += 1
        return
    if any(str(pc._field(s, "name", default="")).strip().lower() == t["name"].lower() for s in segs):
        run.mark(units, "conflict", f"a segment named '{t['name']}' now exists (made since the preview); nothing was created")
        return
    src = next((s for s in segs if _rid(pc._field(s, "id")) == _rid(t["source"])), None)
    if src is None:
        run.mark(units, "conflict", "the segment to clone is gone since the preview; nothing was created")
        return
    doms = [u["value"] for u in units if u["kind"] == "domain"]
    if not doms:
        # ZPA keeps at least one domain in a segment: no empty clone is made.
        run.mark(units, "skipped", "not created: none of its domains could be put in it")
        return
    body = segment_body(src)
    body.update(name=t["name"], domain_names=doms,
                description=f"Clone of {pc._field(src, 'name')} by {run.assessor or 'the assessor'} with Bulk changes"[:255])
    body.pop("microtenant_id", None) if not body.get("microtenant_id") else None
    out = ops.create(run.zpa, "zpa_segment", body, name=t["name"], log=run.log)
    if run.outcome(units, out, "create"):
        run.created.append({"type": "zpa_segment", "id": out.id, "name": t["name"], "domains": doms})
        for u in units:
            u["object"] = dict(u["object"], id=out.id)
        run.log(f"[ZPA segment] {t['name']}: created with {len(doms)} domain(s)")


def _h_zpa_delete(run: _Run, g: Dict[str, Any], units: List[Dict[str, Any]]) -> None:
    t = g["target"]
    fresh, err = get_segment(run.zpa, t["id"])
    if fresh is None:
        halt = _read_halt(err)
        if halt:
            run.halt = halt
            run.mark(units, "skipped", f"not attempted: {halt}")
        else:
            run.mark(units, "noop", "already gone")
        return
    if set(_domains(fresh)) != set(t["domains"]):
        run.mark(units, "conflict", "its domains changed since the preview, so it is kept")
        return
    out = ops.delete(run.zpa, {"kind": "zpa_segment", "id": t["id"], "name": t["name"]}, log=run.log)
    run.outcome(units, out, "delete")


HANDLERS = {"rule_state": _h_rule_state, "rule_order": _h_rule_order, "url_add": lambda r, g, u: _h_url(r, g, u, True),
            "url_remove": lambda r, g, u: _h_url(r, g, u, False), "url_create": _h_url_create, "url_delete": _h_url_delete,
            "zpa_update": _h_zpa_update, "zpa_create": _h_zpa_create, "zpa_delete": _h_zpa_delete}


def _verify(run: _Run) -> Dict[str, Any]:
    """Read back every applied item; {checked, confirmed, mismatched, unread}."""
    out = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    applied = [u for u in run.p["items"] if u["status"] == "applied"]
    if not applied:
        return out
    t = run.p["type"]
    if t in PLUGINS and PLUGINS[t].get("verify"):
        return PLUGINS[t]["verify"](run)
    if t == "reorder":
        spec = run.p["spec"]
        rows, err = read_rules(run.zia, spec["policy"], rule_type=spec["rule_type"])
        out["checked"] = len(applied)
        if err:
            out["unread"].append(f"{_label(spec['policy'])} rules: {err}")
            return out
        want = [str(x["id"]) for x in run.p["order_after"]]
        seq = _sequence(rows)
        if seq == want:
            out["confirmed"] = len(applied)
            for u in applied:
                u["verified"] = True
        else:
            out["mismatched"].append("the rule order read back differs from the desired order")
            for u in applied:
                u["verified"] = False
        return out
    cache: Dict[str, Tuple[Optional[Dict[str, Any]], Optional[str]]] = {}
    for u in applied:
        o = u["object"]
        out["checked"] += 1
        if u["kind"] == "rule_state":
            k = f"r:{o['policy']}:{o['id']}"
            if k not in cache:
                cache[k] = get_rule(run.zia, o["policy"], o["id"], o.get("rule_type", ""))
            row, err = cache[k]
            got = _state(row) if row else None
            ok = got == u["after"]
        elif u["kind"] in ("url", "create_category", "delete_category"):
            k = f"c:{o.get('id')}"
            if k not in cache:
                cache[k] = get_category(run.zia, o.get("id")) if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            if u["kind"] == "delete_category":
                ok, err = row is None, None if row is None else err
            elif u["kind"] == "create_category":
                ok = row is not None
            else:
                ok = row is not None and ((u["value"].lower() in _url_set(row)) == u["after"])
        elif u["kind"] in ("domain", "create_segment", "delete_segment"):
            k = f"s:{o.get('id')}"
            if k not in cache:
                cache[k] = get_segment(run.zpa, o.get("id")) if o.get("id") is not None else (None, "no id")
            row, err = cache[k]
            if u["kind"] == "delete_segment":
                ok, err = row is None, None if row is None else err
            elif u["kind"] == "create_segment":
                ok = row is not None
            else:
                ok = row is not None and ((u["value"] in _domains(row)) == u["after"])
        else:
            continue
        if not ok and err and u["kind"] not in ("delete_category", "delete_segment"):
            out["unread"].append(f"{o.get('name')}: {err}")
            u["verified"] = None
            continue
        u["verified"] = bool(ok)
        if ok:
            out["confirmed"] += 1
        else:
            out["mismatched"].append(f"{o.get('name')}: {u.get('value') or u['field']} is not {u['after']} when read back")
    return out


def inverse(result: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """The operation that reverses exactly what `result` applied (its
    items with status `applied`), or None when nothing was applied. A
    new operation: it is previewed, confirmed and guarded like any other."""
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    t = result.get("type")
    if t in PLUGINS:
        inv = PLUGINS[t].get("inverse")
        return inv(result) if inv else None
    if t == "rule_state":
        return {"type": "rule_state", "targets": [{"policy": u["object"]["policy"], "id": u["object"]["id"],
                                                   "rule_type": u["object"].get("rule_type") or "", "to": u["before"]} for u in applied]}
    if t == "reorder":
        spec = result["spec"]
        return {"type": "reorder", "policy": spec["policy"], "rule_type": spec.get("rule_type") or "",
                "order": [str(x) for x in result.get("before_order") or []]}
    if t == "url_categories":
        created_ids = {str(c["id"]) for c in result.get("created") or [] if c.get("type") == "url_category"}
        deltas: Dict[str, Dict[str, List[str]]] = {}
        for u in applied:
            if u["kind"] != "url" or u["object"].get("id") is None or str(u["object"]["id"]) in created_ids:
                continue
            d = deltas.setdefault(str(u["object"]["id"]), {"add": [], "remove": []})
            (d["remove"] if u["after"] else d["add"]).append(u["value"])
        return {"type": "url_categories", "action": "revert",
                "deltas": [{"category": k, "add": v["add"], "remove": v["remove"]} for k, v in sorted(deltas.items())],
                "delete_categories": [{"id": c["id"], "name": c["name"], "urls": c["urls"]} for c in result.get("created") or []
                                      if c.get("type") == "url_category"]}
    if t == "zpa_domains":
        created_ids = {str(c["id"]) for c in result.get("created") or [] if c.get("type") == "zpa_segment"}
        deltas = {}
        for u in applied:
            if u["kind"] != "domain" or u["object"].get("id") is None or str(u["object"]["id"]) in created_ids:
                continue
            d = deltas.setdefault(str(u["object"]["id"]), {"add": [], "remove": []})
            (d["remove"] if u["after"] else d["add"]).append(u["value"])
        return {"type": "zpa_domains", "action": "revert",
                "deltas": [{"segment": k, "add": v["add"], "remove": v["remove"]} for k, v in sorted(deltas.items())],
                "delete_segments": [{"id": c["id"], "name": c["name"], "domains": c["domains"]} for c in result.get("created") or []
                                    if c.get("type") == "zpa_segment"]}
    return None


def is_undo_only(spec: Any) -> bool:
    """Is `spec` the form only an Undo uses (inverse()): a revert or undo
    action, which deletes and restores objects by the ids a recorded run
    gave? Such a spec is applied only as the Undo of that recorded
    operation (undo_of, its inverse exactly), never as an ordinary
    operation that could name objects this app never created."""
    if not isinstance(spec, dict):
        return False
    return str(spec.get("action") or "").strip().lower() in ("revert", "undo") or spec.get("undo") is True


def check_confirmation(prepared: Dict[str, Any], confirm_text: str) -> Optional[str]:
    """Why the typed confirmation does not match, or None."""
    import security   # one rule for every typed phrase: case-insensitive, no look-alikes (no NFKC)
    phrase = prepared.get("confirm_phrase") or ""
    if phrase and not security.typed_phrase_matches(confirm_text, phrase):
        return f"This operation changes {prepared['counts']['change']} items: type {phrase} to confirm it."
    return None


def execute(client, spec: Dict[str, Any], *, plan_hash: str, scope: Dict[str, Any], writes_enabled: Optional[bool],
            confirm_text: str = "", assessor: str = "", tenant_label: str = "", log: LogFn = None,
            cancel: Optional[threading.Event] = None, settle_seconds: float = 45.0) -> Dict[str, Any]:
    """Apply a previewed operation (see the module docstring). Returns
    {status, items (each with its run status), counts, activation,
    verification, stopped, created, inverse, plan_hash, ...}. While another
    write run holds the tenant (pack_ops.tenant_run) nothing is read or
    written: status blocked, busy true."""
    if writes_enabled is not True:
        raise PermissionError("write mode is off: nothing was written")
    if not str(assessor or "").strip():
        # The route requires the named assessor too; the engine refuses on
        # its own as well (defence in depth for every caller), before any read.
        raise OperationError("A named assessor is required to apply a change: nothing was read or written.")
    with ops.tenant_run(client) as mine:
        if not mine:
            ops.audit_refusal("operation", client, plan_hash=plan_hash, reason=ops.BUSY_REASON)
            return ops.busy_result(type=(spec or {}).get("type") if isinstance(spec, dict) else None, plan_hash=plan_hash)
        return _execute_audited(client, spec, plan_hash=plan_hash, scope=scope, confirm_text=confirm_text, assessor=assessor,
                                tenant_label=tenant_label, log=log, cancel=cancel, settle_seconds=settle_seconds)


def _execute_audited(client, spec, *, plan_hash, scope, confirm_text, assessor, tenant_label, log, cancel, settle_seconds) -> Dict[str, Any]:
    import zia_rate
    with zia_rate.using_client(client), ops.run_scope(cancel), ops.audited_run("operation", client, plan_hash=plan_hash, cancel=cancel) as box:
        box["result"] = _execute(client, spec, plan_hash=plan_hash, scope=scope, confirm_text=confirm_text, assessor=assessor,
                                 tenant_label=tenant_label, log=log, cancel=cancel, settle_seconds=settle_seconds)
        return box["result"]


def _execute(client, spec, *, plan_hash, scope, confirm_text, assessor, tenant_label, log, cancel, settle_seconds) -> Dict[str, Any]:
    logs: List[str] = []

    def say(line: str) -> None:
        logs.append(line)
        if log:
            log(line)

    started = time.time()
    say("Checking the previewed plan against the tenant as it is now…")
    try:
        prepared = plan(client, spec, scope=scope, tenant_label=tenant_label, log=say, cancel=cancel)
    except Stopped as e:
        return {"status": "stopped", "stopped": str(e), "items": [], "logs": logs, "summary": {}}
    if not plan_hash or prepared["plan_hash"] != plan_hash:
        say("The tenant changed since the preview: nothing was written. Review the new preview and confirm again.")
        return {"status": "plan_changed", "message": "The tenant changed since this preview (or it is a different operation). Nothing was "
                                                     "written: review the new preview and confirm again.",
                "expected_hash": plan_hash, "current_hash": prepared["plan_hash"], "preview": prepared, "items": [], "logs": logs, "summary": {}}
    if prepared["status"] == "blocked":
        return {"status": "blocked", "blockers": prepared["blockers"], "preview": prepared, "items": [], "logs": logs, "summary": {}}
    why = check_confirmation(prepared, confirm_text)
    if why:
        return {"status": "refused", "message": why, "preview": prepared, "items": [], "logs": logs, "summary": {}}
    run = _Run(client, prepared, say, assessor)
    if prepared["status"] == "nothing_to_do":
        say("Nothing to change: every item is already as asked or excluded.")
    for g in prepared["groups"]:
        units = run.group_units(g)
        if not units:
            continue
        halted = run.halt or ops.stop_reason() or (ops.CANCELLED_REASON if cancel is not None and cancel.is_set() else None)
        if halted:
            run.halt = halted
            run.mark(units, "skipped", f"not attempted: {halted}")
            continue
        ready = []
        for u in units:
            blocked = _deps_ok(run, u)
            if blocked:
                run.mark([u], "skipped", blocked)
            else:
                ready.append(u)
        if not ready:
            continue
        (HANDLERS.get(g["handler"]) or PLUGIN_HANDLERS[g["handler"]])(run, g, ready)
        if ops.stop_reason():
            run.halt = ops.stop_reason()
        if run.halt and not getattr(run, "_told", False):
            run._told = True
            say(f"STOPPED — nothing more is written. {run.halt}")
    activation = None
    settled = None
    if run.wrote_zia:
        say("Activating pending ZIA changes…")
        activation = ops.activate_once(run.zia, say)
        say("Activation " + ("done." if activation.get("activated") else f"could not run: {activation.get('error')}"))
        if activation.get("activated") and not ops.stop_reason():
            settled = pc.wait_active(run.zia, settle_seconds, say)
    verification = {"checked": 0, "confirmed": 0, "mismatched": [], "unread": []}
    if any(u["status"] == "applied" for u in prepared["items"]) and not (cancel is not None and cancel.is_set()):
        say("Reading the changed objects back…")
        verification = _verify(run)
        say(f"Read back: {verification['confirmed']} of {verification['checked']} confirmed"
            + (f"; {len(verification['mismatched'])} differ" if verification["mismatched"] else "")
            + (f"; {len(verification['unread'])} could not be read" if verification["unread"] else "") + ".")
    items = prepared["items"]
    n = lambda s: sum(1 for u in items if u["status"] == s)  # noqa: E731
    counts = {k: n(k) for k in ("applied", "noop", "excluded", "conflict", "failed", "skipped")}
    counts["total"] = len(items)
    planned = prepared["counts"]["change"]
    if counts["applied"] and counts["applied"] == planned and not verification["mismatched"]:
        status = "applied"
    elif counts["applied"]:
        status = "partial"
    elif run.halt and planned:
        status = "stopped" if (cancel is not None and cancel.is_set()) else "failed"
    elif planned:
        status = "failed" if counts["failed"] else "nothing_applied"
    else:
        status = "nothing_to_do"
    result = dict(prepared)
    result.update(status=status, items=items, counts_run=counts, activation=activation, activation_status=settled,
                  verification=verification, stopped=run.halt, created=run.created, logs=logs,
                  elapsed_seconds=round(time.time() - started, 1),
                  summary={"modified": run.counts["modified"], "created": run.counts["created"], "deleted": run.counts["deleted"],
                           "failed": counts["failed"], "skipped": counts["skipped"] + counts["conflict"]})
    if prepared["product"] == "zia" and activation is None and counts["applied"] == 0:
        result["activation_note"] = "Nothing was written, so nothing was activated."
    result["inverse"] = inverse(result)
    return result


# ---------------------------------------------------------------------------
# Records, audit and the approval-queue request
# ---------------------------------------------------------------------------

def record(result: Dict[str, Any], *, by: str = "", actor: Optional[str] = None, undo_of: str = "",
           tenant_ids: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
    """Store an applied operation beside the deployments (deployments.json,
    `operations`) and write its `admin_operation` audit entry. None when
    nothing was applied (nothing to record or undo)."""
    import deployments
    import pack_jobs
    applied = [u for u in result.get("items") or [] if u.get("status") == "applied"]
    if not applied:
        return None
    rec = {"id": deployments.new_operation_id(), "at": deployments._now(), "tenant_label": result.get("tenant_label") or "",
           "by": by or "", "actor": actor or None, "type": result["type"], "title": result.get("title"), "product": result.get("product"),
           "spec": result.get("spec"), "plan_hash": result.get("plan_hash"), "status": result.get("status"),
           "counts": result.get("counts_run"), "created": result.get("created") or [],
           "items": [{k: u.get(k) for k in ("key", "kind", "object", "field", "value", "before", "after", "status", "reason", "error", "verified")}
                     for u in result.get("items") or []],
           "inverse": result.get("inverse"), "undo_of": undo_of or None, "undone_by": None, "undone_at": None}
    for k, v in (tenant_ids or {}).items():
        if v:
            rec[k] = v
    deployments.add_operation(rec)
    if undo_of:
        deployments.mark_operation_undone(undo_of, rec["id"], complete=result.get("status") == "applied")
    pack_jobs.write_audit("admin_operation", actor=actor, operation=rec["id"], type=rec["type"], title=rec["title"],
                          tenant=rec["tenant_label"], by=by or None, plan_hash=rec["plan_hash"], status=rec["status"],
                          counts=rec["counts"], undo_of=undo_of or None)
    return rec


def to_request(prepared: Dict[str, Any]) -> Dict[str, Any]:
    """A prepared operation as a request object a shared approval queue can
    file and, once approved, hand back to execute() (the spec and the
    plan_hash travel with it; the hash still has to match the tenant)."""
    return {"kind": KIND, "op_type": prepared.get("type"), "title": prepared.get("title"), "product": prepared.get("product"),
            "tenant_label": prepared.get("tenant_label"), "created_at": prepared.get("generated_at"),
            "plan_hash": prepared.get("plan_hash"), "spec": prepared.get("spec"), "counts": prepared.get("counts"),
            "confirm_phrase": prepared.get("confirm_phrase") or "", "warnings": list(prepared.get("warnings") or []),
            "impact": list(prepared.get("impact") or []),
            "items": [{"key": u["key"], "object": u["object"], "field": u["field"], "value": u.get("value"), "before": u["before"],
                       "after": u["after"], "status": u["status"], "reason": u.get("reason") or ""} for u in prepared.get("items") or []]}


# ---------------------------------------------------------------------------
# The object picker
# ---------------------------------------------------------------------------

def read_objects(client, family: str, scope: Dict[str, Any], *, log: LogFn = None, cancel: Optional[threading.Event] = None) -> Dict[str, Any]:
    """The objects an operation can pick from, read-only: rules per policy
    in scope, custom URL categories with their URLs, or ZPA segments with
    their domains and ports."""
    require_scope(family, scope)
    say = log or (lambda m: None)
    out: Dict[str, Any] = {"family": family, "not_in_scope": dict(scope.get("not_in_scope") or {}), "errors": {},
                           "sanction": SANCTION_NOTE}
    if family == "rules":
        out["policies"] = []
        for pol in scope["policies"]:
            _check_stop(cancel)
            say(f"Reading the {_label(pol)} rules…")
            rows, err = read_rules(client.zia, pol, cancel=cancel)
            if err:
                out["errors"][pol] = err
                say(f"{_label(pol)} rules could not be read: {err}")
            rows = sorted(rows, key=lambda r: (str(r.get("rule_type") or ""),) + _sort_key(r))
            out["policies"].append({"policy": pol, "label": _label(pol), "ordered": POLICIES[pol]["ordered"],
                                    "rules": [rule_summary(pol, r) for r in rows]})
            say(f"{_label(pol)}: {len(rows)} rules.")
    elif family == "url_categories":
        say("Reading the custom URL categories…")
        _check_stop(cancel)
        cats, err = read_categories(client.zia)
        if err:
            out["errors"]["url_categories"] = err
        out["categories"] = [dict(_cat_ref(c), urls=_urls_of(c), url_count=len(_urls_of(c)),
                                  super_category=pc._field(c, "super_category", "superCategory"), description=pc._field(c, "description"))
                             for c in sorted(cats, key=lambda c: str(_cat_ref(c)["name"]).lower())]
        say(f"{len(out['categories'])} custom URL categories.")
    elif family == "zpa_segments":
        say("Reading the ZPA application segments…")
        segs, err = read_segments(getattr(client, "zpa", None), cancel)
        if err:
            out["errors"]["zpa_segments"] = err
        out["segments"] = [segment_summary(s) for s in sorted(segs, key=lambda s: str(pc._field(s, "name", default="")).lower())]
        say(f"{len(out['segments'])} application segments.")
    elif family in PLUGIN_FAMILIES:
        out.update(PLUGIN_FAMILIES[family]["read_objects"](client, scope, say, cancel) or {})
    _check_stop(cancel)
    return out
