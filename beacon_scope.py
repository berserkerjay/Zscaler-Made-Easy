"""Which tenant endpoints Beacon's tenant API watch may read: only the ones
that belong to what is in scope on the Scope page.

Every GET the watch sends counts against the tenant's ZIA API rate limit,
so the watch reads an endpoint only when a check in a ticked scope reads
it. The map is derived from the code, the same way beacon.tenant_endpoints
derives the endpoint list:

  - A Scope page checkbox (`.scope-cb`: dlp, zia_extras, zpa, zcc, genai,
    automation, zdx, zidentity, rbac) selects check registries exactly as
    dlp_api_server._get_checks does (SCOPE_REGISTRIES below).
  - Each registered check's function is read (and every helper it calls,
    in its own module or another) for the literal endpoints it GETs.
  - A DLP-scope check that belongs to a data-security channel
    (channel_scope.CHANNEL_CHECKS: Ch.A Inline Web, Ch.B Endpoint, 4 — SSL
    Policy, ...) counts only when that channel is marked **Zscaler** on
    the Scope page. Alternative, gap (unticked) and undeclared channels are
    out of scope for the watch. The Endpoint DLP, SaaS (CASB) and Email DLP
    rule endpoints are read only with their channel on Zscaler, whichever
    check reads them (CHANNEL_ONLY_ENDPOINTS).
  - A check of any other ticked scope (GenAI & prompts, ZIA platform's
    Cloud Apps, ...) is in scope because its scope is ticked; a channel
    takes it out only when that channel is declared **alternative**, as
    the assessment itself skips it then (channel_scope.partition).

The endpoints the watch knows (watch_endpoints) are the literal GET calls
in beacon.TENANT_WATCH_MODULES plus every endpoint a check reads through a
helper (_items, _rules, ...), so an in-scope check's endpoint is always
either read or listed as not in scope. An endpoint is read when any
in-scope check reads it. An endpoint that no check reads (only a feature
module does) is "unmapped" and never read by the watch: nothing defaults
to everything.
"""
from __future__ import annotations

import ast
import functools
import importlib
import inspect
import os
import re
import sys
import textwrap
import threading
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Set, Tuple

import channel_scope

ROOT = os.path.dirname(os.path.abspath(__file__))

# Scope key -> (module, registry, section prefix or None), as
# dlp_api_server._get_checks selects checks for the same keys.
SCOPE_REGISTRIES: Dict[str, Tuple[Tuple[str, str, Optional[str]], ...]] = {
    "dlp": (("dlp_assessment_full_auto", "REG", None),),
    "zia_extras": (("zscaler_full_checks", "PLATFORM_REG", "ZIA"),),
    "zpa": (("zscaler_full_checks", "PLATFORM_REG", "ZPA"),),
    "zcc": (("zscaler_full_checks", "PLATFORM_REG", "ZCC"),),
    "genai": (("zscaler_genai_checks", "GENAI_REG", None),),
    "automation": (("zscaler_automation_checks", "AUTOMATION_REG", None),),
    "zdx": (("zscaler_zdx_checks", "ZDX_REG", None),),
    "zidentity": (("zscaler_zidentity_checks", "ZID_REG", None),),
    "rbac": (("zscaler_rbac_checks", "RBAC_REG", None),),
}
SCOPE_LABELS: Dict[str, str] = {
    "dlp": "DLP", "zia_extras": "ZIA platform", "zpa": "ZPA", "zcc": "ZCC", "genai": "GenAI & prompts",
    "automation": "Automation readiness", "zdx": "ZDX", "zidentity": "ZIdentity", "rbac": "RBAC",
}
# Short channel names for the one-line summary ("DLP (Web, Email)").
CHANNEL_SHORT: Dict[str, str] = {
    "web_dlp": "Web", "endpoint_dlp": "Endpoint", "email_dlp": "Email", "saas_casb": "SaaS",
    "genai_security": "GenAI", "shadow_it": "Shadow IT", "endpoint_scan": "Endpoint scan",
    "ssl_inspection": "SSL", "cloud_app_control": "Cloud App Control", "device_control": "Device Control",
    "workflow_automation": "Workflow",
}
# Rule endpoints that are a channel's own: read only with that channel on
# Zscaler, even when a check outside the channel's sections reads them.
CHANNEL_ONLY_ENDPOINTS: Dict[str, str] = {
    "/zia/endPointDlpRules": "endpoint_dlp",
    "/zia/emailDlpRules": "email_dlp",
    "/zia/casbDlpRules/all": "saas_casb",
}
NOTHING_IN_SCOPE = "Nothing is in scope — choose what to assess on the Scope page."


def _get_call() -> "re.Pattern[str]":
    import beacon
    return beacon._GET_CALL


def _unwrap(fn: Any) -> Any:
    while isinstance(fn, functools.partial):
        fn = fn.func
    return inspect.unwrap(fn) if callable(fn) else fn


def _local_imports(tree: ast.AST) -> Dict[str, Any]:
    """Names a function imports in its own body (`from rule_migrator
    import assess_current_status`, `import ssl_flow`), resolved."""
    out: Dict[str, Any] = {}
    for n in ast.walk(tree):
        try:
            if isinstance(n, ast.ImportFrom) and n.module and not n.level:
                mod = importlib.import_module(n.module)
                for a in n.names:
                    if a.name != "*":
                        out[a.asname or a.name] = getattr(mod, a.name, None)
            elif isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        out[a.asname] = importlib.import_module(a.name)
                    else:
                        out[a.name.split(".")[0]] = importlib.import_module(a.name.split(".")[0])
        except Exception:  # noqa: BLE001 — a module that does not load reads nothing
            continue
    return out


def _parse(fn: Any) -> Optional[ast.AST]:
    try:
        return ast.parse(textwrap.dedent(inspect.getsource(fn)))
    except (OSError, TypeError, SyntaxError, IndentationError):
        return None


def _called(fn: Any, tree: Optional[ast.AST] = None) -> List[Any]:
    """The functions `fn` calls or names (its module's globals and what it
    imports in its own body): f(...), mod.f(...), and f handed on as a value."""
    tree = tree if tree is not None else _parse(fn)
    if tree is None:
        return []
    g = dict(getattr(fn, "__globals__", {}) or {})
    g.update(_local_imports(tree))
    out = []
    for n in ast.walk(tree):
        target = None
        if isinstance(n, ast.Name):
            target = g.get(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name):
            mod = g.get(n.value.id)
            if inspect.ismodule(mod):
                target = getattr(mod, n.attr, None)
        if target is not None and (inspect.isfunction(target) or isinstance(target, functools.partial)):
            out.append(_unwrap(target))
    return out


# An endpoint written out as a string of its own: "/zia/urlFilteringRules".
# Not a base or a prefix ("/zia/", "/zpa/mgmtconfig/"): those are joined
# to something else and are not an endpoint of their own.
_ENDPOINT_LITERAL = re.compile(r"/(?:zia|zcc|zpa|zdx|zid)/[A-Za-z0-9_/\-]*[A-Za-z0-9_\-]")

# function -> (the endpoints it names itself, the functions it calls).
# Parsed once per function, however many checks share it.
_DIRECT: Dict[Any, Tuple[FrozenSet[str], Tuple[Any, ...]]] = {}
_DIRECT_LOCK = threading.RLock()


def _direct(fn: Any) -> Tuple[FrozenSet[str], Tuple[Any, ...]]:
    with _DIRECT_LOCK:
        hit = _DIRECT.get(fn)
        if hit is not None:
            return hit
        try:
            src = inspect.getsource(fn)
        except (OSError, TypeError):
            res: Tuple[FrozenSet[str], Tuple[Any, ...]] = (frozenset(), ())
        else:
            eps = {m.group(1) for m in _get_call().finditer(src)}
            tree = _parse(fn)
            if tree is not None:
                for n in ast.walk(tree):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str) and _ENDPOINT_LITERAL.fullmatch(n.value):
                        eps.add(n.value)
            res = (frozenset(eps), tuple(_called(fn, tree)))
        _DIRECT[fn] = res
        return res


def function_endpoints(fn: Any, _seen: Optional[Set[Any]] = None) -> Set[str]:
    """The literal endpoints `fn` reads, itself or through any helper it
    calls (followed transitively, each function once). Every string that
    is an endpoint path counts, whichever helper it is handed to
    (cl.get, _g, _items, _rules, _fetch, ...) or when it is looped over
    from a tuple: a check that names an endpoint reads it. Each function
    is parsed once (_direct), so the whole map costs one pass over the code."""
    seen = _seen if _seen is not None else set()
    eps: Set[str] = set()
    stack = [_unwrap(fn)]
    while stack:
        f = stack.pop()
        if f in seen or not inspect.isfunction(f):
            continue
        seen.add(f)
        own, callees = _direct(f)
        eps |= own
        stack.extend(callees)
    return eps


def check_channels(check_id: str, section: str) -> List[str]:
    """Every channel whose checks include this one (channel_scope.CHANNEL_CHECKS)."""
    return [cid for cid, spec in channel_scope.CHANNEL_CHECKS.items() if channel_scope._matches(spec, str(check_id), str(section or ""))]


def _registry(module: str, attr: str) -> Sequence[tuple]:
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        return list(getattr(importlib.import_module(module), attr, []) or [])
    except Exception:  # noqa: BLE001 — a module that does not load reads nothing
        return []


_MAP: Optional[Tuple[Dict[str, Any], ...]] = None
_MAP_LOCK = threading.Lock()


def check_map() -> Tuple[Dict[str, Any], ...]:
    """One row per registered check per scope: {scope, id, section,
    channels, endpoints, module}. Built once (callers that arrive while it
    is being built wait for that one build): the code does not change
    while the server runs."""
    global _MAP
    if _MAP is None:
        with _MAP_LOCK:
            if _MAP is None:
                _MAP = _build_map()
    return _MAP


def _build_map() -> Tuple[Dict[str, Any], ...]:
    rows = []
    for scope, regs in SCOPE_REGISTRIES.items():
        seen_ids: Set[str] = set()
        for module, attr, prefix in regs:
            for chk in _registry(module, attr):
                cid, section, fn = str(chk[0]), str(chk[1]), chk[-1]
                if prefix and not section.startswith(prefix):
                    continue
                if cid in seen_ids:
                    continue
                seen_ids.add(cid)
                rows.append({"scope": scope, "id": cid, "section": section, "channels": check_channels(cid, section),
                             "endpoints": sorted(function_endpoints(fn)), "module": f"{module}.py"})
    return tuple(rows)


def watch_endpoints() -> Dict[str, List[str]]:
    """endpoint -> modules: everything the watch could read. The literal
    GET calls of beacon.tenant_endpoints, and every endpoint a check reads
    through a helper the GET-call pattern does not see (_items(cl,
    "/zia/firewallIpsRules"), ...), so no endpoint an in-scope check
    depends on is left out of the watch or of its "not read" lists."""
    import beacon
    out = {ep: list(mods) for ep, mods in beacon.tenant_endpoints().items()}
    for row in check_map():
        for ep in row["endpoints"]:
            mods = out.setdefault(ep, [])
            if row["module"] not in mods:
                mods.append(row["module"])
    return dict(sorted(out.items()))


def endpoint_owners(endpoints: Optional[Dict[str, List[str]]] = None) -> Dict[str, List[Dict[str, Any]]]:
    """endpoint -> who reads it: [{scope, channels}] (channels empty when
    the check belongs to no channel), only for the watch's endpoints."""
    eps = endpoints if endpoints is not None else watch_endpoints()
    out: Dict[str, List[Dict[str, Any]]] = {ep: [] for ep in eps}
    for row in check_map():
        for ep in row["endpoints"]:
            if ep not in out:
                continue
            owner = {"scope": row["scope"], "channels": list(row["channels"])}
            if owner not in out[ep]:
                out[ep].append(owner)
    return out


def normalize_scopes(scopes: Any) -> List[str]:
    """The known scope keys, in the Scope page's order; anything else dropped."""
    if not isinstance(scopes, (list, tuple, set)):
        return []
    given = {str(s).strip() for s in scopes}
    return [k for k in SCOPE_REGISTRIES if k in given]


def zscaler_channels(channels: Any) -> List[str]:
    """The channel ids marked Zscaler, in the Scope page's channel order
    whatever order they were sent in (so the same selection always reads
    the same); alternative and gap are out."""
    on = {cid for cid, v in channel_scope.normalize(channels).items() if v["choice"] == "zscaler"}
    order = list(channel_scope.CHANNELS)
    return sorted(on, key=lambda c: (order.index(c) if c in order else len(order), c))


def has_selection(scopes: Any, channels: Any) -> bool:
    """Whether anything at all was chosen (a scope ticked or a channel declared)."""
    return bool(normalize_scopes(scopes)) or bool(channel_scope.normalize(channels))


def _owner_in_scope(owner: Dict[str, Any], scopes: Set[str], on: Set[str], alt: Set[str] = frozenset()) -> bool:
    if owner["scope"] not in scopes:
        return False
    if not owner["channels"]:
        return True
    if owner["scope"] == "dlp":
        return any(c in on for c in owner["channels"])
    # Another ticked scope: its checks run unless a channel of theirs is covered elsewhere.
    return not any(c in alt for c in owner["channels"])


def summary(scopes: Sequence[str], on: Sequence[str], n: int) -> str:
    """"12 endpoints for DLP (Web, Email), ZCC". `on` is the channels that
    bring something in (select passes only those)."""
    chans = [CHANNEL_SHORT.get(c, channel_scope.CHANNELS.get(c, c)) for c in on if c in channel_scope.CHANNEL_CHECKS]
    parts = []
    for s in scopes:
        label = SCOPE_LABELS.get(s, s)
        if s == "dlp" and chans:
            label += f" ({', '.join(chans)})"
        parts.append(label)
    if "dlp" not in scopes and chans and scopes:
        parts.append(f"channels on Zscaler: {', '.join(chans)}")
    what = ", ".join(parts) if parts else "nothing in scope"
    return f"{n} endpoint{'' if n == 1 else 's'} for {what}"


def select(scopes: Any, channels: Any, endpoints: Optional[Dict[str, List[str]]] = None) -> Dict[str, Any]:
    """What the watch reads for this Scope page selection:

    {"endpoints": {ep: modules} to read, "not_in_scope": [ep, ...] read by
     checks outside the selection, "unmapped": [ep, ...] read by no
     check, "scopes": [...], "channels": [zscaler channel ids],
     "summary": "12 endpoints for DLP (Web, Email), ZCC"}"""
    eps = endpoints if endpoints is not None else watch_endpoints()
    sc = normalize_scopes(scopes)
    on = zscaler_channels(channels)
    alt = {cid for cid, v in channel_scope.normalize(channels).items() if v["choice"] == "alternative"}
    sset, onset = set(sc), set(on)
    owners = endpoint_owners(eps)
    picked: Dict[str, List[str]] = {}
    not_in, unmapped = [], []
    for ep, mods in eps.items():
        who = owners.get(ep) or []
        if not who:
            unmapped.append(ep)
            continue
        need = CHANNEL_ONLY_ENDPOINTS.get(ep)
        if need and need not in onset:
            not_in.append(ep)
            continue
        if any(_owner_in_scope(o, sset, onset, alt) for o in who):
            picked[ep] = list(mods)
        else:
            not_in.append(ep)
    # The summary names only the channels that bring something in: all of
    # them with DLP ticked, else a channel whose own rule endpoint
    # (CHANNEL_ONLY_ENDPOINTS) a check of another ticked scope reads.
    named = on if "dlp" in sset else [c for c in on if any(CHANNEL_ONLY_ENDPOINTS.get(ep) == c for ep in picked)]
    return {"endpoints": picked, "not_in_scope": not_in, "unmapped": unmapped, "scopes": sc, "channels": on,
            "summary": summary(sc, named, len(picked))}


def describe(sel: Dict[str, Any], source: str = "") -> Dict[str, Any]:
    """The JSON-safe part of a selection, kept on the snapshot and shown on the page."""
    return {"scopes": list(sel["scopes"]), "channels": list(sel["channels"]), "endpoints": len(sel["endpoints"]),
            "read": list(sel["endpoints"]), "not_in_scope": list(sel["not_in_scope"]), "unmapped": list(sel["unmapped"]),
            "summary": sel["summary"], "source": source}


def scope_map() -> Dict[str, Any]:
    """For review and the report: per scope, per channel, the endpoints
    they bring in, and the endpoints no check reads."""
    owners = endpoint_owners()
    per_scope: Dict[str, Set[str]] = {}
    per_channel: Dict[str, Set[str]] = {}
    for ep, who in owners.items():
        for o in who:
            if not o["channels"]:
                per_scope.setdefault(o["scope"], set()).add(ep)
            for c in o["channels"]:
                per_channel.setdefault(c, set()).add(ep)
    return {"scopes": {k: sorted(v) for k, v in per_scope.items()}, "channels": {k: sorted(v) for k, v in per_channel.items()},
            "unmapped": sorted(ep for ep, who in owners.items() if not who)}


def unreadable(endpoints: Iterable[str], legacy: bool, customer_id: str) -> Dict[str, str]:
    """endpoint -> why this sign-in cannot read it, as beacon.probe_tenant
    skips it: anything but ZIA on the classic ZIA API sign-in, and a ZPA
    path without a ZPA customer id."""
    out: Dict[str, str] = {}
    for ep in endpoints:
        if legacy and not ep.startswith("/zia/"):
            out[ep] = "the classic ZIA API sign-in reaches ZIA only"
        elif ep.startswith("/zpa/") and not str(customer_id or "").strip():
            out[ep] = "no ZPA customer id was given"
    return out


def nothing_readable(sel: Dict[str, Any], legacy: bool, customer_id: str) -> str:
    """The refusal when not one endpoint in scope can be read with this
    sign-in (so signing in would read nothing), else ""."""
    eps = list(sel.get("endpoints") or [])
    why = unreadable(eps, legacy, customer_id)
    if not eps or len(why) < len(eps):
        return ""
    reasons = sorted(set(why.values()))
    return (f"{NOTHING_IN_SCOPE} None of the {sel.get('summary') or f'{len(eps)} endpoints'} can be read with this sign-in "
            f"({'; '.join(reasons)}), so the tenant is not signed in to.")
