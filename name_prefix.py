"""Managed-name prefix: an optional, operator-chosen text put in front of
the name of every dictionary, engine, rule and endpoint application group a
policy pack deploys (Deploy Policy Packs) or builds (the pack's Terraform
workspace). Off by default.

    DLP_CHECK_NAME_PREFIX=ZME-     "PCI Card Numbers" is deployed as
                                   "ZME-PCI Card Numbers"

The prefix is applied once, where a pack is loaded (pack_deploy.load_sources,
pack_removal, pack_terraform.load_pack), so the plan, the deploy, the
journey check, a removal and Terraform all see the same names, and every
reference inside the pack (an engine's D:<dictionary>, a rule's engines,
application groups and parent rule) is rewritten with it. References to
Zscaler's predefined dictionaries and engines are never prefixed.

Reuse by name works on the prefixed name: an object already in the tenant
under the prefixed name is reused, and recognised as this app's (provenance)
even if its description tag was edited away. The trade-off (in-app help):
a prefix makes managed objects easy to find and keeps them apart from the
customer's own, but names get longer (the SaaS rule limit is 31 characters)
and changing or removing the prefix after a deploy makes the next deploy
create new copies under the new names; the old ones stay until removed.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

SETTING = "DLP_CHECK_NAME_PREFIX"
MAX_LEN = 16
# Letters, digits, space and - _ . : only; it starts with a letter or digit.
# No brackets (a provenance tag is "[... pack ...]"), quotes, slashes or
# control characters, so a prefix can never forge a tag or break a name.
_ALLOWED = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.:\-]*$")


class PrefixError(ValueError):
    """The configured prefix is not one this app accepts."""


def problem(prefix: Any) -> Optional[str]:
    """Why `prefix` cannot be used, or None (an empty prefix is "off")."""
    if prefix is None or prefix == "":
        return None
    if not isinstance(prefix, str):
        return "the managed-name prefix must be text"
    if len(prefix) > MAX_LEN:
        return f"the managed-name prefix is {len(prefix)} characters; at most {MAX_LEN} are allowed"
    if not _ALLOWED.match(prefix):
        return ("the managed-name prefix may hold only letters, digits, spaces and - _ . : and must start with a letter "
                "or a digit")
    if "  " in prefix:
        return "the managed-name prefix may not hold two spaces in a row"
    import pack_deploy
    if pack_deploy.TOOL_NAME_RE.search(prefix):
        return "the managed-name prefix may not be the tool's own name"
    return None


def configured() -> str:
    """The operator's prefix ("" when off). PrefixError when it is set but not valid:
    a bad prefix stops a plan with a plain reason, it is never silently dropped."""
    raw = os.environ.get(SETTING, "")
    if not raw.strip():
        return ""
    p = problem(raw)
    if p:
        raise PrefixError(f"{p} ({SETTING}). Fix the setting and start the app again.")
    return raw


def has(name: Any, prefix: str) -> bool:
    """Whether `name` carries the prefix (ZIA compares names case-insensitively)."""
    return bool(prefix) and str(name or "").casefold().startswith(prefix.casefold())


def add(name: Any, prefix: str) -> str:
    """`name` with the prefix (unchanged when it already carries it, so a pack built with it is not prefixed twice)."""
    name = str(name or "")
    if not prefix or not name or has(name, prefix):
        return name
    return prefix + name


def strip(name: Any, prefix: str) -> str:
    """`name` without the prefix, as the pack calls it."""
    name = str(name or "")
    return name[len(prefix):] if has(name, prefix) else name


def _rewrite_expression(expr: str, renamed: Dict[str, str]) -> str:
    # The same boundary as dlp_importer.engine_references: a name that merely starts the same way is not touched.
    for old in sorted(renamed, key=len, reverse=True):
        if f"D:{old}" not in expr:
            continue
        expr = re.sub(r"D:" + re.escape(old) + r"(?=\s*(?:\bAND\b|\bOR\b|\)|>|\+|$))", lambda m, n=renamed[old]: "D:" + n, expr)
    return expr


def apply(dictionaries: List[Dict[str, Any]], engines: List[Dict[str, Any]], policies: List[Dict[str, Any]],
          app_groups: Optional[List[Dict[str, Any]]], prefix: str
          ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    """The pack's objects with the prefix on their names and on every
    reference to one of them (never on a predefined object the pack only
    refers to). The inputs are not modified; no prefix returns them as they are."""
    groups = list(app_groups or [])
    if not prefix:
        return dictionaries, engines, policies, groups

    def names(objs: Iterable[Dict[str, Any]]) -> Dict[str, str]:
        return {str(o["name"]): add(o["name"], prefix) for o in objs if o.get("name")}
    d_map, e_map, g_map, p_map = names(dictionaries), names(engines), names(groups), names(policies)
    out_d = [dict(d, name=d_map[str(d["name"])]) if d.get("name") else d for d in dictionaries]
    out_e = []
    for e in engines:
        e2 = dict(e, name=e_map[str(e["name"])]) if e.get("name") else dict(e)
        for key in ("expression", "engine_expression"):
            if isinstance(e2.get(key), str):
                e2[key] = _rewrite_expression(e2[key], d_map)
        out_e.append(e2)
    out_g = [dict(g, name=g_map[str(g["name"])]) if g.get("name") else g for g in groups]
    out_p = []
    for p in policies:
        p2 = dict(p, name=p_map[str(p["name"])]) if p.get("name") else dict(p)
        if isinstance(p2.get("engines"), list):
            p2["engines"] = [e_map.get(str(x), x) for x in p2["engines"]]
        if isinstance(p2.get("endpoint_application_groups"), list):
            p2["endpoint_application_groups"] = [g_map.get(str(x), x) for x in p2["endpoint_application_groups"]]
        if p2.get("parent_rule") and str(p2["parent_rule"]) in p_map:
            p2["parent_rule"] = p_map[str(p2["parent_rule"])]
        out_p.append(p2)
    return out_d, out_e, out_p, out_g


def ours_by_name(name: Any, pack_names: Set[str], prefix: str) -> bool:
    """An object found under the prefixed name of one of the pack's objects
    is recognised as this app's, whatever its description says."""
    return bool(prefix) and has(name, prefix) and str(name) in pack_names


def preview(prefix: str) -> Dict[str, Any]:
    """What the plan's preview shows about the prefix."""
    if not prefix:
        return {"on": False, "prefix": "", "note": "Off: objects keep the names the policy pack gives them."}
    return {"on": True, "prefix": prefix,
            "note": (f"Every dictionary, engine, rule and application group this plan creates is named with \"{prefix}\" in front; "
                     f"an object already in the tenant under that name is reused and recognised as this app's.")}
