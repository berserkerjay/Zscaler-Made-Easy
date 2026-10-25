"""Console index: what DLP-Check knows about each DLP object, for the
companion browser extension's badges and side panel in the Zscaler admin
console.

Built from the same read-only inventory the rule picker uses
(pack_removal.inventory): every DLP rule on the channels in scope, every
custom engine and every dictionary. For each object: what it uses, what
uses it (counts and names), which policy pack created it, and short
findings (unused, disabled, monitor-only, no engines, shadowed when the
shadowed-rule analysis is available). Pure apart from build(): the tests
feed it an inventory.

The extension matches object names it sees on a console page against this
index locally; the page's content never leaves the browser, and the index
holds configuration metadata only (names, counts, states), never a secret,
user or file name.
"""
from __future__ import annotations

import time
from typing import Any, Dict, Iterable, List, Optional

import pack_channels as pc

MONITOR_ACTIONS = {"ALLOW", "OFLCASB_DLP_REPORT_INCIDENT", "REPORT", "MONITOR"}


def _finding(severity: str, text: str) -> Dict[str, str]:
    return {"severity": severity, "text": text}


def _names(items: Iterable[Any], limit: int = 25) -> List[str]:
    out = sorted({str(x) for x in items if x not in (None, "")}, key=str.lower)
    return out[:limit]


def from_inventory(inv: Dict[str, Any], *, tenant_label: str = "", shadow: Optional[Dict[Any, List[Dict[str, Any]]]] = None,
                   now: Optional[float] = None) -> Dict[str, Any]:
    """The index from an inventory (pack_removal.inventory's answer).
    `shadow` maps (policy, rule name) to shadowed-rule findings."""
    rules = [r for r in (inv.get("rules") or []) if r.get("name")]
    engines = [e for e in (inv.get("engines") or []) if e.get("name")]
    dicts = {str(n): d for n, d in (inv.get("dictionaries") or {}).items()}

    rules_by_engine: Dict[str, List[Dict[str, Any]]] = {}
    for r in rules:
        for e in r.get("engines") or []:
            rules_by_engine.setdefault(str(e), []).append(r)
    engines_by_dict: Dict[str, List[str]] = {}
    for e in engines:
        for d in e.get("dictionaries") or []:
            engines_by_dict.setdefault(str(d), []).append(e["name"])

    objects: List[Dict[str, Any]] = []
    for name, d in sorted(dicts.items(), key=lambda kv: kv[0].lower()):
        users = engines_by_dict.get(name, [])
        via_rules = {r["name"] for e in users for r in rules_by_engine.get(e, [])}
        f = []
        if d.get("custom") and not users:
            f.append(_finding("low", "No custom engine uses this dictionary, so it detects nothing on its own."))
        objects.append({"kind": "dictionary", "name": name, "id": d.get("id"), "custom": bool(d.get("custom")),
                        "type": d.get("type") or "", "used_by": {"engines": _names(users), "rules": _names(via_rules)},
                        "counts": {"engines": len(set(users)), "rules": len(via_rules)}, "pack": None, "findings": f})
    for e in sorted(engines, key=lambda x: str(x["name"]).lower()):
        users = rules_by_engine.get(e["name"], [])
        f = []
        if not users:
            f.append(_finding("low", "No DLP rule uses this engine, so it never acts."))
        objects.append({"kind": "engine", "name": e["name"], "id": e.get("id"), "custom": True,
                        "uses": {"dictionaries": _names(e.get("dictionaries") or [])},
                        "used_by": {"rules": _names(r["name"] for r in users)},
                        "counts": {"rules": len({r["name"] for r in users}), "dictionaries": len(set(e.get("dictionaries") or []))},
                        "pack": None, "findings": f})
    for r in rules:
        ch = r.get("channel") or ""
        state = str(r.get("state") or "").upper()
        action = str(r.get("action") or "").upper()
        f = []
        if state == "DISABLED":
            f.append(_finding("info", "Disabled: this rule does not inspect anything until it is enabled."))
        elif action in MONITOR_ACTIONS:
            f.append(_finding("medium", "Monitor only: matches are logged but the data still leaves."))
        if pc.has_engines(ch) and not (r.get("engines") or []):
            f.append(_finding("medium", "No DLP engine: the rule has nothing to match content with."))
        for s in (shadow or {}).get((ch, r["name"]), []) + (shadow or {}).get(("dlp", r["name"]), []):
            f.append(_finding(str(s.get("severity") or "high"), str(s.get("reason") or "Shadowed by an earlier rule.")))
        objects.append({"kind": "rule", "name": r["name"], "id": r.get("id"), "channel": ch, "channel_label": pc.label(ch) if ch else "",
                        "state": state, "action": action, "parent_id": r.get("parent_id"),
                        "uses": {"engines": _names(r.get("engines") or [])},
                        "counts": {"engines": len(set(r.get("engines") or []))},
                        "pack": r.get("pack"), "findings": f})
    counts = {k: sum(1 for o in objects if o["kind"] == k) for k in ("dictionary", "engine", "rule")}
    counts["findings"] = sum(len(o["findings"]) for o in objects)
    return {"version": 1, "tenant_label": tenant_label, "read_at": int(now if now is not None else time.time()),
            "channels": sorted({r.get("channel") for r in rules if r.get("channel")}),
            "errors": inv.get("errors") or {}, "counts": counts, "objects": objects}


def build(client, channels: Optional[Iterable[str]] = None, *, tenant_label: str = "",
          shadow: Optional[Dict[Any, List[Dict[str, Any]]]] = None) -> Dict[str, Any]:
    """Read the tenant (read-only, the in-scope channels only) and index it,
    with the shadowed-rule findings (shadow_by_channel) when given."""
    import pack_removal
    inv = pack_removal.inventory(client, list(channels) if channels is not None else None)
    if inv.get("status") != "ready":
        return {"status": "blocked", "blockers": inv.get("blockers") or ["Could not read the tenant."], "errors": inv.get("errors") or {}}
    out = from_inventory(inv, tenant_label=tenant_label, shadow=shadow)
    out["status"] = "ready"
    return out


# shadow_rules names DLP policies by policy type; the index by channel.
_SHADOW_CHANNEL = {"web_dlp": "web", "endpoint_dlp": "endpoint", "email_dlp": "email", "saas_dlp": "saas"}


def shadow_by_channel(findings: Iterable[Dict[str, Any]]) -> Dict[Any, List[Dict[str, Any]]]:
    """Shadowed-rule findings (shadow_rules) keyed (channel, rule name) for
    the DLP rules the index holds. Disabled rules are left out: the index
    already says so itself."""
    out: Dict[Any, List[Dict[str, Any]]] = {}
    for f in findings or []:
        ch = _SHADOW_CHANNEL.get(str(f.get("policy") or ""))
        if ch and f.get("rule") is not None and f.get("kind") != "disabled":
            out.setdefault((ch, str(f["rule"])), []).append(f)
    return out


# ---------------------------------------------------------------------------
# A small per-profile cache, so the side panel does not read the tenant on
# every page the admin opens. Kept in memory only.
# ---------------------------------------------------------------------------

CACHE_SECONDS = 30 * 60
_CACHE: Dict[str, Dict[str, Any]] = {}


def cache_key(profile_id: str, channels: Iterable[str]) -> str:
    return f"{profile_id or 'server'}|{','.join(sorted(channels or []))}"


def cache_put(key: str, index: Dict[str, Any]) -> None:
    _CACHE[key] = {"at": time.time(), "index": index}
    for k in sorted(_CACHE, key=lambda k: _CACHE[k]["at"])[:-16]:   # bounded
        _CACHE.pop(k, None)


def cache_get(key: str) -> Optional[Dict[str, Any]]:
    hit = _CACHE.get(key)
    if not hit or time.time() - hit["at"] > CACHE_SECONDS:
        return None
    return dict(hit["index"], cached_at=int(hit["at"]))


def cache_clear() -> None:
    _CACHE.clear()
