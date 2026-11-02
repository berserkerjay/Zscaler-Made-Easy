"""Path analyzer: the same destination for two identities, side by side.

The page runs one analysis per identity (the what-if inputs: user, group,
department, location, and a device when one is picked) on one tenant read,
then `compare` lines the two results up step by step, in the order the
traffic meets them: the device's platform, ZPA (and a workload's
connector), Client Connector's app and forwarding profile, the PAC file,
SSL inspection, every ZIA module, and the verdict. Each step says what
happens for A and for B and whether that differs; the first step where it
differs is where the paths diverge.

Pure: it takes the two results and returns the comparison; `rows` and
`to_csv` make the shareable CSV (spreadsheet-safe, csv_safe).
"""
from __future__ import annotations

import io
from typing import Any, Dict, List, Optional, Tuple

ABSENT = "not on this path"
_PLATFORM = {"windows": "Windows", "macos": "macOS", "ios": "iOS", "android": "Android", "linux": "Linux"}
# A step's outcome in plain words (the page uses the same words).
WORDS = {"pass": "forwarded", "bypass": "bypassed", "bypassed": "bypassed", "block": "blocked", "blocked": "blocked", "allow": "allowed",
         "decrypt": "decrypted", "inspect": "inspected", "caution": "caution", "isolate": "isolated", "none": "no rule", "not_reached": "not reached",
         "not_applicable": "not applicable", "out_of_scope": "not in scope", "unknown": "unknown", "warn": "weak", "blind": "encrypted, not seen",
         "enforce": "enforced", "monitor": "monitored", "not_matched": "no match", "matched": "matched", "conditional": "depends",
         "zpa_allowed": "carried by ZPA", "zpa_denied": "blocked by ZPA"}


def word(outcome: Any) -> str:
    return WORDS.get(str(outcome), str(outcome or "").replace("_", " "))
CSV_COLUMNS = ("step", "label", "a_outcome", "a_rule", "b_outcome", "b_rule", "differs", "first_divergence")


def _txt(v: Any, n: int = 300) -> str:
    return str(v if v is not None else "")[:n]


def _rule(r: Any) -> Optional[str]:
    if isinstance(r, dict):
        return _txt(r.get("name"), 200) or None
    return _txt(r, 200) or None


def steps(res: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One result → its steps in path order: {key, label, outcome, rule, detail}."""
    out: List[Dict[str, Any]] = []
    if not isinstance(res, dict):
        return out
    dev = res.get("device") or {}
    out.append({"key": "platform", "label": "Device platform",
                "outcome": _txt(dev.get("platform_label") if dev else _PLATFORM.get(str(res.get("platform")), res.get("platform"))) or "unknown",
                "rule": _txt((dev.get("app_profile") or {}).get("reported")) or None if dev else None,
                "detail": "the picked device, as the Client Connector Portal reports it" if dev else "the platform chosen"})
    mods = [m for m in res.get("modules") or [] if isinstance(m, dict)]
    hops = [h for h in (res.get("trace") or {}).get("hops") or [] if isinstance(h, dict)]

    def mod(m: Dict[str, Any]) -> Dict[str, Any]:
        return {"key": "m:" + _txt(m.get("key") or m.get("module"), 60), "label": _txt(m.get("module") or m.get("key"), 120),
                "outcome": _txt(m.get("verdict")) or "unknown", "rule": _rule(m.get("rule")), "detail": _txt(m.get("detail"))}

    first = [m for m in mods if str(m.get("key") or "").startswith(("zpa", "connector"))]
    rest = [m for m in mods if m not in first]
    out.extend(mod(m) for m in first)
    for h in hops:
        if h.get("key") in ("zcc", "forwarding"):
            out.append({"key": "h:" + h["key"], "label": _txt(h.get("label"), 120), "outcome": _txt(h.get("status")) or "unknown",
                        "rule": _rule(h.get("decided_by")) or _txt(h.get("profile")) or None, "detail": _txt(h.get("detail"))})
    out.extend(mod(m) for m in rest)
    zm = res.get("zia_modules") or {}
    zmods = [dict(mod(m), key="z:" + _txt(m.get("key") or m.get("module"), 60)) for m in zm.get("modules") or [] if isinstance(m, dict)]
    if isinstance(zm.get("modifier"), dict) and zm["modifier"].get("module"):
        # SSL inspection decides what the later modules see: it follows URL
        # filtering and Cloud App Control (Zscaler's policy enforcement order).
        at = max((i + 1 for i, s in enumerate(zmods) if s["key"] in ("z:url", "z:cac")), default=len(zmods))
        zmods.insert(at, dict(mod(zm["modifier"]), key="z:ssl"))
    out.extend(zmods)
    v = res.get("verdict") or {}
    out.append({"key": "verdict", "label": "Verdict", "outcome": _txt(v.get("outcome")) or ("stopped" if res.get("stopped") else "unknown"),
                "rule": _txt(v.get("blocked_by")) or None, "detail": _txt(v.get("headline"))})
    return out


def _merge_keys(a: List[str], b: List[str]) -> List[str]:
    """A's step order, with B's own steps placed after the step before them in B."""
    keys = list(a)
    for i, k in enumerate(b):
        if k in keys:
            continue
        prev = next((b[j] for j in range(i - 1, -1, -1) if b[j] in keys), None)
        keys.insert(keys.index(prev) + 1 if prev is not None else 0, k)
    return keys


def side_label(res: Dict[str, Any], letter: str) -> str:
    """'A: user jane; device LKF-LT-0001' or 'A: anyone'."""
    parts = []
    w = (res or {}).get("whatif") or {}
    if w.get("identity_label"):
        parts.append(_txt(w["identity_label"], 200))
    d = (res or {}).get("device") or {}
    if d:
        parts.append("device " + (_txt(d.get("hostname"), 80) or "picked"))
    return f"{letter}: " + ("; ".join(parts) if parts else "anyone (no identity given)")


def summary(res: Dict[str, Any], letter: str) -> Dict[str, Any]:
    v = (res or {}).get("verdict") or {}
    d = (res or {}).get("device") or {}
    return {"label": side_label(res, letter), "identity": ((res or {}).get("whatif") or {}).get("identity"),
            "device": {"hostname": d.get("hostname"), "platform": d.get("platform_label"),
                       "app_profile": (d.get("app_profile") or {}).get("applied") or (d.get("app_profile") or {}).get("reported")} if d else None,
            "outcome": v.get("outcome") or ("stopped" if (res or {}).get("stopped") else None), "headline": v.get("headline") or (res or {}).get("stopped"),
            "stops_at": v.get("stops_at"), "blocked_by": v.get("blocked_by"),
            "network": (res or {}).get("network"), "platform": (res or {}).get("platform")}


def compare(a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
    """The two results side by side: {a, b (summaries), steps [{key, label,
    a, b, differs, first}], first_divergence {key, label} | None,
    same_outcome, headline}."""
    sa, sb = steps(a), steps(b)
    ma, mb = {s["key"]: s for s in sa}, {s["key"]: s for s in sb}
    rows: List[Dict[str, Any]] = []
    first: Optional[Dict[str, Any]] = None
    for k in _merge_keys([s["key"] for s in sa], [s["key"] for s in sb]):
        x, y = ma.get(k), mb.get(k)
        side = lambda s: ({"outcome": s["outcome"], "rule": s["rule"], "detail": s["detail"]} if s else  # noqa: E731
                          {"outcome": ABSENT, "rule": None, "detail": ""})
        differs = (x or {}).get("outcome") != (y or {}).get("outcome") or (x or {}).get("rule") != (y or {}).get("rule") or (x is None) != (y is None)
        row = {"key": k, "label": (x or y)["label"], "a": side(x), "b": side(y), "differs": differs, "first": False}
        # The platform is an input, not a decision: the paths diverge at the first step that decides differently.
        if differs and first is None and k != "platform":
            row["first"] = True
            first = row
        rows.append(row)
    A, B = summary(a, "A"), summary(b, "B")
    same_outcome = A["outcome"] == B["outcome"] and A["blocked_by"] == B["blocked_by"]
    if first is None:
        headline = f"Both identities get the same path, step for step: {A['headline'] or A['outcome'] or 'no answer'}"
    else:
        def says(s: Dict[str, Any]) -> str:
            return word(s["outcome"]) + (f" (“{s['rule']}”)" if s.get("rule") else "")
        headline = (f"The paths diverge at {first['label']}: A gets {says(first['a'])}, B gets {says(first['b'])}."
                    + ("" if not same_outcome else " The final verdict is the same."))
    return {"a": A, "b": B, "steps": rows, "first_divergence": {"key": first["key"], "label": first["label"]} if first else None,
            "differences": sum(1 for r in rows if r["differs"] and r["key"] != "platform"), "same_outcome": same_outcome, "headline": headline}


def rows(cmp: Dict[str, Any]) -> List[Dict[str, Any]]:
    """The comparison as CSV rows: the two identities first, then each step."""
    out = [{"step": "identity", "label": "Who", "a_outcome": (cmp.get("a") or {}).get("label"), "b_outcome": (cmp.get("b") or {}).get("label")}]
    for r in cmp.get("steps") or []:
        out.append({"step": r["key"], "label": r["label"], "a_outcome": r["a"]["outcome"], "a_rule": r["a"]["rule"] or "",
                    "b_outcome": r["b"]["outcome"], "b_rule": r["b"]["rule"] or "", "differs": "yes" if r["differs"] else "no",
                    "first_divergence": "yes" if r["first"] else ""})
    return out


def to_csv(cmp: Dict[str, Any]) -> str:
    import csv_safe
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, list(CSV_COLUMNS), extrasaction="ignore")
    w.writeheader()
    for r in rows(cmp):
        w.writerow({k: r.get(k, "") for k in CSV_COLUMNS})
    return buf.getvalue()


def export_json(cmp: Dict[str, Any], extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The shareable JSON: the comparison and what it was run for (no run log)."""
    keep: Tuple[str, ...] = ("a", "b", "steps", "first_divergence", "differences", "same_outcome", "headline")
    return dict({k: cmp.get(k) for k in keep}, **(extra or {}))
