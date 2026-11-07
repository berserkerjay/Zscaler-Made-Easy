"""Capacity and scaling review: what the tenant uses against what it is licensed for.

Read-only. "Used" counts come from reads the app already makes (the Cloud &
Branch Connector read: locations and their VPN credentials; the ZPA read:
application segments and App Connectors). "Licensed" counts are not in any
Zscaler API the app reads (the subscription list names products, not seats),
so the admin keeps them in a small local file (CAPACITY_FILE, or
DLP_CHECK_CAPACITY) as {"users": 5000, "locations": 200, ...}. A metric with
no read or no licensed count is listed as such, never guessed.

Headroom is (licensed - used) / licensed. Status: ok (>= 20 percent left),
watch (10 to 20), low (under 10), over (used exceeds licensed). Nothing is
written to a tenant; the report exports as Markdown or CSV (md_safe, csv_safe).
"""
from __future__ import annotations

import io
import json
import os
from typing import Any, Dict, List, Optional

import csv_safe
import md_safe

METRICS = (
    ("users", "Users"),
    ("locations", "Locations"),
    ("tunnels", "Tunnels (VPN credentials)"),
    ("app_connectors", "ZPA App Connectors"),
    ("zpa_segments", "ZPA application segments"),
)
WATCH_BELOW = 20.0
LOW_BELOW = 10.0
CAPACITY_FILE = "capacity_entitlements.json"
MAX_COUNT = 10 ** 9


def entitlements_path() -> str:
    return os.environ.get("DLP_CHECK_CAPACITY") or os.path.join(os.path.dirname(os.path.abspath(__file__)), CAPACITY_FILE)


def _count(v: Any) -> Optional[int]:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or v != v or v < 0 or v > MAX_COUNT:
        return None
    return int(v)


def load_entitlements(path: Optional[str] = None) -> Dict[str, int]:
    """The licensed counts the admin recorded; unknown keys and bad values are ignored."""
    try:
        with open(path or entitlements_path(), encoding="utf-8") as f:
            raw = json.load(f)
    except (OSError, ValueError):
        return {}
    keys = {k for k, _ in METRICS}
    return {k: n for k, v in (raw.items() if isinstance(raw, dict) else []) if k in keys and (n := _count(v)) is not None and n > 0}


def status(used: Optional[int], licensed: Optional[int]) -> Dict[str, Any]:
    if used is None:
        return {"status": "not_read", "headroom_pct": None}
    if not licensed:
        return {"status": "no_licensed_count", "headroom_pct": None}
    pct = round((licensed - used) * 100.0 / licensed, 1)
    s = "over" if used > licensed else "low" if pct < LOW_BELOW else "watch" if pct < WATCH_BELOW else "ok"
    return {"status": s, "headroom_pct": pct}


def review(used: Dict[str, Any], licensed: Dict[str, Any]) -> Dict[str, Any]:
    rows: List[Dict[str, Any]] = []
    for key, label in METRICS:
        u, l = _count(used.get(key)), _count(licensed.get(key))
        rows.append({"metric": key, "label": label, "used": u, "licensed": l, **status(u, l)})
    flagged = [r["label"] for r in rows if r["status"] in ("low", "over")]
    return {"rows": rows, "flagged": flagged,
            "notes": ["Licensed counts are the ones you recorded locally; the tenant's subscription list names products, not seat counts.",
                      "Read-only: nothing was changed in the tenant."]}


def used_counts(ztw_snap: Optional[Dict[str, Any]], zpa_snap: Optional[Dict[str, Any]]) -> Dict[str, int]:
    """Used counts from the snapshots the app's own reads return (None: that product was not read)."""
    out: Dict[str, int] = {}
    if ztw_snap is not None:
        locs = [x for x in ztw_snap.get("locations") or [] if isinstance(x, dict)]
        out["locations"] = len(locs)
        out["tunnels"] = sum(n for x in locs if (n := _count(x.get("vpnCredentialCount"))) is not None)
    if zpa_snap is not None:
        out["zpa_segments"] = len(zpa_snap.get("segments") or [])
        out["app_connectors"] = len(zpa_snap.get("connectors") or [])
    return out


def to_markdown(rep: Dict[str, Any], title: str = "Capacity review") -> str:
    lines = [f"# {md_safe.text(title)}", "", "| Metric | Used | Licensed | Headroom | Status |", "|---|---|---|---|---|"]
    for r in rep["rows"]:
        hp = "" if r["headroom_pct"] is None else f"{r['headroom_pct']}%"
        lines.append(f"| {md_safe.text(r['label'])} | {'' if r['used'] is None else r['used']} | {'' if r['licensed'] is None else r['licensed']} | {hp} | {r['status']} |")
    lines += [""] + [f"- {md_safe.text(n)}" for n in rep.get("notes") or []]
    return "\n".join(lines) + "\n"


def to_csv(rep: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, ["metric", "label", "used", "licensed", "headroom_pct", "status"])
    w.writeheader()
    w.writerows(rep["rows"])
    return buf.getvalue()
