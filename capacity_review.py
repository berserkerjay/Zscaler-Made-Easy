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
import re
from typing import Any, Callable, Dict, Iterable, List, Optional

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


def review(used: Dict[str, Any], licensed: Dict[str, Any], seats: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """`seats` are licensed counts read from the tenant's subscription list;
    they win over the local file's `licensed`, which is the fallback."""
    rows: List[Dict[str, Any]] = []
    seats = seats or {}
    for key, label in METRICS:
        u = _count(used.get(key))
        l, src = (_count(seats.get(key)), "subscriptions") if _count(seats.get(key)) else (_count(licensed.get(key)), "local file")
        rows.append({"metric": key, "label": label, "used": u, "licensed": l, "licensed_from": src if l else None, **status(u, l)})
    flagged = [r["label"] for r in rows if r["status"] in ("low", "over")]
    return {"rows": rows, "flagged": flagged,
            "notes": ["Licensed counts come from the tenant's subscription list when it states a seat count (assumed row shape: licenses, quantity or seats), else from the local file you recorded.",
                      "Read-only: nothing was changed in the tenant."]}


_SEAT_KEYS = ("licenses", "quantity", "seats", "licensecount", "usercount")


def subscription_seats(body: Any) -> Dict[str, int]:
    """Licensed user seats from GET /subscriptions: the largest seat count on
    an active row (a row's count repeats per product, so rows are not added
    up). The row shape is assumed (readiness.parse_subscriptions); a list
    with no seat field gives {} and the local file is used."""
    rows = body if isinstance(body, list) else (body.get("list") if isinstance(body, dict) and isinstance(body.get("list"), list) else [])
    best = 0
    for r in rows[:500]:
        if not isinstance(r, dict) or r.get("subscribed") is False or re.search(r"EXPIRED|CANCEL", str(r.get("status") or ""), re.I):
            continue
        for k, v in r.items():
            if str(k).lower() in _SEAT_KEYS and (n := _count(v)):
                best = max(best, n)
    return {"users": best} if best else {}


def count_users(sdk: Any, cancel: Any = None) -> Optional[int]:
    """How many ZIA users exist: paged reads (1000 a page) of which only the
    number is kept. None when the read failed."""
    import ops_zia_directory as od
    rows, err, cut = od._paged(od._svc(sdk).list_users, {}, 100000, cancel)
    return None if err else len(rows)


def read_used(sdk: Any, creds: Dict[str, Any], scopes: Iterable[str], cancel: Any = None) -> Dict[str, Any]:
    """Every read the review makes, GET only, for the products in scope:
    {used, seats, notes}. A failed read becomes a note, never an error."""
    import readiness
    import tenant_auth
    import zpa_reader
    import ztw_overview as zo
    from security import validate_customer_id
    sc = set(scopes)
    used: Dict[str, int] = {}
    seats: Dict[str, int] = {}
    notes: List[str] = []
    oneapi = creds.get("auth_method") != tenant_auth.LEGACY

    def attempt(name: str, fn: Callable[[], Any]) -> Any:
        try:
            return fn()
        except Exception as e:  # noqa: BLE001 - one product failing does not stop the others
            notes.append(f"{name} could not be read ({type(e).__name__}).")
            return None
    ztw = zpa = None
    if "ztw" in sc:
        if oneapi:
            ztw = attempt("Cloud & Branch Connector", lambda: zo.read(sdk))
        else:
            notes.append("Cloud & Branch Connector counts need the OneAPI sign-in; locations and tunnels were not read.")
    if "zpa" in sc:
        if oneapi and validate_customer_id(creds.get("customer_id") or ""):
            zpa = attempt("ZPA", lambda: zpa_reader.read(sdk, log=None, cancel=cancel))
        else:
            notes.append("ZPA counts need the OneAPI sign-in and a customer ID; segments and App Connectors were not read.")
    used.update(used_counts(ztw, zpa))
    if "zia_extras" in sc:
        n = attempt("ZIA users", lambda: count_users(sdk, cancel))
        if n is not None:
            used["users"] = n
        elif not any("ZIA users" in x for x in notes):
            notes.append("ZIA users could not be counted (the read failed or this sign-in has no user management).")
        sub = attempt("Subscriptions", lambda: readiness._raw_get(sdk, readiness.SUBSCRIPTIONS_PATH))
        if sub and sub.get("state") == "ok":
            seats = subscription_seats(sub.get("body"))
        elif sub is not None:
            notes.append("The subscription list could not be read; licensed counts come from the local file.")
    else:
        notes.append("Users are counted only with ZIA platform (extras) in scope; not read.")
    return {"used": used, "seats": seats, "notes": notes}


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
        lines.append(f"| {md_safe.text(r['label'])} | {'' if r['used'] is None else r['used']} | {'' if r['licensed'] is None else r['licensed']}{'' if not r.get('licensed_from') else ' (' + r['licensed_from'] + ')'} | {hp} | {r['status']} |")
    lines += [""] + [f"- {md_safe.text(n)}" for n in rep.get("notes") or []]
    return "\n".join(lines) + "\n"


def to_csv(rep: Dict[str, Any]) -> str:
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, ["metric", "label", "used", "licensed", "licensed_from", "headroom_pct", "status"])
    w.writeheader()
    w.writerows(rep["rows"])
    return buf.getvalue()
