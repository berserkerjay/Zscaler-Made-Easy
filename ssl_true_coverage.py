"""True inspection coverage: one correlated answer to "how much of our web
traffic does Zscaler really inspect, and why is the rest not inspected?".

It joins what ssl_coverage.py already reads (the causes from the SSL
inspection rules, Client Connector and PAC files, and the Z-Insights
traffic numbers) with what traffic_logs.py reads from uploaded ZIA NSS web
logs. It reads nothing itself and is pure: report data in, one block out.

The answer, per unit (transactions and bytes), is four slices that always
add up to exactly 100% (largest-remainder rounding in tenths):

  http                 plain HTTP: Zscaler sees the content without decrypting
  https_inspected      HTTPS that Zscaler decrypted and inspected
  https_not_inspected  HTTPS that passed through still encrypted
  unknown              traffic the source cannot classify (Insights' protocol
                       names this app does not map, NSS lines without the
                       decryption field): never counted as inspected

The true figure is http + https_inspected; with the unknown slice it is a
range ("between 71% and 76%"), never the higher number alone.

Sources, best first (one source gives the figure; no mixing):

  logs      uploaded ZIA NSS web logs (traffic_logs.py): each line says
            whether it was decrypted (ssldecrypted) and its URL category and
            cloud application, so each not-inspected line is tied to the
            first SSL rule, in rule order, that leaves that category or
            application encrypted. Measured, for the logs' own time span.
  insights  Z-Insights WEB_TRAFFIC.protocols (ssl_coverage.read_volume):
            measured, tenant-wide, for the chosen window. Insights cannot
            group traffic by rule or URL category, so the not-inspected
            slice is split only by the Shadow IT bytes of exempted
            applications (an estimate, an upper bound per application),
            and the rest is shown as not split, with the causes that may
            be behind it.
  policy    no traffic numbers: the SSL rules' decision per kind of traffic
            applied to a typical traffic mix (ASSUMED_MIX). Always labelled
            an estimate, never shown as measured, with what is needed for
            the measured figure.

Traffic that never reaches ZIA (Client Connector and PAC bypasses, a
forwarding profile sending a network direct, private applications on ZPA)
is not in any ZIA number: it is listed under `outside` with its cause and
fix. So the figure is the share of the web traffic that REACHED ZIA, and
every label says so. A second figure, `including_bypass`, answers "of all
my web traffic": with the bypassed volume known (the admin's own figure
from firewall or egress logs, in bytes for the same period) the bypassed
traffic is counted as not inspected; without it, it says plainly that the
share is unmeasured and only bounded above. ZPA private applications are
not internet web traffic and stay out of both.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

import ssl_coverage as sc

SLICES = ("http", "https_inspected", "https_not_inspected", "unknown")
SLICE_LABEL = {"http": "Plain HTTP (seen without decryption)", "https_inspected": "HTTPS decrypted and inspected",
               "https_not_inspected": "HTTPS not inspected", "unknown": "Unknown"}
UNITS = ("TRANSACTIONS", "BYTES")
UNIT_LABEL = {"TRANSACTIONS": "transactions", "BYTES": "bytes", "MIX": "a typical traffic mix"}
TOP_CAUSES = 8

# Insights protocol bucket (ssl_coverage.PROTOCOL_BUCKETS) -> slice.
# "other" (tunnels, FTP, names the table does not know) is unknown.
_FROM_PROTOCOL = {"http": "http", "ssl_inspected": "https_inspected", "ssl_not_inspected": "https_not_inspected", "other": "unknown"}
# traffic_logs zia_web ssl bucket -> slice. A line with no ssldecrypted
# field that is not HTTP ("not_logged") is unknown.
_FROM_LOG = {"plain_http": "http", "inspected": "https_inspected", "not_inspected": "https_not_inspected", "not_logged": "unknown"}

# The policy estimate's typical traffic mix. assumed: a round, generic
# enterprise web mix by share of HTTPS bytes per traffic kind
# (ssl_flow.TRAFFIC_CLASSES), and about 5% of web traffic still plain HTTP.
# Neither comes from Zscaler or from this tenant; the page says so and the
# estimate is never presented as measured.
ASSUMED_HTTP_PCT = 5.0
ASSUMED_MIX = {"general": 52.0, "collab": 14.0, "file_share": 10.0, "social": 6.0, "privacy": 6.0, "webmail": 4.0,
               "ai_ml": 3.0, "forums": 2.0, "unknown": 2.0, "remote": 1.0}

# Where each kind of cause is fixed: an existing Bulk changes builder
# (/report/operations?build=<type>), previewed and gated like every write.
FIX_LINKS: Dict[str, Tuple[str, str]] = {
    "ssl_rule": ("rule_edit", "Edit the SSL inspection rule (Bulk changes)"),
    "ssl_rule_scoped": ("rule_edit", "Edit the SSL inspection rule (Bulk changes)"),
    "catch_all": ("rule_edit", "Edit the SSL inspection rule (Bulk changes)"),
    "scoped_catch_all": ("rule_edit", "Edit the SSL inspection rule (Bulk changes)"),
    "zcc_domains": ("zcc_app_profile_settings", "Change the app profile's tunnel exclusions (Bulk changes)"),
    "zcc_ips": ("zcc_app_profile_settings", "Change the app profile's tunnel exclusions (Bulk changes)"),
    "zcc_apps": ("zcc_bypass_app", "Review the Client Connector bypass apps (Bulk changes)"),
    "zcc_processes": ("zcc_bypass_app", "Review the Client Connector bypass apps (Bulk changes)"),
    "forwarding_none": ("zcc_profile_build", "Build a forwarding profile that tunnels (Bulk changes)"),
    "pac_direct": ("zia_pac", "Edit the PAC file (Bulk changes)"),
}
ZPA_FIX = {"href": "/report/zpa", "label": "Open the ZPA page"}

NEEDS = ("For a measured figure: tick ZIA Insights (traffic data) on the Scope page and sign in with a OneAPI (ZIdentity) API "
         "client whose role may read Insights; ZIA's SSL inspection licence makes the decrypted share meaningful. Or upload ZIA "
         "NSS web logs on the Traffic and session logs page (needs an NSS or Cloud NSS web log feed) and pick them here: the logs "
         "also say which rule left each line encrypted.")
ZPA_NOTE = ("Private applications reached through ZPA go from Client Connector to ZPA, never to ZIA's SSL inspection, so they are "
            "not in these numbers. ZPA has its own inspection (AppProtection); its traffic is in ZPA's LSS logs.")


SOURCE_WORD = {"logs": "Uploaded web logs", "insights": "ZIA Insights"}


def source_word(entry: Mapping[str, Any]) -> str:
    """Where a history entry's inspected shares were measured: the true
    figure's source, or ZIA Insights for a run kept before it existed (its
    shares then left unknown traffic out), or nothing when none was measured."""
    src = entry.get("true_source")
    if src in SOURCE_WORD:
        return SOURCE_WORD[src]
    if entry.get("inspected_pct_bytes") is None and entry.get("inspected_pct_transactions") is None:
        return ""
    return "ZIA Insights (unknown left out)"


def fix_of(cause: Mapping[str, Any]) -> Optional[Dict[str, str]]:
    """The fix link of a cause, or None when it should be kept (expected,
    certificate-pinned, or 'do not change')."""
    if cause.get("risk") == "expected" or cause.get("safe") in ("keep", "no"):
        return None
    hit = FIX_LINKS.get(str(cause.get("kind") or ""))
    if not hit:
        return None
    return {"href": f"/report/operations?build={hit[0]}", "label": hit[1]}


# ── Arithmetic ──────────────────────────────────────────────────────────
# No real tenant moves a zettabyte in a window: an amount above this comes
# from a broken or hostile answer or upload, and is left out (as 0).
MAX_AMOUNT = 1e21


def _num(v: Any) -> float:
    if isinstance(v, bool):
        return 0.0
    try:
        f = float(v)
    except (TypeError, ValueError, OverflowError):
        return 0.0
    return f if f == f and 0 < f <= MAX_AMOUNT else 0.0


def tenths(amounts: Mapping[str, float], keys: Iterable[str], total_tenths: int = 1000) -> Dict[str, int]:
    """Largest-remainder shares of `total_tenths` (1000 = 100.0%) in
    tenths of a percent, so the rounded shares add up exactly. Ties go to
    the earlier key. Nothing to divide gives all zeros. Pure."""
    keys = list(keys)
    vals = {k: _num(amounts.get(k)) for k in keys}
    top = max(vals.values(), default=0.0)
    if top <= 0 or total_tenths <= 0:
        return {k: 0 for k in keys}
    vals = {k: v / top for k, v in vals.items()}   # scaled to at most 1: the sum can never overflow
    total = sum(vals.values())
    raw = {k: vals[k] * total_tenths / total for k in keys}
    out = {k: int(raw[k]) for k in keys}
    left = total_tenths - sum(out.values())
    for k in sorted(keys, key=lambda k: (-(raw[k] - out[k]), keys.index(k)))[:left]:
        out[k] += 1
    return out


def unit_split(amounts: Mapping[str, float]) -> Optional[Dict[str, Any]]:
    """The four slices of one unit, their shares (summing to 100.0) and
    the true figure with its range. None when there is nothing to divide."""
    clean = {k: _num(amounts.get(k)) for k in SLICES}
    total = sum(clean.values())
    if total <= 0:
        return None
    t = tenths(clean, SLICES)
    slices = [{"key": k, "label": SLICE_LABEL[k], "amount": clean[k], "pct": t[k] / 10} for k in SLICES]
    seen = t["http"] + t["https_inspected"]
    return {"total": total, "slices": slices, "sum_pct": sum(t.values()) / 10,
            "inspected_pct": seen / 10, "inspected_pct_high": (seen + t["unknown"]) / 10,
            "not_inspected_pct": t["https_not_inspected"] / 10, "unknown_pct": t["unknown"] / 10, "_tenths": t}


def from_protocols(sp: Optional[Mapping[str, Any]]) -> Dict[str, float]:
    b = (sp or {}).get("buckets") or {}
    out = {k: 0.0 for k in SLICES}
    for bucket, slice_ in _FROM_PROTOCOL.items():
        out[slice_] += _num(b.get(bucket))
    return out


def from_logs(ssl: Mapping[str, Any], unit: str) -> Dict[str, float]:
    src = ssl if unit == "TRANSACTIONS" else (ssl.get("bytes") or {})
    out = {k: 0.0 for k in SLICES}
    for bucket, slice_ in _FROM_LOG.items():
        out[slice_] += _num(src.get(bucket))
    return out


# ── Cause attribution ───────────────────────────────────────────────────
def _row(c: Mapping[str, Any]) -> Dict[str, Any]:
    src = c.get("source") or {}
    return {"cause_id": c.get("id"), "kind": c.get("kind"), "kind_label": c.get("kind_label"), "rule": src.get("name") or "",
            "order": src.get("order"), "what": c.get("what"), "risk": c.get("risk"), "risk_label": c.get("risk_label"),
            "scope": c.get("scope"), "recovery": c.get("recovery"), "console": c.get("console"), "fix": fix_of(c)}


def _rule_causes(causes: Iterable[Mapping[str, Any]]) -> List[Mapping[str, Any]]:
    """The causes that act on traffic that reaches ZIA (SSL rules), in rule order."""
    rs = [c for c in causes if not c.get("never_reaches_zscaler") and str(c.get("id") or "").startswith("ssl-")]
    return sorted(rs, key=lambda c: (1 if c.get("kind") in ("catch_all", "scoped_catch_all") else 0,
                                     sc.ssl_flow._int((c.get("source") or {}).get("order"), 10 ** 6)))


def match_log_row(category: str, app: str, causes: List[Mapping[str, Any]]) -> Tuple[Optional[Mapping[str, Any]], str]:
    """(cause, how) for one not-inspected (URL category, cloud application)
    pair of the logs: the first SSL rule, in rule order, that names the
    category or the application, else a catch-all rule that leaves
    everything else encrypted, else Zscaler's certificate-pinned
    exemptions for an application known to pin, else (None, why).
    Category names are compared without case, spaces or punctuation (logs
    carry display names, rules ids); applications by name prefix
    (ssl_coverage._match_name). A rule for some users only may not apply
    to every line: `how` says "probably" then."""
    cat_n = sc._norm(category)
    for c in causes:
        if c.get("kind") in ("catch_all", "scoped_catch_all", "pinned_exemptions"):
            continue
        by_cat = cat_n and any(sc._norm(x) == cat_n for x in c.get("categories") or [])
        by_app = app and any(sc._match_name(a, app) for a in c.get("apps") or [])
        if by_cat or by_app:
            what = f"its {'URL category' if by_cat else 'cloud application'} is in this rule"
            return c, (f"probably: {what}, which applies to {c.get('scope')} only" if c.get("scope") != "everyone" else what)
    for c in causes:
        if c.get("kind") in ("catch_all", "scoped_catch_all"):
            return c, ("no earlier rule decrypts it, and this rule leaves the rest encrypted"
                       + (f" for {c.get('scope')}" if c.get("scope") != "everyone" else ""))
    if app and sc.is_pinned(app):
        for c in causes:
            if c.get("kind") == "pinned_exemptions":
                return c, "a certificate-pinned application Zscaler exempts"
    return None, "no enabled SSL rule read here leaves this category or application encrypted"


def _spread(rows: List[Dict[str, Any]], slice_tenths: int, key: str) -> None:
    """Give each row its share of the slice in tenths, adding up exactly
    to the slice (largest remainder). In place."""
    t = tenths({str(i): r[key] for i, r in enumerate(rows)}, [str(i) for i in range(len(rows))], slice_tenths)
    for i, r in enumerate(rows):
        r["pct"] = t[str(i)] / 10


def attribute_logs(ssl: Mapping[str, Any], causes: List[Mapping[str, Any]], split: Mapping[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """The not-inspected slice of the logs, tied to causes. Per cause:
    transactions and bytes, and its share of all web traffic in each unit
    (the shares add up to the slice). Lines past the logs' top list are
    one row of their own, never guessed onto a rule."""
    rules = _rule_causes(causes)
    by: Dict[str, Dict[str, Any]] = {}
    for r in ssl.get("not_inspected_by") or []:
        if not isinstance(r, Mapping):
            continue
        cat, app = str(r.get("category") or ""), str(r.get("app") or "")
        if cat == "(other values, past the counting limit)":
            c, how = None, "past the counting limit of the log reader"
        else:
            c, how = match_log_row(cat, app, rules)
        key = str(c.get("id")) if c else f"none:{how}"
        row = by.get(key)
        if row is None:
            row = by[key] = dict(_row(c), how=how, basis="measured in your logs", examples=[]) if c else {
                "cause_id": None, "kind": "unexplained", "kind_label": "Not explained by the SSL rules read", "rule": "", "what": "",
                "risk": "medium", "risk_label": "Medium", "how": how, "fix": None, "basis": "measured in your logs", "examples": [],
                "recovery": "Check the SSL policy reason in these log lines (certificate errors, unsupported TLS, a rule not in scope)."}
            row.update(TRANSACTIONS=0.0, BYTES=0.0)
        row["TRANSACTIONS"] += _num(r.get("count"))
        row["BYTES"] += _num(r.get("bytes"))
        if len(row["examples"]) < 5:
            row["examples"].append(" / ".join(x for x in (cat, app) if x) or "(no category or application in the log)")
    rows = sorted(by.values(), key=lambda x: (-x["BYTES"], -x["TRANSACTIONS"]))
    rest = {}
    for unit in UNITS:
        sp = split.get(unit)
        whole = sp["slices"][2]["amount"] if sp else 0.0
        rest[unit] = max(0.0, whole - sum(x[unit] for x in rows))
    if any(rest.values()):
        rows.append({"cause_id": None, "kind": "rest", "kind_label": "Smaller amounts", "rule": "", "what": "", "risk": "low",
                     "risk_label": "Low", "how": "the logs' top 100 category and application pairs are tied to rules; the rest is summed here",
                     "fix": None, "basis": "measured in your logs", "examples": [], "recovery": "", **rest})
    return _per_unit(rows, split, unattributed=None)


def _per_unit(rows: List[Dict[str, Any]], split: Mapping[str, Optional[Dict[str, Any]]], unattributed: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Each row's share of all web traffic per unit; the shares of the rows
    (and the not-split row) add up exactly to the not-inspected slice. A
    row with no amount in a unit has no share in it (None)."""
    out: Dict[str, Any] = {"causes": rows, "unattributed": unattributed}
    for unit in UNITS:
        sp = split.get(unit)
        for r in rows + ([unattributed] if unattributed else []):
            r.setdefault("pct_of", {})[unit] = None
        parts = [r for r in rows if r.get(unit) is not None] + ([unattributed] if unattributed and unattributed.get(unit) is not None else [])
        if not sp:
            continue
        tmp = [{"amount": r[unit]} for r in parts]
        _spread(tmp, sp["_tenths"]["https_not_inspected"], "amount")
        for r, t in zip(parts, tmp):
            r.setdefault("pct_of", {})[unit] = t["pct"]
    return out


def attribute_insights(causes: List[Mapping[str, Any]], split: Mapping[str, Optional[Dict[str, Any]]]) -> Dict[str, Any]:
    """The not-inspected slice of Insights, split as far as Insights allows:
    in bytes only, by the Shadow IT bytes of the applications each SSL rule
    exempts (ssl_coverage.attach_app_volume), each application counted once
    for the first rule in order that names it, and never more than the
    slice holds (scaled down when the upper bounds add up to more). The
    rest is one 'not split' row naming the causes Insights cannot measure."""
    rules = _rule_causes(causes)
    seen: set = set()
    rows: List[Dict[str, Any]] = []
    unmeasured: List[Dict[str, Any]] = []
    for c in rules:
        vol = c.get("volume") or {}
        apps = [a for a in vol.get("apps") or [] if str(a.get("application")) not in seen]
        b = sum(_num(a.get("bytes")) for a in apps)
        seen.update(str(a.get("application")) for a in apps)
        if b > 0:
            rows.append(dict(_row(c), how="its applications' Shadow IT bytes (an upper bound: all their traffic)",
                             basis="estimate from Shadow IT application bytes", examples=[a.get("application") for a in apps][:5],
                             TRANSACTIONS=None, BYTES=b))
        else:
            unmeasured.append(_row(c))
    sp = split.get("BYTES")
    slice_b = sp["slices"][2]["amount"] if sp else 0.0
    total = sum(r["BYTES"] for r in rows)
    capped = bool(sp) and total > slice_b
    if capped and total:
        for r in rows:
            r["BYTES"] = r["BYTES"] * slice_b / total
    rows.sort(key=lambda r: -r["BYTES"])
    tx = split.get("TRANSACTIONS")
    un = {"cause_id": None, "kind": "not_split", "kind_label": "Not split by cause", "rule": "", "what": "", "risk": "medium",
          "risk_label": "Medium", "fix": None, "basis": "measured total; Insights cannot group traffic by rule or URL category",
          "how": "category, catch-all and pinned exemptions have no traffic of their own in Insights",
          "likely": unmeasured[:TOP_CAUSES], "examples": [],
          "BYTES": max(0.0, slice_b - sum(r["BYTES"] for r in rows)) if sp else None,
          "TRANSACTIONS": tx["slices"][2]["amount"] if tx else None}
    out = _per_unit(rows, split, un)
    out["capped"] = capped
    return out


# ── Policy estimate ─────────────────────────────────────────────────────
def estimate(classes: List[Mapping[str, Any]], causes: List[Mapping[str, Any]]) -> Optional[Dict[str, Any]]:
    """Slices of a typical traffic mix from the SSL rules' decision per
    kind of traffic (for everyone; rules for some users only are not
    counted). A kind whose decision is unknown is unknown, never
    inspected. None when no class was decided."""
    if not classes:
        return None
    https = 100.0 - ASSUMED_HTTP_PCT
    amounts = {k: 0.0 for k in SLICES}
    amounts["http"] = ASSUMED_HTTP_PCT
    per_rule: Dict[str, Dict[str, Any]] = {}
    by_name = {str((c.get("source") or {}).get("name") or ""): c for c in _rule_causes(causes)}
    for k in classes:
        share = https * ASSUMED_MIX.get(str(k.get("key")), 0.0) / 100.0
        d = k.get("decision")
        if d in ("inspected", "blocked"):
            amounts["https_inspected"] += share
        elif d in ("not_inspected", "no_rule"):
            amounts["https_not_inspected"] += share
            name = str(k.get("decided_by") or "")
            c = by_name.get(name)
            key = name or "(no rule: the default leaves it encrypted)"
            row = per_rule.get(key)
            if row is None:
                row = per_rule[key] = dict(_row(c), how="decides these kinds of traffic for everyone", basis="estimate from a typical traffic mix",
                                           examples=[], MIX=0.0) if c else {
                    "cause_id": None, "kind": "no_rule", "kind_label": "No SSL rule decides it", "rule": name, "what": "", "risk": "high",
                    "risk_label": "High", "how": "no enabled rule matches these kinds of traffic", "fix": None,
                    "basis": "estimate from a typical traffic mix", "examples": [], "MIX": 0.0, "recovery": ""}
            row["MIX"] += share
            row["examples"].append(k.get("label"))
        else:
            amounts["unknown"] += share
    sp = unit_split(amounts)
    if not sp:
        return None
    rows = sorted(per_rule.values(), key=lambda r: -r["MIX"])
    tmp = [{"amount": r["MIX"]} for r in rows]
    _spread(tmp, sp["_tenths"]["https_not_inspected"], "amount")
    for r, t in zip(rows, tmp):
        r["pct_of"] = {"MIX": t["pct"]}
    return {"split": sp, "causes": rows}


# ── Outside ZIA ─────────────────────────────────────────────────────────
def outside(causes: Iterable[Mapping[str, Any]], zpa_in_scope: bool) -> List[Dict[str, Any]]:
    """Causes whose traffic never reaches ZIA: no ZIA number can hold it."""
    rows = [dict(_row(c), why="Never reaches ZIA, so no ZIA traffic number holds it: not measurable here.")
            for c in causes if c.get("never_reaches_zscaler") and c.get("risk") != "expected"]
    rows.sort(key=lambda r: sc.RISK_ORDER.get(r.get("risk"), 9))
    if zpa_in_scope:
        # assumed: Client Connector sends ZPA application segments' traffic to
        # ZPA only (Zscaler's documented ZIA/ZPA split); ZIA never sees it.
        rows.append({"cause_id": "zpa-private-apps", "kind": "zpa_routed", "kind_label": "Private applications on ZPA", "rule": "",
                     "what": "Traffic to ZPA application segments", "risk": "low", "risk_label": "Low", "scope": "devices with ZPA",
                     "recovery": "Use ZPA's own inspection (AppProtection) where private applications carry sensitive data.",
                     "console": "ZPA Admin Portal → Policies → AppProtection", "why": ZPA_NOTE, "fix": dict(ZPA_FIX)})
    return rows


# ── The block ───────────────────────────────────────────────────────────
def _fmt(p: Optional[float]) -> str:
    return "—" if p is None else f"{p:g}%"


def _headline(mode: str, unit: str, sp: Mapping[str, Any], window: str, out_n: int, incl: Optional[Mapping[str, Any]] = None) -> str:
    sl = {s["key"]: s["pct"] for s in sp["slices"]}
    what = UNIT_LABEL.get(unit, unit)
    if mode == "estimate":
        lead = (f"Estimate, not measured: with your SSL rules, about {_fmt(sp['inspected_pct'])} of {what} would be inspected "
                f"({_fmt(sl['http'])} plain HTTP and {_fmt(sl['https_inspected'])} HTTPS decrypted); about {_fmt(sl['https_not_inspected'])} "
                "would be HTTPS left encrypted")
    else:
        lead = (f"True inspection coverage{f' ({window})' if window else ''}: {_fmt(sp['inspected_pct'])} of the web {what} that reached ZIA "
                f"was visible to Zscaler ({_fmt(sl['http'])} plain HTTP and {_fmt(sl['https_inspected'])} HTTPS decrypted); "
                f"{_fmt(sl['https_not_inspected'])} was HTTPS left encrypted")
    if sl["unknown"]:
        lead += (f" and {_fmt(sl['unknown'])} is unknown, so the real figure is between {_fmt(sp['inspected_pct'])} and "
                 f"{_fmt(sp['inspected_pct_high'])}")
    lead += "."
    if incl and incl.get("text"):
        lead += " " + incl["text"]
    elif out_n:
        lead += f" {out_n} cause{'s' if out_n != 1 else ''} send traffic around ZIA; that traffic is in no figure here."
    return lead


def _bypass_count(out_rows: Iterable[Mapping[str, Any]]) -> int:
    """The causes that send internet web traffic around ZIA (ZPA private
    applications are not internet web traffic: never counted here)."""
    return sum(1 for r in out_rows if r.get("kind") != "zpa_routed")


def including_bypass(unit: str, sp: Optional[Mapping[str, Any]], n_bypass: int, bypass_bytes: Optional[float],
                     bypass_read: bool) -> Optional[Dict[str, Any]]:
    """The share of ALL web traffic that was inspected, with the traffic
    that never reaches ZIA counted as not inspected. `bypass_bytes` is the
    admin's own figure for that traffic (bytes, same period) or None.
    Known only in bytes; otherwise unmeasured, with the ZIA figure as an
    upper bound when a bypass exists. Pure."""
    if not sp:
        return None
    zia_lo, zia_hi = sp["inspected_pct"], sp["inspected_pct_high"]
    rng = (lambda lo, hi: _fmt(lo) if lo == hi else f"between {_fmt(lo)} and {_fmt(hi)}")
    known = bypass_bytes if bypass_bytes is not None and not isinstance(bypass_bytes, bool) and (bypass_bytes == 0 or _num(bypass_bytes)) else None
    if unit == "BYTES" and known is not None:
        amounts = {s["key"]: s["amount"] for s in sp["slices"]}
        amounts["bypassed"] = float(known)
        keys = list(SLICES) + ["bypassed"]
        t = tenths(amounts, keys)
        lo, hi = (t["http"] + t["https_inspected"]) / 10, (t["http"] + t["https_inspected"] + t["unknown"]) / 10
        return {"known": True, "unit": unit, "inspected_pct": lo, "inspected_pct_high": hi, "bypassed_pct": t["bypassed"] / 10,
                "bypassed_amount": float(known), "basis": "your figure for the traffic that bypasses ZIA, counted as not inspected",
                "text": (f"Including the traffic that never reaches ZIA (your figure, counted as not inspected): {rng(lo, hi)} of all web "
                         f"{UNIT_LABEL[unit]}.")}
    if not bypass_read:
        return {"known": False, "unit": unit, "upper_pct": None, "inspected_pct": None,
                "text": ("Including the traffic that never reaches ZIA: not known. Client Connector and PAC settings were not read "
                         "(tick ZCC on the Scope page), so traffic sent around ZIA could not be looked for.")}
    if not n_bypass:
        return {"known": True, "unit": unit, "inspected_pct": zia_lo, "inspected_pct_high": zia_hi, "bypassed_pct": 0.0, "bypassed_amount": None,
                "basis": "no setting read sends web traffic around ZIA",
                "text": "No Client Connector, PAC or forwarding setting read here sends web traffic around ZIA, so this is also the share of all web traffic."}
    return {"known": False, "unit": unit, "upper_pct": zia_hi, "inspected_pct": None,
            "text": (f"Including the traffic that never reaches ZIA: not measured. It is at most {_fmt(zia_hi)} of "
                     f"{'all of a typical traffic mix' if unit == 'MIX' else 'all web ' + UNIT_LABEL[unit]}, lower by an amount ZIA cannot see "
                     f"({n_bypass} bypass{'es' if n_bypass != 1 else ''} below)."
                     + ("" if unit == "MIX" else " Enter the bypassed volume from your firewall or egress logs to count it."))}


def _public(sp: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    return {k: v for k, v in sp.items() if not k.startswith("_")} if sp else None


def build(causes: List[Mapping[str, Any]], classes: List[Mapping[str, Any]], volume: Optional[Mapping[str, Any]] = None,
          logs: Optional[Mapping[str, Any]] = None, *, zpa_in_scope: bool = False, no_volume_reason: str = "",
          bypass_bytes: Optional[float] = None, bypass_read: bool = True) -> Dict[str, Any]:
    """The true-coverage block of an SSL coverage report. `volume` is
    ssl_coverage.read_volume's answer (or None), `logs` is
    {"ssl": traffic_logs zia_web ssl section, "period": {first, last},
    "records": n, "report_id": id} (or None). `bypass_bytes` is the
    admin's figure for web traffic that never reaches ZIA (or None);
    `bypass_read` says whether Client Connector and PAC settings were read. Pure."""
    out_rows = outside(causes, zpa_in_scope)
    n_bypass = _bypass_count(out_rows)
    if bypass_bytes is not None and (isinstance(bypass_bytes, bool) or not (_num(bypass_bytes) or bypass_bytes == 0)):
        bypass_bytes = None
    notes: List[str] = []
    ssl = (logs or {}).get("ssl") if isinstance((logs or {}).get("ssl"), Mapping) else None
    ins = None
    if volume and volume.get("available") is not False and isinstance(volume.get("protocols"), Mapping):
        ins = {u: unit_split(from_protocols(volume["protocols"].get(u))) if volume["protocols"].get(u) else None for u in UNITS}
        if not any(ins.values()):
            ins = None
    lg = {u: unit_split(from_logs(ssl, u)) for u in UNITS} if ssl else None
    if lg and not any(lg.values()):
        lg = None
        notes.append("The uploaded logs hold no ZIA web traffic with an inspection status, so they were not used.")
    if lg:
        per = attribute_logs(ssl, causes, lg)
        period = (logs or {}).get("period") or {}
        window = f"your uploaded logs, {period.get('first') or '?'} to {period.get('last') or '?'}"
        mode, source, split = "measured", "logs", lg
        source_label = "Measured: ZIA NSS web logs you uploaded (each line says whether it was decrypted)"
        if ins:
            notes.append("ZIA Insights for the chosen window gives "
                         + "; ".join(f"{_fmt(ins[u]['inspected_pct'])} by {UNIT_LABEL[u]}" for u in UNITS if ins.get(u))
                         + ". The figure above is from your logs, which cover only their own time span and sources.")
        if not lg.get("BYTES"):
            notes.append("The logs carry no request or response sizes, so there is no split by bytes.")
    elif ins:
        per = attribute_insights(causes, ins)
        w = (volume or {}).get("window") or {}
        window = str(w.get("label") or "")
        mode, source, split = "measured", "insights", ins
        source_label = "Measured: ZIA Insights web traffic by protocol (tenant-wide)"
        notes.append(sc.PROTOCOL_NOTE)
        if per.get("capped"):
            notes.append("The exempted applications' Shadow IT bytes add up to more than the not-inspected HTTPS, so their shares were scaled down to fit it.")
        notes.append("The split by cause is in bytes only: Insights has no per-rule or per-category traffic. Upload NSS web logs for a split of every line.")
        for u in UNITS:
            if not ins.get(u):
                notes.append(f"Traffic by protocol in {UNIT_LABEL[u]} could not be read, so there is no split by {UNIT_LABEL[u]}.")
    else:
        est = estimate(classes, causes)
        if not est:
            return {"mode": "none", "source": "none", "source_label": "No traffic numbers and no SSL rule decision to estimate from",
                    "units": {}, "causes": [], "unattributed": None, "outside": out_rows, "needs": NEEDS, "notes": notes,
                    "headline": "Coverage cannot be given: no traffic numbers were read and the SSL rules decide no kind of traffic.",
                    "window": "", "estimate": True}
        sp = est["split"]
        incl = including_bypass("MIX", sp, n_bypass, None, bypass_read)
        return {"mode": "estimate", "including_bypass": {"MIX": incl}, "source": "policy", "estimate": True,
                "source_label": "Estimate from your SSL rules and a typical traffic mix: not measured",
                "window": "", "units": {"MIX": _public(sp)}, "primary_unit": "MIX", "causes": est["causes"], "unattributed": None,
                "outside": out_rows, "needs": NEEDS, "why_estimate": no_volume_reason,
                "assumed_mix": {"http_pct": ASSUMED_HTTP_PCT, "https_by_kind_pct": dict(ASSUMED_MIX)},
                "notes": notes + ["The typical mix is this app's assumption, not your traffic. Rules for some users only are not counted."],
                "headline": _headline("estimate", "MIX", sp, "", len(out_rows), incl)}
    primary = "BYTES" if split.get("BYTES") else "TRANSACTIONS"
    incl = {u: including_bypass(u, split.get(u), n_bypass, bypass_bytes, bypass_read) for u in UNITS}
    if bypass_bytes is not None and not split.get("BYTES"):
        notes.append("Your figure for traffic that bypasses ZIA is in bytes, and this source has no split by bytes, so it could not be counted.")
    return {"mode": mode, "including_bypass": incl, "source": source, "source_label": source_label, "estimate": False, "window": window,
            "units": {u: _public(split.get(u)) for u in UNITS}, "primary_unit": primary,
            "causes": per["causes"], "unattributed": per.get("unattributed"), "outside": out_rows, "needs": None, "notes": notes,
            "headline": _headline(mode, primary, split[primary], window, len(out_rows), incl.get(primary))}
