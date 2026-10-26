"""Benchmarks: how an assessment stacks up against Zscaler's best practices,
the compliance frameworks and the data-governance journey.

The assessment checks already carry Zscaler's guidance inline ("… Best
Practice: <what Zscaler recommends>. Ref: <help article>"); the DLP
programme checklist (sections 1-12, channels A/B/E, multi-channel) is the
practitioner benchmark. This module turns that into numbers a customer
can be measured against:

* Zscaler Best Practices — every check that states a best practice, per
  area (ZIA policy, ZCC, ZPA, GenAI, admin, automation, ZDX, ZIdentity),
  with the deviations and the article to read.
* DLP programme — the twelve-step DLP checklist and the channel
  benchmarks (inline web, endpoint, GenAI, multi-channel) as stages.
* Frameworks — compliance_mapping's control alignment per framework.
* Journey — the baseline-pack ladder, when the assessment measured it.

Every function is pure (results in, dict out) so the Word report, the
API and the page share one computation."""
from __future__ import annotations

import md_safe
import re
from typing import Any, Dict, List, Optional

import compliance_mapping as cm
from report_docx import _BP_FALLBACKS, _parse_detail_for_bp

try:
    from zscaler_best_practices import lookup_by_topic
except Exception:  # noqa: BLE001
    def lookup_by_topic(_topic):  # type: ignore[misc]
        return {}

_REF_RE = re.compile(r"\bRef(?:erence)?\s*[:]\s*(https?://\S+)", re.IGNORECASE)

# Section prefix -> benchmark area. The DLP checklist sections are numbered
# ("4 — SSL Policy"), the channel benchmarks lettered ("Ch.A — Inline Web"),
# the platform checks named by product ("ZIA — Firewall").
AREAS = [
    ("ZIA policy", ("ZIA —",)),
    ("Client Connector", ("ZCC —", "1 —", "2 —", "3 —", "6 —", "10 —")),
    ("SSL inspection", ("4 —", "7 —", "GenAI — SSL")),
    ("DLP programme", ("5 —", "8 —", "9 —", "11 —", "12 —", "Multi-Channel", "Ch.A", "Ch.B")),
    ("GenAI governance", ("GenAI", "Ch.E")),
    ("Private access (ZPA)", ("ZPA —",)),
    ("Administration & RBAC", ("RBAC", "ZIdentity")),
    ("Automation", ("Automation",)),
    ("Digital experience (ZDX)", ("ZDX",)),
]

# The DLP programme benchmark: the checklist sections as stages, in order.
DLP_PROGRAMME = [
    ("Foundation", ["1 —", "2 —", "3 —", "6 —"], "Client Connector portal, bypass inventory, app profile and versions in order"),
    ("Visibility", ["4 —", "7 —", "Ch.A"], "SSL inspection decrypts what matters and inline web DLP sees it"),
    ("Coverage", ["5 —", "Ch.B", "Multi-Channel", "Ch.E"], "Endpoint, SaaS, email and GenAI channels carry the same policy"),
    ("Operation", ["8 —", "9 —", "10 —", "11 —"], "Pilot tests, troubleshooting, macOS and rollback are rehearsed"),
    ("Response", ["12 —"], "Incidents are notified, triaged and measured"),
]


def area_of(section: str) -> str:
    s = section or ""
    for area, prefixes in AREAS:
        if any(s.startswith(p) or p in s for p in prefixes):
            return area
    return "Other"


def best_practice_of(check: Dict[str, Any]) -> Dict[str, Any]:
    """The guidance a check states, or the closest curated fallback.
    Returns {text, reference, inline} — inline=True when the check itself
    carried the guidance (the stronger evidence)."""
    detail = str(check.get("detail") or "")
    _as_is, bp = _parse_detail_for_bp(detail)
    m = _REF_RE.search(detail)
    ref = m.group(1).rstrip(".,);") if m else ""
    if bp:
        return {"text": bp, "reference": ref, "inline": True}
    hay = " ".join((str(check.get("label") or ""), str(check.get("section") or check.get("sec") or ""), str(check.get("id") or ""))).lower()
    for needle, text, fallback_url in _BP_FALLBACKS:
        if needle in hay:
            url = (lookup_by_topic(needle) or {}).get("url") or fallback_url
            return {"text": text, "reference": url, "inline": False}
    return {"text": "", "reference": "", "inline": False}


def annotate(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Add area, best_practice and reference to each check (new dicts)."""
    out = []
    for r in results:
        bp = best_practice_of(r)
        row = dict(r)
        row["area"] = area_of(str(r.get("section") or r.get("sec") or ""))
        row["best_practice"] = bp["text"]
        row["reference"] = bp["reference"]
        row["best_practice_inline"] = bp["inline"]
        out.append(row)
    return out


def _pct(n: int, d: int) -> Optional[int]:
    """A share of measured checks; None (not measured) when nothing was measured, never 100."""
    return round(n / d * 100) if d else None


def _pct_text(p: Optional[int]) -> str:
    return "n/a" if p is None else f"{p}%"


def best_practice_benchmark(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Alignment with Zscaler's stated best practices, per area. A check
    counts when it is scored (PASS / FAIL / REVIEW); INFO checks are
    'not measured'. A FAIL or REVIEW on a check that states a best practice
    is a deviation, listed with the guidance and the article."""
    rows = annotate(results)
    areas: Dict[str, Dict[str, Any]] = {}
    for r in rows:
        a = areas.setdefault(r["area"], {"area": r["area"], "checks": 0, "measured": 0, "aligned": 0, "deviations": 0, "not_measured": 0, "gaps": []})
        a["checks"] += 1
        st = r.get("status")
        if st == "PASS":
            a["measured"] += 1; a["aligned"] += 1
        elif st in ("FAIL", "REVIEW"):
            a["measured"] += 1; a["deviations"] += 1
            a["gaps"].append({"id": r.get("id"), "label": r.get("label"), "status": st, "section": r.get("section") or r.get("sec"),
                              "best_practice": r["best_practice"], "reference": r["reference"], "inline": r["best_practice_inline"],
                              "finding": _parse_detail_for_bp(str(r.get("detail") or ""))[0][:240]})
        else:
            a["not_measured"] += 1
    order = [a for a, _ in AREAS] + ["Other"]
    out_areas = []
    for name in order:
        a = areas.get(name)
        if not a:
            continue
        a["pct"] = _pct(a["aligned"], a["measured"])
        a["gaps"].sort(key=lambda g: (0 if g["status"] == "FAIL" else 1, 0 if g["inline"] else 1, str(g["id"])))
        a["grade"] = grade(a["pct"]) if a["measured"] else "n/a"
        out_areas.append(a)
    measured = sum(a["measured"] for a in out_areas)
    aligned = sum(a["aligned"] for a in out_areas)
    return {"pct": _pct(aligned, measured), "grade": grade(_pct(aligned, measured)) if measured else "n/a",
            "measured": measured, "aligned": aligned, "deviations": measured - aligned,
            "not_measured": sum(a["not_measured"] for a in out_areas), "areas": out_areas}


def grade(pct: int) -> str:
    return "A" if pct >= 90 else "B" if pct >= 75 else "C" if pct >= 60 else "D" if pct >= 40 else "F"


def dlp_programme_benchmark(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """The DLP checklist as a five-stage programme: each stage is the share
    of its scored checks that pass; the stage reached is the last stage at
    or above 75% with every earlier stage also there."""
    stages = []
    reached = 0
    blocked = False
    for i, (name, prefixes, what) in enumerate(DLP_PROGRAMME, 1):
        rs = [r for r in results if any(str(r.get("section") or r.get("sec") or "").startswith(p) for p in prefixes)]
        measured = [r for r in rs if r.get("status") in ("PASS", "FAIL", "REVIEW")]
        passed = [r for r in measured if r.get("status") == "PASS"]
        pct = _pct(len(passed), len(measured))
        met = pct is not None and pct >= 75
        if met and not blocked:
            reached = i
        elif measured:
            blocked = True
        stages.append({"n": i, "name": name, "what": what, "checks": len(rs), "measured": len(measured), "passed": len(passed),
                       "pct": pct if measured else None, "met": met,
                       "todo": [{"id": r.get("id"), "label": r.get("label"), "status": r.get("status")} for r in measured if r.get("status") != "PASS"][:8]})
    measured_any = any(s["measured"] for s in stages)
    return {"stage": reached, "stages": stages, "stage_name": DLP_PROGRAMME[reached - 1][0] if reached else "Not started",
            "applicable": measured_any}


def frameworks_benchmark(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Framework alignment rows, sorted by alignment (weakest first)."""
    summary = cm.get_framework_summary(results)
    rows = []
    for key, s in summary.items():
        rows.append({"key": key, "name": s["name"].split(" — ")[0], "full_name": s["name"], "status": s["status"],
                     "alignment_pct": s["alignment_pct"], "scored": s.get("scored_count", 0), "controls": s["control_count"], "passing": s["passing_count"],
                     "failing": s["failing_count"], "review": s["review_count"]})
    # Weakest first; a framework with nothing scoreable (pct None) goes last.
    rows.sort(key=lambda r: (r["alignment_pct"] is None, r["alignment_pct"] or 0, r["name"]))
    return rows


def benchmark_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Everything the Benchmarks card shows, from an assessment report
    (the `complete` event payload or a saved JSON)."""
    import channel_scope
    results, _ = channel_scope.visible(report.get("checks") or [])   # a check outside the selected scope is hidden
    journey = report.get("journey") if isinstance(report.get("journey"), dict) else None
    j = None
    if journey and journey.get("status") not in (None, "pending", "error"):
        j = {"status": journey.get("status"), "stage": journey.get("stage"), "score": journey.get("score"),
             "baselines": [{"name": b.get("name"), "stage": b.get("stage"), "stage_name": b.get("stage_name"), "score": b.get("score"), "state": b.get("state"),
                            "secure_by_design": b.get("secure_by_design")}
                           for b in (journey.get("baselines") or [])]}
    elif journey and journey.get("status") == "pending":
        j = {"status": "pending"}
    return {
        "score": report.get("score"), "maturity": report.get("maturity"),
        "best_practices": best_practice_benchmark(results),
        "dlp_programme": dlp_programme_benchmark(results),
        "frameworks": frameworks_benchmark(results),
        "journey": j,
    }


def to_markdown(b: Dict[str, Any], org: str = "") -> str:
    b, org = md_safe.escape_data(b), md_safe.text(org)   # findings name tenant objects; org is typed in: inert text
    bp = b["best_practices"]
    lines = [f"# Benchmark alignment{' — ' + org if org else ''}", "",
             f"Assessment score {_pct_text(b.get('score'))} ({b.get('maturity') or 'Not assessed'}). Zscaler best-practice alignment {_pct_text(bp['pct'])} (grade {bp['grade']}): "
             f"{bp['aligned']} of {bp['measured']} measured checks aligned, {bp['deviations']} deviations, {bp['not_measured']} not measured.", "",
             "## Zscaler best practices by area", "", "| Area | Aligned | Measured | Alignment | Grade |", "|---|---|---|---|---|"]
    for a in bp["areas"]:
        lines.append(f"| {a['area']} | {a['aligned']} | {a['measured']} | {_pct_text(a['pct'])} | {a['grade']} |")
    lines += ["", "## Deviations from best practice", ""]
    for a in bp["areas"]:
        for g in a["gaps"]:
            lines.append(f"- **[{g['id']}] {g['label']}** ({g['status']}, {a['area']}): {g['finding']} Best practice: {g['best_practice'] or 'see reference'}"
                         + (f" Ref: {g['reference']}" if g["reference"] else ""))
    p = b["dlp_programme"]
    lines += ["", f"## DLP programme: stage {p['stage']} of {len(p['stages'])} ({p['stage_name']})", ""]
    for s in p["stages"]:
        lines.append(f"- {'✓' if s['met'] else '✗'} {s['n']}. {s['name']} — {s['what']}: {s['passed']}/{s['measured']} ({s['pct'] if s['pct'] is not None else 'n/a'}%)")
    lines += ["", "## Frameworks", "", "| Framework | Alignment | Status | Controls | Failing |", "|---|---|---|---|---|"]
    for f in b["frameworks"]:
        lines.append(f"| {f['name']} | {'n/a' if f['alignment_pct'] is None else str(f['alignment_pct']) + '%'} | {f['status']} | {f['controls']} | {f['failing']} |")
    if b.get("journey") and b["journey"].get("status") not in (None, "pending"):
        j = b["journey"]
        lines += ["", f"## Data governance journey: stage {j.get('stage')} of 5, {j.get('score')}%", ""]
        for x in j.get("baselines") or []:
            lines.append(f"- {x['name']}: stage {x['stage']} ({x['stage_name']}), {x['score']}%")
    return "\n".join(lines) + "\n"
