#!/usr/bin/env python3
"""Posture plus: the score explains itself and says what to do next.

Pure computation on an assessment's results and the tenant profile's
history. Nothing here reads or writes a tenant.

1. ranking()     For every failing check (Action required or Needs review):
                 how many points fixing it adds to the overall score, the
                 effort, whether a one-click fix recipe exists in Review &
                 remediate (remediation.py) and the plain-English steps.
2. project()     The score after a set of fixes: the checks the user ticks
                 and/or the fix recipes staged in the team change queue.
3. trend()       The score over the profile's past assessments and, between
                 consecutive runs, which checks started or stopped failing.
4. score_drop()  The alert when a score fell by at least the threshold
                 (settings(): default 5 points), for the digest and the
                 banner on the main page.
5. coverage()    What the assessment could NOT check and why, normalised to
                 one list (area, what, why, how to fix) with "N% of checks
                 ran".

The score is the engine's own (dlp_assessment_full_auto.compute, see
docs/SCORING.md): configured / (configured + action required + needs
review), rounded. Every "points" number here is that function run twice,
before and after, never an estimate. Under that formula every scoreable
check weighs the same, so fixing any one failing check adds the same
number of points (up to rounding); the ranking then prefers the fix that
costs the least (effort), has a one-click recipe, and lifts the weakest
section most. A recipe that answers several failing checks is also shown
as a bundle with its combined points.

Effort. The remediation recipes carry no effort field, so it is a
documented heuristic (effort_for):
  low     a one-click recipe exists in Review & remediate, or the check is
          Needs review (the setting exists; a person confirms or adjusts it);
  high    the check is about a process, people or another system (pilot
          tests, rollback, troubleshooting, bypass register, reports,
          SIEM / ITSM integration, reviews, cadence, evidence storage);
  medium  everything else: a policy or Client Connector setting to change in
          the admin portal (device settings then roll out to devices).
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

import safe_files

SCORED = ("PASS", "FAIL", "REVIEW")
FAILING = ("FAIL", "REVIEW")
STATE_CODES = {"PASS": "P", "FAIL": "F", "REVIEW": "R", "INFO": "I", "ERROR": "E"}
CODE_STATES = {v: k for k, v in STATE_CODES.items()}
CODE_WORDS = {"P": "configured", "F": "action required", "R": "needs review", "I": "not configured (informational)",
              "E": "could not be checked"}
# A history entry keeps at most this many check states (the registry has
# about 400 checks; one entry is a few kilobytes at most).
MAX_STATES = 1200
DEFAULT_DROP_POINTS = 5
EFFORT_RANK = {"low": 0, "medium": 1, "high": 2}

_APP_DIR = os.path.dirname(os.path.abspath(__file__))
_LOCK = threading.Lock()


# ── The score: the engine's formula ─────────────────────────────────────
def _status(c: Dict[str, Any]) -> str:
    return str(c.get("status") or "").upper()


def visible(checks: Iterable[Any]) -> List[Dict[str, Any]]:
    """The checks the score is built on: dicts, without the ones outside the
    selected scope (channel_scope.visible, the same filter the report uses)."""
    rows = [c for c in (checks or []) if isinstance(c, dict)]
    try:
        import channel_scope
        rows, _hidden = channel_scope.visible(rows)
    except Exception:  # noqa: BLE001
        rows = [c for c in rows if not c.get("out_of_scope")]
    return rows


def score_of(checks: Iterable[Dict[str, Any]]) -> Optional[int]:
    """The overall score exactly as the assessment computes it."""
    from dlp_assessment_full_auto import compute
    _secs, overall = compute(visible(checks))
    return overall


def exact_of(checks: Iterable[Dict[str, Any]]) -> Optional[float]:
    """The same ratio before rounding (for ordering only)."""
    rows = visible(checks)
    scored = [c for c in rows if _status(c) in SCORED]
    if not scored:
        return None
    return sum(1 for c in scored if _status(c) == "PASS") / len(scored) * 100


def with_fixed(checks: Iterable[Dict[str, Any]], ids: Iterable[str]) -> List[Dict[str, Any]]:
    """A copy of the results in which the failing checks named in `ids` are
    configured (PASS). Informational, not-permitted and could-not-be-checked
    results are never "fixed": their outcome is unknown until they run."""
    want = {str(i) for i in ids or []}
    out = []
    for c in checks or []:
        if isinstance(c, dict) and str(c.get("id")) in want and _status(c) in FAILING:
            c = dict(c, status="PASS")
        out.append(c)
    return out


def points_for(checks: List[Dict[str, Any]], ids: Iterable[str]) -> Dict[str, Any]:
    """Score before and after fixing `ids`, recomputed with the real formula."""
    before = score_of(checks)
    fixed = with_fixed(checks, ids)
    after = score_of(fixed)
    eb, ea = exact_of(checks), exact_of(fixed)
    return {"before": before, "after": after,
            "points": (after - before) if (before is not None and after is not None) else 0,
            "exact_points": round((ea or 0) - (eb or 0), 3) if eb is not None else 0.0}


def _section(c: Dict[str, Any]) -> str:
    return str(c.get("sec") or c.get("section") or "Other")


def _section_pct(rows: List[Dict[str, Any]], sec: str) -> Optional[int]:
    from dlp_assessment_full_auto import compute
    secs, _ = compute([r for r in rows if _section(r) == sec])
    return (secs.get(sec) or {}).get("pct")


# ── Effort and the fix recipe ───────────────────────────────────────────
_PROCESS_SECTIONS = ("2 —", "8 —", "9 —", "11 —")
_PROCESS_WORDS = re.compile(r"\b(report|review|plan|test|register|cadence|siem|itsm|integration|evidence|comms|staging|"
                            r"correlation|diagnostics|executive|coaching|workflow|justification|retention)\b", re.I)


def _recipes() -> Tuple[Dict[str, Dict[str, Any]], Any]:
    try:
        import remediation
        return {c: remediation.get_recipe(c) for c in remediation.remediable_checks()}, remediation
    except Exception:  # noqa: BLE001
        return {}, None


def effort_for(check: Dict[str, Any], has_recipe: bool) -> Tuple[str, str]:
    """(low | medium | high, the reason in one sentence): see the module docstring."""
    sec = _section(check)
    label = str(check.get("label") or "")
    if has_recipe:
        return "low", "A guided one-click fix exists in Review & remediate: fill in a short form, preview, apply."
    if sec.startswith(_PROCESS_SECTIONS) or _PROCESS_WORDS.search(label):
        return "high", "Needs people, a process or another system, not one setting: plan it with the customer's team."
    if _status(check) == "REVIEW":
        return "low", "The setting exists; a person confirms it or adjusts it in the admin portal."
    return "medium", "A setting to change in the admin portal; Client Connector settings then roll out to devices."


def _steps(check: Dict[str, Any]) -> List[str]:
    """Plain-English steps: the check's own 'what to do' (plain_english),
    split into sentences, then the re-check."""
    plain = check.get("plain") if isinstance(check.get("plain"), dict) else None
    if not plain or not plain.get("do"):
        try:
            import plain_english
            plain = plain_english.explain(check)
        except Exception:  # noqa: BLE001
            plain = {}
    do = re.sub(r"\s+", " ", str((plain or {}).get("do") or "")).strip()
    do = re.sub(r"\.{2,}(?=\s|$)", ".", do)
    parts = [s.strip() for s in re.split(r"(?<=[.!?])\s+(?=[A-Z])", do) if s.strip()][:4]
    if not parts:
        parts = [f"Change {check.get('label') or 'the setting'} to match Zscaler's recommendation in the admin portal."]
    parts.append("Run the assessment again to confirm the check is configured.")
    return parts


_URL = re.compile(r"https://[A-Za-z0-9.-]*zscaler\.(?:com|net)/[^\s)\"'<>]*")


def _guidance_url(check: Dict[str, Any]) -> str:
    m = _URL.search(str(check.get("detail") or ""))
    return m.group(0).rstrip(".,;") if m else ""


# ── 1. Improve my score ────────────────────────────────────────────────
def ranking(checks: List[Dict[str, Any]], limit: int = 10) -> Dict[str, Any]:
    """The fixes that raise the score most, best value first."""
    rows = visible(checks)
    before = score_of(rows)
    failing = [c for c in rows if _status(c) in FAILING]
    recipes, _mod = _recipes()
    by_recipe: Dict[str, List[str]] = {}
    for c in failing:
        r = recipes.get(str(c.get("id")))
        if r:
            by_recipe.setdefault(r["check_id"], []).append(str(c.get("id")))
    sec_pct: Dict[str, Optional[int]] = {}
    out = []
    for c in failing:
        cid = str(c.get("id"))
        pts = points_for(rows, [cid])
        sec = _section(c)
        if sec not in sec_pct:
            sec_pct[sec] = _section_pct(rows, sec)
        sec_after = _section_pct(with_fixed(rows, [cid]), sec)
        recipe = recipes.get(cid)
        effort, effort_why = effort_for(c, bool(recipe))
        also = [x for x in by_recipe.get((recipe or {}).get("check_id", ""), []) if x != cid]
        out.append({
            "id": cid, "label": c.get("label") or cid, "section": sec, "status": _status(c),
            "status_word": "Action required" if _status(c) == "FAIL" else "Needs review",
            "points": pts["points"], "exact_points": pts["exact_points"], "score_after": pts["after"],
            "section_before": sec_pct[sec], "section_after": sec_after,
            "effort": effort, "effort_why": effort_why,
            "one_click": bool(recipe), "recipe": ({"id": recipe["check_id"], "label": recipe["label"]} if recipe else None),
            "also_fixes": also, "steps": _steps(c), "guidance_url": _guidance_url(c),
        })
    out.sort(key=lambda r: (-r["exact_points"], EFFORT_RANK[r["effort"]], not r["one_click"], r["status"] != "FAIL",
                            -((r["section_after"] or 0) - (r["section_before"] or 0)), _natural(r["id"])))
    bundles = []
    for rid, ids in by_recipe.items():
        if len(ids) < 2:
            continue
        p = points_for(rows, ids)
        bundles.append({"recipe": rid, "label": (recipes.get(ids[0]) or {}).get("label") or rid, "checks": ids,
                        "points": p["points"], "score_after": p["after"]})
    bundles.sort(key=lambda b: (-b["points"], b["recipe"]))
    scored = sum(1 for c in rows if _status(c) in SCORED)
    return {"score": before, "failing": len(failing), "scored": scored, "top": out[:max(0, int(limit))], "all": len(out),
            "bundles": bundles,
            "per_check": round(100 / scored, 2) if scored else None,
            "note": ("Every scoreable check weighs the same in the score, so each fix adds about "
                     f"{round(100 / scored, 1) if scored else 0} points. The list puts the cheapest fixes first.")}


def _natural(cid: str) -> List[Any]:
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", str(cid))]


# ── 2. Projected score ─────────────────────────────────────────────────
def queued_fixes(requests: Iterable[Dict[str, Any]], failing_ids: Iterable[str]) -> Dict[str, Any]:
    """Which open change requests (pending or approved) would fix a failing
    check: a fix recipe names its check. A pack deploy or a removal is listed
    but not counted: which checks it turns green is known only after the
    next assessment."""
    failing = {str(i) for i in failing_ids}
    counted, not_counted = [], []
    for r in requests or []:
        if not isinstance(r, dict) or r.get("status") not in ("pending", "approved"):
            continue
        base = {"request": r.get("id"), "title": str(r.get("title") or "")[:200], "status": r.get("status"),
                "tenant": r.get("tenant_label") or r.get("tenant"), "kind": r.get("kind")}
        cid = str(((r.get("payload") or {}).get("check_id")) or "")
        if r.get("kind") == "fix_recipe" and cid in failing:
            counted.append(dict(base, check_id=cid))
        elif r.get("kind") == "fix_recipe":
            not_counted.append(dict(base, check_id=cid, why="its check is not failing in these results"))
        else:
            not_counted.append(dict(base, why="a policy-pack change: which checks it turns green is known after the next assessment"))
    return {"counted": counted, "not_counted": not_counted}


def project(checks: List[Dict[str, Any]], selected: Iterable[str] = (), requests: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """The score after the ticked fixes and the staged fix recipes."""
    rows = visible(checks)
    failing = {str(c.get("id")) for c in rows if _status(c) in FAILING}
    picked = [str(i) for i in selected or [] if str(i) in failing]
    q = queued_fixes(requests, failing)
    ids = sorted(set(picked) | {x["check_id"] for x in q["counted"]}, key=_natural)
    p = points_for(rows, ids)
    from dlp_assessment_full_auto import maturity
    return {"score": p["before"], "projected": p["after"], "points": p["points"], "maturity": maturity(p["before"]),
            "projected_maturity": maturity(p["after"]), "fixed": ids, "selected": picked, "queue": q,
            "ignored": sorted({str(i) for i in selected or []} - failing)}


# ── 3. History: per-check states and the trend ─────────────────────────
def states_of(checks: Iterable[Dict[str, Any]]) -> Dict[str, str]:
    """{check id: P|F|R|I|E} for a history entry, bounded to MAX_STATES."""
    out: Dict[str, str] = {}
    for c in visible(checks):
        cid = str(c.get("id") or "")
        if cid and len(out) < MAX_STATES:
            out[cid[:32]] = STATE_CODES.get(_status(c), "I")
    return out


def assessments(history: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """The history entries that are assessments (they carry `score`); the
    continuous evaluation's own entries (journey, detection health) are not."""
    return [e for e in (history or []) if isinstance(e, dict) and "score" in e]


def _labels(extra: Iterable[Dict[str, Any]] = ()) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for mod, attr in (("dlp_assessment_full_auto", "REG"), ("zscaler_full_checks", "PLATFORM_REG")):
        try:
            for row in getattr(__import__(mod), attr):
                out[str(row[0])] = str(row[2])
        except Exception:  # noqa: BLE001
            continue
    for c in extra or []:
        if isinstance(c, dict) and c.get("id"):
            out[str(c["id"])] = str(c.get("label") or c["id"])
    return out


def diff(prev: Dict[str, Any], cur: Dict[str, Any], labels: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    """What changed between two assessment entries: score change and the
    checks that became failing or passing. `recorded` is False when either
    entry predates per-check states (an older record)."""
    labels = labels or {}
    ps, cs = prev.get("score"), cur.get("score")
    delta = (cs - ps) if (isinstance(ps, (int, float)) and isinstance(cs, (int, float))) else None
    a, b = prev.get("states"), cur.get("states")
    out: Dict[str, Any] = {"from": prev.get("at"), "to": cur.get("at"), "score_from": ps, "score_to": cs, "delta": delta,
                           "recorded": isinstance(a, dict) and isinstance(b, dict),
                           "newly_failing": [], "newly_passing": [], "other": []}
    if not out["recorded"]:
        out["sentence"] = sentence(out)
        return out
    for cid in sorted(set(a) | set(b), key=_natural):
        x, y = a.get(cid), b.get(cid)
        if x == y:
            continue
        row = {"id": cid, "label": labels.get(cid, cid), "from": CODE_WORDS.get(x, "not run"), "to": CODE_WORDS.get(y, "not run")}
        if y in ("F", "R") and x not in ("F", "R"):
            out["newly_failing"].append(row)
        elif y == "P" and x != "P":
            out["newly_passing"].append(row)
        else:
            out["other"].append(row)
    out["sentence"] = sentence(out)
    return out


def sentence(d: Dict[str, Any]) -> str:
    """'Your score dropped 6 points because these 3 checks started failing.'"""
    delta = d.get("delta")
    nf, np_ = len(d.get("newly_failing") or []), len(d.get("newly_passing") or [])
    if delta is None:
        return "No score to compare: one of the two runs had nothing scoreable."
    move = (f"Your score dropped {-delta} point{'s' if -delta != 1 else ''}" if delta < 0 else
            f"Your score rose {delta} point{'s' if delta != 1 else ''}" if delta > 0 else "Your score stayed the same")
    if not d.get("recorded"):
        return move + "; which checks changed was not recorded for the older run."
    bits = []
    if nf:
        bits.append(f"{'this check' if nf == 1 else f'these {nf} checks'} started failing")
    if np_:
        bits.append(f"{'this check' if np_ == 1 else f'these {np_} checks'} started passing")
    if not bits:
        return move + ("; no check changed between pass and fail (the number of scoreable checks changed)." if delta else ".")
    return move + " because " + " and ".join(bits) + "."


def trend(history: Iterable[Dict[str, Any]], current: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """The score over time and the causes between consecutive runs."""
    runs = assessments(history)
    labels = _labels(current)
    points = [{"at": e.get("at"), "score": e.get("score"), "maturity": e.get("maturity"), "checks": e.get("checks"),
               "critical": e.get("critical"), "recorded": isinstance(e.get("states"), dict)} for e in runs]
    changes = [diff(runs[i - 1], runs[i], labels) for i in range(1, len(runs))]
    return {"points": points, "changes": list(reversed(changes)), "runs": len(runs)}


# ── 4. Score-drop alerts ───────────────────────────────────────────────
def settings_path() -> str:
    """posture_settings.json beside the proposals store (DLPCHECK_PROPOSALS_FILE's
    folder: the app folder on a local install, /data in the read-only
    container), or DLP_CHECK_POSTURE_SETTINGS."""
    env = os.environ.get("DLP_CHECK_POSTURE_SETTINGS")
    if env:
        return env
    try:
        import proposals
        folder = os.path.dirname(os.path.abspath(proposals.store_path()))
    except Exception:  # noqa: BLE001
        folder = _APP_DIR
    return os.path.join(folder, "posture_settings.json")


def settings() -> Dict[str, Any]:
    """{score_drop_points (default 5), notify_score_drop (default False)}.
    notify_score_drop off: a drop is listed in the digest and on the main
    page but never, by itself, makes the digest send anything."""
    data: Dict[str, Any] = {}
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f) or {}
    except Exception:  # noqa: BLE001
        data = {}
    return normalise_settings(data)


def normalise_settings(data: Dict[str, Any]) -> Dict[str, Any]:
    try:
        pts = int(float((data or {}).get("score_drop_points", DEFAULT_DROP_POINTS)))
    except (TypeError, ValueError):
        pts = DEFAULT_DROP_POINTS
    return {"score_drop_points": max(1, min(100, pts)), "notify_score_drop": (data or {}).get("notify_score_drop") is True}


def save_settings(data: Dict[str, Any]) -> Dict[str, Any]:
    clean = normalise_settings(data)
    p = settings_path()
    with _LOCK:
        safe_files.private_makedirs(os.path.dirname(os.path.abspath(p)) or ".")
        fd, tmp = tempfile.mkstemp(prefix=".posture-", dir=os.path.dirname(os.path.abspath(p)) or ".")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(clean, f, indent=1)
            os.replace(tmp, p)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
    return clean


def score_drop(prev_score: Any, cur_score: Any, threshold: Optional[int] = None) -> Optional[int]:
    """The points lost when the score fell by at least `threshold`, else None."""
    t = settings()["score_drop_points"] if threshold is None else int(threshold)
    if not isinstance(prev_score, (int, float)) or not isinstance(cur_score, (int, float)):
        return None
    lost = prev_score - cur_score
    return int(lost) if lost >= t else None


def latest_drop(history: Iterable[Dict[str, Any]], threshold: Optional[int] = None,
                current: Iterable[Dict[str, Any]] = ()) -> Optional[Dict[str, Any]]:
    """The assessment-score drop between the last two assessments, or None."""
    runs = assessments(history)
    if len(runs) < 2:
        return None
    lost = score_drop(runs[-2].get("score"), runs[-1].get("score"), threshold)
    if lost is None:
        return None
    d = diff(runs[-2], runs[-1], _labels(current))
    return {"kind": "assessment", "what": "Assessment score", "points": lost, "from": runs[-2].get("score"), "to": runs[-1].get("score"),
            "at": runs[-1].get("at"), "previous_at": runs[-2].get("at"), "sentence": d.get("sentence") or sentence(d),
            "newly_failing": d.get("newly_failing")[:20] if d.get("recorded") else [], "recorded": d.get("recorded")}


def tenant_alerts(tenant: Dict[str, Any], history: Iterable[Dict[str, Any]], *, cfg: Optional[Dict[str, Any]] = None,
                  seen: Iterable[Tuple[str, str]] = ()) -> List[Dict[str, Any]]:
    """The score-drop alerts for one tenant of a continuous-evaluation run:
    the data-governance journey score this run measured against the one
    recorded before it, and the latest assessment score against the one
    before, each only once (`seen`: (kind, at) pairs an earlier digest
    already reported)."""
    cfg = cfg or settings()
    t = cfg["score_drop_points"]
    seen = {tuple(x) for x in seen or []}
    out = []
    a = latest_drop(history, t)
    if a and ("assessment", str(a["at"])) not in seen:
        out.append(a)
    dr = (tenant or {}).get("drift") or {}
    lost = score_drop(dr.get("previous_score"), dr.get("score"), t)
    if lost is not None:
        out.append({"kind": "journey", "what": "Data governance journey score", "points": lost, "from": dr.get("previous_score"),
                    "to": dr.get("score"), "at": dr.get("measured_at"),
                    "sentence": f"The journey score dropped {lost} points: a pack's rules were removed, disabled or relaxed since the last measurement."})
    for x in out:
        x["threshold"] = t
        x["notify"] = bool(cfg.get("notify_score_drop"))
    return out


# ── 5. Analysis health: what could not be checked ──────────────────────
_ENDPOINT = re.compile(r"(/(?:zia|zcc|zpa|zdx|zid)/[A-Za-z0-9_/{}.-]+)")
CATEGORIES = {
    "permission": "Not permitted to the API client",
    "rate_limit": "Rate limited by ZIA",
    "timeout": "No answer in time",
    "unavailable": "Zscaler API unavailable",
    "sign_in": "Not available with this sign-in",
    "not_licensed": "Feature not licensed or not available",
    "scope": "Left out by the Scope page",
    "capped": "Only part of a list was read",
    "error": "The check itself failed",
}


def _why_of(detail: str) -> str:
    """The category of one 'could not' text (a check detail or a log line)."""
    d = str(detail or "")
    low = d.lower()
    try:
        from permissions import is_denied
        denied = is_denied(d)
    except Exception:  # noqa: BLE001
        denied = bool(re.search(r"\b40[13]\b|forbidden|unauthorized|access denied", d, re.I))
    if denied:
        return "permission"
    if "classic zia api" in low:
        return "sign_in"
    if "429" in d or "rate limit" in low or "rate-limit" in low or "resource access blocked" in low:
        return "rate_limit"
    if "timed out" in low or "timeout" in low or "no answer" in low:
        return "timeout"
    if re.search(r"\b50[234]\b", d) or "unavailable (http" in low:
        return "unavailable"
    if "not selected" in low or "not in scope" in low or "outside the selected scope" in low:
        return "scope"
    if re.search(r"\bcapped\b|\bcap of\b|only the first \d+|more than \d+ .* not (shown|read)", low):
        return "capped"
    if "not licensed" in low or "404" in d or "not available" in low or "not accessible" in low:
        return "not_licensed"
    return "error"


def _fix_for(cat: str, section: str, endpoint: str = "") -> str:
    if cat == "permission":
        perm = ""
        try:
            import permissions
            if endpoint:
                perm = permissions.permission_for_endpoint(endpoint).get("permission", "")
            if not perm:
                from scope_permissions import SCOPE_PERMISSIONS
                sp = SCOPE_PERMISSIONS.get(permissions.scope_of_section(section)) or {}
                perm = ", ".join((sp.get("permissions_read") or [])[:4])
        except Exception:  # noqa: BLE001
            perm = ""
        what = (f"the {perm} read permission{'s' if ',' in perm else ''}") if perm else "a role that can read this area"
        return f"Give the API client {what} (ZIdentity > API Clients > role), then run the assessment again."
    return {
        "rate_limit": "Run the assessment again later, when no other job reads the tenant; the app waits for ZIA's rate limit but gives up on a long hold.",
        "timeout": "Run the assessment again; if it repeats, check the network path from this computer to the Zscaler API.",
        "unavailable": "Zscaler answered that the service was busy. Run the assessment again later.",
        "sign_in": "Sign in with a ZIdentity API client (OneAPI) to cover ZPA, Client Connector and ZDX as well as ZIA.",
        "not_licensed": "Nothing to fix if the customer does not own this feature; otherwise check the subscription with Zscaler.",
        "scope": "Tick the channel or the scope on the Scope page if Zscaler should cover it, then run the assessment again.",
        "capped": "Narrow what is read (fewer channels or one policy type at a time) to see the rest.",
        "error": "Run the assessment again; if it repeats, open Technical detail on the finding and report it.",
    }.get(cat, "Run the assessment again.")


def coverage(report: Dict[str, Any], logs: Iterable[str] = ()) -> Dict[str, Any]:
    """What the assessment could not check, normalised: one row per
    (category, area) with the checks, why and how to fix; and the share of
    checks that ran and got an answer ("Coverage: 87% of checks ran").

    Sources: the check results (not permitted, could not be checked, not
    licensed), the checks hidden by the Scope page (channel_coverage /
    hidden_checks) and, optionally, log lines a reader wrote (`logs`:
    skipped, refused, capped, timed out)."""
    report = report or {}
    rows = visible(report.get("checks") or [])
    groups: Dict[Tuple[str, str], Dict[str, Any]] = {}
    not_ran = 0
    for c in rows:
        st = _status(c)
        if st not in ("INFO", "ERROR"):
            continue
        detail = str(c.get("detail") or "")
        cat = _why_of(detail)
        if st == "INFO" and cat == "error":
            continue   # an informational result that ran and answered: not a coverage gap
        if cat != "not_licensed":
            not_ran += 1
        sec = _section(c)
        m = _ENDPOINT.search(detail)
        ep = m.group(1) if m else ""
        key = (cat, sec)
        g = groups.setdefault(key, {"category": cat, "category_label": CATEGORIES[cat], "area": sec, "checks": [], "endpoints": [],
                                    "why": _first(detail, c.get("label")), "fix": _fix_for(cat, sec, ep)})
        g["checks"].append({"id": c.get("id"), "label": c.get("label")})
        if ep and ep not in g["endpoints"]:
            g["endpoints"].append(ep)
    # The Scope page: per channel left to another product or as a gap.
    cc = report.get("channel_coverage") or {}
    scoped = 0
    for kind, word in (("alternative", "covered by another product"), ("gaps", "not ticked (a gap)")):
        for ch in cc.get(kind) or []:
            n = int(ch.get("checks_not_in_scope") or 0)
            if n:
                scoped += n
                groups[("scope", str(ch.get("name")))] = {
                    "category": "scope", "category_label": CATEGORIES["scope"], "area": str(ch.get("name") or ch.get("id")),
                    "checks": [], "count": n, "endpoints": [],
                    "why": f"The Scope page marks {ch.get('name') or ch.get('id')} as {word}, so its {n} check{'s' if n != 1 else ''} did not run.",
                    "fix": _fix_for("scope", "")}
    hidden = int(report.get("hidden_checks") or cc.get("hidden") or 0)
    if hidden > scoped:
        n = hidden - scoped
        groups[("scope", "Other scopes")] = {"category": "scope", "category_label": CATEGORIES["scope"], "area": "Selected scopes",
                                             "checks": [], "count": n, "endpoints": [],
                                             "why": f"{n} check{'s are' if n != 1 else ' is'} outside the selected scope.", "fix": _fix_for("scope", "")}
    # Log lines a reader wrote.
    for line in list(logs or [])[:2000]:
        s = re.sub(r"\s+", " ", str(line or "")).strip()[:300]
        if not s or not re.search(r"skipp|refus|capped|cap of|could not|not in scope|timed out|429|40[13]|only the first", s, re.I):
            continue
        cat = _why_of(s)
        area = _log_area(s)
        g = groups.setdefault((cat, area), {"category": cat, "category_label": CATEGORIES[cat], "area": area, "checks": [], "endpoints": [],
                                            "why": s, "fix": _fix_for(cat, area, _endpoint_of(s)),
                                            "log_lines": 0})
        g["log_lines"] = int(g.get("log_lines") or 0) + 1
    items = []
    for g in groups.values():
        g.setdefault("count", len(g["checks"]) or int(g.get("log_lines") or 0))
        g["what"] = (", ".join(f"{x['id']} {x['label']}" for x in g["checks"][:6]) + (f" and {len(g['checks']) - 6} more" if len(g["checks"]) > 6 else "")
                     if g["checks"] else (f"{g['count']} check{'s' if g['count'] != 1 else ''}" if g["category"] == "scope" else g["why"]))
        items.append(g)
    order = list(CATEGORIES)
    items.sort(key=lambda g: (order.index(g["category"]), -int(g["count"] or 0), g["area"]))
    total = len(rows)
    ran = total - not_ran
    return {"total": total, "ran": ran, "not_ran": not_ran, "pct": round(ran / total * 100) if total else None,
            "hidden": hidden, "items": items,
            "sentence": (f"Coverage: {round(ran / total * 100)}% of checks ran ({ran} of {total})." if total else "Coverage: no assessment results yet.")
                        + (f" {not_ran} could not be checked; the list says why and how to fix it." if not_ran else ""),
            "by_category": {c: sum(int(g["count"] or 0) for g in items if g["category"] == c) for c in order}}


def _endpoint_of(text: str) -> str:
    m = _ENDPOINT.search(str(text or ""))
    return m.group(1) if m else ""


def _first(detail: str, label: Any) -> str:
    d = re.sub(r"\s+", " ", str(detail or "")).strip()
    lab = str(label or "")
    if lab and d.startswith(lab + ":"):
        d = d[len(lab) + 1:].strip()
    return (d[:240] + "…") if len(d) > 240 else d


def _log_area(line: str) -> str:
    m = re.search(r"Reading the tenant: ([A-Za-z][A-Za-z /-]{2,40}?)(?: rules| could| for|:|…)", line)
    if m:
        return m.group(1).strip()
    ep = _ENDPOINT.search(line)
    return ep.group(1) if ep else "Tenant reads"
