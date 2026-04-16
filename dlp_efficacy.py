#!/usr/bin/env python3
"""
DLP Dictionary & Engine Efficacy Analyzer
==========================================
Scores Zscaler custom DLP dictionaries and engines on how likely they
are to actually detect sensitive data — without creating false positives.

Two analyses:

1) Static analysis (no user data required)
   - Dictionary quality: phrase count, pattern validity, threshold
     sanity, EDM/IDM template usage, whether the dictionary is
     referenced by any engine and whether any engine that references
     it is referenced by a rule (reachability).
   - Engine quality: expression logic (AND is higher precision than
     OR alone), broken dictionary references, engines built entirely
     on empty custom dictionaries, orphan-engine detection.

2) Local corpus test (optional, stays on the server)
   - User supplies sample text (≤ 256 KB). For each custom
     dictionary, we count phrase + regex pattern matches locally
     using stdlib `re`. No content is ever sent to Zscaler or to
     any third party.

Scoring: 0–100 per item, with a letter grade and per-issue
remediation hints. Predefined Zscaler-supplied dictionaries and
engines always score 100 — they're curated by the vendor, and
scoring them would produce noise.

Architecture notes
------------------
- Pure-function module: takes an authenticated Client, returns dicts.
  No FastAPI coupling, no global state.
- Follows the same `/zia/dlpDictionaries`, `/zia/dlpEngines`,
  `/zia/webDlpRules` endpoints the existing checks already use, so
  it relies on the same API-role scope (no new permission required).
- Safe against malformed tenant data: every field access is defensive
  and unknown shapes fall through to neutral defaults, not exceptions.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple


# ─── Helpers ─────────────────────────────────────────────────────

def _ls(payload: Any) -> List[Dict[str, Any]]:
    """Normalize tenant payload to a list. ZIA endpoints sometimes
    return a bare list, sometimes {'list': [...]}. Be defensive."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for k in ("list", "items", "data", "results"):
            v = payload.get(k)
            if isinstance(v, list):
                return v
    return []


def _safe_int(v: Any) -> Optional[int]:
    try:
        return int(v)
    except Exception:
        return None


def _grade(score: int) -> str:
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    if score >= 40: return "D"
    return "F"


def _is_custom_dict(d: Dict[str, Any]) -> bool:
    # ZIA exposes `custom` on the list call and `customDictionary`
    # on the detail call; accept either. Predefined dicts typically
    # have a dictionaryType of "PREDEFINED".
    if d.get("custom") is True or d.get("customDictionary") is True:
        return True
    dt = (d.get("dictionaryType") or "").upper()
    if dt in ("PREDEFINED", "PATTERN_BASED_PREDEFINED"):
        return False
    # Fallback: if we see phrases/patterns we assume custom
    return bool(d.get("phrases") or d.get("patterns"))


def _is_custom_engine(e: Dict[str, Any]) -> bool:
    if e.get("customDlpEngine") is True or e.get("custom") is True:
        return True
    # Predefined engines include names like "HIPAA", "GDPR", "PCI"
    # and have predefinedEngineName set. Presence of that field is
    # a strong hint they're vendor-shipped.
    if e.get("predefinedEngineName"):
        return False
    return True  # assume custom unless proven otherwise


# ─── Data fetchers ───────────────────────────────────────────────

def _fetch_dictionaries(client) -> List[Dict[str, Any]]:
    data, code = client.get("/zia/dlpDictionaries")
    return _ls(data) if code in (200, 204) else []


def _fetch_engines(client) -> List[Dict[str, Any]]:
    data, code = client.get("/zia/dlpEngines")
    return _ls(data) if code in (200, 204) else []


def _fetch_rules(client) -> List[Dict[str, Any]]:
    data, code = client.get("/zia/webDlpRules")
    return _ls(data) if code in (200, 204) else []


def _parse_engine_expression(expr: str) -> List[int]:
    """Extract dictionary IDs from an engine expression.
    Zscaler expressions look like: D(123456) AND D(789012).
    Returns int IDs; silently skips unparseable tokens."""
    if not expr or not isinstance(expr, str):
        return []
    ids: List[int] = []
    for m in re.findall(r"D\((\d+)\)", expr):
        n = _safe_int(m)
        if n is not None:
            ids.append(n)
    return ids


# ─── Scoring: dictionaries ───────────────────────────────────────

# Overly-broad regexes that match virtually anything. Hard-coded so
# a malformed pattern can never be confused with "precision".
_BROAD_PATTERNS = {".*", ".+", ".", "", "^.*$", "^.+$"}

# Anchors / boundary markers that meaningfully narrow a regex. Presence
# pushes TP estimate up because the pattern won't just nibble on any
# random substring.
_TP_ANCHORS = (r"\b", r"\B", r"^", r"$", r"(?=", r"(?<=", r"(?<!")


def _fp_band(tp_pct: int) -> str:
    """Map a TP% estimate to a human-readable false-positive risk band.

    The bands are asymmetric: even a 70% TP is still "Medium FP risk"
    because 3 in 10 incidents being noise is a real analyst burden.
    Numbers are tuned for pragmatic DLP triage, not abstract ML.
    """
    fp = 100 - tp_pct
    if fp >= 55:
        return "Critical"
    if fp >= 35:
        return "High"
    if fp >= 15:
        return "Medium"
    return "Low"


def _nuance(direction: str, delta: int, driver: str, explanation: str) -> Dict[str, Any]:
    """Build a structured nuance record.

    direction: "tp" (improves precision) or "fp" (adds noise risk)
    delta:     absolute percentage-point shift on the TP estimate
               (signed in the output so consumers can re-aggregate)
    driver:    short tag (e.g. "broad_regex", "edm_table")
    explanation: plain-English sentence a DLP admin would act on
    """
    signed = abs(delta) if direction == "tp" else -abs(delta)
    return {
        "direction": direction,
        "delta_pct": signed,
        "driver": driver,
        "explanation": explanation,
    }


def _phrase_text(p: Any) -> str:
    if isinstance(p, dict):
        return (p.get("phrase") or p.get("action") or "") or ""
    return str(p or "")


def _pattern_text(p: Any) -> str:
    if isinstance(p, dict):
        return p.get("pattern") or p.get("regex") or p.get("expression") or ""
    return str(p or "")


def _score_dictionary(
    d: Dict[str, Any],
    engine_refs: Set[int],
    rule_reachable: Set[int],
) -> Dict[str, Any]:
    """Score one dictionary on two axes:
      - `score` 0-100: overall health / hygiene (empty, orphan, broken refs, …)
      - `tp_estimate` 0-100: probability a fire is a true positive

    These intentionally differ. An orphan dictionary is a hygiene
    problem (low `score`) but if fired it could still have excellent
    precision (high `tp_estimate`). The two numbers together tell you
    both "is this configured well?" and "if it fires, will I trust it?".

    engine_refs: dict IDs referenced by ANY engine
    rule_reachable: dict IDs reachable via an engine used by a rule
    """
    name = d.get("name", "?")
    did = _safe_int(d.get("id"))
    phrases = d.get("phrases") or []
    patterns = d.get("patterns") or []
    confidence = d.get("confidence") or d.get("confidenceLevel")
    min_match = _safe_int(
        d.get("minMatchCount") or d.get("minimumMatchCount") or 1
    ) or 1
    has_edm = bool(d.get("exactDataMatchDetails")) or "EDM" in (name or "").upper()
    has_idm = bool(d.get("idmProfile")) or "IDM" in (name or "").upper()

    base = {
        "id": did,
        "name": name,
        "phrases": len(phrases),
        "patterns": len(patterns),
        "confidence": confidence,
        "min_match_count": min_match,
        "orphan_engine": did is not None and did not in engine_refs,
        "orphan_rule": did is not None and did not in rule_reachable,
    }

    # Predefined dictionaries are curated by Zscaler — don't penalize.
    # We assume ~92% TP as an honest ceiling; even vendor content has
    # edge cases (e.g. "HIPAA" dictionaries firing on research papers).
    if not _is_custom_dict(d):
        tp = 92
        return {
            **base,
            "type": "predefined",
            "score": 100,
            "grade": _grade(100),
            "tp_estimate": tp,
            "fp_risk": _fp_band(tp),
            "reasons": ["Predefined Zscaler dictionary — curated by vendor."],
            "remediation": [],
            "nuances": [
                _nuance("tp", 17, "vendor_curated",
                        "Predefined Zscaler dictionary — patterns are vendor-tuned "
                        "from large-scale telemetry, so precision is already high."),
            ],
        }

    score = 100
    reasons: List[str] = []
    remediation: List[str] = []
    nuances: List[Dict[str, Any]] = []

    # TP estimate starts at 75% for a healthy custom dict — custom
    # content is inherently less-tested than vendor content.
    tp = 75

    n_phrases = len(phrases)
    n_patterns = len(patterns)

    # Empty dictionary — critical
    if n_phrases == 0 and n_patterns == 0:
        score -= 90
        tp -= 70  # can't meaningfully fire at all
        reasons.append("Empty dictionary — no phrases and no patterns defined.")
        remediation.append(
            "Add at least 5–10 high-precision phrases or a tested regex before enabling."
        )
        nuances.append(_nuance("fp", 70, "empty_dictionary",
            "No phrases or patterns defined — if it somehow fires (misconfig), "
            "there's no way to know what it was trying to catch."))
    elif n_phrases == 1 and n_patterns == 0:
        score -= 15
        tp -= 5
        reasons.append("Only one phrase — very narrow coverage.")
        remediation.append(
            "Expand to 5+ synonyms/variants so detection survives small wording changes."
        )
        nuances.append(_nuance("fp", 5, "single_phrase",
            "Single phrase means any incidental use of that word fires the rule — "
            "a quoted block, an email footer, a help article."))

    # Regex validity + overly-broad patterns
    invalid_regex: List[Tuple[str, str]] = []
    broad: List[str] = []
    anchored_count = 0
    for p in patterns:
        pat_str = _pattern_text(p)
        if not pat_str:
            continue
        if pat_str.strip() in _BROAD_PATTERNS:
            broad.append(pat_str)
            continue
        try:
            re.compile(pat_str)
            if any(a in pat_str for a in _TP_ANCHORS):
                anchored_count += 1
        except re.error as e:
            invalid_regex.append((pat_str[:40], str(e)[:80]))

    if invalid_regex:
        score -= 25
        tp -= 15
        reasons.append(f"{len(invalid_regex)} invalid regex pattern(s).")
        remediation.append(
            f"Fix invalid regex: /{invalid_regex[0][0]}/ — {invalid_regex[0][1]}"
        )
        nuances.append(_nuance("fp", 15, "invalid_regex",
            f"Pattern /{invalid_regex[0][0]}/ fails to compile — Zscaler will skip it "
            "silently, so you think you have coverage but you don't."))

    if broad:
        score -= 40
        tp -= 55
        reasons.append(
            f"{len(broad)} overly-broad pattern(s) like /.*/ — will match everything and flood incidents."
        )
        remediation.append(
            "Replace catch-all patterns with anchored, specific expressions (e.g. \\b<specific>\\b)."
        )
        nuances.append(_nuance("fp", 55, "broad_regex",
            "A pattern like /.*/ or /.+/ matches any non-empty content — the rule "
            "will fire on every inspected file, making it worse than no DLP at all."))

    if anchored_count:
        tp += min(12, 4 * anchored_count)
        nuances.append(_nuance("tp", min(12, 4 * anchored_count), "anchored_regex",
            f"{anchored_count} regex pattern(s) use word-boundary / anchor tokens "
            r"(\b, ^, $, lookaround) — prevents accidental substring matches."))

    # Single/double-character phrases — noise
    tiny = [p for p in phrases if len(_phrase_text(p).strip()) < 3]
    if tiny:
        score -= 15
        tp -= 20
        reasons.append(
            f"{len(tiny)} phrase(s) shorter than 3 chars — high false-positive risk."
        )
        remediation.append(
            "Remove 1–2 character phrases; use 4+ char terms to avoid accidental matches."
        )
        nuances.append(_nuance("fp", 20, "tiny_phrases",
            f"Phrases like {', '.join(repr(_phrase_text(t).strip()) for t in tiny[:3])} "
            "will match inside thousands of unrelated words."))

    # Common-English-word phrases — also noisy even at 3+ chars
    _VERY_COMMON = {"the","and","for","are","but","not","you","all","any","was",
                    "our","one","can","has","had","out","see","use","now","new",
                    "may","her","him","how","who","its","yes"}
    common_hits = [_phrase_text(p).lower().strip() for p in phrases
                   if _phrase_text(p).lower().strip() in _VERY_COMMON]
    if common_hits:
        tp -= 10
        nuances.append(_nuance("fp", 10, "common_english",
            f"Phrases like {', '.join(repr(w) for w in common_hits[:3])} are "
            "extremely common English words — high incidental-match rate in any "
            "English document."))

    # EDM / IDM — near-zero FP because they match actual indexed data
    if has_edm:
        tp += 15
        nuances.append(_nuance("tp", 15, "edm",
            "Exact Data Match (EDM) checks against indexed sensitive records — "
            "matches are verified against real data, giving near-zero FP rate."))
    if has_idm:
        tp += 12
        nuances.append(_nuance("tp", 12, "idm",
            "Indexed Document Match (IDM) compares against fingerprinted reference "
            "documents — high precision on derivative/excerpted content."))

    # Min-match discipline
    if min_match >= 3:
        tp += 8
        nuances.append(_nuance("tp", 8, "high_min_match",
            f"Minimum match count = {min_match} — requires several distinct hits "
            "before firing, which sharply reduces casual-mention noise."))
    elif min_match == 2:
        tp += 3
        nuances.append(_nuance("tp", 3, "min_match_2",
            "Minimum match count = 2 — a single mention won't fire, which cuts "
            "out a lot of conversational false positives."))
    elif min_match <= 1 and n_phrases >= 20:
        score -= 10
        tp -= 10
        reasons.append(
            f"Minimum match count = {min_match} across {n_phrases} phrases — any single hit fires."
        )
        remediation.append(
            "Raise min match count to 2–3 on broad dictionaries to improve precision."
        )
        nuances.append(_nuance("fp", 10, "lax_threshold",
            f"{n_phrases} phrases with min match = {min_match} means any one of "
            "them firing once triggers an incident — noisy on long documents."))

    # Orphan: nobody uses it (hygiene, not a TP driver — a dict that
    # never fires has no TP/FP rate, but we still flag it).
    if base["orphan_engine"]:
        score -= 30
        reasons.append("Not referenced by any DLP engine.")
        remediation.append(
            f"Add '{name}' to a DLP engine expression (e.g. 'D({did})'), or delete if unused."
        )
        nuances.append(_nuance("fp", 0, "orphan_engine",
            "No engine references this dictionary — it can never fire. Hygiene "
            "issue, not a precision issue."))
    elif base["orphan_rule"]:
        score -= 10
        reasons.append(
            "Used by an engine, but no rule references that engine — not enforced."
        )
        remediation.append(
            "Attach the referencing engine to a webDlpRule, or remove the engine."
        )
        nuances.append(_nuance("fp", 0, "orphan_rule_chain",
            "Engines reference this dictionary but no rule references those "
            "engines — effectively dead code in the policy."))

    # Clamp and return
    score = max(0, min(100, score))
    tp = max(5, min(95, tp))  # never claim 0% or 100% without empirical data
    return {
        **base,
        "type": "custom",
        "has_edm": has_edm,
        "has_idm": has_idm,
        "score": score,
        "grade": _grade(score),
        "tp_estimate": tp,
        "fp_risk": _fp_band(tp),
        "reasons": reasons or ["No issues detected."],
        "remediation": remediation,
        "nuances": nuances,
    }


# ─── Scoring: engines ────────────────────────────────────────────

def _score_engine(
    e: Dict[str, Any],
    rule_refs: Set[int],
    dict_by_id: Dict[int, Dict[str, Any]],
) -> Dict[str, Any]:
    name = e.get("name", "?")
    eid = _safe_int(e.get("id"))
    expr = e.get("engineExpression") or e.get("expression") or ""
    dict_ids = _parse_engine_expression(expr)

    base = {
        "id": eid,
        "name": name,
        "expression": expr[:300],
        "dictionary_count": len(dict_ids),
        "dictionary_ids": dict_ids,
        "orphan_rule": eid is not None and eid not in rule_refs,
    }

    if not _is_custom_engine(e):
        tp = 92
        return {
            **base,
            "type": "predefined",
            "score": 100,
            "grade": _grade(100),
            "tp_estimate": tp,
            "fp_risk": _fp_band(tp),
            "reasons": ["Predefined Zscaler engine."],
            "remediation": [],
            "nuances": [
                _nuance("tp", 17, "vendor_curated",
                        "Predefined engine — expression and thresholds are "
                        "Zscaler-tuned, tested across their customer base."),
            ],
        }

    score = 100
    tp = 75
    reasons: List[str] = []
    remediation: List[str] = []
    nuances: List[Dict[str, Any]] = []

    if not expr:
        score -= 60
        tp -= 60
        reasons.append("Empty engine expression.")
        remediation.append(
            "Define an expression like 'D(<dict_id>) AND D(<dict_id>)'."
        )
        nuances.append(_nuance("fp", 60, "empty_expression",
            "Engine has no expression — cannot fire on anything. If attached to "
            "a rule it's effectively a no-op."))
    else:
        up = expr.upper()
        has_and = " AND " in up
        has_or = " OR " in up
        if has_and and len(dict_ids) >= 2:
            tp += 12
            nuances.append(_nuance("tp", 12, "and_logic",
                "Expression combines multiple dictionaries with AND — the engine "
                "only fires when several signals align, so single-word false "
                "positives are filtered out."))
        if has_or and not has_and and len(dict_ids) > 1:
            score -= 10
            tp -= 15
            reasons.append(
                "Expression uses only OR — any single dictionary hit fires the engine."
            )
            remediation.append(
                "Combine weak dictionaries with AND for higher precision."
            )
            nuances.append(_nuance("fp", 15, "or_only",
                f"{len(dict_ids)} dictionaries joined by OR — the engine inherits "
                "the weakest dict's false-positive rate, not the strongest."))

        # Broken dict refs
        missing = [did for did in dict_ids if did not in dict_by_id]
        if missing:
            score -= 30
            tp -= 15
            reasons.append(
                f"{len(missing)} dictionary reference(s) point to missing/deleted dictionaries."
            )
            remediation.append(
                f"Remove stale IDs from the expression: {', '.join(str(m) for m in missing[:5])}"
            )
            nuances.append(_nuance("fp", 15, "broken_refs",
                f"Expression references dictionary IDs {missing[:5]} that don't "
                "exist — evaluation is undefined and may drop clauses silently."))

        # Empty referenced dicts
        empty_refs: List[str] = []
        weak_custom_refs: List[str] = []
        strong_refs: List[str] = []
        for did in dict_ids:
            d = dict_by_id.get(did)
            if not d:
                continue
            dn = d.get("name") or str(did)
            if _is_custom_dict(d) and not (d.get("phrases") or d.get("patterns")):
                empty_refs.append(dn)
            elif _is_custom_dict(d):
                # Inherit noise signal from the referenced dict
                pats = d.get("patterns") or []
                if any(_pattern_text(p).strip() in _BROAD_PATTERNS for p in pats):
                    weak_custom_refs.append(dn)
                else:
                    strong_refs.append(dn)
            else:
                strong_refs.append(dn)  # predefined → strong

        if empty_refs:
            score -= 20
            tp -= 18
            reasons.append(
                f"{len(empty_refs)} referenced dict(s) are empty: {', '.join(empty_refs[:3])}."
            )
            remediation.append(
                "Populate or replace empty dictionaries before relying on this engine."
            )
            nuances.append(_nuance("fp", 18, "empty_refs",
                f"References empty dictionary '{empty_refs[0]}' — that clause "
                "contributes nothing, so the engine's real logic is narrower "
                "than the expression suggests."))
        if weak_custom_refs:
            tp -= 12
            nuances.append(_nuance("fp", 12, "weak_ref",
                f"References '{weak_custom_refs[0]}' which contains an overly-broad "
                "regex — the engine inherits that dict's false-positive rate."))
        if strong_refs and not weak_custom_refs and not empty_refs:
            tp += 5
            nuances.append(_nuance("tp", 5, "strong_refs",
                f"All referenced dictionaries ({', '.join(strong_refs[:3])}) are "
                "populated and contain precision-oriented patterns."))

    # Orphan engine (hygiene, not precision)
    if base["orphan_rule"]:
        score -= 25
        reasons.append("Not referenced by any DLP rule.")
        remediation.append("Attach this engine to a webDlpRule, or delete it.")
        nuances.append(_nuance("fp", 0, "orphan_rule",
            "No rule references this engine — it never fires. Hygiene issue only."))

    score = max(0, min(100, score))
    tp = max(5, min(95, tp))
    return {
        **base,
        "type": "custom",
        "score": score,
        "grade": _grade(score),
        "tp_estimate": tp,
        "fp_risk": _fp_band(tp),
        "reasons": reasons or ["No issues detected."],
        "remediation": remediation,
        "nuances": nuances,
    }


# ─── Public API ──────────────────────────────────────────────────

def analyze(client) -> Dict[str, Any]:
    """Run the full static efficacy analysis against a tenant.

    Returns:
      {
        "counts":    {dictionaries_total, dictionaries_custom, engines_total, engines_custom, rules},
        "averages":  {custom_dictionary_efficacy, custom_engine_efficacy},
        "orphans":   {dictionaries_unused_by_engines, dictionaries_unused_by_rules, engines_unused_by_rules},
        "dictionaries": [ per-dict score record ],
        "engines":      [ per-engine score record ],
      }
    """
    dicts = _fetch_dictionaries(client)
    engines = _fetch_engines(client)
    rules = _fetch_rules(client)

    # Build reference graph
    engine_dict_refs: Set[int] = set()
    for e in engines:
        for did in _parse_engine_expression(
            e.get("engineExpression") or e.get("expression") or ""
        ):
            engine_dict_refs.add(did)

    rule_engine_refs: Set[int] = set()
    for r in rules:
        for ref in (r.get("dlpEngines") or r.get("engines") or []):
            eid = _safe_int(ref.get("id") if isinstance(ref, dict) else ref)
            if eid is not None:
                rule_engine_refs.add(eid)

    # Dicts reachable through an engine that a rule uses
    rule_reachable_dicts: Set[int] = set()
    for e in engines:
        eid = _safe_int(e.get("id"))
        if eid is None or eid not in rule_engine_refs:
            continue
        for did in _parse_engine_expression(
            e.get("engineExpression") or e.get("expression") or ""
        ):
            rule_reachable_dicts.add(did)

    dict_by_id: Dict[int, Dict[str, Any]] = {}
    for d in dicts:
        did = _safe_int(d.get("id"))
        if did is not None:
            dict_by_id[did] = d

    dict_scores = [
        _score_dictionary(d, engine_dict_refs, rule_reachable_dicts) for d in dicts
    ]
    engine_scores = [
        _score_engine(e, rule_engine_refs, dict_by_id) for e in engines
    ]

    # Sort worst-first by TP estimate (precision is the point of this
    # view) with health-score as a secondary sort key.
    dict_scores.sort(key=lambda x: (x.get("tp_estimate", 0), x["score"], x["name"]))
    engine_scores.sort(key=lambda x: (x.get("tp_estimate", 0), x["score"], x["name"]))

    custom_dicts = [x for x in dict_scores if x["type"] == "custom"]
    custom_engines = [x for x in engine_scores if x["type"] == "custom"]

    def _avg(xs: List[Dict[str, Any]], key: str) -> Optional[float]:
        vals = [x[key] for x in xs if x.get(key) is not None]
        return round(sum(vals) / len(vals), 1) if vals else None

    def _band_counts(xs: List[Dict[str, Any]]) -> Dict[str, int]:
        out = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        for x in xs:
            band = x.get("fp_risk")
            if band in out:
                out[band] += 1
        return out

    return {
        "counts": {
            "dictionaries_total": len(dict_scores),
            "dictionaries_custom": len(custom_dicts),
            "engines_total": len(engine_scores),
            "engines_custom": len(custom_engines),
            "rules": len(rules),
        },
        "averages": {
            "custom_dictionary_efficacy": _avg(custom_dicts, "score"),
            "custom_engine_efficacy": _avg(custom_engines, "score"),
            "custom_dictionary_tp_pct": _avg(custom_dicts, "tp_estimate"),
            "custom_engine_tp_pct": _avg(custom_engines, "tp_estimate"),
        },
        "fp_risk_distribution": {
            "dictionaries": _band_counts(custom_dicts),
            "engines": _band_counts(custom_engines),
        },
        "orphans": {
            "dictionaries_unused_by_engines": [
                x["name"] for x in dict_scores
                if x.get("orphan_engine") and x["type"] == "custom"
            ],
            "dictionaries_unused_by_rules": [
                x["name"] for x in dict_scores
                if x.get("orphan_rule") and x["type"] == "custom"
            ],
            "engines_unused_by_rules": [
                x["name"] for x in engine_scores
                if x.get("orphan_rule") and x["type"] == "custom"
            ],
        },
        "dictionaries": dict_scores,
        "engines": engine_scores,
    }


# ─── Corpus test ─────────────────────────────────────────────────

# Hard caps so a pasted blob can never turn into a DoS against our
# regex engine or our memory. 256 KB is plenty for a representative
# sample — you're not feeding a warehouse through this.
_CORPUS_CAP_BYTES = 262_144
_PATTERN_TIMEOUT_FALLBACK_MAX = 20_000  # chars per pattern match call


def corpus_test(client, corpus: str, max_dicts: int = 200) -> Dict[str, Any]:
    """Test a user-supplied text corpus against every custom dictionary.

    Returns per-dictionary hit counts + a few sample match rows.
    Pure local regex — no content ever leaves this process.

    Caps:
      - corpus trimmed to 256 KB
      - max_dicts custom dictionaries tested (default 200 → usually all)
      - each pattern's findall runs against the full corpus but regex
        is compiled once per pattern, not per-phrase

    Returns:
      {
        "corpus_length": N,
        "dicts_tested": N,
        "results": [
          {id, name, phrase_hits, pattern_hits, total_hits,
           phrase_samples:[{phrase, count}], pattern_samples:[...]},
          ...
        ] (sorted by total_hits desc)
      }
    """
    if not isinstance(corpus, str):
        return {"error": "corpus must be a string", "results": []}
    if len(corpus.encode("utf-8", errors="ignore")) > _CORPUS_CAP_BYTES:
        corpus = corpus.encode("utf-8", errors="ignore")[:_CORPUS_CAP_BYTES].decode(
            "utf-8", errors="ignore"
        )
    if not corpus.strip():
        return {"error": "corpus is empty", "results": []}

    dicts = _fetch_dictionaries(client)
    results: List[Dict[str, Any]] = []
    tested = 0

    for d in dicts[:max_dicts]:
        if not _is_custom_dict(d):
            continue
        tested += 1
        name = d.get("name", "?")
        did = _safe_int(d.get("id"))
        phrases = d.get("phrases") or []
        patterns = d.get("patterns") or []

        phrase_hits = 0
        phrase_samples: List[Dict[str, Any]] = []
        for p in phrases:
            phr = p.get("phrase") or p.get("action") or ""
            if not isinstance(phr, str) or len(phr.strip()) < 2:
                continue
            try:
                n = len(re.findall(re.escape(phr), corpus, flags=re.IGNORECASE))
            except Exception:
                continue
            if n:
                phrase_hits += n
                if len(phrase_samples) < 5:
                    phrase_samples.append({"phrase": phr[:60], "count": n})

        pattern_hits = 0
        pattern_samples: List[Dict[str, Any]] = []
        for p in patterns:
            pat = p.get("pattern") or p.get("regex") or p.get("expression") or ""
            if not pat or pat.strip() in _BROAD_PATTERNS:
                continue
            try:
                rx = re.compile(pat, flags=re.IGNORECASE)
                matches = rx.findall(corpus)
            except re.error:
                continue
            except Exception:
                continue
            if matches:
                pattern_hits += len(matches)
                if len(pattern_samples) < 5:
                    pattern_samples.append({"pattern": pat[:60], "count": len(matches)})

        results.append({
            "id": did,
            "name": name,
            "phrase_hits": phrase_hits,
            "pattern_hits": pattern_hits,
            "total_hits": phrase_hits + pattern_hits,
            "phrase_samples": phrase_samples,
            "pattern_samples": pattern_samples,
        })

    results.sort(key=lambda x: x["total_hits"], reverse=True)
    return {
        "corpus_length": len(corpus),
        "dicts_tested": tested,
        "results": results,
    }


# ─── Export: CSV / JSON / Markdown / DOCX ────────────────────────
# Each export takes the full `analyze()` dict and returns bytes ready
# for HTTP download. Formats are deliberately flat and machine-
# readable (CSV), semi-structured (Markdown), or fully-structured
# (JSON, DOCX) so users can plug the results into whatever review
# workflow they already run (Excel, Confluence, ticketing).

import csv as _csv
import io as _io
import json as _json


def _row_dict_for_export(r: Dict[str, Any], kind: str) -> Dict[str, Any]:
    """Flatten one score record to a row suitable for CSV / Markdown."""
    nuances_tp = [n["explanation"] for n in r.get("nuances", []) if n["direction"] == "tp"]
    nuances_fp = [n["explanation"] for n in r.get("nuances", []) if n["direction"] == "fp"]
    row = {
        "kind": kind,
        "id": r.get("id"),
        "name": r.get("name"),
        "type": r.get("type"),
        "tp_estimate_pct": r.get("tp_estimate"),
        "fp_risk": r.get("fp_risk"),
        "health_score": r.get("score"),
        "reasons": " | ".join(r.get("reasons", [])),
        "remediation": " | ".join(r.get("remediation", [])),
        "tp_drivers": " | ".join(nuances_tp),
        "fp_drivers": " | ".join(nuances_fp),
    }
    if kind == "dictionary":
        row["phrases"] = r.get("phrases")
        row["patterns"] = r.get("patterns")
        row["min_match_count"] = r.get("min_match_count")
        row["orphan_engine"] = r.get("orphan_engine")
        row["orphan_rule"] = r.get("orphan_rule")
    else:
        row["dictionary_count"] = r.get("dictionary_count")
        row["expression"] = r.get("expression")
        row["orphan_rule"] = r.get("orphan_rule")
    return row


def export_csv(analysis: Dict[str, Any]) -> bytes:
    """CSV of every dictionary + engine with TP% / FP risk / nuances.

    One row per item, kind column distinguishes 'dictionary' vs
    'engine'. Designed for pivot-table review in Excel / Sheets.
    """
    rows: List[Dict[str, Any]] = []
    for d in analysis.get("dictionaries", []):
        rows.append(_row_dict_for_export(d, "dictionary"))
    for e in analysis.get("engines", []):
        rows.append(_row_dict_for_export(e, "engine"))
    if not rows:
        return b"kind,id,name,type,tp_estimate_pct,fp_risk,health_score,reasons,remediation\n"
    # Union of keys so every column is represented even if one row lacks a field
    fieldnames: List[str] = []
    seen = set()
    for r in rows:
        for k in r.keys():
            if k not in seen:
                seen.add(k); fieldnames.append(k)
    buf = _io.StringIO()
    w = _csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


def export_json(analysis: Dict[str, Any]) -> bytes:
    """Full analysis as pretty-printed JSON. Preserves the nuance
    objects including `direction`, `delta_pct`, `driver`, and
    `explanation` so downstream tooling can re-aggregate."""
    return _json.dumps(analysis, indent=2, default=str, sort_keys=False).encode("utf-8")


def export_markdown(analysis: Dict[str, Any]) -> bytes:
    """Markdown report — good for pasting into PR descriptions,
    Confluence, or an email body. Sections:
      - Header summary with counts + averages + FP risk distribution
      - Dictionaries table (Name / TP% / FP risk / Health / Drivers)
      - Engines table (same columns)
      - Detail section per item below each table, with nuances."""
    a = analysis or {}
    c = a.get("counts", {}) or {}
    avg = a.get("averages", {}) or {}
    dist = a.get("fp_risk_distribution", {}) or {}

    def _fmt_pct(v):
        return f"{v}%" if v is not None else "—"

    out: List[str] = []
    out.append("# DLP Dictionary & Engine Efficacy\n")
    out.append(f"- **Dictionaries**: {c.get('dictionaries_custom', 0)} custom "
               f"of {c.get('dictionaries_total', 0)} total")
    out.append(f"- **Engines**: {c.get('engines_custom', 0)} custom "
               f"of {c.get('engines_total', 0)} total")
    out.append(f"- **Rules referencing custom engines**: {c.get('rules', 0)}")
    out.append("")
    out.append(f"- **Avg TP% (dictionaries)**: {_fmt_pct(avg.get('custom_dictionary_tp_pct'))}")
    out.append(f"- **Avg TP% (engines)**: {_fmt_pct(avg.get('custom_engine_tp_pct'))}")
    out.append(f"- **Avg health score (dictionaries)**: {avg.get('custom_dictionary_efficacy', '—')}/100")
    out.append(f"- **Avg health score (engines)**: {avg.get('custom_engine_efficacy', '—')}/100")
    out.append("")

    dd = dist.get("dictionaries", {}) or {}
    de = dist.get("engines", {}) or {}
    out.append("**FP risk distribution** (custom items):")
    out.append("")
    out.append("| Risk band | Dictionaries | Engines |")
    out.append("|---|---:|---:|")
    for band in ("Low", "Medium", "High", "Critical"):
        out.append(f"| {band} | {dd.get(band, 0)} | {de.get(band, 0)} |")
    out.append("")

    def _table(rows: List[Dict[str, Any]], kind: str) -> None:
        out.append(f"## {kind.capitalize()}s\n")
        if not rows:
            out.append("_None._\n"); return
        out.append("| Name | TP% | FP risk | Health | Type | Top driver |")
        out.append("|---|---:|:---:|---:|---|---|")
        for r in rows:
            top = ""
            for n in (r.get("nuances") or []):
                if n.get("direction") == "fp":
                    top = n.get("driver", "")
                    break
            if not top:
                for n in (r.get("nuances") or []):
                    if n.get("direction") == "tp":
                        top = n.get("driver", ""); break
            out.append(
                f"| {r.get('name', '?')} "
                f"| {r.get('tp_estimate', '—')} "
                f"| {r.get('fp_risk', '—')} "
                f"| {r.get('score', '—')} "
                f"| {r.get('type', '—')} "
                f"| {top} |"
            )
        out.append("")
        out.append(f"### {kind.capitalize()} details\n")
        for r in rows:
            out.append(f"#### {r.get('name', '?')} "
                       f"— TP {r.get('tp_estimate', '—')}% · "
                       f"FP risk: {r.get('fp_risk', '—')} · "
                       f"health {r.get('score', '—')}/100")
            for nu in r.get("nuances", []):
                sign = "+" if nu["direction"] == "tp" else "−"
                out.append(f"- **{sign}{abs(nu.get('delta_pct', 0))}pp** "
                           f"_{nu.get('driver', '')}_ — {nu.get('explanation', '')}")
            if r.get("remediation"):
                out.append("")
                out.append("**Remediation:**")
                for rem in r["remediation"]:
                    out.append(f"- {rem}")
            out.append("")

    _table(a.get("dictionaries", []), "dictionary")
    _table(a.get("engines", []), "engine")
    return "\n".join(out).encode("utf-8")


def export_docx(analysis: Dict[str, Any]) -> bytes:
    """Word document — one table per section, per-item nuance paragraphs
    below, with TP%/FP risk color-coded.

    Import python-docx lazily so installs that don't have it can still
    use CSV / JSON / Markdown export.
    """
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except Exception as e:
        raise RuntimeError(
            "python-docx is required for DOCX export. "
            "Install with: pip install python-docx"
        ) from e

    a = analysis or {}
    c = a.get("counts", {}) or {}
    avg = a.get("averages", {}) or {}
    dist = a.get("fp_risk_distribution", {}) or {}

    doc = Document()
    doc.add_heading("DLP Dictionary & Engine Efficacy", level=0)

    p = doc.add_paragraph()
    p.add_run("Counts: ").bold = True
    p.add_run(
        f"{c.get('dictionaries_custom', 0)} custom / "
        f"{c.get('dictionaries_total', 0)} total dictionaries · "
        f"{c.get('engines_custom', 0)} custom / "
        f"{c.get('engines_total', 0)} total engines · "
        f"{c.get('rules', 0)} rules.\n"
    )
    p.add_run("Averages: ").bold = True
    p.add_run(
        f"TP (dicts) {avg.get('custom_dictionary_tp_pct', '—')}% · "
        f"TP (engines) {avg.get('custom_engine_tp_pct', '—')}% · "
        f"Health (dicts) {avg.get('custom_dictionary_efficacy', '—')}/100 · "
        f"Health (engines) {avg.get('custom_engine_efficacy', '—')}/100.\n"
    )

    # FP risk distribution table
    doc.add_heading("FP risk distribution", level=1)
    dist_table = doc.add_table(rows=1, cols=3)
    dist_table.style = "Light Grid Accent 1"
    hdr = dist_table.rows[0].cells
    hdr[0].text = "Risk band"
    hdr[1].text = "Dictionaries"
    hdr[2].text = "Engines"
    dd = dist.get("dictionaries", {}) or {}
    de = dist.get("engines", {}) or {}
    for band in ("Low", "Medium", "High", "Critical"):
        row = dist_table.add_row().cells
        row[0].text = band
        row[1].text = str(dd.get(band, 0))
        row[2].text = str(de.get(band, 0))

    def _band_color(band: str) -> RGBColor:
        return {
            "Low":      RGBColor(0x16, 0xA3, 0x4A),
            "Medium":   RGBColor(0xF5, 0x9E, 0x0B),
            "High":     RGBColor(0xF9, 0x73, 0x16),
            "Critical": RGBColor(0xDC, 0x26, 0x26),
        }.get(band, RGBColor(0x64, 0x74, 0x8B))

    def _section(title: str, rows: List[Dict[str, Any]]) -> None:
        doc.add_heading(title, level=1)
        if not rows:
            doc.add_paragraph("None.")
            return
        t = doc.add_table(rows=1, cols=5)
        t.style = "Light Grid Accent 1"
        h = t.rows[0].cells
        h[0].text = "Name"
        h[1].text = "TP %"
        h[2].text = "FP risk"
        h[3].text = "Health"
        h[4].text = "Top FP/TP driver"
        for r in rows:
            cells = t.add_row().cells
            cells[0].text = str(r.get("name", "?"))
            cells[1].text = str(r.get("tp_estimate", "—"))
            cells[2].text = str(r.get("fp_risk", "—"))
            cells[3].text = str(r.get("score", "—"))
            for run in cells[2].paragraphs[0].runs:
                run.font.bold = True
                run.font.color.rgb = _band_color(str(r.get("fp_risk", "")))
            top_n = ""
            for n in (r.get("nuances") or []):
                if n.get("direction") == "fp":
                    top_n = f"{n.get('driver', '')} (−{abs(n.get('delta_pct', 0))}pp)"
                    break
            if not top_n:
                for n in (r.get("nuances") or []):
                    if n.get("direction") == "tp":
                        top_n = f"{n.get('driver', '')} (+{abs(n.get('delta_pct', 0))}pp)"
                        break
            cells[4].text = top_n

        # Per-item nuance detail
        for r in rows:
            doc.add_heading(str(r.get("name", "?")), level=2)
            meta = doc.add_paragraph()
            meta.add_run(
                f"TP {r.get('tp_estimate', '—')}%  ·  "
                f"FP risk: {r.get('fp_risk', '—')}  ·  "
                f"health {r.get('score', '—')}/100  ·  "
                f"type: {r.get('type', '—')}"
            ).italic = True
            for nu in r.get("nuances", []):
                sign = "+" if nu["direction"] == "tp" else "−"
                bp = doc.add_paragraph(style="List Bullet")
                b = bp.add_run(f"{sign}{abs(nu.get('delta_pct', 0))}pp  {nu.get('driver', '')}")
                b.bold = True
                bp.add_run(f" — {nu.get('explanation', '')}")
            if r.get("remediation"):
                rp = doc.add_paragraph()
                rp.add_run("Remediation: ").bold = True
                for rem in r["remediation"]:
                    doc.add_paragraph(rem, style="List Bullet 2")

    _section("Dictionaries", a.get("dictionaries", []))
    _section("Engines", a.get("engines", []))

    out = _io.BytesIO()
    doc.save(out)
    return out.getvalue()


def export(analysis: Dict[str, Any], fmt: str) -> Tuple[bytes, str, str]:
    """Dispatch to the right exporter.

    Returns: (body_bytes, mime_type, suggested_filename)
    """
    f = (fmt or "").lower().strip()
    if f in ("csv",):
        return export_csv(analysis), "text/csv", "dlp_efficacy.csv"
    if f in ("json",):
        return (export_json(analysis),
                "application/json",
                "dlp_efficacy.json")
    if f in ("md", "markdown"):
        return (export_markdown(analysis),
                "text/markdown",
                "dlp_efficacy.md")
    if f in ("docx", "word"):
        return (export_docx(analysis),
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                "dlp_efficacy.docx")
    raise ValueError(f"Unknown export format: {fmt!r}")
