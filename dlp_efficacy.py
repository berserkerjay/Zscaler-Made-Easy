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


def _score_dictionary(
    d: Dict[str, Any],
    engine_refs: Set[int],
    rule_reachable: Set[int],
) -> Dict[str, Any]:
    """Score one dictionary 0-100 and list what's good/bad.

    engine_refs: dict IDs referenced by ANY engine (custom or predefined)
    rule_reachable: dict IDs reachable through an engine that a rule uses
    """
    name = d.get("name", "?")
    did = _safe_int(d.get("id"))
    phrases = d.get("phrases") or []
    patterns = d.get("patterns") or []
    confidence = d.get("confidence") or d.get("confidenceLevel")
    min_match = _safe_int(
        d.get("minMatchCount") or d.get("minimumMatchCount") or 1
    ) or 1

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
    if not _is_custom_dict(d):
        return {
            **base,
            "type": "predefined",
            "score": 100,
            "grade": "A",
            "reasons": ["Predefined Zscaler dictionary — curated by vendor."],
            "remediation": [],
        }

    score = 100
    reasons: List[str] = []
    remediation: List[str] = []

    n_phrases = len(phrases)
    n_patterns = len(patterns)

    # Empty dictionary — critical
    if n_phrases == 0 and n_patterns == 0:
        score -= 90
        reasons.append("Empty dictionary — no phrases and no patterns defined.")
        remediation.append(
            "Add at least 5–10 high-precision phrases or a tested regex before enabling."
        )

    # Thin dictionary
    elif n_phrases == 1 and n_patterns == 0:
        score -= 15
        reasons.append("Only one phrase — very narrow coverage.")
        remediation.append(
            "Expand to 5+ synonyms/variants so detection survives small wording changes."
        )

    # Regex validity + overly-broad patterns
    invalid_regex: List[Tuple[str, str]] = []
    broad: List[str] = []
    for p in patterns:
        pat_str = p.get("pattern") or p.get("regex") or p.get("expression") or ""
        if not pat_str:
            continue
        if pat_str.strip() in _BROAD_PATTERNS:
            broad.append(pat_str)
            continue
        try:
            re.compile(pat_str)
        except re.error as e:
            invalid_regex.append((pat_str[:40], str(e)[:80]))

    if invalid_regex:
        score -= 25
        reasons.append(f"{len(invalid_regex)} invalid regex pattern(s).")
        remediation.append(
            f"Fix invalid regex: /{invalid_regex[0][0]}/ — {invalid_regex[0][1]}"
        )

    if broad:
        score -= 40
        reasons.append(
            f"{len(broad)} overly-broad pattern(s) like /.*/ — will match everything and flood incidents."
        )
        remediation.append(
            "Replace catch-all patterns with anchored, specific expressions (e.g. \\b<specific>\\b)."
        )

    # Single/double-character phrases — noise
    tiny = [
        p for p in phrases
        if isinstance(p.get("phrase"), str) and len(p.get("phrase", "").strip()) < 3
    ]
    if tiny:
        score -= 15
        reasons.append(
            f"{len(tiny)} phrase(s) shorter than 3 chars — high false-positive risk."
        )
        remediation.append(
            "Remove 1–2 character phrases; use 4+ char terms to avoid accidental matches."
        )

    # Orphan: nobody uses it
    if base["orphan_engine"]:
        score -= 30
        reasons.append("Not referenced by any DLP engine.")
        remediation.append(
            f"Add '{name}' to a DLP engine expression (e.g. 'D({did})'), or delete if unused."
        )
    elif base["orphan_rule"]:
        score -= 10
        reasons.append(
            "Used by an engine, but no rule references that engine — not enforced."
        )
        remediation.append(
            "Attach the referencing engine to a webDlpRule, or remove the engine."
        )

    # Threshold hygiene: many phrases + min_match=1 is noisy
    if min_match <= 1 and n_phrases >= 20:
        score -= 10
        reasons.append(
            f"Minimum match count = {min_match} across {n_phrases} phrases — any single hit fires."
        )
        remediation.append(
            "Raise min match count to 2–3 on broad dictionaries to improve precision."
        )

    # Clamp and return
    score = max(0, min(100, score))
    return {
        **base,
        "type": "custom",
        "score": score,
        "grade": _grade(score),
        "reasons": reasons or ["No issues detected."],
        "remediation": remediation,
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
        return {
            **base,
            "type": "predefined",
            "score": 100,
            "grade": "A",
            "reasons": ["Predefined Zscaler engine."],
            "remediation": [],
        }

    score = 100
    reasons: List[str] = []
    remediation: List[str] = []

    if not expr:
        score -= 60
        reasons.append("Empty engine expression.")
        remediation.append(
            "Define an expression like 'D(<dict_id>) AND D(<dict_id>)'."
        )
    else:
        # OR-only logic on multiple dicts → noisier
        up = expr.upper()
        has_and = " AND " in up
        has_or = " OR " in up
        if has_or and not has_and and len(dict_ids) > 1:
            score -= 10
            reasons.append(
                "Expression uses only OR — any single dictionary hit fires the engine."
            )
            remediation.append(
                "Combine weak dictionaries with AND for higher precision."
            )

        # Broken dict refs
        missing = [did for did in dict_ids if did not in dict_by_id]
        if missing:
            score -= 30
            reasons.append(
                f"{len(missing)} dictionary reference(s) point to missing/deleted dictionaries."
            )
            remediation.append(
                f"Remove stale IDs from the expression: {', '.join(str(m) for m in missing[:5])}"
            )

        # Empty referenced dicts
        empty_refs = []
        for did in dict_ids:
            d = dict_by_id.get(did)
            if not d:
                continue
            if _is_custom_dict(d) and not (d.get("phrases") or d.get("patterns")):
                empty_refs.append(d.get("name") or str(did))
        if empty_refs:
            score -= 20
            reasons.append(
                f"{len(empty_refs)} referenced dict(s) are empty: {', '.join(empty_refs[:3])}."
            )
            remediation.append(
                "Populate or replace empty dictionaries before relying on this engine."
            )

    # Orphan engine
    if base["orphan_rule"]:
        score -= 25
        reasons.append("Not referenced by any DLP rule.")
        remediation.append("Attach this engine to a webDlpRule, or delete it.")

    score = max(0, min(100, score))
    return {
        **base,
        "type": "custom",
        "score": score,
        "grade": _grade(score),
        "reasons": reasons or ["No issues detected."],
        "remediation": remediation,
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

    # Sort worst-first for review-table friendliness
    dict_scores.sort(key=lambda x: (x["score"], x["name"]))
    engine_scores.sort(key=lambda x: (x["score"], x["name"]))

    custom_dicts = [x for x in dict_scores if x["type"] == "custom"]
    custom_engines = [x for x in engine_scores if x["type"] == "custom"]

    def _avg(xs: List[Dict[str, Any]]) -> Optional[float]:
        return round(sum(x["score"] for x in xs) / len(xs), 1) if xs else None

    return {
        "counts": {
            "dictionaries_total": len(dict_scores),
            "dictionaries_custom": len(custom_dicts),
            "engines_total": len(engine_scores),
            "engines_custom": len(custom_engines),
            "rules": len(rules),
        },
        "averages": {
            "custom_dictionary_efficacy": _avg(custom_dicts),
            "custom_engine_efficacy": _avg(custom_engines),
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
