#!/usr/bin/env python3
"""
Zscaler Inline Web DLP Rule Migration — Evaluate All Rules
=========================================================
Scope: Inline Web DLP Rules ONLY (/zia/webDlpRules).

Helps migrate the inline Web DLP policy from First-Match-Wins to
Zscaler's recommended Evaluate All Rules mode by:

1. Analyzing current DLP rules for conflicts, shadowing, redundancy
2. Generating a safe reorder that preserves intended behavior under
   Evaluate All Rules mode
3. Exporting rules in API-importable format
4. Optionally pushing the new ordering back to Zscaler (gated)

Zscaler Best Practice for Inline DLP under Evaluate All Rules:
- Block/Deny rules first (most restrictive)
- Quarantine / Isolate next
- Confirm/Prompt rules next (user-coaching)
- Alert/Audit rules next
- Allow rules last (least restrictive)
- Within each action tier: most specific scope first
  (user/group/department scoping > URL category scoping > global)
- Remove redundant rules that would double-fire
- Run in audit/log-only mode before enforcement

Other Zscaler rule types (SSL, URL, Firewall, Cloud App Control)
have different best-practice ordering and are not covered by this
module — by design.
"""

from typing import Any, Dict, List, Optional, Tuple

# Action precedence for Evaluate All Rules mode
# Lower number = higher priority (runs first, most restrictive)
ACTION_PRIORITY = {
    "BLOCK": 10,
    "BLOCK_DROP": 10,
    "BLOCK_RESET": 10,
    "DENY": 10,
    "QUARANTINE": 15,
    "ISOLATE": 18,
    "CONFIRM": 20,
    "PROMPT": 20,
    "ALLOW_WITH_CONFIRM": 20,
    "CAUTION": 25,
    "ALERT": 30,
    "AUDIT": 35,
    "ALLOW": 40,
    "BYPASS": 50,
    "DO_NOT_INSPECT": 50,
}

# How specific is a rule? Higher = more specific (should come first within tier)
def _specificity_score(rule: Dict[str, Any]) -> int:
    """Score a rule's scope specificity. More specific rules fire first."""
    score = 0
    # Each scoping dimension adds points
    for field in ("users", "groups", "departments", "locations"):
        if rule.get(field):
            score += 10 + len(rule.get(field, []))
    for field in ("urlCategories", "cloudApplications", "fileTypes"):
        if rule.get(field):
            score += 5 + len(rule.get(field, []))
    for field in ("srcIpGroups", "destIpGroups", "srcIps", "destIps"):
        if rule.get(field):
            score += 3 + len(rule.get(field, []))
    if rule.get("dlpEngines") or rule.get("engines"):
        score += 5
    return score


def _action_key(rule: Dict[str, Any]) -> int:
    """Get normalized action priority."""
    action = (rule.get("action") or "").upper().replace(" ", "_")
    return ACTION_PRIORITY.get(action, 30)


def analyze_rules(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Analyze rules for issues that affect Evaluate All Rules migration.
    Returns a dict with:
      - issues: list of warnings with rule IDs and descriptions
      - disabled_count: rules that won't evaluate
      - action_counts: how many of each action type
      - scope_coverage: users/groups/depts globally scoped vs targeted
    """
    issues = []
    actions = {}
    disabled = 0
    global_scoped = 0
    specific_scoped = 0

    # Index by name to detect duplicates
    by_name = {}
    engines_used = {}

    for i, r in enumerate(rules):
        rid = str(r.get("id", i + 1))
        name = (r.get("name") or f"Rule {rid}").strip()
        state = (r.get("state") or "ENABLED").upper()
        action = (r.get("action") or "?").upper()
        actions[action] = actions.get(action, 0) + 1

        if state != "ENABLED":
            disabled += 1

        # Check scoping
        is_scoped = bool(r.get("users") or r.get("groups") or r.get("departments") or r.get("locations"))
        if is_scoped:
            specific_scoped += 1
        else:
            global_scoped += 1

        # Duplicate names
        if name in by_name:
            issues.append({
                "severity": "WARNING",
                "rule_id": rid,
                "rule_name": name,
                "type": "Duplicate Name",
                "message": f"Rule '{name}' appears multiple times — rename for clarity.",
            })
        by_name[name] = rid

        # Engine reuse
        for eng in (r.get("dlpEngines") or r.get("engines") or []):
            eid = eng.get("id") if isinstance(eng, dict) else eng
            engines_used.setdefault(eid, []).append((rid, name))

        # Block rule without engines = overbroad
        if action in ("BLOCK", "BLOCK_DROP", "DENY") and not (r.get("dlpEngines") or r.get("engines") or r.get("urlCategories")):
            issues.append({
                "severity": "WARNING",
                "rule_id": rid,
                "rule_name": name,
                "type": "Overbroad Block",
                "message": "Block rule has no DLP engines or URL categories — may block more than intended under Evaluate All.",
            })

        # Allow rule that would shadow nothing under Evaluate All
        if action in ("ALLOW", "BYPASS") and i < len(rules) - 1:
            issues.append({
                "severity": "INFO",
                "rule_id": rid,
                "rule_name": name,
                "type": "Shadowing Allow",
                "message": "Under Rule Order mode this Allow rule stops evaluation; under Evaluate All it has no suppressive effect. Consider consolidating or removing.",
            })

        # Deep scope check for cross-type shadowing (same categories + opposite actions)
        for j, other in enumerate(rules):
            if j <= i:
                continue
            other_action = (other.get("action") or "").upper()
            if other_action == action:
                continue
            # Overlapping URL categories?
            our_cats = set(r.get("urlCategories") or [])
            their_cats = set(other.get("urlCategories") or [])
            if our_cats and their_cats and our_cats & their_cats:
                if action in ("ALLOW", "BYPASS") and other_action in ("BLOCK", "BLOCK_DROP"):
                    issues.append({
                        "severity": "WARNING",
                        "rule_id": rid,
                        "rule_name": name,
                        "type": "Conflicting Overlap",
                        "message": f"Allows overlap with Block in rule '{(other.get('name') or '?')}' on categories: {', '.join(sorted(our_cats & their_cats))}. Under Evaluate All, block wins.",
                    })

    return {
        "total_rules": len(rules),
        "enabled_rules": len(rules) - disabled,
        "disabled_rules": disabled,
        "action_counts": actions,
        "global_scoped_rules": global_scoped,
        "specific_scoped_rules": specific_scoped,
        "duplicate_names": sum(1 for v in by_name.values() if isinstance(v, list)),
        "shared_engines": {eid: len(uses) for eid, uses in engines_used.items() if len(uses) > 1},
        "issues": issues,
        "issue_count": len(issues),
    }


def reorder_for_eval_all(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Return a new list of rules reordered for Evaluate All Rules mode:
      1. Block/Deny rules (most restrictive) — by specificity desc
      2. Quarantine / Isolate rules
      3. Confirm/Prompt rules (user-coaching)
      4. Alert / Audit rules
      5. Allow / Bypass rules (least restrictive)

    Within each tier, more specific rules come first. Disabled rules
    go to the end to keep them out of the way.
    """
    enabled = [r for r in rules if (r.get("state") or "ENABLED").upper() == "ENABLED"]
    disabled = [r for r in rules if (r.get("state") or "ENABLED").upper() != "ENABLED"]

    # Sort enabled: (action_priority asc, specificity desc)
    enabled_sorted = sorted(
        enabled,
        key=lambda r: (_action_key(r), -_specificity_score(r), (r.get("name") or "")),
    )

    # Preserve order of disabled
    out = enabled_sorted + disabled

    # Add a computed order index for export
    for i, r in enumerate(out, 1):
        r["_proposed_order"] = i

    return out


def generate_migration_plan(rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate a complete migration plan:
      - analysis: issues and stats
      - proposed_order: reordered rule list
      - diff: what changed (rule ID, old position, new position, action)
      - checklist: step-by-step migration checklist
    """
    analysis = analyze_rules(rules)
    reordered = reorder_for_eval_all(list(rules))

    # Build diff map: rule_id -> (old_pos, new_pos)
    orig_by_id = {str(r.get("id", i+1)): i+1 for i, r in enumerate(rules)}
    diff = []
    for new_pos, r in enumerate(reordered, 1):
        rid = str(r.get("id", new_pos))
        old_pos = orig_by_id.get(rid, None)
        if old_pos != new_pos:
            diff.append({
                "rule_id": rid,
                "rule_name": r.get("name", f"Rule {rid}"),
                "action": (r.get("action") or "?").upper(),
                "old_position": old_pos,
                "new_position": new_pos,
                "shift": (old_pos - new_pos) if old_pos else None,
            })

    checklist = [
        "1. Review the analysis below — address WARNING-level issues before migrating.",
        "2. In the Zscaler admin portal, enable audit/log-only mode for all rules that will change action (no enforcement yet).",
        "3. Import the proposed ordering using the exported JSON or manually apply in the portal.",
        "4. Enable 'Evaluate All Rules' in ZIA Advanced Settings → DLP.",
        "5. Monitor logs for 48-72 hours to validate no unintended double-fires or user impact.",
        "6. If issues found, disable 'Evaluate All Rules' and investigate specific rules.",
        "7. When stable, switch audit-only rules back to their intended enforcement action (Block/Confirm/Allow).",
        "8. Document the migration date, test window, and any rule changes for compliance audit.",
    ]

    return {
        "analysis": analysis,
        "proposed_order": reordered,
        "diff": diff,
        "diff_count": len(diff),
        "unchanged_count": len(rules) - len(diff),
        "checklist": checklist,
        "target_mode": "Evaluate All Rules",
        "zscaler_best_practice_reference": "https://help.zscaler.com/zia/about-first-match-wins-and-evaluate-all-rules-for-dlp",
    }


def export_rules(rules: List[Dict[str, Any]], format: str = "json") -> str:
    """Export a list of rules for re-import or backup."""
    import json
    if format == "json":
        # Clean internal fields before export
        clean = []
        for r in rules:
            cr = {k: v for k, v in r.items() if not k.startswith("_")}
            clean.append(cr)
        return json.dumps({"rules": clean, "count": len(clean)}, indent=2, default=str)
    elif format == "csv":
        import csv, io
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["Order", "Rule ID", "Name", "Action", "State", "Scope", "URL Categories", "File Types", "DLP Engines"])
        for i, r in enumerate(rules, 1):
            order = r.get("_proposed_order", i)
            scope = []
            if r.get("users"): scope.append(f"users:{len(r['users'])}")
            if r.get("groups"): scope.append(f"groups:{len(r['groups'])}")
            if r.get("departments"): scope.append(f"depts:{len(r['departments'])}")
            if not scope: scope = ["global"]
            w.writerow([
                order,
                r.get("id", ""),
                r.get("name", ""),
                r.get("action", ""),
                r.get("state", "ENABLED"),
                ",".join(scope),
                ",".join(str(c) for c in (r.get("urlCategories") or [])[:5]),
                ",".join(str(t) for t in (r.get("fileTypes") or [])[:5]),
                ",".join(str((e.get("id") if isinstance(e, dict) else e)) for e in (r.get("dlpEngines") or r.get("engines") or [])[:5]),
            ])
        return buf.getvalue()
    return ""


def import_rules_to_zscaler(client, rules: List[Dict[str, Any]], rule_type: str = "web_dlp", dry_run: bool = True) -> Dict[str, Any]:
    """
    Push rules back to Zscaler in the new order via the API.
    Uses the existing Client from dlp_assessment_full_auto.

    For safety, defaults to dry_run=True (just returns what WOULD be done).
    Set dry_run=False to actually make the changes — requires ENABLE_WRITE_ACTIONS
    env var to be set to "YES_I_UNDERSTAND".
    """
    import os
    if not dry_run and os.environ.get("ENABLE_WRITE_ACTIONS") != "YES_I_UNDERSTAND":
        return {
            "status": "blocked",
            "reason": "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND environment variable for safety.",
            "would_update": len(rules),
        }

    changes = []
    for i, r in enumerate(rules, 1):
        changes.append({
            "action": "reorder",
            "rule_id": r.get("id"),
            "rule_name": r.get("name"),
            "new_order": i,
        })

    if dry_run:
        return {
            "status": "dry_run",
            "rule_type": rule_type,
            "planned_changes": changes,
            "total": len(changes),
            "note": "No changes made. Call with dry_run=False + ENABLE_WRITE_ACTIONS env var to apply.",
        }

    # Actual API writes go here — intentionally minimal to avoid accidents
    return {
        "status": "not_implemented",
        "reason": "Automated rule reordering via API is intentionally limited. Import the exported JSON via the Zscaler admin portal instead.",
        "planned_changes": changes,
    }


def fetch_current_rules(client, rule_type: str = "web_dlp") -> List[Dict[str, Any]]:
    """Fetch the current rule list from Zscaler for the given rule type."""
    endpoint_map = {
        "web_dlp": "/zia/webDlpRules",
        "ssl_inspection": "/zia/sslInspectionRules",
        "url_filtering": "/zia/urlFilteringRules",
        "firewall": "/zia/firewallRules",
        "cloud_app_control": "/zia/cloudApplicationRules",
    }
    endpoint = endpoint_map.get(rule_type, "/zia/webDlpRules")
    data, code = client.get(endpoint)
    if code not in (200, 204):
        return []
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for k in ("list", "data", "items", "rules"):
            if k in data and isinstance(data[k], list):
                return data[k]
    return []


# ════════════════════════════════════════════════════════════════════
# STEP 1 — Assess Current Status
# ════════════════════════════════════════════════════════════════════

def assess_current_status(client) -> Dict[str, Any]:
    """
    Determine whether the tenant is currently in Rule Order or
    Evaluate All Rules mode, and summarize current DLP rule posture.

    Returns:
      {
        "current_mode": "Rule Order" | "Evaluate All Rules" | "Unknown",
        "evaluate_all_enabled": bool | None,
        "rule_count": N,
        "enabled_rules": N,
        "action_breakdown": {...},
        "recommendation": "...",
        "ready_to_migrate": bool,
        "diagnostics": [...]   # what we tried + what we saw
      }
    """
    diagnostics = []
    evaluate_all = None
    found_via = None

    # Try multiple endpoints known to expose this setting
    candidate_endpoints = [
        "/zia/dlpAdvancedSettings",
        "/zia/advancedSettings",
        "/zia/security/advanced",
        "/zia/dlpEvaluateAllRulesSetting",
        "/zia/advancedSettings/dlp",
        "/zia/dlpSettings",
        "/zia/dlp/advancedSettings",
        "/zia/dlp/settings",
        "/zia/configuration/advanced",
    ]
    # Field names vary across API versions / docs
    candidate_fields = [
        "evaluateAllRules", "dlpEvaluateAllRules", "enableDlpEvaluateAllRules",
        "dlpEvaluateAll", "dlpEvaluateAllRulesEnabled",
        "isDlpEvaluateAllRules", "evaluateAllDlpRules",
        "dlpEvalAll", "evalAll", "evaluateAll",
        "enableEvaluateAllRules", "enableEvaluateAllDlpRules",
        "evalAllRulesForDlp", "evaluateAllDlp",
    ]

    for ep in candidate_endpoints:
        try:
            data, code = client.get(ep)
        except Exception as e:
            diagnostics.append({"endpoint": ep, "status": 0, "error": str(e)[:100]})
            continue
        diagnostics.append({
            "endpoint": ep,
            "status": code,
            "type": type(data).__name__,
            "keys": (list(data.keys())[:50] if isinstance(data, dict) else None),
        })
        if code != 200 or not isinstance(data, dict):
            continue
        # Look for any matching field (case-insensitive)
        lower_keys = {k.lower(): k for k in data.keys()}
        for fld in candidate_fields:
            real = lower_keys.get(fld.lower())
            if real is not None:
                evaluate_all = bool(data[real])
                found_via = f"{ep} → {real} = {data[real]}"
                break
        # Also walk one level deep in case it's nested
        if evaluate_all is None:
            for k, v in data.items():
                if isinstance(v, dict):
                    nested_lower = {nk.lower(): nk for nk in v.keys()}
                    for fld in candidate_fields:
                        real = nested_lower.get(fld.lower())
                        if real is not None:
                            evaluate_all = bool(v[real])
                            found_via = f"{ep} → {k}.{real} = {v[real]}"
                            break
                if evaluate_all is not None:
                    break
        # Heuristic: any key with 'evaluate' AND 'all' in its name, boolean value
        if evaluate_all is None:
            for k, v in data.items():
                kl = k.lower()
                if "evaluat" in kl and "all" in kl and isinstance(v, bool):
                    evaluate_all = v
                    found_via = f"{ep} → {k} = {v} (heuristic match)"
                    break
        if evaluate_all is not None:
            break

    # Fallback: check individual rules — some Zscaler tenants expose
    # the toggle as a per-rule field rather than a global setting
    if evaluate_all is None:
        try:
            rules_probe, rcode = client.get("/zia/webDlpRules")
            if rcode == 200 and isinstance(rules_probe, list) and rules_probe:
                sample = rules_probe[0]
                if isinstance(sample, dict):
                    diagnostics.append({
                        "endpoint": "/zia/webDlpRules[0]",
                        "status": rcode,
                        "type": "dict",
                        "keys": list(sample.keys())[:50],
                    })
                    sample_lower = {k.lower(): k for k in sample.keys()}
                    for fld in candidate_fields:
                        real = sample_lower.get(fld.lower())
                        if real is not None:
                            # Per-rule: if any rule has it true, mode is Evaluate All
                            any_true = any(
                                bool(r.get(real)) for r in rules_probe if isinstance(r, dict)
                            )
                            evaluate_all = any_true
                            found_via = f"/zia/webDlpRules[*].{real} (per-rule field; any-true = {any_true})"
                            break
        except Exception as e:
            diagnostics.append({"endpoint": "/zia/webDlpRules", "status": 0, "error": str(e)[:100]})

    mode = ("Evaluate All Rules" if evaluate_all is True
            else "Rule Order" if evaluate_all is False
            else "Unknown")

    # Rule posture
    rules = fetch_current_rules(client, "web_dlp")
    enabled = [r for r in rules if (r.get("state") or "ENABLED").upper() == "ENABLED"]
    actions = {}
    for r in enabled:
        a = (r.get("action") or "?").upper()
        actions[a] = actions.get(a, 0) + 1

    # Is current order already safe for Evaluate All?
    if rules:
        proposed = reorder_for_eval_all(list(rules))
        orig_ids = [str(r.get("id", i+1)) for i, r in enumerate(rules)]
        new_ids = [str(r.get("id", i+1)) for i, r in enumerate(proposed)]
        order_already_safe = orig_ids == new_ids
    else:
        order_already_safe = True

    if evaluate_all is True:
        recommendation = "✅ Tenant is ALREADY in Evaluate All Rules mode. No migration needed — focus on ongoing rule tuning and exception management."
    elif evaluate_all is False and order_already_safe:
        recommendation = "Tenant is in Rule Order mode. Rule order is ALREADY optimal for Evaluate All — safe to enable the feature with low risk."
    elif evaluate_all is False and not order_already_safe:
        recommendation = "Tenant is in Rule Order mode and rule order is NOT yet safe for Evaluate All. Run Step 3 (Optimize) before enabling."
    else:
        # Could not auto-detect. Build a helpful message with what we tried.
        endpoints_hit = [d for d in diagnostics if d.get("status") == 200]
        if endpoints_hit:
            # Show keys from EVERY reachable endpoint to maximize chance of spotting it
            sample_lines = []
            for d in endpoints_hit:
                keys = d.get("keys") or []
                if keys:
                    # Highlight any key containing 'eval', 'dlp', or 'all'
                    interesting = [k for k in keys if any(t in k.lower() for t in ("eval", "dlp", "all", "rule"))]
                    sample_lines.append(
                        f"{d['endpoint']}: {', '.join(interesting[:15]) if interesting else ', '.join(keys[:10])}"
                    )
            recommendation = (
                "⚠ Your tenant's API does not expose the 'Evaluate All DLP Rules' toggle. "
                "This is an account-level feature flag that Zscaler manages — many tenants have it "
                "set only via the admin UI with no read-back endpoint.\n\n"
                f"Reachable settings endpoints and likely-relevant fields:\n• " + "\n• ".join(sample_lines) + "\n\n"
                "📋 What to do:\n"
                "  1. Verify the current mode manually in ZIA Admin → Administration → Advanced Settings → DLP → 'Evaluate All DLP Rules'.\n"
                "  2. Use the 'Declare Mode Manually' selector below to tell the wizard the mode — Steps 2-5 will work normally after that.\n"
                "  3. If you believe your tenant SHOULD expose this via API, open the diagnostics and paste the JSON — Zscaler support can confirm whether the field is available in your API version."
            )
        else:
            recommendation = (
                "Could not reach any ZIA Advanced Settings endpoint. The API client role may not include "
                "'View ZIA Advanced Settings' permission. Verify in ZIA Admin → Administration → Advanced "
                "Settings → DLP → 'Evaluate All DLP Rules', or grant the role and retry."
            )

    return {
        "current_mode": mode,
        "evaluate_all_enabled": evaluate_all,
        "found_via": found_via,
        "rule_count": len(rules),
        "enabled_rules": len(enabled),
        "disabled_rules": len(rules) - len(enabled),
        "action_breakdown": actions,
        "order_already_safe_for_eval_all": order_already_safe,
        "ready_to_migrate": evaluate_all is False,
        "recommendation": recommendation,
        "diagnostics": diagnostics,
    }


# ════════════════════════════════════════════════════════════════════
# STEP 3 — Optimize with Exceptions
# ════════════════════════════════════════════════════════════════════

def optimize_for_eval_all_with_exceptions(
    rules: List[Dict[str, Any]],
    exceptions: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Generate an optimized rule ordering for Evaluate All Rules mode,
    with user-supplied exception handling.

    Exceptions supported:
      {
        "pinned": {"rule_id": "5", "position": 1},  # force specific position
        "skip_rule_ids": ["7", "12"],                # don't reorder these
        "disabled_ok": true,                         # disabled rules stay as-is
        "exempt_groups": ["HR-Benefits-Exception"],  # these groups bypass
        "audit_only_actions": ["BLOCK"],             # convert these to ALERT temporarily
        "keep_original_for_review": true,            # include original in output for diff
      }

    Returns:
      {
        "proposed_rules": [...],          # new ordered list
        "original_rules": [...],          # for diff reference
        "conversions": [...],             # rules whose action was changed to audit
        "exception_applied": {...},       # what exceptions were honored
        "diff": [...],                    # position changes
        "safe_to_import": bool,
      }
    """
    exceptions = exceptions or {}
    original = list(rules)
    working = [dict(r) for r in rules]  # deep-ish copy

    # 1. Apply audit-only conversions for specified actions
    conversions = []
    audit_only = [a.upper() for a in (exceptions.get("audit_only_actions") or [])]
    for r in working:
        act = (r.get("action") or "").upper()
        if act in audit_only:
            r["_original_action"] = act
            r["action"] = "ALERT"  # audit-only without enforcement
            conversions.append({
                "rule_id": r.get("id"),
                "rule_name": r.get("name", "?"),
                "from": act,
                "to": "ALERT",
                "reason": "User requested audit-only during migration",
            })

    # 2. Auto-reorder
    reordered = reorder_for_eval_all(list(working))

    # 3. Apply pinned positions (force a specific rule to a specific position)
    pinned = exceptions.get("pinned") or {}
    if pinned.get("rule_id") and pinned.get("position"):
        target_id = str(pinned["rule_id"])
        target_pos = max(1, int(pinned["position"])) - 1
        idx = None
        for i, r in enumerate(reordered):
            if str(r.get("id")) == target_id:
                idx = i
                break
        if idx is not None:
            rule = reordered.pop(idx)
            reordered.insert(min(target_pos, len(reordered)), rule)

    # 4. Honor skip list (leave these rules in their original position)
    skip_ids = {str(x) for x in (exceptions.get("skip_rule_ids") or [])}
    if skip_ids:
        # Build final: keep skipped at original positions, fill others around
        skipped = [(i, r) for i, r in enumerate(original) if str(r.get("id")) in skip_ids]
        others = [r for r in reordered if str(r.get("id")) not in skip_ids]
        final = list(others)
        for orig_pos, rule in skipped:
            insert_at = min(orig_pos, len(final))
            final.insert(insert_at, rule)
        reordered = final

    # 5. Add proposed order index for export
    for i, r in enumerate(reordered, 1):
        r["_proposed_order"] = i

    # Compute diff
    orig_positions = {str(r.get("id", i+1)): i+1 for i, r in enumerate(original)}
    diff = []
    for new_pos, r in enumerate(reordered, 1):
        rid = str(r.get("id", new_pos))
        old_pos = orig_positions.get(rid)
        if old_pos != new_pos:
            diff.append({
                "rule_id": rid,
                "rule_name": r.get("name", f"Rule {rid}"),
                "action": (r.get("action") or "?").upper(),
                "old_position": old_pos,
                "new_position": new_pos,
            })

    # Safety check: any BLOCK after ALLOW under Evaluate All is fine, but
    # a rule with _original_action flagged means we need user review
    safe = not conversions  # conversions require manual review before import

    return {
        "proposed_rules": reordered,
        "original_rules": original,
        "conversions": conversions,
        "exceptions_applied": exceptions,
        "diff": diff,
        "diff_count": len(diff),
        "conversion_count": len(conversions),
        "safe_to_import": safe,
        "notes": [
            "Review the diff below — each shift preserves scope semantics but changes first-match behavior.",
            "If conversions are listed, those rules are TEMPORARILY in audit-only. Revert after validation.",
            "Export the plan (Step 2) for backup before posting (Step 5).",
        ] + (["⚠ Audit-only conversions require manual revert after migration window."] if conversions else []),
    }


# ════════════════════════════════════════════════════════════════════
# STEP 4 — Enable Evaluate All Rules
# ════════════════════════════════════════════════════════════════════

def enable_evaluate_all_rules(client, dry_run: bool = True) -> Dict[str, Any]:
    """
    Toggle 'Evaluate All DLP Rules' ON via the ZIA API.

    Strategy:
      1. Run the same probe as Step 1 to find the field in GET responses.
      2. If found, GET → modify → PUT to the same endpoint.
      3. If not found, try each candidate endpoint + field combination
         with a real PUT, verifying via follow-up GET.
      4. Every attempt is recorded in `attempts[]` so auditors (and
         future debuggers) see exactly what was tried.

    SAFETY:
      - dry_run=True (default) returns the plan only.
      - dry_run=False + ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND is required
        to actually call PUT.
    """
    import os
    # Use the same comprehensive probe as Step 1 to find current state
    status = assess_current_status(client)
    current = status.get("evaluate_all_enabled")
    found_via = status.get("found_via")

    if current is True:
        return {
            "status": "already_enabled",
            "current": current,
            "message": "Evaluate All Rules is already enabled. No change needed.",
        }

    if dry_run:
        plan_source = found_via or "(field not in GET response — will attempt blind PUT on candidate endpoints)"
        return {
            "status": "dry_run",
            "current": current,
            "would_enable": True,
            "plan_source": plan_source,
            "message": (
                f"DRY RUN: Would enable Evaluate All DLP Rules. "
                f"Plan source: {plan_source}. "
                f"Set ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND and click Activate to apply."
            ),
        }

    if os.environ.get("ENABLE_WRITE_ACTIONS") != "YES_I_UNDERSTAND":
        return {
            "status": "blocked",
            "reason": "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND (relaunch via START_Zscaler_Assessment_WRITES_ENABLED.bat).",
            "current": current,
        }

    # ── Real activation path ─────────────────────────────────────
    attempts: List[Dict[str, Any]] = []

    # Same candidate lists used by assess_current_status
    candidate_endpoints = [
        "/zia/dlpAdvancedSettings",
        "/zia/advancedSettings",
        "/zia/security/advanced",
        "/zia/dlpEvaluateAllRulesSetting",
        "/zia/advancedSettings/dlp",
        "/zia/dlpSettings",
        "/zia/dlp/advancedSettings",
        "/zia/dlp/settings",
        "/zia/configuration/advanced",
    ]
    candidate_fields = [
        "evaluateAllRules", "dlpEvaluateAllRules", "enableDlpEvaluateAllRules",
        "dlpEvaluateAll", "dlpEvaluateAllRulesEnabled",
        "isDlpEvaluateAllRules", "evaluateAllDlpRules",
        "dlpEvalAll", "evalAll", "evaluateAll",
        "enableEvaluateAllRules", "enableEvaluateAllDlpRules",
        "evalAllRulesForDlp", "evaluateAllDlp",
    ]

    def _try_put(endpoint: str, field: str) -> Tuple[bool, Dict[str, Any]]:
        """GET the endpoint, inject field=True, PUT, verify via re-GET.
        Returns (success, attempt_record)."""
        rec: Dict[str, Any] = {"endpoint": endpoint, "field": field}
        try:
            current_data, code = client.get(endpoint)
        except Exception as e:
            rec["phase"] = "get"; rec["error"] = str(e)[:150]
            return False, rec
        rec["get_status"] = code
        if code != 200 or not isinstance(current_data, dict):
            rec["phase"] = "get"; rec["skip_reason"] = "non-200 or not dict"
            return False, rec
        # Merge — preserve every other setting on the endpoint
        new_body = dict(current_data)
        new_body[field] = True
        try:
            resp, put_code = client.put(endpoint, new_body)
        except Exception as e:
            rec["phase"] = "put"; rec["error"] = str(e)[:150]
            return False, rec
        rec["put_status"] = put_code
        if put_code not in (200, 201, 204):
            rec["put_error"] = (resp.get("error") if isinstance(resp, dict) else str(resp)[:200])
            return False, rec
        # Verify via re-GET — drop cache so we don't read a stale value
        try:
            client._c = type(client._c)()  # reset LRU cache
        except Exception:
            pass
        try:
            verified, vcode = client.get(endpoint)
        except Exception as e:
            rec["phase"] = "verify"; rec["error"] = str(e)[:150]
            return False, rec
        rec["verify_status"] = vcode
        rec["verify_value"] = verified.get(field) if isinstance(verified, dict) else None
        if isinstance(verified, dict) and bool(verified.get(field)) is True:
            return True, rec
        # PUT succeeded but field didn't stick — still record
        return False, rec

    # Strategy 1: use found_via if available
    if found_via:
        # found_via format: "/zia/advancedSettings → fieldName = value"
        try:
            ep_part, field_part = found_via.split("→", 1)
            endpoint = ep_part.strip()
            field = field_part.split("=", 1)[0].strip().split(".", 1)[-1].strip()
            ok, rec = _try_put(endpoint, field)
            attempts.append(rec)
            if ok:
                return {
                    "status": "activated",
                    "via": endpoint,
                    "field": field,
                    "attempts": attempts,
                    "message": f"✓ Evaluate All DLP Rules enabled via PUT {endpoint} → {field}=true (verified).",
                }
        except Exception as e:
            attempts.append({"phase": "parse_found_via", "error": str(e)[:150], "found_via": found_via})

    # Strategy 2: exhaustive probe — try every candidate endpoint and
    # every candidate field. No early termination on 400/422 since some
    # tenants reject SOME fields and accept OTHERS on the same endpoint.
    seen_eps: set = set()
    for endpoint in candidate_endpoints:
        if endpoint in seen_eps:
            continue
        seen_eps.add(endpoint)
        try:
            data, code = client.get(endpoint)
        except Exception as e:
            attempts.append({"endpoint": endpoint, "phase": "discover", "error": str(e)[:150]})
            continue
        if code != 200 or not isinstance(data, dict):
            attempts.append({"endpoint": endpoint, "phase": "discover",
                             "get_status": code, "skip_reason": f"non-200 or not dict"})
            continue
        # Record that this endpoint was reachable so the user sees it in diagnostics
        attempts.append({"endpoint": endpoint, "phase": "discover",
                         "get_status": code, "keys_count": len(data),
                         "keys_sample": list(data.keys())[:15]})
        for field in candidate_fields:
            ok, rec = _try_put(endpoint, field)
            attempts.append(rec)
            if ok:
                return {
                    "status": "activated",
                    "via": endpoint,
                    "field": field,
                    "attempts": attempts,
                    "message": f"✓ Evaluate All DLP Rules enabled via PUT {endpoint} → {field}=true (verified after blind-probe).",
                }

    # Strategy 3: last-resort — some tenants expose this only through a
    # targeted sub-resource. Try POSTing / PATCHing with just the field
    # and see if anything accepts it.
    for endpoint in ("/zia/advancedSettings", "/zia/dlpSettings", "/zia/dlpAdvancedSettings"):
        for field in candidate_fields:
            rec = {"endpoint": endpoint, "field": field, "phase": "patch"}
            try:
                resp, code = client.put(endpoint, {field: True})
                rec["put_status"] = code
            except Exception as e:
                rec["error"] = str(e)[:150]
                attempts.append(rec); continue
            if code in (200, 201, 204):
                # Verify
                try:
                    client._c = type(client._c)()
                    verified, vcode = client.get(endpoint)
                    rec["verify_status"] = vcode
                    rec["verify_value"] = verified.get(field) if isinstance(verified, dict) else None
                    if isinstance(verified, dict) and bool(verified.get(field)) is True:
                        attempts.append(rec)
                        return {"status": "activated", "via": endpoint, "field": field,
                                "attempts": attempts,
                                "message": f"✓ Enabled via PATCH-style PUT {endpoint} (minimal body) → {field}=true."}
                except Exception as e:
                    rec["verify_error"] = str(e)[:150]
            attempts.append(rec)

    return {
        "status": "failed",
        "current": current,
        "attempts": attempts,
        "summary": {
            "total_attempts":    len(attempts),
            "discover_reachable": sum(1 for a in attempts if a.get("phase") == "discover" and a.get("get_status") == 200),
            "put_200":           sum(1 for a in attempts if a.get("put_status") in (200, 201, 204)),
            "put_400_or_422":    sum(1 for a in attempts if a.get("put_status") in (400, 422)),
            "put_401_or_403":    sum(1 for a in attempts if a.get("put_status") in (401, 403)),
            "put_404":           sum(1 for a in attempts if a.get("put_status") == 404),
        },
        "message": (
            f"Exhausted {len(attempts)} attempts — none enabled the toggle. "
            "Paste the attempts list into a Zscaler support ticket; they can tell you "
            "which endpoint/field your tenant actually exposes (or enable it for you)."
        ),
    }


# ════════════════════════════════════════════════════════════════════
# STEP 4b — Delete All Existing Rules (optional, gated)
# ════════════════════════════════════════════════════════════════════

def delete_all_rules(client, dry_run: bool = True) -> Dict[str, Any]:
    """
    Delete every Inline Web DLP rule in the tenant. Used when the
    migration plan is to wipe + repost a fresh optimized set under
    Evaluate All Rules mode, avoiding any merge / order conflicts.

    SAFETY:
      - Default is dry_run=True (returns the list it would delete).
      - Real delete requires dry_run=False AND env var
        ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND.
      - Always run Step 2 (Download) first to keep a backup.
    """
    import os
    rules = fetch_current_rules(client, "web_dlp")
    plan = [
        {"rule_id": r.get("id"), "rule_name": r.get("name", f"Rule {r.get('id')}"),
         "action": (r.get("action") or "?").upper(),
         "state": (r.get("state") or "ENABLED").upper()}
        for r in rules
    ]

    if dry_run:
        return {
            "status": "dry_run",
            "would_delete_count": len(plan),
            "would_delete": plan,
            "message": (
                f"DRY RUN: Would delete {len(plan)} Inline Web DLP rules. "
                "Make sure you ran Step 2 first to back them up. "
                "Set dry_run=false (and ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND) to actually delete."
            ),
            "warning": "This is destructive and cannot be undone via API — restore requires re-posting from your backup.",
        }

    if os.environ.get("ENABLE_WRITE_ACTIONS") != "YES_I_UNDERSTAND":
        return {
            "status": "blocked",
            "reason": "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND environment variable.",
            "would_delete_count": len(plan),
        }

    deleted, failed = [], []
    for r in rules:
        rid = r.get("id")
        if rid is None:
            failed.append({"rule_name": r.get("name"), "reason": "missing id"})
            continue
        try:
            _, code = client.delete(f"/zia/webDlpRules/{rid}") if hasattr(client, "delete") else (None, 0)
            if code in (200, 204):
                deleted.append({"rule_id": rid, "rule_name": r.get("name")})
            else:
                failed.append({"rule_id": rid, "rule_name": r.get("name"), "http_status": code})
        except Exception as e:
            failed.append({"rule_id": rid, "rule_name": r.get("name"), "error": str(e)[:200]})

    return {
        "status": "completed" if not failed else "partial",
        "deleted_count": len(deleted),
        "failed_count": len(failed),
        "deleted": deleted,
        "failed": failed,
    }


# ════════════════════════════════════════════════════════════════════
# STEP 5 — Post New Rules
# ════════════════════════════════════════════════════════════════════

def post_new_rule_order(
    client,
    proposed_rules: List[Dict[str, Any]],
    dry_run: bool = True,
    mode: str = "auto",
) -> Dict[str, Any]:
    """
    Push the proposed rules back to Zscaler.

    mode:
      - "auto"   : if rule has an id and exists in tenant, PUT (update order); else POST (create)
      - "create" : always POST (use after delete-all)
      - "update" : always PUT (preserve ids — re-order existing rules in place)

    SAFETY: Requires ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND env var
    AND dry_run=False to actually write. Default is dry-run.
    """
    import os
    plan = []
    for new_pos, r in enumerate(proposed_rules, 1):
        rid = r.get("id")
        action_op = "POST" if mode == "create" or (mode == "auto" and rid is None) else "PUT"
        plan.append({
            "rule_id": rid,
            "rule_name": r.get("name", f"Rule {rid or new_pos}"),
            "new_order": new_pos,
            "action": (r.get("action") or "?").upper(),
            "operation": action_op,
        })

    if dry_run:
        return {
            "status": "dry_run",
            "mode": mode,
            "planned_updates": plan,
            "total": len(plan),
            "message": (
                f"DRY RUN: Would {('create' if mode=='create' else 'update/create')} {len(plan)} DLP rules in the new order. "
                "Set ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND and dry_run=false to apply."
            ),
            "recommendation": "Best practice: keep a JSON backup from Step 2 before running with dry_run=false.",
        }

    if os.environ.get("ENABLE_WRITE_ACTIONS") != "YES_I_UNDERSTAND":
        return {
            "status": "blocked",
            "reason": "Write actions require ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND environment variable.",
            "planned_updates": plan,
        }

    succeeded, failed = [], []
    for new_pos, r in enumerate(proposed_rules, 1):
        rid = r.get("id")
        body = {k: v for k, v in r.items() if not k.startswith("_")}
        body["order"] = new_pos
        try:
            if mode == "create" or (mode == "auto" and rid is None):
                # Strip id so server assigns a new one
                body.pop("id", None)
                data, code = client.post("/zia/webDlpRules", body)
                op = "POST"
            else:
                data, code = client.put(f"/zia/webDlpRules/{rid}", body)
                op = "PUT"
            if code in (200, 201, 204):
                succeeded.append({"rule_id": rid or (data or {}).get("id"),
                                  "rule_name": r.get("name"), "operation": op,
                                  "new_order": new_pos, "http_status": code})
            else:
                failed.append({"rule_id": rid, "rule_name": r.get("name"),
                               "operation": op, "http_status": code,
                               "error": (data or {}).get("error") if isinstance(data, dict) else str(data)[:200]})
        except Exception as e:
            failed.append({"rule_id": rid, "rule_name": r.get("name"),
                           "error": str(e)[:200]})

    return {
        "status": "completed" if not failed else "partial",
        "mode": mode,
        "succeeded_count": len(succeeded),
        "failed_count": len(failed),
        "succeeded": succeeded,
        "failed": failed,
    }
