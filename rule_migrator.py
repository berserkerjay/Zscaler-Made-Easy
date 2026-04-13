#!/usr/bin/env python3
"""
Zscaler Rule Migration Helper — Evaluate All Rules Mode
=========================================================
Helps migrate DLP and Cloud App Control rules from First-Match-Wins
to Evaluate All Rules mode by:

1. Analyzing current rules for conflicts, shadowing, redundancy
2. Generating a safe reorder that preserves intended behavior under
   Evaluate All Rules mode
3. Exporting rules in API-importable format
4. Optionally pushing the new ordering back to Zscaler

Zscaler Best Practice for Evaluate All Rules mode:
- Block/Deny rules first (most restrictive)
- Confirm/Prompt rules next (user-coaching)
- Allow rules last (least restrictive)
- Within each action tier: most specific scope first
- Remove redundant rules that would double-fire
- Run in audit mode before enforcement
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
                "message": "Under First-Match-Wins this Allow rule stops evaluation; under Evaluate All it has no suppressive effect. Consider consolidating or removing.",
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
