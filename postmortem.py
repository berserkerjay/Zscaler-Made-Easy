"""Incident postmortem generator: a template report for a chosen time window.

Built from the app's own records only (its audit log and deployment history,
through audit_timeline.build), so it reads no tenant and writes nothing. The
report has the usual postmortem sections (summary, timeline, changes by
others, gaps to fill in by hand). People are counted in the summary; the
timeline names the admin who acted because a postmortem needs it, and the
Markdown and CSV exports are escaped (md_safe, csv_safe).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

import audit_timeline as at
import md_safe

MAX_TIMELINE = 500
TEMPLATE_PROMPTS = ("Impact (who and what was affected):", "Root cause:", "Detection (how and when it was noticed):",
                    "Resolution:", "Follow-up actions (owner, due date):")


def generate(*, window_: Dict[str, Any], deployments: List[Dict[str, Any]], audit_entries: List[Dict[str, Any]],
             labels: Optional[Iterable[str]] = None, title: str = "Incident postmortem") -> Dict[str, Any]:
    tl = at.build(window_=window_, zia=None, deployments=deployments, audit_entries=audit_entries, labels=labels,
                  zia_requested=False, zia_reason="The ZIA admin audit log is not part of this report: only Zscaler Made Easy's own records.")
    events = tl["events"]
    by_action: Dict[str, int] = {}
    for e in events:
        k = str(e.get("action") or "other")[:80]
        by_action[k] = by_action.get(k, 0) + 1
    return {"title": title, "window": tl["window"], "summary": tl["summary"],
            "people": len({e.get("admin") for e in events if e.get("admin")}),
            "by_action": dict(sorted(by_action.items(), key=lambda kv: -kv[1])[:20]),
            "timeline": sorted(events, key=lambda e: e.get("ts") or 0)[:MAX_TIMELINE],
            "changed_by_others": [e for e in events if e.get("foreign_change")][:100],
            "notes": tl["notes"], "template": list(TEMPLATE_PROMPTS)}


def to_markdown(rep: Dict[str, Any]) -> str:
    t = md_safe.text
    w = rep["window"]
    s = rep["summary"]
    out = [f"# {t(rep['title'])}", "", f"Window: {t(w.get('start', ''))} to {t(w.get('end', ''))}", "",
           "## Summary", "", f"- Events: {s['events']} (app {s['app']}, deployments {s['deployment']})",
           f"- Admins involved: {rep['people']}", f"- Changes by someone else to objects the app created: {s['foreign_changes']}", ""]
    if rep["by_action"]:
        out += ["## Events by action", ""] + [f"- {t(k)}: {v}" for k, v in rep["by_action"].items()] + [""]
    out += ["## Timeline (oldest first)", "", "| Time | Source | Admin | Action | Object | Result |", "|---|---|---|---|---|---|"]
    for e in rep["timeline"]:
        out.append("| " + " | ".join(t(e.get(k) or "") for k in ("time", "source_label", "admin", "action", "object", "result")) + " |")
    if rep["changed_by_others"]:
        out += ["", "## Changed by someone else", ""] + [f"- {t(e.get('time') or '')}: {t(e.get('object') or '')} ({t(e.get('foreign_reason') or '')})"
                                                         for e in rep["changed_by_others"]]
    if rep["notes"]:
        out += ["", "## Notes", ""] + [f"- {t(n)}" for n in rep["notes"]]
    out += ["", "## To fill in", ""]
    for p in rep["template"]:
        out += [f"### {p}", "", "_TBD_", ""]
    return "\n".join(out)


def to_csv(rep: Dict[str, Any]) -> str:
    return at.to_csv(rep["timeline"])
