"""Channel ownership, declared on the Scope page, applied to the assessment.

The Scope page lists the Zscaler data-security channels (Inline Web DLP,
Endpoint DLP, Email DLP, ...) and the operator marks each one:

- **zscaler**: the customer runs it on Zscaler. Its checks run as usual.
- **alternative**: another product covers it. Its checks are not run: the
  tenant is not read for them and each is reported as *Not in scope*,
  outside the score, with the vendor note when one was typed. Scoring a
  customer's Zscaler tenant for a channel they knowingly bought elsewhere
  would only produce noise.
- **gap** (not addressed): nothing covers it. Its checks run exactly as
  before, because the findings are the evidence of the gap.

The declaration travels with the assessment request (`channels`), is
saved on the tenant profile, and comes back in the report as
`channel_coverage` so the dashboard, the JSON export and the Word report
say the same thing. Only the *alternative* choice changes what runs."""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

CHOICES = ("zscaler", "alternative", "gap")

# The Scope page's channels (dashboard.js carries their descriptions).
CHANNELS: Dict[str, str] = {
    "web_dlp": "Inline Web DLP",
    "endpoint_dlp": "Endpoint DLP",
    "email_dlp": "Email DLP",
    "saas_casb": "SaaS Security (CASB)",
    "genai_security": "GenAI Security",
    "shadow_it": "Shadow IT Discovery",
    "endpoint_scan": "Endpoint Data Scan",
    "ssl_inspection": "SSL/TLS Inspection",
    "cloud_app_control": "Cloud App Control",
    "device_control": "Device Control",
    "workflow_automation": "Workflow Automation",
}

# Which checks read each channel: whole sections (matched on the section
# name's start) and single check ids. Deliberately narrow: "5 — Endpoint
# DLP" is really the general DLP section (dictionaries, engines, EDM, IDM,
# web DLP rules) despite its name, so only its ZDP-install check belongs
# to the Endpoint DLP channel. A channel with no entry (Shadow IT
# Discovery) is recorded in the report but changes nothing that runs.
CHANNEL_CHECKS: Dict[str, Dict[str, Sequence[str]]] = {
    "web_dlp": {"sections": ("Ch.A — Inline Web",), "ids": ("MC.1", "8.5")},
    "endpoint_dlp": {"sections": ("Ch.B — Endpoint",), "ids": ("5.1", "MC.2", "MC.8", "8.1", "8.2", "8.3")},
    "email_dlp": {"sections": ("Ch.D — Email DLP",), "ids": ("MC.4", "MC.9", "8.9")},
    "saas_casb": {"sections": ("Ch.C — SaaS Security",), "ids": ("MC.3", "MC.10", "8.10")},
    "genai_security": {"sections": ("Ch.E — GenAI", "GenAI —"), "ids": ("MC.7", "8.8")},
    "shadow_it": {"sections": (), "ids": ()},
    "endpoint_scan": {"sections": (), "ids": ("MC.6", "MC.11")},
    "ssl_inspection": {"sections": ("4 — SSL Policy", "7 — SSL Alignment", "GenAI — SSL Inspection"), "ids": ("5.5", "CA.3", "E.2")},
    "cloud_app_control": {"sections": ("ZIA — Cloud Apps",), "ids": ("E.3",)},
    "device_control": {"sections": (), "ids": ("8.1",)},
    "workflow_automation": {"sections": (), "ids": ("12.4", "12.5", "12.7")},
}


def normalize(channels: Any) -> Dict[str, Dict[str, str]]:
    """{id: {choice, note, name}} from whatever the browser or a profile
    sent. Unknown choices read as a gap; custom channels are kept by id."""
    out: Dict[str, Dict[str, str]] = {}
    if not isinstance(channels, dict):
        return out
    for cid, v in channels.items():
        cid = str(cid).strip()[:64]
        if not cid:
            continue
        if isinstance(v, str):
            v = {"choice": v}
        if not isinstance(v, dict):
            continue
        choice = str(v.get("choice") or "gap").strip().lower()
        if choice not in CHOICES:
            choice = "gap"
        out[cid] = {"choice": choice, "note": str(v.get("note") or "").strip()[:200],
                    "name": str(v.get("name") or CHANNELS.get(cid) or cid).strip()[:80]}
    return out


def _matches(spec: Dict[str, Sequence[str]], check_id: str, section: str) -> bool:
    if check_id in spec.get("ids", ()):
        return True
    return any(section == s or section.startswith(s) for s in spec.get("sections", ()))


def channel_of_check(check_id: str, section: str, channels: Dict[str, Dict[str, str]]) -> Optional[str]:
    """The first of `channels` whose checks include this one, else None."""
    for cid in channels:
        spec = CHANNEL_CHECKS.get(cid)
        if spec and _matches(spec, str(check_id), str(section or "")):
            return cid
    return None


def skipped_result(check_id: str, section: str, label: str, cid: str, ch: Dict[str, str]) -> Dict[str, Any]:
    """The result a not-run check is reported with: INFO, flagged out of
    scope, saying which channel and why. It carries its own plain-English
    block so the findings row explains itself."""
    note = f" ({ch['note']})" if ch.get("note") else ""
    name = ch.get("name") or CHANNELS.get(cid) or cid
    return {
        "id": check_id, "section": section, "label": label, "status": "INFO",
        "detail": (f"Not in scope: {name} is covered by an alternative solution{note}, as declared on the Scope page. "
                   "The tenant was not read for this check and it is outside the score."),
        "out_of_scope": True, "channel": cid,
        "plain": {"found": f"Not read: {name} is covered outside Zscaler{note}.",
                  "means": "", "do": "",
                  "outcome": "Declared on the Scope page. Mark the channel as Zscaler there and run again to assess it."},
    }


def partition(checks: Sequence[Tuple], channels: Any) -> Tuple[List[Tuple], List[Dict[str, Any]], List[Tuple[str, int]]]:
    """Split the check tuples (id, section, label, fn) into the ones to run
    and the results of the ones declared out of scope, plus the order to
    merge them back in (`merge`) so the findings keep their section order."""
    alt = {k: v for k, v in normalize(channels).items() if v["choice"] == "alternative"}
    to_run: List[Tuple] = []
    skipped: List[Dict[str, Any]] = []
    order: List[Tuple[str, int]] = []
    for chk in checks:
        check_id, section, label = str(chk[0]), str(chk[1]), str(chk[2])
        cid = channel_of_check(check_id, section, alt) if alt else None
        if cid:
            order.append(("skip", len(skipped)))
            skipped.append(skipped_result(check_id, section, label, cid, alt[cid]))
        else:
            order.append(("run", len(to_run)))
            to_run.append(chk)
    return to_run, skipped, order


def merge(order: Iterable[Tuple[str, int]], run_results: Sequence[Dict[str, Any]], skipped: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [run_results[i] if kind == "run" else skipped[i] for kind, i in order]


def coverage(channels: Any, skipped: Iterable[Dict[str, Any]] = ()) -> Dict[str, Any]:
    """What was declared and what it did, for the report: the channels on
    Zscaler, the ones covered elsewhere (with how many checks that took
    out of scope), the gaps, and one sentence that says it."""
    ch = normalize(channels)
    skipped = list(skipped)
    per: Dict[str, int] = {}
    for r in skipped:
        per[str(r.get("channel"))] = per.get(str(r.get("channel")), 0) + 1
    by: Dict[str, List[Dict[str, Any]]] = {"zscaler": [], "alternative": [], "gap": []}
    for cid, v in ch.items():
        by[v["choice"]].append({"id": cid, "name": v["name"], "note": v["note"], "checks_not_in_scope": per.get(cid, 0)})
    declared = bool(ch)
    if not declared:
        note = "No channel ownership was declared on the Scope page: every check in the selected scopes ran."
    else:
        names = lambda rows: ", ".join(r["name"] + (f" ({r['note']})" if r["note"] else "") for r in rows)  # noqa: E731
        parts = [f"{len(by['zscaler'])} on Zscaler" + (f" ({names(by['zscaler'])})" if by["zscaler"] else "")]
        parts.append(f"{len(by['alternative'])} covered by an alternative solution"
                     + (f" ({names(by['alternative'])}; {len(skipped)} checks not in scope)" if by["alternative"] else ""))
        parts.append(f"{len(by['gap'])} gap{'' if len(by['gap']) == 1 else 's'}" + (f" ({names(by['gap'])})" if by["gap"] else ""))
        note = "Channels as declared on the Scope page: " + "; ".join(parts) + "."
    return {"declared": declared, "zscaler": by["zscaler"], "alternative": by["alternative"], "gaps": by["gap"],
            "not_in_scope": len(skipped), "note": note}
