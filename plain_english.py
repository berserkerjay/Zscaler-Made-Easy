"""One plain-English block for every finding, in every output.

A check result is a status and a detail string written for an engineer.
`explain()` turns it into four sentences a first-week engineer can read
to a customer, and every output (the results tab, the JSON, the Word
report, the digest) uses the same four:

    found    what we found, in one sentence
    means    what it means for the business (risk, cost, audit)
    do       what to do next, concretely
    outcome  the business outcome once it is fixed (consistent per area,
             so the same control reads the same everywhere)

The "why it matters" and "what to do" sentences reuse the generators the
Word report has always had; the outcome comes from one table per area
of the product, so it is consistent across checks and outputs.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Tuple

# The business outcome per area. Matched as case-insensitive substrings
# against the check's section and id prefix; the first hit wins, so the
# more specific entries come first.
OUTCOMES: List[Tuple[Tuple[str, ...], str]] = [
    (("tenant health", "hlt."), "Saved changes are activated and certificates are renewed before they expire, so the policy that runs is the policy you configured."),
    (("insights", "ins."), "Every cloud application in use has an owner's decision, risky ones are stopped, and sanctioned ones holding company data are scanned."),
    (("cloud & branch connector", "ztw."), "Workload traffic from clouds and branches reaches Zscaler through healthy, redundant connectors and is inspected, never sent around it."),
    (("ch.c", "c.", "saas security"), "Sensitive files stored and shared in SaaS applications are found, and exposure is removed before it becomes a breach."),
    (("ch.d", "d.", "email dlp"), "Sensitive data cannot leave by email without being seen, and the right mail is stopped before it reaches the wrong recipient."),
    (("incident mgmt", "12."), "Every incident reaches an analyst with the evidence, in time to act, and an auditor can see it was handled."),
    # The other products first: their sections name no channel word, but keep them apart from the rest.
    (("zero trust branch", "ztb."), "Branch offices reach the internet and each other only through Zscaler, and a compromised device cannot spread across the site."),
    (("external attack surface", "easm."), "What the organization exposes on the internet is known and fixed before an attacker finds it."),
    (("business insights", "zbi."), "The business sees which applications it pays for and uses, so licences and risk are decided on facts."),
    (("zero trust cellular", "zcell."), "SIM-connected devices are inspected like any other device, and a SIM that wanders is noticed."),
    (("microsegmentation", "zms."), "A compromised server cannot reach the rest of the data centre: only the connections a rule names are allowed."),
    (("pilot tests", "8."), "The controls are proven to work on real traffic before the customer relies on them."),
    (("troubleshooting", "9."), "Problems are found and fixed before users notice them."),
    (("rollback", "11."), "A change can be undone quickly, so the team can act without fear of breaking the business."),
    (("bypass inventory", "2."), "Every exception is known and justified, so there is no traffic the customer believes is inspected but is not."),
    (("ssl", "4.", "7."), "Encrypted traffic is inspected, so the DLP and threat controls see what users actually send."),
    (("genai", "ch.e", "e.", "ai."), "Employees use AI tools without leaking customer data, source code or secrets, and the business can prove it."),
    (("ch.a", "a.", "inline web"), "Sensitive data cannot be uploaded to the web without being seen, and the right rule wins every time."),
    # Before Ch.B's "endpoint": section "5 — Endpoint DLP" (rules,
    # dictionaries, EDM, IDM) would otherwise read as the endpoint channel.
    (("endpoint dlp", "5."), "Sensitive data is detected accurately before it leaves, with few false alarms and every incident worth an analyst's time."),
    (("ch.b", "b.", "endpoint"), "Sensitive data cannot leave through USB, print, shares or personal cloud without being seen."),
    (("multi-channel", "mc."), "The same protection on every channel, so a gap on one is not a way around the others."),
    (("cc portal", "app profile", "versions", "macos", "zcc", "1.", "3.", "6.", "10."), "Every device is protected wherever it works, and nobody can switch that protection off."),
    (("firewall",), "Non-web traffic is controlled too, so nothing slips out over a port the web policy never sees."),
    (("url filtering", "cloud apps"), "Risky destinations and applications are controlled before content inspection is even needed."),
    (("security",), "Threats are stopped at the cloud edge, before they reach a user or a device."),
    (("bandwidth",), "Business applications get the capacity they need and recreational traffic does not starve them."),
    (("zia — forwarding", "fwd."), "Traffic always takes the path the policy expects, with a working fallback, so an outage or a forgotten exception never lets it out uninspected."),
    (("locations",), "Every office and every user is sent to the cloud the same way, with the same policy."),
    (("governance", "gov."), "Problems are reported to people who act on them, logs leave the console for the SIEM, and Zscaler's own audit of the tenant comes back clean."),
    (("users & admin", "rbac", "zidentity", "zid.", "rbac."), "Only the right people can change the security policy, and every change is traceable to a person."),
    (("zpa",), "Private applications are reachable only by the right user on a trusted device, never by the network."),
    (("zdx",), "The user experience is measured, so a slow application is located and fixed instead of blamed on Zscaler."),
    (("automation", "auto-"), "The policy is code: repeatable, reviewable and recoverable, with no hand-made drift."),
]
FALLBACK_OUTCOME = "The tenant matches Zscaler's documented best practice, so the control delivers what the customer is paying for."


def outcome_for(check_id: str, section: str) -> str:
    sec = (section or "").lower()
    cid = (check_id or "").lower()
    for keys, text in OUTCOMES:
        for k in keys:
            if k.endswith(".") and cid.startswith(k):
                return text
            if not k.endswith(".") and k in sec:
                return text
    return FALLBACK_OUTCOME


def _status_word(status: str) -> str:
    s = (status or "").upper()
    return {"PASS": "configured", "FAIL": "action required", "WARN": "needs review", "REVIEW": "needs review", "INFO": "not configured", "ERROR": "could not be checked"}.get(s, s.lower())


def _not_permitted(detail: str) -> bool:
    """The same rule permissions.classify uses for a refused read."""
    try:
        from permissions import is_denied
        return bool(is_denied(detail))
    except Exception:  # noqa: BLE001 - never let the explanation break a result
        return False


def _first_sentence(text: str, limit: int = 220) -> str:
    t = re.sub(r"\s+", " ", (text or "")).strip()
    if not t:
        return ""
    m = re.match(r"(.+?[.!?])(\s|$)", t)
    t = m.group(1) if m else t
    return t if len(t) <= limit else t[: limit - 1] + "…"


def explain(check: Dict[str, Any]) -> Dict[str, str]:
    """The four sentences for one check result ({id, section|sec, label, status, detail})."""
    try:
        from report_docx import _generate_recommendation, _generate_why_it_matters, _parse_detail_for_bp, _resolve_best_practice, _resolve_remediation
    except Exception:  # noqa: BLE001 - python-docx missing: keep the app working without the generators
        _parse_detail_for_bp = lambda d: (d or "", "")   # type: ignore
        _resolve_best_practice = lambda l, s, i: ""      # type: ignore
        _generate_why_it_matters = lambda **k: ""        # type: ignore
        _generate_recommendation = lambda **k: ""        # type: ignore
        _resolve_remediation = lambda l, s, i: ("", "")  # type: ignore
    cid = str(check.get("id") or "")
    section = str(check.get("section") or check.get("sec") or "")
    label = str(check.get("label") or "")
    status = str(check.get("status") or "").upper()
    detail = str(check.get("detail") or "")
    as_is, bp = _parse_detail_for_bp(detail)
    bp_txt = bp or _resolve_best_practice(label, section, cid) or ""
    word = _status_word(status)
    what = _first_sentence(as_is)
    if status == "PASS":
        found = f"{label} is configured the way Zscaler recommends." + (f" ({what})" if what and len(what) < 120 else "")
        means = "Nothing to change here; this control is doing its job."
        do = "Keep it as it is, and re-check on the next visit."
    elif status in ("FAIL",):
        found = f"{label}: {word}." + (f" {what}" if what else "")
        means = _generate_why_it_matters(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt, section=section)
        do = _generate_recommendation(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt)
    elif status in ("WARN", "REVIEW"):
        found = f"{label} needs a person to confirm it." + (f" {what}" if what else "")
        means = _generate_why_it_matters(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt, section=section)
        do = _generate_recommendation(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt)
    elif _not_permitted(detail):
        # The tenant refused the read: the row says so, never "not configured".
        found = f"{label} could not be read: the API client is not permitted to." + (f" {what}" if what else "")
        means = "The app cannot say whether this control is in place. It is outside the score (not a failure); the customer's coverage is unknown here until the permission is granted."
        do = "Ask the customer's Zscaler admin to give the API client a role that can read this area (Required API Access lists it), then run the assessment again."
    elif status == "ERROR":
        found = f"{label} could not be checked." + (f" {what}" if what else "")
        means = "Without this reading the app cannot say whether the control is in place; the score treats it as unknown, not as a failure."
        do = "Check the API client's permissions for this area (Required API Access lists them) and run the assessment again."
    else:
        found = f"{label} is not configured or not in use." + (f" {what}" if what else "")
        means = _generate_why_it_matters(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt, section=section)
        do = _generate_recommendation(check_id=cid, label=label, as_is=as_is, best_practice=bp_txt)
    portal, _api = _resolve_remediation(label, section, cid)
    if portal and status != "PASS" and portal.lower() not in (do or "").lower():
        do = f"{do} Where: {portal}." if do else f"Where: {portal}."
    return {"found": found.strip(), "means": (means or "").strip(), "do": (do or "").strip(),
            "outcome": outcome_for(cid, section), "best_practice": bp_txt.strip()}


def enrich(check: Dict[str, Any]) -> Dict[str, Any]:
    """Add the plain-English block to a result dict, in place, and return it."""
    try:
        check["plain"] = explain(check)
    except Exception:  # noqa: BLE001 - never let the explanation break a result
        check["plain"] = {"found": str(check.get("label") or ""), "means": "", "do": "", "outcome": outcome_for(str(check.get("id") or ""), str(check.get("section") or check.get("sec") or "")), "best_practice": ""}
    return check
