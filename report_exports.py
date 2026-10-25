"""Excel and PDF exports built on the in-house writers (xlsx_writer,
pdf_writer):

* assessment_workbook: the assessment results (summary, findings,
  compliance mapping, best practices);
* inventory_workbook: the tenant's DLP dictionaries, engines and rules
  per channel, with who uses what (from pack_export.read_tenant);
* plan_pdf / plan_workbook: a Deploy policy packs preflight, for change
  approval, with a sign-off block.

Nothing here reads or writes a tenant: callers pass what was read. No
credential is ever an input. Every text cell goes through xlsx_writer
(never a formula; formula-looking text neutralised as csv_safe does).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import pdf_writer
import xlsx_writer

XLSX = xlsx_writer.MEDIA_TYPE
PDF = pdf_writer.MEDIA_TYPE

MAX_CHECKS = 5000           # an assessment has a few hundred; more is not a report the page made
_URL_RE = re.compile(r"https?://[^\s)\]>\"']+")


def safe_filename_part(text: Any, fallback: str = "report", limit: int = 60) -> str:
    """Letters, digits, '-' and '_' only (a Content-Disposition filename)."""
    s = re.sub(r"[^A-Za-z0-9_-]+", "_", str(text or "")).strip("_")[:limit]
    return s or fallback


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _date_text(when: Any = None) -> str:
    if isinstance(when, str) and when:
        try:
            when = datetime.fromisoformat(when.replace("Z", "+00:00"))
        except ValueError:
            return when[:40]
    if not isinstance(when, datetime):
        when = _now()
    return when.strftime("%Y-%m-%d %H:%M UTC") if when.tzinfo else when.strftime("%Y-%m-%d %H:%M")


# ---------------------------------------------------------------------------
# Assessment results
# ---------------------------------------------------------------------------

STATUS_WORDS = {"PASS": "Configured", "FAIL": "Action required", "REVIEW": "Needs review", "WARN": "Needs review",
                "INFO": "Not configured", "ERROR": "Could not be checked"}
# No check records a severity of its own: it follows the status, the way the
# Word report puts every FAIL under "Critical findings".
SEVERITY = {"FAIL": "High", "REVIEW": "Medium", "WARN": "Medium", "INFO": "Low", "ERROR": "Unknown", "PASS": "None"}
SEVERITY_NOTE = ("Severity follows the status (no check records a severity of its own): action required is High, "
                 "needs review Medium, not configured Low, could not be checked Unknown, configured None.")


def _clip(value: Any, limit: int = 4000) -> str:
    s = "" if value is None else str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def assessment_checks(report: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], int]:
    """The checks of a posted assessment report, as plain dicts with the
    fields the exports read (strings, clipped), out-of-scope ones dropped
    (channel_scope.visible); and how many were hidden."""
    import channel_scope
    raw = report.get("checks") if isinstance(report, dict) else None
    if not isinstance(raw, list):
        raise ValueError("The report has no checks.")
    if len(raw) > MAX_CHECKS:
        raise ValueError(f"Too many checks in one report ({len(raw)}; at most {MAX_CHECKS}).")
    rows = []
    for c in raw:
        if not isinstance(c, dict):
            continue
        row = {k: _clip(c.get(k), 200 if k in ("id", "status") else 4000)
               for k in ("id", "label", "status", "detail") if c.get(k) is not None}
        row["section"] = _clip(c.get("section") or c.get("sec") or "", 200)
        row["status"] = str(row.get("status") or "").upper()
        for k in ("out_of_scope", "channel", "not_in_scope", "scope_state"):
            if k in c and isinstance(c[k], (str, bool, int)) and not isinstance(c[k], float):
                row[k] = c[k]
        rows.append(row)
    shown, dropped = channel_scope.visible(rows)
    try:
        hidden = max(0, int(report.get("hidden_checks") or 0)) + dropped
    except (TypeError, ValueError):
        hidden = dropped
    return shown, hidden


def _plain(check: Dict[str, Any]) -> Dict[str, str]:
    """The plain-English block, recomputed here from the check itself."""
    try:
        import plain_english
        return plain_english.explain(check)
    except Exception:  # noqa: BLE001 - the export still has the evidence
        return {"found": check.get("label", ""), "means": "", "do": "", "outcome": "", "best_practice": ""}


def _urls(*texts: Any) -> List[str]:
    out: List[str] = []
    for t in texts:
        for u in _URL_RE.findall(str(t or "")):
            u = u.rstrip(".,;")
            if u not in out:
                out.append(u)
    return out


def assessment_workbook(report: Dict[str, Any]) -> bytes:
    """The assessment as a workbook: Summary, Findings, Compliance mapping
    (when the mapping module is there), Best practices."""
    from dlp_assessment_full_auto import compute, maturity, pct_text
    checks, hidden = assessment_checks(report)
    meta = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    secs, overall = compute(checks)
    try:
        import permissions
        cov = permissions.assessment_summary(checks, hidden=hidden)
    except Exception:  # noqa: BLE001
        cov = None
    org = _clip(meta.get("org") or meta.get("org_name") or "", 200)
    wb = xlsx_writer.Workbook(title=f"Zscaler assessment {org}".strip(), subject="Assessment results")

    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([
        ["Organization", org or "Not named"],
        ["Assessor", _clip(meta.get("assessor"), 200)],
        ["Cloud", _clip(meta.get("cloud"), 100)],
        ["Assessment date", _date_text(meta.get("timestamp"))],
        ["Exported", _date_text()],
        ["Scope", _clip(meta.get("scope"), 400)],
        ["Overall score", pct_text(overall)],
        ["Maturity", maturity(overall)],
        ["Checks shown", len(checks)],
    ])
    if cov:
        s.append(["Assessed", f"{cov['assessed']} of {cov['total']}"])
        if cov.get("not_permitted"):
            s.append(["Not permitted to the API client", cov["not_permitted"]])
        if cov.get("errors"):
            s.append(["Could not be checked", cov["errors"]])
    if hidden:
        import channel_scope
        s.append(["Outside the selected scope", channel_scope.hidden_note(hidden)])
    s.append(["Severity", SEVERITY_NOTE])
    s.append([])
    s.append(["Section", "Score", "Configured", "Action required", "Needs review", "Not configured or not checked", "Checks"], bold=True)
    for name, v in secs.items():
        s.append([name, pct_text(v.get("pct")), v.get("pass", 0), v.get("fail", 0), v.get("warn", 0), v.get("info", 0), v.get("total", 0)])

    f = wb.add_sheet("Findings", columns=["ID", "Section", "Title", "Status", "Severity", "Evidence", "Recommendation", "References"])
    bp_rows = []
    for c in checks:
        p = _plain(c)
        st = c.get("status", "")
        refs = _urls(p.get("best_practice"), c.get("detail"))
        f.append([c.get("id", ""), c.get("section", ""), c.get("label", ""), STATUS_WORDS.get(st, st.title()),
                  SEVERITY.get(st, "Unknown"), c.get("detail", ""), "" if st == "PASS" else p.get("do", ""), refs])
        if p.get("best_practice"):
            bp_rows.append([c.get("id", ""), c.get("section", ""), c.get("label", ""), STATUS_WORDS.get(st, st.title()),
                            p["best_practice"], _urls(p["best_practice"])])

    try:
        from compliance_mapping import FRAMEWORK_DESCRIPTIONS, get_compliance_for_check, get_framework_summary
    except Exception:  # noqa: BLE001 - the mapping is optional
        get_compliance_for_check = None
    if get_compliance_for_check is not None:
        fw = get_framework_summary(checks)
        if fw:
            m = wb.add_sheet("Frameworks", columns=["Framework", "Name", "Status", "Alignment", "Mapped checks", "Configured",
                                                    "Action required", "Needs review", "Controls addressed"])
            for key in sorted(fw):
                v = fw[key]
                m.append([key, v.get("name", ""), v.get("status", ""), pct_text(v.get("alignment_pct")), v.get("covered_count", 0),
                          v.get("passing_count", 0), v.get("failing_count", 0), v.get("review_count", 0),
                          ", ".join(v.get("controls_addressed") or [])])
        cm = wb.add_sheet("Compliance mapping", columns=["ID", "Title", "Status", "Framework", "Framework name", "Controls"])
        for c in checks:
            for fwk, controls in sorted((get_compliance_for_check(c.get("id", "")) or {}).items()):
                cm.append([c.get("id", ""), c.get("label", ""), STATUS_WORDS.get(c.get("status", ""), c.get("status", "")), fwk,
                           FRAMEWORK_DESCRIPTIONS.get(fwk, fwk), ", ".join(controls)])
    if bp_rows:
        wb.add_sheet("Best practices", columns=["ID", "Section", "Title", "Status", "Best practice", "References"], rows=bp_rows)
    return wb.to_bytes()


def assessment_filename(report: Dict[str, Any]) -> str:
    meta = report.get("metadata") if isinstance(report.get("metadata"), dict) else {}
    org = safe_filename_part(meta.get("org") or meta.get("org_name"), "report")
    return f"zscaler_{org}_{_now().strftime('%Y%m%d')}.xlsx"


# ---------------------------------------------------------------------------
# DLP inventory
# ---------------------------------------------------------------------------

_TERM_RE = re.compile(r"D(\d+)\.S")
# Rule fields that name people: never in the inventory (counted in "Scoped to").
_PEOPLE = {"auditor", "users", "excluded_users", "receiver", "external_auditor_email", "notification_template"}
_SCOPE_FIELDS = ("locations", "location_groups", "groups", "departments", "users", "excluded_groups", "excluded_departments",
                 "excluded_users", "time_windows", "workload_groups", "source_ip_groups", "labels", "devices", "device_groups",
                 "cloud_app_tenants", "email_tenants", "end_point_application_groups", "endpoint_application_groups",
                 "included_domain_profiles", "excluded_domain_profiles", "email_recipient_profiles", "zpa_app_segments")


def _ids_in(expr: Any) -> List[str]:
    return list(dict.fromkeys(_TERM_RE.findall(str(expr or ""))))


def _ref_names(items: Any) -> List[str]:
    out = []
    for x in items if isinstance(items, list) else ([items] if items else []):
        if isinstance(x, dict):
            n = x.get("name") or x.get("tenant_name") or x.get("id")
        else:
            n = getattr(x, "name", None) or x
        if n not in (None, ""):
            out.append(str(n))
    return out


def _ref_ids(items: Any) -> List[str]:
    out = []
    for x in items if isinstance(items, list) else ([items] if items else []):
        i = x.get("id") if isinstance(x, dict) else getattr(x, "id", x if isinstance(x, (str, int)) else None)
        if i not in (None, ""):
            out.append(str(i))
    return out


def _list_text(values: Any, key: str) -> List[str]:
    """Patterns or phrases as lines: '<text> (<count type>)'."""
    out = []
    for v in values or []:
        if isinstance(v, dict):
            t, a = v.get(key), v.get("action")
        elif isinstance(v, (list, tuple)) and len(v) >= 2:
            a, t = v[0], v[1]
        else:
            t, a = getattr(v, key, None), getattr(v, "action", None)
        if t:
            a = str(a or "").replace(f"{key.upper()}_COUNT_TYPE_", "").lower()
            out.append(f"{t} ({a})" if a else str(t))
    return out


def _value_text(v: Any) -> Any:
    if isinstance(v, (list, tuple)):
        return ", ".join(str(x) for x in (_ref_names(list(v)) if v and isinstance(v[0], dict) else v))
    if isinstance(v, dict):
        return ", ".join(_ref_names([v])) or ""
    return v


def _dict_kind(d: Dict[str, Any]) -> str:
    if d.get("predefined_clone") or d.get("dict_template_id"):
        return "Clone"
    return "Custom" if d.get("custom") else "Predefined"


def inventory_workbook(snap: Dict[str, Any], *, tenant_label: str = "", channels: Sequence[str] = ()) -> bytes:
    """The tenant's DLP objects (a pack_export.read_tenant snapshot of the
    channels in scope) with who uses what."""
    import pack_channels as pc
    import pack_export
    try:
        import pack_deploy
        known = pack_deploy.library_ids()
        tag = lambda desc: pack_deploy.tag_pack(desc, known=known)  # noqa: E731
    except Exception:  # noqa: BLE001
        tag = lambda desc: None  # noqa: E731
    dicts = [d for d in snap.get("dictionaries") or [] if isinstance(d, dict)]
    engines = [e for e in snap.get("engines") or [] if isinstance(e, dict)]
    rules_by_ch = {ch: [r for r in rs or [] if isinstance(r, dict)] for ch, rs in (snap.get("rules") or {}).items()}
    dict_by_id = {str(d.get("id")): d for d in dicts if d.get("id") is not None}
    eng_by_id = {str(e.get("id")): e for e in engines if e.get("id") is not None}

    def dname(did: str) -> str:
        d = dict_by_id.get(str(did))
        return str(d.get("name") or f"D{did}") if d else f"dictionary {did} (not listed)"

    def ename(e: Dict[str, Any]) -> str:
        return str(e.get("name") or e.get("predefined_engine_name") or e.get("id") or "")

    # Usage: dictionary id -> engine names; engine id -> "Channel: rule" names.
    dict_users: Dict[str, List[str]] = {}
    for e in engines:
        for did in _ids_in(e.get("engine_expression") or e.get("expression")):
            dict_users.setdefault(did, []).append(ename(e))
    eng_users: Dict[str, List[str]] = {}
    for ch, rules in rules_by_ch.items():
        for r in rules:
            for eid in _ref_ids(r.get("dlp_engines")):
                eng_users.setdefault(eid, []).append(f"{pc.label(ch)}: {r.get('name') or r.get('id')}")
    dict_rules: Dict[str, set] = {}
    for did, users in dict_users.items():
        for e in engines:
            if ename(e) in users:
                dict_rules.setdefault(did, set()).update(eng_users.get(str(e.get("id")), []))

    title = f"DLP inventory {tenant_label}".strip()
    wb = xlsx_writer.Workbook(title=title, subject="DLP dictionaries, engines and rules")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([
        ["Tenant", tenant_label or "Not named"],
        ["Exported", _date_text()],
        ["Channels in scope", ", ".join(pc.label(ch) for ch in channels) or "None"],
        ["Dictionaries", len(dicts)],
        ["Custom dictionaries (clones included)", sum(1 for d in dicts if _dict_kind(d) != "Predefined")],
        ["Engines", len(engines)],
        ["Custom engines", sum(1 for e in engines if not pack_export._is_predefined_engine(e))],
    ])
    for ch in channels:
        if ch in rules_by_ch:
            s.append([f"{pc.label(ch)} rules", len(rules_by_ch[ch])])
    for key, err in sorted((snap.get("errors") or {}).items()):
        s.append([f"Could not be read: {pc.label(key) if key in pc.CHANNELS else key}", _clip(err, 300)])
    s.append(["How it was read", "Read-only: listed from the tenant's API; nothing was written. Only the DLP channels in scope on "
                                 "the Scope page were read. People named in rule scope (users, auditors, receivers) are counted, not named."])

    d_sheet = wb.add_sheet("Dictionaries", columns=[
        "Name", "ID", "Type", "Custom or predefined", "Clone of", "Patterns", "Phrases", "Confidence", "Match type", "Proximity",
        "Used by engines", "Engine names", "Used by rules (through engines)", "Deployed by pack", "Description"])
    for d in sorted(dicts, key=lambda x: str(x.get("name") or "").lower()):
        did = str(d.get("id"))
        tid = d.get("dict_template_id")
        clone_of = ""
        if _dict_kind(d) == "Clone":
            t = dict_by_id.get(str(tid)) if tid not in (None, "") else None
            clone_of = str((t or {}).get("name") or d.get("dict_template_name") or (f"dictionary {tid}" if tid else "not named by the tenant"))
        users = sorted(set(dict_users.get(did, [])), key=str.lower)
        d_sheet.append([d.get("name"), d.get("id"), str(d.get("dictionary_type") or "").replace("_", " ").lower(), _dict_kind(d), clone_of,
                        _list_text(d.get("patterns"), "pattern"), _list_text(d.get("phrases"), "phrase"),
                        d.get("confidence_threshold") or d.get("confidence_level_for_predefined_dict") or "",
                        d.get("custom_phrase_match_type") or "", d.get("proximity") if d.get("proximity") not in (None, 0) else "",
                        len(users), users, len(dict_rules.get(did, ())), tag(d.get("description")) or "", d.get("description") or ""])

    e_sheet = wb.add_sheet("Engines", columns=[
        "Name", "ID", "Custom or predefined", "Expression", "Expression (dictionary names)", "Dictionaries", "Used by rules",
        "Rule names", "Deployed by pack", "Description"])
    for e in sorted(engines, key=lambda x: ename(x).lower()):
        expr = str(e.get("engine_expression") or e.get("expression") or "")
        ids = _ids_in(expr)
        users = eng_users.get(str(e.get("id")), [])
        e_sheet.append([ename(e), e.get("id"), "Predefined" if pack_export._is_predefined_engine(e) else "Custom", expr,
                        _TERM_RE.sub(lambda m: f"[{dname(m.group(1))}]", expr), [dname(i) for i in ids], len(users), users,
                        tag(e.get("description")) or "", e.get("description") or ""])

    for ch in pc.DLP_CHANNELS:
        if ch not in rules_by_ch:
            continue
        extra = [f for f in list(pack_export._PLAIN.get(ch, ())) + list(pack_export._FLAGS.get(ch, ())) if f not in _PEOPLE]
        cols = ["Order", "Name", "ID", "State", "Action", "Severity", "Engines", "Engine count", "Parent rule"]
        cols += [f.replace("_", " ").capitalize() for f in extra] + ["Scoped to", "Deployed by pack", "Description"]
        r_sheet = wb.add_sheet(f"{pc.label(ch)} rules", columns=cols)
        for r in sorted(rules_by_ch[ch], key=lambda x: (int(x.get("order") or 0) if str(x.get("order") or "0").lstrip("-").isdigit() else 0)):
            eng = r.get("dlp_engines")
            names = [ename(eng_by_id[i]) if i in eng_by_id else n for i, n in zip(_ref_ids(eng), _ref_names(eng))] or _ref_names(eng)
            parent = r.get("parent_rule") or r.get("parent_id") or ""
            scoped = []
            for fld in _SCOPE_FIELDS:
                v = r.get(fld)
                n = len(v) if isinstance(v, list) else (1 if v else 0)
                if n:
                    scoped.append(f"{fld.replace('_', ' ')}: {n}")
            r_sheet.append([r.get("order"), r.get("name"), r.get("id"), r.get("state"), r.get("action"),
                            str(r.get("severity") or "").replace("RULE_SEVERITY_", "").lower(), names, len(names), _value_text(parent)]
                           + [_value_text(r.get(f)) for f in extra]
                           + [", ".join(scoped), tag(r.get("description")) or "", r.get("description") or ""])
    return wb.to_bytes()


def inventory_filename(tenant_label: str) -> str:
    return f"dlp_inventory_{safe_filename_part(tenant_label, 'tenant')}_{_now().strftime('%Y%m%d')}.xlsx"


# ---------------------------------------------------------------------------
# Deployment plan (a preflight)
# ---------------------------------------------------------------------------

PLAN_STATUS = {"create": "Will create", "modify": "Will modify", "restore": "Will overwrite (converge)",
               "reuse": "Already present", "reuse_differs": "Kept as-is", "conflict": "Conflict",
               "blocked_dependency": "Skipped: needs a prerequisite", "skip_empty": "Skipped: empty", "noop": "No change"}
PLAN_KIND = {"dictionary": "Dictionary", "engine": "Engine", "app_group": "App group", "policy": "Rule", "tweak": "Tweak"}
SIGN_OFF = ("Requested by", "Approved by", "Date")
_KIND_ORDER = {"dictionary": 0, "engine": 1, "app_group": 2, "policy": 3, "tweak": 4}


def plan_counts(report: Dict[str, Any]) -> Dict[str, int]:
    """The Studio's count vocabulary (deploy_studio.js _dzCounts)."""
    items = report.get("items") or []
    n = lambda s: sum(1 for i in items if i.get("status") == s)  # noqa: E731
    return {"create": n("create"), "modify": n("modify"), "restore": n("restore"), "kept": n("reuse_differs"),
            "conflict": n("conflict"), "skipped": n("blocked_dependency") + n("skip_empty"), "in_place": n("reuse") + n("noop"),
            "total": len(items)}


def _plan_items(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    items = [i for i in report.get("items") or [] if isinstance(i, dict)]
    return sorted(items, key=lambda i: (_KIND_ORDER.get(i.get("kind"), 9), str(i.get("name") or "").lower()))


def _item_channel(i: Dict[str, Any]) -> str:
    import pack_channels as pc
    ch = (i.get("detail") or {}).get("channel") if isinstance(i.get("detail"), dict) else None
    return pc.label(ch) if ch else ""


def _item_reason(i: Dict[str, Any]) -> str:
    parts = [str(i.get("reason") or "")]
    parts += [str(w) for w in (i.get("warnings") or []) if w]
    return " ".join(p for p in parts if p).strip()


def _plan_meta(report: Dict[str, Any]) -> List[Tuple[str, Any]]:
    opts = report.get("options") or {}
    packs = ", ".join(f"{p.get('name') or p.get('id')} ({p.get('id')})" if p.get("name") and p.get("name") != p.get("id")
                      else str(p.get("id")) for p in report.get("packs") or [])
    c = plan_counts(report)
    return [
        ("Tenant", report.get("tenant_label") or "Not named"),
        ("Policy packs", packs or "None"),
        ("Assessor", report.get("assessor") or "Not named"),
        ("Preflight run", _date_text(report.get("generated_at"))),
        ("Plan hash", report.get("plan_hash") or "None (the tenant could not be read; this plan cannot be approved)"),
        ("Plan status", {"ready": "Ready to deploy", "warnings": "Ready, with things to review", "blocked": "Blocked"}.get(
            report.get("status"), str(report.get("status") or ""))),
        ("Options", f"rank 0 {'on' if opts.get('use_rank_0') else 'off'}; confidence tweaks {'on' if opts.get('apply_tweaks') else 'off'}; "
                    f"converge mode {'on' if opts.get('restore_drift') else 'off'}"),
        ("Counts", f"{c['create']} to create, {c['modify']} to modify, {c['restore']} to overwrite, {c['kept']} kept as-is, "
                   f"{c['conflict']} conflicts, {c['skipped']} skipped, {c['in_place']} already in place ({c['total']} items)"),
    ]


PLAN_NOTE = ("Nothing has been written to the tenant: this is the preflight's plan. A deployment applies only this plan: "
             "if the tenant or the selection changes, the plan hash changes and the deployment is refused until a new "
             "preflight is reviewed. Every rule is created DISABLED.")


def plan_pdf(report: Dict[str, Any], page_size: str = "A4") -> bytes:
    """The preflight as a printable plan for change approval."""
    label = str(report.get("tenant_label") or "tenant")
    doc = pdf_writer.PdfDocument(title=f"Deployment plan: {label}", page_size=page_size,
                                 footer=f"DLP-Check deployment plan · {label} · plan {str(report.get('plan_hash') or 'none')[:16]}",
                                 author=str(report.get("assessor") or ""), subject="Deploy policy packs: plan for change approval")
    doc.heading("Deployment plan for change approval")
    doc.paragraph(PLAN_NOTE, size=9, grey=0.3)
    doc.key_values(_plan_meta(report))
    blockers = [str(b) for b in report.get("blockers") or []]
    warnings = [str(w) for w in report.get("warnings") or []]
    if blockers:
        doc.heading("Blockers", 2)
        doc.bullets(blockers)
    if warnings:
        doc.heading("Warnings", 2)
        doc.bullets(warnings)
    impacts = [i for i in report.get("impacts") or [] if isinstance(i, dict)]
    if impacts:
        doc.heading("Impact on this tenant", 2)
        doc.table(["Severity", "Impact", "Detail"], [[i.get("severity", ""), i.get("title", ""), i.get("detail", "")] for i in impacts],
                  widths=[1.2, 3, 6])
    deps = [d for d in report.get("dependencies") or [] if isinstance(d, dict)]
    if deps:
        import pack_channels as pc
        doc.heading("Tenant prerequisites", 2)
        doc.table(["Channel", "Requirement", "Status", "Detail"],
                  [[pc.label(d.get("channel")) if d.get("channel") else "", d.get("requirement", ""), d.get("status", ""),
                    d.get("detail", "")] for d in deps], widths=[1.6, 3, 1.3, 5])
    doc.heading("Planned items", 2)
    items = _plan_items(report)
    if items:
        doc.table(["Kind", "Name", "Status", "Channel", "Reason", "Depends on"],
                  [[PLAN_KIND.get(i.get("kind"), i.get("kind")), i.get("name", ""), PLAN_STATUS.get(i.get("status"), i.get("status")),
                    _item_channel(i), _item_reason(i), ", ".join(str(x) for x in i.get("depends_on") or [])] for i in items],
                  widths=[1.1, 2.6, 1.6, 1.2, 3.6, 2.4], size=7.5)
    else:
        doc.paragraph("The plan has no items.")
    doc.heading("Sign-off", 2)
    doc.paragraph("By signing, the approver accepts the plan above, identified by its plan hash.", size=9, grey=0.3)
    doc.signature_lines(list(SIGN_OFF))
    return doc.to_bytes()


def plan_workbook(report: Dict[str, Any]) -> bytes:
    """The preflight as a workbook: Summary (with sign-off rows), Items,
    Warnings and blockers, Prerequisites."""
    import pack_channels as pc
    wb = xlsx_writer.Workbook(title=f"Deployment plan {report.get('tenant_label') or ''}".strip(), subject="Deploy policy packs plan")
    s = wb.add_sheet("Summary", columns=["Item", "Value"], autofilter=False)
    s.extend([[k, v] for k, v in _plan_meta(report)])
    s.append(["Note", PLAN_NOTE])
    s.append([])
    s.append(["Sign-off", ""], bold=True)
    for label in SIGN_OFF:
        s.append([label, ""])
    wb.add_sheet("Items", columns=["Kind", "Name", "Status", "Channel", "Reason", "Depends on", "Packs", "Position"],
                 rows=[[PLAN_KIND.get(i.get("kind"), i.get("kind")), i.get("name", ""), PLAN_STATUS.get(i.get("status"), i.get("status")),
                        _item_channel(i), _item_reason(i), [str(x) for x in i.get("depends_on") or []],
                        ", ".join(str(p) for p in i.get("packs") or []), i.get("position") or ""] for i in _plan_items(report)])
    wb.add_sheet("Warnings and blockers", columns=["Type", "Text"],
                 rows=[["Blocker", b] for b in report.get("blockers") or []] + [["Warning", w] for w in report.get("warnings") or []]
                 + [[f"Impact ({i.get('severity', '')})", f"{i.get('title', '')}: {i.get('detail', '')}"]
                    for i in report.get("impacts") or [] if isinstance(i, dict)])
    deps = [d for d in report.get("dependencies") or [] if isinstance(d, dict)]
    if deps:
        wb.add_sheet("Prerequisites", columns=["Channel", "Requirement", "Status", "Detail", "Needed by"],
                     rows=[[pc.label(d.get("channel")) if d.get("channel") else "", d.get("requirement", ""), d.get("status", ""),
                            d.get("detail", ""), d.get("rules") or []] for d in deps])
    return wb.to_bytes()


def plan_filename(report: Dict[str, Any], ext: str) -> str:
    return (f"deployment_plan_{safe_filename_part(report.get('tenant_label'), 'tenant', 40)}_"
            f"{safe_filename_part(str(report.get('plan_hash') or 'nohash')[:12], 'nohash')}.{ext}")
