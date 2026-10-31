"""The compliance pack: local files made from one compliance profile
(compliance_profiles.py) and a ZIA baseline spec, or from a baseline run the
app recorded. Nothing here reads or writes a tenant.

Files (FILES):
  mapping.html / mapping.csv / mapping.xlsx   every rule -> objective -> the profile's controls, or its reason code;
                                              the control catalogue with sources and the assumed flag
  policy.json / policy.csv                    what would be built (or, from a recorded run, what was)
  testplan.html / testplan.csv                a test plan grouped by control, with an empty Result column
  dlp-<pack>-<rule>.txt                       one synthetic DLP test file per DLP rule of the offered packs
  compliance-pack.zip                         all of the above

Synthetic data only: every DLP test file starts with SYNTHETIC TEST DATA and
uses documented-invalid or published test values (corpus_engines.SAMPLES):
Social Security numbers from the block 987-65-4320 to 987-65-4329 that SSA
reserved for examples, card-network test card numbers (they pass the Luhn
check and are never issued), the CMS specimen Medicare identifier, specimen
IBANs, a test routing number, names like "Avery Example", addresses on
example.com and 555-01xx phone numbers. Markings (CUI, FTI, CJIS, TLP ...)
are the words of the marking itself. A dictionary with no safe sample is
named as not covered; the engine's expression is evaluated locally on the
file's own samples and the file says whether it should fire.
"""
from __future__ import annotations

import copy
import html
import io
import json
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import compliance_profiles as cp

FORMAT = "zme-compliance-pack"
BANNER = ("SYNTHETIC TEST DATA - made by Zscaler Made Easy for a DLP test. Not real people, accounts or documents: "
          "Social Security numbers are from the block 987-65-4320 to 987-65-4329 reserved for examples (never issued), card numbers "
          "are published card-network test numbers (Luhn-valid, never issued), e-mail addresses are on example.com and phone numbers "
          "are in the 555-0100 to 555-0199 range set aside for fiction. Markings are sample labels on a fake document.")
MAX_FILES = 200

# ---------------------------------------------------------------------------
# Building the context
# ---------------------------------------------------------------------------


class PackError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def default_spec(profile_key: str) -> Dict[str, Any]:
    import ops_zia_baseline as zb
    return {"type": zb.TYPE, "compliance_profile": profile_key, "areas": list(zb.DEFAULT_AREAS) + ["atp"]}


def _applied_keys(rec: Dict[str, Any]) -> Dict[str, str]:
    """{rule key: 'applied' | other status} from a recorded run's items."""
    out: Dict[str, str] = {}
    for u in rec.get("items") or []:
        key = str(u.get("key") or "")
        m = re.match(r"^zb:([a-z]+):([a-z0-9_.]+):", key) or re.match(r"^zb:(atp):([a-z_]+)$", key)
        if not m:
            continue
        rk = m.group(2) if m.group(1) != "atp" else "atp." + m.group(2)
        st = str(u.get("status") or "")
        if out.get(rk) != "applied":
            out[rk] = st
    return out


def build(profile_key: str, spec: Optional[Dict[str, Any]] = None, operation: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Everything the files are made from: the profile summary, the
    baseline review of `spec` (or of a recorded run's spec), the mapping of
    every rule and what was applied when it is a recorded run."""
    import admin_ops as ao
    import ops_zia_baseline as zb
    try:
        pk = cp.key_of(profile_key)
    except cp.ProfileError as e:
        raise PackError(str(e)) from None
    if not pk:
        raise PackError("Pick a compliance profile.")
    built = None
    if operation is not None:
        if operation.get("type") != zb.TYPE:
            raise PackError("That recorded change is not a ZIA baseline build.", 409)
        spec = copy.deepcopy(operation.get("spec") or {})
        built = {"id": operation.get("id"), "at": operation.get("at"), "tenant_label": operation.get("tenant_label") or "",
                 "status": operation.get("status"), "applied": _applied_keys(operation)}
    spec = dict(spec or default_spec(pk))
    spec["type"] = zb.TYPE
    spec["compliance_profile"] = pk
    if spec.get("action") == "revert":
        raise PackError("An Undo has no compliance pack.")
    try:
        rev = zb.review(spec)
    except ao.OperationError as e:
        raise PackError(str(e)) from None
    n = rev["normalized"]
    areas = n["areas"] or list(zb.DEFAULT_AREAS)
    rows = []
    for r in rev["rules"]:
        r = dict(r)
        if r["area"] not in areas:
            r["on"] = False
        if built is not None:
            st = built["applied"].get(r["key"])
            r["on"] = r["on"] and st in ("applied", "noop")
        rows.append(r)
    atp = [dict(s) for s in rev["atp"]] if "atp" in areas else []
    review = {"rules": rows, "atp": atp}
    mp = cp.mapping(pk, review)
    if "atp" not in areas:
        for k, label in zb.ATP_SETTINGS:
            m = cp.map_rule(pk, "atp." + k, on=False)
            mp["rows"].append({"source": "ZIA baseline", "area": "Advanced Threat Protection", "key": "atp." + k, "name": label, "title": label,
                               "action": "", "on": False, "created": False, "state": "setting", **m,
                               "profile_note": "Advanced Threat Protection is not picked in this build (it has no disabled state)."})
    return {"profile": pk, "summary": cp.summary(pk), "spec": {k: v for k, v in n.items() if k not in ("framework",)},
            "tier_label": rev["tier_label"], "areas": areas, "review": review, "mapping": mp, "built": built,
            "tier_warning": (rev.get("compliance_profile") or {}).get("tier_warning", ""),
            "controls": cp.controls(pk), "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}


# ---------------------------------------------------------------------------
# Small writers
# ---------------------------------------------------------------------------
E = html.escape


def _ctrl_text(m: Dict[str, Any]) -> str:
    return "; ".join(f"{c['id']}{' (assumed)' if c.get('assumed') else ''}" for c in m.get("controls") or [])


def _act(a: Any) -> str:
    if isinstance(a, list):
        return ", ".join(str(x) for x in a)
    if isinstance(a, dict):
        return str(a.get("type") or "")
    return str(a or "")


def _csv(header: Sequence[str], rows: Sequence[Sequence[Any]], first: str = "") -> bytes:
    import csv_safe
    buf = io.StringIO()
    if first:
        buf.write(f"# {first}\r\n")
    w = csv_safe.writer(buf, lineterminator="\r\n")
    w.writerow(header)
    for r in rows:
        w.writerow(r)
    return buf.getvalue().encode("utf-8")


_HTML_HEAD = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>
body{{font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#111827;background:#fff;margin:24px;max-width:1200px}}
h1{{font-size:22px}} h2{{font-size:17px;margin-top:28px}} table{{border-collapse:collapse;width:100%;margin:8px 0}}
th,td{{border:1px solid #cbd5e1;padding:4px 6px;vertical-align:top;text-align:left}} th{{background:#e2e8f0}}
.a{{color:#9a3412;font-weight:600}} .r{{color:#374151}} .note{{color:#374151}} .tag{{display:inline-block;border:1px solid #94a3b8;border-radius:4px;padding:0 4px;margin:1px}}
@media print{{body{{margin:0}}}}
</style></head><body>"""


def _head(ctx: Dict[str, Any], what: str) -> str:
    s = ctx["summary"]
    built = ctx.get("built")
    origin = (f"What was built: recorded run {E(str(built['id']))} on {E(str(built['at']))}"
              f"{' for ' + E(built['tenant_label']) if built.get('tenant_label') else ''}." if built else
              "What would be built: nothing has been written to a tenant.")
    src = "; ".join(f"<a href=\"{E(x['url'])}\">{E(x['title'])}</a>" for x in s["sources"]) or "The overlay's own documents (per control)."
    warn = f"<p class=\"a\">{E(ctx['tier_warning'])}</p>" if ctx.get("tier_warning") else ""
    return (_HTML_HEAD.format(title=E(f"{what}: {s['label']}")) +
            f"<h1>{E(what)}: {E(s['label'])}</h1><p>{E(s['what'])}</p><p>{origin} Tier: {E(ctx['tier_label'])}. Areas: "
            f"{E(', '.join(ctx['areas']))}. Generated {E(ctx['generated_at'])} by Zscaler Made Easy.</p><p>Sources: {src}</p>{warn}"
            f"<p class=\"note\">{E(s['reuses'])}</p>")


# ---------------------------------------------------------------------------
# Control mapping report
# ---------------------------------------------------------------------------
MAP_COLUMNS = ["Source", "Area", "Rule", "Rule key", "Created", "Action", "Objective", "Controls", "Assumed", "Reason code", "Reason",
               "Note"]


def _map_rows(ctx: Dict[str, Any]) -> List[List[Any]]:
    out = []
    for r in ctx["mapping"]["rows"]:
        out.append([r["source"], r["area"], r["name"], r["key"], "yes" if r["created"] else ("setting" if r.get("state") == "setting" and r["on"] else "no"),
                    _act(r["action"]), r["objective_label"], _ctrl_text(r), "yes" if any(c.get("assumed") for c in r["controls"]) else "",
                    r["reason"], r["reason_text"], " ".join(x for x in (r.get("why"), r.get("profile_note")) if x)])
    return out


CTRL_COLUMNS = ["Control", "Title", "Source", "Baseline", "Rules that carry it out", "Assumed", "Why assumed"]


def _ctrl_rows(ctx: Dict[str, Any]) -> List[List[Any]]:
    count: Dict[str, int] = {}
    for r in ctx["mapping"]["rows"]:
        for c in r["controls"]:
            count[c["id"]] = count.get(c["id"], 0) + 1
    return [[c["id"], c.get("title", ""), c["source_ref"]["title"], c.get("baseline", ""), count.get(c["id"], 0),
             "yes" if c.get("assumed") else "", c.get("assumed_why", "")] for c in ctx["controls"]]


def mapping_csv(ctx: Dict[str, Any]) -> bytes:
    return _csv(MAP_COLUMNS, _map_rows(ctx), f"Control mapping: {ctx['summary']['label']}. Generated {ctx['generated_at']}.")


def mapping_xlsx(ctx: Dict[str, Any]) -> bytes:
    from xlsx_writer import Workbook
    wb = Workbook(title=f"Control mapping: {ctx['summary']['label']}")
    s = wb.add_sheet("Summary")
    for line in [f"Compliance profile: {ctx['summary']['label']}", ctx["summary"]["what"], f"Tier: {ctx['tier_label']}",
                 f"Rules: {ctx['mapping']['counts']['rules']}, mapped to controls: {ctx['mapping']['counts']['mapped']}, "
                 f"with a reason code: {ctx['mapping']['counts']['reasoned']}"] + ctx["summary"]["lines"]:
        s.append([line])
    wb.add_sheet("Rule mapping", columns=MAP_COLUMNS, rows=_map_rows(ctx))
    wb.add_sheet("Controls", columns=CTRL_COLUMNS, rows=_ctrl_rows(ctx))
    wb.add_sheet("Reason codes", columns=["Code", "Meaning"], rows=[[k, v] for k, v in cp.REASONS.items()])
    return wb.to_bytes()


def mapping_html(ctx: Dict[str, Any]) -> bytes:
    c = ctx["mapping"]["counts"]
    parts = [_head(ctx, "Control mapping report"),
             f"<p>{c['rules']} rules and settings: {c['mapped']} map to controls of this profile, {c['reasoned']} carry a reason code "
             f"instead. A control marked <span class=\"a\">assumed</span> is not verified against its source (see the Controls table).</p>",
             "<h2>What the profile does</h2><ul>" + "".join(f"<li>{E(x)}</li>" for x in ctx["summary"]["lines"]) + "</ul>",
             "<h2>Every rule mapped</h2><table><thead><tr>" + "".join(f"<th scope=\"col\">{E(h)}</th>" for h in MAP_COLUMNS) + "</tr></thead><tbody>"]
    for row in _map_rows(ctx):
        parts.append("<tr>" + "".join(f"<td>{E(str(v))}</td>" for v in row) + "</tr>")
    parts.append("</tbody></table><h2>Controls</h2><table><thead><tr>" + "".join(f"<th scope=\"col\">{E(h)}</th>" for h in CTRL_COLUMNS)
                 + "</tr></thead><tbody>")
    for row in _ctrl_rows(ctx):
        cls = ' class="a"'
        parts.append("<tr>" + "".join(f"<td{cls if i == 5 and v else ''}>{E(str(v))}</td>" for i, v in enumerate(row)) + "</tr>")
    parts.append("</tbody></table><h2>Reason codes</h2><table><tbody>" +
                 "".join(f"<tr><th scope=\"row\">{E(k)}</th><td>{E(v)}</td></tr>" for k, v in cp.REASONS.items()) + "</tbody></table></body></html>")
    return "".join(parts).encode("utf-8")


# ---------------------------------------------------------------------------
# Policy export
# ---------------------------------------------------------------------------

def _pack_bundles(pk: str) -> List[Tuple[str, str, Dict[str, Any]]]:
    from dlp_importer import discover_packs
    import pack_library
    have = {p["id"]: p for p in discover_packs()}
    out = []
    for pid in cp.PROFILES[pk]["packs"]:
        if pid in have:
            out.append((pid, have[pid].get("name") or pid, pack_library.pack_bundle(have[pid]["dir"])))
    return out


def policy(ctx: Dict[str, Any]) -> Dict[str, Any]:
    import ai_guard as ag
    import ops_aiguard
    pk = ctx["profile"]
    s = ctx["summary"]
    built = ctx.get("built")
    rules = []
    for r in ctx["review"]["rules"]:
        rules.append({"key": r["key"], "name": r["name"], "area": r["area_label"], "on": r["on"], "action": r["action"],
                      "applied": (built["applied"].get(r["key"]) if built else None), "fields": r["fields"],
                      "note": r.get("profile_note", "")})
    packs = []
    for pid, name, b in _pack_bundles(pk):
        packs.append({"id": pid, "name": name, "dictionaries": [d.get("name") for d in b.get("dictionaries") or []],
                      "engines": [{"name": e.get("name"), "expression": e.get("expression")} for e in b.get("engines") or []],
                      "rules": [{"name": r.get("name"), "channel": r.get("channel") or "web", "action": r.get("action"),
                                 "state": r.get("state"), "engines": r.get("engines")} for r in b.get("policies") or []]})
    aig = s["aiguard"]
    return {"format": FORMAT + "-policy", "version": 1, "profile": pk, "label": s["label"], "generated_at": ctx["generated_at"],
            "built": bool(built), "operation": {k: v for k, v in (built or {}).items() if k != "applied"} or None,
            "baseline": {"tier": ctx["spec"].get("tier"), "prefix": ctx["spec"].get("prefix"), "areas": ctx["areas"],
                         "enable_rules": bool(ctx["spec"].get("enable_rules")), "rules": rules,
                         "atp": [{"key": a["key"], "label": a["label"], "value": a["value"]} for a in ctx["review"]["atp"]]},
            "policy_packs": packs,
            "ai_guard": {"profile": aig, "name": ag.PROFILES.get(aig, {}).get("name", aig), "mode": "monitor",
                         "detection_policy": ops_aiguard.build_policy("AIG-Policy", aig, "monitor") if aig in ag.PROFILES else None},
            "note": "Rules are created DISABLED and policy-pack rules monitor-only; the AI Guard policy is in Monitor mode. "
                    "This file is a review copy: it is not an import format."}


def policy_csv(ctx: Dict[str, Any]) -> bytes:
    p = policy(ctx)
    rows = [["ZIA baseline", r["area"], r["name"], "on" if r["on"] else "off", _act(r["action"]), r["applied"] or ""] for r in p["baseline"]["rules"]]
    rows += [["ZIA baseline", "Advanced Threat Protection", a["label"], "on" if a["value"] else "off", "", ""] for a in p["baseline"]["atp"]]
    for pk_ in p["policy_packs"]:
        rows += [[f"Policy pack: {pk_['name']}", f"DLP ({r['channel']})", r["name"], str(r["state"] or "").lower(), _act(r["action"]), ""]
                 for r in pk_["rules"]]
    rows.append(["AI Guard", "Detection policy", p["ai_guard"]["name"], "monitor", "", ""])
    return _csv(["Source", "Area", "Name", "State", "Action", "Applied in the recorded run"], rows,
                f"Policy export: {p['label']} ({'what was built' if p['built'] else 'what would be built'}).")


# ---------------------------------------------------------------------------
# Test plan by control
# ---------------------------------------------------------------------------
_STEPS: Dict[str, Tuple[str, str]] = {
    "web_risk_block": ("From a test device behind ZIA, open a site in one of the rule's URL categories{what}.",
                       "The Zscaler block page names {rule}."),
    "isolation": ("Open an uncategorised or unknown site{what}.", "The site opens in Cloud Browser Isolation (a caution page without an "
                                                                 "isolation profile); {rule} is in the web log."),
    "malicious_code": ("Download the EICAR test file (eicar.org) and the unique sandbox PDF from the POV test kit through ZIA.",
                       "The EICAR download is blocked and the first-seen PDF is held until the sandbox verdict; the log names {rule}."),
    "mobile_code": ("Open the AMTSO security features check pages (amtso.org) through ZIA.",
                    "Advanced Threat Protection blocks the exploit checks ({rule})."),
    "spam_phishing": ("Open the AMTSO phishing page check (amtso.org) through ZIA.", "The phishing page is blocked ({rule})."),
    "deny_by_default": ("From a test device, open a connection on a port and application no allow rule names (for example TCP 6667 to "
                        "an internet test host).", "The connection is dropped; the firewall log names {rule}."),
    "least_functionality": ("Start the application or protocol the rule names{what} (a test client, with written approval).",
                            "It is blocked and the log names {rule}."),
    "boundary_restrict": ("Use the Path analyzer, or with written approval an SSH/RDP attempt, to a host in a listed country{what}.",
                          "The connection is dropped by {rule}."),
    "boundary_monitoring": ("Check in the ZIA portal that the setting is on, and run the AMTSO botnet callback check if the customer "
                            "allows it.", "Command-and-control callbacks are blocked ({rule})."),
    "encrypted_visibility": ("For SSL inspection: open a general HTTPS site and read its certificate. For QUIC: watch chrome://net-internals. "
                             "For archives: upload a password-protected zip.", "The certificate is issued by Zscaler / no QUIC session / "
                                                                                 "the archive is blocked ({rule})."),
    "protective_dns": ("Resolve a test name from a device using its own resolver setting; with written approval run a DNS tunnel test.",
                       "The query is answered through the Trusted Resolver or the tunnel is blocked; the DNS log names {rule}."),
    "encrypted_dns": ("Turn on DNS over HTTPS in a browser and browse to a few sites.", "The DoH lookups appear in the DNS log; risky "
                                                                                       "ones are blocked ({rule})."),
    "external_systems": ("Open the app or site the rule controls{what} (a personal webmail, file share or app).",
                         "It is blocked or limited as {rule} says."),
    "public_posting": ("Open a social networking site and try to post.", "Reading works or not as the tier says; posting is blocked by {rule}."),
    "data_flow_enforce": ("Upload a harmless test document to the app or category the rule controls{what}.", "The upload is blocked by {rule}."),
    "data_flow_detect": ("Through ZIA, upload the synthetic file {file} to a test upload page (for example https://dlptest.com/http-post/) "
                         "after enabling the rule in monitor mode.", "A DLP incident names {rule} and its engine; the upload is not blocked "
                                                                     "(monitor only)."),
    "software_restriction": ("Download a harmless installer or script (for example a vendor's .exe or a .ps1 test file).",
                             "The download is blocked by {rule}."),
}


def _what(r: Dict[str, Any]) -> str:
    f = r.get("fields") or {}
    vals = (f.get("url_categories") or f.get("nw_applications") or f.get("applications") or f.get("dest_countries") or [])
    if f.get("type") and not vals:
        vals = [f["type"]]
    return f" ({', '.join(map(str, vals[:4]))}{', ...' if len(vals) > 4 else ''})" if vals else ""


def test_plan(ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """One entry per control: the tests that prove it, from the rules that
    carry it out. A control no rule carries out says so."""
    fields = {r["key"]: r for r in ctx["review"]["rules"]}
    files: Dict[str, str] = {}
    for f in dlp_files(ctx, meta_only=True):
        for rn in [f["rule"]] + list(f.get("mirrors") or []):
            files[str(rn)] = f["name"]
    by: Dict[str, List[Dict[str, Any]]] = {c["id"]: [] for c in ctx["controls"]}
    n = 0
    for r in ctx["mapping"]["rows"]:
        if not r["controls"]:
            continue
        step, expect = _STEPS[r["objective"]]
        what = _what(fields.get(r["key"], {}))
        fname = files.get(str(r["name"])) or "from the DLP files of this pack"
        for c in r["controls"]:
            n += 1
            by.setdefault(c["id"], []).append({"id": f"T{n:03d}", "rule": r["name"], "source": r["source"], "area": r["area"],
                                               "steps": step.format(what=what, rule=r["name"], file=fname),
                                               "expected": expect.format(rule=r["name"]),
                                               "evidence": "Screenshot of the block page or log line, or the DLP incident."})
    out = []
    cat = {c["id"]: c for c in ctx["controls"]}
    for cid, tests in by.items():
        c = cat.get(cid, {"id": cid, "title": "", "assumed": False})
        out.append({"control": cid, "title": c.get("title", ""), "assumed": bool(c.get("assumed")), "tests": tests,
                    "note": "" if tests else "No rule of this build carries this control out: assess it with the Compliance page or outside ZIA."})
    return out


TP_COLUMNS = ["Control", "Title", "Assumed", "Test", "Rule", "Source", "Steps", "Expected", "Evidence", "Result"]


def _tp_rows(ctx: Dict[str, Any]) -> List[List[Any]]:
    rows = []
    for c in test_plan(ctx):
        if not c["tests"]:
            rows.append([c["control"], c["title"], "yes" if c["assumed"] else "", "", "", "", c["note"], "", "", ""])
        for t in c["tests"]:
            rows.append([c["control"], c["title"], "yes" if c["assumed"] else "", t["id"], t["rule"], t["source"], t["steps"], t["expected"],
                         t["evidence"], ""])
    return rows


def testplan_csv(ctx: Dict[str, Any]) -> bytes:
    return _csv(TP_COLUMNS, _tp_rows(ctx), f"Test plan by control: {ctx['summary']['label']}.")


def testplan_html(ctx: Dict[str, Any]) -> bytes:
    parts = [_head(ctx, "Test plan by control"),
             "<p>Run each test from a test device behind ZIA after enabling the rule (rules are created disabled; DLP rules are "
             "monitor-only). Write the result in the last column. The synthetic DLP files are in this pack.</p>"]
    for c in test_plan(ctx):
        mark = ' <span class="a">(assumed)</span>' if c["assumed"] else ""
        parts.append(f"<h2>{E(c['control'])} {E(c['title'])}{mark}</h2>")
        if not c["tests"]:
            parts.append(f"<p class=\"note\">{E(c['note'])}</p>")
            continue
        parts.append("<table><thead><tr><th scope=\"col\">Test</th><th scope=\"col\">Rule</th><th scope=\"col\">Steps</th>"
                     "<th scope=\"col\">Expected</th><th scope=\"col\">Result</th></tr></thead><tbody>")
        for t in c["tests"]:
            parts.append(f"<tr><td>{E(t['id'])}</td><td>{E(str(t['rule']))}<div class=\"note\">{E(t['source'])}</div></td>"
                         f"<td>{E(t['steps'])}</td><td>{E(t['expected'])}</td><td></td></tr>")
        parts.append("</tbody></table>")
    parts.append("</body></html>")
    return "".join(parts).encode("utf-8")


# ---------------------------------------------------------------------------
# Synthetic DLP test files
# ---------------------------------------------------------------------------
# Sample labels that a marking pattern may match: the words of the marking
# on a fake document (a key file's header line, never a key). Nothing personal.
MARKINGS: Tuple[str, ...] = (
    "CUI", "CONTROLLED UNCLASSIFIED INFORMATION", "CUI//SP-CTI", "CUI//SP-PRVCY", "CUI//PRVCY", "CUI//PROPIN", "(CUI)", "(U//CUI)",
    "CUI//NOFORN", "CUI//SP-EXPT//NOFORN", "Controlled by: Example Agency", "CUI Category: PRVCY", "Limited Dissemination Control: FEDCON",
    "POC: Avery Example, 555-0100", "Decontrol on: 20991231", "DISTRIBUTION STATEMENT D", "FOR OFFICIAL USE ONLY", "(U//FOUO)", "FOUO",
    "LAW ENFORCEMENT SENSITIVE", "(U//LES)", "SENSITIVE BUT UNCLASSIFIED", "(U//SBU)", "RESTRICTED DATA", "FORMERLY RESTRICTED DATA",
    "This document contains Restricted Data as defined in the Atomic Energy Act of 1954", "TLP:RED", "TLP:AMBER+STRICT", "TLP:AMBER",
    "CJIS", "(CJI)", "//CHRI", "CJIS SECURITY POLICY", "CRIMINAL HISTORY RECORD INFORMATION", "ORI: ZZ0000000",
    "FEDERAL TAX INFORMATION", "IRC 6103", "26 U.S.C. 6103", "Form 1040", "Form W-2", "Account Transcript", "Schedule K-1",
    "ITAR", "International Traffic in Arms Regulations", "22 CFR 120-130", "EXPORT CONTROLLED", "SF-86", "Standard Form 86",
    "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----", "-----BEGIN OPENSSH PRIVATE KEY-----",
    "MATERIAL NON-PUBLIC INFORMATION", "MNPI", "STRICTLY CONFIDENTIAL", "CONFIDENTIAL", "Medical Record Number: MRN-TEST-000001",
    "Diagnosis: E11.9 Type 2 diabetes mellitus without complications", "ICD-10", "Patient Name: Avery Example",
)
# Predefined dictionaries (by template, either name) and the corpus_engines sample key that is safe for them.
TEMPLATE_SAMPLES: Tuple[Tuple[str, str], ...] = (
    ("SSN", "ssn"), ("SOCIAL SECURITY", "ssn"), ("USITIN", "ssn"), ("TAX IDENTIFICATION", "ssn"), ("CREDIT_CARD", "credit_card"),
    ("CREDIT CARD", "credit_card"), ("CCN", "credit_card"), ("ABA", "aba"), ("ROUTING", "aba"), ("IBAN", "iban"),
    ("MEDICARE", "mbi"), ("MBI", "mbi"), ("DATE OF BIRTH", "date_of_birth"), ("DOB", "date_of_birth"), ("NAME", "name"),
    ("EMAIL", "email"), ("PHONE", "phone"),
)
_SAMPLE_NOTE = {"ssn": "reserved SSNs 987-65-4320 to 4329 (a strict SSN or TIN dictionary may not count them)",
                "credit_card": "published card-network test numbers", "aba": "a test routing number", "iban": "specimen IBANs",
                "mbi": "the CMS specimen Medicare identifier", "date_of_birth": "generated dates", "name": "example names",
                "email": "addresses on example.com", "phone": "555-01xx numbers"}


def _template_key(d: Dict[str, Any]) -> str:
    t = str(d.get("dict_template_name") or d.get("name") or "").upper()
    for frag, key in TEMPLATE_SAMPLES:
        if frag in t:
            return key
    return ""


def _pattern_hits(pattern: str, candidates: Sequence[str]) -> List[str]:
    try:
        rx = re.compile(pattern)
    except re.error:
        return []
    return [c for c in candidates if rx.search(c)]


def _dict_samples(d: Dict[str, Any], rng: Any) -> Tuple[List[str], str, int, bool]:
    """(sample lines for dictionary `d`, how they were made, the count the
    file gives it, whether that count is uncertain) or ([], why not, 0, False).
    A predefined dictionary is known by its template (or, for one an engine
    names directly, by its name)."""
    import corpus_engines as ce
    custom = bool(d.get("patterns") or d.get("phrases")) and not d.get("predefined_clone")
    if not custom:
        key = _template_key(d)
        if not key:
            what = d.get("dict_template_name") or d.get("name")
            return [], f"no safe test value for the predefined dictionary {what}", 0, False
        vals = [ce.sample(key, i, rng) for i in range(6)]
        return vals, _SAMPLE_NOTE[key], 3 * len(vals), key == "ssn"
    phrases = [str((p or {}).get("phrase") or "").strip().strip('"').strip("'") for p in d.get("phrases") or [] if isinstance(p, dict)]
    phrases = [p for p in phrases if p][:6]
    hits: List[str] = []
    for p in d.get("patterns") or []:
        pat = str((p or {}).get("pattern") or "") if isinstance(p, dict) else ""
        for hit in _pattern_hits(pat, list(MARKINGS) + phrases):
            if hit not in hits:
                hits.append(hit)
            break
    both = str(d.get("custom_phrase_match_type") or "") == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
    if both and not hits:
        return [], "needs a pattern match beside a phrase, and no safe sample matches its pattern", 0, False
    lines = hits + [p for p in phrases if p not in hits]
    lines = lines[:8]
    if not lines:
        return [], "a pattern-only dictionary with no safe sample here", 0, False
    unique = any("UNIQUE" in str((x or {}).get("action") or "") for x in (d.get("phrases") or []) + (d.get("patterns") or [])
                 if isinstance(x, dict))
    return lines, "the dictionary's own phrases and sample markings", (len(lines) if unique else 3 * len(lines)), False


_REF_END = re.compile(r"\s*(?:[<>=+]|\bAND\b|\bOR\b)")
_TOKEN = re.compile(r"\s*(\d+|>=|<=|==|[<>=()+]|AND\b|OR\b|NOT\b)")


def _ref_spans(expr: str) -> List[Tuple[int, int, str]]:
    """(start, end, name) of every D:<name> reference: a name runs to the
    next comparison, '+' or AND/OR, less the closing parentheses it does
    not open itself (a name may hold its own: 'Names (US)')."""
    out = []
    for m in re.finditer(r"D:", expr):
        start = m.end()
        e = _REF_END.search(expr, start)
        end = e.start() if e else len(expr)
        name = expr[start:end].rstrip()
        while name.endswith(")") and name.count(")") > name.count("("):
            name = name[:-1].rstrip()
        if name.endswith(".S"):
            name = name[:-2]
        if name:
            out.append((m.start(), start + len(name), name))
    return out


def _refs(expr: str) -> List[str]:
    out: List[str] = []
    for _, _, name in _ref_spans(expr):
        if name not in out:
            out.append(name)
    return out


def _negated(expr: str) -> set:
    """Names inside a NOT ( ... ) group: a test file must not contain them."""
    out: set = set()
    for m in re.finditer(r"\bNOT\s*\(", expr):
        depth, k = 0, m.end() - 1
        while k < len(expr):
            depth += {"(": 1, ")": -1}.get(expr[k], 0)
            if depth == 0:
                break
            k += 1
        out |= set(_refs(expr[m.end():k]))
    return out


def _evaluate(expr: str, counts: Dict[str, int]) -> Optional[bool]:
    """The engine expression with each dictionary's count in this file,
    evaluated by a small parser of numbers, '+', comparisons, AND, OR, NOT
    and parentheses (nothing is ever executed); None when anything else is
    left in it."""
    text = str(expr or "")
    if len(text) > 20000:
        return None
    for start, end, name in reversed(_ref_spans(text)):
        tail = 2 if text[end:end + 2] == ".S" else 0
        text = text[:start] + str(int(counts.get(name, 0))) + text[end + tail:]
    toks: List[str] = []
    i = 0
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        m = _TOKEN.match(text, i)
        if not m:
            return None
        toks.append(m.group(1))
        i = m.end()
    pos = [0]

    def peek() -> str:
        return toks[pos[0]] if pos[0] < len(toks) else ""

    def take() -> str:
        if pos[0] >= len(toks):
            raise ValueError("ended early")
        pos[0] += 1
        return toks[pos[0] - 1]

    def value() -> Any:          # a number (or a sum of them), or a parenthesised expression
        if peek() == "(":
            take()
            v = disj()
            if take() != ")":
                raise ValueError("unbalanced")
        elif peek().isdigit():
            v = int(take())
        else:
            raise ValueError("unexpected token")
        while peek() == "+":
            take()
            w = value()
            if isinstance(v, bool) or isinstance(w, bool):
                raise ValueError("a sum of conditions")
            v = v + w
        return v

    def comparison() -> Any:
        v = value()
        if peek() in (">", "<", ">=", "<=", "=", "=="):
            op = take()
            w = value()
            if isinstance(v, bool) or isinstance(w, bool):
                raise ValueError("a comparison of conditions")
            v = {">": v > w, "<": v < w, ">=": v >= w, "<=": v <= w, "=": v == w, "==": v == w}[op]
        return v

    def negation() -> Any:
        if peek() == "NOT":
            take()
            return not negation()
        return comparison()

    def conj() -> Any:
        v = negation()
        while peek() == "AND":
            take()
            w = negation()
            v = bool(v) and bool(w)
        return v

    def disj() -> Any:
        v = conj()
        while peek() == "OR":
            take()
            w = conj()
            v = bool(v) or bool(w)
        return v

    try:
        out = disj()
    except (ValueError, KeyError):
        return None
    if pos[0] != len(toks) or not isinstance(out, bool):
        return None
    return out


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(s).lower()).strip("-")[:60] or "rule"


def dlp_files(ctx: Dict[str, Any], *, meta_only: bool = False, rng: Any = None) -> List[Dict[str, Any]]:
    """One synthetic test file per DLP rule (the inline rule; its Endpoint,
    SaaS and Email mirrors use the same engine and are named in it)."""
    import random
    import pack_library
    r_ = rng if rng is not None else random.Random(1075)
    out: List[Dict[str, Any]] = []
    for pid, pname, b in _pack_bundles(ctx["profile"]):
        dicts = {d.get("name"): d for d in b.get("dictionaries") or []}
        engines = {e.get("name"): e for e in b.get("engines") or []}
        policies = b.get("policies") or []
        for rule in policies:
            if rule.get("channel") not in (None, "", "web"):
                continue
            name = str(rule.get("name") or "")
            fname = f"dlp-{_slug(pid)}-{_slug(name)}.txt"
            mirrors = [m.get("name") for m in policies if m is not rule and m.get("engines") == rule.get("engines")]
            item = {"id": fname, "name": fname, "rule": name, "pack": pname, "mirrors": mirrors}
            if meta_only:
                out.append(item)
                continue
            lines = [f"### {BANNER}", "", f"SYNTHETIC TEST DATA for the DLP rule: {name} (policy pack: {pname})",
                     f"Also tests its mirrors: {', '.join(map(str, mirrors)) or 'none'}", ""]
            verdicts = []
            for en in rule.get("engines") or []:
                e = engines.get(en) or {}
                expr = str(e.get("expression") or "")
                refs, neg = _refs(expr), _negated(expr)
                counts: Dict[str, int] = {}
                unsure: List[str] = []
                coverage, body = [], []
                for dn in refs:
                    d = dicts.get(dn) or {"name": dn}
                    if dn in neg:
                        coverage.append(f"  {dn}: left out on purpose (the engine excludes it)")
                        continue
                    samples, how, n, uncertain = _dict_samples(d, r_)
                    counts[dn] = n
                    if uncertain:
                        unsure.append(dn)
                    coverage.append(f"  {dn}: {'covered with ' + how if samples else 'NOT covered: ' + how}")
                    for i in range(3):
                        body += [f"[{i + 1}] {x}" for x in samples]
                best = _evaluate(expr, counts)
                worst = _evaluate(expr, {k: (0 if k in unsure else v) for k, v in counts.items()})
                verdict = best if best is not True or worst is True else "maybe"
                verdicts.append(verdict)
                lines += [f"Engine: {en}"] + coverage + [
                    "Expected: " + ({True: "this file satisfies the engine's expression (checked locally with Python regular expressions; "
                                           "ZIA's own matching and confidence may differ)",
                                     "maybe": "fires only if the tenant's SSN or TIN dictionary counts the reserved example SSNs "
                                              "(a strict one does not)",
                                     False: "this file may NOT fire the engine (see the dictionaries not covered above)",
                                     None: "not evaluated: the engine's expression could not be read here"}[verdict]), "",
                    "----- SAMPLE DOCUMENT (SYNTHETIC TEST DATA) -----"] + body + ["----- END OF SYNTHETIC TEST DATA -----", ""]
            item["expected"] = verdicts[0] if len(verdicts) == 1 else (all(v is True for v in verdicts) or None)
            item["content"] = ("\r\n".join(lines)).encode("utf-8")
            out.append(item)
            if len(out) >= MAX_FILES:
                return out
    return out


# ---------------------------------------------------------------------------
# The files
# ---------------------------------------------------------------------------
FILES: Dict[str, Tuple[str, str]] = {
    "mapping.html": ("Control mapping report (HTML)", "text/html; charset=utf-8"),
    "mapping.csv": ("Control mapping (CSV)", "text/csv; charset=utf-8"),
    "mapping.xlsx": ("Control mapping (Excel)", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
    "policy.json": ("Policy export (JSON)", "application/json"),
    "policy.csv": ("Policy export (CSV)", "text/csv; charset=utf-8"),
    "testplan.html": ("Test plan by control (HTML)", "text/html; charset=utf-8"),
    "testplan.csv": ("Test plan by control (CSV)", "text/csv; charset=utf-8"),
    "compliance-pack.zip": ("Everything above and the DLP test files (ZIP)", "application/zip"),
}
_FILE_ID = re.compile(r"^[a-z0-9][a-z0-9.-]{0,90}$")


def manifest(ctx: Dict[str, Any]) -> Dict[str, Any]:
    dl = dlp_files(ctx, meta_only=True)
    return {"profile": ctx["profile"], "label": ctx["summary"]["label"], "summary": ctx["summary"], "built": bool(ctx.get("built")),
            "counts": ctx["mapping"]["counts"], "tier_warning": ctx.get("tier_warning", ""),
            "files": [{"id": k, "label": v[0]} for k, v in FILES.items()] +
                     [{"id": f["id"], "label": f"Synthetic DLP test file: {f['rule']} ({f['pack']})", "dlp": True} for f in dl]}


def _readme(ctx: Dict[str, Any]) -> bytes:
    s = ctx["summary"]
    text = [f"Compliance pack: {s['label']}", "", s["what"], "", *s["lines"], "",
            "Files: mapping (HTML, CSV, XLSX), policy export (JSON, CSV), test plan by control (HTML, CSV) and dlp/*.txt, one "
            "synthetic DLP test file per DLP rule.", "", BANNER, "",
            "Controls marked 'assumed' are not verified against their source; the mapping report lists why."]
    return "\r\n".join(text).encode("utf-8")


def render(ctx: Dict[str, Any], file_id: str) -> Tuple[bytes, str, str]:
    """(bytes, media type, download name) of one file; PackError(404) for
    an unknown id."""
    if not isinstance(file_id, str) or not _FILE_ID.fullmatch(file_id):
        raise PackError("No such file in the compliance pack.", 404)
    base = f"{ctx['profile'].lower()}-"
    if file_id in FILES:
        media = FILES[file_id][1]
        if file_id == "mapping.html":
            data = mapping_html(ctx)
        elif file_id == "mapping.csv":
            data = mapping_csv(ctx)
        elif file_id == "mapping.xlsx":
            data = mapping_xlsx(ctx)
        elif file_id == "policy.json":
            data = json.dumps(policy(ctx), indent=2, default=str).encode("utf-8")
        elif file_id == "policy.csv":
            data = policy_csv(ctx)
        elif file_id == "testplan.html":
            data = testplan_html(ctx)
        elif file_id == "testplan.csv":
            data = testplan_csv(ctx)
        else:
            data = zip_all(ctx)
        return data, media, base + file_id
    for f in dlp_files(ctx):
        if f["id"] == file_id:
            return f["content"], "text/plain; charset=utf-8", base + file_id
    raise PackError("No such file in the compliance pack.", 404)


def zip_all(ctx: Dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("README.txt", _readme(ctx))
        for fid in FILES:
            if fid != "compliance-pack.zip":
                z.writestr(fid, render(ctx, fid)[0])
        for f in dlp_files(ctx):
            z.writestr("dlp/" + f["id"], f["content"])
    return buf.getvalue()


__all__ = ["build", "manifest", "render", "PackError", "FILES", "BANNER", "dlp_files", "test_plan", "policy", "default_spec"]
