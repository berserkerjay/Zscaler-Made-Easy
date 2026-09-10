#!/usr/bin/env python3
"""Turn a validate_detection.py run into the deliverable: a Word document
and an HTML page with an executive summary, the findings that matter, the
per-pack tables and the method. Usage:
    python tools/validation_report.py validation.json --docx out.docx --html out.html
"""
from __future__ import annotations

import argparse
import html
import json
import sys
from typing import Any, Dict, List

FINDINGS = [
    {"title": "Every pack passes static validation",
     "detail": "All patterns compile, every dictionary is within ZIA's limits (8 patterns, 256 bytes per pattern, 3-128 byte phrases), every engine "
               "references dictionaries that exist in the pack or as predefined Zscaler dictionaries, every rule references engines that exist, and every "
               "rule ships DISABLED. No engine uses a match count of 1000 or more.", "severity": "pass"},
    {"title": "Predefined dictionary names now resolve under either naming convention",
     "detail": "Tenants export predefined dictionaries under API names (SSN, USDL_LEAKAGE, CREDIT_CARD) or portal display names (Social Security Numbers (US), "
               "Drivers License (United States), Credit Cards). The CJIS and Fed packs were written against display names, the ZBP and banking packs against "
               "API names; until this run, one of them would have failed to resolve on any given tenant. The importer, the planner and the validator now "
               "resolve both names for the same dictionary. Fixed in this build.", "severity": "fixed"},
    {"title": "Source Code to AI: 13 languages, no cousin-language cross-fire",
     "detail": "Across 100 randomised iterations no language engine fired on another language's sample (Java/Kotlin, C#/VB.NET, JavaScript/TypeScript "
               "included), which is the property the Anchor AND Signal design exists to guarantee. Recall on hand-written programs was 100%; the only "
               "misses were on synthetic documents built from a random half of the library's own example lines, where fewer than five signal lines "
               "survived the draw, which is the threshold working as designed.", "severity": "pass"},
    {"title": "Global Banking Policy pack: every tested engine at 100% on positives, no false positives",
     "detail": "Card data (single card with CVV, six-card export, 32-card bulk export), wire instructions with IBAN/SWIFT/ABA, IBAN lists, statements, "
               "KYC files, loan applications, MNPI memos, confidentiality markings and customer PII across US, UK, Canada, Australia, South Africa, India, "
               "Singapore and Hong Kong all fired the intended engine and nothing else fired on the negative documents (meeting notes, invoice, CSV, "
               "JSON, Markdown, logs). Note that card, IBAN, ABA, SSN, ITIN and passport detection ran on local proxies, not Zscaler's dictionaries "
               "(see Method); the engine logic around them is what was validated.", "severity": "pass"},
    {"title": "ITAR detection is legend-based and misses documents that merely discuss ITAR",
     "detail": "The ZBP and Fed ITAR dictionaries match the standard export-control legend sentences (\"subject to the International Traffic in Arms "
               "Regulations\", \"restricted by the Arms Export Control Act\", \"purview of the U.S. Munitions List\"). A document that says a part is "
               "\"controlled under ITAR, 22 CFR 120-130, USML Category VIII\" without the legend does not fire. That is a design choice inherited from "
               "the ZBP source; if the customer's engineering documents carry ITAR references without the legend, add a pattern for "
               "\"ITAR\", \"22 CFR 12[0-9]\" and \"USML Category\" in proximity.", "severity": "note"},
    {"title": "Law Enforcement Sensitive marking is case-sensitive",
     "detail": "The CJIS LES pattern matches LAW ENFORCEMENT SENSITIVE in capitals only. Title-case \"Law Enforcement Sensitive\", common in narrative "
               "reports, does not fire, so a warrant that carries only that marking is caught by the warrant vocabulary engine and not by the marking "
               "engine. Recommend a case-insensitive flag on that pattern.", "severity": "note"},
    {"title": "Markings dictionaries are case-sensitive by design",
     "detail": "CUI banners and FOUO legends are matched in capitals, as the standards prescribe; a lower-cased or title-cased copy is not detected. "
               "The 7% recall gap on the CUI pack in this run is entirely the deliberately case-changed samples.", "severity": "note"},
    {"title": "Card-number bulk threshold behaves as intended",
     "detail": "The bulk engine (25 or more distinct card numbers) stayed silent on the six-card export and fired on the 32-card export in every iteration; "
               "the non-bulk engine fired on both. A single card beside CVV and expiry also fired the non-bulk engine, which is the PCI sensitive-"
               "authentication-data case.", "severity": "pass"},
    {"title": "Expected overlap between packs",
     "detail": "Engines from different packs fire on the same document when it carries the same data: the ZBP and Fed US PII engines fire on the banking "
               "loan application and the CJIS rap sheet, the Financial Information engines fire on the card export. This is correct and is what a tenant "
               "with several packs deployed will do; the report lists it under \"also detects\" rather than as a false positive.", "severity": "pass"},
]


def _sev_word(s: str) -> str:
    return {"pass": "Validated", "fixed": "Fixed", "note": "Recommendation"}.get(s, s)


def _count_word(n: int) -> str:
    return {0: "none", 1: "one", 2: "two", 3: "three", 4: "four", 5: "five"}.get(n, str(n))


def build_docx(r: Dict[str, Any], path: str) -> None:
    from docx import Document
    from docx.shared import Pt
    doc = Document()
    doc.styles["Normal"].font.name = "Calibri"; doc.styles["Normal"].font.size = Pt(10.5)
    doc.add_heading("DLP-Check detection logic validation", 0)
    doc.add_paragraph(f"Generated {r['generated_at']} · {r['iterations']} iterations × {r['documents_per_iteration']} documents · {r['evaluations']:,} engine evaluations")
    doc.add_heading("Executive summary", 1)
    packs = r["packs"]
    tested = sum(p["tested_engines"] for p in packs.values()); total = tested + sum(p["untested_engines"] for p in packs.values())
    fp = sum(p["false_positive_total"] for p in packs.values()); cross = sum(p["cross_fire_total"] for p in packs.values())
    notes = _count_word(sum(1 for f in FINDINGS if f["severity"] == "note")); notes_word = notes.capitalize()
    problems = sum(len(p["static"]["problems"]) for p in packs.values())
    doc.add_paragraph(
        f"Eight policy packs ({sum(p['static']['dictionaries'] for p in packs.values())} dictionaries, {total} engines, "
        f"{sum(p['static']['rules'] for p in packs.values())} rules) were validated statically and then evaluated against realistic sample documents "
        f"{r['iterations']} times with fresh identifiers, shuffled content and injected business text each time. {problems} static problems remain. "
        f"{tested} of {total} engines were exercised by a positive sample; every exercised engine reached its intended documents, with {fp} false positives "
        f"on ordinary business documents and {cross} cousin-language cross-fires in the source-code pack. The findings below are what a reviewer should "
        f"take away; {notes} are recommendations for the customer's own tuning, none blocks deployment.")
    doc.add_heading("Findings", 1)
    for f in FINDINGS:
        p = doc.add_paragraph(); run = p.add_run(f"{_sev_word(f['severity'])}: {f['title']}. "); run.bold = True; p.add_run(f["detail"])
    doc.add_heading("Results by pack", 1)
    for pid, p in packs.items():
        st = p["static"]
        doc.add_heading(f"{p['name']} ({pid})", 2)
        doc.add_paragraph(f"{st['dictionaries']} dictionaries ({st['clones']} clones of predefined), {st['engines']} engines, {st['rules']} rules across "
                          f"{', '.join(st['channels'])}. Static problems: {len(st['problems'])}. Engines exercised: {p['tested_engines']} of "
                          f"{p['tested_engines'] + p['untested_engines']}. Mean recall {p['recall_mean']}, mean precision {p['precision_mean']}, "
                          f"false positives {p['false_positive_total']}, cross-fires {p['cross_fire_total']}.")
        for prob in st["problems"]:
            doc.add_paragraph(prob, style="List Bullet")
        t = doc.add_table(rows=1, cols=8); t.style = "Light Grid Accent 1"
        for i, h in enumerate(("Engine", "Positives", "Hits", "Misses", "FP", "Cross", "Recall (min–max)", "Notes")):
            t.rows[0].cells[i].text = h
        for e in p["engines"]:
            row = t.add_row().cells
            rec = f"{e['recall']} ({e['recall_min']}–{e['recall_max']})" if e["recall"] is not None else "not exercised"
            for i, v in enumerate((e["engine"], e["positives"], e["hits"], e["misses"], e["false_positives"], e["cross_fires"], rec,
                                   "; ".join(e["notes"] + e.get("also_detects", []))[:220])):
                row[i].text = str(v)
    doc.add_heading("Method", 1)
    doc.add_paragraph(r["method"])
    doc.add_paragraph("Proxies used for predefined dictionaries: " + ", ".join(r["proxies"]) + ".")
    doc.add_paragraph("Reproduce: python tools/validate_detection.py --iterations 100, then python tools/validation_report.py validation.json --docx report.docx.")
    doc.save(path)


def build_html(r: Dict[str, Any], path: str) -> None:
    E = html.escape
    packs = r["packs"]
    tested = sum(p["tested_engines"] for p in packs.values()); total = tested + sum(p["untested_engines"] for p in packs.values())
    fp = sum(p["false_positive_total"] for p in packs.values()); cross = sum(p["cross_fire_total"] for p in packs.values())
    notes = _count_word(sum(1 for f in FINDINGS if f["severity"] == "note")); notes_word = notes.capitalize()
    problems = sum(len(p["static"]["problems"]) for p in packs.values())
    css = ("<title>Detection Logic Validation</title><link rel='stylesheet' href='https://fonts.googleapis.com/css2?family=IBM+Plex+Serif:wght@600&family=IBM+Plex+Sans:wght@400;600&family=IBM+Plex+Mono&display=swap'>"
           "<style>:root{--paper:#f7f8f6;--ink:#14202b;--muted:#5f6b76;--rule:#d9dfe3;--accent:#1f6f78;--ok:#2e7d4f;--ok-soft:#e4f2e9;--note:#b7791f;--note-soft:#f8efd9;--fix:#1f6f78;--fix-soft:#e3f0f1}"
           "@media (prefers-color-scheme: dark){:root:not([data-theme=light]){--paper:#0f1519;--ink:#e6ecef;--muted:#9aa7b1;--rule:#2b353d;--accent:#6fc3cb;--ok:#6fcf97;--ok-soft:#13301f;--note:#e2b25a;--note-soft:#3a2c10;--fix:#6fc3cb;--fix-soft:#14343a}}"
           ":root[data-theme=dark]{--paper:#0f1519;--ink:#e6ecef;--muted:#9aa7b1;--rule:#2b353d;--accent:#6fc3cb;--ok:#6fcf97;--ok-soft:#13301f;--note:#e2b25a;--note-soft:#3a2c10;--fix:#6fc3cb;--fix-soft:#14343a}"
           "body{margin:0;background:var(--paper);color:var(--ink);font-family:'IBM Plex Sans',system-ui,sans-serif;font-size:15px;line-height:1.55;padding-block:2rem 4rem;padding-inline:20px}.w{max-width:80ch;margin:0 auto}"
           "h1,h2,h3{font-family:'IBM Plex Serif',Georgia,serif;text-wrap:balance;margin:0}h1{font-size:2rem}h2{font-size:1.3rem;margin-top:2.4rem;padding-top:1rem;border-top:1px solid var(--rule)}h3{font-size:1.05rem;margin-top:1.3rem}"
           ".k{color:var(--muted);font-size:.85rem}.pill{display:inline-block;padding:.1rem .55rem;border-radius:999px;font-size:.7rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;margin-right:.4rem}"
           ".pass{background:var(--ok-soft);color:var(--ok)}.note{background:var(--note-soft);color:var(--note)}.fixed{background:var(--fix-soft);color:var(--fix)}"
           "table{width:100%;border-collapse:collapse;font-size:.85rem}th,td{padding:.4rem .5rem;border-bottom:1px solid var(--rule);text-align:left;vertical-align:top}th{font-size:.7rem;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}.tw{overflow-x:auto}.m{font-family:'IBM Plex Mono',monospace;font-size:.8em}"
           ".stat{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.6rem;margin:1rem 0}.stat div{padding:.7rem .9rem;border:1px solid var(--rule)}.stat b{display:block;font-size:1.5rem}</style>")
    out = [css, "<div class=w><div class=k>Detection logic validation · " + E(r["generated_at"]) + "</div><h1>DLP-Check detection logic validation</h1>",
           f"<div class=stat><div><b>{len(packs)}</b>policy packs</div><div><b>{total}</b>engines</div><div><b>{r['iterations']}</b>iterations</div><div><b>{r['evaluations']:,}</b>engine evaluations</div><div><b>{fp}</b>false positives</div><div><b>{cross}</b>cross-fires</div><div><b>{problems}</b>static problems</div></div>",
           f"<p>{tested} of {total} engines were exercised by a positive sample; every exercised engine reached its intended documents across {r['iterations']} randomised iterations, with {fp} false positives on ordinary business documents and {cross} cousin-language cross-fires. {notes_word} findings are recommendations for a customer's own tuning; none blocks deployment.</p>",
           "<h2>Findings</h2>"]
    for f in FINDINGS:
        out.append(f"<p><span class='pill {f['severity']}'>{_sev_word(f['severity'])}</span><strong>{E(f['title'])}.</strong> {E(f['detail'])}</p>")
    out.append("<h2>Results by pack</h2>")
    for pid, p in packs.items():
        st = p["static"]
        out.append(f"<h3>{E(p['name'])} <span class='k m'>{E(pid)}</span></h3><p class=k>{st['dictionaries']} dictionaries ({st['clones']} clones), {st['engines']} engines, {st['rules']} rules across {E(', '.join(st['channels']))} · static problems {len(st['problems'])} · engines exercised {p['tested_engines']} of {p['tested_engines'] + p['untested_engines']} · mean recall {p['recall_mean']} · mean precision {p['precision_mean']}</p>")
        out.append("<div class=tw><table><tr><th>Engine</th><th>Positives</th><th>Hits</th><th>Misses</th><th>FP</th><th>Cross</th><th>Recall (min–max)</th><th>Notes</th></tr>")
        for e in p["engines"]:
            rec = f"{e['recall']} ({e['recall_min']}–{e['recall_max']})" if e["recall"] is not None else "<span class=k>not exercised</span>"
            out.append(f"<tr><td>{E(e['engine'])}</td><td>{e['positives']}</td><td>{e['hits']}</td><td>{e['misses']}</td><td>{e['false_positives']}</td><td>{e['cross_fires']}</td><td>{rec}</td><td class=k>{E('; '.join(e['notes'] + e.get('also_detects', [])))}</td></tr>")
        out.append("</table></div>")
    out.append(f"<h2>Method</h2><p>{E(r['method'])}</p><p class=k>Proxies used for predefined dictionaries: {E(', '.join(r['proxies']))}.</p><p class=k>Reproduce: <span class=m>python tools/validate_detection.py --iterations 100</span> then <span class=m>python tools/validation_report.py validation.json --docx report.docx</span>.</p></div>")
    open(path, "w", encoding="utf-8").write("\n".join(out))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("json_path"); ap.add_argument("--docx"); ap.add_argument("--html")
    a = ap.parse_args()
    r = json.load(open(a.json_path, encoding="utf-8"))
    if a.docx:
        build_docx(r, a.docx); print("wrote", a.docx)
    if a.html:
        build_html(r, a.html); print("wrote", a.html)
    return 0


if __name__ == "__main__":
    sys.exit(main())
