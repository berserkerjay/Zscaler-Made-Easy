#!/usr/bin/env python3
"""
Zscaler Assessment — Word Document Report Generator
=====================================================
Generates a professional .docx report from assessment results.

Usage:
    from report_docx import generate_report
    generate_report(results, cfg, "report.docx")

Or standalone:
    python report_docx.py smoes_report.json
"""

import json
import sys
from datetime import datetime
from pathlib import Path

try:
    from docx import Document
    from docx.shared import Inches, Pt, Cm, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.enum.table import WD_TABLE_ALIGNMENT
    from docx.oxml.ns import qn
except ImportError:
    print("Install python-docx:  pip install python-docx")
    sys.exit(1)


# ── Colors ───────────────────────────────────────────────────────────

COLORS = {
    "PASS": RGBColor(0x22, 0x8B, 0x22),    # green
    "FAIL": RGBColor(0xDC, 0x14, 0x3C),    # red
    "REVIEW": RGBColor(0xDA, 0xA5, 0x20),  # gold
    "INFO": RGBColor(0x64, 0x95, 0xED),    # blue
    "ERROR": RGBColor(0x64, 0x95, 0xED),   # blue (same as info)
}

STATUS_LABELS = {
    "PASS": "Configured",
    "FAIL": "Action Required",
    "REVIEW": "Needs Review",
    "INFO": "Not Configured / N/A",
    "ERROR": "Not Configured / N/A",
}


# ── Helpers ──────────────────────────────────────────────────────────

def _set_cell_shading(cell, color_hex):
    """Set background color on a table cell."""
    shading = cell._element.get_or_add_tcPr()
    shading_elem = shading.makeelement(qn("w:shd"), {
        qn("w:val"): "clear",
        qn("w:color"): "auto",
        qn("w:fill"): color_hex,
    })
    shading.append(shading_elem)


def _add_styled_row(table, cells_data):
    """Add a row with optional coloring."""
    row = table.add_row()
    for i, (text, bold, color) in enumerate(cells_data):
        cell = row.cells[i]
        p = cell.paragraphs[0]
        run = p.add_run(str(text))
        run.font.size = Pt(9)
        if bold:
            run.bold = True
        if color:
            run.font.color.rgb = color
    return row


# ── Main Generator ───────────────────────────────────────────────────

def generate_report(results, cfg, output_path, compute_fn=None, maturity_fn=None):
    """
    Generate a Word document report from assessment results.

    Args:
        results: List of check result dicts with id, sec, label, status, detail
        cfg: Config dict with org_name, assessor, cloud
        output_path: Path for the .docx file
        compute_fn: Optional compute function (imported from engine)
        maturity_fn: Optional maturity function (imported from engine)
    """
    # Import compute/maturity if not provided
    if compute_fn is None or maturity_fn is None:
        from dlp_assessment_full_auto import compute, maturity
        compute_fn = compute_fn or compute
        maturity_fn = maturity_fn or maturity

    secs, overall = compute_fn(results)
    mat = maturity_fn(overall)

    doc = Document()

    # ── Styles ────────────────────────────────────────────────────
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(10)

    # ── Title Page ────────────────────────────────────────────────
    doc.add_paragraph()  # spacer
    title = doc.add_heading("Zscaler Platform Assessment Report", level=0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph()
    meta_table = doc.add_table(rows=0, cols=2)
    meta_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    meta_data = [
        ("Organization", cfg.get("org_name", "Unknown")),
        ("Assessor", cfg.get("assessor", "Unknown")),
        ("Cloud", cfg.get("cloud", "Unknown")),
        ("Date", datetime.now().strftime("%B %d, %Y")),
        ("Total Checks", str(len(results))),
        ("Overall Score", f"{overall}%"),
        ("Maturity Level", mat),
    ]
    for label, value in meta_data:
        row = meta_table.add_row()
        row.cells[0].paragraphs[0].add_run(label).bold = True
        row.cells[1].text = value

    doc.add_page_break()

    # ── Executive Summary ─────────────────────────────────────────
    doc.add_heading("Executive Summary", level=1)

    counts = {"PASS": 0, "FAIL": 0, "REVIEW": 0, "INFO": 0}
    for r in results:
        st = r["status"]
        if st in counts:
            counts[st] += 1
        elif st == "ERROR":
            counts["INFO"] += 1

    summary = doc.add_paragraph()
    summary.add_run(f"The Zscaler platform assessment for {cfg.get('org_name', 'the organization')} "
                    f"evaluated {len(results)} configuration checks across all deployed Zscaler services. ")
    summary.add_run(f"The overall maturity score is {overall}% ({mat}). ").bold = True

    summary2 = doc.add_paragraph()
    summary2.add_run(f"Configured correctly: ").bold = True
    summary2.add_run(f"{counts['PASS']} checks. ")
    summary2.add_run(f"Action required: ").bold = True
    summary2.add_run(f"{counts['FAIL']} checks. ")
    summary2.add_run(f"Needs review: ").bold = True
    summary2.add_run(f"{counts['REVIEW']} checks. ")
    summary2.add_run(f"Not configured/N/A: ").bold = True
    summary2.add_run(f"{counts['INFO']} checks.")

    # ── Maturity Model Explanation ────────────────────────────────
    doc.add_heading("Maturity Model & Scoring Methodology", level=2)
    doc.add_paragraph(
        "This assessment uses a five-tier maturity model adapted from the Zscaler "
        "Zero Trust Maturity Framework. The overall score is calculated as the "
        "percentage of evaluable checks that pass, where evaluable checks are those "
        "where the corresponding feature is licensed and accessible via API. Features "
        "marked 'Not Configured / N/A' are excluded from scoring, since they represent "
        "capabilities not currently in use rather than failures."
    )

    mat_table = doc.add_table(rows=1, cols=3)
    mat_table.style = "Light Grid Accent 1"
    mat_headers = ["Score Range", "Maturity Level", "Description"]
    for i, h in enumerate(mat_headers):
        cell = mat_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True

    mat_data = [
        ("0 – 24%", "Ad Hoc",
         "No formal program. Configurations are inconsistent or missing entirely. "
         "Significant exposure to data loss, threats, and compliance gaps. Immediate "
         "remediation needed for foundational security controls."),
        ("25 – 49%", "Initial",
         "Basic security controls in place but not standardized across the organization. "
         "Coverage is partial; key features (DLP, SSL inspection, MFA enforcement) may "
         "be missing or only applied to subsets of users."),
        ("50 – 74%", "Developing",
         "Most foundational controls are configured. Policy framework exists but "
         "consistency, scoping, and tuning need work. Some advanced features in pilot "
         "or limited rollout."),
        ("75 – 89%", "Managed",
         "Strong configuration baseline aligned with Zscaler best practices. Most "
         "policies properly scoped to users/groups. Comprehensive logging in place. "
         "Minor gaps remain in advanced features."),
        ("90 – 100%", "Optimized",
         "Comprehensive, well-tuned configuration matching Zscaler leading practices. "
         "Full coverage across all licensed services. Continuous monitoring, automated "
         "incident response, and integration with SIEM/SOAR. Mature zero trust posture."),
    ]
    current_band = mat
    for score_range, level, desc in mat_data:
        row = mat_table.add_row()
        row.cells[0].text = score_range
        row.cells[1].text = level
        row.cells[2].text = desc
        # Highlight the current maturity level
        if level == current_band:
            for cell in row.cells:
                cell.paragraphs[0].runs[0].bold = True

    doc.add_paragraph()
    you_are = doc.add_paragraph()
    you_are.add_run("Your organization is currently rated: ").italic = True
    your_run = you_are.add_run(f"{mat} ({overall}%)")
    your_run.bold = True
    if overall >= 75:
        your_run.font.color.rgb = COLORS["PASS"]
    elif overall >= 50:
        your_run.font.color.rgb = COLORS["REVIEW"]
    else:
        your_run.font.color.rgb = COLORS["FAIL"]

    # ── Status Definitions ────────────────────────────────────────
    doc.add_heading("Finding Status Definitions", level=2)
    sd_table = doc.add_table(rows=1, cols=2)
    sd_table.style = "Light Grid Accent 1"
    sd_headers = ["Status", "What it Means"]
    for i, h in enumerate(sd_headers):
        cell = sd_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
    sd_data = [
        ("Configured",
         "Feature is enabled and configured in alignment with Zscaler best practices. "
         "No action required."),
        ("Action Required",
         "Critical gap detected. Feature is misconfigured, disabled, or absent where "
         "Zscaler best practice requires it. Address these findings first."),
        ("Needs Review",
         "Feature is present but its configuration requires manual verification or "
         "additional context to determine alignment with best practice. Often indicates "
         "policies that are partially scoped or default values that may not fit your "
         "environment."),
        ("Not Configured / N/A",
         "Feature was not accessible during the assessment. This may indicate it is "
         "not licensed, not deployed, or the API role lacks permission to read it. "
         "These checks are excluded from the overall score."),
    ]
    for status, desc in sd_data:
        row = sd_table.add_row()
        row.cells[0].text = status
        row.cells[0].paragraphs[0].runs[0].bold = True
        row.cells[1].text = desc

    doc.add_page_break()

    # ── Score Summary Table ───────────────────────────────────────
    doc.add_heading("Scorecard by Section", level=2)

    score_table = doc.add_table(rows=1, cols=6)
    score_table.style = "Light Grid Accent 1"
    headers = ["Section", "Score", "Configured", "Action Req.", "Review", "N/A"]
    for i, h in enumerate(headers):
        cell = score_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True

    for sec_name, data in secs.items():
        row = score_table.add_row()
        row.cells[0].text = sec_name
        pct = data["pct"]
        row.cells[1].text = f"{pct}%"
        # Color the score
        run = row.cells[1].paragraphs[0].runs[0]
        if pct >= 75:
            run.font.color.rgb = COLORS["PASS"]
        elif pct >= 50:
            run.font.color.rgb = COLORS["REVIEW"]
        else:
            run.font.color.rgb = COLORS["FAIL"]
        row.cells[2].text = str(data["pass"])
        row.cells[3].text = str(data["fail"])
        row.cells[4].text = str(data["warn"])
        row.cells[5].text = str(data.get("info", 0))

    doc.add_page_break()

    # ── Critical Findings ─────────────────────────────────────────
    fails = [r for r in results if r["status"] == "FAIL"]
    if fails:
        doc.add_heading("Critical Findings — Immediate Action Required", level=1)
        for r in fails:
            p = doc.add_paragraph()
            run = p.add_run(f"{r['id']} — {r['label']}")
            run.bold = True
            run.font.color.rgb = COLORS["FAIL"]
            detail = doc.add_paragraph(r["detail"], style="List Bullet")
            detail.paragraph_format.space_after = Pt(6)
        doc.add_page_break()

    # ── Review Items ──────────────────────────────────────────────
    reviews = [r for r in results if r["status"] == "REVIEW"]
    if reviews:
        doc.add_heading("Items Requiring Review", level=1)
        p = doc.add_paragraph(
            f"The following {len(reviews)} item(s) were detected but require manual "
            f"verification or organizational context to determine if action is needed."
        )
        doc.add_paragraph()
        for r in reviews:
            p = doc.add_paragraph()
            run = p.add_run(f"{r['id']} — {r['label']}: ")
            run.bold = True
            p.add_run(r["detail"])
        doc.add_page_break()

    # ── Detailed Findings by Section ──────────────────────────────
    doc.add_heading("Detailed Findings", level=1)

    current_sec = ""
    for r in results:
        if r["sec"] != current_sec:
            current_sec = r["sec"]
            doc.add_heading(current_sec, level=2)

            # Section summary
            if current_sec in secs:
                sd = secs[current_sec]
                sp = doc.add_paragraph()
                sp.add_run(f"Score: {sd['pct']}% — ")
                sp.add_run(f"{sd['pass']} configured, {sd['fail']} action required, "
                          f"{sd['warn']} review, {sd.get('info',0)} N/A")
                sp.paragraph_format.space_after = Pt(12)

        # Individual check
        p = doc.add_paragraph()
        status = r["status"]
        label = STATUS_LABELS.get(status, status)
        color = COLORS.get(status, RGBColor(0, 0, 0))

        run_id = p.add_run(f"[{r['id']}] ")
        run_id.font.size = Pt(9)
        run_id.font.color.rgb = RGBColor(0x66, 0x66, 0x66)

        run_status = p.add_run(f"{label}  ")
        run_status.bold = True
        run_status.font.color.rgb = color
        run_status.font.size = Pt(9)

        run_label = p.add_run(f"{r['label']}")
        run_label.font.size = Pt(10)

        if r.get("detail"):
            detail_p = doc.add_paragraph()
            detail_p.paragraph_format.left_indent = Cm(1)
            detail_p.paragraph_format.space_after = Pt(4)
            run_d = detail_p.add_run(r["detail"])
            run_d.font.size = Pt(9)
            run_d.font.color.rgb = RGBColor(0x55, 0x55, 0x55)

    # ── Not Configured Summary ────────────────────────────────────
    infos = [r for r in results if r["status"] in ("INFO", "ERROR")]
    if infos:
        doc.add_page_break()
        doc.add_heading("Features Not Configured or Not Licensed", level=1)
        p = doc.add_paragraph(
            f"The following {len(infos)} feature(s) were not accessible during the assessment. "
            f"This may indicate the feature is not licensed, not configured, or the API client "
            f"role does not have permission to read this data."
        )
        doc.add_paragraph()

        nc_table = doc.add_table(rows=1, cols=3)
        nc_table.style = "Light Grid Accent 1"
        nc_table.rows[0].cells[0].text = "Check"
        nc_table.rows[0].cells[1].text = "Feature"
        nc_table.rows[0].cells[2].text = "Detail"
        for cell in nc_table.rows[0].cells:
            cell.paragraphs[0].runs[0].bold = True

        for r in infos:
            row = nc_table.add_row()
            row.cells[0].text = r["id"]
            row.cells[1].text = r["label"]
            # Truncate long details for table
            detail = r.get("detail", "")
            row.cells[2].text = detail[:120] + ("..." if len(detail) > 120 else "")
            for cell in row.cells:
                for p in cell.paragraphs:
                    for run in p.runs:
                        run.font.size = Pt(8)

    # ── Footer ────────────────────────────────────────────────────
    doc.add_page_break()
    doc.add_heading("About This Assessment", level=1)
    doc.add_paragraph(
        "This report was generated by the Zscaler Platform Assessment Automation Engine. "
        "All checks are performed via the Zscaler OneAPI using read-only API calls. "
        "No configuration changes were made during the assessment."
    )
    doc.add_paragraph(
        f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}"
    )
    doc.add_paragraph(f"Engine version: 3.0 | Total checks: {len(results)}")

    # ── Save ──────────────────────────────────────────────────────
    doc.save(output_path)
    return output_path


# ── CLI Usage ────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python report_docx.py <report.json> [output.docx]")
        sys.exit(1)

    json_path = sys.argv[1]
    with open(json_path) as f:
        data = json.load(f)

    results = data.get("checks", [])
    cfg = data.get("metadata", {})
    output = sys.argv[2] if len(sys.argv) > 2 else json_path.replace(".json", ".docx")

    generate_report(results, cfg, output)
    print(f"Report saved: {output}")
