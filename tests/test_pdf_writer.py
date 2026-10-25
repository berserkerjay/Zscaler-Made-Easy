"""The in-house PDF writer (pdf_writer): PDF 1.4 with the standard
Helvetica fonts, WinAnsi text, word wrap, tables that break across pages
and repeat their header, page numbers, a footer line and document info.

The structure is checked by parsing the file the way a reader does: the
cross-reference table's offsets must point at each object, startxref at
the table, the page tree must count the pages. pdftotext / qpdf check it
too when they are on PATH, and so does poppler through LibreOffice's
xpdfimport helper when that is installed.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

import pdf_writer as pw

XPDFIMPORT = "/usr/lib/libreoffice/program/xpdfimport"


def parse_pdf(data: bytes) -> dict:
    """Objects by number (from the xref offsets), the trailer, the pages."""
    assert data.startswith(b"%PDF-1.4\n")
    assert data.rstrip().endswith(b"%%EOF")
    m = re.search(rb"startxref\s+(\d+)\s+%%EOF\s*$", data)
    assert m, "no startxref"
    xref_at = int(m.group(1))
    assert data[xref_at:xref_at + 5] == b"xref\n", "startxref does not point at the xref table"
    head = re.match(rb"xref\n0 (\d+)\n", data[xref_at:])
    count = int(head.group(1))
    pos = xref_at + head.end()
    entries = []
    for i in range(count):
        line = data[pos + 20 * i: pos + 20 * (i + 1)]
        assert len(line) == 20 and line.endswith(b" \n"), line      # every entry is exactly 20 bytes
        entries.append((int(line[:10]), int(line[11:16]), line[17:18]))
    assert entries[0] == (0, 65535, b"f")
    objects = {}
    for n, (off, gen, kind) in enumerate(entries[1:], start=1):
        assert kind == b"n" and gen == 0
        assert data[off:].startswith(b"%d 0 obj\n" % n), f"xref offset of object {n} is wrong"
        end = data.index(b"\nendobj\n", off)
        objects[n] = data[off + len(b"%d 0 obj\n" % n): end]
    trailer = data[data.index(b"trailer", xref_at):]
    size = int(re.search(rb"/Size (\d+)", trailer).group(1))
    assert size == count == len(objects) + 1
    root = int(re.search(rb"/Root (\d+) 0 R", trailer).group(1))
    info = int(re.search(rb"/Info (\d+) 0 R", trailer).group(1))
    assert b"/Type /Catalog" in objects[root]
    pages_ref = int(re.search(rb"/Pages (\d+) 0 R", objects[root]).group(1))
    tree = objects[pages_ref]
    kids = [int(k) for k in re.findall(rb"(\d+) 0 R", re.search(rb"/Kids \[([^\]]*)\]", tree).group(1))]
    assert int(re.search(rb"/Count (\d+)", tree).group(1)) == len(kids)
    pages = []
    for k in kids:
        assert b"/Type /Page " in objects[k] and b"/Parent %d 0 R" % pages_ref in objects[k]
        c = int(re.search(rb"/Contents (\d+) 0 R", objects[k]).group(1))
        body = objects[c]
        length = int(re.search(rb"/Length (\d+)", body).group(1))
        stream = body[body.index(b"stream\n") + 7:]
        assert stream[length:] == b"\nendstream", "stream /Length is wrong"
        pages.append({"obj": objects[k], "stream": stream[:length].decode("ascii")})
    return {"objects": objects, "info": objects[info].decode("ascii"), "pages": pages}


def strings(stream: str) -> list:
    """The text shown by each Tj, unescaped (octal escapes as cp1252)."""
    out = []
    for m in re.finditer(r"\(((?:\\.|[^\\)])*)\) Tj", stream):
        raw = re.sub(r"\\([0-7]{3})", lambda x: chr(int(x.group(1), 8)), m.group(1))
        raw = re.sub(r"\\(.)", r"\1", raw)
        out.append(raw.encode("latin-1").decode("cp1252", errors="replace"))
    return out


def info_text(info: str, key: str) -> str:
    m = re.search(r"/%s <FEFF([0-9A-F]*)>" % key, info)
    return bytes.fromhex(m.group(1)).decode("utf-16-be") if m else ""


def _doc(page_size="A4", rows=150):
    doc = pw.PdfDocument(title="Deployment plan: acme → prod", page_size=page_size, footer="DLP-Check · acme")
    doc.heading("Deployment plan")
    doc.paragraph("Nothing has been written to the tenant. " * 12)
    doc.key_values([("Tenant", "acme (production)"), ("Plan hash", "ab" * 32)])
    doc.bullets(["first warning", "second (with parentheses) and a back\\slash"])
    doc.table(["Kind", "Name", "Reason"], [["Rule", f"Rule {i}", "a reason " * (i % 25)] for i in range(rows)])
    doc.signature_lines(["Requested by", "Approved by", "Date"])
    return doc


def test_structure_xref_offsets_page_tree_and_document_info():
    doc = _doc()
    pdf = parse_pdf(doc.to_bytes())
    assert len(pdf["pages"]) == len(doc.pages) > 2
    assert info_text(pdf["info"], "Producer") == "DLP-Check"
    assert info_text(pdf["info"], "Title") == "Deployment plan: acme → prod"     # info strings are UTF-16: no loss
    assert "/CreationDate (D:" in pdf["info"]
    fonts = b"".join(o for o in pdf["objects"].values() if b"/Type /Font" in o)
    assert b"/BaseFont /Helvetica " in fonts and b"/BaseFont /Helvetica-Bold " in fonts
    assert fonts.count(b"/Encoding /WinAnsiEncoding") == 2 and b"/FontFile" not in fonts    # nothing embedded


@pytest.mark.parametrize("size, box", [("A4", b"[0 0 595.28 841.89]"), ("Letter", b"[0 0 612 792]")])
def test_a4_and_letter(size, box):
    pdf = parse_pdf(_doc(size, rows=5).to_bytes())
    assert all(box in p["obj"] for p in pdf["pages"])


def test_unknown_page_size_is_refused():
    with pytest.raises(ValueError):
        pw.PdfDocument(page_size="A3")


def test_text_appears_and_every_page_has_a_footer_and_its_number():
    pdf = parse_pdf(_doc().to_bytes())
    n = len(pdf["pages"])
    allt = []
    for i, p in enumerate(pdf["pages"], start=1):
        t = strings(p["stream"])
        assert f"Page {i} of {n}" in t
        assert "DLP-Check · acme" in t
        allt += t
    assert "Deployment plan" in allt and "acme (production)" in allt
    assert any("second (with parentheses) and a back\\slash" == s for s in allt)
    assert "Requested by" in allt and "Approved by" in allt and "Date" in allt


def test_a_table_that_breaks_across_pages_repeats_its_header():
    pdf = parse_pdf(_doc().to_bytes())
    pages_with_rows = [p for p in pdf["pages"] if any(s.startswith("Rule ") for s in strings(p["stream"]))]
    assert len(pages_with_rows) >= 2
    for p in pages_with_rows:
        t = strings(p["stream"])
        assert "Kind" in t and "Name" in t and "Reason" in t, "header not repeated"
    names = [s for p in pdf["pages"] for s in strings(p["stream"]) if re.fullmatch(r"Rule \d+", s)]
    assert names == [f"Rule {i}" for i in range(150)]          # every row once, in order


def test_a_row_taller_than_a_page_is_split_and_nothing_is_lost():
    doc = pw.PdfDocument(title="t")
    words = [f"w{i}" for i in range(2500)]
    doc.table(["A", "B"], [["tall", " ".join(words)]])
    pdf = parse_pdf(doc.to_bytes())
    assert len(pdf["pages"]) >= 2
    got = " ".join(s for p in pdf["pages"] for s in strings(p["stream"]) if s.startswith("w")).split()
    assert got == words


def test_winansi_text_and_visible_replacement():
    # Outside WinAnsi: a few symbols spelled out (an arrow as ->), anything else a visible '?'.
    assert pw.winansi("café – €5 → 中\x00\x07\tx ✓") == "café – €5 -> ? x ?"
    assert pw.pdf_string("a(b)c\\d é") == "(a\\(b\\)c\\\\d \\351)"
    doc = pw.PdfDocument(title="t")
    doc.paragraph("café → ok 中")
    pdf = parse_pdf(doc.to_bytes())
    assert "café -> ok ?" in strings(pdf["pages"][0]["stream"])
    # The content streams are plain ASCII (octal escapes), so the file never depends on a byte encoding.
    assert all(ord(ch) < 128 for p in pdf["pages"] for ch in p["stream"])


def test_wrapped_lines_fit_the_width():
    text = "Supercalifragilisticexpialidocious " * 5 + "x" * 300
    for size in (8, 10, 14):
        lines = pw.wrap(text, size, 200)
        assert len(lines) > 3
        assert all(pw.text_width(ln, size) <= 200 + 0.01 for ln in lines)
    assert pw.wrap("one\ntwo", 10, 500) == ["one", "two"]
    assert pw.text_width("A", 10) == pytest.approx(6.67) and pw.text_width("A", 10, bold=True) == pytest.approx(7.22)


def test_an_empty_document_is_one_valid_page():
    pdf = parse_pdf(pw.PdfDocument(title="Empty").to_bytes())
    assert len(pdf["pages"]) == 1 and "Page 1 of 1" in strings(pdf["pages"][0]["stream"])


@pytest.mark.skipif(shutil.which("qpdf") is None, reason="qpdf is not on PATH")
def test_qpdf_check(tmp_path):  # pragma: no cover - only where qpdf is installed
    f = tmp_path / "t.pdf"
    f.write_bytes(_doc().to_bytes())
    r = subprocess.run(["qpdf", "--check", str(f)], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.skipif(shutil.which("pdftotext") is None, reason="pdftotext is not on PATH")
def test_pdftotext_extracts_the_text(tmp_path):  # pragma: no cover - only where poppler-utils is installed
    f = tmp_path / "t.pdf"
    f.write_bytes(_doc().to_bytes())
    r = subprocess.run(["pdftotext", "-layout", str(f), "-"], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0 and "Deployment plan" in r.stdout and "Rule 149" in r.stdout and "Requested by" in r.stdout


def poppler_chars(data: bytes, tmp_path) -> list:
    """(page, x1, y1, x2, char) for every glyph poppler draws (LibreOffice's xpdfimport)."""
    f = tmp_path / "p.pdf"
    f.write_bytes(data)
    r = subprocess.run([XPDFIMPORT, str(f), str(tmp_path / "err")], input="\n", capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-500:]
    page, out = 0, []
    for line in r.stdout.splitlines():
        parts = line.split(" ")
        if parts[0] == "startPage":
            page += 1
        elif parts[0] == "drawChar":
            out.append((page, float(parts[1]), float(parts[2]), float(parts[3]), parts[-1]))
    return out


@pytest.mark.skipif(not os.access(XPDFIMPORT, os.X_OK), reason="poppler via LibreOffice's xpdfimport is not installed")
def test_poppler_renders_every_page_inside_the_margins(tmp_path):  # pragma: no cover - only where it is installed
    doc = _doc("Letter")
    chars = poppler_chars(doc.to_bytes(), tmp_path)
    assert max(c[0] for c in chars) == len(doc.pages)
    assert all(doc.left - 0.01 <= c[1] and c[3] <= doc.width - doc.right + 0.01 for c in chars)
    assert all(0 < c[2] < doc.height - doc.top + 1 for c in chars)
