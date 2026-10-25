"""The in-house Excel writer (xlsx_writer): a standards-correct Office
Open XML SpreadsheetML package without a spreadsheet library.

Every workbook is checked the way a spreadsheet application opens it:
the package parts, their content types and relationships, then each XML
part parsed. When openpyxl happens to be installed it reads the workbook
back too (it is not a dependency and is never installed for this).
"""
from __future__ import annotations

import importlib.util
import io
import re
import zipfile
from xml.etree import ElementTree as ET

import pytest

import xlsx_writer as xw

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "pr": "http://schemas.openxmlformats.org/package/2006/relationships",
      "ct": "http://schemas.openxmlformats.org/package/2006/content-types"}
R_ID = "{%s}id" % NS["r"]


def _col_index(ref: str) -> int:
    letters = re.match(r"[A-Z]+", ref).group(0)
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def check_package(data: bytes) -> zipfile.ZipFile:
    """The parts, content types and relationships a spreadsheet application
    needs to open the file, every XML part well-formed; no formula anywhere."""
    z = zipfile.ZipFile(io.BytesIO(data))
    names = set(z.namelist())
    for part in ("[Content_Types].xml", "_rels/.rels", "xl/workbook.xml", "xl/_rels/workbook.xml.rels", "xl/styles.xml"):
        assert part in names, part
    for n in names:
        if n.endswith(".xml") or n.endswith(".rels"):
            ET.fromstring(z.read(n))     # well-formed
    ct = ET.fromstring(z.read("[Content_Types].xml"))
    defaults = {d.get("Extension"): d.get("ContentType") for d in ct.findall("ct:Default", NS)}
    overrides = {o.get("PartName"): o.get("ContentType") for o in ct.findall("ct:Override", NS)}
    assert defaults["rels"] == "application/vnd.openxmlformats-package.relationships+xml"
    assert overrides["/xl/workbook.xml"] == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
    assert overrides["/xl/styles.xml"].endswith("spreadsheetml.styles+xml")
    for o in overrides:
        assert o.lstrip("/") in names, o
    root = {r.get("Type").rsplit("/", 1)[-1]: r.get("Target") for r in ET.fromstring(z.read("_rels/.rels")).findall("pr:Relationship", NS)}
    assert root["officeDocument"] == "xl/workbook.xml"
    rels = {r.get("Id"): r for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels")).findall("pr:Relationship", NS)}
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    sheets = wb.findall("m:sheets/m:sheet", NS)
    assert sheets
    ids = set()
    for s in sheets:
        rel = rels[s.get(R_ID)]
        assert rel.get("Type").endswith("/worksheet")
        target = "xl/" + rel.get("Target")
        assert target in names and overrides["/" + target].endswith("spreadsheetml.worksheet+xml")
        assert s.get("sheetId") not in ids
        ids.add(s.get("sheetId"))
        ws = ET.fromstring(z.read(target))
        assert ws.find(".//m:f", NS) is None, "a formula cell"
    assert any(r.get("Type").endswith("/styles") for r in rels.values())
    return z


def read_workbook(data: bytes) -> dict:
    """{sheet name: rows of cell text (None for an empty cell), by column}."""
    z = check_package(data)
    rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels"))}
    out = {}
    for s in ET.fromstring(z.read("xl/workbook.xml")).findall("m:sheets/m:sheet", NS):
        ws = ET.fromstring(z.read("xl/" + rels[s.get(R_ID)]))
        rows = []
        for row in ws.find("m:sheetData", NS):
            vals: list = []
            for c in row:
                i = _col_index(c.get("r"))
                vals += [None] * (i + 1 - len(vals))
                t, v = c.find("m:is/m:t", NS), c.find("m:v", NS)
                vals[i] = t.text if t is not None else (v.text if v is not None else None)
            rows.append(vals)
        out[s.get("name")] = rows
    return out


def sheet_xml(data: bytes, index: int = 1) -> ET.Element:
    return ET.fromstring(zipfile.ZipFile(io.BytesIO(data)).read(f"xl/worksheets/sheet{index}.xml"))


def _sample() -> bytes:
    wb = xw.Workbook(title="Sample <&> workbook")
    ws = wb.add_sheet("Findings", columns=["ID", "Title", "Count", "Notes"])
    ws.append(["A.1", "=HYPERLINK(\"http://x.example/?\"&A1,\"Click\")", 3, "short"])
    ws.append(["A.2", "+cmd|' /C calc'!A0", 2.5, "line one\nline two"])
    ws.append(["A.3", "-5", -7, "x" * 300])
    ws.append(["A.4", "@SUM(A1)", True, None])
    s = wb.add_sheet("Summary", freeze=False)
    s.append(["Tenant", "acme <prod> & co"], bold=True)
    return wb.to_bytes()


def test_the_package_has_every_part_content_type_and_relationship():
    data = _sample()
    z = check_package(data)
    core = z.read("docProps/core.xml").decode()
    assert "<dc:creator>Zscaler Made Easy</dc:creator>" in core and "Sample &lt;&amp;&gt; workbook" in core
    assert xw.MEDIA_TYPE == "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"


def test_header_is_bold_frozen_and_filtered_and_the_table_has_an_autofilter():
    data = _sample()
    ws = sheet_xml(data, 1)
    pane = ws.find("m:sheetViews/m:sheetView/m:pane", NS)
    assert pane.get("state") == "frozen" and pane.get("ySplit") == "1" and pane.get("topLeftCell") == "A2"
    assert ws.find("m:autoFilter", NS).get("ref") == "A1:D5"
    header = ws.find("m:sheetData/m:row", NS)
    assert {c.get("s") for c in header} == {str(xw.S_HEADER)}
    styles = ET.fromstring(zipfile.ZipFile(io.BytesIO(data)).read("xl/styles.xml"))
    xfs = styles.findall("m:cellXfs/m:xf", NS)
    fonts = styles.findall("m:fonts/m:font", NS)
    assert fonts[int(xfs[xw.S_HEADER].get("fontId"))].find("m:b", NS) is not None
    assert xfs[xw.S_WRAP].find("m:alignment", NS).get("wrapText") == "1"
    # Excel's own name for the filter range, hidden, per sheet.
    wb = ET.fromstring(zipfile.ZipFile(io.BytesIO(data)).read("xl/workbook.xml"))
    dn = wb.find("m:definedNames/m:definedName", NS)
    assert dn.get("name") == "_xlnm._FilterDatabase" and dn.get("localSheetId") == "0" and dn.text == "'Findings'!$A$1:$D$5"
    # The free-form sheet: no frozen pane, no filter; a bold row.
    ws2 = sheet_xml(data, 2)
    assert ws2.find("m:sheetViews/m:sheetView/m:pane", NS) is None and ws2.find("m:autoFilter", NS) is None
    assert {c.get("s") for c in ws2.find("m:sheetData/m:row", NS)} == {str(xw.S_BOLD)}


def test_numbers_are_numbers_and_text_is_inline_never_a_formula():
    ws = sheet_xml(_sample(), 1)
    cells = {c.get("r"): c for c in ws.iter("{%s}c" % NS["m"])}
    assert cells["C2"].get("t") is None and cells["C2"].find("m:v", NS).text == "3"
    assert cells["C3"].find("m:v", NS).text == "2.5" and cells["C4"].find("m:v", NS).text == "-7"
    assert cells["B2"].get("t") == "inlineStr"
    assert ws.find(".//m:f", NS) is None
    rows = read_workbook(_sample())["Findings"]
    # Formula-looking text keeps csv_safe's quote; a plain signed number as text does not.
    assert rows[1][1].startswith("'=HYPERLINK(")
    assert rows[2][1] == "'+cmd|' /C calc'!A0"
    assert rows[3][1] == "-5"
    assert rows[4][1] == "'@SUM(A1)"
    assert rows[4][2] == "Yes" and len(rows[4]) == 3     # True as Yes; None as no cell at all
    assert rows[2][3] == "line one\nline two"


def test_long_and_multiline_cells_wrap_and_widths_are_sized_and_capped():
    data = _sample()
    ws = sheet_xml(data, 1)
    cols = [float(c.get("width")) for c in ws.findall("m:cols/m:col", NS)]
    assert cols[0] == xw.WIDTH_MIN or cols[0] < 12
    assert cols[3] == xw.WIDTH_MAX                      # 300 characters: capped
    cells = {c.get("r"): c for c in ws.iter("{%s}c" % NS["m"])}
    assert cells["D4"].get("s") == str(xw.S_WRAP)       # long
    assert cells["D3"].get("s") == str(xw.S_WRAP)       # multi-line
    assert cells["D2"].get("s") == str(xw.S_TOP)


def test_text_is_escaped_and_characters_xml_cannot_carry_are_removed():
    wb = xw.Workbook()
    wb.add_sheet("T", columns=["A"], rows=[["a<b>&c \"q\" \x00\x07\x1b\ud800 ￾ end"], ["tab\there"]])
    rows = read_workbook(wb.to_bytes())["T"]
    assert rows[1][0] == "a<b>&c \"q\"   end"
    assert rows[2][0] == "tab\there"


def test_a_cell_longer_than_excel_allows_is_truncated_visibly():
    wb = xw.Workbook()
    wb.add_sheet("T", columns=["A"], rows=[["y" * 40000]])
    v = read_workbook(wb.to_bytes())["T"][1][0]
    assert len(v) == xw.MAX_CELL_CHARS and v.endswith(xw.TRUNCATED)


@pytest.mark.parametrize("raw, want", [
    ("Findings", "Findings"),
    ("a/b\\c[d]e:f*g?h", "a b c d e f g h"),
    ("'quoted'", "quoted"),
    ("x" * 40, "x" * 31),
    ("", "Sheet"),
    ("History", "History data"),
])
def test_sheet_names_are_sanitised(raw, want):
    assert xw.sanitize_sheet_name(raw) == want


def test_sheet_names_are_unique_whatever_the_case():
    wb = xw.Workbook()
    names = [wb.add_sheet(n).name for n in ("Rules", "rules", "RULES", "x" * 40, "x" * 31)]
    assert names[:3] == ["Rules", "rules (2)", "RULES (3)"]
    assert len({n.lower() for n in names}) == 5 and all(len(n) <= 31 for n in names)
    assert set(read_workbook(wb.to_bytes())) == set(names)


def test_a_sheet_name_with_an_apostrophe_is_quoted_in_the_filter_range():
    wb = xw.Workbook()
    wb.add_sheet("Bob's rules", columns=["A"], rows=[[1]])
    dn = ET.fromstring(zipfile.ZipFile(io.BytesIO(wb.to_bytes())).read("xl/workbook.xml")).find("m:definedNames/m:definedName", NS)
    assert dn.text == "'Bob''s rules'!$A$1:$A$2"


def test_column_letters():
    assert [xw.col_letter(i) for i in (0, 25, 26, 27, 51, 52, 701, 702, 16383)] == \
        ["A", "Z", "AA", "AB", "AZ", "BA", "ZZ", "AAA", "XFD"]


def test_an_empty_workbook_still_opens():
    data = xw.Workbook().to_bytes()
    assert list(read_workbook(data)) == ["Sheet1"]


@pytest.mark.skipif(importlib.util.find_spec("openpyxl") is None, reason="openpyxl is not installed (it is not a dependency)")
def test_openpyxl_reads_the_workbook_back():  # pragma: no cover - only where openpyxl happens to be installed
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(_sample()))
    ws = wb["Findings"]
    assert ws.freeze_panes == "A2" and ws.auto_filter.ref == "A1:D5"
    assert ws["C2"].value == 3 and ws["B2"].value.startswith("'=") and ws["A1"].font.b
