"""A small Excel (.xlsx) writer: Office Open XML SpreadsheetML, written
with zipfile and plain XML, so no spreadsheet library joins the locked
dependencies (requirements.lock, SBOM, third-party notices).

What it does, and nothing more:

* several sheets, each a table with a bold header row that stays frozen
  while scrolling and an AutoFilter over the table, or free rows (a
  summary) with any row in bold;
* column widths sized to the content, capped; long or multi-line cells
  wrap;
* numbers are numbers, everything else is an inline string. No cell is
  ever a formula, so a value can never run in Excel. A text cell that
  starts like a formula (= + - @ ...) is still prefixed with a quote, the
  way csv_safe does it for CSV, so every export of the app reads the same;
* sheet names sanitised (31 characters, none of [ ] : * ? / \\, unique);
  text XML-escaped, characters XML cannot carry removed.

Usage::

    wb = Workbook(title="DLP inventory")
    ws = wb.add_sheet("Rules", columns=["Order", "Name"])
    ws.append([1, "Block PCI"])
    data = wb.to_bytes()
"""
from __future__ import annotations

import io
import math
import re
import zipfile
from datetime import datetime, timezone
from typing import Any, Iterable, List, Optional, Sequence
from xml.sax.saxutils import escape as _xml_escape

import csv_safe

MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"

MAX_CELL_CHARS = 32767          # Excel's limit for one cell
TRUNCATED = " [truncated]"
MAX_SHEET_NAME = 31
MAX_ROWS = 1048576
MAX_COLS = 16384
WIDTH_MIN = 6
WIDTH_MAX = 60                  # columns wider than this wrap instead
WRAP_AT = 60                    # a cell longer than this (or multi-line) wraps
_BAD_SHEET_CHARS = re.compile(r"[\[\]:*?/\\]")
# Characters XML 1.0 cannot carry (C0 controls except TAB/LF/CR, lone
# surrogates, U+FFFE / U+FFFF).
_BAD_XML = re.compile("[^\u0009\u000A\u000D -퟿-�\U00010000-\U0010FFFF]")

# Style indexes into cellXfs (see _STYLES).
S_DEFAULT, S_HEADER, S_WRAP, S_BOLD, S_TOP = 0, 1, 2, 3, 4

_NS_MAIN = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_NS_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_REL_DOC = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"
_REL_SHEET = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet"
_REL_STYLES = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles"
_REL_CORE = "http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties"
_REL_APP = "http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties"


def clean_text(value: Any) -> str:
    """Text XML can carry: characters it cannot are removed."""
    return _BAD_XML.sub("", str(value))


def _esc(value: Any) -> str:
    return _xml_escape(clean_text(value), {'"': "&quot;"})


def col_letter(index: int) -> str:
    """0 -> A, 25 -> Z, 26 -> AA."""
    if index < 0:
        raise ValueError("column index must be >= 0")
    out = ""
    n = index + 1
    while n:
        n, rem = divmod(n - 1, 26)
        out = chr(65 + rem) + out
    return out


def cell_ref(row: int, col: int) -> str:
    """Zero-based (row, col) -> 'A1'."""
    return f"{col_letter(col)}{row + 1}"


def sanitize_sheet_name(name: Any, taken: Iterable[str] = (), fallback: str = "Sheet") -> str:
    """A name Excel accepts: at most 31 characters, none of [ ] : * ? / \\,
    not starting or ending with an apostrophe, not 'History', and unique
    (case-insensitive) among `taken`."""
    s = clean_text(name if name is not None else "")
    s = _BAD_SHEET_CHARS.sub(" ", s)
    s = re.sub(r"\s+", " ", s).strip().strip("'").strip()
    if not s:
        s = fallback
    if s.lower() == "history":   # reserved by Excel
        s = "History data"
    s = s[:MAX_SHEET_NAME].rstrip().rstrip("'") or fallback
    used = {t.lower() for t in taken}
    if s.lower() not in used:
        return s
    n = 2
    while True:
        tail = f" ({n})"
        cand = s[: MAX_SHEET_NAME - len(tail)].rstrip() + tail
        if cand.lower() not in used:
            return cand
        n += 1


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool) and not (isinstance(v, float) and not math.isfinite(v))


def _num_text(v: Any) -> str:
    if isinstance(v, int):
        return str(v)
    r = repr(float(v))
    return r[:-2] if r.endswith(".0") else r


def cell_text(value: Any) -> Optional[str]:
    """The text a non-number cell shows (None: an empty cell)."""
    if value is None:
        return None
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, float) and not math.isfinite(value):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, (list, tuple, set, frozenset)):
        return "\n".join(str(x) for x in value if x is not None and str(x) != "")
    s = clean_text(value).replace("\r\n", "\n").replace("\r", "\n")
    if len(s) > MAX_CELL_CHARS:
        s = s[: MAX_CELL_CHARS - len(TRUNCATED)] + TRUNCATED
    # Never a formula; and text that looks like one keeps csv_safe's quote.
    return csv_safe.safe_cell(s) if s else s


def _display_len(value: Any) -> int:
    if _is_number(value):
        return len(_num_text(value))
    t = cell_text(value)
    if not t:
        return 0
    return max(len(line) for line in t.split("\n"))


class Sheet:
    """One worksheet. With `columns`, the first row is a bold header that
    stays frozen, and an AutoFilter covers the table."""

    def __init__(self, name: str, columns: Optional[Sequence[Any]] = None, *, freeze: Optional[bool] = None,
                 autofilter: Optional[bool] = None, widths: Optional[Sequence[Optional[float]]] = None):
        self.name = name
        self.rows: List[List[Any]] = []
        self.styles: List[int] = []     # per row: S_DEFAULT, S_HEADER or S_BOLD
        self.columns = [cell_text(c) or "" for c in columns] if columns else None
        self.freeze = bool(columns) if freeze is None else bool(freeze)
        self.autofilter = bool(columns) if autofilter is None else bool(autofilter)
        self.widths = list(widths) if widths else None
        if self.columns:
            self.rows.append(list(self.columns))
            self.styles.append(S_HEADER)

    def append(self, values: Sequence[Any], bold: bool = False) -> None:
        if len(self.rows) >= MAX_ROWS:
            raise ValueError("too many rows for one sheet")
        vals = list(values)[:MAX_COLS]
        self.rows.append(vals)
        self.styles.append(S_BOLD if bold else S_DEFAULT)

    def extend(self, rows: Iterable[Sequence[Any]]) -> None:
        for r in rows:
            self.append(r)

    @property
    def ncols(self) -> int:
        return max((len(r) for r in self.rows), default=0)

    def col_widths(self) -> List[float]:
        n = self.ncols
        out = []
        for c in range(n):
            if self.widths and c < len(self.widths) and self.widths[c]:
                out.append(float(self.widths[c]))
                continue
            longest = max((_display_len(r[c]) for r in self.rows if c < len(r)), default=0)
            # A header is bold and carries the filter button: a little extra room.
            if self.columns and c < len(self.columns):
                longest = max(longest, len(self.columns[c]) + 3)
            out.append(float(min(WIDTH_MAX, max(WIDTH_MIN, longest + 2))))
        return out

    def table_ref(self) -> Optional[str]:
        if not self.columns or not self.rows:
            return None
        return f"A1:{col_letter(max(1, len(self.columns)) - 1)}{len(self.rows)}"

    # -- XML --------------------------------------------------------------
    def _cell_xml(self, r: int, c: int, value: Any, row_style: int) -> str:
        ref = cell_ref(r, c)
        if _is_number(value):
            style = row_style if row_style in (S_HEADER, S_BOLD) else S_TOP
            return f'<c r="{ref}" s="{style}"><v>{_num_text(value)}</v></c>'
        text = cell_text(value)
        if text is None or text == "":
            return ""
        if row_style == S_HEADER:
            style = S_HEADER
        elif row_style == S_BOLD:
            style = S_BOLD
        elif "\n" in text or len(text) > WRAP_AT:
            style = S_WRAP
        else:
            style = S_TOP
        return (f'<c r="{ref}" s="{style}" t="inlineStr"><is><t xml:space="preserve">{_esc(text)}</t></is></c>')

    def to_xml(self, selected: bool = False) -> str:
        n = self.ncols
        parts = [f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n<worksheet xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">']
        last = f"{col_letter(max(n, 1) - 1)}{max(len(self.rows), 1)}"
        parts.append(f'<dimension ref="A1:{last}"/>')
        sel = ' tabSelected="1"' if selected else ""
        if self.freeze and self.rows:
            parts.append(f'<sheetViews><sheetView workbookViewId="0"{sel}>'
                         '<pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/>'
                         '<selection pane="bottomLeft" activeCell="A2" sqref="A2"/></sheetView></sheetViews>')
        else:
            parts.append(f'<sheetViews><sheetView workbookViewId="0"{sel}/></sheetViews>')
        parts.append('<sheetFormatPr defaultRowHeight="15"/>')
        if n:
            parts.append("<cols>" + "".join(
                f'<col min="{i + 1}" max="{i + 1}" width="{w:.2f}" customWidth="1"/>' for i, w in enumerate(self.col_widths())) + "</cols>")
        parts.append("<sheetData>")
        for r, (row, st) in enumerate(zip(self.rows, self.styles)):
            cells = "".join(self._cell_xml(r, c, v, st) for c, v in enumerate(row))
            parts.append(f'<row r="{r + 1}">{cells}</row>' if cells else f'<row r="{r + 1}"/>')
        parts.append("</sheetData>")
        ref = self.table_ref() if self.autofilter else None
        if ref:
            parts.append(f'<autoFilter ref="{ref}"/>')
        parts.append('<pageMargins left="0.7" right="0.7" top="0.75" bottom="0.75" header="0.3" footer="0.3"/>')
        parts.append("</worksheet>")
        return "".join(parts)


_STYLES = f"""<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<styleSheet xmlns="{_NS_MAIN}">
<fonts count="2"><font><sz val="11"/><name val="Calibri"/><family val="2"/></font><font><b/><sz val="11"/><name val="Calibri"/><family val="2"/></font></fonts>
<fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FFE7E9EE"/><bgColor indexed="64"/></patternFill></fill></fills>
<borders count="2"><border><left/><right/><top/><bottom/><diagonal/></border><border><left/><right/><top/><bottom style="thin"><color rgb="FF9AA0A6"/></bottom><diagonal/></border></borders>
<cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs>
<cellXfs count="5">
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/>
<xf numFmtId="0" fontId="1" fillId="2" borderId="1" xfId="0" applyFont="1" applyFill="1" applyBorder="1" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top" wrapText="1"/></xf>
<xf numFmtId="0" fontId="1" fillId="0" borderId="0" xfId="0" applyFont="1" applyAlignment="1"><alignment vertical="top"/></xf>
<xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0" applyAlignment="1"><alignment vertical="top"/></xf>
</cellXfs>
<cellStyles count="1"><cellStyle name="Normal" xfId="0" builtinId="0"/></cellStyles>
</styleSheet>"""


def _quote_sheet(name: str) -> str:
    return "'" + name.replace("'", "''") + "'"


class Workbook:
    """A workbook of one or more sheets, serialised by to_bytes()."""

    def __init__(self, title: str = "", subject: str = "", creator: str = "Zscaler Made Easy"):
        self.title = title
        self.subject = subject
        self.creator = creator
        self.sheets: List[Sheet] = []
        self.created = datetime.now(timezone.utc)

    def add_sheet(self, name: str, columns: Optional[Sequence[Any]] = None, rows: Optional[Iterable[Sequence[Any]]] = None,
                  **kw: Any) -> Sheet:
        safe = sanitize_sheet_name(name, [s.name for s in self.sheets], fallback=f"Sheet{len(self.sheets) + 1}")
        ws = Sheet(safe, columns, **kw)
        if rows is not None:
            ws.extend(rows)
        self.sheets.append(ws)
        return ws

    # -- parts ------------------------------------------------------------
    def _content_types(self) -> str:
        sheets = "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" '
                         'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                         for i in range(len(self.sheets)))
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                + sheets +
                '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
                '<Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>'
                '<Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/>'
                '</Types>')

    def _root_rels(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<Relationships xmlns="{_NS_PKG_REL}">'
                f'<Relationship Id="rId1" Type="{_REL_DOC}" Target="xl/workbook.xml"/>'
                f'<Relationship Id="rId2" Type="{_REL_CORE}" Target="docProps/core.xml"/>'
                f'<Relationship Id="rId3" Type="{_REL_APP}" Target="docProps/app.xml"/>'
                '</Relationships>')

    def _workbook(self) -> str:
        sheets = "".join(f'<sheet name="{_esc(s.name)}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, s in enumerate(self.sheets))
        names = "".join(
            f'<definedName name="_xlnm._FilterDatabase" localSheetId="{i}" hidden="1">'
            f'{_esc(_quote_sheet(s.name))}!{_abs_ref(s.table_ref())}</definedName>'
            for i, s in enumerate(self.sheets) if s.autofilter and s.table_ref())
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<workbook xmlns="{_NS_MAIN}" xmlns:r="{_NS_REL}">'
                '<bookViews><workbookView activeTab="0"/></bookViews>'
                f'<sheets>{sheets}</sheets>'
                + (f"<definedNames>{names}</definedNames>" if names else "") +
                '</workbook>')

    def _workbook_rels(self) -> str:
        rels = "".join(f'<Relationship Id="rId{i + 1}" Type="{_REL_SHEET}" Target="worksheets/sheet{i + 1}.xml"/>'
                       for i in range(len(self.sheets)))
        rels += f'<Relationship Id="rId{len(self.sheets) + 1}" Type="{_REL_STYLES}" Target="styles.xml"/>'
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                f'<Relationships xmlns="{_NS_PKG_REL}">{rels}</Relationships>')

    def _core(self) -> str:
        when = self.created.strftime("%Y-%m-%dT%H:%M:%SZ")
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" '
                'xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                f'<dc:title>{_esc(self.title)}</dc:title>'
                + (f'<dc:subject>{_esc(self.subject)}</dc:subject>' if self.subject else "") +
                f'<dc:creator>{_esc(self.creator)}</dc:creator>'
                f'<dcterms:created xsi:type="dcterms:W3CDTF">{when}</dcterms:created>'
                f'<dcterms:modified xsi:type="dcterms:W3CDTF">{when}</dcterms:modified>'
                '</cp:coreProperties>')

    def _app(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
                '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
                'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
                f'<Application>{_esc(self.creator)}</Application></Properties>')

    def to_bytes(self) -> bytes:
        if not self.sheets:
            self.add_sheet("Sheet1")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            z.writestr("[Content_Types].xml", self._content_types())
            z.writestr("_rels/.rels", self._root_rels())
            z.writestr("docProps/core.xml", self._core())
            z.writestr("docProps/app.xml", self._app())
            z.writestr("xl/workbook.xml", self._workbook())
            z.writestr("xl/_rels/workbook.xml.rels", self._workbook_rels())
            z.writestr("xl/styles.xml", _STYLES)
            for i, s in enumerate(self.sheets):
                z.writestr(f"xl/worksheets/sheet{i + 1}.xml", s.to_xml(selected=(i == 0)))
        return buf.getvalue()


def _abs_ref(ref: Optional[str]) -> str:
    """'A1:H20' -> '$A$1:$H$20'."""
    if not ref:
        return ""
    out = []
    for part in ref.split(":"):
        m = re.fullmatch(r"([A-Z]+)(\d+)", part)
        out.append(f"${m.group(1)}${m.group(2)}" if m else part)
    return ":".join(out)
