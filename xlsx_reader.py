"""Read the cells of an uploaded Excel workbook (.xlsx), as untrusted input.

The app writes workbooks with xlsx_writer; this is the matching reader for
the few places that take one in, such as the Client Connector portal's
device export for a bulk device removal. It reads the first worksheet's
cell values as text and nothing else: no formula is evaluated (a formula
cell gives its cached value, or nothing), no macro, external link, image or
style is opened.

An .xlsx is a ZIP of XML parts, so it is read like any untrusted archive:
  - at most MAX_PARTS members, whose declared sizes add up to at most
    MAX_TOTAL_BYTES, none expanding more than MAX_RATIO times its
    compressed size (past MAX_RATIO_FLOOR bytes); only the parts it needs
    are opened
    (the workbook, its relationships, the shared strings and one sheet),
    each through safe_files.zip_member (stored or deflate only, never
    encrypted, at most its own size cap, refused when it expands past it:
    the zip-bomb guard);
  - the XML is parsed with defusedxml (already a pinned dependency for the
    PAN-OS import): no DTD, no entity, no external reference (XXE and
    billion-laughs refused);
  - at most MAX_ROWS rows and MAX_COLS columns are returned, each value at
    most MAX_CELL characters, control characters removed.
XlsxRefused (a ValueError) says in plain words why a file is refused.

Format source: ECMA-376 Part 1 (SpreadsheetML): xl/workbook.xml <sheets>,
xl/_rels/workbook.xml.rels, xl/sharedStrings.xml <si>, xl/worksheets/
sheetN.xml <sheetData><row><c r t><v>|<is>.
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import List, Optional

import safe_files

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PARTS = 2000
MAX_PART_BYTES = 32 * 1024 * 1024
MAX_SMALL_PART = 2 * 1024 * 1024
MAX_ROWS = 20_000
MAX_COLS = 64
MAX_CELL = 512
MAX_SHARED = 500_000
MAX_TOTAL_BYTES = 96 * 1024 * 1024   # every member's declared size, added up
MAX_RATIO = 200                      # uncompressed / compressed, per member
MAX_RATIO_FLOOR = 1024 * 1024        # a small part may compress better than that

_NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
       "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
       "rel": "http://schemas.openxmlformats.org/package/2006/relationships"}
_CTRL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_REF = re.compile(r"\A([A-Z]{1,3})(\d{1,7})\Z")


class XlsxRefused(ValueError):
    """A workbook this reader will not open; the message says why."""


def _xml(data: bytes):
    try:
        from defusedxml import ElementTree as DET
        from defusedxml.common import DefusedXmlException
    except ImportError:  # pragma: no cover - defusedxml is in requirements.txt
        raise XlsxRefused("the hardened XML parser (defusedxml) is not installed, so Excel files cannot be read") from None
    try:
        return DET.fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except DefusedXmlException:
        raise XlsxRefused("the workbook holds XML features this app never reads (a DTD or entities)") from None
    except Exception as e:  # noqa: BLE001 - ParseError and the like: a damaged part
        raise XlsxRefused(f"the workbook's XML is damaged ({type(e).__name__})") from None


def _too_dense(size: int, compressed: int) -> bool:
    return size > MAX_RATIO_FLOOR and size > MAX_RATIO * max(compressed, 1)


def _part(z: zipfile.ZipFile, name: str, limit: int) -> Optional[bytes]:
    try:
        info = z.getinfo(name)
    except KeyError:
        return None
    if _too_dense(info.file_size, info.compress_size):
        raise XlsxRefused(f"{name}: expands more than {MAX_RATIO} times (a zip bomb)")
    try:
        data = safe_files.zip_member(z, info, limit)
    except safe_files.ArchiveRefused as e:
        raise XlsxRefused(str(e)) from None
    if _too_dense(len(data), info.compress_size):   # a header that lies about its size
        raise XlsxRefused(f"{name}: expands more than {MAX_RATIO} times (a zip bomb)")
    return data


def _text(v: Optional[str]) -> str:
    return _CTRL.sub("", v or "")[:MAX_CELL]


def _col(letters: str) -> int:
    n = 0
    for ch in letters:
        n = n * 26 + (ord(ch) - 64)
    return n - 1


def _first_sheet(z: zipfile.ZipFile) -> str:
    wb = _part(z, "xl/workbook.xml", MAX_SMALL_PART)
    rels = _part(z, "xl/_rels/workbook.xml.rels", MAX_SMALL_PART)
    if wb is not None and rels is not None:
        sheet = _xml(wb).find("m:sheets/m:sheet", _NS)
        rid = sheet.get(f"{{{_NS['r']}}}id") if sheet is not None else None
        for rel in _xml(rels).findall("rel:Relationship", _NS):
            if rel.get("Id") == rid:
                target = str(rel.get("Target") or "")
                target = target.lstrip("/")
                if not target.startswith("xl/"):
                    target = "xl/" + target
                # A target is a part inside this package, never a path elsewhere.
                if ".." in target.split("/") or not re.fullmatch(r"xl/[A-Za-z0-9_./-]{1,200}\.xml", target):
                    raise XlsxRefused("the workbook names its sheet with a path this app does not follow")
                return target
    return "xl/worksheets/sheet1.xml"


def read_rows(data: bytes) -> List[List[str]]:
    """The first worksheet's rows as lists of text cells (empty cells as
    ""), at most MAX_ROWS rows of MAX_COLS cells. XlsxRefused otherwise."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise XlsxRefused("the file is empty")
    if len(data) > MAX_FILE_BYTES:
        raise XlsxRefused(f"the workbook is larger than {MAX_FILE_BYTES // (1024 * 1024)} MB")
    if data[:4] != b"PK\x03\x04":
        raise XlsxRefused("this is not an Excel .xlsx workbook (save it as .xlsx, or as CSV)")
    try:
        z = zipfile.ZipFile(io.BytesIO(bytes(data)))
    except (zipfile.BadZipFile, NotImplementedError, ValueError, OSError, EOFError):
        raise XlsxRefused("the workbook is damaged (not a valid ZIP package)") from None
    with z:
        infos = z.infolist()
        if len(infos) > MAX_PARTS:
            raise XlsxRefused(f"the workbook has more than {MAX_PARTS} parts")
        if sum(max(i.file_size, 0) for i in infos) > MAX_TOTAL_BYTES:
            raise XlsxRefused(f"the workbook expands to more than {MAX_TOTAL_BYTES // (1024 * 1024)} MB")
        shared: List[str] = []
        sst = _part(z, "xl/sharedStrings.xml", MAX_PART_BYTES)
        if sst is not None:
            for si in _xml(sst).findall("m:si", _NS):
                if len(shared) >= MAX_SHARED:
                    break
                shared.append(_text("".join(t.text or "" for t in si.iter(f"{{{_NS['m']}}}t"))))
        name = _first_sheet(z)
        sheet = _part(z, name, MAX_PART_BYTES)
        if sheet is None:
            raise XlsxRefused("the workbook has no worksheet")
        root = _xml(sheet)
    rows: List[List[str]] = []
    for row in root.iterfind("m:sheetData/m:row", _NS):
        if len(rows) >= MAX_ROWS:
            break
        cells: List[str] = []
        for i, c in enumerate(row.findall("m:c", _NS)):
            m = _REF.match(str(c.get("r") or ""))
            idx = _col(m.group(1)) if m else len(cells)
            if idx >= MAX_COLS:
                continue
            t = c.get("t") or "n"
            if t == "inlineStr":
                val = "".join(x.text or "" for x in c.iter(f"{{{_NS['m']}}}t"))
            else:
                v = c.find("m:v", _NS)
                raw = v.text if v is not None else ""
                if t == "s":
                    try:
                        val = shared[int(raw or "")]
                    except (ValueError, IndexError):
                        val = ""
                elif t == "b":
                    val = "TRUE" if (raw or "").strip() == "1" else "FALSE"
                else:   # n, str (a formula's cached text), e (an error): the stored text
                    val = raw or ""
            while len(cells) < idx:
                cells.append("")
            if len(cells) == idx:
                cells.append(_text(val))
        rows.append(cells)
    return rows
