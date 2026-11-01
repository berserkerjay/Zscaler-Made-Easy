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
  - the sheet and the shared strings are streamed (an iterative parse fed
    from the ZIP member a chunk at a time, each row dropped once read), so
    memory follows the rows kept, not the part's size; the expansion caps
    are checked on the bytes as they are inflated;
  - a sheet with more than MAX_ROWS rows, more than MAX_CELLS non-empty
    cells or a value past column MAX_COLS, and more than MAX_SHARED shared
    strings, is refused, never cut short: reading stops at the first one
    over the cap and the file is refused with the reason (a list read only
    in part would plan a partial removal without saying so);
  - each value is at most MAX_CELL characters, control characters removed.
XlsxRefused (a ValueError) says in plain words why a file is refused.

Format source: ECMA-376 Part 1 (SpreadsheetML): xl/workbook.xml <sheets>,
xl/_rels/workbook.xml.rels, xl/sharedStrings.xml <si>, xl/worksheets/
sheetN.xml <sheetData><row><c r t><v>|<is>.
"""
from __future__ import annotations

import io
import re
import zipfile
import zlib
from typing import List, Optional

import safe_files

MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_PARTS = 2000
MAX_PART_BYTES = 32 * 1024 * 1024
MAX_SMALL_PART = 2 * 1024 * 1024
MAX_ROWS = 20_000
MAX_COLS = 64
MAX_CELLS = 250_000                  # non-empty cells in the sheet
MAX_CELL = 512
MAX_SHARED = 250_000
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


def _defused():
    try:
        from defusedxml import ElementTree as DET
        from defusedxml.common import DefusedXmlException
    except ImportError:  # pragma: no cover - defusedxml is in requirements.txt
        raise XlsxRefused("the hardened XML parser (defusedxml) is not installed, so Excel files cannot be read") from None
    return DET, DefusedXmlException


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


class _Stream:
    """One ZIP member read a chunk at a time for an iterative parse: the
    same checks as _part (method, encryption, declared size, expansion
    ratio), applied to the bytes as they are inflated, so a header that
    lies about its size is stopped at the cap, not after."""

    def __init__(self, z: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int):
        self.name, self.limit, self.compressed = info.filename, limit, max(info.compress_size, 1)
        if info.compress_type not in safe_files.ZIP_METHODS:
            raise XlsxRefused(f"{self.name}: compressed with a method this app does not open (only stored and deflate ZIP members are read)")
        if info.flag_bits & 0x1:
            raise XlsxRefused(f"{self.name}: password-protected; export it again without a password")
        if info.file_size > limit:
            raise XlsxRefused(f"{self.name}: larger than {limit // (1024 * 1024)} MB")
        if _too_dense(info.file_size, info.compress_size):
            raise XlsxRefused(f"{self.name}: expands more than {MAX_RATIO} times (a zip bomb)")
        self.read_bytes = 0
        try:
            self._fh = z.open(info)
        except (zipfile.BadZipFile, NotImplementedError, ValueError, OSError, RuntimeError) as e:
            raise XlsxRefused(f"{self.name}: damaged or not what it claims ({str(e)[:80]})") from None

    def read(self, n: int = -1) -> bytes:
        n = 64 * 1024 if n is None or n < 0 else min(n, 64 * 1024)
        try:
            chunk = self._fh.read(n)
        except (zipfile.BadZipFile, zlib.error, EOFError, RuntimeError, NotImplementedError, ValueError, OSError) as e:
            raise XlsxRefused(f"{self.name}: damaged or not what it claims ({str(e)[:80]})") from None
        self.read_bytes += len(chunk)
        if self.read_bytes > self.limit:
            raise XlsxRefused(f"{self.name}: expands past its limit")
        if _too_dense(self.read_bytes, self.compressed):
            raise XlsxRefused(f"{self.name}: expands more than {MAX_RATIO} times (a zip bomb)")
        return chunk

    def close(self) -> None:
        self._fh.close()


def _iterparse(z: zipfile.ZipFile, name: str, limit: int):
    """(event, element) pairs of one part, streamed; None when the part is
    absent. The caller clears what it has read."""
    try:
        info = z.getinfo(name)
    except KeyError:
        return None
    DET, Defused = _defused()
    src = _Stream(z, info, limit)

    def gen():
        try:
            yield from DET.iterparse(src, events=("start", "end"), forbid_dtd=True, forbid_entities=True, forbid_external=True)
        except (XlsxRefused, Defused) as e:
            if isinstance(e, XlsxRefused):
                raise
            raise XlsxRefused("the workbook holds XML features this app never reads (a DTD or entities)") from None
        except Exception as e:  # noqa: BLE001 - ParseError and the like: a damaged part
            raise XlsxRefused(f"the workbook's XML is damaged ({type(e).__name__})") from None
        finally:
            src.close()
    return gen()


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
    """The first worksheet's rows as lists of text cells (an empty cell
    before a filled one as ""; trailing empty cells left off). A sheet past
    MAX_ROWS rows, MAX_CELLS filled cells or MAX_COLS columns is refused
    (XlsxRefused, the reason in words), never returned in part."""
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
        shared = _shared_strings(z)
        name = _first_sheet(z)
        events = _iterparse(z, name, MAX_PART_BYTES)
        if events is None:
            raise XlsxRefused("the workbook has no worksheet")
        try:
            return _sheet_rows(events, shared)
        finally:
            events.close()   # stops the stream at once when a cap refused the file


_M = "{%s}" % _NS["m"]


def _shared_strings(z: zipfile.ZipFile) -> List[str]:
    """xl/sharedStrings.xml's <si> texts, streamed; refused past MAX_SHARED."""
    shared: List[str] = []
    events = _iterparse(z, "xl/sharedStrings.xml", MAX_PART_BYTES)
    if events is None:
        return shared
    root = None
    try:
        for ev, el in events:
            if root is None:
                root = el
            if ev == "end" and el.tag == _M + "si":
                if len(shared) >= MAX_SHARED:
                    raise XlsxRefused(f"the workbook has more than {MAX_SHARED} distinct text values; split it into smaller files")
                shared.append(_text("".join(t.text or "" for t in el.iter(_M + "t"))))
                root.clear()   # drop what was read
    finally:
        events.close()
    return shared


def _col_name(i: int) -> str:
    out = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        out = chr(65 + r) + out
    return out


def _sheet_rows(events, shared: List[str]) -> List[List[str]]:
    """The rows of one streamed sheet. Each <row> is read when it closes and
    then dropped; reading stops (and the file is refused) at the first row,
    cell or column past its cap."""
    rows: List[List[str]] = []
    n_cells = 0
    holder = None   # <sheetData>: emptied after each row
    for ev, el in events:
        if ev == "start":
            if el.tag == _M + "sheetData":
                holder = el
            continue
        if el.tag != _M + "row" or holder is None:
            continue
        if len(rows) >= MAX_ROWS:
            raise XlsxRefused(f"the first sheet has more than {MAX_ROWS} rows; split it into smaller files")
        cells: List[str] = []
        for c in el.findall("m:c", _NS):
            m = _REF.match(str(c.get("r") or ""))
            idx = _col(m.group(1)) if m else len(cells)
            t = c.get("t") or "n"
            if t == "inlineStr":
                val = "".join(x.text or "" for x in c.iter(_M + "t"))
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
            if not val.strip():
                continue
            if idx >= MAX_COLS:
                raise XlsxRefused(f"the first sheet has a value past column {_col_name(MAX_COLS - 1)} (at most {MAX_COLS} columns)")
            n_cells += 1
            if n_cells > MAX_CELLS:
                raise XlsxRefused(f"the first sheet has more than {MAX_CELLS} filled cells; split it into smaller files")
            while len(cells) < idx:
                cells.append("")
            if len(cells) == idx:
                cells.append(_text(val))
        rows.append(cells)
        holder.clear()   # the row is read: drop it (and any before it)
    return rows
