"""A small PDF 1.4 writer for the app's printable exports (a deployment
plan for change approval, ...), written by hand so no PDF library joins
the locked dependencies (requirements.lock, SBOM, third-party notices).

What it does, and nothing more:

* the standard Helvetica and Helvetica-Bold fonts (every PDF reader has
  them; nothing is embedded), WinAnsi text: a character outside WinAnsi
  (cp1252) is shown as '?', never dropped silently;
* A4 or Letter pages with margins; headings, paragraphs with word wrap,
  bullet lists, label/value lists, simple tables (bold header row,
  hairline rules) that break across pages and repeat their header, and
  sign-off lines;
* a footer line and "Page n of N" on every page; document information
  (Title, Producer "Zscaler Made Easy"); a correct cross-reference table.

Usage::

    doc = PdfDocument(title="Deployment plan", footer="Zscaler Made Easy · acme")
    doc.heading("Deployment plan")
    doc.paragraph("Nothing has been written to the tenant.")
    doc.table(["Kind", "Name"], [["Rule", "Block PCI"]])
    data = doc.to_bytes()
"""
from __future__ import annotations

import hashlib
import unicodedata
from datetime import datetime, timezone
from typing import Any, List, Optional, Sequence, Tuple

MEDIA_TYPE = "application/pdf"
PRODUCER = "Zscaler Made Easy"

PAGE_SIZES = {"A4": (595.28, 841.89), "LETTER": (612.0, 792.0)}

# Glyph widths (1/1000 em) of the standard 14 fonts for codes 32..126,
# from Adobe's Helvetica and Helvetica-Bold AFM files.
_HELV = [278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
         556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
         1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
         667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
         333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
         556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584]
_HELV_BOLD = [278, 333, 474, 556, 556, 889, 722, 238, 333, 333, 389, 584, 278, 333, 278, 278,
              556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 333, 333, 584, 584, 584, 611,
              975, 722, 722, 722, 722, 667, 611, 778, 722, 278, 556, 722, 611, 833, 722, 778,
              667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 333, 278, 333, 584, 556,
              333, 556, 611, 556, 611, 556, 333, 611, 611, 278, 278, 556, 278, 889, 611, 611,
              611, 611, 389, 556, 333, 611, 556, 778, 556, 556, 500, 389, 280, 389, 584]
# A few WinAnsi characters above 126 (regular, bold); others take the
# width of their base letter (é as e) or, failing that, 556.
_EXTRA = {"–": (556, 556), "—": (1000, 1000), "‘": (222, 278), "’": (222, 278),
          "“": (333, 500), "”": (333, 500), "•": (350, 350), "…": (1000, 1000),
          "€": (556, 556), "©": (737, 737), "®": (737, 737), "°": (400, 400),
          "×": (584, 584), "·": (278, 278), " ": (278, 278), "™": (1000, 1000),
          "§": (556, 556), "¶": (537, 556)}

FONT_REGULAR, FONT_BOLD = "F1", "F2"


# A few symbols the app's own texts use, spelled in WinAnsi rather than '?'.
_SPELLED = {"\u2192": "->", "\u2190": "<-", "\u2194": "<->", "\u2265": ">=", "\u2264": "<=", "\u2260": "!=",
            "\u2212": "-", "\u2011": "-", "\u2009": " ", "\u202f": " "}


def winansi(text: Any) -> str:
    """`text` as the characters WinAnsi (cp1252) can show: tabs become
    spaces, other control characters are dropped, a few symbols are
    spelled out (-> for an arrow), anything else outside WinAnsi becomes
    '?' so the loss is visible."""
    out = []
    for ch in str(text if text is not None else ""):
        if ch in _SPELLED:
            out.append(_SPELLED[ch])
            continue
        if ch == "\t":
            out.append(" ")
            continue
        if ch in "\r\n":
            out.append(ch)
            continue
        if unicodedata.category(ch) in ("Cc", "Cs"):
            continue
        try:
            ch.encode("cp1252")
            out.append(ch)
        except UnicodeEncodeError:
            out.append("?")
    return "".join(out)


def _char_width(ch: str, bold: bool) -> int:
    o = ord(ch)
    if 32 <= o <= 126:
        return (_HELV_BOLD if bold else _HELV)[o - 32]
    if ch in _EXTRA:
        return _EXTRA[ch][1 if bold else 0]
    base = unicodedata.normalize("NFKD", ch)[:1]
    if base and 32 <= ord(base) <= 126:
        return (_HELV_BOLD if bold else _HELV)[ord(base) - 32]
    return 556


def text_width(text: str, size: float, bold: bool = False) -> float:
    """Width in points of `text` (already WinAnsi) at `size`."""
    return sum(_char_width(c, bold) for c in text) * size / 1000.0


def _break_word(word: str, size: float, bold: bool, width: float) -> List[str]:
    parts, cur = [], ""
    for ch in word:
        if cur and text_width(cur + ch, size, bold) > width:
            parts.append(cur)
            cur = ch
        else:
            cur += ch
    if cur:
        parts.append(cur)
    return parts or [""]


def wrap(text: Any, size: float, width: float, bold: bool = False) -> List[str]:
    """Lines of `text` that fit `width` points; explicit newlines kept, a
    word longer than the width broken across lines."""
    lines: List[str] = []
    for para in winansi(text).replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        words = para.split(" ")
        cur = ""
        for w in words:
            if w == "" and cur == "":
                continue
            cand = f"{cur} {w}" if cur else w
            if text_width(cand, size, bold) <= width:
                cur = cand
                continue
            if cur:
                lines.append(cur)
            if text_width(w, size, bold) <= width:
                cur = w
            else:
                pieces = _break_word(w, size, bold, width)
                lines.extend(pieces[:-1])
                cur = pieces[-1]
        lines.append(cur)
    return lines or [""]


def pdf_string(text: str) -> str:
    """A PDF literal string of WinAnsi text, ASCII-only (octal escapes)."""
    out = ["("]
    for b in winansi(text).encode("cp1252", errors="replace"):
        if b in (0x28, 0x29, 0x5C):
            out.append("\\" + chr(b))
        elif 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append("\\%03o" % b)
    out.append(")")
    return "".join(out)


def _info_string(text: Any) -> str:
    """A text string for the document information: UTF-16BE with BOM, as hex."""
    return "<FEFF" + str(text or "").encode("utf-16-be", errors="replace").hex().upper() + ">"


def _num(v: float) -> str:
    s = f"{v:.2f}".rstrip("0").rstrip(".")
    return s if s not in ("", "-0") else "0"


class PdfDocument:
    """A flowing document: content is added top to bottom and pages break
    by themselves. to_bytes() returns the finished PDF."""

    def __init__(self, title: str = "", *, page_size: str = "A4", margins: Tuple[float, float, float, float] = (54, 54, 54, 64),
                 footer: str = "", author: str = "", subject: str = ""):
        size = PAGE_SIZES.get(str(page_size).upper())
        if size is None:
            raise ValueError(f"page_size must be one of {', '.join(PAGE_SIZES)}")
        self.width, self.height = size
        self.left, self.top, self.right, self.bottom = (float(m) for m in margins)
        self.title, self.footer, self.author, self.subject = title, footer, author, subject
        self.pages: List[List[str]] = []
        self.y = 0.0
        self.created = datetime.now(timezone.utc)
        self._new_page()

    # -- geometry ------------------------------------------------------------
    @property
    def content_width(self) -> float:
        return self.width - self.left - self.right

    def _new_page(self) -> None:
        self.pages.append([])
        self.y = self.height - self.top

    def _room(self) -> float:
        return self.y - self.bottom

    def _ensure(self, h: float) -> None:
        if h > self._room() and self.y < self.height - self.top - 0.5:
            self._new_page()

    # -- drawing primitives ---------------------------------------------------
    def _ops(self) -> List[str]:
        return self.pages[-1]

    def _text(self, x: float, baseline: float, text: str, size: float, bold: bool = False, grey: float = 0.0) -> None:
        if not text:
            return
        font = FONT_BOLD if bold else FONT_REGULAR
        self._ops().append(f"BT {_num(grey)} g /{font} {_num(size)} Tf 1 0 0 1 {_num(x)} {_num(baseline)} Tm {pdf_string(text)} Tj ET")

    def _line(self, x1: float, y1: float, x2: float, y2: float, width: float = 0.5, grey: float = 0.6) -> None:
        self._ops().append(f"{_num(grey)} G {_num(width)} w {_num(x1)} {_num(y1)} m {_num(x2)} {_num(y2)} l S")

    # -- content ---------------------------------------------------------------
    def spacer(self, h: float = 6) -> None:
        self.y -= h

    def page_break(self) -> None:
        self._new_page()

    def heading(self, text: str, level: int = 1) -> None:
        size = {1: 18.0, 2: 13.0}.get(level, 11.0)
        before = {1: 4.0, 2: 12.0}.get(level, 8.0)
        lead = size * 1.25
        lines = wrap(text, size, self.content_width, bold=True)
        # A heading never sits alone at the bottom of a page.
        self._ensure(before + lead * len(lines) + 30)
        if self.y < self.height - self.top - 0.5:
            self.y -= before
        for ln in lines:
            self._text(self.left, self.y - size, ln, size, bold=True)
            self.y -= lead
        self.y -= 3

    def paragraph(self, text: str, size: float = 10, bold: bool = False, grey: float = 0.0, indent: float = 0.0,
                  space_after: float = 6) -> None:
        lead = size * 1.3
        for ln in wrap(text, size, self.content_width - indent, bold=bold):
            self._ensure(lead)
            self._text(self.left + indent, self.y - size, ln, size, bold=bold, grey=grey)
            self.y -= lead
        self.y -= space_after

    def bullets(self, items: Sequence[str], size: float = 10) -> None:
        lead = size * 1.3
        for item in items:
            lines = wrap(item, size, self.content_width - 14)
            for i, ln in enumerate(lines):
                self._ensure(lead)
                if i == 0:
                    self._text(self.left + 3, self.y - size, "•", size)
                self._text(self.left + 14, self.y - size, ln, size)
                self.y -= lead
            self.y -= 2
        self.y -= 4

    def key_values(self, pairs: Sequence[Tuple[str, Any]], size: float = 10, label_width: Optional[float] = None) -> None:
        """Label (bold) and value per line, values wrapped beside their label."""
        lead = size * 1.3
        lw = label_width or min(150.0, max((text_width(winansi(k), size, True) for k, _ in pairs), default=60.0) + 12)
        for k, v in pairs:
            vlines = wrap("" if v is None else v, size, self.content_width - lw)
            klines = wrap(k, size, lw - 8, bold=True)
            for i in range(max(len(vlines), len(klines))):
                self._ensure(lead)
                if i < len(klines):
                    self._text(self.left, self.y - size, klines[i], size, bold=True)
                if i < len(vlines):
                    self._text(self.left + lw, self.y - size, vlines[i], size)
                self.y -= lead
            self.y -= 1.5
        self.y -= 5

    def rule(self) -> None:
        self._ensure(8)
        self.y -= 4
        self._line(self.left, self.y, self.width - self.right, self.y)
        self.y -= 4

    def signature_lines(self, labels: Sequence[str], size: float = 10) -> None:
        """'Requested by ________' lines to sign by hand."""
        block = 34.0
        self._ensure(block * len(labels))
        lw = max(text_width(winansi(l), size, True) for l in labels) + 14 if labels else 0
        for label in labels:
            self.y -= 22
            self._text(self.left, self.y, winansi(label), size, bold=True)
            self._line(self.left + lw, self.y - 2, self.width - self.right, self.y - 2, width=0.5, grey=0.0)
            self.y -= 12

    def _col_widths(self, columns: Sequence[str], rows: Sequence[Sequence[Any]], size: float,
                    widths: Optional[Sequence[float]]) -> List[float]:
        n = len(columns)
        avail = self.content_width
        if widths:
            w = [float(x) for x in list(widths)[:n]] + [1.0] * max(0, n - len(widths))
        else:
            w = []
            for c in range(n):
                nat = text_width(winansi(columns[c]), size, True)
                for r in rows[:400]:
                    if c < len(r) and r[c] is not None:
                        longest = max((text_width(p, size) for p in winansi(r[c]).split("\n")), default=0.0)
                        nat = max(nat, longest)
                w.append(min(max(nat + 8, 36.0), avail * 0.45))
        total = sum(w) or 1.0
        return [x * avail / total for x in w]

    def table(self, columns: Sequence[str], rows: Sequence[Sequence[Any]], *, widths: Optional[Sequence[float]] = None,
              size: float = 8.0) -> None:
        """A table with a bold header row and hairline rules. Rows break
        across pages (a tall row is split line by line) and the header is
        repeated at the top of every page the table continues on."""
        columns = [winansi(c) for c in columns]
        cw = self._col_widths(columns, rows, size, widths)
        pad, lead = 3.0, size * 1.25
        x0, x1 = self.left, self.left + sum(cw)

        def cell_lines(values: Sequence[Any], bold: bool = False) -> List[List[str]]:
            return [wrap("" if (i >= len(values) or values[i] is None) else values[i], size, cw[i] - 2 * pad, bold=bold)
                    for i in range(len(cw))]

        head = cell_lines(columns, bold=True)
        head_h = max(len(c) for c in head) * lead + 2 * pad

        def draw_lines(lines: List[List[str]], start: int, count: int, bold: bool) -> None:
            x = x0
            for i, col in enumerate(lines):
                for j, ln in enumerate(col[start:start + count]):
                    self._text(x + pad, self.y - pad - size - j * lead + size * 0.18, ln, size, bold=bold)
                x += cw[i]

        def draw_header() -> None:
            n = max(len(c) for c in head)
            self._line(x0, self.y, x1, self.y, width=0.75, grey=0.2)
            draw_lines(head, 0, n, True)
            self.y -= n * lead + 2 * pad
            self._line(x0, self.y, x1, self.y, width=0.75, grey=0.2)

        self._ensure(head_h + lead + 2 * pad)
        draw_header()
        self._at_top_of_table = True
        full_page = (self.height - self.top - self.bottom) - head_h
        for values in rows:
            lines = cell_lines(values)
            n = max(len(c) for c in lines)
            h = n * lead + 2 * pad
            if h > self._room() and h <= full_page:
                self._new_page()
                draw_header()
                self._at_top_of_table = True
            done = 0
            while done < n:
                fit = int((self._room() - 2 * pad) // lead)
                if fit < 1:
                    if self._at_top_of_table:
                        fit = 1   # a page too small for one line: draw it anyway rather than loop
                    else:
                        self._new_page()
                        draw_header()
                        self._at_top_of_table = True
                        continue
                self._at_top_of_table = False
                take = min(fit, n - done)
                draw_lines(lines, done, take, False)
                self.y -= take * lead + 2 * pad
                done += take
                self._line(x0, self.y, x1, self.y, width=0.25, grey=0.7)
                if done < n:
                    self._new_page()
                    draw_header()
                    self._at_top_of_table = True
        self.y -= 10

    # -- output ------------------------------------------------------------
    def _footer_ops(self, page_no: int, total: int) -> List[str]:
        fy = self.bottom - 22
        saved = self.pages
        ops: List[str] = []
        self.pages = [ops]
        self._line(self.left, fy + 11, self.width - self.right, fy + 11, width=0.5, grey=0.6)
        label = f"Page {page_no} of {total}"
        lw = text_width(label, 8)
        foot = winansi(self.footer or self.title or "")
        room = self.content_width - lw - 16
        while foot and text_width(foot, 8) > room:
            foot = foot[:-2] + "…" if len(foot) > 2 else ""
        self._text(self.left, fy, foot, 8, grey=0.35)
        self._text(self.width - self.right - lw, fy, label, 8, grey=0.35)
        self.pages = saved
        return ops

    def to_bytes(self) -> bytes:
        total = len(self.pages)
        objects: List[bytes] = []   # object n is objects[n - 1]

        def add(body: bytes) -> int:
            objects.append(body)
            return len(objects)

        catalog = add(b"")          # 1, filled in below
        pages_id = add(b"")         # 2
        f1 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
        f2 = add(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>")
        when = self.created.strftime("D:%Y%m%d%H%M%S+00'00'")
        info_parts = [f"/Title {_info_string(self.title)}", f"/Producer {_info_string(PRODUCER)}",
                      f"/Creator {_info_string(PRODUCER)}", f"/CreationDate ({when})", f"/ModDate ({when})"]
        if self.author:
            info_parts.append(f"/Author {_info_string(self.author)}")
        if self.subject:
            info_parts.append(f"/Subject {_info_string(self.subject)}")
        info = add(("<< " + " ".join(info_parts) + " >>").encode("ascii"))
        kids = []
        for i, ops in enumerate(self.pages):
            stream = "\n".join(ops + self._footer_ops(i + 1, total)).encode("ascii")
            content = add(b"<< /Length %d >>\nstream\n" % len(stream) + stream + b"\nendstream")
            page = add((f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {_num(self.width)} {_num(self.height)}] "
                        f"/Resources << /Font << /{FONT_REGULAR} {f1} 0 R /{FONT_BOLD} {f2} 0 R >> >> "
                        f"/Contents {content} 0 R >>").encode("ascii"))
            kids.append(page)
        objects[catalog - 1] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")
        objects[pages_id - 1] = (f"<< /Type /Pages /Kids [{' '.join(f'{k} 0 R' for k in kids)}] /Count {len(kids)} >>").encode("ascii")

        out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
        offsets = []
        for n, body in enumerate(objects, start=1):
            offsets.append(len(out))
            out += b"%d 0 obj\n" % n + body + b"\nendobj\n"
        xref_at = len(out)
        out += b"xref\n0 %d\n" % (len(objects) + 1)
        out += b"0000000000 65535 f \n"
        for off in offsets:
            out += b"%010d 00000 n \n" % off
        doc_id = hashlib.sha256(bytes(out)).hexdigest()[:32].upper()
        out += (f"trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R /Info {info} 0 R /ID [<{doc_id}> <{doc_id}>] >>\n"
                f"startxref\n{xref_at}\n%%EOF\n").encode("ascii")
        return bytes(out)
