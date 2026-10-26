"""ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: no new unescaped HTML sink in the browser code.

Tenant names, descriptions, comments, uploaded file names, HAR content, log
lines and search terms reach the page through innerHTML, insertAdjacentHTML,
outerHTML, document.write and HTML template literals. tests/html_sink_scan.py
reads every script the app ships (static/*.js, the inline scripts of
static/*.html, browser_extension/*.js) and reports each value it cannot show
is escaped where it lands, including an escaped value in a context where
HTML escaping is not enough (an on* handler, a style attribute, an unquoted
attribute, the start of an href/src). The values it cannot prove safe but
that are safe by construction (server-computed numbers, enums, the page's
own constants) are listed, with the reason, in tests/xss_sink_allowlist.json.

Table-driven over every shipped script, so a new page or a new sink in an
existing one is checked without touching this file. Deny by default: a value
that is neither proven escaped nor reviewed fails the build.
"""
from __future__ import annotations

import json
import os
from collections import Counter

import pytest

import html_sink_scan as scan

HERE = os.path.dirname(os.path.abspath(__file__))
ALLOWLIST = os.path.join(HERE, "xss_sink_allowlist.json")


@pytest.fixture(scope="module")
def findings():
    by_file = {}
    for f in scan.scan_all():
        by_file.setdefault(f.file, []).append(f)
    return by_file


def _allowed():
    with open(ALLOWLIST, encoding="utf-8") as fh:
        data = json.load(fh)
    data.pop("//", None)
    return data


SOURCES = [name for name, _src in scan.sources()]


@pytest.mark.parametrize("source", SOURCES)
def test_every_value_reaching_html_is_escaped_or_reviewed(source, findings):
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-02: each script's HTML sinks only take escaped or reviewed values."""
    # Arrange
    allowed = {expr: n for expr, (n, _why) in _allowed().get(source, {}).items()}
    # Act
    seen = Counter(f.expr for f in findings.get(source, []))
    new = [f for f in findings.get(source, []) if seen[f.expr] > allowed.get(f.expr, 0)]
    # Assert
    assert not new, (
        "Unescaped value(s) reaching HTML. Escape each with the page's escaper (E(), escapeHtml(), _dzE() ...); "
        "for a URL also check its scheme, and never put data in an on* handler. Only a value that is not tenant, "
        "upload or user text by construction may go in tests/xss_sink_allowlist.json, with the reason:\n"
        + "\n".join(f"  {f.file}:{f.line}: {f.reason}: {f.expr[:200]}" for f in new))


def test_allowlist_has_no_stale_entries(findings):
    """ASVS V1.14.1 · CWE-1059: the reviewed list only names values that still exist, so it cannot hide a new one."""
    # Arrange
    allowed = _allowed()
    # Act
    stale = []
    for source, entries in allowed.items():
        seen = Counter(f.expr for f in findings.get(source, []))
        for expr, (n, _why) in entries.items():
            if seen[expr] < n:
                stale.append(f"{source} :: {expr} (listed {n}, found {seen[expr]})")
    # Assert
    assert not stale, "Remove or lower these entries in tests/xss_sink_allowlist.json:\n" + "\n".join(stale)


def test_every_allowlist_entry_says_why():
    """ASVS V1.14.1 · CWE-1059: each reviewed value carries the reason it is safe."""
    for source, entries in _allowed().items():
        for expr, (n, why) in entries.items():
            assert isinstance(n, int) and n >= 1, (source, expr)
            assert isinstance(why, str) and len(why) >= 20 and why != "REVIEW", (source, expr)


def test_every_shipped_script_is_scanned():
    """ASVS V5.3.3 · CWE-79: no script directory or page escapes the scan (boundary: pages with inline scripts)."""
    names = set(SOURCES)
    for d in ("static", "browser_extension"):
        for f in os.listdir(os.path.join(scan.ROOT, d)):
            path = os.path.join(scan.ROOT, d, f)
            if f.endswith(".js"):
                assert f"{d}/{f}" in names, f
            elif f.endswith(".html"):
                with open(path, encoding="utf-8") as fh:
                    if scan._SCRIPT_RE.search(fh.read()):
                        assert f"{d}/{f}" in names, f


# ── the scanner itself: it must catch what it is for (negative cases) and
#    accept what is safe (positive cases), or the table above proves nothing.

E_DEF = "const E = s => String(s == null ? '' : s).replace(/[&<>\"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '\"': '&quot;', \"'\": '&#39;' }[c]));\n"
NO_QUOTES = "const esc = s => String(s).replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));\n"

UNSAFE = [
    ("raw data in innerHTML", "el.innerHTML = r.name;"),
    ("raw data in a template", "el.innerHTML = `<td>${r.name}</td>`;"),
    ("raw data concatenated to markup", "el.innerHTML = '<b>' + r.name + '</b>';"),
    ("insertAdjacentHTML", "el.insertAdjacentHTML('beforeend', `<li>${x.title}</li>`);"),
    ("document.write", "w.document.write(`<title>${t.label}</title>`);"),
    ("outerHTML", "el.outerHTML = `<p>${d.note}</p>`;"),
    ("map callback without escaping", "el.innerHTML = rows.map(r => `<li>${r.comment}</li>`).join('');"),
    ("variable built from data", "const n = r.description; el.innerHTML = `<p>${n}</p>`;"),
    ("helper returning raw data", "function cell(v) { return `<td>${v}</td>`; } el.innerHTML = cell(r.name);"),
    ("escaped value in an onclick", "el.innerHTML = `<button onclick=\"go('${E(r.id)}')\">x</button>`;"),
    ("escaped value in a style attribute", "el.innerHTML = `<b style=\"color:${E(r.color)}\">x</b>`;"),
    ("escaped value in an unquoted attribute", "el.innerHTML = `<b class=${E(r.cls)}>x</b>`;"),
    ("data at the start of an href", "el.innerHTML = `<a href=\"${E(r.url)}\">x</a>`;"),
    ("quote-blind escaper in an attribute", "el.innerHTML = `<b title=\"${esc(r.name)}\">x</b>`;"),
]
SAFE = [
    ("escaped data", "el.innerHTML = `<td>${E(r.name)}</td>`;"),
    ("string constants and ternaries", "el.innerHTML = `<td>${ok ? 'Yes' : 'No'}</td>`;"),
    ("a length", "el.innerHTML = `<td>${rows.length}</td>`;"),
    ("map/join with escaping", "el.innerHTML = rows.map(r => `<li>${E(r.name)}</li>`).join('');"),
    ("helper that escapes", "function cell(v) { return `<td>${E(v)}</td>`; } el.innerHTML = cell(r.name);"),
    ("a fixed path prefix in href", "el.innerHTML = `<a href=\"/api/x/${encodeURIComponent(r.id)}\">x</a>`;"),
    ("constant table lookup", "const T = { a: 'A', b: 'B' }; el.innerHTML = `<i>${T[k]}</i>`;"),
    ("array index", "el.innerHTML = rows.map((r, i) => `<tr data-i=\"${i}\"><td>${E(r.name)}</td></tr>`).join('');"),
    ("plain text sink", "el.textContent = r.name;"),
]


@pytest.mark.parametrize("label,code", UNSAFE, ids=[u[0] for u in UNSAFE])
def test_scanner_reports_unsafe_sinks(label, code):
    """ASVS V5.3.3 · CWE-79: the scanner flags each unsafe pattern (negative cases)."""
    found = scan.FileScan("probe.js", E_DEF + NO_QUOTES + code).scan()
    assert found, label


@pytest.mark.parametrize("label,code", SAFE, ids=[s[0] for s in SAFE])
def test_scanner_accepts_safe_sinks(label, code):
    """ASVS V5.3.3 · CWE-79: the scanner does not flag escaped or constant values (positive cases)."""
    found = scan.FileScan("probe.js", E_DEF + code).scan()
    assert not found, [(f.reason, f.expr) for f in found]
