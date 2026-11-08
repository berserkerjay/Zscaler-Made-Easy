#!/usr/bin/env python3
"""Editorial audit of the app's own user-facing documents.

Checks prose and consistency across README.md, INSTALL.md, CHANGELOG.md and
docs/*.md, and prints a report with file:line for each finding. It only reads:
no file is written, nothing is fetched, no tenant is contacted.

  python tools/docs_audit.py            # the report; exit 1 when any error is found
  python tools/docs_audit.py --json     # the same findings as JSON
  python dlp_assessment_full_auto.py --audit-docs

Rules (severity in brackets; "error" fails the audit, "note" is only reported):

  broken-link        [error] a relative link whose file is missing, or whose #anchor is not a heading of the target
  heading-skip       [error] a heading that jumps down more than one level (## then ####)
  open-source-note   [error] the open-source note (open_source.NOTE_MD) is not near the top
  product-name       [error] the app's earlier names, or a misspelling of its current name
  changelog-order    [error] CHANGELOG date headings that do not descend (newest first)
  todo               [error] TODO or FIXME left in a document
  glossary           [error] a glossary term written in a variant spelling
  long-sentence      [note]  a sentence of more than LONG_SENTENCE words (report only)

Code blocks and inline code are skipped by the prose rules, so a command or a
file name never counts as a misspelling. History (CHANGELOG.md) is skipped by
the earlier-names rule: entries say what was true when they were written.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import open_source  # noqa: E402

LONG_SENTENCE = 60
NEAR_TOP_LINES = 12

# The earlier repository name and the earlier app name (tests/test_old_repo_name.py, tests/test_product_name.py).
OLD_NAMES = re.compile(r"DLP-Check|dlp-check|dlpcheck|zscaler[\s_-]*(?:platform[\s_-]*)?assessment", re.I)
# Spellings of the current name that are not it (ZscalerMadeEasy, the release file and app bundle name, is not prose).
BAD_NAME = re.compile(r"Zscaler\s+Made-Easy|Zscaler\s+made\s+easy|Zscaler\s+Made\s+easy|zscaler\s+Made\s+Easy|Zscaler\s+MadeEasy")
# What an existing install still needs: exact strings that may spell an earlier name, and why
# (the command aliases kept after the rename and the migration note in INSTALL.md).
OLD_NAME_OK = ("`dlp-check`", "`dlp-check-assess`", "`dlp-check-evaluate`", "`DLP-Check`", "dlp-check-assess", "dlp-check-evaluate",
               "dlpcheck-data", "[DLP-Check", '"dlp-check"', "zscaler-made-easy and dlp-check")
OLD_NAME_SECTIONS = {"INSTALL.md": ("Moving to the new name",)}
HISTORY = {"CHANGELOG.md"}

# A small glossary: the spelling used everywhere, and the variants that are not.
GLOSSARY: List[Tuple[str, re.Pattern]] = [
    ("Client Connector", re.compile(r"\bClient connector\b")),
    ("Cloud & Branch Connector", re.compile(r"\bCloud and Branch Connector\b|\bCloud/Branch Connector\b|\bCloud & branch connector\b|\bCloud and branch connector\b")),
    ("ZIdentity", re.compile(r"\bZidentity\b|\bZ-Identity\b|\bZIDentity\b")),
    ("OneAPI", re.compile(r"\bOne API\b|\bOneApi\b|\bOne-API\b|\bOneapi\b")),
    ("Cloud Browser Isolation", re.compile(r"\bCloud browser isolation\b|\bCloud Browser isolation\b")),
]

_FENCE = re.compile(r"^\s*(```|~~~)")
_HEADING = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_LINK = re.compile(r"(?<!\!)\[([^\]]*)\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
_INLINE_CODE = re.compile(r"`[^`\n]*`")
_DATE_HEADING = re.compile(r"^##\s+(\d{4}-\d{2}-\d{2})\b")
_TODO = re.compile(r"\b(TODO|FIXME)\b")


def documents(root: str = ROOT) -> List[str]:
    """README.md, INSTALL.md, CHANGELOG.md and docs/*.md that exist, as paths relative to the root."""
    out = [p for p in ("README.md", "INSTALL.md", "CHANGELOG.md") if os.path.isfile(os.path.join(root, p))]
    out += sorted(os.path.relpath(p, root).replace(os.sep, "/") for p in glob.glob(os.path.join(root, "docs", "*.md")))
    return out


def _read(root: str, rel: str) -> List[str]:
    with open(os.path.join(root, *rel.split("/")), encoding="utf-8") as f:
        return f.read().split("\n")


def _prose(lines: List[str]) -> Iterable[Tuple[int, str]]:
    """(line number, text) of the prose lines: outside code fences, with inline code blanked."""
    fenced = False
    for i, line in enumerate(lines, 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield i, _INLINE_CODE.sub(lambda m: " " * len(m.group(0)), line)


def _plain(heading: str) -> str:
    h = _INLINE_CODE.sub(lambda m: m.group(0).strip("`"), heading)
    h = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", h)
    return re.sub(r"[*_]", "", h)


def slug(heading: str) -> str:
    """GitHub's anchor for a heading: lower case, punctuation dropped, spaces to hyphens."""
    s = _plain(heading).strip().lower()
    s = re.sub(r"[^\w\- ]", "", s, flags=re.UNICODE)
    return s.replace(" ", "-")


def anchors(lines: List[str]) -> set:
    seen: Dict[str, int] = {}
    out = set()
    fenced = False
    for line in lines:
        if _FENCE.match(line):
            fenced = not fenced
            continue
        m = None if fenced else _HEADING.match(line)
        if m:
            s = slug(m.group(2))
            n = seen.get(s, 0)
            seen[s] = n + 1
            out.add(s if n == 0 else f"{s}-{n}")
    # explicit anchors: <a id="x"> / <a name="x">
    for m in re.finditer(r'<a\s+(?:id|name)="([^"]+)"', "\n".join(lines)):
        out.add(m.group(1))
    return out


def _finding(file: str, line: int, rule: str, severity: str, message: str) -> Dict[str, Any]:
    return {"file": file, "line": line, "rule": rule, "severity": severity, "message": message}


def check_links(rel: str, lines: List[str], root: str, cache: Dict[str, set]) -> List[Dict[str, Any]]:
    out = []
    base = os.path.dirname(rel)
    for i, text in _prose(lines):
        for m in _LINK.finditer(text):
            target = m.group(2)
            if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*:", target) or target.startswith("//"):
                continue   # http(s), mailto and other schemes
            path, _, frag = target.partition("#")
            if path:
                full = os.path.normpath(os.path.join(root, base, path))
                if not full.startswith(os.path.normpath(root) + os.sep) or not os.path.exists(full):
                    out.append(_finding(rel, i, "broken-link", "error", f"the link {target!r} points at a file that does not exist"))
                    continue
                dest = os.path.relpath(full, root).replace(os.sep, "/")
            else:
                dest = rel
            if frag and dest.endswith(".md"):
                if dest not in cache:
                    cache[dest] = anchors(lines if dest == rel else _read(root, dest))
                if frag.lower() not in cache[dest] and frag not in cache[dest]:
                    out.append(_finding(rel, i, "broken-link", "error", f"the anchor #{frag} is not a heading of {dest}"))
    return out


def check_headings(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    out = []
    last = 0
    fenced = False
    for i, line in enumerate(lines, 1):
        if _FENCE.match(line):
            fenced = not fenced
            continue
        m = None if fenced else _HEADING.match(line)
        if not m:
            continue
        level = len(m.group(1))
        if last and level > last + 1:
            out.append(_finding(rel, i, "heading-skip", "error", f"a level {level} heading follows level {last}: no level {last + 1} in between"))
        last = level
    return out


def check_note(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    top = [i for i, line in enumerate(lines[:NEAR_TOP_LINES + 8]) if open_source.NOTE_MD in line]
    start = lines.index("---", 1) + 1 if lines and lines[0] == "---" and "---" in lines[1:] else 0
    first_section = next((i for i, line in enumerate(lines) if line.startswith("## ")), len(lines))
    if top and top[0] - start < NEAR_TOP_LINES and top[0] < first_section:
        return []
    return [_finding(rel, 1, "open-source-note", "error", "the open-source note is missing or not near the top (before the first ## section)")]


def _in_allowed_section(rel: str, lines: List[str], idx: int) -> bool:
    for head in OLD_NAME_SECTIONS.get(rel, ()):
        start = next((i for i, ln in enumerate(lines) if _HEADING.match(ln) and head in ln), None)
        if start is None or idx < start:
            continue
        level = len(_HEADING.match(lines[start]).group(1))
        end = next((i for i in range(start + 1, len(lines)) if (_HEADING.match(lines[i]) and len(_HEADING.match(lines[i]).group(1)) <= level)), len(lines))
        if idx < end:
            return True
    return False


def check_names(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    out = []
    for i, text in ((i, ln) for i, ln in enumerate(lines, 1)):
        if rel not in HISTORY:
            masked = text
            for ok in OLD_NAME_OK:
                masked = masked.replace(ok, " " * len(ok))
            m = OLD_NAMES.search(masked)
            if m and not _in_allowed_section(rel, lines, i - 1):
                out.append(_finding(rel, i, "product-name", "error", f"the app's earlier name {m.group(0)!r}: it is called Zscaler Made Easy"))
        m = BAD_NAME.search(_INLINE_CODE.sub("", text))
        if m:
            out.append(_finding(rel, i, "product-name", "error", f"{m.group(0)!r} is not the app's name: write Zscaler Made Easy"))
    return out


def check_changelog(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    if os.path.basename(rel) != "CHANGELOG.md":
        return []
    out, prev = [], None
    for i, line in enumerate(lines, 1):
        m = _DATE_HEADING.match(line)
        if not m:
            continue
        if prev and m.group(1) > prev[0]:
            out.append(_finding(rel, i, "changelog-order", "error", f"{m.group(1)} comes after {prev[0]} (line {prev[1]}): dates must descend, newest first"))
        if prev and m.group(1) == prev[0]:
            out.append(_finding(rel, i, "changelog-order", "error", f"the date {m.group(1)} is a heading twice (line {prev[1]})"))
        prev = (m.group(1), i)
    return out


def check_todo(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    return [_finding(rel, i, "todo", "error", f"{m.group(1)} left in the document") for i, line in enumerate(lines, 1) for m in [_TODO.search(line)] if m]


def check_glossary(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    out = []
    for i, text in _prose(lines):
        for term, pat in GLOSSARY:
            m = pat.search(text)
            if m:
                out.append(_finding(rel, i, "glossary", "error", f"{m.group(0)!r}: the term is written {term}"))
    return out


_SENT_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`*(\[])")


def check_sentences(rel: str, lines: List[str]) -> List[Dict[str, Any]]:
    out = []
    for i, text in _prose(lines):
        s = text.strip()
        if not s or s.startswith(("|", "#", "<", "---")) or re.match(r"^[-*+]\s+\[", s) and "](" in s and len(s) < 120:
            continue
        s = _LINK.sub(lambda m: m.group(1), s)
        for sent in _SENT_SPLIT.split(s):
            n = len(re.findall(r"\b[\w'’-]+\b", sent))
            if n > LONG_SENTENCE:
                out.append(_finding(rel, i, "long-sentence", "note", f"a sentence of {n} words (more than {LONG_SENTENCE}): {sent.strip()[:60]}…"))
    return out


def audit(root: str = ROOT, files: Optional[List[str]] = None) -> Dict[str, Any]:
    """Read the documents and return {files, findings, counts}. Read-only."""
    docs = files if files is not None else documents(root)
    findings: List[Dict[str, Any]] = []
    cache: Dict[str, set] = {}
    for rel in docs:
        lines = _read(root, rel)
        findings += check_links(rel, lines, root, cache) + check_headings(rel, lines) + check_note(rel, lines) + check_names(rel, lines)
        findings += check_changelog(rel, lines) + check_todo(rel, lines) + check_glossary(rel, lines) + check_sentences(rel, lines)
    findings.sort(key=lambda f: (f["file"], f["line"], f["rule"]))
    counts = {"errors": sum(1 for f in findings if f["severity"] == "error"), "notes": sum(1 for f in findings if f["severity"] == "note"),
              "files": len(docs)}
    return {"files": docs, "findings": findings, "counts": counts}


def report(result: Dict[str, Any]) -> str:
    lines = [f"{f['file']}:{f['line']}: [{f['rule']}] {f['severity']}: {f['message']}" for f in result["findings"]]
    c = result["counts"]
    lines.append(f"Docs audit: {c['files']} documents, {c['errors']} error(s), {c['notes']} note(s) (long sentences are only reported). Nothing was changed.")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Read-only editorial audit of README.md, INSTALL.md, CHANGELOG.md and docs/*.md.")
    ap.add_argument("--json", action="store_true", help="print the findings as JSON")
    ap.add_argument("--root", default=ROOT, help="the folder to audit (default: this repository)")
    args = ap.parse_args(argv)
    result = audit(args.root)
    print(json.dumps(result, indent=1) if args.json else report(result))
    return 1 if result["counts"]["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
