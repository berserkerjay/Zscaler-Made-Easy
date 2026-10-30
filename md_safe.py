"""One way to put untrusted text into a Markdown export.

Rule, dictionary, engine and URL-category names, descriptions, comments,
file names and log lines come from the tenant, an uploaded file or another
person, and the app writes them into Markdown reports (change queue,
proposals, digests, detection health, data flow, SSL flow, bypass,
benchmarks, efficacy, upstream check, Terraform READMEs). Markdown viewers
render links, images and inline HTML, so a rule named
``[Approve](javascript:alert(1))`` or ``<img src=x onerror=alert(1)>`` would
become a live link or HTML in the viewer, and a name with a line break
could forge a heading or a table row of its own.

``text`` makes a value inert inline text: one line, ``<`` and ``>`` as
HTML entities (no tag, no autolink), and
link and image brackets, code backticks, table pipes and the escape
character itself backslash-escaped. ``escape_data`` applies ``text`` to
every string in a report's data (keys stay as they are), so a generator
escapes its input once and its own Markdown stays as written. ``code``
makes a value an inline code span whatever backticks it holds. ``url`` returns a link target only for http(s) and
mailto, so a ``javascript:`` or ``data:`` URL is never a link.
"""
from __future__ import annotations

import re
from typing import Any, Optional

_BREAKS = re.compile(r"[\r\n\t\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u2028\u2029\u0085]+")
# Link and image brackets, code, table pipes and the escape character
# itself. Emphasis characters (* _ ~) are left alone: at worst they change
# how a name is styled, and identifiers such as FILE_TYPE stay readable.
_SPECIAL = re.compile(r"([\\`\[\]|])")
# What makes a line an ATX heading, a list item, a thematic break or a
# setext underline when a value starts it ("- {name}" too: "- # x" is a
# heading inside the item; > is already an entity). Its marker is
# backslash-escaped, which every Markdown viewer shows as the character
# itself; "-5" or a lone "-" is left as it is.
_BLOCK_START = re.compile(r"^(?:#{1,6}(?=\s|$)|[-+*](?=\s)|([-*_])(?:\s*\1){2,}\s*$|=+\s*$|\d{1,9}(?=[.)](?:\s|$)))")


# Explicit bidirectional embeddings, overrides and isolates (U+202A-U+202E,
# U+2066-U+2069). A tenant name holding U+202E (right-to-left override)
# turns the rest of its line around in a viewer, so a sentence such as
# "rule X allows uploads" reads as something else (CWE-451). Names never
# need them (right-to-left scripts display by the implicit algorithm);
# each becomes U+FFFD so the oddity stays visible. Zero-width joiners and
# spaces are left alone: some scripts need them.
BIDI_CONTROLS = re.compile("[\u202a-\u202e\u2066-\u2069]")


def no_bidi(value: Any) -> str:
    """The value with every explicit bidirectional control shown as U+FFFD."""
    return BIDI_CONTROLS.sub("\ufffd", "" if value is None else str(value))


def one_line(value: Any) -> str:
    """The value as a single line: line and paragraph breaks and other
    control characters become one space, and a bidirectional control
    U+FFFD (no_bidi)."""
    return no_bidi(_BREAKS.sub(" ", "" if value is None else str(value))).strip()


def text(value: Any, limit: Optional[int] = None) -> str:
    """Inert inline Markdown for an untrusted value (see the module doc)."""
    s = one_line(value)
    if limit is not None and len(s) > limit:
        s = s[: max(0, limit - 1)] + "…"
    # < and > as entities: no tag, no autolink. & stays: an entity in a
    # value can only ever decode to a character, never to markup.
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    s = _SPECIAL.sub(r"\\\1", s)
    m = _BLOCK_START.match(s)
    if m:
        s = s[: m.end()] + "\\" + s[m.end():] if m.group(0)[0].isdigit() else "\\" + s
    return s


def code(value: Any, limit: Optional[int] = None) -> str:
    """An inline code span holding the value verbatim (one line): the fence
    is one backtick longer than the longest run inside, padded with a space
    when the value starts or ends with a backtick."""
    s = one_line(value)
    if limit is not None and len(s) > limit:
        s = s[: max(0, limit - 1)] + "…"
    if not s:
        return "``"
    run = max((len(m) for m in re.findall(r"`+", s)), default=0)
    fence = "`" * (run + 1)
    pad = " " if s.startswith("`") or s.endswith("`") else ""
    return f"{fence}{pad}{s}{pad}{fence}"


def cell_code(value: Any, limit: Optional[int] = None) -> str:
    """``code`` for a table cell: GFM splits a row on a pipe even inside a
    code span, so pipes are escaped too."""
    return code(value, limit).replace("|", "\\|")


def url(value: Any) -> Optional[str]:
    """``value`` as a Markdown link target when it is an http(s) or mailto
    URL without spaces, angle brackets or a pipe (which would split a table
    row); None otherwise (show it as text)."""
    s = one_line(value)
    if not re.match(r"(?i)^(https?://|mailto:)[^\s<>()\[\]`|]+$", s):
        return None
    return s


def link(label: Any, target: Any) -> str:
    """``[label](target)`` when the target is a safe URL, else the label
    as text followed by the target as text."""
    u = url(target)
    if u is None:
        t = one_line(target)
        return text(label) + (f" ({text(t)})" if t else "")
    return f"[{text(label)}]({u})"


def escape_data(obj: Any) -> Any:
    """A copy of ``obj`` with every string value made inert by ``text``
    (an http(s) or mailto URL is kept as it is, so it still links). Dict keys, numbers, booleans and None are unchanged."""
    if isinstance(obj, str):
        return obj if url(obj) == obj else text(obj)
    if isinstance(obj, dict):
        return {k: escape_data(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [escape_data(v) for v in obj]
    return obj
