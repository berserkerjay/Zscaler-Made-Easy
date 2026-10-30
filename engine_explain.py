"""DLP engine explainability: an engine expression as people read it.

ZIA stores a custom DLP engine as an expression over dictionary ids:
`((D63.S > 1) AND (D7.S > 0))`. `D<id>.S` is the number of matches of
dictionary <id> in the content (the form pack_deploy /
dlp_importer.resolve_engine_expression writes and every fixture uses),
compared with `>`, `>=`, `<`, `<=` or `=`; terms are combined with AND, OR
and NOT (also `AND NOT`), parentheses group them, and `+` adds counts
(`(D1.S + D2.S) > 1`, the Engine Builder's Sum). A bare term counts as
"at least one match" (`> 0`). `.U` (unique matches) is read too. Packs
write `D:<dictionary name>` instead of an id; that form is read as well.

readable() replaces each id with the dictionary's name
(`(SSN count > 1) AND (Credit cards count > 0)`), summary() says it in one
sentence ("Fires when the content has more than one SSN match and at
least one Credit cards match."). The raw expression is never changed:
callers keep it for copying. An expression this module cannot parse
still gets its ids replaced (readable) but no summary, never a wrong one.

Pure: no tenant read, no I/O.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

MAX_EXPRESSION = 4000          # longer expressions are named, not parsed
MAX_NESTING = 40               # parentheses or NOTs nested deeper are named, not parsed (never a RecursionError)
_NUM_WORDS = ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten"]
_OPS = (">=", "<=", "==", "!=", ">", "<", "=")

_TOKEN_RE = re.compile(
    r"\s*(?:"
    r"(?P<lp>\()|(?P<rp>\))"
    r"|(?P<op>>=|<=|==|!=|>|<|=)"
    r"|(?P<plus>\+)"
    r"|(?P<kw>\b(?:AND|OR|NOT)\b)"
    r"|(?P<term>D(?P<id>\d+)\.(?P<suf>[A-Za-z]+))"
    r"|(?P<tpl>D\$\{[^}]{1,200}\}\.(?P<tsuf>[A-Za-z]+))"
    r"|(?P<named>D:(?P<name>[^()<>=!+]+?))(?=\s*(?:\bAND\b|\bOR\b|\)|[<>=!+]|$))"
    r"|(?P<num>\d+)"
    r")", re.I)
_ID_TERM_RE = re.compile(r"D(\d+)\.([A-Za-z]+)")
_SPACES = re.compile(r"\s+")


class ParseError(ValueError):
    """The expression is not one this module can read."""


# ── names ────────────────────────────────────────────────────────────
def display_name(name: Any) -> str:
    """A dictionary's name as people read it: Zscaler's predefined
    dictionaries come back as codes (CREDIT_CARD) and read as words."""
    s = str(name or "").strip()
    if "_" in s and s.upper() == s:
        s = s.replace("_", " ").lower()
        return s[:1].upper() + s[1:]
    return s


def names_by_id(dictionaries: Any) -> Dict[str, str]:
    """{id: name} from a dictionary list ([{id, name}]) or a {name: {id}}
    map (pack_removal.inventory's shape) or an {id: name} map."""
    out: Dict[str, str] = {}
    if isinstance(dictionaries, Mapping):
        for k, v in dictionaries.items():
            if isinstance(v, Mapping) and v.get("id") not in (None, ""):
                out[str(v["id"])] = str(k)
            elif isinstance(v, str):
                out[str(k)] = v
    else:
        for d in dictionaries or []:
            if isinstance(d, Mapping) and d.get("id") not in (None, "") and d.get("name"):
                out[str(d["id"])] = str(d["name"])
            elif hasattr(d, "id") and getattr(d, "name", None):
                out[str(d.id)] = str(d.name)
    return out


# ── parsing ──────────────────────────────────────────────────────────
def _tokens(expr: str) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    pos, n = 0, len(expr)
    while pos < n:
        if expr[pos:].strip() == "":
            break
        m = _TOKEN_RE.match(expr, pos)
        if not m or m.end() == pos:
            raise ParseError(f"unexpected text at {pos}: {expr[pos:pos + 20]!r}")
        pos = m.end()
        if m.group("lp"):
            out.append(("(", None))
        elif m.group("rp"):
            out.append((")", None))
        elif m.group("op"):
            out.append(("op", "=" if m.group("op") == "==" else m.group("op")))
        elif m.group("plus"):
            out.append(("+", None))
        elif m.group("kw"):
            out.append((m.group("kw").upper(), None))
        elif m.group("term"):
            out.append(("term", {"id": m.group("id"), "suffix": m.group("suf").upper(), "raw": m.group("term")}))
        elif m.group("tpl"):
            out.append(("term", {"id": None, "suffix": m.group("tsuf").upper(), "raw": m.group("tpl")}))
        elif m.group("named"):
            out.append(("term", {"id": None, "name": m.group("name").strip(), "suffix": "S", "raw": m.group("named").strip()}))
        else:
            out.append(("num", int(m.group("num"))))
    return out


def _cond(node: tuple) -> tuple:
    """A bare dictionary count (or Sum) where a condition is needed reads
    as "at least one match" (> 0), as ZIA's grammar has it."""
    if node[0] in ("term", "sum"):
        return ("cmp", node, ">", 0)
    if node[0] == "num":
        raise ParseError("a number on its own is not a condition")
    return node


class _Parser:
    """or := and (OR and)* ; and := not (AND not)* ; not := NOT not | cmp ;
    cmp := sum (op num)? ; sum := atom (+ atom)* ; atom := ( or ) | term | num"""

    def __init__(self, toks: List[Tuple[str, Any]]):
        self.t, self.i = toks, 0
        self.depth = 0

    def _deeper(self, fn):
        """fn() one nesting level down; ParseError past MAX_NESTING."""
        self.depth += 1
        try:
            if self.depth > MAX_NESTING:
                raise ParseError(f"nested more than {MAX_NESTING} levels deep")
            return fn()
        finally:
            self.depth -= 1

    def peek(self) -> Optional[str]:
        return self.t[self.i][0] if self.i < len(self.t) else None

    def take(self, kind: str) -> Any:
        if self.peek() != kind:
            raise ParseError(f"expected {kind}, found {self.peek()}")
        v = self.t[self.i][1]
        self.i += 1
        return v

    def parse(self) -> tuple:
        if not self.t:
            raise ParseError("empty expression")
        node = _cond(self.or_())
        if self.i != len(self.t):
            raise ParseError(f"unexpected {self.peek()}")
        return node

    def or_(self) -> tuple:
        items = [self.and_()]
        while self.peek() == "OR":
            self.i += 1
            items.append(self.and_())
        return items[0] if len(items) == 1 else ("or", [_cond(x) for x in items])

    def and_(self) -> tuple:
        items = [self.not_()]
        while self.peek() == "AND":
            self.i += 1
            items.append(self.not_())
        return items[0] if len(items) == 1 else ("and", [_cond(x) for x in items])

    def not_(self) -> tuple:
        if self.peek() == "NOT":
            self.i += 1
            return ("not", _cond(self._deeper(self.not_)))
        return self.cmp()

    def cmp(self) -> tuple:
        left = self.sum()
        if self.peek() == "op":
            op = self.take("op")
            n = self.take("num")
            if left[0] in ("and", "or", "not", "cmp", "num"):
                raise ParseError("a comparison needs a dictionary count on its left")
            return ("cmp", left, op, n)
        return left   # a bare count: made a condition where one is needed (_cond)

    def sum(self) -> tuple:
        items = [self.atom()]
        while self.peek() == "+":
            self.i += 1
            items.append(self.atom())
        if len(items) == 1:
            return items[0]
        if any(x[0] not in ("term", "sum") for x in items):
            raise ParseError("only dictionary counts can be added")
        flat: List[tuple] = []
        for x in items:
            flat += x[1] if x[0] == "sum" else [x]
        return ("sum", flat)

    def atom(self) -> tuple:
        k = self.peek()
        if k == "(":
            self.i += 1
            node = self._deeper(self.or_)
            self.take(")")
            return node
        if k == "term":
            return ("term", self.take("term"))
        if k == "num":
            return ("num", self.take("num"))
        raise ParseError(f"unexpected {k}")


def parse(expr: str) -> tuple:
    """The expression as a tree: ("or"|"and", [nodes]), ("not", node),
    ("cmp", term-or-sum, op, n), ("sum", [terms]), ("term", {...}).
    ParseError when it is not one this module reads."""
    s = str(expr or "")
    if len(s) > MAX_EXPRESSION:
        raise ParseError("expression too long to explain")
    # Runs of white space read as one space: a D:<name> term is found by
    # trying each longer name and looking past the spaces after it, which
    # on one long run of spaces would cost the square of its length.
    return _Parser(_tokens(_SPACES.sub(" ", s))).parse()


# ── rendering ────────────────────────────────────────────────────────
def _term_name(t: Dict[str, Any], names: Mapping[str, str]) -> Tuple[str, bool]:
    """(the dictionary's display name, known)."""
    if t.get("name"):
        return display_name(t["name"]), True
    if t.get("id") is None:
        return t["raw"].rsplit(".", 1)[0], False
    n = names.get(str(t["id"]))
    return (display_name(n), True) if n else (f"unknown dictionary {t['id']}", False)


def _count_word(suffix: str) -> str:
    return {"S": "count", "U": "unique count"}.get(suffix.upper(), f"{suffix.upper()} value")


def _readable(node: tuple, names: Mapping[str, str], top: bool = False) -> str:
    kind = node[0]
    if kind == "term":
        name, _ = _term_name(node[1], names)
        return f"{name} {_count_word(node[1]['suffix'])}"
    if kind == "num":
        return str(node[1])
    if kind == "sum":
        return " + ".join(_readable(x, names) for x in node[1])
    if kind == "cmp":
        left = _readable(node[1], names)
        if node[1][0] == "sum":
            left = f"({left})"
        return f"{left} {node[2]} {node[3]}"
    if kind == "not":
        return f"NOT ({_readable(node[1], names, True)})"
    word = " AND " if kind == "and" else " OR "
    return word.join(f"({_readable(x, names, True)})" for x in node[1])


def _fallback(expr: str, names: Mapping[str, str]) -> str:
    def sub(m: "re.Match") -> str:
        n = names.get(m.group(1))
        return f"{display_name(n) if n else f'unknown dictionary {m.group(1)}'} {_count_word(m.group(2))}"
    return _ID_TERM_RE.sub(sub, str(expr or ""))


def readable(expr: Any, names: Optional[Mapping[str, str]] = None) -> str:
    """The expression with dictionary names in place of ids and no
    redundant outer parentheses. Unknown ids read "unknown dictionary
    <id>". An expression that cannot be parsed keeps its own shape with the
    ids replaced."""
    names = names or {}
    s = str(expr or "").strip()
    if not s:
        return ""
    try:
        return _readable(parse(s), names, True)
    except ParseError:
        return _fallback(s, names)


def _n(n: int) -> str:
    return _NUM_WORDS[n] if 0 <= n < len(_NUM_WORDS) else str(n)


def _quant(op: str, n: int) -> Tuple[str, bool]:
    """(the quantifier, plural) of a comparison: ('more than one', False)."""
    if op == ">":
        return ("at least one", False) if n == 0 else (f"more than {_n(n)}", n > 1)
    if op == ">=":
        return ("at least one", False) if n <= 1 else (f"at least {_n(n)}", True)
    if op == "<":
        return ("no", False) if n <= 1 else (f"fewer than {_n(n)}", True)
    if op == "<=":
        return ("no", False) if n == 0 else (f"at most {_n(n)}", n > 1)
    if op == "=":
        return ("no", False) if n == 0 else (f"exactly {_n(n)}", n > 1)
    return (f"a number of matches {op} {n} of", True)   # != and anything new


def _cmp_phrase(node: tuple, names: Mapping[str, str]) -> str:
    """'more than one SSN match'; a Sum: 'at least one match of A and B combined'.
    A count is never negative, so `>= 0` holds for any content and `< 0`
    for none: said as such, never as "at least one" or "no" match."""
    op, n = node[2], node[3]
    if op == "!=" and n == 0:
        op = ">"   # a count other than zero is at least one
    left = node[1]
    if left[0] == "term":
        name = _term_name(left[1], names)[0]
        what = f"unique {name}" if left[1]["suffix"] == "U" else name
    else:
        parts = [_term_name(t[1], names)[0] for t in left[1]]
        what = (", ".join(parts[:-1]) + " and " + parts[-1] if len(parts) > 1 else parts[0]) + " combined"
    if op == ">=" and n <= 0:
        return f"any number of {what} matches, even none (always true)"
    if op == "<" and n <= 0:
        return f"fewer than zero {what} matches (never true)"
    if op == "!=":
        return f"a number of {what} matches other than {_n(n)}"
    q, plural = _quant(op, n)
    word = "matches" if plural else "match"
    if left[0] == "term":
        return f"{q} {what} {word}"
    return f"{q} {word} of {what}"


def _join(parts: List[str], word: str) -> str:
    return parts[0] if len(parts) == 1 else ", ".join(parts[:-1]) + f" {word} " + parts[-1]


def _says(node: tuple, names: Mapping[str, str], nested: bool = False) -> str:
    kind = node[0]
    if kind == "cmp":
        return _cmp_phrase(node, names)
    if kind == "term":
        return f"at least one {_term_name(node[1], names)[0]} match"
    if kind == "not":
        inner = node[1]
        if inner[0] == "cmp" and inner[2] == ">" and inner[3] == 0 and inner[1][0] == "term":
            return f"no {_term_name(inner[1][1], names)[0]} match"
        return f"not {_says(inner, names, True)}"
    if kind in ("and", "or"):
        parts = [_says(x, names, True) for x in node[1]]
        text = _join(parts, kind)
        if not nested:
            return text
        if kind == "and":
            return f"both {text}" if len(parts) == 2 else f"all of {text}"
        return f"either {text}" if len(parts) == 2 else f"any of {text}"
    raise ParseError("nothing to say")


def summary(expr: Any, names: Optional[Mapping[str, str]] = None) -> str:
    """One plain-English sentence: when the engine fires. Empty when the
    expression cannot be parsed (never a guess)."""
    s = str(expr or "").strip()
    if not s:
        return ""
    try:
        text = _says(parse(s), names or {})
    except ParseError:
        return ""
    return f"Fires when the content has {text}."


def explain(expr: Any, names: Optional[Mapping[str, str]] = None) -> Dict[str, Any]:
    """{expression (raw, unchanged), readable, summary, dictionaries: [{id,
    name, known}], unknown_ids, parsed}."""
    names = names or {}
    raw = str(expr or "")
    try:
        parse(raw)
        parsed = bool(raw.strip())
    except ParseError:
        parsed = False
    seen: Dict[str, Dict[str, Any]] = {}
    for m in _ID_TERM_RE.finditer(raw):
        did = m.group(1)
        if did not in seen:
            n = names.get(did)
            seen[did] = {"id": did, "name": display_name(n) if n else "", "known": bool(n)}
    return {"expression": raw, "readable": readable(raw, names), "summary": summary(raw, names),
            "dictionaries": list(seen.values()), "unknown_ids": [d["id"] for d in seen.values() if not d["known"]],
            "parsed": parsed}


# ── file types ───────────────────────────────────────────────────────
def file_type_label(token: Any) -> Tuple[str, str]:
    """(label, kind) of a File Type Control / DLP file type token:
    FTCATEGORY_WINDOWS_EXECUTABLES -> ('Windows executables', 'File type
    category'); anything else -> its words, 'File type'. Extensions are
    not in the token: a custom file type's extension is named only when the
    tenant's custom file types were read."""
    s = str(token or "").strip()
    kind = "File type category" if s.upper().startswith("FTCATEGORY_") else "File type"
    words = re.sub(r"^FTCATEGORY_", "", s, flags=re.I).replace("_", " ").strip().lower()
    for up in ("ms", "pdf", "zip", "rar", "iso", "xml", "csv", "html", "json", "sql", "dll", "exe", "apk", "jar", "ios", "cad", "rtf", "vba"):
        words = re.sub(rf"\b{up}\b", up.upper(), words)
    words = re.sub(r"\bMS (\w)", lambda m: "MS " + m.group(1).upper(), words)
    return (words[:1].upper() + words[1:]) if words else s, kind


def file_type_usage(rules_by_policy: Mapping[str, Iterable[Mapping[str, Any]]]) -> List[Dict[str, Any]]:
    """[{token, label, kind, used_by: {policy: [rule names]}}] from raw rules
    that name file types (fileTypes / file_types), sorted by label."""
    out: Dict[str, Dict[str, Any]] = {}
    for policy, rules in (rules_by_policy or {}).items():
        for r in rules or []:
            if not isinstance(r, Mapping):
                continue
            fts = r.get("fileTypes") if r.get("fileTypes") is not None else r.get("file_types")
            for ft in fts or []:
                tok = str(ft.get("name") or ft.get("id") or "") if isinstance(ft, Mapping) else str(ft)
                if not tok or tok.upper() in ("ANY", "ALL", "NONE"):
                    continue
                label, kind = file_type_label(tok)
                slot = out.setdefault(tok, {"token": tok, "label": label, "kind": kind, "used_by": {}})
                name = str(r.get("name") or f"Rule {r.get('id')}")
                lst = slot["used_by"].setdefault(policy, [])
                if name not in lst:
                    lst.append(name)
    return sorted(out.values(), key=lambda x: x["label"].lower())
