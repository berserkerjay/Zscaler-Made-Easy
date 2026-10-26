"""Static scanner for HTML injection sinks in the browser code.

Used by tests/test_xss_sinks.py. It reads every script in static/*.js,
the inline <script> blocks of static/*.html and browser_extension/*.js,
and checks every value that can reach HTML:

* the right-hand side of ``.innerHTML =`` / ``+=``, ``.outerHTML =``,
  ``insertAdjacentHTML(pos, html)`` and ``document.write(html)``;
* every ``${...}`` inside a template literal that contains markup, and every
  operand concatenated (``+``) to a string literal that contains markup.

A value is accepted only when the scanner can show it is safe: a literal,
a number, a call to an HTML escaper defined in that file (a function whose
body replaces ``[&<>"']``), ``encodeURIComponent``, a template or
concatenation whose own parts are all safe, a ``.map(cb).join()`` whose
callback returns something safe, a local variable or function whose every
assignment / return is safe, or a parameter whose every call site passes
something safe. Everything else is reported as a ``Finding`` (file, line,
expression, reason). Context matters too: an escaped value inside an
``on*=`` handler attribute, a ``style`` attribute, an unquoted attribute, or
at the start of an ``href``/``src``/``action`` value is still reported,
because HTML escaping does not make those contexts safe.

It is a deliberately small, conservative analysis (no full JS parser
dependency, so it runs anywhere CI runs Python): it over-reports rather
than under-reports, and the test keeps a reviewed allowlist of the
remaining values with the reason each one is safe.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Lexer ─────────────────────────────────────────────────────────────


@dataclass(eq=False)
class Tok:
    kind: str          # ident, num, str, tpl, punct, regex
    text: str
    pos: int
    parts: List[str] = field(default_factory=list)          # tpl: static chunks
    exprs: List[List["Tok"]] = field(default_factory=list)  # tpl: ${} token lists
    expr_src: List[str] = field(default_factory=list)       # tpl: ${} source text
    end: int = 0
    lst: int = 0       # index of the token list this token belongs to
    i: int = 0         # index inside that list


_PUNCT3 = ("===", "!==", "**=", "...", "<<=", ">>=", ">>>", "&&=", "||=", "??=")
_PUNCT2 = ("=>", "==", "!=", "<=", ">=", "&&", "||", "??", "?.", "+=", "-=", "*=", "/=",
           "%=", "&=", "|=", "^=", "++", "--", "<<", ">>", "**")
_REGEX_PREV_PUNCT = set("(,=:[!&|?{};+-*%<>~^") | {"=>", "==", "===", "!=", "!==", "&&", "||",
                                                     "??", "+=", "-=", "<=", ">=", "return", "typeof"}
_KEYWORDS_BEFORE_REGEX = {"return", "typeof", "case", "do", "else", "in", "of", "new", "delete", "void", "throw"}


class LexError(Exception):
    pass


_WS_RE = re.compile(r"[ \t\r\n]+")
_NUM_RE = re.compile(r"0[xX][0-9a-fA-F_]+|\d[\d_]*\.?\d*(?:[eE][+-]?\d+)?n?|\.\d+")
_ID_RE = re.compile(r"[A-Za-z_$][\w$]*")
_FLAGS_RE = re.compile(r"[a-z]*")
_PUNCT_RE = re.compile("|".join(re.escape(p) for p in sorted(_PUNCT3 + _PUNCT2, key=len, reverse=True)) + "|.", re.S)


def lex(src: str, start: int = 0, stop_at_brace: bool = False) -> Tuple[List[Tok], int]:
    """Tokenise ``src`` from ``start``. With stop_at_brace, stop at the
    ``}`` that closes a template ``${`` and return its index."""
    toks: List[Tok] = []
    i, n, depth = start, len(src), 0
    while i < n:
        c = src[i]
        if c in " \t\r\n":
            i = _WS_RE.match(src, i).end()
            continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                j += 1
            toks.append(Tok("str", src[i:j + 1], i, end=j + 1))
            i = j + 1
            continue
        if c == "`":
            t, i = _lex_template(src, i)
            toks.append(t)
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            m = _NUM_RE.match(src, i)
            toks.append(Tok("num", m.group(0), i, end=m.end()))
            i = m.end()
            continue
        if c.isalpha() or c in "_$":
            m = _ID_RE.match(src, i)
            toks.append(Tok("ident", m.group(0), i, end=m.end()))
            i = m.end()
            continue
        if c == "/":
            prev = toks[-1] if toks else None
            if prev is None or (prev.kind == "punct" and prev.text in _REGEX_PREV_PUNCT) or \
                    (prev.kind == "ident" and prev.text in _KEYWORDS_BEFORE_REGEX):
                j, in_cls = i + 1, False
                while j < n:
                    ch = src[j]
                    if ch == "\\":
                        j += 2
                        continue
                    if ch == "[":
                        in_cls = True
                    elif ch == "]":
                        in_cls = False
                    elif ch == "/" and not in_cls:
                        break
                    elif ch == "\n":
                        raise LexError(f"unterminated regex at {i}")
                    j += 1
                m = _FLAGS_RE.match(src, j + 1)
                toks.append(Tok("regex", src[i:m.end()], i, end=m.end()))
                i = m.end()
                continue
        if stop_at_brace:
            if c == "{":
                depth += 1
            elif c == "}":
                if depth == 0:
                    return toks, i
                depth -= 1
        m = _PUNCT_RE.match(src, i)
        toks.append(Tok("punct", m.group(0), i, end=m.end()))
        i = m.end()
    if stop_at_brace:
        raise LexError("unterminated ${")
    return toks, i


def _lex_template(src: str, i: int) -> Tuple[Tok, int]:
    start, j, n = i, i + 1, len(src)
    parts, exprs, expr_src, buf = [], [], [], []
    while j < n:
        ch = src[j]
        if ch == "\\":
            buf.append(src[j:j + 2])
            j += 2
            continue
        if ch == "`":
            parts.append("".join(buf))
            return Tok("tpl", src[start:j + 1], start, parts, exprs, expr_src, end=j + 1), j + 1
        if src.startswith("${", j):
            parts.append("".join(buf))
            buf = []
            toks, k = lex(src, j + 2, stop_at_brace=True)
            exprs.append(toks)
            expr_src.append(src[j + 2:k])
            j = k + 1
            continue
        buf.append(ch)
        j += 1
    raise LexError(f"unterminated template at {start}")


# ── Structure helpers ─────────────────────────────────────────────────

_OPEN = {"(": ")", "[": "]", "{": "}"}


def match_brackets(toks: List[Tok]) -> Dict[int, int]:
    m, st = {}, []
    for k, t in enumerate(toks):
        if t.kind != "punct":
            continue
        if t.text in _OPEN:
            st.append(k)
        elif t.text in (")", "]", "}") and st:
            o = st.pop()
            m[o] = k
            m[k] = o
    return m


def split_top(toks: List[Tok], seps: Tuple[str, ...]) -> List[List[Tok]]:
    out, cur, d = [], [], 0
    for t in toks:
        if t.kind == "punct" and t.text in _OPEN:
            d += 1
        elif t.kind == "punct" and t.text in (")", "]", "}"):
            d -= 1
        if d == 0 and t.kind == "punct" and t.text in seps:
            out.append(cur)
            cur = []
            continue
        cur.append(t)
    out.append(cur)
    return out


def strip_parens(toks: List[Tok]) -> List[Tok]:
    while len(toks) >= 2 and toks[0].text == "(" and toks[0].kind == "punct":
        m = match_brackets(toks)
        if m.get(0) == len(toks) - 1:
            toks = toks[1:-1]
        else:
            break
    return toks


def src_of(toks: List[Tok], src: str) -> str:
    if not toks:
        return ""
    return re.sub(r"\s+", " ", src[toks[0].pos:toks[-1].end]).strip()


# ── Per-file analysis ─────────────────────────────────────────────────

MARKUP = re.compile(r"<\s*/?\s*[A-Za-z!]")
_ESCAPER_BODY = re.compile(r"replace\(\s*/\[[^\]]*&[^\]]*<[^\]]*>[^\]]*\]/g")
SAFE_GLOBAL_CALLS = {"encodeURIComponent", "Number", "parseInt", "parseFloat", "Boolean",
                     "isFinite", "isNaN"}
SAFE_METHODS_NUM = {"toFixed", "toPrecision", "getTime", "valueOf", "indexOf", "findIndex",
                    "lastIndexOf", "getFullYear", "getHours", "getMinutes", "includes",
                    "has", "some", "every", "startsWith", "endsWith", "test", "localeCompare"}
SAFE_MEMBERS = {"length", "size"}
ARRAY_PASS = {"filter", "slice", "sort", "reverse", "concat", "flat"}
CALLBACK_METHODS = {"map", "forEach", "filter", "some", "every", "find", "findIndex", "reduce",
                    "flatMap", "sort"}




@dataclass
class Finding:
    file: str
    line: int
    expr: str
    reason: str
    span: Tuple[int, int] = (0, 0)

    @property
    def key(self) -> str:
        return f"{self.file} :: {self.expr}"


@dataclass(eq=False)
class Func:
    name: Optional[str]
    lst: int                       # which token list (0 = the file, others = ${} bodies)
    params: List[str]
    body: Tuple[int, int]          # token index range [a, b) of the body in that list
    expr_body: bool
    is_callback_of: Optional[str]  # "map" etc. when passed inline to a method
    decl_index: int                # index of the function's first token in that list


class FileScan:
    """Analysis of one script (or the concatenation of a page's inline
    scripts)."""

    def __init__(self, name: str, src: str, shared: Optional["Shared"] = None):
        self.name, self.src = name, src
        root, _ = lex(src)
        self.lists: List[List[Tok]] = []
        self.parent: Dict[int, Tuple[int, int]] = {}
        self._register(root, None)
        self.brs = [match_brackets(t) for t in self.lists]
        self.shared = shared or Shared()
        self.funcs: List[Func] = []
        for lid in range(len(self.lists)):
            self._find_funcs(lid)
        self.refresh()

    def refresh(self):
        """Recompute what depends on the shared (cross-file) knowledge and
        forget every verdict reached so far."""
        self.escapers = set(self.shared.escapers)
        self._find_escapers()
        self.memo: Dict[tuple, bool] = {}
        self.memo_leaf: Dict[tuple, tuple] = {}
        self._sc = {}
        self.findings: List[Finding] = []
        self._seen = set()

    def _register(self, toks: List[Tok], parent: Optional[Tuple[int, int]]):
        lid = len(self.lists)
        self.lists.append(toks)
        if parent is not None:
            self.parent[lid] = parent
        for k, t in enumerate(toks):
            t.lst, t.i = lid, k
        for k, t in enumerate(toks):
            if t.kind == "tpl":
                for e in t.exprs:
                    self._register(e, (lid, k))

    @property
    def _names(self):
        """Per token list: identifier text -> the indices where it occurs."""
        if not hasattr(self, "_name_idx"):
            self._name_idx = []
            for T in self.lists:
                d: Dict[str, List[int]] = {}
                for k, t in enumerate(T):
                    if t.kind == "ident":
                        d.setdefault(t.text, []).append(k)
                self._name_idx.append(d)
        return self._name_idx

    def line(self, pos: int) -> int:
        return self.src.count("\n", 0, pos) + 1

    # -- discovery ---------------------------------------------------
    def _params_from(self, T: List[Tok], a: int, b: int) -> List[str]:
        names = []
        for g in split_top(T[a:b], (",",)):
            if not g:
                continue
            if g[0].kind == "ident":
                names.append(g[0].text)
            elif g[0].text == "..." and len(g) > 1:
                names.append(g[1].text)
            else:   # destructuring: every identifier before a default is a param
                for t in g:
                    if t.text == "=":
                        break
                    if t.kind == "ident":
                        names.append(t.text)
        return names

    def _find_funcs(self, lid: int):
        T, br = self.lists[lid], self.brs[lid]
        for k, t in enumerate(T):
            if t.kind == "ident" and t.text == "function":
                j, fname = k + 1, None
                if j < len(T) and T[j].text == "*":
                    j += 1
                if j < len(T) and T[j].kind == "ident":
                    fname, j = T[j].text, j + 1
                if j < len(T) and T[j].text == "(" and j in br:
                    close = br[j]
                    if close + 1 < len(T) and T[close + 1].text == "{" and close + 1 in br:
                        head = k - 1 if k and T[k - 1].text == "async" else k
                        self.funcs.append(Func(fname or self._assigned_name(T, head), lid,
                                               self._params_from(T, j + 1, close),
                                               (close + 2, br[close + 1]), False,
                                               self._callback_of(T, head), head))
            elif t.kind == "punct" and t.text == "=>":
                p = k - 1
                if p < 0:
                    continue
                if T[p].text == ")" and p in br:
                    head = br[p]
                    params = self._params_from(T, head + 1, p)
                elif T[p].kind == "ident":
                    head, params = p, [T[p].text]
                else:
                    continue
                if head > 0 and T[head - 1].text == "async":
                    head -= 1
                b0 = k + 1
                if b0 < len(T) and T[b0].text == "{" and b0 in br:
                    body, expr_body = (b0 + 1, br[b0]), False
                else:
                    body, expr_body = (b0, self._expr_end(lid, b0)), True
                self.funcs.append(Func(self._assigned_name(T, head), lid, params, body, expr_body,
                                       self._callback_of(T, head), head))
            elif t.kind == "punct" and t.text == "(" and k > 1 and T[k - 1].kind == "ident" and k in br \
                    and br[k] + 1 < len(T) and T[br[k] + 1].text == "{" and T[k - 2].text in ("{", ",", "}", ";") \
                    and T[k - 1].text not in ("if", "for", "while", "switch", "catch", "function", "return", "with"):
                close = br[k]
                if close + 1 in br:   # object-literal / class method: name(params) { body }
                    self.funcs.append(Func(T[k - 1].text, lid, self._params_from(T, k + 1, close),
                                           (close + 2, br[close + 1]), False, None, k - 1))

    @staticmethod
    def _assigned_name(T: List[Tok], head: int) -> Optional[str]:
        if head >= 2 and T[head - 1].text in ("=", ":") and T[head - 2].kind in ("ident", "str"):
            return T[head - 2].text.strip("'\"")
        return None

    @staticmethod
    def _callback_of(T: List[Tok], head: int) -> Optional[str]:
        if head >= 3 and T[head - 1].text == "(" and T[head - 2].kind == "ident" and T[head - 3].text in (".", "?."):
            return T[head - 2].text
        return None

    def _expr_end(self, lid: int, a: int) -> int:
        T, br, k = self.lists[lid], self.brs[lid], a
        while k < len(T):
            t = T[k]
            if t.kind == "punct":
                if t.text in _OPEN:
                    k = br.get(k, k) + 1
                    continue
                if t.text in (")", "]", "}", ",", ";"):
                    return k
            k += 1
        return k

    def _body_src(self, f: Func) -> str:
        T = self.lists[f.lst]
        a, b = f.body
        return self.src[T[a].pos:T[b - 1].end] if b > a else ""

    def _find_escapers(self):
        quotes = set()
        for f in self.funcs:
            body = self._body_src(f)
            if f.name and _ESCAPER_BODY.search(body) and all(x in body for x in ("&amp;", "&lt;", "&gt;")):
                self.escapers.add(f.name)
                if "&quot;" in body and ("&#39;" in body or "&#x27;" in body):
                    quotes.add(f.name)
        self.full_escapers = set(self.shared.full_escapers) | quotes
        T = self.lists[0]
        for _ in range(2):   # aliases: const E = escapeHtml;  const E = _bpE;  const E = FA.E;
            for k in range(len(T) - 5):
                if T[k].text in ("const", "let", "var") and T[k + 2].text == "=" and T[k + 3].kind == "ident" and \
                        T[k + 4].text == "." and T[k + 5].text in self.shared.member_escapers and \
                        (k + 6 >= len(T) or T[k + 6].text in (";", ",")):
                    self.escapers.add(T[k + 1].text)
                    self.full_escapers.add(T[k + 1].text)
            for k in range(len(T) - 3):
                if T[k].text in ("const", "let", "var") and T[k + 2].text == "=" and \
                        T[k + 3].text in self.escapers and (k + 4 >= len(T) or T[k + 4].text in (";", ",")):
                    self.escapers.add(T[k + 1].text)
                    if T[k + 3].text in self.full_escapers:
                        self.full_escapers.add(T[k + 1].text)

    # -- scope ---------------------------------------------------------
    def _contains(self, f: Func, tok: Tok) -> bool:
        lid, idx = tok.lst, tok.i
        while True:
            if lid == f.lst:
                return f.body[0] <= idx < f.body[1]
            if lid not in self.parent:
                return False
            lid, idx = self.parent[lid]

    def enclosing_funcs(self, tok: Tok) -> List[Func]:
        out, lid, idx = [], tok.lst, tok.i
        while True:
            here = [f for f in self.funcs if f.lst == lid and f.body[0] <= idx < f.body[1]]
            here.sort(key=lambda f: f.body[1] - f.body[0])
            out.extend(here)
            if lid not in self.parent:
                return out
            lid, idx = self.parent[lid]

    def resolve(self, name: str, tok: Tok):
        """('param', func, i) | ('decl', [exprs]) | ('func', [funcs]) | None."""
        for f in self.enclosing_funcs(tok):
            if name in f.params:
                return ("param", f, f.params.index(name))
            r = self._decls_in(name, f.lst, f.body[0], f.body[1], tok)
            if r is not None:
                return r
        return self._decls_in(name, 0, 0, len(self.lists[0]), tok)

    def _decls_in(self, name, lid, a, b, tok):
        T = self.lists[lid]
        nested = [g for g in self.funcs if g.lst == lid and a <= g.decl_index and g.body[1] <= b
                  and not self._contains(g, tok)]
        exprs, funcs, found = [], [], False
        idx = self._names[lid].get(name, ())
        for k in idx:
            if not a <= k < b:
                continue
            if any(g.decl_index <= k < g.body[1] for g in nested):
                continue
            prev = T[k - 1] if k else None
            nxt = T[k + 1] if k + 1 < len(T) else None
            pt = prev.text if prev is not None else ""
            nt = nxt.text if nxt is not None else ""
            if pt in (".", "?."):
                continue
            fn_here = [g for g in self.funcs if g.lst == lid and g.decl_index == k + 2 and nt == "="]
            if fn_here:
                funcs.extend(fn_here)
                found = True
                continue
            if pt == "function":
                funcs.extend(g for g in self.funcs if g.lst == lid and g.decl_index in (k - 1, k - 2) and g.name == name)
                found = True
            elif pt in ("const", "let", "var") and nt in ("of", "in"):
                exprs.append(None)
                found = True
            elif pt in ("const", "let", "var") or (pt == "," and self._in_decl_list(T, k)):
                found = True
                if nt == "=":
                    exprs.append(T[k + 2:self._expr_end(lid, k + 2)])
                elif nt in (",", ";", ""):
                    pass                     # declared without a value, assigned later
                else:
                    exprs.append(None)
            elif nt in ("=", "+=", "||=", "??=") and pt not in ("(", ",") or \
                    (nt in ("=", "+=") and pt in ("(", ",") and not self._in_destructure(T, k)):
                if nt == "=" and k + 2 < len(T) and T[k + 2].text == "=":
                    continue
                exprs.append(T[k + 2:self._expr_end(lid, k + 2)])
            elif nt in (",", "}", ":", "]", "=") and self._in_destructure(T, k):
                found = True
                exprs.append(None)
        for g in self.funcs:   # object-literal methods / name: function
            if g.name == name and g.lst == lid and a <= g.decl_index < b and g not in funcs and \
                    not any(h.decl_index <= g.decl_index < h.body[1] for h in nested):
                if lid == 0 or True:
                    funcs.append(g)
        if funcs:
            return ("func", funcs)
        if found:
            return ("decl", exprs)
        return None

    @staticmethod
    def _in_decl_list(T, k) -> bool:
        j, d = k - 1, 0
        while j >= 0:
            t = T[j]
            if t.kind == "punct" and t.text in (")", "]", "}"):
                d += 1
            elif t.kind == "punct" and t.text in _OPEN:
                if d == 0:
                    return False
                d -= 1
            elif d == 0 and t.text == ";":
                return False
            elif d == 0 and t.text in ("const", "let", "var"):
                return True
            j -= 1
        return False

    @staticmethod
    def _in_destructure(T, k) -> bool:
        j, d = k - 1, 0
        while j >= 0:
            t = T[j]
            if t.kind == "punct" and t.text in (")", "]", "}"):
                d += 1
            elif t.kind == "punct" and t.text in ("[", "{"):
                if d == 0:
                    return j > 0 and T[j - 1].text in ("const", "let", "var", "(", ",", "of")
                d -= 1
            elif t.kind == "punct" and t.text == "(":
                if d == 0:
                    return False
                d -= 1
            elif t.text == ";":
                return False
            j -= 1
        return False

    # -- the safety judgement -------------------------------------------
    def safe(self, toks: List[Tok], depth: int = 0) -> Tuple[bool, str]:
        """Is this expression's value safe as HTML text?"""
        if depth > 60:
            return False, "too deep to follow"
        toks = strip_parens(toks)
        if not toks:
            return True, ""
        parts = split_top(toks, (",",))
        if len(parts) > 1:
            return self.safe(parts[-1], depth + 1)
        for op in ("=", "+=", "||=", "??="):
            k = _top_index(toks, op)
            if k is not None:
                return self.safe(toks[k + 1:], depth + 1)
        q = _top_index(toks, "?")
        if q is not None:
            c = _matching_colon(toks, q)
            if c is not None:
                for branch in (toks[q + 1:c], toks[c + 1:]):
                    ok, why = self.safe(branch, depth + 1)
                    if not ok:
                        return ok, why
                return True, ""
        sp = split_top(toks, ("||", "??"))
        if len(sp) > 1:
            for s in sp:
                ok, why = self.safe(s, depth + 1)
                if not ok:
                    return ok, why
            return True, ""
        sp = split_top(toks, ("&&",))
        if len(sp) > 1:
            return self.safe(sp[-1], depth + 1)   # the left side only ever yields a falsy value
        for op in ("===", "!==", "==", "!=", "<", ">", "<=", ">=", "instanceof", "in"):
            if _top_index(toks, op) is not None:
                return True, ""
        if toks[0].text in ("!", "typeof", "delete"):
            return True, ""
        sp = split_top(toks, ("+",))
        if len(sp) > 1:
            for s in sp:
                if s:
                    ok, why = self.safe(s, depth + 1)
                    if not ok:
                        return ok, why
            return True, ""
        for op in ("-", "*", "/", "%", "**", "|", "&", "^", "<<", ">>", ">>>"):
            sp = split_top(toks, (op,))
            if len(sp) > 1 and all(sp):
                return True, ""
        if toks[0].kind == "punct" and toks[0].text in ("-", "+", "~", "++", "--"):
            return True, ""
        if toks[0].kind == "ident" and toks[0].text in ("await", "void"):
            return self.safe(toks[1:], depth + 1)
        return self.safe_operand(toks, depth)

    # The innermost value that made a check fail (the "leaf"), so a
    # finding is reported once, where the unsafe value enters, not at every
    # template that later includes it.
    _leaf = None

    def _memo_store(self, key, ok, why):
        self.memo[key] = ok
        if not ok:
            self.memo_leaf[key] = (self._leaf, why)

    def _memo_hit(self, key, label):
        ok = self.memo[key]
        if ok:
            return True, ""
        leaf, why = self.memo_leaf.get(key, (None, label))
        if self._leaf is None:
            self._leaf = leaf
        return False, why

    def safe_operand(self, toks: List[Tok], depth: int) -> Tuple[bool, str]:
        ok, why = self._safe_operand(toks, depth)
        if not ok and self._leaf is None:
            self._leaf = (toks, why)
        return ok, why

    def _safe_operand(self, toks: List[Tok], depth: int) -> Tuple[bool, str]:
        t0, last = toks[0], toks[-1]
        if len(toks) == 1:
            if t0.kind in ("str", "num", "regex"):
                return True, ""
            if t0.kind == "tpl":
                for e in t0.exprs:
                    ok, why = self.safe(e, depth + 1)
                    if not ok:
                        return ok, why
                return True, ""
            if t0.kind == "ident":
                if t0.text in ("true", "false", "null", "undefined", "NaN", "Infinity"):
                    return True, ""
                return self.safe_ident(t0, depth)
            return False, "data"
        if t0.text == "new" and len(toks) > 1 and toks[1].text in ("Date", "Intl"):
            return True, ""
        if len(toks) >= 3 and toks[-2].text in (".", "?.") and last.kind == "ident" and last.text in SAFE_MEMBERS:
            return True, ""
        if last.text == "]":
            o = _local_open(toks, len(toks) - 1)
            if o:
                if self._constant_map(toks[:o], depth):
                    return True, ""
            return False, "indexed data"
        if last.text == ")":
            o = _local_open(toks, len(toks) - 1)
            if not o:
                return False, "call"
            return self.safe_call(toks[:o], toks[o + 1:-1], depth)
        return False, "data"

    def _constant_map(self, base: List[Tok], depth) -> bool:
        base = strip_parens(base)
        if not base:
            return False
        if base[0].text in ("{", "[") and _local_close(base, 0) == len(base) - 1:
            return self._literal_all_safe(base, depth)
        if len(base) == 1 and base[0].kind == "ident":
            r = self.resolve(base[0].text, base[0])
            if r and r[0] == "decl" and r[1] and all(
                    e and e[0].text in ("{", "[") and _local_close(e, 0) == len(e) - 1 and self._literal_all_safe(e, depth)
                    for e in r[1]):
                return True
        return False

    def _literal_all_safe(self, lit: List[Tok], depth) -> bool:
        for item in split_top(lit[1:-1], (",",)):
            if not item:
                continue
            if lit[0].text == "{":
                kv = split_top(item, (":",))
                if len(kv) < 2:
                    if len(item) == 1 and item[0].kind == "ident":
                        val = item               # { a } shorthand
                    elif item[0].text == "...":
                        return False
                    else:
                        continue                 # method: not a value we index for text
                else:
                    val = item[len(kv[0]) + 1:]
            else:
                val = item
            if not self.safe(val, depth + 1)[0]:
                return False
        return True

    def safe_ident(self, t: Tok, depth: int) -> Tuple[bool, str]:
        key = ("id", t.lst, t.i)
        if key in self.memo:
            return self._memo_hit(key, t.text)
        self.memo[key] = True
        ok, why = self._safe_ident(t, depth)
        self._memo_store(key, ok, why)
        return ok, why

    def _safe_ident(self, t: Tok, depth):
        r = self.resolve(t.text, t)
        if r is None:
            if t.text in self.shared.safe_globals:
                return True, ""
            return False, f"{t.text} is not defined here"
        if r[0] == "param":
            return self.safe_param(r[1], r[2], depth)
        if r[0] == "func":
            return False, f"{t.text} is a function"
        if not r[1]:
            return False, f"{t.text} is never assigned"
        for e in r[1]:
            if e is None:
                return False, f"{t.text} is data"
            ok, why = self.safe(e, depth + 1)
            if not ok:
                return False, f"{t.text} = {why}"
        return True, ""

    def safe_param(self, f: Func, i: int, depth: int) -> Tuple[bool, str]:
        key = ("param", id(f), i)
        if key in self.memo:
            return self._memo_hit(key, "param")
        self.memo[key] = True
        ok, why = self._safe_param(f, i, depth)
        self._memo_store(key, ok, why)
        return ok, why

    def _safe_param(self, f: Func, i: int, depth):
        pname = f.params[i]
        if f.is_callback_of in ("map", "forEach", "flatMap", "filter", "some", "every", "find", "findIndex"):
            if i == 1:
                return True, ""        # the index
            if i == 0:                 # an item of an array the scanner can show is all safe
                T = self.lists[f.lst]
                recv = _operand_before(T, f.decl_index - 4) if f.decl_index >= 4 else []
                if recv and self.safe_array(recv, [], depth + 1)[0]:
                    return True, ""
            return False, f"{pname} is an array item"
        if f.is_callback_of is not None:
            return False, f"{pname} is a {f.is_callback_of} callback argument"
        if not f.name:
            return False, f"{pname} is a parameter of an anonymous function"
        sites = self.call_sites(f.name)
        if not sites:
            return False, f"{pname}: {f.name}() is not called in this file"
        for args in sites:
            if args is None:
                return False, f"{f.name} is passed as a callback"
            if i >= len(args):
                continue
            ok, why = self.safe(args[i], depth + 1)
            if not ok:
                return False, f"{f.name}({pname}) gets {why}"
        return True, ""

    def call_sites(self, name: str) -> List[Optional[List[List[Tok]]]]:
        key = ("sites", name)
        if key in self._sites_cache:
            return self._sites_cache[key]
        out = []
        for toks in self.lists:
            for k, t in enumerate(toks):
                if t.kind != "ident" or t.text != name:
                    continue
                prev = toks[k - 1] if k else None
                nxt = toks[k + 1] if k + 1 < len(toks) else None
                pt, nt = (prev.text if prev else ""), (nxt.text if nxt else "")
                if pt in ("function", "const", "let", "var"):
                    continue
                if pt in (".", "?.") and not (k >= 2 and toks[k - 2].text in ("window", "self", "globalThis")):
                    continue
                if nt == "(":
                    close = _local_close(toks, k + 1)
                    if close is not None:
                        out.append([a for a in split_top(toks[k + 2:close], (",",))] if close > k + 2 else [])
                elif nt in ("=", ":", "(") or pt == "typeof":
                    continue
                elif pt in ("(", ",", "=", "||", "&&", "?", ":") and nt in (")", ",", ";", "}", ":"):
                    out.append(None)
        self._sites_cache[key] = out
        return out

    @property
    def _sites_cache(self):
        if not hasattr(self, "_sc"):
            self._sc = {}
        return self._sc

    def safe_call(self, callee: List[Tok], args: List[Tok], depth: int) -> Tuple[bool, str]:
        callee = strip_parens(callee)
        if callee and callee[-1].text == "?.":
            callee = callee[:-1]
        if len(callee) == 1 and callee[0].kind == "ident":
            name = callee[0].text
            if name in self.escapers or name in SAFE_GLOBAL_CALLS:
                return True, ""
            if name in ("String", "decodeURIComponent", "atob"):
                return self.safe(args, depth + 1) if name == "String" else (False, f"{name}() of data")
            return self.safe_func_call(callee[0], depth)
        if len(callee) >= 3 and callee[-2].text in (".", "?.") and callee[-1].kind == "ident":
            meth, recv = callee[-1].text, callee[:-2]
            rs = [t.text for t in recv]
            if rs in (["Math"], ["Number"], ["Date"]) or rs[-2:] in (["Math", "."],):
                return True, ""
            if rs in (["window"], ["self"], ["globalThis"]):
                if meth in self.escapers:
                    return True, ""
                return self.safe_func_call(callee[-1], depth)
            if rs in (["JSON"],):
                return False, "JSON text"
            if meth in SAFE_METHODS_NUM or meth in ("toLocaleTimeString", "toLocaleDateString", "toISOString",
                                                     "toUTCString", "toDateString", "toTimeString", "format"):
                if meth == "format" and not (recv and recv[0].text == "new"):
                    pass
                else:
                    return True, ""
            if meth == "toLocaleString":
                r = strip_parens(recv)
                if r and (r[0].text in ("new", "Number", "Math") or r[-1].text in SAFE_MEMBERS or
                          (r[-1].text == ")" and self.safe(r, depth + 1)[0])):
                    return True, ""
                return False, "toLocaleString of data"
            if meth == "join":
                return self.safe_array(recv, args, depth)
            if meth in ("trim", "toUpperCase", "toLowerCase", "padStart", "padEnd", "repeat", "trimEnd",
                        "trimStart", "slice", "substring", "substr", "charAt", "toString", "normalize", "at"):
                return self.safe(recv, depth + 1)
            if meth in ("replace", "replaceAll"):
                a = split_top(args, (",",))
                ok, why = self.safe(recv, depth + 1)
                if not ok:
                    return ok, why
                if len(a) == 2:
                    fn = self._inline_func_at(a[1])
                    if fn is not None:
                        return self.safe_func_returns(fn, depth)
                    return self.safe(a[1], depth + 1)
                return False, "replace"
            if meth in ("reduce",):
                a = split_top(args, (",",))
                fn = self._inline_func_at(a[0])
                if fn is not None and len(a) == 2:
                    ok, why = self.safe(a[1], depth + 1)
                    if ok:
                        # accumulator: the callback returns acc + something safe
                        return self.safe_func_returns(fn, depth, skip_params=fn.params[:1])
                return False, "reduce"
            if meth in ("call", "apply", "bind"):
                return self.safe_call(recv, [], depth)
            if meth in ("get", "find", "pop", "shift", "getAttribute", "getItem", "value", "text", "json",
                        "querySelector"):
                return False, f".{meth}() of data"
            return self.safe_func_call(callee[-1], depth)
        if callee and callee[0].kind in ("tpl",) or (callee and callee[0].text == "function"):
            return False, "call"
        # immediately-invoked function: (() => { ... })()
        fn = self._inline_func_at(callee)
        if fn is not None:
            return self.safe_func_returns(fn, depth)
        return False, "call"

    def _inline_func_at(self, toks: List[Tok]) -> Optional[Func]:
        toks = strip_parens(toks)
        if not toks:
            return None
        t = toks[0]
        for f in self.funcs:
            if f.lst == t.lst and f.decl_index == t.i:
                return f
        return None

    def safe_array(self, recv: List[Tok], join_args: List[Tok], depth: int) -> Tuple[bool, str]:
        recv = strip_parens(recv)
        if not recv:
            return False, "join"
        if join_args:
            ok, why = self.safe(join_args, depth + 1)
            if not ok:
                return ok, why
        if recv[0].text == "[" and _local_close(recv, 0) == len(recv) - 1:
            return (True, "") if self._literal_all_safe(recv, depth) else (False, "array item")
        if recv[-1].text == ")":
            o = _local_open(recv, len(recv) - 1)
            if o is not None and o >= 2 and recv[o - 2].text in (".", "?.") and recv[o - 1].kind == "ident":
                meth = recv[o - 1].text
                inner_recv, args = recv[:o - 2], recv[o + 1:-1]
                if meth in ("map", "flatMap"):
                    a0 = split_top(args, (",",))[0]
                    if len(a0) == 1 and a0[0].kind == "ident":
                        if a0[0].text in self.escapers or a0[0].text in SAFE_GLOBAL_CALLS:
                            return True, ""
                        return self.safe_func_call(a0[0], depth)
                    if len(a0) == 3 and a0[0].text in ("window", "self") and a0[2].text in self.escapers:
                        return True, ""
                    fn = self._inline_func_at(a0)
                    if fn is None:
                        return False, "map callback"
                    return self.safe_func_returns(fn, depth)
                if meth in ARRAY_PASS:
                    return self.safe_array(inner_recv, [], depth)
                if meth == "split":
                    return self.safe(inner_recv, depth + 1)
                if meth == "from" and [t.text for t in inner_recv] == ["Array"]:
                    a = split_top(args, (",",))
                    if len(a) == 2:
                        fn = self._inline_func_at(a[1])
                        if fn is not None:
                            return self.safe_func_returns(fn, depth)
                    return False, "Array.from"
                if meth in ("keys",) and [t.text for t in inner_recv] == ["Object"]:
                    return False, "object keys"
                if len(inner_recv) == 0:
                    return self.safe_func_call(recv[o - 1], depth)
            if o is not None and o >= 1 and recv[o - 1].kind == "ident" and (o == 1):
                return self.safe_func_call(recv[0], depth)   # local builder returning an array
            return False, "join of a call"
        if len(recv) == 1 and recv[0].kind == "ident":
            return self.safe_array_var(recv[0], depth)
        return False, "join of data"

    def safe_array_var(self, t: Tok, depth: int) -> Tuple[bool, str]:
        key = ("arr", t.lst, t.i)
        if key in self.memo:
            return self._memo_hit(key, "array")
        self.memo[key] = True
        ok, why = self._safe_array_var(t, depth)
        self._memo_store(key, ok, why)
        return ok, why

    def _safe_array_var(self, t: Tok, depth: int):
        r = self.resolve(t.text, t)
        if not r or r[0] != "decl":
            if r and r[0] == "param":
                f, i = r[1], r[2]
                if f.name and f.is_callback_of is None:
                    sites = self.call_sites(f.name)
                    if sites and all(s is not None for s in sites):
                        for s in sites:
                            if i < len(s):
                                ok, why = self.safe_array(s[i], [], depth + 1)
                                if not ok:
                                    return False, f"{f.name}({f.params[i]}) gets {why}"
                        return True, ""
            return False, f"{t.text} is array data"
        for e in r[1]:
            if e is None:
                return False, f"{t.text} is array data"
            if e and e[0].text == "[" and _local_close(e, 0) == len(e) - 1:
                if not self._literal_all_safe(e, depth):
                    return False, f"{t.text} item"
            else:
                ok, why = self.safe_array(e, [], depth + 1)
                if not ok:
                    return False, f"{t.text}: {why}"
        for p in self._mutations(t):
            for a in split_top(p, (",",)):
                if a and a[0].text == "...":
                    ok, why = self.safe_array(a[1:], [], depth + 1)
                else:
                    ok, why = self.safe(a, depth + 1)
                if not ok:
                    return False, f"{t.text}.push({why})"
        return True, ""

    def _mutations(self, t: Tok) -> List[List[Tok]]:
        """Arguments of name.push(...)/unshift(...)/splice(..) in the enclosing function (any nesting)."""
        fs = self.enclosing_funcs(t)
        scope = fs[0] if fs else None
        out = []
        for lid, T in enumerate(self.lists):
            for k in range(len(T) - 3):
                if T[k].text == t.text and T[k].kind == "ident" and T[k + 1].text == "." and \
                        T[k + 2].text in ("push", "unshift") and T[k + 3].text == "(":
                    if scope is not None and not self._contains(scope, T[k]):
                        continue
                    close = _local_close(T, k + 3)
                    if close:
                        out.append(T[k + 4:close])
        return out

    def safe_func_call(self, name_tok: Tok, depth: int) -> Tuple[bool, str]:
        name = name_tok.text
        if name in self.escapers:
            return True, ""
        r = self.resolve(name, name_tok)
        funcs = r[1] if r and r[0] == "func" else [f for f in self.funcs if f.name == name]
        if not funcs:
            if name in self.shared.safe_funcs:
                return True, ""
            return False, f"{name}() is not defined here"
        key = ("fn", tuple(id(f) for f in funcs))
        if key in self.memo:
            return self._memo_hit(key, f"{name}()")
        self.memo[key] = True
        for f in funcs:
            ok, why = self.safe_func_returns(f, depth)
            if not ok:
                self._memo_store(key, False, f"{name}() returns {why}")
                return False, f"{name}() returns {why}"
        return True, ""

    def safe_func_returns(self, f: Func, depth: int, skip_params=()) -> Tuple[bool, str]:
        T = self.lists[f.lst]
        a, b = f.body
        if f.expr_body:
            toks = T[a:b]
            return self._safe_ret(toks, depth, skip_params)
        nested = [g for g in self.funcs if g is not f and g.lst == f.lst and a <= g.decl_index and g.body[1] <= b]
        for k in range(a, b):
            if T[k].kind == "ident" and T[k].text == "return":
                if any(g.decl_index <= k < g.body[1] for g in nested):
                    continue
                e = T[k + 1:self._expr_end(f.lst, k + 1)]
                if e and self.src.count("\n", T[k].end, e[0].pos) and T[k + 1].text not in ("`", "(", "'", '"'):
                    if not T[k + 1].kind in ("tpl", "str"):
                        e = []   # "return" then newline: ASI returns undefined
                ok, why = self._safe_ret(e, depth, skip_params)
                if not ok:
                    return ok, why
        return True, ""

    def _safe_ret(self, toks, depth, skip_params):
        if skip_params:
            sp = split_top(strip_parens(toks), ("+",))
            toks2 = [s for s in sp if not (len(s) == 1 and s[0].text in skip_params)]
            for s in toks2:
                ok, why = self.safe(s, depth + 1)
                if not ok:
                    return ok, why
            return True, ""
        return self.safe(toks, depth + 1)

    # -- contexts ------------------------------------------------------
    @staticmethod
    def attr_context(before: str) -> Optional[Tuple[str, str, str]]:
        """If the markup before an interpolation leaves us inside an
        attribute value, return (attribute name, quote char or '', value so far)."""
        lt, gt = before.rfind("<"), before.rfind(">")
        if lt < 0 or gt > lt:
            return None
        tag = before[lt:]
        m = None
        for m in re.finditer(r"""([^\s"'<>/=\x00]+)\s*=\s*("[^"]*"?|'[^']*'?|[^\s"'>]*)""", tag):
            pass
        if not m or m.end() != len(tag):
            return None
        val = m.group(2)
        if val and val[0] in "\"'":
            if len(val) == 1 or not val.endswith(val[0]):
                return m.group(1).lower(), val[0], val[1:]
            return None
        return m.group(1).lower(), "", val

    def context_problem(self, attr, expr: List[Tok]) -> Optional[str]:
        name, quote, prefix = attr
        if self.is_numeric(expr):
            return None
        if quote == "":
            return f"unquoted attribute {name}="
        if name.startswith("on"):
            return f"value inside the {name} handler (HTML escaping does not protect JavaScript)"
        if name == "style":
            if self._constant(expr):
                return None
            return "value inside a style attribute"
        if name in URL_ATTRS:
            if re.match(r"^\s*(/[^/]|#|\?|\.|https?:|mailto:)", prefix.replace("\x00", "")) or \
                    (prefix == "" and self._starts_fixed(expr)):
                return None
            if self._constant(expr):
                return None
            if any(t.kind == "ident" and t.text in self.shared.url_sanitizers for t in expr):
                return None
            return f"data at the start of {name}= (the URL scheme is not checked)"
        if not self._constant(expr) and not self._uses(expr, self.full_escapers) and self._uses(expr, self.escapers):
            return f"attribute {name}= escaped without quote escaping"
        return None

    def _constant(self, expr) -> bool:
        """Every leaf is a literal (no data at all)."""
        e = strip_parens(expr)
        if len(e) == 1 and e[0].kind in ("str", "num"):
            return True
        q = _top_index(e, "?")
        if q is not None:
            c = _matching_colon(e, q)
            if c is not None:
                return self._constant(e[q + 1:c]) and self._constant(e[c + 1:])
        if len(e) == 1 and e[0].kind == "tpl":
            return all(self._constant(x) for x in e[0].exprs)
        if len(e) == 1 and e[0].kind == "ident":
            r = self.resolve(e[0].text, e[0])
            if r and r[0] == "decl" and r[1] and all(x is not None and self._constant(x) for x in r[1]):
                return True
            if r and r[0] == "param":
                f, i = r[1], r[2]
                if f.name and f.is_callback_of is None:
                    sites = self.call_sites(f.name)
                    return bool(sites) and all(s is not None for s in sites) and \
                        all(i >= len(s) or self._constant(s[i]) for s in sites)
        if e and e[-1].text == "]":
            o = _local_open(e, len(e) - 1)
            if o:
                base = strip_parens(e[:o])
                if base and base[0].text in ("{", "[") and _local_close(base, 0) == len(base) - 1:
                    return all(self._constant(v) for v in self._literal_values(base))
                if len(base) == 1 and base[0].kind == "ident":
                    r = self.resolve(base[0].text, base[0])
                    if r and r[0] == "decl" and r[1] and all(
                            x and x[0].text in ("{", "[") and _local_close(x, 0) == len(x) - 1 and
                            all(self._constant(v) for v in self._literal_values(x)) for x in r[1]):
                        return True
        return False

    @staticmethod
    def _literal_values(lit):
        out = []
        for item in split_top(lit[1:-1], (",",)):
            if not item:
                continue
            if lit[0].text == "{":
                kv = split_top(item, (":",))
                if len(kv) >= 2:
                    out.append(item[len(kv[0]) + 1:])
                else:
                    out.append([Tok("ident", "?", 0)])
            else:
                out.append(item)
        return out

    def _starts_fixed(self, expr) -> bool:
        e = strip_parens(expr)
        if e and e[0].kind == "tpl" and re.match(r"^(/[^/]|#|\?|https?:|mailto:)", e[0].parts[0]):
            return True
        if e and e[0].kind == "str" and re.match(r"^.(/[^/]|#|\?|https?:|mailto:)", e[0].text):
            return True
        return False

    def is_numeric(self, expr: List[Tok]) -> bool:
        e = strip_parens(expr)
        if len(e) == 1 and e[0].kind == "num":
            return True
        if len(e) >= 3 and e[-1].text in SAFE_MEMBERS and e[-2].text in (".", "?."):
            return True
        if len(e) == 1 and e[0].kind == "ident":
            r = self.resolve(e[0].text, e[0])
            if r and r[0] == "param" and r[1].is_callback_of in ("map", "forEach") and r[2] == 1:
                return True
        if e and e[0].text in ("Math", "Number", "parseInt") and not any(t.kind in ("str", "tpl") for t in e):
            return True
        if any(t.text in ("-", "*", "%") for t in e) and not any(t.kind in ("str", "tpl") for t in e):
            return True
        return False

    @staticmethod
    def _uses(expr, names) -> bool:
        return any(t.kind == "ident" and t.text in names for t in expr)

    # -- driver ------------------------------------------------------
    def report(self, anchor: Tok, expr: List[Tok], why: str):
        if not expr:
            return
        f = Finding(self.name, self.line(expr[0].pos), src_of(expr, self.src), why or "not shown safe",
                    (expr[0].pos, expr[-1].end))
        k = f.span
        if k not in self._seen:
            self._seen.add(k)
            self.findings.append(f)

    def check_value(self, anchor: Tok, expr: List[Tok]):
        self._leaf = None
        ok, why = self.safe(expr)
        if not ok:
            if self._leaf and self._leaf[0]:
                self.report(anchor, self._leaf[0], self._leaf[1])
            else:
                self.report(anchor, expr, why)

    def scan(self) -> List[Finding]:
        for T in self.lists:
            self._scan_list(T)
        # keep the innermost values: a template that is unsafe only because
        # of a value inside it is reported once, at that value
        spans = [f.span for f in self.findings]
        return [f for f in self.findings
                if not any(o != f.span and f.span[0] <= o[0] and o[1] <= f.span[1] for o in spans)]

    def _scan_list(self, T: List[Tok]):
        for k, t in enumerate(T):
            if t.kind == "ident" and t.text in ("innerHTML", "outerHTML") and k + 1 < len(T) and \
                    T[k + 1].text in ("=", "+=") and k and T[k - 1].text in (".", "?."):
                self.check_value(t, T[k + 2:self._stmt_end(T, k + 2)])
            elif t.kind == "ident" and t.text in ("insertAdjacentHTML", "write", "writeln", "createContextualFragment",
                                                  "parseFromString") and \
                    k + 1 < len(T) and T[k + 1].text == "(" and k and T[k - 1].text in (".", "?."):
                if t.text in ("write", "writeln") and not (k >= 2 and T[k - 2].text == "document"):
                    continue
                close = _local_close(T, k + 1)
                args = split_top(T[k + 2:close], (",",))
                val = args[1] if t.text == "insertAdjacentHTML" and len(args) > 1 else args[0]
                self.check_value(t, val)
            elif t.kind == "ident" and t.text == "srcdoc" and k + 1 < len(T) and T[k + 1].text == "=":
                self.check_value(t, T[k + 2:self._stmt_end(T, k + 2)])
            if t.kind == "tpl":
                self._check_template(t)
            if t.kind == "str" and MARKUP.search(t.text):
                if k + 1 < len(T) and T[k + 1].text == "+":
                    self.check_value(t, _operand_after(T, k + 2))
                if k >= 1 and T[k - 1].text == "+":
                    self.check_value(t, _operand_before(T, k - 2))

    def _check_template(self, t: Tok):
        if not MARKUP.search("".join(t.parts)):
            return
        before = ""
        for i, e in enumerate(t.exprs):
            before += t.parts[i]
            self._leaf = None
            ok, why = self.safe(e)
            if not ok:
                if self._leaf and self._leaf[0]:
                    self.report(t, self._leaf[0], self._leaf[1])
                else:
                    self.report(t, e, why)
            else:
                attr = self.attr_context(before)
                if attr:
                    prob = self.context_problem(attr, e)
                    if prob:
                        self.report(t, e, prob)
            before += "\x00"

    def _stmt_end(self, T, a):
        k = a
        while k < len(T):
            x = T[k]
            if x.kind == "punct" and x.text in _OPEN:
                c = _local_close(T, k)
                k = (c if c is not None else len(T) - 1) + 1
                continue
            if x.kind == "punct" and x.text in (")", "]", "}", ";", ","):
                return k
            if k > a and x.kind in ("ident", "str", "tpl", "num") and T[k - 1].kind != "punct" and \
                    x.text not in ("instanceof", "in"):
                return k
            if k > a and x.kind == "ident" and T[k - 1].kind == "punct" and T[k - 1].text in (")", "]") and \
                    self.src.count("\n", T[k - 1].end, x.pos):
                return k
            k += 1
        return k


URL_ATTRS = ("href", "src", "action", "formaction", "xlink:href", "srcdoc", "data", "poster", "background", "ping")


def _top_index(toks, op):
    d = 0
    for k, t in enumerate(toks):
        if t.kind == "punct" and t.text in _OPEN:
            d += 1
        elif t.kind == "punct" and t.text in (")", "]", "}"):
            d -= 1
        elif d == 0 and t.text == op and t.kind in ("punct", "ident"):
            return k
    return None


def _matching_colon(toks, q):
    d, nest = 0, 0
    for k in range(q + 1, len(toks)):
        t = toks[k]
        if t.kind == "punct" and t.text in _OPEN:
            d += 1
        elif t.kind == "punct" and t.text in (")", "]", "}"):
            d -= 1
        elif d == 0 and t.text == "?":
            nest += 1
        elif d == 0 and t.text == ":":
            if nest == 0:
                return k
            nest -= 1
    return None


def _local_open(toks, k):
    d = 0
    for j in range(k, -1, -1):
        t = toks[j]
        if t.kind == "punct" and t.text in (")", "]", "}"):
            d += 1
        elif t.kind == "punct" and t.text in _OPEN:
            d -= 1
            if d == 0:
                return j
    return None


def _local_close(toks, k):
    d = 0
    for j in range(k, len(toks)):
        t = toks[j]
        if t.kind == "punct" and t.text in _OPEN:
            d += 1
        elif t.kind == "punct" and t.text in (")", "]", "}"):
            d -= 1
            if d == 0:
                return j
    return None


def _operand_after(T, a):
    k, start = a, a
    while k < len(T):
        x = T[k]
        if x.kind == "punct" and x.text in _OPEN:
            c = _local_close(T, k)
            k = (c if c is not None else len(T) - 1) + 1
            continue
        if x.kind == "punct" and x.text not in (".", "?."):
            break
        if k > start and x.kind != "punct" and T[k - 1].kind != "punct":
            break
        k += 1
    return T[start:k]


def _operand_before(T, b):
    k, end = b, b + 1
    while k >= 0:
        x = T[k]
        if x.kind == "punct" and x.text in (")", "]", "}"):
            o = _local_open(T[:k + 1], k)
            k = (o if o is not None else 0) - 1
            continue
        if x.kind == "punct" and x.text not in (".", "?."):
            break
        if k < b and x.kind != "punct" and T[k + 1].kind != "punct":
            break
        k -= 1
    return T[k + 1:end]



@dataclass
class Shared:
    escapers: set = field(default_factory=set)
    full_escapers: set = field(default_factory=set)
    safe_funcs: set = field(default_factory=set)
    safe_globals: set = field(default_factory=set)
    member_escapers: set = field(default_factory=set)   # names every file defines only as a full escaper
    url_sanitizers: set = field(default_factory=lambda: {"safeHref", "_safeHref", "safeUrl"})


# ── Sources ───────────────────────────────────────────────────────────

_SCRIPT_RE = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.S | re.I)


def inline_scripts(html: str) -> str:
    """The page's inline scripts at their own offsets (everything else
    blanked, newlines kept), so reported line numbers are the page's."""
    keep = [" " if ch != "\n" else "\n" for ch in html]
    for m in _SCRIPT_RE.finditer(html):
        a, b = m.span(1)
        keep[a:b] = list(html[a:b])
        if a:
            keep[a - 1] = ";"
    return "".join(keep)


def sources() -> List[Tuple[str, str]]:
    """(display name, script text) for every script the app ships."""
    out = []
    for d, pat in (("static", ".js"), ("browser_extension", ".js")):
        full = os.path.join(ROOT, d)
        for f in sorted(os.listdir(full)):
            if f.endswith(pat):
                with open(os.path.join(full, f), encoding="utf-8") as fh:
                    out.append((f"{d}/{f}", fh.read()))
    for d in ("static", "browser_extension"):
        full = os.path.join(ROOT, d)
        for f in sorted(os.listdir(full)):
            if f.endswith(".html"):
                with open(os.path.join(full, f), encoding="utf-8") as fh:
                    html = fh.read()
                if _SCRIPT_RE.search(html):
                    out.append((f"{d}/{f}", inline_scripts(html)))
    return out


def scan_all() -> List[Finding]:
    """Every value in every shipped script that the scanner cannot show is
    safe where it lands (see the module doc)."""
    shared = Shared()
    scans = [FileScan(name, src, shared) for name, src in sources()]

    def top_level(fs):
        return [f for f in fs.funcs if f.lst == 0 and f.name and not any(
            g is not f and g.lst == 0 and g.body[0] <= f.decl_index < g.body[1] for g in fs.funcs)]

    # Top-level escapers (escapeHtml, _bpE, _sfE ...) are globals the pages
    # that load their script call; a name any file defines differently is not.
    defined: Dict[str, bool] = {}
    full: set = set()
    for fs in scans:
        for f in top_level(fs):
            defined[f.name] = defined.get(f.name, True) and f.name in fs.escapers
            if f.name in fs.full_escapers:
                full.add(f.name)
    shared.escapers = {n for n, ok in defined.items() if ok}
    shared.full_escapers = full & shared.escapers
    # A namespace member (FA.E) is an escaper only if every definition of
    # that name, at any depth in any file, is a full escaper.
    anywhere: Dict[str, bool] = {}
    for fs in scans:
        for f in fs.funcs:
            if f.name:
                anywhere[f.name] = anywhere.get(f.name, True) and f.name in fs.full_escapers
    shared.member_escapers = {n for n, ok in anywhere.items() if ok}
    for fs in scans:
        fs.refresh()
    # Helpers one script defines at top level and others call (icons.js's
    # dlpIcon(), index.html's builders the add-ons use): shared as safe only
    # if every top-level definition of the name, in every file, returns
    # something safe. Two rounds, so a helper built on another one settles.
    for _ in range(2):
        verdict: Dict[str, bool] = {}
        for fs in scans:
            for f in top_level(fs):
                verdict[f.name] = verdict.get(f.name, True) and fs.safe_func_returns(f, 0)[0]
        shared.safe_funcs = {n for n, ok in verdict.items() if ok}
        for fs in scans:
            fs.refresh()
    found: List[Finding] = []
    for fs in scans:
        found.extend(fs.scan())
    return found


if __name__ == "__main__":   # pragma: no cover - manual use
    import sys
    fs = scan_all()
    for f in fs:
        if len(sys.argv) < 2 or sys.argv[1] in f.file:
            print(f"{f.file}:{f.line}: {f.reason}: {f.expr[:160]}")
    print(len(fs), "values not shown safe", file=sys.stderr)
