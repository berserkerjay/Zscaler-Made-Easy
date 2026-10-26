"""A strict parser for the HCL native syntax subset Terraform files use.

Raises HCLError on anything HCL would refuse: unbalanced brackets, a
newline inside a quoted string, an unknown escape, an unterminated
template sequence, a missing `=`, two attributes on one line, a bad
expression. Returns the interpolations (expression text) and directives
found in every quoted template, so a caller can check that no tenant
text became live Terraform.
"""
from __future__ import annotations

import re
from typing import List, Tuple

__all__ = ["HCLError", "parse", "string_value"]


class HCLError(ValueError):
    pass


_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_\-]*")
_NUMBER = re.compile(r"\d+(\.\d+)?([eE][+-]?\d+)?")
_OPS = ("==", "!=", ">=", "<=", "&&", "||", "=>", "...", "?", ":", "+", "-", "*", "/", "%", ">", "<", "!", ".", ",", "=")


class _Tok:
    __slots__ = ("kind", "val", "line", "parts")

    def __init__(self, kind, val, line, parts=None):
        self.kind, self.val, self.line, self.parts = kind, val, line, parts

    def __repr__(self):
        return f"{self.kind}:{self.val!r}@{self.line}"


class _Lexer:
    def __init__(self, text: str):
        self.s = text
        self.i = 0
        self.line = 1
        self.interps: List[str] = []
        self.directives: List[str] = []

    def err(self, msg):
        raise HCLError(f"line {self.line}: {msg}")

    def tokens(self, stop_at_close_brace=False) -> List[_Tok]:
        out: List[_Tok] = []
        depth = 0
        s = self.s
        while self.i < len(s):
            c = s[self.i]
            if c == "\n":
                out.append(_Tok("NL", "\n", self.line))
                self.line += 1
                self.i += 1
            elif c in " \t\r":
                self.i += 1
            elif c == "#" or s.startswith("//", self.i):
                while self.i < len(s) and s[self.i] != "\n":
                    self.i += 1
            elif s.startswith("/*", self.i):
                j = s.find("*/", self.i + 2)
                if j < 0:
                    self.err("unterminated /* comment")
                self.line += s.count("\n", self.i, j)
                self.i = j + 2
            elif c == '"':
                out.append(self.quoted())
            elif s.startswith("<<", self.i) and re.match(r"<<-?[A-Za-z_]\w*\n", s[self.i:]):
                out.append(self.heredoc())
            elif c in "{[(":
                depth += 1 if c == "{" else 0
                out.append(_Tok(c, c, self.line))
                self.i += 1
            elif c in "}])":
                if c == "}" and stop_at_close_brace and depth == 0:
                    return out
                depth -= 1 if c == "}" else 0
                out.append(_Tok(c, c, self.line))
                self.i += 1
            else:
                m = _IDENT.match(s, self.i)
                if m:
                    out.append(_Tok("ID", m.group(), self.line))
                    self.i = m.end()
                    continue
                m = _NUMBER.match(s, self.i)
                if m:
                    out.append(_Tok("NUM", m.group(), self.line))
                    self.i = m.end()
                    continue
                for op in _OPS:
                    if s.startswith(op, self.i):
                        out.append(_Tok("OP", op, self.line))
                        self.i += len(op)
                        break
                else:
                    self.err(f"unexpected character {c!r}")
        if stop_at_close_brace:
            self.err("unterminated template interpolation")
        return out

    def _template_seq(self, kind: str):
        """At `${` or `%{`: lex the inner expression up to the matching `}`."""
        start = self.i + 2
        self.i = start
        if self.i < len(self.s) and self.s[self.i] == "~":
            self.i += 1
        inner_start = self.i
        sub = _Lexer.__new__(_Lexer)
        sub.s, sub.i, sub.line, sub.interps, sub.directives = self.s, self.i, self.line, self.interps, self.directives
        toks = sub.tokens(stop_at_close_brace=True)
        inner = self.s[inner_start:sub.i].rstrip("~").strip()
        self.i = sub.i + 1
        self.line = sub.line
        if kind == "$":
            if not toks:
                self.err("empty interpolation")
            _Parser(toks + [_Tok("EOF", "", self.line)], self).expr_only()
            self.interps.append(inner)
        else:
            self.directives.append(inner)
        return inner

    def quoted(self) -> _Tok:
        s = self.s
        line = self.line
        self.i += 1
        buf = []
        parts = []
        while True:
            if self.i >= len(s):
                self.err("unterminated string")
            c = s[self.i]
            if c == "\n":
                self.err("newline inside a quoted string")
            if c == '"':
                self.i += 1
                break
            if c == "\\":
                n = s[self.i + 1:self.i + 2]
                if n in ('"', "\\"):
                    buf.append(n)
                    self.i += 2
                elif n in "ntr":
                    buf.append({"n": "\n", "t": "\t", "r": "\r"}[n])
                    self.i += 2
                elif n == "u" and re.fullmatch(r"[0-9A-Fa-f]{4}", s[self.i + 2:self.i + 6]):
                    buf.append(chr(int(s[self.i + 2:self.i + 6], 16)))
                    self.i += 6
                elif n == "U" and re.fullmatch(r"[0-9A-Fa-f]{8}", s[self.i + 2:self.i + 10]):
                    buf.append(chr(int(s[self.i + 2:self.i + 10], 16)))
                    self.i += 10
                else:
                    self.err(f"invalid escape \\{n}")
                continue
            if s.startswith("$${", self.i) or s.startswith("%%{", self.i):
                buf.append(s[self.i + 1:self.i + 3])
                self.i += 3
                continue
            if s.startswith("${", self.i) or s.startswith("%{", self.i):
                parts.append(("lit", "".join(buf)))
                buf = []
                inner = self._template_seq(c)
                parts.append(("interp" if c == "$" else "directive", inner))
                continue
            buf.append(c)
            self.i += 1
        parts.append(("lit", "".join(buf)))
        return _Tok("STR", "".join(p[1] if p[0] == "lit" else "\0" for p in parts), line, parts)

    def heredoc(self) -> _Tok:
        m = re.match(r"<<(-?)([A-Za-z_]\w*)\n", self.s[self.i:])
        marker = m.group(2)
        self.i += m.end()
        line = self.line
        self.line += 1
        while True:
            j = self.s.find("\n", self.i)
            if j < 0:
                self.err("unterminated heredoc")
            text = self.s[self.i:j]
            self.i = j + 1
            self.line += 1
            if text.strip() == marker:
                self.i -= 1
                self.line -= 1
                break
        return _Tok("STR", "", line, [("lit", "")])


class _Parser:
    def __init__(self, toks: List[_Tok], lx: _Lexer):
        self.t = toks
        self.p = 0
        self.lx = lx

    def peek(self, skip_nl=False):
        p = self.p
        while skip_nl and self.t[p].kind == "NL":
            p += 1
        return self.t[p]

    def next(self):
        tok = self.t[self.p]
        self.p += 1
        return tok

    def err(self, msg, tok=None):
        tok = tok or self.peek()
        raise HCLError(f"line {tok.line}: {msg} (at {tok!r})")

    def skip_nl(self):
        while self.peek().kind == "NL":
            self.p += 1

    def expect(self, kind, val=None):
        tok = self.next()
        if tok.kind != kind or (val is not None and tok.val != val):
            self.err(f"expected {val or kind}", tok)
        return tok

    # body := (attribute | block)*
    def body(self, top=True):
        seen = set()
        while True:
            self.skip_nl()
            tok = self.peek()
            if tok.kind == "EOF":
                if not top:
                    self.err("unexpected end of file inside a block")
                return
            if tok.kind == "}":
                if top:
                    self.err("unbalanced }")
                return
            name = self.expect("ID")
            nxt = self.peek()
            if nxt.kind == "OP" and nxt.val == "=":
                self.next()
                if name.val in seen:
                    self.err(f"duplicate attribute {name.val}", name)
                seen.add(name.val)
                self.expr()
                end = self.next()
                if end.kind == "}":
                    self.p -= 1
                    self.err("a block's closing brace must be on its own line", end)
                if end.kind not in ("NL", "EOF"):
                    self.err("attribute must end at a newline", end)
                if end.kind == "EOF":
                    self.p -= 1
            else:
                while self.peek().kind in ("STR", "ID"):
                    lab = self.next()
                    if lab.kind == "STR" and any(k != "lit" for k, _ in lab.parts):
                        self.err("a block label cannot be a template", lab)
                self.expect("{")
                if self.peek().kind != "NL":
                    # single-line block: name { attr = expr }
                    if self.peek().kind != "}":
                        self.expect("ID")
                        self.expect("OP", "=")
                        self.expr()
                    self.expect("}")
                else:
                    self.body(top=False)
                    self.expect("}")
                end = self.peek()
                if end.kind not in ("NL", "EOF"):
                    self.err("block must end at a newline", end)

    def expr_only(self):
        self.skip_nl()
        self.expr()
        self.skip_nl()
        if self.peek().kind != "EOF":
            self.err("trailing tokens in interpolation")

    # expression grammar (precedence climbing)
    _BIN = [("||",), ("&&",), ("==", "!="), (">", ">=", "<", "<="), ("+", "-"), ("*", "/", "%")]

    def expr(self):
        self.binary(0)
        tok = self.peek()
        if tok.kind == "OP" and tok.val == "?":
            self.next()
            self.skip_nl()
            self.expr()
            self.skip_nl()
            self.expect("OP", ":")
            self.skip_nl()
            self.expr()

    def binary(self, lvl):
        if lvl == len(self._BIN):
            return self.unary()
        self.binary(lvl + 1)
        while self.peek().kind == "OP" and self.peek().val in self._BIN[lvl]:
            self.next()
            self.skip_nl()
            self.binary(lvl + 1)

    def unary(self):
        tok = self.peek()
        if tok.kind == "OP" and tok.val in ("!", "-"):
            self.next()
            return self.unary()
        self.postfix()

    def postfix(self):
        self.primary()
        while True:
            tok = self.peek()
            if tok.kind == "OP" and tok.val == ".":
                self.next()
                n = self.next()
                if n.kind not in ("ID", "NUM") and not (n.kind == "OP" and n.val == "*"):
                    self.err("expected attribute name after .", n)
            elif tok.kind == "[":
                self.next()
                self.skip_nl()
                self.expr()
                self.skip_nl()
                self.expect("]")
            else:
                return

    def for_expr(self, close):
        self.expect("ID", "for")
        self.expect("ID")
        if self.peek().kind == "OP" and self.peek().val == ",":
            self.next()
            self.expect("ID")
        self.expect("ID", "in")
        self.expr()
        self.expect("OP", ":")
        self.skip_nl()
        self.expr()
        if close == "}":
            self.expect("OP", "=>")
            self.expr()
            if self.peek().kind == "OP" and self.peek().val == "...":
                self.next()
        self.skip_nl()
        if self.peek().kind == "ID" and self.peek().val == "if":
            self.next()
            self.expr()
        self.skip_nl()
        self.expect(close)

    def primary(self):
        tok = self.next()
        if tok.kind in ("NUM", "STR"):
            return
        if tok.kind == "ID":
            if self.peek().kind == "(":
                self.next()
                self.skip_nl()
                if self.peek().kind != ")":
                    while True:
                        self.skip_nl()
                        self.expr()
                        self.skip_nl()
                        if self.peek().kind == "OP" and self.peek().val == "...":
                            self.next()
                            self.skip_nl()
                        if self.peek().kind == "OP" and self.peek().val == ",":
                            self.next()
                            self.skip_nl()
                            if self.peek().kind == ")":
                                break
                            continue
                        break
                self.expect(")")
            return
        if tok.kind == "(":
            self.skip_nl()
            self.expr()
            self.skip_nl()
            self.expect(")")
            return
        if tok.kind == "[":
            self.skip_nl()
            if self.peek().kind == "ID" and self.peek().val == "for":
                self.for_expr("]")
                return
            while self.peek().kind != "]":
                self.expr()
                self.skip_nl()
                if self.peek().kind == "OP" and self.peek().val == ",":
                    self.next()
                    self.skip_nl()
                elif self.peek().kind != "]":
                    self.err("expected , or ] in a list")
            self.expect("]")
            return
        if tok.kind == "{":
            self.skip_nl()
            if self.peek().kind == "ID" and self.peek().val == "for":
                self.for_expr("}")
                return
            while self.peek().kind != "}":
                self.expr()
                op = self.next()
                if not (op.kind == "OP" and op.val in ("=", ":")):
                    self.err("expected = in an object", op)
                self.skip_nl()
                self.expr()
                if self.peek().kind == "OP" and self.peek().val == ",":
                    self.next()
                self.skip_nl()
            self.expect("}")
            return
        self.err("expected an expression", tok)


def parse(text: str) -> Tuple[List[str], List[str]]:
    """Parse `text`; return (interpolations, directives) found in strings."""
    lx = _Lexer(text)
    toks = lx.tokens() + [_Tok("EOF", "", lx.line)]
    _Parser(toks, lx).body(top=True)
    return lx.interps, lx.directives


def string_value(literal: str) -> str:
    """The value of one quoted HCL string literal with no interpolation."""
    lx = _Lexer(literal)
    tok = lx.quoted()
    if lx.interps or lx.directives:
        raise HCLError(f"live template sequence in {literal!r}")
    return tok.val
