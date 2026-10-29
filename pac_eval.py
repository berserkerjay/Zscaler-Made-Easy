"""A safe PAC evaluator: what a PAC file answers for one URL, without
running JavaScript.

A PAC file is JavaScript (FindProxyForURL(url, host) returns "DIRECT",
"PROXY host:port", ...). Running it would mean running a customer's (or
an attacker's) code inside this app, so this module never does: there is
no JavaScript engine and no eval. It parses the small subset PAC files
use and interprets that subset itself:

* `function FindProxyForURL(url, host) { ... }` and other top-level
  helper functions it calls, top-level `var`/`let`/`const`;
* `var`, assignment (`=`, `+=`), `if` / `else if` / `else`, blocks,
  `return`;
* `&&`, `||`, `!`, `==`, `!=`, `===`, `!==`, `<`, `>`, `<=`, `>=`,
  `+` (string concatenation and numbers), `-`, the ternary `?:`;
* the string methods toLowerCase, toUpperCase, indexOf, lastIndexOf,
  substring, substr, charAt, trim and `.length`;
* the PAC helpers shExpMatch, dnsDomainIs, isPlainHostName,
  localHostOrDomainIs, isInNet, dnsResolve, myIpAddress, dnsDomainLevels,
  isResolvable, and weekdayRange / dateRange / timeRange (which answer
  "unknown": the time of a future request is not known), plus alert
  (ignored).

Anything else (loops, regular expressions, objects, arrays, `new`,
`eval`, any other property or function) is refused in words:
"could not evaluate safely: <construct>". It never falls back to running
code. The source size, nesting depth, steps, undecided branches and CPU
time are capped; a run over a cap is refused the same way.

DNS is never looked up and the device's address is not known. dnsResolve,
isInNet, isResolvable and myIpAddress answer "unknown" unless the caller
injects an answer (`resolve`, `my_ip`) or allows the stated assumption
`dns="assume_public"` (a public host name resolves to a public address,
so isInNet against a private, loopback, link-local or shared range is
false). An `if` on an unknown condition follows both branches: the result
lists each possible answer and what it depends on.

Every answer is classified: DIRECT, Zscaler (a Zscaler cloud gateway, a
Zscaler PAC macro such as ${GATEWAY}, or Client Connector's local
listener) or another proxy.
"""
from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

MAX_SOURCE = 256 * 1024        # characters of PAC source
MAX_TOKENS = 120_000
MAX_DEPTH = 32                 # nesting: blocks, parentheses, calls, unary operators, ternaries
MAX_STEPS = 200_000            # interpreter steps per evaluation (shExpMatch counts its work too)
MAX_SECONDS = 0.5              # CPU-independent wall budget per evaluation
MAX_PATHS = 64                 # branches followed on unknown conditions
MAX_CALL_DEPTH = 16            # helper function calls
MAX_STRING = 64 * 1024         # longest string a concatenation may build
MAX_TRAIL = 20                 # conditions kept for the explanation

PREFIX = "could not evaluate safely: "


class Unsafe(Exception):
    """The PAC uses something outside the evaluated subset, or a cap was
    reached. `construct` names it in words."""

    def __init__(self, construct: str) -> None:
        super().__init__(construct)
        self.construct = construct


# ── Values ─────────────────────────────────────────────────────────────
class _Undefined:
    __slots__ = ()

    def __repr__(self) -> str:
        return "undefined"


UNDEF = _Undefined()


class Unknown:
    """A value this evaluator cannot know (DNS, the device's address, the
    time). `reasons` say why; `options` are the concrete values it can
    take, when they are known (an undecided ternary)."""
    __slots__ = ("reasons", "options")

    def __init__(self, reasons, options: Tuple[Any, ...] = ()) -> None:
        self.reasons = frozenset(reasons)
        self.options = tuple(options)


class PublicAddress:
    """dnsResolve(host) under dns="assume_public": some public address."""
    __slots__ = ("host",)

    def __init__(self, host: str) -> None:
        self.host = host


R_DNS = "DNS resolution of the host name (no lookup is made)"
R_MYIP = "the device's own IP address"
R_TIME = "the day or time of the request"
A_PUBLIC = "the destination is taken to resolve to a public address (no DNS lookup is made)"

_NON_PUBLIC = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
                                                 "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4")]


def _reasons(*vals) -> frozenset:
    out: set = set()
    for v in vals:
        if isinstance(v, Unknown):
            out |= v.reasons
    return frozenset(out)


# ── Tokenizer ──────────────────────────────────────────────────────────
_PUNCT3 = ("===", "!==")
_PUNCT2 = ("==", "!=", "<=", ">=", "&&", "||", "+=", "-=")
_PUNCT1 = set("{}()[];,.?:!<>+-*/%=")
_KEYWORDS = {"var", "let", "const", "function", "if", "else", "return", "true", "false", "null"}
_UNSUPPORTED_WORDS = {"for", "while", "do", "switch", "case", "default", "try", "catch", "finally", "throw", "new", "this",
                      "typeof", "delete", "in", "instanceof", "with", "class", "break", "continue", "void", "yield",
                      "async", "await", "import", "export", "eval", "Function", "arguments", "debugger", "super",
                      "extends", "of", "get", "set", "static"}
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "b": "\b", "f": "\f", "v": "\v", "0": "\0", "'": "'", '"': '"', "\\": "\\", "\n": ""}


def _tokenize(src: str) -> List[Tuple[str, Any, int]]:
    """(kind, value, position) tokens; kind is id, num, str or p. Linear:
    every character is looked at a bounded number of times."""
    toks: List[Tuple[str, Any, int]] = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if c in " \t\r\n\f\v﻿ ":
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = src.find("\n", i)
            i = n if j < 0 else j + 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j < 0:
                raise Unsafe("an unterminated comment")
            i = j + 2
            continue
        if len(toks) > MAX_TOKENS:
            raise Unsafe(f"more than {MAX_TOKENS} tokens")
        if c.isalpha() or c in "_$":
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            toks.append(("id", src[i:j], i))
            i = j
            continue
        if c.isdigit() or (c == "." and i + 1 < n and src[i + 1].isdigit()):
            j = i
            if src.startswith(("0x", "0X"), i):
                j = i + 2
                while j < n and src[j] in "0123456789abcdefABCDEF":
                    j += 1
                toks.append(("num", float(int(src[i + 2:j] or "0", 16)), i))
            else:
                while j < n and (src[j].isdigit() or src[j] == "."):
                    j += 1
                try:
                    toks.append(("num", float(src[i:j]), i))
                except ValueError:
                    raise Unsafe(f"the number '{src[i:j][:20]}'")
            i = j
            continue
        if c in "'\"":
            j, buf = i + 1, []
            while True:
                if j >= n or src[j] == "\n":
                    raise Unsafe("an unterminated string")
                ch = src[j]
                if ch == c:
                    break
                if ch == "\\":
                    if j + 1 >= n:
                        raise Unsafe("an unterminated string")
                    e = src[j + 1]
                    if e in _ESCAPES:
                        buf.append(_ESCAPES[e]); j += 2
                    elif e == "x" and re.fullmatch(r"[0-9a-fA-F]{2}", src[j + 2:j + 4] or ""):
                        buf.append(chr(int(src[j + 2:j + 4], 16))); j += 4
                    elif e == "u" and re.fullmatch(r"[0-9a-fA-F]{4}", src[j + 2:j + 6] or ""):
                        buf.append(chr(int(src[j + 2:j + 6], 16))); j += 6
                    else:
                        buf.append(e); j += 2
                    continue
                buf.append(ch)
                j += 1
            toks.append(("str", "".join(buf), i))
            i = j + 1
            continue
        if c == "`":
            raise Unsafe("a template literal")
        if c == "/":
            prev = toks[-1] if toks else None
            if prev is None or not ((prev[0] == "id" and prev[1] not in ("return", "typeof", "case", "else", "in", "of", "void"))
                                    or prev[0] in ("num", "str") or prev[1] in (")", "]")):
                raise Unsafe("a regular expression")
        three, two = src[i:i + 3], src[i:i + 2]
        if three in _PUNCT3:
            toks.append(("p", three, i)); i += 3
        elif two in _PUNCT2:
            toks.append(("p", two, i)); i += 2
        elif c in _PUNCT1:
            toks.append(("p", c, i)); i += 1
        else:
            raise Unsafe(f"the character {c!r}")
    toks.append(("eof", None, n))
    return toks


# ── Parser ─────────────────────────────────────────────────────────────
# Expressions are tuples: ("lit", v) ("name", n) ("or", [e]) ("and", [e])
# ("arith", e, [(op, e)]) ("not", e) ("neg", e) ("cmp", op, a, b)
# ("cond", c, a, b, (start, end)) ("call", name, [args], line)
# ("meth", obj, name, [args]) ("len", obj).
# Statements: ("var", [(name, e|None)]) ("assign", name, op, e) ("expr", e)
# ("if", [(cond, stmt, (start, end))], else|None) ("block", [s])
# ("return", e|None, line) ("empty",).
_STRING_METHODS = {"toLowerCase", "toUpperCase", "indexOf", "lastIndexOf", "substring", "substr", "charAt", "trim"}


class _Parser:
    def __init__(self, src: str) -> None:
        self.src = src
        self.toks = _tokenize(src)
        self.i = 0
        self.depth = 0

    # helpers
    def peek(self, k: int = 0) -> Tuple[str, Any, int]:
        return self.toks[min(self.i + k, len(self.toks) - 1)]

    def is_p(self, v: str) -> bool:
        t = self.toks[self.i]
        return t[0] == "p" and t[1] == v

    def is_kw(self, v: str) -> bool:
        t = self.toks[self.i]
        return t[0] == "id" and t[1] == v

    def take(self) -> Tuple[str, Any, int]:
        t = self.toks[self.i]
        if t[0] != "eof":
            self.i += 1
        return t

    def expect(self, v: str) -> None:
        t = self.take()
        if not (t[0] == "p" and t[1] == v):
            raise Unsafe(f"unexpected {self._desc(t)} where '{v}' was expected (line {self.line(t[2])})")

    def line(self, pos: int) -> int:
        return self.src.count("\n", 0, pos) + 1

    @staticmethod
    def _desc(t) -> str:
        if t[0] == "eof":
            return "end of file"
        if t[0] == "str":
            return "a string"
        return f"'{str(t[1])[:24]}'"

    def ident(self) -> str:
        t = self.take()
        if t[0] != "id":
            raise Unsafe(f"unexpected {self._desc(t)} where a name was expected (line {self.line(t[2])})")
        self._check_word(t)
        if t[1] in _KEYWORDS:
            raise Unsafe(f"the keyword '{t[1]}' used as a name")
        return t[1]

    def _check_word(self, t) -> None:
        if t[0] == "id" and t[1] in _UNSUPPORTED_WORDS:
            raise Unsafe(f"'{t[1]}' (line {self.line(t[2])})")

    def enter(self) -> None:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise Unsafe(f"nesting deeper than {MAX_DEPTH} levels")

    def leave(self) -> None:
        self.depth -= 1

    # program
    def program(self) -> Dict[str, Any]:
        funcs: Dict[str, Tuple[List[str], List[Any]]] = {}
        top: List[Any] = []
        while self.peek()[0] != "eof":
            if self.is_kw("function"):
                self.take()
                name = self.ident()
                self.expect("(")
                params: List[str] = []
                if not self.is_p(")"):
                    params.append(self.ident())
                    while self.is_p(","):
                        self.take()
                        params.append(self.ident())
                self.expect(")")
                self.enter()
                body = self.block()
                self.leave()
                if name in funcs:
                    raise Unsafe(f"the function '{name}' defined twice")
                funcs[name] = (params, body[1])
            else:
                top.append(self.statement())
        if "FindProxyForURL" not in funcs:
            raise Unsafe("no function FindProxyForURL(url, host)")
        return {"functions": funcs, "top": top}

    def block(self):
        self.expect("{")
        stmts = []
        while not self.is_p("}"):
            if self.peek()[0] == "eof":
                raise Unsafe("a block that is never closed")
            stmts.append(self.statement())
        self.expect("}")
        return ("block", stmts)

    def statement(self):
        t = self.peek()
        self._check_word(t)
        if t[0] == "p" and t[1] == "{":
            self.enter()
            b = self.block()
            self.leave()
            return b
        if t[0] == "p" and t[1] == ";":
            self.take()
            return ("empty",)
        if t[0] == "id" and t[1] in ("var", "let", "const"):
            self.take()
            decls = []
            while True:
                name = self.ident()
                init = None
                if self.is_p("="):
                    self.take()
                    init = self.conditional()
                    if self.is_p("=") or self.is_p("+=") or self.is_p("-="):
                        raise Unsafe(f"an assignment inside an expression (line {self.line(self.peek()[2])})")
                decls.append((name, init))
                if self.is_p(","):
                    self.take()
                    continue
                break
            self.semi()
            return ("var", decls)
        if t[0] == "id" and t[1] == "function":
            raise Unsafe(f"a function defined inside another (line {self.line(t[2])})")
        if t[0] == "id" and t[1] == "if":
            return self.if_chain()
        if t[0] == "id" and t[1] == "else":
            raise Unsafe(f"'else' without 'if' (line {self.line(t[2])})")
        if t[0] == "id" and t[1] == "return":
            self.take()
            line = self.line(t[2])
            if self.is_p(";") or self.is_p("}") or self.peek()[0] == "eof":
                self.semi()
                return ("return", None, line)
            e = self.expression()
            self.semi()
            return ("return", e, line)
        # assignment or expression statement
        if t[0] == "id" and t[1] not in _KEYWORDS and self.peek(1)[0] == "p" and self.peek(1)[1] in ("=", "+=", "-="):
            name = self.ident()
            op = self.take()[1]
            e = self.expression()
            self.semi()
            return ("assign", name, op, e)
        e = self.expression()
        self.semi()
        return ("expr", e)

    def semi(self) -> None:
        # Automatic semicolon insertion, as far as PAC files rely on it.
        if self.is_p(";"):
            self.take()

    def if_chain(self):
        arms, other = [], None
        while True:
            self.take()   # 'if'
            self.expect("(")
            start = self.peek()[2]
            cond = self.expression()
            end = self.peek()[2]
            self.expect(")")
            self.enter()
            body = self.statement()
            self.leave()
            arms.append((cond, body, (start, end)))
            if self.is_kw("else"):
                self.take()
                if self.is_kw("if"):
                    continue
                self.enter()
                other = self.statement()
                self.leave()
            break
        return ("if", arms, other)

    # expressions, lowest precedence first
    def expression(self):
        t = self.peek()
        if t[0] == "p" and t[1] == ",":
            raise Unsafe(f"unexpected ',' (line {self.line(t[2])})")
        e = self.conditional()
        if self.is_p(","):
            raise Unsafe(f"the comma operator (line {self.line(self.peek()[2])})")
        if self.is_p("=") or self.is_p("+=") or self.is_p("-="):
            raise Unsafe(f"an assignment inside an expression (line {self.line(self.peek()[2])})")
        return e

    def conditional(self):
        start = self.peek()[2]
        c = self.logical("||")
        if self.is_p("?"):
            self.take()
            self.enter()
            a = self.conditional()
            self.expect(":")
            b = self.conditional()
            self.leave()
            return ("cond", c, a, b, (start, self.peek()[2]))
        return c

    def logical(self, op: str):
        sub = (lambda: self.logical("&&")) if op == "||" else self.equality
        items = [sub()]
        while self.is_p(op):
            self.take()
            items.append(sub())
        if len(items) == 1:
            return items[0]
        return ("or" if op == "||" else "and", items)

    def equality(self):
        a = self.relational()
        t = self.peek()
        if t[0] == "p" and t[1] in ("==", "!=", "===", "!=="):
            self.take()
            b = self.relational()
            if self.peek()[0] == "p" and self.peek()[1] in ("==", "!=", "===", "!=="):
                raise Unsafe(f"a chained comparison (line {self.line(self.peek()[2])})")
            return ("cmp", t[1], a, b)
        return a

    def relational(self):
        a = self.additive()
        t = self.peek()
        if t[0] == "p" and t[1] in ("<", ">", "<=", ">="):
            self.take()
            b = self.additive()
            if self.peek()[0] == "p" and self.peek()[1] in ("<", ">", "<=", ">="):
                raise Unsafe(f"a chained comparison (line {self.line(self.peek()[2])})")
            return ("cmp", t[1], a, b)
        return a

    def additive(self):
        first = self.multiplicative()
        rest = []
        while self.peek()[0] == "p" and self.peek()[1] in ("+", "-"):
            op = self.take()[1]
            rest.append((op, self.multiplicative()))
        return ("arith", first, rest) if rest else first

    def multiplicative(self):
        first = self.unary()
        rest = []
        while self.peek()[0] == "p" and self.peek()[1] in ("*", "/", "%"):
            op = self.take()[1]
            rest.append((op, self.unary()))
        return ("arith", first, rest) if rest else first

    def unary(self):
        t = self.peek()
        if t[0] == "p" and t[1] in ("!", "-", "+"):
            self.take()
            self.enter()
            e = self.unary()
            self.leave()
            return ("not", e) if t[1] == "!" else ("neg", e) if t[1] == "-" else ("arith", ("lit", 0.0), [("+", e)])
        return self.postfix()

    def args(self) -> List[Any]:
        self.expect("(")
        self.enter()
        out = []
        if not self.is_p(")"):
            out.append(self.conditional())
            while self.is_p(","):
                self.take()
                out.append(self.conditional())
        self.expect(")")
        self.leave()
        return out

    def postfix(self):
        e = self.primary()
        while True:
            t = self.peek()
            if t[0] == "p" and t[1] == ".":
                self.take()
                nt = self.take()
                if nt[0] != "id":
                    raise Unsafe(f"unexpected {self._desc(nt)} after '.' (line {self.line(nt[2])})")
                name = nt[1]
                if name == "length" and not self.is_p("("):
                    e = ("len", e)
                    continue
                if name not in _STRING_METHODS or not self.is_p("("):
                    raise Unsafe(f"the property '{name[:40]}' (line {self.line(nt[2])})")
                e = ("meth", e, name, self.args())
                continue
            if t[0] == "p" and t[1] == "[":
                raise Unsafe(f"an index or array (line {self.line(t[2])})")
            if t[0] == "p" and t[1] == "(":
                raise Unsafe(f"a call of a computed value (line {self.line(t[2])})")
            return e

    def primary(self):
        t = self.take()
        if t[0] == "num":
            return ("lit", t[1])
        if t[0] == "str":
            return ("lit", t[1])
        if t[0] == "p" and t[1] == "(":
            self.enter()
            e = self.expression()
            self.expect(")")
            self.leave()
            return e
        if t[0] == "p" and t[1] in ("[", "{"):
            raise Unsafe(f"an {'array' if t[1] == '[' else 'object'} literal (line {self.line(t[2])})")
        if t[0] == "id":
            self._check_word(t)
            w = t[1]
            if w == "true":
                return ("lit", True)
            if w == "false":
                return ("lit", False)
            if w == "null":
                return ("lit", None)
            if w == "undefined":
                return ("lit", UNDEF)
            if w == "function":
                raise Unsafe(f"a function expression (line {self.line(t[2])})")
            if w in _KEYWORDS:
                raise Unsafe(f"unexpected '{w}' (line {self.line(t[2])})")
            if self.is_p("("):
                return ("call", w, self.args(), self.line(t[2]))
            return ("name", w)
        raise Unsafe(f"unexpected {self._desc(t)} (line {self.line(t[2])})")


_CACHE: Dict[str, Any] = {}
_CACHE_MAX = 16
_CACHE_LOCK = threading.Lock()


def compile_pac(source: str) -> Dict[str, Any]:
    """Parse `source` once (cached by content). Raises Unsafe."""
    if not isinstance(source, str):
        raise Unsafe("a PAC that is not text")
    if len(source) > MAX_SOURCE:
        raise Unsafe(f"a PAC larger than {MAX_SOURCE // 1024} KB")
    key = hashlib.sha256(source.encode("utf-8", "surrogatepass")).hexdigest()
    with _CACHE_LOCK:
        hit = _CACHE.get(key)
    if hit is not None:
        if isinstance(hit, Unsafe):
            raise Unsafe(hit.construct)
        return hit
    try:
        prog = _Parser(source).program()
        prog["source"] = source
        res: Any = prog
    except Unsafe as e:
        res = e
    except RecursionError:
        res = Unsafe(f"nesting deeper than {MAX_DEPTH} levels")
    with _CACHE_LOCK:
        while len(_CACHE) >= _CACHE_MAX:
            _CACHE.pop(next(iter(_CACHE)))
        _CACHE[key] = res
    if isinstance(res, Unsafe):
        raise Unsafe(res.construct)
    return res


# ── Interpreter ────────────────────────────────────────────────────────
def _is_ipv4(s: Any) -> bool:
    if not isinstance(s, str) or not s or len(s) > 15:
        return False
    try:
        ipaddress.IPv4Address(s)
        return True
    except ValueError:
        return False


def _to_str(v: Any) -> str:
    if isinstance(v, str):
        return v
    if v is True:
        return "true"
    if v is False:
        return "false"
    if v is None:
        return "null"
    if v is UNDEF:
        return "undefined"
    if isinstance(v, float):
        if math.isnan(v):
            return "NaN"
        if math.isinf(v):
            return "Infinity" if v > 0 else "-Infinity"
        if v == int(v) and abs(v) < 1e21:
            return str(int(v))
        return repr(v)
    return str(v)


def _to_num(v: Any) -> float:
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, float):
        return v
    if v is None:
        return 0.0
    if v is UNDEF:
        return float("nan")
    if isinstance(v, str):
        s = v.strip()
        if not s:
            return 0.0
        try:
            return float(int(s[2:], 16)) if s[:2].lower() == "0x" else float(s)
        except ValueError:
            return float("nan")
    return float("nan")


def _truthy(v: Any) -> Optional[bool]:
    if isinstance(v, Unknown):
        return None
    if isinstance(v, PublicAddress):
        return True
    if v is None or v is UNDEF or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, float):
        return not (v == 0 or math.isnan(v))
    if isinstance(v, str):
        return v != ""
    return True


def _loose_eq(a: Any, b: Any) -> bool:
    if (a is None or a is UNDEF) and (b is None or b is UNDEF):
        return True
    if a is None or a is UNDEF or b is None or b is UNDEF:
        return False
    if type(a) is type(b):
        return a == b
    return _to_num(a) == _to_num(b)


class _Env:
    __slots__ = ("local", "glob")

    def __init__(self, local: Dict[str, Any], glob: Dict[str, Any]) -> None:
        self.local, self.glob = local, glob

    def copy(self) -> "_Env":
        return _Env(dict(self.local), dict(self.glob))


class _Interp:
    def __init__(self, prog: Dict[str, Any], *, resolve: Optional[Callable[[str], Optional[str]]], my_ip: Optional[str],
                 dns: str, clock: Callable[[], float], max_steps: int, max_seconds: float) -> None:
        self.prog = prog
        self.resolve = resolve
        self.my_ip = my_ip
        self.dns = dns
        self.clock = clock
        self.max_steps = max_steps
        self.max_seconds = max_seconds
        self.start = clock()
        self.steps = 0
        self.paths = 1
        self.calls = 0
        self.assumed: set = set()
        self.trail: List[Dict[str, str]] = []
        self._depth = 0
        self.depends: set = set()

    def tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > self.max_steps:
            raise Unsafe(f"more than {self.max_steps} evaluation steps")
        if self.steps & 1023 < n and self.clock() - self.start > self.max_seconds:
            raise Unsafe(f"more than {self.max_seconds:g} s of evaluation")

    def fork(self) -> None:
        self.paths += 1
        if self.paths > MAX_PATHS:
            raise Unsafe(f"more than {MAX_PATHS} undecided branches (time, DNS or the device's address)")

    def note(self, span: Tuple[int, int], state: Optional[bool]) -> None:
        if len(self.trail) >= MAX_TRAIL:
            return
        text = " ".join(self.prog["source"][span[0]:span[1]].split())
        if len(text) > 120:
            text = text[:117] + "…"
        self.trail.append({"name": text, "state": "match" if state else "unknown" if state is None else "nomatch"})

    # statements: a list of ("ret", value) / ("cont", env) results
    def run(self, stmts: List[Any], env: _Env) -> List[Tuple[str, Any]]:
        results: List[Tuple[str, Any]] = []
        pending: List[Tuple[int, _Env]] = [(0, env)]
        while pending:
            i, env = pending.pop()
            while i < len(stmts):
                self.tick()
                st = stmts[i]
                kind = st[0]
                if kind == "return":
                    results.append(("ret", self.value(st[1], env) if st[1] is not None else UNDEF))
                    break
                if kind in ("if", "block"):
                    outs = self.run_if(st, env) if kind == "if" else self.run(st[1], env)
                    rets = [o for o in outs if o[0] == "ret"]
                    conts = [o[1] for o in outs if o[0] == "cont"]
                    results.extend(rets)
                    if not conts:
                        break
                    for extra in conts[1:]:
                        pending.append((i + 1, extra))
                    env = conts[0]
                    i += 1
                    continue
                if kind == "var":
                    for name, init in st[1]:
                        val = self.value(init, env) if init is not None else UNDEF
                        if init is not None or name not in env.local:
                            env.local[name] = val
                elif kind == "assign":
                    _, name, op, e = st
                    val = self.value(e, env)
                    if op != "=":
                        val = self.binop(op[0], self.lookup(name, env), val)
                    if name in env.local or name not in env.glob:
                        env.local[name] = val
                    else:
                        env.glob[name] = val
                elif kind == "expr":
                    self.value(st[1], env)
                i += 1
            else:
                results.append(("cont", env))
        return results

    def run_if(self, st, env: _Env) -> List[Tuple[str, Any]]:
        _, arms, other = st
        out: List[Tuple[str, Any]] = []
        for cond, body, span in arms:
            v = self.value(cond, env)
            t = _truthy(v)
            self.note(span, t)
            if t is True:
                return out + self.run([body], env)
            if t is None:
                self.fork()
                self.depends |= _reasons(v)
                out += self.run([body], env.copy())
        if other is not None:
            return out + self.run([other], env)
        return out + [("cont", env)]

    def lookup(self, name: str, env: _Env) -> Any:
        if name in env.local:
            return env.local[name]
        if name in env.glob:
            return env.glob[name]
        raise Unsafe(f"the unknown name '{name[:40]}'")

    def binop(self, op: str, a: Any, b: Any) -> Any:
        if isinstance(a, PublicAddress) or isinstance(b, PublicAddress):
            a = Unknown([R_DNS]) if isinstance(a, PublicAddress) else a
            b = Unknown([R_DNS]) if isinstance(b, PublicAddress) else b
        if isinstance(a, Unknown) or isinstance(b, Unknown):
            return Unknown(_reasons(a, b))
        if op == "+":
            if isinstance(a, str) or isinstance(b, str):
                s = _to_str(a) + _to_str(b)
                if len(s) > MAX_STRING:
                    raise Unsafe(f"a string longer than {MAX_STRING // 1024} KB")
                self.tick(len(s) // 4096)
                return s
            return _to_num(a) + _to_num(b)
        x, y = _to_num(a), _to_num(b)
        if op == "-":
            return x - y
        if op == "*":
            return x * y
        if op == "/":
            return x / y if y else (float("nan") if x == 0 or math.isnan(x) else math.copysign(float("inf"), x) * math.copysign(1, y))
        if op == "%":
            return math.fmod(x, y) if y and not math.isinf(x) else float("nan")
        raise Unsafe(f"the operator '{op}'")

    def value(self, e, env: _Env) -> Any:
        self.tick()
        k = e[0]
        if k == "lit":
            return e[1]
        if k == "name":
            return self.lookup(e[1], env)
        if k == "or" or k == "and":
            unknown: List[Any] = []
            want = k == "or"
            last: Any = None
            for item in e[1]:
                v = self.value(item, env)
                t = _truthy(v)
                if t is None:
                    unknown.append(v)
                    continue
                if t is want:
                    if not unknown:
                        return v
                    return want if isinstance(v, bool) else Unknown(_reasons(*unknown))
                last = v
            return Unknown(_reasons(*unknown)) if unknown else last
        if k == "not":
            v = self.value(e[1], env)
            t = _truthy(v)
            return Unknown(_reasons(v) or {R_DNS}) if t is None else not t
        if k == "neg":
            v = self.value(e[1], env)
            return v if isinstance(v, Unknown) else -_to_num(v)
        if k == "arith":
            acc = self.value(e[1], env)
            for op, sub in e[2]:
                acc = self.binop(op, acc, self.value(sub, env))
            return acc
        if k == "cmp":
            return self.compare(e[1], self.value(e[2], env), self.value(e[3], env))
        if k == "cond":
            cv = self.value(e[1], env)
            t = _truthy(cv)
            self.note(e[4], t)
            if t is True:
                return self.value(e[2], env)
            if t is False:
                return self.value(e[3], env)
            a, b = self.value(e[2], env), self.value(e[3], env)
            if not isinstance(a, (Unknown, PublicAddress)) and not isinstance(b, (Unknown, PublicAddress)) and type(a) is type(b) and a == b:
                return a
            self.fork()
            self.depends |= _reasons(cv)
            opts = []
            for v in (a, b):
                opts.extend(v.options if isinstance(v, Unknown) else [] if isinstance(v, PublicAddress) else [v])
            complete = all(not isinstance(v, (Unknown, PublicAddress)) or (isinstance(v, Unknown) and v.options) for v in (a, b))
            return Unknown(_reasons(cv, a, b), tuple(opts) if complete else ())
        if k == "len":
            v = self.value(e[1], env)
            if isinstance(v, Unknown):
                return v
            if isinstance(v, str):
                return float(len(v))
            raise Unsafe("'.length' of a value that is not a string")
        if k == "meth":
            return self.method(self.value(e[1], env), e[2], [self.value(a, env) for a in e[3]])
        if k == "call":
            return self.call(e[1], [self.value(a, env) for a in e[2]], env)
        raise Unsafe(f"the construct '{k}'")

    def compare(self, op: str, a: Any, b: Any) -> Any:
        if isinstance(a, PublicAddress) or isinstance(b, PublicAddress) or isinstance(a, Unknown) or isinstance(b, Unknown):
            return Unknown(_reasons(a, b) or {R_DNS})
        if op == "==":
            return _loose_eq(a, b)
        if op == "!=":
            return not _loose_eq(a, b)
        if op == "===":
            return type(a) is type(b) and a == b and not (isinstance(a, float) and math.isnan(a))
        if op == "!==":
            return not (type(a) is type(b) and a == b and not (isinstance(a, float) and math.isnan(a)))
        if isinstance(a, str) and isinstance(b, str):
            x, y = a, b
        else:
            x, y = _to_num(a), _to_num(b)
            if math.isnan(x) or math.isnan(y):
                return False
        return {"<": x < y, ">": x > y, "<=": x <= y, ">=": x >= y}[op]

    def method(self, obj: Any, name: str, args: List[Any]) -> Any:
        if isinstance(obj, (Unknown, PublicAddress)) or any(isinstance(a, (Unknown, PublicAddress)) for a in args):
            return Unknown(_reasons(obj, *args) or {R_DNS})
        if not isinstance(obj, str):
            raise Unsafe(f"the method '{name}' on a value that is not a string")
        self.tick(len(obj) // 1024)
        a = args + [UNDEF, UNDEF]
        if name == "toLowerCase":
            return obj.lower()
        if name == "toUpperCase":
            return obj.upper()
        if name == "trim":
            return obj.strip()
        if name in ("indexOf", "lastIndexOf"):
            needle = _to_str(a[0])
            if name == "indexOf":
                start = 0 if a[1] is UNDEF else max(0, int(_to_num(a[1]) if not math.isnan(_to_num(a[1])) else 0))
                return float(obj.find(needle, start))
            return float(obj.rfind(needle))
        if name == "charAt":
            i = _to_num(a[0]) if a[0] is not UNDEF else 0.0
            i = 0 if math.isnan(i) else int(i)
            return obj[i] if 0 <= i < len(obj) else ""

        def clamp(v: Any, default: int) -> int:
            if v is UNDEF:
                return default
            x = _to_num(v)
            if math.isnan(x):
                return 0
            return int(max(0, min(len(obj), x)))
        if name == "substring":
            s, t = clamp(a[0], 0), clamp(a[1], len(obj))
            return obj[min(s, t):max(s, t)]
        if name == "substr":
            x = _to_num(a[0]) if a[0] is not UNDEF else 0.0
            x = 0 if math.isnan(x) else int(x)
            if x < 0:
                x = max(0, len(obj) + x)
            ln = len(obj) - x if a[1] is UNDEF else max(0, int(_to_num(a[1]) if not math.isnan(_to_num(a[1])) else 0))
            return obj[x:x + ln]
        raise Unsafe(f"the method '{name}'")

    # PAC helpers and helper functions
    def call(self, name: str, args: List[Any], env: _Env) -> Any:
        a = args + [UNDEF, UNDEF, UNDEF]
        if name in self.prog["functions"]:
            return self.user_call(name, args, env)
        if name == "alert":
            return UNDEF
        if name in ("weekdayRange", "dateRange", "timeRange"):
            return Unknown([R_TIME])
        if name == "myIpAddress":
            if self.my_ip:
                return self.my_ip
            return Unknown([R_MYIP])
        if any(isinstance(x, Unknown) for x in args):
            return Unknown(_reasons(*args))
        if name not in ("isInNet", "dnsResolve", "isResolvable") and any(isinstance(x, PublicAddress) for x in args):
            return Unknown([R_DNS])
        if name == "shExpMatch":
            return self.glob(_to_str(a[0]), _to_str(a[1]))
        if name == "dnsDomainIs":
            h, d = _to_str(a[0]).lower(), _to_str(a[1]).lower()
            return len(h) >= len(d) and h.endswith(d)
        if name == "localHostOrDomainIs":
            h, hd = _to_str(a[0]).lower(), _to_str(a[1]).lower()
            return h == hd or ("." not in h and hd.split(".", 1)[0] == h)
        if name == "isPlainHostName":
            return "." not in _to_str(a[0])
        if name == "dnsDomainLevels":
            return float(_to_str(a[0]).count("."))
        if name == "dnsResolve":
            return self.dns_resolve(a[0])
        if name == "isResolvable":
            r = self.dns_resolve(a[0])
            if isinstance(r, Unknown):
                return r
            return r is not None
        if name == "isInNet":
            return self.is_in_net(a[0], a[1], a[2])
        raise Unsafe(f"the function '{name[:40]}'")

    def user_call(self, name: str, args: List[Any], env: _Env) -> Any:
        self.calls += 1
        if self.calls > 10_000:
            raise Unsafe("more than 10000 function calls")
        depth = self._depth + 1
        if depth > MAX_CALL_DEPTH:
            raise Unsafe(f"function calls nested deeper than {MAX_CALL_DEPTH}")
        params, body = self.prog["functions"][name]
        local = {p: (args[i] if i < len(args) else UNDEF) for i, p in enumerate(params)}
        self._depth = depth
        try:
            outs = self.run(body, _Env(local, env.glob))
        finally:
            self._depth = depth - 1
        vals = [o[1] if o[0] == "ret" else UNDEF for o in outs]
        first = vals[0] if vals else UNDEF
        if all(not isinstance(v, (Unknown, PublicAddress)) and type(v) is type(first) and v == first for v in vals):
            return first
        opts: List[Any] = []
        complete = True
        for v in vals:
            if isinstance(v, Unknown):
                opts.extend(v.options)
                complete = complete and bool(v.options)
            elif isinstance(v, PublicAddress):
                complete = False
            else:
                opts.append(v)
        return Unknown(_reasons(*vals) | self.depends or {R_DNS}, tuple(opts) if complete else ())

    def glob(self, s: str, p: str) -> bool:
        """shExpMatch: * and ? wildcards, every other character literal.
        Iterative; its work counts against the step budget."""
        i = j = 0
        star, mark = -1, 0
        n, m = len(s), len(p)
        work = 0
        while i < n:
            work += 1
            if work & 255 == 0:
                self.tick(256)
            if j < m and (p[j] == "?" or p[j] == s[i]):
                i += 1
                j += 1
            elif j < m and p[j] == "*":
                star, mark = j, i
                j += 1
            elif star != -1:
                j = star + 1
                mark += 1
                i = mark
            else:
                return False
        while j < m and p[j] == "*":
            j += 1
        return j == m

    def dns_resolve(self, h: Any) -> Any:
        if isinstance(h, PublicAddress):
            return h
        s = _to_str(h)
        if _is_ipv4(s):
            return s
        if self.resolve is not None:
            try:
                r = self.resolve(s)
            except Exception:  # noqa: BLE001 — an injected resolver that fails answers "not resolvable"
                r = None
            return r if _is_ipv4(r) else None
        if self.dns == "assume_public" and "." in s:
            self.assumed.add(A_PUBLIC)
            return PublicAddress(s)
        return Unknown([R_DNS])

    def is_in_net(self, h: Any, pattern: Any, mask: Any) -> Any:
        addr = self.dns_resolve(h)
        if isinstance(addr, Unknown):
            return addr
        try:
            net = ipaddress.IPv4Network(f"{_to_str(pattern)}/{_to_str(mask)}", strict=False)
        except ValueError:
            return False
        if isinstance(addr, PublicAddress):
            if any(net.subnet_of(n) for n in _NON_PUBLIC):
                return False
            return Unknown([R_DNS])
        if addr is None:
            return False
        try:
            return ipaddress.IPv4Address(addr) in net
        except ValueError:
            return False


# ── Classification ─────────────────────────────────────────────────────
_ZS_HOST = re.compile(r"(?:^|\.)(?:zscaler|zscalerone|zscalertwo|zscalerthree|zscloud|zscalerten|zscalerbeta|zscalergov)\.net$|(?:^|\.)zscalergov\.us$")
ZSCALER_MACROS = ("GATEWAY", "SECONDARY_GATEWAY", "GATEWAY_FX", "SECONDARY_GATEWAY_FX", "GATEWAY_HOST", "SECONDARY_GATEWAY_HOST",
                  "COUNTRY_GATEWAY", "ZAPP_LOCAL_PROXY", "ZSCALER_LOCAL_PROXY")
_MACRO = re.compile(r"^\$\{([A-Z_]{1,40})\}$")
CLIENT_CONNECTOR_LISTENER = ("127.0.0.1", "9000")   # Client Connector's local proxy (assumed, see module notes)


def proxy_entries(answer: Any) -> List[Dict[str, Any]]:
    """Every entry of one answer ("PROXY a:80; PROXY b:80; DIRECT"):
    [{type, host, port, kind (direct, zscaler, other_proxy, invalid)}]."""
    s = answer if isinstance(answer, str) else _to_str(answer)
    out: List[Dict[str, Any]] = []
    for x in [x.strip() for x in s.split(";") if x.strip()][:50]:
        typ, _, rest = x.partition(" ")
        typ = typ.upper()
        if typ == "DIRECT" and not rest.strip():
            out.append({"type": "DIRECT", "host": None, "port": None, "kind": "direct"})
            continue
        if typ not in ("PROXY", "HTTP", "HTTPS", "SOCKS", "SOCKS4", "SOCKS5") or not rest.strip():
            out.append({"type": typ[:20], "host": None, "port": None, "kind": "invalid"})
            continue
        hp = rest.strip().split()[0]
        if hp.startswith("["):
            host, _, port = hp[1:].partition("]")
            port = port.lstrip(":")
        elif hp.startswith("${"):
            host, _, port = hp.partition("}")
            host += "}"
            port = port.lstrip(":")
        else:
            host, _, port = hp.rpartition(":") if hp.count(":") == 1 else (hp, "", "")
        host = (host if host.startswith("${") else host.lower().rstrip("."))[:200]
        m = _MACRO.match(host.upper())
        zs = (m and m.group(1) in ZSCALER_MACROS) or bool(_ZS_HOST.search(host)) or (host, port) == CLIENT_CONNECTOR_LISTENER
        out.append({"type": typ, "host": host, "port": port[:5] or None, "kind": "zscaler" if zs else "other_proxy"})
    return out


def classify(answer: Any) -> Dict[str, Any]:
    """One FindProxyForURL answer → {result, kind (direct, zscaler,
    other_proxy, invalid), proxy, fallback_direct}. The first entry
    decides; a later DIRECT is a fail-open fallback."""
    s = answer if isinstance(answer, str) else _to_str(answer)
    entries = proxy_entries(s)
    out = {"result": s[:300], "kind": "invalid", "proxy": None, "fallback_direct": False}
    if not entries:
        return out
    first = entries[0]
    out["kind"] = first["kind"]
    out["fallback_direct"] = any(e["kind"] == "direct" for e in entries[1:])
    if first["host"]:
        out["proxy"] = first["host"] + (f":{first['port']}" if first["port"] else "")
    return out


# ── Entry points ───────────────────────────────────────────────────────
def _error(construct: str, steps: int = 0) -> Dict[str, Any]:
    return {"status": "error", "kind": "error", "result": None, "outcomes": [], "depends_on": [], "assumptions": [],
            "trail": [], "error": PREFIX + construct, "steps": steps}


def evaluate(source: str, url: str, host: Optional[str] = None, *, resolve: Optional[Callable[[str], Optional[str]]] = None,
             my_ip: Optional[str] = None, dns: str = "none", clock: Callable[[], float] = time.monotonic,
             max_steps: int = MAX_STEPS, max_seconds: float = MAX_SECONDS) -> Dict[str, Any]:
    """What FindProxyForURL(url, host) answers. Never raises: a PAC
    outside the subset or over a cap is {"status": "error", "error":
    "could not evaluate safely: ..."}. Otherwise status "ok" (one answer)
    or "depends" (the answer depends on DNS, the device's address or the
    time: every possible answer is listed with what it depends on), and
    `kind`: direct, zscaler, other_proxy, invalid, mixed or unknown."""
    try:
        prog = compile_pac(source)
    except Unsafe as e:
        return _error(e.construct)
    url = str(url or "")[:4096]
    if host is None:
        m = re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]{0,20}://([^/?#]{0,300})", url)
        host = (m.group(1) if m else "").rsplit("@", 1)[-1]
        host = host[1:].split("]")[0] if host.startswith("[") else host.split(":")[0]
    host = str(host or "")[:300].lower()
    it = _Interp(prog, resolve=resolve, my_ip=my_ip, dns=dns, clock=clock, max_steps=max_steps, max_seconds=max_seconds)
    try:
        glob: Dict[str, Any] = {}
        env = _Env(glob, glob)
        for st in prog["top"]:
            if st[0] == "return":
                raise Unsafe("a return outside a function")
            outs = it.run([st], env)
            if any(o[0] == "ret" for o in outs) or len(outs) != 1:
                raise Unsafe("a top-level statement whose effect depends on the time, DNS or the device's address")
            env = outs[0][1]
        glob = dict(env.local)
        answer = it.user_call("FindProxyForURL", [url, host], _Env(glob, glob))
    except Unsafe as e:
        return _error(e.construct, it.steps)
    except RecursionError:
        return _error(f"nesting deeper than {MAX_DEPTH} levels", it.steps)
    except Exception as e:  # noqa: BLE001 — fail closed, never a crash and never a fallback to running code
        return _error(f"an internal error ({type(e).__name__})", it.steps)
    depends = sorted(answer.reasons) if isinstance(answer, Unknown) else []
    if isinstance(answer, Unknown) and answer.options:
        values = list(dict.fromkeys(_to_str(v) for v in answer.options))
    elif isinstance(answer, (Unknown, PublicAddress)):
        values = []
    else:
        values = [_to_str(answer)]
    outcomes = [classify(v) for v in values]
    kinds = {o["kind"] for o in outcomes}
    kind = "unknown" if not outcomes else kinds.pop() if len(kinds) == 1 else "mixed"
    status = "ok" if len(outcomes) == 1 and not depends else "depends"
    return {"status": status, "kind": kind, "result": values[0] if status == "ok" else None, "outcomes": outcomes,
            "depends_on": depends, "assumptions": sorted(it.assumed), "trail": it.trail, "error": None, "steps": it.steps}


# ── Static facts for the log analyzer and the tenant read ──────────────
_BYPASS_FNS = ("shExpMatch", "dnsDomainIs", "localHostOrDomainIs", "isInNet", "isPlainHostName")


def inspect(source: str) -> Dict[str, Any]:
    """What a PAC says without evaluating it for a URL, from the same
    parse: {ok, error, returns (each return's literal answer, None when
    computed), direct_rules ([{fn, value, line}]: the helper calls whose
    match leads to a literal DIRECT), calls (helper names used),
    isinnet_on_host (isInNet called on the bare host name)}."""
    try:
        prog = compile_pac(source)
    except Unsafe as e:
        return {"ok": False, "error": PREFIX + e.construct, "returns": [], "direct_rules": [], "calls": [], "isinnet_on_host": False}
    returns: List[Optional[str]] = []
    rules: List[Dict[str, Any]] = []
    calls: set = set()
    flags = {"isinnet_on_host": False}
    budget = [0]

    def returned(stmts) -> List[Any]:
        """The expressions a helper function's body returns (any branch)."""
        out, stack = [], list(stmts)
        while stack and len(out) < 64:
            st = stack.pop()
            if st[0] == "return" and st[1] is not None:
                out.append(st[1])
            elif st[0] == "block":
                stack.extend(st[1])
            elif st[0] == "if":
                stack.extend(body for _c, body, _ in st[1])
                if st[2] is not None:
                    stack.append(st[2])
        return out
    # A condition that calls a helper function (isCorp(host)) is that
    # helper's returned conditions: a DIRECT behind it lists them too.
    helpers = {name: returned(body) for name, (_params, body) in prog["functions"].items() if name != "FindProxyForURL"}

    def lit(e) -> Optional[str]:
        if e is None:
            return None
        if e[0] == "lit" and isinstance(e[1], str):
            return e[1]
        if e[0] == "arith" and all(op == "+" for op, _ in e[2]):
            parts = [lit(e[1])] + [lit(x) for _, x in e[2]]
            return "".join(parts) if all(p is not None for p in parts) else None
        return None

    def is_direct(e) -> bool:
        s = lit(e)
        return s is not None and s.strip().upper() == "DIRECT"

    def conds(e, positive: bool, out: List[Dict[str, Any]]) -> None:
        stack = [(e, positive)]
        expanded: set = set()   # each helper once per condition: a recursive helper never loops
        while stack:
            budget[0] += 1
            if budget[0] > MAX_STEPS:
                return
            x, pos = stack.pop()
            if x is None:
                continue
            k = x[0]
            if k == "not":
                stack.append((x[1], not pos))
            elif k in ("or", "and"):
                stack.extend((y, pos) for y in reversed(x[1]))
            elif k == "call":
                calls.add(x[1])
                if x[1] == "isInNet" and x[2] and x[2][0] == ("name", "host"):
                    flags["isinnet_on_host"] = True
                stack.extend((y, pos) for y in reversed(x[2]))
                if pos and x[1] in _BYPASS_FNS:
                    strings = [a[1] for a in x[2] if a[0] == "lit" and isinstance(a[1], str)]
                    if x[1] == "isPlainHostName":
                        out.append({"fn": x[1], "value": "", "line": x[3]})
                    elif strings:
                        out.append({"fn": x[1], "value": strings[0], "line": x[3]})
                if pos and x[1] in helpers and x[1] not in expanded:
                    expanded.add(x[1])
                    stack.extend((y, pos) for y in reversed(helpers[x[1]]))
            elif k == "cmp":
                stack.extend([(x[2], pos), (x[3], pos)])
            elif k == "arith":
                stack.append((x[1], pos))
                stack.extend((y, pos) for _, y in x[2])
            elif k in ("neg", "len"):
                stack.append((x[1], pos))
            elif k == "meth":
                stack.append((x[1], pos))
                stack.extend((y, pos) for y in x[3])
            elif k == "cond":
                stack.extend([(x[1], pos), (x[2], pos), (x[3], pos)])

    def walk(stmts, guards) -> None:
        stack = [(s, guards) for s in reversed(stmts)]
        while stack:
            budget[0] += 1
            if budget[0] > MAX_STEPS:
                return
            st, g = stack.pop()
            k = st[0]
            if k == "block":
                stack.extend((s, g) for s in reversed(st[1]))
            elif k == "if":
                if st[2] is not None:
                    stack.append((st[2], g))
                for cond, body, _ in reversed(st[1]):
                    conds(cond, False, [])   # calls inventory only
                    stack.append((body, g + [cond]))
            elif k == "return":
                e = st[1]
                if e is None or e[0] != "cond":
                    returns.append(lit(e))
                if e is not None and e[0] == "cond":
                    conds(e[1], False, [])
                    for arm, pos in ((e[2], True), (e[3], False)):
                        returns.append(lit(arm))
                        if is_direct(arm):
                            found: List[Dict[str, Any]] = []
                            for c in g:
                                conds(c, True, found)
                            conds(e[1], pos, found)
                            rules.extend(found)
                elif is_direct(e):
                    for c in g:
                        conds(c, True, rules)
                elif e is not None:
                    conds(e, False, [])
            elif k in ("var",):
                for _, init in st[1]:
                    conds(init, False, [])
            elif k in ("assign",):
                conds(st[3], False, [])
            elif k == "expr":
                conds(st[1], False, [])

    walk(prog["top"], [])
    for name, (_params, body) in sorted(prog["functions"].items(), key=lambda kv: kv[0] == "FindProxyForURL"):
        walk(body, [])
    seen, uniq = set(), []
    for r in rules:
        key = (r["fn"], r["value"])
        if key not in seen:
            seen.add(key)
            uniq.append(r)
    return {"ok": True, "error": None, "returns": returns, "direct_rules": uniq, "calls": sorted(calls),
            "isinnet_on_host": flags["isinnet_on_host"]}


def direct_hosts(source: str) -> List[str]:
    """Host and network patterns whose match the PAC answers DIRECT, from
    inspect(): the tenant read keeps them next to each PAC file."""
    info = inspect(source) if source else {"direct_rules": []}
    return sorted({r["value"] for r in info["direct_rules"] if r["fn"] != "isPlainHostName" and r["value"]})


# ── The Path analyzer's PAC hop ────────────────────────────────────────
_KIND_WORDS = {"direct": "DIRECT (no Zscaler)", "zscaler": "Zscaler", "other_proxy": "another proxy, not Zscaler",
               "invalid": "an answer browsers do not understand"}


# The PAC answer as the shared hop's verdict: to Zscaler is forwarded;
# DIRECT or another proxy bypasses Zscaler; branches that differ are
# conditional; anything else is unknown.
_PAC_VERDICT = {"zscaler": "forwarded", "direct": "bypassed", "other_proxy": "bypassed", "mixed": "conditional"}


def path_hop(pacs: List[Dict[str, Any]], host: str, url: str) -> Optional[Dict[str, Any]]:
    """The PAC hop of a traced path: each linked PAC file (with its
    `source`) evaluated for `url`. None when no linked file has its source
    (the caller keeps its static check). Returns {status (bypass, warn,
    pass, unknown), decided_by, detail, weak_point, evaluation, module_hop}
    where module_hop is the PAC step in the one hop shape every Path
    analyzer module shares (zia_path_modules.module_hop, rendered by
    static/path_modules.js): the file is the rule, each condition it
    tested a criterion, and the answer the verdict (forwarded to Zscaler,
    bypassed, conditional or unknown)."""
    out = _path_hop(pacs, host, url)
    if out is not None:
        out["module_hop"]["detail"] = out["detail"]
    return out


def _path_hop(pacs: List[Dict[str, Any]], host: str, url: str) -> Optional[Dict[str, Any]]:
    from zia_path_modules import module_hop
    usable = [f for f in pacs if isinstance(f.get("source"), str) and f.get("source")]
    if not usable or not host:
        return None
    is_ip = _is_ipv4(host)
    f = usable[0]
    name = str(f.get("name") or f.get("id") or "PAC file")
    ev = evaluate(f["source"], url, host, dns="none" if is_ip else "assume_public")
    notes = list(ev.get("assumptions") or []) + [f"Depends on {r}." for r in ev.get("depends_on") or []]
    if len(usable) > 1:
        notes.append(f"{len(usable)} PAC files share this URL; the first, '{name}', was evaluated.")
    verdict = _PAC_VERDICT.get(ev["kind"], "unknown")
    if ev["status"] == "error":
        notes = [ev["error"]] + notes
    view = module_hop("PAC file", verdict, {"name": name, "order": None}, key="pac", criteria=ev.get("trail") or [], notes=notes)
    by = {"name": name, "id": f.get("id")}
    if ev["status"] == "error":
        return {"status": "error", "decided_by": None, "evaluation": ev, "module_hop": view,
                "detail": f"PAC '{name}' {ev['error']}. Only its literal DIRECT patterns were checked; nothing in it was run."}
    outs = ev["outcomes"]
    shown = "; ".join(f"'{o['result']}' ({_KIND_WORDS.get(o['kind'], o['kind'])})" for o in outs[:4]) or "an answer that cannot be known in advance"
    if ev["status"] == "ok":
        o = outs[0]
        if o["kind"] in ("direct", "other_proxy"):
            what = "returns DIRECT" if o["kind"] == "direct" else f"sends it to another proxy ({o['proxy']}), not Zscaler"
            return {"status": "bypass", "decided_by": by, "evaluation": ev, "module_hop": view,
                    "detail": f"PAC '{name}' {what} for {host} (evaluated: '{o['result']}'): the browser connects without Zscaler.",
                    "weak_point": {"severity": "high", "title": "PAC sends this destination around Zscaler",
                                   "fix": "Remove the DIRECT (or other-proxy) clause or narrow it; Zscaler recommends returning the ZIA proxy for everything except RFC1918 and explicit local hosts."}}
        if o["kind"] == "zscaler":
            tail = " If every listed gateway is unreachable it falls back to DIRECT (fail-open)." if o["fallback_direct"] else ""
            return {"status": "pass", "decided_by": by, "evaluation": ev, "module_hop": view,
                    "detail": f"PAC '{name}' answers '{o['result']}' for {host}: the browser sends it to Zscaler.{tail}"
                              + (" Assumed: " + "; ".join(ev["assumptions"]) + "." if ev["assumptions"] else "")}
        return {"status": "unknown", "decided_by": by, "evaluation": ev, "module_hop": view,
                "detail": f"PAC '{name}' answers '{o['result']}' for {host}, which is not a valid proxy answer; browsers usually go direct."}
    deps = ", ".join(ev["depends_on"]) or "values this app cannot know"
    if ev["kind"] == "zscaler":
        return {"status": "pass", "decided_by": by, "evaluation": ev, "module_hop": view,
                "detail": f"PAC '{name}' sends {host} to Zscaler whatever {deps} turns out to be: {shown}."}
    return {"status": "warn", "decided_by": by, "evaluation": ev, "module_hop": view,
            "detail": f"PAC '{name}' answers differently for {host} depending on {deps}: {shown}. On the answers that are not Zscaler the browser connects without it.",
            "weak_point": {"severity": "medium", "title": "PAC answer depends on the device or the time",
                           "fix": "Make the PAC send this destination to Zscaler on every branch, or move the location logic to the Forwarding Profile's trusted-network criteria."}}
