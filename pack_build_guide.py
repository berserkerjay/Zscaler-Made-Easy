"""Word build guide for a DLP policy pack, in one fixed format.

`build(pack_id)` reads one pack (a shipped pack or one uploaded through the
pack library) from its pack.json and configs/dlp_*.json and returns a .docx
that walks a person through building the pack by hand in the Zscaler
console: dictionaries, engines and rules, each with a mock-up of the console
form to copy from. It reads local files only; it never touches a tenant and
changes nothing.

The format is the owner's template: cover, summary, engine alignment table,
the Step-by-Step Instructions (steps 1 to 8), assumptions and sign-off. A
field you type has a thick blue outline in the mock-ups; a field the page
fills in itself has a thin grey one.

Engine expressions (`D:name > n` terms joined by AND / OR / NOT and nested
parentheses) are parsed into a tree (`parse_expression`); the tree draws the
Engine Builder mock-up, the Expression Preview and the plain-language
"Engine logic" column, and `render_expression` writes it back to text.
"""
from __future__ import annotations

import datetime as _dt
import importlib.util
import io
import json
import os
import random
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Pt, RGBColor, Twips

ROOT = os.path.dirname(os.path.abspath(__file__))

# ── Limits ───────────────────────────────────────────────────────────
MAX_PARAM = 80            # prepared_for / prepared_by are cut to this many characters
MAX_DEPTH = 60            # an expression nested deeper than this is not drawn as a tree
MAX_EXPR_CHARS = 16384    # as the pack library: a longer expression is shown as text only

# ── Palette and type (the template's) ────────────────────────────────
FONT, MONO = "Arial", "Consolas"
BLUE, NAVY, GREY, LIGHT, LINE, HEAD = "1A56DB", "0B1F44", "6B7280", "F3F4F6", "C9CED6", "E8EEF8"
W = 9360                  # text width in twips (Letter, 1 inch side margins)
FIXED_DATE = _dt.datetime(2026, 1, 1)   # document properties never change between builds


class GuideError(ValueError):
    """The pack cannot be found or read."""


# ═══════════════════════════════════════════════════════════════════════
# Engine expressions
# ═══════════════════════════════════════════════════════════════════════

class ExprError(ValueError):
    """The text is not an engine expression this module can draw."""


@dataclass
class Term:
    name: str
    op: str
    n: int


@dataclass
class Op:
    op: str                       # "AND" or "OR"
    items: List[Any]


@dataclass
class Sum:
    """(D:a + D:b + ...) > n: the matches of several dictionaries added together."""
    names: List[str]
    op: str
    n: int


@dataclass
class Not:
    item: Any


@dataclass
class Group:
    """One pair of parentheses, kept so the text can be written back as it was."""
    item: Any


_SUM = re.compile(r"\(\s*D:(?P<body>[^\n]+?)\s*\)\s*(?P<op>>=|<=|>|<|=)\s*(?P<n>\d+)")
_TERM = re.compile(r"D:(?P<name>[^\n]+?)\s*(?P<op>>=|<=|>|<|=)\s*(?P<n>\d+)")
_WORD = re.compile(r"(AND|OR|NOT)\b", re.I)


def _tokens(text: str) -> List[Tuple[str, Any]]:
    out: List[Tuple[str, Any]] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c.isspace():
            i += 1
        elif c == "(" and (ms := _SUM.match(text, i)) and re.search(r"\s\+\s*D:", ms.group("body")) \
                and not re.search(r"\s(?:AND|OR)\s|\s(?:>=|<=|>|<|=)\s*\d", ms.group("body")):
            names = [x.strip() for x in re.split(r"\s*\+\s*D:", ms.group("body"))]
            out.append(("term", Sum(names, ms.group("op"), int(ms.group("n")))))
            i = ms.end()
        elif c in "()":
            out.append((c, c))
            i += 1
        elif text.startswith("D:", i):
            m = _TERM.match(text, i)
            if not m or re.search(r"\bD:|\)\s*(?:AND|OR)\b|\s(?:AND|OR)\s+\(", m.group("name")):
                raise ExprError(f"a dictionary term is not closed with > n at character {i}")
            out.append(("term", Term(m.group("name").strip(), m.group("op"), int(m.group("n")))))
            i = m.end()
        else:
            m = _WORD.match(text, i)
            if not m:
                raise ExprError(f"unexpected text at character {i}")
            out.append((m.group(1).upper(), m.group(1).upper()))
            i = m.end()
    return out


def parse_expression(text: str) -> Any:
    """The tree of an engine expression: Term, Op (AND / OR), Not and Group
    (one pair of parentheses). AND binds tighter than OR, NOT tighter than
    both. Raises ExprError on anything else."""
    text = str(text or "")
    if not text.strip():
        raise ExprError("the expression is empty")
    if len(text) > MAX_EXPR_CHARS:
        raise ExprError("the expression is too long to draw")
    toks = _tokens(text)
    pos = [0]

    def peek():
        return toks[pos[0]][0] if pos[0] < len(toks) else None

    def take(kind=None):
        if pos[0] >= len(toks) or (kind and toks[pos[0]][0] != kind):
            raise ExprError(f"expected {kind or 'more text'}")
        pos[0] += 1
        return toks[pos[0] - 1][1]

    def parse_or(depth):
        items = [parse_and(depth)]
        while peek() == "OR":
            take()
            items.append(parse_and(depth))
        return items[0] if len(items) == 1 else Op("OR", items)

    def parse_and(depth):
        items = [parse_unary(depth)]
        while peek() == "AND":
            take()
            items.append(parse_unary(depth))
        return items[0] if len(items) == 1 else Op("AND", items)

    def parse_unary(depth):
        if peek() == "NOT":
            take()
            return Not(parse_unary(depth + 1))
        if peek() == "(":
            if depth >= MAX_DEPTH:
                raise ExprError("the expression is nested too deeply")
            take()
            inner = parse_or(depth + 1)
            take(")")
            return Group(inner)
        if peek() == "term":
            return take()
        raise ExprError("expected a dictionary term or an opening parenthesis")

    tree = parse_or(0)
    if pos[0] != len(toks):
        raise ExprError("text left after the expression")
    return tree


def render_expression(node: Any, strip: bool = False) -> str:
    """The expression as text. strip=True leaves out the `D:` before each
    dictionary name (the Expression Preview the console shows)."""
    if isinstance(node, Term):
        return f"{'' if strip else 'D:'}{node.name} {node.op} {node.n}"
    if isinstance(node, Sum):
        d = "" if strip else "D:"
        return "(" + " + ".join(d + n for n in node.names) + f") {node.op} {node.n}"
    if isinstance(node, Op):
        return f" {node.op} ".join(render_expression(i, strip) for i in node.items)
    if isinstance(node, Not):
        return "NOT " + render_expression(node.item, strip)
    return "(" + render_expression(node.item, strip) + ")"


def expression_terms(node: Any) -> List[Term]:
    """Every dictionary term, in order."""
    if isinstance(node, Term):
        return [node]
    if isinstance(node, Sum):
        return [Term(n, node.op, node.n) for n in node.names]
    if isinstance(node, Op):
        return [t for i in node.items for t in expression_terms(i)]
    return expression_terms(node.item)


def expression_preview(text: str) -> str:
    """The Expression Preview of an expression: parsed and written back with
    `D:` taken off; text that cannot be parsed has `D:` taken off as it is."""
    try:
        return render_expression(parse_expression(text), strip=True)
    except ExprError:
        return re.sub(r"\bD:", "", " ".join(str(text or "").split()))


# The Engine Builder tree: ("ALL" | "ANY" | "EXCLUDE", [children]) or a leaf (Term).
def builder_tree(node: Any) -> Tuple[str, List[Any]]:
    """The Engine Builder shape of a parsed expression. AND is ALL, OR is
    ANY, NOT is EXCLUDE. The console puts dictionaries under an ANY, so a
    dictionary that sits directly under ALL gets an ANY of its own."""
    def build(n):
        if isinstance(n, (Term, Sum)):
            return n
        if isinstance(n, Group):
            return build(n.item)
        if isinstance(n, Not):
            inner = build(n.item)
            if isinstance(inner, tuple) and inner[0] == "ANY":
                return ("EXCLUDE", inner[1])
            return ("EXCLUDE", [inner])
        kind = "ALL" if n.op == "AND" else "ANY"
        return flatten((kind, [build(i) for i in n.items]))

    def flatten(t):
        kind, items = t
        out: List[Any] = []
        for i in items:
            if isinstance(i, tuple) and i[0] == kind and kind != "EXCLUDE":
                out.extend(i[1])
            else:
                out.append(i)
        return (kind, out)

    def wrap(t):
        kind, items = t
        out = []
        for i in items:
            if isinstance(i, tuple):
                out.append(wrap(i))
            elif kind == "ALL":
                out.append(("ANY", [i]))
            else:
                out.append(i)
        return (kind, out)

    root = build(node)
    if not isinstance(root, tuple):
        root = ("ANY", [root])
    root = flatten(root) if isinstance(root, tuple) else root
    return wrap(root)


def _term_text(t: Any, with_count: bool = True) -> str:
    if isinstance(t, Sum):
        return f"total matches of {' + '.join(t.names)} ({t.op} {t.n})"
    return t.name + (f" ({t.op} {t.n})" if with_count and not (t.op == ">" and t.n == 0) else "")


def _logic_inline(t: Any) -> str:
    """A builder item on one line: a, (a AND b), (a OR b), NOT (a OR b)."""
    if isinstance(t, (Term, Sum)):
        return _term_text(t)
    kind, items = t
    parts = [_term_text(x) if isinstance(x, (Term, Sum)) else "(" + _logic_inline(x) + ")" for x in items]
    if kind == "EXCLUDE":
        return "NOT (" + " OR ".join(parts) + ")"
    return (" AND " if kind == "ALL" else " OR ").join(parts)


def _names(items: Sequence[Any]) -> Tuple[List[str], str]:
    """The names in a group and, when its dictionaries all share one match
    count above zero, that count as 'more than n matches'."""
    terms = [i for i in items if isinstance(i, Term)]
    others = [i for i in items if not isinstance(i, Term)]
    counts = {(t.op, t.n) for t in terms}
    uniform = len(counts) == 1 and not others
    extra = ""
    if uniform:
        op, n = next(iter(counts))
        if not (op == ">" and n == 0):
            extra = f"more than {n} matches" if op == ">" else f"{op} {n} matches"
    names = [t.name if uniform else _term_text(t) for t in terms]
    names += [_term_text(o) if isinstance(o, Sum) else "(" + _logic_inline(o) + ")" for o in others]
    return names, extra


def _any_text(items: Sequence[Any], head: str, plural_head: str) -> str:
    names, extra = _names(items)
    if len(names) == 1:
        return f"{head}" + (f" ({extra})" if extra else "") + f": {names[0]}"
    return f"{plural_head} (any one of" + (f", {extra}" if extra else "") + "): " + "; ".join(names)


def engine_logic(expression: str) -> str:
    """The Engine logic cell of section 2. An ALL of ANYs reads 'Identifier
    (any one of): ... AND supporting data (any one of): ...'; anything else
    reads 'Any one of: ...'. A NOT is added as 'But NOT: ...'. Text that
    cannot be parsed is shown as it is."""
    try:
        kind, items = builder_tree(parse_expression(expression))
    except ExprError:
        return "Expression: " + expression_preview(expression)
    if kind == "EXCLUDE":
        return "Must not contain: " + "; ".join(_logic_inline(i) for i in items)
    excluded = [i for i in items if isinstance(i, tuple) and i[0] == "EXCLUDE"] if kind == "ALL" else []
    pos = [i for i in items if not (isinstance(i, tuple) and i[0] == "EXCLUDE")] if kind == "ALL" else items
    if kind == "ALL" and pos and all(isinstance(i, tuple) and i[0] == "ANY" for i in pos):
        out = _any_text(pos[0][1], "Identifier", "Identifier")
        for i in pos[1:]:
            out += "\n\nAND " + _any_text(i[1], "supporting data", "supporting data")
    elif kind == "ANY" and len(items) == 1 and isinstance(items[0], Sum):
        out = _term_text(items[0])[0].upper() + _term_text(items[0])[1:]
    elif kind == "ANY":
        names, extra = _names(items)
        out = "Any one of" + (f" ({extra})" if extra else "") + ": " + "; ".join(names)
    else:
        out = "All of: " + "; ".join(_logic_inline(i) for i in pos)
    for i in excluded:
        out += "\n\nBut NOT: " + "; ".join(_logic_inline(x) for x in i[1])
    return out


# ═══════════════════════════════════════════════════════════════════════
# The pack
# ═══════════════════════════════════════════════════════════════════════

_BAD = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿]")


def _s(v: Any) -> str:
    """Text safe for a Word run (no XML-illegal characters)."""
    return _BAD.sub("", "" if v is None else str(v))


def _list(v: Any) -> list:
    return v if isinstance(v, list) else []


@dataclass
class PackData:
    id: str
    name: str
    meta: Dict[str, Any]
    dicts: List[Dict[str, Any]]
    engines: List[Dict[str, Any]]
    rules: List[Dict[str, Any]]
    custom: List[Dict[str, Any]] = field(default_factory=list)
    predefined: List[str] = field(default_factory=list)       # names the engines use that the pack does not define
    trees: Dict[str, Any] = field(default_factory=dict)       # engine name -> parsed tree or None
    web_rules: List[Dict[str, Any]] = field(default_factory=list)
    channels: Dict[str, int] = field(default_factory=dict)


def _load_json(path: str) -> List[Dict[str, Any]]:
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    if isinstance(data, dict):
        data = next((v for v in data.values() if isinstance(v, list)), [])
    return [x for x in data if isinstance(x, dict)] if isinstance(data, list) else []


def load_pack(pack_id: str) -> PackData:
    """Read one pack from disk by id (shipped or uploaded). Raises GuideError."""
    import dlp_importer
    meta = next((p for p in dlp_importer.discover_packs() if p.get("id") == pack_id), None)
    if not meta:
        raise GuideError(f"Unknown pack '{_s(pack_id)[:64]}'.")
    configs = dlp_importer._resolve_configs(meta["dir"])
    dicts = _load_json(os.path.join(configs, "dlp_dictionaries.json"))
    engines = _load_json(os.path.join(configs, "dlp_engines.json"))
    rules = _load_json(os.path.join(configs, "dlp_policies.json"))
    pd = PackData(id=pack_id, name=_s(meta.get("name") or pack_id), meta=meta, dicts=dicts, engines=engines, rules=rules)
    pd.custom = [d for d in dicts if d.get("name")]
    own = {_s(d["name"]).strip() for d in pd.custom}
    seen: List[str] = []
    for e in engines:
        expr = _s(e.get("expression"))
        try:
            tree = parse_expression(expr)
            names = [t.name for t in expression_terms(tree)]
        except ExprError:
            tree = None
            names = [m.group(1).strip() for m in re.finditer(r"D:(.+?)\s*[<>=]", expr)]
        pd.trees[_s(e.get("name"))] = tree
        for nm in names:
            if nm not in own and nm not in seen:
                seen.append(nm)
    pd.predefined = seen
    pd.web_rules = [r for r in rules if str(r.get("channel") or "web").strip().lower() in ("", "web")]
    for r in rules:
        ch = str(r.get("channel") or "web").strip().lower() or "web"
        pd.channels[ch] = pd.channels.get(ch, 0) + 1
    return pd


def is_clone(d: Dict[str, Any]) -> bool:
    return bool(d.get("predefined_clone"))


# ── Alignment facts: regulation, vertical, region ────────────────────

_NOT_A_VERTICAL = {"Any industry", "Canada"}
_REGION = {"canada_privacy_baseline": "Canada", "global_banking_baseline": "Global", "zbp_source_code_baseline": "Global",
           "zbp_enterprise_baseline": "Global", "fed_policy_pack": "United States", "cjis_policy_pack": "United States",
           "irs_fti_pack": "United States", "healthcare_phi_baseline": "United States", "education_ferpa_baseline": "United States"}


def _profiles_for(pack_id: str) -> List[Dict[str, Any]]:
    try:
        import compliance_profiles
        return [dict(v, key=k) for k, v in compliance_profiles.PROFILES.items() if pack_id in (v.get("packs") or [])]
    except Exception:  # noqa: BLE001
        return []


def regulations(pack_id: str) -> List[str]:
    """The compliance profiles whose packs include this pack, by label."""
    return [_s(p.get("label") or p["key"]) for p in _profiles_for(pack_id)]


def vertical_label(pack_id: str) -> str:
    try:
        import vertical
        inds = [i for i, packs in vertical.INDUSTRY_PACKS.items() if pack_id in packs]
    except Exception:  # noqa: BLE001
        inds = []
    if not inds:
        groups = []
        for p in _profiles_for(pack_id):
            g = p.get("group")
            if g and g not in _NOT_A_VERTICAL and g not in groups:
                groups.append(g)
        inds = groups
    return "; ".join(inds) if 0 < len(inds) < 4 else "All verticals"


def region_label(pack_id: str) -> str:
    if pack_id in _REGION:
        return _REGION[pack_id]
    if any(p.get("group") == "Canada" for p in _profiles_for(pack_id)):
        return "Canada"
    return "Not specific to one region"


def _join(items: Sequence[str], last: str = "and") -> str:
    items = [i for i in items if i]
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" {last} " + items[-1]


# ── Predefined dictionary options ────────────────────────────────────

_CONF = {"CONFIDENCE_LEVEL_LOW": "Low", "CONFIDENCE_LEVEL_MEDIUM": "Medium", "CONFIDENCE_LEVEL_HIGH": "High"}


def _conf(v: Any) -> str:
    return _CONF.get(str(v), _s(v).replace("CONFIDENCE_LEVEL_", "").title())


def _tweaks(pd: PackData) -> List[Dict[str, Any]]:
    """The confidence tweaks a deploy applies: the pack's own, else the app's defaults."""
    own = pd.meta.get("confidence_tweaks")
    if own is None:
        try:
            import dlp_importer
            return list(dlp_importer.DEFAULT_CONFIDENCE_TWEAKS)
        except Exception:  # noqa: BLE001
            return []
    return [t for t in own if isinstance(t, dict)] if isinstance(own, list) else []


def predefined_option(pd: PackData, name: str) -> str:
    for t in _tweaks(pd):
        cands = t.get("name_patterns") or ([t["name"]] if t.get("name") else [])
        if name in cands:
            return f"Confidence: {_conf(t.get('target_confidence'))} ({_s(t.get('label') or 'confidence tweak')})"
    return "Leave at its default; the pack sets no option"


# ═══════════════════════════════════════════════════════════════════════
# Test samples from the offline detection validator
# ═══════════════════════════════════════════════════════════════════════

_VALIDATOR: Dict[str, Any] = {}


def _validator():
    """tools/validate_detection.py as a module, or None when it is not shipped."""
    if "m" not in _VALIDATOR:
        mod = None
        path = os.path.join(ROOT, "tools", "validate_detection.py")
        if os.path.isfile(path):
            try:
                spec = importlib.util.spec_from_file_location("_pack_guide_validator", path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore[union-attr]
            except Exception:  # noqa: BLE001
                mod = None
        _VALIDATOR["m"] = mod
    return _VALIDATOR["m"]


_TEST_IBAN_COUNTRIES = ("DE", "GB", "NL", "FR", "ES", "IT", "BE", "AT", "PT", "IE", "FI", "LU")


def _check_digit(body: str) -> str:
    """The Luhn check digit that makes body + digit valid."""
    for c in range(10):
        if _luhn(body + str(c)):
            return str(c)
    return "0"


def _made_up_card(k: int, length: int) -> str:
    prefix = "3400" if length == 15 else "4000"
    body = prefix + f"{(k + 1) * 7919 % 10 ** (length - len(prefix) - 1):0{length - len(prefix) - 1}d}"
    return body + _check_digit(body)


def _made_up_ssn(k: int) -> str:
    area = 123 + k
    area = area + 1 if area == 666 else area
    return f"{area % 665 + 1:03d}-{45 + k % 50:02d}-{6789 + k * 11 % 3000:04d}"


def _made_up_sin(k: int) -> str:
    body = f"{13069254 + k * 1013:08d}"
    d = body + _check_digit(body)
    return f"{d[0:3]} {d[3:6]} {d[6:9]}"


def _made_up_iban(country: str, length: int, k: int) -> str:
    n = max(length - 4, 4)
    bban = f"{(31415926535897932384626 * (k + 1)) % 10 ** n:0{n}d}"
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in bban + country + "00")
    return f"{country}{98 - int(num) % 97:02d}{bban}"


def _luhn(d: str) -> bool:
    s, alt = 0, False
    for ch in reversed(d):
        x = int(ch)
        if alt:
            x = x * 2 - 9 if x * 2 > 9 else x * 2
        s += x
        alt = not alt
    return s % 10 == 0


def mask_sample(text: str) -> str:
    """Replace anything that looks like a real number (card, SSN, IBAN, ABA
    routing, SIN) with a made-up value. Each distinct number becomes a
    distinct made-up number, so a list of fifty cards is still fifty
    different values and a bulk engine still counts them."""
    seen: Dict[str, Dict[str, str]] = {"c": {}, "s": {}, "n": {}, "i": {}}

    def swap(kind: str, value: str, make) -> str:
        table = seen[kind]
        if value not in table:
            table[value] = make(len(table))
        return table[value]

    def card(m):
        d = m.group(0)
        return swap("c", d, lambda k: _made_up_card(k, len(d))) if _luhn(d) else d

    def iban(m):
        v = m.group(0)
        if v[:2] in _TEST_IBAN_COUNTRIES and len(v) >= 15 and _iban_ok(v):
            return swap("i", v, lambda k: _made_up_iban(v[:2], len(v), k))
        return v

    text = re.sub(r"\b\d{13,19}\b", card, text)
    text = re.sub(r"\b\d{3}-\d{2}-\d{4}\b", lambda m: swap("s", m.group(0), _made_up_ssn), text)
    text = re.sub(r"\b[1-79]\d{2} \d{3} \d{3}\b", lambda m: swap("n", m.group(0), _made_up_sin), text)
    text = re.sub(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b", iban, text)
    text = re.sub(r"(?i)(routing number )\d{9}\b", r"\g<1>123456780", text)
    return text


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", s):
        return False
    return int("".join(str(ord(c) - 55) if c.isalpha() else c for c in s[4:] + s[:4])) % 97 == 1


def _samples(pack_id: str) -> Dict[str, Tuple[str, List[str]]]:
    """class -> (masked sample text, engine names the validator expects to fire), fixed seed."""
    V = _validator()
    if V is None:
        return {}
    expect = (getattr(V, "EXPECT", {}) or {}).get(pack_id, {})
    rng = random.Random(7)
    texts: Dict[str, str] = {}
    try:
        if pack_id == "global_banking_baseline":
            texts.update(V.banking_samples(rng))
        if pack_id == "zbp_source_code_baseline":
            texts.update(V.CODE_SAMPLES)
        groups = {"healthcare_phi_baseline": "healthcare", "fed_policy_pack": ("cui", "zbp"), "cjis_policy_pack": "cjis",
                  "zbp_enterprise_baseline": "zbp", "canada_privacy_baseline": "canada"}
        g = groups.get(pack_id)
        for key in ((g,) if isinstance(g, str) else (g or ())):
            for cls, fn in V.OTHER_SAMPLES[key].items():
                texts[cls] = fn(rng)
    except Exception:  # noqa: BLE001
        return {}
    return {cls: (mask_sample(texts[cls]), list(engs)) for cls, engs in expect.items() if cls in texts}


def _negatives() -> List[str]:
    V = _validator()
    if V is None:
        return []
    neg = getattr(V, "NEGATIVES", {}) or {}
    return [neg[k][0] for k in ("invoice", "prose", "log", "markdown", "csv", "json_config") if neg.get(k)]


def _shorten(text: str, limit: int) -> str:
    text = text.replace("\r", "")
    flat = "\n".join(line.rstrip() for line in text.split("\n"))
    return flat if len(flat) <= limit else flat[:limit].rstrip() + " ..."


def test_rows(pd: PackData) -> List[List[str]]:
    """Step 7 rows: [test, should match, should not match, engine that should fire]."""
    num = {_s(e.get("name")): i + 1 for i, e in enumerate(pd.engines)}
    samples = _samples(pd.id)
    negs = _negatives()
    code = set(getattr(_validator(), "CODE_SAMPLES", {}) or {})
    rows: List[List[str]] = []
    covered = set()
    V = _validator()
    try:
        checker = V.Pack(pd.meta) if V is not None and samples else None
    except Exception:  # noqa: BLE001
        checker = None
    for cls, (text, engs) in samples.items():
        engs = [e for e in engs if e in num]
        if checker is not None and engs:
            # Only an engine the validator's own evaluator fires on this exact sample is promised here.
            try:
                fired = checker.evaluate(text)
                engs = [e for e in engs if fired.get(e)]
            except Exception:  # noqa: BLE001
                engs = []
        if not engs:
            continue
        covered.update(engs)
        neg = negs[len(rows) % len(negs)] if negs else "A file with no data of this kind"
        label = f"{cls} source code" if cls in code else (cls.replace("_", " ")[:1].upper() + cls.replace("_", " ")[1:])
        rows.append([label, _shorten(text, 360 if cls in code else 700), _shorten(neg, 140),
                     "\n".join(f"#{num[e]} {e}" for e in engs)])
    for e in pd.engines:
        name = _s(e.get("name"))
        if name in covered:
            continue
        rows.append([name, "No validator sample covers this engine. Build a short file that meets the engine logic in section 2, using made-up values only.",
                     "A file that meets only part of that logic, or none of it", f"#{num[name]} {name}"])
    return rows


# ═══════════════════════════════════════════════════════════════════════
# Word helpers
# ═══════════════════════════════════════════════════════════════════════

def _fonts(rpr, name: str) -> None:
    rf = rpr.find(qn("w:rFonts"))
    if rf is None:
        rf = OxmlElement("w:rFonts")
        rpr.insert(0, rf)
    for a in ("w:asciiTheme", "w:hAnsiTheme", "w:eastAsiaTheme", "w:cstheme"):
        if rf.get(qn(a)) is not None:
            del rf.attrib[qn(a)]
    for a in ("w:ascii", "w:hAnsi", "w:cs", "w:eastAsia"):
        rf.set(qn(a), name)


def _run(p, text: str, size: float = 9.5, bold=False, italic=False, color: Optional[str] = None, mono=False, box: Optional[str] = None, btn=False):
    r = p.add_run(_s(text))
    r.font.size = Pt(size)
    r.bold = bold or None
    r.italic = italic or None
    if color:
        r.font.color.rgb = RGBColor.from_string(color)
    _fonts(r._r.get_or_add_rPr(), MONO if mono else FONT)
    rpr = r._r.get_or_add_rPr()
    if box:
        b = OxmlElement("w:bdr")
        b.set(qn("w:val"), "single")
        b.set(qn("w:sz"), "4" if box == "thin" else "12")
        b.set(qn("w:space"), "1")
        b.set(qn("w:color"), "9CA3AF" if box == "thin" else BLUE)
        rpr.append(b)
    if btn:
        sh = OxmlElement("w:shd")
        sh.set(qn("w:val"), "clear")
        sh.set(qn("w:color"), "auto")
        sh.set(qn("w:fill"), BLUE)
        rpr.append(sh)
    return r


def _spacing(p, before=0, after=6, keep_next=False, page_break=False, indent=None, right=None, align=None):
    pf = p.paragraph_format
    pf.space_before = Twips(before)
    pf.space_after = Twips(after)
    if keep_next:
        pf.keep_with_next = True
    if page_break:
        pf.page_break_before = True
    if indent is not None:
        pf.left_indent = Twips(indent)
    if right is not None:
        pf.right_indent = Twips(right)
    if align:
        p.alignment = align


def _pbdr(p, thin: bool, space: int = 2) -> None:
    """A box round the paragraph (paragraph borders): thick blue to type in, thin grey when pre-filled."""
    ppr = p._p.get_or_add_pPr()
    bd = OxmlElement("w:pBdr")
    for side in ("top", "left", "bottom", "right"):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), "4" if thin else "12")
        e.set(qn("w:space"), str(space))
        e.set(qn("w:color"), "9CA3AF" if thin else BLUE)
        bd.append(e)
    # pBdr must precede spacing / ind / jc in pPr
    anchor = None
    for tag in ("w:shd", "w:tabs", "w:suppressAutoHyphens", "w:spacing", "w:ind", "w:contextualSpacing", "w:jc", "w:rPr"):
        anchor = ppr.find(qn(tag))
        if anchor is not None:
            break
    if anchor is not None:
        anchor.addprevious(bd)
    else:
        ppr.append(bd)


def _bottom_rule(p, color: str = NAVY) -> None:
    ppr = p._p.get_or_add_pPr()
    bd = OxmlElement("w:pBdr")
    e = OxmlElement("w:bottom")
    e.set(qn("w:val"), "single")
    e.set(qn("w:sz"), "6")
    e.set(qn("w:space"), "4")
    e.set(qn("w:color"), color)
    bd.append(e)
    anchor = ppr.find(qn("w:spacing"))
    if anchor is not None:
        anchor.addprevious(bd)
    else:
        ppr.append(bd)


def _cell_borders(cell, top=None, bottom=None, left=None, right=None) -> None:
    """Each side: None (none), or (size, color)."""
    tcpr = cell._tc.get_or_add_tcPr()
    old = tcpr.find(qn("w:tcBorders"))
    if old is not None:
        tcpr.remove(old)
    bd = OxmlElement("w:tcBorders")
    for side, spec in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        e = OxmlElement(f"w:{side}")
        if spec:
            e.set(qn("w:val"), "single")
            e.set(qn("w:sz"), str(spec[0]))
            e.set(qn("w:color"), spec[1])
            e.set(qn("w:space"), "0")
        else:
            e.set(qn("w:val"), "nil")
        bd.append(e)
    _insert_tcpr(tcpr, bd, ("w:shd", "w:noWrap", "w:tcMar", "w:textDirection", "w:tcFitText", "w:vAlign", "w:hideMark"))


def _insert_tcpr(tcpr, el, after_tags: Sequence[str]) -> None:
    for tag in after_tags:
        a = tcpr.find(qn(tag))
        if a is not None:
            a.addprevious(el)
            return
    tcpr.append(el)


def _cell_shade(cell, fill: str) -> None:
    tcpr = cell._tc.get_or_add_tcPr()
    sh = OxmlElement("w:shd")
    sh.set(qn("w:val"), "clear")
    sh.set(qn("w:color"), "auto")
    sh.set(qn("w:fill"), fill)
    _insert_tcpr(tcpr, sh, ("w:noWrap", "w:tcMar", "w:textDirection", "w:tcFitText", "w:vAlign", "w:hideMark"))


def _cell_margins(cell, top, bottom, left, right) -> None:
    tcpr = cell._tc.get_or_add_tcPr()
    mar = OxmlElement("w:tcMar")
    for side, v in (("top", top), ("left", left), ("bottom", bottom), ("right", right)):
        e = OxmlElement(f"w:{side}")
        e.set(qn("w:w"), str(v))
        e.set(qn("w:type"), "dxa")
        mar.append(e)
    _insert_tcpr(tcpr, mar, ("w:textDirection", "w:tcFitText", "w:vAlign", "w:hideMark"))


def _row_flags(row, header=False, cant_split=True) -> None:
    trpr = row._tr.get_or_add_trPr()
    if cant_split:
        trpr.append(OxmlElement("w:cantSplit"))
    if header:
        trpr.append(OxmlElement("w:tblHeader"))


def _new_table(doc, rows: int, widths: Sequence[int]):
    t = doc.add_table(rows=rows, cols=len(widths))
    t.autofit = False
    tblpr = t._tbl.tblPr
    for tag in ("w:tblStyle", "w:tblW", "w:tblLayout"):
        old = tblpr.find(qn(tag))
        if old is not None:
            tblpr.remove(old)
    tw = OxmlElement("w:tblW")
    tw.set(qn("w:w"), str(sum(widths)))
    tw.set(qn("w:type"), "dxa")
    tblpr.append(tw)
    lay = OxmlElement("w:tblLayout")
    lay.set(qn("w:type"), "fixed")
    tblpr.append(lay)
    grid = t._tbl.tblGrid
    for gc, w in zip(grid.findall(qn("w:gridCol")), widths):
        gc.set(qn("w:w"), str(w))
    for row in t.rows:
        for c, w in zip(row.cells, widths):
            c.width = Twips(w)
    return t


def _clean_cell(cell) -> None:
    """Drop the empty first paragraph a fresh cell has (a cell must keep one)."""
    ps = cell.paragraphs
    if len(ps) > 1 and not ps[0].text and not ps[0].runs:
        ps[0]._p.getparent().remove(ps[0]._p)


# ═══════════════════════════════════════════════════════════════════════
# The document
# ═══════════════════════════════════════════════════════════════════════

class _Doc:
    def __init__(self) -> None:
        self.doc = Document()
        self._lists = 0
        self._setup()

    # ── set-up ───────────────────────────────────────────────────────
    def _setup(self) -> None:
        d = self.doc
        sec = d.sections[0]
        sec.page_width, sec.page_height = Twips(12240), Twips(15840)
        sec.top_margin = sec.bottom_margin = Twips(1300)
        sec.left_margin = sec.right_margin = Twips(1440)
        sec.header_distance = sec.footer_distance = Twips(600)
        normal = d.styles["Normal"]
        normal.font.name = FONT
        normal.font.size = Pt(9.5)
        _fonts(normal.element.get_or_add_rPr(), FONT)
        normal.paragraph_format.space_after = Twips(0)
        for name, size, before, after in (("Heading 1", 15, 280, 140), ("Heading 2", 11, 220, 110)):
            st = d.styles[name]
            st.font.name = FONT
            st.font.size = Pt(size)
            st.font.bold = True
            st.font.italic = False
            st.font.color.rgb = RGBColor.from_string(NAVY)
            _fonts(st.element.get_or_add_rPr(), FONT)
            st.paragraph_format.space_before = Twips(before)
            st.paragraph_format.space_after = Twips(after)
            st.paragraph_format.keep_with_next = True
        cp = d.core_properties
        cp.author = "Zscaler Made Easy"
        cp.last_modified_by = "Zscaler Made Easy"
        cp.created = cp.modified = FIXED_DATE
        cp.revision = 1
        # header: ZSCALER (right); footer: the confidentiality line and the page number
        hp = sec.header.paragraphs[0]
        hp.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        _run(hp, "ZSCALER", 8, bold=True, color=BLUE)
        fp = sec.footer.paragraphs[0]
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        _run(fp, "© Zscaler, Inc. All rights reserved.   |   Confidential — prepared for the named customer   |   page ", 7, color=GREY)
        self._page_field(fp)
        self._numbering()

    def _page_field(self, p) -> None:
        r = _run(p, "", 7, color=GREY)
        for kind, text in (("begin", None), (None, " PAGE "), ("separate", None), (None, "1"), ("end", None)):
            if kind:
                fc = OxmlElement("w:fldChar")
                fc.set(qn("w:fldCharType"), kind)
                r._r.append(fc)
            elif text == " PAGE ":
                it = OxmlElement("w:instrText")
                it.set(qn("xml:space"), "preserve")
                it.text = text
                r._r.append(it)
            else:
                t = OxmlElement("w:t")
                t.text = text
                r._r.append(t)

    def _numbering(self) -> None:
        num = self.doc.part.numbering_part.element
        first_num = num.find(qn("w:num"))

        def abstract(aid: int, fmt: str, text: str, left: int, hanging: int):
            an = OxmlElement("w:abstractNum")
            an.set(qn("w:abstractNumId"), str(aid))
            ml = OxmlElement("w:multiLevelType")
            ml.set(qn("w:val"), "singleLevel")
            an.append(ml)
            lvl = OxmlElement("w:lvl")
            lvl.set(qn("w:ilvl"), "0")
            for tag, val in (("w:start", "1"), ("w:numFmt", fmt), ("w:lvlText", text), ("w:lvlJc", "left")):
                e = OxmlElement(tag)
                e.set(qn("w:val"), val)
                lvl.append(e)
            ppr = OxmlElement("w:pPr")
            ind = OxmlElement("w:ind")
            ind.set(qn("w:left"), str(left))
            ind.set(qn("w:hanging"), str(hanging))
            ppr.append(ind)
            lvl.append(ppr)
            an.append(lvl)
            if first_num is not None:
                first_num.addprevious(an)
            else:
                num.append(an)

        abstract(900, "bullet", "•", 540, 270)
        abstract(901, "decimal", "%1.", 540, 300)
        self._bullet_id = 900
        self._add_num(900, 900, restart=False)

    def _add_num(self, num_id: int, abstract_id: int, restart: bool) -> None:
        num = self.doc.part.numbering_part.element
        n = OxmlElement("w:num")
        n.set(qn("w:numId"), str(num_id))
        a = OxmlElement("w:abstractNumId")
        a.set(qn("w:val"), str(abstract_id))
        n.append(a)
        if restart:
            ov = OxmlElement("w:lvlOverride")
            ov.set(qn("w:ilvl"), "0")
            so = OxmlElement("w:startOverride")
            so.set(qn("w:val"), "1")
            ov.append(so)
            n.append(ov)
        num.append(n)

    def new_list(self) -> int:
        self._lists += 1
        nid = 910 + self._lists
        self._add_num(nid, 901, restart=True)
        return nid

    def _numpr(self, p, num_id: int) -> None:
        ppr = p._p.get_or_add_pPr()
        np_ = OxmlElement("w:numPr")
        il = OxmlElement("w:ilvl")
        il.set(qn("w:val"), "0")
        ni = OxmlElement("w:numId")
        ni.set(qn("w:val"), str(num_id))
        np_.append(il)
        np_.append(ni)
        anchor = ppr.find(qn("w:spacing"))
        if anchor is not None:
            anchor.addprevious(np_)
        else:
            ppr.append(np_)

    # ── text blocks ──────────────────────────────────────────────────
    def para(self, runs, after=120, before=0, **kw):
        p = self.doc.add_paragraph()
        _spacing(p, before, after, **kw)
        if isinstance(runs, str):
            _run(p, runs)
        else:
            for r in runs:
                _run(p, r[0], **(r[1] if len(r) > 1 else {}))
        return p

    def h1(self, text: str, page_break=False):
        p = self.doc.add_paragraph(style="Heading 1")
        p.add_run(_s(text))
        if page_break:
            p.paragraph_format.page_break_before = True
        return p

    def h2(self, text: str, page_break=False):
        p = self.doc.add_paragraph(style="Heading 2")
        p.add_run(_s(text))
        if page_break:
            p.paragraph_format.page_break_before = True
        return p

    def bullet(self, text: str):
        p = self.doc.add_paragraph()
        _spacing(p, 0, 80)
        self._numpr(p, self._bullet_id)
        _run(p, text)
        return p

    def steps(self, items: Sequence[str]) -> None:
        nid = self.new_list()
        for s in items:
            p = self.doc.add_paragraph()
            _spacing(p, 0, 70)
            self._numpr(p, nid)
            _run(p, s)

    def label(self, k: str, v: str):
        return self.para([(k + ": ", {"bold": True}), (v, {})], after=80)

    def gap(self, n=80):
        p = self.doc.add_paragraph()
        _spacing(p, 0, n)
        return p

    # ── plain table ──────────────────────────────────────────────────
    def table(self, headers: Sequence[str], rows: Sequence[Sequence[str]], widths: Sequence[int], mono=False):
        t = _new_table(self.doc, 1 + len(rows), widths)
        line = (4, LINE)
        for ri, row in enumerate([list(headers)] + [list(r) for r in rows]):
            head = ri == 0
            _row_flags(t.rows[ri], header=head)
            for ci, txt in enumerate(row):
                c = t.rows[ri].cells[ci]
                _cell_borders(c, line, line, line, line)
                if head:
                    _cell_shade(c, HEAD)
                _cell_margins(c, 50, 50, 90, 90)
                lines = _s(txt).split("\n")
                for li, ln in enumerate(lines):
                    p = c.paragraphs[0] if li == 0 else c.add_paragraph()
                    _spacing(p, 0, 0)
                    _run(p, ln, 8.5, bold=head, mono=mono and not head)
        return t

    # ── console form mock-ups ────────────────────────────────────────
    def form(self, rows: List[Dict[str, Any]]):
        """rows: dicts with kind crumb|section|fields|button; fields hold paragraph builders."""
        t = _new_table(self.doc, len(rows) + 1, [4680, 4680])
        frame = (6, "B8BEC8")
        for ri, spec in enumerate(rows):
            row = t.rows[ri]
            two = spec["kind"] == "fields" and len(spec["cells"]) == 2
            if not two:
                row.cells[0].merge(row.cells[1])
            cells = [row.cells[0], row.cells[1]] if two else [row.cells[0]]
            if not spec.get("split"):
                _row_flags(row)
            for ci, c in enumerate(cells):
                left = frame if ci == 0 else None
                right = frame if ci == len(cells) - 1 else None
                top = frame if spec["kind"] in ("crumb", "section") else None
                _cell_borders(c, top, None, left, right)
                _cell_margins(c, 20, 20, 110, 110)
                if spec["kind"] == "crumb":
                    _cell_shade(c, LIGHT)
                body = spec["cells"][ci] if spec["kind"] == "fields" else spec["cells"][0]
                first = True
                for build in body:
                    p = c.paragraphs[0] if first else c.add_paragraph()
                    first = False
                    build(p)
        last = t.rows[len(rows)]
        last.cells[0].merge(last.cells[1])
        _cell_borders(last.cells[0], None, frame, frame, frame)
        _row_flags(last)
        lp = last.cells[0].paragraphs[0]
        _spacing(lp, 0, 60)
        return t


# Builders: each returns a function that fills one paragraph.
def _lbl(text: str):
    def f(p):
        _spacing(p, 60, 20)
        _run(p, text, 7.5, color=GREY)
    return f


def _val(text: str, thin=False, drop=False, mono=False, after=60, size=8):
    def f(p):
        _spacing(p, 0, after, indent=40, right=40)
        _pbdr(p, thin)
        _run(p, f"{text}{'   ▾' if drop else ''}", size, bold=not thin, mono=mono)
    return f


def _line(text: str, last=False):
    """One line of a multi-line typed box; neighbours with the same border join into one outline."""
    def f(p):
        _spacing(p, 0, 60 if last else 0, indent=40, right=40)
        _pbdr(p, False)
        _run(p, text, 8, bold=True)
    return f


def _btn(text: str):
    def f(p):
        _spacing(p, 40, 60)
        _run(p, f" {text} ", 7.5, bold=True, color="FFFFFF", btn=True)
    return f


def _section(text: str):
    return {"kind": "section", "cells": [[lambda p, t=text: (_spacing(p, 60, 20), _run(p, t, 8.5, bold=True, color=NAVY))]]}


def _crumb(parts: Sequence[str]):
    def f(p):
        _spacing(p, 40, 40)
        for i, part in enumerate(parts):
            last = i == len(parts) - 1
            _run(p, part, 7.5, bold=last, color=NAVY if last else BLUE)
            if not last:
                _run(p, "  ›  ", 7.5, color=GREY)
    return {"kind": "crumb", "cells": [[f]]}


def _fields(*cells):
    return {"kind": "fields", "cells": [list(c) for c in cells]}


_MATCH_LABEL = {"MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE": "Match Any Patterns and Any Phrases",
                "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY": "Match Any",
                "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY": "Match All"}


def _match_label(v: Any) -> str:
    v = str(v or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")
    return _MATCH_LABEL.get(v, v.replace("MATCH_", "").replace("_", " ").title())


def _act(a: Any) -> str:
    return "Count Unique" if "UNIQUE" in str(a or "") else "Count All"


def _dict_form(dd: _Doc, d: Dict[str, Any], clone: bool):
    name = _s(d.get("name"))
    prox = d.get("proximity")
    try:
        prox = int(prox) if prox else 0
    except (TypeError, ValueError):
        prox = 0
    rows: List[Dict[str, Any]] = []
    if clone:
        rows.append(_crumb(["DLP Dictionaries", "Clone Predefined Dictionary"]))
        rows.append(_section("DLP Dictionary"))
        rows.append(_fields([_lbl("Name"), _val(name)], [_lbl("Clone of (Zscaler predefined dictionary)"), _val(_s(d.get("dict_template_name") or "-"), drop=True)]))
        rows.append(_fields([_lbl("Description"), _val(_s(d.get("description")), after=60)]))
        cfg = []
        if d.get("confidence_threshold"):
            cfg.append([_lbl("Confidence Threshold"), _val(_conf(d["confidence_threshold"]), drop=True)])
        if d.get("confidence_level_for_predefined_dict"):
            cfg.append([_lbl("Confidence level for the predefined dictionary"), _val(_conf(d["confidence_level_for_predefined_dict"]), drop=True)])
        for i in range(0, len(cfg), 2):
            rows.append(_fields(*cfg[i:i + 2]) if len(cfg[i:i + 2]) == 2 else _fields(cfg[i], [_lbl(" ")]))
        flags = [(k, lbl) for k, lbl in (("include_bin_numbers", "Include BIN numbers"), ("include_ssn_numbers", "Include SSN numbers")) if k in d]
        for i in range(0, len(flags), 2):
            part = [[_lbl(lbl), _val("On" if d.get(k) else "Off", thin=True)] for k, lbl in flags[i:i + 2]]
            rows.append(_fields(*part) if len(part) == 2 else _fields(part[0], [_lbl(" ")]))
        ids = [_s(x) for x in _list(d.get("hierarchical_identifiers"))]
        if ids:
            shown = ", ".join(ids[:6]) + (f", and {len(ids) - 6} more" if len(ids) > 6 else "")
            rows.append(_fields([_lbl(f"Identifiers ({len(ids)} selected)"), _val(shown)]))
    else:
        rows.append(_crumb(["DLP Dictionaries", "Add DLP Dictionary"]))
        rows.append(_section("DLP Dictionary"))
        rows.append(_fields([_lbl("Name"), _val(name)], [_lbl("Dictionary Type"), _val("Patterns & Phrases", thin=True, drop=True)]))
        rows.append(_fields([_lbl("Match Type"), _val(_match_label(d.get("custom_phrase_match_type")), drop=True)],
                            [_lbl("Non-delimited Unicode phrase matching"), _val("Off", thin=True)]))
        rows.append(_fields([_lbl("Description"), _val(_s(d.get("description")))]))
    if prox:
        def pref(p):
            _spacing(p, 0, 40)
            _run(p, "◉ Near   ", 8, bold=True, color=BLUE)
            _run(p, "○ Not Near", 8, color=GREY)
        rows.append(_section("Proximity"))
        rows.append(_fields([_lbl("Select Your Preferences"), pref], [_lbl("Proximity Length"), _val(str(prox))]))
    pats = [p for p in _list(d.get("patterns")) if isinstance(p, dict)]
    if pats:
        rows.append(_section("Patterns"))
        for pt in pats:
            rows.append(_fields([_lbl("Pattern"), _val(_s(pt.get("pattern")), mono=True)], [_lbl("Action"), _val(_act(pt.get("action")), thin=True, drop=True)]))
        rows.append({"kind": "button", "cells": [[_btn("Add Pattern")]]})
    phr = [p for p in _list(d.get("phrases")) if isinstance(p, dict) and p.get("phrase") is not None]
    if phr:
        acts = list(dict.fromkeys(_act(p.get("action")) for p in phr))
        lines = [_line(_s(p["phrase"]), last=i == len(phr) - 1) for i, p in enumerate(phr)]
        rows.append(_section("Phrases"))
        rows.append({"kind": "fields", "split": True, "cells": [[_lbl("Phrase (one per line)")] + lines, [_lbl("Action"), _val(" / ".join(acts), thin=True, drop=True)]]})
        rows.append({"kind": "button", "cells": [[_btn("Add Phrase")]]})
    return dd.form(rows)


def _tree_builders(tree: Tuple[str, List[Any]]) -> List[Any]:
    out: List[Any] = []

    def op(kind: str, depth: int):
        def f(p):
            _spacing(p, 0, 0, indent=200 + depth * 420)
            _run(p, "Operator", 7, color=GREY)
        def g(p):
            _spacing(p, 0, 30, indent=200 + depth * 420)
            _run(p, f" {kind} ▾ ", 8, bold=True, box="thick")
        out.extend([f, g])

    def leaf(t: Term, depth: int):
        def f(p):
            _spacing(p, 0, 0, indent=200 + (depth + 1) * 420)
            _run(p, "Dictionary", 7, color=GREY)
        def g(p):
            _spacing(p, 0, 30, indent=200 + (depth + 1) * 420)
            _run(p, f" {t.name} ▾ ", 8, bold=True, box="thick")
            _run(p, f"   {t.op}   ", 8)
            _run(p, f" {t.n} ", 8, bold=True, box="thick")
        out.extend([f, g])

    def total(t: Sum, depth: int):
        """(a + b) > n: the console's SUM operator over the dictionaries, then the match count."""
        op("SUM", depth + 1)
        for nm in t.names:
            def g(p, nm=nm):
                _spacing(p, 0, 0, indent=200 + (depth + 2) * 420)
                _run(p, "Dictionary", 7, color=GREY)

            def g2(p, nm=nm):
                _spacing(p, 0, 30, indent=200 + (depth + 2) * 420)
                _run(p, f" {nm} ▾ ", 8, bold=True, box="thick")
            out.extend([g, g2])

        def h(p):
            _spacing(p, 20, 30, indent=200 + (depth + 2) * 420)
            _run(p, f"{t.op}   ", 8)
            _run(p, f" {t.n} ", 8, bold=True, box="thick")
        out.append(h)

    def walk(node, depth):
        kind, items = node
        op(kind, depth)
        for i in items:
            if isinstance(i, Sum):
                total(i, depth)
            elif isinstance(i, Term):
                leaf(i, depth)
            else:
                walk(i, depth + 1)

    walk(tree, 0)
    return out


def _engine_form(dd: _Doc, e: Dict[str, Any], tree: Any):
    expr = _s(e.get("expression"))
    if tree is not None:
        builder = _tree_builders(builder_tree(tree))
        preview = render_expression(tree, strip=True)
    else:
        def note(p):
            _spacing(p, 20, 20)
            _run(p, "This expression cannot be drawn as a tree. Type it as the Expression Preview shows.", 8, italic=True, color=GREY)
        builder = [note]
        preview = expression_preview(expr)

    def prev(p):
        _spacing(p, 40, 40)
        _run(p, preview, 7.5, mono=True)

    rows = [_crumb(["DLP Dictionaries & Engines", "DLP Engines", "Add DLP Engine"]),
            _fields([_lbl("Name"), _val(_s(e.get("name")))]),
            _fields([_lbl("Description"), _val(_s(e.get("description")))]),
            _section("Engine Builder"),
            _fields([_lbl("Expression")] + builder),
            _section("Expression Preview"),
            _fields([prev])]
    return dd.form(rows), preview


# ═══════════════════════════════════════════════════════════════════════
# Wording that depends on the pack
# ═══════════════════════════════════════════════════════════════════════

def _fmt_minutes(m: int) -> str:
    if m <= 0:
        return "-"
    if m < 60:
        return f"About {m} minutes"
    h = round(m / 30) / 2
    return f"About {h:g} hour{'' if h == 1 else 's'}"


def _days(minutes: int) -> str:
    d = round(minutes / 360 * 2) / 2
    if minutes < 360:
        return "under 1 working day"
    return f"about {d:g} working day{'' if d == 1 else 's'}"


def _plural(n: int, one: str, many: str = "") -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _act_label(a: Any) -> str:
    return str(a or "ALLOW").replace("_", " ").title()


def _first_sentence(text: str, limit: int = 220) -> str:
    """The first sentence; a long one is cut at its first colon, else at a word."""
    text = " ".join(_s(text).split())
    m = re.match(r"(.+?[.!?])(?:\s|$)", text)
    s = m.group(1) if m else text
    if len(s) > limit and ": " in s[:limit * 2]:
        s = s.split(": ", 1)[0] + "."
    if len(s) > limit:
        s = s[:limit].rsplit(" ", 1)[0].rstrip(",;:") + "..."
    return s


def _common_prefix(names: Sequence[str]) -> str:
    heads = {n.split("-", 1)[0] + "-" for n in names if "-" in n}
    return next(iter(heads)) if len(heads) == 1 and all("-" in n for n in names) and names else ""


def _channel_names(chs: Sequence[str]) -> List[str]:
    return [{"endpoint": "Endpoint", "saas": "SaaS", "email": "Email"}.get(c, c.title()) for c in chs]


def build(pack_id: str, prepared_for: str = "", prepared_by: str = "", on_date: Optional[str] = None) -> bytes:
    """The build guide for one pack as .docx bytes. Reads local pack files
    only. Raises GuideError for an unknown pack."""
    pd = load_pack(pack_id)
    dd = _Doc()
    for_ = _s(prepared_for).strip()[:MAX_PARAM] or "______________________"
    by_ = _s(prepared_by).strip()[:MAX_PARAM] or "______________________"
    meta = pd.meta
    title_name = re.sub(r"\s+Pack$", "", pd.name)
    regs = regulations(pack_id)
    vert = vertical_label(pack_id)
    clones = [d for d in pd.custom if is_clone(d)]
    plain = [d for d in pd.custom if not is_clone(d)]
    nDict, nPre, nEng, nRule = len(pd.custom), len(pd.predefined), len(pd.engines), len(pd.web_rules)
    other = [c for c in ("endpoint", "saas", "email") if pd.channels.get(c)]
    other += sorted(c for c in pd.channels if c not in ("web", "endpoint", "saas", "email"))
    n_other = sum(pd.channels.get(c, 0) for c in other)
    web_actions = list(dict.fromkeys(_act_label(r.get("action")) for r in pd.web_rules))
    all_allow = web_actions == ["Allow"] or not web_actions
    act_phrase = "Allow with alerting" if all_allow else _join(web_actions, "and")
    all_disabled = all(str(r.get("state") or "DISABLED").upper() == "DISABLED" for r in pd.rules)
    num = {_s(e.get("name")): i + 1 for i, e in enumerate(pd.engines)}
    used_by: Dict[str, List[str]] = {}
    for e in pd.engines:
        tr = pd.trees.get(_s(e.get("name")))
        names = [t.name for t in expression_terms(tr)] if tr is not None else [m.group(1).strip() for m in re.finditer(r"D:(.+?)\s*[<>=]", _s(e.get("expression")))]
        for nm in dict.fromkeys(names):
            used_by.setdefault(nm, []).append(_s(e.get("name")))

    # time (minutes)
    m_dict, m_pre, m_eng, m_rule = 20 * nDict, 5 * nPre, 10 * nEng, 15 * nRule
    m_test = m_dict
    hand_total = m_pre + m_dict + m_eng + m_rule + m_test
    api_total = (15 if nPre else 0) + (30 if nDict else 0) + (30 if nEng else 0) + (30 if nRule else 0) + m_test

    # ── Cover ────────────────────────────────────────────────────────
    dd.para([("ZSCALER", {"size": 20, "bold": True, "color": BLUE})], after=400, before=1600)
    dd.para([(f"DLP Policy Pack: {title_name}", {"size": 24, "bold": True, "color": NAVY})], after=60)
    rule = dd.doc.add_paragraph()
    _spacing(rule, 0, 160)
    _bottom_rule(rule)
    dd.para([("Zscaler Data Protection Advisory", {"size": 13, "color": BLUE})], after=500)
    dd.label("Prepared for", for_)
    dd.label("Prepared by", by_)
    dd.label("Pack", f"{pd.name} (id {pack_id}" + (f", version {_s(meta['version'])}" if meta.get("version") else "") + ")")
    dd.label("Vertical", vert)
    dd.label("Regions in scope", region_label(pack_id))
    dd.label("DLP channel", "Inline/Web" + (f" (the same engines are also built for {_join(_channel_names(other))})" if other else ""))
    dd.label("Regulations", ", ".join(regs) if regs else "None mapped to this pack")
    dd.label("Date", on_date or _dt.date.today().isoformat())

    # ── 1. Summary ───────────────────────────────────────────────────
    dd.h1("1. Summary", page_break=True)
    lead = (_first_sentence(meta.get("description"), 260) or f"{pd.name} is a DLP policy pack").rstrip(".")
    dd.para(f"{lead}. It has {_plural(nDict, 'custom dictionary', 'custom dictionaries')}, {_plural(nEng, 'engine')} and {_plural(nRule, 'inline rule')}"
            + (f", mapped to {_join(regs)}" if regs else "") + ". The table in section 2 lines up each engine with the data it protects, the vertical and the regulation.")
    dd.bullet(f"Every DLP action on the inline rules is {act_phrase}." if all_allow else f"The inline rules use these DLP actions: {act_phrase}.")
    dd.bullet("The pack ships with every rule disabled; enable each rule only after testing (Step 7)." if all_disabled
              else "Some rules in this pack ship enabled; check the Rule Status in Step 6 against your change plan before you start.")
    dd.bullet(f"The {_plural(nEng, 'engine')} each combine dictionaries with AND, OR or NOT; the \"Engine logic\" column in section 2 says in plain words what each one needs before it matches.")
    if nPre and nDict:
        dd.bullet(f"{_plural(len(plain), 'dictionary', 'dictionaries')} {'is' if len(plain) == 1 else 'are'} custom and you create {'it' if len(plain) == 1 else 'them'}"
                  + (f"; {_plural(len(clones), 'more is a clone', 'more are clones')} of a Zscaler predefined dictionary" if clones else "")
                  + f". {_plural(nPre, 'Zscaler predefined dictionary', 'Zscaler predefined dictionaries')} already exist{'s' if nPre == 1 else ''}: you only set the option the pack names (Step 3).")
    elif nDict:
        dd.bullet(f"Every dictionary in this pack is created by you ({_plural(len(plain), 'custom dictionary', 'custom dictionaries')}"
                  + (f", {_plural(len(clones), 'clone')} of a Zscaler predefined dictionary" if clones else "") + "); no Zscaler predefined dictionary is used on its own.")
    dd.bullet(f"To build this, follow the Step-by-Step Instructions after the table. The same settings are in the app as JSON ({pack_id}) and can be deployed from Deploy Studio instead of typing them.")

    # ── 2. Engine alignment ──────────────────────────────────────────
    dd.h1("2. Engine alignment: data, vertical and regulations")
    dd.para("How to read the table: \"Data protected\" is the information the engine finds. \"Vertical\" shows whether the engine is specific to a sector. \"Regulation\" is the law or framework the engine supports.")
    reg_txt = "; ".join(regs) if regs else "None mapped"
    rows = [[_first_sentence(e.get("description")) or _s(e.get("name")), vert, reg_txt, _s(e.get("name")), engine_logic(_s(e.get("expression")))] for e in pd.engines]
    if rows:
        dd.table(["Data protected", "Vertical", "Regulation", "Engine", "Engine logic"], rows, [1900, 1150, 1450, 1500, 3360])
    else:
        dd.para("This pack has no engines.")

    # ── Instructions intro ───────────────────────────────────────────
    dd.h1("Step-by-Step Instructions", page_break=True)
    dd.para("This guide is written for the person doing the setup. Work through the steps in order, from top to bottom. Tick each box when the item is done. Every name and value you need to type is in this guide, so you do not need to search the pack files.")
    dd.para(f"Two rules for the whole guide: (1) every DLP action in this plan is {act_phrase.split(' with')[0] if all_allow else 'the one in the Step 6 table'}, and it stays that way; (2) if something on your screen does not look like the guide, stop and ask a senior engineer instead of guessing.")
    dd.h2("The work at a glance")
    glance = [
        ["1", "Check the basics are in place", "5 checks", "Before the build", "Before the build", "☐"],
        ["2", "Set the action for each unsanctioned app", "Nothing to do", "-", "-", "☐"],
        ["3", "Set the confidence on Zscaler predefined dictionaries", f"{_plural(nPre, 'predefined dictionary', 'predefined dictionaries')}" if nPre else "Nothing to do (all custom)", _fmt_minutes(m_pre), "About 15 minutes" if nPre else "-", "☐"],
        ["4", "Create custom dictionaries", _plural(nDict, "dictionary", "dictionaries") if nDict else "Nothing to do", _fmt_minutes(m_dict), "About 30 minutes" if nDict else "-", "☐"],
        ["5", "Create DLP engines", _plural(nEng, "engine") if nEng else "Nothing to do", _fmt_minutes(m_eng), "About 30 minutes" if nEng else "-", "☐"],
        ["6", "Create DLP policy rules", _plural(nRule, "rule") if nRule else "Nothing to do", _fmt_minutes(m_rule), "About 30 minutes" if nRule else "-", "☐"],
        ["7", "Activate and test", f"{_plural(nDict, 'custom dictionary', 'custom dictionaries')}, 2 files each" if nDict else "Nothing to do", _fmt_minutes(m_test), "Same as by hand" if nDict else "-", "☐"],
        ["8", "Watch, tune and report back", "Weekly for 12 weeks, then every quarter", "After the build", "After the build", "☐"],
        ["", f"Total DLP build time (Steps {'3' if nPre else '4'} to 7)", "", f"{_fmt_minutes(hand_total)}, {_days(hand_total)}", f"{_fmt_minutes(api_total)}, {_days(api_total)}", ""],
    ]
    dd.table(["Step", "What you do", "How many", "Time by hand", "Time by API", "Done"], glance, [600, 2600, 1700, 1750, 1810, 900])
    dd.gap()
    dd.para("Time by hand is typing each item into the console: 20 minutes for each custom dictionary, 5 for each predefined dictionary, 10 for each engine and 15 for each rule. Time by API is a planning figure for deploying the pack's JSON through the app's Deploy Studio or the ZIA API: about 30 minutes for each of Steps 4 to 6, because the calls themselves take seconds. The steps below describe the build by hand.")

    dd.h2("Words used in this guide")
    prox_vals = sorted({int(d["proximity"]) for d in plain if str(d.get("proximity") or "").isdigit() or isinstance(d.get("proximity"), int)})
    prox_txt = f"This pack uses {_join([str(v) for v in prox_vals])}." if prox_vals else "This pack's custom dictionaries do not use it."
    words = [
        ["Dictionary", "A list of things to look for, such as a number pattern or a set of words."],
        ["Predefined dictionary", "A dictionary Zscaler has already built. It is always available; you only set its options."],
        ["Custom dictionary", "A dictionary you create by typing in a pattern or a list of words" + (f", or by cloning a predefined one. This pack has {nDict} of them." if nDict else ".")],
        ["Pattern", "A formula (regular expression) that describes the shape of a number or code. Copy it; never retype it."],
        ["Phrase", "A word or group of words to look for."],
        ["Count Unique / Count All", "Count Unique counts the same value once. Count All counts it every time it appears."],
        ["Proximity", "How close (in bytes, roughly characters) the words must be to the number. " + prox_txt],
        ["Engine", "A recipe that combines dictionaries, for example \"a number AND the words that go with it\"."],
        ["Anchor", "The identifier in an engine, such as an account or record number. Every engine has one."],
        ["Signal", "The supporting words or data that must appear together with the anchor."],
        ["Match count", "How many matches are needed. \"> 0\" means one or more. \"> 4\" means 5 or more."],
        ["Rule", f"Says where an engine applies and what happens. In this plan every inline DLP action is {act_phrase if all_allow else 'the one in the Step 6 table'}."],
        ["SSL/TLS inspection", "Lets Zscaler read encrypted web traffic. Without it, DLP cannot see file contents."],
        ["Client Connector", "The Zscaler app on each laptop that sends traffic to Zscaler."],
        ["Incident", "The record Zscaler creates when an engine matches."],
    ]
    dd.table(["Word", "What it means"], words, [2600, 6760])

    dd.h2("Which dictionaries are predefined and which are custom")
    pref = _common_prefix([_s(d["name"]) for d in pd.custom])
    if nPre:
        kinds = f"{_plural(nDict, 'dictionary', 'dictionaries')} {'is' if nDict == 1 else 'are'} custom and you create {'it' if nDict == 1 else 'them'} in Step 4" if nDict else "none is custom"
        dd.para(f"How to tell dictionaries apart: {kinds}; {nPre} {'is a' if nPre == 1 else 'are'} Zscaler predefined dictionar{'y' if nPre == 1 else 'ies'} that already exist{'s' if nPre == 1 else ''} and you only set an option (Step 3)."
                + (f" The names of the custom ones start with \"{pref}\"." if pref else ""))
    else:
        dd.para("How to tell dictionaries apart: every dictionary in this pack is custom, and you create it in Step 4." + (f" Each name starts with \"{pref}\"." if pref else ""))
    kind_rows: List[List[str]] = []
    for d in pd.custom:
        kind_rows.append([_s(d["name"]), f"Custom (clone of {_s(d.get('dict_template_name') or 'a predefined dictionary')})" if is_clone(d) else "Custom (you create)", "Create it", "Step 4"])
    for nm in pd.predefined:
        kind_rows.append([nm, "Predefined (Zscaler)", "Already exists - set its option only", "Step 3"])
    dd.table(["#", "Dictionary", "Predefined or custom", "What you do", "Where"], [[str(i + 1)] + r for i, r in enumerate(kind_rows)], [500, 3300, 2000, 2400, 1160]) if kind_rows else dd.para("This pack has no dictionaries.")

    # ── Step 1 ───────────────────────────────────────────────────────
    dd.h2("Step 1 — Check the basics are in place", page_break=True)
    dd.label("Goal", "Make sure traffic reaches Zscaler and can be read. If these are missing, nothing after this step will work.")
    dd.label("Where", "Each check names its own page.")
    dd.label("Time by hand", "About 1 hour.")
    dd.table(["Check", "How to confirm", "Done"], [
        ["You have an admin role that can edit DLP and policy", "You can open Data Security > Common Resources > Dictionaries & Engines (older consoles: Administration > DLP Dictionaries & Engines).", "☐"],
        ["A change window is agreed", "Your manager or change board has approved the date.", "☐"],
        ["SSL/TLS inspection is on for file sharing, webmail, Generative AI and social media", "Internet Access > Policy > SSL/TLS Inspection (older consoles: Policy > SSL Inspection) shows Inspect for these categories.", "☐"],
        ["Client Connector uses Z-Tunnel 2.0", "Client Connector Portal > forwarding profile shows Z-Tunnel 2.0. Ask a senior engineer if you do not have access.", "☐"],
        ["A DLP notification template exists", "Ask your senior engineer for the template name and write it here: ______________", "☐"],
    ], [3200, 5260, 900])
    dd.gap()
    dd.para("If a check fails: stop and ask a senior engineer before going on.")

    # ── Step 2 ───────────────────────────────────────────────────────
    dd.h2("Step 2 — Set the action for each unsanctioned app")
    dd.label("Goal", "Close the open doors first.")
    dd.para("This pack does not change cloud app actions, so there is nothing to change here. Go to Step 3.")

    # ── Step 3 ───────────────────────────────────────────────────────
    dd.h2("Step 3 — Set the confidence on Zscaler predefined dictionaries")
    dd.label("Goal", "Set the options on the Zscaler dictionaries the engines use.")
    if not nPre:
        dd.para("Nothing to do. This pack uses no predefined dictionaries on their own, so there is nothing to set. Go to Step 4.")
    else:
        dd.label("Where", "Data Security > Common Resources > Dictionaries & Engines (older consoles: Administration > DLP Dictionaries & Engines), DLP Dictionaries tab. Open each dictionary named below.")
        dd.label("Time by hand", _fmt_minutes(m_pre) + " (5 minutes each).")
        dd.para("These dictionaries already exist in every Zscaler tenant. Do not create or edit their patterns: only set the option in the table, then tick the box.")
        dd.table(["#", "Dictionary", "Status", "Option to set", "Used by engine", "Done"],
                 [[str(i + 1), nm, "Already exists - set its option only", predefined_option(pd, nm),
                   "; ".join(f"#{num.get(x, '?')}" for x in used_by.get(nm, [])), "☐"] for i, nm in enumerate(pd.predefined)],
                 [450, 2400, 1800, 2310, 1500, 900])
        dd.gap()
        dd.para("Check: after the last one, click Activate. If a name is not in the list, your tenant does not have that dictionary or licence: tell a senior engineer before you go on.")

    # ── Step 4 ───────────────────────────────────────────────────────
    dd.h2("Step 4 — Create custom dictionaries", page_break=True)
    if not nDict:
        dd.label("Goal", "Add the dictionaries Zscaler does not ship.")
        dd.para("Nothing to do. This pack defines no dictionaries of its own. Go to Step 5.")
    else:
        dd.label("Goal", "Add the dictionaries Zscaler does not ship. Each dictionary has its own form below.")
        dd.label("Where", "Data Security > Common Resources > Dictionaries & Engines (older consoles: Administration > DLP Dictionaries & Engines), DLP Dictionaries tab, Add DLP Dictionary.")
        dd.label("Time by hand", f"{_fmt_minutes(m_dict)} (20 minutes each).")
        dd.label("Time by API", "About 30 minutes for all of them, using the pack's JSON (Deploy Studio or the ZIA API). The API calls take seconds; the time is for running the deploy and checking the result.")
        steps4 = [
            "Click Add DLP Dictionary. The page looks like the forms below.",
            "Name: copy the Name from the form. Spelling and hyphens must be exactly the same.",
            "Dictionary Type: leave it on Patterns & Phrases.",
            "Match Type: choose the value in the form. When it is \"Match Any Patterns and Any Phrases\", a Proximity section appears: leave Near selected and type the Proximity Length from the form.",
            "Description: copy it from the form.",
            "Patterns: paste each pattern into a Pattern box and set the Action beside it. Copy the pattern from this document; never retype it. If the form has no Patterns section, leave the Pattern box empty.",
            "Phrases: paste the phrases into the Phrase box, one phrase per line, exactly as listed (keep any accents). Set the Action beside the box, then click Add Phrase.",
            "Non-delimited Unicode phrase matching: leave it Off; no dictionary here needs it.",
        ]
        if clones:
            steps4.append("Clones (the form says \"Clone Predefined Dictionary\"): find the Zscaler dictionary named in \"Clone of\", click Clone, then set the name, description, confidence, proximity and the other fields as the form shows.")
        steps4.append("Compare the page with the form from top to bottom, click Save and tick the box. After the last dictionary, click Activate.")
        dd.steps(steps4)
        dd.para("Remember: everything in this step is custom. It does not exist until you create it.", before=80)
        dd.para("How to read the forms: each form is laid out like the console page. A field with a thick blue outline is one you type or choose. A field with a thin grey outline should already show that value when the page opens.")
        cnt: Dict[str, int] = {}
        for d in plain:
            cnt[str(d.get("custom_phrase_match_type") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")] = cnt.get(str(d.get("custom_phrase_match_type") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"), 0) + 1

        def used(k: str, what: str = "") -> str:
            n = cnt.get(k, 0)
            return f"{_plural(n, 'dictionary', 'dictionaries')}{what}." if n else "Not used in this build."
        dd.table(["Match Type", "What it does", "Used in this build for"], [
            ["Match Any", "One pattern or one phrase is enough.", used("MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")],
            ["Match All", "Every pattern and every phrase must be found.", used("MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY")],
            ["Match Any Patterns and Any Phrases", "A pattern and a phrase must both be found, close together. The page adds a Proximity section (Near or Not Near, and Proximity Length).", used("MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE", ", each needing its label within the proximity")],
            ["Match Near or Not Near Phrases", "A phrase must be close to (or away from) another phrase.", "Not used in this build."],
        ], [2600, 3900, 2860])
        dd.gap()
        dd.para("The Action drop-down beside a pattern or a phrase has two options: Count Unique counts the same value once however often it appears; Count All counts every appearance.")
        for i, d in enumerate(pd.custom):
            kind = f"Clone of {_s(d.get('dict_template_name') or 'a predefined dictionary')}" if is_clone(d) else "Custom (you create)"
            dd.h2(f"4.{i + 1}  {_s(d['name'])}   [{kind}]   ☐", page_break=True)
            _dict_form(dd, d, is_clone(d))

    # ── Step 5 ───────────────────────────────────────────────────────
    dd.h2("Step 5 — Create DLP engines", page_break=True)
    if not nEng:
        dd.label("Goal", "Combine the dictionaries into engines.")
        dd.para("Nothing to do. This pack defines no engines. Go to Step 6.")
    else:
        dd.label("Goal", "Combine the dictionaries into engines. Each engine has its own form below.")
        dd.label("Where", "Data Security > Common Resources > Dictionaries & Engines (older consoles: Administration > DLP Dictionaries & Engines), DLP Engines tab, Add DLP Engine.")
        dd.label("Time by hand", f"{_fmt_minutes(m_eng)} (10 minutes each).")
        dd.label("Time by API", "About 30 minutes for all of them, using the pack's JSON.")
        dd.steps([
            "Click Add DLP Engine. Name: copy it from the form.",
            "Engine Builder: set the top Operator (ALL, ANY or EXCLUDE), then add each Operator and Dictionary line as the form shows, with the same match count after \">\". EXCLUDE is the NOT in the Expression Preview: the engine does not match when that dictionary is found.",
            "Compare the Expression Preview with the one in the form. They must be the same, word for word.",
            "Click Save and tick the box. After the last engine, click Activate.",
        ])
        own = {_s(d["name"]) for d in pd.custom}
        for i, e in enumerate(pd.engines):
            dd.h2(f"5.{i + 1}  {_s(e.get('name'))}   ☐", page_break=True)
            tr = pd.trees.get(_s(e.get("name")))
            _engine_form(dd, e, tr)
            dd.gap()
            names = list(dict.fromkeys([t.name for t in expression_terms(tr)] if tr is not None else [m.group(1).strip() for m in re.finditer(r"D:(.+?)\s*[<>=]", _s(e.get("expression")))]))
            cu = [n for n in names if n in own]
            pu = [n for n in names if n not in own]
            if cu:
                dd.para([("Dictionaries it uses: ", {"bold": True}), ("Custom (you create): " + ", ".join(cu), {})], after=60)
            if pu:
                dd.para([("" if cu else "Dictionaries it uses: ", {"bold": True}), ("Predefined (already exists): " + ", ".join(pu), {})], after=60)
            if not names:
                dd.para([("Dictionaries it uses: ", {"bold": True}), ("none", {})])
        dd.gap()
        dd.para("Check: every engine saves, then click Activate. If a dictionary is not in the drop-down list, it was not created or is named differently: compare the name with Step 3 and Step 4.")

    # ── Step 6 ───────────────────────────────────────────────────────
    dd.h2("Step 6 — Create DLP policy rules", page_break=True)
    if not nRule:
        dd.label("Goal", "Tell Zscaler where each engine applies.")
        dd.para("Nothing to do. This pack has no inline Web rules" + (f"; its {_plural(n_other, 'rule')} for other channels are in the pack's JSON and deploy from Deploy Studio." if n_other else ".") + " Go to Step 7.")
    else:
        dd.label("Goal", "Tell Zscaler where each engine applies. Create the rows in the order shown.")
        dd.label("Where", "Data Security > Inline DLP > Data Loss Prevention (older consoles: Policy > Data Loss Prevention), Add Rule.")
        dd.label("Time by hand", f"{_fmt_minutes(m_rule)} (15 minutes each).")
        dd.label("Time by API", "About 30 minutes for all of them, using the pack's JSON.")
        states = list(dict.fromkeys(str(r.get("state") or "DISABLED").title() for r in pd.web_rules))
        dd.steps([
            "Click Add Rule.",
            "Rule Name: copy the name from the table.",
            "Applies to: \"All web and cloud app uploads\" means leave URL Categories and Cloud Applications on Any. If the row names cloud app classes, choose those under Cloud Applications.",
            "Content Matching: choose Select DLP Engines and tick the engine listed for that row. The number is the engine number from Step 5 (#1 is engine 5.1).",
            "Minimum Data Size (KB): type the number in the table. 0 means no minimum.",
            f"Action: choose the value in the table ({_join(web_actions, 'or')}). On some consoles this field is called Data Traffic." + (" Every row uses Allow." if all_allow else ""),
            "Notification: select the DLP notification template you wrote down in Step 1, so each match raises an alert.",
            f"Rule Status: " + ("leave it Disabled until Step 7 has passed for that engine, then enable it." if all_disabled else f"set it as the plan says (the pack ships these rules as {_join(states)})."),
            "Click Save. Then use Edit Rule Order so the row sits at the Order number in the table, and tick the box. After the last row, click Activate.",
        ])
        rrows = []
        for i, r in enumerate(pd.web_rules):
            engs = [_s(x) for x in _list(r.get("engines"))]
            classes = _list(r.get("cloud_app_classes"))
            applies = ("Cloud app classes: " + ", ".join(_s(c) for c in classes) + " (inline)") if classes else "All web and cloud app uploads (inline)"
            rrows.append([str(i + 1), _s(r.get("name")), applies, "\n".join(f"#{num[x]} {x}" if x in num else x for x in engs) or "-", "0", _act_label(r.get("action"))])
        dd.table(["Order", "Rule name", "Applies to", "Engines to select", "Min size (KB)", "Action"], rrows, [700, 2500, 1900, 2560, 900, 800])
        dd.gap()
        more = f" The {_join(_channel_names(other))} versions of these rules ({n_other} more) are in the pack's JSON; deploy them from Deploy Studio, one channel per run, after the inline rules are tuned." if other else ""
        dd.para(f"Check: you have created {_plural(nRule, 'row')}, all set to {_join(web_actions, 'or') if web_actions else 'Allow'}. " + ("Every rule ships disabled." if all_disabled else "") + more)

    # ── Step 7 ───────────────────────────────────────────────────────
    dd.h2("Step 7 — Activate and test", page_break=True)
    dd.label("Goal", "Prove each engine finds what it should and ignores what it should not.")
    dd.label("Where", "Results: Data Explorer > Internet & SaaS > Web Insights > Logs (older consoles: Analytics > Web Insights > Logs). Show the DLP Engine and DLP Dictionary columns and filter on your own user name.")
    dd.label("Time by hand", _fmt_minutes(m_test) + ".")
    dd.para("Before you start: an engine only fires when its whole logic (section 2) is met in the file. For each row, make a \"should match\" file containing the example text. Then make a second file with only the \"should not match\" text. All numbers below are made up for testing.")
    dd.steps([
        "Ask your senior engineer which website to use for uploads and write it here: ______________",
        "Enable the rules for this test (Step 6), from a managed laptop upload the \"should match\" file to that website.",
        "Wait 5 minutes, then open the logs page. You should see an incident naming the engine in the last column.",
        "Repeat with the \"should not match\" file. There should be no incident.",
        "Repeat the \"should match\" check with a Word, an Excel, a PDF and a plain text version.",
        "Tick the box when both results are correct. If a result is wrong, write down the dictionary, the file and what you saw, and tell a senior engineer. Do not change the action.",
    ])
    trows = test_rows(pd)
    if trows:
        dd.table(["Test", "Should match", "Should not match", "Engine that should fire"], trows, [1600, 3600, 2300, 1860])
        dd.gap()
    else:
        dd.para("This pack has no engines to test.")
    dd.para("Long samples are shortened here; the full sample text and the generator are in tools/validate_detection.py. The pack can also be checked offline: run that tool and it repeats these samples, noise and look-alikes 100 times against the pack's dictionaries and engines. Step 7 confirms the same in your tenant.")

    # ── Step 8 ───────────────────────────────────────────────────────
    dd.h2("Step 8 — Watch, tune and report back")
    dd.label("Goal", f"Keep everything on {'Allow' if all_allow else 'the planned action'} while you learn what normal looks like, then tidy up noisy engines.")
    dd.label("Where", "Data Explorer > Internet & SaaS > Web Insights > Logs (older consoles: Analytics > Web Insights > Logs).")
    dd.label("Time by hand", "30 minutes a week.")
    dd.table(["When", "What to do", "Finished when", "Done"], [
        ["Weeks 0–4", "Each week, list the engines with the most incidents. Open ten incidents per engine and mark each one right or wrong.", "Every engine has produced incidents, or you know why it has not.", "☐"],
        ["Weeks 4–8", "For engines with many wrong matches, ask a senior engineer to add the organisation's own labels or words, or raise the match count, with the data owner's agreement.", "Wrong matches are 5 in 100 or fewer for each engine.", "☐"],
        ["Weeks 8–12", "Ask a senior engineer to switch on end-user notifications for the engines that are accurate. Do not change the action yourself; it stays as planned. Keep any engine marked low confidence in monitor.", "Wrong matches are 2 in 100 or fewer.", "☐"],
        ["Every quarter", "Repeat the Step 7 checks, and check whether Zscaler now ships a predefined dictionary that can replace a custom one.", "9 in 10 example files are detected.", "☐"],
    ], [1400, 4400, 2660, 900])

    # ── Assumptions and limits ───────────────────────────────────────
    dd.h2("Assumptions and limits")
    notes = [_s(n) for n in _list(meta.get("notes")) if isinstance(n, str) and n.strip()]
    for n in notes:
        dd.bullet(n)
    if not notes:
        dd.bullet("The pack's pack.json carries no notes.")
    if nPre:
        dd.bullet("Predefined dictionaries are Zscaler's own: their names and options can differ by licence and console version. Check each one in Step 3 against your tenant.")
    dd.bullet("This guide is operational reference, not legal advice." + (f" Your compliance and legal owners decide how {_join(regs)} apply and own any breach decision." if regs else " Your compliance and legal owners own any breach decision."))

    # ── Sign-off ─────────────────────────────────────────────────────
    dd.h2("Sign-off")
    dd.table(["Item", "Name", "Date"], [["Steps 1 to 7 completed by", "", ""], ["Checked by (senior engineer)", "", ""], ["Customer data owner informed", "", ""]], [4200, 3360, 1800])

    dd.doc.core_properties.title = f"DLP Policy Pack: {title_name}"
    dd.doc.core_properties.subject = "Build guide"
    buf = io.BytesIO()
    dd.doc.save(buf)
    return buf.getvalue()


def document_text(data: bytes) -> str:
    """All the text of a built guide (body paragraphs and every table cell, in order)."""
    doc = Document(io.BytesIO(data))
    out: List[str] = []
    body = doc.element.body
    for el in body.iter():
        if el.tag == qn("w:p"):
            out.append("".join(t.text or "" for t in el.iter(qn("w:t"))))
    return "\n".join(out)
