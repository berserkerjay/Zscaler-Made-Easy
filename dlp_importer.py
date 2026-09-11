#!/usr/bin/env python3
"""
DLP Policy Pack Importer — general-purpose library
====================================================
Imports DLP dictionaries (custom + clones), engines, and policies from
any pack directory containing JSON definition files. The pack layout:

    <pack_dir>/
      configs/
        dlp_dictionaries.json   (optional)
        dlp_engines.json        (optional)
        dlp_policies.json       (optional)
      pack.json                 (optional — metadata: name, version, description)

Or flat layout (JSON files directly in pack_dir):

    <pack_dir>/
      dlp_dictionaries.json
      dlp_engines.json
      dlp_policies.json

All functions accept a `pack_dir` path and a ZIA client instance.
They return structured dicts instead of printing, so the web GUI and
API server can stream progress to the frontend.

The fed_policy_pack/ directory ships as a built-in pack; users can
drop additional pack directories alongside it or upload zips via the
web GUI.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _nx(ret):
    if not isinstance(ret, tuple):
        return ret, None
    if len(ret) == 1:
        return ret[0], None
    return ret[0], ret[-1]


def _obj_to_dict(obj):
    if hasattr(obj, "to_dict"):
        return obj.to_dict()
    if hasattr(obj, "as_dict"):
        return obj.as_dict()
    if hasattr(obj, "__dict__"):
        return vars(obj)
    return obj


def _extract_id(response):
    if response and isinstance(response, tuple) and response[0] is not None:
        first = response[0]
        return first.id if hasattr(first, "id") else _obj_to_dict(first).get("id")
    return None


def _extract_error(response):
    if not response:
        return "No response"
    if isinstance(response, tuple) and len(response) > 2 and response[2]:
        err = response[2]
        if isinstance(err, dict):
            return err.get("message", str(err))
        return str(err)
    return "Unknown error"


# ---------------------------------------------------------------------------
# Pack discovery
# ---------------------------------------------------------------------------

PACKS_ROOT = os.path.dirname(os.path.abspath(__file__))


def _resolve_configs(pack_dir: str) -> str:
    """Return the directory containing the JSON files. Supports both
    <pack>/configs/ layout and flat layout."""
    configs = os.path.join(pack_dir, "configs")
    if os.path.isdir(configs):
        return configs
    return pack_dir


def _load_json(configs_dir: str, filename: str) -> List[Dict[str, Any]]:
    path = os.path.join(configs_dir, filename)
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_pack_metadata(pack_dir: str) -> Dict[str, Any]:
    """Load pack.json if present, merge with dir-inferred defaults.
    Counts (dictionaries / engines / policies) are ALWAYS computed from
    the on-disk JSON so the UI never shows a stale count from pack.json."""
    meta: Dict[str, Any] = {}
    meta_path = os.path.join(pack_dir, "pack.json")
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f) or {}
        except Exception:
            meta = {}
    configs = _resolve_configs(pack_dir)
    dicts = _load_json(configs, "dlp_dictionaries.json")
    engines = _load_json(configs, "dlp_engines.json")
    policies = _load_json(configs, "dlp_policies.json")
    # Inferred defaults — pack.json values win for 'name'/'description'/etc,
    # but counts are always authoritative from the on-disk files.
    meta.setdefault("name", os.path.basename(pack_dir).replace("_", " ").title())
    meta["dir"] = pack_dir
    meta["dictionaries"] = len(dicts)
    meta["engines"] = len(engines)
    # Endpoint sub-rules are rules too (created under their parent).
    meta["policies"] = len(policies) + sum(len(p.get("sub_rules") or []) for p in policies)
    meta["app_groups"] = len(_load_json(configs, "endpoint_application_groups.json"))
    channels: Dict[str, int] = {}
    for p in policies:
        ch = str(p.get("channel") or "web").strip().lower()
        channels[ch] = channels.get(ch, 0) + 1 + len(p.get("sub_rules") or [])
    meta["channels"] = channels
    return meta


def discover_packs(root: Optional[str] = None) -> List[Dict[str, Any]]:
    """Scan the project root for directories that look like DLP packs
    (contain configs/dlp_*.json or dlp_*.json at top level)."""
    root = root or PACKS_ROOT
    packs: List[Dict[str, Any]] = []
    seen: set = set()

    def scan(base: str, source: str) -> None:
        if not os.path.isdir(base):
            return
        for entry in sorted(os.listdir(base)):
            d = os.path.join(base, entry)
            if not os.path.isdir(d) or entry in seen:
                continue
            configs = _resolve_configs(d)
            has_json = any(
                f.startswith("dlp_") and f.endswith(".json")
                for f in os.listdir(configs)
            ) if os.path.isdir(configs) else False
            if has_json:
                meta = load_pack_metadata(d)
                meta["dir"] = d
                meta["id"] = entry
                meta["source"] = source
                packs.append(meta)
                seen.add(entry)

    scan(root, "built-in")
    # Packs added from Advanced settings (or dropped into user_packs/ by hand).
    try:
        from pack_library import user_packs_dir
        lib = user_packs_dir(root)
    except Exception:  # noqa: BLE001
        lib = os.path.join(root, "user_packs")
    if os.path.realpath(lib) != os.path.realpath(root):
        scan(lib, "uploaded")
    return packs


def load_pack_contents(pack_dir: str) -> Dict[str, Any]:
    """Load all three config files from a pack and return summary."""
    configs = _resolve_configs(pack_dir)
    dicts = _load_json(configs, "dlp_dictionaries.json")
    engines = _load_json(configs, "dlp_engines.json")
    policies = _load_json(configs, "dlp_policies.json")

    clone_count = sum(1 for d in dicts if d.get("predefined_clone"))
    return {
        "pack_dir": pack_dir,
        "metadata": load_pack_metadata(pack_dir),
        "dictionaries": {
            "total": len(dicts),
            "custom": len(dicts) - clone_count,
            "clones": clone_count,
            "items": [
                {
                    "name": d["name"],
                    "type": "clone" if d.get("predefined_clone") else "custom",
                    "patterns": len(d.get("patterns", [])),
                    "phrases": len(d.get("phrases", [])),
                    "proximity": d.get("proximity", 0),
                }
                for d in dicts
            ],
        },
        "engines": {
            "total": len(engines),
            "items": [{"name": e["name"]} for e in engines],
        },
        "policies": {
            "total": len(policies),
            "items": [
                {
                    "name": p["name"],
                    "action": p.get("action", "?"),
                    "severity": p.get("severity", "?"),
                    "engines": p.get("engines", []),
                    "channel": str(p.get("channel") or "web").strip().lower(),
                    "saas_type": p.get("saas_type"),
                }
                for p in policies
            ],
        },
    }


# ---------------------------------------------------------------------------
# Payload builders — shared by the per-pack importer below and by the
# multi-pack planner in pack_deploy.py so both produce identical API calls.
# ---------------------------------------------------------------------------

EMPTY_DICT_REASON = "no patterns/phrases"

# Documented ZIA custom-dictionary limits (Zscaler help: Configuring DLP
# Dictionaries): 8 patterns per dictionary, 256 bytes per pattern, proximity
# 0-10000 bytes, PCRE syntax without lookaround. Phrases fuzzy-match unless
# quoted, which is a design choice rather than a limit.
DICT_MAX_PATTERNS = 8
DICT_PATTERN_MAX_BYTES = 256
DICT_PROXIMITY_MAX = 10000
DICT_MAX_PHRASES = 256
DICT_PHRASE_MIN_BYTES, DICT_PHRASE_MAX_BYTES = 3, 128
ENGINE_COUNT_MAX = 999          # engine match counts accept any value under 1000
DICT_MATCH_TYPES = ("MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                    "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE")
# The only pattern-and-phrase match type on which ZIA accepts a proximity
# window ("Match any Patterns and any Phrases" in the portal).
DICT_PROXIMITY_MATCH_TYPE = "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
_LOOKAROUND_RE = re.compile(r"\(\?<?[=!]")
_COUNT_RE = re.compile(r"[<>=]=?\s*(\d+)")


def engine_limit_problems(expr: str) -> List[str]:
    """Reasons an engine expression would be rejected: match counts must be
    under 1000."""
    out: List[str] = []
    for n in _COUNT_RE.findall(expr or ""):
        if int(n) > ENGINE_COUNT_MAX:
            out.append(f"match count {n} is not accepted (engine counts must be under 1000)")
    return out


def dictionary_limit_problems(d: Dict[str, Any]) -> List[str]:
    """Plain-language reasons a custom dictionary would be rejected by ZIA
    (empty list when it is within the documented limits)."""
    out: List[str] = []
    pats = d.get("patterns") or []
    if len(pats) > DICT_MAX_PATTERNS:
        out.append(f"{len(pats)} patterns; ZIA allows at most {DICT_MAX_PATTERNS} per dictionary")
    for p in pats:
        pat = p.get("pattern", "") if isinstance(p, dict) else (p[1] if isinstance(p, (list, tuple)) and len(p) > 1 else str(p))
        if len(str(pat).encode("utf-8")) > DICT_PATTERN_MAX_BYTES:
            out.append(f"pattern longer than {DICT_PATTERN_MAX_BYTES} bytes: {str(pat)[:40]}…")
        if _LOOKAROUND_RE.search(str(pat)):
            out.append(f"pattern uses lookaround, which ZIA's PCRE does not support: {str(pat)[:40]}…")
    phrases = d.get("phrases") or []
    if len(phrases) > DICT_MAX_PHRASES:
        out.append(f"{len(phrases)} phrases; ZIA allows at most {DICT_MAX_PHRASES} per dictionary")
    for ph in phrases:
        text = ph.get("phrase", "") if isinstance(ph, dict) else (ph[1] if isinstance(ph, (list, tuple)) and len(ph) > 1 else str(ph))
        n = len(str(text).strip('"').encode("utf-8"))
        if n < DICT_PHRASE_MIN_BYTES or n > DICT_PHRASE_MAX_BYTES:
            out.append(f"phrase must be {DICT_PHRASE_MIN_BYTES}-{DICT_PHRASE_MAX_BYTES} bytes: {str(text)[:40]}")
    mt = d.get("custom_phrase_match_type")
    if mt and mt not in DICT_MATCH_TYPES:
        out.append(f"unknown match type {mt}; expected one of {', '.join(DICT_MATCH_TYPES)}")
    if mt == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE" and (not pats or not phrases):
        out.append("MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE needs at least one pattern and one phrase")
    prox = d.get("proximity") or 0
    try:
        prox = int(prox)
    except (TypeError, ValueError):
        out.append(f"proximity is not a number: {prox!r}")
        prox = 0
    if prox < 0 or prox > DICT_PROXIMITY_MAX:
        out.append(f"proximity {prox} is outside 0-{DICT_PROXIMITY_MAX} bytes")
    if prox > 0 and mt and mt != DICT_PROXIMITY_MATCH_TYPE and not d.get("predefined_clone"):
        # ZIA: "Proximity can be enabled only for 'Match any Patterns and any
        # Phrases' or 'Match Near or Not Near Phrases' match types."
        out.append(f"proximity {prox} needs match type {DICT_PROXIMITY_MATCH_TYPE} (any pattern within {prox} bytes of any phrase); "
                   f"ZIA rejects proximity on {mt}")
    return out

# ZIA caps a DLP dictionary description at 255 characters (the Terraform
# provider validates the same range) and a DLP engine description at the
# same 255 ("DLP engine description can not be more than 255 characters"
# from a real tenant); rule descriptions allow far more.
DICT_DESCRIPTION_MAX = 255
ENGINE_DESCRIPTION_MAX = 255
# "DLP Engine name can only have alphanumeric, underscore, hyphen, dot,
# paranthesis and space" (a real tenant's answer to "HIPAA Narrative / Low
# Volume"). Dictionaries are held to the same characters, which every
# production-deployed pack satisfies.
NAME_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_\-. ()]+$")
NAME_RULE = "only letters, digits, underscore, hyphen, dot, parentheses and space"


def name_problems(name: str, kind: str = "engine") -> List[str]:
    """Plain-language reasons ZIA would refuse an object name."""
    n = (name or "").strip()
    if not n:
        return [f"{kind} has no name"]
    if not NAME_ALLOWED_RE.match(n):
        bad = sorted({c for c in n if not NAME_ALLOWED_RE.match(c)})
        return [f"{kind} name '{n}' uses {', '.join(repr(c) for c in bad)}; ZIA allows {NAME_RULE}"]
    return []


def _blen(s: str) -> int:
    return len(s.encode("utf-8"))


def _cut_bytes(s: str, limit: int) -> str:
    """Longest prefix of s that fits in `limit` UTF-8 bytes, ending with '...'."""
    if limit <= 3:
        return ""
    out = s.encode("utf-8")[: limit - 3].decode("utf-8", errors="ignore").rstrip()
    return out + "..."


def fit_description(base: Optional[str], tag: str = "", limit: int = DICT_DESCRIPTION_MAX) -> str:
    """Join a description and a provenance tag within `limit` UTF-8 BYTES
    (ZIA and the provider measure bytes), shortening the description —
    never the tag — with an ASCII ellipsis."""
    base = (base or "").strip()
    tag = (tag or "").strip()
    if not tag:
        return base if _blen(base) <= limit else _cut_bytes(base, limit)
    room = limit - _blen(tag) - 1
    if room <= 0:
        return tag.encode("utf-8")[:limit].decode("utf-8", errors="ignore")
    if _blen(base) > room:
        base = _cut_bytes(base, room)
    return f"{base} {tag}".strip()


# The same predefined dictionary is exported under its API name by some
# tenants and its portal display name by others; packs use either. Both
# resolve, so a pack written against one export works against the other.
PREDEFINED_TEMPLATE_ALIASES: Dict[str, str] = {
    "Social Security Numbers (US)": "SSN", "Drivers License (United States)": "USDL_LEAKAGE", "Credit Cards": "CREDIT_CARD",
    "ABA Bank Routing Number": "ABA_LEAKAGE", "Tax Identification Number (US)": "USITIN_LEAKAGE",
    "International Bank Account Number (EU)": "EUIBAN_LEAKAGE", "Credentials Leakage": "CRED_LEAKAGE",
    "Financial Statements": "FINANCIAL", "Medical Information": "MEDICAL",
    # Portal display names the healthcare build uses (codes as the API exports them).
    "Medical Document": "ML_MEDICAL_DOC_LEAKAGE", "Drugs Information": "DRUGS_LEAKAGE", "Diseases Information": "DISEASES_LEAKAGE",
    "Credentials and Secrets": "CRED_LEAKAGE", "Tax Document": "ML_TAX_LEAKAGE", "ABA Bank Routing Numbers": "ABA_LEAKAGE",
    "Driver's License (United States)": "USDL_LEAKAGE",
}
# Codes map back to ONE display name (the first written above wins).
_display = {}
for _k, _v in list(PREDEFINED_TEMPLATE_ALIASES.items()):
    _display.setdefault(_v, _k)
PREDEFINED_TEMPLATE_ALIASES.update(_display)
# Every display name of a code resolves to the code as well.
_CODE_DISPLAY_NAMES: Dict[str, List[str]] = {}
for _k, _v in list(PREDEFINED_TEMPLATE_ALIASES.items()):
    if _k != _display.get(_v, _k):
        _CODE_DISPLAY_NAMES.setdefault(_v, []).append(_k)


def predefined_candidates(name: Optional[str]) -> List[str]:
    """The name as written, its API code, and every display name of that code."""
    if not name:
        return []
    out = [name]
    code = PREDEFINED_TEMPLATE_ALIASES.get(name)
    if code and code != name:
        out.append(code)
    for c in list(out):
        for disp in _CODE_DISPLAY_NAMES.get(c, []):
            if disp not in out:
                out.append(disp)
    return out


def template_candidates(name: Optional[str]) -> List[str]:
    """The name as written plus its known aliases (API code and display names)."""
    return predefined_candidates(name)


def resolve_template(name: Optional[str], predefined_name_to_id: Dict[str, Any]) -> Any:
    """Tenant id of a predefined dictionary by either of its names, or None."""
    for cand in template_candidates(name):
        if cand in predefined_name_to_id:
            return predefined_name_to_id[cand]
    return None


def build_dict_kwargs(
    d: Dict[str, Any], predefined_name_to_id: Dict[str, Any]
) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    """Translate one pack dictionary definition into `add_dict` kwargs.

    Returns (kwargs, error). `error` is EMPTY_DICT_REASON for a custom
    dictionary with nothing to match on (importer skips it), or a message
    when a clone's template can't be resolved in the tenant (importer
    fails it)."""
    is_clone = bool(d.get("predefined_clone"))
    if is_clone:
        template_id = d.get("dict_template_id")
        template_name = d.get("dict_template_name")
        if not template_id and template_name:
            template_id = resolve_template(template_name, predefined_name_to_id)
        if not template_id:
            return None, f"No template ID for '{template_name}'"
        kwargs: Dict[str, Any] = {
            "description": fit_description(d.get("description", "")),
            "dict_template_id": int(template_id),
            "custom": True,
        }
    else:
        if not d.get("patterns") and not d.get("phrases"):
            return None, EMPTY_DICT_REASON
        limit_problems = dictionary_limit_problems(d)
        if limit_problems:
            return None, "outside ZIA's documented dictionary limits: " + "; ".join(limit_problems)
        kwargs = {"description": fit_description(d.get("description", ""))}

    for opt in ("confidence_threshold", "confidence_level_for_predefined_dict", "hierarchical_identifiers"):
        if d.get(opt):
            kwargs[opt] = d[opt]
    for flag in ("include_bin_numbers", "include_ssn_numbers"):
        if d.get(flag):
            kwargs[flag] = True

    proximity = d.get("proximity") or 0
    if proximity > 0:
        kwargs["proximity"] = proximity
        kwargs["proximity_length_enabled"] = True
        if not is_clone:
            kwargs["proximity_enabled_for_custom_dictionary"] = True

    if d.get("patterns"):
        kwargs["patterns"] = [(p["action"], p["pattern"]) for p in d["patterns"]]
    if d.get("phrases"):
        kwargs["phrases"] = [(p["action"], p["phrase"]) for p in d["phrases"]]
    return kwargs, None


def resolve_engine_expression(expr: str, dict_name_to_id: Dict[str, Any]) -> Tuple[str, List[str]]:
    """Rewrite symbolic `D:<dictionary name>` references to the API's
    `D<id>.S` form. Longest names are substituted first so a name that is
    a prefix of another can't clobber it. Returns (expression, unresolved)
    where `unresolved` lists any `D:` references that had no matching
    dictionary."""
    for dict_name in sorted(dict_name_to_id.keys(), key=len, reverse=True):
        placeholder = f"D:{dict_name}"
        if placeholder in expr:
            expr = expr.replace(placeholder, f"D{dict_name_to_id[dict_name]}.S")
    # ZIA's grammar wants every dictionary term compared to a count
    # (`D63.S > 1`); a bare term means "at least one match". Terms inside a
    # Sum — `(D63.S + D64.S) > 1`, the Engine Builder's Sum operator — carry
    # no comparison of their own.
    expr = default_counts(expr, _BARE_TERM_RE)
    # Paren-aware: a missing "Names (US)" or "Driver's License (United States)"
    # must come back whole, or the pruning step cannot find it, the engine
    # is blocked, and every rule behind it is skipped.
    unresolved = [u.strip() for u in find_refs(expr) if u.strip()]
    return expr, unresolved


_BARE_TERM_RE = re.compile(r"(D\d+\.S)(?!\s*[<>=+])")


def default_counts(expr: str, term_re: "re.Pattern") -> str:
    """Append `> 0` to every dictionary term that has no comparison and is
    not part of a Sum (`a + b`)."""
    out, last = [], 0
    for m in term_re.finditer(expr):
        before = expr[:m.start()].rstrip()
        after = expr[m.end():].lstrip()
        in_sum = before.endswith("+") or after.startswith("+")
        out.append(expr[last:m.end()])
        if not in_sum:
            out.append(" > 0")
        last = m.end()
    out.append(expr[last:])
    return "".join(out)


# A leftover `D:<name>` runs until the next boolean operator, closing paren,
# proximity operator, or end of expression. (The original script's pattern
# skipped any name beginning with "D", hiding e.g. "Date of Birth".)
_UNRESOLVED_REF_RE = re.compile(r"D:([^&|>+]+?)\s*(?=\bAND\b|\bOR\b|\)|>|\+|$)")


_ENGINE_TOKEN_RE = re.compile(r"\(|\)|\bAND\s+NOT\b|\bAND\b|\bOR\b|\+|§[KP]\d+§(?:\s*[<>=]+\s*\d+)?|[<>=]+\s*\d+|\s+")


def prune_engine_terms(expr: str, prune: Iterable[str], known: Iterable[str]) -> Tuple[Optional[str], List[str]]:
    """Drop every `D:<name>` term that names one of `prune` from an engine
    expression, keeping the boolean structure valid: an operator whose
    operand went away goes with it, an emptied group disappears, and an
    `AND NOT` over a pruned term is simply dropped. `known` lists the
    dictionary names that must survive. Returns (expression, pruned
    names); expression is None when nothing meaningful would be left or
    the expression could not be parsed."""
    prune_l, known_l = [n for n in prune if n], [n for n in known if n]
    if not prune_l:
        return expr, []
    names = sorted({(n, "P") for n in prune_l} | {(n, "K") for n in known_l if n not in prune_l}, key=lambda t: -len(t[0]))
    back: Dict[str, str] = {}
    work = expr
    for i, (n, tag) in enumerate(names):
        key = f"§{tag}{i}§"
        pat = re.compile(r"D:" + re.escape(n) + r"(?=\s*(?:\bAND\b|\bOR\b|\)|>|<|=|\+|$))")
        if pat.search(work):
            work = pat.sub(key, work)
            back[key] = f"D:{n}"
    pos, toks = 0, []
    for m in _ENGINE_TOKEN_RE.finditer(work):
        if m.start() != pos:
            return None, []          # unparseable text between tokens
        if not m.group(0).isspace():
            toks.append(m.group(0))
        pos = m.end()
    if pos != len(work):
        return None, []

    def parse(i: int):
        items: list = []
        op = None
        while i < len(toks):
            t = toks[i]
            if t == "(":
                node, i = parse(i + 1)
                if i >= len(toks) or toks[i] != ")":
                    raise ValueError("unbalanced")
                i += 1
                # A Sum group carries its comparison after the parenthesis: (a + b) > n
                if i < len(toks) and re.fullmatch(r"[<>=]+\s*\d+", toks[i]):
                    node = ("group", node[1], re.sub(r"\s+", " ", toks[i])); i += 1
                items.append((op, node)); op = None
            elif t == ")":
                break
            elif re.fullmatch(r"AND\s+NOT|AND|OR|\+", t):
                op = re.sub(r"\s+", " ", t); i += 1
            elif re.fullmatch(r"[<>=]+\s*\d+", t):
                raise ValueError("comparison without a group")
            else:
                items.append((op, ("term", t))); op = None; i += 1
        return ("group", items), i

    try:
        tree, end = parse(0)
        if end != len(toks):
            return None, []
    except ValueError:
        return None, []

    dropped: set = set()

    def cut(node):
        if node[0] == "term":
            key = node[1].split()[0]
            if key.startswith("§P"):
                dropped.add(back.get(key, key).replace("D:", "", 1)); return None
            return node
        kept = []
        for op, child in node[1]:
            c = cut(child)
            if c is not None:
                kept.append((op, c))
        if not kept:
            return None
        kept[0] = (None, kept[0][1])
        return ("group", kept) + tuple(node[2:])

    def render(node, root: bool = False) -> str:
        if node[0] == "term":
            t = node[1]
            for key, name in back.items():
                t = t.replace(key, name)
            return t
        parts = []
        for op, child in node[1]:
            parts.append((op + " " if op else "") + render(child))
        body = " ".join(parts)
        cmp = (" " + node[2]) if len(node) > 2 and node[2] else ""
        # The root is the expression itself, not a parenthesised group.
        return body if root else "(" + body + ")" + cmp

    pruned_tree = cut(tree)
    if pruned_tree is None:
        return None, sorted(dropped)
    out = render(pruned_tree, root=True)
    if "D:" not in out:
        return None, sorted(dropped)
    return out, sorted(dropped)


def find_refs(expr: str) -> List[str]:
    """Every `D:<name>` reference in an engine expression, in order, with
    the name read paren-aware: a name may contain balanced parentheses
    ("Names (US)"), and ends at a comparison, an AND / OR / +, a closing
    parenthesis that is not the name's own, or the end."""
    out: List[str] = []
    i = 0
    n = len(expr or "")
    while True:
        i = expr.find("D:", i)
        if i < 0:
            break
        j = i + 2
        depth = 0
        while j < n:
            ch = expr[j]
            rest = expr[j:]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            elif depth == 0 and (ch in "<>=+" or re.match(r"\s+(?:AND|OR)\b", rest) or re.match(r"\s+[<>=+]", rest) or re.match(r"\s+\)", rest)):
                break
            j += 1
        name = expr[i + 2:j].strip()
        if name:
            out.append(name)
        i = j if j > i + 2 else i + 2
    return out


def engine_references(expr: str, candidate_names: Iterable[str]) -> List[str]:
    """Return the candidate dictionary names an expression references as
    `D:<name>`, requiring an operator/paren/end boundary after the name so
    a name that is a prefix of another ("Alpha" vs "Alpha Dict") is not a
    false hit."""
    found = []
    for name in candidate_names:
        if re.search(r"D:" + re.escape(name) + r"(?=\s*(?:\bAND\b|\bOR\b|\)|>|\+|$))", expr):
            found.append(name)
    return found


def build_policy_payload(
    policy_def: Dict[str, Any], engine_ids: List[Any], *, use_rank_0: bool = False
) -> Dict[str, Any]:
    """Translate one pack policy definition into `add_rule` kwargs. New
    rules are always inserted at order 1 (top of the policy), which is
    why the planner reports an order shift for existing rules."""
    action = str(policy_def.get("action", "ALLOW") or "ALLOW")
    payload: Dict[str, Any] = {
        "name": policy_def["name"],
        "order": "1",
        # Every rule is created DISABLED and monitor-only, whatever the pack
        # says; a designed BLOCK / CONFIRM stays in the plan as the target.
        "state": "DISABLED",
        "action": "ALLOW" if action.upper() in ("BLOCK", "CONFIRM", "ICAP_RESPONSE") else action,
        "dlp_engines": engine_ids,
        "protocols": policy_def.get("protocols", ["ANY_RULE"]),
        "rank": 0 if use_rank_0 else policy_def.get("rank", 7),
    }
    for opt in ("description", "severity", "min_size", "file_types", "cloud_applications"):
        if policy_def.get(opt):
            payload[opt] = policy_def[opt]
    for field in ("locations", "location_groups", "groups", "departments", "users", "url_categories", "labels"):
        if policy_def.get(field):
            payload[field] = policy_def[field]
    for flag in ("match_only", "without_content_inspection", "ocr_enabled", "zscaler_incident_receiver"):
        if policy_def.get(flag):
            payload[flag] = True
    return payload


# ---------------------------------------------------------------------------
# Import operations — each returns a structured result dict and calls an
# optional `on_progress(msg: str)` callback for live streaming.
# ---------------------------------------------------------------------------

LogFn = Optional[Callable[[str], None]]


def import_dictionaries(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 1: create missing dictionaries (custom + clones)."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_dictionaries.json")
    if not desired:
        return {"phase": "dictionaries", "status": "skipped", "reason": "no file"}

    _log(f"Loaded {len(desired)} dictionary definitions")

    existing_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return {"phase": "dictionaries", "status": "error", "error": str(err)}

    existing_names: Dict[str, int] = {}
    predefined_name_to_id: Dict[str, int] = {}
    for d in existing_dicts:
        dd = _obj_to_dict(d)
        name = dd.get("name", "").strip()
        existing_names[name] = dd.get("id")
        if not dd.get("custom", False):
            predefined_name_to_id[name] = dd.get("id")

    missing = [d for d in desired if d["name"].strip() not in existing_names]
    if not missing:
        _log("All dictionaries already exist")
        return {"phase": "dictionaries", "status": "ok", "created": 0, "skipped": 0, "failed": 0, "total": len(desired)}

    _log(f"Creating {len(missing)} missing dictionaries")
    created, failed, skipped = 0, 0, 0
    details: List[Dict[str, Any]] = []

    for d in missing:
        name = d["name"]
        try:
            kwargs, build_err = build_dict_kwargs(d, predefined_name_to_id)
            if build_err == EMPTY_DICT_REASON:
                skipped += 1
                details.append({"name": name, "status": "skipped", "reason": build_err})
                continue
            if build_err:
                failed += 1
                details.append({"name": name, "status": "failed", "error": build_err})
                continue

            response = zia.dlp_dictionary.add_dict(
                name, d["custom_phrase_match_type"], "PATTERNS_AND_PHRASES", **kwargs
            )
            new_id = _extract_id(response)
            if new_id:
                created += 1
                details.append({"name": name, "status": "created", "id": new_id})
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Dictionaries: {created} created, {skipped} skipped, {failed} failed")
    return {"phase": "dictionaries", "status": "ok", "created": created, "skipped": skipped, "failed": failed, "total": len(desired), "details": details}


def import_engines(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 2: create missing engines, resolving D:name → D<id>.S."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_engines.json")
    if not desired:
        return {"phase": "engines", "status": "skipped", "reason": "no file"}

    _log(f"Loaded {len(desired)} engine definitions")

    existing_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    if err:
        return {"phase": "engines", "status": "error", "error": str(err)}
    existing_names = {e.name.strip() for e in existing_engines if e.name}

    missing = [e for e in desired if e["name"].strip() not in existing_names]
    if not missing:
        _log("All engines already exist")
        return {"phase": "engines", "status": "ok", "created": 0, "failed": 0, "total": len(desired)}

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return {"phase": "engines", "status": "error", "error": f"Could not fetch dictionaries: {err}"}
    dict_name_to_id = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d).get("id") for d in all_dicts}

    _log(f"Creating {len(missing)} missing engines")
    created, failed = 0, 0
    details: List[Dict[str, Any]] = []

    for engine_def in missing:
        name = engine_def["name"]
        try:
            expr, unresolved = resolve_engine_expression(engine_def["expression"], dict_name_to_id)
            response = zia.dlp_engine.add_dlp_engine(
                name=name,
                engine_expression=expr,
                custom_dlp_engine=True,
                description=engine_def.get("description", "Imported engine"),
            )
            new_id = _extract_id(response)
            if new_id:
                created += 1
                detail = {"name": name, "status": "created", "id": new_id}
                if unresolved:
                    detail["warnings"] = [f"Unresolved: {u}" for u in unresolved]
                details.append(detail)
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Engines: {created} created, {failed} failed")
    return {"phase": "engines", "status": "ok", "created": created, "failed": failed, "total": len(desired), "details": details}


def import_policies(
    client, pack_dir: str, *, use_rank_0: bool = False, log: LogFn = None
) -> Dict[str, Any]:
    """Phase 3: create missing DLP web rules."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    desired = _load_json(configs, "dlp_policies.json")
    if not desired:
        return {"phase": "policies", "status": "skipped", "reason": "no file"}

    non_web = [p["name"] for p in desired if str(p.get("channel") or "web").lower() != "web"]
    if non_web:
        # The single-pack importer only handles inline web rules; endpoint /
        # SaaS / email rules need the prerequisite checks in pack_deploy.
        _log(f"Skipping {len(non_web)} non-web policies (use Deploy Studio / pack_deploy): {', '.join(non_web)}")
        desired = [p for p in desired if str(p.get("channel") or "web").lower() == "web"]
    _log(f"Loaded {len(desired)} web policy definitions")

    existing_rules, err = _nx(client.zia.dlp_web_rules.list_rules())
    if err:
        return {"phase": "policies", "status": "error", "error": str(err)}
    existing_names = {r.name.strip() for r in existing_rules if r.name}

    missing = [p for p in desired if p["name"].strip() not in existing_names]
    if not missing:
        _log("All policies already exist")
        return {"phase": "policies", "status": "ok", "created": 0, "failed": 0, "total": len(desired)}

    all_engines, err = _nx(client.zia.dlp_engine.list_dlp_engines_lite())
    if err:
        return {"phase": "policies", "status": "error", "error": f"Could not fetch engines: {err}"}
    engine_name_to_id = {e.name.strip(): e.id for e in all_engines if e.name}

    _log(f"Creating {len(missing)} missing policies")
    created, failed = 0, 0
    details: List[Dict[str, Any]] = []

    for policy_def in missing:
        name = policy_def["name"]
        try:
            engine_names = policy_def.get("engines", [])
            engine_ids = [engine_name_to_id[n] for n in engine_names if n in engine_name_to_id]
            if not engine_ids:
                failed += 1
                details.append({"name": name, "status": "failed", "error": "No valid engines found"})
                continue

            payload = build_policy_payload(policy_def, engine_ids, use_rank_0=use_rank_0)
            response = client.zia.dlp_web_rules.add_rule(**payload)
            new_id = _extract_id(response)
            if new_id:
                created += 1
                details.append({"name": name, "status": "created", "id": new_id})
                _log(f"  Created: {name} (ID {new_id})")
            else:
                failed += 1
                details.append({"name": name, "status": "failed", "error": _extract_error(response)})
        except Exception as e:
            failed += 1
            details.append({"name": name, "status": "failed", "error": str(e)[:200]})

    _log(f"Policies: {created} created, {failed} failed")
    return {"phase": "policies", "status": "ok", "created": created, "failed": failed, "total": len(desired), "details": details}


# ---------------------------------------------------------------------------
# Verification — compares deployed state against the pack's JSON definitions
# ---------------------------------------------------------------------------

def verify_deployment(
    zia, pack_dir: str, *, log: LogFn = None
) -> Dict[str, Any]:
    """Compare deployed dictionaries + engines against the pack's JSON files."""
    _log = log or (lambda m: None)
    configs = _resolve_configs(pack_dir)
    result: Dict[str, Any] = {"phase": "verify", "dictionaries": {}, "engines": {}, "all_good": True}

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    deployed_map = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d) for d in all_dicts} if not err else {}

    all_engines, err = _nx(zia.dlp_engine.list_dlp_engines_lite())
    deployed_engine_names = {e.name.strip() for e in all_engines if e.name} if not err else set()

    # Dictionary verification
    desired_dicts = _load_json(configs, "dlp_dictionaries.json")
    missing_dicts: List[str] = []
    mismatched: Dict[str, List[str]] = {}

    def _extract_items(item_list, key_name):
        out = set()
        if not item_list:
            return out
        for item in item_list:
            item_d = item if isinstance(item, dict) else _obj_to_dict(item)
            out.add((item_d.get("action", ""), item_d.get(key_name, "")))
        return out

    for d_json in desired_dicts:
        dname = d_json["name"].strip()
        if dname not in deployed_map:
            missing_dicts.append(dname)
            continue
        dd = deployed_map[dname]
        issues = []
        exp_prox = d_json.get("proximity") or 0
        act_prox = dd.get("proximity") or 0
        if exp_prox != act_prox:
            issues.append(f"Proximity mismatch (expected {exp_prox}, got {act_prox})")
        if exp_prox > 0:
            if not dd.get("proximity_length_enabled", dd.get("proximityLengthEnabled", False)):
                issues.append("proximity_length_enabled missing")
            if not d_json.get("predefined_clone") and not dd.get(
                "proximity_enabled_for_custom_dictionary",
                dd.get("proximityEnabledForCustomDictionary", False),
            ):
                issues.append("custom proximity flag missing")
        if _extract_items(d_json.get("patterns", []), "pattern") != _extract_items(dd.get("patterns", []), "pattern"):
            issues.append("Pattern content mismatch")
        if _extract_items(d_json.get("phrases", []), "phrase") != _extract_items(dd.get("phrases", []), "phrase"):
            issues.append("Phrase content mismatch")
        if issues:
            mismatched[dname] = issues

    result["dictionaries"] = {"missing": missing_dicts, "mismatched": mismatched, "total": len(desired_dicts), "ok": len(desired_dicts) - len(missing_dicts) - len(mismatched)}

    # Engine verification
    desired_engines = _load_json(configs, "dlp_engines.json")
    desired_engine_names = {e["name"].strip() for e in desired_engines}
    missing_engines = sorted(desired_engine_names - deployed_engine_names)
    result["engines"] = {"missing": missing_engines, "total": len(desired_engines), "ok": len(desired_engines) - len(missing_engines)}

    result["all_good"] = not missing_dicts and not mismatched and not missing_engines
    _log("Verification passed" if result["all_good"] else "Verification found issues")
    return result


# ---------------------------------------------------------------------------
# Post-import confidence tweaks (generic — driven by pack.json or defaults)
# ---------------------------------------------------------------------------

DEFAULT_CONFIDENCE_TWEAKS = [
    {"name": "MEDICAL", "target_confidence": "CONFIDENCE_LEVEL_LOW", "label": "Medical → Low confidence"},
    {"name_patterns": ["Financial Document", "Financial Documents", "FINANCIAL_DOCUMENT", "FINANCIAL_DOCUMENTS", "FINANCIAL"],
     "target_confidence": "CONFIDENCE_LEVEL_HIGH", "label": "Financial → High confidence"},
]


def apply_confidence_tweaks(
    zia, tweaks: Optional[List[Dict[str, Any]]] = None, *, log: LogFn = None
) -> List[Dict[str, Any]]:
    """Apply confidence-level overrides to named dictionaries.
    `tweaks=None` means the pack didn't say, so DEFAULT_CONFIDENCE_TWEAKS
    apply; an explicit empty list means the pack opted out."""
    _log = log or (lambda m: None)
    if tweaks is None:
        tweaks = DEFAULT_CONFIDENCE_TWEAKS
    if not tweaks:
        return []

    all_dicts, err = _nx(zia.dlp_dictionary.list_dicts())
    if err:
        return [{"status": "error", "error": str(err)}]
    dict_map = {_obj_to_dict(d).get("name", "").strip(): _obj_to_dict(d) for d in all_dicts}

    results = []
    for tweak in tweaks:
        candidates = tweak.get("name_patterns") or ([tweak["name"]] if tweak.get("name") else [])
        match = next((dict_map[n] for n in candidates if n in dict_map), None)
        if not match:
            results.append({"label": tweak.get("label", "?"), "status": "not_found"})
            continue
        mid = match.get("id")
        mname = match.get("name")
        try:
            _, _, err2 = zia.dlp_dictionary.update_dict(
                mid,
                name=mname,
                dictionary_type=match.get("dictionary_type", "PATTERNS_AND_PHRASES"),
                custom_phrase_match_type=match.get("custom_phrase_match_type", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"),
                confidence_threshold=tweak["target_confidence"],
            )
            if err2:
                results.append({"label": tweak.get("label", mname), "status": "failed", "error": str(err2)})
            else:
                results.append({"label": tweak.get("label", mname), "status": "applied", "id": mid})
                _log(f"  Applied: {tweak.get('label', mname)}")
        except Exception as e:
            results.append({"label": tweak.get("label", mname), "status": "failed", "error": str(e)[:200]})
    return results


# ---------------------------------------------------------------------------
# Full import — orchestrates all phases
# ---------------------------------------------------------------------------

def run_full_import(
    client,
    pack_dir: str,
    *,
    use_rank_0: bool = False,
    apply_tweaks: bool = True,
    verify: bool = True,
    log: LogFn = None,
) -> Dict[str, Any]:
    """Run the complete 5-phase import pipeline for any DLP pack."""
    _log = log or (lambda m: None)
    started = time.time()
    results: Dict[str, Any] = {"pack_dir": pack_dir, "phases": {}}

    meta = load_pack_metadata(pack_dir)
    _log(f"Importing pack: {meta.get('name', pack_dir)}")

    # Phase 1
    _log("Phase 1: Dictionaries")
    results["phases"]["dictionaries"] = import_dictionaries(client.zia, pack_dir, log=log)

    # Phase 2
    _log("Phase 2: Engines")
    results["phases"]["engines"] = import_engines(client.zia, pack_dir, log=log)

    # Phase 3
    _log("Phase 3: Policies")
    results["phases"]["policies"] = import_policies(client, pack_dir, use_rank_0=use_rank_0, log=log)

    # Phase 4 — confidence tweaks (pack-specific or defaults)
    if apply_tweaks:
        _log("Phase 4: Confidence tweaks")
        pack_tweaks = meta.get("confidence_tweaks")
        results["phases"]["tweaks"] = apply_confidence_tweaks(client.zia, pack_tweaks, log=log)

    # Phase 5 — verification
    if verify:
        _log("Phase 5: Verification")
        results["phases"]["verify"] = verify_deployment(client.zia, pack_dir, log=log)

    results["elapsed_seconds"] = round(time.time() - started, 2)
    results["metadata"] = meta
    return results
