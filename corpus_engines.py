"""Local corpus test, beyond the custom dictionaries.

Zscaler does not expose the patterns behind its predefined dictionaries,
so a corpus test on the laptop can only *approximate* them. This module
carries local detectors for the pattern-based ones (numbers with a
checksum or a fixed shape: card numbers, SSNs, routing numbers, IBANs,
NPIs, e-mail addresses, cloud keys, private keys …), matched to the
tenant's predefined dictionaries by name. Dictionaries whose detection
is machine-learning or content-based (financial statements, medical
records, source code, resumes …) cannot be run offline and are reported
as *not simulated*, never guessed.

With every dictionary's hit count known (custom: exact, predefined:
approximate or unknown), each engine's expression is evaluated the way
ZIA evaluates it — `D<id>.S > n` terms joined by AND / OR / NOT with
parentheses — giving three answers: fires, does not fire, or *possible*
when the outcome hinges on a dictionary that could not be simulated.
The rules that reference a firing engine are listed with it.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

# ── Validators ─────────────────────────────────────────────────────────

def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 12:
        return False
    total, parity = 0, len(d) % 2
    for i, n in enumerate(d):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def ssn_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9:
        return False
    area, group, serial = d[:3], d[3:5], d[5:]
    if area in ("000", "666") or area.startswith("9") or group == "00" or serial == "0000":
        return False
    if d in ("078051120", "219099999", "123456789"):
        return False
    return True


def aba_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    if len(d) != 9:
        return False
    n = [int(c) for c in d]
    checksum = (3 * (n[0] + n[3] + n[6]) + 7 * (n[1] + n[4] + n[7]) + (n[2] + n[5] + n[8])) % 10
    return checksum == 0 and 1 <= int(d[:2]) <= 99 and not d.startswith("00")


def iban_ok(s: str) -> bool:
    v = re.sub(r"\s", "", s).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{11,30}", v):
        return False
    rearranged = v[4:] + v[:4]
    num = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(num) % 97 == 1


def npi_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return len(d) == 10 and luhn_ok("80840" + d)


def itin_ok(s: str) -> bool:
    d = re.sub(r"\D", "", s)
    return len(d) == 9 and d[0] == "9" and 50 <= int(d[3:5]) <= 99


def mbi_ok(s: str) -> bool:
    # Medicare Beneficiary Identifier: 11 chars, fixed letter/number positions, no S L O I B Z.
    v = re.sub(r"[\s-]", "", s).upper()
    return bool(re.fullmatch(r"[1-9][AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y][AC-HJKMNP-RT-Y0-9]\d[AC-HJKMNP-RT-Y]{2}\d{2}", v))


# ── Local detectors ────────────────────────────────────────────────────
# (name regex on the tenant's predefined dictionary name, detector key,
#  regex, optional validator, what the approximation does and misses)
_ALWAYS = lambda s: True  # noqa: E731

DETECTORS: List[Dict[str, Any]] = [
    {"key": "credit_card", "match": r"credit.?card|payment.?card|\bpan\b|card.?number|pci",
     "pattern": r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)", "validate": luhn_ok,
     "note": "13–19 digit numbers that pass the Luhn check; Zscaler also uses issuer prefixes and context."},
    {"key": "ssn", "match": r"social.?security|\bssn\b",
     "pattern": r"(?<![\d-])\d{3}[- ]?\d{2}[- ]?\d{4}(?![\d-])", "validate": ssn_ok,
     "note": "nine-digit numbers with a valid area/group/serial; Zscaler's high-confidence variant also wants 'SSN' nearby."},
    {"key": "itin", "match": r"\bitin\b|taxpayer.?identification",
     "pattern": r"(?<![\d-])9\d{2}[- ]?\d{2}[- ]?\d{4}(?![\d-])", "validate": itin_ok,
     "note": "9xx-xx-xxxx with an IRS group range."},
    {"key": "aba", "match": r"routing|\baba\b|bank.?account",
     "pattern": r"(?<!\d)\d{9}(?!\d)", "validate": aba_ok,
     "note": "nine-digit numbers that pass the ABA checksum."},
    {"key": "iban", "match": r"\biban\b|international.?bank",
     "pattern": r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b", "validate": iban_ok,
     "note": "country code + check digits validated with mod-97."},
    {"key": "swift", "match": r"\bswift\b|\bbic\b",
     "pattern": r"\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b", "validate": _ALWAYS,
     "note": "8 or 11 character BIC shape only; no registry lookup."},
    {"key": "npi", "match": r"\bnpi\b|national.?provider",
     "pattern": r"(?<!\d)\d{10}(?!\d)", "validate": npi_ok,
     "note": "ten digits passing the NPI Luhn check (80840 prefix)."},
    {"key": "mbi", "match": r"medicare|\bmbi\b",
     "pattern": r"\b[1-9][A-Z][A-Z0-9]\d[A-Z][A-Z0-9]\d[A-Z]{2}\d{2}\b", "validate": mbi_ok,
     "note": "Medicare Beneficiary Identifier shape."},
    {"key": "email", "match": r"e-?mail",
     "pattern": r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "validate": _ALWAYS,
     "note": "RFC-shaped e-mail addresses."},
    {"key": "phone", "match": r"phone|telephone",
     "pattern": r"(?<!\d)(?:\+?1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)", "validate": _ALWAYS,
     "note": "North American number shapes; Zscaler covers more countries."},
    {"key": "ipv4", "match": r"\bip\b.*address|ipv4",
     "pattern": r"(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)(?!\d)", "validate": _ALWAYS,
     "note": "dotted IPv4 addresses."},
    {"key": "aws_key", "match": r"\baws\b|amazon",
     "pattern": r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "validate": _ALWAYS,
     "note": "AWS access key ids; secret keys are not shaped and are not simulated."},
    {"key": "google_key", "match": r"google|\bgcp\b",
     "pattern": r"\bAIza[0-9A-Za-z_-]{35}\b", "validate": _ALWAYS,
     "note": "Google API key shape."},
    {"key": "github_token", "match": r"github",
     "pattern": r"\bgh[pousr]_[A-Za-z0-9]{36,}\b", "validate": _ALWAYS,
     "note": "GitHub token prefixes."},
    {"key": "slack_token", "match": r"slack",
     "pattern": r"\bxox[abprs]-[0-9A-Za-z-]{10,}\b", "validate": _ALWAYS,
     "note": "Slack token prefixes."},
    {"key": "private_key", "match": r"private.?key|\bpem\b|\bssh\b",
     "pattern": r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", "validate": _ALWAYS,
     "note": "PEM private key headers."},
    {"key": "jwt", "match": r"\bjwt\b|json.?web.?token|bearer",
     "pattern": r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b", "validate": _ALWAYS,
     "note": "three-part base64url tokens starting with eyJ."},
    {"key": "us_passport", "match": r"passport",
     "pattern": r"\b(?:[A-Z]\d{8}|\d{9})\b", "validate": _ALWAYS,
     "note": "US passport shape (letter + 8 digits or 9 digits); Zscaler requires context and covers other countries."},
    {"key": "drivers_license", "match": r"driver|licen[cs]e",
     "pattern": r"\b(?:[A-Z]\d{7}|[A-Z]\d{12}|\d{8,9})\b", "validate": _ALWAYS,
     "note": "a few US state shapes; Zscaler's per-state rules are richer."},
    {"key": "date_of_birth", "match": r"date.?of.?birth|\bdob\b|birth",
     "pattern": r"\b(?:0?[1-9]|1[0-2])[/-](?:0?[1-9]|[12]\d|3[01])[/-](?:19|20)\d{2}\b|\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b", "validate": _ALWAYS,
     "note": "dates in US or ISO shape; Zscaler wants a birth keyword nearby."},
    {"key": "icd10", "match": r"\bicd|diagnos",
     "pattern": r"\b[A-TV-Z]\d{2}(?:\.\d{1,4})?\b", "validate": _ALWAYS,
     "note": "ICD-10 code shape; matches many ordinary tokens, so it is an upper bound."},
    {"key": "vin", "match": r"\bvin\b|vehicle.?identification",
     "pattern": r"\b[A-HJ-NPR-Z0-9]{17}\b", "validate": _ALWAYS,
     "note": "17-character VIN shape without the check digit."},
    {"key": "mac_address", "match": r"\bmac\b.*address",
     "pattern": r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b", "validate": _ALWAYS,
     "note": "MAC address shape."},
    {"key": "uk_nino", "match": r"national.?insurance|\bnino\b",
     "pattern": r"\b[A-CEGHJ-PR-TW-Z]{2}\d{6}[A-D]\b", "validate": _ALWAYS,
     "note": "UK National Insurance number shape."},
    {"key": "uk_nhs", "match": r"\bnhs\b",
     "pattern": r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{4}(?!\d)", "validate": lambda s: _mod11(s),
     "note": "NHS number with its mod-11 check digit."},
    {"key": "canada_sin", "match": r"social.?insurance|\bsin\b",
     "pattern": r"(?<!\d)\d{3}[ -]?\d{3}[ -]?\d{3}(?!\d)", "validate": lambda s: luhn_ok(re.sub(r"\D", "", s)) and len(re.sub(r"\D", "", s)) == 9,
     "note": "Canadian SIN, Luhn-checked."},
    {"key": "australia_tfn", "match": r"tax.?file|\btfn\b",
     "pattern": r"(?<!\d)\d{3}[ ]?\d{3}[ ]?\d{3}(?!\d)", "validate": lambda s: _tfn(s),
     "note": "Australian TFN with its weighted check."},
]

# Predefined dictionaries that cannot be run locally at all.
NOT_SIMULATED = [
    (r"financial.?statement|corporate.?financ|balance.?sheet|income.?statement|earnings", "financial statements are recognised from document structure and vocabulary (machine learning)"),
    (r"medical|health.?record|\bphi\b|hipaa|clinical|prescription|patient", "medical content is recognised from vocabulary and context (machine learning)"),
    (r"source.?code|\bcode\b", "source code is recognised by language structure (machine learning)"),
    (r"resume|\bcv\b|curriculum", "resumes are recognised from document structure (machine learning)"),
    (r"legal|contract|nda|agreement", "legal documents are recognised from vocabulary (machine learning)"),
    (r"tax|w-?2|1099|form", "tax forms are recognised from form structure"),
    (r"adult|gambling|weapon|drug|illegal|violence|profan|harass", "content categories are keyword and ML based; the word lists are Zscaler's"),
    (r"salary|payroll|compensation|\bhr\b|human.?resources", "HR and payroll content is recognised from vocabulary"),
    (r"insurance|policy.?number|claim", "insurance identifiers vary by carrier; no public shape"),
    (r"\bedm\b|exact.?data|\bidm\b|index", "exact and indexed data match need the customer's index; nothing to run locally"),
    (r"\bml\b|machine.?learning|classif|ai.?generated|prompt", "machine-learning classifiers are not available offline"),
]


def _mod11(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if len(d) != 10:
        return False
    total = sum(n * (10 - i) for i, n in enumerate(d[:9]))
    check = 11 - (total % 11)
    if check == 11:
        check = 0
    return check != 10 and check == d[9]


def _tfn(s: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", s)]
    if len(d) != 9:
        return False
    weights = [1, 4, 3, 7, 5, 8, 6, 9, 10]
    return sum(n * w for n, w in zip(d, weights)) % 11 == 0


def detector_for(name: str) -> Optional[Dict[str, Any]]:
    n = (name or "").lower()
    for det in DETECTORS:
        if re.search(det["match"], n, re.I):
            return det
    return None


def why_not_simulated(name: str) -> str:
    n = (name or "").lower()
    for rx, why in NOT_SIMULATED:
        if re.search(rx, n, re.I):
            return why
    return "Zscaler does not publish this dictionary's patterns; it cannot be run locally"


def run_detector(det: Dict[str, Any], corpus: str, limit: int = 5) -> Tuple[int, List[str]]:
    """Validated hit count and a few masked samples."""
    n, samples = 0, []
    try:
        for m in re.finditer(det["pattern"], corpus):
            v = m.group(0)
            try:
                if not det["validate"](v):
                    continue
            except Exception:  # noqa: BLE001
                continue
            n += 1
            if len(samples) < limit:
                samples.append(mask(v))
    except re.error:
        return 0, []
    return n, samples


def mask(v: str) -> str:
    """Keep the shape, hide the value: last four characters stay."""
    v = str(v)
    if len(v) <= 4:
        return "•" * len(v)
    return "".join("•" if ch.isalnum() else ch for ch in v[:-4]) + v[-4:]


# ── Synthetic samples (never real data) ────────────────────────────────
# Test values for the detectors above, for a corpus test or a DLP test
# file: published card-network test numbers (Luhn valid, never real
# accounts), the Social Security numbers the SSA reserved for examples
# (987-65-4320 to 987-65-4329, never issued; area 9xx, so the strict `ssn`
# validator above, like a strict DLP dictionary, does not count them), the
# CMS specimen Medicare Beneficiary Identifier, the standard specimen IBANs,
# a sandbox test routing number, e-mail addresses on example.com and phone
# numbers in the 555-0100 to 555-0199 range set aside for fiction.
SAMPLES: Dict[str, Tuple[str, ...]] = {
    "credit_card": ("4111 1111 1111 1111", "4012 8888 8888 1881", "5555 5555 5555 4444", "5105 1051 0510 5100",
                    "3782 822463 10005", "3714 496353 98431", "6011 1111 1111 1117", "6011 0009 9013 9424"),
    "ssn": tuple(f"987-65-432{i}" for i in range(10)),
    "mbi": ("1EG4TE5MK73",),
    "iban": ("GB82 WEST 1234 5698 7654 32", "DE89 3704 0044 0532 0130 00"),
    "aba": ("110000000",),
}
_SAMPLE_FIRST = ("Avery", "Jordan", "Taylor", "Morgan", "Casey", "Riley", "Jamie", "Quinn", "Rowan", "Skyler")
_SAMPLE_LAST = ("Example", "Sample", "Testperson", "Specimen", "Demo")


def sample(key: str, i: int = 0, rng: Any = None) -> str:
    """The i-th synthetic value for a detector key (a fixed published or
    reserved value), or a generated one for the keys with no registry
    behind them (name, email, phone, date_of_birth). `rng` is a
    random.Random (injected in tests)."""
    if key in SAMPLES:
        vals = SAMPLES[key]
        return vals[i % len(vals)]
    if key == "name":
        return f"{_SAMPLE_FIRST[i % len(_SAMPLE_FIRST)]} {_SAMPLE_LAST[i % len(_SAMPLE_LAST)]}"
    if key == "email":
        return f"{_SAMPLE_FIRST[i % len(_SAMPLE_FIRST)].lower()}.{_SAMPLE_LAST[i % len(_SAMPLE_LAST)].lower()}@example.com"
    import random
    r = rng if rng is not None else random.SystemRandom()
    if key == "phone":
        return f"(555) 555-01{r.randint(0, 99):02d}"
    if key == "date_of_birth":
        return f"{r.randint(1950, 1999)}-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}"
    raise KeyError(key)


def sample_detected(key: str, value: str) -> Optional[bool]:
    """Whether this module's local detector for `key` counts `value`
    (None when there is no detector of that key)."""
    det = next((d for d in DETECTORS if d["key"] == key), None)
    if det is None:
        return None
    return run_detector(det, value)[0] > 0


def predefined_results(dicts: Iterable[Dict[str, Any]], corpus: str, is_custom: Callable[[Dict[str, Any]], bool]) -> List[Dict[str, Any]]:
    """One row per predefined dictionary: simulated (approximate hits) or not."""
    out: List[Dict[str, Any]] = []
    for d in dicts:
        if is_custom(d):
            continue
        name = str(d.get("name") or "?")
        did = d.get("id")
        det = detector_for(name)
        if det:
            n, samples = run_detector(det, corpus)
            out.append({"id": did, "name": name, "simulated": True, "detector": det["key"], "hits": n, "samples": samples,
                        "note": det["note"], "total_hits": n})
        else:
            out.append({"id": did, "name": name, "simulated": False, "detector": None, "hits": None, "samples": [],
                        "note": why_not_simulated(name), "total_hits": 0})
    out.sort(key=lambda r: (-(r["hits"] or 0), not r["simulated"], r["name"]))
    return out


# ── Engine expressions ─────────────────────────────────────────────────
# ZIA writes engine expressions as ((D63.S > 1) AND (D64.S > 0)); the
# importer's shorthand D:<name> and the older D(63) form are accepted too.
_TOKEN = re.compile(r"\s*(?:(?P<lp>\()|(?P<rp>\))|(?P<and>AND\b)|(?P<or>OR\b)|(?P<not>NOT\b)"
                    r"|(?P<term>D\(?\s*(?P<id>\d+)\s*\)?(?:\.S)?\s*(?P<op>>=|<=|==|!=|>|<|=)\s*(?P<n>\d+))"
                    r"|(?P<bare>D\(?\s*(?P<bid>\d+)\s*\)?(?:\.S)?))", re.I)

UNKNOWN = None   # tri-state: True fires, False does not, None unknown
MAX_NESTING = 40  # an engine expression nested deeper is not evaluated (unknown)
MAX_EXPRESSION = 4000   # nor a longer one (engine_explain's limit): the Sum pattern's cost grows with the square of a run of spaces


def _cmp(count: Optional[int], op: str, n: int) -> Optional[bool]:
    if count is None:
        return UNKNOWN
    return {">": count > n, ">=": count >= n, "<": count < n, "<=": count <= n, "=": count == n, "==": count == n, "!=": count != n}[op]


def _and(a, b):
    if a is False or b is False:
        return False
    if a is None or b is None:
        return UNKNOWN
    return True


def _or(a, b):
    if a is True or b is True:
        return True
    if a is None or b is None:
        return UNKNOWN
    return False


def _not(a):
    return UNKNOWN if a is None else (not a)


_SUM_RE = re.compile(r"\(\s*D\(?\s*\d+\s*\)?(?:\.S)?(?:\s*\+\s*D\(?\s*\d+\s*\)?(?:\.S)?)+\s*\)\s*(>=|<=|==|!=|>|<|=)\s*(\d+)")


def evaluate_expression(expr: str, counts: Dict[int, Optional[int]]) -> Tuple[Optional[bool], List[int], List[str]]:
    """(result, dictionary ids referenced, terms explained). `counts`
    maps dictionary id → hit count, or None when the count is unknown.
    Sum groups — `(D1.S + D2.S) > n`, the Engine Builder's Sum — are
    totalled first; an unknown count makes the sum unknown."""
    toks: List[Tuple[str, Any]] = []
    ids: List[int] = []
    pos = 0
    s = (expr or "").strip()
    if len(s) > MAX_EXPRESSION:
        return UNKNOWN, ids, [f"not evaluated: the expression is longer than {MAX_EXPRESSION} characters"]
    sums: Dict[str, Tuple[List[int], str, int]] = {}
    # A Sum becomes one synthetic term, numbered above every real id in the
    # expression so it can never be taken for a dictionary.
    base = max([900000] + [int(x) + 1 for x in re.findall(r"D\(?\s*(\d+)", s, re.I)])

    def _sum(m):
        # Every id in the group: all of "(D(1).S + D(2).S)", the older
        # D(n) form included (its own parentheses are not the group's end).
        sids = [int(x) for x in re.findall(r"D\(?\s*(\d+)", m.group(0), re.I)]
        key = f"D{base + len(sums)}.S"
        sums[key] = (sids, m.group(1), int(m.group(2)))
        return f"{key} {m.group(1)} {m.group(2)}"
    s = _SUM_RE.sub(_sum, s)
    while pos < len(s):
        m = _TOKEN.match(s, pos)
        if not m or m.end() == pos:
            return UNKNOWN, ids, [f"could not parse near: {s[pos:pos + 20]!r}"]
        pos = m.end()
        if m.group("lp"):
            toks.append(("(", None))
        elif m.group("rp"):
            toks.append((")", None))
        elif m.group("and"):
            toks.append(("AND", None))
        elif m.group("or"):
            toks.append(("OR", None))
        elif m.group("not"):
            toks.append(("NOT", None))
        elif m.group("term"):
            did = int(m.group("id"))
            if f"D{did}.S" not in sums:   # a Sum's synthetic term is not a dictionary
                ids.append(did)
            toks.append(("T", (did, m.group("op"), int(m.group("n")))))
        elif m.group("bare"):
            did = int(m.group("bid")); ids.append(did)
            toks.append(("T", (did, ">", 0)))
    if not toks:
        return UNKNOWN, ids, ["empty expression"]
    explained: List[str] = []
    i = 0
    depth = 0

    def deeper(fn):
        # Parentheses or NOTs nested past MAX_NESTING are "could not parse"
        # (unknown), never a RecursionError that ends the whole corpus test.
        nonlocal depth
        depth += 1
        try:
            if depth > MAX_NESTING:
                raise ValueError(f"nested more than {MAX_NESTING} levels deep")
            return fn()
        finally:
            depth -= 1

    def parse_or():
        nonlocal i
        v = parse_and()
        while i < len(toks) and toks[i][0] == "OR":
            i += 1
            v = _or(v, parse_and())
        return v

    def parse_and():
        nonlocal i
        v = parse_not()
        while i < len(toks) and toks[i][0] == "AND":
            i += 1
            v = _and(v, parse_not())
        return v

    def parse_not():
        nonlocal i
        if i < len(toks) and toks[i][0] == "NOT":
            i += 1
            return _not(deeper(parse_not))
        return parse_atom()

    def parse_atom():
        nonlocal i
        if i >= len(toks):
            raise ValueError("unexpected end")
        kind, val = toks[i]
        if kind == "(":
            i += 1
            v = deeper(parse_or)
            if i >= len(toks) or toks[i][0] != ")":
                raise ValueError("unbalanced")
            i += 1
            return v
        if kind == "T":
            i += 1
            did, op, n = val
            key = f"D{did}.S"
            if key in sums:
                sids, sop, sn = sums[key]
                ids.extend(x for x in sids if x not in ids)
                parts = [counts.get(x, UNKNOWN) for x in sids]
                total = None if any(v is None for v in parts) else sum(parts)
                r = _cmp(total, sop, sn)
                explained.append(f"Sum({' + '.join(f'D{x}.S' for x in sids)}) {sop} {sn}: " + ("unknown (a dictionary is not simulated)" if total is None else f"{total} → {'true' if r else 'false'}"))
                return r
            c = counts.get(did, UNKNOWN)
            r = _cmp(c, op, n)
            explained.append(f"D{did}.S {op} {n}: " + ("unknown (not simulated)" if c is None else f"{c} → {'true' if r else 'false'}"))
            return r
        raise ValueError(f"unexpected {kind}")

    try:
        result = parse_or()
        if i != len(toks):
            raise ValueError("trailing tokens")
    except ValueError as e:
        return UNKNOWN, ids, [f"could not parse: {e}"]
    return result, ids, explained


def rule_reference(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Allowlisted configuration reference, never an enforcement claim."""
    refs = rule.get("dlpEngines") or rule.get("dlp_engines") or rule.get("engines") or []
    refs = refs if isinstance(refs, list) else []
    ids = [str(x.get("id")) if isinstance(x, dict) else str(x) for x in refs if not isinstance(x, dict) or x.get("id") is not None]
    action = rule.get("action") or ""
    if isinstance(action, dict):
        action = action.get("type") or ""
    state = str(rule.get("state") or "UNKNOWN").upper()
    disabled = state == "DISABLED" or rule.get("enabled") is False
    scope_fields = [k for k in ("users", "groups", "departments", "locations", "locationGroups", "urlCategories", "cloudApplications", "fileTypes", "protocols", "recipients", "casbTenants", "devices", "activities") if rule.get(k)]
    return {"id": rule.get("id"), "name": str(rule.get("name") or rule.get("id") or "Unnamed rule"),
            "engine_ids": ids, "action": str(action).upper(), "state": state,
            "order": rule.get("order"), "applicability": "disabled" if disabled else "conditional",
            "reason": "Disabled rule; cannot act" if disabled else "Configured rule reference; channel, identity, operation, precedence and content applicability must be established",
            "scope_fields": scope_fields,
            "without_content_inspection": str(rule.get("withoutContentInspection", rule.get("without_content_inspection", False))).lower() in ("true", "1"),
            "incident_receiver": str(rule.get("zscalerIncidentReceiver", rule.get("zscaler_incident_receiver", rule.get("incidentReceiver", False)))).lower() in ("true", "1"),
            "icap_server_id": ((rule.get("icapServer") or {}).get("id") if isinstance(rule.get("icapServer"), dict) else rule.get("icapServer"))}


def engine_results(engines: Iterable[Dict[str, Any]], rules: Iterable[Dict[str, Any]], counts: Dict[int, Optional[int]],
                   dict_names: Dict[int, str]) -> List[Dict[str, Any]]:
    """Which engines fire on the corpus, and the rules they drive."""
    by_engine: Dict[int, List[str]] = {}
    rule_objects: Dict[int, List[Dict[str, Any]]] = {}
    for r in rules or []:
        for e in (r.get("dlpEngines") or r.get("dlp_engines") or []):
            eid = e.get("id") if isinstance(e, dict) else e
            try:
                by_engine.setdefault(int(eid), []).append(str(r.get("name") or r.get("id")))
                rule_objects.setdefault(int(eid), []).append(rule_reference(r))
            except (TypeError, ValueError):
                continue
    out: List[Dict[str, Any]] = []
    for e in engines or []:
        expr = str(e.get("engineExpression") or e.get("engine_expression") or e.get("expression") or "")
        result, ids, explained = evaluate_expression(expr, counts)
        try:
            eid = int(e.get("id"))
        except (TypeError, ValueError):
            eid = None
        out.append({"id": eid, "name": str(e.get("name") or e.get("predefinedEngineName") or "?"),
                    "custom": bool(e.get("customDlpEngine") or e.get("custom")), "expression": expr,
                    "fires": result, "verdict": {True: "fires", False: "does not fire", None: "possible"}[result],
                    "dictionaries": [dict_names.get(d, f"D{d}") for d in ids], "terms": explained,
                    "dictionary_refs": [{"id": d, "name": dict_names.get(d, f"D{d}"), "count": counts.get(d)} for d in dict.fromkeys(int(x) for x in re.findall(r"D\(?\s*(\d+)", expr, re.I))],
                    "explanation": ("Expression is true on the available local counts; this is not proof a tenant rule acts" if result is True else
                                    "Expression is false on the available counts, including its Boolean operators; unresolved terms cannot change this result" if result is False else
                                    "Expression remains unknown because a required detector is unavailable or its expression is unsupported"),
                    "evidence_status": "simulated", "expression_evaluated": expr,
                    "rule_objects": rule_objects.get(eid, []) if eid is not None else [],
                    "rules": by_engine.get(eid, []) if eid is not None else []})
    order = {True: 0, None: 1, False: 2}
    out.sort(key=lambda x: (order[x["fires"]], -len(x["rules"]), x["name"]))
    return out
