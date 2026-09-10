#!/usr/bin/env python3
"""Validate every pack's detection logic offline, many times over.

For each shipped pack this harness:
  1. checks the static logic: every pattern compiles, every dictionary is
     inside ZIA's limits, every engine references dictionaries that exist
     (pack or predefined), every rule references engines that exist, every
     rule ships DISABLED;
  2. evaluates the dictionaries and engines against realistic sample
     documents (positives that should fire, negatives that must not,
     cousin classes that must not cross-fire) using a local evaluator that
     mirrors ZIA's counting (unique pattern matches, phrases, proximity,
     All/Any engine expressions);
  3. repeats the evaluation N times (default 100) with randomised documents
     (fresh identifiers, shuffled paragraphs, injected noise, changed case)
     and reports precision, recall and their spread.

Predefined Zscaler dictionaries cannot run here; they are replaced by
labelled proxies (Luhn-checked card numbers, mod-97 IBANs, ABA checksum,
SSN/ITIN shapes, keyword lists) so the engine logic around them can still
be exercised. The report says so wherever a proxy stood in.

Usage: python tools/validate_detection.py [--iterations 100] [--out validation]
Writes <out>.json, <out>.md and <out>.html.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import random
import re
import statistics
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dlp_importer import discover_packs, dictionary_limit_problems, engine_limit_problems  # noqa: E402
import pack_channels as pc  # noqa: E402

# ── Predefined dictionary proxies ────────────────────────────────────


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = ord(ch) - 48
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if len(s) < 15 or not s[:2].isalpha():
        return False
    rearranged = s[4:] + s[:4]
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(num) % 97 == 1
    except ValueError:
        return False


def _aba_ok(d: str) -> bool:
    if len(d) != 9 or not d.isdigit():
        return False
    w = [3, 7, 1, 3, 7, 1, 3, 7, 1]
    return sum(int(c) * x for c, x in zip(d, w)) % 10 == 0


def _count_cards(text: str) -> int:
    out = set()
    for m in re.finditer(r"\b(?:\d[ -]?){12,18}\d\b", text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if 13 <= len(digits) <= 19 and _luhn_ok(digits):
            out.add(digits)
    return len(out)


def _count_ibans(text: str) -> int:
    return len({m.group(0) for m in re.finditer(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", text) if _iban_ok(m.group(0))})


def _count_aba(text: str) -> int:
    return len({m.group(0) for m in re.finditer(r"\b\d{9}\b", text) if _aba_ok(m.group(0))})


def _count_re(text: str, rx: str) -> int:
    return len(set(re.findall(rx, text)))


PROXIES: Dict[str, Any] = {
    "CREDIT_CARD": _count_cards, "CREDIT_CARDS": _count_cards,
    "SSN": lambda t: _count_re(t, r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
    "USITIN_LEAKAGE": lambda t: _count_re(t, r"\b9\d{2}-[5-9]\d-\d{4}\b"),
    "ABA_LEAKAGE": _count_aba,
    "EUIBAN_LEAKAGE": lambda t: len({m for m in re.findall(r"\b(?:DE|FR|ES|IT|NL|BE|AT|PT|IE|FI|LU|GR|PL|CZ|SK|HU|RO|BG|HR|SI|LT|LV|EE|MT|CY|DK|SE)\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b", t) if _iban_ok(m)}),
    "PPEU_LEAKAGE": lambda t: _count_re(t, r"(?i)\bpassport(?: no\.?| number)?[:\s]+[A-Z0-9]{7,9}\b"),
    "ASPP_LEAKAGE": lambda t: _count_re(t, r"(?i)\bpassport(?: no\.?| number)?[:\s]+[A-Z]{1,2}\d{7,8}\b"),
    "USDL_LEAKAGE": lambda t: _count_re(t, r"(?i)\b(?:driver'?s? licen[cs]e|DL)(?: no\.?| number| #)?[:\s]+[A-Z0-9]{6,12}\b"),
    "CRED_LEAKAGE": lambda t: _count_re(t, r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "FINANCIAL": lambda t: min(1, len(re.findall(r"(?i)\b(balance sheet|income statement|cash flow statement|statement of operations|retained earnings|EBITDA)\b", t)) // 2),
    "ML_CORPORATE_FINANCE_LEAKAGE": lambda t: min(1, len(re.findall(r"(?i)\b(quarterly results|earnings per share|guidance|revenue forecast|EBITDA|pre-announcement)\b", t)) // 2),
    "ML_TAX_LEAKAGE": lambda t: min(1, len(re.findall(r"(?i)\b(form 1040|w-2|1099|taxable income|adjusted gross income)\b", t)) // 2),
    "MEDICAL": lambda t: min(1, len(re.findall(r"(?i)\b(diagnosis|prescribed|mg daily|patient|discharge summary|attending physician)\b", t)) // 2),
    "ML_MEDICAL_DOC_LEAKAGE": lambda t: min(1, len(re.findall(r"(?i)\b(discharge summary|progress note|history of present illness|assessment and plan)\b", t))),
    "DRUGS_LEAKAGE": lambda t: len(set(re.findall(r"(?i)\b(metformin|lisinopril|atorvastatin|amoxicillin|ibuprofen|insulin|warfarin|omeprazole|sertraline|prednisone)\b", t))),
    "DISEASES_LEAKAGE": lambda t: len(set(re.findall(r"(?i)\b(diabetes|hypertension|asthma|pneumonia|depression|cancer|hepatitis|epilepsy|anemia|arthritis)\b", t))),
}
PROXY_ALIASES = {"Social Security Numbers (US)": "SSN", "Drivers License (United States)": "USDL_LEAKAGE", "Credit Cards": "CREDIT_CARD",
                 "ABA Bank Routing Number": "ABA_LEAKAGE", "Tax Identification Number (US)": "USITIN_LEAKAGE"}
for _alias, _canon in PROXY_ALIASES.items():
    PROXIES[_alias] = PROXIES[_canon]
PROXY_NOTE = "predefined Zscaler dictionary replaced by a local proxy (see Method)"


# ── Local dictionary / engine evaluator ──────────────────────────────

class Dictionary:
    def __init__(self, d: Dict[str, Any], predefined_counts: Dict[str, int]):
        self.name = d["name"]
        self.clone = bool(d.get("predefined_clone"))
        self.template = d.get("dict_template_name")
        self.match = d.get("custom_phrase_match_type") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"
        self.proximity = int(d.get("proximity") or 0)
        self.patterns: List[Tuple[re.Pattern, str]] = []
        self.compile_errors: List[str] = []
        for p in d.get("patterns") or []:
            try:
                self.patterns.append((re.compile(p["pattern"]), p.get("action", "")))
            except re.error as e:
                self.compile_errors.append(f"{p['pattern'][:60]}: {e}")
        self.phrases = [(p["phrase"], p.get("action", "")) for p in (d.get("phrases") or []) if p.get("phrase")]

    def count(self, text: str) -> int:
        if self.clone:
            fn = PROXIES.get(self.template or "")
            base = fn(text) if fn else 0
            if self.proximity and base:
                # A proximity clone needs a related phrase near the match; the
                # clone's own phrases when it has them, else the template's keywords.
                words = [p for p, _ in self.phrases] or _TEMPLATE_WORDS.get(self.template or "", [])
                if words and not any(re.search(r"(?i)\b" + re.escape(w) + r"\b", text) for w in words):
                    return 0
            return base
        pat_hits: List[Tuple[int, str]] = []
        for rx, action in self.patterns:
            for m in rx.finditer(text):
                pat_hits.append((m.start(), m.group(0)))
        phr_hits: List[Tuple[int, str]] = []
        for ph, _ in self.phrases:
            for m in re.finditer(r"(?i)(?<![A-Za-z0-9])" + re.escape(ph.strip()) + r"(?![A-Za-z0-9])", text):
                phr_hits.append((m.start(), ph))
        if self.match == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE":
            if not phr_hits:
                return 0
            prox = self.proximity or 10 ** 9
            near = {v for pos, v in pat_hits if any(abs(pos - p2) <= prox for p2, _ in phr_hits)}
            return len(near)
        if self.match == "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY":
            return (len({v for _, v in pat_hits}) + len({v for _, v in phr_hits})) if (not self.patterns or pat_hits) and (not self.phrases or phr_hits) else 0
        unique_pats = len({v for _, v in pat_hits})
        # PHRASE_COUNT_TYPE_ALL counts every occurrence; UNIQUE counts distinct phrases.
        phrase_all = sum(1 for _ in phr_hits)
        return unique_pats + phrase_all


_TEMPLATE_WORDS = {
    "CREDIT_CARD": ["card", "visa", "mastercard", "amex", "cvv", "expiry", "expiration"],
    "SSN": ["ssn", "social security"], "USITIN_LEAKAGE": ["itin", "tax id", "taxpayer"],
    "ABA_LEAKAGE": ["routing", "aba", "wire", "account"], "USDL_LEAKAGE": ["driver", "license", "licence"],
}

_TERM_RE = re.compile(r"\(\s*D:(?P<name>.+?)\s*(?P<op>>=|<=|>|<|=)\s*(?P<n>\d+)\s*\)")


class Engine:
    def __init__(self, e: Dict[str, Any], dict_names: List[str], predefined: List[str]):
        self.name = e["name"]
        self.expr = e["expression"]
        self.refs: List[str] = []
        self.unresolved: List[str] = []
        expr = self.expr
        # Longest names first so a name that prefixes another is not clobbered.
        ordered = sorted(set(dict_names) | set(predefined), key=len, reverse=True)
        self.slots: Dict[str, str] = {}
        for i, name in enumerate(ordered):
            token = f"D:{name}"
            if token in expr:
                slot = f"__D{i}__"
                expr = expr.replace(token, f"D:{slot}")
                self.slots[slot] = name
                self.refs.append(name)
        for m in re.finditer(r"D:([^>]+?)\s*[<>=]", expr):
            if not m.group(1).strip().startswith("__D"):
                self.unresolved.append(m.group(1).strip())
        self.compiled = expr

    def fires(self, counts: Dict[str, int]) -> bool:
        expr = self.compiled

        def repl(m):
            name = self.slots.get(m.group("name").strip(), m.group("name").strip())
            n = counts.get(name, 0)
            return f"({n} {m.group('op').replace('=', '==') if m.group('op') == '=' else m.group('op')} {m.group('n')})"
        expr = _TERM_RE.sub(repl, expr)
        expr = re.sub(r"\bAND\b", "and", expr); expr = re.sub(r"\bOR\b", "or", expr); expr = re.sub(r"\bNOT\b", "not", expr)
        if re.search(r"[^0-9()<>= andortu\s]", expr):
            return False
        try:
            return bool(eval(expr, {"__builtins__": {}}, {}))  # noqa: S307 — sanitised arithmetic/boolean only
        except Exception:  # noqa: BLE001
            return False


class Pack:
    def __init__(self, meta: Dict[str, Any]):
        self.id = meta["id"]; self.dir = meta["dir"]
        self.name = meta.get("name") or self.id
        load = lambda n: json.load(open(os.path.join(self.dir, "configs", n), encoding="utf-8"))
        self.dicts_raw = load("dlp_dictionaries.json"); self.engines_raw = load("dlp_engines.json"); self.rules = load("dlp_policies.json")
        self.dicts = [Dictionary(d, {}) for d in self.dicts_raw]
        names = [d.name for d in self.dicts]
        self.engines = [Engine(e, names, list(PROXIES)) for e in self.engines_raw]

    def counts(self, text: str) -> Dict[str, int]:
        c = {d.name: d.count(text) for d in self.dicts}
        for name, fn in PROXIES.items():
            if name not in c:
                c[name] = fn(text)
        return c

    def evaluate(self, text: str) -> Dict[str, bool]:
        c = self.counts(text)
        return {e.name: e.fires(c) for e in self.engines}


# ── Static validation ────────────────────────────────────────────────

def static_checks(pack: Pack) -> Dict[str, Any]:
    problems: List[str] = []
    for d, raw in zip(pack.dicts, pack.dicts_raw):
        for err in d.compile_errors:
            problems.append(f"dictionary '{d.name}': pattern does not compile in Python re ({err})")
        if not raw.get("predefined_clone"):
            for p in dictionary_limit_problems(raw):
                problems.append(f"dictionary '{d.name}': {p}")
        if d.clone and (d.template or "") not in PROXIES and d.template not in ("USDL_LEAKAGE",):
            problems.append(f"dictionary '{d.name}': clone template '{d.template}' has no local proxy (evaluated as 0)")
    for e in pack.engines:
        for p in engine_limit_problems(e.expr):
            problems.append(f"engine '{e.name}': {p}")
        for u in e.unresolved:
            problems.append(f"engine '{e.name}': references unknown dictionary '{u}'")
    engine_names = {e.name for e in pack.engines}
    for r in pack.rules:
        for en in r.get("engines") or []:
            if en not in engine_names:
                problems.append(f"rule '{r['name']}': references unknown engine '{en}'")
        if str(r.get("state", "")).upper() != "DISABLED":
            problems.append(f"rule '{r['name']}': ships {r.get('state')} (must be DISABLED)")
        ch = pc.channel_of(r)
        if pc.has_engines(ch) and not r.get("engines"):
            problems.append(f"rule '{r['name']}': {ch} rule without engines")
    channels = sorted({pc.channel_of(r) for r in pack.rules})
    return {"problems": problems, "dictionaries": len(pack.dicts), "clones": sum(1 for d in pack.dicts if d.clone),
            "engines": len(pack.engines), "rules": len(pack.rules), "channels": channels,
            "predefined_refs": sorted({n for e in pack.engines for n in e.refs if n in PROXIES})}


# ── Sample corpora ───────────────────────────────────────────────────

def _rand_digits(rng, n):
    return "".join(rng.choice("0123456789") for _ in range(n))


def luhn_number(rng, prefix="4", length=16):
    body = prefix + _rand_digits(rng, length - len(prefix) - 1)
    for check in range(10):
        if _luhn_ok(body + str(check)):
            return body + str(check)
    return body + "0"


def iban(rng, country="DE", bban_len=18):
    bban = _rand_digits(rng, bban_len)
    rearranged = bban + country + "00"
    num = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    check = 98 - int(num) % 97
    return f"{country}{check:02d}{bban}"


def aba_number(rng):
    while True:
        d = _rand_digits(rng, 9)
        if _aba_ok(d):
            return d


def ssn(rng):
    return f"{rng.randint(100, 665):03d}-{rng.randint(1, 99):02d}-{rng.randint(1, 9999):04d}"


NOISE = [
    "Thanks for joining the town hall on Thursday. The recording is on the intranet and the slides are attached.",
    "Reminder: the parking garage on level 2 is closed for maintenance until the 14th. Please use the north lot.",
    "Our Q3 offsite agenda: 09:00 welcome, 09:30 product roadmap, 11:00 breakout sessions, 12:30 lunch, 14:00 customer panel.",
    "The cafeteria will serve a vegetarian option every day starting next week. Feedback forms are by the exit.",
    "Please review the updated travel policy. Economy class for flights under six hours; book through the portal.",
    "Marketing update: the spring campaign lifted web traffic 18% and trial sign-ups 11% quarter on quarter.",
    "IT notice: the VPN client will update automatically overnight. No action is needed on your side.",
    "Facilities: the third-floor printers are being replaced on Friday. Print jobs will route to the second floor.",
]

NEGATIVES = {
    "prose": [
        "Meeting notes, 12 March. Attendees: product, design, engineering. We agreed to move the launch to the second week of May, keep the pricing page unchanged and revisit the onboarding flow after the beta. Action items: Priya to draft the announcement, Tom to schedule the dry run, Lena to confirm venue capacity for 120 people.",
        "The annual employee survey opens Monday. It takes about eight minutes, answers are anonymous, and results will be shared by department in June. Last year 74% of staff took part; the top request was clearer career paths, which led to the new levelling guide.",
    ],
    "invoice": [
        "Invoice INV-2026-004417 for order 88213. Items: 12 x monitor stand at 39.00, 4 x docking station at 149.00. Subtotal 1,064.00, VAT 212.80, total 1,276.80. Payment terms 30 days. Customer reference PO-77120. Delivered to 14 Harbour Road, Bristol.",
    ],
    "csv": [
        "sku,description,qty,unit_price\nA1001,Widget small,120,2.35\nA1002,Widget large,80,3.10\nB2001,Bracket,400,0.55\nC3001,Cable 2m,150,4.80\nC3002,Cable 5m,90,7.20",
    ],
    "json_config": [
        '{"service": "orders", "replicas": 3, "resources": {"cpu": "500m", "memory": "512Mi"}, "env": {"LOG_LEVEL": "info", "REGION": "eu-west-1"}, "healthcheck": {"path": "/healthz", "interval": 30}}',
    ],
    "markdown": [
        "# Release 4.2\n\n## Highlights\n- Faster search across projects\n- New calendar view\n- Dark mode\n\n## Fixed\n- Export to PDF lost page breaks\n- Notifications were sent twice on mobile\n\nUpgrade by pulling the latest image; no migration needed.",
    ],
    "log": [
        "2026-09-10 08:14:02 INFO gateway request_id=7f2a path=/api/orders status=200 latency_ms=41\n2026-09-10 08:14:03 WARN cache miss key=orders:1182\n2026-09-10 08:14:05 INFO gateway request_id=7f2b path=/api/orders/1182 status=200 latency_ms=12",
    ],
}


def banking_samples(rng) -> Dict[str, str]:
    cards = [luhn_number(rng, rng.choice(["4", "5", "34", "6011"])) for _ in range(6)]
    bulk = [luhn_number(rng, rng.choice(["4", "5"])) for _ in range(32)]
    return {
        "card_bulk_export": "PAN export for the card-reissue batch (cardholder name, card number, expiry date):\n" + "\n".join(f"Customer {i},{c},{rng.randint(1,12):02d}/{rng.randint(27,31)}" for i, c in enumerate(bulk)),
        "card_export": "Cardholder name,PAN,Expiry date,CVV\n" + "\n".join(f"J. Smith,{c},{rng.randint(1,12):02d}/{rng.randint(27,31)},{rng.randint(100,999)}" for c in cards) + "\nPrimary account number list for the chargeback team. Card verification values included for the disputes queue.",
        "single_card_with_cvv": f"Hi, the customer read out card number {cards[0]}, expiry date 04/29 and CVV {rng.randint(100,999)} over the phone; please process the refund. Cardholder name as on file.",
        "wire_instructions": f"Wire transfer instructions for the beneficiary bank: SWIFT code DEUTDEFF, beneficiary account IBAN {iban(rng,'DE')}, intermediary bank CHASUS33, ABA routing number {aba_number(rng)}, value date tomorrow, MT103 to follow. Ordering customer: Acme Treasury. Amount to be transferred: EUR 1,250,000. Reference number TR-{rng.randint(10000,99999)}.",
        "iban_list": "Beneficiary account numbers for the payroll run: " + ", ".join(iban(rng, rng.choice(["DE", "FR", "NL", "GB", "ES"])) for _ in range(5)) + ". Bank identifier code per row as before; sort code on the UK ones.",
        "statement": f"Account statement, statement period 1-31 August. Account holder: R. Patel, customer number CIF-{rng.randint(100000,999999)}, IBAN {iban(rng,'NL',14)}. Opening balance 4,210.55, closing balance 3,980.10, available balance 3,980.10. Transaction history: direct debit energy 120.00, standing order rent 1,450.00, deposit salary 3,200.00, withdrawal ATM 200.00. Interest accrued 1.12. Overdraft limit 500.00.",
        "kyc_file": f"KYC onboarding pack. Customer due diligence completed; enhanced due diligence not required. PEP screening negative, sanctions screening against OFAC and the SDN list negative, adverse media none. Beneficial owner: the applicant. Source of funds: salary. Proof of identity: passport number {rng.choice('ABCDEFG')}{_rand_digits(rng,8)}; proof of address: utility bill. Date of birth {rng.randint(1,28):02d}/{rng.randint(1,12):02d}/19{rng.randint(60,99)}. Nationality: Irish. Risk rating: low.",
        "loan_application": f"Mortgage application. Applicant SSN {ssn(rng)}, date of birth 03/14/1988, annual income 92,000, employer name Northwind Traders, employment verification attached. Credit score (FICO) {rng.randint(640,810)} from Experian and TransUnion; credit report shows no delinquent accounts. Loan amount 410,000, APR 6.1%, debt-to-income 31%, collateral: the property. Co-signer: none. Underwriting decision pending.",
        "mnpi_memo": "STRICTLY CONFIDENTIAL. Project codename Falcon: acquisition target is Meridian Foods; term sheet agreed, letter of intent to be signed Friday, pre-announcement embargo until the earnings release. This is material non-public information; the deal team is wall-crossed and names are on the restricted list. Do not distribute.",
        "confidential_marking": "Bank Confidential. Internal Use Only. Q3 branch performance summary for regional managers. Do not distribute outside the retail division.",
        "pii_form": f"Customer record export: full name Maria Gonzalez, date of birth 07/22/1975, place of birth Madrid, nationality Spanish, home address 12 Calle Mayor, mobile number +34 600 123 456, email address maria@example.org, passport number {rng.choice('XYZ')}{_rand_digits(rng,8)}, tax identification 55-321-9876, occupation architect, marital status married.",
        "uk_ids": f"National Insurance number QQ {rng.randint(10,99)} {rng.randint(10,99)} {rng.randint(10,99)} C for payroll; Tax File Number {rng.randint(100,999)} {rng.randint(100,999)} {rng.randint(100,999)} for the Australian secondee; Social Insurance Number {rng.randint(100,999)}-{rng.randint(100,999)}-{rng.randint(100,999)} for the Toronto hire; South African ID number {rng.randint(60,99)}{rng.randint(1,12):02d}{rng.randint(1,28):02d}{_rand_digits(rng,4)}08{rng.randint(0,9)}.",
        "apac_ids": f"PAN card ABCPE{_rand_digits(rng,4)}F, Aadhaar {rng.randint(2000,9999)} {_rand_digits(rng,4)} {_rand_digits(rng,4)}, NRIC S{_rand_digits(rng,7)}A, HKID A{_rand_digits(rng,6)}(3) collected at account opening; identity card copies on file.",
    }


CODE_SAMPLES = {
    "CSharp": "using System;\nusing System.Collections.Generic;\nusing Microsoft.Extensions.Logging;\n\nnamespace Acme.Payments\n{\n    public sealed class PaymentService\n    {\n        private readonly ILogger<PaymentService> _log;\n        public PaymentService(ILogger<PaymentService> log) { _log = log; }\n        public async Task<Order> GetOrderAsync(int id)\n        {\n            if (id <= 0) throw new ArgumentOutOfRangeException(nameof(id));\n            Console.WriteLine($\"loading {id}\");\n            return await Task.FromResult(new Order { Id = id });\n        }\n        public static bool IsValid(string s) => !String.IsNullOrEmpty(s);\n    }\n}\n",
    "CPlusPlus": "#include <iostream>\n#include <vector>\n#include <memory>\nusing namespace std;\n\ntemplate <typename T>\nclass Stack {\npublic:\n    void push(const T& v) { items.push_back(v); }\n    virtual T pop();\nprivate:\n    std::vector<T> items;\n};\n\nint main() {\n    auto p = std::make_unique<Stack<int>>();\n    p->push(3);\n    std::cout << \"size \" << 1 << std::endl;\n    return 0;\n}\n",
    "Go": "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n)\n\ntype Server struct {\n\tAddr string\n}\n\nfunc (s *Server) Handle(w http.ResponseWriter, r *http.Request) {\n\tfmt.Fprintf(w, \"ok\")\n}\n\nfunc main() {\n\ts := &Server{Addr: \":8080\"}\n\tif err := http.ListenAndServe(s.Addr, nil); err != nil {\n\t\tfmt.Println(err)\n\t}\n}\n",
    "HTML": "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n  <meta charset=\"utf-8\">\n  <title>Admin console</title>\n  <link rel=\"stylesheet\" href=\"/static/admin.css\">\n</head>\n<body>\n  <nav class=\"top\"><a href=\"/\">Home</a><a href=\"/users\">Users</a></nav>\n  <main id=\"content\">\n    <form action=\"/users\" method=\"post\">\n      <input type=\"text\" name=\"q\" placeholder=\"Search\">\n      <button type=\"submit\">Go</button>\n    </form>\n    <table><tr><th>Name</th><th>Role</th></tr></table>\n  </main>\n  <script src=\"/static/admin.js\"></script>\n</body>\n</html>\n",
    "Java": "package com.acme.orders;\n\nimport java.util.List;\nimport java.util.ArrayList;\nimport org.springframework.stereotype.Service;\n\n@Service\npublic class OrderService {\n    private final List<Order> orders = new ArrayList<>();\n\n    public Order find(long id) throws OrderNotFoundException {\n        for (Order o : orders) {\n            if (o.getId() == id) return o;\n        }\n        throw new OrderNotFoundException(id);\n    }\n\n    public static void main(String[] args) {\n        System.out.println(\"orders\");\n    }\n}\n",
    "JavaScript": "const express = require('express');\nconst fs = require('fs');\nconst app = express();\n\nfunction loadConfig(path) {\n  const raw = fs.readFileSync(path, 'utf8');\n  return JSON.parse(raw);\n}\n\napp.get('/health', (req, res) => {\n  console.log('health check');\n  res.json({ ok: true });\n});\n\nmodule.exports = { app, loadConfig };\napp.listen(3000, () => console.log('listening'));\n",
    "Kotlin": "package com.acme.billing\n\nimport kotlinx.coroutines.flow.Flow\n\ndata class Invoice(val id: Int, val amount: Double)\n\nclass BillingRepository(private val api: BillingApi) {\n    suspend fun fetch(id: Int): Invoice? {\n        val res = api.invoice(id) ?: return null\n        return Invoice(res.id, res.total)\n    }\n\n    fun stream(): Flow<Invoice> = api.watch()\n}\n\nfun calculateTax(amount: Double): Double = amount * 0.2\n",
    "Python": "from typing import Optional\nimport json\nimport os\n\nclass OrderRepository:\n    def __init__(self, path: str):\n        self.path = path\n\n    def load(self) -> dict:\n        with open(self.path) as f:\n            return json.load(f)\n\n    def find(self, order_id: int) -> Optional[dict]:\n        for row in self.load().get('orders', []):\n            if row['id'] == order_id:\n                return row\n        return None\n\nif __name__ == '__main__':\n    print(OrderRepository(os.environ['ORDERS']).find(1))\n",
    "Rust": "use std::collections::HashMap;\nuse std::fmt;\n\n#[derive(Debug, Clone)]\npub struct Order {\n    pub id: u64,\n    pub total: f64,\n}\n\nimpl fmt::Display for Order {\n    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {\n        write!(f, \"order {}\", self.id)\n    }\n}\n\npub fn index(orders: &[Order]) -> HashMap<u64, &Order> {\n    let mut m = HashMap::new();\n    for o in orders { m.insert(o.id, o); }\n    m\n}\n\nfn main() { println!(\"{}\", index(&[]).len()); }\n",
    "SQL": "CREATE TABLE orders (\n  id BIGINT PRIMARY KEY,\n  customer_id BIGINT NOT NULL REFERENCES customers(id),\n  total NUMERIC(12,2) NOT NULL,\n  created_at TIMESTAMP DEFAULT now()\n);\n\nCREATE INDEX idx_orders_customer ON orders(customer_id);\n\nINSERT INTO orders (id, customer_id, total) VALUES (1, 42, 99.50);\n\nSELECT o.id, c.name, o.total\nFROM orders o\nJOIN customers c ON c.id = o.customer_id\nWHERE o.created_at > now() - interval '7 days'\nORDER BY o.total DESC;\n\nUPDATE orders SET total = total * 1.1 WHERE customer_id = 42;\n",
    "Swift": "import Foundation\nimport UIKit\n\nstruct Order: Codable {\n    let id: Int\n    let total: Double\n}\n\nfinal class OrderClient {\n    func fetch(id: Int) async throws -> Order {\n        guard let url = URL(string: \"https://api.example.com/orders/\\(id)\") else { throw URLError(.badURL) }\n        let (data, _) = try await URLSession.shared.data(from: url)\n        return try JSONDecoder().decode(Order.self, from: data)\n    }\n}\n\nfunc format(_ o: Order) -> String { return \"\\(o.id): \\(o.total)\" }\n",
    "TypeScript": "import type { Request, Response } from 'express';\nimport { z } from 'zod';\n\ntype OrderId = string;\n\ninterface Order {\n  id: OrderId;\n  total: number;\n}\n\nconst schema = z.object({ id: z.string(), total: z.number() });\n\nexport async function getOrder(req: Request, res: Response): Promise<void> {\n  const parsed = schema.safeParse(req.body);\n  if (!parsed.success) { res.status(400).json({ error: 'bad' }); return; }\n  const order: Order = parsed.data;\n  const view: Partial<Order> = { id: order.id };\n  res.json(view);\n}\n",
    "VBNet": "Imports System\nImports System.Collections.Generic\n\nPublic Class OrderService\n    Private ReadOnly _orders As New List(Of Order)()\n\n    Public Function Find(id As Integer) As Order\n        For Each o In _orders\n            If o.Id = id Then Return o\n        Next\n        Return Nothing\n    End Function\n\n    Public Sub Add(o As Order)\n        _orders.Add(o)\n    End Sub\nEnd Class\n",
}

OTHER_SAMPLES = {
    "healthcare": {
        "phi_record": lambda rng: f"Patient: A. Nguyen, MRN {rng.randint(1000000,9999999)}, account number {rng.randint(100000000,999999999)}, date of birth {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(50,95)}, legal sex F. Discharge summary: diagnosis pneumonia, prescribed amoxicillin 500 mg daily, attending physician Dr. Rao. History of present illness: three days of fever. Assessment and plan: follow up in clinic.",
        "phi_bulk": lambda rng: "\n".join(f"MRN {rng.randint(1000000,9999999)}, DOB {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(50,95)}, account number {rng.randint(100000000,999999999)}, patient {n}" for n in range(14)) + "\nDischarge summary export for the diabetes clinic.",
    },
    "cui": {
        "cui_banner": lambda rng: "CONTROLLED UNCLASSIFIED INFORMATION\nCUI//SP-PRVCY//NOFORN\nControlled by: Department of Energy. CUI Category: Privacy. Distribution/Dissemination Control: FEDCON. POC: J. Lee, 202-555-0100.\n(CUI) The attached personnel roster contains privacy information. Decontrol on 2031-01-01.",
        "fouo_legacy": lambda rng: "FOR OFFICIAL USE ONLY\nThis document contains information exempt from mandatory disclosure under the FOIA. Exemption 5 applies. Not for release outside the agency. FOUO markings apply to every page.",
    },
    "zbp": {
        "tax_forms": lambda rng: f"Form W-2 Wage and Tax Statement, employee SSN {ssn(rng)}, employer identification number 12-{rng.randint(1000000,9999999)}. Box 1 wages 84,200.00, federal income tax withheld 9,310.00. Copy B to be filed with employee's federal tax return. Form 1040 line 1a. Schedule 1 attached.",
        "private_key": lambda rng: "Deploy key for the build server:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA" + "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(120)) + "\n-----END RSA PRIVATE KEY-----\nDo not commit this file.",
        "itar_legend": lambda rng: "WARNING: This document contains technical data whose export is restricted by the Arms Export Control Act (Title 22, U.S.C., Sec 2751, et seq.) or the Export Administration Act of 1979, as amended. This information may be subject to the International Traffic in Arms Regulations. Violations are subject to severe criminal penalties. USML Category VIII.",
        "itar_mention": lambda rng: "This technical data is controlled under the International Traffic in Arms Regulations (ITAR), 22 CFR 120-130. Export controlled: USML Category VIII. Not for release to foreign persons without a license from the Directorate of Defense Trade Controls. ECCN 9A610.",
        "tlp_red": lambda rng: "TLP:RED. Incident 2026-0412: credential stuffing against the customer portal from 14 IPs. Not for disclosure, restricted to participants only. Indicators attached.",
        "us_pii_export": lambda rng: "\n".join(f"{n}, SSN {ssn(rng)}, DOB {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(50,95)}, driver license number {rng.choice('ABC')}{rng.randint(1000000,9999999)}" for n in ("A. Kim", "B. Ortiz", "C. Weber", "D. Chen", "E. Rossi", "F. Byrne")) + "\nHR export for the benefits enrolment vendor.",
    },
    "endpoint": {
        "pci_usb": lambda rng: "Copying the chargeback spreadsheet to the USB drive. " + " ".join(luhn_number(rng, "4") for _ in range(4)) + " are the disputed card numbers, expiry dates in column C.",
    },
    "cjis": {
        "ncic_query": lambda rng: f"NCIC/III query results. ORI CA{rng.randint(1000000,9999999)}, purpose code C, QH inquiry on subject DOB {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(60,95)}, SSN {ssn(rng)}. Criminal history record information returned: two prior arrests. Hit confirmation requested. Law Enforcement Sensitive, CJIS.",
        "warrant": lambda rng: f"WANTED PERSON. Active warrant issued by Harris County. Subject SSN {ssn(rng)}, DOB {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(60,95)}, driver license number TX{rng.randint(10000000,99999999)}. Extradition limits: full. NCIC entry confirmed. Law Enforcement Sensitive.",
        "rap_sheet": lambda rng: f"CRIMINAL HISTORY RECORD INFORMATION. NCIC ORI: TX{rng.randint(1000000,9999999)}. FBI UCN {rng.randint(100000,999999)}AB{rng.randint(1,9)}. SID: {rng.randint(10000000,99999999)}. Subject DOB {rng.randint(1,12):02d}/{rng.randint(1,28):02d}/19{rng.randint(60,95)}, SSN {ssn(rng)}, driver license number {rng.choice('ABC')}{rng.randint(1000000,9999999)}. Purpose code C. Query III returned prior arrests. Law Enforcement Sensitive.",
    },
}


def build_docs(rng, iteration: int) -> List[Dict[str, Any]]:
    """Every sample document for one iteration, with its class and pack."""
    docs = []
    for k, v in banking_samples(rng).items():
        docs.append({"pack": "global_banking_baseline", "cls": k, "positive": True, "text": v})
    for lang, code in CODE_SAMPLES.items():
        docs.append({"pack": "zbp_source_code_baseline", "cls": lang, "positive": True, "text": code})
    fx = os.path.join(ROOT, "tools", "fixtures", "source_code_examples.json")
    if os.path.exists(fx):
        for lang, item in json.load(open(fx, encoding="utf-8")).items():
            ex = list(item["examples"]); rng.shuffle(ex)
            docs.append({"pack": "zbp_source_code_baseline", "cls": lang, "positive": True, "text": "\n".join(ex[: max(10, len(ex) // 2)]), "source": "library examples"})
    for pack, items in (("healthcare_phi_baseline", OTHER_SAMPLES["healthcare"]), ("cui_marking_baseline", OTHER_SAMPLES["cui"]), ("cjis_policy_pack", OTHER_SAMPLES["cjis"]),
                        ("zbp_enterprise_baseline", OTHER_SAMPLES["zbp"]), ("zbp_endpoint_dlp_baseline", OTHER_SAMPLES["endpoint"]), ("fed_policy_pack", OTHER_SAMPLES["zbp"])):
        for k, fn in items.items():
            docs.append({"pack": pack, "cls": k, "positive": True, "text": fn(rng)})
    for k, items in NEGATIVES.items():
        for t in items:
            docs.append({"pack": "*", "cls": f"negative:{k}", "positive": False, "text": t})
    # Randomise: noise paragraphs before/after, case changes, shuffled lines for prose.
    out = []
    for d in docs:
        text = d["text"]
        if rng.random() < 0.6:
            text = rng.choice(NOISE) + "\n\n" + text
        if rng.random() < 0.6:
            text = text + "\n\n" + rng.choice(NOISE)
        if d["positive"] and rng.random() < 0.25 and d["cls"] in ("kyc_file", "mnpi_memo", "confidential_marking", "cui_banner", "fouo_legacy"):
            text = text.upper() if rng.random() < 0.5 else text.lower()
            d = dict(d, variant="case-changed")
        out.append(dict(d, text=text, iteration=iteration))
    return out


# Which engines are expected to fire for which sample classes.
EXPECT = {
    "global_banking_baseline": {
        "card_export": ["Bank-Payment Card Data"], "card_bulk_export": ["Bank-Payment Card Data", "Bank-Payment Card Data - Bulk"], "single_card_with_cvv": ["Bank-Payment Card Data"],
        "wire_instructions": ["Bank-Account and Payment Instructions"], "iban_list": ["Bank-Account and Payment Instructions"],
        "statement": ["Bank-Customer Financial Records"], "kyc_file": ["Bank-KYC and AML Files"], "loan_application": ["Bank-Credit and Loan Applications"],
        "mnpi_memo": ["Bank-MNPI and Deal Information", "Bank-Confidential Markings"], "confidential_marking": ["Bank-Confidential Markings"],
        "pii_form": ["Bank-Customer PII (Global)"], "uk_ids": ["Bank-Customer PII (Global)"], "apac_ids": ["Bank-Customer PII (Global)"],
    },
    "zbp_source_code_baseline": {lang: [f"SRC-{lang}"] for lang in CODE_SAMPLES},
    "healthcare_phi_baseline": {"phi_record": ["E_HEALTHCARE_PHI"], "phi_bulk": ["E_PHI_BULK_EXPORT"]},
    "cui_marking_baseline": {"cui_banner": ["CUI-Detect-All"], "fouo_legacy": ["CUI-Detect-All"]},
    "cjis_policy_pack": {"rap_sheet": ["CJIS Any-Signal Engine", "Criminal History / RAP Sheet Engine"], "ncic_query": ["CJIS Any-Signal Engine", "NCIC / III Data Engine"], "warrant": ["Warrant / Wanted-Person Engine"]},
    "zbp_enterprise_baseline": {"tax_forms": ["ZBP-Financial Information", "ZBP-US PII"], "private_key": ["ZBP-Private Keys"], "itar_legend": ["ZBP-ITAR Phrases"], "itar_mention": [], "tlp_red": ["ZBP-TLP Red"], "us_pii_export": ["ZBP-US PII"]},
    "fed_policy_pack": {"tax_forms": ["Financial Information", "US PII"], "private_key": ["Private Keys"], "itar_legend": ["ITAR Phrases"], "itar_mention": [], "tlp_red": ["TLP Red"], "us_pii_export": ["US PII"]},
    "zbp_endpoint_dlp_baseline": {"pci_usb": ["PCI - Low", "PCI - Medium"]},
}


# ── The run ──────────────────────────────────────────────────────────

def run(iterations: int, seed: int = 7) -> Dict[str, Any]:
    packs = {p["id"]: Pack(p) for p in discover_packs()}
    static = {pid: static_checks(p) for pid, p in packs.items()}
    # stats[pack][engine] = {"tp":[per-iter], "fn":[], "fp":[], "cross":[]}
    stats: Dict[str, Dict[str, Dict[str, List[int]]]] = {pid: {e.name: {"tp": [], "fn": [], "fp": [], "cross": [], "also": []} for e in p.engines} for pid, p in packs.items()}
    examples: Dict[str, Dict[str, List[str]]] = {pid: {} for pid in packs}
    overlap: Dict[str, Dict[str, List[str]]] = {pid: {} for pid in packs}
    started = time.time()
    for it in range(iterations):
        rng = random.Random(seed * 1000 + it)
        docs = build_docs(rng, it)
        per = {pid: {e.name: {"tp": 0, "fn": 0, "fp": 0, "cross": 0, "also": 0} for e in p.engines} for pid, p in packs.items()}
        for pid, pack in packs.items():
            expect = EXPECT.get(pid, {})
            for d in docs:
                fired = pack.evaluate(d["text"])
                if d["pack"] == pid:
                    wanted = set(expect.get(d["cls"], []))
                    for en, f in fired.items():
                        if en in wanted:
                            per[pid][en]["tp" if f else "fn"] += 1
                            if not f and len(examples[pid].setdefault(en, [])) < 3:
                                examples[pid][en].append(f"missed: {d['cls']}" + (f" ({d.get('variant')})" if d.get("variant") else ""))
                        elif f and pid == "zbp_source_code_baseline" and d["cls"] in CODE_SAMPLES:
                            per[pid][en]["cross"] += 1     # a language engine fired on another language
                            if len(examples[pid].setdefault(en, [])) < 3:
                                examples[pid][en].append(f"cross-fired on {d['cls']} sample")
                elif not d["positive"]:
                    for en, f in fired.items():
                        if f:
                            per[pid][en]["fp"] += 1
                            if len(examples[pid].setdefault(en, [])) < 3:
                                examples[pid][en].append(f"FALSE POSITIVE on {d['cls']}")
                else:
                    for en, f in fired.items():
                        if f:
                            per[pid][en]["also"] += 1
                            key = f"also detects {d['cls']} ({d['pack']})"
                            if key not in overlap[pid].setdefault(en, []):
                                overlap[pid][en].append(key)
        for pid in packs:
            for en in per[pid]:
                for k in ("tp", "fn", "fp", "cross", "also"):
                    stats[pid][en][k].append(per[pid][en][k])
    # Summaries.
    summary: Dict[str, Any] = {}
    for pid, pack in packs.items():
        rows = []
        for e in pack.engines:
            s = stats[pid][e.name]
            tp, fn, fp, cross = (sum(s[k]) for k in ("tp", "fn", "fp", "cross"))
            tested = tp + fn > 0
            prec = tp / (tp + fp + cross) if (tp + fp + cross) else None
            rec = tp / (tp + fn) if (tp + fn) else None
            per_iter_recall = [t / (t + f) for t, f in zip(s["tp"], s["fn"]) if t + f]
            rows.append({"engine": e.name, "tested": tested, "positives": tp + fn, "hits": tp, "misses": fn, "false_positives": fp, "cross_fires": cross,
                         "precision": None if prec is None else round(prec, 3), "recall": None if rec is None else round(rec, 3),
                         "recall_min": round(min(per_iter_recall), 3) if per_iter_recall else None, "recall_max": round(max(per_iter_recall), 3) if per_iter_recall else None,
                         "uses_proxy": any(n in PROXIES for n in e.refs), "notes": examples[pid].get(e.name, []), "also_detects": overlap[pid].get(e.name, [])})
        tested_rows = [r for r in rows if r["tested"]]
        summary[pid] = {"name": pack.name, "static": static[pid], "engines": rows,
                        "tested_engines": len(tested_rows), "untested_engines": len(rows) - len(tested_rows),
                        "recall_mean": round(statistics.mean([r["recall"] for r in tested_rows if r["recall"] is not None]), 3) if tested_rows else None,
                        "precision_mean": round(statistics.mean([r["precision"] for r in tested_rows if r["precision"] is not None]), 3) if tested_rows else None,
                        "false_positive_total": sum(r["false_positives"] for r in rows), "cross_fire_total": sum(r["cross_fires"] for r in rows)}
    docs_per_iter = len(build_docs(random.Random(0), 0))
    return {"generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "iterations": iterations, "documents_per_iteration": docs_per_iter,
            "evaluations": iterations * docs_per_iter * sum(len(p.engines) for p in packs.values()), "elapsed_seconds": round(time.time() - started, 1),
            "packs": summary, "proxies": sorted(PROXIES), "method": METHOD}


METHOD = (
    "Static validation reads every pack's dictionaries, engines and rules and checks compile-ability, ZIA limits (8 patterns, 256 bytes per pattern, "
    "no lookaround, 3-128 byte phrases, proximity 0-10000), engine match counts under 1000, that every D: reference resolves to a pack or predefined "
    "dictionary, that every rule's engines exist and that every rule ships DISABLED. Dynamic validation runs a local evaluator that mirrors ZIA's counting: "
    "unique regex matches per pattern, case-insensitive phrase counts, pattern-with-phrase dictionaries only count a pattern when a phrase is within the "
    "proximity window, and engine expressions are evaluated with All/Any (AND/OR) exactly as written. Predefined Zscaler dictionaries cannot run outside a "
    "tenant, so they are replaced by labelled proxies: Luhn-validated card numbers, mod-97 validated IBANs, ABA-checksummed routing numbers, SSN/ITIN shapes, "
    "passport and licence shapes anchored to their words, and short keyword lists for the ML and content dictionaries. Every iteration regenerates the sample "
    "documents with new identifiers, shuffles lines, adds unrelated business text before or after, and changes case on a quarter of the positives; negatives "
    "are ordinary business documents (meeting notes, an invoice, CSV, JSON, Markdown, logs) that must fire nothing. Precision counts false positives on "
    "negatives and, for the source-code pack, cross-fires on other languages. Python's re engine stands in for ZIA's PCRE; the constructs used ((?m), (?i), "
    "non-capturing groups, \\b, character classes) behave the same in both."
)


def to_markdown(r: Dict[str, Any]) -> str:
    L = [f"# Detection logic validation — {r['generated_at']}", "",
         f"{r['iterations']} iterations × {r['documents_per_iteration']} documents; {r['evaluations']:,} engine evaluations in {r['elapsed_seconds']} s.", ""]
    for pid, p in r["packs"].items():
        st = p["static"]
        L += [f"## {p['name']} (`{pid}`)", "",
              f"{st['dictionaries']} dictionaries ({st['clones']} clones of predefined), {st['engines']} engines, {st['rules']} rules across {', '.join(st['channels'])}. "
              f"Static problems: {len(st['problems'])}. Tested engines: {p['tested_engines']} (untested: {p['untested_engines']}). "
              f"Mean recall {p['recall_mean']}, mean precision {p['precision_mean']}, false positives {p['false_positive_total']}, cross-fires {p['cross_fire_total']}.", ""]
        for prob in st["problems"]:
            L.append(f"- PROBLEM: {prob}")
        L += ["", "| Engine | Positives | Hits | Misses | FP | Cross | Recall (min–max) | Precision | Proxy |", "|---|---|---|---|---|---|---|---|---|"]
        for e in p["engines"]:
            rec = f"{e['recall']} ({e['recall_min']}–{e['recall_max']})" if e["recall"] is not None else "not tested"
            L.append(f"| {e['engine']} | {e['positives']} | {e['hits']} | {e['misses']} | {e['false_positives']} | {e['cross_fires']} | {rec} | {e['precision'] if e['precision'] is not None else '–'} | {'yes' if e['uses_proxy'] else ''} |")
        notes = [(e["engine"], n) for e in p["engines"] for n in e["notes"] + [a for a in e["also_detects"]]]
        if notes:
            L += ["", "Notes:"] + [f"- {en}: {n}" for en, n in notes[:20]]
        L.append("")
    L += ["## Method", "", r["method"], "", "Proxies used for predefined dictionaries: " + ", ".join(r["proxies"]) + "."]
    return "\n".join(L) + "\n"


def to_html(r: Dict[str, Any]) -> str:
    E = html.escape
    parts = [f"<title>Detection Logic Validation</title><style>body{{font-family:Segoe UI,Helvetica,Arial,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;line-height:1.5;color:#14202b;background:#fff}}table{{border-collapse:collapse;width:100%;font-size:.9rem}}th,td{{border-bottom:1px solid #ddd;padding:.4rem .5rem;text-align:left}}th{{font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:#555}}.ok{{color:#1f7a4d;font-weight:600}}.bad{{color:#b23a3a;font-weight:600}}.warn{{color:#a86b00;font-weight:600}}code{{font-size:.85em}}.k{{font-size:.8rem;color:#555}}</style>",
             f"<h1>Detection logic validation</h1><p class=k>{E(r['generated_at'])} · {r['iterations']} iterations × {r['documents_per_iteration']} documents · {r['evaluations']:,} engine evaluations · {r['elapsed_seconds']} s</p>"]
    for pid, p in r["packs"].items():
        st = p["static"]
        prob = f"<span class=bad>{len(st['problems'])} static problems</span>" if st["problems"] else "<span class=ok>no static problems</span>"
        parts.append(f"<h2>{E(p['name'])} <span class=k>{E(pid)}</span></h2><p>{st['dictionaries']} dictionaries ({st['clones']} clones), {st['engines']} engines, {st['rules']} rules across {E(', '.join(st['channels']))}. {prob}. "
                     f"Tested engines {p['tested_engines']}, untested {p['untested_engines']}. Mean recall <b>{p['recall_mean']}</b>, mean precision <b>{p['precision_mean']}</b>, false positives <b>{p['false_positive_total']}</b>, cross-fires <b>{p['cross_fire_total']}</b>.</p>")
        if st["problems"]:
            parts.append("<ul>" + "".join(f"<li class=bad>{E(x)}</li>" for x in st["problems"]) + "</ul>")
        parts.append("<table><tr><th>Engine</th><th>Positives</th><th>Hits</th><th>Misses</th><th>FP</th><th>Cross</th><th>Recall (min–max)</th><th>Precision</th><th>Proxy</th><th>Notes</th></tr>")
        for e in p["engines"]:
            rec = f"{e['recall']} ({e['recall_min']}–{e['recall_max']})" if e["recall"] is not None else "<span class=k>not tested</span>"
            cls = "ok" if (e["recall"] or 0) >= 0.95 and not e["false_positives"] and not e["cross_fires"] else ("warn" if e["tested"] else "")
            parts.append(f"<tr class='{cls}'><td>{E(e['engine'])}</td><td>{e['positives']}</td><td>{e['hits']}</td><td>{e['misses']}</td><td>{e['false_positives']}</td><td>{e['cross_fires']}</td><td>{rec}</td><td>{e['precision'] if e['precision'] is not None else '–'}</td><td>{'yes' if e['uses_proxy'] else ''}</td><td class=k>{E('; '.join(e['notes'] + e['also_detects']))}</td></tr>")
        parts.append("</table>")
    parts.append(f"<h2>Method</h2><p>{E(r['method'])}</p><p class=k>Proxies: {E(', '.join(r['proxies']))}</p>")
    return "\n".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iterations", type=int, default=100)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--out", default="validation")
    a = ap.parse_args()
    r = run(a.iterations, a.seed)
    json.dump(r, open(a.out + ".json", "w", encoding="utf-8"), indent=1)
    open(a.out + ".md", "w", encoding="utf-8").write(to_markdown(r))
    open(a.out + ".html", "w", encoding="utf-8").write(to_html(r))
    for pid, p in r["packs"].items():
        print(f"{pid:28} static problems {len(p['static']['problems']):2}  tested {p['tested_engines']:2}/{p['tested_engines'] + p['untested_engines']:2}  recall {p['recall_mean']}  precision {p['precision_mean']}  FP {p['false_positive_total']}  cross {p['cross_fire_total']}")
    print(f"{r['evaluations']:,} evaluations in {r['elapsed_seconds']} s -> {a.out}.json/.md/.html")
    return 0


if __name__ == "__main__":
    sys.exit(main())
