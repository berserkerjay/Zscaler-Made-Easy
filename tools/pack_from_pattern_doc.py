#!/usr/bin/env python3
"""Rebuild the source-code pack from a "DLP Pattern Library" Word document.

The document (v4.14 layout) has one table per language: eight Signal
patterns (rows 1-8) and one Anchor pattern (last row, marked with an
anchor symbol). Each language becomes two Zscaler dictionaries and one
engine that requires both:

    (D:<prefix><Lang> Signal > <threshold>) AND (D:<prefix><Lang> Anchor > 0)

Usage:
    python tools/pack_from_pattern_doc.py <doc.docx> [--pack zbp_source_code_baseline]
        [--prefix SRC-] [--threshold 4] [--html-threshold 3]

Writes configs/dlp_dictionaries.json and configs/dlp_engines.json for the
pack, rewrites the pack's DLP rules to reference the new engines, and
prints what changed. Run `python pack_terraform.py <pack> --out terraform`
afterwards so the committed Terraform workspace matches.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Display names used in the pack (short, portal-friendly).
LANG_SHORT = {
    "C# (C-Sharp)": "CSharp", "C++": "CPlusPlus", "Visual Basic (.NET)": "VBNet",
}
UNIQ = "PATTERN_COUNT_TYPE_UNIQUE"
ANY = "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"


def read_doc(path: str) -> Tuple[List[str], List[List[List[str]]]]:
    import docx  # python-docx
    d = docx.Document(path)
    paras = [p.text for p in d.paragraphs]
    tables = [[[c.text for c in r.cells] for r in t.rows] for t in d.tables]
    return paras, tables


def language_headings(paras: List[str]) -> List[str]:
    """Section headings: short capitalised lines that are not the front matter."""
    skip = ("Architecture", "Why each", "Reference", "DLP Pattern", "Within each")
    out = []
    for p in paras:
        t = p.strip()
        if t and len(t) < 28 and t[0].isupper() and not t.startswith(skip) and not t[0].isdigit():
            out.append(t)
    return out


def parse(paras: List[str], tables: List[List[List[str]]]) -> List[Dict[str, Any]]:
    langs = language_headings(paras)
    pattern_tables = [t for t in tables if t and len(t[0]) >= 3 and "regex" in " ".join(t[0]).lower()]
    if len(pattern_tables) != len(langs):
        raise SystemExit(f"found {len(langs)} language headings but {len(pattern_tables)} pattern tables: {langs}")
    out = []
    for lang, table in zip(langs, pattern_tables):
        signals, anchor = [], None
        for row in table[1:]:
            num, what, regex = row[0].strip(), row[1].strip(), row[2].strip()
            if not regex:
                continue
            entry = {"n": num, "what": what.replace("ANCHOR\n", "").strip(), "regex": regex}
            if num.isdigit():
                signals.append(entry)
            else:
                anchor = entry
        if not anchor or not signals:
            raise SystemExit(f"{lang}: expected signal rows and one anchor row")
        out.append({"lang": lang, "short": LANG_SHORT.get(lang, re.sub(r"[^A-Za-z0-9]", "", lang)), "signals": signals, "anchor": anchor})
    return out


def build(langs: List[Dict[str, Any]], prefix: str, threshold: int, html_threshold: int, version: str):
    from dlp_importer import dictionary_limit_problems
    dicts, engines = [], []
    for L in langs:
        sig_name = f"{prefix}{L['short']} Signal"
        anc_name = f"{prefix}{L['short']} Anchor"
        sig = {"name": sig_name,
               "description": f"{L['lang']} syntax evidence (v{version}): {len(L['signals'])} patterns counted as unique matches. Fires the engine only together with the Anchor.",
               "custom_phrase_match_type": ANY,
               "patterns": [{"action": UNIQ, "pattern": s["regex"]} for s in L["signals"]], "phrases": [],
               "_patterns_explained": [{"n": s["n"], "what": s["what"]} for s in L["signals"]]}
        anc = {"name": anc_name,
               "description": f"{L['lang']} structural fingerprint (v{version}): {L['anchor']['what'][:150]}",
               "custom_phrase_match_type": ANY,
               "patterns": [{"action": UNIQ, "pattern": L["anchor"]["regex"]}], "phrases": []}
        for d in (sig, anc):
            problems = dictionary_limit_problems(d)
            if problems:
                raise SystemExit(f"{d['name']}: {'; '.join(problems)}")
        dicts += [sig, anc]
        thr = html_threshold if L["short"].upper() == "HTML" else threshold
        engines.append({"name": f"{prefix}{L['short']}",
                        "description": f"{L['lang']} source code: the Anchor fingerprint is present AND more than {thr} Signal matches accumulate (All/AND), which is what removes cousin-language false positives.",
                        "expression": f"((D:{sig_name} > {thr}) AND (D:{anc_name} > 0))"})
    return dicts, engines


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("doc")
    ap.add_argument("--pack", default="zbp_source_code_baseline")
    ap.add_argument("--prefix", default="SRC-")
    ap.add_argument("--threshold", type=int, default=4, help="Signal count the engine needs (> N)")
    ap.add_argument("--html-threshold", type=int, default=3)
    ap.add_argument("--version", default="")
    args = ap.parse_args()
    paras, tables = read_doc(args.doc)
    version = args.version or (re.search(r"v(\d+\.\d+)", " ".join(paras[:3])) or [None, "?"])[1]
    langs = parse(paras, tables)
    dicts, engines = build(langs, args.prefix, args.threshold, args.html_threshold, version)
    pack_dir = os.path.join(ROOT, args.pack)
    cfg = os.path.join(pack_dir, "configs")
    os.makedirs(cfg, exist_ok=True)
    old_engines = []
    try:
        old_engines = [e["name"] for e in json.load(open(os.path.join(cfg, "dlp_engines.json"), encoding="utf-8"))]
    except Exception:  # noqa: BLE001
        pass
    json.dump(dicts, open(os.path.join(cfg, "dlp_dictionaries.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    json.dump(engines, open(os.path.join(cfg, "dlp_engines.json"), "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    # Rules that referenced the old engines now reference every new engine.
    pol_path = os.path.join(cfg, "dlp_policies.json")
    if os.path.exists(pol_path):
        policies = json.load(open(pol_path, encoding="utf-8"))
        names = [e["name"] for e in engines]
        for p in policies:
            if p.get("engines"):
                p["engines"] = names
        json.dump(policies, open(pol_path, "w", encoding="utf-8"), indent=2, ensure_ascii=False)
    print(f"{args.pack}: {len(langs)} languages -> {len(dicts)} dictionaries, {len(engines)} engines "
          f"(signal > {args.threshold}, HTML > {args.html_threshold}); replaced engines: {', '.join(old_engines) or 'none'}")
    for L in langs:
        print(f"  {L['lang']:<22} {len(L['signals'])} signal patterns, anchor: {L['anchor']['what'][:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
