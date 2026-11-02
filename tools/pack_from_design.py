#!/usr/bin/env python3
"""
Convert a dictionary/engine DESIGN file (the "ZIA dlpDictionaries" JSON a
DLP engineer hands over, with `_`-prefixed build metadata) into pack
configs.

    python tools/pack_from_design.py <pack_dir>            # reads <pack_dir>/design.json
    python tools/pack_from_design.py <pack_dir> design.json

Writes <pack_dir>/configs/dlp_dictionaries.json and dlp_engines.json and
<pack_dir>/README.md (the tier / intended-action / notes table). Policies
and pack.json are authored by hand and left alone.

Design format (per dictionary): name, description, customPhraseMatchType,
patterns [{action, pattern}], phrases [{action, phrase}], proximity,
plus metadata `_tier`, `_min_match_count`, `_intended_action`
(Block | Caution | Exclude), `_notes`, `_VERIFY`. Engines: name,
description, engineExpression with `${Dictionary-Name}.S` placeholders.

Besides the designed engines, two are DERIVED when the metadata is
present: `<Prefix>-Detect-Block-Grade` over the Block dictionaries and
`<Prefix>-Detect-Caution-Grade` over the Caution ones, each with the
dictionaries' minimum counts and `AND NOT` over every Exclude
dictionary. Documented ZIA limits are enforced (8 patterns per
dictionary, 256 bytes per pattern, proximity 0-10000, no lookaround,
255-byte descriptions).
"""
from __future__ import annotations

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dlp_importer import DICT_DESCRIPTION_MAX, dictionary_limit_problems, engine_limit_problems  # noqa: E402
from open_source import NOTE_MD  # noqa: E402

TIER_LABEL = {1: "Tier 1 structural marking", 2: "Tier 2 category token", 3: "Tier 3 malformed marking (proximity)",
              4: "Tier 4 legacy marking", 5: "Tier 5 designation block", 6: "Tier 6 exclusion"}
PER_OPERATOR = 16


def _ref(expr: str) -> str:
    return re.sub(r"\$\{([^}]+)\}\.S", r"D:\1", expr)


def _term(d: dict) -> str:
    return f"(D:{d['name']} > {max(0, int(d.get('_min_match_count') or 1) - 1)})"


def _or_groups(ds: list) -> str:
    chunks = [ds[i:i + PER_OPERATOR] for i in range(0, len(ds), PER_OPERATOR)]
    return "(" + " OR ".join("(" + " OR ".join(_term(d) for d in c) + ")" for c in chunks) + ")"


def convert(design: dict, prefix: str) -> tuple[list, list, str]:
    dicts, rows, problems = [], [], []
    for d in design["dictionaries"]:
        tier = d.get("_tier")
        meta = []
        if tier in TIER_LABEL:
            meta.append(TIER_LABEL[tier])
        if d.get("_intended_action"):
            meta.append(f"intended action {d['_intended_action']}")
        if d.get("_min_match_count"):
            meta.append(f"min matches {d['_min_match_count']}")
        desc = d["description"].strip()
        if meta:
            desc = f"{desc} {'; '.join(meta)}."
        o = {"name": d["name"], "description": desc, "custom_phrase_match_type": d["customPhraseMatchType"]}
        if d.get("proximity"):
            o["proximity"] = int(d["proximity"])
            # ZIA needs both the window and the enable flag on custom dictionaries.
            o["proximity_enabled_for_custom_dictionary"] = bool(d.get("proximityEnabledForCustomDictionary", True))
        o["patterns"] = list(d.get("patterns") or [])
        o["phrases"] = list(d.get("phrases") or [])
        if len(desc.encode("utf-8")) > DICT_DESCRIPTION_MAX:
            problems.append(f"{d['name']}: description {len(desc.encode('utf-8'))} bytes > {DICT_DESCRIPTION_MAX}")
        problems.extend(f"{d['name']}: {p}" for p in dictionary_limit_problems(o))
        dicts.append(o)
        rows.append((d["name"], tier, d.get("_intended_action", ""), d.get("_min_match_count", ""), d.get("_notes", ""), d.get("_VERIFY", "")))
    if problems:
        raise SystemExit("Design violates documented ZIA limits:\n  " + "\n  ".join(problems))

    engines = []
    for e in design.get("engines") or []:
        engines.append({"name": e["name"], "description": e["description"], "expression": _ref(e["engineExpression"])})
    by_action: dict = {}
    for d in design["dictionaries"]:
        if d.get("_intended_action"):
            by_action.setdefault(d["_intended_action"], []).append(d)
    excl = by_action.get("Exclude") or []
    not_part = (" AND NOT (" + " OR ".join(f"(D:{d['name']} > 0)" for d in excl) + ")") if excl else ""
    if by_action.get("Block"):
        engines.append({"name": f"{prefix}-Detect-Block-Grade",
                        "description": f"High-precision signals intended to BLOCK ({len(by_action['Block'])} dictionaries with their minimum counts)"
                                       + (", minus the exclusion dictionaries." if excl else "."),
                        "expression": _or_groups(by_action["Block"]) + not_part})
    if by_action.get("Caution"):
        engines.append({"name": f"{prefix}-Detect-Caution-Grade",
                        "description": f"Lower-precision signals intended to CAUTION ({len(by_action['Caution'])} dictionaries with their minimum counts)"
                                       + (", minus the exclusion dictionaries. Never wire to BLOCK." if excl else ". Never wire to BLOCK."),
                        "expression": _or_groups(by_action["Caution"]) + not_part})
    for e in engines:
        if len(e["description"].encode("utf-8")) > DICT_DESCRIPTION_MAX:
            raise SystemExit(f"engine {e['name']}: description too long")
        if engine_limit_problems(e["expression"]):
            raise SystemExit(f"engine {e['name']}: " + "; ".join(engine_limit_problems(e["expression"])))

    lines = [f"# {design.get('_title') or prefix} — dictionary notes\n\n", NOTE_MD + "\n\n",
             "Build metadata from the design file (tier, intended action, minimum match count, notes). "
             "The pack configs carry the API fields only; regenerate with `python tools/pack_from_design.py <pack_dir>`.\n\n"]
    if design.get("_documented_limits"):
        lines.append(f"**Documented ZIA limits:** {design['_documented_limits']}\n\n")
    if design.get("_proximity_semantics"):
        lines.append(f"**Proximity semantics:** {design['_proximity_semantics']}\n\n")
    if design.get("_phrase_semantics"):
        lines.append(f"**Phrase semantics:** {design['_phrase_semantics']}\n\n")
    lines.append("| Dictionary | Tier | Intended action | Min matches | Notes |\n|---|---|---|---|---|\n")
    for n, t, a, m, no, v in rows:
        note = no + (f" **VERIFY:** {v}" if v else "")
        lines.append(f"| {n} | {t} | {a} | {m} | {note} |\n")
    lines.append("\n## Engines\n\n")
    for e in engines:
        lines.append(f"- **{e['name']}**: {e['description']}\n")
    for e in design.get("engines") or []:
        if e.get("_notes"):
            lines.append(f"\n{e['name']} design note: {e['_notes']}\n")
    if design.get("_builder_limits"):
        lines.append(f"\nEngine Builder limits: {design['_builder_limits']}\n")
    return dicts, engines, "".join(lines)


def _write_notes(path: str, readme: str) -> None:
    tail = ""
    if os.path.exists(path):
        old = open(path, encoding="utf-8").read()
        if "\n## Rules\n" in old:
            tail = "\n## Rules\n" + old.split("\n## Rules\n", 1)[1]
    open(path, "w", encoding="utf-8").write(readme + tail)


def _merge(existing: list, generated: list, owns: list) -> list:
    """Replace the entries a design owns (by name prefix) and keep the rest
    of a hand-authored pack untouched, so one pack can carry several
    designs next to its own dictionaries and engines."""
    kept = [o for o in existing if not any(o["name"].startswith(p) for p in owns)]
    return kept + generated


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    pack_dir = argv[1]
    meta_path = os.path.join(pack_dir, "pack.json")
    meta = json.load(open(meta_path, encoding="utf-8")) if os.path.exists(meta_path) else {}
    cfg = os.path.join(pack_dir, "configs")
    os.makedirs(cfg, exist_ok=True)
    # A pack can declare the designs it carries in pack.json:
    #   "designs": [{"file": "cui_design.json", "prefix": "CUI", "owns": ["CUI-", "Legacy-"], "notes": "CUI_MARKINGS.md"}]
    # Each design then replaces only the dictionaries/engines it owns and
    # writes its notes file; the pack's other objects are left alone.
    designs = meta.get("designs") if len(argv) < 3 else None
    if designs:
        dp, ep = os.path.join(cfg, "dlp_dictionaries.json"), os.path.join(cfg, "dlp_engines.json")
        all_d = json.load(open(dp, encoding="utf-8")) if os.path.exists(dp) else []
        all_e = json.load(open(ep, encoding="utf-8")) if os.path.exists(ep) else []
        for spec in designs:
            design = json.load(open(os.path.join(pack_dir, spec["file"]), encoding="utf-8"))
            dicts, engines, readme = convert(design, spec.get("prefix") or "PACK")
            owns = spec.get("owns") or [f"{spec.get('prefix', 'PACK')}-"]
            all_d, all_e = _merge(all_d, dicts, owns), _merge(all_e, engines, owns)
            _write_notes(os.path.join(pack_dir, spec.get("notes") or "README.md"), readme)
            print(f"{pack_dir}: design {spec['file']} -> {len(dicts)} dictionaries, {len(engines)} engines merged")
        json.dump(all_d, open(dp, "w", encoding="utf-8"), indent=2)
        json.dump(all_e, open(ep, "w", encoding="utf-8"), indent=2)
        return 0
    design_path = argv[2] if len(argv) > 2 else os.path.join(pack_dir, "design.json")
    design = json.load(open(design_path, encoding="utf-8"))
    prefix = (meta.get("baseline") or {}).get("prefix", "").rstrip("-") or meta.get("name", "PACK").split()[0]
    dicts, engines, readme = convert(design, prefix)
    json.dump(dicts, open(os.path.join(cfg, "dlp_dictionaries.json"), "w", encoding="utf-8"), indent=2)
    json.dump(engines, open(os.path.join(cfg, "dlp_engines.json"), "w", encoding="utf-8"), indent=2)
    _write_notes(os.path.join(pack_dir, "README.md"), readme)
    print(f"{pack_dir}: {len(dicts)} dictionaries, {len(engines)} engines -> configs/, README.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
