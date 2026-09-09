#!/usr/bin/env python3
"""
Convert a Terraform JSON template of ZIA DLP resources into a DLP-Check
policy pack.

Reads a `.tf.json` document that declares `zia_dlp_dictionaries`,
`zia_dlp_engines` and `zia_dlp_web_rules` resources (plus
`data.zia_dlp_dictionaries` lookups for predefined templates), and writes
a pack directory:

    <out>/pack.json
    <out>/configs/dlp_dictionaries.json
    <out>/configs/dlp_engines.json
    <out>/configs/dlp_policies.json

Terraform references are rewritten to the pack's symbolic form:
    ${zia_dlp_dictionaries.<res>.id}        -> D:<dictionary name> (engines)
    ${data.zia_dlp_dictionaries.<res>.id}   -> dict_template_name (clones)
    ${zia_dlp_engines.<res>.id}             -> engine name (rules)

Usage:
    python tools/pack_from_terraform.py path/to/template.tf.json out_dir \
        --name "ZBP Enterprise Baseline" --version 1.0 --prefix ZBP- \
        --baseline --enable-rules
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List

_DICT_REF = re.compile(r"\$\{zia_dlp_dictionaries\.([A-Za-z0-9_]+)\.id\}")
_DATA_REF = re.compile(r"\$\{data\.zia_dlp_dictionaries\.([A-Za-z0-9_]+)\.id\}")
_ENGINE_REF = re.compile(r"\$\{zia_dlp_engines\.([A-Za-z0-9_]+)\.(?:id|engine_id)\}")
_TF_MANAGED = re.compile(r"\s*Terraform managed [^.]*\.?\s*", re.I)


def _clean_desc(text: str) -> str:
    """Drop 'Terraform managed ...' provenance from upstream descriptions."""
    if not text:
        return ""
    text = _TF_MANAGED.sub(" ", text)
    text = re.sub(r"\s*;?\s*prefix [^;]+;\s*original (?:dictionary|engine|policy): [^.]+\.?", "", text)
    return re.sub(r"\s+", " ", text).strip()


def convert(tf: Dict[str, Any], *, enable_rules: bool = False, rank: int = 7) -> Dict[str, List[Dict[str, Any]]]:
    data_dicts = (tf.get("data") or {}).get("zia_dlp_dictionaries") or {}
    template_names = {res: spec.get("name") for res, spec in data_dicts.items()}
    res = tf.get("resource") or {}
    r_dicts = res.get("zia_dlp_dictionaries") or {}
    r_engines = res.get("zia_dlp_engines") or {}
    r_rules = res.get("zia_dlp_web_rules") or {}

    dict_names = {k: v["name"] for k, v in r_dicts.items()}
    engine_names = {k: v["name"] for k, v in r_engines.items()}

    dictionaries: List[Dict[str, Any]] = []
    for key, d in r_dicts.items():
        out: Dict[str, Any] = {
            "name": d["name"],
            "description": _clean_desc(d.get("description", "")),
            "custom_phrase_match_type": d.get("custom_phrase_match_type", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY"),
        }
        tpl = d.get("dict_template_id")
        if tpl:
            m = _DATA_REF.fullmatch(str(tpl))
            if not m or m.group(1) not in template_names:
                raise SystemExit(f"dictionary {key}: unresolvable dict_template_id {tpl!r}")
            out["predefined_clone"] = True
            out["dict_template_name"] = template_names[m.group(1)]
            if d.get("confidence_level_for_predefined_dict"):
                out["confidence_level_for_predefined_dict"] = d["confidence_level_for_predefined_dict"]
        if d.get("confidence_threshold"):
            out["confidence_threshold"] = d["confidence_threshold"]
        if d.get("proximity"):
            out["proximity"] = int(d["proximity"])
        for flag in ("include_bin_numbers", "include_ssn_numbers", "hierarchical_identifiers"):
            if d.get(flag):
                out[flag] = d[flag]
        out["patterns"] = [{"action": p.get("action", "PATTERN_COUNT_TYPE_ALL"), "pattern": p["pattern"]} for p in d.get("patterns") or []]
        out["phrases"] = [{"action": p.get("action", "PHRASE_COUNT_TYPE_ALL"), "phrase": p["phrase"]} for p in d.get("phrases") or []]
        dictionaries.append(out)

    engines: List[Dict[str, Any]] = []
    for key, e in r_engines.items():
        expr = e["engine_expression"]

        def _sub(m: re.Match) -> str:
            ref = m.group(1)
            if ref not in dict_names:
                raise SystemExit(f"engine {key}: references unknown dictionary resource {ref}")
            return "D:" + dict_names[ref]

        def _sub_data(m: re.Match) -> str:
            ref = m.group(1)
            if ref not in template_names:
                raise SystemExit(f"engine {key}: references unknown data source {ref}")
            return "D:" + template_names[ref]
        # Terraform form is `D${ref}.S`; pack form is `D:<name>` (the `.S`
        # suffix is added back when the expression is resolved to IDs).
        # Resource refs name pack dictionaries; data refs name predefined
        # Zscaler dictionaries, resolved against the tenant at deploy time.
        expr = re.sub(r"D\$\{zia_dlp_dictionaries\.([A-Za-z0-9_]+)\.id\}\.S", _sub, expr)
        expr = re.sub(r"D\$\{data\.zia_dlp_dictionaries\.([A-Za-z0-9_]+)\.id\}\.S", _sub_data, expr)
        if "${" in expr:
            raise SystemExit(f"engine {key}: unexpected reference form in {expr!r}")
        engines.append({"name": e["name"], "description": _clean_desc(e.get("description", "")), "expression": expr})

    policies: List[Dict[str, Any]] = []
    for key, r in r_rules.items():
        names: List[str] = []
        for block in r.get("dlp_engines") or []:
            for ref in block.get("id") or []:
                m = _ENGINE_REF.fullmatch(str(ref))
                if not m or m.group(1) not in engine_names:
                    raise SystemExit(f"rule {key}: unresolvable engine reference {ref!r}")
                names.append(engine_names[m.group(1)])
        state = r.get("state", "ENABLED")
        if enable_rules:
            state = "ENABLED"
        pol: Dict[str, Any] = {
            "name": r["name"],
            "description": _clean_desc(r.get("description", "")),
            "action": r.get("action", "ALLOW"),
            "state": state,
            "rank": rank,
            "engines": names,
            "protocols": list(r.get("protocols") or ["ANY_RULE"]),
        }
        if r.get("severity"):
            pol["severity"] = r["severity"]
        for opt in ("file_types", "cloud_applications", "min_size"):
            if r.get(opt):
                pol[opt] = r[opt]
        for flag in ("match_only", "without_content_inspection"):
            if r.get(flag) is True:
                pol[flag] = True
        policies.append(pol)

    return {"dictionaries": dictionaries, "engines": engines, "policies": policies}


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("template", help="Terraform JSON file (*.tf.json)")
    ap.add_argument("out", help="pack directory to create")
    ap.add_argument("--name", required=True)
    ap.add_argument("--version", default="1.0")
    ap.add_argument("--description", default="")
    ap.add_argument("--prefix", default="", help="managed-name prefix the objects carry (informational)")
    ap.add_argument("--baseline", action="store_true", help="mark the pack as an immutable baseline")
    ap.add_argument("--enable-rules", action="store_true", help="force every rule to state ENABLED")
    ap.add_argument("--rank", type=int, default=7)
    ap.add_argument("--source", default="", help="where the template came from (recorded in pack.json)")
    args = ap.parse_args(argv)

    with open(args.template, "r", encoding="utf-8") as f:
        tf = json.load(f)
    pack = convert(tf, enable_rules=args.enable_rules, rank=args.rank)

    bad = [d["name"] for k in ("dictionaries", "engines", "policies") for d in pack[k]
           if args.prefix and not d["name"].startswith(args.prefix)]
    if bad:
        print(f"warning: {len(bad)} object(s) do not carry prefix {args.prefix!r}: {', '.join(bad[:5])}", file=sys.stderr)

    meta: Dict[str, Any] = {
        "name": args.name,
        "version": args.version,
        "description": args.description,
        "confidence_tweaks": [],
    }
    if args.source:
        meta["source"] = args.source
    if args.baseline:
        meta["baseline"] = {"immutable": True, "prefix": args.prefix, "version": args.version}

    configs = os.path.join(args.out, "configs")
    os.makedirs(configs, exist_ok=True)
    with open(os.path.join(args.out, "pack.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")
    for key in ("dictionaries", "engines", "policies"):
        with open(os.path.join(configs, f"dlp_{key}.json"), "w", encoding="utf-8") as f:
            json.dump(pack[key], f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(f"wrote {args.out}: {len(pack['dictionaries'])} dictionaries, {len(pack['engines'])} engines, {len(pack['policies'])} policies")
    return 0


if __name__ == "__main__":
    sys.exit(main())
