"""Rebuild a source-code pack from the dictionaries a tenant already has.

A DLP engineer who maintains the source-code library in the tenant (an
Anchor dictionary and a Signal dictionary per language) can pull those
dictionaries out and turn them into the pack, so the pack, Terraform and
every other tenant follow the tenant that is the source of truth.

Pairing is by name: a dictionary whose name contains "anchor" or "signal"
(any case, any separator) belongs to the language that is the rest of the
name, e.g. "SRC-Python Anchor" + "SRC-Python Signal", "Python_Signal_v4",
"Anchor: Go". Each pair becomes one engine:

    ((D:<signal> > <threshold>) AND (D:<anchor> > 0))

The dictionaries keep their tenant names, so deploying the pack back into
the same tenant reuses them; other tenants get exact copies.

Read-only against the tenant; writes only the pack's configs on disk.

CLI:
    python pack_from_tenant.py --pack zbp_source_code_baseline [--filter SRC-]
        [--threshold 4] [--html-threshold 3] [--dry-run]
    credentials from ZSCALER_CLIENT_ID / ZSCALER_CLIENT_SECRET /
    ZSCALER_VANITY_DOMAIN / ZSCALER_CLOUD.
"""
from __future__ import annotations

import json
import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple
import safe_files


from pack_deploy import _field, _items_set, load_pack_file, PackFileError  # tenant object readers (snake/camel case), pack files

ROLE_RE = re.compile(r"(?i)\b(anchor|signal)s?\b")
SEP_RE = re.compile(r"[\s_\-:/]+")


def read_custom_dictionaries(client) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Every custom (non-predefined, non-clone) dictionary of the tenant as
    a plain pack definition. Returns (dictionaries, error)."""
    try:
        items, err = client.zia.dlp_dictionary.list_dicts()
    except Exception as ex:  # noqa: BLE001
        return [], f"Could not list dictionaries: {ex}"
    if err:
        return [], f"Could not list dictionaries: {err}"
    out = []
    for t in items or []:
        if _field(t, "custom", default=True) is False:
            continue
        if _field(t, "dict_template_id", "dictTemplateId"):
            continue   # a clone of a predefined dictionary: not a pattern library entry
        patterns = _items_set(_field(t, "patterns"), "pattern")
        phrases = _items_set(_field(t, "phrases"), "phrase")
        if not patterns and not phrases:
            continue
        d = {
            "id": _field(t, "id"),
            "name": str(_field(t, "name") or ""),
            "description": str(_field(t, "description") or ""),
            "custom_phrase_match_type": _field(t, "custom_phrase_match_type", "customPhraseMatchType") or "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            "patterns": [{"action": a, "pattern": p} for a, p in patterns],
            "phrases": [{"action": a, "phrase": p} for a, p in phrases],
        }
        try:
            prox = int(_field(t, "proximity", default=0) or 0)
        except (TypeError, ValueError):
            prox = 0     # a tenant value that is not a number is not carried into the pack
        if prox:
            d["proximity"] = prox
        out.append(d)
    return out, None


def _language_key(name: str) -> Tuple[str, str, str]:
    """('python', 'Python', 'signal') for 'SRC-Python Signal v4'. Version
    tags and separators are dropped from the key; the label keeps the words."""
    norm = SEP_RE.sub(" ", name)           # "Go_Signal_v4" -> "Go Signal v4" so the role is a word
    role = ROLE_RE.search(norm)
    rest = ROLE_RE.sub(" ", norm)
    rest = re.sub(r"(?i)\bv?\d+(\.\d+)*\b", " ", rest)          # version tags
    words = [w for w in SEP_RE.split(rest) if w]
    label = " ".join(words).strip()
    return label.lower(), label, (role.group(1).lower() if role else "")


def _usable_name(name: str) -> bool:
    """A tenant dictionary name that stays one `D:<name>` term in the
    engine expression built from it: no control characters, and the
    expression reader (dlp_importer.find_refs) reads exactly this name
    back. A name such as "Py) OR (D:CREDIT_CARD Signal" would otherwise
    rewrite the engine's logic in every tenant the pack is deployed to."""
    if not name or name != name.strip() or any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        return False
    return _refs(f"((D:{name} > 0) AND (D:{name} > 0))") == [name, name]


def _filter_matches(name_filter: str, name: str) -> bool:
    """Whether `name` passes the literal filter (see pair_anchor_signal)."""
    flt = str(name_filter or "")
    if not flt:
        return True
    starts, ends = flt.startswith("^"), len(flt) > 1 and flt.endswith("$")
    core = flt[1 if starts else 0:len(flt) - (1 if ends else 0)].casefold()
    low = name.casefold()
    if starts and ends:
        return low == core
    if starts:
        return low.startswith(core)
    if ends:
        return low.endswith(core)
    return core in low


def pair_anchor_signal(dicts: Sequence[Dict[str, Any]], name_filter: str = "") -> Dict[str, Any]:
    """Group dictionaries into {language: {anchor, signal}} pairs.
    `name_filter` (a case-insensitive substring, matched literally, with
    an optional leading ^ for "starts with" and trailing $ for "ends
    with": no regular expression is ever run against tenant names, so a
    filter cannot hang the server) narrows the set."""
    groups: Dict[str, Dict[str, Any]] = {}
    ignored: List[str] = []
    for d in dicts:
        if not _filter_matches(name_filter, d["name"]):
            continue
        if not _usable_name(d["name"]):
            ignored.append(f"{d['name']!r} (the name cannot be used in an engine expression)")
            continue
        key, label, role = _language_key(d["name"])
        if not role or not key:
            ignored.append(d["name"])
            continue
        g = groups.setdefault(key, {"language": label, "anchor": None, "signal": None})
        if g[role] is not None:
            ignored.append(f"{d['name']} (second {role} for {label}; kept {g[role]['name']})")
            continue
        g[role] = d
    pairs = {k: g for k, g in sorted(groups.items()) if g["anchor"] and g["signal"]}
    unpaired = [f"{g['language']}: {'anchor' if g['anchor'] else 'signal'} only" for k, g in sorted(groups.items()) if k not in pairs]
    return {"pairs": pairs, "unpaired": unpaired, "ignored": ignored}


def _short(label: str) -> str:
    fixes = {"c#": "CSharp", "c sharp": "CSharp", "csharp": "CSharp", "c++": "CPlusPlus", "cpp": "CPlusPlus",
             "vb.net": "VBNet", "vb net": "VBNet", "visual basic": "VBNet"}
    low = label.lower().strip()
    for k, v in fixes.items():
        if low == k or low.endswith(" " + k):
            return v
    return re.sub(r"[^A-Za-z0-9]", "", label) or "Lang"


def build_configs(pairs: Dict[str, Dict[str, Any]], *, prefix: str = "SRC-", threshold: int = 4,
                  html_threshold: int = 3) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Dictionaries (tenant names kept) and one engine per language."""
    dicts: List[Dict[str, Any]] = []
    engines: List[Dict[str, Any]] = []
    seen = set()
    for key, g in pairs.items():
        for role in ("signal", "anchor"):
            d = dict(g[role]); d.pop("id", None)
            if d["name"] not in seen:
                seen.add(d["name"]); dicts.append(d)
        short = _short(g["language"])
        thr = html_threshold if short.upper() == "HTML" else threshold
        engines.append({
            "name": f"{prefix}{short}",
            "description": f"{g['language']} source code from the tenant's own library: Anchor '{g['anchor']['name']}' present AND more than {thr} matches of Signal '{g['signal']['name']}' (All/AND).",
            "expression": f"((D:{g['signal']['name']} > {thr}) AND (D:{g['anchor']['name']} > 0))",
        })
    return dicts, engines


def _refs(expr: str) -> List[str]:
    """Dictionary names an engine expression references (D:<name> terms)."""
    from dlp_importer import find_refs
    return [r.strip() for r in find_refs(expr if isinstance(expr, str) else "") if r.strip()]


def _is_language_engine(engine: Dict[str, Any], dicts: List[Dict[str, Any]]) -> bool:
    """A language engine is one built from Signal / Anchor dictionaries (the
    ones this rebuild regenerates); anything else in the pack is kept."""
    refs = _refs(engine.get("expression") or engine.get("engine_expression") or "")
    return bool(refs) and all(r.endswith(" Signal") or r.endswith(" Anchor") for r in refs)


def write_pack(pack_dir: str, dicts: List[Dict[str, Any]], engines: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Replace the pack's dictionaries and engines; rules keep everything
    else and now reference every new engine. Returns what was replaced."""
    cfg = os.path.join(pack_dir, "configs")
    safe_files.private_makedirs(cfg)
    # The pack's current files are untrusted (load_pack_file: size, nesting,
    # shape); one that is not a pack stops the rebuild before anything is written.
    old: Dict[str, List[Dict[str, Any]]] = {kind: [x for x in load_pack_file(cfg, f"dlp_{kind}.json", os.path.basename(pack_dir))
                                                   if isinstance(x.get("name"), str)]
                                            for kind in ("dictionaries", "engines")}
    policies = load_pack_file(cfg, "dlp_policies.json", os.path.basename(pack_dir))
    before = {kind: [x["name"] for x in old[kind]] for kind in old}
    # Engines that are not language engines (Private Keys, say) and the
    # dictionaries only they use are kept: the rebuild replaces the language
    # coverage, not the rest of the pack.
    lang_names = {e["name"] for e in engines}
    lang_dicts = {d["name"] for d in dicts}
    kept_engines = [e for e in old["engines"] if e["name"] not in lang_names and not _is_language_engine(e, old["dictionaries"])]
    kept_refs = set()
    for e in kept_engines:
        kept_refs |= set(_refs(e.get("expression") or e.get("engine_expression") or ""))
    kept_dicts = [d for d in old["dictionaries"] if d["name"] in kept_refs and d["name"] not in lang_dicts]
    engines = list(engines) + kept_engines
    dicts = list(dicts) + kept_dicts
    pol_path = os.path.join(cfg, "dlp_policies.json")
    rewired = []
    kept_names = {k["name"] for k in kept_engines}
    names = [e["name"] for e in engines if e["name"] not in kept_names]
    for p in policies:
        engs = p.get("engines")
        if isinstance(engs, list) and engs and not ({str(x) for x in engs} & kept_names):
            p["engines"] = names; rewired.append(str(p.get("name") or ""))
    # The tenant's own dictionaries and engines: owner-only (0600), each file
    # replaced whole (a crash never leaves half a pack file).
    safe_files.write_private_atomic(os.path.join(cfg, "dlp_dictionaries.json"), json.dumps(dicts, indent=2, ensure_ascii=False))
    safe_files.write_private_atomic(os.path.join(cfg, "dlp_engines.json"), json.dumps(engines, indent=2, ensure_ascii=False))
    if os.path.exists(pol_path):
        safe_files.write_private_atomic(pol_path, json.dumps(policies, indent=2, ensure_ascii=False))
    return {"removed_dictionaries": [n for n in before["dictionaries"] if n not in {d["name"] for d in dicts}],
            "removed_engines": [n for n in before["engines"] if n not in {e["name"] for e in engines}],
            "rules_rewired": rewired}


def rebuild_from_tenant(client, pack_dir: str, *, name_filter: str = "", prefix: str = "SRC-", threshold: int = 4,
                        html_threshold: int = 3, dry_run: bool = True) -> Dict[str, Any]:
    """The whole flow, returning a preview (dry run) or the written result."""
    dicts, err = read_custom_dictionaries(client)
    if err:
        return {"status": "error", "error": err}
    grouped = pair_anchor_signal(dicts, name_filter)
    new_dicts, engines = build_configs(grouped["pairs"], prefix=prefix, threshold=threshold, html_threshold=html_threshold)
    out = {
        "status": "preview" if dry_run else "written",
        "tenant_custom_dictionaries": len(dicts),
        "languages": [{"language": g["language"], "anchor": g["anchor"]["name"], "signal": g["signal"]["name"],
                       "signal_patterns": len(g["signal"]["patterns"]), "anchor_patterns": len(g["anchor"]["patterns"])}
                      for g in grouped["pairs"].values()],
        "unpaired": grouped["unpaired"], "ignored": grouped["ignored"],
        "dictionaries": len(new_dicts), "engines": [e["name"] for e in engines],
    }
    if not grouped["pairs"]:
        out["status"] = "error"
        out["error"] = "No Anchor/Signal dictionary pairs found" + (f" matching '{name_filter}'" if name_filter else "") + \
            ". Names must contain 'Anchor' or 'Signal' with the language as the rest of the name."
        return out
    if not dry_run:
        try:
            out.update(write_pack(pack_dir, new_dicts, engines))
        except PackFileError as e:
            return dict(out, status="error", error=f"The pack was not rewritten: {e}.")
    return out


def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pack", default="zbp_source_code_baseline")
    ap.add_argument("--filter", default="", help="substring/regex the dictionary names must match")
    ap.add_argument("--prefix", default="SRC-")
    ap.add_argument("--threshold", type=int, default=4)
    ap.add_argument("--html-threshold", type=int, default=3)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()
    from zscaler import ZscalerClient
    cfg = {"clientId": os.environ.get("ZSCALER_CLIENT_ID", ""), "clientSecret": os.environ.get("ZSCALER_CLIENT_SECRET", ""),
           "vanityDomain": os.environ.get("ZSCALER_VANITY_DOMAIN", ""), "cloud": os.environ.get("ZSCALER_CLOUD", "production")}
    if not all(cfg.values()):
        print("Set ZSCALER_CLIENT_ID, ZSCALER_CLIENT_SECRET, ZSCALER_VANITY_DOMAIN (and ZSCALER_CLOUD).")
        return 2
    client = ZscalerClient(cfg)
    pack_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), args.pack)
    res = rebuild_from_tenant(client, pack_dir, name_filter=args.filter, prefix=args.prefix, threshold=args.threshold,
                              html_threshold=args.html_threshold, dry_run=args.dry_run)
    print(json.dumps(res, indent=2))
    if res["status"] == "written":
        print(f"\nNow run: python pack_terraform.py {args.pack} --out terraform")
    return 0 if res["status"] != "error" else 1


if __name__ == "__main__":
    raise SystemExit(_main())
