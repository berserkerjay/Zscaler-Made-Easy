"""Migrate from another DLP: a fail-closed converter from a vendor's policy
export to disabled ZIA DLP objects, one adapter per source vendor.

Symantec DLP (Broadcom) is the first adapter; Forcepoint, Netskope and
Skyhigh are registered as planned so the page lists them and the same
contract applies when their export samples arrive.

The contract, unchanged from the stand-alone tool this grew from:

* **Inventory** reads the export (read-only, DTD/entities refused) and
  lists every policy with its id and name, bound to the export's SHA-256.
  Nothing is inferred from the vendor's XML beyond id, name and status.
* **Decisions** are a reviewed JSON mapping: every source policy needs an
  approved translation (a web rule with named engines) or an approved
  retirement / exclusion with a reason; dictionaries and engines are
  spelled out and approved one by one. The decisions carry the export's
  SHA-256, so a changed export invalidates them until reviewed.
* **Compile** is fail-closed: any unmapped or unapproved object blocks the
  run (a report with the questions, no Terraform); a ready run emits
  native `.tf.json` for the zscaler/zia provider in which every web rule
  is DISABLED. Enabling, ordering with the tenant's existing rules,
  applying and activating are separate change-control steps done
  elsewhere (the Terraform hand-off, Deploy policy packs).

Nothing here contacts a tenant or writes to one."""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

PROVIDER_VERSION = "4.8.8"
SAFE_ACTIONS = ("BLOCK", "CONFIRM", "ALLOW")
MATCH_TYPES = ("MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE")
MAX_EXPORT_BYTES = 32 * 1024 * 1024
WEB_RULE_LIMIT = 127

# ── Vendors ────────────────────────────────────────────────────────────
# One entry per source product. `status` is "available" when an adapter
# exists, "planned" when the page should list it but refuse uploads until
# a real export sample has been mapped.
VENDORS: Dict[str, Dict[str, Any]] = {
    "symantec": {
        "name": "Symantec DLP (Broadcom)", "prefix": "sym",
        "export": "Enforce policy export (XML, Policy Export/Import format)",
        "accepts": [".xml"], "status": "available",
        "how": "In the Enforce console export the policies (Manage > Policies > Policy List > Export); or fetch the XML from your tenant's documented export URL with the command-line fetcher.",
        "coverage": "Custom phrase/pattern dictionaries, explicitly reviewed engine expressions and ZIA inline web DLP rules. Detection, response, exception, scope, EDM, IDM, endpoint, email and SaaS semantics are not inferred from the XML; each needs a reviewed decision.",
    },
    "forcepoint": {"name": "Forcepoint DLP", "prefix": "fp", "export": "Policy export", "accepts": [], "status": "planned",
                   "how": "Adapter not built yet: it needs a real export sample and a mapping decision.", "coverage": ""},
    "netskope": {"name": "Netskope DLP", "prefix": "nsk", "export": "Policy export", "accepts": [], "status": "planned",
                 "how": "Adapter not built yet: it needs a real export sample and a mapping decision.", "coverage": ""},
    "skyhigh": {"name": "Skyhigh Security DLP", "prefix": "sky", "export": "Policy export", "accepts": [], "status": "planned",
                "how": "Adapter not built yet: it needs a real export sample and a mapping decision.", "coverage": ""},
}


def vendors() -> List[Dict[str, Any]]:
    return [dict(v, id=k) for k, v in VENDORS.items()]


def vendor(vendor_id: str) -> Dict[str, Any]:
    v = VENDORS.get(str(vendor_id or "").strip().lower())
    if not v:
        raise ValueError(f"Unknown vendor: {vendor_id!r}. Known: {', '.join(VENDORS)}")
    if v["status"] != "available":
        raise ValueError(f"{v['name']}: adapter not built yet. It needs a real export sample and a mapping decision before anything is converted.")
    return dict(v, id=str(vendor_id).strip().lower())


# ── Upload helpers ─────────────────────────────────────────────────────
def decode_upload(f: Dict[str, Any]) -> bytes:
    """The bytes of an uploaded file ({name, content, encoding})."""
    content = f.get("content") or ""
    if str(f.get("encoding") or "").lower() == "base64":
        try:
            data = base64.b64decode(content, validate=False)
        except Exception as e:  # noqa: BLE001
            raise ValueError(f"{f.get('name') or 'file'}: not valid base64 ({e})")
    else:
        data = str(content).encode("utf-8")
    if len(data) > MAX_EXPORT_BYTES:
        raise ValueError(f"{f.get('name') or 'file'}: larger than {MAX_EXPORT_BYTES // (1024 * 1024)} MiB")
    return data


# ── Symantec adapter: inventory ────────────────────────────────────────
def _tag(e) -> str:
    return e.tag.rsplit("}", 1)[-1]


def _direct_text(node, field: str) -> Optional[str]:
    for child in node:
        if _tag(child).lower() == field.lower():
            return (child.text or "").strip()
    return None


# ── Detection facets: what a source policy is made of ─────────────────
# The export's schema is not interpreted; facets are recognised from the
# element names (and the text they carry) under each policy. The facet
# list is what the efficacy mapping scores: each facet found in the
# source is either carried by the ZIA translation, carried in part,
# dropped, or attested by a reviewer. Weights say how much of a policy's
# detection each facet is; only facets present in the source count.
FACETS: Dict[str, Dict[str, Any]] = {
    "content_patterns": {"name": "Keywords, phrases and regular expressions", "weight": 25,
                         "tags": ("keyword", "phrase", "regex", "regularexpression", "pattern", "contentmatches", "matchkeyword"),
                         "zia": "Patterns & Phrases dictionaries referenced by the rule's engines",
                         "how": "the source's keyword and regex items against the phrases and patterns in the approved dictionaries the rule's engines reference"},
    "data_identifiers": {"name": "Predefined data identifiers", "weight": 15, "tags": ("dataidentifier", "identifier", "datatype", "classifier"),
                         "zia": "Zscaler's ~120 predefined dictionaries (not created by this adapter)",
                         "how": "not computable: a predefined dictionary is chosen by hand; a reviewer attests which identifiers are covered"},
    "edm": {"name": "Exact Data Match", "weight": 10, "tags": ("edm", "exactdata", "exactmatch"), "zia": "EDM dictionary from the Index Tool VM",
            "how": "not computable: EDM needs the Index Tool VM and a template; attested when built"},
    "idm": {"name": "Indexed Document Match", "weight": 10, "tags": ("idm", "indexeddocument", "documentmatch", "fingerprint"), "zia": "IDM dictionary from the Index Tool VM",
            "how": "not computable: IDM needs the Index Tool VM and a template; attested when built"},
    "ml": {"name": "Machine-learning / vector classifiers", "weight": 5, "tags": ("vml", "machinelearning", "vector", "mlclassifier", "classification"),
           "zia": "ML predefined dictionaries where one exists", "how": "not computable: attested when an ML dictionary is chosen"},
    "match_thresholds": {"name": "Match counts and thresholds", "weight": 5, "tags": ("mincount", "matchcount", "minmatches", "threshold", "count", "occurrence"),
                         "zia": "the engine expression's strict \"more than N\"",
                         "how": "carried when every referenced engine expression carries a numeric threshold"},
    "channel": {"name": "Channels and protocols", "weight": 10, "tags": ("protocol", "channel", "destination", "endpointdestination", "network", "application", "app"),
                "zia": "Inline Web DLP rule (HTTP/HTTPS)",
                "how": "the share of the source's protocol mentions that are web (http, https, web, ftp); this adapter emits web rules only"},
    "identity_scope": {"name": "Users, groups, senders and recipients", "weight": 8, "tags": ("sender", "recipient", "user", "group", "department", "policygroup", "scope"),
                       "zia": "the rule's users / groups / departments criteria",
                       "how": "dropped: the generated rule applies to Any (that is what scope_acknowledged_any acknowledges)"},
    "file_conditions": {"name": "File type, size and name conditions", "weight": 4, "tags": ("filetype", "filesize", "filename", "attachment", "mimetype", "extension"),
                        "zia": "the rule's file types and size limits", "how": "dropped: not emitted by this adapter; set on the rule by hand"},
    "exceptions": {"name": "Exceptions", "weight": 4, "tags": ("exception", "exclude", "exempt", "whitelist", "allowlist"),
                   "zia": "Exclude subexpressions and DLP Advanced Settings exemptions", "how": "dropped: not emitted by this adapter"},
    "response_action": {"name": "Response rules and actions", "weight": 4, "tags": ("response", "action", "block", "notify", "quarantine", "encrypt", "remediat"),
                        "zia": "the rule's action (Allow / Block / Confirm) plus auditor and template",
                        "how": "carried when the rule's action is approved; notifications, quarantine and encryption responses are not carried"},
    "severity": {"name": "Severity", "weight": 2, "tags": ("severity", "priority", "risk"), "zia": "rule severity", "how": "dropped: not emitted by this adapter"},
}
_WEB_PROTOCOL_RE = re.compile(r"\b(https?|web|ftp|browser|upload)\b", re.I)
_THRESHOLD_RE = re.compile(r">\s*\d+")


_FACET_ORDER = ("edm", "idm", "ml", "data_identifiers") + tuple(k for k in FACETS if k not in ("edm", "idm", "ml", "data_identifiers"))


def _facet_of(tag: str) -> Optional[str]:
    """The facet an element name belongs to; the specific detection types
    win over the generic content match (contentMatchesDataIdentifier is an
    identifier, not a keyword)."""
    t = tag.lower()
    for key in _FACET_ORDER:
        if any(needle in t for needle in FACETS[key]["tags"]):
            return key
    return None


def _policy_facets(node) -> Dict[str, Any]:
    """Facets recognised under one policy element: per facet the element
    count and, for a few, the item texts that the scoring compares. The
    unrecognised element names are listed so a reviewer sees what was
    ignored."""
    found: Dict[str, Dict[str, Any]] = {}
    unknown: set = set()
    for el in node.iter():
        if el is node:
            continue
        tag = _tag(el)
        key = _facet_of(tag)
        if key is None:
            if tag.lower() not in ("id", "name", "description", "activestatus", "rule", "rules", "detectionrules", "condition", "conditions", "policy", "value", "values", "item", "items"):
                unknown.add(tag)
            continue
        f = found.setdefault(key, {"elements": 0, "items": [], "texts": []})
        f["elements"] += 1
        text = " ".join((el.text or "").split())
        if text:
            f["texts"].append(text[:200])
            if key == "content_patterns" and el.tag.lower().endswith(("keyword", "phrase", "regex", "regularexpression", "pattern")):
                f["items"].append(text[:200])
        for k, v in el.attrib.items():
            if key == "channel" and v:
                f["texts"].append(str(v)[:100])
    for f in found.values():
        f["items"] = f["items"][:512]
        f["texts"] = f["texts"][:64]
    return {"facets": found, "unrecognised": sorted(unknown)[:40]}


def inventory_bytes(data: bytes, source_name: str = "export.xml") -> Dict[str, Any]:
    """Symantec XML export → {source_file, sha256, policies}. Read-only;
    DTDs and entities are refused before parsing."""
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("DTD/entities are not accepted")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as e:
        raise ValueError(f"Not well-formed XML: {e}")
    policies = []
    for node in root.iter():
        if _tag(node).lower() != "policy":
            continue
        ident = node.get("id") or node.get("policyId") or _direct_text(node, "id")
        name = node.get("name") or _direct_text(node, "name")
        if not ident or not name:
            continue
        entry = {"id": str(ident), "name": name, "active_status": _direct_text(node, "activeStatus"),
                 "child_tags": sorted({_tag(c) for c in node})}
        entry.update(_policy_facets(node))
        policies.append(entry)
    if not policies:
        raise ValueError("No policy elements with an id and name were found; provide an export fixture")
    ids = [p["id"] for p in policies]
    if len(set(ids)) != len(ids):
        raise ValueError("Duplicate policy IDs in export")
    return {"source_file": os.path.basename(str(source_name or "export.xml")), "sha256": hashlib.sha256(data).hexdigest(),
            "policies": sorted(policies, key=lambda x: x["id"])}


def inventory_xml(path) -> Dict[str, Any]:
    p = Path(path)
    return inventory_bytes(p.read_bytes(), p.name)


def decisions_template(snapshot: Dict[str, Any]) -> Dict[str, Any]:
    """A starting decisions file for this export: the SHA-256 filled in,
    every source policy listed with nothing approved, and one worked
    dictionary and engine to copy. Every field is reviewed by a person."""
    return {
        "_help": ("Review every policy: either an approved web-rule translation (channel web, action BLOCK/CONFIRM/ALLOW, 1-4 engine_refs, "
                  "a unique order from 1, scope_acknowledged_any true because the generated rule applies to Any user/location) or an approved "
                  "retired/out_of_scope disposition with a reason. Dictionaries and engines are spelled out here and approved one by one; "
                  "{{dict:ID}} in an engine expression references a dictionary below. A changed export SHA-256 invalidates this file."),
        "source_sha256": snapshot["sha256"],
        "source_file": snapshot.get("source_file", ""),
        "dictionaries": [{"id": "example_context", "name": "EXAMPLE_CONTEXT", "approved": False, "description": "Migrated from the source DLP",
                          "match_type": "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY", "phrases": ["example phrase"], "patterns": ["example[ -]?[0-9]{6,10}"]}],
        "engines": [{"id": "example_engine", "name": "EXAMPLE_ENGINE", "approved": False, "description": "Migrated from the source DLP",
                     "zia_expression": "((D{{dict:example_context}}.S > 1))"}],
        "policies": [{"source_id": p["id"], "source_name": p["name"], "disposition": "", "reason": "", "channel": "web", "approved": False,
                      "scope_acknowledged_any": False, "action": "", "order": i + 1, "engine_refs": [], "target_name": p["name"],
                      # The efficacy mapping computes what it can from the export and the
                      # decisions; facets it cannot compute (predefined identifiers, EDM,
                      # IDM, ML) count as 0 unless a reviewer attests them here: true,
                      # false or a fraction 0-1, with a note.
                      "attest": {k: {"carried": False, "note": ""} for k in sorted(p.get("facets") or {}) if FACETS[k]["how"].startswith("not computable")}}
                     for i, p in enumerate(snapshot["policies"])],
    }


# ── Efficacy mapping ───────────────────────────────────────────────────
def _clamp(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def _facet_score(key: str, src: Dict[str, Any], pol: Dict[str, Any], dict_items: int, engine_exprs: List[str], attest: Dict[str, Any]) -> Dict[str, Any]:
    """One facet's score in [0, 1] with the arithmetic that produced it.
    `basis` says whether the number was computed, attested or fixed."""
    spec = FACETS[key]
    at = attest.get(key) if isinstance(attest, dict) else None
    if isinstance(at, dict) and at.get("carried") not in (None, ""):
        c = at["carried"]
        val = 1.0 if c is True else 0.0 if c is False else _clamp(c) if isinstance(c, (int, float)) else 0.0
        return {"score": val, "basis": "attested", "detail": f"reviewer attested {val:.0%}" + (f": {at.get('note')}" if at.get("note") else "")}
    if key == "content_patterns":
        n = len(src.get("items") or []) or src.get("elements", 0)
        if n <= 0:
            return {"score": 0.0, "basis": "computed", "detail": "no keyword or regex items readable in the export"}
        val = _clamp(dict_items / n)
        return {"score": val, "basis": "computed", "detail": f"{dict_items} phrases and patterns in the referenced dictionaries ÷ {n} keyword and regex items in the source = {val:.0%}"}
    if key == "match_thresholds":
        if not engine_exprs:
            return {"score": 0.0, "basis": "computed", "detail": "no engine referenced"}
        with_t = sum(1 for e in engine_exprs if _THRESHOLD_RE.search(e))
        val = with_t / len(engine_exprs)
        return {"score": val, "basis": "computed", "detail": f"{with_t} of {len(engine_exprs)} referenced engine expressions carry a numeric threshold = {val:.0%}"}
    if key == "channel":
        texts = src.get("texts") or []
        if not texts:
            return {"score": 1.0 if pol.get("channel") == "web" else 0.0, "basis": "computed", "detail": "no protocol named in the source; the web rule is taken as the whole channel"}
        web = sum(1 for t in texts if _WEB_PROTOCOL_RE.search(t))
        val = web / len(texts)
        return {"score": val, "basis": "computed", "detail": f"{web} of {len(texts)} protocol mentions are web = {val:.0%}; endpoint, email and SaaS mentions need their own adapter"}
    if key == "response_action":
        ok = pol.get("action") in SAFE_ACTIONS and bool(pol.get("approved"))
        return {"score": 1.0 if ok else 0.0, "basis": "computed", "detail": ("action " + str(pol.get("action")) + " approved; notification, quarantine and encryption responses are not carried") if ok else "no approved action"}
    if key in ("identity_scope", "file_conditions", "exceptions", "severity"):
        return {"score": 0.0, "basis": "fixed", "detail": spec["how"]}
    return {"score": 0.0, "basis": "fixed", "detail": spec["how"] + " (nothing attested)"}


def efficacy(snapshot: Dict[str, Any], decisions: Dict[str, Any], res: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """How much of each source policy's detection the ZIA translation
    carries, as a weighted percentage over the facets the export exposes,
    with the arithmetic per facet. Retired and out-of-scope policies are
    listed but not scored; a policy whose export carries no recognisable
    detection facet is "not computable", never a number."""
    by_id = {p["id"]: p for p in snapshot["policies"]}
    dict_sizes = {slug(d.get("id", "")): len(d.get("phrases") or []) + len(d.get("patterns") or [])
                  for d in decisions.get("dictionaries", []) or [] if d.get("approved")}
    engines = {slug(e.get("id", "")): e.get("zia_expression", "") or "" for e in decisions.get("engines", []) or [] if e.get("approved")}
    rows = []
    tot_w = tot_s = 0.0
    for p in decisions.get("policies", []) or []:
        sid = str(p.get("source_id", ""))
        src = by_id.get(sid)
        if not src:
            continue
        if p.get("disposition") in ("retired", "out_of_scope"):
            rows.append({"source_id": sid, "name": src["name"], "status": p["disposition"], "fidelity": None, "facets": [], "note": "not scored: the policy is not being carried over"})
            continue
        facets = src.get("facets") or {}
        if not facets:
            rows.append({"source_id": sid, "name": src["name"], "status": "not_computable", "fidelity": None, "facets": [],
                         "note": "the export carries no recognisable detection element for this policy (only id, name and status), so no percentage is claimed"})
            continue
        refs = [slug(x) for x in (p.get("engine_refs") or [])]
        exprs = [engines[r] for r in refs if r in engines]
        dict_items = 0
        for e in exprs:
            for m in re.finditer(r"zia_dlp_dictionaries\.([a-z0-9_]+)\.id|\{\{dict:([A-Za-z0-9_-]+)\}\}", e):
                dict_items += dict_sizes.get(slug(m.group(1) or m.group(2)), 0)
        attest = p.get("attest") or {}
        frows = []
        w_sum = s_sum = 0.0
        for key in FACETS:
            if key not in facets:
                continue
            sc = _facet_score(key, facets[key], p, dict_items, exprs, attest)
            w = FACETS[key]["weight"]
            w_sum += w; s_sum += w * sc["score"]
            frows.append({"facet": key, "name": FACETS[key]["name"], "weight": w, "source_elements": facets[key]["elements"],
                          "source_sample": (facets[key].get("items") or facets[key].get("texts") or [])[:5],
                          "zia": FACETS[key]["zia"], "score": round(sc["score"], 4), "points": round(w * sc["score"], 2), "basis": sc["basis"], "detail": sc["detail"]})
        fid = round(s_sum / w_sum * 100, 1) if w_sum else None
        tot_w += w_sum; tot_s += s_sum
        rows.append({"source_id": sid, "name": src["name"], "status": "translated" if p.get("approved") else "not_approved", "fidelity": fid,
                     "points": round(s_sum, 2), "weight": round(w_sum, 2), "facets": frows, "unrecognised": src.get("unrecognised") or [],
                     "note": f"{s_sum:.1f} of {w_sum:.0f} weighted points carried = {fid}%" if fid is not None else ""})
    overall = round(tot_s / tot_w * 100, 1) if tot_w else None
    scored = [r for r in rows if r["fidelity"] is not None]
    return {"overall_fidelity": overall, "scored_policies": len(scored), "policies": rows,
            "method": ("Per policy: every detection facet recognised in the export (by element name) is scored 0-1 against what the "
                       "decisions carry (computed where the export and the decisions expose the numbers, attested by a reviewer for "
                       "predefined identifiers, EDM, IDM and ML, fixed at 0 for what this adapter never emits), weighted by the facet's "
                       "share of a policy's detection; fidelity = weighted points carried ÷ weighted points present. Overall = the same "
                       "ratio over every scored policy. Retired policies and exports with no recognisable detection element are not "
                       "scored and no number is claimed for them."),
            "weights": {k: v["weight"] for k, v in FACETS.items()},
            "note": (f"{overall}% of the recognised detection across {len(scored)} scored polic{'y' if len(scored) == 1 else 'ies'} is carried by the translation."
                     if overall is not None else "Not computable: no scored policy exposes a detection facet the mapping can measure.")}


# ── Compile (vendor-agnostic) ──────────────────────────────────────────
def slug(s: str) -> str:
    x = re.sub(r"[^a-z0-9_]", "_", str(s).lower()).strip("_")
    if not x or x[0].isdigit():
        x = "obj_" + x
    return x[:60]


def compile_export(snapshot: Dict[str, Any], decisions: Dict[str, Any], prefix: str = "sym") -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """(terraform, report). The report's `ready` is True only when every
    source policy has an approved disposition or translation and every
    referenced object was generated; the Terraform is deployable only then."""
    if not isinstance(decisions, dict):
        raise ValueError("Decisions must be a JSON object")
    if decisions.get("source_sha256") != snapshot["sha256"]:
        raise ValueError("Decision file source_sha256 does not match export; review source changes")
    by_id = {p["id"]: p for p in snapshot["policies"]}
    selected = decisions.get("policies", []) or []
    if len({p.get("source_id") for p in selected}) != len(selected):
        raise ValueError("Duplicate source_id in decisions")
    res: Dict[str, Dict[str, Any]] = {"zia_dlp_dictionaries": {}, "zia_dlp_engines": {}, "zia_dlp_web_rules": {}}
    report: Dict[str, Any] = {"source_sha256": snapshot["sha256"], "provider_version": PROVIDER_VERSION,
                              "semantic_equivalence": "manual_review_required_native_xml_not_interpreted",
                              "converted": [], "questions": [], "blocked": [], "dispositions": []}

    def question(source_id, reason, kind="ASK"):
        report["questions"].append({"source_id": source_id, "kind": kind, "reason": reason})
        report["blocked"].append(source_id)

    for d in decisions.get("dictionaries", []) or []:
        key = slug(d.get("id", ""))
        if key in res["zia_dlp_dictionaries"]:
            raise ValueError("Duplicate dictionary slug: " + key)
        phrases, patterns = d.get("phrases", []) or [], d.get("patterns", []) or []
        if not d.get("approved") or not d.get("name") or not (phrases or patterns) or len(phrases) > 256 or len(patterns) > 8:
            question(d.get("id", "?"), "Dictionary requires approval, name, content and valid item limits")
            continue
        if any(not isinstance(x, str) or not 0 < len(x) <= 128 for x in phrases) or any(not isinstance(x, str) or not 0 < len(x) <= 256 for x in patterns):
            question(d.get("id", "?"), "Dictionary phrase/pattern length invalid")
            continue
        obj: Dict[str, Any] = {"name": d["name"], "description": d.get("description", "Migrated from the source DLP"),
                               "dictionary_type": "PATTERNS_AND_PHRASES",
                               "custom_phrase_match_type": d.get("match_type", "MATCH_ALL_CUSTOM_PHRASE_PATTERN_DICTIONARY")}
        if obj["custom_phrase_match_type"] not in MATCH_TYPES:
            question(d.get("id", "?"), "Unknown ZIA custom phrase match type")
            continue
        if phrases:
            obj["phrases"] = [{"phrase": x, "action": "PHRASE_COUNT_TYPE_ALL"} for x in phrases]
        if patterns:
            obj["patterns"] = [{"pattern": x, "action": "PATTERN_COUNT_TYPE_UNIQUE"} for x in patterns]
        res["zia_dlp_dictionaries"][key] = obj

    for e in decisions.get("engines", []) or []:
        key = slug(e.get("id", ""))
        if key in res["zia_dlp_engines"]:
            raise ValueError("Duplicate engine slug: " + key)
        expr = e.get("zia_expression", "") or ""
        if not e.get("approved") or not e.get("name") or not expr:
            question(e.get("id", "?"), "Engine name, approved expression and approval required")
            continue
        missing: List[str] = []

        def sub(m):
            ref = slug(m.group(1))
            if ref not in res["zia_dlp_dictionaries"]:
                missing.append(m.group(1))
            return "${zia_dlp_dictionaries." + ref + ".id}"
        expr2 = re.sub(r"\{\{dict:([A-Za-z0-9_-]+)\}\}", sub, expr)
        if missing or "{{" in expr2 or "${" in expr:
            question(e.get("id", "?"), "Unresolved dictionary reference or unsafe interpolation: " + ", ".join(missing))
            continue
        res["zia_dlp_engines"][key] = {"name": e["name"], "description": e.get("description", "Migrated from the source DLP"),
                                       "engine_expression": expr2, "custom_dlp_engine": True}

    for p in selected:
        source_id = str(p.get("source_id", ""))
        if source_id not in by_id:
            raise ValueError("Decision references absent source policy: " + source_id)
        if p.get("disposition") in ("retired", "out_of_scope"):
            if not p.get("approved") or not p.get("reason"):
                question(source_id, "Retirement or exclusion needs approval and a reason")
            else:
                report["dispositions"].append({"source_id": source_id, "disposition": p["disposition"], "reason": p["reason"]})
            continue
        if p.get("channel") != "web":
            question(source_id, "Channel needs a reviewed target adapter: " + str(p.get("channel")), "UNSUPPORTED")
            continue
        engines = p.get("engine_refs", []) or []
        if (not p.get("approved") or not p.get("scope_acknowledged_any") or p.get("action") not in SAFE_ACTIONS
                or not 1 <= len(engines) <= 4 or not isinstance(p.get("order"), int) or isinstance(p.get("order"), bool) or p["order"] < 1):
            question(source_id, "Web rule needs approval, explicit Any-scope acknowledgement, action, 1-4 engines and positive order")
            continue
        missing_engines = [x for x in engines if slug(x) not in res["zia_dlp_engines"]]
        if missing_engines:
            question(source_id, "Engine not generated: " + ", ".join(missing_engines))
            continue
        key = slug(f"{prefix}_{source_id}")
        if key in res["zia_dlp_web_rules"]:
            raise ValueError("Duplicate web rule slug: " + key)
        res["zia_dlp_web_rules"][key] = {"name": p.get("target_name") or by_id[source_id]["name"],
                                         "action": p["action"], "order": p["order"], "state": "DISABLED",
                                         "protocols": ["HTTPS_RULE", "HTTP_RULE"], "without_content_inspection": False,
                                         "dlp_engines": [{"id": ["${zia_dlp_engines." + slug(x) + ".id}" for x in engines]}]}
        report["converted"].append({"source_id": source_id, "target": "zia_dlp_web_rules." + key, "state": "DISABLED"})
    selected_ids = {str(p.get("source_id", "")) for p in selected}
    for source_id in by_id:
        if source_id not in selected_ids:
            question(source_id, "No reviewed disposition or translation")
    orders = [v["order"] for v in res["zia_dlp_web_rules"].values()]
    if len(set(orders)) != len(orders) or sorted(orders) != list(range(1, len(orders) + 1)):
        raise ValueError("Generated web-rule orders must be unique and contiguous starting at 1")
    if len(orders) > WEB_RULE_LIMIT:
        raise ValueError(f"ZIA API web-rule limit exceeded ({WEB_RULE_LIMIT})")
    tf = {"terraform": {"required_providers": {"zia": {"source": "zscaler/zia", "version": PROVIDER_VERSION}}},
          "provider": {"zia": {}}, "resource": {k: v for k, v in res.items() if v}}
    report["ready"] = not report["blocked"]
    report["efficacy"] = efficacy(snapshot, decisions, res)
    report["counts"] = {"source_policies": len(by_id), "converted_web_rules": len(report["converted"]),
                        "blocked_policies_or_objects": len(report["questions"]),
                        "dictionaries": len(res["zia_dlp_dictionaries"]), "engines": len(res["zia_dlp_engines"]),
                        "dispositions": len(report["dispositions"])}
    return tf, report


# ── The page's two calls ───────────────────────────────────────────────
def inventory_upload(vendor_id: str, export_file: Dict[str, Any]) -> Dict[str, Any]:
    v = vendor(vendor_id)
    data = decode_upload(export_file)
    snapshot = inventory_bytes(data, export_file.get("name") or "export.xml")
    return {"vendor": v["id"], "vendor_name": v["name"], "snapshot": snapshot, "decisions_template": decisions_template(snapshot)}


def compile_upload(vendor_id: str, export_file: Dict[str, Any], decisions: Any) -> Dict[str, Any]:
    v = vendor(vendor_id)
    data = decode_upload(export_file)
    snapshot = inventory_bytes(data, export_file.get("name") or "export.xml")
    if isinstance(decisions, dict) and "content" in decisions and "policies" not in decisions:
        try:
            decisions = json.loads(decode_upload(decisions).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Decisions file is not valid JSON: {e}")
    tf, report = compile_export(snapshot, decisions, prefix=v["prefix"])
    return {"vendor": v["id"], "vendor_name": v["name"],
            "snapshot": {"source_file": snapshot["source_file"], "sha256": snapshot["sha256"], "policy_count": len(snapshot["policies"])},
            "report": report, "terraform": tf if report["ready"] else None}


# ── Command line: the same steps, plus the export fetcher ──────────────
def fetch_export(url: str, token: str, out) -> int:
    """One authenticated HTTPS GET of a tenant's documented export URL.
    Refuses redirects (the bearer token must not follow to another
    origin), caps the response at MAX_EXPORT_BYTES, writes mode 0600."""
    import urllib.request
    from urllib.parse import urlsplit
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("Only HTTPS URLs are accepted")
    if not token:
        raise ValueError("Token is missing")
    req = urllib.request.Request(url, headers={"Authorization": "Bearer " + token, "Accept": "application/xml"}, method="GET")

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, request, fp, code, msg, headers, newurl):
            return None
    with urllib.request.build_opener(NoRedirect).open(req, timeout=30) as response:
        data = response.read(MAX_EXPORT_BYTES + 1)
    if len(data) > MAX_EXPORT_BYTES or not data.lstrip().startswith(b"<"):
        raise ValueError("Response exceeds the size limit or is not XML")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(data)
    out.chmod(0o600)
    return 0


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Migrate from another DLP: inventory an export, compile reviewed decisions to disabled ZIA Terraform.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    inv = sub.add_parser("inventory", help="List the export's policies and write a decisions template")
    inv.add_argument("export", type=Path)
    inv.add_argument("--vendor", default="symantec")
    inv.add_argument("--out", type=Path, default=Path("build"))
    comp = sub.add_parser("compile", help="Compile reviewed decisions; Terraform is written only when every policy is decided")
    comp.add_argument("export", type=Path)
    comp.add_argument("--decisions", type=Path, required=True)
    comp.add_argument("--vendor", default="symantec")
    comp.add_argument("--out", type=Path, default=Path("build"))
    fe = sub.add_parser("fetch", help="Fetch the XML export from the tenant's documented export URL (token from an environment variable)")
    fe.add_argument("--url", required=True)
    fe.add_argument("--token-env", required=True)
    fe.add_argument("--out", required=True, type=Path)
    args = ap.parse_args(argv)
    try:
        if args.cmd == "fetch":
            token = os.environ.get(args.token_env)
            if not token:
                ap.error("Token environment variable is missing")
            fetch_export(args.url, token, args.out)
            print("Saved export to", args.out)
            return 0
        v = vendor(args.vendor)
        snapshot = inventory_xml(args.export)
        _write_json(args.out / "source-inventory.json", snapshot)
        if args.cmd == "inventory":
            _write_json(args.out / "decisions.template.json", decisions_template(snapshot))
            print("Inventory and a decisions template written. Review every policy, then run compile.")
            return 0
        tf, report = compile_export(snapshot, json.loads(args.decisions.read_text()), prefix=v["prefix"])
        _write_json(args.out / "migration-report.json", report)
        if report["ready"]:
            _write_json(args.out / "main.tf.json", tf)
            print("READY: disabled Terraform written; review and run terraform init/validate/plan.")
            return 0
        (args.out / "main.tf.json").unlink(missing_ok=True)
        print("BLOCKED: see migration-report.json; no deployable Terraform emitted.", file=sys.stderr)
        return 2
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print("ERROR: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
