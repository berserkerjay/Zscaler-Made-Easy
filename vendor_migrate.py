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
        policies.append({"id": str(ident), "name": name, "active_status": _direct_text(node, "activeStatus"),
                         "child_tags": sorted({_tag(c) for c in node})})
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
                      "scope_acknowledged_any": False, "action": "", "order": i + 1, "engine_refs": [], "target_name": p["name"]}
                     for i, p in enumerate(snapshot["policies"])],
    }


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
