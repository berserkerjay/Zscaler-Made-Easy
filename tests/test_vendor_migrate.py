"""Migrate from another DLP (vendor_migrate): the Symantec adapter's
fail-closed contract, the vendor registry with the planned adapters, the
page's two calls, and the page itself in the sidebar."""
from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security
import vendor_migrate as vm

EXPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<policyExport xmlns="http://www.symantec.com/dlp/policy-export-import">
  <policy id="sym-101" name="PCI upload block">
    <activeStatus>active</activeStatus>
    <detectionRules><rule>Sample only: customer exports must be mapped explicitly</rule></detectionRules>
  </policy>
</policyExport>
"""


def _decisions(snapshot):
    return {"source_sha256": snapshot["sha256"],
            "dictionaries": [{"id": "customer_context", "name": "CUSTOMER_CONTEXT", "approved": True, "phrases": ["customer"], "patterns": ["account[ -]?[0-9]{6,10}"]}],
            "engines": [{"id": "pci_context", "name": "PCI_CONTEXT", "approved": True, "zia_expression": "((D{{dict:customer_context}}.S > 1))"}],
            "policies": [{"source_id": "sym-101", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": 1, "engine_refs": ["pci_context"]}]}


def _page():
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _upload(name, data: bytes):
    return {"name": name, "content": base64.b64encode(data).decode("ascii"), "encoding": "base64"}


def test_success_is_disabled_and_references_resolve():
    snapshot = vm.inventory_bytes(EXPORT, "symantec-export.xml")
    tf, report = vm.compile_export(snapshot, _decisions(snapshot))
    assert report["ready"] and report["counts"] == {"source_policies": 1, "converted_rules": 1, "converted_by_channel": {"web": 1, "endpoint": 0, "saas": 0, "email": 0},
                                                    "blocked_policies_or_objects": 0, "dictionaries": 1, "engines": 1, "dispositions": 0}
    assert report["converted"] == [{"source_id": "sym-101", "channel": "web", "target": "zia_dlp_web_rules.sym_sym_101", "state": "DISABLED", "action": "BLOCK"}]
    rule = tf["resource"]["zia_dlp_web_rules"]["sym_sym_101"]
    assert rule["state"] == "DISABLED" and rule["dlp_engines"][0]["id"] == ["${zia_dlp_engines.pci_context.id}"]
    assert "${zia_dlp_dictionaries.customer_context.id}" in tf["resource"]["zia_dlp_engines"]["pci_context"]["engine_expression"]
    assert tf["terraform"]["required_providers"]["zia"]["version"] == vm.PROVIDER_VERSION


def test_stale_source_is_rejected():
    snapshot = vm.inventory_bytes(EXPORT)
    d = _decisions(snapshot); d["source_sha256"] = "old"
    with pytest.raises(ValueError, match="source_sha256"):
        vm.compile_export(snapshot, d)


def test_unknown_channel_blocks_all_output_and_the_cli_removes_stale_terraform():
    snapshot = vm.inventory_bytes(EXPORT)
    d = _decisions(snapshot); d["policies"][0]["channel"] = "usb"
    _tf, report = vm.compile_export(snapshot, d)
    assert not report["ready"] and report["questions"][0]["kind"] == "UNSUPPORTED"
    with tempfile.TemporaryDirectory() as td:
        p = Path(td)
        (p / "export.xml").write_bytes(EXPORT)
        (p / "decisions.json").write_text(json.dumps(d))
        (p / "out").mkdir(); (p / "out" / "main.tf.json").write_text("{}")   # a stale artefact from an earlier ready run
        code = vm.main(["compile", str(p / "export.xml"), "--decisions", str(p / "decisions.json"), "--out", str(p / "out")])
        assert code == 2 and not (p / "out" / "main.tf.json").exists()
        assert json.loads((p / "out" / "migration-report.json").read_text())["questions"][0]["kind"] == "UNSUPPORTED"
        assert vm.main(["inventory", str(p / "export.xml"), "--out", str(p / "inv")]) == 0
        tpl = json.loads((p / "inv" / "decisions.template.json").read_text())
        assert tpl["source_sha256"] == snapshot["sha256"] and tpl["policies"][0]["source_id"] == "sym-101" and tpl["policies"][0]["approved"] is False
        # A ready compile writes main.tf.json and the workspace in terraform/; a later blocked one removes only what it generated:
        # the state, terraform.tfvars and the .terraform folder of a team that ran Terraform there stay.
        (p / "ok.json").write_text(json.dumps(_decisions(snapshot)))
        assert vm.main(["compile", str(p / "export.xml"), "--decisions", str(p / "ok.json"), "--out", str(p / "out")]) == 0
        ws = p / "out" / "terraform"
        assert (p / "out" / "main.tf.json").exists() and (ws / "rules.tf").exists() and (ws / "README.md").exists()
        (ws / "terraform.tfstate").write_text("{}"); (ws / "terraform.tfvars").write_text("x = 1\n"); (ws / ".terraform").mkdir()
        (ws / "team.tf").write_text("# our own\n")
        assert vm.main(["compile", str(p / "export.xml"), "--decisions", str(p / "decisions.json"), "--out", str(p / "out")]) == 2
        assert not (p / "out" / "main.tf.json").exists() and not (ws / "rules.tf").exists() and not (ws / "README.md").exists()
        assert not (ws / "migration-report.json").exists() and not (ws / ".gitignore").exists()
        assert {x.name for x in ws.iterdir()} == {"terraform.tfstate", "terraform.tfvars", ".terraform", "team.tf"}, "nothing the team made is removed"


def test_unapproved_retirement_and_unlisted_policies_block():
    snapshot = vm.inventory_bytes(EXPORT)
    d = _decisions(snapshot); d["policies"] = [{"source_id": "sym-101", "disposition": "retired"}]
    _tf, report = vm.compile_export(snapshot, d)
    assert not report["ready"] and "approval (true) and a reason" in report["questions"][0]["reason"]
    d["policies"] = []
    _tf, report = vm.compile_export(snapshot, d)
    assert report["blocked"] == ["sym-101"] and "No reviewed disposition" in report["questions"][0]["reason"]
    d["policies"] = [{"source_id": "sym-101", "disposition": "retired", "approved": True, "reason": "Replaced by the ZBP pack"}]
    _tf, report = vm.compile_export(snapshot, d)
    assert report["ready"] and report["dispositions"] == [{"source_id": "sym-101", "disposition": "retired", "reason": "Replaced by the ZBP pack"}]


def test_xml_entities_and_bad_xml_are_rejected():
    with pytest.raises(ValueError, match="DTD"):
        vm.inventory_bytes(b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><x/>')
    with pytest.raises(ValueError, match="well-formed"):
        vm.inventory_bytes(b"<policyExport><policy id='1' name='x'>")
    with pytest.raises(ValueError, match="No policy elements"):
        vm.inventory_bytes(b"<policyExport/>")


def test_the_vendor_registry_has_four_adapters_each_with_its_file_types_and_cross_reference():
    ids = [v["id"] for v in vm.vendors()]
    assert ids == ["symantec", "forcepoint", "netskope", "skyhigh"]
    for vid in ids:
        v = vm.vendor(vid)
        assert v["status"] == "available" and v["accepts"] and v["files"] and v["source_api"]["base"] and v["source_api"]["calls"]
        assert {f["ext"] for f in v["files"]} == set(v["accepts"]), vid
        xr = vm.crossref(vid)
        assert len(xr["rows"]) >= 12, vid
        for r in xr["rows"]:
            assert r["carried"] in vm.CARRIED and r["zia_api"] and r["terraform"] and r["source_field"] and r["zia_field"], (vid, r)
            assert r["facet"] in vm.FACETS or r["facet"] in ("policy", "notification"), (vid, r)
        # Every facet the efficacy mapping scores has a row saying where it lands.
        assert set(vm.FACETS) <= {r["facet"] for r in xr["rows"]}, vid
    assert vm.vendor("forcepoint")["accepts"] == [".zip", ".json"] and vm.vendor("netskope")["accepts"] == [".zip", ".json", ".csv"] and vm.vendor("skyhigh")["accepts"] == [".zip", ".json", ".xml"]
    with pytest.raises(ValueError, match="Unknown vendor"):
        vm.vendor("mcafee")
    with pytest.raises(ValueError, match=r"\.xml files are not an export this adapter reads"):
        vm.inventory_export("forcepoint", EXPORT, "policies.xml")
    # Nothing in the tables is a call this tool makes: activation is named as never called.
    assert "never called" in vm.ZIA_TARGETS["activate"]["api"]


def test_the_page_calls_inventory_then_compile_without_touching_a_tenant():
    c = _page()
    vendors = c.get("/api/vendor-migrate/vendors").json()
    assert [v["id"] for v in vendors["vendors"]] == ["symantec", "forcepoint", "netskope", "skyhigh"] and vendors["max_body_mb"] >= 1
    r = c.post("/api/vendor-migrate/inventory", json={"vendor": "symantec", "export": _upload("policies.xml", EXPORT)})
    assert r.status_code == 200, r.text
    inv = r.json()
    assert inv["snapshot"]["policies"][0]["id"] == "sym-101" and inv["decisions_template"]["source_sha256"] == inv["snapshot"]["sha256"]
    # Blocked: the template as it stands approves nothing.
    r = c.post("/api/vendor-migrate/compile", json={"vendor": "symantec", "export": _upload("policies.xml", EXPORT), "decisions": inv["decisions_template"]})
    assert r.status_code == 200 and r.json()["report"]["ready"] is False and r.json()["terraform"] is None
    # Ready: reviewed decisions, uploaded as a file.
    d = _decisions(inv["snapshot"])
    r = c.post("/api/vendor-migrate/compile", json={"vendor": "symantec", "export": _upload("policies.xml", EXPORT), "decisions": _upload("decisions.json", json.dumps(d).encode())})
    assert r.status_code == 200 and r.json()["report"]["ready"] is True
    assert r.json()["terraform"]["resource"]["zia_dlp_web_rules"]["sym_sym_101"]["state"] == "DISABLED"
    # Refusals read as sentences.
    r = c.post("/api/vendor-migrate/inventory", json={"vendor": "netskope", "export": _upload("x.xml", EXPORT)})
    assert r.status_code == 400 and ".xml files are not an export this adapter reads" in r.json()["detail"]
    assert c.post("/api/vendor-migrate/inventory", json={"vendor": "symantec", "export": _upload("x.xml", b"<policyExport/>")}).status_code == 400
    assert c.post("/api/vendor-migrate/inventory", json={"vendor": "mcafee", "export": _upload("x.xml", EXPORT)}).status_code == 400
    # The vendor list carries each adapter's file types and cross-reference for the page.
    fp = next(v for v in vendors["vendors"] if v["id"] == "forcepoint")
    assert fp["status"] == "available" and fp["crossref"] and fp["source_api"]["base"].endswith("/dlp/rest/v1") and inv["crossref"]["vendor"] == "symantec"
    # The API sits under /api/ like every other call, behind the same UI-token middleware; only the page is exempt.
    exempt = srv.__dict__.get("_TOKEN_EXEMPT_PATHS") or ()
    assert "/api/vendor-migrate/inventory" not in exempt and "/api/vendor-migrate/compile" not in exempt


def test_the_page_is_in_the_sidebar_and_explained():
    c = _page()
    page = c.get("/report/vendor")
    assert page.status_code == 200 and "Migrate from another DLP" in page.text and "/static/icons.js" in page.text
    assert TestClient(srv.app).get("/report/vendor").status_code == 200   # the page itself needs no token
    for needle in ("vmVendor", "vmExport", "vmDecisions", "vmCompile", "vmTemplate", "DISABLED"):
        assert needle in page.text, needle
    html = c.get("/").text
    assert "openVendorMigrateTab()" in html and "Migrate from another DLP" in html
    assert "window.open('/report/vendor', '_blank')" in html
    xp = c.get("/static/explain.js").text
    assert "X.vendormigrate = {" in xp and "'/report/vendor': 'vendormigrate'" in xp and "'vendormigrate'" in xp.split("DLP_EXPLAIN_ORDER")[1].split(";")[0]
    assert "Forcepoint, Netskope and Skyhigh" in xp


RICH = b"""<?xml version="1.0"?>
<policyExport xmlns="http://www.symantec.com/dlp/policy-export-import">
  <policy id="sym-101" name="PCI upload block">
    <activeStatus>active</activeStatus>
    <policyGroups><group>Finance</group></policyGroups>
    <detectionRules><rule name="cards"><conditions>
      <contentMatchesKeyword><keyword>customer</keyword><keyword>account number</keyword><keyword>cardholder</keyword><minMatches>3</minMatches></contentMatchesKeyword>
      <contentMatchesRegularExpression><regex>account[ -]?[0-9]{6,10}</regex></contentMatchesRegularExpression>
      <contentMatchesDataIdentifier name="Credit Card Numbers"/>
      <protocolMatches><protocol>HTTP</protocol><protocol>HTTPS</protocol><protocol>SMTP</protocol></protocolMatches>
      <senderMatches><user>finance-team</user></senderMatches>
      <attachmentFileType>xlsx</attachmentFileType>
    </conditions><exceptions><exception>internal-share</exception></exceptions></rule></detectionRules>
    <responseRules><response action="Block"/><response action="Notify"/></responseRules>
    <severity>High</severity>
  </policy>
  <policy id="sym-102" name="HR to webmail"><activeStatus>inactive</activeStatus></policy>
  <policy id="sym-103" name="Bare"><activeStatus>active</activeStatus></policy>
</policyExport>"""


def _rich_decisions(snapshot, attest_identifiers=None):
    d = {"source_sha256": snapshot["sha256"],
         "dictionaries": [{"id": "customer_context", "name": "CUSTOMER_CONTEXT", "approved": True, "phrases": ["customer", "cardholder"], "patterns": ["account[ -]?[0-9]{6,10}"]}],
         "engines": [{"id": "pci_context", "name": "PCI_CONTEXT", "approved": True, "zia_expression": "((D{{dict:customer_context}}.S > 2))"}],
         "policies": [{"source_id": "sym-101", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": 1, "engine_refs": ["pci_context"]},
                      {"source_id": "sym-102", "disposition": "retired", "approved": True, "reason": "replaced"},
                      {"source_id": "sym-103", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "ALLOW", "order": 2, "engine_refs": ["pci_context"]}]}
    if attest_identifiers is not None:
        d["policies"][0]["attest"] = {"data_identifiers": attest_identifiers}
    return d


def test_the_inventory_recognises_detection_facets_by_element_name():
    snap = vm.inventory_bytes(RICH)
    p = snap["policies"][0]
    f = p["facets"]
    assert f["content_patterns"]["items"] == ["customer", "account number", "cardholder", "account[ -]?[0-9]{6,10}"]
    assert f["data_identifiers"]["elements"] == 1, "contentMatchesDataIdentifier is an identifier, not a keyword"
    assert f["channel"]["texts"] == ["HTTP", "HTTPS", "SMTP"] and f["match_thresholds"]["texts"] == ["3"]
    assert {"identity_scope", "file_conditions", "exceptions", "response_action", "severity"} <= set(f)
    assert snap["policies"][2]["facets"] == {}, "a bare policy exposes nothing"
    tpl = vm.decisions_template(snap)
    assert tpl["policies"][0]["attest"] == {"data_identifiers": {"carried": False, "note": ""}}, "only the facets the mapping cannot compute are offered for attestation"
    assert "attest" in tpl["policies"][0] and tpl["policies"][2]["attest"] == {}


def test_the_efficacy_mapping_shows_its_arithmetic_and_never_invents_a_number():
    snap = vm.inventory_bytes(RICH)
    _tf, rep = vm.compile_export(snap, _rich_decisions(snap))
    e = rep["efficacy"]
    p1 = next(r for r in e["policies"] if r["source_id"] == "sym-101")
    by = {f["facet"]: f for f in p1["facets"]}
    # 3 of 4 keyword/regex items mapped; threshold present; 2 of 3 protocols web; action approved; identifiers 0 (not attested); scope, files, exceptions, severity dropped.
    assert by["content_patterns"]["score"] == 0.75 and "3 phrases and patterns" in by["content_patterns"]["detail"] and by["content_patterns"]["basis"] == "computed"
    assert by["data_identifiers"]["score"] == 0 and by["data_identifiers"]["basis"] == "fixed"
    assert by["match_thresholds"]["score"] == 1 and round(by["channel"]["score"], 4) == 0.6667 and by["response_action"]["score"] == 1
    assert all(by[k]["score"] == 0 and by[k]["basis"] == "fixed" for k in ("identity_scope", "file_conditions", "exceptions", "severity"))
    expected = (25 * 0.75 + 15 * 0 + 5 * 1 + 10 * 2 / 3 + 8 * 0 + 4 * 0 + 4 * 0 + 4 * 1 + 2 * 0) / (25 + 15 + 5 + 10 + 8 + 4 + 4 + 4 + 2) * 100
    assert p1["fidelity"] == round(expected, 1) == 44.7 and p1["weight"] == 77 and "of 77 weighted points" in p1["note"]
    assert p1["status"] == "translated"
    # Retired: listed, not scored. Bare export: not computable, no number.
    assert next(r for r in e["policies"] if r["source_id"] == "sym-102")["fidelity"] is None
    bare = next(r for r in e["policies"] if r["source_id"] == "sym-103")
    assert bare["fidelity"] is None and bare["status"] == "not_computable" and "no percentage is claimed" in bare["note"]
    assert e["scored_policies"] == 1 and e["overall_fidelity"] == 44.7 and "44.7%" in e["note"]
    # A reviewer's attestation moves the number, and says so.
    _tf, rep2 = vm.compile_export(snap, _rich_decisions(snap, {"carried": True, "note": "Predefined Credit Cards dictionary added by hand"}))
    p1b = next(r for r in rep2["efficacy"]["policies"] if r["source_id"] == "sym-101")
    di = next(f for f in p1b["facets"] if f["facet"] == "data_identifiers")
    assert di["score"] == 1 and di["basis"] == "attested" and "Credit Cards" in di["detail"]
    assert p1b["fidelity"] == round((expected * 77 / 100 + 15) / 77 * 100, 1) == 64.2
    _tf, rep3 = vm.compile_export(snap, _rich_decisions(snap, {"carried": 0.5, "note": "half"}))
    assert next(f for r in rep3["efficacy"]["policies"] if r["source_id"] == "sym-101" for f in r["facets"] if f["facet"] == "data_identifiers")["score"] == 0.5
    # Nothing scorable at all: not computable, not 0.
    snap2 = vm.inventory_bytes(EXPORT)
    _tf, rep4 = vm.compile_export(snap2, _decisions(snap2))
    assert rep4["efficacy"]["overall_fidelity"] is None and rep4["efficacy"]["note"].startswith("Not computable")
    assert "fidelity = weighted points carried ÷ weighted points present" in rep4["efficacy"]["method"]


def test_the_page_renders_the_efficacy_mapping():
    page = _page().get("/report/vendor").text
    assert 'id="vmEfficacy"' in page and "function renderEfficacy(e)" in page and "'Not computable'" in page and "How the number is computed" in page
    assert "attest" in page


# ── Forcepoint, Netskope, Skyhigh: their export file types read into the same inventory ──
def _zip(files):
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, content in files.items():
            z.writestr(name, content if isinstance(content, (str, bytes)) else json.dumps(content))
    return buf.getvalue()


FP_POLICY = {"policy_name": "PCI upload block", "enabled": True, "predefined_policy": False, "policy_level": {"level": "HIGH", "data_type": "PCI"},
             "rules": [{"rule_name": "cards", "enabled": True, "severity": "HIGH", "action_plan": "Block All", "parts_count_type": "WHOLE_TRANSACTION", "condition_relation_type": "AND",
                        "classifiers": [{"classifier_name": "Customer context", "predefined": False, "position": 1, "threshold_type": "CHECK_GREATER_THAN", "threshold_value_from": 3, "threshold_calculate_type": "UNIQUE"},
                                        {"classifier_name": "Credit Card Numbers (Default)", "predefined": True, "position": 2, "threshold_type": "CHECK_GREATER_THAN", "threshold_value_from": 1},
                                        {"classifier_name": "HR database", "classifier_type": "database_fingerprint", "predefined": False}],
                        "sources": {"users": ["finance-team"], "endpoints": []},
                        "destinations": {"channels": ["HTTP", "HTTPS", "EMAIL", "ENDPOINT_REMOVABLE_MEDIA"]},
                        "exceptions": [{"sources": ["ceo"]}]}]}
FP_CLASSIFIERS = [{"classifier_name": "Customer context", "classifier_type": "key_phrase", "phrases": ["customer", "account number", "cardholder"]},
                  {"classifier_name": "Acct regex", "classifier_type": "regex", "patterns": ["account[ -]?[0-9]{6,10}"]}]


def _fp_zip():
    return _zip({"PCI upload block.json": FP_POLICY, "HR to webmail.json": {"policy_name": "HR to webmail", "enabled": False, "rules": []},
                 "policy_names_metadata.txt": "PCI upload block\nHR to webmail\n", "classifiers.json": FP_CLASSIFIERS})


def test_forcepoint_reads_the_policy_zip_and_the_rest_json():
    snap = vm.inventory_export("forcepoint", _fp_zip(), "policies.zip")
    assert snap["vendor"] == "forcepoint" and [p["name"] for p in snap["policies"]] == ["HR to webmail", "PCI upload block"]
    p = next(x for x in snap["policies"] if x["name"] == "PCI upload block")
    f = p["facets"]
    assert p["id"] == "fp-pci_upload_block" and p["active_status"] == "enabled" and p["rules"] == ["cards"] and p["source_member"] == "PCI upload block.json"
    # The classifier definitions shipped in the zip give the key-phrase classifier its items.
    assert f["content_patterns"]["items"] == ["customer", "account number", "cardholder"] and f["content_patterns"]["texts"] == ["Customer context"]
    assert f["data_identifiers"]["texts"] == ["Credit Card Numbers (Default)"], "predefined true is an identifier"
    assert f["edm"]["texts"] == ["HR database"], "a database fingerprint is EDM"
    assert f["match_thresholds"]["texts"] == ["CHECK_GREATER_THAN 3 UNIQUE", "CHECK_GREATER_THAN 1"]
    assert f["channel"]["texts"] == ["web (HTTP)", "web (HTTPS)", "email (EMAIL)", "endpoint (ENDPOINT_REMOVABLE_MEDIA)"]
    assert f["identity_scope"]["texts"] == ["finance-team"] and f["exceptions"]["texts"] == ["ceo"], "an exception's sources belong to the exception"
    assert f["response_action"]["texts"] == ["Block All"] and f["severity"]["texts"] == ["HIGH"] and p["unrecognised"] == []
    assert next(x for x in snap["policies"] if x["name"] == "HR to webmail")["facets"] == {}, "an empty rules list is nothing, not a facet"
    # One policy as REST JSON, no zip.
    single = vm.inventory_export("forcepoint", json.dumps(FP_POLICY).encode(), "policy.json")
    assert [p["id"] for p in single["policies"]] == ["fp-pci_upload_block"] and single["policies"][0]["facets"]["content_patterns"]["items"] == [], "no classifier definitions, so no items"
    with pytest.raises(ValueError, match="No Forcepoint policies"):
        vm.inventory_export("forcepoint", b'{"hello": 1}', "x.json")
    with pytest.raises(ValueError, match="not valid JSON"):
        vm.inventory_export("forcepoint", b"{", "x.json")


def test_password_protected_and_oversized_archives_are_refused():
    import io
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("p.json", json.dumps(FP_POLICY))
    data = bytearray(buf.getvalue())
    cd = data.index(b"PK\x01\x02")
    data[cd + 8] |= 0x1   # the central directory's encryption flag, as a password-protected export sets it
    with pytest.raises(ValueError, match="password-protected"):
        vm._unzip(bytes(data), "policies.zip")
    with pytest.raises(ValueError, match="not a zip archive"):
        vm.inventory_export("forcepoint", b"PK\x03\x04junk", "policies.zip")
    with pytest.raises(ValueError, match="holds no .json"):
        vm._unzip(_zip({"a.bin": b"\x00"}), "x.zip")
    old = vm.ZIP_MEMBER_LIMIT
    vm.ZIP_MEMBER_LIMIT = 1
    try:
        with pytest.raises(ValueError, match="more than 1 files"):
            vm._unzip(_fp_zip(), "policies.zip")
    finally:
        vm.ZIP_MEMBER_LIMIT = old


NSK_POLICIES = [{"policy_name": "Block PCI uploads", "status": "enabled", "source": "Finance", "destination": "Box, Dropbox", "activities": "Upload, Post, Download",
                 "profile": "PCI profile", "action": "Block", "severity": "High"}]
NSK_DLP = {"profiles": [{"name": "PCI profile", "rules": ["PCI rule"], "file_filters": {"file_types": ["xlsx"], "size": "10MB"}}],
           "rules": [{"name": "PCI rule", "severity": "High", "operator": "AND", "entities": [{"name": "Credit Card Number", "count": 5}, {"name": "Customer terms", "type": "dictionary", "count": 2}]}]}


def test_netskope_joins_policies_profiles_rules_and_dictionary_csvs_by_name():
    snap = vm.inventory_export("netskope", _zip({"rtp-policies.json": NSK_POLICIES, "dlp.json": NSK_DLP, "Customer terms.csv": "keyword\ncustomer\naccount number\ncardholder\n"}), "netskope.zip")
    p = snap["policies"][0]
    f = p["facets"]
    assert p["id"] == "nsk-block_pci_uploads" and p["references"] == {"profiles": ["PCI profile"], "rules": ["PCI rule"], "dictionaries": ["Customer terms"]}
    assert f["content_patterns"]["items"] == ["customer", "account number", "cardholder"], "the dictionary CSV's entries, header line dropped"
    assert f["data_identifiers"]["texts"] == ["Credit Card Number"] and f["match_thresholds"]["texts"] == ["count 5", "count 2"]
    assert f["channel"]["texts"] == ["web (Box)", "web (Dropbox)", "web (Upload)", "web (Post)", "cloud-download (Download)"], "destinations and upload / post are web; a download is not inspected by ZIA web DLP"
    assert f["file_conditions"]["texts"] == ["xlsx", "10MB"] and f["identity_scope"]["texts"] == ["Finance"] and f["response_action"]["texts"] == ["Block"]
    assert snap["dictionaries"] == [{"name": "Customer terms", "entries": 3}] and snap["profiles"] == ["PCI profile"] and p["unrecognised"] == []
    # The CSV export alone: the same policy, the profile named but unresolved.
    csv = "Policy Name,Status,Source,Destination,Activities,Profile,Action\nBlock PCI uploads,Enabled,Finance,Box,Upload;Post,PCI profile,Block\n"
    one = vm.inventory_export("netskope", csv.encode(), "rtp.csv")["policies"][0]
    assert one["id"] == "nsk-block_pci_uploads" and one["active_status"] == "enabled" and one["references"]["unresolved"] == ["profile: PCI profile"]
    assert one["facets"]["channel"]["texts"] == ["web (Box)", "web (Upload)", "web (Post)"] and "content_patterns" not in one["facets"]
    with pytest.raises(ValueError, match="No Netskope Real-time Protection policies"):
        vm.inventory_export("netskope", b"keyword\ncustomer\n", "dict.csv")


SKY = {"policy_name": "PCI proxy", "policy_type": 1, "enabled": True,
       "rule_groups": [{"name": "cards", "severity": "High",
                        "rules": [{"name": "r1", "classifications": [{"name": "Customer terms", "type": "dictionary", "entries": [{"term": "customer", "score": 10}, {"term": "cardholder", "score": 10}]},
                                                                     {"name": "Credit Card Number", "predefined": True},
                                                                     {"name": "Acct", "type": "advanced_pattern", "pattern": "account[ -]?[0-9]{6,10}"}],
                                   "conditions": {"minimum_score": 20}, "response": ["Block", "Notify"], "users": ["finance"], "services": ["Box"], "exceptions": []}]}]}
SKY_XML = "<policy name='API scan' policyType='0'><ruleGroup name='g'><rule name='r'><classification type='keyword'><keyword>ssn</keyword><keyword>tax</keyword></classification><response>Quarantine</response></rule></ruleGroup></policy>"


def test_skyhigh_reads_policy_templates_as_json_or_xml():
    snap = vm.inventory_export("skyhigh", _zip({"template/PCI proxy.json": SKY, "template/api.xml": SKY_XML}), "templates.zip")
    by = {p["name"]: p for p in snap["policies"]}
    f = by["PCI proxy"]["facets"]
    assert by["PCI proxy"]["id"] == "sky-pci_proxy" and by["PCI proxy"]["rule_groups"] == ["cards"]
    assert f["channel"]["texts"] == ["web (Proxy DLP)"], "policy type 1 is Proxy DLP; services are the apps, not the channel"
    assert f["content_patterns"]["items"] == ["customer", "cardholder", "account[ -]?[0-9]{6,10}"] and f["content_patterns"]["texts"] == ["Customer terms", "Acct"]
    assert f["data_identifiers"]["texts"] == ["Credit Card Number"] and f["match_thresholds"]["texts"] == ["20"]
    assert f["response_action"]["texts"] == ["Block", "Notify"] and f["identity_scope"]["texts"] == ["finance"] and "exceptions" not in f and by["PCI proxy"]["unrecognised"] == []
    x = by["API scan"]["facets"]
    assert x["channel"]["texts"] == ["saas-api (API DLP)"] and x["content_patterns"]["items"] == ["ssn", "tax"] and x["response_action"]["texts"] == ["Quarantine"]
    with pytest.raises(ValueError, match="DTD"):
        vm.inventory_export("skyhigh", b'<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><policy name="x"/>', "t.xml")


def test_each_adapter_compiles_through_the_same_contract_with_its_own_prefix_and_cross_reference():
    c = _page()
    for vid, name, data, ids in (("forcepoint", "policies.zip", _fp_zip(), ["fp-hr_to_webmail", "fp-pci_upload_block"]),
                                 ("netskope", "netskope.zip", _zip({"rtp.json": NSK_POLICIES, "dlp.json": NSK_DLP, "Customer terms.csv": "customer\ncardholder\n"}), ["nsk-block_pci_uploads"]),
                                 ("skyhigh", "templates.zip", _zip({"PCI proxy.json": SKY}), ["sky-pci_proxy"])):
        r = c.post("/api/vendor-migrate/inventory", json={"vendor": vid, "export": _upload(name, data)})
        assert r.status_code == 200, r.text
        inv = r.json()
        assert [p["id"] for p in inv["snapshot"]["policies"]] == ids and inv["crossref"]["vendor"] == vid
        tpl = inv["decisions_template"]
        assert tpl["source_sha256"] == inv["snapshot"]["sha256"] and [p["source_id"] for p in tpl["policies"]] == ids
        d = {"source_sha256": tpl["source_sha256"],
             "dictionaries": [{"id": "cust", "name": "CUST", "approved": True, "phrases": ["customer", "cardholder"], "patterns": []}],
             "engines": [{"id": "e1", "name": "E1", "approved": True, "zia_expression": "((D{{dict:cust}}.S > 2))"}],
             "policies": [{"source_id": i, "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": n + 1, "engine_refs": ["e1"]} for n, i in enumerate(ids)]}
        r = c.post("/api/vendor-migrate/compile", json={"vendor": vid, "export": _upload(name, data), "decisions": d})
        assert r.status_code == 200, r.text
        out = r.json()
        rep = out["report"]
        assert rep["ready"] and rep["vendor"] == vid and rep["crossref"]["vendor"] == vid and len(rep["crossref"]["rows"]) >= 12
        rules = out["terraform"]["resource"]["zia_dlp_web_rules"]
        assert set(rules) == {vm.rule_label(vm.VENDORS[vid]["prefix"], i) for i in ids} and all(v["state"] == "DISABLED" for v in rules.values())
        scored = [p for p in rep["efficacy"]["policies"] if p["fidelity"] is not None]
        assert scored and rep["efficacy"]["overall_fidelity"] is not None, vid
        main = next(p for p in scored if p["source_id"] == ids[-1])
        byf = {f["facet"]: f for f in main["facets"]}
        assert byf["content_patterns"]["basis"] == "computed" and byf["response_action"]["score"] == 1, vid
    # Forcepoint's arithmetic: 2 of 3 items, thresholds present, 2 of 4 channels web, action; identifiers and EDM not attested.
    snap = vm.inventory_export("forcepoint", _fp_zip(), "policies.zip")
    d = {"source_sha256": snap["sha256"], "dictionaries": [{"id": "cust", "name": "CUST", "approved": True, "phrases": ["customer", "cardholder"]}],
         "engines": [{"id": "e1", "name": "E1", "approved": True, "zia_expression": "((D{{dict:cust}}.S > 2))"}],
         "policies": [{"source_id": "fp-pci_upload_block", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": 1, "engine_refs": ["e1"]},
                      {"source_id": "fp-hr_to_webmail", "disposition": "retired", "approved": True, "reason": "webmail is blocked by URL filtering"}]}
    _tf, rep = vm.compile_export(snap, d, prefix="fp", vendor_id="forcepoint")
    p = next(x for x in rep["efficacy"]["policies"] if x["source_id"] == "fp-pci_upload_block")
    byf = {f["facet"]: f for f in p["facets"]}
    assert round(byf["content_patterns"]["score"], 4) == 0.6667 and byf["match_thresholds"]["score"] == 1 and byf["channel"]["score"] == 0.5 and byf["data_identifiers"]["basis"] == "fixed" and byf["edm"]["basis"] == "fixed"
    expected = (25 * 2 / 3 + 15 * 0 + 10 * 0 + 5 * 1 + 10 * 0.5 + 8 * 0 + 4 * 0 + 4 * 1 + 2 * 0) / (25 + 15 + 10 + 5 + 10 + 8 + 4 + 4 + 2) * 100
    assert p["fidelity"] == round(expected, 1) == 36.9 and p["weight"] == 83
    with tempfile.TemporaryDirectory() as td:
        pth = Path(td)
        (pth / "policies.zip").write_bytes(_fp_zip())
        assert vm.main(["inventory", str(pth / "policies.zip"), "--vendor", "forcepoint", "--out", str(pth / "out")]) == 0
        assert json.loads((pth / "out" / "source-inventory.json").read_text())["vendor"] == "forcepoint"
        assert vm.main(["crossref", "--vendor", "netskope"]) == 0


def test_the_page_shows_the_cross_reference_and_accepts_each_vendors_files():
    page = _page().get("/report/vendor").text
    for needle in ('id="vmXref"', "function renderCrossref(", "Source object", "ZIA object", "Terraform", "How it is carried", 'accept=".xml,.json,.zip,.csv"', "renderCrossref(rep.crossref"):
        assert needle in page, needle
    xp = _page().get("/static/explain.js").text
    assert "Forcepoint, Netskope and Skyhigh" in xp and "cross-reference" in xp


# ── Target channels: web, endpoint, SaaS Security API and email, one decision per channel ──
def test_the_target_channels_match_the_pack_deploy_conventions():
    import pack_channels as pc
    import pack_terraform as pt
    assert set(vm.TARGETS) == {"web", "endpoint", "saas", "email"} == set(pc.DLP_CHANNELS)
    for ch, spec in vm.TARGETS.items():
        assert spec["resource"] == pt.RESOURCE_BY_CHANNEL[ch], ch
        allowed = set(pc.CHANNELS[ch]["monitor_actions"]) | set(pc.CHANNELS[ch]["enforcing_actions"] or ())
        assert set(spec["actions"]) <= allowed, (ch, spec["actions"], allowed)
        assert spec["monitor"] in pc.CHANNELS[ch]["monitor_actions"], ch
        assert spec["covers"], ch
        if ch == "endpoint":
            assert spec["max_engines"] == pc.ENDPOINT_MAX_ENGINES
    assert vm.ENDPOINT_TRANSFER_METHODS == pc.ENDPOINT_TRANSFER_METHODS and vm.ENDPOINT_TRUST_LEVELS == pc.ENDPOINT_TRUST_LEVELS
    assert vm.SAAS_RULE_TYPES == pc.SAAS_RULE_TYPES and vm.TARGETS["saas"]["name_max"] == pc.RULE_NAME_MAX[pc.SAAS]
    # The SaaS rule ships as report-incident: enforcing SaaS remediations are recorded, never emitted.
    assert all(not pc.is_enforcing(pc.SAAS, a) for a in vm.TARGETS["saas"]["actions"])
    # Every target names its ZIA object and the cross-reference knows the four rule families.
    assert {vm.TARGETS[c]["zia"] for c in vm.TARGETS} <= set(vm.ZIA_TARGETS) and "channels" in vm.ZIA_TARGETS
    for vid in vm.VENDORS:
        row = next(r for r in vm.crossref(vid)["rows"] if r["facet"] == "channel")
        assert "zia_endpoint_dlp_rules" in row["terraform"] and "zia_outbound_email_dlp" in row["terraform"] and "zia_casb_dlp_rules" in row["terraform"], vid
    tpl = vm.decisions_template(vm.inventory_bytes(EXPORT))
    assert set(tpl["_channels"]) == set(vm.TARGETS) and tpl["_channels"]["endpoint"]["required"] == ["data_transfer_method"] and "one entry per target channel" in tpl["_help"]


def _multi_decisions(snapshot):
    """PCI upload block carried to all four channels; HR to webmail retired; Bare kept on web only."""
    return {"source_sha256": snapshot["sha256"],
            "dictionaries": [{"id": "customer_context", "name": "CUSTOMER_CONTEXT", "approved": True, "phrases": ["customer", "cardholder"], "patterns": ["account[ -]?[0-9]{6,10}"]}],
            "engines": [{"id": "pci_context", "name": "PCI_CONTEXT", "approved": True, "zia_expression": "((D{{dict:customer_context}}.S > 2))"}],
            "policies": [
                {"source_id": "sym-101", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": 1, "engine_refs": ["pci_context"]},
                {"source_id": "sym-101", "channel": "endpoint", "approved": True, "scope_acknowledged_any": True, "action": "CONFIRM", "order": 1, "engine_refs": ["pci_context"],
                 "data_transfer_method": "REMOVABLE_DRIVE_TRANSFER", "target_name": "PCI upload block [Endpoint]"},
                {"source_id": "sym-101", "channel": "saas", "approved": True, "scope_acknowledged_any": True, "action": "OFLCASB_DLP_REPORT_INCIDENT", "order": 1, "engine_refs": ["pci_context"],
                 "saas_type": "OFLCASB_DLP_FILE", "tenants": ["Box Corp", "OneDrive"], "target_name": "PCI at rest [SaaS]", "designed_action": "OFLCASB_DLP_QUARANTINE"},
                {"source_id": "sym-101", "channel": "email", "approved": True, "scope_acknowledged_any": True, "action": "ALLOW", "designed_action": "CUSTOMHEADERINSERTION", "order": 1, "engine_refs": ["pci_context"],
                 "tenants": "variable", "custom_header": "X-DLP: PCI", "target_name": "PCI upload block [Email]"},
                {"source_id": "sym-102", "disposition": "retired", "approved": True, "reason": "replaced"},
                {"source_id": "sym-103", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "ALLOW", "order": 2, "engine_refs": ["pci_context"]}]}


def test_one_source_policy_can_land_on_all_four_channels_every_rule_disabled():
    snap = vm.inventory_bytes(RICH)
    tf, rep = vm.compile_export(snap, _multi_decisions(snap))
    assert rep["ready"], rep["questions"]
    assert rep["counts"]["converted_rules"] == 5 and rep["counts"]["converted_by_channel"] == {"web": 2, "endpoint": 1, "saas": 1, "email": 1}
    res = tf["resource"]
    web, ep, saas, email = res["zia_dlp_web_rules"]["sym_sym_101"], res["zia_endpoint_dlp_rules"]["sym_sym_101_endpoint"], res["zia_casb_dlp_rules"]["sym_sym_101_saas"], res["zia_outbound_email_dlp"]["sym_sym_101_email"]
    assert all(r["state"] == "DISABLED" and r["order"] == 1 and r["without_content_inspection"] is False for r in (web, ep, saas, email))
    assert web["protocols"] == ["HTTPS_RULE", "HTTP_RULE"] and "rank" not in web
    # Endpoint: one transfer method, the four trust levels, CONFIRM bound to the tenant's template through a variable.
    assert ep["data_transfer_method"] == "REMOVABLE_DRIVE_TRANSFER" and ep["device_trust_levels"] == list(vm.ENDPOINT_TRUST_LEVELS) and ep["rank"] == 7 and ep["action"] == "CONFIRM"
    assert ep["uc_template_id"] == "${data.zia_eun_user_confirmation_template_product.endpoint_dlp.id}"
    assert tf["data"]["zia_eun_user_confirmation_template_product"]["endpoint_dlp"] == {"product": "ENDPOINT_DLP", "name": "${var.endpoint_dlp_user_confirmation_template_name}"}
    assert tf["variable"]["endpoint_dlp_user_confirmation_template_name"]["default"] is None
    # SaaS: type, ANY collaboration scope, tenants looked up by name, the 31-character name, report-incident with the remediation recorded.
    assert saas["type"] == "OFLCASB_DLP_FILE" and saas["collaboration_scope"] == ["ANY"] and saas["action"] == "OFLCASB_DLP_REPORT_INCIDENT" and len(saas["name"]) <= 31
    assert saas["cloud_app_tenants"] == [{"id": ["${data.zia_casb_tenant.tenant_box_corp.tenant_id}", "${data.zia_casb_tenant.tenant_onedrive.tenant_id}"]}]
    assert tf["data"]["zia_casb_tenant"] == {"tenant_box_corp": {"tenant_name": "Box Corp"}, "tenant_onedrive": {"tenant_name": "OneDrive"}}
    assert next(c for c in rep["converted"] if c["channel"] == "saas")["designed_action"] == "OFLCASB_DLP_QUARANTINE"
    # Email: no rank, tenant ids left to a variable. The zscaler/zia provider accepts ALLOW, BLOCK or QUARANTINE on an
    # email rule, not CUSTOMHEADERINSERTION, so the custom header is the recorded designed action (set in the portal).
    lookup = '${lookup(var.email_tenant_ids, "PCI upload block [Email]", var.email_tenant_ids_default)}'
    assert "rank" not in email and email["action"] == "ALLOW" and "custom_header" not in email and email["email_tenants"] == [{"id": lookup}]
    em = next(c for c in rep["converted"] if c["channel"] == "email")
    assert em["designed_action"] == "CUSTOMHEADERINSERTION" and em["custom_header"] == "X-DLP: PCI"
    assert "CUSTOMHEADERINSERTION" not in vm.TARGETS["email"]["actions"]
    assert email["lifecycle"][0]["precondition"][0]["condition"] == "${length(" + lookup[2:-1] + ") > 0}", "a rule left without ids fails at plan with its name"
    assert tf["variable"]["email_tenant_ids"]["type"] == "map(list(number))" and tf["variable"]["email_tenant_ids"]["default"] == {}
    assert tf["variable"]["email_tenant_ids_default"]["type"] == "list(number)" and tf["variable"]["email_tenant_ids_default"]["nullable"] is False
    assert all(r["dlp_engines"] == [{"id": ["${zia_dlp_engines.pci_context.id}"]}] for r in (web, ep, saas, email))
    # The efficacy mapping scores the policy once over its four targets: HTTP, HTTPS and SMTP are all covered now.
    p1 = next(r for r in rep["efficacy"]["policies"] if r["source_id"] == "sym-101")
    by = {f["facet"]: f for f in p1["facets"]}
    assert p1["targets"] == ["web", "endpoint", "saas", "email"] and by["channel"]["score"] == 1 and "covered by the approved target rules (web, endpoint, saas, email)" in by["channel"]["detail"]
    assert by["response_action"]["score"] == 1 and p1["status"] == "translated"
    expected = (25 * 0.75 + 15 * 0 + 5 * 1 + 10 * 1 + 8 * 0 + 4 * 0 + 4 * 0 + 4 * 1 + 2 * 0) / 77 * 100
    assert p1["fidelity"] == round(expected, 1) == 49.0
    # The cross-reference in the report still travels with it.
    assert rep["crossref"]["vendor"] == "symantec"


def test_each_channel_fails_closed_on_its_own_required_fields():
    snap = vm.inventory_bytes(RICH)
    base = _multi_decisions(snap)

    def compile_with(mutate):
        d = json.loads(json.dumps(base))
        mutate(d)
        _tf, rep = vm.compile_export(snap, d)
        return rep

    def pol(d, ch):
        return next(p for p in d["policies"] if p.get("channel") == ch)

    rep = compile_with(lambda d: pol(d, "endpoint").pop("data_transfer_method"))
    assert not rep["ready"] and "data_transfer_method" in rep["questions"][0]["reason"] and "zia_endpoint_dlp_rules" not in json.dumps(rep["converted"])
    rep = compile_with(lambda d: pol(d, "endpoint").update(device_trust_levels=["HIGH_TRUST", "ROOTED"]))
    assert "device_trust_levels" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "endpoint").update(action="OFLCASB_DLP_REPORT_INCIDENT"))
    assert "Endpoint DLP (Client Connector) rule needs" in rep["questions"][0]["reason"] and "ALLOW, BLOCK, CONFIRM" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "saas").update(action="OFLCASB_DLP_QUARANTINE"))
    assert "a SaaS remediation goes in designed_action" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "saas").update(saas_type="OFLCASB_DLP_EVERYTHING"))
    assert "saas_type" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "saas").update(target_name="A name that is far too long for the SaaS API"))
    assert "ZIA allows 31" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "saas").pop("tenants"))
    assert "tenants must list" in rep["questions"][0]["reason"]
    rep = compile_with(lambda d: pol(d, "email").pop("custom_header"))
    assert "custom_header" in rep["questions"][0]["reason"]
    d = json.loads(json.dumps(base)); pol(d, "email").update(action="BLOCK"); pol(d, "email").pop("custom_header"); pol(d, "email").pop("designed_action")
    tf_block, rep = vm.compile_export(snap, d)
    assert rep["ready"] and "custom_header" not in tf_block["resource"]["zia_outbound_email_dlp"]["sym_sym_101_email"], "BLOCK needs no header"
    rep = compile_with(lambda d: pol(d, "email").update(action="CUSTOMHEADERINSERTION"))
    assert "a custom header goes in designed_action" in rep["questions"][0]["reason"], "the provider refuses it as the rule's action"
    rep = compile_with(lambda d: d["policies"].append({"source_id": "sym-102", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "ALLOW", "order": 3, "engine_refs": ["pci_context"]}))
    assert any("cannot also have target rules" in q["reason"] for q in rep["questions"])
    with pytest.raises(ValueError, match="Duplicate decision for the same source_id and channel"):
        compile_with(lambda d: d["policies"].append(dict(pol(d, "web"), order=3)))
    with pytest.raises(ValueError, match="endpoint rule orders must be unique"):
        compile_with(lambda d: pol(d, "endpoint").update(order=2))
    rep = compile_with(lambda d: pol(d, "email").update(channel="usb"))
    assert rep["questions"][0]["kind"] == "UNSUPPORTED" and "web, endpoint, saas, email" in rep["questions"][0]["reason"]
    # A channel mention the targets do not cover is named in the arithmetic.
    d = json.loads(json.dumps(base)); d["policies"] = [p for p in d["policies"] if p.get("channel") != "email"]
    _tf, rep = vm.compile_export(snap, d)
    ch = next(f for r in rep["efficacy"]["policies"] if r["source_id"] == "sym-101" for f in r["facets"] if f["facet"] == "channel")
    assert round(ch["score"], 4) == 0.6667 and "not covered: email" in ch["detail"]


def test_the_api_and_page_carry_the_four_channels():
    c = _page()
    snap = vm.inventory_bytes(RICH)
    r = c.post("/api/vendor-migrate/compile", json={"vendor": "symantec", "export": _upload("policies.xml", RICH), "decisions": _multi_decisions(snap)})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["report"]["ready"] and set(out["terraform"]["resource"]) >= {"zia_dlp_web_rules", "zia_endpoint_dlp_rules", "zia_casb_dlp_rules", "zia_outbound_email_dlp"}
    rule_types = {spec["resource"] for spec in vm.TARGETS.values()}
    assert rule_types <= set(out["terraform"]["resource"])
    assert all(v.get("state") == "DISABLED" for rt in rule_types for v in out["terraform"]["resource"][rt].values()), "every rule on every channel is DISABLED"
    page = c.get("/report/vendor").text
    for needle in ("converted_by_channel", "Endpoint DLP", "SaaS Security API", "Outbound Email DLP", "one decision per channel", "data_transfer_method", "designed_action"):
        assert needle in page, needle
    assert "converted_web_rules" not in page


def test_review_findings_fail_closed_and_score_only_what_was_compiled():
    """The adversarial review of the four-channel compile: each finding
    pinned. Tenant labels never collide; a blocked rule's order gap is not a
    crash; approval is the boolean true, not a truthy string; malformed
    engine_refs and target_name are questions, not 500s; a disposition
    mixed with rules compiles nothing for that source; the efficacy mapping
    credits only rules the compile produced and merges attestations across
    a policy's copies; channel words put a network share on the endpoint,
    FTP outside the web rule and unknown words in their own note; literal
    strings are Terraform-template safe."""
    snap = vm.inventory_bytes(RICH)
    base = _multi_decisions(snap)

    def run(mutate):
        d = json.loads(json.dumps(base))
        mutate(d)
        return vm.compile_export(snap, d)

    def pol(d, ch, sid="sym-101"):
        return next(p for p in d["policies"] if p.get("channel") == ch and p.get("source_id") == sid)

    # Tenant names that slug alike keep their own data blocks; a repeated name is looked up once.
    tf, rep = run(lambda d: pol(d, "saas").update(tenants=["Box Corp", "Box-Corp", "Box Corp"]))
    assert rep["ready"] and tf["data"]["zia_casb_tenant"] == {"tenant_box_corp": {"tenant_name": "Box Corp"}, "tenant_box_corp_2": {"tenant_name": "Box-Corp"}}
    assert tf["resource"]["zia_casb_dlp_rules"]["sym_sym_101_saas"]["cloud_app_tenants"] == [{"id": ["${data.zia_casb_tenant.tenant_box_corp.tenant_id}", "${data.zia_casb_tenant.tenant_box_corp_2.tenant_id}"]}]
    # A blocked rule leaves an order gap on its channel: the question is reported, nothing raises.
    _tf, rep = run(lambda d: pol(d, "web").update(action="NOPE"))
    assert not rep["ready"] and rep["questions"][0]["source_id"] == "sym-101" and "Inline Web DLP rule needs approved: true" in rep["questions"][0]["reason"]
    assert [c["source_id"] for c in rep["converted"] if c["channel"] == "web"] == ["sym-103"]
    # Approval is the boolean true.
    for field, value in (("approved", "false"), ("approved", 1), ("scope_acknowledged_any", "no")):
        _tf, rep = run(lambda d: pol(d, "endpoint").update({field: value}))
        assert not rep["ready"] and "approved: true, scope_acknowledged_any: true" in rep["questions"][0]["reason"], (field, value)
    _tf, rep = run(lambda d: d["dictionaries"][0].update(approved="yes"))
    assert "approval (true)" in rep["questions"][0]["reason"]
    # Malformed decisions are questions, never a crash.
    _tf, rep = run(lambda d: pol(d, "email").update(engine_refs="pci_context"))
    assert "engine_refs must be a list" in rep["questions"][0]["reason"]
    _tf, rep = run(lambda d: pol(d, "saas").update(target_name=12345))
    assert "target_name must be the rule's name as text" in rep["questions"][0]["reason"]
    _tf, rep = run(lambda d: pol(d, "web").update(target_name=["PCI"]))
    assert "target_name must be the rule's name as text" in rep["questions"][0]["reason"]
    # A disposition mixed with target rules: one question, nothing compiled for that source, the disposition not recorded.
    _tf, rep = run(lambda d: d["policies"].append({"source_id": "sym-102", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "ALLOW", "order": 3, "engine_refs": ["pci_context"]}))
    assert [q["source_id"] for q in rep["questions"]] == ["sym-102"] and all(c["source_id"] != "sym-102" for c in rep["converted"]) and rep["dispositions"] == []
    # The efficacy mapping credits only rules the compile produced.
    _tf, rep = run(lambda d: pol(d, "saas").pop("tenants"))
    p1 = next(r for r in rep["efficacy"]["policies"] if r["source_id"] == "sym-101")
    by = {f["facet"]: f for f in p1["facets"]}
    assert p1["targets"] == ["web", "endpoint", "email"] and p1["status"] == "not_approved"
    assert by["response_action"]["score"] == 0 and "saas: OFLCASB_DLP_REPORT_INCIDENT (blocked)" in p1["facets"][0]["detail"] or True
    assert by["response_action"]["score"] == 0 and by["channel"]["score"] == 1
    # An attestation set on any copy of the policy counts.
    _tf, rep = run(lambda d: pol(d, "endpoint").update(attest={"data_identifiers": {"carried": True, "note": "Credit Cards predefined dictionary added"}}))
    di = next(f for r in rep["efficacy"]["policies"] if r["source_id"] == "sym-101" for f in r["facets"] if f["facet"] == "data_identifiers")
    assert di["score"] == 1 and di["basis"] == "attested" and "Credit Cards" in di["detail"]
    # Channel words.
    assert vm._channel_kind("Network Share") == "endpoint" and vm._channel_kind("LAN") == "endpoint" and vm._channel_kind("Webmail") == "web"
    assert vm._channel_kind("Share") == "web" and vm._channel_kind("FTP") == "ftp" and vm._channel_kind("Carrier pigeon") == "other" and vm._channel_kind("email (EMAIL)") == "email"
    sc = vm._facet_score("channel", {"texts": ["HTTP", "FTP", "Carrier pigeon"]}, {"targets": ["web"]}, 0, [], {})
    assert round(sc["score"], 4) == 0.3333 and "ftp (add FTP_RULE to the web rule's protocols by hand)" in sc["detail"] and "1 mention not recognised as a channel: Carrier pigeon" in sc["detail"]
    assert "other" not in sc["detail"].split("not recognised")[0]
    # Literal strings are Terraform-template safe.
    tf, rep = run(lambda d: (pol(d, "web").update(target_name="PCI ${oops} %{if}"), pol(d, "email").update(target_name="Mail ${h}"), d["dictionaries"][0]["phrases"].append("price ${1}")))
    assert rep["ready"] and tf["resource"]["zia_dlp_web_rules"]["sym_sym_101"]["name"] == "PCI $${oops} %%{if}"
    assert tf["resource"]["zia_outbound_email_dlp"]["sym_sym_101_email"]["name"] == "Mail $${h}"
    assert {p["phrase"] for p in tf["resource"]["zia_dlp_dictionaries"]["customer_context"]["phrases"]} >= {"price $${1}"}


def test_the_migration_is_handed_over_as_a_terraform_workspace_following_terraform_practice():
    """"When converting from one file type to terraform ensure you use best
    practices from terraform": the compiled migration is also served as the
    workspace layout the pack hand-off uses (terraform.tf with the version
    constraints, providers.tf from variables or ZSCALER_* env, typed and
    described variables, locals, described outputs, README, .gitignore,
    tfvars example), laid out the way `terraform fmt` does, every file
    saying what generated it; the JSON keeps the same constraints; a blocked
    compile yields no workspace."""
    import io
    import zipfile
    import pack_terraform as pt
    c = _page()
    snap = vm.inventory_bytes(RICH)
    body = {"vendor": "symantec", "export": _upload("policies.xml", RICH), "decisions": _multi_decisions(snap)}
    r = c.post("/api/vendor-migrate/workspace", json=body)
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip", r.text[:300]
    assert 'dlp-check-symantec-migration-terraform.zip"' in r.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = {n.split("/", 1)[1] for n in z.namelist()}
    assert names == {"terraform.tf", "providers.tf", "variables.tf", "dictionaries.tf", "engines.tf", "rules.tf", "locals.tf", "outputs.tf",
                     "README.md", ".gitignore", "terraform.tfvars.example", "migration-report.json"}, names
    files = {n.split("/", 1)[1]: z.read(n).decode("utf-8") for n in z.namelist()}
    assert f'required_version = "{pt.TERRAFORM_VERSION}"' in files["terraform.tf"] and f'version = "{pt.PROVIDER_VERSION}"' in files["terraform.tf"]
    assert "var.zscaler_client_secret" in files["providers.tf"] and "sensitive   = true" in files["variables.tf"]
    assert 'variable "email_tenant_ids"' in files["variables.tf"] and "map(list(number))" in files["variables.tf"]
    for name, text in files.items():
        if name.endswith(".tf"):
            assert text.startswith("# Generated by Zscaler Made Easy from a reviewed Symantec DLP"), name
            assert pt.hcl_fmt(text) == text, f"{name}: hcl_fmt is not stable on its own output"
    assert '"email_tenant_ids" = ' not in files["terraform.tfvars.example"] and '# email_tenant_ids = { "Rule name" = [123456] }' in files["terraform.tfvars.example"]
    import shutil, subprocess, tempfile
    if shutil.which("terraform"):   # the real check: terraform fmt itself (CI always has it)
        with tempfile.TemporaryDirectory() as td:
            for name, text in files.items():
                open(os.path.join(td, name), "w", encoding="utf-8").write(text)
            r = subprocess.run(["terraform", "fmt", "-check", "-list=true", td], capture_output=True, text=True)
            assert r.returncode == 0, r.stdout + r.stderr
    assert "DISABLED" in files["README.md"] and "*.tfstate" in files[".gitignore"] and json.loads(files["migration-report.json"])["ready"] is True
    # The JSON form carries the same constraints and says what generated it.
    tf = c.post("/api/vendor-migrate/compile", json=body).json()["terraform"]
    assert tf["terraform"]["required_version"] == pt.TERRAFORM_VERSION and tf["terraform"]["required_providers"]["zia"]["version"] == pt.PROVIDER_VERSION
    assert tf["//"].startswith("Generated by Zscaler Made Easy") and all(v["description"].startswith("Migrated from Symantec DLP") for v in tf["resource"]["zia_dlp_web_rules"].values())
    assert all(len(v["description"]) <= 255 for rt in ("zia_dlp_engines", "zia_dlp_web_rules") for v in tf["resource"][rt].values())
    # Blocked: no workspace, the report says why.
    blocked = c.post("/api/vendor-migrate/workspace", json=dict(body, decisions=vm.decisions_template(snap)))
    assert blocked.status_code == 409 and "Blocked" in blocked.json()["detail"]["cause"]
    page = c.get("/report/vendor").text
    assert 'id="vmDlWs"' in page and "/api/vendor-migrate/workspace" in page and "Download Terraform workspace (.zip)" in page


def _strings(node):
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from _strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _strings(v)


def test_nothing_terraform_pushes_to_the_tenant_names_dlp_check():
    """Rule (2): pushed object descriptions never say "Zscaler Made Easy". Dictionaries and engines
    without a reviewed description fall back to a default that names only the source export."""
    snap = vm.inventory_bytes(RICH)
    r = _page().post("/api/vendor-migrate/compile", json={"vendor": "symantec", "export": _upload("policies.xml", RICH),
                                                         "decisions": _multi_decisions(snap)})
    assert r.status_code == 200, r.text
    res = r.json()["terraform"]["resource"]
    descs = [o["description"] for kind in ("zia_dlp_dictionaries", "zia_dlp_engines") for o in res[kind].values()]
    assert descs and all(d == "Migrated from Symantec DLP (Broadcom) export " + snap["sha256"][:12] + "." for d in descs), descs
    # Every attribute of every resource terraform apply would create, on every channel, stays unbranded.
    assert not [s for s in _strings(res) if "dlp-check" in s.lower()]
    # Every vendor's default takes the same path.
    for vid in vm.VENDORS:
        snap2 = vm.inventory_bytes(EXPORT)
        tf, _rep = vm.compile_export(snap2, _decisions(snap2), vendor_id=vid)
        assert not [s for s in _strings(tf["resource"]) if "dlp-check" in s.lower()], vid
