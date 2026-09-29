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
    assert report["ready"] and report["counts"] == {"source_policies": 1, "converted_web_rules": 1, "blocked_policies_or_objects": 0, "dictionaries": 1, "engines": 1, "dispositions": 0}
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


def test_unapproved_retirement_and_unlisted_policies_block():
    snapshot = vm.inventory_bytes(EXPORT)
    d = _decisions(snapshot); d["policies"] = [{"source_id": "sym-101", "disposition": "retired"}]
    _tf, report = vm.compile_export(snapshot, d)
    assert not report["ready"] and "approval and a reason" in report["questions"][0]["reason"]
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


def test_the_vendor_registry_lists_the_planned_adapters_and_refuses_them():
    ids = [v["id"] for v in vm.vendors()]
    assert ids == ["symantec", "forcepoint", "netskope", "skyhigh"]
    assert vm.vendor("symantec")["status"] == "available"
    for planned in ("forcepoint", "netskope", "skyhigh"):
        with pytest.raises(ValueError, match="not built yet"):
            vm.vendor(planned)
    with pytest.raises(ValueError, match="Unknown vendor"):
        vm.vendor("mcafee")


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
    assert c.post("/api/vendor-migrate/inventory", json={"vendor": "netskope", "export": _upload("x.xml", EXPORT)}).status_code == 400
    assert "not built yet" in c.post("/api/vendor-migrate/inventory", json={"vendor": "netskope", "export": _upload("x.xml", EXPORT)}).json()["detail"]
    assert c.post("/api/vendor-migrate/inventory", json={"vendor": "symantec", "export": _upload("x.xml", b"<policyExport/>")}).status_code == 400
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
