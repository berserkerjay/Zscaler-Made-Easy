"""C6 QA: the migration slice. vendor_migrate (another vendor's DLP export,
untrusted), rule_migrator (the Evaluate All Rules wizard) and dlp_importer
(the pack helpers both share). Every test runs offline against fakes: no
tenant, no network, no clock, no files left in the repository."""
from __future__ import annotations

import base64
import io
import json
import os
import stat
import zipfile
from typing import Any, Dict, List, Optional, Tuple

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv
import dlp_importer as di
import rule_migrator as rm
import security
import vendor_migrate as vm

EXPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<policyExport><policy id="sym-101" name="PCI upload block">
  <detectionRules><keyword>account</keyword><keyword>cardholder</keyword><regex>acct[0-9]{6}</regex><keyword>pan</keyword>
  <protocol>HTTPS</protocol><minMatches>3</minMatches></detectionRules></policy></policyExport>"""


def _decisions(snapshot: Dict[str, Any], **over: Any) -> Dict[str, Any]:
    d = {"source_sha256": snapshot["sha256"],
         "dictionaries": [{"id": "ctx", "name": "CUSTOMER_CONTEXT", "approved": True, "phrases": ["customer", "cardholder"], "patterns": ["acct[0-9]{6}"]}],
         "engines": [{"id": "eng", "name": "PCI_CONTEXT", "approved": True, "zia_expression": "((D{{dict:ctx}}.S > 2))"}],
         "policies": [{"source_id": "sym-101", "channel": "web", "approved": True, "scope_acknowledged_any": True, "action": "BLOCK", "order": 1, "engine_refs": ["eng"]}]}
    for k, v in over.items():
        d[k] = v
    return d


def _snap() -> Dict[str, Any]:
    return vm.inventory_bytes(EXPORT, "export.xml")


def _questions(report: Dict[str, Any]) -> str:
    return " | ".join(q["reason"] for q in report["questions"])


def _upload(name: str, data: bytes) -> Dict[str, str]:
    return {"name": name, "content": base64.b64encode(data).decode("ascii"), "encoding": "base64"}


def _zip(files: Dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for n, b in files.items():
            z.writestr(n, b)
    return buf.getvalue()


def _page() -> TestClient:
    c = TestClient(srv.app, raise_server_exceptions=False)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


# ════════════════════════════════════════════════════════════════════
# dlp_importer: every imported regex is validated before it reaches ZIA
# ════════════════════════════════════════════════════════════════════
@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(\w+\s?)*$", r"([a-z]+)*@", r"(a*)*b", r"(x+x+)+y", r"(a|b+)+c", r"((ab)*)+z"])
def test_a_nested_unbounded_repeat_is_refused_as_redos(pattern):
    """ASVS V5.1.3 · A03:2021 · CWE-1333 · WSTG-INPV-01: a pattern that backtracks catastrophically is refused with the reason."""
    # Act
    problems = di.pattern_problems(pattern)
    # Assert
    assert len(problems) == 1 and "ReDoS" in problems[0]


@pytest.mark.parametrize("pattern", [r"(?:\.[A-Z][A-Za-z0-9]+)*", r"\b\d{3}-\d{2}-\d{4}\b", r"(\d{1,3}\.){3}\d{1,3}", r"^(\s*,\s*\w+)*$",
                                     r"(\w+\s)+", r"(?m)^\s*\bpackage\b\s+[a-z]\w*(?:\.[a-z]\w*)*\s*;", r"\h+\d{4}", r"[[:digit:]]{4}"])
def test_safe_patterns_and_pcre_escapes_are_not_refused(pattern):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a fixed separator between repeats, bounded repeats and PCRE-only escapes pass (no false refusal)."""
    assert di.pattern_problems(pattern) == []


@pytest.mark.parametrize("pattern", ["([a-z", "*abc", "a{2,1}", "(?P<x>a)(?P<x>b)"])
def test_a_pattern_that_is_not_a_regex_is_refused(pattern):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a pattern that does not parse is refused in words, never sent to ZIA."""
    problems = di.pattern_problems(pattern)
    assert len(problems) == 1 and "not a valid regular expression" in problems[0]


@pytest.mark.parametrize("pattern", ["", None, 7])
def test_an_empty_or_non_text_pattern_is_refused(pattern):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a pattern of the wrong type is a problem, not a crash."""
    assert di.pattern_problems(pattern) == ["pattern must be non-empty text"]


def test_a_dictionary_whose_patterns_are_not_a_list_is_refused():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: patterns given as one string are refused, never read character by character."""
    assert di.dictionary_limit_problems({"name": "X", "patterns": "(a+)+"}) == ["patterns and phrases must each be a list"]


def test_a_redos_pattern_in_a_pack_dictionary_is_a_limit_problem():
    """ASVS V5.1.3 · CWE-1333 · WSTG-INPV-01: dictionary_limit_problems (the pack deploy's check) carries the ReDoS refusal."""
    problems = di.dictionary_limit_problems({"name": "X", "patterns": [{"pattern": r"(\d+)*$", "action": "PATTERN_COUNT_TYPE_UNIQUE"}]})
    assert any("ReDoS" in p for p in problems)


def test_an_engine_count_of_thousands_of_digits_is_a_problem_not_a_crash():
    """ASVS V5.1.4 · CWE-400 · CWE-755 · WSTG-INPV-01: a count past Python's int-parsing limit is refused in words."""
    # Arrange
    expr = "((D:Names > " + "9" * 5000 + "))"
    # Act
    problems = di.engine_limit_problems(expr)
    # Assert
    assert len(problems) == 1 and "under 1000" in problems[0] and len(problems[0]) < 120


@pytest.mark.parametrize("expr,bad", [("D:x > 999", False), ("D:x > 1000", True), ("D:x > 0999", False), ("D:x >= 00001000", True), ("", False), (None, False)])
def test_engine_count_boundaries(expr, bad):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: counts up to 999 pass, 1000 and above are refused (leading zeros read as the number)."""
    assert bool(di.engine_limit_problems(expr)) is bad


def _pack(tmp_path, files: Dict[str, Any]) -> str:
    d = tmp_path / "broken_pack" / "configs"
    d.mkdir(parents=True)
    for name, content in files.items():
        (d / name).write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    return str(tmp_path / "broken_pack")


@pytest.mark.parametrize("content", ["{not json", {"a": 1}, ["x", "y"], "[" * 5000])
def test_one_broken_pack_is_listed_with_its_reason_and_does_not_break_discovery(tmp_path, monkeypatch, content):
    """ASVS V7.4.1 · CWE-755 · CWE-20 · WSTG-ERRH-01: a pack file that is not a list of objects is listed with its error, not a 500 for every page."""
    # Arrange
    _pack(tmp_path, {"dlp_policies.json": content})
    monkeypatch.setattr("pack_library.user_packs_dir", lambda root=None: str(tmp_path / "none"))
    # Act
    packs = di.discover_packs(str(tmp_path))
    # Assert
    assert [p["id"] for p in packs] == ["broken_pack"]
    assert "dlp_policies.json" in packs[0]["error"] and packs[0]["policies"] == 0


def test_the_pack_detail_of_a_broken_pack_says_why(tmp_path):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the pack summary of an unreadable pack carries the reason and no items."""
    pack = _pack(tmp_path, {"dlp_dictionaries.json": {"a": 1}, "dlp_engines.json": [{"expression": "D:x"}]})
    out = di.load_pack_contents(pack)
    assert "must be a JSON list of objects" in out["error"] and out["dictionaries"]["total"] == 0


def test_the_pack_detail_tolerates_a_definition_without_a_name(tmp_path):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a definition missing its name is summarised, not a KeyError."""
    pack = _pack(tmp_path, {"dlp_engines.json": [{"expression": "D:x"}], "dlp_policies.json": [{"action": "ALLOW", "sub_rules": "x"}]})
    out = di.load_pack_contents(pack)
    assert out["engines"]["items"] == [{"name": None}] and out["metadata"]["policies"] == 1


def _custom(**over: Any) -> Dict[str, Any]:
    d = {"name": "CTX", "custom_phrase_match_type": "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE",
         "patterns": [{"action": "PATTERN_COUNT_TYPE_UNIQUE", "pattern": r"\d{6}"}], "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "account"}]}
    d.update(over)
    return d


def test_a_proximity_written_as_text_is_sent_as_a_number():
    """ASVS V5.1.4 · CWE-20 · CWE-704 · WSTG-INPV-01: proximity "50" from a pack file becomes 50, not a TypeError."""
    kwargs, err = di.build_dict_kwargs(_custom(proximity="50"), {})
    assert err is None and kwargs["proximity"] == 50 and kwargs["proximity_enabled_for_custom_dictionary"] is True


def test_a_pattern_without_an_action_is_refused_in_words():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a pattern entry missing its action is a refusal, not a KeyError."""
    kwargs, err = di.build_dict_kwargs(_custom(patterns=[{"pattern": r"\d{6}"}]), {})
    assert kwargs is None and "action" in err


def test_a_clone_template_id_that_is_not_a_number_is_refused_in_words():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a clone's dict_template_id "abc" is refused, not int("abc")."""
    kwargs, err = di.build_dict_kwargs({"name": "C", "predefined_clone": True, "dict_template_id": "abc"}, {"SSN": 3})
    assert kwargs is None and "not a number" in err


@pytest.mark.parametrize("action", ["BLOCK", "block ", "Confirm", "QUARANTINE", "ICAP_RESPONSE", None, 7, "ALLOW"])
def test_every_pack_web_rule_is_created_disabled_and_monitor_only(action):
    """ASVS V1.4.4 · A04:2021 · CWE-1188 · WSTG-BUSL-01: whatever action the pack names, the rule is created DISABLED with ALLOW."""
    payload = di.build_policy_payload({"name": "R", "action": action}, [1])
    assert payload["state"] == "DISABLED" and payload["action"] == "ALLOW"


@pytest.mark.parametrize("call", [lambda: di.name_problems(123), lambda: di.fit_description(5), lambda: di.name_problems(None)])
def test_name_and_description_helpers_accept_any_type(call):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a non-text name or description is read as text, never an AttributeError."""
    assert isinstance(call(), (list, str))


@pytest.mark.parametrize("text,limit,want", [("é" * 200, 255, 255), ("abc", 255, 3), ("x" * 300, 10, 10)])
def test_descriptions_fit_in_utf8_bytes(text, limit, want):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a description is cut to ZIA's limit counted in UTF-8 bytes."""
    assert len(di.fit_description(text, "", limit).encode("utf-8")) <= want


# ════════════════════════════════════════════════════════════════════
# vendor_migrate: compile validates what reaches ZIA
# ════════════════════════════════════════════════════════════════════
def test_a_clean_migration_compiles_disabled():
    """ASVS V1.4.4 · A04:2021 · CWE-1188 · WSTG-BUSL-01: the baseline decisions compile ready, every rule DISABLED (regression)."""
    tf, report = vm.compile_export(_snap(), _decisions(_snap()))
    assert report["ready"] and tf["resource"]["zia_dlp_web_rules"]["sym_sym_101"]["state"] == "DISABLED"


@pytest.mark.parametrize("pattern,word", [(r"(a+)+$", "ReDoS"), (r"([0-9]", "not a valid regular expression"), (r"(?<=x)\d{6}", "lookaround")])
def test_an_imported_regex_is_validated_before_it_reaches_zia(pattern, word):
    """ASVS V5.1.3 · A03:2021 · CWE-1333 · WSTG-INPV-01: a ReDoS, invalid or lookaround pattern in the decisions blocks the run."""
    # Arrange
    s = _snap()
    d = _decisions(s, dictionaries=[{"id": "ctx", "name": "CTX", "approved": True, "phrases": ["customer"], "patterns": [pattern]}])
    # Act
    tf, report = vm.compile_export(s, d)
    # Assert
    assert not report["ready"] and word in _questions(report) and "zia_dlp_dictionaries" not in tf["resource"]


@pytest.mark.parametrize("phrase", ["ab", "é" * 65])
def test_phrase_limits_are_counted_in_utf8_bytes(phrase):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a 2-byte or 130-byte phrase is refused at compile, not by ZIA at apply."""
    s = _snap()
    tf, report = vm.compile_export(s, _decisions(s, dictionaries=[{"id": "ctx", "name": "CTX", "approved": True, "phrases": [phrase]}]))
    assert not report["ready"] and "3-128 bytes" in _questions(report)


@pytest.mark.parametrize("name", ["HIPAA / Low", "ctx;drop", "名前"])
def test_object_names_zia_refuses_block_the_run(name):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a dictionary or engine name with characters ZIA refuses is a question, not a failed apply."""
    s = _snap()
    _tf, r1 = vm.compile_export(s, _decisions(s, dictionaries=[{"id": "ctx", "name": name, "approved": True, "phrases": ["customer"]}]))
    _tf, r2 = vm.compile_export(s, _decisions(s, engines=[{"id": "eng", "name": name, "approved": True, "zia_expression": "((D{{dict:ctx}}.S > 2))"}]))
    assert "Dictionary refused" in _questions(r1) and "Engine refused" in _questions(r2)


def test_an_engine_count_of_1000_blocks_the_run():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: an engine threshold ZIA refuses (>= 1000) blocks the run."""
    s = _snap()
    _tf, report = vm.compile_export(s, _decisions(s, engines=[{"id": "eng", "name": "E", "approved": True, "zia_expression": "((D{{dict:ctx}}.S > 1000))"}]))
    assert not report["ready"] and "under 1000" in _questions(report)


@pytest.mark.parametrize("key,value", [("policies", "x"), ("policies", ["x"]), ("dictionaries", [1]), ("engines", {"a": 1}), ("dictionaries", "abc")])
def test_decisions_of_the_wrong_type_are_refused_in_words(key, value):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: decisions whose lists are not lists of objects are a ValueError, never an AttributeError."""
    s = _snap()
    with pytest.raises(ValueError, match=f"{key} must be a list of objects"):
        vm.compile_export(s, _decisions(s, **{key: value}))


def test_the_compile_api_answers_400_for_decisions_of_the_wrong_type():
    """ASVS V7.4.1 · CWE-209 · CWE-755 · WSTG-ERRH-01: the page's compile call answers 400 in words, not a 500."""
    body = {"vendor": "symantec", "export": _upload("export.xml", EXPORT), "decisions": {"policies": [1, 2]}}
    r = _page().post("/api/vendor-migrate/compile", json=body, headers={"Origin": "http://127.0.0.1:8000"})
    assert r.status_code == 400 and "list of objects" in r.json()["detail"]


@pytest.mark.parametrize("field,value", [("target_name", "Rule\nname"), ("target_name", "Rule\x00")])
def test_a_rule_name_with_control_characters_is_refused(field, value):
    """ASVS V5.3.1 · A03:2021 · CWE-74 · WSTG-INPV-01: a line break in a rule name (it lands in HCL strings) blocks the rule."""
    s = _snap()
    pol = dict(_decisions(s)["policies"][0], **{field: value})
    _tf, report = vm.compile_export(s, _decisions(s, policies=[pol]))
    assert not report["ready"] and "control characters" in _questions(report)


def test_a_tenant_name_with_a_line_break_is_refused():
    """ASVS V5.3.1 · CWE-74 · WSTG-INPV-01: an email tenant name with a newline is not written into a Terraform data block."""
    s = _snap()
    pol = dict(_decisions(s)["policies"][0], channel="email", action="BLOCK", tenants=["corp\nmail"])
    tf, report = vm.compile_export(s, _decisions(s, policies=[pol]))
    assert not report["ready"] and "zia_casb_tenant" not in (tf.get("data") or {})


def test_terraform_interpolation_in_reviewed_text_is_escaped():
    """ASVS V5.3.1 · A03:2021 · CWE-94 · WSTG-INPV-11: ${ and %{ in a phrase reach Terraform as text, and in an engine expression block it."""
    s = _snap()
    d = _decisions(s, dictionaries=[{"id": "ctx", "name": "CTX", "approved": True, "phrases": ['${file("/etc/passwd")}', "%{ if true }x"]}])
    tf, report = vm.compile_export(s, d)
    phrases = [p["phrase"] for p in tf["resource"]["zia_dlp_dictionaries"]["ctx"]["phrases"]]
    assert report["ready"] and phrases == ['$${file("/etc/passwd")}', "%%{ if true }x"]
    _tf, r2 = vm.compile_export(s, _decisions(s, engines=[{"id": "eng", "name": "E", "approved": True, "zia_expression": "%{ for x in y }((D{{dict:ctx}}.S > 1))"}]))
    assert "unsafe interpolation" in _questions(r2)


def test_rule_orders_are_carried_exactly_as_decided():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: each generated rule keeps the order its decision gives; a gap is refused."""
    xml = b"<x>" + b"".join(b'<policy id="p%d" name="P%d"/>' % (i, i) for i in (1, 2, 3)) + b"</x>"
    s = vm.inventory_bytes(xml)
    base = _decisions(s)["policies"][0]
    pols = [dict(base, source_id=f"p{i}", order=o) for i, o in ((1, 3), (2, 1), (3, 2))]
    tf, report = vm.compile_export(s, _decisions(s, policies=pols))
    rules = tf["resource"]["zia_dlp_web_rules"]
    assert report["ready"] and {k: v["order"] for k, v in rules.items()} == {"sym_p1": 3, "sym_p2": 1, "sym_p3": 2}
    with pytest.raises(ValueError, match="contiguous"):
        vm.compile_export(s, _decisions(s, policies=[dict(p, order=p["order"] * 2) for p in pols]))


# ── Mapping oracles ────────────────────────────────────────────────
@pytest.mark.parametrize("text,kind", [
    ("HTTPS", "web"), ("Uploads", "web"), ("Webmail", "web"), ("Form post", "web"), ("SharePoint sharing", "web"),
    ("SMTP relay", "email"), ("Gmail", "email"), ("E-mail", "email"),
    ("Removable media", "endpoint"), ("Printing", "endpoint"), ("USB", "endpoint"), ("Network share", "endpoint"),
    ("API-enabled protection", "saas-api"), ("Box (API)", "saas-api"), ("cloud storage at rest", "saas-api"),
    ("Downloads", "cloud-download"), ("Preview", "cloud-download"), ("SFTP", "ftp"), ("FTP", "ftp"),
    ("Capital One", "other"), ("Fingerprint", "other"), ("Atlanta office", "other"), ("Information", "other"), ("Rapid7", "other"),
])
def test_channel_words_oracle(text, kind):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a source channel lands on the documented ZIA channel by whole word, never by substring."""
    assert vm._channel_kind(vm._norm_channel(text)) == kind


@pytest.mark.parametrize("tag,facet", [
    ("contentMatchesDataIdentifier", "data_identifiers"), ("keyword", "content_patterns"), ("regularExpression", "content_patterns"),
    ("minMatches", "match_thresholds"), ("edmProfile", "edm"), ("indexedDocumentProfile", "idm"), ("vmlProfile", "ml"),
    ("attachmentFileType", "file_conditions"), ("protocol", "channel"), ("recipient", "identity_scope"),
    ("exception", "exceptions"), ("responseRule", "response_action"), ("severity", "severity"), ("foo", None),
])
def test_symantec_element_names_map_to_facets(tag, facet):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: each Symantec element name is read as the detection facet it documents."""
    assert vm._facet_of(tag) == facet


@pytest.mark.parametrize("classifier,facet", [
    ({"classifier_type": "Database Fingerprint"}, "edm"), ({"classifier_type": "File Fingerprint"}, "idm"),
    ({"classifier_type": "Machine Learning"}, "ml"), ({"classifier_type": "File Properties"}, "file_conditions"),
    ({"classifier_type": "Script", "predefined": False}, "data_identifiers"), ({"predefined": True}, "data_identifiers"),
    ({"classifier_type": "Key Phrase"}, "content_patterns"), ({"classifier_type": "Regex"}, "content_patterns"),
    ({"predefined": False}, "content_patterns"), ({}, "data_identifiers"),
])
def test_forcepoint_classifiers_map_to_facets(classifier, facet):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: Forcepoint classifier types land on the documented facet."""
    assert vm._fp_classifier_facet(classifier) == facet


@pytest.mark.parametrize("cls,facet", [
    ({"type": "IDM"}, "idm"), ({"type": "EDM"}, "edm"), ({"type": "ML"}, "ml"), ({"type": "pre-canned"}, "data_identifiers"),
    ({"type": "keyword", "keywords": ["a"]}, "content_patterns"), ({"type": "advanced_pattern"}, "content_patterns"), ({"name": "x"}, "data_identifiers"),
])
def test_skyhigh_classifications_map_to_facets(cls, facet):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: Skyhigh classification types land on the documented facet."""
    assert vm._sky_class_facet(cls) == facet


@pytest.mark.parametrize("prefix,sid,channel,label", [
    ("sym", "sym-101", "web", "sym_sym_101"), ("fp", "7", "endpoint", "fp_7_endpoint"), ("nsk", "A B", "saas", "nsk_a_b_saas"), ("sky", "x", "email", "sky_x_email"),
])
def test_rule_labels_are_kept_as_earlier_versions_wrote_them(prefix, sid, channel, label):
    """ASVS V1.14.4 · CWE-694 · WSTG-CONF-01: a migrated rule keeps its Terraform address across versions (regression)."""
    assert vm.rule_label(prefix, sid, channel) == label


def test_the_content_pattern_share_is_dictionary_items_over_source_items():
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: 3 dictionary items for 4 source keyword/regex items score 75% on that facet."""
    s = _snap()
    _tf, report = vm.compile_export(s, _decisions(s))
    row = next(f for f in report["efficacy"]["policies"][0]["facets"] if f["facet"] == "content_patterns")
    assert row["score"] == 0.75 and row["basis"] == "computed"


# ── Untrusted export files ─────────────────────────────────────────
@pytest.mark.parametrize("encoding", ["utf-16", "utf-16-le", "utf-16-be"])
def test_a_dtd_is_refused_in_every_utf16_encoding(encoding):
    """ASVS V5.5.2 · A05:2021 · CWE-611 · CWE-776 · WSTG-INPV-07: a DOCTYPE written in UTF-16 (with or without BOM) is refused."""
    doc = ('<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE x [<!ENTITY a "aaaa">]><x><policy id="1" name="&a;"/></x>')
    data = doc.encode(encoding)
    if encoding != "utf-16":
        data = (b"\xff\xfe" if encoding.endswith("le") else b"\xfe\xff") + data
    with pytest.raises(ValueError):
        vm.inventory_bytes(data)


def test_a_dtd_inside_a_zip_member_is_refused():
    """ASVS V5.5.2 · CWE-611 · WSTG-INPV-07: a Skyhigh template member carrying a DTD is refused, zip or not."""
    doc = b'<?xml version="1.0"?><!DOCTYPE p SYSTEM "file:///etc/passwd"><policy name="x"><rule_groups/></policy>'
    with pytest.raises(ValueError, match="DTD"):
        vm.inventory_export("skyhigh", _zip({"t.xml": doc}), "templates.zip")


def test_a_latin1_declared_document_with_a_dtd_is_refused():
    """ASVS V5.5.2 · CWE-611 · WSTG-INPV-07: an encoding declaration does not hide a DOCTYPE."""
    doc = '<?xml version="1.0" encoding="ISO-8859-1"?><!doctype x><x/>'.encode("latin-1")
    with pytest.raises(ValueError, match="DTD"):
        vm.inventory_bytes(doc)


def test_deeply_nested_json_and_xml_are_refused_in_words():
    """ASVS V5.1.4 · CWE-400 · CWE-674 · WSTG-INPV-01: JSON or XML nested past the cap is a ValueError, not a RecursionError."""
    with pytest.raises(ValueError, match="nested"):
        vm.inventory_export("forcepoint", b"[" * 200 + b"]" * 200, "p.json")
    with pytest.raises(ValueError, match="nested"):
        vm.inventory_export("skyhigh", b"<a>" * 200 + b"</a>" * 200, "p.xml")


def test_a_zip_member_whose_crc_lies_is_refused_in_words():
    """ASVS V12.1.2 · CWE-409 · CWE-755 · WSTG-BUSL-09: a damaged archive member is a ValueError, not a BadZipFile 500."""
    data = bytearray(_zip({"p.json": b'{"policy_name": "A", "rules": []}'}))
    i = data.find(b"PK\x01\x02")   # the central directory's CRC for the member
    data[i + 16:i + 20] = b"\0\0\0\0"
    with pytest.raises(ValueError):
        vm.inventory_export("forcepoint", bytes(data), "p.zip")


def test_too_many_zip_members_are_refused(monkeypatch):
    """ASVS V12.1.2 · CWE-400 · WSTG-BUSL-09: an archive with more members than the cap is refused before any is read."""
    monkeypatch.setattr(vm, "ZIP_MEMBER_LIMIT", 3)
    with pytest.raises(ValueError, match="more than 3 files"):
        vm.inventory_export("netskope", _zip({f"d{i}.csv": b"k\n" for i in range(4)}), "n.zip")


def test_an_oversized_upload_is_refused_before_it_is_decoded(monkeypatch):
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-09: base64 text past the cap is refused from its length, without a decoded copy."""
    # Arrange
    monkeypatch.setattr(vm, "MAX_EXPORT_BYTES", 30)

    def no_decode(*_a, **_k):
        raise AssertionError("decoded before the size check")
    monkeypatch.setattr(vm.base64, "b64decode", no_decode)
    # Act / Assert
    with pytest.raises(ValueError, match="larger than"):
        vm.decode_upload({"name": "x.zip", "content": "A" * 5000, "encoding": "base64"})


@pytest.mark.parametrize("content", [["a"], {"a": 1}, 5])
def test_upload_content_of_the_wrong_type_is_refused(content):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: file content that is not text is refused, never stringified."""
    with pytest.raises(ValueError, match="must be text"):
        vm.decode_upload({"name": "x.xml", "content": content})


def test_policies_whose_names_slug_alike_are_told_apart():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: two id-less Netskope policies "PCI Upload" and "pci upload" both inventory, the first id unchanged."""
    csv = b"policy name,action,activities\nPCI Upload,Block,Upload\npci upload,Alert,Upload\n"
    snap = vm.inventory_export("netskope", csv, "policies.csv")
    assert sorted(p["id"] for p in snap["policies"]) == ["nsk-pci_upload", "nsk-pci_upload-2"]


def test_two_policies_carrying_the_same_id_are_still_refused():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: equal ids the export itself carries are refused (regression)."""
    data = json.dumps([{"policy_name": "A", "policy_id": "7", "rules": []}, {"policy_name": "B", "policy_id": "7", "rules": []}]).encode()
    with pytest.raises(ValueError, match="Duplicate policy IDs"):
        vm.inventory_export("forcepoint", data, "p.json")


def test_a_decisions_file_saved_with_a_byte_order_mark_is_read():
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: a decisions file written by Notepad (UTF-8 BOM) compiles."""
    s = _snap()
    raw = b"\xef\xbb\xbf" + json.dumps(_decisions(s)).encode("utf-8")
    out = vm.compile_upload("symantec", _upload("export.xml", EXPORT), _upload("decisions.json", raw))
    assert out["report"]["ready"] and out["terraform"] is not None


def test_a_decisions_file_too_large_is_said_as_such(monkeypatch):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a decisions upload past the cap is refused for its size, not called invalid JSON."""
    monkeypatch.setattr(vm, "MAX_EXPORT_BYTES", len(EXPORT) + 10)
    with pytest.raises(ValueError, match="larger than") as e:
        vm.compile_upload("symantec", _upload("export.xml", EXPORT), _upload("decisions.json", b" " * (len(EXPORT) + 500)))
    assert "not valid JSON" not in str(e.value)


# ── Command line: files owner-only, errors in words, no network ────
class _Resp:
    def __init__(self, data: bytes):
        self._d = data

    def read(self, n: int = -1) -> bytes:
        return self._d

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_a_fetched_export_is_created_owner_only_from_the_first_byte(tmp_path, monkeypatch):
    """ASVS V8.1.1 · A01:2021 · CWE-276 · CWE-367 · WSTG-CONF-11: the export file is opened 0600, never written wider and chmod-ed after."""
    # Arrange
    import urllib.request
    monkeypatch.setattr(urllib.request, "build_opener", lambda *_h: type("O", (), {"open": lambda self, req, timeout: _Resp(b"<x/>")})())
    modes: List[int] = []
    real_open = os.open

    def spy(path, flags, mode=0o777, *a, **k):
        if str(path).endswith("export.xml"):
            modes.append(mode)
        return real_open(path, flags, mode, *a, **k)
    monkeypatch.setattr(os, "open", spy)
    out = tmp_path / "sub" / "export.xml"
    # Act
    vm.fetch_export("https://enforce.example.test/export", "token", out)
    # Assert
    assert modes == [0o600] and stat.S_IMODE(out.stat().st_mode) == 0o600 and out.read_bytes() == b"<x/>"


@pytest.mark.parametrize("url,header,err", [("http://x.example.test/e", "Authorization: Bearer", "HTTPS"), ("https://x.example.test/e", "Bad Header\r\nX: y", "header name")])
def test_the_fetcher_refuses_plain_http_and_header_injection(tmp_path, url, header, err):
    """ASVS V9.2.1 · A10:2021 · CWE-918 · CWE-113 · WSTG-INPV-15: only HTTPS, and a header name cannot smuggle a second header."""
    with pytest.raises(ValueError, match=err):
        vm.fetch_export(url, "token", tmp_path / "e.xml", header=header)


def test_the_cli_writes_owner_only_files(tmp_path):
    """ASVS V8.1.1 · CWE-732 · WSTG-CONF-11: the inventory and decisions template (customer policy text) are 0600."""
    exp = tmp_path / "e.xml"
    exp.write_bytes(EXPORT)
    assert vm.main(["inventory", str(exp), "--out", str(tmp_path / "out")]) == 0
    for name in ("source-inventory.json", "decisions.template.json"):
        assert stat.S_IMODE((tmp_path / "out" / name).stat().st_mode) == 0o600


def test_the_cli_answers_a_too_deep_decisions_file_in_words(tmp_path, capsys):
    """ASVS V7.4.1 · CWE-674 · CWE-209 · WSTG-ERRH-01: a decisions file nested 100 000 deep is "ERROR: ...", exit 1, no traceback."""
    exp, dec = tmp_path / "e.xml", tmp_path / "d.json"
    exp.write_bytes(EXPORT)
    dec.write_text("[" * 100000 + "]" * 100000)
    assert vm.main(["compile", str(exp), "--decisions", str(dec), "--out", str(tmp_path / "o")]) == 1
    assert "nested" in capsys.readouterr().err


# ════════════════════════════════════════════════════════════════════
# rule_migrator: the Evaluate All Rules wizard
# ════════════════════════════════════════════════════════════════════
class FakeZia:
    """An in-memory ZIA: Web DLP rules, settings objects and /status, with
    every call recorded. PUT on a settings object replaces it (as ZIA does)."""

    def __init__(self, rules: List[Dict[str, Any]], settings: Optional[Dict[str, Dict[str, Any]]] = None, shuffle: bool = False):
        self.rules = {r["id"]: dict(r) for r in rules}
        self.settings = {k: dict(v) for k, v in (settings or {}).items()}
        self.calls: List[Tuple[str, str, Any]] = []
        self.shuffle = shuffle
        self.next_id = 1000
        self._c: Dict[str, Any] = {}

    def get(self, path):
        self.calls.append(("GET", path, None))
        if path == "/zia/webDlpRules":
            rows = sorted(self.rules.values(), key=lambda r: r.get("order", 0))
            return ([dict(r) for r in (rows[::-1] if self.shuffle else rows)], 200)
        if path in self.settings:
            return dict(self.settings[path]), 200
        if path == "/zia/status":
            return {"status": "ACTIVE"}, 200
        return None, 404

    def put(self, path, body):
        self.calls.append(("PUT", path, dict(body)))
        if path.startswith("/zia/webDlpRules/"):
            rid = int(path.rsplit("/", 1)[1])
            if rid not in self.rules:
                return {"error": "not found"}, 404
            self.rules[rid] = dict(body)
            return body, 200
        if path in self.settings:
            self.settings[path] = dict(body)
            return body, 200
        return None, 404

    def post(self, path, body):
        self.calls.append(("POST", path, dict(body)))
        if path == "/zia/webDlpRules":
            self.next_id += 1
            self.rules[self.next_id] = dict(body, id=self.next_id)
            return {"id": self.next_id}, 200
        return {}, 200

    def delete(self, path):
        self.calls.append(("DELETE", path, None))
        self.rules.pop(int(path.rsplit("/", 1)[1]), None)
        return None, 204

    def writes(self):
        return [c for c in self.calls if c[0] != "GET"]

    def policy(self):
        return [(r["name"], r["action"], r["state"], r["order"]) for r in sorted(self.rules.values(), key=lambda r: r["order"])]


RULES = [{"id": 11, "name": "Allow HR", "action": "ALLOW", "state": "ENABLED", "order": 1, "groups": [1]},
         {"id": 12, "name": "Block PCI", "action": "BLOCK", "state": "ENABLED", "order": 2, "dlpEngines": [{"id": 5}]},
         {"id": 13, "name": "Confirm PII", "action": "CONFIRM", "state": "ENABLED", "order": 3},
         {"id": 14, "name": "Old", "action": "BLOCK", "state": "DISABLED", "order": 4}]


@pytest.fixture
def writes_on(monkeypatch):
    monkeypatch.setattr(security, "writes_enabled", lambda: True)
    monkeypatch.setattr(rm, "_sleep", lambda s: None)


def test_duplicate_rule_names_are_counted():
    """ASVS V1.4.4 · CWE-682 · WSTG-BUSL-01: two rules named alike count as one duplicate name (it read 0 whatever the rules)."""
    out = rm.analyze_rules([{"id": 1, "name": "A"}, {"id": 2, "name": "A"}, {"id": 3, "name": "B"}])
    assert out["duplicate_names"] == 1 and sum(1 for i in out["issues"] if i["type"] == "Duplicate Name") == 1


def test_analysis_of_rules_with_fields_of_the_wrong_type_does_not_crash():
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: an uploaded rule with numbers and objects where text is expected is analysed."""
    rules = [{"id": 1, "name": 5, "action": 7, "state": None, "users": 3, "urlCategories": "NEWS", "dlpEngines": [{"id": [1]}, {"id": [1]}]},
             {"id": 2, "name": "B", "action": "block", "urlCategories": ["NEWS"]}]
    out = rm.analyze_rules(rules)
    plan = rm.generate_migration_plan(rules)
    assert out["total_rules"] == 2 and plan["proposed_order"][0]["id"] == 2


def test_reorder_follows_the_documented_action_tiers_and_keeps_disabled_last():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: Block, Quarantine, Confirm, Alert, Allow; disabled rules after, in their order."""
    names = ["allow", "alert", "confirm", "quarantine", "block"]
    rules = [{"id": i, "name": n, "action": n.upper()} for i, n in enumerate(names)] + [{"id": 9, "name": "off2", "state": "DISABLED"}, {"id": 8, "name": "off1", "state": "disabled"}]
    out = rm.reorder_for_eval_all(rules)
    assert [r["name"] for r in out] == ["block", "quarantine", "confirm", "alert", "allow", "off2", "off1"]


def test_rules_with_the_same_action_and_scope_keep_the_admins_order():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: ties are not re-sorted by name (order still matters between same-action rules)."""
    rules = [{"id": 1, "name": "zeta", "action": "BLOCK"}, {"id": 2, "name": "alpha", "action": "BLOCK"}, {"id": 3, "name": "mid", "action": "BLOCK"}]
    assert [r["id"] for r in rm.reorder_for_eval_all(rules)] == [1, 2, 3]


def test_the_plan_does_not_stamp_the_callers_rules():
    """ASVS V1.4.4 · CWE-471 · WSTG-BUSL-01: generating a plan leaves the rule list it was given unchanged."""
    rules = [dict(r) for r in RULES]
    rm.generate_migration_plan(rules)
    assert rules == RULES


def test_fetched_rules_are_in_zia_order_whatever_the_response_order():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: rules come back sorted by order, non-objects dropped, unnumbered rules last."""
    class C:
        def get(self, path):
            return [{"id": 3, "order": "3"}, "junk", {"id": 2, "order": 2}, {"id": 9}, {"id": 1, "order": 1}, {"id": 0, "order": True}], 200
    assert [r["id"] for r in rm.fetch_current_rules(C())] == [1, 2, 3, 9, 0]


@pytest.mark.parametrize("data", [{"list": [{"id": 1}]}, {"rules": [{"id": 1}]}, [{"id": 1}]])
def test_fetched_rules_are_read_from_every_documented_wrapper(data):
    """ASVS V1.4.4 · CWE-20 · WSTG-BUSL-01: a bare list or a list/rules wrapper are read alike; a non-200 is no rules."""
    class C:
        def __init__(self, code):
            self.code = code

        def get(self, path):
            return data, self.code
    assert rm.fetch_current_rules(C(200)) == [{"id": 1}] and rm.fetch_current_rules(C(403)) == []


def test_a_rule_kept_in_place_keeps_its_audit_only_conversion():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: skip_rule_ids keeps the converted copy, and the caller's rules are not changed."""
    rules = [{"id": 1, "name": "B", "action": "BLOCK"}, {"id": 2, "name": "A", "action": "ALLOW"}]
    out = rm.optimize_for_eval_all_with_exceptions(rules, {"audit_only_actions": ["BLOCK"], "skip_rule_ids": ["1"]})
    kept = next(r for r in out["proposed_rules"] if r["id"] == 1)
    assert kept["action"] == "ALERT" and out["conversion_count"] == 1 and rules == [{"id": 1, "name": "B", "action": "BLOCK"}, {"id": 2, "name": "A", "action": "ALLOW"}]


@pytest.mark.parametrize("exceptions", [{"pinned": {"rule_id": "1", "position": "top"}}, {"pinned": "1"}, {"audit_only_actions": "BLOCK"},
                                        {"skip_rule_ids": 5}, ["not", "a", "dict"], {"pinned": {"rule_id": "2", "position": 10 ** 30}}])
def test_exceptions_of_the_wrong_type_do_not_crash_the_optimiser(exceptions):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: malformed exceptions are ignored or applied, never a 500."""
    out = rm.optimize_for_eval_all_with_exceptions([dict(r) for r in RULES], exceptions)
    assert sorted(r["id"] for r in out["proposed_rules"]) == [11, 12, 13, 14]


def test_a_pinned_rule_goes_to_its_position():
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: pinned {rule_id, position} moves that rule to the position asked."""
    out = rm.optimize_for_eval_all_with_exceptions([dict(r) for r in RULES], {"pinned": {"rule_id": 11, "position": "1"}})
    assert out["proposed_rules"][0]["id"] == 11 and [r["_proposed_order"] for r in out["proposed_rules"]] == [1, 2, 3, 4]


@pytest.mark.parametrize("step", [
    lambda c: rm.post_new_rule_order(c, [dict(r) for r in RULES], dry_run=True, mode="update"),
    lambda c: rm.post_new_rule_order(c, [dict(r) for r in RULES], dry_run=True, mode="create"),
    lambda c: rm.delete_all_rules(c, dry_run=True),
    lambda c: rm.enable_evaluate_all_rules(c, dry_run=True),
    lambda c: rm.import_rules_to_zscaler(c, RULES, dry_run=True),
])
def test_a_dry_run_never_writes(writes_on, step):
    """ASVS V1.4.4 · A04:2021 · CWE-841 · WSTG-BUSL-01: with writes enabled, every dry run issues only GETs."""
    c = FakeZia(RULES, {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}})
    out = step(c)
    assert out["status"] == "dry_run" and c.writes() == []


@pytest.mark.parametrize("step", [
    lambda c: rm.post_new_rule_order(c, [dict(r) for r in RULES], dry_run=False, mode="update"),
    lambda c: rm.delete_all_rules(c, dry_run=False),
    lambda c: rm.enable_evaluate_all_rules(c, dry_run=False),
    lambda c: rm.import_rules_to_zscaler(c, RULES, dry_run=False),
])
def test_a_real_run_is_blocked_while_writes_are_off(monkeypatch, step):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · WSTG-ATHZ-02: the module's own gate refuses a write when write mode is off (defence in depth)."""
    monkeypatch.setattr(security, "writes_enabled", lambda: False)
    c = FakeZia(RULES, {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}})
    assert step(c)["status"] == "blocked" and c.writes() == []


@pytest.mark.parametrize("mode", ["delete", "UPDATE", "", None])
def test_an_unknown_post_mode_is_refused_without_writing(writes_on, mode):
    """ASVS V4.1.5 · CWE-841 · CWE-20 · WSTG-BUSL-01: a mode other than auto/create/update is refused, never read as update."""
    c = FakeZia(RULES)
    out = rm.post_new_rule_order(c, [dict(r) for r in RULES], dry_run=False, mode=mode)
    assert out["status"] == "refused" and c.calls == []


@pytest.mark.parametrize("rid", ["1/../../adminUsers/9", "12?x=1", -3, 1.5, True, "", "9" * 30])
def test_a_rule_id_cannot_steer_the_put_path(writes_on, rid):
    """ASVS V5.1.3 · A01:2021 · CWE-22 · CWE-918 · WSTG-ATHZ-01: an id that is not a whole number is never written into the request path."""
    c = FakeZia(RULES)
    out = rm.post_new_rule_order(c, [{"id": rid, "name": "X", "action": "ALLOW"}], dry_run=False, mode="update")
    assert c.writes() == [] and out["failed_count"] == 1 and "not a ZIA rule id" in out["failed"][0]["error"]
    assert "problem" in rm.post_new_rule_order(c, [{"id": rid, "name": "X"}], dry_run=True, mode="update")["planned_updates"][0]


def test_a_numeric_text_rule_id_is_put_as_its_number(writes_on):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: id "12" from a JSON backup updates rule 12."""
    c = FakeZia(RULES)
    out = rm.post_new_rule_order(c, [dict(RULES[1], id="12")], dry_run=False, mode="update")
    assert out["succeeded_count"] == 1 and c.writes()[0][:2] == ("PUT", "/zia/webDlpRules/12")


def test_posting_sends_each_rule_with_its_proposed_position(writes_on):
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: rule order is preserved: the n-th proposed rule is sent with order n, internal fields stripped."""
    c = FakeZia(RULES)
    proposed = rm.reorder_for_eval_all([dict(r) for r in RULES])
    rm.post_new_rule_order(c, proposed, dry_run=False, mode="update")
    sent = [(p, b["order"], any(k.startswith("_") for k in b)) for _m, p, b in c.writes()]
    assert sent == [("/zia/webDlpRules/12", 1, False), ("/zia/webDlpRules/13", 2, False), ("/zia/webDlpRules/11", 3, False), ("/zia/webDlpRules/14", 4, False)]


def test_undo_after_a_reorder_restores_the_original_order(writes_on):
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: posting the Step 2 backup back restores every rule's order, even when ZIA lists rules out of order."""
    # Arrange
    c = FakeZia(RULES, shuffle=True)
    original = c.policy()
    backup = rm.fetch_current_rules(c)
    rm.post_new_rule_order(c, rm.reorder_for_eval_all([dict(r) for r in backup]), dry_run=False, mode="update")
    assert c.policy() != original
    # Act
    rm.post_new_rule_order(c, backup, dry_run=False, mode="update")
    # Assert
    assert c.policy() == original


def test_delete_all_hands_back_the_backup_and_posting_it_undoes_the_delete(writes_on):
    """ASVS V1.4.4 · CWE-840 · WSTG-BUSL-01: delete-all returns every deleted rule; posting it (create) re-creates the policy as it was."""
    # Arrange
    c = FakeZia(RULES, shuffle=True)
    original = c.policy()
    # Act
    out = rm.delete_all_rules(c, dry_run=False)
    assert out["deleted_count"] == 4 and c.rules == {}
    rm.post_new_rule_order(c, out["backup"], dry_run=False, mode="create")
    # Assert
    assert c.policy() == original and out["activation"]["status"] == "ACTIVE"


def test_delete_all_never_writes_a_malformed_id_into_the_path(writes_on):
    """ASVS V5.1.3 · CWE-22 · WSTG-ATHZ-01: a tenant row whose id is not a number is reported, not deleted by path."""
    class C(FakeZia):
        def get(self, path):
            if path == "/zia/webDlpRules":
                self.calls.append(("GET", path, None))
                return [{"id": "../users/1", "name": "x", "order": 1}, {"name": "noid", "order": 2}], 200
            return super().get(path)
    c = C([])
    out = rm.delete_all_rules(c, dry_run=False)
    assert [f["reason"] for f in out["failed"]] == ["not a ZIA rule id", "missing id"] and not [w for w in c.writes() if w[0] == "DELETE"]


def test_enable_uses_the_documented_setting_and_keeps_every_other_field(writes_on):
    """ASVS V1.4.4 · CWE-841 · WSTG-BUSL-01: GET /webDlpGlobalOptions, set enableEvaluateAllDlpRules, PUT the whole object back (SDK 1.11.3)."""
    c = FakeZia([], {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False, "enableInlineDlpOcr": True, "urlCategories": ["X"]}})
    out = rm.enable_evaluate_all_rules(c, dry_run=False)
    assert out["status"] == "activated" and c.settings["/zia/webDlpGlobalOptions"] == {"enableEvaluateAllDlpRules": True, "enableInlineDlpOcr": True, "urlCategories": ["X"]}
    assert [w[1] for w in c.writes()] == ["/zia/webDlpGlobalOptions"]


def test_enable_never_puts_a_minimal_body_that_would_reset_other_settings(writes_on):
    """ASVS V1.4.4 · A04:2021 · CWE-1188 · CWE-841 · WSTG-BUSL-01: no settings object is overwritten with a one-field body or a guessed key."""
    adv = {"enableOffice365": True, "authBypassUrls": ["a.example"], "dnsResolutionOnTransparentProxyExemptUrls": []}
    c = FakeZia([], {"/zia/advancedSettings": adv, "/zia/dlpSettings": {"x": 1}})
    out = rm.enable_evaluate_all_rules(c, dry_run=False)
    assert out["status"] == "failed" and c.writes() == [] and c.settings["/zia/advancedSettings"] == adv


def test_a_boolean_setting_is_never_sent_an_enum_word(writes_on):
    """ASVS V5.1.4 · CWE-704 · CWE-841 · WSTG-BUSL-01: a field the tenant holds as a boolean is written True, never "EVALUATE_ALL_RULES"."""
    c = FakeZia([], {"/zia/dlpSettings": {"dlpEvaluationMode": False, "other": 1}})
    out = rm.enable_evaluate_all_rules(c, dry_run=False)
    assert out["status"] == "activated" and [w[2]["dlpEvaluationMode"] for w in c.writes()] == [True]


def test_an_enum_setting_is_sent_the_enum_word(writes_on):
    """ASVS V1.4.4 · CWE-20 · WSTG-BUSL-01: a field held as text (BY_RULE_ORDER) is set to EVALUATE_ALL_RULES."""
    c = FakeZia([], {"/zia/dlpSettings": {"inlineDlpRuleEvaluation": "BY_RULE_ORDER"}})
    out = rm.enable_evaluate_all_rules(c, dry_run=False)
    assert out["status"] == "activated" and c.settings["/zia/dlpSettings"]["inlineDlpRuleEvaluation"] == "EVALUATE_ALL_RULES"


def test_enable_answers_already_enabled_without_writing(writes_on):
    """ASVS V1.4.4 · CWE-841 · WSTG-BUSL-01: idempotent: a tenant already in Evaluate All Rules is left alone."""
    c = FakeZia([], {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": True}})
    assert rm.enable_evaluate_all_rules(c, dry_run=False)["status"] == "already_enabled" and c.writes() == []


def test_waiting_for_activation_uses_the_injectable_sleep_and_a_bounded_poll(monkeypatch):
    """ASVS V11.1.4 · CWE-400 · CWE-835 · WSTG-BUSL-07: the activation wait never calls the real clock and stops after its polls."""
    # Arrange
    import time
    monkeypatch.setattr(time, "sleep", lambda s: (_ for _ in ()).throw(AssertionError("real sleep")))
    slept: List[float] = []
    monkeypatch.setattr(rm, "_sleep", slept.append)

    class C:
        def get(self, path):
            return {"status": "PENDING"}, 200
    # Act
    status = rm._wait_active_raw(C(), 9)
    # Assert
    assert status == "PENDING" and slept == [3, 3, 3]


def test_the_status_step_reads_the_documented_mode_setting():
    """ASVS V1.4.4 · CWE-20 · WSTG-BUSL-01: enableEvaluateAllDlpRules false on /webDlpGlobalOptions reads as Rule Order, ready to migrate."""
    c = FakeZia(RULES, {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}})
    out = rm.assess_current_status(c)
    assert out["current_mode"] == "Rule Order" and out["ready_to_migrate"] is True and out["rule_count"] == 4 and c.writes() == []


def test_a_capability_flag_is_not_read_as_the_mode():
    """ASVS V1.4.4 · CWE-20 · WSTG-BUSL-01: DLP_RULE_EVALUATE_ALL on /featureFlags says the feature exists, not that it is on."""
    c = FakeZia([], {"/zia/featureFlags": {"DLP_RULE_EVALUATE_ALL": True}})
    out = rm.assess_current_status(c)
    assert out["current_mode"] == "Unknown" and out["feature_available"] is True


def test_the_csv_export_neutralises_formulas_in_rule_names():
    """ASVS V5.3.10 · A03:2021 · CWE-1236 · WSTG-INPV-01: a tenant rule named =HYPERLINK(...) is exported as text."""
    import csv as _csv
    out = rm.export_rules([{"id": 1, "name": '=HYPERLINK("http://x.example","c")', "action": "+ALLOW", "urlCategories": ["@SUM(1)"]}], "csv")
    row = list(_csv.reader(io.StringIO(out)))[1]
    assert row[2].startswith("'=") and row[3].startswith("'+") and row[6].startswith("'@")


def test_the_json_export_drops_internal_fields():
    """ASVS V8.3.4 · CWE-200 · WSTG-INFO-05: the JSON backup carries the rules without the planner's _ fields."""
    out = json.loads(rm.export_rules([{"id": 1, "_proposed_order": 1, "_original_action": "BLOCK"}], "json"))
    assert out == {"rules": [{"id": 1}], "count": 1}


def test_a_failed_enable_puts_the_setting_back_as_it_was(writes_on):
    """ASVS V1.4.4 · A04:2021 · CWE-460 · CWE-841 · WSTG-BUSL-01: when no value takes effect, the settings object is restored, not left at the last value tried."""
    # Arrange: a tenant that accepts every PUT but normalises an unknown enum word to UNKNOWN
    class C(FakeZia):
        def put(self, path, body):
            body = dict(body)
            if body.get("inlineDlpRuleEvaluation") not in ("BY_RULE_ORDER",):
                body["inlineDlpRuleEvaluation"] = "UNKNOWN"
            return super().put(path, body)
    c = C([], {"/zia/dlpSettings": {"inlineDlpRuleEvaluation": "BY_RULE_ORDER", "other": 1}})
    # Act
    out = rm.enable_evaluate_all_rules(c, dry_run=False)
    # Assert
    assert out["status"] == "failed" and c.settings["/zia/dlpSettings"] == {"inlineDlpRuleEvaluation": "BY_RULE_ORDER", "other": 1}


def test_a_duplicate_id_in_a_large_export_is_refused_in_linear_time():
    """ASVS V11.1.4 · A04:2021 · CWE-407 · WSTG-BUSL-09: one duplicate among thousands of ids costs a linear number of comparisons, not one count per id."""
    # Arrange: ids that count every equality test made on them (deterministic, no clock)
    seen = [0]

    class Id(str):
        __hash__ = str.__hash__

        def __eq__(self, other):
            seen[0] += 1
            return str.__eq__(self, other)
    n = 2000
    policies = [{"id": Id(str(i))} for i in range(n)] + [{"id": Id("7")}]
    # Act
    with pytest.raises(ValueError, match="Duplicate policy IDs in export: 7"):
        vm._finish(policies, b"x", "p.json", "p.json", "policies")
    # Assert
    assert seen[0] < 10 * n


def test_duplicate_decisions_are_named_once_each():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a decisions file repeating one source/channel pair is refused, the pair named once."""
    s = _snap()
    pol = _decisions(s)["policies"][0]
    with pytest.raises(ValueError, match=r"Duplicate decision for the same source_id and channel: sym-101 \(web\)$"):
        vm.compile_export(s, _decisions(s, policies=[dict(pol) for _ in range(50)]))


@pytest.mark.parametrize("value,mode", [("BY_RULE_ORDER", "Rule Order"), ("EVALUATE_ALL_RULES", "Evaluate All Rules"), (False, "Rule Order"), (True, "Evaluate All Rules")])
def test_the_per_rule_mode_field_is_read_as_the_mode_words(value, mode):
    """ASVS V1.4.4 · CWE-697 · WSTG-BUSL-01: a per-rule dlpRuleEvaluation of BY_RULE_ORDER reads as Rule Order, not as a true value."""
    c = FakeZia([{"id": 1, "name": "R", "action": "BLOCK", "state": "ENABLED", "order": 1, "dlpRuleEvaluation": value}])
    assert rm.assess_current_status(c)["current_mode"] == mode
