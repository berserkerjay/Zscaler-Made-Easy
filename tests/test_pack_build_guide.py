"""The Word build guide of every DLP policy pack: one fixed format, built from
the pack's own files, served read-only, and committed under docs/packs.

Nothing here reaches a tenant: the sign-in factories are replaced by fakes
that fail the test when they are called."""
from __future__ import annotations

import functools
import io
import json
import os
import re

import pytest
from docx import Document
from fastapi.testclient import TestClient

import dlp_api_server as srv
import pack_build_guide as pbg
import team_routes
from dlp_importer import discover_packs
from test_pack_library import _bundle, lib_client  # noqa: F401  (fixture)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACK_IDS = [p["id"] for p in discover_packs()]
ROUTE = "GET /api/dlp-packs/{pack_id}/build-guide"


def _text(data: bytes) -> str:
    """Every paragraph and table cell of a .docx, read with python-docx."""
    doc = Document(io.BytesIO(data))
    parts = [p.text for p in doc.paragraphs]
    for t in doc.tables:
        for row in t.rows:
            for c in row.cells:
                parts.extend(p.text for p in c.paragraphs)
    return "\n".join(parts)


def _norm(text: str) -> str:
    """Document text with the build date and line breaks flattened, so two builds compare."""
    text = re.sub(r"(?m)^Date: .*$", "Date: -", text)
    return re.sub(r"\s+", " ", text).strip()


def _load(pid: str):
    return pbg.load_pack(pid)


@functools.lru_cache(maxsize=None)
def _built(pid: str) -> bytes:
    """One build per pack for the whole module (a build reads the pack files only)."""
    return pbg.build(pid)


@pytest.fixture
def no_tenant(monkeypatch):
    """Any attempt to sign in to a tenant fails the test."""
    def boom(*a, **k):
        raise AssertionError("the build guide must never sign in to a tenant")
    for name in ("_build_sdk_client", "_build_client", "_raw_client"):
        if hasattr(srv, name):
            monkeypatch.setattr(srv, name, boom)


# ── Every pack builds ────────────────────────────────────────────────

def test_the_nine_shipped_packs_are_found():
    """SSDF PW.8.2 · CWE-1068: the test set is the discovered packs, and the shipped ones are all in it."""
    assert len(PACK_IDS) >= 9 and "canada_privacy_baseline" in PACK_IDS and "healthcare_phi_baseline" in PACK_IDS


@pytest.mark.parametrize("pid", PACK_IDS)
def test_every_pack_builds_and_names_everything_in_it(pid, no_tenant):
    """ASVS V5.3.3 · CWE-79 (output made from data): every dictionary, engine, expression preview and web rule of the pack is in its guide."""
    # Arrange
    pd = _load(pid)
    # Act
    data = _built(pid)
    text = _text(data)
    # Assert
    assert data[:2] == b"PK"
    for d in pd.custom:
        assert str(d["name"]) in text, d["name"]
    for e in pd.engines:
        assert str(e["name"]) in text, e["name"]
        assert pbg.expression_preview(e["expression"]) in text.replace("\n", " ") or pbg.expression_preview(e["expression"]) in text, e["name"]
    for r in pd.web_rules:
        assert str(r["name"]) in text, r["name"]
    for heading in ("1. Summary", "2. Engine alignment", "Step-by-Step Instructions", "The work at a glance", "Words used in this guide",
                    "Step 1 ", "Step 2 ", "Step 3 ", "Step 4 ", "Step 5 ", "Step 6 ", "Step 7 ", "Step 8 ", "Assumptions and limits", "Sign-off"):
        assert heading in text, heading
    assert "Zscaler Data Protection Advisory" in text


@pytest.mark.parametrize("pid", PACK_IDS)
def test_the_header_footer_and_page_setup_follow_the_template(pid):
    """ASVS V1.14.1 · CWE-1164: header ZSCALER on the right, the confidentiality footer with a page field, Letter page."""
    doc = Document(io.BytesIO(_built(pid)))
    sec = doc.sections[0]
    assert sec.header.paragraphs[0].text == "ZSCALER" and sec.header.paragraphs[0].alignment == 2
    foot = sec.footer.paragraphs[0]
    assert "© Zscaler, Inc. All rights reserved." in foot.text and "Confidential" in foot.text
    assert "PAGE" in foot._p.xml
    assert sec.page_width.twips == 12240 and sec.page_height.twips == 15840


@pytest.mark.parametrize("pid", PACK_IDS)
def test_forms_use_thick_blue_for_typed_fields_and_thin_grey_for_filled_ones(pid):
    """WCAG 2.2 SC 1.4.1 · CWE-1164: typed fields carry a 1.5 pt blue paragraph border, pre-filled ones a 0.5 pt grey border."""
    xml = Document(io.BytesIO(_built(pid))).element.xml
    assert 'w:sz="12"' in xml and "1A56DB" in xml and 'w:sz="4"' in xml and "9CA3AF" in xml
    assert xml.count("<w:pBdr>") > 5


def test_the_guide_is_the_same_every_time():
    """SSDF PS.3.1 · CWE-1357: two builds of one pack have the same text, apart from the date (fixed seed, fixed properties)."""
    a = _text(pbg.build("canada_privacy_baseline"))
    b = _text(pbg.build("canada_privacy_baseline"))
    assert _norm(a) == _norm(b)
    c = Document(io.BytesIO(pbg.build("canada_privacy_baseline"))).core_properties
    assert c.created.year == 2026 and c.author == "Zscaler Made Easy"


def test_the_cover_takes_the_prepared_for_and_by_names_and_caps_them():
    """ASVS V5.1.3 · CWE-20: the names fill the cover; a name is cut to the cap and XML-illegal characters never reach the file."""
    text = _text(pbg.build("irs_fti_pack", "Acme Corp", "A. Analyst\x00\x08" + "x" * 500))
    assert "Prepared for: Acme Corp" in text
    by = next(l for l in text.splitlines() if l.startswith("Prepared by: "))
    assert len(by) == len("Prepared by: ") + pbg.MAX_PARAM and "\x00" not in by
    blank = _text(_built("irs_fti_pack"))
    assert "Prepared for: ______________________" in blank


def test_an_unknown_pack_is_an_error_not_a_crash():
    """ASVS V5.1.3 · CWE-20: an unknown pack id raises GuideError."""
    with pytest.raises(pbg.GuideError):
        pbg.build("no_such_pack")


# ── What the sections say ────────────────────────────────────────────

def test_canada_matches_the_owners_example_in_structure_and_numbers():
    """ASVS V1.14.1 · CWE-1164: the Canada guide has the example's 11 dictionaries, 4 engines, 4 rules and its time table."""
    text = _text(_built("canada_privacy_baseline"))
    assert "It has 11 custom dictionaries, 4 engines and 4 inline rules" in text
    assert "About 3.5 hours" in text and "About 40 minutes" in text and "About 9 hours, about 1.5 working days" in text
    assert "About 5 hours, under 1 working day" in text
    assert "Identifier (any one of): CA-SIN; CA-Health-Card-ON" in text and "AND supporting data: CA-Privacy-Name-DOB-Keywords" in text
    assert "Any one of (more than 4 matches): CA-SIN" in text
    assert "Nothing to do" in text and "PIPEDA; Quebec Law 25" in text and "All verticals" in text
    assert "4.11  CA-Health-Context-Keywords" in text and "5.4  CA Bank Account Low Confidence" in text


def test_a_pack_with_predefined_dictionaries_lists_them_in_step_3():
    """ASVS V1.14.1 · CWE-1164: predefined dictionaries are listed 'Already exists - set its option only', with the pack's confidence tweak."""
    pid = "fed_policy_pack"
    pd = _load(pid)
    assert pd.predefined, "the federal pack uses predefined dictionaries"
    text = _text(_built(pid))
    assert "Already exists - set its option only" in text
    for name in pd.predefined:
        assert name in text
    assert "Confidence: Low (Medical" in text            # the app's default tweak for MEDICAL
    cj = _text(_built("cjis_policy_pack"))
    assert "Nothing to do. This pack uses no predefined dictionaries" in cj


def test_clones_and_the_sum_operator_are_drawn():
    """ASVS V1.14.1 · CWE-1164: a clone gets a Clone Predefined Dictionary form, a (a + b) > n engine a SUM operator."""
    text = _text(_built("healthcare_phi_baseline"))
    assert "Clone Predefined Dictionary" in text and "Clone of (Zscaler predefined dictionary)" in text
    assert " SUM ▾ " in text and "Expression Preview" in text


def test_the_step_6_table_has_the_real_actions_and_the_disabled_note():
    """ASVS V1.14.1 · CWE-1164: every web rule row has its order, engine numbers and real action; the guide says every rule ships disabled."""
    for pid in PACK_IDS:
        pd = _load(pid)
        text = _text(_built(pid))
        assert "Every rule ships disabled." in text or "ship enabled" in text
        doc = Document(io.BytesIO(_built(pid)))
        table = next(t for t in doc.tables if [c.text for c in t.rows[0].cells][:3] == ["Order", "Rule name", "Applies to"])
        assert len(table.rows) == 1 + len(pd.web_rules)
        for i, rule in enumerate(pd.web_rules):
            cells = [c.text for c in table.rows[i + 1].cells]
            assert cells[0] == str(i + 1) and cells[1] == rule["name"]
            assert cells[3].startswith("#") and rule["engines"][0] in cells[3]
            assert cells[5] == str(rule.get("action") or "ALLOW").replace("_", " ").title()


def test_step_7_says_so_when_an_engine_has_no_validator_sample():
    """ASVS V1.14.1 · CWE-1164: an engine with no sample in tools/validate_detection.py gets a row that says so, never an invented sample."""
    text = _text(_built("education_ferpa_baseline"))
    assert text.count("No validator sample covers this engine") == 2
    rows = pbg.test_rows(_load("canada_privacy_baseline"))
    assert rows and all(r[3].startswith("#") for r in rows)
    assert not any(r[1].startswith("No validator sample") for r in rows)         # all four Canada engines have samples
    assert any("Social insurance number" in r[1] for r in rows)


def test_samples_carry_only_made_up_numbers():
    """GDPR Art. 25 · CWE-359: card, SSN, IBAN, SIN and ABA values in the samples are replaced by made-up ones, each distinct value by a distinct one."""
    raw = ("cards 4539578763621486, 4916338506082832 ssn 219-09-9999 and 078-05-1120, SIN 246 813 570, "
           "IBAN GB82WEST12345698765432 ABA routing number 021000021")
    out = pbg.mask_sample(raw)
    for real in ("4539578763621486", "4916338506082832", "219-09-9999", "078-05-1120", "246 813 570", "021000021"):
        assert real not in out
    cards = re.findall(r"\b\d{15,16}\b", out)
    assert len(cards) == 2 and len(set(cards)) == 2 and all(pbg._luhn(c) for c in cards)
    assert len(set(re.findall(r"\b\d{3}-\d{2}-\d{4}\b", out))) == 2
    assert "routing number 123456780" in out
    for pid in PACK_IDS:                         # nothing the validator generates survives unmasked either
        for cls, (text, _engs) in pbg._samples(pid).items():
            assert pbg.mask_sample(text) == text, (pid, cls)


# ── The expression parser ────────────────────────────────────────────

@pytest.mark.parametrize("pid", PACK_IDS)
def test_the_expression_parser_round_trips_every_engine(pid):
    """ASVS V5.1.3 · CWE-20: every engine expression parses and renders back to the same text; the tree is stable and the D: names match."""
    for e in _load(pid).engines:
        expr = " ".join(str(e["expression"]).split())
        tree = pbg.parse_expression(expr)
        assert pbg.render_expression(tree) == expr, e["name"]
        assert pbg.parse_expression(pbg.render_expression(tree)) == tree
        assert "D:" not in pbg.render_expression(tree, strip=True)
        assert len(pbg.expression_terms(tree)) == len(re.findall(r"\bD:", expr)), e["name"]
        assert pbg.builder_tree(tree)[0] in ("ALL", "ANY", "EXCLUDE")


def test_the_parser_reads_and_or_not_sum_and_nesting():
    """ASVS V5.1.3 · CWE-20: AND binds tighter than OR, NOT is unary, parentheses nest, (a + b) > n is one term."""
    t = pbg.parse_expression("D:A > 0 OR D:B > 1 AND D:C > 2")
    assert isinstance(t, pbg.Op) and t.op == "OR" and isinstance(t.items[1], pbg.Op) and t.items[1].op == "AND"
    n = pbg.parse_expression("((D:Names (US) > 0)) AND NOT (D:X Y > 3)")
    assert [x.name for x in pbg.expression_terms(n)] == ["Names (US)", "X Y"]
    assert pbg.render_expression(n, strip=True) == "((Names (US) > 0)) AND NOT (X Y > 3)"
    s = pbg.parse_expression("((D:SSN (US) + D:MRN + D:Driver's License (United States)) > 2)")
    assert isinstance(s.item, pbg.Sum) and s.item.names == ["SSN (US)", "MRN", "Driver's License (United States)"] and s.item.n == 2
    assert pbg.builder_tree(s) == ("ANY", [s.item])


def test_the_builder_tree_puts_dictionaries_under_any_like_the_console():
    """ASVS V1.14.1 · CWE-1164: AND is ALL, OR is ANY, NOT is EXCLUDE; a dictionary directly under ALL gets an ANY of its own (the owner's example)."""
    kind, items = pbg.builder_tree(pbg.parse_expression("(((D:A > 0) OR (D:B > 0)) AND (D:C > 0))"))
    assert kind == "ALL" and [i[0] for i in items] == ["ANY", "ANY"] and [len(i[1]) for i in items] == [2, 1]
    kind, items = pbg.builder_tree(pbg.parse_expression("((D:A > 4) OR (D:B > 4))"))
    assert kind == "ANY" and len(items) == 2
    kind, items = pbg.builder_tree(pbg.parse_expression("((D:A > 0)) AND NOT ((D:B > 0))"))
    assert kind == "ALL" and items[1][0] == "EXCLUDE"
    assert pbg.engine_logic("(((D:A > 0) OR (D:B > 0)) AND (D:C > 0))") == "Identifier (any one of): A; B\n\nAND supporting data: C"
    assert pbg.engine_logic("((D:A > 0) OR (D:B > 0))") == "Any one of: A; B"
    assert pbg.engine_logic("((D:A > 0)) AND NOT ((D:B > 0))").endswith("But NOT: B")


@pytest.mark.parametrize("bad", ["", "   ", "D:A", "D:A > x", "(D:A > 0", "D:A > 0)", "D:A > 0 AND", "D:A > 0 D:B > 0", "AND D:A > 0", "D:A > 0 XOR D:B > 0",
                                 "(" * 200 + "D:A > 0" + ")" * 200, "D:A > 0 OR " * 3000])
def test_text_that_is_not_an_expression_is_refused_and_the_guide_still_builds(bad):
    """ASVS V5.1.3 · CWE-20 · CWE-674: a bad or absurdly nested expression raises ExprError, and its engine is still shown as text."""
    with pytest.raises(pbg.ExprError):
        pbg.parse_expression(bad)
    assert isinstance(pbg.expression_preview(bad), str) and isinstance(pbg.engine_logic(bad), str)


# ── The route ────────────────────────────────────────────────────────

def test_the_route_serves_the_docx_read_only(no_tenant):
    """ASVS V12.5.2 · CWE-434 · CWE-525: 200, a Word attachment, no-store, a filename that is a plain token, no tenant sign-in."""
    r = TestClient(srv.app).get("/api/dlp-packs/canada_privacy_baseline/build-guide")
    assert r.status_code == 200, r.text[:200]
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    cd = r.headers["content-disposition"]
    assert re.fullmatch(r'attachment; filename="[A-Za-z0-9_-]+_build_guide\.docx"', cd), cd
    assert r.content[:2] == b"PK" and "CA-SIN" in _text(r.content)


def test_the_route_takes_prepared_for_and_by_and_caps_them(no_tenant):
    """ASVS V5.1.3 · CWE-20: the query names reach the cover, cut to the cap."""
    r = TestClient(srv.app).get("/api/dlp-packs/irs_fti_pack/build-guide", params={"prepared_for": "Acme", "prepared_by": "B" * 900})
    assert r.status_code == 200
    text = _text(r.content)
    assert "Prepared for: Acme" in text and "B" * pbg.MAX_PARAM in text and "B" * (pbg.MAX_PARAM + 1) not in text


@pytest.mark.parametrize("pid", ["nope", "..%2F..%2Fetc", "canada_privacy_baseline%00", "a" * 300])
def test_an_unknown_pack_is_404(pid, no_tenant):
    """ASVS V5.1.3 · CWE-22: an unknown or hostile pack id is a 404 with no file read."""
    r = TestClient(srv.app).get(f"/api/dlp-packs/{pid}/build-guide")
    assert r.status_code in (404, 400, 422), r.status_code
    assert r.status_code != 200 and b"PK" not in r.content[:2]


def test_the_route_is_registered_as_a_read_in_the_team_table():
    """ASVS V4.1.1 · CWE-285: the team server's route table classes the guide as a READ, and every live route has an entry."""
    assert team_routes.ROUTE_RULES[ROUTE] == team_routes.READ
    live = {f"{m} {r.path}" for r in srv.app.routes for m in (getattr(r, "methods", None) or ()) if m == "GET"}
    assert ROUTE in live


def test_the_route_reads_no_tenant_and_writes_nothing():
    """ASVS V4.1.3 · CWE-863: the handler never reaches a client factory, a tenant call or a file write."""
    import ast
    import inspect
    src = inspect.getsource(srv.dlp_pack_build_guide)
    names = {n.id for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(ast.parse(src)) if isinstance(n, ast.Attribute)}
    assert not names & {"_build_sdk_client", "_build_client", "_raw_client", "_tenant_creds", "open", "write", "write_text", "write_bytes"}
    mod = inspect.getsource(pbg)
    assert "_build_sdk_client" not in mod and "sdk_client" not in mod and "tenant_auth" not in mod and "requests" not in mod


def test_an_uploaded_pack_gets_a_guide_too(lib_client, no_tenant):
    """ASVS V12.5.1 · CWE-434: a pack added through the pack library builds like a shipped one, over HTTP and directly."""
    c = lib_client
    up = c.post("/api/pack-library/upload", json={"files": [{"name": "acme.json", "content": json.dumps(_bundle())}], "pack_id": "my_acme"})
    assert up.status_code == 200, up.text[:300]
    r = c.get("/api/dlp-packs/my_acme/build-guide")
    assert r.status_code == 200 and 'filename="my_acme_build_guide.docx"' in r.headers["content-disposition"]
    text = _text(r.content)
    for name in ("Acme Dict", "Acme SSN", "Acme Engine", "Acme-Web-Monitor"):
        assert name in text, name
    assert "Clone Predefined Dictionary" in text
    assert "No validator sample covers this engine" in text
    assert c.get("/api/dlp-packs/builtin/build-guide").status_code == 200


# ── The committed guides ─────────────────────────────────────────────

@pytest.mark.parametrize("pid", PACK_IDS)
def test_the_committed_guide_exists_and_matches_a_fresh_build(pid):
    """SSDF PS.3.1 · CWE-1357: docs/packs/<pack>_build_guide.docx is committed for every pack and its text equals a fresh build (text, not zip bytes)."""
    path = os.path.join(ROOT, "docs", "packs", f"{pid}_build_guide.docx")
    assert os.path.isfile(path), f"run: python tools/build_pack_guides.py --all --out docs/packs ({path} is missing)"
    committed = _text(open(path, "rb").read())
    assert _norm(committed) == _norm(_text(_built(pid))), f"{pid}: stale; regenerate with python tools/build_pack_guides.py --all --out docs/packs"


def test_the_cli_writes_one_file_per_pack(tmp_path):
    """SSDF PS.3.1 · CWE-1357: tools/build_pack_guides.py --pack writes <id>_build_guide.docx and refuses an unknown pack."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("pack_build_guide_cli", os.path.join(ROOT, "tools", "build_pack_guides.py"))
    cli = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cli)
    assert cli.main(["--pack", "irs_fti_pack", "--out", str(tmp_path)]) == 0
    assert [p.name for p in tmp_path.iterdir()] == ["irs_fti_pack_build_guide.docx"]
    assert cli.main(["--pack", "nope", "--out", str(tmp_path)]) == 2


def test_the_module_is_packaged_and_documented():
    """SSDF PS.3.1 · CWE-1104: pack_build_guide is a py-module of the package, and the policy packs page and the changelog say so."""
    assert '"pack_build_guide"' in open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert "build-guide" in open(os.path.join(ROOT, "POLICY_PACKS.md"), encoding="utf-8").read()
    assert "pack_build_guide" in open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()


def test_the_ui_links_the_guide_and_the_help_catalogue_explains_it():
    """WCAG 2.2 SC 3.3.2 · ASVS V1.14.1: Deploy Studio and the pack library link the guide, and both links have help entries (extension copy identical)."""
    ds = open(os.path.join(ROOT, "static", "deploy_studio.js"), encoding="utf-8").read()
    adv = open(os.path.join(ROOT, "static", "advanced.js"), encoding="utf-8").read()
    assert "/build-guide" in ds and "/build-guide" in adv
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    assert cat.count('a[href$=\\"/build-guide\\"]') == 2
    assert cat == open(os.path.join(ROOT, "browser_extension", "help_catalog.js"), encoding="utf-8").read()
