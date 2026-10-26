"""ASVS V5.3.1 · CWE-74 · WSTG-INPV-11: tenant, upload and user text stays inert in Markdown, Terraform and Word exports.

Names, descriptions, comments, log lines and uploaded file names come from
the tenant or from someone else's file. The exports must carry them as
text: a Markdown viewer must not get a link, an image, raw HTML or a heading
of the value's own; a Terraform workspace must not get HCL of the value's
own (a comment that ends early, a live ${...} or %{...}); a Word report must
not fail on a control character. Every case feeds the real generator a
payload and checks the output (Arrange-Act-Assert, no network, no clock).
"""
from __future__ import annotations

import copy
import io
import json
import re
import zipfile

import pytest

import md_safe

HTML = "<img src=x onerror=alert(1)>"
LINK = "[click](javascript:alert(1))"
PAYLOAD = f"Evil {HTML} {LINK} a|b `tick`\n# Forged heading\n| forged | row |"
TEXT_KEYS = {"name", "title", "label", "detail", "text", "reason", "note", "comment", "description", "value", "fix", "why",
             "sentence", "tenant_label", "department", "message", "rule_name", "destination", "finding", "best_practice",
             "stage_name", "requested_by", "by", "what", "outcome", "error", "explanation", "driver"}


def poison(obj, key=""):
    """A copy of a report with the payload appended to every free-text value."""
    if isinstance(obj, dict):
        return {k: poison(v, k) for k, v in obj.items()}
    if isinstance(obj, list):
        return [poison(v, key) for v in obj]
    if isinstance(obj, str) and key in TEXT_KEYS:
        return obj + " " + PAYLOAD
    return obj


def assert_inert_markdown(md: str):
    """Render the export the way a Markdown viewer does (CommonMark with raw
    HTML on, GFM tables) and check that nothing from the data became markup."""
    from markdown_it import MarkdownIt
    assert "Evil" in md, "the payload should reach the export (as text)"
    html = MarkdownIt("commonmark", {"html": True}).enable("table").render(md).lower()
    assert "<img" not in html, "raw HTML from data"
    assert 'href="javascript:' not in html, "a live javascript: link from data"
    assert "<h1>forged" not in html and "<td>forged" not in html, "a line break in data forged structure"
    for line in md.splitlines():
        assert not line.startswith("# Forged") and not line.startswith("| forged"), f"a line break in data forged: {line!r}"


# ── md_safe ──────────────────────────────────────────────────────────

@pytest.mark.parametrize("value,expected", [
    (None, ""), ("", ""), (0, "0"), ("plain FILE_TYPE * name", "plain FILE_TYPE * name"),
    ("<b>x</b>", "&lt;b&gt;x&lt;/b&gt;"), ("[a](javascript:x)", "\\[a\\](javascript:x)"), ("a|b", "a\\|b"),
    ("a\nb\r\nc d", "a b c d"), ("back\\slash `code`", "back\\\\slash \\`code\\`"), ("![i](x)", "!\\[i\\](x)"),
])
def test_md_text_is_inert_inline_text(value, expected):
    """ASVS V5.3.1 · CWE-74: md_safe.text escapes links, HTML, pipes, code and line breaks (boundaries: None, 0, empty)."""
    assert md_safe.text(value) == expected


@pytest.mark.parametrize("value", ["a`b", "``x``", "`", "plain"])
def test_md_code_span_holds_any_backticks(value):
    """ASVS V5.3.1 · CWE-74: a code span never ends inside the value."""
    out = md_safe.code(value)
    fence = re.match(r"`+", out).group(0)
    inner = out[len(fence):-len(fence)]
    assert out.endswith(fence) and fence not in inner.strip()


@pytest.mark.parametrize("target,ok", [("https://help.zscaler.com/zia", True), ("mailto:a@b.c", True), ("javascript:alert(1)", False),
                                       ("JAVASCRIPT:alert(1)", False), ("data:text/html,<b>", False), ("vbscript:x", False),
                                       ("https://x/a b", False), ("", False), (None, False)])
def test_md_url_allows_only_http_and_mailto(target, ok):
    """ASVS V5.1.5 · CWE-79 · CWE-601: only http(s) and mailto become link targets (deny by default)."""
    assert (md_safe.url(target) is not None) is ok
    if not ok:
        assert "](" not in md_safe.link("x", target)


def test_md_escape_data_keeps_keys_numbers_and_urls():
    """ASVS V5.3.1 · CWE-74: escaping a report's data leaves keys, numbers, booleans and safe URLs alone."""
    out = md_safe.escape_data({"a_b": [1, True, None, "<b>", "https://x.y/a_b"], "n": 2.5})
    assert out == {"a_b": [1, True, None, "&lt;b&gt;", "https://x.y/a_b"], "n": 2.5}


# ── Markdown generators, table-driven ─────────────────────────────────

def _detection_health():
    import detection_health as dh
    from test_detection_health import _client, _inc
    rep = dh.generate(_client([_inc("i1", "Cards-Block", "Card Data", ["Credit Cards - High"], resolution="Confirmed")]), days=30)
    return lambda: dh.to_markdown(poison(rep), "acme " + PAYLOAD)


def _data_flow():
    import data_flow as df
    from test_data_flow import _client
    rep = df.generate_data_flow_report(_client(), platform="windows")
    return lambda: df.to_markdown(poison(rep), "acme " + PAYLOAD)


def _ssl_flow():
    import ssl_flow as sf
    from test_ssl_flow import CATALOGUE, DLP, SSL
    rep = sf.analyse(SSL, DLP, CATALOGUE, {})
    rep["tenant_label"] = "acme"
    return lambda: sf.to_markdown(poison(rep))


def _benchmarks():
    import benchmarks as bm
    from test_benchmarks import _checks
    b = bm.benchmark_report({"checks": poison(_checks()), "score": 50, "maturity": "Developing"})
    return lambda: bm.to_markdown(b, "Org " + PAYLOAD)


def _change_queue():
    import change_queue as cq
    items = [{"id": "r1", "status": "pending", "title": "T " + PAYLOAD, "kind": "deploy", "kind_label": "Deploy " + PAYLOAD,
              "tenant": "acme", "tenant_label": "acme " + PAYLOAD, "requested_by": "x " + PAYLOAD, "requested_at": "2026-01-01",
              "plan_hash": "abc`def", "summary": {"create": 1},
              "items": [{"status": "create", "kind": "rule", "name": "R " + PAYLOAD, "channel": "web", "note": PAYLOAD}],
              "comments": [{"by": "y " + PAYLOAD, "at": "2026-01-01", "text": PAYLOAD}]}]
    return lambda: cq.to_markdown(items)


def _proposals():
    import proposals as pr
    items = [{"status": "open", "title": "P " + PAYLOAD, "label": PAYLOAD, "gate": "g", "created_at": "2026-01-01",
              "change": {"name": PAYLOAD}, "expected_effect": PAYLOAD, "rollback": {"name": PAYLOAD}, "evidence": {"rule": PAYLOAD}}]
    return lambda: pr.to_markdown("acme " + PAYLOAD, items)


def _continuous_eval():
    import continuous_eval as ce
    d = {"at": "2026-01-01T00:00:00Z", "noteworthy": True, "duration_s": 1,
         "summary": {k: 0 for k in ("proposals_new", "proposals_open", "guidance_new", "stale_sources", "tenants_not_active", "drift_changed", "errors")},
         "guidance": {"raised": [{"title": "G " + PAYLOAD, "kind": "doc", "topics": [PAYLOAD], "checks": ["1"], "url": "javascript:alert(1)", "outcome": PAYLOAD}]},
         "sources": {"stale": [{"name": PAYLOAD, "host": "h", "last_error": PAYLOAD}]},
         "tenants": [{"name": "T " + PAYLOAD, "tenant": "t", "note": "note " + PAYLOAD, "errors": [PAYLOAD],
                      "proposals": {"new": 1, "open": 1, "approved": 0, "applied": 0, "titles": [PAYLOAD]}}],
         "errors": [PAYLOAD]}
    return lambda: ce.to_markdown(d)


def _dlp_efficacy():
    import dlp_efficacy as de
    row = {"name": "D " + PAYLOAD, "tp_estimate": 50, "fp_risk": "High", "score": 40, "type": "custom",
           "nuances": [{"direction": "fp", "driver": PAYLOAD, "delta_pct": 5, "explanation": PAYLOAD}], "remediation": [PAYLOAD]}
    a = {"counts": {}, "averages": {}, "fp_risk_distribution": {}, "dictionaries": [row], "engines": [dict(row)]}
    return lambda: de.export_markdown(a).decode("utf-8")


def _bypass_report():
    import bypass_report as br
    keys = ("ssl_bypass_rules", "ssl_exemptions", "url_filter_allow", "firewall_allow", "dlp_allow", "zcc_apps", "zcc_processes",
            "zcc_ips", "zcc_domains", "zcc_trusted_nets", "total_bypass_items")
    item = {"id": 1, "name": "R " + PAYLOAD, "action": "ALLOW`", "state": "ENABLED", "scope": PAYLOAD, "url_categories": [PAYLOAD]}
    rep = {"generated_at": "2026-01-01", "elapsed_seconds": 1, "summary": {k: 1 for k in keys},
           "risk_flags": [{"name": PAYLOAD, "source": "ssl", "id": 1, "action": "ALLOW` <img src=x onerror=alert(1)> `", "reason": PAYLOAD}],
           "sections": {"ssl_bypass_rules": {"count": 1, "items": [item]}, "ssl_exemptions": {"count": 1, "items": [{"source": "s", "field": "f", "value": PAYLOAD}]},
                        "zcc": {"apps": {"count": 1, "items": [{"profile": PAYLOAD, "name": PAYLOAD, "value": PAYLOAD, "raw_field": "x"}]}}},
           "aggregated": {"all_urls_bypassed": {"count": 1, "items": [{"value": "x.com`|" + HTML, "rules": [{"source": "ssl", "id": 1, "name": PAYLOAD}]}]}}}
    return lambda: br.to_markdown(rep)


def _dlp_analysis():
    import dlp_analysis as da
    return lambda: "\n".join(da.markdown({"required_controls": [{"label": "L " + PAYLOAD, "status": "gap", "detail": PAYLOAD}]}))


def _terraform_readme():
    import pack_terraform as pt
    from test_baselines import BASELINE_META
    from test_pack_deploy import _dict, _engine, _policy, write_pack

    def gen(tmp):
        meta = dict(BASELINE_META, name="Pack " + PAYLOAD)
        pack = write_pack(tmp, "readme_pack", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", "(D:Alpha Dict)")],
                          policies=[_policy("Web-Monitor", ["Alpha Engine"])], meta=meta)
        return pt.generate(pack)["README.md"]
    return gen


GENERATORS = {"detection_health": _detection_health, "data_flow": _data_flow, "ssl_flow": _ssl_flow, "benchmarks": _benchmarks,
              "change_queue": _change_queue, "proposals": _proposals, "continuous_eval": _continuous_eval,
              "dlp_efficacy": _dlp_efficacy, "bypass_report": _bypass_report, "dlp_analysis": _dlp_analysis}


@pytest.mark.parametrize("name", sorted(GENERATORS))
def test_markdown_export_keeps_tenant_text_inert(name):
    """ASVS V5.3.1 · CWE-79 · CWE-74 · WSTG-INPV-11: every Markdown export carries tenant text as text, never link/HTML/structure."""
    # Arrange
    render = GENERATORS[name]()
    # Act
    md = render()
    # Assert
    assert_inert_markdown(md)


def test_terraform_readme_keeps_the_pack_name_inert(tmp_path):
    """ASVS V5.3.1 · CWE-74: the workspace README names the pack as text."""
    md = _terraform_readme()(tmp_path)
    assert_inert_markdown(md)


def test_compliance_markdown_export_keeps_evidence_inert():
    """ASVS V5.3.1 · CWE-79 · WSTG-INPV-11: the compliance report's Markdown download carries check evidence as text."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    rid = "compliance-xss-test"
    srv._REPORTS[rid] = {"tenant_label": "acme " + PAYLOAD, "check_count": 1, "generated_at": "2026-01-01", "frameworks_selected": ["NIST"],
                         "summary": {"NIST": {"name": "NIST " + PAYLOAD, "status": "Partial", "alignment_pct": 50, "control_count": 1}},
                         "drilldown": {"NIST": {"controls": [{"control": "AC-1 " + PAYLOAD, "status": "met", "evidence": [
                             {"status": "PASS", "check_id": "1.1", "label": PAYLOAD, "detail": PAYLOAD}]}]}}}
    try:
        r = TestClient(srv.app).get(f"/api/compliance/export/{rid}?format=markdown")
    finally:
        srv._REPORTS.pop(rid, None)
    assert r.status_code == 200, r.text[:300]
    assert_inert_markdown(r.text)


# ── Terraform ────────────────────────────────────────────────────────

def _gap_files(tmp_path, evil_name):
    import pack_deploy as pd
    import pack_terraform as pt
    from test_baselines import BASELINE_META, tenant_dict, tenant_engine, tenant_rule
    from test_pack_deploy import PREDEF_SSN, FakeClient, _dict, _engine, _policy, write_pack
    pack = write_pack(tmp_path, "alpha_baseline",
                      dicts=[_dict("ZBP-Alpha Dict", pattern=r"\bZ\d{4}\b"), _dict(evil_name, pattern="q")],
                      engines=[_engine("ZBP-Alpha Engine", "(D:ZBP-Alpha Dict)")],
                      policies=[_policy("ZBP-Alpha-Monitor", ["ZBP-Alpha Engine"])], meta=BASELINE_META)
    client = FakeClient(dicts=[PREDEF_SSN, tenant_dict(pattern=r"\bTAMPERED\b")], engines=[tenant_engine()], rules=[tenant_rule(order=3)])
    rep = pd.public_report(pd.preflight(client, [pack], writes_enabled=True))
    return pt.generate(pack, report=pt.split_report(rep, "alpha_baseline"))


HCL = 'resource "terraform_data" "pwn" {\n  provisioner "local-exec" { command = "id" }\n}\n#'


@pytest.mark.parametrize("brk", ["\n", "\r\n", "\r", " ", "\x0b"])
def test_terraform_gap_comments_cannot_be_ended_by_a_name(tmp_path, brk):
    """ASVS V5.3.1 · CWE-94 · WSTG-INPV-11: a pack or tenant name with a line break never becomes HCL in imports.tf."""
    # Arrange
    evil = "ZBP-Evil" + brk + HCL.replace("\n", brk)
    # Act
    files = _gap_files(tmp_path, evil)
    # Assert: no line of any .tf file starts HCL that came from the name
    hcl = "\n".join(t for n, t in files.items() if n.endswith(".tf"))
    lines = [ln.strip() for ln in re.split(r"\r\n|\r|\n", hcl)]
    assert not [ln for ln in lines if ln.startswith(('resource "terraform_data"', 'provisioner "local-exec"'))], "HCL from a name"
    assert any("local-exec" in ln and ln.startswith("#") for ln in lines), "the name should still be named, in a comment"


def test_terraform_export_note_keeps_referenced_names_on_one_comment_line():
    """ASVS V5.3.1 · CWE-94: the 'exported without dependencies' note lists tenant names inside one comment line."""
    import pack_export as pe
    from test_pack_export import _export, _source
    pack = _export(_source())
    pack["meta"]["referenced_only"] = {"dictionaries": ["Dict\n" + HCL], "engines": []}
    _pid, files = pe.terraform_files(pack, assessor="Jane Doe")
    assert not re.search(r'(?m)^\s*resource "terraform_data"', "\n".join(files.values()))


@pytest.mark.parametrize("expr,live", [
    ('(D:Alpha Dict > 0) OR ${nonsensitive(var.zscaler_client_secret)}', False),
    ('(D:Alpha Dict > 0) OR ${file("/etc/hostname")}', False),
    ('(D:Alpha Dict > 0) OR $${already_escaped}', False),
    ('(D:Alpha Dict > 0)', True),
])
def test_terraform_engine_expression_has_only_its_own_references_live(tmp_path, expr, live):
    """ASVS V5.3.1 · CWE-94 · CWE-200: an engine expression's own ${...} is escaped; only the generated dictionary reference is live."""
    import pack_terraform as pt
    from test_baselines import BASELINE_META
    from test_pack_deploy import _dict, _engine, _policy, write_pack
    pack = write_pack(tmp_path, "tfpack", dicts=[_dict("Alpha Dict")], engines=[_engine("Alpha Engine", expr)],
                      policies=[_policy("Web-Monitor", ["Alpha Engine"])], meta=BASELINE_META)
    line = next(ln for ln in pt.generate(pack)["engines.tf"].splitlines() if "engine_expression" in ln)
    live_refs = re.findall(r"(?<!\$)\$\{([^}]*)\}", line)
    assert live_refs and all(re.fullmatch(r"(data\.)?zia_dlp_dictionaries\.[a-z0-9_]+\.id", r) for r in live_refs), line


@pytest.mark.parametrize("directive", ['%{ if true }x%{ endif }', '%{for c in ["a"]}${c}%{endfor}', "%%{ escaped }"])
def test_vendor_migration_refuses_template_directives_in_engine_expressions(directive):
    """ASVS V5.3.1 · CWE-94: a reviewed vendor expression with a Terraform %{...} directive is refused (fail closed)."""
    import vendor_migrate as vm
    from test_vendor_migrate import EXPORT, _decisions
    snap = vm.inventory_bytes(EXPORT, "x.xml")
    d = _decisions(snap)
    d["engines"][0]["zia_expression"] = "((D{{dict:customer_context}}.S > 1)) " + directive
    tf, report = vm.compile_export(snap, d)
    assert not report["ready"] and "%{" not in json.dumps(tf)


def test_vendor_migration_still_accepts_a_plain_expression():
    """ASVS V5.3.1 · CWE-94: positive case, a plain expression still compiles."""
    import vendor_migrate as vm
    from test_vendor_migrate import EXPORT, _decisions
    snap = vm.inventory_bytes(EXPORT, "x.xml")
    _tf, report = vm.compile_export(snap, _decisions(snap))
    assert report["ready"]


# ── Word ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["\x00", "\x01", "\x0b", "\x1f", "￾"])
def test_word_report_survives_control_characters_in_tenant_text(tmp_path, bad):
    """ASVS V5.3.1 · CWE-116 · CWE-20: a control character in a check detail or name never stops the Word report."""
    pytest.importorskip("docx")
    import plain_english as pe
    from dlp_assessment_full_auto import compute, maturity
    from report_docx import generate_report
    results = [pe.enrich(r) for r in [
        {"id": "4.1", "sec": "4 — SSL Policy", "label": "Inspection" + bad, "status": "FAIL", "detail": f"Rule 'x{bad}{HTML}' disables inspection."},
        {"id": "12.4", "sec": "12 — Incident Mgmt", "label": "Workflow Automation", "status": "PASS", "detail": "ok"}]]
    out = tmp_path / "r.docx"
    generate_report(results, {"org_name": "Acme" + bad, "assessor": "A" + bad, "cloud": "zscaler.net"}, str(out), compute, maturity)
    with zipfile.ZipFile(out) as z:
        body = z.read("word/document.xml").decode("utf-8")
    assert "&lt;img src=x onerror=alert(1)&gt;" in body and bad not in body
