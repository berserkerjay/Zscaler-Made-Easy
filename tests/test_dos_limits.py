"""Denial of service and resource limits (QA check T13).

Every hostile input here is small enough to fit in one request (the body
cap is 10 MB) or one tenant read, and each one used to cost the server
seconds to hours of CPU, or a crash, before the fix it guards:

* catastrophic or quadratic regular expressions on uploaded or typed text
  (the Log Analyzer, the corpus test's detectors, the audit timeline's dates,
  the Terraform reader of the pack upload, the engine-expression readers);
* algorithms that compare every pair (pack validation, the rule migrator,
  the ZPA analysis and its map, device posture, the shadowed-rule check);
* unbounded recursion on nested JSON, XML, Terraform and engine expressions;
* stores that grow without bound (finished jobs, change-request history,
  workspace notes) and upload parsers that ran on the event loop.

How the tests decide. Where the cost can be counted (calls of the pairwise
comparison, compiled patterns, list sizes) it is counted: that is exact and
independent of the machine. Catastrophic backtracking has no count Python
exposes, so those tests measure the CPU time of this process
(time.process_time, not the wall clock, so a busy machine does not change
the verdict) against a budget at least ten times what the fixed code needs
and far below what the old code took on the same input (noted per case).
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
import time

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cpu(fn, *args, **kwargs) -> float:
    """CPU seconds this process spent in fn(*args, **kwargs)."""
    start = time.process_time()
    fn(*args, **kwargs)
    return time.process_time() - start


def _client() -> TestClient:
    return TestClient(srv.app, raise_server_exceptions=False)


# ── Log Analyzer (uploaded Client Connector logs and PAC files) ─────────
_LOG_CASES = {
    # name: (file name, content); old code: CPU seconds on the same input
    "user line of -A runs (was 27 s)": ("a.log", "user " + "-A" * 40000),
    "PAC proxy string of a. runs (was 16 s)": ("p.pac", "function FindProxyForURL(url, host) { return 'PROXY " + "a." * 20000 + "'; }"),
    "PAC bypass lines of open isInNet( (was 13 s)": ("p.pac", "function FindProxyForURL(url, host) {\n"
                                                    + ("return 'DIRECT'; " + "isInNet(" * 500 + "\n") * 40 + "}"),
    "one line of tunnel_state_ runs": ("a.log", "tunnel " + "tunnel_state_" * 6000),
    "one line of authauth runs": ("a.log", "auth" * 20000),
}


@pytest.mark.parametrize("case", sorted(_LOG_CASES))
def test_a_hostile_log_or_pac_file_is_analysed_in_linear_time(case):
    """ASVS V11.1.4 · A04:2021 · CWE-1333 · WSTG-BUSL-09: a crafted log or PAC upload cannot pin the CPU (ReDoS)."""
    import log_analyzer
    name, content = _LOG_CASES[case]
    spent = _cpu(log_analyzer.analyze, [{"name": name, "content": content}])
    assert spent < 2.0, f"{case}: {spent:.2f} s of CPU"


def test_a_log_line_is_read_up_to_max_line_chars_only():
    """ASVS V11.1.4 · A04:2021 · CWE-400: text past MAX_LINE_CHARS on one line is not pattern-matched (boundary)."""
    import log_analyzer
    cap = log_analyzer.MAX_LINE_CHARS
    inside = "x" * (cap - len("captive portal")) + "captive portal"
    outside = "x" * cap + "captive portal"
    keys = lambda text: {f["key"] for f in log_analyzer.analyze([{"name": "a.log", "content": text}])["logs"]["findings"]}  # noqa: E731
    assert "captive_portal" in keys(inside)
    assert "captive_portal" not in keys(outside)


def test_the_bounded_signatures_still_match_ordinary_log_lines():
    """ASVS V11.1.4 · A04:2021 · CWE-1333: bounding the word runs keeps every signature working on real lines."""
    import log_analyzer
    lines = ["2026-10-26 10:00:00 ERR authentication failed for user",
             "2026-10-26 10:00:01 ERR tunnel_state_disconnected while connecting",
             "2026-10-26 10:00:02 ERR tunnel_state_disconnected while connecting",
             "2026-10-26 10:00:03 WRN Zscaler service stopped by user"]
    found = {f["key"] for f in log_analyzer.analyze([{"name": "a.log", "content": "\n".join(lines)}])["logs"]["findings"]}
    assert {"auth_failed", "tunnel_down", "disabled_by_user"} <= found


def test_the_pac_reader_still_names_hard_coded_gateways():
    """ASVS V11.1.4 · A04:2021 · CWE-1333: the linear gateway pattern finds the same gateways."""
    import log_analyzer
    pac = "function FindProxyForURL(url, host) { if (shExpMatch(host, '*.corp.example')) return 'DIRECT'; return 'PROXY gw1.zscalertwo.net:80; DIRECT'; }"
    out = log_analyzer.analyze_pac("p.pac", pac)
    hard = next(f for f in out["findings"] if "hard-coded" in f["title"])
    assert hard["evidence"] == ["gw1.zscalertwo.net"]


# ── Pack upload: validation and the Terraform reader ───────────────────
def _preview(pack: dict):
    return _client().post("/api/pack-library/preview", json={"files": [{"name": "pack.json", "content": json.dumps(pack)}]})


def test_pack_validation_of_a_long_engine_expression_is_linear():
    """ASVS V11.1.4 · A04:2021 · CWE-407 · WSTG-BUSL-09: a 16 KB engine expression of spaces is checked at once (was 2 s; 40 KB: 29 s)."""
    import pack_library as pl
    pack = pl.assemble_pack([{"name": "pack.json", "content": json.dumps(
        {"name": "p", "dictionaries": [], "engines": [{"name": "e", "expression": "D:x" + " " * (pl.MAX_EXPRESSION_CHARS - 3)}], "policies": []})}])
    assert _cpu(pl.validate_pack, pack) < 0.5


def test_pack_validation_does_not_compile_a_pattern_per_dictionary_and_engine(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407 · WSTG-BUSL-09: 600 dictionaries x 600 engines cost 600 patterns, not 360,000 (was 30 s+)."""
    import pack_library as pl
    n = 600
    pack = pl.assemble_pack([{"name": "pack.json", "content": json.dumps({
        "name": "p", "dictionaries": [{"name": f"dict{i}", "phrases": ["abc"]} for i in range(n)],
        "engines": [{"name": f"e{i}", "expression": f"D:dict{i} > 0"} for i in range(n)], "policies": []})}])
    compiled = []
    real = pl.re.compile
    monkeypatch.setattr(pl.re, "compile", lambda p, *a, **k: compiled.append(p) or real(p, *a, **k))
    v = pl.validate_pack(pack)
    assert v["ok"], v["problems"][:3]
    per_name = [p for p in compiled if isinstance(p, str) and p.startswith("D:")]
    # Only names that follow a "D:" in the expression get a pattern (dict1 is also tried on "D:dict10"):
    # a few per engine, never one per dictionary and engine (360,000 before).
    assert n <= len(per_name) <= 4 * n


@pytest.mark.parametrize("extra, refused", [(0, False), (1, True)])
def test_an_engine_expression_over_the_limit_is_refused_in_words(extra, refused):
    """ASVS V11.1.4 · A04:2021 · CWE-400: MAX_EXPRESSION_CHARS is the boundary (at it: read; one more: a problem)."""
    import pack_library as pl
    expr = "D:dict0 > 0" + " " * (pl.MAX_EXPRESSION_CHARS - len("D:dict0 > 0") + extra)
    pack = {"meta": {"name": "p"}, "dictionaries": [{"name": "dict0", "phrases": ["abc"]}], "engines": [{"name": "e", "expression": expr}],
            "policies": [], "app_groups": []}
    problems = pl.validate_pack(pack)["problems"]
    assert any("this app reads engine expressions of up to" in p for p in problems) is refused


def test_a_pack_whose_expressions_exceed_the_lookup_budget_fails_closed(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-400: past REF_LOOKUP_BUDGET the pack is refused, not checked for minutes."""
    import pack_library as pl
    monkeypatch.setattr(pl, "REF_LOOKUP_BUDGET", 1000)
    pack = {"meta": {"name": "p"}, "dictionaries": [{"name": "n" * k, "phrases": ["abc"]} for k in range(1, 51)],
            "engines": [{"name": f"e{i}", "expression": "D:" * 200} for i in range(5)], "policies": [], "app_groups": []}
    v = pl.validate_pack(pack)
    assert not v["ok"] and any("too many dictionaries to check" in p for p in v["problems"])


_HCL_CASES = {
    "/* comments never closed (was 21 s)": "/* " * 40000,
    "heredocs never closed": "x = <<A\n" * 15000,
    "index brackets never closed (was 6 s)": "x = " + "a[" * 60000,
}


@pytest.mark.parametrize("case", sorted(_HCL_CASES))
def test_a_hostile_terraform_upload_is_tokenised_in_linear_time(case):
    """ASVS V11.1.4 · A04:2021 · CWE-1333 · WSTG-BUSL-09: an unclosed comment, heredoc or index cannot make the reader quadratic."""
    import pack_library as pl

    def run():
        with pytest.raises(ValueError):
            pl.assemble_pack([{"name": "main.tf", "content": _HCL_CASES[case]}])
    assert _cpu(run) < 1.5, case


@pytest.mark.parametrize("text", ["x = " + "[" * 5000 + "]" * 5000, "a {\n" * 3000 + "}\n" * 3000],
                         ids=["nested lists", "nested blocks"])
def test_deeply_nested_terraform_is_a_parse_error_not_a_crash(text):
    """ASVS V11.1.4 · A04:2021 · CWE-674 · WSTG-BUSL-09: nesting past MAX_HCL_DEPTH is refused in words (no RecursionError)."""
    import pack_library as pl
    with pytest.raises(ValueError, match="nested more than"):
        pl.assemble_pack([{"name": "main.tf", "content": text}])


@pytest.mark.parametrize("depth, ok", [(20, True), (70, False)])
def test_terraform_nesting_boundary(depth, ok):
    """ASVS V11.1.4 · A04:2021 · CWE-674: ordinary nesting parses; past MAX_HCL_DEPTH it does not (boundary)."""
    import pack_library as pl
    text = 'resource "zia_dlp_engines" "e" {\n  x = ' + "[" * depth + "1" + "]" * depth + "\n}\n"
    if ok:
        assert pl.parse_hcl(text)["resource"]
    else:
        with pytest.raises(pl.HCLError):
            pl.parse_hcl(text)


# ── Engine expressions (tenant data and packs) ─────────────────────────
@pytest.mark.parametrize("expr", ["(" * 300 + "D1.S > 0" + ")" * 300, "NOT " * 900 + "D1.S"], ids=["parentheses", "NOTs"])
def test_a_deeply_nested_engine_expression_is_named_not_crashed_on(expr):
    """ASVS V11.1.4 · A04:2021 · CWE-674: a tenant engine nested hundreds deep gives no summary instead of a RecursionError."""
    import corpus_engines
    import engine_explain
    assert engine_explain.summary(expr, {"1": "SSN"}) == ""
    assert engine_explain.readable(expr, {"1": "SSN"})            # the ids replaced, shape kept
    result, ids, notes = corpus_engines.evaluate_expression(expr, {1: 3})
    assert result is None and ids == [1] and "nested more than" in notes[0]


@pytest.mark.parametrize("depth, explained", [(40, True), (41, False)])
def test_engine_expression_nesting_boundary(depth, explained):
    """ASVS V11.1.4 · A04:2021 · CWE-674: MAX_NESTING levels are explained, one more is not (boundary)."""
    import corpus_engines
    import engine_explain
    assert engine_explain.MAX_NESTING == corpus_engines.MAX_NESTING == 40
    expr = "(" * depth + "D1.S > 0" + ")" * depth
    assert bool(engine_explain.summary(expr, {"1": "SSN"})) is explained
    assert (corpus_engines.evaluate_expression(expr, {1: 3})[0] is True) is explained


def test_the_engine_reference_reader_is_linear():
    """ASVS V11.1.4 · A04:2021 · CWE-407: find_refs on a long run of spaces does not re-read the run per space."""
    from dlp_importer import find_refs
    assert find_refs("D:Names (US) AND D:SSN > 1") == ["Names (US)", "SSN"]
    assert _cpu(find_refs, "D:x" + " " * 200000 + "y") < 0.5


def test_the_engine_pruner_stops_at_the_first_text_that_is_not_a_token():
    """ASVS V11.1.4 · A04:2021 · CWE-1333: a run of '<' is refused at once (the token search used to restart at every position)."""
    from dlp_importer import prune_engine_terms
    pruned, dropped = prune_engine_terms("(D:a > 0) AND (D:b > 0)", ["b"], ["a"])
    assert "D:a" in pruned and "D:b" not in pruned and dropped == ["b"]
    assert prune_engine_terms("<" * 20000 + " D:a > 0", ["a"], ["b"]) == (None, [])
    assert _cpu(prune_engine_terms, "<" * 20000 + " D:a > 0", ["a"], ["b"]) < 0.5


def test_thousands_of_tenant_dictionaries_cost_no_pattern_each(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407: engine_references and prune_engine_terms only build patterns for names the expression holds."""
    import dlp_importer
    names = [f"Customer dictionary {i}" for i in range(5000)]
    expr = "((D:Customer dictionary 7 > 0) AND (D:Credit Cards > 1))"
    calls = []
    real_search, real_compile = dlp_importer.re.search, dlp_importer.re.compile
    monkeypatch.setattr(dlp_importer.re, "search", lambda p, *a, **k: calls.append(p) or real_search(p, *a, **k))
    monkeypatch.setattr(dlp_importer.re, "compile", lambda p, *a, **k: calls.append(p) or real_compile(p, *a, **k))
    assert dlp_importer.engine_references(expr, names) == ["Customer dictionary 7"]
    pruned, dropped = dlp_importer.prune_engine_terms(expr, ["Credit Cards"], names)
    assert "D:Customer dictionary 7" in pruned and "Credit Cards" not in pruned and dropped == ["Credit Cards"]
    per_name = [p for p in calls if isinstance(p, str) and p.startswith("D:")]
    assert len(per_name) <= 4, "patterns only for the names the expression holds, not for 5,000 dictionaries"


# ── Corpus test detectors (pasted sample text) ─────────────────────────
def test_the_email_detector_is_linear_on_a_pasted_corpus():
    """ASVS V11.1.4 · A04:2021 · CWE-1333: 64 KB of '._' no longer costs seconds (was 5.8 s; the 256 KB cap: about 90 s)."""
    import corpus_engines
    det = next(d for d in corpus_engines.DETECTORS if d["key"] == "email")
    assert corpus_engines.run_detector(det, "write to jane.doe@corp.example or bob@x.io.")[0] == 2
    assert corpus_engines.run_detector(det, "no address here")[0] == 0
    assert _cpu(corpus_engines.run_detector, det, "._" * 32768) < 0.5


# ── Nested JSON / XML bodies and uploads ───────────────────────────────
def _json_routes():
    spec = srv.app.openapi()
    out = []
    for path, ops in spec["paths"].items():
        op = ops.get("post")
        if path.startswith("/api/") and op and "application/json" in (op.get("requestBody") or {}).get("content", {}):
            out.append(path)
    return sorted(out)


@pytest.mark.parametrize("path", _json_routes())
def test_a_deeply_nested_json_body_is_a_400_on_every_route_and_is_audited(path, tmp_path, monkeypatch):
    """ASVS V7.1.3 · A09:2021 · CWE-674 · WSTG-ERRH-01: JSON nested past the decoder's depth is refused with 400 and still logged."""
    log = tmp_path / "audit.log"
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(log))
    url = path.replace("{", "").replace("}", "")      # path parameters: any value; the body is refused first
    body = "[" * 5000 + "]" * 5000
    r = _client().post(url, content=body, headers={"content-type": "application/json"})
    assert r.status_code == 400, (path, r.status_code, r.text[:200])
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert any(e.get("event") == "api" and e.get("path") == url and e.get("body") == f"<{len(body)} bytes>" for e in lines)


@pytest.mark.parametrize("vendor, name, content", [
    ("forcepoint", "x.json", "[" * 50000 + "]" * 50000),
    ("netskope", "x.json", "[" * 50000 + "]" * 50000),
    ("skyhigh", "x.json", "{\"a\":" * 70 + "1" + "}" * 70),
    ("skyhigh", "x.xml", "<a>" * 50000 + "</a>" * 50000),
], ids=["forcepoint json", "netskope json", "skyhigh json 70 deep", "skyhigh xml"])
def test_a_deeply_nested_vendor_export_is_refused_in_words(vendor, name, content):
    """ASVS V11.1.4 · A04:2021 · CWE-674 · WSTG-BUSL-09: a nested export gets a 400 naming the limit, never a 500."""
    r = _client().post("/api/vendor-migrate/inventory", json={"vendor": vendor, "export": {"name": name, "content": content}})
    assert r.status_code == 400 and "nested more than" in r.json()["detail"], r.text[:200]


def test_a_nested_decisions_file_is_refused_in_words():
    """ASVS V11.1.4 · A04:2021 · CWE-674: the decisions upload has the same depth limit."""
    import vendor_migrate
    from test_vendor_migrate import EXPORT
    export = {"name": "e.xml", "content": base64.b64encode(EXPORT).decode(), "encoding": "base64"}
    with pytest.raises(ValueError, match="nested more than"):
        vendor_migrate.compile_upload("symantec", export, {"name": "d.json", "content": "[" * 5000 + "]" * 5000})


def test_vendor_exports_nested_within_the_limit_still_parse():
    """ASVS V11.1.4 · A04:2021 · CWE-674: MAX_NESTING levels parse (boundary, negative of the refusal)."""
    import vendor_migrate
    d = vendor_migrate.MAX_NESTING
    assert vendor_migrate._load_json(("[" * d + "]" * d).encode(), "x.json") is not None
    with pytest.raises(ValueError):
        vendor_migrate._load_json(("[" * (d + 1) + "]" * (d + 1)).encode(), "x.json")


# ── Audit timeline window (typed dates) ────────────────────────────────
def test_a_long_typed_date_is_refused_at_once():
    """ASVS V11.1.4 · A04:2021 · CWE-1333 · WSTG-BUSL-07: 32 KB of tabs in a date is not a time (was 27 s on the event loop)."""
    import audit_timeline as at
    start = "2026-10-01" + "\t" * 32000 + "x"
    cpu = time.process_time()
    with pytest.raises(ValueError) as e:
        at.window(None, start, "", now=1_790_000_000)
    assert time.process_time() - cpu < 0.2
    assert len(str(e.value)) < 120, "the message quotes at most 40 characters of the input"
    r = _client().post("/api/audit-timeline/start", json={"start": start, "include_zia": False})
    assert r.status_code == 400 and len(r.text) < 300


@pytest.mark.parametrize("text, parsed", [("2026-10-01 10:00:00 UTC", True), ("  2026-10-01  ", True),
                                          ("2026-10-01" + " " * 51 + "UTC", True), ("2026-10-01" + " " * 52 + "UTC", False)])
def test_time_text_boundary(text, parsed):
    """ASVS V11.1.4 · A04:2021 · CWE-1333: times up to MAX_TIME_TEXT characters still parse; longer text is not a time."""
    import audit_timeline as at
    assert (at.parse_time(text) is not None) is parsed


# ── Rule migrator (uploaded rule lists) ────────────────────────────────
def test_the_rule_migrator_analysis_is_not_quadratic():
    """ASVS V11.1.4 · A04:2021 · CWE-407 · WSTG-BUSL-07: 16,000 uploaded rules analyse in well under a second (was 20 s on the event loop)."""
    from rule_migrator import analyze_rules
    rules = [{"id": i, "name": f"R{i}", "action": "BLOCK", "urlCategories": [f"C{i}"], "dlpEngines": [{"id": i}]} for i in range(16000)]
    assert _cpu(analyze_rules, rules) < 1.5


def _brute_overlaps(rules):
    out = []
    for i, r in enumerate(rules):
        a = (r.get("action") or "").upper()
        if a not in ("ALLOW", "BYPASS"):
            continue
        for o in rules[i + 1:]:
            if (o.get("action") or "").upper() in ("BLOCK", "BLOCK_DROP") and set(r.get("urlCategories") or []) & set(o.get("urlCategories") or []):
                out.append((r["name"], o["name"]))
    return out


def test_the_rule_migrator_lists_the_same_overlaps_as_comparing_every_pair():
    """ASVS V11.1.4 · A04:2021 · CWE-407: the category index finds exactly the Allow/Block pairs the pairwise loop found."""
    from rule_migrator import analyze_rules
    acts = ["ALLOW", "BLOCK", "BYPASS", "BLOCK_DROP", "CONFIRM"]
    rules = [{"id": i, "name": f"R{i}", "action": acts[(i * 7) % 5], "urlCategories": [f"C{(i * 3) % 5}", f"C{i % 4}"]} for i in range(40)]
    got = [(x["rule_name"], x["message"].split("rule '")[1].split("'")[0]) for x in analyze_rules(rules)["issues"] if x["type"] == "Conflicting Overlap"]
    assert got == _brute_overlaps(rules) and got


@pytest.mark.parametrize("blocks, summary", [(3, False), (4, True)])
def test_the_rule_migrator_caps_listed_overlaps(monkeypatch, blocks, summary):
    """ASVS V11.1.4 · A04:2021 · CWE-770: at most MAX_OVERLAP_ISSUES pairs are listed, then one line says there are more (boundary)."""
    import rule_migrator
    monkeypatch.setattr(rule_migrator, "MAX_OVERLAP_ISSUES", 3)
    rules = [{"id": 0, "name": "A", "action": "ALLOW", "urlCategories": ["X"]}] + \
            [{"id": i, "name": f"B{i}", "action": "BLOCK", "urlCategories": ["X"]} for i in range(1, blocks + 1)]
    overlaps = [x for x in rule_migrator.analyze_rules(rules)["issues"] if x["type"] == "Conflicting Overlap"]
    assert len(overlaps) == 3 + summary
    assert ("More Allow rules overlap" in overlaps[-1]["message"]) is summary


# ── Jobs, change requests and notes kept by the server ─────────────────
def test_finished_jobs_are_kept_up_to_a_count_and_running_ones_always(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-770: finished jobs (each with a result and a file) are capped; a running job is never dropped."""
    import pack_jobs
    monkeypatch.setattr(pack_jobs, "_jobs", {})
    monkeypatch.setattr(pack_jobs, "MAX_FINISHED_JOBS", 3)
    now = 1_000_000.0
    for i in range(6):
        j = pack_jobs.Job(id=f"done{i}", kind="test")
        j.finished, j.status = now - 100 + i, pack_jobs.DONE
        pack_jobs._jobs[j.id] = j
    pack_jobs._jobs["run"] = pack_jobs.Job(id="run", kind="test")
    assert pack_jobs.prune(now=now) == 3
    assert sorted(pack_jobs._jobs) == ["done3", "done4", "done5", "run"]
    assert pack_jobs.prune(now=now + pack_jobs.KEEP_SECONDS + 1) == 3, "the age limit still applies"
    assert list(pack_jobs._jobs) == ["run"]


def test_change_request_history_does_not_grow_with_every_comment(monkeypatch, tmp_path):
    """ASVS V11.1.4 · A04:2021 · CWE-770: repeated comments keep at most MAX_COMMENTS history lines; decisions are kept."""
    import change_queue as cq
    monkeypatch.setenv("DLPCHECK_CHANGE_QUEUE_FILE", str(tmp_path / "change_requests.json"))
    monkeypatch.setattr(cq, "MAX_COMMENTS", 3)
    rec = cq.file_request(kind="pack_deploy", tenant="acme", tenant_label="acme (production)", title="t", summary={}, items=[],
                          plan_hash="h" * 16, requested_by="alice", payload={})
    for i in range(10):
        rec = cq.comment(rec["id"], by="bob", text=f"comment {i}")
    actions = [h["action"] for h in rec["history"]]
    assert actions == ["filed", "commented", "commented", "commented"]
    assert [c["text"] for c in rec["comments"]] == ["comment 7", "comment 8", "comment 9"]


@pytest.fixture
def _notes(monkeypatch, tmp_path):
    import workspace_notes as wn
    monkeypatch.setenv("DLP_CHECK_WORKSPACE_NOTES", str(tmp_path / "workspace_notes.json"))
    return wn


def test_the_notes_store_has_a_total_size_quota(_notes, monkeypatch):
    """ASVS V12.1.3 · A04:2021 · CWE-770: once the store passes MAX_STORE_BYTES adding is refused (413); deleting still works."""
    wn = _notes
    monkeypatch.setattr(wn, "MAX_STORE_BYTES", 6000)
    added = 0
    with pytest.raises(wn.NotesError) as e:
        for i in range(100):
            wn.apply("acme", "rule", f"r{i}", "add_comment", by="alice", text="x" * 500)
            added += 1
    assert e.value.status == 413 and 0 < added < 100
    assert os.path.getsize(wn.store_path()) < 2 * 6000
    assert wn.delete("acme", "rule", "r0", by="alice") is True


def test_a_note_within_the_quota_is_written(_notes):
    """ASVS V12.1.3 · A04:2021 · CWE-770: the quota does not refuse ordinary notes (negative case)."""
    wn = _notes
    note = wn.apply("acme", "rule", "r1", "add_comment", by="alice", text="Check this rule")
    assert note["comments"][0]["text"] == "Check this rule"


# ── Large tenants: the analyses that compared every pair ───────────────
def _zpa():
    import zpa_analysis as za
    from test_zpa_analysis import NOW, APP, _cond, _op, _rule, _seg, messy, read
    return za, NOW, APP, _cond, _op, _rule, _seg, messy, read


def _zpa_rules_tenant(n):
    za, NOW, APP, _cond, _op, _rule, _seg, messy, read = _zpa()
    data = messy()
    data["segments"] += [_seg(f"s-b{i}", f"Bulk {i:04d}", [f"h{i}.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]) for i in range(n)]
    data["policies"]["access"] = data["policies"]["access"] + [
        _rule(f"r-b{i}", 100 + i, f"Rule {i}", "ALLOW", _cond(*[APP(f"s-b{j}") for j in range(i, min(n, i + 5))]), _cond(_op("SCIM_GROUP", "idp1", f"grp{i}")))
        for i in range(n)]
    return read(data)


def test_zpa_rule_shadowing_compares_plausible_pairs_only(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407: 2,000 access rules cost a few comparisons each, not 2 million (was 43 s)."""
    za = _zpa()[0]
    snap = _zpa_rules_tenant(2000)
    calls = []
    real = za.shadows
    monkeypatch.setattr(za, "shadows", lambda a, b, ix: calls.append(1) or real(a, b, ix))
    za.analyze(snap, now=_zpa()[1])
    assert len(calls) < 20 * 2000


def test_zpa_indexes_give_the_same_answers_as_comparing_every_pair():
    """ASVS V11.1.4 · A04:2021 · CWE-407: the reach and shadow indexes agree with the pairwise definitions on the messy tenant."""
    za, NOW, *_rest, read = _zpa()
    snap = read()
    ix = za._Index(snap)
    rules = za._enabled_rules(snap, "access")
    reaching = za._reach_index(rules)
    for s in snap["segments"]:
        assert reaching(s) == [r for r in rules if za._reaches(r, s)], s["id"]
    candidates = za._shadow_candidates(rules, ix)
    for j, b in enumerate(rules):
        brute = [a for a in rules[:j] if za.shadows(a, b, ix)]
        indexed = [rules[k] for k in candidates(b, j) if za.shadows(rules[k], b, ix)]
        assert indexed == brute, b["name"]


@pytest.mark.parametrize("extra, summary", [(2, False), (3, True)])
def test_zpa_overlap_findings_are_capped(monkeypatch, extra, summary):
    """ASVS V11.1.4 · A04:2021 · CWE-770: a domain in thousands of segments lists MAX_OVERLAP_FINDINGS pairs, then says there are more."""
    za, NOW, APP, _cond, _op, _rule, _seg, messy, read = _zpa()
    data = messy()
    base = len([f for f in za.analyze(read(data), now=NOW)["findings"] if f["template"] == "ZPA-AS-03"])
    monkeypatch.setattr(za, "MAX_OVERLAP_FINDINGS", base + 1)    # one more pair than the messy tenant has
    data["segments"] += [_seg(f"s-o{i}", f"Overlap {i}", ["shared.overlap.example"], [(443, 443)], "sg-eng", ["srv-dc1"]) for i in range(extra)]
    found = [f for f in za.analyze(read(data), now=NOW)["findings"] if f["template"] == "ZPA-AS-03"]
    assert len(found) == base + 1 + summary
    assert any(f["object"] == "More app segments" for f in found) is summary


def test_zpa_overlap_comparison_stops_at_max_pairs(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407: segments sharing a domain without sharing ports stop being compared at MAX_OVERLAP_PAIRS."""
    za, NOW, APP, _cond, _op, _rule, _seg, messy, read = _zpa()
    monkeypatch.setattr(za, "MAX_OVERLAP_PAIRS", 50)
    data = messy()
    data["segments"] += [_seg(f"s-p{i}", f"Port {i}", ["shared.ports.example"], [(1000 + i, 1000 + i)], "sg-eng", ["srv-dc1"]) for i in range(40)]
    found = [f for f in za.analyze(read(data), now=NOW)["findings"] if f["template"] == "ZPA-AS-03"]
    assert any("Comparing stopped after 50 pairs" in f["reason"] for f in found)


def test_the_zpa_map_does_not_walk_every_segment_for_every_rule():
    """ASVS V11.1.4 · A04:2021 · CWE-407: 4,000 rules x 4,000 segments build the overview in under 2 s of CPU (was 4.3 s)."""
    import zpa_overview as zo
    za, NOW = _zpa()[:2]
    snap = _zpa_rules_tenant(4000)
    an = za.analyze(snap, now=NOW)
    assert _cpu(zo.overview, snap, an) < 2.0


def test_device_posture_rule_segments_use_an_index():
    """ASVS V11.1.4 · A04:2021 · CWE-407: 4,000 rules over 4,000 segments resolve in well under a second (was a pass per rule)."""
    import device_posture as dp
    n = 4000
    snap = {"segments": [{"id": f"s{i}", "name": f"S{i}", "enabled": True, "segment_group_id": f"g{i % 50}"} for i in range(n)],
            "segment_groups": [{"id": f"g{k}", "name": f"G{k}"} for k in range(50)]}
    names = dp.Names(snap)
    rules = [{"conditions": [{"operands": [{"type": "APP", "rhs": f"s{i}"}], "negated": False}]} for i in range(n)]
    rules.append({"conditions": [{"operands": [{"type": "APP_GROUP", "rhs": "g7"}], "negated": False}]})
    rules.append({"conditions": [{"operands": [{"type": "APP", "rhs": "s1"}], "negated": True}]})
    out = []
    spent = _cpu(lambda: out.extend(dp._rule_segments(r, names) for r in rules))
    assert spent < 1.0
    assert [s["id"] for s in out[0]] == ["s0"]
    assert [s["id"] for s in out[-2]] == [f"s{i}" for i in range(n) if i % 50 == 7]
    assert len(out[-1]) == n - 1 and all(s["id"] != "s1" for s in out[-1])


def test_evaluate_all_superseded_rules_compare_plausible_pairs_only(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407: 2,000 Endpoint DLP rules with their own engines are not compared pair by pair (was 5 s)."""
    import shadow_rules as sr
    rules = [{"id": i, "name": f"r{i}", "order": i + 1, "action": "BLOCK", "state": "ENABLED", "dlpEngines": [{"id": i}],
              "groups": [{"id": i}]} for i in range(2000)]
    calls = []
    real = sr.covers
    monkeypatch.setattr(sr, "covers", lambda a, b: calls.append(1) or real(a, b))
    assert sr.analyse({"endpoint_dlp": rules})["findings"] == []
    assert len(calls) < 5 * 2000


def test_superseded_candidates_match_comparing_every_pair(monkeypatch):
    """ASVS V11.1.4 · A04:2021 · CWE-407: with shared engines and rules without content inspection the findings are unchanged."""
    import shadow_rules as sr
    rules = [{"id": i, "name": f"r{i}", "order": i + 1, "action": ["BLOCK", "ALLOW", "CONFIRM"][i % 3], "state": "ENABLED",
              **({"withoutContentInspection": True} if i % 7 == 0 else {"dlpEngines": [{"id": i % 4}]}),
              **({"groups": [{"id": i % 2}]} if i % 5 else {})} for i in range(30)]
    got = sr.analyse({"endpoint_dlp": rules})["findings"]
    monkeypatch.setattr(sr, "_content_candidates", lambda live: (lambda b: list(live)))   # every pair: the old behaviour
    assert got == sr.analyse({"endpoint_dlp": rules})["findings"] and got


# ── Upload parsers run off the event loop ──────────────────────────────
_UPLOAD_ROUTES = [
    ("/api/pack-library/preview", "pack_library", "assemble_pack", {"files": [{"name": "pack.json", "content": "{}"}]}),
    ("/api/pack-library/upload", "pack_library", "assemble_pack", {"files": [{"name": "pack.json", "content": "{}"}]}),
    ("/api/dlp-packs/upload", "pack_library", "assemble_pack", {"pack_name": "p"}),
    ("/api/vendor-migrate/inventory", "vendor_migrate", "inventory_upload", {"export": {"name": "e.xml", "content": "<a/>"}}),
    ("/api/vendor-migrate/compile", "vendor_migrate", "compile_upload", {"export": {"name": "e.xml", "content": "<a/>"}, "decisions": {}}),
    ("/api/vendor-migrate/workspace", "vendor_migrate", "compile_upload", {"export": {"name": "e.xml", "content": "<a/>"}, "decisions": {}}),
    ("/api/logs/analyze", "log_analyzer", "analyze", {"files": [{"name": "a.log", "content": "x"}]}),
    ("/api/report/docx", "report_docx", "generate_report", {"checks": [{"id": "1.1", "label": "x", "status": "PASS"}]}),
    ("/api/compliance", "compliance_mapping", "get_framework_summary", {"checks": [{"id": "1.1", "status": "PASS"}]}),
    ("/api/compliance/drilldown", "compliance_mapping", "get_control_drilldown", {"checks": [{"id": "1.1", "status": "PASS"}]}),
    ("/api/compliance/report", "compliance_mapping", "get_framework_summary", {"checks": [{"id": "1.1", "status": "PASS"}]}),
    ("/api/benchmarks", "benchmarks", "benchmark_report", {"checks": [{"id": "1.1", "status": "PASS"}]}),
    ("/api/benchmarks/export", "benchmarks", "benchmark_report", {"checks": [{"id": "1.1", "status": "PASS"}]}),
]


@pytest.mark.parametrize("path, module, func, body", _UPLOAD_ROUTES, ids=[r[0] for r in _UPLOAD_ROUTES])
def test_upload_parsers_run_off_the_event_loop(monkeypatch, path, module, func, body):
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: parsing a 10 MB upload never blocks every other request (worker thread)."""
    import importlib
    mod = importlib.import_module(module)
    seen = []

    def probe(*args, **kwargs):
        try:
            asyncio.get_running_loop()
            seen.append("event loop")
        except RuntimeError:
            seen.append("worker thread")
        raise ValueError("probe")
    monkeypatch.setattr(mod, func, probe)
    r = _client().post(path, json=body)
    assert seen == ["worker thread"], (path, r.status_code, r.text[:200])
    if module not in ("compliance_mapping", "benchmarks"):
        assert "probe" in r.text   # an upload parser's error is answered in words, whatever its status


# ── Find anything (the browser search box) ─────────────────────────────
def test_find_anything_reads_a_bounded_query():
    """ASVS V11.1.4 · A04:2021 · CWE-400: a pasted page of text is cut to MAX_QUERY_CHARS / MAX_TERMS and the box has a maxlength."""
    src = open(os.path.join(ROOT, "static", "find_anything.js"), encoding="utf-8").read()
    assert "const MAX_QUERY_CHARS = 200, MAX_TERMS = 12;" in src
    assert "words(String(q == null ? '' : q).slice(0, MAX_QUERY_CHARS))" in src
    assert "return terms.slice(0, MAX_TERMS);" in src
    assert "maxlength: MAX_QUERY_CHARS" in src


def test_find_anything_query_cap_runs_in_node():
    """ASVS V11.1.4 · A04:2021 · CWE-400: parseQuery of 16,000 words returns at most MAX_TERMS terms (executed, not only read)."""
    import shutil
    import subprocess
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    js = ("global.document = { body: null, addEventListener() {} };"
          "const c = require(process.argv[1] + '/static/find_anything.js');"
          "const q = Array.from({length: 16000}, (_, i) => 'word' + i).join(' ');"
          "console.log(JSON.stringify([c.parseQuery(q).length, c.MAX_TERMS, c.parseQuery('terraform export').length]));")
    out = subprocess.run([node, "-e", js, ROOT], capture_output=True, text=True, timeout=30)
    assert out.returncode == 0, out.stderr
    n, cap, normal = json.loads(out.stdout)
    assert n <= cap == 12 and normal == 2


def test_base64_upload_of_a_hostile_log_through_the_api_is_bounded():
    """ASVS V12.1.1 · A04:2021 · CWE-1333 · WSTG-BUSL-09: the same hostile line uploaded as base64 through the API answers fast."""
    data = base64.b64encode(("user " + "-A" * 40000).encode()).decode()
    start = time.process_time()
    r = _client().post("/api/logs/analyze", json={"files": [{"name": "a.log", "content": data, "encoding": "base64"}]})
    assert r.status_code == 200 and time.process_time() - start < 2.0


# ── ZIP uploads: declared sizes, lying sizes ───────────────────────────
def _zip(name: str, size: int, declare: int = 0) -> str:
    """A base64 ZIP holding `size` zero bytes as `name`; with `declare`, both
    headers claim that size instead (a member that lies about its size)."""
    import io
    import struct
    import zipfile
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(name, b"0" * size)
    data = bytearray(buf.getvalue())
    if declare:
        struct.pack_into("<I", data, data.find(b"PK\x03\x04") + 22, declare)
        struct.pack_into("<I", data, data.find(b"PK\x01\x02") + 24, declare)
    return base64.b64encode(bytes(data)).decode()


def _zip_upload(route: str, b64: str):
    f = {"name": "u.zip", "content": b64, "encoding": "base64"}
    body = {"files": [f]} if route == "/api/pack-library/preview" else {"vendor": "forcepoint", "export": f}
    return _client().post(route, json=body)


def _refusal(r) -> str:
    return " ".join(r.json().get("problems") or []) if r.status_code == 200 else str(r.json().get("detail"))


@pytest.mark.parametrize("route", ["/api/pack-library/preview", "/api/vendor-migrate/inventory"])
def test_a_zip_member_that_lies_about_its_size_is_refused_in_words(route):
    """ASVS V12.1.2 · A04:2021 · CWE-409 · WSTG-BUSL-09: 5 MB of content declared as 10 bytes is read no further than declared and refused (was a 500)."""
    r = _zip_upload(route, _zip("a.json", 5 * 1024 * 1024, declare=10))
    assert r.status_code in (200, 400), r.text[:200]
    assert re.search(r"could not be read|damaged or not what it claims", _refusal(r)), _refusal(r)   # refused in words, whichever reader names it


@pytest.mark.parametrize("route, size", [("/api/pack-library/preview", 9 * 1024 * 1024), ("/api/vendor-migrate/inventory", 40 * 1024 * 1024)])
def test_a_zip_that_expands_past_the_upload_limit_is_refused_before_it_is_inflated(route, size):
    """ASVS V12.1.2 · A04:2021 · CWE-409 · WSTG-BUSL-09: a small ZIP declaring more than the limit is refused on its declared size."""
    b64 = _zip("a.json", size)
    assert len(b64) < 200_000
    cpu = time.process_time()
    r = _zip_upload(route, b64)
    assert time.process_time() - cpu < 1.0
    refused = r.status_code == 400 or r.json().get("ok") is False
    assert refused and _refusal(r), r.text[:200]   # skipped as too large (pack) or refused in words (vendor export)


@pytest.mark.parametrize("extra, status", [(0, 200), (1, 413)])
def test_a_word_report_has_a_check_limit(monkeypatch, extra, status):
    """ASVS V11.1.4 · A04:2021 · CWE-407 · WSTG-BUSL-07: _DOCX_MAX_CHECKS checks are built, one more is refused (4,000 took 70 s on the event loop)."""
    import report_docx
    built = []
    monkeypatch.setattr(srv, "_DOCX_MAX_CHECKS", 5)
    monkeypatch.setattr(report_docx, "generate_report", lambda results, cfg, path, *a: built.append(len(results)) or open(path, "wb").close())
    checks = [{"id": f"1.{i}", "label": "x", "status": "PASS"} for i in range(5 + extra)]
    r = _client().post("/api/report/docx", json={"checks": checks})
    assert r.status_code == status, r.text[:200]
    assert built == ([5] if status == 200 else [])


def test_explaining_an_engine_with_a_long_run_of_spaces_is_linear():
    """ASVS V11.1.4 · A04:2021 · CWE-1333: a 4,000-character tenant expression of spaces is explained at once (was 0.7 s each, per engine)."""
    import engine_explain
    expr = "D:a" + " " * 3990 + "x"
    assert _cpu(lambda: [engine_explain.summary(expr, {}) for _ in range(20)]) < 1.0
    assert engine_explain.summary("D:Credit  Cards   AND D:SSN > 1", {}) == \
        "Fires when the content has at least one Credit Cards match and more than one SSN match."


@pytest.mark.parametrize("extra, evaluated", [(0, True), (1, False)])
def test_the_corpus_engine_evaluator_has_an_expression_limit(extra, evaluated):
    """ASVS V11.1.4 · A04:2021 · CWE-1333: MAX_EXPRESSION characters are evaluated, one more is unknown in words (boundary)."""
    import corpus_engines
    expr = "D1.S" + " " * (corpus_engines.MAX_EXPRESSION - len("D1.S> 0") + extra) + "> 0"
    assert len(expr) == corpus_engines.MAX_EXPRESSION + extra
    result, _ids, notes = corpus_engines.evaluate_expression(expr, {1: 2})
    assert (result is True) is evaluated
    assert any("longer than" in n for n in notes) is not evaluated
    assert _cpu(corpus_engines.evaluate_expression, "(D1" + " " * 200000, {}) < 0.2


# Routes that read request.json() themselves (no request model in the OpenAPI schema).
_RAW_JSON_ROUTES = ["/api/report/xlsx", "/api/compliance", "/api/compliance/drilldown", "/api/compliance/report", "/api/benchmarks",
                    "/api/benchmarks/export", "/api/migrate/analyze", "/api/migrate/plan", "/api/migrate/export", "/api/report/docx",
                    "/api/report/findings-csv"]


def test_the_raw_json_route_list_is_complete():
    """ASVS V7.4.1 · A04:2021 · CWE-674: every handler that parses its own body is in the table below (a new one must be added)."""
    import re
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    found = set()
    for m in re.finditer(r'@app\.post\("([^"]+)"\)\nasync def \w+\([^)]*request: Request[^)]*\):(?:(?!\n@app\.).)*?await (?:request\.json\(\)|_json_object\(request\))', src, re.S):
        found.add(m.group(1))
    assert found == set(_RAW_JSON_ROUTES)


@pytest.mark.parametrize("path", _RAW_JSON_ROUTES)
def test_a_deeply_nested_body_on_a_raw_json_route_is_a_400(path):
    """ASVS V7.4.1 · A04:2021 · CWE-674 · WSTG-ERRH-01: JSON nested past the decoder's depth is a 400 in words, never a 500."""
    r = _client().post(path, content="[" * 5000 + "]" * 5000, headers={"content-type": "application/json"})
    assert r.status_code == 400, (path, r.status_code, r.text[:200])


@pytest.mark.parametrize("path", ["/api/compliance", "/api/compliance/drilldown", "/api/compliance/report", "/api/benchmarks",
                                  "/api/benchmarks/export", "/api/report/xlsx"])
@pytest.mark.parametrize("extra, refused", [(0, False), (1, True)])
def test_posted_assessment_results_have_a_check_limit(monkeypatch, path, extra, refused):
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-07: report_exports.MAX_CHECKS checks are accepted, one more is refused (boundary)."""
    import report_exports
    monkeypatch.setattr(report_exports, "MAX_CHECKS", 4)
    checks = [{"id": f"1.{i}", "label": "x", "status": "PASS", "section": "S"} for i in range(4 + extra)]
    r = _client().post(path, json={"checks": checks})
    assert (r.status_code in (400, 413) and "Too many checks" in r.text) is refused, (path, r.status_code, r.text[:200])


@pytest.mark.parametrize("size", [10, 5_000_000])
def test_a_server_error_log_entry_does_not_grow_with_the_request(capsys, monkeypatch, size):
    """ASVS V7.1.2 · A09:2021 · CWE-779 · WSTG-ERRH-01: an error quoting a 5 MB request value writes a bounded entry to server.log (was 3x the value)."""
    from starlette.requests import Request
    monkeypatch.delenv("ZSCALER_DEBUG", raising=False)
    try:
        try:
            raise KeyError("y" * size)
        except KeyError as inner:
            raise ValueError("Unknown sign-in method '" + "x" * size + "'") from inner
    except ValueError as e:
        exc = e
    req = Request({"type": "http", "method": "POST", "path": "/api/tenant/check", "headers": [], "query_string": b""})
    resp = asyncio.run(srv._safe_exception_handler(req, exc))
    logged = capsys.readouterr().out
    assert resp.status_code == 500 and "Internal error (ValueError)" in resp.body.decode()
    assert "Unknown sign-in method" in logged and "KeyError" in logged      # still says what failed
    assert len(logged) < srv._LOG_TRACE_MAX + 2 * srv._LOG_LINE_MAX + 1000
