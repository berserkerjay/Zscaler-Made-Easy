"""Flow animator (static/flow_anim.js, /report/motion): the pure models
run under node, the page follows the report-page conventions, and the
module stays read-only and self-contained."""
import json
import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")


def _read(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


NODE = shutil.which("node")


def _run(expr):
    """Evaluate `expr` with FA loaded in node; returns the JSON result."""
    script = (
        "const FA = require(%s);\n"
        "const out = (function () { %s })();\n"
        "process.stdout.write(JSON.stringify(out));\n"
    ) % (json.dumps(os.path.join(STATIC, "flow_anim.js")), expr)
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


@needs_node
def test_parse_term_reads_the_corpus_engine_explanations():
    out = _run("""return [
      FA.parseTerm('D63.S > 4: 3 → false'),
      FA.parseTerm('Sum(D1.S + D2.S) > 6: 7 → true'),
      FA.parseTerm('D9.S > 0: unknown (not simulated)'),
      FA.parseTerm('garbage')];""")
    assert out[0]["ids"] == ["63"] and out[0]["op"] == ">" and out[0]["n"] == 4 and out[0]["count"] == 3 and out[0]["ok"] is False
    assert out[1]["ids"] == ["1", "2"] and out[1]["sum"] is True and out[1]["count"] == 7 and out[1]["ok"] is True
    assert out[2]["count"] is None and out[2]["ok"] is None
    assert out[3]["ids"] == [] and out[3]["ok"] is None


@needs_node
def test_an_engine_that_does_not_fire_says_why():
    m = _run("return FA.corpusModel(FA.SAMPLE.corpus);")
    by = {e["name"]: e for e in m["engines"]}
    assert by["PII ENGINE"]["why"]["kind"] == "fires"
    near = by["PCI ENGINE"]["why"]
    assert near["kind"] == "near" and near["text"] == "near miss: 3 found, needs more than 4"
    assert by["PHI ENGINE"]["why"]["kind"] == "none"
    # Firing engines first, then near misses: the picture leads with what matters.
    assert [e["why"]["kind"] for e in m["engines"]] == ["fires", "near", "none"]
    assert {d["name"]: d["count"] for d in m["dicts"]} == {"PII – US SSN": 2, "PCI – Card numbers": 3, "PHI – Medical terms": 0}
    assert {r["name"] for r in m["rules"]} == {"PCI – Block", "PII – Monitor", "PHI – Block"}
    summary = _run("return FA.drillSummary(FA.corpusModel(FA.SAMPLE.corpus));")
    assert "PCI ENGINE does not fire, near miss: 3 found, needs more than 4, so PCI – Block never runs." in summary


@needs_node
def test_corpus_model_caps_what_one_picture_holds_and_says_so():
    m = _run("""const engines = [];
      for (let i = 0; i < 10; i++) engines.push({ name: 'E' + i, fires: false, terms: ['D' + i + '.S > 1: 0 → false'], rules: [] });
      return FA.corpusModel({ results: [], predefined: [], engines });""")
    assert len(m["engines"]) == 6 and m["hidden"]["engines"] == 4


@needs_node
def test_path_model_stops_at_the_blocking_hop_and_greys_the_rest():
    m = _run("""return FA.pathModel({ network: 'off', platform: 'windows', destination: { host: 'pastebin.com' },
      trace: { hops: [
        { key: 'zcc', status: 'pass', decided_by: { name: 'Default' }, detail: '' },
        { key: 'zia', status: 'skipped' },
        { key: 'url', status: 'blocked', decided_by: { name: 'Block paste sites' }, detail: 'Blocked.' },
        { key: 'ssl', status: 'na', detail: '' }] },
      verdict: { outcome: 'blocked', headline: 'Blocked by URL filtering.' } });""")
    keys = [h["key"] for h in m["hops"]]
    assert keys == ["device", "zcc", "url", "ssl", "dest"]   # zia skipped is dropped
    assert m["stop"] == 2 and m["hops"][2]["tone"] == "stop" and m["hops"][2]["by"] == "Block paste sites"
    assert [h["tone"] for h in m["hops"][3:]] == ["after", "after"]
    assert m["verdict"]["tone"] == "bad" and m["dest"] == "pastebin.com"


@needs_node
def test_path_drill_without_counts_is_honest_and_merges_counts_when_known():
    m = _run("return FA.pathDrillModel(FA.pathModel(FA.SAMPLE.path), null);")
    assert m["measured"] is False and all(e["why"]["kind"] == "unmeasured" for e in m["engines"])
    assert [r["action"] for r in m["rules"]] == ["BLOCK", "ALLOW", "BLOCK"]
    merged = _run("return FA.pathDrillModel(FA.pathModel(FA.SAMPLE.path), FA.corpusModel(FA.SAMPLE.corpus));")
    kinds = {e["name"]: e["why"]["kind"] for e in merged["engines"]}
    assert kinds == {"PCI ENGINE": "near", "PII ENGINE": "fires", "PHI ENGINE": "none"}
    assert merged["measured"] is True and len(merged["dicts"]) == 3


@needs_node
def test_deploy_model_builds_columns_edges_and_result_tones():
    m = _run("""const p = JSON.parse(JSON.stringify(FA.SAMPLE.deploy));
      p.results = [{ kind: 'engine', name: 'PCI engine', status: 'failed' }, { kind: 'dictionary', name: 'PCI – Card numbers', status: 'created' }];
      return FA.deployModel(p);""")
    assert [c["kind"] for c in m["cols"]] == ["template", "dictionary", "engine", "policy", "resource"]
    assert m["nodes"]["engine:PCI engine"]["tone"] == "stop"
    assert m["nodes"]["dictionary:PCI – Card numbers"]["tone"] == "pass"
    assert m["nodes"]["dictionary:PHI – Medical terms"]["tone"] == "reuse"
    assert {"from": "template:CREDIT_CARDS", "to": "dictionary:PCI – Card numbers"} in m["edges"]
    # A missing prerequisite hangs off the rule that needs it.
    assert {"from": "policy:SaaS – PHI (monitor)", "to": "resource:SaaS tenant"} in m["edges"]
    assert m["nodes"]["resource:SaaS tenant"]["tone"] == "stop"


@needs_node
def test_deploy_model_folds_long_columns():
    m = _run("""const items = [];
      for (let i = 0; i < 40; i++) items.push({ kind: 'policy', name: 'R' + i, status: 'create', depends_on: ['engine:E'] });
      items.push({ kind: 'engine', name: 'E', status: 'create', depends_on: [] });
      return FA.deployModel({ items });""")
    pol = [c for c in m["cols"] if c["kind"] == "policy"][0]
    assert len(pol["keys"]) == 12 and pol["keys"][-1] == "policy:__more"
    assert m["nodes"]["policy:__more"]["name"] == "+29 more"
    assert {"from": "engine:E", "to": "policy:__more"} in m["edges"]
    assert m["counts"] == {"create": 41}


@needs_node
def test_live_model_keeps_no_user_or_file_names():
    m = _run("""return FA.liveModel({ id: 7, channel: 'endpoint', user: 'alice@example.com', user_name: 'Alice', file: 'secrets.xlsx',
      rules: ['EP – PII'], engines: ['PII'], dictionaries: [{ name: 'SSN', count: 2 }, { name: 'CC', count: 9 }],
      enforcement: 'monitor', host: 'usb' });""")
    flat = json.dumps(m)
    assert "alice" not in flat.lower() and "secrets.xlsx" not in flat
    assert m["channel"] == "endpoint" and m["dicts"][0] == {"name": "CC", "count": 9} and m["enforcement"] == "monitor"
    assert _run("return FA.liveModel({ channel: 'other' }).channel;") == "web"


@needs_node
def test_architecture_flows_follow_the_reference_sections():
    flows = _run("return FA.ARCH.map(f => ({ id: f.id, anchor: f.anchor, n: f.steps.length, gates: f.steps.filter(s => s.gate).length }));")
    ref = _read(os.path.join("reference", "data-security-architect.html"))
    for f in flows:
        assert f'<section id="{f["anchor"]}"' in ref, f["anchor"]
        assert f["n"] >= 5 and f["gates"] >= 1, f
    assert [f["id"] for f in flows] == ["chain", "dictionaries", "engines", "inline", "endpoint", "email", "saas", "edmidm", "aisec", "workflow"]


def test_module_is_self_contained_and_motion_safe():
    js = _read("flow_anim.js")
    assert "(prefers-reduced-motion: reduce)" in js and "visibilitychange" in js
    assert "requestAnimationFrame" in js and "cancelAnimationFrame" in js
    assert 'role: \'img\'' in js and "aria-label" in js
    assert not re.search(r"https?://(?!www\.w3\.org/2000/svg)", js), "no external URLs"
    assert "fetch(" not in js, "the module never reads the tenant itself"
    assert "flatMap" not in js and "?." not in js and "??" not in js
    assert "localStorage" not in js, "the module keeps nothing; the page decides"
    css = _read("flow_anim.css")
    assert "@media (prefers-reduced-motion: reduce)" in css
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", css.replace("#fff", "")), "theme colours only"


def test_page_follows_report_conventions():
    html = _read("report_motion.html")
    order = ["/static/icons.js", "/static/ui_auth.js", "/static/report_theme.js", "/static/safety_banner.js", "/static/explain.js", "/static/flow_anim.js"]
    pos = [html.index(f'<script src="{s}"></script>') for s in order]
    assert pos == sorted(pos)
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html
    assert 'href="/"' in html and "<main" in html and "<h1" in html
    assert 'role="status"' in html and 'aria-live="polite"' in html
    assert html.count('<button type="button" role="tab"') == 5 and html.count('role="tabpanel"') == 5
    # Samples are always labelled as samples.
    assert html.count("SAMPLE_TAG") >= 3


def test_page_reads_only_the_existing_read_only_endpoints():
    html = _read("report_motion.html")
    endpoints = set(re.findall(r"fetch\('([^']+)'", html))
    assert endpoints == {"/api/tenant-profiles", "/api/dlp/efficacy/test", "/api/live-feed"}
    # Live incidents and test content stay in memory: nothing about them is stored.
    assert "setItem" not in html


def test_path_analyzer_hands_its_result_over_without_the_log():
    html = _read("report_path.html")
    assert "keepForAnimator(res);" in html and "delete slim.logs" in html
    assert "localStorage.setItem('zassess_path_last'" in html
    assert 'href="/report/motion#path"' in html
    assert html.count("motion.update(") == 1


def test_page_is_served_and_listed(client=None):
    from fastapi.testclient import TestClient
    import dlp_api_server
    c = TestClient(dlp_api_server.app)
    r = c.get("/report/motion", headers={"Host": "127.0.0.1:8000"})
    assert r.status_code in (200, 401, 403)
    src = open(os.path.join(ROOT, "dlp_api_server.py"), encoding="utf-8").read()
    assert '"/report/motion"' in src
    assert "X.motion = {" in _read("explain.js") and "'/report/motion': 'motion'" in _read("explain.js")
    assert 'onclick="openFlowAnimatorTab()"' in _read("index.html")


def test_architecture_overlay_greys_every_step_after_the_stop():
    """With a path that stops at the PAC file, the inline flow marks
    Capture as the stop and nothing after it as passed, even steps the
    path analyzer has no hop for (threat checks, rule action)."""
    js = _read("flow_anim.js")
    assert "stopAt >= 0 && k > stopAt ? 'after'" in js
