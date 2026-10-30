"""Traffic motion models (static/flow_anim.js: dataFlowModel, sslWalkModel,
sslCoverageModel) run under node against reports the app's own code builds
from fake tenant reads. Every number a picture carries must be the page's
own number (report.summary, volume.protocols[unit], summary.by_kind), and
the shares must add up: a second count that could drift fails here.
Table-driven over scopes, units and traffic classes; deterministic (no
clock, network or randomness)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

import flow_motion_fixtures as fx
import ssl_flow as sf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")


def _run(expr, **data):
    """Evaluate `expr` with FA loaded and `data` bound by name; returns its JSON."""
    script = ("const FA = require(%s);\nconst D = JSON.parse(require('fs').readFileSync(0, 'utf8'));\n"
              "const out = (function () { %s })();\nprocess.stdout.write(JSON.stringify(out));\n"
              ) % (json.dumps(os.path.join(ROOT, "static", "flow_anim.js")), expr)
    r = subprocess.run([NODE, "-e", script], input=json.dumps(data, default=str), capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ── Data Flow Map ───────────────────────────────────────────────────
SCOPES = {
    "everything in scope": ("dlp", "zcc", "zia_extras"),
    "Client Connector only (SSL not read)": ("zcc",),
    "DLP without Client Connector": ("dlp", "zia_extras"),
}


@pytest.fixture(scope="module", params=list(SCOPES), ids=list(SCOPES))
def dataflow(request):
    rep = fx.dataflow_report(SCOPES[request.param])
    return rep, _run("return FA.dataFlowModel(D.rep);", rep=rep)


@needs_node
def test_data_flow_streams_are_the_summary_numbers(dataflow):
    """CWE-684 · ASVS V1.4.4: every visibility class (bypassed, blind, enforced, monitored, blocked, unverified, decrypted_other) streams report.summary's own number."""
    # Arrange
    rep, m = dataflow
    s = rep["summary"]
    keys = ("traces", "bypassed", "blind", "enforced", "monitored", "blocked", "unverified", "decrypted_other")
    # Act
    c = m["counts"]
    # Assert
    assert m["mismatch"] == []
    assert tuple(c[k] for k in keys) == tuple(s[k] for k in keys)
    assert m["total"] == s["traces"] and m["summary"] == {k: s[k] for k in keys}


@needs_node
def test_data_flow_every_path_ends_once_and_the_shares_sum_to_one(dataflow):
    """CWE-682: each traced path lands in exactly one terminal stream; the shares add up to 100%."""
    rep, m = dataflow
    assert sum(t["count"] for t in m["terminals"]) == len(rep["traces"])
    assert abs(sum(t["share"] for t in m["terminals"]) - 1.0) < 1e-9
    assert len(m["routes"]) == len(rep["traces"]) and all(r["weight"] == 1 for r in m["routes"])


@needs_node
def test_data_flow_streams_conserve_paths_at_every_hop(dataflow):
    """CWE-682: what flows into a hop flows out of it (or ends there); each stream's width is its own path count."""
    rep, m = dataflow
    value = {n["key"]: n["value"] for n in m["nodes"]}
    for l in m["links"]:
        assert l["value"] == len(l["items"]) > 0, l["key"]
    for key, v in value.items():
        ins = sum(l["value"] for l in m["links"] if l["to"] == key)
        outs = sum(l["value"] for l in m["links"] if l["from"] == key)
        assert key == "src" or ins == v, key
        terminal = any(t["key"] == key for t in m["terminals"])
        assert outs == (0 if terminal or key == "incident" else v) or (key.startswith("o_") and outs <= v), key


@needs_node
def test_data_flow_words_say_the_summary_numbers(dataflow):
    """WCAG 2.2 SC 1.1.1 · CWE-684: the text alternative states the page's own numbers."""
    rep, m = dataflow
    s = rep["summary"]
    words = " ".join(m["alt"])
    assert f"{s['traces']} paths traced" in words
    assert f"Never reach Zscaler: {s['bypassed']}" in words and f"Reach ZIA, left encrypted (Web DLP is blind): {s['blind']}." in words
    assert f"A DLP rule can block: {s['enforced']}." in words and f"DLP monitors only: {s['monitored']}." in words


@needs_node
def test_data_flow_each_stream_links_to_its_table_rows(dataflow):
    """WCAG 2.2 SC 2.4.4: a stream lists the paths it carries by their row in the destination × network table."""
    rep, m = dataflow
    for l in m["links"]:
        for it in l["items"]:
            t = rep["traces"][it["i"]]
            assert it["name"].startswith(t["destination"]["label"] + " · ")


def _trace(**kw):
    hops = kw.pop("hops")
    base = {"destination": {"label": "x"}, "network": "off", "reaches_zscaler": True, "conditional": False, "decrypted": True, "outcome": "monitor"}
    base.update(kw)
    base["hops"] = [{"key": k, "status": st} for k, st in hops]
    return base


ROUTES = [
    ("app profile bypass", _trace(reaches_zscaler=False, decrypted=False, outcome="bypassed", hops=[("zcc", "bypass")]), ["src", "cc", "x_cc"]),
    ("PAC sends it direct", _trace(reaches_zscaler=False, decrypted=False, outcome="bypassed", hops=[("zcc", "pass"), ("forwarding", "pass"), ("pac", "bypass")]), ["src", "cc", "pac", "x_pac"]),
    ("routing unverified", _trace(conditional=True, outcome="unknown", hops=[("zcc", "unknown")]), ["src", "cc", "u_cc"]),
    ("PAC answer unverified", _trace(conditional=True, outcome="unknown", hops=[("zcc", "pass"), ("forwarding", "pass"), ("pac", "unknown")]), ["src", "cc", "pac", "u_pac"]),
    ("URL filtering blocks", _trace(outcome="blocked", decrypted=False, hops=[("url", "blocked"), ("ssl", "not_reached")]), ["src", "cc", "pac", "policy", "b_policy"]),
    ("SSL blocks", _trace(outcome="blocked", decrypted=False, hops=[("url", "pass"), ("ssl", "blocked")]), ["src", "cc", "pac", "policy", "ssl", "b_ssl"]),
    ("left encrypted", _trace(outcome="blind", decrypted=False, hops=[("ssl", "blind"), ("dlp", "blind")]), ["src", "cc", "pac", "policy", "ssl", "enc"]),
    ("SSL not in scope", _trace(outcome="unknown", decrypted=False, hops=[("ssl", "out_of_scope")]), ["src", "cc", "pac", "policy", "ssl", "u_ssl"]),
    ("File Type Control blocks", _trace(outcome="blocked", hops=[("ssl", "pass"), ("ftc", "blocked")]), ["src", "cc", "pac", "policy", "ssl", "dlp", "o_block"]),
    ("enforce with a receiver", _trace(outcome="enforce", hops=[("ssl", "pass"), ("dlp", "enforce"), ("incident", "conditional")]), ["src", "cc", "pac", "policy", "ssl", "dlp", "o_enforce", "incident"]),
    ("monitor, logs only", _trace(outcome="monitor", hops=[("ssl", "pass"), ("dlp", "monitor"), ("incident", "warn")]), ["src", "cc", "pac", "policy", "ssl", "dlp", "o_monitor"]),
    ("no DLP rule", _trace(outcome="none", hops=[("ssl", "pass"), ("dlp", "none")]), ["src", "cc", "pac", "policy", "ssl", "dlp", "o_other"]),
    # The precedence the summary uses (data_flow.visibility): unverified before bypassed, blocked before decrypted.
    ("conditional bypass", _trace(conditional=True, reaches_zscaler=False, decrypted=False, outcome="bypassed", hops=[("zcc", "bypass")]),
     ["src", "cc", "u_cc"]),
    ("policy depends on the user", _trace(policy_conditional=True, outcome="monitor", hops=[("ssl", "pass"), ("dlp", "monitor")]),
     ["src", "cc", "pac", "policy", "ssl", "u_ssl"]),
    ("blocked, never decrypted", _trace(outcome="blocked", decrypted=False, hops=[("url", "pass"), ("ssl", "blind")]),
     ["src", "cc", "pac", "policy", "ssl", "b_ssl"]),
]
# The visibility class each end node stands for (data_flow.VISIBILITY).
END_CLASS = {"x_cc": "bypassed", "x_pac": "bypassed", "u_cc": "unverified", "u_pac": "unverified", "u_ssl": "unverified",
             "b_policy": "blocked", "b_ssl": "blocked", "o_block": "blocked", "enc": "blind",
             "o_enforce": "enforce", "o_monitor": "monitor", "o_other": "decrypted"}


@needs_node
@pytest.mark.parametrize("name,trace,route", ROUTES, ids=[r[0] for r in ROUTES])
def test_each_trace_takes_the_route_its_hops_describe(name, trace, route):
    """CWE-684: bypasses leave at the hop that bypasses (with a marker), blocks where they block, the rest split at SSL."""
    assert _run("return FA.dfRoute(D.t);", t=trace) == route


@pytest.mark.parametrize("name,trace,route", ROUTES, ids=[r[0] for r in ROUTES])
def test_each_route_ends_in_the_class_the_summary_counts_it_in(name, trace, route):
    """CWE-684 · CWE-682: the end node of every route is the trace's own class in data_flow.visibility, so picture and summary agree."""
    import data_flow
    end = [k for k in route if k in END_CLASS][-1]
    assert END_CLASS[end] == data_flow.visibility(trace), (name, end)


@needs_node
@pytest.mark.parametrize("key,trace", [("blocked", ROUTES[4][1]), ("unverified", ROUTES[2][1]), ("decrypted_other", ROUTES[11][1])])
def test_a_summary_that_disagrees_on_any_class_is_said(key, trace):
    """CWE-684 · CISA Secure by Design (fail visibly): a blocked, unverified or decrypted_other count the picture does not match is named."""
    s = {"traces": 1, "bypassed": 0, "blind": 0, "enforced": 0, "monitored": 0, "blocked": 0, "unverified": 0, "decrypted_other": 0}
    s[key] = 7
    m = _run("return FA.dataFlowModel(D.rep);", rep={"summary": s, "networks": [], "traces": [trace]})
    assert m["mismatch"] == [f"{key}: picture 1, summary 7"], m["mismatch"]


def test_flow_anim_declares_no_unused_constant():
    """ASVS V1.14.1 · CWE-1164 (Irrelevant Code): every top-level constant of the motion engine is used (SSL_UNVERIFIED was left behind)."""
    import re
    src = open(os.path.join(ROOT, "static", "flow_anim.js"), encoding="utf-8").read()
    names = re.findall(r"^  const ([A-Z][A-Z0-9_]+)\s*=", src, re.M)
    assert len(names) > 10
    dead = [n for n in names if len(re.findall(r"\b%s\b" % n, src)) < 2]
    assert not dead, dead


@needs_node
def test_bypass_and_block_exits_carry_a_marker():
    """WCAG 2.2 SC 1.4.1: a stream that leaves the flow is marked by a shape, not colour alone."""
    rep = {"summary": {"traces": 3, "bypassed": 2, "blind": 0, "enforced": 0, "monitored": 0, "destinations": 1},
           "networks": [{"key": "off", "label": "Off"}], "traces": [r[1] for r in ROUTES[:2]] + [ROUTES[4][1]]}
    m = _run("return FA.dataFlowModel(D.rep);", rep=rep)
    exits = {n["key"]: n["exit"] for n in m["nodes"] if n["exit"]}
    assert exits == {"x_cc": "bypass", "x_pac": "bypass", "b_policy": "blocked"}
    assert m["counts"]["bypassed_cc"] + m["counts"]["bypassed_pac"] == rep["summary"]["bypassed"] and m["mismatch"] == []


@needs_node
def test_a_summary_that_disagrees_is_said_not_hidden():
    """CWE-684 · CISA Secure by Design (fail visibly): if the picture and the summary ever differ, the model says so."""
    rep = {"summary": {"traces": 1, "bypassed": 5, "blind": 0, "enforced": 0, "monitored": 0}, "networks": [], "traces": [ROUTES[0][1]]}
    m = _run("return FA.dataFlowModel(D.rep);", rep=rep)
    assert m["mismatch"] == ["bypassed: picture 1, summary 5"]


@needs_node
@pytest.mark.parametrize("bad", [None, {}, {"traces": []}, {"summary": {}}])
def test_data_flow_model_refuses_what_is_not_a_report(bad):
    """CWE-20: anything that is not a Data Flow Map report draws nothing."""
    assert _run("return FA.dataFlowModel(D.bad);", bad=bad) is None


# ── SSL flow: the rule walk ─────────────────────────────────────────
@pytest.fixture(scope="module")
def sslflow():
    rep = fx.sslflow_report()
    keys = [c["key"] for c in rep["classes"]]
    return rep, dict(zip(keys, _run("return D.keys.map(k => FA.sslWalkModel(D.rep, k));", rep=rep, keys=keys)))


@needs_node
@pytest.mark.parametrize("key", [c["key"] for c in fx.sslflow_report()["classes"]])
def test_the_walk_meets_every_enabled_rule_in_order_and_the_page_decider_decides(sslflow, key):
    """CWE-684: the rule that decides in the walk is the page's decided_by; every enabled rule is met once, in order."""
    rep, walks = sslflow
    c = next(x for x in rep["classes"] if x["key"] == key)
    m = walks[key]
    enabled = [r for r in rep["ssl_rules"] if r["enabled"]]
    met = sum(s["count"] if s["kind"] in ("skip", "after") else 0 if s["kind"] == "none" else 1 for s in m["steps"])
    assert met == len(enabled)
    deciders = [s for s in m["steps"] if s["kind"] == "decide"]
    if c["decided_by"]:
        assert [d["name"] for d in deciders] == [c["decided_by"]["name"]] and m["decision"] == c["decision"]
    else:
        assert deciders == [] and m["steps"][-1]["kind"] in ("none", "skip")
    assert [s["name"] for s in m["steps"] if s["kind"] == "exception"] == [e["name"] for e in c["exceptions"]]
    assert m["peels"] == len(c["exceptions"])
    assert next(s for s in m["steps"] if s["kind"] == "after")["shadowed"] == [r["name"] for r in c["shadowed"]] if c["shadowed"] else True


@needs_node
def test_certificate_and_tls_checks_are_gates_of_the_deciding_rule(sslflow):
    """CWE-684: the gates show the deciding rule's own certificate and TLS-version sub-actions, and 'not in the rule data' when it has none."""
    rep, walks = sslflow
    ai = {g["key"]: g for g in walks["ai_ml"]["gates"]}
    assert ai["tls"]["known"] and ai["tls"]["text"] == "client at least TLS 1.2; server at least TLS 1.2"
    assert ai["cert"]["text"] == "untrusted certificate: block; OCSP revocation check on; no SNI: blocked"
    files = {g["key"]: g for g in walks["file_share"]["gates"]}   # decided by "DNI file hosts": DNI sub-actions
    assert files["tls"]["text"] == "server at least TLS 1.0" and not files["cert"]["known"]
    assert walks["remote"]["gates"] == [], "a blocked request meets no gate"
    general = {g["key"]: g for g in walks["general"]["gates"]}
    assert general["cert"]["text"] == "untrusted certificate: pass thru; OCSP revocation check off"


@needs_node
def test_the_walk_words_name_each_rule_and_the_outcome(sslflow):
    """WCAG 2.2 SC 1.1.1: the walk's text alternative names each rule met, the decider, the gates and what Web DLP sees."""
    rep, walks = sslflow
    m = walks["file_share"]
    words = " ".join(m["alt"])
    assert "Exec bypass (order 2)" in words and "DNI file hosts (order 4) decides: DO_NOT_DECRYPT." in words
    assert "Gate: TLS version check: server at least TLS 1.0." in words and words.endswith("Then: Web DLP blind (still encrypted).")


def test_tls_checks_read_both_spellings_and_never_invent_a_setting():
    """CWE-20 · CWE-684: the SDK's camelCase and snake_case sub-action names are read; no sub-actions is None, not 'off'."""
    camel = sf.tls_checks({"action": {"type": "DECRYPT", "decryptSubActions": {"serverCertificates": "block", "ocspCheck": "true", "minClientTLSVersion": "CLIENT_TLS_1_3"}}})
    snake = sf.tls_checks({"action": {"type": "DO_NOT_DECRYPT", "do_not_decrypt_sub_actions": {"min_tls_version": "SERVER_TLS_1_1", "block_ssl_traffic_with_no_sni_enabled": False}}})
    assert camel["server_certificates"] == "BLOCK" and camel["ocsp_check"] is True and camel["min_client_tls"] == "CLIENT_TLS_1_3" and camel["min_server_tls"] is None
    assert snake["min_server_tls"] == "SERVER_TLS_1_1" and snake["block_no_sni"] is False and snake["ocsp_check"] is None
    assert sf.tls_checks({"action": "DECRYPT"}) is None and sf.tls_checks({"action": {"type": "DECRYPT"}}) is None
    assert sf.normalize_ssl_rule({"id": 1, "action": {"type": "DECRYPT"}})["checks"] is None


# ── SSL coverage: the traffic river ─────────────────────────────────
@pytest.fixture(scope="module")
def coverage():
    rep = fx.sslcoverage_report()
    return rep, {u: _run("return FA.sslCoverageModel(D.rep, D.u);", rep=rep, u=u) for u in ("BYTES", "TRANSACTIONS")}


@needs_node
@pytest.mark.parametrize("unit", ["BYTES", "TRANSACTIONS"])
def test_stream_widths_are_the_insights_numbers_of_the_unit(coverage, unit):
    """CWE-684: each traffic stream is the page's own Insights number in the chosen unit, nothing recomputed."""
    rep, models = coverage
    sel, m = rep["volume"]["protocols"][unit], models[unit]["traffic"]
    b = sel["buckets"]
    links = {l["key"]: l["value"] for l in m["links"]}
    assert links.get("reach>ssl") == sel["ssl_total"] and links.get("reach>http", 0) == sel["http_total"]
    assert links.get("ssl>ins", 0) == b["ssl_inspected"] and links.get("ssl>unins", 0) == b["ssl_not_inspected"]
    assert links.get("other>other_x", 0) == sel["other_total"]
    assert m["total"] == sel["ssl_total"] + sel["http_total"]
    assert m["shares"]["ssl_inspected_pct"] == sel["ssl_pct"] and m["shares"]["total_pct"] == sel["total_pct"] and m["shares"]["http_pct"] == sel["http_pct"]


@needs_node
@pytest.mark.parametrize("unit", ["BYTES", "TRANSACTIONS"])
def test_inspected_and_uninspected_shares_split_to_one_hundred(coverage, unit):
    """CWE-682: the inspected and the left-encrypted share of SSL/TLS add up to 100%, and the streams to the whole."""
    rep, models = coverage
    m = models[unit]["traffic"]
    assert round(m["shares"]["ssl_inspected_pct"] + m["shares"]["ssl_not_inspected_pct"], 6) == 100
    out = sum(l["value"] for l in m["links"] if l["from"] == "reach")
    assert out == m["total"]
    for n in m["nodes"]:
        if n["key"] in ("ins", "unins"):
            assert n["value"] == sum(l["value"] for l in m["links"] if l["to"] == n["key"])


@needs_node
def test_the_cause_branches_are_their_share_of_the_causes(coverage):
    """CWE-682 · CWE-684: Do not inspect rules, exemptions, Client Connector and PAC bypass are each their share of summary.causes."""
    rep, models = coverage
    s, m = rep["summary"], models["BYTES"]["causes"]
    by = {g["key"]: g["count"] for g in m["groups"]}
    kinds = s["by_kind"]
    assert by["dni"] == sum(kinds.get(k, 0) for k in ("ssl_rule", "ssl_rule_scoped", "catch_all", "scoped_catch_all"))
    assert by["exempt"] == kinds.get("pinned_exemptions", 0) and by["pac"] == kinds.get("pac_direct", 0)
    assert by["zcc"] == sum(v for k, v in kinds.items() if k.startswith("zcc_") or k == "forwarding_none")
    assert sum(by.values()) == s["causes"] == m["total"]
    assert abs(sum(g["share"] for g in m["groups"]) - 1.0) < 1e-9
    never = next(n for n in m["nodes"] if n["key"] == "never")
    assert never["exit"] == "bypass" and never["value"] == by["zcc"] + by["pac"]


@needs_node
def test_the_river_words_use_the_page_percentages(coverage):
    """WCAG 2.2 SC 1.1.1 · CWE-684: the words say the page's percentages, formatted by the page's own formatter."""
    rep, _ = coverage
    m = _run("return FA.sslCoverageModel(D.rep, 'TRANSACTIONS', { pct: p => p == null ? 'not measurable' : p + '%', amount: v => 'n' + v });", rep=rep)
    sel = rep["volume"]["protocols"]["TRANSACTIONS"]
    words = " ".join(m["alt"])
    assert f"SSL/TLS: {sel['ssl_pct']:g}% inspected" in words and f"In total {sel['total_pct']:g}% of SSL/TLS and HTTP is inspected." in words   # JS prints 75, not 75.0
    assert f"SSL/TLS n{sel['ssl_total']:g} and HTTP n{sel['http_total']:g}" in words


@needs_node
def test_without_traffic_numbers_the_river_is_the_kinds_of_traffic():
    """CWE-684: no Insights numbers means no byte river; the page's class counts are drawn and it says so."""
    rep = fx.sslcoverage_report(volume=False)
    s = rep["summary"]
    m = _run("return FA.sslCoverageModel(D.rep, 'BYTES');", rep=rep)
    t = m["traffic"]
    assert t["unit"] == "kinds" and t["total"] == s["classes_total"] and "not read" in m["note"]
    links = {l["key"]: l["value"] for l in t["links"]}
    assert links.get("kinds>cov", 0) == s["classes_covered"] and links.get("kinds>enc", 0) == s["classes_not_inspected"]
    assert links.get("kinds>cov", 0) + links.get("kinds>enc", 0) == s["classes_total"]


@needs_node
def test_nothing_measured_draws_no_empty_stream():
    """CWE-369: zero traffic draws no river (never a 0% or a division by zero), and a zero stream is left out."""
    rep = fx.sslcoverage_report()
    for u in ("BYTES", "TRANSACTIONS"):
        rep["volume"]["protocols"][u] = {"buckets": {"ssl_inspected": 0, "ssl_not_inspected": 0, "http": 0, "other": 0}, "ssl_total": 0, "http_total": 0,
                                         "other_total": 0, "ssl_pct": None, "http_pct": None, "total_pct": None}
    m = _run("return FA.sslCoverageModel(D.rep, 'BYTES');", rep=rep)
    assert m["traffic"]["unit"] == "kinds", "falls back to the kinds of traffic"
    rep2 = fx.sslcoverage_report()
    rep2["volume"]["protocols"]["BYTES"]["http_total"] = 0
    rep2["volume"]["protocols"]["BYTES"]["buckets"]["http"] = 0
    m2 = _run("return FA.sslCoverageModel(D.rep, 'BYTES');", rep=rep2)
    assert all(l["value"] > 0 for l in m2["traffic"]["links"]) and "http" not in {n["key"] for n in m2["traffic"]["nodes"]}


# ── Engine rules ────────────────────────────────────────────────────
def test_one_engine_no_external_scripts_and_motion_safety():
    """WCAG 2.2 SC 2.2.2 · SC 2.3.3 · ASVS V14.2.3: the three pages reuse flow_anim.js only, local scripts only, reduced motion honoured."""
    pages = {"report_dataflow.html": "data_flow.js", "report_sslflow.html": "ssl_flow.js", "report_ssl_coverage.html": None}
    for page, own in pages.items():
        html = open(os.path.join(ROOT, "static", page), encoding="utf-8").read()
        assert '<script src="/static/flow_anim.js"></script>' in html and '<link rel="stylesheet" href="/static/flow_anim.css">' in html, page
        assert "<script src=\"http" not in html and "requestAnimationFrame" not in html, page   # one engine: the clock lives in flow_anim.js
        if own:
            assert html.index("/static/flow_anim.js") < html.index(f"/static/{own}"), page
    for own in ("data_flow.js", "ssl_flow.js"):
        js = open(os.path.join(ROOT, "static", own), encoding="utf-8").read()
        assert "requestAnimationFrame" not in js, own
    js = open(os.path.join(ROOT, "static", "flow_anim.js"), encoding="utf-8").read()
    assert "if (!reduced() && o.autoplay !== false) s.play();" in js, "reduced motion starts still"
    css = open(os.path.join(ROOT, "static", "reports.css"), encoding="utf-8").read()
    assert ".sf-edge.flow { animation: none; }" in css, "the SSL flow's dashed edges stop under reduced motion"
