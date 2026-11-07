"""Live motion on the ZPA, Traffic insights, Live DLP feed and Bypass pages
(static/flow_pages.js on the Flow animator's engine, static/flow_anim.js).

The models run under node on payloads the real modules build from fakes
(zpa_reader / zpa_analysis / zpa_overview over the messy and clean ZPA
tenants, insights.read over the fake Z-Insights executor,
bypass_report.generate_bypass_report over a fake client), and every
number a flow draws is checked against the page's own number. A real
headless Chrome then opens each page on the real app (reports kept in
memory, the two polled feeds answered by a page-local stub) and checks
that the picture renders, moves, stops under reduced motion, has a text
alternative, works by keyboard and never scrolls the page sideways at 320
and 390 px. Browser checks skip without node and Chrome."""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

import bypass_report as br
import insights
import zpa_analysis as za
import zpa_overview as zo
import zpa_reader as zr
from test_csv_injection import FakeCl
from test_findings_reflow import CDP_PRELUDE, run_in_browser
from test_insights import _read as insights_read, tenant as insights_tenant
from test_zpa_analysis import ENG, NOW, clean, messy, read

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATIC = os.path.join(ROOT, "static")
NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not installed")
PAGES = {"zpa": "report_zpa.html", "insights": "report_insights.html", "live": "report_live.html", "bypass": "report_bypass.html"}
SALES = {"scim_groups": [], "saml": "Department=Sales", "client_type": "zpn_client_type_zapp", "posture_pass": []}
CONTRACTOR = {"scim_groups": ["Contractors"], "client_type": "zpn_client_type_zapp", "posture_pass": [], "saml": "Department=Engineering"}
NOBODY = {"scim_groups": [], "client_type": "zpn_client_type_zapp", "posture_pass": [], "saml": "Department=Ops"}


def _static(name):
    with open(os.path.join(STATIC, name), encoding="utf-8") as f:
        return f.read()


def _fp(tmp_path, expr, data):
    """Evaluate `expr` with FP (static/flow_pages.js) and `data` loaded in node."""
    src = tmp_path / "data.json"
    src.write_text(json.dumps(data), encoding="utf-8")
    script = ("const FP = require(%s);\nconst data = JSON.parse(require('fs').readFileSync(%s, 'utf8'));\n"
              "const out = (function () { %s })();\nprocess.stdout.write(JSON.stringify(out));\n") % (
        json.dumps(os.path.join(STATIC, "flow_pages.js")), json.dumps(str(src)), expr)
    r = subprocess.run([NODE, "-e", script], capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout)


# ── Payloads, built by the real modules from fakes ─────────────────────
def _zpa_overview(data=None):
    snap = read(data)
    an = za.analyze(snap, now=NOW)
    return snap, an, zo.overview(snap, an)


def zpa_report():
    """The stored report of a ZPA analysis job (as dlp_api_server._run_zpa_read builds it)."""
    snap, an, ov = _zpa_overview()
    return {"kind": "zpa", "snapshot": snap, "summary": zr.summary(snap), "collections": snap.get("collections") or {},
            "readable": zr.readable(snap), "choices": za.choices(snap), "read_at": snap.get("read_at"), "overview": ov,
            "findings": an["findings"], "catalog": an["catalog"], "counts": an["counts"], "not_assessed": an["not_assessed"],
            "assumptions": za.ASSUMPTIONS}


def insights_result():
    return insights_read(insights_tenant())


BYPASS_ROUTES = {
    "/zia/sslInspectionRules": [{"id": 2, "name": "Banks", "order": 1, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["bank.example"]},
                                {"id": 3, "name": "Health", "order": 2, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urls": ["clinic.example"]},
                                {"id": 4, "name": "Decrypt all", "order": 3, "state": "ENABLED", "action": {"type": "DECRYPT"}}],
    "/zia/urlFilteringRules": [{"id": 5, "name": "Allow partners", "order": 1, "state": "ENABLED", "action": "ALLOW", "urls": ["partner.example"]}],
    "/zcc/webPolicies": [{"id": 9, "name": "Default", "bypassApps": ["Teams.exe", "Zoom.exe"], "bypassDomains": ["update.example"],
                          "bypassIps": ["10.0.0.0/8"], "trustedNetworks": ["HQ"]}],
}


def bypass_rep(routes=None):
    return br.generate_bypass_report(FakeCl(dict(BYPASS_ROUTES if routes is None else routes)))


# ── ZPA infrastructure ─────────────────────────────────────────────────
@needs_node
def test_zpa_connections_carry_the_maps_own_boxes_and_connector_counts(tmp_path):
    """WCAG 2.2 SC 1.1.1: the ZPA connections flow draws the map's IdPs, connector groups and segments, and its down / outdated counts equal the overview's."""
    # Arrange
    _, _, ov = _zpa_overview()
    g = ov["graph"]
    kpi = {k["key"]: k["value"] for k in ov["kpis"]}
    # Act
    m = _fp(tmp_path, "return FP.zpaInfraModel(data);", g)
    # Assert
    ids = lambda col: [n["id"] for n in g["nodes"] if n["col"] == col]  # noqa: E731
    cols = {c["key"]: [n["id"] for n in c["nodes"]] for c in m["cols"]}
    assert cols["users"] == ids("idps") and cols["groups"] == ids("connector_groups") and cols["apps"] == ids("segments")
    assert cols["cloud"] == ["zpa:cloud"]
    assert m["connectors"] == {"down": kpi["connectors_down"], "outdated": kpi["connectors_outdated"]}
    assert sum(m["tally"].values()) == len(m["links"])
    by = {x["label"]: x for x in m["groups"]}
    assert by["DC1 connectors"]["state"] == "live"
    assert by["DC2 connectors"]["state"] == "stop" and "dc2-a" in by["DC2 connectors"]["reason"]
    assert by["Branch connectors"]["state"] == "flicker" and "branch-b" in by["Branch connectors"]["reason"]
    assert by["Empty connectors"]["state"] == "stop"


@needs_node
def test_zpa_group_to_segment_links_follow_the_server_groups_and_inherit_the_groups_health(tmp_path):
    """WCAG 2.2 SC 1.3.1: every group → app segment link is a real segment → server group → connector group chain of the map, in the group's state."""
    # Arrange
    _, _, ov = _zpa_overview()
    g = ov["graph"]
    col = {n["id"]: n["col"] for n in g["nodes"]}
    want = set()
    for s, sg in g["edges"]:
        if col.get(s) == "segments" and col.get(sg) == "server_groups":
            want |= {(cg, s) for a, cg in g["edges"] if a == sg and col.get(cg) == "connector_groups"}
    # Act
    m = _fp(tmp_path, "return FP.zpaInfraModel(data);", g)
    # Assert
    got = {(l["from"], l["to"]) for l in m["links"] if l["from"] != "zpa:cloud" and l["to"] != "zpa:cloud"}
    assert got == want and want
    state = {x["id"]: x["state"] for x in m["groups"]}
    for l in m["links"]:
        if (l["from"], l["to"]) in want and state[l["from"]] != "live":
            assert l["state"] == state[l["from"]]


@needs_node
def test_a_healthy_zpa_tenant_has_no_stopped_or_flickering_link(tmp_path):
    """WCAG 2.2 SC 1.1.1: on the clean tenant every connector group carries traffic (negative case: nothing marked red)."""
    _, _, ov = _zpa_overview(clean())
    m = _fp(tmp_path, "return FP.zpaInfraModel(data);", ov["graph"])
    assert m["tally"]["stop"] == 0 and m["tally"]["flicker"] == 0
    assert m["connectors"] == {"down": 0, "outdated": 0} and all(x["state"] == "live" for x in m["groups"])


@needs_node
def test_zpa_connections_say_nothing_to_draw_without_a_graph(tmp_path):
    """WCAG 2.2 SC 1.1.1: no graph gives no model (boundary), so the page says why instead of drawing an empty picture."""
    assert _fp(tmp_path, "return [FP.zpaInfraModel(null), FP.zpaInfraModel({})];", {}) == [None, None]


# ── ZPA diagnosis ──────────────────────────────────────────────────────
@needs_node
def test_the_walk_visits_every_evaluated_rule_in_order_and_each_miss_says_why(tmp_path):
    """WCAG 2.2 SC 1.3.2: the diagnosis walk is segment → segment group → each access rule in order (with why) → the deciding rule → server groups → connectors."""
    # Arrange
    d = za.diagnose(read(), SALES, "jira.corp.example", 443)
    ev = d["access"]["evaluated"]
    # Act
    m = _fp(tmp_path, "return FP.zpaDiagModel(data);", d)
    # Assert
    keys = [h["key"] for h in m["hops"]]
    assert keys[:3] == ["user", "segment", "segment_group"] and keys[-3:] == ["server_groups", "connectors", "dest"]
    rules = [h for h in m["hops"] if h["key"] == "rule"]
    assert [r["label"] for r in rules] == [f"Rule {w['order']}: {w['name']}" if w["order"] is not None else w["name"] for w in ev]
    assert [r["name"] for r in m["rules"]] == [w["name"] for w in ev]
    for h, w in zip(rules, ev):
        assert w["why"] in h["note"] if w["why"] else True
        if w["status"] == "not_matched":
            assert h["sub"] == "no match" and h["tone"] == "idle"
    decider = [h for h in rules if h.get("decides")]
    assert len(decider) == 1 and decider[0]["label"].endswith(d["verdict"]["rule"]) and decider[0]["tone"] == "pass"
    assert m["stop"] == -1 and m["verdict"]["outcome"] == "allowed"


@needs_node
@pytest.mark.parametrize("user,dest,outcome,stop_key", [
    (CONTRACTOR, "payroll.corp.example", "denied", "rule"),      # a deny rule decides
    (NOBODY, "jira.corp.example", "denied", "default"),          # no rule: the default deny
    ({}, "shop.example.com", "bypassed", "segment"),            # bypass ALWAYS: never through ZPA
    (ENG, "jira.corp.example:8080", "not_zpa", "segment"),       # no segment carries it
    ({}, "orphan.corp.example", "unreachable", "server_groups"),  # allowed but nothing serves it
])
def test_the_walk_stops_where_the_diagnosis_stops_and_greys_what_follows(tmp_path, user, dest, outcome, stop_key):
    """WCAG 2.2 SC 1.1.1: the packet stops at the hop that ends the request (deny, default deny, bypass, no segment, nothing serving) and every later hop is greyed."""
    # Arrange
    host, _, port = dest.partition(":")
    d = za.diagnose(read(), user, host, int(port) if port else 443)
    assert d["verdict"]["outcome"] == outcome
    # Act
    m = _fp(tmp_path, "return FP.zpaDiagModel(data);", d)
    # Assert
    assert m["stop"] >= 0 and m["hops"][m["stop"]]["key"] == stop_key and m["hops"][m["stop"]]["tone"] == "stop"
    assert all(h["tone"] == "after" for h in m["hops"][m["stop"] + 1:])
    assert m["verdict"]["outcome"] == outcome


@needs_node
def test_a_long_rule_walk_is_capped_but_keeps_the_deciding_rule(tmp_path):
    """WCAG 2.2 SC 1.1.1: 30 evaluated rules draw 11 misses, an "18 more rules" hop and the deciding rule (boundary)."""
    # Arrange
    d = za.diagnose(read(), SALES, "jira.corp.example", 443)
    miss = {"order": 1, "name": "x", "action": "ALLOW", "status": "not_matched", "why": "needs SCIM group X"}
    decider = dict(d["access"]["evaluated"][-1])
    d["access"]["evaluated"] = [dict(miss, order=i + 1, name=f"Rule {i}") for i in range(29)] + [decider]
    # Act
    m = _fp(tmp_path, "return FP.zpaDiagModel(data);", d)
    # Assert
    rules = [h for h in m["hops"] if h["key"] in ("rule", "more")]
    assert len(rules) == 13 and rules[-2]["key"] == "more" and rules[-2]["label"] == "18 more rules"
    assert rules[-1]["decides"] and m["hidden"] == 18


# ── Traffic insights ───────────────────────────────────────────────────
@needs_node
def test_the_web_flow_streams_are_the_location_and_action_numbers(tmp_path):
    """WCAG 2.2 SC 1.1.1: the web traffic Sankey's location streams and action streams equal the Insights tables, and its widths are proportional."""
    # Arrange
    res = insights_result()
    loc = {r["name"]: r["total"] for r in res["sections"]["web_location"]["rows"]}
    act = {r["name"]: r["total"] for r in res["sections"]["web_action"]["rows"] if r["action"] != "ANY"}
    everything = next(r["total"] for r in res["sections"]["web_action"]["rows"] if r["action"] == "ANY")
    # Act
    m = _fp(tmp_path, "const m = FP.insightsFlowModel(data, 'web'); return { m, s: FP.sankeySpec(m) };", res)
    mm, spec = m["m"], m["s"]
    # Assert
    assert {x["label"]: x["value"] for x in mm["left"]} == loc
    assert {x["label"]: x["value"] for x in mm["right"]} == act
    assert mm["hub"]["value"] == everything == sum(loc.values()) == sum(act.values())
    tone = {x["label"]: x["tone"] for x in mm["right"]}
    assert tone == {"Allowed": "pass", "Blocked": "stop"}
    widths = {(l["from"], l["to"]): l["width"] for l in spec["links"]}
    hq = next(x["id"] for x in mm["left"] if x["label"] == "HQ")
    br_ = next(x["id"] for x in mm["left"] if x["label"] == "Branch")
    assert widths[(hq, "hub")] / widths[(br_, "hub")] == pytest.approx(loc["HQ"] / loc["Branch"])
    assert any("cross locations with actions" in s for s in mm["summary"])


@needs_node
def test_traffic_neither_allowed_nor_blocked_is_its_own_stream(tmp_path):
    """WCAG 2.2 SC 1.1.1: when allowed and blocked add up to less than all web traffic, the rest flows to "Other actions (caution, isolate…)" (boundary)."""
    res = insights_result()
    for r in res["sections"]["web_action"]["rows"]:
        if r["action"] == "BLOCK":
            r["total"] = 40
    m = _fp(tmp_path, "return FP.insightsFlowModel(data, 'web');", res)
    other = [x for x in m["right"] if x.get("gap")]
    assert [(x["label"], x["value"]) for x in other] == [("Other actions (caution, isolate…)", 60)]
    assert m["hub"]["value"] == 1000 and sum(x["value"] for x in m["right"]) == 1000
    assert any("cautioned, isolated and other actions are not broken down" in s for s in m["summary"])


@needs_node
def test_a_gap_between_the_two_web_tables_is_drawn_and_named_never_spread(tmp_path):
    """WCAG 2.2 SC 1.1.1: when the locations add up to less than the actions, the difference is its own named stream (boundary)."""
    res = insights_result()
    res["sections"]["web_location"]["rows"] = [{"name": "HQ", "total": 600}]
    m = _fp(tmp_path, "return FP.insightsFlowModel(data, 'web');", res)
    gap = [x for x in m["left"] if x.get("gap")]
    assert gap == [{"id": "loc:gap", "label": "Not attributed to a location", "value": 400, "gap": True}]
    assert any("Not attributed to a location: 400" in s for s in m["summary"])


@needs_node
def test_the_firewall_and_application_flows_use_their_own_numbers(tmp_path):
    """WCAG 2.2 SC 1.1.1: the firewall flow is the firewall action table; the application flow sends each app's data to its sanctioned state."""
    # Arrange
    res = insights_result()
    fw = {r["name"]: r["total"] for r in res["sections"]["fw_action"]["rows"]}
    apps = res["sections"]["cloud_apps"]["rows"]
    # Act
    m = _fp(tmp_path, "return [FP.insightsFlowModel(data, 'fw'), FP.insightsFlowModel(data, 'apps'), FP.insightsViews(data)];", res)
    f, a, views = m
    # Assert
    assert {x["label"]: x["value"] for x in f["right"]} == fw and f["left"][0]["value"] == sum(fw.values())
    assert {x["label"]: x["value"] for x in a["left"]} == {r["application"]: r["data_consumed"] for r in apps}
    state = {}
    for r in apps:
        state[r["sanctioned_state"]] = state.get(r["sanctioned_state"], 0) + r["data_consumed"]
    assert {x["label"]: x["value"] for x in a["right"]} == state
    assert sum(l["value"] for l in a["links"]) == sum(r["data_consumed"] for r in apps)
    assert [v["key"] for v in views] == ["web", "fw", "apps"]


@needs_node
def test_more_than_six_applications_fold_into_one_other_stream(tmp_path):
    """WCAG 2.2 SC 1.1.1: 9 applications draw the 6 largest and one "3 other applications" stream that sums the rest (boundary)."""
    res = insights_result()
    res["sections"]["cloud_apps"]["rows"] = [{"application": f"App {i}", "data_consumed": (i + 1) * 10, "sanctioned_state": "Sanctioned"} for i in range(9)]
    m = _fp(tmp_path, "return FP.insightsFlowModel(data, 'apps');", res)
    assert len(m["left"]) == 7 and m["left"][-1] == {"id": "app:more", "label": "3 other applications", "value": 60, "folded": 3}
    assert sum(x["value"] for x in m["left"]) == sum((i + 1) * 10 for i in range(9)) == m["right"][0]["value"]


@needs_node
def test_an_empty_insights_read_draws_no_flow_and_says_why(tmp_path):
    """WCAG 2.2 SC 1.1.1: with no numbers there is no view and a sentence says why (negative case)."""
    from test_insights import EMPTY
    res = insights_read(insights_tenant(EMPTY))
    m = _fp(tmp_path, "return FP.insightsFlowModel(data);", res)
    assert m["views"] == [] and m["view"] is None and "No section" in m["summary"][0]


# ── Bypass report ─────────────────────────────────────────────────────
@needs_node
def test_each_bypass_stream_is_the_reports_own_count(tmp_path):
    """WCAG 2.2 SC 1.1.1: the Client Connector, SSL Do Not Inspect and allow streams equal the report's summary counts, and together its total."""
    # Arrange
    rep = bypass_rep()
    s = rep["summary"]
    # Act
    m = _fp(tmp_path, "const m = FP.bypassFlowModel(data); return { m, s: FP.bypassSpec(m) };", rep)
    mm, spec = m["m"], m["s"]
    # Assert
    v = {p["key"]: p["value"] for p in mm["points"]}
    assert v["zcc"] == s["zcc_apps"] + s["zcc_processes"] + s["zcc_ips"] + s["zcc_domains"] + s["zcc_trusted_nets"] == 5
    assert v["ssl"] == s["ssl_bypass_rules"] + s["ssl_exemptions"] == 2
    assert v["allow"] == s["url_filter_allow"] + s["firewall_allow"] + s["dlp_allow"] == 1
    assert mm["drawn"] == mm["total"] == s["total_bypass_items"]
    assert v["zpa"] is None and v["pac"] is None
    assert {p["key"]: p["state"] for p in mm["points"]}["pac"] == "not_measured"
    w = {l["id"]: l["width"] for l in spec["links"]}
    assert w["peel:zcc"] > w["peel:ssl"] > w["peel:allow"] > w["peel:pac"]


@needs_node
def test_a_bypass_section_out_of_scope_is_not_read_never_zero(tmp_path):
    """WCAG 2.2 SC 1.1.1: a section the Scope page left out is drawn as "not read", not as an empty stream (negative case)."""
    rep = bypass_rep()
    rep["sections"]["zcc"] = {"not_in_scope": "Not in scope: Client Connector is not ticked.", "items": [], "count": 0}
    for k in ("zcc_apps", "zcc_processes", "zcc_ips", "zcc_domains", "zcc_trusted_nets"):
        rep["summary"][k] = 0
    m = _fp(tmp_path, "return FP.bypassFlowModel(data);", rep)
    z = next(p for p in m["points"] if p["key"] == "zcc")
    assert z["state"] == "not_read" and z["text"] == "not read (out of scope)"


# ── Live DLP feed ─────────────────────────────────────────────────────
@needs_node
def test_a_live_incident_line_follows_channel_rule_action_and_receiver_without_people(tmp_path):
    """ASVS V8.3.4 · CWE-359: an incident in words names its channel, rule, configured action and the incident receiver, never the user or the file."""
    # Arrange
    inc = {"id": "i1", "channel": "endpoint", "user": "jane.doe@acme.example", "file": "payroll-2026.xlsx", "rules": ["Endpoint – PII"],
           "engines": ["PII engine"], "dictionaries": [{"name": "US SSN", "count": 3}], "enforcement": "monitor", "destination": "USB drive"}
    # Act
    out = _fp(tmp_path, "const FA = require(%s); return FP.liveLine(FA.liveModel(data));" % json.dumps(os.path.join(STATIC, "flow_anim.js")), inc)
    # Assert
    assert out == 'Endpoint → US SSN (3 matches) → PII engine → rule "Endpoint – PII", configured to monitor only → incident receiver → Workflow Automation.'
    assert "jane" not in out and "payroll" not in out


# ── The pages and the engine ──────────────────────────────────────────
@pytest.mark.parametrize("page", sorted(PAGES))
def test_each_page_loads_the_one_engine_after_its_shared_scripts(page):
    """WCAG 2.2 SC 2.2.2: each page loads flow_anim.js then flow_pages.js after explain.js, and the motion stylesheet."""
    html = _static(PAGES[page])
    order = [html.index(f'src="/static/{s}"') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js", "flow_anim.js", "flow_pages.js")]
    assert order == sorted(order)
    assert 'href="/static/flow_anim.css"' in html


def test_the_page_motion_reuses_the_engine_and_writes_no_html():
    """ASVS V5.3.3 · CWE-79 · WCAG 2.2 SC 2.3.3: flow_pages.js has no clock or HTML sink of its own: it uses FA.animator, and tenant strings reach the page as text."""
    js = re.sub(r"//[^\n]*", "", _static("flow_pages.js"))
    assert "requestAnimationFrame" not in js and "FA.animator()" in js and "FA.reduced()" in js
    for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write"):
        assert sink not in js, sink
    css = _static("flow_anim.css")
    assert re.search(r"@media \(prefers-reduced-motion: reduce\) \{ \.fp-moving \.fp-link\.st-flicker \{ animation: none; \} \}", css)
    assert not re.findall(r"#[0-9a-fA-F]{3,6}\b", css.split("static/flow_pages.js")[1])


# ── In a real browser ─────────────────────────────────────────────────
DRIVER = CDP_PRELUDE + r"""
const S = JSON.parse(args[0]);
const stubs = S.stubs;
await send('Page.addScriptToEvaluateOnNewDocument', { source: `
  try { localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['zpa', 'insights', 'dlp', 'workflow'] })); } catch (e) {}
  (function () {
    const S = ${JSON.stringify(stubs)}; const real = window.fetch.bind(window);
    window.fetch = (u, o) => { const url = String(u && u.url || u); for (const k of Object.keys(S)) if (url.indexOf(k) >= 0) return Promise.resolve(new Response(JSON.stringify(S[k]), { status: 200, headers: { 'Content-Type': 'application/json' } })); return real(u, o); };
  })();` });
const key = async (k, mods = 0) => {
  const code = { Enter: 13, Tab: 9 }[k];
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: k, code: k, windowsVirtualKeyCode: code, modifiers: mods, text: k === 'Enter' ? '\r' : undefined });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: k, code: k, windowsVirtualKeyCode: code, modifiers: mods });
};
const frames = n => ev(`new Promise(r => { let i = 0; const f = () => (++i >= ${n} ? r(true) : requestAnimationFrame(f)); requestAnimationFrame(f); })`);
const dotsMove = host => ev(`new Promise(r => {
  const pos = () => [...document.querySelectorAll('${host} circle.fa-dot')].map(c => c.getAttribute('cx') + ',' + c.getAttribute('cy')).join(' ');
  // At least 700 ms and three rendered frames: a picture moves only on a
  // frame, and on a slow runner (software raster of the glass backdrop)
  // frames can be hundreds of ms apart. Capped at 10 s, then sampled as is.
  const a = pos(), t0 = performance.now(); let frames = 0, done = false;
  const end = () => { if (done) return; done = true; const b = pos(); r({ n: document.querySelectorAll('${host} circle.fa-dot').length, moved: a !== b && b !== '', frames }); };
  const f = () => { frames++; if (frames >= 3 && performance.now() - t0 >= 700) end(); else if (!done) requestAnimationFrame(f); };
  requestAnimationFrame(f); setTimeout(end, 10000); })`);
async function open(url, ready) {
  await send('Page.navigate', { url: base + url });
  await until(() => ev(`document.readyState === 'complete'`), url + ' load');
  if (ready) await until(() => ev(ready), url + ' ready', 15000);
}
// A page's stream picture: keyboard toggle, text alternative, motion.
async function stream(host, reducedRun) {
  const out = {};
  out.atStart = await ev(`document.querySelectorAll('${host} circle.fa-dot').length`);   // as soon as the picture is ready
  out.boxes = await ev(`document.querySelectorAll('${host} .fa-box').length`);
  out.links = await ev(`document.querySelectorAll('${host} .fp-link').length`);
  out.alt = await ev(`(() => { const s = document.querySelector('${host} svg'); const d = s && document.getElementById(s.getAttribute('aria-describedby')); return { role: s && s.getAttribute('role'), label: s && s.getAttribute('aria-label'), lines: d ? [...d.querySelectorAll('li')].map(li => li.textContent) : [] }; })()`);
  out.button0 = await ev(`document.querySelector('${host} .fp-head button').textContent`);
  out.first = await dotsMove(host);
  // Keyboard: from the picture's frame, Shift+Tab reaches the toggle; Enter presses it.
  await ev(`document.querySelector('${host} .fp-stage').focus(), 1`);
  await key('Tab', 8);
  out.focusIsToggle = await ev(`document.activeElement === document.querySelector('${host} .fp-head button')`);
  await key('Enter');
  await frames(3);
  out.button1 = await ev(`document.querySelector('${host} .fp-head button').textContent`);
  out.note1 = await ev(`document.querySelector('${host} .fp-note').textContent`);
  out.second = await dotsMove(host);
  return out;
}
async function widths(check) {
  const res = {};
  for (const w of [320, 390]) {
    await send('Emulation.setDeviceMetricsOverride', { width: w, height: 900, deviceScaleFactor: 1, mobile: false });
    await frames(3);
    res[w] = await ev(`document.documentElement.scrollWidth - document.documentElement.clientWidth`);
  }
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  return res;
}
const out = {};
for (const mode of ['normal', 'reduce']) {
  await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-reduced-motion', value: mode === 'reduce' ? 'reduce' : 'no-preference' }] });
  await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
  const R = out[mode] = {};
  // ZPA: the overview's live connections, then a diagnosis walk.
  await open('/report/zpa?id=' + S.zpa, `!!document.querySelector('#zoFlow svg')`);
  R.zpa = await stream('#zoFlow');
  R.zpa.flicker = await ev(`document.querySelectorAll('#zoFlow .fp-link.st-flicker').length`);
  R.zpa.stopped = await ev(`document.querySelectorAll('#zoFlow .fp-link.st-stop').length`);
  R.zpa.width = await widths();
  await ev(`document.getElementById('tab-diagnose').click(), 1`);
  await ev(`(() => { const set = (id, v) => { document.getElementById(id).value = v; }; set('dDest', 'jira.corp.example'); set('dPort', '443'); set('dScim', 'none'); set('dSaml', 'Department=Sales'); set('dPosture', 'none'); set('dClient', 'zpn_client_type_zapp'); document.getElementById('zpForm').requestSubmit(); return 1; })()`);
  await until(() => ev(`!!document.querySelector('#zpWalk svg')`), 'the diagnosis walk', 15000);
  const walk = R.walk = {};
  walk.steps = await ev(`[...document.querySelectorAll('#zpWalk .fp-walk li')].map(li => li.textContent)`);
  walk.dotSeen = await ev(`new Promise(r => { const end = Date.now() + 1500; const f = () => { if (document.querySelector('#zpWalk circle.fa-dot')) return r(true); if (Date.now() > end) return r(false); requestAnimationFrame(f); }; f(); })`);
  await until(() => ev(`/Allowed by access rule/.test(document.querySelector('#zpWalk .fp-note').textContent)`), 'the walk to end', 20000);
  walk.lit = await ev(`[...document.querySelectorAll('#zpWalk .fa-box')].map(g => g.getAttribute('class'))`);
  walk.alt = await ev(`(() => { const s = document.querySelector('#zpWalk svg'); return s.getAttribute('role') + '|' + s.getAttribute('aria-describedby') + '|' + !!document.getElementById(s.getAttribute('aria-describedby')); })()`);
  await ev(`document.querySelector('#zpWalk .fp-stage').focus(), 1`);
  await key('Tab', 8);
  walk.focus = await ev(`document.activeElement.textContent`);
  await key('Enter');   // Stop: back to the start, nothing moving
  await frames(2);
  walk.afterStop = await ev(`[...document.querySelectorAll('#zpWalk .fa-box')].filter(g => ['pass', 'stop', 'warn'].some(c => g.classList.contains(c))).length`);
  walk.width = await widths();
  // Traffic insights.
  await open('/report/insights', `!!document.getElementById('tiRun')`);
  await ev(`document.getElementById('tiRun').click(), 1`);
  await until(() => ev(`!!document.querySelector('#tiFlow svg')`), 'the insights flow', 15000);
  R.insights = await stream('#tiFlow');
  R.insights.views = await ev(`[...document.querySelectorAll('#tiFlowView option')].map(o => o.value)`);
  await ev(`(() => { const s = document.getElementById('tiFlowView'); s.value = 'apps'; s.dispatchEvent(new Event('change')); return 1; })()`);
  await frames(2);
  R.insights.appsLabel = await ev(`document.querySelector('#tiFlow svg').getAttribute('aria-label')`);
  R.insights.afterSwitch = await ev(`document.querySelector('#tiFlow .fp-head button').textContent`);
  R.insights.width = await widths();
  // Bypass report.
  await open('/report/bypass?id=' + S.bypass, `!!document.querySelector('#bpFlow svg')`);
  R.bypass = await stream('#bpFlow');
  R.bypass.width = await widths();
  // Live DLP feed: start it; the stubbed poll lands two incidents.
  await open('/report/live', `!!document.querySelector('#lfLanesBody svg')`);
  const L = R.live = {};
  L.button0 = await ev(`document.querySelector('#lfLanes .fp-head button').textContent`);
  await ev(`document.getElementById('lfStart').click(), 1`);
  L.dotSeen = await ev(`new Promise(r => { const end = Date.now() + 2500; const f = () => { if (document.querySelector('#lfLanesBody circle.fa-dot')) return r(true); if (Date.now() > end) return r(false); requestAnimationFrame(f); }; f(); })`);
  await until(() => ev(`/2 incidents through the lanes/.test(document.querySelector('#lfLanes .fp-tally').textContent)`), 'both incidents landed', 15000);
  L.tally = await ev(`document.querySelector('#lfLanes .fp-tally').textContent`);
  L.log = await ev(`[...document.querySelectorAll('#lfLanes .fp-livelog li')].map(li => li.textContent)`);
  L.sink = await ev(`[...document.querySelectorAll('#lfLanesBody .fa-box')].map(g => g.querySelector('.fa-t').textContent + ' ' + g.querySelector('.fa-s').textContent).filter(t => /Incident/.test(t))`);
  L.alt = await ev(`(() => { const s = document.querySelector('#lfLanesBody svg'); return s.getAttribute('role') + '|' + !!document.getElementById(s.getAttribute('aria-describedby')); })()`);
  await ev(`document.querySelector('#lfLanes .fp-stage').focus(), 1`);
  await key('Tab', 8);
  L.focusIsToggle = await ev(`document.activeElement === document.querySelector('#lfLanes .fp-head button')`);
  await key('Enter');
  L.button1 = await ev(`document.querySelector('#lfLanes .fp-head button').textContent`);
  L.width = await widths();
  await ev(`document.getElementById('lfStop').click(), 1`);
}
console.log(JSON.stringify(out));
ws.close(); p.kill(); process.exit(0);
"""


def _scenario():
    import dlp_api_server as srv
    res = insights_result()
    incidents = [
        {"id": "i1", "created_at": "2026-10-29T10:00:00Z", "user": "jane.doe@acme.example", "file": "secret-plan.docx", "channel": "web",
         "rules": ["PCI – Block"], "engines": ["PCI engine"], "dictionaries": [{"name": "Credit cards", "count": 14}], "enforcement": "enforced",
         "destination": "drive.example", "real": None},
        {"id": "i2", "created_at": "2026-10-29T10:00:05Z", "user": "sam@acme.example", "file": "", "channel": "email",
         "rules": ["Email – PII"], "engines": ["PII engine"], "dictionaries": [{"name": "US SSN", "count": 3}], "enforcement": "monitor",
         "destination": "partner.example", "real": None},
    ]
    feed = {"incidents": incidents, "next_since": "2026-10-29T10:00:06Z", "read_at": "2026-10-29T10:00:06Z", "tenant_label": "acme",
            "stats": {"seen": 2, "enforced": 1, "monitor": 1, "unknown_action": 0, "open": 2, "real": 0, "not_real": 0, "fp_tp_ratio": "–"}, "errors": []}
    stubs = {"/api/insights/start": {"job_id": "ti-job", "status": "running"},
             "/api/dlp-packs/jobs/ti-job": {"status": "done", "result": res, "logs": ["Asking Insights…"], "next": 1},
             "/api/live-feed": feed}
    zrid = srv._remember_report("zpa", zpa_report(), "acme")
    brid = srv._remember_report("bypass", bypass_rep(), "acme")
    return srv, [zrid, brid], {"zpa": zrid, "bypass": brid, "stubs": stubs}


@pytest.fixture(scope="module")
def motion(tmp_path_factory):
    srv, ids, scenario = _scenario()
    try:
        return run_in_browser(tmp_path_factory.mktemp("flow-pages"), DRIVER, json.dumps(scenario), timeout=400)
    finally:
        for rid in ids:
            srv._REPORTS.pop(rid, None)


STREAMS = ("zpa", "insights", "bypass")


@pytest.mark.parametrize("page", STREAMS)
def test_the_stream_picture_renders_with_a_text_alternative(motion, page):
    """WCAG 2.2 SC 1.1.1 · SC 1.3.1: each page draws its flow as an image whose description is a list in words."""
    m = motion["normal"][page]
    assert m["boxes"] >= 3 and m["links"] >= 3
    assert m["alt"]["role"] == "img" and m["alt"]["label"] and len(m["alt"]["lines"]) >= 2


# The bypass picture's widths count bypass items, not traffic: its motion is
# an opt-in extra, so it starts still in both modes.
MOVING = ("zpa", "insights")


@pytest.mark.parametrize("page", MOVING)
def test_the_stream_picture_moves_and_a_keyboard_press_pauses_it(motion, page):
    """WCAG 2.2 SC 2.2.2 · SC 2.1.1: packets are on the links as soon as the picture is ready and move on their own, the toggle is reached by Shift+Tab from the picture, and Enter pauses every packet."""
    m = motion["normal"][page]
    assert m["atStart"] > 0, m   # it was empty until a slow link's random start came round (up to seconds)
    assert m["button0"] == "Pause motion" and m["first"]["n"] > 0 and m["first"]["moved"]
    assert m["focusIsToggle"] and m["button1"] == "Play motion" and m["note1"] == "Motion paused."
    assert m["second"]["n"] == 0


@pytest.mark.parametrize("page", STREAMS)
def test_the_stream_picture_is_still_under_reduced_motion_until_play(motion, page):
    """WCAG 2.2 SC 2.3.3 · SC 2.2.2: under reduced motion nothing moves and the toggle offers Play; pressing it by keyboard starts the packets."""
    m = motion["reduce"][page]
    assert m["button0"] == "Play motion" and m["first"]["n"] == 0
    assert m["focusIsToggle"] and m["button1"] == "Pause motion" and m["second"]["n"] > 0 and m["second"]["moved"]


def test_the_bypass_picture_starts_still_and_play_is_opt_in(motion):
    """WCAG 2.2 SC 2.2.2 · SC 2.1.1: the bypass widths count items, not traffic, so the picture starts still; Play by keyboard starts it."""
    m = motion["normal"]["bypass"]   # reduced motion: the test above
    assert m["button0"] == "Play motion" and m["first"]["n"] == 0
    assert m["focusIsToggle"] and m["button1"] == "Pause motion" and m["second"]["n"] > 0 and m["second"]["moved"]


def test_the_zpa_connections_mark_the_down_and_outdated_connector_groups(motion):
    """WCAG 2.2 SC 1.4.1: links to the outdated group flicker and links to the groups whose connectors are down stop, also said in the list."""
    m = motion["normal"]["zpa"]
    assert m["flicker"] >= 1 and m["stopped"] >= 1
    lines = " ".join(m["alt"]["lines"])
    assert "DC2 connectors: stopped, every App Connector is down" in lines and "Branch connectors: flickering" in lines


def test_the_zpa_walk_moves_lights_the_deciding_rule_and_stops_by_keyboard(motion):
    """WCAG 2.2 SC 2.2.2 · SC 2.1.1 · SC 1.1.1: the diagnosis packet walks each rule (misses say why), lights the deciding rule, and Stop by keyboard resets it."""
    w = motion["normal"]["walk"]
    assert w["dotSeen"]
    assert any(s.startswith("Rule ") and "no match" in s and "SCIM group Engineering" in s for s in w["steps"])
    assert any("Sales via SAML" in s and "decides" in s for s in w["steps"])
    assert sum(1 for c in w["lit"] if re.search(r"\bpass\b", c)) >= 5
    assert w["alt"].startswith("img|") and w["alt"].endswith("|true")
    assert w["focus"] == "Stop" and w["afterStop"] == 1   # only the first hop is lit after Stop


def test_the_zpa_walk_is_drawn_still_under_reduced_motion(motion):
    """WCAG 2.2 SC 2.3.3: under reduced motion no packet flies; the walk is drawn in its final state at once."""
    w = motion["reduce"]["walk"]
    assert not w["dotSeen"] and sum(1 for c in w["lit"] if re.search(r"\bpass\b", c)) >= 5


def test_the_insights_flow_offers_each_view_the_numbers_allow(motion):
    """WCAG 2.2 SC 2.1.1: the view picker lists web, firewall and application flows, and switching redraws the picture."""
    m = motion["normal"]["insights"]
    assert m["views"] == ["web", "fw", "apps"] and "Cloud applications by data" in m["appsLabel"]


@pytest.mark.parametrize("mode,label", [("normal", "Play motion"), ("reduce", "Pause motion")])
def test_a_pause_or_play_choice_survives_a_redraw(motion, mode, label):
    """WCAG 2.2 SC 2.2.2: after the viewer pauses (or plays, under reduced motion), switching the flow view keeps that choice."""
    assert motion[mode]["insights"]["afterSwitch"] == label


def test_the_live_lanes_fly_each_incident_and_say_it_without_people(motion):
    """WCAG 2.2 SC 1.1.1 · SC 2.2.2 · CWE-359: each landed incident flies to the incident receiver, is listed in words without user or file names, and the toggle pauses by keyboard."""
    m = motion["normal"]["live"]
    assert m["dotSeen"] and m["button0"] == "Pause motion" and m["sink"] == ["Incident receiver → WA"]
    assert m["tally"].startswith("2 incidents through the lanes this session: 1 configured to enforce, 1 monitor only")
    assert m["log"][0].startswith("Email → US SSN (3 matches)") and m["log"][1].startswith("Inline web → Credit cards (14 matches)")
    assert not any(x in " ".join(m["log"]) for x in ("jane", "sam@", "secret-plan"))
    assert m["alt"] == "img|true" and m["focusIsToggle"] and m["button1"] == "Play motion"


def test_the_live_lanes_land_incidents_at_once_under_reduced_motion(motion):
    """WCAG 2.2 SC 2.3.3: under reduced motion no dot flies, yet both incidents land and are counted."""
    m = motion["reduce"]["live"]
    assert not m["dotSeen"] and m["button0"] == "Play motion" and m["tally"].startswith("2 incidents")


@pytest.mark.parametrize("mode", ["normal", "reduce"])
@pytest.mark.parametrize("page", ["zpa", "walk", "insights", "bypass", "live"])
@pytest.mark.parametrize("width", [320, 390])
def test_no_motion_page_scrolls_sideways(motion, page, width, mode):
    """WCAG 2.2 SC 1.4.10: with the picture drawn, the page is no wider than a 320 or 390 px window (the picture scrolls inside its own frame)."""
    assert motion[mode][page]["width"][str(width)] == 0
