"""The ZPA overview (zpa_overview.py, the Overview tab of /report/zpa and its
Excel export): the KPI sentences, the infrastructure map (nodes, edges, the
precise filter links, the aggregation cap, unhealthy boxes), the inventory
tables and the workbook. Fixtures and the fake SDK client come from
test_zpa_analysis (the messy and clean tenants)."""
from __future__ import annotations

import os
import re

import pytest
from fastapi.testclient import TestClient

import zpa_analysis as za
import zpa_overview as zo
import zpa_reader as zr
from test_xlsx_writer import read_workbook
from test_zpa_analysis import CREDS, NOW, ZPA_SCOPE, FakeTenant, _seg, _wait, clean, messy, read

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ov(data=None, cap=zo.MAP_CAP, **kw):
    snap = read(data, **kw)
    an = za.analyze(snap, now=NOW)
    return snap, an, zo.overview(snap, an, cap=cap)


def _kpi(ov, key):
    return next(k for k in ov["kpis"] if k["key"] == key)


def _row(ov, table, oid):
    return next(r for r in ov["tables"][table]["rows"] if r["_id"] == oid)


def _node(ov, nid):
    return next(n for n in ov["graph"]["nodes"] if n["id"] == nid)


@pytest.fixture(scope="module")
def messy_ov():
    return _ov()


# ── KPIs ───────────────────────────────────────────────────────────────
def test_kpis_count_the_messy_tenant_in_plain_sentences(messy_ov):
    _, _, ov = messy_ov
    want = {"segments": 12, "segments_no_rule": 1, "segments_broad": 3, "segment_groups": 6, "server_groups": 5,
            "connector_groups": 5, "connectors": 5, "connectors_down": 1, "connectors_outdated": 1, "access_rules": 9,
            "rules_unreachable": 2, "rules_reference_nothing": 1}
    assert {k["key"]: k["value"] for k in ov["kpis"]} == want
    assert _kpi(ov, "segments_no_rule")["text"] == "1 app segment nobody can reach: no enabled access rule applies to it."
    assert _kpi(ov, "segments_broad")["text"] == "3 app segments use a wildcard domain or a subnet; 1 of them is over-broad."
    assert _kpi(ov, "connectors")["text"] == "5 App Connectors: 4 connected."
    assert _kpi(ov, "connectors_down")["text"] == "1 App Connector is not connected."
    assert _kpi(ov, "rules_unreachable")["text"] == "2 access rules never decide: an earlier rule always matches first."
    assert _kpi(ov, "access_rules")["text"] == "9 access rules, 8 enabled."
    for k in ov["kpis"]:      # every sentence links to the table rows behind it
        assert k["table"] in ov["tables"] and k["text"].endswith(".") and k["text"][0].isdigit()
        rows = ov["tables"][k["table"]]["rows"]
        if k["flags"] and k["key"].startswith(("segments_", "connectors_", "rules_")):   # the value is the flagged count
            hits = [r for r in rows if set(k["flags"]) & set(r["_flags"])]
            assert len(hits) == k["value"], k["key"]
    assert _kpi(ov, "segments_no_rule")["tone"] == "fail" and _kpi(ov, "connectors_outdated")["tone"] == "warn"
    assert [r["name"] for r in ov["tables"]["segments"]["rows"] if "no_rule" in r["_flags"]] == ["Unused app"]


def test_a_clean_tenant_has_no_problem_kpi():
    _, _, ov = _ov(clean())
    problems = [k for k in ov["kpis"] if k["flags"]]
    assert problems and all(k["value"] == 0 and k["tone"] == "" for k in problems), problems
    assert _kpi(ov, "connectors")["text"] == "2 App Connectors: 2 connected."
    assert all(n["status"] == "ok" for n in ov["graph"]["nodes"] if n["col"] != "idps"), [n for n in ov["graph"]["nodes"] if n["status"] != "ok"]


def test_a_list_that_was_not_read_is_unknown_never_zero():
    _, _, ov = _ov(fail={"app_connectors": "HTTP 403 Forbidden", "policies": "HTTP 500"})
    con = _kpi(ov, "connectors")
    assert con["value"] is None and "unknown" in con["text"] and "403" in con["text"]
    assert "connectors_down" not in {k["key"] for k in ov["kpis"]}
    nr = _kpi(ov, "segments_no_rule")
    assert nr["value"] is None and "access rules could not be read" in nr["text"]
    assert ov["tables"]["connectors"]["read"] is False and "unknown, not empty" in ov["tables"]["connectors"]["empty"]
    assert ov["tables"]["segments"]["rows"] and all(r["rules"] is None for r in ov["tables"]["segments"]["rows"])


def test_no_access_rules_means_every_enabled_segment_is_unreachable():
    data = messy()
    data["policies"]["access"] = []
    _, _, ov = _ov(data)
    assert _kpi(ov, "segments_no_rule")["value"] == 12 and _kpi(ov, "access_rules")["value"] == 0


# ── the map ────────────────────────────────────────────────────────────
def test_the_map_has_every_object_in_its_column_and_the_chain_edges(messy_ov):
    snap, _, ov = messy_ov
    g = ov["graph"]
    cols = {c["key"]: c["count"] for c in g["columns"]}
    assert list(cols) == ["idps", "access_rules", "segment_groups", "segments", "server_groups", "connector_groups", "connectors"]
    assert cols == {"idps": 3, "access_rules": 9, "segment_groups": 6, "segments": 12, "server_groups": 5, "connector_groups": 5, "connectors": 5}
    assert not g["aggregated"] and g["note"] == "" and len(g["nodes"]) == 45 == g["total_nodes"]
    edges = {tuple(e) for e in g["edges"]}
    assert len(edges) == g["total_edges"] == 49   # the disabled rule r8 connects to nothing
    order = {k: i for i, k in enumerate(cols)}
    for a, b in edges:   # every edge joins two neighbouring columns, left to right
        assert order[b.split(":")[0]] == order[a.split(":")[0]] + 1, (a, b)
    assert ("idps:idp1", "access_rules:r1") in edges and ("idps:*any", "access_rules:r5") in edges
    assert ("access_rules:r2", "segment_groups:sg-eng") in edges and ("access_rules:r4", "segment_groups:sg-fin") in edges
    assert ("segment_groups:sg-eng", "segments:s-git") in edges and ("segments:s-git", "server_groups:srv-dc1") in edges
    assert ("server_groups:srv-dc1", "connector_groups:cg-dc1") in edges and ("connector_groups:cg-dc1", "connectors:c1") in edges
    # A disabled IdP's SAML rule hangs off that IdP (the attribute's IdP), not off "any user".
    assert ("idps:idp2", "access_rules:r6") in edges


def test_the_filter_links_are_precise(messy_ov):
    _, _, ov = messy_ov
    L = ov["graph"]["links"]
    links = {tuple(e) for e in L["edges"]}
    assert L["complete"]
    # r2 names only s-git: it links to that segment, not to Jira in the same group.
    assert ("access_rules:r2", "segments:s-git") in links and ("access_rules:r2", "segments:s-jira") not in links
    # r1 names the whole group: every segment in it.
    assert {b for a, b in links if a == "access_rules:r1"} == {"segments:s-git", "segments:s-jira", "segments:s-mirror"}
    # A disabled rule gives no access, so it links to nothing (its catch-all shape included).
    assert L["all_apps"] == [] and not [e for e in links if e[0] == "access_rules:r8"]
    assert len(L["enabled_segments"]) == 12


def test_unhealthy_boxes_are_flagged_and_coloured(messy_ov):
    _, _, ov = messy_ov
    assert _node(ov, "connectors:c3")["status"] == "fail" and "not_connected" in _node(ov, "connectors:c3")["flags"]
    assert _node(ov, "connectors:c5")["status"] == "warn" and "outdated" in _node(ov, "connectors:c5")["flags"]
    assert _node(ov, "connectors:c1")["status"] == "ok"
    assert _node(ov, "connector_groups:cg-dc2")["status"] == "fail"           # every connector down (high)
    assert _node(ov, "connector_groups:cg-spare")["status"] == "warn"         # no connector, used by nobody (low)
    assert _node(ov, "segments:s-unused")["status"] == "fail" and _node(ov, "segments:s-jira")["status"] == "ok"
    # Unreachable with the opposite action is high (red); with the same action medium (amber).
    assert _node(ov, "access_rules:r3")["status"] == "fail" and _node(ov, "access_rules:r2")["status"] == "warn"
    assert _node(ov, "access_rules:r8")["status"] == "off"
    assert _node(ov, "segment_groups:sg-old")["status"] == "off"
    assert _node(ov, "server_groups:srv-static")["status"] == "fail"
    # Problems first within a column.
    segs = [n for n in ov["graph"]["nodes"] if n["col"] == "segments"]
    ranks = [zo.STATUS_ORDER[n["status"]] for n in segs]
    assert ranks == sorted(ranks)


def test_a_large_tenant_is_capped_per_column_and_says_so():
    data = messy()
    data["segments"] += [_seg(f"s-bulk{i}", f"Bulk app {i:03d}", [f"bulk{i}.corp.example"], [(443, 443)], "sg-eng", ["srv-dc1"]) for i in range(300)]
    _, _, ov = _ov(data, cap=12)
    g = ov["graph"]
    segs = [n for n in g["nodes"] if n["col"] == "segments"]
    assert len(segs) == 13
    agg = segs[-1]
    assert agg["aggregate"] and agg["id"] == "segments:*more" and agg["count"] == 312 - 12 == len(agg["members"])
    assert agg["label"] == "300 more app segments"
    kept = {n["id"] for n in segs[:-1]}
    assert "segments:s-unused" in kept and "segments:s-orphan" in kept, "problems are kept in view"
    assert not kept & set(agg["members"])
    drawn = {n["id"] for n in g["nodes"]}
    assert all(a in drawn and b in drawn for a, b in g["edges"]) and len({tuple(e) for e in g["edges"]}) == len(g["edges"])
    assert ["segment_groups:sg-eng", "segments:*more"] in g["edges"] and ["segments:*more", "server_groups:srv-dc1"] in g["edges"]
    assert g["aggregated"] and "at most 12 boxes" in g["note"] and "312 app segments" in g["note"] and "tables below" in g["note"]
    col = next(c for c in g["columns"] if c["key"] == "segments")
    assert (col["count"], col["shown"], col["hidden"]) == (312, 12, 300)
    assert len(ov["tables"]["segments"]["rows"]) == 312, "the tables keep every object"
    assert len(zo.overview(read(data), za.analyze(read(data), now=NOW), cap=3)["graph"]["nodes"]) <= 7 * 4


def test_too_many_links_fall_back_to_the_box_itself(monkeypatch, messy_ov):
    snap, an, _ = messy_ov
    monkeypatch.setattr(zo, "MAX_LINKS", 5)
    L = zo.overview(snap, an)["graph"]["links"]
    assert L["complete"] is False and L["edges"] == [] and L["all_apps"] == []


def test_tables_have_every_object_with_flags_and_findings(messy_ov):
    _, an, ov = messy_ov
    t = ov["tables"]
    assert [k for k in t] == list(zo.TABLE_ORDER)
    git = _row(ov, "segments", "s-git")
    assert git["segment_group"] == "Engineering apps" and git["tcp"] == "22, 443" and git["rules"] == 3   # r1, r2 and r9
    assert any(i.startswith("ZPA-AS-03") for i in git["_issues"])
    r2 = _row(ov, "access_rules", "r2")
    assert r2["applications"] == "app segment Git servers" and "SCIM group" in r2["who"] and "unreachable" in r2["_flags"]
    assert _row(ov, "access_rules", "r5")["who"] == "Any signed-in user"
    assert [r["order"] for r in t["access_rules"]["rows"]] == list(range(1, 10))
    cg = _row(ov, "connector_groups", "cg-branch")
    assert cg["connectors"] == 2 and cg["connected"] == 2 and cg["versions"] == "23.9.4, 24.1.1"
    c3 = _row(ov, "connectors", "c3")
    assert c3["status"] == "ZPN_STATUS_DISCONNECTED" and c3["last_connected"].endswith("UTC")
    assert all(set(r["_flags"]) <= set(zo.FLAG_LABELS) for tab in t.values() for r in tab["rows"])
    every = {(f["object_type"], f["object_id"]) for f in an["findings"] if f["object_type"] in zo.OBJ_TABLE}
    tagged = {(ot, r["_id"]) for ot, tk in zo.OBJ_TABLE.items() for r in t[tk]["rows"] if r["_issues"]}
    assert every <= tagged


# ── the Excel workbook ─────────────────────────────────────────────────
def test_the_workbook_has_every_table_and_is_formula_safe():
    data = messy()
    data["segments"][0]["name"] = "=HYPERLINK(\"http://x\",\"y\")"
    snap = read(data)
    an = za.analyze(snap, now=NOW)
    wb = read_workbook(zo.workbook(snap, an, tenant_label="acme", read_at=snap["read_at"]))
    assert list(wb) == ["Overview", "App segments", "Segment groups", "Server groups", "Connector groups", "App Connectors",
                        "Access rules", "Identity providers", "Findings", "Map connections", "Not read"]
    texts = [r[0] for r in wb["Overview"][1:]]
    assert "1 app segment nobody can reach: no enabled access rule applies to it." in texts and "Tenant" in texts
    assert len(wb["App segments"]) == 13 and wb["App segments"][0][:2] == ["Name", "Enabled"]
    assert any(c == "'=HYPERLINK(\"http://x\",\"y\")" for r in wb["App segments"] for c in r), "neutralised like the CSV"
    assert len(wb["Findings"]) == len(an["findings"]) + 1 and len(wb["Map connections"]) == 50
    assert wb["Not read"][1][0] == "Every list was read."


def test_the_excel_export_endpoint(monkeypatch):
    import dlp_api_server as srv
    tenant = FakeTenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: tenant)
    monkeypatch.setattr(zr, "PACE_SECONDS", 0)
    t = TestClient(srv.app)
    r = t.post("/api/zpa/analysis/start", json=dict(CREDS, **ZPA_SCOPE))
    res = _wait(t, r.json()["job_id"])["result"]
    ov = res["overview"]
    assert {k["key"] for k in ov["kpis"]} >= {"segments_no_rule", "connectors_down", "rules_unreachable"} and ov["graph"]["nodes"]
    x = t.get(f"/api/zpa/report/{res['report_id']}/export?format=xlsx&severity=high")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.openxmlformats-officedocument.spreadsheetml")
    assert "attachment" in x.headers["content-disposition"] and ".xlsx" in x.headers["content-disposition"]
    wb = read_workbook(x.content)
    assert {r[0] for r in wb["Findings"][1:]} == {"high"} and len(wb["App segments"]) == 13
    assert "secret-secret-secret" not in x.content.decode("latin-1")
    assert not tenant.writes
    assert t.get("/api/zpa/report/zpa-nope/export?format=xlsx").status_code == 404
    assert t.get(f"/api/zpa/report/{res['report_id']}/export?format=docx").status_code == 400
    monkeypatch.setattr(srv._security, "ui_auth_enabled", lambda: True)
    assert t.get(f"/api/zpa/report/{res['report_id']}/export?format=xlsx").status_code == 401
    ok = t.get(f"/api/zpa/report/{res['report_id']}/export?format=xlsx", headers={"X-DLP-Check-Token": srv._security.ui_token()})
    assert ok.status_code == 200


# ── the page ───────────────────────────────────────────────────────────
def test_the_overview_tab_draws_an_accessible_map_without_libraries():
    html = open(os.path.join(ROOT, "static", "report_zpa.html"), encoding="utf-8").read()
    assert html.index('id="tab-overview"') < html.index('id="tab-findings"') < html.index('id="tab-diagnose"')
    assert '<section role="tabpanel" id="panel-overview"' in html and 'id="zpOverview"' in html
    assert "<script src=\"http" not in html and "d3" not in html.lower().split("<script>")[0]
    for needle in ('role="region" aria-label="Infrastructure map', 'role="button" tabindex="-1" aria-pressed="false"', "The map as a list",
                   "ArrowRight", "ArrowDown", "'Escape'", "prefers-reduced-motion: reduce", "matchMedia('(prefers-reduced-motion: reduce)')",
                   "format=xlsx", 'id="expXlsx"', "Show everything", "zo-node.st-fail", "zo-node.st-warn", 'role="status" aria-live="polite"'):
        assert needle in html, needle
    style = html[html.index("<style>"):html.index("</style>")]
    assert "var(--fail)" in style and "var(--warn)" in style and not re.search(r"#[0-9a-fA-F]{3,8}\b", style)
    assert "overflow-x: auto" in style[style.index(".zo-mapwrap {"):style.index(".zo-mapwrap {") + 120]
