"""ZPA builder (ops_zpa): operation types on the Bulk changes engine.

Every test runs against the stateful fake ZPA tenant in tests/zpa_fake.py:
no network, no clock (the pacing is set to 0), state files in tmp_path."""
from __future__ import annotations

import json
import logging
import os
import sys

import pytest
from conftest import read_store_text

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_zpa  # noqa: E402
import pack_ops as ops  # noqa: E402
import zpa_reader  # noqa: E402
from zpa_fake import CANARY_KEY, Client, Tenant  # noqa: E402

ZPA = ao.scope_for(["zpa"], {})
NO_ZPA = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
ASSESSOR = "Jane Doe"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ops_zpa, "_SECRETS", {})
    ao.load_plugins()
    return tmp_path


def _apply(client, spec, **kw):
    """Preview, then apply with every gate held: (prepared, result)."""
    p = ao.plan(client, spec, scope=ZPA, tenant_label="acme")
    r = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                   confirm_text=p.get("confirm_phrase") or "", **kw)
    return p, r


def _built(t: Tenant = None) -> Client:
    """A tenant with a whole build for prefix pov1."""
    c = Client(t)
    iso = c.tenant.add("isolation_profile", {"name": "Default isolation"})
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "1-65535"}})
    _apply(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": True, "inspection": True, "isolation_profile_id": iso["id"]})
    return c


# ── registration and scope ──────────────────────────────────────────────

def test_the_four_builder_types_are_registered_with_their_form():
    """ASVS V1.4.4 · CWE-1059: the ZPA builder is four plugin types on the Bulk changes engine, each with the ops_zpa.js form."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for t in ("zpa_connector_group", "zpa_app_segments", "zpa_policies", "zpa_prefix_delete"):
        assert cat[t]["script"] == "ops_zpa.js" and cat[t]["group"] == "Build new" and cat[t]["product"] == "zpa"


@pytest.mark.parametrize("spec", [{"type": "zpa_connector_group", "prefix": "pov1"}, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True},
                                  {"type": "zpa_policies", "prefix": "pov1", "access": True}])
def test_out_of_scope_is_refused_before_anything_is_read(spec):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZPA ticked on the Scope page a ZPA build or delete reads nothing and writes nothing."""
    c = Client()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZPA)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(c, ops_zpa.FAMILY, NO_ZPA)
    assert c.tenant.reads == [] and c.tenant.writes == []


# ── validation of what the page sends ───────────────────────────────────

@pytest.mark.parametrize("prefix", ["", "a" * 21, "pov 1", "pov1;", "../x", "pöv", "<b>", None, "a.b"])
def test_a_bad_prefix_is_refused_before_anything_is_read(prefix):
    """ASVS V5.1.3 · CWE-20: the prefix must match ^[A-Za-z0-9_-]{1,20}$; anything else is refused before a read."""
    c = Client()
    with pytest.raises(ao.OperationError, match="prefix"):
        ao.plan(c, {"type": "zpa_connector_group", "prefix": prefix}, scope=ZPA)
    assert c.tenant.reads == []


@pytest.mark.parametrize("prefix", ["a", "A" * 20, "pov_1-x"])
def test_boundary_prefixes_are_accepted(prefix):
    """ASVS V5.1.3 · CWE-20: one character, twenty characters, '-' and '_' are valid prefixes."""
    assert ops_zpa.check_prefix(prefix) == prefix


def test_a_dry_run_preview_writes_nothing_and_names_every_call():
    """ASVS V1.4.1 · CWE-841: the preview of a build reads only and lists, per object, the API call the apply would make."""
    c = Client()
    p = ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1"}, scope=ZPA)
    assert c.tenant.writes == [] and p["status"] == "ready" and len(p["plan_hash"]) == 64
    assert all(u["reason"].startswith("Creates it: POST /") for u in p["items"])


# ── App Connector group and the provisioning key ────────────────────────

def test_connector_group_build_creates_group_and_key_and_rerun_never_duplicates():
    """ASVS V1.4.1 · CWE-841: the group and its key are created once; the same build again changes nothing."""
    c = Client()
    _p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "location": "london", "max_usage": 3})
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 2
    key = c.tenant.by_name("provisioning_key", "pov1-provisioning-key")
    assert key["zcomponentId"] == c.tenant.by_name("connector_group", "pov1-connector-group")["id"] and key["maxUsage"] == "3"
    again = ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1", "location": "london", "max_usage": 3}, scope=ZPA)
    assert again["status"] == "nothing_to_do"
    assert c.tenant.names("connector_group") == ["pov1-connector-group"] and c.tenant.names("provisioning_key") == ["pov1-provisioning-key"]


def test_a_rerun_with_a_new_value_updates_in_place():
    """ASVS V1.4.1 · CWE-841: a re-run with another max usage updates the existing key (PUT), it does not create a second one."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 3})
    c.tenant.writes.clear()
    p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 9})
    assert [(u["field"], u["before"], u["after"]) for u in p["items"] if u["status"] == "change"] == [("max_usage", "3", "9")]
    assert r["status"] == "applied" and c.tenant.writes == [("update", "provisioning_key", "pov1-provisioning-key")]
    assert r["inverse"]["restore"][0]["before"] == {"max_usage": "3"}


def test_reusing_an_existing_connector_group_never_changes_it():
    """ASVS V1.4.1 · CWE-284: an existing group the operator picks is reused as it is; only the prefixed key is created for it."""
    c = Client()
    g = c.tenant.add("connector_group", {"name": "HQ connectors", "enabled": True, "connectors": [{"id": "1"}]})
    p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "mode": "existing", "connector_group_id": g["id"]})
    assert r["status"] == "applied" and c.tenant.writes == [("create", "provisioning_key", "pov1-provisioning-key")]
    assert c.tenant.by_name("provisioning_key", "pov1-provisioning-key")["zcomponentId"] == g["id"]
    bad = ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov2", "mode": "existing", "connector_group_id": "999"}, scope=ZPA)
    assert bad["status"] == "blocked"


def _everything_that_was_written(tmp_path, r, caplog_text, job_logs=""):
    files = "".join(open(os.path.join(tmp_path, f), encoding="utf-8").read() for f in os.listdir(tmp_path) if os.path.isfile(os.path.join(tmp_path, f)))
    return json.dumps(r, default=str) + caplog_text + files + job_logs


def test_provisioning_key_canary_is_shown_once_and_never_stored_logged_or_recorded(isolated, caplog):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-312 · A09:2021: the provisioning key ZPA returns appears in no result, log, audit entry or change record; it is revealed once."""
    caplog.set_level(logging.DEBUG)
    c = Client()
    p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    rec = ao.record(r, by=ASSESSOR, actor=None)
    assert rec is not None
    # every later read of the key (re-plan, re-read, read-back) carries it too: still nowhere
    ao.plan(c, {"type": "zpa_connector_group", "prefix": "pov1"}, scope=ZPA)
    ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True}, scope=ZPA)
    objects = ao.read_objects(c, ops_zpa.FAMILY, ZPA)
    blob = _everything_that_was_written(isolated, [p, r, rec, objects], caplog.text)
    assert CANARY_KEY not in blob and "CANARY-PROVISIONING" not in blob
    token = r["one_time_secrets"][0]["token"]
    assert ops_zpa.reveal(token) == {"name": "pov1-provisioning-key", "provisioning_key": CANARY_KEY}
    assert ops_zpa.reveal(token) is None


def test_the_one_time_key_expires_and_is_bound_to_who_ran_the_build():
    """ASVS V3.3.1 · V4.2.1 · CWE-613 · CWE-639: a key token is single use, ten minutes long, and only for the actor whose run made it."""
    tok = ops_zpa.stash("k-1", "pov1-provisioning-key", "alice", now=1000.0)
    assert ops_zpa.reveal(tok, actor="mallory", now=1001.0) is None
    assert ops_zpa.reveal(tok, actor="alice", now=1000.0 + ops_zpa.SECRET_TTL + 1) is None
    tok2 = ops_zpa.stash("k-2", "n", "alice", now=1000.0)
    assert ops_zpa.reveal(tok2, actor="alice", now=1001.0)["provisioning_key"] == "k-2"
    for bad in ("", "x" * 500, "../../etc", None, {"a": 1}):
        assert ops_zpa.reveal(bad) is None


# ── application segments ────────────────────────────────────────────────

CSV = "name,domains,tcp_ports,udp_ports,description\nCRM App,crm.example.com;crm2.example.com,443,,Customer CRM\nDNS,dns.example.com,,53,\n"


def test_wildcard_preset_and_csv_segments_are_built_under_one_segment_and_server_group():
    """ASVS V1.4.1 · CWE-841: the three ways to describe applications build disabled segments in the prefix's segment and server groups."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    p, r = _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "*.corp.example.com", "tcp": "1-65535"},
                      "preset": {"vertical": "finance", "domain": "bank.example"}, "csv": CSV})
    assert r["status"] == "applied", r.get("message")
    segs = {s["name"]: s for s in c.tenant.rows["segment"].values()}
    assert segs["pov1-wildcard-corp-example-com"]["domainNames"] == ["*.corp.example.com"]
    assert segs["pov1-finance-core"]["domainNames"] == ["core.bank.example"] and segs["pov1-crm-app"]["tcpPortRanges"] == ["443", "443"]
    assert segs["pov1-dns"]["udpPortRanges"] == ["53", "53"]
    assert all(s["enabled"] is False for s in segs.values()), "segments are created disabled by default"
    sg, svg = c.tenant.by_name("segment_group", "pov1-segment-group"), c.tenant.by_name("server_group", "pov1-server-group")
    assert all(s["segmentGroupId"] == sg["id"] and s["serverGroups"] == [{"id": svg["id"]}] for s in segs.values())
    assert svg["appConnectorGroups"] == [{"id": c.tenant.by_name("connector_group", "pov1-connector-group")["id"]}]


def test_segments_need_a_connector_group_first():
    """ASVS V1.4.1 · CWE-841: without the prefix's App Connector group (or a picked one) the segment build is blocked, nothing written."""
    c = Client()
    p = ao.plan(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443"}}, scope=ZPA)
    assert p["status"] == "blocked" and "App Connector group" in p["blockers"][0]


def test_a_domain_another_segment_already_serves_on_the_same_ports_is_not_built():
    """ASVS V1.4.1 · CWE-841: a segment whose domain sits in another segment on overlapping ports is excluded with the reason."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    c.tenant.add("segment", {"name": "Legacy CRM", "domainNames": ["crm.example.com"], "tcpPortRanges": ["443", "443"]})
    p = ao.plan(c, {"type": "zpa_app_segments", "prefix": "pov1", "csv": CSV}, scope=ZPA)
    crm = next(u for u in p["items"] if u["object"]["name"] == "pov1-crm-app")
    assert crm["status"] == "excluded" and "Legacy CRM" in crm["reason"]


@pytest.mark.parametrize("csv_text,match", [
    ("name,domains,tcp_ports\n" + "".join(f"a{i},a{i}.example.com,443\n" for i in range(501)), "at most 500"),
    ("x" * (ops_zpa.MAX_CSV_BYTES + 1), "larger than"),
    ("name,domains,tcp_ports\nok,ok.example.com,443\x00\n", "NUL"),
    ("domain,ports\nexample.com,443\n", "first line"),
    ("name,domains,tcp_ports\napp,not a domain!,443\n", "line 2"),
    ("name,domains,tcp_ports\napp,app.example.com,99999\n", "line 2"),
    ("name,domains,tcp_ports\napp,app.example.com,\n", "no TCP or UDP"),
    ("name,domains,tcp_ports\n=cmd|' /C calc'!A0,app.example.com,443\nok,=1+1,443\n", "line 3"),
    ("name,domains,tcp_ports\na,a.example.com,443\nA,b.example.com,443\n", "used twice"),
    ("name,domains,tcp_ports\na,\"" + ";".join(f"h{i}.example.com" for i in range(51)) + "\",443\n", "more than 50"),
])
def test_a_hostile_or_oversized_csv_is_refused_before_anything_is_read(csv_text, match):
    """ASVS V12.1.1 · V5.1.4 · CWE-400 · CWE-20 · A04:2021: the CSV is untrusted: size, row count, NUL, header, domains and ports are checked; nothing is read or written."""
    c = Client()
    with pytest.raises(ao.OperationError, match=match):
        ao.plan(c, {"type": "zpa_app_segments", "prefix": "pov1", "csv": csv_text}, scope=ZPA)
    assert c.tenant.reads == [] and c.tenant.writes == []


def test_the_csv_boundary_of_500_rows_is_accepted():
    """ASVS V12.1.1 · CWE-400: exactly 500 rows is within the limit."""
    rows = ops_zpa.parse_csv("name,domains,tcp_ports\n" + "".join(f"a{i},a{i}.example.com,443\n" for i in range(500)))
    assert len(rows) == 500 and rows[0]["slug"] == "a0"


def test_a_formula_looking_name_becomes_a_plain_slug():
    """ASVS V5.3.10 · CWE-1236: a CSV name is reduced to letters, digits and '-' before it names anything in ZPA."""
    rows = ops_zpa.parse_csv("name,domains,tcp_ports\n\"=HYPERLINK(\"\"x\"\")\",a.example.com,443\n")
    assert rows[0]["slug"] == "hyperlink-x"


def test_browser_access_and_pra_build_their_applications_and_consoles():
    """ASVS V1.4.1 · CWE-841: Browser Access gets one clientless app with the picked certificate; PRA gets an RDP and an SSH application with consoles in the picked portal."""
    c = Client()
    cert, portal = c.tenant.add("certificate", {"name": "web"}), c.tenant.add("pra_portal", {"name": "portal"})
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    p, r = _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "browser_access": {"domain": "ehr.example.com", "port": 443, "certificate_id": cert["id"]},
                      "pra": {"rdp_host": "rdp.example.com", "ssh_host": "10.0.0.5", "portal_id": portal["id"]}})
    assert r["status"] == "applied", (r.get("message"), [u for u in r["items"] if u["status"] != "applied"])
    ba = c.tenant.by_name("segment", "pov1-browser-access")
    assert ba["clientlessApps"][0]["certificate_id"] == cert["id"] and ba["clientlessApps"][0]["trust_untrusted_cert"] is False
    rdp = c.tenant.by_name("segment", "pov1-pra-rdp")
    con = c.tenant.by_name("pra_console", "pov1-pra-rdp-console")
    assert con["praApplication"]["id"] == rdp["praApps"][0]["id"] and con["praPortals"] == [{"id": portal["id"]}] and con["enabled"] is False


# ── policy rules ────────────────────────────────────────────────────────

def test_policy_rules_cover_the_prefixed_segments_with_the_owasp_profile_and_the_chosen_isolation_profile():
    """ASVS V1.4.1 · CWE-841: access, timeout, inspection (newest predefined OWASP version) and isolation rules name every prefixed segment."""
    c = _built()
    segs = sorted(s["id"] for s in c.tenant.rows["segment"].values())
    rules = {t: next(iter(c.tenant.rows[f"rule:{t}"].values())) for t in ("access", "timeout", "inspection", "isolation")}
    for r in rules.values():
        assert sorted(o["rhs"] for o in r["conditions"][0]["operands"]) == segs
    assert rules["access"]["action"] == "ALLOW" and rules["timeout"]["action"] == "RE_AUTH" and rules["timeout"]["reauthTimeout"] == "28800"
    prof = c.tenant.by_name("inspection_profile", "pov1-owasp-inspection")
    assert prof["predefinedControlsVersion"] == "OWASP_CRS/4.10.0" and rules["inspection"]["zpnInspectionProfileId"] == prof["id"]
    assert rules["isolation"]["zpnIsolationProfileId"] == c.tenant.by_name("isolation_profile", "Default isolation")["id"]


def test_rules_follow_new_segments_on_a_rerun():
    """ASVS V1.4.1 · CWE-841: after another segment is built, the same policy build updates the rules' applications in place."""
    c = _built()
    _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "csv": CSV})
    p = ao.plan(c, {"type": "zpa_policies", "prefix": "pov1", "access": True}, scope=ZPA)
    assert [u["field"] for u in p["items"] if u["status"] == "change"] == ["apps"]


def _with_access_policy(c: Client) -> dict:
    """Two access rules that exist before the build (a Deny above an Allow) and the Default rule."""
    t = c.tenant
    deny = t.add("rule:access", {"name": "Deny contractors", "action": "DENY", "ruleOrder": "1"})
    allow = t.add("rule:access", {"name": "Allow staff", "action": "ALLOW", "ruleOrder": "2"})
    t.add("rule:access", {"name": "Default_Rule", "action": "DENY", "ruleOrder": "3", "defaultRule": True})
    return {"deny": deny["id"], "allow": allow["id"]}


def _access_order(c: Client) -> list:
    rows = [r for r in c.tenant.rows["rule:access"].values() if not r.get("defaultRule")]
    return [r["name"] for r in sorted(rows, key=lambda r: int(r["ruleOrder"]))]


def _prefixed(c: Client) -> Client:
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1"})
    _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443"}})
    return c


def test_a_new_access_rule_with_a_position_lands_above_the_rule_picked_and_undo_restores_the_order():
    """ASVS V1.4.1 · V11.1.1 · CWE-841 · CWE-670: an access rule built with 'Place it above' is created, then moved just above the picked rule with one bulk_reorder_rules write (the Default rule left out); the Undo deletes it and the other rules keep their order."""
    c = _prefixed(Client())
    ids = _with_access_policy(c)
    spec = {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": False, "access_above": ids["deny"]}
    p, r = _apply(c, spec)
    move = next(u for u in p["items"] if u["field"] == "position")
    assert move["status"] == "change" and "above 'Deny contractors'" in move["after"] and move["depends_on"], move
    assert r["status"] == "applied" and r["verification"]["mismatched"] == [], r
    assert _access_order(c) == ["pov1-access", "Deny contractors", "Allow staff"]
    assert [w[0] for w in c.tenant.writes if w[0] == "reorder"] == ["reorder"]
    _u, undone = _apply(c, r["inverse"])
    assert undone["status"] == "applied", undone
    assert _access_order(c) == ["Deny contractors", "Allow staff"]


def test_moving_an_existing_access_rule_is_undone_to_where_it_was():
    """ASVS V7.2.1 · CWE-1188: a rebuild that only moves the existing access rule records where it sat; the Undo puts it back exactly."""
    c = _prefixed(Client())
    ids = _with_access_policy(c)
    _apply(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": False})
    before = _access_order(c)
    assert before == ["Deny contractors", "Allow staff", "pov1-access"]
    _p, r = _apply(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": False, "access_above": ids["allow"]})
    assert r["status"] == "applied" and _access_order(c) == ["Deny contractors", "pov1-access", "Allow staff"]
    assert r["inverse"]["move_back"][0]["above"] is None
    _u, undone = _apply(c, r["inverse"])
    assert undone["status"] == "applied" and _access_order(c) == before
    assert c.tenant.by_name("rule:access", "pov1-access"), "an access rule that existed before is moved back, not deleted"


def test_an_access_policy_reordered_after_the_preview_is_a_conflict_and_nothing_moves(monkeypatch):
    """ASVS V11.1.3 · CWE-367: the order is read again right before the write; a change since the preview is a conflict and the order is left as it is."""
    c = _prefixed(Client())
    ids = _with_access_policy(c)
    _apply(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": False})
    orig = ops_zpa.HANDLERS["zpa_b_order"]

    def someone_reorders_first(run, g, units):
        rows = c.tenant.rows["rule:access"]
        rows[ids["deny"]]["ruleOrder"], rows[ids["allow"]]["ruleOrder"] = rows[ids["allow"]]["ruleOrder"], rows[ids["deny"]]["ruleOrder"]
        return orig(run, g, units)

    monkeypatch.setitem(ao.PLUGIN_HANDLERS, "zpa_b_order", someone_reorders_first)
    c.tenant.writes.clear()
    _p, r = _apply(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "timeout": False, "access_above": ids["deny"]})
    assert [u["status"] for u in r["items"] if u["field"] == "position"] == ["conflict"]
    assert not [w for w in c.tenant.writes if w[0] == "reorder"]
    assert _access_order(c) == ["Allow staff", "Deny contractors", "pov1-access"]


@pytest.mark.parametrize("above, why", [("72058304859999999", "not in ZPA now"), ("default", "always last")])
def test_a_position_that_cannot_be_used_blocks_the_plan(above, why):
    """ASVS V5.1.3 · CWE-20: a rule to place it above that is gone, or the Default rule, blocks the plan with the reason; a position without the access rule is refused."""
    c = _prefixed(Client())
    _with_access_policy(c)
    if above == "default":
        above = next(r["id"] for r in c.tenant.rows["rule:access"].values() if r.get("defaultRule"))
    p = ao.plan(c, {"type": "zpa_policies", "prefix": "pov1", "access": True, "access_above": above}, scope=ZPA)
    assert any(why in b for b in p["blockers"]), p["blockers"]
    with pytest.raises(ao.OperationError, match="Access"):
        ao.plan(c, {"type": "zpa_policies", "prefix": "pov1", "access": False, "timeout": True, "access_above": above}, scope=ZPA)


def test_the_picker_lists_the_access_policy_in_order_without_the_default_rule():
    """ASVS V4.1.3 · CWE-272: the builder's 'Place it above' list is the access policy top first; the Default rule is never offered."""
    c = _prefixed(Client())
    _with_access_policy(c)
    out = ao.read_objects(c, ops_zpa.FAMILY, ZPA)
    assert [r["name"] for r in out["access_rules"]] == ["Deny contractors", "Allow staff"]


def _published(c: Client) -> dict:
    """A segment that is already in ZPA (not built with a prefix) and publishes the domain a Test a list row expects to reach."""
    return c.tenant.add("segment", {"name": "HR access", "enabled": True, "domainNames": ["hr.corp.example"], "tcpPortRanges": ["443", "443"]})


def _rule_of(c: Client, name: str) -> dict:
    return c.tenant.by_name("rule:access", name) or {}


def test_an_access_rule_for_an_existing_segment_lands_above_the_deny_and_undo_deletes_only_the_rule():
    """ASVS V1.4.1 · V7.2.1 · CWE-841 · CWE-1188: a row ZPA denies is fixed with an access rule that names the segment already holding the domain (never changing the segment), placed above the deciding Deny; the phrase is always typed, and Undo deletes only the rule."""
    c = Client()
    seg = _published(c)
    ids = _with_access_policy(c)
    spec = {"type": "zpa_policies", "prefix": "fix", "access": True, "timeout": False, "access_segments": [seg["id"]], "access_above": ids["deny"]}
    p, r = _apply(c, spec)
    assert p["blockers"] == [] and p["confirm_phrase"] == "ALLOW ACCESS NOW", p
    assert p["spec"]["access_segments"] == [seg["id"]] and "HR access" in p["title"]
    assert any("cannot be created disabled" in w for w in p["warnings"]) and any("every user" in w for w in p["warnings"])
    assert r["status"] == "applied" and r["verification"]["mismatched"] == [], r
    rule = _rule_of(c, "fix-allow-hr-access-rule")
    assert rule["action"] == "ALLOW" and ops_zpa.rule_apps(rule) == [seg["id"]]
    assert _access_order(c) == ["fix-allow-hr-access-rule", "Deny contractors", "Allow staff"]
    assert [w for w in c.tenant.writes if w[1] == "segment"] == [], "the segment is only named by the rule, never changed"
    _u, undone = _apply(c, r["inverse"])
    assert undone["status"] == "applied", undone
    assert _access_order(c) == ["Deny contractors", "Allow staff"]
    assert c.tenant.rows["segment"][seg["id"]]["domainNames"] == ["hr.corp.example"]


def test_an_access_rule_for_an_existing_segment_conflicts_when_one_with_its_name_appeared_after_the_preview(monkeypatch):
    """ASVS V11.1.3 · CWE-367: a rule with the same name made between the preview and the write is a conflict; nothing is created or moved."""
    c = Client()
    seg = _published(c)
    ids = _with_access_policy(c)
    spec = {"type": "zpa_policies", "prefix": "fix", "access": True, "timeout": False, "access_segments": [seg["id"]], "access_above": ids["deny"]}
    orig = ops_zpa.HANDLERS["zpa_b_create"]

    def someone_creates_it_first(run, g, units):
        c.tenant.add("rule:access", {"name": g["target"]["name"], "action": "ALLOW", "ruleOrder": "9"})
        return orig(run, g, units)

    monkeypatch.setitem(ao.PLUGIN_HANDLERS, "zpa_b_create", someone_creates_it_first)
    c.tenant.writes.clear()
    _p, r = _apply(c, spec)
    assert [u["status"] for u in r["items"] if u["field"] == "exists"] == ["conflict"]
    assert not [w for w in c.tenant.writes if w[0] in ("create", "reorder")]


def test_existing_segments_are_checked_and_build_the_access_rule_alone():
    """ASVS V5.1.3 · CWE-20: existing segments must be ids read from ZPA (at most 20), still in ZPA, and take the access rule only."""
    c = Client()
    seg = _published(c)
    base = {"type": "zpa_policies", "prefix": "fix", "access": True, "timeout": False}
    for bad, why in ((["hr"], "pick it from the list"), ("1", "list of ids"), ([str(i) for i in range(1, 22)], "At most 20")):
        with pytest.raises(ao.OperationError, match=why):
            ao.plan(c, dict(base, access_segments=bad), scope=ZPA)
    with pytest.raises(ao.OperationError, match="untick Timeout"):
        ao.plan(c, dict(base, timeout=True, access_segments=[seg["id"]]), scope=ZPA)
    with pytest.raises(ao.OperationError, match="tick Access"):
        ao.plan(c, dict(base, access=False, timeout=True, access_segments=[seg["id"]]), scope=ZPA)
    p = ao.plan(c, dict(base, access_segments=["72058304859999999"]), scope=ZPA)
    assert any("not in ZPA now" in b for b in p["blockers"]), p["blockers"]
    assert ops_zpa.access_rule_name("fix", "Payroll access") == "fix-allow-payroll-access-rule"
    assert len(ops_zpa.access_rule_name("p" * 20, "x" * 200)) <= ops_zpa.ACCESS_NAME_MAX


# ── delete by prefix ────────────────────────────────────────────────────

ORDER = ["rule:access", "rule:timeout", "rule:inspection", "rule:isolation", "inspection_profile", "segment", "server_group", "segment_group",
         "provisioning_key", "connector_group"]


def test_prefix_delete_removes_only_prefixed_objects_in_dependency_order():
    """ASVS V4.1.3 · V1.4.1 · CWE-284 · CWE-841: everything named pov1-… goes, policies first and connector groups last; other objects stay."""
    c = _built()
    keep = c.tenant.add("segment_group", {"name": "pov10 is not pov1-"})
    other = c.tenant.add("segment_group", {"name": "Production apps"})
    c.tenant.writes.clear()
    p, r = _apply(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True})
    assert p["confirm_phrase"] == "DELETE POV1" and r["status"] == "applied"
    kinds = [k for op, k, _n in c.tenant.writes if op == "delete"]
    assert kinds == sorted(kinds, key=ORDER.index)
    assert set(c.tenant.rows["segment_group"]) == {keep["id"], other["id"]}
    assert not any(c.tenant.rows[k] for k in ORDER if k != "segment_group")
    assert r["inverse"] is None


def test_prefix_delete_needs_its_typed_phrase():
    """ASVS V4.1.3 · V11.1.1 · CWE-841: a delete is refused without 'DELETE <PREFIX>' typed, whatever its size; nothing is written."""
    c = _built()
    c.tenant.writes.clear()
    p = ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True}, scope=ZPA)
    r = ao.execute(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True}, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True,
                   assessor=ASSESSOR, confirm_text="APPLY")
    assert r["status"] == "refused" and c.tenant.writes == []


def test_an_unselected_dependency_is_flagged_and_its_users_kept():
    """ASVS V1.4.1 · CWE-841: picking a segment group without its segments keeps the group and names the segment that still uses it."""
    c = _built()
    sg = c.tenant.by_name("segment_group", "pov1-segment-group")
    p = ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "select": [f"segment_group:{sg['id']}"]}, scope=ZPA)
    u = next(x for x in p["items"] if x["object"]["name"] == "pov1-segment-group")
    assert u["status"] == "excluded" and "pov1-wildcard-corp-example-com" in u["reason"] and "not selected" in u["reason"]
    assert p["status"] == "nothing_to_do"


def test_objects_outside_the_prefix_that_use_ours_keep_them():
    """ASVS V1.4.1 · CWE-284: a production rule that names a prefixed segment keeps that segment (and what it needs) and is never deleted."""
    c = _built()
    seg = c.tenant.by_name("segment", "pov1-wildcard-corp-example-com")
    c.tenant.add("rule:access", {"name": "Production access", "action": "ALLOW",
                                 "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": seg["id"]}]}]})
    p, r = _apply(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True})
    kept = {u["object"]["name"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert "Production access" in kept["pov1-wildcard-corp-example-com"] and "not made with the prefix" in kept["pov1-wildcard-corp-example-com"]
    assert {"pov1-server-group", "pov1-segment-group", "pov1-connector-group"} <= set(kept)
    assert c.tenant.by_name("rule:access", "Production access") is not None and c.tenant.by_name("segment", seg["name"]) is not None


def test_ids_sent_by_the_browser_never_delete_an_object_without_the_prefix():
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a picked id of a production object is ignored; only re-read prefixed objects are deleted."""
    c = _built()
    prod = c.tenant.add("segment", {"name": "Production ERP", "domainNames": ["erp.example.com"]})
    p, r = _apply(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "select": [f"segment:{prod['id']}", "segment:123456"]})
    assert c.tenant.by_name("segment", "Production ERP") is not None
    assert any("do not carry the prefix" in w for w in p["warnings"])
    assert not any(u["status"] == "change" for u in p["items"])
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "select": ["idp:1"]}, scope=ZPA)
    with pytest.raises(ao.OperationError):
        ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1"}, scope=ZPA)


def test_a_connector_group_with_enrolled_connectors_is_kept():
    """ASVS V1.4.1 · CWE-841: a prefixed App Connector group with App Connectors enrolled is flagged and kept."""
    c = _built()
    c.tenant.by_name("connector_group", "pov1-connector-group")["connectors"] = [{"id": "1"}, {"id": "2"}]
    p = ao.plan(c, {"type": "zpa_prefix_delete", "prefix": "pov1", "everything": True}, scope=ZPA)
    u = next(x for x in p["items"] if x["object"]["name"] == "pov1-connector-group")
    assert u["status"] == "excluded" and "2 App Connectors are enrolled" in u["reason"]


# ── Undo, conflicts, the engine's gates ─────────────────────────────────

def test_undo_of_a_build_deletes_what_it_created_and_puts_back_what_it_changed():
    """ASVS V1.4.1 · V11.1.1 · CWE-841: the inverse of a build is a previewed delete of the objects it created plus a restore of the fields it changed."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 3})
    _p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 8})
    _p2, seg = _apply(c, {"type": "zpa_app_segments", "prefix": "pov1", "wildcard": {"domain": "corp.example.com", "tcp": "443"}})
    _u, undone = _apply(c, seg["inverse"])
    assert undone["status"] == "applied" and c.tenant.rows["segment"] == {} and c.tenant.rows["server_group"] == {}
    assert c.tenant.names("connector_group") == ["pov1-connector-group"], "the undo of the segments leaves the earlier build alone"
    _u2, undone2 = _apply(c, r["inverse"])
    assert undone2["status"] == "applied" and c.tenant.by_name("provisioning_key", "pov1-provisioning-key")["maxUsage"] == "3"


def test_undo_leaves_an_object_someone_changed_since():
    """ASVS V1.4.1 · CWE-362: a restore whose object changed after the build is excluded, never overwritten."""
    c = Client()
    _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 3})
    _p, r = _apply(c, {"type": "zpa_connector_group", "prefix": "pov1", "max_usage": 8})
    c.tenant.by_name("provisioning_key", "pov1-provisioning-key")["maxUsage"] = "12"
    p = ao.plan(c, r["inverse"], scope=ZPA)
    assert p["status"] == "nothing_to_do" and any("changed in ZPA since the build" in u["reason"] for u in p["items"])


def test_a_tenant_that_moved_after_the_preview_gets_nothing_written():
    """ASVS V11.1.1 · CWE-362: an object made between the preview and the apply changes the plan hash; nothing is written."""
    c = Client()
    spec = {"type": "zpa_connector_group", "prefix": "pov1"}
    p = ao.plan(c, spec, scope=ZPA)
    c.tenant.add("connector_group", {"name": "pov1-connector-group", "enabled": False})
    c.tenant.writes.clear()
    r = ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor=ASSESSOR)
    assert r["status"] == "plan_changed" and c.tenant.writes == []


def test_write_mode_off_refuses_before_reading():
    """ASVS V4.1.3 · CWE-1188: the engine refuses a ZPA build with write mode off; nothing is read or written."""
    c = Client()
    with pytest.raises(PermissionError):
        ao.execute(c, {"type": "zpa_connector_group", "prefix": "pov1"}, plan_hash="0" * 64, scope=ZPA, writes_enabled=False)
    assert c.tenant.reads == [] and c.tenant.writes == []


def test_every_zpa_builder_write_goes_through_the_shared_path(monkeypatch):
    """ASVS V1.14.1 · CWE-1059: each builder kind maps to an SDK method that exists in the installed SDK; the writes are pack_ops calls."""
    import zscaler.zpa.zpa_service as zs
    svc_types = {n: getattr(zs.ZPAService, n).fget.__annotations__.get("return") for n in dir(zs.ZPAService)
                 if isinstance(getattr(zs.ZPAService, n), property)}
    for kind, (svc, c, u, d) in ops.ZPA_KINDS.items():
        cls = svc_types[svc]
        for m in (c, u, d):
            assert callable(getattr(cls, m, None)), f"{kind}: {svc}.{m} is not in the installed SDK"
    seen = []
    real = ops.call
    monkeypatch.setattr(ops, "call", lambda fn, *a, **k: seen.append(k.get("kind")) or real(fn, *a, **k))
    _built()
    assert {"zpa_connector_group", "zpa_provisioning_key", "zpa_segment_group", "zpa_server_group", "zpa_segment", "zpa_access_rule",
            "zpa_timeout_rule", "zpa_inspection_profile", "zpa_inspection_rule", "zpa_isolation_rule"} <= set(seen)


def test_read_objects_lists_the_pick_lists_without_secrets():
    """ASVS V8.3.4 · CWE-200: the form's lists carry ids and names only; the provisioning key value is never among them."""
    c = _built()
    out = ao.read_objects(c, ops_zpa.FAMILY, ZPA)
    assert {"connector_groups", "isolation_profiles", "pra_portals", "certificates", "inventory", "verticals", "locations"} <= set(out)
    assert any(o["name"] == "pov1-provisioning-key" for o in out["inventory"]) and CANARY_KEY not in json.dumps(out)


# ── Through the app's routes (preview, gated apply as a job, the one-time reveal) ──

API_CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}
API_SCOPE = {"scopes": ["zpa"], "channels": {}, "from_page": True}


def test_the_key_through_the_api_is_in_no_job_poll_audit_or_record_and_is_revealed_once(isolated, monkeypatch, caplog):
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-200 · A09:2021 · WSTG-INFO-05: the key is absent from the job's logs and result, the audit log and the change history; the reveal answers it once with no-store."""
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import pack_jobs
    import security
    caplog.set_level(logging.DEBUG)
    client = Client()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: client)
    monkeypatch.setattr(security, "_write_override", True)
    real_start = pack_jobs.start

    def start_and_finish(*a, **k):
        job = real_start(*a, **k)
        job.thread.join(20)
        return job
    monkeypatch.setattr(pack_jobs, "start", start_and_finish)
    api = TestClient(srv.app)
    spec = {"type": "zpa_connector_group", "prefix": "pov1"}
    prev = api.post("/api/operations/preview", json=dict(API_CREDS, **API_SCOPE, operation=spec))
    assert prev.status_code == 200, prev.text
    started = api.post("/api/operations/apply/start", json=dict(API_CREDS, **API_SCOPE, operation=spec, plan_hash=prev.json()["plan_hash"], confirm=True,
                                                                assessor=ASSESSOR))
    assert started.status_code == 200, started.text
    snap = api.get(f"/api/dlp-packs/jobs/{started.json()['job_id']}")
    res = snap.json()["result"]
    assert res["status"] == "applied", res
    history = api.get("/api/operations").text + api.get(f"/api/operations/{res['operation_id']}").text
    blob = _everything_that_was_written(isolated, res, caplog.text, snap.text + history + prev.text)
    assert CANARY_KEY not in blob and "CANARY-PROVISIONING" not in blob
    token = res["one_time_secrets"][0]["token"]
    first = api.post("/api/operations/zpa/provisioning-key", json={"token": token})
    second = api.post("/api/operations/zpa/provisioning-key", json={"token": token})
    assert first.status_code == 200 and first.json()["provisioning_key"] == CANARY_KEY and "no-store" in first.headers["cache-control"]
    assert second.status_code == 404 and CANARY_KEY not in second.text
    assert CANARY_KEY not in read_store_text(os.path.join(isolated, "audit.log"))
