"""Restore breadth (config_backup.py, ops_config_restore.py): the wider
catalogue (ZIA NAT and traffic capture rules, ZPA user portals, PRA
credentials, SCIM attributes and groups, Service Edges, enrollment
certificates, Client Connector apps and devices), ZIA objects and rules that
clone (forwarding, bandwidth, NAT, traffic capture, workload groups, cloud
app instances, tenancy profiles), ZPA policy rules with every operand
remapped in dependency order, Browser Access / PRA / inspection segments,
Client Connector app profiles and entitlements from a backup, the separately
confirmed tenant-bound mode (static IPs, GRE tunnels, locations) and the
label / prefix selection. Every write goes through the Bulk changes engine:
plan hash, re-read before the write, read-back, Undo.

Everything runs on the stateful fake tenant in tests/config_fake.py: no
network, state files in tmp_path."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import config_backup as cb  # noqa: E402
import ops_config_restore as ocr  # noqa: E402
from config_fake import Client, Tenant, state  # noqa: E402

ASSESSOR = "Jane Doe"
SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc"], {"web_dlp": "zscaler", "email_dlp": "zscaler"})
CANARY = "CANARY-PW-5b7e1d"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ocr, "_HANDOVER", {})
    ao.load_plugins()
    return tmp_path


def backup_of(data, products=("zia", "zpa", "zcc"), *, key="key-source"):
    c = Client(Tenant(data))
    got = cb.capture(c, list(products), SCOPE)
    return cb.save_backup(cb.build_doc(got["types"], {"tenant_label": "Source", "tenant_key": key, "products": list(products)}))["id"]


def spec(product, bid, mode="update_matching", target="other", **kw):
    s = {"type": f"config_restore_{product}", "source": {"backup": bid}, "mode": mode, "target": target,
         "target_profile_id": "tgt" if target == "other" else ""}
    s.update(kw)
    return s


def apply(client, sp, *, confirm=None):
    p = ao.plan(client, sp, scope=SCOPE, tenant_label="target")
    r = ao.execute(client, sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"] if confirm is None else confirm)
    return p, r


def undo(client, r):
    inv = r["inverse"]
    p = ao.plan(client, inv, scope=SCOPE, tenant_label="target")
    return p, ao.execute(client, inv, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR,
                         tenant_label="target", confirm_text=p["confirm_phrase"])


def same_state(a, b):
    """Two state() snapshots hold the same configuration (a field empty on one
    side and absent on the other is no difference, as in the diff)."""
    assert a.keys() == b.keys()
    for k in a:
        assert a[k].keys() == b[k].keys(), k
        for n in a[k]:
            assert cb.field_diff(a[k][n], b[k][n]) == [], (k, n, cb.field_diff(a[k][n], b[k][n]))
    return True


def item(p, key, name):
    return next(u for u in p["items"] if (u["object"] or {}).get("type") == key and u["object"].get("name") == name)


# ── #3 the catalogue: what a backup and the local cache read ────────────

def test_the_catalogue_reads_at_least_as_many_types_as_the_other_configuration_tools():
    """ASVS V1.14.1 · CWE-1059: ZIA, ZPA and Client Connector each have at least 53, 28 and 17 backed-up object types, NAT and traffic capture rules among them."""
    count = {p: len(cb.types_for(p)) for p in cb.PRODUCTS}
    assert count["zia"] >= 53 and count["zpa"] >= 28 and count["zcc"] >= 17, count
    for k in ("zia.nat_control_rules", "zia.traffic_capture_rules", "zpa.user_portals", "zpa.pra_credentials", "zpa.scim_attributes",
              "zpa.scim_groups", "zpa.service_edges", "zpa.enrollment_certificates", "zcc.admin_users", "zcc.custom_ip_apps",
              "zcc.predefined_ip_apps", "zcc.process_apps", "zcc.devices"):
        assert k in cb.BY_KEY, k


def test_the_cache_reads_the_new_types_per_identity_provider_and_without_people_or_keys(isolated):
    """ASVS V8.3.4 · CWE-359 · WSTG-CONF-11: SCIM groups are read per identity provider, devices keep no user, host name or hardware id, certificates and credentials keep no PEM or secret."""
    t = Tenant({
        "zia.nat_control_rules": [{"id": 1, "name": "DNAT web", "order": 1, "state": "ENABLED"}],
        "zia.traffic_capture_rules": [{"id": 2, "name": "Capture DNS", "order": 1, "state": "ENABLED"}],
        "zpa.idps": [{"id": "11", "name": "Okta"}, {"id": "12", "name": "Azure"}],
        "zpa.scim_groups": [{"id": "31", "name": "Finance", "idp_id": "11"}, {"id": "32", "name": "Sales", "idp_id": "12"}],
        "zpa.scim_attributes": [{"id": "41", "name": "department", "idp_id": "11"}],
        "zpa.enrollment_certificates": [{"id": "51", "name": "Connector", "certificate": "-----BEGIN CERTIFICATE-----x", "private_key": CANARY}],
        "zpa.pra_credentials": [{"id": "61", "name": "root ssh", "credential_type": "USERNAME_PASSWORD", "password": CANARY}],
        "zcc.devices": [{"id": 71, "os_type": "Windows", "agent_version": "4.5", "user_name": "alice@corp.example",
                         "machine_hostname": "LAPTOP-1", "mac_address": "00:11:22:33:44:55", "serial_number": "SN1", "udid": "U1"}],
    })
    got = cb.capture(Client(t), ["zia", "zpa", "zcc"], SCOPE)
    ty = got["types"]
    assert [r["name"] for r in ty["zia.nat_control_rules"]] == ["DNAT web"] and ty["zia.traffic_capture_rules"]
    assert sorted((r["name"], r["idp_id"]) for r in ty["zpa.scim_groups"]) == [("Finance", "11"), ("Sales", "12")]
    assert ty["zcc.devices"] == [{"id": 71, "os_type": "Windows", "agent_version": "4.5"}]
    raw = json.dumps(ty)
    assert CANARY not in raw and "BEGIN CERTIFICATE" not in raw and "alice@" not in raw and "LAPTOP-1" not in raw
    res = cb.refresh_cache("prof-a", got["types"], {"tenant_label": "acme"})
    assert res["types"] >= 8 and cb.read_cache("prof-a")["objects"]["zia.nat_control_rules"]


# ── #11 clone breadth: ZIA objects and rules that clone ─────────────────

ZIA_BREADTH = {
    "zia.rule_labels": [{"id": 1, "name": "Team A"}],
    "zia.bandwidth_classes": [{"id": 81, "name": "Video", "type": "BANDWIDTH_CAT_CUSTOM", "web_applications": ["YOUTUBE"]},
                              {"id": 82, "name": "General surfing", "type": "BANDWIDTH_CAT_GENERAL", "is_name_l10n_tag": True}],
    "zia.bandwidth_control_rules": [{"id": 91, "name": "Cap video", "order": 1, "state": "ENABLED", "max_bandwidth": 20,
                                     "bandwidth_classes": [{"id": 81, "name": "Video"}], "labels": [{"id": 1, "name": "Team A"}]}],
    "zia.workload_groups": [{"id": 101, "name": "Prod VMs", "expression": "tag:env=prod"}],
    "zia.cloud_app_instances": [{"id": 111, "name": "Corp Box", "instance_type": "BOX", "instance_identifiers": [{"instance_identifier": "corp.box.com"}]}],
    "zia.tenancy_restriction_profiles": [{"id": 121, "name": "Only corp M365", "app_type": "MSLOGINSERVICES", "item_value": ["corp.example"]}],
    "zia.forwarding_rules": [{"id": 131, "name": "Direct to SaaS", "order": 1, "state": "ENABLED", "forward_method": "DIRECT"}],
    "zia.nat_control_rules": [{"id": 141, "name": "DNAT web", "order": 1, "state": "ENABLED", "redirect_ip": "10.0.0.5",
                               "labels": [{"id": 1, "name": "Team A"}]}],
    "zia.traffic_capture_rules": [{"id": 151, "name": "Capture DNS", "order": 1, "state": "ENABLED", "action": "CAPTURE"}],
    "zia.firewall_rules": [{"id": 161, "name": "Allow prod", "order": 1, "state": "ENABLED", "action": "ALLOW",
                            "workload_groups": [{"id": 101, "name": "Prod VMs"}]}],
}
ZIA_KEYS = [k for k in ZIA_BREADTH if k != "zia.rule_labels"]


def zia_target():
    return Tenant({k: [] for k in ZIA_BREADTH} | {"zia.bandwidth_classes": [{"id": 9082, "name": "General surfing", "type": "BANDWIDTH_CAT_GENERAL",
                                                                            "is_name_l10n_tag": True}]})


def test_forwarding_bandwidth_nat_capture_workload_instances_and_tenancy_clone_with_references_remapped():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: every newly writable ZIA type is created in dependency order, its references remapped by name, rules disabled, and read back."""
    bid = backup_of(ZIA_BREADTH, ["zia"])
    tgt = Client(zia_target())
    p, r = apply(tgt, spec("zia", bid))
    assert p["status"] == "ready" and r["status"] == "applied", (p["blockers"], r.get("stopped"))
    order = [k for op, k, _n in tgt.tenant.writes if op == "create"]
    assert order.index("zia.bandwidth_classes") < order.index("zia.bandwidth_control_rules")
    assert order.index("zia.workload_groups") < order.index("zia.firewall_rules")
    rows = tgt.tenant.data
    assert sorted(r["name"] for r in rows["zia.bandwidth_classes"]) == ["General surfing", "Video"]   # the predefined class is not copied
    video = tgt.tenant.by_name("zia.bandwidth_classes", "Video")
    assert tgt.tenant.by_name("zia.bandwidth_control_rules", "Cap video")["bandwidth_classes"] == [{"id": video["id"]}]
    wg = tgt.tenant.by_name("zia.workload_groups", "Prod VMs")
    assert tgt.tenant.by_name("zia.firewall_rules", "Allow prod")["workload_groups"] == [{"id": wg["id"]}]
    for k in ("zia.bandwidth_control_rules", "zia.forwarding_rules", "zia.nat_control_rules", "zia.traffic_capture_rules", "zia.firewall_rules"):
        assert all(x["state"] == "DISABLED" for x in rows[k]), k
    for k in ("zia.cloud_app_instances", "zia.tenancy_restriction_profiles"):
        assert len(rows[k]) == 1, k
    assert all(u.get("verified") is True for u in r["items"] if u["status"] == "applied" and u["kind"] == "object"
               and u["object"]["type"] != "backup")


def test_the_breadth_clone_undoes_exactly():
    """ASVS V7.2.2 · CWE-460 · WSTG-BUSL-06: the Undo of a breadth clone deletes what it created, in reverse order, back to the target as it was."""
    bid = backup_of(ZIA_BREADTH, ["zia"])
    tgt = Client(zia_target())
    before = state(tgt.tenant, ZIA_KEYS)
    _p, r = apply(tgt, spec("zia", bid))
    pu, ru = undo(tgt, r)
    assert ru["status"] == "applied", ru.get("stopped")
    assert same_state(state(tgt.tenant, ZIA_KEYS), before)


# ── #7 ZPA policy rules: every operand remapped, dependency order ───────

def zpa_source():
    return {
        "zpa.idps": [{"id": "11", "name": "Okta"}],
        "zpa.saml_attributes": [{"id": "21", "name": "Department", "idp_id": "11"}],
        "zpa.scim_groups": [{"id": "31", "name": "Finance", "idp_id": "11"}],
        "zpa.scim_attributes": [{"id": "35", "name": "costCenter", "idp_id": "11"}],
        "zpa.posture_profiles": [{"id": "41", "name": "CrowdStrike", "posture_udid": "udid-src-1"}],
        "zpa.trusted_networks": [{"id": "45", "name": "HQ", "network_id": "net-src-1"}],
        "zpa.machine_groups": [{"id": "47", "name": "Kiosks"}],
        "zpa.connector_groups": [{"id": "301", "name": "DC1", "enabled": True}],
        "zpa.segment_groups": [{"id": "401", "name": "Apps", "enabled": True}],
        "zpa.server_groups": [{"id": "501", "name": "Web", "enabled": True, "app_connector_groups": [{"id": "301"}]}],
        "zpa.application_segments": [{"id": "601", "name": "Intranet", "enabled": True, "segment_group_id": "401", "server_groups": [{"id": "501"}],
                                      "domain_names": ["intranet.corp.example"], "tcp_port_ranges": ["443", "443"]}],
        "zpa.service_edge_groups": [{"id": "801", "name": "PSE Frankfurt"}],
        "zpa.isolation_profiles": [{"id": "811", "name": "Isolate risky"}],
        "zpa.inspection_profiles": [{"id": "821", "name": "OWASP top 10"}],
        "zpa.pra_credentials": [{"id": "831", "name": "root ssh"}],
        "zpa.access_rules": [
            {"id": "701", "name": "Finance to intranet", "action": "ALLOW", "rule_order": "1", "custom_msg": "Ask IT",
             "app_connector_groups": [{"id": "301", "name": "DC1"}], "app_server_groups": [{"id": "501"}],
             "conditions": [
                 {"id": "c1", "operator": "OR", "negated": False, "operands": [
                     {"id": "o1", "object_type": "APP", "lhs": "id", "rhs": "601", "name": "Intranet"},
                     {"id": "o2", "object_type": "APP_GROUP", "lhs": "id", "rhs": "401", "name": "Apps"}]},
                 {"operator": "OR", "negated": False, "operands": [{"object_type": "SCIM_GROUP", "lhs": "11", "rhs": "31"},
                                                                    {"object_type": "SCIM", "lhs": "35", "rhs": "CC-7", "idp_id": "11"}]},
                 {"operator": "AND", "negated": True, "operands": [{"object_type": "POSTURE", "lhs": "udid-src-1", "rhs": "false"},
                                                                   {"object_type": "TRUSTED_NETWORK", "lhs": "net-src-1", "rhs": "true"}]},
                 {"operator": "OR", "negated": False, "operands": [{"object_type": "SAML", "lhs": "21", "rhs": "Sales"}]},
                 {"operator": "OR", "negated": False, "operands": [{"object_type": "MACHINE_GRP", "lhs": "id", "rhs": "47"}]},
                 {"operator": "OR", "negated": False, "operands": [{"object_type": "CLIENT_TYPE", "lhs": "id", "rhs": "zpn_client_type_zapp"}]}]},
            {"id": "702", "name": "Old contractor rule", "action": "DENY", "rule_order": "2", "disabled": "1", "conditions": []},
            {"id": "799", "name": "Default access", "action": "DENY", "default_rule": True, "conditions": []}],
        "zpa.timeout_rules": [{"id": "711", "name": "Reauth daily", "action": "RE_AUTH", "reauth_timeout": "86400", "reauth_idle_timeout": "3600",
                               "conditions": [{"operator": "OR", "negated": False, "operands": [
                                   {"object_type": "APP_GROUP", "lhs": "id", "rhs": "401"}]}]}],
        "zpa.forwarding_rules": [{"id": "721", "name": "Bypass intranet on net", "action": "BYPASS", "conditions": [
            {"operator": "OR", "negated": False, "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]}],
        "zpa.isolation_rules": [{"id": "731", "name": "Isolate unmanaged", "action": "ISOLATE", "zpn_isolation_profile_id": "811", "conditions": [
            {"operator": "OR", "negated": False, "operands": [{"object_type": "CLIENT_TYPE", "lhs": "id", "rhs": "zpn_client_type_exporter"}]},
            {"operator": "OR", "negated": False, "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]}],
        "zpa.inspection_rules": [{"id": "741", "name": "Inspect intranet", "action": "INSPECT", "zpn_inspection_profile_id": "821", "conditions": [
            {"operator": "OR", "negated": False, "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]}],
        "zpa.redirection_rules": [{"id": "751", "name": "Prefer Frankfurt", "action": "REDIRECT_PREFERRED", "service_edge_groups": [{"id": "801"}],
                                   "conditions": [{"operator": "OR", "operands": [{"object_type": "CLIENT_TYPE", "lhs": "id",
                                                                                   "rhs": "zpn_client_type_zapp"}]}]}],
        "zpa.credential_rules": [{"id": "761", "name": "Inject root", "action": "INJECT_CREDENTIALS", "credential": {"id": "831"},
                                  "conditions": [{"operator": "OR", "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]},
                                 {"id": "762", "name": "Not for kiosks", "action": "INJECT_CREDENTIALS", "credential": {"id": "831"},
                                  "conditions": [{"operator": "OR", "negated": True, "operands": [
                                      {"object_type": "MACHINE_GRP", "lhs": "id", "rhs": "47"}]}]}],
        "zpa.capabilities_rules": [{"id": "771", "name": "No clipboard", "action": "CHECK_CAPABILITIES",
                                    "privileged_capabilities": {"capabilities": ["FILE_DOWNLOAD", "MONITOR_SESSION"]},
                                    "conditions": [{"operator": "OR", "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]}],
    }


ZPA_RULE_KEYS = ["zpa.access_rules", "zpa.timeout_rules", "zpa.forwarding_rules", "zpa.isolation_rules", "zpa.inspection_rules",
                 "zpa.redirection_rules", "zpa.credential_rules", "zpa.capabilities_rules"]


def zpa_target():
    src = zpa_source()
    t = {k: [] for k in src}
    t.update({"zpa.idps": [{"id": "91", "name": "Okta"}], "zpa.saml_attributes": [{"id": "92", "name": "Department", "idp_id": "91"}],
              "zpa.scim_groups": [{"id": "93", "name": "Finance", "idp_id": "91"}, {"id": "96", "name": "Finance", "idp_id": "99"}],
              "zpa.scim_attributes": [{"id": "95", "name": "costCenter", "idp_id": "91"}],
              "zpa.posture_profiles": [{"id": "94", "name": "CrowdStrike", "posture_udid": "udid-tgt-9"}],
              "zpa.trusted_networks": [{"id": "97", "name": "HQ", "network_id": "net-tgt-9"}],
              "zpa.machine_groups": [{"id": "98", "name": "Kiosks"}],
              "zpa.service_edge_groups": [{"id": "981", "name": "PSE Frankfurt"}],
              "zpa.isolation_profiles": [{"id": "982", "name": "Isolate risky"}],
              "zpa.inspection_profiles": [{"id": "983", "name": "OWASP top 10"}],
              "zpa.pra_credentials": [{"id": "984", "name": "root ssh"}]})
    return Tenant(t)


def _ops(rule):
    return sorted((o["object_type"], o["lhs"], o["rhs"], o.get("idp_id", "")) for b in rule["conditions"] for o in b["operands"])


def test_zpa_policy_rules_clone_with_every_operand_remapped_after_what_they_use():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: access, timeout, forwarding, isolation, inspection, redirection, credential and capabilities rules are created after their segments with every operand, group and profile pointed at the target's objects."""
    bid = backup_of(zpa_source(), ["zpa"])
    tgt = Client(zpa_target())
    p, r = apply(tgt, spec("zpa", bid, keep_state=True))
    assert p["status"] == "ready" and r["status"] == "applied", (p["blockers"], r.get("stopped"), [u for u in r["items"] if u["status"] == "failed"])
    order = [k for op, k, _n in tgt.tenant.writes if op == "create"]
    assert order.index("zpa.application_segments") < order.index("zpa.access_rules")
    assert all(order.index("zpa.segment_groups") < order.index(k) for k in ZPA_RULE_KEYS)
    T = tgt.tenant
    seg, sg, cg, srv = (T.by_name("zpa.application_segments", "Intranet")["id"], T.by_name("zpa.segment_groups", "Apps")["id"],
                        T.by_name("zpa.connector_groups", "DC1")["id"], T.by_name("zpa.server_groups", "Web")["id"])
    acc = T.by_name("zpa.access_rules", "Finance to intranet")
    assert _ops(acc) == sorted([("APP", "id", seg, ""), ("APP_GROUP", "id", sg, ""), ("SCIM_GROUP", "91", "93", ""),
                                ("SCIM", "95", "CC-7", "91"), ("POSTURE", "udid-tgt-9", "false", ""), ("TRUSTED_NETWORK", "net-tgt-9", "true", ""),
                                ("SAML", "92", "Sales", ""), ("MACHINE_GRP", "id", "98", ""), ("CLIENT_TYPE", "id", "zpn_client_type_zapp", "")])
    neg = next(b for b in acc["conditions"] if b["negated"])
    assert neg["operator"] == "AND" and {o["object_type"] for o in neg["operands"]} == {"POSTURE", "TRUSTED_NETWORK"}
    assert acc["app_connector_groups"] == [{"id": cg}] and acc["app_server_groups"] == [{"id": srv}] and acc["custom_msg"] == "Ask IT"
    assert T.by_name("zpa.isolation_rules", "Isolate unmanaged")["zpn_isolation_profile_id"] == "982"
    assert T.by_name("zpa.inspection_rules", "Inspect intranet")["zpn_inspection_profile_id"] == "983"
    assert T.by_name("zpa.redirection_rules", "Prefer Frankfurt")["service_edge_groups"] == [{"id": "981"}]
    assert T.by_name("zpa.credential_rules", "Inject root")["credential"] == {"id": "984"}
    assert T.by_name("zpa.capabilities_rules", "No clipboard")["privileged_capabilities"] == {"capabilities": ["FILE_DOWNLOAD", "MONITOR_SESSION"]}
    to = T.by_name("zpa.timeout_rules", "Reauth daily")
    assert to["reauth_timeout"] == "86400" and _ops(to) == [("APP_GROUP", "id", sg, "")]
    # the v1 calls get dict blocks (exact), the v2 calls tuples the SDK rebuilds into the same blocks
    calls = {m: kw for m, _k, kw in T.calls}
    assert isinstance(calls["add_access_rule"]["conditions"][0], dict) and isinstance(calls["add_redirection_rule_v2"]["conditions"][0], tuple)
    assert all(u.get("verified") is True for u in r["items"] if u["status"] == "applied" and u["object"]["type"] in ZPA_RULE_KEYS)


def test_zpa_rules_that_cannot_be_sent_exactly_are_left_out_with_the_reason():
    """ASVS V1.4.1 · CWE-684 · WSTG-BUSL-01: a disabled rule, a v2 rule with a NOT block, the default rule and an operand no backup carries (cross-tenant) are excluded, never approximated."""
    src = zpa_source()
    src["zpa.access_rules"].append({"id": "703", "name": "From branch", "action": "ALLOW", "conditions": [
        {"operator": "OR", "negated": False, "operands": [{"object_type": "LOCATION", "lhs": "id", "rhs": "123"}]}]})
    bid = backup_of(src, ["zpa"])
    tgt = Client(zpa_target())
    p = ao.plan(tgt, spec("zpa", bid, keep_state=True), scope=SCOPE, tenant_label="target")
    assert "disabled state" in item(p, "zpa.access_rules", "Old contractor rule")["reason"]
    assert "NOT block" in item(p, "zpa.credential_rules", "Not for kiosks")["reason"]
    assert "backups do not carry" in item(p, "zpa.access_rules", "From branch")["reason"]
    assert not any(u["object"].get("name") == "Default access" for u in p["items"])
    assert item(p, "zpa.access_rules", "Finance to intranet")["status"] == "change"


def test_a_new_zpa_rule_needs_the_explicit_tick_because_it_cannot_be_created_disabled():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: without 'keep each rule's state', no ZPA policy rule is created (the SDK has no disabled state); the segments still are."""
    bid = backup_of(zpa_source(), ["zpa"])
    tgt = Client(zpa_target())
    p = ao.plan(tgt, spec("zpa", bid), scope=SCOPE, tenant_label="target")
    for k in ZPA_RULE_KEYS:
        assert all(u["status"] == "excluded" for u in p["items"] if u["object"].get("type") == k), k
    assert "cannot be created disabled" in item(p, "zpa.access_rules", "Finance to intranet")["reason"]
    assert item(p, "zpa.application_segments", "Intranet")["status"] == "change"


def test_a_zpa_rule_restore_updates_in_place_rereads_first_and_undoes_exactly():
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: restoring a changed access rule updates it with its conditions; a rule changed since the preview stops the run; Undo puts the rule back."""
    src = zpa_source()
    bid = backup_of(src, ["zpa"])
    live = zpa_source()
    rule = live["zpa.access_rules"][0]
    rule["action"] = "DENY"
    rule["conditions"] = [b for b in rule["conditions"] if b["operands"][0]["object_type"] != "SAML"]
    tgt = Client(Tenant(live))
    keys = ["zpa.access_rules"]
    before = state(tgt.tenant, keys)
    sp = spec("zpa", bid, target="same", types=keys)
    p, r = apply(tgt, sp)
    assert r["status"] == "applied", r.get("stopped")
    got = tgt.tenant.by_name("zpa.access_rules", "Finance to intranet")
    assert got["action"] == "ALLOW" and ("SAML", "21", "Sales", "") in _ops(got)
    assert any(m == "update_access_rule" for m, _k, _kw in tgt.tenant.calls)
    _pu, ru = undo(tgt, r)
    assert ru["status"] == "applied" and same_state(state(tgt.tenant, keys), before)
    # a colleague edits the rule between the preview and the write: nothing is overwritten
    tgt2 = Client(Tenant(live))
    p2 = ao.plan(tgt2, sp, scope=SCOPE, tenant_label="target")
    tgt2.tenant.by_name("zpa.access_rules", "Finance to intranet")["description"] = "edited meanwhile"
    r2 = ao.execute(tgt2, sp, plan_hash=p2["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                    confirm_text=p2["confirm_phrase"])
    assert r2["status"] != "applied" and not any(op == "update" and k == "zpa.access_rules" for op, k, _n in tgt2.tenant.writes)


# ── Browser Access, PRA and inspection segments in the JSON restore ─────

def special_source():
    return {
        "zpa.segment_groups": [{"id": "401", "name": "Apps", "enabled": True}],
        "zpa.server_groups": [{"id": "501", "name": "Web", "enabled": True}],
        "zpa.certificates": [{"id": "901", "name": "wiki.corp.example", "certificate": "-----BEGIN CERTIFICATE-----"}],
        "zpa.application_segments": [
            {"id": "611", "name": "Wiki BA", "enabled": True, "segment_group_id": "401", "server_groups": [{"id": "501"}],
             "domain_names": ["wiki.corp.example"], "tcp_port_ranges": ["443", "443"],
             "clientless_apps": [{"id": "6111", "app_id": "611", "name": "wiki", "domain": "wiki.corp.example", "application_port": "443",
                                  "application_protocol": "HTTPS", "certificate_id": "901", "certificate_name": "wiki.corp.example"}]},
            {"id": "612", "name": "Servers PRA", "enabled": True, "segment_group_id": "401", "server_groups": [{"id": "501"}],
             "domain_names": ["srv1.corp.example"], "tcp_port_ranges": ["22", "22"],
             "pra_apps": [{"id": "6121", "app_id": "612", "name": "srv1", "domain": "srv1.corp.example", "application_port": "22",
                           "application_protocol": "SSH"}]}],
    }


def _special(data):
    d = dict(data)
    segs = d["zpa.application_segments"]
    d["zpa.ba_segments"] = [s for s in segs if s.get("clientless_apps")]
    d["zpa.pra_segments"] = [s for s in segs if s.get("pra_apps")]
    d["zpa.inspection_segments"] = [s for s in segs if s.get("inspection_apps")]
    return d


def test_browser_access_and_pra_segments_clone_with_their_applications():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: a Browser Access segment is created with its clientless apps (no source ids, certificate by name) and a PRA segment with its apps as common_apps_dto; the plain segment type leaves both to them."""
    bid = backup_of(_special(special_source()), ["zpa"])
    tgt = Client(Tenant({"zpa.segment_groups": [], "zpa.server_groups": [], "zpa.application_segments": [], "zpa.ba_segments": [],
                         "zpa.pra_segments": [], "zpa.inspection_segments": [],
                         "zpa.certificates": [{"id": "9901", "name": "wiki.corp.example"}]}))
    p, r = apply(tgt, spec("zpa", bid))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    assert "its own type" in item(p, "zpa.application_segments", "Wiki BA")["reason"]
    calls = {m: kw for m, _k, kw in tgt.tenant.calls}
    ba = calls["add_segment_ba"]["clientless_apps"]
    assert ba == [{"name": "wiki", "domain": "wiki.corp.example", "application_port": "443", "application_protocol": "HTTPS",
                   "certificate_id": "9901"}]
    pra = calls["add_segment_pra"]["common_apps_dto"]["apps_config"]
    assert pra[0]["domain"] == "srv1.corp.example" and pra[0]["app_types"] == ["SECURE_REMOTE_ACCESS"] and "id" not in pra[0]
    assert "add_segment" not in calls
    assert all(u.get("verified") is True for u in r["items"] if u["status"] == "applied" and u["object"]["type"] in
               ("zpa.ba_segments", "zpa.pra_segments"))


def test_a_special_segment_update_sends_the_targets_own_applications_back_and_full_mode_spares_it():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: updating a Browser Access segment changes its fields and sends the target's clientless apps back as read; the plain segment type never deletes a special segment."""
    src = _special(special_source())
    src["zpa.ba_segments"][0] = dict(src["zpa.ba_segments"][0], description="restored description")
    bid = backup_of(src, ["zpa"])
    live = _special(special_source())
    tgt = Client(Tenant(live))
    p, r = apply(tgt, spec("zpa", bid, target="same", mode="full", types=["zpa.ba_segments", "zpa.application_segments"]))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    upd = next(kw for m, _k, kw in tgt.tenant.calls if m == "update_segment_ba")
    assert upd["description"] == "restored description" and upd["clientless_apps"][0]["id"] == "6111"
    assert not any(op == "delete" for op, _k, _n in tgt.tenant.writes)


# ── #8 Client Connector: app profiles and entitlements from a backup ────

def zcc_data(**over):
    d = {"zcc.app_profiles": [{"id": 51, "name": "Windows default", "device_type": "DEVICE_TYPE_WINDOWS", "active": "1",
                               "description": "office laptops", "logout_password": CANARY, "policy_token": CANARY,
                               "windows_policy": {"uninstall_password": CANARY, "disable_password": CANARY, "pac_url": "http://pac/a"}}],
         "zcc.zpa_entitlements": [{"zpa_enable_for_all": False, "group_list": [{"id": 7, "name": "Finance"}]}],
         "zcc.zdx_entitlements": [{"upm_enable_for_all": True, "upm_group_list": []}]}
    d.update(over)
    return d


def test_client_connector_app_profiles_and_entitlements_restore_without_any_password():
    """ASVS V8.3.4 · CWE-312 · WSTG-CONF-11: an app profile restore updates only its non-secret fields (no masked or secret value is ever sent) and the ZPA entitlement is PUT back; Undo reverses both."""
    bid = backup_of(zcc_data(), ["zcc"])
    live = zcc_data()
    live["zcc.app_profiles"][0] = dict(live["zcc.app_profiles"][0], description="changed", windows_policy={
        "uninstall_password": CANARY, "disable_password": CANARY, "pac_url": "http://pac/b"})
    live["zcc.zpa_entitlements"] = [{"zpa_enable_for_all": True, "group_list": []}]
    tgt = Client(Tenant(live))
    keys = ["zcc.app_profiles", "zcc.zpa_entitlements"]
    before = state(tgt.tenant, keys)
    p, r = apply(tgt, spec("zcc", bid, target="same", types=keys))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    sent = json.dumps(tgt.tenant.calls) + json.dumps(tgt.tenant.sent)
    assert "(set)" not in sent and CANARY not in sent
    prof = tgt.tenant.by_name("zcc.app_profiles", "Windows default")
    assert prof["description"] == "office laptops" and prof["windows_policy"]["pac_url"] == "http://pac/a"
    assert tgt.tenant.rows("zcc.zpa_entitlements")[0]["zpa_enable_for_all"] is False
    assert tgt.tenant.rows("zcc.zpa_entitlements")[0]["group_list"] == [{"id": 7, "name": "Finance"}]
    _pu, ru = undo(tgt, r)
    assert ru["status"] == "applied", ru.get("stopped")
    after = state(tgt.tenant, keys)
    assert after["zcc.zpa_entitlements"] == before["zcc.zpa_entitlements"]
    assert after["zcc.app_profiles"]["Windows default"]["description"] == "changed"


def test_app_profiles_and_entitlements_are_never_cloned_to_another_tenant():
    """ASVS V4.1.3 · CWE-639 · WSTG-ATHZ-02: app profiles and entitlements name the tenant's own groups by id, so a clone leaves them out with the reason."""
    bid = backup_of(zcc_data(), ["zcc"])
    tgt = Client(Tenant(zcc_data(**{"zcc.app_profiles": [dict(zcc_data()["zcc.app_profiles"][0], description="theirs")]})))
    p = ao.plan(tgt, spec("zcc", bid, types=["zcc.app_profiles", "zcc.zpa_entitlements"]), scope=SCOPE, tenant_label="target")
    assert "own user groups" in item(p, "zcc.app_profiles", "Windows default")["reason"]
    assert p["counts"]["change"] == 0


# ── #13 Full Clone: tenant-bound objects, separately confirmed ──────────

def bound_source():
    return {
        "zia.static_ips": [{"id": 1, "ip_address": "198.51.100.10", "comment": "HQ egress"},
                           {"id": 2, "ip_address": "203.0.113.20", "comment": "Branch"}],
        "zia.gre_tunnels": [{"id": 11, "source_ip": "198.51.100.10", "comment": "HQ tunnel", "primary_dest_vip": {"id": 4681, "virtual_ip": "1.2.3.4"},
                             "internal_ip_range": "172.17.0.0"},
                            {"id": 12, "source_ip": "192.0.2.99", "comment": "unknown address"}],
        "zia.vpn_credentials": [{"id": 30, "fqdn": "branch@corp.example", "type": "UFQDN"}],
        "zia.locations": [{"id": 900, "name": "HQ", "ip_addresses": ["198.51.100.10"], "parent_id": 0, "tz": "GERMANY_EUROPE_BERLIN",
                           "static_location_groups": [{"id": 5}]},
                          {"id": 901, "name": "HQ guest wifi", "parent_id": 900, "ip_addresses": ["10.1.0.0/16"]},
                          {"id": 902, "name": "Branch", "ip_addresses": [], "vpn_credentials": [{"id": 30, "type": "UFQDN", "fqdn": "branch@corp.example"}]}],
    }


def bound_target():
    t = Tenant({"zia.static_ips": [], "zia.gre_tunnels": [], "zia.locations": [], "zia.vpn_credentials": []})
    t.foreign_ips = {"203.0.113.20"}
    return t


BOUND = ["zia.static_ips", "zia.gre_tunnels", "zia.locations", "zia.vpn_credentials"]


def test_tenant_bound_objects_stay_out_of_a_clone_unless_included():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: by default a clone never touches locations, static IPs or GRE tunnels; picking one without the separate tick is refused before a read."""
    bid = backup_of(bound_source(), ["zia"])
    tgt = Client(bound_target())
    with pytest.raises(ao.OperationError, match="tenant-bound"):
        ao.plan(tgt, spec("zia", bid, types=BOUND), scope=SCOPE, tenant_label="target")
    assert tgt.tenant.reads == []
    p = ao.plan(tgt, spec("zia", bid), scope=SCOPE, tenant_label="target")
    assert not any(g["target"].get("type") in BOUND[:3] for g in p["groups"])
    assert any("static IP" in m for m in p["manual_steps"])
    with pytest.raises(ao.OperationError, match="Only ZIA"):
        ao.plan(tgt, spec("zpa", bid, include_tenant_bound=True), scope=SCOPE)


def test_included_tenant_bound_objects_are_validated_ordered_and_need_their_own_phrase():
    """ASVS V2.8.1 · CWE-352 · WSTG-BUSL-06: with the tick, a static IP the target cannot own is left out (checked with the tenant), a GRE tunnel or location only uses the target's own static IPs, a sub-location is left out, and the apply needs CREATE <n> TENANT-BOUND OBJECTS."""
    bid = backup_of(bound_source(), ["zia"])
    tgt = Client(bound_target())
    sp = spec("zia", bid, types=BOUND, include_tenant_bound=True, psk=["branch@corp.example"])
    p = ao.plan(tgt, sp, scope=SCOPE, tenant_label="target")
    assert p["status"] == "ready", p["blockers"]
    assert "already in use" in item(p, "zia.static_ips", "203.0.113.20")["reason"]
    assert "not a static IP address of the target" in item(p, "zia.gre_tunnels", "192.0.2.99")["reason"]
    assert "sub-location" in item(p, "zia.locations", "HQ guest wifi")["reason"]
    assert item(p, "zia.gre_tunnels", "198.51.100.10")["depends_on"] == [item(p, "zia.static_ips", "198.51.100.10")["group"]]
    assert p["confirm_phrase"] == "CREATE 4 TENANT-BOUND OBJECTS"
    assert any(m.startswith("GRE tunnel from 198.51.100.10") for m in p["manual_steps"])
    assert any(m.startswith("location HQ") for m in p["manual_steps"])
    ocr.provide(p["plan_hash"], secrets={"branch@corp.example": "a-typed-psk"})
    refused = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                         confirm_text="APPLY 5 CHANGES")
    assert refused["status"] == "refused" and tgt.tenant.writes == []
    ocr.provide(p["plan_hash"], secrets={"branch@corp.example": "a-typed-psk"})
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert r["status"] == "applied", r.get("stopped")
    order = [k for op, k, _n in tgt.tenant.writes if op == "create"]
    assert sorted(order) == sorted(["zia.static_ips", "zia.vpn_credentials", "zia.gre_tunnels", "zia.locations", "zia.locations"])
    assert order.index("zia.static_ips") < order.index("zia.gre_tunnels") < order.index("zia.locations")
    assert order.index("zia.vpn_credentials") < order.index("zia.locations")
    gre = tgt.tenant.rows("zia.gre_tunnels")[0]
    assert "primary_dest_vip" not in gre and "internal_ip_range" not in gre   # ZIA picks the target's own VIPs
    hq = tgt.tenant.by_name("zia.locations", "HQ")
    assert hq["ip_addresses"] == ["198.51.100.10"] and "static_location_groups" not in hq
    vpn = tgt.tenant.by_name("zia.vpn_credentials", "branch@corp.example")
    assert tgt.tenant.by_name("zia.locations", "Branch")["vpn_credentials"] == [{"id": vpn["id"]}]
    pu, ru = undo(tgt, r)
    assert ru["status"] == "applied" and tgt.tenant.rows("zia.locations") == [] and tgt.tenant.rows("zia.static_ips") == []
    assert tgt.tenant.rows("zia.gre_tunnels") == [] and "never deleted" in item(pu, "zia.vpn_credentials", "branch@corp.example")["reason"]


def test_full_mode_never_deletes_the_targets_own_tenant_bound_objects_and_a_rehearsal_cannot_validate():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: full mode leaves the target's own locations and static IPs alone; a rehearsal cannot ask the tenant, so it plans no static IP."""
    bid = backup_of(bound_source(), ["zia"])
    t = bound_target()
    t.data["zia.static_ips"] = [{"id": 77, "ip_address": "192.0.2.1"}]
    t.data["zia.locations"] = [{"id": 78, "name": "Their office", "ip_addresses": ["192.0.2.1"]}]
    tgt = Client(t)
    p = ao.plan(tgt, spec("zia", bid, mode="full", types=BOUND[:3], include_tenant_bound=True), scope=SCOPE, tenant_label="target")
    assert not any(g["handler"] == "cfg_delete" for g in p["groups"])
    assert "never deleted" in item(p, "zia.locations", "Their office")["reason"]
    rh = ocr.rehearse(cb.load_backup(bid)["types"], {k: [] for k in BOUND}, spec("zia", bid, types=BOUND[:3], include_tenant_bound=True))
    assert "rehearsal" in item(rh, "zia.static_ips", "198.51.100.10")["reason"]


# ── selection: a rule label and a name prefix (the sync's selection) ────

def test_a_label_selection_plans_and_deletes_only_labelled_rules():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: with select.label, only the source's rules carrying the label are planned and only the target's labelled rules may be deleted."""
    src = {"zia.rule_labels": [{"id": 1, "name": "Team A"}, {"id": 2, "name": "Team B"}],
           "zia.nat_control_rules": [{"id": 1, "name": "A one", "order": 1, "state": "ENABLED", "labels": [{"id": 1, "name": "Team A"}]},
                                     {"id": 2, "name": "B one", "order": 2, "state": "ENABLED", "labels": [{"id": 2, "name": "Team B"}]}]}
    bid = backup_of(src, ["zia"])
    tgt = Client(Tenant({"zia.rule_labels": [{"id": 8, "name": "Team A"}, {"id": 9, "name": "Team B"}],
                         "zia.nat_control_rules": [{"id": 50, "name": "A old", "order": 1, "state": "ENABLED", "labels": [{"id": 8}]},
                                                   {"id": 51, "name": "B old", "order": 2, "state": "ENABLED", "labels": [{"id": 9}]}]}))
    p = ao.plan(tgt, spec("zia", bid, mode="full", types=["zia.nat_control_rules"], select={"label": "team a"}), scope=SCOPE)
    planned = {(g["handler"], g["target"]["name"]) for g in p["groups"] if g["handler"] != "cfg_backup" and g["handler"] != "cfg_activate"}
    assert planned == {("cfg_create", "A one"), ("cfg_delete", "A old")}
    pp = ao.plan(tgt, spec("zia", bid, types=["zia.nat_control_rules"], select={"prefix": "B "}), scope=SCOPE)
    assert {g["target"]["name"] for g in pp["groups"] if g["handler"] == "cfg_create"} == {"B one"}
    with pytest.raises(ao.OperationError, match="128"):
        ao.plan(tgt, spec("zia", bid, select={"label": "x" * 200}), scope=SCOPE)
