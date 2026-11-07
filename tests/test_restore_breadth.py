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
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import config_backup as cb  # noqa: E402
import ops_config_restore as ocr  # noqa: E402
from config_fake import Client, Tenant, state  # noqa: E402

ASSESSOR = "Jane Doe"
SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc"], {"web_dlp": "zscaler", "email_dlp": "zscaler"})
CANARY = "CANARY-PW-5b7e1d"
ROOT = Path(__file__).resolve().parents[1]


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


def test_the_sample_tenants_pools_and_isolation_profiles_are_remapped_by_name_on_restore():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: the sample tenant's PRA credential pool and ZPA isolation profile, backed up from the sample, are found on the target by name, so a restored credential rule names the target's pool and a restored isolation rule the target's profile."""
    import offline_tenant as ot
    sample = cb.from_offline(ot.sample_store(reset=True))["types"]
    pool, prof = sample["zpa.pra_credential_pools"][0], sample["zpa.isolation_profiles"][0]
    src = zpa_source()
    src["zpa.pra_credential_pools"], src["zpa.isolation_profiles"] = [pool], [prof]
    src["zpa.isolation_rules"][0]["zpn_isolation_profile_id"] = prof["id"]
    src["zpa.credential_rules"].append({"id": "763", "name": "Inject the depot pool", "action": "INJECT_CREDENTIALS",
                                        "credential_pool": {"id": pool["id"]}, "conditions": [
                                            {"operator": "OR", "operands": [{"object_type": "APP", "lhs": "id", "rhs": "601"}]}]})
    bid = backup_of(src, ["zpa"])
    t = zpa_target()
    t.data["zpa.pra_credential_pools"] = [{"id": "986", "name": pool["name"]}]
    t.data["zpa.isolation_profiles"] = [{"id": "987", "name": prof["name"]}]
    tgt = Client(t)
    p, r = apply(tgt, spec("zpa", bid, keep_state=True))
    assert p["status"] == "ready" and r["status"] == "applied", (p["blockers"], [u for u in r["items"] if u["status"] == "failed"])
    assert tgt.tenant.by_name("zpa.credential_rules", "Inject the depot pool")["credential_pool"] == {"id": "986"}
    assert tgt.tenant.by_name("zpa.isolation_rules", "Isolate unmanaged")["zpn_isolation_profile_id"] == "987"


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
    made = [u for u in r["items"] if u["status"] == "applied" and u["object"].get("type") in BOUND[:3]]
    assert len(made) == 4 and all(u.get("verified") is True for u in made), [(u["object"]["name"], u.get("verified")) for u in made]
    gre = tgt.tenant.rows("zia.gre_tunnels")[0]
    assert "primary_dest_vip" not in gre and "internal_ip_range" not in gre   # ZIA picks the target's own VIPs
    hq = tgt.tenant.by_name("zia.locations", "HQ")
    assert hq["ip_addresses"] == ["198.51.100.10"] and "static_location_groups" not in hq
    vpn = tgt.tenant.by_name("zia.vpn_credentials", "branch@corp.example")
    assert tgt.tenant.by_name("zia.locations", "Branch")["vpn_credentials"] == [{"id": vpn["id"]}]
    pu, ru = undo(tgt, r)
    assert ru["status"] == "applied" and tgt.tenant.rows("zia.locations") == [] and tgt.tenant.rows("zia.static_ips") == []
    assert tgt.tenant.rows("zia.gre_tunnels") == [] and "never deleted" in item(pu, "zia.vpn_credentials", "branch@corp.example")["reason"]


@pytest.mark.parametrize("key,name,row", [
    ("zia.static_ips", "198.51.100.10", {"id": 501, "ip_address": "198.51.100.10", "comment": "added meanwhile"}),
    ("zia.locations", "HQ", {"id": 502, "name": "HQ", "ip_addresses": [], "comment": "added meanwhile"}),
], ids=["static_ip", "location"])
def test_a_tenant_bound_object_made_in_the_target_since_the_preview_stops_the_create(monkeypatch, key, name, row):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: a static IP or location that appears in the target between the apply's re-plan and its create is a conflict: it is not created again and nothing more is written."""
    bid = backup_of(bound_source(), ["zia"])
    tgt = Client(bound_target())
    sp = spec("zia", bid, types=BOUND, include_tenant_bound=True, psk=["branch@corp.example"])
    p = ao.plan(tgt, sp, scope=SCOPE, tenant_label="target")
    real = ocr._rows_named
    at = []

    def colleague_adds_it_first(run, t, nm):
        if t["key"] == key and nm == name and tgt.tenant.by_name(key, name) is None:
            tgt.tenant.rows(key).append(dict(row))
            at.append(len(tgt.tenant.writes))
        return real(run, t, nm)

    monkeypatch.setattr(ocr, "_rows_named", colleague_adds_it_first)
    ocr.provide(p["plan_hash"], secrets={"branch@corp.example": "a-typed-psk"})
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert r["status"] != "applied"
    assert next(u for u in r["items"] if u["object"].get("type") == key and u["object"].get("name") == name)["status"] == "conflict"
    assert ("create", key, name) not in tgt.tenant.writes
    assert [x for x in tgt.tenant.rows(key) if cb.name_of(cb.BY_KEY[key], x) == name] == [row]
    assert at and len(tgt.tenant.writes) == at[0]   # nothing written after the conflict


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


# ── 2026-11-04 clone breadth: every comparison row present ──────────────
# PAC files, Endpoint DLP and SaaS Security API DLP rules, ZPA gateways and
# proxies join the backup → plan → restore / clone path (row 11);
# sub-locations clone with their parent location, tenant-bound (row 13);
# Client Connector app profiles and entitlements clone to another tenant only
# when included, never with a password (row 8).

WIDE = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc"], {"web_dlp": "zscaler", "email_dlp": "zscaler", "endpoint_dlp": "zscaler",
                                                         "saas_casb": "zscaler"})
NO_ZPA = ao.scope_for(["dlp", "zia_extras", "zcc"], {"web_dlp": "zscaler", "endpoint_dlp": "zscaler", "saas_casb": "zscaler"})


def wide_backup(data, products=("zia",)):
    c = Client(Tenant(data))
    got = cb.capture(c, list(products), WIDE)
    return cb.save_backup(cb.build_doc(got["types"], {"tenant_label": "Source", "tenant_key": "key-source", "products": list(products)}))["id"]


def wide_apply(client, sp, *, scope=WIDE, confirm=None):
    p = ao.plan(client, sp, scope=scope, tenant_label="target")
    r = ao.execute(client, sp, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"] if confirm is None else confirm)
    return p, r


def wide_undo(client, r, scope=WIDE):
    inv = r["inverse"]
    p = ao.plan(client, inv, scope=scope, tenant_label="target")
    return p, ao.execute(client, inv, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR,
                         tenant_label="target", confirm_text=p["confirm_phrase"])


def creates(t):
    return [k for op, k, _n in t.writes if op == "create"]


NEW_WRITES = {
    # type key: (SDK module, class) the catalogue's calls must exist on (installed zscaler-sdk-python)
    "zia.pac_files": ("zscaler.zia.pac_files", "PacFilesAPI"),
    "zia.endpoint_dlp_rules": ("zscaler.zia.endpoint_dlp_rules", "EndpointDLPRulesAPI"),
    "zia.saas_dlp_rules": ("zscaler.zia.casb_dlp_rules", "CasbdDlpRulesAPI"),
    "zia.zpa_gateways": ("zscaler.zia.zpa_gateway", "ZPAGatewayAPI"),
    "zia.sub_locations": ("zscaler.zia.locations", "LocationsAPI"),
    "zcc.app_profiles": ("zscaler.zcc.web_policy", "WebPolicyAPI"),
    "zia.casb_tenants": ("zscaler.zia.saas_security_api", "SaaSSecurityAPI"),
    "zia.domain_profiles": ("zscaler.zia.saas_security_api", "SaaSSecurityAPI"),
}


@pytest.mark.parametrize("key", sorted(NEW_WRITES))
def test_every_new_call_is_in_the_installed_sdk_with_the_arguments_the_restore_passes(key):
    """ASVS V14.2.1 · CWE-1104 · WSTG-CONF-01: each list, get, add, update and delete call a new type names exists on the installed SDK, and the positional arguments a write passes are the call's own parameters."""
    import importlib
    import inspect
    mod, cls_name = NEW_WRITES[key]
    m = importlib.import_module(mod)
    cls = getattr(m, cls_name, None) or next(c for _n, c in inspect.getmembers(m, inspect.isclass) if c.__module__ == mod)
    t = cb.BY_KEY[key]
    for role in ("ls", "get", "add", "upd", "rm"):
        if t[role] and t[role] != "raw":
            assert callable(getattr(cls, t[role], None)), (key, role, t[role])
    if t["add_pos"]:
        params = list(inspect.signature(getattr(cls, t["add"])).parameters)[1:]
        assert params[:len(t["add_pos"])] == list(t["add_pos"]), params
    if t["type_arg"]:
        for role in ("get", "rm"):
            params = list(inspect.signature(getattr(cls, t[role])).parameters)[1:]
            assert params[:2] == ["rule_id", "rule_type"], params


def test_the_catalogue_writes_the_four_read_only_types_and_names_what_stays_manual():
    """ASVS V1.14.1 · CWE-1059: PAC files, Endpoint DLP rules, SaaS Security API DLP rules and ZPA gateways are written; proxy gateways stay read-only (the API only lists them) with a manual step; sub-locations are a tenant-bound type, no longer a manual-only note."""
    for k in ("zia.pac_files", "zia.endpoint_dlp_rules", "zia.saas_dlp_rules", "zia.zpa_gateways"):
        assert cb.writable(cb.BY_KEY[k]), k
    assert cb.BY_KEY["zia.proxy_gateways"]["level"] == "read" and "manual" in cb.BY_KEY["zia.proxy_gateways"] \
        and cb.BY_KEY["zia.proxy_gateways"]["manual"]
    assert cb.BY_KEY["zia.sub_locations"]["tenant_bound"] and cb.writable(cb.BY_KEY["zia.sub_locations"], tenant_bound=True)
    assert "zia.sub_locations" not in {k for k, _l, _w in cb.NOT_COVERED}
    cov = {r["key"]: r for r in cb.coverage()["products"]["zcc"]}
    assert cov["zcc.app_profiles"]["clone_opt"] == "zcc_profiles" and cov["zcc.zpa_entitlements"]["clone_opt"] == "zcc_profiles"
    tiers = ocr.TIER
    assert tiers["zia.dlp_engines"] < tiers["zia.endpoint_dlp_rules"] and tiers["zia.dlp_engines"] < tiers["zia.saas_dlp_rules"]
    assert tiers["zia.dlp_notification_templates"] < tiers["zia.endpoint_dlp_rules"]
    assert tiers["zia.zpa_gateways"] < tiers["zia.forwarding_rules"] and tiers["zia.locations"] < tiers["zia.sub_locations"]


# ── row 11: DLP rules (Endpoint, SaaS Security API) cloned with remapping ──

def dlp_source():
    return {
        "zia.rule_labels": [{"id": 1, "name": "DLP team"}],
        "zia.dlp_dictionaries": [{"id": 11, "name": "Card numbers", "custom": True, "custom_phrase_match_type": "MATCH_ANY",
                                  "dictionary_type": "PATTERNS_AND_PHRASES", "patterns": [{"pattern": "4[0-9]{15}"}]}],
        "zia.dlp_engines": [{"id": 21, "name": "Cards", "custom_dlp_engine": True, "engine_expression": "((D11.S > 1))"}],
        "zia.dlp_notification_templates": [{"id": 31, "name": "Notify owner", "subject": "DLP", "plain_text_message": "x"}],
        "zia.incident_receivers": [{"id": 41, "name": "Corp receiver"}],
        "zia.casb_tenants": [{"tenant_id": 51, "tenant_name": "Corp Box", "saas_application": "BOX"}],
        "zia.domain_profiles": [{"profile_id": 61, "profile_name": "Partners"}],
        "zia.endpoint_dlp_rules": [
            {"id": 201, "order": 1, "rank": 7, "name": "Cards to USB", "state": "ENABLED", "action": "BLOCK",
             "dlp_engines": [{"id": 21, "name": "Cards"}], "notification_template": {"id": 31, "name": "Notify owner"},
             "receiver": {"id": 41, "name": "Corp receiver"}, "labels": [{"id": 1, "name": "DLP team"}], "uc_template_id": 0},
            {"id": 202, "order": 2, "rank": 7, "name": "Parent with sub-rules", "state": "ENABLED", "action": "ALLOW",
             "sub_rules": [{"id": 203}]},
            {"id": 204, "order": 3, "rank": 7, "name": "Uses an app group", "state": "ENABLED", "action": "BLOCK",
             "end_point_application_groups": [{"id": 77, "name": "Browsers"}]}],
        "zia.saas_dlp_rules": [
            {"id": 301, "order": 1, "rank": 7, "name": "Box files with cards", "type": "OFLCASB_DLP_FILE", "state": "ENABLED",
             "action": "OFLCASB_DLP_REPORT_INCIDENT", "dlp_engines": [{"id": 21, "name": "Cards"}],
             "cloud_app_tenants": [{"id": 51, "name": "Corp Box"}], "included_domain_profiles": [{"id": 61, "name": "Partners"}],
             "zscaler_incident_receiver": True},
            {"id": 302, "order": 1, "rank": 7, "name": "S3 buckets", "type": "OFLCASB_DLP_STORAGE", "state": "ENABLED",
             "buckets": [{"id": 88, "name": "corp-data"}]}],
    }


def dlp_target():
    return Tenant({"zia.rule_labels": [], "zia.dlp_dictionaries": [], "zia.dlp_engines": [], "zia.dlp_notification_templates": [],
                   "zia.incident_receivers": [{"id": 941, "name": "Corp receiver"}],
                   "zia.casb_tenants": [{"tenant_id": 951, "tenant_name": "Corp Box"}],
                   "zia.domain_profiles": [{"profile_id": 961, "profile_name": "Partners"}],
                   "zia.casb_tombstone_templates": [], "zia.casb_email_labels": [],
                   "zia.endpoint_dlp_rules": [], "zia.saas_dlp_rules": []})


DLP_TYPES = ["zia.rule_labels", "zia.dlp_dictionaries", "zia.dlp_engines", "zia.dlp_notification_templates", "zia.endpoint_dlp_rules",
             "zia.saas_dlp_rules"]


def test_endpoint_and_saas_dlp_rules_clone_after_their_engines_with_every_reference_remapped():
    """ASVS V4.1.3 · CWE-639 · WSTG-BUSL-01: dictionaries, engines and notification templates are created first, the rules after them, created disabled, each reference pointing at the target's object (by name), and every write is read back."""
    bid = wide_backup(dlp_source())
    tgt = Client(dlp_target())
    p, r = wide_apply(tgt, spec("zia", bid, types=DLP_TYPES))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    order = creates(tgt.tenant)
    for dep in ("zia.dlp_engines", "zia.dlp_notification_templates", "zia.rule_labels"):
        assert order.index(dep) < order.index("zia.endpoint_dlp_rules"), order
    assert order.index("zia.dlp_engines") < order.index("zia.saas_dlp_rules")
    eng = tgt.tenant.by_name("zia.dlp_engines", "Cards")
    dic = tgt.tenant.by_name("zia.dlp_dictionaries", "Card numbers")
    assert eng["engine_expression"] == f"((D{dic['id']}.S > 1))"
    ep = tgt.tenant.by_name("zia.endpoint_dlp_rules", "Cards to USB")
    assert ep["dlp_engines"] == [{"id": eng["id"]}] and ep["state"] == "DISABLED"
    assert ep["notification_template"] == {"id": tgt.tenant.by_name("zia.dlp_notification_templates", "Notify owner")["id"]}
    assert ep["receiver"] == {"id": 941} and ep["labels"] == [{"id": tgt.tenant.by_name("zia.rule_labels", "DLP team")["id"]}]
    assert ep["uc_template_id"] == 0   # nothing to point at: sent as it is
    saas = tgt.tenant.by_name("zia.saas_dlp_rules", "Box files with cards")
    assert saas["type"] == "OFLCASB_DLP_FILE" and saas["cloud_app_tenants"] == [{"id": 951}]
    assert saas["included_domain_profiles"] == [{"id": 961}] and saas["zscaler_incident_receiver"] is True
    made = [u for u in r["items"] if u["status"] == "applied" and u["kind"] == "object"]
    assert made and all(u.get("verified") is True for u in made)
    assert ("zia.saas_dlp_rules", "get", (str(saas["id"]), "OFLCASB_DLP_FILE")) in [(k, ro, (str(a[0]),) + a[1:]) for k, ro, a in tgt.tenant.args]


def test_dlp_rules_that_name_what_another_tenant_cannot_have_are_left_out_with_the_reason():
    """ASVS V4.1.3 · CWE-639 · WSTG-BUSL-01: a rule with sub-rules, one naming endpoint application groups and one naming SaaS buckets are not cloned; each says why."""
    bid = wide_backup(dlp_source())
    p = ao.plan(Client(dlp_target()), spec("zia", bid, types=DLP_TYPES), scope=WIDE, tenant_label="target")
    assert "sub-rules" in item(p, "zia.endpoint_dlp_rules", "Parent with sub-rules")["reason"]
    assert "endpoint application groups" in item(p, "zia.endpoint_dlp_rules", "Uses an app group")["reason"]
    assert "casb buckets" in item(p, "zia.saas_dlp_rules", "S3 buckets")["reason"]


def test_a_dlp_rule_clone_undoes_exactly_and_deletes_the_saas_rule_with_its_type():
    """ASVS V8.1.1 · CWE-460 · WSTG-BUSL-04: Undo deletes every created rule and object (the SaaS rule's delete names its rule type) and leaves the target as it was."""
    bid = wide_backup(dlp_source())
    tgt = Client(dlp_target())
    before = state(tgt.tenant, DLP_TYPES)
    _p, r = wide_apply(tgt, spec("zia", bid, types=DLP_TYPES))
    saas_id = tgt.tenant.by_name("zia.saas_dlp_rules", "Box files with cards")["id"]
    _pu, ru = wide_undo(tgt, r)
    assert ru["status"] == "applied", ru.get("stopped")
    assert same_state(state(tgt.tenant, DLP_TYPES), before)
    assert ("zia.saas_dlp_rules", "rm", (str(saas_id), "OFLCASB_DLP_FILE")) in [(k, ro, (str(a[0]),) + a[1:]) for k, ro, a in tgt.tenant.args]


def test_a_dlp_rule_changed_in_the_target_since_the_preview_is_a_conflict_not_overwritten(monkeypatch):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: an Endpoint DLP rule someone edits between the preview and its update is not overwritten, and nothing more is written."""
    src = dlp_source()
    bid = wide_backup(src)
    t = dlp_target()
    t.data["zia.endpoint_dlp_rules"] = [dict(src["zia.endpoint_dlp_rules"][2], action="ALLOW")]
    tgt = Client(t)
    sp = spec("zia", bid, target="same", objects=[{"type": "zia.endpoint_dlp_rules", "name": "Uses an app group"}])
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    assert p["status"] == "ready", p["blockers"]

    real = cb.get_one

    def colleague_edits_it_first(client, ty, oid, rule_type=""):
        if ty["key"] == "zia.endpoint_dlp_rules":
            t.data["zia.endpoint_dlp_rules"][0]["description"] = "edited meanwhile"
        return real(client, ty, oid, rule_type)
    monkeypatch.setattr(cb, "get_one", colleague_edits_it_first)
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert r["status"] != "applied"
    assert any(u["status"] == "conflict" for u in r["items"] if u["object"].get("type") == "zia.endpoint_dlp_rules")
    assert not [w for w in t.writes if w[1] == "zia.endpoint_dlp_rules"]


# ── row 11: PAC files ───────────────────────────────────────────────────

PAC = "function FindProxyForURL(url, host) { return \"PROXY ${GATEWAY}:80; DIRECT\"; }"


def pac_source():
    return {"zia.pac_files": [{"id": 31, "name": "corp.pac", "domain": "corp.example", "pac_content": PAC, "pac_version": 4,
                               "pac_url": "https://pac.example/corp/corp.pac", "pac_version_status": "DEPLOYED",
                               "pac_verification_status": "VERIFY_NOERR", "pac_commit_message": "v4", "editable": True},
                              {"id": 32, "name": "default.pac", "domain": "corp.example", "pac_content": PAC, "editable": False}]}


def test_pac_files_clone_as_new_files_without_their_url_or_version_and_undo_removes_them():
    """ASVS V5.1.3 · CWE-20 · WSTG-BUSL-01: a custom PAC file is created in the target with its content (never its source URL or version), Zscaler's own PAC file is left alone, the read-back confirms it and Undo deletes only the created one."""
    bid = wide_backup(pac_source())
    t = Tenant({"zia.pac_files": [{"id": 932, "name": "default.pac", "pac_content": "x", "editable": False}]})
    tgt = Client(t)
    p, r = wide_apply(tgt, spec("zia", bid, types=["zia.pac_files"]))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    assert creates(t) == ["zia.pac_files"]
    made = t.by_name("zia.pac_files", "corp.pac")
    assert made["pac_content"] == PAC and made["domain"] == "corp.example" and "pac_url" not in made and "pac_version" not in made
    assert all(u.get("verified") for u in r["items"] if u["status"] == "applied" and u["kind"] == "object")
    assert any("PAC file" in m for m in p["manual_steps"])
    _pu, ru = wide_undo(tgt, r)
    assert ru["status"] == "applied" and t.names("zia.pac_files") == ["default.pac"]


def test_an_existing_pac_file_is_never_updated_or_deleted_here():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: a PAC file the target already has is left as it is (versions are changed in the portal) and full mode does not delete the target's own PAC files (a delete removes every version)."""
    bid = wide_backup(pac_source())
    t = Tenant({"zia.pac_files": [{"id": 931, "name": "corp.pac", "pac_content": "old", "editable": True},
                                  {"id": 933, "name": "theirs.pac", "pac_content": "x", "editable": True}]})
    p = ao.plan(Client(t), spec("zia", bid, mode="full", target="same", types=["zia.pac_files"]), scope=WIDE, tenant_label="target")
    assert item(p, "zia.pac_files", "corp.pac")["status"] == "noop"
    assert "every version" in item(p, "zia.pac_files", "theirs.pac")["reason"]
    assert not p["groups"]


def test_a_pac_file_that_does_not_read_back_as_sent_is_flagged_and_offered_again(monkeypatch):
    """ASVS V11.1.5 · CWE-354 · WSTG-BUSL-01: when the read-back of a created PAC file differs from what was sent, the item is marked not verified and the re-push names it."""
    bid = wide_backup(pac_source())
    t = Tenant({"zia.pac_files": []})
    real = cb.get_one

    def changed(client, ty, oid, rule_type=""):
        row, err = real(client, ty, oid, rule_type)
        if row is not None and ty["key"] == "zia.pac_files":
            row = dict(row, pac_content="tampered")
        return row, err
    monkeypatch.setattr(cb, "get_one", changed)
    _p, r = wide_apply(Client(t), spec("zia", bid, types=["zia.pac_files"]))
    u = item(r, "zia.pac_files", "corp.pac")
    assert u["status"] == "applied" and u["verified"] is False
    assert ocr.repush_spec(r)["objects"] == [{"type": "zia.pac_files", "name": "corp.pac"}]


# ── row 11: ZPA gateways (and the forwarding rules that use them) ───────

def gw_source():
    return {"zia.zpa_gateways": [{"id": 71, "name": "Anchor", "type": "ZPA", "zpa_tenant_id": 999,
                                  "zpa_server_group": {"external_id": "2301", "name": "DC servers", "extensions": {"x": 1}},
                                  "zpa_app_segments": [{"external_id": "2201", "name": "Billing"}]}],
            "zia.forwarding_rules": [{"id": 72, "name": "Billing via ZPA", "order": 1, "state": "ENABLED", "forward_method": "ZPA",
                                      "zpa_gateway": {"id": 71, "name": "Anchor"}}],
            "zpa.server_groups": [{"id": "2301", "name": "DC servers"}],
            "zpa.application_segments": [{"id": "2201", "name": "Billing"}]}


def gw_target(anchored=True):
    return Tenant({"zia.zpa_gateways": [], "zia.forwarding_rules": [],
                   "zpa.server_groups": [{"id": "7301", "name": "DC servers", "ip_anchored": anchored}],
                   "zpa.application_segments": [{"id": "7201", "name": "Billing"}]})


def test_a_zpa_gateway_clones_with_the_targets_own_zpa_objects_and_its_forwarding_rule_follows():
    """ASVS V4.1.3 · CWE-639 · WSTG-BUSL-01: the gateway's ZPA server group and segments point at the target's ZPA objects of the same name, the source's ZPA tenant id is not sent, and the forwarding rule is created after it pointing at the new gateway; Undo removes both."""
    bid = wide_backup(gw_source(), ("zia", "zpa"))
    t = gw_target()
    tgt = Client(t)
    p, r = wide_apply(tgt, spec("zia", bid, types=["zia.zpa_gateways", "zia.forwarding_rules"]))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    assert creates(t) == ["zia.zpa_gateways", "zia.forwarding_rules"]
    gw = t.by_name("zia.zpa_gateways", "Anchor")
    assert gw["zpa_server_group"] == {"external_id": "7301", "name": "DC servers"} and "zpa_tenant_id" not in gw
    assert gw["zpa_app_segments"] == [{"external_id": "7201", "name": "Billing"}]
    assert t.by_name("zia.forwarding_rules", "Billing via ZPA")["zpa_gateway"] == {"id": gw["id"]}
    assert all(u.get("verified") for u in r["items"] if u["status"] == "applied" and u["kind"] == "object")
    _pu, ru = wide_undo(tgt, r)
    assert ru["status"] == "applied" and t.rows("zia.zpa_gateways") == [] and t.rows("zia.forwarding_rules") == []


@pytest.mark.parametrize("scope,anchored,words", [(NO_ZPA, True, "tick ZPA on the Scope page"),
                                                  (WIDE, False, "Source IP Anchoring")], ids=["zpa_not_in_scope", "not_anchored"])
def test_a_zpa_gateway_is_not_cloned_when_its_zpa_objects_cannot_be_matched(scope, anchored, words):
    """ASVS V4.1.3 · CWE-639 · WSTG-BUSL-01: without ZPA in scope, or when the target's server group is not set up for Source IP Anchoring, the gateway is left out with the reason and its forwarding rule with it."""
    bid = wide_backup(gw_source(), ("zia", "zpa"))
    p = ao.plan(Client(gw_target(anchored)), spec("zia", bid, types=["zia.zpa_gateways", "zia.forwarding_rules"]), scope=scope,
                tenant_label="target")
    assert words in item(p, "zia.zpa_gateways", "Anchor")["reason"]
    assert item(p, "zia.forwarding_rules", "Billing via ZPA")["status"] == "excluded"


def test_a_proxy_gateway_stays_a_manual_step_while_its_proxies_clone():
    """ASVS V1.14.6 · CWE-1023: the API cannot create a proxy gateway, so a clone names it as a manual step instead of claiming it."""
    data = {"zia.proxies": [{"id": 81, "name": "Egress", "address": "proxy.corp.example", "port": 8080}],
            "zia.proxy_gateways": [{"id": 82, "name": "Chain", "primary_proxy": {"id": 81, "name": "Egress"}}]}
    bid = wide_backup(data)
    p = ao.plan(Client(Tenant({"zia.proxies": [], "zia.proxy_gateways": []})), spec("zia", bid), scope=WIDE, tenant_label="target")
    assert any("proxy gateways" in m for m in p["manual_steps"])
    assert any(g["target"].get("type") == "zia.proxies" for g in p["groups"])


# ── row 13: sub-locations clone with their parent location ──────────────

def sub_source():
    return {"zia.static_ips": [{"id": 1, "ip_address": "198.51.100.10"}],
            "zia.locations": [{"id": 900, "name": "HQ", "ip_addresses": ["198.51.100.10"], "parent_id": 0},
                              {"id": 901, "name": "Guest Wi-Fi", "parent_id": 900, "ip_addresses": ["10.1.0.0/16"], "profile": "GUESTWIFI"},
                              {"id": 902, "name": "other", "parent_id": 900, "other_sub_location": True, "ip_addresses": []},
                              {"id": 903, "name": "Orphan office", "ip_addresses": ["192.0.2.50"], "parent_id": 0},
                              {"id": 904, "name": "Lab", "parent_id": 903, "ip_addresses": ["10.9.0.0/16"]}]}


SUB = ["zia.static_ips", "zia.locations", "zia.sub_locations"]


def test_sub_locations_are_read_under_each_location_and_named_with_their_parent():
    """ASVS V8.3.4 · CWE-1059: a backup reads the sub-locations under each parent location, names each '<parent> / <name>' and keeps its parent's id."""
    got = cb.capture(Client(Tenant(sub_source())), ["zia"], WIDE)
    rows = {r["location_path"]: r for r in got["types"]["zia.sub_locations"]}
    assert set(rows) == {"HQ / Guest Wi-Fi", "HQ / other", "Orphan office / Lab"}
    assert rows["HQ / Guest Wi-Fi"]["parent_id"] == 900


def test_a_sub_location_is_created_after_its_parent_under_the_new_location_and_needs_the_tenant_bound_phrase():
    """ASVS V2.8.1 · CWE-352 · WSTG-BUSL-06: with tenant-bound objects included, the sub-location is created after its parent (pointing at the parent's new id), Zscaler's own 'other' sub-location and one whose parent cannot be created are left out, the typed phrase counts it, the read-back confirms it and Undo removes it before its parent."""
    bid = wide_backup(sub_source())
    t = Tenant({"zia.static_ips": [], "zia.locations": [], "zia.gre_tunnels": []})
    tgt = Client(t)
    sp = spec("zia", bid, types=SUB, include_tenant_bound=True)
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    assert p["status"] == "ready", p["blockers"]
    assert p["confirm_phrase"] == "CREATE 3 TENANT-BOUND OBJECTS"
    assert "other" in item(p, "zia.sub_locations", "HQ / other")["reason"]
    assert "Orphan office" in item(p, "zia.sub_locations", "Orphan office / Lab")["reason"]
    assert item(p, "zia.sub_locations", "HQ / Guest Wi-Fi")["depends_on"] == [item(p, "zia.locations", "HQ")["group"]]
    assert any("sub-locations" in w for w in p["warnings"])
    refused = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                         confirm_text="APPLY 4 CHANGES")
    assert refused["status"] == "refused" and t.writes == []
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert r["status"] == "applied", r.get("stopped")
    assert creates(t) == ["zia.static_ips", "zia.locations", "zia.locations"]
    hq = t.by_name("zia.locations", "HQ")
    sub = t.by_name("zia.locations", "Guest Wi-Fi")
    assert sub["parent_id"] == hq["id"] and sub["ip_addresses"] == ["10.1.0.0/16"] and "location_path" not in sub
    assert item(r, "zia.sub_locations", "HQ / Guest Wi-Fi")["verified"] is True
    assert any(m.startswith("sub-location HQ / Guest Wi-Fi") for m in r["manual_steps"])
    _pu, ru = wide_undo(tgt, r)
    assert ru["status"] == "applied" and t.rows("zia.locations") == [] and t.rows("zia.static_ips") == []
    deletes = [n for op, k, n in t.writes if op == "delete" and k == "zia.locations"]
    assert deletes == ["Guest Wi-Fi", "HQ"]


def test_sub_locations_need_the_tenant_bound_tick_and_go_under_an_existing_parent_by_name(monkeypatch):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: without the tick a sub-location type is refused before a read; with it, a sub-location goes under the target's own location of the same name, and a sub-location made since the preview stops the create."""
    bid = wide_backup(sub_source())
    t = Tenant({"zia.static_ips": [], "zia.gre_tunnels": [], "zia.locations": [{"id": 7000, "name": "HQ", "ip_addresses": [], "parent_id": 0}]})
    tgt = Client(t)
    with pytest.raises(ao.OperationError, match="tenant-bound"):
        ao.plan(tgt, spec("zia", bid, types=["zia.sub_locations"]), scope=WIDE)
    assert t.reads == []
    sp = spec("zia", bid, types=["zia.sub_locations"], include_tenant_bound=True)
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    g = next(g for g in p["groups"] if g["handler"] == "cfg_create")
    assert g["target"]["desired"]["parent_id"] == 7000 and p["confirm_phrase"] == "CREATE 1 TENANT-BOUND OBJECT"

    real = ocr._rows_named

    def colleague_adds_it_first(run, ty, nm):
        if ty["key"] == "zia.sub_locations" and t.by_name("zia.locations", "Guest Wi-Fi") is None:
            t.rows("zia.locations").append({"id": 7001, "name": "Guest Wi-Fi", "parent_id": 7000, "ip_addresses": []})
        return real(run, ty, nm)
    monkeypatch.setattr(ocr, "_rows_named", colleague_adds_it_first)
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert item(r, "zia.sub_locations", "HQ / Guest Wi-Fi")["status"] == "conflict" and t.writes == []


# ── row 8: Client Connector app profiles and entitlements to another tenant ──

def zcc_source():
    return {"zcc.trusted_networks": [],
            "zcc.forwarding_profiles": [{"id": 61, "name": "Office forwarding", "active": "1"}],
            "zcc.app_profiles": [
                {"id": 51, "name": "Everyone - Windows", "device_type": "DEVICE_TYPE_WINDOWS", "active": 1, "group_all": 1,
                 "forwarding_profile_id": 61, "groups": [], "users": [], "logout_password": CANARY, "policy_token": CANARY,
                 "windows_policy": {"uninstall_password": CANARY, "disable_password": CANARY, "pac_url": "http://pac/a"},
                 "policy_extension": {"id": 777, "nonce": "n-1", "packet_tunnel_exclude_list": "10.0.0.0/8", "exit_password": CANARY},
                 "disaster_recovery": {"zia_domain_name": "source.example", "zia_rsa_pub_key": "KEY"}},
                {"id": 52, "name": "Finance only", "device_type": "DEVICE_TYPE_MACOS", "active": 1, "group_all": 0,
                 "groups": [{"id": 7, "name": "Finance"}], "users": []}],
            "zcc.zpa_entitlements": [{"zpa_enable_for_all": False, "machine_tun_enabled_for_all": True,
                                      "group_list": [{"id": 7, "name": "Finance"}]}],
            "zcc.zdx_entitlements": [{"upm_enable_for_all": True, "upm_group_list": []}]}


def zcc_target():
    return Tenant({"zcc.trusted_networks": [], "zcc.forwarding_profiles": [{"id": 9061, "name": "Office forwarding", "active": "1"}],
                   "zcc.app_profiles": [],
                   "zcc.zpa_entitlements": [{"zpa_enable_for_all": True, "machine_tun_enabled_for_all": False,
                                             "group_list": [{"id": 90, "name": "Their group"}]}],
                   "zcc.zdx_entitlements": [{"upm_enable_for_all": False, "upm_group_list": [{"id": 91, "name": "Theirs"}]}]})


ZCC_KEYS = ["zcc.app_profiles", "zcc.zpa_entitlements", "zcc.zdx_entitlements"]


def test_client_connector_profiles_clone_only_when_included_and_never_carry_a_password():
    """ASVS V8.3.4 · CWE-312 · WSTG-CONF-11: included, an app profile that applies to everyone is created inactive in the other tenant with its forwarding profile matched by name and no password, policy token or source-only setting; one scoped to the source's groups is left out; the entitlements' switches are copied while the target keeps its own group lists; the preview says passwords are never read or sent; Undo puts it all back."""
    bid = wide_backup(zcc_source(), ("zcc",))
    t = zcc_target()
    tgt = Client(t)
    before = state(t, ZCC_KEYS)
    sp = spec("zcc", bid, types=ZCC_KEYS, include_zcc_profiles=True)
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    assert p["status"] == "ready", p["blockers"]
    assert p["confirm_phrase"] == "CLONE 3 CLIENT CONNECTOR OBJECTS"
    assert any("never read unless revealed on demand" in w and "without any password" in w for w in p["warnings"])
    assert "groups" in item(p, "zcc.app_profiles", "Finance only")["reason"]
    assert "without any password" in item(p, "zcc.app_profiles", "Everyone - Windows")["reason"]
    raw = json.dumps(p)
    assert CANARY not in raw and "(set)" not in raw
    refused = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                         confirm_text="APPLY 3 CHANGES")
    assert refused["status"] == "refused" and t.writes == []
    r = ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"])
    assert r["status"] == "applied", r.get("stopped")
    sent = json.dumps(t.calls) + json.dumps(t.sent)
    assert CANARY not in sent and "(set)" not in sent and "source.example" not in sent and "777" not in sent and "n-1" not in sent
    prof = t.by_name("zcc.app_profiles", "Everyone - Windows")
    assert prof["active"] == 0 and prof["forwarding_profile_id"] == 9061 and prof["windows_policy"] == {"pac_url": "http://pac/a"}
    assert prof["policy_extension"] == {"packet_tunnel_exclude_list": "10.0.0.0/8"} and "disaster_recovery" not in prof
    zpa = t.rows("zcc.zpa_entitlements")[0]
    assert zpa["zpa_enable_for_all"] is False and zpa["machine_tun_enabled_for_all"] is True
    assert zpa["group_list"] == [{"id": 90, "name": "Their group"}]
    assert t.rows("zcc.zdx_entitlements")[0]["upm_group_list"] == [{"id": 91, "name": "Theirs"}]
    assert all(u.get("verified") for u in r["items"] if u["status"] == "applied" and u["kind"] in ("object", "field"))
    _pu, ru = wide_undo(tgt, r)
    assert ru["status"] == "applied", ru.get("stopped")
    assert same_state(state(t, ZCC_KEYS), before)


def test_the_client_connector_option_is_refused_where_it_does_not_belong_and_creates_nothing_without_it():
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06: the option is refused for ZIA and for a template, and without it a missing app profile is not created, even on its own tenant."""
    bid = wide_backup(zcc_source(), ("zcc",))
    tgt = Client(zcc_target())
    with pytest.raises(ao.OperationError, match="Only Client Connector"):
        ao.plan(tgt, spec("zia", bid, include_zcc_profiles=True), scope=WIDE)
    p = ao.plan(tgt, spec("zcc", bid, target="same", types=["zcc.app_profiles"]), scope=WIDE, tenant_label="target")
    assert "tick 'Include Client Connector app profiles" in item(p, "zcc.app_profiles", "Everyone - Windows")["reason"]
    assert p["counts"]["change"] == 0
    assert any("never read unless revealed on demand" in w for w in p["warnings"]) or not p["groups"]


def test_the_page_lists_the_new_types_and_both_options():
    """ASVS V1.14.1 · CWE-1059 · WCAG 2.2 SC 3.3.2: the restore page lists tenant-bound types apart behind their own tick, offers the Client Connector option, sends each only when ticked, and both ticks have help."""
    js = (ROOT / "static" / "ops_config_restore.js").read_text(encoding="utf-8")
    assert 'id="crTb"' in js and "include_tenant_bound = true" in js
    assert 'id="crZccProfiles"' in js and "include_zcc_profiles = true" in js
    for copy_ in ("static/help_catalog.js", "browser_extension/help_catalog.js"):
        help_ = (ROOT / copy_).read_text(encoding="utf-8")
        assert '"#crTb"' in help_ and '"#crZccProfiles"' in help_ and "never read unless revealed on demand" in help_


def test_the_sample_tenant_has_data_for_every_new_type():
    """ASVS V14.2.1 · CWE-1059: the sample tenant answers every new type, so the restore and clone pages rehearse them offline."""
    import offline_tenant as ot
    doc = cb.from_offline(ot.sample_store(), ["zia", "zcc"])
    for k in ("zia.pac_files", "zia.endpoint_dlp_rules", "zia.saas_dlp_rules", "zia.zpa_gateways", "zia.proxies", "zia.proxy_gateways",
              "zia.sub_locations", "zia.casb_tenants", "zia.domain_profiles", "zia.casb_tombstone_templates", "zia.casb_email_labels",
              "zcc.app_profiles", "zcc.zpa_entitlements", "zcc.zdx_entitlements"):
        assert doc["types"].get(k), k
    assert {r["location_path"] for r in doc["types"]["zia.sub_locations"]} >= {"Larkspur HQ (Portland) / HQ guest Wi-Fi"}


# ── fixes after verify: an app profile clone never widens who it applies to (N1);
# the preview and the result name only the fields really written (N2) ──────

def zcc_profile_target(**prof):
    """The clone target with an app profile of the same name as the source's 'Everyone - Windows'."""
    t = zcc_target()
    t.data["zcc.app_profiles"] = [dict({"id": 8051, "name": "Everyone - Windows", "device_type": "DEVICE_TYPE_WINDOWS", "active": 1,
                                        "forwarding_profile_id": 9061}, **prof)]
    return t


def clone_profiles(t, src=None):
    bid = wide_backup(src or zcc_source(), ("zcc",))
    return Client(t), spec("zcc", bid, types=["zcc.app_profiles"], include_zcc_profiles=True)


def test_a_clone_never_widens_a_same_named_target_profile_to_everyone():
    """ASVS V4.1.3 · CWE-269 · WSTG-ATHZ-02: a source profile that applies to everyone is not cloned onto a same-named target profile that applies only to its own groups; the item is refused with the target's current and the would-be groups, and nothing is written."""
    t = zcc_profile_target(group_all=0, groups=[{"id": 95, "name": "B staff"}])
    tgt, sp = clone_profiles(t)
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    u = item(p, "zcc.app_profiles", "Everyone - Windows")
    assert u["status"] == "excluded"
    assert "widen" in u["reason"] and "B staff" in u["reason"] and "everyone" in u["reason"]
    assert not any(g["target"].get("name") == "Everyone - Windows" for g in p["groups"])
    ao.execute(tgt, sp, plan_hash=p["plan_hash"], scope=WIDE, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
               confirm_text=p["confirm_phrase"])
    assert ("update", "zcc.app_profiles", "Everyone - Windows") not in t.writes
    prof = t.by_name("zcc.app_profiles", "Everyone - Windows")
    assert prof["group_all"] == 0 and prof["groups"] == [{"id": 95, "name": "B staff"}]


def zcc_grouped_source(groups):
    src = zcc_source()
    src["zcc.app_profiles"] = [{"id": 53, "name": "Sales laptops", "device_type": "DEVICE_TYPE_WINDOWS", "active": 1, "group_all": 0,
                                "forwarding_profile_id": 61, "groups": groups, "users": []}]
    return src


def test_a_profiles_groups_are_matched_by_name_in_the_target_and_an_unmatched_group_refuses_the_item():
    """ASVS V4.1.3 · CWE-269 · WSTG-ATHZ-02: a source profile's groups are remapped to the target's groups of the same name (known from the target's own profiles and entitlements); a group the target cannot match refuses the item with the reason, and it never falls back to everyone."""
    t = zcc_target()
    t.data["zcc.zpa_entitlements"][0]["group_list"] = [{"id": 97, "name": "Sales"}]
    tgt, sp = clone_profiles(t, zcc_grouped_source([{"id": 7, "name": "Sales"}]))
    p, r = wide_apply(tgt, sp)
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    assert any("Sales laptops" in w and "Sales" in w for w in p["warnings"])
    prof = t.by_name("zcc.app_profiles", "Sales laptops")
    assert prof["group_all"] == 0 and prof["groups"] == [{"id": 97, "name": "Sales"}] and prof["active"] == 0
    # a group the target does not have: refused, not cloned to everyone
    t2 = zcc_target()
    tgt2, sp2 = clone_profiles(t2, zcc_grouped_source([{"id": 7, "name": "Sales"}, {"id": 8, "name": "Legal"}]))
    p2 = ao.plan(tgt2, sp2, scope=WIDE, tenant_label="target")
    u = item(p2, "zcc.app_profiles", "Sales laptops")
    assert u["status"] == "excluded" and "Legal" in u["reason"] and "everyone" in u["reason"]
    assert p2["counts"]["change"] == 0


def test_a_clone_may_narrow_a_same_named_profile_and_the_preview_shows_its_current_and_new_groups():
    """ASVS V4.1.3 · CWE-269 · WSTG-ATHZ-02: onto a same-named target profile for 'Sales' and 'Support', a source profile for 'Sales' is cloned (narrower, never wider): the preview names the target's current and new groups, the target's users stay its own, and the read-back confirms it."""
    t = zcc_profile_target(name="Sales laptops", group_all=0, groups=[{"id": 97, "name": "Sales"}, {"id": 98, "name": "Support"}],
                           users=[{"id": 5, "name": "kim"}])
    tgt, sp = clone_profiles(t, zcc_grouped_source([{"id": 7, "name": "Sales"}]))
    p, r = wide_apply(tgt, sp)
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    words = next(w for w in p["warnings"] if "Sales laptops" in w)
    assert "Sales, Support" in words and words.index("Sales, Support") < words.rindex("Sales")
    prof = t.by_name("zcc.app_profiles", "Sales laptops")
    assert prof["groups"] == [{"id": 97, "name": "Sales"}] and prof["users"] == [{"id": 5, "name": "kim"}]
    assert all(u.get("verified") for u in r["items"] if u["status"] == "applied")


def test_fields_a_clone_leaves_out_are_listed_as_kept_never_as_applied_or_verified():
    """ASVS V7.2.2 · CWE-451 · WSTG-BUSL-01: onto a same-named target profile, the fields a clone leaves out (on-net policy, device groups, posture, the policy extension's own id) are listed as kept with the target's value, are never reported applied or verified, and the target still has them afterwards."""
    t = zcc_profile_target(group_all=1, groups=[], on_net_policy={"x": 1}, device_group_ids=["12"], zia_posture_config_id=44,
                           policy_extension={"id": 900, "nonce": "t-1", "packet_tunnel_exclude_list": "192.168.0.0/16"})
    tgt, sp = clone_profiles(t)
    p, r = wide_apply(tgt, sp)
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    mine = [u for u in p["items"] if (u["object"] or {}).get("name") == "Everyone - Windows"]
    changed = {u["field"] for u in mine if u["status"] == "change"}
    assert "policy_extension.packet_tunnel_exclude_list" in changed
    for f in ("on_net_policy.x", "device_group_ids", "zia_posture_config_id", "policy_extension.id", "policy_extension.nonce"):
        assert f not in changed, f
    kept = {u["field"]: u for u in mine if u["status"] == "noop" and u["reason"].startswith("kept")}
    assert {"on_net_policy.x", "device_group_ids", "zia_posture_config_id"} <= set(kept), sorted(kept)
    assert kept["zia_posture_config_id"]["before"] == kept["zia_posture_config_id"]["after"] == 44
    done = [u for u in r["items"] if (u["object"] or {}).get("name") == "Everyone - Windows"]
    assert not any(u["field"] in kept and u["status"] == "applied" for u in done)
    assert all(u.get("verified") for u in done if u["status"] == "applied")
    prof = t.by_name("zcc.app_profiles", "Everyone - Windows")
    assert prof["on_net_policy"] == {"x": 1} and prof["device_group_ids"] == ["12"] and prof["zia_posture_config_id"] == 44
    assert prof["policy_extension"] == {"id": 900, "nonce": "t-1", "packet_tunnel_exclude_list": "10.0.0.0/8"}


def test_a_field_the_source_does_not_have_is_kept_on_a_restore_not_reported_as_cleared():
    """ASVS V7.2.2 · CWE-451 · WSTG-BUSL-01: on the same tenant, a field the backup lacks is listed as kept (an update merges, so the target keeps it), never as changed to nothing, applied or verified."""
    bid = backup_of(zcc_data(), ["zcc"])
    live = zcc_data()
    live["zcc.app_profiles"][0] = dict(live["zcc.app_profiles"][0], description="changed", install_note="theirs")
    tgt = Client(Tenant(live))
    p, r = apply(tgt, spec("zcc", bid, target="same", types=["zcc.app_profiles"]))
    assert r["status"] == "applied", (p["blockers"], r.get("stopped"))
    u = next(u for u in p["items"] if u["field"] == "install_note")
    assert u["status"] == "noop" and u["reason"].startswith("kept") and u["before"] == u["after"] == "theirs"
    assert next(u for u in r["items"] if u["field"] == "install_note")["status"] == "noop"
    assert next(u for u in r["items"] if u["field"] == "description")["status"] == "applied"
    assert tgt.tenant.by_name("zcc.app_profiles", "Windows default")["install_note"] == "theirs"


# ── fixes after verify: every new write type is refused without each of the four gates ──

GATE_CASES = {
    "dlp_rules": (lambda: wide_backup(dlp_source()), dlp_target, {"types": DLP_TYPES}),
    "pac_files": (lambda: wide_backup(pac_source()), lambda: Tenant({"zia.pac_files": []}), {"types": ["zia.pac_files"]}),
    "zpa_gateways": (lambda: wide_backup(gw_source(), ("zia", "zpa")), gw_target, {"types": ["zia.zpa_gateways", "zia.forwarding_rules"]}),
    "sub_locations": (lambda: wide_backup(sub_source()), lambda: Tenant({"zia.static_ips": [], "zia.locations": [], "zia.gre_tunnels": []}),
                      {"types": SUB, "include_tenant_bound": True}),
    "zcc_profiles": (lambda: wide_backup(zcc_source(), ("zcc",)), zcc_target, {"types": ZCC_KEYS, "include_zcc_profiles": True}),
}


@pytest.mark.parametrize("gate", ["write_mode", "assessor", "plan_hash", "typed_phrase"])
@pytest.mark.parametrize("case", sorted(GATE_CASES))
def test_each_new_write_type_is_refused_without_each_of_the_four_gates(monkeypatch, case, gate):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: a PAC file, DLP rule, ZPA gateway, sub-location or Client Connector clone writes nothing with write mode off, without a named assessor, with a plan hash other than the preview's, or without its typed phrase; with all four it applies (so each refusal is the gate's)."""
    monkeypatch.setattr(ao, "CONFIRM_ABOVE", 0)   # every plan asks for its phrase, so the phrase gate is tested for each type
    make_backup, make_target, kw = GATE_CASES[case]
    bid = make_backup()
    t = make_target()
    tgt = Client(t)
    sp = spec("zcc" if case == "zcc_profiles" else "zia", bid, **kw)
    p = ao.plan(tgt, sp, scope=WIDE, tenant_label="target")
    assert p["status"] == "ready" and p["confirm_phrase"], p["blockers"]
    args = {"plan_hash": p["plan_hash"], "scope": WIDE, "writes_enabled": True, "assessor": ASSESSOR, "tenant_label": "target",
            "confirm_text": p["confirm_phrase"]}
    if gate == "write_mode":
        with pytest.raises(PermissionError):
            ao.execute(tgt, sp, **dict(args, writes_enabled=False))
    elif gate == "assessor":
        with pytest.raises(ao.OperationError, match="assessor"):
            ao.execute(tgt, sp, **dict(args, assessor="  "))
    elif gate == "plan_hash":
        assert ao.execute(tgt, sp, **dict(args, plan_hash="0" * 64))["status"] == "plan_changed"
    else:
        assert ao.execute(tgt, sp, **dict(args, confirm_text="APPLY"))["status"] == "refused"
    assert t.writes == []
    r = ao.execute(tgt, sp, **args)
    assert r["status"] == "applied" and t.writes, r.get("stopped")


# ── fixes after verify: in a real browser, tenant-bound types start unticked ──

TB_DRIVER = r"""
const { chromium } = require('playwright');
const fs = require('fs');
const [chrome, js] = process.argv.slice(2);
(async () => {
  const b = await chromium.launch(chrome ? { executablePath: chrome } : {});
  try {
    const page = await b.newPage();
    await page.setContent('<!doctype html><html lang="en"><body><main id="where"></main></body></html>');
    await page.evaluate(() => { window.__plugins = {}; window.OPS_PLUGINS = { register: d => { window.__plugins[d.type] = d; } }; });
    await page.addScriptTag({ content: fs.readFileSync(js, 'utf8') });
    const out = await page.evaluate(() => {
      const res = { backups: [{ id: 'b1', tenant_label: 'Source', saved_at: '2026-11-01T10:00', kind: 'manual', objects: 9, products: ['zia'] }],
        modes: [{ id: 'update_matching', label: 'Update matching' }], templates: [],
        coverage: { products: { zia: [{ key: 'zia.rule_labels', label: 'Rule labels', level: 'full' },
                                      { key: 'zia.locations', label: 'Locations', level: 'full', tenant_bound: true },
                                      { key: 'zia.sub_locations', label: 'Sub-locations', level: 'full', tenant_bound: true }] } } };
      const S = { kind: 'config_restore_zia' };
      const E = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
      const H = { E, S, body: o => Object.assign({ profile_id: 'p1' }, o), say() {}, fail() {}, preview() {} };
      const where = document.getElementById('where'), d = window.__plugins.config_restore_zia;
      d.render(res, where, S, H);
      where.querySelector('input[name="crBackup"][value="b1"]').click();
      const look = () => ({ tb: document.getElementById('crTb').checked,
        shown: [...where.querySelectorAll('input[data-crtype]')].map(i => i.dataset.crtype),
        ticked: [...where.querySelectorAll('input[data-crtype]:checked')].map(i => i.dataset.crtype), spec: d.spec(S, H) });
      const before = look();
      document.getElementById('crTb').click();   // the person ticks "Include tenant-bound objects"
      return { before, after: look() };
    });
    console.log(JSON.stringify(out));
  } finally { await b.close(); }
})().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
"""


def test_tenant_bound_types_start_unticked_on_the_restore_page_and_are_sent_only_once_included(tmp_path):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-06 · WCAG 2.2 SC 3.3.2: in a real browser the restore page opens with 'Include tenant-bound objects' unticked, shows no tenant-bound type and leaves them (and the flag) out of the operation; ticking it shows them ticked and sends them with the flag."""
    node = shutil.which("node")
    if not node or subprocess.run([node, "-e", "require('playwright')"], capture_output=True, timeout=30).returncode:
        pytest.skip("needs node and Playwright")
    chrome = os.environ.get("CHROME_BIN", "")
    (tmp_path / "drive.js").write_text(TB_DRIVER, encoding="utf-8")
    r = subprocess.run([node, str(tmp_path / "drive.js"), chrome if chrome and os.path.exists(chrome) else "",
                        str(ROOT / "static" / "ops_config_restore.js")], capture_output=True, text=True, timeout=180, cwd=str(tmp_path))
    assert r.returncode == 0, r.stderr[-2000:]
    got = json.loads(r.stdout.strip().splitlines()[-1])
    before, after = got["before"], got["after"]
    assert before["tb"] is False and before["shown"] == ["zia.rule_labels"]
    assert before["spec"]["types"] == ["zia.rule_labels"] and "include_tenant_bound" not in before["spec"]
    assert after["tb"] is True and {"zia.locations", "zia.sub_locations"} <= set(after["ticked"])
    assert set(after["spec"]["types"]) == {"zia.rule_labels", "zia.locations", "zia.sub_locations"}
    assert after["spec"]["include_tenant_bound"] is True
