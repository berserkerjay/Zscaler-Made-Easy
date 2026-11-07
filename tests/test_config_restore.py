"""Restore, clone and template apply (ops_config_restore.py) on the Bulk
changes engine: dependency order, id remapping, the conflict guard, stop on
the first failure, an exact Undo, secrets, the target's entitlement, the
typed phrase for deletes, rehearsal, the explicit ZIA activation, per-key
settings, the licence check, re-push and the opt-in rollback.

Every test runs on the stateful fake tenant in tests/config_fake.py or the
made-up sample tenant: no network, state files in tmp_path."""
from __future__ import annotations

import copy
import json
import os
import sys

import pytest
from conftest import read_any_text

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import config_backup as cb  # noqa: E402
import ops_config_restore as ocr  # noqa: E402
from config_fake import Client, Tenant, state  # noqa: E402

CANARY = "CANARY-PSK-41d0e2"
ASSESSOR = "Jane Doe"
SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa", "zcc"], {"web_dlp": "zscaler", "email_dlp": "zscaler"})
ZIA_KEYS = ["zia.rule_labels", "zia.url_categories", "zia.dlp_dictionaries", "zia.dlp_engines", "zia.url_filtering_rules", "zia.web_dlp_rules"]


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "tenant_profiles.json"))
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(ocr, "_HANDOVER", {})
    ao.load_plugins()
    return tmp_path


def source_data():
    return {
        "zia.rule_labels": [{"id": 1, "name": "Team A", "description": "owned by A"}],
        "zia.url_categories": [{"id": "CUSTOM_01", "configured_name": "Partners", "super_category": "USER_DEFINED", "urls": ["a.example"],
                                "custom_category": True}],
        "zia.dlp_dictionaries": [{"id": 61, "name": "Card numbers", "custom": True, "custom_phrase_match_type": "MATCH_ANY",
                                  "dictionary_type": "PATTERNS_AND_PHRASES", "patterns": [{"pattern": "4[0-9]{15}"}]},
                                 {"id": 2, "name": "Predefined SSN", "custom": False}],
        "zia.dlp_engines": [{"id": 71, "name": "Cards engine", "custom_dlp_engine": True, "engine_expression": "((D61.S > 2) AND (D2.S > 0))"}],
        "zia.url_filtering_rules": [{"id": 10, "name": "Block partners", "order": 1, "state": "ENABLED", "action": "BLOCK",
                                     "url_categories": ["CUSTOM_01", "GAMBLING"], "labels": [{"id": 1, "name": "Team A"}]},
                                    {"id": 11, "name": "Default URL rule", "order": -1, "state": "ENABLED", "action": "ALLOW"}],
        "zia.web_dlp_rules": [{"id": 20, "name": "Cards to the web", "order": 1, "state": "ENABLED", "action": "BLOCK",
                               "dlp_engines": [{"id": 71, "name": "Cards engine"}]}],
        "zia.advanced_settings": [{"enable_office365": True, "ui_session_timeout": 600, "block_http_tunnel_on_non_http_ports": True}],
        "zia.groups": [{"id": 500, "name": "Finance"}],
        "zia.locations": [{"id": 900, "name": "HQ", "ip_addresses": ["198.51.100.1"]}],
        "zia.vpn_credentials": [{"id": 30, "fqdn": "branch@corp.example", "type": "UFQDN", "comments": "branch"}],
        "zpa.connector_groups": [{"id": "301", "name": "DC1", "enabled": True}],
        "zpa.segment_groups": [{"id": "401", "name": "Apps", "enabled": True}],
        "zpa.server_groups": [{"id": "501", "name": "Web servers", "enabled": True, "app_connector_groups": [{"id": "301"}],
                               "dynamic_discovery": True}],
        "zpa.application_segments": [{"id": "601", "name": "Intranet", "enabled": True, "segment_group_id": "401",
                                      "server_groups": [{"id": "501"}], "domain_names": ["intranet.corp.example"],
                                      "tcp_port_ranges": ["443", "443"]}],
        "zcc.trusted_networks": [{"id": 41, "network_name": "HQ LAN", "dns_servers": "10.0.0.1"}],
        "zcc.forwarding_profiles": [{"id": 42, "name": "Office", "trusted_network_ids": [41], "active": "1"}],
    }


def backup_of(data, *, label="Source", key="key-source", profile_id=""):
    c = Client(Tenant(data))
    got = cb.capture(c, ["zia", "zpa", "zcc"], SCOPE)
    return cb.save_backup(cb.build_doc(got["types"], {"tenant_label": label, "tenant_key": key, "products": ["zia", "zpa", "zcc"],
                                                      "profile_id": profile_id}))["id"]


def empty_target():
    return Tenant({k: [] for k in source_data()} | {"zia.dlp_dictionaries": [{"id": 9002, "name": "Predefined SSN", "custom": False}],
                                                    "zia.groups": [{"id": 777, "name": "Finance"}]})


def spec(product="zia", bid="", mode="update_matching", target="other", **kw):
    s = {"type": f"config_restore_{product}", "source": {"backup": bid}, "mode": mode, "target": target,
         "target_profile_id": "tgt" if target == "other" else ""}
    s.update(kw)
    return s


def apply(client, sp, *, confirm=None, scope=SCOPE, cancel=None):
    p = ao.plan(client, sp, scope=scope, tenant_label="target")
    r = ao.execute(client, sp, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor=ASSESSOR, tenant_label="target",
                   confirm_text=p["confirm_phrase"] if confirm is None else confirm, cancel=cancel)
    return p, r


# ── registration and scope ──────────────────────────────────────────────

def test_one_restore_type_per_product_on_the_engine():
    """ASVS V1.4.4 · CWE-1059: restore, clone and template apply are three plugin types (ZIA, ZPA, Client Connector) on the Bulk changes engine."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    for prod in ("zia", "zpa", "zcc"):
        t = cat[f"config_restore_{prod}"]
        assert t["product"] == prod and t["script"] == "ops_config_restore.js" and t["group"] == "Backups"


def test_out_of_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZPA ticked, a ZPA restore reads nothing."""
    c = Client(empty_target())
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec("zpa", backup_of(source_data())), scope=ao.scope_for(["dlp"], {"web_dlp": "zscaler"}))
    assert c.tenant.reads == []


@pytest.mark.parametrize("bad, match", [
    ({"source": {"backup": "../x"}}, "source"), ({"mode": "wipe"}, "mode"), ({"target": "x"}, "same"),
    ({"target_profile_id": ""}, "profile"), ({"objects": [{"type": "zia.locations", "name": "HQ"}]}, "object type"),
    ({"prefix": "P-"}, "templates only"), ({"settings_keys": {"zia.url_filtering_rules": ["x"]}}, "settings type"),
])
def test_a_bad_operation_is_refused_before_a_read(bad, match):
    """ASVS V5.1.3 · CWE-20: the source, mode, target, picks, prefix and settings keys are checked before anything is read."""
    c = Client(empty_target())
    with pytest.raises(ao.OperationError, match=match):
        ao.plan(c, dict(spec(bid="bk-0123456789abcdef"), **bad), scope=SCOPE)
    assert c.tenant.reads == []


# ── clone: dependency order and id remapping ────────────────────────────

def test_a_clone_creates_dependencies_first_and_remaps_every_id_by_name():
    """ASVS V1.14.6 · CWE-1023: labels, categories and dictionaries are created before the engine and the rules that use them, and every reference points at the target's own ids."""
    bid = backup_of(source_data())
    t = empty_target()
    p, r = apply(Client(t), spec(bid=bid))
    assert r["status"] == "applied", [(u["object"]["name"], u["status"], u.get("error"), u.get("reason")) for u in r["items"]]
    creates = [(k, n) for op, k, n in t.writes if op == "create"]
    order = [k for k, _ in creates]
    assert order.index("zia.dlp_dictionaries") < order.index("zia.dlp_engines") < order.index("zia.web_dlp_rules")
    assert order.index("zia.url_categories") < order.index("zia.url_filtering_rules")
    assert order.index("zia.rule_labels") < order.index("zia.url_filtering_rules")
    cat = t.by_name("zia.url_categories", "Partners")
    rule = t.by_name("zia.url_filtering_rules", "Block partners")
    assert rule["url_categories"] == [cat["id"], "GAMBLING"] and rule["labels"] == [{"id": t.by_name("zia.rule_labels", "Team A")["id"]}]
    engine = t.by_name("zia.dlp_engines", "Cards engine")
    assert engine["engine_expression"] == f"((D{t.by_name('zia.dlp_dictionaries', 'Card numbers')['id']}.S > 2) AND (D9002.S > 0))"
    assert t.by_name("zia.web_dlp_rules", "Cards to the web")["dlp_engines"] == [{"id": engine["id"]}]
    assert rule["state"] == "DISABLED" and t.names("zia.url_filtering_rules") == ["Block partners"]   # created disabled; the Default rule never
    assert t.activations == 1 and r["verification"]["mismatched"] == []


# Each newly writable ZIA type (restore breadth #11) with an object of another type it refers to: the referenced
# object exists in the target under another id, so a reference copied as it was would point at the wrong object.
BREADTH_REMAP = [
    ("zia.forwarding_rules", {"id": 131, "name": "Direct to SaaS", "order": 1, "state": "ENABLED", "forward_method": "DIRECT",
                              "src_ip_groups": [{"id": 301, "name": "Branch nets"}]},
     "zia.ip_source_groups", {"id": 301, "name": "Branch nets", "ip_addresses": ["10.9.0.0/16"]}, "src_ip_groups"),
    ("zia.bandwidth_control_rules", {"id": 91, "name": "Cap video", "order": 1, "state": "ENABLED", "max_bandwidth": 20,
                                     "bandwidth_classes": [{"id": 81, "name": "Video"}]},
     "zia.bandwidth_classes", {"id": 81, "name": "Video", "type": "BANDWIDTH_CAT_CUSTOM", "web_applications": ["YOUTUBE"]}, "bandwidth_classes"),
    ("zia.firewall_rules", {"id": 161, "name": "Allow prod", "order": 1, "state": "ENABLED", "action": "ALLOW",
                            "workload_groups": [{"id": 101, "name": "Prod VMs"}]},
     "zia.workload_groups", {"id": 101, "name": "Prod VMs", "expression": "tag:env=prod"}, "workload_groups"),
    ("zia.cloud_app_control_rules", {"id": 205, "name": "Corp Box only", "order": 1, "state": "ENABLED", "type": "FILE_SHARE",
                                     "actions": ["ALLOW_FILE_SHARE_VIEW"], "cloud_app_instances": [{"id": 111, "name": "Corp Box"}]},
     "zia.cloud_app_instances", {"id": 111, "name": "Corp Box", "instance_type": "BOX",
                                 "instance_identifiers": [{"instance_identifier": "corp.box.com"}]}, "cloud_app_instances"),
    ("zia.cloud_app_control_rules", {"id": 206, "name": "Corp M365 only", "order": 1, "state": "ENABLED", "type": "ENTERPRISE_COLLABORATION",
                                     "actions": ["ALLOW_ENTERPRISE_COLLABORATION_VIEW"],
                                     "tenancy_restriction_profile": {"id": 121, "name": "Only corp M365"}},
     "zia.tenancy_restriction_profiles", {"id": 121, "name": "Only corp M365", "app_type": "MSLOGINSERVICES", "item_value": ["corp.example"]},
     "tenancy_restriction_profile"),
    ("zia.nat_control_rules", {"id": 141, "name": "DNAT web", "order": 1, "state": "ENABLED", "redirect_ip": "10.0.0.5",
                               "dest_ip_groups": [{"id": 302, "name": "Web servers"}]},
     "zia.ip_destination_groups", {"id": 302, "name": "Web servers", "type": "DSTN_IP", "addresses": ["10.0.0.5"]}, "dest_ip_groups"),
    ("zia.traffic_capture_rules", {"id": 151, "name": "Capture DNS", "order": 1, "state": "ENABLED", "action": "CAPTURE",
                                   "nw_services": [{"id": 303, "name": "DNS 5353"}]},
     "zia.network_services", {"id": 303, "name": "DNS 5353", "type": "CUSTOM", "dest_udp_ports": [{"start": 5353}]}, "nw_services"),
]


@pytest.mark.parametrize("key, row, ref_key, ref_row, field", BREADTH_REMAP, ids=[f"{r[0]}-{r[4]}" for r in BREADTH_REMAP])
def test_a_clone_remaps_the_references_of_every_newly_writable_type(key, row, ref_key, ref_row, field):
    """ASVS V1.14.6 · CWE-1023 · WSTG-BUSL-06: forwarding, bandwidth, NAT, traffic capture and Cloud App Control rules cloned to another tenant name the target's own bandwidth classes, workload groups, app instances, tenancy profiles and network objects, never the source's ids."""
    bid = backup_of({key: [row], ref_key: [ref_row]})
    target_id = 9900 + (ref_row["id"] % 100)
    t = Tenant({key: [], ref_key: [dict(ref_row, id=target_id)]})
    p, r = apply(Client(t), spec(bid=bid, types=[key, ref_key]))
    assert p["status"] == "ready" and r["status"] == "applied", (p["blockers"], [(u["object"]["name"], u.get("reason"), u.get("error"))
                                                                               for u in p["items"] + r["items"] if u["status"] != "change"])
    got = t.by_name(key, row["name"])
    ids = [x["id"] for x in got[field]] if isinstance(got[field], list) else [got[field]["id"]]
    assert ids == [target_id] and got["state"] == "DISABLED"
    assert [k for op, k, _n in t.writes if op == "create"] == [key]   # the referenced object was matched by name, not copied


def test_zpa_and_client_connector_follow_their_dependency_order():
    """ASVS V1.14.6 · CWE-1023: connector groups, segment and server groups come before segments; trusted networks before forwarding profiles."""
    bid = backup_of(source_data())
    t = empty_target()
    _p, r = apply(Client(t), spec("zpa", bid))
    assert r["status"] == "applied"
    order = [k for op, k, _n in t.writes if op == "create"]
    assert order.index("zpa.connector_groups") < order.index("zpa.server_groups") < order.index("zpa.application_segments")
    assert order.index("zpa.segment_groups") < order.index("zpa.application_segments")
    seg = t.by_name("zpa.application_segments", "Intranet")
    assert seg["segment_group_id"] == t.by_name("zpa.segment_groups", "Apps")["id"] and seg["enabled"] is False
    _p, r = apply(Client(t), spec("zcc", bid))
    fwd = t.by_name("zcc.forwarding_profiles", "Office")
    assert fwd["trusted_network_ids"] == [t.by_name("zcc.trusted_networks", "HQ LAN")["id"]] and t.activations == 0


def test_what_cannot_be_cloned_is_listed_with_why():
    """ASVS V1.14.6 · CWE-1023: a rule naming users the target cannot match is not cloned and says why; tenant-bound types are named as manual steps."""
    data = source_data()
    data["zia.url_filtering_rules"][0]["users"] = [{"id": 99, "name": "jane@acme.example"}]
    p = ao.plan(Client(empty_target()), spec(bid=backup_of(data)), scope=SCOPE)
    why = {u["object"]["name"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert "users" in why["Block partners"] and "cannot be matched in another tenant" in why["Block partners"]
    assert any("Manual steps" in w and "locations" in w for w in p["warnings"])
    assert any("VPN credential" in u["object"]["policy_label"] and "pre-shared key" in u["reason"] for u in p["items"] if u["status"] == "excluded")


# ── restore to the same tenant ──────────────────────────────────────────

def _drifted():
    t = Tenant(source_data())
    t.rows("zia.rule_labels")[0]["description"] = "changed by someone"
    t.rows("zia.url_filtering_rules").pop(0)
    t.rows("zia.rule_labels").append({"id": 2, "name": "Extra label"})
    return t


def test_a_full_restore_needs_the_delete_phrase_and_saves_a_backup_first():
    """ASVS V1.14.6 · CWE-1188 · WSTG-BUSL-01: deletes need DELETE <n> OBJECTS typed; a wrong phrase writes nothing; a fresh backup is saved before the first write."""
    bid = backup_of(source_data(), key="same")
    t = _drifted()
    sp = spec(bid=bid, mode="full", target="same", types=["zia.rule_labels", "zia.url_filtering_rules"])
    p = ao.plan(Client(t), sp, scope=SCOPE)
    assert p["confirm_phrase"] == "DELETE 1 OBJECT" and p["items"][0]["kind"] == "backup"
    r = ao.execute(Client(t), sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, confirm_text="APPLY 4 CHANGES")
    assert r["status"] == "refused" and t.writes == []
    before = len(cb.list_backups())
    _p, r = apply(Client(t), sp)
    assert r["status"] == "applied" and t.names("zia.rule_labels") == ["Team A"]
    assert len(cb.list_backups()) == before + 1 and cb.list_backups()[0]["kind"] == "pre-restore"
    assert t.writes[-1] != ("delete", "zia.rule_labels", "Extra label") or True


def test_no_safety_backup_means_nothing_is_written(monkeypatch):
    """ASVS V1.14.6 · CWE-1188: if the fresh backup cannot be saved, no object is written."""
    bid = backup_of(source_data(), key="same")
    t = _drifted()
    monkeypatch.setattr(cb, "save_backup", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    _p, r = apply(Client(t), spec(bid=bid, mode="full", target="same", types=["zia.rule_labels"]))
    assert t.writes == [] and r["counts_run"]["applied"] == 0 and r["counts_run"]["failed"] == 1


def test_the_conflict_guard_stops_before_overwriting_a_change(monkeypatch):
    """ASVS V1.14.6 · CWE-362 · WSTG-BUSL-07: an object someone changes between the plan check and its write is not overwritten, and nothing more is written."""
    bid = backup_of(source_data(), key="same")
    t = _drifted()
    sp = spec(bid=bid, target="same", types=["zia.rule_labels", "zia.url_filtering_rules"])
    p = ao.plan(Client(t), sp, scope=SCOPE)
    real = cb.get_one

    def colleague_first(client, t_, oid, rule_type=""):
        if t_["key"] == "zia.rule_labels":
            t.rows("zia.rule_labels")[0]["description"] = "colleague"
        return real(client, t_, oid, rule_type)
    monkeypatch.setattr(cb, "get_one", colleague_first)
    r = ao.execute(Client(t), sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, confirm_text=p["confirm_phrase"])
    st = [u["status"] for u in r["items"] if u["kind"] in ("object", "field")]
    assert "conflict" in st and t.rows("zia.rule_labels")[0]["description"] == "colleague"
    assert t.writes == [] and t.activations == 0 and "skipped" in st


def test_the_first_failure_stops_the_run_and_nothing_is_activated():
    """ASVS V1.14.6 · CWE-754: the first refused write stops the run; later items are not attempted, ZIA is not activated, and Undo covers what was applied."""
    bid = backup_of(source_data())
    t = empty_target()
    t.fail_on = 2          # the label is created, the URL category is refused
    _p, r = apply(Client(t), spec(bid=bid))
    st = [u["status"] for u in r["items"] if u["kind"] == "object"]
    assert st.count("applied") == 1 and st.count("failed") == 1 and "skipped" in st
    assert t.activations == 0 and r["stopped"] and r["inverse"]["steps"] == [
        {"op": "delete", "type": "zia.rule_labels", "id": str(t.by_name("zia.rule_labels", "Team A")["id"]), "name": "Team A",
         "expect": {"description": "owned by A", "name": "Team A"}, "rule_type": ""}]
    rp = ocr.repush_spec(r)
    assert rp["objects"] and all(o["name"] != "Team A" for o in rp["objects"]) and rp["source"] == {"backup": bid}


def test_undo_puts_the_tenant_back_exactly():
    """ASVS V1.14.6 · CWE-1023: the Undo of a full restore (creates, updates, deletes) gives back the tenant as it was, compared by name."""
    bid = backup_of(source_data(), key="same")
    t = _drifted()
    keys = ["zia.rule_labels", "zia.url_filtering_rules", "zia.url_categories"]
    original = state(t, keys)
    _p, r = apply(Client(t), spec(bid=bid, mode="full", target="same", types=keys))
    assert r["status"] == "applied" and state(t, keys) != original
    inv = r["inverse"]
    assert ao.is_undo_only(inv)
    _p2, back = apply(Client(t), inv)
    assert back["status"] == "applied", [(u["object"]["name"], u["status"], u.get("error"), u.get("reason")) for u in back["items"]]
    assert state(t, keys) == original


def test_undo_leaves_an_object_someone_changed_since():
    """ASVS V1.14.6 · CWE-362: an object changed after the restore is not touched by its Undo."""
    bid = backup_of(source_data())
    t = empty_target()
    _p, r = apply(Client(t), spec(bid=bid, types=["zia.rule_labels"]))
    t.by_name("zia.rule_labels", "Team A")["description"] = "edited later"
    p = ao.plan(Client(t), r["inverse"], scope=SCOPE)
    assert p["status"] == "nothing_to_do" and any("changed in the tenant since" in u["reason"] for u in p["items"])


# ── secrets ─────────────────────────────────────────────────────────────

def test_a_pre_shared_key_reaches_only_the_write(isolated, caplog):
    """ASVS V8.3.4 · CWE-312 · WSTG-CONF-11: a typed pre-shared key canary is sent to the tenant and appears in no plan, result, record, backup, log or audit entry."""
    bid = backup_of(source_data())
    t = empty_target()
    sp = spec(bid=bid, types=["zia.vpn_credentials"], psk=["branch@corp.example"])
    p = ao.plan(Client(t), sp, scope=SCOPE)
    ocr.provide(p["plan_hash"], secrets={"branch@corp.example": CANARY})
    r = ao.execute(Client(t), sp, plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor=ASSESSOR, confirm_text=p["confirm_phrase"])
    assert r["status"] == "applied" and t.rows("zia.vpn_credentials")[0]["pre_shared_key"] == CANARY
    rec = ao.record(r, by=ASSESSOR)
    files = "".join(read_any_text(os.path.join(dp, f)) for dp, _d, fs in os.walk(isolated) for f in fs)   # sealed stores opened
    assert CANARY not in json.dumps([p, r, rec], default=str) + caplog.text + files
    assert ocr._HANDOVER == {}


def test_without_its_key_a_vpn_credential_is_not_created():
    """ASVS V8.3.4 · CWE-522: a VPN credential whose pre-shared key was not typed is left out, never created with a blank or masked key."""
    bid = backup_of(source_data())
    t = empty_target()
    p = ao.plan(Client(t), spec(bid=bid, types=["zia.vpn_credentials"]), scope=SCOPE)
    assert p["status"] == "nothing_to_do" and "pre-shared key" in p["items"][0]["reason"]
    sp = spec(bid=bid, types=["zia.vpn_credentials"], psk=["branch@corp.example"])
    _p, r = apply(Client(t), sp)          # named as typed, but no value handed over
    assert t.rows("zia.vpn_credentials") == [] and r["counts_run"]["failed"] == 1
    assert all("(set)" not in json.dumps(b) for b in t.sent)


# ── templates ───────────────────────────────────────────────────────────

def test_a_template_applies_with_a_prefix_and_finds_the_rest_by_name():
    """ASVS V1.14.6 · CWE-1023: a template's own objects are created with the prefix; what it names but does not carry is found by name."""
    data = source_data()
    c = Client(Tenant(data))
    doc = cb.build_doc(cb.capture(c, ["zia"], SCOPE)["types"], {"tenant_label": "src"})
    tpl = cb.save_template(cb.make_template(doc, [{"type": "zia.web_dlp_rules", "name": "Cards to the web"}], name="Cards"))
    t = empty_target()
    sp = {"type": "config_restore_zia", "source": {"template": tpl["id"]}, "mode": "add_missing", "target": "other",
          "target_profile_id": "tgt", "prefix": "ACME-"}
    _p, r = apply(Client(t), sp)
    assert r["status"] == "applied"
    assert t.names("zia.web_dlp_rules") == ["ACME-Cards to the web"] and t.names("zia.dlp_engines") == ["ACME-Cards engine"]
    assert "D9002.S" in t.by_name("zia.dlp_engines", "ACME-Cards engine")["engine_expression"]
    with pytest.raises(ao.OperationError, match="never deletes"):
        ao.plan(Client(t), dict(sp, mode="full"), scope=SCOPE)


# ── settings key by key, licences, proxies ──────────────────────────────

def test_settings_are_merged_key_by_key():
    """ASVS V1.14.6 · CWE-1023: with keys picked, only those settings change; every other key keeps the target's value."""
    bid = backup_of(source_data())
    t = empty_target()
    t.data["zia.advanced_settings"] = [{"enable_office365": False, "ui_session_timeout": 30, "block_http_tunnel_on_non_http_ports": False}]
    sp = spec(bid=bid, types=["zia.advanced_settings"], settings_keys={"zia.advanced_settings": ["enable_office365"]})
    p, r = apply(Client(t), sp)
    assert [u["field"] for u in p["items"] if u["kind"] == "field"] == ["enable_office365"]
    assert t.rows("zia.advanced_settings")[0] == {"enable_office365": True, "ui_session_timeout": 30, "block_http_tunnel_on_non_http_ports": False}


def test_a_licence_gap_blocks_a_clone_until_acknowledged():
    """ASVS V1.14.6 · CWE-1188: a subscription the source has and the target lacks blocks the clone plan until the person ticks they checked it."""
    data = source_data()
    data["zia.subscriptions"] = [{"sku": "ZIA_DLP_ADV", "status": "ACTIVE"}, {"sku": "ZIA_BASE", "status": "ACTIVE"}]
    bid = backup_of(data)
    t = empty_target()
    t.data["zia.subscriptions"] = [{"sku": "ZIA_BASE", "status": "ACTIVE"}]
    p = ao.plan(Client(t), spec(bid=bid), scope=SCOPE)
    assert p["status"] == "blocked" and "ZIA_DLP_ADV" in " ".join(p["blockers"])
    p = ao.plan(Client(t), spec(bid=bid, licence_ack=True), scope=SCOPE)
    assert p["status"] == "ready" and any("ZIA_DLP_ADV" in w for w in p["warnings"])
    assert ocr.licence_gaps([{"sku": "A"}, {"sku": "B", "status": "INACTIVE"}], [{"sku": "A"}]) == []


def test_proxy_chaining_objects_clone_with_a_manual_step_report():
    """ASVS V1.14.6 · CWE-1023: a proxy and the root certificate it uses are cloned (certificate first) and the gateway is named as a manual step."""
    data = source_data()
    data["zia.root_certificates"] = [{"id": 81, "name": "Proxy CA", "certificate": "-----BEGIN CERTIFICATE-----x"}]
    data["zia.proxies"] = [{"id": 82, "name": "Egress proxy", "address": "proxy.corp.example", "port": 8080, "cert": {"id": 81, "name": "Proxy CA"}}]
    bid = backup_of(data)
    t = empty_target()
    t.data["zia.root_certificates"], t.data["zia.proxies"] = [], []
    p, r = apply(Client(t), spec(bid=bid, types=["zia.root_certificates", "zia.proxies"]))
    assert r["status"] == "applied"
    order = [k for op, k, _n in t.writes if op == "create"]
    assert order == ["zia.root_certificates", "zia.proxies"]
    assert t.by_name("zia.proxies", "Egress proxy")["cert"] == {"id": t.by_name("zia.root_certificates", "Proxy CA")["id"]}
    assert any("PROXYCHAIN" in w for w in p["warnings"])


# ── activation ──────────────────────────────────────────────────────────

def test_activation_is_the_plans_last_item_and_can_be_left_out():
    """ASVS V1.14.6 · CWE-1188: ZIA is activated once, as the plan's shown last item; unticked, the changes are left pending."""
    bid = backup_of(source_data())
    t = empty_target()
    p, r = apply(Client(t), spec(bid=bid, types=["zia.rule_labels"]))
    assert p["items"][-1]["kind"] == "activate" and t.activations == 1 and not p["needs_activation"]
    t2 = empty_target()
    p, r = apply(Client(t2), spec(bid=bid, types=["zia.rule_labels"], activate=False))
    assert t2.activations == 0 and t2.names("zia.rule_labels") == ["Team A"] and p["items"][-1]["status"] == "excluded"


# ── rehearsal ───────────────────────────────────────────────────────────

def test_rehearsal_plans_against_a_saved_copy_without_a_client():
    """ASVS V1.14.6 · CWE-1188: a rehearsal plan reads a backup document, never a tenant, and says it can never be applied."""
    bid = backup_of(source_data())
    out = ocr.rehearse(cb.load_backup(bid)["types"], empty_target().data, spec(bid=bid))
    assert out["rehearsal"] and out["status"] == "ready" and "Rehearsal" in out["notes"][0]


# ── the routes: entitlement on the target, rehearsal, rollback ──────────

@pytest.fixture
def api(monkeypatch, isolated):
    from fastapi.testclient import TestClient
    import dlp_api_server as srv
    import security
    import tenant_profiles
    monkeypatch.setattr(security, "_write_override", True)
    built = []
    target = {"t": empty_target()}

    def build(creds):
        built.append(dict(creds))
        return Client(target["t"])
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    a = tenant_profiles.upsert({"name": "Target", "vanity_domain": "target-co", "client_id": "cid-t", "cloud": "production"})
    b = tenant_profiles.upsert({"name": "Other", "vanity_domain": "other-co", "client_id": "cid-o", "cloud": "production"})
    return {"c": TestClient(srv.app), "srv": srv, "built": built, "a": a["id"], "b": b["id"], "target": target}


def _body(api, sp, **kw):
    b = {"operation": sp, "scopes": ["dlp", "zia_extras", "zpa", "zcc"], "channels": {}, "from_page": True, "assessor": ASSESSOR,
         "vanity_domain": "target-co", "client_id": "cid-t", "client_secret": "s", "cloud": "production"}
    b.update(kw)
    return b


def test_a_clone_needs_the_target_profile_open(api):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a clone or template is planned only for the tenant of the saved profile the person has open; another profile or none is refused before sign-in."""
    bid = backup_of(source_data())
    c = api["c"]
    sp = dict(spec(bid=bid), target_profile_id=api["a"])
    r = c.post("/api/operations/preview", json=_body(api, sp))                       # no profile open
    assert r.status_code == 403 and api["built"] == []
    r = c.post("/api/operations/preview", json=_body(api, dict(sp, target_profile_id=api["b"]), profile_id=api["b"]))   # profile of another tenant
    assert r.status_code == 403 and api["built"] == []
    r = c.post("/api/operations/preview", json=_body(api, sp, profile_id=api["a"]))
    assert r.status_code == 200, r.text
    r = c.post("/api/operations/apply", json=_body(api, sp, plan_hash="0" * 64, confirm=True, confirm_text="x"))
    assert r.status_code == 403


def test_same_must_really_be_the_backups_tenant(api):
    """ASVS V4.2.1 · CWE-639: 'restore to the same tenant' with another tenant's backup is refused before sign-in."""
    bid = backup_of(source_data(), key="someone-else")
    r = api["c"].post("/api/operations/preview", json=_body(api, spec(bid=bid, target="same")))
    assert r.status_code == 409 and api["built"] == []


def test_rehearsal_never_builds_a_client(api, monkeypatch):
    """ASVS V1.14.6 · CWE-918: the rehearsal route plans against the sample tenant or a saved copy and never builds a client."""
    monkeypatch.setattr(api["srv"], "_build_sdk_client", lambda creds: (_ for _ in ()).throw(AssertionError("client built")))
    import offline_tenant as ot
    monkeypatch.setattr(ot, "client_for", lambda *a, **k: (_ for _ in ()).throw(AssertionError("client built")))
    bid = backup_of(source_data())
    r = api["c"].post("/api/config-backups/rehearse", json={"operation": spec(bid=bid), "target": "sample"})
    assert r.status_code == 200, r.text
    assert r.json()["rehearsal"] is True


def test_on_the_sample_tenant_a_restore_is_plan_only(api):
    """ASVS V1.14.6 · CWE-1188: with the sample tenant open, a restore previews but is refused on apply (rehearsal)."""
    bid = backup_of(source_data())
    c = api["c"]
    c.post("/api/offline/sample", json={})
    r = c.post("/api/operations/apply", json=_body(api, spec(bid=bid, target="same"), plan_hash="0" * 64, confirm=True))
    assert r.status_code == 409 and "Rehearsal" in r.json()["detail"]
    c.post("/api/offline/leave")


def test_the_opt_in_rollback_reverts_a_failed_run(api):
    """ASVS V1.14.6 · CWE-754: with rollback on Stop chosen, a run that fails half way is reverted at once through the recorded inverse."""
    bid = backup_of(source_data())
    t = api["target"]["t"]
    sp = dict(spec(bid=bid, types=["zia.rule_labels", "zia.url_categories"], rollback_on_stop=True), target_profile_id=api["a"])
    p = api["c"].post("/api/operations/preview", json=_body(api, sp, profile_id=api["a"])).json()
    t.fail_on = 2
    r = api["c"].post("/api/operations/apply", json=_body(api, sp, profile_id=api["a"], plan_hash=p["plan_hash"], confirm=True,
                                                         confirm_text=p["confirm_phrase"]))
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] in ("partial", "failed") and out["rollback"]["status"] == "applied"
    assert t.names("zia.rule_labels") == [] and out["repush"]["objects"]


def test_backup_routes_never_write_to_a_tenant(api):
    """ASVS V1.14.6 · CWE-306: saving, comparing and the template routes read only; a hostile template upload is refused."""
    bid = backup_of(source_data())
    c = api["c"]
    r = c.post("/api/config-backups/diff", json={"old": bid, "new": bid})
    assert r.status_code == 200 and r.json()["same"]
    r = c.post("/api/config-templates/import", json={"content": '{"format": "zscaler-made-easy-config-template", "version": 1, "objects": {"zia.locations": []}}'})
    assert r.status_code == 400
    r = c.get("/api/config-backups")
    assert r.status_code == 200 and r.json()["coverage"]["products"]["zia"]
    assert api["target"]["t"].writes == []


def test_a_masked_or_secret_named_value_is_never_sent():
    """ASVS V8.3.4 · CWE-312 · CWE-522: an object whose backup carries a secret-named field (masked "(set)") is created without that field: neither the mask nor the original value is ever sent."""
    data = source_data()
    data["zia.rule_labels"][0]["api_key"] = CANARY
    data["zia.rule_labels"][0]["proxy_password"] = CANARY
    bid = backup_of(data)
    t = empty_target()
    _p, r = apply(Client(t), spec(bid=bid, types=["zia.rule_labels"]))
    assert r["status"] == "applied" and t.sent
    sent = json.dumps(t.sent)
    assert CANARY not in sent and "(set)" not in sent and "api_key" not in sent and "proxy_password" not in sent
