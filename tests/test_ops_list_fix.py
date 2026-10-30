"""Fix selected, wider (ops_list_fix): Test a list rows that missed their
expected outcome become IP destination group, Cloud Firewall rule, DNS
Control rule and ATP list changes on the Bulk changes engine. Fakes only: a
recording ZIA with the SDK's service and method names; no network, no real
tenant."""
from __future__ import annotations

import copy

import pytest

import admin_ops as ao
import bulk_test as bt
import ops_list_fix as lf
import pack_channels as pc

# ---------------------------------------------------------------------------
# The fake tenant: the SDK 1.11.3 services and methods ops_list_fix uses
# ---------------------------------------------------------------------------


class Rules:
    """cloud_firewall_rules / cloud_firewall_dns: list_rules, get_rule, add_rule, update_rule, delete_rule."""

    def __init__(self, t, name, rows):
        self.t, self.name, self.rows, self.next_id = t, name, [copy.deepcopy(r) for r in rows], 900

    def _find(self, rid):
        return next((r for r in self.rows if str(r["id"]) == str(rid)), None)

    def list_rules(self, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return [copy.deepcopy(r) for r in self.rows], None, None

    def get_rule(self, rid):
        self.t.reads.append(f"{self.name}.get_rule")
        if self.t.before_get:
            self.t.before_get(self.name, rid)
        r = self._find(rid)
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add_rule(self, **kw):
        self.t.writes.append((self.name, "add_rule", copy.deepcopy(kw)))
        self.next_id += 1
        for r in self.rows:
            if not r.get("default_rule") and int(r.get("order") or 0) >= int(kw.get("order") or 0):
                r["order"] = int(r["order"]) + 1
        row = dict(copy.deepcopy(kw), id=self.next_id)
        row["dest_ip_groups"] = [{"id": int(g)} for g in kw.get("dest_ip_groups") or []]
        row["nw_services"] = [{"id": int(g)} for g in kw.get("nw_services") or []]
        self.rows.append(row)
        return copy.deepcopy(row), None, None

    def update_rule(self, rid, **kw):
        self.t.writes.append((self.name, "update_rule", rid, copy.deepcopy(kw)))
        r = self._find(rid)
        r.clear()
        r.update(copy.deepcopy(kw), id=int(rid))
        for f in ("dest_ip_groups", "nw_services"):
            if f in kw:
                r[f] = [{"id": int(x)} for x in kw[f]]
        return copy.deepcopy(r), None, None

    def delete_rule(self, rid, *a):
        self.t.writes.append((self.name, "delete_rule", rid))
        self.rows = [r for r in self.rows if str(r["id"]) != str(rid)]
        return None, None, None


class Firewall:
    """cloud_firewall: the IP destination groups and network services."""

    def __init__(self, t, groups, services):
        self.t, self.groups, self.services, self.next_id = t, [copy.deepcopy(g) for g in groups], services, 7000

    def _find(self, gid):
        return next((g for g in self.groups if str(g["id"]) == str(gid)), None)

    def list_ip_destination_groups(self, *a, **k):
        self.t.reads.append("cloud_firewall.list_ip_destination_groups")
        return copy.deepcopy(self.groups), None, None

    def get_ip_destination_group(self, gid):
        self.t.reads.append("cloud_firewall.get_ip_destination_group")
        if self.t.before_get:
            self.t.before_get("group", gid)
        g = self._find(gid)
        return (copy.deepcopy(g), None, None) if g else (None, None, {"message": "not found", "status": 404})

    def add_ip_destination_group(self, **kw):
        self.t.writes.append(("cloud_firewall", "add_ip_destination_group", copy.deepcopy(kw)))
        if len(kw.get("addresses") or []) > self.t.group_cap:
            return None, None, {"message": f"more than {self.t.group_cap} addresses", "status": 400}
        self.next_id += 1
        g = dict(copy.deepcopy(kw), id=self.next_id)
        self.groups.append(g)
        return copy.deepcopy(g), None, None

    def update_ip_destination_group(self, gid, **kw):
        self.t.writes.append(("cloud_firewall", "update_ip_destination_group", gid, copy.deepcopy(kw)))
        g = self._find(gid)
        g.clear()
        g.update(copy.deepcopy(kw), id=int(gid))
        return copy.deepcopy(g), None, None

    def delete_ip_destination_group(self, gid):
        self.t.writes.append(("cloud_firewall", "delete_ip_destination_group", gid))
        self.groups = [g for g in self.groups if str(g["id"]) != str(gid)]
        return None, None, None

    def list_network_services(self, *a, **k):
        self.t.reads.append("cloud_firewall.list_network_services")
        return copy.deepcopy(self.services), None, None


class Security:
    """security_policy_settings: the allow and deny lists."""

    def __init__(self, t, allow, deny):
        self.t, self.allow, self.deny = t, list(allow), list(deny)

    def get_whitelist(self):
        self.t.reads.append("security.get_whitelist")
        if self.t.before_get:
            self.t.before_get("allowlist", None)
        return {"whitelist_urls": list(self.allow)}, None, None

    def get_blacklist(self):
        self.t.reads.append("security.get_blacklist")
        if self.t.before_get:
            self.t.before_get("denylist", None)
        return {"blacklist_urls": list(self.deny)}, None, None

    def replace_whitelist(self, urls):
        self.t.writes.append(("security", "replace_whitelist", list(urls)))
        self.allow = list(urls)
        return {"whitelist_urls": list(self.allow)}, None, None

    def add_urls_to_blacklist(self, urls):
        self.t.writes.append(("security", "add_urls_to_blacklist", list(urls)))
        self.deny += [u for u in urls if u not in self.deny]
        return {"blacklist_urls": list(self.deny)}, None, None

    def delete_urls_from_blacklist(self, urls):
        self.t.writes.append(("security", "delete_urls_from_blacklist", list(urls)))
        self.deny = [u for u in self.deny if u not in urls]
        return {"blacklist_urls": list(self.deny)}, None, None


FW_RULES = [{"id": 31, "name": "Block bad hosts", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK_DROP",
             "dest_ip_groups": [{"id": 501, "name": "Bad IPs"}], "nw_services": []},
            {"id": 32, "name": "Allow all outbound", "order": 2, "rank": 7, "state": "ENABLED", "action": "ALLOW"},
            {"id": 39, "name": "Default Firewall Filtering Rule", "order": 127, "default_rule": True, "predefined": True, "action": "ALLOW"}]
DNS_RULES = [{"id": 61, "name": "Block DNS tunnels", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK", "applications": ["DNS_TUNNELS"]},
             {"id": 62, "name": "Allow partner DNS", "order": 2, "rank": 7, "state": "DISABLED", "action": "ALLOW"}]
GROUPS = [{"id": 501, "name": "Bad IPs", "type": "DSTN_IP", "addresses": ["198.51.100.0/24"], "description": "kept"},
          {"id": 502, "name": "Bad hosts", "type": "DSTN_FQDN", "addresses": ["evil.example"]},
          {"id": 503, "name": "Countries", "type": "DSTN_OTHER", "countries": ["COUNTRY_KP"]},
          {"id": 504, "name": "Zscaler managed", "type": "DSTN_IP", "addresses": [], "is_non_editable": True}]
SERVICES = [{"id": 41, "name": "QUIC"}, {"id": 42, "name": "SSH"}]


class Tenant:
    def __init__(self, groups=GROUPS, allow=("partner.example",), deny=("drop.example",)):
        self.reads, self.writes = [], []
        self.before_get = None
        self.group_cap = 10 ** 9
        z = type("Zia", (), {})()
        z.cloud_firewall_rules = Rules(self, "cloud_firewall_rules", FW_RULES)
        z.cloud_firewall_dns = Rules(self, "cloud_firewall_dns", DNS_RULES)
        z.cloud_firewall = Firewall(self, groups, SERVICES)
        z.security_policy_settings = Security(self, allow, deny)
        self.zia, self.zpa = z, None

    def state(self):
        z = self.zia
        return copy.deepcopy({"fw": z.cloud_firewall_rules.rows, "dns": z.cloud_firewall_dns.rows, "groups": z.cloud_firewall.groups,
                              "allow": z.security_policy_settings.allow, "deny": z.security_policy_settings.deny})


PLATFORM = ao.scope_for(["zia_extras"], {})
DLP_ONLY = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})


@pytest.fixture(autouse=True)
def _no_activation(monkeypatch):
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def plan(t, spec, scope=PLATFORM):
    return ao.plan(t, spec, scope=scope, tenant_label="acme (zscalertwo)")


def apply(t, spec, scope=PLATFORM, prepared=None):
    prepared = prepared or plan(t, spec, scope)
    return ao.execute(t, spec, plan_hash=prepared["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=prepared["confirm_phrase"], tenant_label="acme (zscalertwo)")


def undo(t, result, scope=PLATFORM):
    inv = result["inverse"]
    assert inv and ao.is_undo_only(inv)
    return apply(t, inv, scope)


def fw(dests, **kw):
    f = {"area": "firewall", "purpose": "block", "destinations": [{"value": v, "rows": [i + 1]} for i, v in enumerate(dests)]}
    f.update(kw)
    return {"type": "list_fix", "fixes": [f]}


def writes(t, method):
    return [w for w in t.writes if w[1] == method]


# ---------------------------------------------------------------------------
# Payload oracle per object type (the SDK 1.11.3 methods and model fields)
# ---------------------------------------------------------------------------

def _model_fields(cls):
    return {k for k in vars(cls(None)) if not k.startswith("_")}


def test_a_new_ip_group_and_a_new_disabled_rule_send_the_sdk_payloads():
    """ASVS V5.1.3 · CWE-20 · CWE-1188: a new IP destination group and a new Cloud Firewall rule are sent with the SDK 1.11.3 methods and fields, the rule DISABLED, placed above the rule that decided the rows."""
    from zscaler.zia.models.cloud_firewall_destination_groups import IPDestinationGroups
    from zscaler.zia.models.cloud_firewall_rules import FirewallRule
    t = Tenant()
    spec = fw(["203.0.113.4", "203.0.113.5", "203.0.113.6", "203.0.113.7"], ip_group={"new": "Fix blocked IPs"},
              rule={"new": {"name": "Fix: block listed IPs", "above": 32}}, services=[42], decided_by=["Allow all outbound"])
    res = apply(t, spec)
    assert res["status"] == "applied", res
    (_s, _m, grp), = writes(t, "add_ip_destination_group")
    assert grp == {"name": "Fix blocked IPs", "type": "DSTN_IP", "addresses": ["203.0.113.4/30"],
                   "description": "Created by Jane Doe with Bulk changes (Fix selected, Test a list)"}
    assert set(grp) <= _model_fields(IPDestinationGroups)
    (_s, _m, rule), = writes(t, "add_rule")
    assert rule == {"name": "Fix: block listed IPs", "state": "DISABLED", "action": "BLOCK_DROP", "rank": 7, "dest_ip_groups": [7001],
                    "nw_services": [42], "order": 2, "description": "Created by Jane Doe with Bulk changes (Fix selected, Test a list)"}
    assert set(rule) <= _model_fields(FirewallRule)
    assert res["verification"]["confirmed"] == res["verification"]["checked"] > 0


def test_adding_to_an_existing_group_and_rule_sends_the_whole_object_back():
    """ASVS V5.1.3 · CWE-20 · CWE-915: an existing group is PUT with its own fields and the new addresses; an existing rule keeps its fields and gains the group."""
    from zscaler.zia.models.cloud_firewall_destination_groups import IPDestinationGroups
    from zscaler.zia.models.cloud_firewall_rules import FirewallRule
    t = Tenant()
    spec = fw(["203.0.113.9", "bad.example"], ip_group={"id": 501}, fqdn_group={"id": 502}, rule={"id": 31})
    res = apply(t, spec)
    assert res["status"] == "applied", res
    ups = writes(t, "update_ip_destination_group")
    assert [(w[2], w[3]) for w in ups] == [
        (501, {"name": "Bad IPs", "type": "DSTN_IP", "description": "kept", "addresses": ["198.51.100.0/24", "203.0.113.9"]}),
        (502, {"name": "Bad hosts", "type": "DSTN_FQDN", "addresses": ["evil.example", "bad.example"]})]
    for w in ups:
        assert set(w[3]) <= _model_fields(IPDestinationGroups)
    (_s, _m, rid, body), = writes(t, "update_rule")
    assert rid == 31 and body["dest_ip_groups"] == [501, 502] and body["action"] == "BLOCK_DROP" and body["name"] == "Block bad hosts"
    assert set(body) <= _model_fields(FirewallRule)


def test_a_dns_fix_creates_a_disabled_dns_rule_with_a_fqdn_group():
    """ASVS V5.1.3 · CWE-20 · CWE-1188: a DNS Control fix puts host names in a DSTN_FQDN group and creates a DNS rule (action BLOCK) disabled."""
    from zscaler.zia.models.cloud_firewall_dns_rules import FirewallDNSRules
    t = Tenant()
    spec = {"type": "list_fix", "fixes": [{"area": "dns", "purpose": "block", "destinations": [{"value": "tunnel.example", "rows": [3]}],
                                           "fqdn_group": {"new": "Fix DNS block"}, "rule": {"new": {"name": "Fix: DNS block"}}}]}
    res = apply(t, spec)
    assert res["status"] == "applied", res
    (_s, _m, grp), = writes(t, "add_ip_destination_group")
    assert grp["type"] == "DSTN_FQDN" and grp["addresses"] == ["tunnel.example"]
    (name, _m, rule), = writes(t, "add_rule")
    assert name == "cloud_firewall_dns" and rule["action"] == "BLOCK" and rule["state"] == "DISABLED" and rule["order"] == 3
    assert set(rule) <= _model_fields(FirewallDNSRules)


def test_atp_lists_use_the_incremental_denylist_and_the_whole_allowlist():
    """ASVS V5.1.3 · CWE-20: the denylist gets ADD_TO_LIST (add_urls_to_blacklist); the allowlist, which has no incremental call, gets its whole list back with the addition (replace_whitelist)."""
    t = Tenant()
    spec = {"type": "list_fix", "fixes": [
        {"area": "atp", "purpose": "block", "destinations": [{"value": "https://phish.example/login", "rows": [1]}, {"value": "drop.example", "rows": [2]}]},
        {"area": "atp", "purpose": "allow", "destinations": [{"value": "Vendor.Example", "rows": [5]}]}]}
    p = plan(t, spec)
    assert p["confirm_phrase"] == "APPLY 2 CHANGES"            # live at activation: typed whatever the count
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied", res
    assert writes(t, "add_urls_to_blacklist") == [("security", "add_urls_to_blacklist", ["phish.example/login"])]
    assert writes(t, "replace_whitelist") == [("security", "replace_whitelist", ["partner.example", "vendor.example"])]
    assert [u["status"] for u in res["items"] if u["value"] == "drop.example"] == ["noop"]


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------

def test_an_existing_group_at_its_limit_refuses_the_rest_clearly(monkeypatch):
    """ASVS V12.1.1 · CWE-770: boundary: an existing group takes entries up to its per-group limit; the rest are excluded with the reason, never sent."""
    monkeypatch.setattr(lf, "MAX_GROUP_ADDRESSES", 3)
    t = Tenant()
    p = plan(t, fw(["10.1.0.1", "10.2.0.1", "10.3.0.1"], ip_group={"id": 501}))
    st = {u["value"]: (u["status"], u["reason"]) for u in p["items"]}
    assert [st[v][0] for v in ("10.1.0.1", "10.2.0.1", "10.3.0.1")] == ["change", "change", "excluded"]
    assert "more than 3 entries" in st["10.3.0.1"][1]


def test_a_new_group_over_the_limit_is_split_into_numbered_groups(monkeypatch):
    """ASVS V12.1.1 · CWE-770: boundary: a new group past the per-group limit is split into 'name', 'name (2)', each added to the new rule."""
    monkeypatch.setattr(lf, "MAX_GROUP_ADDRESSES", 2)
    t = Tenant()
    t.group_cap = 2
    res = apply(t, fw(["10.1.0.1", "10.2.0.1", "10.3.0.1"], ip_group={"new": "Split"}, rule={"new": {"name": "Fix split"}}))
    assert res["status"] == "applied", res
    names = [w[2]["name"] for w in writes(t, "add_ip_destination_group")]
    assert names == ["Split", "Split (2)"]
    (_s, _m, rule), = writes(t, "add_rule")
    assert rule["dest_ip_groups"] == [7001, 7002]
    assert any("split over 2 new groups" in w for w in res["warnings"])


def test_ipv6_and_bad_entries_are_refused_with_the_reason():
    """ASVS V5.1.3 · CWE-20: an IPv6 destination (no user-defined IPv6 group in ZIA's API), a CIDR with host bits and a group of the wrong type are refused in words."""
    t = Tenant()
    p = plan(t, fw(["2001:db8::1", "10.0.0.5/24", "ok.example"], ip_group={"id": 501}, fqdn_group={"id": 503}))
    why = {u["value"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert "IPv6" in why["2001:db8::1"] and "10.0.0.0/24" in why["10.0.0.5/24"]
    assert p["status"] == "blocked" and any("DSTN_OTHER" in b for b in p["blockers"])


def test_a_rule_whose_action_is_the_opposite_blocks_the_plan():
    """ASVS V4.1.3 · CWE-840: rows to block are never added to an Allow rule (and the Default rule is never changed)."""
    t = Tenant()
    p = plan(t, fw(["203.0.113.9"], ip_group={"id": 501}, rule={"id": 32}))
    assert p["status"] == "blocked" and any("ALLOW" in b for b in p["blockers"])
    p2 = plan(t, dict(fw(["203.0.113.9"], ip_group={"id": 501}, rule={"id": 39}), fixes=[dict(fw(["203.0.113.9"])["fixes"][0],
                                                                                                ip_group={"id": 501}, rule={"id": 39}, purpose="allow")]))
    assert p2["status"] == "blocked" and any("Default rule" in b for b in p2["blockers"])
    assert not t.writes


# ---------------------------------------------------------------------------
# Conflict on re-read
# ---------------------------------------------------------------------------

def test_a_group_changed_after_the_preview_is_left_as_it_is():
    """ASVS V11.1.3 · CWE-362 · CWE-367: someone adds the same address right before the write: the item is a conflict and nothing overwrites their change."""
    t = Tenant()
    spec = fw(["203.0.113.9"], ip_group={"id": 501})
    p = plan(t, spec)

    def race(kind, gid):
        if kind == "group":
            g = t.zia.cloud_firewall._find(501)
            if "203.0.113.9" not in g["addresses"]:
                g["addresses"].append("203.0.113.9")
    t.before_get = race
    res = apply(t, spec, prepared=p)
    assert [u["status"] for u in res["items"] if u["value"] == "203.0.113.9"] == ["conflict"]
    assert not writes(t, "update_ip_destination_group")


def test_a_tenant_that_moved_since_the_preview_writes_nothing():
    """ASVS V11.1.3 · CWE-367: the plan hash no longer matches the tenant: nothing is written and the new preview is returned."""
    t = Tenant()
    spec = fw(["203.0.113.9"], ip_group={"id": 501}, rule={"id": 31})
    p = plan(t, spec)
    t.zia.cloud_firewall._find(501)["addresses"].append("203.0.113.9")
    res = apply(t, spec, prepared=p)
    assert res["status"] == "plan_changed" and not t.writes


def test_the_atp_allowlist_conflict_guard_reads_right_before_the_write():
    """ASVS V11.1.3 · CWE-362: an allowlist entry added by someone else after the preview is a conflict, not a duplicate write."""
    t = Tenant()
    spec = {"type": "list_fix", "fixes": [{"area": "atp", "purpose": "allow", "destinations": [{"value": "vendor.example", "rows": [1]}]}]}
    p = plan(t, spec)
    seen = []

    def race(kind, _):
        # After the preview: the re-plan reads first (and agrees), then the handler.
        if kind == "allowlist":
            seen.append(1)
            if len(seen) == 2:
                t.zia.security_policy_settings.allow.append("vendor.example")
    t.before_get = race
    res = apply(t, spec, prepared=p)
    assert len(seen) >= 2 and [u["status"] for u in res["items"]] == ["conflict"]
    assert not writes(t, "replace_whitelist")


# ---------------------------------------------------------------------------
# Undo restores exactly
# ---------------------------------------------------------------------------

def test_undo_restores_the_tenant_exactly_for_mixed_fixes():
    """ASVS V7.2.1 · CWE-1188 · CWE-459: a fix touching new and existing groups, an existing rule, a new rule and both ATP lists is undone to the exact state before it, in dependency order."""
    t = Tenant()
    first = t.state()
    spec = {"type": "list_fix", "fixes": [
        {"area": "firewall", "purpose": "block", "destinations": [{"value": "203.0.113.9", "rows": [1]}, {"value": "bad2.example", "rows": [2]}],
         "ip_group": {"id": 501}, "fqdn_group": {"new": "Fix hosts"}, "rule": {"id": 31}, "services": [41]},
        {"area": "dns", "purpose": "block", "destinations": [{"value": "tunnel.example", "rows": [3]}], "fqdn_group": {"new": "Fix DNS"},
         "rule": {"new": {"name": "Fix: DNS"}}},
        {"area": "atp", "purpose": "block", "destinations": [{"value": "phish.example", "rows": [4]}]},
        {"area": "atp", "purpose": "allow", "destinations": [{"value": "vendor.example", "rows": [5]}]}]}
    res = apply(t, spec)
    assert res["status"] == "applied", res
    assert t.state() != first
    back = undo(t, res)
    assert back["status"] == "applied", back
    after = t.state()
    for r in after["fw"] + after["dns"]:   # the fake turns refs into [{"id": n}]; compare ids only
        for f in ("dest_ip_groups", "nw_services"):
            if f in r:
                r[f] = [x["id"] if isinstance(x, dict) else x for x in r[f]]
    want = copy.deepcopy(first)
    for r in want["fw"] + want["dns"]:
        for f in ("dest_ip_groups", "nw_services"):
            if f in r:
                r[f] = [x["id"] if isinstance(x, dict) else x for x in r[f]]
    assert after["groups"] == want["groups"] and after["allow"] == want["allow"] and after["deny"] == want["deny"]
    assert [r["id"] for r in after["fw"]] == [r["id"] for r in want["fw"]] and [r["id"] for r in after["dns"]] == [r["id"] for r in want["dns"]]
    assert {r["id"]: r.get("dest_ip_groups") for r in after["fw"]} == {r["id"]: r.get("dest_ip_groups") for r in want["fw"]}
    assert {r["id"]: r.get("nw_services") for r in after["fw"] if r["id"] == 31} == {31: []}
    deletes = [w[1] for w in t.writes if w[1].startswith("delete")]
    assert deletes.index("delete_rule") < max(i for i, w in enumerate(deletes) if w == "delete_ip_destination_group")


def test_undo_keeps_a_created_group_someone_changed():
    """ASVS V11.1.3 · CWE-367: the Undo deletes a group it created only while it still holds what was created."""
    t = Tenant()
    res = apply(t, fw(["203.0.113.9"], ip_group={"new": "Fix mine"}))
    gid = next(c["id"] for c in res["created"] if c["type"] == "ip_group")
    t.zia.cloud_firewall._find(gid)["addresses"].append("192.0.2.1")
    p = plan(t, res["inverse"])
    assert [u["status"] for u in p["items"] if u["kind"] == "delete_group"] == ["excluded"]


def test_an_undo_spec_is_refused_unless_applied_as_an_undo():
    """ASVS V4.1.3 · CWE-639 · CWE-863: the revert form deletes by id, so it is only ever applied as the Undo of a recorded operation."""
    assert ao.is_undo_only({"type": "list_fix", "action": "revert", "steps": []})


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec", [fw(["203.0.113.9"], ip_group={"id": 501}),
                                  {"type": "list_fix", "fixes": [{"area": "atp", "purpose": "block", "destinations": [{"value": "x.example"}]}]},
                                  {"type": "list_fix", "action": "revert", "steps": [{"op": "delete_group", "area": "dns", "id": 1, "name": "x"}]}])
def test_a_fix_outside_the_scope_page_is_refused_before_any_read(spec):
    """ASVS V4.1.3 · CWE-272 · CWE-863: a fix (or its Undo) naming an area that is not ticked on the Scope page is refused before anything is read."""
    t = Tenant()
    with pytest.raises(ao.OperationError, match="in scope"):
        plan(t, spec, scope=DLP_ONLY)
    assert not t.reads and not t.writes


def test_the_scope_check_names_each_area():
    """ASVS V4.1.3 · CWE-272: with ZIA platform ticked every area is in scope; without it none is, and the reason says what to tick."""
    assert lf.areas_in_scope(PLATFORM)[0] == ["firewall", "dns", "atp"]
    read, why = lf.areas_in_scope(DLP_ONLY)
    assert read == [] and "ZIA platform" in why["atp"]
    assert lf._in_scope(DLP_ONLY) and lf._in_scope(PLATFORM) is None


# ---------------------------------------------------------------------------
# The preview explains each change and links back to the rows
# ---------------------------------------------------------------------------

def test_the_preview_explains_each_write_and_names_its_rows():
    """ASVS V1.4.1 · CWE-1059: every write has a plain sentence and the row numbers it fixes; a rule below the deciding rule is called out."""
    t = Tenant()
    p = plan(t, {"type": "list_fix", "fixes": [{"area": "firewall", "purpose": "block", "decided_by": ["Allow all outbound"],
                                                "destinations": [{"value": "203.0.113.9", "rows": [4, 9]}],
                                                "ip_group": {"new": "Fix IPs"}, "rule": {"new": {"name": "Fix rule"}}}]})
    ex = p["explanations"]
    assert ex and all(e["text"] and e["rows"] == [4, 9] for e in ex)
    assert any("disabled" in e["text"] and "Fix rule" in e["text"] for e in ex)
    assert any("below 'Allow all outbound'" in w for w in p["warnings"])
    assert all(u["rows"] == [4, 9] for u in p["items"])


def test_a_new_rule_created_enabled_needs_the_typed_phrase():
    """ASVS V11.1.1 · CWE-1188 · CWE-841: a rule created enabled (only when asked) acts at activation, so the typed phrase is asked whatever the count."""
    t = Tenant()
    p = plan(t, fw(["203.0.113.9"], ip_group={"new": "Fix IPs"}, rule={"new": {"name": "Fix on", "enabled": True}}))
    assert p["confirm_phrase"] == "APPLY 3 CHANGES" and any("ENABLED" in w for w in p["warnings"])
    res = ao.execute(t, p["spec"], plan_hash=p["plan_hash"], scope=PLATFORM, writes_enabled=True, assessor="Jane Doe", confirm_text="",
                     tenant_label="acme (zscalertwo)")
    assert res["status"] == "refused" and not t.writes


@pytest.mark.parametrize("bad, why", [({"area": "moon"}, "Unknown area"), ({"purpose": "maybe"}, "purpose"),
                                      ({"rule": {"new": {"name": "x" * 32}}}, "31"), ({"services": [41]}, "need a rule"),
                                      ({"ip_group": {"id": "../1"}}, "number"), ({"destinations": []}, "no destination")])
def test_a_malformed_fix_is_refused_in_words(bad, why):
    """ASVS V5.1.3 · CWE-20: an unknown area or purpose, a rule name over 31 characters, services without a rule, a non-numeric id or no destination is a 400 in words."""
    spec = fw(["203.0.113.9"], ip_group={"id": 501})
    spec["fixes"][0].update(bad)
    with pytest.raises(ao.OperationError, match=why):
        lf.normalize(spec)


def test_the_picker_reads_only_what_is_in_scope():
    """ASVS V4.1.3 · CWE-272: the object picker lists groups, rules, services and list sizes, read-only."""
    t = Tenant()
    out = ao.read_objects(t, lf.FAMILY, PLATFORM)
    assert [g["id"] for g in out["ip_groups"]] == [501, 502, 504, 503] or {g["id"] for g in out["ip_groups"]} == {501, 502, 503, 504}
    assert [r["id"] for r in out["firewall_rules"]] == [31, 32, 39] and out["atp_lists"]["denylist"]["count"] == 1
    assert not t.writes


# ---------------------------------------------------------------------------
# The hand-off from Test a list, mixed rows, and Prove it
# ---------------------------------------------------------------------------

class ListTenant:
    """Test a list's tenant: nothing in scope but the lookup (no module read), so each row's area comes from the recommendation."""


def _row(**kw):
    base = {"row": 1, "target": "x", "is_ip": False, "expected": "BLOCK", "result": "allowed", "rule": "", "area": "", "meets": "no",
            "recommended_area": "URL", "recommendation": "r"}
    base.update(kw)
    return base


def test_a_hand_off_sorts_mixed_rows_into_the_operations_that_fix_them(monkeypatch):
    """ASVS V4.1.1 · CWE-841 · A01:2021: rows needing URL, Cloud Firewall, DNS, ATP and ZPA fixes go to the URL change, the list fix per area and purpose, or are excluded with the reason; nothing is sent."""
    rn = bt.Run(bt.parse("destination,expected\na.example,block\n203.0.113.9,block\nt.example,block\nphish.example,allow\nseg.corp,block\nok.example,block\n"))
    rows = {1: _row(row=1, target="a.example", recommended_area="URL"),
            2: _row(row=2, target="203.0.113.9", is_ip=True, recommended_area="Firewall", rule="Allow all outbound", area="Firewall"),
            3: _row(row=3, target="t.example", recommended_area="DNS"),
            4: _row(row=4, target="phish.example", expected="ALLOW", result="blocked", recommended_area="ATP"),
            5: _row(row=5, target="seg.corp", recommended_area="ZPA"),
            6: _row(row=6, target="ok.example", result="blocked", meets="yes", recommended_area="")}
    monkeypatch.setattr(bt.Run, "row", lambda self, i: dict(rows[i + 1]))
    rec = bt.fix_handoff(rn, rows=[1, 2, 3, 4, 5, 6], purpose="block")
    assert rec["urls"] == ["a.example"]
    assert [(f["area"], f["purpose"], [d["value"] for d in f["destinations"]]) for f in rec["fixes"]] == [
        ("firewall", "block", ["203.0.113.9"]), ("dns", "block", ["t.example"]), ("atp", "allow", ["phish.example"])]
    assert rec["fixes"][0]["decided_by"] == ["Allow all outbound"] and rec["fixes"][0]["destinations"][0]["rows"] == [2]
    why = {e["row"]: e["why"] for e in rec["excluded"]}
    assert "ZPA" in why[5] and "as expected" in why[6]
    assert rec["retest_rows"] == [1, 2, 3, 4] and rec["retest_text"].splitlines()[0].startswith("destination,port")


def test_a_hand_off_leaves_out_what_is_not_in_scope(monkeypatch):
    """ASVS V4.1.3 · CWE-272: a part of the hand-off that is out of scope is left out with the Scope page's reason; with nothing left it is refused."""
    rn = bt.Run(bt.parse("destination,expected\n203.0.113.9,block\n"))
    monkeypatch.setattr(bt.Run, "row", lambda self, i: _row(row=1, target="203.0.113.9", is_ip=True, recommended_area="Firewall"))
    with pytest.raises(bt.ListError, match="ZIA platform"):
        bt.fix_handoff(rn, rows=[1], in_scope={"firewall": "Not in scope: tick ZIA platform"})


def test_prove_it_compares_each_row_before_and_after(monkeypatch):
    """ASVS V1.4.1 · CWE-1059: Prove it tests the handed-off rows again and says, per row, whether it now does what was expected."""
    rn = bt.Run(bt.parse("destination,expected\n203.0.113.9,block\nt.example,block\n"))
    first = {1: _row(row=1, target="203.0.113.9", is_ip=True, recommended_area="Firewall"), 2: _row(row=2, target="t.example", recommended_area="DNS")}
    monkeypatch.setattr(bt.Run, "row", lambda self, i: dict(first[i + 1]))
    rec = bt.fix_handoff(rn, rows=[1, 2])
    again = bt.Run(bt.parse(rec["retest_text"]))
    now = {1: _row(row=1, target="203.0.113.9", result="blocked", meets="yes", rule="Fix: block"), 2: _row(row=2, target="t.example")}
    monkeypatch.setattr(bt.Run, "row", lambda self, i: dict(now[i + 1]))
    proof = bt.prove(again, rec)
    assert proof["counts"] == {"fixed": 1, "still": 1, "not_tested": 0}
    assert [(r["row"], r["before"], r["now"], r["state"]) for r in proof["rows"]] == [(1, "allowed", "blocked", "fixed"), (2, "allowed", "allowed", "still")]


# ---------------------------------------------------------------------------
# The standalone operations (usable without Test a list)
# ---------------------------------------------------------------------------

def test_a_standalone_group_change_adds_and_removes_on_one_group_and_undoes_exactly():
    """ASVS V5.1.3 · ASVS V7.2.1 · CWE-20: ip_group_edit adds and removes entries on an existing group through the same engine; its Undo restores the group exactly."""
    t = Tenant()
    first = t.state()
    spec = {"type": "ip_group_edit", "group": {"id": 501}, "add": ["203.0.113.9", "203.0.113.10"], "remove": ["198.51.100.0/24"]}
    p = plan(t, spec)
    assert p["type"] == "ip_group_edit" and p["counts"]["change"] == 3 and "Bad IPs" in p["title"]
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied", res
    assert t.zia.cloud_firewall._find(501)["addresses"] == ["203.0.113.9", "203.0.113.10"]
    back = undo(t, res)
    assert back["status"] == "applied", back
    assert sorted(t.state()["groups"][0]["addresses"]) == sorted(first["groups"][0]["addresses"])


def test_a_standalone_new_group_takes_only_its_kind_of_entry():
    """ASVS V5.1.3 · CWE-20: a new DSTN_FQDN group takes host names; an address listed with them is excluded with the reason."""
    t = Tenant()
    p = plan(t, {"type": "ip_group_edit", "group": {"new": "Partner hosts", "group_type": "DSTN_FQDN"}, "add": "a.example\n203.0.113.9"})
    st = {u["value"]: u["status"] for u in p["items"]}
    assert st["a.example"] == "change" and st["203.0.113.9"] == "excluded" and st["Partner hosts"] == "change"


def test_a_standalone_atp_list_change_writes_through_the_security_list_methods():
    """ASVS V5.1.3 · CWE-20: atp_list_edit adds to and removes from the denylist with the incremental SDK calls and asks for the typed phrase."""
    t = Tenant()
    spec = {"type": "atp_list_edit", "list": "denylist", "add": ["phish.example"], "remove": ["drop.example"]}
    p = plan(t, spec)
    assert p["type"] == "atp_list_edit" and p["confirm_phrase"] == "APPLY 2 CHANGES"
    res = apply(t, spec, prepared=p)
    assert res["status"] == "applied", res
    assert writes(t, "add_urls_to_blacklist") == [("security", "add_urls_to_blacklist", ["phish.example"])]
    assert writes(t, "delete_urls_from_blacklist") == [("security", "delete_urls_from_blacklist", ["drop.example"])]
    assert t.zia.security_policy_settings.deny == ["phish.example"]


@pytest.mark.parametrize("spec", [{"type": "ip_group_edit", "group": {"id": 501}, "add": ["203.0.113.9"]},
                                  {"type": "atp_list_edit", "list": "allowlist", "add": ["x.example"]}])
def test_the_standalone_operations_are_refused_out_of_scope(spec):
    """ASVS V4.1.3 · CWE-272: the standalone group and list changes are refused before any read when ZIA platform is not ticked."""
    t = Tenant()
    with pytest.raises(ao.OperationError, match="in scope"):
        plan(t, spec, scope=DLP_ONLY)
    assert not t.reads


# ---------------------------------------------------------------------------
# End to end on the sample tenant, through the real SDK 1.11.3 services
# (offline: the SDK's own service and model classes over an in-memory table)
# ---------------------------------------------------------------------------

def _sample():
    import offline_tenant as ot
    import sample_tenant
    st = ot.OfflineStore("sample", ot.SAMPLE, {p: {"status": 200, "body": b} for p, b in sample_tenant.responses().items()},
                         {"tenant_label": "Sample"}, writable=True)
    return st, ot.OfflineSdkClient(st, ot.creds_for(st))


def _body(st, path):
    import copy as _c
    return _c.deepcopy(st.responses[f"/zia/api/v1{path}"]["body"])


def test_on_the_sample_tenant_the_sdk_sends_the_wire_fields_and_undo_restores_them():
    """ASVS V5.1.3 · ASVS V7.2.1 · CWE-20: through the SDK's own services the group, rule and list writes reach the API as ipDestinationGroups addresses, destIpGroups ids, a DISABLED rule and blacklistUrls; the Undo puts every list back as it was."""
    st, client = _sample()
    before = {p: _body(st, p) for p in ("/ipDestinationGroups", "/firewallFilteringRules", "/firewallDnsRules", "/security/advanced", "/security")}
    spec = {"type": "list_fix", "fixes": [
        {"area": "firewall", "purpose": "block", "destinations": [{"value": "203.0.113.9", "rows": [1]}], "ip_group": {"new": "Fix sample IPs"},
         "rule": {"new": {"name": "Fix sample block", "above": 802}}, "decided_by": ["Allow office traffic"]},
        {"area": "dns", "purpose": "block", "destinations": [{"value": "tunnel.example", "rows": [2]}], "fqdn_group": {"new": "Fix sample DNS"},
         "rule": {"id": 811}},
        {"area": "atp", "purpose": "block", "destinations": [{"value": "phish.example", "rows": [3]}]},
        {"area": "atp", "purpose": "allow", "destinations": [{"value": "vendor.example", "rows": [4]}]}]}
    res = apply(client, spec)
    assert res["status"] == "applied" and res["verification"]["mismatched"] == [], res
    groups = _body(st, "/ipDestinationGroups")
    ip = next(g for g in groups if g["name"] == "Fix sample IPs")
    assert ip["type"] == "DSTN_IP" and ip["addresses"] == ["203.0.113.9"]
    rule = next(r for r in _body(st, "/firewallFilteringRules") if r["name"] == "Fix sample block")
    assert rule["state"] == "DISABLED" and rule["action"] == "BLOCK_DROP" and rule["destIpGroups"] == [{"id": ip["id"]}] and rule["order"] == 2
    fq = next(g for g in groups if g["name"] == "Fix sample DNS")
    dns = next(r for r in _body(st, "/firewallDnsRules") if r["id"] == 811)
    assert dns["destIpGroups"] == [{"id": fq["id"]}] and dns["applications"] == ["DNS_TUNNELS"] and dns["action"] == "BLOCK"
    assert "phish.example" in _body(st, "/security/advanced")["blacklistUrls"] and "vendor.example" in _body(st, "/security")["whitelistUrls"]
    back = undo(client, res)
    assert back["status"] == "applied", back
    assert _body(st, "/ipDestinationGroups") == before["/ipDestinationGroups"]
    assert _body(st, "/security/advanced") == before["/security/advanced"] and _body(st, "/security") == before["/security"]
    assert [r["id"] for r in _body(st, "/firewallFilteringRules")] == [r["id"] for r in before["/firewallFilteringRules"]]
    assert not next(r for r in _body(st, "/firewallDnsRules") if r["id"] == 811).get("destIpGroups")


# ---------------------------------------------------------------------------
# The routes: the hand-off's scope check and Prove it
# ---------------------------------------------------------------------------

def _follow(t, job):
    import time
    deadline = time.time() + 30
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_the_route_hands_off_mixed_rows_and_prove_it_tests_them_again(monkeypatch):
    """ASVS V4.1.3 · ASVS V1.4.1 · CWE-841: Fix selected over the route returns the URL and the list-fix parts; Prove it re-runs exactly those rows read-only and compares them, writing nothing."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    from test_bulk_test import CREDS, Tenant as ListTenant
    c = ListTenant()
    monkeypatch.setattr(srv, "_build_client", lambda req: c)
    t = TestClient(srv.app)
    text = "destination,expected\nnews.example,block\n203.0.113.9,block\n"
    snap = _follow(t, t.post("/api/bulk-test/start", json=dict(CREDS, text=text)).json()["job_id"])
    rid = snap["result"]["run_id"]
    fix = t.post(f"/api/bulk-test/{rid}/fix", json=dict(CREDS, rows=[1, 2], purpose="block"))
    assert fix.status_code == 200, fix.text
    d = fix.json()
    assert d["urls"] == 1 and [(f["area"], f["destinations"]) for f in d["fixes"]] == [("firewall", 1)] and d["rows"] == 2
    got = t.get(f"/api/bulk-test/fix/{d['fix_id']}").json()
    assert [r["row"] for r in got["rows"]] == [1, 2] and got["fixes"][0]["destinations"][0]["value"] == "203.0.113.9"
    assert "retest_text" not in got
    proof = _follow(t, t.post(f"/api/bulk-test/fix/{d['fix_id']}/prove/start", json=CREDS).json()["job_id"])
    pr = proof["result"]["proof"]
    assert pr["total"] == 2 and [r["row"] for r in pr["rows"]] == [1, 2] and set(pr["counts"]) == {"fixed", "still", "not_tested"}
    assert not c.writes


def test_the_route_refuses_a_hand_off_when_nothing_it_changes_is_in_scope():
    """ASVS V4.1.3 · CWE-272: Fix selected is a 400 before anything else when neither URL categories nor ZIA platform is in scope."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    from test_bulk_test import CREDS
    base = {k: v for k, v in CREDS.items() if k not in ("scopes", "channels")}
    r = TestClient(srv.app).post("/api/bulk-test/anything/fix", json=dict(base, scopes=["zpa"], channels={}, from_page=True, rows=[1]))
    assert r.status_code == 400 and "ZIA platform" in r.json()["detail"] and "URL" in r.json()["detail"]


def test_prove_it_needs_a_kept_hand_off():
    """ASVS V4.2.1 · CWE-639: Prove it for a hand-off that is not kept (or a guessed id) is a 404 and reads nothing."""
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    from test_bulk_test import CREDS
    r = TestClient(srv.app).post("/api/bulk-test/fix/" + "0" * 24 + "/prove/start", json=CREDS)
    assert r.status_code == 404
