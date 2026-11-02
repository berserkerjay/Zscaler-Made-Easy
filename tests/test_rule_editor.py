"""The rule editor (rule_editor, ops_rule_editor) and the objects around it
(ops_zia_objects) on the Bulk changes engine, and DNS Control and IPS in
Enable or disable rules. Fakes only: a recording tenant with the SDK's
service and method names; no network, no clock, no real tenant."""
from __future__ import annotations

import copy
import importlib
import json

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import admin_rank
import ops_rule_editor as re_ops
import ops_zia_objects as zo
import pack_channels as pc
import pack_ops as ops
import rule_editor as R

ao.load_plugins()


# ---------------------------------------------------------------------------
# The fake tenant
# ---------------------------------------------------------------------------

class Rules:
    """One rule service: list_rules / get_rule / add_rule / update_rule / delete_rule."""

    def __init__(self, t, name, rows=()):
        self.t, self.name, self.rows, self.next_id = t, name, [copy.deepcopy(r) for r in rows], 900
        self.tamper = None      # a change someone else makes right before the next get_rule

    def _find(self, rid):
        return next((r for r in self.rows if str(r["id"]) == str(rid)), None)

    def list_rules(self, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return [copy.deepcopy(r) for r in self.rows], None, None

    def get_rule(self, rid, *a):
        self.t.reads.append(f"{self.name}.get_rule")
        r = self._find(rid)
        if r is not None and self.tamper:
            r.update(self.tamper)
            self.tamper = None
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add_rule(self, **kw):
        assert not self.t.frozen, "a preview must never write"
        self.t.writes.append((self.name, "add_rule", copy.deepcopy(kw)))
        self.next_id += 1
        row = dict(copy.deepcopy(kw), id=self.next_id)
        for r in self.rows:
            if not r.get("default_rule") and int(r.get("order") or 0) >= int(kw.get("order") or 0):
                r["order"] = int(r["order"]) + 1
        self.rows.append(row)
        return copy.deepcopy(row), None, None

    def update_rule(self, rid, **kw):
        assert not self.t.frozen, "a preview must never write"
        self.t.writes.append((self.name, "update_rule", copy.deepcopy(kw)))
        r = self._find(rid)
        r.clear()
        r.update(copy.deepcopy(kw), id=int(rid))
        return copy.deepcopy(r), None, None

    def delete_rule(self, rid, *a):
        assert not self.t.frozen, "a preview must never write"
        self.t.writes.append((self.name, "delete_rule", rid))
        gone = self._find(rid)
        self.rows = [r for r in self.rows if str(r["id"]) != str(rid)]
        for r in self.rows:
            if gone and not r.get("default_rule") and int(r.get("order") or 0) > int(gone.get("order") or 0):
                r["order"] = int(r["order"]) - 1
        return None, None, None


class Cac(Rules):
    def list_rules(self, rule_type=None, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return [copy.deepcopy(r) for r in self.rows if r.get("type") == rule_type], None, None

    def get_rule(self, rule_type, rid):
        return Rules.get_rule(self, rid)

    def add_rule(self, rule_type, **kw):
        return Rules.add_rule(self, **kw)

    def update_rule(self, rule_type, rid, **kw):
        return Rules.update_rule(self, rid, **kw)

    def delete_rule(self, rule_type, rid):
        return Rules.delete_rule(self, rid)


class Svc:
    """A service with list methods (name -> rows) and optional object writes."""

    def __init__(self, t, name, lists=None, *, obj=None, id_key="id"):
        self.t, self.name, self.lists, self.id_key, self.next_id = t, name, lists or {}, id_key, 700
        self.rows = [copy.deepcopy(r) for r in (obj or [])]
        for m in self.lists:
            setattr(self, m, self._lister(m))

    def _lister(self, m):
        def f(*a, **k):
            self.t.reads.append(f"{self.name}.{m}")
            rows = self.lists[m]
            return copy.deepcopy(rows if rows is not None else self.rows), None, None
        return f

    def _find(self, oid):
        return next((r for r in self.rows if str(r.get(self.id_key)) == str(oid)), None)

    def get(self, oid):
        self.t.reads.append(f"{self.name}.get")
        r = self._find(oid)
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add(self, **kw):
        assert not self.t.frozen
        self.t.writes.append((self.name, "add", copy.deepcopy(kw)))
        self.next_id += 1
        row = dict(copy.deepcopy(kw), **{self.id_key: self.next_id})
        self.rows.append(row)
        return copy.deepcopy(row), None, None

    def update(self, oid, **kw):
        assert not self.t.frozen
        self.t.writes.append((self.name, "update", copy.deepcopy(kw)))
        r = self._find(oid)
        r.clear()
        r.update(copy.deepcopy(kw), **{self.id_key: int(oid) if str(oid).isdigit() else oid})
        return copy.deepcopy(r), None, None

    def delete(self, oid):
        assert not self.t.frozen
        self.t.writes.append((self.name, "delete", oid))
        self.rows = [r for r in self.rows if str(r.get(self.id_key)) != str(oid)]
        return None, None, None


URL = [{"id": 101, "name": "Block gambling", "order": 1, "rank": 3, "state": "ENABLED", "action": "BLOCK", "url_categories": ["GAMBLING"],
        "protocols": ["ANY_RULE"], "groups": [{"id": 31, "name": "All Staff"}], "cbi_profile": {"id": "p1", "name": "Isolation"},
        "access_control": "READ_WRITE"},
       {"id": 102, "name": "Caution streaming", "order": 2, "rank": 5, "state": "DISABLED", "action": "CAUTION",
        "url_categories": ["STREAMING_MEDIA"], "protocols": ["ANY_RULE"], "access_control": "READ_WRITE"},
       {"id": 199, "name": "Default URL Filtering Rule", "order": 127, "rank": 7, "default_rule": True, "action": "ALLOW", "state": "ENABLED"}]
FW = [{"id": 201, "name": "Allow web", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW", "nw_services": [{"id": 41, "name": "HTTPS"}]},
      {"id": 299, "name": "Default Firewall Filtering Rule", "order": -1, "default_rule": True, "action": "ALLOW"}]
DNS = [{"id": 811, "name": "Block DNS tunnels", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK", "dest_ip_categories": ["GAMBLING"]}]
IPS = [{"id": 821, "name": "IPS watch", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW", "dest_countries": ["COUNTRY_US"]},
       {"id": 829, "name": "Default IPS rule", "order": -1, "default_rule": True, "action": "ALLOW", "state": "ENABLED"}]
SEGMENTS = [{"id": "2201", "name": "Freight billing", "enabled": True, "bypass_type": "NEVER", "health_reporting": "ON_ACCESS",
             "domain_names": ["billing.larkspur.example"], "tcp_port_ranges": ["443", "443"], "segment_group_id": "9",
             "server_groups": [{"id": "77"}], "icmp_access_type": "NONE"}]


class Tenant:
    def __init__(self, *, rank_on=False, settings_error=False):
        self.reads, self.writes, self.frozen = [], [], False
        z = type("Zia", (), {})()
        z.url_filtering = Rules(self, "url_filtering", URL)
        z.cloud_firewall_rules = Rules(self, "cloud_firewall_rules", FW)
        z.ssl_inspection_rules = Rules(self, "ssl_inspection_rules", [])
        z.forwarding_control = Rules(self, "forwarding_control", [])
        z.dlp_web_rules = Rules(self, "dlp_web_rules", [])
        z.cloud_firewall_dns = Rules(self, "cloud_firewall_dns", DNS)
        z.cloud_firewall_ips = Rules(self, "cloud_firewall_ips", IPS)
        z.file_type_control_rule = Rules(self, "file_type_control_rule", [])
        z.sandbox_rules = Rules(self, "sandbox_rules", [])
        z.cloudappcontrol = Cac(self, "cloudappcontrol", [])
        z.url_categories = Svc(self, "url_categories", {"list_categories_lite": [
            {"id": "GAMBLING", "configured_name": "Gambling"}, {"id": "STREAMING_MEDIA"}, {"id": "CUSTOM_01", "configured_name": "Partners"}]})
        z.user_management = Svc(self, "user_management", {"list_groups": [{"id": 31, "name": "All Staff"}, {"id": 32, "name": "Finance"}],
                                                          "list_departments": [{"id": 21, "name": "Ops"}], "list_users": [{"id": 11, "name": "Avery"}]})
        z.locations = Svc(self, "locations", {"list_locations_lite": [{"id": 5, "name": "HQ"}], "list_location_groups_lite": []})
        z.rule_labels = Svc(self, "rule_labels", {"list_labels": [{"id": 61, "name": "Reviewed"}]})
        z.cloud_firewall = Svc(self, "cloud_firewall", {"list_time_windows_lite": [], "list_ip_source_groups_lite": [],
                                                        "list_ip_destination_groups_lite": [], "list_network_services_lite": [{"id": 41, "name": "HTTPS"}],
                                                        "list_network_svc_groups_lite": [], "list_network_apps": []})
        z.dlp_engine = Svc(self, "dlp_engine", {"list_dlp_engines": [{"id": 1, "name": "PCI", "engine_expression": "((D63.S > 1))"}]})
        z.dlp_dictionary = Svc(self, "dlp_dictionary", {"list_dicts_lite": [{"id": 63, "name": "Credit Cards"}]})
        z.zpa_gateway = Svc(self, "zpa_gateway", {"list_gateways": []})
        z.dns_gatways = Svc(self, "dns_gatways", {"list_dns_gateways": []})
        z.cloud_applications = Svc(self, "cloud_applications", {"list_cloud_app_policy": [{"app": "DROPBOX", "app_name": "Dropbox"}]})
        if settings_error:
            z.advanced_settings = Svc(self, "advanced_settings")
            z.advanced_settings.get_advanced_settings = lambda: (None, None, {"message": "boom", "status": 500})
        else:
            z.advanced_settings = Svc(self, "advanced_settings")
            z.advanced_settings.get_advanced_settings = lambda: (self.reads.append("advanced_settings") or
                                                                 ({"enable_admin_rank_access": rank_on}, None, None))
        # Objects: proxies and gateways, cloud app instances, tenancy restriction profiles
        px = Svc(self, "proxies", {"list_proxies": None, "list_proxy_gateway_lite": [{"id": 861, "name": "GW"}],
                                   "list_proxy_gateways": [{"id": 861, "name": "GW", "primary_proxy": {"id": 851}, "fail_closed": True}]},
                 obj=[{"id": 851, "name": "Egress", "type": "PROXYCHAIN", "address": "proxy.example.com", "port": 8080}])
        px.get_proxy, px.add_proxy, px.update_proxy, px.delete_proxy = px.get, px.add, px.update, px.delete
        z.proxies = px
        inst = Svc(self, "cloud_app_instances", {"list_cloud_app_instances": None}, id_key="instance_id",
                   obj=[{"instance_id": 871, "instance_name": "Larkspur SharePoint", "instance_type": "SHAREPOINTONLINE",
                         "instance_identifiers": [{"instance_identifier": "lark.sharepoint.com", "identifier_type": "URL"}]}])
        inst.get_cloud_app_instances, inst.add_cloud_app_instances = inst.get, inst.add
        inst.update_cloud_app_instances, inst.delete_cloud_app_instances = inst.update, inst.delete
        z.cloud_app_instances = inst
        tr = Svc(self, "tenancy_restriction_profile", {"list_restriction_profile": None})
        tr.get_restriction_profile, tr.add_restriction_profile = tr.get, tr.add
        tr.update_restriction_profile, tr.delete_restriction_profile = tr.update, tr.delete
        z.tenancy_restriction_profile = tr
        self.zia = z
        zp = type("Zpa", (), {})()
        seg = Svc(self, "application_segment", {"list_segments": None}, obj=SEGMENTS)
        seg.get_segment = seg.get
        seg.update_segment = seg.update
        zp.application_segment = seg
        self.zpa = zp

    def rows(self, svc):
        return getattr(self.zia, svc).rows


FULL = ao.scope_for(["dlp", "zia_extras", "zpa"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
DLP_ONLY = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
PLATFORM_ONLY = ao.scope_for(["zia_extras"], {})


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def plan(t, spec, scope=FULL):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme (zscalertwo)")
    finally:
        t.frozen = False


def apply(t, spec, scope=FULL, prepared=None, confirm=None):
    prepared = prepared or plan(t, spec, scope)
    return ao.execute(t, spec, plan_hash=prepared["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=prepared["confirm_phrase"] if confirm is None else confirm, tenant_label="acme (zscalertwo)")


def undo(t, result, scope=FULL):
    inv = result["inverse"]
    assert inv and (ao.is_undo_only(inv) or inv["type"] == "rule_state")
    return apply(t, inv, scope)


def create(policy="url_filtering", **kw):
    fields = kw.pop("fields", None) or {"name": "Block partners", "action": "BLOCK", "url_categories": ["CUSTOM_01"], "groups": ["32"]}
    return dict({"type": "rule_edit", "action": "create", "policy": policy, "fields": fields}, **kw)


# ---------------------------------------------------------------------------
# The forms against the SDK models (the payload oracle)
# ---------------------------------------------------------------------------

MODELS = {"url_filtering": ("url_filtering_rules", "URLFilteringRule"), "firewall": ("cloud_firewall_rules", "FirewallRule"),
          "ssl_inspection": ("ssl_inspection_rules", "SSLInspectionRules"),
          "forwarding": ("forwarding_control_policy", "ForwardingControlRule"), "web_dlp": ("dlp_web_rules", "DLPWebRules"),
          "dns_control": ("cloud_firewall_dns_rules", "FirewallDNSRules"), "firewall_ips": ("cloud_firewall_ips_rules", "FirewallIPSrules"),
          "file_type_control": ("filetyperules", "FileTypeControlRules"), "sandbox": ("sandboxrules", "SandboxRules"),
          "cloud_app_control": ("cloudappcontrol", "CloudApplicationControl")}
SAMPLE = {"text": "Rule 1", "longtext": "Why", "refs": ["11"], "ref": "12", "names": ["FINANCE"], "enums_free": ["FTCATEGORY_ZIP"],
          "addrs": ["10.0.0.0/8"], "countries": ["COUNTRY_US"], "bool": True, "int": 5, "ssl_action": "DECRYPT",
          "cac_actions": ["BLOCK_FILE_SHARE_UPLOAD"]}


def _full_values(policy):
    vals = {}
    for k, f in R.fields_of(policy).items():
        v = f["values"][0] if f["kind"] in ("enum", "ssl_action") and f.get("values") else SAMPLE.get(f["kind"])
        if f["kind"] == "enums":
            v = [f["values"][0]]
        vals[k] = v
    return R.validate(policy, vals)


@pytest.mark.parametrize("policy", R.ORDER)
def test_every_form_field_is_a_field_of_the_sdk_model(policy):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a payload with every form field of the rule type, built into the SDK 1.11.3 model, keeps each field: the form offers only fields the model has."""
    # Arrange
    from zscaler.helpers import convert_keys_to_camel_case
    mod, cls = MODELS[policy]
    model = getattr(importlib.import_module(f"zscaler.zia.models.{mod}"), cls)
    body = R.payload(policy, _full_values(policy), state="DISABLED", order=1, rank=7, rule_type="WEBMAIL")
    # Act
    built = model(convert_keys_to_camel_case(copy.deepcopy(body)))
    # Assert
    missing = [k for k in body if getattr(built, k, None) in (None, [], "")]
    assert not missing, f"{policy}: the SDK model drops {missing}"
    assert body["state"] == "DISABLED" and body["order"] == 1 and body["rank"] == 7


@pytest.mark.parametrize("policy", R.ORDER)
def test_references_go_out_as_id_objects_the_sdk_keeps(policy):
    """ASVS V5.1.3 · CWE-20: every reference field is sent as [{"id": n}] (one as {"id": n}), so the SDK's id transform leaves it as the API takes it."""
    # Arrange
    from zscaler.utils import reformat_params, transform_common_id_fields
    body = R.payload(policy, _full_values(policy), state="DISABLED")
    sent = copy.deepcopy(body)
    # Act
    transform_common_id_fields(reformat_params, sent, sent)
    # Assert
    for k, f in R.fields_of(policy).items():
        if f["kind"] == "refs":
            assert body[k] == [{"id": 11}], (policy, k)
        if f["kind"] == "ref":
            assert body[k] == {"id": 12}, (policy, k)
    assert not [k for k in body if k not in sent and k not in {p for p, _ in reformat_params}], "no field is dropped by the SDK"


def test_ssl_action_type_becomes_the_full_action_and_keeps_sub_actions_when_unchanged():
    """ASVS V5.1.3 · CWE-20: an SSL inspection action is sent as ZIA's action object; an edit that keeps the type keeps the tenant's sub-actions."""
    # Arrange
    old = {"type": "DECRYPT", "decrypt_sub_actions": {"min_client_tls_version": "CLIENT_TLS_1_3"}}
    # Act
    new = R.wire("ssl_inspection", "action", "DECRYPT", old=old)
    changed = R.wire("ssl_inspection", "action", "DO_NOT_DECRYPT", old=old)
    # Assert
    assert new is old and changed["type"] == "DO_NOT_DECRYPT" and "do_not_decrypt_sub_actions" in changed
    assert R.ssl_action("DECRYPT")["decrypt_sub_actions"]["min_client_tls_version"] == "CLIENT_TLS_1_2"


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy,fields,words", [
    ("url_filtering", {"name": "x", "action": "BLOCK", "url_categories": ["GAMBLING"], "bogus": 1}, "no field bogus"),
    ("url_filtering", {"name": "x", "action": "NUKE", "url_categories": ["GAMBLING"]}, "not one of"),
    ("url_filtering", {"name": "x" * 32, "action": "BLOCK", "url_categories": ["GAMBLING"]}, "longer than 31"),
    ("url_filtering", {"name": "bad‮name", "action": "BLOCK", "url_categories": ["GAMBLING"]}, "control character"),
    ("url_filtering", {"name": "<b>x</b>", "action": "BLOCK", "url_categories": ["GAMBLING"]}, "control character or < >"),
    ("url_filtering", {"name": "x", "action": "BLOCK"}, "Fill in: URL categories"),
    ("url_filtering", {"name": "x", "action": "BLOCK", "url_categories": ["GAMBLING"], "groups": ["abc"]}, "is not an id"),
    ("url_filtering", {"name": "x", "action": "BLOCK", "url_categories": ["GAMBLING"], "protocols": ["GOPHER_RULE"]}, "not one of"),
    ("firewall", {"name": "x", "action": "ALLOW", "src_ips": ["example.com"]}, "is not an IP address"),
    ("firewall", {"name": "x", "action": "ALLOW", "dest_addresses": ["10.0.0.9-10.0.0.1"]}, "not a valid range"),
    ("firewall", {"name": "x", "action": "ALLOW", "dest_countries": ["USA"]}, "not a country code"),
    ("firewall", {"name": "x", "action": "ALLOW", "url_categories": ["GAMBLING"]}, "no field url_categories"),
    ("cloud_app_control", {"name": "x", "actions": ["DELETE_EVERYTHING"], "applications": ["DROPBOX"]}, "not a Cloud App Control action"),
    ("web_dlp", {"name": "x", "action": "ALLOW", "min_size": -1}, "between 0 and"),
    ("url_filtering", {"name": "x", "action": "BLOCK", "url_categories": ["GAMBLING"] * 1001}, "at most 1000"),
])
def test_the_form_refuses_what_the_rule_type_cannot_take(policy, fields, words):
    """ASVS V5.1.3 · V5.1.4 · CWE-20 · WSTG-INPV-01: unknown fields, values outside the SDK's enumerations, bad addresses, ids, oversized lists, over-long names and control characters are refused with the field named."""
    # Arrange / Act
    with pytest.raises(R.FormError) as e:
        R.validate(policy, fields)
    # Assert
    assert words in str(e.value)


def test_plan_refuses_an_invalid_rule_and_reads_nothing_more():
    """ASVS V5.1.3 · CWE-20: a whole-rule problem (proxy chaining without a gateway) is refused before anything is written, with the reason."""
    # Arrange
    t = Tenant()
    spec = create("forwarding", fields={"name": "Chain", "forward_method": "PROXYCHAIN"})
    # Act / Assert
    with pytest.raises(ao.OperationError, match="needs a proxy gateway"):
        plan(t, spec)
    assert t.writes == []


def test_addresses_are_normalized():
    """ASVS V5.1.3 · CWE-20: addresses are stored in one canonical form (CIDR network, lower-case host)."""
    # Arrange / Act / Assert
    assert R.norm_addr("10.1.2.3/8") == ("10.0.0.0/8", None)
    assert R.norm_addr("WWW.Example.COM") == ("www.example.com", None)
    assert R.norm_addr("*.example.com") == ("*.example.com", None)
    assert R.norm_addr("10.0.0.1 - 10.0.0.9")[0] is None
    assert R.norm_addr("example.com", ip_only=True)[0] is None


def test_a_name_the_tenant_does_not_have_for_a_reference_blocks_the_plan():
    """ASVS V5.1.3 · CWE-20 · CWE-639: a picked object that is not in the tenant (a stale or forged id) blocks the plan."""
    # Arrange
    t = Tenant()
    spec = create(fields={"name": "x", "action": "BLOCK", "url_categories": ["GAMBLING"], "groups": ["999"]})
    # Act
    p = plan(t, spec)
    # Assert
    assert p["status"] == "blocked" and any("not in the tenant now: 999" in b for b in p["blockers"])
    assert apply(t, spec)["status"] == "blocked" and t.writes == []


# ---------------------------------------------------------------------------
# Placement and rank
# ---------------------------------------------------------------------------

ON = {"state": admin_rank.ON}
OFF = {"state": admin_rank.OFF}
UNKNOWN = {"state": admin_rank.UNKNOWN, "why": "HTTP 500"}


def test_placement_takes_the_rank_of_the_rule_it_sits_above_when_admin_ranking_is_on():
    """ASVS V1.4.4 · CWE-840: with Admin Ranking on, a rule asked for at order N takes the rank of the rule now at N, so it really sits there."""
    # Arrange
    rows = [dict(r) for r in URL]
    # Act
    at2 = R.place(rows, {"at": "order", "order": 2}, ON)
    top = R.place(rows, {"at": "top"}, ON)
    last = R.place(rows, {"at": "bottom"}, ON)
    below = R.place(rows, {"at": "below", "id": 101}, ON)
    # Assert
    assert (at2["order"], at2["rank"], at2["anchor"]["name"]) == (2, 5, "Caution streaming")
    assert (top["order"], top["rank"]) == (1, 3)
    assert (last["order"], last["rank"], last["above_id"]) == (3, 5, None), "going last: the rank of the rule just above, above the Default rule"
    assert (below["order"], below["rank"]) == (2, 5)


@pytest.mark.parametrize("setting,why", [(OFF, "Admin Ranking is off"), (UNKNOWN, "could not be read"),
                                         ({"state": admin_rank.OUT_OF_SCOPE}, "not ticked")])
def test_placement_keeps_rank_7_when_admin_ranking_is_off_or_unknown(setting, why):
    """ASVS V1.4.4 · CWE-840: Admin Ranking off, unreadable or out of scope: rank 7 as before, and the preview says why."""
    # Arrange / Act
    p = R.place([dict(r) for r in URL], {"at": "top"}, setting)
    # Assert
    assert p["rank"] == 7 and why in p["why"]


def test_placement_is_clamped_and_warns_about_a_read_only_neighbour():
    """ASVS V1.4.4 · CWE-840: an order past the end goes last (above the Default rule); a read-only neighbour's rank is flagged."""
    # Arrange
    rows = [dict(URL[0], access_control="READ_ONLY"), dict(URL[1]), dict(URL[2])]
    # Act
    p = R.place(rows, {"at": "order", "order": 500}, ON)
    q = R.place(rows, {"at": "top"}, ON)
    # Assert
    assert p["order"] == 3
    assert any("read-only" in w for w in q["warnings"])
    with pytest.raises(R.FormError):
        R.place(rows, {"at": "order", "order": 0}, ON)
    with pytest.raises(R.FormError):
        R.place(rows, {"at": "below", "id": 4242}, ON)


def test_the_admin_ranking_setting_is_read_only_when_zia_platform_is_in_scope():
    """ASVS V1.4.4 · CWE-200: the scope rule: without ZIA platform ticked, the advanced settings are not read and rank 7 is used."""
    # Arrange
    t = Tenant(rank_on=True)
    # Act
    fields = {"name": "Block partners", "action": "BLOCK", "url_categories": ["CUSTOM_01"]}
    p = plan(t, create(place={"at": "top"}, fields=fields), DLP_ONLY)
    q = plan(t, create(place={"at": "top"}, fields=fields))
    # Assert
    assert p["groups"][0]["target"]["rank"] == 7 and "not ticked" in " ".join(p["summary"])
    assert q["groups"][0]["target"]["rank"] == 3
    assert t.reads.count("advanced_settings") == 1


# ---------------------------------------------------------------------------
# Create, read-back, Undo
# ---------------------------------------------------------------------------

def test_a_new_rule_is_created_disabled_where_the_preview_said_and_read_back():
    """ASVS V1.4.4 · V11.1.1 · CWE-841: the preview names what the rule does, its order and rank; the rule is created disabled at that place and read back."""
    # Arrange
    t = Tenant(rank_on=True)
    spec = create(place={"at": "order", "order": 2})
    # Act
    p = plan(t, spec)
    r = apply(t, spec, prepared=p)
    # Assert
    assert p["summary"][0].startswith("This rule will block the URL categories Partners for the groups Finance, placed at order 2, rank 5.")
    assert "created disabled" in p["summary"][0] and p["confirm_phrase"] == ""
    sent = t.zia.url_filtering.writes if hasattr(t.zia.url_filtering, "writes") else [w for w in t.writes if w[1] == "add_rule"]
    body = sent[0][2]
    assert body["state"] == "DISABLED" and body["order"] == 2 and body["rank"] == 5
    assert body["groups"] == [{"id": 32, "name": "Finance"}] and body["url_categories"] == ["CUSTOM_01"]
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1 and r["activation"]["activated"]
    assert [x["name"] for x in sorted(t.rows("url_filtering"), key=lambda x: x["order"])][:3] == ["Block gambling", "Block partners", "Caution streaming"]


def test_a_rule_created_enabled_needs_the_typed_phrase():
    """ASVS V2.8.x · V11.1.6 · CWE-306 · CWE-841: a rule that is live at once needs the typed phrase, whatever the count; without it nothing is written."""
    # Arrange
    t = Tenant()
    spec = create(enabled=True)
    # Act
    p = plan(t, spec)
    refused = apply(t, spec, prepared=p, confirm="")
    # Assert
    assert p["confirm_phrase"] == "APPLY 1 CHANGE" and refused["status"] == "refused" and t.writes == []
    assert apply(t, spec, prepared=p)["status"] == "applied"
    assert [w[2]["state"] for w in t.writes if w[1] == "add_rule"] == ["ENABLED"]


def test_undo_of_a_create_deletes_exactly_that_rule():
    """ASVS V11.1.1 · CWE-841: Undo is a previewed operation that deletes the rule created, and the policy is back as it was."""
    # Arrange
    t = Tenant()
    before = copy.deepcopy(t.rows("url_filtering"))
    r = apply(t, create(place={"at": "top"}))
    # Act
    u = undo(t, r)
    # Assert
    assert u["status"] == "applied" and u["verification"]["confirmed"] == 1
    assert t.rows("url_filtering") == before


def test_undo_of_a_create_leaves_a_rule_someone_changed_since():
    """ASVS V11.1.1 · CWE-362 · CWE-841: the Undo never deletes a created rule that someone changed after it was made."""
    # Arrange
    t = Tenant()
    r = apply(t, create())
    made = next(x for x in t.rows("url_filtering") if x["name"] == "Block partners")
    made["action"] = "ALLOW"
    # Act
    p = plan(t, r["inverse"])
    # Assert
    assert p["counts"]["change"] == 0 and p["items"][0]["status"] == "excluded" and "changed in the tenant" in p["items"][0]["reason"]


# ---------------------------------------------------------------------------
# Edit, conflict guard, Undo exactness
# ---------------------------------------------------------------------------

def test_an_edit_sends_back_the_whole_rule_with_only_the_changed_fields():
    """ASVS V1.4.4 · CWE-840: an update replaces the rule, so every field the form does not show (cbi_profile) is sent back as read and only the changed field differs."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "update", "policy": "url_filtering", "id": 101,
            "fields": dict(R.current("url_filtering", URL[0]), action="CAUTION")}
    # Act
    p = plan(t, spec)
    r = apply(t, spec, prepared=p)
    # Assert
    assert [(u["field"], u["before"], u["after"]) for u in p["items"]] == [("action", "BLOCK", "CAUTION")]
    assert p["confirm_phrase"] == "APPLY 1 CHANGE", "the rule is enabled: the edit is live at once"
    body = [w for w in t.writes if w[1] == "update_rule"][0][2]
    assert body["action"] == "CAUTION" and body["cbi_profile"] == URL[0]["cbi_profile"] and body["rank"] == 3 and body["order"] == 1
    assert body["state"] == "ENABLED" and r["status"] == "applied" and r["verification"]["confirmed"] == 1


def test_the_conflict_guard_never_overwrites_a_change_made_after_the_preview():
    """ASVS V11.1.6 · CWE-362 · CWE-367: the rule is read again right before the write; a field someone changed meanwhile is a conflict and nothing is written."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "update", "policy": "url_filtering", "id": 102, "fields": {"action": "BLOCK"}}
    p = plan(t, spec)
    t.zia.url_filtering.tamper = {"action": "ALLOW"}     # someone else, between the re-plan and the write
    # Act
    r = apply(t, spec, prepared=p)
    # Assert
    assert r["status"] != "applied" and r["items"][0]["status"] == "conflict"
    assert [w for w in t.writes if w[1] == "update_rule"] == []
    assert t.zia.url_filtering._find(102)["action"] == "ALLOW"


def test_a_tenant_change_after_the_preview_changes_the_plan_hash():
    """ASVS V11.1.6 · CWE-367: the plan is made again before writing; a different hash writes nothing."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "update", "policy": "url_filtering", "id": 102, "fields": {"action": "BLOCK"}}
    p = plan(t, spec)
    t.zia.url_filtering._find(102)["url_categories"] = ["GAMBLING"]
    # Act
    r = apply(t, spec, prepared=p)
    # Assert
    assert r["status"] == "plan_changed" and t.writes == []


def test_undo_of_an_edit_puts_the_rule_back_exactly():
    """ASVS V11.1.1 · CWE-841: after an edit of several fields and the state, Undo restores the rule to exactly what it was."""
    # Arrange
    t = Tenant()
    before = copy.deepcopy(t.zia.url_filtering._find(101))
    spec = {"type": "rule_edit", "action": "update", "policy": "url_filtering", "id": 101, "state": "DISABLED",
            "fields": {"action": "CAUTION", "groups": ["31", "32"], "description": "reviewed", "request_methods": ["GET"]}}
    r = apply(t, spec)
    assert r["status"] == "applied"
    # Act
    u = undo(t, r)
    # Assert
    assert u["status"] == "applied"
    after = t.zia.url_filtering._find(101)
    assert R.current("url_filtering", after) == R.current("url_filtering", before)
    assert after["state"] == "ENABLED" and after["cbi_profile"] == before["cbi_profile"] and after["rank"] == 3


def test_locked_rules_are_never_edited_duplicated_or_deleted():
    """ASVS V4.1.3 · CWE-284: the Default rule is excluded with the reason; nothing is written."""
    # Arrange
    t = Tenant()
    # Act
    e = plan(t, {"type": "rule_edit", "action": "update", "policy": "url_filtering", "id": 199, "fields": {"action": "BLOCK"}})
    d = plan(t, {"type": "rule_edit", "action": "delete", "policy": "url_filtering", "id": 199})
    c = plan(t, {"type": "rule_edit", "action": "duplicate", "policy": "url_filtering", "id": 199, "name": "Copy"})
    # Assert
    for p in (e, d, c):
        assert p["counts"]["change"] == 0 and p["items"][0]["status"] == "excluded" and "Default" in p["items"][0]["reason"]


# ---------------------------------------------------------------------------
# Duplicate and delete
# ---------------------------------------------------------------------------

def test_a_duplicate_sits_right_below_its_source_at_its_rank_disabled():
    """ASVS V1.4.4 · CWE-840: a copy keeps every setting, takes a new name, sits right below its source at the source's rank and is disabled."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "duplicate", "policy": "url_filtering", "id": 101, "name": "Block gambling copy"}
    # Act
    r = apply(t, spec)
    # Assert
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1
    body = [w for w in t.writes if w[1] == "add_rule"][0][2]
    assert (body["name"], body["order"], body["rank"], body["state"]) == ("Block gambling copy", 2, 3, "DISABLED")
    assert body["cbi_profile"] == URL[0]["cbi_profile"] and "id" not in body and "access_control" not in body
    src = t.zia.url_filtering._find(101)
    assert R.current("url_filtering", src) == R.current("url_filtering", URL[0])


def test_a_duplicate_name_that_exists_blocks_the_plan():
    """ASVS V5.1.3 · CWE-694: a copy cannot take the name of a rule the policy has."""
    # Arrange / Act
    p = plan(Tenant(), {"type": "rule_edit", "action": "duplicate", "policy": "url_filtering", "id": 101, "name": "caution STREAMING"})
    # Assert
    assert p["status"] == "blocked"


def test_a_delete_needs_the_stronger_confirmation_naming_the_rule():
    """ASVS V2.8.x · V11.1.6 · CWE-306 · CWE-841: a delete asks for DELETE and the rule's name, whatever the count; the usual phrase or nothing is refused and nothing is written."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "delete", "policy": "url_filtering", "id": 102, "name": "Caution streaming"}
    p = plan(t, spec)
    # Act
    no = [apply(t, spec, prepared=p, confirm=c)["status"] for c in ("", "APPLY 1 CHANGE", "DELETE", "DELETE CAUTION STREAMINGX")]
    ok = apply(t, spec, prepared=p, confirm="delete caution streaming")
    # Assert
    assert p["confirm_phrase"] == "DELETE CAUTION STREAMING"
    assert no == ["refused"] * 4 and ok["status"] == "applied"
    assert [w[1] for w in t.writes] == ["delete_rule"] and t.zia.url_filtering._find(102) is None


def test_undo_of_a_delete_recreates_the_rule_with_its_fields_order_rank_and_state():
    """ASVS V11.1.1 · CWE-841: Undo re-creates a deleted rule exactly (every field, its order, rank and state), with a new id."""
    # Arrange
    t = Tenant()
    before = copy.deepcopy(t.zia.url_filtering._find(101))
    r = apply(t, {"type": "rule_edit", "action": "delete", "policy": "url_filtering", "id": 101})
    assert r["status"] == "applied"
    # Act
    u = undo(t, r)
    # Assert
    assert u["status"] == "applied" and u["verification"]["confirmed"] == 1
    back = next(x for x in t.rows("url_filtering") if x["name"] == "Block gambling")
    assert back["id"] != 101
    strip = lambda x: {k: v for k, v in x.items() if k not in ("id", "access_control")}  # noqa: E731
    assert strip(back) == strip(before)
    assert [x["name"] for x in sorted(t.rows("url_filtering"), key=lambda x: x["order"])][:2] == ["Block gambling", "Caution streaming"]


def test_a_delete_skips_a_rule_changed_since_the_preview():
    """ASVS V11.1.6 · CWE-362: a rule someone changed after the preview is not deleted."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_edit", "action": "delete", "policy": "url_filtering", "id": 102}
    p = plan(t, spec)
    t.zia.url_filtering.tamper = {"url_categories": ["GAMBLING"]}
    # Act
    r = apply(t, spec, prepared=p)
    # Assert
    assert r["items"][0]["status"] == "conflict" and t.zia.url_filtering._find(102) is not None


# ---------------------------------------------------------------------------
# Every rule type writes through its own service
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("policy,svc,fields,rtype", [
    ("firewall", "cloud_firewall_rules", {"name": "fw", "action": "BLOCK_DROP", "nw_services": ["41"], "dest_addresses": ["10.0.0.0/8"]}, ""),
    ("dns_control", "cloud_firewall_dns", {"name": "dns", "action": "BLOCK", "dest_ip_categories": ["GAMBLING"]}, ""),
    ("firewall_ips", "cloud_firewall_ips", {"name": "ips", "action": "BLOCK_RESET", "dest_countries": ["RU"]}, ""),
    ("sandbox", "sandbox_rules", {"name": "sb", "first_time_operation": "QUARANTINE", "url_categories": ["GAMBLING"]}, ""),
    ("forwarding", "forwarding_control", {"name": "fwd", "forward_method": "DIRECT", "dest_addresses": ["portal.example.com"]}, ""),
    ("ssl_inspection", "ssl_inspection_rules", {"name": "ssl", "action": "DECRYPT", "url_categories": ["GAMBLING"]}, ""),
    ("file_type_control", "file_type_control_rule", {"name": "ftc", "filtering_action": "BLOCK", "file_types": ["FTCATEGORY_ZIP"]}, ""),
    ("web_dlp", "dlp_web_rules", {"name": "dlp", "action": "ALLOW", "dlp_engines": ["1"]}, ""),
    ("cloud_app_control", "cloudappcontrol", {"name": "cac", "actions": ["BLOCK_FILE_SHARE_UPLOAD"], "applications": ["DROPBOX"]}, "FILE_SHARE"),
])
def test_each_rule_type_is_created_through_its_sdk_service_and_undone(policy, svc, fields, rtype):
    """ASVS V1.4.4 · V11.1.1 · CWE-841: each rule type's create goes through its SDK service (add_rule), disabled, is read back, and its Undo deletes it."""
    # Arrange
    t = Tenant()
    spec = create(policy, fields=fields, rule_type=rtype)
    # Act
    r = apply(t, spec)
    u = undo(t, r)
    # Assert
    assert r["status"] == "applied", r["items"]
    adds = [w for w in t.writes if w[1] == "add_rule"]
    assert adds[0][0] == svc and adds[0][2]["state"] == "DISABLED"
    if policy == "cloud_app_control":
        assert adds[0][2]["type"] == "FILE_SHARE"
    assert u["status"] == "applied" and not [x for x in getattr(t.zia, svc).rows if x.get("name") == fields["name"]]


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def test_rule_types_out_of_scope_are_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-285: a rule type the Scope page does not put in scope is refused before any read (DNS, IPS, Sandbox, forwarding and Cloud Firewall need ZIA platform)."""
    # Arrange
    t = Tenant()
    # Act / Assert
    for pol in ("dns_control", "firewall_ips", "sandbox", "forwarding", "firewall"):
        with pytest.raises(ao.OperationError, match="Not in scope"):
            ao.plan(t, create(pol, fields={"name": "x"}), scope=DLP_ONLY)
    with pytest.raises(ao.OperationError, match="Not in scope"):
        ao.plan(t, create("web_dlp", fields={"name": "x", "action": "ALLOW"}), scope=PLATFORM_ONLY)
    with pytest.raises(ao.OperationError):
        ao.read_objects(t, "rule_editor", ao.scope_for([], {}))
    assert t.reads == [] and t.writes == []


def test_an_undo_naming_a_type_out_of_scope_is_refused():
    """ASVS V4.1.3 · CWE-285: the Undo's steps are checked against the Scope page too."""
    # Arrange
    t = Tenant()
    inv = {"type": "rule_edit", "action": "revert", "steps": [{"op": "delete", "policy": "dns_control", "id": 811, "name": "Block DNS tunnels"}]}
    # Act / Assert
    with pytest.raises(ao.OperationError, match="Not in scope"):
        ao.plan(t, inv, scope=DLP_ONLY)
    assert t.reads == []


def test_the_picker_lists_rules_forms_and_names_only_for_what_is_in_scope():
    """ASVS V4.1.3 · CWE-200: the picker reads only the rule types in scope, and offers each form's fields and the named objects."""
    # Arrange
    t = Tenant()
    # Act
    out = ao.read_objects(t, "rule_editor", DLP_ONLY)
    # Assert
    assert out["order"] == ["url_filtering", "ssl_inspection", "web_dlp", "file_type_control", "cloud_app_control"]
    assert "dns_control" in out["not_in_scope"] and not any("cloud_firewall_dns" in r for r in t.reads)
    assert "advanced_settings" not in t.reads
    assert not [r for r in t.reads if r.startswith(("user_management", "locations", "rule_labels"))], "identities need ZIA platform"
    assert out["refs"]["groups"]["not_in_scope"] and out["refs"]["groups"]["rows"] == []
    assert {x["name"] for x in out["refs"]["url_categories"]["rows"]} == {"Gambling", "STREAMING_MEDIA", "Partners"}
    assert out["refs"]["dlp_engines"]["rows"][0]["note"] == "uses Credit Cards"
    names = [f["key"] for f in out["forms"]["url_filtering"]["fields"]]
    assert names[:3] == ["name", "description", "action"] and t.writes == []


# ---------------------------------------------------------------------------
# DNS Control and IPS in Enable or disable rules
# ---------------------------------------------------------------------------

def test_dns_and_ips_rules_can_be_enabled_and_disabled_with_undo():
    """ASVS V1.4.4 · V11.1.1 · CWE-841: rule_state covers DNS Control and IPS rules: each state change goes through its own service, is read back and undone."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "dns_control", "id": 811}, {"policy": "firewall_ips", "id": 821},
                                                                   {"policy": "firewall_ips", "id": 829}]}
    # Act
    p = plan(t, spec)
    r = apply(t, spec, prepared=p)
    # Assert
    assert p["counts"] == {"change": 2, "noop": 0, "excluded": 1, "total": 3}, "the Default IPS rule is never changed"
    assert r["status"] == "applied" and {w[0] for w in t.writes} == {"cloud_firewall_dns", "cloud_firewall_ips"}
    assert t.zia.cloud_firewall_dns._find(811)["state"] == "DISABLED" and t.zia.cloud_firewall_ips._find(821)["state"] == "DISABLED"
    u = undo(t, r)
    assert u["status"] == "applied" and t.zia.cloud_firewall_ips._find(821)["state"] == "ENABLED"


def test_dns_and_ips_state_changes_need_zia_platform_in_scope():
    """ASVS V4.1.3 · CWE-285: DNS Control and IPS rules are in scope only when ZIA platform is ticked."""
    # Arrange
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "firewall_ips", "id": 821}]}
    # Act / Assert
    with pytest.raises(ao.OperationError, match="Not in scope"):
        ao.plan(t, spec, scope=DLP_ONLY)
    assert "firewall_ips" in ao.scope_for(["zia_extras"], {})["policies"] and "dns_control" not in DLP_ONLY["policies"]


# ---------------------------------------------------------------------------
# ZPA segments, cloud app instances and tenancy profiles, proxy chaining
# ---------------------------------------------------------------------------

def test_a_zpa_segment_edit_keeps_its_domains_and_servers_and_is_undone():
    """ASVS V1.4.4 · V11.1.1 · CWE-841: disabling a segment and changing its ports sends the segment as read with those fields changed, needs the typed phrase (ZPA applies at once) and is undone exactly."""
    # Arrange
    t = Tenant()
    spec = {"type": "zpa_segment_edit", "action": "update", "object": "segment", "id": "2201",
            "fields": {"enabled": False, "tcp_ports": ["443", "8443-8444"]}}
    # Act
    p = plan(t, spec)
    r = apply(t, spec, prepared=p)
    # Assert
    assert p["confirm_phrase"] == "APPLY 2 CHANGES" and any("stops ZPA access" in w for w in p["warnings"])
    body = [w for w in t.writes if w[1] == "update"][0][2]
    assert body["enabled"] is False and body["tcp_port_ranges"] == ["443", "443", "8443", "8444"]
    assert body["domain_names"] == ["billing.larkspur.example"] and body["server_group_ids"] == ["77"] and body["segment_group_id"] == "9"
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 2
    u = undo(t, r)
    seg = t.zpa.application_segment._find("2201")
    assert u["status"] == "applied" and seg["enabled"] is True and seg["tcp_port_ranges"] == ["443", "443"]


def test_a_zpa_segment_needs_a_port_and_zpa_in_scope():
    """ASVS V5.1.3 · V4.1.3 · CWE-20 · CWE-285: a segment left without ports, or ZPA not ticked, is refused."""
    # Arrange
    t = Tenant()
    spec = {"type": "zpa_segment_edit", "action": "update", "object": "segment", "id": "2201", "fields": {"tcp_ports": []}}
    # Act / Assert
    with pytest.raises(ao.OperationError, match="at least one TCP or UDP port"):
        plan(t, spec)
    with pytest.raises(ao.OperationError, match="ZPA"):
        ao.plan(t, dict(spec, fields={"enabled": False}), scope=DLP_ONLY)
    with pytest.raises(ao.OperationError, match="not a port"):
        plan(t, dict(spec, fields={"tcp_ports": ["70000"]}))


def test_cloud_app_instances_are_browsed_created_and_the_create_undone():
    """ASVS V1.4.4 · V11.1.1 · CWE-841: instances and tenancy profiles are listed read-only; a new instance goes through the SDK and its Undo deletes it."""
    # Arrange
    t = Tenant()
    spec = {"type": "app_object_edit", "action": "create", "object": "instance",
            "fields": {"instance_name": "Box", "instance_type": "BOXNET", "instance_identifiers": ["URL acme.box.com"]}}
    # Act
    seen = ao.read_objects(t, "app_objects", FULL)
    r = apply(t, spec)
    # Assert
    assert [o["name"] for o in seen["objects"]["instance"]] == ["Larkspur SharePoint"] and seen["objects"]["tenancy"] == []
    sent = [w for w in t.writes if w[1] == "add"][0][2]
    assert sent["instance_identifiers"] == [{"identifier_type": "URL", "instance_identifier": "acme.box.com", "instance_identifier_name": "acme.box.com"}]
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1
    u = undo(t, r)
    assert u["status"] == "applied" and [x["instance_name"] for x in t.zia.cloud_app_instances.rows] == ["Larkspur SharePoint"]


def test_a_tenancy_profile_is_created_with_validated_values():
    """ASVS V5.1.3 · CWE-20: a tenancy restriction profile takes only the SDK's application and item types; bad entries are refused."""
    # Arrange
    t = Tenant()
    good = {"type": "app_object_edit", "action": "create", "object": "tenancy",
            "fields": {"name": "M365 only ours", "app_type": "MSLOGINSERVICES", "item_type_primary": "TENANT_RESTRICTION_TENANT_DIRECTORY",
                       "item_data_primary": "76b66e9c-201a-49dc-bb7e-e9d77604a4c2", "restrict_personal_o365_domains": True}}
    # Act
    r = apply(t, good)
    # Assert
    assert r["status"] == "applied" and [w[2]["app_type"] for w in t.writes if w[1] == "add"] == ["MSLOGINSERVICES"]
    with pytest.raises(ao.OperationError):
        plan(t, dict(good, fields=dict(good["fields"], app_type="MYSPACE")))
    with pytest.raises(ao.OperationError):
        plan(t, dict(good, fields=dict(good["fields"], item_data_primary="a b <x>")))
    with pytest.raises(ao.OperationError, match="ZIA platform"):
        ao.plan(t, good, scope=DLP_ONLY)


def test_a_proxy_is_created_and_the_gateway_is_reported_as_a_manual_step():
    """ASVS V1.4.4 · CWE-841: a proxy goes through proxies.add_proxy; the SDK cannot make a gateway, so the preview and result list the portal steps."""
    # Arrange
    t = Tenant()
    spec = {"type": "proxy_chain_edit", "action": "create", "object": "proxy",
            "fields": {"name": "Branch egress", "address": "egress.example.com", "port": 3128}}
    # Act
    seen = ao.read_objects(t, "proxy_chaining", FULL)
    p = plan(t, spec)
    r = apply(t, spec, prepared=p)
    # Assert
    assert seen["gateway_report"]["gateways"][0] == {"id": 861, "name": "GW", "primary": "Egress", "secondary": "", "fail_closed": True}
    assert "Gateway for Proxies" in p["gateway_report"]["manual_steps"][0] and "cannot create" not in p["gateway_report"]["manual_steps"][0]
    sent = [w for w in t.writes if w[1] == "add"][0][2]
    assert sent == {"name": "Branch egress", "address": "egress.example.com", "port": "3128", "type": "PROXYCHAIN"}
    assert r["status"] == "applied" and r["gateway_report"]["manual_steps"]
    assert undo(t, r)["status"] == "applied" and [x["name"] for x in t.zia.proxies.rows] == ["Egress"]


def test_a_proxy_edit_updates_it_in_place_and_refuses_a_bad_address():
    """ASVS V5.1.3 · CWE-20: a proxy edit goes through proxies.update_proxy; an address that is not an IP or host name is refused."""
    # Arrange
    t = Tenant()
    spec = {"type": "proxy_chain_edit", "action": "update", "object": "proxy", "id": "851", "fields": {"port": 3129}}
    # Act
    r = apply(t, spec)
    # Assert
    assert r["status"] == "applied" and [w[2]["port"] for w in t.writes if w[1] == "update"] == ["3129"]
    assert t.zia.proxies._find(851)["address"] == "proxy.example.com"
    with pytest.raises(ao.OperationError, match="not an IP address or a host name"):
        plan(t, dict(spec, fields={"address": "http://x/"}))


# ---------------------------------------------------------------------------
# The shared write path: timeouts, audit with the actor, the endpoints
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind,channel", [("cloud_app_instance", None), ("tenancy_profile", None), ("policy", "ips")])
def test_a_timed_out_create_of_a_new_kind_is_not_sent_again_blind(kind, channel):
    """ASVS V11.1.6 · CWE-694 · CWE-837: the new kinds go through pack_ops.call: a create answered by a timeout is not resent without a check."""
    # Arrange
    sent = []

    class Any_:
        def __getattr__(self, name):
            def f(*a, **k):
                sent.append(name)
                return None, None, "HTTP 504 Gateway Timeout"
            return f
    z = type("Z", (), {})()
    z.cloud_app_instances = z.tenancy_restriction_profile = z.cloud_firewall_ips = Any_()
    # Act
    out = ops.create(z, kind, {"name": "x"}, channel=channel, name="x")
    # Assert
    assert not out.ok and len([s for s in sent if s.startswith("add")]) == 1


def test_an_applied_edit_is_recorded_and_audited_with_the_actor(tmp_path):
    """ASVS V7.1.3 · V7.2.1 · CWE-778: the applied change is recorded for Undo and its audit entry names the actor."""
    # Arrange
    t = Tenant()
    r = apply(t, create())
    # Act
    rec = ao.record(r, by="Jane Doe", actor="jane@example.com")
    # Assert
    lines = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines() if x.strip()]
    ent = [x for x in lines if x.get("event") == "admin_operation"]
    assert rec["inverse"]["action"] == "revert" and ent and ent[-1]["actor"] == "jane@example.com"
    assert any(x.get("event") == "object_write" for x in lines)


def test_endpoints_refuse_out_of_scope_and_undo_forms_before_signing_in(monkeypatch):
    """ASVS V4.1.3 · V11.1.6 · CWE-285 · WSTG-ATHZ-02: the routes refuse a rule type out of scope (400, before sign-in) and an Undo form without the record it undoes (409)."""
    # Arrange
    import dlp_api_server as srv
    import security
    called = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: called.append(1))
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(security, "may_write", lambda: True)
    client = TestClient(srv.app)
    body = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True, "client_id": "cid", "client_secret": "s3cret-value",
            "vanity_domain": "acme", "cloud": "zscalertwo", "assessor": "Jane Doe"}
    # Act
    r1 = client.post("/api/operations/preview", json=dict(body, operation=create("firewall_ips", fields={"name": "x"})))
    r2 = client.post("/api/operations/objects", json=dict(body, family="proxy_chaining"))
    inv = {"type": "rule_edit", "action": "revert", "steps": [{"op": "recreate", "policy": "url_filtering", "name": "x", "payload": {}}]}
    r3 = client.post("/api/operations/apply", json=dict(body, operation=inv, plan_hash="a" * 64, confirm=True))
    # Assert
    assert r1.status_code == 400 and "Not in scope" in r1.json()["detail"]
    assert r2.status_code == 400
    assert r3.status_code == 409 and "Undo" in r3.json()["detail"]
    assert called == [] and "s3cret" not in r1.text + r2.text + r3.text


def test_the_page_script_escapes_tenant_text_and_registers_every_editor():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the editor's script registers its four forms and builds HTML only through the page's escaper."""
    # Arrange
    from pathlib import Path
    js = (Path(__file__).resolve().parents[1] / "static" / "ops_rule_editor.js").read_text()
    # Act
    regs = [p["type"] for p in ao.plugin_catalog() if p["script"] == "ops_rule_editor.js"]
    # Assert
    assert sorted(regs) == ["app_object_edit", "proxy_chain_edit", "rule_edit", "zpa_segment_edit"]
    for t in regs:
        assert f"type: '{t}'" in js
    assert "innerHTML = `" in js and ".innerHTML = r" not in js and "eval(" not in js and "new Function" not in js
    for name in ("r.name", "o.name", "g.name", "x.name"):
        assert f"${{{name}}}" not in js, f"{name} must go through E()"


def test_users_groups_and_locations_are_set_only_with_zia_platform_in_scope():
    """ASVS V4.1.3 · CWE-285 · CWE-200: users, groups, departments and locations are ZIA platform objects: without it ticked they are not read, and a rule that names them is blocked."""
    # Arrange
    t = Tenant()
    # Act
    p = plan(t, create(), DLP_ONLY)
    # Assert
    assert p["status"] == "blocked" and any("Groups: not in scope" in b for b in p["blockers"])
    assert not [r for r in t.reads if r.startswith("user_management")] and t.writes == []
