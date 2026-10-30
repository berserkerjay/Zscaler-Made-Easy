"""Firewall and private-access migration from Palo Alto Networks: the PAN-OS
reader and mapper (panos_migrate), the firewall import operation on the Bulk
changes engine (ops_fw_import) and the migration page's endpoint. A
synthetic PAN-OS export (tests/fixtures/panos) and a recording fake ZIA with
the SDK's method names; no network, no real tenant."""
from __future__ import annotations

import base64
import copy
import json
import os

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import ops_fw_import as fwi
import pack_channels as pc
import panos_migrate as pm

FIXTURE = os.path.join(os.path.dirname(__file__), "fixtures", "panos", "synthetic_config.xml")


def _data() -> bytes:
    with open(FIXTURE, "rb") as f:
        return f.read()


@pytest.fixture(scope="module")
def plan_doc():
    return pm.build_plan(_data(), source_name="synthetic_config.xml", prefix="pan")


# ---------------------------------------------------------------------------
# The hardened parse
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("doc", [
    b'<?xml version="1.0"?><!DOCTYPE config [<!ENTITY x "boom">]><config>&x;</config>',
    b'<?xml version="1.0"?><!DOCTYPE config SYSTEM "http://example.invalid/x.dtd"><config/>',
    b'<?xml version="1.0"?><!DOCTYPE config [<!ENTITY x SYSTEM "file:///etc/passwd">]><config>&x;</config>',
    '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE config [<!ENTITY a "b">]><config/>'.encode("utf-16"),
])
def test_dtds_entities_and_external_references_are_refused(doc):
    """ASVS V5.5.2 · CWE-611 · CWE-776 · WSTG-INPV-07: a DTD, an entity (internal or external) or a UTF-16 disguise is refused before parsing."""
    with pytest.raises(pm.MigrationError, match="DTD|entit|external"):
        pm.parse(doc, "x.xml")


def test_size_depth_and_element_caps_are_enforced(monkeypatch):
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-07: an oversized, too-deep or too-large export is refused in words, never parsed further."""
    with pytest.raises(pm.MigrationError, match="larger than"):
        pm.parse(b"<config>" + b" " * (pm.MAX_BYTES + 1) + b"</config>")
    with pytest.raises(pm.MigrationError, match="nested more than"):
        pm.parse(b"<config>" + b"<a>" * (pm.MAX_DEPTH + 2) + b"</a>" * (pm.MAX_DEPTH + 2) + b"</config>")
    monkeypatch.setattr(pm, "MAX_ELEMENTS", 50)
    with pytest.raises(pm.MigrationError, match="elements"):
        pm.parse(b"<config>" + b"<a/>" * 60 + b"</config>")
    with pytest.raises(pm.MigrationError, match="not a PAN-OS"):
        pm.parse(b"<policy/>")
    with pytest.raises(pm.MigrationError, match="well-formed"):
        pm.parse(b"<config><a></config>")


# ---------------------------------------------------------------------------
# The mapping
# ---------------------------------------------------------------------------

def test_security_rules_map_to_disabled_cloud_firewall_rules_with_groups_and_services(plan_doc):
    """ASVS V1.4.1 · CWE-1188: rules map to Cloud Firewall rules (actions, groups, services, network apps) and arrive disabled."""
    z = plan_doc["zia"]
    assert z["type"] == "zia_firewall_import" and z["enable"] is False
    rules = {r["source_rule"]: r for r in z["rules"]}
    assert set(rules) == {"Allow-DNS-out", "Partner API alt ports", "Block remote admin"}
    dns = rules["Allow-DNS-out"]
    assert dns["action"] == "ALLOW" and dns["nw_applications"] == ["DNS"]
    assert dns["src_ip_groups"] == ["pan-lan-users"] and dns["dest_ip_groups"] == ["pan-dns-public"], "shared objects resolve too"
    partner = rules["Partner API alt ports"]
    assert partner["action"] == "BLOCK_RESET" and partner["src_ips"] == ["10.40.0.0/24"]
    assert partner["nw_services"] == ["pan-tcp-8080-8090", "pan-tcp-8443", "pan-udp-syslog"], "a service group is flattened"
    assert rules["Block remote admin"]["action"] == "BLOCK_DROP" and rules["Block remote admin"]["nw_applications"] == ["SSH", "RDP"]
    assert all(len(r["name"]) <= 31 and r["name"].startswith("pan-") for r in z["rules"])
    svc = {s["source"]: s for s in z["network_services"]}
    assert svc["tcp-8080-8090"]["dest_tcp"] == ["8080-8090"] and svc["udp-syslog"]["dest_udp"] == ["514"]
    assert {g["source"]: g["ip_addresses"] for g in z["ip_source_groups"]}["lab-range"] == ["10.20.0.10-10.20.0.20"]


def test_globalprotect_rules_become_zpa_segments_and_users_are_noted(plan_doc):
    """ASVS V1.4.1 · CWE-284: allow rules from the GlobalProtect zone to internal destinations become ZPA segments, not ZIA rules."""
    zpa = plan_doc["zpa"]
    segs = {s["source_rule"]: s for s in zpa["segments"]}
    assert set(segs) == {"GP to intranet", "GP to build server ssh"}
    assert segs["GP to intranet"]["domains"] == ["10.30.1.15", "intranet.example.test", "wiki.example.test"]
    assert segs["GP to intranet"]["tcp"] == ["80", "443"]
    assert "10.20.0.10/31" in segs["GP to build server ssh"]["domains"] and segs["GP to build server ssh"]["tcp"] == ["22"]
    assert zpa["segments_spec"]["type"] == "zpa_app_segments" and zpa["segments_spec"]["enable"] is False
    assert zpa["policies_spec"] == {"type": "zpa_policies", "prefix": "pan", "access": True}
    note = next(m for m in plan_doc["mapped"] if m["rule"] == "GP to intranet")["notes"]
    assert any("engineering" in n and "ZPA access rule" in n for n in note)
    # The CSV is what the ZPA builder reads, unchanged.
    import ops_zpa
    rows = ops_zpa.parse_csv(zpa["segments_csv"])
    assert [r["slug"] for r in rows] == ["gp-to-intranet", "gp-to-build-server-ssh"]


def test_unmappable_items_are_listed_with_reasons_never_trimmed(plan_doc):
    """ASVS V1.4.1 · CWE-863: a rule with any part that cannot be carried exactly is listed with each reason, not widened or narrowed."""
    un = {u["name"]: u for u in plan_doc["unmappable"]}
    assert "web or SaaS application" in un["Users to social"]["reasons"][0]
    assert "negate-destination" in un["Not to partner"]["reasons"][0]
    assert "users or groups" in un["Engineering only"]["reasons"][0]
    assert any("wildcard" in r for r in un["Wildcard and dynamic"]["reasons"]) and any("dynamic" in r for r in un["Wildcard and dynamic"]["reasons"])
    assert any("IPv6" in r for r in un["Signalling"]["reasons"]) and any("SCTP" in r for r in un["Signalling"]["reasons"])
    assert un["Old rule"]["info"] and "disabled on the firewall" in un["Old rule"]["reasons"][0]
    assert "Default Firewall Filtering Rule" in un["Default deny"]["reasons"][0], "a catch-all is not duplicated"
    assert any(k.startswith("GlobalProtect") for k in un) and "1 nat rule" in un and "1 decryption rule" in un
    zones = {z["name"]: z for z in plan_doc["zones"]}
    assert zones["gp-users"]["globalprotect"] and not zones["trust"]["globalprotect"]
    mapped = {m["rule"] for m in plan_doc["mapped"]}
    assert not mapped & {u["name"] for u in plan_doc["unmappable"]}


def test_include_disabled_and_explicit_gp_zones_change_the_mapping():
    """ASVS V5.1.3 · CWE-20: options are honoured: disabled rules on request, the GlobalProtect zones as named."""
    doc = pm.build_plan(_data(), prefix="pan", include_disabled=True, gp_zones=["dmz-only"])
    assert any(r["source_rule"] == "Old rule" for r in doc["zia"]["rules"])
    assert doc["zpa"] is None, "no rule comes from the named zone, so nothing goes to ZPA"
    with pytest.raises(pm.MigrationError, match="prefix"):
        pm.build_plan(_data(), prefix="bad prefix!")


def test_names_from_the_export_are_checked(tmp_path):
    """ASVS V5.1.3 · CWE-116 · WSTG-INPV-01: a rule name with markup or control characters is listed, never turned into a Zscaler name."""
    xml = _data().replace(b'name="Allow-DNS-out"', b'name="&lt;img src=x&gt;"')
    doc = pm.build_plan(xml, prefix="pan")
    assert any(u["name"].startswith("<img") and "characters" in u["reasons"][0] for u in doc["unmappable"])
    assert all("<" not in r["name"] for r in doc["zia"]["rules"])


# ---------------------------------------------------------------------------
# The firewall import on the Bulk changes engine
# ---------------------------------------------------------------------------

class FakeFirewall:
    def __init__(self, t, apps):
        self.t = t
        self.objs = {"src": [], "dst": [], "svc": []}
        self.apps = apps
        self.next_id = 500

    def _list(self, kind):
        self.t.reads.append(f"list:{kind}")
        return copy.deepcopy(self.objs[kind]), None, None

    def _get(self, kind, oid):
        row = next((r for r in self.objs[kind] if str(r["id"]) == str(oid)), None)
        return (copy.deepcopy(row), None, None) if row else (None, None, {"message": "not found", "status": 404})

    def _add(self, kind, kw):
        self.t.writes.append(("add", kind, kw.get("name")))
        self.next_id += 1
        row = dict(copy.deepcopy(kw), id=self.next_id)
        self.objs[kind].append(row)
        return copy.deepcopy(row), None, None

    def _del(self, kind, oid):
        self.t.writes.append(("delete", kind, oid))
        self.objs[kind] = [r for r in self.objs[kind] if str(r["id"]) != str(oid)]
        return None, None, None

    def list_ip_source_groups(self, *a, **k): return self._list("src")
    def list_ip_destination_groups(self, *a, **k): return self._list("dst")
    def list_network_services(self, *a, **k): return self._list("svc")
    def get_ip_source_group(self, oid): return self._get("src", oid)
    def get_ip_destination_group(self, oid): return self._get("dst", oid)
    def get_network_service(self, oid): return self._get("svc", oid)
    def add_ip_source_group(self, **kw): return self._add("src", kw)
    def add_ip_destination_group(self, **kw): return self._add("dst", kw)
    def add_network_service(self, **kw): return self._add("svc", kw)
    def delete_ip_source_group(self, oid): return self._del("src", oid)
    def delete_ip_destination_group(self, oid): return self._del("dst", oid)
    def delete_network_service(self, oid): return self._del("svc", oid)

    def list_network_apps(self, *a, **k):
        return [{"id": a} for a in self.apps], None, None


class Tenant:
    def __init__(self, apps=("DNS", "SSH", "RDP", "HTTP", "SSL", "FTP")):
        from test_ops_zia_baseline import Rules
        self.reads, self.writes = [], []
        z = type("Zia", (), {})()
        z.cloud_firewall = FakeFirewall(self, list(apps))
        z.cloud_firewall_rules = Rules(self, "cloud_firewall_rules", [{"id": 21, "name": "Default Firewall Filtering Rule", "order": -1,
                                                                      "default_rule": True, "action": "ALLOW"},
                                                                     {"id": 22, "name": "Own rule", "order": 1, "action": "ALLOW", "state": "ENABLED"}])
        self.zia, self.zpa = z, None


SCOPE = ao.scope_for(["dlp", "zia_extras"], {"web_dlp": "zscaler"})
NO_FW = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})


@pytest.fixture(autouse=True)
def _no_activation(monkeypatch):
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def _apply(t, spec, prepared=None):
    prepared = prepared or ao.plan(t, spec, scope=SCOPE, tenant_label="acme")
    return ao.execute(t, spec, plan_hash=prepared["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=prepared["confirm_phrase"], tenant_label="acme", settle_seconds=0)


def test_the_import_is_out_of_scope_without_cloud_firewall(plan_doc):
    """ASVS V4.1.3 · CWE-284: with Cloud Firewall not ticked the import is refused before anything is read."""
    t = Tenant()
    with pytest.raises(ao.OperationError, match="Not in scope"):
        ao.plan(t, plan_doc["zia"], scope=NO_FW)
    assert t.reads == []


def test_preview_then_apply_creates_disabled_rules_after_their_objects_and_undo_deletes_them(plan_doc):
    """ASVS V1.4.1 · V11.1.1 · CWE-1188: objects first, rules DISABLED at the bottom with resolved ids; ZIA activated; Undo deletes rules first."""
    t = Tenant()
    p = ao.plan(t, plan_doc["zia"], scope=SCOPE)
    assert p["status"] == "ready" and t.writes == [], "the preview never writes"
    assert p["confirm_phrase"] == "IMPORT 10 OBJECTS", "an import always needs the typed phrase"
    res = _apply(t, plan_doc["zia"], p)
    assert res["status"] in ("applied", "done", "completed", "partial") or res["counts"]["created"], res.get("status")
    kinds = [w[1] for w in t.writes if w[0] == "add"]
    assert kinds.index("svc") < len(kinds) and t.writes[-1][0] == "cloud_firewall_rules"
    rules = [r for r in t.zia.cloud_firewall_rules.rows if str(r["name"]).startswith("pan-")]
    assert len(rules) == 3 and all(r["state"] == "DISABLED" for r in rules)
    assert all(r["order"] > 1 for r in rules), "after the tenant's own rule"
    dns = next(r for r in rules if r["name"] == "pan-Allow-DNS-out")
    src = next(g for g in t.zia.cloud_firewall.objs["src"] if g["name"] == "pan-lan-users")
    assert dns["src_ip_groups"] == [src["id"]] and dns["nw_applications"] == ["DNS"]
    svc = next(s for s in t.zia.cloud_firewall.objs["svc"] if s["name"] == "pan-tcp-8080-8090")
    assert svc["dest_tcp_ports"] == [{"start": 8080, "end": 8090}]
    undo = res["inverse"]
    assert undo and undo["action"] == "undo"
    up = ao.plan(t, undo, scope=SCOPE)
    assert up["confirm_phrase"].startswith("DELETE "), "a delete always needs the typed phrase"
    t.writes.clear()
    _apply(t, undo, up)
    assert t.writes[0][0] == "cloud_firewall_rules" and t.writes[0][1] == "delete_rule"
    assert not [r for r in t.zia.cloud_firewall_rules.rows if str(r["name"]).startswith("pan-")]
    assert all(not v for v in t.zia.cloud_firewall.objs.values())


def test_an_existing_object_with_other_content_is_never_changed_and_blocks_its_rules(plan_doc):
    """ASVS V1.4.1 · CWE-284 · CWE-362: a same-named object with other content is excluded with the reason, and so is every rule needing it."""
    t = Tenant()
    t.zia.cloud_firewall.objs["src"].append({"id": 9, "name": "pan-lan-users", "ip_addresses": ["10.99.0.0/16"]})
    p = ao.plan(t, plan_doc["zia"], scope=SCOPE)
    items = {u["key"]: u for u in p["items"]}
    assert items["src:pan-lan-users"]["status"] == "excluded"
    assert items["rule:pan-Allow-DNS-out"]["status"] == "excluded" and "other content" in items["rule:pan-Allow-DNS-out"]["reason"]
    _apply(t, plan_doc["zia"], p)
    assert t.zia.cloud_firewall.objs["src"][0]["ip_addresses"] == ["10.99.0.0/16"]


def test_a_network_application_the_tenant_lacks_excludes_the_rule(plan_doc):
    """ASVS V5.1.3 · CWE-20: a rule naming a network application the tenant does not have is excluded, never sent without it."""
    t = Tenant(apps=("DNS",))
    p = ao.plan(t, plan_doc["zia"], scope=SCOPE)
    u = next(u for u in p["items"] if u["key"] == "rule:pan-Block-remote-admin")
    assert u["status"] == "excluded" and "SSH" in u["reason"]


def test_the_tenant_moving_after_the_preview_writes_nothing(plan_doc):
    """ASVS V11.1.1 · CWE-367: an object made after the preview changes the plan hash and nothing is written."""
    t = Tenant()
    p = ao.plan(t, plan_doc["zia"], scope=SCOPE)
    t.zia.cloud_firewall.objs["svc"].append({"id": 77, "name": "pan-tcp-8443", "dest_tcp_ports": [{"start": 9000}]})
    res = _apply(t, plan_doc["zia"], p)
    assert res["status"] == "plan_changed" and not [w for w in t.writes if w[0] == "add"]


def test_write_mode_and_the_assessor_are_required(plan_doc):
    """ASVS V4.1.5 · CWE-862: with write mode off, or no named assessor, nothing is read or written."""
    t = Tenant()
    p = ao.plan(t, plan_doc["zia"], scope=SCOPE)
    with pytest.raises(PermissionError):
        ao.execute(t, plan_doc["zia"], plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=False, assessor="Jane", confirm_text=p["confirm_phrase"])
    with pytest.raises(ao.OperationError, match="assessor"):
        ao.execute(t, plan_doc["zia"], plan_hash=p["plan_hash"], scope=SCOPE, writes_enabled=True, assessor="", confirm_text=p["confirm_phrase"])
    assert t.writes == []


@pytest.mark.parametrize("mutate,why", [
    (lambda s: s.update(prefix="no spaces"), "prefix"),
    (lambda s: s["rules"][0].update(action="ALLOW_ALL"), "action"),
    (lambda s: s["rules"][0].update(name="other-name"), "prefix"),
    (lambda s: s["rules"][0].update(src_ip_groups=["pan-undefined"]), "does not define"),
    (lambda s: s["ip_source_groups"][0].update(ip_addresses=["not-an-ip"]), "IPv4"),
    (lambda s: s["network_services"][0].update(dest_tcp=["0-70000"]), "port"),
    (lambda s: s["rules"][0].update(nw_applications=["dns; drop"]), "network application"),
    (lambda s: s["rules"].append({"name": "pan-all", "action": "ALLOW"}), "match all"),
])
def test_a_hand_edited_plan_is_checked_again(plan_doc, mutate, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the plan is untrusted: names, prefixes, references, addresses, ports and apps are checked again."""
    spec = copy.deepcopy(plan_doc["zia"])
    mutate(spec)
    with pytest.raises(ao.OperationError, match=why):
        fwi.normalize(spec)


# ---------------------------------------------------------------------------
# The migration page's endpoint
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(monkeypatch):
    import dlp_api_server as srv
    import security
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    c = TestClient(srv.app)
    c.headers.update({security.UI_TOKEN_HEADER: security.ui_token()})
    return c


def test_the_endpoint_returns_the_plan_and_refuses_a_dtd(client):
    """ASVS V5.5.2 · CWE-611 · WSTG-INPV-07: POST /api/vendor-migrate/panos/plan maps the export; a DTD is a 400 with no plan."""
    body = {"export": {"name": "config.xml", "content": base64.b64encode(_data()).decode(), "encoding": "base64"},
            "options": {"prefix": "pan"}}
    r = client.post("/api/vendor-migrate/panos/plan", json=body)
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["format"] == pm.FORMAT and d["counts"]["to_zia"] == 3 and d["counts"]["to_zpa"] == 2
    bad = dict(body, export={"name": "x.xml", "content": '<!DOCTYPE config [<!ENTITY a "b">]><config>&a;</config>'})
    r = client.post("/api/vendor-migrate/panos/plan", json=bad)
    assert r.status_code == 400 and "DTD" in r.json()["detail"]


def test_the_vendor_list_offers_palo_alto_networks(client):
    """ASVS V1.1.2 · CWE-1059: the migration page lists the firewall adapter next to the DLP ones."""
    d = client.get("/api/vendor-migrate/vendors").json()
    assert d.get("firewall", {}).get("id") == "panos"
    assert json.dumps(d).count("Palo Alto") >= 1
