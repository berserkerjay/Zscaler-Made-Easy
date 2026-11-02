"""IP source and destination groups (ops_ip_groups): the source group
editor, deleting either kind, and CSV import and export, on the Bulk
changes engine.

A recording fake of the SDK 1.11.3 cloud_firewall service and the rule
services: no network, no clock, state in tmp_path."""
from __future__ import annotations

import copy
import csv
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_ip_groups as ig  # noqa: E402
import pack_channels as pc  # noqa: E402

ASSESSOR = "Jane Doe"
PLATFORM = ao.scope_for(["zia_extras"], {})
NO_FW = ao.scope_for(["zpa"], {})


def _nf():
    return None, None, {"message": "not found", "status": 404}


class Rules:
    def __init__(self, t, name, rows):
        self.t, self.name, self.rows = t, name, rows

    def list_rules(self, *a, **k):
        self.t.reads.append(f"{self.name}.list_rules")
        return copy.deepcopy(self.rows), None, None


class Firewall:
    def __init__(self, t):
        self.t = t
        self.src = [{"id": 11, "name": "HQ offices", "description": "both floors", "ip_addresses": ["10.1.0.0/16", "10.2.0.5"]},
                    {"id": 12, "name": "Lab", "ip_addresses": ["192.168.50.0/24"]},
                    {"id": 13, "name": "Branch spare", "ip_addresses": ["172.16.9.0/24"]},
                    {"id": 14, "name": "Predefined", "ip_addresses": [], "is_non_editable": True}]
        self.dst = [{"id": 21, "name": "Payment hosts", "type": "DSTN_FQDN", "addresses": ["pay.example.com"]},
                    {"id": 22, "name": "Old servers", "type": "DSTN_IP", "addresses": ["203.0.113.0/28"], "countries": ["COUNTRY_US"]}]
        self.n = 500

    def _rows(self, kind):
        return self.src if kind == "src" else self.dst

    def _get(self, kind, gid):
        self.t.reads.append(f"get_{kind}")
        if self.t.before_get:
            self.t.before_get(kind, gid)
        g = next((x for x in self._rows(kind) if str(x["id"]) == str(gid)), None)
        return (copy.deepcopy(g), None, None) if g else _nf()

    def _write(self, verb, kind, gid, kw):
        assert not self.t.frozen, "write during a preview"
        self.t.writes.append((verb, kind, gid, copy.deepcopy(kw)))

    def list_ip_source_groups(self, *a, **k):
        self.t.reads.append("list_src")
        return copy.deepcopy(self.src), None, None

    def get_ip_source_group(self, gid):
        return self._get("src", gid)

    def add_ip_source_group(self, **kw):
        self._write("add", "src", None, kw)
        self.n += 1
        self.src.append(dict(copy.deepcopy(kw), id=self.n))
        return copy.deepcopy(self.src[-1]), None, None

    def update_ip_source_group(self, gid, **kw):
        self._write("update", "src", gid, kw)
        g = next(x for x in self.src if str(x["id"]) == str(gid))
        keep = {k: v for k, v in g.items() if k in ("id", "is_non_editable")}
        g.clear()
        g.update(keep, **copy.deepcopy(kw))
        return copy.deepcopy(g), None, None

    def delete_ip_source_group(self, gid):
        self._write("delete", "src", gid, {})
        self.src = [x for x in self.src if str(x["id"]) != str(gid)]
        return None, None, None

    def list_ip_destination_groups(self, *a, **k):
        self.t.reads.append("list_dst")
        return copy.deepcopy(self.dst), None, None

    def get_ip_destination_group(self, gid):
        return self._get("dst", gid)

    def add_ip_destination_group(self, **kw):
        self._write("add", "dst", None, kw)
        self.n += 1
        self.dst.append(dict(copy.deepcopy(kw), id=self.n))
        return copy.deepcopy(self.dst[-1]), None, None

    def update_ip_destination_group(self, gid, **kw):
        self._write("update", "dst", gid, kw)
        g = next(x for x in self.dst if str(x["id"]) == str(gid))
        g.clear()
        g.update(copy.deepcopy(kw), id=int(gid))
        return copy.deepcopy(g), None, None

    def delete_ip_destination_group(self, gid):
        self._write("delete", "dst", gid, {})
        self.dst = [x for x in self.dst if str(x["id"]) != str(gid)]
        return None, None, None


class Tenant:
    def __init__(self):
        self.reads, self.writes, self.frozen, self.before_get = [], [], False, None
        z = type("Zia", (), {})()
        z.cloud_firewall = Firewall(self)
        z.cloud_firewall_rules = Rules(self, "fw", [{"id": 401, "name": "Allow HQ out", "order": 1, "state": "ENABLED", "src_ip_groups": [{"id": 11}]},
                                                    {"id": 402, "name": "Block old", "order": 2, "state": "DISABLED", "dest_ip_groups": [{"id": 22}]}])
        z.cloud_firewall_dns = Rules(self, "dns", [{"id": 501, "name": "Lab DNS", "order": 1, "state": "ENABLED", "src_ip_groups": [{"id": 12}]}])
        z.cloud_firewall_ips = Rules(self, "ips", [])
        self.zia = z

    @property
    def fw(self):
        return self.zia.cloud_firewall


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()
    return acts


def preview(t, spec, scope=PLATFORM):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec, *, phrase=None, prepared=None):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=PLATFORM, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


def test_registered_with_its_form_and_out_of_scope_reads_nothing():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: one ZIA plugin type with its form; without the Cloud Firewall in scope nothing is read."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[ig.TYPE]["product"] == "zia" and cat[ig.TYPE]["script"] == "ops_ip_groups.js" and cat[ig.TYPE]["group"] == "Change"
    assert os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_ip_groups.js"))
    t = Tenant()
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(t, {"type": ig.TYPE, "action": "delete", "kind": "source", "id": 13}, scope=NO_FW)
    with pytest.raises(ao.OperationError):
        ao.read_objects(t, ig.FAMILY, NO_FW)
    assert t.reads == [] and t.writes == []


def test_a_source_group_edit_sends_the_group_back_with_its_new_list_and_undo_restores_it(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle: PUT /ipSourceGroups/{id} with name, description and the new ip_addresses; read back; Undo puts the list back."""
    t = Tenant()
    p, r = apply(t, {"type": ig.TYPE, "action": "source_edit", "group": {"id": 11}, "add": ["10.3.0.0/16", "10.4.4.1-10.4.4.9"], "remove": ["10.2.0.5"]})
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 3 and len(isolated) == 1
    assert t.writes == [("update", "src", 11, {"name": "HQ offices", "ip_addresses": ["10.1.0.0/16", "10.3.0.0/16", "10.4.4.1-10.4.4.9"],
                                                "description": "both floors"})]
    inv = r["inverse"]
    assert inv["undo"] is True and ao.is_undo_only(inv)
    _p, r2 = apply(t, inv)
    assert r2["status"] == "applied" and sorted(t.fw.src[0]["ip_addresses"]) == ["10.1.0.0/16", "10.2.0.5"]


def test_a_new_source_group_is_created_and_undo_deletes_it():
    """ASVS V1.4.1 · CWE-841: payload oracle for POST /ipSourceGroups; Undo deletes the group it created (still unchanged)."""
    t = Tenant()
    _p, r = apply(t, {"type": ig.TYPE, "action": "source_edit", "group": {"new": "Contractors", "description": "temp"}, "add": ["198.51.100.7", "198.51.100.0/30"]})
    assert r["status"] == "applied"
    assert t.writes[0][:2] == ("add", "src") and t.writes[0][3] == {"name": "Contractors", "ip_addresses": ["198.51.100.7", "198.51.100.0/30"], "description": "temp"}
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and not [g for g in t.fw.src if g["name"] == "Contractors"]


def test_bad_and_ipv6_entries_are_refused_with_the_reason():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: a host name, an IPv6 address and junk are excluded with the reason; the rest goes through."""
    t = Tenant()
    p = preview(t, {"type": ig.TYPE, "action": "source_edit", "group": {"id": 12}, "add": ["example.com", "2001:db8::1", "10.9.9.300", "10.9.9.9"]})
    why = {u["value"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert set(why) == {"example.com", "2001:db8::1", "10.9.9.300"} and "IPv6" in why["2001:db8::1"]
    assert [u["value"] for u in p["items"] if u["status"] == "change"] == ["10.9.9.9"]


def test_delete_is_refused_while_rules_use_the_group_and_lists_them():
    """ASVS V4.1.3 · CWE-672 · WSTG-BUSL-01: a group named by a firewall or DNS rule is never deleted; each rule is named."""
    t = Tenant()
    for kind, gid, rule_name in (("source", 11, "Allow HQ out"), ("source", 12, "Lab DNS"), ("destination", 22, "Block old")):
        p = preview(t, {"type": ig.TYPE, "action": "delete", "kind": kind, "id": gid})
        assert p["counts"]["change"] == 0 and rule_name in p["items"][0]["reason"] and p["items"][0]["reason"].startswith("still used by")
    p = preview(t, {"type": ig.TYPE, "action": "delete", "kind": "source", "id": 14})
    assert p["items"][0]["reason"].startswith("a predefined group")
    assert t.writes == []


def test_delete_needs_delete_and_the_name_typed_and_undo_creates_it_again():
    """ASVS V4.1.3 · CWE-862: DELETE <name> is the phrase; the wrong phrase sends nothing; Undo re-creates the destination group with its type, countries and addresses."""
    t = Tenant()
    spec = {"type": ig.TYPE, "action": "delete", "kind": "destination", "id": 21}
    p = preview(t, spec)
    assert p["confirm_phrase"] == "DELETE PAYMENT HOSTS"
    _p, r = apply(t, spec, phrase="DELETE", prepared=p)
    assert r["status"] == "refused" and t.writes == []
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "applied" and t.writes == [("delete", "dst", 21, {})] and r["verification"]["confirmed"] == 1
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied"
    made = [g for g in t.fw.dst if g["name"] == "Payment hosts"][0]
    assert made["type"] == "DSTN_FQDN" and made["addresses"] == ["pay.example.com"] and made["id"] != 21


def test_delete_is_blocked_when_dns_or_ips_rules_are_not_in_scope():
    """ASVS V4.1.3 · CWE-863: deny by default: with only the Cloud Firewall in scope the DNS and IPS rules cannot be checked, so the delete is blocked."""
    t = Tenant()
    narrow = dict(PLATFORM, policies=["firewall"])
    p = preview(t, {"type": ig.TYPE, "action": "delete", "kind": "source", "id": 13}, scope=narrow)
    assert p["status"] == "blocked" and "DNS Control" in p["blockers"][0] and t.writes == []


def test_a_group_changed_after_the_preview_is_left_alone():
    """ASVS V11.1.4 · CWE-367: a group changed since the preview gives plan_changed, or a conflict at the re-read; nothing is written."""
    t = Tenant()
    spec = {"type": ig.TYPE, "action": "source_edit", "group": {"id": 13}, "add": ["172.16.10.0/24"]}
    p = preview(t, spec)
    t.fw.src[2]["ip_addresses"].append("172.16.11.1")
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "plan_changed" and t.writes == []
    t = Tenant()
    p = preview(t, spec)
    t.before_get = lambda kind, gid: t.fw.src[2].update(description="edited meanwhile")
    _p, r = apply(t, spec, prepared=p)
    assert r["items"][0]["status"] == "conflict" and t.writes == []


def test_the_export_is_csv_the_import_reads_back_and_cells_are_spreadsheet_safe():
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-15: every group exported with its kind, type and addresses; a formula-like description is neutralised and survives a round trip."""
    t = Tenant()
    t.fw.src[1]["description"] = "=HYPERLINK(\"http://evil\")"
    out = ao.read_objects(t, ig.FAMILY, PLATFORM)
    rows = list(csv.reader(io.StringIO(out["csv"])))
    assert rows[0] == list(ig.CSV_COLUMNS)
    lab = next(r for r in rows if r[1] == "Lab")
    assert lab[0] == "source" and lab[3].startswith("'=") and lab[4] == "192.168.50.0/24"
    assert next(r for r in rows if r[1] == "Payment hosts")[2] == "DSTN_FQDN"
    back = {(g["kind"], g["name"]): g for g in ig.parse_csv(out["csv"])}
    assert back[("source", "Lab")]["description"] == "=HYPERLINK(\"http://evil\")"
    assert back[("source", "HQ offices")]["addresses"] == ["10.1.0.0/16", "10.2.0.5"]
    assert {u["name"] for u in next(g for g in out["source_groups"] if g["name"] == "HQ offices")["used_by"]} == {"Allow HQ out"}


def test_an_import_creates_new_groups_merges_or_replaces_existing_ones_and_undo_reverses_all():
    """ASVS V1.4.1 · CWE-841: payload oracles for the import: a new destination group created, an existing source group merged (or replaced); Undo deletes and restores."""
    t = Tenant()
    text = ("kind,name,type,description,addresses\r\n"
            "source,Lab,,,192.168.51.0/24\r\n"
            "destination,Partners,DSTN_FQDN,partner sites,a.partner.example; b.partner.example\r\n"
            "destination,Partners,DSTN_FQDN,,c.partner.example\r\n")
    p, r = apply(t, {"type": ig.TYPE, "action": "import", "mode": "merge", "csv": text})
    assert r["status"] == "applied"
    assert ("update", "src", 12, {"name": "Lab", "ip_addresses": ["192.168.50.0/24", "192.168.51.0/24"]}) in t.writes
    adds = [w for w in t.writes if w[0] == "add"]
    assert adds == [("add", "dst", None, {"name": "Partners", "addresses": ["a.partner.example", "b.partner.example", "c.partner.example"],
                                          "description": "partner sites", "type": "DSTN_FQDN"})]
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and t.fw.src[1]["ip_addresses"] == ["192.168.50.0/24"] and not [g for g in t.fw.dst if g["name"] == "Partners"]
    t = Tenant()
    p = preview(t, {"type": ig.TYPE, "action": "import", "mode": "replace", "csv": "kind,name,addresses\nsource,Lab,192.168.51.0/24\n"})
    assert {(u["value"], u["after"]) for u in p["items"] if u["status"] == "change"} == {("192.168.51.0/24", True), ("192.168.50.0/24", False)}
    assert any("Replace mode removes" in w for w in p["warnings"])


@pytest.mark.parametrize("text, why", [("name,addresses\nLab,1.2.3.4\n", "kind"), ("kind,name,addresses\nsource,,1.2.3.4\n", "Row 2"),
                                       ("kind,name,type,addresses\ndestination,X,DSTN_OTHER,1.2.3.4\n", "DSTN_IP"),
                                       ("kind,name,addresses\nfirewall,X,1.2.3.4\n", "source or destination"), ("", "empty"),
                                       ("kind,name,addresses\nsource,a\x00b,1.2.3.4\n", "NUL"), ("x" * (ig.MAX_CSV_BYTES + 1), "larger")])
def test_a_bad_csv_is_refused_in_words_before_anything_is_read(text, why):
    """ASVS V5.2.2 · CWE-20 · CWE-400 · WSTG-INPV-01: missing columns, a bad row, an unknown kind or type, NUL bytes and an oversized file are refused with the reason."""
    t = Tenant()
    with pytest.raises(ao.OperationError, match=why):
        ao.plan(t, {"type": ig.TYPE, "action": "import", "csv": text}, scope=PLATFORM)
    assert t.reads == [] and t.writes == []


def test_an_undo_form_is_refused_unless_applied_as_an_undo():
    """ASVS V4.1.3 · CWE-639: a revert is marked undo-only (the route applies it only as a recorded operation's Undo); without the marker it is refused."""
    with pytest.raises(ao.OperationError):
        ao.plan(Tenant(), {"type": ig.TYPE, "action": "revert", "steps": [{"op": "delete", "kind": "source", "id": 13, "name": "Branch spare"}]}, scope=PLATFORM)
    assert ao.is_undo_only({"type": ig.TYPE, "action": "revert", "undo": True})
