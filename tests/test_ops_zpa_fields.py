"""ZPA segment settings in bulk (ops_zpa_fields): one operation type on the
Bulk changes engine. Runs against the stateful fake ZPA tenant in
tests/zpa_fake.py, with an update that REPLACES the segment as ZPA's PUT
does (the SDK clears the port ranges it is not given). No network."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import zpa_reader  # noqa: E402
from zpa_fake import Client, Segments, Tenant, _body  # noqa: E402

ZPA = ao.scope_for(["zpa"], {})
NO_ZPA = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})

# What ZPA keeps on a PUT that does not mention it (assumed for PRA and
# inspection apps); Browser Access apps are kept only when sent back.
SERVER_KEPT = ("praApps", "inspectionApps", "commonAppsDto", "microtenantName", "readOnly", "zscalerManaged")


class ReplacingSegments(Segments):
    def update_segment(self, sid, **kw):
        r = self.t.rows["segment"].get(str(sid))
        if r is None:
            return None, None, "HTTP 404"
        self.t.puts.append((str(sid), dict(kw)))
        new = {"id": r["id"], **{k: r[k] for k in SERVER_KEPT if k in r}, **_body(kw)}
        r.clear()
        r.update(new)
        self.t.writes.append(("update", "segment", r["name"]))
        return dict(r), None, None


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    ao.load_plugins()
    return tmp_path


def seg(t, name, domains, tcp, **kw):
    row = {"name": name, "domainNames": domains, "segmentGroupId": "g1", "serverGroups": [{"id": "sg1"}], "tcpPortRanges": tcp,
           "udpPortRanges": [], "enabled": True, "healthReporting": "ON_ACCESS", "bypassType": "NEVER", "doubleEncrypt": False,
           "isCnameEnabled": True, "description": "kept as it is"}
    row.update(kw)
    return t.add("segment", row)


def tenant():
    t = Tenant()
    t.puts = []
    c = Client(t)
    c.zpa.application_segment = ReplacingSegments(t, "segment")
    t.add("segment_group", {"id": "g1", "name": "Apps"})
    t.add("segment_group", {"id": "g2", "name": "Admin apps"})
    t.add("server_group", {"id": "sg1", "name": "DC1"})
    t.add("server_group", {"id": "sg2", "name": "DC2"})
    plain = seg(t, "Intranet", ["wiki.corp.example"], ["443", "443"])
    ba = seg(t, "Jenkins BA", ["jenkins.corp.example"], ["443", "443", "8443", "8443"],
             clientlessApps=[{"id": "ba1", "name": "jenkins.corp.example", "domain": "jenkins.corp.example", "applicationPort": "8443",
                              "applicationProtocol": "HTTPS", "certificateId": "c1", "enabled": True}])
    pra = seg(t, "Jump hosts PRA", ["jump.corp.example"], ["22", "22", "3389", "3389"],
              praApps=[{"id": "p1", "name": "jump.corp.example", "applicationPort": "22", "applicationProtocol": "SSH"}],
              commonAppsDto={"appsConfig": [{"appTypes": ["SECURE_REMOTE_ACCESS"], "domain": "jump.corp.example"}]})
    insp = seg(t, "Portal inspected", ["portal.corp.example"], ["443", "443"],
               inspectionApps=[{"id": "i1", "name": "portal.corp.example", "applicationPort": "443", "applicationProtocol": "HTTPS"}])
    return c, {"plain": plain["id"], "ba": ba["id"], "pra": pra["id"], "insp": insp["id"]}


def preview(c, spec, scope=ZPA):
    before = len(c.tenant.writes)
    p = ao.plan(c, spec, scope=scope, tenant_label="acme")
    assert len(c.tenant.writes) == before, "a preview wrote to the tenant"
    return p


def apply(c, spec, p=None, **kw):
    p = p or preview(c, spec)
    return ao.execute(c, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor="Jane Doe", tenant_label="acme",
                      confirm_text=p.get("confirm_phrase") or "", **kw)


def row(c, sid):
    return c.tenant.rows["segment"][sid]


# ── registration, scope, validation ─────────────────────────────────────

def test_registered_as_a_change_existing_type_with_its_form():
    """ASVS V1.4.4 · CWE-1059: the bulk segment edit is a plugin type on the Bulk changes engine, with its own form script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    p = cat["zpa_segment_fields"]
    assert p["script"] == "ops_zpa_fields.js" and p["product"] == "zpa" and p["group"] == "Change existing"


def test_out_of_scope_is_refused_before_anything_is_read():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without ZPA ticked on the Scope page nothing is read and nothing is written."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": {"health_reporting": "CONTINUOUS"}}
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(c, spec, scope=NO_ZPA)
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.read_objects(c, "zpa_segment_bulk", NO_ZPA)
    assert c.tenant.reads == [] and c.tenant.writes == []


@pytest.mark.parametrize("bad, match", [
    ({"health_reporting": "SOMETIMES"}, "not one of"),
    ({"bypass_type": "<script>"}, "not one of"),
    ({"double_encrypt": "maybe"}, "on or off"),
    ({"name": "renamed"}, "not a segment setting"),
    ({"domain_names": ["evil.example"]}, "not a segment setting"),
    ({"tcp_ports": {"add": "70000"}}, "1-65535"),
    ({"tcp_ports": {"add": "443", "remove": "443"}}, "both added and removed"),
    ({"server_groups": {"replace": []}}, "at least one setting|at least one server group"),
    ({"server_groups": {"add": ["../x"]}}, "not a ZPA id"),
    ({}, "at least one setting"),
])
def test_a_bad_request_is_refused_before_anything_is_read(bad, match):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unknown fields, bad values, bad ids and bad port ranges are refused before a read (deny by default)."""
    c, ids = tenant()
    with pytest.raises(ao.OperationError, match=match):
        ao.plan(c, {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": bad}, scope=ZPA)
    assert c.tenant.reads == []


def test_too_many_segments_are_refused():
    """ASVS V11.1.4 · CWE-770: one operation changes at most MAX_SEGMENTS segments."""
    import ops_zpa_fields as f
    c, _ids = tenant()
    with pytest.raises(ao.OperationError, match="At most"):
        ao.plan(c, {"type": "zpa_segment_fields", "segments": [str(i) for i in range(f.MAX_SEGMENTS + 1)], "set": {"enabled": False}}, scope=ZPA)
    assert c.tenant.reads == []


# ── the bulk edit across every kind of segment ──────────────────────────

def test_one_edit_across_plain_browser_access_pra_and_inspection_segments():
    """ASVS V1.4.1 · CWE-841: health reporting, bypass, DR mode, a server group and a port range are set on all four kinds of segment;
    everything else, the Browser Access, PRA and inspection applications included, survives the replacing PUT."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": list(ids.values()),
            "set": {"health_reporting": "CONTINUOUS", "use_in_dr_mode": True, "server_groups": {"add": ["sg2"]}, "tcp_ports": {"add": "9443"}}}
    p = preview(c, spec)
    assert p["status"] == "ready" and p["counts"]["change"] == 16 and p["confirm_phrase"] == "APPLY 16 CHANGES"
    kinds = {u["object"]["name"]: u["object"]["kinds"] for u in p["items"]}
    assert kinds["Jenkins BA"] == ["Browser Access"] and kinds["Jump hosts PRA"] == ["PRA"] and kinds["Portal inspected"] == ["inspection"]
    r = apply(c, spec, p)
    assert r["status"] == "applied", r
    assert r["verification"]["confirmed"] == 16 and not r["verification"]["mismatched"]
    for sid in ids.values():
        s = row(c, sid)
        assert s["healthReporting"] == "CONTINUOUS" and s["useInDrMode"] is True
        assert [g["id"] for g in s["serverGroups"]] == ["sg1", "sg2"] and "9443" in s["tcpPortRanges"]
        assert s["description"] == "kept as it is" and s["isCnameEnabled"] is True and s["segmentGroupId"] == "g1"
    assert row(c, ids["ba"])["clientlessApps"][0]["id"] == "ba1"
    assert row(c, ids["pra"])["praApps"][0]["id"] == "p1" and row(c, ids["insp"])["inspectionApps"][0]["id"] == "i1"
    # the Browser Access apps were sent back on the PUT; PRA / inspection apps were not (commonAppsDto never sent)
    puts = dict(c.tenant.puts)
    assert puts[ids["ba"]]["clientlessApps"][0]["id"] == "ba1"
    assert all("commonAppsDto" not in kw and "common_apps_dto" not in kw for kw in puts.values())


def test_the_read_back_reports_a_browser_access_app_the_put_dropped(monkeypatch):
    """ASVS V7.2.2 · CWE-754: if ZPA drops a Browser Access application on the PUT, the read-back says so instead of confirming."""
    c, ids = tenant()
    real = ReplacingSegments.update_segment

    def drops(self, sid, **kw):
        kw.pop("clientlessApps", None)
        return real(self, sid, **kw)
    monkeypatch.setattr(ReplacingSegments, "update_segment", drops)
    r = apply(c, {"type": "zpa_segment_fields", "segments": [ids["ba"]], "set": {"health_reporting": "NONE"}})
    assert r["status"] != "applied" or r["verification"]["mismatched"]
    assert any("Browser Access" in m for m in r["verification"]["mismatched"])


def test_scalar_fields_bypass_double_encryption_and_segment_group():
    """ASVS V1.4.1 · CWE-841: bypass, double encryption and the segment group are set; a value already as asked is a no-op; warnings are named."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": [ids["plain"], ids["insp"]],
            "set": {"bypass_type": "ON_NET", "double_encrypt": True, "segment_group_id": "g2", "enabled": True}}
    p = preview(c, spec)
    assert {(u["field"], u["status"]) for u in p["items"] if u["object"]["id"] == ids["plain"]} == {
        ("bypass_type", "change"), ("double_encrypt", "change"), ("segment_group_id", "change"), ("enabled", "noop")}
    grp = next(u for u in p["items"] if u["field"] == "segment_group_id")
    assert grp["before"] == "Apps" and grp["after"] == "Admin apps"
    assert any("double encryption" in w for w in p["warnings"]) and any("not through ZPA" in w for w in p["warnings"])
    r = apply(c, spec, p)
    assert r["status"] == "applied"
    for sid in (ids["plain"], ids["insp"]):
        assert row(c, sid)["bypassType"] == "ON_NET" and row(c, sid)["doubleEncrypt"] is True and row(c, sid)["segmentGroupId"] == "g2"


def test_unknown_segment_or_group_blocks_the_plan():
    """ASVS V4.2.1 · CWE-639: a server group or segment group that is not in the tenant blocks the plan; nothing is written."""
    c, ids = tenant()
    p = preview(c, {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": {"server_groups": {"add": ["sg9"]}}})
    assert p["status"] == "blocked"
    with pytest.raises(ao.OperationError, match="not in the tenant"):
        preview(c, {"type": "zpa_segment_fields", "segments": ["nope"], "set": {"enabled": False}})


# ── ZPA's rules, checked in the preview ─────────────────────────────────

def test_the_last_server_group_and_the_last_port_range_are_never_removed():
    """ASVS V5.1.3 · CWE-840: a removal that would leave a segment with no server group or no port range is excluded with the reason."""
    c, ids = tenant()
    p = preview(c, {"type": "zpa_segment_fields", "segments": [ids["plain"]],
                    "set": {"server_groups": {"remove": ["sg1"]}, "tcp_ports": {"remove": "443"}}})
    ex = {u["field"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert "at least one server group" in ex["server_groups"] and "at least one port range" in ex["tcp_port_ranges"]
    assert p["status"] == "nothing_to_do"


def test_a_port_an_application_uses_is_not_removed():
    """ASVS V5.1.3 · CWE-840: the TCP range a Browser Access or PRA application listens on stays; other ranges can go."""
    c, ids = tenant()
    p = preview(c, {"type": "zpa_segment_fields", "segments": [ids["ba"], ids["pra"]], "set": {"tcp_ports": {"remove": "8443, 22, 3389"}}})
    st = {(u["object"]["name"], u["value"]): (u["status"], u["reason"]) for u in p["items"] if u["field"] == "tcp_port_ranges"}
    assert st[("Jenkins BA", "8443")][0] == "excluded" and "Browser Access application" in st[("Jenkins BA", "8443")][1]
    assert st[("Jump hosts PRA", "22")][0] == "excluded" and "PRA application" in st[("Jump hosts PRA", "22")][1]
    assert st[("Jump hosts PRA", "3389")][0] == "change"
    assert st[("Jenkins BA", "22")][0] == "noop"


def test_a_port_added_where_another_segment_serves_the_same_domain_is_excluded():
    """ASVS V5.1.3 · CWE-840: one domain is never put in two segments on overlapping ports, also across the segments of the same edit."""
    c, ids = tenant()
    seg(c.tenant, "Wiki alt", ["wiki.corp.example"], ["8080", "8080"])
    p = preview(c, {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": {"tcp_ports": {"add": "8000-8100"}}})
    u = next(x for x in p["items"] if x["field"] == "tcp_port_ranges")
    assert u["status"] == "excluded" and "Wiki alt" in u["reason"] and "wiki.corp.example" in u["reason"]


def test_a_range_already_covered_is_a_noop_and_ranges_are_removed_whole():
    """ASVS V5.1.3 · CWE-20: adding a port inside an existing range changes nothing; removing part of a range is not done."""
    c, _ids = tenant()
    wide = seg(c.tenant, "Legacy", ["old.corp.example"], ["1", "1000"])
    p = preview(c, {"type": "zpa_segment_fields", "segments": [wide["id"]], "set": {"tcp_ports": {"add": "443", "remove": "80"}}})
    st = {u["value"]: u for u in p["items"]}
    assert st["443"]["status"] == "noop" and "covered by 1-1000" in st["443"]["reason"]
    assert st["80"]["status"] == "noop" and "removed whole" in st["80"]["reason"]


def test_a_read_only_segment_is_excluded():
    """ASVS V4.1.3 · CWE-284: a segment ZPA marks read-only is never changed."""
    c, _ids = tenant()
    ro = seg(c.tenant, "Locked", ["locked.corp.example"], ["443", "443"], readOnly=True)
    p = preview(c, {"type": "zpa_segment_fields", "segments": [ro["id"]], "set": {"health_reporting": "NONE"}})
    assert p["items"][0]["status"] == "excluded" and "read-only" in p["items"][0]["reason"] and not p["groups"]


# ── conflict guard, plan hash, Undo ─────────────────────────────────────

def test_a_field_changed_since_the_preview_is_a_conflict_and_left_alone():
    """ASVS V11.1.6 · CWE-362 (TOCTOU): the re-read before the write leaves a field someone else changed; the other fields still apply."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": {"health_reporting": "CONTINUOUS", "bypass_type": "ALWAYS"}}
    p = preview(c, spec)
    import ops_zpa as zb
    calls = {"n": 0}
    orig = zb.get_one

    def get_one(zpa, kind, oid):
        calls["n"] += 1
        if calls["n"] == 1:
            row(c, oid)["bypassType"] = "ON_NET"      # someone else's change, after the plan was checked again
        return orig(zpa, kind, oid)
    zb.get_one = get_one
    try:
        r = apply(c, spec, p)
    finally:
        zb.get_one = orig
    st = {u["field"]: u["status"] for u in r["items"]}
    assert st == {"health_reporting": "applied", "bypass_type": "conflict"}
    assert row(c, ids["plain"])["bypassType"] == "ON_NET" and row(c, ids["plain"])["healthReporting"] == "CONTINUOUS"


def test_a_tenant_change_after_the_preview_changes_the_plan_hash():
    """ASVS V11.1.6 · CWE-367: a preview that no longer matches the tenant is refused as a whole; nothing is written."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": [ids["plain"]], "set": {"health_reporting": "CONTINUOUS"}}
    p = preview(c, spec)
    row(c, ids["plain"])["healthReporting"] = "NONE"
    r = apply(c, spec, p)
    assert r["status"] == "plan_changed" and c.tenant.puts == []


def test_undo_puts_back_exactly_what_was_changed():
    """ASVS V7.2.2 · CWE-1265: Undo is a new operation that restores the fields, server groups and ports applied, and nothing else."""
    c, ids = tenant()
    spec = {"type": "zpa_segment_fields", "segments": [ids["plain"], ids["ba"]],
            "set": {"health_reporting": "NONE", "server_groups": {"replace": ["sg2"]}, "tcp_ports": {"add": "9000-9010", "remove": "443"}}}
    before = {sid: dict(row(c, sid)) for sid in (ids["plain"], ids["ba"])}
    r = apply(c, spec)
    assert r["status"] == "applied", r
    inv = r["inverse"]
    assert inv["type"] == "zpa_segment_fields" and len(inv["per_segment"]) == 2
    u = apply(c, inv)
    assert u["status"] == "applied", u
    for sid, b in before.items():
        s = row(c, sid)
        assert s["healthReporting"] == b["healthReporting"] and [g["id"] for g in s["serverGroups"]] == ["sg1"]
        assert zpa_reader.port_ranges(s, "tcp")[0] == zpa_reader.port_ranges(b, "tcp")[0]
    assert row(c, ids["ba"])["clientlessApps"][0]["id"] == "ba1"


def test_read_objects_lists_segments_with_their_kind_and_the_groups():
    """ASVS V1.4.1 · CWE-200: the form gets each segment's settings and kind and the group pick lists; reads only."""
    c, ids = tenant()
    res = ao.read_objects(c, "zpa_segment_bulk", ZPA)
    segs = {s["name"]: s for s in res["segments"]}
    assert segs["Jenkins BA"]["kinds"] == ["Browser Access"] and segs["Intranet"]["tcp"] == ["443"]
    assert segs["Intranet"]["server_groups"] == ["DC1"] and segs["Intranet"]["segment_group"] == "Apps"
    assert [g["name"] for g in res["server_groups"]] == ["DC1", "DC2"] and c.tenant.writes == []


def test_the_sample_tenant_through_the_real_sdk_reads_previews_and_applies():
    """ASVS V1.4.1 · CWE-841: on the made-up sample tenant (the installed SDK's services over the offline store, no network) the edit
    reads, previews, applies, reads back and keeps every other setting of the segment."""
    import offline_tenant
    st = offline_tenant.sample_store(reset=True)
    try:
        client = offline_tenant.OfflineSdkClient(st, offline_tenant.creds_for(st))
        res = ao.read_objects(client, "zpa_segment_bulk", ZPA)
        segs = {s["name"]: s for s in res["segments"]}
        assert segs["Freight billing"]["health_reporting"] == "ON_ACCESS" and segs["Freight billing"]["tcp"] == ["443"]
        spec = {"type": "zpa_segment_fields", "segments": [segs["Freight billing"]["id"]],
                "set": {"health_reporting": "CONTINUOUS", "tcp_ports": {"add": "8443"}}}
        p = ao.plan(client, spec, scope=ZPA)
        assert p["status"] == "ready" and p["counts"]["change"] == 2
        r = ao.execute(client, spec, plan_hash=p["plan_hash"], scope=ZPA, writes_enabled=True, assessor="Jane Doe", tenant_label="sample")
        assert r["status"] == "applied" and r["verification"]["confirmed"] == 2, r
        again = {s["name"]: s for s in ao.read_objects(client, "zpa_segment_bulk", ZPA)["segments"]}["Freight billing"]
        assert again["health_reporting"] == "CONTINUOUS" and again["tcp"] == ["443", "8443"] and again["server_groups"] == ["Portland data centre"]
    finally:
        offline_tenant.sample_store(reset=True)
