"""Bulk changes (admin_ops): plan, preview, conflict guard, apply, records,
undo, and the endpoints' gates, against a fake tenant that behaves like
ZIA and ZPA where it matters (rule order renumbering, incremental URL
lists, ZPA's update replacing the segment)."""
from __future__ import annotations

import copy
import json
import random
import threading

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import deployments
import pack_channels as pc
import pack_ops as ops

# ---------------------------------------------------------------------------
# The fake tenant
# ---------------------------------------------------------------------------


class Resp:
    def __init__(self, items=None):
        self._items = items or []

    def get_results(self):
        return self._items

    def has_next(self):
        return False


def ok(data):
    return copy.deepcopy(data), Resp(copy.deepcopy(data) if isinstance(data, list) else []), None


def refused(message, status=400):
    return None, None, {"status": status, "message": message}


WRITE_PREFIXES = ("add_", "update_", "delete_", "bulk_")


class Guarded:
    """Base for fake services: every write is logged in tenant.writes, and
    refused outright while the tenant is frozen (the preview guard)."""

    def __init__(self, tenant, name):
        self.tenant, self.name = tenant, name
        self.fail = {}        # (method, id) -> error tuple, or method -> callable

    def _write(self, method, oid, body):
        if self.tenant.frozen:
            raise AssertionError(f"write during a read-only step: {self.name}.{method}({oid})")
        self.tenant.writes.append((self.name, method, oid, copy.deepcopy(body)))
        hook = self.fail.get(method)
        if callable(hook):
            return hook(oid, body)
        return self.fail.get((method, str(oid)))


class FakeRules(Guarded):
    """A ZIA rule service. Order works as in ZIA: a PUT with order k puts
    the rule at position k among the ordered rules and renumbers 1..n; the
    Default rule stays last."""

    def __init__(self, tenant, name, rows):
        super().__init__(tenant, name)
        self.rows = [dict(r) for r in rows]
        self.on_get = None

    def _sorted(self, rows=None):
        rows = self.rows if rows is None else rows
        return sorted(rows, key=lambda r: (1 if r.get("default_rule") else 0, r.get("order", 0)))

    def _find(self, rid):
        return next((r for r in self.rows if str(r["id"]) == str(rid)), None)

    def list_rules(self, *a, **kw):
        if self.tenant.read_error:
            return refused(*self.tenant.read_error)
        return ok(self._sorted())

    def get_rule(self, rule_id, *a):
        if self.on_get:
            self.on_get(rule_id)
        if self.tenant.read_error:
            return refused(*self.tenant.read_error)
        r = self._find(rule_id)
        return ok(r) if r else refused("not found", 404)

    def update_rule(self, rule_id, **kw):
        bad = self._write("update_rule", rule_id, kw)
        if bad:
            return bad
        r = self._find(rule_id)
        if r is None:
            return refused("not found", 404)
        want = kw.get("order")
        r.update({k: v for k, v in kw.items() if k != "order"})
        if want is not None and int(want) != r["order"]:
            ordered = [x for x in self._sorted() if not x.get("default_rule")]
            ordered.remove(r)
            ordered.insert(int(want) - 1, r)
            for i, x in enumerate(ordered, 1):
                x["order"] = i
        return ok(r)


class FakeCAC(FakeRules):
    """Cloud App Control: rules are ordered per application type."""

    def update_rule(self, rule_type, rule_id, **kw):
        others = [r for r in self.rows if r.get("type") != rule_type]
        self.rows = [r for r in self.rows if r.get("type") == rule_type]
        try:
            return FakeRules.update_rule(self, rule_id, **kw)
        finally:
            self.rows = self.rows + others

    def list_rules(self, rule_type, *a, **kw):
        return ok([r for r in self._sorted() if r.get("type") == rule_type])

    def get_rule(self, rule_type, rule_id):
        r = self._find(rule_id)
        return ok(r) if r and r.get("type") == rule_type else refused("not found", 404)


class FakeCasb(FakeRules):
    def list_all_rules(self):
        return ok(self._sorted())

    def get_rule(self, rule_id, rule_type=None):
        return FakeRules.get_rule(self, rule_id)


class FakeCategories(Guarded):
    def __init__(self, tenant, rows):
        super().__init__(tenant, "url_categories")
        self.rows = [dict(r) for r in rows]
        self.quota = 1000

    def _find(self, cid):
        return next((c for c in self.rows if str(c["id"]) == str(cid)), None)

    def list_categories(self, query_params=None):
        if self.tenant.read_error:
            return refused(*self.tenant.read_error)
        return ok(self.rows)

    def get_category(self, category_id):
        if self.tenant.read_error:
            return refused(*self.tenant.read_error)
        c = self._find(category_id)
        return ok(c) if c else refused("not found", 404)

    def add_url_category(self, super_category, urls=None, configured_name=None, **kw):
        bad = self._write("add_url_category", None, dict(kw, super_category=super_category, urls=urls, configured_name=configured_name))
        if bad:
            return bad
        cid = f"CUSTOM_{len(self.rows) + 10:02d}"
        row = {"id": cid, "configured_name": configured_name, "super_category": super_category, "urls": list(urls or []),
               "custom_category": True, "description": kw.get("description")}
        self.rows.append(row)
        return ok(row)

    def update_url_category(self, category_id, action=None, **kw):
        bad = self._write("update_url_category", category_id, dict(kw, action=action))
        if bad:
            return bad
        c = self._find(category_id)
        if c is None:
            return refused("not found", 404)
        assert kw.get("configured_name") == c["configured_name"], "the name travels with an incremental update"
        if action == "ADD_TO_LIST":
            c["urls"] = c["urls"] + [u for u in kw["urls"] if u not in c["urls"]]
        elif action == "REMOVE_FROM_LIST":
            c["urls"] = [u for u in c["urls"] if u not in kw["urls"]]
        else:
            c["urls"] = list(kw.get("urls") or [])
        return ok(c)

    def delete_category(self, category_id):
        bad = self._write("delete_category", category_id, {})
        if bad:
            return bad
        self.rows = [c for c in self.rows if str(c["id"]) != str(category_id)]
        return None, None, None

    def get_quota(self):
        return {"remainingUrlsQuota": self.quota}


class FakeSegments(Guarded):
    """ZPA application segments. update_segment replaces the segment, and
    (as the SDK does) clears the port ranges it is not given."""

    def __init__(self, tenant, rows):
        super().__init__(tenant, "application_segment")
        self.rows = [dict(r) for r in rows]
        self.next_id = 900

    def _find(self, sid):
        return next((s for s in self.rows if str(s["id"]) == str(sid)), None)

    def list_segments(self, query_params=None):
        return ok(self.rows)

    def get_segment(self, segment_id, query_params=None):
        s = self._find(segment_id)
        return ok(s) if s else refused("not found", 404)

    def add_segment(self, **kw):
        bad = self._write("add_segment", None, kw)
        if bad:
            return bad
        assert kw.get("server_group_ids") and kw.get("segment_group_id") and kw.get("domain_names")
        self.next_id += 1
        row = {"id": str(self.next_id), "name": kw["name"], "domain_names": list(kw["domain_names"]), "segment_group_id": kw["segment_group_id"],
               "server_groups": [{"id": g} for g in kw["server_group_ids"]], "tcp_port_ranges": list(kw.get("tcp_port_ranges") or []),
               "udp_port_ranges": list(kw.get("udp_port_ranges") or []), "enabled": kw.get("enabled", True), "description": kw.get("description")}
        self.rows.append(row)
        return ok(row)

    def update_segment(self, segment_id, **kw):
        bad = self._write("update_segment", segment_id, kw)
        if bad:
            return bad
        s = self._find(segment_id)
        if s is None:
            return refused("not found", 404)
        s.update(name=kw.get("name", s["name"]), domain_names=list(kw.get("domain_names") or []),
                 tcp_port_ranges=list(kw.get("tcp_port_ranges") or []), udp_port_ranges=list(kw.get("udp_port_ranges") or []),
                 server_groups=[{"id": g} for g in kw.get("server_group_ids") or []], segment_group_id=kw.get("segment_group_id"))
        return ok(s)

    def delete_segment(self, segment_id, force_delete=False, microtenant_id=None):
        bad = self._write("delete_segment", segment_id, {})
        if bad:
            return bad
        self.rows = [s for s in self.rows if str(s["id"]) != str(segment_id)]
        return None, None, None


def rule(rid, name, order, state="ENABLED", **kw):
    return dict({"id": rid, "name": name, "order": order, "state": state, "rank": 7}, **kw)


URL_RULES = [rule(101, "Block gambling", 1), rule(102, "Allow finance", 2, url_categories=["CUSTOM_01"]),
             rule(103, "Caution social", 3, state="DISABLED"), rule(104, "Block custom", 4, url_categories=["CUSTOM_02"]),
             rule(105, "Zscaler predefined", 5, predefined=True), rule(199, "Default URL Filtering Rule", -1, default_rule=True)]
WEB_RULES = [rule(201, "Web DLP - PCI", 1), rule(202, "Web DLP - PHI", 2, url_categories=["CUSTOM_01"]),
             rule(203, "Web DLP - child", 3, parent_rule=201)]
CATEGORIES = [{"id": "CUSTOM_01", "configured_name": "Finance partners", "super_category": "USER_DEFINED", "custom_category": True,
               "urls": ["bank.example.com", ".pay.example.net"]},
              {"id": "CUSTOM_02", "configured_name": "Blocked extra", "super_category": "USER_DEFINED", "custom_category": True,
               "urls": ["bad.example.org"]},
              {"id": "MUSIC", "configured_name": "Music", "super_category": "ENTERTAINMENT", "custom_category": False, "urls": []}]
SEGMENTS = [{"id": "s1", "name": "Intranet", "domain_names": ["wiki.corp.example", "hr.corp.example"], "segment_group_id": "g1",
             "server_groups": [{"id": "sg1"}], "tcp_port_ranges": ["443", "443"], "udp_port_ranges": [], "enabled": True},
            {"id": "s2", "name": "Intranet web", "domain_names": ["portal.corp.example"], "segment_group_id": "g1",
             "server_groups": [{"id": "sg1"}], "tcp_port_ranges": ["443", "443", "8443", "8443"], "udp_port_ranges": [], "enabled": True},
            {"id": "s3", "name": "SSH hosts", "domain_names": ["jump.corp.example"], "segment_group_id": "g2",
             "server_groups": [{"id": "sg2"}], "tcp_port_ranges": ["22", "22"], "udp_port_ranges": [], "enabled": True},
            {"id": "s4", "name": "Legacy", "domain_names": ["old.corp.example", "*.lab.corp.example"], "segment_group_id": "g2",
             "server_groups": [{"id": "sg2"}], "tcp_port_ranges": ["1", "1000"], "udp_port_ranges": [], "enabled": True}]


class Tenant:
    def __init__(self, url_rules=None, web_rules=None, categories=None, segments=None):
        self.writes = []
        self.frozen = False
        self.read_error = None
        z = type("Zia", (), {})()
        z.url_filtering = FakeRules(self, "url_filtering", URL_RULES if url_rules is None else url_rules)
        z.ssl_inspection_rules = FakeRules(self, "ssl_inspection_rules", [rule(301, "Decrypt all", 1), rule(399, "Default SSL", -1, default_rule=True)])
        z.cloud_firewall_rules = FakeRules(self, "cloud_firewall_rules", [rule(401, "Allow DNS", 1), rule(402, "Block telnet", 2, state="DISABLED"),
                                                                            rule(403, "Default Firewall Filtering Rule", 3, predefined=True)])
        z.cloudappcontrol = FakeCAC(self, "cloudappcontrol", [rule(501, "AI uploads", 1, type="AI_ML"), rule(502, "AI chat", 2, type="AI_ML"),
                                                               rule(511, "Webmail send", 1, type="WEBMAIL")])
        z.file_type_control_rule = FakeRules(self, "file_type_control_rule", [rule(601, "Block exe", 1)])
        z.dlp_web_rules = FakeRules(self, "dlp_web_rules", WEB_RULES if web_rules is None else web_rules)
        z.endpoint_dlp_rules = FakeRules(self, "endpoint_dlp_rules", [rule(701, "USB PCI", 1)])
        z.outbound_email_dlp_rules = FakeRules(self, "outbound_email_dlp_rules", [rule(801, "Email PCI", 1)])
        z.casb_dlp_rules = FakeCasb(self, "casb_dlp_rules", [rule(901, "SaaS PCI", 1, type="OFLCASB_DLP_FILE")])
        z.url_categories = FakeCategories(self, CATEGORIES if categories is None else categories)
        zp = type("Zpa", (), {})()
        zp.application_segment = FakeSegments(self, SEGMENTS if segments is None else segments)
        self.zia, self.zpa = z, zp

    def writes_of(self, method):
        return [w for w in self.writes if w[1] == method]


FULL_SCOPE = ao.scope_for(["dlp", "zia_extras", "zpa"], {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb",
                                                                                  "cloud_app_control", "ssl_inspection")})


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    return acts


def preview(t, spec, scope=FULL_SCOPE):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme (zscalertwo)")
    finally:
        t.frozen = False


def apply(t, spec, prepared=None, **kw):
    prepared = prepared or preview(t, spec)
    kw.setdefault("confirm_text", prepared["confirm_phrase"])
    return ao.execute(t, spec, plan_hash=prepared["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor="Jane Doe",
                      tenant_label="acme (zscalertwo)", **kw)


def by_key(result):
    return {u["key"]: u for u in result["items"]}


def audit_entries(tmp_audit=None):
    import audit
    try:
        return [json.loads(l) for l in open(audit.path(), encoding="utf-8")]
    except FileNotFoundError:
        return []


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------

def test_scope_follows_the_scope_page():
    s = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
    assert "web_dlp" in s["policies"] and "firewall" not in s["policies"] and "email_dlp" not in s["policies"]
    assert s["url_categories"] and not s["zpa"]
    assert "ZPA is not ticked" in s["not_in_scope"]["zpa_segments"]
    with pytest.raises(ao.OperationError, match="ZPA is not ticked"):
        ao.require_scope({"type": "zpa_domains"}, s)
    with pytest.raises(ao.OperationError, match="Cloud Firewall"):
        ao.require_scope({"type": "rule_state", "targets": [{"policy": "firewall", "id": 1}]}, s)
    assert ao.scope_for([], {})["policies"] == []
    with pytest.raises(ao.OperationError, match="No rule policy"):
        ao.require_scope("rules", ao.scope_for([], {}))
    full = FULL_SCOPE
    assert set(full["policies"]) == set(ao.POLICIES) and full["zpa"] and full["url_categories"]


# ---------------------------------------------------------------------------
# Mass enable / disable
# ---------------------------------------------------------------------------

def test_rule_state_preview_lists_changes_noops_and_exclusions_and_writes_nothing():
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [
        {"policy": "url_filtering", "id": 101}, {"policy": "url_filtering", "id": 103}, {"policy": "url_filtering", "id": 105},
        {"policy": "url_filtering", "id": 199}, {"policy": "url_filtering", "id": 12345}, {"policy": "firewall", "id": 401},
        {"policy": "cloud_app_control", "id": 502, "rule_type": "AI_ML"}, {"policy": "url_filtering", "id": 101}]}
    p = preview(t, spec)
    assert t.writes == []
    st = {(u["object"]["policy"], str(u["object"]["id"])): (u["status"], u["before"], u["after"], u["reason"]) for u in p["items"]}
    assert st[("url_filtering", "101")][:3] == ("change", "ENABLED", "DISABLED")
    assert st[("url_filtering", "103")][:2] == ("noop", "DISABLED")
    assert st[("url_filtering", "105")][0] == "excluded" and "predefined" in st[("url_filtering", "105")][3]
    assert st[("url_filtering", "199")][0] == "excluded" and "Default rule" in st[("url_filtering", "199")][3]
    assert st[("url_filtering", "12345")][0] == "excluded" and "no such rule" in st[("url_filtering", "12345")][3]
    assert st[("firewall", "401")][0] == "change" and st[("cloud_app_control", "502")][0] == "change"
    assert p["counts"] == {"change": 3, "noop": 1, "excluded": 3, "total": 7}, "the duplicate target is counted once"
    assert p["title"] == "Disable 3 rules" and p["status"] == "ready" and p["confirm_phrase"] == ""
    assert len(p["plan_hash"]) == 64 and p["needs_activation"]


def test_rule_state_limits_and_bad_values_are_refused():
    t = Tenant()
    with pytest.raises(ao.OperationError, match="At most 100"):
        preview(t, {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in range(101)]})
    with pytest.raises(ao.OperationError, match="ENABLED or DISABLED"):
        preview(t, {"type": "rule_state", "value": "BLOCK", "targets": [{"policy": "url_filtering", "id": 101}]})
    with pytest.raises(ao.OperationError, match="Pick at least one"):
        preview(t, {"type": "rule_state", "value": "DISABLED", "targets": []})


def test_rule_state_applies_activates_once_verifies_records_and_audits(_isolated, monkeypatch):
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}, {"policy": "firewall", "id": 401},
                                                                  {"policy": "cloud_app_control", "id": 502, "rule_type": "AI_ML"},
                                                                  {"policy": "web_dlp", "id": 202}]}
    with ops.audit_scope(actor="alice@example.com"):
        res = apply(t, spec)
    assert res["status"] == "applied", res["counts_run"]
    assert res["counts_run"]["applied"] == 4 and res["verification"]["confirmed"] == 4
    assert _isolated == [1], "one activation after the last write"
    updates = t.writes_of("update_rule")
    assert {w[0] for w in updates} == {"url_filtering", "cloud_firewall_rules", "cloudappcontrol", "dlp_web_rules"}
    body = next(w[3] for w in updates if w[0] == "url_filtering")
    assert body["state"] == "DISABLED" and body["name"] == "Block gambling" and body["order"] == 1, "the rule goes back as read, one field changed"
    assert "id" not in body
    assert next(w[3] for w in updates if w[0] == "cloudappcontrol")["type"] == "AI_ML"
    assert t.zia.url_filtering._find(101)["state"] == "DISABLED"
    rec = ao.record(res, by="Jane Doe", actor="alice@example.com", tenant_ids={"tenant_key": "k1"})
    assert rec and deployments.get_operation(rec["id"])["inverse"] == res["inverse"]
    listed = deployments.list_operations()
    assert listed[0]["id"] == rec["id"] and listed[0]["can_undo"] and listed[0]["by"] == "Jane Doe" and listed[0]["actor"] == "alice@example.com"
    assert deployments.list_all() == [], "a bulk change is not a pack deployment"
    entries = audit_entries()
    writes = [e for e in entries if e["event"] == "object_write"]
    assert len(writes) == 4 and all(e["actor"] == "alice@example.com" and e["action"] == "update" and e["result"] == "ok" for e in writes)
    summary = next(e for e in entries if e["event"] == "run_finished" and e.get("run") == "operation")
    assert summary["counts"]["updated"] == 4 and summary["plan_hash"] == res["plan_hash"] and summary["actor"] == "alice@example.com"
    op = next(e for e in entries if e["event"] == "admin_operation")
    assert op["actor"] == "alice@example.com" and op["operation"] == rec["id"] and op["by"] == "Jane Doe"


def test_undo_builds_the_exact_inverse_and_applying_it_restores_the_tenant():
    t = Tenant()
    before = copy.deepcopy(t.zia.url_filtering.rows)
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102, 103)]}
    res = apply(t, spec)
    assert res["inverse"] == {"type": "rule_state", "targets": [{"policy": "url_filtering", "id": 101, "rule_type": "", "to": "ENABLED"},
                                                               {"policy": "url_filtering", "id": 102, "rule_type": "", "to": "ENABLED"}]}, \
        "only what was applied is reversed (103 was already disabled)"
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and t.zia.url_filtering.rows == before
    assert ao.inverse(undo) == {"type": "rule_state", "targets": [{"policy": "url_filtering", "id": 101, "rule_type": "", "to": "DISABLED"},
                                                                 {"policy": "url_filtering", "id": 102, "rule_type": "", "to": "DISABLED"}]}


def test_typed_confirmation_above_ten_changes():
    t = Tenant(url_rules=[rule(i, f"R{i}", i) for i in range(1, 13)])
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in range(1, 13)]}
    p = preview(t, spec)
    assert p["counts"]["change"] == 12 and p["confirm_phrase"] == "APPLY 12 CHANGES"
    res = apply(t, spec, p, confirm_text="apply 11 changes")
    assert res["status"] == "refused" and "APPLY 12 CHANGES" in res["message"] and t.writes == []
    assert apply(t, spec, p, confirm_text="apply 12 changes")["status"] == "applied"


def test_execute_refuses_without_write_mode_or_matching_plan_hash():
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
    p = preview(t, spec)
    with pytest.raises(PermissionError):
        ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=False)
    res = ao.execute(t, spec, plan_hash="0" * 64, scope=FULL_SCOPE, writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "plan_changed" and t.writes == []
    t.zia.url_filtering._find(101)["name"] = "Renamed"     # the tenant moved after the preview
    res = ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor="Jane Doe")
    assert res["status"] == "plan_changed" and res["current_hash"] != p["plan_hash"] and t.writes == []


def test_conflict_guard_skips_an_item_changed_since_the_plan_and_never_overwrites_it():
    t = Tenant()
    svc = t.zia.url_filtering

    def someone_else(rid):   # an admin flips 102 between the plan and its write
        if str(rid) == "102":
            svc._find(102)["state"] = "DISABLED"
    svc.on_get = someone_else
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102, 104)]}
    p = preview(t, spec)
    res = apply(t, spec, p)
    k = {str(u["object"]["id"]): u for u in res["items"]}
    assert k["102"]["status"] == "conflict" and "the preview read ENABLED" in k["102"]["reason"]
    assert k["101"]["status"] == k["104"]["status"] == "applied"
    assert [w[2] for w in t.writes_of("update_rule")] == [101, 104], "no write for the conflicted rule"
    assert res["status"] == "partial"
    assert res["inverse"]["targets"] == [{"policy": "url_filtering", "id": 101, "rule_type": "", "to": "ENABLED"},
                                         {"policy": "url_filtering", "id": 104, "rule_type": "", "to": "ENABLED"}]


def test_an_item_level_failure_is_reported_and_the_run_goes_on():
    t = Tenant()
    t.zia.url_filtering.fail[("update_rule", "102")] = refused("Request body is invalid", 400)
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102, 104)]}
    res = apply(t, spec)
    k = {str(u["object"]["id"]): u for u in res["items"]}
    assert k["102"]["status"] == "failed" and k["102"]["http_status"] == 400 and "HTTP 400" in k["102"]["explanation"]
    assert k["101"]["status"] == k["104"]["status"] == "applied" and res["status"] == "partial"
    assert res["summary"]["failed"] == 1 and res["summary"]["modified"] == 2


def test_a_rate_limit_stops_the_run_with_the_reason_and_nothing_more_is_sent(_isolated):
    t = Tenant()
    t.zia.url_filtering.fail["update_rule"] = lambda oid, body: refused("Rate Limit (1/SECOND) exceeded", 429)
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102, 104)]}
    res = apply(t, spec)
    assert res["stopped"] == ops.RATE_STOP_REASON
    assert len(t.writes_of("update_rule")) == 1 + ops.RATE_WINDOWS, "one rule: the first try and one per window, then the stop"
    st = [u["status"] for u in res["items"]]
    assert st.count("failed") == 1 and st.count("skipped") == 2 and res["status"] == "failed"
    assert all("not attempted" in u["reason"] for u in res["items"] if u["status"] == "skipped")
    assert _isolated == [], "nothing was written, so nothing is activated"


def test_a_rate_limited_or_refused_re_read_stops_the_run():
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102)]}
    p = preview(t, spec)
    calls = []

    def blocked(rid):
        calls.append(rid)
        t.read_error = ("Resource Access Blocked", 403)
    t.zia.url_filtering.on_get = blocked
    res = apply(t, spec, p)
    assert res["stopped"] == ao.READ_RATE_STOP and t.writes == []
    assert [u["status"] for u in res["items"]] == ["skipped", "skipped"] and len(calls) == 1


def test_stop_before_a_write_sends_nothing_more():
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": i} for i in (101, 102, 104)]}
    p = preview(t, spec)
    cancel = threading.Event()
    t.zia.url_filtering.fail["update_rule"] = lambda oid, body: (cancel.set() or None)
    res = apply(t, spec, p, cancel=cancel)
    assert len(t.writes_of("update_rule")) == 1 and res["status"] == "partial"
    assert [u["status"] for u in res["items"]] == ["applied", "skipped", "skipped"]


# ---------------------------------------------------------------------------
# Reordering
# ---------------------------------------------------------------------------

def _lis(seq, must=()):
    """The longest increasing subsequence that contains every index in
    `must` (a reference written apart from admin_ops' weighted version)."""
    must = set(must)
    best = [None] * len(seq)
    for i, x in enumerate(seq):
        cands = [best[j] for j in range(i) if best[j] is not None and seq[j] < x and not any(j < k < i for k in must)]
        if not any(k < i for k in must):
            cands.append(0)
        best[i] = 1 + max(cands) if cands else None
    tail = [best[i] for i in range(len(seq)) if best[i] is not None and not any(k > i for k in must)]
    return max(tail, default=0 if not must else None)


def _apply_moves(current, steps):
    sim = list(current)
    for s in steps:
        assert sim == s["before"]
        sim.remove(s["id"])
        sim.insert(s["index"], s["id"])
        assert sim == s["after"]
    return sim


def test_minimal_moves_property_over_random_orders():
    rnd = random.Random(20261025)
    for _ in range(400):
        n = rnd.randint(0, 14)
        current = [f"r{i}" for i in range(n)]
        locked = set(rnd.sample(current, rnd.randint(0, min(3, n)))) if n else set()
        movable = [r for r in current if r not in locked]
        rnd.shuffle(movable)
        it = iter(movable)
        desired = [r if r in locked else next(it) for r in current]
        steps = ao.minimal_moves(current, desired, locked)
        assert _apply_moves(current, steps) == desired
        assert not ({s["id"] for s in steps} & locked), "a locked rule never moves"
        assert len({s["id"] for s in steps}) == len(steps), "each rule moves at most once"
        pos = {r: i for i, r in enumerate(current)}
        seq = [pos[r] for r in desired]
        assert len(steps) == n - _lis(seq, [i for i, r in enumerate(desired) if r in locked]), \
            "the fewest moves that leave the locked rules in place"
        if not locked:
            assert len(steps) == n - _lis(seq), "without locked rules: everything outside a longest increasing subsequence"


def test_minimal_moves_refuses_a_wrong_order():
    with pytest.raises(ao.OperationError):
        ao.minimal_moves(["a", "b"], ["a", "c"])
    with pytest.raises(ao.OperationError, match="locked"):
        ao.minimal_moves(["a", "b", "c"], ["b", "a", "c"], locked={"a"})


def test_reorder_plans_the_fewest_moves_keeps_locked_rules_and_reaches_the_order():
    t = Tenant()
    spec = {"type": "reorder", "policy": "url_filtering", "order": [104, 101, 102, 103]}
    p = preview(t, spec)
    assert t.writes == []
    moves = [u for u in p["items"] if u["status"] == "change"]
    assert [u["object"]["id"] for u in moves] == [104] and moves[0]["before"] == 4 and moves[0]["after"] == 1
    st = {u["object"]["id"]: u["status"] for u in p["items"]}
    assert st[105] == "excluded" and st[199] == "excluded" and st[101] == st[102] == st[103] == "noop"
    assert p["title"] == "Reorder URL filtering: 1 move"
    res = apply(t, spec)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 1
    seq = [r["id"] for r in t.zia.url_filtering._sorted()]
    assert seq == [104, 101, 102, 103, 105, 199]
    body = t.writes_of("update_rule")[0][3]
    assert body["order"] == 1 and body["name"] == "Block custom" and body["url_categories"] == ["CUSTOM_02"], "rule content untouched"
    # Undo puts the original order back, with its own minimal plan.
    assert res["inverse"] == {"type": "reorder", "policy": "url_filtering", "rule_type": "", "order": ["101", "102", "103", "104"]}
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and [r["id"] for r in t.zia.url_filtering._sorted()] == [101, 102, 103, 104, 105, 199]


def test_reorder_property_on_the_fake_tenant():
    rnd = random.Random(7)
    for _ in range(25):
        n = rnd.randint(2, 9)
        rows = [rule(i, f"R{i}", i) for i in range(1, n + 1)] + [rule(99, "Default", -1, default_rule=True)]
        if n > 3:
            rows[2]["predefined"] = True
        t = Tenant(url_rules=rows)
        movable = [r["id"] for r in rows if not r.get("predefined") and not r.get("default_rule")]
        rnd.shuffle(movable)
        res = apply(t, {"type": "reorder", "policy": "url_filtering", "order": movable})
        it = iter(movable)
        want = [r["id"] if (r.get("predefined") or r.get("default_rule")) else next(it) for r in sorted(rows, key=lambda r: (r.get("default_rule", False), r["order"]))]
        assert [r["id"] for r in t.zia.url_filtering._sorted()] == want
        assert res["status"] in ("applied", "nothing_to_do")


def test_reorder_refuses_orders_that_move_locked_rules_or_miss_rules():
    t = Tenant()
    with pytest.raises(ao.OperationError, match="never move"):
        preview(t, {"type": "reorder", "policy": "url_filtering", "order": [104, 101, 102, 103, 105]})
    with pytest.raises(ao.OperationError, match="missing"):
        preview(t, {"type": "reorder", "policy": "url_filtering", "order": [104, 101]})
    with pytest.raises(ao.OperationError, match="no documented evaluation order"):
        preview(t, {"type": "reorder", "policy": "saas_dlp", "order": [901]})
    with pytest.raises(ao.OperationError, match="rule_type"):
        preview(t, {"type": "reorder", "policy": "cloud_app_control", "order": [502, 501]})
    p = preview(t, {"type": "reorder", "policy": "web_dlp", "order": [202, 201]})
    assert any(u["object"]["id"] == 203 and u["status"] == "excluded" and "exception rule" in u["reason"] for u in p["items"])


def test_reorder_stops_when_someone_moves_a_rule_during_the_run():
    t = Tenant(url_rules=[rule(i, f"R{i}", i) for i in range(1, 6)])
    spec = {"type": "reorder", "policy": "url_filtering", "order": [5, 4, 1, 2, 3]}
    p = preview(t, spec)
    assert p["counts"]["change"] == 2
    svc = t.zia.url_filtering
    real = svc.update_rule

    def update_then_interfere(rule_id, **kw):
        out = real(rule_id, **kw)
        svc._find(3)["order"], svc._find(2)["order"] = svc._find(2)["order"], svc._find(3)["order"]   # an admin swaps two rules
        return out
    svc.update_rule = update_then_interfere
    res = apply(t, spec, p)
    st = {u["object"]["id"]: u["status"] for u in res["items"]}
    assert st[5] == "applied" and st[4] == "conflict" and len(t.writes_of("update_rule")) == 1, "the first move went out; the second saw the swap"
    assert res["status"] == "partial"


def test_cloud_app_control_reorders_within_one_type():
    t = Tenant()
    res = apply(t, {"type": "reorder", "policy": "cloud_app_control", "rule_type": "AI_ML", "order": [502, 501]})
    assert res["status"] == "applied"
    assert [r["id"] for r in t.zia.cloudappcontrol._sorted() if r["type"] == "AI_ML"] == [502, 501]
    assert t.writes_of("update_rule")[0][3]["type"] == "AI_ML"


# ---------------------------------------------------------------------------
# URL categories
# ---------------------------------------------------------------------------

def test_url_validation():
    assert ao.normalize_url("HTTPS://Example.COM/Path") == ("example.com/Path", None)
    assert ao.normalize_url(".Example.com") == (".example.com", None)
    assert ao.normalize_url("example.com:8443/x")[0] == "example.com:8443/x"
    assert ao.normalize_url("10.1.2.3")[0] == "10.1.2.3"
    for bad in ("*.example.com", "exa mple.com", "localhost", "example..com", "-bad.example.com", "example.com:99999", ""):
        assert ao.normalize_url(bad)[0] is None, bad
    assert ao.normalize_domain("*.Corp.Example") == ("*.corp.example", None)
    assert ao.normalize_domain("10.0.0.0/8") == ("10.0.0.0/8", None)
    assert ao.normalize_domain("bad_*_domain")[0] is None


def test_url_add_lists_noops_invalid_urls_and_the_rules_that_use_the_category():
    t = Tenant()
    spec = {"type": "url_categories", "action": "add", "target": "CUSTOM_01", "urls": ["new.example.com", "BANK.example.com", "*.nope.com", "new.example.com"]}
    p = preview(t, spec)
    assert t.writes == []
    st = {(u["value"], u["status"]) for u in p["items"]}
    assert ("new.example.com", "change") in st and ("bank.example.com", "noop") in st and ("*.nope.com", "excluded") in st
    assert p["counts"] == {"change": 1, "noop": 1, "excluded": 1, "total": 3}
    imp = p["impact"][0]
    assert imp["category"] == "Finance partners" and {r["name"] for r in imp["rules"]} == {"Allow finance", "Web DLP - PHI"}
    res = apply(t, spec)
    assert res["status"] == "applied" and "new.example.com" in t.zia.url_categories._find("CUSTOM_01")["urls"]
    w = t.writes_of("update_url_category")
    assert len(w) == 1 and w[0][3]["action"] == "ADD_TO_LIST" and w[0][3]["urls"] == ["new.example.com"]
    assert res["inverse"] == {"type": "url_categories", "action": "revert", "deltas": [{"category": "CUSTOM_01", "add": [], "remove": ["new.example.com"]}],
                              "delete_categories": []}


def test_url_move_adds_first_removes_after_and_undo_puts_them_back():
    t = Tenant()
    spec = {"type": "url_categories", "action": "move", "source": "CUSTOM_01", "target": "CUSTOM_02", "urls": ["bank.example.com", "missing.example.com"]}
    p = preview(t, spec)
    st = {(u["object"]["id"], u["value"]): u["status"] for u in p["items"]}
    assert st[("CUSTOM_02", "bank.example.com")] == "change" and st[("CUSTOM_01", "bank.example.com")] == "change"
    assert st[("CUSTOM_01", "missing.example.com")] == "excluded"
    assert {i["category"] for i in p["impact"]} == {"Finance partners", "Blocked extra"}
    res = apply(t, spec, p)
    assert [w[3]["action"] for w in t.writes_of("update_url_category")] == ["ADD_TO_LIST", "REMOVE_FROM_LIST"]
    cats = t.zia.url_categories
    assert "bank.example.com" in cats._find("CUSTOM_02")["urls"] and "bank.example.com" not in cats._find("CUSTOM_01")["urls"]
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied"
    assert sorted(cats._find("CUSTOM_01")["urls"]) == sorted(CATEGORIES[0]["urls"]) and cats._find("CUSTOM_02")["urls"] == CATEGORIES[1]["urls"]


def test_url_move_keeps_the_source_when_the_target_add_fails():
    t = Tenant()
    t.zia.url_categories.fail[("update_url_category", "CUSTOM_02")] = refused("Request body is invalid", 400)
    spec = {"type": "url_categories", "action": "move", "source": "CUSTOM_01", "target": "CUSTOM_02", "urls": ["bank.example.com"]}
    res = apply(t, spec)
    st = {(u["object"]["id"], u["status"]) for u in res["items"]}
    assert ("CUSTOM_02", "failed") in st and ("CUSTOM_01", "skipped") in st
    assert "bank.example.com" in t.zia.url_categories._find("CUSTOM_01")["urls"], "a move never loses a URL"


def test_url_copy_into_a_new_category_and_undo_deletes_it():
    t = Tenant()
    spec = {"type": "url_categories", "action": "copy", "source": "CUSTOM_01", "create_target": {"name": "Finance copy"},
            "urls": ["bank.example.com"]}
    p = preview(t, spec)
    assert any(u["kind"] == "create_category" and u["status"] == "change" for u in p["items"])
    res = apply(t, spec, p)
    new = next(c for c in t.zia.url_categories.rows if c["configured_name"] == "Finance copy")
    assert new["urls"] == ["bank.example.com"] and "Jane Doe" in new["description"] and "Zscaler Made Easy" not in new["description"]
    assert res["inverse"]["delete_categories"] == [{"id": new["id"], "name": "Finance copy", "urls": ["bank.example.com"]}]
    assert res["inverse"]["deltas"] == []
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and not any(c["configured_name"] == "Finance copy" for c in t.zia.url_categories.rows)
    # A category that was changed since, or that a rule uses, is kept.
    p2 = preview(t, {"type": "url_categories", "action": "revert", "deltas": [], "delete_categories": [{"id": "CUSTOM_02", "name": "Blocked extra",
                                                                                                      "urls": ["bad.example.org"]}]})
    assert p2["items"][0]["status"] == "excluded" and "still used" in p2["items"][0]["reason"]


def test_url_operations_refuse_predefined_categories_and_existing_names():
    t = Tenant()
    with pytest.raises(ao.OperationError, match="not a custom URL category"):
        preview(t, {"type": "url_categories", "action": "add", "target": "MUSIC", "urls": ["x.example.com"]})
    p = preview(t, {"type": "url_categories", "action": "copy", "source": "CUSTOM_01", "create_target": {"name": "blocked EXTRA"}, "urls": ["bank.example.com"]})
    assert p["status"] == "blocked" and "already exists" in p["blockers"][0]
    t.zia.url_categories.quota = 0
    p = preview(t, {"type": "url_categories", "action": "add", "target": "CUSTOM_02", "urls": ["x.example.com"]})
    assert p["status"] == "blocked" and "quota" in p["blockers"][0]


# ---------------------------------------------------------------------------
# ZPA application segments
# ---------------------------------------------------------------------------

def test_ports_overlap():
    assert ao.ports_overlap(SEGMENTS[0], SEGMENTS[1]) == ["TCP 443"]
    assert ao.ports_overlap(SEGMENTS[0], SEGMENTS[2]) == []
    assert ao.ports_overlap({"tcp_port_range": [{"from": "100", "to": "200"}]}, {"tcp_port_ranges": ["150", "300"]}) == ["TCP 150-200"]


def test_zpa_move_between_segments_that_share_ports_removes_first_and_keeps_the_ports():
    t = Tenant()
    spec = {"type": "zpa_domains", "action": "move", "source": "s1", "target": "s2", "domains": ["wiki.corp.example"]}
    p = preview(t, spec)
    assert t.writes == []
    assert [g["target"]["id"] for g in p["groups"]] == ["s1", "s2"], "the two segments share TCP 443: the domain leaves first"
    res = apply(t, spec, p)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 2
    segs = t.zpa.application_segment
    assert segs._find("s1")["domain_names"] == ["hr.corp.example"] and "wiki.corp.example" in segs._find("s2")["domain_names"]
    assert segs._find("s1")["tcp_port_ranges"] == ["443", "443"] and segs._find("s2")["tcp_port_ranges"] == ["443", "443", "8443", "8443"], \
        "update_segment replaces the segment: the ports are sent back as read"
    assert segs._find("s1")["server_groups"] == [{"id": "sg1"}]
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied"
    assert sorted(segs._find("s1")["domain_names"]) == sorted(SEGMENTS[0]["domain_names"]) and segs._find("s2")["domain_names"] == SEGMENTS[1]["domain_names"]


def test_zpa_move_without_shared_ports_adds_first():
    # s3 keeps a second domain: moving its only one is excluded (ZPA keeps one domain per segment).
    segs = [dict(s, domain_names=s["domain_names"] + ["bastion.corp.example"]) if s["id"] == "s3" else s for s in SEGMENTS]
    t = Tenant(segments=segs)
    p = preview(t, {"type": "zpa_domains", "action": "move", "source": "s3", "target": "s1", "domains": ["jump.corp.example"]})
    assert [g["target"]["id"] for g in p["groups"]] == ["s1", "s3"]


def test_zpa_overlap_check_excludes_a_domain_already_served_on_the_same_ports():
    t = Tenant()
    # Copy keeps the domain in the source: same domain, both on TCP 443 -> excluded.
    p = preview(t, {"type": "zpa_domains", "action": "copy", "source": "s1", "target": "s2", "domains": ["wiki.corp.example"]})
    u = next(x for x in p["items"] if x["value"] == "wiki.corp.example")
    assert u["status"] == "excluded" and "overlapping ports" in u["reason"] and "TCP 443" in u["reason"]
    # Copy to SSH hosts (TCP 22 only): no overlap.
    p = preview(t, {"type": "zpa_domains", "action": "copy", "source": "s1", "target": "s3", "domains": ["wiki.corp.example"]})
    assert next(x for x in p["items"] if x["value"] == "wiki.corp.example")["status"] == "change"
    # A wildcard elsewhere on overlapping ports is a warning, not an exclusion.
    p = preview(t, {"type": "zpa_domains", "action": "move", "source": "s1", "target": "s2", "domains": ["x.lab.corp.example", "not a domain"]})
    assert any("*.lab.corp.example" in w for w in p["warnings"])
    assert any(x["status"] == "excluded" and "not valid" in x["reason"] for x in p["items"])
    # A move whose target overlaps a third segment keeps the domain in the source.
    t2 = Tenant(segments=SEGMENTS + [{"id": "s5", "name": "Dup", "domain_names": ["hr.corp.example"], "segment_group_id": "g1",
                                      "server_groups": [{"id": "sg1"}], "tcp_port_ranges": ["8443", "8443"]}])
    p = preview(t2, {"type": "zpa_domains", "action": "move", "source": "s1", "target": "s2", "domains": ["hr.corp.example"]})
    st = {x["object"]["id"]: x for x in p["items"]}
    assert st["s2"]["status"] == "excluded" and "Dup" in st["s2"]["reason"]
    assert st["s1"]["status"] == "excluded" and st["s1"]["reason"].startswith("not moved")
    assert p["groups"] == []


def test_zpa_clone_with_move_and_undo_deletes_the_clone():
    t = Tenant()
    spec = {"type": "zpa_domains", "action": "clone", "source": "s1", "name": "HR portal", "domains": ["hr.corp.example"], "move": True}
    p = preview(t, spec)
    assert [g["handler"] for g in p["groups"]] == ["zpa_update", "zpa_create"]
    res = apply(t, spec, p)
    segs = t.zpa.application_segment
    new = next(s for s in segs.rows if s["name"] == "HR portal")
    assert new["domain_names"] == ["hr.corp.example"] and new["tcp_port_ranges"] == ["443", "443"] and new["server_groups"] == [{"id": "sg1"}]
    assert "Jane Doe" in new["description"]
    assert segs._find("s1")["domain_names"] == ["wiki.corp.example"]
    inv = res["inverse"]
    assert inv["delete_segments"] == [{"id": new["id"], "name": "HR portal", "domains": ["hr.corp.example"]}]
    assert inv["deltas"] == [{"segment": "s1", "add": ["hr.corp.example"], "remove": []}]
    undo = apply(t, inv)
    assert undo["status"] == "applied", [(u["key"], u["status"], u["reason"]) for u in undo["items"]]
    assert not any(s["name"] == "HR portal" for s in segs.rows) and sorted(segs._find("s1")["domain_names"]) == sorted(SEGMENTS[0]["domain_names"])


def test_zpa_clone_without_move_excludes_domains_the_source_serves_on_the_same_ports():
    t = Tenant()
    p = preview(t, {"type": "zpa_domains", "action": "clone", "source": "s1", "name": "Copy", "domains": ["wiki.corp.example"]})
    assert p["counts"]["change"] == 0 and p["groups"] == []
    p = preview(t, {"type": "zpa_domains", "action": "clone", "source": "s1", "name": "Intranet", "domains": ["new.corp.example"]})
    assert p["status"] == "blocked"


# ---------------------------------------------------------------------------
# The approval-queue request
# ---------------------------------------------------------------------------

def test_to_request_carries_kind_title_items_and_plan_hash():
    t = Tenant()
    p = preview(t, {"type": "rule_state", "value": "ENABLED", "targets": [{"policy": "url_filtering", "id": 103}]})
    r = ao.to_request(p)
    assert r["kind"] == "admin_operation" and r["op_type"] == "rule_state" and r["plan_hash"] == p["plan_hash"] and r["title"] == "Enable 1 rule"
    assert r["items"] == [{"key": p["items"][0]["key"], "object": p["items"][0]["object"], "field": "state", "value": None,
                           "before": "DISABLED", "after": "ENABLED", "status": "change", "reason": ""}]
    assert r["spec"] == p["spec"]
    json.dumps(r)
    # The spec in the request plans to the same hash: it can be filed now and applied after approval.
    assert ao.plan(t, r["spec"], scope=FULL_SCOPE, tenant_label="acme (zscalertwo)")["plan_hash"] == r["plan_hash"]


def test_the_plan_pdf_renders_a_preview():
    import report_exports
    t = Tenant()
    p = preview(t, {"type": "url_categories", "action": "move", "source": "CUSTOM_01", "target": "CUSTOM_02", "urls": ["bank.example.com"]})
    pdf = report_exports.operation_pdf(p)
    assert pdf.startswith(b"%PDF-") and pdf.rstrip().endswith(b"%%EOF")
    assert report_exports.operation_filename(p, "pdf").startswith("bulk_change_plan_acme")


def test_the_object_picker_reads_only_what_is_in_scope():
    t = Tenant()
    t.frozen = True
    scope = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
    out = ao.read_objects(t, "rules", scope)
    pols = [p["policy"] for p in out["policies"]]
    assert "web_dlp" in pols and "firewall" not in pols and "email_dlp" not in pols
    web = next(p for p in out["policies"] if p["policy"] == "web_dlp")
    assert next(r for r in web["rules"] if r["id"] == 203)["order_locked"]
    url = next(p for p in out["policies"] if p["policy"] == "url_filtering")
    assert next(r for r in url["rules"] if r["id"] == 199)["locked"]
    cats = ao.read_objects(t, "url_categories", scope)["categories"]
    assert [c["name"] for c in cats] == ["Blocked extra", "Finance partners"], "custom categories only"
    with pytest.raises(ao.OperationError):
        ao.read_objects(t, "zpa_segments", scope)
    segs = ao.read_objects(t, "zpa_segments", FULL_SCOPE)["segments"]
    assert segs[0]["name"] == "Intranet" and segs[0]["tcp"] == ["443"]
    assert "sanction" in out and "Sanction or unsanction cloud apps" in out["sanction"]
    assert t.writes == []


# ---------------------------------------------------------------------------
# The endpoints
# ---------------------------------------------------------------------------

import dlp_api_server as srv  # noqa: E402
import security  # noqa: E402

SCOPE_BODY = {"scopes": ["dlp", "zia_extras", "zpa"], "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb",
                                                                                             "cloud_app_control", "ssl_inspection")},
              "from_page": True, "client_id": "cid", "client_secret": "s3cret-value", "vanity_domain": "acme", "cloud": "zscalertwo",
              "assessor": "Jane Doe"}


@pytest.fixture
def api(monkeypatch):
    t = Tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    client = TestClient(srv.app)
    return client, t


def _write_mode(monkeypatch, on=True):
    monkeypatch.setattr(srv, "writes_enabled", lambda: on)


def test_endpoint_preview_and_apply_with_every_gate(api, monkeypatch):
    client, t = api
    op = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
    r = client.post("/api/operations/preview", json=dict(SCOPE_BODY, operation=op))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["counts"]["change"] == 1 and t.writes == [] and "s3cret" not in r.text
    body = dict(SCOPE_BODY, operation=op, plan_hash=p["plan_hash"], confirm=True)
    _write_mode(monkeypatch, False)
    r = client.post("/api/operations/apply", json=body)
    assert r.status_code == 403 and "ENABLE_WRITE_ACTIONS" in r.json()["detail"] and t.writes == []
    _write_mode(monkeypatch, True)
    assert client.post("/api/operations/apply", json=dict(body, confirm=False)).status_code == 400
    assert client.post("/api/operations/apply", json=dict(body, plan_hash="")).status_code == 400
    assert client.post("/api/operations/apply", json=dict(body, assessor="")).status_code == 400
    assert client.post("/api/operations/apply", json=dict(body, assessor="Zscaler Made Easy")).status_code == 400
    r = client.post("/api/operations/apply", json=dict(body, plan_hash="f" * 64))
    assert r.status_code == 409 and r.json()["status"] == "plan_changed" and t.writes == []
    monkeypatch.setattr(security, "may_write", lambda: False)
    r = client.post("/api/operations/apply", json=body)
    assert r.status_code == 403 and "may not change the tenant" in r.json()["detail"] and t.writes == []
    monkeypatch.setattr(security, "may_write", lambda: True)
    r = client.post("/api/operations/apply", json=body)
    assert r.status_code == 200, r.text
    res = r.json()
    assert res["status"] == "applied" and res["operation_id"].startswith("op-") and len(t.writes) == 1
    ops_list = client.get("/api/operations").json()["operations"]
    assert ops_list[0]["id"] == res["operation_id"] and ops_list[0]["can_undo"]
    rec = client.get(f"/api/operations/{res['operation_id']}").json()
    assert "tenant_key" not in rec and rec["items"][0]["before"] == "ENABLED"
    # Undo: a preview of the inverse, then the same apply with undo_of.
    r = client.post(f"/api/operations/{res['operation_id']}/undo/preview", json=SCOPE_BODY)
    assert r.status_code == 200, r.text
    u = r.json()
    assert u["undo_of"] == res["operation_id"] and u["counts"]["change"] == 1
    r = client.post("/api/operations/apply", json=dict(SCOPE_BODY, operation=u["operation"], plan_hash=u["plan_hash"], confirm=True,
                                                       undo_of=res["operation_id"]))
    assert r.status_code == 200 and r.json()["status"] == "applied"
    assert t.zia.url_filtering._find(101)["state"] == "ENABLED"
    first = next(o for o in client.get("/api/operations").json()["operations"] if o["id"] == res["operation_id"])
    assert first["undone_by"] and not first["can_undo"]
    assert client.post(f"/api/operations/{res['operation_id']}/undo/preview", json=SCOPE_BODY).status_code == 409


def test_endpoint_refuses_what_is_out_of_scope_before_signing_in(monkeypatch):
    called = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: called.append(1))
    client = TestClient(srv.app)
    body = dict(SCOPE_BODY, scopes=["dlp"], channels={"web_dlp": "zscaler"})
    r = client.post("/api/operations/preview", json=dict(body, operation={"type": "zpa_domains", "action": "move"}))
    assert r.status_code == 400 and "ZPA is not ticked" in r.json()["detail"]
    r = client.post("/api/operations/objects", json=dict(body, scopes=[], channels={}, family="rules"))
    assert r.status_code == 400
    assert called == []


def test_endpoint_jobs_plan_pdf_and_request(api):
    client, t = api
    import time as _t
    op = {"type": "url_categories", "action": "add", "target": "CUSTOM_02", "urls": ["x.example.com"]}
    r = client.post("/api/operations/preview/start", json=dict(SCOPE_BODY, operation=op))
    assert r.status_code == 200
    jid = r.json()["job_id"]
    for _ in range(100):
        snap = client.get(f"/api/dlp-packs/jobs/{jid}").json()
        if snap["status"] != "running":
            break
        _t.sleep(0.05)
    assert snap["status"] == "done" and snap["result"]["counts"]["change"] == 1
    pdf = client.get(f"/api/operations/jobs/{jid}/plan.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-") and "attachment" in pdf.headers["content-disposition"]
    req = client.get(f"/api/operations/jobs/{jid}/request").json()
    assert req["kind"] == "admin_operation" and req["plan_hash"] == snap["result"]["plan_hash"]
    assert client.get("/api/operations/jobs/nope/plan.pdf").status_code == 404
    assert client.get("/report/operations").status_code == 200
    assert t.writes == []
