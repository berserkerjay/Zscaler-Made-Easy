"""Cloud QA round 6, admin-ops slice: the Bulk changes engine (admin_ops)
and its plugin registry, the four-eyes change queue (change_queue), the
proposal queue (proposals) and the one-click fix recipes (remediation).

Regression, functionality and Secure by Design checks. No real tenant: the
fake ZIA / ZPA tenant from test_admin_ops, small fake raw clients and tmp
stores. Each test's first docstring line maps it to the standards it checks.
"""
from __future__ import annotations

import copy
import json
import os
import stat
import threading
from datetime import datetime

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import change_queue
import dlp_api_server as srv
import pack_channels as pc
import proposals
import remediation
import security
from test_admin_ops import FULL_SCOPE, SCOPE_BODY, Tenant, apply, by_key, preview, rule


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLPCHECK_CHANGE_QUEUE_FILE", str(tmp_path / "change_requests.json"))
    monkeypatch.setenv("DLPCHECK_PROPOSALS_FILE", str(tmp_path / "proposals.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.delenv("DLP_CHECK_FOUR_EYES", raising=False)
    monkeypatch.delenv("ENABLE_WRITE_ACTIONS", raising=False)
    monkeypatch.setattr(security, "_write_override", None)
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    yield tmp_path


# ═══════════════════════════════════════════════════════════════════════
# admin_ops: plan, plan hash, execute, verify, inverse per built-in type
# ═══════════════════════════════════════════════════════════════════════

def test_plan_never_writes_and_its_hash_is_stable_for_the_same_tenant():
    """ASVS V1.14.6 · A04:2021 · CWE-841 · WSTG-BUSL-06: planning reads only, and two plans of an unchanged tenant hash the same."""
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
    a, b = preview(t, spec), preview(t, spec)
    assert t.writes == [] and a["plan_hash"] == b["plan_hash"] and len(a["plan_hash"]) == 64


def test_the_plan_hash_changes_when_the_tenant_moves():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: a tenant change between preview and apply changes the plan_hash."""
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}, {"policy": "url_filtering", "id": 102}]}
    before = preview(t, spec)["plan_hash"]
    t.zia.url_filtering._find(102)["state"] = "DISABLED"
    assert preview(t, spec)["plan_hash"] != before


def test_rule_state_applies_verifies_and_its_inverse_restores_the_state():
    """ASVS V1.14.6 · CWE-841 · WSTG-BUSL-01: enable/disable applies, reads back, and Undo puts the old state back."""
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}, {"policy": "web_dlp", "id": 201}]}
    res = apply(t, spec)
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 2
    assert t.zia.url_filtering._find(101)["state"] == "DISABLED"
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and t.zia.url_filtering._find(101)["state"] == "ENABLED"
    assert t.zia.dlp_web_rules._find(201)["state"] == "ENABLED"


def test_reorder_applies_and_its_inverse_restores_the_original_order():
    """ASVS V1.14.6 · CWE-841 · WSTG-BUSL-01: a reorder reaches the desired order and Undo restores the previous one."""
    t = Tenant()
    original = [r["id"] for r in t.zia.url_filtering._sorted()]
    spec = {"type": "reorder", "policy": "url_filtering", "order": [104, 101, 103, 102]}
    res = apply(t, spec)
    assert res["status"] == "applied" and res["verification"]["confirmed"] >= 1
    assert [r["id"] for r in t.zia.url_filtering._sorted()][:4] == [104, 101, 103, 102]
    undo = apply(t, res["inverse"])
    assert undo["status"] == "applied" and [r["id"] for r in t.zia.url_filtering._sorted()] == original


def test_url_category_remove_and_its_inverse_adds_the_urls_back():
    """ASVS V1.14.6 · CWE-841 · WSTG-BUSL-01: a URL removal applies and Undo adds exactly the removed URL back."""
    t = Tenant()
    res = apply(t, {"type": "url_categories", "action": "remove", "source": "CUSTOM_01", "urls": ["bank.example.com", "nothere.example.com"]})
    assert res["status"] == "applied" and "bank.example.com" not in t.zia.url_categories._find("CUSTOM_01")["urls"]
    assert res["inverse"]["deltas"] == [{"category": "CUSTOM_01", "add": ["bank.example.com"], "remove": []}]
    apply(t, res["inverse"])
    assert "bank.example.com" in t.zia.url_categories._find("CUSTOM_01")["urls"]


def test_zpa_copy_applies_and_its_inverse_removes_only_the_copy():
    """ASVS V1.14.6 · CWE-841 · WSTG-BUSL-01: a ZPA domain copy applies; Undo removes it from the target and leaves the source."""
    t = Tenant()
    res = apply(t, {"type": "zpa_domains", "action": "copy", "source": "s1", "target": "s3", "domains": ["wiki.corp.example"]})
    assert res["status"] == "applied" and "wiki.corp.example" in t.zpa.application_segment._find("s3")["domain_names"]
    apply(t, res["inverse"])
    assert "wiki.corp.example" not in t.zpa.application_segment._find("s3")["domain_names"]
    assert "wiki.corp.example" in t.zpa.application_segment._find("s1")["domain_names"]


def test_inverse_of_a_result_with_nothing_applied_is_none():
    """ASVS V1.14.6 · CWE-754: nothing applied means nothing to undo (no blind rollback)."""
    assert ao.inverse({"type": "rule_state", "items": [{"status": "conflict"}]}) is None
    assert ao.inverse({"type": "no_such_type", "items": [{"status": "applied"}]}) is None


def test_sanction_is_not_an_operation_type_and_the_reason_is_shown():
    """ASVS V1.14.6 · CWE-20 · WSTG-BUSL-01: cloud app sanction is refused (no read of the before state) and the picker says why."""
    with pytest.raises(ao.OperationError):
        ao.plan(Tenant(), {"type": "sanction", "apps": [1]}, scope=FULL_SCOPE)
    assert "sanction" in ao.read_objects(Tenant(), "rules", FULL_SCOPE)["sanction"].lower()


def test_writes_off_raises_before_anything_is_read():
    """ASVS V1.14.6 · A01:2021 · CWE-841 · WSTG-BUSL-06: execute refuses with write mode off, before re-planning."""
    t = Tenant()
    t.read_error = ("should not be read", 500)
    with pytest.raises(PermissionError):
        ao.execute(t, {"type": "rule_state"}, plan_hash="x", scope=FULL_SCOPE, writes_enabled=None)
    assert t.writes == []


# ── concurrent edits: two people, one rule ─────────────────────────────

def test_two_people_previewing_the_same_change_only_the_first_applies():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: the second person's apply sees the tenant moved (plan_changed) and writes nothing."""
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
    alice, bob = preview(t, spec), preview(t, spec)
    assert apply(t, spec, alice)["status"] == "applied"
    n = len(t.writes)
    second = apply(t, spec, bob)
    assert second["status"] == "plan_changed" and len(t.writes) == n


def test_the_conflict_guard_skips_a_url_someone_added_during_the_run():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: a URL added by someone else after the re-plan is a conflict; nothing is overwritten."""
    t = Tenant()
    spec = {"type": "url_categories", "action": "add", "target": "CUSTOM_02", "urls": ["new.example.com"]}
    p = preview(t, spec)
    cats = t.zia.url_categories
    real = cats.get_category

    def someone_else(cid):
        c = cats._find(cid)
        c["urls"] = c["urls"] + ["new.example.com"]   # a new list: the fake shares its rows' lists with the module's data
        return real(cid)
    cats.get_category = someone_else
    res = apply(t, spec, p)
    assert by_key(res)["cat:CUSTOM_02:+new.example.com"]["status"] == "conflict"
    assert t.writes_of("update_url_category") == []


def test_the_conflict_guard_skips_a_domain_someone_removed_during_the_run():
    """ASVS V11.1.6 · CWE-367 · WSTG-BUSL-08: a ZPA domain removed by someone else before the write is a conflict, not re-sent."""
    t = Tenant()
    spec = {"type": "zpa_domains", "action": "move", "source": "s1", "target": "s3", "domains": ["hr.corp.example"]}
    p = preview(t, spec)
    segs = t.zpa.application_segment
    real = segs.get_segment

    def someone_else(sid, query_params=None):
        s = segs._find("s1")
        s["domain_names"] = [d for d in s["domain_names"] if d != "hr.corp.example"]
        return real(sid, query_params)
    segs.get_segment = someone_else
    res = apply(t, spec, p)
    assert by_key(res)["seg:s1:-hr.corp.example"]["status"] == "conflict"
    assert "hr.corp.example" not in segs._find("s3")["domain_names"] or by_key(res)["seg:s3:+hr.corp.example"]["status"] == "applied"


def test_a_rule_renamed_by_someone_else_keeps_its_new_name_after_the_state_change():
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: the write sends the rule as read just before it, so another admin's edit is kept."""
    t = Tenant()
    spec = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
    p = preview(t, spec)
    svc = t.zia.url_filtering
    real = svc.get_rule
    svc.get_rule = lambda rid, *a: (svc._find(rid).update(description="edited by Bob"), real(rid, *a))[1]
    res = apply(t, spec, p)
    assert res["status"] == "applied" and svc._find(101)["description"] == "edited by Bob"


# ── typed confirmation ─────────────────────────────────────────────────

def _eleven_rule_tenant():
    rows = [rule(1000 + i, f"R{i}", i + 1) for i in range(11)] + [rule(1999, "Default", -1, default_rule=True)]
    return Tenant(url_rules=rows), {"type": "rule_state", "value": "DISABLED",
                                    "targets": [{"policy": "url_filtering", "id": 1000 + i} for i in range(11)]}


@pytest.mark.parametrize("typed", ["", "APPLY 10 CHANGES", "APPLY 11 CHANGE", "yes"])
def test_above_ten_changes_a_wrong_phrase_writes_nothing(typed):
    """ASVS V2.8.1 · A04:2021 · CWE-841 · WSTG-BUSL-06: more than ten changes need exactly APPLY N CHANGES; anything else is refused."""
    t, spec = _eleven_rule_tenant()
    res = apply(t, spec, confirm_text=typed)
    assert res["status"] == "refused" and t.writes == []


def test_the_phrase_is_case_and_space_insensitive_but_exact():
    """ASVS V2.8.1 · CWE-841 · WSTG-BUSL-06: ' apply 11 changes ' confirms; the phrase is derived from the server's own re-plan."""
    t, spec = _eleven_rule_tenant()
    assert apply(t, dict(spec, confirm_phrase=""), confirm_text="  apply 11 changes ")["status"] == "applied"


def test_exactly_ten_changes_need_no_phrase():
    """ASVS V2.8.1 · CWE-841: the boundary: ten changes (CONFIRM_ABOVE) need no typed phrase; eleven do."""
    assert ao.confirm_phrase(ao.CONFIRM_ABOVE) == "" and ao.confirm_phrase(ao.CONFIRM_ABOVE + 1) == "APPLY 11 CHANGES"


class _OneChangeClient:
    def __init__(self):
        self.zpa = type("Z", (), {"writes": []})()


def _one_change_plan(phrase_key):
    def _plan(client, spec, scope, say, cancel):
        u = ao._unit("demo:1", "demo:1", "demo", {"type": "demo", "id": None, "name": "x"}, "exists", False, True)
        return {"type": "c6_demo", "spec": {"type": "c6_demo"}, "product": "zpa", "title": "demo", "items": [u],
                "groups": [{"key": "demo:1", "handler": "c6_demo_write", "target": {}}], phrase_key: "DELETE X"}
    return _plan


def _demo_write(run, g, units):
    run.client.zpa.writes.append(g["key"])
    run.mark(units, "applied")


@pytest.fixture
def clean_registry(monkeypatch):
    monkeypatch.setattr(ao, "PLUGINS", {})
    monkeypatch.setattr(ao, "PLUGIN_FAMILIES", {})
    monkeypatch.setattr(ao, "PLUGIN_HANDLERS", {})
    monkeypatch.setattr(ao, "_plugins_loaded", True)
    return ao


def _always_in_scope(scope):
    return None


def _no_objects(*a):
    return {}


def _register_demo(plan, **kw):
    base = dict(family="c6_demo_family", product="zpa", label="demo", hint="demo", in_scope=_always_in_scope, plan=plan,
                read_objects=_no_objects, handlers={"c6_demo_write": _demo_write})
    base.update(kw)
    ao.register("c6_demo", **base)


@pytest.mark.parametrize("phrase_key", ["confirm_always", "confirm_phrase"])
def test_a_plugins_own_phrase_is_needed_even_for_one_change(clean_registry, phrase_key):
    """ASVS V2.8.1 · CWE-841 · WSTG-BUSL-06: a plugin's confirm_always / confirm_phrase is asked whatever the count; a blank or wrong one is refused."""
    _register_demo(_one_change_plan(phrase_key))
    c = _OneChangeClient()
    p = ao.plan(c, {"type": "c6_demo"}, scope=FULL_SCOPE)
    assert p["confirm_phrase"] == "DELETE X"
    for typed in ("", "DELETE", "APPLY 1 CHANGES"):
        res = ao.execute(c, {"type": "c6_demo"}, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor="Jane Doe", confirm_text=typed)
        assert res["status"] == "refused" and c.zpa.writes == []
    res = ao.execute(c, {"type": "c6_demo"}, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor="Jane Doe", confirm_text="delete x")
    assert res["status"] == "applied" and c.zpa.writes == ["demo:1"]


# ── plugin registry validation ─────────────────────────────────────────

def test_a_plan_naming_an_unknown_write_handler_is_refused_before_any_write(clean_registry):
    """ASVS V1.14.6 · A04:2021 · CWE-754 · WSTG-ERRH-01: a plan whose write step has no handler is a plain refusal, not a KeyError mid-run."""
    def bad_plan(client, spec, scope, say, cancel):
        p = _one_change_plan("confirm_phrase")(client, spec, scope, say, cancel)
        p["groups"][0]["handler"] = "no_such_handler"
        return p
    _register_demo(bad_plan)
    with pytest.raises(ao.OperationError, match="write step"):
        ao.plan(_OneChangeClient(), {"type": "c6_demo"}, scope=FULL_SCOPE)


@pytest.mark.parametrize("bad", [
    {"plan": "not callable"}, {"in_scope": None}, {"read_objects": 5}, {"verify": "x"}, {"inverse": 1},
    {"handlers": {}}, {"handlers": {"Bad-Name": _demo_write}}, {"handlers": {"ok_name": "x"}},
    {"product": "ZIA platform"}, {"product": ""}, {"family": "c6_demo"},
])
def test_register_refuses_malformed_plugins(clean_registry, bad):
    """ASVS V5.1.3 · V14.2.4 · CWE-20 · WSTG-INPV-01: a plugin with a non-callable hook, a bad handler or product name, or type == family is refused."""
    with pytest.raises(ValueError):
        _register_demo(**dict({"plan": _one_change_plan("confirm_phrase")}, **bad))
    assert "c6_demo" not in ao.PLUGINS


def test_a_second_plugin_cannot_take_over_a_registered_type_or_family(clean_registry):
    """ASVS V1.14.6 · A08:2021 · CWE-284 · WSTG-ATHZ-02: re-registering a type with another planner, or a family with another scope gate, is refused."""
    plan = _one_change_plan("confirm_phrase")
    _register_demo(plan)
    _register_demo(plan)   # the same module importing twice is fine
    with pytest.raises(ValueError):
        _register_demo(_one_change_plan("confirm_always"))
    with pytest.raises(ValueError):
        ao.register("c6_other", family="c6_demo_family", product="zpa", label="x", hint="x", in_scope=lambda s: None,
                    plan=plan, read_objects=lambda *a: {}, handlers={"c6_other_write": _demo_write})
    assert ao.PLUGINS["c6_demo"]["plan"] is plan


def test_a_plugin_type_cannot_reuse_another_plugins_family_name(clean_registry):
    """ASVS V5.1.3 · CWE-694 · WSTG-INPV-01: a type named like an existing family (or the reverse) is refused: one name, one scope gate."""
    _register_demo(_one_change_plan("confirm_phrase"))
    with pytest.raises(ValueError):
        ao.register("c6_demo_family", family="c6_x", product="zpa", label="x", hint="x", in_scope=lambda s: None,
                    plan=lambda *a: {}, read_objects=lambda *a: {}, handlers={"c6_x_write": _demo_write})
    with pytest.raises(ValueError):
        ao.register("c6_y", family="c6_demo", product="zpa", label="x", hint="x", in_scope=lambda s: None,
                    plan=lambda *a: {}, read_objects=lambda *a: {}, handlers={"c6_y_write": _demo_write})


def test_every_shipped_plugin_still_registers_and_has_a_script():
    """ASVS V14.2.4 · SSDF PW.4.1 · CWE-1104: the real ops_*.py builders pass the stricter registry checks."""
    names = ao.types()
    assert {"zcc_profile_build", "zdx_probes", "zia_baseline", "aiguard_routing"} <= set(names)
    assert all(p["script"].startswith("ops_") for p in ao.plugin_catalog())


# ── malformed specs are plain 400s, never crashes ──────────────────────

@pytest.mark.parametrize("spec", [
    {"type": "rule_state", "targets": 5, "value": "DISABLED"},
    {"type": "rule_state", "targets": {"policy": "url_filtering"}, "value": "DISABLED"},
    {"type": "reorder", "policy": "url_filtering", "order": 5},
    {"type": "url_categories", "action": "revert", "deltas": 5},
    {"type": "url_categories", "action": "revert", "deltas": ["CUSTOM_01"]},
    {"type": "url_categories", "action": "revert", "delete_categories": ["x"]},
    {"type": "zpa_domains", "action": "revert", "deltas": [1]},
    {"type": "zpa_domains", "action": "revert", "delete_segments": [None]},
    {"type": "zpa_domains", "action": "revert", "delete_segments": [{"id": "s1", "domains": 7}]},
])
def test_a_malformed_operation_is_an_operation_error(spec):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-ERRH-01: a wrongly shaped spec is refused in plain words (the endpoint's 400), not a TypeError (500)."""
    with pytest.raises(ao.OperationError):
        ao.plan(Tenant(), spec, scope=FULL_SCOPE)


def test_the_preview_endpoint_answers_400_for_a_malformed_spec(monkeypatch):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: /api/operations/preview with targets=5 is a 400 with a reason, no traceback."""
    t = Tenant()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: t)
    r = TestClient(srv.app).post("/api/operations/preview", json=dict(SCOPE_BODY, operation={"type": "rule_state", "targets": 5}))
    assert r.status_code == 400 and "list" in r.json()["detail"] and "Traceback" not in r.text


def test_an_undo_spec_is_capped_like_any_operation():
    """ASVS V11.1.4 · A04:2021 · CWE-400 · WSTG-BUSL-05: a revert (Undo) spec cannot carry more URLs than MAX_URLS."""
    many = [f"h{i}.example.com" for i in range(ao.MAX_URLS + 1)]
    with pytest.raises(ao.OperationError, match="At most"):
        ao.plan(Tenant(), {"type": "url_categories", "action": "revert", "deltas": [{"category": "CUSTOM_01", "add": many}]}, scope=FULL_SCOPE)
    doms = [f"h{i}.corp.example" for i in range(ao.MAX_DOMAINS + 1)]
    with pytest.raises(ao.OperationError, match="At most"):
        ao.plan(Tenant(), {"type": "zpa_domains", "action": "revert", "deltas": [{"segment": "s1", "remove": doms}]}, scope=FULL_SCOPE)


def test_invalid_urls_count_toward_the_cap():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a list of MAX_URLS+1 invalid entries is refused, not turned into that many excluded items."""
    with pytest.raises(ao.OperationError, match="At most"):
        ao.plan(Tenant(), {"type": "url_categories", "action": "add", "target": "CUSTOM_02", "urls": ["*bad*"] * (ao.MAX_URLS + 1)},
                scope=FULL_SCOPE)
    with pytest.raises(ao.OperationError, match="At most"):
        ao.plan(Tenant(), {"type": "zpa_domains", "action": "copy", "source": "s1", "target": "s3", "domains": ["bad_*"] * (ao.MAX_DOMAINS + 1)},
                scope=FULL_SCOPE)


def test_exactly_max_targets_rules_is_accepted_and_one_more_refused():
    """ASVS V11.1.4 · CWE-770: the MAX_TARGETS boundary for a mass enable / disable."""
    targets = [{"policy": "url_filtering", "id": i} for i in range(ao.MAX_TARGETS)]
    p = ao.plan(Tenant(), {"type": "rule_state", "value": "DISABLED", "targets": targets}, scope=FULL_SCOPE)
    assert p["counts"]["total"] == ao.MAX_TARGETS
    with pytest.raises(ao.OperationError):
        ao.plan(Tenant(), {"type": "rule_state", "value": "DISABLED", "targets": targets + [{"policy": "url_filtering", "id": -1}]}, scope=FULL_SCOPE)


# ── URL and domain validation (oracle table) ───────────────────────────

@pytest.mark.parametrize("raw,want", [
    ("bücher.de", "xn--bcher-kva.de"),
    (".Bücher.de/path", ".xn--bcher-kva.de/path"),
    ("xn--bcher-kva.de", "xn--bcher-kva.de"),
    ("https://EXAMPLE.com:443/a", "example.com:443/a"),
    ("192.0.2.10", "192.0.2.10"),
])
def test_normalize_url_accepts_idn_as_punycode(raw, want):
    """ASVS V5.1.3 · CWE-176 · WSTG-INPV-01: an internationalised host is sent in the ASCII (punycode) form; ASCII hosts are unchanged."""
    assert ao.normalize_url(raw) == (want, None)


@pytest.mark.parametrize("raw", ["a.example.com/p\x00x", "a.example.com/\x1b[31m", "a.example.com/\x7f", "[2001:db8::1]", "2001:db8::1",
                                 "ex​ample.com" + "\x01", "a" * 64 + ".com", "x.example.com:0"])
def test_normalize_url_refuses_control_characters_and_bad_hosts(raw):
    """ASVS V5.1.4 · CWE-20 · CWE-74 · WSTG-INPV-01: control characters, IPv6 literals ZIA custom URLs are not known to take, and bad labels are refused."""
    assert ao.normalize_url(raw)[0] is None


@pytest.mark.parametrize("raw,want", [("*.Bücher.de", "*.xn--bcher-kva.de"), ("Wiki.Corp.Example.", "wiki.corp.example"),
                                      ("2001:db8::1", "2001:db8::1"), ("2001:db8::/32", "2001:db8::/32")])
def test_normalize_domain_oracle(raw, want):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZPA domains: IDN wildcard to punycode, trailing dot dropped, IPv6 address and CIDR kept."""
    assert ao.normalize_domain(raw) == (want, None)


@pytest.mark.parametrize("raw", ["a b.example", "x\x00.example", "*", "*.*.example", "300.1.1.1/8", "-x.example"])
def test_normalize_domain_refuses(raw):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: spaces, control characters, bare or nested wildcards and bad CIDR ranges are refused."""
    assert ao.normalize_domain(raw)[0] is None


def test_minimal_moves_handles_empty_and_identity_orders():
    """ASVS V1.14.6 · CWE-682: an empty or already-correct order needs no move; a duplicate id is refused."""
    assert ao.minimal_moves([], []) == [] and ao.minimal_moves(["1", "2"], ["1", "2"]) == []
    with pytest.raises(ao.OperationError):
        ao.minimal_moves(["1", "1"], ["1", "1"])


# ═══════════════════════════════════════════════════════════════════════
# change_queue: four-eyes, plan-hash binding, no replay
# ═══════════════════════════════════════════════════════════════════════

def _file(by="alice@example.com", **kw):
    base = dict(kind="fix_recipe", tenant="acme", tenant_label="acme", title="t", summary={"write": 1}, items=[{"method": "POST"}],
                plan_hash="h" * 64, requested_by=by, payload={"check_id": "FW-01", "criteria": {"name": "a"}})
    base.update(kw)
    return change_queue.file_request(**base)


@pytest.mark.parametrize("approver", ["alice@example.com", "ALICE@EXAMPLE.COM", " Alice@Example.com ", "ａｌｉｃｅ@example.com"])
def test_the_requester_cannot_approve_their_own_request_in_any_spelling(approver):
    """ASVS V1.4.1 · V4.1.3 · A01:2021 · CWE-654 · WSTG-BUSL-07: four-eyes compares people case- and width-insensitively (NFKC, casefold)."""
    rec = _file()
    with pytest.raises(change_queue.QueueError) as e:
        change_queue.decide(rec["id"], "approve", by=approver)
    assert e.value.status == 403 and change_queue.get(rec["id"])["status"] == "pending"


def test_a_local_identity_never_counts_as_the_second_person():
    """ASVS V4.1.3 · A01:2021 · CWE-654 · WSTG-ATHZ-02: filed as 'local, no UI token', approved as 'local UI token' (the same human) is refused."""
    rec = _file(by=security.LOCAL_NO_TOKEN_ACTOR)
    for who in (security.LOCAL_TOKEN_ACTOR, security.NO_REQUEST_ACTOR, "unknown"):
        with pytest.raises(change_queue.QueueError) as e:
            change_queue.decide(rec["id"], "approve", by=who)
        assert e.value.status == 403
    assert change_queue.get(rec["id"])["status"] == "pending"


def test_an_unnamed_caller_cannot_decide_comment_withdraw_or_apply():
    """ASVS V7.1.3 · V4.1.3 · CWE-287 · WSTG-ATHN-04: every queue step needs a named actor (401 otherwise)."""
    rec = _file()
    for step in (lambda: change_queue.decide(rec["id"], "reject", by="", comment="no"),
                 lambda: change_queue.comment(rec["id"], by="  ", text="hi"),
                 lambda: change_queue.withdraw(rec["id"], by=""),
                 lambda: change_queue.begin_apply(rec["id"], by="")):
        with pytest.raises(change_queue.QueueError) as e:
            step()
        assert e.value.status == 401


def test_four_eyes_off_lets_a_single_person_install_approve_its_own(monkeypatch):
    """ASVS V1.4.1 · CWE-654: DLP_CHECK_FOUR_EYES=0 is the documented single-person mode."""
    monkeypatch.setenv("DLP_CHECK_FOUR_EYES", "0")
    rec = _file(by=security.LOCAL_TOKEN_ACTOR)
    assert change_queue.decide(rec["id"], "approve", by=security.LOCAL_TOKEN_ACTOR)["status"] == "approved"


def test_approval_records_a_digest_of_what_was_approved():
    """ASVS V11.1.1 · CWE-345 · WSTG-BUSL-01: an approval stores the digest of kind, tenant, plan_hash and payload."""
    rec = change_queue.decide(_file()["id"], "approve", by="bob@example.com")
    assert rec["approved_digest"] == change_queue.approval_digest(rec) and rec["decided_by"] == "bob@example.com"


@pytest.mark.parametrize("field,value", [("plan_hash", "0" * 64), ("payload", {"check_id": "FW-01", "criteria": {"name": "evil"}}),
                                         ("tenant", "other"), ("kind", "pack_removal")])
def test_an_approval_does_not_carry_over_to_a_changed_request(field, value):
    """ASVS V11.1.1 · A08:2021 · CWE-345 · WSTG-BUSL-01: a request whose plan_hash, payload, tenant or kind changed after approval is not applied."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    data = json.load(open(change_queue.store_path()))
    data["requests"][rid][field] = value
    json.dump(data, open(change_queue.store_path(), "w"))
    with pytest.raises(change_queue.QueueError, match="not the one that was approved"):
        change_queue.begin_apply(rid, by="bob@example.com")


def test_a_request_approved_by_an_earlier_version_still_applies():
    """ASVS V1.14.6 · CWE-1188 (regression): a stored approval without approved_digest is still applied (plan_hash re-checked by the apply path)."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    data = json.load(open(change_queue.store_path()))
    data["requests"][rid].pop("approved_digest", None)
    json.dump(data, open(change_queue.store_path(), "w"))
    assert change_queue.begin_apply(rid, by="bob@example.com")["applying"]["by"] == "bob@example.com"


def test_a_finished_request_cannot_be_finished_again():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06: once applied, a second finish (a replay) changes nothing and returns None."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    change_queue.begin_apply(rid, by="bob@example.com")
    assert change_queue.finish_apply(rid, by="bob@example.com", status="applied", result={"status": "completed"})["status"] == "applied"
    assert change_queue.finish_apply(rid, by="eve@example.com", status="failed", result={"status": "error"}) is None
    rec = change_queue.get(rid)
    assert rec["status"] == "applied" and rec["applied_by"] == "bob@example.com"


def test_an_applied_or_rejected_request_cannot_be_approved_or_applied_again():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06: no replay: decisions and applies need the right status."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    with pytest.raises(change_queue.QueueError):
        change_queue.decide(rid, "approve", by="carol@example.com")
    change_queue.begin_apply(rid, by="bob@example.com")
    change_queue.finish_apply(rid, by="bob@example.com", status="applied", result={})
    for step in (lambda: change_queue.begin_apply(rid, by="bob@example.com"), lambda: change_queue.decide(rid, "reject", by="x", comment="late"),
                 lambda: change_queue.withdraw(rid, by="alice@example.com")):
        with pytest.raises(change_queue.QueueError):
            step()
    rid2 = _file(plan_hash="2" * 64)["id"]
    change_queue.decide(rid2, "reject", by="bob@example.com", comment="no")
    with pytest.raises(change_queue.QueueError):
        change_queue.decide(rid2, "approve", by="bob@example.com")


def test_a_second_apply_while_the_first_runs_is_refused():
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: an approved request is claimed by one apply at a time."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    change_queue.begin_apply(rid, by="bob@example.com")
    change_queue.set_job(rid, "job-1")
    with pytest.raises(change_queue.QueueError, match="applying"):
        change_queue.begin_apply(rid, by="carol@example.com", job_running=lambda j: True)


def test_the_same_plan_cannot_be_filed_twice_while_open():
    """ASVS V11.1.1 · CWE-837 · WSTG-BUSL-07: a duplicate open request for one plan is refused (409)."""
    _file()
    with pytest.raises(change_queue.QueueError) as e:
        _file(by="carol@example.com")
    assert e.value.status == 409


def test_only_the_requester_withdraws_and_reject_needs_a_reason():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: another person cannot withdraw a request; a reject without a comment is refused."""
    rid = _file()["id"]
    with pytest.raises(change_queue.QueueError) as e:
        change_queue.withdraw(rid, by="mallory@example.com")
    assert e.value.status == 403
    with pytest.raises(change_queue.QueueError):
        change_queue.decide(rid, "reject", by="bob@example.com", comment="   ")
    assert change_queue.withdraw(rid, by="ALICE@example.com")["status"] == "withdrawn"


def test_the_queue_store_is_owner_only():
    """ASVS V8.3.4 · CWE-276 · CWE-732 · WSTG-CONF-11: change_requests.json and its lock are 0600."""
    _file()
    for p in (change_queue.store_path(), change_queue.store_path() + ".lock"):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


def test_comments_are_capped_and_control_characters_dropped():
    """ASVS V5.1.4 · V11.1.4 · CWE-400 · CWE-117: a comment is cleaned of control characters and capped at MAX_COMMENT."""
    rid = _file()["id"]
    rec = change_queue.comment(rid, by="bob@example.com", text="a\x1b[2Jb" + "x" * 5000)
    text = rec["comments"][-1]["text"]
    assert "\x1b" not in text and len(text) == change_queue.MAX_COMMENT


def test_the_markdown_export_keeps_hostile_titles_inert():
    """ASVS V5.3.1 · A03:2021 · CWE-79 · CWE-1236 · WSTG-INPV-01: titles and comments cannot inject Markdown links, HTML or headings."""
    rid = _file(title="[click](javascript:alert(1)) <img src=x onerror=alert(1)>")["id"]
    change_queue.comment(rid, by="bob@example.com", text="# owned\n<script>x</script>")
    md = change_queue.to_markdown(change_queue.list_requests())
    assert "\\[click\\](javascript:" in md and "<img" not in md and "<script>" not in md and "\n# owned" not in md


# ═══════════════════════════════════════════════════════════════════════
# proposals: decisions cannot be replayed; the store is safe
# ═══════════════════════════════════════════════════════════════════════

def _proposal(kind="retire_rule", target="rule:web:R1"):
    p = {"id": proposals.proposal_id("acme", kind, target), "tenant": "acme", "kind": kind, "label": kind, "target": target, "title": "t",
         "change": {"apply": "rule"}, "evidence": {}, "expected_effect": "", "rollback": {}, "gate": proposals.GATES[kind], "applies_via": "phase 3"}
    proposals.merge("acme", [p])
    return p["id"]


def test_an_applied_proposal_cannot_be_approved_again():
    """ASVS V11.1.1 · A04:2021 · CWE-841 · WSTG-BUSL-06: an applied change is rolled back first; approving it again (a replay) is refused."""
    pid = _proposal()
    proposals.decide("acme", pid, "approve", by="bob")
    proposals.set_status("acme", pid, "applied", by="bob")
    for d in ("approve", "dismiss", "snooze", "reopen"):
        with pytest.raises(ValueError, match="applied"):
            proposals.decide("acme", pid, d, by="bob")
    assert proposals.get("acme", pid)["status"] == "applied"


def test_an_approved_or_resolved_proposal_is_not_approved_again():
    """ASVS V11.1.1 · CWE-841 · WSTG-BUSL-06: approve is refused on approved (no double count) and on resolved proposals."""
    pid = _proposal()
    proposals.decide("acme", pid, "approve", by="bob")
    with pytest.raises(ValueError, match="already approved"):
        proposals.decide("acme", pid, "approve", by="carol")
    proposals.set_status("acme", pid, "resolved")
    with pytest.raises(ValueError, match="resolved"):
        proposals.decide("acme", pid, "approve", by="carol")


def test_a_rolled_back_proposal_can_be_approved_again():
    """ASVS V1.14.6 · CWE-841 (regression): rolled back is not terminal; the change may be approved and applied again."""
    pid = _proposal()
    proposals.set_status("acme", pid, "rolled_back")
    assert proposals.decide("acme", pid, "approve", by="bob")["status"] == "approved"


def test_a_stricter_change_still_needs_the_phrase():
    """ASVS V2.8.1 · CWE-841 · WSTG-BUSL-06: approve_double gates (promote, heal) need I UNDERSTAND; a wrong phrase is refused."""
    pid = _proposal("promote_rule", "rule:web:R2")
    with pytest.raises(ValueError, match="I UNDERSTAND"):
        proposals.decide("acme", pid, "approve", by="bob", confirm="i understand it")
    assert proposals.decide("acme", pid, "approve", by="bob", confirm=" i understand ")["status"] == "approved"


@pytest.mark.parametrize("days,want", [(10 ** 9, 365), (-5, 1), (0, proposals.SNOOZE_DAYS_DEFAULT), ("30", 30)])
def test_snooze_days_are_clamped_not_a_crash(days, want):
    """ASVS V5.1.4 · A04:2021 · CWE-1284 · CWE-190 · WSTG-INPV-01: a huge snooze is capped (no OverflowError 500); a tiny one is one day."""
    pid = _proposal()
    p = proposals.decide("acme", pid, "snooze", by="bob", days=days)
    got = (datetime.fromisoformat(p["snoozed_until"]) - datetime.fromisoformat(p["decided_at"])).days
    assert got in (want, want - 1)


def test_snooze_days_that_are_not_a_number_are_a_plain_error():
    """ASVS V5.1.3 · CWE-20 · WSTG-ERRH-01: snooze days must be a whole number."""
    with pytest.raises(ValueError, match="whole number"):
        proposals.decide("acme", _proposal(), "snooze", by="bob", days="soon")


def test_the_store_write_never_follows_a_planted_temp_symlink(tmp_path):
    """ASVS V12.3.1 · A01:2021 · CWE-59 · CWE-377 · WSTG-ATHZ-01: the store's temporary is created afresh (O_EXCL, O_NOFOLLOW), so a planted link is never followed."""
    victim = tmp_path / "victim.txt"
    victim.write_text("keep me")
    os.symlink(victim, proposals.store_path() + ".tmp")
    _proposal()
    assert victim.read_text() == "keep me"
    assert stat.S_IMODE(os.stat(proposals.store_path()).st_mode) == 0o600
    assert not os.path.lexists(proposals.store_path() + ".tmp")


def test_concurrent_merges_from_two_threads_lose_nothing():
    """ASVS V11.1.6 · CWE-362 · WSTG-BUSL-08: two writers merging at once both land (lock + atomic replace)."""
    def add(i):
        target = f"rule:web:T{i}"
        p = {"id": proposals.proposal_id("acme", "retire_rule", target), "kind": "retire_rule", "target": target, "title": "t",
             "change": {}, "gate": "approve"}
        proposals.merge("acme", [p], resolve_missing=False)
    threads = [threading.Thread(target=add, args=(i,)) for i in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert len(proposals.list_queue("acme")) == 8


@pytest.mark.skipif(os.name != "posix", reason="flock is POSIX")
def test_a_store_update_holds_a_lock_another_process_would_wait_for():
    """ASVS V11.1.6 · CWE-362 · CWE-667 · WSTG-BUSL-08: proposals.json is updated under an exclusive lock on proposals.json.lock (two server processes)."""
    import fcntl
    with proposals._locked():
        fd = os.open(proposals.store_path() + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(fd)


def test_an_expired_snooze_is_open_again_and_can_be_approved():
    """ASVS V1.14.6 · CWE-672 (regression): a snooze in the past reads as open and accepts a decision."""
    pid = _proposal()
    proposals.decide("acme", pid, "snooze", by="bob", days=1)
    proposals.set_status("acme", pid, "snoozed", snoozed_until="2000-01-01T00:00:00+00:00")
    assert proposals.list_queue("acme")[0]["status"] == "open"
    assert proposals.decide("acme", pid, "approve", by="bob")["status"] == "approved"


# ═══════════════════════════════════════════════════════════════════════
# remediation: secure defaults, input validation, the PATCH path, gates
# ═══════════════════════════════════════════════════════════════════════

GOOD_FW = {"name": "c6_rule", "description": "why", "action": "BLOCK_DROP", "order": 1, "rank": 7, "state": "DISABLED"}


@pytest.mark.parametrize("recipe", [r for r in remediation.REMEDIATIONS if r["method"] == "POST"], ids=lambda r: r["check_id"])
def test_every_recipe_creates_its_rule_disabled_by_default(recipe):
    """ASVS V1.14.6 · CISA SbD secure defaults · CWE-1188 · WSTG-CONF-02: a recipe's rule arrives DISABLED unless the person picks ENABLED."""
    state = next(f for f in recipe["fields"] if f["key"] == "state")
    assert state["default"] == "DISABLED"
    criteria = {f["key"]: f.get("default", "x") for f in recipe["fields"] if f["key"] != "state"}
    criteria.update({k: "ADULT_MATERIAL" for k in ("url_categories",)})
    p = remediation.plan(recipe["check_id"], criteria)
    assert p["ok"], p and p["body"]["state"] == "DISABLED"


def test_an_optional_number_left_out_gets_its_default_not_a_crash():
    """ASVS V5.1.3 · A04:2021 · CWE-754 · WSTG-ERRH-01: leaving out rank (optional) plans with the default 7 instead of a TypeError (500)."""
    left_out = {k: v for k, v in GOOD_FW.items() if k not in ("rank", "state")}
    p = remediation.plan("FW-01", left_out)
    assert p["ok"] and p["body"]["rank"] == 7 and p["body"]["state"] == "DISABLED"


@pytest.mark.parametrize("bad", [{"name": {"$ne": 1}}, {"description": ["a", "b"]}, {"order": True}, {"order": 1.5}, {"order": [1]}])
def test_structured_or_boolean_values_never_reach_the_body(bad):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · CWE-915 · WSTG-INPV-01: a dict, list, bool or fraction where a field takes one value is refused."""
    p = remediation.plan("FW-01", dict(GOOD_FW, **bad))
    assert p["ok"] is False and p["errors"]


def test_a_text_field_without_its_own_limit_is_still_capped():
    """ASVS V5.1.4 · V11.1.4 · CWE-400 · WSTG-INPV-01: URL-01's description has no max_length; MAX_TEXT applies."""
    c = {"name": "r", "description": "d" * (2048 + 1), "action": "BLOCK", "url_categories": "GAMBLING", "order": 1, "rank": 7, "state": "DISABLED"}
    assert remediation.plan("URL-01", c)["ok"] is False
    assert remediation.plan("URL-01", dict(c, description="d" * 2048))["ok"] is True


def test_criteria_that_are_not_an_object_are_refused():
    """ASVS V5.1.3 · CWE-20 · WSTG-ERRH-01: criteria must be an object."""
    assert remediation.plan("FW-01", ["name"])["ok"] is False


@pytest.mark.parametrize("rid", ["../users", "1/2", "1?x=1", "1#f", "%2e%2e", "1 2", "x" * 65])
def test_a_path_parameter_cannot_retarget_the_write(rid):
    """ASVS V12.3.1 · A01:2021 · CWE-22 · WSTG-ATHZ-01: a rule id with '/', '..', '?', '#', '%' or space is refused before a path is built."""
    p = remediation.plan("RULE-DESC", {"rule_type": "webDlpRules", "rule_id": rid, "description": "d"})
    assert p["ok"] is False


class _RawClient:
    """A raw-HTTP client like dlp_assessment_full_auto.Client: get/post/put/delete, no patch."""

    def __init__(self, current=None, get_code=200):
        self.calls, self.current, self.get_code = [], current, get_code

    def get(self, ep, p=None):
        self.calls.append(("GET", ep, None))
        return (copy.deepcopy(self.current), self.get_code)

    def post(self, ep, body=None):
        self.calls.append(("POST", ep, body))
        return ({"id": 1}, 200)

    def put(self, ep, body=None):
        self.calls.append(("PUT", ep, body))
        return (body, 200)

    def delete(self, ep, body=None):
        self.calls.append(("DELETE", ep, body))
        return ({}, 204)


def _writes_on(monkeypatch):
    monkeypatch.setattr(security, "writes_enabled", lambda: True)


def test_a_patch_recipe_without_client_patch_sends_the_whole_rule(monkeypatch):
    """ASVS V1.14.6 · A04:2021 · CWE-440 · WSTG-BUSL-01: 'Add description' reads the rule and PUTs it back whole; a PUT of the description alone would replace the rule."""
    _writes_on(monkeypatch)
    c = _RawClient(current={"id": 7, "name": "PCI", "order": 3, "action": "BLOCK", "description": ""})
    out = remediation.execute(c, "RULE-DESC", {"rule_type": "webDlpRules", "rule_id": "7", "description": "owner: SecOps"}, dry_run=False)
    assert out["status"] == "completed"
    assert [x[0] for x in c.calls] == ["GET", "PUT"]
    assert c.calls[1][2] == {"id": 7, "name": "PCI", "order": 3, "action": "BLOCK", "description": "owner: SecOps"}


@pytest.mark.parametrize("current,code", [(None, 404), ("error page", 200), ({"error": "x"}, 401)])
def test_a_patch_recipe_whose_rule_cannot_be_read_sends_nothing(monkeypatch, current, code):
    """ASVS V7.4.1 · CISA SbD fail closed · CWE-755 · WSTG-ERRH-01: if the rule cannot be read first, no write is sent."""
    _writes_on(monkeypatch)
    c = _RawClient(current=current, get_code=code)
    out = remediation.execute(c, "RULE-DESC", {"rule_type": "webDlpRules", "rule_id": "7", "description": "d"}, dry_run=False)
    assert out["status"] == "failed" and [x[0] for x in c.calls] == ["GET"]


def test_dry_run_and_write_mode_off_send_nothing(monkeypatch):
    """ASVS V1.14.6 · A01:2021 · CWE-841 · WSTG-BUSL-06: dry run is the default and write mode off blocks a live run."""
    c, crit = _RawClient(), GOOD_FW
    assert remediation.execute(c, "FW-01", crit)["status"] == "dry_run"
    monkeypatch.setattr(security, "writes_enabled", lambda: False)
    assert remediation.execute(c, "FW-01", crit, dry_run=False)["status"] == "blocked"
    assert c.calls == []


def test_a_client_error_is_reported_without_a_traceback(monkeypatch):
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: a client exception becomes status error with a short message."""
    _writes_on(monkeypatch)

    class Boom(_RawClient):
        def post(self, ep, body=None):
            raise RuntimeError("connection reset " + "x" * 500)
    out = remediation.execute(Boom(), "FW-01", GOOD_FW, dry_run=False)
    assert out["status"] == "error" and len(out["error"]) < 260 and "Traceback" not in out["error"]


def test_an_unknown_check_has_no_recipe():
    """ASVS V5.1.3 · CWE-20: an unknown check id plans nothing; a known assessment check maps to its recipe."""
    assert remediation.plan("ZZ-404", {})["ok"] is False and remediation.get_recipe("") is None
    assert remediation.get_recipe("4.1")["check_id"] == "SSL-01"


@pytest.mark.parametrize("body,status,needle", [
    ({"confirm": False, "assessor": "Jane Doe"}, 400, "confirm"),
    ({"confirm": True, "assessor": ""}, 400, "assessor"),
    ({"confirm": True, "assessor": "Jane Doe", "_writes": False}, 403, "ENABLE_WRITE_ACTIONS"),
])
def test_the_one_click_fix_endpoint_checks_every_gate_before_signing_in(monkeypatch, body, status, needle):
    """ASVS V4.1.3 · V1.14.6 · A01:2021 · CWE-841 · WSTG-BUSL-06: a live remediation needs confirm, the assessor and write mode, all before sign-in."""
    signed = []
    monkeypatch.setattr(srv, "_build_client", lambda req: signed.append(1))
    writes = body.pop("_writes", True)
    monkeypatch.setattr(srv, "writes_enabled", lambda: writes)
    r = TestClient(srv.app).post("/api/remediation/execute", json=dict(
        {"vanity_domain": "acme", "client_id": "cid", "client_secret": "never-echoed", "check_id": "FW-01", "criteria": GOOD_FW, "dry_run": False},
        **body))
    assert r.status_code == status and needle.lower() in r.text.lower() and signed == []
    assert "never-echoed" not in r.text


def test_the_one_click_fix_endpoint_refuses_a_non_writer(monkeypatch):
    """ASVS V4.1.3 · A01:2021 · CWE-285 · WSTG-ATHZ-02: an SSO reader cannot apply a fix (403) and nothing is signed in to."""
    signed = []
    monkeypatch.setattr(srv, "_build_client", lambda req: signed.append(1))
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(security, "may_write", lambda: False)
    r = TestClient(srv.app).post("/api/remediation/execute", json={"vanity_domain": "acme", "client_id": "c", "client_secret": "s", "check_id": "FW-01",
                                                                  "criteria": GOOD_FW, "dry_run": False, "confirm": True, "assessor": "Jane Doe"})
    assert r.status_code == 403 and signed == []


# ── second pass: names of created objects and recipe id lists ──────────

@pytest.mark.parametrize("name", ["Evil\nname", "tab\tname\x07", "x" * 256])
def test_a_new_category_name_with_control_characters_or_too_long_is_refused(name):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · CWE-117 · WSTG-INPV-01: a created category's name is refused with control characters or past 255 characters (no silent cut)."""
    with pytest.raises(ao.OperationError, match="name"):
        ao.plan(Tenant(), {"type": "url_categories", "action": "add", "urls": ["a.example.com"], "create_target": {"name": name}}, scope=FULL_SCOPE)


@pytest.mark.parametrize("sup", ["user defined", "../x", "1ABC", "A" * 65])
def test_a_super_category_that_is_not_a_zia_name_is_refused(sup):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: super_category must look like a ZIA super category name (SDK 1.11.3: e.g. BUSINESS_AND_ECONOMY)."""
    with pytest.raises(ao.OperationError, match="super category"):
        ao.plan(Tenant(), {"type": "url_categories", "action": "add", "urls": ["a.example.com"],
                           "create_target": {"name": "New one", "super_category": sup}}, scope=FULL_SCOPE)


def test_a_valid_new_category_name_and_super_category_plan():
    """ASVS V5.1.3 · CWE-20 (regression): a normal name and super category still plan the create."""
    p = ao.plan(Tenant(), {"type": "url_categories", "action": "add", "urls": ["a.example.com"],
                           "create_target": {"name": "Partners 2026", "super_category": "business_and_economy"}}, scope=FULL_SCOPE)
    assert p["groups"][0]["target"]["super_category"] == "BUSINESS_AND_ECONOMY"


def test_a_clone_name_with_a_control_character_is_refused():
    """ASVS V5.1.4 · CWE-20 · CWE-117 · WSTG-INPV-01: a cloned ZPA segment's name has no control characters."""
    with pytest.raises(ao.OperationError, match="name"):
        ao.plan(Tenant(), {"type": "zpa_domains", "action": "clone", "source": "s1", "name": "Copy\r\nX", "domains": ["wiki.corp.example"]},
                scope=FULL_SCOPE)


@pytest.mark.parametrize("cats", ["GAMBLING,<script>", "A B", ",".join(["X"] * 257), "GAMBLING;DROP"])
def test_a_recipe_id_list_takes_ids_only(cats):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: URL-01's category list is up to 256 plain ids."""
    c = {"name": "r", "description": "d", "action": "BLOCK", "url_categories": cats, "order": 1, "rank": 7, "state": "DISABLED"}
    assert remediation.plan("URL-01", c)["ok"] is False
    assert remediation.plan("URL-01", dict(c, url_categories="GAMBLING, CUSTOM_01"))["ok"] is True


# ── coverage of the remaining branches ─────────────────────────────────

def _demo_recipe(method):
    return {"check_id": "C6-DEMO", "checks": [], "label": "demo", "summary": "demo", "destructive": True,
            "fields": [{"key": "rule_id", "label": "Rule ID", "type": "text", "required": True},
                       {"key": "note", "label": "Note", "type": "text", "required": False}],
            "endpoint": "/zia/demo/{rule_id}", "method": method, "body_template": {"text": "id {rule_id}: {note}"}}


@pytest.mark.parametrize("method,verb,code,status", [("PUT", "PUT", 200, "completed"), ("DELETE", "DELETE", 204, "completed"),
                                                    ("POST", "POST", 500, "failed"), ("OPTIONS", None, None, "error")])
def test_each_recipe_method_goes_to_the_matching_call(monkeypatch, method, verb, code, status):
    """ASVS V13.2.1 · CWE-650 · WSTG-CONF-06: PUT, DELETE and POST map to their own call; an unsupported method sends nothing."""
    monkeypatch.setattr(remediation, "REMEDIATIONS", [_demo_recipe(method)])
    _writes_on(monkeypatch)

    class C(_RawClient):
        def post(self, ep, body=None):
            self.calls.append(("POST", ep, body))
            return ({"error": "boom"}, code)
    c = C()
    out = remediation.execute(c, "C6-DEMO", {"rule_id": "42", "note": "x"}, dry_run=False)
    assert out["status"] == status
    assert [x[0] for x in c.calls] == ([verb] if verb else [])
    if verb:
        assert c.calls[0][1] == "/zia/demo/42" and c.calls[0][2] == {"text": "id 42: x"}


def test_a_description_fix_reads_the_rule_and_puts_it_back_whole(monkeypatch):
    """ASVS V1.14.6 · CWE-440 · CWE-665: RULE-DESC reads the rule and PUTs it whole with only the description changed (a PUT replaces the rule; a description-only body would wipe it), even when the client has patch()."""
    _writes_on(monkeypatch)

    class P(_RawClient):
        def patch(self, ep, body=None):
            self.calls.append(("PATCH", ep, body))
            return ({}, 200)
    rule = {"id": 7, "name": "Keep me", "order": 3, "action": "BLOCK", "description": "old"}
    c = P(current=rule)
    assert remediation.execute(c, "RULE-DESC", {"rule_type": "webDlpRules", "rule_id": "7", "description": "d"}, dry_run=False)["status"] == "completed"
    assert c.calls == [("GET", "/zia/webDlpRules/7", None), ("PUT", "/zia/webDlpRules/7", dict(rule, description="d"))]


@pytest.mark.parametrize("field,value,msg", [("order", 0, "≥"), ("order", 1000, "≤"), ("action", "PERMIT", "one of"), ("order", "ten", "number")])
def test_number_bounds_and_enums_are_checked(field, value, msg):
    """ASVS V5.1.4 · CWE-1284 · WSTG-INPV-01: min / max, enum options and numbers are validated with a plain message."""
    p = remediation.plan("FW-01", dict(GOOD_FW, **{field: value}))
    assert p["ok"] is False and any(msg in e for e in p["errors"])


def test_the_public_catalog_has_no_endpoints_or_templates():
    """ASVS V14.3.3 · CWE-200: the catalog the page gets lists fields, not the API call."""
    for r in remediation.get_catalog():
        assert "endpoint" not in r and "body_template" not in r
    assert remediation.remediable_checks()["4.1"] == "SSL-01"


@pytest.mark.parametrize("env,sso_on,needle", [("1", False, "needs SSO"), ("0", False, "Four-eyes is off"), ("1", True, "")])
def test_the_queue_settings_explain_four_eyes(monkeypatch, env, sso_on, needle):
    """ASVS V1.4.1 · WCAG 2.2 SC 3.3.2 · CWE-654: the page is told whether four-eyes can work here and why."""
    import sso
    monkeypatch.setenv("DLP_CHECK_FOUR_EYES", env)
    monkeypatch.setattr(sso, "sso_enabled", lambda: sso_on)
    s = change_queue.settings()
    assert s["four_eyes"] is (env == "1") and s["confirm_phrase"] == "I UNDERSTAND"
    assert (needle in s["note"]) if needle else s["note"] == ""


def test_release_gives_the_claim_back_and_a_bad_end_status_is_refused():
    """ASVS V11.1.1 · CWE-841: a run that never started releases its claim; an apply ends applied, failed or stale only."""
    rid = _file()["id"]
    change_queue.decide(rid, "approve", by="bob@example.com")
    change_queue.begin_apply(rid, by="bob@example.com")
    assert "applying" not in change_queue.release(rid, by="bob@example.com", reason="job queue full")
    assert change_queue.release("cr-missing", by="bob", reason="x") is None
    with pytest.raises(change_queue.QueueError):
        change_queue.finish_apply(rid, by="bob@example.com", status="approved", result={})
    assert change_queue.counts("acme")["approved"] == 1


def test_the_excel_export_never_holds_a_formula():
    """ASVS V5.3.1 · A03:2021 · CWE-1236 · WSTG-INPV-01: a title or comment starting with '=' is text in the workbook, not a formula."""
    import io
    import zipfile
    rid = _file(title="=HYPERLINK(\"http://x\")")["id"]
    change_queue.comment(rid, by="bob@example.com", text="@SUM(A1)")
    data = change_queue.to_xlsx(change_queue.list_requests(), tenant="acme")
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        sheets = [z.read(n).decode("utf-8") for n in z.namelist() if n.startswith("xl/worksheets/")]
    assert sheets and not any("<f>" in s or "<f " in s for s in sheets)
    assert change_queue.rows(change_queue.list_requests())[0]["title"].startswith("=HYPERLINK")


# ── C6-ADMIN-OPS-19: a live fix writes only a rule policy in scope ─────

_FIX_BASE = {"vanity_domain": "acme", "client_id": "cid", "client_secret": "never-echoed", "dry_run": False, "confirm": True, "assessor": "Jane Doe"}
_FIX_POLICY_SCOPE = {
    "firewall": {"scopes": ["zia_extras"], "channels": {}, "from_page": True},
    "url_filtering": {"scopes": ["zia_extras"], "channels": {}, "from_page": True},
    "ssl_inspection": {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler", "ssl_inspection": "zscaler"}, "from_page": True},
    "web_dlp": {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True},
}
_FIX_CASES = [("FW-01", {}, "firewall"), ("URL-01", {}, "url_filtering"), ("SSL-01", {}, "ssl_inspection"), ("DLP-01", {}, "web_dlp")] + [
    ("RULE-DESC", {"rule_type": t, "rule_id": "7", "description": "d"}, p) for t, p in (
        ("webDlpRules", "web_dlp"), ("urlFilteringRules", "url_filtering"), ("firewallFilteringRules", "firewall"), ("sslInspectionRules", "ssl_inspection"))]
_NOTHING_TICKED = {"scopes": [], "channels": {}, "from_page": True}


@pytest.fixture
def fix_route(monkeypatch):
    signed = []
    monkeypatch.setattr(srv, "_build_client", lambda req: signed.append(1) or object())
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    monkeypatch.setattr(remediation, "execute", lambda client, check_id, criteria, dry_run: {"status": "completed"})
    return TestClient(srv.app), signed


def test_every_recipe_has_a_known_rule_policy():
    """ASVS V4.1.3 · CWE-863 · CISA SbD deny by default: every fix recipe in the catalogue maps to the rule policy its scope check uses (a new recipe without one fails here)."""
    # Arrange
    ids = {r["check_id"] for r in remediation.get_catalog()}
    # Act
    unmapped = sorted(ids - set(getattr(srv, "_REMEDIATION_POLICY", {})) - {"RULE-DESC"})
    rule_types = next(f["options"] for r in remediation.get_catalog() if r["check_id"] == "RULE-DESC" for f in r["fields"] if f["key"] == "rule_type")
    # Assert
    assert unmapped == [] and {c[0] for c in _FIX_CASES} >= ids
    assert set(rule_types) == set(getattr(srv, "_REMEDIATION_RULE_TYPE_POLICY", {}))


@pytest.mark.parametrize("check_id,criteria,policy", _FIX_CASES, ids=[f"{c[0]}-{c[2]}" for c in _FIX_CASES])
def test_a_live_fix_outside_the_scope_page_is_refused_before_sign_in(fix_route, check_id, criteria, policy):
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: a live remediation whose rule policy is not in scope on the Scope page is a 400 and never signs in."""
    # Arrange
    api, signed = fix_route
    # Act
    r = api.post("/api/remediation/execute", json=dict(_FIX_BASE, **_NOTHING_TICKED, check_id=check_id, criteria=criteria))
    # Assert
    assert r.status_code == 400 and "not in scope" in r.json()["detail"] and signed == [] and "never-echoed" not in r.text


@pytest.mark.parametrize("check_id,criteria,policy", _FIX_CASES, ids=[f"{c[0]}-{c[2]}" for c in _FIX_CASES])
def test_a_live_fix_in_scope_reaches_the_write(fix_route, check_id, criteria, policy):
    """ASVS V4.1.3 · CWE-863 · WSTG-BUSL-01: with its rule policy in scope (and every write gate held) a live remediation signs in and runs."""
    # Arrange
    api, signed = fix_route
    # Act
    r = api.post("/api/remediation/execute", json=dict(_FIX_BASE, **_FIX_POLICY_SCOPE[policy], check_id=check_id, criteria=criteria))
    # Assert
    assert r.status_code == 200 and r.json()["status"] == "completed" and signed == [1], r.text


def test_add_description_is_scoped_by_the_rule_type_it_names(fix_route):
    """ASVS V4.1.3 · A01:2021 · CWE-863 · WSTG-ATHZ-02: "Add description" on a Web DLP rule with only ZIA platform ticked is refused (the channel decides, not the recipe)."""
    # Arrange
    api, signed = fix_route
    crit = {"rule_type": "webDlpRules", "rule_id": "7", "description": "d"}
    # Act
    r = api.post("/api/remediation/execute", json=dict(_FIX_BASE, **_FIX_POLICY_SCOPE["firewall"], check_id="RULE-DESC", criteria=crit))
    # Assert
    assert r.status_code == 400 and "Inline Web DLP" in r.json()["detail"] and signed == []


@pytest.mark.parametrize("rule_type", ["", "dlpEngines", "../admin", None])
def test_add_description_on_an_unknown_rule_type_is_refused(fix_route, rule_type):
    """ASVS V5.1.3 · CWE-863 · CISA SbD deny by default: an unknown rule type has no policy to check, so the live fix is a 400 before sign-in."""
    # Arrange
    api, signed = fix_route
    crit = {"rule_type": rule_type, "rule_id": "7", "description": "d"}
    # Act
    r = api.post("/api/remediation/execute", json=dict(_FIX_BASE, **_FIX_POLICY_SCOPE["web_dlp"], check_id="RULE-DESC", criteria=crit))
    # Assert
    assert r.status_code == 400 and signed == []


def test_a_dry_run_fix_needs_no_scope(fix_route):
    """ASVS V1.14.6 · CWE-440 · WSTG-BUSL-01: a dry run (the plan only) is not gated by the Scope page (negative case: no change to previews)."""
    # Arrange
    api, signed = fix_route
    # Act
    r = api.post("/api/remediation/execute", json=dict(_FIX_BASE, **_NOTHING_TICKED, check_id="FW-01", criteria=GOOD_FW, dry_run=True, confirm=False))
    # Assert
    assert r.status_code == 200


@pytest.mark.parametrize("mod_name", ["proposals", "change_queue"])
def test_the_store_lock_is_reentrant_in_one_thread(mod_name, tmp_path, monkeypatch):
    """CWE-833 · ASVS V1.11.3: a nested _locked() in the same thread never waits on its own file lock (a deadlock froze the whole server)."""
    import importlib
    import threading as _t
    mod = importlib.import_module(mod_name)
    monkeypatch.setattr(mod, "store_path", lambda: str(tmp_path / "store.json"))
    done = []

    def nested():
        with mod._locked():
            with mod._locked():
                with mod._locked():
                    done.append(True)
    th = _t.Thread(target=nested, daemon=True)
    th.start()
    th.join(5)
    assert done == [True] and not th.is_alive()
    with mod._locked():   # released afterwards: the next caller gets it at once
        pass
