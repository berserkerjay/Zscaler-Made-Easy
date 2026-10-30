"""Deep QA of the deploy slice: pack_deploy, pack_removal, pack_from_tenant,
deployments and proposal_apply.

Regression, Secure by Design and functionality checks for deploying and
removing policy packs, rebuilding a pack from a tenant and applying a
proposal. Every test runs against in-memory fakes (tests/test_pack_deploy
FakeClient); nothing here can reach a tenant.
"""
from __future__ import annotations

import json
import os
import threading

import pytest

import deployments
import pack_deploy as pd
import pack_from_tenant as pft
import pack_removal as pr
import proposal_apply as pa
import proposals
from test_pack_deploy import PREDEF_SSN, FakeClient, Obj, _clone, _dict, _engine, _policy, write_pack
from test_pack_removal import TAG, _deletable, _pack_dir, _tenant
from test_proposals import REPORT, _store

CANARY = "c6-canary-secret-Zq81xx"


@pytest.fixture
def no_activation(monkeypatch):
    """ZIA's activation answers at once, so a run never waits."""
    monkeypatch.setattr(pd.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pd.pc, "wait_active", lambda zia, seconds, log=None: "ACTIVE")


@pytest.fixture
def alpha(tmp_path):
    return write_pack(tmp_path, "alpha", dicts=[_dict("Alpha Dict"), _clone("SSN Clone")],
                      engines=[_engine("Alpha Engine", "(D:Alpha Dict OR D:SSN Clone)")],
                      policies=[_policy("Z-Alpha-Monitor", ["Alpha Engine"], action="BLOCK")],
                      meta={"name": "Alpha Pack", "version": "1", "confidence_tweaks": []})


def _audit_lines():
    import audit
    try:
        with open(audit.path(), encoding="utf-8") as f:
            return [json.loads(x) for x in f if x.strip()]
    except OSError:
        return []


# ---------------------------------------------------------------------------
# 1. Write safety: the gates, monitor-only defaults, dependency order
# ---------------------------------------------------------------------------

def test_deploy_without_an_explicit_write_gate_writes_nothing(alpha):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · WSTG-BUSL-06: a deploy whose write gate is unset (None) is refused, not run."""
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [alpha], writes_enabled=True)

    res = pd.apply(client, [alpha], plan_hash=rep["plan_hash"])

    assert res["status"] == "blocked" and res["results"] == []
    assert client.zia.dlp_dictionary.added == [] and client.zia.dlp_engine.added == [] and client.zia.dlp_web_rules.added == []


def test_removal_without_an_explicit_write_gate_deletes_nothing(tmp_path):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · WSTG-BUSL-06: a removal whose write gate is unset (None) is refused."""
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    plan = pr.plan_removal(client, [pack])

    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"])

    assert res["status"] == "blocked"
    assert len(client.zia.dlp_web_rules.items) == 1 and len(client.zia.dlp_engine.items) == 1


def test_proposal_apply_without_an_explicit_write_gate_is_refused(tmp_path, monkeypatch):
    """ASVS V4.1.3 · A01:2021 · CWE-841 · WSTG-BUSL-06: applying a proposal with the write gate unset (None) raises PermissionError."""
    _store(tmp_path, monkeypatch)
    proposals.refresh_from_report(REPORT, "acme")
    promo = next(p for p in proposals.list_queue("acme") if p["kind"] == "promote_rule")
    proposals.decide("acme", promo["id"], "approve", confirm="I UNDERSTAND")
    client = _proposal_client()

    with pytest.raises(PermissionError):
        pa.apply(client, "acme", promo["id"])

    assert client.zia.dlp_web_rules.updated == []


def test_every_rule_a_pack_creates_is_disabled_and_monitor_only(alpha, no_activation):
    """ASVS V1.4.1 · A04:2021 · CWE-276 · WSTG-CONF-02: a pack rule shipped as BLOCK/ENABLED is created DISABLED and non-enforcing."""
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [alpha], writes_enabled=True)

    pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)

    sent = client.zia.dlp_web_rules.added
    assert len(sent) == 1 and sent[0]["state"] == "DISABLED" and sent[0]["action"] not in pd.ENFORCING_ACTIONS


def test_deploy_creates_dictionaries_then_engines_then_rules(alpha, no_activation):
    """ASVS V1.4.1 · A04:2021 · CWE-696 · WSTG-BUSL-06: creation follows dependency order (dictionary, engine, rule)."""
    client = FakeClient(dicts=[PREDEF_SSN])
    order = []
    z = client.zia
    for svc, meth, kind in ((z.dlp_dictionary, "add_dict", "dictionary"), (z.dlp_engine, "add_dlp_engine", "engine"),
                            (z.dlp_web_rules, "add_rule", "policy")):
        real = getattr(svc, meth)
        setattr(svc, meth, lambda *a, _r=real, _k=kind, **k: (order.append(_k), _r(*a, **k))[1])
    rep = pd.preflight(client, [alpha], writes_enabled=True)

    pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert order == ["dictionary", "dictionary", "engine", "policy"]


def test_undo_deletes_rules_then_engines_then_dictionaries(tmp_path, no_activation, monkeypatch):
    """ASVS V1.4.1 · A04:2021 · CWE-696 · WSTG-BUSL-06: an undo deletes in reverse dependency order (rule, engine, dictionary)."""
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    client = _deletable(_tenant(with_survivors=False))
    order = []
    z = client.zia
    for svc, meth, kind in ((z.dlp_dictionary, "delete_dict", "dictionary"), (z.dlp_engine, "delete_dlp_engine", "engine"),
                            (z.dlp_web_rules, "delete_rule", "policy")):
        real = getattr(svc, meth)
        setattr(svc, meth, lambda oid, _r=real, _k=kind: (order.append(_k), _r(oid))[1])
    record = {"id": "dep-1", "created": [{"kind": "dictionary", "id": 9001, "name": "RM-Dict"},
                                         {"kind": "engine", "id": 5001, "name": "RM-Engine"},
                                         {"kind": "policy", "id": 7001, "name": "RM-Web-Monitor", "channel": "web"}]}

    out = pd.undo(client, record, writes_enabled=True, settle_seconds=0)

    assert out["status"] == "undone" and order == ["policy", "engine", "dictionary"]


# ---------------------------------------------------------------------------
# 2. Plan stability: a tenant or pack that moved since the preflight
# ---------------------------------------------------------------------------

def test_plan_hash_is_stable_for_an_unchanged_tenant_and_pack(alpha):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: two preflights of the same tenant and pack give the same plan_hash."""
    client = FakeClient(dicts=[PREDEF_SSN], rules=[Obj(id=11, name="Customer", order=1, action="ALLOW", rank=7)])

    first = pd.preflight(client, [alpha], writes_enabled=True)["plan_hash"]
    second = pd.preflight(client, [alpha], writes_enabled=True)["plan_hash"]

    assert first and first == second


def test_a_pack_file_edited_after_the_preflight_refuses_the_apply(alpha, no_activation):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: the approved plan binds the pack content, not only names and statuses."""
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [alpha], writes_enabled=True)
    path = os.path.join(alpha["dir"], "configs", "dlp_dictionaries.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump([_dict("Alpha Dict", pattern="SWAPPED-AFTER-APPROVAL"), _clone("SSN Clone")], f)

    res = pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert res["status"] == "plan_changed" and client.zia.dlp_dictionary.added == []


def test_a_tenant_rule_replaced_after_the_preflight_refuses_the_apply(alpha, no_activation):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: a tenant rule swapped for another (same count) changes the plan_hash."""
    client = FakeClient(dicts=[PREDEF_SSN], rules=[Obj(id=11, name="Customer A", order=1, action="ALLOW", rank=7)])
    rep = pd.preflight(client, [alpha], writes_enabled=True)
    client.zia.dlp_web_rules.items = [Obj(id=12, name="Customer B", order=1, action="BLOCK", rank=7)]

    res = pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert res["status"] == "plan_changed" and client.zia.dlp_web_rules.added == []


def test_a_removal_without_the_previewed_plan_hash_is_refused(tmp_path, no_activation):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: a removal with an empty plan_hash deletes nothing (no unreviewed delete)."""
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))

    res = pr.remove(client, [pack], plan_hash="", writes_enabled=True, settle_seconds=0)

    assert res["status"] == "blocked" and "plan_hash" in res["blockers"][0]
    assert len(client.zia.dlp_dictionary.items) == 1 and len(client.zia.dlp_web_rules.items) == 1


def test_a_pick_mode_removal_without_the_previewed_plan_hash_is_refused(tmp_path, no_activation):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: a rule-picker removal with an empty plan_hash deletes nothing."""
    client = _deletable(_tenant(with_survivors=False))

    res = pr.remove_selected(client, [{"channel": "web", "id": 7001}], plan_hash="", writes_enabled=True, settle_seconds=0)

    assert res["status"] == "blocked" and len(client.zia.dlp_web_rules.items) == 1


def test_a_proposal_rule_changed_between_preview_and_write_is_not_overwritten(tmp_path, monkeypatch):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: a rule changed after the preview read is left as the admin set it."""
    _store(tmp_path, monkeypatch)
    proposals.refresh_from_report(REPORT, "acme")
    promo = next(p for p in proposals.list_queue("acme") if p["kind"] == "promote_rule")
    proposals.decide("acme", promo["id"], "approve", confirm="I UNDERSTAND")
    client = _proposal_client()
    rules = client.zia.dlp_web_rules
    reads = {"n": 0}
    real_list = rules.list_rules

    def list_rules():
        reads["n"] += 1
        if reads["n"] == 2:     # an admin sets BLOCK right after the preview read
            rules.items[0] = Obj(**dict(rules.items[0].as_dict(), action="BLOCK"))
        return real_list()
    rules.list_rules = list_rules

    out = pa.apply(client, "acme", promo["id"], writes_enabled=True, by="jane")

    assert out["ok"] is False and rules.updated == [] and rules.items[0].action == "BLOCK"
    assert "previewed" in out["results"][0]["why"]


# ---------------------------------------------------------------------------
# 3. Partial failure: what was written is reported exactly
# ---------------------------------------------------------------------------

def test_a_failed_engine_skips_its_rule_and_the_record_lists_only_what_was_created(alpha, no_activation):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a mid-run failure reports partial and records only created objects."""
    client = FakeClient(dicts=[PREDEF_SSN])
    client.zia.dlp_engine.fail_names = {"Alpha Engine"}
    rep = pd.preflight(client, [alpha], writes_enabled=True)

    res = pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)
    rec = deployments.from_apply(res, tenant_label="t", packs=["alpha"], options={})

    by = {r["name"]: r for r in res["results"]}
    assert res["status"] == "partial" and by["Alpha Engine"]["status"] == "failed"
    assert by["Z-Alpha-Monitor"]["status"] == "skipped" and "dependency failed" in by["Z-Alpha-Monitor"]["reason"]
    assert client.zia.dlp_web_rules.added == []
    assert sorted(c["name"] for c in rec["created"]) == ["Alpha Dict", "SSN Clone"]


# ---------------------------------------------------------------------------
# 4. Removal targeting: tags only, never a customer's lookalike
# ---------------------------------------------------------------------------

def test_a_customer_rule_named_like_a_pack_rule_is_never_deleted(tmp_path, no_activation, monkeypatch):
    """ASVS V4.2.1 · A01:2021 · CWE-863 · WSTG-ATHZ-02: an untagged object that only shares a pack name is kept, not deleted."""
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    pack = _pack_dir(tmp_path)
    client = _deletable(FakeClient(
        dicts=[Obj(id=9001, name="RM-Dict", custom=True, description="customer's own")],
        engines=[Obj(id=5001, name="RM-Engine", engine_expression="D9001.S > 0", description="")],
        rules=[Obj(id=7001, name="RM-Web-Monitor", order=1, action="BLOCK", state="ENABLED", dlp_engines=[{"id": 5001}],
                   description="customer's own")]))

    plan = pr.plan_removal(client, [pack])
    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert plan["remove_count"] == 0 and all(i["status"] == "keep" for i in plan["items"])
    assert res["summary"].get("deleted", 0) == 0
    assert len(client.zia.dlp_web_rules.items) == 1 and len(client.zia.dlp_engine.items) == 1 and len(client.zia.dlp_dictionary.items) == 1


def test_a_generic_legacy_name_is_never_deleted_by_remove_everything(tmp_path):
    """ASVS V4.2.1 · A01:2021 · CWE-863 · WSTG-ATHZ-02: a customer's own untagged "PCI - High" engine survives "remove everything"."""
    pack = _pack_dir(tmp_path)
    client = FakeClient(engines=[Obj(id=5103, name="PCI - High", engine_expression="D1.S > 9", description="")])

    plan = pr.plan_removal(client, [pack], everything=True)

    item = next(i for i in plan["items"] if i["name"] == "PCI - High")
    assert item["status"] == "keep" and plan["remove_count"] == 0


def test_removing_one_pack_never_matches_a_longer_pack_ids_legacy_tag(tmp_path):
    """ASVS V4.2.1 · A01:2021 · CWE-1023 · WSTG-ATHZ-02: removing pack "removeme" leaves objects tagged for "removeme_v2"."""
    pack = _pack_dir(tmp_path)
    other = "[DLP-Check pack removeme_v2 v3]"
    client = FakeClient(dicts=[Obj(id=9101, name="Other-Dict", custom=True, description="x " + other)],
                        engines=[Obj(id=5101, name="Other-Engine", engine_expression="D9101.S > 0", description=other)],
                        rules=[Obj(id=7101, name="Other-Rule", order=1, action="ALLOW", dlp_engines=[{"id": 5101}], description=other)])

    plan = pr.plan_removal(client, [pack])

    assert not any(i["name"].startswith("Other-") for i in plan["items"])


@pytest.mark.parametrize("desc,expected", [
    ("[DLP-Check pack removeme]", True),
    ("note [DLP-Check pack removeme v1]", True),
    ("[DLP-Check baseline removeme v1] Measured on every journey check, never overwritten.", True),
    ("[DLP-Check pack removeme_v2 v1]", False),
    ("[DLP-Check pack removemeX]", False),
    ("", False),
    (None, False),
])
def test_the_legacy_tag_names_the_pack_id_whole(desc, expected):
    """ASVS V4.2.1 · A01:2021 · CWE-1023 · WSTG-ATHZ-02: the tool's legacy tag matches its exact pack id and no longer prefix."""
    assert pd.has_mark(desc, pack_id="removeme") is expected


def test_tagged_objects_are_still_removed_with_their_pack(tmp_path, monkeypatch):
    """ASVS V4.2.1 · A01:2021 · CWE-863 · WSTG-ATHZ-02: regression: the pack's own tagged objects are still removed in full."""
    monkeypatch.setattr(pr.pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    pack = _pack_dir(tmp_path)
    client = _deletable(_tenant(with_survivors=False))
    plan = pr.plan_removal(client, [pack])

    res = pr.remove(client, [pack], plan_hash=plan["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert res["status"] == "removed" and res["summary"] == {"deleted": 3}


def test_an_unchanged_removal_plan_has_a_stable_hash(tmp_path):
    """ASVS V11.1.1 · A04:2021 · CWE-367 · WSTG-BUSL-01: two previews of the same tenant give the same removal plan_hash."""
    pack = _pack_dir(tmp_path)
    client = _tenant(with_survivors=False)

    assert pr.plan_removal(client, [pack])["plan_hash"] == pr.plan_removal(client, [pack])["plan_hash"]


# ---------------------------------------------------------------------------
# 5. Idempotence
# ---------------------------------------------------------------------------

def test_deploying_the_same_pack_twice_writes_nothing_the_second_time(alpha, no_activation):
    """ASVS V11.1.2 · A04:2021 · CWE-837 · WSTG-BUSL-05: a second deploy of a deployed pack creates nothing and fails nothing."""
    client = FakeClient(dicts=[PREDEF_SSN])
    first = pd.preflight(client, [alpha], writes_enabled=True)
    pd.apply(client, [alpha], plan_hash=first["plan_hash"], writes_enabled=True, settle_seconds=0)
    adds = (len(client.zia.dlp_dictionary.added), len(client.zia.dlp_engine.added), len(client.zia.dlp_web_rules.added))

    second = pd.preflight(client, [alpha], writes_enabled=True)
    res = pd.apply(client, [alpha], plan_hash=second["plan_hash"], writes_enabled=True, settle_seconds=0)

    assert second["will_create"] == 0 and res["status"] == "blocked"
    assert (len(client.zia.dlp_dictionary.added), len(client.zia.dlp_engine.added), len(client.zia.dlp_web_rules.added)) == adds


# ---------------------------------------------------------------------------
# 6. Audit: every write, no secrets
# ---------------------------------------------------------------------------

def test_every_deploy_write_is_audited_without_secrets(alpha, no_activation):
    """ASVS V7.1.1 · A09:2021 · CWE-778 · WSTG-ERRH-01: each created object leaves an object_write entry; no secret is logged."""
    client = FakeClient(dicts=[PREDEF_SSN])
    client.config = {"clientSecret": CANARY}
    rep = pd.preflight(client, [alpha], writes_enabled=True)

    pd.apply(client, [alpha], plan_hash=rep["plan_hash"], writes_enabled=True, settle_seconds=0)

    writes = [e for e in _audit_lines() if e.get("event") == "object_write"]
    assert sorted(e["name"] for e in writes) == ["Alpha Dict", "Alpha Engine", "SSN Clone", "Z-Alpha-Monitor"]
    import audit
    with open(audit.path(), encoding="utf-8") as f:
        assert CANARY not in f.read()


def test_a_proposal_rule_write_is_audited_with_its_run_and_tenant(tmp_path, monkeypatch):
    """ASVS V7.1.3 · A09:2021 · CWE-778 · WSTG-ERRH-01: the rule write of an applied proposal names the run and the tenant."""
    _store(tmp_path, monkeypatch)
    proposals.refresh_from_report(REPORT, "acme")
    promo = next(p for p in proposals.list_queue("acme") if p["kind"] == "promote_rule")
    proposals.decide("acme", promo["id"], "approve", confirm="I UNDERSTAND")

    pa.apply(_proposal_client(), "acme", promo["id"], writes_enabled=True, by="jane")

    w = [e for e in _audit_lines() if e.get("event") == "object_write"]
    assert len(w) == 1 and w[0]["run"] == "proposal_apply" and w[0]["tenant"] == proposals.tenant_key("acme")


# ---------------------------------------------------------------------------
# 7. Pack files are untrusted input
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("content", [
    '{"name": "not a list"}',
    '[1, "two"]',
    '[{"name": 5}]',
    '[{"name": "R", "sub_rules": "x"}]',
    "not json at all",
    "[" * 200 + "]" * 200,
], ids=["object", "scalars", "number-name", "bad-sub-rules", "not-json", "deep"])
def test_a_pack_file_that_is_not_a_pack_is_a_blocked_plan_not_a_crash(tmp_path, content):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: a malformed pack file gives a plain blocked plan before the tenant is read."""
    pack = write_pack(tmp_path, "bad", dicts=[_dict("D")])
    with open(os.path.join(pack["dir"], "configs", "dlp_policies.json"), "w", encoding="utf-8") as f:
        f.write(content)
    client = FakeClient()
    client.zia.dlp_dictionary.list_dicts = lambda: pytest.fail("the tenant must not be read for an unusable pack")

    rep = pd.preflight(client, [pack], writes_enabled=True)

    assert rep["status"] == "blocked" and "dlp_policies.json" in rep["blockers"][0] and rep["plan_hash"] == ""


@pytest.mark.parametrize("kw", [
    {"policies": [{"name": "R", "engines": None}]},
    {"policies": [{"name": "R", "engines": [], "protocols": 5}]},
    {"policies": [{"name": "R", "engines": [], "rank": "high"}]},
    {"policies": [{"name": "R", "engines": [], "sub_rules": [{"name": "S", "engines": "E"}]}]},
    {"engines": [{"name": "E", "expression": 5}]},
    {"dicts": [{"name": "D", "patterns": "abc"}]},
    {"dicts": [{"name": "D", "patterns": ["abc"]}]},
    {"dicts": [{"name": "D", "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": 5}]}]},
    {"dicts": [{"name": "D", "proximity": "far", "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "x"}]}]},
    {"dicts": [{"name": "D", "predefined_clone": "yes"}]},
], ids=["engines-null", "protocols-int", "rank-text", "sub-rule-engines-text", "expression-int", "patterns-text",
        "pattern-entries-text", "pattern-value-int", "proximity-text", "clone-flag-text"])
def test_a_pack_field_of_the_wrong_type_is_a_blocked_plan_not_a_crash(tmp_path, kw):
    """ASVS V5.1.4 · A03:2021 · CWE-1287 · WSTG-INPV-01: a field of the wrong type in a pack file is refused with a plain message."""
    pack = write_pack(tmp_path, "typed", **kw)

    rep = pd.preflight(FakeClient(dicts=[PREDEF_SSN]), [pack], writes_enabled=True)
    plan = pr.plan_removal(FakeClient(), [pack])

    assert rep["status"] == "blocked" and "wrong type" in rep["blockers"][0]
    assert plan["status"] == "blocked" and "wrong type" in plan["blockers"][0]


def test_a_digit_string_rank_and_a_null_description_still_load(tmp_path):
    """ASVS V5.1.4 · A03:2021 · CWE-1287 · WSTG-INPV-01: boundary: "0" as a number and null text stay accepted (no false refusal)."""
    pack = write_pack(tmp_path, "ok", dicts=[dict(_dict("D"), description=None)], engines=[_engine("E", "(D:D > 0)")],
                      policies=[dict(_policy("R", ["E"]), rank="0")])

    rep = pd.preflight(FakeClient(), [pack], writes_enabled=True)

    assert rep["status"] in ("ready", "warnings") and rep["will_create"] == 3


def test_an_oversized_pack_file_is_refused(tmp_path, monkeypatch):
    """ASVS V12.1.1 · A05:2021 · CWE-400 · WSTG-BUSL-09: a pack file over the size cap is refused, not parsed."""
    monkeypatch.setattr(pd, "PACK_FILE_MAX_BYTES", 64)
    pack = write_pack(tmp_path, "big", dicts=[_dict("D" * 80)])

    with pytest.raises(pd.PackFileError, match="larger than"):
        pd.load_pack_file(os.path.join(pack["dir"], "configs"), "dlp_dictionaries.json", "big")


def test_a_missing_or_null_pack_file_is_an_empty_list(tmp_path):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: boundary: an absent file and a JSON null both read as no objects."""
    (tmp_path / "n.json").write_text("null")

    assert pd.load_pack_file(str(tmp_path), "absent.json") == [] and pd.load_pack_file(str(tmp_path), "n.json") == []


def test_a_removal_preview_of_a_malformed_pack_is_blocked_not_a_crash(tmp_path):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: a removal preview of a pack whose file is not a pack is a plain refusal."""
    pack = write_pack(tmp_path, "bad", dicts=[_dict("D")])
    with open(os.path.join(pack["dir"], "configs", "dlp_engines.json"), "w", encoding="utf-8") as f:
        f.write('{"engines": 1}')

    plan = pr.plan_removal(FakeClient(), [pack])

    assert plan["status"] == "blocked" and "dlp_engines.json" in plan["blockers"][0]


def test_a_utf8_bom_pack_file_still_loads(tmp_path):
    """ASVS V5.1.4 · A03:2021 · CWE-20 · WSTG-INPV-01: regression: a pack saved with a UTF-8 byte-order mark is read as before."""
    (tmp_path / "dlp_dictionaries.json").write_bytes("﻿".encode() + json.dumps([_dict("Ünïcode Dict")]).encode())

    assert pd.load_pack_file(str(tmp_path), "dlp_dictionaries.json")[0]["name"] == "Ünïcode Dict"


# ---------------------------------------------------------------------------
# pack_from_tenant: tenant names are untrusted
# ---------------------------------------------------------------------------

def _pair(lang: str):
    entry = {"patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "x"}], "phrases": []}
    return [dict(entry, name=f"{lang} Signal"), dict(entry, name=f"{lang} Anchor")]


def test_the_name_filter_is_never_run_as_a_regular_expression(monkeypatch):
    """ASVS V5.1.5 · A05:2021 · CWE-1333 · WSTG-INPV-13: the operator's filter is never compiled, so "(a+)+$" cannot backtrack."""
    import re as _re

    class NoCompile:
        def __getattr__(self, name):
            return getattr(_re, name)

        def compile(self, *a, **k):
            raise AssertionError("the name filter was compiled as a regular expression")
    monkeypatch.setattr(pft, "re", NoCompile())
    names = [{"name": "a" * 12 + "!", "patterns": [], "phrases": []}] + _pair("Python")

    out = pft.pair_anchor_signal(names, "(a+)+$")

    assert out["pairs"] == {}


@pytest.mark.parametrize("flt,expected", [
    ("", True), ("python", True), ("^src-", True), ("signal$", True), ("^SRC-Python Signal$", True),
    ("^python", False), ("src-$", False), ("PYTHON SIG", True), ("ß", False),
])
def test_the_name_filter_supports_prefix_suffix_and_substring(flt, expected):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: the literal filter: substring, ^prefix, suffix$, both, case-folded."""
    assert pft._filter_matches(flt, "SRC-Python Signal") is expected


def test_a_dictionary_name_that_would_rewrite_the_engine_expression_is_ignored():
    """ASVS V5.3.10 · A03:2021 · CWE-74 · WSTG-INPV-11: a tenant name smuggling ") OR (D:..." never reaches an engine expression."""
    dicts = _pair("Py) OR (D:CREDIT_CARD") + _pair("Go")

    out = pft.pair_anchor_signal(dicts)
    _d, engines = pft.build_configs(out["pairs"])

    assert [e["name"] for e in engines] == ["SRC-Go"] and all("CREDIT_CARD" not in e["expression"] for e in engines)
    assert any("cannot be used in an engine expression" in i for i in out["ignored"])


@pytest.mark.parametrize("name,ok", [("SRC-Python Signal", True), ("Names (US) Signal", True), ("Ünïcode Anchor", True),
                                     ("Bad\nSignal", False), (" Lead Signal", False), ("A > 0 Signal", False), ("", False)])
def test_only_names_that_stay_one_expression_term_are_usable(name, ok):
    """ASVS V5.3.10 · A03:2021 · CWE-74 · WSTG-INPV-11: boundary table of dictionary names the rebuild accepts."""
    assert pft._usable_name(name) is ok


def test_a_rebuild_refuses_a_pack_whose_rules_file_is_not_a_pack(tmp_path):
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: the rebuild stops with a plain error, and writes no file, on a bad rules file."""
    cfg = tmp_path / "pack" / "configs"
    cfg.mkdir(parents=True)
    (cfg / "dlp_policies.json").write_text('{"rules": "not a list"}')
    client = FakeClient(dicts=[Obj(id=1, name=n["name"], custom=True, patterns=n["patterns"], phrases=[]) for n in _pair("Python")])

    out = pft.rebuild_from_tenant(client, str(tmp_path / "pack"), dry_run=False)

    assert out["status"] == "error" and "dlp_policies.json" in out["error"]
    assert not (cfg / "dlp_dictionaries.json").exists() and not (cfg / "dlp_engines.json").exists()


def test_a_rebuilt_pack_is_written_owner_only(tmp_path):
    """ASVS V8.3.4 · A01:2021 · CWE-732 · WSTG-CONF-11: the rebuilt pack files (tenant dictionaries) are 0600."""
    client = FakeClient(dicts=[Obj(id=1, name=n["name"], custom=True, patterns=n["patterns"], phrases=[]) for n in _pair("Python")])
    (tmp_path / "pack" / "configs").mkdir(parents=True)
    (tmp_path / "pack" / "configs" / "dlp_policies.json").write_text(json.dumps([{"name": "R", "engines": ["Old"]}]))

    out = pft.rebuild_from_tenant(client, str(tmp_path / "pack"), dry_run=False)

    assert out["status"] == "written" and out["rules_rewired"] == ["R"]
    for fn in ("dlp_dictionaries.json", "dlp_engines.json", "dlp_policies.json"):
        if os.name == "posix":
            assert oct(os.stat(tmp_path / "pack" / "configs" / fn).st_mode & 0o777) == "0o600"


# ---------------------------------------------------------------------------
# deployments.py: the record store
# ---------------------------------------------------------------------------

def test_two_records_written_at_once_are_both_kept(monkeypatch):
    """ASVS V11.1.6 · A04:2021 · CWE-362 · WSTG-BUSL-07: two deployments finishing together never lose a record."""
    real_write = deployments._write
    a_in_write, b_started, b_done = threading.Event(), threading.Event(), threading.Event()
    first = {"done": False}

    def write(data):
        if not first["done"]:
            first["done"] = True
            a_in_write.set()
            b_started.wait(1)
            b_done.wait(0.3)     # with the lock B cannot finish while A writes; without it B would
        real_write(data)
    monkeypatch.setattr(deployments, "_write", write)

    def run_b():
        b_started.set()
        deployments.add({"id": "dep-b", "created": []})
        b_done.set()
    ta = threading.Thread(target=deployments.add, args=({"id": "dep-a", "created": []},))
    ta.start()
    a_in_write.wait(1)
    tb = threading.Thread(target=run_b)
    tb.start()
    ta.join(2)
    tb.join(2)

    assert sorted(r["id"] for r in deployments._read()["deployments"]) == ["dep-a", "dep-b"]


@pytest.mark.parametrize("content", ['["a list"]', '{"deployments": null}', '{"deployments": "x"}', '{"deployments": [1, {"no": "id"}]}', "{"])
def test_a_store_of_another_shape_reads_as_empty_not_a_crash(content):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: a deployments file of another shape lists nothing instead of raising."""
    with open(deployments.store_path(), "w", encoding="utf-8") as f:
        f.write(content)

    assert deployments.list_all() == [] and deployments.get("x") is None


def test_an_older_record_without_kinds_still_summarises():
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: regression: a record saved by an older version (no kind, no status) loads."""
    with open(deployments.store_path(), "w", encoding="utf-8") as f:
        json.dump({"deployments": [{"id": "dep-old", "at": "2024-01-01", "created": [{"name": "X", "id": 1}, "junk"]}]}, f)

    rows = deployments.list_all()

    assert rows[0]["id"] == "dep-old" and rows[0]["created"] == 1 and rows[0]["remaining"] == 1


def test_the_store_is_owner_only_and_adds_refuse_a_non_record():
    """ASVS V8.3.4 · A01:2021 · CWE-276 · WSTG-CONF-11: the store is written 0600 and add() refuses anything but a record."""
    deployments.add({"id": "dep-1", "created": []})

    with pytest.raises(ValueError):
        deployments.add(None)
    if os.name == "posix":
        assert oct(os.stat(deployments.store_path()).st_mode & 0o777) == "0o600"


def test_an_undo_marks_only_the_deleted_items_and_a_second_undo_retries_the_rest():
    """ASVS V11.1.2 · A04:2021 · CWE-837 · WSTG-BUSL-05: mark_undo flags deleted and gone items; the rest stay to retry."""
    deployments.add({"id": "dep-1", "created": [{"kind": "engine", "id": 1, "name": "E"}, {"kind": "dictionary", "id": 2, "name": "D"}]})

    rec = deployments.mark_undo("dep-1", [{"kind": "engine", "id": 1, "status": "deleted"}, {"kind": "dictionary", "id": 2, "status": "failed"}],
                                complete=False)

    assert [c.get("undone", False) for c in rec["created"]] == [True, False] and rec.get("undone_at") is None
    assert deployments.summary(rec)["remaining"] == 1 and deployments.mark_undo("nope", [], complete=True) is None


def test_a_record_keeps_the_tenant_key_but_the_summary_never_shows_it():
    """ASVS V8.3.1 · A02:2021 · CWE-200 · WSTG-INFO-05: the tenant fingerprint is stored for matching and never in the summary."""
    res = {"status": "applied", "results": [{"kind": "policy", "name": "R", "id": 9, "status": "created"}]}

    rec = deployments.from_apply(res, tenant_label="t", packs=["p"], options={}, tenant_fp="fp-secret-ish")

    assert rec["tenant_fp"] == "fp-secret-ish" and "fp-secret-ish" not in json.dumps(deployments.summary(rec))
    assert deployments.from_apply({"results": [{"kind": "policy", "status": "reused", "id": 1}]}, tenant_label="t", packs=[], options={}) is None


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _proposal_client(action="ALLOW"):
    return FakeClient(rules=[Obj(id=7003, name="Old-Monitor", order=1, rank=7, action=action, state="ENABLED",
                                 dlp_engines=[{"id": 5100}], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_HIGH",
                                 last_modified_time=123, zscaler_incident_receiver=False)])


def test_an_undo_preview_skips_record_entries_that_are_not_objects(tmp_path):
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: a deployment record with a junk entry still previews its undo."""
    client = _tenant(with_survivors=False)
    record = {"id": "dep-1", "created": ["junk", None, {"kind": "policy", "id": 7001, "name": "RM-Web-Monitor", "channel": "web"}]}

    plan = pr.plan_removal_deployment(client, record)

    assert plan["status"] == "ready" and [i["name"] for i in plan["items"]] == ["RM-Web-Monitor"]


def test_a_tenant_dictionary_with_a_non_numeric_proximity_is_read_without_a_crash():
    """ASVS V5.1.3 · A03:2021 · CWE-20 · WSTG-INPV-01: an untrusted tenant field of the wrong type is dropped, not fatal."""
    client = FakeClient(dicts=[Obj(id=1, name="Go Signal", custom=True, proximity="near", phrases=[],
                                   patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "x"}])])

    dicts, err = pft.read_custom_dictionaries(client)

    assert err is None and dicts[0]["name"] == "Go Signal" and "proximity" not in dicts[0]


# ---------------------------------------------------------------------------
# proposal_apply: every error path answers in plain words
# ---------------------------------------------------------------------------

def _approved(tmp_path, monkeypatch, kind="promote_rule"):
    _store(tmp_path, monkeypatch)
    proposals.refresh_from_report(REPORT, "acme")
    p = next(x for x in proposals.list_queue("acme") if x["kind"] == kind)
    proposals.decide("acme", p["id"], "approve", confirm="I UNDERSTAND")
    return p


@pytest.mark.parametrize("make,why", [
    (lambda: FakeClient(), "unknown channel"),
], ids=["unknown-channel"])
def test_reading_a_rule_on_an_unknown_channel_is_a_plain_error(make, why):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a channel the app does not know is refused with a message."""
    with pytest.raises(ValueError, match=why):
        pa.read_rule(make(), "no-such-channel", name="R")


def test_reading_rules_without_a_service_or_lister_is_a_plain_error():
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a client lacking the rule service, or its list call, says so."""
    client = FakeClient()
    del client.zia.dlp_web_rules
    with pytest.raises(ValueError, match="no .* service"):
        pa.read_rule(client, "web", name="R")
    client.zia.dlp_web_rules = object()

    rule, err = pa.read_rule(client, "web", name="R")

    assert rule is None and "cannot list rules" in err


def test_a_rule_list_that_raises_is_reported_not_raised():
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a list call that raises becomes a could-not-read message."""
    client = FakeClient()
    client.zia.dlp_web_rules.list_rules = lambda: (_ for _ in ()).throw(RuntimeError("HTTP 500"))

    rule, err = pa.read_rule(client, "web", rule_id=1)

    assert rule is None and "could not read" in err and "HTTP 500" in err


def test_a_rule_is_found_by_name_when_its_id_is_unknown():
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: lookup by id first, then by exact name."""
    rule, err = pa.read_rule(_proposal_client(), "web", rule_id=999, name="Old-Monitor")

    import pack_channels
    assert err is None and str(pack_channels._field(rule, "id")) == "7003"


def test_the_update_body_drops_read_only_and_private_fields_of_a_plain_object():
    """ASVS V5.1.2 · A08:2021 · CWE-915 · WSTG-INPV-20: the body sent back never carries read-only, private or null fields."""
    class Plain:
        def __init__(self):
            self.id, self.name, self.last_modified_time, self._raw, self.order, self.description = 1, "R", 5, "x", 2, None

    assert pa._body_from(Plain()) == {"name": "R", "order": 2}


def test_a_proposal_already_in_effect_is_a_no_op(tmp_path, monkeypatch):
    """ASVS V11.1.2 · A04:2021 · CWE-837 · WSTG-BUSL-05: a rule already at the proposed value is unchanged, not written."""
    p = _approved(tmp_path, monkeypatch)
    client = _proposal_client(action="CONFIRM")

    out = pa.apply(client, "acme", p["id"], writes_enabled=True)

    assert out["ok"] and out["changed"] == 0 and out["results"][0]["result"] == "unchanged" and client.zia.dlp_web_rules.updated == []


def test_a_rollback_of_a_proposal_never_applied_is_refused(tmp_path, monkeypatch):
    """ASVS V11.1.1 · A04:2021 · CWE-841 · WSTG-BUSL-06: only an applied (or failed) change can be rolled back."""
    p = _approved(tmp_path, monkeypatch)

    with pytest.raises(ValueError, match="only an applied change"):
        pa.rollback(_proposal_client(), "acme", p["id"], writes_enabled=True)


def test_a_rollback_without_a_recorded_value_is_refused_in_the_preview(tmp_path, monkeypatch):
    """ASVS V11.1.1 · A04:2021 · CWE-754 · WSTG-BUSL-06: no recorded before-value means no guess: the preview refuses."""
    p = _approved(tmp_path, monkeypatch)
    proposals.set_status("acme", p["id"], "applied", rollback={})

    pv = pa.preview(_proposal_client(), "acme", p["id"], direction="rollback")

    assert pv["ok"] is False and "no recorded value" in pv["steps"][0]["why"]


def test_a_rollback_already_in_place_is_a_no_op(tmp_path, monkeypatch):
    """ASVS V11.1.2 · A04:2021 · CWE-837 · WSTG-BUSL-05: rolling back to the value the rule already has changes nothing."""
    p = _approved(tmp_path, monkeypatch)
    proposals.set_status("acme", p["id"], "applied", applied={"before": {"7003": "ALLOW"}})

    out = pa.rollback(_proposal_client(), "acme", p["id"], writes_enabled=True)

    assert out["ok"] and out["status"] == "rolled_back" and out["changed"] == 0


def test_a_refused_rule_write_is_reported_failed(tmp_path, monkeypatch):
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: ZIA refusing the update marks the proposal failed, with the reason."""
    p = _approved(tmp_path, monkeypatch)
    client = _proposal_client()
    client.zia.dlp_web_rules.update_rule = lambda rule_id, **kw: (None, None, {"status": 400, "message": "INVALID_INPUT_ARGUMENT"})

    out = pa.apply(client, "acme", p["id"], writes_enabled=True)

    assert out["ok"] is False and out["status"] == "failed" and "INVALID_INPUT_ARGUMENT" in out["results"][0]["why"]


def test_a_read_back_that_disagrees_is_reported_failed(tmp_path, monkeypatch):
    """ASVS V7.4.1 · A04:2021 · CWE-754 · WSTG-ERRH-01: a write the tenant did not keep is failed, never reported as changed."""
    p = _approved(tmp_path, monkeypatch)
    client = _proposal_client()
    rules = client.zia.dlp_web_rules
    rules.update_rule = lambda rule_id, **kw: (rules.items[0], None, None)     # accepted, but nothing changes

    out = pa.apply(client, "acme", p["id"], writes_enabled=True)

    assert out["ok"] is False and "read-back shows action = ALLOW" in out["results"][0]["why"]


def test_a_lost_audit_line_is_reported_loudly_and_the_result_stands(tmp_path, monkeypatch):
    """ASVS V7.1.4 · A09:2021 · CWE-778 · WSTG-ERRH-01: an audit write that fails is reported, and the applied result is kept."""
    import audit
    p = _approved(tmp_path, monkeypatch)
    reported = []
    monkeypatch.setattr(audit, "record", lambda *a, **k: (_ for _ in ()).throw(OSError("disk full")))
    monkeypatch.setattr(audit, "report_failure", lambda what, e: reported.append(what))

    out = pa.apply(_proposal_client(), "acme", p["id"], writes_enabled=True)

    assert out["ok"] and reported and p["id"] in reported[0]


# ---------------------------------------------------------------------------
# pack_from_tenant: reading the tenant and the CLI
# ---------------------------------------------------------------------------

def test_a_dictionary_list_that_fails_is_a_plain_error():
    """ASVS V7.4.1 · A04:2021 · CWE-755 · WSTG-ERRH-01: a refused or raising list call is an error message, never a crash."""
    refused = FakeClient(dict_fail=True)
    raising = FakeClient()
    raising.zia.dlp_dictionary.list_dicts = lambda: (_ for _ in ()).throw(RuntimeError("timeout"))

    assert pft.read_custom_dictionaries(refused)[1] == "Could not list dictionaries: boom"
    assert "timeout" in pft.read_custom_dictionaries(raising)[1]
    assert pft.rebuild_from_tenant(refused, "/nonexistent")["status"] == "error"


def test_only_custom_pattern_dictionaries_are_read():
    """ASVS V5.1.3 · A04:2021 · CWE-20 · WSTG-INPV-01: predefined dictionaries, clones and empty dictionaries are left out."""
    pat = [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "x"}]
    client = FakeClient(dicts=[Obj(id=1, name="Predef Signal", custom=False, patterns=pat),
                               Obj(id=2, name="Clone Signal", custom=True, dict_template_id=5, patterns=pat),
                               Obj(id=3, name="Empty Signal", custom=True, patterns=[], phrases=[]),
                               Obj(id=4, name="Go Signal", custom=True, patterns=pat, phrases=[], proximity=10)])

    dicts, err = pft.read_custom_dictionaries(client)

    assert err is None and [(d["name"], d.get("proximity")) for d in dicts] == [("Go Signal", 10)]


def test_the_cli_refuses_to_run_without_credentials(monkeypatch, capsys):
    """ASVS V14.2.1 · A05:2021 · CWE-522 · WSTG-CONF-02: the CLI stops (exit 2) when the API credentials are not all set."""
    for k in ("ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET", "ZSCALER_VANITY_DOMAIN"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setattr("sys.argv", ["pack_from_tenant.py", "--dry-run"])

    assert pft._main() == 2 and "Set ZSCALER_CLIENT_ID" in capsys.readouterr().out


def test_the_cli_previews_through_a_client_and_never_prints_the_secret(monkeypatch, capsys):
    """ASVS V8.3.4 · A09:2021 · CWE-532 · WSTG-INFO-05: a dry run prints the preview, never the client secret."""
    import zscaler
    env = {"ZSCALER_CLIENT_ID": "id-123", "ZSCALER_CLIENT_SECRET": CANARY, "ZSCALER_VANITY_DOMAIN": "acme", "ZSCALER_CLOUD": "beta"}
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    seen = {}
    pat = [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "x"}]
    fake = FakeClient(dicts=[Obj(id=1, name=n, custom=True, patterns=pat, phrases=[]) for n in ("Go Signal", "Go Anchor")])
    monkeypatch.setattr(zscaler, "ZscalerClient", lambda cfg: (seen.update(cfg), fake)[1])
    monkeypatch.setattr("sys.argv", ["pack_from_tenant.py", "--dry-run", "--pack", "no_such_pack"])

    rc = pft._main()

    out = capsys.readouterr().out
    assert rc == 0 and '"status": "preview"' in out and CANARY not in out and seen["vanityDomain"] == "acme"


# ---------------------------------------------------------------------------
# deployments.py: operations (Bulk changes) share the store
# ---------------------------------------------------------------------------

def test_operations_are_stored_listed_and_marked_undone():
    """ASVS V7.1.3 · A09:2021 · CWE-778 · WSTG-BUSL-05: an operation record is kept, listed per tenant and marked when undone."""
    op = {"id": deployments.new_operation_id(), "at": "2026-01-01T00:00:00+00:00", "tenant_label": "t1", "type": "rule_state",
          "inverse": {"type": "rule_state"}}
    deployments.add_operation(op)
    deployments.add_operation(dict(op, id="op-other", tenant_label="t2"))

    partial = deployments.mark_operation_undone(op["id"], "op-undo-1", complete=False)
    rows = deployments.list_operations("t1")

    assert partial["undo_runs"][0]["complete"] is False and "undone_by" not in partial
    assert [r["id"] for r in rows] == [op["id"]] and rows[0]["can_undo"] is True
    assert deployments.mark_operation_undone(op["id"], "op-undo-2", complete=True)["undone_by"] == "op-undo-2"
    assert deployments.list_operations("t1")[0]["can_undo"] is False
    assert deployments.get_operation("op-missing") is None and deployments.mark_operation_undone("op-missing", "x", complete=True) is None


def test_deployments_are_listed_per_tenant_newest_first():
    """ASVS V4.2.1 · A01:2021 · CWE-639 · WSTG-ATHZ-04: the list filters by tenant label and sorts newest first."""
    for i, (label, at) in enumerate((("t1", "2026-01-01"), ("t2", "2026-02-01"), ("t1", "2026-03-01"))):
        deployments.add({"id": f"dep-{i}", "at": at, "tenant_label": label, "created": []})

    assert [r["id"] for r in deployments.list_all("t1")] == ["dep-2", "dep-0"] and len(deployments.list_all()) == 3


def test_a_rollback_without_a_recorded_value_writes_nothing(tmp_path, monkeypatch):
    """ASVS V11.1.1 · A04:2021 · CWE-754 · WSTG-BUSL-06: no recorded before-value never becomes an empty action sent to ZIA."""
    p = _approved(tmp_path, monkeypatch)
    proposals.set_status("acme", p["id"], "applied", rollback={})
    client = _proposal_client(action="CONFIRM")

    with pytest.raises(ValueError, match="no recorded value"):
        pa.rollback(client, "acme", p["id"], writes_enabled=True)

    assert client.zia.dlp_web_rules.updated == []


def test_a_proposal_that_names_no_target_value_is_refused(tmp_path, monkeypatch):
    """ASVS V5.1.3 · A04:2021 · CWE-754 · WSTG-BUSL-06: a proposal whose change has no "to" value is refused, never written as ""."""
    p = _approved(tmp_path, monkeypatch)
    rec = proposals.get("acme", p["id"])
    proposals.set_status("acme", p["id"], "approved", change=dict(rec["change"], to=None))
    client = _proposal_client()

    with pytest.raises(ValueError, match="names no value"):
        pa.apply(client, "acme", p["id"], writes_enabled=True)

    assert client.zia.dlp_web_rules.updated == []
