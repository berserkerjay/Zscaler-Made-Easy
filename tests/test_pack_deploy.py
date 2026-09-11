"""
Unit tests for pack_deploy — the multi-pack preflight planner + executor.

These run entirely against an in-memory fake of the three ZIA SDK
services the planner touches (dlp_dictionary, dlp_engine,
dlp_web_rules), so they need neither the zscaler SDK nor a tenant.
"""
from __future__ import annotations

import json
import os

import pytest

import pack_deploy as pd


# ---------------------------------------------------------------------------
# Fake ZIA client — mimics the (data, response, error) tuple shape of the SDK
# ---------------------------------------------------------------------------

class Obj:
    """Stand-in for an SDK model: attribute access plus as_dict()."""
    def __init__(self, **kw):
        self.__dict__.update(kw)

    def as_dict(self):
        return dict(self.__dict__)


class FakeDicts:
    def __init__(self, items=None, fail=False):
        self.items = list(items or [])
        self.fail = fail
        self.added = []
        self.updated = []
        self._next = 9000
        self.fail_names = set()

    def list_dicts(self):
        if self.fail:
            return None, "boom"
        return list(self.items), None

    def add_dict(self, name, match_type, dict_type, **kw):
        self.added.append({"name": name, "match": match_type, **kw})
        if name in self.fail_names:
            return None, None, {"message": "simulated API error"}
        self._next += 1
        # The SDK takes (action, value) tuples but the API returns objects;
        # store the response shape so verification can read it back.
        stored = {k: v for k, v in kw.items() if k != "custom"}
        for key, field in (("patterns", "pattern"), ("phrases", "phrase")):
            if stored.get(key):
                stored[key] = [{"action": v[0], field: v[1]} if isinstance(v, (tuple, list)) else v for v in stored[key]]
        obj = Obj(id=self._next, name=name, custom=True, custom_phrase_match_type=match_type, dictionary_type=dict_type, **stored)
        self.items.append(obj)
        return obj, None, None

    def update_dict(self, id_, **kw):
        self.updated.append({"id": id_, **kw})
        # PUT semantics: the stored object becomes the new payload (API shape).
        stored = {k: v for k, v in kw.items() if k != "custom"}
        for key, field in (("patterns", "pattern"), ("phrases", "phrase")):
            if stored.get(key):
                stored[key] = [{"action": v[0], field: v[1]} if isinstance(v, (tuple, list)) else v for v in stored[key]]
        for i, it in enumerate(self.items):
            if it.id == id_:
                merged = dict(it.as_dict())
                merged.update(stored)
                self.items[i] = Obj(**merged)
                return self.items[i], None, None
        return Obj(id=id_, **stored), None, None


class FakeEngines:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.added = []
        self._next = 5000
        self.fail_names = set()

    def list_dlp_engines(self):
        return list(self.items), None

    def list_dlp_engines_lite(self):
        return list(self.items), None

    def add_dlp_engine(self, **kw):
        self.added.append(kw)
        if kw["name"] in self.fail_names:
            return None, None, {"message": "simulated engine failure"}
        self._next += 1
        obj = Obj(id=self._next, name=kw["name"], engine_expression=kw["engine_expression"],
                  description=kw.get("description"))
        self.items.append(obj)
        return obj, None, None

    def update_dlp_engine(self, engine_id, **kw):
        self.updated = getattr(self, "updated", [])
        self.updated.append({"id": engine_id, **kw})
        for i, it in enumerate(self.items):
            if it.id == engine_id:
                self.items[i] = Obj(id=engine_id, name=kw.get("name", it.name),
                                    engine_expression=kw.get("engine_expression", it.engine_expression),
                                    description=kw.get("description"))
                return self.items[i], None, None
        return None, None, {"message": "not found"}


class FakeRules:
    def __init__(self, items=None):
        self.items = list(items or [])
        self.added = []
        self.updated = []
        self._next = 7000

    def list_rules(self):
        return list(self.items), None

    def add_rule(self, **kw):
        self.added.append(kw)
        self._next += 1
        obj = Obj(id=self._next, **kw)
        self.items.append(obj)
        return obj, None, None

    def update_rule(self, rule_id, **kw):
        self.updated.append({"id": rule_id, **kw})
        for i, it in enumerate(self.items):
            if it.id == rule_id:
                self.items[i] = Obj(id=rule_id, **kw)
                return self.items[i], None, None
        return None, None, {"message": "not found"}


class FakeZia:
    def __init__(self, dicts=None, engines=None, rules=None, dict_fail=False):
        self.dlp_dictionary = FakeDicts(dicts, fail=dict_fail)
        self.dlp_engine = FakeEngines(engines)
        self.dlp_web_rules = FakeRules(rules)


class FakeClient:
    def __init__(self, **kw):
        self.zia = FakeZia(**kw)


PREDEF_SSN = Obj(id=1, name="Social Security Numbers (US)", custom=False)


# ---------------------------------------------------------------------------
# Pack fixtures
# ---------------------------------------------------------------------------

def _dict(name, pattern="\\bX\\d{3}\\b", proximity=0):
    return {"name": name, "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
            "confidence_threshold": "CONFIDENCE_LEVEL_HIGH", "proximity": proximity,
            "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": pattern}], "phrases": []}


def _clone(name, template="Social Security Numbers (US)"):
    return {"name": name, "predefined_clone": True, "dict_template_name": template,
            "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "proximity": 500}


def _engine(name, expr):
    return {"name": name, "expression": expr}


def _policy(name, engines, action="ALLOW"):
    return {"name": name, "action": action, "state": "ENABLED", "rank": 7, "engines": engines,
            "protocols": ["HTTPS_RULE"], "severity": "RULE_SEVERITY_HIGH"}


def write_pack(tmp_path, pack_id, dicts=(), engines=(), policies=(), meta=None):
    d = tmp_path / pack_id / "configs"
    d.mkdir(parents=True)
    (d / "dlp_dictionaries.json").write_text(json.dumps(list(dicts)))
    (d / "dlp_engines.json").write_text(json.dumps(list(engines)))
    (d / "dlp_policies.json").write_text(json.dumps(list(policies)))
    if meta:
        (tmp_path / pack_id / "pack.json").write_text(json.dumps(meta))
    return {"id": pack_id, "dir": str(tmp_path / pack_id)}


@pytest.fixture
def base_pack(tmp_path):
    return write_pack(
        tmp_path, "alpha",
        dicts=[_dict("Alpha Dict"), _clone("SSN Clone")],
        engines=[_engine("Alpha Engine", "(D:Alpha Dict OR D:SSN Clone)")],
        policies=[_policy("Z-Alpha-Monitor", ["Alpha Engine"])],
        meta={"name": "Alpha Pack", "confidence_tweaks": []},
    )


def items_by(report, kind):
    return {i["name"]: i for i in report["items"] if i["kind"] == kind}


# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

def test_preflight_all_new_is_ready(base_pack):
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    assert rep["status"] == "ready"
    assert rep["blockers"] == []
    dicts, engines, policies = items_by(rep, "dictionary"), items_by(rep, "engine"), items_by(rep, "policy")
    assert dicts["Alpha Dict"]["status"] == pd.CREATE
    assert dicts["SSN Clone"]["status"] == pd.CREATE
    assert engines["Alpha Engine"]["status"] == pd.CREATE
    assert policies["Z-Alpha-Monitor"]["status"] == pd.CREATE
    assert rep["will_create"] == 4
    assert rep["summary"]["policy"] == {pd.CREATE: 1}
    assert len(rep["plan_hash"]) == 64
    assert any(i["type"] == "monitor_only" for i in rep["impacts"])
    assert any(i["type"] == "activation" for i in rep["impacts"])
    assert "_internal" not in pd.public_report(rep)


def test_cross_pack_conflict_blocks_and_cascades(tmp_path, base_pack):
    beta = write_pack(
        tmp_path, "beta",
        dicts=[_dict("Alpha Dict", pattern="DIFFERENT")],           # same name, different content
        engines=[_engine("Beta Engine", "D:Alpha Dict")],
        policies=[_policy("Z-Beta-Monitor", ["Beta Engine"])],
    )
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack, beta], writes_enabled=True)
    assert rep["status"] == "warnings"
    d = items_by(rep, "dictionary")["Alpha Dict"]
    assert d["status"] == pd.CONFLICT
    assert sorted(d["packs"]) == ["alpha", "beta"]
    # Both engines reference the conflicted dictionary → blocked, and their policies too.
    assert items_by(rep, "engine")["Alpha Engine"]["status"] == pd.BLOCKED_DEPENDENCY
    assert items_by(rep, "engine")["Beta Engine"]["status"] == pd.BLOCKED_DEPENDENCY
    assert items_by(rep, "policy")["Z-Alpha-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert items_by(rep, "policy")["Z-Beta-Monitor"]["status"] == pd.BLOCKED_DEPENDENCY
    assert any("defined differently" in w for w in rep["warnings"])
    # The unaffected clone still deploys.
    assert items_by(rep, "dictionary")["SSN Clone"]["status"] == pd.CREATE


def test_identical_duplicate_across_packs_is_collapsed(tmp_path, base_pack):
    beta = write_pack(tmp_path, "beta", dicts=[_dict("Alpha Dict")])   # identical definition
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack, beta], writes_enabled=True)
    d = items_by(rep, "dictionary")["Alpha Dict"]
    assert d["status"] == pd.CREATE
    assert sorted(d["packs"]) == ["alpha", "beta"]
    assert rep["summary"]["dictionary"] == {pd.CREATE: 2}


def test_existing_with_different_content_is_reused_with_warning(base_pack):
    tenant_alpha = Obj(id=42, name="Alpha Dict", custom=True, proximity=0,
                       custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                       confidence_threshold="CONFIDENCE_LEVEL_HIGH",
                       patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "TENANT-VERSION"}], phrases=[])
    client = FakeClient(dicts=[PREDEF_SSN, tenant_alpha])
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    d = items_by(rep, "dictionary")["Alpha Dict"]
    assert d["status"] == pd.REUSE_DIFFERS
    assert d["tenant"]["id"] == 42
    assert "tenant's version will be kept" in d["reason"]
    assert any("Alpha Dict" in w and "different content" in w for w in rep["warnings"])
    # Engine can still be created because the dictionary is available (from the tenant).
    assert items_by(rep, "engine")["Alpha Engine"]["status"] == pd.CREATE

    res = pd.apply(client, [base_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "applied"
    assert not any(a["name"] == "Alpha Dict" for a in client.zia.dlp_dictionary.added), "must not overwrite"


def test_existing_identical_is_reused_silently(base_pack):
    tenant_alpha = Obj(id=42, name="Alpha Dict", custom=True, proximity=0,
                       custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                       confidence_threshold="CONFIDENCE_LEVEL_HIGH",
                       patterns=[{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "\\bX\\d{3}\\b"}], phrases=[])
    client = FakeClient(dicts=[PREDEF_SSN, tenant_alpha])
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    assert items_by(rep, "dictionary")["Alpha Dict"]["status"] == pd.REUSE
    assert not any("Alpha Dict" in w for w in rep["warnings"])


def test_missing_dependency_blocks_engine_and_policy(tmp_path):
    pack = write_pack(
        tmp_path, "gamma",
        engines=[_engine("Gamma Engine", "(D:Does Not Exist AND D:Also Missing)")],
        policies=[_policy("Z-Gamma", ["Gamma Engine"]), _policy("Z-Orphan", ["No Such Engine"])],
    )
    client = FakeClient()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    e = items_by(rep, "engine")["Gamma Engine"]
    assert e["status"] == pd.BLOCKED_DEPENDENCY
    assert "Does Not Exist" in e["reason"] and "Also Missing" in e["reason"]
    p = items_by(rep, "policy")
    assert p["Z-Gamma"]["status"] == pd.BLOCKED_DEPENDENCY and "blocked engines" in p["Z-Gamma"]["reason"]
    assert p["Z-Orphan"]["status"] == pd.BLOCKED_DEPENDENCY and "No Such Engine" in p["Z-Orphan"]["reason"]
    # Nothing creatable → the plan is blocked as a whole.
    assert rep["status"] == "blocked"
    assert any("Nothing to deploy" in b for b in rep["blockers"])


def test_clone_with_unknown_template_is_blocked(tmp_path):
    pack = write_pack(tmp_path, "delta", dicts=[_clone("Bad Clone", template="Not A Predefined Dict")])
    client = FakeClient()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    d = items_by(rep, "dictionary")["Bad Clone"]
    assert d["status"] == pd.BLOCKED_DEPENDENCY
    assert "Not A Predefined Dict" in d["reason"]


def test_rule_cap_blocks_and_order_shift_is_explained(tmp_path, base_pack):
    existing = [Obj(id=i, name=f"Existing {i}", order=i, action="ALLOW", rank=7) for i in range(1, 127)]
    two = write_pack(tmp_path, "two", engines=[_engine("E2", "D:Alpha Dict")],
                     policies=[_policy("Z-Two", ["E2"])])
    client = FakeClient(dicts=[PREDEF_SSN], rules=existing)
    rep = pd.preflight(client, [base_pack, two], writes_enabled=True)
    assert rep["status"] == "blocked"
    assert any("API cap" in b for b in rep["blockers"])

    client = FakeClient(dicts=[PREDEF_SSN], rules=existing[:3])
    rep = pd.preflight(client, [base_pack, two], writes_enabled=True)
    shift = next(i for i in rep["impacts"] if i["type"] == "order_shift")
    assert "2 new Web DLP rules" in shift["title"]
    assert "'Existing 1' order 1 → 3" in shift["detail"]
    assert shift["severity"] == "warning"


def test_enforcing_action_is_flagged(tmp_path):
    # A pack may be designed to block; it still ships monitor-only and
    # DISABLED, and the plan carries the designed action as the target.
    pack = write_pack(tmp_path, "block", dicts=[_dict("BD")], engines=[_engine("BE", "D:BD")],
                      policies=[_policy("Z-Block", ["BE"], action="BLOCK")])
    client = FakeClient()
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["status"] == "ready", rep["warnings"]
    item = items_by(rep, "policy")["Z-Block"]
    assert "enforcing action" not in item["warnings"]
    assert item["detail"]["action"] == "ALLOW" and item["detail"]["target_action"] == "BLOCK"
    assert not any(i["type"] == "enforcement" for i in rep["impacts"])
    assert any(i["type"] == "monitor_only" for i in rep["impacts"])
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    posted = next(r for r in client.zia.dlp_web_rules.added if r["name"] == "Z-Block")
    assert posted["action"] == "ALLOW" and posted["state"] == "DISABLED" and "target_action" not in posted


def test_confidence_tweak_is_explicit_modification(tmp_path):
    pack = write_pack(tmp_path, "tw", dicts=[_dict("TD")],
                      meta={"confidence_tweaks": [{"name": "MEDICAL", "target_confidence": "CONFIDENCE_LEVEL_LOW",
                                                   "label": "Medical → Low"}]})
    medical = Obj(id=3, name="MEDICAL", custom=False, confidence_threshold="CONFIDENCE_LEVEL_HIGH",
                  dictionary_type="PATTERNS_AND_PHRASES", custom_phrase_match_type="MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY")
    client = FakeClient(dicts=[medical])
    rep = pd.preflight(client, [pack], writes_enabled=True)
    tw = items_by(rep, "tweak")["Medical → Low"]
    assert tw["status"] == pd.MODIFY
    assert "EXISTING tenant dictionary 'MEDICAL'" in tw["reason"]
    assert any("Medical → Low" in w for w in rep["warnings"])

    # Opting out removes the modification entirely.
    rep2 = pd.preflight(client, [pack], apply_tweaks=False, writes_enabled=True)
    assert items_by(rep2, "tweak") == {}

    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["summary"].get("modified") == 1
    assert client.zia.dlp_dictionary.updated[0]["confidence_threshold"] == "CONFIDENCE_LEVEL_LOW"


def test_writes_disabled_blocks_deploy_but_not_the_plan(base_pack):
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack], writes_enabled=False)
    assert rep["status"] == "warnings" and rep["read_only"] is True     # the plan is still reviewable
    assert any("read-only" in w and "Enable write mode" in w for w in rep["warnings"])
    res = pd.apply(client, [base_pack], plan_hash=rep["plan_hash"], writes_enabled=False)
    assert res["status"] == "blocked" and res["results"] == []
    assert client.zia.dlp_dictionary.added == []


def test_one_unreadable_listing_degrades_to_a_warned_plan(base_pack):
    """A client that cannot list dictionaries still gets a plan: those
    objects are planned as new and marked unverified (a partial plan is
    better than none); only a tenant where nothing lists is blocked."""
    client = FakeClient(dict_fail=True)
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    assert rep["status"] == "warnings"
    assert rep["tenant"]["reachable"] is True and "dictionaries:" in " ".join(rep["tenant"]["errors"])
    assert any("Could not list the tenant's dictionaries" in w for w in rep["warnings"])
    assert rep["plan_hash"]
    assert all(any(w.startswith("unverified") for w in i.get("warnings", [])) for i in rep["items"] if i["kind"] == "dictionary" and i["status"] == pd.CREATE)


def test_tenant_unreachable_blocks_plan(base_pack, monkeypatch):
    client = FakeClient(dict_fail=True)
    monkeypatch.setattr(client.zia.dlp_engine, "list_dlp_engines", lambda: (None, "boom"))
    monkeypatch.setattr(client.zia.dlp_web_rules, "list_rules", lambda: (None, "boom"))
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    assert rep["status"] == "blocked"
    assert rep["tenant"]["reachable"] is False
    assert any("Could not read the tenant" in b for b in rep["blockers"])
    assert rep["plan_hash"] == ""


def test_apply_rejects_changed_plan(base_pack):
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack], writes_enabled=True)
    # Tenant drifts between approval and apply: a new rule appears.
    client.zia.dlp_web_rules.items.append(Obj(id=1, name="Someone Else's Rule", order=1, action="BLOCK"))
    res = pd.apply(client, [base_pack], plan_hash=rep["plan_hash"], writes_enabled=True)
    assert res["status"] == "plan_changed"
    assert res["current_hash"] != rep["plan_hash"]
    assert client.zia.dlp_dictionary.added == [] and client.zia.dlp_web_rules.added == []


def test_apply_creates_in_dependency_order_and_isolates_failures(tmp_path):
    pack = write_pack(
        tmp_path, "eps",
        dicts=[_dict("D1"), _dict("D2")],
        engines=[_engine("E-good", "D:D1"), _engine("E-bad", "D:D2")],
        policies=[_policy("Z-good", ["E-good"]), _policy("Z-bad", ["E-bad"]), _policy("Z-both", ["E-good", "E-bad"])],
    )
    client = FakeClient()
    client.zia.dlp_engine.fail_names.add("E-bad")
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["status"] == "ready"
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)

    by_name = {r["name"]: r for r in res["results"]}
    assert by_name["D1"]["status"] == "created" and by_name["D2"]["status"] == "created"
    assert by_name["E-good"]["status"] == "created"
    assert by_name["E-bad"]["status"] == "failed" and "simulated" in by_name["E-bad"]["error"]
    assert by_name["Z-good"]["status"] == "created"
    assert by_name["Z-bad"]["status"] == "skipped" and "E-bad" in by_name["Z-bad"]["reason"]
    assert by_name["Z-both"]["status"] == "skipped"
    assert res["status"] == "partial"
    assert res["activation_required"] is True

    # Engine expression was resolved to the freshly created dictionary ID.
    d1_id = next(a for a in client.zia.dlp_dictionary.items if a.name == "D1").id
    assert client.zia.dlp_engine.added[0]["engine_expression"] == f"D{d1_id}.S > 0"
    # Policy resolved the engine ID and was inserted at the top.
    rule = client.zia.dlp_web_rules.added[0]
    assert rule["order"] == "1" and rule["action"] == "ALLOW" and rule["rank"] == 7


def test_apply_happy_path_with_rank_0_and_verification(base_pack):
    client = FakeClient(dicts=[PREDEF_SSN])
    rep = pd.preflight(client, [base_pack], use_rank_0=True, writes_enabled=True)
    assert any(i["type"] == "rank_0" for i in rep["impacts"])
    res = pd.apply(client, [base_pack], plan_hash=rep["plan_hash"], use_rank_0=True, writes_enabled=True)
    assert res["status"] == "applied"
    assert res["summary"] == {"created": 4}
    assert client.zia.dlp_web_rules.added[0]["rank"] == 0
    assert "alpha" in res["verification"]
    # Re-running is a no-op: everything now exists.
    rep2 = pd.preflight(client, [base_pack], writes_enabled=True)
    assert rep2["status"] == "blocked" and any("Nothing to deploy" in b for b in rep2["blockers"])


def test_empty_selection_is_blocked():
    rep = pd.preflight(FakeClient(), [], writes_enabled=True)
    assert rep["status"] == "blocked" and rep["items"] == []
