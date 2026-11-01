"""DLP dictionaries and engines, ad hoc (ops_dlp_objects): create, edit or
delete one custom dictionary or engine on the Bulk changes engine, with the
engine-expression parser and the DLP explainer in the preview.

A recording fake of the SDK 1.11.3 dlp_dictionary and dlp_engine services
(the SDK's own (action, text) -> {action, phrase} conversion) and the DLP
rule services: no network, no clock, state in tmp_path."""
from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ops_dlp_objects as dl  # noqa: E402
import pack_channels as pc  # noqa: E402
from test_admin_ops import FULL_SCOPE, FakeCasb, FakeRules, rule  # noqa: E402

ASSESSOR = "Jane Doe"
NO_DLP = ao.scope_for(["zpa"], {})


def _pairs(kw):
    kw = copy.deepcopy(kw)
    if "phrases" in kw:
        kw["phrases"] = [{"action": a, "phrase": p} for a, p in kw["phrases"]]
    if "patterns" in kw:
        kw["patterns"] = [{"action": a, "pattern": p} for a, p in kw["patterns"]]
    return kw


class Dicts:
    def __init__(self, t):
        self.t = t
        self.rows = [
            {"id": 61, "name": "CREDIT_CARD", "custom": False, "confidence_threshold": "CONFIDENCE_LEVEL_MEDIUM", "dictionary_type": "PATTERNS_AND_PHRASES"},
            {"id": 101, "name": "Project names", "custom": True, "description": "codenames", "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
             "dictionary_type": "PATTERNS_AND_PHRASES", "phrases": [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "Bluebird"}], "patterns": []},
            {"id": 102, "name": "Spare words", "custom": True, "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
             "dictionary_type": "PATTERNS_AND_PHRASES", "phrases": [{"action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "spare"}]}]
        self.n = 900

    def _w(self, *w):
        assert not self.t.frozen, "write during a preview"
        self.t.writes.append(w)

    def list_dicts(self, *a, **k):
        return copy.deepcopy(self.rows), None, None

    def get_dict(self, oid):
        if self.t.before_get:
            self.t.before_get("dict", oid)
        r = next((x for x in self.rows if str(x["id"]) == str(oid)), None)
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add_dict(self, name, custom_phrase_match_type, dictionary_type, **kw):
        body = dict(_pairs(kw), name=name, custom_phrase_match_type=custom_phrase_match_type, dictionary_type=dictionary_type)
        self._w("add_dict", body)
        self.n += 1
        self.rows.append(dict(body, id=self.n, custom=True))
        return copy.deepcopy(self.rows[-1]), None, None

    def update_dict(self, oid, **kw):
        body = _pairs(kw)
        self._w("update_dict", oid, body)
        r = next(x for x in self.rows if str(x["id"]) == str(oid))
        r.update(body)
        return copy.deepcopy(r), None, None

    def delete_dict(self, oid):
        self._w("delete_dict", oid)
        self.rows = [x for x in self.rows if str(x["id"]) != str(oid)]
        return None, None, None


class Engines:
    def __init__(self, t):
        self.t = t
        self.rows = [{"id": 201, "name": "Projects and cards", "custom_dlp_engine": True, "engine_expression": "((D101.S > 2) AND (D61.S > 0))"},
                     {"id": 202, "name": "Unused engine", "custom_dlp_engine": True, "description": "old", "engine_expression": "((D61.S > 4))"},
                     {"id": 60, "name": "PCI", "custom_dlp_engine": False, "predefined_engine_name": "PCI", "engine_expression": "((D61.S > 0))"}]
        self.n = 950

    def _w(self, *w):
        assert not self.t.frozen, "write during a preview"
        self.t.writes.append(w)

    def list_dlp_engines(self, *a, **k):
        return copy.deepcopy(self.rows), None, None

    def get_dlp_engines(self, oid):
        r = next((x for x in self.rows if str(x["id"]) == str(oid)), None)
        return (copy.deepcopy(r), None, None) if r else (None, None, {"message": "not found", "status": 404})

    def add_dlp_engine(self, **kw):
        self._w("add_dlp_engine", copy.deepcopy(kw))
        self.n += 1
        self.rows.append(dict(copy.deepcopy(kw), id=self.n))
        return copy.deepcopy(self.rows[-1]), None, None

    def update_dlp_engine(self, oid, **kw):
        self._w("update_dlp_engine", oid, copy.deepcopy(kw))
        r = next(x for x in self.rows if str(x["id"]) == str(oid))
        keep = {"id": r["id"]}
        r.clear()
        r.update(keep, **copy.deepcopy(kw))
        return copy.deepcopy(r), None, None

    def delete_dlp_engine(self, oid):
        self._w("delete_dlp_engine", oid)
        self.rows = [x for x in self.rows if str(x["id"]) != str(oid)]
        return None, None, None


class Tenant:
    def __init__(self):
        self.writes, self.frozen, self.before_get, self.read_error = [], False, None, None
        z = type("Zia", (), {})()
        z.dlp_dictionary = Dicts(self)
        z.dlp_engine = Engines(self)
        z.dlp_web_rules = FakeRules(self, "dlp_web_rules", [rule(301, "Web projects", 1, dlp_engines=[{"id": 201, "name": "Projects and cards"}])])
        z.endpoint_dlp_rules = FakeRules(self, "endpoint_dlp_rules", [])
        z.outbound_email_dlp_rules = FakeRules(self, "outbound_email_dlp_rules", [])
        z.casb_dlp_rules = FakeCasb(self, "casb_dlp_rules", [])
        self.zia = z


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    acts = []
    monkeypatch.setattr(pc, "activate", lambda zia: (acts.append(1) or {"activated": True, "status": "ACTIVE", "error": None}))
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()
    return acts


def preview(t, spec, scope=FULL_SCOPE):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=scope, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec, *, phrase=None, prepared=None):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=True, assessor=ASSESSOR, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


def test_registered_with_its_form_and_out_of_scope_reads_nothing():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: one ZIA plugin type with its form; without DLP in scope nothing is read or written."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[dl.TYPE]["product"] == "zia" and cat[dl.TYPE]["script"] == "ops_dlp_objects.js"
    assert os.path.exists(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "ops_dlp_objects.js"))

    class Boom:
        @property
        def zia(self):
            raise AssertionError("read before the scope check")
    with pytest.raises(ao.OperationError, match="Scope page"):
        ao.plan(Boom(), {"type": dl.TYPE, "object": "engine", "action": "delete", "id": 202}, scope=NO_DLP)
    with pytest.raises(ao.OperationError):
        ao.read_objects(Boom(), dl.FAMILY, NO_DLP)


def test_the_picker_explains_each_engine_and_says_what_uses_what():
    """ASVS V1.14.1 · CWE-1164: each engine's expression in words (the DLP explainer), the rules using it, and the engines using each dictionary."""
    out = ao.read_objects(Tenant(), dl.FAMILY, FULL_SCOPE)
    e = {x["name"]: x for x in out["engines"]}
    assert e["Projects and cards"]["readable"] == "(Project names count > 2) AND (Credit card count > 0)"
    assert e["Projects and cards"]["summary"].startswith("Fires when") and e["Projects and cards"]["used_by"][0]["name"] == "Web projects"
    d = {x["name"]: x for x in out["dictionaries"]}
    assert d["Project names"]["used_by"] == ["Projects and cards"] and d["CREDIT_CARD"]["custom"] is False


def test_a_new_dictionary_is_created_with_the_sdk_payload_and_undo_deletes_it(isolated):
    """ASVS V1.4.1 · CWE-841: payload oracle for add_dict (phrases and patterns as SDK pairs, the ZIA action words); one activation; Undo deletes it."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "dictionary", "action": "create",
            "fields": {"name": "Merger codes", "description": "deal names", "phrases": [{"phrase": "Project Falcon", "action": "unique"}],
                       "patterns": [{"pattern": "MRG-[0-9]{4}", "action": "all"}]}}
    p, r = apply(t, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == len([u for u in p["items"] if u["status"] == "change"]) and len(isolated) == 1
    assert t.writes == [("add_dict", {"name": "Merger codes", "custom_phrase_match_type": "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY",
                                      "dictionary_type": "PATTERNS_AND_PHRASES", "description": "deal names",
                                      "phrases": [{"action": "PHRASE_COUNT_TYPE_UNIQUE", "phrase": "Project Falcon"}],
                                      "patterns": [{"action": "PATTERN_COUNT_TYPE_ALL", "pattern": "MRG-[0-9]{4}"}]})]
    inv = r["inverse"]
    assert inv["action"] == "delete" and ao.is_undo_only(inv)
    _p, r2 = apply(t, inv)
    assert r2["status"] == "applied" and not [d for d in t.zia.dlp_dictionary.rows if d["name"] == "Merger codes"]


def test_a_dictionary_outside_zias_limits_or_with_a_redos_pattern_is_blocked():
    """ASVS V5.1.3 · CWE-1333 · WSTG-INPV-01: a nested unbounded repeat (ReDoS), lookaround or an over-long pattern blocks the plan; nothing is sent."""
    t = Tenant()
    for bad in ("(a+)+$", "(?=x)abc", "x" * 300):
        p = preview(t, {"type": dl.TYPE, "object": "dictionary", "action": "create",
                        "fields": {"name": "Bad one", "patterns": [{"pattern": bad, "action": "all"}]}})
        assert p["status"] == "blocked", bad
    assert t.writes == []


def test_editing_a_dictionary_sends_it_back_as_read_with_the_new_phrases_and_undo_puts_them_back():
    """ASVS V1.4.1 · CWE-841: payload oracle for update_dict: every field as read, only the phrases changed; read back; Undo restores the phrases."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 101,
            "fields": {"phrases": [{"phrase": "Bluebird", "action": "all"}, {"phrase": "Kestrel", "action": "all"}]}}
    p, r = apply(t, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 1
    w = t.writes[0]
    assert w[0] == "update_dict" and w[1] == 101
    assert w[2]["name"] == "Project names" and w[2]["description"] == "codenames"
    assert w[2]["phrases"] == [{"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "Bluebird"}, {"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "Kestrel"}]
    assert any("changes at once" in x for x in p["warnings"])
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and [x["phrase"] for x in t.zia.dlp_dictionary.rows[1]["phrases"]] == ["Bluebird"]


def test_a_predefined_dictionarys_confidence_can_be_changed_but_nothing_else():
    """ASVS V4.1.3 · CWE-284: a predefined dictionary takes a confidence change only; a custom one has no confidence to change."""
    t = Tenant()
    _p, r = apply(t, {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 61, "fields": {"confidence_threshold": "CONFIDENCE_LEVEL_HIGH"}})
    assert r["status"] == "applied" and t.writes[0][2]["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH"
    p = preview(Tenant(), {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 61, "fields": {"name": "Cards"}})
    assert p["counts"]["change"] == 0 and "predefined" in p["items"][0]["reason"]
    p = preview(Tenant(), {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 101, "fields": {"confidence_threshold": "CONFIDENCE_LEVEL_LOW"}})
    assert p["counts"]["change"] == 0 and "no confidence" in p["items"][0]["reason"]


def test_an_engine_expression_is_parsed_resolved_by_name_and_explained_before_and_after():
    """ASVS V5.1.3 · CWE-20: D:<name> becomes D<id>.S; the preview carries the DLP explainer's words before and after; the PUT carries the new expression."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "engine", "action": "update", "id": 201, "fields": {"expression": "(D:Project names > 0) AND (D:Spare words > 1)"}}
    p, r = apply(t, spec)
    assert p["explain"]["before"]["readable"] == "(Project names count > 2) AND (Credit card count > 0)"
    assert p["explain"]["after"]["readable"] == "(Project names count > 0) AND (Spare words count > 1)"
    assert r["status"] == "applied"
    assert t.writes == [("update_dlp_engine", 201, {"name": "Projects and cards", "engine_expression": "(D101.S > 0) AND (D102.S > 1)",
                                                     "custom_dlp_engine": True})]
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and t.zia.dlp_engine.rows[0]["engine_expression"] == "((D101.S > 2) AND (D61.S > 0))"


@pytest.mark.parametrize("expr, why", [("(D:No such dictionary > 0)", "no dictionary is named"), ("(D999.S > 0)", "no dictionary has id 999"),
                                       ("((D101.S > 0)", "cannot be read"), ("(D101.S > 5000)", "under 1000")])
def test_a_bad_engine_expression_blocks_the_plan_in_words(expr, why):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an unknown dictionary, an unbalanced expression or an out-of-range count blocks with the reason."""
    t = Tenant()
    p = preview(t, {"type": dl.TYPE, "object": "engine", "action": "create", "fields": {"name": "New engine", "expression": expr}})
    assert p["status"] == "blocked" and any(why in b for b in p["blockers"]), p["blockers"]
    assert t.writes == []


def test_a_new_engine_is_created_custom_and_undo_deletes_it():
    """ASVS V1.4.1 · CWE-841: payload oracle for add_dlp_engine (custom_dlp_engine true); Undo deletes the engine it created."""
    t = Tenant()
    p, r = apply(t, {"type": dl.TYPE, "object": "engine", "action": "create", "fields": {"name": "Codes", "expression": "(D:Project names > 1)"}})
    assert p["explain"]["after"]["summary"].startswith("Fires when")
    assert t.writes == [("add_dlp_engine", {"name": "Codes", "engine_expression": "(D101.S > 1)", "custom_dlp_engine": True})]
    _p, r2 = apply(t, r["inverse"])
    assert r2["status"] == "applied" and not [e for e in t.zia.dlp_engine.rows if e["name"] == "Codes"]


def test_deleting_what_is_used_is_refused_and_names_the_user():
    """ASVS V4.1.3 · CWE-672 · WSTG-BUSL-01: a dictionary an engine names, or an engine a DLP rule names, is never deleted; predefined objects neither."""
    t = Tenant()
    p = preview(t, {"type": dl.TYPE, "object": "dictionary", "action": "delete", "id": 101})
    assert p["counts"]["change"] == 0 and "engine 'Projects and cards'" in p["items"][0]["reason"]
    p = preview(t, {"type": dl.TYPE, "object": "engine", "action": "delete", "id": 201})
    assert p["counts"]["change"] == 0 and "Inline Web DLP rule 1 'Web projects'" in p["items"][0]["reason"]
    p = preview(t, {"type": dl.TYPE, "object": "engine", "action": "delete", "id": 60})
    assert "predefined" in p["items"][0]["reason"]
    assert t.writes == []


def test_a_delete_needs_delete_and_the_name_typed_and_undo_creates_it_again():
    """ASVS V4.1.3 · CWE-862: DELETE <name>; the wrong phrase sends nothing; Undo re-creates the engine with its expression and description."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "engine", "action": "delete", "id": 202}
    p = preview(t, spec)
    assert p["confirm_phrase"] == "DELETE UNUSED ENGINE"
    _p, r = apply(t, spec, phrase="DELETE", prepared=p)
    assert r["status"] == "refused" and t.writes == []
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "applied" and t.writes == [("delete_dlp_engine", 202)]
    _p, r2 = apply(t, r["inverse"])
    made = [e for e in t.zia.dlp_engine.rows if e["name"] == "Unused engine"][0]
    assert r2["status"] == "applied" and made["engine_expression"] == "((D61.S > 4))" and made["description"] == "old"


def test_an_engine_delete_is_blocked_when_dlp_rules_are_not_in_scope():
    """ASVS V4.1.3 · CWE-863: deny by default: rules of a DLP channel not in scope cannot be checked, so the delete is blocked."""
    t = Tenant()
    narrow = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
    p = preview(t, {"type": dl.TYPE, "object": "engine", "action": "delete", "id": 202}, scope=narrow)
    assert p["status"] == "blocked" and t.writes == []


def test_a_dictionary_an_enabled_rule_uses_through_an_engine_needs_the_typed_phrase():
    """ASVS V4.1.3 · CWE-841 · WSTG-BUSL-01: dictionary 101 is in engine 201, which the enabled Web DLP rule uses: a phrase change asks APPLY 1 CHANGE and names the rule; without it nothing is sent."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 101, "fields": {"phrases": [{"phrase": "Kestrel", "action": "all"}]}}
    p = preview(t, spec)
    assert p["confirm_phrase"] == "APPLY 1 CHANGE"
    assert p["impact"][-1]["used_by"] == ["Inline Web DLP rule 1 'Web projects'"] and "enabled DLP rule" in p["impact"][-1]["detail"]
    _p, r = apply(t, spec, prepared=p, phrase="")
    assert r["status"] == "refused" and t.writes == []


def test_an_engine_expression_used_by_an_enabled_rule_needs_the_phrase_and_an_unused_one_does_not():
    """ASVS V4.1.3 · CWE-841: engine 201 (an enabled rule uses it) asks the phrase for a new expression; engine 202 (no rule) does not."""
    t = Tenant()
    used = preview(t, {"type": dl.TYPE, "object": "engine", "action": "update", "id": 201, "fields": {"expression": "(D101.S > 0)"}})
    unused = preview(t, {"type": dl.TYPE, "object": "engine", "action": "update", "id": 202, "fields": {"expression": "(D101.S > 0)"}})
    assert used["confirm_phrase"] == "APPLY 1 CHANGE" and unused["confirm_phrase"] == ""


def test_a_description_change_never_asks_the_phrase():
    """ASVS V4.1.3 · CWE-841: a change that does not alter what is matched (the description) acts on no traffic: no phrase."""
    t = Tenant()
    p = preview(t, {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 101, "fields": {"description": "new words"}})
    assert p["status"] == "ready" and p["confirm_phrase"] == ""


def test_rules_that_cannot_be_checked_count_as_using_the_engine():
    """ASVS V4.1.3 · CWE-863 · CWE-754: DLP rules not in scope cannot be checked: unknown is treated as used, so even an unused engine asks the phrase."""
    t = Tenant()
    narrow = ao.scope_for(["dlp"], {"web_dlp": "zscaler"})
    p = preview(t, {"type": dl.TYPE, "object": "engine", "action": "update", "id": 202, "fields": {"expression": "(D101.S > 0)"}}, scope=narrow)
    assert p["confirm_phrase"] == "APPLY 1 CHANGE" and "Not checked" in p["impact"][-1]["detail"]


def test_an_object_changed_after_the_preview_is_left_alone():
    """ASVS V11.1.4 · CWE-367: a change since the preview gives plan_changed; at the re-read it is a conflict; nothing is written."""
    t = Tenant()
    spec = {"type": dl.TYPE, "object": "dictionary", "action": "update", "id": 102, "fields": {"description": "x"}}
    p = preview(t, spec)
    t.zia.dlp_dictionary.rows[2]["phrases"].append({"action": "PHRASE_COUNT_TYPE_ALL", "phrase": "more"})
    _p, r = apply(t, spec, prepared=p)
    assert r["status"] == "plan_changed" and t.writes == []
    t = Tenant()
    p = preview(t, spec)
    t.before_get = lambda kind, oid: t.zia.dlp_dictionary.rows[2].update(name="Renamed meanwhile")
    _p, r = apply(t, spec, prepared=p)
    assert r["items"][0]["status"] == "conflict" and t.writes == []


@pytest.mark.parametrize("spec", [{"object": "rule", "action": "create"}, {"object": "engine", "action": "create", "fields": {"name": "X"}},
                                  {"object": "dictionary", "action": "create", "fields": {"name": "No entries"}},
                                  {"object": "dictionary", "action": "create", "fields": {"name": "Bad/name", "phrases": [{"phrase": "abc"}]}},
                                  {"object": "dictionary", "action": "update", "id": 101, "fields": {"secret": 1}},
                                  {"object": "dictionary", "action": "update", "id": "x", "fields": {"name": "a"}},
                                  {"object": "dictionary", "action": "update", "id": 101, "fields": {"phrases": [{"phrase": "a", "action": "some"}]}},
                                  {"object": "engine", "action": "update", "id": 201, "fields": {"expression": "D1.S\x00"}}])
def test_bad_requests_are_refused_before_anything_is_read(spec):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unknown objects or fields, missing names, entries or expression, bad names, ids and actions: 400."""
    t = Tenant()
    t.zia.dlp_dictionary.list_dicts = lambda *a, **k: (_ for _ in ()).throw(AssertionError("read"))
    with pytest.raises(ao.OperationError):
        ao.plan(t, dict({"type": dl.TYPE}, **spec), scope=FULL_SCOPE)
