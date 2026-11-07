"""AI prompt capture builder (ops_zia_ai_prompt): a dedicated Bulk changes operation for the GenAI prompt-capture
switches. Nothing pre-picked, a typed phrase every time, the subscription needed to turn one on, the whole settings
object written back as re-read, a read-back and an exact Undo. Fakes only: no tenant, no network."""
from __future__ import annotations

import copy
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import admin_ops as ao  # noqa: E402
import ai_guard as ag  # noqa: E402
import ops_zia_ai_prompt as op  # noqa: E402
import pack_channels as pc  # noqa: E402
import pack_ops  # noqa: E402
from test_admin_ops import FULL_SCOPE, Tenant  # noqa: E402

ASSESSOR = "Jane Doe"
START = {"enableChatGptPrompt": False, "enableMicrosoftCoPilotPrompt": False, "enableGeminiPrompt": True, "enableClaudePrompt": False,
         "enforceSafeSearch": True, "enableUcaasZoom": True}


class Settings:
    def __init__(self, t, start=None, licensed=True, complete=True):
        self.t, self.cur, self.licensed, self.complete, self.puts = t, copy.deepcopy(start or START), licensed, complete, []

    def read(self, zia):
        return copy.deepcopy(self.cur), self.complete, None

    def subs(self, zia):
        return self.licensed, ["GEN_AI_SECURITY"] if self.licensed else [], None

    def update(self, zia, kind, oid, payload, **kw):
        assert kind == "url_app_settings" and not self.t.frozen, "a write was sent during a preview"
        self.puts.append(copy.deepcopy(payload))
        self.cur = copy.deepcopy(payload)
        return pack_ops.Outcome(True, data=payload)


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")
    ao.load_plugins()


def tenant(monkeypatch, **kw):
    t = Tenant()
    s = Settings(t, **kw)
    monkeypatch.setattr(ag, "read_app_settings", s.read)
    monkeypatch.setattr(ag, "read_subscriptions", s.subs)
    monkeypatch.setattr(pack_ops, "update", s.update)
    return t, s


def preview(t, spec):
    t.frozen = True
    try:
        return ao.plan(t, spec, scope=FULL_SCOPE, tenant_label="acme")
    finally:
        t.frozen = False


def apply(t, spec, *, prepared=None, phrase=None, writes=True):
    p = prepared or preview(t, spec)
    return p, ao.execute(t, spec, plan_hash=p["plan_hash"], scope=FULL_SCOPE, writes_enabled=writes, assessor=ASSESSOR, tenant_label="acme",
                         confirm_text=p["confirm_phrase"] if phrase is None else phrase)


SPEC = {"type": op.TYPE, "switches": {"enableChatGptPrompt": True, "enableGeminiPrompt": False}}


def test_registered_under_build_new_with_its_form():
    """ASVS V1.14.1 · CWE-1059: the prompt-capture builder is a plugin type of the one engine under Build new, with its form script."""
    cat = {p["type"]: p for p in ao.plugin_catalog()}
    assert cat[op.TYPE]["group"] == "Build new" and cat[op.TYPE]["script"] == "ops_zia_ai_prompt.js"
    assert "register({ type: 'zia_ai_prompt_capture'" in open(os.path.join(os.path.dirname(os.path.dirname(__file__)), "static", "ops_zia_ai_prompt.js")).read()


def test_read_lists_each_switch_with_its_app_and_nothing_is_picked(monkeypatch):
    """ASVS V4.1.3 · CWE-1188: the form lists the tenant's prompt switches with their apps and state; the spec must name switches, none is implied."""
    t, s = tenant(monkeypatch)
    objs = op.read_objects(t, FULL_SCOPE, lambda m: None, None)
    by = {x["key"]: x for x in objs["switches"]}
    assert by["enableChatGptPrompt"]["app"] == "ChatGPT (OpenAI)" and by["enableGeminiPrompt"]["on"] is True and "enforceSafeSearch" not in by
    with pytest.raises(ao.OperationError, match="nothing is pre-picked"):
        op.normalize({"type": op.TYPE, "switches": {}})


def test_plan_changes_only_the_named_switches_and_asks_the_phrase(monkeypatch):
    """ASVS V4.1.3 · V11.1.1 · CWE-841 · WSTG-BUSL-01: only the named switches change, each before and after; the privacy warning and CAPTURE PROMPTS are always there; nothing is written in the preview."""
    t, s = tenant(monkeypatch)
    p = preview(t, SPEC)
    got = {u["field"]: (u["before"], u["after"]) for u in p["items"]}
    assert got == {"enableChatGptPrompt": (False, True), "enableGeminiPrompt": (True, False)}
    assert p["confirm_phrase"] == op.PHRASE and op.PRIVACY in p["warnings"] and s.puts == []


def test_apply_writes_the_whole_object_with_only_those_switches_changed_and_undo_restores(monkeypatch):
    """ASVS V11.1.1 · V7.1.3 · CWE-754 · WSTG-BUSL-01: one write of the object as re-read with only the picked switches changed, read back, and Undo restores the old values."""
    t, s = tenant(monkeypatch)
    before = copy.deepcopy(s.cur)
    _p, r = apply(t, SPEC)
    assert r["status"] == "applied" and len(s.puts) == 1
    assert s.puts[0]["enforceSafeSearch"] is True and s.puts[0]["enableChatGptPrompt"] is True and s.puts[0]["enableGeminiPrompt"] is False
    assert r["verification"]["mismatched"] == [] and r["verification"]["confirmed"] == 2
    inv = r["inverse"]
    assert inv == {"type": op.TYPE, "switches": {"enableChatGptPrompt": False, "enableGeminiPrompt": True}}
    _p2, r2 = apply(t, inv)
    assert r2["status"] == "applied" and s.cur == before


def test_turning_one_on_without_the_subscription_is_blocked_but_off_is_allowed(monkeypatch):
    """ASVS V4.1.3 · CWE-863: without the Gen AI Security subscription, turning a switch on is blocked and nothing is sent; turning one off still plans."""
    t, s = tenant(monkeypatch, licensed=False)
    p = preview(t, {"type": op.TYPE, "switches": {"enableChatGptPrompt": True}})
    assert p["status"] == "blocked" and "subscription" in " ".join(p["blockers"])
    _p, r = apply(t, {"type": op.TYPE, "switches": {"enableChatGptPrompt": True}}, prepared=p)
    assert r["status"] == "blocked" and s.puts == []
    assert preview(t, {"type": op.TYPE, "switches": {"enableGeminiPrompt": False}})["status"] == "ready"


def test_partial_settings_and_unknown_switches_are_never_written(monkeypatch):
    """ASVS V7.4.1 · CWE-754: settings read in part are not written back (a partial PUT could reset others); a switch the tenant lacks is excluded; a name that is not a prompt switch is refused."""
    t, s = tenant(monkeypatch, complete=False)
    with pytest.raises(ao.OperationError, match="Only part"):
        preview(t, SPEC)
    t2, s2 = tenant(monkeypatch)
    p = preview(t2, {"type": op.TYPE, "switches": {"enableNopePrompt": True, "enableGeminiPrompt": False}})
    assert {u["field"]: u["status"] for u in p["items"]}["enableNopePrompt"] == "excluded"
    for bad in ({"enforceSafeSearch": True}, {"enableChatGptPrompt": "yes"}):
        with pytest.raises(ao.OperationError):
            op.normalize({"type": op.TYPE, "switches": bad})


def test_gates_write_mode_assessor_phrase_and_scope(monkeypatch):
    """ASVS V4.1.3 · CWE-862 · WSTG-ATHZ-02: read-only by default: without write mode, the phrase, the assessor or the scope, nothing is written."""
    t, s = tenant(monkeypatch)
    p = preview(t, SPEC)
    with pytest.raises(PermissionError):
        apply(t, SPEC, prepared=p, writes=False)
    _p, r = apply(t, SPEC, prepared=p, phrase="capture prompts please")
    assert r["status"] == "refused" and s.puts == []
    with pytest.raises(ao.OperationError):
        ao.plan(t, SPEC, scope=ao.scope_for(["zpa"], {}))
