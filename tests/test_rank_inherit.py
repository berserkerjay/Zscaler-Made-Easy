"""Rules the app creates or moves take the admin rank they need
(rank_inherit), not a fixed rank 7.

An oracle table across the builders (AI Guard routing, the ZIA security
baseline, the SSL certificate move, a policy pack deploy and a Bulk changes
reorder) with Admin Ranking on, off and unknown (and not read, where the
builder can run without ZIA platform), the warning when the API role's rank
is too low to place a rule where asked, a read-back that finds another rank
than the one sent, and Undo putting ranks back. Fakes only: every tenant here
is an in-memory stand-in from the builders' own test modules, with the ZIA
advanced settings (GET /zia/advancedSettings) added; nothing reaches a
network.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest

import admin_ops as ao
import admin_rank
import pack_channels as pc
import pack_deploy as pd
import rank_inherit as ri
import test_admin_ops as ot
import test_ops_aiguard as at
import test_ops_zia_baseline as zt
import test_pack_deploy as pt

ROOT = Path(__file__).resolve().parents[1]

ON, OFF, MISSING = {"enableAdminRankAccess": True}, {"enableAdminRankAccess": False}, {"someOtherSetting": True}


class _Body:
    def __init__(self, body):
        self._b = copy.deepcopy(body)

    def get_body(self):
        return copy.deepcopy(self._b)


class AdvancedSettings:
    """zia.advanced_settings with get_advanced_settings (SDK 1.11.3), answering
    a raw body, a refusal, or counting that it was never asked."""

    def __init__(self, body=None, status=None):
        self.body, self.status, self.calls = body, status, 0

    def get_advanced_settings(self):
        self.calls += 1
        if self.status:
            return None, None, {"status": self.status, "message": "Forbidden"}
        return None, _Body(self.body), None


def with_setting(client, body, status=None):
    client.zia.advanced_settings = AdvancedSettings(body, status)
    return client


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def rule(rid, name, order, rank, acl="READ_WRITE", **kw):
    return dict({"id": rid, "name": name, "order": order, "rank": rank, "access_control": acl, "state": "ENABLED"}, **kw)


# ===========================================================================
# The decision itself
# ===========================================================================

POLICY = [rule(1, "Top admin rule", 1, 0), rule(2, "Middle", 2, 3), rule(3, "Bottom", 3, 7),
          {"id": 9, "name": "Default", "order": -1, "default_rule": True, "rank": 7}]
S_ON, S_OFF = admin_rank.parse(ON), admin_rank.parse(OFF)
S_UNKNOWN = admin_rank.parse(MISSING)
S_OUT = {"state": ri.OUT_OF_SCOPE, "why": admin_rank.NOT_IN_SCOPE_WHY}


@pytest.mark.parametrize("rules,order,setting,rank,sent,warns,words", [
    (POLICY, 1, S_ON, 0, 1, False, "rule now at order 1"),                    # takes the rank of the rule it sits above
    (POLICY, 2, S_ON, 3, 2, False, "'Middle'"),
    (POLICY, 3, S_ON, 7, 3, False, "'Bottom'"),
    (POLICY, None, S_ON, 7, None, False, "goes last"),                       # last: the rule just above it
    (POLICY, 99, S_ON, 7, 99, False, "goes last"),                           # boundary: past the end is last (ZIA appends it)
    ([], 1, S_ON, 7, 1, False, "no other rule"),                             # boundary: an empty policy
    (POLICY, 1, S_OFF, 7, 1, False, "is off"),                               # off: rank 7 as before
    (POLICY, 1, S_UNKNOWN, 7, 1, False, "could not be read"),                # unknown: rank 7 as before, and said
    (POLICY, 1, S_OUT, 7, 1, False, "was not read"),
    ([dict(r, access_control=None) for r in POLICY], 1, S_ON, 0, 1, True, "could not be read"),   # the client's rank unknown: assumed, warned
    ([rule(1, "Admin only", 1, 0, "READ_ONLY"), rule(2, "Also admin", 2, 2, "READ_ONLY"), rule(3, "Ours", 3, 7)], 1, S_ON, 7, 3, True, "not first"),
    ([rule(1, "Admin only", 1, 0, "READ_ONLY"), rule(2, "Mine", 2, 4), rule(3, "Ours", 3, 7)], 1, S_ON, 4, 2, True, "below 1 rule(s) of rank 0"),
], ids=["on-top", "on-middle", "on-order3", "on-last", "on-past-end", "on-empty", "off", "unknown", "not-read", "on-client-rank-unknown",
        "on-too-low-not-first", "on-too-low-own-rank"])
def test_the_rank_a_new_rule_takes(rules, order, setting, rank, sent, warns, words):
    """ASVS V1.4.1 · CWE-1188 · CWE-841: a new rule takes the rank of the rule it is placed above (on), rank 7 (off, unknown), never a rank the client cannot assign."""
    # Act
    pl = ri.place(rules, order, setting, name="New rule")
    # Assert
    assert (pl["rank"], pl["order"]) == (rank, sent)
    assert bool(pl["warning"]) is warns
    assert words in pl["why"] + pl["warning"]


def test_the_client_rank_is_inferred_from_what_it_may_edit_and_marked_assumed():
    """ASVS V1.4.1 · CWE-1188: the API client's own rank is never claimed as read: the SDK has no call for it, so it is inferred and says so."""
    who = ri.caller([rule(1, "a", 1, 0, "READ_ONLY"), rule(2, "b", 2, 3), rule(3, "c", 3, 7)])
    assert (who["at_least"], who["at_most"]) == (1, 3) and "assumed" in who["basis"] and "1.11.3" in who["basis"]
    assert ri.can_assign(3, who) is True and ri.can_assign(0, who) is False and ri.can_assign(2, who) is None
    assert ri.can_assign(7, {"at_most": None, "at_least": None}) is True   # rank 7 is always assignable


@pytest.mark.parametrize("body,status,scopes,state,calls", [
    (ON, None, ["zia_extras"], ri.ON, 1), (OFF, None, ["zia_extras"], ri.OFF, 1), (MISSING, None, ["zia_extras"], ri.UNKNOWN, 1),
    ({"enableAdminRankAccess": "maybe"}, None, ["zia_extras"], ri.UNKNOWN, 1), (ON, 403, ["zia_extras"], ri.UNKNOWN, 1),
    (ON, None, ["dlp"], ri.OUT_OF_SCOPE, 0), (ON, None, [], ri.OUT_OF_SCOPE, 0),
], ids=["on", "off", "missing", "not-a-boolean", "refused", "zia-platform-not-ticked", "nothing-ticked"])
def test_the_setting_is_read_once_through_the_sdk_and_only_in_scope(body, status, scopes, state, calls):
    """ASVS V4.1.3 · CWE-272 · CWE-1188: Admin Ranking is read only with ZIA platform ticked; a refusal or a missing field is unknown, never off."""
    # Arrange
    client = with_setting(at.Fake(), body, status)
    # Act
    got = ri.read_setting(client, scopes)
    # Assert
    assert got["state"] == state and client.zia.advanced_settings.calls == calls
    assert "Forbidden" not in got["why"]   # the tenant's words are not echoed


def test_a_sign_in_without_advanced_settings_is_unknown_not_an_error():
    """ASVS V7.4.1 · CWE-755: a client with no advanced settings service plans as unknown (rank 7, said), not a crash."""
    assert ri.read_setting(ot.Tenant(), ["zia_extras"])["state"] == ri.UNKNOWN


@pytest.mark.parametrize("ranks,moved,setting,want", [
    ({"A": 0, "C": 7, "B": 0}, {"C"}, S_ON, {"C": (0, True)}),            # moved above rank-0 rules: takes their rank
    ({"B": 0, "C": 7, "A": 0}, {"A"}, S_ON, {"A": (7, True)}),            # moved last below rank-7: takes the rank above it
    ({"A": 0, "C": 3, "B": 7}, {"C"}, S_ON, {}),                          # fits between its neighbours: keeps its rank
    ({"A": 0, "C": 7, "B": 0}, {"C"}, S_OFF, {}),                         # off: ranks are left alone
    ({"A": 0, "C": 7, "B": 0}, {"C"}, S_UNKNOWN, {}),                     # unknown: ranks are left alone
], ids=["up-takes-rank", "down-last-takes-rank", "fits-keeps", "off", "unknown"])
def test_the_ranks_a_reorder_needs(ranks, moved, setting, want):
    """ASVS V1.4.1 · CWE-841: a moved rule keeps its rank when it fits, else takes the rank of the rule it now sits above; only with Admin Ranking on."""
    rows = [rule(n, n, i + 1, rk) for i, (n, rk) in enumerate(ranks.items())]
    got = ri.place_moves(rows, moved, setting, id_of=lambda r: str(r["id"]))
    assert {k: (v["rank"], v["change"]) for k, v in got.items()} == want


def test_a_reorder_rank_the_client_cannot_assign_is_kept_and_warned():
    """ASVS V1.4.1 · CWE-1188: a moved rule needing a rank above the client's keeps its own rank, with a warning, never a refused write."""
    rows = [rule("A", "Admin rule", 1, 0, "READ_ONLY"), rule("C", "Ours", 2, 7), rule("B", "Other", 3, 7)]
    got = ri.place_moves(rows, {"C"}, S_ON, id_of=lambda r: str(r["id"]))
    assert got == {} or (got["C"]["change"] is False)
    rows = [rule("C", "Ours", 1, 7), rule("A", "Admin rule", 2, 0, "READ_ONLY"), rule("B", "Other", 3, 7)]
    got = ri.place_moves(rows, {"C"}, S_ON, id_of=lambda r: str(r["id"]))
    assert got["C"]["change"] is False and got["C"]["rank"] == 7 and "too low" in got["C"]["warning"]


def test_read_back_names_the_rank_and_order_zia_stored():
    """ASVS V7.2.1 · CWE-754: read-back compares the stored rank and order with those sent, and a field not returned is not a difference."""
    assert ri.stored({"rank": 0, "order": 1}, {"rank": 7, "order": 4}) == "rank 7 stored, 0 sent; order 4 stored, 1 sent"
    assert ri.stored({"rank": 0, "order": 1}, {"rank": 0, "order": 1}) is None
    assert ri.stored({"rank": 0}, {"order": 1}) is None


# ===========================================================================
# AI Guard routing: the SSL Inspect rule "at order 1"
# ===========================================================================

SSL_TOP = [{"id": 5, "name": "Admin exemptions", "order": 1, "rank": 0, "accessControl": "READ_WRITE", "state": "ENABLED",
            "action": {"type": "DO_NOT_DECRYPT"}},
           {"id": 6, "name": "Inspect most", "order": 2, "rank": 7, "accessControl": "READ_WRITE", "state": "ENABLED", "action": {"type": "DECRYPT"}}]
ROUTE = {"type": "aiguard_routing", "apps": ["chatgpt"], "cert": {"mode": "existing", "id": 11}, "block_quic": False,
         "prompt_capture": False, "allow_in_zia": False}


def _ssl_new(f):
    return next(r for r in f.stores["ssl"].rows if r["name"] == at.oa.names("")["ssl"])


@pytest.mark.parametrize("body,rank", [(ON, 0), (OFF, 7), (MISSING, 7)], ids=["on", "off", "unknown"])
def test_ai_guard_ssl_inspect_rule_takes_the_rank_it_needs(body, rank):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: AI Guard's SSL Inspect rule at order 1 takes the rank of the rule it sits above (on), rank 7 otherwise; preview says why, read-back confirms."""
    # Arrange
    f = with_setting(at.Fake(proxy=True, gateway=True, ssl_rules=SSL_TOP), body)
    # Act
    p = at.preview(f, ROUTE)
    res = at.apply(f, ROUTE, prepared=p)
    # Assert
    step = next(g["target"] for g in p["groups"] if g["target"]["kind"] == "ssl_rule")
    assert step["payload"]["rank"] == rank and step["payload"]["order"] == 1
    item = next(u for u in p["items"] if u["key"] == "ssl")
    assert f"rank {rank}" in item["after"] and item["reason"]
    assert [r["rank"] for r in p["rank_plan"]["rules"] if r["policy"] == "SSL inspection rule"] == [rank]
    assert p["rank_plan"]["state"] == admin_rank.parse(body)["state"]
    if body is MISSING:
        assert any("could not be read" in n for n in p["notes"])
    assert res["status"] == "applied" and not res["verification"]["mismatched"]
    assert _ssl_new(f)["rank"] == rank


def test_ai_guard_warns_when_the_api_role_rank_is_too_low_for_order_1():
    """ASVS V1.4.1 · CWE-1188 · CWE-841: with rank 0-6 rules the client cannot edit, the order-1 rule gets a rank it may assign and the preview says it will not be first."""
    # Arrange
    ssl = [dict(SSL_TOP[0], accessControl="READ_ONLY"), dict(SSL_TOP[0], id=7, name="Ops exemptions", order=2, rank=4, accessControl="READ_ONLY"),
           dict(SSL_TOP[1], order=3)]
    f = with_setting(at.Fake(proxy=True, gateway=True, ssl_rules=ssl), ON)
    # Act
    p = at.preview(f, ROUTE)
    res = at.apply(f, ROUTE, prepared=p)
    # Assert
    step = next(g["target"] for g in p["groups"] if g["target"]["kind"] == "ssl_rule")
    assert (step["payload"]["rank"], step["payload"]["order"]) == (7, 3)
    warn = next(w for w in p["warnings"] if "too low" in w)
    assert "not first" in warn and "order 3" in warn and "rank 0–4" in warn
    assert p["confirm_phrase"]   # the typed confirmation still applies
    assert res["status"] == "applied" and _ssl_new(f)["rank"] == 7


def test_ai_guard_read_back_reports_a_rank_zia_did_not_keep():
    """ASVS V7.2.1 · CWE-754: when ZIA stores another rank than sent, the read-back says so with both values, and the run is not called applied."""
    # Arrange
    f = with_setting(at.Fake(proxy=True, gateway=True, ssl_rules=SSL_TOP), ON)
    store = f.stores["ssl"]
    real_add = store.add
    store.add = lambda body: real_add(dict(body, rank=7))   # this "ZIA" ignores the rank sent
    # Act
    res = at.apply(f, ROUTE)
    # Assert
    assert res["status"] == "partial"
    assert any("rank 7 stored, 0 sent" in m for m in res["verification"]["mismatched"])


def test_ai_guard_moving_its_own_rule_up_changes_its_rank_and_undo_puts_it_back():
    """ASVS V1.4.1 · CWE-841 · CWE-1188: the builder's own SSL rule moved to order 1 takes the needed rank, and Undo restores its rank and order."""
    # Arrange
    name = at.oa.names("")["ssl"]
    mine = {"id": 8, "name": name, "order": 3, "rank": 7, "accessControl": "READ_WRITE", "state": "ENABLED", "action": {"type": "DECRYPT"},
            "destIpGroups": [{"id": 999}]}
    f = with_setting(at.Fake(proxy=True, gateway=True, ssl_rules=SSL_TOP + [mine]), ON)
    # Act
    res = at.apply(f, ROUTE)
    moved = next((r["rank"], r["order"]) for r in f.stores["ssl"].rows if r["id"] == 8)
    undo = at.apply(f, res["inverse"])
    back = next((r["rank"], r["order"]) for r in f.stores["ssl"].rows if r["id"] == 8)
    # Assert
    assert res["status"] == "applied" and moved == (0, 1)
    assert undo["status"] == "applied" and back == (7, 3)


# ===========================================================================
# ZIA security baseline: new rules go last
# ===========================================================================

URL_RULES = [dict(zt.URL_OWN, rank=3, access_control="READ_WRITE"), zt.URL_DEFAULT]
BASELINE = {"type": "zia_baseline", "tier": "balanced", "areas": ["url"]}


@pytest.mark.parametrize("body,scope,rank", [(ON, zt.FULL, 3), (OFF, zt.FULL, 7), (MISSING, zt.FULL, 7), (ON, zt.WEB_ONLY, 7)],
                         ids=["on", "off", "unknown", "not-read"])
def test_zia_baseline_rules_take_the_rank_of_the_rule_above_them(body, scope, rank):
    """ASVS V1.4.1 · V4.1.3 · CWE-841: baseline rules created last take the rank of the rule just above them (on), rank 7 otherwise; without ZIA platform the setting is not read."""
    # Arrange
    t = with_setting(zt.Tenant(url=URL_RULES), body)
    # Act
    p = zt.plan(t, BASELINE, scope)
    res = zt.apply(t, BASELINE, scope, prepared=p)
    # Assert
    made = [r for r in t.zia.url_filtering.rows if r["name"].startswith("BL-")]
    assert made and {r["rank"] for r in made} == {rank}
    assert {g["target"]["rank"] for g in p["groups"] if g["handler"] == "zb_create"} == {rank}
    assert {r["rank"] for r in p["rank_plan"]["rules"]} == {rank}
    assert (t.zia.advanced_settings.calls == 0) is (scope is zt.WEB_ONLY)   # read with ZIA platform ticked, never without
    assert res["status"] == "applied" and not res["verification"]["mismatched"]


def test_zia_baseline_read_back_reports_another_stored_rank():
    """ASVS V7.2.1 · CWE-754: a baseline rule ZIA stored at another rank is reported with the rank stored and sent."""
    t = with_setting(zt.Tenant(url=URL_RULES), ON)
    svc = t.zia.url_filtering
    real = svc.add_rule
    svc.add_rule = lambda **kw: real(**dict(kw, rank=7))
    res = zt.apply(t, BASELINE)
    assert res["status"] == "partial" and any("rank 7 stored, 3 sent" in m for m in res["verification"]["mismatched"])


# ===========================================================================
# SSL certificate move: rank and order are kept
# ===========================================================================

def test_ssl_certificate_move_keeps_rank_and_order_and_reads_them_back():
    """ASVS V1.4.1 · V7.2.1 · CWE-754: a certificate move says the rule keeps its rank and order, and the read-back checks ZIA kept both."""
    # Arrange
    ssl = [zt.SSL_DEFAULT, zt.SSL_PREDEF, dict(zt.SSL_OWN, rank=3), zt.SSL_OTHER]
    spec = {"type": "ssl_certificate_move", "rules": [3], "certificate": 52}
    t = with_setting(zt.Tenant(ssl=ssl), ON)
    # Act
    p = zt.plan(t, spec)
    res = zt.apply(t, spec, prepared=p)
    # Assert
    assert "keeps its rank 3 and order 2" in p["items"][0]["reason"]
    assert res["status"] == "applied" and res["verification"]["confirmed"] == 1
    # A "ZIA" that drops the rank on update: the read-back says so.
    t2 = zt.Tenant(ssl=ssl)
    real = t2.zia.ssl_inspection_rules.update_rule
    t2.zia.ssl_inspection_rules.update_rule = lambda rid, **kw: real(rid, **dict(kw, rank=7))
    res2 = zt.apply(t2, spec)
    assert res2["status"] == "partial" and any("rank 7 stored, 3 sent" in m for m in res2["verification"]["mismatched"])


# ===========================================================================
# Policy pack deploy: Web DLP rules go in at order 1
# ===========================================================================

def _pack_client(body, rules=None):
    rules = rules if rules is not None else [pt.Obj(id=1, name="Existing top", order=1, rank=2, access_control="READ_WRITE"),
                                             pt.Obj(id=2, name="Existing low", order=2, rank=7, access_control="READ_WRITE")]
    return with_setting(pt.FakeClient(dicts=[pt.PREDEF_SSN], rules=rules), body)


@pytest.fixture
def pack(tmp_path):
    return pt.write_pack(tmp_path, "alpha", dicts=[pt._dict("Alpha Dict")], engines=[pt._engine("Alpha Engine", "(D:Alpha Dict)")],
                         policies=[pt._policy("Z-Alpha-Monitor", ["Alpha Engine"])], meta={"name": "Alpha Pack", "confidence_tweaks": []})


@pytest.mark.parametrize("body,scopes,rank,calls", [(ON, ["zia_extras", "dlp"], 2, 1), (OFF, ["zia_extras"], 7, 1), (MISSING, ["zia_extras"], 7, 1),
                                                   (ON, None, 7, 0), (ON, ["dlp"], 7, 0)],
                         ids=["on", "off", "unknown", "no-scopes", "zia-platform-not-ticked"])
def test_pack_deploy_rule_takes_the_rank_it_needs(pack, body, scopes, rank, calls):
    """ASVS V1.4.1 · V4.1.3 · CWE-841: a pack's Web DLP rule at order 1 takes the rank of the rule it sits above (on), the pack's rank 7 otherwise; plan, write and read-back agree."""
    # Arrange
    client = _pack_client(body)
    # Act
    rep = pd.preflight(client, [pack], writes_enabled=True, rank_scopes=scopes)
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, rank_scopes=scopes, settle_seconds=0)
    # Assert
    item = pt.items_by(rep, "policy")["Z-Alpha-Monitor"]
    assert item["rank_plan"]["rank"] == rank and item["rank_plan"]["why"]
    assert rep["admin_ranking"]["rules"][0]["rank"] == rank
    assert client.zia.dlp_web_rules.added[0]["rank"] == rank and int(client.zia.dlp_web_rules.added[0]["order"]) == 1
    assert res["status"] == "applied" and res["read_check"]["rank_mismatched"] == []
    assert (client.zia.advanced_settings.calls > 0) is bool(calls)   # read only with ZIA platform among the scopes


def test_pack_plan_changes_when_the_rank_a_rule_needs_changes(pack):
    """ASVS V11.1.1 · CWE-367: the plan hash binds the planned ranks: a rank changed in the tenant since the preview stops the deploy."""
    client = _pack_client(ON)
    rep = pd.preflight(client, [pack], writes_enabled=True, rank_scopes=["zia_extras"])
    client.zia.dlp_web_rules.items[0].rank = 1   # someone re-ranked the top rule
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, rank_scopes=["zia_extras"], settle_seconds=0)
    assert res["status"] == "plan_changed" and client.zia.dlp_web_rules.added == []


def test_pack_rank_too_low_warns_and_read_back_reports_a_dropped_rank(pack):
    """ASVS V1.4.1 · V7.2.1 · CWE-754 · CWE-1188: a rank the client cannot assign is warned in the plan; a rank ZIA did not keep fails verification."""
    # Arrange
    rules = [pt.Obj(id=1, name="Admin rule", order=1, rank=0, access_control="READ_ONLY"),
             pt.Obj(id=2, name="Ours", order=2, rank=5, access_control="READ_WRITE")]
    client = _pack_client(ON, rules)
    # Act
    rep = pd.preflight(client, [pack], writes_enabled=True, rank_scopes=["zia_extras"])
    # Assert: rank 5 (the client's), order 2, and the plan says it is not first
    rp = pt.items_by(rep, "policy")["Z-Alpha-Monitor"]["rank_plan"]
    assert (rp["rank"], rp["order"]) == (5, 2) and any("not first" in w for w in rep["warnings"])
    # Arrange 2: a "ZIA" that stores rank 7 whatever is sent
    client2 = _pack_client(ON)
    svc = client2.zia.dlp_web_rules
    real = svc.add_rule
    svc.add_rule = lambda **kw: real(**dict(kw, rank=7))
    rep2 = pd.preflight(client2, [pack], writes_enabled=True, rank_scopes=["zia_extras"])
    res2 = pd.apply(client2, [pack], plan_hash=rep2["plan_hash"], writes_enabled=True, rank_scopes=["zia_extras"], settle_seconds=0)
    assert res2["read_check"]["rank_mismatched"] and "rank 7 stored, 2 sent" in res2["read_check"]["rank_mismatched"][0]["detail"]
    assert res2["verification"]["alpha"]["all_good"] is False


def test_use_rank_0_stays_the_operators_choice(pack):
    """ASVS V1.4.1 · CWE-1188: 'Use rank 0' still sends rank 0, with Admin Ranking on, and says so."""
    client = _pack_client(ON)
    rep = pd.preflight(client, [pack], writes_enabled=True, use_rank_0=True, rank_scopes=["zia_extras"])
    pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, use_rank_0=True, rank_scopes=["zia_extras"], settle_seconds=0)
    assert client.zia.dlp_web_rules.added[0]["rank"] == 0
    assert "Use rank 0" in pt.items_by(rep, "policy")["Z-Alpha-Monitor"]["rank_plan"]["why"]


def test_the_deploy_request_carries_only_scope_page_keys():
    """ASVS V4.1.3 · V5.1.3 · CWE-20: the scopes a pack plan reads Admin Ranking under are only the Scope page's own keys."""
    import dlp_api_server as srv
    req = srv.DLPPackDeployRequest(pack_ids=["x"], scopes=["zia_extras", "ZIA_EXTRAS", "bogus", "dlp"])
    assert srv._rank_scopes(req) == ["dlp", "zia_extras"]
    assert srv._cq_deploy_params(req)["rank_scopes"] == ["dlp", "zia_extras"]


# ===========================================================================
# Bulk changes reorder
# ===========================================================================

REORDER_RULES = [ot.rule(101, "Admin block", 1, rank=0, access_control="READ_WRITE"), ot.rule(102, "Admin allow", 2, rank=0, access_control="READ_WRITE"),
                 ot.rule(103, "Team caution", 3, access_control="READ_WRITE"), ot.rule(199, "Default URL Filtering Rule", -1, default_rule=True)]
REORDER = {"type": "reorder", "policy": "url_filtering", "order": ["103", "101", "102"]}


@pytest.mark.parametrize("body,rank,changes", [(ON, 0, 1), (OFF, 7, 0), (MISSING, 7, 0)], ids=["on", "off", "unknown"])
def test_reorder_moves_a_rule_with_the_rank_its_new_place_needs(body, rank, changes):
    """ASVS V1.4.1 · V11.1.1 · CWE-841: a rule moved above rank-0 rules takes rank 0 with Admin Ranking on; off or unknown only the order changes, and the preview says why."""
    # Arrange
    t = with_setting(ot.Tenant(url_rules=REORDER_RULES), body)
    # Act
    p = ot.preview(t, REORDER)
    res = ot.apply(t, REORDER, prepared=p)
    # Assert
    rank_units = [u for u in p["items"] if u["field"] == "rank" and u["status"] == "change"]
    assert len(rank_units) == changes
    moved = next(r for r in t.zia.url_filtering.rows if r["id"] == 103)
    assert (moved["order"], moved["rank"]) == (1, rank)
    assert res["status"] == "applied" and not res["verification"]["mismatched"]
    words = {ri.ON: "takes the rank", ri.OFF: "is off", ri.UNKNOWN: "could not be read"}[admin_rank.parse(body)["state"]]
    assert any(words in n for n in p["notes"])


def test_reorder_undo_puts_back_order_and_rank():
    """ASVS V1.4.1 · CWE-841: the Undo of a reorder that changed a rank restores the order and the rank, previewed like any change."""
    # Arrange
    t = with_setting(ot.Tenant(url_rules=REORDER_RULES), ON)
    res = ot.apply(t, REORDER)
    inv = res["inverse"]
    # Act
    undo = ot.apply(t, inv)
    # Assert
    assert inv["ranks"] == {"103": 7}
    back = {r["id"]: (r["order"], r["rank"]) for r in t.zia.url_filtering.rows if not r.get("default_rule")}
    assert undo["status"] == "applied" and back == {101: (1, 0), 102: (2, 0), 103: (3, 7)}


def test_reorder_read_back_reports_a_rank_zia_did_not_keep():
    """ASVS V7.2.1 · CWE-754: a reorder whose rank change ZIA did not keep is reported with the stored and sent rank."""
    t = with_setting(ot.Tenant(url_rules=REORDER_RULES), ON)
    svc = t.zia.url_filtering
    real = svc.update_rule
    svc.update_rule = lambda rid, **kw: real(rid, **dict(kw, rank=7))
    res = ot.apply(t, REORDER)
    assert res["status"] == "partial" and any("rank 7 stored, 0 sent" in m for m in res["verification"]["mismatched"])


@pytest.mark.parametrize("ranks", [{"103": 8}, {"103": "x"}, {"103": True}, {"bad id!": 1}, ["103"]],
                         ids=["above-7", "not-a-number", "boolean", "bad-id", "not-a-map"])
def test_reorder_ranks_are_validated(ranks):
    """ASVS V5.1.3 · CWE-20: the ranks an Undo puts back must be rule ids mapped to 0-7; anything else is refused before any write."""
    t = ot.Tenant(url_rules=REORDER_RULES)
    with pytest.raises(ao.OperationError):
        ot.preview(t, dict(REORDER, ranks=ranks))
    assert t.writes == []


# ===========================================================================
# The pages
# ===========================================================================

def test_the_pages_show_each_rank_and_why_escaped():
    """WCAG 2.2 SC 1.3.1 · ASVS V5.3.3 · CWE-79: the Bulk changes preview lists each rule's rank, order and why in a captioned table with every value escaped; the deploy plan shows the rank line escaped."""
    ops_page = (ROOT / "static" / "report_operations.html").read_text(encoding="utf-8")
    card = ops_page[ops_page.index("function rankCard"):ops_page.index("function renderPlan")]
    assert "<caption" in card and 'scope="col"' in card and "rankCard(p.rank_plan)" in ops_page
    for expr in re.findall(r"\$\{([^}]*r\.(?:name|policy|rank|order|why|warning)[^}]*)\}", card):
        assert "E(" in expr or "?" in expr, expr
    studio = (ROOT / "static" / "deploy_studio.js").read_text(encoding="utf-8")
    assert "_dzE(rankLine)" in studio and "_dzE(rk.warning)" in studio and "scopes: _dzRankScopes()" in studio
