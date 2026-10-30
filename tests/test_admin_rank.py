"""ASVS V1.4.4 · CWE-284 · CWE-670 · OWASP A01:2021: ZIA admin ranking decides which rule applies, and is never guessed.

With the tenant's Admin Ranking on (ZIA advanced settings,
enableAdminRankAccess), ZIA evaluates the ranked policies by admin rank
first (0 highest, 7 lowest), then by rule order (admin_rank.py names the
sources). Every analysis that says "this rule decides" must agree:

* an oracle table, module by module (URL filtering, Cloud App Control,
  SSL inspection, File Type Control, Web DLP, Cloud Firewall, DNS
  Control), for ranking on, off, unknown (could not be read) and not in
  scope: on, the better-ranked rule decides and says decided_by "rank";
  off, rule order decides; not known, rule order decides and the module
  is conditional with the plain-language caution naming both rules;
* the default rule stays last whatever its rank, and a rank tie falls
  back to rule order;
* the shadowed-rule analysis compares a rule only with the rules
  evaluated before it; the what-if and Test a list follow the same order;
* the setting is read only when ZIA platform is ticked (the Scope rule):
  nothing in scope is refused before sign-in, and a selection without
  ZIA platform never asks for /zia/advancedSettings;
* an older kept read or snapshot without the setting still loads, as
  "unknown", with the caution only where rank would change a decision;
  the sample tenant carries the setting (off).

Deterministic and offline: fake tenants and the in-memory sample only,
no network, no clock, no tenant.
"""
from __future__ import annotations

import copy

import pytest
from fastapi.testclient import TestClient

import admin_rank
import bulk_test
import data_flow as df
import dlp_api_server as srv
import offline_tenant
import path_analyzer as pa
import path_whatif
import sample_tenant
import shadow_rules as sr
import zia_path_modules as zpm
from test_data_flow import ROUTES as DF_ROUTES
from test_path_analyzer import LookupCl
from test_scope_rule_routes import CREDS, NOTHING_TICKED, WEB, ZIA, tenant  # noqa: F401 — `tenant` is the fixture
from test_ssl_flow import CATALOGUE
from zia_module_fixtures import MODULE_ROUTES

FULL = pa.full_path_scope()
# DLP ticked with every web channel on Zscaler, ZIA platform not ticked:
# the ranked web policies are read, the admin ranking setting is not.
WEB_ONLY = df.path_scope(["dlp"], {cid: "zscaler" for _, _, cid in df.PATH_SECTIONS.values() if cid})

ON, OFF = {"enableAdminRankAccess": True}, {"enableAdminRankAccess": False}


class Tenant(LookupCl):
    """The Data Flow fake with ZIA's URL lookup, the module endpoints and
    the advanced settings; every GET is recorded."""
    LOOKUP = dict(LookupCl.LOOKUP, **{"files.example": {"urlClassifications": ["WEB_MAIL"]}})

    def __init__(self, routes):
        super().__init__(routes, CATALOGUE)
        self.paths = []

    def get(self, ep, p=None):
        self.paths.append(ep)
        return super().get(ep, p)


DECRYPT_ALL = [{"id": 3, "name": "Decrypt all", "order": 9, "rank": 7, "state": "ENABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["ANY"]}]

# module key -> (routes override, destination, analyze kwargs, rule A (first by
# order, rank 7), rule B (later by order, better rank), A's and B's outcome).
# A and B both match and give different outcomes.
CASES = {
    "url": ({"/zia/urlFilteringRules": [
        {"id": 20, "name": "Block gambling (by order)", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["GAMBLING"]},
        {"id": 22, "name": "Allow gambling (by rank)", "order": 2, "rank": 1, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["GAMBLING"]}]},
        "casino.example", {}),
    "cac": ({"/zia/sslInspectionRules": DECRYPT_ALL, "/zia/cloudApplicationRules": [
        {"id": 30, "name": "AI browse only (by order)", "order": 1, "rank": 7, "state": "ENABLED", "type": "AI_ML", "applications": ["CHATGPT_AI"],
         "actions": ["ALLOW_AI_ML_WEB_USE"]},
        {"id": 32, "name": "AI uploads allowed (by rank)", "order": 2, "rank": 2, "state": "ENABLED", "type": "AI_ML", "applications": ["CHATGPT_AI"],
         "actions": ["ALLOW_AI_ML_WEB_USE", "ALLOW_AI_ML_UPLOAD"]}]},
        "chat.openai.com", {}),
    "ssl": ({"/zia/sslInspectionRules": [
        {"id": 1, "name": "Do not decrypt webmail (by order)", "order": 1, "rank": 7, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["WEB_MAIL"]},
        {"id": 2, "name": "Decrypt webmail (by rank)", "order": 2, "rank": 3, "state": "ENABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["WEB_MAIL"]}]},
        "mail.example.com", {}),
    "ftc": ({"/zia/sslInspectionRules": DECRYPT_ALL, "/zia/fileTypeRules": [
        {"id": 40, "name": "Allow archives (by order)", "order": 1, "rank": 7, "state": "ENABLED", "filteringAction": "ALLOW", "operation": "UPLOAD",
         "fileTypes": ["FTCATEGORY_ZIP"], "urlCategories": ["WEB_MAIL"]},
        {"id": 41, "name": "Block archives (by rank)", "order": 2, "rank": 0, "state": "ENABLED", "filteringAction": "BLOCK", "operation": "UPLOAD",
         "fileTypes": ["FTCATEGORY_ZIP"], "urlCategories": ["WEB_MAIL"]}]},
        "mail.example.com", {"context": {"operation": "UPLOAD", "file_types": ["FTCATEGORY_ZIP"]}}),
    "dlp": ({"/zia/sslInspectionRules": DECRYPT_ALL, "/zia/webDlpRules": [
        {"id": 50, "name": "Monitor webmail (by order)", "order": 1, "rank": 7, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["WEB_MAIL"],
         "dlpEngines": [{"id": 1, "name": "PCI"}]},
        {"id": 51, "name": "Block webmail (by rank)", "order": 2, "rank": 4, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["WEB_MAIL"],
         "dlpEngines": [{"id": 1, "name": "PCI"}]}]},
        "mail.example.com", {}),
    "firewall": ({"/zia/firewallFilteringRules": [
        {"id": 1, "name": "Block HTTPS (by order)", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK_DROP", "nwServices": [{"id": 12, "name": "HTTPS"}]},
        {"id": 2, "name": "Allow HTTPS (by rank)", "order": 2, "rank": 0, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 12, "name": "HTTPS"}]},
        {"id": 5, "name": "Default Firewall Filtering Rule", "order": -1, "rank": 7, "defaultRule": True, "predefined": True, "state": "ENABLED", "action": "BLOCK_DROP"}]},
        "chat.openai.com", {}),
    "dns": ({"/zia/firewallDnsRules": [
        {"id": 1, "name": "Block gambling lookups (by order)", "order": 1, "rank": 7, "state": "ENABLED", "action": "BLOCK", "destIpCategories": ["GAMBLING"]},
        {"id": 3, "name": "Allow gambling lookups (by rank)", "order": 2, "rank": 2, "state": "ENABLED", "action": "ALLOW", "destIpCategories": ["GAMBLING"]},
        {"id": 2, "name": "Default DNS rule", "order": -1, "rank": 7, "defaultRule": True, "state": "ENABLED", "action": "ALLOW"}]},
        "casino.example", {}),
}
NAMES = {k: [r["name"] for r in next(v for ep, v in c[0].items() if ep != "/zia/sslInspectionRules" or k == "ssl")[:2]] for k, c in CASES.items()}


def routes_for(key, setting):
    r = dict(DF_ROUTES, **MODULE_ROUTES)
    # Only the default DNS rule, so DNS Control never ends a web case first.
    r["/zia/firewallDnsRules"] = [{"id": 2, "name": "Default DNS rule", "order": -1, "defaultRule": True, "state": "ENABLED", "action": "ALLOW"}]
    r.update(copy.deepcopy(CASES[key][0]))
    if setting is not None:
        r["/zia/advancedSettings"] = setting
    return r


def module(res, key):
    zm = res["zia_modules"]
    return zm["modifier"] if key == "ssl" else next(m for m in zm["modules"] if m["key"] == key)


def analyze(key, setting, scope=FULL):
    _, dest, kw = CASES[key]
    t = Tenant(routes_for(key, setting))
    return pa.analyze(t, dest, "off", "windows", scope=scope, **kw), t


# ── The oracle table ────────────────────────────────────────────────
@pytest.mark.parametrize("key", list(CASES))
def test_ranking_on_lets_the_better_ranked_rule_decide_and_says_so(key):
    """ASVS V1.4.4 · CWE-670: admin ranking on -> rank first; the step names the rank and says decided_by "rank" in text and JSON."""
    # Arrange
    a, b = NAMES[key]
    # Act
    res, _ = analyze(key, ON)
    m = module(res, key)
    # Assert
    assert res["admin_ranking"]["state"] == "on"
    assert m["rule"]["name"] == b and m["decided_by"] == "rank" and m["rule"]["rank"] is not None, m
    assert not m.get("admin_rank_caution"), m
    # (File Type Control stays conditional on its own: the operation criterion is not evaluated.)
    assert m["certainty"] == "definite" or key == "ftc", m
    text = m["detail"] + " " + " ".join(h.get("detail") or "" for h in res["trace"]["hops"] if h.get("key") == key)
    assert "admin rank first" in text and a in text and b in text
    hop = next(h for h in res["trace"]["hops"] if h.get("key") == key)
    assert hop["decided_by"]["by"] == "rank" and hop["decided_by"]["rank"] is not None


@pytest.mark.parametrize("key", list(CASES))
def test_ranking_off_keeps_rule_order(key):
    """ASVS V1.4.4 · CWE-670: admin ranking off -> rule order decides, no caution, decided_by "order"."""
    # Arrange
    a, _ = NAMES[key]
    # Act
    res, _ = analyze(key, OFF)
    m = module(res, key)
    # Assert
    assert res["admin_ranking"]["state"] == "off"
    assert m["rule"]["name"] == a and m["decided_by"] == "order" and not m.get("admin_rank_caution"), m


@pytest.mark.parametrize("key", list(CASES))
def test_ranking_not_readable_is_never_asserted(key):
    """ASVS V1.4.4 · CWE-670 · CWE-754: the setting could not be read and rank would decide differently -> conditional, with the caution naming both rules."""
    # Arrange
    a, b = NAMES[key]
    # Act: the tenant answers 404 for /zia/advancedSettings
    res, t = analyze(key, None)
    m = module(res, key)
    # Assert
    assert "/zia/advancedSettings" in t.paths and res["admin_ranking"]["state"] == "unknown"
    caution = m.get("admin_rank_caution") or ""
    assert caution.startswith("Admin ranking could not be read") and f"'{a}'" in caution and f"'{b}'" in caution, m
    assert "would decide differently with it on" in caution
    assert m["certainty"] == "conditional" and (m["rule"] is None or m["rule"]["name"] == a)
    assert res["verdict"]["certainty"] == "conditional" and any(caution in r for r in res["verdict"]["certainty_reasons"]), res["verdict"]


@pytest.mark.parametrize("key", ["url", "cac", "ssl", "ftc", "dlp"])
def test_ranking_not_in_scope_is_not_read_and_said(key):
    """ASVS V1.4.4 · CWE-272 · CWE-670: ZIA platform not ticked -> the setting is not read; where rank would matter the caution says it was not read."""
    # Act
    res, t = analyze(key, ON, scope=WEB_ONLY)
    m = module(res, key)
    # Assert
    assert "/zia/advancedSettings" not in t.paths
    assert res["admin_ranking"]["state"] == "out_of_scope"
    assert (m.get("admin_rank_caution") or "").startswith("Admin ranking was not read"), m
    assert m["certainty"] == "conditional"


@pytest.mark.parametrize("key", list(CASES))
def test_a_rank_tie_falls_back_to_rule_order_without_a_caution(key):
    """ASVS V1.4.4 · CWE-670: equal ranks -> rule order decides, whether ranking is on, off or unknown."""
    # Arrange: every rule at rank 3
    a, _ = NAMES[key]
    for ep, rules in CASES[key][0].items():
        for r in rules:
            r["rank"] = 3
    try:
        for setting, by in ((ON, "order"), (OFF, "order"), (None, "order")):
            # Act
            res, _ = analyze(key, setting)
            m = module(res, key)
            # Assert
            assert m["rule"]["name"] == a and m["decided_by"] == by and not m.get("admin_rank_caution"), (setting, m)
    finally:
        CASES[key][0].update(copy.deepcopy(_ORIGINAL[key]))


_ORIGINAL = {k: copy.deepcopy(c[0]) for k, c in CASES.items()}


def test_the_default_rule_stays_last_whatever_its_rank():
    """ASVS V1.4.4 · CWE-670: a default rule at rank 0 is still evaluated after every other rule."""
    # Arrange
    rules = [{"id": 9, "name": "Default", "order": -1, "rank": 0, "defaultRule": True, "action": "BLOCK_DROP"},
             {"id": 1, "name": "Low rank", "order": 5, "rank": 7, "action": "ALLOW"},
             {"id": 2, "name": "High rank", "order": 9, "rank": 1, "action": "ALLOW"}]
    # Act
    on = sorted(rules, key=zpm._ranked_key(True))
    off = sorted(rules, key=zpm._ranked_key(False))
    # Assert
    assert [r["name"] for r in on] == ["High rank", "Low rank", "Default"]
    assert [r["name"] for r in off] == ["Low rank", "High rank", "Default"]
    # The firewall module: the default rule (rank 0) never decides ahead of a match.
    res, _ = analyze("firewall", ON)
    assert module(res, "firewall")["rule"]["name"] == "Allow HTTPS (by rank)"


def test_a_rule_without_a_rank_is_taken_as_the_lowest_rank():
    """CWE-670: no rank (or one outside 0..7) sorts as rank 7 (assumed, admin_rank.DEFAULT_RANK)."""
    assert [admin_rank.rank_of(r) for r in ({}, {"rank": None}, {"rank": "x"}, {"rank": 9}, {"rank": True}, {"rank": "2"}, {"rank": 0})] == [7, 7, 7, 7, 7, 2, 0]


@pytest.mark.parametrize("answer,code,state", [(ON, 200, "on"), (OFF, 200, "off"), ({"enable_admin_rank_access": True}, 200, "on"),
                                               ({}, 200, "unknown"), ({"enableAdminRankAccess": "maybe"}, 200, "unknown"),
                                               ([], 200, "unknown"), ({"error": "forbidden"}, 403, "unknown")])
def test_the_setting_is_read_from_advanced_settings_and_never_guessed(answer, code, state):
    """ASVS V1.4.4 · CWE-754: true/false is on/off; missing, malformed or refused is unknown, never off."""
    class C:
        def get(self, ep, p=None):
            assert ep == "/zia/advancedSettings"
            return answer, code
    assert admin_rank.read(C(), ["zia_extras"])["state"] == state


def test_the_setting_is_not_read_when_zia_platform_is_not_ticked():
    """ASVS V4.1.3 · CWE-272: the reader refuses to send anything without ZIA platform in scope."""
    class C:
        def get(self, ep, p=None):
            raise AssertionError("read out of scope")
    assert admin_rank.read(C(), ["dlp", "zcc"])["state"] == "out_of_scope"


# ── Shadowed and unreachable rules ──────────────────────────────────
def _url(rid, name, order, rank, action):
    return {"id": rid, "name": name, "order": order, "rank": rank, "action": action, "state": "ENABLED", "urlCategories": ["GAMBLING"]}


SHADOW = {"url_filtering": [_url(1, "Block gambling", 1, 7, "BLOCK"), _url(2, "Allow gambling", 2, 1, "ALLOW")]}


def test_shadow_analysis_off_compares_by_rule_order():
    """ASVS V1.4.4 · CWE-670: ranking off -> the later rule by order is shadowed."""
    res = sr.analyse(SHADOW, admin_ranking={"state": "off"})
    assert [(f["rule"], f["kind"], f["shadowed_by"]["name"]) for f in res["findings"]] == [("Allow gambling", "shadowed", "Block gambling")]


def test_shadow_analysis_on_compares_only_with_rules_evaluated_before():
    """ASVS V1.4.4 · CWE-670: ranking on -> the better-ranked rule is evaluated first, so the rule order 1 is the one shadowed."""
    res = sr.analyse(SHADOW, admin_ranking={"state": "on"})
    f = res["findings"]
    assert [(x["rule"], x["kind"], x["shadowed_by"]["name"]) for x in f] == [("Block gambling", "shadowed", "Allow gambling")]
    assert f[0]["rank"] == 7 and f[0]["shadowed_by"]["rank"] == 1 and "rank 1, order 2" in f[0]["reason"]
    assert "admin rank first" in res["notes"]["url_filtering"]


def test_shadow_analysis_with_ranking_unknown_marks_findings_that_depend_on_it():
    """ASVS V1.4.4 · CWE-670 · CWE-754: ranking unknown -> both possible findings, each saying which setting it holds under."""
    res = sr.analyse(SHADOW, admin_ranking={"state": "unknown", "why": "HTTP 403"})
    by_rule = {f["rule"]: f for f in res["findings"]}
    assert set(by_rule) == {"Allow gambling", "Block gambling"}
    assert all(f["admin_rank"] == "depends" for f in by_rule.values())
    assert "holds only if admin ranking is off" in by_rule["Allow gambling"]["admin_rank_caution"]
    assert "holds only if admin ranking is on" in by_rule["Block gambling"]["admin_rank_caution"]
    assert "could not be read (HTTP 403)" in by_rule["Allow gambling"]["reason"]


def test_shadow_analysis_with_a_rank_tie_is_unchanged():
    """CWE-670: equal ranks -> the order finding only, nothing depends on ranking."""
    rules = {"url_filtering": [_url(1, "Block gambling", 1, 3, "BLOCK"), _url(2, "Allow gambling", 2, 3, "ALLOW")]}
    for st in ("on", "off", "unknown"):
        res = sr.analyse(rules, admin_ranking={"state": st})
        assert [(f["rule"], f.get("admin_rank")) for f in res["findings"]] == [("Allow gambling", None)], st


def test_shadow_read_asks_for_the_setting_only_with_zia_platform_in_scope():
    """ASVS V4.1.3 · CWE-272: the shadowed-rule reader reads admin ranking with ZIA platform ticked, never without."""
    from test_shadow_rules import ROUTES as SR_ROUTES, ReadOnlyClient
    routes = dict(SR_ROUTES, **{"/zia/advancedSettings": ON, "/zia/urlFilteringRules": SHADOW["url_filtering"]})
    with_zia = ReadOnlyClient(routes)
    res = sr.run(with_zia, sr.scope_for(["dlp", "zia_extras"], {"web_dlp": "zscaler"}))
    assert ("GET", "/zia/advancedSettings") in with_zia.calls and res["admin_ranking"]["state"] == "on"
    assert any(f["rule"] == "Block gambling" and f["kind"] == "shadowed" for f in res["findings"])
    dlp_only = ReadOnlyClient(routes)
    res = sr.run(dlp_only, sr.scope_for(["dlp"], {"web_dlp": "zscaler"}))
    assert ("GET", "/zia/advancedSettings") not in dlp_only.calls and res["admin_ranking"]["state"] == "out_of_scope"


# ── What-if and Test a list ─────────────────────────────────────────
def test_whatif_lists_a_scoped_rule_only_when_it_is_evaluated_before_the_fallback():
    """ASVS V1.4.4 · CWE-670: with ranking on, a scoped rule ranked below the rule for everyone never changes the action."""
    scoped = {"id": 1, "name": "Finance may gamble", "order": 1, "rank": 7, "enabled": True, "action": "ALLOW", "url_categories": ["GAMBLING"],
              "cloud_applications": [], "app_classes": [], "request_methods": [], "protocols": [], "scope": ["group Finance"], "scoped": True,
              "scope_items": {"groups": [{"id": 5, "name": "Finance"}]}}
    everyone = dict(scoped, id=2, name="Block gambling", order=2, rank=1, action="BLOCK", scope=[], scoped=False, scope_items={})
    dest = {"categories": ["GAMBLING"], "applications": [], "app_classes": [], "kind": "host", "host": "casino.example"}
    off = path_whatif.depends_on({"url": [scoped, everyone], "admin_ranking": {"state": "off"}}, dest)
    on = path_whatif.depends_on({"url": [scoped, everyone], "admin_ranking": {"state": "on"}}, dest)
    assert [e["rule"]["name"] for e in off] == ["Finance may gamble"]
    assert on == []


def test_test_a_list_does_not_assert_a_row_rank_could_change():
    """ASVS V1.4.4 · CWE-754: a row whose module depends on an unread admin ranking is unverified, with the caution."""
    res, _ = analyze("url", None)
    row = bulk_test.summarize_analysis(res)
    assert row["result"] == "unverified" and row["notes"] and row["notes"][0].startswith("Admin ranking could not be read")
    res_on, _ = analyze("url", ON)
    assert bulk_test.summarize_analysis(res_on)["result"] == "allowed"
    assert pa.batch_row("casino.example", res_on)["decided_by_rank"] == ["URL filtering"]


# ── The Scope rule at the routes ────────────────────────────────────
def test_path_route_with_nothing_ticked_is_refused_before_sign_in(tenant):  # noqa: F811
    """ASVS V4.1.3 · CWE-272: nothing in scope -> 400 before any client is built; the setting is never read."""
    r = TestClient(srv.app).post("/api/path-analyzer", json=dict(CREDS, destination="example.com", **NOTHING_TICKED))
    assert r.status_code == 400 and tenant.built == [] and tenant.reads == []


@pytest.mark.parametrize("sel,read", [(WEB, False), (ZIA, True)], ids=["dlp-only", "zia-platform"])
def test_path_route_reads_the_setting_only_with_zia_platform(tenant, sel, read):  # noqa: F811
    """ASVS V4.1.3 · CWE-272: DLP only -> /zia/advancedSettings is not read; ZIA platform ticked -> it is."""
    r = TestClient(srv.app).post("/api/path-analyzer", json=dict(CREDS, destination="example.com", **sel))
    assert r.status_code == 200, r.text[:300]
    assert ("/zia/advancedSettings" in tenant.raw()) is read, tenant.raw()


# ── Older reads, snapshots and the sample tenant ────────────────────
def test_a_kept_read_without_the_setting_still_answers_as_unknown():
    """ASVS V1.4.4 · CWE-754: a kept read made before the setting was recorded is reused; ranking is unknown and cautioned only where it matters."""
    res, _ = analyze("url", ON)
    old = copy.deepcopy(res["snapshot_for_cache"])
    old["snapshot"]["zia"].pop("admin_ranking")
    t = Tenant(routes_for("url", ON))
    again = pa.analyze(t, "casino.example", "off", "windows", scope=FULL, snapshot=old)
    assert not again["fresh_read"] and "/zia/advancedSettings" not in t.paths
    assert again["admin_ranking"]["state"] == "unknown" and admin_rank.NOT_RECORDED_WHY in again["admin_ranking"]["why"]
    assert module(again, "url")["admin_rank_caution"]
    # Where rank changes nothing (the firewall here has no ranked choice), no caution.
    assert not any(m.get("admin_rank_caution") for m in again["zia_modules"]["modules"] if m["key"] != "url")


def _offline_client(responses):
    answers = {offline_tenant.normalize_path(p): {"status": 200, "body": b} for p, b in responses.items()}
    # A copy of the sample (writable in memory, as the sample is, so its URL lookup answers); never a tenant.
    st = offline_tenant.OfflineStore("sample", offline_tenant.SAMPLE, answers, {"tenant_label": "Sample with ranking on"}, writable=True)
    return offline_tenant.OfflineRawClient(st, offline_tenant.creds_for(st))


def test_an_older_snapshot_without_the_setting_loads_and_reads_as_unknown():
    """ASVS V1.4.4 · CWE-754: a snapshot saved without /advancedSettings, or with it but without the field, loads; ranking is unknown, never off."""
    base = sample_tenant.responses()
    no_endpoint = {k: v for k, v in base.items() if not k.endswith("/advancedSettings")}
    no_field = dict(base)
    no_field[f"{sample_tenant.ZIA}/advancedSettings"] = {k: v for k, v in base[f"{sample_tenant.ZIA}/advancedSettings"].items() if k != "enableAdminRankAccess"}
    for responses, why in ((no_endpoint, "could not be read"), (no_field, "is missing")):
        doc = offline_tenant.build_snapshot({p: {"status": 200, "body": b} for p, b in responses.items()}, {"tenant_label": "old (production)"})
        st = offline_tenant.open_document(offline_tenant.dumps(doc))
        res = pa.analyze(offline_tenant.OfflineRawClient(st, offline_tenant.creds_for(st)), "online-casino.example", "off", "windows", scope=FULL)
        assert res["admin_ranking"]["state"] == "unknown" and why in res["admin_ranking"]["why"], res["admin_ranking"]
        # The sample's rules all sit at rank 7: nothing depends on ranking, so nothing is cautioned.
        assert not any(m.get("admin_rank_caution") for m in res["zia_modules"]["modules"])


def test_the_sample_tenant_has_admin_ranking_off():
    """ASVS V1.4.4: the sample tenant carries the setting (off) and the Path analyzer reads it."""
    st = offline_tenant.sample_store()
    res = pa.analyze(offline_tenant.OfflineRawClient(st, offline_tenant.creds_for(st)), "online-casino.example", "off", "windows", scope=FULL)
    assert sample_tenant.ADVANCED_SETTINGS["enableAdminRankAccess"] is False
    assert res["admin_ranking"]["state"] == "off" and module(res, "url")["rule"]["name"] == "Block gambling"


def test_the_sample_tenant_with_admin_ranking_on_lets_rank_decide():
    """ASVS V1.4.4 · CWE-670: the sample with ranking on and a rank-0 allow rule below the block: the allow decides, by rank."""
    responses = sample_tenant.responses()
    responses[f"{sample_tenant.ZIA}/advancedSettings"]["enableAdminRankAccess"] = True
    responses[f"{sample_tenant.ZIA}/urlFilteringRules"].append(
        {"id": 604, "order": 4, "rank": 0, "name": "Allow gambling for the risk team", "state": "ENABLED", "action": "ALLOW",
         "urlCategories": ["GAMBLING"], "protocols": ["ANY_RULE"]})
    res = pa.analyze(_offline_client(responses), "online-casino.example", "off", "windows", scope=FULL)
    m = module(res, "url")
    assert res["admin_ranking"]["state"] == "on"
    assert m["rule"]["name"] == "Allow gambling for the risk team" and m["decided_by"] == "rank" and m["rule"]["rank"] == 0
    assert any("Admin ranking is on" in a for a in res["assumptions"])


# ── The page shows the rank next to the order ───────────────────────
def test_the_page_renderer_shows_rank_next_to_order_and_the_caution():
    """ASVS V1.4.4: the module renderer writes 'rank R, order N', 'decided by admin rank' and the caution."""
    import os
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "path_modules.js"), encoding="utf-8") as f:
        js = f.read()
    assert "rank ${r.rank}" in js and "decided by admin rank" in js and "admin_rank_caution" in js and "Rank, order" in js
