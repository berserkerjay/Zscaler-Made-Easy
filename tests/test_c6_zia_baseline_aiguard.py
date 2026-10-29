"""C6 QA: the ZIA security baseline (ops_zia_baseline), the AI Guard builders
(ops_aiguard) and AI Guard readiness (ai_guard). Every tier, overlay, area
and option combination; the rule constraints (31-character unique names,
the catch-all last, locked rules, disabled by default, re-runs in place);
framework files and Undo specs as untrusted input; the AI Guard routing
order, QUIC block, SSL Inspect placement, Monitor default and the detection
policy per profile; and the payloads against zscaler-sdk-python 1.11.3.

Fakes only (the recording tenants of test_ops_zia_baseline and
test_ops_aiguard): no network, no clock, no real tenant."""
from __future__ import annotations

import copy
import itertools
import json
import re
import threading

import pytest

import admin_ops as ao
import ai_guard as ag
import ops_aiguard as oa
import ops_zia_baseline as zb
import pack_channels as pc
import test_ops_aiguard as at
import test_ops_zia_baseline as zt

MODES = ("tier", "allow_all", "block_all")
OVERLAY_SETS = [[]] + [[o] for o in zb.OVERLAYS] + [list(zb.OVERLAYS)]
FW = {"format": zb.FRAMEWORK_FORMAT, "format_version": zb.FRAMEWORK_VERSION}


@pytest.fixture(autouse=True)
def _offline(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(pc, "activate", lambda zia: {"activated": True, "status": "ACTIVE", "error": None})
    monkeypatch.setattr(pc, "wait_active", lambda zia, s=0, log=None: "ACTIVE")


def zb_plan(t, spec, scope=zt.FULL):
    return ao.plan(t, dict(spec, type=spec.get("type", zb.TYPE)), scope=scope, tenant_label="acme")


def zb_apply(t, spec, scope=zt.FULL, prepared=None):
    spec = dict(spec, type=spec.get("type", zb.TYPE))
    p = prepared or zb_plan(t, spec, scope)
    return ao.execute(t, spec, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe",
                      confirm_text=p["confirm_phrase"], tenant_label="acme", settle_seconds=0)


def fw_rule(area, name, default, fields=None, **extra):
    r = {"name": name, "default": default, **extra}
    if fields is not None:
        r["fields"] = fields
    return r


def framework(areas):
    return dict(FW, areas=areas)


def rows_of(t, area):
    return getattr(t.zia, zb.AREAS[area]["service"]).rows


# ===========================================================================
# ZIA baseline: every tier x mode x overlay set (review is pure)
# ===========================================================================

@pytest.mark.parametrize("tier,mode,overlays", list(itertools.product(zb.TIERS, MODES, OVERLAY_SETS)),
                         ids=lambda v: v if isinstance(v, str) else "+".join(v) or "none")
def test_every_tier_mode_and_overlay_combination_keeps_the_rule_constraints(tier, mode, overlays):
    """ASVS V5.1.3 · V1.4.1 · CWE-20 · CWE-1188 · WSTG-BUSL-01: for every tier, mode and overlay set the names are unique and at most 31 characters, locked rules stay on and Allow, the DNS redirect keeps its action, each rule cites a source, and overlays never change a rule."""
    # Arrange
    spec = {"tier": tier, "mode": mode, "overlays": overlays, "prefix": "ABCDEFGHIJ"}
    # Act
    rv = zb.review(spec)
    plain = zb.review(dict(spec, overlays=[]))
    # Assert
    rows = rv["rules"]
    buckets = {}
    for r in rows:
        assert 0 < len(r["name"]) <= zb.MAX_NAME and r["name"].startswith("ABCDEFGHIJ-")
        key = r["area"] + ":" + str(r["fields"].get("type") or "")
        assert r["name"] not in buckets.setdefault(key, set())
        buckets[key].add(r["name"])
        assert r["sources"] and all(s["url"].startswith("https://") for s in r["sources"])
        if r["locked"]:
            assert r["on"] is True and r["action"] == "ALLOW" and r["choices"] == []
        if r["action_locked"]:
            assert r["action"] == "REDIR_REQ_KEEP_SENDER"
        if mode != "tier" and zb.AREAS[r["area"]]["choose"] and not (r["locked"] or r["action_locked"]):
            assert r["choice"] == ("ALLOW" if mode == "allow_all" else "BLOCK")
        if not overlays:
            assert r["controls"] == []
        if len(overlays) == len(zb.OVERLAYS):   # HIPAA, NIST and the others cover every control domain
            assert r["controls"] and all(c["controls"] and c["source"]["url"].startswith("https://") for c in r["controls"])
    assert [(r["key"], r["action"], r["on"]) for r in rows] == [(r["key"], r["action"], r["on"]) for r in plain["rules"]]
    assert {c["overlay"] for r in rows for c in r["controls"]} <= set(overlays)


# Oracle: the default action of a rule per tier (None: not in the tier).
ORACLE = [
    ("fw.default_deny", {"strict": "BLOCK_DROP", "balanced": None, "permissive": None, "healthcare": None}),
    ("fw.p2p", {"strict": "BLOCK_DROP", "balanced": None, "permissive": None, "healthcare": "BLOCK_DROP"}),
    ("fw.quic", {t: "BLOCK_DROP" for t in zb.TIERS}),
    ("fw.allow_web", {t: "ALLOW" for t in zb.TIERS}),
    ("url.bandwidth", {"strict": "BLOCK", "balanced": "CAUTION", "permissive": None, "healthcare": None}),
    ("url.security", {"strict": "BLOCK", "balanced": "BLOCK", "permissive": "BLOCK", "healthcare": None}),
    ("url.security_global", {"strict": None, "balanced": None, "permissive": None, "healthcare": "BLOCK"}),
    ("url.misc", {t: "ISOLATE" for t in zb.TIERS}),
    ("ssl.catch_all", {"strict": "DECRYPT", "balanced": "DECRYPT", "permissive": "DO_NOT_DECRYPT", "healthcare": "DECRYPT"}),
    ("ssl.exempt_health", {"strict": None, "balanced": "DO_NOT_DECRYPT", "permissive": None, "healthcare": None}),
    ("ssl.exempt_fhg", {"strict": None, "balanced": None, "permissive": None, "healthcare": "DO_NOT_DECRYPT"}),
    ("sb.executables", {"strict": "ALLOW_SCAN", "balanced": "ALLOW_SCAN", "permissive": None, "healthcare": "ALLOW_SCAN"}),
    ("dns.resolver", {t: "REDIR_REQ_KEEP_SENDER" for t in zb.TIERS}),
    ("dns.tunnels_high", {"strict": "BLOCK", "balanced": "BLOCK", "permissive": None, "healthcare": "BLOCK"}),
    ("ftc.pw_archives", {"strict": "BLOCK", "balanced": None, "permissive": None, "healthcare": "BLOCK"}),
    ("cac.im", {"strict": ["BLOCK_CHAT", "BLOCK_FILE_TRANSFER_IN_CHAT"], "balanced": ["BLOCK_FILE_TRANSFER_IN_CHAT"], "permissive": None,
                "healthcare": ["BLOCK_CHAT", "BLOCK_FILE_TRANSFER_IN_CHAT"]}),
    ("cac.ai_ml", {"strict": ["DENY_AI_ML_WEB_USE"], "balanced": ["CAUTION_AI_ML_WEB_USE"], "permissive": ["CAUTION_AI_ML_WEB_USE"],
                   "healthcare": ["DENY_AI_ML_WEB_USE"]}),
]


@pytest.mark.parametrize("key,per_tier", ORACLE, ids=[k for k, _ in ORACLE])
def test_each_tier_sets_the_documented_default_action(key, per_tier):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-01: an oracle table of the tier defaults (Strict, Balanced, Permissive, Healthcare zero trust) matches the review."""
    for tier, want in per_tier.items():
        rows = {r["key"]: r for r in zb.review({"tier": tier})["rules"]}
        assert (rows[key]["action"] if key in rows else None) == want, (tier, key)


@pytest.mark.parametrize("tier", list(zb.TIERS))
def test_the_catch_alls_are_the_only_rules_with_nothing_to_match(tier):
    """ASVS V1.4.1 · CWE-1188: in the catalog only the SSL catch-all and the firewall default deny match everything, and both are flagged to go last."""
    for r in zb.review({"tier": tier})["rules"]:
        names_something = any(r["fields"].get(k) for k in zb.MATCH_FIELDS[r["area"]])
        assert names_something or r["catch_all"], r["key"]


@pytest.mark.parametrize("tier", list(zb.TIERS))
def test_every_atp_setting_defaults_per_tier_and_each_switch_off_is_flagged(tier):
    """ASVS V1.4.1 · CWE-1188: the 20 ATP block switches are on for the tier (Permissive leaves SSH tunnelling off) and each one switched off is flagged weaker."""
    rv = zb.review({"tier": tier})
    assert [s["key"] for s in rv["atp"]] == [k for k, _ in zb.ATP_SETTINGS]
    for s in rv["atp"]:
        assert s["value"] is (s["key"] not in zb.ATP_TIER_OFF.get(tier, set()))
    for key, _ in zb.ATP_SETTINGS:
        one = {s["key"]: s for s in zb.review({"tier": tier, "atp": {key: False}})["atp"]}[key]
        assert one["value"] is False and one["weakened"] == ("switched off" if one["default"] else "")


@pytest.mark.parametrize("area,choice,want", [
    ("firewall", "BLOCK", "BLOCK_DROP"), ("firewall", "ALLOW", "ALLOW"), ("url", "ISOLATE", "ISOLATE"), ("url", "ALLOW", "ALLOW"),
    ("url", "BLOCK", "BLOCK"), ("dns", "ALLOW", "ALLOW"), ("ftc", "ALLOW", "ALLOW"), ("ssl", "ALLOW", None), ("sandbox", "BLOCK", None)])
def test_each_area_offers_only_its_own_actions(area, choice, want):
    """ASVS V5.1.3 · CWE-20: a per-rule choice is applied only where the area offers it; elsewhere the tier default stays."""
    key = next(r["key"] for r in zb.CATALOG if r["area"] == area and "strict" in r["tiers"] and not r["locked"] and not r["action_locked"])
    row = {r["key"]: r for r in zb.review({"tier": "strict", "rules": {key: {"action": choice}}})["rules"]}[key]
    assert row["action"] == (want if want is not None else zb.CATALOG_BY_KEY[key]["tiers"]["strict"])


@pytest.mark.parametrize("key", ["fw.allow_web", "fw.allow_ntp"])
@pytest.mark.parametrize("choice", [{"on": False}, {"action": "BLOCK"}, {"on": False, "action": "BLOCK"}])
def test_locked_rules_cannot_be_weakened_or_switched_off(key, choice):
    """ASVS V1.4.1 · CWE-284 · CWE-1188: the locked Allow-Web and Allow-NTP rules stay on and Allow whatever the choice."""
    row = {r["key"]: r for r in zb.review({"tier": "strict", "mode": "block_all", "rules": {key: choice}})["rules"]}[key]
    assert row["on"] is True and row["action"] == "ALLOW" and row["choice"] == "TIER"


def test_the_dns_redirect_keeps_its_action_under_block_all():
    """ASVS V1.4.1 · CWE-1188: blocking the Trusted Resolver redirect would block all DNS, so its action is locked."""
    row = {r["key"]: r for r in zb.review({"tier": "balanced", "mode": "block_all", "rules": {"dns.resolver": {"action": "BLOCK"}}})["rules"]}
    assert row["dns.resolver"]["action"] == "REDIR_REQ_KEEP_SENDER"


@pytest.mark.parametrize("prefix,suffix", [("A", "SSL-Exempt-Fin-Health-Gov"), ("ABCDEFGHIJ", "SSL-Exempt-Fin-Health-Gov"),
                                           ("ABCDEFGHIJ", "X" * 60), ("", "CAC-Instant-Messaging"), ("P", "")])
def test_short_names_fit_31_characters_and_keep_the_prefix(prefix, suffix):
    """ASVS V5.1.3 · CWE-20: a rule name is at most 31 characters and keeps its prefix (boundary: the 10-character prefix, a 60-character suffix)."""
    n = zb.short_name(prefix, suffix)
    assert len(n) <= zb.MAX_NAME and n.startswith(f"{prefix}-" if prefix else "")


def test_names_that_shorten_to_the_same_text_are_made_unique():
    """ASVS V5.1.3 · CWE-694: two rules whose names cut to the same 31 characters get distinct names within ZIA's limit."""
    rows = [{"area": "url", "fields": {}, "name": "BL-" + "Z" * 28}, {"area": "url", "fields": {}, "name": "BL-" + "Z" * 28},
            {"area": "url", "fields": {}, "name": "BL-" + "Z" * 28}]
    zb._unique_names(rows)
    names = [r["name"] for r in rows]
    assert len(set(names)) == 3 and all(len(n) <= zb.MAX_NAME for n in names) and names[1].endswith("-2") and names[2].endswith("-3")


# ===========================================================================
# ZIA baseline: apply, catch-all last, disabled by default, re-runs in place
# ===========================================================================

@pytest.mark.parametrize("tier", list(zb.TIERS))
@pytest.mark.parametrize("mode", MODES)
def test_every_tier_and_mode_applies_disabled_with_catch_alls_last_and_a_rerun_changes_nothing(tier, mode):
    """ASVS V1.4.1 · V11.1.1 · CWE-1188 · CWE-841: every tier and mode creates its rules DISABLED below the tenant's, the SSL catch-all and firewall default deny last, and the same baseline again is a no-op (idempotent)."""
    # Arrange
    t = zt.Tenant()
    spec = {"tier": tier, "mode": mode}
    # Act
    res = zb_apply(t, spec)
    again = zb_plan(t, spec)
    # Assert
    assert res["status"] == "applied", [(u["key"], u["status"], u.get("error")) for u in res["items"] if u["status"] not in ("applied", "noop")]
    for area in zb.RULE_AREAS:
        made = [r for r in rows_of(t, area) if r.get("id", 0) > 900]
        assert all(r["state"] == "DISABLED" for r in made), area
        last = max((r for r in rows_of(t, area) if not r.get("default_rule")), key=lambda r: int(r.get("order") or 0), default=None)
        if any(r["name"].endswith(("SSL-Catch-All", "FW-Dflt-Deny", "FW-Default-Deny")) for r in made):
            assert last["name"].endswith(("SSL-Catch-All", "FW-Default-Deny")), (area, last["name"])
    assert again["status"] == "nothing_to_do", [(u["key"], u["field"], u["before"], u["after"]) for u in again["items"] if u["status"] == "change"]


def test_enable_rules_creates_rules_enabled_and_needs_the_phrase():
    """ASVS V11.1.1 · CWE-841: "Create the rules enabled" is the only way a rule arrives ENABLED, and it asks for the typed phrase."""
    t = zt.Tenant()
    p = zb_plan(t, {"tier": "strict", "areas": ["ftc"], "enable_rules": True})
    assert p["confirm_phrase"] == "APPLY 4 CHANGES"
    zb_apply(t, {"tier": "strict", "areas": ["ftc"], "enable_rules": True}, prepared=p)
    assert {r["state"] for r in rows_of(t, "ftc")} == {"ENABLED"}


@pytest.mark.parametrize("value", ["true", 1, "yes"])
def test_enable_rules_must_be_exactly_true(value):
    """ASVS V5.1.3 · CWE-1188: anything but the boolean true keeps the rules disabled (secure default)."""
    assert zb.normalize({"tier": "strict", "enable_rules": value})["enable_rules"] is False


def test_a_tier_change_updates_the_same_rules_in_place():
    """ASVS V1.4.1 · CWE-841: Strict then Balanced matches the rules by name and updates the fields that differ; nothing is created twice."""
    t = zt.Tenant()
    zb_apply(t, {"tier": "strict", "areas": ["url"]})
    count = len(rows_of(t, "url"))
    p = zb_plan(t, {"tier": "balanced", "areas": ["url"]})
    bw = [u for u in p["items"] if u["object"].get("name") == "BL-URL-Bandwidth-Loss" and u["field"] == "action"]
    assert bw and bw[0]["before"] == "BLOCK" and bw[0]["after"] == "CAUTION"
    res = zb_apply(t, {"tier": "balanced", "areas": ["url"]}, prepared=p)
    assert res["status"] in ("applied", "partial") and not [u for u in res["items"] if u["kind"] == "rule_create" and u["status"] == "applied"
                                                             and u["object"]["name"] in {r["name"] for r in rows_of(t, "url")[:count]}]
    assert next(r for r in rows_of(t, "url") if r["name"] == "BL-URL-Bandwidth-Loss")["action"] == "CAUTION"


def test_atp_is_changed_only_when_picked_and_read_never_otherwise():
    """ASVS V4.1.3 · CWE-1188: with the default areas ATP is neither read nor changed; picked, it is planned with the phrase."""
    t = zt.Tenant()
    zb_plan(t, {"tier": "strict"})
    assert "atp_policy.get_atp_settings" not in t.reads
    p = zb_plan(t, {"tier": "strict", "areas": ["atp"]})
    assert [u["field"] for u in p["items"] if u["status"] == "change"] == ["crypto_mining_blocked"] and p["confirm_phrase"] == "APPLY 1 CHANGE"


# ===========================================================================
# ZIA baseline: regression tests for the defects fixed here
# ===========================================================================

@pytest.mark.parametrize("area,default", [("url", "BLOCK"), ("firewall", "BLOCK_DROP"), ("url", "ALLOW"), ("ftc", "BLOCK"), ("dns", "BLOCK")])
def test_a_framework_rule_that_names_nothing_to_match_is_dropped_not_created(area, default):
    """ASVS V5.1.3 · V1.4.1 · CWE-20 · CWE-1188 · WSTG-BUSL-01: a framework rule with no categories, applications, countries or file types would match all traffic; it is dropped with the reason, never created."""
    # Arrange
    t = zt.Tenant()
    fw = framework({area: [fw_rule(area, "Match Everything", default, {"protocols": ["ANY_RULE"]})]})
    # Act
    p = zb_plan(t, {"framework": fw, "areas": [area]})
    # Assert
    item = next(u for u in p["items"] if u["object"].get("name") == "Match Everything")
    assert item["status"] == "excluded" and "match all traffic" in item["reason"] and p["status"] == "nothing_to_do"


def test_a_captured_rule_that_matched_only_people_does_not_become_a_block_all():
    """ASVS V1.4.1 · CWE-1188 · CWE-284: a source rule that blocked everything for one group is captured without the group, so it is dropped rather than blocking everyone."""
    src = zt.Tenant(url=[{"id": 31, "name": "Block All For Interns", "order": 1, "state": "ENABLED", "action": "BLOCK", "protocols": ["ANY_RULE"],
                          "groups": [{"id": 3, "name": "Interns"}]}, zt.URL_DEFAULT])
    fw = zb.capture(src, ["url"], tenant_label="src")["framework"]
    dst = zt.Tenant(url=[zt.URL_DEFAULT])
    res = zb_apply(dst, {"framework": json.loads(json.dumps(fw)), "areas": ["url"]})
    assert [r["name"] for r in rows_of(dst, "url")] == ["Default URL Filtering Rule"] and res["status"] == "nothing_to_do"


@pytest.mark.parametrize("fields,why", [
    ([1], "fields must be an object"), ("url_categories", "fields must be an object"),
    ({"url_categories": True}, "list of Zscaler names"), ({"url_categories": "GAMBLING"}, "list of Zscaler names"),
    ({"url_categories": ["GAMBLING\n"]}, "list of Zscaler names"), ({"protocols": ["ANY_RULE", 7]}, "list of Zscaler names"),
])
def test_framework_fields_of_the_wrong_shape_are_refused_in_plain_words(fields, why):
    """ASVS V5.1.3 · V7.4.1 · CWE-20 · CWE-755 · WSTG-INPV-01: an uploaded framework's fields of the wrong shape are refused with a plain error, never an AttributeError or a rule matching single letters."""
    with pytest.raises(ao.OperationError, match=why):
        zb.load_framework(framework({"url": [fw_rule("url", "R1", "BLOCK", fields)]}))


@pytest.mark.parametrize("area,fields,why", [
    ("ssl", {"min_tls": "TLS_9_9"}, "Zscaler name"), ("ssl", {"min_tls": ["TLS_1_2"]}, "Zscaler name"),
    ("ftc", {"file_types": ["FTCATEGORY_ZIP"], "password_protected": "yes"}, "true or false"),
    ("sandbox", {"file_types": ["FTCATEGORY_ZIP"], "ml_action_enabled": 1}, "true or false"),
    ("ftc", {"file_types": ["FTCATEGORY_ZIP"], "operation": "UPLOAD\n"}, "Zscaler name"),
])
def test_framework_scalar_and_switch_values_are_checked(area, fields, why):
    """ASVS V5.1.3 · CWE-20: a framework's TLS version, switches and operation are checked (a trailing newline or a string for a switch is refused)."""
    default = {"ssl": "DECRYPT", "ftc": "BLOCK", "sandbox": "QUARANTINE"}[area]
    with pytest.raises(ao.OperationError, match=why):
        zb.load_framework(framework({area: [fw_rule(area, "R1", default, fields)]}))


def test_framework_fields_outside_their_area_are_ignored():
    """ASVS V5.1.3 · CWE-915: trusted_resolver and min_tls are taken only in DNS Control and SSL inspection, where they mean something."""
    got = zb.load_framework(framework({"url": [fw_rule("url", "R1", "BLOCK", {"url_categories": ["GAMBLING"], "trusted_resolver": True,
                                                                               "min_tls": "TLS_1_3"})]}))
    assert got["rules"][0]["fields"] == {"url_categories": ["GAMBLING"]}


@pytest.mark.parametrize("ver,why", [(True, "no usable format_version"), ("1", "no usable format_version"), (None, "no usable format_version"),
                                     (0, "no usable format_version"), (2, "newer version")])
def test_framework_format_version_is_an_exact_integer(ver, why):
    """ASVS V5.1.3 · CWE-1287: format_version must be the integer 1 (true, "1" or a missing version are refused with the right reason)."""
    with pytest.raises(ao.OperationError, match=why):
        zb.load_framework({"format": zb.FRAMEWORK_FORMAT, "format_version": ver, "areas": {"url": [fw_rule("url", "R1", "BLOCK")]}})


def test_framework_name_title_and_rule_count_are_capped():
    """ASVS V5.1.3 · CWE-400 · WSTG-BUSL-05: a framework's name, rule names and titles are cut to their limits; 200 rules per area pass, 201 are refused."""
    rules = [fw_rule("url", f"R{i}{'x' * 60}", "BLOCK", {"url_categories": ["GAMBLING"]}, title="t" * 5000) for i in range(200)]
    got = zb.load_framework(dict(framework({"url": rules}), name="n" * 1000))
    assert len(got["name"]) == 120 and all(len(r["name"]) <= zb.MAX_NAME and len(r["title"].encode()) <= 200 for r in got["rules"])
    with pytest.raises(ao.OperationError, match="too many"):
        zb.load_framework(framework({"url": rules + rules[:1]}))


@pytest.mark.parametrize("text,limit", [("é" * 20_000, 200), ("a" * 20_000, 255), ("😀" * 5_000, 200)])
def test_cutting_a_long_title_takes_a_bounded_number_of_steps(text, limit):
    """ASVS V5.1.3 · CWE-407 · CWE-400 · WSTG-BUSL-05: an untrusted 20,000-character title is cut to its byte limit in a bounded number of steps (counted, not timed), not one character per pass."""
    import sys
    steps = [0]

    def tracer(frame, event, arg):
        if frame.f_code is zb._fit_bytes.__code__ and event == "line":
            steps[0] += 1
        return tracer
    before = sys.gettrace()   # coverage's own tracer, put back afterwards
    sys.settrace(tracer)
    try:
        out = zb._fit_bytes(text, limit)
    finally:
        sys.settrace(before)
    assert len(out.encode("utf-8")) <= limit and out.endswith("…") and steps[0] < 2 * limit


def test_a_capture_over_200_rules_says_what_it_left_out():
    """ASVS V1.4.1 · CWE-221: a tenant with more than 200 rules in an area is captured to the limit and the rest is listed, not dropped silently."""
    many = [{"id": 100 + i, "name": f"Block {i}", "order": i + 1, "state": "ENABLED", "action": "BLOCK", "url_categories": ["GAMBLING"]}
            for i in range(205)]
    fw = zb.capture(zt.Tenant(url=many), ["url"], tenant_label="src")["framework"]
    assert len(fw["areas"]["url"]) == 200 and fw["counts"]["url"] == 200
    assert any("first 200 of 205" in x["reason"] for x in fw["not_exported"])


def test_an_unknown_tier_is_refused_even_with_a_framework():
    """ASVS V5.1.3 · CWE-20: the tier is one of the four or "captured" with a framework; any other string is refused."""
    fw = framework({"url": [fw_rule("url", "R1", "BLOCK", {"url_categories": ["GAMBLING"]})]})
    with pytest.raises(ao.OperationError, match="Unknown tier"):
        zb.normalize({"tier": "<img src=x>", "framework": fw})
    assert zb.normalize({"framework": fw})["tier"] == "captured"


@pytest.mark.parametrize("atp", [{"crypto_mining_blocked": "false"}, {"crypto_mining_blocked": 0}, {"tor_blocked": None}, {"nope": True}, ["x"]])
def test_atp_choices_must_be_booleans(atp):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: an ATP choice is a JSON boolean; the string "false" is refused, never read as on."""
    with pytest.raises(ao.OperationError, match="true or false"):
        zb.normalize({"tier": "strict", "atp": atp})


def test_a_tier_that_turns_off_a_block_the_tenant_has_says_so():
    """ASVS V1.4.1 · CWE-1188 · CWE-693: applying Permissive's ATP to a tenant that blocks SSH tunnelling warns that it lowers protection."""
    p = zb_plan(zt.Tenant(), {"tier": "permissive", "areas": ["atp"]})
    assert any("turns off what this tenant blocks today" in w and "SSH tunnelling" in w for w in p["warnings"])
    assert not any("turns off" in w for w in zb_plan(zt.Tenant(), {"tier": "strict", "areas": ["atp"]})["warnings"])


def test_the_atp_write_keeps_settings_the_sdk_model_does_not_know():
    """ASVS V1.4.1 · CWE-1188 · CWE-665: the ATP PUT carries every field the tenant sent (also one outside the SDK model), so no setting is reset."""
    # Arrange
    t = zt.Tenant()
    atp = t.zia.atp_policy
    raw = dict({at._camel(k): v for k, v in atp.settings.items()}, futureSettingBlocked=True)
    atp.get_atp_settings = lambda: (copy.deepcopy(atp.settings), at.Resp(raw), None)
    # Act
    res = zb_apply(t, {"tier": "strict", "areas": ["atp"]})
    # Assert
    assert res["status"] == "applied" and atp.settings.get("futureSettingBlocked") is True and atp.settings["crypto_mining_blocked"] is True


@pytest.mark.parametrize("step,why", [
    ({"op": "restore", "area": "url", "id": 11, "name": "x", "fields": [1]}, "fields must be an object"),
    ({"op": "restore", "area": "url", "id": 11, "name": "x", "fields": {"action": "ALLOW"}, "expect": "BLOCK"}, "expect must be an object"),
    ({"op": "restore", "area": "url", "id": 11, "name": "x", "fields": {"name": "Hijacked"}}, "only the fields a baseline sets"),
    ({"op": "restore", "area": "url", "id": 11, "name": "x", "fields": {"__class__": 1}}, "only the fields a baseline sets"),
    ({"op": "restore_atp", "fields": {"risk_tolerance": 0}}, "not an Advanced Threat Protection setting"),
    ({"op": "delete", "area": "url", "id": {"$ne": 1}, "name": "x"}, "id and name"),
    ({"op": "delete", "area": "url", "id": "11\n", "name": "x"}, "id and name"),
    ({"op": "create", "area": "url"}, "delete, restore or restore_atp"),
])
def test_an_undo_step_of_the_wrong_shape_is_refused_before_anything_is_read(step, why):
    """ASVS V5.1.3 · V4.2.1 · CWE-20 · CWE-915 · CWE-755: a crafted Undo step is refused in plain words before any read; it cannot rename a rule or set an unknown ATP field."""
    t = zt.Tenant()
    with pytest.raises(ao.OperationError, match=why):
        zb_plan(t, {"action": "revert", "steps": [step]})
    assert t.reads == [] and t.writes == []


def test_duplicate_certificate_moves_are_one_write():
    """ASVS V5.1.3 · V11.1.1 · CWE-694 · CWE-837: the same rule picked twice is moved once (one unit, one write)."""
    t = zt.Tenant()
    p = zb_plan(t, {"type": zb.CERT_TYPE, "rules": [3, 3, "3"], "certificate": 52})
    assert [u["key"] for u in p["items"]] == ["cert:3"] and len(p["groups"]) == 1
    zb_apply(t, {"type": zb.CERT_TYPE, "rules": [3, 3, "3"], "certificate": 52}, prepared=p)
    assert [w for w in t.writes if w[1] == "update_rule"] == [("ssl_inspection_rules", "update_rule", "Inspect Finance")]


@pytest.mark.parametrize("moves,why", [
    ([{"id": 3, "certificate": 52}, {"id": 3, "certificate": 51}], "two different certificates"),
    ([{"id": {"x": 1}, "certificate": 52}], "names a rule id"), ([{"id": 3, "certificate": ["52"]}], "names a rule id"),
    ([{"id": True, "certificate": 52}], "names a rule id"), ([{"id": "3\n", "certificate": 52}], "names a rule id"),
    ([{"id": 3, "certificate": "x" * 65}], "names a rule id"),
])
def test_certificate_moves_are_checked(moves, why):
    """ASVS V5.1.3 · CWE-20: each move names a short rule id and certificate id; conflicting duplicates are refused before anything is read."""
    t = zt.Tenant()
    with pytest.raises(ao.OperationError, match=why):
        zb_plan(t, {"type": zb.CERT_TYPE, "moves": moves})
    assert t.reads == []


def test_the_certificate_move_to_default_and_its_undo():
    """ASVS V1.4.1 · CWE-841: moving to the tenant's default certificate clears the override, and Undo moves it back."""
    t = zt.Tenant()
    res = zb_apply(t, {"type": zb.CERT_TYPE, "rules": [4], "certificate": "default"})
    rule = next(r for r in rows_of(t, "ssl") if r["id"] == 4)
    assert res["status"] == "applied" and rule["action"]["override_default_certificate"] is False and "ssl_interception_cert" not in rule["action"]
    back = zb_apply(t, res["inverse"])
    assert back["status"] == "applied" and next(r for r in rows_of(t, "ssl") if r["id"] == 4)["action"]["ssl_interception_cert"]["id"] == 51


# ===========================================================================
# ZIA baseline: payloads against zscaler-sdk-python 1.11.3
# ===========================================================================

def _sdk_fields(module, cls):
    import importlib
    import inspect
    src = inspect.getsource(getattr(importlib.import_module(f"zscaler.zia.models.{module}"), cls))
    return set(re.findall(r'config\["(\w+)"\]', src)) | set(re.findall(r'"(\w+)": self\.', src))


SDK_MODELS = {"url": ("url_filtering_rules", "URLFilteringRule"), "firewall": ("cloud_firewall_rules", "FirewallRule"),
              "ssl": ("ssl_inspection_rules", "SSLInspectionRules"), "sandbox": ("sandboxrules", "SandboxRules"),
              "dns": ("cloud_firewall_dns_rules", "FirewallDNSRules"), "ftc": ("filetyperules", "FileTypeControlRules"),
              "cac": ("cloudappcontrol", "CloudApplicationControl")}


@pytest.mark.parametrize("area", list(SDK_MODELS))
def test_every_baseline_payload_field_is_in_the_sdk_model(area):
    """SSDF PW.4.1 · ASVS V1.14.6 · CWE-1104: every top-level field a baseline rule sends is a field of the SDK 1.11.3 model for that rule type (camelCased as the SDK sends it)."""
    pytest.importorskip("zscaler")
    from zscaler.helpers import to_lower_camel_case
    try:
        known = _sdk_fields(*SDK_MODELS[area])
    except (ImportError, AttributeError) as e:   # a renamed model is a finding, not a skip
        pytest.fail(f"SDK model for {area} not found: {e}")
    facts = {"isolation_profile": {"id": "p1", "name": "P", "url": "u"}, "trusted_resolver": {"id": 9, "name": "ZTR"},
             "certificate": {"id": 52, "name": "New CA"}}
    for tier in zb.TIERS:
        for r in zb.review({"tier": tier, "mode": "block_all"})["rules"] + zb.review({"tier": tier})["rules"]:
            if r["area"] != area:
                continue
            body = zb.payload(r, facts, "Strict", False)
            missing = {k for k in body if to_lower_camel_case(k) not in known}
            assert not missing, (r["key"], missing)


def test_the_atp_switches_are_fields_of_the_sdk_model():
    """SSDF PW.4.1 · CWE-1104: each of the 20 ATP switches is a field of the SDK 1.11.3 AdvancedThreatProtectionSettings model (its own spelling)."""
    pytest.importorskip("zscaler")
    from zscaler.helpers import to_lower_camel_case
    import inspect
    import zscaler.zia.models.advanced_threat_settings as m
    src = inspect.getsource(m)
    assert all(f'"{to_lower_camel_case(k)}"' in src for k in zb.ATP_KEYS)


def test_the_ssl_tls_fields_serialise_with_the_sdk_acronyms():
    """SSDF PW.4.1 · CWE-1104: the SSL action's min TLS fields reach ZIA as minClientTLSVersion and minServerTLSVersion through the SDK's own conversion."""
    pytest.importorskip("zscaler")
    from zscaler.helpers import convert_keys_to_camel_case
    row = next(r for r in zb.review({"tier": "strict"})["rules"] if r["key"] == "ssl.catch_all")
    wire = convert_keys_to_camel_case(zb.payload(row, {}, "Strict", False))
    sub = wire["action"]["decryptSubActions"]
    assert sub["minClientTLSVersion"] == "CLIENT_TLS_1_2" and sub["minServerTLSVersion"] == "SERVER_TLS_1_2"


# ===========================================================================
# AI Guard routing: order, QUIC, SSL placement, typed phrase
# ===========================================================================

def aig_preview(f, spec, scope=at.FULL):
    return at.preview(f, spec, scope)


def aig_apply(f, spec, scope=at.FULL, prepared=None, confirm=None):
    p = prepared or aig_preview(f, spec, scope)
    return ao.execute(f, spec, plan_hash=p["plan_hash"], scope=scope, writes_enabled=True, assessor="Jane Doe", tenant_label="acme",
                      confirm_text=p["confirm_phrase"] if confirm is None else confirm, settle_seconds=0)


def test_the_proxy_chain_is_built_in_dependency_order():
    """ASVS V1.4.1 · CWE-841 · CWE-696: certificate, then proxy, then destination group, then QUIC block and SSL Inspect, each naming what the earlier step created."""
    # Arrange
    f = at.Fake()
    spec = dict(at.ROUTE, cert={"mode": "upload", "pem": at.PEM}, allow_in_zia=False)
    # Act
    res = aig_apply(f, spec)
    # Assert
    adds = [w[0] for w in f.t.writes if w[1] == "add"]
    assert res["status"] == "applied" and adds[:5] == ["certs", "proxies", "ipgroups", "firewall", "ssl"], adds
    proxy, cert = f.stores["proxies"].rows[0], f.stores["certs"].rows[-1]
    assert proxy["cert"]["id"] == cert["id"] and f.stores["ssl"].rows[0]["destIpGroups"][0]["id"] == f.stores["groups"].rows[0]["id"]


def test_the_quic_block_is_the_predefined_service_at_the_top():
    """ASVS V1.4.1 · CWE-1188: the QUIC rule blocks the predefined QUIC service (Block/ICMP) at order 1, so browsers fall back to inspected TCP 443."""
    f = at.Fake()
    aig_apply(f, dict(at.ROUTE, ssl_inspect=False, prompt_capture=False, allow_in_zia=False))
    rule = f.stores["firewall"].rows[0]
    assert rule["name"] == "AIG-NoQUIC" and rule["action"] == "BLOCK_ICMP" and rule["order"] == 1 and rule["nwServices"] == [{"id": 41}]


@pytest.mark.parametrize("change", ["no_service", "off"])
def test_no_quic_service_or_quic_off_plans_no_quic_rule(change):
    """ASVS V1.4.1 · CWE-1188: without the predefined QUIC service the rule is excluded with the reason; block_quic false plans none."""
    f = at.Fake()
    if change == "no_service":
        f.zia.cloud_firewall.list_network_services = lambda query_params=None: at.ok([{"id": 42, "name": "HTTPS"}])
    k = at.by_key(aig_preview(f, dict(at.ROUTE, block_quic=change != "off")))
    assert (k["quic"]["status"] == "excluded" and "QUIC network service" in k["quic"]["reason"]) if change == "no_service" else "quic" not in k


@pytest.mark.parametrize("dni_order,dni_state,want", [(2, "ENABLED", "change"), (9, "ENABLED", "noop"), (2, "DISABLED", "noop")])
def test_ssl_inspect_is_kept_above_every_enabled_do_not_decrypt_rule(dni_order, dni_state, want):
    """ASVS V1.4.1 · CWE-1188 · CWE-693: an existing AI Guard Inspect rule below an enabled Do Not Decrypt bypass is moved to order 1; above it, or below a disabled one, it is left."""
    # Arrange
    f = at.Fake(proxy=True, gateway=True)
    aig_apply(f, at.ROUTE)
    ssl = next(r for r in f.stores["ssl"].rows if r["name"] == "AIG-Inspect")
    ssl["order"] = 5
    f.stores["ssl"].rows.append({"id": 77, "name": "Bypass Banking", "order": dni_order, "state": dni_state, "action": {"type": "DO_NOT_DECRYPT"}})
    # Act
    k = at.by_key(aig_preview(f, at.ROUTE))
    # Assert
    assert k["ssl"]["status"] == want
    if want == "change":
        res = aig_apply(f, at.ROUTE)
        assert next(r for r in f.stores["ssl"].rows if r["name"] == "AIG-Inspect")["order"] == 1 and res["status"] in ("applied", "partial")


def test_the_allow_rule_goes_above_a_block_and_is_not_added_without_one():
    """ASVS V1.4.1 · CWE-1188 · CWE-863: the Cloud App Control Allow is created at order 1 only when a Block, Caution or Isolate rule would stop the apps."""
    blocker = {"id": 5, "name": "Block AI", "type": "AI_ML", "order": 1, "state": "ENABLED", "actions": ["DENY_AI_ML_WEB_USE"]}
    k = at.by_key(aig_preview(at.Fake(proxy=True, gateway=True, cac_rules=[blocker]), at.ROUTE))
    assert k["allow"]["status"] == "change" and "order 1" in k["allow"]["after"]
    k2 = at.by_key(aig_preview(at.Fake(proxy=True, gateway=True, cac_rules=[dict(blocker, state="DISABLED")]), at.ROUTE))
    assert k2["allow"]["status"] == "noop"


def test_routing_asks_for_the_typed_phrase_whatever_the_count():
    """ASVS V11.1.1 · V1.4.1 · CWE-841 · CWE-1188: the routing creates live (enabled) rules, so even a two-change plan needs the typed phrase, and a wrong one writes nothing."""
    # Arrange
    f = at.Fake(proxy=True, gateway=True)
    spec = dict(at.ROUTE, ssl_inspect=False, prompt_capture=False, allow_in_zia=False, block_quic=False)
    p = aig_preview(f, spec)
    # Act
    res = aig_apply(f, spec, prepared=p, confirm="")
    # Assert
    assert p["counts"]["change"] == 2 and p["confirm_phrase"] == "APPLY 2 CHANGES"
    assert res["status"] == "refused" and f.t.writes == []
    assert aig_apply(f, spec, prepared=p, confirm="apply 2 changes")["status"] == "applied"


def test_a_detection_policy_asks_for_the_typed_phrase_and_nothing_to_do_asks_none():
    """ASVS V11.1.1 · CWE-841: an AI Guard policy is live as soon as it is saved, so its plan asks for the phrase; a plan with no change asks for none."""
    f = at.Fake()
    p = aig_preview(f, at.POLICY, at.AIG_ONLY)
    assert p["confirm_phrase"] == "APPLY 2 CHANGES"
    aig_apply(f, at.POLICY, at.AIG_ONLY, prepared=p)
    assert aig_preview(f, at.POLICY, at.AIG_ONLY)["confirm_phrase"] == ""


@pytest.mark.parametrize("name", ["Corp-AIG-Thing", "AIG-Something", "ACME-AIG-Proxy-2", "../AIG-Proxy", "AIG-Proxy ", "TOOLONGPREFIX1-AIG-Proxy"])
def test_an_undo_cannot_touch_an_object_this_builder_did_not_name(name):
    """ASVS V4.2.1 · V5.1.3 · CWE-639 · CWE-863: an Undo deletes or puts back only names the builder gives (an optional prefix, AIG- and a known suffix), not any name containing AIG-."""
    with pytest.raises(ao.OperationError, match="only objects this builder named"):
        aig_preview(at.Fake(proxy=True), {"type": oa.ROUTING, "action": "undo", "steps": [{"kind": "zia_proxy", "op": "delete", "id": 21, "name": name}]})


@pytest.mark.parametrize("prefix", ["", "ACME", "A_B-C", "AIG-X", "ABCDEFGHIJKL"])
def test_every_builder_name_is_recognised_and_fits_31_characters(prefix):
    """ASVS V5.1.3 · CWE-20: every name the routing and policy builders give, for any valid prefix, is at most 31 characters, unique and recognised as theirs."""
    ns = oa.names(prefix)
    assert len(set(ns.values())) == len(ns) and all(len(n) <= 31 and oa.is_builder_name(n) for n in ns.values())


def test_an_undo_update_of_an_object_renamed_since_is_kept():
    """ASVS V4.2.1 · CWE-639 · CWE-367: an Undo update is planned only on an object still carrying the builder's name."""
    f = at.Fake()
    f.stores["firewall"].rows.append({"id": 61, "name": "Customer Allow All", "state": "ENABLED", "action": "ALLOW"})
    step = {"kind": "firewall_rule", "op": "update", "id": 61, "name": "AIG-NoQUIC", "set": {"state": "DISABLED"}, "expect": {"state": "ENABLED"}}
    k = at.by_key(aig_preview(f, {"type": oa.ROUTING, "action": "undo", "steps": [step]}))
    assert k["u0"]["status"] == "excluded" and "renamed" in k["u0"]["reason"]


def test_an_object_renamed_between_preview_and_apply_is_a_conflict():
    """ASVS V11.1.1 · CWE-367: the write re-reads the object; one renamed since the preview is a conflict and is not written."""
    f = at.Fake(proxy=True, gateway=True)
    aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False))
    grp = f.stores["groups"].rows[0]
    grp["addresses"] = [".old.example"]
    spec = dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False)
    p = aig_preview(f, spec)
    real_get = f.stores["groups"].get

    def renamed_just_before_the_write(oid):   # an admin renames it after the re-plan, before the write
        grp["name"] = "Renamed by admin"
        return real_get(oid)
    f.zia.cloud_firewall.get_ip_destination_group = renamed_just_before_the_write
    res = aig_apply(f, spec, prepared=p)
    assert at.by_key(res)["group"]["status"] == "conflict" and grp["addresses"] == [".old.example"]


@pytest.mark.parametrize("bad", [{"cert": {"mode": "existing", "id": "11\n"}}, {"cert": {"mode": "existing", "id": True}}])
def test_a_certificate_id_with_a_trailing_newline_is_refused(bad):
    """ASVS V5.1.3 · CWE-93 · CWE-20: an id is matched in full (a regex `$` would accept a trailing newline that ends up in a request path)."""
    with pytest.raises(ao.OperationError, match="root certificate"):
        aig_preview(at.Fake(), dict(at.ROUTE, **bad))


def test_an_undo_step_id_with_a_trailing_newline_is_refused():
    """ASVS V5.1.3 · CWE-93: an Undo step's id is matched in full before it reaches an SDK path."""
    with pytest.raises(ao.OperationError, match="id and name"):
        aig_preview(at.Fake(), {"type": oa.ROUTING, "action": "undo", "steps": [{"kind": "zia_proxy", "op": "delete", "id": "21\n", "name": "AIG-Proxy"}]})


def test_prompt_capture_settings_cannot_be_deleted_by_an_undo():
    """ASVS V4.2.1 · CWE-863: the GenAI settings object can only be put back, never deleted."""
    with pytest.raises(ao.OperationError, match="does not change"):
        aig_preview(at.Fake(), {"type": oa.ROUTING, "action": "undo", "steps": [{"kind": "url_app_settings", "op": "delete", "id": "settings",
                                                                                   "name": "GenAI prompt capture"}]})


def test_stop_while_listing_the_routing_objects_is_a_stop_not_a_failure():
    """ASVS V7.4.1 · CWE-755: Stop during the routing page's read is raised as the engine's Stop (the job ends stopped, not failed)."""
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ao.Stopped):
        ao.read_objects(at.Fake(), "aiguard_routing_setup", at.FULL, cancel=cancel)


# ===========================================================================
# AI Guard detection policy: every profile and mode
# ===========================================================================

@pytest.mark.parametrize("profile", sorted(ag.PROFILES))
def test_every_profile_names_only_known_entities_without_overlap(profile):
    """ASVS V5.1.3 · CWE-1188: a profile's block and detect identifiers are known PII entity types and never both (a typo would silently disable one)."""
    p = ag.PROFILES[profile]
    assert set(p["block"]) <= set(ag.PII_ENTITIES) and set(p["detect"]) <= set(ag.PII_ENTITIES) and not set(p["block"]) & set(p["detect"])


@pytest.mark.parametrize("profile,mode", list(itertools.product(sorted(ag.PROFILES), ag.MODES)))
def test_each_profile_and_mode_builds_the_documented_detection_policy(profile, mode):
    """ASVS V1.4.1 · CWE-1188 · WSTG-BUSL-01: an oracle per profile and mode: block identifiers BLOCK only in Block mode, detect ones DETECT, others DISABLE; the attacks block only in Block mode; deep scan only where the profile says."""
    # Arrange
    p = ag.PROFILES[profile]
    # Act
    body = oa.build_policy("AIG-Policy", profile, mode)
    # Assert
    for side in ("inputDetectorPolicies", "outputDetectorPolicies"):
        dets = {d["detector"]: d for d in body[side]}
        ents = {e["entityType"]: e["action"] for e in dets["pii"]["configuration"]["entities"]}
        assert set(ents) == set(ag.PII_ENTITIES)
        for e, a in ents.items():
            want = ("BLOCK" if mode == "block" else "DETECT") if e in p["block"] else ("DETECT" if e in p["detect"] else "DISABLE")
            assert a == want, (side, e)
        assert ("pii_deepscan" in dets) is p["deep"]
        assert dets["malicious_url"]["configuration"]["action"] == ("BLOCK" if mode == "block" else "DETECT")
        assert dets["toxicity"]["configuration"]["action"] == "DETECT"
    inp = {d["detector"]: d for d in body["inputDetectorPolicies"]}
    assert inp["prompt_injection"]["configuration"]["action"] == ("BLOCK" if mode == "block" else "DETECT")
    if mode == "monitor":
        assert "'BLOCK'" not in str(body)
    assert body["description"].endswith(("Block mode.", "Monitor mode."))


def test_monitor_is_the_default_mode():
    """ASVS V1.4.1 · CWE-1188: a policy spec without a mode is built in Monitor mode (detect only)."""
    f = at.Fake()
    aig_apply(f, at.POLICY, at.AIG_ONLY)
    pol = f.stores["aig_policies"].rows[0]
    assert "BLOCK" not in json.dumps(pol) and pol["description"].endswith("Monitor mode. By Jane Doe.")


@pytest.mark.parametrize("mode", ["Monitor", " BLOCK ", "block"])
def test_the_mode_is_read_without_case(mode):
    """ASVS V5.1.3 · CWE-20: the mode is matched without case or surrounding spaces."""
    p = aig_preview(at.Fake(), dict(at.POLICY, mode=mode), at.AIG_ONLY)
    assert p["status"] == "ready"


def test_the_policy_and_match_rule_payloads_carry_the_sdk_fields():
    """SSDF PW.4.1 · CWE-1104: the policy (name, description, input and output detectors) and the match rule (policyId, name, enabled, ruleOrder, matchCriteria) carry the AI Guard model's fields; llmProviders is listed as assumed."""
    pytest.importorskip("zscaler")
    import inspect
    import zscaler.aiguard.models.policies as pm
    import zscaler.aiguard.models.policy_match_rules as rm
    psrc, rsrc = inspect.getsource(pm), inspect.getsource(rm)
    body = oa.build_policy("AIG-Policy", "HIPAA", "block")
    assert all(f'"{k}"' in psrc for k in body)
    for d in body["inputDetectorPolicies"]:
        assert all(f'"{k}"' in psrc for k in d) and all(f'"{k}"' in psrc for k in d["configuration"])
    assert all(f'"{k}"' in rsrc for k in ("policyId", "name", "enabled", "ruleOrder", "matchCriteria", "type", "llmApplications"))
    assert '"llmProviders"' not in rsrc and any("llmProviders" in a for a in ag.ASSUMED)


# ===========================================================================
# AI Guard readiness
# ===========================================================================

@pytest.mark.parametrize("broken", ["proxies", "gateways", "forwarding"])
def test_readiness_is_not_ready_on_what_it_could_not_read(broken):
    """ASVS V1.4.1 · V7.4.1 · CWE-636 · CWE-754: a proxy, gateway or forwarding list that could not be read is a warning and readiness is not ready (fail closed)."""
    # Arrange
    f = at.Fake(proxy=True, gateway=True)
    aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False, block_quic=False))
    assert ag.readiness(f)["ready"] is True
    deny = lambda *a, **k: at.refused("Forbidden", 403)  # noqa: E731
    if broken == "proxies":
        f.zia.proxies.list_proxies = deny
    elif broken == "gateways":
        f.zia.proxies.list_proxy_gateways = deny
    else:
        f.zia.forwarding_control.list_rules = deny
    # Act
    rd = ag.readiness(f)
    # Assert
    st = {c["id"]: c["status"] for c in rd["checks"]}
    assert rd["ready"] is False and "warn" in (st.get("zia.proxy"), st.get("zia.gateway"), st.get("zia.forwarding"))


def test_readiness_never_writes_and_never_carries_a_secret():
    """ASVS V8.3.4 · CWE-200 · CWE-532: readiness reads only and its answer holds no certificate body, key or token."""
    f = at.Fake(proxy=True, gateway=True)
    f.stores["certs"].rows[0].update(pem=at.PEM, private_key="SECRET-KEY-CANARY")
    f.t.frozen = True
    rd = ag.readiness(f)
    text = json.dumps(rd)
    assert "SECRET-KEY-CANARY" not in text and "BEGIN CERTIFICATE" not in text and f.t.writes == []


def test_readiness_stops_when_asked():
    """ASVS V7.4.1 · CWE-400: readiness checks Stop before each read and reads nothing after it."""
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(ag.Stopped):
        ag.readiness(at.Fake(), cancel=cancel)


@pytest.mark.parametrize("subs,want", [([{"id": "ZS_DP_GEN_AI", "status": "ACTIVE"}], True), ([{"id": "ZS_DP_GEN_AI", "status": "EXPIRED"}], False),
                                       ([{"sku": "GENAI_SEC", "subscribed": True}], True), ([{"id": "ZS_DP_GEN_AI", "subscribed": False}], False),
                                       ([], False), ({"list": [{"id": "ZS_DP_GEN_AI"}]}, True)])
def test_the_gen_ai_subscription_oracle(subs, want):
    """ASVS V1.4.1 · CWE-1188: the Gen AI Security subscription is recognised by id or SKU, and an expired, cancelled or unsubscribed one does not count."""
    z = at.Svc(organization_information=at.Svc(get_subscriptions=lambda: (None, at.Resp(subs), None)))
    assert ag.read_subscriptions(z)[0] is want


@pytest.mark.parametrize("host,ok", [("forward.prod.zsaiguard.net", True), ("forward.zseclipse.net", True), ("FORWARD.PROD.ZSAIGUARD.NET", True),
                                     ("forward.zsaiguard.net.evil.com", False), ("evil.com/forward.zsaiguard.net", False),
                                     ("forward.zsaiguard.net\n", False), ("forward..zsaiguard.net", False), ("x" * 5000 + ".zsaiguard.net", False)])
def test_the_ai_guard_forwarder_allow_list(host, ok):
    """ASVS V5.1.3 · V12.6.1 · CWE-918 · CWE-1333: the proxy address is one of Zscaler's AI Guard forwarders; any other host (also a look-alike or a long one) is refused."""
    assert bool(ag.AIG_HOST.fullmatch(host)) is ok


# ===========================================================================
# Error paths and branches: plain-language errors, never a traceback
# ===========================================================================

@pytest.mark.parametrize("spec,why", [
    ([], "must be an object"), ({"overlays": "HIPAA"}, "must be a list"), ({"overlays": ["SOC9"]}, "Unknown compliance overlay"),
    ({"areas": ["email"]}, "Unknown area"), ({"prefix": "has space"}, "name prefix"), ({"prefix": "ABCDEFGHIJK"}, "name prefix"),
    ({"mode": "deny_all"}, "mode is tier"), ({"rules": ["url.legal"]}, "per-rule choices"), ({"rules": {"url.legal": "BLOCK"}}, "must be an object"),
    ({"rules": {"url.legal": {"action": "DELETE"}}}, "TIER, ALLOW, BLOCK or ISOLATE"), ({"action": "revert", "steps": []}, "steps to reverse"),
    ({"action": "revert", "steps": [{}] * 601}, "steps to reverse"),
])
def test_a_baseline_spec_that_cannot_be_built_is_refused_in_plain_words(spec, why):
    """ASVS V5.1.3 · V7.4.1 · CWE-20 · CWE-209 · WSTG-INPV-01: every malformed baseline spec is refused with a plain sentence (boundary: an 11-character prefix, 601 undo steps)."""
    with pytest.raises(ao.OperationError, match=why):
        zb.normalize(spec)


def test_an_undo_has_no_review():
    """ASVS V5.1.3 · CWE-20: asking for the review of an undo is refused in plain words."""
    with pytest.raises(ao.OperationError, match="no review"):
        zb.review({"action": "revert", "steps": [{"op": "delete", "area": "url", "id": 1, "name": "x"}]})


def test_the_catalog_lists_every_tier_overlay_area_rule_and_atp_switch():
    """ASVS V1.4.1 · CWE-1059: the form's catalog lists the four tiers, nine overlays, eight areas (ATP not ticked by default), every rule and 20 ATP switches."""
    c = zb.catalog()
    assert [t["key"] for t in c["tiers"]] == list(zb.TIERS) and len(c["overlays"]) == len(zb.OVERLAYS) == 9
    assert {a["key"]: a["default"] for a in c["areas"]}["atp"] is False and len(c["rules"]) == len(zb.CATALOG) and len(c["atp"]) == 20
    assert c["max_name"] == 31 and all(r["choices"] == [] for r in c["rules"] if r["locked"] or r["action_locked"])


def test_canon_and_show_compare_and_print_values_safely():
    """ASVS V5.1.3 · CWE-1023: comparisons treat references by id, empties as equal and lists as sets; the preview shows short values."""
    assert zb.same([{"id": 1, "name": "a"}], [{"id": 1}]) and zb.same(None, []) and zb.same(False, "") and zb.same({"x": None}, None)
    assert zb.same(["b", "a"], ("a", "b")) and zb.same(3, "3") and not zb.same(True, "true")
    assert zb._show({"name": "CA"}) == "CA" and zb._show({"k": "v"}) == '{"k": "v"}' and zb._show(["x" * 100, "y" * 100]).endswith("…")
    body = {}
    zb._set_path(body, "a.b", 1)
    zb._set_path(body, "a.c", None)
    assert body == {"a": {"b": 1}}


class _Model:
    def __init__(self, d):
        self.d = d

    def as_dict(self):
        return self.d


def test_sdk_model_rows_are_read_as_snake_case():
    """ASVS V5.1.3 · CWE-20: an SDK model row (as_dict, camelCase, acronyms) is read with snake_case keys."""
    assert zb._deep_snake([_Model({"minClientTLSVersion": "X", "subActions": {"ocspCheck": True}})]) == \
        [{"min_client_tls_version": "X", "sub_actions": {"ocsp_check": True}}]


def _raising(*a, **k):
    raise RuntimeError("tenant said no")


def test_reads_that_fail_report_the_reason_and_never_raise():
    """ASVS V7.4.1 · CWE-755 · CWE-209: a failing SDK read becomes a short error string (type and message), never an exception."""
    t = zt.Tenant()
    t.zia.sandbox_rules.list_rules = _raising
    t.zia.sandbox_rules.get_rule = _raising
    t.zia.atp_policy.get_atp_settings = _raising
    t.zia.intermediate_certificates.list_ready_to_use = _raising
    assert zb.read_area(t.zia, "sandbox") == ([], "RuntimeError: tenant said no")
    assert zb.get_one(t.zia, "sandbox", 1) == (None, "RuntimeError: tenant said no")
    assert zb.read_atp(t.zia) == (None, "RuntimeError: tenant said no")
    assert zb.read_certificates(t.zia)[1] == "RuntimeError: tenant said no"
    del t.zia.cloud_browser_isolation, t.zia.intermediate_certificates
    assert "no cloud_browser_isolation" in zb.read_isolation_profiles(t.zia)[1] and "no intermediate_certificates" in zb.read_certificates(t.zia)[1]
    del t.zia.cloud_firewall_dns
    with pytest.raises(ao.OperationError, match="no cloud_firewall_dns service"):
        zb.read_area(t.zia, "dns")


def test_unreadable_lists_drop_the_rules_that_need_them_fail_closed():
    """ASVS V1.4.1 · CWE-636 · CWE-754: when URL categories, network apps, cloud apps or DNS gateways cannot be read, the rules that need them are dropped, never widened."""
    t = zt.Tenant()
    for svc, m in (("url_categories", "list_categories_lite"), ("cloud_firewall", "list_network_apps"),
                   ("cloud_applications", "list_cloud_app_policy"), ("dns_gatways", "list_dns_gateways")):
        setattr(getattr(t.zia, svc), m, _raising)
    p = zb_plan(t, {"tier": "strict"})
    excl = {u["object"]["name"]: u["reason"] for u in p["items"] if u["status"] == "excluded"}
    assert "could not be checked" in excl["BL-URL-Legal-Liability"] and "could not be checked" in excl["BL-FW-Block-QUIC"]
    assert "could not be checked" in excl["BL-CAC-FileShare-ViewOnly"] and "DNS gateways could not be read" in excl["BL-DNS-Trusted-Resolver"]
    assert "BL-FW-Default-Deny" not in excl and "BL-CAC-FileShare" not in excl


def test_no_isolation_profile_turns_isolate_into_caution_and_quarantine_isolate_into_quarantine():
    """ASVS V1.4.1 · CWE-1188: without a Cloud Browser Isolation profile, Isolate becomes a Caution page and Quarantine-and-isolate becomes Quarantine, with a warning."""
    t = zt.Tenant(profiles=False)
    p = zb_plan(t, {"tier": "strict", "areas": ["url", "sandbox"], "isolation_profile": "Named"})
    g = {x["target"]["name"]: x["target"]["payload"] for x in p["groups"]}
    assert g["BL-URL-Misc-Unknown"]["action"] == "CAUTION" and g["BL-SB-Office-PDF"]["first_time_operation"] == "QUARANTINE"
    assert sum("Caution page instead of isolating" in w or "quarantined without isolation" in w for w in p["warnings"]) == 2


def test_a_named_isolation_profile_and_certificate_the_tenant_lacks_fall_back_with_a_warning():
    """ASVS V1.4.1 · CWE-1188: an isolation profile or certificate not in the tenant is replaced by the tenant's default, and the plan says so."""
    p = zb_plan(zt.Tenant(), {"tier": "strict", "areas": ["url", "ssl"], "isolation_profile": "Nope", "certificate": "Nope CA"})
    assert any("isolation profile 'Nope'" in w for w in p["warnings"]) and any("certificate 'Nope CA'" in w for w in p["warnings"])
    g = {x["target"]["name"]: x["target"]["payload"] for x in p["groups"]}
    assert g["BL-URL-Misc-Unknown"]["cbi_profile"]["id"] == "p1" and "ssl_interception_cert" not in g["BL-SSL-Catch-All"]["action"]


def test_a_named_certificate_is_used_by_the_inspect_rules():
    """ASVS V1.4.1 · CWE-295: a ready-to-use certificate named in the baseline is set on its Inspect rules (override on)."""
    p = zb_plan(zt.Tenant(), {"tier": "strict", "areas": ["ssl"], "certificate": "New CA 2026"})
    act = next(x for x in p["groups"] if x["target"]["name"] == "BL-SSL-Catch-All")["target"]["payload"]["action"]
    assert act["override_default_certificate"] is True and act["ssl_interception_cert"] == {"id": 52, "name": "New CA 2026"}


def test_cloud_apps_are_read_page_by_page_until_a_short_page():
    """ASVS V1.4.1 · CWE-400: the cloud application list is read in pages of 1000 and stops at the first short page (at most 20)."""
    t = zt.Tenant()
    pages = []

    def page(query_params=None):
        pages.append(query_params["page"])
        n = 1000 if query_params["page"] < 3 else 5
        return [{"app": "GDRIVE" if i == 0 else f"APP{i}"} for i in range(n)], None, None
    t.zia.cloud_applications.list_cloud_app_policy = page
    zb_plan(t, {"tier": "strict", "areas": ["cac"]})
    assert pages == [1, 2, 3]


def test_an_area_whose_rules_cannot_be_read_plans_nothing_there():
    """ASVS V1.4.1 · CWE-754: an area whose rules cannot be read is excluded rule by rule with the reason; the other areas are planned."""
    t = zt.Tenant()
    t.zia.file_type_control_rule.list_rules = lambda *a, **k: (None, None, {"status": 500, "message": "boom"})
    p = zb_plan(t, {"tier": "strict", "areas": ["ftc", "sandbox"]})
    assert {u["status"] for u in p["items"] if u["object"]["area"] == "ftc"} == {"excluded"}
    assert any(u["status"] == "change" for u in p["items"] if u["object"]["area"] == "sandbox") and any("File Type Control" in w for w in p["warnings"])


def test_a_predefined_rule_with_a_baseline_name_is_left_alone():
    """ASVS V4.2.1 · CWE-284: a read-only (predefined) rule that happens to carry a baseline name is excluded, never overwritten."""
    t = zt.Tenant(url=[{"id": 40, "name": "BL-URL-Legal-Liability", "order": 1, "predefined": True, "action": "ALLOW"}, zt.URL_DEFAULT])
    item = next(u for u in zb_plan(t, {"tier": "strict", "areas": ["url"]})["items"] if u["object"]["name"] == "BL-URL-Legal-Liability")
    assert item["status"] == "excluded" and "exists but is" in item["reason"]


def test_unreadable_atp_settings_plan_nothing():
    """ASVS V7.4.1 · CWE-754: ATP settings that cannot be read are excluded with the reason, never guessed."""
    t = zt.Tenant()
    t.zia.atp_policy.get_atp_settings = lambda: (None, None, {"status": 403, "message": "Forbidden"})
    p = zb_plan(t, {"tier": "strict", "areas": ["atp"]})
    assert p["status"] == "nothing_to_do" and any("Advanced Threat Protection: the settings could not be read" in w for w in p["warnings"])


def test_handlers_skip_what_changed_or_appeared_since_the_preview():
    """ASVS V11.1.1 · CWE-367: a rule created by someone else with a baseline name, or a field changed since the preview, is a conflict and not written."""
    # Arrange
    t = zt.Tenant()
    zb_apply(t, {"tier": "strict", "areas": ["url"]})
    p = zb_plan(t, {"tier": "balanced", "areas": ["url", "ftc"]})
    bw = next(r for r in rows_of(t, "url") if r["name"] == "BL-URL-Bandwidth-Loss")
    real_get, real_list = t.zia.url_filtering.get_rule, t.zia.file_type_control_rule.list_rules
    state = {"n": 0}

    def get_after_change(rid):   # someone edits the rule after the re-plan, before the write
        bw["action"] = "ALLOW"
        return real_get(rid)

    def list_after_create(*a, **k):   # ... and creates a rule with a baseline name
        state["n"] += 1
        if state["n"] == 2:
            t.zia.file_type_control_rule.rows.append({"id": 5000, "name": "BL-FTC-DB-Upload", "order": 1, "filtering_action": "ALLOW"})
        return real_list(*a, **k)
    t.zia.url_filtering.get_rule = get_after_change
    t.zia.file_type_control_rule.list_rules = list_after_create
    # Act
    res = zb_apply(t, {"tier": "balanced", "areas": ["url", "ftc"]}, prepared=p)
    # Assert
    st = {(u["object"]["name"], u["field"]): u["status"] for u in res["items"]}
    assert st[("BL-URL-Bandwidth-Loss", "action")] == "conflict" and bw["action"] == "ALLOW"
    assert st[("BL-FTC-DB-Upload", "rule")] == "conflict"


def test_undo_of_atp_and_rule_fields_respects_what_changed_since():
    """ASVS V11.1.1 · CWE-367: Undo puts back ATP switches and rule fields only while they hold what the baseline set; one changed since is left."""
    t = zt.Tenant()
    res = zb_apply(t, {"tier": "strict", "areas": ["atp"]})
    t.zia.atp_policy.settings["crypto_mining_blocked"] = False     # an admin changed it back already
    p = zb_plan(t, res["inverse"])
    item = next(u for u in p["items"] if u["field"] == "crypto_mining_blocked")
    assert item["status"] == "noop" and "already as before" in item["reason"]
    t.zia.atp_policy.get_atp_settings = lambda: (None, None, {"status": 500, "message": "down"})
    assert next(u for u in zb_plan(t, res["inverse"])["items"])["status"] == "excluded"


def test_undo_restores_order_and_skips_gone_and_unreadable_rules():
    """ASVS V11.1.1 · CWE-367 · CWE-754: Undo moves a catch-all back to its earlier order, says a deleted rule is gone, and excludes rules it cannot read."""
    t = zt.Tenant(ssl=[zt.SSL_DEFAULT, {"id": 70, "name": "BL-SSL-Catch-All", "order": 1, "state": "DISABLED", "action": {"type": "DECRYPT"}},
                       dict(zt.SSL_OWN, order=2)])
    res = zb_apply(t, {"tier": "strict", "areas": ["ssl"]})
    assert next(r for r in rows_of(t, "ssl") if r["id"] == 70)["order"] == 2
    p = zb_plan(t, res["inverse"])
    assert any(u["field"] == "order" and u["status"] == "change" for u in p["items"])
    back = zb_apply(t, res["inverse"], prepared=p)
    assert back["status"] in ("applied", "partial") and next(r for r in rows_of(t, "ssl") if r["id"] == 70)["order"] == 1
    gone = zb_plan(t, {"action": "revert", "steps": [{"op": "delete", "area": "ssl", "id": 999, "name": "BL-x"},
                                                     {"op": "restore", "area": "ssl", "id": 998, "name": "BL-y", "fields": {"state": "DISABLED"}}]})
    assert [u["status"] for u in gone["items"]] == ["noop", "excluded"]
    t.zia.ssl_inspection_rules.list_rules = lambda *a, **k: (None, None, {"status": 500, "message": "down"})
    assert zb_plan(t, {"action": "revert", "steps": [{"op": "delete", "area": "ssl", "id": 70, "name": "BL-SSL-Catch-All"}]})["items"][0]["status"] == "excluded"


def test_an_undo_needs_its_areas_in_scope():
    """ASVS V4.1.3 · CWE-863: an Undo touching an area out of scope is refused before anything is read."""
    t = zt.Tenant()
    with pytest.raises(ao.OperationError, match="not in scope|Not in scope"):
        zb_plan(t, {"action": "revert", "steps": [{"op": "delete", "area": "firewall", "id": 1, "name": "x"}]}, scope=zt.WEB_ONLY)
    assert t.reads == []


def test_read_back_reports_a_rule_that_is_not_as_written():
    """ASVS V1.4.1 · V7.1.3 · CWE-754: read-back flags a created rule whose fields differ from what was sent, and one that cannot be read."""
    t = zt.Tenant()
    real_add = t.zia.file_type_control_rule.add_rule

    def add_but_tenant_changes_it(**kw):
        row, r, e = real_add(**kw)
        t.zia.file_type_control_rule.rows[-1]["filtering_action"] = "ALLOW"
        return row, r, e
    t.zia.file_type_control_rule.add_rule = add_but_tenant_changes_it
    res = zb_apply(t, {"tier": "strict", "areas": ["ftc"]})
    assert res["verification"]["mismatched"] and res["verification"]["confirmed"] == 0


def test_the_certificate_manager_lists_rules_and_explains_each_exclusion():
    """ASVS V1.4.1 · CWE-754: the certificate move excludes a default rule, a Do Not Decrypt rule, an unknown rule and certificate, and a rule already on the target."""
    t = zt.Tenant()
    listed = ao.read_objects(t, zb.CERT_FAMILY, zt.FULL)
    assert {r["id"]: r["certificate"] for r in listed["ssl_rules"]}[4] == "Old CA" and len(listed["certificates"]) == 3
    p = zb_plan(t, {"type": zb.CERT_TYPE, "moves": [{"id": 1, "certificate": 52}, {"id": 2, "certificate": 52}, {"id": 404, "certificate": 52},
                                                     {"id": 3, "certificate": 777}, {"id": 4, "certificate": 51}]})
    st = [(u["status"], u["reason"]) for u in p["items"]]
    assert st[0][0] == "excluded" and st[1][0] == "excluded" and "no such rule" in st[2][1] and "not a ready-to-use" in st[3][1]
    assert st[4] == ("noop", "already uses it") and p["status"] == "nothing_to_do"


def test_the_certificate_move_plans_nothing_when_a_list_cannot_be_read():
    """ASVS V7.4.1 · CWE-754: unreadable certificates or rules exclude every move with the reason."""
    t = zt.Tenant()
    t.zia.intermediate_certificates.list_ready_to_use = _raising
    p = zb_plan(t, {"type": zb.CERT_TYPE, "rules": [3], "certificate": 52})
    assert p["items"][0]["status"] == "excluded" and any("could not be read" in w for w in p["warnings"])


@pytest.mark.parametrize("spec,why", [("x", "must be an object"), ({"rules": []}, "at least one"), ({"rules": [3]}, "Pick the certificate"),
                                      ({"moves": []}, "Move 1 to"), ({"moves": [{"id": 3}]}, "names a rule id")])
def test_certificate_move_specs_are_checked(spec, why):
    """ASVS V5.1.3 · CWE-20: a certificate move without rules, a certificate or of the wrong shape is refused in plain words."""
    with pytest.raises(ao.OperationError, match=why):
        zb._plan_cert(zt.Tenant(), spec, zt.FULL, lambda m: None, None)


def test_a_certificate_changed_since_the_preview_is_not_moved():
    """ASVS V11.1.1 · CWE-367: a rule whose certificate changed after the re-plan is a conflict and left as it is."""
    t = zt.Tenant()
    p = zb_plan(t, {"type": zb.CERT_TYPE, "rules": [3], "certificate": 52})
    real = t.zia.ssl_inspection_rules.get_rule

    def changed(rid):
        t.zia.ssl_inspection_rules.rows[2]["action"] = {"type": "DO_NOT_DECRYPT"}
        return real(rid)
    t.zia.ssl_inspection_rules.get_rule = changed
    res = zb_apply(t, {"type": zb.CERT_TYPE, "rules": [3], "certificate": 52}, prepared=p)
    assert res["items"][0]["status"] == "conflict"


def test_the_baseline_page_lists_profiles_and_certificates_in_scope_only():
    """ASVS V4.1.3 · CWE-272: the baseline form reads isolation profiles and certificates only for areas in scope."""
    t = zt.Tenant()
    out = ao.read_objects(t, zb.FAMILY, zt.PLATFORM_ONLY)
    assert "certificates" not in out and out["isolation_profiles"] and "ssl" not in out["in_scope"]
    t2 = zt.Tenant()
    t2.zia.cloud_browser_isolation.list_isolation_profiles = _raising
    out2 = ao.read_objects(t2, zb.FAMILY, zt.FULL)
    assert out2["errors"]["isolation_profiles"].startswith("RuntimeError") and out2["certificates"]


def test_capture_takes_each_area_action_and_skips_what_it_cannot_rebuild():
    """ASVS V1.4.1 · CWE-20: capture reads SSL, Sandbox, File Type Control and DNS actions; a redirect without a gateway, an unknown action and an all-custom rule are skipped with reasons."""
    t = zt.Tenant(url=[{"id": 1, "name": "Custom Only", "order": 1, "action": "BLOCK", "url_categories": ["CUSTOM_02"]},
                       {"id": 2, "name": "Odd", "order": 2, "action": "ALLOW_WITH_WARNINGS", "url_categories": ["GAMBLING"]}])
    t.zia.sandbox_rules.rows = [{"id": 3, "name": "SB", "order": 1, "first_time_operation": "QUARANTINE", "file_types": ["FTCATEGORY_ZIP"]}]
    t.zia.file_type_control_rule.rows = [{"id": 4, "name": "FT", "order": 1, "filtering_action": "BLOCK", "file_types": ["FTCATEGORY_ZIP"],
                                          "nw_services": [{"id": 1}]}]
    t.zia.cloud_firewall_dns.rows = [{"id": 5, "name": "Redir", "order": 1, "action": "REDIR_REQ_KEEP_SENDER", "dns_gateway": {"id": 9}},
                                     {"id": 6, "name": "Redir NoGw", "order": 2, "action": "REDIR_REQ_KEEP_SENDER"}]
    t.zia.ssl_inspection_rules.rows = [{"id": 7, "name": "TLS13", "order": 1, "action": {"type": "DECRYPT", "decrypt_sub_actions": {
        "min_client_tls_version": "CLIENT_TLS_1_3"}}}]
    fw = zb.capture(t, list(zb.CAPTURE_AREAS), tenant_label="src")["framework"]
    assert fw["areas"]["sandbox"][0]["default"] == "QUARANTINE" and fw["areas"]["ftc"][0]["default"] == "BLOCK"
    assert fw["areas"]["dns"][0]["fields"]["trusted_resolver"] is True and len(fw["areas"]["dns"]) == 1
    assert fw["areas"]["ssl"][0]["fields"]["min_tls"] == "TLS_1_3" and fw["areas"]["ssl"][0]["catch_all"] is True
    reasons = " ".join(x["reason"] for x in fw["not_exported"])
    assert "every URL category it named was custom" in reasons and "not one the baseline can apply" in reasons
    assert "redirect without a DNS gateway" in reasons and "network services" in reasons
    assert zb.load_framework(json.loads(json.dumps(fw)))["rules"]


def test_capture_stops_and_reports_an_unreadable_area():
    """ASVS V7.4.1 · CWE-754: capture stops when asked, and an area that cannot be read is listed as not exported."""
    cancel = threading.Event()
    cancel.set()
    assert zb.capture(zt.Tenant(), ["url"], cancel=cancel)["status"] == "stopped"
    t = zt.Tenant()
    t.zia.url_filtering.list_rules = lambda *a, **k: (None, None, {"status": 500, "message": "down"})
    fw = zb.capture(t, ["url"])["framework"]
    assert fw["areas"] == {} and "could not be read" in fw["not_exported"][0]["reason"]


# ===========================================================================
# AI Guard: plan branches, writes, read-back, error paths
# ===========================================================================

def test_routing_reuses_an_ai_guard_proxy_with_the_chosen_certificate():
    """ASVS V1.4.1 · CWE-841: an AI Guard proxy already in ZIA is reused (no upload, no new proxy), and a gateway with Fail Close off is warned about."""
    f = at.Fake(proxy=True, gateway=True)
    f.stores["gateways"].rows[0]["failClosed"] = False
    k = at.by_key(aig_preview(f, dict(at.ROUTE, cert={"mode": "upload", "pem": at.PEM})))
    p = aig_preview(f, at.ROUTE)
    assert k["cert"]["status"] == "noop" and "carries its certificate" in k["cert"]["reason"] and k["proxy"]["status"] == "noop"
    assert any("Fail Close off" in w for w in p["warnings"])


def test_routing_is_blocked_by_a_customer_proxy_with_its_name_or_a_gone_certificate():
    """ASVS V1.4.1 · CWE-694: a non-AI Guard proxy with the builder's name, or a chosen certificate no longer in ZIA, blocks the plan with the reason."""
    f = at.Fake()
    f.stores["proxies"].rows.append({"id": 22, "name": "AIG-Proxy", "type": "PROXYCHAIN", "address": "proxy.corp.example", "port": 8080})
    assert any("does not point at AI Guard" in b for b in aig_preview(f, at.ROUTE)["blockers"])
    p = aig_preview(at.Fake(), dict(at.ROUTE, cert={"mode": "existing", "id": 999}))
    assert p["status"] == "blocked" and "no longer in ZIA" in p["blockers"][0]


def test_an_uploaded_certificate_from_an_earlier_run_is_reused():
    """ASVS V1.4.1 · CWE-841: a certificate uploaded earlier (the builder's name) is reused instead of uploaded twice."""
    f = at.Fake()
    f.stores["certs"].rows.append({"id": 12, "name": "AIG-CA"})
    k = at.by_key(aig_preview(f, dict(at.ROUTE, cert={"mode": "upload", "pem": at.PEM})))
    assert k["cert"]["status"] == "noop" and "uploaded earlier" in k["cert"]["reason"]


def test_routing_reads_that_fail_block_the_plan_with_the_reason():
    """ASVS V7.4.1 · CWE-754 · CWE-636: unreadable proxies, gateways, destination groups, SSL or forwarding rules block the routing plan (fail closed)."""
    f = at.Fake(proxy=True, gateway=True)
    f.t.read_error = "Forbidden"
    p = aig_preview(f, at.ROUTE)
    assert p["status"] == "blocked" and len(p["blockers"]) >= 3 and all("Forbidden" in b for b in p["blockers"])


def test_a_routing_rerun_updates_objects_someone_changed():
    """ASVS V1.4.1 · CWE-841: on a re-run a destination group, QUIC rule, forwarding rule and Allow rule that drifted are updated back, field by field."""
    # Arrange
    blocker = {"id": 5, "name": "Caution AI", "type": "AI_ML", "order": 1, "state": "ENABLED", "actions": ["CAUTION_AI_ML_WEB_USE"]}
    f = at.Fake(proxy=True, gateway=True, cac_rules=[blocker])
    aig_apply(f, at.ROUTE)
    f.stores["groups"].rows[0]["addresses"] = [".chatgpt.com"]
    next(r for r in f.stores["firewall"].rows if r["name"] == "AIG-NoQUIC")["state"] = "DISABLED"
    f.stores["forwarding"].rows[0]["state"] = "DISABLED"
    next(r for r in f.stores["cac"].rows if r["name"] == "AIG-Allow-AI")["state"] = "DISABLED"
    # Act
    k = at.by_key(aig_preview(f, at.ROUTE))
    res = aig_apply(f, at.ROUTE)
    # Assert
    assert [k[x]["status"] for x in ("group", "quic", "fwd", "allow")] == ["change"] * 4
    assert res["status"] == "applied" and f.stores["forwarding"].rows[0]["state"] == "ENABLED"
    assert aig_preview(f, at.ROUTE)["status"] == "nothing_to_do"


def test_prompt_capture_already_on_is_a_noop():
    """ASVS V1.4.1 · CWE-841: prompt capture already on for the picked apps plans no write."""
    f = at.Fake(settings={"enableChatGptPrompt": True, "enableClaudePrompt": True, "enableMicrosoftCoPilotPrompt": True})
    assert at.by_key(aig_preview(f, at.ROUTE))["prompt"]["status"] == "noop"
    f.zia.url_filtering.get_url_and_app_settings = lambda: (None, None, {"status": 500, "message": "down"})
    assert at.by_key(aig_preview(f, at.ROUTE))["prompt"]["status"] == "excluded"


def test_the_url_allow_is_added_only_when_a_url_rule_would_stop_the_apps():
    """ASVS V1.4.1 · CWE-863: a URL filtering Block on the apps' category adds a custom category and an Allow at order 1; without one nothing is added."""
    url_scope = ao.scope_for(["zia_extras", "aiguard", "dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    stopper = {"id": 9, "name": "Block AI", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["AI_ML_APPS"]}
    k = at.by_key(aig_preview(at.Fake(proxy=True, gateway=True, url_rules=[stopper]), at.ROUTE, url_scope))
    assert k["allow_cat"]["status"] == "change" and k["allow_url"]["status"] == "change"
    k2 = at.by_key(aig_preview(at.Fake(proxy=True, gateway=True), at.ROUTE, url_scope))
    assert k2["allow_url"]["status"] == "noop" and "allow_cat" not in k2


def test_routing_undo_of_an_update_puts_the_old_value_back():
    """ASVS V11.1.1 · CWE-841: Undo of a routing update puts back the value it replaced, only while the object still holds what the run wrote."""
    f = at.Fake(proxy=True, gateway=True)
    aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False, block_quic=False))
    f.stores["groups"].rows[0]["addresses"] = [".old.example"]
    res = aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False, block_quic=False))
    undo = aig_apply(f, res["inverse"])
    assert undo["status"] == "applied" and f.stores["groups"].rows[0]["addresses"] == [".old.example"]
    again = aig_preview(f, res["inverse"])
    assert again["items"][0]["status"] == "noop" and "already as before" in again["items"][0]["reason"]


def test_an_existing_policy_that_could_not_be_read_in_full_blocks_and_a_bad_list_is_explained():
    """ASVS V7.4.1 · CWE-754 · CWE-209: an existing policy unreadable in full blocks the plan; an AI Guard refusal is explained in plain words."""
    f = at.Fake(policies=[{"id": 1, "name": "AIG-Policy"}])
    f.aiguard.policies.get_policy = lambda pid: at.refused("boom", 500)
    p = aig_preview(f, at.POLICY, at.AIG_ONLY)
    assert p["status"] == "blocked" and "could not be read in full" in p["blockers"][0]
    g = at.Fake()
    g.aiguard.policies.list_policies = lambda: at.refused("Forbidden", 403)
    with pytest.raises(ao.OperationError, match="role"):
        aig_preview(g, at.POLICY, at.AIG_ONLY)
    h = at.Fake()
    del h.aiguard
    with pytest.raises(ao.OperationError, match="OneAPI"):
        aig_preview(h, at.POLICY, at.AIG_ONLY)


def test_a_match_rule_that_drifted_is_updated_and_one_in_place_is_a_noop():
    """ASVS V1.4.1 · CWE-841: the policy match rule is updated when it was disabled since, and left when it matches."""
    f = at.Fake()
    aig_apply(f, at.POLICY, at.AIG_ONLY)
    f.stores["aig_rules"].rows[0]["enabled"] = False
    assert at.by_key(aig_preview(f, at.POLICY, at.AIG_ONLY))["rule"]["status"] == "change"
    aig_apply(f, at.POLICY, at.AIG_ONLY)
    assert at.by_key(aig_preview(f, at.POLICY, at.AIG_ONLY))["rule"]["status"] == "noop"


def test_a_write_that_needs_an_object_not_created_is_skipped():
    """ASVS V11.1.1 · CWE-696: a step that names an object an earlier step failed to create is skipped, not sent with a dangling reference."""
    f = at.Fake(proxy=True, gateway=True)
    f.zia.cloud_firewall.add_ip_destination_group = lambda **kw: at.refused("Invalid", 400)
    res = aig_apply(f, dict(at.ROUTE, allow_in_zia=False, prompt_capture=False))
    k = at.by_key(res)
    assert k["group"]["status"] == "failed" and k["ssl"]["status"] == "skipped" and "AIG-Apps" in k["ssl"]["reason"]
    assert not [w for w in f.t.writes if w[0] in ("ssl", "forwarding")]


def test_an_object_created_since_the_preview_is_a_conflict_and_a_failed_read_fails_the_step():
    """ASVS V11.1.1 · CWE-367 · CWE-754: a destination group created by someone else after the re-plan is not duplicated; an unreadable list fails the step."""
    f = at.Fake(proxy=True, gateway=True)
    spec = dict(at.ROUTE, allow_in_zia=False, prompt_capture=False, ssl_inspect=False, block_quic=False)
    p = aig_preview(f, spec)
    real = f.stores["groups"].list
    calls = {"n": 0}

    def appears(*a, **k):
        calls["n"] += 1
        if calls["n"] == 2:
            f.stores["groups"].rows.append({"id": 7, "name": "AIG-Apps", "addresses": []})
        return real(*a, **k)
    f.zia.cloud_firewall.list_ip_destination_groups = appears
    assert at.by_key(aig_apply(f, spec, prepared=p))["group"]["status"] == "conflict"


def test_read_back_flags_an_object_that_is_not_as_written():
    """ASVS V1.4.1 · CWE-754: the routing read-back reports an object whose fields differ from what was written."""
    f = at.Fake(proxy=True, gateway=True)
    real = f.stores["firewall"].add

    def add_and_drift(body):
        out = real(body)
        f.stores["firewall"].rows[-1]["state"] = "DISABLED"
        return out
    f.zia.cloud_firewall_rules.add_rule = lambda **kw: add_and_drift(kw)
    res = aig_apply(f, dict(at.ROUTE, allow_in_zia=False, prompt_capture=False, ssl_inspect=False))
    assert res["verification"]["mismatched"] == ["AIG-NoQUIC: not as written when read back"]


def test_the_policy_page_reads_ai_guard_only():
    """ASVS V4.1.3 · CWE-272: the detection policy page reads AI Guard (policies, rules, providers) and not ZIA."""
    f = at.Fake()
    f.zia = None
    out = ao.read_objects(f, "aiguard_policy_setup", at.AIG_ONLY)
    assert out["providers"] == ["Default Anthropic Provider", "Default OpenAI Provider"] and out["readiness"]["zia"]["read"] is False


@pytest.mark.parametrize("kind", ["zia_proxy", "ip_destination_group", "firewall_rule", "ssl_rule", "forwarding_rule", "cac_rule", "url_category",
                                  "url_rule", "aiguard_policy", "aiguard_rule", "root_certificate", "url_app_settings"])
def test_fetch_of_every_kind_answers_or_says_why(kind):
    """ASVS V7.4.1 · CWE-754 · CWE-209: every object kind is read fresh by id; a missing one says 'not found', an SDK error is a short string."""
    f = at.Fake()
    row, err = oa.fetch(f, kind, 424242)
    assert (row is None and err) or kind == "url_app_settings"   # one settings object: no id
    f.zia, f.aiguard = at.Svc(), at.Svc()
    row, err = oa.fetch(f, kind, 1)
    assert row is None and isinstance(err, str) and len(err) < 300


# ===========================================================================
# AI Guard readiness and readers: branches
# ===========================================================================

def test_readiness_on_a_ready_tenant_and_without_a_licence():
    """ASVS V1.4.1 · CWE-1188: with proxy, gateway and forwarding rule in place readiness is ready; without the Gen AI licence prompt capture is info only."""
    f = at.Fake(proxy=True, gateway=True, licensed=False)
    aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False, block_quic=False))
    rd = ag.readiness(f)
    st = {c["id"]: c["status"] for c in rd["checks"]}
    assert rd["ready"] is True and st["zia.genai_license"] == "info" and st["zia.forwarding"] == "pass" and st["zia.o365"] == "info"


def test_readiness_reports_unreadable_subscriptions_certificates_and_no_policy():
    """ASVS V7.4.1 · CWE-754: unreadable subscriptions and certificates are info with the reason; AI Guard with no detection policy is a warning."""
    f = at.Fake(proxy=True, gateway=True)
    f.zia.organization_information.get_subscriptions = lambda: at.refused("down", 500)
    f.zia.proxies._request_executor.certs = None
    f.zia.proxies._request_executor.execute = lambda req: (None, {"status": 500, "message": "certs down"})
    rd = ag.readiness(f)
    st = {c["id"]: (c["status"], c["detail"]) for c in rd["checks"]}
    assert st["zia.genai_license"][0] == "info" and "could not be read" in st["zia.genai_license"][1]
    assert st["zia.root_ca"][0] == "info" and st["aiguard.policy"][0] == "warn"


def test_readiness_without_a_zia_service_and_out_of_scope():
    """ASVS V4.1.3 · CWE-272: a client with no ZIA service and ZIA out of scope are both reported as not read."""
    f = at.Fake()
    f.zia = None
    assert {c["id"]: c["status"] for c in ag.readiness(f, aiguard=False)["checks"]}["zia.proxy"] == "not_read"
    rd = ag.readiness(at.Fake(), zia=False, aiguard=False)
    assert all(c["status"] == "not_read" for c in rd["checks"]) and rd["ready"] is False


@pytest.mark.parametrize("data,want", [([{"id": 1, "name": "A"}], ["A"]), ({"list": [{"id": 2, "displayName": "B"}]}, ["B"]),
                                       ({"other": 1}, []), ([{"name": "no id"}, "junk"], [])])
def test_root_certificates_are_read_from_list_or_wrapped_answers(data, want, monkeypatch):
    """ASVS V5.1.3 · CWE-20: the root certificate answer (a list, a {list} object, or junk) is read defensively; only id, name and expiry are kept."""
    monkeypatch.setattr(pc, "raw_get", lambda zia, path: (data, None))
    rows, err = ag.read_root_certs(object())
    assert err is None and [r["name"] for r in rows] == want and all(set(r) == {"id", "name", "expiry"} for r in rows)


def test_app_settings_from_a_model_are_partial_and_never_written_back():
    """ASVS V1.4.1 · CWE-665: settings rebuilt from the SDK model (no raw body) are marked partial, so they are never PUT back."""
    class Model:
        def request_format(self):
            return {"enableChatGptPrompt": False, "x": None}
    z = at.Svc(url_filtering=at.Svc(get_url_and_app_settings=lambda: (Model(), None, None)))
    assert ag.read_app_settings(z) == ({"enableChatGptPrompt": False}, False, None)
    z2 = at.Svc(url_filtering=at.Svc(get_url_and_app_settings=lambda: (None, None, None)))
    assert ag.read_app_settings(z2) == (None, False, "no answer")


def test_field_helpers_read_snake_and_camel_paths():
    """ASVS V5.1.3 · CWE-20: get() reads dotted paths in either case, ref_ids reads ids or names, is_gone recognises a 404."""
    row = {"primaryProxy": {"id": 3}, "dest_ip_groups": [{"id": 9}, {"name": "n"}, "x"]}
    assert ag.get(row, "primary_proxy.id") == 3 and ag.get(row, "missing.x", "d") == "d" and ag.get("not a dict", "a") is None
    assert ag.ref_ids(row["dest_ip_groups"]) == ["9", "n", "x"] and ag.ref_ids(None) == []
    assert ag.is_gone({"status": 404}) and ag.is_gone("Resource does not exist") and not ag.is_gone("timeout")
    assert ag.classify_aiguard_error("timeout").startswith("AI Guard did not answer")
    assert ag.app_ids(["CLAUDE", "nope"]) == ["claude"] and ag.app_ids(None) == [a["id"] for a in ag.AI_APPS if a["default"]]


def test_raw_bodies_and_rows_are_read_defensively():
    """ASVS V5.1.3 · CWE-20 · CWE-755: a raw body that is bytes, junk or deeply nested JSON, and a lookup-style (data, error) answer, never raise."""
    class R:
        def __init__(self, b):
            self.b = b

        def get_body(self):
            return self.b
    assert ag.raw_body((None, R(b'{"a": 1}'), None)) == {"a": 1} and ag.raw_body((None, R("not json"), None)) is None
    assert ag.raw_body((None, R("[" * 100_000 + "]" * 100_000), None)) is None
    assert ag.rows(([{"a": 1}], None)) == ([{"a": 1}], None) and ag.rows((None, "refused")) == ([], "refused")
    assert ag.one((None, None, {"status": 404})) == (None, "not found") and ag.one(({}, None, None)) == (None, "not found")


@pytest.mark.parametrize("spec,refused", [
    ({"type": zb.TYPE, "areas": ["firewall"]}, True), ({"type": zb.TYPE, "areas": ["url", "atp"]}, True), ({"type": zb.TYPE, "areas": ["url"]}, False),
    ({"type": zb.TYPE}, False), ({"type": zb.TYPE, "action": "revert", "steps": [{"op": "restore_atp", "fields": {}}]}, True),
    ({"type": zb.TYPE, "action": "revert", "steps": [{"op": "delete", "area": "url", "id": 1, "name": "x"}]}, False),
    ({"type": zb.TYPE, "areas": "firewall"}, False),
])
def test_the_scope_check_refuses_areas_that_are_not_ticked(spec, refused):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: given the spec, the baseline's scope check (run before sign-in) refuses an area or Undo step outside the Scope page selection."""
    why = zb._in_scope(zt.WEB_ONLY, spec)
    assert bool(why) is refused and (not why or "Nothing was read" in why)
    assert zb._in_scope(zt.WEB_ONLY) is None and zb._in_scope(zt.NOTHING, spec)


def test_a_subscription_with_a_numeric_id_and_a_gen_ai_sku_counts():
    """ASVS V1.4.1 · CWE-1188: a subscription read as a numeric id beside the Gen AI SKU is still recognised."""
    z = at.Svc(organization_information=at.Svc(get_subscriptions=lambda: (None, at.Resp([{"id": 7, "sku": "ZS_DP_GEN_AI", "status": "ACTIVE"}]), None)))
    assert ag.read_subscriptions(z)[0] is True


def test_the_url_allow_path_is_idempotent_and_repairs_drift():
    """ASVS V1.4.1 · CWE-841: the URL Allow and its custom category apply, a re-run is a no-op, and a category or rule changed since is updated back."""
    url_scope = ao.scope_for(["zia_extras", "aiguard", "dlp"], {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    stopper = {"id": 9, "name": "Block AI", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["AI_ML_APPS"]}
    f = at.Fake(proxy=True, gateway=True, url_rules=[stopper])
    assert aig_apply(f, at.ROUTE, url_scope)["status"] == "applied"
    assert aig_preview(f, at.ROUTE, url_scope)["status"] == "nothing_to_do"
    f.stores["categories"].rows[0]["urls"] = [".chatgpt.com"]
    next(r for r in f.stores["url"].rows if r["name"] == "AIG-Allow-URL")["action"] = "BLOCK"
    k = at.by_key(aig_preview(f, at.ROUTE, url_scope))
    assert k["allow_cat"]["status"] == "change" and k["allow_url"]["status"] == "change"
    assert aig_apply(f, at.ROUTE, url_scope)["status"] == "applied" and aig_preview(f, at.ROUTE, url_scope)["status"] == "nothing_to_do"
    f.zia.url_categories.lookup = lambda urls: (None, "lookup refused")
    assert at.by_key(aig_preview(f, at.ROUTE, url_scope))["allow_url"]["status"] == "excluded"


def test_an_undo_delete_of_an_object_gone_or_renamed_during_the_run():
    """ASVS V11.1.1 · CWE-367: during the Undo, an object deleted meanwhile is 'already gone' and one renamed meanwhile is kept."""
    f = at.Fake(proxy=True, gateway=True)
    res = aig_apply(f, dict(at.ROUTE, ssl_inspect=False, allow_in_zia=False, prompt_capture=False))
    p = aig_preview(f, res["inverse"])
    real_get_fw, real_get_grp = f.stores["firewall"].get, f.stores["groups"].get

    calls = {"fw": 0, "grp": 0}

    def fw_gone(oid):   # 1: the re-plan, 2: right before the delete
        calls["fw"] += 1
        if calls["fw"] == 2:
            f.stores["firewall"].rows.clear()
        return real_get_fw(oid)

    def grp_renamed(oid):
        calls["grp"] += 1
        if calls["grp"] == 2:
            f.stores["groups"].rows[0]["name"] = "Renamed by admin"
        return real_get_grp(oid)
    f.zia.cloud_firewall_rules.get_rule = fw_gone
    f.zia.cloud_firewall.get_ip_destination_group = grp_renamed
    undo = aig_apply(f, res["inverse"], prepared=p)
    st = sorted(u["status"] for u in undo["items"])
    assert "noop" in st and "conflict" in st and f.stores["groups"].rows


def test_a_write_whose_list_cannot_be_read_again_fails_that_step_only():
    """ASVS V7.4.1 · CWE-754: a create whose list cannot be read again right before the write fails with the reason; nothing is written for it."""
    f = at.Fake(proxy=True, gateway=True)
    spec = dict(at.ROUTE, allow_in_zia=False, prompt_capture=False, ssl_inspect=False)
    p = aig_preview(f, spec)
    calls = {"n": 0}
    real = f.stores["firewall"].list

    def second_read_fails(*a, **k):
        calls["n"] += 1
        return at.refused("down", 500) if calls["n"] >= 2 else real(*a, **k)
    f.zia.cloud_firewall_rules.list_rules = second_read_fails
    k = at.by_key(aig_apply(f, spec, prepared=p))
    assert k["quic"]["status"] == "failed" and "could not read" in (k["quic"].get("error") or "") and not f.stores["firewall"].rows


def test_a_baseline_update_of_a_rule_deleted_since_fails_with_the_reason():
    """ASVS V7.4.1 · V11.1.1 · CWE-754 · CWE-367: an update of a rule deleted after the re-plan fails with the reason and writes nothing."""
    t = zt.Tenant()
    zb_apply(t, {"tier": "strict", "areas": ["url"]})
    p = zb_plan(t, {"tier": "balanced", "areas": ["url"]})
    real = t.zia.url_filtering.get_rule
    writes = len(t.writes)

    def gone(rid):
        t.zia.url_filtering.rows = [r for r in t.zia.url_filtering.rows if r["id"] != rid]
        return real(rid)
    t.zia.url_filtering.get_rule = gone
    res = zb_apply(t, {"tier": "balanced", "areas": ["url"]}, prepared=p)
    assert {u["status"] for u in res["items"] if u["status"] != "noop"} == {"failed"} and len(t.writes) == writes


def test_the_atp_write_skips_a_switch_changed_since_the_preview():
    """ASVS V11.1.1 · CWE-367: the ATP write re-reads the settings and leaves a switch someone changed after the re-plan."""
    t = zt.Tenant()
    p = zb_plan(t, {"tier": "strict", "areas": ["atp"]})
    real = t.zia.atp_policy.get_atp_settings
    calls = {"n": 0}

    def changed():
        calls["n"] += 1
        if calls["n"] == 2:   # 1: the re-plan, 2: right before the write
            t.zia.atp_policy.settings["crypto_mining_blocked"] = True
        return real()
    t.zia.atp_policy.get_atp_settings = changed
    res = zb_apply(t, {"tier": "strict", "areas": ["atp"]}, prepared=p)
    item = next(u for u in res["items"] if u["field"] == "crypto_mining_blocked")
    assert item["status"] == "conflict" and ("atp_policy", "update_atp_settings", None) not in t.writes


def _model_drops(svc, field):
    """get_rule as SDK 1.11.3 answers for a model without `field` (the sandbox model has no cbiProfile): the
    parsed row lacks it, the raw body (response.get_body) still has it."""
    real = svc.get_rule

    def get(*a):
        row, _r, err = real(*a)
        if row is None:
            return row, _r, err
        raw = {at._camel(k): v for k, v in row.items()}
        return {k: v for k, v in row.items() if k != field}, at.Resp(raw), err
    svc.get_rule = get


def test_a_sandbox_update_keeps_the_isolation_profile_the_sdk_model_drops():
    """ASVS V1.4.1 · CWE-665 · CWE-1188: a Sandbox rule re-read for an update keeps its Cloud Browser Isolation profile from the raw answer, so the PUT written back does not strip it."""
    # Arrange
    t = zt.Tenant()
    zb_apply(t, {"tier": "strict", "areas": ["sandbox"]})
    _model_drops(t.zia.sandbox_rules, "cbi_profile")
    p = zb_plan(t, {"tier": "balanced", "areas": ["sandbox"]})          # the description names the tier: an update
    # Act
    res = zb_apply(t, {"tier": "balanced", "areas": ["sandbox"]}, prepared=p)
    # Assert
    rule = next(r for r in rows_of(t, "sandbox") if r["name"] == "BL-SB-Office-PDF")
    assert res["status"] == "applied" and "Balanced" in rule["description"]
    assert (rule.get("cbi_profile") or rule.get("cbiProfile") or {}).get("id") == "p1"
    assert not res["verification"]["mismatched"]


def test_read_back_of_a_created_sandbox_rule_sees_the_profile_the_model_drops():
    """ASVS V1.4.1 · V7.1.3 · CWE-754: the read-back of a new Quarantine-and-isolate rule is not a false mismatch when the SDK model leaves its profile out."""
    t = zt.Tenant()
    _model_drops(t.zia.sandbox_rules, "cbi_profile")
    res = zb_apply(t, {"tier": "strict", "areas": ["sandbox"]})
    assert res["verification"]["mismatched"] == [] and res["verification"]["confirmed"] == res["verification"]["checked"] == 3


@pytest.mark.parametrize("thr", ["1.2.3", ".", "1e999", "9" * 400, None, "0.8", 0.8])
def test_a_tenant_threshold_that_is_not_a_number_is_compared_without_a_crash(thr):
    """ASVS V5.1.3 · V7.4.1 · CWE-20 · CWE-755: a detection policy threshold from the tenant that is not a number (1.2.3, a dot, an overflow) is compared as no threshold, never raising."""
    sig = oa.canon([{"detector": "pii", "enabled": True, "configuration": {"threshold": thr}}], "input_detector_policies")
    assert sig[0]["threshold"] in (None, 0.8) or isinstance(sig[0]["threshold"], float)


def test_a_policy_with_a_malformed_threshold_in_the_tenant_is_planned_as_an_update():
    """ASVS V7.4.1 · CWE-755: an existing AI Guard policy whose threshold is malformed is planned (as an update), not a failed job."""
    f = at.Fake()
    aig_apply(f, at.POLICY, at.AIG_ONLY)
    f.stores["aig_policies"].rows[0]["inputDetectorPolicies"][0]["configuration"]["threshold"] = "1.2.3"
    assert at.by_key(aig_preview(f, at.POLICY, at.AIG_ONLY))["policy"]["status"] == "change"


def test_a_captured_framework_always_loads_again():
    """ASVS V5.1.3 · CWE-20 · CWE-1287: rules whose tenant name or values a framework file cannot carry (<, >, a value that is not a Zscaler name) are left out with the reason, so the captured file loads."""
    t = zt.Tenant(url=[{"id": 1, "name": "Block <Games>", "order": 1, "action": "BLOCK", "url_categories": ["GAMBLING"]},
                       {"id": 2, "name": "Odd Values", "order": 2, "action": "BLOCK", "url_categories": ["GAMBLING", {"id": 5}]},
                       {"id": 3, "name": "Fine", "order": 3, "action": "BLOCK", "url_categories": ["GAMBLING", "CUSTOM_07"]}, zt.URL_DEFAULT])
    fw = zb.capture(t, ["url"], tenant_label="src")["framework"]
    got = zb.load_framework(json.loads(json.dumps(fw)))
    assert [r["name"] for r in got["rules"]] == ["Fine"]
    reasons = " ".join(x["reason"] for x in fw["not_exported"])
    assert "characters a framework file does not carry" in reasons and "cannot be carried in a framework file" in reasons


@pytest.mark.parametrize("action,want", [("BLOCK", "change"), ("DO_NOT_DECRYPT", "change"), ("DECRYPT", "noop")])
def test_ssl_inspect_is_kept_above_an_ssl_block_rule_too(action, want):
    """ASVS V1.4.1 · CWE-1188 · CWE-696: an AI Guard Inspect rule below an enabled SSL inspection Block rule is moved to order 1 (a Block would stop the apps before inspection); another Inspect rule above it changes nothing."""
    f = at.Fake(proxy=True, gateway=True)
    aig_apply(f, at.ROUTE)
    next(r for r in f.stores["ssl"].rows if r["name"] == "AIG-Inspect")["order"] = 5
    f.stores["ssl"].rows.append({"id": 78, "name": "Theirs", "order": 2, "state": "ENABLED", "action": {"type": action}})
    assert at.by_key(aig_preview(f, at.ROUTE))["ssl"]["status"] == want


@pytest.mark.parametrize("key,choice,weaker", [("url.legal", "ISOLATE", "Block → Isolate"), ("url.legal", "ALLOW", "Block → Allow"),
                                               ("url.misc", "BLOCK", ""), ("url.legal", "BLOCK", "")])
def test_isolating_a_category_the_tier_blocks_is_flagged_weaker(key, choice, weaker):
    """ASVS V1.4.1 · CWE-1188: Isolate in place of the tier's Block lets users view the site, so it is flagged as weaker; Block in place of Isolate is not."""
    row = {r["key"]: r for r in zb.review({"tier": "strict", "rules": {key: {"action": choice}}})["rules"]}[key]
    assert row["weakened"] == weaker


def test_saved_undo_records_still_load_after_a_json_round_trip():
    """ASVS V1.4.1 · CWE-502 · CWE-20: the Undo specs saved with a change record (JSON on disk) for a baseline with ATP, a certificate move and an AI Guard routing still pass the stricter Undo checks and plan."""
    t = zt.Tenant()
    saved = [json.loads(json.dumps(zb_apply(t, {"tier": "strict", "areas": ["ssl", "atp"]})["inverse"])),
             json.loads(json.dumps(zb_apply(t, {"type": zb.CERT_TYPE, "rules": [3], "certificate": 52})["inverse"]))]
    for spec in saved:
        assert zb_plan(t, spec)["status"] == "ready", spec["type"]
    f = at.Fake(proxy=True, gateway=True)
    inv = json.loads(json.dumps(aig_apply(f, at.ROUTE)["inverse"]))
    assert aig_preview(f, inv)["status"] == "ready"
