"""Federal compliance profiles, one compliance choice and the compliance pack
(compliance_profiles.py, compliance_pack.py, the ZIA baseline, AI Guard, the
POV planner, the IRS 1075 FTI Pack and their routes). Fakes only: the ZIA
baseline's and AI Guard's recording tenants from their own test files; no
network, no real tenant."""
from __future__ import annotations

import csv
import io
import json
import re
import zipfile

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import ai_guard as ag
import compliance_pack as cpk
import compliance_profiles as cp
import corpus_engines
import deployments
import dlp_api_server as srv
import ops_aiguard as oa
import ops_zia_baseline as zb
import pov
import tenant_profiles
import vertical
from test_ops_zia_baseline import FULL, Tenant, _no_activation, apply as zb_apply, plan as zb_plan  # noqa: F401 (fixture)

FED = cp.FEDERAL_KEYS
ALL_FILES = list(cpk.FILES)


def _review(profile, **spec):
    return zb.review(dict({"type": zb.TYPE, "compliance_profile": profile}, **spec))


def _rows(rev):
    return {r["key"]: r for r in rev["rules"]}


# ── The profiles and their sources ──────────────────────────────────────

def test_there_are_six_federal_profiles_each_with_sourced_controls():
    """ASVS V1.14.1 · CWE-1059: FedRAMP Moderate and High, CMMC Level 2, Federal Zero Trust, IRS 1075 and GovRAMP exist, each control names an https source and an assumed one says why."""
    assert set(FED) == {"FEDRAMP_MOD", "FEDRAMP_HIGH", "CMMC_L2", "FED_ZT", "IRS_1075", "GOVRAMP"}
    for k in FED:
        p = cp.PROFILES[k]
        assert p["sources"] and all(cp.SOURCES[s]["url"].startswith("https://") for s in p["sources"])
        ctrls = cp.controls(k)
        assert ctrls, k
        for c in ctrls:
            assert c["source_ref"]["url"].startswith("https://") and c["id"] and c["title"], (k, c["id"])
            assert bool(c["assumed"]) == bool(c["assumed_why"]), (k, c["id"])


def test_fedramp_high_adds_the_high_only_controls_moderate_does_not_have():
    """ASVS V1.14.1 · CWE-1059: AC-4(4) and SI-4(10) are High-baseline controls (SP 800-53B) and only FedRAMP High lists them."""
    mod = {c["id"] for c in cp.controls("FEDRAMP_MOD")}
    high = {c["id"]: c for c in cp.controls("FEDRAMP_HIGH")}
    assert {"AC-4(4)", "SI-4(10)"} <= set(high) and not ({"AC-4(4)", "SI-4(10)"} & mod)
    assert high["AC-4(4)"]["baseline"] == "H" and high["SC-7(5)"]["baseline"] == "M H"
    assert mod <= set(high)


def test_cmmc_level_2_cites_practice_ids_and_their_800_171_numbers():
    """ASVS V1.14.1 · CWE-1059: every CMMC Level 2 control is a CMMC practice id (domain, level, SP 800-171 Rev. 2 number) whose title names that number."""
    for c in cp.controls("CMMC_L2"):
        m = re.fullmatch(r"(AC|AU|CM|IA|IR|MP|RA|SC|SI)\.L[12]-(3\.\d+\.\d+)", c["id"])
        assert m and f"SP 800-171 {m.group(2)}" in c["title"], c


def test_the_assumed_list_names_every_unverified_control():
    """ASVS V1.14.1 · CWE-1059: controls not verified against their source are listed by assumed() with a reason (SC-21's DNSSEC link, GovRAMP's equivalence, IRS enhancements)."""
    got = {(a["profile"], a["control"]) for a in cp.assumed()}
    assert ("FEDRAMP_MOD", "SC-21") in got and ("GOVRAMP", "SC-7") in got and ("IRS_1075", "SI-4(4)") in got
    assert ("FEDRAMP_MOD", "SC-7") not in got and ("CMMC_L2", "AC.L2-3.1.3") not in got
    assert all(a["why"] for a in cp.assumed())


# ── Every rule mapped ───────────────────────────────────────────────────

def test_every_catalog_rule_and_atp_setting_has_an_objective_or_a_reason_code():
    """ASVS V1.14.1 · CWE-1059: every ZIA baseline catalog rule, ATP setting and UCaaS one-click switch is in RULE_OBJECTIVES with a known objective or reason code."""
    import ucaas_oneclick
    keys = {r["key"] for r in zb.CATALOG} | {"atp." + k for k, _ in zb.ATP_SETTINGS} | {"ucaas." + k for k in ucaas_oneclick.KEYS}
    assert keys == set(cp.RULE_OBJECTIVES)
    for k, e in cp.RULE_OBJECTIVES.items():
        assert bool(e.get("objective")) != bool(e.get("reason")), k
        assert (e.get("objective") in cp.OBJECTIVES) if e.get("objective") else (e["reason"] in cp.REASONS), k


@pytest.mark.parametrize("profile", sorted(cp.PROFILES))
@pytest.mark.parametrize("tier", ["", "balanced", "permissive", "healthcare"])
def test_every_created_rule_maps_to_a_control_or_a_reason_code(profile, tier):
    """ASVS V1.14.1 · CWE-1059: for every profile and tier, every baseline rule, ATP setting and offered pack rule has controls or a reason code."""
    spec = {"tier": tier} if tier else {}
    m = cp.mapping(profile, _review(profile, **spec))
    assert m["counts"]["rules"] > 50
    for r in m["rows"]:
        assert r["controls"] or r["reason"] in cp.REASONS, (profile, r["name"])
    packs = [r for r in m["rows"] if r["source"].startswith("Policy pack")]
    assert packs and all(r["controls"] for r in packs), "a pack rule maps to detection controls once enabled"
    import ucaas_oneclick
    assert {r["key"] for r in m["rows"] if r["area"] == "UCaaS one-click"} == {"ucaas." + k for k in ucaas_oneclick.KEYS}


@pytest.mark.parametrize("tier,on", [("balanced", True), ("strict", False)])
def test_every_ucaas_one_click_switch_is_mapped_or_reasoned_either_way(tier, on):
    """ASVS V1.14.1 · CWE-1059: each UCaaS one-click switch is a mapping row: on (calls break out uninspected) carries MEDIA_BREAKOUT and no control; off keeps the calls inspected and maps to the encrypted-visibility controls; the review row says the same."""
    import ucaas_oneclick
    # Arrange
    rev = _review("FEDRAMP_MOD", tier=tier, areas=["firewall", "ucaas"])
    # Act
    rows = {r["key"]: r for r in cp.mapping("FEDRAMP_MOD", rev, packs=[])["rows"] if r["area"] == "UCaaS one-click"}
    # Assert
    assert set(rows) == {"ucaas." + k for k in ucaas_oneclick.KEYS}
    for k, r in rows.items():
        if on:
            assert r["reason"] == "MEDIA_BREAKOUT" and not r["controls"] and r["action"] == "BREAKOUT", r
        else:
            assert r["controls"] and r["objective"] == "encrypted_visibility" and not r["reason"] and r["action"] == "INSPECT", r
    for s in rev["ucaas"]:
        assert s["profile"]["reason"] == ("MEDIA_BREAKOUT" if on else "")


def test_a_ucaas_switch_with_no_entry_fails_the_mapping(monkeypatch):
    """ASVS V1.14.1 · CWE-1059: a UCaaS switch missing from RULE_OBJECTIVES is an error, never a silent gap."""
    monkeypatch.delitem(cp.RULE_OBJECTIVES, "ucaas.enableUcaasZoom")
    with pytest.raises(cp.ProfileError, match="enableUcaasZoom"):
        cp.mapping("FEDRAMP_MOD", _review("FEDRAMP_MOD"), packs=[])


def test_the_compliance_pack_lists_the_ucaas_switches_picked_or_not():
    """ASVS V1.14.1 · CWE-1059: the compliance pack's mapping has a row per UCaaS switch: mapped or MEDIA_BREAKOUT when the area is picked (the default), NOT_CREATED when it is not."""
    import ucaas_oneclick
    picked = cpk.build("HIPAA")
    unpicked = cpk.build("HIPAA", {"type": zb.TYPE, "areas": ["url", "ssl"]})
    want = {"ucaas." + k for k in ucaas_oneclick.KEYS}
    rows_p = {r["key"]: r for r in picked["mapping"]["rows"] if r["key"].startswith("ucaas.")}
    rows_u = {r["key"]: r for r in unpicked["mapping"]["rows"] if r["key"].startswith("ucaas.")}
    assert set(rows_p) == want and set(rows_u) == want
    assert all(r["reason"] == "MEDIA_BREAKOUT" for r in rows_p.values())   # HIPAA keeps the Balanced tier: switches on
    assert all(r["reason"] == "NOT_CREATED" for r in rows_u.values())


def test_a_rule_with_neither_a_control_nor_a_reason_fails_the_mapping(monkeypatch):
    """ASVS V1.14.1 · CWE-1059: a catalog rule missing from RULE_OBJECTIVES, or a row with neither, is an error, never a silent gap."""
    monkeypatch.delitem(cp.RULE_OBJECTIVES, "fw.p2p")
    with pytest.raises(cp.ProfileError, match="fw.p2p"):
        cp.map_rule("FEDRAMP_MOD", "fw.p2p")
    monkeypatch.setitem(cp.RULE_OBJECTIVES, "fw.p2p", {"objective": "least_functionality"})
    monkeypatch.setattr(cp, "_finish_map", lambda *a, **k: {"objective": "", "objective_label": "", "controls": [], "reason": "", "reason_text": "", "why": ""})
    with pytest.raises(cp.ProfileError, match="neither"):
        cp.mapping("FEDRAMP_MOD", _review("FEDRAMP_MOD"))


def test_a_rule_switched_to_allow_or_off_is_not_credited_to_a_control():
    """ASVS V1.14.1 · CWE-1059: an Allow choice gives ALLOWS_TRAFFIC, a switched-off rule NOT_CREATED, a caution page CAUTION_ONLY; privacy exemptions and productivity rules carry their reasons."""
    rev = _review("FEDRAMP_MOD", rules={"url.legal": {"action": "ALLOW"}, "fw.p2p": {"on": False}})
    m = {r["key"]: r for r in cp.mapping("FEDRAMP_MOD", rev, packs=[])["rows"]}
    assert m["url.legal"]["reason"] == "ALLOWS_TRAFFIC" and not m["url.legal"]["controls"]
    assert m["fw.p2p"]["reason"] == "NOT_CREATED"
    assert m["url.productivity"]["reason"] == "NOT_IN_SCOPE_FOR_PROFILE" and m["fw.allow_web"]["reason"] == "OPERATIONAL"
    assert [c["id"] for c in m["fw.default_deny"]["controls"]] == ["SC-7(5)"]
    bal = {r["key"]: r for r in cp.mapping("HIPAA", _review("HIPAA"), packs=[])["rows"]}
    assert bal["ssl.exempt_health"]["reason"] == "PRIVACY_EXCEPTION" and bal["url.bandwidth"]["reason"] == "NOT_IN_SCOPE_FOR_PROFILE"
    hc = {r["key"]: r for r in cp.mapping("FEDRAMP_MOD", _review("FEDRAMP_MOD", tier="healthcare"), packs=[])["rows"]}
    assert hc["url.genai"]["reason"] == "CAUTION_ONLY" and not hc["url.genai"]["controls"]


# ── The profile changes rules where its source says so ──────────────────

def test_federal_profiles_build_on_strict_and_say_why():
    """ASVS V1.14.1 · CWE-1059: a federal profile with no tier given builds Strict (the default deny SC-7(5)/3.13.6 needs); another tier warns in the plan."""
    for k in FED:
        rev = _review(k)
        assert rev["tier"] == "strict" and _rows(rev)["fw.default_deny"]["locked"].startswith("required by"), k
    rev = _review("CMMC_L2", tier="balanced")
    assert "builds on the Strict tier" in rev["compliance_profile"]["tier_warning"] and "fw.default_deny" not in _rows(rev)


def test_fedramp_high_requires_inspection_and_leaves_out_privacy_exemptions():
    """ASVS V1.14.1 · CWE-693: FedRAMP High locks the SSL catch-all, QUIC block and password-protected archive block on (AC-4(4)) and drops the SSL exemptions even on Balanced."""
    rows = _rows(_review("FEDRAMP_HIGH", rules={"ssl.catch_all": {"on": False}, "fw.quic": {"on": False}}, mode="allow_all"))
    for k in ("ssl.catch_all", "fw.quic", "ftc.pw_archives"):
        assert rows[k]["on"] and "AC-4(4)" in rows[k]["locked"], k
    assert rows["fw.quic"]["action"] == "BLOCK_DROP", "a required rule keeps its tier action under Allow all"
    bal = _rows(_review("FEDRAMP_HIGH", tier="balanced"))
    assert not ({"ssl.exempt_health", "ssl.exempt_finance"} & set(bal))
    assert {"ssl.exempt_health", "ssl.exempt_finance"} <= set(_rows(zb.review({"type": zb.TYPE, "tier": "balanced"})))


def test_cmmc_and_irs_add_a_translation_block_and_irs_requires_the_webmail_block():
    """ASVS V1.14.1 · CWE-1059: CMMC Level 2 and IRS 1075 add URL-Translation (Block) to Strict with the control and why; IRS 1075 requires the personal webmail block."""
    assert "url.translation" not in _rows(zb.review({"type": zb.TYPE, "tier": "strict"}))
    for k, ctrl in (("CMMC_L2", "AC.L2-3.1.3"), ("IRS_1075", "IRC 6103(p)(4)")):
        r = _rows(_review(k))["url.translation"]
        assert r["action"] == "BLOCK" and ctrl in r["profile_note"], k
        assert ctrl in [c["id"] for c in r["profile"]["controls"]], k
    assert _rows(_review("IRS_1075"))["cac.webmail"]["locked"].startswith("required by IRS Publication 1075")


def test_federal_zero_trust_requires_doh_inspection_and_govramp_reuses_fedramp_moderate():
    """ASVS V1.14.1 · CWE-1059: Federal Zero Trust locks DNS over HTTPS inspection and the Trusted Resolver (M-22-09 encrypted DNS); GovRAMP builds exactly FedRAMP Moderate's rules."""
    zt = _rows(_review("FED_ZT"))
    assert "M-22-09" in zt["dns.doh"]["locked"] and "M-22-09" in zt["dns.resolver"]["locked"]
    strip = lambda rev: [(r["key"], r["on"], json.dumps(r["action"])) for r in rev["rules"]]  # noqa: E731
    assert strip(_review("GOVRAMP")) == strip(_review("FEDRAMP_MOD"))
    assert "reuses" in cp.summary("GOVRAMP")["reuses"].lower() or "FedRAMP Moderate" in cp.summary("GOVRAMP")["reuses"]


def test_no_profile_and_framework_profiles_leave_the_rules_as_before():
    """ASVS V1.14.1 · CWE-1059: a spec without a profile is unchanged (existing builds keep working); a framework profile keeps the chosen tier and only adds its overlay."""
    base = zb.review({"type": zb.TYPE, "tier": "balanced"})
    hip = _review("HIPAA", tier="balanced")
    assert [r["key"] for r in base["rules"]] == [r["key"] for r in hip["rules"]]
    assert hip["normalized"]["overlays"] == ["HIPAA"] and "compliance_profile" not in base
    with pytest.raises(ao.OperationError, match="Unknown compliance profile"):
        zb.normalize({"type": zb.TYPE, "compliance_profile": "NOPE<script>"})


def test_a_profile_build_is_previewed_applied_disabled_and_recorded_with_its_profile(_no_activation):
    """ASVS V1.4.1 · V11.1.1 · CWE-1188: a FedRAMP High baseline goes through the shared preview and gates, creates only disabled rules, and the recorded run keeps the profile."""
    t = Tenant()
    spec = {"type": zb.TYPE, "compliance_profile": "FEDRAMP_HIGH", "areas": ["url", "ssl", "firewall"]}
    p = zb_plan(t, spec)
    assert "FedRAMP High" in p["title"] and any("Compliance profile FedRAMP High" in n for n in p["notes"])
    res = zb_apply(t, spec, prepared=p)
    assert res["status"] == "applied"
    made = [r for svc in (t.zia.url_filtering, t.zia.ssl_inspection_rules, t.zia.cloud_firewall_rules) for r in svc.rows if r["name"].startswith("BL-")]
    assert made and all(r["state"] == "DISABLED" for r in made)
    assert not any(r["name"].startswith("BL-SSL-Ex") for r in made)
    stored = ao.record(res, by="Jane Doe")
    rec = deployments.get_operation(stored["id"])
    assert rec["spec"]["compliance_profile"] == "FEDRAMP_HIGH"
    ctx = cpk.build("FEDRAMP_HIGH", operation=rec)
    pol = cpk.policy(ctx)
    assert pol["built"] is True and pol["operation"]["id"] == rec["id"]
    applied = {r["key"]: r["applied"] for r in pol["baseline"]["rules"]}
    assert applied["fw.default_deny"] == "applied" and applied.get("dns.doh") is None
    rows = {r["key"]: r for r in ctx["mapping"]["rows"]}
    assert rows["dns.doh"]["reason"] == "NOT_CREATED" and rows["fw.default_deny"]["controls"]


# ── AI Guard ────────────────────────────────────────────────────────────

def test_every_profile_names_an_ai_guard_profile_and_the_federal_ones_block_their_identifiers():
    """ASVS V1.14.1 · CWE-1059: each compliance profile's AI Guard profile exists; NIST 800-53, 800-171 and IRS 1075 block SSNs and ITINs in Block mode and block nothing in Monitor."""
    for k, p in cp.PROFILES.items():
        assert p["aiguard"] in ag.PROFILES, k
    assert {cp.PROFILES[k]["aiguard"] for k in FED} == {"NIST_800_53", "NIST_800_171", "IRS_1075"}
    for prof in ("NIST_800_53", "NIST_800_171", "IRS_1075"):
        body = oa.build_policy("AIG-Policy", prof, "block")
        ents = {e["entityType"]: e["action"] for d in body["inputDetectorPolicies"] if d["detector"] == "pii" for e in d["configuration"]["entities"]}
        assert ents["US_SSN"] == "BLOCK" and ents["US_ITIN"] == "BLOCK", prof
        assert set(ag.PROFILES[prof]["block"]) | set(ag.PROFILES[prof]["detect"]) <= set(ag.PII_ENTITIES)
        assert "BLOCK" not in re.findall(r"'action': '(\w+)'", str(oa.build_policy("AIG-Policy", prof, "monitor")))


def test_the_ai_guard_policy_follows_the_compliance_choice():
    """ASVS V1.14.1 · CWE-20: a detection policy spec naming only the compliance profile uses that profile's AI Guard profile; an unknown one is refused."""
    from test_ops_aiguard import AIG_ONLY, Fake, preview
    p = preview(Fake(), {"type": oa.POLICY, "compliance_profile": "IRS_1075", "apps": ["chatgpt"]}, AIG_ONLY)
    assert "IRS Publication 1075" in p["title"]
    with pytest.raises(ao.OperationError, match="Unknown compliance profile"):
        preview(Fake(), {"type": oa.POLICY, "compliance_profile": "XX", "apps": ["chatgpt"]}, AIG_ONLY)


# ── The compliance pack ─────────────────────────────────────────────────

@pytest.mark.parametrize("profile", FED)
def test_every_pack_file_renders_and_the_zip_holds_them_all(profile):
    """ASVS V12.5.1 · CWE-434 · WSTG-BUSL-08: every file renders with its media type; the ZIP holds the README, every file and one DLP file per web DLP rule."""
    ctx = cpk.build(profile)
    for fid in ALL_FILES:
        data, media, name = cpk.render(ctx, fid)
        assert data and name == f"{profile.lower()}-{fid}" and media
    z = zipfile.ZipFile(io.BytesIO(cpk.render(ctx, "compliance-pack.zip")[0]))
    names = set(z.namelist())
    assert {"README.txt", "mapping.html", "mapping.xlsx", "testplan.csv", "policy.json"} <= names
    dl = [n for n in names if n.startswith("dlp/")]
    web_rules = sum(1 for pid in cp.PROFILES[profile]["packs"] for r in cp._pack_rules(pid)[1] if r.get("channel") in (None, "", "web"))
    assert len(dl) == web_rules > 0
    assert json.loads(z.read("policy.json"))["note"].startswith("Rules are created DISABLED")


def test_the_mapping_csv_and_xlsx_carry_every_row_and_the_assumed_flag():
    """ASVS V1.14.1 · CWE-1236: the CSV has one row per mapped rule (formula-safe), the controls column marks assumed controls, and the workbook has the mapping and control sheets."""
    ctx = cpk.build("FEDRAMP_MOD")
    text = cpk.mapping_csv(ctx).decode("utf-8")
    rows = list(csv.reader(text.splitlines()[1:]))
    assert rows[0][:4] == ["Source", "Area", "Rule", "Rule key"] and len(rows) - 1 == ctx["mapping"]["counts"]["rules"]
    assert any("SC-21 (assumed)" in r[7] for r in rows[1:])
    assert not any(c.startswith(("=", "+", "@")) for r in rows for c in r)
    xl = zipfile.ZipFile(io.BytesIO(cpk.mapping_xlsx(ctx)))
    wb = xl.read("xl/workbook.xml").decode()
    assert "Rule mapping" in wb and "Controls" in wb and "Reason codes" in wb


def test_the_html_reports_escape_everything_they_show():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: a rule name or note holding markup is escaped in the mapping report and the test plan."""
    ctx = cpk.build("CMMC_L2")
    evil = '<img src=x onerror="alert(1)">'
    ctx["mapping"]["rows"][0]["name"] = evil
    ctx["mapping"]["rows"][0]["profile_note"] = evil
    for html_ in (cpk.mapping_html(ctx).decode(), cpk.testplan_html(ctx).decode()):
        assert "<img" not in html_ and "&lt;img src=x" in html_


def test_the_test_plan_groups_tests_by_control_and_names_controls_no_rule_proves():
    """ASVS V1.14.1 · CWE-1059: each control lists the tests of the rules that carry it out (with an empty Result column); a control no rule carries out says so."""
    ctx = cpk.build("FEDRAMP_HIGH")
    plan_ = {c["control"]: c for c in cpk.test_plan(ctx)}
    assert any("Zscaler" in t["expected"] or "blocked" in t["expected"] for t in plan_["AC-4(4)"]["tests"])
    assert plan_["IA-2"]["tests"] == [] and "No rule of this build" in plan_["IA-2"]["note"]
    dlp = [t for t in plan_["AU-12"]["tests"] if t["source"].startswith("Policy pack")]
    assert dlp and all(".txt" in t["steps"] for t in dlp)
    rows = list(csv.reader(cpk.testplan_csv(ctx).decode().splitlines()[1:]))
    assert rows[0][-1] == "Result" and all(r[-1] == "" for r in rows[1:])


_CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")


@pytest.mark.parametrize("profile", ["FEDRAMP_MOD", "IRS_1075", "PCI", "HIPAA", "CJIS"])
def test_synthetic_dlp_files_hold_only_documented_test_values(profile):
    """ASVS V8.3.1 · CWE-359 · CWE-200: every DLP test file says SYNTHETIC TEST DATA; each SSN is in the reserved block, each card a published test number, each address on example.com."""
    files = cpk.dlp_files(cpk.build(profile))
    assert files
    for f in files:
        text = f["content"].decode("utf-8")
        assert text.startswith("### SYNTHETIC TEST DATA") and "SYNTHETIC TEST DATA" in text.split("----- SAMPLE DOCUMENT")[-1]
        for ssn in re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text):
            assert ssn in corpus_engines.SAMPLES["ssn"], (f["id"], ssn)
        cards = {c for c in corpus_engines.SAMPLES["credit_card"]}
        for m in _CARD.findall(text):
            digits = re.sub(r"\D", "", m)
            if 13 <= len(digits) <= 19 and corpus_engines.luhn_ok(digits):
                assert any(re.sub(r"\D", "", c) == digits for c in cards), (f["id"], m)
        assert all(e.endswith("@example.com") for e in re.findall(r"[\w.]+@[\w.]+\.\w+", text))
        assert "Expected:" in text


def test_the_fti_files_fire_their_engines_and_an_unfireable_file_says_so():
    """ASVS V1.14.1 · CWE-1059: the FTI markings file satisfies its engine (checked locally); a file whose dictionaries have no safe sample says it may not fire."""
    files = {f["rule"]: f for f in cpk.dlp_files(cpk.build("IRS_1075"))}
    assert files["FTI-Markings-Monitor"]["expected"] is True
    assert "FEDERAL TAX INFORMATION" in files["FTI-Markings-Monitor"]["content"].decode()
    assert files["FTI-Return-Data-Monitor"]["expected"] == "maybe"
    hip = [f for f in cpk.dlp_files(cpk.build("HIPAA")) if f["expected"] is False]
    assert hip and all("may NOT fire" in f["content"].decode() for f in hip)


def test_the_engine_evaluator_never_runs_anything_but_counts_and_logic():
    """ASVS V5.2.4 · CWE-95 · WSTG-INPV-11: an engine expression is evaluated only after every name became a number; anything else is not evaluated."""
    assert cpk._evaluate("((D:A > 1) AND NOT ((D:B (x) > 0)))", {"A": 3, "B (x)": 0}) is True
    assert cpk._evaluate("((D:A + D:B (US)) > 4)", {"A": 3, "B (US)": 2}) is True
    assert cpk._evaluate("__import__('os').system('x')", {}) is None
    assert cpk._evaluate("(D:A > 0) OR (1).__class__", {"A": 1}) is None
    assert cpk._negated("(D:A > 0) AND NOT ((D:B > 0) OR (D:C > 0))") == {"B", "C"}


def test_an_unknown_file_or_profile_is_refused():
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: a file id outside the pack (a path, an unknown name) is 404; an unknown profile is refused."""
    ctx = cpk.build("FED_ZT")
    for bad in ("../etc/passwd", "mapping.exe", "", "a" * 200, "dlp-x/../../y.txt"):
        with pytest.raises(cpk.PackError) as e:
            cpk.render(ctx, bad)
        assert e.value.status == 404
    with pytest.raises(cpk.PackError):
        cpk.build("NOT_A_PROFILE")


# ── The IRS 1075 FTI Pack ───────────────────────────────────────────────

def test_the_fti_pack_validates_and_its_markings_match_labels_not_prose():
    """ASVS V5.1.3 · CWE-185: the FTI pack passes the pack validator; its markings dictionary matches the IRC 6103 citation and the FTI label, not ordinary prose."""
    import pack_library
    from dlp_importer import discover_packs
    pk = next(p for p in discover_packs() if p["id"] == "irs_fti_pack")
    b = pack_library.pack_bundle(pk["dir"])
    v = pack_library.validate_pack(b)
    assert not v["problems"], v["problems"]
    pats = [re.compile(p["pattern"]) for p in b["dictionaries"][0]["patterns"]]
    hit = lambda s: any(p.search(s) for p in pats)  # noqa: E731
    for s in ("Protected by IRC 6103", "26 U.S.C. 6103(p)(4)", "FEDERAL TAX INFORMATION", "per I.R.C. § 6103"):
        assert hit(s), s
    for s in ("Form 6103 order", "federal taxes are due", "FTI Consulting"):
        assert not hit(s), s
    assert all(r["state"] == "DISABLED" and r["action"] in ("ALLOW", "OFLCASB_DLP_REPORT_INCIDENT") for r in b["policies"])


# ── One choice: tenant profiles, vertical, POV ──────────────────────────

def test_the_choice_is_remembered_per_tenant_profile_and_survives_a_profile_save():
    """ASVS V4.1.3 · CWE-20: the compliance choice is stored on the profile (checked against the list), kept when the Connect form saves the profile, and forgotten with ''."""
    c = TestClient(srv.app)
    pid = c.post("/api/tenant-profiles", json={"name": "Acme Fed", "vanity_domain": "acmefed"}).json()["id"]
    assert c.post("/api/compliance-profiles/choice", json={"profile_id": pid, "compliance_profile": "cmmc_l2"}).json()["compliance_profile"] == "CMMC_L2"
    c.post("/api/tenant-profiles", json={"id": pid, "name": "Acme Fed", "vanity_domain": "acmefed", "notes": "x"})
    assert tenant_profiles.get(pid)["compliance_profile"] == "CMMC_L2"
    assert c.post("/api/compliance-profiles/choice", json={"profile_id": pid, "compliance_profile": "<b>x"}).status_code == 400
    assert c.post("/api/compliance-profiles/choice", json={"profile_id": "nobody", "compliance_profile": "GOVRAMP"}).status_code == 404
    assert c.post("/api/compliance-profiles/choice", json={"profile_id": pid, "compliance_profile": ""}).json()["compliance_profile"] == ""
    assert "compliance_profile" not in tenant_profiles._read()["profiles"][pid]


def test_the_federal_industry_and_pov_vertical_preset_pick_the_federal_profiles():
    """ASVS V5.1.3 · CWE-20: the Federal industry offers the federal profiles first; State & local offers the FTI pack; the POV's federal vertical defaults to FedRAMP Moderate and an unknown profile is refused."""
    sc = vertical.scope_for({"industry": "Federal"})
    assert sc["compliance_profiles"][:2] == ["FEDRAMP_MOD", "FEDRAMP_HIGH"] and set(sc["compliance_profiles"]) <= set(FED)
    assert "irs_fti_pack" in vertical.INDUSTRY_PACKS["State & local government"]
    assert pov.clean_intake({"customer": "Agency", "vertical": "federal"})["compliance_profile"] == "FEDRAMP_MOD"
    assert pov.clean_intake({"customer": "Agency", "vertical": "federal", "compliance_profile": "irs_1075"})["compliance_profile"] == "IRS_1075"
    assert pov.clean_intake({"customer": "Shop"})["compliance_profile"] == ""
    with pytest.raises(pov.PovError, match="compliance profile"):
        pov.clean_intake({"customer": "Agency", "compliance_profile": "../x"})
    assert {p["key"] for p in pov.catalog()["compliance_profiles"]} == set(cp.PROFILES)
    r = TestClient(srv.app).get("/api/vertical-scope", params={"industry": "Federal"})
    assert r.json()["compliance_profiles"][0] == "FEDRAMP_MOD"


# ── Routes ──────────────────────────────────────────────────────────────

def test_the_routes_list_profiles_and_serve_pack_files_as_no_store_attachments():
    """ASVS V8.1.1 · V14.4.1 · CWE-524 · WSTG-INFO-05: the catalogue lists every profile; pack files come as attachments with no-store and nosniff, from defaults or a posted spec."""
    c = TestClient(srv.app)
    cat = c.get("/api/compliance-profiles").json()
    assert {p["key"] for p in cat["profiles"]} == set(cp.PROFILES) and cat["profiles"][0]["group"] == "Federal and public sector"
    assert c.get("/api/compliance-profiles/FEDRAMP_HIGH").json()["summary"]["tier"] == "strict"
    r = c.get("/api/compliance-pack/IRS_1075/mapping.csv")
    assert r.status_code == 200 and r.headers["content-disposition"] == 'attachment; filename="irs_1075-mapping.csv"'
    assert r.headers["cache-control"] == "no-store" and r.headers["x-content-type-options"] == "nosniff"
    m = c.post("/api/compliance-pack", json={"compliance_profile": "CMMC_L2", "spec": {"tier": "balanced"}}).json()
    assert "builds on the Strict tier" in m["tier_warning"] and any(f.get("dlp") for f in m["files"])
    r = c.post("/api/compliance-pack/file", json={"compliance_profile": "CMMC_L2", "spec": {"tier": "strict", "prefix": "FED"}, "file": "policy.json"})
    assert r.status_code == 200 and json.loads(r.content)["baseline"]["prefix"] == "FED"


@pytest.mark.parametrize("method,path,body,status", [
    ("GET", "/api/compliance-profiles/NOPE", None, 400),
    ("GET", "/api/compliance-pack/FEDRAMP_MOD/..%2F..%2Fsecret", None, 404),
    ("GET", "/api/compliance-pack/FEDRAMP_MOD/nope.txt", None, 404),
    ("POST", "/api/compliance-pack", {"compliance_profile": ""}, 400),
    ("POST", "/api/compliance-pack/file", {"compliance_profile": "FEDRAMP_MOD", "spec": {"tier": "ultra"}, "file": "mapping.csv"}, 400),
    ("POST", "/api/compliance-pack/file", {"compliance_profile": "FEDRAMP_MOD", "operation_id": "op-none", "file": "mapping.csv"}, 404),
    ("POST", "/api/compliance-pack/file", {"compliance_profile": "FEDRAMP_MOD", "spec": {"action": "revert", "steps": [{"op": "delete", "id": "1"}]}, "file": "mapping.csv"}, 400),
    ("POST", "/api/compliance/profile-view", {"compliance_profile": "FEDRAMP_MOD", "results": "x"}, 422),
])
def test_bad_requests_are_refused_with_a_4xx(method, path, body, status):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: unknown profiles, files, tiers and recorded runs, an Undo spec and a malformed body are refused, never a 500."""
    c = TestClient(srv.app)
    r = c.request(method, path, json=body) if body is not None else c.request(method, path)
    assert r.status_code == status, r.text


def test_the_routes_need_the_ui_token_and_a_same_origin_post(monkeypatch):
    """ASVS V4.1.1 · V13.2.3 · CWE-306 · CWE-352 · WSTG-ATHN-04: with the UI token on, a download without the token is 401; a cross-origin POST is refused."""
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    c = TestClient(srv.app)
    assert c.get("/api/compliance-pack/FEDRAMP_MOD/mapping.csv").status_code == 401
    assert c.get("/api/compliance-profiles").status_code == 401
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    r = TestClient(srv.app).post("/api/compliance-pack/file", json={"compliance_profile": "FEDRAMP_MOD", "file": "mapping.csv"},
                                 headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


def test_an_assessment_is_read_against_a_profile_from_the_compliance_page():
    """ASVS V1.14.1 · CWE-1059: a remembered assessment read against CMMC Level 2 gives each control a status from its checks, lists the controls no check reaches, and downloads as CSV."""
    c = TestClient(srv.app)
    checks = [{"id": "FW.1", "label": "Default deny", "status": "FAIL"}, {"id": "4.1", "label": "SSL inspection", "status": "PASS"},
              {"id": "ZPA.1", "label": "<b>access</b>", "status": "REVIEW"}]
    rid = c.post("/api/compliance/report", json={"checks": checks}).json()["report_id"]
    v = c.get(f"/api/compliance/report/{rid}/profile/CMMC_L2").json()
    st = {x["control"]: x["status"] for x in v["controls"]}
    assert st["SC.L2-3.13.6"] == "Not met" and st["SI.L2-3.14.6"] in ("Met", "Partially met") and st["IA.L2-3.5.3"] == "Partially met"
    assert "AC.L2-3.1.3" in v["not_assessed"]
    r = c.get(f"/api/compliance/report/{rid}/profile/CMMC_L2", params={"format": "csv"})
    assert r.status_code == 200 and r.text.startswith("Control,Title,Status") and "attachment" in r.headers["content-disposition"]
    assert c.get(f"/api/compliance/report/{rid}/profile/NOPE").status_code == 400
    assert c.get("/api/compliance/report/compliance-nope/profile/CMMC_L2").status_code == 404
    assert c.get(f"/api/compliance/report/{rid}/profile/CMMC_L2", params={"format": "xml"}).status_code == 400
