"""Education (FERPA) policy pack: the Education industry preset ships its own pack, detection only, valid for
the same checks an uploaded pack passes. Fakes only: no tenant, no network."""
from __future__ import annotations

import json
import re

import pack_library as pl
import vertical
import compliance_profiles as cp

PID = "education_ferpa_baseline"


def _load():
    from dlp_importer import discover_packs
    p = next(p for p in discover_packs() if p["id"] == PID)
    d = p["dir"]
    rd = lambda f: json.load(open(f"{d}/{f}", encoding="utf-8"))  # noqa: E731
    return rd("configs/dlp_dictionaries.json"), rd("configs/dlp_engines.json"), rd("configs/dlp_policies.json"), rd("pack.json")


def test_pack_is_discovered_and_passes_the_upload_validator():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the shipped Education pack is found by discovery and passes the same validator an uploaded pack does (patterns compile, engines name real dictionaries)."""
    dicts, engines, policies, meta = _load()
    pack = {"meta": meta, "dictionaries": dicts, "engines": engines, "policies": policies, "app_groups": []}
    res = pl.validate_pack(pack)
    assert res["ok"], res
    names = {d["name"] for d in dicts}
    for e in engines:
        assert set(re.findall(r"D:([^>]+?) >", e["expression"])) <= names, e["name"]
    for p in policies:
        assert {x for x in p["engines"]} <= {e["name"] for e in engines}


def test_every_rule_ships_disabled_at_info_on_all_four_channels():
    """ASVS V4.1.3 · CWE-1188 · WSTG-BUSL-01: read-only by default: every rule is DISABLED at INFO severity, and the markings and student-record engines each reach web, endpoint, SaaS and email."""
    _d, engines, policies, _m = _load()
    assert policies and all(p["state"] == "DISABLED" and p["severity"] == "RULE_SEVERITY_INFO" for p in policies)
    for e in engines:
        chans = {p.get("channel", "web") for p in policies if e["name"] in p["engines"]}
        assert chans == {"web", "endpoint", "saas", "email"}, (e["name"], chans)


def test_student_record_detection_needs_a_term_and_an_ssn_not_a_term_alone():
    """ASVS V5.1.3 · CWE-185: the markings pattern fires on the FERPA citation and the words Education Record; the record-terms pattern recognises a transcript; the SSN rides the cloned predefined dictionary at 500-character proximity."""
    dicts, engines, _p, _m = _load()
    by = {d["name"]: d for d in dicts}
    marks = [re.compile(p["pattern"], re.I) for p in by["EDU-Record-Markings"]["patterns"]]
    assert any(r.search("Protected under 34 CFR Part 99") for r in marks) and any(r.search("Contains EDUCATION RECORD data") for r in marks)
    assert not any(r.search("A record of the weather") for r in marks)
    terms = [re.compile(p["pattern"], re.I) for p in by["EDU-Student-Record-Terms"]["patterns"]]
    assert any(r.search("Official Transcript for Sam Lee") for r in terms)
    clone = by["EDU-Social Security Numbers (US) - Prox 500"]
    assert clone["predefined_clone"] and clone["proximity"] == 500 and clone["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH"
    data_engine = next(e for e in engines if e["name"] == "EDU Student Record Data")
    assert " AND " in data_engine["expression"]


def test_the_education_industry_and_ferpa_profile_offer_the_pack_first():
    """ASVS V1.14.1 · CWE-1059: the Education industry preset and the FERPA compliance profile both start with the Education pack, beside the ZBP baseline."""
    assert vertical.INDUSTRY_PACKS["Education"][0] == PID
    assert cp.PROFILES["FERPA"]["packs"][0] == PID and "zbp_enterprise_baseline" in cp.PROFILES["FERPA"]["packs"]
