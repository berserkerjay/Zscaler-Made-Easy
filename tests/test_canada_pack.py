"""Canada privacy (PIPEDA, Quebec Law 25, PHIPA) policy pack: detection only, valid for the same checks an
uploaded pack passes. Fakes only: no tenant, no network."""
from __future__ import annotations

import json
import os
import re

import pack_library as pl
import compliance_profiles as cp
import ops_zia_baseline as zb
import ai_guard as ag
import corpus_engines as ce

PID = "canada_privacy_baseline"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load():
    from dlp_importer import discover_packs
    p = next(p for p in discover_packs() if p["id"] == PID)
    d = p["dir"]
    rd = lambda f: json.load(open(f"{d}/{f}", encoding="utf-8"))  # noqa: E731
    return rd("configs/dlp_dictionaries.json"), rd("configs/dlp_engines.json"), rd("configs/dlp_policies.json"), rd("pack.json")


def _fires(dicts, name, text):
    """A dictionary as ZIA reads it: any pattern within `proximity` bytes of any phrase (pattern-only: any pattern)."""
    d = next(x for x in dicts if x["name"] == name)
    pats = [re.compile(p["pattern"]) for p in d.get("patterns", [])]
    phrases = [p["phrase"].strip('"').lower() for p in d.get("phrases", [])]
    prox = d.get("proximity") or 0
    low = text.lower()
    if not pats:
        return any(ph in low for ph in phrases)
    for rx in pats:
        for m in rx.finditer(text):
            if not phrases:
                return True
            for ph in phrases:
                for k in re.finditer(re.escape(ph), low):
                    if min(abs(k.start() - m.end()), abs(m.start() - k.end())) <= prox:
                        return True
    return False


def test_pack_is_discovered_and_passes_the_upload_validator():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the shipped Canada pack is found by discover_packs and passes the validator an uploaded pack does (patterns compile, engines name real dictionaries, SaaS names fit)."""
    dicts, engines, policies, meta = _load()
    res = pl.validate_pack({"meta": meta, "dictionaries": dicts, "engines": engines, "policies": policies, "app_groups": []})
    assert res["ok"], res
    names = {d["name"] for d in dicts}
    for e in engines:
        assert set(re.findall(r"D:([^>]+?) >", e["expression"])) <= names, e["name"]
    assert (len(dicts), len(engines), len(policies)) == (11, 4, 16)
    for n in ("CA-SIN", "CA-Health-Card-ON", "CA-Health-Card-QC", "CA-Health-Card-BC", "CA-Passport", "CA-Drivers-Licence-ON", "CA-Drivers-Licence-QC"):
        assert n in names


def test_every_rule_ships_disabled_at_info_and_each_engine_reaches_all_four_channels():
    """ASVS V4.1.3 · CWE-1188 · WSTG-BUSL-01: read-only by default: every rule is DISABLED at INFO severity and monitor-only, and every engine reaches web, endpoint, SaaS and email."""
    _d, engines, policies, _m = _load()
    assert policies and all(p["state"] == "DISABLED" and p["severity"] == "RULE_SEVERITY_INFO" for p in policies)
    assert not [p for p in policies if str(p["action"]).upper().startswith(("BLOCK", "DENY"))]
    for e in engines:
        chans = {p.get("channel", "web") for p in policies if e["name"] in p["engines"]}
        assert chans == {"web", "endpoint", "saas", "email"}, (e["name"], chans)


def _luhn(digits: str) -> bool:
    return ce._luhn([int(c) for c in digits])


def test_sin_samples_match_with_a_label_and_the_luhn_check_separates_valid_from_invalid():
    """ASVS V5.1.3 · CWE-185 · CWE-1023: a Luhn-valid SIN beside an English or French label matches with dashes, spaces or none; wrong length, a leading 0 or 8, and a bare number in prose do not (the Luhn check itself is run on the samples, since a ZIA pattern cannot)."""
    dicts, _e, _p, _m = _load()
    valid = ["123 456 782", "123-456-782", "123456782", "130-692-544"]
    for s in valid:
        assert _luhn(re.sub(r"\D", "", s)), s
        assert _fires(dicts, "CA-SIN", f"Social Insurance Number: {s}"), s
    assert _fires(dicts, "CA-SIN", "Numéro d'assurance sociale : 123 456 782")
    assert _fires(dicts, "CA-SIN", "numero d'assurance sociale 130-692-544")
    # Luhn-invalid: the shape and label still match (a ZIA pattern has no checksum), the test's own check rejects it
    assert not _luhn("123456789") and not _luhn("130692545")
    # not SIN-shaped, or no label: do not fire
    assert not _fires(dicts, "CA-SIN", "Social Insurance Number: 04645428")        # 8 digits
    assert not _fires(dicts, "CA-SIN", "Social Insurance Number: 0464542861")      # 10 digits
    assert not _fires(dicts, "CA-SIN", "Social Insurance Number: 846-454-286")     # leading 8 is never issued
    assert not _fires(dicts, "CA-SIN", "Social Insurance Number: 046-454-286")     # leading 0 is never issued
    assert not _fires(dicts, "CA-SIN", "The invoice total was 123456789 units shipped in March.")
    assert not _fires(dicts, "CA-SIN", "Call us on 416 555 0199 about the 2024 order 987654321")
    # a label far away (beyond 50 bytes) does not anchor the number
    assert not _fires(dicts, "CA-SIN", "Social Insurance Number" + " lorem ipsum" * 12 + " 130-692-544")


def test_health_card_samples_match_by_province_and_wrong_shapes_do_not():
    """ASVS V5.1.3 · CWE-185 · CWE-20: Ontario OHIP (ten digits plus optional version code), Quebec RAMQ (four letters plus eight digits, birth date inside) and BC PHN (ten digits starting with 9) match beside their labels; wrong lengths, other starts and unlabelled numbers do not."""
    dicts, _e, _p, _m = _load()
    for s in ("1234-567-890", "1234 567 890 AB", "1234567890", "1234-567-890-KT"):
        assert _fires(dicts, "CA-Health-Card-ON", f"OHIP health card number {s}"), s
    assert _fires(dicts, "CA-Health-Card-ON", "carte santé de l'Ontario 1234-567-890")
    assert not _fires(dicts, "CA-Health-Card-ON", "OHIP health card number 123456789")        # 9 digits
    assert not _fires(dicts, "CA-Health-Card-ON", "OHIP health card number 12345678901")      # 11 digits
    assert not _fires(dicts, "CA-Health-Card-ON", "Order 1234567890 shipped on Friday")      # no label

    for s in ("TREM 8501 0112", "TREM85010112", "TREM-8551-0112"):   # male 1985-01-01 ; female (month+50) 1985-01-01
        assert _fires(dicts, "CA-Health-Card-QC", f"Carte d'assurance maladie {s}"), s
    assert _fires(dicts, "CA-Health-Card-QC", "RAMQ: TREM85010112")
    assert not _fires(dicts, "CA-Health-Card-QC", "RAMQ: TREM85130112")       # month 13
    assert not _fires(dicts, "CA-Health-Card-QC", "RAMQ: TREM8501011")        # 7 digits
    assert not _fires(dicts, "CA-Health-Card-QC", "RAMQ: TRE850101123")        # 3 letters
    assert not _fires(dicts, "CA-Health-Card-QC", "Part code TREM85010112 in stock")  # no label

    for s in ("9123 456 789", "9123-456-789", "9123456789"):
        assert _fires(dicts, "CA-Health-Card-BC", f"BC Personal Health Number {s}"), s
    assert not _fires(dicts, "CA-Health-Card-BC", "Personal Health Number 8123456789")   # does not start with 9
    assert not _fires(dicts, "CA-Health-Card-BC", "Personal Health Number 912345678")    # 9 digits
    assert not _fires(dicts, "CA-Health-Card-BC", "Reference 9123456789 for the quote")  # no label


def test_passport_and_licence_samples_match_and_lookalikes_do_not():
    """ASVS V5.1.3 · CWE-185: a Canadian passport (two letters, six digits), an Ontario licence (letter plus 14 digits) and a Quebec licence (letter plus 12 digits) match beside a label; shorter shapes and unlabelled codes do not."""
    dicts, _e, _p, _m = _load()
    assert _fires(dicts, "CA-Passport", "Canadian passport number AB123456")
    assert _fires(dicts, "CA-Passport", "numéro de passeport : GA654321")
    assert not _fires(dicts, "CA-Passport", "Canadian passport number AB12345")
    assert not _fires(dicts, "CA-Passport", "Canadian passport number AB1234567")
    assert not _fires(dicts, "CA-Passport", "Part AB123456 is back in stock")
    for s in ("A1234-12345-12345", "A1234 12345 12345", "A123412345 12345".replace(" 12345", "12345")):
        assert _fires(dicts, "CA-Drivers-Licence-ON", f"Ontario driver's licence {s}"), s
    assert not _fires(dicts, "CA-Drivers-Licence-ON", "Ontario driver's licence A1234-12345-1234")
    assert not _fires(dicts, "CA-Drivers-Licence-ON", "Code A1234-12345-12345 in the catalogue")
    for s in ("T1234-123456-12", "T123412345612"):
        assert _fires(dicts, "CA-Drivers-Licence-QC", f"Permis de conduire {s}"), s
    assert not _fires(dicts, "CA-Drivers-Licence-QC", "Permis de conduire T1234-123456-1")
    assert not _fires(dicts, "CA-Drivers-Licence-QC", "Serial T1234-123456-12 ships Monday")


def test_bank_numbers_fire_only_beside_labels_and_the_engine_needs_both_parts():
    """ASVS V5.1.3 · CWE-1188: transit/institution numbers fire only beside their label, and the low-confidence bank engine needs a transit number AND an account number, so either alone never fires."""
    dicts, engines, policies, _m = _load()
    assert _fires(dicts, "CA-Bank-Transit-Institution", "Transit number 12345-678")
    assert _fires(dicts, "CA-Bank-Transit-Institution", "numéro de transit 12345 678")
    assert not _fires(dicts, "CA-Bank-Transit-Institution", "Postal range 12345-678 is the draft")
    assert _fires(dicts, "CA-Bank-Account-Number", "Bank account 1234567")
    assert not _fires(dicts, "CA-Bank-Account-Number", "The count was 1234567 last week")
    bank = next(e for e in engines if "Bank" in e["name"])
    assert " AND " in bank["expression"] and "LOW CONFIDENCE" in bank["description"]
    assert all(p["severity"] == "RULE_SEVERITY_INFO" for p in policies if bank["name"] in p["engines"])


def test_engines_combine_identifiers_with_keywords_in_english_and_french():
    """ASVS V5.1.3 · CWE-185: the PIPEDA engine needs an identifier AND a name or date-of-birth keyword, the provincial health engine needs a health card AND a health term; the bilingual keyword dictionaries match both languages."""
    dicts, engines, _p, _m = _load()
    by = {e["name"]: e["expression"] for e in engines}
    pi = by["CA PIPEDA Personal Information"]
    assert " AND (D:CA-Privacy-Name-DOB-Keywords > 0)" in pi and "D:CA-SIN > 0" in pi and "D:CA-Health-Card-ON > 0" in pi
    ph = by["CA Provincial Health Information"]
    assert "D:CA-Health-Context-Keywords > 0" in ph and "D:CA-SIN" not in ph
    assert _fires(dicts, "CA-Privacy-Name-DOB-Keywords", "Date de naissance : 1985-01-01")
    assert _fires(dicts, "CA-Privacy-Name-DOB-Keywords", "Surname: Tremblay")
    assert not _fires(dicts, "CA-Privacy-Name-DOB-Keywords", "Quarterly revenue grew in March")
    assert _fires(dicts, "CA-Health-Context-Keywords", "Dossier médical du patient")
    assert _fires(dicts, "CA-Health-Context-Keywords", "Diagnosis and prescription notes")
    assert not _fires(dicts, "CA-Health-Context-Keywords", "Parking permit renewal form")


def test_the_terraform_workspace_exists_with_a_lock_file_covering_four_platforms():
    """ASVS V14.2.1 · CWE-1357: the pack has a generated Terraform workspace whose .terraform.lock.hcl pins the zia provider with four platform hashes (h1:), like the sibling packs."""
    tf = os.path.join(ROOT, "terraform", PID)
    for f in ("terraform.tf", "providers.tf", "dictionaries.tf", "engines.tf", "rules.tf", "README.md", ".gitignore", ".terraform.lock.hcl"):
        assert os.path.isfile(os.path.join(tf, f)), f
    lock = open(os.path.join(tf, ".terraform.lock.hcl"), encoding="utf-8").read()
    assert 'provider "registry.terraform.io/zscaler/zia"' in lock and len(re.findall(r'"h1:', lock)) == 4
    assert open(os.path.join(tf, ".terraform.lock.hcl")).read() == open(os.path.join(ROOT, "terraform", "education_ferpa_baseline", ".terraform.lock.hcl")).read()
    assert "11 dictionaries · 4 engines · 16 rules" in open(os.path.join(tf, "README.md"), encoding="utf-8").read()


def test_the_canadian_profiles_offer_the_pack_first_and_mark_their_controls_assumed():
    """ASVS V1.14.1 · CWE-1059: PIPEDA, Quebec Law 25 and PHIPA are compliance profiles that offer the Canada pack first, map every pack rule to a control, cite generic controls flagged assumed, and use a real AI Guard profile; no Canada industry option exists, so the wizard's industry list is unchanged."""
    import vertical
    for k in ("PIPEDA", "QUEBEC_LAW25", "PHIPA"):
        p = cp.PROFILES[k]
        assert p["packs"][0] == PID and p["group"] == "Canada" and p["assumed"], k
        assert p["aiguard"] in ag.PROFILES
        assert set(ag.PROFILES[p["aiguard"]]["block"]) | set(ag.PROFILES[p["aiguard"]]["detect"]) <= set(ag.PII_ENTITIES)
        assert k in zb.OVERLAYS and zb.OVERLAYS[k]["assumed"]
        ctrls = cp.controls(k)
        assert ctrls and all(c["assumed"] and c["assumed_why"] for c in ctrls), k
        assert not any(re.search(r"\b(s|art|article|section)\.? ?\d", c["id"], re.I) for c in ctrls), "no invented clause numbers"
        _name, rules = cp._pack_rules(PID)
        assert len(rules) == 16 and all(cp.map_pack_rule(k, r)["controls"] for r in rules)
    assert "Canada" in cp.GROUP_ORDER and {x["profile"] for x in cp.assumed()} >= {"PIPEDA", "QUEBEC_LAW25", "PHIPA"}
    assert "Canada" not in vertical.INDUSTRIES and all(PID not in v for v in vertical.INDUSTRY_PACKS.values())


def test_the_offline_validator_fires_every_canadian_engine_on_its_samples_and_nothing_else():
    """SSDF PW.8.2 · CWE-697: tools/validate_detection.py cross-references the pack (every engine's dictionaries, every rule's engines) and, over randomised Canadian samples and the other packs' look-alikes (US SSN, driver licence), every Canadian engine fires on its own samples and on nothing else."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("validate_detection", os.path.join(ROOT, "tools", "validate_detection.py"))
    vd = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vd)
    report = vd.run(3)["packs"]["canada_privacy_baseline"]
    assert report["static"]["problems"] == []
    assert report["tested_engines"] == 4 and report["untested_engines"] == 0
    for e in report["engines"]:
        assert e["recall"] == 1.0 and e["precision"] == 1.0 and e["false_positives"] == 0 and e["cross_fires"] == 0, e
