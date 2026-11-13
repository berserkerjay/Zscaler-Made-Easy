"""Schema, referential integrity, safety and coverage for Canada DLP candidate pack."""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1] / "canada_dlp_baseline"
def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))
def test_canada_pack_structure_and_coverage():
    meta=load("pack.json")
    dictionaries=load("configs/dlp_dictionaries.json")
    engines=load("configs/dlp_engines.json")
    policies=load("configs/dlp_policies.json")
    sources=load("sources.json")
    names={d["name"] for d in dictionaries}
    assert len(dictionaries)==53 and len(names)==53
    assert set(sources)==names
    assert all(f"CA-Health-{p}" in names for p in ("NL","PE","NS","NB","QC","ON","MB","SK","AB","BC","YT","NT","NU"))
    assert all(f"CA-Driver-{p}" in names for p in ("NL","PE","NS","NB","QC","ON","MB","SK","AB","BC","YT","NT","NU"))
    assert len(engines)==18 and len(policies)==72
    assert len({e["name"] for e in engines})==18
    assert len({p["name"] for p in policies})==72
    assert meta["baseline"]["prefix"]=="CA-"
    for dictionary in dictionaries:
        assert dictionary["phrases"]
        assert len(dictionary["phrases"])<=256
        assert all(len(x["phrase"].encode("utf-8"))<=128 for x in dictionary["phrases"])
        if dictionary.get("patterns"):
            assert len(dictionary["patterns"])<=8
            assert all(len(x["pattern"].encode("utf-8"))<=256 for x in dictionary["patterns"])
            assert dictionary["custom_phrase_match_type"]=="MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE"
            assert 0 < dictionary["proximity"] <= 10000
            for pattern in dictionary["patterns"]:
                re.compile(pattern["pattern"])
    for e in engines:
        refs=set(re.findall(r"D:(CA-[A-Za-z0-9-]+)",e["expression"]))
        assert refs and refs <= names,(e["name"],refs-names)
    for e in engines:
        matching=[p for p in policies if p["engines"]==[e["name"]]]
        assert len(matching)==4
        assert {p.get("channel","web") for p in matching}=={"web","endpoint","saas","email"}
    for p in policies:
        assert p["state"]=="DISABLED" and p["severity"]=="RULE_SEVERITY_INFO"
        assert p["action"]==("OFLCASB_DLP_REPORT_INCIDENT" if p.get("channel")=="saas" else "ALLOW")
        assert len(p["name"])<=31
        assert p["rank"]==0
