"""Global Banking Baseline: premised on Zscaler's predefined dictionaries at
high confidence, reusing the ZBP Enterprise engines, and deploying across
web, endpoint, SaaS, email and the containment channels."""
from __future__ import annotations

import json
import re

import pack_deploy as pd
from test_pack_channels import add_control_services, make_client, tenant as casb_tenant  # noqa: F401
from test_pack_deploy import Obj  # noqa: F401

PREDEFINED = ["ABA_LEAKAGE", "CREDIT_CARD", "CRED_LEAKAGE", "SSN", "USDL_LEAKAGE", "USITIN_LEAKAGE",
              "EUIBAN_LEAKAGE", "PPEU_LEAKAGE", "ASPP_LEAKAGE",
              "FINANCIAL", "ML_CORPORATE_FINANCE_LEAKAGE", "ML_TAX_LEAKAGE"]


def _pack(pid):
    from dlp_importer import discover_packs
    p = next(p for p in discover_packs() if p["id"] == pid)
    return {"id": p["id"], "dir": p["dir"]}


def _client():
    client = add_control_services(make_client(casb_tenants=[casb_tenant("Acme M365 Mail", "OFFICE_365", 503),
                                                            casb_tenant("Acme OneDrive", "ONEDRIVE", 504)]))
    client.zia.dlp_dictionary.items = [Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(PREDEFINED)]
    return client


def _load(pid):
    d = _pack(pid)["dir"]
    return (json.load(open(f"{d}/configs/dlp_dictionaries.json", encoding="utf-8")),
            json.load(open(f"{d}/configs/dlp_engines.json", encoding="utf-8")),
            json.load(open(f"{d}/configs/dlp_policies.json", encoding="utf-8")),
            json.load(open(f"{d}/pack.json", encoding="utf-8")))


def test_banking_pack_is_premised_on_predefined_dictionaries_at_high_confidence():
    dicts, engines, policies, meta = _load("global_banking_baseline")
    assert pd.baseline_meta(meta, "global_banking_baseline")["prefix"] == "Bank-"
    clones = {d["name"]: d for d in dicts if d.get("predefined_clone")}
    templates = {d["dict_template_name"] for d in clones.values()}
    assert {"CREDIT_CARD", "ABA_LEAKAGE", "SSN", "USITIN_LEAKAGE", "USDL_LEAKAGE"} <= templates
    for d in clones.values():
        if d["dict_template_name"] != "CRED_LEAKAGE":   # the private-key clone is a credentials dictionary, kept at ZBP's medium
            assert d["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH", d["name"]
    # Every clone has a plain "High" variant and a 500-byte proximity variant.
    prox = {n for n, d in clones.items() if d.get("proximity") == 500}
    assert prox and all(n.endswith("Prox 500") for n in prox)
    assert clones["ZBP-Credit Cards - High"]["include_bin_numbers"] is True
    # Hierarchical predefined dictionaries are referenced directly, never cloned blind.
    exprs = " ".join(e["expression"] for e in engines)
    for name in ("EUIBAN_LEAKAGE", "PPEU_LEAKAGE", "ASPP_LEAKAGE", "FINANCIAL", "ML_CORPORATE_FINANCE_LEAKAGE"):
        assert f"D:{name} >" in exprs, name
    assert not any(d.get("dict_template_name") in ("EUIBAN_LEAKAGE", "PPEU_LEAKAGE", "ASPP_LEAKAGE") for d in clones.values())
    # The engines reuse the ZBP Enterprise engines verbatim, so both packs share them.
    zbp_engines = {e["name"]: e for e in json.load(open(f"{_pack('zbp_enterprise_baseline')['dir']}/configs/dlp_engines.json", encoding="utf-8"))}
    zbp_dicts = {d["name"]: d for d in json.load(open(f"{_pack('zbp_enterprise_baseline')['dir']}/configs/dlp_dictionaries.json", encoding="utf-8"))}
    mine = {e["name"]: e for e in engines}
    for n in ("ZBP-US PII", "ZBP-Financial Information", "ZBP-Private Keys"):
        assert mine[n] == zbp_engines[n], n
    for d in dicts:
        if d["name"].startswith("ZBP-"):
            assert d == zbp_dicts[d["name"]], d["name"]
    # Every D: reference resolves to a pack dictionary or a predefined name.
    names = {d["name"] for d in dicts} | set(PREDEFINED)
    for e in engines:
        expr = e["expression"]
        for n in sorted(names, key=len, reverse=True):
            expr = expr.replace(f"D:{n}", "D_OK")
        assert not re.findall(r"D:[^>]+", expr), (e["name"], expr)
    # Banking-specific coverage: PCI, payment instructions, global PII, KYC, lending, MNPI, markings.
    for n in ("Bank-Payment Card Data", "Bank-Payment Card Data - Bulk", "Bank-Account and Payment Instructions",
              "Bank-Customer PII (Global)", "Bank-Customer PII - Bulk", "Bank-KYC and AML Files",
              "Bank-Credit and Loan Applications", "Bank-MNPI and Deal Information", "Bank-Confidential Markings"):
        assert n in mine, n
    assert "(D:ZBP-Credit Cards - High > 0) AND (D:Bank-Card Security Data > 1)" in mine["Bank-Payment Card Data"]["expression"]
    # Detection only: the pack ships Web, Endpoint, SaaS and Email DLP rules.
    # Containment (Cloud App Control, File Type Control, URL Filtering, SSL
    # Inspection) is managed separately and is not part of any pack.
    channels = {p.get("channel", "web") for p in policies}
    assert channels == {"web", "endpoint", "saas", "email"}
    assert {p["action"] for p in policies if p.get("channel", "web") == "web"} == {"ALLOW", "BLOCK"}
    assert all(p["state"] == "DISABLED" for p in policies)
    assert meta["baseline"]["immutable"] is True and meta["baseline"]["prefix"] == "Bank-"


def test_banking_pack_deploys_across_every_channel(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_CARVED_CHANNELS", "none")   # this test covers the pack's full channel coverage
    pk = _pack("global_banking_baseline")
    client = _client()
    rep = pd.preflight(client, [pk], writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"] + rep.get("warnings", [])
    dicts, engines, policies, _ = _load("global_banking_baseline")
    res = pd.apply(client, [pk], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    assert res["status"] == "applied", res.get("logs")
    assert res["summary"] == {"created": len(dicts) + len(engines) + len(policies)}
    # Clones carry the template id and the high confidence threshold.
    added = {d["name"]: d for d in client.zia.dlp_dictionary.added}
    cc = added["ZBP-Credit Cards - High"]
    assert cc["dict_template_id"] == PREDEFINED.index("CREDIT_CARD") + 1 and cc["confidence_threshold"] == "CONFIDENCE_LEVEL_HIGH"
    px = added["ZBP-Credit Cards - Prox 500"]
    assert px["proximity"] == 500 and px["proximity_length_enabled"] is True
    iban = added["Bank-IBAN (Global)"]
    assert iban["proximity"] == 500 and iban["patterns"] and iban["phrases"]
    # Engines resolve the predefined dictionaries by tenant id.
    eng = {e["name"]: e for e in client.zia.dlp_engine.added}
    euiban = PREDEFINED.index("EUIBAN_LEAKAGE") + 1
    assert f"D{euiban}.S > 2" in eng["Bank-Account and Payment Instructions"]["engine_expression"]
    assert "D:" not in "".join(e["engine_expression"] for e in eng.values())
    # Every channel mirrors the inline (web) rules one-for-one: same count,
    # same engines, so Endpoint / SaaS / Email match Web DLP.
    web = [r["name"] for r in client.zia.dlp_web_rules.added]
    assert "Bank-Payment Card Data-Monitor" in web and "Bank-Customer PII-Bulk-Block" in web
    ep = [r["name"] for r in client.zia.endpoint_dlp_rules.added]
    saas = [r["name"] for r in client.zia.casb_dlp_rules.added]
    email = [r["name"] for r in client.zia.outbound_email_dlp_rules.added]
    # Web DLP is the cue: exactly one Endpoint, one SaaS and one Email rule per inline rule.
    assert len(ep) == len(web) and all(n.endswith("[Endpoint]") for n in ep)
    # The Endpoint mirror carries no data_transfer_method, so it covers removable media too.
    assert all("data_transfer_method" not in r for r in client.zia.endpoint_dlp_rules.added)
    assert len(saas) == len(web) and all(n.endswith("[SaaS]") for n in saas)
    assert len(email) == len(web) and all(n.endswith("[Email]") for n in email)
    # Nothing to do the second time: the baseline is in sync.
    rep2 = pd.preflight(client, [pk], writes_enabled=True)
    assert rep2["status"] == "blocked" and any("every policy pack object already exists" in b for b in rep2["blockers"])
    assert rep2["baselines"][0]["missing"] == 0 and rep2["baselines"][0]["in_sync"] == len(dicts) + len(engines) + len(policies)


def test_banking_and_zbp_packs_share_their_objects():
    """The reused ZBP dictionaries and engines are identical in both packs, so
    deploying them together collapses to one object each (no conflicts)."""
    packs = [_pack("zbp_enterprise_baseline"), _pack("global_banking_baseline")]
    client = _client()
    n = len(client.zia.dlp_dictionary.items)
    client.zia.dlp_dictionary.items += [Obj(id=n + i + 1, name=m, custom=False) for i, m in
                                        enumerate(("MEDICAL", "ML_MEDICAL_DOC_LEAKAGE", "DRUGS_LEAKAGE", "DISEASES_LEAKAGE"))]
    rep = pd.preflight(client, packs, writes_enabled=True)
    assert rep["status"] == "ready", rep["blockers"] + rep.get("warnings", [])
    names = [(i["kind"], i["name"]) for i in rep["items"] if i["kind"] in ("dictionary", "engine")]
    assert len(names) == len(set(names))
    shared = [i for i in rep["items"] if i["name"] == "ZBP-US PII"]
    assert len(shared) == 1 and set(shared[0]["packs"]) == {"zbp_enterprise_baseline", "global_banking_baseline"}
    assert not any(i["status"] == "conflict" for i in rep["items"])
