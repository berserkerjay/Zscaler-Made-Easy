"""A predefined dictionary resolves by its API name or its portal display
name, whichever the tenant exports, so the CJIS/Fed packs (display names)
and the ZBP/banking packs (API names) both plan against either tenant."""
from __future__ import annotations

import pack_deploy as pd
from dlp_importer import build_dict_kwargs, resolve_template, template_candidates
from test_pack_channels import add_control_services, make_client
from test_pack_deploy import Obj


def _pack(pid):
    from dlp_importer import discover_packs
    p = next(p for p in discover_packs() if p["id"] == pid)
    return {"id": p["id"], "dir": p["dir"]}


def test_resolve_template_accepts_either_name():
    assert resolve_template("Social Security Numbers (US)", {"SSN": 11}) == 11
    assert resolve_template("SSN", {"Social Security Numbers (US)": 12}) == 12
    assert resolve_template("CREDIT_CARD", {"CREDIT_CARD": 3, "Credit Cards": 4}) == 3     # exact name first
    assert resolve_template("Unknown Thing", {"SSN": 1}) is None
    assert template_candidates("USDL_LEAKAGE") == ["USDL_LEAKAGE", "Drivers License (United States)"]
    kw, err = build_dict_kwargs({"name": "x", "predefined_clone": True, "dict_template_name": "Drivers License (United States)", "proximity": 500}, {"USDL_LEAKAGE": 77})
    assert err is None and kw["dict_template_id"] == 77


def test_cjis_pack_plans_against_a_tenant_that_exports_api_names():
    client = add_control_services(make_client())
    client.zia.dlp_dictionary.items = [Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(["SSN", "USDL_LEAKAGE"])]
    rep = pd.preflight(client, [_pack("cjis_policy_pack")], writes_enabled=True)
    clones = [i for i in rep["items"] if i["kind"] == "dictionary" and "CJIS Prox 500" in i["name"] and i["name"].startswith(("Social", "Drivers"))]
    assert clones and all(i["status"] == pd.CREATE for i in clones), [(i["name"], i["status"], i.get("reason")) for i in clones]
    assert not [d for d in rep.get("dependencies", []) if d.get("kind") == "predefined" and d.get("missing")]


def test_banking_pack_plans_against_a_tenant_that_exports_display_names():
    client = add_control_services(make_client())
    names = ["Credit Cards", "ABA Bank Routing Number", "Social Security Numbers (US)", "Tax Identification Number (US)", "Drivers License (United States)",
             "Credentials Leakage", "International Bank Account Number (EU)", "PPEU_LEAKAGE", "ASPP_LEAKAGE", "Financial Statements", "ML_CORPORATE_FINANCE_LEAKAGE", "ML_TAX_LEAKAGE"]
    client.zia.dlp_dictionary.items = [Obj(id=i + 1, name=n, custom=False) for i, n in enumerate(names)]
    rep = pd.preflight(client, [_pack("global_banking_baseline")], writes_enabled=True)
    clones = [i for i in rep["items"] if i["kind"] == "dictionary" and i["name"].startswith("ZBP-Credit Cards")]
    assert clones and all(i["status"] == pd.CREATE for i in clones), [(i["name"], i["status"], i.get("reason")) for i in clones]
