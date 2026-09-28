"""The ZIA API contract, enforced by the test tenant.

Every rule ZIA has answered with a 400 on a real tenant, plus its
documented limits, lives here so a pack is checked against the real
constraints before anyone deploys it. The strict tenant refuses what
ZIA refuses, with ZIA's own messages where they are known:

  dictionaries  description <= 255; proximity only on
                MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE, which needs a
                pattern and a phrase; <= 8 patterns of <= 256 bytes with no
                lookaround; <= 256 phrases of 3-128 bytes; a clone needs the
                id of a predefined dictionary this tenant has; unique names;
                no confidence score on a custom dictionary; a clone carries
                one; a clone of a hierarchical template names identifiers
  engines       name in [A-Za-z0-9_-. ()]; description <= 255; every D<id>.S
                names a dictionary the tenant has; match counts < 1000
  rules         unique names per channel; engines that exist; the channel's
                action set; ENABLED/DISABLED; RULE_SEVERITY_*; rank 0-7;
                Web protocols from the DLP set (NATIVE_FTP_RULE is refused as
                "Request body is invalid."); an endpoint rule names one
                transfer method ("Channel is mandatory"); SaaS rules carry
                their type and a tenant; email rules a tenant

Then every shipped pack is deployed on a tenant that exposes every
predefined dictionary the packs depend on, and nothing may fail; and the
whole set is removed again and the tenant read back empty.
"""
from __future__ import annotations

import glob
import json
import os
import re

import pytest

import pack_deploy as pd
import pack_removal as pr
from dlp_importer import PREDEFINED_DISPLAY_NAMES, discover_packs, find_refs, norm_name, template_candidates
from test_channel_targets_undo import _with_delete
from test_pack_channels import TENANTS, add_control_services, make_client, tenant as casb_tenant
from test_pack_deploy import FakeDicts, FakeEngines, Obj

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_NAME_RE = re.compile(r"^[A-Za-z0-9_\-. ()]+$")
_LOOKAROUND_RE = re.compile(r"\(\?<?[=!]")
_TERM_RE = re.compile(r"D(\d+)\.S")
_COUNT_RE = re.compile(r"[<>=]=?\s*(\d+)")
WEB_ACTIONS = {"ALLOW", "BLOCK", "CONFIRM", "ICAP_RESPONSE"}
ENDPOINT_ACTIONS = {"ALLOW", "BLOCK", "CONFIRM"}
EMAIL_ACTIONS = {"ALLOW", "BLOCK", "CUSTOMHEADERINSERTION"}
SEVERITIES = {"RULE_SEVERITY_HIGH", "RULE_SEVERITY_MEDIUM", "RULE_SEVERITY_LOW", "RULE_SEVERITY_INFO"}
# What a production tenant accepted on webDlpRules; NATIVE_FTP_RULE (a URL
# Filtering protocol) came back "Request body is invalid." with no code.
PROTOCOLS = {"HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "WEBSOCKET_RULE", "WEBSOCKETSSL_RULE", "ANY_RULE"}
TRANSFER_METHODS = {"REMOVABLE_DRIVE_TRANSFER", "NETWORK_DRIVE_TRANSFER", "APPLICATION_FILE_ACCESS", "PRINTING"}
# Predefined dictionaries whose clones must name identifiers.
HIERARCHICAL = {"USDL_LEAKAGE", "CRED_LEAKAGE", "EUIBAN_LEAKAGE", "PPEU_LEAKAGE", "ASPP_LEAKAGE"}


def _err(msg, code="INVALID_INPUT_ARGUMENT"):
    return None, None, {"status": 400, "code": code, "message": msg}


def _squash(name):
    """A name as ZIA compares it for duplicates: case and spacing ignored."""
    return " ".join(str(name or "").split()).casefold()


class StrictDicts(FakeDicts):
    def add_dict(self, name, match_type, dict_type, **kw):
        n = (name or "").strip()
        if not n:
            return _err("Dictionary name is required")
        # ZIA compares names without regard to case, and a predefined
        # dictionary's display name (its description: CRED_LEAKAGE is shown as
        # "Private Key") counts as taken too. Its answer, verbatim.
        taken = {_squash(getattr(i, "name", "")) for i in self.items}
        taken |= {_squash(getattr(i, "description", "")) for i in self.items if not getattr(i, "custom", True)}
        taken.discard("")
        if _squash(n) in taken:
            return _err(f"Duplicate DLP dictionary names are not allowed. [{n}].")
        if len(n) > 255:
            return _err("DLP Dictionary name can not be more than 255 characters.")
        if len(kw.get("description") or "") > 255:
            return _err("DLP Dictionary description can not be more than 255 characters.")
        pats = kw.get("patterns") or []
        phrs = kw.get("phrases") or []
        if kw.get("dict_template_id"):
            tid = kw["dict_template_id"]
            tpl = next((i for i in self.items if getattr(i, "id", None) == tid and not getattr(i, "custom", True)), None)
            if tpl is None:
                return _err(f"dictTemplateId {tid} is not a predefined dictionary")
            if not kw.get("confidence_threshold"):
                return _err("Dlp dictionary's confidenceThreshold can't be null")
            if str(getattr(tpl, "name", "")) in HIERARCHICAL and not kw.get("hierarchical_identifiers"):
                return None, None, {"status": 400, "code": None, "message": "Atleast 1 hierarchical identifier should be selected for hierarchical dictionaries"}
        else:
            if kw.get("confidence_threshold"):
                return _err("Confidence score value is not supported in custom dictionary")
            if not pats and not phrs:
                return _err("A custom dictionary needs at least one pattern or phrase")
            if len(pats) > 8:
                return _err("A dictionary can have at most 8 patterns")
            for p in pats:
                pat = p[1] if isinstance(p, (list, tuple)) else str(p)
                if len(pat.encode("utf-8")) > 256:
                    return _err("A pattern can be at most 256 characters")
                if _LOOKAROUND_RE.search(pat):
                    return _err("Invalid regex pattern")
            if len(phrs) > 256:
                return _err("A dictionary can have at most 256 phrases")
            for p in phrs:
                ph = p[1] if isinstance(p, (list, tuple)) else str(p)
                n_b = len(ph.strip('"').encode("utf-8"))
                if n_b < 3 or n_b > 128:
                    return _err("A phrase must be between 3 and 128 characters")
            if match_type == "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE" and (not pats or not phrs):
                return _err("'Match any Patterns and any Phrases' needs at least one pattern and one phrase")
        return super().add_dict(name, match_type, dict_type, **kw)   # proximity / match-type rule lives in the base fake


class StrictEngines(FakeEngines):
    def __init__(self, items=None, dicts=None):
        super().__init__(items)
        self.dicts = dicts

    def add_dlp_engine(self, **kw):
        n = (kw.get("name") or "").strip()
        if any(str(getattr(i, "name", "")) == n for i in self.items):
            return _err(f"A DLP engine named '{n}' already exists", "DUPLICATE_ITEM")
        expr = kw.get("engine_expression") or ""
        ids = {str(getattr(d, "id")) for d in (self.dicts.items if self.dicts else [])}
        missing = sorted({m for m in _TERM_RE.findall(expr) if m not in ids})
        if not _TERM_RE.search(expr):
            return _err("Engine expression must reference at least one dictionary")
        if missing:
            return _err("Invalid dictionary id(s) in engine expression: " + ", ".join(missing))
        if any(int(c) >= 1000 for c in _COUNT_RE.findall(expr)):
            return _err("Match count must be less than 1000")
        if expr.count("(") != expr.count(")"):
            return _err("Unbalanced parentheses in engine expression")
        return super().add_dlp_engine(**kw)   # name charset and description length live in the base fake


def _strict_rules(svc, channel, engines, casb=None, admin_rank=None):
    """Wrap a channel service's add_rule with the ZIA contract for rules.
    `admin_rank` models a real tenant's answer on SaaS rules: the API
    client's admin rank was such that a rank-0 rule came back 403
    RBA_LIMITED 'Rule rank is higher than the admin rank.' — modelled as
    'a rank below admin_rank is refused'."""
    real_add = svc.add_rule

    def add_rule(*args, **kw):
        n = (kw.get("name") or "").strip()
        if not n:
            return _err("Rule name is required")
        if any(str(getattr(i, "name", "")) == n for i in svc.items):
            return _err(f"A rule named '{n}' already exists on this channel", "DUPLICATE_ITEM")
        if kw.get("state") not in ("ENABLED", "DISABLED"):
            return _err(f"Invalid state {kw.get('state')}")
        if len(kw.get("description") or "") > 10240:
            return _err("Rule description can not be more than 10240 characters.")
        if kw.get("severity") is not None and kw["severity"] not in SEVERITIES:
            return _err(f"Invalid severity {kw['severity']}")
        if kw.get("rank") is not None and not (0 <= int(kw["rank"]) <= 7):
            return _err("Rank must be between 0 and 7")
        eids = {str(getattr(e, "id")) for e in engines.items}
        refs = [str(x["id"] if isinstance(x, dict) else x) for x in (kw.get("dlp_engines") or [])]
        if not refs:
            return _err("A DLP rule needs at least one engine")
        if any(r not in eids for r in refs):
            return _err("Invalid DLP engine id: " + ", ".join(r for r in refs if r not in eids))
        act = kw.get("action")
        if channel == "web":
            if act not in WEB_ACTIONS:
                return _err(f"Invalid action {act}")
            if set(kw.get("protocols") or []) - PROTOCOLS:
                return None, None, {"status": 400, "code": None, "message": "Request body is invalid."}
        elif channel == "endpoint":
            if act not in ENDPOINT_ACTIONS:
                return _err(f"Invalid action {act}")
            if len(refs) > 4:
                return _err("Exceeded maximum number of DLP engines: 4")
            if not kw.get("data_transfer_method"):
                return _err("Channel is mandatory")
            if kw["data_transfer_method"] not in TRANSFER_METHODS:
                return None, None, {"status": 400, "code": None, "message": "Request body is invalid."}
        elif channel == "saas":
            if len(n) > 31:
                return _err("Name exceeds the max length 31 characters")
            if admin_rank is not None and int(kw.get("rank", 7) or 0) < admin_rank:
                return None, None, {"status": 403, "code": "RBA_LIMITED", "message": "Rule rank is higher than the admin rank.",
                                    "url": "https://api.zsapi.net/zia/api/v1/casbDlpRules"}
            if not str(act or "").startswith("OFLCASB_DLP_"):
                return _err(f"Invalid action {act}")
            if not kw.get("type"):
                return _err("ruleType is required")
            if not kw.get("cloud_app_tenants"):
                return _err("At least one cloud application tenant is required")
            # The tenant's own rule of this type stays last: a rank-7 rule may
            # take any order up to it (it shifts down), not one beyond it.
            same = [i for i in svc.items if str(getattr(i, "type", "")) == str(kw["type"])]
            if same and int(kw.get("order") or 0) > len(same):
                return _err(f"Rule with rank {kw.get('rank', 7)} is not allowed at order {kw.get('order')}")
            for i in same:
                if int(getattr(i, "order", 0) or 0) >= int(kw.get("order") or 0):
                    i.order = int(getattr(i, "order", 0) or 0) + 1
        elif channel == "email":
            if act not in EMAIL_ACTIONS:
                return _err(f"Invalid action {act}")
            if not kw.get("email_tenants"):
                return _err("At least one email tenant is required")
        return real_add(*args, **kw)
    svc.add_rule = add_rule
    return svc


# Every predefined dictionary the shipped packs depend on, as a tenant
# exports them: some by API code with the display name in the description,
# some by display name.
PREDEFINED = [
    ("SSN", "Social Security Numbers (US)"), ("USITIN_LEAKAGE", "Tax Identification Number (US)"), ("USDL_LEAKAGE", "Driver's License (United States)"),
    ("ABA_LEAKAGE", "ABA Bank Routing Number"), ("CREDIT_CARD", "Credit Cards"), ("CRED_LEAKAGE", "Private Key"), ("EUIBAN_LEAKAGE", "IBAN"),
    ("ASPP_LEAKAGE", "Adult Content"), ("PPEU_LEAKAGE", "Passport (EU)"), ("FINANCIAL", "Financial Statements"), ("ML_CORPORATE_FINANCE_LEAKAGE", "Corporate Finance"),
    ("ML_TAX_LEAKAGE", "Tax"), ("ML_MEDICAL_DOC_LEAKAGE", "Medical Document"), ("MEDICAL", "Medical Information"), ("DRUGS_LEAKAGE", "Drugs Information"),
    ("DISEASES_LEAKAGE", "Diseases Information"), ("Treatments Information", ""), ("Medical Imaging", ""), ("Insurance Document", ""),
    ("NDC Number (Package)", ""), ("NDC Number (Product)", ""), ("Names (US)", ""), ("National Provider Identifier", ""),
    ("Enhanced Driver's License (United States)", ""), ("Self-Harm & Cyberbullying", ""), ("Illegal Drugs", ""),
]


# A SaaS rule the customer made in the portal (rank 0) that ZIA keeps last.
TENANT_SAAS_RULE = Obj(id=8400, name="Customer SaaS rule", order=1, rank=0, type="OFLCASB_DLP_FILE", state="ENABLED",
                       action="OFLCASB_DLP_REPORT_INCIDENT", dlp_engines=[], description="made in the portal")


def strict_tenant(saas_admin_rank=None):
    client = add_control_services(make_client(casb_tenants=TENANTS + [casb_tenant("Acme Exchange", "EXCHANGE", 505)],
                                              saas_rules=[Obj(**TENANT_SAAS_RULE.as_dict())]))
    z = client.zia
    z.dlp_dictionary = StrictDicts([Obj(id=i + 1, name=n, description=d, custom=False) for i, (n, d) in enumerate(PREDEFINED)])
    z.dlp_engine = StrictEngines([], dicts=z.dlp_dictionary)
    _strict_rules(z.dlp_web_rules, "web", z.dlp_engine)
    _strict_rules(z.endpoint_dlp_rules, "endpoint", z.dlp_engine)
    _strict_rules(z.casb_dlp_rules, "saas", z.dlp_engine, admin_rank=saas_admin_rank)
    _strict_rules(z.outbound_email_dlp_rules, "email", z.dlp_engine)
    return _with_delete(client)   # after the swap, so the strict services get their delete methods


def _packs():
    return [{"id": p["id"], "dir": p["dir"]} for p in discover_packs()]


def test_the_contract_refuses_what_zia_refuses():
    c = strict_tenant(); z = c.zia
    assert z.dlp_dictionary.add_dict("Long", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", description="x" * 256, phrases=[("PHRASE_COUNT_TYPE_ALL", "alpha beta")])[2]["message"].startswith("DLP Dictionary description")
    assert "Proximity" in z.dlp_dictionary.add_dict("Prox", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", proximity=50, patterns=[("PATTERN_COUNT_TYPE_ALL", r"\d{6}")], phrases=[("PHRASE_COUNT_TYPE_ALL", "mrn number")])[2]["message"]
    assert "pattern and one phrase" in z.dlp_dictionary.add_dict("NoPhrase", "MATCH_CUSTOM_ANY_PATTERN_WITH_ANY_PHRASE", "PATTERNS_AND_PHRASES", patterns=[("PATTERN_COUNT_TYPE_ALL", r"\d{6}")])[2]["message"]
    assert "predefined" in z.dlp_dictionary.add_dict("Clone", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", dict_template_id=999999, custom=True)[2]["message"]
    # The CJIS deploy log, verbatim.
    assert "not supported in custom dictionary" in z.dlp_dictionary.add_dict("Conf", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", confidence_threshold="CONFIDENCE_LEVEL_HIGH", phrases=[("PHRASE_COUNT_TYPE_ALL", "alpha beta")])[2]["message"]
    ssn = next(i.id for i in z.dlp_dictionary.items if i.name == "SSN"); usdl = next(i.id for i in z.dlp_dictionary.items if i.name == "USDL_LEAKAGE")
    assert "confidenceThreshold can't be null" in z.dlp_dictionary.add_dict("SSN Clone", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", dict_template_id=ssn, custom=True)[2]["message"]
    assert "hierarchical identifier" in z.dlp_dictionary.add_dict("DL Clone", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", dict_template_id=usdl, custom=True, confidence_threshold="CONFIDENCE_LEVEL_HIGH")[2]["message"]
    dl, _, err = z.dlp_dictionary.add_dict("DL Clone", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", dict_template_id=usdl, custom=True, confidence_threshold="CONFIDENCE_LEVEL_HIGH", hierarchical_identifiers=["USDL_CA"])
    assert dl and not err
    ok, _, err = z.dlp_dictionary.add_dict("Fine", "MATCH_ANY_CUSTOM_PHRASE_PATTERN_DICTIONARY", "PATTERNS_AND_PHRASES", phrases=[("PHRASE_COUNT_TYPE_ALL", "alpha beta")])
    assert ok and not err
    assert "Invalid dictionary id" in z.dlp_engine.add_dlp_engine(name="E1", engine_expression="((D424242.S > 0))", custom_dlp_engine=True)[2]["message"]
    assert "INVALID_NAME" == z.dlp_engine.add_dlp_engine(name="A / B", engine_expression=f"((D{ok.id}.S > 0))", custom_dlp_engine=True)[2]["code"]
    e, _, err = z.dlp_engine.add_dlp_engine(name="E1", engine_expression=f"((D{ok.id}.S > 0))", custom_dlp_engine=True, description="ok")
    assert e and not err
    assert "Invalid DLP engine id" in z.dlp_web_rules.add_rule(name="R1", state="DISABLED", action="ALLOW", dlp_engines=[424242], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_INFO", rank=7, order=1)[2]["message"]
    r, _, err = z.dlp_web_rules.add_rule(name="R1", state="DISABLED", action="ALLOW", dlp_engines=[e.id], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_INFO", rank=7, order=1)
    assert r and not err
    assert "already exists" in z.dlp_web_rules.add_rule(name="R1", state="DISABLED", action="ALLOW", dlp_engines=[e.id], protocols=["HTTPS_RULE"], severity="RULE_SEVERITY_INFO", rank=7, order=2)[2]["message"]
    assert z.dlp_web_rules.add_rule(name="R2", state="DISABLED", action="ALLOW", dlp_engines=[e.id], protocols=["HTTP_RULE", "HTTPS_RULE", "FTP_RULE", "NATIVE_FTP_RULE"], severity="RULE_SEVERITY_INFO", rank=7, order=1)[2]["message"] == "Request body is invalid."
    assert z.endpoint_dlp_rules.add_rule(name="E1", state="DISABLED", action="ALLOW", dlp_engines=[{"id": e.id}], severity="RULE_SEVERITY_INFO", rank=7, order=1)[2]["message"] == "Channel is mandatory"
    assert z.endpoint_dlp_rules.add_rule(name="E1", state="DISABLED", action="ALLOW", dlp_engines=[{"id": e.id}], severity="RULE_SEVERITY_INFO", rank=7, order=1, data_transfer_method="ANY")[2]["message"] == "Request body is invalid."
    ep, _, err = z.endpoint_dlp_rules.add_rule(name="E1", state="DISABLED", action="ALLOW", dlp_engines=[{"id": e.id}], severity="RULE_SEVERITY_INFO", rank=7, order=1, data_transfer_method="REMOVABLE_DRIVE_TRANSFER")
    assert ep and not err
    # Endpoint DLP allows at most four engines on one rule (the old Fed pack's 17-engine extension rule was refused this way).
    assert z.endpoint_dlp_rules.add_rule(name="E5", state="DISABLED", action="ALLOW", dlp_engines=[{"id": e.id}] * 5, severity="RULE_SEVERITY_INFO", rank=7, order=1, data_transfer_method="REMOVABLE_DRIVE_TRANSFER")[2]["message"] == "Exceeded maximum number of DLP engines: 4"
    assert "ruleType" in z.casb_dlp_rules.add_rule(name="S1", state="DISABLED", action="OFLCASB_DLP_REPORT_INCIDENT", dlp_engines=[{"id": e.id}], order=1, cloud_app_tenants=[{"id": 501}])[2]["message"]
    saas = dict(state="DISABLED", action="OFLCASB_DLP_REPORT_INCIDENT", dlp_engines=[{"id": e.id}], type="OFLCASB_DLP_FILE", cloud_app_tenants=[{"id": 501}], rank=7)
    assert z.casb_dlp_rules.add_rule(name="SRC-JavaScript Code to AI [SaaS]", order=1, **saas)[2]["message"] == "Name exceeds the max length 31 characters"
    assert z.casb_dlp_rules.add_rule(name="S2", order=2, **saas)[2]["message"] == "Rule with rank 7 is not allowed at order 2"
    s2, _, err = z.casb_dlp_rules.add_rule(name="S2", order=1, **saas)
    assert s2 and not err and TENANT_SAAS_RULE.order == 1 and next(i for i in z.casb_dlp_rules.items if i.id == 8400).order == 2


@pytest.mark.parametrize("pack_id", [p["id"] for p in discover_packs()])
def test_every_shipped_pack_deploys_on_the_strict_tenant(pack_id):
    """On a tenant that exposes the predefined dictionaries the packs
    depend on, every object of every pack is created: nothing failed,
    nothing blocked, nothing skipped."""
    client = strict_tenant()
    pack = next(p for p in _packs() if p["id"] == pack_id)
    rep = pd.preflight(client, [pack], writes_enabled=True)
    assert rep["status"] != "blocked", rep["blockers"]
    bad = [(i["kind"], i["name"], i["status"], i.get("reason")) for i in rep["items"]
           if i["status"] not in (pd.CREATE, pd.REUSE) and not (i["kind"] == "tweak" and i["status"] == "modify")]
    assert not bad, bad
    res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
    problems = [(r["kind"], r["name"], r["status"], r.get("error") or r.get("reason")) for r in res["results"] if r["status"] not in ("created", "reused", "modified")]
    assert not problems, problems
    assert res["summary"].get("failed", 0) == 0 and res["summary"].get("skipped", 0) == 0
    # Every channel got the same number of rules: the mirror convention held all the way to the tenant.
    z = client.zia
    counts = {"web": len(z.dlp_web_rules.added), "endpoint": len(z.endpoint_dlp_rules.added), "saas": len(z.casb_dlp_rules.added), "email": len(z.outbound_email_dlp_rules.added)}
    assert len(set(counts.values())) == 1 and counts["web"] > 0, counts
    # What reached the tenant is what the CJIS and Source Code logs said it must be.
    assert all(len(r["name"]) <= 31 for r in z.casb_dlp_rules.added)
    orders = sorted(int(getattr(i, "order", 0)) for i in z.casb_dlp_rules.items if getattr(i, "type", "") == "OFLCASB_DLP_FILE")
    assert orders == list(range(1, len(orders) + 1)) and max(orders) == getattr(next(i for i in z.casb_dlp_rules.items if i.id == 8400), "order"), "every SaaS rule has its own order and the customer's rule stayed last"
    assert all(r["data_transfer_method"] in TRANSFER_METHODS for r in z.endpoint_dlp_rules.added)
    assert all(not (set(r["protocols"]) - PROTOCOLS) for r in z.dlp_web_rules.added)
    for d in z.dlp_dictionary.added:
        if d.get("dict_template_id"):
            assert d.get("confidence_threshold"), d["name"]
        else:
            assert "confidence_threshold" not in d and "hierarchical_identifiers" not in d, d["name"]


def test_every_shipped_pack_removes_cleanly_from_the_strict_tenant():
    client = strict_tenant()
    packs = _packs()
    for pack in packs:
        rep = pd.preflight(client, [pack], writes_enabled=True)
        res = pd.apply(client, [pack], plan_hash=rep["plan_hash"], writes_enabled=True, verify=False)
        assert res["summary"].get("failed", 0) == 0, (pack["id"], res["summary"])
    plan = pr.plan_removal(client, packs, everything=True)
    assert plan["status"] == "ready" and plan["keep_count"] == 0
    res = pr.remove(client, packs, plan_hash=plan["plan_hash"], writes_enabled=True, everything=True)
    assert res["status"] == "removed" and res["verification"]["clean"], res["verification"]["remaining"][:5]
    z = client.zia
    assert not z.dlp_engine.items and not z.dlp_web_rules.items and not z.endpoint_dlp_rules.items and not z.outbound_email_dlp_rules.items
    assert [i.name for i in z.casb_dlp_rules.items] == ["Customer SaaS rule"], "the customer's own SaaS rule is untouched"
    assert all(not getattr(d, "custom", True) for d in z.dlp_dictionary.items), "only the tenant's predefined dictionaries remain"


def test_every_predefined_name_the_packs_use_is_in_the_strict_tenant():
    """Keep PREDEFINED honest: a new pack reference must be added here so
    the deploy test above keeps meaning what it says."""
    known = {n for n, _ in PREDEFINED} | {d for _, d in PREDEFINED if d}
    for f in sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_dictionaries.json"))):
        ds = json.load(open(f, encoding="utf-8")); names = {d["name"] for d in ds}
        for d in ds:
            if d.get("predefined_clone"):
                assert any(c in known for c in template_candidates(d.get("dict_template_name"))), (f, d["name"], d.get("dict_template_name"))
        for e in json.load(open(f.replace("dlp_dictionaries", "dlp_engines"), encoding="utf-8")):
            for r in find_refs(e["expression"]):
                r = r.strip()
                assert not r or r in names or r in known, (f, e["name"], r)


def test_the_strict_tenant_display_names_are_known_to_the_loader_and_no_shipped_pack_needs_the_rename():
    """Every name the strict tenant shows a predefined dictionary under is
    one heal_predefined_names renames a pack dictionary away from (the
    two lists must move together), and no shipped pack carries such a
    name: the rename exists for uploads, and a built-in pack that relied
    on it would deploy under a name its JSON does not show."""
    for code, disp in PREDEFINED:
        assert norm_name(disp or code) in PREDEFINED_DISPLAY_NAMES, (code, disp)
    for f in sorted(glob.glob(os.path.join(ROOT, "*", "configs", "dlp_dictionaries.json"))):
        for d in json.load(open(f, encoding="utf-8")):
            assert norm_name(d["name"]) not in PREDEFINED_DISPLAY_NAMES, (f, d["name"])
