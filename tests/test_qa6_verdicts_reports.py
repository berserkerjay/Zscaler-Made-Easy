"""Functional QA (wave 6): the verdicts and reports that tell an operator
what will happen: readiness for every role, licence and scope combination
(the classic sign-in, the ZPA customer ID and token-only products included),
the snapshot comparison, and the POV runbook, Prove it and the customer
report in Word and PDF, opened and read back as text.

Fakes only (tests/test_readiness.py's SDK fake, the POV route fixtures of
tests/test_pov.py); no network, no clock, stores in tmp_path."""
from __future__ import annotations

import copy
import io
import itertools
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import offline_tenant as ot  # noqa: E402
import pov  # noqa: E402
import readiness as rd  # noqa: E402
import sample_tenant  # noqa: E402
import test_readiness as T  # noqa: E402
from test_pov import CREDS, SECRET, WEB, _profile, _start, app  # noqa: E402,F401  (app is a fixture)

# ── Readiness: a table of roles, licences, scopes and sign-ins ───────────

READ_ROLE = {"id": 4711, "name": "Assessment API role", "policyAccess": "READ_ONLY",
             "featurePermissions": {k: "READ_ONLY" for k in rd.ZIA_PERMS}}
NO_DLP_ROLE = {"id": 4711, "name": "Assessment API role", "policyAccess": "READ_WRITE",
               "featurePermissions": {k: "READ_WRITE" for k in rd.ZIA_PERMS if k not in ("INLINE_DLP", "DLP_DICTIONARIES_ENGINES")}}
NO_DLP_SUBS = [s for s in T.SUBS if s["id"] not in rd.DLP_SKUS]
ZPA_VIEW = [{"id": "216", "name": "API Full Access", "classPermissionGroups": [{"classPermissions": [
    {"classType": {"friendlyName": "Application Segment"}, "permission": {"type": "VIEW_ONLY"}},
    {"classType": {"friendlyName": "Policy"}, "permission": {"type": "FULL"}}]}]}]
ZCC_FULL = [{"id": 9, "roleName": "Read Only Admin", "deviceOverview": 2, "forwardingProfile": 2, "windowsProfile": 2, "macProfile": 2,
             "trustedNetwork": 2}]
TOKEN_ONLY = T.jwt({"service-info": T.SERVICE_INFO + [{"prd": "ZIAM", "ext": {"rnm": "ZIdentity Reader"}},
                                                      {"prd": "ZTW", "ext": {"rnm": "Connector Admin"}}],
                    "exp": T.NOW + 3600, "iat": T.NOW})

ROLES = {"full": dict(role=T.FULL_ROLE), "read_only": dict(role=READ_ROLE), "no_dlp": dict(role=NO_DLP_ROLE)}
LICENCES = {"licensed": dict(subs=T.SUBS), "no_dlp_sku": dict(subs=NO_DLP_SUBS)}
SCOPES = {"dlp": ["dlp"], "dlp+zpa+zcc": ["dlp", "zpa", "zcc"], "everything": ["dlp", "zia_extras", "zpa", "zcc", "zdx", "insights", "aiguard"]}
CASES = list(itertools.product(ROLES, LICENCES, SCOPES))


def _verdict(role, licence, scopes, **kw):
    client = T.Fake(**ROLES[role], **LICENCES[licence], **kw.pop("fake", {}))
    return T.by_key(T.facts_for(client, SCOPES[scopes], **kw))


@pytest.mark.parametrize("role,licence,scopes", CASES, ids=["-".join(c) for c in CASES])
def test_readiness_verdicts_follow_the_role_the_licence_and_the_scope(role, licence, scopes):
    """ASVS V1.4.4 · V4.1.3 · CWE-284 · CWE-863: every write feature's verdict follows from the role, the licence and the Scope page, never 'Will work' on no evidence."""
    k = _verdict(role, licence, scopes)
    deploy = k["deploy_packs"]["status"]
    if role == "full" and licence == "licensed":
        assert deploy == "ok"
    elif role == "read_only":
        assert deploy == "read_only"
    elif role == "no_dlp":
        assert deploy == "blocked"
    else:
        assert deploy == "not_licensed"
    assert k["dlp"]["status"] == ("blocked" if role == "no_dlp" else "not_licensed" if licence == "no_dlp_sku" else "ok")
    in_scope = set(SCOPES[scopes])
    for feature, scope in (("zpa_builder", "zpa"), ("zpa_segment_moves", "zpa"), ("zcc_builder", "zcc")):
        if scope not in in_scope:
            assert k[feature]["status"] == "not_in_scope", (feature, k[feature])
        else:
            assert k[feature]["status"] in ("ok", "read_only", "blocked"), (feature, k[feature])
    if "zcc" in in_scope:
        assert k["zcc_builder"]["status"] == "read_only"          # the token's ZCC role is read only
    for token_only in ("zidentity", "ztw"):
        assert k[token_only]["status"] in ("blocked", "unknown", "ok")
    for f in k.values():
        if f["status"] in ("blocked", "not_licensed", "read_only"):
            assert f["why"] and (f["steps"] or f["status"] == "read_only" or f["key"] in ("zdx", "zdx_probes", "aiguard", "aiguard_builders",
                                                                                          "zidentity", "ztw")), f


def test_a_missing_zpa_customer_id_blocks_every_zpa_feature_with_the_same_steps():
    """ASVS V1.4.4 · CWE-284: without the ZPA customer ID the ZPA scope and the ZPA builders say 'Will not work' with the steps to add it, not 'Not checked'."""
    k = _verdict("full", "licensed", "dlp+zpa+zcc", customer_id="")
    for key in ("zpa", "zpa_builder", "zpa_segment_moves"):
        assert k[key]["status"] == "blocked" and "customer ID" in k[key]["why"], (key, k[key])
        assert k[key]["steps"] == rd._steps_customer_id()


def test_a_zpa_role_that_cannot_change_segments_reads_only_for_the_segment_features():
    """ASVS V1.4.4 · CWE-284: a ZPA role with view-only application segments makes segment moves and the builder read only."""
    k = _verdict("full", "licensed", "dlp+zpa+zcc", fake={"zpa_roles": ZPA_VIEW})
    assert k["zpa_segment_moves"]["status"] == "read_only" and "Application Segment" in k["zpa_segment_moves"]["why"]
    assert k["zpa_builder"]["status"] == "read_only"


def test_a_full_zcc_role_makes_the_client_connector_builder_work():
    """ASVS V1.4.4 · CWE-284: a Client Connector role with full access to the profiles it writes: the builder will work."""
    k = _verdict("full", "licensed", "dlp+zpa+zcc", fake={"zcc_roles": ZCC_FULL})
    assert k["zcc_builder"]["status"] == "ok"


def test_the_classic_sign_in_judges_only_zia_and_never_claims_the_other_products():
    """ASVS V1.4.4 · CWE-284: the classic ZIA API sign-in: ZIA writes are 'Not checked' (no API role to read); every other product's feature will not work."""
    client = T.Fake(token=None)
    k = T.by_key(rd.evaluate(rd.read(client, SCOPES["everything"], auth_method="legacy", customer_id="7210000000000", now=T.NOW)))
    assert k["deploy_packs"]["status"] == "unknown"
    for key in ("zpa", "zcc", "zdx", "insights", "aiguard", "zpa_builder", "zcc_builder", "zdx_probes", "aiguard_builders"):
        assert k[key]["status"] == "blocked", (key, k[key])
    assert not any(f["status"] == "ok" for key, f in k.items() if key not in ("dlp", "zia_extras", "genai", "automation", "rbac"))


def test_token_only_products_are_judged_from_the_token():
    """ASVS V1.4.4 · CWE-284: ZIdentity and Cloud & Branch Connector are never read: with a role in the token they can read, without one they will not work."""
    with_role = T.by_key(T.facts_for(T.Fake(token=TOKEN_ONLY), ["dlp", "zidentity", "ztw"]))
    without = T.by_key(T.facts_for(T.Fake(), ["dlp", "zidentity", "ztw"]))
    assert with_role["zidentity"]["status"] == "ok" and with_role["ztw"]["status"] == "ok"
    assert without["zidentity"]["status"] == "blocked" and without["ztw"]["status"] == "blocked"


# ── Snapshot compare ─────────────────────────────────────────────────────

def _sample():
    return {ot.normalize_path(p): {"status": 200, "body": b} for p, b in copy.deepcopy(sample_tenant.responses()).items()}


def test_an_identical_snapshot_reports_nothing():
    """ASVS V7.1.1 · CWE-440: comparing the sample tenant with itself finds no added, removed or changed object."""
    d = ot.compare(_sample(), _sample())
    assert d["same"] and d["lists"] == [] and d["totals"] == {"added": 0, "removed": 0, "changed": 0}


EDITS = {
    "zia-list": ("/zia/api/v1/webDlpRules", lambda b: b.append({"id": 999, "name": "New rule"}), "added", "New rule"),
    "zia-remove": ("/zia/api/v1/urlFilteringRules", lambda b: b.pop(0), "removed", "Block gambling"),
    "zia-change": ("/zia/api/v1/urlFilteringRules", lambda b: b[0].update(action="ALLOW"), "changed", "Block gambling"),
    "zpa-envelope": ("/zpa/mgmtconfig/v1/admin/customers/{customerId}/application", lambda b: b["list"].append({"id": "77", "name": "HR"}), "added", "HR"),
    "zcc-envelope": ("/zcc/papi/public/v1/webTrustedNetwork/listByCompany", lambda b: b["trustedNetworkContracts"].pop(0), "removed", None),
    "settings": ("/zia/api/v1/advancedSettings", lambda b: b.update(enableOffice365=False), "changed", "(settings)"),
}


@pytest.mark.parametrize("edit", list(EDITS))
def test_compare_finds_an_add_a_remove_and_a_change_in_every_list_shape(edit):
    """ASVS V7.1.1 · CWE-440: a list (ZIA), an envelope (ZPA, Client Connector) and a settings object each report the one change made."""
    path, fn, kind, name = EDITS[edit]
    old, new = _sample(), _sample()
    fn(new[path]["body"])
    d = ot.compare(old, new)
    assert not d["same"] and d["totals"][kind] == 1 and sum(d["totals"].values()) == 1, d["totals"]
    row = d["lists"][0]
    assert row["path"] == path and (name is None or name in row[kind])


def test_the_same_change_in_two_products_lists_is_counted_in_both():
    """ASVS V7.1.1 · CWE-440: ZIA and ZDX both have locations: an object added to each is two changes, each named with its product."""
    old, new = _sample(), _sample()
    new["/zia/api/v1/locations"]["body"].append({"id": 9991, "name": "Branch 7"})
    new["/zdx/v1/administration/locations"]["body"].append({"id": 9992, "name": "Branch 7"})
    d = ot.compare(old, new)
    assert d["totals"]["added"] == 2
    assert sorted(r["what"] for r in d["lists"]) == ["Locations", "ZDX locations"]


def test_one_list_served_on_two_paths_is_counted_once():
    """ASVS V7.1.1 · CWE-440: SaaS DLP rules answer on casbDlpRules and casbDlpRules/all: one new rule is one change."""
    old, new = _sample(), _sample()
    rule = {"id": 4242, "name": "New SaaS rule"}
    new["/zia/api/v1/casbDlpRules"]["body"].append(rule)
    if new["/zia/api/v1/casbDlpRules/all"]["body"] is not new["/zia/api/v1/casbDlpRules"]["body"]:
        new["/zia/api/v1/casbDlpRules/all"]["body"].append(copy.deepcopy(rule))
    assert ot.compare(old, new)["totals"]["added"] == 1


def test_change_times_and_secret_values_are_not_changes():
    """ASVS V7.1.1 · CWE-440: a new modified time or a secret field's value is never reported (the snapshot keeps no secret)."""
    old, new = _sample(), _sample()
    new["/zia/api/v1/urlFilteringRules"]["body"][0]["lastModifiedTime"] = 99
    old["/zia/api/v1/adminUsers"]["body"][0]["password"] = "(set)"
    new["/zia/api/v1/adminUsers"]["body"][0]["password"] = "a-new-secret"
    assert ot.compare(old, new)["same"]


# ── POV: runbook, criteria, Prove it, the report in Word and PDF ─────────

def test_every_runbook_test_is_provable_or_says_how_it_is_proved():
    """ASVS V1.1.1 · CWE-1059: each runbook test names a known product and either a web destination with an expected verdict, or how it is proved instead."""
    for t in pov.RUNBOOK:
        assert t["product"] in pov.PRODUCTS and t["steps"] and t["expect"]
        assert (t["destination"] and t["check"] in pov.CHECKS) or t["prove_note"], t["id"]
    for v in pov.VERTICALS.values():
        assert v["criteria"] and set(v["products"]) <= set(pov.PRODUCTS)


@pytest.mark.parametrize("tid,outcome,decrypted,agrees", [
    ("url-allowed", "blocked", True, False), ("url-allowed", "none", True, True), ("url-allowed", "bypassed", False, False),
    ("apps-genai", "blocked", True, False), ("apps-fileshare", "monitor", True, True),
    ("url-block", "blocked", True, True), ("ssl-exempt", "blind", False, True), ("dlp-upload", "metadata_only", True, False),
])
def test_prove_it_judges_each_runbook_test_by_what_it_expects(tid, outcome, decrypted, agrees):
    """ASVS V1.1.1 · CWE-754 · CWE-440: a site that must keep working is not 'agreed' when the analyzer finds it blocked; each test's own expectation decides."""
    t = pov.RUNBOOK_BY_ID[tid]
    ev = pov.prove_evidence(t, {"verdict": {"outcome": outcome, "headline": "h", "decrypted": decrypted, "reaches_zscaler": outcome != "bypassed"},
                                "destination": {"host": t["destination"]}})
    assert ev["verdict"]["agrees"] is agrees


def _pdf_text(data: bytes) -> str:
    """The text the app's PDF writer drew: its literal strings shown with Tj (uncompressed, WinAnsi, octal escapes)."""
    raw = data.decode("latin-1")
    out = []
    for m in re.finditer(r"\(((?:\\.|[^\\)])*)\)\s*Tj", raw):
        s = re.sub(r"\\([0-7]{3})", lambda x: chr(int(x.group(1), 8)), m.group(1))
        s = re.sub(r"\\(.)", r"\1", s)
        out.append(s.encode("latin-1").decode("cp1252", errors="replace"))
    return " ".join(" ".join(out).split())


def _docx_text(data: bytes) -> str:
    from docx import Document
    d = Document(io.BytesIO(data))
    parts = [p.text for p in d.paragraphs]
    for t in d.tables:
        for row in t.rows:
            parts.extend(c.text for c in row.cells)
    return " ".join(" ".join(parts).split())


def test_the_pov_report_in_word_and_pdf_says_what_ran_what_was_proved_and_what_is_met(app, monkeypatch):
    """ASVS V8.3.1 · CWE-200 · CWE-440: the Word and the PDF report, opened and read, carry the summary counts, the criteria with their tests, Prove it's recorded verdict, what did not run, and no secret."""
    from test_scope_rule_routes import FakeRaw, FakeSdk, Reads, _sync_start
    import dlp_api_server as srv
    import pack_jobs
    log = Reads()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: FakeSdk(log))
    monkeypatch.setattr(srv, "_raw_client", lambda c: FakeRaw(log))
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    monkeypatch.setattr(srv, "_REPORTS", {})
    pid = _profile()
    p = _start(app, pid, products=["url_filtering", "dlp", "ssl"])
    prove = app.post("/api/pov/prove/start", json=dict(CREDS, profile_id=pid, test_id="dlp-upload", **WEB))
    assert prove.status_code == 200
    p = app.post("/api/pov/open", json={"profile_id": pid}).json()["pov"]
    ev = p["tests"]["dlp-upload"]["evidence"][-1]
    assert ev["kind"] == "prove" and ev["verdict"]["check"] == "dlp" and ev["verdict"]["destination"] == "dlptest.com"
    crit = [dict(c) for c in p["criteria"]]
    crit[0].update(status="met", tests=["dlp-upload"])
    crit[1].update(status="not_met", tests=["url-block"])
    upd = app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {
        "criteria": crit,
        "tests": {"dlp-upload": {"status": "pass", "notes": "Blocked with an incident"}, "url-block": {"status": "fail", "notes": "Gambling allowed"}}}})
    assert upd.status_code == 200, upd.text
    texts = {}
    for fmt in ("docx", "pdf"):
        r = app.post("/api/pov/report", json={"profile_id": pid, "format": fmt})
        assert r.status_code == 200 and SECRET.encode() not in r.content
        texts[fmt] = _docx_text(r.content) if fmt == "docx" else _pdf_text(r.content)
    for fmt, text in texts.items():
        assert "Proof of value: Acme Health" in text, fmt
        assert "2 tests ran: 1 passed, 1 failed." in text and "1 of " in text and "success criteria are met" in text, fmt
        assert "Sensitive data upload detected" in text and "Blocked web category" in text, fmt
        assert "Path analyzer" in text and "dlptest.com" in text, fmt
        assert "Notes: Blocked with an incident" in text and "Notes: Gambling allowed" in text, fmt
        assert "Sensitive data upload detected: Pass" in text and "Blocked web category: Fail" in text, fmt
        assert "Not run:" in text and "General web traffic is inspected" in text, fmt
        assert "No change was made through Zscaler Made Easy" in text, fmt
        assert SECRET not in text, fmt


# ── The sample tenant speaks the API's own field names ───────────────────

SAMPLE_MODELS = [("/webDlpRules", "dlp_web_rules", "DLPWebRules"), ("/urlFilteringRules", "url_filtering_rules", "URLFilteringRule"),
                 ("/sslInspectionRules", "ssl_inspection_rules", "SSLInspectionRules"),
                 ("/firewallFilteringRules", "cloud_firewall_rules", "FirewallRule"),
                 ("/cyberThreatProtection/advancedThreatSettings", "advanced_threat_settings", "AdvancedThreatProtectionSettings"),
                 ("/dlpEngines", "dlp_engine", "DLPEngine"), ("/urlCategories", "urlcategory", "URLCategory"),
                 ("/dlpDictionaries", "dlp_dictionary", "DLPDictionary")]
# ZIA answers it; SDK 1.11.3's model does not declare it (not the sample's invention).
SDK_GAPS = {"DLPDictionary.thresholdType"}


@pytest.mark.parametrize("path,module,cls", SAMPLE_MODELS, ids=[m[0] for m in SAMPLE_MODELS])
def test_the_sample_tenant_uses_the_apis_field_names_and_shapes(path, module, cls):
    """ASVS V5.1.3 · CWE-20 · CWE-440: every sample object's fields are ones the SDK's model reads, so every page shows on the sample what a tenant would answer (ATP phishing, Web DLP URL categories as references, SSL client and server TLS minimums)."""
    import importlib
    import sdk_wire_fake as wf
    model = getattr(importlib.import_module(f"zscaler.zia.models.{module}"), cls)
    body = sample_tenant.responses()[f"/zia/api/v1{path}"]
    unknown = sorted({f for row in (body if isinstance(body, list) else [body]) for f in wf.unknown_fields(row, model)} - SDK_GAPS)
    assert unknown == []
    if path == "/webDlpRules":
        assert all(isinstance(c, dict) and c.get("id") for r in body for c in r.get("urlCategories") or [])


def test_two_reads_of_the_sample_compare_equal_when_the_clock_ticks(monkeypatch):
    """ASVS V7.1.1 · CWE-440 · WSTG-BUSL-01: the sample's incident times are read from one anchored clock, so two snapshots taken a second apart compare equal."""
    from datetime import datetime, timedelta, timezone
    ticks = iter(datetime(2026, 11, 4, 12, 0, 0, 999_000, tzinfo=timezone.utc) + timedelta(seconds=s) for s in range(100))
    monkeypatch.setattr(sample_tenant, "_clock", lambda: next(ticks))
    monkeypatch.setattr(sample_tenant, "_ANCHOR", None)
    old = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.zwa_answers().items()}
    new = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.zwa_answers().items()}
    assert ot.compare(old, new)["same"]
