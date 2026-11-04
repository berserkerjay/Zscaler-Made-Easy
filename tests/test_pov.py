"""POV planner (pov.py, /report/pov): one proof of value per tenant profile,
kept in the profile's folder with no secret, bound to the profile's tenant,
with an untrusted import, a synthetic test kit, Prove it through the Path
analyzer and a customer report built from what actually ran.

No tenant, no network, no clock: the stores live in tmp_path, the tenant
readers are the fakes of tests/test_scope_rule_routes.py, background jobs
run in the request, randomness is a seeded random.Random."""
from __future__ import annotations

import hashlib
import json
import os
import random
import re
import stat

import pytest
from conftest import read_store_text
from fastapi.testclient import TestClient

import corpus_engines
import dlp_api_server as srv
import pov
import tenant_profiles

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "pov-secret-Zq81-never-stored"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}
WEB = {"scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True}
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


@pytest.fixture
def app(tmp_path, monkeypatch):
    """Arrange: every store in tmp_path, the secret store a file, no environment tenant."""
    for var, name in (("DLP_CHECK_PROFILES", "profiles/tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments.json"),
                      ("DLP_CHECK_AUDIT", "audit.log"), ("DLP_CHECK_FINGERPRINT_KEY", "fp.key")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    return TestClient(srv.app)


def _profile(name="Acme", vanity="acme", client_id=CREDS["client_id"]):
    return tenant_profiles.upsert({"name": name, "cloud": "production", "vanity_domain": vanity, "client_id": client_id},
                                  client_secret=SECRET, remember_secret=True)["id"]


def _start(app, pid, **intake):
    r = app.post("/api/pov/create", json={"profile_id": pid, "intake": dict({"customer": "Acme Health", "vertical": "healthcare"}, **intake)})
    assert r.status_code == 200, r.text
    return r.json()["pov"]


# ── Intake ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("name,prefix", [("Acme Health Systems", "AHS"), ("Globex", "GLOBEX"), ("The Bank of Springfield", "BSPRIN"),
                                         ("A", "APOV"), ("", ""), ("x" * 500, "XXXXXX")])
def test_the_prefix_is_made_from_the_customer_name(name, prefix):
    """ASVS V5.1.3 · CWE-20: the generated prefix is 2 to 6 letters or digits (boundaries: one letter, nothing, a very long name)."""
    assert pov.suggest_prefix(name) == prefix


@pytest.mark.parametrize("intake,fragment", [
    ({"customer": ""}, "customer name"),
    ({"customer": "Acme", "domain": "not a domain"}, "internal domain"),
    ({"customer": "Acme", "vertical": "casino"}, "vertical"),
    ({"customer": "Acme", "products": ["dlp", "teleport"]}, "unknown product"),
    ({"customer": "Acme", "products": []}, "at least one product"),
    ({"customer": "Acme", "prefix": "a!"}, "prefix"),
    ({"customer": "x" * 121}, "too long"),
])
def test_a_bad_intake_is_refused_in_words(intake, fragment):
    """ASVS V5.1.3 · ASVS V5.1.4 · CWE-20: every intake field is validated; a bad one is a 400 naming the field, never a 500."""
    with pytest.raises(pov.PovError) as e:
        pov.clean_intake(intake)
    assert fragment in str(e.value) and e.value.status == 400


def test_a_vertical_preset_fills_the_products_and_the_criteria(app):
    """ASVS V1.1.1 · CWE-1188: a new POV starts from its vertical preset (products and suggested success criteria)."""
    pid = _profile()
    p = _start(app, pid, vertical="financial")
    assert p["intake"]["products"] == [k for k in pov.PRODUCTS if k in pov.VERTICALS["financial"]["products"]]
    assert [c["text"] for c in p["criteria"]] == pov.VERTICALS["financial"]["criteria"]
    assert p["intake"]["prefix"] == "AHEALT" and p["status"] == "planning"


# ── Storage: the profile's folder, owner-only, no secret ────────────────

def test_a_pov_lives_in_the_profile_folder_owner_only_with_no_secret(app):
    """ASVS V8.3.4 · ASVS V2.10.4 · CWE-312 · CWE-732: the POV file is beside the profiles, 0600, and never holds the client secret."""
    pid = _profile()
    _start(app, pid)
    path = tenant_profiles.pov_path(pid)
    text = read_store_text(path)
    assert os.path.dirname(os.path.dirname(path)) == os.path.dirname(tenant_profiles.store_path())
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert SECRET not in text and "client_secret" not in text and json.loads(text)["tenant"] == {"label": "acme (production)"}


def test_a_secret_typed_into_a_note_is_masked_before_it_is_kept(app):
    """ASVS V8.3.4 · CWE-312 · CWE-532: a sign-in secret pasted into POV text is masked in the store."""
    pid = _profile()
    p = _start(app, pid)
    r = app.post("/api/pov/update", json=dict(CREDS, profile_id=pid, rev=p["rev"], changes={"notes": [{"text": f"key is {SECRET}"}]}))
    assert r.status_code == 200, r.text
    assert SECRET not in read_store_text(tenant_profiles.pov_path(pid))


def test_deleting_the_profile_deletes_its_pov(app):
    """ASVS V8.3.2 · CWE-459: a POV belongs to its profile and goes with it, last-good copy included."""
    pid = _profile()
    p = _start(app, pid)
    app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"status": "testing"}})
    path = tenant_profiles.pov_path(pid)
    tenant_profiles.delete(pid)
    assert not os.path.exists(path) and not os.path.exists(path + ".last-good")


@pytest.mark.parametrize("pid", ["../etc/passwd", "UPPER", "a" * 49, "a/b", ""])
def test_a_profile_id_never_becomes_a_path(app, pid):
    """ASVS V12.3.1 · CWE-22 · WSTG-ATHZ-01: an id that is not a profile id is refused before any file is touched."""
    r = app.post("/api/pov/open", json={"profile_id": pid})
    folder = os.path.dirname(tenant_profiles.store_path())
    assert r.status_code in (400, 404), r.text
    assert not os.path.exists(os.path.join(folder, tenant_profiles.POV_DIR))


# ── Bound to its tenant ─────────────────────────────────────────────────

def test_a_sign_in_naming_another_tenant_is_refused(app):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a POV never opens against another tenant's sign-in (409), and does for its own."""
    pid = _profile()
    _start(app, pid)
    other = app.post("/api/pov/open", json={"profile_id": pid, "vanity_domain": "globex", "client_id": "zzz"})
    own = app.post("/api/pov/open", json=dict(CREDS, profile_id=pid))
    assert other.status_code == 409 and own.status_code == 200 and own.json()["pov"]


def test_a_profile_moved_to_another_tenant_no_longer_opens_its_pov(app):
    """ASVS V4.2.1 · CWE-639: editing the profile's vanity domain does not hand the old tenant's POV to the new one."""
    pid = _profile()
    _start(app, pid)
    tenant_profiles.upsert({"name": "Acme", "vanity_domain": "globex"}, profile_id=pid)
    r = app.post("/api/pov/open", json={"profile_id": pid})
    assert r.status_code == 409 and "another tenant" in r.json()["detail"]


def test_a_stale_revision_is_refused_and_nothing_is_lost(app):
    """ASVS V11.1.2 · CWE-362: a save made on an old revision is a 409 (two tabs never overwrite each other)."""
    pid = _profile()
    p = _start(app, pid)
    ok = app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"status": "testing"}})
    stale = app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"status": "closed"}})
    assert ok.status_code == 200 and stale.status_code == 409
    assert app.post("/api/pov/open", json={"profile_id": pid}).json()["pov"]["status"] == "testing"


def test_a_page_cannot_forge_a_prove_it_verdict(app):
    """ASVS V4.1.3 · ASVS V5.1.4 · CWE-345: evidence a page sends is a note; a Prove it verdict is only ever written by the app."""
    pid = _profile()
    p = _start(app, pid)
    forged = {"url-block": {"status": "pass", "evidence": [{"kind": "prove", "verdict": {"headline": "Blocked", "agrees": True}},
                                                           {"kind": "note", "text": "block page seen"}]}}
    r = app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"tests": forged}})
    ev = r.json()["pov"]["tests"]["url-block"]["evidence"]
    assert [e["kind"] for e in ev] == ["note"] and r.json()["pov"]["status"] == "testing"


# ── Untrusted import ────────────────────────────────────────────────────

def _export(app, pid):
    r = app.post("/api/pov/export", json={"profile_id": pid})
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    return r.text


@pytest.mark.parametrize("content,status,fragment", [
    ("", 400, "choose"),
    ("{not json", 400, "not JSON"),
    ("[]", 400, "not an exported POV"),
    (json.dumps({"format": "something-else", "version": 1}), 400, "format"),
    (json.dumps({"format": pov.FORMAT, "version": 99}), 400, "version"),
    ("[" * 5000 + "]" * 5000, 400, ""),
    (json.dumps({"format": pov.FORMAT, "version": 1, "a": {"b": {"c": {"d": {"e": {"f": {"g": {"h": {"i": {"j": {"k": {"l": {"m": 1}}}}}}}}}}}}}), 400, "nested"),
    ("x" * (pov.MAX_IMPORT_BYTES + 1), 413, "larger"),
])
def test_an_import_is_checked_for_size_depth_and_format(app, content, status, fragment):
    """ASVS V5.1.4 · ASVS V12.1.1 · CWE-20 · CWE-674 · CWE-400 · WSTG-BUSL-09: a hostile POV file is refused in words, never a 500."""
    pid = _profile()
    r = app.post("/api/pov/import", json={"profile_id": pid, "content": content})
    assert r.status_code == status, r.text
    assert fragment in r.json()["detail"]


def test_an_import_for_another_tenant_is_refused(app):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a POV exported from tenant A cannot be imported into tenant B's profile."""
    a, b = _profile(), _profile("Globex", "globex", "zzz987654321")
    _start(app, a)
    r = app.post("/api/pov/import", json={"profile_id": b, "content": _export(app, a)})
    assert r.status_code == 409 and "acme (production)" in r.json()["detail"]
    assert not os.path.exists(tenant_profiles.pov_path(b))


def test_an_import_drops_unknown_fields_marks_verdicts_and_needs_replace(app):
    """ASVS V5.1.4 · CWE-915 · CWE-345: an import keeps only known fields, marks a verdict as imported, and never overwrites without Replace."""
    pid = _profile()
    p = _start(app, pid)
    data = json.loads(_export(app, pid))
    data["evil"] = "<script>"
    data["tests"] = {"url-block": {"status": "pass", "evidence": [{"kind": "prove", "verdict": {"headline": "Blocked.", "agrees": True}}]}}
    refused = app.post("/api/pov/import", json={"profile_id": pid, "content": json.dumps(data)})
    done = app.post("/api/pov/import", json={"profile_id": pid, "content": json.dumps(data), "replace": True})
    kept = done.json()["pov"]
    assert refused.status_code == 409 and done.status_code == 200
    assert "evil" not in kept and kept["rev"] == p["rev"] + 1 and kept["tests"]["url-block"]["evidence"][0]["imported"] is True


# ── Templates ───────────────────────────────────────────────────────────

def test_a_template_keeps_the_plan_and_never_the_customer(app):
    """ASVS V8.3.1 · CWE-359: a template holds the vertical, products and criteria, never the customer, domain, prefix or tenant."""
    pid = _profile()
    _start(app, pid, domain="corp.acme-health.example")
    r = app.post("/api/pov/templates", json={"profile_id": pid, "name": "Hospital POV", "description": "Two weeks"})
    t = r.json()["template"]
    text = json.dumps(t)
    assert r.status_code == 200 and t["vertical"] == "healthcare" and t["criteria"]
    assert "Acme" not in text and "acme" not in text and "AH" not in t.values()
    other = _profile("Globex", "globex", "zzz987654321")
    started = app.post("/api/pov/create", json={"profile_id": other, "intake": {"customer": "Globex"}, "template_id": t["id"]}).json()["pov"]
    assert started["intake"]["vertical"] == "healthcare" and started["template"] == "Hospital POV"


def test_deleting_an_unknown_template_is_a_404(app):
    """ASVS V7.4.1 · CWE-755: an unknown template id is a 404, not a 500."""
    assert app.delete("/api/pov/templates/does-not-exist").status_code == 404


# ── The test kit: synthetic only ────────────────────────────────────────

@pytest.mark.parametrize("file_id", [k for k in pov.KIT_FILES if k.endswith(".csv")])
def test_dlp_test_files_hold_only_published_test_or_reserved_values(file_id):
    """ASVS V8.3.1 · CWE-359 · CWE-200: every card is a published Luhn-valid test number and every SSN is in the reserved block 987-65-4320..4329."""
    import csv
    data, media, name = pov.kit_file(file_id, rng=random.Random(7))
    text = data.decode("utf-8")
    rows = list(csv.DictReader(text.splitlines()[1:]))
    cards = [r["Card number"] for r in rows if "Card number" in r]
    ssns = re.findall(r"\b\d{3}-\d{2}-\d{4}\b", text)
    assert text.startswith("# SYNTHETIC TEST DATA") and media.startswith("text/csv") and name.endswith(file_id)
    assert all(corpus_engines.luhn_ok(c) and c in corpus_engines.SAMPLES["credit_card"] for c in cards)
    assert ssns and all(s in corpus_engines.SAMPLES["ssn"] for s in ssns)
    assert all(e.endswith("@example.com") for e in re.findall(r"[\w.]+@[\w.]+", text))


def test_the_sample_generator_values_pass_the_local_detectors():
    """ASVS V5.1.3 · CWE-1287: the generator's cards, IBANs, MBI and routing number pass corpus_engines' own validators; reserved SSNs do not (by design)."""
    for key in ("credit_card", "iban", "mbi", "aba"):
        assert all(corpus_engines.sample_detected(key, v) for v in corpus_engines.SAMPLES[key]), key
    assert not any(corpus_engines.sample_detected("ssn", v) for v in corpus_engines.SAMPLES["ssn"])


def test_the_dlp_files_are_deterministic_for_a_seed():
    """SSDF PW.8.2 · CWE-330: the generator takes an injected random source (same seed, same file)."""
    a = pov.kit_file("dlp-general.csv", rng=random.Random(3))[0]
    b = pov.kit_file("dlp-general.csv", rng=random.Random(3))[0]
    assert a == b


def test_the_eicar_file_is_the_standard_string_and_no_source_file_carries_it(app):
    """ASVS V12.4.1 · CWE-506: the download is the 68-byte EICAR string; it is assembled at run time, so pov.py is never quarantined."""
    r = app.get("/api/pov/kit/eicar.com.txt")
    src = open(os.path.join(ROOT, "pov.py"), encoding="utf-8").read()
    assert r.status_code == 200 and hashlib.sha256(r.content).hexdigest() == EICAR_SHA256 and len(r.content) == 68
    assert pov.eicar() not in src and "EICAR-STANDARD" not in src


def test_the_sandbox_pdf_is_new_on_every_download():
    """ASVS V12.4.1 · CWE-330: the sandbox file is a PDF whose hash differs with its nonce."""
    a = pov.kit_file("sandbox-unique.pdf", nonce="a" * 32)
    b = pov.kit_file("sandbox-unique.pdf", nonce="b" * 32)
    assert a[0].startswith(b"%PDF-") and a[1] == "application/pdf" and hashlib.sha256(a[0]).digest() != hashlib.sha256(b[0]).digest()


@pytest.mark.parametrize("file_id", ["nope.csv", "..%2Fpov.py", "dlp-healthcare.csv.exe"])
def test_an_unknown_kit_file_is_a_404(app, file_id):
    """ASVS V12.3.1 · CWE-22: only the listed kit files are served."""
    assert app.get(f"/api/pov/kit/{file_id}").status_code == 404


# ── Prove it ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("check,outcome,decrypted,agrees", [
    ("blocked", "blocked", True, True), ("blocked", "enforce", True, False),
    ("inspected", "none", True, True), ("inspected", "blind", False, False), ("inspected", "bypassed", False, False),
    ("dlp", "monitor", True, True), ("dlp", "none", True, False),
    ("exempt", "blind", False, True), ("exempt", "enforce", True, False),
    ("blocked", "unknown", False, None), ("dlp", "out_of_scope", True, None),
])
def test_prove_it_compares_the_verdict_with_the_expected_result(check, outcome, decrypted, agrees):
    """ASVS V1.1.1 · CWE-754: each expected result agrees, disagrees, or (unknown, not in scope) says it cannot tell."""
    test = dict(pov.RUNBOOK[0], check=check)
    ev = pov.prove_evidence(test, {"verdict": {"outcome": outcome, "headline": "h", "decrypted": decrypted, "reaches_zscaler": outcome != "bypassed"},
                                   "destination": {"host": "x.example"}})
    assert ev["kind"] == "prove" and ev["verdict"]["agrees"] is agrees


def test_prove_it_runs_the_path_analyzer_and_records_the_verdict(app, monkeypatch):
    """ASVS V4.1.3 · CWE-272 · CWE-345: Prove it reads only what is in scope through the Path analyzer and records the app's verdict on the test."""
    from test_scope_rule_routes import FakeRaw, FakeSdk, Reads, _sync_start
    import pack_jobs
    log = Reads()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: FakeSdk(log))
    monkeypatch.setattr(srv, "_raw_client", lambda c: FakeRaw(log))
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    monkeypatch.setattr(srv, "_REPORTS", {})
    pid = _profile()
    _start(app, pid)
    r = app.post("/api/pov/prove/start", json=dict(CREDS, profile_id=pid, test_id="dlp-upload", **WEB))
    p = app.post("/api/pov/open", json={"profile_id": pid}).json()["pov"]
    ev = p["tests"]["dlp-upload"]["evidence"]
    assert r.status_code == 200 and log.reads
    assert ev[-1]["kind"] == "prove" and ev[-1]["verdict"]["destination"] == "dlptest.com"


def test_prove_it_for_another_tenant_is_refused_before_sign_in(app, monkeypatch):
    """ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-04: a sign-in naming another tenant never reads it or records into this POV."""
    built = []
    monkeypatch.setattr(srv, "_raw_client", lambda c: built.append(c))
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: built.append(c))
    pid = _profile()
    _start(app, pid)
    r = app.post("/api/pov/prove/start", json=dict(CREDS, vanity_domain="globex", profile_id=pid, test_id="url-block", **WEB))
    assert r.status_code == 409 and built == []


def test_prove_it_refuses_a_test_without_a_web_destination(app):
    """ASVS V5.1.3 · CWE-20: a firewall, DNS, ZPA or ZDX test says how it is proved instead of tracing nothing."""
    pid = _profile()
    _start(app, pid)
    r = app.post("/api/pov/prove/start", json=dict(CREDS, profile_id=pid, test_id="zpa-access", **WEB))
    assert r.status_code == 400 and "ZPA analysis" in r.json()["detail"]


# ── The customer report ─────────────────────────────────────────────────

def _deployment(at, creds, label="acme (production)"):
    import deployments
    import tenant_fingerprint
    deployments.add(dict({"id": f"dep-{at}", "at": at, "tenant_label": label, "by": "Ann Assessor", "packs": ["healthcare_phi_baseline"],
                          "created": [{"kind": "policy", "name": "PHI rule", "id": 1}], "status": "applied", "undone_at": None},
                         **tenant_fingerprint.record_ids(creds)))


def test_the_report_lists_what_ran_and_the_changes_made_during_the_pov(app):
    """ASVS V8.3.1 · CWE-200 · CWE-359: the report has the tests with a result, the criteria and this tenant's changes since the POV began, never a secret."""
    pid = _profile()
    p = _start(app, pid)
    creds = tenant_profiles.creds_from(tenant_profiles.get(pid))
    _deployment("2000-01-01T00:00:00+00:00", creds)                          # before the POV
    _deployment("2999-01-01T00:00:00+00:00", creds)                          # during
    _deployment("2999-01-02T00:00:00+00:00", dict(creds, vanity_domain="globex"), "globex (production)")   # another tenant
    app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"tests": {"url-block": {"status": "fail", "notes": "allowed"}}}})
    model = pov.report_model(pov.require(pid)[1], pov.changes_made(creds, p["created_at"]))
    pdf = app.post("/api/pov/report", json={"profile_id": pid, "format": "pdf"})
    docx = app.post("/api/pov/report", json={"profile_id": pid, "format": "docx"})
    assert [r["test"]["id"] for r in model["ran"]] == ["url-block"] and model["counts"]["fail"] == 1
    assert [c["at"][:4] for c in model["changes"]] == ["2999"]
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF-") and SECRET.encode() not in pdf.content
    assert docx.status_code == 200 and docx.content.startswith(b"PK") and "attachment" in docx.headers["content-disposition"]


def test_a_report_in_another_format_is_refused(app):
    """ASVS V5.1.3 · CWE-20: the report format is pdf or docx only."""
    pid = _profile()
    _start(app, pid)
    assert app.post("/api/pov/report", json={"profile_id": pid, "format": "html"}).status_code == 400


def test_every_pov_change_is_audited_without_its_text(app):
    """ASVS V7.1.1 · ASVS V7.1.2 · CWE-778 · CWE-532: create, update and delete are in the audit log with who; the notes' text never is."""
    pid = _profile()
    p = _start(app, pid)
    app.post("/api/pov/update", json={"profile_id": pid, "rev": p["rev"], "changes": {"notes": [{"text": "customer-private remark"}]}})
    app.post("/api/pov/delete", json={"profile_id": pid, "confirm": True})
    log = read_store_text(os.environ["DLP_CHECK_AUDIT"])
    actions = [json.loads(x).get("action") for x in log.splitlines() if '"event":"pov"' in x]
    assert actions == ["create", "update", "delete"] and "customer-private remark" not in log


def test_deleting_a_pov_needs_confirmation(app):
    """ASVS V4.3.1 · CWE-352 · CWE-1188: a delete without confirm=true deletes nothing."""
    pid = _profile()
    _start(app, pid)
    assert app.post("/api/pov/delete", json={"profile_id": pid}).status_code == 400
    assert os.path.exists(tenant_profiles.pov_path(pid))


# ── The page ────────────────────────────────────────────────────────────

def test_the_page_follows_the_report_page_structure_and_tab_pattern(app):
    """WCAG 2.2 SC 1.3.1 · SC 2.1.1 · SC 4.1.2: landmarks, a labelled tablist with tabpanels, a live region and the shared scripts in order."""
    html = app.get("/report/pov").text
    order = [html.index(f'/static/{s}"') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js", "pov.js")]
    assert '<header class="hero rp-hero">' in html and '<nav class="rp-bar" aria-label="Page actions">' in html and "← Back to the assessment" in html
    assert 'role="tablist"' in html and html.count('<button type="button" role="tab"') == 6 and html.count('role="tabpanel"') == 6
    assert 'role="status"' in html and 'aria-live' in html and order == sorted(order)


def test_the_page_script_never_renders_data_as_html():
    """ASVS V5.3.3 · CWE-79 · WSTG-INPV-01: pov.js builds every node with textContent, never innerHTML or insertAdjacentHTML."""
    js = open(os.path.join(ROOT, "static", "pov.js"), encoding="utf-8").read()
    assert "innerHTML" not in js and "insertAdjacentHTML" not in js and "outerHTML" not in js


def test_simple_mode_links_to_the_pov_page():
    """WCAG 2.2 SC 2.4.4 · SC 3.2.3: Simple mode has one entry to the POV planner, with no wizard of its own."""
    html = open(os.path.join(ROOT, "static", "simple.html"), encoding="utf-8").read()
    assert html.count('href="/report/pov"') == 1


def test_prove_it_with_only_a_profile_signs_in_on_the_profiles_cloud(app, monkeypatch):
    """ASVS V4.2.1 · CWE-639: a profile on another cloud is read on that cloud, so its own POV records the verdict (regression: the default cloud was used)."""
    from test_scope_rule_routes import FakeRaw, FakeSdk, Reads, _sync_start
    import pack_jobs
    log, seen = Reads(), []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda c: FakeSdk(log))
    monkeypatch.setattr(srv, "_raw_client", lambda c: seen.append(c["cloud"]) or FakeRaw(log))
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    pid = tenant_profiles.upsert({"name": "Ten", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": CREDS["client_id"]},
                                 client_secret=SECRET, remember_secret=True)["id"]
    _start(app, pid)
    r = app.post("/api/pov/prove/start", json=dict(profile_id=pid, test_id="dlp-upload", **WEB))
    assert r.status_code == 200, r.text
    assert seen == ["zscalerten"]
