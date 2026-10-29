"""Cloud QA wave 6, slice `checks`: the assessment's check catalogues, the
compliance mapping, the best-practice sources and crawler, and the benchmarks.

Every test is offline: checks read through small fakes (or the made-up
sample tenant), the crawler through a recording fetcher. No real tenant, no
network, no real clock."""
from __future__ import annotations

import inspect
import json
import os
import re
import sys
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import benchmarks  # noqa: E402
import bp_crawler  # noqa: E402
import bp_sources  # noqa: E402
import compliance_mapping as cm  # noqa: E402
import offline_tenant as ot  # noqa: E402
import permissions  # noqa: E402
import saas_matrix  # noqa: E402
import zscaler_automation_checks as auto  # noqa: E402
import zscaler_best_practices as zbp  # noqa: E402
import zscaler_full_checks as full  # noqa: E402
import zscaler_genai_checks as genai  # noqa: E402
import zscaler_rbac_checks as rbac  # noqa: E402
import zscaler_zdx_checks as zdx  # noqa: E402
import zscaler_zidentity_checks as zid  # noqa: E402
from dlp_assessment_full_auto import R  # noqa: E402

REGISTRIES = {"PLATFORM_REG": full.PLATFORM_REG, "GENAI_REG": genai.GENAI_REG, "AUTOMATION_REG": auto.AUTOMATION_REG,
              "ZDX_REG": zdx.ZDX_REG, "ZID_REG": zid.ZID_REG, "RBAC_REG": rbac.RBAC_REG}
ALL_ROWS = [row for reg in REGISTRIES.values() for row in reg]
DENIED_BODY = {"code": "FORBIDDEN", "message": "Forbidden"}


class FakeClient:
    """The engine Client's read interface: get(ep, params) -> (body, code).
    `table` maps an endpoint to (body, code); anything else answers `default`."""
    customer_id = "1"
    legacy = False
    token = "t"
    base = "https://fake.invalid"
    exp = 0

    def __init__(self, table=None, default=([], 200)):
        self.table = dict(table or {})
        self.default = default
        self.reads = []

    def get(self, ep, *a, **k):
        self.reads.append(ep)
        return self.table.get(ep, self.default)


def _run(fn, table=None, default=([], 200)):
    cl = FakeClient(table, default)
    return fn(cl), cl


def _row(check_id):
    return next(r for r in ALL_ROWS if r[0] == check_id)


def _as_result(row, r):
    return {"id": row[0], "section": row[1], "label": row[2], "status": r.status, "detail": r.detail}


# ═══════════════════════════════════════════════════════════════════════
# 1. A refused read is never judged (the permission guard)
# ═══════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("code", [401, 403])
@pytest.mark.parametrize("row", ALL_ROWS, ids=[r[0] for r in ALL_ROWS])
def test_a_check_built_on_a_refused_read_is_not_permitted(row, code):
    """ASVS V4.1.5 · A01:2021 · CWE-863 · CWE-754 · WSTG-ATHZ-02: a check whose read the role was refused (401/403) is "Not permitted", never PASS, FAIL or REVIEW."""
    # Arrange
    fn = row[3]
    # Act
    r, cl = _run(fn, default=(DENIED_BODY, code))
    # Assert
    if cl.reads:
        assert permissions.classify(_as_result(row, r)) == "not_permitted", (row[0], r.status, r.detail)
        assert r.status not in (R.PASS, R.FAIL, R.WARN)


def test_one_refused_read_among_answered_ones_still_makes_the_check_not_permitted():
    """ASVS V4.1.5 · CWE-863 · WSTG-ATHZ-02: URL categories answered but the URL Filtering rules refused: UF.2 is not judged on half the data."""
    # Arrange
    table = {"/zia/urlCategories": ([{"id": "CUSTOM_01", "customCategory": True, "configuredName": "Allow list"}], 200),
             "/zia/urlFilteringRules": (DENIED_BODY, 403)}
    # Act
    r, _ = _run(_row("UF.2")[3], table)
    # Assert
    assert r.status == R.INFO and permissions.is_denied(r.detail)


def test_the_guard_names_the_refused_endpoint_and_code():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: the not-permitted detail says which read was refused and how, in plain words, without a traceback."""
    # Arrange / Act
    r, _ = _run(_row("FW.8")[3], default=(DENIED_BODY, 403))
    # Assert
    assert "HTTP 403 on /zia/firewallFilteringRules" in r.detail and "Traceback" not in r.detail


def test_a_check_without_refused_reads_is_unchanged_by_the_guard():
    """ASVS V1.14.6 · CWE-440 · WSTG-BUSL-01: on the sample tenant every guarded check gives exactly what the bare check gives."""
    # Arrange
    cl = ot.OfflineRawClient(ot.sample_store(), {})
    # Act
    pairs = [(row[0], row[3](cl), inspect.unwrap(row[3])(cl)) for row in ALL_ROWS]
    # Assert
    assert [(cid, a.status, a.detail) for cid, a, _ in pairs] == [(cid, b.status, b.detail) for cid, _, b in pairs]


def test_an_info_result_on_a_refused_read_keeps_its_guidance_and_is_classified_not_permitted():
    """ASVS V4.1.5 · CWE-863 · WSTG-ATHZ-02: ZCC.12's own "not accessible" note stays, and the run counts it as not permitted, not informational."""
    # Arrange / Act
    r, _ = _run(_row("ZCC.12")[3], default=(DENIED_BODY, 403))
    # Assert
    assert r.status == R.INFO and "PAC files API not accessible" in r.detail and permissions.is_denied(r.detail)


def test_a_guarded_check_unwraps_to_the_original_function():
    """ASVS V1.14.6 · CWE-440 · SSDF PW.4.4: the scope tooling (beacon_scope) still finds each check's endpoints through the wrapper."""
    # Arrange
    import beacon_scope
    # Act
    eps = beacon_scope.function_endpoints(_row("FW.1")[3])
    # Assert
    assert inspect.unwrap(_row("FW.1")[3]) is full.fw_1 and "/zia/firewallFilteringRules" in eps


def test_the_unanswered_read_code_0_is_left_to_the_run_guard():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: a read refused by the scope guard (code 0) is not mislabelled as a role refusal."""
    # Arrange / Act
    r, _ = _run(_row("FW.1")[3], default=({"error": "not selected"}, 0))
    # Assert
    assert not permissions.is_denied(r.detail)


# ═══════════════════════════════════════════════════════════════════════
# 1b. Oracle tables: passing tenant, failing tenant, missing data, denied
# ═══════════════════════════════════════════════════════════════════════

ORACLE = [
    # check, endpoint, passing body, failing status on empty
    ("FW.1", "/zia/firewallFilteringRules", [{"name": "Allow web", "state": "ENABLED"}], R.WARN),
    ("FW.3", "/zia/firewallDnsRules", [{"name": "DNS"}], R.WARN),
    ("UF.1", "/zia/urlFilteringRules", [{"name": "Block", "state": "ENABLED"}], R.FAIL),
    ("SEC.2", "/zia/sandboxRules", [{"name": "Sandbox"}], R.WARN),
    ("ZPA.11", "/zpa/idp", [{"name": "Entra"}], R.WARN),
    ("ZCC.1", "/zcc/trustedNetworks", [{"networkName": "HQ"}], R.WARN),
    ("ZDX.1", "/zdx/administration/apps", [{"id": 1, "name": "M365"}], R.WARN),
    ("ZID.1", "/zid/users", [{"id": "u1"}], R.WARN),
    ("RBAC.1", "/zia/adminRoles", [{"name": "Super Admin"}, {"name": "Auditor"}], R.WARN),
]


@pytest.mark.parametrize("cid, ep, good, empty_status", ORACLE, ids=[o[0] for o in ORACLE])
def test_oracle_passing_tenant(cid, ep, good, empty_status):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: the configured tenant passes."""
    # Arrange / Act
    r, _ = _run(_row(cid)[3], {ep: (good, 200)})
    # Assert
    assert r.status == R.PASS, r.detail


@pytest.mark.parametrize("cid, ep, good, empty_status", ORACLE, ids=[o[0] for o in ORACLE])
def test_oracle_failing_tenant(cid, ep, good, empty_status):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: the empty (unconfigured) tenant gets the documented finding, not a pass."""
    # Arrange / Act
    r, _ = _run(_row(cid)[3], {ep: ([], 200)})
    # Assert
    assert r.status == empty_status, r.detail


@pytest.mark.parametrize("cid, ep, good, empty_status", ORACLE, ids=[o[0] for o in ORACLE])
def test_oracle_missing_data_never_passes(cid, ep, good, empty_status):
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: a 404 (not licensed) or an unreadable body is never a pass."""
    # Arrange / Act
    r, _ = _run(_row(cid)[3], {ep: ({"error": "not found"}, 404)})
    # Assert
    assert r.status != R.PASS


@pytest.mark.parametrize("action, status", [("BLOCK_DROP", R.PASS), ("BLOCK_RESET", R.PASS), ("BLOCK_ICMP", R.PASS), ("ALLOW", R.WARN), (None, R.WARN)])
def test_fw2_default_rule_action_oracle(action, status):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: every ZIA Block action of the Default Firewall Filtering Rule passes; Allow or no action does not (and never crashes)."""
    # Arrange
    rules = [{"name": "Default Firewall Filtering Rule", "defaultRule": True, "action": action}]
    # Act
    r, _ = _run(full.fw_2, {"/zia/firewallFilteringRules": (rules, 200)})
    # Assert
    assert r.status == status


def test_fw2_reads_the_predefined_rule_not_a_custom_rule_named_default():
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: an Allow rule named "Allow default apps" does not stand in for the predefined default rule."""
    # Arrange
    rules = [{"name": "Allow default apps", "action": "ALLOW", "order": 1},
             {"name": "Default Firewall Filtering Rule", "defaultRule": True, "action": "BLOCK_DROP", "order": 99}]
    # Act
    r, _ = _run(full.fw_2, {"/zia/firewallFilteringRules": (rules, 200)})
    # Assert
    assert r.status == R.PASS


def test_zpa8_some_service_edges_offline_needs_review():
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: 1 of 2 Private Service Edges offline is a finding (as for App Connectors), not a pass."""
    # Arrange
    edges = [{"name": "a", "controlChannelStatus": "ZPN_STATUS_AUTHENTICATED"}, {"name": "b", "controlChannelStatus": "ZPN_STATUS_DISCONNECTED"}]
    # Act
    r, _ = _run(full.zpa_8, {"/zpa/serviceEdge": (edges, 200)})
    # Assert
    assert r.status == R.WARN


def test_zcc4_numeric_os_type_is_counted_not_a_crash():
    """ASVS V5.1.4 · CWE-704 · WSTG-INPV-01: the API's numeric osType is read as a value, not called .lower() on."""
    # Arrange
    devs = [{"osType": 3}, {"osType": 4}, {"osType": 3}]
    # Act
    r, _ = _run(full.zcc_4, {"/zcc/devices": (devs, 200)})
    # Assert
    assert r.status == R.PASS and "2x3" in r.detail


@pytest.mark.parametrize("name, passes", [("Source code to AI tools", True), ("Block GitHub repo uploads", True),
                                          ("Weekly report rule", False), ("Barcode scanner uploads", False), ("Outsourced vendor", False)])
def test_ai9_source_code_rule_matches_whole_words(name, passes):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: "Weekly report" or "Barcode" is not a source-code DLP rule (no pass on a substring)."""
    # Arrange
    rules = [{"name": name, "state": "ENABLED"}]
    # Act
    r, _ = _run(genai.ai_9, {"/zia/webDlpRules": (rules, 200)})
    # Assert
    assert (r.status == R.PASS) is passes


@pytest.mark.parametrize("name, passes", [("PII to GenAI", True), ("Block PAN uploads", True), ("HIPAA PHI", True),
                                          ("Company confidential", False), ("Graphics uploads", False), ("Japan office", False)])
def test_ai10_pii_rule_matches_whole_words(name, passes):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: "Company" (pan) or "Graphics" (phi) is not a PII/PHI/PCI rule."""
    # Arrange
    rules = [{"name": name, "state": "ENABLED"}]
    # Act
    r, _ = _run(genai.ai_10, {"/zia/webDlpRules": (rules, 200)})
    # Assert
    assert (r.status == R.PASS) is passes


NOW = 1_800_000_000.0


@pytest.mark.parametrize("users, status", [
    ([{"id": "a", "adminEntitlementEnabled": True}, {"id": "b"}], R.INFO),                      # the SDK's UserRecord: no login time
    ([{"id": "a", "lastLogin": NOW - 10 * 86400}], R.PASS),
    ([{"id": "a", "lastLogin": (NOW - 91 * 86400) * 1000}], R.WARN),                            # milliseconds
    ([{"id": "a", "lastLogin": True}], R.INFO),                                                 # a boolean is not a time
])
def test_rbac12_stale_admin_oracle(monkeypatch, users, status):
    """ASVS V2.1.1 · CWE-754 · WSTG-IDNT-01: no last-login time is no evidence (INFO); a stale or fresh login is judged against an injected clock."""
    # Arrange
    monkeypatch.setattr(rbac, "_now", lambda: NOW)
    # Act
    r, _ = _run(rbac.rbac_zid_stale_admins, {"/zid/users": (users, 200)})
    # Assert
    assert r.status == status, r.detail


def test_automation_checks_on_a_client_without_token_fields_do_not_crash():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: AUTO-SDK-01/02 on a client that has no token/exp attribute answer, not raise."""
    # Arrange
    class Bare:
        def get(self, ep, *a, **k):
            return [], 200
    # Act
    out = [auto.auto_sdk_1(Bare()).status, auto.auto_sdk_2(Bare()).status]
    # Assert
    assert out == [R.FAIL, R.INFO]


def test_every_cited_reference_is_https_on_a_zscaler_host():
    """ASVS V14.2.1 · CWE-1104 · SSDF PW.4.1: every URL a check cites is https on help/automate.zscaler.com, the ZIdentity portal or github.com/zscaler."""
    # Arrange
    text = "".join(open(os.path.join(ROOT, m), encoding="utf-8").read() for m in (
        "zscaler_full_checks.py", "zscaler_genai_checks.py", "zscaler_automation_checks.py", "zscaler_rbac_checks.py",
        "zscaler_zdx_checks.py", "zscaler_zidentity_checks.py", "saas_email_checks.py"))
    # Act
    urls = re.findall(r"https?://[^\s\"')<>]+", text)
    bad = [u for u in urls if not re.match(r"https://(help\.zscaler\.com|automate\.zscaler\.com|admin\.zidentity\.net|github\.com/zscaler)(/|\.?$)", u)]
    # Assert
    assert urls and not bad, bad


# ═══════════════════════════════════════════════════════════════════════
# 2. Compliance mapping: ids exist and are correctly formatted
# ═══════════════════════════════════════════════════════════════════════

FORMATS = {
    "NIST_800_53": r"[A-Z]{2}-\d{1,2}(\(\d{1,2}\))? \(.+\)",
    "NIST_800_171": r"3\.\d{1,2}\.\d{1,2} \(.+\)",
    "SOC_2": r"(CC\d\.\d|C1\.\d|P\d\.\d|A1\.\d|PI1\.\d) \(.+\)",
    "GDPR": r"Art\. \d{1,2}(\(\d\)(\([a-f]\))?)? \(.+\)",
    "HIPAA": r"§164\.3(08|10|12)\([a-e]\)(\(\d{1,2}\))?(\((i|ii|iii|iv)\))?(\([A-H]\))? \(.+\)",
    "PCI_DSS": r"\d{1,2}(\.\d{1,2}){1,2} \(.+\)",
    "ISO_27001": r"A\.(5\.([1-9]|[1-2]\d|3[0-7])|6\.[1-8]|7\.([1-9]|1[0-4])|8\.([1-9]|[1-2]\d|3[0-4])) \(.+\)",
    "CIS": r"(1[0-8]|[1-9])\.\d{1,2} \(.+\)",
    "CMMC_L1": r"(AC|IA|MP|PE|SC|SI)\.L1-3\.\d{1,2}\.\d{1,2} \(.+\)",
    "CMMC_L2": r"(AC|AT|AU|CM|IA|IR|MA|MP|PS|PE|RA|CA|SC|SI)\.L2-3\.\d{1,2}\.\d{1,2} \(.+\)",
    "CMMC_L3": r"(AC|AT|CM|IA|IR|PS|RA|CA|SC|SI)\.L3-3\.\d{1,2}\.\d{1,2}e \(.+\)",
    "NIST_CSF_2": r"(GV|ID|PR|DE|RS|RC)\.[A-Z]{2}-\d{2} \(.+\)",
    "GLBA": r"314\.4\([a-j]\)(\(\d{1,2}\))? \(.+\)",
}
CONTROLS = [(d, fw, c) for d, by_fw in cm.CONTROL_DOMAINS.items() for fw, cs in by_fw.items() if not fw.startswith("_") for c in cs]


@pytest.mark.parametrize("domain, fw, control", CONTROLS, ids=[f"{d}-{fw}-{i}" for i, (d, fw, _c) in enumerate(CONTROLS)])
def test_every_control_id_is_correctly_formatted(domain, fw, control):
    """ASVS V1.1.1 · CWE-1164 · WSTG-INFO-01: every mapped control id has its framework's format (and a framework the module describes)."""
    # Arrange
    pattern = FORMATS[fw]
    # Act
    ok = re.fullmatch(pattern, control)
    # Assert
    assert fw in cm.FRAMEWORK_DESCRIPTIONS and ok, control


# The control ids the mapping uses whose number and meaning were checked
# against the framework text: id -> a word its title must carry.
TITLES = {
    "ISO_27001": {"A.8.22": "Segregation", "A.8.23": "Web Filtering", "A.8.12": "Leakage", "A.8.24": "Cryptography", "A.8.20": "Networks"},
    "PCI_DSS": {"10.6": "Time", "9.4": "Media", "1.5.1": "Computing Devices", "4.2.1": "Cryptography", "5.4": "Phishing"},
    "CIS": {"3.10": "Encrypt Sensitive Data in Transit", "13.6": "Network Traffic Flow", "9.7": "Email Server Anti-Malware", "10.7": "Behavior", "3.13": "DLP"},
    "CMMC_L2": {"CA.L2-3.12.2": "Plans of Action", "SC.L2-3.13.6": "Deny", "IA.L2-3.5.3": "Multifactor"},
    "CMMC_L3": {"SC.L3-3.13.4e": "Isolation", "CM.L3-3.4.1e": "Authoritative", "SI.L3-3.14.1e": "Integrity"},
    "HIPAA": {"§164.310(d)(2)(i)": "Disposal", "§164.310(d)(1)": "Device and Media", "§164.312(c)(1)": "Integrity", "§164.312(b)": "Audit"},
    "NIST_800_171": {"3.3.2": "Accountability", "3.4.2": "Configuration", "3.13.11": "Crypto", "3.1.3": "Flow"},
}


def _controls(fw):
    return {c for d, f, c in CONTROLS if f == fw}


@pytest.mark.parametrize("fw", sorted(TITLES))
def test_control_ids_carry_the_framework_title_for_their_number(fw):
    """ASVS V1.1.1 · CWE-1164 · WSTG-INFO-01: a control id names what the framework says it is (e.g. ISO A.8.23 is Web filtering, PCI DSS v4.0 10.6 is time sync)."""
    # Arrange
    wrong = []
    # Act
    for c in _controls(fw):
        cid, title = c.split(" (", 1)
        want = TITLES[fw].get(cid)
        if want and want.lower() not in title.lower():
            wrong.append(c)
    # Assert
    assert not wrong, wrong


@pytest.mark.parametrize("fw, control", [("ISO_27001", "A.8.22 (Web Filtering)"), ("PCI_DSS", "10.7 (Time Synchronization)"),
                                         ("PCI_DSS", "9.7 (Removable Media)"), ("PCI_DSS", "1.4.5 (NSC for User Devices)"),
                                         ("CIS", "13.10 (Encrypt Sensitive Data in Transit)"), ("CIS", "10.7 (Anti-Phishing)"),
                                         ("CMMC_L2", "CA.L2-3.12.4 (Plans of Action)"), ("CMMC_L3", "AU.L3-3.3.1e (Automated Audit Analysis)"),
                                         ("HIPAA", "§164.310(d)(1) (Disposal)")])
def test_a_known_wrong_control_is_not_mapped(fw, control):
    """ASVS V1.1.1 · CWE-1164 · WSTG-INFO-01: the mis-numbered controls (and 800-172's non-existent AU.L3-3.3.1e) are gone."""
    # Arrange / Act
    present = control in _controls(fw)
    # Assert
    assert not present


def test_nist_800_171_is_described_as_the_revision_its_numbering_is():
    """ASVS V1.1.1 · CWE-1164 · WSTG-INFO-01: the ids are Rev 2 numbers (3.x.y, what CMMC 2.0 Level 2 uses), so the framework says Rev 2, not Rev 3."""
    # Arrange / Act
    desc = cm.FRAMEWORK_DESCRIPTIONS["NIST_800_171"]
    # Assert
    assert "Rev 2" in desc and "Rev 3" not in desc


@pytest.mark.parametrize("cid, domain", [("C.1", "dlp"), ("D.4", "dlp"), ("RBAC.5", "identity_admin"), ("ZID.5", "identity_admin")])
def test_saas_email_rbac_and_identity_checks_map_to_frameworks(cid, domain):
    """ASVS V1.1.1 · CWE-1164 · WSTG-INFO-01: the SaaS, Email, RBAC and ZIdentity checks back their controls (they mapped to none)."""
    # Arrange
    want = cm.CONTROL_DOMAINS[domain]["NIST_800_53"]
    # Act
    got = cm.get_compliance_for_check(cid).get("NIST_800_53", [])
    # Assert
    assert set(want) <= set(got)


@pytest.mark.parametrize("cid, not_domain", [("10.1", "endpoint_dlp"), ("12.3", "device_compliance"), ("CA.1", "dlp"), ("AI.1", "endpoint_dlp")])
def test_prefix_matching_is_exact_on_the_dot(cid, not_domain):
    """ASVS V1.1.1 · CWE-1023 · WSTG-BUSL-01: "1." does not match 10.x/12.x, "C." does not match CA.x (regression)."""
    # Arrange
    extra = set(cm.CONTROL_DOMAINS[not_domain]["NIST_800_171"])
    own = set()
    for prefix, domains in cm.CHECK_DOMAIN_MAP.items():
        if cid.startswith(prefix):
            for d in domains:
                own |= set(cm.CONTROL_DOMAINS[d]["NIST_800_171"])
    # Act
    got = set(cm.get_compliance_for_check(cid).get("NIST_800_171", []))
    # Assert
    assert got == own and not (extra - own) & got


def _rows(*statuses, cid="FW.1"):
    return [{"id": f"{cid.split('.')[0]}.{i}", "status": s} for i, s in enumerate(statuses, 1)]


@pytest.mark.parametrize("statuses, status, pct", [
    (("PASS",) * 4, "Aligned", 100), (("PASS", "PASS", "PASS", "REVIEW"), "Aligned", 75), (("PASS", "PASS", "REVIEW", "REVIEW"), "Partial", 50), (("PASS", "PASS", "FAIL", "FAIL"), "Gaps", 50),
    (("PASS", "PASS", "PASS", "FAIL"), "Partial", 75), (("INFO", "ERROR"), "Not measured", None), (("PASS", "INFO"), "Aligned", 100)])
def test_framework_summary_maths(statuses, status, pct):
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: alignment is PASS ÷ (PASS+FAIL+REVIEW), "Gaps" over 25% failing, "Aligned" at ≥75% with no failure, None when nothing scored."""
    # Arrange / Act
    s = cm.get_framework_summary(_rows(*statuses))["NIST_800_53"]
    # Assert
    assert (s["status"], s["alignment_pct"]) == (status, pct)


@pytest.mark.parametrize("statuses, status", [(("PASS",), "Met"), (("FAIL",), "Not Met"), (("INFO",), "Not Tested"),
                                              (("PASS", "FAIL", "FAIL"), "Not Met"), (("PASS", "FAIL"), "Partially Met"), (("PASS", "REVIEW"), "Partially Met")])
def test_control_drilldown_status_oracle(statuses, status):
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: a control is Met, Partially Met, Not Met or Not Tested by its evidence."""
    # Arrange / Act
    d = cm.get_control_drilldown(_rows(*statuses))["NIST_800_53"]["controls"][0]
    # Assert
    assert d["status"] == status


# ═══════════════════════════════════════════════════════════════════════
# 3. bp_crawler: SSRF, redirects, size caps, safe parsing
# ═══════════════════════════════════════════════════════════════════════

def test_a_hostile_sitemap_parses_in_linear_time():
    """ASVS V5.1.3 · CWE-1333 · CWE-400 · WSTG-INPV-01: unclosed <sitemap> tags (cubic backtracking before) parse quickly."""
    # Arrange
    text = "<sitemap><loc>https://help.zscaler.com/a</loc>" * 400
    t0 = time.perf_counter()
    # Act
    children, pages = bp_crawler.parse_sitemap(text)
    # Assert
    assert time.perf_counter() - t0 < 1.0 and children == [] and len(pages) == 400


def test_sitemap_index_children_and_pages_are_told_apart():
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: <sitemap><loc> is a child sitemap, <url><loc> a page; entities are decoded."""
    # Arrange
    xml = ("<sitemapindex><sitemap><loc>https://help.zscaler.com/s1.xml</loc></sitemap></sitemapindex>"
           "<urlset><url><loc> https://help.zscaler.com/zia/a-best-practice?x=1&amp;y=2 </loc></url></urlset>")
    # Act
    out = bp_crawler.parse_sitemap(xml)
    # Assert
    assert out == (["https://help.zscaler.com/s1.xml"], ["https://help.zscaler.com/zia/a-best-practice?x=1&y=2"])


class Fetcher:
    def __init__(self, pages):
        self.pages, self.calls = pages, []

    def __call__(self, url, verify_tls=None):
        self.calls.append(url)
        body = self.pages.get(url)
        return (body.encode(), 200, "") if body is not None else (None, 404, "")


SRC = {"id": "help_zscaler", "name": "Help", "host": "help.zscaler.com", "credibility": 100, "tier": "official",
       "seeds": ["https://help.zscaler.com/zia"], "article_patterns": ["best-practice"]}

HOSTILE_LINKS = ["http://help.zscaler.com/zia/x-best-practice", "https://169.254.169.254/latest/meta-data/best-practice",
                 "https://127.0.0.1/best-practice", "https://user@help.zscaler.com/zia/y-best-practice",
                 "https://help.zscaler.com\\@127.0.0.1/best-practice", "https://evil.example/best-practice",
                 "https://www.zscaler.com/blogs/z-best-practice", "javascript:alert(1)//best-practice", "file:///etc/passwd",
                 "https://help.zscaler.com/zia/manual-best-practice.pdf"]


def test_the_page_walk_never_fetches_or_records_an_off_allowlist_link(monkeypatch):
    """ASVS V12.6.1 · A10:2021 · CWE-918 · WSTG-INPV-19: links to http, metadata IPs, loopback, user-info, other hosts and files are neither fetched nor listed."""
    # Arrange
    monkeypatch.setattr(bp_crawler, "CRAWL_POLITE_DELAY", 0)
    html = "".join(f'<a href="{u}">t</a>' for u in HOSTILE_LINKS) + '<a href="/zia/good-best-practice">Good</a>'
    fetch = Fetcher({"https://help.zscaler.com/zia": html, "https://help.zscaler.com/zia/good-best-practice": "<title>Good</title>"})
    # Act
    rep = bp_crawler._crawl_source(SRC, fetch, False, 50)
    # Assert
    assert {e["url"] for e in rep["matched"]} == {"https://help.zscaler.com/zia/good-best-practice"}
    assert all(u.startswith("https://help.zscaler.com/") for u in fetch.calls)


def test_a_sitemap_on_another_host_is_never_fetched(monkeypatch):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: a child sitemap pointing off the source host is dropped before any request."""
    # Arrange
    monkeypatch.setattr(bp_crawler, "CRAWL_POLITE_DELAY", 0)
    src = dict(SRC, sitemaps=["https://help.zscaler.com/sitemap.xml"])
    xml = ("<sitemapindex><sitemap><loc>https://169.254.169.254/s.xml</loc></sitemap>"
           "<sitemap><loc>https://evil.example/s.xml</loc></sitemap></sitemapindex>"
           "<urlset><url><loc>https://help.zscaler.com/zia/a-best-practice</loc></url></urlset>")
    fetch = Fetcher({"https://help.zscaler.com/sitemap.xml": xml})
    # Act
    rep = bp_crawler._crawl_sitemaps(src, fetch, False, None)
    # Assert
    assert fetch.calls == ["https://help.zscaler.com/sitemap.xml"] and list(rep["matched"]) == ["https://help.zscaler.com/zia/a-best-practice"]


def test_the_page_walk_stops_at_its_page_cap(monkeypatch):
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: a site of endless links costs at most the per-source page budget."""
    # Arrange
    monkeypatch.setattr(bp_crawler, "CRAWL_POLITE_DELAY", 0)

    class Endless(Fetcher):
        def __call__(self, url, verify_tls=None):
            self.calls.append(url)
            n = len(self.calls)
            return (f'<a href="/zia/p{n}a">a</a><a href="/zia/p{n}b">b</a>'.encode(), 200, "")
    fetch = Endless({})
    # Act
    rep = bp_crawler._crawl_source(SRC, fetch, False, 7)
    # Assert
    assert rep["pages_fetched"] == 7 and len(fetch.calls) == 7


def test_links_per_page_are_capped():
    """ASVS V11.1.4 · CWE-400 · WSTG-BUSL-05: at most MAX_LINKS_PER_PAGE links are read from one page."""
    # Arrange
    html = "".join(f'<a href="/zia/{i}">x</a>' for i in range(bp_crawler.MAX_LINKS_PER_PAGE + 50))
    # Act
    links = bp_crawler._extract_links(html, "https://help.zscaler.com/")
    # Assert
    assert len(links) == bp_crawler.MAX_LINKS_PER_PAGE


def test_script_and_style_text_is_never_read_as_a_title_or_link():
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: the parser ignores <script>/<style>; markup in a title stays text and is never executed."""
    # Arrange
    html = ('<script><a href="https://help.zscaler.com/zia/hidden-best-practice">x</a></script><style>a{}</style>'
            '<title>&lt;img src=x onerror=alert(1)&gt; Real | Zscaler</title>')
    # Act
    title, links = bp_crawler.page_title(html), bp_crawler._extract_links(html, "https://help.zscaler.com/")
    # Assert
    assert title == "<img src=x onerror=alert(1)> Real" and links == []


def test_a_title_from_a_fetched_page_is_bounded():
    """ASVS V5.1.3 · CWE-400 · WSTG-INPV-01: a megabyte <title> is stored as at most MAX_TITLE_CHARS characters."""
    # Arrange
    html = "<title>" + "A" * 1_000_000 + "</title>"
    # Act
    t = bp_crawler.page_title(html)
    # Assert
    assert len(t) == bp_crawler.MAX_TITLE_CHARS


def test_a_malformed_page_never_raises():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: broken markup gives no links and no exception."""
    # Arrange
    html = "<a href='/zia/x-best-practice'><<<</title><h1 " * 1000
    # Act
    links = bp_crawler._extract_links(html, "https://help.zscaler.com/")
    # Assert
    assert isinstance(links, list)


def _cache_dir(monkeypatch, tmp_path):
    import zscaler_update_check as zu
    monkeypatch.setattr(zu, "data_dir", lambda: str(tmp_path))
    return tmp_path


@pytest.mark.parametrize("payload", [{"timestamp": "yesterday"}, {"timestamp": True, "per_source": "x"}, ["not", "a", "dict"],
                                     {"timestamp": 1.0, "per_source": [1, "a", None], "last_attempt": "x"}])
def test_a_tampered_crawl_cache_is_read_defensively(monkeypatch, tmp_path, payload):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: a cache file with fields of the wrong type gives a summary, never a TypeError (a 500 on the library page)."""
    # Arrange
    d = _cache_dir(monkeypatch, tmp_path)
    (d / "bp_crawl_cache.json").write_text(json.dumps(payload), encoding="utf-8")
    # Act
    summary = bp_crawler.last_summary()
    cache = bp_crawler._load_cache()
    # Assert
    assert isinstance(summary["per_source"], list) and not isinstance(cache.get("timestamp", 0), (str, bool))


def test_a_tampered_cache_timestamp_does_not_crash_the_crawl(monkeypatch, tmp_path):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: crawl() with a string timestamp in the cache re-crawls instead of raising."""
    # Arrange
    d = _cache_dir(monkeypatch, tmp_path)
    (d / "bp_crawl_cache.json").write_text(json.dumps({"timestamp": "x"}), encoding="utf-8")
    import zscaler_update_check as zu
    monkeypatch.setattr(zu, "_safe_get", lambda url, verify_tls=None: (None, 0, "offline test"))
    monkeypatch.setattr(bp_sources, "crawlable_sources", lambda: [])
    # Act
    out = bp_crawler.crawl()
    # Assert
    assert out["from_cache"] is False and out["error"] is None


def test_the_crawl_cache_file_is_owner_only(monkeypatch, tmp_path):
    """ASVS V8.3.4 · CWE-276 · CWE-732 · WSTG-CONF-09: the crawl cache is written readable by its owner only."""
    # Arrange
    d = _cache_dir(monkeypatch, tmp_path)
    # Act
    bp_crawler._save_cache({"timestamp": 1.0})
    # Assert
    assert os.stat(d / "bp_crawl_cache.json").st_mode & 0o077 == 0


def test_save_discovered_refuses_non_https_urls_and_bounds_titles(monkeypatch, tmp_path):
    """ASVS V5.1.3 · CWE-79 · CWE-20 · WSTG-INPV-01: a javascript:, http: or data: URL never enters the library; a long title is bounded."""
    # Arrange
    _cache_dir(monkeypatch, tmp_path)
    entries = [{"url": "javascript:alert(1)", "title": "x"}, {"url": "http://help.zscaler.com/a"}, {"url": "data:text/html,x"},
               "not a dict", {"url": "https://help.zscaler.com/zia/new-best-practice", "title": "T" * 5000}]
    # Act
    added = zbp.save_discovered(entries)
    stored = zbp._load_discovered()
    # Assert
    assert added == 1 and [e["url"] for e in stored] == ["https://help.zscaler.com/zia/new-best-practice"] and len(stored[0]["title"]) == 300


def test_a_malformed_discovery_store_is_read_defensively(monkeypatch, tmp_path):
    """ASVS V5.1.4 · CWE-755 · WSTG-ERRH-01: entries without a URL, non-dicts or javascript: links in the store are skipped; saving more still works."""
    # Arrange
    d = _cache_dir(monkeypatch, tmp_path)
    (d / "bp_discovered.json").write_text(json.dumps({"entries": [1, {"title": "no url"}, {"url": "javascript:x"}]}), encoding="utf-8")
    # Act
    added = zbp.save_discovered([{"url": "https://help.zscaler.com/zia/x-best-practice"}])
    # Assert
    assert added == 1 and all(e["url"].startswith("https://") for e in zbp.list_all())


def test_every_crawlable_source_is_https_and_on_the_fetch_allowlist():
    """ASVS V12.6.1 · CWE-918 · SSDF PO.5.1: each crawlable source's host, seeds and sitemaps are https on its own allowlisted host."""
    # Arrange
    import zscaler_update_check as zu
    bad = []
    # Act
    for s in bp_sources.crawlable_sources():
        for u in list(s.get("seeds") or []) + list(s.get("sitemaps") or []):
            host, refusal = zu._allowed_url(u)
            if refusal or host != s["host"]:
                bad.append(u)
    # Assert
    assert not bad


@pytest.mark.parametrize("cred, label", [(100, "Official"), (99, "Authoritative"), (80, "Authoritative"), (79, "Community"), (60, "Community"), (59, "Unverified"), (0, "Unverified")])
def test_tier_label_boundaries(cred, label):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: credibility maps to its tier at each boundary."""
    # Arrange / Act
    got = bp_sources.tier_label(cred)
    # Assert
    assert got == label


# ═══════════════════════════════════════════════════════════════════════
# 4. Benchmarks: the maths
# ═══════════════════════════════════════════════════════════════════════

AREA_ORACLE = {"1 — CC Portal": "Client Connector", "10 — macOS": "Client Connector", "11 — Rollback": "DLP programme",
               "12 — Incident Mgmt": "DLP programme", "Ch.C — SaaS Security": "DLP programme", "Ch.D — Email DLP": "DLP programme",
               "GenAI — SSL Inspection": "SSL inspection", "Ch.E — GenAI": "GenAI governance", "RBAC — ZIA": "Administration & RBAC",
               "ZIdentity — Directory": "Administration & RBAC", "ZIA — Firewall": "ZIA policy", "": "Other", None: "Other"}


@pytest.mark.parametrize("section, area", list(AREA_ORACLE.items()))
def test_area_of_oracle(section, area):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: sections 11 and 12 are DLP programme (not Client Connector), and SaaS/Email channels are not "Other"."""
    # Arrange / Act
    got = benchmarks.area_of(section)
    # Assert
    assert got == area


def test_the_coverage_stage_counts_the_saas_and_email_channels():
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: Coverage says "SaaS, email" and so measures the Ch.C and Ch.D checks."""
    # Arrange
    rows = [{"id": "C.1", "section": "Ch.C — SaaS Security", "status": "FAIL"}, {"id": "D.1", "section": "Ch.D — Email DLP", "status": "PASS"}]
    # Act
    cov = benchmarks.dlp_programme_benchmark(rows)["stages"][2]
    # Assert
    assert (cov["name"], cov["measured"], cov["passed"], cov["pct"]) == ("Coverage", 2, 1, 50)


@pytest.mark.parametrize("pct, g", [(100, "A"), (90, "A"), (89, "B"), (75, "B"), (74, "C"), (60, "C"), (59, "D"), (40, "D"), (39, "F"), (0, "F")])
def test_grade_boundaries(pct, g):
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: grade thresholds 90/75/60/40."""
    # Arrange / Act
    got = benchmarks.grade(pct)
    # Assert
    assert got == g


@pytest.mark.parametrize("n, d, p", [(0, 0, None), (0, 4, 0), (1, 3, 33), (2, 3, 67), (3, 3, 100)])
def test_pct_is_none_when_nothing_was_measured(n, d, p):
    """ASVS V1.14.6 · CWE-369 · WSTG-BUSL-01: a share of nothing is "not measured" (None), never 100 or a ZeroDivisionError."""
    # Arrange / Act
    got = benchmarks._pct(n, d)
    # Assert
    assert got == p


def _sec(prefix, *statuses):
    return [{"id": f"x{i}", "section": prefix, "status": s} for i, s in enumerate(statuses)]


@pytest.mark.parametrize("rows, stage", [
    (_sec("1 — CC Portal", "PASS", "PASS", "PASS", "FAIL") + _sec("4 — SSL Policy", "PASS"), 2),
    (_sec("1 — CC Portal", "PASS", "FAIL") + _sec("4 — SSL Policy", "PASS"), 0),
    (_sec("1 — CC Portal", "PASS") + _sec("4 — SSL Policy", "FAIL") + _sec("12 — Incident Mgmt", "PASS"), 1),
    (_sec("1 — CC Portal", "INFO"), 0),
])
def test_programme_stage_is_the_last_met_stage_without_a_gap(rows, stage):
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: the stage reached is the last stage at ≥75% with no measured stage below it failing."""
    # Arrange / Act
    got = benchmarks.dlp_programme_benchmark(rows)["stage"]
    # Assert
    assert got == stage


def test_best_practice_benchmark_counts_and_rolls_up():
    """ASVS V1.14.6 · CWE-682 · WSTG-BUSL-01: aligned + deviations = measured; INFO is not measured; totals equal the sum of areas."""
    # Arrange
    rows = _sec("ZIA — Firewall", "PASS", "FAIL", "INFO") + _sec("ZPA — App Access", "PASS", "REVIEW")
    # Act
    b = benchmarks.best_practice_benchmark(rows)
    # Assert
    assert (b["measured"], b["aligned"], b["deviations"], b["not_measured"], b["pct"]) == (4, 2, 2, 1, 50)


def test_markdown_never_prints_na_percent_or_none_percent():
    """ASVS V7.4.1 · CWE-684 · WSTG-BUSL-01: an unmeasured stage or journey score reads "n/a", never "n/a%" or "None%"."""
    # Arrange
    rep = {"checks": _sec("ZIA — Firewall", "PASS"), "journey": {"status": "ok", "stage": None, "score": None,
                                                                 "baselines": [{"name": "b", "stage": 1, "stage_name": "s", "score": None}]}}
    # Act
    md = benchmarks.to_markdown(benchmarks.benchmark_report(rep))
    # Assert
    assert "n/a%" not in md and "None%" not in md


@pytest.mark.parametrize("checks", ["not a list", {"a": 1}, [1, None, "x"], None])
def test_benchmark_report_on_a_malformed_saved_file(checks):
    """ASVS V5.1.4 · CWE-20 · CWE-755 · WSTG-INPV-01: a saved report whose checks are not a list of objects gives an empty benchmark, not an exception."""
    # Arrange / Act
    b = benchmarks.benchmark_report({"checks": checks})
    # Assert
    assert b["best_practices"]["measured"] == 0


def test_markdown_escapes_tenant_strings():
    """ASVS V5.3.1 · CWE-1236 · CWE-79 · WSTG-INPV-01: a check label carrying markdown/HTML is inert in the export."""
    # Arrange
    rep = {"checks": [{"id": "FW.1", "section": "ZIA — Firewall", "label": "<script>x</script>|[a](javascript:1)", "status": "FAIL", "detail": "d"}]}
    # Act
    md = benchmarks.to_markdown(benchmarks.benchmark_report(rep))
    # Assert
    assert "<script>" not in md and not re.search(r"(?<!\\)\]\(javascript:", md)


# ═══════════════════════════════════════════════════════════════════════
# 5. SaaS matrix
# ═══════════════════════════════════════════════════════════════════════

MATRIX = {"types": {}, "applications": [{"name": "Box", "type": "OFLCASB_DLP_FILE", "capabilities": ["DLP"]},
                                        {"name": "Dropbox", "type": "OFLCASB_DLP_FILE", "capabilities": ["DLP"]},
                                        {"name": "Microsoft OneDrive", "type": "OFLCASB_DLP_FILE", "capabilities": ["DLP"]}]}


def test_an_inactive_tenant_is_not_counted_as_active():
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: status INACTIVE contains the word ACTIVE but is not active."""
    # Arrange
    tenants = [{"name": "t1", "app": "BOX", "status": "INACTIVE"}, {"name": "t2", "app": "BOX", "status": "ACTIVE"}]
    # Act
    f = saas_matrix.tenant_findings(tenants, matrix=MATRIX)
    # Assert
    assert f["active"] == 1 and [t["name"] for t in f["not_active"]] == ["t1"]


def test_a_box_tenant_does_not_hide_dropbox_as_a_candidate():
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: whole-word matching: Box onboarded leaves Dropbox to onboard; ONEDRIVE covers Microsoft OneDrive."""
    # Arrange
    tenants = [{"name": "Contoso files", "app": "BOX", "status": "ACTIVE"}, {"name": "c", "app": "ONEDRIVE", "status": "ACTIVE"}]
    # Act
    names = [c["name"] for c in saas_matrix.tenant_findings(tenants, matrix=MATRIX)["onboard_candidates"]]
    # Assert
    assert names == ["Dropbox"]


@pytest.mark.parametrize("cell, ok", [("Yes", True), ("✓", True), ("Supported", True), ("x", True), ("Not supported", False),
                                      ("Unsupported", False), ("No", False), ("Not available", False), ("—", False), ("", False), ("N/A", False)])
def test_capability_cells_oracle(cell, ok):
    """ASVS V5.1.3 · CWE-697 · WSTG-INPV-01: "Not supported" and "Not available" are no, though they contain the yes-words."""
    # Arrange
    html = f"<table><tr><th>Application</th><th>DLP</th></tr><tr><td>App</td><td>{cell}</td></tr></table>"
    # Act
    caps = saas_matrix.parse_matrix(html)[0]["capabilities"]
    # Assert
    assert (caps == ["DLP"]) is ok


def test_parse_matrix_bounds_and_survives_hostile_html():
    """ASVS V5.1.3 · CWE-400 · CWE-20 · WSTG-INPV-01: a huge or broken page parses within the cap and never raises."""
    # Arrange
    html = "<table><tr><th>Application</th><th>DLP</th></tr>" + "<tr><td>A</td><td>yes</td></tr>" * 200_000
    # Act
    apps = saas_matrix.parse_matrix(html) + saas_matrix.parse_matrix(None) + saas_matrix.parse_matrix("<table><tr><td></td>")
    # Assert
    assert apps and len(apps) == 1


# ═══════════════════════════════════════════════════════════════════════
# 6. SaaS and Email checks in the engine's registry
# ═══════════════════════════════════════════════════════════════════════

def test_d6_with_the_tenant_list_refused_is_not_a_pass():
    """ASVS V4.1.5 · A01:2021 · CWE-863 · WSTG-ATHZ-02: D.6 claims rules point at onboarded tenants; with the tenant list refused it is not permitted, not PASS."""
    # Arrange
    import dlp_assessment_full_auto as engine
    fn = next(r[3] for r in engine.REG if r[0] == "D.6")
    table = {"/zia/emailDlpRules": ([{"name": "r", "emailTenants": [{"id": 7}]}], 200)}
    # Act
    r, _ = _run(fn, table, default=(DENIED_BODY, 403))
    # Assert
    assert r.status == R.INFO and permissions.is_denied(r.detail)


def test_the_spliced_saas_email_checks_keep_their_own_refusal_wording():
    """ASVS V7.4.1 · CWE-209 · WSTG-ERRH-01: C.2's own "cannot read … (HTTP 403)" ERROR is kept as it is (already counted not permitted)."""
    # Arrange
    import dlp_assessment_full_auto as engine
    fn = next(r[3] for r in engine.REG if r[0] == "C.2")
    # Act
    r, _ = _run(fn, default=(DENIED_BODY, 403))
    # Assert
    assert r.status == R.ERROR and r.detail.startswith("The API client's role cannot read")


@pytest.mark.parametrize("topic, key", [("admin", None), ("ai", None), ("a", None), ("ssl", "zia_ssl_leading"), ("firewall", "zia_firewall"),
                                        ("url filter", "zia_policy_leading"), ("ad", "deception_ad"), ("", None)])
def test_lookup_by_topic_does_not_match_on_a_short_substring(monkeypatch, tmp_path, topic, key):
    """ASVS V1.14.6 · CWE-697 · WSTG-BUSL-01: an admin finding is not linked to the Deception Active Directory guide ("ad" in "admin")."""
    # Arrange
    _cache_dir(monkeypatch, tmp_path)
    # Act
    got = zbp.lookup_by_topic(topic).get("key")
    # Assert
    assert got == key
