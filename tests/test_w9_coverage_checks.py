"""Wave 9, slice `coverage-checks`: the remaining high-value Zscaler resources
read and scored (zscaler_full_checks B.17, FW.10, THR.12, GOV.9, ZPA.22-24,
HLT.5-6; zscaler_genai_checks AIG.7).

Every test is offline: checks read through a small fake or the made-up
sample tenant (offline_tenant); the live clients get a fake session or
executor. No real tenant, no network, no real clock (AIG.7's clock is
injected)."""
from __future__ import annotations

import copy
import importlib
import inspect
import json
import logging
import os
import re
import sys

import pytest
from fastapi.testclient import TestClient

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import channel_scope as cs  # noqa: E402
import compliance_mapping  # noqa: E402
import dlp_analysis  # noqa: E402
import dlp_assessment_full_auto as A  # noqa: E402
import offline_tenant as ot  # noqa: E402
import sample_tenant  # noqa: E402
import scope_permissions  # noqa: E402
import zscaler_full_checks as full  # noqa: E402
import zscaler_genai_checks as genai  # noqa: E402
from dlp_assessment_full_auto import R  # noqa: E402
from test_scope_rule_routes import CREDS, page, tenant  # noqa: E402,F401  (the isolated app fixture)

ZIA = "/zia/api/v1"
ZPA1 = "/zpa/mgmtconfig/v1/admin/customers/{customerId}"
NEW = full.COVERAGE_REG + full.COVERAGE_DLP_REG + [r for r in genai.AIGUARD_REG if r[0] == "AIG.7"]
IDS = [r[0] for r in NEW]
REAL = {r[0]: r[3] for r in full.COVERAGE_REG + full.COVERAGE_DLP_REG}
REAL["AIG.7"] = genai.aig_7
GUARDED = {r[0]: r[3] for r in list(full.PLATFORM_REG) + list(full.DLP_EXTRA_REG) + list(genai.AIGUARD_REG)}
# The Scope page key each check runs under.
KEY = {"FW.10": "zia_extras", "THR.12": "zia_extras", "GOV.9": "zia_extras", "ZPA.22": "zpa", "ZPA.23": "zpa", "ZPA.24": "zpa",
       "HLT.5": "zpa", "HLT.6": "zpa", "B.17": "dlp", "AIG.7": "aiguard",
       "FW.11": "zia_extras", "FW.12": "zia_extras", "CA.6": "zia_extras", "ZPA.25": "zpa", "ZPA.26": "zpa", "ZTW.9": "ztw"}
NOW_MS = 1793491200000   # 2026-11-01T00:00:00Z, injected
DAY = 86400 * 1000
CANARY = "sk-" + "CANARY-provider-key-0123456789abcdef"   # split, so the committed source holds no key-shaped text


class Fake:
    """The engine client's read interface: get(ep, params) -> (body, code)."""

    def __init__(self, table=None, default=(None, 404)):
        self.table = dict(table or {})
        self.default = default
        self.reads = []

    def get(self, ep, *a, **k):
        self.reads.append(ep)
        return copy.deepcopy(self.table.get(ep, self.default))


def sample():
    st = ot.sample_store(reset=True)
    return st, ot.OfflineRawClient(st, ot.creds_for(st))


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch):
    monkeypatch.setattr(genai, "_now_ms", lambda: NOW_MS)
    monkeypatch.setattr(full, "_now_s", lambda: NOW_MS / 1000)


# ── Registered, unique, scoped, guarded ─────────────────────────────────

def test_check_ids_are_unique_across_every_registry():
    """ASVS V1.14.1 · CWE-694: every check id is unique across the DLP, platform, GenAI, AI Guard, automation, ZDX, ZIdentity, RBAC and other-product registries the server runs (acceptance 6)."""
    import dlp_api_server as srv
    every = (list(srv.REG) + list(srv.PLATFORM_REG) + list(srv.GENAI_REG) + list(srv.AUTOMATION_REG) + list(srv.ZDX_REG)
             + list(srv.ZID_REG) + list(srv.RBAC_REG) + list(srv.OTHER_REG) + list(srv.AIGUARD_REG))
    ids = [c[0] for c in every]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    assert dupes == [] and set(IDS) <= set(ids), dupes


def test_every_new_check_is_permission_guarded():
    """ASVS V4.1.3 · CWE-280: each new check runs through the permission guard (a refused read is never judged)."""
    for cid in IDS:
        assert getattr(GUARDED[cid], "__wrapped__", None) is REAL[cid], cid


@pytest.mark.parametrize("cid", IDS)
def test_each_check_runs_only_under_its_scope_key(cid):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: a new check runs when its Scope page key is ticked and never when only the other keys are (read only what is in scope)."""
    import dlp_api_server as srv
    others = [k for k in ("dlp", "zia_extras", "zpa", "zcc", "aiguard", "genai", "ztw") if k != KEY[cid]]
    assert cid in {c[0] for c in srv._get_checks(scopes=[KEY[cid]])}
    assert cid not in {c[0] for c in srv._get_checks(scopes=others)}


@pytest.mark.parametrize("cid", IDS)
def test_a_refused_read_is_not_permitted_never_judged(cid):
    """ASVS V4.1.3 · CWE-280 · WSTG-ERRH-01: a 403 on any read makes the check "Not permitted" through the guard, whatever it would have said."""
    import permissions
    r = GUARDED[cid](Fake(default=({"code": "FORBIDDEN"}, 403)))
    row = {"id": cid, "section": "x", "label": cid, "status": r.status, "detail": r.detail}
    assert r.status not in (R.PASS, R.FAIL, R.WARN) and permissions.classify(row) == "not_permitted", (cid, r.status, r.detail)


@pytest.mark.parametrize("cid", IDS)
def test_missing_or_odd_data_never_passes_or_crashes(cid):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: an error answer never passes, and empty or odd shapes never crash a check or make it fail."""
    r = REAL[cid](Fake(default=({"error": "boom"}, 0)))
    assert r.status == R.INFO, (cid, r.status, r.detail)
    for body in ([], {}, "text", 7, [1, "x", None], True):
        r = REAL[cid](Fake(default=(body, 200)))
        assert isinstance(r, R) and r.status in (R.PASS, R.WARN, R.INFO), (cid, body, r.status)
        # Only a real empty list may pass: an answer of any other shape is unknown, never a pass.
        assert body == [] or r.status != R.PASS, (cid, body, r.detail)


# ── The sample tenant answers every new read ────────────────────────────

def test_the_sample_tenant_answers_every_new_read_and_shows_its_gaps():
    """ASVS V1.14.1 · CWE-1287: every new check is assessed on the sample tenant without a "not readable", and the sample's deliberate gaps are found."""
    _st, cl = sample()
    got = {cid: REAL[cid](cl) for cid in IDS}
    assert not [c for c, r in got.items() if "could not be read" in r.detail or "not readable" in r.detail], {c: r.detail[:90] for c, r in got.items()}
    assert {c for c, r in got.items() if r.status == R.WARN} == {"FW.10", "THR.12", "GOV.9", "HLT.5", "AIG.7", "FW.11", "ZTW.9"}
    assert {c for c, r in got.items() if r.status == R.PASS} >= {"HLT.6", "FW.12", "CA.6", "ZPA.25", "ZPA.26"}, {c: r.detail[:80] for c, r in got.items()}
    assert "Partner resolvers" in got["FW.11"].detail and "Retired DR subnets" in got["ZTW.9"].detail
    assert "Holiday change freeze" in got["FW.10"].detail and "Larkspur SD-WAN" in got["THR.12"].detail
    assert "Gemini pilot key" in got["AIG.7"].detail and "OpenAI production key" not in got["AIG.7"].detail


# ── 1. Endpoint DLP rules scoped to empty or missing groups (B.17) ───────

def _scope_rule(st, group):
    body = st.responses[ot.normalize_path(f"{ZIA}/endPointDlpRules")]["body"]
    body[0]["resourceGroups"] = [group]


def test_b17_rule_on_an_empty_group_is_a_finding():
    """ASVS V1.14.1 · CWE-1164: on the sample tenant, an enabled Endpoint DLP rule scoped to a resource group with no resources is flagged (acceptance 1)."""
    st, cl = sample()
    _scope_rule(st, {"id": 5302, "name": "Depot label printers"})
    r = full.b_17(cl)
    assert r.status == R.WARN and "Depot label printers" in r.detail and "no resources" in r.detail, r.detail


def test_b17_rule_on_a_populated_group_passes():
    """ASVS V1.14.1 · CWE-1164: on the sample tenant, a rule scoped to a group that holds a resource passes (acceptance 1)."""
    st, cl = sample()
    _scope_rule(st, {"id": 5301, "name": "Approved encrypted USB drives"})
    assert full.b_17(cl).status == R.PASS


def test_b17_rule_on_a_deleted_group_is_a_finding():
    """ASVS V1.14.1 · CWE-1164: a rule scoped to a group no channel lists any more (every channel read) is flagged as missing."""
    st, cl = sample()
    _scope_rule(st, {"id": 9999, "name": "Old USB group"})
    r = full.b_17(cl)
    assert r.status == R.WARN and "no longer exists" in r.detail and "Old USB group" in r.detail


def test_b17_group_read_missing_is_unknown_never_pass():
    """ASVS V7.4.1 · CWE-754 · CWE-391: when a channel's resource groups cannot be read, a group not found is unknown (INFO with the reason), never a pass or a finding (acceptance 1)."""
    st, cl = sample()
    _scope_rule(st, {"id": 5301, "name": "Approved encrypted USB drives"})
    del st.responses[ot.normalize_path(f"{ZIA}/endPointDlpResourceGroups/REMOVABLE_DRIVE_TRANSFER")]
    r = full.b_17(cl)
    assert r.status == R.INFO and "Unknown" in r.detail and "REMOVABLE_DRIVE_TRANSFER" in r.detail, r.detail


def test_b17_a_group_listing_only_resources_that_are_gone_counts_as_empty():
    """ASVS V1.14.1 · CWE-1164: a group whose listed resources no longer exist on its channel matches nothing and is flagged."""
    rules = [{"name": "USB", "state": "ENABLED", "resourceGroups": [{"id": 1, "name": "G"}]}]
    table = {"/zia/endPointDlpRules": (rules, 200), **{p: ([], 200) for p in full.EP_GROUP_PATHS + full.EP_RESOURCE_PATHS}}
    table["/zia/endPointDlpResourceGroups/PRINTING"] = ([{"id": 1, "name": "G", "resources": [{"id": 77}]}], 200)
    assert full.b_17(Fake(table)).status == R.WARN
    table["/zia/dlpEndpointResource/PRINTING"] = ([{"id": 77}], 200)
    assert full.b_17(Fake(table)).status == R.PASS


def test_b17_sub_rules_and_disabled_rules():
    """ASVS V1.14.1 · CWE-1164: a sub-rule's group counts; a disabled rule's group does not."""
    groups = {p: ([], 200) for p in full.EP_GROUP_PATHS + full.EP_RESOURCE_PATHS}
    sub = [{"name": "P", "state": "ENABLED", "subRules": [{"state": "ENABLED", "resourceGroups": [{"id": 4, "name": "Gone"}]}]}]
    assert full.b_17(Fake({"/zia/endPointDlpRules": (sub, 200), **groups})).status == R.WARN
    off = [{"name": "P", "state": "DISABLED", "resourceGroups": [{"id": 4, "name": "Gone"}]}]
    assert full.b_17(Fake({"/zia/endPointDlpRules": (off, 200), **groups})).status == R.INFO


def test_b17_belongs_to_the_endpoint_dlp_channel():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the resource group and resource lists are Endpoint DLP configuration; B.17 is skipped (nothing read) unless Endpoint DLP is on Zscaler."""
    for p in full.EP_GROUP_PATHS + full.EP_RESOURCE_PATHS:
        assert "endpoint_dlp" in cs.endpoint_channels(p)
    row = [r for r in full.DLP_EXTRA_REG if r[0] == "B.17"]
    run, skipped, _ = cs.partition(row, {"web_dlp": "zscaler"})
    assert run == [] and [s["id"] for s in skipped] == ["B.17"]
    run, _s, _ = cs.partition(row, {"endpoint_dlp": "zscaler"})
    assert [r[0] for r in run] == ["B.17"]


# ── 2. The ZPA link to ZIA (ZPA.22) ─────────────────────────────────────

SEG_ZIA = {"/zpa/application": ({"list": [{"id": "1", "name": "Billing", "enabled": True, "inspectTrafficWithZia": True}]}, 200)}


@pytest.mark.parametrize("answer,status", [(False, R.FAIL), ("false", R.FAIL), (True, R.PASS), ({"value": True}, R.PASS), ("maybe", R.INFO)])
def test_zpa22_zia_inspection_without_the_link_is_a_finding(answer, status):
    """ASVS V1.14.1 · CWE-1164: a ZPA tenant sending segments to ZIA for inspection without the ZIA cloud link is flagged; with it, passes; an answer this app does not know is unknown (acceptance 2)."""
    r = full.zpa_22(Fake(dict(SEG_ZIA, **{"/zpa/config/isZiaCloudConfigAvailable": (answer, 200)})))
    assert r.status == status, r.detail
    if status == R.FAIL:
        assert "ZIA cloud/SAML link for ZPA not configured" in r.detail and "Billing" in r.detail


def test_zpa22_not_needed_and_not_readable():
    """ASVS V7.4.1 · CWE-754: no segment inspected by ZIA is N/A; an unreadable link answer is unknown, never a pass."""
    none = {"/zpa/application": ({"list": [{"id": "1", "name": "B", "inspectTrafficWithZia": False}]}, 200)}
    assert full.zpa_22(Fake(none)).status == R.INFO
    r = full.zpa_22(Fake(dict(SEG_ZIA, **{"/zpa/config/isZiaCloudConfigAvailable": ({"error": "x"}, 500)})))
    assert r.status == R.INFO and "Unknown" in r.detail


def test_zpa22_never_reads_the_zia_credentials():
    """ASVS V8.3.4 · CWE-200 · CWE-312: the ZPA ZIA cloud configuration (ZIA password, API key, sandbox token) is never read; only the yes/no availability is."""
    f = Fake(dict(SEG_ZIA, **{"/zpa/config/isZiaCloudConfigAvailable": (False, 200)}), default=([], 200))
    full.zpa_22(f)
    assert "/zpa/config/isZiaCloudConfigAvailable" in f.reads and not [p for p in f.reads if "ziaCloudConfig" in p]
    assert not [ep for _t, ep in ot.CAPTURE if "ziaCloudConfig" in ep and "isZia" not in ep]


# ── 3. Connector schedules and version profiles (HLT.5, HLT.6) ──────────

def test_hlt5_connector_schedule_disabled_is_a_finding():
    """ASVS V1.14.1 · CWE-1164: auto-delete of disconnected App Connectors turned off is flagged; on, passes (acceptance 3)."""
    off = {"/zpa/connectorSchedule": ({"enabled": False, "frequencyInterval": "5"}, 200), "/zpa/serviceEdge": ({"list": []}, 200)}
    on = {"/zpa/connectorSchedule": ({"enabled": True, "frequency": "days", "frequencyInterval": "5"}, 200), "/zpa/serviceEdge": ({"list": []}, 200)}
    assert full.hlt_5(Fake(off)).status == R.WARN
    r = full.hlt_5(Fake(on))
    assert r.status == R.PASS and "5 days" in r.detail


def test_hlt5_service_edge_schedule_counts_only_with_service_edges():
    """ASVS V1.14.1 · CWE-1164: the Service Edge schedule is judged when the tenant has Private Service Edges, and ignored when it has none."""
    base = {"/zpa/connectorSchedule": ({"enabled": True}, 200), "/zpa/serviceEdgeSchedule": ({"enabled": False}, 200)}
    assert full.hlt_5(Fake(dict(base, **{"/zpa/serviceEdge": ({"list": [{"id": "1"}]}, 200)}))).status == R.WARN
    assert full.hlt_5(Fake(dict(base, **{"/zpa/serviceEdge": ({"list": []}, 200)}))).status == R.PASS


def test_hlt5_a_schedule_without_its_field_is_unknown():
    """ASVS V7.4.1 · CWE-754: a schedule answer with no enabled field is unknown, never a pass."""
    r = full.hlt_5(Fake({"/zpa/connectorSchedule": ({"frequency": "days"}, 200), "/zpa/serviceEdge": ({"list": []}, 200)}))
    assert r.status == R.INFO and "Unknown" in r.detail


PROFILES = {"/zpa/visible/versionProfiles": ({"list": [{"id": "0", "name": "Default", "versionDetails": [{"role": "ASSISTANT", "version": "24.300.1"}]},
                                                       {"id": "1", "name": "Previous Default", "versionDetails": [{"role": "ASSISTANT", "version": "24.200.4"}]},
                                                       {"id": "9", "name": "Pinned custom", "versionDetails": [{"role": "ASSISTANT", "version": "23.100.0"}]},
                                                       {"id": "2", "name": "New Release", "versionDetails": [{"role": "ASSISTANT", "version": "24.400.0"}]}]}, 200)}


@pytest.mark.parametrize("group,status", [
    ({"name": "G", "versionProfileId": "1"}, R.WARN), ({"name": "G", "versionProfileName": "Previous Default"}, R.WARN),
    ({"name": "G", "versionProfileId": "9"}, R.WARN), ({"name": "G", "versionProfileId": "0"}, R.PASS),
    ({"name": "G", "versionProfileId": "2"}, R.PASS), ({"name": "G", "versionProfileId": "77"}, R.INFO), ({"name": "G"}, R.INFO),
])
def test_hlt6_a_group_on_an_older_profile_is_a_finding(group, status):
    """ASVS V1.14.1 · CWE-1164: a connector group on Previous Default or on a profile older than Default is flagged; Default and New Release pass; an unresolvable profile is unknown (acceptance 3)."""
    r = full.hlt_6(Fake(dict(PROFILES, **{"/zpa/appConnectorGroup": ({"list": [group]}, 200)})))
    assert r.status == status, r.detail


def test_hlt6_no_default_profile_listed_is_unknown_never_pass():
    """ASVS V7.4.1 · CWE-754 · CWE-697: when ZPA lists no Default profile, a group on any profile not old by name cannot be compared, so the check is unknown with the reason, never a pass."""
    profiles = {"/zpa/visible/versionProfiles": ({"list": [{"id": "9", "name": "Custom", "versionDetails": [{"role": "ASSISTANT", "version": "23.1.0"}]}]}, 200)}
    r = full.hlt_6(Fake(dict(profiles, **{"/zpa/appConnectorGroup": ({"list": [{"name": "G", "versionProfileId": "9"}]}, 200)})))
    assert r.status == R.INFO and "Unknown" in r.detail and "no Default profile" in r.detail, r.detail
    old = dict(profiles, **{"/zpa/appConnectorGroup": ({"list": [{"name": "G", "versionProfileName": "Previous Default"}]}, 200)})
    old["/zpa/visible/versionProfiles"] = ({"list": [{"id": "1", "name": "Previous Default"}]}, 200)
    assert full.hlt_6(Fake(old)).status == R.WARN


def test_hlt6_a_profile_without_a_version_is_unknown_never_pass():
    """ASVS V7.4.1 · CWE-754: a group on a custom profile with no version to compare with Default's is unknown, never a pass; the sample's profiles carry versions so the comparison runs offline."""
    profiles = {"/zpa/visible/versionProfiles": ({"list": [{"id": "0", "name": "Default", "versionDetails": [{"role": "ASSISTANT", "version": "24.300.1"}]}, {"id": "9", "name": "Custom"}]}, 200)}
    r = full.hlt_6(Fake(dict(profiles, **{"/zpa/appConnectorGroup": ({"list": [{"name": "G", "versionProfileId": "9"}]}, 200)})))
    assert r.status == R.INFO and "no version" in r.detail, r.detail
    edge_only = {"/zpa/visible/versionProfiles": ({"list": [{"id": "0", "name": "Default", "versionDetails": [{"role": "ASSISTANT", "version": "24.3"}]},
                                                            {"id": "9", "name": "Custom", "versionDetails": [{"role": "SERVICE_EDGE", "version": "1.0"}]}]}, 200)}
    r = full.hlt_6(Fake(dict(edge_only, **{"/zpa/appConnectorGroup": ({"list": [{"name": "G", "versionProfileId": "9"}]}, 200)})))
    assert r.status == R.INFO, r.detail   # another component's version is never compared with the connectors'
    rows = sample_tenant.ZPA_VERSION_PROFILES
    assert all(full._ver(p) for p in rows) and full._ver(rows[1]) < full._ver(rows[0])


# ── 4. AI Guard provider credentials: metadata only (AIG.7) ─────────────

def _creds(*rows):
    return {"/aiguard/v1/llm-provider-credentials": ({"items": list(rows)}, 200)}


@pytest.mark.parametrize("row,status", [
    ({"name": "k", "expireTimeMillis": NOW_MS - DAY}, R.FAIL), ({"name": "k", "expireTimeMillis": NOW_MS + 10 * DAY}, R.WARN),
    ({"name": "k", "createTimeMillis": NOW_MS - 400 * DAY}, R.WARN), ({"name": "k", "expireTimeMillis": NOW_MS + 200 * DAY}, R.PASS),
    ({"name": "k", "createTimeMillis": NOW_MS - 10 * DAY}, R.PASS), ({"name": "k"}, R.INFO),
    ({"name": "k", "expireTimeMillis": (NOW_MS - DAY) // 1000}, R.FAIL),
])
def test_aig7_expired_expiring_and_old_credentials(row, status):
    """ASVS V2.10.1 · CWE-324 · CWE-262: an expired provider credential fails, one expiring within 30 days or a year old without expiry asks for rotation, a credential with no date is unknown."""
    assert genai.aig_7(Fake(_creds(row))).status == status


def test_aig7_never_shows_a_key_value():
    """ASVS V8.3.4 · CWE-200 · CWE-532: a provider credential answer carrying a key (apiCredentials, or any other field) leaves no trace of it in the result, even when the reader did not strip it (acceptance 4)."""
    row = {"name": "OpenAI key", "createTimeMillis": NOW_MS - 400 * DAY, "apiCredentials": {"type": "API_KEY", "apiKey": CANARY}, "secret": CANARY}
    r = genai.aig_7(Fake(_creds(row)))
    assert r.status == R.WARN and CANARY not in json.dumps([r.detail, getattr(r, "data", None)], default=str)


def test_the_live_client_keeps_only_metadata(monkeypatch, caplog):
    """ASVS V8.3.4 · CWE-200 · CWE-532: the assessment's raw client strips the key from the provider credential answer before it is cached or returned, and logs nothing of it (acceptance 4)."""

    class Resp:
        status_code, headers, text = 200, {}, ""

        def json(self):
            return {"items": [{"id": 1, "name": "OpenAI key", "providerId": 7, "expireTimeMillis": NOW_MS,
                               "apiCredentials": {"type": "API_KEY", "apiKey": CANARY}, "keyValue": CANARY}]}

    class Sess:
        headers, cookies = {}, {}

        def get(self, *a, **k):
            return Resp()

    A._reset_tenant_gates()
    monkeypatch.setattr(A, "_sleep", lambda s: None)
    cl = A.Client("w9-cov-cid", "s3cr3t-Value!", "acme", "zscaler")
    cl.sess, cl.token, cl.exp = Sess(), "t", float("inf")
    with caplog.at_level(logging.DEBUG):
        body, code = cl.get("/aiguard/v1/llm-provider-credentials")
    assert code == 200 and body == {"items": [{"id": 1, "name": "OpenAI key", "providerId": 7, "expireTimeMillis": NOW_MS}]}
    assert CANARY not in json.dumps(list(cl._c.values()), default=str) and CANARY not in caplog.text


def test_the_sdk_client_keeps_only_metadata(caplog):
    """ASVS V8.3.4 · CWE-200 · CWE-532: the SDK-backed client's raw read keeps only the provider credentials' names and dates, and only id, name, type and enabled state of partner integrations."""
    import sdk_client

    class Resp:
        def __init__(self, body):
            self.body = body

        def get_status(self):
            return 200

        def get_body(self):
            return self.body

    class Exec:
        def __init__(self, body):
            self.body = body

        def create_request(self, **k):
            return object()

        def execute(self, request):
            return Resp(self.body), None

    c = sdk_client.SdkClient.__new__(sdk_client.SdkClient)
    for path, body, keep in (
        ("/aiguard/v1/llm-provider-credentials", {"items": [{"name": "k", "apiCredentials": {"apiKey": CANARY}}]}, {"items": [{"name": "k"}]}),
        ("/zia/integrationPartners", [{"id": 1, "name": "P", "type": "SDWAN", "disabled": False, "apiKey": CANARY}],
         [{"id": 1, "name": "P", "type": "SDWAN", "disabled": False}]),
    ):
        c._zs = type("Zs", (), {"get_request_executor": lambda self, b=body: Exec(b)})()
        with caplog.at_level(logging.DEBUG):
            got, code = c._raw_get(path)
        assert code == 200 and got == keep and CANARY not in caplog.text


def test_a_snapshot_never_holds_a_provider_key():
    """ASVS V8.3.4 · CWE-312 · CWE-200: a saved snapshot of a provider credential answer has no key value, whatever reader produced it (acceptance 4)."""
    body = {"items": [{"name": "k", "apiCredentials": {"type": "API_KEY", "apiKey": CANARY}}]}
    doc = ot.build_snapshot({"/aiguard/v1/llm-provider-credentials": {"status": 200, "body": body}}, {})
    assert CANARY not in ot.dumps(doc)
    assert CANARY not in json.dumps(A.metadata_only("/aiguard/v1/llm-provider-credentials", body))


def test_the_sample_snapshot_of_ai_guard_keeps_names_and_dates_only():
    """ASVS V8.3.4 · CWE-312: the provider credentials a snapshot saves from the sample tenant carry names and dates and no apiCredentials."""
    _st, cl = sample()
    got = ot.capture(cl, ["aiguard"], {}, lambda m: None)
    body = got["responses"][ot.normalize_path("/aiguard/v1/llm-provider-credentials")]["body"]
    rows = body["items"]
    assert rows and all(set(r) <= {"id", "name", "providerId", "expireTimeMillis", "createTimeMillis", "updateTimeMillis"} for r in rows)


# ── 5. Scope: refused before anything is read ───────────────────────────

ZPA_PATHS = ("/zpa/connectorSchedule", "/zpa/serviceEdgeSchedule", "/zpa/visible/versionProfiles", "/zpa/config/isZiaCloudConfigAvailable",
             "/zpa/userportal/aup", "/zpa/userPortalLink", "/zpa/ipRanges", "/zpa/cbiconfig/certificates")
ZIA_PATHS = ("/zia/integrationPartners", "/zia/trafficCaptureRules", "/zia/timeIntervals", "/zia/dnsApplicationGroups", "/zia/workloadGroups",
             "/zia/httpHeaderProfile", "/zia/httpHeaderActionProfile")
ZTW_IP_GROUPS = "/ztw/api/v1/ipGroups"


def test_nothing_ticked_is_refused_before_a_client_is_built(tenant):  # noqa: F811
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: an assessment with nothing ticked on the Scope page is a 400 before any client is built or anything is read (acceptance 5)."""
    r = TestClient(srv_app()).post("/api/assess", json=dict(CREDS, **page([])))
    assert r.status_code == 400 and "scope" in str(r.json().get("detail")).lower(), r.text[:300]
    assert tenant.built == [] and tenant.reads == []


def srv_app():
    import dlp_api_server as srv
    return srv.app


@pytest.mark.parametrize("path,key", [(p, "zpa") for p in ZPA_PATHS] + [("/aiguard/v1/llm-provider-credentials", "aiguard"), (ZTW_IP_GROUPS, "ztw")])
def test_each_new_service_read_is_refused_when_its_key_is_unticked(path, key):
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: each new ZPA and AI Guard read is refused by the run's client, with no request sent, when its Scope page key is not ticked (acceptance 5)."""
    inner = Fake(default=([], 200))
    others = [k for k in ("dlp", "zia_extras", "zpa", "zcc", "aiguard", "ztw") if k != key]
    sc = dlp_analysis.ScopedClient(inner, {c: {"choice": "zscaler"} for c in cs.CHANNELS}, others)
    body, code = sc.get(path)
    assert code == 0 and inner.reads == []
    dlp_analysis.ScopedClient(inner, {c: {"choice": "zscaler"} for c in cs.CHANNELS}, [key]).get(path)
    assert inner.reads == [path]


def test_endpoint_dlp_reads_are_refused_without_the_channel():
    """ASVS V4.1.3 · CWE-284 · WSTG-ATHZ-02: the Endpoint DLP resource reads are refused, with no request sent, when Endpoint DLP is not on Zscaler (acceptance 5)."""
    inner = Fake(default=([], 200))
    declared = {c: {"choice": "alternative"} for c in cs.CHANNELS}
    declared["web_dlp"] = {"choice": "zscaler"}
    sc = dlp_analysis.ScopedClient(inner, declared, ["dlp"])
    for p in full.EP_GROUP_PATHS + full.EP_RESOURCE_PATHS:
        assert sc.get(p)[1] == 0
    assert inner.reads == []


def test_every_read_is_in_required_api_access_and_the_snapshot_only_under_its_key():
    """ASVS V1.14.1 · CWE-1164: every endpoint a new check reads is listed under its scope key in Required API access, and saved in a snapshot when that key is ticked (and not under another key)."""
    for cid in IDS:
        f = Fake(default=([], 200))
        REAL[cid](f)
        reads = {p.removeprefix("raw:") for p in f.reads}
        used = set(scope_permissions.SCOPE_PERMISSIONS[KEY[cid]]["endpoints_used"])
        assert reads - used == set(), (cid, reads - used)
        plan = set(ot.capture_plan([KEY[cid]]))
        assert reads - plan == set(), (cid, reads - plan)
    assert not set(ZPA_PATHS) & set(ot.capture_plan(["zia_extras", "dlp", "aiguard", "ztw"]))
    assert not set(ZIA_PATHS) & set(ot.capture_plan(["zpa", "dlp", "aiguard", "ztw"]))
    assert ZTW_IP_GROUPS not in ot.capture_plan(["zia_extras", "zpa", "dlp", "aiguard"])
    assert "/aiguard/v1/llm-provider-credentials" not in ot.capture_plan(["zia_extras", "zpa", "dlp"])


# ── 7, 8. Traffic capture, partners, time intervals, portals ────────────

ORACLES = [
    ("GOV.9", {"/zia/trafficCaptureRules": ([{"name": "c", "state": "DISABLED", "action": "CAPTURE"}], 200)},
     {"/zia/trafficCaptureRules": ([{"name": "c", "state": "ENABLED", "action": "CAPTURE"}], 200)}),
    ("THR.12", {"/zia/integrationPartners": ([{"name": "p", "disabled": False}], 200)},
     {"/zia/integrationPartners": ([{"name": "p", "disabled": True}], 200)}),
    ("FW.10", {"/zia/timeIntervals": ([{"name": "t", "daysOfWeek": ["MON"]}], 200)},
     {"/zia/timeIntervals": ([{"name": "t", "daysOfWeek": []}], 200)}),
    ("ZPA.23", {"/zpa/userPortal": ({"list": [{"id": "1", "name": "Partners", "enabled": True}]}, 200),
                "/zpa/userportal/aup": ({"list": [{"name": "AUP", "aup": "Use for work only.", "enabled": True}]}, 200)},
     {"/zpa/userPortal": ({"list": [{"id": "1", "name": "Partners", "enabled": True}]}, 200),
      "/zpa/userportal/aup": ({"list": [{"name": "AUP", "aup": " ", "enabled": True}]}, 200)}),
    ("ZPA.24", {"/zpa/userPortalLink": ({"list": [{"name": "Wiki", "enabled": True, "userPortals": [{"id": "1"}]}]}, 200),
                "/zpa/userPortal": ({"list": [{"id": "1", "enabled": True}]}, 200)},
     {"/zpa/userPortalLink": ({"list": [{"name": "Wiki", "enabled": True, "userPortals": [{"id": "1"}]}]}, 200),
      "/zpa/userPortal": ({"list": [{"id": "1", "enabled": False}]}, 200)}),
]


@pytest.mark.parametrize("cid,good,bad", ORACLES, ids=[o[0] for o in ORACLES])
def test_oracle_passes_the_good_tenant_and_flags_the_bad_one(cid, good, bad):
    """ASVS V1.14.1 · CWE-1164 · SSDF PW.8.2: each check passes a tenant that follows the practice and asks for review on one that does not, with the fix in plain words."""
    ok, ko = REAL[cid](Fake(good)), REAL[cid](Fake(bad))
    assert ok.status == R.PASS, ok.detail
    assert ko.status == R.WARN and ("Best Practice:" in ko.detail or "Fix:" in ko.detail), ko.detail


@pytest.mark.parametrize("cid,table", [
    ("GOV.9", {"/zia/trafficCaptureRules": ([{"name": "c", "action": "CAPTURE"}], 200)}),
    ("THR.12", {"/zia/integrationPartners": ([{"name": "p"}], 200)}),
    ("FW.10", {"/zia/timeIntervals": ([{"name": "t"}], 200)}),
])
def test_a_missing_state_field_is_unknown_never_pass(cid, table):
    """ASVS V7.4.1 · CWE-754 · CWE-391: a rule, partner or interval that states no state or days is unknown with the reason, never a pass."""
    r = REAL[cid](Fake(table))
    assert r.status == R.INFO and "Unknown" in r.detail, r.detail


@pytest.mark.parametrize("body", [{}, "text", 7, True, [1, "x", None], {"list": "x"}, {"rules": []}, None],
                         ids=["dict", "text", "int", "bool", "junk-list", "list-not-a-list", "other-key", "none"])
def test_gov9_a_malformed_answer_is_unknown_never_pass(body):
    """ASVS V5.1.3 · CWE-20 · CWE-754: a 200 traffic capture answer that is not a list of rules is unknown with the reason, never "no capture rule"."""
    r = full.gov_9(Fake({"/zia/trafficCaptureRules": (body, 200)}))
    assert r.status == R.INFO and "Unknown" in r.detail, (body, r.status, r.detail)


@pytest.mark.parametrize("body", [[], {"list": []}])
def test_gov9_only_a_real_empty_list_means_no_capture_rule(body):
    """ASVS V5.1.3 · CWE-20: an empty list (bare or in ZIA's list envelope) is the one answer that means no capture rule."""
    assert full.gov_9(Fake({"/zia/trafficCaptureRules": (body, 200)})).status == R.PASS


def test_gov9_unreadable_entries_beside_disabled_rules_are_unknown():
    """ASVS V5.1.3 · CWE-20 · CWE-754: a disabled rule next to an entry that is not a rule is unknown (the entry could be an enabled rule), never a pass."""
    r = full.gov_9(Fake({"/zia/trafficCaptureRules": ([{"name": "c", "state": "DISABLED", "action": "CAPTURE"}, "x"], 200)}))
    assert r.status == R.INFO and "1 unreadable entry" in r.detail, r.detail


def test_thr12_partners_without_a_state_are_counted_not_dropped():
    """ASVS V7.4.1 · CWE-754 · CWE-391: a partner with no disabled field is never silently dropped: the result counts and names it as unknown, in a pass and in a finding."""
    mixed = [{"name": "Edr", "disabled": False}, {"name": "Mystery"}]
    r = full.thr_12(Fake({"/zia/integrationPartners": (mixed, 200)}))
    assert r.status == R.PASS and "1 of 2" in r.detail and "1 more" in r.detail and "Mystery" in r.detail and "unknown" in r.detail, r.detail
    r = full.thr_12(Fake({"/zia/integrationPartners": (mixed + [{"name": "Off", "disabled": True}], 200)}))
    assert r.status == R.WARN and "Mystery" in r.detail and "unknown" in r.detail, r.detail


@pytest.mark.parametrize("cid", ["GOV.9", "THR.12", "FW.11", "FW.12", "CA.6", "ZPA.25", "ZPA.26", "ZTW.9"])
def test_a_feature_not_licensed_is_outside_the_score(cid):
    """ASVS V7.4.1 · CWE-754: a 404 (not licensed or not enabled) is INFO saying so, never a failure."""
    r = REAL[cid](Fake(default=({"code": "NOT_FOUND"}, 404)))
    assert r.status == R.INFO and "not licensed" in r.detail


def test_tenant_names_in_findings_are_cleaned_and_capped():
    """ASVS V5.3.1 · CWE-117 · CWE-74: a tenant name with control characters or of any length is shown without them and capped."""
    evil = "Cap\x1b[31m\r\n" + "A" * 500
    r = full.gov_9(Fake({"/zia/trafficCaptureRules": ([{"name": evil, "state": "ENABLED", "action": "CAPTURE"}], 200)}))
    assert r.status == R.WARN and "\x1b" not in r.detail and "\r" not in r.detail and "A" * (full._NAME_MAX + 1) not in r.detail


# ── SDK: every path and every sample field is the installed SDK's ───────

@pytest.mark.parametrize("module,name,path", [
    ("zia.endpoint_dlp_resource_groups", "list_resource_group_tags", "/endPointDlpResourceGroups/{channel}"),
    ("zia.dlp_endpoint_resource", "list_resources_by_channel", "/dlpEndpointResource/{channel}"),
    ("zia.partner_integrations", "list_integration_partners", "/integrationPartners"),
    ("zia.traffic_capture", "list_rules", "/trafficCaptureRules"),
    ("zia.time_intervals", "list_time_intervals", "/timeIntervals"),
    ("zpa.zia_customer_config", "check_zia_cloud_config", "/config/isZiaCloudConfigAvailable"),
    ("zpa.app_connector_schedule", "get_connector_schedule", "/connectorSchedule"),
    ("zpa.service_edge_schedule", "get_service_edge_schedule", "/serviceEdgeSchedule"),
    ("zpa.customer_version_profile", "list_version_profiles", "/visible/versionProfiles"),
    ("zpa.user_portal_aup", "list_user_portal_aup", "/userportal/aup"),
    ("zpa.user_portal_link", "list_portal_link", "/userPortalLink"),
    ("aiguard.llm_provider_credentials", "list_credentials", "/llm-provider-credentials"),
    ("zia.dns_application_groups", "list_groups", "/dnsApplicationGroups"),
    ("zia.workload_groups", "list_groups", "/workloadGroups"),
    ("zia.http_header_control", "list_http_header_profiles", "/httpHeaderProfile"),
    ("zia.http_header_control", "list_http_header_action_profiles", "/httpHeaderActionProfile"),
    ("zpa.c2c_ip_ranges", "list_ip_ranges", "/ipRanges"),
    ("zpa.cbi_certificate", "list_cbi_certificates", "/certificates"),
    ("ztw.ip_groups", "list_ip_groups", "/ipGroups"),
])
def test_every_path_is_the_one_the_sdk_calls(module, name, path):
    """SSDF PW.4.1 · CWE-1164: each path the new checks read is the one the installed SDK's method sends."""
    mod = importlib.import_module(f"zscaler.{module}")
    cls = next(getattr(mod, c) for c in dir(mod) if c.endswith("API") and inspect.isclass(getattr(mod, c)) and getattr(mod, c).__module__ == mod.__name__)
    src = inspect.getsource(cls)
    fn = re.search(rf"def {name}\(.*?(?=\n    def |\Z)", src, re.S).group(0)
    assert re.search(rf"(\n\s*|_endpoint\}}){re.escape(path)}\s*\n", fn), (module, name, path)


SAMPLE_MODELS = [
    (f"{ZIA}/endPointDlpResourceGroups/REMOVABLE_DRIVE_TRANSFER", "zia.models.endpoint_dlp_resource_groups", "EndpointDlpResourceGroups"),
    (f"{ZIA}/dlpEndpointResource/REMOVABLE_DRIVE_TRANSFER", "zia.models.dlp_endpoint_resource", "DlpEndpointResource"),
    (f"{ZIA}/integrationPartners", "zia.models.partner_integrations", "IntegrationPartner"),
    (f"{ZIA}/trafficCaptureRules", "zia.models.traffic_capture", "TrafficCapture"),
    (f"{ZIA}/timeIntervals", "zia.models.time_intervals", "TimeIntervals"),
    (f"{ZPA1}/connectorSchedule", "zpa.models.app_connector_schedule", "AppConnectorSchedule"),
    (f"{ZPA1}/serviceEdgeSchedule", "zpa.models.service_edge_schedule", "ServiceEdgeSchedule"),
    (f"{ZPA1}/visible/versionProfiles", "zpa.models.customer_version_profile", "CustomerVersionProfile"),
    ("/aiguard/v1/llm-provider-credentials", "aiguard.models.llm_provider_credentials", "LlmProviderCredentials"),
    (f"{ZIA}/dnsApplicationGroups", "zia.models.dns_application_groups", "DnsApplicationGroups"),
    (f"{ZIA}/workloadGroups", "zia.models.workload_groups", "WorkloadGroups"),
    (f"{ZIA}/httpHeaderProfile", "zia.models.http_header_control", "HttpHeaderProfile"),
    (f"{ZIA}/httpHeaderActionProfile", "zia.models.http_header_control", "HttpHeaderActionProfile"),
    (f"{ZPA1}/v2/ipRanges", "zpa.models.c2c_ip_ranges", "IpRanges"),
    ("/zpa/cbiconfig/cbi/api/customers/{customerId}/certificates", "zpa.models.cbi_certificate", "CBICertificate"),
    ("/ztw/api/v1/ipGroups", "ztw.models.ip_groups", "IPGroups"),
]


@pytest.mark.parametrize("path,module,cls", SAMPLE_MODELS, ids=[m[0].rsplit("/", 1)[-1] for m in SAMPLE_MODELS])
def test_the_sample_answers_speak_the_sdk_models(path, module, cls):
    """ASVS V5.1.3 · CWE-1287 · SSDF PW.4.1: every field of a new sample answer is one the SDK 1.11.3 model reads (no invented field names), apart from the provider credential's id and creation time (assumed)."""
    import sdk_wire_fake as wf
    model = getattr(importlib.import_module(f"zscaler.{module}"), cls)
    body = sample_tenant.responses()[path]
    rows = body.get("list", body.get("items", [body])) if isinstance(body, dict) else body
    unknown = sorted({f for row in rows for f in wf.unknown_fields(row, model)})
    assert unknown in ([], ["LlmProviderCredentials.createTimeMillis", "LlmProviderCredentials.id"]), unknown


def test_compliance_mapping_covers_the_new_checks():
    """ASVS V1.14.1 · CWE-1164: each new check maps to compliance controls (THR.12, HLT.5, HLT.6 and AIG.7 by their own entries, the others by their prefix)."""
    for cid in IDS:
        assert compliance_mapping.get_compliance_for_check(cid), cid


# ── 8. Objects read only by backup and Terraform, now scored ────────────
# FW.11 DNS application groups, FW.12 workload groups, CA.6 HTTP header
# profiles, ZPA.25 client-to-client IP ranges, ZPA.26 isolation certificates,
# ZTW.9 Cloud & Branch Connector IP groups.

def _pem(days_left):
    """A public certificate (no key kept) that ends `days_left` days after the injected date."""
    import datetime as dt
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.derive_private_key(424242, ec.SECP256R1())   # fixed, so nothing random decides the test
    now = dt.datetime.fromtimestamp(NOW_MS / 1000, dt.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test isolation root")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(7)
            .not_valid_before(now - dt.timedelta(days=400)).not_valid_after(now + dt.timedelta(days=days_left)).sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def _certs(*rows):
    return {"/zpa/cbiconfig/certificates": (list(rows), 200)}


ITEM8_ORACLES = [
    ("FW.11", {"/zia/dnsApplicationGroups": ([{"name": "g", "dnsApplications": ["X"]}], 200)},
     {"/zia/dnsApplicationGroups": ([{"name": "g", "dnsApplications": []}], 200)}),
    ("FW.12", {"/zia/workloadGroups": ([{"name": "w", "expressionJson": {"expressionContainers": [
        {"tagContainer": {"tags": [{"key": "App", "value": "billing"}]}}]}}], 200)},
     {"/zia/workloadGroups": ([{"name": "w", "expression": "", "expressionJson": {"expressionContainers": []}}], 200)}),
    ("CA.6", {"/zia/httpHeaderProfile": ([{"name": "p", "httpHeaderProfileCriteria": [{"header": "Host"}], "profileReadyForUse": True}], 200),
              "/zia/httpHeaderActionProfile": ([{"name": "a", "httpHeaderActionProfileKeys": [{"key": "K", "value": "V"}]}], 200)},
     {"/zia/httpHeaderProfile": ([], 200), "/zia/httpHeaderActionProfile": ([{"name": "a", "httpHeaderActionProfileKeys": []}], 200)}),
    ("ZPA.25", {"/zpa/ipRanges": ([{"name": "r", "enabled": True, "totalIps": "100", "usedIps": "10", "availableIps": "90"}], 200)},
     {"/zpa/ipRanges": ([{"name": "r", "enabled": True, "totalIps": "100", "usedIps": "100", "availableIps": "0"}], 200)}),
    ("ZTW.9", {ZTW_IP_GROUPS: ([{"name": "g", "ipAddresses": ["10.0.0.0/24"]}], 200)},
     {ZTW_IP_GROUPS: ([{"name": "g", "ipAddresses": []}], 200)}),
]


@pytest.mark.parametrize("cid,good,bad", ITEM8_ORACLES, ids=[o[0] for o in ITEM8_ORACLES])
def test_item8_oracle_passes_the_good_tenant_and_flags_the_bad_one(cid, good, bad):
    """ASVS V1.14.1 · CWE-1164 · SSDF PW.8.2: each new object check passes a tenant whose objects can do their job and asks for review on an empty or incomplete one, with the fix in plain words."""
    ok, ko = REAL[cid](Fake(good)), REAL[cid](Fake(bad))
    assert ok.status == R.PASS, ok.detail
    assert ko.status == R.WARN and ("Best Practice:" in ko.detail or "Fix:" in ko.detail), ko.detail


@pytest.mark.parametrize("cid,table", [
    ("FW.11", {"/zia/dnsApplicationGroups": ([{"name": "g"}], 200)}),
    ("FW.12", {"/zia/workloadGroups": ([{"name": "w"}], 200)}),
    ("CA.6", {"/zia/httpHeaderProfile": ([{"name": "p"}], 200), "/zia/httpHeaderActionProfile": ([], 200)}),
    ("CA.6", {"/zia/httpHeaderProfile": ([], 200), "/zia/httpHeaderActionProfile": ({"code": "x"}, 500)}),
    ("ZPA.25", {"/zpa/ipRanges": ([{"name": "r", "enabled": True}], 200)}),
    ("ZPA.25", {"/zpa/ipRanges": ([{"name": "r", "enabled": True, "totalIps": "many", "usedIps": "some"}], 200)}),
    ("ZPA.26", _certs({"name": "c"})),
    ("ZPA.26", _certs({"name": "c", "pem": "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGUgYXQgYWxs\n-----END CERTIFICATE-----"})),
    ("ZPA.26", _certs({"name": "c", "pem": "A" * (full._PEM_MAX + 1)})),
    ("ZTW.9", {ZTW_IP_GROUPS: ([{"name": "g"}], 200)}),
], ids=["fw11-no-list", "fw12-no-expression", "ca6-no-criteria", "ca6-one-unreadable", "zpa25-no-counts", "zpa25-junk-counts",
        "zpa26-no-pem", "zpa26-junk-pem", "zpa26-huge-pem", "ztw9-no-list"])
def test_item8_a_missing_or_unreadable_field_is_unknown_never_pass(cid, table):
    """ASVS V7.4.1 · CWE-754 · CWE-20: an object whose list, counts or certificate is missing or cannot be read is unknown with the reason, never a pass."""
    r = REAL[cid](Fake(table))
    assert r.status == R.INFO and "Unknown" in r.detail, r.detail


@pytest.mark.parametrize("days,status", [(-3, R.FAIL), (10, R.WARN), (200, R.PASS)])
def test_zpa26_expired_and_expiring_isolation_certificates(days, status):
    """ASVS V9.2.1 · CWE-298 · WSTG-CRYP-01: an expired isolation certificate fails, one ending within 30 days asks for review, a later one passes (the date is injected)."""
    r = full.zpa_26(Fake(_certs({"name": "Isolation root", "isDefault": True, "pem": _pem(days)})))
    assert r.status == status and (status == R.PASS or "Isolation root (default)" in r.detail), r.detail


def test_zpa26_never_shows_the_certificate_and_a_pasted_key_never_reaches_a_snapshot():
    """ASVS V8.3.4 · CWE-200 · CWE-312: no part of a certificate's PEM is shown in the result, and a private key pasted into the pem field is masked when a snapshot is saved."""
    pem = _pem(-1)
    r = full.zpa_26(Fake(_certs({"name": "c", "pem": pem})))
    body = pem.splitlines()[1]
    assert r.status == R.FAIL and body not in r.detail and "BEGIN" not in r.detail
    pasted = pem + "-----BEGIN PRIVATE KEY-----\n" + CANARY + "\n-----END PRIVATE KEY-----\n"
    kept = ot.scrub([{"name": "c", "pem": pasted, "isDefault": True}])
    assert CANARY not in json.dumps(kept) and kept[0]["pem"] == "(set)" and kept[0]["name"] == "c"


def test_ca6_a_profile_not_ready_is_flagged_and_a_deleted_one_ignored():
    """ASVS V1.14.1 · CWE-1164: a header profile ZIA marks not ready for use asks for review; a deleted profile is left out."""
    table = {"/zia/httpHeaderProfile": ([{"name": "Gone", "deleted": True, "httpHeaderProfileCriteria": []},
                                         {"name": "Pending", "profileReadyForUse": False, "httpHeaderProfileCriteria": [{"header": "Host"}]}], 200),
             "/zia/httpHeaderActionProfile": ([], 200)}
    r = full.ca_6(Fake(table))
    assert r.status == R.WARN and "Pending (header profile: not ready for use)" in r.detail and "Gone" not in r.detail, r.detail


def test_zpa25_a_nearly_full_range_is_flagged_and_counts_are_derived():
    """ASVS V1.14.1 · CWE-400: a range 90 % used asks for review; available addresses are worked out from total and used when not given; disabled ranges are left out."""
    rows = [{"name": "Nearly", "enabled": True, "totalIps": 100, "usedIps": 95},
            {"name": "Off", "enabled": False, "totalIps": 10, "usedIps": 10, "availableIps": 0}]
    r = full.zpa_25(Fake({"/zpa/ipRanges": (rows, 200)}))
    assert r.status == R.WARN and "Nearly (95 of 100 used)" in r.detail and "Off" not in r.detail, r.detail


def test_item8_new_paths_resolve_to_the_sdk_base_paths():
    """SSDF PW.4.1 · CWE-1164: the client-to-client ranges and isolation certificates resolve to the base paths the installed SDK builds (a /v2 segment of the customer base; the cbiconfig service base)."""
    c2c = inspect.getsource(importlib.import_module("zscaler.zpa.c2c_ip_ranges"))
    cbi = inspect.getsource(importlib.import_module("zscaler.zpa.cbi_certificate"))
    assert 'f"/zpa/mgmtconfig/v1/admin/customers/{customer_id}/v2"' in c2c and 'f"/zpa/cbiconfig/cbi/api/customers/{customer_id}"' in cbi
    assert A._resolve_ep("/zpa/ipRanges", "123") == "/zpa/mgmtconfig/v1/admin/customers/123/v2/ipRanges"
    assert A._resolve_ep("/zpa/cbiconfig/certificates", "123") == "/zpa/cbiconfig/cbi/api/customers/123/certificates"
    assert ot.normalize_path("/zpa/cbiconfig/cbi/api/customers/123/certificates") == "/zpa/cbiconfig/cbi/api/customers/{customerId}/certificates"


def test_item8_checks_are_in_the_ztw_registry_and_the_others_in_their_sections():
    """ASVS V1.14.1 · CWE-1164: each new check sits in the product section whose Scope key reads it (ZIA Firewall and Cloud Apps, ZPA App Access, Cloud & Branch Connector)."""
    sections = {r[0]: r[1] for r in full.COVERAGE_REG}
    assert sections["FW.11"] == sections["FW.12"] == "ZIA — Firewall" and sections["CA.6"] == "ZIA — Cloud Apps"
    assert sections["ZPA.25"] == sections["ZPA.26"] == "ZPA — App Access" and sections["ZTW.9"].startswith("ZTW")
