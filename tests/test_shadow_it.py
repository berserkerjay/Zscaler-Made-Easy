"""Shadow IT sanction and Insights checks (work package w8 shadow-it).

Covers: the Insights assessment checks INS.1-INS.3 (pass, fail, N/A, not
permitted, the Scope gate and the legacy full scope), the raw-client
executor the checks and snapshots ask Z-Insights through, the new Traffic
insights sections (threat class and super-category, firewall by location
and network service, incidents by location, IoT), the sample tenant's and
a snapshot's Insights answers, and the Bulk changes operation
cloud_app_sanction (scope refused before sign-in, the plan and its
exclusions, the typed phrase always, the four write gates, the re-read
conflict, the read-back, the audit entry with the actor and the exact
Undo). The real SDK services run against the in-memory sample tenant
(offline_tenant, no network code); no real tenant is ever contacted.
"""
from __future__ import annotations

import copy
import json
import os
import re
import uuid

import pytest
from fastapi.testclient import TestClient

import admin_ops as ao
import insights
import offline_tenant as ot
import ops_sanction as osn
import sample_tenant
import zscaler_full_checks as zf

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCOPE = ao.scope_for(["zia_extras", "insights"], {})
CHECKS = {cid: fn for cid, _sec, _label, fn in zf.PLATFORM_REG if cid.startswith("INS.")}


def _store(mutate=None, writable=True, kind=ot.SAMPLE):
    """A fresh in-memory copy of the sample tenant (its own id), optionally changed."""
    r = copy.deepcopy(sample_tenant.responses())
    if mutate:
        mutate(r)
    responses = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in r.items()}
    return ot.OfflineStore(f"t-{uuid.uuid4().hex[:8]}", kind, responses, sample_tenant.meta(), writable=writable)


def _sdk(store):
    return ot.OfflineSdkClient(store, ot.creds_for(store))


def _raw(store):
    return ot.OfflineRawClient(store, ot.creds_for(store))


def _apps(r):
    return r["/zins/graphql/ShadowITApps"]["data"]["SHADOW_IT"]["apps"]["entries"]


def _state_of(store, name):
    ent = store.responses["/zins/graphql/ShadowITApps"]["body"]["data"]["SHADOW_IT"]["apps"]["entries"]
    return next(e["sanctioned_state"] for e in ent if e["application"] == name)


def _ids():
    return {a["name"]: a["id"] for a in sample_tenant.CLOUD_APPS}


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)


# ── The assessment checks ──────────────────────────────────────────────

def test_the_three_insights_checks_find_the_sample_tenants_gaps_with_plain_findings():
    """ASVS V1.14.1 · CWE-1059 · WSTG-CONF-01: on the sample, INS.1 names the high-risk unsanctioned apps with traffic, INS.2 the high-risk app with no decision, INS.3 the sanctioned SaaS apps without a SaaS Security API tenant, each with the fix."""
    cl = _raw(_store())
    r1, r2, r3 = (CHECKS[c](cl) for c in ("INS.1", "INS.2", "INS.3"))
    assert r1.status == "FAIL" and r1.data["names"] == ["WeTransfer", "MEGA", "Pastebin"] and "Best Practice:" in r1.detail
    assert "Dropbox" not in r1.detail, "risk 3 is not high risk"
    assert r2.status == "REVIEW" and r2.data["names"] == ["ChatGPT"]
    assert r3.status == "FAIL" and set(r3.data["names"]) == {"Slack", "Salesforce", "Zoom"} and "Box" not in r3.detail
    assert r3.data["tenants"] == 3


def test_a_tenant_without_the_gaps_passes():
    """ASVS V1.14.1 · CWE-697: with every risky app sanctioned or blocked off and every SaaS app connected, the checks pass."""
    def fix(r):
        for e in _apps(r):
            if e["risk_index"] >= 4:
                e["sanctioned_state"] = "Unsanctioned"
                e["data_consumed"] = e["data_uploaded"] = 0
        r["/zia/api/v1/casbTenant/lite"] += [{"tenantId": 600 + i, "tenantName": n, "saasApplication": n.upper(), "status": ["ACTIVE"]}
                                             for i, n in enumerate(("Slack", "Salesforce", "Zoom"))]
    cl = _raw(_store(fix))
    assert [CHECKS[c](cl).status for c in ("INS.1", "INS.2", "INS.3")] == ["PASS", "PASS", "PASS"]


def test_no_casb_subscription_or_no_traffic_is_not_applicable_never_a_failure():
    """ASVS V1.14.1 · CWE-754: without a CASB subscription INS.3 is N/A (INFO, outside the score); with no Shadow IT traffic INS.1 and INS.2 are N/A."""
    def no_casb(r):
        r["/zia/api/v1/subscriptions"] = [s for s in r["/zia/api/v1/subscriptions"] if not s["id"].startswith("Z_CASB")]
    r = CHECKS["INS.3"](_raw(_store(no_casb)))
    assert r.status == "INFO" and r.detail.startswith("N/A") and "CASB" in r.detail

    def empty(r):
        _apps(r).clear()
    cl = _raw(_store(empty))
    for c in ("INS.1", "INS.2"):
        r = CHECKS[c](cl)
        assert r.status == "INFO" and r.detail.startswith("N/A"), r.detail


def test_a_refused_insights_read_is_not_permitted_and_the_classic_sign_in_is_not_applicable():
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: a 403 from Z-Insights is "Not permitted" (never judged); the classic ZIA API sign-in has no Z-Insights path and nothing is sent."""
    class Refusing:
        def post(self, ep, body=None):
            return {"message": "Forbidden"}, 403

        def get(self, ep, *a, **k):
            return [], 200
    r = CHECKS["INS.1"](Refusing())
    assert r.status == "INFO" and "Not permitted" in r.detail and "Access denied" in r.detail
    import permissions
    assert permissions.is_denied(r.detail)

    class Legacy:
        sent = []

        def post(self, ep, body=None):
            from dlp_assessment_full_auto import _LEGACY_ZIA_ONLY, _resolve_ep
            assert _resolve_ep(ep, None, legacy=True) is None
            return _LEGACY_ZIA_ONLY

        def get(self, ep, *a, **k):
            return [], 200
    r = CHECKS["INS.2"](Legacy())
    assert r.status == "INFO" and r.detail.startswith("N/A")


def test_the_insights_checks_run_only_when_insights_is_ticked_and_never_under_the_legacy_full_scope():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the Scope rule: "Insights —" checks are selected for the insights key alone; ZIA platform or the legacy full scope never reads traffic data."""
    import dlp_api_server as srv
    ids = lambda checks: {c[0] for c in checks}  # noqa: E731
    assert {"INS.1", "INS.2", "INS.3"} <= ids(srv._get_checks(scopes=["insights"]))
    assert not {"INS.1", "INS.2", "INS.3"} & ids(srv._get_checks(scopes=["dlp", "zia_extras", "zpa", "zcc", "genai"]))
    assert not {"INS.1", "INS.2", "INS.3"} & ids(srv._get_checks(scope="full"))
    assert ids(srv._get_checks(scopes=["insights"])) == {"INS.1", "INS.2", "INS.3"}


def test_each_insights_finding_reads_as_four_plain_sentences_with_a_fix():
    """WCAG 2.2 SC 3.1.5 · ASVS V1.14.1: every INS finding gets the plain found / means / do / outcome block, with the Shadow IT fix and its portal path."""
    import plain_english
    cl = _raw(_store())
    for cid, sec, label, fn in zf.PLATFORM_REG:
        if not cid.startswith("INS."):
            continue
        r = fn(cl)
        e = plain_english.explain({"id": cid, "section": sec, "label": label, "status": r.status, "detail": r.detail})
        assert all(e[k] for k in ("found", "means", "do", "outcome")), (cid, e)
        assert "decision" in e["outcome"] and ("Shadow IT" in e["do"] or "SaaS Application Tenants" in e["do"]), (cid, e["do"])


def test_the_insights_checks_read_aggregates_only():
    """ASVS V8.3.4 · CWE-359: the checks ask Z-Insights for application aggregates only: never a user, device or host dimension."""
    sent = []

    class Rec:
        def __init__(self, cl):
            self.cl = cl

        def post(self, ep, body=None):
            sent.append(body)
            return self.cl.post(ep, body)

        def get(self, ep, *a, **k):
            return self.cl.get(ep, *a, **k)
    cl = Rec(_raw(_store()))
    for fn in CHECKS.values():
        fn(cl)
    assert sent and {b["operationName"] for b in sent} == {"ShadowITApps"}
    q = " ".join(b["query"] for b in sent).lower()
    assert "user_id" not in q and "hostname" not in q and "device" not in q


# ── The raw-client executor and the Insights page sections ─────────────

def test_the_raw_executor_keeps_the_sdks_own_queries_and_says_why_an_answer_was_refused():
    """ASVS V7.4.1 · CWE-209 · CWE-20: the SDK's query goes out as built by the SDK; a refusal becomes an error with its status, a malformed answer never crashes."""
    seen = []

    class Cl:
        def __init__(self, answer):
            self.answer = answer

        def post(self, ep, body=None):
            seen.append((ep, body["operationName"]))
            if isinstance(self.answer, Exception):
                raise self.answer
            return self.answer
    z = insights.zins_over(Cl(({"message": "slow down"}, 429)))
    data, _r, err = z.firewall.get_network_services(start_time=1, end_time=2)
    assert data is None and isinstance(err, insights.InsightsRefused) and err.status == 429 and err.classification == "TOO_MANY_REQUESTS"
    assert seen[-1] == ("/zins/graphql", "FirewallNetworkServices")
    _d, _r, err = insights.zins_over(Cl(RuntimeError("reset"))).iot.get_device_stats()
    assert isinstance(err, insights.InsightsRefused) and "reset" in str(err)
    _d, _r, err = insights.zins_over(Cl(("not json", 200))).web_traffic.get_threat_class(start_time=1, end_time=2)
    assert isinstance(err, insights.InsightsRefused)


def test_the_new_traffic_insights_sections_read_from_the_sample_and_export_without_users():
    """ASVS V8.3.4 · CWE-359 · CWE-1236: threat class and super-category, firewall by location and service, incidents by location and IoT are read; the CSV carries them and no user, and tenant text stays inert."""
    w = insights.window("7d")
    res = insights.read(_sdk(_store()), w["start_ms"], w["end_ms"], pace=0)
    s = res["sections"]
    assert res["status"] == "ok", {k: v["status"] for k, v in s.items()}
    assert s["threat_class"]["rows"][0] == {"name": "Advanced Threats", "total": 412}
    assert s["threat_super"]["rows"][0]["name"] == "Phishing"
    assert s["fw_location"]["rows"][0]["name"] == "Larkspur HQ (Portland)" and s["fw_service"]["rows"][-1] == {"name": "SSH", "total": 1900}
    assert s["incident_location"]["rows"][1] == {"name": "Reno depot", "total": 23}
    iot = s["iot"]["summary"]
    assert iot["totals"]["iot_devices_count"] == 96 and iot["groups"][0]["rows"][0] == {"name": "IP camera", "category": "IoT", "total": 38}
    assert "no time window" in s["iot"]["note"]
    csv = insights.to_csv(res)
    assert "Web threats by class" in csv and "IoT and unmanaged devices" in csv and ",devices," in csv
    assert "larkspur-freight.example" not in csv, "the per-user section is never exported"


def test_the_iot_parser_is_defensive():
    """ASVS V5.1.4 · CWE-20: junk entries, missing totals and over-long names are skipped or trimmed; a non-object answer is empty."""
    out = insights.iot_of({"devices_count": "12", "entries": ["x", {"classifications": None, "total": 3}, {"classifications": "y" * 500, "total": "4"},
                                                                  {"classifications": "z", "total": "n/a"}]})
    assert out["totals"]["devices_count"] == 12 and out["totals"]["iot_devices_count"] is None
    rows = out["groups"][0]["rows"]
    assert rows[0]["name"] == "(unclassified)" and len(rows[1]["name"]) == insights.NAME_MAX and len(rows) == 2
    assert insights.iot_of("junk") == {"totals": {k: None for k in insights._IOT_TOTALS}, "groups": []}


def test_sanction_words_are_read_strictly():
    """ASVS V5.1.3 · CWE-20: only the two states are recognised; ANY, blanks and anything else are "not stated"."""
    assert [insights.sanction_of(v) for v in ("Sanctioned", "SANCTIONED", "UN_SANCTIONED", "Unsanctioned", "ANY", "", None, "sanctioned!x")] == \
        ["sanctioned", "sanctioned", "unsanctioned", "unsanctioned", None, None, None, None]


# ── Offline: the sample and snapshots ─────────────────────────────────

def test_a_snapshot_keeps_the_insights_answers_per_question_without_the_per_user_one():
    """ASVS V8.3.4 · CWE-359 · CWE-200: saving a snapshot with Insights in scope keeps each aggregate answer and the app list; the per-user incidents query is never asked; the snapshot then answers offline and refuses the sanction write."""
    asked = []
    src = _store()
    raw = _raw(src)
    real = raw.post

    def post(ep, body=None):
        asked.append((body or {}).get("operationName"))
        return real(ep, body)
    raw.post = post
    cap = ot.capture(raw, ["insights"], {}, lambda m: None)
    keys = set(cap["responses"])
    assert "CyberSecurityIncidents" not in asked
    assert {"/zins/graphql/ShadowITApps", "/zins/graphql/IoTDeviceStats", "/zins/graphql/FirewallNetworkServices"} <= keys
    assert "/zins/graphql/CyberSecurityIncidents" not in keys
    assert "/zia/api/v1/cloudApplications/lite" in keys and "/zia/api/v1/subscriptions" in keys
    assert all(ot.valid_path(k) for k in keys)
    snap = ot.OfflineStore("snap-x", "snapshot", cap["responses"], {"kind": "snapshot"}, writable=False)
    assert CHECKS["INS.1"](_raw(snap)).status == "FAIL"
    st, body = snap.answer_write("PUT", "/zia/api/v1/cloudApplications/bulkUpdate", {"sanctionedState": "SANCTIONED", "applicationIds": [2105]})
    assert st == 403 and snap.writes == 0


def test_the_offline_insights_answer_filters_by_application_and_refuses_odd_operations():
    """ASVS V5.1.4 · CWE-20 · CWE-73: the Shadow IT application filter is honoured; an operation name that is not a plain identifier is never looked up."""
    s = _store()
    st, body = s.answer_write("POST", "/zins/graphql", {"operationName": "ShadowITApps", "variables": {"filterBy": {"application": {"in": ["Box", "MEGA"]}}}})
    assert st == 200 and [e["application"] for e in body["data"]["SHADOW_IT"]["apps"]["entries"]] == ["Box", "MEGA"]
    for op in ("../zia/api/v1/adminUsers", "", None, "a" * 100, "Shadow IT"):
        st, _b = s.answer_write("POST", "/zins/graphql", {"operationName": op})
        assert st == 404, op


def test_the_sample_bulk_update_is_validated():
    """ASVS V5.1.3 · CWE-20: the sample refuses a bulk update with an unknown state or id; a valid one changes only the named apps."""
    s = _store()
    assert s.answer_write("PUT", "/zia/api/v1/cloudApplications/bulkUpdate", {"sanctionedState": "MAYBE", "applicationIds": [2100]})[0] == 400
    assert s.answer_write("PUT", "/zia/api/v1/cloudApplications/bulkUpdate", {"sanctionedState": "SANCTIONED", "applicationIds": [99]})[0] == 400
    assert s.answer_write("PUT", "/zia/api/v1/cloudApplications/bulkUpdate", {"sanctionedState": "SANCTIONED", "applicationIds": [2106]})[0] == 204
    assert _state_of(s, "MEGA") == "Sanctioned" and _state_of(s, "WeTransfer") == "Unsanctioned"


# ── The sanction operation ─────────────────────────────────────────────

@pytest.mark.parametrize("scopes", [[], ["zia_extras"], ["insights"], ["dlp", "zpa"]])
def test_sanction_out_of_scope_is_refused_before_anything_is_read(scopes):
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: without both ZIA platform and ZIA Insights ticked the operation and its picker are refused before any request."""
    s = _store()
    reads = []
    s.answer_get = lambda *a, **k: reads.append(a) or (200, [])
    with pytest.raises(ao.OperationError, match="ZIA Insights"):
        ao.plan(_sdk(s), {"type": osn.T_SANCTION, "targets": [{"id": 2105, "to": "sanctioned"}]}, scope=ao.scope_for(scopes, {}))
    with pytest.raises(ao.OperationError, match="ZIA Insights"):
        ao.read_objects(_sdk(s), osn.FAMILY, ao.scope_for(scopes, {}))
    assert reads == [] and s.writes == 0


def test_the_picker_lists_only_apps_with_a_known_state_riskiest_first():
    """ASVS V1.4.1 · CWE-200: the picker lists the apps whose state can be read (risk and traffic beside each), says how many cannot be changed, and writes nothing."""
    s = _store()
    out = ao.read_objects(_sdk(s), osn.FAMILY, SCOPE)
    names = [a["name"] for a in out["apps"]]
    assert names[:2] == ["WeTransfer", "MEGA"] and "ChatGPT" not in names and out["unknown"] == 1 and out["catalogue"] == 11
    assert out["apps"][0]["state"] == "unsanctioned" and out["apps"][0]["risk_index"] == 5 and s.writes == 0
    assert "Tenant-wide" in out["tenant_wide"]


def test_the_plan_reads_each_state_and_excludes_what_it_cannot_undo():
    """ASVS V1.14.6 · CWE-20 · WSTG-BUSL-01: before and after per app; an app with no readable state, an unknown id and a renamed app are excluded with the reason; the same state is a no-op; the typed phrase is asked even for two changes."""
    ids = _ids()
    spec = {"type": osn.T_SANCTION, "targets": [{"id": ids["WeTransfer"], "name": "WeTransfer", "to": "Sanctioned"},
                                               {"id": ids["ChatGPT"], "to": "unsanctioned"}, {"id": ids["Box"], "to": "sanctioned"},
                                               {"id": 999, "to": "unsanctioned"}, {"id": ids["Slack"], "name": "Old Slack", "to": "unsanctioned"},
                                               {"id": ids["MEGA"], "to": "UN_SANCTIONED"}]}
    p = ao.plan(_sdk(_store()), spec, scope=SCOPE)
    by = {u["object"]["name"]: u for u in p["items"]}
    assert (by["WeTransfer"]["before"], by["WeTransfer"]["after"], by["WeTransfer"]["status"]) == ("unsanctioned", "sanctioned", "change")
    assert by["ChatGPT"]["status"] == "excluded" and "no exact Undo" in by["ChatGPT"]["reason"]
    assert by["Box"]["status"] == "noop" and by["MEGA"]["status"] == "noop"
    assert by["Slack"]["status"] == "excluded" and "now called 'Slack'" in by["Slack"]["reason"]
    assert any(u["status"] == "excluded" and "not in the tenant" in u["reason"] for u in p["items"])
    assert p["counts"]["change"] == 1 and p["confirm_phrase"] == "CHANGE 1 CLOUD APPS" and p["needs_activation"] is True
    assert any("Tenant-wide" in w for w in p["warnings"])


@pytest.mark.parametrize("targets,needle", [([], "at least one"), ("x", "at least one"), ([{"id": "1; drop", "to": "sanctioned"}], "number"),
                                            ([{"id": 1, "to": "any"}], "sanctioned or unsanctioned"), ([{"id": 1}], "sanctioned or unsanctioned"),
                                            ([{"id": i, "to": "sanctioned"} for i in range(101)], "At most 100"), (["x"], "object")])
def test_bad_requests_are_refused_before_anything_is_read(targets, needle):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: targets are checked (list, numeric ids, the two states, at most 100) before any read."""
    s = _store()
    reads = []
    s.answer_get = lambda *a, **k: reads.append(a) or (200, [])
    with pytest.raises(ao.OperationError, match=needle):
        ao.plan(_sdk(s), {"type": osn.T_SANCTION, "targets": targets}, scope=SCOPE)
    assert reads == []


def _apply(client, spec, prepared=None, **kw):
    prepared = prepared or ao.plan(client, spec, scope=SCOPE)
    kw.setdefault("confirm_text", prepared["confirm_phrase"])
    kw.setdefault("assessor", "Jane Doe")
    return ao.execute(client, spec, plan_hash=prepared["plan_hash"], scope=SCOPE, writes_enabled=kw.pop("writes", True), settle_seconds=0, **kw)


def test_apply_needs_write_mode_the_assessor_and_the_typed_phrase():
    """ASVS V4.1.3 · V1.14.6 · CWE-841 · WSTG-BUSL-06: write mode off, no assessor or the wrong phrase writes nothing."""
    s = _store()
    c = _sdk(s)
    spec = {"type": osn.T_SANCTION, "targets": [{"id": _ids()["WeTransfer"], "to": "sanctioned"}]}
    with pytest.raises(PermissionError):
        _apply(c, spec, writes=False)
    with pytest.raises(ao.OperationError):
        _apply(c, spec, assessor="  ")
    r = _apply(c, spec, confirm_text="yes")
    assert r["status"] != "applied" and s.writes == 0 and _state_of(s, "WeTransfer") == "Unsanctioned"


def test_apply_sends_one_bulk_update_per_state_reads_back_and_undo_restores_each_app():
    """ASVS V1.14.6 · V7.1.3 · CWE-841 · WSTG-BUSL-01: one bulk_update per target state with the app ids only (no tags), read back; Undo puts each app back to the state the plan read."""
    s = _store()
    sent = []
    real = s.answer_write

    def spy(method, url, body=None):
        if "bulkUpdate" in url:
            sent.append(copy.deepcopy(body))
        return real(method, url, body)
    s.answer_write = spy
    c, ids = _sdk(s), _ids()
    spec = {"type": osn.T_SANCTION, "targets": [{"id": ids["WeTransfer"], "to": "sanctioned"}, {"id": ids["MEGA"], "to": "sanctioned"},
                                               {"id": ids["Slack"], "to": "unsanctioned"}]}
    r = _apply(c, spec)
    assert r["status"] == "applied" and r["verification"]["confirmed"] == 3 and not r["verification"]["mismatched"]
    assert sorted((b["sanctionedState"], sorted(b["applicationIds"])) for b in sent) == [("SANCTIONED", sorted([ids["WeTransfer"], ids["MEGA"]])),
                                                                                         ("UN_SANCTIONED", [ids["Slack"]])]
    assert all("customTags" not in b for b in sent), "tags are never sent"
    assert (_state_of(s, "WeTransfer"), _state_of(s, "Slack")) == ("Sanctioned", "Unsanctioned")
    inv = r["inverse"]
    assert inv["type"] == osn.T_SANCTION and {(t["name"], t["to"]) for t in inv["targets"]} == {("WeTransfer", "unsanctioned"), ("MEGA", "unsanctioned"), ("Slack", "sanctioned")}
    r2 = _apply(c, inv)
    assert r2["status"] == "applied" and (_state_of(s, "WeTransfer"), _state_of(s, "MEGA"), _state_of(s, "Slack")) == ("Unsanctioned", "Unsanctioned", "Sanctioned")


def test_an_app_changed_in_the_tenant_after_the_re_plan_is_a_conflict_and_not_sent(monkeypatch):
    """ASVS V1.14.6 · CWE-367 (TOCTOU) · WSTG-BUSL-01: the handler re-reads every app right before the write; one someone changed meanwhile is a conflict, the rest are sent."""
    s = _store()
    c, ids = _sdk(s), _ids()
    calls = {"n": 0}
    real = osn.read_usage

    def moving(zins, names=None, now_ms=None):
        calls["n"] += 1
        if calls["n"] == 3:   # plan, re-plan, then the handler's re-read: someone changes MEGA in the portal
            ent = s.responses["/zins/graphql/ShadowITApps"]["body"]["data"]["SHADOW_IT"]["apps"]["entries"]
            next(e for e in ent if e["application"] == "MEGA")["sanctioned_state"] = "Sanctioned"
        return real(zins, names, now_ms)
    monkeypatch.setattr(osn, "read_usage", moving)
    spec = {"type": osn.T_SANCTION, "targets": [{"id": ids["WeTransfer"], "to": "sanctioned"}, {"id": ids["MEGA"], "to": "sanctioned"}]}
    r = _apply(c, spec)
    by = {u["object"]["name"]: u for u in r["items"]}
    assert by["MEGA"]["status"] == "conflict" and "since the preview" in by["MEGA"]["reason"]
    assert by["WeTransfer"]["status"] == "applied"
    assert r["inverse"]["targets"] == [{"id": str(ids["WeTransfer"]), "name": "WeTransfer", "to": "unsanctioned"}]


def test_insights_not_answering_blocks_the_plan():
    """ASVS V1.14.6 · CWE-754: without the current states (Insights refused) nothing is planned: the plan is blocked with the reason."""
    def no_insights(r):
        del r["/zins/graphql/ShadowITApps"]
    p = ao.plan(_sdk(_store(no_insights)), {"type": osn.T_SANCTION, "targets": [{"id": 2105, "to": "sanctioned"}]}, scope=SCOPE)
    assert p["status"] == "blocked" and any("ZIA Insights could not be read" in b for b in p["blockers"])


def test_a_state_on_the_app_lists_raw_row_is_used_when_present():
    """ASVS V5.1.4 · CWE-20: when the application list's raw answer carries a state (an assumed field), it is the before; Insights is the fallback."""
    def raw_state(r):
        for a in r["/zia/api/v1/cloudApplications/lite"]:
            if a["name"] == "ChatGPT":
                a["sanctionedState"] = "UN_SANCTIONED"
    p = ao.plan(_sdk(_store(raw_state)), {"type": osn.T_SANCTION, "targets": [{"id": _ids()["ChatGPT"], "to": "sanctioned"}]}, scope=SCOPE)
    assert p["items"][0]["before"] == "unsanctioned" and p["items"][0]["status"] == "change"


def test_every_sanction_write_leaves_an_audit_entry(tmp_path):
    """ASVS V7.1.3 · V7.2.1 · CWE-778: the bulk update is one object_write audit entry (kind, the ids, the names, the result)."""
    s = _store()
    _apply(_sdk(s), {"type": osn.T_SANCTION, "targets": [{"id": _ids()["WeTransfer"], "to": "sanctioned"}]})
    rows = [json.loads(x) for x in (tmp_path / "audit.log").read_text().splitlines()]
    w = [r for r in rows if r.get("event") == "object_write"]
    assert len(w) == 1 and w[0]["object_type"] == "cloud_app_sanction" and w[0]["result"] == "ok" and w[0]["id"] == str(_ids()["WeTransfer"])
    assert w[0]["name"] == "WeTransfer"


BODY = {"scopes": ["zia_extras", "insights"], "channels": {}, "from_page": True, "client_id": "cid", "client_secret": "s3cret-value",
        "vanity_domain": "acme", "cloud": "zscalertwo", "assessor": "Jane Doe"}


def test_the_bulk_changes_routes_gate_preview_apply_record_and_undo(monkeypatch, tmp_path):
    """ASVS V4.1.3 · V1.14.6 · V7.1.3 · CWE-841 · WSTG-ATHZ-02: scope is a 400 before sign-in; preview writes nothing and never echoes the secret; apply needs write mode and the assessor; the record's Undo restores the app; the audit log names the actor."""
    import dlp_api_server as srv
    s = _store()
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or _sdk(s))
    c = TestClient(srv.app)
    op = {"type": osn.T_SANCTION, "targets": [{"id": _ids()["WeTransfer"], "name": "WeTransfer", "to": "sanctioned"}]}
    assert any(p["type"] == osn.T_SANCTION and p["script"] == "ops_sanction.js" and p["group"] == "Change existing"
               for p in c.get("/api/operations/plugins").json()["plugins"])
    r = c.post("/api/operations/preview", json=dict(BODY, scopes=["zia_extras"], operation=op))
    assert r.status_code == 400 and "ZIA Insights" in r.json()["detail"] and built == []
    r = c.post("/api/operations/preview", json=dict(BODY, operation=op))
    assert r.status_code == 200, r.text
    p = r.json()
    assert p["confirm_phrase"] == "CHANGE 1 CLOUD APPS" and s.writes == 0 and "s3cret" not in r.text
    monkeypatch.setattr(srv, "writes_enabled", lambda: False)
    r = c.post("/api/operations/apply", json=dict(BODY, operation=op, plan_hash=p["plan_hash"], confirm=True, confirm_text=p["confirm_phrase"]))
    assert r.status_code == 403 and s.writes == 0
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    r = c.post("/api/operations/apply", json=dict(BODY, operation=op, plan_hash=p["plan_hash"], confirm=True, confirm_text=p["confirm_phrase"], assessor=""))
    assert r.status_code == 400 and s.writes == 0
    r = c.post("/api/operations/apply", json=dict(BODY, operation=op, plan_hash=p["plan_hash"], confirm=True, confirm_text=p["confirm_phrase"]))
    assert r.status_code == 200 and r.json()["status"] == "applied", r.text
    assert _state_of(s, "WeTransfer") == "Sanctioned"
    op_id = r.json()["operation_id"]
    u = c.post(f"/api/operations/{op_id}/undo/preview", json=BODY).json()
    assert u["undo_of"] == op_id and u["counts"]["change"] == 1
    r = c.post("/api/operations/apply", json=dict(BODY, operation=u["operation"], plan_hash=u["plan_hash"], confirm=True,
                                                  confirm_text=u["confirm_phrase"], undo_of=op_id))
    assert r.status_code == 200 and r.json()["status"] == "applied" and _state_of(s, "WeTransfer") == "Unsanctioned"
    log = (tmp_path / "audit.log").read_text()
    assert "s3cret" not in log
    assert any(json.loads(x).get("actor") for x in log.splitlines() if '"object_write"' in x), "each write names who ran it"


# ── The page form ──────────────────────────────────────────────────────

def test_the_form_script_labels_its_controls_escapes_tenant_text_and_registers_the_type():
    """WCAG 2.2 SC 1.3.1 · SC 3.3.2 · SC 4.1.2 · ASVS V5.3.3 · CWE-79: static/ops_sanction.js registers cloud_app_sanction, names every input, and passes every tenant value through H.E (escape) before it reaches HTML."""
    js = open(os.path.join(ROOT, "static", "ops_sanction.js"), encoding="utf-8").read()
    assert "window.OPS_PLUGINS.register({ type: 'cloud_app_sanction'" in js
    for tag in re.findall(r"<input\b[^>]*>", js):
        assert "aria-label=" in tag or "type=\"radio\"" in tag or "type=\"checkbox\" id=" in tag, tag
    # every interpolation inside the HTML templates is escaped (E(...)) or a number / a fixed word
    html_part = js[js.index("function rows("):js.index("function spec(")]
    for expr in re.findall(r"\$\{([^}]*)\}", html_part):
        e = expr.strip()
        assert (e.startswith(("E(", "H.E(", "rows(", "H.errorsHtml(", "MAX", "z.pick.size", "shown.length", "apps.length"))
                or "checked" in e or "st-" in e or e.startswith("a.risk_index == null")), e
    assert not re.search(r"#[0-9a-fA-F]{3,6}\b", js), "colours come from the theme"


def test_the_help_catalogue_covers_every_new_control():
    """WCAG 2.2 SC 3.3.2 · SC 1.4.13: each new control on Bulk changes and the Insights page has a help entry."""
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    for sel in ('input[name=\\"opKind\\"][value=\\"cloud_app_sanction\\"]', 'input[name=\\"sanTo\\"][value=\\"unsanctioned\\"]',
                'input[name=\\"sanTo\\"][value=\\"sanctioned\\"]', '"#sanFilter"', '"#sanRisky"', '"#sanNone"',
                '#opObjects:has(input[name=\\"sanTo\\"]) input[data-id]'):
        assert sel in cat, sel
    ext = open(os.path.join(ROOT, "browser_extension", "help_catalog.js"), encoding="utf-8").read()
    assert ext == cat
