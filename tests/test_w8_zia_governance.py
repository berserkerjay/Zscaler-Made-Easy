"""ZIA governance and audit checks (w8-zia-governance).

GOV.1-GOV.8 in zscaler_full_checks (Zscaler's configuration audit, alert
subscriptions, NSS VM health and log streaming, N/A when not licensed) and
RBAC.13-RBAC.14 in zscaler_rbac_checks (admin password expiry, Zscaler
Support remote assistance). Every test is offline: a dict-backed fake client,
or the made-up sample tenant behind offline_tenant's clients."""
import importlib
import json

import pytest

import offline_tenant as ot
import permissions
import plain_english
import posture_plus
import sample_tenant
import scope_permissions
import zscaler_full_checks as fc
import zscaler_rbac_checks as rbac
import compliance_mapping

NOW = 1793000000.0   # 2026-10-26, the sample report's day
ZIA = "/zia/api/v1"


class FakeCl:
    """Answers short endpoints from a dict; anything else is 404."""
    customer_id = ""

    def __init__(self, routes, codes=None):
        self.routes, self.codes, self.calls = routes, codes or {}, []

    def get(self, endpoint, params=None):
        ep = endpoint.replace("raw:", "")
        self.calls.append(ep)
        if ep in self.codes:
            return {"error": "refused", "code": "RBA_LIMITED"}, self.codes[ep]
        if ep in self.routes:
            return self.routes[ep], 200
        return {"error": "not found"}, 404


def _reg(reg, cid):
    return next(fn for i, _s, _l, fn in reg if i == cid)


GOV = {cid: _reg(fc.PLATFORM_REG, cid) for cid in ("GOV.1", "GOV.2", "GOV.3", "GOV.4", "GOV.5", "GOV.6", "GOV.7", "GOV.8")}
RBAC13 = _reg(rbac.RBAC_REG, "RBAC.13")
RBAC14 = _reg(rbac.RBAC_REG, "RBAC.14")
LICENSED = [{"id": "ZIA_TENANT", "status": "ACTIVE", "subscribed": True}, {"id": "Z_CLOUD_NSS_WEB", "status": "ACTIVE", "subscribed": True}]
UNLICENSED = [{"id": "ZIA_TENANT", "status": "ACTIVE", "subscribed": True}]


# ── The registry, the scope and the sample ─────────────────────────────

def test_the_governance_checks_run_under_the_scope_page_keys_they_read_for():
    """ASVS V1.14.1 · CWE-1287: GOV.* run with ZIA platform (zia_extras) and RBAC.13-14 with RBAC; their reads are listed for those keys, so nothing un-ticked is read."""
    gov = [(i, s) for i, s, _l, _f in fc.PLATFORM_REG if i.startswith("GOV.")]
    rb = [(i, s) for i, s, _l, _f in rbac.RBAC_REG if i in ("RBAC.13", "RBAC.14")]
    zia_eps = set(scope_permissions.SCOPE_PERMISSIONS["zia_extras"]["endpoints_used"])
    rbac_eps = set(scope_permissions.SCOPE_PERMISSIONS["rbac"]["endpoints_used"])

    assert len(gov) == 8 and all(permissions.scope_of_section(s) == "zia_extras" for _i, s in gov)
    assert len(rb) == 2 and all(permissions.scope_of_section(s) == "rbac" for _i, s in rb)
    assert {"/zia/configAudit", "/zia/alertSubscriptions", "/zia/nssServers", "/zia/nssCollectors", "/zia/nssFeeds", "/zia/subscriptions"} <= zia_eps
    assert {"/zia/passwordExpiry/settings", "/zia/remoteAssistance"} <= rbac_eps


def test_a_snapshot_reads_the_governance_endpoints_only_for_their_ticked_scope():
    """ASVS V4.1.3 · CWE-863 · WSTG-ATHZ-02: the snapshot plan adds the config audit, alerts and NSS reads only with ZIA platform, and password expiry and remote assistance only with RBAC."""
    dlp, zia, rb = set(ot.capture_plan(["dlp"])), set(ot.capture_plan(["zia_extras"])), set(ot.capture_plan(["rbac"]))
    gov = {"/zia/configAudit", "/zia/alertSubscriptions", "/zia/nssServers", "/zia/nssCollectors", "/zia/subscriptions"}
    adm = {"/zia/passwordExpiry/settings", "/zia/remoteAssistance"}

    assert gov <= zia and not gov & rb and not gov & dlp
    assert adm <= rb and not adm & zia and not adm & dlp


SDK_MODELS = [
    (f"{ZIA}/configAudit", "zia.models.system_audit", "ConfigAudit"),
    (f"{ZIA}/passwordExpiry/settings", "zia.models.admin_roles", "PasswordExpiry"),
    (f"{ZIA}/remoteAssistance", "zia.models.remoteassistance", "RemoteAssistance"),
    (f"{ZIA}/alertSubscriptions", "zia.models.alert_subscriptions", "AlertSubscriptions"),
    (f"{ZIA}/nssServers", "zia.models.nss_servers", "Nssservers"),
]


@pytest.mark.parametrize("path,module,cls", SDK_MODELS, ids=[m[2] for m in SDK_MODELS])
def test_the_sample_governance_answers_use_the_sdk_models_field_names(path, module, cls):
    """ASVS V5.1.3 · CWE-1287 · SSDF PW.4.1: every field of the sample's governance answers is one zscaler-sdk-python 1.11.3's model reads."""
    import sdk_wire_fake as wf
    model = getattr(importlib.import_module(f"zscaler.{module}"), cls)
    body = sample_tenant.responses()[path]
    rows = body if isinstance(body, list) else [body]

    assert rows and sorted({f for row in rows for f in wf.unknown_fields(row, model)}) == []


def test_every_governance_check_is_assessed_on_the_sample_tenant():
    """ASVS V1.14.1 · CWE-1287: on the sample (offline, no network) every new check answers from data, none says "could not be read", and the sample shows both a pass and a finding."""
    st = ot.sample_store(reset=True)
    cl = ot.OfflineRawClient(st, ot.creds_for(st))

    res = {cid: fn(cl) for cid, fn in list(GOV.items()) + [("RBAC.13", RBAC13), ("RBAC.14", RBAC14)]}

    assert all("could not be read" not in r.detail for r in res.values()), {k: r.detail for k, r in res.items()}
    assert res["GOV.2"].status == "REVIEW" and "backup GRE tunnel" in res["GOV.2"].detail
    assert res["GOV.7"].status == "REVIEW" and res["GOV.8"].status == "PASS" and res["RBAC.13"].status == "PASS"


# ── GOV.1-GOV.5: Zscaler's configuration audit ─────────────────────────

AUDIT = {"overallGrade": "A", "highAvailabilityGrade": "A", "greTunnelGrade": "A", "authFrequencyGrade": "B", "pacFileGrade": "A",
         "pacfileSizeGrade": "A", "office365Grade": "A", "ipVisibilityGrade": "A", "userPerformanceGrade": "A", "otherGrade": "A",
         "dataPresent": True, "reportTimestamp": 1792994400000}


def test_a_clean_configuration_audit_passes_and_a_poor_item_becomes_a_finding_with_zscalers_advice():
    """ASVS V1.14.1 · CWE-1287: Zscaler's own grades map into findings: all good is a pass, a poor PAC file grade is a review naming the recommended configuration."""
    good = FakeCl({"/zia/configAudit": AUDIT})
    bad = FakeCl({"/zia/configAudit": dict(AUDIT, overallGrade="C", pacfileSizeGrade="D",
                                           pacFileSizeRecommendedConfiguration="Keep the PAC file under 256 KB.")})

    assert GOV["GOV.1"](good).status == "PASS" and GOV["GOV.4"](good).status == "PASS"
    r1, r4, r3 = GOV["GOV.1"](bad), GOV["GOV.4"](bad), GOV["GOV.3"](bad)
    assert r1.status == "REVIEW" and "PAC file size (grade D)" in r1.detail
    assert r4.status == "REVIEW" and "Keep the PAC file under 256 KB" in r4.detail and "2026-10-26" in r4.detail
    assert r3.status == "PASS"   # another item's grade does not leak into this one


@pytest.mark.parametrize("routes,codes,word", [
    ({"/zia/configAudit": dict(AUDIT, dataPresent=False)}, {}, "no configuration audit report"),
    ({}, {"/zia/configAudit": 404}, "could not be read"),
    ({"/zia/configAudit": {"overallGrade": "N/A", "dataPresent": True}}, {}, "no overall grade"),
])
def test_no_report_or_no_grade_is_informational_never_a_pass(routes, codes, word):
    """ASVS V1.14.1 · CWE-754: no report, an unreadable report or an ungraded one is INFO (outside the score), never a pass."""
    r = GOV["GOV.1"](FakeCl(routes, codes))

    assert r.status == "INFO" and word in r.detail


def test_a_refused_audit_read_is_not_permitted_not_judged():
    """ASVS V4.1.3 · CWE-285: the config audit answers 403 without the Reports scope; the check says "not permitted" and is outside the score."""
    r = GOV["GOV.1"](FakeCl({}, {"/zia/configAudit": 403}))

    assert r.status == "INFO" and permissions.classify({"status": r.status, "detail": r.detail}) == "not_permitted"


def test_the_audits_recommended_text_is_capped_and_made_inert():
    """ASVS V5.1.4 · CWE-117 · CWE-400 · CWE-451: tenant text in a finding loses control characters and bidi overrides and is capped, so a long or odd value cannot swamp, reorder or forge a line."""
    rec = "Fix\x1b[31m it\r\nFAKE LINE \u202egnirts " + "x" * 5000
    r = GOV["GOV.4"](FakeCl({"/zia/configAudit": dict(AUDIT, pacFileGrade="F", pacFileRecommendedConfiguration=rec)}))

    assert r.status == "REVIEW" and "\x1b" not in r.detail and "\n" not in r.detail and "\r" not in r.detail and "\u202e" not in r.detail
    assert "x" * 200 not in r.detail and len(r.detail) < 1200


@pytest.mark.parametrize("grade,verdict", [("A", "good"), ("B+", "good"), ("GOOD", "good"), (92, "good"), ("C", "bad"), ("F", "bad"),
                                           ("POOR", "bad"), (41, "bad"), (None, None), ("", None), ("N/A", None), (True, None), ("MAYBE", None)])
def test_the_grade_scale_is_read_conservatively(grade, verdict):
    """ASVS V5.1.3 · CWE-20: letters, words and 0-100 scores map to good or poor; anything else is "not graded", never a pass."""
    assert fc._grade(grade) == verdict


# ── GOV.6: alert subscriptions ─────────────────────────────────────────

def _sub(email, **sev):
    base = {"pt0Severities": [], "secureSeverities": [], "manageSeverities": [], "complySeverities": [], "systemSeverities": []}
    return dict(base, id=1, email=email, deleted=False, **sev)


ALL_SEV = {k: ["CRITICAL"] for k in ("pt0Severities", "secureSeverities", "manageSeverities", "complySeverities", "systemSeverities")}


def test_alert_recipients_are_counted_never_listed():
    """ASVS V8.3.4 · CWE-359 · CWE-200: the finding says how many recipients alerts reach and never shows an address."""
    subs = [_sub("ana.private@cust.example", **ALL_SEV), _sub("soc-team@cust.example", **ALL_SEV)]
    r = GOV["GOV.6"](FakeCl({"/zia/alertSubscriptions": subs}))

    assert r.status == "PASS" and "2 recipient(s)" in r.detail and "@" not in r.detail and "ana.private" not in r.detail


@pytest.mark.parametrize("subs,word", [
    ([], "No alert subscription"),
    ([dict(_sub("a@x.example", **ALL_SEV), deleted=True)], "No alert subscription"),
    ([_sub("a@x.example", secureSeverities=["CRITICAL"]), _sub("b@x.example", systemSeverities=["MAJOR"])], "Patient 0, Manage, Comply"),
    ([_sub("a@x.example", **ALL_SEV)], "one address"),
])
def test_missing_alert_classes_or_a_single_recipient_need_review(subs, word):
    """ASVS V7.1.3 · CWE-778: no live subscription, an uncovered alert class or a single recipient is a review; deleted subscriptions do not count."""
    r = GOV["GOV.6"](FakeCl({"/zia/alertSubscriptions": subs}))

    assert r.status == "REVIEW" and word in r.detail and "@" not in r.detail


# ── GOV.7-GOV.8: NSS servers, collectors, feeds and the licence ────────

def test_an_unhealthy_or_disabled_nss_vm_is_a_finding_and_healthy_ones_pass():
    """ASVS V7.1.3 · CWE-778: an NSS VM that is disabled or unhealthy stops its feeds; the check says how many, beside the healthy ones."""
    ok = [{"id": 1, "name": "a", "status": "ENABLED", "state": "HEALTHY"}, {"id": 2, "name": "b", "status": "ENABLED", "state": "HEALTHY"}]
    bad = ok + [{"id": 3, "name": "c", "status": "DISABLED_BY_SERVICE_PROVIDER", "state": "HEALTHY"}]

    assert GOV["GOV.7"](FakeCl({"/zia/nssServers": ok})).status == "PASS"
    r = GOV["GOV.7"](FakeCl({"/zia/nssServers": bad}))
    assert r.status == "REVIEW" and "1 of 3" in r.detail


@pytest.mark.parametrize("subs,status,word", [
    (UNLICENSED, "INFO", "not licensed"),
    (LICENSED, "INFO", "No NSS server"),
    (None, "INFO", "No NSS server"),   # the subscriptions could not be read: not marked N/A on a guess
])
def test_no_nss_vm_is_na_only_when_the_subscriptions_say_nss_is_not_owned(subs, status, word):
    """ASVS V1.14.1 · CWE-754: with no NSS VM the check is N/A (not licensed) only when the subscriptions were read and hold no NSS SKU."""
    routes = {"/zia/nssServers": []}
    if subs is not None:
        routes["/zia/subscriptions"] = subs
    r = GOV["GOV.7"](FakeCl(routes))

    assert r.status == status and word in r.detail
    if word == "not licensed":
        assert posture_plus._why_of(r.detail) == "not_licensed"


@pytest.mark.parametrize("routes,status,word", [
    ({"/zia/nssFeeds": [{"id": 1, "feedStatus": "ENABLED", "nssLogType": "WEBLOG"}], "/zia/nssServers": [], "/zia/nssCollectors": []}, "PASS", "1 enabled Cloud NSS feed"),
    ({"/zia/nssFeeds": [], "/zia/nssServers": [], "/zia/nssCollectors": [{"id": 9, "name": "c", "status": "ENABLED"}]}, "PASS", "1 NSS collector"),
    ({"/zia/nssFeeds": [{"id": 1, "feedStatus": "DISABLED"}], "/zia/nssServers": [], "/zia/nssCollectors": [], "/zia/subscriptions": LICENSED}, "REVIEW", "No log stream"),
    ({"/zia/nssFeeds": [], "/zia/nssServers": [], "/zia/nssCollectors": [], "/zia/subscriptions": UNLICENSED}, "INFO", "not licensed"),
    ({"/zia/nssFeeds": [{"id": 1, "feedStatus": "ENABLED"}], "/zia/nssServers": [{"id": 2, "status": "ENABLED", "state": "UNHEALTHY"}],
      "/zia/nssCollectors": []}, "REVIEW", "is down"),
])
def test_log_streaming_needs_a_live_feed_server_or_collector(routes, status, word):
    """ASVS V7.1.3 · CWE-778: logs must leave ZIA through a Cloud NSS feed, a healthy NSS VM or a collector; nothing is a finding, nothing owned is N/A."""
    r = GOV["GOV.8"](FakeCl(routes))

    assert r.status == status and word in r.detail


def test_subscriptions_nobody_understands_are_no_evidence_of_a_missing_licence():
    """ASVS V5.1.3 · CWE-20: a subscriptions answer with no SKU the parser accepts (or an error) leaves the licence unknown, so nothing is marked N/A."""
    assert fc._subscriptions(FakeCl({"/zia/subscriptions": [{"id": "x" * 200}, "junk", 5]})) is None
    assert fc._subscriptions(FakeCl({"/zia/subscriptions": {"error": "boom"}})) is None
    assert fc._subscriptions(FakeCl({}, {"/zia/subscriptions": 403})) is None
    assert fc._subscriptions(FakeCl({"/zia/subscriptions": LICENSED})) == {"ZIA_TENANT", "Z_CLOUD_NSS_WEB"}


# ── RBAC.13: admin password expiry ─────────────────────────────────────

@pytest.mark.parametrize("body,status,word", [
    ({"passwordExpirationEnabled": True, "passwordExpiryDays": 90}, "PASS", "after 90 days"),
    ({"passwordExpirationEnabled": True, "passwordExpiryDays": "60"}, "PASS", "after 60 days"),
    ({"passwordExpirationEnabled": False, "passwordExpiryDays": 90}, "REVIEW", "is off"),
    ({"passwordExpirationEnabled": True, "passwordExpiryDays": 365}, "REVIEW", "365 days"),
    ({"passwordExpirationEnabled": "(not set)", "passwordExpiryDays": "(set)"}, "INFO", "not reported"),
    ({}, "INFO", "not reported"),
])
def test_admin_password_expiry(body, status, word):
    """ASVS V2.1.10 · CWE-262: admin passwords that never expire (or only after a year) need review; a masked or missing value is no evidence."""
    r = RBAC13(FakeCl({"/zia/passwordExpiry/settings": body}))

    assert r.status == status and word in r.detail


def test_a_snapshot_keeps_the_password_expiry_switch_and_nothing_secret():
    """ASVS V8.3.4 · CWE-312 · CWE-1287: the snapshot scrubber keeps passwordExpirationEnabled and passwordExpiryDays as true/false and a number (no secret), so RBAC.13 judges a snapshot as it judges the tenant; text under those names and real password fields stay masked."""
    out = ot.scrub({"passwordExpirationEnabled": False, "passwordExpiryDays": 30, "password": "hunter2"})
    text = ot.scrub({"passwordExpirationEnabled": "hunter2", "passwordExpiryDays": "hunter2"})

    assert out == {"passwordExpirationEnabled": False, "passwordExpiryDays": 30, "password": "(set)"}
    assert "hunter2" not in json.dumps(text)
    assert RBAC13(FakeCl({"/zia/passwordExpiry/settings": out})).status == "REVIEW"


def test_the_governance_reads_survive_a_snapshot_round_trip():
    """ASVS V1.14.1 · CWE-1287 · CWE-312: a snapshot of the sample (ZIA platform and RBAC ticked) answers every new read offline, and the checks give the same results as on the live store."""
    st = ot.sample_store(reset=True)
    live = ot.OfflineRawClient(st, ot.creds_for(st))
    cap = ot.capture(live, ["zia_extras", "rbac"], {}, lambda _m: None)
    doc = ot.build_snapshot(cap["responses"], {"tenant_label": "Sample", "scopes": ["zia_extras", "rbac"]})
    snap = ot.open_document(json.dumps(doc).encode())
    off = ot.OfflineRawClient(snap, ot.creds_for(snap))

    fns = list(GOV.values()) + [RBAC13, RBAC14]
    assert [fn(off).status for fn in fns] == [fn(live).status for fn in fns]
    assert "secops@" not in json.dumps([fn(off).detail for fn in fns])


# ── RBAC.14: Zscaler Support remote assistance ─────────────────────────

@pytest.fixture
def clock(monkeypatch):
    monkeypatch.setattr(rbac, "_now", lambda: NOW)


@pytest.mark.parametrize("body,status,word", [
    ({"viewOnlyUntil": 0, "fullAccessUntil": 0}, "PASS", "No remote assistance"),
    ({"fullAccessUntil": int(NOW + 3 * 86400) * 1000, "usernameObfuscated": False}, "REVIEW", "not obfuscated"),
    ({"fullAccessUntil": int(NOW + 86400), "usernameObfuscated": True}, "REVIEW", "full (change) access"),
    ({"fullAccessUntil": int(NOW - 86400), "viewOnlyUntil": int(NOW - 86400)}, "PASS", "No remote assistance"),
    ({"viewOnlyUntil": int(NOW + 90 * 86400), "usernameObfuscated": True}, "REVIEW", "more than 30 days"),
    ({"viewOnlyUntil": int(NOW + 2 * 86400), "usernameObfuscated": True}, "PASS", "view-only access until"),
    ({"fullAccessUntil": 10 ** 30, "viewOnlyUntil": "soon"}, "PASS", "No remote assistance"),   # nonsense times are ignored
])
def test_remote_assistance_open_too_long_or_with_change_access_needs_review(clock, body, status, word):
    """ASVS V4.1.3 · CWE-284 · CWE-359: Zscaler Support full access, or view-only access open for more than 30 days, is a review; seconds and milliseconds both read; absurd values are ignored."""
    r = RBAC14(FakeCl({"/zia/remoteAssistance": body}))

    assert r.status == status and word in r.detail


# ── Plain language, compliance, licences ───────────────────────────────

def test_governance_findings_read_in_plain_language_and_map_to_frameworks():
    """ASVS V1.14.1 · CWE-1059: each new check has a plain title, a business outcome of its own area and framework mappings."""
    row = {"id": "GOV.6", "section": "ZIA — Governance", "label": "Alert subscriptions reach a team", "status": "REVIEW",
           "detail": "1 alert subscription(s) to 1 recipient(s): every alert goes to one address. Best Practice: send alerts to a team mailbox."}
    plain = plain_english.explain(row)

    assert "SIEM" in plain["outcome"] and plain["do"]
    assert compliance_mapping.get_compliance_for_check("GOV.6") and compliance_mapping.get_compliance_for_check("RBAC.14")
    labels = [l for i, _s, l, _f in fc.PLATFORM_REG + rbac.RBAC_REG if i.startswith("GOV.") or i in ("RBAC.13", "RBAC.14")]
    assert len(labels) == 10 and all(len(l) <= 70 and l[0].isupper() for l in labels)


def test_the_new_reads_name_the_permission_to_ask_for():
    """ASVS V4.1.3 · CWE-285: a refused governance read names the role permission the admin must grant (Required API access)."""
    for ep in ("/zia/configAudit", "/zia/alertSubscriptions", "/zia/remoteAssistance", "/zia/passwordExpiry/settings", "/zia/nssCollectors",
               "/zia/subscriptions"):
        p = permissions.permission_for_endpoint(ep)
        assert p["product"] == "ZIA" and not p["permission"].startswith("read access to"), ep
