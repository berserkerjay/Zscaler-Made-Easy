"""Tenant health, readiness tenant checks, API call diagnostics and ZDX
probes fitted to the tier (wave 7, feat/health-diag).

* tenant_health: ZIA pending activation, the SSL inspection rule order,
  certificate expiry thresholds (boundary days, missing dates, units),
  App Connector groups with no connector; the readiness checks; the
  assessment checks HLT.1 to HLT.4; the /api/tenant-health routes and the
  Scope rule.
* api_calls: the bounded ring buffer, the path template (ids masked), the
  retry fold, the job tag, and that no secret, token or tenant value ever
  reaches a row, the list or an export (the secret canaries of
  tests/test_secret_canaries.py, over the real SDK and the echoing transport).
* ops_zdx: a payload oracle per tier and what is verified against the
  installed SDK (1.11.3).

Fakes only: no tenant, no network, an injected clock."""
from __future__ import annotations

import csv
import io
import json
import threading
import types
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

import api_calls
import dlp_api_server as srv
import readiness
import tenant_health as th
from test_readiness import CREDS, Fake as ReadinessFake, Resp, ApiError, _no_canary
from test_secret_canaries import token_echo  # noqa: F401 — the fixture: the real clients over the echoing transport

NOW = 1_800_000_000.0          # injected clock (2027-01-15)
DAY = 86400


# ── Fakes ─────────────────────────────────────────────────────────────

def _answer(calls: List[str], name: str, body: Any, deny: bool = False):
    def call(*a, **k):
        calls.append(name)
        if deny:
            return None, Resp(None, 403), ApiError(403)
        return None, Resp(body), None
    return call


class Client(ReadinessFake):
    """The readiness fake plus what tenant health reads: ZIA activation,
    SSL rules and intermediate certificates; ZPA certificates, client
    settings, connector groups, connectors and service edges."""

    def __init__(self, *, status: Any = "ACTIVE", ssl: Any = None, zia_certs: Any = None, enroll: Any = None, web: Any = None,
                 client_settings: Any = None, groups: Any = None, connectors: Any = None, edges: Any = None, deny_health: tuple = (), **kw):
        super().__init__(**kw)
        c, ns = self.calls, types.SimpleNamespace
        self.zia.activate = ns(status=_answer(c, "zia.status", {"status": status} if status is not None else {}, "zia.status" in deny_health))
        self.zia.ssl_inspection_rules = ns(list_rules=_answer(c, "zia.ssl", ssl if ssl is not None else GOOD_SSL, "zia.ssl" in deny_health))
        self.zia.intermediate_certificates = ns(list_ca_certificates=_answer(c, "zia.certs", zia_certs or [], "zia.certs" in deny_health))
        self.zpa.enrollment_certificates = ns(list_enrolment=_answer(c, "zpa.enroll", enroll or [], "zpa.enroll" in deny_health))
        self.zpa.certificates = ns(list_certificates=_answer(c, "zpa.web", web or [], "zpa.web" in deny_health))
        self.zpa.client_settings = ns(get_client_settings=_answer(c, "zpa.client", client_settings or {}, "zpa.client" in deny_health))
        self.zpa.app_connector_groups = ns(list_connector_groups=_answer(c, "zpa.groups", groups or [], "zpa.groups" in deny_health))
        self.zpa.app_connectors = ns(list_connectors=_answer(c, "zpa.connectors", connectors or [], "zpa.connectors" in deny_health))
        self.zpa.service_edges = ns(list_service_edges=_answer(c, "zpa.edges", edges or [], "zpa.edges" in deny_health))


def rule(order, name, action, **kw):
    return dict({"id": 700 + order, "order": order, "name": name, "state": "ENABLED", "action": {"type": action}}, **kw)


REC = rule(1, "Zscaler Recommended Exemptions", "DO_NOT_DECRYPT", predefined=True, urlCategories=["FINANCE"])
DEFAULT_DNI = rule(99, "Default SSL Inspection Rule", "DO_NOT_DECRYPT", defaultRule=True)
GOOD_SSL = [REC, rule(2, "Do not decrypt webmail", "DO_NOT_DECRYPT", urlCategories=["WEB_MAIL"]),
            rule(3, "Inspect everything else", "DECRYPT"), DEFAULT_DNI]


# ── ZIA activation ────────────────────────────────────────────────────

@pytest.mark.parametrize("raw,state", [("ACTIVE", "active"), ("PENDING", "pending"), ("pending", "pending"), ("INPROGRESS", "in_progress"),
                                       ("IN_PROGRESS", "in_progress"), ("", "unknown"), (None, "unknown"), ("<b>DONE</b>", "unknown")])
def test_activation_status_words_are_read_and_anything_else_is_unknown(raw, state):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: ZIA's activation status maps to active, pending, in_progress or unknown; markup never passes through."""
    a = th.activation({"status": raw})
    assert a["state"] == state
    assert a["status"] is None or a["status"].replace("_", "").isalpha()


def test_readiness_says_changes_wait_for_activation_with_the_steps_to_fix_it():
    """ASVS V1.14.1 · CWE-1188 · WSTG-CONF-05: PENDING is a readiness check needing attention, with plain steps and the warning that a deploy activates other people's changes too."""
    out = readiness.run(Client(status="PENDING"), ["dlp"], now=NOW, label="acme")
    chk = {c["key"]: c for c in out["checks"]}
    a = chk["zia_activation"]
    assert a["status"] == "attention" and a["severity"] == "warning"
    assert "not activated" in a["why"] and "someone else's too" in a["why"]
    assert any("Activate" in s for s in a["steps"]) and len(a["steps"]) >= 3
    assert out["attention_count"] >= 1 and "ZIA changes waiting for activation: needs attention" in out["summary"]
    html = readiness.html_section([out])
    assert "Tenant checks" in html and "ZIA changes waiting for activation" in html and "Needs attention" in html


def test_readiness_activation_is_ok_when_active_and_unknown_when_refused():
    """ASVS V4.1.3 · CWE-755 · WSTG-ERRH-01: ACTIVE is ok; a refused read is 'unknown', never a crash, and its error text is not kept."""
    ok = {c["key"]: c for c in readiness.run(Client(status="ACTIVE"), ["dlp"], now=NOW)["checks"]}
    assert ok["zia_activation"]["status"] == "ok" and ok["zia_activation"]["steps"] == []
    denied = readiness.run(Client(deny_health=("zia.status",)), ["dlp"], now=NOW)
    d = {c["key"]: c for c in denied["checks"]}["zia_activation"]
    assert d["status"] == "unknown" and "HTTP 403" in d["why"]
    assert _no_canary(json.dumps(denied)) == []


def test_readiness_reads_activation_and_ssl_rules_only_for_what_is_in_scope():
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: activation is read for any ZIA scope; the SSL rules only when DLP or ZIA platform is ticked; nothing ZIA without a ZIA scope."""
    c = Client()
    readiness.run(c, ["genai"], now=NOW)
    assert "zia.status" in c.calls and "zia.ssl" not in c.calls
    c = Client()
    readiness.run(c, ["zia_extras"], now=NOW)
    assert "zia.status" in c.calls and "zia.ssl" in c.calls
    c = Client()
    readiness.run(c, ["zcc"], now=NOW)
    assert not [x for x in c.calls if x.startswith("zia.")]


def test_the_assessment_check_flags_pending_activation():
    """ASVS V1.14.1 · CWE-1188: HLT.1 warns on PENDING, passes on ACTIVE and never judges an unread status."""
    import zscaler_full_checks as full
    from dlp_assessment_full_auto import R
    from test_c6_checks import FakeClient
    assert full.hlt_1(FakeClient({"/zia/status": ({"status": "PENDING"}, 200)})).status == R.WARN
    assert full.hlt_1(FakeClient({"/zia/status": ({"status": "ACTIVE"}, 200)})).status == R.PASS
    assert full.hlt_1(FakeClient({"/zia/status": ({}, 500)})).status == R.INFO


# ── SSL inspection rule order ─────────────────────────────────────────

def test_a_good_order_has_no_problem():
    """ASVS V1.14.1 · CWE-696: exemptions, then a catch-all Inspect rule above the Default rule, is ok."""
    assert th.ssl_order(GOOD_SSL) == {"state": "ok", "severity": "ok", "problems": [], "checked": 4}


def test_a_broad_do_not_inspect_rule_above_inspect_rules_is_critical_with_steps():
    """ASVS V1.14.1 · CWE-696 · WSTG-CONF-05: a custom Do Not Inspect rule with no criteria above Inspect rules shadows them all; the fix names the rules."""
    rules = [REC, rule(2, "Bypass all", "DO_NOT_DECRYPT"), rule(3, "Inspect finance", "DECRYPT", urlCategories=["FINANCE"]),
             rule(4, "Inspect everything else", "DECRYPT"), DEFAULT_DNI]
    out = th.ssl_order(rules)
    p = next(x for x in out["problems"] if x["kind"] == "dni_above_inspect")
    assert out["state"] == "attention" and out["severity"] == "critical" and p["rule"] == "Bypass all" and p["affected_count"] == 2
    assert "never decrypt" in p["why"] and any("Bypass all" in s for s in p["steps"]) and any("activate" in s.lower() for s in p["steps"])


def test_an_inspect_all_rule_above_the_recommended_exemptions_is_critical():
    """ASVS V1.14.1 · CWE-696: an Inspect rule with no criteria above Zscaler Recommended Exemptions makes the exemptions dead (pinned apps break)."""
    rules = [rule(1, "Inspect everything", "DECRYPT"), dict(REC, order=2), DEFAULT_DNI]
    p = th.ssl_order(rules)["problems"][0]
    assert p["kind"] == "inspect_above_exemptions" and p["severity"] == "critical" and "Zscaler Recommended Exemptions" in p["affected"]
    assert "pin" in p["why"] and any("just above the Default rule" in s for s in p["steps"])


def test_nothing_inspecting_what_reaches_the_default_rule_is_a_warning():
    """ASVS V1.14.1 · CWE-1188: no catch-all Inspect rule and a Default rule that does not inspect leaves new traffic uninspected."""
    rules = [REC, rule(2, "Inspect finance", "DECRYPT", urlCategories=["FINANCE"]), DEFAULT_DNI]
    out = th.ssl_order(rules)
    assert [p["kind"] for p in out["problems"]] == ["default_decides"] and out["severity"] == "warning"
    assert th.ssl_order([REC, rule(2, "Inspect finance", "DECRYPT", urlCategories=["X"]), dict(DEFAULT_DNI, action={"type": "DECRYPT"})])["state"] == "ok"


def test_disabled_and_scoped_rules_do_not_shadow_and_odd_input_never_raises():
    """ASVS V5.1.3 · CWE-20: a disabled broad rule or a scoped exemption shadows nothing; a non-list answer is 'unknown'."""
    rules = [rule(1, "Off", "DO_NOT_DECRYPT", state="DISABLED"), rule(2, "Scoped", "DO_NOT_DECRYPT", locations=[{"id": 5}]),
             rule(3, "Inspect everything else", "DECRYPT"), DEFAULT_DNI]
    assert th.ssl_order(rules)["state"] == "ok"
    assert th.ssl_order("nope")["state"] == "unknown"
    assert th.ssl_order({"list": [None, 3, "x", rule(1, "Inspect all", "DECRYPT")]})["state"] == "ok"


# ── Certificate expiry ────────────────────────────────────────────────

@pytest.mark.parametrize("left,state,days", [
    (0, "expired", 0), (-1, "expired", -1), (-DAY, "expired", -1), (-DAY - 1, "expired", -2),
    (1, "critical", 0), (7 * DAY, "critical", 7), (7 * DAY + 1, "warning", 7),
    (30 * DAY, "warning", 30), (30 * DAY + 1, "ok", 30), (365 * DAY, "ok", 365),
])
def test_expiry_thresholds_at_the_boundary_days(left, state, days):
    """ASVS V9.1.2 · CWE-298 · CWE-324: expired at or before now, critical within 7 days (inclusive), warning within 30 (inclusive), ok after."""
    e = th.expiry(NOW + left, NOW, 30, 7)
    assert (e["state"], e["days_left"]) == (state, days)


def test_custom_thresholds_move_the_boundaries():
    """ASVS V9.1.2 · CWE-298: thresholds of 60 and 14 days flag a certificate 45 days out as a warning and 10 days out as critical."""
    assert th.expiry(NOW + 45 * DAY, NOW, 60, 14)["state"] == "warning"
    assert th.expiry(NOW + 10 * DAY, NOW, 60, 14)["state"] == "critical"
    assert th.expiry(NOW + 45 * DAY, NOW, 30, 7)["state"] == "ok"


@pytest.mark.parametrize("raw,expect", [
    (None, None), ("", None), (True, None), (0, None), (-5, None), ("soon", None), (float("nan"), None), (float("inf"), None),
    (NOW, NOW), (int(NOW), NOW), (str(int(NOW)), NOW), (NOW * 1000, NOW), (f"{int(NOW * 1000)}", NOW),
    ("2027-01-15T08:00:00Z", 1800000000.0), ("2027-01-15T08:00:00", 1800000000.0), ("9" * 40, None),
])
def test_dates_in_seconds_milliseconds_or_iso_and_missing_dates(raw, expect):
    """ASVS V5.1.3 · CWE-20 · CWE-1287: an expiry in seconds, milliseconds or ISO 8601 is read; a missing, boolean or unreadable one is no date."""
    got = th.parse_time(raw)
    assert (got is None) if expect is None else abs(got - expect) < 1


def test_a_certificate_without_a_date_is_unknown_and_never_judged_healthy():
    """ASVS V9.1.2 · CWE-754: a ZPA certificate with no validToInEpochSec is 'unknown' and the item says it could not be judged."""
    certs = th.zpa_certificates([{"id": "1", "name": "Connector"}, {"id": "2", "name": "Root", "validToInEpochSec": str(int(NOW + 400 * DAY))}], NOW)
    assert [c["state"] for c in certs] == ["unknown", "ok"]
    item = th._cert_item("k", "ZPA", "x", certs, 30, 7, ["step"])
    assert item["status"] == "ok" and "could not be judged" in item["summary"]


@pytest.mark.parametrize("warn,crit,err", [(None, None, None), (60, 14, None), (7, 7, "fewer days"), (5, 10, "fewer days"), (0, None, "between 1"),
                                           (366, None, "between 1"), ("x", None, "whole number"), (None, 400, "between 1")])
def test_threshold_requests_are_validated(warn, crit, err, monkeypatch):
    """ASVS V5.1.4 · CWE-20 · WSTG-INPV-01: thresholds are whole days from 1 to 365 and the critical one is below the warning one."""
    monkeypatch.delenv("DLP_CHECK_CERT_WARN_DAYS", raising=False)
    monkeypatch.delenv("DLP_CHECK_CERT_CRIT_DAYS", raising=False)
    if err:
        with pytest.raises(ValueError, match=err):
            th.thresholds(warn, crit)
    else:
        assert th.thresholds(warn, crit) == ((warn, crit) if warn else (30, 7))


def test_threshold_settings_are_read_and_a_bad_setting_falls_back(monkeypatch):
    """ASVS V14.1.1 · CWE-1188: DLP_CHECK_CERT_WARN_DAYS / _CRIT_DAYS set the defaults; a bad or contradictory setting falls back to 30 and 7."""
    monkeypatch.setenv("DLP_CHECK_CERT_WARN_DAYS", "45")
    monkeypatch.setenv("DLP_CHECK_CERT_CRIT_DAYS", "10")
    assert th.thresholds() == (45, 10)
    monkeypatch.setenv("DLP_CHECK_CERT_WARN_DAYS", "junk")
    assert th.thresholds() == (30, 10)
    monkeypatch.setenv("DLP_CHECK_CERT_WARN_DAYS", "5")
    assert th.thresholds() == (30, 7)


def _zpa_client(**kw):
    soon, gone, far = str(int(NOW + 5 * DAY)), str(int(NOW - DAY)), str(int(NOW + 400 * DAY))
    base = dict(enroll=[{"id": "11", "name": "Connector", "validToInEpochSec": soon, "certificate": "-----BEGIN CERTIFICATE-----CANARYpem",
                         "zrsaencryptedprivatekey": "CANARYkey"},
                        {"id": "12", "name": "Service Edge", "validToInEpochSec": far}, {"id": "13", "name": "Root", "validToInEpochSec": far}],
                web=[{"id": "21", "name": "portal.acme.example", "validToInEpochSec": gone}],
                client_settings={"singningCertExpiryInEpochSec": str(int(NOW + 20 * DAY))},
                groups=[{"id": "31", "name": "PDX", "enrollmentCertId": "11", "connectors": [{"id": "41"}, {"id": "42"}]},
                        {"id": "32", "name": "Empty group", "connectors": []}],
                connectors=[{"id": "41", "name": "c1"}, {"id": "42", "name": "c2", "enrollmentCert": {"name": "Connector"}}],
                edges=[{"id": "51", "name": "e1", "enrollmentCert": {"name": "Service Edge"}}],
                zia_certs=[{"id": 1, "name": "Zscaler Intermediate", "type": "ZSCALER", "certExpDate": int(NOW + 400 * DAY)},
                           {"id": 2, "name": "Acme CA", "type": "CUSTOM_SW", "defaultCertificate": True, "certExpDate": int(NOW + 25 * DAY) * 1000}])
    base.update(kw)
    return Client(**base)


def test_tenant_health_flags_each_certificate_by_threshold_and_counts_what_is_enrolled():
    """ASVS V9.1.2 · CWE-298 · CWE-324: expired web certs and a connector enrollment cert within 7 days are critical, the signing and custom ZIA certs warnings; the connectors and edges enrolled with each are counted."""
    out = th.run(_zpa_client(), ["dlp", "zpa"], customer_id="7210000000000", now=NOW, label="acme")
    by = {i["key"]: i for i in out["items"]}
    assert by["zpa_web_certificates"]["status"] == "critical" and "expired" in by["zpa_web_certificates"]["summary"]
    enr = by["zpa_enrollment_certificates"]
    assert enr["status"] == "critical" and enr["rows"][0]["name"] == "Connector" and enr["rows"][0]["connectors"] == 2
    assert next(r for r in enr["rows"] if r["name"] == "Service Edge")["service_edges"] == 1
    assert by["zpa_client_certificate"]["status"] == "warning"
    zc = by["zia_certificates"]
    assert zc["status"] == "warning" and zc["rows"][0]["name"] == "Acme CA" and zc["rows"][0]["default"] is True and zc["rows"][0]["days_left"] == 25
    assert by["zpa_empty_groups"]["status"] == "warning" and "Empty group" in by["zpa_empty_groups"]["summary"]
    assert out["worst"] == "critical" and out["counts"]["critical"] == 2
    text = json.dumps(out)
    assert "CANARY" not in text and "BEGIN CERTIFICATE" not in text, "only names, dates and states are kept"


def test_tenant_health_reads_only_what_is_in_scope():
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: ZPA is not read without ZPA ticked or without a customer ID; SSL and the ZIA certificates only with DLP or ZIA platform."""
    c = _zpa_client()
    out = th.run(c, ["genai"], customer_id="7210000000000", now=NOW)
    assert c.calls == ["zia.status"]
    assert {i["key"]: i["status"] for i in out["items"]}["zpa_empty_groups"] == "not_in_scope"
    c = _zpa_client()
    out = th.run(c, ["zpa"], customer_id="", now=NOW)
    assert c.calls == [] and all(i["status"] in ("not_in_scope", "unknown") for i in out["items"])
    c = _zpa_client()
    th.run(c, ["zpa"], customer_id="7210000000000", auth_method="legacy", now=NOW)
    assert c.calls == []


def test_a_refused_read_is_unknown_and_the_stop_keeps_nothing():
    """ASVS V7.4.1 · CWE-755: a refused list is 'could not be read' (never healthy); Stop ends with no partial result."""
    out = th.run(_zpa_client(deny_health=("zpa.enroll",)), ["zpa"], customer_id="7210000000000", now=NOW)
    assert {i["key"]: i["status"] for i in out["items"]}["zpa_enrollment_certificates"] == "unknown"
    stop = threading.Event()
    stop.set()
    assert th.run(_zpa_client(), ["zpa", "dlp"], customer_id="7210000000000", cancel=stop, now=NOW)["status"] == "stopped"


def test_the_sample_tenant_is_healthy_through_the_real_sdk_services():
    """SSDF PW.4.1 · CWE-1357: the SDK service names tenant_health calls exist in the installed SDK (the offline client runs them) and the made-up sample is healthy."""
    import offline_tenant as ot
    c = ot.OfflineSdkClient(ot.sample_store(), {"customer_id": ot.CUSTOMER_ID})
    out = th.run(c, ["dlp", "zia_extras", "zpa"], customer_id=ot.CUSTOMER_ID)
    assert {i["status"] for i in out["items"]} == {"ok"} and len(out["items"]) == 7


@pytest.mark.parametrize("fn,table,status", [
    ("hlt_2", {"/zia/intermediateCaCertificate": ([{"name": "CA", "certExpDate": 1}], 200)}, "FAIL"),
    ("hlt_2", {"/zia/intermediateCaCertificate": ([{"name": "CA", "certExpDate": 4102444800}], 200)}, "PASS"),
    ("hlt_3", {"/zpa/enrollmentCert": ([{"name": "Connector", "validToInEpochSec": "1"}], 200)}, "FAIL"),
    ("hlt_3", {"/zpa/enrollmentCert": ({}, 500)}, "INFO"),
    ("hlt_4", {"/zpa/appConnectorGroup": ([{"name": "G", "connectors": []}], 200)}, "WARN"),
    ("hlt_4", {"/zpa/appConnectorGroup": ([{"name": "G", "connectors": [{"id": 1}]}], 200)}, "PASS"),
])
def test_the_assessment_checks_carry_the_health_signals(fn, table, status):
    """ASVS V1.14.1 · CWE-298 · CWE-1188: HLT.2 to HLT.4 fail an expired certificate, warn on an empty connector group and never judge an unread list."""
    import zscaler_full_checks as full
    from dlp_assessment_full_auto import R
    from test_c6_checks import FakeClient
    assert getattr(full, fn)(FakeClient(table)).status == getattr(R, status)
    ids = {c[0]: c[1] for c in full.PLATFORM_REG}
    assert ids["HLT.1"].startswith("ZIA") and ids["HLT.2"].startswith("ZIA") and ids["HLT.3"].startswith("ZPA") and ids["HLT.4"].startswith("ZPA")


# ── The routes ────────────────────────────────────────────────────────

@pytest.fixture
def app(tmp_path, monkeypatch):
    """An isolated app whose sign-in returns the fake client and whose jobs run in the request."""
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_PROFILES", str(tmp_path / "profiles.json"))
    monkeypatch.setattr(srv, "_TENANT_HEALTH", type(srv._TENANT_HEALTH)())
    state: Dict[str, Any] = {"client": _zpa_client(), "built": 0}

    def build(creds):
        state["built"] += 1
        return state["client"]
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    import pack_jobs

    class Job:
        def __init__(self, kind, result):
            self.id, self.kind, self.status, self.result = "thjob", kind, "done", result

    def start(kind, fn, **k):
        logs: List[str] = []
        state["result"] = fn(logs.append, threading.Event())
        state["logs"] = logs
        return Job(kind, state["result"])
    monkeypatch.setattr(pack_jobs, "start", start)
    state["http"] = TestClient(srv.app)
    return state


def test_the_tenant_health_route_reads_in_scope_and_keeps_the_latest(app):
    """ASVS V4.1.3 · CWE-200 · CWE-532: the job answers, closes the client, keeps the latest answer in memory and no secret is in it."""
    r = app["http"].post("/api/tenant-health/start", json=dict(CREDS, scopes=["dlp", "zpa"], from_page=True, warn_days=45, crit_days=10))
    assert r.status_code == 200 and r.json()["kind"] == "tenant_health" and app["client"].closed
    latest = app["http"].get("/api/tenant-health/latest")
    res = latest.json()["results"]
    assert len(res) == 1 and res[0]["thresholds"] == {"warning_days": 45, "critical_days": 10}
    assert latest.headers["cache-control"] == "no-store"
    assert CREDS["client_secret"] not in r.text + latest.text + "\n".join(app["logs"]) and _no_canary(latest.text) == []


@pytest.mark.parametrize("body,needle", [
    ({"scopes": [], "from_page": True}, "not in scope"), ({"scopes": ["zcc", "zdx"], "from_page": True}, "not in scope"),
    ({"scopes": ["dlp"], "from_page": True, "warn_days": 5, "crit_days": 9}, "fewer days"),
    ({"scopes": ["dlp"], "from_page": True, "warn_days": 400}, "between 1"),
])
def test_out_of_scope_or_bad_thresholds_are_refused_before_sign_in(app, body, needle):
    """ASVS V4.1.3 · ASVS V5.1.4 · CWE-272 · CWE-20 · WSTG-ATHZ-02: nothing in scope, or a threshold that is not 1 to 365 days with critical below warning, is a 400 and signs in to nothing."""
    r = app["http"].post("/api/tenant-health/start", json=dict(CREDS, **body))
    assert r.status_code == 400 and needle in r.json()["detail"] and app["built"] == 0


# ── API calls: the ring buffer and the template ───────────────────────

@pytest.fixture
def calls(monkeypatch):
    """An empty log of a known size."""
    api_calls.clear()
    old = api_calls._rows.maxlen
    api_calls.resize(50)
    yield api_calls
    api_calls.resize(old)
    api_calls.clear()


def test_the_ring_buffer_keeps_the_newest_rows_up_to_its_bound(calls):
    """ASVS V7.1.1 · CWE-770 · CWE-400: past the bound the oldest rows go first; the count of dropped rows is said."""
    for i in range(120):
        calls.record("GET", f"https://api.zsapi.net/zia/api/v1/webDlpRules/{i}", 200)
    rows = calls.rows()
    assert len(rows) == 50 and rows[0]["seq"] - rows[-1]["seq"] == 49
    s = calls.summary()
    assert s["rows"] == 50 and s["max"] == 50 and s["dropped"] == 70


@pytest.mark.parametrize("raw,n", [(None, 1000), ("", 1000), ("junk", 1000), ("0", 50), ("10", 50), ("5000", 5000), ("999999", 20000)])
def test_the_bound_setting_is_clamped(raw, n, monkeypatch):
    """ASVS V14.1.1 · CWE-770: DLP_CHECK_API_CALLS_MAX is held between 50 and 20000; anything else is the default 1000."""
    if raw is None:
        monkeypatch.delenv("DLP_CHECK_API_CALLS_MAX", raising=False)
    else:
        monkeypatch.setenv("DLP_CHECK_API_CALLS_MAX", raw)
    assert api_calls.max_rows() == n


@pytest.mark.parametrize("url,product,path", [
    ("https://api.zsapi.net/zia/api/v1/webDlpRules/123456?search=CANARYq", "ZIA", "/zia/api/v1/webDlpRules/{id}"),
    ("https://api.zsapi.net/zpa/mgmtconfig/v1/admin/customers/216196257331281920/application/72058",
     "ZPA", "/zpa/mgmtconfig/v1/admin/customers/{id}/application/{id}"),
    ("https://zsapi.zscalerten.net/api/v1/urlCategories/CUSTOM_01", "ZIA", "/api/v1/urlCategories/{id}"),
    ("https://api.zsapi.net/zdx/v1/config/applications/MICROSOFT_LOGIN/monitors/9", "ZDX", "/zdx/v1/config/applications/MICROSOFT_LOGIN/monitors/{id}"),
    ("https://api.zsapi.net/zia/api/v1/users/jane.doe@acme.example", "ZIA", "/zia/api/v1/users/{id}"),
    ("https://user:CANARYpw@acme.zslogin.net/zcc/papi/public/v1/getDevices#frag", "ZCC", "/zcc/papi/public/v1/getDevices"),
    ("https://api.zsapi.net/ziam/admin/api/v1/users/abc-123-def", "ZIdentity", "/ziam/admin/api/v1/users/{id}"),
    ("not a url", "other", "/{id}"), ("", "other", "/"),
])
def test_the_path_is_a_template_with_every_id_masked_and_no_host_or_query(url, product, path):
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-532 · CWE-359: a row keeps the product and the path with ids, emails and other values as {id}; the host, user info, query and fragment are dropped."""
    assert api_calls.template(url) == (product, path)


@pytest.mark.parametrize("status,exc,word", [
    (200, None, ""), (204, None, ""), (429, None, "rate_limited"), (403, None, "denied"), (404, None, "not_found"), (409, None, "conflict"),
    (400, None, "rejected"), (503, None, "server_error"), (None, TimeoutError("CANARY t"), "timeout (TimeoutError)"),
    (None, ConnectionError("CANARY c"), "network (ConnectionError)"), (None, ValueError("CANARY v"), "error (ValueError)"),
])
def test_the_error_is_a_class_word_never_a_message(status, exc, word):
    """ASVS V7.4.1 · CWE-209 · CWE-532: an error is a category and the exception's class name; its message (which may echo a request) is never kept."""
    assert api_calls.error_class(status, exc) == word


def test_a_retry_after_a_429_is_folded_into_its_call_with_the_wait(calls, monkeypatch):
    """ASVS V7.1.1 · CWE-778: the same thread sending the same request again after a retryable answer is one row with its retries and the wait between; another path is its own row."""
    t = [100.0]
    monkeypatch.setattr(api_calls, "_clock", lambda: t[0])
    calls.record("GET", "https://x/zia/api/v1/webDlpRules", 429)
    t[0] += 12.0
    calls.record("GET", "https://x/zia/api/v1/webDlpRules", 200)
    calls.record("GET", "https://x/zia/api/v1/dlpEngines", 200)
    rows = calls.rows()
    assert [(r["path"], r["status"], r["retries"]) for r in rows] == [("/zia/api/v1/dlpEngines", 200, 0), ("/zia/api/v1/webDlpRules", 200, 1)]
    assert rows[1]["wait_ms"] == 12000 and rows[1]["error"] == ""


def test_a_rate_limit_wait_is_counted_on_the_next_call_of_the_thread(calls):
    """ASVS V7.1.1 · CWE-778: seconds zia_rate held a request for ZIA's limits show as the call's wait."""
    calls.note_wait(1.5)
    calls.note_wait("junk")
    calls.note_wait(float("nan"))
    calls.record("POST", "https://x/zia/api/v1/status/activate", 200)
    assert calls.rows()[0]["wait_ms"] == 1500


def test_calls_are_tagged_with_their_job_for_the_per_run_view(calls):
    """ASVS V7.1.1 · CWE-778: a call made by a job (a builder's run) carries the job id and kind, and the list filters by it."""
    import pack_jobs
    job = pack_jobs.start("operation_apply", lambda log, cancel: (calls.record("PUT", "https://x/zia/api/v1/webDlpRules/9", 200), {})[1])
    job.thread.join(10)
    calls.record("GET", "https://x/zia/api/v1/webDlpRules", 200)
    mine = calls.rows(job=job.id)
    assert len(mine) == 1 and mine[0]["job_kind"] == "operation_apply" and mine[0]["method"] == "PUT"
    assert calls.jobs()[0] == {"id": job.id, "kind": "operation_apply", "calls": 1, "first": mine[0]["at"]}


def test_a_request_that_never_went_out_is_not_a_row(calls):
    """ASVS V7.1.1 · CWE-778: a Stop before sending (nothing reached Zscaler) leaves no row."""
    with calls.call("GET", "https://x/zia/api/v1/webDlpRules"):
        pass
    assert calls.rows() == []


# ── API calls: never a secret ─────────────────────────────────────────

def _send_over_fake_transport(monkeypatch, sess, url, **kw):
    import requests

    def echo(self, request, **k):
        r = requests.models.Response()
        r.status_code = 401
        r._content = json.dumps({"you_sent": str(request.body), "headers": dict(request.headers), "url": request.url}).encode()
        r.url, r.request = request.url, request
        return r
    monkeypatch.setattr(requests.adapters.HTTPAdapter, "send", echo)
    return sess.request(url=url, **kw)


def test_a_session_row_never_holds_a_header_body_query_or_tenant_value(calls, monkeypatch):
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: a request carrying a bearer token, a secret in the body and query and the tenant's host leaves only the method, template, status, times and class."""
    import requests
    from test_secret_canaries import ACCESS_TOKEN, CLIENT_SECRET, _leaks
    sess = api_calls.attach(requests.Session())
    assert api_calls.attach(sess) is sess, "attaching twice wraps once"
    _send_over_fake_transport(monkeypatch, sess, f"https://acme.zsapi.net/zia/api/v1/users/42?pw={CLIENT_SECRET}", method="POST",
                              headers={"Authorization": f"Bearer {ACCESS_TOKEN}"}, json={"client_secret": CLIENT_SECRET})
    rows = calls.rows()
    assert len(rows) == 1 and rows[0]["path"] == "/zia/api/v1/users/{id}" and rows[0]["status"] == 401 and rows[0]["error"] == "denied"
    blob = json.dumps(rows) + calls.to_csv(rows) + calls.to_json(rows)
    assert _leaks(blob, [CLIENT_SECRET, ACCESS_TOKEN]) == [] and "acme" not in blob and "42" not in blob.split("summary")[0].replace('"seq"', "")


def test_the_api_calls_view_and_exports_hold_no_secret_after_real_sdk_calls(token_echo, monkeypatch):
    """ASVS V8.3.4 · ASVS V7.1.1 · CWE-532 · CWE-200 · WSTG-INFO-05: readiness and tenant health over the real SDK (the echoing transport of the secret canaries) leave rows, and the list, the CSV and the JSON hold no token, secret, vanity domain or customer id."""
    from test_secret_canaries import ACCESS_PARTS, ONEAPI, SECRETS, _leaks
    srv_, http = token_echo
    monkeypatch.setattr(srv_, "_TENANT_HEALTH", type(srv_._TENANT_HEALTH)())
    api_calls.clear()
    body = dict(ONEAPI, scopes=["dlp", "zia_extras", "zpa"])
    for route in ("/api/readiness/start", "/api/tenant-health/start"):
        r = http.post(route, json=body)
        assert r.status_code == 200, (route, r.text)
    lst = http.get("/api/api-calls?limit=1000")
    csv_r = http.get("/api/api-calls/export?format=csv")
    json_r = http.get("/api/api-calls/export?format=json")
    rows = lst.json()["rows"]
    assert rows and {r["product"] for r in rows} >= {"ZIA"} and all(r["status"] == 400 for r in rows if r["product"] == "ZIA")
    assert any("/zia/api/v1/status" == r["path"] for r in rows)
    assert all("{id}" in r["path"] for r in rows if r["product"] == "ZPA")
    blob = lst.text + csv_r.text + json_r.text
    assert _leaks(blob, list(SECRETS.values()) + ACCESS_PARTS) == []
    assert ONEAPI["customer_id"] not in blob and ONEAPI["client_id"] not in blob and "acme" not in blob.lower()
    assert csv_r.headers["content-type"].startswith("text/csv") and "attachment" in csv_r.headers["content-disposition"]
    assert list(csv.reader(io.StringIO(csv_r.text)))[0] == list(api_calls.FIELDS)
    api_calls.clear()


@pytest.mark.parametrize("q,code", [("?job=../x", 400), ("?product=<b>", 400), ("?job=abc_123", 200), ("?product=ZIA", 200)])
def test_the_api_calls_routes_check_their_filters(q, code):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: the run and product filters take ids and names only; the export takes csv or json only."""
    http = TestClient(srv.app)
    assert http.get(f"/api/api-calls{q}").status_code == code
    assert http.get("/api/api-calls/export?format=xml").status_code == 400


def test_the_sdk_hooks_install_once_and_only_observe():
    """SSDF PW.4.1 · CWE-1357: the SDK's RequestExecutor.execute and HTTPClient.send_request are wrapped once and keep their signatures' results."""
    from zscaler import oneapi_http_client as hc
    from zscaler import request_executor as rx
    assert api_calls.install_sdk_hooks() is True and api_calls.install_sdk_hooks() is True
    assert getattr(rx.RequestExecutor.execute, "_api_calls", False) and getattr(hc.HTTPClient.send_request, "_api_calls", False)


# ── ZDX: a payload oracle per tier, and what the SDK verifies ─────────

# The oracle: (custom probe interval in minutes, CloudPath probes, predefined apps) per tier, written out here, not read from ops_zdx.
TIER_ORACLE = {
    "strict": (5, True, {"MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS", "SHAREPOINT", "ONEDRIVE", "ZOOM", "WEBEX", "OKTA",
                         "SALESFORCE_CLASSIC", "SERVICENOW", "BOX"}),
    "balanced": (10, True, {"MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS"}),
    "permissive": (15, False, {"MICROSOFT_LOGIN"}),
    "healthcare": (5, True, {"MICROSOFT_LOGIN", "OUTLOOK", "MICROSOFT_TEAMS", "ZOOM"}),
}


@pytest.mark.parametrize("tier", sorted(TIER_ORACLE))
def test_each_tier_plans_the_oracle_payloads(tier, tmp_path, monkeypatch):
    """ASVS V1.14.1 · CWE-1188 · CWE-841: starting from a tier, the custom app's Web probe runs at the tier's interval, its CloudPath probe exists exactly when the tier has them, and the predefined apps are the tier's (those ZDX offers)."""
    import ops_zdx as oz
    from test_ops_zdx import FakeZdx, client_for, preview, SUPPORTED
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    minutes, cloudpath, apps = TIER_ORACLE[tier]
    t = oz.tier_template(tier)
    assert {p["provider"] for p in t["predefined"]} == apps and t["interval_minutes"] == minutes
    assert all(p["cloudpath"] is cloudpath for p in t["predefined"])
    fake = FakeZdx()
    spec = {"type": "zdx_probes", "tier": tier, "template": "", "protocol": "ADAPTIVE", "predefined": t["predefined"],
            "custom": [{"name": "EHR portal", "url": "https://ehr.example.org/", "cloudpath": cloudpath}]}
    p = preview(fake, client_for(fake), spec)
    assert p["status"] == "ready" and fake.writes == []
    assert p["spec"]["tier"] == tier and p["spec"]["interval_minutes"] == minutes, "the tier sets the interval when the form names none"
    group = next(g for g in p["groups"] if g["handler"] == "zdx_custom_app")["target"]
    assert group["web_body"]["frequencyInSeconds"] == minutes * 60 and group["web_body"]["type"] == "WEB"
    assert (group["cloudpath_body"] is not None) is cloudpath
    if cloudpath:
        assert group["cloudpath_body"]["frequencyInSeconds"] == minutes * 60 and group["cloudpath_body"]["host"] == "ehr.example.org"
    offered = {s["provider"] for s in SUPPORTED}
    planned = {g["target"]["provider"] for g in p["groups"] if g["handler"] == "zdx_predefined_app"}
    excluded = {u["object"]["name"] for u in p["items"] if u["status"] == "excluded"}
    assert planned == (apps & offered) - {"ZOOM"}, "ZOOM needs the customer's prefix, so it is left out without one"
    assert len(excluded) == len(apps - offered) + (1 if "ZOOM" in apps else 0)
    assert any(n.startswith(f"Tier: {oz.TIERS[tier]['label']}.") for n in p["notes"]) and f"{oz.TIERS[tier]['label']} tier" in p["title"]


def test_a_choice_looser_than_the_tier_is_a_warning_and_an_unknown_tier_is_refused(tmp_path, monkeypatch):
    """ASVS V5.1.3 · CWE-20 · CWE-1188: a longer interval or a CloudPath probe left out under Strict is a warning (never a block); an unknown tier is refused before anything is read."""
    import admin_ops as ao
    from test_ops_zdx import FakeZdx, client_for, preview
    monkeypatch.setenv("DLP_CHECK_DEPLOYMENTS", str(tmp_path / "deployments.json"))
    fake = FakeZdx()
    spec = {"type": "zdx_probes", "tier": "strict", "interval_minutes": 30, "predefined": [],
            "custom": [{"name": "Intranet", "url": "https://intranet.example.com/", "cloudpath": False}]}
    p = preview(fake, client_for(fake), spec)
    assert p["status"] == "ready"
    assert any("every 30 minutes" in w and "Strict" in w for w in p["warnings"]) and any("no CloudPath probe for Intranet" in w for w in p["warnings"])
    with pytest.raises(ao.OperationError, match="Unknown tier"):
        ao.plan(client_for(fake), dict(spec, tier="paranoid"), scope=ao.scope_for(["zdx"], {}))
    assert [r for r in fake.requests if r[0] != "GET"] == []


def test_a_setup_without_a_tier_is_unchanged():
    """CWE-1357: a spec naming no tier keeps the old shape (no tier key, 5 minutes by default), so earlier plans and records keep their hash."""
    import ops_zdx as oz
    out = oz._clean_setup({"predefined": [{"provider": "MICROSOFT_LOGIN"}], "custom": []})
    assert "tier" not in out and out["interval_minutes"] == 5


def test_the_form_lists_the_tiers_with_balanced_by_default(tmp_path, monkeypatch):
    """WCAG 2.2 SC 3.3.2 · CWE-1188: the object list carries every tier with its interval and CloudPath choice, and Balanced as the default."""
    import admin_ops as ao
    from test_ops_zdx import FakeZdx, client_for
    out = ao.read_objects(client_for(FakeZdx()), "zdx_apps", ao.scope_for(["zdx"], {}))["zdx"]
    assert [t["tier"] for t in out["tiers"]] == ["strict", "balanced", "permissive", "healthcare"] and out["default_tier"] == "balanced"
    assert {t["tier"]: (t["interval_minutes"], t["cloudpath"]) for t in out["tiers"]} == {k: v[:2] for k, v in TIER_ORACLE.items()}


def test_what_is_verified_against_the_installed_sdk_and_what_stays_assumed():
    """SSDF PW.4.1 · CWE-1357: the /zdx/v1 prefix is the SDK's own; the SDK still has no ZDX configuration service, so the /config paths stay marked assumed."""
    import os
    import ops_zdx as oz
    import zscaler.zdx as zdx_pkg
    from zscaler.zdx.apps import AppsAPI
    api = AppsAPI.__new__(AppsAPI)
    AppsAPI.__init__(api, types.SimpleNamespace())
    assert api._zdx_base_endpoint == oz.ZDX_BASE == "/zdx/v1"
    root = os.path.dirname(zdx_pkg.__file__)
    sdk_text = "".join(open(os.path.join(dp, f), encoding="utf-8").read() for dp, _d, fs in os.walk(root) for f in fs if f.endswith(".py"))
    assert "/config/applications" not in sdk_text and "monitors" not in sdk_text, "the SDK gained a ZDX configuration service: verify ops_zdx"
    src = open(oz.__file__, encoding="utf-8").read()
    assert 'CONFIG = ZDX_BASE + "/config"      # ASSUMED' in src and "VERIFIED against the installed zscaler-sdk-python 1.11.3" in src


def test_two_ssl_order_problems_give_each_reason_once_and_all_the_steps():
    """ASVS V1.14.1 · CWE-696 · WCAG 2.2 SC 3.3.2: with two rule-order problems the readiness check says the first as its reason and the second as a note (never twice), and its steps fix both."""
    rules = [rule(1, "Bypass all", "DO_NOT_DECRYPT"), dict(REC, order=2), rule(3, "Inspect finance", "DECRYPT", urlCategories=["FINANCE"]), DEFAULT_DNI]
    chk = {c["key"]: c for c in readiness.run(Client(ssl=rules), ["dlp"], now=NOW)["checks"]}["ssl_rule_order"]
    assert chk["why"].startswith("'Bypass all'") and len(chk["notes"]) == 1 and chk["notes"][0] not in chk["why"]
    steps = " ".join(chk["steps"])
    assert "Bypass all" in steps and "Inspect everything else" in steps and steps.count("SSL/TLS Inspection") == 1
