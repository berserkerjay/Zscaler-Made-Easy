"""ASVS V4.1.3 · ASVS V1.4.4 · CWE-272 · OWASP A01:2021 · WSTG-ATHZ-02: user rule 1, "only read what is in scope", on every route.

One table (ROUTES) lists every route that reads a tenant. For each one:

* nothing it reads is in scope on the Scope page (an empty page selection,
  or no selection at all) -> 400 before any client is built and before
  anything is read (deny by default, fail closed);
* only part of what it reads is in scope -> it builds a client and reads
  only the in-scope part (least privilege).

A guard test walks every FastAPI route in dlp_api_server and fails when a
route reaches a tenant client factory (`_build_sdk_client`, `_build_client`,
`_raw_client`, `_proposal_client`) without being in ROUTES or in EXEMPT
with the reason it is allowed, so a new tenant-reading route without a
scope gate fails CI.

No tenant, no network, no clock: one fake client factory records whether
a client was built and every read (SDK service calls and raw GET paths).
Background jobs run synchronously in the request (pack_jobs.start is
replaced), so there is no sleep or polling. Every state file lives in
tmp_path.
"""
from __future__ import annotations

import ast
import inspect
import os
import re
import types
from typing import Any, Callable, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import dlp_api_server as srv

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "7210000000000"}
ALL_SCOPES = ["dlp", "zia_extras", "zpa", "zcc", "genai", "automation", "zdx", "zidentity", "rbac", "insights"]
ALL_CHANNELS = {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "genai_security", "shadow_it",
                                       "endpoint_scan", "ssl_inspection", "cloud_app_control", "device_control",
                                       "workflow_automation")}
NOT_ZSCALER = {c: "alternative" for c in ALL_CHANNELS}


def page(scopes: List[str], **channels: str) -> Dict[str, Any]:
    """A Scope page selection: the ticked scopes and the channels marked
    Zscaler (every other channel declared covered by another product)."""
    ch = dict(NOT_ZSCALER)
    ch.update(channels)
    return {"scopes": list(scopes), "channels": ch, "from_page": True}


NOTHING_TICKED = page([])
NOTHING_SENT: Dict[str, Any] = {}


# ── The fake client factory ────────────────────────────────────────────

class Reads:
    """What the fake factory saw: clients built and every read."""

    def __init__(self) -> None:
        self.built: List[str] = []
        self.reads: List[str] = []
        self.answers: Dict[str, Any] = {}   # a read's answer instead of an empty list (SDK path or "GET /path")

    def sdk(self) -> List[str]:
        return [r for r in self.reads if not r.startswith(("GET ", "POST ", "PUT ", "DELETE "))]

    def raw(self) -> List[str]:
        return [r[4:] for r in self.reads if r.startswith("GET ")]


class _Svc:
    """An SDK namespace or service: every call records its dotted path and
    answers like an SDK list method, ([], response, None)."""

    def __init__(self, log: Reads, path: str) -> None:
        self._log, self._path = log, path

    def __getattr__(self, name: str) -> "_Svc":
        if name.startswith("__"):
            raise AttributeError(name)
        return _Svc(self._log, f"{self._path}.{name}")

    def __call__(self, *a: Any, **k: Any) -> Any:
        self._log.reads.append(self._path)
        return self._log.answers.get(self._path, []), None, None

    def __iter__(self):
        return iter(())

    def __bool__(self) -> bool:
        return True


SDK_NAMESPACES = ("zia", "zpa", "zcc", "zdx", "zins", "zwa", "zidentity", "ztw")


class FakeSdk:
    """What _build_sdk_client returns: the SDK's product namespaces."""

    def __init__(self, log: Reads) -> None:
        for ns in SDK_NAMESPACES:
            setattr(self, ns, _Svc(log, ns))

    def close(self) -> None:
        pass


class FakeRaw:
    """What _raw_client returns: the assessment client (raw GETs)."""

    def __init__(self, log: Reads) -> None:
        self._log = log
        self._zs = FakeSdk(log)
        self.requests_made = 0

    def auth(self) -> bool:
        return True

    def get(self, ep: str, p: Any = None, **k: Any):
        self._log.reads.append(f"GET {ep}")
        self.requests_made += 1
        return self._log.answers.get(f"GET {ep}", []), 200

    def get_text(self, ep: str, p: Any = None, **k: Any):
        self._log.reads.append(f"GET {ep}")
        return "", 200

    def post(self, ep: str, body: Any = None, **k: Any):
        self._log.reads.append(f"POST {ep}")
        return [], 200

    def stop(self) -> None:
        pass

    def close(self) -> None:
        pass


class SyncJob:
    def __init__(self, kind: str, result: Any, error: str = "") -> None:
        self.id, self.kind, self.result, self.error = "sync-job", kind, result, error
        self.status = "failed" if error else "done"


def _sync_start(kind: str, fn: Callable, **_k: Any) -> SyncJob:
    """pack_jobs.start, run in the request: the job's reads happen before
    the response, so the test needs no thread, sleep or poll."""
    import threading
    try:
        return SyncJob(kind, fn(lambda line: None, threading.Event()))
    except Exception as e:  # noqa: BLE001 — a reader that fails on empty fixtures still read what it read
        return SyncJob(kind, None, f"{type(e).__name__}: {e}")


@pytest.fixture
def tenant(tmp_path, monkeypatch) -> Reads:
    """Arrange: an isolated app (state files in tmp_path, no saved tenant,
    no environment credentials) whose client factories are the fakes."""
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_DEPLOYMENTS", "deployments"),
                      ("DLPCHECK_PROPOSALS_FILE", "proposals.json"), ("DLPCHECK_CHANGE_QUEUE_FILE", "change_queue.json"),
                      ("DLP_CHECK_DIGESTS", "digests"), ("DLP_CHECK_SSL_COVERAGE_STATE", "ssl_coverage.json"),
                      ("DLP_CHECK_SELF_HEAL_STATE", "self_heal.json"), ("DLP_CHECK_BEACON_STATE", "beacon.json"),
                      ("DLP_CHECK_GUIDANCE_STATE", "guidance_state.json"), ("DLP_CHECK_CHECKS_CONFIG", "checks_config.json"),
                      ("DLP_CHECK_SAAS_MATRIX", "saas_apps.local.json")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX_REFRESH", "0")
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if (k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH") or k in ("DLP_CHECK_SMTP_HOST", "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_NOTIFY"):
            monkeypatch.delenv(k, raising=False)
    log = Reads()

    def sdk_factory(creds):
        log.built.append("sdk")
        return FakeSdk(log)

    def raw_factory(creds):
        log.built.append("raw")
        return FakeRaw(log)

    monkeypatch.setattr(srv, "_build_sdk_client", sdk_factory)
    monkeypatch.setattr(srv, "_raw_client", raw_factory)
    import pack_jobs
    monkeypatch.setattr(pack_jobs, "start", _sync_start)
    # Injected time: no reader paces, polls or naps against the real clock.
    import audit_timeline
    import insights
    import zcc_fleet
    import zpa_reader
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(insights, "PACE_SECONDS", 0.0)
    monkeypatch.setattr(audit_timeline, "POLL_SECONDS", 0.0)
    monkeypatch.setattr(audit_timeline, "POLL_TIMEOUT", 0.0)
    monkeypatch.setattr(zcc_fleet, "_nap", lambda seconds, cancel: None)
    # No cached read from another test (isolation).
    import console_index
    monkeypatch.setattr(console_index, "_CACHE", {})
    monkeypatch.setattr(srv, "_live_rules_cache", {})
    monkeypatch.setattr(srv, "_live_connector_cache", {})
    monkeypatch.setattr(srv, "_REPORTS", {})
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    return log


# ── Scope page selections ──────────────────────────────────────────────

WEB = page(["dlp"], web_dlp="zscaler")                       # DLP ticked, only Inline Web DLP on Zscaler
ZIA = page(["zia_extras"])                                   # ZIA platform only
ZPA = page(["zpa"])
ZCC = page(["zcc"])
INSIGHTS = page(["insights"])
AUTOMATION = page(["automation"])
ZDX = page(["zdx"])

# What each partial selection leaves out: a read naming any of these is out of scope.
OTHER_DLP = ("endpoint_dlp_rules", "outbound_email_dlp_rules", "casb_dlp_rules", "saas_security_api", "casb_tenant",
             "/endPointDlpRules", "/emailDlpRules", "/casbDlpRules", "zwa.")
NOT_ZIA_PLATFORM = ("firewall", "/locations", "networkService", "networkApplication", "ipDestinationGroups", "auditlog")
NOT_DECLARED = ("sslInspectionRules", "ssl_inspection_rules", "cloudApplicationRules", "cloudappcontrol.")
OTHER_PRODUCTS = ("zpa.", "zcc.", "/zcc/", "zins.", "zdx.", "zidentity.")
WEB_OUT = OTHER_DLP + NOT_ZIA_PLATFORM + NOT_DECLARED + OTHER_PRODUCTS
ZIA_OUT = ("dlp_web_rules", "/webDlpRules", "dlp_dictionary", "dlp_engine", "/dlpEngines", "/dlpDictionaries") + OTHER_DLP + NOT_DECLARED \
    + OTHER_PRODUCTS + ("auditlog",)
ZPA_OUT = ("zia.", "/zia/", "zcc.", "/zcc/", "zins.", "zwa.")
ZCC_OUT = ("zia.", "zpa.", "zins.", "zwa.") + tuple(f"/zia/{x}" for x in ("webDlpRules", "urlFilteringRules", "sslInspectionRules", "fileTypeRules",
                                                                         "firewallFilteringRules", "cloudApplicationRules", "urlCategories"))
INSIGHTS_OUT = ("zia.", "/zia/", "zpa.", "zcc.", "/zcc/", "zwa.")
ZDX_OUT = ("zia.", "/zia/", "zpa.", "zcc.", "/zcc/", "zins.", "zwa.", "zidentity.")
AUTOMATION_OUT = ("zia.", "zpa.", "zcc.", "/zcc/", "zins.", "zwa.", "/zia/webDlpRules", "/zia/urlFilteringRules")


def _profile_from(sel: Dict[str, Any]) -> Dict[str, Any]:
    """The continuous evaluation reads a saved profile's selection, not the body's."""
    import tenant_profiles
    tenant_profiles.upsert({"name": "Acme", "cloud": "production", "vanity_domain": "acme", "client_id": CREDS["client_id"],
                            "baseline_packs": ["zbp_enterprise_baseline"], "scopes": sel.get("scopes") or [],
                            "channels": sel.get("channels") or {}}, client_secret=CREDS["client_secret"], remember_secret=True)
    return {"notify": False}


def _recorded_operation(sel: Dict[str, Any]) -> Dict[str, Any]:
    """An applied bulk change of Inline Web DLP rules, so its Undo can be previewed."""
    import deployments
    import tenant_auth
    import tenant_fingerprint
    creds = srv._tenant_creds(types.SimpleNamespace(**CREDS))
    deployments.add_operation(dict({"id": "op-qa-1", "at": "2026-01-01T00:00:00Z", "tenant_label": tenant_auth.record_label(creds), "type": "rule_state",
                                    "items": [], "undone_by": None, "status": "applied",
                                    "inverse": {"type": "rule_state", "targets": [{"policy": "web_dlp", "id": 1, "to": "ENABLED"}]}},
                                   **tenant_fingerprint.record_ids(creds)))
    return dict(CREDS, **sel)


class Route:
    """One tenant-reading route: its body, the partial selection that puts
    only part of what it reads in scope and what that selection leaves out,
    and the answer it gives when nothing it reads is in scope."""

    def __init__(self, path: str, body: Optional[Dict[str, Any]] = None, *, partial: Optional[Dict[str, Any]] = WEB,
                 out: tuple = WEB_OUT, nothing: int = 400, setup: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
                 why: str = "") -> None:
        self.path, self.body, self.partial, self.out, self.nothing, self.setup, self.why = path, body or {}, partial, out, nothing, setup, why

    def request(self, sel: Dict[str, Any]) -> Dict[str, Any]:
        if self.setup is not None:
            base = self.setup(sel)
            return dict(base, **self.body)
        return dict(CREDS, **self.body, **sel)

    def __repr__(self) -> str:
        return self.path


DEST = {"destination": "example.com"}
RULE_STATE_WEB = {"operation": {"type": "rule_state", "targets": [{"policy": "web_dlp", "id": 1, "to": "DISABLED"}]}}
ZCC_BUILD = {"operation": {"type": "zcc_profile_build", "platform": "windows", "forwarding": {"template": "best_practice", "name": "QA fwd"},
                           "app": {"template": "best_practice", "name": "QA app"}}}
ZDX_SETUP = {"operation": {"type": "zdx_probes", "predefined": [{"provider": "MICROSOFT_LOGIN"}],
                           "custom": [{"name": "Intranet", "url": "https://intranet.example.com/"}]}}

ROUTES: List[Route] = [
    # Job starts and their waited-for twins
    Route("/api/dlp-packs/removal/inventory"),
    Route("/api/dlp-packs/export/start", {"pack_name": "qa"}),
    Route("/api/dlp-packs/inventory/start"),
    Route("/api/shadow-rules/start"),
    Route("/api/shadow-rules"),
    Route("/api/path-analyzer/start", DEST),
    Route("/api/path-analyzer", DEST),
    Route("/api/path-analyzer/batch/start", {"har_hosts": ["example.com"]}),
    Route("/api/report/data-flow"),
    Route("/api/report/ssl-flow"),
    Route("/api/report/bypass"),
    Route("/api/report/bypass/export", {"format": "json"}),
    Route("/api/detection-health"),
    Route("/api/live-feed"),
    Route("/api/dlp/efficacy"),
    Route("/api/dlp/efficacy/export", {"format": "json"}),
    Route("/api/dlp/efficacy/test", {"corpus": "4111 1111 1111 1111"}),
    Route("/api/migrate/status"),
    Route("/api/migrate/fetch"),
    Route("/api/migrate/status/manual", {"mode": "rule_order"}),
    Route("/api/migrate/enable", {"dry_run": True}),
    Route("/api/migrate/delete-all", {"dry_run": True}),
    Route("/api/migrate/post", {"dry_run": True, "proposed_rules": [{"name": "r"}]}, partial=None),   # a dry run reads nothing
    Route("/api/flow/scenario", {"scenario_id": "web_upload", "destination": "example.com"}, nothing=200,
          why="by design: with nothing in scope the scenario answers locally with every stage marked excluded, and signs in to nothing"),
    Route("/api/assess", partial=None),            # its partial reads: tests/test_scope_prerequisites.py
    Route("/api/beacon/run", {"tenant_watch": True, "online": False}, partial=None),   # partial: tests/test_beacon_scope.py
    Route("/api/diagnose/zcc", partial=ZCC, out=ZCC_OUT),
    # The console index (Find anything and the browser extension)
    Route("/api/console-index"),
    Route("/api/console-index", partial=ZIA, out=ZIA_OUT),
    # Exports
    Route("/api/exports/policies/start", {"format": "xlsx"}),
    Route("/api/exports/policies/start", {"format": "xlsx"}, partial=ZIA, out=ZIA_OUT),
    Route("/api/exports/urls/start"),
    Route("/api/exports/urls/start", partial=ZCC, out=ZCC_OUT),
    Route("/api/exports/url-categories/analyze/start"),
    Route("/api/exports/locations/start", partial=ZIA, out=ZIA_OUT),
    Route("/api/exports/client-connector/start", partial=ZCC, out=ZCC_OUT),
    # Insights, ZPA, device posture, browser security, SSL coverage
    Route("/api/insights/start", partial=INSIGHTS, out=INSIGHTS_OUT),
    Route("/api/insights", partial=INSIGHTS, out=INSIGHTS_OUT),
    Route("/api/zpa/analysis/start", partial=ZPA, out=ZPA_OUT),
    Route("/api/zpa/diagnose", {"destination": "app.example.com", "port": "443"}, partial=ZPA, out=ZPA_OUT),
    Route("/api/device-posture/start", partial=ZPA, out=ZPA_OUT),
    Route("/api/browser-security/start", partial=ZPA, out=ZPA_OUT),
    Route("/api/browser-security/start", partial=ZIA, out=ZIA_OUT),
    Route("/api/ssl-coverage/start", partial=page(["dlp"], web_dlp="zscaler", ssl_inspection="zscaler"),
          out=OTHER_DLP + NOT_ZIA_PLATFORM + ("zpa.", "zcc.", "/zcc/", "zins.")),
    # Self-healing, the audit timeline, the fleet, bulk changes, the loop
    Route("/api/self-heal/tenant/scan", {"pack_ids": ["zbp_enterprise_baseline"]}),
    Route("/api/self-heal/tenant/heal", {"ids": ["x"], "confirm": "x"}, partial=None),   # a write: refused before sign-in only
    Route("/api/audit-timeline/start", {"include_zia": True}, partial=AUTOMATION, out=AUTOMATION_OUT),
    Route("/api/zcc/fleet/start", partial=ZCC, out=ZCC_OUT),
    Route("/api/operations/objects/start", {"family": "rules"}),
    Route("/api/operations/objects", {"family": "rules"}),
    Route("/api/operations/preview/start", RULE_STATE_WEB),
    Route("/api/operations/preview", RULE_STATE_WEB),
    Route("/api/operations/objects/start", {"family": "zdx_apps"}, partial=ZDX, out=ZDX_OUT),
    Route("/api/operations/preview", ZDX_SETUP, partial=ZDX, out=ZDX_OUT),
    Route("/api/operations/preview/start", {"operation": {"type": "zdx_probe_state", "targets": [{"app": "1", "to": "off"}]}},
          partial=ZDX, out=ZDX_OUT),
    Route("/api/operations/op-qa-1/undo/preview/start", setup=_recorded_operation),
    Route("/api/operations/op-qa-1/undo/preview", setup=_recorded_operation),
    # Client Connector profiles: plugin types on the same engine (ops_zcc), and the install command builder's token read
    Route("/api/operations/objects", {"family": "zcc_profiles"}, partial=ZCC, out=ZCC_OUT),
    Route("/api/operations/preview/start", ZCC_BUILD, partial=ZCC, out=ZCC_OUT),
    Route("/api/operations/preview", {"operation": {"type": "zcc_profile_delete", "targets": [{"kind": "forwarding", "id": "1", "name": "QA"}]}},
          partial=ZCC, out=ZCC_OUT),
    Route("/api/zcc/install", {"app_profile_id": "21"}, partial=ZCC, out=ZCC_OUT),
    Route("/api/digests/run", setup=_profile_from, nothing=200,
          why="by design: the loop reads saved profiles, and one with nothing in scope is reported 'not read' in the digest"),
]

NOTHING = {"nothing-ticked": NOTHING_TICKED, "nothing-sent": NOTHING_SENT, "upper-case-keys": page([s.upper() for s in ALL_SCOPES])}


def _ids(r: Route) -> str:
    return r.path + ("" if r.partial in (None, WEB) else f"[{'+'.join(r.partial['scopes'])}]")


@pytest.mark.parametrize("sel", list(NOTHING.values()), ids=list(NOTHING))
@pytest.mark.parametrize("route", ROUTES, ids=_ids)
def test_nothing_in_scope_is_refused_before_a_client_is_built(tenant, route, sel):
    """ASVS V4.1.3 · ASVS V4.1.5 · CWE-272 · CWE-285 · WSTG-ATHZ-02: nothing in scope -> 400 before any client is built or anything is read."""
    # Arrange
    body = route.request(sel)
    # Act
    r = TestClient(srv.app).post(route.path, json=body)
    # Assert
    assert r.status_code == route.nothing, (route.why, r.status_code, r.text[:400])
    if route.nothing == 400:
        assert "scope" in str(r.json().get("detail")).lower(), r.text[:400]
    assert tenant.built == [] and tenant.reads == [], (tenant.built, tenant.reads)


PARTIAL = [r for r in ROUTES if r.partial is not None]


@pytest.mark.parametrize("route", PARTIAL, ids=_ids)
def test_part_in_scope_reads_only_that_part(tenant, route):
    """ASVS V4.1.3 · ASVS V1.4.4 · CWE-272 · CWE-201: part in scope -> a client is built and only the in-scope part is read."""
    # Arrange
    body = route.request(route.partial)
    # Act
    r = TestClient(srv.app).post(route.path, json=body)
    # Assert
    assert r.status_code == 200, r.text[:400]
    assert tenant.built and tenant.reads, "nothing was read: the partial selection proves nothing"
    leaked = sorted({x for x in tenant.reads if any(o in x for o in route.out)})
    assert not leaked, f"read out of scope: {leaked}"


@pytest.mark.parametrize("route", [r for r in PARTIAL if r.setup is None], ids=_ids)
def test_part_in_scope_of_a_saved_profile_reads_only_that_part(tenant, route):
    """ASVS V4.1.3 · CWE-272: with no Scope page selection sent, the saved profile's partial selection is honoured just as narrowly."""
    # Arrange: the page sends nothing; the chosen profile holds the partial selection.
    import tenant_profiles
    pid = tenant_profiles.upsert({"name": "Partial", "cloud": "production", "vanity_domain": "acme", "client_id": CREDS["client_id"],
                                  "scopes": route.partial["scopes"], "channels": route.partial["channels"]},
                                 client_secret=CREDS["client_secret"], remember_secret=True)["id"]
    body = dict(CREDS, **route.body, profile_id=pid)
    # Act
    r = TestClient(srv.app).post(route.path, json=body)
    # Assert
    assert r.status_code == 200, r.text[:400]
    assert tenant.built and tenant.reads
    leaked = sorted({x for x in tenant.reads if any(o in x for o in route.out)})
    assert not leaked, f"read out of scope: {leaked}"


# ── Negative and boundary cases ────────────────────────────────────────

EXPLICIT_PICKS = [
    ("/api/exports/policies/start", {"format": "xlsx", "policies": ["firewall"]}, WEB),
    ("/api/dlp-packs/export/start", {"pack_name": "qa", "rules": {"email": "all"}}, WEB),
    ("/api/operations/preview", {"operation": {"type": "rule_state", "targets": [{"policy": "endpoint_dlp", "id": 1, "to": "DISABLED"}]}}, WEB),
    ("/api/operations/preview", {"operation": {"type": "reorder", "policy": "ssl_inspection", "order": [1]}}, WEB),
    ("/api/operations/objects", {"family": "zpa_segments"}, WEB),
    ("/api/operations/objects", {"family": "url_categories"}, ZPA),
    ("/api/operations/preview", ZDX_SETUP, WEB),
    ("/api/operations/objects", {"family": "zdx_apps"}, ZPA),
    ("/api/self-heal/tenant/scan", {"pack_ids": ["zbp_enterprise_baseline"], "include_who": True}, WEB),
    ("/api/audit-timeline/start", {"include_zia": True}, WEB),
    ("/api/device-posture/start", {}, ZCC),
    ("/api/zpa/diagnose", {"destination": "app.example.com", "port": "443", "report_id": "zpa-anything"}, ZCC),
]


@pytest.mark.parametrize("path,extra,sel", EXPLICIT_PICKS, ids=[f"{p}:{'+'.join(s['scopes'])}:{'-'.join(sorted(e))}" for p, e, s in EXPLICIT_PICKS])
def test_an_explicit_pick_outside_the_scope_is_refused_before_sign_in(tenant, path, extra, sel):
    """ASVS V4.1.3 · ASVS V4.2.1 · CWE-639 · WSTG-ATHZ-02: naming an out-of-scope part in the request never widens the scope."""
    # Arrange
    body = dict(CREDS, **extra, **sel)
    # Act
    r = TestClient(srv.app).post(path, json=body)
    # Assert
    assert r.status_code == 400 and "scope" in r.text.lower(), r.text[:400]
    assert tenant.built == [] and tenant.reads == []


def _wide_profile() -> str:
    import tenant_profiles
    return tenant_profiles.upsert({"name": "Wide", "cloud": "production", "vanity_domain": "acme", "client_id": CREDS["client_id"],
                                   "scopes": ALL_SCOPES, "channels": ALL_CHANNELS}, client_secret=CREDS["client_secret"], remember_secret=True)["id"]


@pytest.mark.parametrize("route", [r for r in ROUTES if r.setup is None and r.nothing == 400], ids=_ids)
def test_a_saved_profile_never_widens_an_empty_scope_page(tenant, route):
    """ASVS V4.1.3 · ASVS V4.1.5 · CWE-272 · CWE-863: an empty Scope page wins over a wider saved profile (fail closed)."""
    # Arrange: the profile ticks everything, the page (from_page) ticks nothing.
    body = dict(route.body, profile_id=_wide_profile(), **NOTHING_TICKED)
    # Act
    r = TestClient(srv.app).post(route.path, json=body)
    # Assert
    assert r.status_code == 400, r.text[:400]
    assert tenant.built == [] and tenant.reads == []


# ── Guard: every tenant-reading route is in ROUTES or EXEMPT ───────────

FACTORIES = {"_build_sdk_client", "_build_client", "_raw_client"}
# Routes that reach a client factory but are not the scope rule's to gate,
# each with why (CISA Secure by Design: every exception is written down).
EXEMPT: Dict[str, str] = {
    "POST /api/tenant/check": "sign-in test only: lists and counts nothing (tenant_check docstring)",
    "POST /api/remediation/execute": "one remediation of a check the operator picked; the write is gated by write mode",
    "POST /api/dlp-packs/{pack_id}/from-tenant": "Deploy Studio: rebuilds the pack the operator picked from its own dictionaries",
    "POST /api/dlp-packs/preflight": "Deploy Studio: plans the packs and channels the operator ticked on each pack card",
    "POST /api/dlp-packs/journey": "Deploy Studio: measures the pack the operator picked on the channels ticked on its card",
    "POST /api/dlp-packs/baseline-status": "Deploy Studio: as /api/dlp-packs/journey",
    "POST /api/dlp-packs/terraform": "Deploy Studio: gap mode plans the packs and channels the operator ticked",
    "POST /api/dlp-packs/terraform/start": "Deploy Studio: as /api/dlp-packs/terraform",
    "POST /api/dlp-packs/apply": "a write: deploys the previewed plan (plan_hash), gated by write mode",
    "POST /api/dlp-packs/apply/start": "a write: as /api/dlp-packs/apply",
    "POST /api/dlp-packs/{pack_id}/import": "a write: imports the pack the operator picked, gated by write mode",
    "POST /api/dlp-packs/{pack_id}/verify": "reads back what a deployment of the picked pack created",
    "POST /api/deployments/{dep_id}/undo": "a write: undoes a recorded deployment in its own tenant",
    "POST /api/dlp-packs/removal/preflight": "plans the removal of the packs, rules or deployment the operator picked",
    "POST /api/dlp-packs/removal/apply": "a write: applies the previewed removal plan",
    "POST /api/dlp-packs/removal/apply/start": "a write: as /api/dlp-packs/removal/apply",
    "POST /api/change-queue/deploy": "files a deploy plan for approval (the Deploy Studio plan)",
    "POST /api/change-queue/removal": "files a removal plan for approval",
    "POST /api/change-queue/{rid}/apply": "a write: applies an approved change request",
    "POST /api/proposals/{tenant}/{pid}/preview": "re-reads the one rule a proposal raised by an in-scope read names",
    "POST /api/proposals/{tenant}/{pid}/apply": "a write: applies an approved proposal",
    "POST /api/proposals/{tenant}/{pid}/rollback": "a write: rolls an applied proposal back",
    "POST /api/operations/apply": "a write: write mode, confirm and plan_hash first, then the same scope gate as the preview (_ops_apply_gate)",
    "POST /api/operations/apply/start": "a write: as /api/operations/apply",
    "ON_EVENT startup": "the continuous evaluation timer: the same run as POST /api/digests/run (in ROUTES)",
}


def _route_reaches_a_client_factory() -> Dict[str, str]:
    """{"METHOD /path": function} for every route of dlp_api_server whose
    function, or a module function it names (transitively, lambdas and
    jobs included), names a tenant client factory."""
    src = inspect.getsource(srv)
    tree = ast.parse(src)
    funcs = {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
    names = {k: {x.id for x in ast.walk(v) if isinstance(x, ast.Name)} for k, v in funcs.items()}
    memo: Dict[str, bool] = {}

    def reaches(name: str, seen: frozenset = frozenset()) -> bool:
        if name in FACTORIES:
            return True
        if name not in funcs or name in seen:
            return False
        if name not in memo:
            memo[name] = any(reaches(x, seen | {name}) for x in names[name] if x in funcs or x in FACTORIES)
        return memo[name]

    out: Dict[str, str] = {}
    for fn in funcs.values():
        for d in fn.decorator_list:
            if not (isinstance(d, ast.Call) and isinstance(d.func, ast.Attribute) and getattr(d.func.value, "id", "") == "app" and d.args
                    and isinstance(d.args[0], ast.Constant)):
                continue
            if any(reaches(x) for x in names[fn.name] if x in funcs or x in FACTORIES):
                out[f"{d.func.attr.upper()} {d.args[0].value}"] = fn.name
    return out


def _table_key(path: str) -> str:
    return "POST " + re.sub(r"/op-qa-1/", "/{op_id}/", path)


def test_every_route_that_reaches_a_tenant_client_is_in_the_scope_table():
    """ASVS V1.4.4 · ASVS V4.1.3 · CWE-862 · SSDF PW.8.2: a new tenant-reading route without a scope gate (and a ROUTES row) fails CI."""
    # Arrange
    reaching = _route_reaches_a_client_factory()
    covered = {_table_key(r.path) for r in ROUTES} | set(EXEMPT)
    # Act
    missing = sorted(k for k in reaching if k not in covered)
    # Assert
    assert len(reaching) > 50, "the route scan found too few routes: is the guard still reading dlp_api_server?"
    assert not missing, ("these routes read a tenant but are neither in ROUTES (scope-gated, tested above) nor in EXEMPT "
                         f"(with the reason): {missing}")


def test_the_scope_table_names_only_routes_that_exist():
    """ASVS V1.4.4 · SSDF PW.8.2: no stale row: every ROUTES and EXEMPT entry is a live route that reaches a tenant client."""
    # Arrange
    reaching = _route_reaches_a_client_factory()
    # Act
    stale = sorted({_table_key(r.path) for r in ROUTES} | set(EXEMPT)) 
    stale = [k for k in stale if k not in reaching]
    # Assert
    assert not stale, stale


# ── The tenant is part of the scope: no read made for one tenant answers for another ──

OTHER_TENANT = dict(CREDS, vanity_domain="globex", client_id="zzz987654321")


@pytest.mark.parametrize("path,extra", [("/api/path-analyzer", {"destination": "example.com"}),
                                        ("/api/path-analyzer/start", {"destination": "example.com"}),
                                        ("/api/path-analyzer/batch/start", {"har_hosts": ["example.com"]})])
def test_a_kept_path_read_is_never_reused_for_another_tenant(tenant, path, extra):
    """ASVS V4.2.1 · CWE-639 · CWE-524 · WSTG-ATHZ-04: report_id of tenant A's read does not answer tenant B's analysis."""
    # Arrange: tenant A's analysis keeps its read under a report_id.
    c = TestClient(srv.app)
    first = c.post("/api/path-analyzer", json=dict(CREDS, destination="example.com", **WEB))
    rid = first.json()["report_id"]
    assert first.status_code == 200 and rid.startswith("dataflow-")
    tenant.reads.clear()
    # Act: tenant B, same scope, sends A's report_id.
    r = c.post(path, json=dict(OTHER_TENANT, report_id=rid, **extra, **WEB))
    # Assert: B's own tenant is read; A's read is not reused.
    assert r.status_code == 200, r.text[:300]
    assert "GET /zia/webDlpRules" in tenant.reads, tenant.reads


def test_a_kept_path_read_is_still_reused_for_the_same_tenant(tenant):
    """ASVS V4.2.1 · CWE-639: boundary: the same tenant and scope reuse the kept read (only the URL lookup is live)."""
    # Arrange
    c = TestClient(srv.app)
    rid = c.post("/api/path-analyzer", json=dict(CREDS, destination="example.com", **WEB)).json()["report_id"]
    tenant.reads.clear()
    # Act
    r = c.post("/api/path-analyzer", json=dict(CREDS, destination="example.org", report_id=rid, **WEB))
    # Assert
    assert r.status_code == 200 and tenant.reads == ["POST /zia/urlLookup"], tenant.reads


def test_the_console_index_cache_never_answers_for_another_tenant(tenant):
    """ASVS V4.2.1 · ASVS V8.1.1 · CWE-524 · CWE-639: tenant B typed on this computer never gets tenant A's cached object index."""
    # Arrange: tenant A's index is cached (typed credentials, no saved profile).
    c = TestClient(srv.app)
    a = c.post("/api/console-index", json=dict(CREDS, **WEB))
    assert a.status_code == 200 and a.json()["tenant_label"].startswith("acme")
    tenant.reads.clear()
    # Act
    b = c.post("/api/console-index", json=dict(OTHER_TENANT, **WEB))
    # Assert
    assert b.status_code == 200 and b.json()["tenant_label"].startswith("globex"), b.json().get("tenant_label")
    assert tenant.reads, "tenant B was answered from tenant A's cache"


def test_the_console_index_cache_still_answers_the_same_tenant(tenant):
    """ASVS V8.1.1 · CWE-524: boundary: the same tenant and scope within the cache window is answered without a read."""
    # Arrange
    c = TestClient(srv.app)
    c.post("/api/console-index", json=dict(CREDS, **WEB))
    tenant.reads.clear()
    # Act
    r = c.post("/api/console-index", json=dict(CREDS, **WEB))
    # Assert
    assert r.status_code == 200 and r.json().get("cached_at") and tenant.reads == []


def test_the_browser_security_page_sends_the_channel_declaration():
    """ASVS V4.1.3 · CWE-272: the Browser security page sends the Scope page's channels, so Cloud App Control is read only when marked Zscaler."""
    # Arrange
    with open(os.path.join(ROOT, "static", "report_browser.html"), encoding="utf-8") as f:
        page_src = f.read()
    # Act
    fn = page_src[page_src.index("function scopeSelection()"):]
    fn = fn[:fn.index("\n    }\n")]
    # Assert
    assert "__dbChannelScope" in fn and "zassess_channels_v1" in fn, fn
    assert "channels: {}, from_page: true" not in fn
