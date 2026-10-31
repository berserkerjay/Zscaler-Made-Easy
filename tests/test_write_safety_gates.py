"""Write safety (QA check T5): no request can change a tenant unless every
gate holds: write mode on, a writer under SSO, the assessor named and the
route's explicit confirmation (confirm=true, or its typed phrase).

How it is proven, without ever touching a real tenant:

* Every tenant client the app builds (`_build_sdk_client`, `_raw_client`)
  is a deny-by-default recording fake (`Recorder`): any call whose name is
  not a read (list/get/search/lookup) is recorded as a write.
* Every function that performs a tenant write (the "sinks": pack deploy,
  removal, undo, proposal apply/rollback, bulk changes, remediation, rule
  migration) is replaced by a stub that writes through the client it was
  given, so a request that reaches a sink shows up as a recorded write.
* `WRITE_CASES` is the table of routes that can change a tenant. For each,
  the positive control (every gate holds) must reach the sink, and dropping
  any one gate must be refused with nothing written and no sink reached.
* `READ_ONLY` classifies every other POST/PUT/PATCH/DELETE route. A route
  in neither table fails `test_every_state_changing_route_is_classified`,
  so a new write path without the gates fails CI.
* Every read-only route is called with every privilege at once (write mode
  on, a signed-in writer, the assessor, confirm=true, the typed phrases,
  dry_run=false): nothing may be written.

Further checks: preview never writes, undo is gated, self-heal auto-apply
is refused, continuous evaluation and Simple mode never write, the browser
extension's origin reaches only its read-only allow-list, and the four-eyes
change queue cannot be self-approved with DLP_CHECK_FOUR_EYES on.
"""
from __future__ import annotations

import os
import re
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional, Tuple

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient

import dlp_api_server as srv
import security
import sso
import tenant_auth

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# The recording fake tenant client (deny by default)
# ---------------------------------------------------------------------------

# zscaler/zwa reads named otherwise: audit_logs (the audit search), change_history (an incident's history).
READ_NAME = re.compile(r"^(list|get|search|lookup)(_|$)|_search$|^(audit_logs|change_history)$")
# POSTs ZIA answers without changing configuration (a URL lookup, preparing
# the admin audit log report); every other raw POST/PUT/DELETE is a write.
# The Workflow Automation incident and audit-log searches are POSTs that change
# nothing too (zscaler/zwa/dlp_incidents.py dlp_incident_search, zwa/audit_logs.py
# audit_logs), sent through channel_scope.ScopedClient.post_read with their paging
# in the query string.
READ_ONLY_POSTS = {"/zia/urlLookup", "/zia/auditlogEntryReport", "/zwa/dlp/v1/incidents/search", "/zwa/dlp/v1/customer/audit"}
NOT_A_CALL = {"auth", "close", "stop", "stop_check", "_ensure_token"}
# SDK reads whose names are not list/get (verified against zscaler-sdk-python
# 1.11.3): zia/activate.py status() is GET /status (activate() is the write).
READ_CALLS = {("zia", "activate", "status")}


class Recorder:
    """A fake tenant client of either kind (the SDK client or the raw HTTP
    `Client`). Attribute access walks a path (`zia.dlp_web_rules.add_rule`);
    calling it records a write unless the last name is a read. Reads answer
    empty (the SDK's `(items, response, error)`, or the raw client's
    `(data, status)` for `get`). Writes answer an error and are refused."""

    def __init__(self, writes: List[str], path: Tuple[str, ...] = ()):
        object.__setattr__(self, "_w", writes)
        object.__setattr__(self, "_p", path)

    def __getattr__(self, name: str) -> "Recorder":
        if name.startswith("__"):
            raise AttributeError(name)
        return Recorder(self._w, self._p + (name,))

    def __setattr__(self, name: str, value: Any) -> None:   # the app sets attributes on clients (pacing hooks)
        pass

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        name = self._p[-1] if self._p else ""
        if name == "auth":
            return True
        if name in NOT_A_CALL:
            return None
        if self._p == ("get",) or name == "get_text":
            return ([], 200)
        if name == "create_request":      # the SDK's raw request builder: the method decides
            method = str(args[0] if args else kwargs.get("method", "")).upper()
            if method == "GET":
                return (None, {"message": "recording fake: no HTTP"})
        if self._p == ("post",) and args and str(args[0]).split("?", 1)[0] in READ_ONLY_POSTS:
            return ([], 200)
        if READ_NAME.search(name) or tuple(self._p[-3:]) in READ_CALLS:
            return ([], None, None)
        self._w.append(".".join(self._p))
        return (None, None, {"message": "recording fake: writes are refused"})

    def __iter__(self):
        return iter(())

    def __bool__(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# The world each test runs in: isolated stores, SSO with a writer list,
# write mode under the test's control, the recording client, stubbed sinks
# ---------------------------------------------------------------------------

CREDS = {"cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-123", "client_secret": "not-a-real-secret"}
SCOPE = {"scopes": ["dlp", "zia_extras", "zpa"],
         "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "cloud_app_control", "ssl_inspection")},
         "from_page": True}
ASSESSOR = "Jane Doe"
PACK = "cjis_policy_pack"
HASH = "a" * 64
DELETE_PHRASE = "DELETE 1 OBJECTS"   # the typed phrase of a removal (its number is checked against the re-made plan, a stubbed sink here)
WRITER = {"sub": "w-1", "email": "writer@example.com", "groups": ["dlp-writers"]}
WRITER_2 = {"sub": "w-2", "email": "second@example.com", "groups": ["dlp-writers"]}
READER = {"sub": "r-1", "email": "reader@example.com", "groups": ["dlp-readers"]}

# (module, function, index of the dry_run argument or None)
SINKS = [
    ("pack_deploy", "apply", None), ("pack_deploy", "undo", None),
    ("pack_removal", "remove", None), ("pack_removal", "remove_selected", None), ("pack_removal", "remove_deployment", None),
    ("proposal_apply", "apply", None), ("proposal_apply", "rollback", None),
    ("admin_ops", "execute", None), ("pov_build", "execute", None),
    ("remediation", "execute", 3),
    ("rule_migrator", "enable_evaluate_all_rules", 1), ("rule_migrator", "delete_all_rules", 1),
    ("rule_migrator", "post_new_rule_order", 2),
    ("zdx_insights", "start_analysis", None), ("zdx_insights", "stop_analysis", None),
]


class World:
    def __init__(self, monkeypatch, tmp_path):
        self.mp, self.tmp = monkeypatch, tmp_path
        self.writes: List[str] = []
        self.sinks: List[str] = []
        self.built: List[str] = []

    # the gates
    def write_mode(self, on: bool) -> None:
        self.mp.setattr(security, "_write_override", bool(on))

    def client(self, who: Optional[Dict[str, Any]] = WRITER, origin: str = "") -> TestClient:
        c = TestClient(srv.app)
        if who is not None:
            c.cookies.set(security.SSO_SESSION_COOKIE, sso.create_session(dict(who)))
        if origin:
            c.headers["Origin"] = origin
        return c

    def tenant_key(self) -> str:
        return srv._cq_tenant(self.creds())[0]

    def creds(self) -> Dict[str, str]:
        return srv._tenant_creds(SimpleNamespace(**CREDS))

    def touched(self) -> List[str]:
        return self.writes + [f"sink:{s}" for s in self.sinks]


def _sink_stub(world: World, mod: str, fn: str, dry_idx: Optional[int]) -> Callable:
    def stub(client: Any, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        dry = kwargs.get("dry_run", args[dry_idx - 1] if dry_idx is not None and len(args) >= dry_idx else False)
        if dry_idx is not None and dry:
            return {"status": "dry_run"}
        world.sinks.append(f"{mod}.{fn}")
        client.zia.write_probe.add_object(f"{mod}.{fn}")   # recorded by the fake client: a write reached the tenant
        return {"status": "applied", "ok": True, "complete": True, "summary": {}, "results": [], "logs": [],
                "verification": {"clean": True}}
    return stub


@pytest.fixture
def world(monkeypatch, tmp_path):
    w = World(monkeypatch, tmp_path)
    for env, name in (("DLP_CHECK_DEPLOYMENTS", "deployments.json"), ("DLPCHECK_PROPOSALS_FILE", "proposals.json"),
                      ("DLPCHECK_CHANGE_QUEUE_FILE", "change_requests.json"), ("DLP_CHECK_PROFILES", "tenant_profiles.json"),
                      ("DLP_CHECK_SELF_HEAL_STATE", "self_heal.json"), ("DLP_CHECK_WORKSPACE_NOTES", "notes.json"),
                      ("DLP_CHECK_DIGESTS", "digests"), ("DLP_CHECK_GUIDANCE_STATE", "guidance.json"),
                      ("DLP_CHECK_CHECKS_CONFIG", "checks_config.json"), ("DLP_CHECK_SAAS_MATRIX", "saas.json"),
                      ("DLP_CHECK_USER_PACKS", "user_packs"), ("DLP_CHECK_BEACON_STATE", "beacon.json"),
                      ("DLP_CHECK_UI_TOKEN_DIR", "token")):
        monkeypatch.setenv(env, str(tmp_path / name))
    for env in ("ENABLE_WRITE_ACTIONS", "DLP_CHECK_FOUR_EYES", "DLP_CHECK_SELF_HEAL_AUTO_APPLY", "DLP_CHECK_SMTP_HOST",
                "DLP_CHECK_DIGEST_TO", "DLP_CHECK_DIGEST_WEBHOOK", "DLP_CHECK_NOTIFY", "ZSCALER_CLIENT_ID", "ZSCALER_CLIENT_SECRET",
                "ZSCALER_VANITY_DOMAIN", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY", "DLP_CHECK_EXTENSION_ID"):
        monkeypatch.delenv(env, raising=False)
    monkeypatch.setenv("DLP_CHECK_SAAS_MATRIX_REFRESH", "0")
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    # SSO on, with a writer list: the "writer" gate is real, per person.
    monkeypatch.setenv("ZSCALER_UI_AUTH", "1")
    monkeypatch.setattr(security, "_ui_token", None)
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "1")
    monkeypatch.setenv("ZSCALER_SSO_ISSUER", "https://idp.example.test/oauth2/default")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_ID", "client-123")
    monkeypatch.setenv("ZSCALER_SSO_CLIENT_SECRET", "not-a-real-secret")
    monkeypatch.setenv("ZSCALER_SSO_REDIRECT_URL", "http://testserver/api/auth/sso/callback")
    monkeypatch.setenv("ZSCALER_SSO_WRITERS", "dlp-writers")
    monkeypatch.setattr(sso, "_SESSIONS", {})
    w.write_mode(False)
    # Never a real tenant, a real file on this machine's tenant_config.json, or the network.
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: w.built.append("sdk") or Recorder(w.writes))
    monkeypatch.setattr(srv, "_raw_client", lambda creds: w.built.append("raw") or Recorder(w.writes))
    monkeypatch.setattr(srv, "_APP_DIR", str(tmp_path))
    import pack_jobs
    real_start = pack_jobs.start

    def start_and_finish(*a, **k):
        job = real_start(*a, **k)
        job.thread.join(20)    # the job's work is part of the request under test
        return job
    monkeypatch.setattr(pack_jobs, "start", start_and_finish)
    for mod, fn, dry_idx in SINKS:
        monkeypatch.setattr(__import__(mod), fn, _sink_stub(w, mod, fn, dry_idx))
    return w


# ---------------------------------------------------------------------------
# Arrange helpers for routes that act on a stored record
# ---------------------------------------------------------------------------

def _deployment(world: World) -> str:
    import deployments
    creds = world.creds()
    rec = deployments.from_apply({"results": [{"kind": "dictionary", "name": "QA Dict", "id": 9001, "status": "created"}]},
                                 tenant_label=tenant_auth.record_label(creds), packs=[PACK], options={}, by=ASSESSOR,
                                 **srv._record_ids(creds))
    deployments.add(rec)
    return rec["id"]


def _approved_request(world: World, kind: str) -> str:
    import change_queue
    tk, label = srv._cq_tenant(world.creds())
    payload = {"pack_deploy": {"pack_ids": [PACK], "use_rank_0": False, "apply_tweaks": True, "restore_drift": False, "verify": True,
                               "channel_targets": {}},
               "pack_removal": {"rules": [{"channel": "web", "id": 1}]},
               "fix_recipe": {"check_id": "FW-01", "recipe": "FW-01", "criteria": {}}}[kind]
    plan_hash = HASH
    if kind == "fix_recipe":
        import remediation
        world.mp.setattr(remediation, "plan", lambda check_id, criteria: {"ok": True, "method": "POST", "endpoint": "/zia/x", "body": {}})
        plan_hash = change_queue.recipe_plan_hash("FW-01", remediation.plan("FW-01", {}))
    rec = change_queue.file_request(kind=kind, tenant=tk, tenant_label=label, title="QA", summary={}, items=[{"kind": "x"}],
                                    plan_hash=plan_hash, requested_by=WRITER_2["email"], payload=payload)
    change_queue.decide(rec["id"], "approve", by=WRITER["email"])
    if kind == "pack_deploy":   # the preflight the apply re-runs is the sink stub's business
        world.mp.setattr(srv, "_cq_cached", lambda *a, **k: None)
    return rec["id"]


def _heal_proposal(world: World) -> str:
    import proposals
    tk = world.tenant_key()
    pid = proposals.proposal_id(tk, "heal_drift", "heal:policy:web:QA-Rule:state")
    proposals.merge(tk, [{"id": pid, "tenant": tk, "kind": "heal_drift", "target": "heal:policy:web:QA-Rule:state", "title": "QA",
                          "change": {"apply": "rule", "rule_id": 7100, "channel": "web", "field": "state", "from": "DISABLED", "to": "ENABLED"},
                          "gate": proposals.GATES["heal_drift"], "channel": "web"}], source="self_heal")
    return pid


def _proposal_tenant(world: World) -> str:
    import proposals
    import tenant_fingerprint
    return proposals.tenant_key(tenant_fingerprint.proposal_key(world.creds(), ""))


def _pov_with_build(world: World) -> Tuple[str, str]:
    """A tenant profile for CREDS' tenant with a POV, and on it a build whose
    one part is a recorded bulk change with an Undo: (profile id, build id)."""
    import deployments
    import pov
    import tenant_profiles
    creds = world.creds()
    pid = tenant_profiles.upsert({"name": "Acme", "cloud": CREDS["cloud"], "vanity_domain": CREDS["vanity_domain"], "client_id": CREDS["client_id"]},
                                 client_secret=CREDS["client_secret"], remember_secret=True)["id"]
    pov.create(pid, None, {"customer": "Acme", "vertical": "general"}, by=ASSESSOR)
    op = {"id": deployments.new_operation_id(), "at": deployments._now(), "tenant_label": tenant_auth.record_label(creds), "by": ASSESSOR,
          "type": "rule_state", "title": "QA", "product": "zia", "spec": OPERATION, "plan_hash": HASH, "status": "applied", "counts": {},
          "created": [], "items": [], "inverse": dict(OPERATION, value="ENABLED"), "undo_of": None, "undone_by": None, "undone_at": None,
          **srv._record_ids(creds)}
    deployments.add_operation(op)
    bid = pov.new_build_id()
    pov.add_build(pid, None, {"id": bid, "at": "2026-10-31T00:00:00+00:00", "by": ASSESSOR, "plan_hash": HASH, "status": "applied",
                              "steps": [{"key": "zia_baseline", "label": "ZIA security baseline", "status": "applied", "operation_id": op["id"]}]},
                  by=ASSESSOR)
    return pid, bid


def _pov_build_body(world: World, undo: bool = False) -> Dict[str, Any]:
    pid, bid = _pov_with_build(world)
    body = dict(_b(**SCOPE), profile_id=pid, plan_hash=HASH, confirm=True, confirm_text="APPLY 1 POV CHANGE")
    if undo:
        return dict(body, build_id=bid)
    return dict(body, parts={"zia_baseline": {"type": "zia_baseline", "tier": "balanced", "prefix": "QA", "areas": ["url"]}})


# ---------------------------------------------------------------------------
# The routes that can change a tenant, with every gate satisfied
# ---------------------------------------------------------------------------

BOOL = "bool"          # confirm must be true
PHRASE = "I UNDERSTAND"

# Each: (case id, method, route path, arrange(world) -> (url, body), confirmation kind)
WriteCase = Tuple[str, str, str, Callable[[World], Tuple[str, Dict[str, Any]]], str]


def _b(**extra) -> Dict[str, Any]:
    return dict(CREDS, assessor=ASSESSOR, **extra)


OPERATION = {"type": "rule_state", "value": "DISABLED", "targets": [{"policy": "url_filtering", "id": 101}]}
ZCC_SCOPE = {"scopes": ["zcc"], "channels": {}, "from_page": True}
ZCC_BUILD = {"type": "zcc_profile_build", "platform": "windows", "forwarding": {"template": "best_practice", "name": "QA fwd"},
             "app": {"template": "best_practice", "name": "QA app"}}
ZCC_DELETE = {"type": "zcc_profile_delete", "targets": [{"kind": "forwarding", "id": "1", "name": "QA"}]}
ZDX_SCOPE = {"scopes": ["zdx"], "channels": {}, "from_page": True}

WRITE_CASES: List[WriteCase] = [
    ("deploy", "POST", "/api/dlp-packs/apply",
     lambda w: ("/api/dlp-packs/apply", _b(pack_ids=[PACK], plan_hash=HASH, confirm=True)), BOOL),
    ("deploy-job", "POST", "/api/dlp-packs/apply/start",
     lambda w: ("/api/dlp-packs/apply/start", _b(pack_ids=[PACK], plan_hash=HASH, confirm=True)), BOOL),
    ("import", "POST", "/api/dlp-packs/{pack_id}/import",
     lambda w: (f"/api/dlp-packs/{PACK}/import", _b(plan_hash=HASH, confirm=True)), BOOL),
    ("undo-deployment", "POST", "/api/deployments/{dep_id}/undo",
     lambda w: (f"/api/deployments/{_deployment(w)}/undo", _b(confirm=True)), BOOL),
    ("removal", "POST", "/api/dlp-packs/removal/apply",
     lambda w: ("/api/dlp-packs/removal/apply", _b(pack_ids=[PACK], plan_hash=HASH, confirm=True, confirm_phrase=DELETE_PHRASE)), BOOL),
    ("removal-job", "POST", "/api/dlp-packs/removal/apply/start",
     lambda w: ("/api/dlp-packs/removal/apply/start", _b(pack_ids=[PACK], plan_hash=HASH, confirm=True, confirm_phrase=DELETE_PHRASE)), BOOL),
    ("removal-undo-deployment", "POST", "/api/dlp-packs/removal/apply",
     lambda w: ("/api/dlp-packs/removal/apply", _b(deployment_id=_deployment(w), plan_hash=HASH, confirm=True, confirm_phrase=DELETE_PHRASE)), BOOL),
    ("proposal-apply", "POST", "/api/proposals/{tenant}/{pid}/apply",
     lambda w: (f"/api/proposals/{_proposal_tenant(w)}/p-1/apply", _b(confirm=True)), BOOL),
    ("proposal-rollback", "POST", "/api/proposals/{tenant}/{pid}/rollback",
     lambda w: (f"/api/proposals/{_proposal_tenant(w)}/p-1/rollback", _b(confirm=True)), BOOL),
    ("queue-apply-deploy", "POST", "/api/change-queue/{rid}/apply",
     lambda w: (f"/api/change-queue/{_approved_request(w, 'pack_deploy')}/apply", _b(confirm=PHRASE)), PHRASE),
    ("queue-apply-removal", "POST", "/api/change-queue/{rid}/apply",
     lambda w: (f"/api/change-queue/{_approved_request(w, 'pack_removal')}/apply", _b(confirm=PHRASE)), PHRASE),
    ("queue-apply-recipe", "POST", "/api/change-queue/{rid}/apply",
     lambda w: (f"/api/change-queue/{_approved_request(w, 'fix_recipe')}/apply",
                _b(confirm=PHRASE, scopes=["zia_extras"], channels={}, from_page=True)), PHRASE),
    ("bulk-apply", "POST", "/api/operations/apply",
     lambda w: ("/api/operations/apply", dict(_b(**SCOPE), operation=OPERATION, plan_hash=HASH, confirm=True)), BOOL),
    ("bulk-apply-job", "POST", "/api/operations/apply/start",
     lambda w: ("/api/operations/apply/start", dict(_b(**SCOPE), operation=OPERATION, plan_hash=HASH, confirm=True)), BOOL),
    ("bulk-apply-zcc-build", "POST", "/api/operations/apply",
     lambda w: ("/api/operations/apply", dict(_b(**ZCC_SCOPE), operation=ZCC_BUILD, plan_hash=HASH, confirm=True, confirm_text="CREATE QA APP")),
     BOOL),
    ("bulk-apply-zcc-delete", "POST", "/api/operations/apply/start",
     lambda w: ("/api/operations/apply/start", dict(_b(**ZCC_SCOPE), operation=ZCC_DELETE, plan_hash=HASH, confirm=True, confirm_text="QA")),
     BOOL),
    ("bulk-apply-aiguard", "POST", "/api/operations/apply",
     lambda w: ("/api/operations/apply", dict(_b(**dict(SCOPE, scopes=SCOPE["scopes"] + ["aiguard"])),
                                              operation={"type": "aiguard_detection_policy", "profile": "HIPAA"}, plan_hash=HASH, confirm=True)), BOOL),
    ("pov-build-apply", "POST", "/api/pov/build/apply/start",
     lambda w: ("/api/pov/build/apply/start", _pov_build_body(w)), BOOL),
    ("pov-build-undo", "POST", "/api/pov/build/undo/apply/start",
     lambda w: ("/api/pov/build/undo/apply/start", _pov_build_body(w, undo=True)), BOOL),
    ("self-heal", "POST", "/api/self-heal/tenant/heal",
     lambda w: ("/api/self-heal/tenant/heal", dict(_b(**SCOPE), ids=[_heal_proposal(w)], confirm=PHRASE)), PHRASE),
    ("remediation", "POST", "/api/remediation/execute",
     lambda w: ("/api/remediation/execute", _b(check_id="FW-01", criteria={}, dry_run=False, confirm=True, plan_hash=HASH,
                                             scopes=["zia_extras"], channels={}, from_page=True)), BOOL),
    ("migrate-enable", "POST", "/api/migrate/enable",
     lambda w: ("/api/migrate/enable", dict(_b(**SCOPE), dry_run=False, confirm=True, plan_hash=HASH)), BOOL),
    ("migrate-delete-all", "POST", "/api/migrate/delete-all",
     lambda w: ("/api/migrate/delete-all", dict(_b(**SCOPE), dry_run=False, confirm=True, plan_hash=HASH, confirm_phrase="DELETE 1 RULES")), BOOL),
    ("zdx-analysis-start", "POST", "/api/zdx/analysis/start",
     lambda w: ("/api/zdx/analysis/start", _b(**ZDX_SCOPE, app_id="3002", confirm=True, confirm_text="START ANALYSIS")), BOOL),
    ("zdx-analysis-stop", "POST", "/api/zdx/analysis/stop",
     lambda w: ("/api/zdx/analysis/stop", _b(**ZDX_SCOPE, analysis_id="90001", confirm=True)), BOOL),
    ("migrate-post", "POST", "/api/migrate/post",
     lambda w: ("/api/migrate/post", dict(_b(**SCOPE), dry_run=False, confirm=True, mode="update", plan_hash=HASH,
                                          proposed_rules=[{"id": 1, "name": "QA rule"}])), BOOL),
]

# Routes that never change a tenant (they may write the app's own files),
# with why. A new state-changing route must be added to one of the tables.
READ_ONLY: Dict[Tuple[str, str], str] = {
    ("POST", "/api/auth/team/login"): "signs in to the team server: team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/me/password"): "changes your own password in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/users"): "adds an account to the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/users/{user_id}"): "changes an account in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("DELETE", "/api/team/users/{user_id}"): "deletes an account from the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/users/{user_id}/password"): "sets an account's password in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/users/{user_id}/unlock"): "unlocks an account in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/grants"): "gives or takes per-tenant-profile access in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/scim-token"): "makes the SCIM bearer token (stored hashed) in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("DELETE", "/api/team/scim-token"): "revokes the SCIM bearer token in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/store-key/rotate"): "re-encrypts the app's own local stores with a new key (store_crypto.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/team/share"): "shares a template or saved plan in the team server account store (team_server.py), never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/scim/v2/Users"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("PUT", "/api/scim/v2/Users/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("PATCH", "/api/scim/v2/Users/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("DELETE", "/api/scim/v2/Users/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/scim/v2/Groups"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("PUT", "/api/scim/v2/Groups/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("PATCH", "/api/scim/v2/Groups/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("DELETE", "/api/scim/v2/Groups/{scim_id}"): "SCIM provisioning of team server accounts and groups, never a tenant; 404 unless ZSCALER_TEAM_MODE",
    ("POST", "/api/offline/sample"): "uses the in-memory sample tenant in this browser (offline_tenant): no tenant is reached",
    ("POST", "/api/offline/leave"): "back to the live tenant in this browser: clears a cookie",
    ("POST", "/api/tenant-profiles/snapshots/open-file"): "opens an uploaded snapshot offline and read-only",
    ("POST", "/api/tenant-profiles/snapshots/{snapshot_id}/open"): "opens a saved snapshot offline and read-only",
    ("POST", "/api/tenant-profiles/snapshots/{snapshot_id}/delete"): "deletes a local snapshot file, never anything in a tenant",
    ("POST", "/api/tenant-profiles/snapshots/save/start"): "a scoped tenant read (GETs and the two read-only Workflow Automation searches) kept in a local file",
    ("POST", "/api/zwa/incident"): "reads one incident's metadata (details, triggers, history, tickets); never the evidence",
    ("POST", "/api/zwa/audit-log"): "reads the Workflow Automation audit log (a search POST that changes nothing)",
    ("POST", "/api/aiguard/inventory"): "reads AI Guard's policies, rules, providers, applications and credential names",
    ("POST", "/api/aiguard/test-prompt"): "sends one synthetic catalogue prompt to AI Guard's policy detection; changes no configuration",
    ("POST", "/api/tenant-profiles/snapshots/compare/start"): "a GET-only, scoped tenant read compared with a snapshot",
    ("POST", "/api/config-backups/save/start"): "a GET-only, scoped configuration read kept in a local owner-only file (config_backup)",
    ("POST", "/api/config-cache/refresh/start"): "a GET-only, scoped configuration read kept in the local cache",
    ("POST", "/api/config-backups/from-snapshot"): "reads a saved snapshot or the sample through the offline client: no tenant is reached",
    ("POST", "/api/config-backups/{backup_id}/delete"): "deletes a local backup file, never anything in a tenant",
    ("POST", "/api/config-backups/diff"): "compares two saved files; no tenant is read",
    ("POST", "/api/config-backups/diff-live/start"): "a GET-only, scoped tenant read compared with a backup",
    ("POST", "/api/config-backups/schedule"): "a local schedule of read-only backups; nothing is ever applied by it",
    ("POST", "/api/config-backups/rehearse"): "plans against a saved copy; builds no client and writes nothing",
    ("POST", "/api/config-templates/export"): "makes a local template file from a backup",
    ("POST", "/api/config-templates/import"): "keeps an uploaded template file (checked as untrusted)",
    ("POST", "/api/config-templates/{template_id}/delete"): "deletes a local template file, never anything in a tenant",
    ("POST", "/api/auth/unlock"): "session sign-in",
    ("POST", "/api/auth/logout"): "session sign-out",
    ("POST", "/api/remediation/plan"): "builds a plan, sends nothing",
    ("POST", "/api/diagnose/zcc"): "GET probes",
    ("POST", "/api/best-practices/crawl"): "public documentation crawl",
    ("POST", "/api/dlp-packs/{pack_id}/from-tenant"): "reads the tenant, writes a local pack",
    ("POST", "/api/dlp-packs/preflight"): "preview",
    ("POST", "/api/detection-health"): "reads incidents",
    ("POST", "/api/live-feed"): "reads incidents",
    ("POST", "/api/change-queue/deploy"): "files a request (local)",
    ("POST", "/api/change-queue/removal"): "files a request (local)",
    ("POST", "/api/change-queue/recipe"): "files a request (local)",
    ("POST", "/api/change-queue/{rid}/approve"): "decision (local), four-eyes",
    ("POST", "/api/change-queue/{rid}/reject"): "decision (local)",
    ("POST", "/api/change-queue/{rid}/withdraw"): "decision (local)",
    ("POST", "/api/change-queue/{rid}/comment"): "comment (local)",
    ("POST", "/api/proposals/{tenant}/{pid}/decide"): "decision (local)",
    ("POST", "/api/proposals/{tenant}/{pid}/preview"): "preview",
    ("POST", "/api/digests/run"): "continuous evaluation (reads)",
    ("POST", "/api/zpa/analysis/start"): "reads",
    ("POST", "/api/zpa/diagnose"): "reads",
    ("POST", "/api/browser-security/start"): "reads",
    ("POST", "/api/ztw/start"): "reads the Cloud & Branch Connector configuration (list and get calls only); no write method is called",
    ("POST", "/api/other-products/start"): "reads",
    ("POST", "/api/device-posture/start"): "reads",
    ("POST", "/api/rate-check"): "local forecast",
    ("POST", "/api/dlp-packs/removal/preflight"): "preview",
    ("POST", "/api/dlp-packs/removal/inventory"): "reads",
    ("POST", "/api/dlp-packs/jobs/stop-before-start"): "Stop",
    ("POST", "/api/dlp-packs/jobs/{job_id}/cancel"): "Stop",
    ("POST", "/api/tenant/check"): "sign-in check",
    ("POST", "/api/write-mode"): "the write-mode gate itself (tested on its own)",
    ("POST", "/api/tenant-profiles"): "local profile",
    ("DELETE", "/api/tenant-profiles/{profile_id}"): "local profile",
    ("POST", "/api/dlp-packs/baseline-status"): "reads",
    ("POST", "/api/dlp-packs/journey"): "reads",
    ("POST", "/api/dlp-packs/terraform"): "Terraform files",
    ("POST", "/api/dlp-packs/terraform/start"): "Terraform files",
    ("POST", "/api/dlp-packs/export/start"): "reads (extension allow-list)",
    ("POST", "/api/dlp-packs/{pack_id}/verify"): "reads",
    ("POST", "/api/dlp-packs/upload"): "local pack library",
    ("POST", "/api/pack-library/preview"): "local pack library",
    ("POST", "/api/pack-library/upload"): "local pack library",
    ("POST", "/api/report/xlsx"): "report file",
    ("POST", "/api/dlp-packs/inventory/start"): "reads",
    ("POST", "/api/exports/policies/start"): "reads",
    ("POST", "/api/exports/urls/start"): "reads",
    ("POST", "/api/exports/url-categories/analyze/start"): "reads",
    ("POST", "/api/exports/locations/start"): "reads",
    ("POST", "/api/exports/client-connector/start"): "reads",
    ("POST", "/api/pack-library/{pack_id}/remove"): "local pack library",
    ("POST", "/api/operations/objects/start"): "reads",
    ("POST", "/api/operations/objects"): "reads",
    ("POST", "/api/operations/preview/start"): "preview",
    ("POST", "/api/operations/preview"): "preview",
    ("POST", "/api/pov/build/defaults"): "local: the parts an intake suggests",
    ("POST", "/api/pov/build/preview/start"): "preview",
    ("POST", "/api/pov/build/preview"): "preview",
    ("POST", "/api/pov/build/undo/preview/start"): "preview",
    ("POST", "/api/operations/{op_id}/undo/preview/start"): "preview",
    ("POST", "/api/operations/{op_id}/undo/preview"): "preview",
    ("POST", "/api/operations/zpa/provisioning-key"): "reveals once a value held in this app's memory; reaches no tenant",
    ("POST", "/api/operations/zidentity/secret"): "reveals once a value held in this app's memory; reaches no tenant",
    # Day-to-day admin (ops_zcc_admin, ops_zdx_trace, ops_zpa_admin): searches, a bounded read-only follow, and the
    # one place a Browser Access key enters the app (held in memory for the next previewed operation; writers only).
    ("POST", "/api/operations/lookup"): "reads (a Client Connector or ZDX search for a form)",
    ("POST", "/api/operations/zdx/deeptrace/follow/start"): "reads (follows a ZDX deep trace, bounded)",
    ("POST", "/api/operations/zpa/ba-certificate"): "holds an uploaded certificate and key in this app's memory; reaches no tenant",
    # Rules from a spreadsheet and scheduled sync (rule_csv, ops_rule_csv, sync_jobs): the import itself is an
    # operation type on the engine (WRITE path); a sync job only reads and files plans in the change queue.
    ("POST", "/api/rule-csv/validate"): "checks a file; reads no tenant",
    ("POST", "/api/rule-csv/export"): "reads",
    ("POST", "/api/sync-jobs"): "a sync job (local): it only reads and files plans for approval",
    ("DELETE", "/api/sync-jobs/{jid}"): "a sync job (local)",
    ("POST", "/api/sync-jobs/{jid}/enabled"): "a sync job's schedule (local)",
    ("POST", "/api/sync-jobs/{jid}/run"): "reads source and targets, files plans in the change queue (local); never writes a tenant",
    ("POST", "/api/path-analyzer/zpa-identity"): "reads (ZPA IdPs, SAML attributes, one SCIM user's groups)",
    ("POST", "/api/tenant-terraform/start"): "reads the tenant into Terraform files (tenant_terraform); writes nothing",
    ("POST", "/api/zcc/fleet/import"): "reads uploaded Client Connector Portal exports (no tenant call)",
    ("POST", "/api/zcc/fleet/{job_id}/sites"): "groups a finished fleet read into sites (no tenant call)",
    ("POST", "/api/zcc/fleet/{job_id}/history"): "keeps a counts-only snapshot of a fleet read (local file)",
    ("POST", "/api/zcc/fleet/history/forget"): "forgets the local fleet history (no tenant)",
    ("POST", "/api/traffic-logs/analyze"): "reads uploaded traffic and session logs (no tenant call)",
    ("POST", "/api/tenant-health/start"): "reads (tenant health checks)",
    ("DELETE", "/api/traffic-logs/report/{report_id}"): "forgets a traffic log report held in memory (no tenant)",
    ("POST", "/api/traffic-logs/report/{report_id}/save"): "keeps a traffic log report as a local file (no tenant)",
    ("POST", "/api/traffic-logs/saved/{saved_name}/open"): "opens a saved traffic log report (local file)",
    ("DELETE", "/api/traffic-logs/saved/{saved_name}"): "deletes a saved traffic log report (local file)",
    ("POST", "/api/console-index"): "reads (extension allow-list)",
    ("POST", "/api/workspace/notes"): "local notes",
    ("DELETE", "/api/workspace/notes"): "local notes",
    ("POST", "/api/beacon/run"): "GET-only probe",
    ("POST", "/api/beacon/stop"): "Stop",
    ("POST", "/api/beacon/scope"): "preview",
    ("POST", "/api/insights/start"): "reads",
    ("POST", "/api/insights"): "reads",
    ("POST", "/api/pov/open"): "local POV",
    ("POST", "/api/pov/create"): "local POV",
    ("POST", "/api/pov/update"): "local POV",
    ("POST", "/api/pov/delete"): "local POV",
    ("POST", "/api/pov/export"): "local POV file",
    ("POST", "/api/pov/import"): "local POV (uploaded file)",
    ("POST", "/api/pov/report"): "report",
    ("POST", "/api/pov/templates"): "local POV template",
    ("DELETE", "/api/pov/templates/{template_id}"): "local POV template",
    ("POST", "/api/pov/prove/start"): "reads",
    ("POST", "/api/pov/insights/start"): "reads",
    ("POST", "/api/app/update"): "the app's own install (stubbed here)",
    ("POST", "/api/app/restart"): "the app's own process (stubbed here)",
    ("POST", "/api/compliance"): "report",
    ("POST", "/api/compliance/drilldown"): "report",
    ("POST", "/api/compliance/report"): "report",
    ("POST", "/api/compliance/profile-view"): "report",
    ("POST", "/api/compliance-pack"): "local files from the posted build; reads and writes no tenant",
    ("POST", "/api/compliance-pack/file"): "local files from the posted build; reads and writes no tenant",
    ("POST", "/api/compliance-profiles/choice"): "the local tenant profile store only; never a tenant",
    ("POST", "/api/logs/analyze"): "uploaded logs",
    ("POST", "/api/vendor-migrate/inventory"): "uploaded export",
    ("POST", "/api/vendor-migrate/compile"): "uploaded export",
    ("POST", "/api/vendor-migrate/workspace"): "Terraform files",
    ("POST", "/api/vendor-migrate/panos/plan"): "uploaded export (a plan; Bulk changes applies it)",
    ("POST", "/api/benchmarks"): "report",
    ("POST", "/api/benchmarks/export"): "report",
    ("POST", "/api/dlp/efficacy"): "reads",
    ("POST", "/api/dlp/efficacy/export"): "report",
    ("POST", "/api/dlp/efficacy/test"): "reads",
    ("POST", "/api/migrate/status"): "reads",
    ("POST", "/api/migrate/status/manual"): "reads",
    ("POST", "/api/migrate/fetch"): "reads",
    ("POST", "/api/migrate/optimize"): "local plan",
    ("POST", "/api/migrate/upload"): "local plan",
    ("POST", "/api/migrate/reorder"): "local plan",
    ("POST", "/api/migrate/analyze"): "local plan",
    ("POST", "/api/migrate/plan"): "local plan",
    ("POST", "/api/migrate/export"): "local plan",
    ("POST", "/api/assess"): "the assessment (reads)",
    ("POST", "/api/report/docx"): "report",
    ("POST", "/api/report/findings-csv"): "report",
    ("POST", "/api/zcc/fleet/start"): "reads",
    ("POST", "/api/zcc/install"): "builds an install command; with app_profile_id it reads that profile's policy token (scope-gated)",
    ("POST", "/api/zcc/otp"): "reads one device's one-time passwords (scope-gated, writer, assessor, typed phrase, rate-limited; tests/test_zcc_otp.py); writes nothing",
    ("POST", "/api/zcc/device-details"): "reads one device's service state (scope-gated)",
    ("POST", "/api/zcc/disable-reasons"): "reads the disable-reason report and counts it (scope-gated)",
    ("POST", "/api/zdx/cloudpath"): "reads ZDX applications and one measured cloud path (scope-gated)",
    ("POST", "/api/zdx/analysis/status"): "reads a ZDX score analysis back (scope-gated)",
    ("POST", "/api/readiness/start"): "reads (the API role, licences and one call per product in scope)",
    ("POST", "/api/report/bypass"): "reads",
    ("POST", "/api/report/data-flow"): "reads",
    ("POST", "/api/path-analyzer/batch/start"): "reads",
    ("POST", "/api/bulk-test/start"): "reads (Test a list)",
    ("POST", "/api/bulk-test/{job_id}/fix"): "hand-off to Bulk changes (local), writes nothing",
    ("POST", "/api/category-lookup/start"): "reads (Category lookup)",
    ("POST", "/api/bulk-test/fix/{fix_id}/prove/start"): "reads (Prove it: the handed-off rows tested again)",
    ("POST", "/api/audit-timeline/start"): "reads",
    ("POST", "/api/shadow-rules/start"): "reads",
    ("POST", "/api/shadow-rules"): "reads",
    ("POST", "/api/posture/analyze"): "reads",
    ("POST", "/api/posture/project"): "local projection",
    ("POST", "/api/posture/summary"): "reads",
    ("PUT", "/api/posture/settings"): "local settings",
    ("PUT", "/api/m365-endpoints/settings"): "local setting: may this app fetch Microsoft's Microsoft 365 endpoint list (no tenant)",
    ("POST", "/api/m365-endpoints/refresh"): "fetches Microsoft's public endpoint list into a local file (no tenant)",
    ("POST", "/api/m365-endpoints/import"): "keeps an uploaded Microsoft 365 endpoint list as a local file (no tenant)",
    ("DELETE", "/api/m365-endpoints"): "forgets the local Microsoft 365 endpoint list (no tenant)",
    ("PUT", "/api/app/update/notify"): "local settings",
    ("PUT", "/api/plugins/settings"): "local settings",
    ("POST", "/api/plugins/approve"): "local plugin allow-list",
    ("POST", "/api/plugins/revoke"): "local plugin allow-list",
    ("POST", "/api/zcc/fleet/{job_id}/dns-records"): "builds DNS text from a finished fleet read (no tenant call)",
    ("PUT", "/api/zscaler-ranges/settings"): "local setting: may this app fetch Zscaler's published IP ranges (no tenant)",
    ("POST", "/api/zscaler-ranges/fetch"): "fetches Zscaler's public IP range feeds into local files (no tenant)",
    ("POST", "/api/zscaler-ranges/import"): "keeps an uploaded IP range feed as a local file (no tenant)",
    ("DELETE", "/api/zscaler-ranges"): "forgets the local IP range feeds (no tenant)",
    ("POST", "/api/zscaler-ranges/build"): "builds an allowlist from local files (no tenant)",
    ("POST", "/api/zscaler-ranges/download"): "downloads an allowlist built from local files (no tenant)",
    ("POST", "/api/self-heal/run"): "local self-healing",
    ("POST", "/api/self-heal/tenant/scan"): "reads",
    ("POST", "/api/self-heal/tenant/view"): "local",
    ("POST", "/api/self-heal/tenant/accept"): "local decision",
    ("POST", "/api/self-heal/tenant/auto-apply"): "always refused (tested on its own)",
    ("POST", "/api/flow/scenario"): "local scenario",
    ("POST", "/api/path-analyzer/start"): "reads",
    ("POST", "/api/path-analyzer"): "reads",
    ("POST", "/api/path-analyzer/identities"): "reads (one page of names)",
    ("POST", "/api/path-analyzer/devices"): "reads (one page of a user's enrolled devices)",
    ("POST", "/api/path-analyzer/devices/detail"): "reads (one device's details)",
    ("POST", "/api/path-analyzer/compare/start"): "reads (two analyses on one read)",
    ("POST", "/api/path-analyzer/test-from-here"): "no tenant call: DNS, a TCP connect and a TLS handshake from this computer (path_probe)",
    ("POST", "/api/report/data-flow/{report_id}/trace"): "reads",
    ("POST", "/api/report/ssl-flow"): "reads",
    ("POST", "/api/ssl-coverage/start"): "reads",
    ("POST", "/api/report/bypass/export"): "report",
    ("POST", "/api/updates/check"): "public update check",
    ("POST", "/api/updates/reset-cache"): "local cache",
}


def _state_changing_routes() -> List[Tuple[str, str]]:
    out = []
    for r in srv.app.routes:
        if isinstance(r, APIRoute):
            for m in sorted(r.methods - {"GET", "HEAD", "OPTIONS"}):
                out.append((m, r.path))
    return out


WRITE_ROUTES = {(m, p) for _id, m, p, _a, _c in WRITE_CASES}


def test_every_state_changing_route_is_classified():
    """ASVS V1.4.1 · CWE-862 · A01:2021: every POST/PUT/PATCH/DELETE route is either a gated tenant write or listed as read-only."""
    # Arrange
    routes = _state_changing_routes()
    # Act
    unclassified = [r for r in routes if r not in WRITE_ROUTES and r not in READ_ONLY]
    stale = [r for r in list(WRITE_ROUTES) + list(READ_ONLY) if r not in routes]
    # Assert
    assert len(routes) >= 120, len(routes)
    assert not unclassified, ("New state-changing route(s): add each to WRITE_CASES (with all four gates) or, if it can never "
                              f"change a tenant, to READ_ONLY with the reason: {unclassified}")
    assert not stale, f"Classified routes that no longer exist: {stale}"
    assert not (WRITE_ROUTES & set(READ_ONLY)), "a route is either a write or read-only"


# ---------------------------------------------------------------------------
# The four gates, table-driven over every tenant-write route
# ---------------------------------------------------------------------------

def _ids(cases):
    return [c[0] for c in cases]


@pytest.mark.parametrize("case", WRITE_CASES, ids=_ids(WRITE_CASES))
def test_every_gate_held_reaches_the_write(world, case):
    """ASVS V1.4.1 · CWE-862 · A01:2021: positive control: with every gate held, each write route reaches its write (so the refusals below are meaningful)."""
    # Arrange
    _id, method, _route, arrange, _kind = case
    world.write_mode(True)
    url, body = arrange(world)
    # Act
    r = world.client(WRITER).request(method, url, json=body)
    # Assert
    assert r.status_code == 200, r.text
    assert world.sinks, f"{url} answered 200 without reaching a write: {r.text[:300]}"
    assert world.writes and all(w.startswith("zia.write_probe.") for w in world.writes), world.writes
    assert "not-a-real-secret" not in r.text


def _drop(gate: str, kind: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """The body with one gate dropped."""
    b = dict(body)
    if gate == "assessor-blank":
        b["assessor"] = ""
    elif gate == "assessor-missing":
        b.pop("assessor", None)
    elif gate == "assessor-is-the-tool":
        b["assessor"] = "Zscaler Made Easy"
    elif gate == "confirm-missing":
        b.pop("confirm", None)
    elif gate == "confirm-false":
        b["confirm"] = False if kind == BOOL else ""
    elif gate == "confirm-wrong":
        if kind == BOOL:
            b["confirm"] = "false"
        else:
            b["confirm"] = security.WRITE_CONFIRM_PHRASE     # another phrase
    elif gate == "confirm-near-miss":        # a typed phrase only
        b["confirm"] = kind + "."
    else:
        raise ValueError(gate)
    return b


BODY_GATES = ["assessor-blank", "assessor-missing", "assessor-is-the-tool", "confirm-missing", "confirm-false", "confirm-wrong",
              "confirm-near-miss"]
ENV_GATES = ["write-mode-off", "not-a-writer", "not-signed-in"]


GATE_MATRIX = [(c, g) for c in WRITE_CASES for g in ENV_GATES + BODY_GATES if not (g == "confirm-near-miss" and c[4] == BOOL)]


@pytest.mark.parametrize("case,gate", GATE_MATRIX, ids=[f"{c[0]}-{g}" for c, g in GATE_MATRIX])
def test_dropping_any_one_gate_writes_nothing(world, case, gate):
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · CWE-841 · A01:2021: with any one gate missing a write route is refused before signing in, and nothing is written."""
    # Arrange
    _id, method, _route, arrange, kind = case
    world.write_mode(gate != "write-mode-off")
    who = {"not-a-writer": READER, "not-signed-in": None}.get(gate, WRITER)
    url, body = arrange(world)
    if gate in BODY_GATES:
        body = _drop(gate, kind, body)
    # Act
    r = world.client(who).request(method, url, json=body)
    # Assert
    assert 400 <= r.status_code < 500, (gate, url, r.status_code, r.text[:300])
    assert world.touched() == [], (gate, url, world.touched())
    assert world.built == [], f"{url} signed in to the tenant before refusing ({gate})"


# The four gates, one dropped at a time, with an offline snapshot open in the
# browser: opening one never stands in for a gate.
SNAPSHOT_GATES = ["write-mode-off", "not-a-writer", "assessor-blank", "confirm-missing"]
SNAPSHOT_MATRIX = [(c, g) for c in WRITE_CASES for g in SNAPSHOT_GATES]


@pytest.mark.parametrize("case,gate", SNAPSHOT_MATRIX, ids=[f"{c[0]}-{g}" for c, g in SNAPSHOT_MATRIX])
def test_with_a_snapshot_open_every_gate_still_refuses(world, monkeypatch, case, gate):
    """ASVS V4.1.3 · V11.1.1 · CWE-862 · CWE-441 · A01:2021: with an offline snapshot open in the browser, a write route missing any one of the four gates is refused before sign-in and nothing is written."""
    # Arrange
    import offline_tenant as ot
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    st = ot.open_document(ot.dumps(ot.build_snapshot({"/zia/api/v1/webDlpRules": {"status": 200, "body": [{"id": 1, "name": "R"}]}},
                                                     {"tenant_label": "acme (zscalerten)"})))
    _id, method, _route, arrange, kind = case
    world.write_mode(gate != "write-mode-off")
    url, body = arrange(world)
    if gate in BODY_GATES:
        body = _drop(gate, kind, body)
    client = world.client(READER if gate == "not-a-writer" else WRITER)
    client.cookies.set(ot.COOKIE, st.id)
    # Act
    r = client.request(method, url, json=body)
    # Assert
    assert 400 <= r.status_code < 500, (gate, url, r.status_code, r.text[:300])
    assert world.touched() == [] and world.built == [], (gate, url, world.touched(), world.built)
    assert st.writes == 0 and st.responses["/zia/api/v1/webDlpRules"]["body"] == [{"id": 1, "name": "R"}]


# ---------------------------------------------------------------------------
# Everything else: called with every privilege at once, writes nothing
# ---------------------------------------------------------------------------

KITCHEN_SINK = dict(CREDS, **SCOPE, assessor=ASSESSOR, confirm=True, confirm_text=PHRASE, dry_run=False, plan_hash=HASH,
                    pack_ids=[PACK], ids=["p-1"], rules=[{"channel": "web", "id": 1}], notify=False, enable=False,
                    operation=OPERATION, proposed_rules=[{"id": 1, "name": "QA rule"}], check_id="FW-01", criteria={},
                    destination="example.com", decision="approve", comment="QA", start_token="qa-token-1234567890")
PATH_VALUES = {"pack_id": PACK, "job_id": "qa-job", "rid": "cr-000000000000", "tenant": "acme", "pid": "p-1",
               "profile_id": "qa-profile", "op_id": "op-qa", "report_id": "qa-report", "dep_id": "qa-dep"}


@pytest.fixture
def no_local_side_effects(monkeypatch):
    import app_update
    import beacon
    monkeypatch.setattr(app_update, "update", lambda *a, **k: {"status": "stubbed"})
    monkeypatch.setattr(app_update, "schedule_restart", lambda *a, **k: {"status": "stubbed"})
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})
    for name in ("run", "run_once", "snapshot"):
        if hasattr(beacon, name):
            monkeypatch.setattr(beacon, name, lambda *a, **k: {"status": "stubbed"})


READ_ONLY_ROUTES = sorted(READ_ONLY)


@pytest.mark.parametrize("route", READ_ONLY_ROUTES, ids=[f"{m} {p}" for m, p in READ_ONLY_ROUTES])
def test_read_only_routes_never_write_even_with_every_privilege(world, no_local_side_effects, route):
    """ASVS V1.4.1 · V4.1.3 · CWE-284 · A01:2021: a route outside the write table writes nothing with write mode on, a writer, confirm and dry_run=false."""
    # Arrange
    method, path = route
    world.write_mode(True)
    url = re.sub(r"\{(\w+)\}", lambda m: PATH_VALUES.get(m.group(1), "x"), path)
    # Act
    world.client(WRITER).request(method, url, json=KITCHEN_SINK)
    # Assert
    assert world.writes == [] and world.sinks == [], (route, world.touched())


# ---------------------------------------------------------------------------
# Write mode itself: only a writer, only with the exact phrase
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("phrase,ok", [("YES_I_UNDERSTAND", True), (" YES_I_UNDERSTAND ", True), ("yes_i_understand", False),
                                       ("YES_I_UNDERSTAND.", False), ("", False), ("I UNDERSTAND", False)])
def test_write_mode_needs_a_writer_and_the_exact_phrase(world, phrase, ok):
    """ASVS V4.1.3 · CWE-862 · CWE-1188 · A01:2021: write mode turns on only for a writer who types the exact phrase; it is off by default."""
    # Arrange
    security._write_override = None
    assert security.writes_enabled() is False, "read-only by default"
    # Act
    reader = world.client(READER).post("/api/write-mode", json={"enable": True, "confirm": security.WRITE_CONFIRM_PHRASE})
    r = world.client(WRITER).post("/api/write-mode", json={"enable": True, "confirm": phrase})
    # Assert
    assert reader.status_code == 403
    assert (r.status_code == 200) is ok and security.writes_enabled() is ok, (phrase, r.text)


def test_write_mode_cannot_be_turned_on_from_the_browser_beyond_loopback(world, monkeypatch):
    """ASVS V4.1.3 · CWE-1188 · A04:2021: on a non-loopback bind the browser cannot switch writes on, whatever it types."""
    # Arrange
    security._write_override = None
    monkeypatch.setenv("ZSCALER_BIND_HOST", "0.0.0.0")
    # Act
    r = world.client(WRITER).post("/api/write-mode", json={"enable": True, "confirm": security.WRITE_CONFIRM_PHRASE})
    # Assert
    assert r.status_code == 403 and security.writes_enabled() is False


def test_anyone_signed_in_may_switch_writes_off(world):
    """ASVS V4.1.3 · CWE-1188 · A04:2021: switching writes off is always allowed (fail safe)."""
    # Arrange
    world.write_mode(True)
    # Act
    r = world.client(READER).post("/api/write-mode", json={"enable": False})
    # Assert
    assert r.status_code == 200 and security.writes_enabled() is False


# ---------------------------------------------------------------------------
# Self-healing never applies on its own
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("setting", ["1", "true", "yes", "on", "YES_I_UNDERSTAND"])
def test_self_heal_auto_apply_is_refused_whatever_the_setting(world, monkeypatch, setting):
    """ASVS V1.4.1 · CWE-1188 · A04:2021: DLP_CHECK_SELF_HEAL_AUTO_APPLY is refused; nothing is read or written."""
    # Arrange
    import self_heal
    monkeypatch.setenv("DLP_CHECK_SELF_HEAL_AUTO_APPLY", setting)
    world.write_mode(True)
    _heal_proposal(world)
    # Act
    r = world.client(WRITER).post("/api/self-heal/tenant/auto-apply", json=dict(CREDS, **SCOPE, assessor=ASSESSOR, confirm=PHRASE))
    run = self_heal.run("timer")
    # Assert
    assert r.status_code == 403 and "not enabled" in r.json()["detail"]
    assert self_heal.auto_apply()["applied"] == 0 and self_heal.auto_apply_setting()["enabled"] is False
    assert world.built == [] and world.touched() == [], world.touched()
    assert isinstance(run, dict)


# ---------------------------------------------------------------------------
# Continuous evaluation and Simple mode never write
# ---------------------------------------------------------------------------

def _all_channels_profile(packs=(PACK, "healthcare_phi_baseline")) -> str:
    import tenant_profiles as tp
    p = tp.upsert({"name": "Acme", "cloud": "zscalerten", "vanity_domain": "acme", "client_id": "cid-123",
                   "baseline_packs": list(packs), "assessor": ASSESSOR, "scopes": ["dlp", "zia_extras"],
                   "channels": {c: "zscaler" for c in ("web_dlp", "endpoint_dlp", "email_dlp", "saas_casb", "workflow_automation")}},
                  client_secret="not-a-real-secret", remember_secret=True)
    return p["id"]


def test_continuous_evaluation_never_writes_even_in_write_mode(world, monkeypatch):
    """ASVS V1.4.1 · CWE-284 · A04:2021: the continuous evaluation loop (and its Run now) only reads, even with write mode on."""
    # Arrange
    import continuous_eval
    monkeypatch.setattr("zscaler_best_practices.list_all", lambda service="": [])
    monkeypatch.setattr("bp_crawler.last_summary", lambda: {})
    _all_channels_profile()
    world.write_mode(True)
    # Act
    d = continuous_eval.run_once(build_client=srv._build_sdk_client, notify=False)
    r = world.client(WRITER).post("/api/digests/run", json={"notify": False})
    # Assert
    assert d["tenants"] and "sdk" in world.built, "the loop did read the tenant"
    assert r.status_code == 200, r.text
    assert world.touched() == [], world.touched()


def _simple_mode_posts() -> List[str]:
    js = open(os.path.join(ROOT, "static", "simple.js"), encoding="utf-8").read()
    found = set(re.findall(r"postJSON\(\s*['`](/api/[^'`]+)['`]", js)) | set(re.findall(r"fetch\('(/api/[^']+)', \{ method: 'POST'", js))
    for url in re.findall(r"'(/api/report/[a-z-]+)'", js):
        found.add(url)
    return sorted(u.replace("${encodeURIComponent(job)}", "qa-job") for u in found)


def test_simple_mode_posts_only_to_read_only_routes():
    """ASVS V1.4.1 · CWE-284 · A01:2021: every POST Simple mode makes is a classified read-only route, never a write route."""
    # Arrange
    posts = _simple_mode_posts()
    templates = {p: re.compile("^" + re.sub(r"\{\w+\}", "[^/]+", p) + "$") for _m, p in READ_ONLY}
    # Act
    unknown = [u for u in posts if not any(t.match(u) for t in templates.values())]
    writes = [u for u in posts for _id, _m, p, _a, _c in WRITE_CASES if re.match("^" + re.sub(r"\{\w+\}", "[^/]+", p) + "$", u)]
    # Assert
    assert len(posts) >= 6, posts
    assert unknown == [] and writes == [], (unknown, writes)


@pytest.mark.parametrize("url", _simple_mode_posts())
def test_simple_mode_calls_write_nothing_in_write_mode(world, no_local_side_effects, url):
    """ASVS V1.4.1 · CWE-284 · A01:2021: each call Simple mode makes writes nothing, even for a writer with write mode on."""
    # Arrange
    world.write_mode(True)
    pid = _all_channels_profile(packs=())      # the packs' journey read is the continuous evaluation test's
    body = {"profile_id": pid, "scopes": ["dlp"], "channels": {"web_dlp": "zscaler"}, "from_page": True, "org_name": "Acme",
            "assessor": ASSESSOR, "destination": "example.com", "start_token": "qa-token-1234567890", **CREDS}
    # Act
    world.client(WRITER).post(url, json=body)
    # Assert
    assert world.touched() == [], (url, world.touched())


# ---------------------------------------------------------------------------
# Preview never writes; undo is gated
# ---------------------------------------------------------------------------

PREVIEWS = [
    ("/api/dlp-packs/preflight", dict(CREDS, pack_ids=[PACK], assessor=ASSESSOR, confirm=True)),
    ("/api/dlp-packs/removal/preflight", dict(CREDS, pack_ids=[PACK], confirm=True)),
    (f"/api/dlp-packs/{PACK}/import", dict(CREDS, assessor=ASSESSOR, confirm=True)),          # no plan_hash: the plan only
    ("/api/operations/preview", dict(CREDS, **SCOPE, operation=OPERATION, confirm=True)),
    ("/api/remediation/execute", dict(CREDS, check_id="FW-01", criteria={}, dry_run=True, confirm=True)),
    ("/api/migrate/enable", dict(CREDS, **SCOPE, dry_run=True, confirm=True)),
    ("/api/migrate/delete-all", dict(CREDS, **SCOPE, dry_run=True, confirm=True)),
    ("/api/migrate/post", dict(CREDS, **SCOPE, dry_run=True, confirm=True, proposed_rules=[{"id": 1, "name": "QA rule"}])),
    (f"/api/dlp-packs/{PACK}/from-tenant", dict(CREDS, confirm=False)),
]


@pytest.mark.parametrize("url,body", PREVIEWS, ids=[u for u, _b in PREVIEWS])
def test_previews_never_write_even_in_write_mode(world, monkeypatch, url, body):
    """ASVS V1.4.1 · V11.1.1 · CWE-841 · A04:2021: a preview or dry run writes nothing, even for a writer with write mode on and confirm=true."""
    # Arrange: the real planners, not the stubs, behind the recording client
    for mod, fn, _d in SINKS:
        monkeypatch.setattr(__import__(mod), fn, _real(mod, fn))
    world.write_mode(True)
    # Act
    world.client(WRITER).post(url, json=body)
    # Assert
    assert world.built, f"{url} did not read the tenant, so it proves nothing"
    assert world.writes == [], (url, world.writes)


_REAL: Dict[Tuple[str, str], Callable] = {(m, f): getattr(__import__(m), f) for m, f, _d in SINKS}


def _real(mod: str, fn: str) -> Callable:
    return _REAL[(mod, fn)]


def test_proposal_preview_never_writes(world):
    """ASVS V1.4.1 · CWE-841 · A04:2021: previewing a proposal (apply or rollback direction) only reads."""
    # Arrange
    world.write_mode(True)
    tenant = _proposal_tenant(world)
    c = world.client(WRITER)
    # Act
    for direction in ("apply", "rollback"):
        c.post(f"/api/proposals/{tenant}/p-1/preview?direction={direction}", json=dict(CREDS, confirm=True))
    # Assert
    assert world.writes == [] and world.sinks == []


def test_operation_undo_is_previewed_then_applied_through_every_gate(world):
    """ASVS V4.1.3 · V11.1.1 · CWE-841 · A04:2021: an Undo of a bulk change is a preview (no write) and its apply needs every gate."""
    # Arrange
    import deployments
    world.write_mode(True)
    creds = world.creds()
    op = {"id": "op-qa", "tenant_label": tenant_auth.record_label(creds), "inverse": OPERATION, **srv._record_ids(creds)}
    deployments.add_operation(op)
    c = world.client(WRITER)
    body = dict(CREDS, **SCOPE, operation=OPERATION, plan_hash=HASH, confirm=True, undo_of="op-qa")
    # Act
    preview = c.post("/api/operations/op-qa/undo/preview", json=dict(CREDS, **SCOPE))
    written_by_preview = list(world.touched())
    no_assessor = c.post("/api/operations/apply", json=body)
    applied = c.post("/api/operations/apply", json=dict(body, assessor=ASSESSOR))
    # Assert
    assert preview.status_code in (200, 400) and written_by_preview == []
    assert no_assessor.status_code == 400
    assert applied.status_code == 200, applied.text
    assert world.sinks == ["admin_ops.execute"]


# ---------------------------------------------------------------------------
# The browser extension's origin: only its read-only allow-list
# ---------------------------------------------------------------------------

EXT_ID = "febekapiipbdccnkbelfpajhillaplbe"
EXT_ORIGIN = f"chrome-extension://{EXT_ID}"


def _ext_allowed(path: str) -> bool:
    return path in security.EXTENSION_POST_PATHS or path == "/api/dlp-packs/jobs/{job_id}/cancel"


ALL_ROUTES = sorted(set(_state_changing_routes()))


@pytest.mark.parametrize("route", ALL_ROUTES, ids=[f"{m} {p}" for m, p in ALL_ROUTES])
def test_the_extension_origin_reaches_only_its_read_only_allow_list(world, no_local_side_effects, route):
    """ASVS V4.2.2 · V14.5.3 · CWE-346 · CWE-352 · WSTG-CLNT-07 · A01:2021: the extension's origin is refused on every state-changing route outside its allow-list."""
    # Arrange
    method, path = route
    world.write_mode(True)
    url = re.sub(r"\{(\w+)\}", lambda m: PATH_VALUES.get(m.group(1), "x"), path)
    c = world.client(WRITER, origin=EXT_ORIGIN)
    # Act
    r = c.request(method, url, json=KITCHEN_SINK)
    # Assert
    refused = r.status_code == 403 and "Origin not allowed" in r.text
    assert refused is (not _ext_allowed(path)), (route, r.status_code, r.text[:200])
    assert world.touched() == [], (route, world.touched())


def test_the_extension_allow_list_is_read_only():
    """ASVS V1.4.1 · CWE-346 · A01:2021: every path the extension may post to is a classified read-only route, never a write route."""
    # Arrange
    allowed = list(security.EXTENSION_POST_PATHS) + ["/api/dlp-packs/jobs/{job_id}/cancel"]
    # Act
    as_routes = {("POST", p) for p in allowed}
    # Assert
    assert as_routes <= set(READ_ONLY) and not (as_routes & WRITE_ROUTES)


@pytest.mark.parametrize("origin", [EXT_ORIGIN.upper(), EXT_ORIGIN + "/", "chrome-extension://" + "a" * 32, "null",
                                    f"chrome-extension://{EXT_ID}.evil.example"])
def test_lookalike_extension_origins_cannot_write(world, origin):
    """ASVS V14.5.3 · CWE-346 · A01:2021: a look-alike or other extension's origin cannot reach a write route."""
    # Arrange
    world.write_mode(True)
    url, body = WRITE_CASES[0][3](world)
    # Act
    r = world.client(WRITER, origin=origin).post(url, json=body)
    # Assert
    assert r.status_code == 403 and world.touched() == []


def test_the_extension_referer_without_origin_cannot_write(world):
    """ASVS V4.2.2 · CWE-352 · A01:2021: a request with only the extension's Referer is refused on a write route."""
    # Arrange
    world.write_mode(True)
    url, body = WRITE_CASES[0][3](world)
    c = world.client(WRITER)
    # Act
    r = c.post(url, json=body, headers={"Referer": EXT_ORIGIN + "/panel.html"})
    # Assert
    assert r.status_code == 403 and world.touched() == []


# ---------------------------------------------------------------------------
# Four-eyes: no self-approval
# ---------------------------------------------------------------------------

def _pending_by(world: World, who: str) -> str:
    import change_queue
    tk, label = srv._cq_tenant(world.creds())
    return change_queue.file_request(kind="pack_deploy", tenant=tk, tenant_label=label, title="QA", summary={}, items=[{"kind": "x"}],
                                     plan_hash=HASH, requested_by=who, payload={"pack_ids": [PACK]})["id"]


@pytest.mark.parametrize("four_eyes", [None, "1", "true", "yes", "on", "garbage"])
def test_the_requester_cannot_approve_their_own_request(world, monkeypatch, four_eyes):
    """ASVS V1.4.1 · V11.1.1 · CWE-863 · CWE-654 · A01:2021: with DLP_CHECK_FOUR_EYES on (unset counts as on), the requester cannot approve their own request."""
    # Arrange
    if four_eyes is not None:
        monkeypatch.setenv("DLP_CHECK_FOUR_EYES", four_eyes)
    rid = _pending_by(world, WRITER["email"])
    # Act
    r = world.client(WRITER).post(f"/api/change-queue/{rid}/approve", json={"comment": "lgtm", "by": WRITER_2["email"]})
    # Assert
    import change_queue
    assert r.status_code == 403 and "four-eyes" in r.json()["detail"]
    assert change_queue.get(rid)["status"] == "pending"


@pytest.mark.parametrize("variant", ["WRITER@EXAMPLE.COM", " writer@example.com", "writer@example.com "])
def test_the_requester_cannot_self_approve_with_a_case_or_space_variant(world, variant):
    """ASVS V11.1.1 · CWE-863 · CWE-178 · A01:2021: the same person under another spelling of their name is still the requester."""
    # Arrange
    rid = _pending_by(world, variant)
    # Act
    r = world.client(WRITER).post(f"/api/change-queue/{rid}/approve", json={"comment": "lgtm"})
    # Assert
    assert r.status_code == 403


def test_another_writer_may_approve_and_a_reader_may_not(world):
    """ASVS V4.1.3 · CWE-863 · A01:2021: a second writer approves; a reader cannot approve at all."""
    # Arrange
    rid = _pending_by(world, WRITER_2["email"])
    # Act
    by_reader = world.client(READER).post(f"/api/change-queue/{rid}/approve", json={"comment": "lgtm"})
    by_writer = world.client(WRITER).post(f"/api/change-queue/{rid}/approve", json={"comment": "lgtm"})
    # Assert
    assert by_reader.status_code == 403 and by_writer.status_code == 200
    assert by_writer.json()["request"]["decided_by"] == WRITER["email"]


def test_without_sso_the_shared_local_identity_cannot_self_approve(world, monkeypatch):
    """ASVS V11.1.1 · CWE-863 · A01:2021: without SSO everyone is the same local identity, so four-eyes refuses every approval."""
    # Arrange
    monkeypatch.setenv("ZSCALER_SSO_ENABLED", "0")
    monkeypatch.setenv("ZSCALER_UI_AUTH", "0")
    rid = _pending_by(world, security.LOCAL_NO_TOKEN_ACTOR)
    # Act
    r = TestClient(srv.app).post(f"/api/change-queue/{rid}/approve", json={"comment": "lgtm"})
    # Assert
    assert r.status_code == 403 and "four-eyes" in r.json()["detail"]


def test_a_request_filed_by_one_person_and_applied_needs_the_approval_first(world):
    """ASVS V11.1.1 · CWE-841 · A04:2021: a pending (not yet approved) request cannot be applied, even with every other gate held."""
    # Arrange
    world.write_mode(True)
    rid = _pending_by(world, WRITER_2["email"])
    # Act
    r = world.client(WRITER).post(f"/api/change-queue/{rid}/apply", json=_b(confirm=PHRASE))
    # Assert
    assert r.status_code == 409 and world.touched() == []


# ---------------------------------------------------------------------------
# Defence in depth below the routes, and the pages that send the gates
# ---------------------------------------------------------------------------

def test_a_live_remediation_is_refused_without_write_mode_whatever_the_recipe_says(world, monkeypatch):
    """ASVS V1.4.1 · CWE-1188 · CWE-276 · A05:2021: remediation.execute denies a live call without write mode even for a recipe with no `destructive` flag."""
    # Arrange
    import remediation
    recipe = {"check_id": "QA-01", "checks": [], "label": "QA", "summary": "QA", "fields": [], "endpoint": "/zia/qa",
              "method": "POST", "body_template": {}}                    # no "destructive" key
    monkeypatch.setattr(remediation, "REMEDIATIONS", [recipe])
    monkeypatch.setattr(remediation, "execute", _real("remediation", "execute"))
    client = Recorder(world.writes)
    # Act
    out = remediation.execute(client, "QA-01", {}, dry_run=False)
    # Assert
    assert out["status"] == "blocked" and world.writes == []


def test_the_pages_send_the_confirmation_and_the_assessor_with_every_live_write():
    """ASVS V11.1.1 · CWE-841 · A04:2021: every page that sends a live tenant write sends confirm=true and the assessor's name with it."""
    # Arrange
    def read(name):
        return open(os.path.join(ROOT, "static", name), encoding="utf-8").read()
    index, heal, dh = read("index.html"), read("report_self_heal.html"), read("detection_health.js")
    helper = index[index.index("function tenantWriteBody(body)"):]
    helper = helper[:helper.index("\n}\n")]
    # Act
    live = {fn: index[index.index(f"async function {fn}("):][:4000] for fn in
            ("step3bDeleteAll", "step4Activate", "step5Post", "remediationActivate", "wizardApply")}
    # Assert
    assert "body.confirm = true;" in helper and "getElementById('assessor')" in helper
    for fn, src in live.items():
        assert "tenantWriteBody(body)" in src.split("fetch(")[0], fn
    assert "b.assessor = a.value.trim()" in heal
    assert "assessor: _dhAssessor()" in dh and "confirm: true" in dh


import pack_jobs as _pack_jobs  # noqa: E402

_REAL_JOB_START = _pack_jobs.start   # before any fixture wraps it


@pytest.mark.parametrize("kind,ext_may_stop", [("deploy", False), ("removal", False), ("ops_apply", False), ("remediation", False),
                                               ("export", True)])
def test_the_extension_may_stop_only_the_export_it_started(world, kind, ext_may_stop):
    """ASVS V4.1.3 · V1.4.1 · CWE-863 · CWE-269 · A01:2021: the extension's origin may Stop its own export job, never a deploy, removal or other app job."""
    # Arrange: a job that runs until it is stopped (bounded wait, no sleeps)
    import threading
    release = threading.Event()

    def fn(log, cancel):
        release.wait(10)
        return {"status": "done", "stopped": cancel.is_set()}
    job = _REAL_JOB_START(kind, fn, label="qa")
    job.started_by = "extension"   # even a job marked as the extension's must be an export for it to stop it
    try:
        # Act
        by_ext = world.client(WRITER, origin=EXT_ORIGIN).post(f"/api/dlp-packs/jobs/{job.id}/cancel", json={})
        ext_stopped = job.cancel.is_set()
        by_app = world.client(WRITER).post(f"/api/dlp-packs/jobs/{job.id}/cancel", json={})
    finally:
        release.set()
        job.thread.join(10)
    # Assert
    assert (by_ext.status_code == 200) is ext_may_stop and ext_stopped is ext_may_stop, by_ext.text
    assert by_app.status_code == 200 and job.cancel.is_set()


def _get_routes() -> List[str]:
    return sorted({r.path for r in srv.app.routes if isinstance(r, APIRoute) and "GET" in r.methods})


GET_ROUTES = _get_routes()


@pytest.mark.parametrize("path", GET_ROUTES)
def test_no_get_route_writes_to_a_tenant(world, no_local_side_effects, path):
    """ASVS V4.2.2 · CWE-650 · A01:2021: no GET route changes a tenant, even for a writer with write mode on."""
    # Arrange
    world.write_mode(True)
    url = re.sub(r"\{(\w+)(:path)?\}", lambda m: PATH_VALUES.get(m.group(1), "x"), path)
    q = "&".join(f"{k}={v}" for k, v in (("confirm", "true"), ("dry_run", "false"), ("assessor", ASSESSOR), ("profile_id", "qa")))
    # Act
    world.client(WRITER).get(f"{url}?{q}")
    # Assert
    assert world.writes == [] and world.sinks == [], (path, world.touched())
