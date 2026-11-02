"""Wave 9 security gates: team-mode tenant isolation of kept records
(configuration backups and templates, saved traffic reports, Client
Connector fleet history, the latest tenant-health answers, and a rehearsal
by backup or template id), template ownership, the forced
password change for accounts an administrator sets up, the plan hash on
the older writes (/api/remediation/execute, /api/migrate/enable) and the
typed phrase on the older deletes (/api/dlp-packs/removal/apply,
/api/migrate/delete-all).

No real tenant and no network: kept records are made directly in the
temporary data folder, the tenant sign-in is faked, and the raw client
records every call it is asked to make."""
from __future__ import annotations

import os
from collections import OrderedDict

import pytest
from fastapi.testclient import TestClient

import config_backup as cb
import dlp_api_server as srv
import remediation
import rule_migrator
import team_server as team
import traffic_logs as tl
import zcc_fleet_history as zh
from tests.test_team_server import ORIGIN, PW, _FakeSdk, _login, _user, team_on, world  # noqa: F401 - fixtures
from tests.test_traffic_logs import T0, activity, lines, upload


# ── kept records of two tenants ─────────────────────────────────────────
def _backup(profile_id, owner_id, label):
    doc = cb.build_doc({"zia.rule_labels": [{"id": 1, "name": f"{label} label"}]},
                       {"tenant_label": label, "profile_id": profile_id, "owner_id": owner_id, "products": ["zia"]})
    return cb.save_backup(doc)["id"]


def _template(backup_id, profile_id, owner_id, name):
    doc = cb.load_backup(backup_id)
    tpl = cb.make_template(doc, [{"type": "zia.rule_labels", "name": doc["types"]["zia.rule_labels"][0]["name"]}], name=name)
    tid = cb.save_template(tpl, profile_id=profile_id, owner_id=owner_id)["id"]
    return tid


@pytest.fixture
def kept(world, monkeypatch):
    """Tenant A's and tenant B's backups and templates; otto is a second
    operator on A who keeps a template of his own."""
    u = world["users"]
    otto = _user("otto", "operator")
    team.set_grant(f"user:{otto['id']}", world["a"], ["read", "plan", "apply"])
    bk_a = _backup(world["a"], u["olga"]["id"], "acme")
    bk_b = _backup(world["b"], u["bea"]["id"], "bolt")
    tpl_a = _template(bk_a, world["a"], otto["id"], "Otto's starter")
    tpl_b = _template(bk_b, world["b"], u["bea"]["id"], "Bolt starter")
    tpl_none = _template(bk_a, "", otto["id"], "Otto's private one")   # no tenant profile: its maker's only
    seen = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: seen.append(dict(creds)) or _FakeSdk())
    return dict(world, otto=otto, bk_a=bk_a, bk_b=bk_b, tpl_a=tpl_a, tpl_b=tpl_b, tpl_none=tpl_none, signed_in=seen)


def test_a_viewer_lists_only_the_backups_and_templates_of_the_tenants_granted(kept):
    """ASVS V4.2.1 · CWE-639 · CWE-200 · WSTG-ATHZ-04: a viewer of tenant A lists only A's backups and the templates they may use; tenant B's (and a template that is another person's own) are not listed."""
    # Act
    d = _login("vic").get("/api/config-backups").json()
    # Assert
    assert [b["id"] for b in d["backups"]] == [kept["bk_a"]]
    assert {t["id"] for t in d["templates"]} == {kept["tpl_a"]}
    root = _login("root").get("/api/config-backups").json()
    assert {b["id"] for b in root["backups"]} == {kept["bk_a"], kept["bk_b"]}, "an administrator sees every tenant's"


@pytest.mark.parametrize("who", ["vic", "olga"])
def test_another_tenants_backup_and_template_cannot_be_downloaded_or_compared(kept, who):
    """ASVS V4.2.1 · CWE-639 · CWE-284 · WSTG-ATHZ-04: download and diff of tenant B's backup or template id are refused ('not found, or not yours') to a person of tenant A; A's own work."""
    c = _login(who)
    # Act / Assert: B's records are refused
    assert c.get(f"/api/config-backups/{kept['bk_b']}/download").status_code == 404
    assert c.get(f"/api/config-templates/{kept['tpl_b']}/download").status_code == 404
    r = c.post("/api/config-backups/diff", json={"old": kept["bk_a"], "new": kept["bk_b"]}, headers=ORIGIN)
    assert r.status_code == 404 and "not yours" in r.json()["detail"]
    # A's own records answer
    assert c.get(f"/api/config-backups/{kept['bk_a']}/download").status_code == 200
    assert c.post("/api/config-backups/diff", json={"old": kept["bk_a"], "new": kept["bk_a"]}, headers=ORIGIN).status_code == 200


def test_another_tenants_backup_and_template_cannot_be_deleted(kept):
    """ASVS V4.2.1 · CWE-639 · CWE-284 · WSTG-ATHZ-04: an operator of tenant A cannot delete tenant B's backup or template; both stay."""
    olga = _login("olga")
    # Act
    r1 = olga.post(f"/api/config-backups/{kept['bk_b']}/delete", headers=ORIGIN)
    r2 = olga.post(f"/api/config-templates/{kept['tpl_b']}/delete", headers=ORIGIN)
    # Assert
    assert r1.status_code == 404 and r2.status_code == 404
    assert cb.backup_meta(kept["bk_b"]) and cb.template_meta(kept["tpl_b"])
    assert _login("vic").post(f"/api/config-backups/{kept['bk_a']}/delete", headers=ORIGIN).status_code == 403, "a viewer deletes nothing"


@pytest.mark.parametrize("source,target", [("bk_b", "same"), ("bk_b", "other"), ("tpl_b", "other")])
def test_restore_clone_or_template_apply_from_another_tenants_record_is_refused_before_sign_in(kept, source, target):
    """ASVS V4.2.1 · CWE-639 · CWE-863 · WSTG-ATHZ-04: a restore, clone or template apply whose source is tenant B's backup or template is refused to an operator of A before any sign-in."""
    kind = "template" if source.startswith("tpl") else "backup"
    op = {"type": "config_restore_zia", "source": {kind: kept[source]}, "target": target, "mode": "add_missing",
          "target_profile_id": kept["a"] if target == "other" else ""}
    # Act
    r = _login("olga").post("/api/operations/preview", json={"profile_id": kept["a"], "operation": op, "scopes": ["dlp", "zia_extras"],
                                                             "channels": {}, "from_page": True}, headers=ORIGIN)
    # Assert
    assert r.status_code == 404 and "not yours" in r.json()["detail"], r.text
    assert kept["signed_in"] == []


def test_a_template_is_deleted_only_by_the_person_who_kept_it(kept):
    """ASVS V4.2.1 · V4.1.3 · CWE-639 · CWE-285 · WSTG-ATHZ-02: olga may use otto's template of tenant A but not delete it; otto may; the picker never lists another person's private template."""
    olga, otto = _login("olga"), _login("otto")
    # Arrange: the picker
    assert kept["tpl_a"] in {t["id"] for t in olga.get("/api/config-backups").json()["templates"]}
    assert kept["tpl_none"] not in {t["id"] for t in olga.get("/api/config-backups").json()["templates"]}
    assert kept["tpl_none"] in {t["id"] for t in otto.get("/api/config-backups").json()["templates"]}
    # Act
    r = olga.post(f"/api/config-templates/{kept['tpl_a']}/delete", headers=ORIGIN)
    # Assert
    assert r.status_code == 403 and "kept this template" in r.json()["detail"] and cb.template_meta(kept["tpl_a"])
    assert otto.post(f"/api/config-templates/{kept['tpl_a']}/delete", headers=ORIGIN).status_code == 200
    assert cb.template_meta(kept["tpl_a"]) is None


def test_a_template_exported_in_team_mode_names_its_maker_and_tenant(kept):
    """ASVS V4.2.1 · CWE-639: a template made from tenant A's backup is bound to A and to the person who made it."""
    # Act
    r = _login("olga").post("/api/config-templates/export", json={"backup_id": kept["bk_a"], "name": "Mine",
                                                                  "objects": [{"type": "zia.rule_labels", "name": "acme label"}]}, headers=ORIGIN)
    # Assert
    assert r.status_code == 200, r.text
    meta = cb.template_meta(r.json()["template"]["id"])
    assert meta["profile_id"] == kept["a"] and meta["owner_id"] == kept["users"]["olga"]["id"]
    assert _login("bea").get(f"/api/config-templates/{meta['id']}/download").status_code == 404


# ── other kept records: saved traffic reports, fleet history, tenant
# health, and a rehearsal by backup or template id ─────────────────────
SNAP = {"at": "2026-10-01T00:00:00+00:00", "devices": 5, "source": "live"}


@pytest.fixture
def records(kept, tmp_path, monkeypatch):
    """Tenant A's and tenant B's saved traffic report, Client Connector fleet
    history and latest tenant-health answer, plus a health answer that names
    no tenant profile."""
    monkeypatch.setenv("DLP_CHECK_TRAFFIC_LOG_REPORTS", str(tmp_path / "saved"))
    monkeypatch.setenv("DLP_CHECK_FLEET_HISTORY", str(tmp_path / "fleet_history.json"))
    u = kept["users"]
    rep = tl.analyze(upload(lines(activity("c1", "secret.user@example.com", T0))))
    rep_a = tl.save_report(rep, "Acme week", profile_id=kept["a"], owner_id=u["olga"]["id"])["name"]
    rep_b = tl.save_report(rep, "Bolt week", profile_id=kept["b"], owner_id=u["bea"]["id"])["name"]
    zh.record("acme-fleet", SNAP, profile_id=kept["a"])
    zh.record("bolt-fleet", SNAP, profile_id=kept["b"])
    health = OrderedDict([("nobody", {"label": "nobody", "status": "done"}),
                          ("bolt", {"label": "bolt", "status": "done", "profile_id": kept["b"]}),
                          ("acme", {"label": "acme", "status": "done", "profile_id": kept["a"]})])
    monkeypatch.setattr(srv, "_TENANT_HEALTH", health)
    return dict(kept, rep_a=rep_a, rep_b=rep_b)


def test_a_saved_traffic_report_is_listed_only_to_people_of_its_tenant(records):
    """ASVS V4.2.1 · CWE-639 · CWE-200 · WSTG-ATHZ-04: the saved traffic report list shows a person only the reports of the tenants they may read; an administrator sees all."""
    # Act
    seen = {who: {r["name"] for r in _login(who).get("/api/traffic-logs/saved").json()["reports"]} for who in ("vic", "bea", "root")}
    # Assert
    assert seen["vic"] == {records["rep_a"]}
    assert seen["bea"] == {records["rep_b"]}
    assert seen["root"] == {records["rep_a"], records["rep_b"]}


def test_another_tenants_saved_traffic_report_cannot_be_opened_or_deleted(records):
    """ASVS V4.2.1 · CWE-639 · CWE-284 · WSTG-ATHZ-04: an operator of tenant A who names tenant B's saved report to open or delete it is answered 'not found, or not yours'; B's report stays; A's own opens."""
    olga = _login("olga")
    # Act
    opened = olga.post(f"/api/traffic-logs/saved/{records['rep_b']}/open", headers=ORIGIN)
    deleted = olga.delete(f"/api/traffic-logs/saved/{records['rep_b']}", headers=ORIGIN)
    # Assert
    assert opened.status_code == 404 and "not yours" in opened.json()["detail"], opened.text
    assert deleted.status_code == 404 and "not yours" in deleted.json()["detail"], deleted.text
    assert tl.saved_meta(records["rep_b"]) is not None, "tenant B's report is still kept"
    assert olga.post(f"/api/traffic-logs/saved/{records['rep_a']}/open", headers=ORIGIN).status_code == 200


def test_another_tenants_fleet_history_cannot_be_forgotten(records):
    """ASVS V4.2.1 · CWE-639 · CWE-284 · WSTG-ATHZ-04: forgetting tenant B's Client Connector fleet history is refused (404) to an operator of A and removes nothing; A's own is forgotten."""
    olga = _login("olga")
    # Act
    r = olga.post("/api/zcc/fleet/history/forget", json={"tenant": "bolt-fleet", "confirm": True}, headers=ORIGIN)
    # Assert
    assert r.status_code == 404 and "not yours" in r.json()["detail"], r.text
    assert len(zh.load("bolt-fleet")) == 1
    own = olga.post("/api/zcc/fleet/history/forget", json={"tenant": "acme-fleet", "confirm": True}, headers=ORIGIN)
    assert own.status_code == 200 and own.json()["removed"] == 1 and zh.load("acme-fleet") == []


def test_tenant_health_latest_shows_only_the_answers_of_tenants_the_person_may_read(records):
    """ASVS V4.2.1 · CWE-639 · CWE-200 · WSTG-ATHZ-04: /api/tenant-health/latest lists tenant B's answer only to people of B, and an answer that names no tenant only to an administrator."""
    # Act
    seen = {who: [x["label"] for x in _login(who).get("/api/tenant-health/latest").json()["results"]] for who in ("vic", "bea", "root")}
    # Assert
    assert seen["vic"] == ["acme"]
    assert seen["bea"] == ["bolt"]
    assert seen["root"] == ["acme", "bolt", "nobody"]


@pytest.mark.parametrize("source,target", [("bk_a", "bk_b"), ("bk_b", "bk_a"), ("tpl_b", "bk_a")])
def test_a_rehearsal_against_or_from_another_tenants_backup_or_template_is_refused(records, source, target):
    """ASVS V4.2.1 · CWE-639 · CWE-863 · WSTG-ATHZ-04: a rehearsal whose target or source is tenant B's backup or template is answered 404 to an operator of A, with no sign-in; A's own rehearses."""
    kind = "template" if source.startswith("tpl") else "backup"
    olga = _login("olga")

    def rehearse(src_kind, src, tgt):
        op = {"type": "config_restore_zia", "source": {src_kind: src}, "target": "other" if src_kind == "template" else "same", "mode": "add_missing"}
        return olga.post("/api/config-backups/rehearse", json={"operation": op, "target": tgt}, headers=ORIGIN)
    # Act
    r = rehearse(kind, records[source], records[target])
    # Assert
    assert r.status_code == 404 and "not yours" in r.json()["detail"], r.text
    assert records["signed_in"] == []
    own = rehearse("backup", records["bk_a"], records["bk_a"])
    assert own.status_code == 200, own.text


def _anon_calls(rec):
    return [("get", "/api/traffic-logs/saved", None),
            ("post", f"/api/traffic-logs/saved/{rec['rep_a']}/open", None),
            ("delete", f"/api/traffic-logs/saved/{rec['rep_a']}", None),
            ("post", "/api/zcc/fleet/history/forget", {"tenant": "acme-fleet", "confirm": True}),
            ("get", "/api/tenant-health/latest", None),
            ("post", "/api/config-backups/rehearse", {"operation": {"type": "config_restore_zia", "source": {"backup": rec["bk_a"]},
                                                                    "target": "same", "mode": "add_missing"}, "target": rec["bk_a"]})]


@pytest.mark.parametrize("i", range(6), ids=["saved-list", "saved-open", "saved-delete", "fleet-forget", "health-latest", "rehearse"])
def test_the_kept_record_routes_refuse_a_caller_who_is_not_signed_in(records, i):
    """ASVS V4.1.1 · V2.1.1 · CWE-306 · CWE-862 · WSTG-ATHN-04: in team mode, the saved report, fleet history forget, tenant-health latest and rehearse routes answer 401 to a caller with no session, and change nothing."""
    method, path, body = _anon_calls(records)[i]
    anon = TestClient(srv.app)
    # Act
    r = getattr(anon, method)(path, headers=ORIGIN, **({"json": body} if body is not None else {}))
    # Assert
    assert r.status_code == 401, (path, r.status_code, r.text[:200])
    assert "acme" not in r.text and "Acme week" not in r.text
    assert tl.saved_meta(records["rep_a"]) is not None and len(zh.load("acme-fleet")) == 1


# ── forced password change ──────────────────────────────────────────────
NEW_PW = "a fresh passphrase of my own"


def test_an_account_an_administrator_creates_reaches_only_the_password_change_until_it_is_changed(world):
    """ASVS V2.1.10 · V2.5.1 · CWE-620 · CWE-1393 · WSTG-ATHN-09: an account created by an administrator signs in, is told to choose a password, may call only the change (and who am I, sign-out); after the change it signs in with the new password and works."""
    # Arrange
    root = _login("root")
    r = root.post("/api/team/users", json={"username": "newbie", "role": "viewer", "password": PW}, headers=ORIGIN)
    assert r.status_code == 200 and r.json()["user"]["must_change_password"] is True, r.text
    team.set_grant(f"user:{r.json()['user']['id']}", world["a"], ["read"])
    c = TestClient(srv.app)
    login = c.post("/api/auth/team/login", json={"username": "newbie", "password": PW}, headers=ORIGIN)
    assert login.status_code == 200 and login.json()["must_change_password"] is True
    # Act / Assert: everything else is refused
    for method, path in (("GET", "/api/tenant-profiles"), ("GET", "/api/config-backups"), ("POST", "/api/tenant-profiles")):
        got = c.request(method, path, headers=ORIGIN)
        assert got.status_code == 403 and got.json().get("password_change_required") is True, (path, got.text)
    assert c.get("/api/team/me").status_code == 200
    assert c.get("/api/auth/status").json()["password_change_required"] is True
    assert c.post("/api/team/me/password", json={"current": PW, "new": PW}, headers=ORIGIN).status_code == 400, "the same password again"
    assert c.post("/api/team/me/password", json={"current": PW, "new": NEW_PW}, headers=ORIGIN).status_code == 200
    # After the change: the old session ended; the new password signs in and works
    again = _login("newbie", NEW_PW)
    assert again.get("/api/tenant-profiles").status_code == 200
    assert team.find_user("newbie").get("must_change_password") is False


def test_an_administrators_reset_requires_a_new_change_but_their_own_change_does_not(world):
    """ASVS V2.1.10 · V2.5.1 · CWE-620: after an administrator resets vic's password vic must choose a new one; an administrator setting their own password is not asked to."""
    root = _login("root")
    vic_id, root_id = world["users"]["vic"]["id"], world["users"]["root"]["id"]
    # Act
    assert root.post(f"/api/team/users/{vic_id}/password", json={"password": "an admin chose this one"}, headers=ORIGIN).status_code == 200
    # Assert
    c = _login("vic", "an admin chose this one")
    r = c.get("/api/tenant-profiles")
    assert r.status_code == 403 and r.json()["password_change_required"] is True
    assert c.post("/api/auth/logout", headers=ORIGIN).status_code in (200, 204), "sign-out stays reachable"
    assert root.post(f"/api/team/users/{root_id}/password", json={"password": "root chose this for root"}, headers=ORIGIN).status_code == 200
    assert _login("root", "root chose this for root").get("/api/tenant-profiles").status_code == 200


def test_the_sign_in_page_has_the_password_change_form():
    """ASVS V2.1.10 · CWE-620 · WCAG 2.2 SC 3.3.2: the Sign in page carries a labelled form to choose the new password, shown when the server says so."""
    html = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "login.html"), encoding="utf-8").read()
    for needle in ('id="lgChange"', 'for="lgCur"', 'for="lgNew"', 'for="lgNew2"', "must_change_password", "password_change_required",
                   "/api/team/me/password", 'id="lgChangeGo"'):
        assert needle in html, needle
    catalog = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static", "help_catalog.js"), encoding="utf-8").read()
    for sel in ("#lgCur", "#lgNew", "#lgNew2", "#lgChangeGo"):
        assert f'"{sel}": {{' in catalog, f"no help entry for {sel}"


# ── plan hash on the older writes ───────────────────────────────────────
class RawTenant:
    """The raw client a remediation or the Evaluate All enable uses: every
    call is recorded; the Evaluate All setting lives on /webDlpGlobalOptions
    (enableEvaluateAllDlpRules, as zscaler-sdk-python's model names it)."""

    def __init__(self):
        self.calls = []
        self.settings = {"enableEvaluateAllDlpRules": False, "otherSetting": 7}

    def get(self, endpoint, params=None):
        self.calls.append(("GET", endpoint))
        if endpoint == "/zia/webDlpGlobalOptions":
            return dict(self.settings), 200
        if endpoint.rstrip("/").split("/")[-1].isdigit():
            return {"id": 7, "name": "r"}, 200
        if endpoint.startswith("/zia/") and "Rules" in endpoint:
            return [], 200
        return None, 404

    def put(self, endpoint, body):
        self.calls.append(("PUT", endpoint))
        if endpoint == "/zia/webDlpGlobalOptions":
            self.settings = dict(body)
        return body, 200

    def post(self, endpoint, body=None):
        self.calls.append(("POST", endpoint))
        return {"id": 9}, 200

    def delete(self, endpoint):
        self.calls.append(("DELETE", endpoint))
        return None, 204


CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "not-a-real-secret", "assessor": "Jane Doe"}
SCOPE = {"scopes": ["dlp", "zia_extras"], "channels": {"web_dlp": "zscaler"}, "from_page": True}
FW = {"name": "w9_rule", "description": "why", "action": "BLOCK_DROP", "order": 1, "rank": 7, "state": "DISABLED"}


@pytest.fixture
def raw(monkeypatch):
    t = RawTenant()
    built = []
    monkeypatch.setattr(srv, "_build_client", lambda req: built.append(1) or t)
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    import security
    monkeypatch.setattr(security, "_write_override", True)
    t.built = built
    return t


def _fix_body(**kw):
    return dict(CREDS, scopes=["zia_extras"], channels={}, from_page=True, check_id="FW-01", criteria=kw.pop("criteria", dict(FW)),
                dry_run=False, confirm=True, **kw)


@pytest.mark.parametrize("plan_hash", [None, "", "not-a-hash", "0" * 64])
def test_a_live_remediation_without_or_with_a_stale_plan_hash_calls_no_tenant(raw, plan_hash):
    """ASVS V11.1.3 · V1.4.1 · CWE-367 · CWE-352 · WSTG-BUSL-04: a live fix with no plan_hash, a malformed one or one of another plan is refused (4xx) before any tenant call."""
    body = _fix_body() if plan_hash is None else _fix_body(plan_hash=plan_hash)
    # Act
    r = TestClient(srv.app).post("/api/remediation/execute", json=body)
    # Assert
    assert 400 <= r.status_code < 500, r.text
    assert raw.built == [] and raw.calls == []


def test_a_live_remediation_with_the_previewed_plan_hash_writes_and_is_audited(raw, tmp_path, monkeypatch):
    """ASVS V11.1.3 · V7.1.3 · CWE-367 · CWE-778: with the preview's plan_hash the fix re-reads the policy, makes its one write and the audit names the actor and the hash."""
    c = TestClient(srv.app)
    body = _fix_body()
    plan = c.post("/api/remediation/plan", json={"check_id": "FW-01", "criteria": body["criteria"]}).json()
    assert plan.get("plan_hash"), plan
    # Act
    r = c.post("/api/remediation/execute", json=dict(body, plan_hash=plan["plan_hash"]))
    # Assert
    assert r.status_code == 200 and r.json()["status"] == "completed", r.text
    assert [m for m, _e in raw.calls] == ["GET", "POST"], raw.calls
    import audit
    ev = [e for e in audit.tail(20) if e.get("event") == "remediation_applied"]
    assert ev and ev[-1]["plan_hash"] == plan["plan_hash"]


def _enable(c, **kw):
    return c.post("/api/migrate/enable", json=dict(CREDS, **SCOPE, **kw))


@pytest.mark.parametrize("plan_hash", [None, "", "f" * 64])
def test_a_live_evaluate_all_enable_without_or_with_a_stale_plan_hash_writes_nothing(raw, plan_hash):
    """ASVS V11.1.3 · CWE-367 · WSTG-BUSL-04: a live Evaluate All enable needs the dry run's plan_hash; with none it is refused before sign-in, with a stale one nothing is written."""
    c = TestClient(srv.app)
    kw = {} if plan_hash is None else {"plan_hash": plan_hash}
    # Act
    r = _enable(c, dry_run=False, confirm=True, **kw)
    # Assert
    if not plan_hash:
        assert 400 <= r.status_code < 500 and raw.built == [] and raw.calls == [], r.text
    else:
        assert r.status_code == 200 and r.json()["status"] == "plan_changed", r.text
    assert not [x for x in raw.calls if x[0] != "GET"], raw.calls


def test_the_evaluate_all_enable_writes_only_the_field_the_dry_run_found(raw):
    """ASVS V11.1.3 · V1.4.1 · CWE-367 · CWE-20: the dry run reads only; the live run with its plan_hash makes one PUT, to the probed endpoint with only the probed field changed, and reads it back; no blind probe PUT."""
    c = TestClient(srv.app)
    dry = _enable(c, dry_run=True).json()
    assert dry["status"] == "dry_run" and dry["endpoint"] == "/zia/webDlpGlobalOptions" and dry["field"] == "enableEvaluateAllDlpRules", dry
    assert not [x for x in raw.calls if x[0] != "GET"], "the dry run wrote"
    raw.calls.clear()
    # Act
    r = _enable(c, dry_run=False, confirm=True, plan_hash=dry["plan_hash"])
    # Assert
    assert r.status_code == 200 and r.json()["status"] == "activated", r.text
    assert [x for x in raw.calls if x[0] != "GET"] == [("PUT", "/zia/webDlpGlobalOptions")]
    assert raw.settings == {"enableEvaluateAllDlpRules": True, "otherSetting": 7}


def test_the_evaluate_all_enable_writes_nothing_when_no_setting_is_found(raw):
    """ASVS V1.4.1 · CWE-20 · CWE-367: when no setting holds the mode the dry run says so and offers no plan; nothing is written."""
    raw.settings = {"unrelated": 1}
    out = _enable(TestClient(srv.app), dry_run=True).json()
    assert out["status"] == "not_found" and not out.get("plan_hash") and out["message"] == rule_migrator.ENABLE_NOT_FOUND
    assert not [x for x in raw.calls if x[0] != "GET"]


# ── typed phrase on the older deletes ───────────────────────────────────
@pytest.mark.parametrize("phrase", [None, "", "yes", "DELETE RULES", "REMOVE ALL"])
def test_delete_all_without_the_typed_phrase_is_refused_before_sign_in(raw, phrase):
    """ASVS V1.4.1 · V11.1.3 · CWE-1188 · WSTG-BUSL-06: deleting every Web DLP rule needs DELETE <n> RULES typed; without it nothing is signed in to or deleted."""
    kw = {} if phrase is None else {"confirm_phrase": phrase}
    # Act
    r = TestClient(srv.app).post("/api/migrate/delete-all", json=dict(CREDS, **SCOPE, dry_run=False, confirm=True, plan_hash="a" * 64, **kw))
    # Assert
    assert r.status_code == 400 and "DELETE <n> RULES" in r.json()["detail"], r.text
    assert raw.built == [] and raw.calls == []


def test_delete_all_with_a_phrase_for_another_number_deletes_nothing(monkeypatch, raw):
    """ASVS V1.4.1 · CWE-1188 · CWE-367: the number in the typed phrase is checked against the rules read now; DELETE 5 RULES for 2 rules deletes nothing."""
    rules = [{"id": 1, "name": "a", "order": 1}, {"id": 2, "name": "b", "order": 2}]
    monkeypatch.setattr(rule_migrator, "fetch_current_rules", lambda client, kind: [dict(r) for r in rules])
    ph = rule_migrator.rules_plan_hash(rules)
    # Act
    r = TestClient(srv.app).post("/api/migrate/delete-all", json=dict(CREDS, **SCOPE, dry_run=False, confirm=True, plan_hash=ph,
                                                                      confirm_phrase="DELETE 5 RULES"))
    # Assert
    assert r.status_code == 400 and "DELETE 2 RULES" in r.json()["detail"], r.text
    assert not [x for x in raw.calls if x[0] == "DELETE"]


@pytest.mark.parametrize("phrase", [None, "", "REMOVE", "DELETE OBJECTS", "yes please"])
def test_pack_removal_without_the_typed_phrase_is_refused_before_sign_in(monkeypatch, phrase):
    """ASVS V1.4.1 · V11.1.3 · CWE-1188 · WSTG-BUSL-06: a pack removal needs DELETE <n> OBJECTS typed (the number its plan deletes); without it nothing is signed in to or deleted."""
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1) or object())
    monkeypatch.setattr(srv, "writes_enabled", lambda: True)
    kw = {} if phrase is None else {"confirm_phrase": phrase}
    body = dict(CREDS, **SCOPE, pack_ids=["cjis_policy_pack"], plan_hash="a" * 64, confirm=True, **kw)
    for path in ("/api/dlp-packs/removal/apply", "/api/dlp-packs/removal/apply/start"):
        # Act
        r = TestClient(srv.app).post(path, json=body)
        # Assert
        assert r.status_code == 400 and "DELETE <n> OBJECTS" in r.json()["detail"], (path, r.text)
    assert built == []


def test_pack_removal_with_a_phrase_for_another_number_deletes_nothing():
    """ASVS V1.4.1 · CWE-1188 · CWE-367: the removal checks the typed number against the plan it re-makes from a fresh read; a phrase for another number deletes nothing."""
    import pack_removal

    class Zia:
        deleted = []
    plan = {"status": "ready", "plan_hash": "h" * 64, "items": [{"status": "remove", "kind": "policy", "name": "r1"}, {"status": "keep", "name": "x"}],
            "blockers": []}

    class Client:
        zia = Zia()
    out = pack_removal._execute_run(Client(), lambda c: dict(plan), plan_hash="h" * 64, writes_enabled=True, log=None, settle_seconds=0,
                                    confirm_text="DELETE 3 OBJECTS")
    assert out["status"] == "blocked" and out["phrase_mismatch"] and out["confirm_phrase"] == "DELETE 1 OBJECTS" and out["results"] == []
