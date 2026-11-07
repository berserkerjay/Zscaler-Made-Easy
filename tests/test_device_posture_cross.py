"""Device posture across products (posture_cross.py): posture checks are
defined in Client Connector and used by ZPA access rules (posture
conditions) and by ZIA rules (the device trust level Client Connector
works out from a ZIA posture profile).

* The original error: /report/device-posture refused to read unless ZPA was
  ticked and readable ("tick ZPA", or the customer ID error), so a tenant
  that scopes Client Connector and ZIA saw only an error. Now each product
  in scope is read and one that is not licensed or not readable is shown
  as such in the report, never as an error page.
* The cross-reference: each device posture check, the ZIA posture profiles
  that name it (and at which trust level), the app profiles that pick each
  ZIA posture profile, the ZIA rules that use the trust level.
* The gaps (XP-01 .. XP-08), and "unknown is never pass".
* The Path analyzer: the device's trust level and posture are conditions
  of the ZIA and ZPA steps.

Offline: the sample tenant (Larkspur Freight) and copies of it with lists
that fail or are empty; no network, no real clock."""
from __future__ import annotations

import io
import json
import os
import threading
import zipfile

import pytest
from fastapi.testclient import TestClient

import device_posture as dp
import offline_tenant as ot
import path_whatif as pw
import posture_cross as pc
import sample_tenant
import zpa_path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALL = ["zpa", "zcc", "zia_extras"]


# ── offline tenants ──────────────────────────────────────────────────
def _store(mutate=None, sid="snap-" + "d" * 16):
    resp = {ot.normalize_path(p): {"status": 200, "body": b} for p, b in sample_tenant.responses().items()}
    if mutate:
        mutate(resp)
    st = ot.OfflineStore(sid, "snapshot", resp, {"tenant_label": "posture test"})
    ot.register(st)
    return st


def _client(st):
    return ot.client_for(ot.creds_for(st), "sdk")


def _set(resp, test, status, body):
    hit = [p for p in resp if test(p)]
    assert hit, "the sample has no such path"
    for p in hit:
        resp[p] = {"status": status, "body": body}


def zpa_posture_403(resp):
    _set(resp, lambda p: p.endswith("/posture"), 403, {"message": "forbidden"})


def zpa_posture_empty(resp):
    _set(resp, lambda p: p.endswith("/posture"), 200, {"list": [], "totalPages": 0})


def zpa_unlicensed(resp):
    _set(resp, lambda p: p.startswith("/zpa/"), 401, {"message": "not licensed"})


def zpa_off_in_company(resp):
    zpa_unlicensed(resp)
    _set(resp, lambda p: p.endswith("/getCompanyInfo"), 200, dict(sample_tenant.COMPANY_INFO, zpnEnabled=0))


def zia_posture_403(resp):
    _set(resp, lambda p: p.endswith("/zia-posture-profiles"), 403, {"message": "forbidden"})


def build(mutate=None, scopes=ALL, zpa_problem=""):
    """The report the page gets, built as the server builds it."""
    st = _store(mutate)
    data = pc.read_all(_client(st), scopes, zpa_problem=zpa_problem, pace=0)
    zr = data.get("zpa")
    snap = zr["snap"] if zr else {"collections": {}, "policies": {}}
    raw = zr["raw"] if zr else {}
    rep = dp.analyze(snap, raw.get("posture_profiles"), raw.get("trusted_networks"), (data.get("zcc") or {}).get("networks"))
    return pc.attach(rep, data)


@pytest.fixture(autouse=True)
def _offline(tmp_path, monkeypatch):
    monkeypatch.setenv("DLP_CHECK_ZIA_RATE_STATE", str(tmp_path / "rate.json"))
    monkeypatch.setattr(ot, "_OPEN", type(ot._OPEN)())
    import socket

    def no_network(*a, **k):
        raise AssertionError("the network was used")
    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(socket, "create_connection", no_network)


@pytest.fixture(scope="module")
def sample():
    mp = pytest.MonkeyPatch()
    mp.setattr(ot, "_OPEN", type(ot._OPEN)())
    try:
        return build()
    finally:
        mp.undo()


def _ids(rep, fid):
    return [f for f in rep["findings"] if f["id"] == fid]


# ── the cross-reference ──────────────────────────────────────────────
def test_every_product_is_read_on_the_sample(sample):
    """ASVS V1.14.1 · CWE-754 · WSTG-BUSL-01: ZPA, Client Connector and ZIA are all read and said to be read."""
    assert {k: v["status"] for k, v in sample["products"].items()} == {"zpa": "read", "zcc": "read", "zia": "read"}


def test_a_device_posture_check_links_to_zpa_rules_and_zia_trust_levels(sample):
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: CrowdStrike running is defined in Client Connector, feeds High and Medium trust and is used."""
    d = next(x for x in sample["cross"]["device_postures"] if x["name"] == "CrowdStrike running")
    assert d["defined_in"].startswith("Client Connector") and set(d["platforms"]) == {"windows", "macos"}
    assert [(z["name"], z["levels"]) for z in d["zia_postures"]] == [("Larkspur laptops (Windows)", ["HIGH_TRUST", "MEDIUM_TRUST"])]
    assert d["used"] is True and isinstance(d["zpa_rules"], list)


def test_a_zia_posture_profile_lists_its_app_profiles_and_the_zia_rules_using_trust(sample):
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: profile 81 is picked by the Windows app profile; the webmail trust rule uses it."""
    z = next(x for x in sample["cross"]["zia_postures"] if x["id"] == "81")
    assert [a["name"] for a in z["app_profiles"]] == ["Windows - Corporate"]
    assert [r["name"] for r in z["zia_rules"]] == ["Block personal webmail on untrusted devices"]
    assert all(c["device_posture"] for rows in z["levels"].values() for c in rows)


def test_a_check_a_zia_posture_profile_uses_is_not_called_unused(sample):
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: DP-05 (no ZPA rule uses it) is dropped for a check ZIA uses through a trust level."""
    assert not [f for f in _ids(sample, "DP-05") if f["object"] == "CrowdStrike running"]


# ── the gaps ──────────────────────────────────────────────────────────
def test_the_sample_gaps_are_found(sample):
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: unused ZIA posture profile, a missing check, trust for some devices only, loose rules."""
    assert [f["object"] for f in _ids(sample, "XP-02")] == ["Driver phones (iOS)"]
    xp4 = _ids(sample, "XP-04")
    assert [f["object"] for f in xp4] == ["Driver phones (iOS)"] and "Not jailbroken" in xp4[0]["reason"]
    xp5 = _ids(sample, "XP-05")
    assert [f["object"] for f in xp5] == ["Block personal webmail on untrusted devices"] and "macOS - Corporate" in xp5[0]["reason"]
    assert {f["object"] for f in _ids(sample, "XP-07")} >= {"File sharing: allow all", "Do not decrypt webmail"}
    assert not {f["object"] for f in _ids(sample, "XP-07")} & {"Default Firewall Filtering Rule", "Zscaler Recommended Exemptions"}


def _data(apps=(), zia_postures=(), rules=(), zpa_ok=True):
    """A read as read_all returns it, built by hand (no ZPA profile)."""
    return {"scopes": ALL, "company": {"read": True, "zpa": True, "zia": True},
            "zpa": {"snap": {"collections": {"posture_profiles": {"read": zpa_ok, "complete": zpa_ok, "label": "posture profiles"},
                                             "policy:access": {"read": True, "complete": True, "label": "access policy"}},
                             "policies": {"access": []}}, "raw": {}},
            "zcc": {"networks": {"read": True, "networks": [], "reason": ""},
                    "zia_postures": {"read": True, "profiles": [pc.normalize_zia_posture(z) for z in zia_postures], "reason": ""},
                    "apps": {"read": True, "complete": True, "profiles": list(apps), "errors": []}},
            "zia": {"sections": {"url": {"label": "URL filtering", "read": True}}, "rules": [pc.normalize_zia_rule(s, r) for s, r in rules]}}


def _attach(data):
    zr = data["zpa"]
    return pc.attach(dp.analyze(zr["snap"], [], [], data["zcc"]["networks"]), data)


def _app(i, plat, zp=""):
    return {"id": str(i), "name": f"App {i}", "platform": plat, "active": True, "zia_posture_id": zp}


ZP = {"id": 5, "name": "Win trust", "platform": 3, "highTrustCriteria": {"cs": []}}


def test_a_platform_in_use_with_no_posture_is_a_gap():
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: Android has app profiles but no device posture check and no ZIA posture profile."""
    rep = _attach(_data(apps=[_app(1, "android")]))
    assert [f["object"] for f in _ids(rep, "XP-01")] == ["Android"]
    assert rep["cross"]["platforms"][0]["covered"] is False


def test_an_unknown_coverage_is_never_a_pass_or_a_gap():
    """ASVS V1.14.1 · CWE-754 · WSTG-BUSL-01: with ZPA's posture list unread, an uncovered platform is unknown, not a gap and not covered."""
    rep = _attach(_data(apps=[_app(1, "android")], zpa_ok=False))
    assert rep["cross"]["platforms"][0]["covered"] is None and not _ids(rep, "XP-01")
    assert any("Android" in n for n in rep["cross"]["not_assessed"])


def test_an_app_profile_naming_a_profile_the_list_lacks_is_possibly_missing_only():
    """ASVS V1.14.1 · CWE-754 · WSTG-BUSL-01: the ZIA posture list can be cut short, so XP-03 is info and says it may exist."""
    rep = _attach(_data(apps=[_app(1, "windows", "99")], zia_postures=[ZP]))
    f = _ids(rep, "XP-03")
    assert len(f) == 1 and f[0]["severity"] == "info" and "may exist" in f[0]["reason"]


def test_a_loose_rule_for_low_or_unknown_trust_is_flagged():
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: an Allow URL rule for low and unknown trust gives failing devices the looser policy."""
    rule = {"id": 1, "name": "Allow uploads", "state": "ENABLED", "action": "ALLOW", "deviceTrustLevels": ["LOW_TRUST", "UNKNOWN_DEVICETRUSTLEVEL"]}
    rep = _attach(_data(apps=[_app(1, "windows", "5")], zia_postures=[ZP], rules=[("url", rule)]))
    f = _ids(rep, "XP-06")
    assert len(f) == 1 and f[0]["severity"] == "medium" and "low trust or unknown trust" in f[0]["reason"]


def test_trust_levels_no_rule_uses_are_said():
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: devices get a trust level but no ZIA rule uses it (XP-08), and loose rules are candidates (XP-07)."""
    rule = {"id": 2, "name": "Allow all", "state": "ENABLED", "action": "ALLOW"}
    rep = _attach(_data(apps=[_app(1, "windows", "5")], zia_postures=[ZP], rules=[("url", rule)]))
    assert len(_ids(rep, "XP-08")) == 1 and [f["object"] for f in _ids(rep, "XP-07")] == ["Allow all"]


def test_without_trust_levels_a_loose_rule_is_not_called_a_gap():
    """ASVS V1.14.1 · CWE-754 · WSTG-BUSL-01: no app profile picks a ZIA posture profile, so XP-07 is not raised (it could not help)."""
    rule = {"id": 2, "name": "Allow all", "state": "ENABLED", "action": "ALLOW"}
    rep = _attach(_data(apps=[_app(1, "windows")], zia_postures=[ZP], rules=[("url", rule)]))
    assert not _ids(rep, "XP-07") and not _ids(rep, "XP-08")


@pytest.mark.parametrize("section,rule,loose", [
    ("ssl", {"action": {"type": "DO_NOT_DECRYPT"}}, "skips SSL inspection"),
    ("cac", {"actions": ["ALLOW_FILE_SHARE_VIEW", "ALLOW_FILE_SHARE_UPLOAD"]}, "allows file share upload"),
    ("cac", {"actions": ["ALLOW_FILE_SHARE_VIEW"]}, ""),
    ("ftc", {"filteringAction": "ALLOW", "operation": "UPLOAD"}, "allows file uploads"),
    ("firewall", {"action": "BLOCK_DROP"}, ""),
])
def test_what_loosens_policy(section, rule, loose):
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: only allow, upload, share and do-not-inspect actions count as loosening."""
    assert pc.normalize_zia_rule(section, dict(rule, id=1, name="r"))["loosens"] == loose


# ── unreadable or unlicensed products: no error page ─────────────────
def test_zpa_posture_read_failing_keeps_the_rest(monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: ZPA's posture list refused: ZPA is partly read, checks named by ZIA stay, nothing raises."""
    rep = build(zpa_posture_403)
    assert rep["products"]["zpa"]["status"] == "partial" and "posture profiles" in rep["products"]["zpa"]["reason"]
    assert rep["cross"]["device_postures"] == [] and not _ids(rep, "XP-04")
    assert any("device posture list was not read" in n for n in rep["cross"]["not_assessed"])
    crit = [c for z in rep["cross"]["zia_postures"] for rows in z["levels"].values() for c in rows]
    assert crit and all(c["resolved"] is None for c in crit), "not found in an unread list is unknown, never missing"


def test_zpa_posture_list_empty_makes_every_named_check_missing():
    """ASVS V1.14.1 · CWE-1059 · WSTG-BUSL-01: an empty (complete) posture list means the checks ZIA names do not exist."""
    rep = build(zpa_posture_empty)
    assert rep["products"]["zpa"]["status"] == "read" and rep["cross"]["device_postures"] == []
    assert {f["object"] for f in _ids(rep, "XP-04")} == {"Larkspur laptops (Windows)", "Driver phones (iOS)"}
    assert all(c["resolved"] is False for z in rep["cross"]["zia_postures"] for rows in z["levels"].values() for c in rows)


def test_zpa_unlicensed_is_said_not_raised():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: every ZPA list refused (401): ZPA is not readable, with why; ZIA and Client Connector stand."""
    rep = build(zpa_unlicensed)
    z = rep["products"]["zpa"]
    assert z["status"] == "not_readable" and "401 or 403" in z["reason"]
    assert rep["products"]["zia"]["status"] == "read" and rep["cross"]["zia_postures"]
    assert rep["not_assessed"] == [f"ZPA: {z['reason']}"]


def test_zpa_off_in_company_info_is_not_licensed():
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: Client Connector's company info says ZPA is off: ZPA is shown as not licensed."""
    rep = build(zpa_off_in_company)
    assert rep["products"]["zpa"]["status"] == "not_licensed"


def test_zia_posture_list_unreadable_leaves_trust_unknown():
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: no ZIA posture list: a check no ZPA rule uses is 'used: unknown', and XP-07 is not raised."""
    rep = build(zia_posture_403)
    assert rep["products"]["zcc"]["status"] == "partial"
    assert all(d["zia_postures"] is None for d in rep["cross"]["device_postures"])
    assert not _ids(rep, "XP-07") and any("trust level" in n for n in rep["cross"]["not_assessed"])
    dp5 = _ids(rep, "DP-05")
    assert dp5 and all("ZIA use is not ruled out" in f["reason"] for f in dp5)


def test_a_product_out_of_scope_is_not_read():
    """ASVS V1.4.1 · CWE-863 · WSTG-ATHZ-01: only ZIA ticked: nothing from ZPA or Client Connector is read, and both say Not in scope."""
    rep = build(scopes=["zia_extras"])
    assert {k: v["status"] for k, v in rep["products"].items()} == {"zpa": "not_in_scope", "zcc": "not_in_scope", "zia": "read"}
    assert rep["cross"]["zia_postures"] == [] and rep["cross"]["app_profiles"] == []


# ── the API: the original error ──────────────────────────────────────
class SyncJob:
    def __init__(self, kind, result=None, error=""):
        self.id, self.kind, self.result, self.error = "sync-job", kind, result, error
        self.status = "failed" if error else "done"


@pytest.fixture
def api(tmp_path, monkeypatch):
    import dlp_api_server as srv
    import pack_jobs
    for var, name in (("DLP_CHECK_PROFILES", "tenant_profiles.json"), ("DLP_CHECK_AUDIT", "audit.log")):
        monkeypatch.setenv(var, str(tmp_path / name))
    monkeypatch.setenv("DLP_CHECK_SECRET_STORE", "file")
    for k in list(os.environ):
        if k.startswith("ZSCALER_") and k != "ZSCALER_UI_AUTH":
            monkeypatch.delenv(k, raising=False)
    jobs = []

    def start(kind, fn, **_k):
        try:
            job = SyncJob(kind, fn(lambda line: None, threading.Event()))
        except Exception as e:  # noqa: BLE001
            job = SyncJob(kind, None, f"{type(e).__name__}: {e}")
        jobs.append(job)
        return job
    monkeypatch.setattr(pack_jobs, "start", start)
    monkeypatch.setattr(srv, "_REPORTS", {})
    import zpa_reader
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0)
    return srv, TestClient(srv.app, base_url="http://127.0.0.1"), jobs


def _scope(*s):
    return {"scopes": list(s), "channels": {}, "from_page": True}


def test_the_sample_without_zpa_in_scope_reads_instead_of_erroring(api):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: the reported error: Client Connector and ZIA ticked, ZPA not: the job reads and reports."""
    srv, t, jobs = api
    assert t.post("/api/offline/sample", json={}).status_code == 200
    r = t.post("/api/device-posture/start", json=_scope("zcc", "zia_extras"))
    assert r.status_code == 200, r.text
    job = jobs[-1]
    assert job.status == "done", job.error
    res = job.result
    assert res["products"]["zpa"]["status"] == "not_in_scope" and res["products"]["zcc"]["status"] == "read"
    assert res["cross"]["zia_postures"] and t.get(f"/api/device-posture/report/{res['report_id']}").status_code == 200


def test_zpa_without_a_customer_id_is_shown_not_refused_when_more_is_in_scope(api, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: ZPA cannot be read (no customer ID) but Client Connector can: ZPA says why, the rest reads."""
    srv, t, jobs = api
    st = _store()
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _client(st))
    creds = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s" * 20, "customer_id": ""}
    r = t.post("/api/device-posture/start", json=dict(creds, **_scope("zpa", "zcc")))
    assert r.status_code == 200, r.text
    res = jobs[-1].result
    assert res["products"]["zpa"]["status"] == "not_readable" and "customer ID" in res["products"]["zpa"]["reason"]
    assert "s" * 20 not in json.dumps(res)


def test_zpa_unlicensed_through_the_api_is_a_report_not_a_failed_job(api, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: every ZPA list answers 401: the job is done and the page gets a report saying so."""
    srv, t, jobs = api
    st = _store(zpa_unlicensed)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: _client(st))
    r = t.post("/api/device-posture/start", json=dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s" * 20,
                                                       "customer_id": "216196257331281920"}, **_scope("zpa", "zcc", "zia_extras")))
    assert r.status_code == 200 and jobs[-1].status == "done", jobs[-1].error
    assert jobs[-1].result["products"]["zpa"]["status"] == "not_readable"


@pytest.mark.parametrize("scopes", [[], ["dlp"], ["zdx", "dlp"]])
def test_refused_before_sign_in_when_no_posture_product_is_in_scope(api, monkeypatch, scopes):
    """ASVS V1.4.1 · CWE-863 · WSTG-ATHZ-01: nothing posture uses is ticked: 400 before any client is built."""
    srv, t, jobs = api
    built = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: built.append(1))
    r = t.post("/api/device-posture/start", json=dict({"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "s" * 20,
                                                       "customer_id": "216196257331281920"}, **_scope(*scopes)))
    assert r.status_code == 400 and "Nothing was read" in r.json()["detail"] and built == [] and jobs == []


def test_the_export_has_the_cross_product_sheets(api):
    """ASVS V14.4.2 · CWE-116 · WSTG-BUSL-01: the Excel export carries Products, Device posture checks, ZIA posture profiles, Platforms, ZIA rules."""
    srv, t, jobs = api
    t.post("/api/offline/sample", json={})
    t.post("/api/device-posture/start", json=_scope("zpa", "zcc", "zia_extras"))
    rid = jobs[-1].result["report_id"]
    x = t.get(f"/api/device-posture/report/{rid}/export?format=xlsx")
    z = zipfile.ZipFile(io.BytesIO(x.content))
    wb = z.read("xl/workbook.xml").decode()
    for name in ("Products", "Device posture checks", "ZIA posture profiles", "Platforms", "ZIA rules"):
        assert f'name="{name}"' in wb, name


# ── the Path analyzer ────────────────────────────────────────────────
TRUST_RULE = {"id": 1, "name": "Block webmail on untrusted devices", "deviceTrustLevels": ["LOW_TRUST", "UNKNOWN_DEVICETRUSTLEVEL"]}


@pytest.mark.parametrize("given,state", [(None, None), ("HIGH_TRUST", False), ("LOW_TRUST", True), ("unknown", True), ("Medium", False)])
def test_the_zia_step_evaluates_the_device_trust_level(given, state):
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: a rule for low and unknown trust applies to those levels, is skipped for others, open when not given."""
    ident = pw.normalize_identity({"device": {"trust_level": given}} if given else {"user": "a@b.example"})
    rule = {"scope_items": pw.scope_items(TRUST_RULE)}
    applies, crit = pw.rule_criteria(rule, ident)
    assert applies is state
    assert [c["dim"] for c in crit] == ["device_trust"]


def test_any_trust_level_matches_every_given_level():
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: a rule naming ANY applies whatever trust level is given."""
    ident = pw.normalize_identity({"device": {"trust_level": "HIGH_TRUST"}})
    assert pw.rule_criteria({"scope_items": pw.scope_items({"deviceTrustLevels": ["ANY"]})}, ident)[0] is True


@pytest.mark.parametrize("raw,out", [("HIGH", "HIGH_TRUST"), ("high trust", "HIGH_TRUST"), ("UNKNOWN_DEVICETRUSTLEVEL", "UNKNOWN_DEVICETRUSTLEVEL"),
                                     ("bogus", None), ("<script>", None), ("", None)])
def test_trust_level_words(raw, out):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: only the four trust levels are accepted; anything else is no level."""
    assert pw.trust_level(raw) == out


def test_the_zpa_step_evaluates_the_posture_the_device_passes():
    """ASVS V1.14.1 · CWE-863 · WSTG-ATHZ-02: the checks given pass, every other one fails, a name no profile has is reported."""
    snap = {"posture_profiles": [{"id": "1", "name": "CrowdStrike running", "posture_udid": "u-1"}, {"id": "2", "name": "Disk encrypted", "posture_udid": "u-2"}]}
    g = zpa_path.given_posture(snap, ["crowdstrike RUNNING", "Not a check"])
    assert g == {"passing": ["u-1"], "names": ["CrowdStrike running"], "unknown": ["Not a check"], "failing": ["Disk encrypted"]}
    assert zpa_path.given_posture(snap, None) is None


# ── the page, help, glossary, release marks ──────────────────────────
def _read(*p):
    with open(os.path.join(ROOT, *p), encoding="utf-8") as f:
        return f.read()


def test_the_page_shows_products_and_the_cross_product_tab():
    """WCAG 2.2 SC 1.3.1 · ASVS V14.1.1 · CWE-1059: the page has the Across products tab and a products block, and no longer needs ZPA."""
    html = _read("static", "report_device_posture.html")
    assert 'id="tab-cross"' in html and 'aria-controls="panel-cross"' in html and 'id="panel-cross"' in html
    assert "function productsHtml" in html and "Tick ZPA on the Scope page</strong>" not in html


def test_help_entries_and_glossary_terms():
    """WCAG 2.2 SC 3.3.5 · ASVS V14.1.1 · CWE-1059: the new controls have help; device posture and trust level are in the glossary."""
    help_ = _read("static", "help_catalog.js")
    assert help_ == _read("browser_extension", "help_catalog.js")
    for key in ('"#tab-cross"', '"#paWi_trust"', '"#paWi_posture"'):
        assert key in help_, key
    g = _read("static", "glossary.js")
    assert "'trust level':" in g and "Client Connector" in g.split("'device posture':")[1].split("\n")[0]
