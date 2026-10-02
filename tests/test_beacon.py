"""Beacon (beacon.py): the SDK, API and Terraform watchers in one snapshot,
what changed since the last run, the kept history, the GET-only tenant
API watch, the timer setting, the endpoints and the tab. Every upstream
answer and every tenant is a fake; nothing leaves this machine."""
from __future__ import annotations

import asyncio
import json
import time

import pytest
from fastapi.testclient import TestClient

import beacon
import zscaler_update_check as zu

PAGE_TEXT = "<html><head><title>{t}</title></head><body><main>" + ("Zscaler documentation text. " * 40) + "{extra}</main></body></html>"
HTML_SOURCES = [s for s in zu.SOURCES if s["type"] == "html_hash"]


@pytest.fixture(autouse=True)
def _state(tmp_path, monkeypatch):
    """Every test keeps its Beacon history in its own folder."""
    monkeypatch.setenv("DLP_CHECK_BEACON_STATE", str(tmp_path / "beacon_state.json"))
    yield


def _f(level, area, text):
    return {"level": level, "area": area, "text": text}


def upstream_report(latest="1.11.0", pre="2.0.0b2", tf_latest="4.8.9", pinned="~> 4.8", missing_ops=("/endPointDlpRules", "/casbDlpRules"),
                    sdk_head="1.11.0 (September 25, 2026)", tf_head="4.8.9 (September 28, 2026)", pypi_error=None, registry_error=None):
    """What upstream_check.run answered on 2026-09-29: the installed 1.9.44
    against 1.11.0 (no watched module changed), the 2.0.0b2 prerelease's
    ZIA service definition (apiVersion 2026-03-01) with no POST operation
    for the endpoint and SaaS rules, the provider pinned ~> 4.8 with 4.8.9
    the latest (inside the pin)."""
    import upstream_check
    kinds = {"/endPointDlpRules": "endpoint", "/casbDlpRules": "saas"}
    findings = [_f("note", "sdk", f"zscaler-sdk-python {latest} is newer than the installed 1.9.44 but changes none of the 25 modules the app calls.")]
    for path in missing_ops:
        findings.append(_f("drift", "sdk", f"zscaler-sdk-python {pre}: no POST operation for {path} in its ZIA service definition "
                                           f"(apiVersion 2026-03-01) — the app's {kinds[path]} writes have no counterpart there."))
    findings.append(_f("note", "sdk", f"zscaler-sdk-python {pre} is a new package layout (zssdk) with a machine-readable ZIA service definition (apiVersion 2026-03-01); the checks above ran against it."))
    if upstream_check.constraint_allows(pinned, tf_latest):
        findings.append(_f("note", "terraform", f"Provider zscaler/zia {tf_latest} is the latest and satisfies the pinned \"{pinned}\"; CI's terraform validate already runs against it."))
    else:
        findings.append(_f("drift", "terraform", f"Provider zscaler/zia {tf_latest} is outside the pinned \"{pinned}\": the workspaces install an older provider than the latest. Test against {tf_latest} and raise the pin."))
    findings.append(_f("note", "api", "Zscaler's API reference (automate.zscaler.com) answers; its machine-readable form is the 2.x SDK service definition checked above."))
    endpoints = {k: {"operation": f"Create{k.title()}", "members": 10, "unknown": [], "unused": 0} for k in upstream_check.ENDPOINTS}
    for path in missing_ops:
        endpoints[kinds[path]] = {"operation": None}
    return {"generated": "2026-09-29T06:23:00Z", "offline": False, "findings": findings,
            "sdk": {"installed": {"version": "1.9.44"},
                    "pypi": {"error": pypi_error} if pypi_error else {"latest": latest, "latest_uploaded": "2026-09-25T10:00:00Z", "latest_prerelease": pre,
                                                                      "prerelease_uploaded": "2026-09-20T00:00:00Z", "newest_on_index": latest},
                    "latest_diff": {"version": latest, "changed": [], "missing": []},
                    "prerelease": {"api_version": "2026-03-01", "operations": 412, "endpoints": endpoints, "version": pre},
                    "changelog_head": sdk_head},
            "terraform": {"pinned": pinned, "registry": {"error": registry_error} if registry_error else {"latest": tf_latest, "published": "2026-09-28T12:00:00Z", "versions": 90},
                          "changelog_head": tf_head, "schema": {"available": False, "error": "terraform is not installed"},
                          "docs": {"zia_dlp_web_rules": {"doc": True, "undocumented": ["rank"]}}},
            "api_reference": {"url": "https://automate.zscaler.com/docs", "reachable": True, "error": None},
            "drift": [f for f in findings if f["level"] == "drift"]}


def fake_upstream(report):
    calls = []

    def run(offline=False, fetch=None, workdir=None):
        calls.append({"offline": offline, "workdir": workdir})
        rep = dict(report)
        rep["offline"] = offline
        return rep
    run.calls = calls
    return run


def fake_fetch(changed_key=None):
    def fetch(url):
        # help.zscaler.com pages are read through the article API (fetch-data);
        # any other page as itself.
        src = next((s for s in HTML_SOURCES if s["url"] == url or zu.help_api_url(s["url"]) == url), None)
        if not src:
            return None, "HTTP 404"
        text = PAGE_TEXT.format(t=src["name"], extra="A new section." if src["key"] == changed_key else "")
        if zu.help_api_url(src["url"]):
            if url != zu.help_api_url(src["url"]):
                return None, "HTTP 404"
            return json.dumps({"data": {"info": {"status": 200}, "body": {"title": src["name"], "content": text}}}), ""
        return text, ""
    return fetch


class FakeTenant:
    """A tenant client that records every call and answers from a table."""
    def __init__(self, answers=None, legacy=False, customer_id=""):
        self.answers = answers or {}
        self.legacy, self.customer_id = legacy, customer_id
        self.calls = []
        self.closed = False

    def get(self, ep, p=None):
        self.calls.append(("GET", ep))
        return self.answers.get(ep, ([{"id": 1}, {"id": 2}], 200))

    def post(self, ep, body=None):
        self.calls.append(("POST", ep))
        raise AssertionError("the tenant watch must never POST")

    put = delete = post

    def close(self):
        self.closed = True


EPS = {"/zia/webDlpRules": ["dlp_assessment_full_auto.py"], "/zia/dlpDictionaries": ["dlp_efficacy.py"],
       "/zcc/devices": ["zcc_evaluation.py"], "/zpa/application": ["zscaler_full_checks.py"]}


# What the Scope page selected (beacon_scope.select's shape): the watch reads only these.
SCOPE = {"endpoints": EPS, "scopes": ["dlp", "zpa", "zcc"], "channels": [], "not_in_scope": [], "unmapped": [],
         "summary": "4 endpoints for DLP, ZPA, ZCC", "source": "the Scope page"}


def _probe():
    return lambda client, endpoints: beacon.probe_tenant(client, endpoints=endpoints, sleep=lambda s: None)


# ── One snapshot ──────────────────────────────────────────────────────

def test_one_snapshot_has_the_three_watchers_and_is_the_baseline():
    up = fake_upstream(upstream_report())
    s = beacon.run(online=True, fetch=fake_fetch(), upstream=up)
    assert up.calls[0]["offline"] is False and up.calls[0]["workdir"]
    sdk, api, tf = s["sdk"], s["api"], s["terraform"]
    assert (sdk["status"], sdk["installed"], sdk["latest"], sdk["prerelease"]) == ("ok", "1.9.44", "1.11.0", "2.0.0b2")
    assert sdk["latest_diff"] == {"version": "1.11.0", "changed": [], "missing": []} and sdk["changelog_head"].startswith("1.11.0")
    assert all(f["area"] == "sdk" and "service definition" not in f["text"] for f in sdk["findings"])
    # The 2.x service definition's findings are API findings.
    assert api["service_definition"]["api_version"] == "2026-03-01" and api["service_definition"]["endpoints"]["endpoint"]["operation"] is None
    assert sorted(d["text"].split("for ")[1].split(" ")[0] for d in api["findings"] if d["level"] == "drift") == ["/casbDlpRules", "/endPointDlpRules"]
    assert len(api["pages"]) == len(HTML_SOURCES) and all(p["hash"] and p["ok"] for p in api["pages"])
    assert (tf["pinned"], tf["latest"], tf["pin_allows_latest"], tf["status"]) == ("~> 4.8", "4.8.9", True, "ok")
    assert tf["docs_undocumented"] == {"zia_dlp_web_rules": ["rank"]} and tf["changelog_head"].startswith("4.8.9")
    assert [d["watcher"] for d in s["drift"]] == ["api", "api"] and s["tenant"] is None
    assert s["diff"]["first_run"] is True and s["diff"]["changes"] == [] and "baseline" in s["diff"]["summary"][0]
    assert beacon.load_history()[-1]["id"] == s["id"]


def test_beacon_keeps_its_own_page_hashes_and_leaves_the_update_check_cache_alone(tmp_path, monkeypatch):
    cache = tmp_path / "update_cache.json"
    monkeypatch.setattr(zu, "_cache_path", lambda: str(cache))
    beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    assert not cache.exists(), "the Zscaler SDK & docs updates tab still reports its own changes"


# ── What changed since the last run ───────────────────────────────────

def test_the_diff_names_version_bumps_new_and_cleared_drift_and_changed_pages():
    beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    second = upstream_report(latest="1.12.0", tf_latest="5.0.0", missing_ops=("/endPointDlpRules",), sdk_head="1.12.0 (October 2, 2026)")
    s = beacon.run(online=True, fetch=fake_fetch(changed_key="dlp_eval_all"), upstream=fake_upstream(second))
    d = s["diff"]
    kinds = {(c["watcher"], c["kind"]) for c in d["changes"]}
    assert ("sdk", "version") in kinds and ("terraform", "version") in kinds and ("sdk", "changelog") in kinds
    assert ("terraform", "drift_new") in kinds and ("api", "drift_cleared") in kinds and ("api", "doc_changed") in kinds
    texts = "\n".join(d["summary"])
    assert "zscaler-sdk-python's latest release moved from 1.11.0 to 1.12.0." in texts
    assert "The zscaler/zia provider's latest version moved from 4.8.9 to 5.0.0." in texts
    assert "New drift: Provider zscaler/zia 5.0.0 is outside the pinned" in texts
    assert "Cleared: zscaler-sdk-python 2.0.0b2: no POST operation for /casbDlpRules" in texts
    assert "DLP — First Match Wins vs Evaluate All Rules changed since the last run" in texts
    assert d["summary"][0].startswith(f"{len(d['changes'])} changes since the last run:")
    assert not any(c["kind"] == "drift_new" and "endPointDlpRules" in c["text"] for c in d["changes"]), "drift that stayed is not news"
    # A third identical run: nothing changed.
    s3 = beacon.run(online=True, fetch=fake_fetch(changed_key="dlp_eval_all"), upstream=fake_upstream(second))
    assert s3["diff"]["changes"] == [] and s3["diff"]["summary"][0].startswith("Nothing changed since the last run")


def test_an_offline_run_is_compared_with_the_last_offline_run_not_an_online_one():
    beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    off = beacon.run(online=False, upstream=fake_upstream(upstream_report()))
    assert off["diff"]["first_run"] is True and off["diff"]["changes"] == [], "online-only facts are not 'cleared' by an offline run"
    online = beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    assert online["diff"]["against"]["upstream"] != off["id"] and online["diff"]["changes"] == []


def test_the_diff_names_tenant_endpoints_whose_answer_changed():
    t1 = FakeTenant(customer_id="7")
    beacon.run(online=False, upstream=fake_upstream(upstream_report()), tenant_client=t1, tenant_label="acme (production)", probe=_probe(), tenant_scope=SCOPE)
    t2 = FakeTenant({"/zia/webDlpRules": ({"error": "not found", "status": 404}, 404),
                     "/zia/dlpDictionaries": ({"error": "Forbidden", "status": 403}, 403),
                     "/zcc/devices": ({"error": "request timeout", "status": 0}, 0)}, customer_id="7")
    s = beacon.run(online=False, upstream=fake_upstream(upstream_report()), tenant_client=t2, tenant_label="acme (production)", probe=_probe(), tenant_scope=SCOPE)
    changes = {c["endpoint"]: c for c in s["diff"]["changes"] if c["watcher"] == "tenant"}
    assert set(changes) == {"/zia/webDlpRules", "/zia/dlpDictionaries", "/zcc/devices"}
    assert changes["/zia/webDlpRules"]["text"].startswith("/zia/webDlpRules answered OK last time and 404 (not found) now.")
    assert "The API client needs DLP Dictionaries." in changes["/zia/dlpDictionaries"]["text"]
    assert (changes["/zcc/devices"]["before"], changes["/zcc/devices"]["after"]) == ("OK", "timeout")
    rows = {e["endpoint"]: e for e in s["tenant"]["endpoints"]}
    assert rows["/zpa/application"]["status"] == "OK" and rows["/zia/webDlpRules"]["items"] is None
    # Another tenant is never compared with this one.
    other = beacon.run(online=False, upstream=fake_upstream(upstream_report()), tenant_client=FakeTenant(), tenant_label="globex (zscalerten)", probe=_probe(), tenant_scope=SCOPE)
    assert other["diff"]["against"]["tenant"] is None and not [c for c in other["diff"]["changes"] if c["watcher"] == "tenant"]


# ── History ───────────────────────────────────────────────────────────

def test_the_history_keeps_the_last_30_runs_newest_first(tmp_path):
    path = str(tmp_path / "h.json")
    up = fake_upstream(upstream_report())
    ids = [beacon.run(online=False, upstream=up, path=path)["id"] for _ in range(beacon.HISTORY_KEEP + 5)]
    hist = beacon.load_history(path)
    assert len(hist) == beacon.HISTORY_KEEP and [s["id"] for s in hist] == ids[-beacon.HISTORY_KEEP:]
    rows = beacon.history_rows(hist)
    assert rows[0]["id"] == ids[-1] and rows[0]["online"] is False and rows[0]["drift"] == 2 and rows[0]["summary"]
    assert beacon.load_history(str(tmp_path / "missing.json")) == []
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    assert beacon.load_history(str(tmp_path / "bad.json")) == []


def test_the_state_file_follows_the_update_check_cache_folder(monkeypatch, tmp_path):
    monkeypatch.delenv("DLP_CHECK_BEACON_STATE")
    monkeypatch.setattr(zu, "_cache_path", lambda: str(tmp_path / "ZscalerAssessment" / "update_cache.json"))
    assert beacon.state_path() == str(tmp_path / "ZscalerAssessment" / "beacon_state.json")


# ── Offline and unreachable ───────────────────────────────────────────

def test_offline_the_real_check_reads_only_this_machine():
    pytest.importorskip("zscaler", reason="the offline check reads the installed SDK")
    s = beacon.run(online=False, fetch=lambda url: pytest.fail(f"an offline run fetched {url}"))
    for w in ("sdk", "api", "terraform"):
        assert s[w]["status"] == "offline" and s[w]["reason"], w
    assert s["sdk"]["installed"] and s["terraform"]["pinned"].startswith("~>") and s["api"]["pages"] == []
    assert s["sdk"]["latest"] is None and s["terraform"]["latest"] is None


def test_online_without_a_network_says_what_it_could_not_read():
    rep = upstream_report(pypi_error="connection error: getaddrinfo failed", registry_error="connection error: getaddrinfo failed")
    rep["api_reference"] = {"url": "https://automate.zscaler.com/docs", "reachable": False, "error": "connection error"}
    s = beacon.run(online=True, fetch=lambda url: (None, "connection error: getaddrinfo failed"), upstream=fake_upstream(rep))
    assert s["sdk"]["status"] == "unreachable" and "PyPI could not be read" in s["sdk"]["reason"]
    assert s["terraform"]["status"] == "unreachable" and s["api"]["status"] == "unreachable"
    assert all(p["hash"] is None and "connection error" in p["reason"] for p in s["api"]["pages"])
    # The next run with the network back does not call the missing versions "changes".
    s2 = beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    assert not [c for c in s2["diff"]["changes"] if c["kind"] in ("version", "doc_changed")]


def test_a_check_that_crashes_is_reported_and_still_kept():
    def boom(**kw):
        raise RuntimeError("pip exploded")
    s = beacon.run(online=True, fetch=fake_fetch(), upstream=boom)
    assert s["error"].startswith("the upstream check failed: RuntimeError: pip exploded")
    assert all(s[w]["status"] == "error" for w in ("sdk", "api", "terraform"))
    assert beacon.load_history()[-1]["id"] == s["id"]


# ── The tenant API watch is GET only ──────────────────────────────────

def test_the_probe_refuses_every_method_but_get_before_touching_the_client():
    t = FakeTenant()
    for method in ("POST", "PUT", "PATCH", "DELETE", "post", ""):
        with pytest.raises(ValueError, match="only sends GET"):
            beacon.probe_endpoint(t, "/zia/webDlpRules", method)
        with pytest.raises(ValueError, match="only sends GET"):
            beacon.probe_tenant(t, endpoints=EPS, method=method, sleep=lambda s: None)
    assert t.calls == []
    ro = beacon.ReadOnlyClient(t)
    for name in ("post", "put", "delete", "patch", "_write", "request", "sess", "token"):
        with pytest.raises(PermissionError):
            getattr(ro, name)
    with pytest.raises(PermissionError):
        ro.get = lambda *a: None
    assert t.calls == []


def test_the_probe_sends_only_gets_about_one_a_second_and_records_each_answer():
    t = FakeTenant({"/zia/dlpDictionaries": ({"error": "rate limited", "status": 429}, 429),
                    "/zcc/devices": ({"error": "boom", "status": 500}, 500)})
    slept = []
    r = beacon.probe_tenant(t, endpoints=EPS, sleep=slept.append)
    assert {m for m, _ep in t.calls} == {"GET"} and [ep for _m, ep in t.calls] == ["/zia/webDlpRules", "/zia/dlpDictionaries", "/zcc/devices"]
    assert slept == [beacon.PROBE_GAP_SECONDS] * 2 and beacon.PROBE_GAP_SECONDS == 1.0
    rows = {e["endpoint"]: e for e in r["endpoints"]}
    assert rows["/zia/webDlpRules"]["status"] == "OK" and rows["/zia/webDlpRules"]["items"] == 2
    assert rows["/zia/dlpDictionaries"]["status"] == "429" and rows["/zcc/devices"]["status"] == "error" and rows["/zcc/devices"]["http"] == 500
    assert rows["/zpa/application"]["status"] == "skipped" and "customer id" in rows["/zpa/application"]["error"]
    assert r["counts"] == {"OK": 1, "429": 1, "error": 1, "skipped": 1} and r["requests"] == 3 and r["method"] == "GET"
    # The classic ZIA API sign-in reaches ZIA only.
    legacy = FakeTenant(legacy=True, customer_id="7")
    r = beacon.probe_tenant(legacy, endpoints=EPS, sleep=lambda s: None)
    assert [ep for _m, ep in legacy.calls] == ["/zia/webDlpRules", "/zia/dlpDictionaries"]


def test_the_probe_stops_at_its_time_budget():
    t = FakeTenant(customer_id="7")
    clock = iter([0, 0, 1000, 1000, 1000, 1000, 1000, 1000]).__next__
    r = beacon.probe_tenant(t, endpoints=EPS, sleep=lambda s: None, clock=clock, budget=10)
    assert r["requests"] == 1 and r["stopped"] and r["counts"].get("not probed") == 3


def test_the_watch_covers_what_the_app_reads_and_not_the_guesses():
    eps = beacon.tenant_endpoints()
    for ep in ("/zia/webDlpRules", "/zia/dlpDictionaries", "/zia/sslInspectionRules", "/zcc/devices", "/zcc/companyInfo", "/zdx/alerts/ongoing", "/zid/users"):
        assert ep in eps, ep
    assert "discover_endpoints.py" not in beacon.TENANT_WATCH_MODULES and "scope_permissions.py" not in beacon.TENANT_WATCH_MODULES
    # CA.5 reads Cascading to URL Filtering from Advanced Settings (SDK advanced_settings.get_advanced_settings).
    assert "/zia/advancedSettings" in eps and "zscaler_full_checks.py" in eps["/zia/advancedSettings"]
    assert "/zcc/getAdminRoles" not in eps, "only the scope_permissions catalogue lists it"
    assert not [e for e in eps if e.startswith("raw:") or e.endswith("/")]
    assert 50 <= len(eps) <= 200


def test_the_watched_sdk_modules_exist_in_the_installed_sdk():
    """A tidy-up: zscaler_client.py and legacy.py at the package root exist
    in no 1.x release (ZscalerClient is in oneapi_client.py, the classic
    client in zia/legacy.py); a watched module should be one the diff can read."""
    pytest.importorskip("zscaler")
    import os
    import upstream_check
    base = upstream_check.installed_sdk_dir()
    assert [f for f in upstream_check.WATCHED_SDK_FILES if not os.path.exists(os.path.join(base, f))] == []
    assert "zia/legacy.py" in upstream_check.WATCHED_SDK_FILES


# ── The server: endpoints, timer setting, page ────────────────────────

def _client():
    import dlp_api_server as srv
    import security
    c = TestClient(srv.app)
    c.cookies.set(security.UI_TOKEN_COOKIE, security.ui_token())
    return c


def _wait_idle(c, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        d = c.get("/api/beacon").json()
        if not d["running"]:
            return d
        time.sleep(0.05)
    pytest.fail("the Beacon run did not finish")


@pytest.fixture
def fake_run(monkeypatch):
    real = beacon.run
    seen = []

    def run(online=True, tenant_client=None, tenant_label="", trigger="manual", tenant_scope=None, **kw):
        seen.append({"online": online, "tenant_client": tenant_client, "tenant_label": tenant_label, "trigger": trigger, "tenant_scope": tenant_scope})
        return real(online=online, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()), tenant_client=tenant_client,
                    tenant_label=tenant_label, trigger=trigger, probe=_probe(), tenant_scope=tenant_scope)
    monkeypatch.setattr(beacon, "run", run)
    return seen


def test_run_then_read_the_snapshot_diff_history_and_timer(fake_run):
    c = _client()
    d = c.get("/api/beacon").json()
    assert d["latest"] is None and d["history"] == [] and d["timer"]["setting"].startswith("DLP_CHECK_BEACON_HOURS")
    r = c.post("/api/beacon/run", json={"online": True})
    assert r.status_code == 200 and r.json()["started"] is True and r.json()["tenant_watch"] is False
    d = _wait_idle(c)
    assert fake_run[0]["online"] is True and fake_run[0]["tenant_client"] is None and fake_run[0]["trigger"] == "manual"
    assert d["latest"]["sdk"]["latest"] == "1.11.0" and d["diff"]["first_run"] is True and len(d["history"]) == 1
    st = c.get("/api/beacon/status").json()
    assert len(st["drift"]) == 2 and st["drift_key"] and st["details"] == "/report/beacon" and st["started"] is False


def test_status_refresh_runs_online_at_most_once_an_hour(fake_run):
    c = _client()
    assert c.get("/api/beacon/status?refresh=1").json()["started"] is True
    _wait_idle(c)
    assert c.get("/api/beacon/status?refresh=1").json()["started"] is False, "the online run is an hour fresh"
    assert [s["trigger"] for s in fake_run] == ["status"]


def test_one_run_at_a_time():
    c = _client()
    assert beacon.RUN_LOCK.acquire(blocking=False)
    try:
        r = c.post("/api/beacon/run", json={"online": False})
        assert r.status_code == 409 and "already in progress" in r.json()["detail"]
        assert c.get("/api/beacon").json()["running"] is True
    finally:
        beacon.RUN_LOCK.release()


def test_the_tenant_watch_signs_in_first_reads_only_and_never_echoes_a_secret(fake_run, monkeypatch):
    import dlp_api_server as srv
    tenant = FakeTenant(customer_id="7")
    monkeypatch.setattr(srv, "_build_client", lambda req: tenant)
    c = _client()
    secret = "s3cr3t-Value-1234567890"
    r = c.post("/api/beacon/run", json={"online": False, "tenant_watch": True, "cloud": "production", "vanity_domain": "acme",
                                        "client_id": "cid-abcdef123456", "client_secret": secret, "scopes": ["zdx"]})
    assert r.status_code == 200 and secret not in r.text and r.json()["tenant"] == "acme (production)"
    d = _wait_idle(c)
    assert d["latest"]["tenant"]["label"] == "acme (production)" and {m for m, _ in tenant.calls} == {"GET"}
    assert {ep for _m, ep in tenant.calls} == set(fake_run[0]["tenant_scope"]["endpoints"]) and all(ep.startswith("/zdx/") for _m, ep in tenant.calls)
    assert tenant.closed and secret not in c.get("/api/beacon").text


def test_bad_input_is_refused_like_every_other_endpoint():
    c = _client()
    assert c.post("/api/beacon/run", json={"online": "sometimes"}).status_code == 422
    secret = "zz-Top-Secret-Value-987654"
    r = c.post("/api/beacon/run", json={"tenant_watch": True, "vanity_domain": "bad domain!", "client_id": "cid-abcdef123456", "client_secret": secret,
                                        "scopes": ["dlp"]})
    assert r.status_code == 400 and secret not in r.text
    assert c.get("/api/beacon").json()["running"] is False


@pytest.fixture
def timer_state(monkeypatch):
    """The timer tests change the server's timer state; each gets a copy."""
    import dlp_api_server as srv
    monkeypatch.setattr(srv, "_BEACON_STATE", dict(srv._BEACON_STATE))
    return srv._BEACON_STATE


def test_the_timer_setting(monkeypatch, capsys, timer_state):
    import dlp_api_server as srv
    for raw, hours in (("", 24.0), ("6", 6.0), ("0", 0.0), ("0.5", 0.5), ("often", 24.0), ("-3", 24.0)):
        monkeypatch.setenv("DLP_CHECK_BEACON_HOURS", raw)
        assert srv._beacon_hours() == hours, raw
    assert "is not a number" in capsys.readouterr().out
    monkeypatch.setenv("DLP_CHECK_BEACON_HOURS", "0")
    started = []
    monkeypatch.setattr(srv.asyncio, "create_task", lambda coro: started.append(coro) or coro.close())
    asyncio.run(srv._start_beacon())
    assert started == [] and srv._BEACON_STATE["enabled"] is False and srv._BEACON_STATE["last_status"] == "disabled"


def test_the_timer_survives_a_failed_run_and_never_reads_a_tenant(monkeypatch, timer_state):
    import dlp_api_server as srv
    runs, sleeps = [], []

    def failing(online, trigger):
        runs.append((online, trigger))
        raise RuntimeError("no network")

    async def fake_sleep(s):
        sleeps.append(s)
        if len(sleeps) > 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(srv, "_beacon_run_blocking", failing)
    monkeypatch.setattr(srv.asyncio, "sleep", fake_sleep)
    monkeypatch.setitem(srv._BEACON_STATE, "enabled", True)
    monkeypatch.setitem(srv._BEACON_STATE, "interval_hours", 2.0)
    asyncio.run(srv._beacon_loop())
    assert runs == [(True, "timer"), (True, "timer")], "online upstream only; the signature has no tenant"
    assert sleeps[0] == 60.0 and sleeps[1] == 7200.0
    assert srv._BEACON_STATE["last_status"] == "error" and "no network" in srv._BEACON_STATE["last_error"]


def test_the_first_timer_run_waits_for_the_last_online_run_to_age(monkeypatch, timer_state):
    import dlp_api_server as srv
    beacon.run(online=True, fetch=fake_fetch(), upstream=fake_upstream(upstream_report()))
    sleeps = []

    async def fake_sleep(s):
        sleeps.append(s)
        raise asyncio.CancelledError

    monkeypatch.setattr(srv.asyncio, "sleep", fake_sleep)
    monkeypatch.setitem(srv._BEACON_STATE, "enabled", True)
    monkeypatch.setitem(srv._BEACON_STATE, "interval_hours", 24.0)
    asyncio.run(srv._beacon_loop())
    assert 24 * 3600 - 120 < sleeps[0] <= 24 * 3600, "a restart does not re-fetch what is a minute old"


def test_the_beacon_tab_and_its_links():
    c = _client()
    page = c.get("/report/beacon")
    assert page.status_code == 200 and "no-cache" in page.headers["cache-control"]
    html = page.text
    for needle in ('<header class="hero rp-hero">', '<nav class="rp-bar" aria-label="Page actions">', "<main", 'role="status" aria-live="polite"',
                   'id="changes"', 'id="sdk"', 'id="api"', 'id="terraform"', 'id="history"', 'id="bcRun"', '<label class="df-ctl" for="bcTenant">',
                   '<script src="/static/beacon.js"></script>', '<th scope="col">'):
        assert needle in html, needle
    js = c.get("/static/beacon.js").text
    assert "/api/beacon/run" in js and "window.opener.migrateCredBody" in js and "tenant_watch" in js
    assert "openBeaconTab()" in c.get("/").text and "window.open('/report/beacon'" in c.get("/").text
    assert 'href="/report/beacon"' in c.get("/report/advanced").text
    import dlp_api_server as srv
    import security
    assert any("/report/beacon".startswith(p) for p in security._UI_AUTH_EXEMPT_PREFIXES), "the page loads before the token is presented"
    assert "'/report/beacon': 'beacon'" in c.get("/static/explain.js").text

def test_the_update_notice_also_carries_upstream_drift_with_its_own_later():
    """The in-app update notice (update_beacon.js) shows Beacon's drift as a
    second bar: read from /api/beacon/status (which never fetches by
    itself), dismissed per set of findings, with a link to the details."""
    import os
    js = open(os.path.join(os.path.dirname(beacon.__file__), "static", "update_beacon.js"), encoding="utf-8").read()
    assert "fetch('/api/beacon/status'" in js and "?refresh" not in js, "the notice only reads; the timer fetches"
    assert "dlpcheck_upstream_dismissed" in js and "st.drift_key" in js and "id=\"dlpUpstreamLater\"" in js
    assert "dlpUpstreamBeacon" in js and "dlpUpdateBeacon" in js and "dlpBeaconStack" in js, "two separate bars in one stack"
    assert "st.details || '/report/beacon'" in js and "role', 'status'" in js
