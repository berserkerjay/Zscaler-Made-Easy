"""Tenant API map (tenant_api_map.py): GET only, throttled and cancellable, skips what returns credentials or needs an id,
keeps counts and field names and never a value, maps 2xx/403/404/other to a verdict, saves per tenant sealed, and the
committed endpoint catalogue matches the installed SDK.

Nothing here contacts a tenant: a scripted fake client stands in for the app's signed-in client and the sample tenant
answers offline."""
from __future__ import annotations

import csv
import io
import json
import os
import sys
import threading

import pytest

import tenant_api_map as m

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANARY = "canary-secret-VALUE-7c1f9"
NAME_CANARY = "Larkspur Payroll Canary"
ID_CANARY = "9988776655443322"


class FakeClient:
    """The app's raw client as the map sees it: get(ep, p) -> (body, status). Records every call; anything else is a failure."""

    offline = False
    legacy = False
    customer_id = "7000000000000001"

    def __init__(self, answers=None, default=(None, 404)):
        self.answers = answers or {}
        self.default = default
        self.calls = []

    def get(self, ep, p=None):
        self.calls.append((ep, p))
        a = self.answers.get(ep.removeprefix("raw:"), self.default)
        return a(ep) if callable(a) else a

    def post(self, *a, **k):
        raise AssertionError("the API map must never POST")

    put = patch = delete = post


def _plan(**kw):
    return m.plan(**kw)


def _fast(rps=5):
    return m.Throttle(rps, clock=lambda: 0.0, sleeper=lambda s: None)


# ── the catalogue ────────────────────────────────────────────────────
def _pinned_sdk_version():
    """The zscaler-sdk-python version requirements.lock pins."""
    import re
    with open(os.path.join(ROOT, "requirements.lock"), encoding="utf-8") as f:
        hit = re.search(r"^zscaler-sdk-python==([0-9][^\s\\]*)", f.read(), re.M)
    assert hit, "requirements.lock does not pin zscaler-sdk-python"
    return hit.group(1)


def test_the_committed_catalogue_matches_the_sdk_pinned_in_requirements_lock():
    """SSDF PW.4.4 · CWE-1104: the catalogue names the SDK version requirements.lock pins, and, with that version installed, is exactly what tools/build_tenant_api_catalogue.py makes from it."""
    # Arrange
    import importlib.metadata
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import build_tenant_api_catalogue as b
    pinned, installed = _pinned_sdk_version(), importlib.metadata.version("zscaler-sdk-python")
    # Assert: the committed file is for the pinned version
    assert m.catalogue()["sdk"] == f"zscaler-sdk-python {pinned}", (
        f"tenant_api_catalogue.json was made from {m.catalogue()['sdk']} but requirements.lock pins {pinned}: "
        "run python tools/build_tenant_api_catalogue.py with the pinned SDK installed, then review the endpoints it added")
    assert installed == pinned, (f"the installed zscaler-sdk-python is {installed} but requirements.lock pins {pinned}: install the pinned version "
                                 "(pip install -r requirements.lock), or, after an SDK upgrade, regenerate the catalogue with "
                                 "python tools/build_tenant_api_catalogue.py and review the endpoints it added")
    # Act
    fresh = b.render(b.catalogue())
    # Assert
    with open(m.CATALOGUE_FILE, encoding="utf-8") as f:
        assert f.read() == fresh, "regenerate the catalogue: python tools/build_tenant_api_catalogue.py, then review the endpoints the SDK added"


def test_the_catalogue_holds_only_get_endpoints_and_the_expected_scale():
    """OWASP ASVS 4.0.3 V13.1.1 · CWE-749: 687 published GET endpoints, of which the probe-able ones are the reads."""
    cat = m.catalogue()
    entries = [e for v in cat["products"].values() for e in v]
    assert len(entries) >= 600 and sum(1 for e in entries if e["probeable"]) >= 350
    assert all(e["path"].startswith("/") and "{?}" not in e["path"] or not e["probeable"] for e in entries)


def test_every_feature_endpoint_is_in_the_catalogue_and_readable():
    """ASVS V1.1.5: a feature's deciding and info reads are real, probe-able SDK endpoints (a typo would hide a feature)."""
    idx = m._entry_index()
    for f in m.FEATURES:
        for path, _params, _p in m.feature_paths(f):
            assert path in idx, (f[0], path)
            assert m.skip_reason(idx[path]) is None, (f[0], path)


# ── the plan and the skip list ───────────────────────────────────────
def test_the_plan_lists_only_parameterless_reads_and_never_a_sensitive_one():
    """ASVS V8.3.4 · CWE-200: no endpoint with an id in its address, and none that returns credentials, one-time passwords, keys or exports."""
    p = _plan()
    assert 300 <= p["count"] <= 400 and p["method"] == "GET"
    for r in p["reads"]:
        assert "{?}" not in r["path"]
        assert [x for x in __import__("re").findall(r"\{([^}]*)\}", r["path"]) if x != "customerId"] == [], r["path"]
        assert not m.SKIP_RE.search(r["path"]) and not m.EXTRA_SKIP.search(r["path"]), r["path"]


@pytest.mark.parametrize("path,why", [
    ("/zcc/papi/public/v1/getOtp", m.REASON_SENSITIVE),
    ("/zia/api/v1/apiKeys/export", m.REASON_SENSITIVE),
    ("/zpa/mgmtconfig/v1/admin/customers/{customerId}/provisioningKey", m.REASON_SENSITIVE),
    ("/zia/api/v1/auditlogEntryReport", m.REASON_SENSITIVE),
    ("/zia/api/v1/ipsecVpnPsk", m.REASON_SENSITIVE),
    ("/zia/api/v1/webDlpRules/{ruleId}", m.REASON_ID),
])
def test_the_skip_list_refuses_credentials_exports_and_id_paths(path, why):
    """CWE-522 · ASVS V8.3.4: an endpoint that returns a secret, or needs an object id, is skipped with its reason."""
    entry = {"path": path, "path_params": ["ruleId"] if "{ruleId}" in path else [], "probeable": True}
    assert m.skip_reason(entry) == why


def test_skipped_endpoints_are_listed_with_a_reason_and_never_read():
    """ASVS V1.14: what is not read is shown, with why; the list and the reads do not overlap."""
    p = _plan()
    assert p["skipped_count"] > 200 and all(s["reason"] for s in p["skipped"])
    assert not ({r["path"] for r in p["reads"]} & {s["path"] for s in p["skipped"] if s["reason"] != m.REASON_PRODUCT})


def test_products_narrow_the_plan_and_features_only_is_small():
    """ASVS V5.1.3: the products and the speed are validated; features-only reads only the deciding and info endpoints."""
    zia = _plan(products=["zia", "nonsense"])
    assert set(zia["by_product"]) == {"zia"} and zia["selected"] == ["zia"]
    small = _plan(features_only=True)
    assert 20 <= small["count"] <= 60 and small["count"] < _plan()["count"]
    assert _plan(rps=1000)["rps"] == m.MAX_RPS and _plan(rps="x")["rps"] == m.DEFAULT_RPS and _plan(rps=0)["rps"] == m.MIN_RPS


def test_the_plan_hash_changes_with_what_is_read():
    """ASVS V4.2.2: the confirmed list is bound to a hash, so a different list needs a new confirmation."""
    a, b = _plan(), _plan(products=["zia"])
    assert a["plan_hash"] == _plan()["plan_hash"] and a["plan_hash"] != b["plan_hash"] and a["plan_hash"] != _plan(rps=2)["plan_hash"]


# ── GET only ─────────────────────────────────────────────────────────
def test_the_read_only_client_has_no_write_method_and_refuses_unplanned_paths():
    """ASVS V13.2.1 · CWE-650: no post/put/delete exists on the map's client; a path outside the plan is refused unsent."""
    fc = FakeClient()
    ro = m.ReadOnlyClient(fc, {"raw:/zia/api/v1/webDlpRules"})
    for name in ("post", "put", "patch", "delete", "request", "_client_post"):
        with pytest.raises(AttributeError):
            getattr(ro, name)
    with pytest.raises(PermissionError):
        ro.get("raw:/zia/api/v1/adminUsers")
    assert fc.calls == []
    ro.get("raw:/zia/api/v1/webDlpRules")
    assert fc.calls == [("raw:/zia/api/v1/webDlpRules", None)]


def test_a_whole_run_only_ever_calls_get():
    """ASVS V13.2.1: a full run touches get() and nothing else (the fake's POST/PUT/DELETE fail the test)."""
    fc = FakeClient({"/zia/api/v1/webDlpRules": ([{"id": 1}], 200)})
    rep = m.run(fc, _plan(features_only=True), label="t", throttle=_fast())
    assert fc.calls and all(c[0].startswith("raw:/") for c in fc.calls)
    assert rep["method"] == "GET" and rep["counts"]["read"] == len(fc.calls)


# ── verdicts ─────────────────────────────────────────────────────────
@pytest.mark.parametrize("status,hint,verdict", [
    (200, None, m.PRESENT), (204, None, m.PRESENT), (404, None, m.NOT_LICENSED), (403, None, m.NO_PERMISSION), (401, None, m.NO_PERMISSION),
    (403, "NOT_SUBSCRIBED", m.NOT_LICENSED), (400, "FEATURE_NOT_ENABLED", m.NOT_LICENSED), (500, None, m.ERROR), (429, None, m.ERROR),
    (400, None, m.ERROR), (None, None, m.ERROR),
])
def test_verdict_mapping(status, hint, verdict):
    """ASVS V7.4.1: 2xx present, 404 or a not-subscribed code not licensed, 401/403 no permission, anything else an error."""
    assert m.verdict_for(status, hint) == verdict


def test_an_error_code_is_read_from_a_wire_answer_as_a_fixed_word_only():
    """CWE-209: only an UPPER_SNAKE code leaves an error answer; the rest of its text is never kept."""
    assert m.error_hint({"code": "NOT_SUBSCRIBED", "message": CANARY}) == "NOT_SUBSCRIBED"
    assert m.error_hint({"error": '{"code":"FEATURE_NOT_ENABLED","message":"%s"}' % CANARY}) == "FEATURE_NOT_ENABLED"
    assert m.error_hint({"error": "boom " + CANARY}) == m.GENERIC_HINT


def test_the_run_turns_each_answer_into_a_verdict_and_a_feature_row():
    """ASVS V7.4.1: present / not licensed / no permission / error show per endpoint and decide each feature."""
    fc = FakeClient({
        "/zia/api/v1/webDlpRules": ([{"id": 1, "name": "x", "state": "ENABLED"}], 200),
        "/zia/api/v1/emailDlpRules": ({"error": "x", "status": 403}, 403),
        "/zia/api/v1/endPointDlpRules": ({"error": '{"code":"NOT_SUBSCRIBED"}', "status": 403}, 403),
        "/zia/api/v1/sandboxRules": ({"error": "service unavailable", "status": 503}, 503),
    })
    rep = m.run(fc, _plan(products=["zia"], features_only=True), label="t", throttle=_fast())
    by = {f["feature"]: f for f in rep["features"]}
    assert by["Web DLP"]["verdict"] == m.PRESENT and by["Web DLP"]["deciding_endpoint"] == "/zia/api/v1/webDlpRules" and by["Web DLP"]["item_count"] == 1
    assert by["Email DLP"]["verdict"] == m.NO_PERMISSION
    assert by["Endpoint DLP"]["verdict"] == m.NOT_LICENSED and by["Endpoint DLP"]["detail"] == "NOT_SUBSCRIBED"
    assert by["Sandbox"]["verdict"] == m.ERROR and by["Cloud IPS"]["verdict"] == m.NOT_LICENSED
    assert by["ZDX"]["verdict"] == m.NOT_PROBED and by["Risk360"]["verdict"] == m.NOT_PROBED
    ep = {e["path"]: e for e in rep["endpoints"]}
    assert ep["/zia/api/v1/webDlpRules"]["field_names"] == ["id", "name", "state"]


def test_a_feature_with_two_deciders_is_present_when_either_answers():
    """ASVS V7.4.1: any 2xx among a feature's deciding endpoints makes it present."""
    fc = FakeClient({"/zia/api/v1/casbTenant/lite": ([], 200), "/zia/api/v1/casbDlpRules": ({"error": "x"}, 404)})
    rep = m.run(fc, _plan(products=["zia"], features_only=True), label="t", throttle=_fast())
    f = {x["feature"]: x for x in rep["features"]}["SaaS Security API (CASB)"]
    assert f["verdict"] == m.PRESENT and f["deciding_endpoint"] == "/zia/api/v1/casbTenant/lite"


# ── values are never kept ────────────────────────────────────────────
def test_summarise_keeps_counts_and_field_names_only():
    """CWE-200 · ASVS V8.3.4: a list becomes a count and the field names; a name that could be data is only counted."""
    s = m.summarise([{"id": 1, "name": NAME_CANARY, "clientSecret": CANARY, NAME_CANARY: 1, ID_CANARY: 2, "Tenant Name": 3}])
    assert s["count"] == 1 and s["fields"] == ["id", "name", "clientSecret"] and s["other_names"] == 3
    assert CANARY not in json.dumps(s) and NAME_CANARY not in json.dumps(s) and ID_CANARY not in json.dumps(s)
    assert m.summarise({"list": [{"a": 1}], "totalCount": 7})["total"] == 7
    assert m.summarise({"key": "v"})["shape"] == "object" and m.summarise("text")["shape"] == "text" and m.summarise(None)["shape"] == "empty"


def test_no_value_reaches_the_map_its_exports_its_log_or_the_saved_file(tmp_path):
    """CWE-532 · CWE-312 · ASVS V8.3.4: secret canaries in answers (values, names, ids, error text) appear in no output."""
    body = [{"id": ID_CANARY, "name": NAME_CANARY, "password": CANARY, "apiKey": CANARY, "nested": {"token": CANARY}, NAME_CANARY: CANARY}]
    err = ({"error": 'denied for ' + CANARY + ' ' + NAME_CANARY, "status": 403, "path": "/" + CANARY}, 403)
    fc = FakeClient({"/zia/api/v1/webDlpRules": (body, 200), "/zia/api/v1/emailDlpRules": err, "/zia/api/v1/sandboxRules": ({"error": CANARY, "status": 500}, 500)},
                    default=(body, 200))
    lines = []
    rep = m.run(fc, _plan(products=["zia"]), label="acme (production)", log=lines.append, throttle=_fast())
    path = str(tmp_path / "map.json")
    m.save("acme (production)", rep, path)
    saved = open(path, encoding="utf-8").read()
    from conftest import read_store_text
    outputs = [json.dumps(rep), m.to_json(rep), m.to_csv(rep, "endpoints"), m.to_csv(rep, "features"), "\n".join(lines),
               json.dumps(m.for_assistant(rep)), read_store_text(path), saved]
    for text in outputs:
        for canary in (CANARY, NAME_CANARY, ID_CANARY):
            assert canary not in text, canary


# ── pace and Stop ────────────────────────────────────────────────────
def test_the_throttle_spaces_requests_and_stop_ends_the_wait():
    """ASVS V11.1.4 · CWE-770: at 2 requests a second the gap is 0.5 s; a set cancel returns False and nothing is sent."""
    now, slept = [0.0], []
    th = m.Throttle(2, clock=lambda: now[0], sleeper=lambda s: (slept.append(round(s, 3)), now.__setitem__(0, now[0] + s)))
    for _ in range(3):
        assert th.wait() is True
    assert slept == [0.5, 0.5]
    ev = threading.Event()
    ev.set()
    assert th.wait(ev) is False


def test_the_speed_is_capped():
    """CWE-770: the page cannot ask for more than MAX_RPS requests a second, nor less than MIN_RPS."""
    assert m.Throttle(10_000).interval == 1.0 / m.MAX_RPS and m.clamp_rps(float("nan")) == m.DEFAULT_RPS and m.MAX_CONCURRENCY == 1


def test_stop_ends_the_run_and_keeps_nothing():
    """ASVS V11.1.4: Stop between two reads ends the run with Stopped; no more request is sent."""
    ev = threading.Event()
    fc = FakeClient(default=([], 200))
    orig = fc.get

    def get(ep, p=None):
        r = orig(ep, p)
        if len(fc.calls) == 3:
            ev.set()
        return r
    fc.get = get
    with pytest.raises(m.Stopped):
        m.run(fc, _plan(features_only=True), label="t", cancel=ev, throttle=_fast())
    assert len(fc.calls) == 3


def test_a_run_of_rate_limit_answers_ends_the_run():
    """CWE-770: three 'too many requests' answers in a row stop the run (nothing saved) instead of hammering the tenant."""
    fc = FakeClient(default=({"error": "rate limited", "status": 429}, 429))
    with pytest.raises(m.Stopped) as e:
        m.run(fc, _plan(), label="t", throttle=_fast())
    assert len(fc.calls) == m.ABORT_AFTER_429 and "too many requests" in str(e.value)


def test_one_map_runs_at_a_time():
    """CWE-770: concurrency is capped at one map per server; a second start is refused."""
    assert m._RUN_LOCK.acquire(blocking=False)
    try:
        with pytest.raises(m.Busy):
            m.run(FakeClient(), _plan(features_only=True), throttle=_fast())
    finally:
        m._RUN_LOCK.release()


# ── sign-in kinds ────────────────────────────────────────────────────
def test_zpa_reads_need_the_customer_id_and_the_classic_sign_in_reads_zia_only():
    """ASVS V4.1.1: ZPA paths without a customer id are not probed; a classic ZIA sign-in sends ZIA reads only, in its short form."""
    no_cust = FakeClient(default=([], 200))
    no_cust.customer_id = ""
    rep = m.run(no_cust, _plan(products=["zpa"], features_only=True), label="t", throttle=_fast())
    assert rep["counts"]["read"] == 0 and all(e["verdict"] == m.NOT_PROBED and e["error"] == m.REASON_CUSTOMER for e in rep["endpoints"])
    classic = FakeClient(default=([], 200))
    classic.legacy = True
    rep = m.run(classic, _plan(features_only=True), label="t", throttle=_fast())
    assert classic.calls and all(c[0].startswith("/zia/") and not c[0].startswith("/zia/api/") for c in classic.calls)
    assert all(e["error"] == m.REASON_CLASSIC for e in rep["endpoints"] if e["product"] != "zia")


# ── the sample tenant ────────────────────────────────────────────────
def test_the_sample_tenant_answers_a_realistic_map_offline():
    """ASVS V1.1.5: the page works on the sample: features present, no-permission and not-licensed examples, no network."""
    import offline_tenant
    st = offline_tenant.sample_store(reset=True)
    cl = offline_tenant.OfflineRawClient(st, offline_tenant.creds_for(st))
    rep = m.run(cl, _plan(), label="Sample tenant: Larkspur Freight")
    c = rep["counts"]
    assert c["planned"] == c["read"] > 300 and c["present"] > 150 and c["no_permission"] == 1 and c["not_licensed"] > 20 and c["error"] == 0
    f = {x["feature"]: x for x in rep["features"]}
    assert f["Web DLP"]["verdict"] == m.PRESENT and f["Web DLP"]["item_count"] > 0
    assert f["Workflow Automation / ZWA (DLP incidents)"]["verdict"] == m.NOT_PROBED
    assert any(e["path"] == "/zia/api/v1/users/auditors" and e["verdict"] == m.NO_PERMISSION for e in rep["endpoints"])


# ── exports ──────────────────────────────────────────────────────────
def test_csv_exports_neutralise_formula_cells():
    """CWE-1236 · ASVS V5.2.2: a cell that starts like a formula is quoted in both CSV tables."""
    rep = {"features": [{"feature": "=HYPERLINK(\"http://x\")", "product": "zia", "verdict": m.PRESENT, "detail": "@SUM(1)"}],
           "endpoints": [{"product": "zia", "path": "/zia/api/v1/x", "verdict": m.ERROR, "field_names": ["+cmd"], "error": "-2+3"}]}
    for what in ("features", "endpoints"):
        rows = list(csv.reader(io.StringIO(m.to_csv(rep, what))))[1:]
        assert all(not str(c).startswith(("=", "+", "@", "-")) for r in rows for c in r if c and not c.startswith("/")), rows


# ── saved maps ───────────────────────────────────────────────────────
def _tiny_map(at="2026-11-07T10:00:00+00:00"):
    return {"status": "done", "tenant_label": "acme (production)", "sign_in": "OneAPI", "started_at": at, "rps": 1.0, "sdk": "zscaler-sdk-python 1.11.3",
            "features_only": False, "products": ["zia"], "plan_hash": "ab", "duration_seconds": 3.0, "counts": {"planned": 1, "read": 1, "present": 1},
            "features": [{"feature": "Web DLP", "product": "zia", "verdict": m.PRESENT, "deciding_endpoint": "/zia/api/v1/webDlpRules", "status": 200,
                          "item_count": 2, "detail": "", "info": []}],
            "endpoints": [{"product": "zia", "path": "/zia/api/v1/webDlpRules", "params": [], "sdk_method": "a.b", "purpose": "decider", "status": 200,
                           "verdict": m.PRESENT, "item_count": 2, "total_reported": None, "shape": "list", "field_names": ["id"], "other_names": 0,
                           "error_code_hint": None, "error": None}], "skipped_count": 0, "skipped_by_reason": {}}


def test_saved_maps_round_trip_per_tenant_keep_the_newest_and_forget(tmp_path):
    """CWE-312 · ASVS V6.1.1: maps are kept per tenant label with their time, the newest KEEP_PER_TENANT, and can be forgotten."""
    p = str(tmp_path / "m.json")
    for i in range(m.KEEP_PER_TENANT + 2):
        m.save("acme (production)", _tiny_map(f"2026-11-0{i + 1}T10:00:00+00:00"), p, profile_id="prof-1")
    m.save("other (production)", _tiny_map(), p)
    got = m.load("acme (production)", p)
    assert [g["started_at"][:10] for g in got] == ["2026-11-03", "2026-11-04", "2026-11-05"]
    assert m.profile_of("acme (production)", p) == "prof-1" and m.profile_of("other (production)", p) == ""
    assert len(m.load("other (production)", p)) == 1
    assert m.forget("acme (production)", p) == 3 and m.load("acme (production)", p) == []
    assert os.stat(p).st_mode & 0o077 == 0


def test_a_saved_file_is_sealed_when_store_encryption_is_on(tmp_path):
    """CWE-311 · ASVS V6.1.1: the store goes through store_crypto like the app's other stores."""
    import store_crypto
    p = str(tmp_path / "m.json")
    m.save("acme (production)", _tiny_map(), p)
    raw = open(p, encoding="utf-8").read()
    assert store_crypto.is_sealed(raw) == store_crypto.enabled()
    assert m.load("acme (production)", p)


def test_a_hand_edited_file_cannot_carry_text_or_crash_the_page(tmp_path):
    """CWE-20 · ASVS V5.1.3: a saved map is read back as untrusted; unknown fields and bad types are dropped."""
    p = str(tmp_path / "m.json")
    bad = _tiny_map()
    bad["endpoints"][0].update(path="javascript:alert(1)", extra="<script>")
    bad["endpoints"].append(dict(_tiny_map()["endpoints"][0], field_names=["ok", "<b>x</b>", 5], verdict="evil", error="x" * 5000, status="200"))
    bad["evil"] = "<script>"
    with open(p, "w", encoding="utf-8") as f:
        json.dump({"tenants": {"acme (production)": ["junk", 5, {"started_at": "nope"}, bad]}, "profiles": {"acme (production)": "../etc"}}, f)
    got = m.load("acme (production)", p)
    assert len(got) == 1 and len(got[0]["endpoints"]) == 1 and "evil" not in got[0]
    e = got[0]["endpoints"][0]
    assert e["field_names"] == ["ok"] and e["verdict"] == m.NOT_PROBED and len(e["error"]) <= 120 and e["status"] is None
    assert m.profile_of("acme (production)", p) == ""
    assert m.load("acme (production)", str(tmp_path / "missing.json")) == []


def test_the_assistant_view_is_counts_and_verdicts():
    """ASVS V8.3.4: the assistant gets counts, the feature table and endpoints that did not answer; no field names or values."""
    out = m.for_assistant(_tiny_map())
    assert out["counts"]["present"] == 1 and out["features"][0]["verdict"] == m.PRESENT and out["present_by_product"] == {"zia": 1}
    assert "field_names" not in json.dumps(out)


# ── the Scope page binds the map ─────────────────────────────────────
def test_an_unticked_product_is_never_planned_and_is_listed_as_skipped_not_in_scope():
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: with only ZPA ticked, no other product's endpoint is planned; each is skipped as 'not in scope' with the link."""
    p = m.plan(scopes=["zpa"])
    assert p["reads"] and {r["product"] for r in p["reads"]} == {"zpa"}
    gone = [s for s in p["skipped"] if s["product"] == "zia"]
    assert gone and {s["reason"] for s in gone} == {m.REASON_SCOPE} == {"skipped: not in scope"}
    assert {n["product"] for n in p["not_in_scope"]} >= {"zia", "zcc", "zdx"} and p["scope_link"].startswith("/#") and p["scope_applied"] is True
    assert m.plan(scopes=[])["reads"] == [] and m.plan(scopes=[])["count"] == 0
    assert m.plan(scopes=["DLP", "ZPA"])["reads"] == []                            # keys are exact, as the Scope page sends them (fail closed)
    assert m.plan()["count"] > p["count"] and m.plan()["scope_applied"] is False   # no selection: the library default


def test_a_run_never_sends_a_read_for_a_product_that_is_not_ticked():
    """ASVS V4.1.3 · CWE-272: the client sees no path of an unticked product, and the feature table says why it was not checked."""
    fc = FakeClient(default=([], 200))
    rep = m.run(fc, m.plan(scopes=["zia_extras"]), label="t", throttle=_fast())
    assert fc.calls and all(c[0].startswith("raw:/zia/") for c in fc.calls)
    rows = {f["feature"]: f for f in rep["features"]}
    assert rows["ZDX"]["detail"] == m.REASON_SCOPE and rows["ZDX"]["verdict"] == m.NOT_PROBED and rows["Cloud Firewall"]["verdict"] == m.PRESENT


# ── error words and field names: nothing a tenant wrote ──────────────
@pytest.mark.parametrize("body", [
    {"id": "ALICE_SMITH_X"}, {"code": "ALICE_SMITH_X"}, {"errorCode": "FEATURE_NOT_ALICE"}, {"error": "user alice@example.com ACME_CORP_ADMIN"},
    {"error": '{"id":"JSMITH_PAYROLL","message":"x"}'}, {"message": "FEATURE_NOT_ACME_PAYROLL_TENANT"}, "ACME_PAYROLL_ADMIN", None, 5, [],
])
def test_an_error_hint_is_only_ever_a_known_word_or_the_generic_one(body):
    """CWE-209 · CWE-200: the verifier's reproductions ({"id":"ALICE_SMITH_X"} and other tenant text shaped like a code) give the generic hint, never the text."""
    assert m.error_hint(body) == m.GENERIC_HINT


@pytest.mark.parametrize("body,word", [
    ({"code": "NOT_SUBSCRIBED"}, "NOT_SUBSCRIBED"), ({"errorCode": "feature_not_enabled"}, "FEATURE_NOT_ENABLED"),
    ({"error": "This feature is not enabled for your org (acme)"}, "FEATURE_NOT_ENABLED"), ({"message": "You are not licensed for X"}, "NOT_LICENSED"),
    ({"error": "NOT_ENABLED"}, "NOT_ENABLED"),
])
def test_known_error_words_and_phrases_are_recognised_and_always_from_the_list(body, word):
    """ASVS V7.4.1: the allow-list still tells a licensing answer from other errors; what comes out is a list member."""
    assert m.error_hint(body) == word and word in m.KNOWN_ERROR_CODES


@pytest.mark.parametrize("name", ["jsmith@acme.com", "acme.example.com", "123e4567-e89b-12d3-a456-426614174000", "9988776655", "ALICE_SMITH", "ID", "USER_42",
                                  "deadbeef00", "Tenant Name", "a" * 41, "key123456", "_x", "7up", "x-y"])
def test_a_field_name_that_looks_like_data_is_not_kept(name):
    """CWE-200: an email, domain, UUID, number, UPPER_SNAKE code, hex run, spaced or long word is counted, never shown."""
    assert m.safe_name(name) is None
    assert m.summarise([{name: 1, "id": 2}])["fields"] == ["id"] and m.summarise([{name: 1}])["other_names"] == 1


@pytest.mark.parametrize("name", ["id", "name", "enabled", "deviceGroupType", "client_secret", "ipv6", "sha256", "x509Cert"])
def test_ordinary_field_names_are_kept(name):
    """Boundary: camelCase, snake_case and short digits are the API's own spelling."""
    assert m.safe_name(name) == name


def test_an_object_keyed_by_tenant_text_keeps_no_key():
    """CWE-200: the verifier's reproduction: {"jsmith": {...}, "acme": {...}} is a map from names to records: its keys are data and only counted."""
    s = m.summarise({"jsmith": {"role": "a", "mail": "x"}, "acme": {"role": "b"}, "alice": {"role": "c"}})
    assert s["fields"] == [] and s["other_names"] == 3 and "jsmith" not in json.dumps(s)
    assert m.summarise({"jsmith": {"role": "a"}, "totalCount": 3})["fields"] == ["jsmith", "totalCount"]   # one record is a field, as an object's own


# ── action-named reads are never sent ────────────────────────────────
@pytest.mark.parametrize("path", ["/zia/api/v1/azure/refreshConnectionStatus", "/zia/api/v1/azure/virtualHubSync", "/zia/api/v1/azure/unConfigureTunnelStatus",
                                  "/zia/api/v1/casbTenant/scanInfo", "/zia/api/v1/x/triggerRun", "/zia/api/v1/ipv6/enable", "/zia/api/v1/a/rotateKey"])
def test_a_get_that_names_an_action_is_skipped(path):
    """CWE-441 · ASVS V4.1.5: a GET named like an action (refresh, sync, unconfigure, scan, rotate...) is never read, even if the SDK lists it as a GET."""
    entry = {"path": path, "path_params": [], "probeable": True}
    assert m.skip_reason(entry) == m.REASON_SENSITIVE


def test_no_endpoint_of_the_catalogue_that_names_an_action_is_planned():
    """CWE-441: scan every catalogue path: any with an action verb in its words is skipped, and none is in the full plan."""
    idx = m._entry_index()
    named = [p for p in idx if m.action_words(p)]
    assert {"/zia/api/v1/azure/refreshConnectionStatus", "/zia/api/v1/azure/virtualHubSync", "/zia/api/v1/azure/unConfigureTunnelStatus",
            "/zia/api/v1/casbTenant/scanInfo"} <= set(named)
    assert all(m.skip_reason(idx[p]) for p in named)
    planned = {r["path"] for r in m.plan()["reads"]}
    assert not planned & set(named) and not any(m.action_words(p) for p in planned)


def test_plain_words_that_contain_a_verb_are_not_mistaken_for_one():
    """Boundary: 'enabled', 'startup' or 'running' are not the verbs; only whole camelCase words count."""
    assert m.action_words("/zia/api/v1/enabledRules/startupConfig") == [] and m.action_words("/zia/api/v1/x/syncInfo") == ["sync"]


# ── Stop reaches the request in flight; retries count against the speed ──
def test_stop_does_not_wait_for_the_request_in_flight():
    """CWE-400 · ASVS V11.1.4: Stop ends the run while a request is still waiting for the tenant: the client is told to stop and the late answer is dropped."""
    release, started, stopped_called = threading.Event(), threading.Event(), threading.Event()

    class Slow(FakeClient):
        def get(self, ep, p=None):
            started.set()
            release.wait(10)
            return ([{"id": 1}], 200)

        def stop(self):
            stopped_called.set()

    ev = threading.Event()
    fc = Slow()
    threading.Thread(target=lambda: (started.wait(5), ev.set()), daemon=True).start()
    try:
        with pytest.raises(m.Stopped):
            m.run(fc, _plan(features_only=True), label="t", cancel=ev, throttle=_fast())
        assert stopped_called.is_set() and not release.is_set()      # it returned while the request was still open
    finally:
        release.set()
    m._RUN_LOCK.acquire(); m._RUN_LOCK.release()                    # the lock was released by the run


def test_a_read_after_stop_sends_nothing():
    """CWE-400: once stopped, the read-only client refuses every further read without touching the client."""
    fc = FakeClient(default=([], 200))
    ro = m.ReadOnlyClient(fc, ["raw:/zia/api/v1/a"])
    ro.stop()
    assert ro.get("raw:/zia/api/v1/a") == (None, 0) and fc.calls == []


def test_the_clients_own_retries_count_against_the_speed():
    """CWE-770: a read that really sent 3 requests (two retries) makes the next read wait 3 intervals, so the rate never exceeds the setting."""
    now, slept = [0.0], []
    th = m.Throttle(1, clock=lambda: now[0], sleeper=lambda s: (slept.append(round(s, 3)), now.__setitem__(0, now[0] + s)))

    class Retrying(FakeClient):
        requests_made = 0

        def get(self, ep, p=None):
            self.requests_made += 3 if not self.calls else 1
            return super().get(ep, p)

    fc = Retrying(default=([], 200))
    m.run(fc, _plan(features_only=True, scopes=["zia_extras"]) | {"reads": _plan(features_only=True, scopes=["zia_extras"])["reads"][:3]}, label="t", throttle=th)
    assert slept[0] == 3.0 and slept[1] == 1.0       # after the 3-request read: 3 s; after a single request: 1 s
    th2 = m.Throttle(1, clock=lambda: 0.0, sleeper=lambda s: None)
    th2.wait(); th2.account(1)
    assert th2._next == 1.0
