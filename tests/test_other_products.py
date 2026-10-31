"""Other Zscaler products, read-only (other_products.py, zscaler_other_products_checks.py).

Zero Trust Branch, External Attack Surface Management, Business Insights,
Zero Trust Cellular and Microsegmentation: every request is built by the
installed SDK's own list/get method and sent through the app's raw client;
each product is read only when its own Scope page key is ticked; secrets are
dropped and people, devices and SIMs counted; a product the tenant does not
own is "not licensed", a refused one "not permitted", never judged. Offline
only: fakes, the sample tenant and snapshots; no network.
"""
from __future__ import annotations

import ast
import copy
import inspect
import io
import json
import os
import threading
import time
import zipfile
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import offline_tenant as ot
import other_products as op
import sample_tenant
from test_xlsx_writer import read_workbook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NOW = datetime(2026, 10, 31, tzinfo=timezone.utc)
# Values that must never leave the read, wherever they sit in an answer.
CANARIES = ("NONCE-KEY-CANARY-7731", "SITE-SECRET-CANARY-1290", "RANSOM-TOKEN-CANARY-4410", "ACTIVATION-CANARY-5521",
            "TOTP-CANARY-8812", "WG-KEY-CANARY-3306")
PEOPLE = ("alert-person@canary.example", "report-person@canary.example", "8988-ICCID-CANARY-0001")


def _answers():
    """The sample's answers with canary secrets and people planted in them."""
    r = copy.deepcopy(sample_tenant.other_products())
    r["/zms/graphql/ListNonces"]["data"]["nonces"]["nodes"][0]["key"] = CANARIES[0]
    r["/ztb/api/v2/Site"]["result"]["sites"][0]["secret_key"] = CANARIES[1]
    r["/ztb/api/v3/ransomware-kill/state"]["result"]["token"] = CANARIES[2]
    r["/ztb/api/v3/ransomware-kill/state"]["cluster_token"] = CANARIES[2]
    r["/ztb/api/v3/api-key-auth/list"]["rows"][0]["key"] = CANARIES[0]
    r["/zcell/config/api/v1/customers/{zcellCustomerId}"]["activationCode"] = CANARIES[3]
    r["/zms/graphql/ListAgentGroups"]["data"]["agentGroups"]["nodes"][0]["totpSecret"] = CANARIES[4]
    r["/ztb/api/v3/CloudGateway/hubs"]["result"][0]["cluster_info"]["gateways"][0]["sgw_wireguard_public_key"] = CANARIES[5]
    r["/zcell/config/api/v1/customers/{zcellCustomerId}/anomaly-policy"]["content"][0]["jsonData"]["alerts"][0]["recipients"] = [PEOPLE[0]]
    r["/bi/api/v1/reports/customapps"][0]["delivery_information"]["emails"] = [PEOPLE[1]]
    r["/zcell/config/api/v1/customers/{zcellCustomerId}/sim-location-groups"]["content"][0]["trackedDevices"] = [PEOPLE[2]]
    return r


class Fake:
    """The raw client's interface over a table of answers; records every request."""

    def __init__(self, answers=None, status=None, legacy=False, customer_id="72000000000000001"):
        self.answers = {ot.normalize_path(k): v for k, v in (answers if answers is not None else _answers()).items()}
        self.status = dict(status or {})
        self.requests = []
        self.legacy = legacy
        self.customer_id = customer_id

    def _answer(self, path):
        p = ot.normalize_path(path)
        for prefix, code in self.status.items():
            if p.startswith(prefix):
                return {"message": f"refused {code}"}, code
        if p in self.answers:
            return copy.deepcopy(self.answers[p]), 200
        return {"message": "no such path"}, 404

    def get(self, ep, p=None):
        self.requests.append(("GET", ep, dict(p or {})))
        return self._answer(ep)

    def post(self, ep, body=None):
        self.requests.append(("POST", ep, body))
        return self._answer(f"{ep}/{(body or {}).get('operationName')}")


IDS = {"zcell": "zc-72000001", "zms": "72000000000000001"}


def _report(fake=None, products=op.SCOPE_KEYS, ids=IDS):
    fake = fake or Fake()
    return op.analyse(op.read(fake, op.scope_for(list(products)), ids), now=NOW), fake


def _status(rep):
    return {c["id"]: c["status"] for p in rep["products"].values() for c in p["checks"]}


# ── the SDK: inventory, request building, read-only ─────────────────────

def _public_methods(package):
    import importlib
    pkg_dir = os.path.dirname(importlib.import_module(f"zscaler.{package}").__file__)
    svc = importlib.import_module(f"zscaler.{package}.{package}_service")
    service_cls = next(v for k, v in vars(svc).items() if inspect.isclass(v) and k.endswith("Service"))
    found = set()
    for attr, prop in inspect.getmembers(service_cls, lambda m: isinstance(m, property)):
        cls = inspect.signature(prop.fget).return_annotation
        if isinstance(cls, str):
            src = open(inspect.getsourcefile(service_cls), encoding="utf-8").read()
            mod_name = next(n.module for n in ast.walk(ast.parse(src)) if isinstance(n, ast.ImportFrom) and any(a.name == cls for a in n.names))
            cls = getattr(importlib.import_module(mod_name), cls)
        for name, fn in inspect.getmembers(cls, inspect.isfunction):
            fn = inspect.unwrap(fn)   # zcell's @zcell_params wraps its list methods
            if not name.startswith("_") and fn.__qualname__.startswith(cls.__name__) and os.path.dirname(inspect.getsourcefile(fn)) == pkg_dir:
                found.add(f"{attr}.{name}")
    return found


@pytest.mark.parametrize("product", op.SCOPE_KEYS)
def test_the_inventory_lists_every_method_of_the_installed_sdk_package(product):
    """SSDF PW.4.1 · CWE-1104 · ASVS V14.2.1: SDK_INVENTORY names every public method of the product's SDK package (1.11.3), each once."""
    listed = [m for m, _verb, _use in op.SDK_INVENTORY[product]]
    assert len(listed) == len(set(listed))
    assert set(listed) == _public_methods(op.SDK_PACKAGE[product])


def test_every_read_is_an_sdk_list_or_get_marked_read_here_and_no_write_is_ever_called():
    """ASVS V1.4.1 · CWE-285 · CWE-1059: each read in READS uses a method the inventory marks "read here"; every write and secret method is marked never called and appears in no read."""
    use = {p: {m: u for m, _v, u in op.SDK_INVENTORY[p]} for p in op.SCOPE_KEYS}
    for product, specs in op.READS.items():
        for _key, _label, method, call in specs:
            assert use[product][method] == "read here", (product, method)
            assert method.split(".", 1)[1].startswith(("list_", "get_"))
            assert "totp" not in method and method != "nonces.get_nonce"
    for product in op.SCOPE_KEYS:
        for m, verb, u in op.SDK_INVENTORY[product]:
            if u.startswith(("write", "secret")):
                assert m not in {s[2] for s in op.READS[product]}


def test_the_requests_are_the_sdks_own_paths_and_queries():
    """ASVS V14.2.1 · CWE-1104: the captured requests carry the SDK's paths, camelCased query keys and GraphQL queries (never a mutation)."""
    ids = dict(IDS, org="org-1")
    got = {(p, k): op.sdk_request(p, lambda s, c=c: c(s, ids), ids) for p, specs in op.READS.items() for k, _l, _m, c in specs}
    assert got[("ztb", "sites")]["url"] == "/ztb/api/v2/Site/" and got[("ztb", "sites")]["params"] == {"page": 1, "limit": op.MAX_ROWS}
    assert got[("ztb", "api_keys")]["url"] == "/ztb/api/v3/api-key-auth/list"
    assert got[("easm", "findings")]["url"] == "/easm/easm-ui/v1/organizations/org-1/findings"
    assert got[("zbi", "report_configs")]["url"] == "/bi/api/v1/reports/customapps"
    anomaly = got[("zcell", "anomaly_policies")]
    assert anomaly["url"] == "/zcell/config/api/v1/customers/zc-72000001/anomaly-policy"
    assert {"startDateTime", "endDateTime"} <= set(anomaly["params"])
    zms = [r for (p, _k), r in got.items() if p == "zms"]
    assert {r["body"]["operationName"] for r in zms} == set(op.ZMS_OPERATIONS)
    for r in zms:
        assert r["method"] == "POST" and r["url"] == "/zms/graphql" and r["body"]["query"].lstrip().startswith("query ")
        assert "mutation" not in r["body"]["query"] and r["body"]["variables"]["customerId"] == "72000000000000001"
    assert all(r["method"] == "GET" for (p, _k), r in got.items() if p != "zms")


def test_the_capture_never_sends_and_a_non_read_is_refused():
    """ASVS V1.4.1 · CWE-285: sdk_request only builds the request; _send refuses anything but a GET or a listed GraphQL query."""
    fake = Fake()
    op.sdk_request("ztb", lambda s: s.site.list_sites())
    assert fake.requests == []
    for req in ({"method": "DELETE", "url": "/ztb/api/v2/Site/x", "params": {}, "body": None},
                {"method": "POST", "url": "/zms/graphql", "params": {}, "body": {"operationName": "DeleteAgent", "query": "mutation { x }"}},
                {"method": "POST", "url": "/zms/graphql", "params": {}, "body": {"operationName": "ListAgents", "query": "mutation ListAgents { x }"}}):
        with pytest.raises(RuntimeError):
            op._send(fake, req)
    assert fake.requests == []


# ── what the checks find ────────────────────────────────────────────────

def test_the_sample_tenant_gives_every_check_a_verdict_and_the_findings_named():
    """ASVS V1.14.1 · CWE-1059: on the sample each check gives the expected verdict, with why, what to do and a source on every finding."""
    rep, _ = _report()
    st = _status(rep)
    assert st == {"ZTB.1": "REVIEW", "ZTB.2": "REVIEW", "ZTB.3": "FAIL", "ZTB.4": "REVIEW", "ZTB.5": "INFO",
                  "EASM.1": "PASS", "EASM.2": "FAIL", "EASM.3": "FAIL", "EASM.4": "REVIEW",
                  "ZBI.1": "REVIEW", "ZBI.2": "PASS",
                  "ZCELL.1": "PASS", "ZCELL.2": "REVIEW", "ZCELL.3": "REVIEW",
                  "ZMS.1": "REVIEW", "ZMS.2": "FAIL", "ZMS.3": "REVIEW", "ZMS.4": "REVIEW", "ZMS.5": "REVIEW", "ZMS.6": "REVIEW"}
    assert rep["counts"]["total"] == len(rep["findings"]) == 16
    assert [f["severity"] for f in rep["findings"]] == sorted((f["severity"] for f in rep["findings"]), key=op.SEVERITIES.index)
    for f in rep["findings"]:
        assert f["why"] and f["fix"] and f["source"], f
    by = {f["id"]: f for f in rep["findings"]}
    assert "legacy-ftp" in by["ZMS.1"]["detail"] and "App servers" in by["ZMS.2"]["detail"] and "anything-goes" in by["ZMS.4"]["detail"]
    assert "Boise dock" in by["ZTB.1"]["detail"] and "terraform-ci" in by["ZTB.4"]["detail"]
    assert "Directive 19-02" in by["EASM.2"]["source"] and "tracking." in by["EASM.3"]["detail"]


def test_fixing_the_tenant_turns_every_finding_into_a_pass():
    """ASVS V1.14.1 · CWE-1059: the same checks pass once the sample is put right (each finding is driven by the data, not fixed)."""
    a = _answers()
    a["/ztb/api/v2/Site"]["result"]["sites"][2].update(site_status="online", template_id="tpl-1")
    a["/ztb/api/v2/alarm"]["result"]["alarms"][0]["status"] = "acknowledged"
    a["/ztb/api/v2/alarm"]["result"]["alarms"][1]["status"] = "acknowledged"
    a["/ztb/api/v3/api-key-auth/list"]["rows"][0]["created_at"] = 1793404800 - 10 * 86400
    for f in a["/easm/easm-ui/v1/organizations/org-larkspur-0001/findings"]["results"]:
        f["status"] = "remediated"
    a["/easm/easm-ui/v1/organizations/org-larkspur-0001/lookalike-domains"]["results"][0]["status"] = "taken_down"
    a["/bi/api/v1/customapps"][1]["signatures"] = [{"type": "DOMAIN", "value": "telematics.example"}]
    pol = a["/zcell/config/api/v1/customers/{zcellCustomerId}/anomaly-policy"]["content"]
    pol[1]["jsonData"]["alerts"] = [{"alertType": "EMAIL", "recipients": ["ops@x.example"]}]
    a["/zcell/config/api/v1/customers/{zcellCustomerId}/sim/analytics/summary"].update(active=58, inactive=2)
    a["/zms/graphql/ListAgents"]["data"]["agents"]["nodes"][2]["connectionStatus"] = "CONNECTED"
    for g in a["/zms/graphql/ListAgentGroups"]["data"]["agentGroups"]["nodes"]:
        g.update(tamperProtectionStatus="ENABLED", agentAutoUpgrade=True)
    a["/zms/graphql/ListNonces"]["data"]["nonces"]["nodes"][1]["maxUsage"] = 3
    for r in a["/zms/graphql/ListDefaultPolicyRules"]["data"]["defaultPolicyRules"]["nodes"]:
        r["action"] = "BLOCK"
    a["/zms/graphql/ResourceProtectionStatus"]["data"]["resourceProtectionStatus"]["nodes"][0]["protectedPercentage"] = 95
    rep, _ = _report(Fake(a))
    assert rep["findings"] == [], rep["findings"]
    assert {s for s in _status(rep).values()} <= {"PASS", "INFO"}


def test_a_disconnected_agent_is_not_read_as_connected():
    """CWE-697 · ASVS V1.14.1: status words match whole (DISCONNECTED is not CONNECTED, offline is not online)."""
    assert op._ONLINE.search("CONNECTED") and op._ONLINE.search("online")
    assert not op._ONLINE.search("DISCONNECTED") and not op._ONLINE.search("offline") and not op._ONLINE.search("not_connected")


# ── secrets and people ──────────────────────────────────────────────────

def test_no_secret_or_person_reaches_the_report_the_workbook_or_the_json():
    """ASVS V8.3.4 · ASVS V8.3.5 · CWE-200 · CWE-312 · CWE-359: keys, secrets, tokens, activation codes, TOTP and WireGuard keys are dropped; recipients, SIMs and devices are counted."""
    rep, _ = _report()
    xlsx = op.workbook(rep)
    with zipfile.ZipFile(io.BytesIO(xlsx)) as z:
        sheets = "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())
    blob = json.dumps(rep) + sheets + json.dumps(op.scrub(rep))
    for s in CANARIES + PEOPLE:
        assert s not in blob, s
    inv = rep["products"]
    assert inv["zcell"]["inventory"]["anomaly_policies"][0]["recipients"] == 1
    assert inv["zbi"]["inventory"]["report_configs"][0]["recipients"] == 1
    assert inv["zcell"]["inventory"]["location_groups"][0]["tracked_sims"] == 1


def test_scrub_drops_secret_shaped_keys_at_any_depth():
    """ASVS V8.3.4 · CWE-312: a key, secret, token, password, OTP or credential field is dropped wherever it is, names stay."""
    out = op.scrub({"a": [{"key": "x", "apiKey": "y", "nested": {"client_secret": "z", "refresh_token": "t", "otp": "1", "name": "keep"}}],
                    "provisioningKey": "p", "wireguardPublicKey": "w"})
    assert out == {"a": [{"nested": {"name": "keep"}}]}


def test_a_snapshot_keeps_the_answers_without_any_secret_and_opens_offline():
    """ASVS V8.3.4 · CWE-312 · CWE-653: snapshot capture keeps each product's answers (ZMS by operation, ZCell id keyed) with secrets dropped, and the opened snapshot serves the same report."""
    fake = Fake()
    fake.zcell_customer_id = "zc-72000001"
    got, unread = {}, []
    for p in op.SCOPE_KEYS:
        g, u = op.snapshot_answers(fake, p, op.ids_for(fake))
        got.update(g)
        unread += u
    assert unread == []
    keys = {ot.normalize_path(k) for k in got}
    assert "/zms/graphql/ListNonces" in keys and "/zcell/config/api/v1/customers/{zcellCustomerId}/regions" in keys
    assert all(ot.valid_path(k) for k in keys)
    blob = json.dumps(got)
    for s in CANARIES:
        assert s not in blob, s
    store = ot.OfflineStore("snap-0000000000000001", "snapshot", {k: {"status": 200, "body": ot.scrub(v)} for k, v in
                                                                  ((ot.normalize_path(k), v) for k, v in got.items())}, {})
    raw = ot.OfflineRawClient(store, {"client_id": "offline-x"})
    rep = op.analyse(op.read(raw, op.scope_for(op.SCOPE_KEYS), op.ids_for(raw)), now=NOW)
    assert _status(rep) == _status(_report()[0])


def test_the_offline_store_answers_only_listed_graphql_queries():
    """ASVS V1.4.1 · CWE-285 · CWE-653: offline, a ZMS query is answered from /zms/graphql/<operation>; a mutation or an unknown operation is refused."""
    st = ot.sample_store(reset=True)
    q = op.sdk_request("zms", lambda s: s.agents.list_agents(customer_id="1"))["body"]
    code, body = st.answer_write("POST", "/zms/graphql", q)
    assert code == 200 and body["data"]["agents"]["nodes"]
    for bad in (dict(q, operationName="DeleteAgents"), dict(q, query="mutation ListAgents { x }"), {"operationName": "ListAgents"}, "x"):
        code, _ = st.answer_write("POST", "/zms/graphql", bad)
        assert code == 403
    assert st.writes == 0


# ── availability: not licensed, not permitted, not given ────────────────

def test_a_product_the_tenant_does_not_own_is_not_licensed_and_not_judged():
    """ASVS V1.14.1 · CWE-754: a 404 on the product's first list is "N/A — not licensed" (INFO), no other list is read, no finding."""
    fake = Fake(status={"/ztb/": 404, "/easm/": 404})
    rep, _ = _report(fake, products=("ztb", "easm"))
    for p in ("ztb", "easm"):
        assert rep["products"][p]["status"] == "not_licensed"
        assert all(c["status"] == "INFO" and "not licensed" in c["detail"] for c in rep["products"][p]["checks"])
    assert rep["findings"] == []
    assert sum(1 for m, ep, _ in fake.requests if ep.startswith("/ztb/")) == 1


def test_a_refused_product_is_not_permitted_and_never_judged():
    """ASVS V4.1.1 · CWE-285 · CWE-754: every list refused (403) is "not permitted" with the permission to ask for, no finding."""
    rep, _ = _report(Fake(status={"/zms/": 403}), products=("zms",))
    p = rep["products"]["zms"]
    assert p["status"] == "not_permitted" and "read access" in p["note"]
    assert rep["findings"] == [] and {c["status"] for c in p["checks"]} == {"INFO"}


def test_zcell_and_zms_need_their_customer_ids_and_classic_sign_in_reads_nothing():
    """ASVS V5.1.3 · CWE-20: ZCell without its customer ID and ZMS without any are not read; the classic ZIA sign-in reads none of the five."""
    fake = Fake(customer_id="")
    rep, _ = _report(fake, products=("zcell", "zms"), ids={"zcell": "", "zms": ""})
    assert rep["products"]["zcell"]["note"] == op.NEEDS_ZCELL_ID and rep["products"]["zms"]["note"] == op.NEEDS_ZMS_ID
    assert fake.requests == []
    legacy = Fake(legacy=True)
    rep, _ = _report(legacy)
    assert legacy.requests == [] and {p["status"] for p in rep["products"].values()} == {"needs"}


@pytest.mark.parametrize("bad", ["../x", "a/b", "a b", "x" * 65, "a?b=1", "%2e%2e", ""])
def test_a_malformed_customer_id_never_reaches_a_path(bad):
    """ASVS V5.1.3 · ASVS V12.3.1 · CWE-22 · CWE-20: only letters, digits, - and _ (1–64) make a customer ID; anything else is dropped."""
    assert not op.valid_id(bad)
    assert op.ids_for(Fake(customer_id=bad), zcell_id=bad, zms_id=bad) == {"zcell": "", "zms": ""}


# ── scope, Stop, untrusted answers ──────────────────────────────────────

def test_only_the_ticked_products_are_read():
    """ASVS V4.1.3 · CWE-272: with only Business Insights ticked nothing of the other four is requested; nothing ticked reads nothing."""
    fake = Fake()
    _report(fake, products=("zbi",))
    assert fake.requests and all(ep.startswith("/bi/") for _m, ep, _p in fake.requests)
    assert op.scope_for([])["read"] is False and op.scope_for(["dlp", "zpa"])["products"] == []
    assert set(op.scope_for(["zms"])["not_in_scope"]) == {"ztb", "easm", "zbi", "zcell"}


def test_stop_ends_the_read_with_nothing_more_read():
    """ASVS V11.1.4 · CWE-400: Stop set before a list is read raises Stopped and sends nothing more."""
    fake, cancel = Fake(), threading.Event()
    cancel.set()
    with pytest.raises(op.Stopped):
        op.read(fake, op.scope_for(op.SCOPE_KEYS), IDS, cancel=cancel)
    assert fake.requests == []


@pytest.mark.parametrize("body", [None, "text", 7, [], {}, {"result": "x"}, {"data": None}, {"results": {"a": 1}}, {"content": "x"},
                                  {"result": {"sites": ["x", None, 3]}}])
def test_odd_answers_are_parsed_defensively(body):
    """ASVS V5.1.1 · CWE-20 · CWE-754: an answer of an unexpected shape gives empty rows and checks that do not crash."""
    answers = {k: body for k in sample_tenant.other_products()}
    rep, _ = _report(Fake(answers))
    assert set(_status(rep)) == {cid for p in op.CHECKS.values() for cid, _t, _f in p}
    assert "ERROR" not in set(_status(rep).values())


def test_a_long_list_is_capped_and_long_text_is_cut():
    """ASVS V5.1.4 · CWE-400 · CWE-770: at most MAX_ROWS rows are kept per list and each text field is cut."""
    a = _answers()
    a["/ztb/api/v2/groups"]["result"]["groups"] = [{"name": "g" * 5000, "type": "device"} for _ in range(op.MAX_ROWS + 50)]
    rep, _ = _report(Fake(a), products=("ztb",))
    groups = rep["products"]["ztb"]["inventory"]["groups"]
    assert len(groups) == op.MAX_ROWS and len(groups[0]["name"]) <= op._TEXT_MAX


def test_a_formula_in_a_tenant_name_stays_text_in_the_workbook():
    """ASVS V5.3.10 · CWE-1236 · WSTG-INPV-15: a name that starts like a formula is written as quoted text, never a formula."""
    a = _answers()
    a["/ztb/api/v2/Site"]["result"]["sites"][2]["display_name"] = '=HYPERLINK("http://x.invalid","y")'
    rep, _ = _report(Fake(a), products=("ztb",))
    wb = read_workbook(op.workbook(rep))
    cells = [c for rows in wb.values() for row in rows for c in row if isinstance(c, str) and "HYPERLINK" in c]
    assert cells and all(not c.startswith("=") for c in cells)
    with zipfile.ZipFile(io.BytesIO(op.workbook(rep))) as z:
        assert not any("<f>" in z.read(n).decode("utf-8", "replace") for n in z.namelist() if n.endswith(".xml"))


# ── the assessment ─────────────────────────────────────────────────────

def test_the_assessment_checks_read_each_product_once_and_score_through_the_raw_client():
    """ASVS V1.14.1 · CWE-1059: OTHER_REG runs each product's checks from one read per run; FAIL and REVIEW map to the scored statuses."""
    import zscaler_other_products_checks as oc
    from dlp_assessment_full_auto import R
    fake = Fake()
    fake.zcell_customer_id = "zc-72000001"
    results = {cid: fn(fake) for cid, _sec, _label, fn in oc.OTHER_REG}
    assert len(results) == 20 and results["ZMS.2"].status == R.FAIL and results["ZBI.2"].status == R.PASS
    assert results["ZTB.1"].status == R.WARN and "Best Practice:" in results["ZTB.1"].detail and "Source:" in results["ZTB.1"].detail
    per_product = {}
    for _m, ep, _p in fake.requests:
        per_product[ep.split("/")[1]] = per_product.get(ep.split("/")[1], 0) + 1
    assert per_product == {"ztb": 8, "easm": 3, "bi": 3, "zcell": 5, "zms": 10}
    assert {k: len(v) for k, v in oc.BY_SCOPE.items()} == {"ztb": 5, "easm": 4, "zbi": 2, "zcell": 3, "zms": 6}


def test_a_not_licensed_product_is_na_in_the_assessment():
    """ASVS V1.14.1 · CWE-754: a product the tenant does not own gives INFO "N/A — not licensed" checks, outside the score."""
    import zscaler_other_products_checks as oc
    from dlp_assessment_full_auto import R
    fake = Fake(status={"/easm/": 404})
    out = [fn(fake) for cid, _s, _l, fn in oc.OTHER_REG if cid.startswith("EASM.")]
    assert {r.status for r in out} == {R.INFO} and all("not licensed" in r.detail for r in out)


def test_the_assessment_runs_only_the_ticked_products_checks(monkeypatch):
    """ASVS V4.1.3 · CWE-272: /api/assess with ztb ticked runs the five ZTB checks on the sample and reads no other product."""
    import dlp_api_server as srv
    t = TestClient(srv.app)
    t.post("/api/offline/sample", json={})
    try:
        with t.stream("POST", "/api/assess", json={"scopes": ["ztb"], "channels": {}}) as r:
            text = "".join(r.iter_text())
    finally:
        t.post("/api/offline/leave", json={})
    assert r.status_code == 200
    ids = {json.loads(line[6:]).get("id") for line in text.splitlines() if line.startswith("data: {\"id\"")}
    assert ids == {"ZTB.1", "ZTB.2", "ZTB.3", "ZTB.4", "ZTB.5"}
    assert {c[0] for c in srv._get_checks(scopes=["dlp"])} & ids == set()


def test_the_scope_guard_refuses_a_zms_query_when_zms_is_not_selected():
    """ASVS V4.1.3 · CWE-862: dlp_analysis.ScopedClient refuses a Microsegmentation GraphQL POST and the other products' GETs unless ticked."""
    import dlp_analysis
    fake = Fake()
    guard = dlp_analysis.ScopedClient(fake, {}, ["ztb"])
    body, code = guard.post("/zms/graphql", {"operationName": "ListAgents"})
    assert code == 0 and fake.requests == []
    for path in ("/easm/easm-ui/v1/organizations", "/bi/api/v1/customapps", "/zcell/config/api/v1/customers/1"):
        assert guard.get(path)[1] == 0
    assert fake.requests == []
    assert guard.get("/ztb/api/v2/Site/")[1] == 200


# ── the API and the page ───────────────────────────────────────────────

@pytest.fixture
def api():
    import dlp_api_server as srv
    t = TestClient(srv.app)
    t.post("/api/offline/sample", json={})
    yield srv, t
    t.post("/api/offline/leave", json={})


def _wait(t, job, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


ALL = {"scopes": list(op.SCOPE_KEYS), "channels": {}, "from_page": True}


@pytest.mark.parametrize("body,needle", [
    ({"scopes": [], "channels": {}, "from_page": True}, "No other Zscaler product is in scope"),
    ({"scopes": ["dlp", "zpa", "ztw"], "channels": {}, "from_page": True}, "No other Zscaler product is in scope"),
    (dict(ALL, zcell_customer_id="../etc"), "letters, digits"),
    (dict(ALL, zms_customer_id="a b"), "letters, digits"),
])
def test_refused_before_sign_in(monkeypatch, body, needle):
    """ASVS V4.1.3 · ASVS V5.1.3 · CWE-272 · CWE-20 · WSTG-ATHZ-02: nothing in scope or a malformed customer ID is a 400 before any client is built."""
    import dlp_api_server as srv
    built = []
    monkeypatch.setattr(srv, "_raw_client", lambda creds: built.append(creds) or None)
    r = TestClient(srv.app).post("/api/other-products/start", json=dict({"vanity_domain": "acme", "client_id": "c" * 20, "client_secret": "s" * 20}, **body))
    assert r.status_code == 400 and needle in r.json()["detail"] and "Nothing was read" in r.json()["detail"], r.text
    assert built == []


def test_classic_sign_in_and_zcell_alone_without_its_id_are_refused_before_sign_in(monkeypatch):
    """ASVS V4.1.3 · CWE-272: the classic ZIA sign-in and Zero Trust Cellular alone with no ZCell customer ID are 400 before any client is built."""
    import dlp_api_server as srv
    built = []
    monkeypatch.setattr(srv, "_raw_client", lambda creds: built.append(creds) or None)
    t = TestClient(srv.app)
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "k" * 12}
    r = t.post("/api/other-products/start", json=dict(legacy, **ALL))
    assert r.status_code == 400 and "OneAPI" in r.json()["detail"]
    r = t.post("/api/other-products/start", json={"vanity_domain": "acme", "client_id": "c" * 20, "client_secret": "s" * 20,
                                                 "scopes": ["zcell"], "channels": {}, "from_page": True})
    assert r.status_code == 400 and "ZCell customer ID" in r.json()["detail"]
    assert built == []


def test_the_job_reads_the_sample_and_exports_excel_and_json(api):
    """ASVS V1.14.1 · ASVS V8.3.4 · CWE-200: the read on the sample tenant finishes, is kept for its exports, and no export carries a secret."""
    srv, t = api
    r = t.post("/api/other-products/start", json=ALL, headers={"X-Start-Token": "o" * 32})
    assert r.status_code == 200 and r.json()["kind"] == "other", r.text
    snap = _wait(t, r.json()["job_id"])
    res = snap["result"]
    assert snap["status"] == "done" and res["report_id"].startswith("other-") and res["counts"]["total"] == 16
    assert {p["status"] for p in res["products"].values()} == {"read"}
    x = t.get(f"/api/other-products/report/{res['report_id']}/export?format=xlsx")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.openxmlformats")
    wb = read_workbook(x.content)
    assert {"Summary", "Findings", "ZTB Sites", "EASM Findings", "ZMS Agents", "Assumptions"} <= set(wb)
    assert len(wb["Findings"]) == 17
    j = t.get(f"/api/other-products/report/{res['report_id']}/export?format=json")
    assert j.status_code == 200 and json.loads(j.content)["counts"] == res["counts"]
    assert t.get(f"/api/other-products/report/{res['report_id']}/export?format=csv").status_code == 400
    assert t.get("/api/other-products/report/other-nope").status_code == 404
    assert t.get(f"/api/other-products/report/browser-{res['report_id'][6:]}").status_code == 404
    assert ot.sample_store().writes == 0


def test_the_page_is_served_and_every_control_has_help():
    """WCAG 2.2 SC 3.3.2 · SC 4.1.2 · ASVS V5.3.3 · CWE-79: the page is served, escapes every value it writes, and each control has a help-catalogue entry."""
    import dlp_api_server as srv
    page = TestClient(srv.app).get("/report/other-products")
    assert page.status_code == 200 and "no-cache" in page.headers["cache-control"]
    html = page.text
    assert "innerHTML = `" in html and "${E(" in html and "eval(" not in html and "new Function" not in html
    cat = open(os.path.join(ROOT, "static", "help_catalog.js"), encoding="utf-8").read()
    for sel in ("#opRun", "#opStop", "#opZcell", "#opZms", "#opTenant", "#expXlsx", "#expJson"):
        assert f'"{sel}"' in cat
    assert open(os.path.join(ROOT, "browser_extension", "help_catalog.js"), encoding="utf-8").read() == cat


def test_the_scope_page_boxes_are_off_by_default_and_mapped_everywhere():
    """ASVS V4.1.3 · ASVS V1.4.4 · CWE-1059: the five boxes exist unticked, with a readiness feature, a Required API access card and a label."""
    import re
    import data_flow
    import readiness
    import scope_permissions
    html = open(os.path.join(ROOT, "static", "index.html"), encoding="utf-8").read()
    for key in op.SCOPE_KEYS:
        tag = re.search(r'<input[^>]*class="scope-cb" value="%s"[^>]*>' % key, html)
        assert tag and "checked" not in tag.group(0), key
        assert key in readiness.SCOPE_FEATURES and key in data_flow.SCOPE_KEYS and key in ot.KNOWN_SCOPES
        assert scope_permissions.get_scope_permissions(key)["permissions_write"] == []
    assert "ztb" not in sample_tenant.meta()["scopes"]


# ── in a real browser (node + headless Chrome; skipped without them) ───

BROWSER_DRIVER = r"""
const [widthsJson] = args;
const errors = [];
const _onmsg = ws.onmessage;
ws.onmessage = e => { _onmsg(e); const m = JSON.parse(e.data); if (m.id) return;
  if (m.method === 'Runtime.exceptionThrown') errors.push(String((m.params.exceptionDetails.exception || {}).description || m.params.exceptionDetails.text).slice(0, 200)); };
const out = { widths: {} };
await send('Page.navigate', { url: base + '/report/other-products' });
await until(() => ev(`document.readyState === 'complete'`), 'the page');
await ev(`fetch('/api/offline/sample', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
await ev(`localStorage.setItem('zassess_scopes_live_v1', JSON.stringify({ scopes: ['ztb', 'easm', 'zbi', 'zcell', 'zms'] })), 1`);
for (const width of JSON.parse(widthsJson)) {
  await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 });
  await send('Page.navigate', { url: base + '/report/other-products' });
  await until(() => ev(`document.readyState === 'complete' && !!document.getElementById('opRun')`), 'the page');
  // The keyboard reaches Read: focus it and press Enter.
  await ev(`document.getElementById('opRun').focus(), 1`);
  out.focused = await ev(`document.activeElement && document.activeElement.id`);
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13, text: '\r' });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Enter', code: 'Enter', windowsVirtualKeyCode: 13 });
  await until(() => ev(`!document.getElementById('expXlsx').hidden`), 'the result', 30000);
  await until(() => ev(`new Promise(r => requestAnimationFrame(() => requestAnimationFrame(() => r(true))))`), 'layout');
  out.widths[width] = await ev(`(() => {
    const W = document.documentElement.clientWidth;
    const wide = [...document.querySelectorAll('body *')].filter(e => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > W + 1 && getComputedStyle(e).position !== 'fixed' && !e.closest('.df-tablewrap') && !(e.parentElement && e.parentElement.getBoundingClientRect().right > W + 1); }).map(e => e.tagName + '#' + e.id + '.' + e.className).slice(0, 8);
    return { overflow: document.documentElement.scrollWidth - W, wide,
             sections: document.querySelectorAll('#opBody section[aria-labelledby^="opP-"]').length,
             findings: document.querySelectorAll('#opBody .pa-impact').length,
             hostile: document.body.textContent.includes('<img src=x onerror=window.__xss=1>'),
             xss: window.__xss === 1, injected: document.querySelectorAll('#opBody img').length,
             helpMarks: document.querySelectorAll('button[aria-label^="Help:"]').length,
             live: document.getElementById('liveRegion').textContent };
  })()`);
}
await ev(`fetch('/api/offline/leave', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }).then(r => r.status)`);
out.errors = errors;
console.log(JSON.stringify(out));
p.kill();
process.exit(0);
"""


@pytest.fixture(scope="module")
def page_in_browser(tmp_path_factory):
    from test_findings_reflow import CDP_PRELUDE, run_in_browser
    mp = pytest.MonkeyPatch()
    hostile = sample_tenant.other_products()
    hostile["/ztb/api/v2/Site"]["result"]["sites"][2]["display_name"] = "<img src=x onerror=window.__xss=1>"
    mp.setattr(sample_tenant, "other_products", lambda: copy.deepcopy(hostile))
    ot.sample_store(reset=True)
    try:
        return run_in_browser(tmp_path_factory.mktemp("other-products"), CDP_PRELUDE + BROWSER_DRIVER, json.dumps([320, 1280]))
    finally:
        mp.undo()
        ot.sample_store(reset=True)


@pytest.mark.parametrize("width", ["320", "1280"])
def test_the_page_reads_the_sample_and_never_scrolls_sideways(page_in_browser, width):
    """WCAG 2.2 SC 1.4.10 · SC 2.1.1 · SC 4.1.3: Enter on Read runs it, every product is shown, nothing but a table scrolls sideways, the result is announced."""
    m = page_in_browser["widths"][width]
    assert page_in_browser["focused"] == "opRun"
    assert m["sections"] == 5 and m["findings"] >= 16
    assert m["overflow"] <= 0 and m["wide"] == [], m
    assert "finding" in m["live"] and m["helpMarks"] >= 4
    assert page_in_browser["errors"] == []


def test_a_hostile_name_from_the_tenant_is_shown_as_text(page_in_browser):
    """ASVS V5.3.3 · CWE-79 · WSTG-CLNT-01: a site named like an HTML tag is shown as text; no element is made from it and no script runs."""
    for m in page_in_browser["widths"].values():
        assert m["hostile"] and not m["xss"] and m["injected"] == 0


def test_secrets_are_dropped_as_each_answer_arrives_not_only_at_the_end():
    """ASVS V8.3.4 · CWE-312 · CWE-200: the first layer (_items) already drops a provisioning key, a site secret and a token from the rows kept in memory."""
    body = {"data": {"nonces": {"nodes": [{"name": "n", "key": CANARIES[0], "eyezId": "e"}], "pageInfo": {"totalCount": 1}}}}
    rows, total = op._items("zms", body, "nonces")
    assert rows == [{"name": "n", "eyez_id": "e"}] and total == 1
    rows, _ = op._items("ztb", {"result": {"sites": [{"name": "s", "secret_key": CANARIES[1], "cluster_token": CANARIES[2]}]}})
    assert rows == [{"name": "s"}]
    raw = op._mask_raw({"result": {"token": CANARIES[2], "state": "green"}, "rows": [{"key": CANARIES[0], "name": "k"}]})
    assert raw == {"result": {"state": "green"}, "rows": [{"name": "k"}]}
