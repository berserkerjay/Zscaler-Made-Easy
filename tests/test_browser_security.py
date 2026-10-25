"""Browser security (browser_security, /report/browser): Zero Trust Browser
isolation profiles, the ZPA browser side and ZIA Browser Control, read
read-only and only when in scope, turned into findings about data
protection, with no secret (debug file password, certificate body, logos,
reviewer addresses) in any output, and an Excel export that opens."""
from __future__ import annotations

import copy
import io
import json
import os
import threading
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

import browser_security as bs
import zpa_reader as zr
from test_xlsx_writer import read_workbook

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "216196257331281920"}
BOTH = {"scopes": ["zia_extras", "zpa"], "channels": {}, "from_page": True}
SECRETS = ("TopSecretPW-123", "BEGIN CERTIFICATE", "MIIBszCCAVmgAwIBAgI", "alice@corp.example", "AAAABBBBCCCC", "iVBORw0KGgo", "secret-secret-secret")


def _sc(copy_paste="none", upload="none", printing=False, watermark=True, user_id=True, persistence=False, debug=False,
        local=False, bib=False, fwd=True):
    return {"securityControls": {"copyPaste": copy_paste, "uploadDownload": upload, "allowPrinting": printing, "documentViewer": True,
                                 "watermark": {"enabled": watermark, "showUserId": user_id, "showTimestamp": True, "showMessage": False,
                                               "message": "Confidential"},
                                 "restrictKeystrokes": False, "cameraAndMic": False, "flattenedPdf": False, "localRender": local,
                                 "deepLink": {"enabled": False, "applications": []}},
            "userExperience": {"sessionPersistence": persistence, "browserInBrowser": bib, "persistIsolationBar": True,
                               "translate": False, "zgpu": False,
                               "forwardToZia": {"enabled": fwd, "organizationId": "44772833", "cloudName": "zscalertwo",
                                                "pacFileUrl": "https://pac.example/proxy.pac"}},
            "debugMode": {"allowed": debug, "filePassword": "TopSecretPW-123"},
            "certificates": [{"id": "c1", "name": "Root CA", "isDefault": True, "enabled": True}],
            "regions": [{"id": "r1", "name": "Frankfurt"}, {"id": "r2", "name": "Amsterdam"}],
            "banner": {"id": "b1", "name": "Default banner"}}


def data():
    cbi = {
        "cbi-1": dict(id="cbi-1", name="Strict GenAI", cbiUrl="https://cbi.example/1", isDefault=True, **_sc()),
        "cbi-2": dict(id="cbi-2", name="Loose", cbiUrl="https://cbi.example/2", isDefault=False,
                      **_sc(copy_paste="all", upload="all", printing=True, watermark=False, persistence=True, debug=True,
                            local=True, bib=True, fwd=False)),
        "cbi-3": dict(id="cbi-3", name="Unused strict", cbiUrl="https://cbi.example/3", isDefault=False, **_sc()),
    }
    return {
        "zia": {
            "profiles": [{"id": "cbi-1", "name": "Strict GenAI", "url": "https://cbi.example/1", "defaultProfile": True},
                         {"id": "cbi-2", "name": "Loose", "url": "https://cbi.example/2", "defaultProfile": False},
                         {"id": "cbi-3", "name": "Unused strict", "url": "https://cbi.example/3", "defaultProfile": False}],
            "browser_control": {"allowAllBrowsers": False, "bypassAllBrowsers": False, "enableWarnings": True,
                                "enableSmartBrowserIsolation": False, "blockedChromeVersions": ["CH120"],
                                "smartIsolationUsers": [{"id": 1, "name": "alice@corp.example"}], "smartIsolationGroups": []},
            "supported": [{"browserType": "CHROME", "versions": ["CH130"], "olderVersions": ["CH120", "CH121"]},
                          {"browserType": "MSCHREDGE", "versions": ["MSE130"], "olderVersions": ["MSE120"]}],
            "url_rules": [
                {"id": 1, "name": "Isolate GenAI", "order": 1, "state": "ENABLED", "action": "ISOLATE", "urlCategories": ["AI_ML_APPS"],
                 "cbiProfile": {"id": "cbi-2", "name": "Loose", "url": "https://cbi.example/2"}},
                {"id": 2, "name": "Isolate no profile", "order": 2, "state": "ENABLED", "action": "ISOLATE", "urlCategories": ["NEWS_AND_MEDIA"]},
                {"id": 3, "name": "Isolate ghost", "order": 3, "state": "ENABLED", "action": "ISOLATE", "urlCategories": ["NEWS_AND_MEDIA"],
                 "cbiProfile": {"id": "cbi-gone", "name": "Deleted"}},
                {"id": 4, "name": "Allow news", "order": 4, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["NEWS_AND_MEDIA"]},
            ],
            "cac_rules": {"FILE_SHARE": [{"id": 11, "name": "Isolate file sharing", "order": 1, "state": "ENABLED",
                                          "actions": ["ISOLATE_FILE_SHARE_VIEW"], "cbiProfile": {"id": "cbi-1", "name": "Strict GenAI"}}]},
        },
        "zpa": {
            "cbi_profiles": [{"id": k, "name": v["name"]} for k, v in cbi.items()],   # the list carries no controls
            "cbi_details": cbi,
            "cbi_banners": [{"id": "b1", "name": "Default banner", "isDefault": True, "logo": "data:image/png;base64,iVBORw0KGgo"}],
            "cbi_certificates": [{"id": "c1", "name": "Root CA", "isDefault": True,
                                  "pem": "-----BEGIN CERTIFICATE-----MIIBszCCAVmgAwIBAgI-----END CERTIFICATE-----"}],
            "cbi_regions": [{"id": "r1", "name": "Frankfurt"}, {"id": "r2", "name": "Amsterdam"}],
            "zpa_profiles": [{"id": "z1", "name": "Loose", "isolationProfileId": "cbi-2", "enabled": True},
                             {"id": "z9", "name": "Orphan ZPA profile", "enabled": True}],
            "managed_browsers": [{"id": "mb1", "name": "Managed Chrome", "browserType": "CHROME",
                                  "chromePostureProfile": {"id": "cp1", "crowdStrikeAgent": True}},
                                 {"id": "mb2", "name": "Spare profile", "browserType": "CHROME", "chromePostureProfile": {"id": "cp2"}}],
            "browser_protection": [{"id": "bp1", "name": "Default BP", "criteria": {"fingerPrintCriteria": {
                "browser": {"canvas": True, "ja3": True, "plugin": False}, "system": {"os_name": True}, "location": {"lat": False},
                "collect_location": False, "fingerprint_timeout": "30"}}}],
            "active_protection": [{"id": "bp1", "name": "Default BP"}],
            "segments": [
                {"id": "seg1", "name": "Intranet BA", "enabled": True, "segmentGroupId": "g1", "domainNames": ["intranet.corp.example"],
                 "clientlessApps": [{"name": "intranet", "applicationProtocol": "HTTPS", "certificateName": "Root CA"}]},
                {"id": "seg2", "name": "Old wiki BA", "enabled": True, "segmentGroupId": "g2", "domainNames": ["wiki.corp.example"],
                 "clientlessApps": [{"name": "wiki", "applicationProtocol": "HTTP"}]},
                {"id": "seg3", "name": "Jump hosts", "enabled": True, "segmentGroupId": "g3", "domainNames": ["jump.corp.example"],
                 "praApps": [{"name": "jump"}]},
                {"id": "seg4", "name": "Plain app", "enabled": True, "segmentGroupId": "g3", "domainNames": ["app.corp.example"]},
            ],
            "pra_portals": [{"id": "pp1", "name": "Admin portal", "enabled": True, "userPortalName": "Employees",
                             "approvalReviewers": [{"email": "alice@corp.example"}]}],
            "pra_consoles": [{"id": "pc1", "name": "jump-host RDP", "enabled": True, "praApplication": {"appId": "seg3", "name": "jump"},
                              "praPortals": [{"id": "pp1", "name": "Admin portal"}]}],
            "user_portals": [{"id": "up1", "name": "Employees", "enabled": True, "imageData": "AAAABBBBCCCC", "managedByZs": False}],
            "policies": {
                "access": [{"id": "a1", "name": "Allow intranet", "action": "ALLOW", "ruleOrder": "1",
                            "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": "seg1"}]},
                                           {"operator": "OR", "operands": [{"objectType": "CHROME_POSTURE_PROFILE", "lhs": "id", "rhs": "mb1"}]}]},
                           {"id": "a2", "name": "Allow jump", "action": "ALLOW", "ruleOrder": "2",
                            "conditions": [{"operator": "OR", "operands": [{"objectType": "APP", "lhs": "id", "rhs": "seg3"}]}]}],
                "isolation": [{"id": "i1", "name": "Isolate HR app", "action": "ISOLATE", "ruleOrder": "1", "zpnIsolationProfileId": "z1",
                               "conditions": [{"operands": [{"objectType": "APP", "lhs": "id", "rhs": "seg4"}]}]},
                              {"id": "i2", "name": "Isolate without profile", "action": "ISOLATE", "ruleOrder": "2"}],
            },
        },
    }


class Resp:
    """The SDK response: get_results() the page's raw JSON, get_body() the object."""

    def __init__(self, results=None, body=None):
        self._results, self._body = results or [], body

    def get_results(self):
        return copy.deepcopy(self._results)

    def get_body(self):
        return copy.deepcopy(self._body)


class FakeService:
    def __init__(self, tenant, product, name):
        self._t, self._p, self._n = tenant, product, name

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        t = self._t
        if not (attr.startswith("list_") or attr.startswith("get_")):
            def write(*a, **k):
                t.writes.append(f"{self._p}.{self._n}.{attr}")
                raise AssertionError(f"write attempted: {self._n}.{attr}")
            return write

        def call(*args, query_params=None, **kw):
            key = f"{self._p}.{self._n}.{attr}"
            t.calls.append((key, args, dict(query_params or {})))
            if t.hook:
                t.hook(key)
            if key in t.fail:
                return None, None, t.fail[key]
            return t.answer(self._p, self._n, attr, args, dict(query_params or {}))
        return call


class FakeProduct:
    def __init__(self, tenant, product):
        self._t, self._p = tenant, product

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return FakeService(self._t, self._p, name)


class FakeTenant:
    """client.zia.<service>.<method>() and client.zpa.<service>.<method>(), as zscaler.ZscalerClient exposes them."""

    def __init__(self, d=None, hook=None, fail=None):
        self.d = d or data()
        self.calls, self.writes = [], []
        self.hook, self.fail = hook, dict(fail or {})
        self.zia = FakeProduct(self, "zia")
        self.zpa = FakeProduct(self, "zpa")

    def answer(self, product, svc, method, args, qp):
        z, p = self.d["zia"], self.d["zpa"]
        if product == "zia":
            if (svc, method) == ("cloud_browser_isolation", "list_isolation_profiles"):
                return copy.deepcopy(z["profiles"]), Resp(z["profiles"]), None
            if (svc, method) == ("secure_browsing", "get_browser_control_settings"):
                return object(), Resp(body=z["browser_control"]), None
            if (svc, method) == ("secure_browsing", "get_supported_browser_versions"):
                return copy.deepcopy(z["supported"]), Resp(), None
            if (svc, method) == ("url_filtering", "list_rules"):
                return copy.deepcopy(z["url_rules"]), Resp(z["url_rules"]), None
            if (svc, method) == ("cloudappcontrol", "list_rules"):
                rows = z["cac_rules"].get(args[0], [])
                return copy.deepcopy(rows), Resp(rows), None
            raise AssertionError(f"unexpected ZIA call {svc}.{method}")
        if (svc, method) == ("cbi_profile", "get_cbi_profile"):
            return object(), Resp(body=p["cbi_details"][args[0]]), None
        if (svc, method) == ("policies", "list_rules"):
            items = p["policies"].get(args[0], [])
        else:
            key = {"list_cbi_profiles": "cbi_profiles", "list_cbi_banners": "cbi_banners", "list_cbi_certificates": "cbi_certificates",
                   "list_cbi_regions": "cbi_regions", "list_isolation_profiles": "zpa_profiles",
                   "list_managed_browser_profiles": "managed_browsers", "list_browser_protection_profile": "browser_protection",
                   "list_active_browser_protection_profile": "active_protection", "list_segments_ba": "segments",
                   "list_portals": "pra_portals", "list_consoles": "pra_consoles", "list_user_portals": "user_portals"}[method]
            items = p[key]
        page, size = int(qp.get("page", 1)), int(qp.get("page_size", 10 ** 6))
        chunk = copy.deepcopy(items[(page - 1) * size: page * size])
        return copy.deepcopy(chunk), Resp(chunk), None


def run(scopes=("zia_extras", "zpa"), d=None, **kw):
    t = FakeTenant(d, **{k: v for k, v in kw.items() if k in ("hook", "fail")})
    out = bs.run(t, bs.scope_for(list(scopes)), pace=0, **{k: v for k, v in kw.items() if k in ("cancel", "zpa_blocked")})
    return out, t


def _by(out, fid, obj=None):
    return [f for f in out["findings"] if f["id"] == fid and (obj is None or f["object"] == obj)]


@pytest.fixture(scope="module")
def full():
    return run()


# ── findings ───────────────────────────────────────────────────────────
def test_a_permissive_profile_used_for_genai_gets_high_findings_and_a_strict_one_none(full):
    out, _t = full
    loose = {f["id"]: f for f in out["findings"] if f["object"] == "Loose"}
    assert loose["BS-C1"]["severity"] == "high" and "copyPaste = \"all\"" in loose["BS-C1"]["reason"]
    assert "URL categories AI_ML_APPS" in loose["BS-C1"]["reason"], loose["BS-C1"]["reason"]
    assert loose["BS-C2"]["severity"] == "high" and "document viewer" in loose["BS-C2"]["fix"]
    assert loose["BS-C3"]["severity"] == "medium"          # printing
    assert loose["BS-C4"]["severity"] == "medium"          # no watermark
    assert loose["BS-C5"]["severity"] == "low" and loose["BS-C5"]["assumption"]
    assert loose["BS-C6"]["severity"] == "medium" and "never read out" in loose["BS-C6"]["reason"]
    assert loose["BS-C7"]["severity"] == "medium" and loose["BS-C7"]["assumption"]
    assert loose["BS-C8"]["severity"] == "info" and "not a gap by itself" in loose["BS-C8"]["assumption"]
    assert loose["BS-C9"]["severity"] == "low"             # used by a ZPA isolation rule, not forwarded to ZIA
    # The strict profiles have no control finding at all.
    assert not [f for f in out["findings"] if f["object"] in ("Strict GenAI", "Unused strict") and f["id"].startswith("BS-C")]
    sev = [bs._SEV_RANK[f["severity"]] for f in out["findings"]]
    assert sev == sorted(sev), "most severe first"
    assert out["counts"]["total"] == len(out["findings"]) and out["counts"]["high"] >= 4


def test_the_same_permissive_profile_unused_is_low():
    d = data()
    d["zia"]["url_rules"] = [r for r in d["zia"]["url_rules"] if r["name"] != "Isolate GenAI"]
    d["zpa"]["policies"]["isolation"] = [r for r in d["zpa"]["policies"]["isolation"] if r["id"] != "i1"]
    out, _t = run(d=d)
    loose = {f["id"]: f for f in out["findings"] if f["object"] == "Loose"}
    assert loose["BS-C1"]["severity"] == "low" and "No rule uses this profile" in loose["BS-C1"]["reason"]
    assert "BS-C9" not in loose
    assert _by(out, "BS-U1", "Loose")


def test_rules_that_isolate_without_a_profile_or_with_a_deleted_one(full):
    out, _t = full
    assert _by(out, "BS-R1", "Isolate no profile")[0]["severity"] == "high"
    assert _by(out, "BS-R2", "Isolate ghost")[0]["severity"] == "medium"
    assert _by(out, "BS-R3", "Isolate without profile")[0]["severity"] == "high"
    assert not _by(out, "BS-R1", "Allow news") and not _by(out, "BS-R2", "Isolate GenAI")
    rows = {r["rule"]: r for r in out["inventory"]["isolation_rules"]}
    assert rows["Isolate GenAI"]["profile"] == "Loose" and rows["Isolate GenAI"]["sensitive"]
    assert rows["Isolate file sharing"]["sensitive"] == "Cloud App Control file sharing apps"
    assert rows["Isolate HR app"]["product"] == "ZPA" and rows["Isolate HR app"]["profile"] == "Loose"
    assert "Allow news" not in rows


def test_unused_profiles_are_detected_on_both_sides(full):
    out, _t = full
    unused = {f["object"] for f in _by(out, "BS-U1")}
    assert unused == {"Unused strict", "Orphan ZPA profile"}, unused
    prof = {r["name"]: r for r in out["inventory"]["isolation_profiles"]}
    assert prof["Loose"]["used"] is True and set(prof["Loose"]["sources"]) == {"isolation (Zero Trust Browser)", "ZIA", "ZPA"}
    assert prof["Strict GenAI"]["used"] is True and prof["Unused strict"]["used"] is False


def test_usage_is_unknown_not_unused_when_the_other_side_was_not_read():
    out, t = run(scopes=("zpa",))
    assert not _by(out, "BS-U1", "Unused strict"), "ZIA rules were not read, so ZIA use is unknown"
    assert any("Unused strict" in x and "not read" in x for x in out["not_assessed"])
    assert not [c for c in t.calls if c[0].startswith("zia.")], "ZIA not in scope: nothing read"
    out, t = run(scopes=("zia_extras",))
    assert {f["object"] for f in _by(out, "BS-U1")} == {"Unused strict"}
    assert not [c for c in t.calls if c[0].startswith("zpa.")], "ZPA not in scope: nothing read"
    assert any("Isolation controls" in x for x in out["not_assessed"])
    assert not [f for f in out["findings"] if f["id"].startswith("BS-C")], "controls need the ZPA isolation API"


def test_browser_control_findings():
    out, _t = run(scopes=("zia_extras",))
    assert _by(out, "BS-B1")[0]["severity"] == "low"                    # smart isolation off
    b5 = _by(out, "BS-B5")
    assert len(b5) == 1 and "does not block 1 of them: CH121." in b5[0]["reason"]
    assert any("Edge" in x for x in out["not_assessed"])
    d = data()
    d["zia"]["browser_control"].update(allowAllBrowsers=True, bypassAllBrowsers=True, enableSmartBrowserIsolation=True, enableWarnings=False)
    out, _t = run(scopes=("zia_extras",), d=d)
    ids = {f["id"] for f in out["findings"]}
    assert {"BS-B3", "BS-B4", "BS-B2", "BS-B6"} <= ids and "BS-B5" not in ids and "BS-B1" not in ids
    assert out["inventory"]["browser_control"]["smart_isolation_users"] == 1


def test_browser_access_managed_browsers_and_pra(full):
    out, _t = full
    a1 = _by(out, "BS-A1")
    assert [f["object"] for f in a1] == ["Old wiki BA"]
    assert [f["object"] for f in _by(out, "BS-M1")] == ["Spare profile"]
    assert not _by(out, "BS-M2"), "an access rule checks the browser"
    inv = out["inventory"]
    ba = {s["name"]: s for s in inv["ba_segments"]}
    assert set(ba) == {"Intranet BA", "Old wiki BA"} and ba["Intranet BA"]["reached_by"] == ["Allow intranet"]
    assert inv["pra_segments"] == ["Jump hosts"]
    assert inv["pra_consoles"][0]["segment"] == "Jump hosts" and inv["pra_consoles"][0]["portals"] == ["Admin portal"]
    assert [m["used_by"] for m in inv["managed_browsers"]] == [["Allow intranet"], []]
    assert inv["managed_browsers"][0]["crowdstrike_agent"] is True
    bp = inv["browser_protection"][0]
    assert bp["active"] and bp["browser_criteria"] == ["canvas", "ja3"] and bp["system_criteria"] == ["os_name"]
    assert len(inv["user_portals"]) == 1 and inv["certificates"] == [{"id": "c1", "name": "Root CA", "is_default": True, "enabled": None}]


def test_no_access_rule_checking_the_browser_is_said_once():
    d = data()
    d["zpa"]["policies"]["access"][0]["conditions"] = d["zpa"]["policies"]["access"][0]["conditions"][:1]
    out, _t = run(d=d)
    assert len(_by(out, "BS-M2")) == 1 and len(_by(out, "BS-M1")) == 2


# ── no secrets ─────────────────────────────────────────────────────────
def _texts_of_workbook(blob: bytes) -> str:
    z = zipfile.ZipFile(io.BytesIO(blob))
    return "".join(z.read(n).decode("utf-8", "replace") for n in z.namelist())


def test_no_password_certificate_body_logo_or_person_in_any_output(full):
    out, _t = full
    logs = []
    again = bs.run(FakeTenant(), bs.scope_for(["zia_extras", "zpa"]), log=logs.append, pace=0)
    blobs = [json.dumps(out), json.dumps(again), "\n".join(logs), _texts_of_workbook(bs.workbook(dict(out, tenant_label="acme")))]
    for blob in blobs:
        for s in SECRETS:
            assert s not in blob, s
        assert "file_password" not in blob and "filePassword" not in blob and '"pem"' not in blob


def test_scrub_drops_secret_shaped_keys_anywhere():
    x = bs.scrub({"a": [{"filePassword": "p", "keep": 1, "pem": "x", "nested": {"client_secret": "s", "logo": "l", "ok": True}}]})
    assert x == {"a": [{"keep": 1, "nested": {"ok": True}}]}


def test_errors_never_carry_a_secret():
    out, _t = run(fail={"zpa.cbi_certificate.list_cbi_certificates": "403 -----BEGIN CERTIFICATE-----MIIBszCCAVmgAwIBAgI-----END CERTIFICATE-----",
                        "zia.url_filtering.list_rules": "401 bearer abc.def.ghi token=xyz"})
    blob = json.dumps(out)
    assert "MIIBszCC" not in blob and "abc.def.ghi" not in blob and "xyz" not in blob
    assert out["sections"]["zpa:cbi_certificates"]["read"] is False and out["sections"]["zia:url_filtering"]["read"] is False


# ── read-only, scope, Stop ─────────────────────────────────────────────
def test_only_list_and_get_calls_and_a_failed_list_is_not_assessed(full):
    _out, t = full
    assert t.writes == []
    assert all(k.split(".")[-1].startswith(("list_", "get_")) for k, _a, _q in t.calls)
    out, _t = run(fail={"zpa.policies.list_rules": "boom"})
    assert out["sections"]["zpa:policy:access"]["read"] is False
    assert not _by(out, "BS-A1") and any("access policy could not be read" in x for x in out["not_assessed"])


def test_stop_ends_the_read_with_nothing_more_read():
    cancel = threading.Event()
    seen = []

    def hook(key):
        seen.append(key)
        if key == "zpa.cbi_banner.list_cbi_banners":
            cancel.set()
    with pytest.raises(bs.Stopped):
        run(hook=hook, cancel=cancel)
    assert seen[-1] == "zpa.cbi_banner.list_cbi_banners", seen[-3:]


def test_scope_for_reads_nothing_and_says_what_is_out():
    s = bs.scope_for(["dlp"])
    assert not s["read"] and s["summary"] == bs.NOTHING_IN_SCOPE and set(s["not_in_scope"]) == {"zia", "zpa"}
    assert bs.scope_for(["zpa"])["zpa"] and not bs.scope_for(["zpa"])["zia"]


def test_the_reader_drives_the_real_sdk_services_and_paths():
    """The real zscaler.zia and zscaler.zpa services with a recording
    executor: the methods exist, they are GETs, and they hit the paths the
    module documents."""
    from zscaler.zia.zia_service import ZIAService
    from zscaler.zpa.zpa_service import ZPAService
    seen = []

    class R:
        def __init__(self, url):
            self.url = url

        def get_results(self):
            return [] if "policySet" in self.url or "webApplicationRules" in self.url or "urlFilteringRules" in self.url \
                else [{"id": "1", "name": "x"}]

        def get_body(self):
            return {"id": "1", "name": "x", "allowAllBrowsers": False}

        def get_status(self):
            return 200

    class Executor:
        def create_request(self, method, url, *a, **k):
            seen.append((method, " ".join(url.split()).replace(" ", "")))
            return {"url": url}, None

        def execute(self, request, *a, **k):
            return R(request["url"]), None

    class Client:
        zia = ZIAService(Executor())
        zpa = ZPAService(Executor(), {"client": {"customerId": "216196257331281920"}})

    out = bs.run(Client(), bs.scope_for(["zia_extras", "zpa"]), pace=0)
    assert seen and all(m == "GET" for m, _u in seen), "read-only"
    urls = [u for _m, u in seen]
    cbi = "/zpa/cbiconfig/cbi/api/customers/216196257331281920"
    mgmt = "/zpa/mgmtconfig/v1/admin/customers/216196257331281920"
    for path in ("/zia/api/v1/browserIsolation/profiles", "/zia/api/v1/browserControlSettings",
                 "/zia/api/v1/browserControlSettings/supportedBrowserVersions", "/zia/api/v1/urlFilteringRules",
                 "/zia/api/v1/webApplicationRules/AI_ML", cbi + "/profiles", cbi + "/profiles/1", cbi + "/banners", cbi + "/certificates",
                 cbi + "/regions", mgmt + "/isolation/profiles", mgmt + "/managedBrowserProfile/search", mgmt + "/browserProtectionProfile",
                 mgmt + "/activeBrowserProtectionProfile", mgmt + "/application", mgmt + "/praPortal", mgmt + "/praConsole",
                 mgmt + "/userPortal", mgmt + "/policySet/rules/policyType/ACCESS_POLICY", mgmt + "/policySet/rules/policyType/ISOLATION_POLICY"):
        assert any(u == path or u.startswith(path + "?") for u in urls), (path, urls)
    unread = {k: v["error"] for k, v in out["sections"].items() if not v["read"]}
    assert not unread, unread


# ── the API ────────────────────────────────────────────────────────────
@pytest.fixture
def api(monkeypatch):
    import dlp_api_server as srv
    built = []
    tenant = FakeTenant()

    def build(creds):
        built.append(dict(creds))
        return tenant
    monkeypatch.setattr(srv, "_build_sdk_client", build)
    monkeypatch.setattr(zr, "PACE_SECONDS", 0)
    return srv, TestClient(srv.app), tenant, built


def _wait(t, job, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("body", [
    {"scopes": [], "channels": {}, "from_page": True},
    {"scopes": ["dlp", "zcc"], "channels": {"web_dlp": "zscaler"}, "from_page": True},
])
def test_refused_before_any_read_when_nothing_is_in_scope(api, body):
    srv, t, tenant, built = api
    r = t.post("/api/browser-security/start", json=dict(CREDS, **body))
    assert r.status_code == 400 and "tick ZIA platform" in r.json()["detail"] and "Nothing was read" in r.json()["detail"], r.text
    assert built == [] and tenant.calls == []


def test_zpa_alone_needs_oneapi_and_a_customer_id_before_sign_in(api, monkeypatch):
    srv, t, tenant, built = api
    monkeypatch.delenv("ZSCALER_CUSTOMER_ID", raising=False)
    zpa_only = {"scopes": ["zpa"], "channels": {}, "from_page": True}
    r = t.post("/api/browser-security/start", json=dict(CREDS, customer_id="", **zpa_only))
    assert r.status_code == 400 and "customer ID" in r.json()["detail"] and "Nothing was read" in r.json()["detail"]
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "k" * 12, "customer_id": "123"}
    r = t.post("/api/browser-security/start", json=dict(legacy, **zpa_only))
    assert r.status_code == 400 and "OneAPI" in r.json()["detail"]
    assert built == [] and tenant.calls == []


def test_the_job_reads_analyses_and_exports_excel_and_json(api):
    srv, t, tenant, built = api
    r = t.post("/api/browser-security/start", json=dict(CREDS, **BOTH), headers={"X-Start-Token": "b" * 32})
    assert r.status_code == 200 and r.json()["kind"] == "browser", r.text
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done", snap
    res = snap["result"]
    assert res["status"] == "done" and res["report_id"].startswith("browser-") and res["counts"]["total"] > 10
    assert tenant.writes == []
    rep = t.get(f"/api/browser-security/report/{res['report_id']}")
    assert rep.status_code == 200 and rep.json()["findings"] == res["findings"]
    x = t.get(f"/api/browser-security/report/{res['report_id']}/export?format=xlsx")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.openxmlformats")
    wb = read_workbook(x.content)
    assert {"Summary", "Findings", "Isolation profiles", "Rules that isolate", "Browser Control", "Browser Access",
            "Privileged Remote Access", "Glossary", "Assumptions"} <= set(wb)
    assert wb["Findings"][0][:4] == ["Severity", "ID", "Area", "Title"] and len(wb["Findings"]) == res["counts"]["total"] + 1
    assert any(row and row[0] == "Loose" and row[4] == "all" for row in wb["Isolation profiles"])
    j = t.get(f"/api/browser-security/report/{res['report_id']}/export?format=json")
    assert j.status_code == 200 and json.loads(j.content)["counts"] == res["counts"]
    for blob in (json.dumps(snap), _texts_of_workbook(x.content), j.text):
        for s in SECRETS:
            assert s not in blob, s
    assert t.get("/api/browser-security/report/browser-nope").status_code == 404
    assert t.get(f"/api/browser-security/report/{res['report_id']}/export?format=csv").status_code == 400


def test_zia_and_zpa_ticked_with_the_classic_sign_in_reads_zia_and_says_why_not_zpa(api):
    srv, t, tenant, built = api
    legacy = {"auth_method": "legacy", "username": "admin@acme.example", "password": "pw-pw-pw-pw", "api_key": "k" * 12}
    r = t.post("/api/browser-security/start", json=dict(legacy, **BOTH))
    assert r.status_code == 200, r.text
    res = _wait(t, r.json()["job_id"])["result"]
    assert "OneAPI" in res["not_in_scope"]["zpa"]
    assert tenant.calls and not [c for c in tenant.calls if c[0].startswith("zpa.")]
    assert "pw-pw-pw-pw" not in json.dumps(res)


def test_the_page_is_served_and_registered():
    import dlp_api_server as srv
    t = TestClient(srv.app)
    r = t.get("/report/browser")
    assert r.status_code == 200 and "Browser security" in r.text and "no-cache" in r.headers["cache-control"]
    html = r.text
    assert "Zscaler Made Easy" in html
    for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js"):
        assert f"/static/{s}" in html
    js = open(os.path.join(ROOT, "static", "explain.js"), encoding="utf-8").read()
    assert "'/report/browser': 'browser'" in js and "X.browser = {" in js
    assert bs.NO_ENTERPRISE_BROWSER_API.split(",")[0] in html or "Enterprise Browser" in html
