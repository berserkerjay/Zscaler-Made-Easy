"""Device posture: posture-profile classification (by type, reliable; by
name, inferred; markers never counted as enforcement), the cross-links to
access rules with must-pass / must-fail, the findings, the readable
conditions (nested AND / OR / NOT groups, names not ids, one plain
sentence), the API (scope refused before any read, job, exports, no
secrets) and the page conventions.

The fake tenant answers with the SDK's own models built from API-shaped
JSON and a response whose get_results() is that JSON, as the SDK's list
methods return (items, response, error)."""
from __future__ import annotations

import copy
import io
import json
import os
import re
import threading
import time
import zipfile

import pytest
from fastapi.testclient import TestClient

import device_posture as dp
import zpa_reader as zr

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SECRET = "secret-secret-secret"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET, "customer_id": "216196257331281920"}
ZPA_SCOPE = {"scopes": ["zpa"], "channels": {}, "from_page": True}
ZPA_ZCC_SCOPE = {"scopes": ["zpa", "zcc"], "channels": {}, "from_page": True}


def _op(t, lhs, rhs, name=""):
    o = {"objectType": t, "lhs": lhs, "rhs": rhs}
    if name:
        o["name"] = name
    return o


def _cond(*ops, operator="OR", negated=False):
    return {"operator": operator, "negated": negated, "operands": list(ops)}


def _rule(i, order, name, action, *conds, **kw):
    d = {"id": i, "ruleOrder": str(order), "name": name, "action": action, "operator": "AND", "conditions": list(conds)}
    d.update(kw)
    return d


APP = lambda sid: _op("APP", "id", sid)                       # noqa: E731
GRP = lambda gid: _op("APP_GROUP", "id", gid)                 # noqa: E731
SCIM = lambda gid: _op("SCIM_GROUP", "idp1", gid)             # noqa: E731
POST = lambda udid, rhs="true": _op("POSTURE", udid, rhs)     # noqa: E731
TN = lambda nid, rhs="true": _op("TRUSTED_NETWORK", nid, rhs)  # noqa: E731


def _seg(i, name, domains, ports, group):
    flat = []
    for a, b in ports:
        flat += [str(a), str(b)]
    return {"id": i, "name": name, "enabled": True, "domainNames": domains, "tcpPortRanges": flat, "segmentGroupId": group,
            "serverGroups": [{"id": "srv1", "name": "DC servers"}], "bypassType": "NEVER"}


def tenant_data():
    """A posture-heavy tenant: every family, every finding, nested conditions."""
    return {
        "segments": [
            _seg("s-hr", "HR app", ["hr.corp.example"], [(443, 443)], "sg-hr"),
            _seg("s-wiki", "Wiki", ["wiki.corp.example"], [(443, 443)], "sg-gen"),
            _seg("s-wild", "Corp wildcard", ["*.corp.example"], [(443, 443)], "sg-gen"),
            _seg("s-rdp", "Jump hosts", ["jump.corp.example"], [(3389, 3389)], "sg-gen"),
        ],
        "segment_groups": [{"id": "sg-hr", "name": "HR apps", "enabled": True}, {"id": "sg-gen", "name": "General", "enabled": True}],
        "server_groups": [{"id": "srv1", "name": "DC servers", "enabled": True, "dynamicDiscovery": True, "appConnectorGroups": []}],
        "connector_groups": [], "connectors": [], "service_edge_groups": [], "service_edges": [],
        "idps": [{"id": "idp1", "name": "Okta", "enabled": True, "scimEnabled": True, "enableScimBasedPolicy": True}],
        "saml_attributes": [{"id": "attr-dept", "name": "Department", "idpId": "idp1", "samlName": "department"}],
        "posture_profiles": [
            {"id": "p-ad", "name": "Corp AD joined", "postureUdid": "udid-ad", "postureType": "DOMAIN_JOINED", "platform": ["windows"]},
            {"id": "p-cs", "name": "CrowdStrike ZTA 40", "postureUdid": "udid-cs", "postureType": "CROWDSTRIKE_ZTA_SCORE"},
            {"id": "p-cert", "name": "Corp cert", "postureUdid": "udid-cert", "postureType": "CERT_TRUST", "crlCheckEnabled": True,
             "rootCert": "-----BEGIN CERTIFICATE-----MIIBroot-----END CERTIFICATE-----"},
            {"id": "p-marker", "name": "CrowdStrike installed", "postureUdid": "udid-marker", "postureType": "FILE_PATH"},
            {"id": "p-s1", "name": "SentinelOne check", "postureUdid": "udid-s1"},
            {"id": "p-ovr", "name": "Falcon override", "postureUdid": "udid-ovr"},
            {"id": "p-disk", "name": "BitLocker on", "postureUdid": "udid-disk", "postureType": "DISK_ENCRYPTION"},
            {"id": "p-weird", "name": "Legacy check 7", "postureUdid": "udid-weird", "postureType": "SOMETHING_NEW"},
            {"id": "p-jail", "name": "Mobile integrity", "postureUdid": "udid-jail", "postureType": "UNAUTHORIZED_MODIFICATION"},
        ],
        "trusted_networks": [{"id": "tn-hq", "name": "HQ", "networkId": "net-hq"}, {"id": "tn-lab", "name": "Lab", "networkId": "net-lab"}],
        "machine_groups": [],
        "scim_groups": {"idp1": [{"id": "g-hr", "name": "HR"}, {"id": "g-all", "name": "Everyone"}]},
        "zcc_trusted": [{"id": "1", "guid": "net-hq", "networkName": "HQ", "active": False, "dnsServers": "10.0.0.53",
                         "trustedSubnets": ["10.0.0.0/8"]}],
        "policies": {
            "access": [
                _rule("r1", 1, "HR on corp devices", "ALLOW", _cond(APP("s-hr")), _cond(SCIM("g-hr")),
                      _cond(_op("PLATFORM", "windows", "true")), _cond(POST("udid-ad"))),
                _rule("r2", 2, "Wiki for everyone", "ALLOW", _cond(APP("s-wiki")), _cond(SCIM("g-all"))),
                _rule("r3", 3, "Wildcard for HQ", "ALLOW", _cond(APP("s-wild")), _cond(TN("net-hq"))),
                _rule("r4", 4, "Jump hosts for non-compliant", "ALLOW", _cond(APP("s-rdp")), _cond(POST("udid-cs", "false"))),
                _rule("r5", 5, "HR negated cert", "ALLOW", _cond(APP("s-hr")), _cond(POST("udid-cert"), negated=True)),
                _rule("r6", 6, "Jump hosts marker only", "ALLOW", _cond(APP("s-rdp")), _cond(POST("udid-marker"))),
                _rule("r7", 7, "HR optional posture", "ALLOW", _cond(APP("s-hr")), _cond(POST("udid-s1"), SCIM("g-hr"))),
                _rule("r8", 8, "Everything for everyone", "ALLOW", _cond(SCIM("g-all"))),
                _rule("r9", 9, "Block failing override", "DENY", _cond(GRP("sg-gen")), _cond(POST("udid-ovr", "false"))),
                _rule("r10", 10, "Wiki dangling", "ALLOW", _cond(APP("s-wiki")), _cond(POST("udid-gone"))),
                _rule("r11", 11, "Nested", "ALLOW", _cond(GRP("sg-hr")),
                      _cond(_op("PLATFORM", "mac", "true"), _op("CLIENT_TYPE", "id", "zpn_client_type_zapp"), operator="AND"),
                      _cond(TN("net-hq"), _op("COUNTRY_CODE", "US", "true"), negated=True), _cond(POST("udid-jail"))),
                _rule("r12", 12, "Old allow all", "ALLOW", disabled="1"),
            ],
            "timeout": [_rule("t1", 1, "Reauth legacy", "RE_AUTH", _cond(POST("udid-weird")))],
            "client_forwarding": [], "inspection": [], "isolation": [],
        },
    }


# ── fake SDK client ───────────────────────────────────────────────────
from zscaler.zcc.models.trustednetworks import TrustedNetworks as ZccTrusted  # noqa: E402
from zscaler.zpa.models.application_segment import ApplicationSegments  # noqa: E402
from zscaler.zpa.models.idp import IDPController  # noqa: E402
from zscaler.zpa.models.policyset_controller_v1 import PolicySetControllerV1  # noqa: E402
from zscaler.zpa.models.posture_profiles import PostureProfile  # noqa: E402
from zscaler.zpa.models.saml_attributes import SAMLAttribute  # noqa: E402
from zscaler.zpa.models.scim_groups import SCIMGroup  # noqa: E402
from zscaler.zpa.models.segment_group import SegmentGroup  # noqa: E402
from zscaler.zpa.models.server_group import ServerGroup  # noqa: E402
from zscaler.zpa.models.trusted_network import TrustedNetwork  # noqa: E402

SERVICES = {
    "application_segment": ("segments", ApplicationSegments), "segment_groups": ("segment_groups", SegmentGroup),
    "server_groups": ("server_groups", ServerGroup), "app_connector_groups": ("connector_groups", dict),
    "app_connectors": ("connectors", dict), "service_edge_group": ("service_edge_groups", dict), "service_edges": ("service_edges", dict),
    "idp": ("idps", IDPController), "saml_attributes": ("saml_attributes", SAMLAttribute),
    "posture_profiles": ("posture_profiles", PostureProfile), "trusted_networks": ("trusted_networks", TrustedNetwork),
    "machine_groups": ("machine_groups", dict),
}


class FakeResp:
    def __init__(self, raw):
        self._raw = raw

    def get_results(self):
        return list(self._raw)


class FakeService:
    def __init__(self, tenant, name, product="zpa"):
        self._t, self._name, self._product = tenant, name, product

    def __getattr__(self, attr):
        if attr.startswith("_"):
            raise AttributeError(attr)
        t = self._t
        if not attr.startswith("list_"):
            def write(*a, **k):
                t.writes.append(f"{self._name}.{attr}")
                raise AssertionError(f"write attempted: {self._name}.{attr}")
            return write

        def lister(*args, query_params=None, **kw):
            qp = dict(query_params or {})
            t.calls.append((self._product, self._name, attr, args))
            if t.hook:
                t.hook(self._name, attr, args)
            if self._name in t.fail:
                return None, None, t.fail[self._name]
            page, size = int(qp.get("page", 1)), int(qp.get("page_size", 20))
            if self._product == "zcc":
                items = t.data["zcc_trusted"][(page - 1) * size: page * size]
                return [ZccTrusted(copy.deepcopy(x)) for x in items], None, None   # models only: as_dict fallback
            if self._name == "policies":
                items, model = t.data["policies"].get(args[0], []), PolicySetControllerV1
            elif self._name == "scim_groups":
                items, model = t.data["scim_groups"].get(args[0], []), SCIMGroup
            else:
                key, model = SERVICES[self._name]
                items = t.data[key]
            chunk = copy.deepcopy(items[(page - 1) * size: page * size])
            return [model(copy.deepcopy(x)) for x in chunk], FakeResp(chunk), None
        return lister


class _Product:
    def __init__(self, tenant, product):
        self._t, self._p = tenant, product

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        return FakeService(self._t, name, self._p)


class FakeTenant:
    def __init__(self, data=None, hook=None, fail=None):
        self.data = data if data is not None else tenant_data()
        self.calls, self.writes = [], []
        self.hook, self.fail = hook, dict(fail or {})
        self.zpa = _Product(self, "zpa")
        self.zcc = _Product(self, "zcc")


def build(data=None, zcc=True):
    t = FakeTenant(data)
    snap, raw, zout = dp.read(t, zcc=zcc, pace=0)
    return dp.analyze(snap, raw["posture_profiles"], raw["trusted_networks"], zout), t


@pytest.fixture(scope="module")
def rep():
    return build()[0]


def _p(rep, name):
    return next(p for p in rep["profiles"] if p["name"] == name)


def _r(rep, name):
    return next(r for r in rep["rules"] if r["name"] == name)


def _f(rep, fid):
    return [f for f in rep["findings"] if f["id"] == fid]


# ── classification ────────────────────────────────────────────────────
@pytest.mark.parametrize("ptype,family", [
    ("DOMAIN_JOINED", "domain_join"), ("AZURE_AD_DOMAIN_JOINED", "domain_join"), ("CROWDSTRIKE_ZTA_SCORE", "edr"),
    ("DETECT_SENTINELONE", "edr"), ("MS_DEFENDER", "edr"), ("CERT_TRUST", "certificate"), ("SERVER_VALIDATED_CLIENT_CERTIFICATE", "certificate"),
    ("DISK_ENCRYPTION", "disk_hygiene"), ("FULL_DISK_ENCRYPTION", "disk_hygiene"), ("OS_VERSION", "os_version"),
    ("UNAUTHORIZED_MODIFICATION", "mobile_integrity"), ("JAILBROKEN", "mobile_integrity"), ("INTUNE_MDM", "mdm"),
    ("FIREWALL", "firewall"), ("PROCESS_CHECK", "process"), ("FILE_PATH", "marker"), ("REGISTRY_KEY", "marker"),
    ("OWNERSHIP_VARIABLE", "marker"), ("file-path", "marker"),
])
def test_the_posture_type_decides_the_family_reliably(ptype, family):
    c = dp.classify("Anything at all", ptype)
    assert c["family"] == family and c["source"] == "type" and c["confidence"] == "reliable"


@pytest.mark.parametrize("name,family", [
    ("SentinelOne check", "edr"), ("Falcon running", "edr"), ("AD joined laptops", "domain_join"), ("Corp certificate", "certificate"),
    ("BitLocker on", "disk_hygiene"), ("Jailbreak check", "mobile_integrity"), ("Intune managed", "mdm"), ("Windows firewall", "firewall"),
    ("Falcon override", "marker"), ("CrowdStrike bypass", "marker"), ("Domain join exception", "marker"), ("Zebra 7", "unknown"),
])
def test_without_a_known_type_the_name_infers_the_family_and_says_so(name, family):
    c = dp.classify(name, "")
    assert c["family"] == family
    assert c["source"] == ("none" if family == "unknown" else "name")
    assert c["confidence"] == ("unknown" if family == "unknown" else "inferred")


def test_an_unrecognised_type_falls_back_to_the_name_and_says_why():
    c = dp.classify("CrowdStrike posture", "BRAND_NEW_TYPE")
    assert c["family"] == "edr" and c["source"] == "name" and "BRAND_NEW_TYPE" in c["why"] and "not one this page recognises" in c["why"]


def test_a_marker_is_never_counted_as_edr_or_domain_join_enforcement(rep):
    m = _p(rep, "CrowdStrike installed")      # file path check named after an EDR
    assert m["family"] == "marker" and m["source"] == "type" and m["enforces"] is False
    assert "suggests edr" in m["why"].lower() and "not counted" in m["why"]
    o = _p(rep, "Falcon override")             # no type, name says override
    assert o["family"] == "marker" and o["source"] == "name" and o["enforces"] is False
    fam = {f["id"]: f for f in rep["families"]}
    assert fam["edr"]["profiles"] == ["CrowdStrike ZTA 40", "SentinelOne check"]
    assert "CrowdStrike installed" not in fam["edr"]["profiles"] and "Falcon override" not in fam["domain_join"]["profiles"]
    assert fam["marker"]["enforces"] is False and fam["edr"]["enforces"] is True
    assert fam["edr"]["reliable"] == 1 and fam["edr"]["inferred"] == 1
    # The marker-only allow rule does not count as enforcing posture.
    assert rep["counts"]["allow_rules_enforced"] == 2   # r1 (domain join) and r11 (mobile integrity)


def test_profiles_keep_the_type_and_platform_but_never_the_root_certificate(rep):
    c = _p(rep, "Corp cert")
    assert c["posture_type"] == "CERT_TRUST" and c["crl_check"] is True and c["has_root_cert"] is True
    assert "BEGIN CERTIFICATE" not in json.dumps(rep)
    assert _p(rep, "Corp AD joined")["platforms"] == ["windows"]


def test_the_raw_lists_come_from_the_readers_own_calls_no_extra_read():
    t = FakeTenant()
    snap, raw, zout = dp.read(t, zcc=False, pace=0)
    posture_calls = [c for c in t.calls if c[1] == "posture_profiles"]
    assert len(posture_calls) == 1 and len(raw["posture_profiles"]) == 9
    assert raw["posture_profiles"][0].get("postureType") == "DOMAIN_JOINED"
    assert not any(c[0] == "zcc" for c in t.calls) and zout["read"] is False and "not ticked" in zout["reason"]
    assert not t.writes


# ── usage and findings ────────────────────────────────────────────────
def test_usage_cross_links_rules_with_must_pass_and_must_fail(rep):
    ad = _p(rep, "Corp AD joined")["used_by"]
    assert [(u["rule"], u["sense"]) for u in ad] == [("HR on corp devices", "must_pass")]
    cs = _p(rep, "CrowdStrike ZTA 40")["used_by"][0]
    assert cs["sense"] == "must_fail" and cs["via"] == "the operand says it must fail"
    cert = _p(rep, "Corp cert")["used_by"][0]
    assert cert["sense"] == "must_fail" and cert["via"] == "the condition is negated"
    s1 = _p(rep, "SentinelOne check")["used_by"][0]
    assert s1["optional"] is True
    weird = _p(rep, "Legacy check 7")["used_by"][0]
    assert weird["policy"] == "timeout" and weird["policy_label"] == "timeout policy"
    hq = next(t for t in rep["trusted_networks"] if t["name"] == "HQ")
    assert {(u["rule"], u["sense"]) for u in hq["used_by"]} == {("Wildcard for HQ", "on"), ("Nested", "off")}


def test_double_negation_is_must_pass():
    rule = zr.normalize_rule(_rule("x", 1, "x", "ALLOW", _cond(POST("u", "false"), negated=True)), 0, "access")
    (u,) = dp._uses(rule, "POSTURE")
    assert u["sense"] == "must_pass" and "so it must pass" in u["via"]


def test_findings_flag_each_gap_once_with_the_rule_named(rep):
    dp01 = {f["object"]: f for f in _f(rep, "DP-01")}
    assert set(dp01) == {"Wildcard for HQ", "Everything for everyone"}
    assert dp01["Everything for everyone"]["severity"] == "high" and "every application" in dp01["Everything for everyone"]["reason"]
    assert dp01["Wildcard for HQ"]["severity"] == "medium" and "wildcard domain" in dp01["Wildcard for HQ"]["reason"]
    assert "trusted network" in dp01["Wildcard for HQ"]["reason"]
    assert {f["object"] for f in _f(rep, "DP-02")} == {"Jump hosts for non-compliant", "HR negated cert"}
    assert all(f["severity"] == "high" for f in _f(rep, "DP-02"))
    assert [f["object"] for f in _f(rep, "DP-03")] == ["Jump hosts marker only"]
    assert [f["object"] for f in _f(rep, "DP-04")] == ["HR optional posture"]
    assert [f["object"] for f in _f(rep, "DP-05")] == ["BitLocker on"]          # weird is used in the timeout policy
    assert [f["object"] for f in _f(rep, "DP-06")] == ["Lab"]
    assert [f["object"] for f in _f(rep, "DP-07")] == ["Wiki dangling"]
    assert [f["object"] for f in _f(rep, "DP-08")] == ["Legacy check 7"]
    assert [f["object"] for f in _f(rep, "DP-09")] == ["HQ"]                    # inactive in Client Connector
    # No finding for a compliant rule, a deny rule, a disabled rule or a narrow app without posture.
    named = {f["object"] for f in rep["findings"]}
    assert not named & {"HR on corp devices", "Block failing override", "Old allow all", "Wiki for everyone"}
    sev = [dp.SEV_ORDER[f["severity"]] for f in rep["findings"]]
    assert sev == sorted(sev)
    assert _r(rep, "HR negated cert")["flags"] == ["DP-02"]


def test_nothing_is_called_unused_when_the_access_policy_was_not_read():
    data = tenant_data()
    t = FakeTenant(data, fail={})
    snap, raw, zout = dp.read(t, pace=0)
    snap["policies"].pop("access")
    out = dp.analyze(snap, raw["posture_profiles"], raw["trusted_networks"], zout)
    assert not _f(out, "DP-05") and not _f(out, "DP-06") and any("access policy" in n for n in out["not_assessed"])


def test_without_raw_lists_the_names_still_classify_as_inferred():
    t = FakeTenant()
    snap = zr.read(t, pace=0)
    out = dp.analyze(snap)
    assert all(p["source"] in ("name", "none") for p in out["profiles"])
    assert _p(out, "CrowdStrike ZTA 40")["family"] == "edr" and _p(out, "CrowdStrike ZTA 40")["confidence"] == "inferred"


def test_client_connector_networks_add_their_criteria(rep):
    hq = next(t for t in rep["trusted_networks"] if t["name"] == "HQ")
    assert hq["zcc"]["criteria"] == ["DNS servers", "subnets"] and hq["zcc"]["active"] is False
    assert rep["zcc"]["read"] is True and rep["zcc"]["count"] == 1


# ── readable conditions ───────────────────────────────────────────────
def test_the_tree_nests_and_or_not_with_names_not_ids(rep):
    tree = _r(rep, "Nested")["tree"]
    assert tree["op"] == "AND" and tree["root"] and len(tree["children"]) == 4
    app, plat, neg, post = tree["children"]
    assert app["kind"] == "operand" and app["text"] == "segment group “HR apps”"
    assert plat["kind"] == "group" and plat["op"] == "AND" and not plat["negated"]
    assert [c["text"] for c in plat["children"]] == ["platform is macOS", "client type is Client Connector"]
    assert neg["kind"] == "group" and neg["op"] == "OR" and neg["negated"] and neg["label"] == "NOT any of these"
    assert neg["children"][0]["text"] == "device is on trusted network “HQ”" and neg["children"][1]["text"] == "country is US"
    assert post["family"] == "mobile_integrity" and "Mobile integrity" in post["text"]
    text = json.dumps(tree)
    for raw_id in ("sg-hr", "net-hq", "udid-jail"):
        assert f'"text": "{raw_id}' not in text


def test_the_html_is_nested_lists_with_group_labels_and_explicit_not(rep):
    h = _r(rep, "Nested")["html"]
    assert h.count('role="group"') == 3
    assert 'aria-label="All of these must be true"' in h and 'aria-label="NOT: none of these may be true"' in h
    assert h.index('aria-label="All of these must be true"') < h.index('aria-label="NOT: none of these may be true"')
    assert re.search(r'<ul role="group"[^>]*>.*<li><div class="ct-g ct-or ct-negated">', h)
    assert '<span class="ct-k">Segment group:</span> “HR apps”' in h and '<span class="ct-k">Platform:</span> macOS' in h
    neg = _r(rep, "Jump hosts for non-compliant")["html"]
    assert '<strong class="ct-not">NOT</strong>' in neg and "CrowdStrike ZTA 40" in neg
    dangling = _r(rep, "Wiki dangling")["html"]
    assert "not found in the tenant" in dangling
    assert "No conditions" in _r(rep, "Old allow all")["html"]


def test_the_html_escapes_every_value():
    data = tenant_data()
    data["segments"][0]["name"] = '<img src=x onerror="alert(1)">'
    out, _ = build(data)
    h = _r(out, "HR on corp devices")["html"]
    assert "<img" not in h and "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;" in h


def test_one_plain_sentence_per_rule(rep):
    assert _r(rep, "HR on corp devices")["sentence"] == (
        "Allow “HR app” for people in group “HR”, on Windows, when the device is domain-joined (“Corp AD joined”).")
    assert _r(rep, "Jump hosts for non-compliant")["sentence"] == (
        "Allow “Jump hosts” when the device fails the EDR or antivirus check (“CrowdStrike ZTA 40”).")
    assert _r(rep, "Nested")["sentence"] == (
        "Allow segment group “HR apps”, on macOS and outside country US, using Client Connector, when the device is off "
        "trusted network “HQ” and the device passes the jailbreak and root check (“Mobile integrity”).")
    assert _r(rep, "HR optional posture")["sentence"].endswith(
        "when (the device passes the EDR or antivirus check (“SentinelOne check”) or in group “HR”).")
    assert _r(rep, "Everything for everyone")["sentence"] == "Allow every application for people in group “Everyone”."
    assert _r(rep, "Old allow all")["sentence"].startswith("This rule is disabled. Allow every application for everyone")
    assert _r(rep, "Block failing override")["sentence"].startswith("Block segment group “General” when the device does not carry the marker")


def test_the_reader_is_reusable_on_its_own():
    snap = {"segments": [{"id": "s1", "name": "Payroll", "enabled": True}], "idps": [], "posture_profiles": [],
            "trusted_networks": [], "scim_groups": {}}
    rule = zr.normalize_rule(_rule("x", 1, "x", "ALLOW", _cond(APP("s1")), _cond(APP("s1"), _op("SAML", "a1", "Sales", "Dept"), negated=True),
                                   operator="OR"), 0, "access")
    out = dp.readable_rule(rule, dp.Names(snap))
    assert set(out) == {"tree", "html", "text", "sentence"}
    assert out["tree"]["op"] == "OR" and "any one of these holds" in out["sentence"]
    assert "Any of these:" in out["text"] and "NOT any of these:" in out["text"]


# ── the API ───────────────────────────────────────────────────────────
@pytest.fixture
def api(monkeypatch):
    import dlp_api_server as srv
    built = []
    tenant = FakeTenant()

    def b(creds):
        built.append(dict(creds))
        return tenant
    monkeypatch.setattr(srv, "_build_sdk_client", b)
    monkeypatch.setattr(zr, "PACE_SECONDS", 0)
    return srv, TestClient(srv.app), tenant, built


def _wait(t, job, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        snap = t.get(f"/api/dlp-packs/jobs/{job}").json()
        if snap["status"] != "running":
            return snap
        time.sleep(0.05)
    raise AssertionError("job did not finish")


@pytest.mark.parametrize("body", [{"scopes": ["dlp", "zcc"], "channels": {}, "from_page": True}, {"scopes": [], "channels": {}, "from_page": True}])
def test_refused_before_any_read_unless_zpa_is_in_scope(api, body):
    srv, t, tenant, built = api
    r = t.post("/api/device-posture/start", json=dict(CREDS, **body))
    assert r.status_code == 400 and "tick ZPA" in r.json()["detail"] and "Nothing was read" in r.json()["detail"]
    assert built == [] and tenant.calls == []


def test_refused_before_sign_in_without_a_customer_id(api, monkeypatch):
    srv, t, tenant, built = api
    monkeypatch.delenv("ZSCALER_CUSTOMER_ID", raising=False)
    r = t.post("/api/device-posture/start", json=dict(CREDS, customer_id="", **ZPA_SCOPE))
    assert r.status_code == 400 and "customer ID" in r.json()["detail"] and built == []


def test_the_job_reads_zpa_only_and_returns_the_report_without_secrets(api):
    srv, t, tenant, built = api
    r = t.post("/api/device-posture/start", json=dict(CREDS, **ZPA_SCOPE), headers={"X-Start-Token": "b" * 32})
    assert r.status_code == 200 and r.json()["kind"] == "posture"
    snap = _wait(t, r.json()["job_id"])
    assert snap["status"] == "done", snap
    res = snap["result"]
    assert res["report_id"].startswith("posture-") and res["counts"]["profiles"] == 9 and "snapshot" not in res
    assert not any(c[0] == "zcc" for c in tenant.calls), "Client Connector is not in scope"
    assert res["zcc"]["read"] is False
    blob = json.dumps(res) + json.dumps(snap)
    assert SECRET not in blob and CREDS["client_id"] not in json.dumps(res["rules"])
    assert not tenant.writes
    g = t.get(f"/api/device-posture/report/{res['report_id']}")
    assert g.status_code == 200 and g.json()["counts"] == res["counts"]
    assert t.get("/api/device-posture/report/posture-nope").status_code == 404
    assert t.get("/api/device-posture/report/zpa-nope").status_code == 404


def test_client_connector_networks_are_read_only_when_it_is_in_scope(api):
    srv, t, tenant, built = api
    r = t.post("/api/device-posture/start", json=dict(CREDS, **ZPA_ZCC_SCOPE))
    res = _wait(t, r.json()["job_id"])["result"]
    assert [c[1:3] for c in tenant.calls if c[0] == "zcc"] == [("trusted_networks", "list_by_company")]
    assert res["zcc"]["read"] is True and any(f["id"] == "DP-09" for f in res["findings"])


def test_excel_and_json_exports(api):
    srv, t, tenant, built = api
    r = t.post("/api/device-posture/start", json=dict(CREDS, **ZPA_SCOPE))
    res = _wait(t, r.json()["job_id"])["result"]
    x = t.get(f"/api/device-posture/report/{res['report_id']}/export?format=xlsx")
    assert x.status_code == 200 and x.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert "device_posture_" in x.headers["content-disposition"]
    z = zipfile.ZipFile(io.BytesIO(x.content))
    wbxml = z.read("xl/workbook.xml").decode()
    for sheet in ("Summary", "Findings", "Profiles", "Families", "Usage", "Trusted networks", "Access rules"):
        assert f'name="{sheet}"' in wbxml
    allxml = "".join(z.read(n).decode() for n in z.namelist() if n.startswith("xl/worksheets/"))
    assert "From the posture type (reliable)" in allxml and "From the name (inferred)" in allxml
    assert "NOT any of these:" in allxml and "Must fail" in allxml and SECRET not in allxml
    assert "Zscaler Made Easy" in z.read("docProps/core.xml").decode()
    j = t.get(f"/api/device-posture/report/{res['report_id']}/export?format=json")
    assert j.status_code == 200 and j.json()["counts"] == res["counts"]
    assert t.get(f"/api/device-posture/report/{res['report_id']}/export?format=pdf").status_code == 400


def test_stop_ends_the_job_with_nothing_more_read_and_nothing_kept(api):
    srv, t, tenant, built = api
    gate, entered = threading.Event(), threading.Event()

    def hook(svc, method, args):
        if svc == "server_groups":
            entered.set()
            gate.wait(10)
    tenant.hook = hook
    before = {k for k in srv._REPORTS if k.startswith("posture-")}
    r = t.post("/api/device-posture/start", json=dict(CREDS, **ZPA_SCOPE))
    job = r.json()["job_id"]
    assert entered.wait(10)
    assert t.post(f"/api/dlp-packs/jobs/{job}/cancel").status_code == 200
    n = len(tenant.calls)
    gate.set()
    snap = _wait(t, job)
    assert snap["status"] == "cancelled", snap
    assert (snap["result"] or {}).get("stopped") and "findings" not in (snap["result"] or {})
    assert len(tenant.calls) == n
    assert any("nothing more is read" in l for l in snap["logs"])
    assert {k for k in srv._REPORTS if k.startswith("posture-")} == before


def test_a_failed_list_error_never_carries_the_secret(api):
    srv, t, tenant, built = api
    tenant.fail["posture_profiles"] = f"401 bad client_secret={SECRET}"
    r = t.post("/api/device-posture/start", json=dict(CREDS, **ZPA_SCOPE))
    snap = _wait(t, r.json()["job_id"])
    res = snap["result"]
    assert SECRET not in json.dumps(snap)
    assert res["counts"]["profiles"] == 0 and any("Posture profiles could not be read" in n for n in res["not_assessed"])


# ── the page ──────────────────────────────────────────────────────────
def _read(*p):
    return open(os.path.join(ROOT, *p), encoding="utf-8").read()


def test_the_page_follows_the_report_page_conventions():
    import dlp_api_server as srv
    html_ = _read("static", "report_device_posture.html")
    assert '<header class="hero rp-hero">' in html_ and '<nav class="rp-bar" aria-label="Page actions">' in html_
    assert '<a class="rp-btn" href="/">← Back to the assessment</a>' in html_ and '<main class="rp-card"' in html_
    order = [html_.index(f'<script src="/static/{s}"></script>') for s in ("icons.js", "ui_auth.js", "report_theme.js", "safety_banner.js", "explain.js")]
    assert order == sorted(order)
    assert 'role="status"' in html_ and 'aria-live="polite"' in html_ and 'role="tablist"' in html_
    style = html_[html_.index("<style>"):html_.index("</style>")]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", style) and "linear-gradient" not in style and "box-shadow" not in style
    assert "prefers-reduced-motion" in style
    assert "/api/device-posture/start" in html_ and "/api/dlp-packs/jobs/stop-before-start" in html_ and "format=xlsx" in html_
    assert "DLP-Check" not in html_, "new user-visible text uses the new app name"
    r = TestClient(srv.app).get("/report/device-posture")
    assert r.status_code == 200 and "Device posture" in r.text and "no-cache" in r.headers["cache-control"]


def test_the_page_is_explained_on_the_toolbar_in_the_overview_and_glossary():
    js = _read("static", "explain.js")
    # Its own key: X.posture is Improve my score (a shared key made this page show that page's explainer).
    assert js.count("  X.deviceposture = {") == 1 and "'/report/device-posture': 'deviceposture'" in js
    assert "'deviceposture'" in js[js.index("DLP_EXPLAIN_ORDER"):]
    assert "group: 'Find the gaps', name: 'Device posture'" in js[js.index("  X.deviceposture = {"):][:200]
    html_ = _read("static", "index.html")
    assert 'onclick="openDevicePostureTab()"' in html_ and "function openDevicePostureTab()" in html_
    assert "Device posture" in _read("docs", "OVERVIEW.md")
    g = _read("static", "glossary.js")
    for term in ("device posture", "trusted network", "edr", "domain-joined", "negated condition"):
        assert f"'{term}':" in g, term

