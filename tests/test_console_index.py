"""The console index (console_index.py, POST /api/console-index): what the
browser extension's badges and side panel show about each DLP object, and
the narrow trust the app gives the extension (read-only endpoints only)."""
from __future__ import annotations

import json

import pytest

import console_index as ci
import security
from test_pack_export import ALL_DLP_IN_SCOPE, SECRET, ReadOnly, _source

EXT = security.extension_origin()


def _inventory():
    import pack_removal
    return pack_removal.inventory(_source())


def test_the_index_says_what_uses_what_and_flags_what_never_acts():
    idx = ci.from_inventory(_inventory(), tenant_label="acme", now=1000)
    by = {(o["kind"], o["name"]): o for o in idx["objects"]}
    leak = by[("engine", "Project Leak")]
    assert leak["uses"]["dictionaries"] == ["Project Codes", "SSN"] and leak["used_by"]["rules"] == ["SaaS-Projects", "Web-Projects"]
    assert leak["counts"] == {"rules": 2, "dictionaries": 2} and leak["findings"] == []
    unused = by[("engine", "Unused Engine")]
    assert unused["counts"]["rules"] == 0 and "never acts" in unused["findings"][0]["text"]
    phrases = by[("dictionary", "Board Phrases")]
    assert set(phrases["used_by"]["engines"]) == {"Board Leak", "Unused Engine"}
    assert set(phrases["used_by"]["rules"]) == {"EP-Board", "Email-Board"}
    web_pci = by[("rule", "Web-PCI")]
    assert web_pci["channel"] == "web" and web_pci["state"] == "DISABLED" and web_pci["findings"][0]["severity"] == "info"
    ep = by[("rule", "EP-Board")]
    assert any("Monitor only" in f["text"] for f in ep["findings"]), "an enabled ALLOW rule only logs"
    assert idx["counts"]["rule"] == 5 and idx["counts"]["engine"] == 3 and idx["read_at"] == 1000


def test_shadowed_rule_findings_are_merged_when_given():
    shadow = {("web", "Web-PCI"): [{"severity": "high", "reason": "Rule 'Web-PCI' can never match: 'Block all' above it matches everything."}]}
    idx = ci.from_inventory(_inventory(), shadow=shadow)
    pci = next(o for o in idx["objects"] if o["name"] == "Web-PCI")
    assert {"severity": "high", "text": shadow[("web", "Web-PCI")][0]["reason"], "short": "shadowed"} in pci["findings"]


def test_shadow_findings_map_from_policy_to_channel_and_skip_disabled():
    findings = [{"policy": "web_dlp", "rule": "Web-PCI", "kind": "shadowed", "severity": "high", "reason": "Shadowed."},
                {"policy": "web_dlp", "rule": "Web-PCI", "kind": "disabled", "severity": "info", "reason": "Disabled."},
                {"policy": "endpoint_dlp", "rule": "EP-Board", "kind": "superseded", "severity": "medium", "reason": "Superseded."},
                {"policy": "url_filtering", "rule": "Block all", "kind": "duplicate", "severity": "low", "reason": "Dup."}]
    by = ci.shadow_by_channel(findings)
    assert set(by) == {("web", "Web-PCI"), ("endpoint", "EP-Board")}
    assert [f["kind"] for f in by[("web", "Web-PCI")]] == ["shadowed"]


def test_the_index_holds_no_secret_user_or_file_name():
    blob = json.dumps(ci.from_inventory(_inventory(), tenant_label="acme"))
    assert SECRET not in blob and "abc123456789" not in blob


def test_the_cache_is_per_tenant_and_scope_and_expires(monkeypatch):
    ci.cache_clear()
    k1, k2 = ci.cache_key("p1", ["web"]), ci.cache_key("p1", ["web", "email"])
    assert k1 != k2 and ci.cache_key("p1", ["email", "web"]) == k2
    ci.cache_put(k1, {"objects": [], "read_at": 1})
    assert ci.cache_get(k1)["cached_at"] and ci.cache_get(k2) is None
    monkeypatch.setattr(ci, "CACHE_SECONDS", -1)
    assert ci.cache_get(k1) is None


@pytest.fixture
def api(monkeypatch, tmp_path):
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    import dlp_api_server as srv
    from fastapi.testclient import TestClient
    ro = ReadOnly(_source())
    reads = []
    monkeypatch.setattr(srv, "_build_sdk_client", lambda creds: reads.append(1) or ro)
    ci.cache_clear()
    return TestClient(srv.app), ro, reads


CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": SECRET}


def test_the_endpoint_reads_once_then_serves_the_cache_until_refresh(api):
    c, ro, reads = api
    r = c.post("/api/console-index", json=dict(CREDS, **ALL_DLP_IN_SCOPE))
    assert r.status_code == 200, r.text
    first = r.json()
    assert first["status"] == "ready" and first["counts"]["rule"] == 5 and first["cached_at"] is None
    again = c.post("/api/console-index", json=dict(CREDS, **ALL_DLP_IN_SCOPE)).json()
    assert again["cached_at"] and len(reads) == 1, "the second call is served from the 30-minute cache"
    c.post("/api/console-index", json=dict(CREDS, refresh=True, **ALL_DLP_IN_SCOPE))
    assert len(reads) == 2
    assert ro.writes == [] and SECRET not in json.dumps(first)


def test_nothing_in_scope_is_refused_before_any_read(api):
    c, _, reads = api
    r = c.post("/api/console-index", json=dict(CREDS, scopes=["zcc"], channels={}, from_page=True))
    assert r.status_code == 400 and reads == []


def test_the_extension_may_post_only_to_its_read_only_endpoints(api):
    c, _, _ = api
    assert EXT.startswith("chrome-extension://") and len(EXT) == len("chrome-extension://") + 32
    ok = c.post("/api/console-index", json=dict(CREDS, **ALL_DLP_IN_SCOPE), headers={"Origin": EXT})
    assert ok.status_code == 200, ok.text
    assert c.post("/api/dlp-packs/export/start", json=dict(CREDS, parts=["engines"], **ALL_DLP_IN_SCOPE), headers={"Origin": EXT}).status_code == 200
    # Any write, or any other endpoint, from the extension's origin is refused by the origin check.
    for path in ("/api/dlp-packs/apply", "/api/dlp-packs/removal/apply", "/api/write-mode", "/api/tenant-profiles", "/api/console-index/x"):
        r = c.post(path, json={}, headers={"Origin": EXT})
        assert r.status_code == 403 and "Origin not allowed" in r.text, (path, r.status_code)
    # Another extension, or a web page, gets nothing.
    other = "chrome-extension://" + "a" * 32
    assert c.post("/api/console-index", json={}, headers={"Origin": other}).status_code == 403
    assert c.post("/api/console-index", json={}, headers={"Origin": "https://evil.example"}).status_code == 403


def test_the_extension_trust_can_be_moved_or_switched_off(monkeypatch):
    monkeypatch.setenv("DLP_CHECK_EXTENSION_ID", "off")
    assert security.extension_origin() == "" and not security.extension_may_post(EXT, "/api/console-index")
    monkeypatch.setenv("DLP_CHECK_EXTENSION_ID", "b" * 32)
    assert security.extension_origin() == "chrome-extension://" + "b" * 32
    monkeypatch.setenv("DLP_CHECK_EXTENSION_ID", "not-an-id")
    assert security.extension_origin() == ""


# ── ZIA policies and the objects their rules reference ─────────────────
PERSON, DEVICE, ADMIN, NOTE, URL = "jane.doe@acme.example", "Jane's MacBook", "admin.bob@acme.example", "Asked by Jane Doe", "secret-partner.example"


def _zia_rules():
    return {
        "url_filtering": [
            {"id": 10, "name": "Allow all", "order": 1, "state": "ENABLED", "action": "ALLOW", "labels": [{"id": 7, "name": "Baseline"}]},
            {"id": 11, "name": "Block gambling", "order": 2, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["GAMBLING", "CUSTOM_01"],
             "groups": [{"id": 3, "name": "Finance"}], "locations": [{"id": 1, "name": "HQ"}], "users": [{"id": 99, "name": PERSON}],
             "overrideUsers": [{"id": 98, "name": PERSON}], "lastModifiedBy": {"id": 5, "name": ADMIN}, "description": NOTE,
             "labels": [{"id": 7, "name": "Baseline"}]},
            {"id": 12, "name": "Old rule", "order": 3, "state": "DISABLED", "action": "BLOCK", "urlCategories": ["CUSTOM_01"],
             "departments": [{"id": 4, "name": "Engineering"}], "excludedUsers": [{"id": 97, "name": PERSON}]},
        ],
        "ssl_inspection": [{"id": 30, "name": "Inspect finance", "order": 1, "state": "ENABLED", "action": {"type": "DECRYPT"},
                            "urlCategories": ["FINANCE"], "locationGroups": [{"id": 8, "name": "Branches"}]}],
        "firewall": [{"id": 20, "name": "Allow DNS", "order": 1, "state": "ENABLED", "action": "ALLOW", "nwServices": [{"id": 5, "name": "DNS"}],
                      "srcIpGroups": [{"id": 6, "name": "Servers"}], "destIpGroups": [{"id": 9, "name": "Partners"}], "destIpCategories": ["CUSTOM_02"],
                      "nwApplications": ["APNS"], "nwServiceGroups": [{"id": 2, "name": "Web services"}], "devices": [{"id": 1, "name": DEVICE}]}],
        "cloud_app_control": [{"id": 40, "name": "Block webmail upload", "order": 1, "state": "ENABLED", "type": "WEBMAIL",
                               "actions": ["BLOCK_WEBMAIL_ATTACHMENT_SEND"], "applications": ["GMAIL"], "groups": [{"id": 3, "name": "Finance"}]}],
        "file_type_control": [{"id": 50, "name": "Block exe", "order": 1, "state": "ENABLED", "filteringAction": "BLOCK",
                               "fileTypes": ["FTCATEGORY_WINDOWS_EXECUTABLES"], "urlCategories": ["GAMBLING"], "users": [{"id": 99, "name": PERSON}]}],
        "web_dlp": [{"id": 101, "name": "Web-Projects", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": [{"id": "CUSTOM_01"}],
                     "locations": [{"id": 1, "name": "HQ"}], "dlpEngines": [{"id": 2001, "name": "Project Leak"}]}],
    }


CATEGORIES = [{"id": "GAMBLING", "customCategory": False}, {"id": "FINANCE", "customCategory": False},
              {"id": "CUSTOM_01", "configuredName": "Partner sites", "customCategory": True, "urls": [URL], "keywords": ["partner"]},
              {"id": "CUSTOM_02", "configuredName": "Partner IPs", "customCategory": True},
              {"id": "CUSTOM_03", "configuredName": "Never used", "customCategory": True}]


def _zia(**over):
    import shadow_rules
    rules = _zia_rules()
    res = shadow_rules.analyse({k: v for k, v in rules.items() if k in shadow_rules.POLICIES}, categories=CATEGORIES)
    z = {"rules": rules, "categories": CATEGORIES, "findings": res["findings"], "read_errors": {}, "not_in_scope": {}}
    z.update(over)
    return z


def _by(idx):
    return {(o["kind"], o["name"]): o for o in idx["objects"]}


def test_url_categories_count_their_rules_per_policy_and_an_unused_custom_one_is_a_finding():
    by = _by(ci.from_inventory(_inventory(), zia=_zia(), now=1))
    partner = by[("url_category", "Partner sites")]
    assert partner["custom"] and partner["id"] == "CUSTOM_01" and not partner["name_derived"]
    assert partner["used_by"] == {"url_filtering": ["Block gambling", "Old rule"], "web_dlp": ["Web-Projects"]}
    assert partner["counts"] == {"rules": 3, "by_policy": {"url_filtering": 2, "web_dlp": 1}} and partner["findings"] == []
    gambling = by[("url_category", "Gambling")]
    assert not gambling["custom"] and gambling["name_derived"] and gambling["counts"]["by_policy"] == {"url_filtering": 1, "file_type_control": 1}
    assert by[("url_category", "Partner IPs")]["used_by"] == {"firewall": ["Allow DNS"]}, "Cloud Firewall names categories in destIpCategories"
    unused = by[("url_category", "Never used")]
    assert unused["counts"]["rules"] == 0 and unused["findings"][0]["short"] == "unused" and unused["findings"][0]["severity"] == "low"
    assert "Bandwidth Control" in unused["findings"][0]["text"], "it says what was not checked"
    # A predefined category no rule names is not indexed (only custom ones are, used or not).
    assert ("url_category", "Finance") in by and not any(o["kind"] == "url_category" and o["id"] == "OTHER_ADULT_MATERIAL" for o in by.values())
    assert ci.category_label("NEWS_AND_MEDIA") == "News and Media" and ci.category_label("OTHER_ADULT_MATERIAL") == "Other Adult Material"


def test_an_unused_custom_category_says_which_policies_were_not_read():
    z = _zia()
    z["rules"].pop("firewall")
    z["not_in_scope"] = {"firewall": "Not in scope"}
    f = _by(ci.from_inventory(_inventory(), zia=z))[("url_category", "Partner IPs")]["findings"][0]
    assert "Cloud Firewall not read" in f["text"], f


def test_policy_rules_carry_order_state_action_references_and_shadow_findings():
    by = _by(ci.from_inventory(_inventory(), zia=_zia()))
    gamb = by[("url_rule", "Block gambling")]
    assert gamb["policy"] == "url_filtering" and gamb["order"] == 2 and gamb["state"] == "ENABLED" and gamb["action"] == "BLOCK"
    assert gamb["uses"] == {"url_category": ["Gambling", "Partner sites"], "group": ["Finance"], "location": ["HQ"], "label": ["Baseline"]}
    assert gamb["key"] == "url_rule:Block gambling"
    shadowed = [f for f in gamb["findings"] if f["short"] == "shadowed"]
    assert shadowed and shadowed[0]["severity"] == "high" and "Allow all" in shadowed[0]["text"], gamb["findings"]
    old = by[("url_rule", "Old rule")]
    assert [f["short"] for f in old["findings"]] == ["disabled"], "the analysis' own disabled finding is not repeated"
    assert by[("ssl_rule", "Inspect finance")]["action"] == "DECRYPT"
    fw = by[("firewall_rule", "Allow DNS")]
    assert fw["uses"]["network_service"] == ["DNS"] and fw["uses"]["network_application"] == ["APNS"]
    assert fw["uses"]["source_ip_group"] == ["Servers"] and fw["uses"]["destination_ip_group"] == ["Partners"]
    cac = by[("cac_rule", "Block webmail upload")]
    assert cac["key"] == "cac_rule:WEBMAIL:Block webmail upload" and cac["actions"] == ["BLOCK_WEBMAIL_ATTACHMENT_SEND"]
    ftc = by[("ftc_rule", "Block exe")]
    assert ftc["policy"] == "file_type_control" and ftc["action"] == "BLOCK" and ftc["uses"] == {"url_category": ["Gambling"], "file_type": ["Windows executables"]}


def test_referenced_objects_say_which_rules_use_them_per_policy():
    idx = ci.from_inventory(_inventory(), zia=_zia())
    by = _by(idx)
    finance = by[("group", "Finance")]
    assert finance["used_by"] == {"url_filtering": ["Block gambling"], "cloud_app_control": ["Block webmail upload"]}
    assert finance["counts"] == {"rules": 2, "by_policy": {"url_filtering": 1, "cloud_app_control": 1}}
    hq = by[("location", "HQ")]
    assert hq["used_by"] == {"url_filtering": ["Block gambling"], "web_dlp": ["Web-Projects"]}
    assert by[("location_group", "Branches")]["used_by"] == {"ssl_inspection": ["Inspect finance"]}
    assert by[("department", "Engineering")]["counts"]["rules"] == 1
    assert by[("label", "Baseline")]["counts"]["by_policy"] == {"url_filtering": 2}
    for kind, name in (("network_service", "DNS"), ("network_service_group", "Web services"), ("network_application", "APNS"),
                       ("source_ip_group", "Servers"), ("destination_ip_group", "Partners")):
        assert by[(kind, name)]["used_by"] == {"firewall": ["Allow DNS"]}, kind
    # The DLP rule gains what its raw rule references, next to its engines.
    proj = by[("rule", "Web-Projects")]
    assert proj["uses"]["url_category"] == ["Partner sites"] and proj["uses"]["location"] == ["HQ"] and proj["uses"]["engines"]
    assert idx["counts"]["url_rule"] == 3 and idx["counts"]["location"] == 1 and idx["counts"]["url_category"] == 5
    assert idx["policy_kinds"]["firewall"] == "firewall_rule" and idx["policy_labels"]["file_type_control"] == "File Type Control"
    kinds = {k["kind"]: k for k in idx["kinds"]}
    assert kinds["rule"]["export"] and not kinds["url_category"]["export"] and kinds["url_rule"]["label"] == "URL filtering rule"
    assert idx["zia"]["read"][:1] == ["web_dlp"] and "file_type_control" in idx["zia"]["read"]
    # Every object has a unique key the extension uses for badges, the panel and the stage.
    keys = [o["key"] for o in idx["objects"]]
    assert len(keys) == len(set(keys))


def test_the_zia_part_holds_no_user_device_admin_description_or_url():
    blob = json.dumps(ci.from_inventory(_inventory(), zia=_zia()))
    for leak in (PERSON, DEVICE, ADMIN, NOTE, URL, '"partner"'):
        assert leak not in blob, leak
    assert not any(k in blob for k in ('"user"', '"users"', '"device"'))


def test_each_kind_is_capped_with_a_count_of_the_rest(monkeypatch):
    monkeypatch.setattr(ci, "MAX_PER_KIND", 5)
    rules = [{"id": i, "name": f"Rule {i:03d}", "order": i, "state": "ENABLED", "action": "ALLOW",
              "locations": [{"id": i, "name": f"Site {i:03d}"}] + ([{"id": 0, "name": "Busy site"}] if i % 2 else [])} for i in range(1, 41)]
    idx = ci.from_inventory(_inventory(), zia={"rules": {"url_filtering": rules}, "categories": None, "findings": []})
    assert idx["counts"]["location"] == 5 and idx["more"]["location"] == 36 and idx["more"]["url_rule"] == 35
    assert any(o["name"] == "Busy site" for o in idx["objects"]), "the most used are kept"
    assert idx["counts"]["dictionary"] <= 5


def test_the_reader_reads_only_what_is_in_scope_and_file_type_control_with_it():
    import shadow_rules
    from test_shadow_rules import ReadOnlyClient
    rules = _zia_rules()
    routes = {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}, "/zia/dlpEngines": [{"id": 2001, "name": "Project Leak"}],
              "/zia/urlCategories": CATEGORIES, "/zia/fileTypeRules": rules["file_type_control"]}
    for key, p in shadow_rules.POLICIES.items():
        routes[p["endpoint"]] = rules.get(key, [])
    c = ReadOnlyClient(routes)
    z = ci.zia_read(c, shadow_rules.scope_for(["zia_extras"], {}), ftc=True)
    eps = [e for _, e in c.calls]
    assert "/zia/firewallFilteringRules" in eps and "/zia/fileTypeRules" in eps and "/zia/webDlpRules" not in eps
    assert set(z["rules"]) == {"url_filtering", "firewall", "file_type_control"} | ({"ssl_inspection", "cloud_app_control"} & set(z["rules"]))
    assert z["categories"] and any(f["policy"] == "url_filtering" and f["rule"] == "Block gambling" for f in z["findings"])
    c2 = ReadOnlyClient(routes)
    z2 = ci.zia_read(c2, shadow_rules.scope_for([], {}), ftc=False)
    assert c2.calls == [] and z2["rules"] == {} and "file_type_control" in z2["not_in_scope"]


@pytest.fixture
def zapi(api, monkeypatch):
    import shadow_rules
    import dlp_api_server as srv
    from test_shadow_rules import ReadOnlyClient
    rules = _zia_rules()
    routes = {"/zia/webDlpGlobalOptions": {"enableEvaluateAllDlpRules": False}, "/zia/dlpEngines": [{"id": 2001, "name": "Project Leak"}],
              "/zia/urlCategories": CATEGORIES, "/zia/fileTypeRules": rules["file_type_control"]}
    for key, p in shadow_rules.POLICIES.items():
        routes[p["endpoint"]] = rules.get(key, [])
    raw = ReadOnlyClient(routes)
    monkeypatch.setattr(srv, "_build_client", lambda req: raw)
    return api + (raw,)


def test_the_endpoint_indexes_the_zia_policies_in_scope(zapi):
    c, ro, reads, raw = zapi
    body = dict(CREDS, scopes=["dlp", "zia_extras"], channels=ALL_DLP_IN_SCOPE["channels"], from_page=True)
    idx = c.post("/api/console-index", json=body).json()
    by = _by(idx)
    assert ("firewall_rule", "Allow DNS") in by and ("ftc_rule", "Block exe") in by and ("url_category", "Partner sites") in by
    assert by[("rule", "Web-Projects")]["uses"]["location"] == ["HQ"] and idx["counts"]["rule"] == 5
    assert all(m == "GET" for m, _ in raw.calls) and ro.writes == []
    assert PERSON not in json.dumps(idx) and SECRET not in json.dumps(idx)
    # The same tenant with a narrower scope is another cache entry, read again, without Cloud Firewall.
    raw.calls.clear()
    idx2 = c.post("/api/console-index", json=dict(CREDS, **ALL_DLP_IN_SCOPE)).json()
    assert idx2["cached_at"] is None and "/zia/firewallFilteringRules" not in [e for _, e in raw.calls]
    assert not any(o["kind"] == "firewall_rule" for o in idx2["objects"])


def test_without_a_dlp_channel_the_zia_policies_alone_make_the_index(zapi):
    c, ro, reads, raw = zapi
    r = c.post("/api/console-index", json=dict(CREDS, scopes=["zia_extras"], channels={}, from_page=True))
    assert r.status_code == 200, r.text
    idx = r.json()
    assert reads == [], "no DLP channel in scope: the DLP inventory is not read"
    assert idx["counts"]["rule"] == 0 and idx["counts"]["dictionary"] == 0 and idx["counts"]["firewall_rule"] == 1
    assert "/zia/webDlpRules" not in [e for _, e in raw.calls]


def test_the_manifest_key_gives_the_id_the_app_trusts():
    import base64
    import hashlib
    import os
    m = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "browser_extension", "manifest.json")))
    digest = hashlib.sha256(base64.b64decode(m["key"])).hexdigest()[:32]
    ext_id = "".join(chr(ord("a") + int(ch, 16)) for ch in digest)
    assert ext_id == security.EXTENSION_ID
