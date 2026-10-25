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
    assert {"severity": "high", "text": shadow[("web", "Web-PCI")][0]["reason"]} in pci["findings"]


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


def test_the_manifest_key_gives_the_id_the_app_trusts():
    import base64
    import hashlib
    import os
    m = json.load(open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "browser_extension", "manifest.json")))
    digest = hashlib.sha256(base64.b64decode(m["key"])).hexdigest()[:32]
    ext_id = "".join(chr(ord("a") + int(ch, 16)) for ch in digest)
    assert ext_id == security.EXTENSION_ID
