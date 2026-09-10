"""Data Flow Map: the path tracer through Client Connector, forwarding
profiles, PAC, SSL, URL filtering, app control, file type control and DLP."""
from __future__ import annotations

from fastapi.testclient import TestClient

import data_flow as df
import dlp_api_server as srv
from test_ssl_flow import FakeCl, CATALOGUE

APP_PROFILES = [
    {"id": 11, "name": "Windows-Corp", "os": "windows", "active": True, "ruleOrder": 1, "forwardingProfileId": 5,
     "strictEnforcement": True, "installEndpointDlp": True, "sslCertInstall": True,
     "hostnameBypassForIpv4": ["*.internal.corp", "updates.vendor.com"], "appBypassCustom": [{"name": "Zoom", "path": "zoom.exe"}], "ipExclusions": ["10.0.0.0/8"]},
    {"id": 12, "name": "Mac-Contractors", "os": "mac", "active": True, "ruleOrder": 2, "forwardingProfileId": 6,
     "strictEnforcement": False, "installEndpointDlp": False, "sslCertInstall": True},
]
FWD = [
    {"id": 5, "name": "Corp forwarding", "forwardingProfileActions": [
        {"networkType": "ON_TRUSTED_NETWORK", "tunnelType": "ZSCALER_TUNNEL_2"},
        {"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "ZSCALER_TUNNEL_2"},
        {"networkType": "VPN_TRUSTED_NETWORK", "tunnelType": "NONE"}]},
    {"id": 6, "name": "Contractor forwarding", "forwardingProfileActions": [
        {"networkType": "ON_TRUSTED_NETWORK", "tunnelType": "NONE"},
        {"networkType": "OFF_TRUSTED_NETWORK", "tunnelType": "ENFORCE_PROXY"}]},
]
PAC = [{"id": 1, "name": "corp.pac", "pacContent": 'function FindProxyForURL(url, host) { if (shExpMatch(host, "*.box.com")) { return "DIRECT"; } return "PROXY gateway.zscaler.net:80"; }'}]
SSL = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["FINANCE"]},
    {"id": 2, "name": "No decrypt webmail", "order": 2, "state": "ENABLED", "action": {"type": "DO_NOT_DECRYPT"}, "urlCategories": ["WEB_MAIL", "WEBMAIL"]},
    {"id": 3, "name": "Decrypt all", "order": 3, "state": "ENABLED", "action": {"type": "DECRYPT"}, "urlCategories": ["ANY"]},
]
URL = [{"id": 20, "name": "Block gambling", "order": 1, "state": "ENABLED", "action": "BLOCK", "urlCategories": ["GAMBLING"]},
       {"id": 21, "name": "Allow file sharing", "order": 2, "state": "ENABLED", "action": "ALLOW", "urlCategories": ["FILE_HOST", "ONLINE_STORAGE"]}]
CAC = [{"id": 30, "name": "AI no upload", "state": "ENABLED", "type": "AI_ML", "applications": ["CHATGPT_AI"], "actions": ["ALLOW_AI_ML_WEB_USE", "BLOCK_AI_ML_UPLOAD"]},
       {"id": 31, "name": "File share allow all", "state": "ENABLED", "type": "FILE_SHARE", "cloudAppClasses": ["FILE_SHARE"], "actions": ["ALLOW_FILE_SHARE_UPLOAD", "ALLOW_FILE_SHARE_VIEW"]}]
FTC = [{"id": 40, "name": "Block archives to file share", "state": "ENABLED", "filteringAction": "BLOCK", "operation": "UPLOAD", "fileTypes": ["FTCATEGORY_ZIP"], "cloudAppClasses": ["FILE_SHARE"]}]
DLP = [{"id": 50, "name": "Bank-Customer PII-Monitor", "order": 1, "state": "ENABLED", "action": "ALLOW", "dlpEngines": [{"name": "Bank-Customer PII (Global)"}]},
       {"id": 51, "name": "Bank-Payment Card Data-Bulk-Block", "order": 2, "state": "ENABLED", "action": "BLOCK", "cloudApplications": ["CHATGPT_AI"], "dlpEngines": [{"name": "Bank-Payment Card Data - Bulk"}]}]
ROUTES = {
    "/zcc/webPolicies": APP_PROFILES, "/zcc/forwardingProfiles": FWD, "/zcc/trustedNetworks": [{"id": 1, "name": "HQ", "dnsServers": ["10.1.1.1"]}],
    "/zia/pacFiles": PAC, "/zia/sslInspectionRules": SSL, "/zia/urlFilteringRules": URL, "/zia/cloudApplicationRules": CAC,
    "/zia/fileTypeControlRules": FTC, "/zia/webDlpRules": DLP,
    "/zia/endpointDlpRules": [{"id": 60, "name": "Bank-Endpoint-Monitor", "state": "ENABLED", "action": "ALLOW"}],
    "/zia/casbDlpRules": [], "/zia/emailDlpRules": [{"id": 70, "name": "Bank-Email-Monitor", "state": "DISABLED", "action": "ALLOW"}],
    "/zia/urlCategories": [{"id": "FILE_HOST", "configuredName": "File Sharing", "urls": [], "dbCategorizedUrls": []},
                           {"id": "CUSTOM_01", "configuredName": "Partner portals", "customCategory": True, "urls": ["portal.partner.com"], "dbCategorizedUrls": []}],
}


def _client():
    return FakeCl(ROUTES, CATALOGUE)


def test_client_connector_readers_interpret_profiles_forwarding_and_pac():
    zcc = df.read_client_connector(_client())
    assert zcc["errors"] == []
    win = next(p for p in zcc["app_profiles"] if p["platform"] == "windows")
    assert win["bypass"]["domains"] == ["*.internal.corp", "updates.vendor.com"] and win["bypass"]["apps"] == ["Zoom"] and win["bypass"]["ips"] == ["10.0.0.0/8"]
    assert win["endpoint_dlp"] and win["strict_enforcement"] and win["forwarding_profile"] == 5
    corp = next(f for f in zcc["forwarding_profiles"] if f["id"] == 5)
    assert corp["actions"]["on"]["mode_kind"] == "tunnel" and corp["actions"]["vpn"]["mode_kind"] == "none"
    contractor = next(f for f in zcc["forwarding_profiles"] if f["id"] == 6)
    assert contractor["actions"]["off"]["mode_label"] == "Enforce proxy (PAC)"
    assert zcc["pac_files"][0]["direct_hosts"] == ["*.box.com"]
    assert df.classify_mode("4") == ("Z-Tunnel 2.0", "tunnel") and df.classify_mode("TUNNEL_WITH_LOCAL_PROXY")[1] == "tunnel" and df.classify_mode("")[1] == "unknown"


def test_trace_follows_every_hop_and_names_the_weak_points():
    rep = df.generate_data_flow_report(_client(), platform="windows")
    by = {(t["destination"]["class"], t["network"]): t for t in rep["traces"]}
    # AI on Windows off network: tunnelled, decrypted, app control blocks upload, DLP enforces.
    t = by[("ai_ml", "off")]
    keys = [h["key"] for h in t["hops"]]
    assert keys == ["zcc", "forwarding", "ssl", "url", "cac", "ftc", "dlp"] and t["reaches_zscaler"] and t["decrypted"]
    assert next(h for h in t["hops"] if h["key"] == "cac")["status"] == "blocked"
    assert next(h for h in t["hops"] if h["key"] == "dlp")["status"] == "enforce" and t["outcome"] == "enforce"
    # Webmail: left encrypted by the exemption -> blind, high weak point at SSL.
    w = by[("webmail", "off")]
    ssl = next(h for h in w["hops"] if h["key"] == "ssl")
    assert ssl["status"] == "blind" and ssl["decided_by"]["name"] == "No decrypt webmail" and w["outcome"] == "blind"
    assert w["weak_points"][0]["severity"] == "high" and w["weak_points"][0]["hop"] == "ssl"
    # File share: URL allows, app control allows upload (weak), FTC blocks zips, DLP monitor only.
    f = by[("file_share", "off")]
    assert next(h for h in f["hops"] if h["key"] == "url")["decided_by"]["name"] == "Allow file sharing"
    assert next(h for h in f["hops"] if h["key"] == "cac")["status"] == "warn"
    assert next(h for h in f["hops"] if h["key"] == "ftc")["status"] == "blocked"
    assert next(h for h in f["hops"] if h["key"] == "dlp")["status"] == "monitor"
    # On VPN the corp forwarding profile forwards nothing: never reaches Zscaler.
    v = by[("ai_ml", "vpn")]
    assert not v["reaches_zscaler"] and v["outcome"] == "bypassed" and v["hops"][1]["status"] == "bypass"
    assert v["channels"]["endpoint"]["status"] == "monitor"          # Endpoint DLP is the remaining control on the device
    assert v["channels"]["email"]["status"] == "none" and v["channels"]["email"]["weak_point"]["title"] == "Email not covered"
    # Pack overlay: the banking pack's rules are found by name in every channel.
    bank = next(p for p in t["packs"] if p["id"] == "global_banking_baseline")
    st = {r["name"]: r for r in bank["rules"]}
    assert st["Bank-Customer PII-Monitor"]["state"] == "monitoring" and st["Bank-Customer PII-Monitor"]["on_path"]
    assert st["Bank-Payment Card Data-Bulk-Block"]["state"] == "enforcing" and st["Bank-Email-Monitor"]["state"] == "disabled"
    assert st["Bank-SaaS File-Monitor"]["state"] == "missing" and bank["coverage"] == "partial"
    s = rep["summary"]
    assert s["traces"] == len(df.TRAFFIC_CLASSES) * 3 and s["bypassed"] >= len(df.TRAFFIC_CLASSES) and s["high"] > 0


def test_custom_destinations_hostname_bypass_pac_direct_and_mac_contractor():
    rep = df.generate_data_flow_report(_client(), platform="windows")
    # A hostname the app profile bypasses never leaves the device towards Zscaler.
    t = df.trace_from_report(rep, "files.internal.corp", "off", "windows")
    assert t["hops"][0]["status"] == "bypass" and "internal.corp" in t["hops"][0]["detail"] and t["outcome"] == "bypassed"
    # A custom category resolves by its configured name and its URL.
    c = df.trace_from_report(rep, "Partner portals", "off", "windows")
    assert c["destination"]["kind"] == "category" and c["destination"]["categories"] == ["CUSTOM_01"]
    h = df.trace_from_report(rep, "https://portal.partner.com/login", "off", "windows")
    assert h["destination"]["kind"] == "host" and h["destination"]["categories"] == ["CUSTOM_01"]
    # macOS contractors: on network nothing is forwarded; off network PAC mode and box.com goes DIRECT.
    m = df.trace_from_report(rep, "chatgpt_ai", "on", "macos")
    assert m["hops"][1]["status"] == "bypass" and "Contractor forwarding" in m["hops"][1]["detail"]
    b = df.trace_from_report(rep, "app.box.com", "off", "macos")
    assert [h["key"] for h in b["hops"]][:3] == ["zcc", "forwarding", "pac"] and b["hops"][2]["status"] == "bypass"
    assert b["channels"]["endpoint"]["status"] == "off"             # profile does not install Endpoint DLP
    # An application name straight from the catalogue.
    a = df.trace_from_report(rep, "CHATGPT_AI", "off", "windows")
    assert a["destination"]["kind"] == "application" and a["outcome"] == "enforce"


def test_data_flow_api_page_trace_and_export(monkeypatch):
    monkeypatch.setattr(srv, "_build_client", lambda req: _client())
    c = TestClient(srv.app)
    body = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret"}
    r = c.post("/api/report/data-flow", json=body)
    assert r.status_code == 200, r.text[:300]
    rep = r.json()
    rid = rep["report_id"]
    assert rid.startswith("dataflow-") and rep["summary"]["traces"] == len(df.TRAFFIC_CLASSES) * 3
    assert c.get(f"/api/report/data-flow/{rid}").status_code == 200
    t = c.post(f"/api/report/data-flow/{rid}/trace", json={"destination": "webmail", "network": "off", "platform": "windows"})
    assert t.status_code == 200 and t.json()["outcome"] == "blind"
    assert c.post(f"/api/report/data-flow/{rid}/trace", json={"destination": " ", "network": "off", "platform": "windows"}).status_code == 400
    md = c.get(f"/api/report/data-flow/export/{rid}?format=markdown")
    assert md.status_code == 200 and "# Data Flow Map" in md.text and "Weak point (high)" in md.text
    assert c.get(f"/api/report/data-flow/export/{rid}?format=json").headers["content-type"].startswith("application/json")
    page = c.get("/report/dataflow?id=x").text
    assert '<script src="/static/data_flow.js"></script>' in page and 'id="dfDest"' in page
    assert "openDataFlowTab()" in c.get("/").text and "__dataFlowGenerate" in c.get("/").text
