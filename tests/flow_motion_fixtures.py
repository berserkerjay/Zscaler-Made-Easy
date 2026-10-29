"""Offline fixtures for the traffic motion on the Data Flow Map, SSL flow and
SSL coverage pages: each built by the app's own report code from fake tenant
reads (no network, no clock, no randomness), so the pictures are tested
against the numbers the pages really show."""
from __future__ import annotations

import copy

import data_flow as df
import ssl_coverage as sc
import ssl_flow as sf

# A tenant string that would execute if it ever reached HTML unescaped.
HOSTILE = '<img src=x onerror="window.__xss=1">'


def dataflow_report(scopes=("dlp", "zcc", "zia_extras"), hostile=False):
    """A Data Flow Map report traced through every traffic class on every network."""
    from test_data_flow import ROUTES
    from test_ssl_flow import CATALOGUE, FakeCl
    routes = copy.deepcopy(ROUTES)
    if hostile:
        routes["/zia/webDlpRules"][0]["name"] = HOSTILE
        routes["/zia/sslInspectionRules"][1]["name"] = HOSTILE
    scope = df.path_scope(list(scopes), {"web_dlp": "zscaler", "ssl_inspection": "zscaler", "cloud_app_control": "zscaler"})
    return df.generate_data_flow_report(FakeCl(routes, CATALOGUE), platform="windows", scope=scope)


# SSL rules with the certificate and TLS-version sub-actions the SDK models.
SSL_RULES = [
    {"id": 1, "name": "Zscaler Recommended Exemptions", "order": 1, "state": "ENABLED", "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 2, "name": "Exec bypass", "order": 2, "state": "ENABLED", "groups": [{"id": 9, "name": "Execs"}], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 3, "name": "Privacy DNI", "order": 3, "state": "ENABLED", "url_categories": ["FINANCE", "HEALTH"], "action": {"type": "DO_NOT_DECRYPT"}},
    {"id": 4, "name": "DNI file hosts", "order": 4, "state": "ENABLED", "url_categories": ["FILE_HOST"], "action": {"type": "DO_NOT_DECRYPT",
     "doNotDecryptSubActions": {"bypassOtherPolicies": False, "minTLSVersion": "SERVER_TLS_1_0"}}},
    {"id": 5, "name": "Decrypt AI", "order": 5, "state": "ENABLED", "cloud_applications": ["CHATGPT_AI"], "action": {"type": "DECRYPT",
     "decryptSubActions": {"serverCertificates": "BLOCK", "ocspCheck": True, "blockSslTrafficWithNoSniEnabled": True,
                           "minClientTLSVersion": "CLIENT_TLS_1_2", "minServerTLSVersion": "SERVER_TLS_1_2"}}},
    {"id": 6, "name": "Decrypt file hosts", "order": 6, "state": "ENABLED", "url_categories": ["FILE_HOST"], "action": {"type": "DECRYPT"}},
    {"id": 7, "name": "Block anonymizers", "order": 7, "state": "ENABLED", "url_categories": ["ANONYMIZER"], "action": {"type": "BLOCK"}},
    {"id": 8, "name": "Decrypt webmail (off)", "order": 8, "state": "DISABLED", "url_categories": ["WEB_MAIL"], "action": {"type": "DECRYPT"}},
    {"id": 10, "name": "Decrypt everything", "order": 10, "state": "ENABLED", "url_categories": ["ANY"], "action": {"type": "DECRYPT",
     "decryptSubActions": {"serverCertificates": "PASS_THRU", "ocspCheck": False, "minClientTLSVersion": "CLIENT_TLS_1_0"}}},
    {"id": 9, "name": "Default SSL Inspection Rule", "order": 99, "state": "ENABLED", "default_rule": True, "predefined": True, "action": {"type": "DO_NOT_DECRYPT"}},
]
DLP_RULES = [
    {"id": 10, "name": "Monitor PII everywhere", "order": 1, "state": "ENABLED", "action": "ALLOW", "dlp_engines": [{"id": 1, "name": "PII"}]},
    {"id": 11, "name": "Block SSN to file hosts", "order": 2, "state": "ENABLED", "action": "BLOCK", "url_categories": ["FILE_HOST"], "dlp_engines": [{"id": 2}]},
    {"id": 12, "name": "Block code to AI", "order": 3, "state": "ENABLED", "action": "BLOCK", "cloud_applications": ["CHATGPT_AI", "GEMINI"], "dlp_engines": [{"id": 3}]},
]


def sslflow_report(hostile=False):
    """An SSL flow report: first match, a scoped exemption, gates, a block, a shadowed decrypt."""
    from test_ssl_flow import CATALOGUE, FakeCl
    rules = copy.deepcopy(SSL_RULES)
    if hostile:
        rules[1]["name"] = HOSTILE
    cl = FakeCl({"/zia/sslInspectionRules": rules, "/zia/webDlpRules": DLP_RULES, "/zcc/webPolicies": [], "/zia/urlFilteringRules": [],
                 "/zia/fileTypeRules": [], "/zia/urlCategories": [{"id": "FILE_HOST", "configuredName": "File Host"}]}, apps=CATALOGUE)
    return sf.generate_ssl_flow_report(cl)


PROTOCOLS = {"TRANSACTIONS": [{"name": "HTTPS", "total": 600}, {"name": "SSL", "total": 200}, {"name": "HTTP", "total": 200},
                              {"name": "TUNNEL", "total": 30}],
             "BYTES": [{"name": "HTTPS", "total": 9_000_000_000}, {"name": "Tunnel SSL", "total": 1_000_000_000}, {"name": "HTTP", "total": 500_000_000}]}


def sslcoverage_report(volume=True, hostile=False):
    """An SSL coverage result as the page receives it (causes, plan, classes, Insights split)."""
    from test_ssl_coverage import FakeCl, SSL, tenant_routes
    rules = copy.deepcopy(SSL)
    if hostile:
        rules[3]["name"] = HOSTILE
    cc = df.read_client_connector(FakeCl(tenant_routes()), scope=df.path_scope(["dlp", "zcc"], {"ssl_inspection": "zscaler"}))
    vol = None
    if volume:
        vol = {"available": True, "status": "ok", "window": {"key": "7d", "label": "last 7 days"}, "errors": [], "daily": [],
               "note": sc.PROTOCOL_NOTE, "bypass_note": sc.BYPASS_NOTE,
               "protocols": {u: dict(sc.protocol_split(rows), status="ok") for u, rows in PROTOCOLS.items()},
               "apps": [{"application": "Dropbox", "data_consumed": 4_000_000}, {"application": "Zoom", "data_consumed": 9_000_000}]}
    rep = sc.analyse(rules, cc=cc, volume=vol)
    v = dict(vol) if vol else {"available": False, "reason": "Traffic numbers were not asked for.", "bypass_note": sc.BYPASS_NOTE}
    v.pop("apps", None)
    v["unavailable"] = sc.VOLUME_UNAVAILABLE
    rep.update(volume=v, diagnostics=[], read_errors={}, not_in_scope={}, status="done", logs=["fixture"], tenant_label="Fixture tenant",
               generated_at="2026-01-01T00:00:00+00:00", history=[])
    return rep
