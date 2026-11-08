"""SCIM-provisioned users (scim_view.list_users, /api/scim/users), DigiCert addresses resolved on demand
(zscaler_ip_ranges.resolve_digicert, /api/zscaler-ranges/digicert-resolve).

Fakes only: an in-memory credential store, an injected SCIM transport and an injected getaddrinfo. No network, no tenant."""
from __future__ import annotations

import json
import logging
import os
import socket
import sys
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import audit  # noqa: E402
import dlp_api_server as srv  # noqa: E402
import scim_view as sv  # noqa: E402
import team_routes  # noqa: E402
import zpa_reader  # noqa: E402
import zscaler_ip_ranges as zr  # noqa: E402

SECRET = "scim-secret-CANARY-0123456789"
GOOD = "https://scim1.private.zscaler.com/216196257331281920/scim"
CREDS = {"vanity_domain": "acme", "client_id": "abc123456789", "client_secret": "secret-secret-secret", "customer_id": "216196257331281920"}


class FakeKeyring:
    def __init__(self):
        self.d = {}

    def get_keyring(self):
        return self

    def set_password(self, svc, user, pw):
        self.d[(svc, user)] = pw

    def get_password(self, svc, user):
        return self.d.get((svc, user))

    def delete_password(self, svc, user):
        if (svc, user) not in self.d:
            raise KeyError(user)
        del self.d[(svc, user)]


@pytest.fixture
def kr(monkeypatch, tmp_path):
    k = FakeKeyring()
    monkeypatch.setattr(sv, "_keyring", lambda: k)
    monkeypatch.setenv("DLP_CHECK_AUDIT", str(tmp_path / "audit.log"))
    monkeypatch.setenv("DLP_CHECK_ZSCALER_RANGES_DIR", str(tmp_path / "ranges"))
    monkeypatch.setattr(zpa_reader, "PACE_SECONDS", 0.0)
    return k


class Scim:
    """A SCIM 2.0 service: `total` users, answers startIndex/count; records every request."""

    def __init__(self, total=3, status=200):
        self.total, self.status, self.sent = total, status, []

    def __call__(self, url, headers):
        self.sent.append((url, dict(headers)))
        q = dict(p.split("=", 1) for p in url.split("?", 1)[1].split("&"))
        start, count = int(q["startIndex"]), int(q["count"])
        rows = [{"userName": f"u{i}@example.com", "active": i % 2 == 0, "displayName": f"User {i}",
                 "groups": [{"value": "g1", "display": "Eng", "members": ["leak@example.com"]}] * (i % 3), "emails": ["private@example.com"]}
                for i in range(start, min(start + count, self.total + 1))]
        return self.status, json.dumps({"totalResults": self.total, "startIndex": start, "Resources": rows}).encode()


# ── 1. SCIM users ─────────────────────────────────────────────────────
def test_user_list_is_off_without_a_stored_secret_and_sends_nothing(kr):
    """ASVS V2.10.4 · CWE-306 · WSTG-ATHN-04: without the IdP's SCIM secret the opt-in list is off and no request is made."""
    net = Scim()
    out = sv.list_users(GOOD, "11", net)
    assert out["users"] == [] and out["token_stored"] is False and "off" in out["error"] and net.sent == []


@pytest.mark.parametrize("url", [
    "https://evil.example.com/scim", "https://scim.evil.example/", "https://scim1.private.zscaler.com.evil.example/scim",
    "https://scim1.notzscaler.com/", "https://private.zscaler.com/scim", "https://api.zscaler.com/scim",
    "https://127.0.0.1/scim", "https://169.254.169.254/latest", "https://localhost/scim",
    "https://scim1.private.zscaler.com\\@evil.example/", "https://scim1.private.zscaler.com@evil.example/",
])
def test_non_zscaler_scim_host_is_refused_before_any_request(kr, url):
    """ASVS V12.6.1 · CWE-918 · WSTG-INPV-19: an endpoint that is not a Zscaler-owned SCIM host is refused and the secret is never sent."""
    sv.set_token("11", SECRET)
    net = Scim()
    out = sv.list_users(url, "11", net)
    assert out["users"] == [] and out["error"] and net.sent == []
    assert SECRET not in json.dumps(out)


@pytest.mark.parametrize("url", ["http://scim1.private.zscaler.com/scim", "ftp://scim1.private.zscaler.com/", "//scim1.private.zscaler.com/",
                                 "https://user:pw@scim1.private.zscaler.com/scim", "https://scim1.private.zscaler.com:8443/scim",
                                 "https://scim1.private.zscaler.com/scim?x=1", "https://scim1.private.zscaler.com/scim#f", ""])
def test_scim_endpoint_is_https_only_without_credentials_port_or_query(kr, url):
    """ASVS V9.1.1 · CWE-319 · WSTG-CRYP-03: plain http, credentials in the URL, another port or a query string are refused; nothing is sent."""
    sv.set_token("11", SECRET)
    net = Scim()
    assert sv.list_users(url, "11", net)["error"] and net.sent == []


def test_a_zscaler_scim_host_is_read_with_the_bearer_and_only_get_users(kr):
    """ASVS V4.1.3 · CWE-200 · WSTG-ATHZ-02: user name, active, display name and group count only; the bearer goes to the checked host only; no member list, e-mail or group detail is returned."""
    sv.set_token("11", SECRET)
    net = Scim(total=3)
    out = sv.list_users(GOOD, "11", net)
    assert out["error"] is None and out["complete"] is True and out["total"] == 3 and out["shown"] == 3
    assert set(out["users"][0]) == {"userName", "active", "displayName", "group_count"}
    assert [u["group_count"] for u in out["users"]] == [1, 2, 0]
    assert "leak@example.com" not in json.dumps(out) and "private@example.com" not in json.dumps(out)
    assert all(u.startswith("https://scim1.private.zscaler.com/216196257331281920/scim/Users?startIndex=") for u, _h in net.sent)
    assert net.sent[0][1]["Authorization"] == f"Bearer {SECRET}"
    assert SECRET not in json.dumps(out)


def test_paging_is_capped(kr):
    """ASVS V13.2.6 · CWE-770 · WSTG-BUSL-05: a service with thousands of users is read for at most MAX_PAGES pages and said to be incomplete."""
    sv.set_token("11", SECRET)
    net = Scim(total=100000)
    out = sv.list_users(GOOD, "11", net)
    assert len(net.sent) == sv.MAX_PAGES and len(out["users"]) == sv.MAX_USERS == 500
    assert out["complete"] is False and out["total"] == 100000
    assert "startIndex=101&count=100" in net.sent[1][0]


def test_a_refused_secret_or_a_failed_connection_is_said_without_the_secret(kr):
    """ASVS V7.1.1 · CWE-532 · WSTG-ERRH-01: 401, a bad body and a transport error give plain errors that never carry the secret or the request."""
    sv.set_token("11", SECRET)
    assert "refused" in sv.list_users(GOOD, "11", Scim(status=401))["error"]
    assert sv.list_users(GOOD, "11", lambda u, h: (200, b"<html>"))["error"]

    def boom(url, headers):
        raise OSError(f"cannot connect with {headers['Authorization']}")
    err = sv.list_users(GOOD, "11", boom)["error"]
    assert "OSError" in err and SECRET not in err


def test_the_secret_lives_only_in_the_credential_store(kr, tmp_path, monkeypatch):
    """ASVS V2.10.3 · CWE-522 · WSTG-ATHN-07: the secret is kept in the OS credential store; with none available it is refused, not written to a file."""
    sv.set_token("11", SECRET)
    assert kr.d == {(sv.KEYRING_SERVICE, "11"): SECRET} and sv.has_token("11")
    assert sv.clear_token("11") is True and not sv.has_token("11")
    with pytest.raises(sv.ScimUsersError):
        sv.set_token("../x", SECRET)
    with pytest.raises(sv.ScimUsersError):
        sv.set_token("11", "short")
    monkeypatch.setattr(sv, "_keyring", lambda: None)
    with pytest.raises(sv.ScimUsersError, match="credential store"):
        sv.set_token("11", SECRET)
    for root, _d, files in os.walk(tmp_path):
        for f in files:
            assert SECRET not in open(os.path.join(root, f), errors="ignore").read()


def _sdk(scim_enabled=True, endpoint=GOOD):
    rows = [{"id": "11", "name": "Okta", "enabled": True, "scimEnabled": scim_enabled, "scimServiceProviderEndpoint": endpoint,
             "scimSharedSecretExists": True},
            {"id": "12", "name": "Entra", "enabled": True, "scimEnabled": False}]
    idp = SimpleNamespace(list_idps=lambda query_params=None: (rows if (query_params or {}).get("page", "1") == "1" else [], None, None))
    return SimpleNamespace(zpa=idp and SimpleNamespace(idp=idp))


def test_endpoint_comes_from_the_tenant_idp_and_scim_off_reads_nothing(kr):
    """ASVS V4.1.3 · CWE-441 · WSTG-INPV-19: the address is the IdP's own scimServiceProviderEndpoint; an IdP with SCIM off is not contacted."""
    sv.set_token("11", SECRET)
    net = Scim(total=2)
    out = sv.users_for_idp(_sdk(), "11", net)
    assert out["shown"] == 2 and out["endpoint_host"] == "scim1.private.zscaler.com" and out["idp"]["name"] == "Okta"
    off = Scim()
    assert sv.users_for_idp(_sdk(scim_enabled=False), "11", off)["error"] and off.sent == []
    bad = Scim()
    assert sv.users_for_idp(_sdk(endpoint="https://evil.example/scim"), "11", bad)["error"] and bad.sent == []
    assert "not one of the tenant's" in sv.users_for_idp(_sdk(), "999", Scim())["error"]


def test_routes_gate_scope_keep_the_secret_out_of_answers_audit_and_logs(kr, monkeypatch, caplog):
    """ASVS V7.1.1 · V8.3.4 · CWE-532 · WSTG-ATHZ-02: ZPA must be ticked; the token never appears in a response, the audit log or the logs; the list route only reads."""
    c = TestClient(srv.app)
    built = []
    net = Scim(total=2)
    monkeypatch.setattr(srv, "_build_sdk_client", lambda cr: built.append(1) or _sdk())
    monkeypatch.setattr(sv, "_http_get", net)
    caplog.set_level(logging.DEBUG)
    put = c.put("/api/scim/users/token", json={"idp_id": "11", "token": SECRET})
    assert put.status_code == 200 and put.json() == {"stored": True, "idp_id": "11"} and kr.d[(sv.KEYRING_SERVICE, "11")] == SECRET
    no = c.post("/api/scim/users", json=dict(CREDS, from_page=True, scopes=["dlp"], idp_id="11"))
    assert no.status_code == 400 and built == [] and net.sent == []
    ok = c.post("/api/scim/users", json=dict(CREDS, from_page=True, scopes=["zpa"], idp_id="11"))
    assert ok.status_code == 200, ok.text
    assert ok.json()["shown"] == 2 and len(net.sent) == 1 and "/Users?" in net.sent[0][0]
    bad = c.put("/api/scim/users/token", json={"idp_id": "11", "token": "x" * 5000})
    assert bad.status_code == 422 and SECRET not in bad.text and "x" * 50 not in bad.text
    short = c.put("/api/scim/users/token", json={"idp_id": "11", "token": "tiny"})
    assert short.status_code == 400 and "tiny" not in short.text
    cl = c.delete("/api/scim/users/token?idp_id=11")
    assert cl.status_code == 200 and (sv.KEYRING_SERVICE, "11") not in kr.d
    after = c.post("/api/scim/users", json=dict(CREDS, from_page=True, scopes=["zpa"], idp_id="11")).json()
    assert after["users"] == [] and "off" in after["error"]
    blob = json.dumps([ok.json(), put.json(), cl.json(), after]) + json.dumps(audit.tail(50), default=str) + caplog.text
    assert SECRET not in blob
    events = [e.get("event") for e in audit.tail(50)]
    assert "scim_users_read" in events and "scim_users_token_set" in events


def test_team_rules_make_the_routes_administrator_only(kr):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: listing SCIM users and handling the secret need the administrator role."""
    for k in ("POST /api/scim/users", "PUT /api/scim/users/token", "DELETE /api/scim/users/token"):
        assert team_routes.ROUTE_RULES[k] == team_routes.ADMIN


def test_the_module_only_reads_with_get():
    """ASVS V4.1.3 · CWE-650 · WSTG-CONF-06: the SCIM client has one request function and it is a GET with TLS verified, a timeout and no redirect."""
    src = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scim_view.py"), encoding="utf-8").read()
    assert src.count("requests.") == 1 and "requests.get(" in src and "allow_redirects=False" in src and "timeout=" in src
    assert "verify=False" not in src and ".post(" not in src and ".put(" not in src and ".delete(" not in src.replace("kr.delete_password", "")


# ── 2. DigiCert addresses resolved now ────────────────────────────────
def _gai(table):
    def gai(host, port, type=0, **kw):
        v = table[host]
        if isinstance(v, Exception):
            raise v
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "", (a, port)) for a in v]
    return gai


TABLE = {"ocsp.digicert.com": ["93.184.220.29", "93.184.220.30", "2606:4700:10::6816:1"],
         "crl3.digicert.com": ["93.184.220.29", "10.1.2.3"], "crl4.digicert.com": socket.gaierror("no such host"),
         "cacerts.digicert.com": ["152.195.38.76"]}


def test_resolve_digicert_by_dns_labels_and_keeps_ipv4_and_ipv6(kr):
    """ASVS V1.4.4 · CWE-1188 · WSTG-CONF-01: each listed host is resolved by DNS (injected), private answers and failures are said, the result carries the time and the CDN label."""
    now = zr._dt.datetime(2026, 11, 7, 9, 0, tzinfo=zr._dt.timezone.utc)
    r = zr.resolve_digicert(_gai(TABLE), now=now)
    assert r["resolved_at"].startswith("2026-11-07T09:00")
    assert r["label"] == "Resolved by DNS now; DigiCert uses a CDN, so re-resolve before each change."
    assert r["ranges"] == sorted({"93.184.220.29/32", "93.184.220.30/32", "152.195.38.76/32", "2606:4700:10::6816:1/128"})
    assert any("crl4.digicert.com did not resolve" in w for w in r["warnings"]) and any("10.1.2.3" in w for w in r["warnings"])
    assert r["hosts"]["crl4.digicert.com"] == [] and zr.digicert_resolved()["ranges"] == r["ranges"]


def test_resolved_addresses_are_consolidated_and_included_in_the_export(kr):
    """ASVS V1.4.4 · CWE-682 · WSTG-CONF-01: resolved addresses join the allowlist with overlap consolidation and the /32 form; the label and time are in every export format that carries notes."""
    zr.resolve_digicert(_gai(TABLE), operator_ranges="93.184.220.0/24\n198.51.100.7")
    off = zr.build("zscaler", ["cenr"], digicert=False)
    assert off["all"]["ipv4"] == [] and off["digicert"] is None
    on = zr.build("zscaler", ["cenr"], digicert=True)
    assert on["all"]["ipv4"] == ["93.184.220.0/24", "152.195.38.76/32", "198.51.100.7/32"]      # the two /32s fold into the /24
    assert on["all"]["ipv6"] == ["2606:4700:10::6816:1/128"]
    assert on["digicert"]["resolved"]["label"].startswith("Resolved by DNS now; DigiCert uses a CDN")
    assert any("re-resolve before each change" in w for w in on["warnings"])
    host = zr.build("zscaler", ["cenr"], digicert=True, single_hosts=True)
    assert "152.195.38.76" in host["all"]["ipv4"] and "2606:4700:10::6816:1" in host["all"]["ipv6"]
    _n, _m, txt = zr.render(on, "txt")
    assert "152.195.38.76/32" in txt
    j = json.loads(zr.render(on, "json")[2])
    assert "198.51.100.7/32" in j["ipv4"] and j["digicert"]["resolved"]["at"]
    assert "ocsp.digicert.com" in {h["host"] for h in on["hosts"]}


@pytest.mark.parametrize("bad", ["not-a-range", "999.1.1.1/24", "10.0.0.0/33", "0.0.0.0/0", "1.2.3.4/5 extra!", "2001:db8::/7"])
def test_invalid_operator_ranges_are_refused_and_nothing_is_kept(kr, bad):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an operator range that is not a valid, bounded CIDR is refused with its line, and nothing is saved."""
    with pytest.raises(zr.FeedError):
        zr.resolve_digicert(_gai(TABLE), operator_ranges="198.51.100.0/24\n" + bad)
    assert zr.digicert_resolved() is None


def test_digicert_routes_resolve_report_and_refuse_bad_ranges(kr, monkeypatch):
    """ASVS V4.1.1 · CWE-285 · WSTG-ATHZ-02: the resolve route is administrator-only in team mode, answers the labelled result, refuses an invalid range with 400 and audits counts only."""
    c = TestClient(srv.app)
    monkeypatch.setattr(socket, "getaddrinfo", _gai(TABLE))
    assert team_routes.ROUTE_RULES["POST /api/zscaler-ranges/digicert-resolve"] == team_routes.ADMIN
    assert c.get("/api/zscaler-ranges/digicert").json() == {"resolved": None}
    bad = c.post("/api/zscaler-ranges/digicert-resolve", json={"operator_ranges": "nope"})
    assert bad.status_code == 400
    ok = c.post("/api/zscaler-ranges/digicert-resolve", json={"operator_ranges": "198.51.100.0/24"})
    assert ok.status_code == 200 and ok.json()["operator_ranges"] == ["198.51.100.0/24"] and "re-resolve" in ok.json()["label"]
    assert c.get("/api/zscaler-ranges/digicert").json()["resolved"]["ranges"]
    built = c.post("/api/zscaler-ranges/build", json={"cloud": "zscaler.net", "feeds": ["cenr"], "digicert": True})
    assert built.status_code == 200 and "198.51.100.0/24" in built.json()["all"]["ipv4"]
    assert any(e.get("event") == "zscaler_ranges_digicert_resolve" for e in audit.tail(20))


def test_nothing_resolved_keeps_nothing_and_says_so(kr):
    """ASVS V7.4.1 · CWE-754 · WSTG-ERRH-01: when DNS answers nothing and no range is supplied, nothing is kept, the answer says why, and an older kept resolution is not overwritten."""
    zr.resolve_digicert(_gai(TABLE))
    kept = zr.digicert_resolved()["ranges"]
    r = zr.resolve_digicert(_gai({h: [] for h in TABLE}))
    assert r["ranges"] == [] and any("nothing is kept" in w for w in r["warnings"])
    assert zr.digicert_resolved()["ranges"] == kept
