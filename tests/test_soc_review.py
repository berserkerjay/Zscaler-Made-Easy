"""The SOC review (soc_review.py, /report/soc-review, /api/soc-review/*, the
MCP tools rbac_review and telemetry_review): admin access (RBAC) and logging
(telemetry) on ZIA, ZPA, Client Connector, ZDX and ZIdentity.

Offline: the made-up sample tenant and in-memory fakes; no sign-in, no
network. Each test checks one behaviour: a finding, unknown never reported
as a pass, the Scope rule (refused before sign-in, unticked services never
read), no secret or person in an answer, and the MCP read-only marking."""
from __future__ import annotations

import asyncio
import json
import threading

import pytest

import offline_tenant
import soc_review

ALL = ["rbac", "zia_extras", "zpa", "zcc", "zdx", "zidentity"]


class FakeClient:
    """The assessment client's get(), answering from a table; records every path asked."""

    def __init__(self, answers):
        self.answers, self.paths = answers, []

    def get(self, ep, p=None):
        self.paths.append(ep)
        return self.answers.get(ep, ([], 200))

    def put(self, *a, **k):   # pragma: no cover - the Guard never exposes it
        raise AssertionError("a write was attempted")


def _sample():
    st = offline_tenant.sample_store(reset=True)
    return offline_tenant.client_for(offline_tenant.creds_for(st), "raw")


def _by(rep, fid, product=None):
    return [f for f in rep["findings"] if f["id"] == fid and (product is None or product in f["product"] or product in f["title"])]


@pytest.fixture(scope="module")
def rbac():
    return soc_review.rbac_review(_sample(), ALL)


@pytest.fixture(scope="module")
def tel():
    return soc_review.telemetry_review(_sample(), ALL)


# ── RBAC findings on the sample tenant ──────────────────────────────

def test_rbac_lists_admins_and_rights_for_every_product(rbac):
    """ASVS V1.4.1 · CWE-269 · WSTG-ATHZ-03: each product's admins are listed with full, scoped or read-only rights; ZDX comes from ZIdentity."""
    # Arrange
    p = {x["key"]: x for x in rbac["products"]}
    # Assert
    assert [x["key"] for x in rbac["products"]] == ["zia", "zpa", "zcc", "zdx", "zidentity"]
    assert p["zia"]["counts"]["full"] == 1 and p["zia"]["counts"]["read_only"] == 1
    assert p["zpa"]["counts"] == dict(p["zpa"]["counts"], enabled=4, full=2, scoped=1, read_only=1, disabled=1)
    assert p["zdx"]["state"] == "derived" and p["zdx"]["counts"]["full"] == 1
    assert {c["name"] for c in p["zidentity"]["api_clients"]} == {"Larkspur reporting"}


def test_rbac_finds_no_second_factor_stale_admins_and_broad_automation(rbac):
    """ASVS V2.8.1 · V1.4.1 · CWE-308 · CWE-269: a local ZPA admin with no second factor is Fix; disabled admins still holding rights are Fix; a full-access API key is Review."""
    # Assert
    assert _by(rbac, "SOC.R2")[0]["status"] == "fail" and "1 ZPA" in _by(rbac, "SOC.R2")[0]["detail"]
    assert [f["status"] for f in _by(rbac, "SOC.R3") if f["title"].startswith("Disabled")] == ["fail"]
    r4 = _by(rbac, "SOC.R4")[0]
    assert r4["status"] == "review" and "terraform-ci" in r4["detail"]


def test_rbac_reuses_the_rbac_and_zidentity_checks(rbac):
    """ASVS V1.4.1 · CWE-1059: the RBAC.* and ZID.5 to ZID.7 checks run as they are, not copied."""
    # Assert
    ids = {c["id"] for c in rbac["checks"]}
    assert {"RBAC.1", "RBAC.14", "RBAC.18", "RBAC.6", "RBAC.10", "ZID.6", "ZID.7"} <= ids
    assert next(c for c in rbac["checks"] if c["id"] == "RBAC.14")["status"] == "fail"


def test_too_many_full_access_admins_is_a_review_and_three_is_not():
    """ASVS V1.4.1 · CWE-250 · WSTG-ATHZ-03: five enabled full-access ZPA admins is Review; three is As recommended (boundary)."""
    # Arrange
    def zpa(n):
        admins = [{"id": str(i), "username": f"a{i}", "isEnabled": True, "localLoginDisabled": True, "role": {"id": "9"}} for i in range(n)]
        return FakeClient({"/zpa/administrators": ({"list": admins, "totalPages": 1}, 200),
                           "/zpa/roles": ({"list": [{"id": "9", "name": "Super Admin"}], "totalPages": 1}, 200)})
    # Act
    five = soc_review.rbac_review(zpa(5), ["rbac", "zpa"])
    three = soc_review.rbac_review(zpa(3), ["rbac", "zpa"])
    # Assert
    assert _by(five, "SOC.R1", "ZPA")[0]["status"] == "review"
    assert _by(three, "SOC.R1", "ZPA")[0]["status"] == "pass"


# ── Unknown is never a pass ──────────────────────────────────────────

def test_what_the_api_does_not_report_is_unknown_never_pass(rbac):
    """ASVS V1.4.1 · CWE-1188 · CWE-754: second factor on ZIA, Client Connector and ZIdentity and missing last sign-in times are Unknown findings."""
    # Arrange
    unknown = [f for f in rbac["findings"] if f["status"] == "unknown"]
    # Assert
    assert any(f["title"] == "Second factor not reported" and "ZIA" in f["product"] for f in unknown)
    assert any(f["title"] == "Last sign-in not reported" for f in unknown)
    assert not any(f["status"] == "pass" and "not reported" in f["title"] for f in rbac["findings"])


@pytest.mark.parametrize("status,detail,want", [("PASS", "", "pass"), ("FAIL", "", "fail"), ("REVIEW", "", "review"),
                                                ("INFO", "ZPA administrators: not permitted (HTTP 403).", "unknown"),
                                                ("INFO", "No microtenant is in use; Not licensed or not in use. N/A.", "na"),
                                                ("ERROR", "boom", "unknown"), ("", "", "unknown")])
def test_a_check_that_could_not_judge_is_unknown_or_na(status, detail, want):
    """ASVS V7.4.1 · CWE-754 · CWE-1188: an INFO or ERROR check result maps to unknown (or N/A when not licensed), never to pass."""
    # Act / Assert
    assert soc_review.check_status(status, detail) == want


def test_a_refused_product_read_is_not_permitted_and_gives_no_pass():
    """ASVS V4.1.3 · CWE-754: a 403 on the ZPA admin list marks ZPA not permitted; no finding for ZPA passes."""
    # Arrange
    cl = FakeClient({"/zpa/administrators": ({}, 403)})
    # Act
    rep = soc_review.rbac_review(cl, ["rbac", "zpa"])
    # Assert
    zpa = next(p for p in rep["products"] if p["key"] == "zpa")
    assert zpa["state"] == "not_permitted" and "403" in zpa["why"]
    assert not [f for f in rep["findings"] if "ZPA" in f["product"] and f["status"] == "pass"]


def test_zdx_logging_is_unknown_because_the_api_has_no_read(tel):
    """ASVS V7.1.1 · CWE-778 · CWE-1188: ZDX streaming is Unknown with the reason; nothing of ZDX is read."""
    # Assert
    zdx = next(p for p in tel["products"] if p["key"] == "zdx")
    assert zdx["state"] == "unknown" and "no log-streaming" in zdx["why"]
    assert [f["status"] for f in tel["findings"] if f["product"] == "ZDX"] == ["unknown"]


# ── Telemetry findings ───────────────────────────────────────────────

def test_telemetry_finds_disabled_feeds_and_missing_log_types(tel):
    """ASVS V7.1.1 · V7.3.1 · CWE-778: the disabled admin audit feed and the unhealthy NSS server are Review; missing ZIA and ZPA log types are named."""
    # Assert
    assert "Admin audit to SIEM" in _by(tel, "SOC.T2", "ZIA")[0]["detail"] and "nss-fw-portland-1" in _by(tel, "SOC.T2", "ZIA")[0]["detail"]
    zia_missing = next(f for f in _by(tel, "SOC.T3", "ZIA") if f["status"] == "review")
    assert "Admin audit" in zia_missing["detail"] and "Web" not in zia_missing["detail"]
    zpa_missing = _by(tel, "SOC.T3", "ZPA")[0]
    assert zpa_missing["status"] == "review" and "User Status" in zpa_missing["detail"] and "User Activity" not in zpa_missing["detail"]
    assert "Connector status to SIEM" in _by(tel, "SOC.T2", "ZPA")[0]["detail"]
    assert "Windows - Contractors" in _by(tel, "SOC.T5", "Client Connector")[0]["detail"]


def test_telemetry_names_destinations_and_their_queries(tel):
    """ASVS V7.1.1 · CWE-778: the Cloud NSS feed's destination is its host with the Splunk queries; LSS receivers keep host and port."""
    # Assert
    d = {(x["destination"], x["kind"]): x for x in tel["destinations"]}
    nss = d[("siem.larkspur-freight.example", "Cloud NSS feed")]
    assert nss["queries"] == "Splunk SPL" and nss["enabled_streams"] == 1
    assert ("siem.larkspur-freight.example:6514", "Log Streaming Service") in d
    stream = next(s for p in tel["products"] if p["key"] == "zpa" for s in p["streams"] if s["log_code"] == "zpn_trans_log")
    assert stream["traffic_logs"] == "ZPA User Activity" and stream["tls"] is True


def test_a_product_with_nothing_streamed_is_a_review():
    """ASVS V7.1.1 · CWE-778: ZPA with no LSS configuration is Review 'nothing streamed', and is named."""
    # Arrange
    cl = FakeClient({"/zpa/lssConfig": ({"list": [], "totalPages": 1}, 200)})
    # Act
    rep = soc_review.telemetry_review(cl, ["zpa"])
    # Assert
    assert _by(rep, "SOC.T1", "ZPA")[0]["status"] == "review" and rep["nothing_streamed"] == ["ZPA"]


def test_a_feed_url_with_a_token_and_headers_never_reach_the_answer():
    """ASVS V8.3.4 · V7.1.1 · CWE-532 · CWE-200: a Cloud NSS feed's token, URL path and query and its headers are never copied out."""
    # Arrange
    canary = "nss-canary-token-71bd"
    feed = {"id": 1, "name": "Web", "feedStatus": "ENABLED", "nssLogType": "WEBLOG", "siemType": "SPLUNK",
            "connectionURL": f"https://user:{canary}@collector.example.net:8088/raw?token={canary}",
            "connectionHeaders": [f"Authorization:Splunk {canary}"], "authenticationToken": canary, "clientSecret": canary}
    cl = FakeClient({"/zia/nssFeeds": ([feed], 200), "/zia/nssServers": ([], 200), "/zia/nssCollectors": ([], 200)})
    # Act
    rep = soc_review.telemetry_review(cl, ["zia_extras"])
    # Assert
    assert canary not in json.dumps(rep)
    assert rep["destinations"][0]["destination"] == "collector.example.net"


# ── The Scope rule ───────────────────────────────────────────────────

def test_rbac_with_only_rbac_ticked_reads_no_other_product():
    """ASVS V4.1.3 · CWE-272 · WSTG-ATHZ-02: RBAC alone reads ZIA admins only; ZPA, Client Connector and ZIdentity are not ticked, not read."""
    # Arrange
    cl = FakeClient({})
    # Act
    rep = soc_review.rbac_review(cl, ["rbac"])
    # Assert
    assert cl.paths and all(p.startswith("/zia/") for p in cl.paths), cl.paths
    assert {p["key"]: p["state"] for p in rep["products"]}["zpa"] == "not_in_scope"


def test_telemetry_with_only_zpa_ticked_reads_only_zpa():
    """ASVS V4.1.3 · CWE-272: the telemetry review with ZPA ticked reads nothing of ZIA or Client Connector."""
    # Arrange
    cl = FakeClient({})
    # Act
    soc_review.telemetry_review(cl, ["zpa"])
    # Assert
    assert cl.paths and all(p.startswith("/zpa/") for p in cl.paths), cl.paths


def test_the_guard_has_no_write_method_and_honours_stop():
    """ASVS V4.1.3 · V1.4.1 · CWE-285: the review client exposes GET only; Stop ends the review before the next read."""
    # Arrange
    stop = threading.Event()
    stop.set()
    g = soc_review.Guard(FakeClient({}), {"zia"}, stop)
    # Act / Assert
    for name in ("post", "put", "patch", "delete"):
        assert not hasattr(g, name)
    with pytest.raises(soc_review.Stopped):
        soc_review.rbac_review(FakeClient({}), ["rbac"], cancel=stop)


@pytest.fixture
def server(monkeypatch):
    import dlp_api_server as srv

    def boom(*a, **k):
        pytest.fail("a client was built before the Scope rule")
    monkeypatch.setattr(srv, "_signed_in_raw", boom)
    from fastapi.testclient import TestClient
    return TestClient(srv.app)


@pytest.mark.parametrize("path", ["/api/soc-review/rbac/start", "/api/soc-review/telemetry/start"])
def test_a_review_with_nothing_in_scope_is_refused_before_sign_in(server, path):
    """ASVS V4.1.3 · CWE-285 · WSTG-ATHZ-02: nothing the review reads is ticked: 400 naming the scope, no client built."""
    # Act
    r = server.post(path, json={"scopes": ["dlp"], "channels": {}, "from_page": True})
    # Assert
    assert r.status_code == 400 and "not in scope" in r.json()["detail"]


def test_an_unknown_report_id_is_404(server):
    """ASVS V4.2.1 · CWE-639: a report id of another kind or none is a 404."""
    # Act / Assert
    assert server.get("/api/soc-review/report/ztw-abc").status_code == 404
    assert server.get("/api/soc-review/report/socrbac-nope").status_code == 404


# ── The MCP tools ────────────────────────────────────────────────────

@pytest.fixture
def mcp_env(monkeypatch):
    for k in ("ZSCALER_MCP_PROFILE", "ZSCALER_MCP_SCOPES", "ZSCALER_MCP_CHANNELS", "ZSCALER_CLIENT_SECRET", "ZSCALER_CLIENT_ID",
              "ZSCALER_VANITY_DOMAIN", "ZSCALER_AUTH_METHOD"):
        monkeypatch.delenv(k, raising=False)
    offline_tenant.sample_store(reset=True)
    import dlp_mcp_server
    return dlp_mcp_server


def _call(m, tool, **args):
    return json.loads(asyncio.run(m.mcp.call_tool(tool, args)).content[0].text)


def test_the_mcp_tools_are_marked_read_only_and_take_no_secret(mcp_env):
    """ASVS V1.4.1 · CWE-269 · CWE-522: rbac_review and telemetry_review are registered read-only, not destructive, with no secret or write argument."""
    # Act
    tools = {t.name: t for t in asyncio.run(mcp_env.mcp.list_tools())}
    # Assert
    for name in ("rbac_review", "telemetry_review"):
        t = tools[name]
        assert t.annotations.read_only_hint is True and t.annotations.destructive_hint is False
        params = set((getattr(t, "inputSchema", None) or getattr(t, "input_schema", None) or {}).get("properties") or {})
        assert params == {"source", "snapshot_id"}


def test_the_mcp_rbac_review_numbers_admins_and_names_nobody(mcp_env):
    """ASVS V8.3.4 · CWE-359: on the sample, admins are "<product> admin n"; no login name or e-mail is in the answer; the tenant is unchanged."""
    # Act
    out = _call(mcp_env, "rbac_review", source="sample")
    # Assert
    text = json.dumps(out)
    assert out["read_only"] is True and out["data"]["products"][0]["admins"][0]["name"] == "ZIA admin 1"
    assert "@" not in text and "avery" not in text.lower()
    assert offline_tenant.sample_store().writes == 0


@pytest.mark.parametrize("tool", ["rbac_review", "telemetry_review"])
def test_the_mcp_tools_refuse_what_the_server_scope_does_not_tick(mcp_env, monkeypatch, tool):
    """ASVS V4.1.3 · CWE-285: with only DLP in the server's scope, each tool answers not_in_scope and reads nothing."""
    # Arrange
    monkeypatch.setenv("ZSCALER_MCP_SCOPES", "dlp")
    # Act
    out = _call(mcp_env, tool, source="sample")
    # Assert
    assert out["code"] == "not_in_scope" and "data" not in out
