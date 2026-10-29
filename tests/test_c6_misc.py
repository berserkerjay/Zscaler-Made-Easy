"""Cloud QA wave 6, misc area: the MCP server tools, url_tools,
console_index, workspace_notes, beacon, discover_endpoints,
zscaler_clouds, engine_explain, plain_english, corpus_engines,
native_zscaler, guidance and vertical.

Every test is offline and deterministic: fake clients and fake
transports only, never a real tenant, no sleeps, no real clock.
"""
from __future__ import annotations

import json
import os
import stat
from typing import Any, Dict, List

import pytest


# ── The MCP server tools ──────────────────────────────────────────────

SECRET = "mcp-secret-not-real-7f3a"


class _FakeSdk:
    """What dlp_mcp_server builds instead of the SDK adapter: records how it
    was made and closed; signs in as told."""
    made: List[Dict[str, Any]] = []
    closed = 0
    auth_answer: Any = True

    def __init__(self, **kw: Any) -> None:
        type(self).made.append(kw)
        self._config = {"cloud": kw.get("cloud") or "production"}
        self._creds = {"client_secret": kw.get("client_secret"), "password": kw.get("password"), "api_key": kw.get("api_key")}

    def auth(self):
        return type(self).auth_answer

    def close(self) -> None:
        type(self).closed += 1

    def get(self, ep: str, params: Any = None):
        return [], 200


@pytest.fixture
def mcp(monkeypatch):
    import dlp_mcp_server as m
    for k, v in {"ZSCALER_CLIENT_ID": "cid-mcp", "ZSCALER_CLIENT_SECRET": SECRET, "ZSCALER_VANITY_DOMAIN": "acme",
                 "ZSCALER_CLOUD": "production"}.items():
        monkeypatch.setenv(k, v)
    for k in ("ZSCALER_AUTH_METHOD", "ZSCALER_USERNAME", "ZSCALER_PASSWORD", "ZSCALER_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    _FakeSdk.made, _FakeSdk.closed, _FakeSdk.auth_answer = [], 0, True
    monkeypatch.setattr(m, "SdkClient", _FakeSdk)
    return m


def _tool(m, name):
    t = getattr(m, name)
    return getattr(t, "fn", t)


@pytest.mark.parametrize("cloud", ["zscalergovv", "evil.example", "zscaler.net/x"])
def test_mcp_unknown_cloud_argument_is_refused_before_sign_in(mcp, cloud):
    """ASVS V5.1.3 · A04:2021 · CWE-1188 · WSTG-INPV-01: an MCP tool's unknown cloud is refused, never signed in to the commercial cloud."""
    out = _tool(mcp, "run_section")(section="CC Portal", cloud=cloud)

    assert "Unknown Zscaler cloud" in out["error"] and _FakeSdk.made == []


def test_mcp_unknown_cloud_in_the_environment_is_refused(mcp, monkeypatch):
    """ASVS V14.1.3 · CWE-636 · WSTG-CONF-02: a mistyped ZSCALER_CLOUD fails closed instead of falling back to production."""
    monkeypatch.setenv("ZSCALER_CLOUD", "zscalergovus-typo")

    out = _tool(mcp, "run_assessment")()

    assert "Unknown Zscaler cloud" in out["error"] and _FakeSdk.made == []


def test_mcp_known_cloud_spelling_still_signs_in(mcp):
    """ASVS V5.1.3 · CWE-20: an accepted spelling of a cloud (admin host form) still runs the section."""
    out = _tool(mcp, "run_section")(section="CC Portal", cloud="admin.zscalertwo.net")

    assert "error" not in out and _FakeSdk.made and out["checks"]


def test_mcp_bad_auth_method_in_the_environment_is_a_plain_error(mcp, monkeypatch):
    """ASVS V7.4.1 · CWE-755 · WSTG-ERRH-01: an unknown ZSCALER_AUTH_METHOD is a plain error, not an exception out of the tool."""
    monkeypatch.setenv("ZSCALER_AUTH_METHOD", "kerberos")

    out = _tool(mcp, "run_assessment")()

    assert "Unknown sign-in method" in out["error"] and SECRET not in json.dumps(out)


def test_mcp_check_exception_detail_masks_the_client_secret(mcp, monkeypatch):
    """ASVS V7.1.1 · A09:2021 · CWE-209 · CWE-532: a check that raises with the secret in its message reports it masked."""
    def leaky(cl):
        raise RuntimeError(f"400 from token endpoint: client_secret={SECRET}")
    monkeypatch.setattr(mcp, "REG", [("T.1", "Test section", "Leaky check", leaky)])

    out = _tool(mcp, "run_section")(section="Test")

    assert out["checks"][0]["status"] == "ERROR" and SECRET not in json.dumps(out)
    assert "[redacted client_secret]" in out["checks"][0]["detail"]


@pytest.mark.parametrize("section", ["", "   "])
def test_mcp_empty_section_is_refused_not_every_check(mcp, section):
    """ASVS V5.1.3 · CWE-20 · WSTG-INPV-01: an empty section name is refused instead of matching every section."""
    out = _tool(mcp, "run_section")(section=section)

    assert out["error"].startswith("Name a section") and out["available"] and _FakeSdk.made == []


@pytest.mark.parametrize("field", ["org_name", "assessor"])
def test_mcp_oversized_argument_is_refused(mcp, field):
    """ASVS V5.1.4 · CWE-400 · WSTG-INPV-01: an argument over the cap is refused before sign-in."""
    out = _tool(mcp, "run_assessment")(**{field: "x" * (mcp.MAX_ARG_LEN + 1)})

    assert "too long" in out["error"] and _FakeSdk.made == []


def test_mcp_argument_at_the_cap_is_accepted(mcp):
    """ASVS V5.1.4 · CWE-20: an argument exactly at the cap is accepted (boundary)."""
    out = _tool(mcp, "run_section")(section="CC Portal", org_name="o" * mcp.MAX_ARG_LEN)

    assert out["metadata"]["org"] == "o" * mcp.MAX_ARG_LEN


def test_mcp_control_characters_in_an_argument_are_refused(mcp):
    """ASVS V5.1.3 · CWE-117 · WSTG-INPV-01: a newline in an argument (log forging) is refused."""
    out = _tool(mcp, "run_section")(section="CC Portal\nFAKE LOG LINE")

    assert "control characters" in out["error"] and _FakeSdk.made == []


def test_mcp_client_is_closed_when_sign_in_fails(mcp):
    """ASVS V7.4.1 · CWE-404: a failed sign-in still closes the client."""
    _FakeSdk.auth_answer = (False, "Invalid client")

    out = _tool(mcp, "run_section")(section="CC Portal")

    assert out == {"error": "Authentication failed: (False, 'Invalid client')"} and _FakeSdk.closed == 1


def test_mcp_tools_take_no_write_or_secret_argument():
    """ASVS V1.4.1 · A01:2021 · CWE-841 · CWE-522: the MCP server exposes only read tools and none takes a secret or a write switch."""
    import asyncio
    import dlp_mcp_server as m

    tools = {t.name: t for t in asyncio.run(m.mcp.list_tools())}

    schemas = [getattr(t, "input_schema", None) or getattr(t, "inputSchema", None) or {} for t in tools.values()]
    params = {p for sc in schemas for p in (sc.get("properties") or {})}
    assert set(tools) == {"get_health", "list_checks", "run_assessment", "run_section"}
    assert not params & {"client_secret", "password", "api_key", "token", "confirm", "write", "apply", "assessor_confirm"}
