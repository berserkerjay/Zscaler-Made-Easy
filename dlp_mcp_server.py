#!/usr/bin/env python3
"""
DLP Assessment MCP Tool Server
================================
Model Context Protocol (MCP) server that exposes the DLP assessment
engine as tools callable by AI agents (Claude, Cursor, Copilot, etc.).

Credentials come from environment variables only — no tool takes a client
ID, secret, password or API key, so a secret never passes through the AI
conversation or its tool-call logs.

Install:
    pip install "mcp[cli]" zscaler-sdk-python     # mcp 2.x (MCPServer) or 1.x (FastMCP)

Run:
    python dlp_mcp_server.py                         # streamable-http on :8080
    python dlp_mcp_server.py --transport stdio        # stdio for Claude Desktop

Register with Claude Code:
    claude mcp add --transport http dlp-assess http://localhost:8080/mcp

Environment variables:
    ZSCALER_CLIENT_ID       — API client ID
    ZSCALER_CLIENT_SECRET   — Client secret
    ZSCALER_VANITY_DOMAIN   — Org vanity domain
    ZSCALER_CLOUD           — Cloud from the tenant admin URL (default: production; zscalergov / zscalergovus for FedRAMP)

Tools exposed:
    run_assessment    — Full 150+ check assessment with scored report
    run_section       — Run checks for a single section
    list_checks       — List all available check IDs and labels
    get_health        — Check server and engine status
"""

import argparse
import inspect
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

try:  # mcp 2.x renamed FastMCP to MCPServer; the requirements.lock pins 2.x
    from mcp.server.mcpserver import MCPServer
except ImportError:  # mcp 1.x
    from mcp.server.fastmcp import FastMCP as MCPServer

# ── Import the assessment engine ─────────────────────────────────────
# Engine sits alongside this file
import importlib.util

ENGINE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dlp_assessment_full_auto.py")
spec = importlib.util.spec_from_file_location("engine", ENGINE_PATH)
engine = importlib.util.module_from_spec(spec)
spec.loader.exec_module(engine)

REG = engine.REG
R = engine.R
compute = engine.compute
maturity = engine.maturity

# ── Import SDK client adapter ────────────────────────────────────────
SDK_CLIENT_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sdk_client.py")
sdk_spec = importlib.util.spec_from_file_location("sdk_client", SDK_CLIENT_PATH)
sdk_client_mod = importlib.util.module_from_spec(sdk_spec)
sdk_spec.loader.exec_module(sdk_client_mod)

SdkClient = sdk_client_mod.SdkClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("dlp_mcp")

# ── MCP Server ───────────────────────────────────────────────────────

mcp = MCPServer(
    "Zscaler DLP Assessment",
    instructions=(
        "Zscaler DLP Assessment tool server. Runs 150+ automated checks "
        "against a Zscaler tenant via OneAPI and returns a scored maturity "
        "report. Credentials are loaded from environment variables — do NOT "
        "pass secrets in prompts. Use run_assessment for a full report, "
        "run_section to focus on a specific area, or list_checks to see "
        "what's available."
    ),
)


# ── Helpers ──────────────────────────────────────────────────────────

def _get_sections() -> dict:
    """Return unique section names from the registry."""
    sections = {}
    for check_id, sec, label, _ in REG:
        if sec not in sections:
            sections[sec] = []
        sections[sec].append({"id": check_id, "label": label})
    return sections


def _create_client(
    vanity_domain: Optional[str] = None,
    cloud: Optional[str] = None,
) -> SdkClient:
    """Create an SdkClient from environment variables. Only the vanity
    domain and cloud, which are not secrets, may be overridden by a tool
    argument. Client ID and secret, and the classic ZIA API sign-in
    (ZSCALER_AUTH_METHOD=legacy, ZSCALER_USERNAME, ZSCALER_PASSWORD,
    ZSCALER_API_KEY), come from the environment alone; see tenant_auth."""
    import tenant_auth
    env = tenant_auth.from_env()
    c = tenant_auth.merge({"vanity_domain": vanity_domain or "", "cloud": cloud or ""}, env)
    return SdkClient(
        client_id=c["client_id"], client_secret=c["client_secret"], vanity_domain=c["vanity_domain"],
        cloud=c["cloud"] or "production", auth_method=c["auth_method"], username=c["username"],
        password=c["password"], api_key=c["api_key"],
    )


def _run_checks(client, checks) -> list:
    """Run a list of (id, section, label, fn) checks and return results."""
    results = []
    for check_id, sec, label, fn in checks:
        try:
            r = fn(client)
        except Exception as ex:
            r = R(R.ERROR, str(ex))
        results.append({
            "id": check_id,
            "section": sec,
            "label": label,
            "status": r.status,
            "detail": r.detail,
        })
    return results


def _build_report(results: list, org_name: str = "", assessor: str = "", cloud: str = "") -> dict:
    """Build a scored assessment report from check results."""
    secs, overall = compute(results)
    return {
        "metadata": {
            "tool": "DLP Assessment MCP Server (SDK)",
            "version": "3.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "org": org_name,
            "assessor": assessor,
            "cloud": cloud,
            "total_checks": len(results),
        },
        "score": overall,
        "maturity": maturity(overall),
        "sections": secs,
        "checks": results,
        "critical": [r for r in results if r["status"] == "FAIL"],
        "review": [r for r in results if r["status"] == "REVIEW"],
        "summary": (
            f"Score: {'n/a' if overall is None else str(overall) + '%'} ({maturity(overall)}). "
            f"{sum(1 for r in results if r['status']=='PASS')} passed, "
            f"{sum(1 for r in results if r['status']=='FAIL')} failed, "
            f"{sum(1 for r in results if r['status']=='REVIEW')} need review."
        ),
    }


# ── MCP Tools ────────────────────────────────────────────────────────

@mcp.tool()
def run_assessment(
    org_name: str = "Unknown",
    assessor: str = "AI Agent",
    cloud: str = "",
    vanity_domain: str = "",
) -> dict:
    """
    Run the full DLP assessment (150+ checks) against a Zscaler tenant.

    Credentials are read from the server's environment variables only.
    Never ask the user for a client secret, password or API key: if
    get_health reports credentials missing, tell the user which
    environment variables to set before starting the server.

    Returns a scored maturity report with pass/fail/review for every check,
    section scores, overall score, and critical findings.
    """
    client = _create_client(vanity_domain or None, cloud or None)
    auth = client.auth()
    if auth is not True:
        return {"error": f"Authentication failed: {auth}"}

    logger.info("Running full assessment (%d checks)...", len(REG))
    results = _run_checks(client, REG)
    client.close()

    return _build_report(results, org_name, assessor, client._config.get("cloud", ""))


@mcp.tool()
def run_section(
    section: str,
    org_name: str = "Unknown",
    cloud: str = "",
    vanity_domain: str = "",
) -> dict:
    """
    Run checks for a specific assessment section only.

    Credentials are read from the server's environment variables only.

    Available sections (use list_checks to see all):
      "1 — CC Portal", "2 — Bypass Inventory", "3 — App Profile",
      "4 — SSL Policy", "5 — Endpoint DLP", "Multi-Channel",
      "6 — Versions", "7 — SSL Alignment", "8 — Pilot Tests",
      "9 — Troubleshooting", "10 — macOS", "11 — Rollback",
      "12 — Incident Mgmt", "Ch.A — Inline Web", "Ch.B — Endpoint",
      "Ch.E — GenAI"

    The section parameter is matched as a substring, so "SSL" matches
    both "4 — SSL Policy" and "7 — SSL Alignment".
    """
    section_lower = section.lower()
    filtered = [(cid, sec, label, fn) for cid, sec, label, fn in REG
                if section_lower in sec.lower()]

    if not filtered:
        available = sorted(set(sec for _, sec, _, _ in REG))
        return {"error": f"No section matches '{section}'", "available": available}

    client = _create_client(vanity_domain or None, cloud or None)
    auth = client.auth()
    if auth is not True:
        return {"error": f"Authentication failed: {auth}"}

    logger.info("Running %d checks for section '%s'...", len(filtered), section)
    results = _run_checks(client, filtered)
    client.close()

    return _build_report(results, org_name, "AI Agent", client._config.get("cloud", ""))


@mcp.tool()
def list_checks() -> dict:
    """
    List all available DLP assessment checks grouped by section.

    Returns section names, check IDs, and labels. Use this to understand
    what the assessment covers before running it.
    """
    sections = _get_sections()
    return {
        "total_checks": len(REG),
        "sections": {
            sec: {"count": len(checks), "checks": checks}
            for sec, checks in sections.items()
        },
    }


@mcp.tool()
def get_health() -> dict:
    """
    Check the DLP assessment server health.

    Verifies the engine is loaded and credentials are configured.
    Does NOT make API calls to Zscaler.
    """
    import tenant_auth
    env = tenant_auth.from_env()
    missing = [tenant_auth.ENV[k] for k in tenant_auth.missing(env)]
    return {
        "status": "ok",
        "engine_loaded": True,
        "total_checks": len(REG),
        "version": "3.0",
        "auth_method": env["auth_method"],
        "credentials_configured": not missing,
        # Names only, never values. These are set where the server runs;
        # no tool accepts a secret.
        "missing_environment_variables": missing,
        "sdk": "zscaler-sdk-python",
    }


# ── Entrypoint ───────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DLP Assessment MCP Server")
    parser.add_argument("--transport", default="streamable-http",
                        choices=["streamable-http", "stdio", "sse"],
                        help="MCP transport (default: streamable-http)")
    parser.add_argument("--port", type=int, default=8080,
                        help="Port for HTTP transport (default: 8080)")
    parser.add_argument("--host", default=os.environ.get("ZSCALER_MCP_BIND_HOST", "127.0.0.1"),
                        help="Bind address for HTTP transports (default: 127.0.0.1, loopback only). The server holds "
                             "tenant credentials and has no authentication of its own, so expose it beyond this "
                             "machine only behind an authenticating proxy.")
    args = parser.parse_args()

    if args.transport in ("streamable-http", "sse") and args.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: MCP server bound to {args.host}: anyone who can reach port {args.port} can run assessments "
              "with this process's tenant credentials. Put an authenticating proxy in front of it.", file=sys.stderr)
    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif "host" in inspect.signature(mcp.run).parameters:  # mcp 2.x takes the address in run()
        mcp.run(transport=args.transport, host=args.host, port=args.port)
    else:  # mcp 1.x reads it from settings
        mcp.settings.host, mcp.settings.port = args.host, args.port
        mcp.run(transport=args.transport)
