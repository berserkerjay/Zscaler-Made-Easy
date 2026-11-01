# Ask an AI assistant about your tenant

Zscaler Made Easy ships an MCP server (`dlp_mcp_server.py`) and a skill
(`skills/zscaler-made-easy/`) so an AI assistant (Claude, or any assistant
that speaks the Model Context Protocol) can answer an admin's questions
about their own tenant with the app's engines: *why was this blocked?*,
*which rule wins?*, *is our DLP covering email?*, *what is not SSL
inspected?*, *what changed since last week?*

This page says what the assistant can and cannot do, and how to connect it.

## What it can do, and what it never does

The server has these tools. **Every one is read-only.** There is no tool
that changes the tenant, none takes a secret, and none takes a write
switch or a confirmation. Changes stay in the app's pages, behind write
mode, a named writer and assessor, a preview and a typed confirmation.

| Tool | The app's engine | Answers |
|---|---|---|
| `list_sources` | — | Is the sign-in set? What is in scope? Which snapshots exist? |
| `path_check` | Path analyzer | Why is X blocked or allowed, for whom, on which network and platform |
| `test_list` | Test a list | The same for up to 50 destinations |
| `rule_precedence` | Shadowed rules | How each policy orders its rules; rules that never match or act |
| `explain_dlp` | DLP engine explainer | An engine or DLP rule in plain words; a channel's rules |
| `data_flow` | Data Flow Map | Every traffic class through the tenant's data security controls |
| `ssl_coverage` | SSL coverage | What is left encrypted, why, and the recovery plan |
| `dlp_incidents` | Live DLP feed | DLP incidents counted by rule and enforcement (users counted, not named) |
| `traffic_summary` | Traffic insights | ZIA Insights aggregates (no per-user rows) |
| `zpa_path` | ZPA diagnostics | Segment, access rule and connectors for one private destination |
| `fleet_health` | Client Connector fleet | Device counts, alerts and failing profile checks (no device list) |
| `snapshot_diff` | Snapshot compare | Objects added, removed and changed |
| `category_lookup` | URL lookup | Zscaler's categories for up to 25 URLs |
| `readiness` | Readiness check | What the API client can read or change |
| `compliance_map` | Compliance mapping | Framework controls met or not, from the last assessment |
| `traffic_logs_summary` | Traffic and session logs | A saved report as counts (people counted); never an upload through MCP |
| `ztw_summary` | Cloud & Branch Connector | Connector counts and the connector checks (admins and keys counted) |
| `zdx_summary` | ZDX | App score bands, the lowest apps, alerts by severity and rule (no devices) |
| `timeline` | Audit timeline | What the app did since a date, from its own records (people counted) |
| `case_notes` | Workspace notes | The admin's notes for the tenant (local) |
| `run_assessment`, `run_section`, `list_checks`, `get_health` | The assessment | As before |

Each analysis tool takes `source`: `live` (the tenant whose sign-in is set
where the server runs), `sample` (the made-up Larkspur Freight tenant, no
sign-in needed) or `snapshot` (a snapshot saved in the app, by its id).

How it stays safe:

- **Credentials come from the server's environment only**, the same
  `ZSCALER_*` variables the assessment tools always used. The assistant
  never sees them, and every answer is masked for them.
- **Read-only, twice over.** Every client a tool builds refuses PUT, PATCH,
  DELETE and every POST except the URL lookup, and every HTTP request the
  server sends passes a guard that lets through only reads: GET, plus the
  POSTs that only read (the sign-in token, the URL lookup, the Insights
  query, the Workflow Automation incident search).
- **The Scope rule.** You choose what may be read where the server runs
  (below); the assistant cannot widen it. A tool asked for something out of
  scope is refused before any sign-in, with what to tick.
- **Small, summarised answers.** At most about 48,000 characters each; long
  lists are shortened and the answer says so. People are counted, not
  named: no device list, no user names in the incident summary, no per-user
  Insights rows.
- **Tenant text is untrusted.** Rule names and descriptions can carry text
  meant to steer an assistant. Every answer keeps them under `data` and says
  they are data, not instructions; the skill tells the assistant the same.
- **One tenant read at a time**, on top of the app's pacing for ZIA's rate
  limits.

## 1. Install

The MCP server comes with the app: `./install.sh` (Mac, Linux) or
`INSTALL_Zscaler_Made_Easy.bat` (Windows) installs everything it needs. In a
plain checkout: `pip install -r requirements.txt`.

## 2. Tell the server which tenant and what is in scope

Set these where the server runs (in the assistant's MCP configuration, or
the shell that starts it). Never paste them into the conversation.

| Variable | What |
|---|---|
| `ZSCALER_VANITY_DOMAIN`, `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET` | The tenant's ZIdentity (OneAPI) API client |
| `ZSCALER_CLOUD` | The cloud, if not production (for example `zscalergov`) |
| `ZSCALER_CUSTOMER_ID` | The ZPA customer ID, for `zpa_path` and ZPA in `path_check` |
| `ZSCALER_AUTH_METHOD=legacy`, `ZSCALER_USERNAME`, `ZSCALER_PASSWORD`, `ZSCALER_API_KEY` | The classic ZIA API instead (ZIA only) |
| `ZSCALER_MCP_PROFILE` | **Scope:** a saved tenant profile's id or name; its Scope page ticks apply |
| `ZSCALER_MCP_SCOPES` | **Scope** without a profile: comma-separated keys, e.g. `dlp,zia_extras,zpa,zcc,insights` |
| `ZSCALER_MCP_CHANNELS` | The channels you run on Zscaler, e.g. `web_dlp,email_dlp,ssl_inspection,cloud_app_control,workflow_automation` |

With no scope set, every live read is refused (deny by default). The sample
tenant then uses everything it models, and a snapshot uses what was in
scope when it was saved. `list_sources` shows what the server sees.

The scope keys are the Scope page's: `dlp` (DLP), `zia_extras` (ZIA
platform), `zpa`, `zcc` (Client Connector), `insights` (ZIA Insights),
`ztw` (Cloud & Branch Connector), `genai`, `automation`, `zdx`,
`zidentity`, `rbac`, `aiguard`. The channel keys: `web_dlp`,
`endpoint_dlp`, `email_dlp`, `saas_casb`, `genai_security`, `shadow_it`,
`endpoint_scan`, `ssl_inspection`, `cloud_app_control`, `device_control`,
`workflow_automation`.

## 3. Connect the assistant

**stdio (recommended):** the assistant starts the server itself and talks
to it over a pipe; nothing listens on the network.

Claude Code:

```sh
claude mcp add zscaler-made-easy \
  -e ZSCALER_VANITY_DOMAIN=acme -e ZSCALER_CLIENT_ID=... -e ZSCALER_CLIENT_SECRET=... \
  -e ZSCALER_MCP_PROFILE="Acme production" \
  -- /path/to/app/.venv/bin/python /path/to/app/dlp_mcp_server.py --transport stdio
```

Claude Desktop (Settings → Developer → Edit config, `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "zscaler-made-easy": {
      "command": "/path/to/app/.venv/bin/python",
      "args": ["/path/to/app/dlp_mcp_server.py", "--transport", "stdio"],
      "env": {
        "ZSCALER_VANITY_DOMAIN": "acme",
        "ZSCALER_CLIENT_ID": "...",
        "ZSCALER_CLIENT_SECRET": "...",
        "ZSCALER_MCP_SCOPES": "dlp,zia_extras,zcc",
        "ZSCALER_MCP_CHANNELS": "web_dlp,ssl_inspection,cloud_app_control"
      }
    }
  }
}
```

On Windows the Python path is `C:\path\to\app\.venv\Scripts\python.exe`.
These files then hold the client secret: keep them readable by you only.
Other assistants (Cursor, VS Code, ...) take the same command, arguments
and environment in their own MCP settings.

**HTTP:** `python dlp_mcp_server.py` serves streamable HTTP on
`http://127.0.0.1:8080/mcp` (loopback only; `--port` to change it). Then,
for Claude Code: `claude mcp add --transport http zscaler-made-easy
http://127.0.0.1:8080/mcp`. The server has no sign-in of its own: anything
on this computer that can reach the port can use it, with the tenant
credentials it holds. It refuses requests whose Host header is not a
loopback name (DNS-rebinding protection), and refuses to listen beyond
loopback unless started with `--allow-remote`, which only belongs behind
an authenticating proxy. Prefer stdio.

## 4. Add the skill

The skill tells the assistant which tool answers which question, how to
read each answer, how to word the reply, and SIEM queries for checking what
really happened.

- **Claude Code:** copy the folder `skills/zscaler-made-easy` to
  `~/.claude/skills/` (for you) or to `.claude/skills/` in a project.
- **Claude apps:** zip the `zscaler-made-easy` folder and upload it under
  Settings → Capabilities → Skills.
- **Other assistants:** add `SKILL.md` as instructions; keep the
  `references/` files next to it, or paste the ones you need.

## 5. Try it

Ask, with no tenant connected: *"On the sample tenant, why would an upload
to drive.google.com be blocked?"* The assistant should call `list_sources`,
then `path_check` with `source: "sample"`, and answer with the deciding
rule, the source line and a note that the sample is made up.

## Limits

- Configuration is not traffic: most tools say what the tenant is set to
  do. `dlp_incidents` (DLP incidents only) and `traffic_summary` (aggregates
  only) are observed; for anything else, the skill offers a SIEM query for
  the admin to run.
- `test_list` takes 50 destinations and `category_lookup` 25 URLs per call;
  for more, use Test a list and the category analyzer in the app.
- `compliance_map` maps the last assessment run by this server
  (`run_assessment` or `run_section`), kept in memory only.
- Live reads take as long as on the app's pages (the Data Flow Map reads
  the most); one runs at a time.
