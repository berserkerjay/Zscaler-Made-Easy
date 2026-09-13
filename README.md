# DLP-Check — Zscaler DLP assessment and policy-pack deployment

DLP-Check connects to a customer's Zscaler tenant with API credentials,
runs 300+ automated checks against the DLP assessment checklist and
Zscaler's best practices, and gives a scored maturity report with plain
findings. It then closes the gaps by deploying **policy packs** (ready-made
dictionaries, engines and rules for CJIS, Federal CUI, Healthcare PHI,
banking, enterprise best practice and source code) through a guided plan →
review → approve → deploy → verify flow, removes them just as carefully,
and measures where the tenant is on the data-governance journey on every
visit. Every rule a pack creates arrives switched off and monitor-only, so
deploying never affects the customer's users.

Two ways to run it, built from this one source tree:

| Mode | For | How |
|---|---|---|
| **Local** | a consultant's laptop | `INSTALL_Zscaler_Assessment.bat` (Windows) or `./install.sh` (Linux, macOS), then the Start script |
| **Container** | a server or cloud host | `docker compose up --build` (or `docker build -t dlp-check .`) |

Both install the same hash-pinned dependencies (`requirements.lock`) and
run the same entry point (`dlp_api_server.py`). A test
(`tests/test_packaging.py`) fails if they drift apart.

## Quick start (local)

Windows: install Python 3.11+ (tick *Add Python to PATH*), double-click
`INSTALL_Zscaler_Assessment.bat`, then the desktop shortcut it creates.

Linux / macOS:

```bash
./install.sh        # private .venv, pinned dependencies, the dlp-check command
./start.sh          # prints the address and the UI token, opens the browser
./stop.sh           # when started with ./start.sh --background
```

The server binds to `127.0.0.1:8000` and prints a one-time UI token; open
the printed address (it carries the token) or paste the token when asked.
Type the tenant's API credentials in the form, or save a tenant profile.

## Quick start (container)

```bash
docker compose up --build          # published on 127.0.0.1:8000 only
docker logs dlp-check              # shows the UI token
```

The container runs as a non-root user on a read-only filesystem with every
capability dropped; everything it writes (profiles, deployment records,
audit log, the token file, uploaded packs) goes to the `dlpcheck-data`
volume mounted at `/data`. Put `ZSCALER_*` variables in a `.env` file next
to `docker-compose.yml` to pre-fill credentials (git-ignored). To reach it
from other machines, front it with a reverse proxy that authenticates users
and terminates TLS; do not publish port 8000 on a public interface.

## Running the tests and the checks

```bash
make dev                                 # once: installs pytest and pyflakes into .venv
make test                                # .venv/bin/python -m pytest -q tests
make check                               # compile, pyflakes, pack conventions, Terraform freshness (what CI runs)
```

The suite (340 tests) covers the checks, the policy-pack planner and
executor against a fake tenant that refuses what a real ZIA tenant refuses,
the API endpoints, the entry points' error paths and the packaging files.

## Configuration

Everything is configured by environment variables; the launchers read
`local_settings.bat` / `local_settings.env` (copy the `.example` files;
both are git-ignored), the container reads `.env`.

| Variable | Default | Meaning |
|---|---|---|
| `ZSCALER_BIND_HOST` | `127.0.0.1` | Address to listen on. Anything else exposes the server to the network. |
| `ZSCALER_PORT` | `8000` | Port (1–65535; an invalid value falls back to 8000 with a warning). |
| `ZSCALER_UI_AUTH` | `1` | Every caller must present the per-process UI token; `0` turns the gate off (local development only). |
| `ZSCALER_UI_TOKEN` | random | Fix the UI token instead of minting one per start. |
| `DLP_CHECK_UI_TOKEN_DIR` | app folder | Where `ui_token.txt` is written (`/data` in the container). |
| `ENABLE_WRITE_ACTIONS` | unset | `YES_I_UNDERSTAND` lets the server change a tenant; otherwise the switch in Deploy Policy Packs enables it per session on a localhost bind. |
| `ZSCALER_OPEN_BROWSER` | unset | `1` opens the browser when the server starts (the launchers set it). |
| `ZSCALER_DEBUG` | unset | `1` shows tracebacks and request logs. |
| `ZSCALER_MAX_BODY_MB` | `10` | Request body cap, 1–100 MB. |
| `ZSCALER_CLOUD`, `ZSCALER_VANITY_DOMAIN`, `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET` | unset | Pre-fill the tenant credentials (never required; the form or a saved profile work too). |
| `HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`, `ZSCALER_UPDATE_PROXY`, `ZSCALER_UPDATE_VERIFY_TLS` | unset | Corporate proxy and TLS inspection. |
| `DLP_CHECK_PROFILES`, `DLP_CHECK_DEPLOYMENTS`, `DLP_CHECK_AUDIT`, `DLP_CHECK_USER_PACKS` | app folder | Where profiles, deployment records, the audit log and uploaded packs are stored (the container points them at `/data`). |

Tenant credentials for the command-line assessment come from a JSON file:
copy `tenant_config_sample.json`, fill in `client_id`, `client_secret`,
`vanity_domain` and `cloud`, and run
`.venv/bin/dlp-check-assess --config tenant.json --output report.json`.
A missing or malformed file is reported in one sentence with exit code 2.

## How the project is structured

Flat Python modules in the repository root, each independent of the others
(see `ARCHITECTURE.md`); the web UI in `static/`; one directory per policy
pack; generated Terraform per pack in `terraform/`; tests in `tests/`.

| Area | Files |
|---|---|
| Web server and API | `dlp_api_server.py` (FastAPI, the `dlp-check` command), `security.py` (token gate, origin check, body cap, rate limit, write mode), `audit.py` |
| Assessment engine | `dlp_assessment_full_auto.py` (the `Client`, the check registry, the `dlp-check-assess` command), `zscaler_*_checks.py`, `zcc_evaluation.py`, `benchmarks.py`, `compliance_mapping.py`, `plain_english.py`, `report_docx.py` |
| Policy packs | `pack_ops.py` (the shared execution path every pack goes through: validation, ordering, retries, structured events), `pack_deploy.py` (plan, apply, journey, verify), `pack_removal.py` (remove, undo), `pack_channels.py` (per-channel payloads), `pack_library.py` (uploads), `pack_terraform.py`, `dlp_importer.py` (pack data and ZIA limits); pack data in `cjis_policy_pack/`, `fed_policy_pack/`, `global_banking_baseline/`, `healthcare_phi_baseline/`, `zbp_enterprise_baseline/`, `zbp_source_code_baseline/` |
| Reports and analysis | `bypass_report.py`, `ssl_flow.py`, `data_flow.py`, `detection_health.py`, `dlp_efficacy.py`, `log_analyzer.py`, `secure_by_design.py` |
| Continuous evaluation | `continuous_eval.py` (the `dlp-check-evaluate` command), `proposals.py`, `proposal_apply.py`, `deployments.py`, `tenant_profiles.py` |
| Tools | `tools/fan_out_channels.py` (channel mirrors), `tools/validate_detection.py` (offline detection validation), `app_update.py` (the Update app button) |

Documentation: `GETTING_STARTED.md` (first engagement, step by step),
`POLICY_PACKS.md` (pack format), `docs/SHARED_EXECUTION_PATH.md` (how
every pack is deployed, verified and removed), `SECURITY.md` (posture and
disclosure), `CHANGELOG.md`. Inside the app, every page has a *What is this
and why it matters* panel and *How a deployment works* walks through a
deployment step by step.

## Zscaler prerequisites

1. OneAPI and ZIdentity enabled on the tenant.
2. An API client in ZIdentity with client-secret authentication and a
   read-only role for assessments; a DLP-policy write role only if packs
   will be deployed.
3. Client ID, client secret, vanity domain and cloud.

`docs/DLP_Assessment_Step_by_Step_Guide.docx` walks through creating them.

## Security

See `SECURITY.md`. In short: read-only by default, machine identity only,
secrets never leave the machine or the API, loopback bound and token
guarded, dependencies pinned by hash and scanned in CI, the container
non-root and read-only, reports treated as confidential.

## License

Internal tooling. Not for redistribution.
