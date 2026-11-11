# Zscaler Made Easy — assess, administer, audit and deploy Zscaler, in plain words

> **Project status: paused for community feedback.** I won't be updating this app until I hear from people who use it. If you try it, please open an issue with what worked, what didn't, and what you'd want next. That feedback decides what comes next.

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

Zscaler Made Easy connects to a customer's Zscaler tenant with API credentials,
runs 300+ automated checks against the DLP assessment checklist and
Zscaler's best practices, and gives a scored maturity report with plain
findings. It then closes the gaps by deploying **policy packs** (ready-made
dictionaries, engines and rules for CJIS, Federal CUI, Healthcare PHI,
banking, enterprise best practice and source code) through a guided plan →
review → approve → deploy → verify flow, removes them just as carefully,
and measures where the tenant is on the data-governance journey on every
visit. Every rule a pack creates arrives switched off and monitor-only, so
deploying never affects the customer's users.

New to this? **[docs/OVERVIEW.md](docs/OVERVIEW.md)** is a five-minute tour
of what the app can do and what it never does. **[INSTALL.md](INSTALL.md)**
is a click-by-click install walkthrough for Windows, Mac, Linux or a
container, written for someone who has never installed a developer tool
before; **[GETTING_STARTED.md](GETTING_STARTED.md)** then walks through a
first engagement. Nothing to install at all: each release also ships a
standalone edition for Windows, Mac and Linux, checked by checksum and
build attestation before you run it (INSTALL.md, *Download and run*).
To ask an AI assistant about a tenant with the app's engines (read-only),
see **[docs/AI_ASSISTANT.md](docs/AI_ASSISTANT.md)**.

Two ways to run it, built from this one source tree:

| Mode | For | How |
|---|---|---|
| **Local** | a consultant's laptop | `INSTALL_Zscaler_Made_Easy.bat` (Windows) or `./install.sh` (Linux, macOS), then the Start script |
| **Container** | a server or cloud host | `docker compose up --build` (or `docker build -t zscaler-made-easy:local .`) |

Both install the same hash-pinned dependencies (`requirements.lock`) and
run the same entry point (`dlp_api_server.py`). A test
(`tests/test_packaging.py`) fails if they drift apart.

## Quick start (local)

Windows: install Python 3.11+ (tick *Add python.exe to PATH*), get the code
(`git clone`, or the ZIP from the Code button), double-click
`INSTALL_Zscaler_Made_Easy.bat`, then the desktop shortcut it creates.
The installer uses a private `.venv` on Windows as well as Mac/Linux. The
server runs in the background (output in `server.log`);
`STOP_Zscaler_Made_Easy.bat` stops it.

Linux / macOS:

```bash
./install.sh        # private .venv, pinned dependencies, the zscaler-made-easy command
./start.sh          # prints the address and the UI token, opens the browser
./stop.sh           # when started with ./start.sh --background
```

The server binds to `127.0.0.1:8000` and prints a one-time UI token; open
the printed address (it carries the token) or paste the token when asked.
Type the tenant's API credentials in the form, or save a tenant profile.

## Quick start (container)

There is no published image: Docker builds it from this code. Install Docker first (INSTALL.md, *Run it in a container instead*, has every step for Windows, Mac and Linux), then clone and build:

```powershell
# Windows (PowerShell)
git clone https://github.com/berserkerjay/Zscaler-Made-Easy.git; cd Zscaler-Made-Easy
powershell -ExecutionPolicy Bypass -File .\update_container.ps1 -Force
docker logs zscaler-made-easy      # shows the UI token and http://localhost:8001/?token=…
```

```bash
# Mac or Linux
git clone https://github.com/berserkerjay/Zscaler-Made-Easy.git && cd Zscaler-Made-Easy
./update_container.sh --force
docker logs zscaler-made-easy      # shows the UI token and http://localhost:8001/?token=…
```

**Behind Zscaler or another TLS-inspecting proxy?** The build fails with `CERTIFICATE_VERIFY_FAILED` at step `[6/8]` unless the container trusts your company's root certificate. Run this once in the app folder before the update script; it copies your computer's Zscaler Root CA into `certs/` (the build log then says `extra root certificates added: 1`):

```bash
./get_zscaler_cert.sh                                                   # Mac or Linux
powershell -ExecutionPolicy Bypass -File .\get_zscaler_cert.ps1          # Windows
```

If it can't find the certificate, ask IT for the root certificate as a Base-64 `.crt` file and save it in `certs/`, or ask them to exempt `pypi.org` and `files.pythonhosted.org` from inspection. Already failed once? Run the script, then the update script again. The file stays on your machine (`certs/` is git-ignored).

No git? Docker can fetch and build it by itself: `docker build --secret id=GIT_AUTH_TOKEN,env=GIT_AUTH_TOKEN -t zscaler-made-easy:local "https://github.com/berserkerjay/Zscaler-Made-Easy.git#main"` with a read-only GitHub token in `GIT_AUTH_TOKEN`, then `docker run` (INSTALL.md, *Install with Docker commands only*).

The update script runs `docker compose up -d --build` with the build's git commit stamped in; plain `docker compose up --build` works too. It is published on 127.0.0.1:8001 only (the local install uses 8000).

The container runs as a non-root user on a read-only filesystem with every
capability dropped; everything it writes (profiles, deployment records,
audit log, the token file, uploaded packs) goes to the `zscaler-made-easy-data`
volume mounted at `/data`. Put `ZSCALER_*` variables in a `.env` file next
to `docker-compose.yml` to pre-fill credentials (git-ignored). To reach it
from other machines, front it with a reverse proxy that authenticates users
and terminates TLS; do not publish port 8000 on a public interface.

## Running the tests and the checks

```bash
make dev                                 # once: installs pytest, pyflakes and bandit into .venv
make test                                # .venv/bin/python -m pytest -q tests
make check                               # compile, pyflakes, pack conventions, Terraform freshness, offline upstream check (what CI runs)
make sast                                # offline static analysis (bandit); fails on a medium+ finding (tests/test_sast.py runs it too)
make upstream                            # the daily upstream check by hand: SDK, Terraform provider, API reference vs what the app sends
```

The upstream check (`upstream_check.py`) runs every day in GitHub Actions
(`.github/workflows/upstream_check.yml`). It compares what the app sends
with the installed `zscaler-sdk-python`, PyPI's latest release and 2.x
prerelease (whose ZIA service definition is machine-readable), the
`zscaler/zia` Terraform provider's latest version, schema and docs, and
Zscaler's API reference. Drift opens or updates one issue labelled
`upstream-drift` with the report; a clean day closes it.

CodeQL (`.github/workflows/codeql.yml`) scans the Python and the JavaScript
with GitHub's security-extended queries on pull requests to `dev`, `qa` and
`main` and weekly; see `SECURITY.md` "Static analysis (SAST)".

The same watchers also run inside the app as **Beacon** (`beacon.py`, the
Beacon tab, `/report/beacon`): the SDK, the ZIA API (service definition,
API reference, help-center pages) and the Terraform provider, on a timer
while the server runs (`DLP_CHECK_BEACON_HOURS`, default 24, 0 turns it
off) and on demand, each run compared with the last (the last 30 are
kept). The tab can also read from a tenant the endpoints that are in scope on the
Scope page (and nothing else), GET only, and say which ones now answer
differently.

The **Digest** (`continuous_eval.py`) reads tenants, and every read counts
against the ZIA API rate limit, so it never runs on its own by default: it
runs when you click *Run the loop now*, or from `python continuous_eval.py
--once` / `RUN_Continuous_Evaluation.bat`, and each tenant profile is read
only for what its Scope page puts in scope (nothing, when no scope is
saved). `DLP_CHECK_CONTINUOUS_EVAL_HOURS` opts in to a timer while the
server runs (unset or 0, the default: off).

The suite (380 tests) covers the checks, the policy-pack planner and
executor against a fake tenant that refuses what a real ZIA tenant refuses,
the API endpoints, the background jobs, the entry points' error paths and
the packaging files.

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
| `ZSCALER_SSO_ENABLED` | unset | `1` requires an OpenID Connect sign-in (Okta, Entra ID, Google Workspace, Auth0, Keycloak, ...) before the UI token cookie is issued, instead of the static-token shortcuts. Off by default — see `sso.py` and `SECURITY.md`. |
| `ZSCALER_SSO_ISSUER`, `ZSCALER_SSO_CLIENT_ID`, `ZSCALER_SSO_CLIENT_SECRET`, `ZSCALER_SSO_REDIRECT_URL` | unset | Required once `ZSCALER_SSO_ENABLED=1` (the server refuses to start otherwise); `ZSCALER_SSO_SCOPES` is optional (`openid email profile`). |
| `ENABLE_WRITE_ACTIONS` | unset | `YES_I_UNDERSTAND` lets the server change a tenant; otherwise the switch in Deploy Policy Packs enables it per session on a localhost bind. |
| `ZSCALER_OPEN_BROWSER` | unset | `1` opens the browser when the server starts (the launchers set it). |
| `ZSCALER_DEBUG` | unset | `1` shows tracebacks and request logs. |
| `ZSCALER_MAX_BODY_MB` | `10` | Request body cap, 1–100 MB. |
| `ZSCALER_CLOUD`, `ZSCALER_VANITY_DOMAIN`, `ZSCALER_CLIENT_ID`, `ZSCALER_CLIENT_SECRET` | unset | Pre-fill the OneAPI tenant credentials (never required; the form or a saved profile work too). `ZSCALER_CLOUD` is the cloud in the tenant's admin URL: `zscaler`, `zscalerone`, `zscalertwo`, `zscalerthree`, `zscloud`, `zscalerten` (all commercial: zslogin.net and api.zsapi.net), `zscalerbeta`, `zscalergov` (zscalergov.net) or `zscalergovus` (zscalergov.us); the government clouds use their own FedRAMP sign-in and gateway. |
| `ZSCALER_AUTH_METHOD`, `ZSCALER_USERNAME`, `ZSCALER_PASSWORD`, `ZSCALER_API_KEY` | unset | The classic ZIA API sign-in for a tenant without ZIdentity: `ZSCALER_AUTH_METHOD=legacy` with the admin's username and password and the tenant's API key (ZIA Administration → API Key Management). Signs in at `zsapi.<cloud>.net`, so `ZSCALER_CLOUD` must name the actual cloud (Commercial means zscaler.net). ZIA only: no ZPA, Client Connector or ZDX checks. |
| `HTTPS_PROXY`, `REQUESTS_CA_BUNDLE`, `ZSCALER_UPDATE_PROXY`, `ZSCALER_UPDATE_VERIFY_TLS` | unset | Corporate proxy and TLS inspection. |
| `DLP_CHECK_PROFILES`, `DLP_CHECK_DEPLOYMENTS`, `DLP_CHECK_AUDIT`, `DLP_CHECK_USER_PACKS` | app folder | Where profiles, deployment records, the audit log and uploaded packs are stored (the container points them at `/data`). |

Tenant credentials for the command-line assessment come from a JSON file:
copy `tenant_config_sample.json`, fill in `client_id`, `client_secret`,
`vanity_domain` and `cloud` (or `auth_method: "legacy"` with `username`,
`password` and `api_key`), and run
`.venv/bin/zscaler-made-easy-assess --config tenant.json --output report.json`.
The commands from before the rename (`dlp-check`, `dlp-check-assess`,
`dlp-check-evaluate`) still work.
A missing or malformed file is reported in one sentence with exit code 2.

## How the project is structured

Flat Python modules in the repository root, each independent of the others
(see `ARCHITECTURE.md`); the web UI in `static/`; one directory per policy
pack; generated Terraform per pack in `terraform/`; tests in `tests/`.

| Area | Files |
|---|---|
| Web server and API | `dlp_api_server.py` (FastAPI, the `zscaler-made-easy` command), `security.py` (token gate, origin check, body cap, rate limit, write mode), `sso.py` (optional OpenID Connect sign-in, off by default), `audit.py` |
| Assessment engine | `dlp_assessment_full_auto.py` (the `Client`, the check registry, the `zscaler-made-easy-assess` command), `zscaler_*_checks.py`, `zcc_evaluation.py`, `benchmarks.py`, `compliance_mapping.py`, `plain_english.py`, `report_docx.py` |
| Policy packs | `pack_ops.py` (the shared execution path every pack goes through: validation, ordering, retries, run control, structured events), `pack_deploy.py` (plan, apply, journey, verify), `pack_removal.py` (remove, undo), `pack_jobs.py` (deploys and removals as background jobs the GUI follows live), `pack_channels.py` (per-channel payloads), `pack_library.py` (uploads), `pack_terraform.py`, `dlp_importer.py` (pack data and ZIA limits); pack data in `cjis_policy_pack/`, `fed_policy_pack/`, `global_banking_baseline/`, `healthcare_phi_baseline/`, `zbp_enterprise_baseline/`, `zbp_source_code_baseline/` |
| Reports and analysis | `bypass_report.py`, `ssl_flow.py`, `data_flow.py`, `detection_health.py`, `dlp_efficacy.py`, `log_analyzer.py`, `secure_by_design.py` |
| Continuous evaluation | `continuous_eval.py` (the `zscaler-made-easy-evaluate` command), `proposals.py`, `proposal_apply.py`, `deployments.py`, `tenant_profiles.py` |
| Tools | `tools/fan_out_channels.py` (channel mirrors), `tools/validate_detection.py` (offline detection validation), `app_update.py` (the Update app button), `upstream_check.py` (the SDK, the Terraform provider and Zscaler's API reference cross-checked against what the app sends; offline in `make check`, online daily in `.github/workflows/upstream_check.yml`), `beacon.py` (the same watchers in the app on a timer, what changed since the last run, and the GET-only tenant API watch) |

Documentation: `docs/OVERVIEW.md` (what the app does, in five minutes),
`docs/BROWSER_EXTENSION.md` (the companion browser extension),
`docs/SECURITY_TESTING.md` (every security and regression test, mapped to OWASP ASVS, CWE, WSTG, WCAG, SLSA and SSDF),
`INSTALL.md` (installing, click by click), `GETTING_STARTED.md` (first
engagement, step by step),
`POLICY_PACKS.md` (pack format), `docs/SHARED_EXECUTION_PATH.md` (how
every pack is deployed, verified and removed), `SECURITY.md` (posture and
disclosure), `CHANGELOG.md`. Inside the app, every page has a *What is this
and why it matters* panel and *How a deployment works* walks through a
deployment step by step.

## Branching and releases

Three long-lived branches, promoted in one direction only:

```
feature branch → dev → qa → main
```

- **`dev`** is where new work lands first: a feature branch is opened off
  `dev`, developed there, and merged back into `dev` by pull request once
  its own tests are green.
- **`qa`** is `dev`'s work once it's ready to be
  verified end to end. Promoting is a fast-forward of `qa` to `dev`'s tip —
  never a new commit, never a rebase — so what gets tested is exactly what
  was merged, byte for byte.
- **`main`** is what customers run. Promoting is the same fast-forward,
  from `qa` to `main`, once QA has signed off.

Every promotion is a plain fast-forward (`git push origin <source>:<target>`
or an equivalent PR with no merge commit), not a rebase or a squash, so the
three branches never diverge from each other's history — only ever how far
ahead one is of the next. `git rev-list --left-right --count qa...main`
(or `dev...qa`) being anything other than `0 <n>` means something landed
out of order and needs attention before promoting further.

An install can be pointed at any of the three from the **Update app** card
(the **Branch** dropdown), `UPDATE_Zscaler_Made_Easy.bat <branch>`, or
`python app_update.py --branch <branch>`, so a fix can be tried on `dev`
or `qa` before it is promoted. The names are a strict allowlist
(`app_update.BRANCHES`); with no branch given, an update stays on the
branch the install is on. `main` is the default and what customers run.

## Zscaler prerequisites

1. OneAPI and ZIdentity enabled on the tenant.
2. An API client in ZIdentity with client-secret authentication and a
   read-only role for assessments; a DLP-policy write role only if packs
   will be deployed.
3. Client ID, client secret, vanity domain and cloud.

A tenant that has not enabled ZIdentity can use the **classic ZIA API**
instead (sign-in method in Tenant Configuration): an admin allowed to use
the API (username and password) and the tenant's API key from
Administration → API Key Management. It covers ZIA only.

`DLP_Assessment_Step_by_Step_Guide.docx` (repository root) walks through
creating them; `GETTING_STARTED.md` section 2 lists what to ask for.

## Security

See `SECURITY.md`. In short: read-only by default, machine identity only,
secrets never leave the machine or the API, loopback bound and token
guarded, dependencies pinned by hash and scanned in CI, the container
non-root and read-only, reports treated as confidential.

## License

Open source under the Apache License 2.0: the full text is in `LICENSE`,
and `NOTICE` carries the attribution that travels with every copy. You may
use, copy, change and redistribute the app under those terms. Whether the
GitHub repository is public or private is set by its owner; while it is
private, access is granted per GitHub account (`INSTALL.md` says whom to
ask). Third-party components keep their own licences:
`THIRD_PARTY_NOTICES.md` lists every one and says what the GPL and LGPL
components among them mean for redistributing the app. Report
vulnerabilities as `SECURITY.md` describes.
