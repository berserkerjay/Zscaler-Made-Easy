# Security policy

DLP-Check runs on a consultant's laptop, holds a Zscaler API client's
credentials for the length of an engagement, and can write to a customer
tenant. This page says how the tool protects that, and how to report a
problem with it.

## Reporting a vulnerability

Open a **private security advisory** on the GitHub repository
(Security → Advisories → Report a vulnerability), or email the repository
owner directly. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and the build (the commit
shown in the app's *Build* badge or `GET /api/health`). You will get an
acknowledgement within 3 business days and a fix or a mitigation within
30 days for anything that exposes credentials, tenant data or allows a
write the operator did not approve.

## Supported versions

Only the `main` branch is supported. The in-app **Update app** button (or
`UPDATE_Zscaler_Assessment.bat`) fast-forwards to it. There are no
maintained release branches.

## What the tool does to be safe by default

| Area | Behaviour |
|---|---|
| Access to the UI and API | A random token per server process (`ZSCALER_UI_TOKEN` to fix it). The launcher opens the browser with it and the server turns it into an HttpOnly, SameSite=Strict cookie; any other caller needs `X-DLP-Check-Token` or a Bearer header, or gets 401. The token is printed on the console and written to `ui_token.txt` (owner-only, git-ignored). `ZSCALER_UI_AUTH=0` disables it. |
| SSO (optional, off by default) | `ZSCALER_SSO_ENABLED=1` (`sso.py`) requires an OpenID Connect sign-in (Authorization Code + PKCE, ID token signature/issuer/audience/nonce verified against the identity provider's published keys) before the same UI token cookie above is issued; the static-token shortcuts (`?token=...`, paste-in unlock) are refused once it's on. Enabled but missing a required `ZSCALER_SSO_*` variable refuses to start rather than falling back silently. Meant for the container/server deployment, not the single-operator desktop launcher. |
| Audit trail | Every non-GET API call is appended to `audit.log` (owner-only, git-ignored, rotated at 20 MB) with time, path, status, caller, write-mode state and a redacted body; deployments are additionally recorded in `deployments.json` for undo. |
| Dependencies and updates | `requirements.lock` pins every wheel by hash; the installer, the updater and the container install with `--require-hashes`. CI checks the lock against `requirements.txt`, runs `pip-audit`, publishes a CycloneDX SBOM, builds the image and scans it; Dependabot watches pip, Actions and the base image. |
| Container | `Dockerfile` + `docker-compose.yml`: non-root user, read-only filesystem, no capabilities, no privilege escalation, data on a volume, published on the host loopback only. |
| Writes to a tenant | Refused unless write mode is enabled for the session (typed phrase, localhost only) or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Deploys require an approved plan hash; every rule ships DISABLED and monitor-only; nothing is activated; every deployment is recorded for undo. Applying an approved FP/TP Detection Ratio proposal goes through the same gate with an explicit confirmation, a re-read that refuses when the tenant moved, a read-back, and a recorded rollback value. |
| Credentials | Form, `ZSCALER_*` environment, `local_settings.bat`, or a saved profile (secrets only when *remember* is ticked; the OS credential store, else the owner-only file). Two sign-ins: a ZIdentity API client (OneAPI) or the classic ZIA API (admin username, password, API key; the password and key are secrets like the client secret). Never returned by the API, masked in every error, redacted in the audit log, all files git-ignored. |
| Network | Web server and MCP server bind to 127.0.0.1 by default. CORS and origin checks allow localhost origins only. Security headers (CSP, frame-ancestors none, nosniff, no-referrer), a body-size cap and a rate limit are always on. Update, pack upload and pack rewrite are refused unless bound to localhost. |
| Outbound calls | Only the Zscaler API for the tenant, GitHub for the app update, Zscaler and integration-partner documentation hosts on an allowlist for the update check, the best-practice library and the SaaS capability matrix, and, only when you configure them, your SMTP relay and an https Teams or Slack webhook for the digest. No AI or LLM service is called by the app. |
| Continuous evaluation | Runs read-only every six hours (and from a scheduled task): FP/TP Detection Ratio, SaaS tenant status, journey drift and guidance mapping. It raises proposals; a person decides them; applying goes through the deploy path. Digests hold counts, titles and rule names, never credentials; the SMTP password and webhook URL stay in `local_settings.bat` (git-ignored) and are never returned by the API. |
| Inputs | Cloud, vanity domain, credentials and customer id are validated before any client is built; pack ids resolve against the discovered pack list; report ids are random tokens; dictionary patterns are bounded to ZIA's limits. |
| Uploaded logs (Log Analyzer) | Client Connector log bundles and PAC files are analysed in memory on the local server and discarded: nothing is written to disk and nothing leaves the machine. Archives are opened with caps (600 members, 48 MB per member, 160 MB in total, one level of nesting), member names are never used as paths, binary members are skipped, and the whole request is under the body-size cap. Evidence lines shown back have passwords, tokens, cookies and JWTs blanked out; the audit log records the call without the file contents. The page renders every value through one HTML escaper. |
| Code | Python 3.11, no `eval`/`exec`/`pickle`/`shell=True`, no SQL, one HTML escaper at every render site. Tests, `py_compile`, `node --check` and Terraform validation run in CI on every push. |

## Measuring it

The Advanced settings tab carries a **CISA Secure by Design score**: every
control in the table above is checked live against the running server and
the app folder (`GET /api/secure-by-design`), with what was found and what
to do when a control falls short.

## Known limitations

- The UI token is a bearer secret: anyone who reads `ui_token.txt` or the
  console can use the API from that machine. Exposing the server beyond
  loopback (`ZSCALER_BIND_HOST`) still needs a reverse proxy that
  authenticates users and terminates TLS, or `ZSCALER_SSO_ENABLED` set to
  require an identity-provider sign-in first (see the table above).
- A remembered profile secret goes to the operating system's credential
  store only when the optional `keyring` package is installed
  (`pip install keyring`); otherwise it stays in the owner-only profile
  file. Prefer `local_settings.bat` or the form on a shared laptop.
- The updater fast-forwards `main` over HTTPS but does not verify commit
  signatures. Update over a trusted network; do not set
  `ZSCALER_UPDATE_VERIFY_TLS=0` except behind a corporate TLS-inspection
  proxy whose root you trust.
- The page's Content-Security-Policy still allows inline scripts, because
  the GUI ships its script inline; a stored XSS in tenant-supplied text is
  mitigated by escaping at every render site, not by CSP.
