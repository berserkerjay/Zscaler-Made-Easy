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
| Writes to a tenant | Refused unless write mode is enabled for the session (typed phrase, localhost only) or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Deploys require an approved plan hash; every rule ships DISABLED; nothing is activated; every deployment is recorded for undo. |
| Credentials | Form, `ZSCALER_*` environment, `local_settings.bat`, or a saved profile (secret only when *remember* is ticked; owner-only file). Never returned by the API, masked in every error, all files git-ignored. |
| Network | Web server and MCP server bind to 127.0.0.1 by default. CORS and origin checks allow localhost origins only. Security headers (CSP, frame-ancestors none, nosniff, no-referrer), a body-size cap and a rate limit are always on. Update, pack upload and pack rewrite are refused unless bound to localhost. |
| Outbound calls | Only the Zscaler API for the tenant, Zscaler/vendor documentation hosts on an allowlist for the update check and best-practice library, and an LLM endpoint you configure (loopback, or an allowlisted vendor host). |
| Inputs | Cloud, vanity domain, credentials and customer id are validated before any client is built; pack ids resolve against the discovered pack list; report ids are random tokens; dictionary patterns are bounded to ZIA's limits. |
| Code | Python 3.11, no `eval`/`exec`/`pickle`/`shell=True`, no SQL, one HTML escaper at every render site. Tests, `py_compile`, `node --check` and Terraform validation run in CI on every push. |

## Known limitations

- The web UI has no login of its own. The localhost bind is the access
  control; do not run it on a shared machine, and do not set
  `ZSCALER_BIND_HOST` to a non-loopback address without a reverse proxy
  that authenticates users.
- A remembered profile secret is stored in plain text in an owner-only
  file. On Windows the file inherits the user's profile permissions
  (there is no DPAPI wrapping yet). Prefer `local_settings.bat` or the
  form if the laptop is shared.
- Dependencies are floor-pinned in `requirements.txt` without hashes,
  and the updater does not verify commit signatures. Update over a
  trusted network; do not set `ZSCALER_UPDATE_VERIFY_TLS=0` except behind
  a corporate TLS-inspection proxy whose root you trust.
