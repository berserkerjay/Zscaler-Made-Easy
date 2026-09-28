# Security policy

DLP-Check runs on a consultant's laptop, holds a Zscaler API client's
credentials for the length of an engagement, and can write to a customer
tenant. This page says how the tool protects that, who is authorized to
test it, and how to report a problem with it.

## Scope and authorization for security testing

This policy authorizes good-faith security testing of **this product** —
the DLP-Check application, its container image, its dependencies and its
policy-pack content — running under your own control, against your own
test instance and your own credentials.

It does **not** authorize testing against a customer's Zscaler tenant, a
customer's data, or any environment you were not separately engaged to
test. DLP-Check is a client for the Zscaler API; a vulnerability in
Zscaler's own platform is Zscaler's to receive, not ours, and should go
to Zscaler directly.

Stay in scope and you are covered by the safe harbor below. Testing a
live customer tenant, someone else's install, or anything requiring you
to access data that is not yours is out of scope and not authorized by
this policy.

## Safe harbor

If you make a good-faith effort to comply with this policy while
researching or reporting a vulnerability in DLP-Check:

- We will not pursue legal action against you for that research, and we
  will not report it to law enforcement, provided you stay within the
  scope above.
- We consider that testing authorized under applicable computer-crime
  law (for example the U.S. Computer Fraud and Abuse Act) for the
  purposes of a good-faith vulnerability disclosure.
- If a third party (a hosting provider, a dependency's maintainer)
  initiates legal action related to your research and you have complied
  with this policy, we will make it known that your actions were
  authorized.

This safe harbor does not extend to testing a customer's tenant, social
engineering, physical access, denial-of-service testing, or accessing
data beyond what is needed to demonstrate the issue.

## Reporting a vulnerability

Open a **private security advisory** on the GitHub repository
(Security → Advisories → Report a vulnerability), or email the repository
owner directly. Do not open a public issue for a security problem.

Include what you found, how to reproduce it, and the build (the commit
shown in the app's *Build* badge or `GET /api/health`). You will get an
acknowledgement within 3 business days and a fix or a mitigation within
30 days for anything that exposes credentials, tenant data or allows a
write the operator did not approve.

## Coordinated disclosure

We ask for coordinated disclosure: please give us the chance to ship a
fix before any public write-up. Once a report is accepted, the issue is
made public — by us, as a GitHub Security Advisory, or by you if we have
not — at whichever comes first of:

- **90 days** after the report was accepted, or
- **7 days** after the fix lands on `main` and is available to every
  install through the in-app **Update app** button.

We will agree an earlier or later date with you in writing when the
issue needs it (an actively exploited flaw, or a fix that needs more
coordination with an upstream dependency).

Fixed vulnerabilities are published as **GitHub Security Advisories**
once the fix ships, with a plain-language description, the affected
versions, and, for anything **High** or **Critical**, a **CWE**
(Common Weakness Enumeration) classification.

## Supported versions

`main` is the supported branch: what customers run, and what the in-app
**Update app** button (or `UPDATE_Zscaler_Assessment.bat`) fast-forwards
to by default. The button's **Branch** choice (or
`UPDATE_Zscaler_Assessment.bat dev`, `python app_update.py --branch dev`)
can also move an install to `DLP-CHECK-QA` (QA) or `dev` (development) —
the two branches a fix passes through before it reaches `main` (README,
*Branching and releases*) — so a fix can be tried before it is promoted.
Those two carry work that has not been through QA, and a report produced
on them should say so. The choice is a strict allowlist of those three
names, validated before anything reaches git; with no branch named, an
update stays on the branch the install is on. There are no maintained
release branches.

## What the tool does to be safe by default

| Area | Behaviour |
|---|---|
| Access to the UI and API | A random token per server process (`ZSCALER_UI_TOKEN` to fix it). The launcher opens the browser with it and the server turns it into an HttpOnly, SameSite=Strict cookie; any other caller needs `X-DLP-Check-Token` or a Bearer header, or gets 401. The token is printed on the console and written to `ui_token.txt` (owner-only, git-ignored). `ZSCALER_UI_AUTH=0` disables it. This token is a bearer secret, not multi-factor authentication — see Known limitations. |
| SSO (optional, off by default) | `ZSCALER_SSO_ENABLED=1` (`sso.py`) requires an OpenID Connect sign-in (Authorization Code + PKCE, ID token signature/issuer/audience/nonce verified against the identity provider's published keys) before the same UI token cookie above is issued; the static-token shortcuts (`?token=...`, paste-in unlock) are refused once it's on. Enabled but missing a required `ZSCALER_SSO_*` variable refuses to start rather than falling back silently. Meant for the container/server deployment, not the single-operator desktop launcher. |
| Bind host beyond loopback | Refused at startup unless the operator either has SSO fully configured (the row above) or sets `ZSCALER_ALLOW_NONLOCAL_BIND=YES_I_UNDERSTAND` to say they have their own authenticating reverse proxy in front of it; binding beyond loopback with the UI token gate itself turned off (`ZSCALER_UI_AUTH=0`) is refused the same way. This stops a server from being exposed to a network with only a bearer token, or nothing at all, guarding it. `docker-compose.yml` sets this override deliberately: the container's *internal* bind is `0.0.0.0` inside its own isolated network namespace, and `ports: "127.0.0.1:8000:8000"` in the same file is what actually controls host exposure — the app itself cannot see that distinction, so the override documents the operator's (Docker's) decision instead. Changing that `ports:` mapping to publish beyond the host's loopback should come with configuring SSO, not just relying on this override. |
| Audit trail | Every non-GET API call is appended to `audit.log` (owner-only, git-ignored, rotated at 20 MB) with time, path, status, caller, write-mode state and a redacted body; deployments are additionally recorded in `deployments.json` for undo. |
| Dependencies and updates | `requirements.lock` pins every wheel by hash; the installer, the updater and the container install with `--require-hashes`. CI installs from that lock hash-verified, checks it against `requirements.txt`, runs `pip-audit`, publishes a CycloneDX SBOM, builds the image and scans it; Dependabot watches pip, Actions and the base image. The updater also cross-checks the commit it just pulled against GitHub's REST API — a separate channel from the git pull itself — and refuses the update if they disagree. |
| Container | `Dockerfile` + `docker-compose.yml`: non-root user, read-only filesystem, no capabilities, no privilege escalation, data on a volume, published on the host loopback only. |
| Writes to a tenant | Refused unless write mode is enabled for the session (typed phrase, localhost only) or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Deploys require an approved plan hash; every rule ships DISABLED and monitor-only; nothing is activated; every deployment is recorded for undo. Applying an approved FP/TP Detection Ratio proposal goes through the same gate with an explicit confirmation, a re-read that refuses when the tenant moved, a read-back, and a recorded rollback value. |
| Credentials | Form, `ZSCALER_*` environment, `local_settings.bat`, or a saved profile (secrets only when *remember* is ticked; the OS credential store, else the owner-only file). Two sign-ins: a ZIdentity API client (OneAPI) or the classic ZIA API (admin username, password, API key; the password and key are secrets like the client secret). Never returned by the API, masked in every error, redacted in the audit log, all files git-ignored. |
| Network | Web server and MCP server bind to 127.0.0.1 by default. CORS and origin checks allow localhost origins only. Security headers (CSP, frame-ancestors none, nosniff, no-referrer), a body-size cap and a rate limit are always on. Update, pack upload and pack rewrite are refused unless bound to localhost. |
| Outbound calls | Only the Zscaler API for the tenant, GitHub for the app update (git pull and, for the cross-check above, the GitHub REST API), Zscaler and integration-partner documentation hosts on an allowlist for the update check, the best-practice library and the SaaS capability matrix, and, only when you configure them, your SMTP relay and an https Teams or Slack webhook for the digest. The upstream contract check (`upstream_check.py`, run daily in GitHub Actions, never by the server) additionally reads PyPI, the Terraform registry, raw.githubusercontent.com and automate.zscaler.com through the same allowlist. No AI or LLM service is called by the app. |
| Continuous evaluation | Runs read-only every six hours (and from a scheduled task): FP/TP Detection Ratio, SaaS tenant status, journey drift and guidance mapping. It raises proposals; a person decides them; applying goes through the deploy path. Digests hold counts, titles and rule names, never credentials; the SMTP password and webhook URL stay in `local_settings.bat` (git-ignored) and are never returned by the API. |
| Inputs | Cloud, vanity domain, credentials and customer id are validated before any client is built; pack ids resolve against the discovered pack list; report ids are random tokens; dictionary patterns are bounded to ZIA's limits. |
| Uploaded logs (Log Analyzer) | Client Connector log bundles and PAC files are analysed in memory on the local server and discarded: nothing is written to disk and nothing leaves the machine. Archives are opened with caps (600 members, 48 MB per member, 160 MB in total, one level of nesting), member names are never used as paths, binary members are skipped, and the whole request is under the body-size cap. Evidence lines shown back have passwords, tokens, cookies and JWTs blanked out; the audit log records the call without the file contents. The page renders every value through one HTML escaper. |
| Code | Python 3.11, no `eval`/`exec`/`pickle`/`shell=True`, no SQL, one HTML escaper at every render site. Tests, `py_compile`, `node --check` and Terraform validation run in CI on every push. See `docs/VULNERABILITY_CLASSES.md` for the fuller picture of which classes of vulnerability this designs out, and which remain. |

## Measuring it

The Advanced settings tab carries a **CISA Secure by Design score**: every
control in the table above is checked live against the running server and
the app folder (`GET /api/secure-by-design`), with what was found and what
to do when a control falls short.

## Known limitations

- The UI token is a bearer secret, and SSO sign-in through an identity
  provider is only as strong as that provider's own policy — **neither
  is multi-factor authentication by itself.** Anyone who reads
  `ui_token.txt` or the console can use the API from that machine.
  Exposing the server beyond loopback (`ZSCALER_BIND_HOST`) now refuses
  to start unless SSO is fully configured (`ZSCALER_SSO_ENABLED`) or the
  operator explicitly accepts the risk with
  `ZSCALER_ALLOW_NONLOCAL_BIND=YES_I_UNDERSTAND` because they already
  have a reverse proxy in front of it that authenticates users, requires
  a second factor and terminates TLS.
- A remembered profile secret goes to the operating system's credential
  store only when the optional `keyring` package is installed
  (`pip install keyring`); otherwise it stays in the owner-only profile
  file. Prefer `local_settings.bat` or the form on a shared laptop.
- The updater fast-forwards `main` over HTTPS and cross-checks the
  commit it pulled against GitHub's REST API (a channel separate from
  the git pull), but it does not verify GPG or Sigstore signatures on
  commits or tags — `main` carries no signed tags. A compromise of
  GitHub itself, or of the maintainer's account, would defeat both
  checks. Update over a trusted network; do not set
  `ZSCALER_UPDATE_VERIFY_TLS=0` except behind a corporate TLS-inspection
  proxy whose root you trust.
- The page's Content-Security-Policy still allows inline scripts, because
  the GUI ships its script inline; a stored XSS in tenant-supplied text is
  mitigated by escaping at every render site, not by CSP. See
  `docs/VULNERABILITY_CLASSES.md`.
