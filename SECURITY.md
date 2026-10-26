# Security policy

Zscaler Made Easy runs on a consultant's laptop, holds a Zscaler API client's
credentials for the length of an engagement, and can write to a customer
tenant. This page says how the tool protects that, who is authorized to
test it, and how to report a problem with it.

## Scope and authorization for security testing

This policy authorizes good-faith security testing of **this product** —
the Zscaler Made Easy application, its container image, its dependencies and its
policy-pack content — running under your own control, against your own
test instance and your own credentials.

It does **not** authorize testing against a customer's Zscaler tenant, a
customer's data, or any environment you were not separately engaged to
test. Zscaler Made Easy is a client for the Zscaler API; a vulnerability in
Zscaler's own platform is Zscaler's to receive, not ours, and should go
to Zscaler directly.

Stay in scope and you are covered by the safe harbor below. Testing a
live customer tenant, someone else's install, or anything requiring you
to access data that is not yours is out of scope and not authorized by
this policy.

## Safe harbor

If you make a good-faith effort to comply with this policy while
researching or reporting a vulnerability in Zscaler Made Easy:

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
can also move an install to `qa` (QA) or `dev` (development) —
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
| SSO (optional, off by default) | SSO is off by default; turn it on with ZSCALER_SSO_ENABLED=1 plus the ZSCALER_SSO_* settings (`sso.py`). It then requires an OpenID Connect sign-in per person (Authorization Code + PKCE, ID token signature/issuer/audience/nonce verified against the identity provider's published keys). Each sign-in gets its own random session id kept on the server with who signed in; the cookie carries only that id (HttpOnly, SameSite=Lax, Secure over HTTPS). The static UI token is refused in every form (header, Bearer, cookie, `?token=`, paste-in unlock), and it is neither printed nor written to `ui_token.txt`. Sessions end after 12 hours, after `ZSCALER_SSO_IDLE_MINUTES` (default 30) without use, or on **Sign out** (`POST /api/auth/logout`, audited). Enabled but missing a required `ZSCALER_SSO_*` variable refuses to start rather than falling back silently. Meant for the container/server deployment, not the single-operator desktop launcher. See *SSO: who may sign in and who may write* below. |
| Bind host beyond loopback | Local install: refused at startup unless SSO is fully configured (the row above), or the operator sets `ZSCALER_ALLOW_NONLOCAL_BIND=YES_I_UNDERSTAND` to say they have their own authenticating reverse proxy in front of it. With the UI token gate itself turned off (`ZSCALER_UI_AUTH=0`) a bind beyond loopback is always refused, in the container too and even with SSO; the override does not skip that. A server started some other way (`uvicorn --host 0.0.0.0`) is caught at request time: with the gate off only a request that arrived on a loopback address with a loopback `Host` name (localhost, 127.0.0.1, [::1]) is served, which also defeats DNS rebinding. Container: the server always listens on `0.0.0.0` inside its own network namespace, so the check reads the host address the container is published on instead (`DLP_CHECK_HOST_BIND`, also used by the `ports:` line of `docker-compose.yml`, `127.0.0.1` by default). Loopback starts as shipped, without SSO; any other address refuses to start unless SSO is fully configured, and the message names both choices (configure SSO, or publish on loopback). `ZSCALER_ALLOW_NONLOCAL_BIND` is not used in the container. |
| Audit trail | Every non-GET API call is appended to `audit.log` (owner-only, git-ignored, rotated at 20 MB) with time, path, status, caller address, the actor (the signed-in email, or subject, under SSO; otherwise `local UI token`, or `local, no UI token` with the gate off), write-mode state and a redacted body (secret-looking keys redacted; uploaded content such as `content`, `corpus`, `export` or `text` replaced by its size, never a prefix of it); sign-in, refused sign-in and sign-out are recorded too. Who decided, applied or rolled back a proposal is set by the server from the actor; a `by` sent by the page is ignored. A line that cannot be written is reported on stderr, never silently dropped. Deployments are additionally recorded in `deployments.json` for undo; a classic-API deployment there carries a one-way fingerprint of its sign-in (HMAC-SHA256 of the cloud and admin login under the install's own key, `tenant_fingerprint.key`, owner-only and git-ignored), never the login or the domain, and it is never shown. |
| Dependencies and updates | `requirements.lock` pins every wheel by hash; the installer, the updater and the container install with `--require-hashes`. CI installs from that lock hash-verified, checks it against `requirements.txt`, runs `pip-audit`, publishes a CycloneDX SBOM, builds the image and scans it; Dependabot watches pip, Actions and the base image. The updater also cross-checks the commit it just pulled against GitHub's REST API — a separate channel from the git pull itself — and refuses the update if they disagree. |
| Container | `Dockerfile` + `docker-compose.yml`: non-root user, read-only filesystem, no capabilities, no privilege escalation, data on a volume, published on the host loopback only. |
| Writes to a tenant | Refused unless write mode is enabled for the session (typed phrase, localhost only) or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Under SSO with `ZSCALER_SSO_WRITERS` set, only the listed groups and email addresses may do either, or deploy, remove, import, undo, apply or roll back; everyone else gets 403 and can still assess, read and preview. Every route that changes a tenant (deploy, import, removal, undo, proposal apply and rollback, change queue apply, heal, bulk changes, remediation, the Evaluate All Rules steps) also needs the explicit confirmation (`confirm=true`, or its typed phrase) and the assessor's name, and all four gates are checked before the tenant is signed in to (`tests/test_write_safety_gates.py` holds every POST, PUT and DELETE route to this). Deploys require an approved plan hash; every rule ships DISABLED and monitor-only; nothing is activated; every deployment is recorded for undo. Applying an approved FP/TP Detection Ratio proposal goes through the same gate with an explicit confirmation, a re-read that refuses when the tenant moved, a read-back, and a recorded rollback value. |
| Credentials | Form, `ZSCALER_*` environment, `local_settings.bat`, or a saved profile (secrets only when *remember* is ticked, and only in the OS credential store; without a usable one the secret is not remembered and the save says so, unless the operator explicitly allows the owner-only profile file with `DLP_CHECK_SECRET_STORE=file`). Two sign-ins: a ZIdentity API client (OneAPI) or the classic ZIA API (admin username, password, API key; the password and key are secrets like the client secret). Never returned by the API, masked in every error, redacted in the audit log, all files git-ignored. |
| Network | Web server and MCP server bind to 127.0.0.1 by default. CORS and origin checks allow localhost origins only. Security headers (CSP, frame-ancestors none, nosniff, no-referrer), a body-size cap and a rate limit are always on. The body-size cap is the outermost layer and counts streamed (chunked) bodies as they arrive, so no other layer (the audit log included) holds more than the cap; a refused body is recorded as `request_too_large` without its content. The rate limit runs ahead of the UI token check, so a flood of unauthenticated calls cannot fill and rotate away the audit log. Update, pack upload and pack rewrite are refused unless bound to localhost. |
| Outbound calls | Only the Zscaler API for the tenant, GitHub for the app update (git pull and, for the cross-check above, the GitHub REST API), Zscaler and integration-partner documentation hosts on an allowlist for the update check, the best-practice library and the SaaS capability matrix, and, only when you configure them, your SMTP relay and an https Teams or Slack webhook for the digest. Allowlisted fetches are https only and check every redirect hop against the allowlist; the digest webhook's redirects are not followed; the vanity domain must be a DNS name, so the client secret only goes to the cloud's Zscaler sign-in host. The upstream contract check (`upstream_check.py`, run daily in GitHub Actions, never by the server) additionally reads PyPI, the Terraform registry, raw.githubusercontent.com and automate.zscaler.com through the same allowlist. No AI or LLM service is called by the app. |
| Continuous evaluation | Runs read-only only when someone runs it (Run the loop now, `continuous_eval.py --once`, or a scheduled task you create); the server's timer is off unless `DLP_CHECK_CONTINUOUS_EVAL_HOURS` is set above 0. Each tenant profile is read only for what its Scope page puts in scope (nothing when no scope is saved): FP/TP Detection Ratio and the ticked packs' drift on the in-scope DLP channels when DLP is in scope, SaaS tenant status when SaaS Security runs on Zscaler, plus guidance mapping. It raises proposals; a person decides them; applying goes through the deploy path. Digests hold counts, titles and rule names, never credentials; the SMTP password and webhook URL stay in `local_settings.bat` (git-ignored) and are never returned by the API. The manual FP/TP Detection Ratio, the live feed and the Data Flow Map read only what the Scope page (else the chosen profile) puts in scope, and refuse before signing in when nothing they read is. |
| Inputs | Cloud, vanity domain, credentials and customer id are validated before any client is built; pack ids resolve against the discovered pack list; report ids are random tokens; dictionary patterns are bounded to ZIA's limits. |
| Uploaded logs (Log Analyzer) | Client Connector log bundles and PAC files are analysed in memory on the local server and discarded: nothing is written to disk and nothing leaves the machine. Archives are opened with caps (600 members, 48 MB per member, 160 MB in total, one level of nesting), member names are never used as paths, binary members are skipped, and the whole request is under the body-size cap. Evidence lines shown back have passwords, tokens, cookies and JWTs blanked out; the audit log records the call without the file contents. The page renders every value through one HTML escaper. |
| Code | Python 3.11, no `eval`/`exec`/`pickle`/`shell=True`, no SQL, one HTML escaper at every render site. Tests, `py_compile`, `node --check` and Terraform validation run in CI on every push. See `docs/VULNERABILITY_CLASSES.md` for the fuller picture of which classes of vulnerability this designs out, and which remain. |

## SSO: who may sign in and who may write

SSO is off by default; turn it on with ZSCALER_SSO_ENABLED=1 plus the
ZSCALER_SSO_* settings. Nothing below applies without it: a default
install, local or in the container on its default loopback publish, uses
the UI token exactly as before. SSO becomes necessary only when the
container is deliberately published beyond loopback (`DLP_CHECK_HOST_BIND`).

| Setting | Meaning |
|---|---|
| `ZSCALER_SSO_IDLE_MINUTES` | Minutes a session may sit unused before it ends (default 30). Every session ends after 12 hours regardless. |
| `ZSCALER_SSO_ALLOWED_GROUPS` | Comma-separated group names or ids. When set, a person in none of them is refused at sign-in, and the refusal is written to `audit.log`. Unset: anyone your identity provider signs in for this app. |
| `ZSCALER_SSO_WRITERS` | Comma-separated groups or email addresses. An email address matches only when the ID token marks it verified (`email_verified` true); an unverified email, which many providers let the user set, never makes anyone a writer, so list group ids for providers that do not send `email_verified` (Microsoft Entra ID). When set, only matching people may turn on write mode or change the tenant (deploy, removal, import, undo, remediation, Evaluate All Rules changes, proposal apply and rollback). Everyone else gets 403 with the reason and can still assess, read and preview. Unset: every signed-in person may, as before. |
| `ZSCALER_SSO_GROUPS_CLAIM` | The ID token claim that lists the person's groups (default `groups`). |

Sessions are kept in the server's memory: **restarting the app signs
everyone out**, and each person signs in again. A sign-in completes only in
the browser that started it (a short-lived HttpOnly cookie binds the
sign-in's state to it), so a callback link replayed in another browser is refused.

**Getting the identity provider to send groups.** The group settings
match against a claim in the ID token, so the provider must put it there:

- **Microsoft Entra ID:** in the app registration, *Token configuration* >
  *Add groups claim*, pick *Security groups* (or *Groups assigned to the
  application*) and tick it for the **ID** token. Entra sends group
  object ids, not names, so list those ids in the settings above.
- **Okta:** on the app's *Sign On* tab, set a *Groups claim* named
  `groups` with a filter (for example *Matches regex* `.*`, or *Starts with*
  `dlp-`). With a custom authorization server, add a `groups` claim to the
  ID token there instead.
- **Keycloak:** add a *Group Membership* mapper to the client (token claim
  name `groups`, *Add to ID token* on, *Full group path* off).
- **Google Workspace:** Google's OpenID Connect ID token carries no groups
  claim, so use `ZSCALER_SSO_WRITERS` with email addresses, or a provider
  that does send groups.
- **Other providers:** any claim holding a list of strings works; name it in
  `ZSCALER_SSO_GROUPS_CLAIM` if it is not called `groups`.

A person whose token has no groups claim is refused when
`ZSCALER_SSO_ALLOWED_GROUPS` is set (the page says the claim is missing),
and counts as a writer only by email address.

Scripts that called the API with the UI token (header or Bearer) stop
working once SSO is on: the token is refused. Run them against a local
install without SSO, or sign in through the browser.

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
  a second factor and terminates TLS. The container publishing beyond
  loopback (`DLP_CHECK_HOST_BIND`) needs SSO; that override does not apply.
- SSO sessions are held in memory: a restart of the app signs everyone
  out. There are two roles only (writer or not, from
  `ZSCALER_SSO_WRITERS`); anyone allowed to sign in can read every
  assessment and preview the app holds.
- A remembered profile secret goes to the operating system's credential
  store (Windows Credential Manager, macOS Keychain) through the `keyring`
  package. It is a pinned dependency on Windows and macOS: the installers
  install it, hash-verified, from `requirements.lock` with the rest of the
  app, and it is in the SBOM, so no separate or unpinned install is needed.
  On Linux and in the container it is not installed (there is no Secret
  Service there), and if the store refuses a secret the result is the
  same: the secret is not remembered and the save says so.
  `DLP_CHECK_SECRET_STORE=file` keeps it in the owner-only profile file
  instead, an explicit choice; there is no silent plaintext fallback. On
  Windows "owner-only" is a POSIX mode bit, not an ACL. Prefer
  `local_settings.bat` or the form on a shared laptop.
- The updater fast-forwards `main` over HTTPS and cross-checks the
  commit it pulled against GitHub's REST API (a channel separate from
  the git pull). The repository is private, so that cross-check needs a
  read-only `DLP_CHECK_GITHUB_TOKEN`; without one (or offline, or from a
  fork or mirror) it cannot run, and the update shows a "Verify against
  GitHub: skipped" warning with the reason instead of claiming it was
  verified. It does not verify GPG or Sigstore signatures on
  commits or tags — `main` carries no signed tags. A compromise of
  GitHub itself, or of the maintainer's account, would defeat both
  checks. Update over a trusted network; do not set
  `ZSCALER_UPDATE_VERIFY_TLS=0` except behind a corporate TLS-inspection
  proxy whose root you trust.
- The page's Content-Security-Policy still allows inline scripts, because
  the GUI ships its script inline; a stored XSS in tenant-supplied text is
  mitigated by escaping at every render site, not by CSP. See
  `docs/VULNERABILITY_CLASSES.md`.
