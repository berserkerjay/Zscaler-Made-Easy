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
**Update app** button (or `UPDATE_Zscaler_Made_Easy.bat`) fast-forwards
to by default. The button's **Branch** choice (or
`UPDATE_Zscaler_Made_Easy.bat dev`, `python app_update.py --branch dev`)
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
| Standalone edition | `standalone_main.py`, built per platform by `.github/workflows/release-standalone.yml` with a hash-pinned PyInstaller. Always loopback (`ZSCALER_BIND_HOST` ignored), always the UI token (`ZSCALER_UI_AUTH=0` ignored), a new random token every start (`ZSCALER_UI_TOKEN` ignored), read-only at every start (`ENABLE_WRITE_ACTIONS` ignored: write mode is the in-app switch); everything it writes goes to the owner-only per-user data folder. The bundle holds only files git tracks (a tracked secret or state file stops the build). Each archive is smoke-tested as shipped and checksummed, and given signed SLSA build provenance (`gh attestation verify`) when the repository can have it (public, or the variable `STANDALONE_PROVENANCE` set on Enterprise Cloud); the release job then verifies both before publishing, and otherwise checks the checksums and the release notes say there is no provenance. Code signing runs only when the signing secrets exist; otherwise the release notes say the build is unsigned. It never updates or restarts itself, and it never runs code passed on its command line. Binaries are never committed. |
| Writes to a tenant | Refused unless write mode is enabled for the session (typed phrase, localhost only) or the server is started with `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND`. Under SSO with `ZSCALER_SSO_WRITERS` set, only the listed groups and email addresses may do either, or deploy, remove, import, undo, apply or roll back; everyone else gets 403 and can still assess, read and preview. Every route that changes a tenant (deploy, import, removal, undo, proposal apply and rollback, change queue apply, heal, bulk changes, remediation, the Evaluate All Rules steps) also needs the explicit confirmation (`confirm=true`, or its typed phrase) and the assessor's name, and all four gates are checked before the tenant is signed in to (`tests/test_write_safety_gates.py` holds every POST, PUT and DELETE route to this). Deploys require an approved plan hash; every rule ships DISABLED and monitor-only; nothing is activated; every deployment is recorded for undo. Applying an approved FP/TP Detection Ratio proposal goes through the same gate with an explicit confirmation, a re-read that refuses when the tenant moved, a read-back, and a recorded rollback value; its rollback runs only while the rule still holds the value the apply set. Typed phrases compare case-insensitively, one character for one, with deliberately no NFKC or other compatibility folding: a look-alike (dotless i, long s, full-width letters or digits) never confirms, and a blank phrase never matches (`security.typed_phrase_matches`). One write run per tenant at a time: a second deploy, removal or bulk change started while one is writing is refused as busy, with nothing read or written. A create answered by a timeout or a 502/504 is sent again only after a read by name shows it is not there. An Undo is applied only as the recorded inverse of its operation, once. The migration wizard's delete-all and post write only what their dry run showed (its plan hash). The older writes and deletes carry the same gates (wave 9): a fix from the assessment (`/api/remediation/execute`) and Evaluate All Rules (`/api/migrate/enable`) need the plan hash of their preview or dry run, and the enable writes only the one field its read-only probe found; a pack removal needs `DELETE n OBJECTS` and the wizard's delete-all `DELETE n RULES`, the number checked on the server against a fresh read. A Client Connector one-time password, a sensitive read, needs write mode on as well as ZCC in scope, a writer, the assessor and `SHOW OTP <device>`. (`tests/test_sbd_writes.py`, `tests/test_security_gates.py`, `tests/test_zcc_otp.py`) |
| Credentials | Form, `ZSCALER_*` environment, `local_settings.bat`, or a saved profile (secrets only when *remember* is ticked, and only in the OS credential store; without a usable one the secret is not remembered and the save says so, unless the operator explicitly allows the owner-only profile file with `DLP_CHECK_SECRET_STORE=file`). Two sign-ins: a ZIdentity API client (OneAPI) or the classic ZIA API (admin username, password, API key; the password and key are secrets like the client secret). Never returned by the API, masked in every error, redacted in the audit log, all files git-ignored. |
| Network | Web server and MCP server bind to 127.0.0.1 by default. CORS and origin checks allow localhost origins only. Security headers (CSP, frame-ancestors none, nosniff, no-referrer), a body-size cap and a rate limit are always on. The body-size cap is the outermost layer and counts streamed (chunked) bodies as they arrive, so no other layer (the audit log included) holds more than the cap; a refused body is recorded as `request_too_large` without its content. The rate limit runs ahead of the UI token check, so a flood of unauthenticated calls cannot fill and rotate away the audit log. Update, pack upload and pack rewrite are refused unless bound to localhost. |
| Outbound calls | Only the Zscaler API for the tenant, GitHub for the app update (git pull and, for the cross-check above, the GitHub REST API), Zscaler and integration-partner documentation hosts on an allowlist for the update check, the best-practice library and the SaaS capability matrix, and, only when you configure them, your SMTP relay, an https Teams or Slack webhook for the digest (also used, when switched on in Advanced settings, for one notice per new app version), `https://endpoints.office.com` (Microsoft's published Microsoft 365 endpoint list, for app service groups such as the Office 365 One Click rule's: off by default, turned on in Advanced settings; GET only, that host only, no redirect followed, a 10-second timeout, at most 2 MB, schema-checked and kept with its version and date; a random request id and nothing about the tenant is sent; the file can be imported by hand instead), and `https://config.zscaler.com` (Zscaler's published IP ranges and host names for firewall allowlists, on Policy exports: off by default, and even when turned on only fetched when you click Fetch now; GET only, that host only, no redirect followed, a 10-second timeout, at most 4 MB a feed, schema-checked with private, reserved and over-broad ranges and host names outside Zscaler's domains dropped, and kept with its date; nothing about the tenant is sent; each feed can be imported by hand instead). Only with `ZSCALER_TLS=acme` (off by default): the ACME directory's host (acme-v02.api.letsencrypt.org by default) and api.cloudflare.com, for a Let's Encrypt certificate through dns-01. Allowlisted fetches are https only and check every redirect hop against the allowlist; the digest webhook's redirects are not followed; the vanity domain must be a DNS name, so the client secret only goes to the cloud's Zscaler sign-in host. The upstream contract check (`upstream_check.py`, run daily in GitHub Actions, never by the server) additionally reads PyPI, the Terraform registry, raw.githubusercontent.com and automate.zscaler.com through the same allowlist. No AI or LLM service is called by the app. The Path analyzer's *Test from here* is the one exception, and only on an explicit click: it opens a TCP connection (and a TLS handshake) from this computer to the one destination being analyzed; see *Test from here: threat model* below. |
| Continuous evaluation | Runs read-only only when someone runs it (Run the loop now, `continuous_eval.py --once`, or a scheduled task you create); the server's timer is off unless `DLP_CHECK_CONTINUOUS_EVAL_HOURS` is set above 0. Each tenant profile is read only for what its Scope page puts in scope (nothing when no scope is saved): FP/TP Detection Ratio and the ticked packs' drift on the in-scope DLP channels when DLP is in scope, SaaS tenant status when SaaS Security runs on Zscaler, plus guidance mapping. It raises proposals; a person decides them; applying goes through the deploy path. Digests hold counts, titles and rule names, never credentials; the SMTP password and webhook URL stay in `local_settings.bat` (git-ignored) and are never returned by the API. The manual FP/TP Detection Ratio, the live feed and the Data Flow Map read only what the Scope page (else the chosen profile) puts in scope, and refuse before signing in when nothing they read is. |
| Inputs | Cloud, vanity domain, credentials and customer id are validated before any client is built; pack ids resolve against the discovered pack list; report ids are random tokens; dictionary patterns are bounded to ZIA's limits. Parsers of uploaded or typed text are bounded so no single request can pin the server: every pattern on user or tenant text runs in time linear in its length (log lines are read up to 4,096 characters, typed dates up to 64), nesting is capped (JSON bodies past the decoder's depth are a 400; Terraform, engine expressions and migration exports refuse nesting past 40 to 64 levels in words), a ZIP member that lies about its size fails its check instead of inflating, uploads and report exports are parsed off the event loop, pack engine expressions are read up to 16,384 characters, a Word report holds at most 1,000 checks and other posted reports 5,000. Analyses of large tenants (shadowed rules, ZPA, device posture, the rule migrator) compare only the pairs that can matter and cap how many pairs they list; finished jobs (200), change-request comment history and the workspace notes store (8 MB) are bounded. |
| Uploaded logs (Log Analyzer) | Client Connector log bundles and PAC files are analysed in memory on the local server and discarded: nothing is written to disk and nothing leaves the machine. Archives are opened with caps (600 members, 48 MB per member, 160 MB in total, one level of nesting; ZIP members only stored or deflate, read in bounded steps; a compressed tar read as one stream that stops at the total cap; each log line read to 4,096 characters), member names are never used as paths, binary members are skipped, and the whole request is under the body-size cap. Pack and migration uploads take ZIP members the same way, and refuse DTDs in an XML export in any encoding. Evidence lines shown back have passwords, tokens, cookies and JWTs blanked out; the audit log records the call without the file contents. The page renders every value through one HTML escaper. |
| Code | Python 3.11, no `eval`/`exec`/`pickle`/`shell=True`, no SQL, one HTML escaper at every render site. Tests, `py_compile`, `node --check` and Terraform validation run in CI on every push. See `docs/VULNERABILITY_CLASSES.md` for the fuller picture of which classes of vulnerability this designs out, and which remain. |
| Static analysis (SAST) | Two analysers. **bandit** (hash-pinned in `requirements-dev.lock`) checks the app's Python offline: `make sast` locally, and `tests/test_sast.py` in every test run, CI included, so a pull request with a new finding fails. Every bandit check runs (no skips; only `tests/` and local environments are left out, `pyproject.toml` `[tool.bandit]`) and any finding of medium severity or higher fails. A finding is fixed at the root, or, when bandit misreads the code, suppressed on its own line as `# nosec <id> # <why>`; the test holds the reviewed list of those (seven today: an address compared, never bound; XML parsed only after a DOCTYPE/ENTITY refusal; the standalone smoke test's own loopback requests and zip extraction) and fails on an unlisted, unexplained or stale one. Low-severity findings do not fail it (`python -m bandit -c pyproject.toml -r .` lists them; `docs/qa/findings/w7-sast.json` records how each kind was triaged). **CodeQL** (`.github/workflows/codeql.yml`) runs GitHub's security-extended queries over the Python and JavaScript/TypeScript (the web UI and the browser extension) on every pull request to `dev`, `qa` and `main` that changes code, and weekly; results go to the repository's Security tab. One Linux job, read-only token except `security-events: write` on that job, actions pinned by commit SHA, a newer push cancels the running scan, 20-minute limit. Code scanning needs GitHub Advanced Security (Code Security) on a private repository. |

## Test from here: threat model

The Path analyzer predicts from configuration. *Test from here* (`path_probe.py`, `POST /api/path-analyzer/test-from-here`) observes one destination from the computer running the app (in the Docker container, the container's network) and compares that with the prediction. Because it makes the server connect to an address a viewer chose, it is treated as a server-side request forgery (SSRF) risk and bounded as follows; `tests/test_path_probe.py` holds it to each point, against loopback test servers only.

| Threat | Control |
|---|---|
| Someone who is not a viewer triggers it | The UI token or an SSO session, and the origin/CSRF check, as on every route; and the body must carry `confirm=true`, which the page sends only from the *Test from here* button. An install can turn it off: `ZSCALER_TEST_FROM_HERE=0` (403). |
| Reaching the app itself, the computer or cloud metadata | The first resolved address is the only one connected to (pinned: no second lookup, so no DNS rebinding between the check and the connection). Refused before any packet: loopback (this computer, the app), link-local (169.254.0.0/16 and fe80::/10, where cloud metadata such as 169.254.169.254 lives), multicast, unspecified (0.0.0.0, ::) and reserved addresses, IPv4-mapped forms included. Private addresses (RFC 1918, and 100.64.0.0/10, where ZPA synthetic addresses live) are allowed on purpose: internal apps behind ZPA are what the analyzer is about. |
| Port scanning the networks the server sits on | Ports on an allow-list only: 443, 80, 8443, 8080. A port the user typed (in the Port field or the URL) is used only when it is on the list; any other port, even a valid 1-65535 one, is refused. Allowing every typed port would make the button a one-port-per-click scanner of networks that remote viewers (container or SSO deployments) could not otherwise reach; the four ports are what the comparison needs (is TLS inspected, does the name resolve to a ZPA address). One destination per request. |
| Sending data or credentials somewhere, being redirected | Only a TCP connect and, on a TLS port, a TLS ClientHello with the host name (SNI). Never an HTTP request, a body, a cookie, a credential or a client certificate, so there is nothing to redirect and no redirect is followed. Port 80 (or `http://`) is a bare connect. The connection closes right after the handshake. |
| Tying up the server | DNS 3 s, connect 3 s, each TLS handshake 4 s (at most two: one to read the certificate, one to learn whether this computer trusts it); the certificate is read up to 64 KB. At most 6 tests a minute and one at a time for the whole server (429 otherwise). |
| One viewer seeing another's result | Nothing is kept: the answer goes to the viewer who asked, with `Cache-Control: no-store`; it is not cached on the server, in the browser's storage or on disk. The audit log records the call (who, the destination and port) like every other POST. |
| Mistaking the observation for the user's device | Every result says it was observed "from the computer running this app" (or "from inside this app's Docker container"), not from the device the analysis is about. A Zscaler inspection certificate is recognised by its issuer's name only (a tenant's own custom CA shows as "not Zscaler's name"). |

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

## Local plugins: what they cost

Local plugins (`local_plugins.py`) are **off by default** and stay off
unless `DLP_CHECK_PLUGINS_DIR` names a folder **and** an admin switches
them on in Advanced settings **and** approves each plugin's exact SHA-256
there. Say yes to a plugin only if you would also be happy to edit the
app's own code with it, because that is what it amounts to:

- **A plugin is Python code that runs inside the app's process, with the
  app's privileges.** It can read whatever the app can read on this
  computer: tenant profiles and any secret they remember, the audit log,
  the UI token, files the app's user can open, and the network. The app
  does not and cannot sandbox it.
- **The narrow API is a contract, not a wall.** The objects the app hands
  a plugin are restricted: its planner and object reader get a read-only
  client (only `list`/`get`/`search`/`lookup`/`read` calls, no private
  attributes), its write handlers run only inside an apply the engine
  started (after the Scope rule, write mode, a writer, the named
  assessor, the typed confirmation and the plan hash) and write only
  through the audited pack_ops calls; its pages are shown as text. But
  Python code can import any module, so a plugin written to get around
  these limits can. The protection is the review and the hash.
- **The hash is the control.** Approval is for one SHA-256 over every file
  of the plugin folder (names and content). A plugin that is not on the
  allow-list, or whose files changed after approval, is refused and never
  imported. The files are read once, hashed, and the same bytes are run
  from memory, so a file swapped after the check is not the one that
  runs. Only plain `.py`, `.json`, `.md` and `.txt` files directly in the
  folder are accepted (no sub-folders, no links). Approving, switching
  plugins on and revoking are for a writer, from the computer the app
  runs on, and are written to the audit log; revoking unloads at once.
- **Nothing is installed or downloaded.** There is no plugin store, no
  `pip install` and no network fetch: a plugin is a folder you put there.
- An approval can name the people (sign-in names) allowed to use the
  plugin; anyone else gets 403 on its operations and pages.

An example plugin is in `docs/plugins/example_rule_counter/`; it is not in
any plugin folder and is never loaded unless you copy it there and
approve it.

## Untrusted XML (the PAN-OS migration)

A Palo Alto Networks configuration export is parsed with `defusedxml`
(hash-pinned in `requirements.lock`) with DTDs, entity declarations and
external references refused, after a size cap (8 MiB) and with depth (48)
and element-count (250,000) caps. Every value that becomes a Zscaler name
is checked again when the plan is previewed on Bulk changes.

## Excel workbooks and the syslog listener (wave 9)

- **Excel workbooks** (Remove devices from a list): read by `xlsx_reader.py` as untrusted archives: at most 8 MB, at most 2,000 members whose declared sizes add up to at most 96 MB, no member expanding more than 200 times its compressed size, stored or deflate only and never encrypted, each opened part size-capped; XML through defusedxml with DTDs, entities and external references refused; the first sheet only, streamed (an iterative parse, each row dropped once read); a sheet with more than 20,000 rows, more than 250,000 filled cells, a value past column 64 or more than 250,000 shared strings is refused, never read in part; each value at most 512 characters; formulas are never evaluated (a cached value or nothing).
- **Syslog listener** (Traffic and session logs): the one inbound listener besides the app itself. Off by default and never started on its own; a writer starts it on an interface and high port they choose (other computers only when they say so), it is rate-limited and size-capped, keeps lines in memory only (never on disk unless a report is saved, counts only by default), and every start, stop and clear is audited with the actor.
- **Domain user names** (Client Connector): the one download that lists people by design; it needs an explicit personal-data tick checked on the server, and the audit log records the count, never a name.

## Team server (optional; off by default)

`ZSCALER_TEAM_MODE=1` turns the app into a multi-user team server
(`team_server.py`). Off, nothing in this section runs: the app is the
single-person app bound to this computer with its UI token, as above.

**What it adds.** Local accounts (passwords hashed with scrypt from the
Python standard library, N=2^15, r=8, p=1, a 16-byte salt; PBKDF2-HMAC-SHA256
with 600,000 iterations in FIPS mode), roles (viewer: read; operator: read,
plan, apply; approver: read, approve; administrator: everything and the
server itself) and grants of read, plan, apply and approve per tenant profile
to a user or a SCIM group (or `*` for every profile). What a person may do on
a profile is their role's actions AND what is granted there: deny by default.
Sign-in with a password, through the existing OpenID Connect SSO (`sso.py`),
matched to an account by subject or a verified email, through SAML 2.0
(`sso_saml.py`), or with a passkey (`team_passkeys.py`); both described below.

**Enforcement.** Every route has an access rule in `team_routes.py`
(public, session, read, plan, apply, approve, admin, scim). The access
middleware refuses a route with no rule (403, audited), checks the role, the
tenant profile the request names (path, query or JSON body `profile_id`) and
every stored record it names (reports, jobs, saved plans, change requests,
deployments, operations, snapshots, proposal queues: owned by their maker or
reached through the same right on their tenant profile; unknown is "not
found"). Where the tenant credentials are resolved, the request must name a
profile the person holds the route's action on, and typed sign-in details
naming another tenant are refused, never used. `tests/test_team_server.py`
enumerates every registered route and fails on one with no rule.

**Sign-in and sessions.** Five wrong passwords lock an account for 15
minutes (`ZSCALER_TEAM_LOCKOUT_ATTEMPTS`, `ZSCALER_TEAM_LOCKOUT_MINUTES`); a
locked account is refused even with the right password until the lock runs
out or an administrator unlocks it. A name with no account answers and locks
exactly like a wrong password, after the same hashing work. Sign-in attempts
are limited per address (20 in 5 minutes, then 429). Every sign-in makes a
new session id and ends the browser's earlier one. The cookie holds only that
id: HttpOnly, SameSite=Strict, Secure over HTTPS. A session ends after 15
quiet minutes (`ZSCALER_TEAM_IDLE_MINUTES`) and after 8 hours whatever happens
(`ZSCALER_TEAM_SESSION_HOURS`, at most 12); every page warns two minutes
before the idle sign-out ("Still there?") and five minutes before the
absolute end. A role change, a password change or a disabled account ends
that person's sessions at once. An account an administrator creates with a
password, or whose password an administrator resets (Team server page or
`team_server.py` on the command line), must choose its own password at its
next sign-in: until then every route but the change itself, who am I and
sign-out answers 403 (`must_change_password`). The UI token is refused in every form. The
origin and CSRF checks stay; in addition a change that carries the session
cookie must carry an `Origin` (or `Referer`) of this server.

**SCIM 2.0** (`/api/scim/v2/Users`, `/Groups`, team mode only): a bearer
token an administrator makes on the Team server page, shown once, stored as
its SHA-256 (a 256-bit random value, so a fast hash is the right one), and
revocable. SCIM never makes, demotes or removes an administrator.

**HTTPS.** `ZSCALER_TLS_CERT` and `ZSCALER_TLS_KEY`, or
`ZSCALER_TLS=self-signed` (ECDSA P-256, made on the first start with the
pinned `cryptography` package; its SHA-256 fingerprint is printed at every
start), or `ZSCALER_TLS=acme` for Let's Encrypt through the dns-01 challenge
on Cloudflare (`server_acme.py`; the Cloudflare API token is kept in the OS
credential store, or with `DLP_CHECK_SECRET_STORE=file` in an owner-only
file). While the server runs, a daily check (`ZSCALER_ACME_CHECK_HOURS`, 1 to 168)
renews an ACME certificate with fewer than 30 days left and loads it into
the running TLS context (uvicorn's `ssl_context_factory`), or says a restart
is needed; a failed renewal keeps the current certificate and is audited.
`ZSCALER_TLS_REDIRECT_PORT` adds a plain-HTTP port that only answers a
308 to HTTPS. A team server answering over HTTPS sends HSTS (one year).
**A team server reachable beyond this computer refuses to start without
HTTPS.** Without team mode, the older ways beyond loopback (SSO, or a reverse
proxy with `ZSCALER_ALLOW_NONLOCAL_BIND`) still start, with a loud warning on
stderr that team mode with HTTPS is the supported way.

**Audit and four-eyes.** Every audit entry names its actor (the account's
user name; a background job's entries name the person who started it) and,
on a team server, the tenant profile the request named. Only an
administrator sees entries that name no profile; anyone else sees only the
entries of profiles they may read. Four-eyes cannot be turned off on a team
server: the approver must be another signed-in person than the requester,
with approve on that request's tenant profile.

**Kept records of a tenant** (configuration backups and their templates,
saved traffic log reports, Client Connector fleet history, tenant health
answers) name the tenant profile they were made for and the account that
kept them: lists show only those of profiles the person may read, and every
route that names one (`backup_id`, `template_id`, `saved_name`, a diff side,
a restore or clone source) checks that access; a record of no profile is
its maker's only. A configuration template is deleted only by the person
who kept it or an administrator.

**Templates and saved plans** belong to the person who saved them. Their
owner (or an administrator) shares them with users and groups; a shared plan
still opens only for people who may read its tenant profile.

**Encryption at rest** (`DLP_CHECK_STORE_ENCRYPTION=1`, any mode;
`store_crypto.py`): tenant profiles, snapshots, the change queue, proposals,
deployment and operation records, workspace notes, POVs and templates, the
team accounts, the audit log, configuration backups with their list,
templates and caches, scheduled sync jobs, the Client Connector fleet
history, the SSL coverage history and saved traffic log reports are sealed
with AES-256-GCM. A sealed store whose key is not here is an error, never
read as empty (so a save never overwrites it). The key is kept
in the OS credential store, or in an owner-only key file
(`store_keys.json`, 0600). `python store_crypto.py rotate` (or the Team
server page's administrator) makes a new key, re-seals every store with it
and only then forgets the old one. Turning the setting off never locks data
away: sealed stores still read while their key is there.

**FIPS mode** (`DLP_CHECK_FIPS_MODE=1`) restricts the app's own choices to
FIPS-approved algorithms: PBKDF2-HMAC-SHA256 passwords (an earlier scrypt
hash is refused until an administrator sets the password again), AES-256-GCM
stores, RSA/RSA-PSS/ECDSA ID tokens (no EdDSA), ECDHE/DHE with AES-GCM for
TLS 1.2, ECDSA P-256 certificates, SHA-256 tokens. **It does not make the app
FIPS 140-3 validated**: the Python interpreter and the OpenSSL and
`cryptography` builds it runs on are not a validated module unless your
platform provides one and runs in FIPS mode (for example FIPS-enabled RHEL
with its validated OpenSSL). The TLS 1.3 cipher suites are the platform
OpenSSL's choice.

**SAML 2.0 sign-in** (`sso_saml.py`; team servers only, off until an
administrator turns it on in the Sign-in section of the Team server page, or
`ZSCALER_SAML_ENABLED` sets it, in which case the page shows it read-only and
nothing is mixed). SP-initiated: HTTP-Redirect out, HTTP-POST back to
`/api/auth/saml/acs`. The XML signature is checked by signxml (pure Python
on lxml and cryptography; hash-pinned in `requirements.lock`): it must be
over the assertion itself (a response signature, if present, must verify
too), made with the configured certificate (two during a rotation), RSA or
ECDSA with SHA-256 or stronger; only the bytes the signature covers are read,
and exactly one assertion directly in the response is accepted (signature
wrapping, CWE-347). Issuer, audience, bearer recipient, InResponseTo of a
request this server sent, NotBefore/NotOnOrAfter (60 seconds of skew), status,
destination (required when the response is signed) and the RelayState of the
sign-in this server started are checked; each request and assertion ID is
used once (a replay is refused). Starting a sign-in is limited per address.
The account is the one linked to the identity provider's NameID, else the
one whose user name or email is the asserted email, but **an administrator
account is never linked by its email alone**: an administrator first clicks
**Allow SAML link** on that account (Team server page), and only its next
SAML sign-in within 15 minutes links it; otherwise the sign-in is refused and
audited (`team_saml_link_refused`). Other accounts are linked by email on
their first SAML sign-in. Audit entries carry reasons and names, never the
SAML response, assertion or passkey credential bytes. The parser loads no DTD, expands no entity and reaches no
network, with size caps. The verified sign-in finishes only in the browser
that started it (`/api/auth/saml/finish`, login CSRF), and a locked account is
refused. The ACS is the one change exempt from the Origin check (the
identity provider's page posts it); it signs nobody in by itself, and refused
responses count towards the address's sign-in limit. The identity provider's
metadata uploaded on the page is untrusted: at most 256 KB, refused with a
DTD or entity, nothing fetched; its own signature is not checked (the
administrator downloads it from their identity provider's console). IdP
values are shown with `textContent`. **Test** checks the settings locally and
calls nothing outside. Encrypted assertions and single logout are not
supported.

**Passkeys** (`team_passkeys.py`; on when `ZSCALER_TEAM_PASSKEY_ORIGIN` names
the server's address). WebAuthn ceremonies verified by py_webauthn: a random
challenge used once within five minutes, the exact configured origin and RP
ID (never the Host header), user verification, the signature and the
signature counter (one that does not go up is refused and audited). Only the
credential ID, public key, counter, name and dates are stored. Adding a
passkey needs the current password (an account with no password needs a
sign-in less than 5 minutes old). Once an account has a passkey, a right
password alone gets no session: the account's own passkey must answer a
challenge bound to that account. If passkeys are then not set up on the
server (`ZSCALER_TEAM_PASSKEY_ORIGIN` removed), such an account's password
sign-in fails closed (503, audited) and names the fix, never a password-only
session. Starting a passkey sign-in is limited per address. An administrator can **require** a passkey
after the password (refused while passkeys are not set up); an account
without one then adds one right after its password, before any session. A
passkey that fails counts towards the account's lockout. If the passkey
origin is later removed while passkeys are required, password sign-in fails
closed (503) and names the fix: `python team_server.py require-passkey off`;
`python team_server.py remove-passkeys <user>` clears a lost device.

### Threat model

| Threat | What stops it |
|---|---|
| Someone on the network signs in as another person | Per-person accounts; scrypt (or PBKDF2) hashes; lockout enforced (failed passkeys count too); per-address sign-in limit (refused SAML responses count too); same answer and timing for unknown names; OIDC sign-in only through a linked subject or a verified email; SAML only with a signed, unexpired, unreplayed assertion for this server; a passkey after the password, required if the administrator says so |
| A stolen or fixated session cookie | Random 256-bit ids kept server-side; a new id at every sign-in; HttpOnly, SameSite=Strict, Secure over HTTPS; idle and absolute timeouts; HSTS |
| Passwords or cookies read on the wire | HTTPS required beyond loopback; refusal to start otherwise; HTTP only redirects |
| Cross-site request forgery, DNS rebinding | SameSite=Strict; the origin check; a cookie-bearing change must carry this server's Origin |
| A person reaches a tenant they were not given (horizontal) | A rule on every route; the profile checked in the middleware and again where credentials are resolved; typed details of another tenant refused; reports, jobs, plans and records bound to their profile; lists filtered |
| A viewer or approver changes a tenant (vertical) | Roles cap every grant; apply needs the apply right on that profile, plus write mode, the assessor's name and the typed confirmation as always |
| One person deploys a change alone | Four-eyes always on: approver is another person with approve on that profile |
| A provisioning credential leaks | The SCIM token is stored hashed, shown once, revocable, and cannot make administrators |
| The audit log hides who did what, or leaks other tenants | Every entry has an actor and its profile; reads are filtered per profile |
| The data folder is copied | Optional AES-256-GCM sealing of every store with the key outside the folder (credential store) or owner-only; rotation |
| An administrator account is the weak point | It is the root of trust: protect it with a long password, keep few of them, and prefer SSO with your provider's MFA. The app cannot protect against a malicious administrator or the operating-system account that runs it. |

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
