# What DLP-Check does — an overview

This page is for someone who has just been handed the app: what it is
for, what each part does, what it never does, and where it stops. It
takes five minutes to read. To install it, see [INSTALL.md](../INSTALL.md);
for a first engagement step by step, see
[GETTING_STARTED.md](../GETTING_STARTED.md).

## In one paragraph

DLP-Check connects to a customer's Zscaler tenant with API credentials
and answers three questions. **Where is the tenant today?** It runs 300+
automated checks against the DLP assessment checklist and Zscaler's best
practices and gives a scored maturity report with plain findings and the
fix for each. **Where does inspection leak?** It reads the tenant's
Client Connector profiles, PAC, SSL inspection, URL filtering, app
control and DLP rules and draws the path traffic takes, naming every
bypass and blind spot. **How do we close the gaps?** It deploys
ready-made **policy packs** (dictionaries, engines and rules for CJIS,
Federal CUI, healthcare PHI, banking, enterprise best practice and source
code) through a plan → review → approve → deploy → verify flow, removes
them just as carefully, hands the same policy to a platform team as
Terraform, and migrates policy from another DLP vendor. Every rule a
policy pack creates arrives **disabled and monitor-only**, and a rule
migrated from another vendor arrives **disabled** with the action you
approved, so deploying never changes anything for the customer's users.

## Who it is for, and the shape of an engagement

It is written for a consultant or an IT engineer on their first week
with Zscaler DLP. A typical first engagement runs in this order, and the
app's toolbar is laid out the same way:

1. **Connect to the tenant and Authenticate** (sign-in details only; save
   a tenant profile so history is kept per customer).
2. **Scope and run the assessment** (which channels the customer owns,
   what to check, which frameworks to map to; about 90 seconds,
   read-only).
3. **Read the results, critical findings first**; export as Word or JSON.
4. **Show the customer where inspection is lost** with Traffic flow &
   gaps and SSL inspection flow.
5. **Map it to their framework** (Regulatory & compliance alignment).
6. **Close the gap with a policy pack**, preflight first (writes nothing).
7. On return visits, measure the **data-governance journey** and tune
   with the FP/TP detection ratio.

## Everything it can do, grouped as the in-app help page groups it

The toolbar on the home page has the same five groups. Most items below
are toolbar buttons with the same name; the few that are not say where
they are. Inside the app, **What does everything do?** (`/help`) gives
each one a full card: what it is, why the customer cares, when to use it,
what you get, what to do next.

### Start

- **The assessment page (home)** — the sidebar walks you through Connect
  to the tenant, Scope assessment and the Dashboard, which holds the
  score tiles, every finding and the exports.
- **Connect to the tenant (sign-in details, profiles, Authenticate)** —
  the customer's cloud, vanity domain, API client ID and secret, or the
  classic ZIA API sign-in (admin username, password, API key); tenant
  profiles save those details and the run history per customer.
  Authenticate only signs in (it reads nothing from the tenant) and
  answers "Signed in" or a plain reason why not.
- **Assessment results** — the full results in their own tab: Summary
  (score and maturity), Scores by section, Best practices and
  benchmarks, Regulatory alignment, the Data governance journey, and
  Detailed findings with a fix for each, in four plain sentences apiece.
- **What does everything do?** — every function explained in plain
  English, in first-engagement order, with a glossary.

### Find the gaps

- **Traffic flow & gaps** — the exact path a user's transaction takes
  (Client Connector app and forwarding profile, PAC, SSL inspection, URL
  filtering, Cloud App Control, file type control, DLP), with every point
  where inspection is lost, visibility by cloud-app category, and the
  path diagram per policy pack.
- **Path analyzer** — type a URL, hostname or IP address and see, live
  from the tenant as it is right now, the path a user's traffic takes to
  it, one verdict in plain words, and every rule or profile that blocks
  or impacts it, each with a fix. It reads only what is in scope on the
  Scope page (a part out of scope says "not in scope"), and Stop ends the
  read at once. **Import a HAR file** there to analyze every host a
  browser session reached in one run: the file is read in the browser and
  only host names and request counts are sent; the results table sorts,
  filters, opens any host's full analysis and exports as CSV or JSON.
- **Shadowed rules** — reads the rules of every policy in scope (Inline
  Web, Endpoint, Email and SaaS DLP, URL filtering, Cloud App Control, SSL
  inspection and, with ZIA platform ticked, Cloud Firewall) and lists the
  rules that can never match or never act: hidden below a broader rule or
  a catch-all, duplicated, superseded by a stricter rule (where every rule
  is evaluated), disabled, or naming engines and categories that no longer
  exist; each with the rule that hides it, the reason and the fix, and CSV
  and JSON exports. A criterion it cannot compare safely counts as "not
  shadowed". Read-only; Stop ends the read at once.
- **Flow animator** — the flows the app analyses, animated from your own
  results: the last Path analyzer result hop by hop; inside DLP, the
  dictionary match counts, each engine term against its threshold and the
  rules that act, with an engine that does not fire named as a near miss
  ("3 found, needs more than 4") or as having nothing to match; a policy
  pack plan or deployment with the deploy order replayed; DLP incidents
  as they land, enforced versus monitor-only per channel; and every flow
  of the Data Security Architect reference, with the steps people miss
  marked. Samples, labelled as such, until you have results. Read-only.
- **Browser extension (companion)** — a small Chrome and Edge extension
  for the app on your computer: its button or a right-click opens the Path
  analyzer with the site, a link or a selected hostname filled in, and the
  popup opens the Live DLP feed and the Flow animator. Switched on, it
  badges the ZIA admin console: DLP objects, the URL filtering, Cloud App
  Control, SSL inspection, Cloud Firewall and File Type Control rules, and
  the URL categories, locations, groups and other objects they use (usage
  counts, shadowed and unused findings), with a side panel. It holds no
  credentials or tenant data and talks only to 127.0.0.1. Download it from
  Advanced settings; see docs/BROWSER_EXTENSION.md.
- **Live DLP feed** — Workflow Automation's DLP incidents polled every
  15 seconds: who, what triggered, where it was going, enforced or
  monitor-only, with a running tally. Above the table, the DLP chain from
  the reference architecture, live: each channel that raised an incident
  carries bits through its rule and the evidence lane to Workflow
  Automation, its rule tagged enforce or monitor. It covers DLP incidents
  only, not the whole traffic log, and says so.
- **Traffic insights** — what the tenant's traffic actually did over a
  time window (up to 92 days), from ZIA Insights: web traffic allowed and
  blocked and by location, the cloud applications in use (Shadow IT), SaaS
  security by application, firewall traffic by action, and the users with
  the most security incidents (on screen only, never exported). Needs ZIA
  Insights ticked on the Scope page and a OneAPI API client. It says
  plainly what Insights cannot answer: traffic by URL category, per user,
  per policy rule or to one host.
- **Bypass & non-inspected traffic** — every SSL exemption, allow rule,
  Client Connector bypass and PAC exception that lets traffic skip
  inspection, with exports. Where: opened from Traffic flow & gaps.
- **SSL inspection flow** — for each risky traffic class, which SSL rule
  decides, whether the traffic is decrypted, and whether inline DLP can
  see it. Where: opened from Traffic flow & gaps.
- **DLP efficacy** — scores every custom dictionary and engine for
  false-positive risk and tests sample text against them.
- **FP/TP detection ratio** — what the DLP rules actually do in
  production, measured from Workflow Automation incidents and analyst
  verdicts, turned into proposals you approve, preview, apply with a
  read-back, and roll back.
- **Digest — the evaluation loop** — when you click *Run the loop now*
  (or run `continuous_eval.py --once`) it re-reads the guidance sources
  and, for every profile that remembers its secret, only what that
  profile's Scope page puts in scope (the FP/TP ratio and the ticked
  packs' drift when DLP is in scope, the SaaS tenants when SaaS Security
  runs on Zscaler), and writes a digest (e-mail or a Teams/Slack webhook
  when there is something to decide). Every tenant read counts against
  the ZIA API rate limit, so the timer is off unless the operator sets
  `DLP_CHECK_CONTINUOUS_EVAL_HOURS`. It never writes to a tenant.
- **Regulatory & compliance alignment** — the findings mapped to the
  frameworks the customer answers to (HIPAA, PCI DSS, NIST, CMMC, SOC 2,
  ISO 27001, GDPR, CIS, GLBA), scoped to the industry on the profile.
  Where: the Dashboard, under the findings.

### Close the gaps

- **Deploy policy packs** — pick a pack, run preflight (reads the tenant,
  writes nothing) to see exactly what would be created, kept or
  conflicts, review the plan and its flow diagram, approve, deploy, and
  read the tenant back. The industry on the tenant profile pre-selects
  its packs. Each pack card chooses the channels its rules go into
  (Inline Web, Endpoint, SaaS Security API, Outbound Email). Every
  deployment is recorded and can be undone; rules can also be removed
  selectively, with a usage check before anything goes.
- **Export from tenant as a pack** — the tenant's DLP rules on every
  channel, its custom engines and its custom dictionaries, together or
  each on its own (all of them, or the ones you tick). With *Include what
  they use* (the default) engines bring their dictionaries and rules their
  engines and dictionaries; without it, what they use is named, not
  copied, and listed as *named, not included*. The format is a JSON pack
  (the zip the library accepts and Deploy policy packs can deploy into
  another tenant), a Terraform workspace for the zscaler/zia provider
  (built like the Terraform hand-off: rules DISABLED, the assessor named,
  what is not included looked up by name), or both; each part
  (dictionaries, engines, rules) also downloads as its own file. Scope
  that only exists in the source tenant (users, groups, locations, ...)
  is left out and listed in the pack. Read-only; an empty pick is refused
  before any read, an hourly rate refusal fails the export, and Stop gives
  no pack. Where: Deploy policy
  packs, under the pack list; also Step 2 of the Evaluate All Rules
  migration wizard, for its Inline Web DLP rules.
- **Deploy flow diagram** — the plan a preflight produced as a picture:
  which dictionaries feed which engines, which engines feed which rules,
  on which channels. Where: inside Deploy policy packs, on the review step.
- **How a deployment works** — a step-by-step walk-through of the shared
  path every pack takes: plan, validate, approve, write in order,
  activate, read back; and the removal path: rules, activate, engines,
  activate, dictionaries, activate. Where: linked from Deploy policy packs.
- **Review & remediate** — for each failed check with a known fix, a
  guided change with a before/after view, applied only in write mode
  after approval. Where: the Dashboard, beside each finding that has a
  scripted fix.
- **Terraform hand-off** — the same policy pack as a Terraform workspace
  for the official `zscaler/zia` provider. Static mode needs no
  credentials; gap mode reads the tenant and imports what exists so the
  platform team's first `terraform plan` is exactly the gap.
- **Migrate from another DLP** — upload a Symantec, Forcepoint, Netskope
  or Skyhigh policy export, review every policy's translation in a
  decisions file, and get ZIA dictionaries, engines and rules on any of
  the four channels as Terraform, every rule disabled and carrying the
  action you approved, with an API cross-reference and an efficacy
  mapping that says what share of each policy's detection the
  translation carries.
- **Evaluate All Rules migration wizard** (toolbar: Rule migration
  wizard) — moves a tenant from first-match-wins to Evaluate All Rules:
  reads the rules, reorders them so nothing changes behaviour, and shows
  the plan. Its optional Step 3b deletes every existing Inline Web DLP
  rule (back them up in Step 2 first; there is no undo) and Step 5
  re-posts the tenant's own rules as they were; both only in write mode.

### Reference

- **How Evaluate All Rules decides** — the decision flow with the
  tie-breaker, as a diagram for the customer.
- **Best practices library** — curated Zscaler best-practice articles,
  rated by source and refreshed from help.zscaler.com, the blog and the
  developer portal.
- **Advanced settings** — add your own policy packs (JSON, Terraform,
  native Zscaler API exports or a ZIP) to the library, and see how this
  server is configured (bind host, token gate, write mode, limits) with
  its Secure by Design score.
- **Best practices benchmark and frameworks** — the grade, the DLP
  programme stages and the framework coverage. Where: the Dashboard.
- **Zscaler updates** — a check of PyPI and help.zscaler.com for SDK and
  documentation changes since last time.
- **Beacon: SDK, API & Terraform changes** — the upstream check's online
  half run on this server: the Zscaler Python SDK, the ZIA API (the SDK's
  service definition, the API reference, the help-center pages) and the
  zscaler/zia Terraform provider, on a timer (every 24 hours by default,
  `DLP_CHECK_BEACON_HOURS`) and on demand, with what changed since the
  last run and the last 30 runs. Optionally a read-only (GET) watch of
  the tenant endpoints in scope on the Scope page (nothing else), which
  says which ones now answer differently.
- **Update app** — fetches the latest build of this app from GitHub,
  installs the pinned dependencies and restarts; the Branch dropdown
  tries a fix on QA or Development before it is promoted to Stable.
  Where: the Start here card, beside the build number (a Git install
  only).
- **Data Security Portfolio Framework**, **Public AI security framework**,
  **Public GenAI security framework**, **The framework machine** and
  **Data Security Architect** — reference pages served inside the tool,
  offline: Zscaler's data-security portfolio as an operating program, the
  AI and GenAI control frameworks with story builders and proof plans,
  how those pages are built, and the data-security reference architecture
  (every DLP channel's flow, limits, setup sequences and symptom
  walkbacks).

### Troubleshoot

- **Audit timeline** — ZIA's admin audit log for a window you choose
  (the last 7 days by default, up to 180) merged with DLP-Check's own
  deployment records and audit log, newest first, with filters, a
  field-by-field diff where the entry has before and after values, and
  CSV or JSON export. A change someone else made to an object DLP-Check
  created is marked. Reading ZIA's log needs Automation readiness in scope;
  asking ZIA for the report is a POST that changes no configuration.
- **Log analyzer** — drop in the ZIP from Client Connector's Export Logs
  (or single log files, or a PAC file); it is read on this computer and
  answers what happened, what it means for the user and what to do next.
- **Diagnose ZCC access** — probes every Client Connector API endpoint
  with the credentials you entered and shows which answer. Where: the
  Connect to the tenant card.
- **Required API access** — the exact API roles and scopes the app needs
  per assessment scope, to send to the customer's admin. Where: the
  Connect to the tenant card (`/permissions`).

## The policy packs it ships with

| Pack | For |
|---|---|
| ZBP Enterprise Policy Pack | Any commercial enterprise with no DLP policy yet (Zscaler's enterprise best practice) |
| Source Code to AI Policy Pack | Source code going into AI tools (13 languages; can be rebuilt from the tenant's own dictionaries) |
| Healthcare PHI Policy Pack | Healthcare providers and payers |
| Global Banking Policy Pack | Banks, card issuers, payment processors, wealth managers |
| Fed Policy Pack | US federal agencies and contractors (contains the enterprise pack) |
| CJIS Policy Pack | Law enforcement, courts, CJI handlers |

Your own packs go in through Advanced settings and are treated exactly
like the shipped ones. Every pack ships each rule **DISABLED** and
monitor-only, one rule per engine, with the same shape on every channel.

## What it never does

These rules hold on every page, and the tests enforce them:

- **It starts read-only.** Assessment, every report, preflight and the
  journey measurement work without write mode. Deploying, removing,
  applying a proposal or posting rules is refused until an operator
  enables **write mode** in Deploy policy packs by typing the confirm
  phrase (or starts the server with `ENABLE_WRITE_ACTIONS` set). Write
  mode lets the app create and delete DLP policy in the signed-in tenant,
  lasts until the server restarts, and is shown on the page while it is
  on. The switch works only when nobody but this machine can reach the
  server: it listens on `127.0.0.1` (the laptop default), or it is the
  container published on this machine's loopback (the default,
  `DLP_CHECK_HOST_BIND`). For a server reachable from elsewhere,
  including a container published beyond loopback, the switch is refused: put
  `ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND` in the `.env` file next to
  `docker-compose.yml` and restart.
- **Nothing the customer has is overwritten.** A pack keeps what already
  exists and creates only what is missing; objects it does not define are
  never touched; a removal deletes only what the pack put in, and keeps
  anything another rule still uses, saying so. Two exceptions, both behind
  write mode and both explicit: the Rule migration wizard's optional
  Step 3b deletes every existing Inline Web DLP rule (Step 5 re-posts the
  tenant's own rules as they were), and the API-only converge option
  (`restore_drift`, which no screen in the app uses) overwrites pack
  objects the customer changed.
- **You approve the exact plan.** The plan carries a fingerprint; if the
  tenant changes between approval and deploy, nothing is written until you
  review again.
- **Every rule arrives disabled.** A pack's rules are also monitor-only;
  a migrated rule carries the action approved in its decisions file.
  Enabling or hardening a rule is the customer's decision in the portal;
  the journey card records it as progress and never reverts it.
- **After a deploy or a removal it activates the pending configuration
  and reads the tenant back**, so what it reports is what the tenant
  says, not what it sent. A proposal applied from the FP/TP ratio is left
  pending for an admin to activate.
- **For tenant work it reaches only the Zscaler APIs.** Its own
  housekeeping reaches GitHub (Update app), PyPI and Zscaler's help site,
  blog and developer portal (the update and library checks), a fixed list
  of integration-partner documentation sites (Microsoft Learn, AWS,
  Splunk, CrowdStrike, Okta, Ping, Zscaler Community) for the library and
  guidance checks, and, only if you configure the digest, your SMTP relay
  or Teams/Slack webhook. Reports, profiles, deployment records and the
  audit log stay on the machine it runs on; the Log analyzer and DLP
  efficacy read what you give them locally and store nothing.
- **It listens on this machine only** (`127.0.0.1`), behind a per-start
  UI token; every write is recorded in `audit.log`. For a shared server,
  an OpenID Connect sign-in (SSO) can be required before the token is
  issued; without it the app refuses to listen beyond this machine, and
  the container is kept private by the `127.0.0.1:` in its ports line.
  Details in `SECURITY.md`.

## Two ways to sign in to a tenant

- **OneAPI**: an API client created in ZIdentity (client ID and secret),
  plus the vanity domain and the cloud. Covers ZIA, ZPA, Client Connector
  and ZDX checks.
- **Classic ZIA API**: an admin's username and password plus the tenant's
  API key, for a tenant that has not enabled ZIdentity. Covers ZIA only;
  the ZPA, Client Connector and ZDX checks report as not available, and
  policy packs deploy the same way.

Both are chosen on the Connect to the tenant form; both can be pre-filled
from `local_settings.bat` / `local_settings.env` or saved in a tenant
profile.

## From the command line

The same code runs without the browser:

- **Mac and Linux**, after `./install.sh`: `.venv/bin/dlp-check` (the
  server), `.venv/bin/dlp-check-assess --config tenant.json --output
  report.json` (the assessment from a JSON file), and
  `.venv/bin/dlp-check-evaluate` (one run of the evaluation loop, for cron).
- **Windows**: `python dlp_assessment_full_auto.py --config tenant.json
  --output report.json`, and `RUN_Continuous_Evaluation.bat` for Task
  Scheduler.
- **Container**: `docker compose exec dlp-check python continuous_eval.py
  --once`.

`python dlp_mcp_server.py` runs a separate, optional MCP server (port
8080, or `--transport stdio`) that lets an AI agent run the same
assessment with credentials from `ZSCALER_*` variables only (no tool
accepts a secret, so none passes through the AI conversation;
`get_health` names any variable that is missing); no launcher starts it.

## Limits, and what is still to come

Being honest about the edges:

- The **Live DLP feed** shows Workflow Automation DLP incidents only. URL
  filtering, Cloud App Control and firewall decisions that never trip a
  DLP rule are not in it; that is Web Insights or a Cloud NSS feed, which
  the app does not read.
- **Traffic insights** reads ZIA Insights' aggregated numbers, not the
  transaction log: the installed SDK's Z-Insights queries cannot group
  traffic by URL category, user or policy rule, or filter it to one host,
  so rule hit counts and the Path analyzer's recent traffic to a
  destination are not available from it.
- The **classic ZIA API** sign-in covers ZIA only.
- **Review & remediate** covers the failed checks that have a known,
  scripted fix, not every finding.
- The **Forcepoint, Netskope and Skyhigh** adapters are built from each
  vendor's documented export formats; they have not yet been validated
  against real customer exports, so the first real export from each
  vendor should be checked field by field (the API cross-reference on the
  page shows every mapping).
- **Update app** works for an install made with git; a ZIP copy and a
  container are updated by replacing the files (see `INSTALL.md`).
- **In the container**, write mode is switched on in the app as on a
  laptop while the container is published on loopback (the default);
  published beyond it, it comes from `ENABLE_WRITE_ACTIONS` in `.env`.
  Everything else works as on a laptop, and what it saves lives on the
  volume: profiles, deployments, the audit log, uploaded packs, digests,
  proposals, the guidance state, the check references you approve (added
  to the shipped `checks_config.json`), the update and best-practice
  caches, and a built-in pack rebuilt from the tenant, which is kept in
  the pack library under its own id (remove it there to go back to the
  shipped pack).
- The **Digest** loop is off by default: it runs when you click *Run the
  loop now* or run `continuous_eval.py --once`, and on a timer only while
  the server runs and only when `DLP_CHECK_CONTINUOUS_EVAL_HOURS` is set
  (1 to 8784 hours); for a schedule that outlives the server, use Task
  Scheduler or cron.
- The checks cover ZIA DLP end to end and the parts of ZPA, Client
  Connector and ZDX that affect data protection; they are not a full
  audit of those products.

Everything the app has shipped, batch by batch, is in `CHANGELOG.md`.
