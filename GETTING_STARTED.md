# Getting Started — a walkthrough for your first engagement

This guide assumes you have never used DLP-Check and know only the basics
of Zscaler. It takes a tenant from "we don't know our DLP posture" to
"gaps identified and a policy pack ready to deploy" in about an hour.

## What the tool does, in one paragraph

DLP-Check connects to a customer's Zscaler tenant with read-only API
credentials, runs 300+ automated checks, and gives the tenant a maturity
score with a list of findings. It then lets you close the gaps by deploying
a **policy pack** — a ready-made set of DLP dictionaries, engines and rules
for a regulation (CJIS, Fed, HIPAA PHI) or for Zscaler's own best practice —
after showing you exactly what would change and asking you to approve it.
Every rule in every pack ships **disabled**, so deploying never affects the
customer's users. It works in an empty tenant and on top of an existing one:
whatever the customer already has is kept. Afterwards, the assessment tells
you where the tenant is on the data-governance journey and what to enable
next.

## 1. Install (once per laptop)

1. Install Python 3.11+ from python.org and tick **Add Python to PATH**.
2. Install Git from git-scm.com.
3. In PowerShell:
   ```
   git clone https://github.com/berserkerjay/DLP-Check.git
   cd DLP-Check
   .\INSTALL_Zscaler_Assessment.bat
   ```
4. A **Zscaler Assessment** shortcut appears on the desktop. Double-click it.
   The browser opens to http://localhost:8000; the server runs silently in
   the background (its output is in `server.log` next to the app).
   `STOP_Zscaler_Assessment.bat` stops it. Double-clicking
   `START_Zscaler_Assessment.bat` also starts silently; run it as
   `START_Zscaler_Assessment.bat --console` when you want to watch the
   server output in a window.

To update later: the Start here card says **update available** when
GitHub is ahead; click **Update app now**. The app pulls the latest code,
installs any new dependencies, restarts itself and reloads the page. It
shows each step. Hand-edited files are kept: proxy or CA-bundle lines
that older instructions had you put into the start script are moved into
`local_settings.bat`, and any other edit is set aside and re-applied after
the pull. `UPDATE_Zscaler_Assessment.bat` does the same from a command
prompt. The repository is private, so git on the laptop must be signed in
to GitHub once (`git fetch` in the app folder prompts for it). A copy that was not installed with git cannot update in
place; the card shows the one command that moves it to a git clone.

## 1a. The UI token (why the browser sometimes asks for a code)

Each time the server starts it mints a token. The desktop shortcut opens
the browser with it, so you normally never see it. If you open
`http://localhost:8000` by hand, or in another browser, the page asks for
the token once: it is in `ui_token.txt` next to the app (also printed on
the server console). Paste it and you are in; the browser keeps it as a
cookie for 12 hours. Anything else on the laptop that tries the API
without it gets *401*. Set `ZSCALER_UI_TOKEN=...` in `local_settings.bat`
to keep one token across restarts, or `ZSCALER_UI_AUTH=0` to turn it off
(not recommended). Every write call is recorded in `audit.log` next to
the app.

## 1c. Run it in a container instead

`docker compose up --build` in the app folder builds an image with
hash-pinned dependencies and runs it as a non-root user on a read-only
filesystem, published on `127.0.0.1:8000` only. Profiles, deployments,
the audit log and the UI token live on the `dlpcheck-data` volume
(`docker compose exec dlp-check cat /data/ui_token.txt` prints the token;
`docker compose logs` shows it too). Put `ZSCALER_*` credentials in a
`.env` file next to `docker-compose.yml` if you do not want to type them.
The in-app **Update app** button does not apply inside a container:
rebuild the image instead.

## 1b. Settings that survive updates (proxy, TLS inspection)

If your laptop sits behind Zscaler Client Connector or a corporate proxy,
Python needs the organisation's root CA and/or a proxy address. Do not edit
the start scripts (an update or a fresh clone replaces them). Instead:

1. Copy `local_settings.bat.example` to `local_settings.bat` in the app
   folder (it is git-ignored).
2. Remove the `REM ` in front of the lines you need, for example
   `set REQUESTS_CA_BUNDLE=C:\certs\zscaler-root-ca.pem` or
   `set HTTPS_PROXY=http://proxy.corp:8080`.
3. Stop and start the server (`STOP_Zscaler_Assessment.bat`, then the
   desktop shortcut). Start here shows the CA bundle in use.

Authenticate tells you when this is the problem: "intercepted by TLS
inspection" means the CA bundle is missing or wrong; "rejected the client
ID or client secret" means the credentials themselves.

## 2. Get credentials from the customer

Ask the customer's Zscaler admin for four things. They come from
**ZIdentity → Integration → API Clients → Add API Client**:

| Field | What it is | Example |
|---|---|---|
| Cloud | Almost always Production | Production |
| Vanity domain | The short name before `.zslogin.net` in their login URL | `acme` |
| Client ID | Shown on the API client | `a1b2c3…` |
| Client secret | Shown **once** when the client is created | — |

The API client needs a ZIA role that can **read** DLP dictionaries, engines
and DLP policy. For deploying packs it also needs **write** on those. Ask
for a dedicated client for this engagement so it can be revoked afterwards.

If the customer pasted the secret from the portal later, it is a masked
placeholder and will not work. They must generate a new one.

## 3. Connect (Start here, step 1)

1. Open **Tenant Configuration** and enter the four values plus your
   organisation and assessor name.
2. Click **Authenticate** at the bottom of Tenant Configuration (or in the
   **Start here** panel, step 1). You should see
   "Connected: N dictionaries, N engines, N web DLP rules".
3. If it fails, the panel says why and what to do. The two common causes:
   - *Zscaler rejected the client ID or client secret* → regenerate the secret.
   - *Connection intercepted by TLS inspection* → your laptop is behind
     Zscaler Client Connector or a proxy. Export the corporate root CA as a
     `.pem` and start the tool with `REQUESTS_CA_BUNDLE` pointing at it, or
     run from a machine that is not inspected.
4. Click **Save Config** so the non-secret fields are remembered.

## 4. Assess (step 2 and 3)

1. Leave the default scopes ticked and click **Run Assessment**.
2. After about 90 seconds the **Summary** shows the score and maturity
   level; **Detailed Findings** lists every check that failed or warned,
   with what it means and how to fix it.
3. Walk the customer through **Critical** findings first. Those are
   configurations that leak data today. Use **Export** to give them the
   report as Word or CSV.

## 4a. Results in their own tab

**Run assessment** (Start here, step 2) opens the results in a new tab
with a link back to this page: the progress card while it runs, then the
score, summary, findings and exports. The results stay on the main page
too; **Open in new tab** above them opens them again later.

## 4b. SSL Inspection Flow (what inline DLP can actually see)

Inline Web DLP only reads HTTPS content that an SSL inspection
**Decrypt** rule has opened. The **SSL Inspection Flow** button under
*Find the gaps* opens a live diagram in its own tab:

- **Left column** is a traffic class that matters to DLP: file sharing,
  personal webmail, generative AI, social, collaboration, forums and paste
  sites, uncategorised sites, remote access, the finance/health/government
  privacy set, and everything else.
- **Middle column** is the first enabled SSL rule that matches that class
  (rules run top-down, first match wins): *decrypted*, *not decrypted*,
  *blocked*, or *no rule*. The rule name and order are printed so you can
  find it in the portal.
- **Right column** is what inline Web DLP can do with it: enforcing,
  monitor only, no rule, or *blind* because the traffic stayed encrypted.

The **top row** is different: traffic that bypasses Client Connector (app
and forwarding profile bypasses, trusted networks) never reaches Zscaler
at all, so no SSL rule and no DLP rule ever sees it. It is read live from
the profiles; click the row for every entry and a link that opens the full
Bypass & Non-Inspected report in its own tab.

Red dashed lines and the **GAP** badge mark traffic DLP cannot see. Click
a row for the deciding rule, the scoped exceptions that run before it
(an executive bypass group, for example), shadowed decrypt rules, the
DLP rules that target the traffic, and the fix. The gap list below the
diagram is sorted by severity. **Refresh** (or the auto-refresh box)
re-reads the tenant through the assessment tab, so keep that tab open.
Zscaler's own *Recommended Exemptions* are recognised and listed
separately: they cover certificate-pinned apps and should stay enabled.

## 4c. Keep the Best Practices library current

**Best Practices** (under *Reference*) opens the library of Zscaler
best-practice articles, each badged Official, Authoritative or Community.
Click **Update library now** to read the sources live:

1. The sitemaps of help.zscaler.com, the Zscaler blog and the developer
   portal are read first (every published article in one request), then
   the partner sites (Microsoft Learn, AWS, Splunk, CrowdStrike, Okta,
   Ping, Zscaler Community) are walked page by page.
2. Every article whose address contains *best-practice*, *leading-practice*
   (or *how-to* / *guide* on the blog) that is not yet in the library is
   fetched for its title and added, badged **DISCOVERED**. Additions are
   kept in your per-user data folder, so they survive restarts and
   updates of the tool.
3. The result panel says, per source, whether it answered, how it was
   read (sitemap or page walk) and how many articles it listed. A source
   that could not be reached shows the reason. Common causes: corporate
   TLS inspection (put `set REQUESTS_CA_BUNDLE=...` in `local_settings.bat`
   as in section 1b, or tick *Skip TLS verify* for one run), a proxy
   (`set HTTPS_PROXY=...` in the same file), or the host being blocked.

An update that reaches nothing is never cached: the library keeps its
last good state, the failure is shown at the top, and the next click
tries again. A background refresh also runs every 6 hours.

## 4d. Best practices, benchmarks and frameworks

The results carry a **Best Practices & Benchmarks** card:

- **Zscaler best-practice alignment**: a grade (A to F) and a percentage.
  Every check that names Zscaler's best practice (most do, in the finding
  text after *Best Practice:*) counts; a failed or review finding on one of
  them is a *deviation* and is listed under its area (ZIA policy, Client
  Connector, SSL inspection, DLP programme, GenAI, ZPA, administration,
  automation, ZDX) with the guidance and a **Read the article** link.
  Checks the tenant could not answer (not licensed, not reachable) are
  *not measured* and do not count against it.
- **DLP programme benchmark**: the twelve-step DLP checklist as five stages
  (Foundation, Visibility, Coverage, Operation, Response). A stage is met
  at 75% of its measured checks; the stage reached stops at the first
  unmet one, and each stage names the checks to fix next.
- **Frameworks, weakest first**: NIST 800-53, NIST 800-171, NIST CSF 2.0,
  SOC 2, GDPR, HIPAA, PCI DSS, ISO 27001, CIS Controls, GLBA Safeguards
  and CMMC. The **Regulatory & Compliance Alignment** card below it has
  the control-by-control drilldown with the findings behind each control.
- **Policy pack journey**: the stage the tenant has reached against the
  policy packs (fills in when the journey measurement lands).

**Download benchmark note** gives the same as Markdown for the customer
write-up. Every card on the results page is open by default; click a
heading to collapse it.

## 4e. Data Flow Map (the exact path, and where each pack is weak)

**Data Flow Map** in the toolbar opens a live tab that traces, for every
DLP-relevant traffic class on every network context (off network, on a
trusted network, on VPN), the exact path a transaction takes through
*this* tenant:

1. **Client Connector app profile** for the platform: does a domain, app,
   process or IP bypass send it straight out of the device? Strict
   enforcement, certificate push and Endpoint DLP install are read too.
2. **Forwarding profile** for that network: Z-Tunnel 2.0, Tunnel 1.0,
   tunnel with local proxy, enforce-proxy (PAC) or none.
3. **PAC file**: `DIRECT` statements that skip Zscaler for the host.
4. **SSL inspection**: which rule decides, decrypt or leave encrypted.
5. **URL filtering**, **Cloud App Control** (upload/share controls need
   decryption), **File Type Control**, then **Inline Web DLP**: which
   rules see the content and whether they monitor or enforce.

Beside the path, the channels that do not ride the tunnel: Endpoint DLP
on the device (only if the app profile installs it), SaaS Security API at
rest, Outbound Email DLP. Under it, **every policy pack**: which of its
rules sit on this path and whether each is enforcing, monitoring, disabled
or not deployed, with the pack's weak point in one line.

Type any **cloud application, URL category or hostname** in the box (the
list suggests the tenant's own catalogue and categories), pick the network
and platform, and click **Trace**; the path is computed from the snapshot
without touching the tenant again. **Refresh** re-reads the tenant.
Weak points are ranked worst first, each with the fix. Raw profile values
are kept next to every interpretation because Client Connector schemas
vary by version; if a mode reads *unknown*, the raw value tells you what
the portal says.

## 4f. Log Analyzer (when a user says "Zscaler is broken")

Toolbar › *Troubleshoot › Log Analyzer* (`/report/logs`). Ask the user for
their logs: Zscaler tray icon → **More** → **Export Logs**. It saves a ZIP.
Drop that ZIP into the analyzer as it is (single `.log` files, `.tgz`
bundles and PAC files work too), click **Analyze**, and read from the top:

1. **The verdict**: one line. "The user was not protected for part of this
   period" or "Nothing wrong was found".
2. **What we read**: client version, OS, user, cloud, tunnel version and
   last state, the period the logs cover. If the problem happened outside
   that period, ask for a fresh export taken right after it happens.
3. **What we found, most urgent first**: each finding says what happened,
   what it means for the user, and numbered next steps. A blue note under
   a finding tells you when it is a symptom of another one (errors while
   behind a hotel Wi-Fi sign-in page are not a fault).
4. For a PAC file: the default action, the gateways and macros, every
   bypass with its risk, and what to change.

Nothing leaves the laptop and nothing is stored; evidence lines have
passwords and tokens blanked out. *Download findings* gives you a Markdown
file for the ticket.

## 4h. Detection Health and the proposals queue (return visits)

Toolbar › *Find the gaps › Detection Health*. Once incidents have flowed
through Workflow Automation for a few weeks, this tab measures what the
DLP rules actually do (false-positive rate per rule, engine and
dictionary; dead rules; monitor rules ready to promote) and turns the
findings into **proposals**: one change each, with the evidence, the
expected effect and the way back.

1. **Decide**: approve, snooze or dismiss each proposal. A change that
   makes the tenant stricter for users (monitor → confirm or block) asks
   for the confirm phrase. Nothing is written by deciding.
2. **Preview and apply**: an approved rule proposal gets a *Preview and
   apply to the tenant* button. The app re-reads the rules and shows the
   exact change; if the tenant moved since the evidence was gathered, it
   refuses and says why. Tick the review box, click *Apply now*: each
   rule is updated and read back, and only a verified change counts.
   Write mode is required, and ZIA keeps the change pending until an
   admin clicks Activate.
3. **Roll back**: an applied proposal keeps the value it replaced, so
   *Roll back* puts it back with the same read-back.

Dictionary and engine tuning proposals are made in the ZIA portal; the
queue tracks them and says so. Every decision and every apply is in
`audit.log`.

## 4i. Always on: the digest (nothing to remember)

Toolbar › *Find the gaps › Digest*. Every six hours while the app runs, for
every tenant profile that remembers its secret, the loop:

1. re-reads the guidance sources (Zscaler's own and the integration
   partners, Proofpoint first) and turns a new article on a mapped topic
   into a proposal that names the checks and packs it touches; a source
   that stops answering for seven days is flagged as stale;
2. refreshes Zscaler's SaaS tenant capability matrix and compares it with
   the customer's onboarded tenants (not active, at the limit, not
   onboarded at all);
3. runs Detection Health and refreshes the proposals queue;
4. measures the packs' journey and reports drift since the last run;
5. writes a digest and, when there is something to decide, sends it.

To receive it, put the settings in `local_settings.bat` (see
`local_settings.bat.example`): an SMTP relay and a recipient for e-mail,
or a Teams / Slack incoming webhook (https). To run the loop when the app
is not open, schedule `RUN_Continuous_Evaluation.bat` in Windows Task
Scheduler; in a container run `python continuous_eval.py --once`. The
Digest tab shows the latest digest, the previous ones, the sources and
the settings, and has a *Run the loop now* button. Nothing in the loop
writes to a tenant; decisions stay in Detection Health.

## 4g. What does everything do?

Toolbar › *Start › What does everything do?* (`/help`) lists every function
of the app in plain English (what it is, why the customer cares, when to
use it, what you get, what to do next), in the order of a first
engagement, with the glossary. Every report tab also opens with a
*What is this page, and why it matters* box; hide them from any box once
you no longer need them.

## 5. Choose a policy pack (step 4)

Click **Deploy Policy Packs**. Each card says who it is for and when to use
it. Rule of thumb:

| Customer | Pack |
|---|---|
| Any commercial enterprise with no DLP policy yet | **ZBP Enterprise Policy pack** |
| Worried about source code going into AI tools | add **Source Code to AI** (13 languages; each language is an Anchor dictionary AND a Signal dictionary in one engine, so cousin languages such as Java/Kotlin do not cross-fire). If the customer already maintains their own Anchor/Signal dictionaries in the tenant, click **Rebuild from tenant dictionaries** on the card: it previews the pairs it found, then rebuilds the pack from them, dropping the shipped ones. |
| Healthcare provider or payer | add **Healthcare PHI** |
| Bank, card issuer, payment processor, wealth manager | **Global Banking Policy pack** (PCI, payment instructions, customer PII across jurisdictions, KYC/AML, MNPI; it shares its US PII, financial and private-key objects with ZBP Enterprise, so the two can be deployed together) |
| US federal agency or contractor | **Fed Policy Pack** instead of ZBP Enterprise (it contains it) |
| Law enforcement, courts, CJI handlers | **CJIS Policy Pack** |

Do not select Fed and ZBP Enterprise together; they define the same
objects under different names.

## 5b. Tenant profiles (many customers, one laptop)

The **Tenant profiles** bar at the top of Tenant Configuration saves one
record per customer: organisation, assessor, cloud, vanity domain, client
ID, ZPA customer ID, scopes, industry, which policy packs apply, and
notes. Pick a profile from the list and the form fills itself.

- **Remember the secret on this laptop** stores the client secret in
  `tenant_profiles.json` next to the app (owner-only file, git-ignored).
  Leave it unticked on a shared machine; you will paste the secret each
  time instead. The secret is never sent back to the browser.
- Every assessment run with a profile selected is recorded in that
  profile's **history**: date, score, maturity and the journey stage per
  policy pack. The journey card on the results compares with the previous
  run, so the customer sees movement between visits.
- **Policy packs** on the profile restrict the journey measurement to
  the policy packs that apply to this customer (a hospital is measured
  against Healthcare PHI, not CJIS).

## 5c. Hand off as Terraform (platform teams)

Some customers manage Zscaler as code and will not accept changes made
from a tool. Give them the same policy pack as a Terraform workspace instead:

1. Click **Terraform hand-off** on the front page (or *Terraform hand-off*
   on a pack card, or *Hand off as Terraform* on the preflight review). It
   opens in its own tab.
2. Tick the packs. With tenant details filled in, the page is in **gap
   mode**: DLP-Check reads the tenant and writes `imports.tf` so the
   platform team's first `terraform plan` is exactly the gap. Without
   credentials it is **static** (the whole pack, no tenant knowledge).
3. Read *What you get* (the files and what each is for) and click
   **Download workspace**. One zip, one folder per pack.
4. Hand over the zip with the note on the page: fill `terraform.tfvars`,
   `terraform init`, `terraform plan` (the review), `terraform apply`.
   Every rule arrives disabled.

The repository also carries a ready workspace per pack under
`terraform/<pack>/`, validated against the real provider on every commit.

## 5d. Choose the channels a pack goes into

Every pack card has a **Deploy the engines into** row with four boxes:
Inline Web DLP, Endpoint DLP, SaaS Security, Outbound Email DLP. Boxes
are ticked for the channels the pack ships rules for.

- **Tick a channel the pack has no rule for** and the deploy adds one
  monitor-only rule on that channel carrying every engine of the pack
  (for example *ZBP-Endpoint DLP Monitor*). It arrives disabled at INFO
  severity, so it only adds visibility until you enable it. It needs the
  same prerequisites as any rule on that channel (Endpoint DLP licensed,
  a SaaS or email tenant onboarded); preflight says so if they are
  missing.
- **Untick a channel the pack has rules for** and those rules are
  skipped. Containment rules (Cloud App Control, File Type, URL, SSL) are
  not part of the choice and deploy as packed.
- The choice is part of the approved plan, is remembered per pack on
  this laptop, and is used by *Where is this tenant?* and the Terraform
  hand-off too.

## 5e. Undo a deployment

Every deployment made from this app is recorded under **Previous
deployments** at the bottom of the pack list, and the Deploy step ends
with an **Undo this deployment** button. Undo deletes exactly the objects
that deployment created, in order: rules (sub-rules first), endpoint
application groups, engines, dictionaries. It never touches objects that
already existed, and it leaves alone anything the customer renamed or
that another rule still uses, listing those so you can decide. Undo needs
write mode and the tenant fields set to the same tenant; the deletions
need activation in ZIA like any change.

## 5f. Add your own policy packs (Advanced settings)

**Advanced settings** in the toolbar opens a tab with the policy pack
library: the packs the app ships with and the ones you add. Adding a pack
makes it appear everywhere the app offers a pack: Deploy Policy Packs,
the Data Flow Map, the Terraform hand-off and the detection validator.

What you can bring:

- **One JSON file**: a name, a description and three lists (`dictionaries`,
  `engines`, `policies`). *Download a complete example* on the tab gives you
  the Global Banking Policy pack in this layout to copy from.
- **The three pack files** (`dlp_dictionaries.json`, `dlp_engines.json`,
  `dlp_policies.json`, optional `pack.json`), or a ZIP of a pack folder.
- **Terraform** for the `zscaler/zia` provider (`zia_dlp_dictionaries`,
  `zia_dlp_engines`, the DLP and containment rule resources). A workspace
  from the Terraform hand-off round-trips. Objects must be referenced by
  name; an id copied from another tenant is reported.

How it works: choose the files, the tab checks them (patterns compile,
Zscaler limits, every engine points at a dictionary, every rule at an
engine) and shows what it found. Problems block the upload; warnings are
shown and allowed. *Add to library* stores the pack on this machine only.
Nothing changes in the tenant until you deploy the pack from Deploy Policy
Packs, where its rules are created DISABLED like every other pack.

Where packs live: `user_packs/` next to the app (git-ignored, kept by
updates), or the folder in `DLP_CHECK_USER_PACKS` (the `/data` volume in
the container). *Remove* deletes an uploaded pack from the library only.
Adding and removing is allowed when the server only answers your laptop
(bind host 127.0.0.1) or when the UI token is on; the tab says which.

## 6. Preflight, review, approve

1. Toggle the pack(s) on and click **Run preflight**. Nothing is written.
2. Read the **Impact on this tenant** cards. They tell you how many rules
   are inserted at the top of the policy, whether any would enforce
   rather than monitor, and whether this is a greenfield deploy (nothing
   exists yet) or brownfield (some objects exist and are kept as they are).
3. Check **Tenant prerequisites**. A missing prerequisite (for example, no
   SaaS tenant onboarded) skips only the rules that need it.
4. Open **How to read this plan** if any term is unfamiliar. Hover any
   status chip for a one-line explanation.
5. Read the **Flow** diagram: predefined templates feed dictionaries,
   dictionaries feed engines, engines feed rules, and rules apply to what
   the tenant already has. Hover a box to trace it, click to pin. For a
   full-width view click **↗ Open in new tab**: the Deployment Flow tab has
   a **Details** panel with the full name, the reason each object is in the
   plan and clickable links to what it depends on and what it feeds, plus a
   **Find** box. It stays live while the assessment tab is open (it
   redraws after every preflight and after the deploy), and **← Back to the
   assessment** returns you here. **List** shows the same objects grouped by
   what will happen to them.
6. Click **Review & approve**. Read the checklist, tick the consent box,
   click **Deploy to tenant**.

The server starts **read-only**, so preflight and the plan always work but
deploying is refused. Deploy Policy Packs shows the mode at the top. When
the customer has agreed to the plan, click **Enable write mode** and type
the confirmation phrase it asks for; it lasts until the server restarts.
(`START_Zscaler_Assessment_WRITES_ENABLED.bat` starts in write mode from
the outset, for scripted use.)

## 7. After deploying

1. An admin must click **Activate** in the ZIA Admin Portal.
2. Enable rules one at a time in **Policy → Data Loss Prevention**,
   monitor-only ones first, and raise severity once incidents look right.
3. On the next visit, run the assessment again (or click **Where is this
   tenant?** on the policy pack card). The *Data governance journey* card shows
   the stage reached — Foundation, Policies deployed, Visibility,
   Containment, Enforcement — and names the exact rules to enable or harden
   next. Nothing the customer changed is ever reverted.
4. If the customer's platform team uses Terraform, click **Export
   Terraform** on the review step and hand them the zip. Its first
   `terraform plan` shows exactly the gap.

## 8. When something goes wrong

| You see | It means | Do this |
|---|---|---|
| "Could not connect … rejected the client ID or client secret" | Bad credentials | Regenerate the secret in ZIdentity, paste it fresh |
| "… intercepted by TLS inspection" | Laptop behind ZCC/proxy | `REQUESTS_CA_BUNDLE` to the corporate root CA, or another machine |
| "0 endpoints probed" in ZCC diagnostics | Credentials rejected | Authenticate first |
| Preflight **Blocked** card | A named prerequisite is missing | Read the card; onboard the SaaS tenant, or deselect that rule's pack |
| "Write actions require ENABLE_WRITE_ACTIONS" | Read-only mode | Start with `START_Zscaler_Assessment_WRITES_ENABLED.bat` |
| "The tenant changed since you approved" | Someone edited the tenant mid-flow | Re-run preflight and approve the new plan |
| Only one usage of each socket address (port 8000) | Old server still running | `STOP_Zscaler_Assessment.bat` then start again |

## 8b. When the API client is missing a permission

A partial scan is better than none, so a missing role never stops the
tool:

- **Assessment**: every check the client is allowed to run, runs. Checks
  it is not allowed to run answer *Not permitted* and the results show a
  **Partial scan: what a full scan needs** card naming the permissions to
  grant per scope, with the list of checks that were skipped. The score
  covers what was reachable.
- **Reports** (Bypass, SSL Inspection Flow, Data Flow Map): each section
  that could not be read is listed under *read problems*; the rest of the
  report is complete.
- **Preflight and deploy**: the plan is built from whatever the tenant
  would list. If, say, dictionaries cannot be listed, the pack's
  dictionaries are planned as *new* and marked *unverified*; creating one
  that already exists fails on that item alone (the API rejects a
  duplicate name, nothing is overwritten) and the rest deploys. The
  warnings say which read permission would make the plan verified. Only
  a tenant where nothing at all can be listed blocks the plan.
- **What a configuration change needs** is on the **Required API Access**
  page (`/permissions`): the *Full* permission per object kind the pack
  writes. Activation is never done by the tool.

## Glossary

The **? Help** button in the app has the full glossary. The five words that
matter: a **dictionary** is what to look for; an **engine** combines
dictionaries into a decision; a **rule** says where the engine applies and
whether to monitor (ALLOW) or stop (BLOCK); a **pack** is a folder of all
three for one purpose; a **policy pack** is a pack the tenant is measured
against on its journey from deployed to enforcing.
