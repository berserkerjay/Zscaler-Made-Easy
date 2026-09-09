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

To update later: `.\UPDATE_Zscaler_Assessment.bat` (stops the server,
pulls the latest code, restarts). Press Ctrl+F5 in the browser once.

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

Red dashed lines and the **GAP** badge mark traffic DLP cannot see. Click
a row for the deciding rule, the scoped exceptions that run before it
(an executive bypass group, for example), shadowed decrypt rules, the
DLP rules that target the traffic, and the fix. The gap list below the
diagram is sorted by severity. **Refresh** (or the auto-refresh box)
re-reads the tenant through the assessment tab, so keep that tab open.
Zscaler's own *Recommended Exemptions* are recognised and listed
separately: they cover certificate-pinned apps and should stay enabled.

## 5. Choose a policy pack (step 4)

Click **Deploy Policy Packs**. Each card says who it is for and when to use
it. Rule of thumb:

| Customer | Pack |
|---|---|
| Any commercial enterprise with no DLP policy yet | **ZBP Enterprise Baseline** |
| Worried about source code going into AI tools | add **ZBP Source Code to AI** |
| Healthcare provider or payer | add **Healthcare PHI** |
| US federal agency or contractor | **Fed Policy Pack** instead of ZBP Enterprise (it contains it) |
| Law enforcement, courts, CJI handlers | **CJIS Policy Pack** |

Do not select Fed and ZBP Enterprise together; they define the same
objects under different names.

## 5b. Tenant profiles (many customers, one laptop)

The **Tenant profiles** bar at the top of Tenant Configuration saves one
record per customer: organisation, assessor, cloud, vanity domain, client
ID, ZPA customer ID, scopes, industry, which baseline packs apply, and
notes. Pick a profile from the list and the form fills itself.

- **Remember the secret on this laptop** stores the client secret in
  `tenant_profiles.json` next to the app (owner-only file, git-ignored).
  Leave it unticked on a shared machine; you will paste the secret each
  time instead. The secret is never sent back to the browser.
- Every assessment run with a profile selected is recorded in that
  profile's **history**: date, score, maturity and the journey stage per
  baseline. The journey card on the results compares with the previous
  run, so the customer sees movement between visits.
- **Baseline packs** on the profile restrict the journey measurement to
  the baselines that apply to this customer (a hospital is measured
  against Healthcare PHI, not CJIS).

## 5c. Hand off as Terraform (platform teams)

Some customers manage Zscaler as code and will not accept changes made
from a tool. Give them the same baseline as a Terraform workspace instead:

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
5. Click **Review & approve**. Read the checklist, tick the consent box,
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
   tenant?** on the baseline card). The *Data governance journey* card shows
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

## Glossary

The **? Help** button in the app has the full glossary. The five words that
matter: a **dictionary** is what to look for; an **engine** combines
dictionaries into a decision; a **rule** says where the engine applies and
whether to monitor (ALLOW) or stop (BLOCK); a **pack** is a folder of all
three for one purpose; a **baseline** is a pack the tenant is measured
against on its journey from deployed to enforcing.
