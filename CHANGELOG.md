# Changelog

The app shows its build (git commit) in the guide's *Build* badge and at
`GET /api/health`. Updates are fast-forwards of `main`; this file lists
what each batch of changes did, newest first.

## 2026-09-11

### Pack library
- **Native Zscaler JSON uploads.** The Advanced settings upload now accepts the API's own export shapes (`dlpDictionaries`, `dlpEngines`, `webDlpRules`, `endpointDlpRules`, `casbDlpRules`, `emailDlpRules`: camelCase fields, numeric ids, `D<id>.S` expressions): ids become names, expressions become `D:<name>`, sub-rules are kept, predefined dictionaries and engines are left out (every tenant has them), tenant-specific scope (locations, groups, departments, users, SaaS and email tenant ids, auditor/ICAP) is dropped with a warning that says so. The result is an ordinary pack, and a **Download as Terraform (static)** button appears right after the upload.

### Updater
- **"Fetch from GitHub" behind TLS inspection.** git does not read `REQUESTS_CA_BUNDLE`, so on a laptop where the proxy re-signs github.com the update failed at the fetch with an SSL certificate problem while the app's own HTTPS calls worked. The updater and the GitHub build check now hand git the same bundle (`GIT_SSL_CAINFO`), and an SSL, sign-in or connectivity failure says exactly what to set in `local_settings.bat`.

### Terraform hand-off
- **Static or gap, your choice.** The mode is a radio choice instead of being implied by the credentials: static sends no credentials and reads nothing (no `imports.tf`); gap needs the tenant details and is refused without them.

### Removal
- **Every removal goes through the same guided path.** The history's *Undo* and the Done step's *Undo this deployment* used to delete straight away after a browser confirm; they now open the removal wizard (Preview → Approve with consent → Remove in tiers with activation → Verify by a fresh read) on exactly what that deployment created, with a plan hash, the keep rule for engines and dictionaries something else still uses, and the deployment record marked undone from the read-back (`deployment_id` on `/api/dlp-packs/removal/preflight` and `/apply`).


### Packs
- **Equal counts on every channel, Web DLP as the cue.** Each pack now carries exactly one Endpoint, one SaaS and one Email rule per inline Web DLP rule (CJIS 9 × 4, Fed 12 × 4, Global Banking 9 × 4, Enterprise 6 × 4, Healthcare 1 × 4, Source Code 1 × 4). The separate per-engine `[Endpoint Removable Media]` rules are gone: the Endpoint mirror carries no `data_transfer_method`, so it already covers removable media (USB) along with every other transfer method, and incidents name the engine either way. `tools/fan_out_channels.py` regenerates the mirrors and reports UNEQUAL when a pack drifts; Terraform regenerated.

### Deploy
- **Every SaaS mirror of a pack is created.** SaaS Security API rules are ordered per rule type and the API does not shuffle the others down for a new order 1 the way Web DLP does, so a pack with nine `[SaaS]` mirrors landed one and the rest were refused. Each new SaaS rule now takes the next free order of its type (an order conflict is retried once), and the Done step shows, per channel, how many rules were created, reused, skipped or failed and the first errors (`channels` in the apply result).

### Continuous evaluation, phase 2: proposals and the approval queue
- Detection Health findings become **typed proposals** with evidence, expected effect and rollback: promote a monitor rule (confirm phrase required), retire a dead rule, tune a noisy dictionary (exclude the application behind the noise or raise the match count), forward the matches of rules that reach no Incident Receiver. Ids are stable, so the next evaluation refreshes an open proposal instead of duplicating it.
- The **queue** lives in `proposals.json` next to the app (never committed) and shows at the top of the Detection Health tab: approve, snooze (14 days) or dismiss (remembered 30 days) each one, with your name for the audit log; a proposal whose signal disappears resolves itself. `GET /api/proposals?tenant=`, `POST /api/proposals/{tenant}/{id}/decide`, Markdown/JSON export. The 6-hour refresh feeds the queue for every profile that remembers its secret. Nothing is written to the tenant by a decision; approved proposals wait for the apply step (phase 3).


### Page layout
- **Quick Start Assessment** is a button at the top of the page (toolbar, group *Start*) that opens the four steps and the credential instructions in their own tab (`/quickstart`); the card at the bottom of the page is gone.
- **Tenant details** (organisation, assessor, cloud, vanity domain, API client, scope, tenant profiles) are an expandable section inside step 1, *Connect to the tenant*, of the Start-here panel. The form is the same one (same fields, same ids); it opens by itself until the four connection fields are filled in.
- **Regulatory & Compliance Alignment opens in its own tab** (`/report/compliance`): framework cards, the control-by-control drilldown with the findings behind each control, filters, and Markdown / CSV / JSON export. The results page keeps one chip per framework and a button to open the tab; the inline drilldown is gone.

### Evaluate All Rules
- The Inline DLP Rule Migration wizard opens with **how Evaluate All Rules decides**: a two-lane flow (Rule Order versus Evaluate All Rules) and a **simulator**. Type or load rules (Step 2's download feeds it), name the engines a transaction matches, and read the decision step by step: every enabled rule evaluated, the matching set, the most restrictive action (Block › Isolate › Confirm › Allow), **the tie on the action broken by rule order (lowest order number wins)**, whose template, auditor, Incident Receiver and severity apply, and what Rule Order would have done instead. Presets cover a tie between two Block rules, a monitor rule shadowing a block rule, and Confirm versus Allow.

### Local corpus test (DLP Efficacy)
- Besides the custom dictionaries, the corpus test now reports the **predefined dictionaries that would fire** (local approximations of the public pattern shapes, check digits validated: card numbers, SSN, ITIN, ABA routing, IBAN, SWIFT, NPI, Medicare MBI, e-mail, phone, IPv4, AWS / Google / GitHub / Slack keys, private keys, JWT, passport and driver-licence shapes, dates of birth, ICD-10, VIN, MAC, UK NINO and NHS, Canadian SIN, Australian TFN), with masked samples; machine-learning and content-based dictionaries are listed as *not simulated*, never guessed.
- **Which engines would fire**: every engine's expression (`D<id>.S > n` with AND / OR / NOT and parentheses) is evaluated on those counts — fires, does not fire, or *possible* when it hinges on a dictionary that cannot be simulated — and the Web DLP rules each firing engine drives are named.

### Detection Health
- A noisy dictionary now says **why**: whether it carries the noise itself or only co-fires with another dictionary, how thin its matches are compared with the real incidents, which applications and departments the not-real incidents come from, what is known about the pattern (nine-digit numbers, dates, names, Luhn-valid numbers, clinical or financial vocabulary …), and the dictionary's own settings (custom or predefined, confidence, phrases, patterns, proximity). Each comes with a concrete fix, in the findings, the table and the Markdown export.

### Strict Client Connector evaluation
- Seventeen new checks read the app profiles field by field (anti-tampering, every service-disable / uninstall / exit password, log level, QUIC dropped, fail-close and app fail-open, revert password, intercept on all adapters and VPN gateways, the disable window, bypass hygiene including exclusions wider than a /16), the forwarding profiles (Z-Tunnel 2.0 per network type, DTLS with TLS fallback, filter driver, IPv6, RFC1918, PAC use, trusted-network criteria), the company settings (Endpoint DLP entitlement, phased rollout, telemetry, inactive-device cleanup), the privacy settings, the device fleet (strict enforcement, anti-tampering, tunnel version, Endpoint DLP, version spread) and the **DLP notification templates** (TLS, content attachment, placeholders, plain-text body, enforcing rules that notify nobody). Each names the profile or object at fault and cites the Zscaler guidance it applies. Numeric platform codes and the `policyExtension` blob are read.

### Zscaler Update Check
- A source whose page is gone (HTTP 404, a "page not found" page, or a page with no readable text) is shown as **NO PAGE** with the reason, and its link opens the section index instead of an empty page. The Deployment & Operations root uses the right slug.


### Fixes
- **Traffic Flow map no longer fails with "Internal error".** When no Client Connector app profile matched the platform (the profile list unreadable, or the tenant's profiles carrying the numeric platform codes of the Client Connector API), the forwarding hop dereferenced a missing profile and the whole map died. The tracer now degrades hop by hop, the numeric codes (1 iOS, 2 Android, 3 Windows, 4 macOS, 5 Linux) are read, the ZPA action list of a forwarding profile no longer overwrites the ZIA tunnel mode, one destination that cannot be traced is reported in the diagnostics instead of taking the map down, and a failure names the exception and points to `server.log` (which now carries the traceback for every internal error).
- **Client Connector reads use the right endpoint.** App profiles are read from `web/policy/listByCompany` (the earlier `webPolicies/listByCompany` answered 404 on every tenant, so the ZCC findings said "not readable" while the portal was fine); the client tries each known path and caches the one that works, and a failure names the path and status it tried.
- **Update app restarts reliably.** The relaunch used `cmd /c timeout`, which refuses to run without a console, so the new server never started; it is now the silent launcher itself in batch mode (`wscript //B … /restart`), which waits for the old server to release the port, never shows a Windows Script Host dialog (problems go to `launcher.log`) and keeps the UI token so the page stays unlocked after the restart. If the relaunch cannot be scheduled the page says what to do by hand.
- **Review & Remediate works.** The recipes named ids the assessment never produces (`SSL-01`, `DLP-01` …), so no finding was ever remediable; each recipe now lists the assessment checks it answers (`4.1`, `A.2`, `E.2`, `5.3`, `A.1`, `E.1` …) and the Remediate buttons and the review list match on them.


### Packs
- Fed Policy Pack 2.0 absorbs the CUI Marking Baseline: the 28 tiered marking dictionaries and their block/caution/monitor rules now ship inside the Fed pack, enhanced with the V1.1 contextual phrases, Registry category names and declassify-date patterns as tier 7 (`CUI-Detect-Contextual`, monitor only). The V1.1 `CUI Engine (High/Medium/Low Confidence)` engines, their eight dictionaries and the orphan `AEA Medium Confidence` engine are gone. `cui_marking_baseline` is removed; a tenant that deployed it keeps its objects and the Fed pack adopts them by name.
- `tools/pack_from_design.py` can regenerate a design that lives inside a hand-authored pack (`"designs"` in `pack.json`).

### Packs
- `zbp_endpoint_dlp_baseline` removed: every pack mirrors its rules onto Endpoint DLP, so the PCI-only endpoint pack no longer adds coverage.
- Wording: everything is a **policy pack** now (the word "baseline" is gone from the UI, docs and pack names; ids, JSON keys and the provenance tag are unchanged). `Global Banking Policy Pack`, `Healthcare PHI Policy Pack`, `ZBP Enterprise Policy Pack`, `Source Code to AI Policy Pack`.
- Preflight no longer skips an engine (and every rule behind it) because a predefined dictionary the pack references is not exposed by the tenant: the term is dropped, the engine is created without it, and the plan and warnings say which names were left out (`pruned`). This is what stopped the Global Banking pack on tenants without the EU/APAC passport and IBAN predefined dictionaries.

### Updater
- A half-applied earlier update (re-applying the edits conflicted, leaving "unmerged paths") no longer blocks every later update: the conflicted files are copied to `updater_backup\<timestamp>\`, the folder is reset to the last build and the update continues; the edits from that update remain in `git stash`.
- "Could not set aside the hand-edited files: error: could not write index" is handled: a stale `.git\index.lock` (left by an interrupted git) is removed automatically before the update, a lock that is only seconds old is left alone and explained, and the error now says what to check (editor/IDE, OneDrive or antivirus holding the folder, read-only `.git`).

### Detection Health (continuous evaluation, phase 1)
- New **Detection Health** report (toolbar tile, `/report/health`, `POST /api/detection-health`): what the tenant's DLP rules actually do, measured from Workflow Automation incidents and the analysts' verdicts. Per rule, engine, dictionary, channel, application and department: incidents, closed, not real and the false-positive rate; rules classified **noisy** (≥ 40 % not real over 14 days with ≥ 10 closed), **dead** (enabled, no incident in 30 days), **ready to promote** (monitor-only, ≤ 5 % not real over 30 days with ≥ 20 closed), healthy, disabled or not in the inventory; findings worst first. "Not real" defaults to False Positive / Business Justified / Not an incident / Not a violation / Benign; every threshold can be overridden per request (`settings`).
- The report says **how incidents reach Workflow Automation**: cloud-to-cloud forwarding (rules with Zscaler Incident Receiver), an on-premises Incident Receiver over ICAP, both, or neither — and names the enabled rules that forward nowhere, which is why a tenant can have matches but no incidents.
- Every 6 hours, for tenant profiles that remember their secret, the report runs on its own and a compact entry lands in the profile history (`GET /api/detection-health/schedule` shows the state). Read-only; no user identities are kept (departments and counts only). Markdown and JSON export.
- Traffic Flow's incident hop and reference diagram name both delivery paths.

### Deploy
- **Read back after writing.** After the objects are created and ZIA is activated, the deploy waits for ZIA to report ACTIVE and runs the same preflight again: every dictionary, engine and rule it created, overwrote, modified or reused must be found. The Done step shows "Verified by a fresh read: all N objects are in the tenant" or lists exactly what a fresh read could not find (`read_check` in the API result).
- **Endpoint DLP: one removable-media rule per engine.** Every pack now ships, besides the Endpoint mirror of each inline rule, one Endpoint DLP rule per engine scoped to removable media (`REMOVABLE_DRIVE_TRANSFER`, monitor-only, disabled, named `<engine> [Endpoint Removable Media]`), so incidents on USB and other removable drives name the engine and the control can be enabled engine by engine. `tools/fan_out_channels.py` generates them; Terraform regenerated.

### Removal
- **Verified by reading.** After the deletes and the activation, the removal polls ZIA until it reports ACTIVE (up to 45 s), then runs the same discovery the preview ran against the tenant. The wizard's new **Verify** step says "nothing of the pack remains" or lists exactly what is still there, with *Verify again* (a fresh read on demand) and *Remove leftovers* (runs the removal again on exactly those objects). A removal is only called complete when the read comes back clean.
- **Remove every deployed pack at once** now means everything DLP-Check ever put in the tenant: any object carrying a DLP-Check tag (whatever pack id or version wrote it — the retired CUI Marking and Endpoint packs included), plus the names of every pack in the library and of objects earlier pack versions shipped under other names (Fed 1.1's CUI engines and dictionaries, the endpoint pack's PCI engines and rules, the pre-v4.14 source-code objects, extension rules named after the old "Baseline" pack names). Same per-object rules as a single pack: anything a customer rule or engine still uses is kept and listed.
- **Pick rules to remove**: a third way in, for leftovers no tag or name can identify. The wizard lists every DLP rule in the tenant on every channel (state, engines, whether DLP-Check created it, with a filter and select-by helpers); tick the ones to remove and the plan adds the engines and dictionaries only they use, keeping anything an unticked rule or a surviving engine still uses, then preview → approve → remove → verify as usual. `POST /api/dlp-packs/removal/inventory` lists the rules; `rules: [{channel, id}]` on the preflight/apply endpoints selects them.
- Packs without a baseline section (Fed, CJIS) now tag every object they create (`[DLP-Check pack <id> v<version>]`), so a later removal finds them by tag instead of by name alone.
- SaaS Security API rules are now actually deleted: the delete call carries the rule's `ruleType`, which the API requires; without it every SaaS row failed.
- After the final activation the removal re-reads the tenant and reports any object it still lists as **still present** (the removal is not called complete until nothing is left), instead of trusting the delete calls.

### Traffic Flow & Gaps
- No more "Could not read" boxes. Traced paths draw only the data security controls (Cloud App Control, URL Filtering, SSL, File Type Control, DLP, then logs & incidents); Browser/FTP Control, threat protection, Bandwidth Control and Firewall & DNS are not data-leak controls and are left out of the path (the reference diagram still shows ZIA's full order). A Client Connector hop the tool cannot interpret says what it assumed and why ("no app profile for macos", "no forwarding profile linked", "mode 'X' not recognised for off network").
- The path now follows ZIA's policy enforcement order for a web request (Zscaler, *Understanding Policy Enforcement*): Browser & FTP Control, Cloud App Control before URL Filtering (URL Filtering is marked not evaluated when an app-control rule matched), SSL inspection, Malware Protection / Advanced Threat Protection, upload File Type Control, upload Bandwidth Control, Web DLP, Firewall & DNS Control last, then a "Logs & incidents" hop showing which rules forward to the Zscaler Incident Receiver / ICAP and notify an auditor, with a weak point when none do.
- A reference diagram at the top of the report, "How ZIA processes a policy: device → incident", in the same style as the traced paths, with an explanation per stage through Nanolog/NSS, the Incident Receiver and Workflow Automation.

## 2026-09-10

### Security
- Web UI and API require a per-process UI token (cookie set by the launcher's URL, or `X-DLP-Check-Token` / Bearer header). `ZSCALER_UI_AUTH=0` disables it.
- Audit log (`audit.log`, owner-only) of every non-GET API call with a redacted body, plus write-mode toggles.
- MCP server binds 127.0.0.1 by default; pack upload is localhost-only; Word exports use private temp files removed after download.
- Hash-pinned `requirements.lock`; installer and updater install from it with `--require-hashes`.
- Container image (non-root, read-only filesystem, loopback publish) with `docker-compose.yml`; CI adds pip-audit, an SBOM and an image scan; Dependabot for pip, actions and Docker.
- `SECURITY.md` (disclosure policy), `LICENSE`, this changelog.

### Features
- Advanced settings tab: add your own policy packs from a JSON bundle, the three pack files, Terraform for the zscaler/zia provider or a ZIP; they are validated, kept in `user_packs/` (the `/data` volume in the container) and offered everywhere the app offers a pack. Download any pack as one JSON file.
- Detection validation harness (`tools/validate_detection.py`) and reviewer report; predefined dictionaries resolve by API or display name.
- Assessment runs checks in parallel, streams results first, reports a stuck check instead of hanging, and measures the journey afterwards.
- Partial scans: checks, report sections and plan items the API client cannot read are marked as not permitted; results say what a full scan or a configuration change needs.
- Best Practices & Benchmarks card: best-practice alignment grade per area, DLP programme stages, frameworks incl. NIST CSF 2.0 and GLBA.
- Data Flow Map: the exact path a transaction takes through Client Connector app and forwarding profiles, PAC, SSL, URL filtering, app control, file type control and DLP, per policy pack.
- Source Code to AI pack rebuilt from the v4.14 pattern library (13 languages, Anchor AND Signal); rebuild from the tenant's own dictionaries.
- Global Banking Baseline pack; Deploy Policy Packs flow diagram in its own tab; assessment results in their own tab; SSL Inspection Flow shows Client Connector bypasses.
- Every report section opens by default; the compliance card shows all frameworks when none is ticked.

## Earlier
- Deploy Policy Packs with channel choice and undo, tenant profiles, Terraform hand-off, app update from the UI, SSL Inspection Flow, Bypass report, DLP efficacy, Best Practices library, healthcare / CUI / CJIS / Fed / ZBP packs.
