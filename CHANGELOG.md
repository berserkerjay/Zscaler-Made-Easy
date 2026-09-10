# Changelog

The app shows its build (git commit) in the guide's *Build* badge and at
`GET /api/health`. Updates are fast-forwards of `main`; this file lists
what each batch of changes did, newest first.

## 2026-09-11

### Packs
- Fed Policy Pack 2.0 absorbs the CUI Marking Baseline: the 28 tiered marking dictionaries and their block/caution/monitor rules now ship inside the Fed pack, enhanced with the V1.1 contextual phrases, Registry category names and declassify-date patterns as tier 7 (`CUI-Detect-Contextual`, monitor only). The V1.1 `CUI Engine (High/Medium/Low Confidence)` engines, their eight dictionaries and the orphan `AEA Medium Confidence` engine are gone. `cui_marking_baseline` is removed; a tenant that deployed it keeps its objects and the Fed pack adopts them by name.
- `tools/pack_from_design.py` can regenerate a design that lives inside a hand-authored pack (`"designs"` in `pack.json`).

### Packs
- `zbp_endpoint_dlp_baseline` removed: every pack mirrors its rules onto Endpoint DLP, so the PCI-only endpoint pack no longer adds coverage.
- Wording: everything is a **policy pack** now (the word "baseline" is gone from the UI, docs and pack names; ids, JSON keys and the provenance tag are unchanged). `Global Banking Policy Pack`, `Healthcare PHI Policy Pack`, `ZBP Enterprise Policy Pack`, `Source Code to AI Policy Pack`.
- Preflight no longer skips an engine (and every rule behind it) because a predefined dictionary the pack references is not exposed by the tenant: the term is dropped, the engine is created without it, and the plan and warnings say which names were left out (`pruned`). This is what stopped the Global Banking pack on tenants without the EU/APAC passport and IBAN predefined dictionaries.

### Removal
- SaaS Security API rules are now actually deleted: the delete call carries the rule's `ruleType`, which the API requires; without it every SaaS row failed.
- After the final activation the removal re-reads the tenant and reports any object it still lists as **still present** (the removal is not called complete until nothing is left), instead of trusting the delete calls.

### Traffic Flow & Gaps
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
