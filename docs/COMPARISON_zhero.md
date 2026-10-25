# DLP-Check vs ZHERO

A function-by-function comparison of DLP-Check and ZHERO (zhero.ai, Zhero
Srl), written 2026-10-25 against DLP-Check `main` plus the phase 1 work in
progress (badges and side panel, shadowed rules, Excel/PDF, HAR import and
audit timeline).

**How ZHERO was assessed.** ZHERO's extension is closed source. Its
behaviour below comes from its own public documentation
([zhero.ai](https://zhero.ai/), [help.zhero.ai](https://help.zhero.ai/docs/setup/))
and is the vendor's description, not verified. Its seven open-source tools
([github.com/zscaler-hero](https://github.com/zscaler-hero)) were read in
full (never run), so what is said about them is verified against their code.

Status key: **Same** (DLP-Check does it), **Broader** (DLP-Check does more),
**Partial**, **Phase 1** (being built now), **Missing**, **By design**
(deliberately different).

## 1. ZHERO's functions, one by one

| # | ZHERO function | What it does (per ZHERO) | DLP-Check equivalent | Status |
|---|---|---|---|---|
| 1 | Smart entity badges | Badge on every console object with a usage counter, 18 entity types | Extension badges on DLP dictionaries, engines and rules in the ZIA console (`browser_extension/console.js`) | **Partial**: DLP objects only |
| 2 | Drill-down views | Click an object to see what references it | Side panel: uses / used by, pack, findings (`panel.js`); Deployment flow graph; removal usage check | **Partial**: DLP only |
| 3 | ZIA analysis templates (19) | Named checks on ZIA configuration | Assessment: 300+ checks across DLP, SSL, URL filtering, Cloud App Control, firewall, ZCC, GenAI, ZDX, ZIdentity, RBAC (`dlp_assessment_full_auto.py`, `zscaler_full_checks.py`) | **Broader** |
| 4 | ZPA analysis templates (15) | ZPA checks (unreachable policies, unused segments, ...) | A few ZPA checks in the assessment | **Missing** (ZPA depth) |
| 5 | Unreachable-policy checks (28 variants, 18 entity types) | Policies that never trigger because of precedence | SSL shadowing (`ssl_flow.py`); DLP, URL filtering, Cloud App Control and firewall shadowing (`shadow_rules.py`) | **Phase 1** |
| 6 | ZCC checks (24) | Client Connector configuration checks | Strict ZCC evaluation: app and forwarding profiles, fail-open, notifications, privacy, devices (`zcc_evaluation.py`) | **Same** |
| 7 | Background scanning | Continuous in-browser analysis | Continuous evaluation loop and digest (`continuous_eval.py`), Beacon for SDK/API/Terraform changes | **Same** (server-side, scheduled) |
| 8 | Auto-fix (12 templates) | Fix staged in Pending Changes | Fix recipes in Review & remediate: plan → approve → apply → verify → undo (`remediation.py`) | **Same** |
| 9 | ZIA troubleshooting engine | Traffic flow through 11 policy layers, Sankey view | Path analyzer: Client Connector profile, forwarding, PAC, Cloud App Control, URL, SSL, File Type, DLP, incident; Flow animator | **Same** (DLP deeper) |
| 10 | HAR file analysis | Analyse a browser capture | HAR import into the Path analyzer, parsed in the browser | **Phase 1** |
| 11 | ZIA Insights queries | Per-user traffic logs, traffic per rule | Live DLP feed covers Workflow Automation DLP incidents only | **Missing** |
| 12 | ZPA diagnostics engine | Drill-down by user or domain | None | **Missing** |
| 13 | Advanced exports (15+ Excel/PDF) | Firewall, SSL, URL filtering, ZPA access policy, app segments, audit trail, pending changes | Word report, CSV, Markdown, JSON, JSON pack, Terraform; Excel (assessment, DLP inventory, plan) and PDF (plan) | **Phase 1** for Excel/PDF; firewall and ZPA exports **Missing** |
| 14 | URLs export | URLs from custom categories, firewall rules, PAC files in one workbook | Bypass report (CSV/Markdown) lists bypasses and PAC exceptions | **Partial** |
| 15 | Pending changes (personal queue) | Stage edits, review, apply through the console session | Deploy and fix flow with preflight, plan hash, typed confirmation, verify and undo; the extension's Staged view exports | **By design**: writes stay in the app |
| 16 | Shared team queue | Team members see and approve each other's staged changes | SSO with writer groups; no shared queue | **Missing** |
| 17 | PDF of pending changes | Change-board review | Deployment plan as PDF and Excel | **Phase 1** |
| 18 | Unified audit timeline | ZHERO activity plus the Zscaler audit log, field diffs, 30-day default | Audit timeline: ZIA admin audit log plus DLP-Check deployments and object writes, field diffs, changes by others to pack objects | **Phase 1** |
| 19 | Security posture dashboard | Score, gauge, radar | Maturity score, section scores, radar chart, journey across visits | **Same** |
| 20 | Runs inside the console with the admin's session | No API client to set up | Separate local app with an API client (OneAPI or legacy ZIA API); the extension brings it into the console | **By design** |
| 21 | Optional OneAPI client | URL lookups and Client Connector profiles | OneAPI and legacy ZIA API, profiles, keychain storage | **Same** |
| 22 | Collaboration, MSP partner portal, licensing | Team accounts, partner management, per-tenant licence | Tenant profiles (multi-tenant), SSO with allowed and writer groups; free and open source | **Partial** (no MSP portal) |
| 23 | Open-source ZPA app-segment editor | Bulk-edit ZPA segments and policies via JSON | None | **Missing** (ZPA) |
| 24 | Open-source ZCC tools | Mass device removal, fleet dashboard, DNS forward zones | None (Client Connector is assessed, not administered) | **Missing** (out of scope) |
| 25 | Open-source ZIA custom-category analyzer | Which custom-category URLs Zscaler already categorises | URL lookup inside the bypass report and Path analyzer only | **Partial** |
| 26 | Open-source whitelist subnets, ZPA mini-SIEM | Allow-list builder; ZPA log collector and dashboard | None | **Missing** (out of scope) |

## 2. DLP-Check's functions ZHERO does not document

ZHERO's catalogue has no DLP-specific analysis or export; DLP appears only
as one layer of its traffic trace.

| DLP-Check function | Where |
|---|---|
| Policy packs: preflight, approve, deploy, verify, undo, selective removal with a usage check | Deploy policy packs (`pack_deploy.py`, `pack_removal.py`) |
| Export from tenant: dictionaries, engines and rules separately, as a JSON pack, Terraform or both | `pack_export.py` |
| Terraform hand-off (static and gap mode) and Terraform for every pack | `pack_terraform.py` |
| DLP efficacy: sample content against the tenant's dictionaries and engines, which engines fire and near misses | `dlp_efficacy.py`, `corpus_engines.py`, Flow animator |
| FP/TP detection ratio: noisy, dead and promotable rules from Workflow Automation incidents | `detection_health.py` |
| Live DLP feed with the DLP chain animated | `report_live.html` |
| Regulatory and compliance mapping | `compliance_mapping.py` |
| Migration from Symantec, Forcepoint, Netskope and Skyhigh DLP, with an efficacy percentage | `vendor_migrate.py` |
| Evaluate All Rules migration wizard | `rule_migrator.py` |
| Traffic flow and gaps, bypass report, SSL inspection flow | `data_flow.py`, `bypass_report.py`, `ssl_flow.py` |
| Log analyzer for Client Connector log bundles and PAC files | `log_analyzer.py` |
| Word report for the customer | `report_docx.py` |
| Beacon: SDK, API and Terraform provider drift | `beacon.py`, `upstream_check.py` |
| MCP server for AI agents | `dlp_mcp_server.py` |
| Runs on your machine or your container; no vendor cloud, no telemetry; open source | whole app |

## 3. How ZHERO calls Zscaler

**The extension (vendor documentation, not verified).**
1. The admin signs in to the Zscaler console as usual. ZHERO checks its
   licence with its own service using the tenant name.
2. Configuration is read "through your own session": the extension calls
   the tenant with the admin's signed-in console session, not with an API
   client. The exact endpoints and their order are not published.
3. Optionally, a ZIdentity API client (OAuth client credentials, 60-minute
   token) is used for URL lookups and Client Connector profiles. It needs
   ZIA Full Read Only and ZCC Super Admin.
4. Analysis runs in the browser on what was read.
5. The audit timeline reads the Zscaler audit log "live through your own
   session" (30 days by default) and keeps field diffs locally for 30 days.
6. A change is staged in the browser's local storage, then executed through
   the same session; executed entries are also recorded in ZHERO's cloud.
7. Outside the tenant: the licence check, LaunchDarkly (admin e-mail and
   customer name) and Sentry (error reports).

What sets this apart is the session reuse: no API client to set up, the
admin's own permissions, and whatever the console itself can read. The
cost is that the extension acts with the admin's full rights through
undocumented console endpoints that can change without notice.

**The open-source tools (verified in their code).** Every one that calls
Zscaler signs in with OneAPI client credentials
(`POST {identity}/oauth2/v1/token`, audience `https://api.zscaler.com`) and
calls `https://api.zsapi.net`:

| Tool | Sequence |
|---|---|
| zia-custom-category-analyzer | token → `GET /zia/api/v1/urlCategories/lite` → `GET /urlCategories/{id}` per custom category → `POST /urlLookup` with 100 URLs per call, 2 s apart, one retry on 429 → CSV/XLSX |
| zcc-mass-force-remove-tool | token → `GET /zcc/papi/public/v1/getDevices` (paged, read twice because paging is unstable) → resolve and re-check not-found users → check the rate-limit budget from the response headers → `POST /forceRemoveDevices` or `/removeDevices` → `GET /getDevices` again to verify and flag re-enrolled devices |
| zscaler-client-hostnames-dns-forwarder | token → `GET /zcc/papi/public/v1/downloadDevices` (CSV) → Unbound forward zones |
| zpa-json-appsegment-editor | token → `GET /zpa/mgmtconfig/v1/admin/customers/{cid}/application` → edit → `PUT /application/{id}` or `POST /application`; policies through `.../policySet/rules/policyType/{type}`, the v2 IdP and SCIM group endpoints, `PUT .../policySet/rules/{id}/policyType/{type}`, `POST /zpa/mgmtconfig/v2/.../policySet/{psid}/rule` |
| zscaler-retrieve-whitelist-subnets | no sign-in: `config.zscaler.com/api/<cloud>/hubs/cidr/json/recommended`, `/future/json`, `/zpa/json`, `/svpn/json` |
| zpa-status-mini-siem, zcc-fleet-tracker | no API: ZPA log streaming over syslog, and Client Connector portal CSV exports |

To see the extension's exact calls on your own tenant, open the browser's
developer tools (Network tab) while using ZHERO; ZHERO's FAQ points to the
same check.
