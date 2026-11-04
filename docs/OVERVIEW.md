# What Zscaler Made Easy does — an overview

**Open source.** Zscaler Made Easy is open-source software under the Apache License 2.0 (see LICENSE). It is built entirely from information provided by Zscaler (its public documentation, public API and open-source SDKs and Terraform providers) and by third parties. It is an independent project, not an official Zscaler product; Zscaler and related marks belong to Zscaler, Inc.

This page is for someone who has just been handed the app: what it is
for, what each part does, what it never does, and where it stops. It
takes five minutes to read. To install it, see [INSTALL.md](../INSTALL.md);
for a first engagement step by step, see
[GETTING_STARTED.md](../GETTING_STARTED.md).

## In one paragraph

Zscaler Made Easy connects to a customer's Zscaler tenant with API credentials
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
  Authenticate only signs in (it reads none of the tenant's configuration)
  and answers "Signed in" or a plain reason why not; right after it, the
  readiness check (see Required API access) says what the API client can do.
- **Sample tenant and snapshots** (on the Connect page, under the tenant
  profiles, and in Simple mode's Connect task) — *Try with a sample tenant*
  uses Larkspur Freight, a made-up company with DLP dictionaries,
  engines and rules on every channel, URL filtering, SSL inspection,
  Cloud Firewall, Cloud App Control, Client Connector profiles, ZPA
  segments and policies and ZDX applications. Every page works on it, and
  a banner on every page says "Sample tenant: nothing here is real".
  Every builder (each Build new type, the POV build, policy packs and the
  Bulk changes types) makes its full plan and dry run on the sample and on
  an opened snapshot, labelled "Rehearsal — nothing was written": the
  sample carries the catalogues the builders read, and a snapshot keeps
  them for the products in scope. Applying is refused there with a plain
  message, before any client is built. *Save a snapshot* reads the live
  tenant (read-only, only what is in scope) into an owner-only file kept
  beside the profile, with no credentials and no secret field values in
  it; *Open* uses it offline and read-only, *Compare with the live tenant*
  says what was added, removed or changed since. The sample and a
  snapshot are served by clients with no network code, so they can never
  reach a tenant; a snapshot file opened from disk is checked as
  untrusted (size, nesting, format, every path).
- **Assessment results** — the full results in their own tab: Summary
  (score and maturity), Scores by section, Best practices and
  benchmarks, Regulatory alignment, the Data governance journey, and
  Detailed findings with a fix for each, in four plain sentences apiece.
- **What does everything do?** — every function explained in plain
  English, in first-engagement order, with a glossary.
- **Find anything** (Ctrl+J or Cmd+J, `/` outside a text field, or the
  Find button on every page) — one search box over the app's pages and
  what they do, the glossary words (with the plain meaning inline), the
  tenant's objects from the last console index the app read, the findings
  of the assessment on screen and the open to-dos. It forgives typos
  ("terrafrom") and knows common synonyms ("block" and "deny", "tf" and
  "Terraform"). Typing never reads the tenant: *Load tenant objects* reads
  it once, read-only and only what is in scope. An object opens as a card:
  what it uses, what uses it, its findings, the pages that act on it and
  its tags, to-dos and comments.
- **Help marks** (every page, and the browser extension's popup,
  options and side panel) — a small raised `?` after a page title, a
  sidebar item or a control whose name does not say it all opens what it
  does, what input it expects (format, allowed values, an example,
  required or optional) and whether it reads or changes the tenant; a
  control that changes the tenant says it needs write mode. A `*` after
  an item from the newest two releases opens "New in the <date> update"
  and what it is (`static/whats_new.js`; *Hide new marks* in Advanced
  settings). Each mark is a 24px button named "Help: <item>" or "New in
  this version: <item>": pointing at it, a click, a tap, or Enter or
  Space opens it; Esc or a click elsewhere closes it, one at a time.
  Pointing at, or tabbing to, the control itself opens nothing. The
  words live in one catalogue (`static/help_catalog.js`), keyed per page
  by selector; a native tooltip is converted into it, not kept beside
  it, and a test fails, naming the page and the selector, when a control
  has no entry, or no mark and no recorded reason it needs none.
- **Glass effect** (every page; on by default, switched off per browser
  under Advanced settings → Appearance) — the bars, sidebar, cards,
  dialogs, pop-ups, banners and buttons are one translucent material
  (`static/glass.css`, driven by the theme tokens): a blurred, saturated
  tint over a soft background, a light rim and a soft shadow. Text keeps
  WCAG 2.2 AA contrast against the worst case behind each surface, tables
  stay near-opaque, and surfaces turn solid and unblurred when the system
  asks for reduced transparency, more contrast or forced colours, when
  printing, and in browsers without `backdrop-filter`. The pointer-follow
  highlight (`static/glass.js`) is off under reduced motion.
- **Simple mode** (`/simple`, first item in the sidebar) — the same app
  as seven big tasks for someone with little Zscaler knowledge: connect,
  check how safe the data is, fix the top three problems, protect
  sensitive data with a policy pack, why was something blocked (the Path
  analyzer's answer in one sentence), what changed, and a Word or
  spreadsheet report for the boss. One question per screen, a
  tap-to-explain glossary, traffic lights with the words always shown,
  and one recommended next step. It never writes: deploying and fixing
  open the expert flows (Deploy policy packs, Review & remediate) with
  their own write mode, preview and confirmation. "Switch to expert mode"
  goes back; the browser remembers the choice.

- **POV planner** (`/report/pov`, `pov.py`) — one customer proof of value
  per saved tenant profile, kept in the profile's folder (`povs/` beside
  the profiles, owner-only, no secret) and bound to the profile's tenant (a
  sign-in or an imported file naming another tenant is refused). The Plan
  tab holds the intake (customer, internal domain, a short prefix made from
  the name, a vertical preset: Healthcare, Financial services, General
  enterprise or Education, and the products in scope), the customer's
  success criteria linked to the tests that prove them, and the timeline.
  The Runbook tab lists tests per product (URL filtering, threat, cloud
  apps, firewall, DNS, DLP, SSL, ZPA, ZDX) with steps, the expected result,
  pass or fail, notes and evidence; *Prove it* runs the Path analyzer on
  the test's destination (read-only, only what is in scope) and records
  whether the configuration gives the expected result, and *Read Insights
  counts* records the Traffic insights counts (no user rows). The Test kit
  tab serves synthetic DLP files per vertical (published test card numbers,
  SSNs from the reserved block 987-65-4320 to 4329, specimen identifiers,
  from `corpus_engines.sample`), the EICAR test file and links to the
  EICAR and AMTSO test pages, and a harmless PDF that is new on every
  download for Cloud Sandbox. The Report tab writes a Word or PDF customer
  report from what actually ran (tests with a result, criteria, evidence,
  the latest counts and the changes the app's deployment and bulk-change
  records show for the tenant since the POV began), exports and imports
  the POV (an untrusted file: size, JSON depth, format and every field
  checked) and keeps templates (vertical, products, criteria; never the
  customer). Its Build tab is the one place it changes the tenant, only
  through the Build new builders and their gates (`pov_build.py`): after
  the intake it suggests the parts the POV needs (ZIA security baseline,
  SSL certificates, ZPA connector group, segments and policy rules, Client
  Connector profiles, ZDX probes, AI Guard routing and detection policy)
  with each builder's safe defaults for the vertical preset, plans them as
  ONE dry run (a section per product, every object before and after, one
  plan hash over every part) and applies them with ONE typed confirmation
  (`APPLY <n> POV CHANGES`) in a safe order, what other parts use first.
  Write mode, a writer, the named assessor and the Scope rule per part
  hold; the whole plan is read again first, then each part right before it
  is written, through its builder's own checks, read back, audited and
  recorded with its Undo. The first part that does not apply stops the run;
  Undo reverses what was applied, latest first, as one more dry run and
  confirmation. New objects arrive disabled or monitor-only unless chosen
  otherwise. On the sample tenant or a snapshot it is a rehearsal. A
  preset's builder defaults are data (`pov_build.PRESET_DEFAULTS`, or the
  preset's own `build` entry in `pov.VERTICALS`). Simple mode links to it.

### Find the gaps

- **Traffic flow & gaps** — the path the tenant's configuration gives a
  user's web traffic to each traffic class, for any user (Client Connector
  app and forwarding profile, PAC, Cloud App Control, URL filtering, SSL
  inspection, File Type Control, Web DLP), with the points on those paths
  where inspection is lost, visibility by cloud-app category, and each
  policy pack's rules overlaid by name. Configuration only: no traffic is
  observed.
- **ZPA analysis** — the ZPA configuration read once (only when ZPA is
  ticked on the Scope page, with the ZPA customer ID) and checked by the
  ZPA analysis templates: unreachable access rules, segments nobody
  reaches or only deny rules reach, overlapping segments, over-broad
  domains and ports, bypasses, server and connector groups that cannot
  serve, connector redundancy and versions. It reads every ZPA policy
  type (access, timeout, client forwarding, inspection, isolation,
  redirection, privileged credential and capabilities, browser
  protection), AppProtection profiles and custom controls, application
  servers, business continuity, Private Cloud and Branch and Cloud
  Connectors, and checks web segments nobody inspects, inspection profiles
  that only monitor, custom controls never attached, client forwarding
  that bypasses a sensitive segment, Privileged Remote Access clipboard
  and file transfer, unrecorded sessions and shared credentials,
  redirection to service edges that cannot serve, Browser Access with no
  isolation or browser protection, and business continuity with nothing
  to fail over to. The assessment runs the same checks as ZPA.16 to
  ZPA.21. Business continuity keys and certificates are never kept. The Overview tab says the
  counts in plain sentences (segments nobody can reach, connectors down or
  outdated, rules that never decide), draws the infrastructure map from
  users and IdPs through access rules, segment groups, app segments and
  server groups to connector groups and App Connectors (large tenants are
  grouped per column; a click on a box filters the tables of every object)
  and exports it all as Excel. Diagnose answers, for one
  user and destination, which app segment matches, what serves it and
  which access rule decides, with every earlier rule and why it did not
  match. Read-only; Stop ends the read at once.
- **Device posture** — the ZPA posture profiles, trusted networks and
  access rules read once (only when ZPA is ticked on the Scope page; the
  Client Connector trusted networks too when Client Connector is ticked).
  Each posture profile is sorted into a family (domain join, EDR or
  antivirus, certificate, disk encryption and hygiene, OS version, mobile
  integrity, MDM, firewall, process, marker or override, unknown), marked
  as reliable (from the posture type) or inferred (from the name); markers
  never count as enforcement. Each profile and network lists the rules
  that use it, as must pass or must fail. Findings name allow rules to
  sensitive or broad apps with no posture check, negated checks that let
  failing devices in, marker-only and optional checks, and unused
  profiles. Every access rule is shown as nested AND, OR and NOT groups
  with names instead of IDs, plus one plain sentence. Excel and JSON
  exports. Read-only; Stop ends the read at once.
- **Path analyzer** — type a URL, hostname or IP address and see, live
  from the tenant as it is right now, every step the traffic takes, the
  rule that decides each one, one verdict in plain words (definite or
  conditional), and every rule or profile that blocks or impacts it, each
  with a fix. The steps are walked in the order they apply. **ZPA first**
  (ZPA ticked): the most specific application segment (exact name,
  longest wildcard, longest address range) with its port, the segment's
  bypass setting (Never, On-Net, Always), the client forwarding policy
  (Intercept, Intercept accessible, Bypass) and the access policy, with
  device posture answered both passing and failing; a destination ZPA
  carries is not traced through ZIA. Then **Client Connector**, every
  bypass in order with the one that decided named (`zcc_bypass.py`): the
  app profile's VPN gateway bypass, its host name and address bypasses,
  its IP-based application bypass (the predefined and custom IP-based
  applications it names, read with their addresses, ports and protocols),
  the application bypass by name, then the forwarding mode for the
  protocol and port traced (Z-Tunnel 1.0 carries web traffic on TCP 80
  and 443 only, Enforce proxy web traffic only, Z-Tunnel 2.0 every port
  and protocol except its own destination exclusions, and only its
  inclusions when they are limited; a host name limited inclusions would
  need resolved is unknown), and the **PAC file**, evaluated for the destination
  (`pac_eval.py`: parsed and interpreted, never run; anything outside the
  PAC subset says "could not evaluate safely") and classified DIRECT,
  Zscaler or another proxy. Then **every ZIA module**, one by one (the
  page does not claim the cloud's enforcement order: Advanced Threat Protection, Cloud Firewall, DNS
  Control, Cloud App Control and URL filtering, Sandbox, File Type Control
  and DLP, with SSL inspection deciding what later modules see), and last
  **Forwarding control**: the ZIA forwarding rule that sends allowed traffic
  on (direct, proxy chaining, ZPA, a dedicated egress IP, or dropped), with
  the gateway's fallback, any NAT control rewrite, IPv6 and data centre
  exclusions (`zia_forwarding.py`; the FWD.* checks assess the same objects
  tenant-wide: proxy chaining, ZPA and dedicated IP gateways, GRE VIP
  diversity, IPv6, NAT control, Virtual Service Edges, DNS gateways). Every
  step has the same shape: its deciding rule and order, the other rules
  that also match, the earlier rules that could decide instead, and every
  criterion as match, no match or unknown (`zia_path_modules.py`,
  `zpa_path.py`, drawn by `static/path_modules.js`). An unread condition
  never matches: each module lists the rule fields it evaluates and the
  ones known not to restrict a match, and any other non-empty field (one
  a newer API adds, say) is an unknown criterion (`rule_fields.py`;
  every field of the SDK 1.11.3 models is classified). Zscaler's
  predefined UCaaS and Microsoft 365 one-click rules follow the one-click
  switches, read with the Cloud Firewall (`ucaas_oneclick.py`). An app
  service group (the Office 365 One Click rule's OFFICE365, whose members
  the ZIA API never returns) is matched by host name and address against
  Microsoft's published Microsoft 365 endpoint list when one is kept and
  current (`app_services.py`, `m365_endpoints.py`), saying which set,
  version and date decided; otherwise it stays unknown. A protocol and port
  (UDP/443 is QUIC, TCP/22 is SSH) trace traffic that is not web.
  **Traffic from a workload** (Cloud & Branch Connector ticked) takes a
  source IP, tags, workload group and connector group: the connector's
  forwarding rules decide first (ZIA, ZPA, direct, local switch, proxy
  chaining or drop), then ZIA or ZPA (`workload_path.py`). **What-if**:
  optionally give a user, group, department and location (looked up in
  ZIA only with ZIA platform in scope, 20 names at most per search);
  rules scoped to them apply and rules for others are skipped, and every
  result lists what the policy action also depends on: each scoped
  condition that would change it, with the rule and the action it would
  give (`path_whatif.py`). A **ZPA identity** can be given too (ZPA
  ticked): the IdP the user signs in with, a SCIM user name whose SCIM
  groups ZPA lists for them (read-only, looked up during the run and kept
  only for it; a filter ZPA did not apply leaves them unknown) and SAML or
  SCIM attribute values typed as Name=value. ZPA's access policy is then
  evaluated for that identity (operands joined by the condition's
  operator, negation, the rule's operator, rule order, default deny; a
  condition of another IdP is not met), anything not given stays unknown,
  and the verdict names the identity condition that decided
  (`zpa_identity.py`; the pickers are `POST
  /api/path-analyzer/zpa-identity`). **A user's device** (Client Connector
  ticked, a OneAPI sign-in): look a user's enrolled devices up in the
  Client Connector Portal (one call filtered by user name, at most 20) and
  pick one; the trace then uses that device's platform, the app profile
  the Portal reports for it and its client version, says which app and
  forwarding profile applied and why, and says "unknown" for what the API
  does not give (the network it is on now, its ZPA posture results)
  (`path_device.py`). **Compare two identities** runs the same destination
  for A (the what-if and device) and B on one tenant read and shows every
  step side by side, the step where they diverge marked, with CSV and JSON
  downloads (`path_compare.py`). **Test from here**, after a result and
  only on an explicit click, tests the destination from the computer
  running the app (in Docker, the container's network): a name lookup, a
  TCP connect and a TLS handshake (certificate issuer, subject and names,
  TLS version), compared with the prediction; it sends no request or data,
  only to ports 443, 80, 8443 and 8080, never to this computer or cloud
  metadata, at most 6 a minute, and keeps nothing (`path_probe.py`; threat
  model in SECURITY.md). The analysis is one request,
  `POST /api/path-analyzer/start` (or `POST /api/path-analyzer` for
  scripts). It reads only what is in scope on the Scope page (a part out
  of scope says "not in scope"), writes nothing, and Stop ends the read
  at once. **Import a HAR file** there to analyze every host a browser
  session reached in one run: the file is read in the browser and only
  host names, request counts, HTTP methods, schemes and upload amounts
  are sent (cookies, headers, URL paths and bodies stay in the browser);
  the results table sorts,
  filters, opens any host's full analysis and exports as CSV or JSON.
  **Test a list** (a tab on the same page) does it for a whole list: a
  CSV or pasted list of IP addresses, CIDR blocks (up to a /16 per row),
  ranges, hosts and URLs, up to 250,000 rows, with optional port,
  protocol, source IP, location, country, category, user, group,
  department, a ZPA identity (idp, SCIM user and attributes columns),
  label and what each row is expected to do (block or allow). Each row gets the answer the single-destination analyzer
  gives: ZPA first when ticked, then every ZIA module for the row's
  protocol and port, its identity and its source IP. The tenant (and
  ZPA) is read once, ZIA's URL lookup is asked a hundred destinations per request,
  paced for ZIA's rate limit (a quota that runs out labels the rest
  "rerun later"), and a category in the file overrides the lookup. You
  get counts (blocked, allowed, bypassed, isolated, caution, allowed but
  blockable), the top deciding rules and categories, the rows to look
  at, for each row that misses what was expected the area to fix it in,
  from the module that decided the row (ATP, Cloud Firewall, URL
  filtering, DNS Control, Client Connector, Cloud App Control, ZPA) with
  advice per category, a list per area to paste (an IP destination group
  for the Cloud Firewall, a custom URL category for URL filtering, the
  segments to change for ZPA), and CSV and Excel downloads.
  Fix selected opens Bulk changes with the picked destinations filled in
  as a URL category change; it writes nothing on its own.
  **Category lookup** (the third tab, `category_lookup.py`): up to 25
  URLs, hosts, IP addresses or categories; for each, its ZIA categories,
  predefined and custom (ZIA's URL lookup and the tenant's own category
  lists), the cloud application, any security alert, the custom
  categories that list it, and every rule across URL filtering, Cloud App
  Control (by application), SSL inspection, Cloud Firewall (directly or
  through an IP destination group), DNS Control, File Type Control, Web
  DLP and Sandbox that names each category, in evaluation order with
  order, rank, action and state. A Test a list row's Categories button and
  Find anything (for a host) open it. Read-only, only what is in scope.
  Fix selected opens Bulk changes with the picked rows filled in, each for
  what it was expected to do: URL filtering and Cloud App Control rows as a
  URL category change, Cloud Firewall and DNS Control rows as **Fix rows
  from Test a list** (IPv4 addresses, blocks and ranges into an IP
  destination group of type IP, host names into one of type FQDN, then an
  existing Block or Allow rule or a new one created disabled above the rule
  that decided the rows; no IPv6, which ZIA's API has no user-defined group
  for), ATP rows onto the security policy denylist or allowlist; rows ZPA or
  Client Connector decide are left out with the reason. It writes nothing on
  its own: the preview says each change in plain words and links to its
  rows, applying goes through Bulk changes' four gates, re-read, read-back
  and Undo, and afterwards *Prove it* tests the same rows again and says
  which now do what was expected.
  The **ZDX panel** (ZDX ticked) shows the path ZDX measured to a ZDX
  application from a device that probes it, leg by leg (device, network
  exit, Zscaler service edge, application) with time, loss, hops and the
  tunnel, without naming the device and with private hops hidden
  (`zdx_insights.py`). It also starts a ZDX score analysis (root cause) on
  one device: no setting changes, but it needs write mode, a writer, the
  assessor's name and START ANALYSIS, and starts are rate-limited per tenant
  (one every 5 minutes, 6 an hour) and audited.
- **Shadowed rules** — reads the rules of every policy in scope (Inline
  Web, Endpoint, Email and SaaS DLP, URL filtering, Cloud App Control, SSL
  inspection and, with ZIA platform ticked, Cloud Firewall) and lists the
  rules that can never match or never act: hidden below a broader rule or
  a catch-all, duplicated, superseded by a stricter rule (where every rule
  is evaluated), disabled, or naming engines and categories that no longer
  exist; each with the rule that hides it, the reason and the fix, and CSV
  and JSON exports. A criterion it cannot compare safely counts as "not
  shadowed". Read-only; Stop ends the read at once.
- **Browser security** — Zscaler Zero Trust Browser and ZIA Browser
  Control, read only as far as the Scope page allows (ZIA platform for
  ZIA, its Cloud App Control rules only when Cloud App Control is marked
  Zscaler, ZPA for ZPA with a OneAPI API client and the customer ID): every
  isolation profile's controls (copy and paste, upload and download,
  printing, watermark, debug mode, local rendering, session persistence)
  beside the URL filtering, Cloud App Control and ZPA isolation rules that
  use it; Browser Control (allow all browsers, older versions not blocked,
  smart isolation); and the ZPA browser side (Browser Access segments and
  the access rules that reach them, managed browser profiles, browser
  protection, Privileged Remote Access portals and consoles, user
  portals). Findings in plain English with a severity and a fix, focused
  on data protection (a permissive profile used for GenAI or unsanctioned
  apps is high), a glossary of every control, the assumptions, and an
  Excel or JSON export. It never shows the debug file password, a
  certificate body or the people in the configuration, and says that the
  standalone Zscaler Enterprise Browser has no API. Read-only; Stop ends
  the read at once.
- **Cloud & Branch Connector** (`/report/ztw`, `ztw_overview.py`) — the
  Cloud and Branch Connector configuration read once (only when Cloud &
  Branch Connector is ticked on the Scope page, with a OneAPI API client):
  connector groups and their connectors (deploy type, location, software
  versions, operational and upgrade status, upgrade window), the traffic
  forwarding rules and where each sends workload traffic, forwarding
  gateways, connector locations and location templates, whether saved
  changes are activated, admin roles, admins (counted, never listed),
  provisioning API keys (age and state; the value is never read into a
  result) and public cloud accounts. Eight checks (ZTW.1 to ZTW.8, also in
  the assessment with the same key; not licensed or not deployed is not
  applicable) name single-connector groups, connectors not serving or on
  mixed versions, workload traffic sent DIRECT, gateways that do not fail
  closed, pending activation, locations without the firewall or IPS, admin
  hygiene and old API keys, each with why it matters and how to fix it.
  *Trace in the Path analyzer* opens the workload trace for a group or a
  rule, reusing the same read. Excel and JSON exports. Read-only; no
  provisioning URL is read and nothing is activated; Stop ends the read at
  once.
- **Other Zscaler products** (`/report/other-products`, `other_products.py`)
  — Zero Trust Branch, External attack surface (EASM), Business Insights,
  Zero Trust Cellular and Microsegmentation, each read only when its own
  Scope page box is ticked (all five are off by default; they need a OneAPI
  API client). For each one: what the product is in plain words, what the
  tenant has as tables (ZTB sites, templates, alarms, API key names and
  ages, hubs, the ransomware kill switch; EASM findings and lookalike
  domains; Business Insights custom applications and scheduled reports;
  Zero Trust Cellular account, regions, anomaly policies and SIM counts;
  Microsegmentation agents, agent groups, provisioning key names, policy
  and default rules, resource protection), and best-practice findings with
  why each matters, what to do and its source or "assumed". The same 20
  checks are scored in the assessment (ZTB.1–5, EASM.1–4, ZBI.1–2,
  ZCELL.1–3, ZMS.1–6). A product the tenant does not own is "not licensed"
  and not judged. Every request is built by the installed SDK's own list
  or get method; Zero Trust Cellular needs its customer ID (given on the
  page), Microsegmentation uses the ZPA customer ID unless another is given.
  Keys, secrets, tokens and provisioning keys are never shown; recipients,
  devices and SIMs are counted. Excel and JSON exports. Read-only; Stop
  ends the read at once.
- **Live motion on the Path analyzer** — under the verdict, packets travel
  the analyzed path (device or workload, Client Connector or the
  connector, ZPA turning to the App Connectors and the app when it carries
  it, the PAC file, the Zero Trust Exchange, every ZIA module, the
  destination), each step lit with its verdict and deciding rule, stopping
  with a block, drop, isolate, caution or bypass marker where it is
  decided and a dashed fork at a conditional step; a step opens its card.
  The reference path idles before any result; Test a list streams its rows
  to the step that decided them, the counts climbing from the job poll's
  tally (counts only). One engine (`static/flow_anim.js`: trafficPathModel,
  trafficPath, listFlowModel, listFlow), no tenant reads, reduced motion
  honoured, paused while the tab is hidden, every step also in words.
- **Flow animator** — the flows the app analyses, animated from your own
  results: the last Path analyzer result replayed step by step (ZPA, PAC
  file, ZIA modules and the what-if; back, next, play, pause and speed) or
  hop by hop; inside DLP, the
  dictionary match counts, each engine term against its threshold and the
  rules that act, with an engine that does not fire named as a near miss
  ("3 found, needs more than 4") or as having nothing to match; a policy
  pack plan or deployment with the deploy order replayed; DLP incidents
  as they land, enforced versus monitor-only per channel; and every flow
  of the Data Security Architect reference, with the steps people miss
  marked. Samples, labelled as such, until you have results. Read-only.
  The same engine moves the traffic on three report pages, from the result
  each already shows: the Data Flow Map (every traffic class on every
  network as a stream through Client Connector, PAC, URL filtering and
  Cloud App Control, SSL inspection, Web DLP and the incident receiver,
  each as wide as its share of the traced paths, bypasses marked), the SSL
  inspection flow (packets on its diagram, and a rule walk: the SSL rules
  a request meets in order, scoped exemptions peeling packets off, the
  deciding rule's certificate and TLS-version checks as gates) and SSL
  coverage (a traffic river of SSL/TLS against HTTP from its Insights
  numbers, and the causes as branches by their share). Each has Play and
  Pause, starts still with reduced motion and says the same in words.
  The same engine moves on four pages from the result each page already
  has (`static/flow_pages.js`): ZPA analysis (users → ZPA cloud → App
  Connector groups → app segments, links to down connectors stopped and to
  outdated ones flickering; and each diagnosis walked rule by rule),
  Traffic insights (Insights numbers as Sankey-style streams to allowed
  and blocked), the Live DLP feed (each incident through channel, rule,
  action and incident receiver) and the Bypass report (streams peeling off
  where traffic skips the Zero Trust Exchange). Still under reduced motion
  with a Play button, paused while the tab is hidden, said in words below.
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
  blocked and by location, web threats by class and super-category, the
  cloud applications in use (Shadow IT), SaaS security by application,
  firewall traffic by action, location and network service, security
  incidents by location, IoT and unmanaged device counts (now: that query
  takes no time window), and the users with the most security incidents
  (on screen only, never exported). Needs ZIA Insights ticked on the Scope
  page and a OneAPI API client. It says plainly what Insights cannot
  answer: traffic by URL category, per user, per policy rule or to one host.
- **Shadow IT and SaaS checks** (in the assessment, only with ZIA Insights
  ticked) — from the Shadow IT applications of the last 30 days: high-risk
  unsanctioned apps that still carry traffic (INS.1), high-risk apps with no
  sanction decision (INS.2) and sanctioned SaaS apps with traffic but no
  SaaS Security API tenant (INS.3), N/A without traffic or a CASB
  subscription. Application aggregates only.
- **SSL coverage** — how much web traffic is not inspected, why, and what
  to change. Causes from configuration (SSL inspection rules that do not
  decrypt, the default rule, certificate-pinned exemptions and, with ZCC
  in scope, Client Connector bypasses, direct forwarding and PAC DIRECT
  entries), each with a risk (file sharing or GenAI high; banking or
  health for privacy "expected") and a recovery step, ordered into a
  recovery plan with a safe-to-change note. With ZIA Insights in scope it
  opens with the share of SSL/TLS and HTTP traffic inspected (from ZIA's
  protocol names, mapped in one table in `ssl_coverage.py`), bytes per
  exempted application and a daily trend of all web traffic; Insights has
  no SSL or URL-category dimension and the page says so. Each run's
  summary is kept locally for a trend across runs; Excel and JSON export.
- **Bypass & non-inspected traffic** — every SSL exemption, allow rule,
  Client Connector bypass and PAC exception that lets traffic skip
  inspection, with exports. Where: opened from Traffic flow & gaps.
- **Client Connector fleet** — the Client Connector profiles, hosted PAC
  files and enrolled devices together, read only when ZCC is in scope:
  ZIA, ZPA and ZDX activity, blind spots, bypass risk, ghost devices,
  registration anomalies, multi-device users and version drift, each with
  its exact definition; a profile heatmap with equal-weight and
  device-weighted scores, a side-by-side profile diff, a PAC comparison and
  a remediation plan ranked by impact times devices, exported as CSV or one
  Excel workbook (devices, versions, operating systems, stale devices; with
  a counts-only option). Without device permission it says so and shows
  the configuration only. Read-only; Stop ends the read at once.
  **One-time passwords for a device** (help desk): one device's Client
  Connector one-time passwords (uninstall, turn a service off, exit, as
  the tenant provides them; SDK `getOtp`), found by its enrolled user and
  host name or UDID. A sensitive read guarded like a write: ZCC ticked on
  the Scope page, a person allowed to change the tenant, the assessor's
  name and SHOW OTP and the device typed, at most 5 requests in 10 minutes
  per person (`zcc_otp.py`). Shown once with a Copy button and hidden
  after 60 seconds; never stored, logged or cached; the audit log records
  who asked, when and for which device, never a password.
  It also shows service health (ZIA, ZPA and ZDX active) per Client
  Connector version, flagging a version 10 or more points below the fleet,
  and per app and forwarding profile; a quarantined tile; a last-seen
  histogram (under 1 day, 1 to 7, 7 to 30, over 30 days, never); and sites
  grouped from host names by a prefix length, a delimiter or a list of
  prefixes (never a free pattern). *Save to history* keeps a counts-only
  snapshot per tenant on this computer (owner-only file, 60 per tenant; no
  user, host, device ID or site), with a trend chart, each read's change
  and a compare of any two. Without the device permission, the Client
  Connector Portal's Device Details and Service Status CSV exports can be
  imported instead (no sign-in; untrusted files: size, row, column and
  cell caps, bounded decompression). *Report (PDF)* prints the page,
  counts only; the Excel workbook gains the new tables and the history.
  Its **Install command builder** writes the MSI, EXE or macOS install
  command and a .bat or .command script for a chosen app profile (its
  policy token is read only when ZCC is in scope); tokens and passwords
  show as ******** unless you click Reveal, and none is logged or saved.
  Its **DNS records for client hostnames** (`dns_forward_zones.py`) turn
  the fleet read's enrolled devices into one name per device,
  `<hostname>.<domain>`, sent to the ZPA client-to-client resolver you name
  (a Branch Connector, for example): Unbound forward zones, BIND forward
  zones and a zone file part, and a CSV, to download. Hostnames become RFC
  1123 labels; renames, duplicate enrolments and collisions are listed. No
  second tenant read, no DNS server contacted, nothing applied; hostnames
  are never logged.
  **One device's details** (`zcc_devices.py`) reads, by its device id, which
  services run on a device and whether they are healthy, its versions,
  strict enforcement, anti-tampering and device trust; identifiers are
  hidden and its one-time passwords never reach the answer. **Why Client
  Connector was switched off** counts the disable-reason report per reason,
  device type and service (times and people, no names), on screen or as a
  spreadsheet-safe CSV. Both only when ZCC is in scope.
- **SSL inspection flow** — for each risky traffic class, which SSL rule
  decides, whether the traffic is decrypted, and whether inline DLP can
  see it. Where: opened from Traffic flow & gaps.
- **DLP efficacy** — scores every custom dictionary and engine for
  false-positive risk and tests sample text against them.
- **FP/TP detection ratio** — what the DLP rules actually do in
  production, measured from Workflow Automation incidents and analyst
  verdicts, turned into proposals you approve, preview, apply with a
  read-back, and roll back.
- **Tenant health** (on the same page, `/report/health`,
  `tenant_health.py`) — the quiet problems, read-only and only what the
  Scope page ticks: ZIA changes saved but not activated (a deploy from
  this app would make them live too), the SSL inspection rule order (a
  broad Do Not Inspect rule above Inspect rules, a broad Inspect rule
  above the exemptions, nothing inspecting what reaches the Default
  rule), certificate expiry with a warning and a critical threshold (30
  and 7 days unless `DLP_CHECK_CERT_WARN_DAYS` / `DLP_CHECK_CERT_CRIT_DAYS`
  or the page say otherwise): ZIA's SSL inspection intermediate CA
  certificates, ZPA's enrollment certificates (with the App Connectors and
  Service Edges enrolled with each), web server and client signing
  certificates; and App Connector groups with no connector. Each signal
  comes with the plain steps to fix it. The assessment carries the same
  signals as checks HLT.1 to HLT.4, plus automatic deletion of disconnected
  connectors (HLT.5) and connector groups held on an older version profile
  (HLT.6). Only names, dates and states are kept, never a certificate or key.
  read-back, and roll back. *Incidents in depth* on the same page reads one
  incident by id (or *Details* beside a latest transaction): its details,
  what triggered it (names and match counts), its change history and its
  tickets, metadata only (the evidence is never fetched; the user, file
  name and client IP are withheld), and the Workflow Automation admin audit
  log. A noisy rule or an excluded destination links to *Close DLP incidents
  as false positives* in Bulk changes (four gates, typed phrase, the
  assessor named in each incident's note, read-back; Undo records the
  reversal because the API cannot reopen an incident).
- **AI Guard** (`/report/aiguard`, AI Guard ticked, OneAPI only) — the
  detection policies with their prompt and answer detectors, the policy
  match rules, the LLM providers, the LLM applications (whether they keep
  and encrypt prompts) and the application credentials by name (never a
  key). *Test a prompt* sends one made-up prompt from a fixed list through
  AI Guard's policy detection and shows each detector's verdict; free text
  is refused; live it needs an AI Guard API key in the server's
  `AIGUARD_API_KEY`, the sample tenant answers with a made-up detector. The
  assessment scores the same configuration (AIG.1 to AIG.7; AIG.7 reads the
  LLM provider credentials by name and date only, the key is dropped as it
  is read), plus Workflow
  Automation incidents (ZWA.1 to ZWA.4), EDM and IDM indexes (DLP.IDX1 to
  IDX3) and ZPA Browser Access and Privileged Remote Access (ZPA.BA1 to BA4).
  It also scores Endpoint DLP rules scoped to empty or deleted resource
  groups (B.17), ZPA segments inspected by ZIA without ZPA's ZIA cloud link
  (ZPA.22; only the yes/no availability is read, never the ZIA credentials
  it holds), user portals without an acceptable use policy and portal links
  on no enabled portal (ZPA.23, ZPA.24), partner integrations left disabled
  (THR.12), traffic capture rules left enabled (GOV.9) and time intervals
  that name no day (FW.10). Objects read before only for backup and
  Terraform are scored too: empty DNS application groups (FW.11), workload
  groups with no tag criteria (FW.12), HTTP header insertion profiles that
  insert nothing (CA.6), full client-to-client IP ranges (ZPA.25), expired
  or expiring isolation certificates (ZPA.26; only the end of validity is
  read) and Cloud & Branch Connector IP groups with no address (ZTW.9).
- **Digest — the evaluation loop** — when you click *Run the loop now*
  (or run `continuous_eval.py --once`) it re-reads the guidance sources
  and, for every profile that remembers its secret, only what that
  profile's Scope page puts in scope (the FP/TP ratio and the ticked
  packs' drift when DLP is in scope, the SaaS tenants when SaaS Security
  runs on Zscaler), and writes a digest (e-mail or a Teams/Slack webhook
  when there is something to decide). Every tenant read counts against
  the ZIA API rate limit, so the timer is off unless the operator sets
  `DLP_CHECK_CONTINUOUS_EVAL_HOURS`. It never writes to a tenant.
- **Improve my score** (`/report/posture`, `posture_plus.py`) — from the
  results on the assessment page: the ten fixes that raise the score most,
  each with the points it adds (the real score formula run before and
  after, so every scoreable check weighs the same and the cheapest fixes
  come first), its effort, whether a one-click fix recipe exists in
  Review & remediate, plain steps and a link to the fix; the projected
  score after the fixes you tick and the fix recipes staged in the change
  queue; the score over time from the tenant profile's history, with the
  checks that started or stopped failing between runs (history entries
  now keep each check's state, bounded; older entries still load); a
  score-drop alert (5 points by default) on the results page and in the
  digest, sent through the digest's notifications only when they are set
  up and the operator ticks it; and what the last assessment could not
  check (not permitted, rate limited, timed out, not licensed, left out by
  the Scope page), with why and how to fix it. The results page shows
  "Coverage: N% of checks ran" under the score. Reads nothing from the
  tenant.
- **Regulatory & compliance alignment** — the findings mapped to the
  frameworks the customer answers to (HIPAA, PCI DSS, NIST, CMMC, SOC 2,
  ISO 27001, GDPR, CIS, GLBA), scoped to the industry on the profile.
  Where: the Dashboard, under the findings. Its own tab can also read the
  assessment against a compliance profile (FedRAMP Moderate or High, CMMC
  Level 2, Federal Zero Trust, IRS Publication 1075, GovRAMP or a
  framework profile): each of the profile's controls met, partially met,
  not met or not tested, from the checks behind it, with a CSV.

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
  (dictionaries, engines, rules) also downloads as its own file. A
  fourth part, the **ZIA policy framework**, saves the URL filtering,
  Cloud Firewall, SSL inspection, Sandbox, DNS Control and File Type
  Control rules in scope (not the default or predefined ones) as
  `zia_policy_framework.json`, which the ZIA security baseline in Bulk
  changes applies to another tenant. Scope
  that only exists in the source tenant (users, groups, locations, ...)
  is left out and listed in the pack. Read-only; an empty pick is refused
  before any read, an hourly rate refusal fails the export, and Stop gives
  no pack. Where: Deploy policy
  packs, under the pack list; also Step 2 of the Evaluate All Rules
  migration wizard, for its Inline Web DLP rules.
- **Export from tenant as Terraform (whole tenant)** — every object the
  Scope page puts in scope, from ZIA, ZPA, Cloud & Branch Connector and
  Client Connector, as one Terraform workspace per product for the official
  `zscaler/zia`, `zscaler/zpa`, `zscaler/ztc` and `zscaler/zcc` providers.
  *Adopt* (the default) writes an import block for every object and keeps
  its state, so the platform team's first apply brings the tenant into
  state without recreating or changing anything; *Clone* writes new objects
  for another tenant with every rule disabled (and ZPA segments disabled)
  unless asked otherwise, and leaves settings and tenant-bound objects out.
  References between exported objects are Terraform addresses, the rest are
  looked up by name; no secret is ever written (sensitive variables
  instead), users are never exported, and each workspace's README says what
  was not exported and why. Read-only. Where: Policy exports.
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
- **Team server** (`/report/team`; optional, off unless `ZSCALER_TEAM_MODE=1`)
  — several people on one server. Each signs in with their own account
  (`/login`: a password, then their passkey if they have one; SAML 2.0 or
  OpenID Connect SSO matched to the account; or a passkey alone) and has a role (viewer,
  operator, approver, administrator) and access per tenant profile (read,
  plan, apply, approve) that an administrator gives on this page; nothing is
  allowed until it is given, every route has an access rule
  (`team_routes.py`) and a person sees only their tenant profiles, their
  reports and their audit entries. Wrong passwords lock an account; sessions
  end after a quiet spell (with a warning) and after 8 hours. Your identity
  provider can manage accounts and groups through SCIM 2.0. The server
  serves HTTPS itself (your certificate, a self-signed one, or Let's Encrypt
  through Cloudflare DNS) and will not serve other computers without it.
  POV templates and saved plans belong to who saved them and are shared from
  this page. On a team server the change queue's four-eyes is always on.
  Its Sign-in section sets SAML sign-in up from the identity provider's
  metadata (or typed values), tests it locally and turns it on or off, and
  can require a passkey after the password. An administrator account is
  linked to SAML only after an administrator clicks Allow SAML link on it.
  Optional in any mode: encryption of the app's stores on disk, with key
  rotation, and FIPS mode. See INSTALL.md and SECURITY.md, "Team server".
- **Change queue** — the team's shared queue of changes prepared but not
  applied: a policy-pack deploy plan (Deploy policy packs, preflight step),
  a selective removal plan (the rule picker's review) or a fix recipe
  (Review & remediate, after the preview), each filed with *Request
  approval*. A writer other than the requester approves or rejects it
  (four-eyes, on by default; `DLP_CHECK_FOUR_EYES=0` turns it off for a
  single-person install, and without SSO everyone is the same "local UI
  token", so four-eyes needs SSO). An approved request is applied from the
  queue through the same apply path, with write mode and the typed
  confirmation; the plan is checked against the tenant first and a request
  whose plan no longer matches is marked stale and nothing is written.
  Every step is in the audit log with who did it; the queue exports as JSON,
  Markdown or Excel (requests, items, approvals, comments, history).
  **Scheduled sync** (same page) keeps rules of target tenant profiles in
  step with a source profile or snapshot (Cloud Firewall, URL filtering,
  ZPA access policy; by rule label or name prefix; by hand or every 1 to
  168 hours). A run only reads and files one plan per target here, in the
  job owner's name, for another writer to approve; it never applies
  anything. Deletes only when the job asks (`sync_jobs.py`).
  Every step is in the audit log with who did it; the queue exports as JSON
  or Markdown.
- **Self-healing** — two layers on one page (`/report/self-heal`, toolbar
  *Self-healing*). *This app*: small checks fix the app's own problems and
  say what they did (a background job whose worker died or that is stuck is
  ended as failed so it can be retried; a damaged saved file is moved aside
  as `<name>.corrupt-<time>`, never deleted, and restored from its
  `<name>.last-good` copy, else started empty and flagged; secrets and
  stores others can read are set back to owner-only; locks left by a process
  that is gone are released; a ZIA rate-limit pause longer than any limit
  window is lifted; a cached sign-in that keeps failing is dropped; low disk
  space prunes the app's own old digests; an update without a restart is
  reported with a Restart button). They run at startup, every
  `DLP_CHECK_SELF_HEAL_MINUTES` (10 by default, 0 off) and on *Check the app
  now*; each run is in the audit log. Nothing here touches the tenant.
  *Your tenant*: with DLP in scope, the ticked (or deployed) packs are read
  and compared with what was approved; a rule turned off, an action made
  weaker, an engine or dictionary edited or deleted, or a fix someone undid
  becomes a heal proposal with what changed and, when Automation readiness
  is in scope, who and when from ZIA's audit log. Changes this app recorded
  (deployments, Bulk changes, applied proposals and change requests) and
  progress (a rule turned on, a stricter action) are never drift. *Heal*
  (one or many) goes through the proposal apply path: write mode, a fresh
  read that refuses if the setting moved again, the typed confirmation,
  read-back and an undo; *Accept* makes the current value the approved one
  and stops proposing it (audited). The continuous evaluation loop's drift
  step raises the same proposals. Nothing is ever applied on its own:
  `DLP_CHECK_SELF_HEAL_AUTO_APPLY` is refused in this version, pending the
  product owner's decision.
- **Bulk changes** — many changes as one reviewed plan: enable or
  disable up to 100 rules (URL filtering, SSL inspection, Cloud Firewall,
  Cloud App Control, File Type Control, the four DLP channels, DNS Control
  and IPS; DNS and IPS when ZIA platform is ticked), put one
  policy's rules in a new order with the fewest moves (the Default,
  predefined and read-only rules never move), add, remove, move or copy
  URLs on custom URL categories (with the rules in scope that use each
  one), and move or copy ZPA domains between application segments or
  clone a segment (with the domain and port overlap check), add or remove
  entries on an IP destination group (at most 8,000 per group, assumed: a
  new group past it is split, an existing one refuses the rest) or URLs on
  the ATP security policy allow and deny lists, fix the rows of the
  Path analyzer's Test a list (groups, Cloud Firewall and DNS Control rules
  created disabled, the ATP lists), and set the same fields on up to 200
  ZPA segments at once (enabled, health reporting, bypass, double
  encryption, disaster recovery mode, segment group, server groups, port
  ranges; Browser Access, PRA and inspection segments included, their
  applications kept). The preview
  reads the tenant and lists every item before and after, what is already
  as asked and what is excluded and why, with a plan PDF; applying needs
  write mode, the assessor's name and your confirmation (typed above ten
  changes), re-reads each object right before its write and skips any
  item someone changed meanwhile, activates ZIA once, reads back, and
  records the change with an Undo that is itself previewed. **Sanction or
  unsanction cloud apps** (ZIA platform and ZIA Insights ticked) marks up
  to 100 cloud applications Sanctioned or Unsanctioned: each app's state,
  risk and traffic come from ZIA Insights (the SDK's application list has
  no state), the typed phrase is always asked because the change is
  tenant-wide, an app that moved since the preview is skipped, and Undo
  puts each app back as it was; an app whose state cannot be read is not
  changed.
  Under **Build new**, **Edit a rule** (`ops_rule_editor.py`, forms in
  `rule_editor.py`) creates, edits, duplicates or deletes one URL
  filtering, Cloud Firewall, SSL inspection, forwarding control, Inline
  Web DLP, DNS Control, IPS, File Type Control, Sandbox or Cloud App
  Control rule. Each rule type has a form with only the fields its SDK
  model has, every value checked, and the tenant's categories, groups,
  departments, users, locations, labels, time intervals, network
  services, IP groups, applications, gateways and DLP engines picked by
  name. The preview says in one sentence what the rule will do, for whom,
  at which order and admin rank, and lists every field before and after.
  Placement follows Admin Ranking: when it is on, a new rule takes the
  rank of the rule it sits above (going last, of the rule just above it);
  off, unknown or out of scope, rank 7. New rules and copies arrive
  disabled unless *Create it enabled* is ticked; a copy sits right below
  its source at its rank. An edit sends the rule back as read with only
  the changed fields. A change that is live at once needs the typed
  phrase, a delete needs DELETE and the rule's name. Undo deletes a
  created rule (only while it is as created), puts back each changed
  field (only while it holds what was set) or re-creates a deleted rule
  with the same fields, order, rank and state. The same section has
  **Edit a ZPA application segment** (its settings and ports, or enable
  or disable it; ZPA applies at once, so a change to an enabled segment
  needs the typed phrase), **Cloud app instances and tenancy
  restrictions** (browse them read-only, create or edit one) and **Proxy
  chaining** (create or edit a proxy; the SDK cannot create a proxy
  gateway, so the preview lists the portal steps for the gateway, its
  root certificate and the forwarding rule) (`ops_zia_objects.py`).
  Under **Backups** the same page keeps **configuration backups** of ZIA,
  ZPA and Client Connector (`config_backup.py`): every object type
  zscaler-sdk-python 1.11.3 can read (`config_backup.coverage()` says which
  are restored and cloned, updated only, or kept for comparison and why),
  only what is in scope, owner-only beside the tenant profile, every secret
  masked; on demand, from a saved snapshot or the sample tenant (offline),
  or on a per-profile read-only schedule with a retention count. A
  per-profile configuration cache keeps a hash per object and says what
  changed since the last refresh. Compare two backups, a backup and the
  live tenant, or a backup and the cache field by field (ids, change times,
  who changed it and counters ignored; references compared by name).
  **Restore or clone** (`ops_config_restore.py`, one operation type per
  product) plans from a backup or a template: add what is missing, update
  what differs, or match exactly with deletes (typed DELETE n OBJECTS), in
  dependency order, starting with a fresh automatic backup of the target;
  each write re-reads its object, the first failure or conflict stops the
  run, ZIA's activation is the plan's shown last step, every item is read
  back and Undo puts back exactly what was applied (or, if asked before
  applying, an automatic rollback of a stopped run). A clone remaps every
  reference by name, lists what cannot be cloned and why and the manual
  steps (the proxy gateway, which the API only lists), compares
  the two tenants' subscriptions first, never copies a secret (a VPN
  credential needs its pre-shared key typed; it reaches the write in memory
  only), and writes only to the tenant of the saved profile the person has
  open. Settings can be restored key by key; a re-push plan for what did
  not arrive is offered after the read-back. PAC files (created only),
  Endpoint DLP and SaaS Security API DLP rules (after the engines,
  dictionaries and notification templates they use; SaaS application
  tenants and domain profiles matched by name) and ZPA gateways (their ZPA
  server group and segments matched by name in the target's ZPA) restore
  and clone like the rest. Tenant-bound objects (static IPs, GRE tunnels,
  locations and their sub-locations, each after its parent) are written
  only with their own tick and typed CREATE n TENANT-BOUND OBJECTS. Client
  Connector app profiles and entitlements clone to another tenant only
  with their own tick and typed CLONE n CLIENT CONNECTOR OBJECTS: profiles
  that apply to everyone, created inactive, never with a password or the
  policy token. **Templates** are picked
  objects (with what they use), ids removed, names carrying a prefix chosen
  when they are applied. On the sample tenant or a snapshot, a restore is a
  rehearsal: plan only.
  **Admin rank of new and moved rules** (`rank_inherit.py`, every builder
  below, a reorder and Deploy policy packs): with the tenant's Admin
  Ranking on (read only when ZIA platform is ticked), a rule placed at
  order N takes the admin rank of the rule now at N (or of the rule just
  above it when it goes last), so it is evaluated where it is placed; a
  moved rule keeps its rank when it fits between its new neighbours. It is
  never a rank the API client cannot assign: the SDK has no call for the
  client's own rank, so it is inferred from the rules ZIA lets it edit
  (assumed), and when the rank needed is above it the preview warns that
  the rule lands lower (for example AI Guard's order-1 SSL Inspect rule
  below rank 0-6 rules). Off or unknown, rules get rank 7 as before and the
  preview says so. The preview lists each rule's rank and why, the
  read-back compares the rank ZIA stored, and Undo puts changed ranks back.
  **Rules from a spreadsheet** (two types, ZIA and ZPA access policy)
  exports Cloud Firewall, URL filtering or ZPA access policy rules as CSV
  (names, not ids, with the order and rank; formula-safe cells) and
  imports the edited file: choosing it only checks it, the preview plans
  adds, updates, moves and, only with *Remove rules not in the file* and
  the typed `DELETE <n> RULES`, deletes; new ZIA rules arrive disabled;
  apply, read-back and Undo as above (`rule_csv.py`, `ops_rule_csv.py`).
  Under **Build new** the same page builds Client Connector profiles
  (needs ZCC ticked): pick Windows or macOS, a forwarding profile (best
  practice: tunnel on every network type, the listening-proxy redirect,
  Z-Tunnel 2.0, IPv6 dropped, latency-based ZEN selection, no system PAC,
  ZPA on VPN-trusted networks and ZPA latency-based selection; the portal
  default; or an existing one) and an app profile (best practice for
  Windows or macOS, or the portal default), untick any setting, and
  preview: every setting is an item with its value, the portal default
  and what it does. Applying creates the forwarding profile first and the
  app profile linked to it, both disabled; if the app profile is refused
  the new forwarding profile is deleted again; every setting is read back.
  Undo (and **Delete a Client Connector profile**) needs the profile's
  typed name and is refused while the profile is in use (an enabled app
  profile, or a forwarding profile an app profile links to).
  The app profile's uninstall, turn-off (Internet security) and log-out
  passwords can be set: typed in password fields, sent beside the
  operation for its preview and apply (never in it), written once in the
  create call and never kept (not in the plan, the record, the audit log,
  job logs, snapshots, exports or the browser); the plan shows "set
  (hidden)" and its hash covers only a salted, keyed digest, the read-back
  says set or not set, and Undo deletes the profiles but cannot restore a
  password, as the preview says. The exit and the ZPA, ZDX and Endpoint
  DLP turn-off passwords are not set from here.
  Under *Build new* on the same page, **ZDX probe setup** (only when ZDX
  is ticked on the Scope page, with a OneAPI API client) sets up Zscaler
  Digital Experience apps and probes from a template (Best practice:
  Microsoft 365 sign-in plus a custom app; Microsoft 365; or start
  empty) and a tier (Strict, Balanced, Permissive or Healthcare, as the
  ZIA security baseline: Strict monitors the most apps every 5 minutes with
  CloudPath probes, Permissive sign-in only every 15 minutes with Web
  probes; anything looser than the tier is a warning in the preview):
  predefined apps (Microsoft 365, Teams, SharePoint, OneDrive,
  Zoom, Okta, Box, Salesforce, ServiceNow, Webex; some need the
  customer's tenant prefix) and custom apps by URL, each with a Web probe
  and by default a CloudPath probe, every 5 to 30 minutes, for all users.
  Apps that already exist are skipped or get only what they lack; a
  custom app whose setup fails half way is removed again. Two more types
  turn any ZDX app or probe on or off, and delete custom apps (probes
  first) and custom probes, each name typed to confirm. ZDX's own words
  are shown when it refuses something (a refused host, a missing
  permission). The ZDX configuration API is not in the Zscaler SDK, so
  its paths are assumed and the page says so; the `/zdx/v1` prefix, the
  request routing and the bodies sent as given are verified against the
  SDK (`ops_zdx.py`).
  its paths are assumed and the page says so (`ops_zdx.py`).
  Three more types change live settings the same way (preview, plan hash,
  re-read before each write, read-back, Undo): **ZIdentity group members**
  (`ops_zid.py`, ZIdentity ticked) adds or removes people in one group by
  sign-in name, never listing the directory, refuses dynamic groups and
  warns about groups the identity provider syncs; **Turn Client Connector
  app profiles on or off** and **Change a Client Connector app profile's
  DNS and tunnel settings** (`ops_zcc_live.py`, ZCC ticked) take effect on
  devices at once, so the profile's name is always typed; the settings are
  an allowlist (split DNS, DNS exclusions first, the DNS search order, the
  DNS route exclusion, large UDP DNS answers, DNS through the UDP proxy,
  the packet tunnel exclusions) and never a password.
  Under **Build new** (also linked from the ZPA analysis page as *Build ZPA
  objects*, ZPA ticked on the Scope page), the **ZPA builder** makes a
  proof-of-value ZPA set-up through the same preview, gates, read-back and
  Undo, every object named with a short prefix so a re-run updates in place:
  an App Connector group (or an existing one) with a provisioning key that
  is shown once and never kept, logged or exported; a segment group, a
  server group and application segments from a `*.domain` wildcard, a
  healthcare, finance, education or general preset, or a CSV of up to 500
  rows (created disabled unless you ask), optionally Browser Access and
  Privileged Remote Access consoles; access, timeout, inspection (Zscaler's
  predefined OWASP controls) and isolation rules; the access rule can be
  limited to SCIM groups and SAML attribute values picked from what the
  tenant has (each checked again in the preview). *Delete ZPA objects by
  prefix* reads ZPA again and deletes only objects carrying the prefix, in
  dependency order (policies, segments, server groups, segment groups,
  connector groups), keeping and naming anything still used by an object
  that is not being deleted; it needs `DELETE <PREFIX>` typed.
  The same page carries the **day-to-day admin** types, each through the
  same preview, plan hash, four gates, re-read, read-back, record, audit
  log and (where one exists, which the preview always says) Undo, and each
  only for a product ticked on the Scope page. ZPA (`ops_zpa_admin.py`):
  App Connectors, Private Service Edges and their groups with their
  health; rename, turn on or off, move an App Connector to another group,
  set a group's update day, hour and version profile; turn PRA portals,
  PRA consoles and user portals on or off; delete any of them, Browser
  Access certificates and provisioning keys with the typed confirmation
  naming what goes (anything connected or still used is kept); a new
  provisioning key shown once; a Browser Access certificate uploaded with
  its private key (held in memory ten minutes, sent to ZPA once, never
  kept or logged) and applications pointed at it. Client Connector
  (`ops_zcc_admin.py`): remove or force remove a user's devices, or a
  pasted or uploaded list matched against one read of the fleet (ambiguous
  and unmatched entries settled first), up to 2000 devices in batches
  within Client Connector's 100 API calls an hour, with the plan and result
  as CSV; custom IP-based bypass apps; the ZPA and ZDX entitlements. ZDX
  (`ops_zdx_trace.py`): start, follow (a bounded number of reads) and stop
  a deep trace on a user's device, rate-limited; read-only application
  scores, user and device look-ups, device health and per-device
  application performance.
  Under **Build new**, two AI Guard builders run through the same preview,
  gates, read-back and Undo (they need AI Guard ticked on the Scope page and
  a OneAPI API client). *AI Guard routing for GenAI apps* (ZIA platform
  too) sends the apps you pick (ChatGPT, Microsoft 365 Copilot, Claude,
  Gemini and others) through AI Guard by proxy chaining: it reuses or
  uploads the AI Guard root certificate, reuses an AI Guard proxy or
  creates one, adds a destination group of the apps' domains, blocks QUIC,
  puts an SSL Inspect rule for the apps at the top of SSL inspection (only
  when SSL/TLS Inspection is marked Zscaler), turns on GenAI prompt capture
  when the Gen AI Security subscription is there, adds the forwarding rule,
  and allows the apps in ZIA above any Block, Caution or Isolate rule. The
  proxy gateway cannot be created through the API: the preview says how to
  make it in the ZIA portal and adds the forwarding rule once it exists.
  *AI Guard detection policy* turns a compliance profile (HIPAA, HITRUST,
  PCI, GDPR, CJIS, FERPA, SOX, NIST SP 800-53, NIST SP 800-171 / CMMC,
  IRS Publication 1075 or general) into an AI Guard detection policy
  and a match rule for the apps' LLM providers, Monitor (detect only) by
  default. The read-only readiness check behind both (`ai_guard.readiness`:
  licensed and reachable, existing proxy and gateway, the portal step) is
  shown in each form, and GenAI findings that AI Guard addresses link to
  the builder.
  Two builders run on the same engine
  (*Build new*, `ops_zia_baseline.py`): the **ZIA security baseline**
  (URL filtering, Cloud Firewall, SSL inspection, Sandbox, DNS Control
  with the Trusted Resolver, DoH inspection and geo-blocking, File Type
  Control, Cloud App Control and, only when picked, the Advanced Threat
  Protection settings and UCaaS one-click: the Zoom, Microsoft Teams
  (Microsoft 365 one-click), Webex, RingCentral, GoTo and Talkdesk
  switches that make ZIA add its predefined one-click rules, pre-set on
  for every tier but Strict) from a Strict, Balanced, Permissive or Healthcare
  zero trust tier or a saved framework, with optional compliance overlays
  (HIPAA, HITRUST, NIST 800-53 and 800-171, PCI DSS, CJIS, SOX, FERPA,
  GDPR) that cite each control's source; every rule can be switched off
  or set to Allow, Block or Isolate (or the whole baseline to allow all
  or block all), weaker-than-tier choices are flagged, Allow-Web and
  Allow-NTP are locked, names fit ZIA's 31 characters, what the tenant
  lacks is dropped with a warning, the SSL catch-all goes last, rules
  arrive disabled and re-runs update in place; and the **SSL certificate
  manager**, which lists the intermediate certificate each SSL inspection
  rule uses and moves picked Inspect rules to another ready-to-use one.
- **Compliance profiles and the compliance pack** (`compliance_profiles.py`,
  `compliance_pack.py`) — one compliance choice, made in the ZIA security
  baseline builder and remembered for the saved tenant profile, drives the
  baseline's tier and overlay, the rules the profile adds or requires, the
  policy packs offered, the AI Guard profile and the compliance pack. The
  federal profiles each carry a control catalogue with its cited source:
  FedRAMP Moderate and High (NIST SP 800-53 Rev. 5, SP 800-53B baselines),
  CMMC Level 2 (NIST SP 800-171 Rev. 2 as CMMC practices), Federal Zero
  Trust (OMB M-22-09, CISA ZTMM v2.0), IRS Publication 1075 (with 26 U.S.C.
  6103(p)(4)) and GovRAMP Moderate (which reuses FedRAMP Moderate). They
  build on Strict and change a rule only where the source says why (FedRAMP
  High requires the SSL catch-all, the QUIC block and the password-protected
  archive block; CMMC Level 2 and IRS 1075 block public translation
  services; Federal Zero Trust requires DoH inspection and the Trusted
  Resolver). Every rule the baseline or an offered pack creates maps to the
  profile's controls through an objective, or carries a reason code; a
  control not verified against its source is marked assumed. The compliance
  pack is local files only, downloaded through the app's authenticated
  routes: a control mapping report (HTML, CSV, Excel), a policy export of
  what would be built or was built, a test plan by control and one synthetic
  DLP test file per DLP rule (reserved example SSNs, published test card
  numbers, the markings themselves). The POV planner's intake and Simple
  mode's Protect task offer the same profiles as presets.
  Under **Day-to-day admin** on the same page, through the same preview,
  plan hash, four gates, re-read before each write, read-back, audit log
  with the actor and Undo: **ZIA users, groups and departments** (ZIA
  platform ticked; `ops_zia_directory.py`): find users by name, add a user
  with a department and groups, change users' department and groups, add,
  rename or delete groups and departments; admin accounts, predefined groups
  and groups from the identity provider are left alone, no password is ever
  set, and disabling a ZIA user is not offered (the SDK's user model has no
  such field). **ZIA PAC files** (ZIA platform ticked; `ops_zia_pac.py`):
  each hosted PAC file with its versions and active text, validate (parsed
  by `pac_eval`, never run, and ZIA's validator), a new staged version,
  create or clone a file, switch the active version, delete, with a line
  diff in the preview. **ZIdentity users and API clients** (ZIdentity
  ticked, OneAPI sign-in; `ops_zid.py`): find, add (disabled), disable,
  enable or delete users (not administrators or SCIM users); the API clients
  with their scopes, a new client with only the scopes ticked (none is
  ticked for you), rotate a secret, disable, enable or delete a client
  (never the one this app signs in with). A new secret is shown once, to
  the person who applied, from memory (ten minutes, one view); it is never
  stored, logged or exported. A delete asks the name typed (*DELETE
  <name>*), a rotation *ROTATE <name>*, and the preview says what cannot be
  undone. Password and MFA resets are not offered: Zscaler SDK 1.11.3 has
  no call for them.
  **Sandbox file hashes** (*Build new*, `ops_zia_sandbox.py`, ZIA
  platform ticked) adds the MD5 hashes of files incident response
  confirmed as malicious to the Cloud Sandbox custom block list: MD5 only
  (anything else is refused with the line), up to 100 per operation, a
  typed phrase every time, the list re-read right before the write and
  sent back with only those hashes added (an allow-listed hash is never
  touched), read back after activation, and Undo removes exactly them.
- **To-do list** (`/report/todo`) — tags, comments and to-dos you write
  on any object (a DLP rule, engine or dictionary, a URL filtering or
  firewall rule, a URL category, a location, a finding) from its card in
  Find anything, kept per tenant on the machine the app runs on
  (`workspace_notes.json` beside the tenant profiles, owner-only), with who
  wrote each one and an audit-log line for every change. The page lists the
  open to-dos across tenants, filters by tenant and tag, ticks them done and
  links back to the object. Nothing is read from or written to the tenant;
  the browser extension's side panel shows an object's tags and notes
  (read-only).
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
  Its *Firewall and private access* section reads a Palo Alto Networks
  PAN-OS configuration export (`panos_migrate.py`, parsed with
  defusedxml, size, depth and element capped) and builds a plan for Bulk
  changes: security rules as Cloud Firewall rules with their IP source and
  destination groups and network services, App-IDs as network
  applications where one exists, allow rules from a GlobalProtect zone to
  internal addresses as ZPA application segments and an access rule, zones
  noted, and every item it cannot carry exactly listed with the reason.
  Bulk changes' *Firewall import from Palo Alto Networks*
  (`ops_fw_import.py`) previews it against the tenant and applies it
  through the four gates, every rule disabled, with Undo.
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
- **Policy exports** — every export in one place (assessment Excel and
  Word, DLP inventory, deployment plans, Export from tenant), plus
  read-only exports of the URL filtering, Cloud App Control, SSL
  inspection, Cloud Firewall and File Type Control policies (one Excel
  workbook or PDF review copy per policy: every rule in order, names not
  ids, the shadowed-rule findings per rule), a URLs export (every URL,
  domain and IP the policy names, deduplicated, with where each was
  found) and the custom URL category analyzer (for each custom-category
  URL, whether Zscaler already categorises it the same way, differently
  or not at all, through ZIA's URL lookup, paced, 20,000 URLs a run, with
  Continue for the rest up to 100,000). Also a
  locations workbook (locations and sub-locations with their settings,
  location groups, and which URL filtering, Cloud Firewall, SSL
  inspection, File Type Control and Web DLP rules use each, directly or
  through a group; IP addresses and VPN credentials counted, never
  listed) and a Client Connector workbook (app and forwarding profiles
  with their settings, PAC files, which profile uses which forwarding
  profile and PAC URL; no password, token or key). Export options for
  every workbook: choose columns, one row per value, and the separator
  (new line, comma, semicolon); the defaults give the workbooks as
  before. Every DLP engine (inventory workbook, Deploy views, browser
  extension side panel) shows its expression with dictionary names and
  one sentence saying when it fires; Copy keeps the expression with ids.
  Only what is in scope; a live log and Stop.
  **Zscaler IP ranges and allowlists** (same page, `zscaler_ip_ranges.py`;
  it does not read the tenant): Zscaler's published ranges and host names
  for one ZIA cloud (cloud enforcement nodes by region and city, hub
  ranges, future data centres, App Connector tunnel addresses) and a ZPA
  cloud's allow list, aggregated per region and in all, with ranges left
  out or added, as a plain list, CSV, Palo Alto external dynamic lists,
  JSON or a Microsoft 365-style list. The feeds come from
  `config.zscaler.com` only when fetching is turned on there and you click
  Fetch now (off by default), or are imported from saved files; each is
  checked as untrusted (private, reserved and over-broad ranges and foreign
  host names dropped), kept with its date, unknown when missing and stale
  after 30 days.
- **Advanced settings** — add your own policy packs (JSON, Terraform,
  native Zscaler API exports or a ZIP) to the library, and see how this
  server is configured (bind host, token gate, write mode, limits) with
  its Secure by Design score. The **Microsoft 365 endpoint list** lives
  here too: off by default; turned on, it is fetched from
  `endpoints.office.com` (the version first, at most daily when you
  analyze, or on Fetch now); or import the saved file on an offline
  machine. It is checked as untrusted (2 MB, every field) and kept with
  its version and date; a list not confirmed for 30 days settles nothing.
  Two switches there are off by default: *update notifications* (one
  e-mail or webhook notice per new app version, on the digests' channel,
  `update_notify.py`) and *local plugins* (`local_plugins.py`: Python
  packages in the folder `DLP_CHECK_PLUGINS_DIR` names, loaded only when
  an admin approved their exact SHA-256 there; they can add Bulk changes
  operations, which go through the same gates, and read-only **Plugin pages**
  at /report/plugin; SECURITY.md says what a plugin can do and why the
  hash is the control; an example is in docs/plugins).
- **API calls** (Advanced settings, `api_calls.py`) — every Zscaler API
  call this app made since it started: time, product, method, the path
  with every id shown as `{id}`, the answer, the time taken, how often it
  was sent again, how long it waited for a rate limit, and an error class.
  Never a body, header, token, secret, query or tenant name. In memory
  only, the newest 1,000 (`DLP_CHECK_API_CALLS_MAX`, 50 to 20,000), empty
  after a restart; filter by run or product, export as CSV or JSON. A
  builder's result on Bulk changes links to the calls of its own run.
- **Quality and security score** — this app's own score from 0 to 100 on
  Advanced settings: tests passed in the last full run, open QA findings
  weighted by CVSS severity (an open critical caps it at 39, an open high
  at 69, and any failed test at 79, grade C at best) and standards
  coverage, per area. Built by tools/quality_score.py into
  docs/QUALITY_SCORE.md and docs/quality_score.json; read-only at
  GET /api/quality-score. The tests part needs a recorded full run,
  docs/qa/test_run.json (written by `python tools/quality_score.py
  --from-junit <pytest JUnit XML>`); until one is recorded the page says
  "No score yet" and shows the findings and the standards coverage only.
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
  (the last 7 days by default, up to 180) merged with Zscaler Made Easy's own
  deployment records and audit log, newest first, with filters, a
  field-by-field diff where the entry has before and after values, and
  CSV or JSON export. A change someone else made to an object Zscaler Made Easy
  created is marked. Reading ZIA's log needs Automation readiness in scope;
  asking ZIA for the report is a POST that changes no configuration.
- **Log analyzer** — drop in the ZIP from Client Connector's Export Logs
  (or single log files, or a PAC file); it is read on this computer and
  answers what happened, what it means for the user and what to do next.
- **Traffic and session logs** (`/report/traffic-logs`, `traffic_logs.py`,
  `siem_queries.py`) — upload the logs the customer's log streaming already
  writes: ZPA LSS User Activity, User Status, App Connector Status and
  Private Service Edge Status (JSON lines), and ZIA NSS web, firewall and DNS
  feeds (JSON, the Cloud NSS HTTP shape, a CSV or TSV with a header in NSS or
  Insights column names, the default tab-separated format, or a custom feed
  output format pasted in). Read on this computer as untrusted input (the Log
  analyzer's bounded unpacking, 64 KB per line, 2,000,000 lines, bounded
  counters; a line no format reads is counted, never fatal). It shows sessions
  and failures over time, the top users, applications, App Connectors, Service
  Edges, access rules and destinations, each ZPA internal reason in plain
  words with what to do, ZPA sessions put together per user, App Connector
  and Private Service Edge health, anomalies (spikes, many failures for one
  user, new destinations), and for ZIA blocked against allowed, top
  categories, rules hit per module, DLP and threat events and SSL inspected
  or not. A destination opens in the Path analyzer filled in; Traffic
  insights opens with the same window. Only counts are kept, in memory, until
  you forget them; CSV, Excel and PDF downloads and saved reports (an
  owner-only file) are counts only unless you tick names. The same questions
  come as Splunk SPL, Sentinel KQL and Elastic ES|QL text to copy (values
  escaped for each language). It reads no tenant.
- **Diagnose ZCC access** — probes every Client Connector API endpoint
  with the credentials you entered and shows which answer. Where: the
  Connect to the tenant card.
- **Required API access** — what this API client can do now and the exact
  API roles and scopes the app needs per assessment scope, to send to the
  customer's admin. The live part comes from the readiness check that runs
  right after Authenticate: per product (ZIA, ZPA, Client Connector, ZDX,
  Z-Insights, AI Guard) whether the client can read, change or not reach
  it, read from the OneAPI access token (decoded without checking its
  signature, for display only; the token is never shown, logged or kept)
  and a few reads for what is in scope (the ZIA licences and API role, the
  Client Connector company switches and roles, the ZPA roles, one ZDX and
  one Z-Insights call), two tenant checks (ZIA changes saved but not
  activated, and the SSL inspection rule order when DLP or ZIA platform is
  ticked); the licences and SKUs; and every Scope page key and
  every change of this app that will not work, with the plain steps to ask
  the admin for. On the Start page the same check shows as a short summary,
  greys out the scopes that will not work and stops a deploy or removal
  the role cannot make. Where: the Connect to the tenant card (`/permissions`;
  the page opens without the UI token, so its live part is shown only to a
  browser that has unlocked the app).

## The policy packs it ships with

| Pack | For |
|---|---|
| ZBP Enterprise Policy Pack | Any commercial enterprise with no DLP policy yet (Zscaler's enterprise best practice) |
| Source Code to AI Policy Pack | Source code going into AI tools (13 languages; can be rebuilt from the tenant's own dictionaries) |
| Healthcare PHI Policy Pack | Healthcare providers and payers |
| Global Banking Policy Pack | Banks, card issuers, payment processors, wealth managers |
| Fed Policy Pack | US federal agencies and contractors (contains the enterprise pack) |
| CJIS Policy Pack | Law enforcement, courts, CJI handlers |
| IRS 1075 FTI Pack | Agencies and contractors receiving federal tax information (IRS Publication 1075) |

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
  anything another rule still uses, saying so. Three exceptions, all behind
  write mode and all explicit: the Rule migration wizard's optional
  Step 3b deletes every existing Inline Web DLP rule (Step 5 re-posts the
  tenant's own rules as they were), the API-only converge option
  (`restore_drift`, which no screen in the app uses) overwrites pack
  objects the customer changed, and Bulk changes changes existing objects on
  purpose (a rule's state or order, a category's URLs, a segment's
  domains), only the items you approved, and skips any item someone
  changed since the preview.
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
  guidance checks, only if you configure the digest, your SMTP relay
  or Teams/Slack webhook, and, only if you turn it on in Advanced settings,
  `endpoints.office.com` for Microsoft's published Microsoft 365 endpoint
  list (off by default; the file can be imported by hand instead). Reports, profiles, deployment records and the
  audit log stay on the machine it runs on; the Log analyzer, Traffic
  and session logs and DLP efficacy read what you give them locally and
  store nothing (a traffic log report is kept only if you save it).
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

- **Mac and Linux**, after `./install.sh`: `.venv/bin/zscaler-made-easy` (the
  server), `.venv/bin/zscaler-made-easy-assess --config tenant.json --output
  report.json` (the assessment from a JSON file), and
  `.venv/bin/zscaler-made-easy-evaluate` (one run of the evaluation loop, for cron).
  The names from before the rename (`dlp-check`, `dlp-check-assess`,
  `dlp-check-evaluate`) still work, so existing cron jobs keep running.
- **Windows**: `python dlp_assessment_full_auto.py --config tenant.json
  --output report.json`, and `RUN_Continuous_Evaluation.bat` for Task
  Scheduler.
- **Container**: `docker compose exec zscaler-made-easy python continuous_eval.py
  --once`.
- **Terminal UI**: `zscaler-made-easy tui` (`tui.py`)
  opens a keyboard-only curses view of a running server, over SSH too:
  tenant profiles or the sample tenant, the assessment and its score,
  findings, the Path analyzer for one destination, Test a list from a
  file, snapshots and their differences, and plan previews (a Bulk changes
  operation or a migration plan as JSON). It calls the same API as the
  web pages with the UI token from `ui_token.txt` (never shown), so a write
  goes only through the server's plan, typed confirmation and apply path
  with the same gates. Plain http only to this computer; https elsewhere.

`python dlp_mcp_server.py` runs a separate, optional MCP server (port
8080, or `--transport stdio`) that lets an AI agent run the same
assessment with credentials from `ZSCALER_*` variables only (no tool
accepts a secret, so none passes through the AI conversation;
`get_health` names any variable that is missing); no launcher starts it.
It also answers an admin's live questions with the app's engines, each a
read-only tool (`mcp_tools.py`): the Path analyzer with what-if, Test a
list (50 destinations), rule precedence and shadowed rules, the DLP engine
and rule explainer, the Data Flow Map, SSL coverage, the Live DLP feed
(counts by rule; users counted, not named), Traffic insights, ZPA
diagnostics, Client Connector fleet health (counts only), snapshot
compare, the URL lookup, readiness and the compliance mapping, on the live
tenant, the sample tenant or a saved snapshot. There are no write tools:
every client a tool builds refuses writes and every request the server
sends passes a read-only guard. What is in scope is set where the server
runs (`ZSCALER_MCP_PROFILE`, or `ZSCALER_MCP_SCOPES` and
`ZSCALER_MCP_CHANNELS`), never by the assistant; nothing set means no live
read. Answers are summaries of at most about 48,000 characters, masked
for every credential, with tenant text marked as untrusted data. The
skill in `skills/zscaler-made-easy/` routes questions to the tools and
words the answers; [AI_ASSISTANT.md](AI_ASSISTANT.md) says how to connect
both to an assistant.

## Limits, and what is still to come

Being honest about the edges:

- The **Live DLP feed** shows Workflow Automation DLP incidents only. URL
  filtering, Cloud App Control and firewall decisions that never trip a
  DLP rule are not in it; that is Web Insights or a Cloud NSS feed, which
  the app does not read live (NSS log files can be uploaded to Traffic and
  session logs).
- **Traffic insights** reads ZIA Insights' aggregated numbers, not the
  transaction log: the installed SDK's Z-Insights queries cannot group
  traffic by URL category, user or policy rule, or filter it to one host,
  so rule hit counts and the Path analyzer's recent traffic to a
  destination are not available from it. Uploaded NSS logs give rule hit
  counts, categories, users and hosts on Traffic and session logs.
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
  Connector, ZDX and Cloud & Branch Connector that affect data protection,
  plus ZPA administration
  under RBAC (admins, roles, admin SSO, API keys, emergency access,
  microtenants, provisioning keys, Privileged Remote Access credentials
  and approvals; read with RBAC and ZPA ticked, no key or password value
  ever read into a result); they are not a full audit of those products.
  Zero Trust Branch, EASM, Business Insights, Zero Trust Cellular and
  Microsegmentation are read and checked read-only, a handful of
  best-practice checks each; nothing is built or changed in them.

Everything the app has shipped, batch by batch, is in `CHANGELOG.md`.
