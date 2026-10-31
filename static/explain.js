// ── Plain-English explanations of every function ─────────────────────
// One catalogue, used in three places: the "What is this page, and why
// it matters" box at the top of every report tab, the /help page that
// lists every function, and the glossary in the assessment page's help
// drawer. Written for an engineer on their first week: what the thing
// is, why the customer cares, when to click it, what comes back, and
// what to do with it. Nothing here needs prior Zscaler knowledge.
(function () {
  const X = {};
  // group: where the button lives on the assessment page's toolbar.
  // href: where the function opens (blank when it is a dialog on the page).
  X.assessment = {
    group: 'Start', name: 'The assessment page (home)', href: '/',
    what: 'The home page. The sidebar walks you through: Connect to the tenant (sign in), Scope assessment (which channels the customer owns, what to check, which frameworks to map to, then Run assessment), and the Dashboard, which holds the score tiles, every finding and the exports; then pick a policy pack, close the gap, and measure the journey on the next visit. You can rearrange the sidebar: drag an item or a section heading to anywhere in it, or focus an item and press Alt+↑/↓ to move it (Alt+Shift+↑/↓ moves its whole section); this browser keeps the order, and Reset sidebar order under Sidebar order at the bottom of the sidebar puts it back.',
    why: 'Everything else in the app either feeds this page (the assessment) or acts on what it found (the packs, the hand-off). If you only learn one page, learn this one.',
    when: 'Every engagement starts and ends here; come back to it between the other tabs.',
    get: 'A score out of 100, a maturity level, the findings that matter with the fix for each, the compliance mapping and the data-governance journey per policy pack.',
    next: 'Follow the Start here steps in order; each step tells you when it is ready and what it needs.',
  };
  X.connect = {
    group: 'Start', name: 'Connect to the tenant (sign-in details, profiles, Authenticate)', href: '/',
    what: 'Where you type the customer\'s cloud, vanity domain, API client ID and secret (or the classic ZIA API sign-in), then click Authenticate. Nothing else lives here. Tenant profiles save those details (and the history) per customer. No tenant at hand? Try with a sample tenant (Larkspur Freight, made up: every page works on it and nothing is real), or open a snapshot: a tenant read saved beside its profile (only what was in scope, no credentials) that works offline and read-only.',
    why: 'Nothing works until the app can sign in to the tenant. Authenticate proves the credentials work and does not read the tenant\'s configuration, because every read counts against the tenant\'s ZIA API rate limit. Right after it, the readiness check reads only the API client\'s role and the licences, for what is in scope; the configuration is read only when you run an assessment.',
    when: 'First thing in every engagement. Save a profile so the next visit fills itself in and keeps history. Save a snapshot before you change things, to compare with the live tenant later; use the sample tenant to learn or demo the app.',
    get: 'Signed in (the tenant\'s configuration is not read), or a plain reason why not (wrong secret, TLS inspection). Then a readiness summary: per product whether the API client can read, change or not reach it, and every scope or change that will not work, greyed out with the steps to ask the admin for.',
    next: 'Open Scope assessment: mark the channels the customer owns, choose what to check and which frameworks to map to, name the organisation and assessor, and click Run assessment.',
  };
  X.results = {
    group: 'Start', name: 'Assessment results', href: '/report/view',
    what: 'The full results in their own tab: Summary (score and maturity), Scores by section, Best practices and benchmarks, Regulatory alignment, the Data governance journey, and Detailed findings with a fix for each.',
    why: 'This is the deliverable. Critical findings are configuration that exposes data today; the score gives the customer a number to improve.',
    when: 'Right after the assessment runs, and again on every return visit to show progress.',
    get: 'Every finding in four plain sentences: what we found, what it means for the business, what to do, and the outcome once fixed (the technical detail folds away underneath), plus Word and JSON downloads.',
    next: 'Walk the customer through the critical findings first. Then open Traffic flow & gaps and FP/TP detection ratio for the "show me" evidence.',
  };
  X.dataflow = {
    group: 'Find the gaps', name: 'Traffic flow & gaps', href: '/report/dataflow',
    what: 'A map of the path the tenant\'s configuration gives a user\'s web traffic to each traffic class (or a destination you type), for any user: Client Connector app and forwarding profile, PAC, Cloud App Control, URL filtering, SSL inspection, File Type Control and Web DLP, with the points on those paths where inspection is lost (bypasses, SSL blind spots). It reads configuration; it does not observe traffic.',
    why: 'DLP can only stop what it can see. A bypass or an un-decrypted app category is a hole the customer usually does not know they have.',
    when: 'After the assessment, when the customer asks "why did DLP not catch that upload?" or before deploying a policy pack.',
    get: 'The path for each traffic class on each network with each policy pack\'s rules overlaid by name, visibility by cloud-app category, and the bypasses and blind spots on those paths with the object that causes each (the Bypass inventory lists every bypass in the tenant).',
    next: 'Close the SSL and bypass gaps first; DLP rules deployed behind a blind spot do nothing.',
  };
  X.zpa = {
    group: 'Find the gaps', name: 'ZPA analysis', href: '/report/zpa',
    what: 'Reads the tenant\'s ZPA configuration once (app segments, segment and server groups, App Connectors, Private Service Edges, IdPs and the access, timeout, forwarding, inspection and isolation policies) and runs over two dozen ZPA analysis templates over it, then diagnoses one user and destination: which app segment matches, what serves it and which access rule decides. It reads only when ZPA is ticked on the Scope page.',
    why: 'Private access fails quietly: an access rule an earlier rule always beats, a segment nobody can reach, two segments claiming the same host, a wildcard that opens a whole domain, a connector group with one connector. Each of these is invisible in the console until a user calls; this page names them with a fix each.',
    when: 'During a ZPA health check or a zero trust review, before and after a ZPA change, and while troubleshooting a "I cannot reach this internal app" ticket, where Diagnose answers which segment and which rule decide for that user.',
    get: 'An overview of plain sentences (segments nobody can reach, connectors down or outdated, rules that never decide), an infrastructure map from users to App Connectors whose boxes filter the tables of every object, and the whole overview as Excel; findings grouped by template with a severity filter, counts and a catalog of every template, exported as CSV, JSON or Excel; and a diagnosis hop by hop: segment, segment group, access rules in order with why each did not match, server groups and connector status, plus the assumptions.',
    next: 'Fix the named rule, segment or connector group in the ZPA console, then read ZPA again and confirm the finding is gone; use Diagnose with the user\'s groups to prove the access path before you close the ticket.',
  };
  X.deviceposture = {
    group: 'Find the gaps', name: 'Device posture', href: '/report/device-posture',
    what: 'Reads the ZPA posture profiles, trusted networks and access rules once, sorts every posture profile into a family (domain join, EDR or antivirus, certificate, disk encryption, OS version, jailbreak, MDM, firewall, process, marker or unknown) and says whether that came from the profile type or only from its name. It links each profile and network to the rules that use it, as must pass or must fail, and says every access rule in plain words. It reads only when ZPA is ticked on the Scope page.',
    why: 'Zero trust is only as strong as the device check behind it. An allow rule to a sensitive app with no posture check, a negated check that lets failing devices in, or a check that only looks for a marker file all look fine in the console list, and each one lets an unmanaged or compromised laptop reach private apps.',
    when: 'During a ZPA or zero trust review, before telling a customer that only healthy corporate devices reach a private app, after adding a new EDR or certificate check, and when an auditor asks which rules require a managed device.',
    get: 'Findings with a fix each (no posture on sensitive or broad apps, negated checks, marker-only checks, optional checks, unused profiles and networks), the families with how each was classified, the rules using each profile, and every access rule as nested AND, OR and NOT groups plus one sentence, exported to Excel.',
    next: 'Add a must-pass posture check that enforces something (EDR, domain join or a certificate) to the rules named under Findings, fix any negated check, then read device posture again and confirm the finding is gone.',
  };
  X.path = {
    group: 'Find the gaps', name: 'Path analyzer', href: '/report/path',
    what: 'Type a URL, a hostname or an IP address and see, live from the tenant as it is right now, every step the traffic takes and the rule that decides each one. ZPA comes first (application segment, bypass, client forwarding and access policy): a destination ZPA carries never reaches ZIA. Then Client Connector\'s app and forwarding profile and the PAC file, evaluated for the destination but never run (for traffic from a workload, the Cloud or Branch Connector forwarding rules instead), then every ZIA module, one by one: Advanced Threat Protection, Cloud Firewall, DNS Control, Cloud App Control, URL filtering, SSL inspection, Sandbox, File Type Control and DLP. Each step shows its deciding rule and every condition as match, no match or unknown, and one verdict in plain words says whether the answer is definite or conditional. Pick a protocol and port to trace traffic that is not web, and a user, group, department or location for a what-if. It reads only what is in scope on the Scope page; a part out of scope says Not in scope, never \"no rule\". Test a list does the same for a whole list at once (a CSV of IP addresses, CIDR blocks, ranges, hosts and URLs, up to 250,000 rows), against what each row was expected to do; Import a HAR file analyzes every host a browser HAR file names (the file is read in the browser: only host names, request counts, HTTP methods, schemes and upload amounts are sent; cookies, headers, URL paths and bodies stay in the browser).',
    why: 'When a customer asks "what happens if a user goes to this site?" the honest answer is in a dozen policies across ZPA, Client Connector and ZIA. This page reads them all and answers in one line, naming the rule or profile that decides it, for one destination, one user or workload, or every destination on a threat feed or an allow list.',
    when: 'While troubleshooting a "Zscaler blocks my site" or "DLP did not catch it" ticket, before promising a control will apply, and when showing a customer where a destination is blind.',
    get: 'The verdict (where the traffic stops or that it reaches the destination, whether it is decrypted and inspected), each step before ZIA and each ZIA module with its deciding rule and conditions, what the policy action also depends on (or, with a what-if, the rules for that identity), the objects that block or impact the traffic with a fix each, the hop-by-hop path, the ZIA categories for the destination, and the assumptions, plus a JSON export. For a list: counts of blocked, allowed, bypassed, isolated, cautioned and allowed-but-blockable rows, the top deciding rules and categories, where to fix each row that misses what was expected, lists to paste per area, and CSV and Excel downloads.',
    next: 'Fix the named rule, profile or exemption, click Fresh read, and analyze again to prove the change. For a list, Fix selected opens Bulk changes with the destinations filled in, to preview and apply behind its write gates.',
  };
  X.catlookup = {
    group: 'Find the gaps', name: 'Category lookup', href: '/report/path#categories',
    what: 'Look up a URL, a host name or an IP address (or a category) and see which ZIA URL categories it is in, predefined and custom, and every rule that names each category across URL filtering, Cloud App Control, SSL inspection, Cloud Firewall, DNS Control, File Type Control, Web DLP and Sandbox, in the order ZIA evaluates them, with each rule\'s order, rank and action, plus the custom categories that list it. A tab of the Path analyzer; Test a list rows and Find anything open it. It reads only what is in scope on the Scope page and writes nothing.',
    why: 'Before you change a category, or when a site lands in a category nobody expected, you need to know every rule that category drives: the URL block, the SSL exemption, the firewall rule through an IP group. The portal shows that one policy at a time.',
    when: 'When a destination is blocked or allowed and you want to know through which category, before moving a URL between categories, and before editing or deleting a custom category.',
    get: 'Per entry: its categories with where each came from (ZIA\'s URL lookup or the tenant\'s own list), the cloud application, any security alert, the custom categories that list it, and per category the rules that name it in evaluation order (order, rank, action, enabled or not, and through which field or IP group), plus what was read and what was not in scope.',
    next: 'Open the rule in the ZIA Admin Portal, or Trace its path to see which of those rules decides for this destination.',
  };
  X.live = {
    group: 'Find the gaps', name: 'Live DLP feed', href: '/report/live',
    what: 'Workflow Automation\'s DLP incidents, polled live every 15 seconds: who was transacting, what triggered (rule and dictionaries), where the data was headed, whether the matched rule enforced it or only logged it, and a running seen / enforced / monitor / FP:TP tally for the session.',
    why: 'Vital while troubleshooting: act on the tenant and watch the incident land, with the reason attached, instead of waiting for the next scheduled report. It also states plainly what it does not cover, so nobody mistakes DLP incidents for the whole traffic log.',
    when: 'While reproducing a customer issue live, during a proof of value, or whenever "is this rule actually catching anything right now?" needs an answer in seconds, not minutes.',
    get: 'The DLP chain from the reference architecture, live: each channel that raised an incident carries bits through its rule and the evidence lane to Workflow Automation, its rule tagged enforce or monitor. Below it, a live-updating table (when, who, trigger, destination, channel, enforced or monitor-only, verdict) and a running tally, the tenant\'s forwarding profiles, PAC files and Client Connector configuration behind those channels, with an explicit note on what this feed covers (Workflow Automation DLP incidents) and what it does not (URL Filtering, Cloud App Control and Firewall & DNS Control decisions that never trip a DLP rule — that is Web Insights / Cloud NSS, a feed to your own log store this app does not read).',
    next: 'Start the feed before reproducing the issue, watch the incident land with its rule and dictionaries named, then open Path analyzer for that same destination for the full policy trace.',
  };
  X.motion = {
    group: 'Find the gaps', name: 'Flow animator', href: '/report/motion',
    what: 'Animates the flows this app analyses from your own results: a Path analyzer result hop by hop, what happens inside DLP (dictionary match counts, each engine term against its threshold, the rules that act), a policy-pack plan or deployment, Workflow Automation DLP incidents as they land, and every flow of the Data Security Architect reference.',
    why: 'A moving picture shows where traffic stops and why an engine did not fire ("3 found, needs more than 4") faster than a table does, and it is the clearest way to walk a customer or a new engineer through the chain from content to incident.',
    when: 'After a Path analyzer run or a preflight, while testing sample content against the engines, during a live reproduction with the incident feed running, or when teaching the reference architecture.',
    get: 'Five animated views with a text alternative under each: Traffic path, DLP decision (with near misses named), Deployment (with the deploy order replayed and dependency tracing), Live traffic (enforced versus monitor-only, per channel) and Architecture flows (the steps people miss marked, optionally coloured with your last path).',
    next: 'Fix what the animation shows: the hop that stops the traffic, the engine threshold that is a near miss, the rule that is monitor-only, or the setup gate the reference says is missed; then run the source page again and replay.',
  };
  X.bypass = {
    group: 'Find the gaps', name: 'Bypass & non-inspected traffic', href: '/report/bypass',
    what: 'Every SSL exemption, allow rule, Client Connector bypass and PAC exception that lets traffic skip inspection, in one list with exports.',
    why: 'Each line is traffic DLP will never see. Customers accumulate these over years; most were added for a problem that no longer exists.',
    when: 'When you need the evidence behind a "visibility" finding, or a list to review with the customer\'s security team.',
    get: 'A table of bypasses with type, scope and the reason it matters, and CSV / Markdown exports.',
    next: 'Ask the customer why each one exists; replace broad bypasses with narrow SSL exemptions or app policies.',
  };
  X.sslflow = {
    group: 'Find the gaps', name: 'SSL inspection flow', href: '/report/sslflow',
    what: 'For each risky traffic class (file sharing, webmail, AI tools, social, uncategorised sites) which SSL rule decides, whether the traffic is decrypted, and whether inline DLP can see it.',
    why: 'Without decryption DLP sees only the destination, never the content. This is the number one reason a DLP rule "does not work".',
    when: 'Before promising the customer that a DLP rule will catch anything.',
    get: 'A live flow diagram with gaps highlighted and the fix for each.',
    next: 'Fix the SSL rule order or exemptions it points at, then refresh the diagram.',
  };
  X.sslcoverage = {
    group: 'Find the gaps', name: 'SSL coverage', href: '/report/sslcoverage',
    what: 'How much web traffic Zscaler does not inspect, why, and what to change: every SSL inspection rule that leaves traffic encrypted, Client Connector and PAC file bypasses, each with its risk and a plain recovery step, plus the share of HTTPS and HTTP traffic inspected when ZIA Insights is in scope.',
    why: 'DLP, malware and sandbox scanning only see traffic that reaches Zscaler and is decrypted. Exempting file sharing or AI tools makes DLP blind exactly where data leaves; exempting banking or health sites for privacy is expected but should be written down.',
    when: 'Before promising the customer that a DLP rule will catch anything, after changing SSL rules or Client Connector bypasses, and on a schedule to watch coverage improve run after run.',
    get: 'A traffic and inspection summary (SSL/TLS, HTTP and total share inspected) when ZIA Insights is in scope, the causes ranked by risk, a recovery plan with a safe-to-change note for each step, the coverage trend across runs, and an Excel export.',
    next: 'Work through the recovery plan from step 1, testing each change with a pilot group, then run it again to see coverage rise; trace a single destination in the Path analyzer when in doubt.',
  };
  X.shadow = {
    group: 'Find the gaps', name: 'Shadowed rules', href: '/report/shadow',
    what: 'Reads the rules of every policy in scope (Inline Web, Endpoint, Email and SaaS DLP, URL filtering, Cloud App Control, SSL inspection and Cloud Firewall) and lists the rules that can never match or never act: hidden below a broader rule, below a catch-all, duplicated, superseded by a stricter rule, disabled, or naming engines and categories that no longer exist.',
    why: 'A rule that can never match looks like protection on paper and does nothing in production. Customers add rules for years without removing old ones, and the one that matters often sits under a broad rule nobody remembers.',
    when: 'After the assessment and before deploying a policy pack, during a policy clean-up, and whenever a customer says a rule "never fires".',
    get: 'Findings per policy type with a severity, the rule and the rule that hides it, the reason in one sentence and the fix, a count per policy, the Inline Web DLP evaluation mode it assumed, and CSV and JSON exports.',
    next: 'Fix the high findings first (a stricter rule that never applies), move or delete the rule as the fix says, then run the analysis again to prove it.',
  };
  X.browser = {
    group: 'Find the gaps', name: 'Browser security', href: '/report/browser',
    what: 'Reads, only as far as the Scope page allows, the Zero Trust Browser isolation profiles (copy and paste, upload and download, printing, watermark, debug mode, local rendering), the ZIA and ZPA rules that send traffic to isolation, ZIA Browser Control (allowed and blocked browser versions, smart isolation), and the ZPA browser side: Browser Access apps, managed browser profiles, browser protection, Privileged Remote Access and user portals.',
    why: 'Isolation is how a customer lets people use GenAI, file sharing and other risky sites without letting data out, but one permissive profile (copy and paste or downloads allowed, no watermark) quietly undoes it. Old browsers and Browser Access apps nobody can reach, or anybody can reach from a personal browser, are the other gaps this page names.',
    when: 'During a data protection or GenAI review, before rolling isolation out to more users, after a customer asks "can people copy data out of the isolated app?", and when cleaning up Browser Access and Privileged Remote Access.',
    get: 'Findings in plain English with a severity and a fix each (sorted high first), the controls of every isolation profile side by side with the rules that use it, Browser Control settings with the older versions not blocked, Browser Access, managed browser and PRA tables, a glossary of every control, the assumptions, and an Excel or JSON export. It says once that the standalone Zscaler Enterprise Browser has no API.',
    next: 'Turn copy and paste, file transfer and printing off in the profiles that isolate sensitive, GenAI or unsanctioned apps, give rules that isolate a profile, delete the unused profiles, then read again to confirm each finding is gone.',
  };
  X.efficacy = {
    group: 'Find the gaps', name: 'DLP efficacy', href: '/report/view?tool=efficacy',
    what: 'Scores every custom dictionary and engine for false-positive risk and lets you paste sample text (or run the built-in corpus) to see which dictionaries, engines and predefined ones would fire.',
    why: 'A noisy dictionary buries real incidents and makes the customer switch the rule off. Testing before enabling saves that.',
    when: 'Before enabling a rule, and when the customer complains about false positives.',
    get: 'A score and a reason per dictionary, and a fired / not fired result per engine for your sample.',
    next: 'Tighten the noisy dictionaries (proximity, thresholds), then test again.',
  };
  X.health = {
    group: 'Find the gaps', name: 'FP/TP detection ratio', href: '/report/health',
    what: 'What the DLP rules actually do in production, measured from Workflow Automation incidents and the analysts\' verdicts: false-positive rate per rule, engine and dictionary, dead rules, monitor rules ready to promote, and the proposals queue.',
    why: 'A rule that fires and is always dismissed costs the customer analyst time; a rule that never fires is either perfect or dead. Either way it is a tuning decision with evidence.',
    when: 'On return visits, once incidents have been flowing for a few weeks.',
    get: 'Per-rule health with the reason, and typed proposals (raise a threshold, promote to block) you can approve or dismiss.',
    next: 'Approve the proposals the customer agrees with, then Preview and apply: the app re-reads the rules, shows the exact change, applies it with a read-back, and keeps a Roll back button.',
  };
  X.insights = {
    group: 'Find the gaps', name: 'Traffic insights', href: '/report/insights',
    what: 'What the tenant\'s traffic actually did over a time window, read from ZIA Insights: web traffic allowed and blocked, web traffic by location, the cloud applications in use (Shadow IT), SaaS security (CASB) by application, firewall traffic by action, and the users with the most security incidents.',
    why: 'Configuration says what should happen; traffic says what did. Seeing how much is blocked, which cloud applications carry the data and which locations send it tells the customer where a policy change matters most, without waiting for a log export.',
    when: 'After the assessment, before proposing a policy pack, and whenever someone asks how much traffic a control really touches. It needs ZIA Insights ticked on the Scope page and a OneAPI API client whose role includes Z-Insights.',
    get: 'Sortable tables for each section with its status (read, no data, partial, could not read) and the reason when a section fails, a plain list of what Insights cannot answer (URL category, per-user traffic, per-rule hits, one host), and CSV and JSON exports without the per-user table.',
    next: 'Take the busiest cloud applications and locations into the Path analyzer to see the policy path for them, then close what you find with a policy pack, preflight first.',
  };
  X.posture = {
    group: 'Find the gaps', name: 'Improve my score', href: '/report/posture',
    what: 'Takes the results of the last assessment and says what to do next: the ten fixes that raise the score most (with the points each adds, the effort and whether a one-click fix exists in Review & remediate), the score after the fixes you tick or have staged in the change queue, the score over time with the checks that started or stopped failing between runs, and what the assessment could not check and why.',
    why: 'A score on its own does not tell anyone what to do on Monday. Showing the cheapest fixes first, what the score will be after them, and why the score moved since the last visit turns the number into a plan the customer can follow and a result they can see.',
    when: 'Right after an assessment, when you plan the next changes with the customer, and on every return visit to explain why the score went up or down. Save a tenant profile so each run is kept in its history.',
    get: 'A ranked list of fixes with plain steps and a link to the fix, a projected score, a score trend with the cause of each change, a score-drop alert with its threshold (5 points by default), and a coverage list (area, what was not checked, why, how to fix).',
    next: 'Tick the fixes the customer agrees to, open the first one-click fix in Review & remediate (or request approval in the change queue), give the API client any missing read permission the coverage list names, then run the assessment again.',
  };
  X.digest = {
    group: 'Find the gaps', name: 'Digest — the evaluation loop', href: '/report/digest',
    what: 'When you click Run the loop now, it re-reads the guidance sources and, for every tenant profile that remembers its secret, only what that profile\'s Scope page puts in scope (FP/TP detection ratio and the ticked packs\' drift when DLP is in scope, the SaaS tenants when SaaS Security runs on Zscaler), writes a digest, and sends it by e-mail or to a Teams or Slack webhook when there is something to decide. It does not re-run the assessment checks or re-score the tenant.',
    why: 'Nothing reads the tenant on its own: every read counts against the ZIA API rate limit, so the timer is off unless the operator sets DLP_CHECK_CONTINUOUS_EVAL_HOURS. When it is on, nobody has to remember to check. A new Zscaler or partner article, a noisy rule, a SaaS tenant that lost its authorisation or a pack the customer changed all show up as a proposal in your queue, with the evidence. For a schedule that outlives the server, use Task Scheduler or cron (the Digest tab says how).',
    when: 'Read it when it arrives; open the tab to run the loop now, to see which sources are stale, or to check what is notified where.',
    get: 'The latest digest with counts, the full text, the watched sources with their state, the SaaS capability matrix, the schedule and the notification settings.',
    next: 'Decide the new proposals in FP/TP detection ratio; a stale source or a missing notification setting is fixed in local_settings.bat.',
  };
  X.compliance = {
    group: 'Find the gaps', name: 'Regulatory & compliance alignment', href: '/report/compliance',
    what: 'The assessment findings mapped to the frameworks the customer answers to (HIPAA, PCI DSS, NIST, CMMC, SOC 2, and so on), scoped to the industry on the tenant profile.',
    why: 'Auditors and CISOs think in controls, not in Zscaler settings. This turns "SSL inspection is off for webmail" into the control it fails.',
    when: 'When the customer\'s security or compliance team is in the room.',
    get: 'Coverage per framework, weakest first, with the findings behind each control.',
    next: 'Use it to prioritise: fix the findings that clear the most controls for the customer\'s framework.',
  };
  X.packs = {
    group: 'Close the gaps', name: 'Deploy policy packs', href: '',
    what: 'Ready-made, layered DLP policy for one situation (Healthcare PHI, CJIS, Federal CUI, Zscaler enterprise best practice, source code, banking). Preflight reads the tenant and shows exactly what would be created; you approve; every rule arrives disabled.',
    why: 'Building dictionaries, engines and rules by hand takes days and is error-prone. A pack is the design the customer would end up with, deployed in minutes, with nothing they already have overwritten.',
    when: 'After the assessment, when the customer has agreed to close the gap. Preflight is safe to run any time: it writes nothing.',
    get: 'A plan (create / keep / conflict), impact cards, and after deploying a record you can undo.',
    next: 'Zscaler Made Easy activates the change when the deployment finishes (if that call is refused, activate in the ZIA Admin Portal); then enable rules one at a time in monitor mode, and harden.',
  };
  X.flow = {
    group: 'Close the gaps', name: 'Deploy flow diagram', href: '/report/flow',
    what: 'A picture of the plan a preflight produced: which dictionaries feed which engines, which engines feed which rules, and on which channels.',
    why: 'A customer approving a deployment wants to see what it is, not read JSON.',
    when: 'In the review step of Deploy policy packs.',
    get: 'The diagram, keyboard-navigable, with the counts per channel.',
    next: 'If it matches what the customer expects, approve and deploy.',
  };
  X.deployflow = {
    group: 'Close the gaps', name: 'How a deployment works', href: '/report/deploy-flow',
    what: 'A step-by-step walk-through of what happens when a policy pack is deployed or removed: plan, validate, approve, write in order, activate, read back. Click a step to open it.',
    why: 'Every pack takes the same road, and knowing the road makes a log line or a failure message obvious instead of alarming.',
    when: 'Before the first deployment with a customer, or whenever a message in the deploy log needs context.',
    get: 'The deploy flow and the removal flow, each step with what happens, what can stop it and what you see on screen. Nothing touches the tenant.',
    next: 'Open Deploy policy packs and run a preflight; it writes nothing.',
  };
  X.refportfolio = {
    group: 'Reference', name: 'Data Security Portfolio Framework', href: '/reference/data-security-portfolio-framework',
    what: 'Zscaler\'s data-security portfolio as an operating program: pick the coverage a customer needs, turn it into a customer-ready story, and turn the promised capabilities into a testable proof-of-value plan.',
    why: 'The assessment says where a tenant is; this page says what the whole portfolio can do and in which order to bring it in.',
    when: 'When you are shaping a proposal or a proof of value after the assessment.',
    get: 'The framework page with its coverage selector, story builder, proof plan and the architecture behind the capabilities; it works offline inside the tool.',
    next: 'Select the controls the findings point at, build the story, and bring the proof plan to the customer.',
  };
  X.refai = {
    group: 'Reference', name: 'Public AI security framework', href: '/reference/ai-security-framework',
    what: 'AI security controls as an operating model: coverage by phase, the story for the customer, and a proof plan for what was promised.',
    why: 'AI traffic is the newest place data leaks from, and customers ask for a framework, not a feature list.',
    when: 'When the customer asks how Zscaler secures AI use, or when the GenAI checks in the assessment come back weak.',
    get: 'The framework page with its selectors, story builder and proof plan, in the languages it ships with.',
    next: 'Pair it with the assessment\'s GenAI findings and the source-code and CUI packs.',
  };
  X.refgenai = {
    group: 'Reference', name: 'Public GenAI security framework', href: '/reference/genai-security-framework',
    what: 'The generative-AI subset of the AI security framework: the same operating model, story builder and proof plan, narrowed to generative tools.',
    why: 'Most customer conversations start with ChatGPT and Copilot, not with the whole AI estate.',
    when: 'When the conversation is about generative-AI tools specifically.',
    get: 'The framework page with its coverage selector, story builder and proof plan.',
    next: 'Use it for the first meeting; move to the full AI framework when the scope widens.',
  };
  X.refmachine = {
    group: 'Reference', name: 'The framework machine', href: '/reference/framework-machine',
    what: 'How the framework pages are built and kept portable: the six components, the assembly line, the one direction of trust, and the setup order on a fresh machine.',
    why: 'An engineer who has to maintain or move the framework pages needs the shape of the machine, not the pages alone.',
    when: 'When you set the frameworks up somewhere else or change how they are produced.',
    get: 'A short, static page with the components, the order and the known portability traps.',
    next: 'Follow the setup order; check the traps list before moving anything.',
  };
  X.dsarchitect = {
    group: 'Reference', name: 'Data Security Architect', href: '/reference/data-security-architect',
    what: 'Zscaler\'s data-security reference architecture, offline inside the tool: the DLP chain end to end, then one module per link (dictionaries, engines, inline web, endpoint, email, SaaS API and SSPM, EDM and IDM, AI security, Workflow Automation), each with its diagrams, limits tables and gotchas, plus the setup sequences that break when a step is skipped and the symptom-to-cause walkbacks.',
    why: 'This tool\'s flow pages (Traffic flow & gaps, Path analyzer, SSL inspection flow, Bypass & non-inspected traffic) are the gap analysis and the traffic flows read live from a tenant; the Architect page is the reference architecture they are measured against, so a gap on a flow page and its intended design sit one click apart.',
    when: 'While reading a flow page or a gap, when a finding or a proposal needs the reference architecture behind it, when a channel is set up in the wrong order, or when a symptom (empty Workflow Automation, a rule that never fires) needs walking back to its cause.',
    get: 'Thirty-three diagrams (click any one for full size), the limits and behaviour tables for dictionaries and engines, what reaches DLP and what never does per channel, the setup sequence per channel with its gates, and the walkbacks ordered by hit-rate. The live source site is linked at the top for the current version.',
    next: 'Compare the tenant\'s flow with the reference flow, then use the framework pages, the policy packs or the Terraform hand-off to close the gap.',
  };
  X.operations = {
    group: 'Close the gaps', name: 'Bulk changes', href: '/report/operations',
    what: 'Changes many things at once, safely: enables or disables up to 100 rules across URL filtering, SSL inspection, Cloud Firewall, Cloud App Control, File Type Control and the four DLP channels; puts one policy\'s rules in a new order with the fewest moves; adds, removes, moves or copies URLs between custom URL categories; and moves ZPA domains between application segments or clones a segment. Rules from a spreadsheet (ZIA) and Rules from a spreadsheet (ZPA access policy) export Cloud Firewall, URL filtering or ZPA access policy rules as CSV (names, not ids, with the order and rank) and import the edited file as one reviewed plan of adds, updates, moves and, only when you tick it and type DELETE <n> RULES, deletes. Its builders (Build new) create named, disabled-by-default objects from a template: the ZIA security baseline, a ZPA App Connector group, ZPA application segments and ZPA policy rules, Client Connector profiles, ZDX probe setup, AI Guard routing for GenAI apps and an AI Guard detection policy, the SSL certificate manager, and the Firewall import from Palo Alto Networks (the groups, services and disabled Cloud Firewall rules of a migration plan); and they take a build back: delete ZPA objects by prefix, delete a Client Connector profile, delete ZDX apps and probes, or turn ZDX apps and probes on or off. Build new also has Edit a rule (create, edit, duplicate or delete one URL filtering, Cloud Firewall, SSL inspection, forwarding, Web DLP, DNS Control, IPS, File Type Control, Sandbox or Cloud App Control rule, created disabled, with a plain-language preview of what it does and where it goes), Edit a ZPA application segment (its settings and ports, or enable or disable it), Cloud app instances and tenancy restrictions (browse, create or edit), and Proxy chaining (create or edit a proxy; the gateway is listed as a portal step); Enable or disable rules also covers DNS Control and IPS. Under Backups it saves read-only configuration backups of ZIA, ZPA and Client Connector (secrets masked), compares them field by field, and plans Restore or clone ZIA, Restore or clone ZPA and Restore or clone Client Connector from a backup or a template, in dependency order, with a fresh backup first and Undo.',
    why: 'Clean-ups found by the assessment and Shadowed rules usually mean dozens of clicks in the portal, one rule at a time, with no record of what each rule was before. Here the whole change is one reviewed plan, with the value before and after for every item and a way back.',
    when: 'After Shadowed rules or the assessment name rules to disable, reorder or clean up, when a customer asks to move URLs or ZPA domains between categories or segments, when a POV or a finding needs objects built (a finding\'s "Build" link opens the right builder), and whenever a change touches more than a handful of objects.',
    get: 'A preview of every item (before, after, already as asked, excluded and why, the rules that use each URL category), a plan PDF for change approval, the apply with a per-item result (a conflict when someone changed an item since the preview, never overwritten), the read-back, and a record with Undo.',
    next: 'Download the plan for the change ticket, apply it in write mode with the customer\'s agreement, check the per-item result, and keep Undo for the rollback window; run Shadowed rules again to prove the clean-up.',
  };
  X.terraform = {
    group: 'Close the gaps', name: 'Terraform hand-off', href: '/report/view?tool=terraform',
    what: 'The same policy pack as a Terraform workspace for the official zscaler/zia provider. Static mode needs no credentials; gap mode reads the tenant and imports what exists so the customer\'s first plan is exactly the gap.',
    why: 'Some customers only change Zscaler through code review and a pipeline. This gives their platform team the pack in their language.',
    when: 'Only when the customer\'s platform team manages Zscaler as code (a pipeline, code review). Gap mode: the tenant already has DLP dictionaries, engines or rules, so existing objects are imported and the first plan creates only the gap; it reads the pack\'s objects from the tenant. Static: a new or empty tenant, no credentials, or a reference to review; the team imports anything that already exists before applying. If the customer changes Zscaler in the portal, use Deploy policy packs instead.',
    get: 'A ZIP with main.tf, variables and import blocks, plus the README for the platform team.',
    next: 'Hand the ZIP over; they run terraform plan and see the gap.',
  };
  X.migration = {
    group: 'Close the gaps', name: 'Evaluate All Rules migration wizard', href: '',
    what: 'Moves a tenant from first-match-wins to Evaluate All Rules safely: reads the current rules, reorders them so nothing changes behaviour, and shows the plan before anything is posted.',
    why: 'With first-match-wins one broad monitor rule at the top silently hides every block rule under it. Layered policy (monitor plus block) needs Evaluate All Rules.',
    when: 'When check 5.20 in the assessment says the tenant is on first-match-wins.',
    get: 'A five-step wizard: assess, download current rules, optimise, enable the switch, post the new rules.',
    next: 'Read the reordering plan with the customer; the switch itself is flipped in the ZIA portal.',
  };
  X.evalall = {
    group: 'Reference', name: 'How Evaluate All Rules decides', href: '/report/evalall',
    what: 'The decision flow with the tie-breaker (most restrictive action wins; a tie is broken by rule order) and which channels use it, as a diagram you can put in front of the customer.',
    why: 'Engineers get this wrong constantly and then cannot explain an incident. Five minutes here saves an argument with the customer.',
    when: 'Before the migration wizard, or when an incident\'s winning rule surprises someone.',
    get: 'The diagram and which channels use it (Web, Endpoint, Email; SaaS is first-match, no tie-breaker).',
    next: 'Open the Inline DLP rule migration wizard to see the tenant\'s own rules in order, then set the Advanced Settings switch in ZIA when the customer agrees.',
  };
  X.bestpractices = {
    group: 'Reference', name: 'Best practices library', href: '/report/view?tool=bestpractices',
    what: 'Curated Zscaler best-practice articles, rated by source, refreshed from help.zscaler.com, the blog and the developer portal.',
    why: 'When a customer asks "says who?", you point at the article.',
    when: 'While writing up findings, or to read up before a meeting.',
    get: 'Articles grouped by area with the link and the source rating.',
    next: 'Cite the article next to the finding in your write-up.',
  };
  X.exports = {
    group: 'Reference', name: 'Policy exports', href: '/report/exports',
    what: 'Every export the app has, in one place: the assessment as Excel or Word, the DLP inventory (each engine with its expression in dictionary names and in one sentence), deployment plans as PDF or Excel, Export from tenant, and read-only exports of the URL filtering, Cloud App Control, SSL inspection, Cloud Firewall and File Type Control policies (every rule in order with names, not ids, and the shadowed-rule findings per rule), the locations and location groups with the rules that use them, the Client Connector app and forwarding profiles with their PAC files, one workbook of every URL the policy names, and the custom URL category analyzer. Export options pick the columns, one row per value, and the separator.',
    why: 'Customers want the policy on paper for change boards, audits and handovers, and a custom URL category often repeats what Zscaler already knows or overrides it by mistake. A formatted export answers both without screenshots of the admin portal.',
    when: 'Before a change board or an audit, when handing a tenant over, during a policy clean-up, and before trimming custom URL categories.',
    get: 'One workbook (or PDF review copy) per policy, a locations workbook with each site\'s settings and the rules that name it (no IP list, VPN credential or key), a Client Connector workbook showing which profile uses which forwarding profile and PAC URL (no password or token), a deduplicated URLs workbook with where each entry was found, and per custom-category URL whether Zscaler categorises it the same way, differently or not at all; each with a live log and Stop.',
    next: 'Send the policy workbooks with the change request, fix the rules the Usage and notes column flags, and remove custom-category URLs the analyzer marks redundant after checking with the customer.',
  };
  X.queue = {
    group: 'Close the gaps', name: 'Change queue', href: '/report/queue',
    what: 'The team change queue: a policy-pack deploy plan, a selective removal plan, a fix recipe that someone prepared and filed with Request approval, or a plan a scheduled sync job made, waiting for a second writer to approve or reject it, with its items, requester, comments and plan hash. Scheduled sync jobs live here too: each run only reads the source and the targets and files a plan per target; nothing is applied until a named writer applies the approved plan.',
    why: 'A change to the customer\'s tenant is reviewed by a second person before it is made (four-eyes), and every step is in the audit log with who did it, which is what a change board or an auditor asks for.',
    when: 'After a preflight or a recipe preview, when you want a colleague to review the change before it is applied, or when you are the reviewer with requests waiting.',
    get: 'Pending, approved and history tabs; Approve, Reject (with a comment), Apply and Withdraw buttons shown according to your rights; the four-eyes setting and whether it can work here; and the queue as JSON or Markdown.',
    next: 'Approve or reject what is pending; apply an approved request with write mode on and the typed confirmation (a request whose plan no longer matches the tenant is marked stale: request it again from a fresh preflight).',
  };
  X.selfheal = {
    group: 'Close the gaps', name: 'Self-healing', href: '/report/self-heal',
    what: 'Two things in one page. This app: the app checks itself (stuck jobs, damaged saved files, files others could read, locks left behind, rate-limit pauses that lasted too long, a sign-in that keeps failing, low disk space, an update without a restart), fixes what it safely can and says what it did. Your tenant: settings you approved that changed back since (a rule turned off, an action made weaker, an engine or dictionary edited or deleted, a fix someone undid).',
    why: 'Problems in the app should not need an engineer to find, and a customer\'s protection quietly drifting back after a deployment is the most common way a good assessment goes stale. Seeing it, with who changed it and the exact change that puts it back, keeps the tenant where the customer agreed it should be.',
    when: 'Whenever the main page shows the self-healing banner, after a colleague or another tool may have touched the tenant, and before a review meeting where the customer asks whether the settings are still as agreed.',
    get: 'Each app check as OK, Healed or Needs you, with what was done and the next step; for the tenant, every drifted setting with what changed, who and when (from ZIA\'s audit log when Automation readiness is in scope), and Heal or Accept buttons. Nothing in the tenant changes until you click Heal.',
    next: 'Heal what should go back (write mode on, typed confirmation, read again before and after, undo available), or click Accept when the change was agreed so it is not proposed again; then activate in the ZIA Admin Portal.',
  };
  X.advanced = {
    group: 'Reference', name: 'Advanced settings', href: '/report/advanced',
    what: 'Add your own policy packs (JSON, Terraform, native Zscaler API exports or a ZIP) to the library, transcribe native exports to Terraform, download the companion browser extension (badges and a side panel on DLP objects, policy rules and the objects they use in the ZIA admin console, export to JSON or Terraform, and the Path analyzer for any site), see how this server is configured (bind host, token gate, write mode, limits), check for and install app updates, read this app\'s own quality and security score and its CISA Secure by Design score, and run the daily upstream contract check (the Zscaler SDK, API and Terraform provider the app depends on, offline).',
    why: 'Customers and colleagues have their own designs; this puts them through the same preflight and deploy as the built-in packs.',
    when: 'When someone hands you a pack or an export from another tenant.',
    get: 'A validation preview (what it contains, what blocks it) before anything is added.',
    next: 'Add it; it then shows up in Deploy policy packs and the Terraform hand-off.',
  };
  X.qualityscore = {
    group: 'Reference', name: 'Quality and security score', href: '/report/advanced#quality',
    what: 'One score from 0 to 100 for this app itself (not your tenant): how many tests passed in the last full run, which security findings the QA checks recorded and which are still open, and how many controls of OWASP ASVS, WCAG 2.2, CWE, SLSA, OpenSSF Scorecard and NIST SSDF have a test. Sub-scores cover regression, secure by design, functionality and motion.',
    why: 'Before you put a customer tenant in front of the app, you can see how well the app is tested and whether any serious problem is known and still open. An open critical or high finding caps the score, so a good number cannot hide one.',
    when: 'Before an engagement, after updating the app, or when someone asks how the tool itself is tested and secured.',
    get: 'The overall score and grade, a bar chart and a table per area, finding counts by severity and status, every open finding with its reason, the standards covered and the date and commit of the test run; the full report as QUALITY_SCORE.md.',
    next: 'If a finding is open, read its reason and check whether it touches what you plan to do; update the app when a fix ships. Nothing here reads or changes a tenant.',
  };
  X.updates = {
    group: 'Reference', name: 'Zscaler updates', href: '/report/view?tool=updates',
    what: 'A check of PyPI and help.zscaler.com for SDK and documentation changes since the last check, with a quality check on each link so you are not sent to an empty page.',
    why: 'Zscaler changes the product every few weeks; a finding that cites an outdated page loses credibility.',
    when: 'Once a month, or before a big engagement.',
    get: 'What changed, with a working link or a fallback to the section it now lives in.',
    next: 'Skim for changes in the areas your customer cares about.',
  };
  X.beacon = {
    group: 'Reference', name: 'Beacon: SDK, API & Terraform changes', href: '/report/beacon',
    what: 'A watch on the three things outside this app that can silently break it: the Zscaler Python SDK (a new release, and whether it changes a module the app calls), the ZIA API (the SDK\'s machine-readable service definition, the API reference and the help-center pages) and the zscaler/zia Terraform provider (its version against the pin, its schema and docs). It runs on a timer while this server runs and whenever you click Run now, and says what changed since the last run. Optionally it reads from one tenant only the endpoints that belong to what is in scope on the Scope page (the ticked scopes; for every scope only the channels marked Zscaler, exactly as the assessment reads them; every request counts against the tenant\'s ZIA API rate limit), GET only, and says which ones now answer differently.',
    why: 'When Zscaler moves an endpoint, renames a field or ships an SDK that changes a request body, a deploy or a check fails in front of the customer. Beacon says so first, in plain words, with what to do.',
    when: 'Glance at it before an engagement and after a Zscaler release; run the tenant API watch when a check starts answering 403 or 404 and you want to know whether the endpoint or the permission moved.',
    get: 'A "Changed since last run" list (versions that moved, drift that is new or cleared, pages that changed, tenant endpoints whose answer changed), the SDK, API and Terraform detail, and the last 30 runs.',
    next: 'Act on new drift: read the SDK or provider changelog before upgrading, grant the permission a 403 names, or report an endpoint that moved.',
  };
  X.audit = {
    group: 'Troubleshoot', name: 'Audit timeline', href: '/report/audit',
    what: 'One timeline, newest first, of who changed what in the tenant: ZIA\'s admin audit log for the window you choose, merged with Zscaler Made Easy\'s own deployment records and audit log, with filters, field-by-field diffs and CSV or JSON export.',
    why: 'When a rule stops behaving as deployed, the first question is who touched it and when. The timeline marks every change someone else made to an object Zscaler Made Easy created, so drift is explained instead of guessed.',
    when: 'After a deployment, before a review with the customer, or whenever a policy pack object no longer matches what was deployed and you need to know which admin changed it, through which interface.',
    get: 'Every audit log entry with time, admin, action, category, object, interface and result; Zscaler Made Easy\'s deployments and writes beside them; changes by someone else to Zscaler Made Easy objects flagged; before and after values compared field by field.',
    next: 'Open a flagged row to see exactly what changed, then decide with the customer whether to fold the change into the pack or restore the deployed version.',
  };
  X.fleet = {
    group: 'Find the gaps', name: 'Client Connector fleet', href: '/report/fleet',
    what: 'Reads the Client Connector app and forwarding profiles, the hosted PAC files, the enrolled devices and their per-device service status, and puts them together: ZIA, ZPA and ZDX activity, blind spots, bypass risk, ghost devices, registration anomalies, multi-device users and version drift, a profile heatmap, profile and PAC comparisons and a ranked remediation plan.',
    why: 'A profile that looks fine on paper protects nothing on a device where ZIA is switched off, and a weak profile matters most when thousands of devices use it. This shows where the fleet really is, weighted by the devices each gap affects.',
    when: 'After the assessment, when ZCC is in scope, to show the customer which devices Zscaler cannot see and which profile to fix first; and on every return visit to watch the drift.',
    get: 'Fleet tiles, each alert with its exact definition and the devices in it, profiles against the checks (equal-weight and device-weighted scores), a side-by-side profile diff, the PAC comparison and a ranked plan you can export as CSV, with a counts-only option; and the install command builder, which writes the Client Connector install command and a script to run next to the installer for an app profile you pick (nothing is installed from here).',
    next: 'Work down the remediation plan: the first lines are the gaps with the most devices behind them. Fix the profile in the Client Connector Portal, then read the fleet again.',
  };
  X.logs = {
    group: 'Troubleshoot', name: 'Log analyzer', href: '/report/logs',
    what: 'Drop in the ZIP that Client Connector\'s Export Logs produced (or single .log files, or a PAC file). It reads them on this computer and tells you what happened, what it means for the user, and what to do next.',
    why: 'Most "Zscaler is broken" tickets are a captive portal, a blocked UDP port, a proxy in the path or a certificate. The analyzer recognises those stories so you do not have to read ten thousand lines.',
    when: 'Any time a user reports that Client Connector will not sign in, will not connect, or that the internet stopped; and whenever a customer sends you a PAC file to review.',
    get: 'A one-line verdict, the facts (version, OS, user, cloud, tunnel), findings ordered by how much they hurt the user with numbered next steps and redacted evidence, and for a PAC every bypass with its risk.',
    next: 'Do the numbered steps of the top finding; if it names a portal setting, that is where to look.',
  };
  X.zcc = {
    group: 'Troubleshoot', name: 'Diagnose ZCC access', href: '/report/view?tool=zcc',
    what: 'Probes every Client Connector (ZCC) API endpoint with the credentials you entered and shows which answer.',
    why: 'The ZCC checks in the assessment can only be as good as what the API client is allowed to read. This tells you whether a blank ZCC section is a permission problem.',
    when: 'When ZCC findings look empty or say "not accessible".',
    get: 'A table: endpoint, what it is for, status, how many items came back.',
    next: 'If endpoints answer 401 or 403, the API client needs the ZCC read role; ask the customer admin.',
  };
  X.permissions = {
    group: 'Troubleshoot', name: 'Required API access', href: '/permissions',
    what: 'What this API client can do now, per product (ZIA, ZPA, Client Connector, ZDX, Z-Insights, AI Guard): can read, can change or no access, the licences and SKUs the tenant has, and what each gap blocks in this app. Below that, the minimum API roles each assessment scope needs and what a configuration change needs on top.',
    why: 'The customer admin will ask "what access does this tool need?" before creating the API client, and a role that is a little too small fails quietly later. This answers both: the least access that works, and what is missing right now, with the steps to ask the admin for.',
    when: 'Before the engagement, when the API client is being created; right after Authenticate, which runs the readiness check by itself; and whenever a scope comes back partial.',
    get: 'A per-product table read from the access token (without checking its signature, for display only) and a few reads in scope, the licence list, every Scope page key and every change that will not work with the reason and plain steps, and the per-scope list you can send to the customer as-is.',
    next: 'Send the steps to the customer admin; once they have added the access, click Authenticate again and reload this page to see the new answer.',
  };
  X.remediate = {
    group: 'Close the gaps', name: 'Review & remediate', href: '',
    what: 'For each failed check with a known fix, a guided change: what will be changed, on which object, with a before / after view, applied only in write mode after your approval.',
    why: 'Findings without a way to fix them are just a longer to-do list.',
    when: 'After the customer agrees to a fix and the server is in write mode.',
    get: 'A wizard per finding with the exact change and a read-back afterwards.',
    next: 'Re-run the assessment to see the score move.',
  };
  X.updateapp = {
    group: 'Reference', name: 'Update app', href: '',
    what: 'Fetches the latest version of this app from GitHub, installs the pinned dependencies and restarts the server. The Branch dropdown next to the button picks what it pulls: Stable (main) is what customers run; QA and Development carry a fix before it is promoted, so it can be tried early. With no change made there, an update stays on the branch the install is already on.',
    why: 'Fixes and new checks ship weekly; running an old build means findings the customer already fixed elsewhere.',
    when: 'When the Start here panel says an update is available.',
    get: 'The app restarts on the same address; the browser reconnects.',
    next: 'If it fails, the message says whether it is TLS inspection, sign-in or connectivity, and what to do.',
  };
  X.vendormigrate = {
    group: 'Close the gaps', name: 'Migrate from another DLP', href: '/report/vendor',
    what: 'Upload another vendor\'s DLP policy export, review every policy\'s translation in a decisions file, and get disabled ZIA dictionaries, engines and rules on every channel as Terraform. Four adapters read their vendor\'s own export file types: Symantec DLP (the Enforce XML), and Forcepoint, Netskope and Skyhigh (Forcepoint\'s policy zip or REST JSON; Netskope\'s Real-time Protection export as JSON or CSV with the dictionary CSVs; Skyhigh\'s Policy Templates zip or SSE policy JSON). Each shows an API cross-reference: which source object and field lands on which ZIA object and field, through which ZIA API call and Terraform resource, and how it is carried. A source policy can be carried to any of the four ZIA channels, one decision per channel: web, endpoint (Client Connector), SaaS Security API and outbound email, every rule DISABLED. Leaving a Palo Alto Networks firewall: the Firewall and private access section reads a PAN-OS configuration export and builds a plan for Bulk changes (Cloud Firewall rules with their IP groups and network services, ZPA segments for GlobalProtect access), listing everything it cannot carry with the reason.',
    why: 'A customer leaving Symantec, Forcepoint, Netskope or Skyhigh wants their policies on Zscaler without retyping them, and without a tool guessing what a policy meant. Every translation here is a reviewed decision bound to the exact export, so nothing is deployed that a person did not approve.',
    when: 'At the start of a migration engagement, once the customer has exported their policies, and again whenever the export changes (a changed export invalidates the decisions until they are reviewed).',
    get: 'An inventory of every source policy with the detection facets recognised in it, a decisions template to fill in, then a migration report (converted, blocked with the question to answer, retired), an efficacy mapping that says what share of each policy\'s recognised detection the translation carries with the arithmetic behind every number, and, only when nothing is blocked, the Terraform with every rule DISABLED: a workspace (.zip, the same file layout as the pack hand-off, terraform fmt-clean, with a README, variables and outputs) or the same configuration as main.tf.json.',
    next: 'Review the decisions with the customer, compile until the report says ready, then hand the Terraform to the platform team or run it against a test tenant; enabling rules and ordering them with the existing policy are separate change-control steps. For a firewall plan: open it in Bulk changes (Firewall import from Palo Alto Networks), preview against the tenant and apply through the usual gates; every rule arrives disabled.',
  };
  X.plugin = {
    group: 'Close the gaps', name: 'Plugin pages', href: '/report/plugin',
    what: 'A read-only page added by a local plugin an admin approved in Advanced settings (Local plugins): a title and a table, shown as plain text. Local plugins are off by default and load only when their exact SHA-256 is on the allow-list.',
    why: 'A team can add a view of its own (a count, a list, a check) without changing the app, while the app keeps control of what the page can show.',
    when: 'Only when an admin has switched local plugins on and approved a plugin that adds a page; the link comes with the plugin.',
    get: 'The plugin\'s table and notes. Nothing on the page changes a tenant.',
    next: 'Ask the admin who approved the plugin what its table means; revoke the plugin in Advanced settings to remove the page at once.',
  };
  X.help = {
    group: 'Start', name: 'What does everything do?', href: '/help',
    what: 'This page: every function of the app explained in plain English, in the order you will need them on a first engagement.',
    why: 'You should never have to guess what a button does or why the customer would care.',
    when: 'Day one, and whenever a page has a box at the top you have not read yet.',
    get: 'One card per function: what it is, why it matters, when to use it, what you get, what to do next.',
    next: 'Follow the numbered first-engagement list; each page explains itself at the top.',
  };
  X.simple = {
    group: 'Start', name: 'Simple mode', href: '/simple',
    what: 'The same app as seven big tasks in plain words, for someone with little Zscaler knowledge: connect, check how safe the data is, fix the top problems, protect sensitive data with a policy pack, why was something blocked, what changed, and a report for the boss. Each task is a short wizard with one question per screen, a tap-to-explain glossary and one recommended next step.',
    why: 'A customer admin, a manager or a new engineer can get a score, the top three fixes and a Word report without learning the expert pages first; the expert view is one click away on every screen.',
    when: 'For a first look, for a non-specialist who owns the tenant, or to walk someone through the basics; switch to expert mode for anything the wizards do not cover.',
    get: 'Traffic-light answers with the words always shown, the assessment score and top findings, a policy-pack preview, the Path analyzer verdict in one sentence, the score history and a Word or spreadsheet report.',
    next: 'Anything that changes the tenant opens the expert flow it belongs to (Deploy policy packs, Review & remediate) with its write mode, preview and confirmation; read-only tasks say so on screen.',
  };
  X.find = {
    group: 'Start', name: 'Find anything', href: '',
    what: 'One search box over the whole app, opened with Ctrl+J (Cmd+J on a Mac), the / key or the Find button: the pages and what they do, the glossary words with their plain meaning, the tenant\'s rules, dictionaries, engines, URL categories and other objects from the last read, the findings of the assessment on screen, and your open to-dos.',
    why: 'Nobody remembers which of forty pages does what. Typing "export to terraform" or "why is this blocked" lands on the right page, typos included, and a rule or dictionary opens with what it uses, what uses it, its findings and your notes.',
    when: 'Whenever you know what you want but not where it lives, while walking a customer through their objects, and to jump to an object or finding without scrolling.',
    get: 'Results as you type, each with its type (Page, Term, DLP rule, Finding, To-do) and one line; Enter opens it. A tenant object opens as a card with links to the pages that act on it and its tags, to-dos and comments.',
    next: 'Typing never reads the tenant: click Load tenant objects once (read-only, only what is in scope) to search the tenant\'s objects too, then tag what needs work and add a to-do.',
  };
  X.todo = {
    group: 'Close the gaps', name: 'To-do list', href: '/report/todo',
    what: 'Every open to-do written on a rule, dictionary, URL category, finding or other object, across your tenants, with the object it is on, its tags, who wrote it and when. Tick one when it is done; filter by tenant and tag.',
    why: 'Clean-up work found during an assessment is easy to lose between visits. Notes on the object itself, kept per tenant on this computer, turn findings into a list the team can work through and prove done.',
    when: 'At the end of an assessment to agree the follow-ups, at the start of a return visit, and whenever someone asks what is still open for a customer.',
    get: 'A table of open to-dos (or all of them) with the tenant, the object and its tags, a filter by tag, a done checkbox per row, and a link back to the object in Find anything.',
    next: 'Work down the list: open the object, fix it on the page its card links to, then tick the to-do. Add new ones from any object card in Find anything (Ctrl+J).',
  };

  X.pov = {
    group: 'Start', name: 'POV planner', href: '/report/pov',
    what: 'Plans and runs a customer proof of value (POV) for one tenant profile: the intake (customer, internal domain, a short prefix, a vertical preset and the products in scope), the customer\'s success criteria, a runbook of tests per product with pass or fail, notes and evidence, a test kit, the timeline, notes and follow-ups.',
    why: 'A POV is won on proof the customer agreed in advance. Criteria linked to tests, evidence on each test and a report built from what actually ran turn a week of testing into a decision the customer can sign off.',
    when: 'At the kickoff call to fill in the intake and agree the criteria, during the POV to run and record each test, and at the close to hand over the report.',
    get: 'Per test: the steps, the expected result, Prove it (the Path analyzer\'s verdict for the test\'s destination, read-only) and Insights counts; synthetic DLP files per vertical, the EICAR test file and AMTSO links, a unique PDF for Cloud Sandbox; a Word or PDF customer report; export, import and templates.',
    next: 'Start the POV on the Plan tab, download the test kit, run the tests on the Runbook tab, then download the customer report. Changes to the tenant go through Deploy policy packs or Bulk changes, whose records the report lists.',
  };

  // Which entry a page belongs to, by its path (and ?tool= on the results tab).
  function keyFor(loc) {
    const p = (loc || window.location).pathname.replace(/\/+$/, '') || '/';
    const tool = new URLSearchParams((loc || window.location).search).get('tool');
    if (p === '/report/view') return tool && X[tool] ? tool : 'results';
    const map = { '/': 'assessment', '/report/dataflow': 'dataflow', '/report/path': 'path', '/report/zpa': 'zpa', '/report/device-posture': 'deviceposture', '/report/shadow': 'shadow', '/report/browser': 'browser', '/report/operations': 'operations', '/report/exports': 'exports', '/report/motion': 'motion', '/report/live': 'live', '/report/bypass': 'bypass', '/report/sslflow': 'sslflow', '/report/sslcoverage': 'sslcoverage',
      '/report/flow': 'flow', '/report/deploy-flow': 'deployflow', '/report/advanced': 'advanced', '/report/health': 'health', '/report/compliance': 'compliance', '/report/evalall': 'evalall', '/report/vendor': 'vendormigrate', '/report/plugin': 'plugin',
      '/report/logs': 'logs', '/report/audit': 'audit', '/report/digest': 'digest', '/report/queue': 'queue', '/report/self-heal': 'selfheal', '/report/insights': 'insights', '/report/posture': 'posture', '/report/beacon': 'beacon', '/permissions': 'permissions', '/help': 'help', '/simple': 'simple', '/report/fleet': 'fleet', '/report/todo': 'todo', '/report/pov': 'pov' };
    return map[p] || '';
  }

  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const LS = 'zassess_explain_hidden';
  function hidden() { try { return localStorage.getItem(LS) === '1'; } catch (e) { return false; } }
  function setHidden(v) { try { localStorage.setItem(LS, v ? '1' : '0'); } catch (e) { /* ignore */ } }

  // The card's inner HTML for one entry (shared by the page box and /help).
  function cardHtml(key, withOpen) {
    const x = X[key]; if (!x) return '';
    const open = withOpen && x.href ? `<p><a class="rp-btn" href="${E(x.href)}" target="_blank" rel="noopener">Open ${E(x.name)}</a></p>` : '';
    return `<dl class="xp-dl">
      <dt>What it is</dt><dd>${E(x.what)}</dd>
      <dt>Why it matters to the customer</dt><dd>${E(x.why)}</dd>
      <dt>When you use it</dt><dd>${E(x.when)}</dd>
      <dt>What you get</dt><dd>${E(x.get)}</dd>
      <dt>What to do next</dt><dd>${E(x.next)}</dd>
    </dl>${open}`;
  }

  // On a report page: a box under the title, open by default, with a
  // remembered "hide" for people who no longer need it.
  function mount() {
    const key = keyFor();
    if (!key || key === 'assessment' || key === 'help' || key === 'simple' || document.getElementById('xpBox')) return;
    const hero = document.querySelector('.rp-hero');
    if (!hero) return;
    const box = document.createElement('section');
    box.id = 'xpBox'; box.className = 'xp-box'; box.setAttribute('aria-labelledby', 'xpH');
    box.innerHTML = `<details class="xp-details" ${hidden() ? '' : 'open'}>
      <summary><span id="xpH">What is this page, and why it matters</span> <span class="xp-dim">(${E(X[key].name)})</span></summary>
      <div class="xp-body">${cardHtml(key, false)}
        <p class="xp-foot"><a href="/help#${E(key)}" target="_blank" rel="noopener">Every function explained →</a>
        <button type="button" class="xp-link" id="xpHide">${hidden() ? 'Show these boxes by default' : 'Hide these boxes by default'}</button></p>
      </div></details>`;
    hero.insertAdjacentElement('afterend', box);
    const det = box.querySelector('details');
    det.addEventListener('toggle', () => { if (!det.open) setHidden(true); });
    box.querySelector('#xpHide').addEventListener('click', e => { const h = !hidden(); setHidden(h); e.target.textContent = h ? 'Show these boxes by default' : 'Hide these boxes by default'; det.open = !h; });
    if (!document.getElementById('xpStyle')) {
      const st = document.createElement('style'); st.id = 'xpStyle';
      st.textContent = `.xp-box{margin:0 0 1rem}.xp-details{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:0.2rem 0.9rem}.xp-details>summary{cursor:pointer;font-weight:700;padding:0.6rem 0;list-style:revert}.xp-details>summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:8px}.xp-dim{color:var(--dim);font-weight:400;font-size:0.85rem}.xp-body{padding:0 0 0.8rem;font-size:0.9rem;line-height:1.5}.xp-dl{display:grid;grid-template-columns:minmax(150px,max-content) 1fr;gap:0.3rem 0.9rem;margin:0.2rem 0 0.6rem}.xp-dl dt{font-weight:600;color:var(--dim);font-size:0.78rem;text-transform:uppercase;letter-spacing:0.06em;padding-top:0.15rem}.xp-dl dd{margin:0;overflow-wrap:anywhere}.xp-foot{display:flex;gap:1rem;flex-wrap:wrap;align-items:center;margin:0}.xp-foot a{color:var(--accent)}.xp-link{background:none;border:0;color:var(--dim);text-decoration:underline;cursor:pointer;font:inherit;font-size:0.85rem;padding:0}.xp-link:focus-visible{outline:2px solid var(--accent);outline-offset:2px}@media (max-width:600px){.xp-dl{grid-template-columns:1fr}}`;
      document.head.appendChild(st);
    }
  }

  window.DLP_EXPLAIN = X;
  window.DLP_EXPLAIN_ORDER = ['assessment', 'simple', 'find', 'connect', 'results', 'help', 'pov', 'dataflow', 'zpa', 'deviceposture', 'path', 'catlookup', 'motion', 'live', 'insights', 'bypass', 'sslcoverage', 'sslflow', 'shadow', 'efficacy', 'browser', 'fleet', 'health', 'compliance', 'posture',
    'digest', 'packs', 'flow', 'deployflow', 'remediate', 'queue', 'todo', 'selfheal', 'operations', 'terraform', 'vendormigrate', 'plugin', 'migration', 'evalall', 'bestpractices', 'exports', 'advanced', 'qualityscore', 'updates', 'updateapp', 'beacon',
    'refportfolio', 'refai', 'refgenai', 'refmachine', 'dsarchitect', 'audit', 'logs', 'zcc', 'permissions'];
  window.DLP_EXPLAIN_GROUPS = ['Start', 'Find the gaps', 'Close the gaps', 'Reference', 'Troubleshoot'];
  window.DLP_FIRST_DAY = [
    ['Connect to the tenant and Authenticate', 'connect', 'Sign-in details only. Save a tenant profile so history is kept.'],
    ['Scope and run the assessment', 'assessment', 'Channels the customer owns, what to check, frameworks; then Run assessment. About 90 seconds, read-only.'],
    ['Read the results, critical findings first', 'results', 'Each one says what it means and how to fix it.'],
    ['Show the customer where inspection is lost', 'dataflow', 'Traffic flow & gaps and SSL inspection flow are the "show me" pages.'],
    ['Map it to their framework', 'compliance', 'Only the frameworks for their industry are shown.'],
    ['Close the gap with a policy pack (preflight first)', 'packs', 'Preflight writes nothing; it is the plan you show the customer.'],
    ['When a user says "Zscaler is broken", use the Log analyzer', 'logs', 'Export Logs from the tray icon, drop the ZIP in, follow the top finding.'],
  ];
  window.DLP_GLOSSARY = [
    ['Dictionary', 'The thing to look for: a list of phrases and/or regular-expression patterns (for example, "MRN" next to a 7-digit number). Zscaler ships predefined ones (SSN, credit cards, medical terms); packs add custom ones.'],
    ['Engine', 'How dictionaries combine into a decision, using AND / OR, match counts and Sum, for example "(SSN more than 4 times) OR (passport number at least once)". Rules point at engines, never directly at dictionaries.'],
    ['Rule (policy)', 'Where and how an engine is enforced: which traffic (web uploads, email, SaaS apps, endpoints), which users, and the action. Rules run in order from the top; the first match wins unless the tenant is set to evaluate all rules.'],
    ['Action: ALLOW vs BLOCK', 'ALLOW means monitor: the transaction goes through and an incident is logged. BLOCK stops it. CONFIRM asks the user first. Every pack ships every rule DISABLED and in monitor (ALLOW, or report on SaaS); nothing in a pack blocks. Enforcing a rule is the customer\'s decision in the portal once incidents have been reviewed, and the journey card records it as progress. Nothing happens until you enable a rule.'],
    ['Severity', 'The label an incident gets in reports (INFO, LOW, MEDIUM, HIGH). It does not change what the rule does. Packs ship at INFO; raise it once a rule is tuned.'],
    ['Policy pack', 'A folder of dictionaries, engines and rules for one purpose: CJIS, the Fed pack, Zscaler\'s enterprise best practice, healthcare PHI. Deploying a pack creates those objects in the tenant.'],
    ['Reference policy pack', 'A policy pack that is the reference a tenant is measured against. Deploy it greenfield (empty tenant: everything is created) or brownfield (existing tenant: what exists is kept exactly as the customer has it, the rest is created). Nothing is ever overwritten. Objects the policy pack does not define are never touched.'],
    ['Greenfield / brownfield', 'Greenfield: none of the pack\'s objects exist yet, so the whole pack is created from scratch. Brownfield: some already exist (perhaps from an earlier deploy, perhaps built by hand); they are kept, only the missing ones are created.'],
    ['Preflight', 'The read-only check Deploy Studio runs before anything is written: it reads the tenant, works out what is missing, what already exists, what conflicts, and what the impact would be. You approve that exact plan.'],
    ['Plan hash', 'A fingerprint of the plan you approved. If the tenant changes between approval and deploy, the fingerprint no longer matches and nothing is written until you review again.'],
    ['Journey (where is this tenant?)', 'The data-governance journey has five stages: Foundation (dictionaries and engines exist), Policies deployed (every rule exists), Visibility (SSL decrypts the risky app classes and DLP rules are enabled), Containment (Cloud App Control, File Type and URL rules are enabled), Enforcement (DLP rules block). The assessment and the pack card place the tenant on that ladder and list the exact rules to enable or harden next.'],
    ['Customized', 'A policy pack object the customer changed: a rule they enabled, an action they hardened from ALLOW to BLOCK, a dictionary they tuned. That is progress, not drift. It is kept as-is and shown as customized; converge mode (an explicit API option) is the only thing that overwrites it.'],
    ['Activation', 'ZIA saves changes as pending until they are activated. A deploy or a removal from Zscaler Made Easy activates when it finishes (a removal after every tier) and reads the tenant back; if that call is refused, an admin activates in the ZIA Admin Portal. A proposal applied from FP/TP detection ratio stays pending for an admin to activate.'],
    ['Read-only vs write mode', 'The server starts read-only: assessment, preflight and journey checks all work, deploying is refused. Deploy policy packs shows the current mode and an Enable write mode button (type the confirmation phrase; it lasts until the server restarts). START_Zscaler_Made_Easy_WRITES_ENABLED.bat (Windows) or ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND ./start.sh (Mac, Linux) starts in write mode from the outset; in the container, which has no switch, put ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND in .env next to docker-compose.yml and run docker compose up -d. Stay read-only when you only want to show the customer the plan.'],
    ['OneAPI credentials', 'The client ID and secret of an API client created in ZIdentity, plus the vanity domain (the short name in the login URL, acme for acme.zslogin.net) and the cloud (Production for almost everyone).'],
    ['Terraform hand-off', 'The same pack as a Terraform workspace for the official zscaler/zia provider, for customers whose platform team manages Zscaler as code. Gap mode reads the tenant and imports existing objects so the first plan shows exactly the gap; static mode needs no credentials. Terraform then owns the objects: a later plan shows how the tenant moved, and apply would converge it, so use plan to assess and apply deliberately.'],
    ['Outbound Email DLP', 'Rules that inspect mail leaving onboarded Microsoft 365 / Gmail tenants (Administration > SaaS Application Tenants). The policy packs ship a monitor-only email rule; preflight skips it, with the reason, when no email tenant is onboarded.'],
    ['Client Connector (ZCC)', 'The Zscaler app on the user\'s device. It signs the user in, builds a tunnel to the cloud and forwards traffic through it. Its Export Logs ZIP is what the Log analyzer reads.'],
    ['Z-Tunnel 1.0 / 2.0', 'The two ways Client Connector carries traffic. 2.0 (DTLS or TLS, needs outbound UDP or TCP 443) carries everything; 1.0 (HTTP CONNECT) carries only web ports. A firewall that blocks UDP 443 forces the fallback to 1.0.'],
    ['PAC file', 'A small script the browser or Client Connector runs for every request to decide: send it to Zscaler (PROXY) or straight out (DIRECT). Every DIRECT is a bypass that DLP never sees.'],
    ['Captive portal', 'The Wi-Fi sign-in page at hotels and airports. Until the user clicks through, nothing reaches Zscaler; Client Connector pauses so the page can load.'],
    ['Quality and security score', 'A score from 0 to 100 for this app itself, not for a tenant, on Advanced settings: tests passed in the last full run (40%), open security findings weighted by CVSS severity (40%) and standards controls with a test (20%). Fixed findings are listed but not counted against it; any open critical finding caps it at 39 and any open high at 69. tools/quality_score.py builds it and docs/QUALITY_SCORE.md shows the working.'],
    ['Finding severity (CVSS)', 'How serious a QA finding about this app is, in the CVSS v3.1 bands: critical (9.0 to 10.0), high (7.0 to 8.9), medium (4.0 to 6.9), low (0.1 to 3.9) and info. Each finding is open, fixed (with the test that proves it) or accepted (with the reason).'],
    ['Projected score', 'The score the assessment would give after the fixes you tick on Improve my score (and any fix recipe staged in the change queue), worked out with the same formula as the real score. Nothing is changed or read to get it; run the assessment again to make it real.'],
    ['Points gained', 'How much one fix raises the overall score: the score worked out again with that check configured, minus the score now. Every scoreable check weighs the same, so each fix adds about 100 divided by the number of scoreable checks.'],
    ['Coverage', 'The share of the assessment\'s checks that ran and got an answer. A check that was not permitted to the API client, was rate limited, timed out or failed is left out of the score; Improve my score lists each one with the reason and the fix.'],
    ['Score-drop alert', 'A note on the results and in the digest when the score fell by at least the threshold you set (5 points by default) since the previous run, with the checks that started failing. It is sent by e-mail or webhook only if notifications are already set up and you turned that on.'],
    ['Trusted network', 'A network the customer defined in the Forwarding Profile (office, VPN) where Client Connector may behave differently on purpose, for example not tunnelling at all.'],
    ['Help marks (? and *)', 'A small raised ? after a page title, a sidebar item or a control says what it does, what to type or pick, and whether it reads or changes the tenant. A * marks something new in the last two updates and says what is new. Point at the mark, click or tap it, or move to it with the Tab key and press Enter. Esc or a click elsewhere closes it. Pointing at the control itself opens nothing, and a control whose name says it all (Close, Cancel, Back) has no mark.'],
    ['Glass effect', 'The look of the bars, cards, dialogs and buttons: see-through like frosted glass over a soft background, with a light edge and a soft shadow. Text keeps its contrast in both themes. It is on by default; turn it off for solid surfaces in Advanced settings (Appearance), a choice kept in this browser only. Surfaces are solid anyway when the system asks for less transparency, more contrast or forced colours, and when printing.'],
  ];
  window.DLP_TROUBLE = [
    ['"Could not connect" under step 1', 'tells you the cause and the fix. Nine times out of ten it is a pasted secret that was not the real secret, or a machine behind TLS inspection.'],
    ['"0 endpoints probed" or empty results', 'the credentials were rejected; test the connection.'],
    ['Preflight says blocked', 'read the red card. It names the object and the missing prerequisite (a predefined dictionary, an onboarded SaaS tenant, a licensed feature).'],
    ['"Write actions require ENABLE_WRITE_ACTIONS" or a read-only banner', 'click Enable write mode in Deploy policy packs and type the phrase, or start the server with START_Zscaler_Made_Easy_WRITES_ENABLED.bat; in the container, put ENABLE_WRITE_ACTIONS=YES_I_UNDERSTAND in .env and run docker compose up -d.'],
    ['A user says Client Connector is broken', 'ask them for Export Logs (tray icon > More > Export Logs) and drop the ZIP into the Log analyzer.'],
  ];
  window.DLP_EXPLAIN_CARD = cardHtml;
  window.DLP_EXPLAIN_KEY = keyFor;
  if (document.body) mount(); else document.addEventListener('DOMContentLoaded', mount);
})();
