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
  X.quickstart = {
    group: 'Start', name: 'Quick Start Assessment', href: '/quickstart',
    what: 'A one-page walkthrough of the four steps: get API credentials from the customer, enter the tenant details, choose what to assess, run it and download the report.',
    why: 'The customer is paying for an answer to "how well is our Zscaler set up, and what should we fix first?". This page gets you from nothing to that answer in about ten minutes without knowing the product.',
    when: 'Your very first engagement, or any time you need to explain to a customer admin what credentials to create.',
    get: 'Exact portal paths for the API client, the vanity domain and the ZPA customer ID, and a link to what access each scope needs.',
    next: 'Go back to the assessment page, open Connect to the tenant, fill in the four fields and click Authenticate.',
  };
  X.assessment = {
    group: 'Start', name: 'The assessment page (home)', href: '/',
    what: 'The home page. The numbered Start here panel walks you through: connect to the tenant, run the assessment, read the results, pick a policy pack, close the gap, and measure the journey on the next visit.',
    why: 'Everything else in the app either feeds this page (the assessment) or acts on what it found (the packs, the hand-off). If you only learn one page, learn this one.',
    when: 'Every engagement starts and ends here; come back to it between the other tabs.',
    get: 'A score out of 100, a maturity level, the findings that matter with the fix for each, the compliance mapping and the data-governance journey per policy pack.',
    next: 'Follow the Start here steps in order; each step tells you when it is ready and what it needs.',
  };
  X.connect = {
    group: 'Start', name: 'Connect to the tenant (Tenant details, profiles, Authenticate)', href: '/',
    what: 'Where you type the customer\'s cloud, vanity domain, API client ID and secret, then click Authenticate. Tenant profiles save those details (and the history) per customer.',
    why: 'Nothing works until the app can read the tenant. Authenticate proves the credentials work and shows what the app can see, so a "no results" later is never a mystery.',
    when: 'First thing in every engagement. Save a profile so the next visit fills itself in and keeps history.',
    get: 'Connected: N dictionaries, N engines, N rules, or a plain reason why not (wrong secret, TLS inspection, missing role).',
    next: 'Choose the scope in Tenant Configuration and run the assessment.',
  };
  X.results = {
    group: 'Start', name: 'Assessment results', href: '/report/view',
    what: 'The full results in their own tab: Summary (score and maturity), Scores by section, Best practices and benchmarks, Regulatory alignment, the Data governance journey, and Detailed findings with a fix for each.',
    why: 'This is the deliverable. Critical findings are configuration that exposes data today; the score gives the customer a number to improve.',
    when: 'Right after the assessment runs, and again on every return visit to show progress.',
    get: 'Every failed or warned check with what it means, why it matters and how to fix it, plus Word and JSON downloads.',
    next: 'Walk the customer through the critical findings first. Then open Traffic Flow & Gaps and Detection Health for the "show me" evidence.',
  };
  X.dataflow = {
    group: 'Find the gaps', name: 'Traffic Flow & Gaps', href: '/report/dataflow',
    what: 'A map of the exact path a user\'s transaction takes: Client Connector app and forwarding profile, PAC, SSL inspection, URL filtering, Cloud App Control, file type control and DLP, with every point where inspection is lost (bypasses, SSL blind spots).',
    why: 'DLP can only stop what it can see. A bypass or an un-decrypted app category is a hole the customer usually does not know they have.',
    when: 'After the assessment, when the customer asks "why did DLP not catch that upload?" or before deploying a policy pack.',
    get: 'The path diagram per policy pack, visibility by cloud-app category, and a list of every bypass with the object that causes it.',
    next: 'Close the SSL and bypass gaps first; DLP rules deployed behind a blind spot do nothing.',
  };
  X.bypass = {
    group: 'Find the gaps', name: 'Bypass & Non-Inspected Traffic', href: '/report/bypass',
    what: 'Every SSL exemption, allow rule, Client Connector bypass and PAC exception that lets traffic skip inspection, in one list with exports.',
    why: 'Each line is traffic DLP will never see. Customers accumulate these over years; most were added for a problem that no longer exists.',
    when: 'When you need the evidence behind a "visibility" finding, or a list to review with the customer\'s security team.',
    get: 'A table of bypasses with type, scope and the reason it matters, and CSV / Markdown exports.',
    next: 'Ask the customer why each one exists; replace broad bypasses with narrow SSL exemptions or app policies.',
  };
  X.sslflow = {
    group: 'Find the gaps', name: 'SSL Inspection Flow', href: '/report/sslflow',
    what: 'For each risky traffic class (file sharing, webmail, AI tools, social, uncategorised sites) which SSL rule decides, whether the traffic is decrypted, and whether inline DLP can see it.',
    why: 'Without decryption DLP sees only the destination, never the content. This is the number one reason a DLP rule "does not work".',
    when: 'Before promising the customer that a DLP rule will catch anything.',
    get: 'A live flow diagram with gaps highlighted and the fix for each.',
    next: 'Fix the SSL rule order or exemptions it points at, then refresh the diagram.',
  };
  X.efficacy = {
    group: 'Find the gaps', name: 'DLP Efficacy', href: '/report/view?tool=efficacy',
    what: 'Scores every custom dictionary and engine for false-positive risk and lets you paste sample text (or run the built-in corpus) to see which dictionaries, engines and predefined ones would fire.',
    why: 'A noisy dictionary buries real incidents and makes the customer switch the rule off. Testing before enabling saves that.',
    when: 'Before enabling a rule, and when the customer complains about false positives.',
    get: 'A score and a reason per dictionary, and a fired / not fired result per engine for your sample.',
    next: 'Tighten the noisy dictionaries (proximity, thresholds), then test again.',
  };
  X.health = {
    group: 'Find the gaps', name: 'Detection Health', href: '/report/health',
    what: 'What the DLP rules actually do in production, measured from Workflow Automation incidents and the analysts\' verdicts: false-positive rate per rule, engine and dictionary, dead rules, monitor rules ready to promote, and the proposals queue.',
    why: 'A rule that fires and is always dismissed costs the customer analyst time; a rule that never fires is either perfect or dead. Either way it is a tuning decision with evidence.',
    when: 'On return visits, once incidents have been flowing for a few weeks.',
    get: 'Per-rule health with the reason, and typed proposals (raise a threshold, promote to block) you can approve or dismiss.',
    next: 'Approve the proposals the customer agrees with, then Preview and apply: the app re-reads the rules, shows the exact change, applies it with a read-back, and keeps a Roll back button.',
  };
  X.digest = {
    group: 'Find the gaps', name: 'Digest and the always-on loop', href: '/report/digest',
    what: 'Every six hours the app re-reads the guidance sources, Detection Health, the SaaS tenants and the packs\' drift for every tenant profile that remembers its secret, writes a digest, and sends it by e-mail or to a Teams or Slack webhook when there is something to decide.',
    why: 'Nobody has to remember to check. A new Zscaler or partner article, a noisy rule, a SaaS tenant that lost its authorisation or a pack the customer changed all show up as a proposal in your queue, with the evidence.',
    when: 'Read it when it arrives; open the tab to run the loop now, to see which sources are stale, or to check what is notified where.',
    get: 'The latest digest with counts, the full text, the watched sources with their state, the SaaS capability matrix, the schedule and the notification settings.',
    next: 'Decide the new proposals in Detection Health; a stale source or a missing notification setting is fixed in local_settings.bat.',
  };
  X.compliance = {
    group: 'Find the gaps', name: 'Regulatory & Compliance Alignment', href: '/report/compliance',
    what: 'The assessment findings mapped to the frameworks the customer answers to (HIPAA, PCI DSS, NIST, CMMC, SOC 2, and so on), scoped to the industry on the tenant profile.',
    why: 'Auditors and CISOs think in controls, not in Zscaler settings. This turns "SSL inspection is off for webmail" into the control it fails.',
    when: 'When the customer\'s security or compliance team is in the room.',
    get: 'Coverage per framework, weakest first, with the findings behind each control.',
    next: 'Use it to prioritise: fix the findings that clear the most controls for the customer\'s framework.',
  };
  X.packs = {
    group: 'Close the gaps', name: 'Deploy Policy Packs', href: '',
    what: 'Ready-made, layered DLP policy for one situation (Healthcare PHI, CJIS, Federal CUI, Zscaler enterprise best practice, source code, banking). Preflight reads the tenant and shows exactly what would be created; you approve; every rule arrives disabled.',
    why: 'Building dictionaries, engines and rules by hand takes days and is error-prone. A pack is the design the customer would end up with, deployed in minutes, with nothing they already have overwritten.',
    when: 'After the assessment, when the customer has agreed to close the gap. Preflight is safe to run any time: it writes nothing.',
    get: 'A plan (create / keep / conflict), impact cards, and after deploying a record you can undo.',
    next: 'Activate in the ZIA portal, enable rules one at a time in monitor mode, then harden.',
  };
  X.flow = {
    group: 'Close the gaps', name: 'Deploy flow diagram', href: '/report/flow',
    what: 'A picture of the plan a preflight produced: which dictionaries feed which engines, which engines feed which rules, and on which channels.',
    why: 'A customer approving a deployment wants to see what it is, not read JSON.',
    when: 'In the review step of Deploy Policy Packs.',
    get: 'The diagram, keyboard-navigable, with the counts per channel.',
    next: 'If it matches what the customer expects, approve and deploy.',
  };
  X.terraform = {
    group: 'Close the gaps', name: 'Terraform hand-off', href: '/report/view?tool=terraform',
    what: 'The same policy pack as a Terraform workspace for the official zscaler/zia provider. Static mode needs no credentials; gap mode reads the tenant and imports what exists so the customer\'s first plan is exactly the gap.',
    why: 'Some customers only change Zscaler through code review and a pipeline. This gives their platform team the pack in their language.',
    when: 'When the customer says "we manage Zscaler as code" or refuses to let a tool write to the tenant.',
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
    what: 'The decision flow with the tie-breaker (most restrictive action wins; a tie is broken by rule order) and which channels use it. Reference only: the simulator that runs on the tenant\'s own rules is in the migration wizard.',
    why: 'Engineers get this wrong constantly and then cannot explain an incident. Five minutes here saves an argument with the customer.',
    when: 'Before the migration wizard, or when an incident\'s winning rule surprises someone.',
    get: 'The diagram and which channels use it (Web, Endpoint, Email; SaaS is first-match, no tie-breaker).',
    next: 'Open the migration wizard\'s simulator to show the customer which of their rules would win for a given match.',
  };
  X.bestpractices = {
    group: 'Reference', name: 'Best Practices library', href: '/report/view?tool=bestpractices',
    what: 'Curated Zscaler best-practice articles, rated by source, refreshed from help.zscaler.com, the blog and the developer portal.',
    why: 'When a customer asks "says who?", you point at the article.',
    when: 'While writing up findings, or to read up before a meeting.',
    get: 'Articles grouped by area with the link and the source rating.',
    next: 'Cite the article next to the finding in your write-up.',
  };
  X.advanced = {
    group: 'Reference', name: 'Advanced settings', href: '/report/advanced',
    what: 'Add your own policy packs (JSON, Terraform, native Zscaler API exports or a ZIP) to the library, transcribe native exports to Terraform, and see how this server is configured (bind host, token gate, write mode, limits).',
    why: 'Customers and colleagues have their own designs; this puts them through the same preflight and deploy as the built-in packs.',
    when: 'When someone hands you a pack or an export from another tenant.',
    get: 'A validation preview (what it contains, what blocks it) before anything is added.',
    next: 'Add it; it then shows up in Deploy Policy Packs and the Terraform hand-off.',
  };
  X.updates = {
    group: 'Reference', name: 'Zscaler Updates', href: '/report/view?tool=updates',
    what: 'A check of PyPI and help.zscaler.com for SDK and documentation changes since the last check, with a quality check on each link so you are not sent to an empty page.',
    why: 'Zscaler changes the product every few weeks; a finding that cites an outdated page loses credibility.',
    when: 'Once a month, or before a big engagement.',
    get: 'What changed, with a working link or a fallback to the section it now lives in.',
    next: 'Skim for changes in the areas your customer cares about.',
  };
  X.logs = {
    group: 'Troubleshoot', name: 'Log Analyzer', href: '/report/logs',
    what: 'Drop in the ZIP that Client Connector\'s Export Logs produced (or single .log files, or a PAC file). It reads them on this computer and tells you what happened, what it means for the user, and what to do next.',
    why: 'Most "Zscaler is broken" tickets are a captive portal, a blocked UDP port, a proxy in the path or a certificate. The analyzer recognises those stories so you do not have to read ten thousand lines.',
    when: 'Any time a user reports that Client Connector will not sign in, will not connect, or that the internet stopped; and whenever a customer sends you a PAC file to review.',
    get: 'A one-line verdict, the facts (version, OS, user, cloud, tunnel), findings ordered by how much they hurt the user with numbered next steps and redacted evidence, and for a PAC every bypass with its risk.',
    next: 'Do the numbered steps of the top finding; if it names a portal setting, that is where to look.',
  };
  X.zcc = {
    group: 'Troubleshoot', name: 'Diagnose ZCC Access', href: '/report/view?tool=zcc',
    what: 'Probes every Client Connector (ZCC) API endpoint with the credentials you entered and shows which answer.',
    why: 'The ZCC checks in the assessment can only be as good as what the API client is allowed to read. This tells you whether a blank ZCC section is a permission problem.',
    when: 'When ZCC findings look empty or say "not accessible".',
    get: 'A table: endpoint, what it is for, status, how many items came back.',
    next: 'If endpoints answer 401 or 403, the API client needs the ZCC read role; ask the customer admin.',
  };
  X.permissions = {
    group: 'Troubleshoot', name: 'Required API Access', href: '/permissions',
    what: 'The exact API roles and scopes the app needs per assessment scope, and what a configuration change needs on top.',
    why: 'The customer admin will ask "what access does this tool need?" before creating the API client. This is the answer, and the least access that works.',
    when: 'Before the engagement, when the API client is being created; and when a scope comes back partial.',
    get: 'A per-scope list you can send to the customer as-is.',
    next: 'Send it; then run Authenticate again once the client is updated.',
  };
  X.remediate = {
    group: 'Close the gaps', name: 'Review & Remediate', href: '',
    what: 'For each failed check with a known fix, a guided change: what will be changed, on which object, with a before / after view, applied only in write mode after your approval.',
    why: 'Findings without a way to fix them are just a longer to-do list.',
    when: 'After the customer agrees to a fix and the server is in write mode.',
    get: 'A wizard per finding with the exact change and a read-back afterwards.',
    next: 'Re-run the assessment to see the score move.',
  };
  X.updateapp = {
    group: 'Reference', name: 'Update app', href: '',
    what: 'Fetches the latest version of this app from GitHub, installs the pinned dependencies and restarts the server.',
    why: 'Fixes and new checks ship weekly; running an old build means findings the customer already fixed elsewhere.',
    when: 'When the Start here panel says an update is available.',
    get: 'The app restarts on the same address; the browser reconnects.',
    next: 'If it fails, the message says whether it is TLS inspection, sign-in or connectivity, and what to do.',
  };
  X.help = {
    group: 'Start', name: 'What does everything do?', href: '/help',
    what: 'This page: every function of the app explained in plain English, in the order you will need them on a first engagement.',
    why: 'You should never have to guess what a button does or why the customer would care.',
    when: 'Day one, and whenever a page has a box at the top you have not read yet.',
    get: 'One card per function: what it is, why it matters, when to use it, what you get, what to do next.',
    next: 'Start with Quick Start Assessment, then follow the numbered first-engagement list.',
  };

  // Which entry a page belongs to, by its path (and ?tool= on the results tab).
  function keyFor(loc) {
    const p = (loc || window.location).pathname.replace(/\/+$/, '') || '/';
    const tool = new URLSearchParams((loc || window.location).search).get('tool');
    if (p === '/report/view') return tool && X[tool] ? tool : 'results';
    const map = { '/': 'assessment', '/quickstart': 'quickstart', '/report/dataflow': 'dataflow', '/report/bypass': 'bypass', '/report/sslflow': 'sslflow',
      '/report/flow': 'flow', '/report/advanced': 'advanced', '/report/health': 'health', '/report/compliance': 'compliance', '/report/evalall': 'evalall',
      '/report/logs': 'logs', '/report/digest': 'digest', '/permissions': 'permissions', '/help': 'help' };
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
    if (!key || key === 'assessment' || key === 'help' || document.getElementById('xpBox')) return;
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
      st.textContent = `.xp-box{margin:0 0 1rem}.xp-details{border:1px solid var(--border);border-radius:12px;background:var(--card);padding:0.2rem 0.9rem}.xp-details>summary{cursor:pointer;font-weight:700;padding:0.6rem 0;list-style:revert}.xp-details>summary:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:8px}.xp-dim{color:var(--dim);font-weight:400;font-size:0.85rem}.xp-body{padding:0 0 0.8rem;font-size:0.9rem;line-height:1.5}.xp-dl{display:grid;grid-template-columns:minmax(150px,max-content) 1fr;gap:0.3rem 0.9rem;margin:0.2rem 0 0.6rem}.xp-dl dt{font-weight:600;color:var(--dim);font-size:0.78rem;text-transform:uppercase;letter-spacing:0.06em;padding-top:0.15rem}.xp-dl dd{margin:0}.xp-foot{display:flex;gap:1rem;flex-wrap:wrap;align-items:center;margin:0}.xp-foot a{color:var(--accent)}.xp-link{background:none;border:0;color:var(--dim);text-decoration:underline;cursor:pointer;font:inherit;font-size:0.85rem;padding:0}.xp-link:focus-visible{outline:2px solid var(--accent);outline-offset:2px}@media (max-width:600px){.xp-dl{grid-template-columns:1fr}}`;
      document.head.appendChild(st);
    }
  }

  window.DLP_EXPLAIN = X;
  window.DLP_EXPLAIN_ORDER = ['quickstart', 'assessment', 'connect', 'results', 'help', 'dataflow', 'bypass', 'sslflow', 'efficacy', 'health', 'compliance',
    'digest', 'packs', 'flow', 'remediate', 'terraform', 'migration', 'evalall', 'bestpractices', 'advanced', 'updates', 'updateapp', 'logs', 'zcc', 'permissions'];
  window.DLP_EXPLAIN_GROUPS = ['Start', 'Find the gaps', 'Close the gaps', 'Reference', 'Troubleshoot'];
  window.DLP_FIRST_DAY = [
    ['Read Quick Start Assessment', 'quickstart', 'Ten minutes. You will know what to ask the customer for.'],
    ['Connect to the tenant and Authenticate', 'connect', 'Save a tenant profile so history is kept.'],
    ['Run the assessment', 'assessment', 'About 90 seconds. Read-only.'],
    ['Read the results, critical findings first', 'results', 'Each one says what it means and how to fix it.'],
    ['Show the customer where inspection is lost', 'dataflow', 'Traffic Flow & Gaps and SSL Inspection Flow are the "show me" pages.'],
    ['Map it to their framework', 'compliance', 'Only the frameworks for their industry are shown.'],
    ['Close the gap with a policy pack (preflight first)', 'packs', 'Preflight writes nothing; it is the plan you show the customer.'],
    ['When a user says "Zscaler is broken", use the Log Analyzer', 'logs', 'Export Logs from the tray icon, drop the ZIP in, follow the top finding.'],
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
    ['Activation', 'ZIA saves changes as pending. After a deploy, an admin must click Activate in the ZIA Admin Portal for the new rules to take effect for users.'],
    ['Read-only vs write mode', 'The server starts read-only: assessment, preflight and journey checks all work, deploying is refused. Deploy Policy Packs shows the current mode and an Enable write mode button (type the confirmation phrase; it lasts until the server restarts). START_Zscaler_Assessment_WRITES_ENABLED.bat starts in write mode from the outset. Stay read-only when you only want to show the customer the plan.'],
    ['OneAPI credentials', 'The client ID and secret of an API client created in ZIdentity, plus the vanity domain (the short name in the login URL, acme for acme.zslogin.net) and the cloud (Production for almost everyone).'],
    ['Terraform hand-off', 'The same pack as a Terraform workspace for the official zscaler/zia provider, for customers whose platform team manages Zscaler as code. Gap mode reads the tenant and imports existing objects so the first plan shows exactly the gap; static mode needs no credentials. Terraform then owns the objects: a later plan shows how the tenant moved, and apply would converge it, so use plan to assess and apply deliberately.'],
    ['Outbound Email DLP', 'Rules that inspect mail leaving onboarded Microsoft 365 / Gmail tenants (Administration > SaaS Application Tenants). The policy packs ship a monitor-only email rule; preflight skips it, with the reason, when no email tenant is onboarded.'],
    ['Client Connector (ZCC)', 'The Zscaler app on the user\'s device. It signs the user in, builds a tunnel to the cloud and forwards traffic through it. Its Export Logs ZIP is what the Log Analyzer reads.'],
    ['Z-Tunnel 1.0 / 2.0', 'The two ways Client Connector carries traffic. 2.0 (DTLS or TLS, needs outbound UDP or TCP 443) carries everything; 1.0 (HTTP CONNECT) carries only web ports. A firewall that blocks UDP 443 forces the fallback to 1.0.'],
    ['PAC file', 'A small script the browser or Client Connector runs for every request to decide: send it to Zscaler (PROXY) or straight out (DIRECT). Every DIRECT is a bypass that DLP never sees.'],
    ['Captive portal', 'The Wi-Fi sign-in page at hotels and airports. Until the user clicks through, nothing reaches Zscaler; Client Connector pauses so the page can load.'],
    ['Trusted network', 'A network the customer defined in the Forwarding Profile (office, VPN) where Client Connector may behave differently on purpose, for example not tunnelling at all.'],
  ];
  window.DLP_TROUBLE = [
    ['"Could not connect" under step 1', 'tells you the cause and the fix. Nine times out of ten it is a pasted secret that was not the real secret, or a machine behind TLS inspection.'],
    ['"0 endpoints probed" or empty results', 'the credentials were rejected; test the connection.'],
    ['Preflight says blocked', 'read the red card. It names the object and the missing prerequisite (a predefined dictionary, an onboarded SaaS tenant, a licensed feature).'],
    ['"Write actions require ENABLE_WRITE_ACTIONS" or a read-only banner', 'click Enable write mode in Deploy Policy Packs and type the phrase, or start the server with START_Zscaler_Assessment_WRITES_ENABLED.bat.'],
    ['A user says Client Connector is broken', 'ask them for Export Logs (tray icon > More > Export Logs) and drop the ZIP into the Log Analyzer.'],
  ];
  window.DLP_EXPLAIN_CARD = cardHtml;
  window.DLP_EXPLAIN_KEY = keyFor;
  if (document.body) mount(); else document.addEventListener('DOMContentLoaded', mount);
})();
