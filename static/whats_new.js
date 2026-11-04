// ── What's new: a * after the label of each new feature ───────────────
// The manifest below is the one list of what is new. Each feature names the
// CHANGELOG.md release it came in ("release", the heading's date), a short
// plain label, what it is (the words after "New in the <date> update: "),
// the CHANGELOG phrases it covers, and where it shows ("marks": the page and
// the item: a control, a sidebar item, a page title or a heading). "shown"
// says when a mark's item appears later (after a read, in a dialog).
//
// Only the features of the newest two releases are marked ("keep"): add the
// next release to "releases", with its features, and the oldest set stops
// showing. A CHANGELOG release with nothing to mark goes in "skipped" with
// the reason, and pushes nothing out (tests/test_new_marks.py checks both
// lists against CHANGELOG.md).
//
// This file only says which item is new: it puts the words on the item
// (data-wn-new). The help marks (hover_help.js) draw the superscript * after
// it, a button of its own named "New in this version: <item>", whose pop-up
// says "New in the <date> update: …", beside the item's ? help mark. It also
// puts the legend "* New in this version" in the page header (the sidebar
// foot on the home page), and "Hide new marks" in Advanced settings, kept in
// this browser only. Every word is set with textContent, never as HTML.
window.WHATS_NEW = {
  "keep": 2,
  "releases": {
    "2026-11-04": "Sign in once: every page, Simple mode too, uses the tenant you signed in to",
    "2026-11-01": "Team server SAML 2.0 sign-in, passkeys and a password of your own, security gates, day-to-day admin, rehearse then simulate, Fix selected that changes the answer (URL filtering and ZPA), manual what-if inputs, other providers' endpoint lists, outside-tool gaps closed, and more of the tenant read and scored"
  },
  "skipped": {
    "2026-10-30": "The new name everywhere, ZIA admin ranking in the rule decisions (no new control) and the help and new marks themselves: a * on the marks would push 2026-10-28 out, so this release is not marked and the two releases above stay"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "shared-signin", "release": "2026-11-04", "label": "Sign in once",
      "what": "Sign in once: after Authenticate (or an assessment), every page, Simple mode too, reads that tenant without asking again. The server keeps the sign-in in memory only, for you and this browser, until 30 minutes without use or 8 hours at most; Sign out of tenant forgets it. Changes still need the sign-in details.",
      "changelog": ["Sign in once", "Sign out of tenant", "Authenticate", "Signed-in tenant"],
      "marks": [
        { "page": "/report/advanced", "at": "#advTenantSessionH" },
        { "page": "/", "at": "#authSignOutBtn", "shown": "after signing in with Authenticate" },
        { "page": "/report/advanced", "at": "#advTenantSignOut", "shown": "while signed in to a tenant" }
      ]
    },
    {
      "id": "clone-breadth", "release": "2026-11-04", "label": "Clone tenant-bound objects and Client Connector profiles",
      "what": "Restore and clone now write PAC files, Endpoint and SaaS DLP rules, ZPA gateways, sub-locations (with their location) and, when you tick it, Client Connector app profiles and entitlements, never with a password.",
      "changelog": ["PAC files, Endpoint DLP and SaaS Security API DLP rules, and ZPA gateways in restore and clone", "Sub-locations clone with their parent location", "Client Connector app profiles and entitlements to another tenant"],
      "marks": [
        { "page": "/report/operations", "at": "#opCloneNew" },
        { "page": "/report/operations", "at": "#crTb", "shown": "on the ZIA restore form (Backups)" },
        { "page": "/report/operations", "at": "#crZccProfiles", "shown": "on the Client Connector restore form (Backups)" }
      ]
    },
    {
      "id": "dataflow-simple-view", "release": "2026-11-04", "label": "Data flow map: simple view",
      "what": "The data flow map opens on one path as numbered steps, with a legend beside it, the details of one step at a time and a walk-through. Show all details has the full map.",
      "changelog": ["Simple view by default", "A legend beside the steps", "Walk me through it", "Show all details"],
      "marks": [
        { "page": "/report/dataflow", "at": "#dfViewSimple", "shown": "after the map is drawn" },
        { "page": "/", "at": "button[onclick=\"openDataFlowTab()\"]" }
      ]
    },
    {
      "id": "dataflow-uploads", "release": "2026-11-04", "label": "Where your uploads really go",
      "what": "With ZIA Insights in scope, the data flow map shows how much of the data your users uploaded takes each road, and where it is not checked.",
      "changelog": ["Where your uploads really go"],
      "marks": [{ "page": "/report/dataflow", "at": "#dfsTrafficH", "shown": "after the map is drawn" }]
    },
    {
      "id": "bypass-motion-opt-in", "release": "2026-11-04", "label": "Bypass picture starts still",
      "what": "The Bypass report's picture starts still: its widths count bypass items, not traffic. Play motion starts it.",
      "changelog": ["The Bypass report's picture starts still too"],
      "marks": [{ "page": "/report/bypass", "at": "#bpFlowH", "shown": "after the report is drawn" }]
    },
    {
      "id": "ssl-true-coverage", "release": "2026-11-04", "label": "True inspection coverage",
      "what": "One figure for how much web traffic Zscaler really sees inside (plain HTTP plus decrypted HTTPS), by transactions and by bytes, adding up to 100%, with each share left encrypted tied to its rule or bypass and a fix. It is of the traffic that reaches ZIA; give the traffic that goes around ZIA (Bypass GB) for the share of all web traffic. Without traffic numbers it is a labelled estimate.",
      "changelog": ["True inspection coverage", "Bypass (GB)"],
      "marks": [
        { "page": "/report/sslcoverage", "at": "#scTrueH", "shown": "after a check" },
        { "page": "/report/sslcoverage", "at": "#scBypassGb" },
        { "page": "/report/operations", "at": "#opSslCov" }
      ]
    },
    {
      "id": "ssl-true-coverage-logs", "release": "2026-11-04", "label": "True coverage from your web logs",
      "what": "From the Traffic and session logs page, open SSL coverage with your uploaded ZIA web logs: each line left encrypted is tied to the SSL rule behind it. Try it with the sample web logs.",
      "changelog": ["True coverage from your web logs", "Try with sample web logs"],
      "marks": [
        { "page": "/report/traffic-logs", "at": "#tlSslCov" },
        { "page": "/report/traffic-logs", "at": "#tlSample" },
        { "page": "/report/traffic-logs", "at": "#tlTrueCoverage", "shown": "after reading ZIA web logs that say whether SSL was inspected" }
      ]
    },
    {
      "id": "device-posture-cross", "release": "2026-11-04", "label": "Device posture across products",
      "what": "Device posture now reads Client Connector, ZPA and ZIA: each posture check, where it is defined, the platforms it covers and every ZPA and ZIA rule that uses it, with the gaps. A product that is not in scope, not licensed or not readable is said so instead of an error.",
      "changelog": ["Device posture across products"],
      "marks": [{ "page": "/report/device-posture", "at": "#tab-cross", "shown": "after Read device posture" }]
    },
    {
      "id": "path-device-posture", "release": "2026-11-04", "label": "Device posture in the what-if",
      "what": "The Path analyzer's what-if takes the device's trust level (for ZIA rules) and the posture checks it passes (for ZPA access rules); a picked device's trust level is used too.",
      "changelog": ["Device posture in the what-if"],
      "marks": [{ "page": "/report/path", "at": "#paWiSum" }, { "page": "/report/path", "at": "#paWi_trust", "shown": "with the What-if section open" }]
    },
    {
      "id": "pov-simulate-whole-build", "release": "2026-11-04", "label": "Simulate the whole POV build",
      "what": "Apply to a simulation now carries every part of a rehearsed POV build to the in-memory copy, Cloud App Control, ZPA policy rules, Client Connector profiles, ZDX probes and AI Guard included. Nothing reaches a tenant.",
      "changelog": ["Simulate the whole POV build"],
      "marks": [{ "page": "/report/pov", "at": "#pbSimulate", "shown": "after a dry run of the build on the sample tenant or a snapshot" }]
    },
    {
      "id": "glass-light", "release": "2026-11-04", "label": "Lighter glass",
      "what": "The glass effect draws far less on a computer without a graphics card: the backdrop moves once a second, and cards in the page drop their blur while you scroll. It looks the same.",
      "changelog": ["Lighter glass on slow computers"],
      "marks": [{ "page": "/report/advanced", "at": "#advGlass" }]
    },
    {
      "id": "team-saml", "release": "2026-11-01", "label": "SAML 2.0 sign-in",
      "what": "Team servers can sign people in through the organisation's identity provider with SAML 2.0, strictly checked, matched to their own account.",
      "changelog": ["SAML 2.0 sign-in"],
      "marks": [{ "page": "/login", "at": "#lgSamlBtn", "shown": "when the team server has SAML sign-in turned on" }]
    },
    {
      "id": "team-passkeys", "release": "2026-11-01", "label": "Passkeys",
      "what": "Passkeys for team server accounts: sign in with your device's PIN, fingerprint or face instead of a password. Add one on the Team server page.",
      "changelog": ["Passkeys"],
      "marks": [
        { "page": "/login", "at": "#lgPasskeyBtn", "shown": "when the team server has passkeys turned on" },
        { "page": "/report/team", "at": "#tmPkH", "shown": "when the team server has passkeys turned on" }
      ]
    },
    {
      "id": "team-sign-in-settings", "release": "2026-11-01", "label": "Sign-in settings",
      "what": "A Sign-in section on the Team server page: set SAML sign-in up from your identity provider's metadata, test it, turn it on or off, and require a passkey after the password.",
      "changelog": ["Sign-in settings", "Passkey after the password"],
      "marks": [
        { "page": "/report/advanced", "at": "#advSignInNote" },
        { "page": "/report/team", "at": "#tmSignInH", "shown": "for administrators on a team server" },
        { "page": "/login", "at": "#lgPkGo", "shown": "after a right password, when the account's passkey is asked for next" }
      ]
    },
    {
      "id": "choose-password", "release": "2026-11-01", "label": "Choose your own password",
      "what": "An account whose password an administrator set chooses its own at the next sign-in, on the Sign in page, before anything else opens.",
      "changelog": ["Choose your own password"],
      "marks": [{ "page": "/login", "at": "#lgChangeTitle", "shown": "at the first sign-in after an administrator set the password" }]
    },
    {
      "id": "zia-activation", "release": "2026-11-01", "label": "Activate pending ZIA changes",
      "what": "Activate pending ZIA changes: reads ZIA's activation status, activates what is pending with ACTIVATE typed, refuses when nothing is pending. No Undo.",
      "changelog": ["Activate pending ZIA changes"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zia_activation\"]", "shown": "once the page lists the operation types" },
        { "page": "/report/operations", "at": "#opAdminNew" }
      ]
    },
    {
      "id": "url-category-manage", "release": "2026-11-01", "label": "Rename or delete a URL category",
      "what": "Rename one custom URL category, or delete one no rule uses (DELETE and its name typed), with Undo.",
      "changelog": ["Rename or delete a URL category"],
      "marks": [
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"url_category_manage\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "ip-group-admin", "release": "2026-11-01", "label": "IP source and destination groups",
      "what": "IP groups: edit an IP source group, delete a group no rule uses, and import or export groups as CSV, with Undo.",
      "changelog": ["IP source and destination groups"],
      "marks": [
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"ip_group_admin\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "dlp-object-edit", "release": "2026-11-01", "label": "DLP dictionaries and engines",
      "what": "Create, edit or delete one custom DLP dictionary or engine, its expression explained in plain words, with Undo.",
      "changelog": ["DLP dictionaries and engines"],
      "marks": [
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"dlp_object_edit\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "zid-user-edit", "release": "2026-11-01", "label": "Edit a ZIdentity user",
      "what": "Edit one ZIdentity user's names, email, department and groups, with Undo.",
      "changelog": ["Edit a ZIdentity user"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zid_user_edit\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "zid-user-reset", "release": "2026-11-01", "label": "Reset a ZIdentity user's password or MFA",
      "what": "Reset one ZIdentity user's password or let the user skip MFA once (a raw call to ZIdentity's public API). A temporary password is shown once. No Undo.",
      "changelog": ["Reset a ZIdentity user's password or MFA"],
      "marks": [
        { "page": "/report/operations", "at": "#opAdminKinds input[name=\"opKind\"][value=\"zid_user_reset\"]", "shown": "once the page lists the operation types" }
      ]
    },
    {
      "id": "simulation", "release": "2026-11-01", "label": "Apply to a simulation",
      "what": "On the sample tenant or a snapshot, apply a rehearsed change to an in-memory copy, then see its effect in the Path analyzer. Nothing reaches a tenant.",
      "changelog": ["Apply to a simulation", "Leave the simulation"],
      "marks": [
        { "page": "/report/operations", "at": "#opH4" },
        { "page": "/report/operations", "at": "#opSimulate", "shown": "after a preview on the sample tenant or a snapshot" },
        { "page": "/report/operations", "at": "#opSimLeave", "shown": "after Apply to a simulation" },
        { "page": "/report/pov", "at": "#pbSimulate", "shown": "after a dry run of the build on the sample tenant or a snapshot" },
        { "page": "/report/pov", "at": "#pbSimLeave", "shown": "after Apply to a simulation" }
      ]
    },
    {
      "id": "pov-compliance-profile", "release": "2026-11-01", "label": "Compliance profile in the POV build",
      "what": "The Build tab follows the intake's compliance profile and offers its DLP packs and compliance pack. The federal preset fills every builder default.",
      "changelog": ["Compliance profile in the POV build", "Federal preset"],
      "marks": [
        { "page": "/report/pov", "at": "#pbCompliance", "shown": "on the Build tab, once the intake's parts are loaded" }
      ]
    },
    {
      "id": "licensed-editions", "release": "2026-11-01", "label": "Licensed editions",
      "what": "The ZIA baseline and the ZDX setup read the licence list and leave out what your Cloud Firewall, Sandbox or ZDX edition does not allow.",
      "changelog": ["Licensed editions"],
      "marks": [
        { "page": "/report/operations", "at": "#zbEditions", "shown": "after Read from the tenant in ZIA security baseline" },
        { "page": "/report/operations", "at": "#zdxEdition", "shown": "after Read from the tenant in the ZDX setup" }
      ]
    },
    {
      "id": "baseline-review-search", "release": "2026-11-01", "label": "Search and save the baseline review",
      "what": "Search the ZIA baseline's rules, show only what you changed, and save or load your choices as a file.",
      "changelog": ["Search rules", "Changed from the tier default only", "Download selection", "Load a selection"],
      "marks": [
        { "page": "/report/operations", "at": "#zbSearch", "shown": "after Read from the tenant in ZIA security baseline" },
        { "page": "/report/operations", "at": "#zbSelSave", "shown": "after Read from the tenant in ZIA security baseline" }
      ]
    },
    {
      "id": "remaining-resources-scored", "release": "2026-11-01", "label": "More of the tenant scored",
      "what": "New assessment checks: Endpoint DLP rules on empty resource groups, the ZPA link to ZIA, connector auto-delete and version profiles, user portals, partner integrations, traffic capture rules, time intervals and AI Guard provider credentials.",
      "changelog": ["Remaining resources scored"],
      "marks": [
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"zia_extras\"]", "shown": "on the Scope page" },
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"zpa\"]", "shown": "on the Scope page" },
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"aiguard\"]", "shown": "on the Scope page" }
      ]
    },
    {
      "id": "object-checks", "release": "2026-11-01", "label": "Empty and expired objects",
      "what": "Checks for objects that cannot do their job: empty DNS application, workload and connector IP groups, incomplete header insertion profiles, full client-to-client IP ranges and expired isolation certificates.",
      "changelog": ["Objects that cannot do their job"],
      "marks": [
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"zia_extras\"]", "shown": "on the Scope page" },
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"zpa\"]", "shown": "on the Scope page" },
        { "page": "/", "at": "#scopeField input.scope-cb[value=\"ztw\"]", "shown": "on the Scope page" }
      ]
    },
    {
      "id": "zcc-excel-list", "release": "2026-11-01", "label": "Excel device lists",
      "what": "Remove devices from a list now takes the Client Connector portal's Excel export (.xlsx), read safely on the server.",
      "changelog": ["Excel device lists"],
      "marks": [{ "page": "/report/operations", "at": "#admListFile", "shown": "in Build new, Remove devices from a list" }]
    },
    {
      "id": "zcc-domain-users", "release": "2026-11-01", "label": "Download the domain's user names",
      "what": "Download the user names enrolled under one user domain as a CSV, after ticking that you need the personal data.",
      "changelog": ["Download the domain's user names"],
      "marks": [{ "page": "/report/operations", "at": "#admDomainUsers", "shown": "in Build new, Remove devices from a list" }]
    },
    {
      "id": "tl-no-upload", "release": "2026-11-01", "label": "Read logs without uploading",
      "what": "A daily report from a watched folder and an optional syslog listener, both off until you turn them on.",
      "changelog": ["Read logs without uploading", "Daily report from a folder", "Syslog listener"],
      "marks": [{ "page": "/report/traffic-logs", "at": "#tlAutoH" }]
    },
    {
      "id": "dns-windows", "release": "2026-11-01", "label": "Windows DNS Server output",
      "what": "The DNS records for client hostnames as Windows DNS Server conditional forwarders (PowerShell or dnscmd).",
      "changelog": ["Windows DNS Server output"],
      "marks": [{ "page": "/report/fleet", "at": "#zfDnsWinPs" }]
    },
    {
      "id": "tf-zcc", "release": "2026-11-01", "label": "Client Connector Terraform (beta provider)",
      "what": "The whole-tenant Terraform export writes Client Connector fail-open, device cleanup, web privacy, notification templates and ZIA posture profiles with the beta provider pinned exactly.",
      "changelog": ["Client Connector Terraform"],
      "marks": [{ "page": "/report/exports", "at": "#exTfZccBeta" }]
    },
    {
      "id": "fix-flow-url", "release": "2026-11-01", "label": "URL filtering in Fix rows from Test a list",
      "what": "Fix selected puts URL filtering rows in a custom URL category and adds that category to a matching rule, or to a new disabled rule above the rule that decided them; the preview warns when the category alone changes nothing.",
      "changelog": ["URL filtering in Fix rows from Test a list", "The category alone changes nothing", "Fix rows from Test a list"],
      "marks": [{ "page": "/report/operations", "at": "select[id^=\"lfCat\"]", "shown": "after Read from the tenant, with URL filtering rows" }]
    },
    {
      "id": "zpa-typed-domains", "release": "2026-11-01", "label": "Add typed domains to a segment",
      "what": "ZPA segment domains adds typed domains to an application segment or removes picked ones, and Fix selected opens it for rows ZPA carries.",
      "changelog": ["Add typed domains to a segment", "ZPA rows open the ZPA change", "ZPA segment domains"],
      "marks": [
        { "page": "/report/operations", "at": "#opKindZpaH" },
        { "page": "/report/operations", "at": "#opZAdd", "shown": "when Add typed domains is picked" }
      ]
    },
    {
      "id": "zpa-access-position", "release": "2026-11-01", "label": "Place it above",
      "what": "The ZPA builder places its access rule just above a rule you pick in the access policy, and Undo puts the order back.",
      "changelog": ["Place it above"],
      "marks": [{ "page": "/report/operations", "at": "#zbAbove", "shown": "after Read from the tenant" }]
    },
    {
      "id": "zpa-allow-existing", "release": "2026-11-01", "label": "An access rule for an existing segment",
      "what": "ZPA policy rules builds an access rule for a segment already in ZPA, and Fix selected opens it for a Test a list row ZPA denies, with that segment and the rule that denied it picked.",
      "changelog": ["An access rule for an existing segment", "ZPA policy rules"],
      "marks": [{ "page": "/report/operations", "at": "#zbSeg", "shown": "after Read from the tenant in ZPA policy rules, with An existing segment picked" }]
    },
    {
      "id": "zpa-handoff-segments", "release": "2026-11-01", "label": "Segment from Test a list",
      "what": "When rows from Test a list sit in more than one ZPA segment, a picker offers every segment: fix one, then pick the next.",
      "changelog": ["Segment from Test a list"],
      "marks": [{ "page": "/report/operations", "at": "#opZHand", "shown": "after Fix selected with rows in two or more ZPA segments" }]
    },
    {
      "id": "path-manual-inputs", "release": "2026-11-01", "label": "Manual inputs (what-if)",
      "what": "The Path analyzer evaluates a pasted PAC file and typed VPN gateways and Z-Tunnel 2.0 lists, on their own or added to the tenant's app profiles. Nothing is kept or written.",
      "changelog": ["Manual inputs (what-if)"],
      "marks": [{ "page": "/report/path", "at": "#paManualSum" }]
    },
    {
      "id": "vendor-endpoint-lists", "release": "2026-11-01", "label": "Other providers' endpoint lists",
      "what": "Zoom, Webex, RingCentral, GoTo and Talkdesk lists in Advanced settings, imported from a file or, for Zoom, fetched when you turn it on and click Fetch now, so their app service groups are matched instead of unknown.",
      "changelog": ["Other providers' endpoint lists", "Fetch Zoom's list"],
      "marks": [
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#vendors\"]" },
        { "page": "/report/advanced", "at": "#advVendH" },
        { "page": "/report/advanced", "at": "#advVendZoomOn" },
        { "page": "/report/advanced", "at": "#advVendFile" }
      ]
    },
    {
      "id": "open-source-note", "release": "2026-11-01", "label": "Open source",
      "what": "The app is open source under the Apache License 2.0. The help page and Advanced settings say so, and what it is built from.",
      "changelog": ["Open source under the Apache License 2.0"],
      "marks": [
        { "page": "/help", "at": "#hpAboutH" },
        { "page": "/report/advanced", "at": "#advLicH" }
      ]
    }
  ]
};
// ── end of the manifest ──

(function () {
  'use strict';
  if (window.WhatsNew) return;
  const M = window.WHATS_NEW || {};
  const KEY = 'zme_hide_new_marks';
  const DATE = /^\d{4}-\d{2}-\d{2}$/;
  const norm = s => String(s == null ? '' : s).replace(/\s+/g, ' ').trim();

  // ── Which features are marked ───────────────────────────────────────
  // The newest `keep` releases (default 2), newest first: the dates in
  // "releases" and on the features, so a release with nothing to mark still
  // pushes the oldest set out.
  function releases(m) {
    m = m || M;
    const keep = Math.max(1, Number(m.keep) || 2);
    const named = Object.keys(m.releases || {});
    const dates = Array.from(new Set(named.concat((m.features || []).map(f => f && f.release)).filter(d => typeof d === 'string' && DATE.test(d))));
    return dates.sort().reverse().slice(0, keep);
  }
  function active(m) {
    m = m || M;
    const keep = releases(m);
    return (m.features || []).filter(f => f && keep.indexOf(f.release) >= 0 && Array.isArray(f.marks));
  }
  function sentence(f) { return words([f]); }
  // "New in the <date> update: <what>", one line per release, newest first.
  function words(features) {
    const by = {};
    features.forEach(f => { (by[f.release] = by[f.release] || []).push(norm(f.what)); });
    return Object.keys(by).sort().reverse().map(d => `New in the ${d} update: ${by[d].join(' ')}`).join(' ');
  }
  function pageKey() {
    const forced = document.documentElement.getAttribute('data-hh-page');
    if (forced) return forced;
    return (location.pathname || '/').replace(/\/+$/, '') || '/';
  }
  function hidden() {
    try { return window.localStorage.getItem(KEY) === '1'; } catch (e) { return false; }
  }
  function setHidden(on) {
    try { if (on) window.localStorage.setItem(KEY, '1'); else window.localStorage.removeItem(KEY); } catch (e) { /* storage blocked: this page only */ }
    forced = on ? 'hide' : 'show';
    refresh();
  }
  let forced = '';   // the choice made on this page when storage is blocked
  const isHidden = () => (forced ? forced === 'hide' : hidden());

  function make(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }
  function all(sel) {
    try { return Array.from(document.querySelectorAll(sel)); } catch (e) { return []; }
  }

  // ── Saying which item is new ────────────────────────────────────────
  // The items on this page: element → the features it shows.
  function plan() {
    const page = pageKey(), out = new Map();
    active().forEach(f => f.marks.forEach(mk => {
      if (!mk || mk.page !== page || typeof mk.at !== 'string') return;
      all(mk.at).forEach(el => {
        if (el.closest('[data-hh-ui]')) return;
        const list = out.get(el) || [];
        if (list.indexOf(f) < 0) list.push(f);
        out.set(el, list);
      });
    }));
    return out;
  }
  function unmark(el) { el.removeAttribute('data-wn-new'); el.removeAttribute('data-wn-for'); }
  function legendFor() {
    const anchors = (M.legend && (M.legend[pageKey()] || M.legend['*'])) || [];
    for (const sel of anchors) { const a = all(sel)[0]; if (a) return a; }
    return null;
  }
  function placeLegend() {
    const at = legendFor();
    if (!at) return;
    const have = document.querySelector('.wn-legend');
    if (have && have.parentElement === at) return;
    if (have) have.remove();
    const p = make('p', 'wn-legend');
    const star = make('span', 'wn-legend-mark', '*');
    star.setAttribute('aria-hidden', 'true');
    p.append(star, document.createTextNode(' New in this version'));
    if (at.id === 'dbFoot') at.insertBefore(p, at.firstChild); else at.appendChild(p);
  }

  // Take every "new" and the legend off the page.
  function clear() {
    all('.wn-legend').forEach(n => n.remove());
    all('[data-wn-for]').forEach(unmark);
  }
  function apply() {
    if (isHidden()) { clear(); return 0; }
    const want = plan();
    all('[data-wn-for]').forEach(el => { if (!want.has(el)) unmark(el); });
    want.forEach((features, el) => {
      const text = words(features);
      if (el.getAttribute('data-wn-new') !== text) el.setAttribute('data-wn-new', text);
      if (!el.hasAttribute('data-wn-for')) el.setAttribute('data-wn-for', '');
    });
    if (want.size) placeLegend(); else all('.wn-legend').forEach(n => n.remove());
    return want.size;
  }
  let queued = false;
  function soon() {
    if (queued) return;
    queued = true;
    (window.requestAnimationFrame || (f => window.setTimeout(f, 16)))(() => { queued = false; apply(); });
  }
  function refresh() { clear(); apply(); toggle(); }

  // ── "Hide new marks" in Advanced settings (this browser only) ───────
  function toggle() {
    if (pageKey() !== '/report/advanced') return;
    const after = document.getElementById('advGlassNote');
    if (!after) return;
    let box = document.getElementById('advWnHide');
    if (!box) {
      const lead = make('p', 'adv-lead', 'A * after a name marks a feature from the newest two updates. Point at it, or click it, to read what is new. Hide the marks if you do not need them; the choice is kept in this browser only.');
      lead.id = 'advWnLead';
      const lab = make('label', 'adv-switch');
      lab.htmlFor = 'advWnHide';
      box = make('input');
      box.type = 'checkbox';
      box.id = 'advWnHide';
      box.setAttribute('aria-describedby', 'advWnLead');
      box.addEventListener('change', () => setHidden(box.checked));
      lab.append(box, make('span', null, 'Hide new marks'));
      after.insertAdjacentElement('afterend', lead);
      lead.insertAdjacentElement('afterend', lab);
    }
    box.checked = isHidden();
  }

  function start() {
    if (!document.body) { document.addEventListener('DOMContentLoaded', start, { once: true }); return; }
    toggle();
    apply();
    new MutationObserver(soon).observe(document.body, { subtree: true, childList: true });
    window.addEventListener('storage', e => { if (e.key === KEY || e.key === null) { forced = ''; refresh(); } });
  }

  window.WhatsNew = { manifest: M, KEY, releases, active, sentence, words, pageKey, hidden: isHidden, setHidden, apply, clear, refresh };
  start();
})();
