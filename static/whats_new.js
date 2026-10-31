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
    "2026-10-31": "Every comparison row green: a deeper Path analyzer, Category lookup and more builders",
    "2026-10-29": "Wave 6: regression and secure-by-design testing, live motion, help on hover, Liquid Glass, a quality score"
  },
  "skipped": {
    "2026-10-30": "The new name everywhere, ZIA admin ranking in the rule decisions (no new control) and the help and new marks themselves: a * on the marks would push 2026-10-28 out, so this release is not marked and the two releases above stay"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "category-lookup", "release": "2026-10-31", "label": "Category lookup",
      "what": "Category lookup on the Path analyzer: a URL, host or category's ZIA categories and every rule that names them, in evaluation order.",
      "changelog": ["Category lookup"],
      "marks": [{ "page": "/report/path", "at": "#tab-cat" }]
    },
    {
      "id": "ucaas-one-click", "release": "2026-10-31", "label": "UCaaS one-click",
      "what": "UCaaS one-click in the ZIA baseline: Zoom, Microsoft Teams, Webex, RingCentral, GoTo and Talkdesk, with the same preview, gates, read-back and Undo.",
      "changelog": ["UCaaS one-click"],
      "marks": [{ "page": "/report/operations", "at": "#zbUcaasH", "shown": "after picking the UCaaS one-click area in the ZIA security baseline" }]
    },
    {
      "id": "m365-endpoint-list", "release": "2026-10-31", "label": "Microsoft 365 endpoint list",
      "what": "Microsoft's published list of Microsoft 365 sites and addresses, fetched when you turn it on or imported from a file, so the Office 365 One Click rule is matched instead of unknown.",
      "changelog": ["Microsoft 365 endpoint list", "Fetch Microsoft's list", "Fetch now", "Import the list from a file", "Remove the list"],
      "marks": [
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#m365\"]" },
        { "page": "/report/advanced", "at": "#advM365H" },
        { "page": "/report/advanced", "at": "#advM365On" },
        { "page": "/report/advanced", "at": "#advM365Fetch" },
        { "page": "/report/advanced", "at": "#advM365File" },
        { "page": "/report/advanced", "at": "#advM365Remove" }
      ]
    },
    {
      "id": "m365-app-services", "release": "2026-10-31", "label": "Microsoft 365 app service groups",
      "what": "The Path analyzer, its what-if and Test a list match the Office 365 One Click rule's app service group by host name and address, and say why.",
      "changelog": ["Microsoft 365 app service groups are matched", "Test a list"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" },
        { "page": "/report/path", "at": "#tab-list" }
      ]
    },
    {
      "id": "m365-shadowed", "release": "2026-10-31", "label": "Shadowed rules and the One Click rule",
      "what": "Shadowed rules finds a later firewall rule whose sites are all Microsoft 365 endpoints, hidden by the Office 365 One Click rule.",
      "changelog": ["Shadowed rules"],
      "marks": [{ "page": "/report/shadow", "at": ".rp-hero h1" }]
    },
    {
      "id": "live-motion", "release": "2026-10-29", "label": "Live motion",
      "what": "The result shows as a live flow. It stays still under reduced motion, pauses when the tab is hidden, and is said in words too.",
      "changelog": ["Live motion"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openPathAnalyzerTab()\"]" },
        { "page": "/report/path", "at": "#paFlowRefH" },
        { "page": "/report/path", "at": "#paFlowH", "shown": "after Analyze" },
        { "page": "/report/path", "at": "#plFlowH", "shown": "after a list is tested" },
        { "page": "/report/motion", "at": "#tpH" },
        { "page": "/report/dataflow", "at": "#dfMotionTitle" },
        { "page": "/report/sslflow", "at": "#sfWalkTitle", "shown": "after a read" },
        { "page": "/report/sslcoverage", "at": "#hRiver", "shown": "after a read" },
        { "page": "/report/zpa", "at": "#zoFlowH", "shown": "after a read" },
        { "page": "/report/zpa", "at": "#zpWalkH", "shown": "after Diagnose" },
        { "page": "/report/insights", "at": "#tiFlowH", "shown": "after a read" },
        { "page": "/report/live", "at": "#lfLanesH" },
        { "page": "/report/bypass", "at": "#bpFlowH", "shown": "after a read" }
      ]
    },
    {
      "id": "liquid-glass", "release": "2026-10-29", "label": "Liquid Glass",
      "what": "The Liquid Glass look: see-through, blurred bars, cards, dialogs and buttons, with a switch in Advanced settings to turn it off.",
      "changelog": ["Liquid Glass"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAdvancedTab()\"]" },
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#appearance\"]" },
        { "page": "/report/advanced", "at": "#advGlass" }
      ]
    },
    {
      "id": "quality-score", "release": "2026-10-29", "label": "Quality and security score",
      "what": "The quality and security score for this app, built from every QA record, the standards each test covers and the last full test run.",
      "changelog": ["Quality and security score"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openAdvancedTab()\"]" },
        { "page": "/report/advanced", "at": "a.rp-btn[href=\"#quality\"]" },
        { "page": "/report/advanced", "at": "#advQsH" }
      ]
    },
    {
      "id": "rule-editor", "release": "2026-10-31", "label": "Edit a rule",
      "what": "Edit a rule on Bulk changes: create, edit, duplicate or delete one ZIA rule with a form per rule type, a plain-language preview, its placement and rank, and Undo.",
      "changelog": ["Edit a rule", "Create it enabled", "Create a rule", "Duplicate a rule", "Delete a rule"],
      "marks": [
        { "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"rule_edit\"]", "shown": "under Build new" },
        { "page": "/report/operations", "at": "#reType", "shown": "after Read from the tenant in Edit a rule" }
      ]
    },
    {
      "id": "dns-ips-state", "release": "2026-10-31", "label": "DNS and IPS rules",
      "what": "Enable or disable rules now covers DNS Control and IPS rules.",
      "changelog": ["Enable or disable DNS and IPS rules"],
      "marks": [{ "page": "/report/operations", "at": "#opPolicy", "shown": "after Read from the tenant in Enable or disable rules" }]
    },
    {
      "id": "zpa-segment-edit", "release": "2026-10-31", "label": "Edit a ZPA application segment",
      "what": "Edit one ZPA application segment's settings and ports, or enable or disable it.",
      "changelog": ["Edit a ZPA application segment"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"zpa_segment_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "app-objects", "release": "2026-10-31", "label": "Cloud app instances and tenancy restrictions",
      "what": "Browse cloud application instances and tenancy restriction profiles, and create or edit one.",
      "changelog": ["Cloud app instances and tenancy restrictions"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"app_object_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "proxy-chaining", "release": "2026-10-31", "label": "Proxy chaining",
      "what": "Create or edit a proxy for proxy chaining, see the gateways that use it and the portal steps a gateway needs.",
      "changelog": ["Proxy chaining"],
      "marks": [{ "page": "/report/operations", "at": "input[name=\"opKind\"][value=\"proxy_chain_edit\"]", "shown": "under Build new" }]
    },
    {
      "id": "config-restore", "release": "2026-10-31", "label": "Backups, restore and clone",
      "what": "Backups of ZIA, ZPA and Client Connector, a field-by-field compare, restore and clone with a plan, a fresh backup first and Undo, and templates for any tenant.",
      "changelog": ["Configuration backups", "Compare field by field", "Restore and clone", "Templates", "Scheduled backups", "Configuration cache", "Rehearsal", "Licence check"],
      "marks": [
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"config_restore_zia\"]", "shown": "after the page lists the builders" },
        { "page": "/report/operations", "at": "#crSave", "shown": "after Read from the tenant on a restore type" }
      ]
    },
    {
      "id": "zpa-identity-whatif", "release": "2026-10-31", "label": "ZPA identity in the what-if",
      "what": "The what-if takes a ZPA identity: pick the IdP, look a user's SCIM groups up and type SAML or SCIM attribute values, and ZPA's access policy says which identity condition decided.",
      "changelog": ["ZPA identity in the Path analyzer"],
      "marks": [
        { "page": "/report/path", "at": "#paWhatIf > summary" },
        { "page": "/report/path", "at": "#paZidH", "shown": "after Analyze with a ZPA identity" }
      ]
    },
    {
      "id": "zpa-identity-list", "release": "2026-10-31", "label": "ZPA identity column",
      "what": "Test a list takes a ZPA identity per row: the IdP, a SCIM user name and attribute values.",
      "changelog": ["ZPA identity column"],
      "marks": [{ "page": "/report/path", "at": "#tab-list" }]
    },
    {
      "id": "zpa-builder-identity", "release": "2026-10-31", "label": "Access rules for SCIM groups and SAML attributes",
      "what": "The ZPA builder's access rule can allow only users in SCIM groups or with SAML attribute values picked from the tenant.",
      "changelog": ["Access rules for SCIM groups and SAML attributes"],
      "marks": [{ "page": "/report/operations", "at": "#zbWho > legend", "shown": "in ZPA policy rules, Only some users" }]
    },
    {
      "id": "admin-zpa", "release": "2026-10-31", "label": "ZPA day-to-day admin",
      "what": "Change App Connectors, Service Edges, their groups and PRA and user portals (health first, rename, on or off, move, update schedule), delete them with a typed confirmation, make a provisioning key shown once, and rotate Browser Access certificates.",
      "changelog": ["ZPA day-to-day admin", "ZPA provisioning keys", "ZPA Browser Access certificates"],
      "marks": [
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"zpa_infra_update\"]", "shown": "in Build new" },
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"zpa_ba_certificate\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "admin-zcc", "release": "2026-10-31", "label": "Client Connector day-to-day admin",
      "what": "Remove or force remove devices, one user's or a whole list in batches within the hourly API budget, manage custom bypass apps, and set who gets ZPA and ZDX.",
      "changelog": ["Client Connector day-to-day admin", "Remove devices from a list", "Custom bypass apps and entitlements"],
      "marks": [
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"zcc_device_bulk_remove\"]", "shown": "in Build new" },
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"zcc_entitlements\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "admin-zdx", "release": "2026-10-31", "label": "ZDX deep trace and look-ups",
      "what": "Start a ZDX deep trace on a user's device, follow it and see its results; look up users, devices and their health, and application scores.",
      "changelog": ["ZDX deep trace and look-ups"],
      "marks": [
        { "page": "/report/operations", "at": "#opBuildKinds input[name=\"opKind\"][value=\"zdx_deeptrace_start\"]", "shown": "in Build new" }
      ]
    },
    {
      "id": "rank-inherit", "release": "2026-10-31", "label": "Admin rank of new rules",
      "what": "Rules a change creates or moves take the admin rank they need when Admin Ranking is on, never one the API client cannot assign; the preview says each rule's rank and why, and the read-back checks what ZIA stored.",
      "changelog": ["Rank inherited, not fixed at 7", "Never a rank the API client cannot assign", "Preview", "Read-back", "Undo", "Use rank 0", "Admin rank of the rules this change places"],
      "marks": [{ "page": "/report/operations", "at": "#opRankH", "shown": "in a preview that places a rule" }]
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
