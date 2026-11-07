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
    "2026-11-07": "The Tenant API map: which Zscaler features the tenant has and which reads its API client may make, found by asking after you confirm every endpoint (its own page, separate from the licence and editions check)",
    "2026-11-04": "Sign in once on every page, clone breadth in restore and clone, a data flow map a newcomer can read, true SSL inspection coverage, device posture across products and in the Path analyzer, the whole POV build simulated, lighter glass on slow computers, the SOC review, app service groups out of the box, and encrypted stores on by default with a managed-name prefix"
  },
  "skipped": {
    "2026-11-07": "Assistant tools (capacity review, postmortem, lookup, cite, investigation journal) and the Capacity review page: the assistant tools have no control on a page, and the page is listed here until the next release batch marks it.",
    "2026-11-06": "Fixes with no new control: a read-only container answers health and says why its stores are not encrypted, the glass costs less while scrolling, and the browser acceptance run follows Chrome 157's error-page frames; a * on them would push 2026-11-01 out, so this release is not marked",
    "2026-10-30": "The new name everywhere, ZIA admin ranking in the rule decisions (no new control) and the help and new marks themselves: a * on the marks would push 2026-10-28 out, so this release is not marked and the two releases above stay"
  },
  "legend": { "/": ["#dbFoot", ".hero"], "*": [".rp-hero"] },
  "features": [
    {
      "id": "tenant-api-map", "release": "2026-11-07", "label": "Tenant API map",
      "what": "A Tenant API map page, separate from the licence and editions check: it finds out which Zscaler features the tenant has and which reads your API client may make. It lists every endpoint first and reads nothing until you confirm; GET only, one a second, Stop at any time. It keeps statuses, item counts and field names, never a value, and saves the map for this tenant.",
      "changelog": ["Tenant API map", "Map this tenant's APIs"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openApiMapTab()\"]" },
        { "page": "/report/operations", "at": "#opApiMap" },
        { "page": "/report/api-map", "at": ".rp-hero h1" },
        { "page": "/report/api-map", "at": "#amRun" }
      ]
    },
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
      "changelog": ["Simulate the whole POV build", "Apply to a simulation"],
      "marks": [{ "page": "/report/pov", "at": "#pbSimulate", "shown": "after a dry run of the build on the sample tenant or a snapshot" }]
    },
    {
      "id": "glass-light", "release": "2026-11-04", "label": "Lighter glass",
      "what": "The glass effect draws far less on a computer without a graphics card: the backdrop moves once a second, and cards in the page drop their blur while you scroll. It looks the same.",
      "changelog": ["Lighter glass on slow computers"],
      "marks": [{ "page": "/report/advanced", "at": "#advGlass" }]
    },
    {
      "id": "soc-review", "release": "2026-11-04", "label": "SOC review",
      "what": "A SOC review page: admin access (who can administer ZIA, ZPA, Client Connector, ZDX and ZIdentity, full or limited rights, disabled and unused admins, API keys and clients) and logging (what is sent to your SIEM and the gaps). Unknown is never counted as fine.",
      "changelog": ["SOC review page", "SOC review", "Admin access", "Logging"],
      "marks": [
        { "page": "/", "at": "button[onclick=\"openSocReviewTab()\"]" },
        { "page": "/report/soc-review", "at": ".rp-hero h1" },
        { "page": "/report/operations", "at": "#opSocReview" }
      ]
    },
    {
      "id": "app-service-group-excerpts", "release": "2026-11-04", "label": "App service groups out of the box",
      "what": "Microsoft 365 app service groups now match out of the box from a dated excerpt of Microsoft's published list (version 2026043000) that comes with the app; the other providers' groups match once their list is fetched or imported, and GoTo's list can now be fetched too, on its own switch, off by default.",
      "changelog": ["App service groups out of the box", "Fetch GoTo's list", "Zscaler's own app service groups"],
      "marks": [
        { "page": "/report/advanced", "at": "#advVendBundled" },
        { "page": "/report/advanced", "at": "#advVendGotoOn" },
        { "page": "/report/advanced", "at": "#advVendZs" }
      ]
    },
    {
      "id": "store-encryption-default", "release": "2026-11-04", "label": "Encrypted stores on by default",
      "what": "The app's files on disk are encrypted (AES-256-GCM) without a setting; files an earlier version wrote are encrypted once at the first start, with a verified backup first. DLP_CHECK_STORE_ENCRYPTION=0 opts out.",
      "changelog": ["Encrypted stores on by default"],
      "marks": [
        { "page": "/report/advanced", "at": "#advStoreH" },
        { "page": "/report/team", "at": "#tmStoreRotate", "shown": "for administrators on a team server" }
      ]
    },
    {
      "id": "managed-name-prefix", "release": "2026-11-04", "label": "Managed-name prefix",
      "what": "An optional prefix the operator sets (DLP_CHECK_NAME_PREFIX) goes in front of every name a policy pack deploys or builds; the plan shows it, and objects under the prefixed name are reused, but a removal deletes one only when it carries this app's tag or a deployment record lists it.",
      "changelog": ["Managed-name prefix"],
      "marks": [{ "page": "/", "at": "#dlpDeployModal #dzNamePrefix", "shown": "in the deploy preview when the operator set a prefix" }]
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
