// Update beacon: checks in the background whether GitHub has a newer build
// of this app and, when it does, shows a notice at the top of the page.
// It asks the server (/api/app/update/status), which asks GitHub at most
// every 10 minutes; the page asks a minute after it opens and then every
// 6 hours while it stays open. "Later" hides the notice for that build;
// a newer build shows it again. Works for a local install and for the
// container (whose notice points at update_container).
// A second bar, on the same schedule, shows Beacon's persistent upstream
// drift (SDK, API, Terraform) from /api/beacon/status: a finding must be in
// two consecutive comparable runs before it appears. The endpoint only
// reads what Beacon's own timer found; Later hides that confirmed set until
// it changes.
(function () {
  const FIRST_CHECK_MS = 60 * 1000;
  const EVERY_MS = 6 * 60 * 60 * 1000;
  const LS_DISMISSED = 'dlpcheck_update_dismissed';
  const LS_UPSTREAM_DISMISSED = 'dlpcheck_upstream_dismissed';
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const stored = key => { try { return localStorage.getItem(key) || ''; } catch (e) { return ''; } };
  const dismissed = () => stored(LS_DISMISSED);
  const baseTitle = document.title;
  const BAR_CSS = 'display:flex;gap:12px;align-items:center;flex-wrap:wrap;padding:10px 16px;color:#fff;'
    + 'font:14px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.3)';

  // Both bars live in one fixed stack at the top, so they never overlap.
  function stack() {
    let el = document.getElementById('dlpBeaconStack');
    if (!el) {
      el = document.createElement('div');
      el.id = 'dlpBeaconStack';
      el.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;display:flex;flex-direction:column';
      document.body.appendChild(el);
    }
    return el;
  }
  function retitle() {
    document.title = (document.getElementById('dlpUpdateBeacon') || document.getElementById('dlpUpstreamBeacon') ? '● ' : '') + baseTitle;
  }

  function hide() {
    const el = document.getElementById('dlpUpdateBeacon');
    if (el) el.remove();
    retitle();
  }

  function show(st) {
    hide();
    const bar = document.createElement('div');
    bar.id = 'dlpUpdateBeacon';
    bar.setAttribute('role', 'status');
    bar.setAttribute('aria-live', 'polite');
    bar.style.cssText = BAR_CSS + ';background:#0a3d62';
    const target = st.target_branch || 'main';
    const mine = st.local_commit ? ` You have ${esc(st.local_commit)}.` : '';
    const how = st.in_container
      ? 'Update the container from the computer that runs Docker: update_container.ps1 (Windows) or ./update_container.sh (Mac, Linux).'
      : 'Click Update app to install it.';
    bar.innerHTML = `<strong>Update available.</strong><span>A newer build of Zscaler Made Easy (${esc(st.remote_commit)}, ${esc(target)}) is on GitHub.${mine} ${how}</span>
      <span style="margin-left:auto;display:flex;gap:8px">
        <button type="button" id="dlpUpdateHow" style="padding:4px 12px;border-radius:6px;border:0;background:#fff;color:#0a3d62;font-weight:600;cursor:pointer">${st.in_container ? 'Show how' : 'Update app'}</button>
        <button type="button" id="dlpUpdateLater" style="padding:4px 12px;border-radius:6px;border:1px solid #fff;background:transparent;color:#fff;cursor:pointer">Later</button>
      </span>`;
    stack().prepend(bar);
    retitle();
    document.getElementById('dlpUpdateLater').onclick = () => {
      try { localStorage.setItem(LS_DISMISSED, st.remote_commit || ''); } catch (e) { /* storage unavailable */ }
      hide();
    };
    document.getElementById('dlpUpdateHow').onclick = () => {
      const box = document.getElementById('gdUpdate');   // the guide's update box, on the home page
      if (box && st.in_container && typeof _gdContainerUpdateHelp === 'function') {
        hide(); _gdContainerUpdateHelp(); box.scrollIntoView({ block: 'center' }); return;
      }
      if (box && !st.in_container && typeof _gdUpdateApp === 'function') {
        hide(); _gdUpdateApp(); box.scrollIntoView({ block: 'center' }); return;
      }
      // Anywhere else: say it right here.
      const txt = bar.querySelector('span');
      txt.innerHTML = st.in_container
        ? `On the computer that runs Docker, in the Zscaler Made Easy folder: Windows <code>powershell -ExecutionPolicy Bypass -File .\\update_container.ps1 -Branch ${esc(target)}</code>, Mac or Linux <code>./update_container.sh --branch ${esc(target)}</code>. Add <code>-Schedule</code> / <code>--schedule</code> once to update every day.`
        : 'Open the Home page and click <strong>Update app</strong>.';
    };
  }

  function hideUpstream() {
    const el = document.getElementById('dlpUpstreamBeacon');
    if (el) el.remove();
    retitle();
  }

  function showUpstream(st) {
    hideUpstream();
    const drift = st.drift || [];
    const areas = [...new Set(drift.map(d => d.watcher).filter(Boolean))].join(', ');
    const first = drift[0] ? drift[0].text : '';
    const more = drift.length > 1 ? ` (and ${drift.length - 1} more)` : '';
    const bar = document.createElement('div');
    bar.id = 'dlpUpstreamBeacon';
    bar.setAttribute('role', 'status');
    bar.setAttribute('aria-live', 'polite');
    bar.style.cssText = BAR_CSS + ';background:#7a4b00';
    bar.innerHTML = `<strong>Upstream change${areas ? ': ' + esc(areas) : ''}.</strong><span>${esc(first)}${esc(more)}</span>
      <span style="margin-left:auto;display:flex;gap:8px">
        <a id="dlpUpstreamDetails" href="${esc(st.details || '/report/beacon')}" target="_blank" rel="noopener" style="padding:4px 12px;border-radius:6px;background:#fff;color:#7a4b00;font-weight:600;text-decoration:none">Details</a>
        <button type="button" id="dlpUpstreamLater" style="padding:4px 12px;border-radius:6px;border:1px solid #fff;background:transparent;color:#fff;cursor:pointer">Later</button>
      </span>`;
    stack().appendChild(bar);
    retitle();
    document.getElementById('dlpUpstreamLater').onclick = () => {
      try { localStorage.setItem(LS_UPSTREAM_DISMISSED, st.drift_key || ''); } catch (e) { /* storage unavailable */ }
      hideUpstream();
    };
  }

  async function checkUpstream() {
    try {
      const r = await fetch('/api/beacon/status', { cache: 'no-store' });
      if (!r.ok) return;
      const st = await r.json();
      if ((st.drift || []).length && st.drift_key && st.drift_key !== stored(LS_UPSTREAM_DISMISSED)) showUpstream(st);
      else hideUpstream();
    } catch (e) { /* offline or locked: try again next time */ }
  }

  async function check() {
    checkUpstream();
    try {
      const r = await fetch('/api/app/update/status', { cache: 'no-store' });
      if (!r.ok) return;
      const st = await r.json();
      if (st.update_available && st.remote_commit && st.remote_commit !== dismissed()) show(st);
      else if (!st.update_available) hide();
    } catch (e) { /* offline or locked: try again next time */ }
  }

  window.dlpUpdateBeaconCheck = check;   // for a manual re-check from the console or other add-ons
  setTimeout(check, FIRST_CHECK_MS);
  setInterval(check, EVERY_MS);
})();
