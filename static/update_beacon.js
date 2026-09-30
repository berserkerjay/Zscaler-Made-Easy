// Update beacon: checks in the background whether GitHub has a newer build
// of this app and, when it does, shows a notice at the top of the page.
// It asks the server (/api/app/update/status), which asks GitHub at most
// every 10 minutes; the page asks a minute after it opens and then every
// 6 hours while it stays open. "Later" hides the notice for that build;
// a newer build shows it again. Works for a local install and for the
// container (whose notice points at update_container).
(function () {
  const FIRST_CHECK_MS = 60 * 1000;
  const EVERY_MS = 6 * 60 * 60 * 1000;
  const LS_DISMISSED = 'dlpcheck_update_dismissed';
  const esc = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const dismissed = () => { try { return localStorage.getItem(LS_DISMISSED) || ''; } catch (e) { return ''; } };
  const baseTitle = document.title;

  function hide() {
    const el = document.getElementById('dlpUpdateBeacon');
    if (el) el.remove();
    document.title = baseTitle;
  }

  function show(st) {
    hide();
    const bar = document.createElement('div');
    bar.id = 'dlpUpdateBeacon';
    bar.setAttribute('role', 'status');
    bar.setAttribute('aria-live', 'polite');
    bar.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:9999;display:flex;gap:12px;align-items:center;flex-wrap:wrap;'
      + 'padding:10px 16px;background:#0a3d62;color:#fff;font:14px/1.4 system-ui,-apple-system,Segoe UI,sans-serif;box-shadow:0 2px 8px rgba(0,0,0,.3)';
    const target = st.target_branch || 'main';
    const mine = st.local_commit ? ` You have ${esc(st.local_commit)}.` : '';
    const how = st.in_container
      ? 'Update the container from the computer that runs Docker: update_container.ps1 (Windows) or ./update_container.sh (Mac, Linux).'
      : 'Click Update app to install it.';
    bar.innerHTML = `<strong>Update available.</strong><span>A newer build of DLP-Check (${esc(st.remote_commit)}, ${esc(target)}) is on GitHub.${mine} ${how}</span>
      <span style="margin-left:auto;display:flex;gap:8px">
        <button type="button" id="dlpUpdateHow" style="padding:4px 12px;border-radius:6px;border:0;background:#fff;color:#0a3d62;font-weight:600;cursor:pointer">${st.in_container ? 'Show how' : 'Update app'}</button>
        <button type="button" id="dlpUpdateLater" style="padding:4px 12px;border-radius:6px;border:1px solid #fff;background:transparent;color:#fff;cursor:pointer">Later</button>
      </span>`;
    document.body.appendChild(bar);
    document.title = '● ' + baseTitle;
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
        ? 'On the computer that runs Docker, in the DLP-Check folder: Windows <code>powershell -ExecutionPolicy Bypass -File .\\update_container.ps1</code>, Mac or Linux <code>./update_container.sh</code>. Add <code>-Schedule</code> / <code>--schedule</code> once to update every day.'
        : 'Open the Home page and click <strong>Update app</strong>.';
    };
  }

  async function check() {
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
