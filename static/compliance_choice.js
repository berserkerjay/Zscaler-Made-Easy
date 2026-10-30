// The one compliance choice (compliance_profiles.py), shared by the ZIA
// baseline builder, the AI Guard detection policy, the POV planner and the
// Compliance page: the profile list, the choice remembered per saved tenant
// profile, and compliance pack downloads. Every call is an ordinary /api/
// request (UI token cookie, same-origin check); nothing here reads or
// changes a tenant.
(function () {
  if (window.ZMECompliance) return;
  const E = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  let cat = null, current = '';
  const listeners = [];
  const KEY = /^[A-Z0-9_]{1,40}$/;

  // The saved tenant profile picked on the page (Bulk changes' tenant list), if any.
  function tenantProfileId() {
    const el = document.getElementById('opTenant');
    const v = el ? String(el.value || '') : '';
    return v.startsWith('profile:') ? v.slice(8) : '';
  }
  async function catalog() {
    if (cat) return cat;
    const r = await fetch('/api/compliance-profiles', { cache: 'no-store' });
    if (!r.ok) throw new Error(`The compliance profiles could not be loaded (HTTP ${r.status}).`);
    cat = await r.json();
    return cat;
  }
  async function remembered(pid) {
    pid = pid || tenantProfileId();
    if (!pid) return '';
    try {
      const r = await fetch('/api/tenant-profiles', { cache: 'no-store' });
      if (!r.ok) return '';
      const p = ((await r.json()).profiles || []).find(x => x.id === pid);
      const k = p && p.compliance_profile ? String(p.compliance_profile) : '';
      return KEY.test(k) ? k : '';
    } catch (e) { return ''; }
  }
  async function remember(key, pid) {
    pid = pid || tenantProfileId();
    if (!pid) return false;
    const r = await fetch('/api/compliance-profiles/choice', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: pid, compliance_profile: key || '' }) });
    return r.ok;
  }
  function set(key) {
    current = KEY.test(String(key || '')) ? String(key) : '';
    listeners.forEach(fn => { try { fn(current); } catch (e) { /* a listener's own problem */ } });
  }
  function profile(key) { return ((cat && cat.profiles) || []).find(p => p.key === key) || null; }
  function summary(key) { return ((cat && cat.summaries) || {})[key] || null; }
  // A <select> of every profile, grouped (Federal and public sector first).
  function selectHtml(id, value, label) {
    const groups = {};
    ((cat && cat.profiles) || []).forEach(p => { (groups[p.group] = groups[p.group] || []).push(p); });
    const order = (cat && cat.groups) || Object.keys(groups);
    return `<select id="${E(id)}" aria-label="${E(label || 'Compliance profile')}" style="max-width:100%"><option value="">None (no compliance profile)</option>${
      order.filter(g => groups[g]).map(g => `<optgroup label="${E(g)}">${groups[g].map(p =>
        `<option value="${E(p.key)}"${p.key === value ? ' selected' : ''}>${E(p.label)}</option>`).join('')}</optgroup>`).join('')}</select>`;
  }
  // What picking the profile will do, as a list, with its sources.
  function summaryHtml(key) {
    const s = summary(key);
    if (!s) return '';
    const https = u => (/^https:\/\//.test(String(u || '')) ? String(u) : '#');
    return `<div class="bp-card" role="region" aria-label="What ${E(s.label)} will do"><div class="t">What ${E(s.label)} will do</div>
      <ul>${(s.lines || []).map(l => `<li>${E(l)}</li>`).join('')}</ul>
      <div class="df-hint">${E(s.reuses)}${s.assumed_profile ? ` Assumed: ${E(s.assumed_profile)}` : ''}</div>
      ${(s.sources || []).length ? `<div class="df-hint">Sources: ${s.sources.map(x => `<a href="${E(https(x.url))}" target="_blank" rel="noopener noreferrer">${E(x.title)}</a>`).join('; ')}</div>` : ''}
      ${(s.assumed_controls || []).length ? `<div class="df-hint">Controls marked assumed (not verified against the source): ${E(s.assumed_controls.join(', '))}</div>` : ''}</div>`;
  }
  // One compliance pack file, from the build on screen (spec) or a recorded run.
  async function download(body) {
    const r = await fetch('/api/compliance-pack/file', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    if (!r.ok) { const d = await r.json().catch(() => ({})); throw new Error(typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`); }
    const blob = await r.blob();
    const m = /filename="([^"]+)"/.exec(r.headers.get('Content-Disposition') || '');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob); a.download = m ? m[1] : 'compliance-pack';
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }
  async function manifest(body) {
    const r = await fetch('/api/compliance-pack', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    const d = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(typeof d.detail === 'string' ? d.detail : `HTTP ${r.status}`);
    return d;
  }
  window.ZMECompliance = { catalog, remembered, remember, set, get current() { return current; }, onChange: fn => listeners.push(fn),
    profile, summary, selectHtml, summaryHtml, download, manifest, tenantProfileId };
})();
