// ── Path analyzer: what-if for a user, group, department and location ──
// The what-if panel's inputs are in the page (report_path.html, #paWhatIf);
// this file holds what they do and what the result shows:
//
// * PathWhatIf.init({ credBody, scopeSelection }) wires each "Look up in
//   ZIA" button with the page's own credentials and Scope page selection;
// * PathWhatIf.identity() is what the page adds to its start request
//   (`identity`, only what was typed or picked);
// * PathWhatIf.section(whatif) is "Policy action also depends on" for a
//   result (path_whatif.py on the server), and PathWhatIf.wire(container)
//   wires its "Show more" button.
//
// Names are looked up in ZIA only when ZIA platform is ticked on the Scope
// page (the server checks it again): one search of at most 20 names per
// click, never a bulk listing. Nothing here writes to the tenant.
(function () {
  'use strict';
  const E = s => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const FIELDS = ['user', 'group', 'department', 'location'];
  const STATE = { match: ['met', 'ok'], nomatch: ['not met', 'fail'], unknown: ['depends', 'warn'] };
  const picked = {};          // field -> {id, name, email?} chosen from a ZIA search
  let page = { credBody: () => ({}), scopeSelection: () => ({ scopes: [], channels: {}, from_page: false }) };
  const lookupAllowed = () => (page.scopeSelection().scopes || []).includes('zia_extras');

  // ── The inputs ───────────────────────────────────────────────────────
  function identity() {
    const out = {};
    FIELDS.forEach(k => {
      const el = document.getElementById(`paWi_${k}`);
      const v = el ? el.value.trim().slice(0, 200) : '';
      if (!v) return;
      const p = picked[k];
      out[k] = p && p.name === v ? p : v;
    });
    if (picked.groups && out.group === picked.groups.map(g => g.name).join(', ')) { out.groups = picked.groups; delete out.group; }
    return out;
  }
  // The panel is in the page; this wires its buttons and the scope hint.
  function init(fns) {
    page = Object.assign(page, fns || {});
    const box = document.getElementById('paWhatIf');
    if (!box) return;
    const hint = document.getElementById('paWiScope');
    const refresh = () => {
      const ok = lookupAllowed();
      hint.textContent = ok ? 'Look up searches ZIA by name: one search of at most 20 names, nothing else is read.'
        : 'Looking names up in ZIA needs ZIA platform ticked on the Scope page. You can still type them.';
      box.querySelectorAll('[data-wi-find]').forEach(b => { b.disabled = !ok; });
    };
    refresh();
    box.addEventListener('toggle', refresh);
    box.addEventListener('click', e => {
      const b = e.target.closest('[data-wi-find]');
      if (b) { find(b.dataset.wiFind, b); return; }
      const r = e.target.closest('[data-wi-pick]');
      if (r) pick(r.dataset.wiField, Number(r.dataset.wiPick));
    });
  }
  const found = {};
  async function find(kind, btn) {
    const input = document.getElementById(`paWi_${kind}`);
    const list = document.getElementById(`paWiRes_${kind}`);
    const live = document.getElementById('paWiLive');
    const q = input.value.trim();
    if (q.length < 2) { live.textContent = 'Type at least 2 characters to look a name up.'; input.focus(); return; }
    if (btn) { btn.disabled = true; btn.textContent = 'Looking up…'; }
    try {
      const r = await fetch('/api/path-analyzer/identities', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({}, page.credBody(), page.scopeSelection(), { kind, query: q })) });
      const d = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error((d.detail && (d.detail.cause || d.detail)) || `HTTP ${r.status}`);
      found[kind] = d.results || [];
      list.hidden = false;
      if (d.error) { list.innerHTML = `<li class="df-hint">ZIA could not answer: ${E(d.error)}</li>`; live.textContent = `The lookup failed: ${d.error}`; return; }
      if (!found[kind].length) { list.innerHTML = `<li class="df-hint">No ${E(kind)} in ZIA starts with or contains “${E(q)}”. You can keep the name as typed.</li>`; live.textContent = 'No match.'; return; }
      list.innerHTML = found[kind].map((x, i) => `<li><button type="button" class="rp-btn" data-wi-field="${E(kind)}" data-wi-pick="${i}">${E(x.name)}${x.email ? ` <span class="df-by">${E(x.email)}</span>` : ''}${x.department && x.department.name ? ` <span class="df-by">${E(x.department.name)}</span>` : ''}</button></li>`).join('')
        + (d.capped ? '<li class="df-hint">Showing the first 20; type more of the name to narrow it.</li>' : '');
      live.textContent = `${found[kind].length} match(es). Choose one.`;
      const first = list.querySelector('button'); if (first) first.focus();
    } catch (e) {
      list.hidden = false;
      list.innerHTML = `<li class="df-hint">${E(e.message)}</li>`;
      live.textContent = `The lookup could not run: ${e.message}`;
    } finally {
      if (btn) { btn.disabled = !lookupAllowed(); btn.textContent = 'Look up in ZIA'; }
    }
  }
  function pick(kind, i) {
    const x = (found[kind] || [])[i];
    if (!x) return;
    const input = document.getElementById(`paWi_${kind}`);
    picked[kind] = { id: x.id, name: x.name, email: x.email || undefined };
    input.value = x.name;
    if (kind === 'user') {
      // A user found in ZIA brings their department and groups along.
      if (x.department && x.department.name) { picked.department = x.department; document.getElementById('paWi_department').value = x.department.name; }
      if ((x.groups || []).length) { picked.groups = x.groups; document.getElementById('paWi_group').value = x.groups.map(g => g.name).join(', '); }
    }
    const list = document.getElementById(`paWiRes_${kind}`);
    list.hidden = true; list.innerHTML = '';
    document.getElementById('paWiLive').textContent = `${x.name} chosen.`;
    input.focus();
  }

  // ── The result: "Policy action also depends on" ───────────────────────
  function crit(c) {
    const [lab, cls] = STATE[c.state] || [c.state, 'dim'];
    return `<div><span class="df-chip st-${E(cls)}">${E(lab)}</span> ${E(c.name)}</div>`;
  }
  function section(w) {
    const deps = w.depends_on || [];
    const n = w.shown || 3;
    const who = w.identity_label ? `<div class="df-hint">Evaluated for ${E(w.identity_label)}: ${E(w.counts.applies)} scoped rule(s) apply, ${E(w.counts.skipped)} are for others and skipped, ${E(w.counts.open)} still depend on something not given.</div>` : '';
    const rows = deps.map((d, i) => `<tr${i >= n ? ' hidden data-wi-more' : ''}>
        <td>${(d.criteria || []).map(crit).join('')}</td>
        <td>${E(d.section)}<br><code>${E(d.rule && d.rule.name)}</code>${d.rule && d.rule.order != null ? ` <span class="df-by">order ${E(d.rule.order)}</span>` : ''}</td>
        <td><strong>${E(d.action)}</strong></td>
        <td>${E(d.otherwise)}${d.otherwise_rule ? `<br><span class="df-by">${E(d.otherwise_rule)}</span>` : ''}</td></tr>`).join('');
    const table = deps.length ? `<div class="df-tablewrap"><table class="df-table">
        <caption class="sr-only">Conditions that change the policy action, with the rule and the action it would give</caption>
        <thead><tr><th scope="col">When</th><th scope="col">Rule</th><th scope="col">Action it would give</th><th scope="col">Otherwise</th></tr></thead>
        <tbody>${rows}</tbody></table></div>
        ${deps.length > n ? `<p><button type="button" class="rp-btn" id="paWiMore" aria-expanded="false">Show ${deps.length - n} more</button></p>` : ''}`
      : `<div class="df-hop-d pa-none">${E(w.empty_reason || 'Nothing else changes the action.')}</div>`;
    return `<section class="pa-whatif-out" id="paWhatIfOut" aria-labelledby="paWiH">
        <h2 class="df-h" id="paWiH">Policy action also depends on</h2>
        <div class="df-hint">Each row is a rule scoped to a user, group, department, location, time window or device trust level that would change what happens to this traffic, most disruptive first.</div>
        ${who}${table}</section>`;
  }
  // The "Show more" button of a drawn section.
  function wire(container) {
    const more = container && container.querySelector('#paWiMore');
    if (!more) return;
    more.addEventListener('click', () => {
      const rows = container.querySelectorAll('#paWhatIfOut [data-wi-more]');
      const open = more.getAttribute('aria-expanded') !== 'true';
      rows.forEach(tr => { tr.hidden = !open; });
      more.setAttribute('aria-expanded', open ? 'true' : 'false');
      more.textContent = open ? 'Show fewer' : `Show ${rows.length} more`;
    });
  }

  window.PathWhatIf = { init, identity, section, wire };
})();
