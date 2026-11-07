/* AI prompt capture on Bulk changes (/report/operations, "Build new").
   One form on the shared engine (ops_zia_ai_prompt.py): every prompt-capture
   switch the tenant has, with the app and whether it is on. Nothing is
   pre-picked: choose On or Off for the switches to change, then Preview.
   The page does the rest: the typed phrase, Apply, the read-back and Undo.
   Every tenant string is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  function st(S) { if (!S.aip) S.aip = { pick: new Map() }; return S.aip; }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), sw = res.switches || [];
    where.innerHTML = `${errs(H, res)}
      <div class="bp-card warn" role="note"><div class="t">Privacy</div><div>${E(res.privacy || '')}</div></div>
      <p class="df-hint">Gen AI Security subscription: ${res.licensed === true ? 'present' : res.licensed === false ? 'not found (turning a switch on is refused)' : 'not read'}.</p>
      ${sw.length ? `<div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Prompt-capture switches</caption>
        <thead><tr><th scope="col">App</th><th scope="col">Now</th><th scope="col">Change to</th></tr></thead>
        <tbody>${sw.map(s => `<tr><td>${E(s.app)}<div class="df-by">${E(s.key)}</div></td><td>${s.on ? 'On' : 'Off'}</td>
          <td><select data-sw="${E(s.key)}" aria-label="Change ${E(s.app)} prompt capture to">
            <option value="">Leave as it is</option><option value="on"${z.pick.get(s.key) === true ? ' selected' : ''}>On</option><option value="off"${z.pick.get(s.key) === false ? ' selected' : ''}>Off</option></select></td></tr>`).join('')}</tbody></table></div>`
        : '<div class="df-hint">This tenant\'s settings carry no prompt-capture switch, or they could not be read.</div>'}`;
    where.querySelectorAll('select[data-sw]').forEach(el => el.addEventListener('change', () => {
      if (el.value) z.pick.set(el.dataset.sw, el.value === 'on'); else z.pick.delete(el.dataset.sw);
    }));
  }
  function spec(S) {
    const z = st(S);
    if (!z.pick.size) throw new Error('Pick at least one app and choose On or Off.');
    return { type: 'zia_ai_prompt_capture', switches: Object.fromEntries(z.pick) };
  }
  window.OPS_PLUGINS.register({ type: 'zia_ai_prompt_capture', render, spec });
})();
