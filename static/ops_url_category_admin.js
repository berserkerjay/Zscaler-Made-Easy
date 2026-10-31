/* Rename or delete one custom URL category on Bulk changes (/report/operations,
   "Change"), on the shared engine (ops_url_category_admin.py). Each category
   shows the rules in scope that use it; a used one cannot be deleted. The
   page does the rest: Preview, the gates (DELETE and the name typed for a
   delete), Apply and Undo. Every tenant string is escaped (H.E). */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.ucat) S.ucat = { pick: '', act: 'rename', name: '' };
    return S.ucat;
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), cats = res.categories || [];
    const errs = Object.entries(res.errors || {});
    where.innerHTML = `${errs.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${errs.map(([k, v]) => `<li>${E(k)}: ${E(v)}</li>`).join('')}</ul></div>` : ''}
      ${(res.not_checked || []).length ? `<div class="bp-card warn"><div class="t">Not checked</div><div>These policies are not in scope, so a delete stays blocked until they are ticked: ${E(res.not_checked.join(', '))}.</div></div>` : ''}
      <div class="op-row"><fieldset class="op-inline"><legend>What to do</legend>
        <label><input type="radio" name="ucAct" value="rename"${z.act === 'rename' ? ' checked' : ''}> Rename</label>
        <label><input type="radio" name="ucAct" value="delete"${z.act === 'delete' ? ' checked' : ''}> Delete (refused while a rule uses it)</label></fieldset></div>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Custom URL categories and the rules that use them</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">Category</th><th scope="col">URLs</th><th scope="col">Used by</th></tr></thead>
        <tbody>${cats.map(c => `<tr><td><input type="radio" name="ucPick" value="${E(c.id)}" aria-label="Pick ${E(c.name)}"${z.pick === String(c.id) ? ' checked' : ''}></td>
          <td>${E(c.name)}<div class="df-by">${E(c.id)} · ${E(c.super_category)}</div></td><td>${E(c.urls)}</td>
          <td>${(c.used_by || []).map(r => `${E(r.policy_label)} ${E(r.order)}: ${E(r.name)} <span class="df-chip">${E(String(r.state || '').toLowerCase())}</span>`).join('<br>') || '<span class="df-hint">no rule in scope</span>'}</td></tr>`).join('') || '<tr><td colspan="4">No custom URL category.</td></tr>'}</tbody></table></div>
      ${z.act === 'rename' ? `<div class="op-row"><label class="df-ctl"><span class="lbl">New name</span><input id="ucName" value="${E(z.name)}" maxlength="255" aria-label="New name for the URL category"></label></div>
        <div class="df-hint">Rules name a category by its id, so they keep using it. Undo renames it back.</div>`
        : `<div class="df-hint">You type DELETE and the category's name to confirm. Undo creates it again (with a new id). ${E(res.note || '')}</div>`}`;
    const again = id => { render(res, where, S, H); const el = document.getElementById(id) || where.querySelector(`input[name="${id}"]:checked`); if (el) el.focus(); };
    where.querySelectorAll('input[name="ucAct"]').forEach(r => r.addEventListener('change', () => { z.act = r.value; again('ucAct'); }));
    where.querySelectorAll('input[name="ucPick"]').forEach(r => r.addEventListener('change', () => { z.pick = r.value; }));
    const n = document.getElementById('ucName'); if (n) n.addEventListener('input', () => { z.name = n.value; });
  }
  function spec(S) {
    const z = st(S);
    if (!z.pick) throw new Error('Pick the category.');
    if (z.act === 'rename') {
      if (!String(z.name).trim()) throw new Error('Type the new name.');
      return { type: 'url_category_manage', action: 'rename', id: z.pick, new_name: String(z.name).trim() };
    }
    return { type: 'url_category_manage', action: 'delete', id: z.pick };
  }
  window.OPS_PLUGINS.register({ type: 'url_category_manage', render, spec });
}());
