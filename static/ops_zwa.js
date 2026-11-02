// Close DLP incidents as false positives: the form of ops_zwa.py on the Bulk
// changes page. It registers with window.OPS_PLUGINS and goes through the
// page's own read, preview, gates (write mode, writer, named assessor, typed
// phrase), apply, read-back and Undo; this file only draws the picker from
// the tenant read and builds the spec. Detection health links here as
// /report/operations?build=zwa_close_false_positives&rule=<name> (or &host=).
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;
  const TYPE = 'zwa_close_false_positives';
  const MAX = 100;
  const q = new URLSearchParams(window.location.search);
  const handoff = { rule: (q.get('rule') || '').slice(0, 200), host: (q.get('host') || '').slice(0, 253) };

  function st(S) {
    if (!S.zwa) S.zwa = { pick: new Set(), note: '', mode: (handoff.rule || handoff.host) ? 'match' : 'pick' };
    return S.zwa;
  }
  function render(res, where, S, H) {
    const E = H.E, z = st(S), list = (res && res.incidents) || [];
    const errs = (res && res.errors) || [];
    const er = errs.length ? `<div class="bp-card warn"><div class="t">Could not be read in full</div><ul>${errs.map(e => `<li>${E(e)}</li>`).join('')}</ul></div>` : '';
    const what = handoff.rule ? `rule <strong>${E(handoff.rule)}</strong>` : handoff.host ? `destination <strong>${E(handoff.host)}</strong>` : '';
    const match = what ? `<label class="op-kind"><input type="radio" name="zwaMode" value="match"${z.mode === 'match' ? ' checked' : ''}>
        <span><strong>Every open incident of the ${what}</strong><span class="df-hint">From Detection health: the last 30 days, at most ${MAX}.</span></span></label>` : '';
    const rows = list.map(i => `<tr><td><input type="checkbox" data-zwa="${E(i.id)}" aria-label="Close incident ${E(i.id)}"${z.pick.has(i.id) ? ' checked' : ''}></td>
        <td>${E(i.id)}</td><td>${E((i.rules || []).join(', '))}</td><td>${E(i.host || '')}</td><td>${E(String(i.created_at || '').slice(0, 10))}</td></tr>`).join('');
    where.innerHTML = `${er}
      <p>Close open Workflow Automation incidents that analysts have judged not to be real leaks. Each one is closed with the resolution
      code FALSE_POSITIVE and a note naming you as the assessor; the rule that raised it is not changed. Only incident metadata is read:
      the evidence is never fetched.</p>
      <div class="bp-card warn"><div class="t">No reopen through the API</div><div>${E((res && res.no_reopen) || '')}</div></div>
      <fieldset class="op-kinds"><legend class="op-h">Which incidents</legend>${match}
        <label class="op-kind"><input type="radio" name="zwaMode" value="pick"${z.mode === 'pick' ? ' checked' : ''}>
        <span><strong>The incidents I pick below</strong><span class="df-hint">The open incidents of the last 30 days.</span></span></label></fieldset>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">Open DLP incidents of the last 30 days</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">Incident</th><th scope="col">Rule</th><th scope="col">Destination</th><th scope="col">Created</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="5">No open incident in the last 30 days.</td></tr>'}</tbody></table></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Reason (optional, added to the note)</span>
        <input id="zwaNote" maxlength="300" value="${E(z.note)}" autocomplete="off" aria-label="Reason added to each incident's note"></label>
        <span class="df-chip" id="zwaCount">${z.pick.size} picked</span></div>`;
    where.querySelectorAll('input[name="zwaMode"]').forEach(r => r.addEventListener('change', () => { z.mode = r.value; }));
    where.querySelectorAll('input[data-zwa]').forEach(cb => cb.addEventListener('change', () => {
      if (cb.checked && z.pick.size >= MAX) { cb.checked = false; H.say(`At most ${MAX} incidents per operation.`); return; }
      cb.checked ? z.pick.add(cb.dataset.zwa) : z.pick.delete(cb.dataset.zwa);
      where.querySelector('#zwaCount').textContent = `${z.pick.size} picked`;
      z.mode = 'pick';
      const r = where.querySelector('input[name="zwaMode"][value="pick"]'); if (r) r.checked = true;
    }));
    where.querySelector('#zwaNote').addEventListener('input', e => { z.note = e.target.value; });
  }
  function spec(S) {
    const z = st(S);
    const out = { type: TYPE };
    if (z.mode === 'match' && (handoff.rule || handoff.host)) {
      if (handoff.rule) out.rule = handoff.rule;
      if (handoff.host) out.host = handoff.host;
      out.days = 30;
    } else {
      if (!z.pick.size) throw new Error('Pick at least one incident.');
      out.incident_ids = Array.from(z.pick).slice(0, MAX);
    }
    if (z.note.trim()) out.note = z.note.trim().slice(0, 300);
    return out;
  }
  window.OPS_PLUGINS.register({ type: TYPE, render, spec });
})();
