/* ZPA segment settings in bulk on Bulk changes (/report/operations, "Change existing").
   One form on the shared engine (ops_zpa_fields.py): pick application segments
   (Browser Access, PRA and inspection segments included), choose the settings
   to change, preview. The page does the rest: the gates, Apply, read-back, Undo. */
(function () {
  'use strict';
  if (!window.OPS_PLUGINS) return;

  function st(S) {
    if (!S.zpf) S.zpf = { pick: new Set(), filter: '', set: {}, segGroup: '', sgMode: '', sg: new Set(), tcpAdd: '', tcpRemove: '', udpAdd: '', udpRemove: '' };
    return S.zpf;
  }
  function errs(H, res) {
    const rows = Object.entries((res && res.errors) || {});
    return rows.length ? `<div class="bp-card warn"><div class="t">Could not be read</div><ul>${rows.map(([k, v]) => `<li>${H.E(k)}: ${H.E(v)}</li>`).join('')}</ul></div>` : '';
  }
  const onOff = v => (v ? 'on' : 'off');

  function render(res, where, S, H) {
    const E = H.E, z = st(S), segs = res.segments || [], lim = (res.limits || {}).segments || 200;
    const f = z.filter.toLowerCase();
    const shown = segs.filter(s => !f || String(s.name).toLowerCase().includes(f) || (s.kinds || []).join(' ').toLowerCase().includes(f));
    const fieldSel = fd => {
      const cur = z.set[fd.id] === undefined ? '' : String(z.set[fd.id]);
      const opts = fd.choices ? fd.choices.map(c => [c.id, c.label]) : [['true', 'On'], ['false', 'Off']];
      return `<label class="df-ctl"><span class="lbl">${E(fd.label)}</span><select data-zf-field="${E(fd.id)}" aria-label="${E(fd.label)}">
        <option value="">Leave as it is</option>${opts.map(([v, l]) => `<option value="${E(v)}"${cur === v ? ' selected' : ''}>${E(l)}</option>`).join('')}</select></label>`;
    };
    where.innerHTML = `${errs(H, res)}
      <p class="df-hint">Pick the segments, choose only the settings you want to change, then preview. Everything else in each segment is sent back as it is. Up to ${E(lim)} segments per operation.</p>
      <h3 class="op-h">1. Segments</h3>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Find a segment</span><input id="zfFilter" type="search" value="${E(z.filter)}" aria-label="Find a segment by name or kind"></label>
        <button type="button" class="rp-btn" id="zfAll">Pick every segment shown</button><button type="button" class="rp-btn" id="zfNone">Clear</button>
        <span class="df-chip" id="zfCount">${z.pick.size} picked</span></div>
      <div class="df-tablewrap op-pick"><table class="df-table"><caption class="sr-only">ZPA application segments</caption>
        <thead><tr><th scope="col">Pick</th><th scope="col">Segment</th><th scope="col">Kind</th><th scope="col">Ports</th><th scope="col">Groups</th><th scope="col">Settings</th></tr></thead>
        <tbody>${shown.map(s => `<tr><td><input type="checkbox" data-zf-seg="${E(s.id)}" aria-label="Pick ${E(s.name)}"${z.pick.has(s.id) ? ' checked' : ''}${s.locked ? ' disabled' : ''}></td>
          <td>${E(s.name)}${s.enabled ? '' : ' <span class="df-chip">disabled</span>'}${s.microtenant ? `<div class="df-by">${E(s.microtenant)}</div>` : ''}${s.locked ? `<div class="df-hint">${E(s.locked)}</div>` : ''}</td>
          <td>${(s.kinds || []).length ? s.kinds.map(k => `<span class="df-chip">${E(k)}</span>`).join(' ') : 'Standard'}</td>
          <td>${s.tcp.length ? `TCP ${E(s.tcp.join(', '))}` : ''}${s.udp.length ? `<div>UDP ${E(s.udp.join(', '))}</div>` : ''}</td>
          <td>${E(s.segment_group)}<div class="df-by">${E((s.server_groups || []).join(', '))}</div></td>
          <td class="df-hint">health ${E(String(s.health_reporting || 'not set').toLowerCase())}, bypass ${E(String(s.bypass_type || 'not set').toLowerCase())}, double encryption ${onOff(s.double_encrypt)}, DR mode ${onOff(s.use_in_dr_mode)}</td></tr>`).join('')
          || '<tr><td colspan="6">No segment matches.</td></tr>'}</tbody></table></div>
      <h3 class="op-h">2. Settings to change</h3>
      <div class="op-row">${(res.fields || []).map(fieldSel).join('')}
        <label class="df-ctl"><span class="lbl">Segment group</span><select id="zfSegGroup" aria-label="Segment group">
          <option value="">Leave as it is</option>${(res.segment_groups || []).map(g => `<option value="${E(g.id)}"${z.segGroup === g.id ? ' selected' : ''}>${E(g.name)}</option>`).join('')}</select></label></div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">Server groups</span><select id="zfSgMode" aria-label="What to do with server groups">
          ${[['', 'Leave as they are'], ['add', 'Add the ones ticked'], ['remove', 'Remove the ones ticked'], ['replace', 'Replace with the ones ticked']].map(([v, l]) => `<option value="${E(v)}"${z.sgMode === v ? ' selected' : ''}>${E(l)}</option>`).join('')}</select></label>
        ${z.sgMode ? `<fieldset class="op-inline"><legend>Server groups</legend>${(res.server_groups || []).map(g => `<label><input type="checkbox" data-zf-sg="${E(g.id)}"${z.sg.has(g.id) ? ' checked' : ''}> ${E(g.name)}</label>`).join(' ') || '<span class="df-hint">The tenant has no server group.</span>'}</fieldset>` : ''}</div>
      <div class="op-row"><label class="df-ctl"><span class="lbl">TCP ports to add</span><input id="zfTcpAdd" value="${E(z.tcpAdd)}" maxlength="200" placeholder="443, 8000-8080" aria-label="TCP ports to add"></label>
        <label class="df-ctl"><span class="lbl">TCP ports to remove</span><input id="zfTcpRemove" value="${E(z.tcpRemove)}" maxlength="200" placeholder="8080" aria-label="TCP ports to remove"></label>
        <label class="df-ctl"><span class="lbl">UDP ports to add</span><input id="zfUdpAdd" value="${E(z.udpAdd)}" maxlength="200" aria-label="UDP ports to add"></label>
        <label class="df-ctl"><span class="lbl">UDP ports to remove</span><input id="zfUdpRemove" value="${E(z.udpRemove)}" maxlength="200" aria-label="UDP ports to remove"></label></div>
      <div class="df-hint">Ranges are removed whole (removing 80 does not cut it out of 1-1000). The preview keeps the port a Browser Access, PRA or inspection application uses, the last port range and the last server group.</div>`;
    const again = id => { render(res, where, S, H); const el = document.getElementById(id); if (el) el.focus(); };
    document.getElementById('zfFilter').addEventListener('input', e => { z.filter = e.target.value; const pos = e.target.selectionStart; again('zfFilter'); try { document.getElementById('zfFilter').setSelectionRange(pos, pos); } catch (x) { /* search */ } });
    document.getElementById('zfAll').addEventListener('click', () => { shown.filter(s => !s.locked).forEach(s => { if (z.pick.size < lim) z.pick.add(s.id); }); again('zfAll'); H.say(`${z.pick.size} segments picked.`); });
    document.getElementById('zfNone').addEventListener('click', () => { z.pick.clear(); again('zfNone'); });
    where.querySelectorAll('input[data-zf-seg]').forEach(cb => cb.addEventListener('change', () => {
      if (cb.checked && z.pick.size >= lim) { cb.checked = false; H.say(`At most ${lim} segments per operation.`); return; }
      if (cb.checked) z.pick.add(cb.dataset.zfSeg); else z.pick.delete(cb.dataset.zfSeg);
      document.getElementById('zfCount').textContent = `${z.pick.size} picked`;
    }));
    where.querySelectorAll('select[data-zf-field]').forEach(sel => sel.addEventListener('change', () => {
      const v = sel.value;
      if (!v) delete z.set[sel.dataset.zfField]; else z.set[sel.dataset.zfField] = v;
    }));
    document.getElementById('zfSegGroup').addEventListener('change', e => { z.segGroup = e.target.value; });
    document.getElementById('zfSgMode').addEventListener('change', e => { z.sgMode = e.target.value; again('zfSgMode'); });
    where.querySelectorAll('input[data-zf-sg]').forEach(cb => cb.addEventListener('change', () => { if (cb.checked) z.sg.add(cb.dataset.zfSg); else z.sg.delete(cb.dataset.zfSg); }));
    [['zfTcpAdd', 'tcpAdd'], ['zfTcpRemove', 'tcpRemove'], ['zfUdpAdd', 'udpAdd'], ['zfUdpRemove', 'udpRemove']].forEach(([id, k]) =>
      document.getElementById(id).addEventListener('input', e => { z[k] = e.target.value; }));
  }

  function spec(S) {
    const z = st(S);
    if (!z.pick.size) throw new Error('Pick at least one application segment.');
    const set = {};
    Object.entries(z.set).forEach(([k, v]) => { set[k] = v === 'true' ? true : v === 'false' ? false : v; });
    if (z.segGroup) set.segment_group_id = z.segGroup;
    if (z.sgMode) {
      if (!z.sg.size) throw new Error('Tick the server groups to add, remove or replace with.');
      set.server_groups = { [z.sgMode]: [...z.sg] };
    }
    const ports = (add, rem) => { const o = {}; if (add.trim()) o.add = add.trim(); if (rem.trim()) o.remove = rem.trim(); return Object.keys(o).length ? o : null; };
    const tcp = ports(z.tcpAdd, z.tcpRemove), udp = ports(z.udpAdd, z.udpRemove);
    if (tcp) set.tcp_ports = tcp;
    if (udp) set.udp_ports = udp;
    if (!Object.keys(set).length) throw new Error('Choose at least one setting to change.');
    return { type: 'zpa_segment_fields', segments: [...z.pick], set };
  }

  window.OPS_PLUGINS.register({ type: 'zpa_segment_fields', render, spec: S => spec(S) });
})();
